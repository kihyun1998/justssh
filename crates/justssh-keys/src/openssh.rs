//! The OpenSSH private key format (`PROTOCOL.key` in OpenSSH): an armored `openssh-key-v1`
//! container, unencrypted or encrypted with bcrypt-pbkdf and AES-256 in CTR or CBC mode.

use base64ct::{Base64, Encoding};
use justssh::{EcdsaCurve, Zeroizing};
use justssh_wire::Reader;

use crate::{KeyFile, KeyFileError, Secret};

const BEGIN: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----";
const END: &[u8] = b"-----END OPENSSH PRIVATE KEY-----";
const MAGIC: &[u8] = b"openssh-key-v1\0";
/// The most bcrypt-pbkdf rounds a file may ask for, as x/crypto/ssh's `maxRounds`.
const MAX_ROUNDS: u32 = 1 << 11;
const LINE: usize = 70;

pub(crate) fn decode(text: &[u8], passphrase: Option<&[u8]>) -> Result<KeyFile, KeyFileError> {
    let bin = unarmor(text)?;
    let mut r = Reader::new(bin.strip_prefix(MAGIC).ok_or(KeyFileError::Malformed)?);
    let malformed = |_| KeyFileError::Malformed;
    let cipher = r.string().map_err(malformed)?;
    let kdf = r.string().map_err(malformed)?;
    let kdf_options = r.string().map_err(malformed)?;
    match r.u32().map_err(malformed)? {
        1 => {}
        0 => return Err(KeyFileError::Malformed),
        _ => return Err(KeyFileError::MultipleKeys),
    }
    let public = r.string().map_err(malformed)?;
    let section = r.string().map_err(malformed)?;
    let encrypted = !(cipher == b"none" && kdf == b"none");

    let section = if encrypted {
        let passphrase = passphrase
            .filter(|p| !p.is_empty())
            .ok_or(KeyFileError::PassphraseNeeded)?;
        decrypt(cipher, kdf, kdf_options, section, passphrase)?
    } else {
        if !kdf_options.is_empty() {
            return Err(KeyFileError::Malformed);
        }
        if passphrase.is_some_and(|p| !p.is_empty()) {
            return Err(KeyFileError::NotEncrypted);
        }
        Zeroizing::new(section.to_vec())
    };
    let key = private_section(&section, encrypted)?;
    if key.private_key().plain_public_blob() != public {
        return Err(KeyFileError::InvalidKey);
    }
    Ok(key)
}

/// The container inside the armor of `text`, which may hold other text around it.
fn unarmor(text: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyFileError> {
    let start = line_start(text, BEGIN).ok_or(KeyFileError::NotThisFormat)? + BEGIN.len();
    let len = find(&text[start..], END).ok_or(KeyFileError::Malformed)?;
    let body = &text[start..start + len];
    let mut base64 = Zeroizing::new(Vec::with_capacity(body.len()));
    base64.extend(body.iter().filter(|b| !b.is_ascii_whitespace()));
    let mut bin = Zeroizing::new(vec![0; base64.len() / 4 * 3]);
    let n = Base64::decode(&base64[..], &mut bin)
        .map_err(|_| KeyFileError::Malformed)?
        .len();
    bin.truncate(n);
    Ok(bin)
}

/// Where `line` starts a line of `text`.
fn line_start(text: &[u8], line: &[u8]) -> Option<usize> {
    let mut from = 0;
    while let Some(at) = find(&text[from..], line) {
        let at = from + at;
        if at == 0 || text[at - 1] == b'\n' {
            return Some(at);
        }
        from = at + 1;
    }
    None
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Whether `cipher` and `kdf` are ones x/crypto/ssh reads: bcrypt with AES-256 in CTR or CBC mode.
fn supported(cipher: &[u8], kdf: &[u8]) -> Result<(), KeyFileError> {
    let unsupported = |name: &[u8]| {
        KeyFileError::UnsupportedEncryption(String::from_utf8_lossy(name).into_owned())
    };
    if kdf != b"bcrypt" {
        return Err(unsupported(kdf));
    }
    if cipher != b"aes256-ctr" && cipher != b"aes256-cbc" {
        return Err(unsupported(cipher));
    }
    Ok(())
}

fn decrypt(
    cipher: &[u8],
    kdf: &[u8],
    kdf_options: &[u8],
    section: &[u8],
    passphrase: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeyFileError> {
    supported(cipher, kdf)?;
    let mut r = Reader::new(kdf_options);
    let salt = r.string().map_err(|_| KeyFileError::Malformed)?;
    let rounds = r.u32().map_err(|_| KeyFileError::Malformed)?;
    r.finish().map_err(|_| KeyFileError::Malformed)?;
    if rounds > MAX_ROUNDS {
        return Err(KeyFileError::TooManyRounds(rounds));
    }
    let mut derived = Zeroizing::new([0u8; 48]);
    bcrypt_pbkdf::bcrypt_pbkdf(passphrase, salt, rounds, &mut derived[..])
        .map_err(|_| KeyFileError::Malformed)?;
    let (key, iv) = derived.split_at(32);
    let mut block = Zeroizing::new(section.to_vec());
    if cipher == b"aes256-ctr" {
        use ctr::cipher::{KeyIvInit, StreamCipher};
        ctr::Ctr128BE::<aes::Aes256>::new_from_slices(key, iv)
            .expect("32-byte key and 16-byte IV")
            .apply_keystream(&mut block);
    } else {
        use cbc::cipher::block_padding::NoPadding;
        use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
        cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
            .expect("32-byte key and 16-byte IV")
            .decrypt_padded::<NoPadding>(&mut block)
            .map_err(|_| KeyFileError::Malformed)?;
    }
    Ok(block)
}

/// The key in a decrypted private section: two equal check numbers, the key, its comment and
/// padding counting up from 1.
fn private_section(section: &[u8], encrypted: bool) -> Result<KeyFile, KeyFileError> {
    let mut r = Reader::new(section);
    let checks = r.u32().and_then(|a| Ok((a, r.u32()?)));
    match checks {
        Ok((a, b)) if a == b => {}
        _ if encrypted => return Err(KeyFileError::WrongPassphrase),
        _ => return Err(KeyFileError::Malformed),
    }
    let m = |_| KeyFileError::Malformed;
    let key_type = r.string().map_err(m)?;
    let key = match key_type {
        b"ssh-ed25519" => {
            let public = r.string().map_err(m)?;
            let private = r.string().map_err(m)?;
            if public.len() != 32 || private.len() != 64 || private[32..] != *public {
                return Err(KeyFileError::InvalidKey);
            }
            let mut seed = Zeroizing::new([0; 32]);
            seed.copy_from_slice(&private[..32]);
            KeyFile::ed25519(seed)
        }
        b"ecdsa-sha2-nistp256" | b"ecdsa-sha2-nistp384" | b"ecdsa-sha2-nistp521" => {
            let (curve, name) = match key_type {
                b"ecdsa-sha2-nistp256" => (EcdsaCurve::P256, &b"nistp256"[..]),
                b"ecdsa-sha2-nistp384" => (EcdsaCurve::P384, &b"nistp384"[..]),
                _ => (EcdsaCurve::P521, &b"nistp521"[..]),
            };
            if r.string().map_err(m)? != name {
                return Err(KeyFileError::InvalidKey);
            }
            let point = r.string().map_err(m)?;
            let scalar = mpint(&mut r)?;
            let key = KeyFile::ecdsa(curve, scalar).map_err(|_| KeyFileError::InvalidKey)?;
            let blob = key.private_key().plain_public_blob();
            if !blob.ends_with(point)
                || blob.len() != 4 + key_type.len() + 4 + name.len() + 4 + point.len()
            {
                return Err(KeyFileError::InvalidKey);
            }
            key
        }
        b"ssh-rsa" => {
            let n = mpint(&mut r)?;
            let e = mpint(&mut r)?;
            let d = mpint(&mut r)?;
            let _iqmp = mpint(&mut r)?;
            let p = mpint(&mut r)?;
            let q = mpint(&mut r)?;
            // The bounds x/crypto/ssh puts on an RSA key it reads.
            let bits = |b: &[u8]| b.len() * 8 - b.first().map_or(0, |x| x.leading_zeros() as usize);
            let odd = e.last().is_some_and(|b| b & 1 == 1);
            if bits(&n) > 16384
                || bits(&d) > bits(&n)
                || bits(&p) > 8192
                || bits(&q) > 8192
                || bits(&e) > 24
                || !odd
                || bits(&e) < 2
            {
                return Err(KeyFileError::InvalidKey);
            }
            KeyFile::rsa(&n, &e, d, p, q).map_err(|_| KeyFileError::InvalidKey)?
        }
        other => {
            return Err(KeyFileError::UnsupportedKeyType(
                String::from_utf8_lossy(other).into_owned(),
            ));
        }
    };
    let comment = r.string().map_err(m)?.to_vec();
    let padding = r.remaining();
    if !padding
        .iter()
        .enumerate()
        .all(|(i, &b)| usize::from(b) == i + 1)
    {
        return Err(KeyFileError::Malformed);
    }
    Ok(key.with_comment(comment))
}

/// An mpint that must not be negative, without its leading zero bytes.
fn mpint(r: &mut Reader<'_>) -> Result<Zeroizing<Vec<u8>>, KeyFileError> {
    let bytes = r.string().map_err(|_| KeyFileError::Malformed)?;
    if bytes.first().is_some_and(|b| b & 0x80 != 0) {
        return Err(KeyFileError::Malformed);
    }
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    Ok(Zeroizing::new(bytes[start..].to_vec()))
}

pub(crate) fn encode(key: &KeyFile) -> Zeroizing<String> {
    let public = key.private_key().plain_public_blob();
    let mut section = Buf::default();
    let mut check = [0; 4];
    getrandom::fill(&mut check).expect("system random number generator");
    section.bytes(&check).bytes(&check);
    let mut r = Reader::new(&public);
    let key_type = r.string().expect("public key blob");
    section.string(key_type);
    match &key.secret {
        Secret::Ed25519(seed) => {
            let point = r.string().expect("ed25519 public key");
            section.string(point).u32(64).bytes(&seed[..]).bytes(point);
        }
        Secret::Ecdsa(scalar) => {
            let curve = r.string().expect("curve name");
            let point = r.string().expect("curve point");
            section.string(curve).string(point).mpint(scalar);
        }
        Secret::Rsa { d, iqmp, p, q } => {
            let e = r.string().expect("rsa exponent");
            let n = r.string().expect("rsa modulus");
            section
                .string(n)
                .string(e)
                .mpint(d)
                .mpint(iqmp)
                .mpint(p)
                .mpint(q);
        }
    }
    section.string(&key.comment);
    let mut i = 1;
    while section.0.len() % 8 != 0 {
        section.bytes(&[i]);
        i += 1;
    }
    let mut bin = Buf::default();
    bin.bytes(MAGIC)
        .string(b"none")
        .string(b"none")
        .string(b"")
        .u32(1)
        .string(&public)
        .string(&section.0);
    armor(&bin.0)
}

fn armor(bin: &[u8]) -> Zeroizing<String> {
    let mut base64 = Zeroizing::new(vec![0; Base64::encoded_len(bin)]);
    let encoded = Base64::encode(bin, &mut base64).expect("buffer sized for the encoding");
    let lines = encoded.len().div_ceil(LINE);
    let mut text = Zeroizing::new(String::with_capacity(
        BEGIN.len() + END.len() + encoded.len() + lines + 2,
    ));
    text.push_str("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for line in encoded.as_bytes().chunks(LINE) {
        text.push_str(core::str::from_utf8(line).expect("base64 is ASCII"));
        text.push('\n');
    }
    text.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    text
}

/// A buffer for secret bytes that zeroizes every allocation it leaves behind when it grows.
#[derive(Default)]
struct Buf(Zeroizing<Vec<u8>>);

impl Buf {
    fn bytes(&mut self, b: &[u8]) -> &mut Self {
        if self.0.capacity() - self.0.len() < b.len() {
            let mut grown = Zeroizing::new(Vec::with_capacity(
                (self.0.len() + b.len()).max(2 * self.0.capacity()).max(256),
            ));
            grown.extend_from_slice(&self.0);
            self.0 = grown;
        }
        self.0.extend_from_slice(b);
        self
    }

    fn u32(&mut self, v: u32) -> &mut Self {
        self.bytes(&v.to_be_bytes())
    }

    fn string(&mut self, s: &[u8]) -> &mut Self {
        self.u32(u32::try_from(s.len()).expect("string longer than u32::MAX"))
            .bytes(s)
    }

    /// `mpint` of the unsigned big-endian `magnitude`.
    fn mpint(&mut self, magnitude: &[u8]) -> &mut Self {
        let start = magnitude
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(magnitude.len());
        let m = &magnitude[start..];
        let pad = m.first().is_some_and(|&b| b & 0x80 != 0);
        self.u32((m.len() + usize::from(pad)) as u32);
        if pad {
            self.bytes(&[0]);
        }
        self.bytes(m)
    }
}
