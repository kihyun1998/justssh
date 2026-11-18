//! PEM private keys as x/crypto/ssh's `ParseRawPrivateKey` and `ParseRawPrivateKeyWithPassphrase`
//! read them: the first PEM block, as Go's `encoding/pem` finds it, holding a PKCS#1 RSA key, a
//! PKCS#8 key or a SEC1 EC key, decrypted as Go's `x509.DecryptPEMBlock` decrypts a legacy
//! encrypted block.

use justssh::{EcdsaCurve, Zeroizing};
use pkcs8::ObjectIdentifier;

use crate::{KeyFile, KeyFileError};

const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const EC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const X25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");
const DSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10040.4.1");
const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

/// A PEM block: its type, its headers and its decoded body.
pub(crate) struct Block<'a> {
    pub(crate) label: &'a [u8],
    headers: Vec<(&'a [u8], &'a [u8])>,
    pub(crate) body: Zeroizing<Vec<u8>>,
}

impl Block<'_> {
    fn header(&self, name: &[u8]) -> Option<&[u8]> {
        self.headers
            .iter()
            .rev()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| *v)
    }
}

pub(crate) fn decode(text: &[u8], passphrase: Option<&[u8]>) -> Result<KeyFile, KeyFileError> {
    let block = first_block(text).ok_or(KeyFileError::NotThisFormat)?;
    let passphrase = passphrase.filter(|p| !p.is_empty());
    let encrypted = block
        .header(b"Proc-Type")
        .is_some_and(|v| contains(v, b"ENCRYPTED"));
    if block.label == b"ENCRYPTED PRIVATE KEY" {
        return Err(KeyFileError::UnsupportedEncryption("PKCS#8".into()));
    }
    let der = match (encrypted, passphrase) {
        (false, None) => block.body,
        (true, None) => return Err(KeyFileError::PassphraseNeeded),
        (_, Some(_)) if !encrypted || block.header(b"DEK-Info").is_none() => {
            return Err(KeyFileError::NotEncrypted);
        }
        (_, Some(passphrase)) => {
            if block.label == b"PRIVATE KEY" {
                return Err(KeyFileError::UnsupportedKeyType("PRIVATE KEY".into()));
            }
            decrypt(&block, passphrase)?
        }
    };
    let key = match block.label {
        b"RSA PRIVATE KEY" => pkcs1(&der),
        b"EC PRIVATE KEY" => sec1(&der, None),
        b"PRIVATE KEY" => pkcs8(&der),
        b"DSA PRIVATE KEY" => Err(KeyFileError::UnsupportedKeyType("ssh-dss".into())),
        other => Err(KeyFileError::UnsupportedKeyType(
            String::from_utf8_lossy(other).into_owned(),
        )),
    };
    // A wrong passphrase can leave padding that looks right over noise, which then does not
    // parse; Go's `ParseRawPrivateKeyWithPassphrase` takes that for a wrong passphrase too.
    match key {
        Err(KeyFileError::Malformed) if encrypted => Err(KeyFileError::WrongPassphrase),
        other => other,
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// A line of `data` without its LF or CR LF and trailing spaces and tabs, what follows it, and
/// how many bytes the line took, as Go's `pem` `getLine` reads one.
fn line(data: &[u8]) -> (&[u8], &[u8], usize) {
    let (mut line, rest, consumed) = match data.iter().position(|&b| b == b'\n') {
        Some(i) => (&data[..i], &data[i + 1..], i + 1),
        None => (data, &data[data.len()..], data.len()),
    };
    if let [head @ .., b'\r'] = line
        && consumed > line.len()
    {
        line = head;
    }
    while let [head @ .., b' ' | b'\t'] = line {
        line = head;
    }
    (line, rest, consumed)
}

/// The first PEM block of `text` as Go's `pem.Decode` finds it: the first END line, the last
/// BEGIN line at the start of a line before it, headers up to the first line without a colon,
/// and an END line naming the same type.
pub(crate) fn first_block(text: &[u8]) -> Option<Block<'_>> {
    const BEGIN: &[u8] = b"-----BEGIN ";
    const END: &[u8] = b"\n-----END ";
    const DASHES: &[u8] = b"-----";
    let mut rest = text;
    let mut skip = 0;
    loop {
        rest = rest.get(skip..)?;
        let end = find(rest, END)?;
        skip = end + END.len();
        let Some(begin) = rest[..end].windows(BEGIN.len()).rposition(|w| w == BEGIN) else {
            continue;
        };
        if begin > 0 && rest[begin - 1] != b'\n' {
            continue;
        }
        // Positions from here on count from just after BEGIN, and may fall below zero.
        let start = begin + BEGIN.len();
        let mut end_at = end as isize - start as isize;
        let mut trailer_at = skip as isize - start as isize;
        let (type_line, mut body, consumed) = line(&rest[start..]);
        end_at -= consumed as isize;
        trailer_at -= consumed as isize;
        let Some(label) = type_line.strip_suffix(DASHES) else {
            continue;
        };
        let mut headers = Vec::new();
        loop {
            if body.is_empty() {
                return None;
            }
            let (l, next, consumed) = line(body);
            let Some(colon) = l.iter().position(|&b| b == b':') else {
                break;
            };
            headers.push((
                crate::authorized::trim_space(&l[..colon]),
                crate::authorized::trim_space(&l[colon + 1..]),
            ));
            body = next;
            end_at -= consumed as isize;
            trailer_at -= consumed as isize;
        }
        if !headers.is_empty() && end_at < 0 {
            continue;
        }
        let Some(trailer) = usize::try_from(trailer_at).ok().and_then(|t| body.get(t..)) else {
            continue;
        };
        let matches = trailer
            .strip_prefix(label)
            .and_then(|t| t.strip_prefix(DASHES))
            .is_some_and(|t| line(t).0.is_empty());
        if !matches {
            continue;
        }
        let base64 = match usize::try_from(end_at) {
            Ok(n) if n > 0 => &body[..n],
            _ => &[][..],
        };
        let mut stripped = Zeroizing::new(Vec::with_capacity(base64.len()));
        stripped.extend(
            base64
                .iter()
                .filter(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n')),
        );
        let Some(body) = crate::base64::decode(&stripped) else {
            continue;
        };
        return Some(Block {
            label,
            headers,
            body,
        });
    }
}

/// The body of a legacy encrypted block decrypted as `x509.DecryptPEMBlock` decrypts it.
fn decrypt(block: &Block<'_>, passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyFileError> {
    let dek = block.header(b"DEK-Info").ok_or(KeyFileError::Malformed)?;
    let comma = dek
        .iter()
        .position(|&b| b == b',')
        .ok_or(KeyFileError::Malformed)?;
    let (mode, iv) = (&dek[..comma], &dek[comma + 1..]);
    let (key_size, block_size) = match mode {
        b"DES-CBC" => (8, 8),
        b"DES-EDE3-CBC" => (24, 8),
        b"AES-128-CBC" => (16, 16),
        b"AES-192-CBC" => (24, 16),
        b"AES-256-CBC" => (32, 16),
        other => {
            return Err(KeyFileError::UnsupportedEncryption(
                String::from_utf8_lossy(other).into_owned(),
            ));
        }
    };
    let iv = hex(iv).ok_or(KeyFileError::Malformed)?;
    if iv.len() != block_size {
        return Err(KeyFileError::Malformed);
    }
    let key = derive(passphrase, &iv[..8], key_size);
    if block.body.is_empty() || !block.body.len().is_multiple_of(block_size) {
        return Err(KeyFileError::Malformed);
    }
    let mut data = block.body.clone();
    use cbc::cipher::block_padding::NoPadding;
    use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
    let ok = match mode {
        b"DES-CBC" => cbc::Decryptor::<des::Des>::new_from_slices(&key, &iv)
            .map(|d| d.decrypt_padded::<NoPadding>(&mut data).is_ok()),
        b"DES-EDE3-CBC" => cbc::Decryptor::<des::TdesEde3>::new_from_slices(&key, &iv)
            .map(|d| d.decrypt_padded::<NoPadding>(&mut data).is_ok()),
        b"AES-128-CBC" => cbc::Decryptor::<aes::Aes128>::new_from_slices(&key, &iv)
            .map(|d| d.decrypt_padded::<NoPadding>(&mut data).is_ok()),
        b"AES-192-CBC" => cbc::Decryptor::<aes::Aes192>::new_from_slices(&key, &iv)
            .map(|d| d.decrypt_padded::<NoPadding>(&mut data).is_ok()),
        _ => cbc::Decryptor::<aes::Aes256>::new_from_slices(&key, &iv)
            .map(|d| d.decrypt_padded::<NoPadding>(&mut data).is_ok()),
    };
    if ok != Ok(true) {
        return Err(KeyFileError::Malformed);
    }
    // RFC 1423 padding: the last n bytes, 1 to a block, are all n; anything else is taken for
    // a wrong passphrase, as Go takes it.
    let pad = usize::from(*data.last().expect("not empty"));
    if pad == 0
        || pad > block_size
        || data[data.len() - pad..]
            .iter()
            .any(|&b| usize::from(b) != pad)
    {
        return Err(KeyFileError::WrongPassphrase);
    }
    let len = data.len() - pad;
    data.truncate(len);
    Ok(data)
}

/// OpenSSL's `EVP_BytesToKey` with MD5 and one round, as `x509` derives a PEM key.
fn derive(passphrase: &[u8], salt: &[u8], size: usize) -> Zeroizing<Vec<u8>> {
    use md5::Digest;
    let mut out = Zeroizing::new(Vec::with_capacity(size + 16));
    let mut digest = Zeroizing::new([0u8; 16]);
    let mut first = true;
    while out.len() < size {
        let mut h = md5::Md5::new();
        if !first {
            h.update(&digest[..]);
        }
        h.update(passphrase);
        h.update(salt);
        h.finalize_into((&mut *digest).into());
        out.extend_from_slice(&digest[..]);
        first = false;
    }
    out.truncate(size);
    out
}

fn hex(text: &[u8]) -> Option<Vec<u8>> {
    let digit = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.chunks(2)
        .map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?))
        .collect()
}

/// A PKCS#1 `RSAPrivateKey` with two primes.
fn pkcs1(der: &[u8]) -> Result<KeyFile, KeyFileError> {
    use rsa::pkcs1::der::Decode;
    let key = rsa::pkcs1::RsaPrivateKey::from_der(der).map_err(|_| KeyFileError::Malformed)?;
    if key.other_prime_infos.is_some() {
        return Err(KeyFileError::UnsupportedKeyType("multi-prime RSA".into()));
    }
    let crt = [key.exponent1, key.exponent2, key.coefficient].map(|u| u.as_bytes());
    if !crt_matches(
        key.private_exponent.as_bytes(),
        key.prime1.as_bytes(),
        key.prime2.as_bytes(),
        crt,
    ) {
        return Err(KeyFileError::InvalidKey);
    }
    let secret = |u: rsa::pkcs1::UintRef<'_>| Zeroizing::new(u.as_bytes().to_vec());
    KeyFile::rsa(
        key.modulus.as_bytes(),
        key.public_exponent.as_bytes(),
        secret(key.private_exponent),
        secret(key.prime1),
        secret(key.prime2),
    )
    .map_err(|_| KeyFileError::InvalidKey)
}

/// Whether `[d mod (p-1), d mod (q-1), q⁻¹ mod p]` are `crt`, as Go's `rsa` validates them.
fn crt_matches(d: &[u8], p: &[u8], q: &[u8], crt: [&[u8]; 3]) -> bool {
    use num_bigint_dig::{BigUint, ModInverse};
    use zeroize::Zeroize;
    let (d, p, q) = (
        crate::secret_uint(d),
        crate::secret_uint(p),
        crate::secret_uint(q),
    );
    let one = BigUint::from(1u32);
    let inverse = (&q).mod_inverse(&p).and_then(|i| i.to_biguint());
    let mut computed = match (p > one, q > one, inverse) {
        (true, true, Some(inverse)) => vec![&d % (&p - &one), &d % (&q - &one), inverse],
        _ => return false,
    };
    let given = crt.map(crate::secret_uint);
    let equal = computed.iter().zip(&given).all(|(a, b)| a == b);
    computed.iter_mut().for_each(Zeroize::zeroize);
    for mut v in [d, p, q].into_iter().chain(given) {
        v.zeroize();
    }
    equal
}

/// A SEC1 `ECPrivateKey` on `curve`, or else on the curve it names.
fn sec1(der: &[u8], curve: Option<ObjectIdentifier>) -> Result<KeyFile, KeyFileError> {
    use pkcs8::der::Decode;
    let key = sec1::EcPrivateKey::from_der(der).map_err(|_| KeyFileError::Malformed)?;
    let named = key.parameters.and_then(|p| p.named_curve());
    let curve = match curve.or(named) {
        Some(P256) => EcdsaCurve::P256,
        Some(P384) => EcdsaCurve::P384,
        Some(P521) => EcdsaCurve::P521,
        Some(other) => return Err(KeyFileError::UnsupportedKeyType(other.to_string())),
        None => return Err(KeyFileError::Malformed),
    };
    KeyFile::ecdsa(curve, Zeroizing::new(key.private_key.to_vec()))
        .map_err(|_| KeyFileError::InvalidKey)
}

/// A PKCS#8 `PrivateKeyInfo` holding an RSA, ECDSA or Ed25519 key.
fn pkcs8(der: &[u8]) -> Result<KeyFile, KeyFileError> {
    use pkcs8::der::Decode;
    let info = pkcs8::PrivateKeyInfoRef::from_der(der).map_err(|_| KeyFileError::Malformed)?;
    let private = info.private_key.as_bytes();
    match info.algorithm.oid {
        RSA => pkcs1(private),
        EC => {
            let curve = info
                .algorithm
                .parameters
                .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
            sec1(private, curve)
        }
        ED25519 => {
            // RFC 8410: no parameters, and the key an OCTET STRING opening with the 32-byte seed.
            if info.algorithm.parameters.is_some() {
                return Err(KeyFileError::Malformed);
            }
            let seed = match private {
                [0x04, 0x20, seed @ ..] if seed.len() >= 32 => &seed[..32],
                _ => return Err(KeyFileError::Malformed),
            };
            let mut s = Zeroizing::new([0; 32]);
            s.copy_from_slice(seed);
            Ok(KeyFile::ed25519(s))
        }
        X25519 => Err(KeyFileError::UnsupportedKeyType("X25519".into())),
        DSA => Err(KeyFileError::UnsupportedKeyType("ssh-dss".into())),
        other => Err(KeyFileError::UnsupportedKeyType(other.to_string())),
    }
}
