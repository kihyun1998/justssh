//! PuTTY's private key format (PuTTY `doc/pubkeyfmt.but`, `sshpubk.c` `ppk_load_s`), versions 2
//! and 3, read as acwbroker's `internal/infrastructure/ppk` reads it.

use hmac::{KeyInit, Mac};
use justssh::{EcdsaCurve, Zeroizing};
use justssh_wire::Reader;
use sha1::Digest;

use crate::{KeyFile, KeyFileError};

const MAGIC: &str = "PuTTY-User-Key-File-";
/// The most Argon2 memory a file may ask for, in KiB, and memory times passes.
const MAX_ARGON2_MEMORY: u32 = 1 << 20;
const MAX_ARGON2_WORK: u64 = 4 << 20;
/// The most lines a public or private block may announce.
const MAX_BLOCK_LINES: u32 = 1024;

struct File {
    version: u32,
    algorithm: String,
    encryption: String,
    comment: Vec<u8>,
    public: Zeroizing<Vec<u8>>,
    argon2: Option<Argon2>,
    private: Zeroizing<Vec<u8>>,
    mac: Vec<u8>,
}

struct Argon2 {
    flavour: argon2::Algorithm,
    memory: u32,
    passes: u32,
    threads: u32,
    salt: Vec<u8>,
}

pub(crate) fn decode(text: &[u8], passphrase: Option<&[u8]>) -> Result<KeyFile, KeyFileError> {
    let file = parse(text)?;
    let encrypted = file.encryption != "none";
    let passphrase = passphrase.filter(|p| !p.is_empty());
    if encrypted && passphrase.is_none() {
        return Err(KeyFileError::PassphraseNeeded);
    }
    let keys = derive(&file, passphrase.unwrap_or_default())?;
    let mut private = file.private.clone();
    if encrypted {
        use cbc::cipher::block_padding::NoPadding;
        use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
        if private.is_empty() || !private.len().is_multiple_of(16) {
            return Err(KeyFileError::Malformed);
        }
        cbc::Decryptor::<aes::Aes256>::new_from_slices(&keys.cipher, &keys.iv)
            .expect("32-byte key and 16-byte IV")
            .decrypt_padded::<NoPadding>(&mut private)
            .map_err(|_| KeyFileError::Malformed)?;
    }
    if !mac_matches(&file, &keys.mac, &private) {
        return Err(if encrypted {
            KeyFileError::WrongPassphrase
        } else {
            KeyFileError::Malformed
        });
    }
    let key = build(&file.algorithm, &file.public, &private)?;
    Ok(key.with_comment(file.comment))
}

/// The headers, in the order PuTTY writes them: one out of place is a malformed file. The text
/// is read as bytes, since a comment may be in any encoding, and lines may end in LF, CR LF or
/// CR.
fn parse(text: &[u8]) -> Result<File, KeyFileError> {
    let start = text
        .iter()
        .position(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .unwrap_or(text.len());
    let mut r = Lines(&text[start..]);
    let first = r.line().unwrap_or_default();
    let header = first
        .strip_prefix(MAGIC.as_bytes())
        .ok_or(KeyFileError::NotThisFormat)?;
    let split = header
        .windows(2)
        .position(|w| w == b": ")
        .ok_or(KeyFileError::Malformed)?;
    let (version, algorithm) = (&header[..split], &header[split + 2..]);
    let version = number(version).ok_or(KeyFileError::Malformed)?;
    if version != 2 && version != 3 {
        return Err(KeyFileError::UnsupportedVersion(version));
    }
    let algorithm = match algorithm {
        b"ssh-rsa"
        | b"ecdsa-sha2-nistp256"
        | b"ecdsa-sha2-nistp384"
        | b"ecdsa-sha2-nistp521"
        | b"ssh-ed25519" => String::from_utf8_lossy(algorithm).into_owned(),
        other => return Err(KeyFileError::UnsupportedKeyType(token(other))),
    };
    let encryption = match r.header("Encryption")? {
        e @ (b"none" | b"aes256-cbc") => String::from_utf8_lossy(e).into_owned(),
        other => return Err(KeyFileError::UnsupportedEncryption(token(other))),
    };
    let comment = r.header("Comment")?.to_vec();
    let public = r.block("Public-Lines")?;
    let argon2 = if version == 3 && encryption != "none" {
        let flavour = match r.header("Key-Derivation")? {
            b"Argon2id" => argon2::Algorithm::Argon2id,
            b"Argon2i" => argon2::Algorithm::Argon2i,
            b"Argon2d" => return Err(KeyFileError::UnsupportedEncryption("Argon2d".into())),
            _ => return Err(KeyFileError::Malformed),
        };
        let memory = r.number("Argon2-Memory")?;
        let passes = r.number("Argon2-Passes")?;
        let threads = r.number("Argon2-Parallelism")?;
        if threads == 0 || threads > 255 || passes == 0 {
            return Err(KeyFileError::Malformed);
        }
        if memory > MAX_ARGON2_MEMORY || u64::from(memory) * u64::from(passes) > MAX_ARGON2_WORK {
            return Err(KeyFileError::KdfTooCostly);
        }
        let salt = hex(r.header("Argon2-Salt")?).ok_or(KeyFileError::Malformed)?;
        Some(Argon2 {
            flavour,
            // Go's argon2 raises a memory below eight blocks a lane to that.
            memory: memory.max(8 * threads),
            passes,
            threads,
            salt,
        })
    } else {
        None
    };
    let private = r.block("Private-Lines")?;
    let mac = hex(r.header("Private-MAC")?).ok_or(KeyFileError::Malformed)?;
    Ok(File {
        version,
        algorithm,
        encryption,
        comment,
        public,
        argon2,
        private,
        mac,
    })
}

/// The lines of a file, each without its LF, CR LF or CR.
struct Lines<'a>(&'a [u8]);

impl<'a> Lines<'a> {
    fn line(&mut self) -> Option<&'a [u8]> {
        if self.0.is_empty() {
            return None;
        }
        let end = self
            .0
            .iter()
            .position(|&b| b == b'\n' || b == b'\r')
            .unwrap_or(self.0.len());
        let line = &self.0[..end];
        let rest = &self.0[end..];
        self.0 = match rest {
            [b'\r', b'\n', rest @ ..] | [_, rest @ ..] => rest,
            [] => rest,
        };
        Some(line)
    }

    /// The value of the next line, which must be `name: value`.
    fn header(&mut self, name: &str) -> Result<&'a [u8], KeyFileError> {
        let line = self.line().ok_or(KeyFileError::Malformed)?;
        line.strip_prefix(name.as_bytes())
            .and_then(|rest| rest.strip_prefix(b": "))
            .ok_or(KeyFileError::Malformed)
    }

    fn number(&mut self, name: &str) -> Result<u32, KeyFileError> {
        number(self.header(name)?).ok_or(KeyFileError::Malformed)
    }

    /// The base64 block of `name: count` lines that follows.
    fn block(&mut self, name: &str) -> Result<Zeroizing<Vec<u8>>, KeyFileError> {
        let count = self.number(name)?;
        if count > MAX_BLOCK_LINES {
            return Err(KeyFileError::Malformed);
        }
        let mut lines = Vec::new();
        for _ in 0..count {
            lines.push(self.line().ok_or(KeyFileError::Malformed)?);
        }
        let mut text = Zeroizing::new(Vec::with_capacity(lines.iter().map(|l| l.len()).sum()));
        lines.iter().for_each(|l| text.extend_from_slice(l));
        crate::base64::decode(&text).ok_or(KeyFileError::Malformed)
    }
}

/// A decimal number of ASCII digits only.
fn number(text: &[u8]) -> Option<u32> {
    if text.is_empty() || !text.iter().all(u8::is_ascii_digit) {
        return None;
    }
    core::str::from_utf8(text).ok()?.parse().ok()
}

/// Lowercase or uppercase hex digits, two to a byte.
fn hex(text: &[u8]) -> Option<Vec<u8>> {
    let digit = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.chunks(2)
        .map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?))
        .collect()
}

/// `name` for an error, when it looks like the short identifier it should be: a header from a
/// file whose line breaks were lost carries the private lines, which must not reach a log.
fn token(name: &[u8]) -> String {
    let plain = !name.is_empty()
        && name.len() <= 64
        && name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'@' | b'_'));
    if plain {
        String::from_utf8_lossy(name).into_owned()
    } else {
        "(not shown)".to_owned()
    }
}

struct Keys {
    cipher: Zeroizing<Vec<u8>>,
    iv: Zeroizing<Vec<u8>>,
    mac: Zeroizing<Vec<u8>>,
}

fn derive(file: &File, passphrase: &[u8]) -> Result<Keys, KeyFileError> {
    let encrypted = file.encryption != "none";
    if file.version == 3 {
        let Some(a) = &file.argon2 else {
            return Ok(Keys {
                cipher: Zeroizing::default(),
                iv: Zeroizing::default(),
                mac: Zeroizing::default(),
            });
        };
        let out = argon2(a, passphrase)?;
        return Ok(Keys {
            cipher: Zeroizing::new(out[..32].to_vec()),
            iv: Zeroizing::new(out[32..48].to_vec()),
            mac: Zeroizing::new(out[48..].to_vec()),
        });
    }
    // Version 2: the passphrase enters the MAC key only when the file is encrypted.
    let mut mac_key = sha1::Sha1::new();
    mac_key.update(b"putty-private-key-file-mac-key");
    if encrypted {
        mac_key.update(passphrase);
    }
    let mut mac = Zeroizing::new(vec![0; 20]);
    mac_key.finalize_into(
        (&mut mac[..])
            .try_into()
            .expect("a SHA-1 digest is 20 bytes"),
    );
    let mut cipher = Zeroizing::new(Vec::with_capacity(40));
    if encrypted {
        for sequence in 0u32..2 {
            let mut h = sha1::Sha1::new();
            h.update(sequence.to_be_bytes());
            h.update(passphrase);
            let mut digest = Zeroizing::new([0; 20]);
            h.finalize_into(
                (&mut digest[..])
                    .try_into()
                    .expect("a SHA-1 digest is 20 bytes"),
            );
            cipher.extend_from_slice(&digest[..]);
        }
        cipher.truncate(32);
    }
    Ok(Keys {
        cipher,
        iv: Zeroizing::new(vec![0; 16]),
        mac,
    })
}

/// The 80 bytes of key, IV and MAC key Argon2 derives from `passphrase` as `a` says.
fn argon2(a: &Argon2, passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyFileError> {
    let params = argon2::Params::new(a.memory, a.passes, a.threads, Some(80))
        .map_err(|_| KeyFileError::Malformed)?;
    let mut out = Zeroizing::new(vec![0; 80]);
    argon2::Argon2::new(a.flavour, argon2::Version::V0x13, params)
        .hash_password_into(passphrase, &a.salt, &mut out)
        .map_err(|_| KeyFileError::Malformed)?;
    Ok(out)
}

/// Whether the file's MAC covers its headers, its public blob and its decrypted private blob,
/// padding included.
fn mac_matches(file: &File, key: &[u8], private: &[u8]) -> bool {
    let fields: [&[u8]; 5] = [
        file.algorithm.as_bytes(),
        file.encryption.as_bytes(),
        &file.comment,
        &file.public,
        private,
    ];
    let feed = |m: &mut dyn FnMut(&[u8])| {
        for field in fields {
            m(&(field.len() as u32).to_be_bytes());
            m(field);
        }
    };
    if file.version == 2 {
        let mut m = hmac::Hmac::<sha1::Sha1>::new_from_slice(key).expect("any HMAC key length");
        feed(&mut |b| m.update(b));
        m.verify_slice(&file.mac).is_ok()
    } else {
        let mut m = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).expect("any HMAC key length");
        feed(&mut |b| m.update(b));
        m.verify_slice(&file.mac).is_ok()
    }
}

/// The key from the public blob and the verified private blob. Bytes after the private fields
/// are the padding of an encrypted file and are ignored, as PuTTY ignores them.
fn build(algorithm: &str, public: &[u8], private: &[u8]) -> Result<KeyFile, KeyFileError> {
    let invalid = |_| KeyFileError::InvalidKey;
    let mut publ = Reader::new(public);
    if publ.string().map_err(invalid)? != algorithm.as_bytes() {
        return Err(KeyFileError::InvalidKey);
    }
    let mut priv_ = Reader::new(private);
    let key = match algorithm {
        "ssh-rsa" => {
            let e = mpint(&mut publ)?;
            let n = mpint(&mut publ)?;
            let d = mpint(&mut priv_)?;
            let p = mpint(&mut priv_)?;
            let q = mpint(&mut priv_)?;
            mpint(&mut priv_)?;
            KeyFile::rsa(&n, &e, d, p, q).map_err(|_| KeyFileError::InvalidKey)?
        }
        "ssh-ed25519" => {
            let field = priv_.string().map_err(invalid)?;
            if field.len() != 32 {
                return Err(KeyFileError::InvalidKey);
            }
            let mut seed = Zeroizing::new([0; 32]);
            seed.copy_from_slice(field);
            KeyFile::ed25519(seed)
        }
        _ => {
            let curve = match algorithm {
                "ecdsa-sha2-nistp256" => EcdsaCurve::P256,
                "ecdsa-sha2-nistp384" => EcdsaCurve::P384,
                _ => EcdsaCurve::P521,
            };
            KeyFile::ecdsa(curve, mpint(&mut priv_)?).map_err(|_| KeyFileError::InvalidKey)?
        }
    };
    if key.private_key().plain_public_blob() != public {
        return Err(KeyFileError::InvalidKey);
    }
    Ok(key)
}

/// A non-negative mpint, without its leading zero bytes.
fn mpint(r: &mut Reader<'_>) -> Result<Zeroizing<Vec<u8>>, KeyFileError> {
    let bytes = r.string().map_err(|_| KeyFileError::InvalidKey)?;
    if bytes.first().is_some_and(|b| b & 0x80 != 0) {
        return Err(KeyFileError::InvalidKey);
    }
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    Ok(Zeroizing::new(bytes[start..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// acra_client's `PpkKdf` (pointycastle) over the same inputs, a second implementation, since
    /// no Argon2i reference file exists: WinSCP writes only Argon2id.
    #[test]
    fn argon2_matches_an_independent_implementation() {
        for (flavour, want) in [
            (
                argon2::Algorithm::Argon2i,
                "f09524044f9943225b13562eea22c7be42c69af1e318bceaa5a363b8f683722f549c06a39ba2c4dfaff964306a8243261a7f74b6e7fb17dff3bdffbe95f0ad2f8f250dd523617b86fa0088506e293866",
            ),
            (
                argon2::Algorithm::Argon2id,
                "24b3f31caed28f4934ffc5510d0be0612beae941aa4ed218459755907797b8318466de42ff8f7e1432c039773d897ae0eba67c96ea7fa0ad423db6937c39a33a4e7196c1c728644b13fb8ce0dd59e7d6",
            ),
        ] {
            let a = Argon2 {
                flavour,
                memory: 8192,
                passes: 13,
                threads: 1,
                salt: (0..16).collect(),
            };
            let got = argon2(&a, b"correct horse").unwrap();
            assert_eq!(hex(want.as_bytes()).unwrap(), *got, "{flavour:?}");
        }
    }
}
