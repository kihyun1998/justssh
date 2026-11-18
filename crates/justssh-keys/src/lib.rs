//! Private key files for justssh: OpenSSH private keys read, with or without a passphrase, and
//! written, PuTTY's PPK files and PEM keys read, each as a [`KeyFile`] that yields the core's
//! [`PrivateKey`]; and certificates given as `authorized_keys` lines.

mod authorized;
mod base64;
mod openssh;
mod pem;
mod ppk;

use core::fmt;

use justssh::{EcdsaCurve, KeyError, PrivateKey, Zeroizing};

/// A private key as a key file holds it: its material, kept in types that zeroize on drop, and
/// its comment.
#[derive(Clone)]
pub struct KeyFile {
    secret: Secret,
    key: PrivateKey,
    comment: Vec<u8>,
}

#[derive(Clone)]
enum Secret {
    Ed25519(Zeroizing<[u8; 32]>),
    Ecdsa(Zeroizing<Vec<u8>>),
    Rsa {
        d: Zeroizing<Vec<u8>>,
        iqmp: Zeroizing<Vec<u8>>,
        p: Zeroizing<Vec<u8>>,
        q: Zeroizing<Vec<u8>>,
    },
}

impl KeyFile {
    /// An `ssh-ed25519` key from its 32-byte secret seed, with no comment.
    pub fn ed25519(seed: Zeroizing<[u8; 32]>) -> Self {
        KeyFile {
            key: PrivateKey::ed25519(seed.clone()),
            secret: Secret::Ed25519(seed),
            comment: Vec::new(),
        }
    }

    /// An `ecdsa-sha2-nistp*` key from its big-endian secret scalar, with no comment.
    pub fn ecdsa(curve: EcdsaCurve, scalar: Zeroizing<Vec<u8>>) -> Result<Self, KeyError> {
        Ok(KeyFile {
            key: PrivateKey::ecdsa(curve, scalar.clone())?,
            secret: Secret::Ecdsa(scalar),
            comment: Vec::new(),
        })
    }

    /// An `ssh-rsa` key from its big-endian modulus, public and private exponents and primes,
    /// with no comment.
    pub fn rsa(
        n: &[u8],
        e: &[u8],
        d: Zeroizing<Vec<u8>>,
        p: Zeroizing<Vec<u8>>,
        q: Zeroizing<Vec<u8>>,
    ) -> Result<Self, KeyError> {
        let key = PrivateKey::rsa(n, e, d.clone(), p.clone(), q.clone())?;
        let iqmp = crt_coefficient(&p, &q).ok_or(KeyError::InvalidKey)?;
        Ok(KeyFile {
            key,
            secret: Secret::Rsa { d, iqmp, p, q },
            comment: Vec::new(),
        })
    }

    /// The key with `comment`, which an OpenSSH file stores beside it.
    pub fn with_comment(mut self, comment: impl Into<Vec<u8>>) -> Self {
        self.comment = comment.into();
        self
    }

    /// The comment stored beside the key, empty if none.
    pub fn comment(&self) -> &[u8] {
        &self.comment
    }

    /// The key to authenticate or serve with.
    pub fn private_key(&self) -> &PrivateKey {
        &self.key
    }

    /// Reads an OpenSSH private key file (`-----BEGIN OPENSSH PRIVATE KEY-----`), decrypting it
    /// with `passphrase` when it is encrypted.
    pub fn from_openssh(text: &[u8], passphrase: Option<&[u8]>) -> Result<Self, KeyFileError> {
        openssh::decode(text, passphrase)
    }

    /// Reads a PEM private key: PKCS#1 (`RSA PRIVATE KEY`), PKCS#8 (`PRIVATE KEY`) or SEC1
    /// (`EC PRIVATE KEY`), decrypting a legacy encrypted block (`Proc-Type`, `DEK-Info`) with
    /// `passphrase`.
    pub fn from_pem(text: &[u8], passphrase: Option<&[u8]>) -> Result<Self, KeyFileError> {
        pem::decode(text, passphrase)
    }

    /// Reads a key file of whichever format it is, as acwbroker tells them apart: PuTTY's by its
    /// first line, and otherwise the first PEM block, an OpenSSH key or another PEM key.
    pub fn read(text: &[u8], passphrase: Option<&[u8]>) -> Result<Self, KeyFileError> {
        let start = text
            .iter()
            .position(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
            .unwrap_or(text.len());
        if text[start..].starts_with(b"PuTTY-User-Key-File-") {
            return Self::from_ppk(text, passphrase);
        }
        match pem::first_block(text) {
            Some(block) if block.label == b"OPENSSH PRIVATE KEY" => {
                Self::from_openssh(text, passphrase)
            }
            _ => Self::from_pem(text, passphrase),
        }
    }

    /// Reads a PuTTY private key file (`PuTTY-User-Key-File-2` or `-3`), decrypting it with
    /// `passphrase` when it is encrypted; a passphrase given for one that is not is not used.
    pub fn from_ppk(text: &[u8], passphrase: Option<&[u8]>) -> Result<Self, KeyFileError> {
        ppk::decode(text, passphrase)
    }

    /// The key as an unencrypted OpenSSH private key file.
    pub fn to_openssh(&self) -> Zeroizing<String> {
        openssh::encode(self)
    }
}

/// The OpenSSH certificate on an `authorized_keys` line, such as the `-cert.pub` file
/// `ssh-keygen -s` writes, for [`PrivateKey::with_certificate`]: the first line that holds a key,
/// past blank and `#` lines and any options, whose declared type must match the certificate's.
pub fn certificate_from_line(text: &[u8]) -> Result<Vec<u8>, KeyFileError> {
    authorized::certificate(text)
}

impl fmt::Debug for KeyFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyFile")
            .field("comment", &String::from_utf8_lossy(&self.comment))
            .finish_non_exhaustive()
    }
}

/// `q⁻¹ mod p`, the CRT coefficient an OpenSSH RSA key stores, big-endian.
fn crt_coefficient(p: &[u8], q: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    use num_bigint_dig::{ModInverse, Sign};
    use zeroize::Zeroize;
    let (mut p, mut q) = (secret_uint(p), secret_uint(q));
    let inverse = (&q).mod_inverse(&p);
    p.zeroize();
    q.zeroize();
    let mut inverse = inverse?;
    let bytes = (inverse.sign() == Sign::Plus).then(|| Zeroizing::new(inverse.to_bytes_be().1));
    inverse.zeroize();
    bytes
}

/// A secret big-endian integer, reversed in a zeroizing buffer so that no plain copy is left.
pub(crate) fn secret_uint(be: &[u8]) -> rsa::BigUint {
    let mut le = Zeroizing::new(be.to_vec());
    le.reverse();
    rsa::BigUint::from_bytes_le(&le)
}

/// Why a key file was not read.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyFileError {
    /// The text is not a key file of this format.
    NotThisFormat,
    /// The file does not follow its format.
    Malformed,
    /// The key is encrypted and no passphrase was given.
    PassphraseNeeded,
    /// A passphrase was given for a key that is not encrypted.
    NotEncrypted,
    /// The passphrase does not decrypt the key.
    WrongPassphrase,
    /// The MAC of a file that is not encrypted does not match it.
    MacMismatch,
    /// The key is encrypted with a cipher or key derivation this crate does not read.
    UnsupportedEncryption(String),
    /// The key derivation asks for more rounds than are allowed.
    TooManyRounds(u32),
    /// The file holds more than one key.
    MultipleKeys,
    /// The key is of a type this crate does not read, such as `ssh-dss`.
    UnsupportedKeyType(String),
    /// The file is of a version of its format this crate does not read.
    UnsupportedVersion(u32),
    /// The key derivation asks for more memory or work than is allowed.
    KdfTooCostly,
    /// The key material does not form a valid key, or its public half does not match it.
    InvalidKey,
}

impl fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyFileError::NotThisFormat => f.write_str("not a key file of this format"),
            KeyFileError::Malformed => f.write_str("malformed private key file"),
            KeyFileError::PassphraseNeeded => {
                f.write_str("the key is encrypted; a passphrase is needed")
            }
            KeyFileError::NotEncrypted => f.write_str("the key is not encrypted"),
            KeyFileError::WrongPassphrase => f.write_str("incorrect passphrase"),
            KeyFileError::MacMismatch => f.write_str("the key file does not verify"),
            KeyFileError::UnsupportedEncryption(name) => {
                write!(f, "unsupported encryption {name:?}")
            }
            KeyFileError::TooManyRounds(n) => {
                write!(f, "{n} key derivation rounds exceed the maximum")
            }
            KeyFileError::MultipleKeys => f.write_str("more than one key in the file"),
            KeyFileError::UnsupportedKeyType(name) => write!(f, "unsupported key type {name:?}"),
            KeyFileError::UnsupportedVersion(v) => write!(f, "unsupported key file version {v}"),
            KeyFileError::KdfTooCostly => {
                f.write_str("the key derivation asks for more work than allowed")
            }
            KeyFileError::InvalidKey => f.write_str("invalid private key"),
        }
    }
}

impl std::error::Error for KeyFileError {}
