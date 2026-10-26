//! The key an ISSUE's credential authenticates upstream with, read as acwbroker's
//! `upstream.authMethods` reads it, and why one that cannot be read is refused, as its `Check`
//! and the handoff's `refusalFor` name it.

use justssh::PrivateKey;
use justssh_keys::{KeyFile, KeyFileError, certificate_from_line};
use zeroize::Zeroizing;

use crate::issue::Method;

/// How an ISSUE authenticates upstream and the secrets it does so with. The secrets are zeroed
/// when dropped, and `Debug` does not show them.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Credential {
    pub method: Method,
    pub password: Option<Zeroizing<Vec<u8>>>,
    pub private_key: Option<Zeroizing<Vec<u8>>>,
    pub passphrase: Option<Zeroizing<Vec<u8>>>,
    pub certificate: Option<Zeroizing<Vec<u8>>>,
}

impl Credential {
    /// Drops every secret.
    pub fn wipe(&mut self) {
        (
            self.password,
            self.private_key,
            self.passphrase,
            self.certificate,
        ) = (None, None, None, None);
    }
}

/// Why a credential was refused, as the ERROR frame's reason record carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reason {
    WrongPassphrase = 1,
    PassphraseRequired = 2,
    UnsupportedKey = 3,
    Malformed = 4,
}

impl Reason {
    /// The reason record's byte.
    pub fn code(self) -> u8 {
        self as u8
    }

    /// The ERROR frame's message, acwbroker's `Reason.String`.
    pub fn message(self) -> &'static str {
        match self {
            Reason::WrongPassphrase => "wrong passphrase",
            Reason::PassphraseRequired => "passphrase required",
            Reason::UnsupportedKey => "unsupported private key",
            Reason::Malformed => "unreadable private key or certificate",
        }
    }

    /// acwbroker's error for it, which its log puts before the cause.
    pub fn error(self) -> &'static str {
        match self {
            Reason::WrongPassphrase => {
                "acwbroker: the private key did not open with the passphrase given"
            }
            Reason::PassphraseRequired => {
                "acwbroker: the private key is encrypted and no passphrase was given"
            }
            Reason::UnsupportedKey => {
                "acwbroker: the private key is in a form this build cannot use"
            }
            Reason::Malformed => "acwbroker: the private key or certificate could not be read",
        }
    }
}

/// A credential that cannot authenticate: the reason the app is told, and the cause the log
/// is.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Refused {
    pub reason: Reason,
    pub cause: String,
}

/// Reads the credential as a dial will and drops what it built.
pub fn check(credential: &Credential) -> Result<(), Refused> {
    match credential.method {
        Method::Password => Ok(()),
        _ => private_key(credential).map(drop),
    }
}

/// The secret's bytes, or none.
fn bytes(secret: &Option<Zeroizing<Vec<u8>>>) -> &[u8] {
    secret.as_deref().map_or(&[], |s| &s[..])
}

/// The key a key or certificate credential signs with, under its certificate for the latter;
/// an empty passphrase is none.
pub fn private_key(credential: &Credential) -> Result<PrivateKey, Refused> {
    let text = bytes(&credential.private_key);
    let passphrase = Some(bytes(&credential.passphrase)).filter(|p| !p.is_empty());
    let ppk = is_ppk(text);
    let key = KeyFile::read(text, passphrase)
        .map_err(|e| refused(e, ppk, passphrase.is_some()))?
        .private_key()
        .clone();
    if credential.method != Method::Certificate {
        return Ok(key);
    }
    let malformed = |cause: String| Refused {
        reason: Reason::Malformed,
        cause,
    };
    let blob = certificate_from_line(bytes(&credential.certificate))
        .map_err(|e| malformed(format!("upstream: parsing certificate: {e}")))?;
    key.with_certificate(blob)
        .map_err(|e| malformed(format!("upstream: binding certificate to key: {e}")))
}

/// acwbroker's `ppk.IsPPK`.
fn is_ppk(text: &[u8]) -> bool {
    let start = text
        .iter()
        .position(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .unwrap_or(text.len());
    text[start..].starts_with(b"PuTTY-User-Key-File-")
}

/// acwbroker's `classify`.
fn refused(e: KeyFileError, ppk: bool, passphrase: bool) -> Refused {
    let reason = match e {
        KeyFileError::PassphraseNeeded => Reason::PassphraseRequired,
        KeyFileError::WrongPassphrase => Reason::WrongPassphrase,
        KeyFileError::MacMismatch if passphrase => Reason::WrongPassphrase,
        KeyFileError::UnsupportedEncryption(_)
        | KeyFileError::UnsupportedKeyType(_)
        | KeyFileError::UnsupportedVersion(_)
        | KeyFileError::KdfTooCostly
            if ppk =>
        {
            Reason::UnsupportedKey
        }
        _ => Reason::Malformed,
    };
    let what = if ppk {
        "reading PuTTY private key"
    } else if passphrase {
        "decrypting private key"
    } else {
        "parsing private key"
    };
    Refused {
        reason,
        cause: format!("upstream: {what}: {e}"),
    }
}
