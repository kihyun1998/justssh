//! Server-side user authentication (RFC 4252), counted the way x/crypto/ssh counts it.

use justssh_wire::{DecodeError, Reader};
use zeroize::Zeroizing;

/// Authentication attempts of any outcome after which the server disconnects.
pub(crate) const MAX_ATTEMPTS: u32 = 128;

/// The service user authentication grants access to.
pub(crate) const CONNECTION: &str = "ssh-connection";

/// The methods offered in `SSH_MSG_USERAUTH_FAILURE`.
pub(crate) const METHODS: &[&str] = &["password"];

/// Attempt counters, and whether a verdict is awaited.
pub(crate) struct ServerAuth {
    /// Failed attempts that end the connection once reached; 0 is no limit.
    max_tries: u32,
    failures: u32,
    attempts: u32,
    none_count: u32,
    pub(crate) pending: bool,
}

/// What a failed attempt leads to.
pub(crate) enum AfterFailure {
    /// Disconnect without a final `SSH_MSG_USERAUTH_FAILURE`.
    TooManyFailures,
    /// Send `SSH_MSG_USERAUTH_FAILURE`, then disconnect.
    FailureThenTooManyAttempts,
    /// Send `SSH_MSG_USERAUTH_FAILURE`.
    Failure,
}

impl ServerAuth {
    pub(crate) fn new(max_tries: u32) -> Self {
        ServerAuth {
            max_tries,
            failures: 0,
            attempts: 0,
            none_count: 0,
            pending: false,
        }
    }

    /// Counts a request with `method` before it is judged.
    pub(crate) fn attempt(&mut self, method: &str) {
        self.attempts += 1;
        if method == "none" {
            self.none_count += 1;
        }
    }

    /// Counts a failed attempt with `method`. The first `none`, sent before any failure, is free.
    pub(crate) fn failed(&mut self, method: &str) -> AfterFailure {
        if self.failures > 0 || method != "none" || self.none_count != 1 {
            self.failures += 1;
        }
        if self.max_tries > 0 && self.failures >= self.max_tries {
            AfterFailure::TooManyFailures
        } else if self.attempts >= MAX_ATTEMPTS {
            AfterFailure::FailureThenTooManyAttempts
        } else {
            AfterFailure::Failure
        }
    }
}

/// An `SSH_MSG_USERAUTH_REQUEST` read in place, so the password in `method_data` is not copied.
pub(crate) struct Request<'a> {
    pub(crate) user: &'a [u8],
    pub(crate) service: &'a str,
    pub(crate) method: &'a str,
    pub(crate) method_data: &'a [u8],
}

/// Reads the request in `payload`, message number included.
pub(crate) fn request(payload: &[u8]) -> Result<Request<'_>, DecodeError> {
    let mut r = Reader::new(payload.get(1..).ok_or(DecodeError::Empty)?);
    Ok(Request {
        user: r.string()?,
        service: r.utf8()?,
        method: r.utf8()?,
        method_data: r.remaining(),
    })
}

/// The password in a `password` request's method data: `boolean FALSE, string password`.
/// A password change request (`TRUE`) is refused as malformed.
pub(crate) fn password(method_data: &[u8]) -> Result<Zeroizing<Vec<u8>>, DecodeError> {
    let mut r = Reader::new(method_data);
    if r.u8()? != 0 {
        return Err(DecodeError::InvalidValue);
    }
    let password = Zeroizing::new(r.string()?.to_vec());
    r.finish()?;
    Ok(password)
}
