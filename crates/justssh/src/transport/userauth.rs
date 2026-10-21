//! User authentication (RFC 4252, RFC 4256): the server's attempt counting, the way
//! x/crypto/ssh counts it, and the client's requests.

use justssh_wire::{DecodeError, Reader, number};
use zeroize::Zeroizing;

use crate::event::{InfoRequest, Prompt};

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

/// A client authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Method {
    None,
    Password,
    KeyboardInteractive,
}

impl Method {
    fn name(self) -> &'static str {
        match self {
            Method::None => "none",
            Method::Password => "password",
            Method::KeyboardInteractive => "keyboard-interactive",
        }
    }
}

/// The client's authentication state.
pub(crate) struct ClientAuth {
    pub(crate) user: Vec<u8>,
    /// The method of the request awaiting the server's answer.
    pub(crate) attempt: Option<Method>,
    /// The number of keyboard-interactive questions awaiting the consumer's answers.
    pub(crate) questions: Option<usize>,
    /// Whether `SSH_MSG_EXT_INFO` has arrived during the outstanding attempt.
    pub(crate) ext_info: bool,
    /// The methods the last `SSH_MSG_USERAUTH_FAILURE` named.
    pub(crate) methods: Vec<String>,
}

impl ClientAuth {
    pub(crate) fn new(user: Vec<u8>) -> Self {
        ClientAuth {
            user,
            attempt: None,
            questions: None,
            ext_info: false,
            methods: Vec::new(),
        }
    }
}

/// A payload that may hold a secret, written into one zeroizing allocation of its final size.
struct SecretPayload(Zeroizing<Vec<u8>>);

impl SecretPayload {
    fn with_len(len: usize) -> Self {
        SecretPayload(Zeroizing::new(Vec::with_capacity(len)))
    }

    fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }

    fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    fn string(&mut self, s: &[u8]) -> &mut Self {
        self.u32(u32::try_from(s.len()).expect("string longer than u32::MAX"));
        self.0.extend_from_slice(s);
        self
    }

    fn finish(self) -> Zeroizing<Vec<u8>> {
        debug_assert_eq!(self.0.len(), self.0.capacity());
        self.0
    }
}

/// An `SSH_MSG_USERAUTH_REQUEST` for `method`; `password` is sent with [`Method::Password`].
pub(crate) fn client_request(user: &[u8], method: Method, password: &[u8]) -> Zeroizing<Vec<u8>> {
    let data = match method {
        Method::None => 0,
        Method::Password => 1 + 4 + password.len(),
        Method::KeyboardInteractive => 8,
    };
    let len = 1 + 4 + user.len() + 4 + CONNECTION.len() + 4 + method.name().len() + data;
    let mut p = SecretPayload::with_len(len);
    p.u8(number::USERAUTH_REQUEST)
        .string(user)
        .string(CONNECTION.as_bytes())
        .string(method.name().as_bytes());
    match method {
        Method::None => {}
        Method::Password => {
            p.u8(0).string(password);
        }
        Method::KeyboardInteractive => {
            p.string(b"").string(b"");
        }
    }
    p.finish()
}

/// An `SSH_MSG_USERAUTH_INFO_RESPONSE` carrying `answers`.
pub(crate) fn info_response(answers: &[Zeroizing<Vec<u8>>]) -> Zeroizing<Vec<u8>> {
    let len = 1 + 4 + answers.iter().map(|a| 4 + a.len()).sum::<usize>();
    let mut p = SecretPayload::with_len(len);
    p.u8(number::USERAUTH_INFO_RESPONSE)
        .u32(u32::try_from(answers.len()).expect("more than u32::MAX answers"));
    for a in answers {
        p.string(a);
    }
    p.finish()
}

/// Reads the `SSH_MSG_USERAUTH_INFO_REQUEST` in `payload`, message number included.
pub(crate) fn info_request(payload: &[u8]) -> Result<InfoRequest, DecodeError> {
    let mut r = Reader::new(payload.get(1..).ok_or(DecodeError::Empty)?);
    let name = r.string()?.to_vec();
    let instruction = r.string()?.to_vec();
    r.string()?;
    let count = r.u32()?;
    let mut prompts = Vec::new();
    for _ in 0..count {
        let text = r.string()?.to_vec();
        let echo = r.bool()?;
        prompts.push(Prompt { text, echo });
    }
    r.finish()?;
    Ok(InfoRequest {
        name,
        instruction,
        prompts,
    })
}
