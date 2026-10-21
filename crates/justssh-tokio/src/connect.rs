//! The client side: connecting to a server and authenticating to it.

use std::future::Future;
use std::io;

use justssh::{Action, Client, Closed, DisconnectReason, Event, InfoRequest, Phase, Zeroizing};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::time::{Instant, timeout_at};

use crate::{Deadlines, write};

/// Authentication attempts of any outcome after which [`connect`] gives up.
const MAX_TRIED: usize = 64;

/// A way to authenticate, tried by [`connect`] when the server allows it.
#[non_exhaustive]
pub enum AuthMethod {
    Password(Zeroizing<Vec<u8>>),
    /// Keyboard-interactive (RFC 4256), its questions answered by
    /// [`ClientHandler::answer`].
    KeyboardInteractive,
}

impl AuthMethod {
    fn name(&self) -> &'static str {
        match self {
            AuthMethod::Password(_) => "password",
            AuthMethod::KeyboardInteractive => "keyboard-interactive",
        }
    }
}

/// What [`connect`] asks of the consumer while it connects.
pub trait ClientHandler {
    /// Judges the server's host key blob, its signature already verified; `false` ends the
    /// connection.
    fn check_host_key(&mut self, key: &[u8]) -> impl Future<Output = bool>;

    /// The answers to a keyboard-interactive request, one for each question, in order.
    fn answer(&mut self, request: &InfoRequest) -> impl Future<Output = Vec<Zeroizing<Vec<u8>>>>;

    /// A message the server shows before authentication completes, unfiltered. Ignored by
    /// default.
    fn banner(&mut self, message: &[u8]) {
        let _ = message;
    }
}

/// How [`connect`] ended.
#[non_exhaustive]
#[derive(Debug)]
pub enum Connected<IO> {
    /// The server accepted an authentication. `io` and the [`Client`] are positioned at the
    /// start of the connection protocol.
    Authenticated {
        io: IO,
        /// What the server did that was handled along with its acceptance.
        events: Vec<Action>,
    },
    /// No allowed method was left to try, and this side disconnected with
    /// [`DisconnectReason::NO_MORE_AUTH_METHODS_AVAILABLE`].
    NoMethodLeft {
        /// The methods that failed, `none` first, in the order tried.
        tried: Vec<&'static str>,
        /// The methods the server's last failure named.
        allowed: Vec<String>,
    },
    /// The connection ended before authentication otherwise.
    Closed(Closed),
}

/// Which method to try next, the way x/crypto/ssh picks it.
struct Picker<'a> {
    methods: &'a [AuthMethod],
    tried: Vec<&'static str>,
    partial: usize,
    current: &'static str,
    allowed: Vec<String>,
}

impl<'a> Picker<'a> {
    fn new(methods: &'a [AuthMethod]) -> Self {
        Picker {
            methods,
            tried: Vec::new(),
            partial: 0,
            current: "none",
            allowed: Vec::new(),
        }
    }

    /// Records the failure of the current attempt and picks the next method: the first in
    /// order not yet failed that the server allows.
    fn next(&mut self, allowed: Vec<String>, partial_success: bool) -> Option<&'a AuthMethod> {
        if partial_success {
            self.partial += 1;
        } else {
            self.tried.push(self.current);
        }
        self.allowed = allowed;
        if self.tried.len() + self.partial > MAX_TRIED {
            return None;
        }
        let next = self.methods.iter().find(|m| {
            !self.tried.contains(&m.name()) && self.allowed.iter().any(|a| a == m.name())
        })?;
        self.current = next.name();
        Some(next)
    }
}

/// Runs `client` over `io` through the handshake and user authentication, and returns as soon
/// as the server accepts. It tries `none` first, then each of `methods` in order that the
/// server allows and that has not failed. `handler` judges the host key and answers
/// keyboard-interactive questions, and may take as long as it needs.
///
/// An I/O error, or the peer closing the stream without `SSH_MSG_DISCONNECT`, is returned as
/// `Err`; `client.phase()` then tells where the connection was.
pub async fn connect<IO, H>(
    mut io: IO,
    client: &mut Client,
    deadlines: &Deadlines,
    methods: &[AuthMethod],
    handler: &mut H,
) -> io::Result<Connected<IO>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    H: ClientHandler,
{
    let start = Instant::now();
    let mut buf = vec![0u8; 32 * 1024];
    let mut events = Vec::new();
    let mut picker = Picker::new(methods);
    let mut auth_started = false;
    let mut exhausted = false;
    let mut deadline = None;
    let mut actions = client.process(Event::Connected);
    loop {
        if client.phase() != Phase::Closed {
            deadline = deadlines.until(start, client.phase());
        }
        let mut out = Vec::new();
        let mut host_key = None;
        let mut questions = None;
        let mut failure = None;
        let mut closed = None;
        for action in actions {
            match action {
                Action::Write(bytes) => out.extend_from_slice(&bytes),
                Action::VerifyHostKey { key } => host_key = Some(key),
                Action::KeyboardInteractive(request) => questions = Some(request),
                Action::AuthBanner { message } => handler.banner(&message),
                Action::AuthFailure {
                    methods,
                    partial_success,
                } => {
                    questions = None;
                    failure = Some((methods, partial_success));
                }
                Action::Closed(c) => closed = Some(c),
                other => events.push(other),
            }
        }
        if !out.is_empty() && !write(&mut io, &out, deadline).await? {
            let closed = closed.or_else(|| {
                client
                    .process(Event::DeadlineExceeded)
                    .into_iter()
                    .find_map(|a| match a {
                        Action::Closed(c) => Some(c),
                        _ => None,
                    })
            });
            return Ok(Connected::Closed(
                closed.expect("a deadline ends the connection"),
            ));
        }
        if let Some(closed) = closed {
            if exhausted {
                return Ok(Connected::NoMethodLeft {
                    tried: picker.tried,
                    allowed: picker.allowed,
                });
            }
            return Ok(Connected::Closed(closed));
        }
        if client.phase() == Phase::Connected {
            return Ok(Connected::Authenticated { io, events });
        }

        if let Some(key) = host_key {
            actions = match within(deadline, handler.check_host_key(&key)).await {
                None => client.process(Event::DeadlineExceeded),
                Some(true) => client.process(Event::HostKeyAccepted),
                Some(false) => client.process(Event::HostKeyRejected),
            };
            continue;
        }
        if let Some(request) = questions {
            actions = match within(deadline, handler.answer(&request)).await {
                None => client.process(Event::DeadlineExceeded),
                Some(answers) => client.answer_prompts(answers),
            };
            continue;
        }
        if client.phase() == Phase::Auth && !auth_started {
            auth_started = true;
            actions = client.auth_none();
            continue;
        }
        if let Some((allowed, partial_success)) = failure {
            actions = match picker.next(allowed, partial_success) {
                Some(AuthMethod::Password(password)) => client.auth_password(password.clone()),
                Some(AuthMethod::KeyboardInteractive) => client.auth_keyboard_interactive(),
                None => {
                    exhausted = true;
                    client.disconnect(
                        DisconnectReason::NO_MORE_AUTH_METHODS_AVAILABLE,
                        "no supported authentication methods remain",
                    )
                }
            };
            continue;
        }

        let read = within(deadline, io.read(&mut buf)).await;
        actions = match read {
            None => client.process(Event::DeadlineExceeded),
            Some(n) => match n? {
                0 => return Err(io::ErrorKind::UnexpectedEof.into()),
                n => client.process(Event::Received(&buf[..n])),
            },
        };
    }
}

/// `future`'s output, or `None` if `deadline` passed first.
async fn within<F: Future>(deadline: Option<Instant>, future: F) -> Option<F::Output> {
    match deadline {
        Some(at) => timeout_at(at, future).await.ok(),
        None => Some(future.await),
    }
}
