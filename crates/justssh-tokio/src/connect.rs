//! The client side: connecting to a server and authenticating to it.

use std::future::Future;
use std::io;

use justssh::{
    Action, Client, Closed, DisconnectReason, Event, InfoRequest, Phase, PrivateKey, Zeroizing,
};
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
    /// `publickey` with each key in turn, until one is accepted or the server stops allowing
    /// the method.
    PublicKeys(Vec<PrivateKey>),
}

impl AuthMethod {
    fn name(&self) -> &'static str {
        match self {
            AuthMethod::Password(_) => "password",
            AuthMethod::KeyboardInteractive => "keyboard-interactive",
            AuthMethod::PublicKeys(_) => PUBLICKEY,
        }
    }
}

const PUBLICKEY: &str = "publickey";

/// The algorithm an RSA certificate refused under `rsa-sha2-*-cert` is offered under again,
/// after the other keys.
const RSA_CERT_COMPAT: &str = "ssh-rsa-cert-v01@openssh.com";

/// The keys of a `publickey` method being tried, the way x/crypto/ssh's `publicKeyCallback`
/// tries its signers.
struct KeyQueue<'a> {
    /// Each key with the algorithm it is to be offered under, or `None` for the one
    /// `server-sig-algs` leads to.
    keys: Vec<(&'a PrivateKey, Option<&'static str>)>,
    /// The number of keys given, before compatibility retries are added.
    given: usize,
    /// The key being tried and the algorithm it was offered under.
    current: usize,
    algorithm: &'static str,
    /// The methods of the last failure the method saw.
    methods: Vec<String>,
}

impl<'a> KeyQueue<'a> {
    fn new(keys: &'a [PrivateKey], methods: Vec<String>) -> Self {
        KeyQueue {
            keys: keys.iter().map(|k| (k, None)).collect(),
            given: keys.len(),
            current: 0,
            algorithm: "",
            methods,
        }
    }

    /// Offers the key at `index`, or reports that none is left.
    fn offer(&mut self, client: &mut Client, index: usize) -> Option<Vec<Action>> {
        let (key, algorithm) = *self.keys.get(index)?;
        self.current = index;
        let sig_algs = client.server_sig_algs();
        self.algorithm = algorithm.unwrap_or_else(|| key.algorithm_for(sig_algs.as_deref()));
        Some(client.auth_publickey_as(key, self.algorithm))
    }

    /// After the server refused the current key without a signature: queues the
    /// compatibility retry of an RSA certificate, and offers the next key.
    fn refused(&mut self, client: &mut Client) -> Option<Vec<Action>> {
        let key = self.keys[self.current].0;
        if self.current < self.given
            && self.algorithm != RSA_CERT_COMPAT
            && key.algorithms().contains(&RSA_CERT_COMPAT)
        {
            self.keys.push((key, Some(RSA_CERT_COMPAT)));
        }
        self.offer(client, self.current + 1)
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
            !self.tried.contains(&m.name())
                && self.allowed.iter().any(|a| a == m.name())
                && !matches!(m, AuthMethod::PublicKeys(keys) if keys.is_empty())
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
    let mut keys: Option<KeyQueue> = None;
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
        let mut key_refused = false;
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
                Action::PublicKeyRefused { .. } => key_refused = true,
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
        let failure = match (keys.as_mut(), failure) {
            (Some(queue), _) if key_refused => match queue.refused(client) {
                Some(next) => {
                    actions = next;
                    continue;
                }
                None => Some((queue.methods.clone(), false)),
            },
            (Some(queue), Some((methods, false))) if methods.iter().any(|m| m == PUBLICKEY) => {
                queue.methods = methods.clone();
                match queue.offer(client, queue.current + 1) {
                    Some(next) => {
                        actions = next;
                        continue;
                    }
                    None => Some((methods, false)),
                }
            }
            (_, failure) => failure,
        };
        if failure.is_some() {
            keys = None;
        }
        if let Some((allowed, partial_success)) = failure {
            actions = match picker.next(allowed, partial_success) {
                Some(AuthMethod::PublicKeys(list)) => {
                    let mut queue = KeyQueue::new(list, picker.allowed.clone());
                    let first = queue.offer(client, 0);
                    keys = Some(queue);
                    first.unwrap_or_default()
                }
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
