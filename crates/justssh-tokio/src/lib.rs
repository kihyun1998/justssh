//! Tokio adapter that drives the justssh sans-IO core over TCP.

use std::future::Future;
use std::io;
use std::time::Duration;

use justssh::{Action, Closed, Event, PasswordRequest, Phase, Server};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, timeout_at};

/// How long a connection may take to get past each phase, counted from the start of
/// [`accept`]. A deadline for a phase also bounds every phase before it.
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct Deadlines {
    phases: Vec<(Phase, Duration)>,
}

impl Deadlines {
    /// No deadlines.
    pub fn new() -> Self {
        Deadlines::default()
    }

    /// The connection must have left `phase` within `limit` of starting. x/crypto/ssh's
    /// handshake timeout is `phase(Phase::Auth, …)`.
    pub fn phase(mut self, phase: Phase, limit: Duration) -> Self {
        self.phases.push((phase, limit));
        self
    }

    /// The earliest deadline still binding a connection in `current`.
    fn until(&self, start: Instant, current: Phase) -> Option<Instant> {
        self.phases
            .iter()
            .filter(|(p, _)| rank(current) <= rank(*p))
            .map(|(_, limit)| start + *limit)
            .min()
    }
}

fn rank(phase: Phase) -> u8 {
    match phase {
        Phase::Handshake => 0,
        Phase::Auth => 1,
        Phase::Connected => 2,
        _ => u8::MAX,
    }
}

/// How [`accept`] ended.
#[non_exhaustive]
#[derive(Debug)]
pub enum Accepted<IO, T> {
    /// The client authenticated. `io` and the [`Server`] are positioned at the start of the
    /// connection protocol; `value` is what `authenticate` returned.
    Authenticated { io: IO, value: T },
    /// The connection ended before authentication.
    Closed(Closed),
}

/// Runs `server` over `io` through the handshake and user authentication, and returns as soon
/// as the client is authenticated. Each password attempt is passed to `authenticate`, which
/// accepts it by returning `Some` and may take as long as it needs; the connection waits, and
/// other connections are not held up.
///
/// An I/O error, or the peer closing the stream without `SSH_MSG_DISCONNECT`, is returned as
/// `Err`; `server.phase()` then tells where the connection was.
pub async fn accept<IO, F, Fut, T>(
    mut io: IO,
    server: &mut Server,
    deadlines: &Deadlines,
    mut authenticate: F,
) -> io::Result<Accepted<IO, T>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    F: FnMut(PasswordRequest) -> Fut,
    Fut: Future<Output = Option<T>>,
{
    let start = Instant::now();
    let mut buf = vec![0u8; 32 * 1024];
    let mut accepted = None;
    let mut actions = server.process(Event::Connected);
    loop {
        let deadline = deadlines.until(start, server.phase());
        let mut out = Vec::new();
        let mut pending = None;
        let mut closed = None;
        for action in actions {
            match action {
                Action::Write(bytes) => out.extend_from_slice(&bytes),
                Action::PasswordRequest(request) => pending = Some(request),
                Action::Closed(c) => closed = Some(c),
                _ => {}
            }
        }
        if !out.is_empty() && !write(&mut io, &out, deadline).await? {
            actions = server.process(Event::DeadlineExceeded);
            continue;
        }
        if let Some(closed) = closed {
            return Ok(Accepted::Closed(closed));
        }
        if server.phase() == Phase::Connected
            && let Some(value) = accepted
        {
            return Ok(Accepted::Authenticated { io, value });
        }

        if let Some(request) = pending {
            let verdict = match deadline {
                Some(at) => timeout_at(at, authenticate(request)).await.ok(),
                None => Some(authenticate(request).await),
            };
            actions = match verdict {
                None => server.process(Event::DeadlineExceeded),
                Some(Some(value)) => {
                    accepted = Some(value);
                    server.process(Event::AuthAccepted)
                }
                Some(None) => server.process(Event::AuthRejected),
            };
            continue;
        }

        let read = match deadline {
            Some(at) => timeout_at(at, io.read(&mut buf)).await.ok(),
            None => Some(io.read(&mut buf).await),
        };
        actions = match read {
            None => server.process(Event::DeadlineExceeded),
            Some(n) => match n? {
                0 => return Err(io::ErrorKind::UnexpectedEof.into()),
                n => server.process(Event::Received(&buf[..n])),
            },
        };
    }
}

/// Writes and flushes `bytes`; `false` if `deadline` passed first.
async fn write<IO>(io: &mut IO, bytes: &[u8], deadline: Option<Instant>) -> io::Result<bool>
where
    IO: AsyncWrite + Unpin,
{
    let send = async {
        io.write_all(bytes).await?;
        io.flush().await
    };
    match deadline {
        Some(at) => match timeout_at(at, send).await {
            Ok(r) => r.map(|()| true),
            Err(_) => Ok(false),
        },
        None => send.await.map(|()| true),
    }
}
