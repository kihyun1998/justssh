//! Tokio adapter that drives the justssh sans-IO core over TCP.

use std::future::Future;
use std::io;
use std::time::Duration;

use justssh::{
    Action, ChannelId, Closed, Event, OpenFailureReason, PasswordRequest, Phase, ReplyToken, Server,
};
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
    Authenticated {
        io: IO,
        value: T,
        /// What the peer did that was handled along with the last authentication step, such as
        /// a channel open sent right behind the request; hand it to [`Session::new`].
        events: Vec<Action>,
    },
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
    let mut events = Vec::new();
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
                other => events.push(other),
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
            return Ok(Accepted::Authenticated { io, value, events });
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

/// An authenticated connection: the stream and its [`Server`], run through the connection
/// protocol. [`next`](Session::next) hands over what the peer does; the other methods send.
///
/// Every method is cancel-safe: output not yet written stays queued and goes out on the next
/// call. A command takes effect when it is called, so a cancelled one is not to be repeated.
pub struct Session<IO> {
    io: IO,
    server: Server,
    buf: Vec<u8>,
    out: Vec<u8>,
    written: usize,
    events: std::collections::VecDeque<Action>,
}

impl<IO> Session<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// A session over the stream and server [`accept`] authenticated, starting with the
    /// `events` it returned.
    pub fn new(io: IO, server: Server, events: Vec<Action>) -> Self {
        Session {
            io,
            server,
            buf: vec![0u8; 32 * 1024],
            out: Vec::new(),
            written: 0,
            events: events.into(),
        }
    }

    pub fn server(&self) -> &Server {
        &self.server
    }

    /// The next thing the peer did — never [`Action::Write`]. [`Action::Closed`] is the last
    /// one; after it, `None`. An I/O error, or the peer closing the stream without
    /// `SSH_MSG_DISCONNECT`, is returned as `Err`.
    pub async fn next(&mut self) -> io::Result<Option<Action>> {
        loop {
            self.flush().await?;
            if let Some(action) = self.events.pop_front() {
                return Ok(Some(action));
            }
            if self.server.phase() == Phase::Closed {
                return Ok(None);
            }
            let n = self.io.read(&mut self.buf).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            let actions = self.server.process(Event::Received(&self.buf[..n]));
            self.absorb(actions);
        }
    }

    pub async fn accept_channel(&mut self, channel: ChannelId, data: Vec<u8>) -> io::Result<()> {
        let actions = self.server.accept_channel(channel, data);
        self.send(actions).await
    }

    pub async fn reject_channel(
        &mut self,
        channel: ChannelId,
        reason: OpenFailureReason,
        description: &str,
    ) -> io::Result<()> {
        let actions = self.server.reject_channel(channel, reason, description);
        self.send(actions).await
    }

    /// Sends `data` and returns once the peer's window has taken all of it, reading meanwhile;
    /// what the peer does in the meantime is kept for [`next`](Session::next).
    pub async fn data(&mut self, channel: ChannelId, data: &[u8]) -> io::Result<()> {
        let actions = self.server.channel_data(channel, data);
        self.send(actions).await?;
        self.drain(channel).await
    }

    /// Sends extended data of type `code` (1 is stderr) and waits like [`data`](Session::data).
    pub async fn extended_data(
        &mut self,
        channel: ChannelId,
        code: u32,
        data: &[u8],
    ) -> io::Result<()> {
        let actions = self.server.channel_extended_data(channel, code, data);
        self.send(actions).await?;
        self.drain(channel).await
    }

    /// Reads until nothing is queued for `channel`, it has closed, or the connection has.
    async fn drain(&mut self, channel: ChannelId) -> io::Result<()> {
        while self.server.phase() != Phase::Closed
            && self
                .server
                .channel_info(channel)
                .is_some_and(|info| info.queued() > 0)
        {
            let n = self.io.read(&mut self.buf).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            let actions = self.server.process(Event::Received(&self.buf[..n]));
            self.send(actions).await?;
        }
        Ok(())
    }

    pub async fn eof(&mut self, channel: ChannelId) -> io::Result<()> {
        let actions = self.server.channel_eof(channel);
        self.send(actions).await
    }

    pub async fn close(&mut self, channel: ChannelId) -> io::Result<()> {
        let actions = self.server.channel_close(channel);
        self.send(actions).await
    }

    /// Closes `channel` now, dropping whatever is still queued for it.
    pub async fn abort(&mut self, channel: ChannelId) -> io::Result<()> {
        let actions = self.server.channel_abort(channel);
        self.send(actions).await
    }

    /// Sends `SSH_MSG_DISCONNECT` and ends the connection; [`next`](Session::next) then
    /// returns the [`Action::Closed`].
    pub async fn disconnect(
        &mut self,
        reason: justssh::DisconnectReason,
        description: &str,
    ) -> io::Result<()> {
        let actions = self.server.disconnect(reason, description);
        self.send(actions).await
    }

    pub async fn request(
        &mut self,
        channel: ChannelId,
        kind: &str,
        want_reply: bool,
        data: Vec<u8>,
    ) -> io::Result<()> {
        let actions = self.server.channel_request(channel, kind, want_reply, data);
        self.send(actions).await
    }

    pub async fn reply(&mut self, token: ReplyToken, ok: bool) -> io::Result<()> {
        let actions = self.server.reply_channel_request(token, ok);
        self.send(actions).await
    }

    /// Reports that `bytes` received on `channel` have been taken; see
    /// [`Server::channel_consumed`].
    pub async fn consumed(&mut self, channel: ChannelId, bytes: u32) -> io::Result<()> {
        let actions = self.server.channel_consumed(channel, bytes);
        self.send(actions).await
    }

    async fn send(&mut self, actions: Vec<Action>) -> io::Result<()> {
        self.absorb(actions);
        self.flush().await
    }

    /// Queues writes as one buffer and everything else as events.
    fn absorb(&mut self, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::Write(bytes) => self.out.extend_from_slice(&bytes),
                other => self.events.push_back(other),
            }
        }
    }

    /// Writes what is queued, one `write` at a time, remembering how far it got.
    async fn flush(&mut self) -> io::Result<()> {
        while self.written < self.out.len() {
            let n = self.io.write(&self.out[self.written..]).await?;
            if n == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            self.written += n;
        }
        self.out.clear();
        self.written = 0;
        self.io.flush().await
    }
}
