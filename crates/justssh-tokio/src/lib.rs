//! Tokio adapter that drives the justssh sans-IO core over TCP.

mod connect;

pub use connect::{AuthMethod, ClientHandler, Connected, connect};

use std::future::Future;
use std::io;
use std::time::Duration;

use justssh::{
    Action, ChannelId, Closed, Endpoint, Event, GlobalReplyToken, OpenFailureReason,
    PasswordRequest, Phase, ReplyToken, RequestToken, Server,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, timeout_at};

/// How long a connection may take to get past each phase, counted from the start of
/// [`accept`] or [`connect`]. A deadline for a phase also bounds every phase before it.
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
    let mut deadline = None;
    let mut actions = server.process(Event::Connected);
    loop {
        if server.phase() != Phase::Closed {
            deadline = deadlines.until(start, server.phase());
        }
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
            let closed = closed.or_else(|| {
                server
                    .process(Event::DeadlineExceeded)
                    .into_iter()
                    .find_map(|a| match a {
                        Action::Closed(c) => Some(c),
                        _ => None,
                    })
            });
            return Ok(Accepted::Closed(
                closed.expect("a deadline ends the connection"),
            ));
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

/// An authenticated connection: the stream and its [`Server`] or [`Client`](justssh::Client), run
/// through the connection protocol. [`next`](Session::next) hands over what the peer does; the
/// other methods send.
///
/// Every method is cancel-safe: output not yet written stays queued and goes out on the next
/// call. A command takes effect when it is called, so a cancelled one is not to be repeated.
pub struct Session<IO, E = Server> {
    io: IO,
    endpoint: E,
    buf: Vec<u8>,
    out: Vec<u8>,
    written: usize,
    events: std::collections::VecDeque<Action>,
}

impl<IO, E> Session<IO, E>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    E: Endpoint,
{
    /// A session over the stream and endpoint that [`accept`] or [`connect`] authenticated,
    /// starting with the `events` it returned.
    pub fn new(io: IO, endpoint: E, events: Vec<Action>) -> Self {
        Session {
            io,
            endpoint,
            buf: vec![0u8; 32 * 1024],
            out: Vec::new(),
            written: 0,
            events: events.into(),
        }
    }

    pub fn endpoint(&self) -> &E {
        &self.endpoint
    }

    /// Opens a channel of type `kind`; the peer's answer comes from [`next`](Session::next) as
    /// [`Action::ChannelOpened`] or [`Action::ChannelOpenFailed`].
    pub async fn open_channel(
        &mut self,
        kind: impl AsRef<[u8]>,
        data: Vec<u8>,
    ) -> io::Result<Option<ChannelId>> {
        let (channel, actions) = self.endpoint.open_channel(kind.as_ref(), data);
        self.send(actions).await?;
        Ok(channel)
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
            if self.endpoint.phase() == Phase::Closed {
                return Ok(None);
            }
            let n = self.io.read(&mut self.buf).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            let actions = self.endpoint.process(Event::Received(&self.buf[..n]));
            self.absorb(actions);
        }
    }

    pub async fn accept_channel(&mut self, channel: ChannelId, data: Vec<u8>) -> io::Result<()> {
        let actions = self.endpoint.accept_channel(channel, data);
        self.send(actions).await
    }

    pub async fn reject_channel(
        &mut self,
        channel: ChannelId,
        reason: OpenFailureReason,
        description: &str,
    ) -> io::Result<()> {
        let actions = self.endpoint.reject_channel(channel, reason, description);
        self.send(actions).await
    }

    /// Queues `data` and sends what the peer's window allows, without waiting for the rest;
    /// [`Action::ChannelDrained`] from [`next`](Session::next) reports when what waited has gone.
    /// `ChannelInfo::queued` tells how much waits, which is the consumer's to bound.
    pub async fn queue_data(&mut self, channel: ChannelId, data: &[u8]) -> io::Result<()> {
        let actions = self.endpoint.channel_data(channel, data);
        self.send(actions).await
    }

    /// [`queue_data`](Session::queue_data) for extended data of type `code`.
    pub async fn queue_extended_data(
        &mut self,
        channel: ChannelId,
        code: u32,
        data: &[u8],
    ) -> io::Result<()> {
        let actions = self.endpoint.channel_extended_data(channel, code, data);
        self.send(actions).await
    }

    /// Sends `data` and returns once the peer's window has taken all of it, reading meanwhile;
    /// what the peer does in the meantime is kept for [`next`](Session::next).
    pub async fn data(&mut self, channel: ChannelId, data: &[u8]) -> io::Result<()> {
        let actions = self.endpoint.channel_data(channel, data);
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
        let actions = self.endpoint.channel_extended_data(channel, code, data);
        self.send(actions).await?;
        self.drain(channel).await
    }

    /// Reads until nothing is queued for `channel`, it has closed, the connection has, or a key
    /// re-exchange waits for the host key to be judged.
    async fn drain(&mut self, channel: ChannelId) -> io::Result<()> {
        while self.endpoint.phase() != Phase::Closed
            && !self
                .events
                .iter()
                .any(|a| matches!(a, Action::VerifyHostKey { .. }))
            && self
                .endpoint
                .channel_info(channel)
                .is_some_and(|info| info.queued() > 0)
        {
            let n = self.io.read(&mut self.buf).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            let actions = self.endpoint.process(Event::Received(&self.buf[..n]));
            self.send(actions).await?;
        }
        Ok(())
    }

    /// Starts a key re-exchange, as the endpoint's `rekey`. A timer that rekeys every so often
    /// calls this.
    pub async fn rekey(&mut self) -> io::Result<()> {
        let actions = self.endpoint.rekey();
        self.send(actions).await
    }

    /// Answers the [`Action::VerifyHostKey`] a client's key re-exchange handed over from
    /// [`next`](Session::next): `accept` takes the key and the exchange goes on; otherwise the
    /// connection ends. Until it is answered nothing more from the peer is handled. Accepting without
    /// checking takes any key, a different one included, as x/crypto/ssh's callback would.
    pub async fn answer_host_key(&mut self, accept: bool) -> io::Result<()> {
        let event = if accept {
            Event::HostKeyAccepted
        } else {
            Event::HostKeyRejected
        };
        let actions = self.endpoint.process(event);
        self.send(actions).await
    }

    pub async fn eof(&mut self, channel: ChannelId) -> io::Result<()> {
        let actions = self.endpoint.channel_eof(channel);
        self.send(actions).await
    }

    pub async fn close(&mut self, channel: ChannelId) -> io::Result<()> {
        let actions = self.endpoint.channel_close(channel);
        self.send(actions).await
    }

    /// Closes `channel` now, dropping whatever is still queued for it.
    pub async fn abort(&mut self, channel: ChannelId) -> io::Result<()> {
        let actions = self.endpoint.channel_abort(channel);
        self.send(actions).await
    }

    /// Sends `SSH_MSG_DISCONNECT` and ends the connection; [`next`](Session::next) then
    /// returns the [`Action::Closed`].
    pub async fn disconnect(
        &mut self,
        reason: justssh::DisconnectReason,
        description: &str,
    ) -> io::Result<()> {
        let actions = self.endpoint.disconnect(reason, description);
        self.send(actions).await
    }

    /// Sends a channel request; when it wants a reply, the token returned comes back with it
    /// from [`next`](Session::next) in [`Action::ChannelRequestReply`].
    pub async fn request(
        &mut self,
        channel: ChannelId,
        kind: impl AsRef<[u8]>,
        want_reply: bool,
        data: Vec<u8>,
    ) -> io::Result<Option<RequestToken>> {
        let (token, actions) =
            self.endpoint
                .channel_request(channel, kind.as_ref(), want_reply, data);
        self.send(actions).await?;
        Ok(token)
    }

    pub async fn reply(&mut self, token: ReplyToken, ok: bool) -> io::Result<()> {
        let actions = self.endpoint.reply_channel_request(token, ok);
        self.send(actions).await
    }

    /// Sends a global request; when it wants a reply, the token returned comes back with it
    /// from [`next`](Session::next) in [`Action::GlobalRequestReply`].
    pub async fn global_request(
        &mut self,
        kind: impl AsRef<[u8]>,
        want_reply: bool,
        data: Vec<u8>,
    ) -> io::Result<Option<RequestToken>> {
        let (token, actions) = self
            .endpoint
            .global_request(kind.as_ref(), want_reply, data);
        self.send(actions).await?;
        Ok(token)
    }

    pub async fn reply_global(
        &mut self,
        token: GlobalReplyToken,
        ok: bool,
        data: Vec<u8>,
    ) -> io::Result<()> {
        let actions = self.endpoint.reply_global_request(token, ok, data);
        self.send(actions).await
    }

    /// Reports that `bytes` received on `channel` have been taken; see
    /// [`Server::channel_consumed`].
    pub async fn consumed(&mut self, channel: ChannelId, bytes: u32) -> io::Result<()> {
        let actions = self.endpoint.channel_consumed(channel, bytes);
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
