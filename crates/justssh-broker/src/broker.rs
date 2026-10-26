//! The SSH side: downstream connections on the listener, each authenticated against the issued
//! tokens and relayed to the upstream its token names (acwbroker `service/broker`,
//! `service/relay`, `infrastructure/upstream`).

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use justssh::{
    Action, ChannelId, Client, ClientConfig, Closed, DisconnectReason, Endpoint, Error,
    InfoRequest, OpenFailureReason, Phase, ReplyToken, RequestToken, Server, Zeroizing,
};
use justssh_tokio::{Accepted, AuthMethod, ClientHandler, Connected, Deadlines, Session};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, sleep_until, timeout};

use crate::caller::Caller;
use crate::credential;
use crate::hostkey::HostKeys;
use crate::issue::Method;
use crate::log::{Log, go_duration, quote};
use crate::tokens::{Admission, Conn, Grant, Handle, Shell, Tokens};

/// How long a downstream connection has to authenticate.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(180);

/// How long a channel whose upstream half has ended waits for its downstream half.
pub const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// The message a channel the upstream opens is refused with.
const UPSTREAM_OPENS: &str = "acwbroker does not accept upstream-initiated channels";

/// The message a channel the upstream could not be asked about is refused with.
const UPSTREAM_GONE: &str = "upstream channel open failed";

/// How many bytes of a name the client chose a log line carries.
const MAX_LOGGED_NAME: usize = 32;

/// How much of each direction a connection keeps until it is authenticated.
const KEX_CAPTURE: usize = 16 << 10;

/// Measures who is on the other end of a connection, given its remote address.
pub type Probe = Arc<dyn Fn(SocketAddr) -> Caller + Send + Sync>;

/// What every connection's lines carry and count: the log, the listener's address, and how
/// many connections are authenticated.
#[derive(Clone)]
struct Logs {
    log: Log,
    listener: String,
    live: Arc<AtomicI64>,
}

/// Accepts downstream connections until the listener fails, each in a task of its own, each
/// caller measured by `probe`, and logs what happens on them to `log`.
pub async fn serve(
    listener: TcpListener,
    host_keys: HostKeys,
    tokens: Tokens,
    dial: Duration,
    probe: Probe,
    log: Log,
) {
    let logs = Logs {
        log,
        listener: listener
            .local_addr()
            .map_or_else(|_| "?".to_owned(), |a| a.to_string()),
        live: Arc::default(),
    };
    while let Ok((stream, addr)) = listener.accept().await {
        let (host_keys, tokens, probe) = (host_keys.clone(), tokens.clone(), probe.clone());
        tokio::spawn(connection(
            stream,
            addr,
            host_keys,
            tokens,
            dial,
            probe,
            logs.clone(),
        ));
    }
}

/// One downstream connection: a single password attempt, the upstream reached while it is
/// judged, then the relay.
async fn connection(
    stream: TcpStream,
    addr: SocketAddr,
    host_keys: HostKeys,
    tokens: Tokens,
    dial: Duration,
    probe: Probe,
    logs: Logs,
) {
    let mut server = Server::new(
        host_keys
            .config(&logs.log)
            .await
            .max_auth_tries(NonZeroU32::MIN)
            .build(),
    );
    let deadlines = Deadlines::new().phase(Phase::Auth, HANDSHAKE_TIMEOUT);
    let (io, kex) = Recorded::new(stream);
    let accepted = justssh_tokio::accept(io, &mut server, &deadlines, |request| {
        let caller = probe(addr);
        let verdict = caller.verdict(tokens.app());
        let grant = tokens.authorize(request.password(), request.user(), &caller);
        let user = quote(request.user());
        let logs = logs.clone();
        async move {
            let l = &logs.listener;
            let who = &caller.described;
            let grant = match grant {
                Ok(grant) => grant,
                Err(refusal) => {
                    logs.log.warn(
                        format!(
                            "authentication failed: listener={l} caller={who} verdict={verdict} user={user} reason={refusal}"
                        ),
                        &[],
                    );
                    return None;
                }
            };
            let admitted = match grant.admission {
                Admission::Claim => "claim",
                Admission::Pin => "pin",
                Admission::Descendant => "descendant",
                Admission::Grace => "grace",
            };
            match upstream(grant, dial).await {
                Ok(up) => {
                    let live = logs.live.fetch_add(1, Ordering::SeqCst) + 1;
                    logs.log.info(
                        format!(
                            "authenticated: listener={l} caller={who} verdict={verdict} admitted={admitted} live={live}"
                        ),
                        &[],
                    );
                    Some(up)
                }
                Err(e) => {
                    logs.log
                        .error(format!("upstream authentication failed: {e}"), &[]);
                    None
                }
            }
        }
    })
    .await;
    let l = &logs.listener;
    let failed = |why: String| {
        logs.log
            .error(format!("downstream handshake failed: {why}"), &[]);
        logs.log.error(
            format!(
                "downstream handshake offers: listener={l} {}",
                kex.describe()
            ),
            &[],
        );
    };
    match accepted {
        Ok(Accepted::Authenticated { io, value, events }) => {
            kex.stop();
            let (up, conn) = value;
            let why = relay(Session::new(io, server, events), up, &conn, &logs).await;
            let live = logs.live.fetch_sub(1, Ordering::SeqCst) - 1;
            logs.log.info(
                format!("closed: listener={l} live={live} reason={why}"),
                &[],
            );
        }
        Ok(Accepted::Closed(Closed::Local {
            error: Error::DeadlineExceeded,
            ..
        })) => logs.log.error(
            format!(
                "downstream handshake timed out after {}: listener={l}",
                go_duration(HANDSHAKE_TIMEOUT)
            ),
            &[],
        ),
        Ok(Accepted::Closed(c)) => failed(closed_text(&c)),
        Ok(_) => failed("ended".to_owned()),
        Err(e) => failed(e.to_string()),
    }
}

/// Why a connection ended before it was authenticated, in words.
fn closed_text(c: &Closed) -> String {
    match c {
        Closed::Local { error, .. } => error.to_string(),
        Closed::Requested { .. } => "disconnected".to_owned(),
        Closed::Peer { description, .. } => {
            format!("the client disconnected: {}", description.escape_debug())
        }
        _ => "closed".to_owned(),
    }
}

/// A downstream stream that keeps the first bytes each way until the handshake is done, so a
/// failed one can say what both sides offered.
struct Recorded<S> {
    inner: S,
    kex: Kex,
}

/// The bytes a [`Recorded`] stream kept: in from the client, out to it.
#[derive(Clone, Default)]
struct Kex(Arc<Mutex<Option<Kept>>>);

/// What a connection kept: in from the client, out to it.
type Kept = (Vec<u8>, Vec<u8>);

impl<S> Recorded<S> {
    fn new(inner: S) -> (Self, Kex) {
        let kex = Kex(Arc::new(Mutex::new(Some(Default::default()))));
        (
            Recorded {
                inner,
                kex: kex.clone(),
            },
            kex,
        )
    }
}

impl Kex {
    fn keep(&self, inbound: bool, bytes: &[u8]) {
        let mut kept = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((i, o)) = kept.as_mut() {
            let b = if inbound { i } else { o };
            let room = KEX_CAPTURE.saturating_sub(b.len());
            b.extend_from_slice(&bytes[..bytes.len().min(room)]);
        }
    }

    /// Ends the keeping and drops what was kept: the lists explain only a failure.
    fn stop(&self) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// What each side offered, or why that cannot be said.
    fn describe(&self) -> String {
        let kept = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let (i, o) = kept
            .as_ref()
            .map_or((&[][..], &[][..]), |(i, o)| (&i[..], &o[..]));
        format!(
            "client {}; server {}",
            describe_kexinit(i),
            describe_kexinit(o)
        )
    }
}

/// One direction's version line and the name-lists of its first packet, which must be a
/// KEXINIT.
fn describe_kexinit(mut b: &[u8]) -> String {
    let mut version = None;
    while let Some(i) = b.iter().position(|&c| c == b'\n') {
        let line = &b[..i];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        b = &b[i + 1..];
        if line.starts_with(b"SSH-") {
            version = Some(go_q(line));
            break;
        }
    }
    let Some(version) = version else {
        return "version=? kexinit=?".to_owned();
    };
    let unread = |b: &[u8]| {
        let head: String = b.iter().take(32).map(|x| format!("{x:02x}")).collect();
        format!("version={version} kexinit=? after={} head={head}", b.len())
    };
    if b.len() < 6 {
        return unread(b);
    }
    let plen = u32::from_be_bytes(b[..4].try_into().expect("four")) as usize;
    let pad = usize::from(b[4]);
    if plen > b.len() - 4 || plen < pad + 1 {
        return unread(b);
    }
    let payload = &b[5..4 + plen - pad];
    if payload.len() < 17 || payload[0] != 20 {
        return unread(b);
    }
    let mut rest = &payload[17..];
    let mut out = format!("version={version}");
    for name in [
        "kex",
        "hostkey",
        "cipher_c2s",
        "cipher_s2c",
        "mac_c2s",
        "mac_s2c",
    ] {
        let Some((n, tail)) = rest.split_first_chunk::<4>() else {
            break;
        };
        let n = u32::from_be_bytes(*n) as usize;
        if n > tail.len() {
            break;
        }
        out += &format!(" {name}={}", String::from_utf8_lossy(&tail[..n]));
        rest = &tail[n..];
    }
    out
}

/// `s` as Go's `%q` writes it.
fn go_q(s: &[u8]) -> String {
    quote(s)
}

impl<S: AsyncRead + Unpin> AsyncRead for Recorded<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = r {
            self.kex.keep(true, &buf.filled()[before..]);
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Recorded<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = r {
            self.kex.keep(false, &buf[..n]);
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The downstream channels a connection has seen, numbered from 1 for its log lines, and how
/// many are open.
struct Channels<'a> {
    logs: &'a Logs,
    ids: HashMap<ChannelId, (u64, Vec<u8>)>,
    next: u64,
}

impl Channels<'_> {
    fn opened(&mut self, d: ChannelId, kind: &[u8]) {
        self.next += 1;
        self.ids.insert(d, (self.next, kind.to_vec()));
        let mut m = format!(
            "channel: listener={} id={} type=",
            self.logs.listener, self.next
        )
        .into_bytes();
        m.extend_from_slice(kind);
        m.extend(format!(" opened chans={}", self.ids.len()).as_bytes());
        self.logs.log.info(m, &[]);
    }

    fn closed(&mut self, d: ChannelId) {
        let Some((id, kind)) = self.ids.remove(&d) else {
            return;
        };
        let mut m = format!("channel: listener={} id={id} type=", self.logs.listener).into_bytes();
        m.extend_from_slice(&kind);
        m.extend(format!(" closed chans={}", self.ids.len()).as_bytes());
        self.logs.log.info(m, &[]);
    }

    fn id(&self, d: ChannelId) -> u64 {
        self.ids.get(&d).map_or(0, |(id, _)| *id)
    }
}

/// `name` cut to what a log line carries.
fn clip(name: &[u8]) -> &[u8] {
    &name[..name.len().min(MAX_LOGGED_NAME)]
}

/// Answers every keyboard-interactive question with the password, and takes any host key.
struct Answers(Zeroizing<Vec<u8>>);

impl ClientHandler for Answers {
    async fn check_host_key(&mut self, _key: &[u8]) -> bool {
        true
    }

    async fn answer(&mut self, request: &InfoRequest) -> Vec<Zeroizing<Vec<u8>>> {
        request.prompts().iter().map(|_| self.0.clone()).collect()
    }
}

/// The upstream `grant` names, connected within `dial` and authenticated with its password,
/// then keyboard-interactive, or with its key, with the connection the grant counts; or why it
/// was not.
async fn upstream(
    grant: Grant,
    dial: Duration,
) -> Result<(Session<TcpStream, Client>, Conn), String> {
    let credential = grant.credential;
    let (methods, password) = match credential.method {
        Method::Password => {
            let password = credential
                .password
                .ok_or("upstream: the credential was wiped")?;
            let methods = vec![
                AuthMethod::Password(password.clone()),
                AuthMethod::KeyboardInteractive,
            ];
            (methods, password)
        }
        _ => {
            if credential.private_key.is_none() {
                return Err("upstream: the credential was wiped".to_owned());
            }
            let key = credential::private_key(&credential).map_err(|r| r.cause)?;
            (
                vec![AuthMethod::PublicKeys(vec![key])],
                Zeroizing::default(),
            )
        }
    };
    let addr = String::from_utf8_lossy(&grant.upstream).into_owned();
    let stream = match timeout(dial, TcpStream::connect(&addr)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => return Err(format!("dial tcp {addr}: {e}")),
        Err(_) => return Err(format!("dial tcp {addr}: i/o timeout")),
    };
    let mut client = Client::new(ClientConfig::builder(&grant.username).build());
    let connected = justssh_tokio::connect(
        stream,
        &mut client,
        &Deadlines::new(),
        &methods,
        &mut Answers(password),
    )
    .await
    .map_err(|e| format!("upstream {addr}: {e}"))?;
    match connected {
        Connected::Authenticated { io, events } => {
            Ok((Session::new(io, client, events), grant.conn))
        }
        Connected::NoMethodLeft { tried, .. } => Err(format!(
            "upstream {addr}: unable to authenticate, attempted methods [{}], no supported methods remain",
            tried.join(" ")
        )),
        Connected::Closed(c) => Err(format!("upstream {addr}: {}", closed_text(&c))),
        _ => Err(format!("upstream {addr}: not authenticated")),
    }
}

/// One downstream channel and its upstream twin.
struct Pair {
    up: ChannelId,
    /// Received upstream and queued downstream, not yet given back to the upstream.
    from_up: u32,
    /// Received downstream and queued upstream, not yet given back to the downstream.
    from_down: u32,
    eof_down: bool,
    eof_up: bool,
    /// The upstream half has closed.
    up_done: bool,
    /// The downstream half has sent EOF or closed.
    down_done: bool,
    /// When the downstream half is closed without waiting further.
    grace: Option<Instant>,
    /// The token's shell, when this channel holds it.
    shell: Option<Shell>,
    /// A request on it was refused: the upstream half is closing, and the downstream half
    /// closes once it has.
    refused: bool,
}

impl Pair {
    fn new(up: ChannelId) -> Self {
        Pair {
            up,
            from_up: 0,
            from_down: 0,
            eof_down: false,
            eof_up: false,
            up_done: false,
            down_done: false,
            grace: None,
            shell: None,
            refused: false,
        }
    }
}

type Down = Session<Recorded<TcpStream>, Server>;
type Up = Session<TcpStream, Client>;

/// Requests passed on to one side, by the token its answer will carry, with the reply owed to
/// the side they came from.
#[derive(Default)]
struct Replies {
    /// Sent upstream for the downstream.
    to_down: HashMap<RequestToken, ReplyToken>,
    /// Sent downstream for the upstream.
    to_up: HashMap<RequestToken, ReplyToken>,
    global_to_down: HashMap<RequestToken, justssh::GlobalReplyToken>,
    global_to_up: HashMap<RequestToken, justssh::GlobalReplyToken>,
}

/// Relays one authenticated downstream connection to its upstream until the downstream ends,
/// holding its channels to the policy of the token `conn` counts against, and ending the
/// upstream when that token is disposed of. Says how it ended: `clean` when the client
/// closed the stream, `error` otherwise.
async fn relay(down: Down, up: Up, conn: &Conn, logs: &Logs) -> &'static str {
    let handle = conn.handle();
    let mut channels = Channels {
        logs,
        ids: HashMap::new(),
        next: 0,
    };
    let why = relay_until_end(down, up, conn, handle, &mut channels).await;
    let open: Vec<ChannelId> = channels.ids.keys().copied().collect();
    for d in open {
        channels.closed(d);
    }
    why
}

async fn relay_until_end(
    mut down: Down,
    mut up: Up,
    conn: &Conn,
    handle: &Handle,
    channels: &mut Channels<'_>,
) -> &'static str {
    let mut pairs: HashMap<ChannelId, Pair> = HashMap::new();
    let mut up_to_down: HashMap<ChannelId, ChannelId> = HashMap::new();
    let mut opening: HashMap<ChannelId, ChannelId> = HashMap::new();
    let mut replies = Replies::default();
    let mut up_alive = true;
    loop {
        let grace = pairs.values().filter_map(|p| p.grace).min();
        let step = tokio::select! {
            a = down.next() => Step::Down(a),
            a = up.next(), if up_alive => Step::Up(a),
            () = conn.disposed(), if up_alive => Step::Disposed,
            () = sleep_until(grace.unwrap_or_else(Instant::now)), if grace.is_some() => Step::Grace,
        };
        let result = match step {
            Step::Down(Ok(Some(Action::Closed(_)))) => return "error",
            Step::Down(Ok(Some(a))) => {
                if let Action::ChannelClosed { channel } = &a {
                    channels.closed(*channel);
                }
                from_down(
                    a,
                    &mut down,
                    &mut up,
                    up_alive,
                    handle,
                    &mut pairs,
                    &mut opening,
                    &mut replies,
                    channels,
                )
                .await
            }
            Step::Down(Ok(None)) => return "clean",
            Step::Down(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => return "clean",
            Step::Down(Err(_)) => return "error",
            Step::Up(Ok(Some(Action::Closed(_))) | Ok(None) | Err(_)) => {
                up_alive = false;
                for (&d, p) in pairs.iter_mut() {
                    up_ended(d, p, &mut down).await.ok();
                }
                for (_, d) in opening.drain() {
                    down.reject_channel(d, OpenFailureReason::CONNECT_FAILED, UPSTREAM_GONE)
                        .await
                        .ok();
                    channels.closed(d);
                }
                Ok(())
            }
            Step::Up(Ok(Some(a))) => {
                from_up(
                    a,
                    &mut down,
                    &mut up,
                    &mut pairs,
                    &mut up_to_down,
                    &mut opening,
                    &mut replies,
                    channels,
                )
                .await
            }
            Step::Disposed => {
                up.disconnect(DisconnectReason::BY_APPLICATION, "")
                    .await
                    .ok();
                Ok(())
            }
            Step::Grace => {
                let now = Instant::now();
                let due: Vec<ChannelId> = pairs
                    .iter()
                    .filter(|(_, p)| p.grace.is_some_and(|g| g <= now))
                    .map(|(&d, _)| d)
                    .collect();
                let mut r = Ok(());
                for d in due {
                    if let Some(p) = pairs.remove(&d) {
                        up_to_down.remove(&p.up);
                        r = r.and(finish(d, &p, &mut down, &mut up).await);
                    }
                }
                r
            }
        };
        if result.is_err() {
            return "error";
        }
    }
}

enum Step {
    Down(std::io::Result<Option<Action>>),
    Up(std::io::Result<Option<Action>>),
    Disposed,
    Grace,
}

/// Closes both halves of a pair whose upstream half has ended.
async fn finish(d: ChannelId, p: &Pair, down: &mut Down, up: &mut Up) -> std::io::Result<()> {
    down.close(d).await?;
    up.close(p.up).await
}

/// The upstream half of `p` has closed: the downstream half gets its EOF, then is closed once it
/// is done too, or after [`CLOSE_GRACE`].
async fn up_ended(d: ChannelId, p: &mut Pair, down: &mut Down) -> std::io::Result<()> {
    p.up_done = true;
    if !p.eof_down {
        p.eof_down = true;
        down.eof(d).await?;
    }
    if p.down_done {
        down.close(d).await?;
        p.grace = None;
    } else {
        p.grace = Some(Instant::now() + CLOSE_GRACE);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn from_down(
    action: Action,
    down: &mut Down,
    up: &mut Up,
    up_alive: bool,
    handle: &Handle,
    pairs: &mut HashMap<ChannelId, Pair>,
    opening: &mut HashMap<ChannelId, ChannelId>,
    replies: &mut Replies,
    channels: &mut Channels<'_>,
) -> std::io::Result<()> {
    match action {
        Action::ChannelOpenRequest(r) => {
            channels.opened(r.channel(), r.kind().as_bytes());
            let opened = match up_alive {
                true => up.open_channel(r.kind(), r.data().to_vec()).await?,
                false => None,
            };
            match opened {
                Some(u) => {
                    opening.insert(u, r.channel());
                }
                None => {
                    down.reject_channel(
                        r.channel(),
                        OpenFailureReason::CONNECT_FAILED,
                        UPSTREAM_GONE,
                    )
                    .await?;
                    channels.closed(r.channel());
                }
            }
        }
        Action::ChannelData { channel, data } => match pairs.get_mut(&channel) {
            Some(p) if !p.eof_up => {
                up.queue_data(p.up, &data).await?;
                p.from_down += data.len() as u32;
                if queued(up, p.up) == 0 {
                    down.consumed(channel, std::mem::take(&mut p.from_down))
                        .await?;
                }
            }
            _ => down.consumed(channel, data.len() as u32).await?,
        },
        Action::ChannelExtendedData {
            channel,
            code,
            data,
        } => match pairs.get_mut(&channel) {
            Some(p) if !p.eof_up => {
                up.queue_extended_data(p.up, code, &data).await?;
                p.from_down += data.len() as u32;
                if queued(up, p.up) == 0 {
                    down.consumed(channel, std::mem::take(&mut p.from_down))
                        .await?;
                }
            }
            _ => down.consumed(channel, data.len() as u32).await?,
        },
        Action::ChannelEof { channel } | Action::ChannelClosed { channel } => {
            if let Some(p) = pairs.get_mut(&channel) {
                p.down_done = true;
                if !p.eof_up {
                    p.eof_up = true;
                    up.eof(p.up).await?;
                }
                if p.up_done {
                    let p = pairs.remove(&channel).expect("present");
                    finish(channel, &p, down, up).await?;
                }
            }
        }
        Action::ChannelRequest(r) => {
            let kind = r.kind().as_bytes();
            let l = &channels.logs.listener;
            let id = channels.id(r.channel());
            if let Some(p) = pairs.get(&r.channel())
                && !p.refused
                && matches!(kind, b"shell" | b"exec" | b"subsystem")
            {
                let mut m = format!("request: listener={l} id={id} type=").into_bytes();
                m.extend_from_slice(kind);
                if kind == b"subsystem" {
                    m.extend(b" name=");
                    m.extend_from_slice(only_string(r.data()).map_or(&b"?"[..], clip));
                }
                channels.logs.log.info(m, &[]);
            }
            let refusal = match pairs.get_mut(&r.channel()) {
                Some(p) if p.refused => Some(None),
                Some(p) => refuses(p, handle, kind, r.data()).map(Some),
                None => None,
            };
            if let Some(why) = refusal {
                let p = pairs.get_mut(&r.channel()).expect("present");
                if let Some(why) = why {
                    let mut m = format!("request refused: listener={l} id={id} type=").into_bytes();
                    m.extend_from_slice(kind);
                    m.extend(format!(" reason={why}").as_bytes());
                    channels.logs.log.warn(m, &[]);
                }
                if let Some(reply) = r.reply() {
                    down.reply(reply, false).await?;
                }
                p.refused = true;
                p.eof_up = true;
                up.abort(p.up).await?;
                return Ok(());
            }
            let token = match pairs.get(&r.channel()) {
                Some(p) => {
                    up.request(p.up, r.kind(), r.want_reply(), r.data().to_vec())
                        .await?
                }
                None => None,
            };
            match (token, r.reply()) {
                (Some(t), Some(reply)) => {
                    replies.to_down.insert(t, reply);
                }
                (None, Some(reply)) => down.reply(reply, false).await?,
                _ => {}
            }
        }
        Action::ChannelRequestReply { token, ok, .. } => {
            if let Some(reply) = replies.to_up.remove(&token) {
                up.reply(reply, ok).await?;
            }
        }
        Action::GlobalRequest(r) => {
            let kind = r.kind().as_bytes();
            if !kind.starts_with(b"keepalive@") {
                let mut m = format!("global request: listener={} type=", channels.logs.listener)
                    .into_bytes();
                m.extend_from_slice(clip(kind));
                channels.logs.log.info(m, &[]);
            }
            let token = match up_alive {
                true => {
                    up.global_request(r.kind(), r.want_reply(), r.data().to_vec())
                        .await?
                }
                false => None,
            };
            match (token, r.reply()) {
                (Some(t), Some(reply)) => {
                    replies.global_to_down.insert(t, reply);
                }
                (None, Some(reply)) => down.reply_global(reply, false, Vec::new()).await?,
                _ => {}
            }
        }
        Action::GlobalRequestReply { token, ok, data } => {
            if let Some(reply) = replies.global_to_up.remove(&token) {
                up.reply_global(reply, ok, data).await?;
            }
        }
        Action::ChannelDrained { channel } => {
            if let Some(p) = pairs.get_mut(&channel)
                && queued(down, channel) == 0
            {
                up.consumed(p.up, std::mem::take(&mut p.from_up)).await?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn from_up(
    action: Action,
    down: &mut Down,
    up: &mut Up,
    pairs: &mut HashMap<ChannelId, Pair>,
    up_to_down: &mut HashMap<ChannelId, ChannelId>,
    opening: &mut HashMap<ChannelId, ChannelId>,
    replies: &mut Replies,
    channels: &mut Channels<'_>,
) -> std::io::Result<()> {
    let twin = |u: &ChannelId| up_to_down.get(u).copied();
    match action {
        Action::ChannelOpened { channel, .. } => {
            if let Some(d) = opening.remove(&channel) {
                down.accept_channel(d, Vec::new()).await?;
                pairs.insert(d, Pair::new(channel));
                up_to_down.insert(channel, d);
            }
        }
        Action::ChannelOpenFailed {
            channel,
            reason,
            description,
        } => {
            if let Some(d) = opening.remove(&channel) {
                down.reject_channel(d, reason, description).await?;
                channels.closed(d);
            }
        }
        Action::ChannelOpenRequest(r) => {
            up.reject_channel(
                r.channel(),
                OpenFailureReason::ADMINISTRATIVELY_PROHIBITED,
                UPSTREAM_OPENS,
            )
            .await?;
        }
        Action::ChannelData { channel, data } => {
            if let Some(d) = twin(&channel)
                && let Some(p) = pairs.get_mut(&d)
            {
                down.queue_data(d, &data).await?;
                p.from_up += data.len() as u32;
                if queued(down, d) == 0 {
                    up.consumed(channel, std::mem::take(&mut p.from_up)).await?;
                }
            }
        }
        Action::ChannelExtendedData {
            channel,
            code,
            data,
        } => {
            if let Some(d) = twin(&channel)
                && let Some(p) = pairs.get_mut(&d)
            {
                down.queue_extended_data(d, code, &data).await?;
                p.from_up += data.len() as u32;
                if queued(down, d) == 0 {
                    up.consumed(channel, std::mem::take(&mut p.from_up)).await?;
                }
            }
        }
        Action::ChannelEof { channel } => {
            if let Some(d) = twin(&channel)
                && let Some(p) = pairs.get_mut(&d)
                && !p.eof_down
            {
                p.eof_down = true;
                down.eof(d).await?;
            }
        }
        Action::ChannelClosed { channel } => {
            if let Some(d) = up_to_down.remove(&channel)
                && let Some(p) = pairs.get_mut(&d)
            {
                if p.refused {
                    pairs.remove(&d);
                    return down.abort(d).await;
                }
                up_ended(d, p, down).await?;
                if p.grace.is_none() {
                    pairs.remove(&d);
                }
            }
        }
        Action::ChannelRequest(r) => {
            let token = match twin(&r.channel()) {
                Some(d) => {
                    down.request(d, r.kind(), r.want_reply(), r.data().to_vec())
                        .await?
                }
                None => None,
            };
            match (token, r.reply()) {
                (Some(t), Some(reply)) => {
                    replies.to_up.insert(t, reply);
                }
                (None, Some(reply)) => up.reply(reply, false).await?,
                _ => {}
            }
        }
        Action::ChannelRequestReply { token, ok, .. } => {
            if let Some(reply) = replies.to_down.remove(&token) {
                down.reply(reply, ok).await?;
            }
        }
        Action::GlobalRequest(r) => {
            let token = down
                .global_request(r.kind(), r.want_reply(), r.data().to_vec())
                .await?;
            match (token, r.reply()) {
                (Some(t), Some(reply)) => {
                    replies.global_to_up.insert(t, reply);
                }
                (None, Some(reply)) => up.reply_global(reply, false, Vec::new()).await?,
                _ => {}
            }
        }
        Action::GlobalRequestReply { token, ok, data } => {
            if let Some(reply) = replies.global_to_down.remove(&token) {
                down.reply_global(reply, ok, data).await?;
            }
        }
        Action::ChannelDrained { channel } => {
            if let Some(d) = twin(&channel)
                && let Some(p) = pairs.get_mut(&d)
                && queued(up, channel) == 0
            {
                down.consumed(d, std::mem::take(&mut p.from_down)).await?;
            }
        }
        Action::VerifyHostKey { .. } => up.answer_host_key(true).await?,
        _ => {}
    }
    Ok(())
}

/// Why the token behind `handle` refuses the request `kind` with `data` on the channel of
/// `p`, when it does: a file transfer the token does not allow, or a shell while the token's
/// one shell is open elsewhere. A shell it allows is taken for `p` here.
fn refuses(p: &mut Pair, handle: &Handle, kind: &[u8], data: &[u8]) -> Option<&'static str> {
    if is_file_transfer(kind, data) && !handle.file_transfer_allowed() {
        return Some("the node does not allow file transfer");
    }
    if kind == b"shell" && p.shell.is_none() {
        p.shell = handle.open_shell();
        if p.shell.is_none() {
            return Some("a shell is already open on this token");
        }
    }
    None
}

/// Whether a channel request starts a file transfer: the subsystem `sftp`, or a command whose
/// first word's base name is `scp` or `sftp-server`. A payload that is not exactly one string
/// starts none.
fn is_file_transfer(kind: &[u8], data: &[u8]) -> bool {
    let Some(arg) = only_string(data) else {
        return false;
    };
    match kind {
        b"subsystem" => arg == b"sftp",
        b"exec" => {
            let command = String::from_utf8_lossy(arg);
            let Some(first) = command.split_whitespace().next() else {
                return false;
            };
            let base = first.trim_end_matches('/').rsplit('/').next().unwrap_or("");
            matches!(base, "scp" | "sftp-server")
        }
        _ => false,
    }
}

/// The string `data` holds when it holds one and nothing after it.
fn only_string(data: &[u8]) -> Option<&[u8]> {
    let (len, rest) = data.split_first_chunk::<4>()?;
    (rest.len() == u32::from_be_bytes(*len) as usize).then_some(rest)
}

/// How much of `channel`'s data `s` still holds back for the peer's window.
fn queued<S: AsyncRead + AsyncWrite + Unpin, E: Endpoint>(
    s: &Session<S, E>,
    channel: ChannelId,
) -> usize {
    s.endpoint().channel_info(channel).map_or(0, |i| i.queued())
}
