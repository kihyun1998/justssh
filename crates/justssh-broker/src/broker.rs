//! The SSH side: downstream connections on the listener, each authenticated against the issued
//! tokens and relayed to the upstream its token names (acwbroker `service/broker`,
//! `service/relay`, `infrastructure/upstream`).

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::time::Duration;

use justssh::{
    Action, ChannelId, Client, ClientConfig, Endpoint, HostKey, InfoRequest, OpenFailureReason,
    Phase, ReplyToken, RequestToken, Server, ServerConfig, Zeroizing,
};
use justssh_tokio::{Accepted, AuthMethod, ClientHandler, Connected, Deadlines, Session};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, sleep_until, timeout};

use crate::issue::Method;
use crate::tokens::{Grant, Tokens};

/// How long a downstream connection has to authenticate.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(180);

/// How long a channel whose upstream half has ended waits for its downstream half.
pub const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// The message a channel the upstream opens is refused with.
const UPSTREAM_OPENS: &str = "acwbroker does not accept upstream-initiated channels";

/// The message a channel the upstream could not be asked about is refused with.
const UPSTREAM_GONE: &str = "upstream channel open failed";

/// Accepts downstream connections until the listener fails, each in a task of its own.
pub async fn serve(listener: TcpListener, host_key: HostKey, tokens: Tokens, dial: Duration) {
    while let Ok((stream, _)) = listener.accept().await {
        let (host_key, tokens) = (host_key.clone(), tokens.clone());
        tokio::spawn(connection(stream, host_key, tokens, dial));
    }
}

/// One downstream connection: a single password attempt, the upstream reached while it is
/// judged, then the relay.
async fn connection(stream: TcpStream, host_key: HostKey, tokens: Tokens, dial: Duration) {
    let mut server = Server::new(
        ServerConfig::builder(host_key)
            .max_auth_tries(NonZeroU32::MIN)
            .build(),
    );
    let deadlines = Deadlines::new().phase(Phase::Auth, HANDSHAKE_TIMEOUT);
    let accepted = justssh_tokio::accept(stream, &mut server, &deadlines, |request| {
        let grant = tokens.authorize(request.password(), request.user());
        async move { upstream(grant?, dial).await }
    })
    .await;
    if let Ok(Accepted::Authenticated { io, value, events }) = accepted {
        relay(Session::new(io, server, events), value).await;
    }
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
/// then keyboard-interactive.
async fn upstream(grant: Grant, dial: Duration) -> Option<Session<TcpStream, Client>> {
    if grant.method != Method::Password {
        return None;
    }
    let password = grant.password?;
    let addr = std::str::from_utf8(&grant.upstream).ok()?;
    let stream = timeout(dial, TcpStream::connect(addr)).await.ok()?.ok()?;
    let mut client = Client::new(ClientConfig::builder(&grant.username).build());
    let methods = [
        AuthMethod::Password(password.clone()),
        AuthMethod::KeyboardInteractive,
    ];
    let connected = justssh_tokio::connect(
        stream,
        &mut client,
        &Deadlines::new(),
        &methods,
        &mut Answers(password),
    )
    .await
    .ok()?;
    match connected {
        Connected::Authenticated { io, events } => Some(Session::new(io, client, events)),
        _ => None,
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
        }
    }
}

type Down = Session<TcpStream, Server>;
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

/// Relays one authenticated downstream connection to its upstream until the downstream ends.
async fn relay(mut down: Down, mut up: Up) {
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
            () = sleep_until(grace.unwrap_or_else(Instant::now)), if grace.is_some() => Step::Grace,
        };
        let result = match step {
            Step::Down(Ok(Some(a))) => {
                from_down(
                    a,
                    &mut down,
                    &mut up,
                    up_alive,
                    &mut pairs,
                    &mut opening,
                    &mut replies,
                )
                .await
            }
            Step::Down(_) => return,
            Step::Up(Ok(Some(Action::Closed(_))) | Ok(None) | Err(_)) => {
                up_alive = false;
                for (&d, p) in pairs.iter_mut() {
                    up_ended(d, p, &mut down).await.ok();
                }
                for (_, d) in opening.drain() {
                    down.reject_channel(d, OpenFailureReason::CONNECT_FAILED, UPSTREAM_GONE)
                        .await
                        .ok();
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
                )
                .await
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
            return;
        }
    }
}

enum Step {
    Down(std::io::Result<Option<Action>>),
    Up(std::io::Result<Option<Action>>),
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
    pairs: &mut HashMap<ChannelId, Pair>,
    opening: &mut HashMap<ChannelId, ChannelId>,
    replies: &mut Replies,
) -> std::io::Result<()> {
    match action {
        Action::ChannelOpenRequest(r) => {
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
                    .await?
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

async fn from_up(
    action: Action,
    down: &mut Down,
    up: &mut Up,
    pairs: &mut HashMap<ChannelId, Pair>,
    up_to_down: &mut HashMap<ChannelId, ChannelId>,
    opening: &mut HashMap<ChannelId, ChannelId>,
    replies: &mut Replies,
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

/// How much of `channel`'s data `s` still holds back for the peer's window.
fn queued<E: Endpoint>(s: &Session<TcpStream, E>, channel: ChannelId) -> usize {
    s.endpoint().channel_info(channel).map_or(0, |i| i.queued())
}
