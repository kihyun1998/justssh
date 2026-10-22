//! A relay in the shape of acwbroker's, on two `Session`s in one task: upstream output to a
//! downstream that does not consume for a while, with upstream channel keepalives forwarded and
//! answered meanwhile, and the upstream window given back only as the downstream takes data.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use justssh::{
    Action, ChannelId, Client, ClientConfig, HostKey, InfoRequest, ReplyToken, Server,
    ServerConfig, Zeroizing,
};
use justssh_tokio::{Accepted, AuthMethod, ClientHandler, Connected, Deadlines, Session};
use tokio::io::DuplexStream;
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(60);
const OUTPUT: usize = 8 << 20;
const KEEPALIVES: usize = 7;

struct AcceptAll;

impl ClientHandler for AcceptAll {
    async fn check_host_key(&mut self, _key: &[u8]) -> bool {
        true
    }

    async fn answer(&mut self, _request: &InfoRequest) -> Vec<Zeroizing<Vec<u8>>> {
        Vec::new()
    }
}

fn host_key() -> HostKey {
    HostKey::ed25519_from_seed(Zeroizing::new([7; 32]))
}

async fn server_session(io: DuplexStream) -> Session<DuplexStream, Server> {
    let mut server = Server::new(ServerConfig::builder(host_key()).build());
    let Accepted::Authenticated { io, events, .. } =
        justssh_tokio::accept(io, &mut server, &Deadlines::new(), |_| async { Some(()) })
            .await
            .unwrap()
    else {
        panic!("not authenticated");
    };
    Session::new(io, server, events)
}

async fn client_session(io: DuplexStream, window: u32) -> Session<DuplexStream, Client> {
    let mut client = Client::new(ClientConfig::builder(b"u").channel_window(window).build());
    let Connected::Authenticated { io, events } = justssh_tokio::connect(
        io,
        &mut client,
        &Deadlines::new(),
        &[AuthMethod::Password(Zeroizing::new(b"pw".to_vec()))],
        &mut AcceptAll,
    )
    .await
    .unwrap() else {
        panic!("not authenticated");
    };
    Session::new(io, client, events)
}

/// The upstream: on `exec`, prints [`OUTPUT`] bytes with a channel keepalive wanting a reply
/// after each MiB but the last, then exit status 0, EOF and close. Returns the keepalives
/// answered, and how many of them before `consuming` was set.
async fn upstream(io: DuplexStream, consuming: Arc<AtomicBool>) -> (usize, usize) {
    let mut s = server_session(io).await;
    let (mut exec, mut printed, mut asked) = (None::<ChannelId>, 0, 0);
    let (mut answered, mut stalled) = (0, 0);
    let chunk = vec![b'u'; 32 * 1024];
    loop {
        if let Some(channel) = exec {
            while printed < OUTPUT
                && s.endpoint()
                    .channel_info(channel)
                    .is_some_and(|i| i.queued() < 256 * 1024)
            {
                s.queue_data(channel, &chunk).await.unwrap();
                printed += chunk.len();
                if printed % (1 << 20) == 0 && printed < OUTPUT && asked < KEEPALIVES {
                    asked += 1;
                    s.request(channel, "keepalive@openssh.com", true, Vec::new())
                        .await
                        .unwrap();
                }
                if printed == OUTPUT {
                    s.request(channel, "exit-status", false, vec![0; 4])
                        .await
                        .unwrap();
                    s.eof(channel).await.unwrap();
                    s.close(channel).await.unwrap();
                }
            }
        }
        match s.next().await {
            Ok(Some(Action::ChannelOpenRequest(r))) => {
                s.accept_channel(r.channel(), Vec::new()).await.unwrap();
            }
            Ok(Some(Action::ChannelRequest(r))) => {
                if r.kind() == "exec" {
                    exec = Some(r.channel());
                }
                if let Some(token) = r.reply() {
                    s.reply(token, r.kind() == "exec").await.unwrap();
                }
            }
            Ok(Some(Action::ChannelRequestReply { ok: true, .. })) => {
                answered += 1;
                stalled += usize::from(!consuming.load(Ordering::SeqCst));
            }
            Ok(Some(Action::Closed(_)) | None) | Err(_) => return (answered, stalled),
            Ok(Some(_)) => {}
        }
    }
}

/// The downstream client, with a 256 KiB channel window: runs `exec`, takes nothing for two
/// seconds from the first data while answering requests,
/// then sets `consuming` and consumes everything. Returns the output and the exit status.
async fn downstream(io: DuplexStream, consuming: Arc<AtomicBool>) -> (usize, Option<u32>) {
    let mut s = client_session(io, 256 * 1024).await;
    let channel = s
        .open_channel("session", Vec::new())
        .await
        .unwrap()
        .unwrap();
    let mut first_data = None::<tokio::time::Instant>;
    let (mut received, mut unconsumed, mut status) = (0, 0u32, None);
    loop {
        let next = if first_data.is_none_or(|t| t.elapsed() < Duration::from_secs(2)) {
            match timeout(Duration::from_millis(50), s.next()).await {
                Ok(n) => n.unwrap(),
                Err(_) => continue,
            }
        } else {
            consuming.store(true, Ordering::SeqCst);
            if unconsumed > 0 {
                s.consumed(channel, unconsumed).await.unwrap();
                unconsumed = 0;
            }
            s.next().await.unwrap()
        };
        match next {
            Some(Action::ChannelOpened { .. }) => {
                let mut cmd = 5u32.to_be_bytes().to_vec();
                cmd.extend(b"print");
                s.request(channel, "exec", true, cmd).await.unwrap();
            }
            Some(Action::ChannelData { data, .. }) => {
                first_data.get_or_insert_with(tokio::time::Instant::now);
                received += data.len();
                unconsumed += data.len() as u32;
            }
            Some(Action::ChannelRequest(r)) => {
                if r.kind() == "exit-status" {
                    status = Some(u32::from_be_bytes(r.data().try_into().unwrap()));
                }
                if let Some(token) = r.reply() {
                    s.reply(token, true).await.unwrap();
                }
            }
            Some(Action::ChannelClosed { .. }) | Some(Action::Closed(_)) | None => {
                return (received, status);
            }
            Some(_) => {}
        }
    }
}

/// The relay, one task: the downstream's channel becomes an upstream channel; upstream output
/// is queued downstream and the upstream window given back once the downstream has taken it;
/// requests cross both ways with their replies. Returns the most output that waited downstream.
async fn relay(down_io: DuplexStream, up_io: DuplexStream) -> usize {
    let mut down = server_session(down_io).await;
    let mut up = client_session(up_io, 2 << 20).await;
    let (mut down_ch, mut up_ch) = (None::<ChannelId>, None::<ChannelId>);
    let mut held = 0u32;
    let mut most = 0usize;
    // Upstream request tokens awaiting the downstream's reply, and the other way.
    let mut to_up: HashMap<justssh::RequestToken, ReplyToken> = HashMap::new();
    let mut to_down: HashMap<justssh::RequestToken, ReplyToken> = HashMap::new();
    loop {
        tokio::select! {
            a = down.next() => match a.unwrap() {
                Some(Action::ChannelOpenRequest(r)) => {
                    down_ch = Some(r.channel());
                    up_ch = up.open_channel(r.kind(), r.data().to_vec()).await.unwrap();
                }
                Some(Action::ChannelRequest(r)) => {
                    let token = up
                        .request(up_ch.unwrap(), r.kind(), r.want_reply(), r.data().to_vec())
                        .await
                        .unwrap();
                    if let (Some(t), Some(reply)) = (token, r.reply()) {
                        to_down.insert(t, reply);
                    }
                }
                Some(Action::ChannelRequestReply { token, ok, .. }) => {
                    if let Some(reply) = to_up.remove(&token) {
                        up.reply(reply, ok).await.unwrap();
                    }
                }
                Some(Action::ChannelDrained { channel }) => {
                    if down.endpoint().channel_info(channel).is_some_and(|i| i.queued() == 0) {
                        up.consumed(up_ch.unwrap(), held).await.unwrap();
                        held = 0;
                    }
                }
                Some(Action::ChannelClosed { .. }) | Some(Action::Closed(_)) | None => return most,
                Some(_) => {}
            },
            a = up.next() => match a.unwrap() {
                Some(Action::ChannelOpened { .. }) => {
                    down.accept_channel(down_ch.unwrap(), Vec::new()).await.unwrap();
                }
                Some(Action::ChannelData { data, .. }) => {
                    let ch = down_ch.unwrap();
                    down.queue_data(ch, &data).await.unwrap();
                    held += data.len() as u32;
                    let queued = down.endpoint().channel_info(ch).map_or(0, |i| i.queued());
                    most = most.max(queued);
                    if queued == 0 {
                        up.consumed(up_ch.unwrap(), held).await.unwrap();
                        held = 0;
                    }
                }
                Some(Action::ChannelRequest(r)) => {
                    let token = down
                        .request(down_ch.unwrap(), r.kind(), r.want_reply(), r.data().to_vec())
                        .await
                        .unwrap();
                    if let (Some(t), Some(reply)) = (token, r.reply()) {
                        to_up.insert(t, reply);
                    }
                }
                Some(Action::ChannelRequestReply { token, ok, .. }) => {
                    if let Some(reply) = to_down.remove(&token) {
                        down.reply(reply, ok).await.unwrap();
                    }
                }
                Some(Action::ChannelEof { .. }) => down.eof(down_ch.unwrap()).await.unwrap(),
                Some(Action::ChannelClosed { .. }) => down.close(down_ch.unwrap()).await.unwrap(),
                Some(Action::Closed(_)) | None => return most,
                Some(_) => {}
            },
        }
    }
}

#[tokio::test]
async fn a_relay_answers_upstream_keepalives_while_a_stalled_downstream_holds_output_back() {
    let (down_client, down_server) = tokio::io::duplex(1 << 16);
    let (up_client, up_server) = tokio::io::duplex(1 << 16);
    let consuming = Arc::new(AtomicBool::new(false));
    let up = tokio::spawn(upstream(up_server, consuming.clone()));
    let relay = tokio::spawn(relay(down_server, up_client));
    let (received, status) = timeout(LIMIT, downstream(down_client, consuming))
        .await
        .expect("the downstream hung");
    let most = timeout(LIMIT, relay)
        .await
        .expect("the relay hung")
        .unwrap();
    let (answered, stalled) = timeout(LIMIT, up)
        .await
        .expect("the upstream hung")
        .unwrap();
    assert_eq!((received, status), (OUTPUT, Some(0)));
    assert_eq!(answered, KEEPALIVES);
    assert!(
        stalled >= 2,
        "{stalled} keepalives answered while the downstream stalled"
    );
    assert!(most <= 3 << 20, "{most} bytes waited downstream");
}
