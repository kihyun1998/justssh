//! Two justssh `Session`s on one small in-memory pipe: both writing more than it holds at once,
//! and calls cancelled while their output waits.

use std::time::Duration;

use justssh::{
    Action, ChannelId, Client, ClientConfig, Endpoint, HostKey, InfoRequest, Server, ServerConfig,
    Zeroizing,
};
use justssh_tokio::{Accepted, AuthMethod, ClientHandler, Connected, Deadlines, Session};
use tokio::io::DuplexStream;
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(30);
const PIPE: usize = 64 << 10;

struct AcceptAll;

impl ClientHandler for AcceptAll {
    async fn check_host_key(&mut self, _key: &[u8]) -> bool {
        true
    }

    async fn answer(&mut self, _request: &InfoRequest) -> Vec<Zeroizing<Vec<u8>>> {
        Vec::new()
    }
}

/// A server and a client session on a pipe of [`PIPE`] bytes, with one session channel open
/// between them: the server's id for it, then the client's.
async fn pair() -> (
    (Session<DuplexStream, Server>, ChannelId),
    (Session<DuplexStream, Client>, ChannelId),
) {
    let (client_io, server_io) = tokio::io::duplex(PIPE);
    let server = async {
        let mut server = Server::new(
            ServerConfig::builder(HostKey::ed25519_from_seed(Zeroizing::new([7; 32]))).build(),
        );
        let Accepted::Authenticated { io, events, .. } =
            justssh_tokio::accept(server_io, &mut server, &Deadlines::new(), |_| async {
                Some(())
            })
            .await
            .unwrap()
        else {
            panic!("not authenticated");
        };
        let mut s = Session::new(io, server, events);
        loop {
            if let Some(Action::ChannelOpenRequest(r)) = s.next().await.unwrap() {
                s.accept_channel(r.channel(), Vec::new()).await.unwrap();
                return (s, r.channel());
            }
        }
    };
    let client = async {
        let mut client = Client::new(ClientConfig::builder(b"u").build());
        let Connected::Authenticated { io, events } = justssh_tokio::connect(
            client_io,
            &mut client,
            &Deadlines::new(),
            &[AuthMethod::Password(Zeroizing::new(b"pw".to_vec()))],
            &mut AcceptAll,
        )
        .await
        .unwrap() else {
            panic!("not authenticated");
        };
        let mut s = Session::new(io, client, events);
        let channel = s
            .open_channel("session", Vec::new())
            .await
            .unwrap()
            .unwrap();
        loop {
            if let Some(Action::ChannelOpened { .. }) = s.next().await.unwrap() {
                return (s, channel);
            }
        }
    };
    timeout(LIMIT, async { tokio::join!(server, client) })
        .await
        .unwrap()
}

/// Reads until `want` bytes of data have arrived on `channel` and nothing of this side's waits,
/// giving each byte's window back as it arrives; the bytes.
async fn receive<E: Endpoint>(
    s: &mut Session<DuplexStream, E>,
    channel: ChannelId,
    want: usize,
) -> Vec<u8> {
    let mut got = Vec::new();
    while got.len() < want
        || s.endpoint()
            .channel_info(channel)
            .is_some_and(|i| i.queued() > 0)
    {
        match s.next().await.unwrap() {
            Some(Action::ChannelData { data, .. }) => {
                s.consumed(channel, data.len() as u32).await.unwrap();
                got.extend(data);
            }
            Some(Action::Closed(c)) => panic!("{c:?}"),
            None => panic!("ended"),
            Some(_) => {}
        }
    }
    got
}

#[tokio::test]
async fn two_sessions_each_writing_more_than_the_pipe_holds_both_finish() {
    const EACH: usize = 1 << 20;
    let ((mut server, server_channel), (mut client, client_channel)) = pair().await;
    let server_side = async {
        server
            .queue_data(server_channel, &vec![b's'; EACH])
            .await
            .unwrap();
        receive(&mut server, server_channel, EACH).await
    };
    let client_side = async {
        client
            .queue_data(client_channel, &vec![b'c'; EACH])
            .await
            .unwrap();
        receive(&mut client, client_channel, EACH).await
    };
    let (at_server, at_client) = timeout(LIMIT, async { tokio::join!(server_side, client_side) })
        .await
        .expect("the two sessions stalled");
    assert_eq!(at_server, vec![b'c'; EACH]);
    assert_eq!(at_client, vec![b's'; EACH]);
}

#[tokio::test]
async fn calls_cancelled_while_their_output_waits_lose_and_repeat_nothing() {
    let ((mut server, server_channel), (mut client, client_channel)) = pair().await;
    let mut sent = Vec::new();
    for i in 0..40u8 {
        let chunk = vec![i; 50_000];
        let _ = timeout(
            Duration::from_millis(2),
            client.queue_data(client_channel, &chunk),
        )
        .await;
        sent.extend(chunk);
    }
    let client_side = async {
        while client
            .endpoint()
            .channel_info(client_channel)
            .is_some_and(|i| i.queued() > 0)
        {
            client.next().await.unwrap();
        }
        client.eof(client_channel).await.unwrap();
        loop {
            if let Some(Action::Closed(_)) | None = client.next().await.unwrap() {
                return;
            }
        }
    };
    let server_side = async {
        let got = receive(&mut server, server_channel, sent.len()).await;
        server
            .disconnect(justssh::DisconnectReason::BY_APPLICATION, "done")
            .await
            .unwrap();
        got
    };
    let (got, ()) = timeout(LIMIT, async { tokio::join!(server_side, client_side) })
        .await
        .expect("stalled");
    assert!(got == sent, "{} bytes arrived of {}", got.len(), sent.len());
}
