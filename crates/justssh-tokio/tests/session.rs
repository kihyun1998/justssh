//! `Session` against a raw in-memory client (`justssh/test-support`) over a duplex pipe.

use std::time::Duration;

use justssh::{
    Action, Client, ClientConfig, Event, HostKey, Phase, Server, ServerConfig, Zeroizing,
};
use justssh_tokio::{Accepted, Deadlines, Session};
use justssh_wire::{ChannelOpen, ChannelWindowAdjust, Message, UserauthRequest};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::time::timeout;

/// A client driven by hand over one end of the pipe.
struct RawClient {
    io: DuplexStream,
    client: Client,
    received: Vec<Message>,
}

impl RawClient {
    async fn write(&mut self, actions: Vec<Action>) {
        for a in actions {
            match a {
                Action::Write(b) => self.io.write_all(&b).await.unwrap(),
                Action::RawReceived(p) => self.received.push(Message::decode(&p).unwrap()),
                _ => {}
            }
        }
    }

    /// Reads once and handles what arrived.
    async fn read(&mut self) {
        let mut buf = vec![0u8; 64 * 1024];
        let n = self.io.read(&mut buf).await.unwrap();
        assert!(n > 0, "server closed the pipe");
        let actions = self.client.process(Event::Received(&buf[..n]));
        self.write(actions).await;
    }

    async fn send(&mut self, m: Message) {
        let actions = self.client.send_raw(&m.encode());
        self.write(actions).await;
    }
}

/// A connected session with one accepted channel whose peer window is `window`, and the
/// client on the other end.
async fn session_with_channel(
    window: u32,
) -> (Session<DuplexStream>, justssh::ChannelId, RawClient) {
    let (server_io, client_io) = tokio::io::duplex(1 << 20);
    let server_task = tokio::spawn(async move {
        let config =
            ServerConfig::builder(HostKey::ed25519_from_seed(Zeroizing::new([7; 32]))).build();
        let mut server = Server::new(config);
        match justssh_tokio::accept(server_io, &mut server, &Deadlines::new(), |_| async {
            Some(())
        })
        .await
        .unwrap()
        {
            Accepted::Authenticated { io, events, .. } => Session::new(io, server, events),
            _ => panic!("not authenticated"),
        }
    });

    let mut c = RawClient {
        io: client_io,
        client: Client::new(ClientConfig::builder().build()),
        received: Vec::new(),
    };
    let actions = c.client.process(Event::Connected);
    c.write(actions).await;
    while c.client.phase() != Phase::Auth {
        c.read().await;
    }
    c.client.set_raw_receive(true);
    let mut pw = vec![0, 0, 0, 0, 2];
    pw.extend(b"pw");
    c.send(Message::UserauthRequest(UserauthRequest::new(
        b"u".to_vec(),
        "ssh-connection",
        "password",
        pw,
    )))
    .await;
    let mut session = server_task.await.unwrap();
    c.read().await;

    c.send(Message::ChannelOpen(ChannelOpen::new(
        "session".into(),
        3,
        window,
        32 * 1024,
        Vec::new(),
    )))
    .await;
    let id = match session.next().await.unwrap() {
        Some(Action::ChannelOpenRequest(open)) => open.channel(),
        other => panic!("{other:?}"),
    };
    session.accept_channel(id, Vec::new()).await.unwrap();
    c.read().await;
    (session, id, c)
}

fn data_bytes(received: &[Message]) -> usize {
    received
        .iter()
        .map(|m| match m {
            Message::ChannelData(d) => d.data.len(),
            _ => 0,
        })
        .sum()
}

#[tokio::test]
async fn data_waits_until_the_peer_has_taken_it() {
    let (mut session, id, mut client) = session_with_channel(1000).await;
    let payload = vec![b'x'; 100 * 1024];

    let sending = session.data(id, &payload);
    tokio::pin!(sending);
    assert!(
        timeout(Duration::from_millis(200), &mut sending)
            .await
            .is_err(),
        "data returned while the peer's window was closed"
    );

    let feeding = async {
        while data_bytes(&client.received) < payload.len() {
            client.read().await;
            let taken = data_bytes(&client.received) as u32;
            client
                .send(Message::ChannelWindowAdjust(ChannelWindowAdjust::new(
                    id.get(),
                    taken.max(1),
                )))
                .await;
        }
    };
    let (sent, ()) = tokio::join!(sending, feeding);
    sent.unwrap();
    assert_eq!(data_bytes(&client.received), payload.len());
}

#[tokio::test]
async fn abort_closes_a_channel_whose_data_the_window_holds_back() {
    let (mut session, id, mut client) = session_with_channel(0).await;
    let payload = vec![b'x'; 1000];
    let sending = session.data(id, &payload);
    assert!(timeout(Duration::from_millis(100), sending).await.is_err());
    session.abort(id).await.unwrap();
    client.read().await;
    assert!(
        matches!(client.received.last(), Some(Message::ChannelClose(_))),
        "{:?}",
        client.received
    );
}

#[tokio::test]
async fn an_open_sent_right_behind_the_auth_request_is_not_lost() {
    let (server_io, client_io) = tokio::io::duplex(1 << 20);
    let server_task = tokio::spawn(async move {
        let config =
            ServerConfig::builder(HostKey::ed25519_from_seed(Zeroizing::new([7; 32]))).build();
        let mut server = Server::new(config);
        match justssh_tokio::accept(server_io, &mut server, &Deadlines::new(), |_| async {
            Some(())
        })
        .await
        .unwrap()
        {
            Accepted::Authenticated { io, events, .. } => Session::new(io, server, events),
            _ => panic!("not authenticated"),
        }
    });
    let mut c = RawClient {
        io: client_io,
        client: Client::new(ClientConfig::builder().build()),
        received: Vec::new(),
    };
    let actions = c.client.process(Event::Connected);
    c.write(actions).await;
    while c.client.phase() != Phase::Auth {
        c.read().await;
    }
    c.client.set_raw_receive(true);
    let mut pw = vec![0, 0, 0, 0, 2];
    pw.extend(b"pw");
    let mut actions = c.client.send_raw(
        &Message::UserauthRequest(UserauthRequest::new(
            b"u".to_vec(),
            "ssh-connection",
            "password",
            pw,
        ))
        .encode(),
    );
    actions.extend(
        c.client.send_raw(
            &Message::ChannelOpen(ChannelOpen::new(
                "session".into(),
                0,
                1000,
                32768,
                Vec::new(),
            ))
            .encode(),
        ),
    );
    c.write(actions).await;
    let mut session = server_task.await.unwrap();
    assert!(
        matches!(
            timeout(Duration::from_secs(5), session.next())
                .await
                .expect("no event within 5 s")
                .unwrap(),
            Some(Action::ChannelOpenRequest(_))
        ),
        "the pipelined open was lost"
    );
}
