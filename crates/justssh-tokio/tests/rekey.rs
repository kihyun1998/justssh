//! Two `Session`s over a duplex pipe: a key re-exchange while the client's `data` waits for the
//! window.

use std::time::Duration;

use justssh::{
    Action, Client, ClientConfig, HostKey, InfoRequest, Server, ServerConfig, Zeroizing,
};
use justssh_tokio::{Accepted, AuthMethod, ClientHandler, Connected, Deadlines, Session};
use tokio::io::DuplexStream;
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(60);
const UPLOAD: usize = 8 << 20;

struct AcceptAll;

impl ClientHandler for AcceptAll {
    async fn check_host_key(&mut self, _key: &[u8]) -> bool {
        true
    }

    async fn answer(&mut self, _request: &InfoRequest) -> Vec<Zeroizing<Vec<u8>>> {
        Vec::new()
    }
}

/// A server that accepts one channel, counts the data on it, and asks for a key re-exchange
/// after `rekey_after` bytes, until the client disconnects; the bytes it received.
async fn counting_server(io: DuplexStream, rekey_after: Option<usize>) -> usize {
    let config = ServerConfig::builder(HostKey::ed25519_from_seed(Zeroizing::new([7; 32]))).build();
    let mut server = Server::new(config);
    let Accepted::Authenticated { io, events, .. } =
        justssh_tokio::accept(io, &mut server, &Deadlines::new(), |_| async { Some(()) })
            .await
            .unwrap()
    else {
        panic!("not authenticated");
    };
    let mut session = Session::new(io, server, events);
    let (mut received, mut asked) = (0, false);
    loop {
        let Ok(next) = session.next().await else {
            break;
        };
        match next {
            Some(Action::ChannelOpenRequest(r)) => {
                session
                    .accept_channel(r.channel(), Vec::new())
                    .await
                    .unwrap();
            }
            Some(Action::ChannelData { channel, data }) => {
                received += data.len();
                let _ = session.consumed(channel, data.len() as u32).await;
                if !asked && rekey_after.is_some_and(|n| received >= n) {
                    asked = true;
                    let _ = session.rekey().await;
                }
            }
            Some(Action::Closed(justssh::Closed::Peer { .. })) | None => break,
            Some(Action::Closed(c)) => panic!("{c:?}"),
            Some(_) => {}
        }
    }
    received
}

/// A client uploading [`UPLOAD`] bytes on one channel through `data`, answering a host key to
/// judge whenever `data` hands control back; the host keys it was asked about.
async fn uploading_client(io: DuplexStream, config: ClientConfig) -> usize {
    let mut client = Client::new(config);
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
    let mut session = Session::new(io, client, events);
    let channel = session
        .open_channel("session", Vec::new())
        .await
        .unwrap()
        .unwrap();
    let mut verdicts = 0;
    loop {
        match session.next().await.unwrap() {
            Some(Action::ChannelOpened { .. }) => break,
            Some(Action::VerifyHostKey { .. }) => {
                verdicts += 1;
                session.answer_host_key(true).await.unwrap();
            }
            other => assert!(
                !matches!(other, Some(Action::Closed(_)) | None),
                "{other:?}"
            ),
        }
    }
    let chunk = vec![7u8; 64 * 1024];
    for _ in 0..UPLOAD / chunk.len() {
        session.data(channel, &chunk).await.unwrap();
        // Whatever data handed back without blocking.
        while let Ok(next) = timeout(Duration::ZERO, session.next()).await {
            match next.unwrap() {
                Some(Action::VerifyHostKey { .. }) => {
                    verdicts += 1;
                    session.answer_host_key(true).await.unwrap();
                }
                Some(Action::Closed(c)) => panic!("{c:?}"),
                _ => {}
            }
        }
    }
    session
        .disconnect(justssh::DisconnectReason::BY_APPLICATION, "done")
        .await
        .unwrap();
    verdicts
}

async fn upload(rekey_after: Option<usize>, config: ClientConfig) -> (usize, usize) {
    let (server_io, client_io) = tokio::io::duplex(1 << 16);
    let server = tokio::spawn(counting_server(server_io, rekey_after));
    let verdicts = timeout(LIMIT, uploading_client(client_io, config))
        .await
        .expect("the upload hung");
    let received = timeout(LIMIT, server)
        .await
        .expect("the server hung")
        .unwrap();
    (received, verdicts)
}

#[tokio::test]
async fn a_rekey_the_server_asks_for_during_an_upload_does_not_hold_up_data() {
    let (received, verdicts) = upload(Some(1 << 20), ClientConfig::builder(b"u").build()).await;
    assert_eq!(received, UPLOAD);
    assert!(verdicts >= 1, "{verdicts}");
}

#[tokio::test]
async fn a_rekey_the_clients_threshold_starts_during_an_upload_does_not_hold_up_data() {
    let config = ClientConfig::builder(b"u").rekey_threshold(1 << 20).build();
    let (received, verdicts) = upload(None, config).await;
    assert_eq!(received, UPLOAD);
    assert!(verdicts >= 4, "{verdicts}");
}
