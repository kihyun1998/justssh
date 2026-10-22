//! `accept` under a deadline, against peers that stop reading.

use std::time::Duration;

use justssh::{
    Action, Closed, DisconnectReason, Error, Event, HostKey, Phase, Server, ServerConfig, Zeroizing,
};
use justssh_tokio::{Accepted, Deadlines};
use tokio::io::{AsyncReadExt, DuplexStream};

fn config() -> ServerConfig {
    ServerConfig::builder(HostKey::ed25519_from_seed(Zeroizing::new([7; 32]))).build()
}

/// How `accept` on `io` ended under a 200 ms deadline on authentication, failing the test if it
/// has not ended after ten seconds.
async fn closed_within_the_deadline(io: DuplexStream) -> Closed {
    let mut server = Server::new(config());
    let accepted = tokio::time::timeout(
        Duration::from_secs(10),
        justssh_tokio::accept(
            io,
            &mut server,
            &Deadlines::new().phase(Phase::Auth, Duration::from_millis(200)),
            |_| async { Some(()) },
        ),
    )
    .await
    .expect("accept is still waiting")
    .unwrap();
    match accepted {
        Accepted::Closed(closed) => closed,
        other => panic!("{other:?}"),
    }
}

const ENDED_BY_THE_DEADLINE: Closed = Closed::Local {
    reason: DisconnectReason::BY_APPLICATION,
    error: Error::DeadlineExceeded,
    phase: Phase::Handshake,
};

#[tokio::test]
async fn a_deadline_ends_accept_even_when_the_peer_reads_nothing() {
    // A pipe too small for the server's first flight, whose other end never reads.
    let (_peer, io) = tokio::io::duplex(8);
    assert_eq!(closed_within_the_deadline(io).await, ENDED_BY_THE_DEADLINE);
}

#[tokio::test]
async fn a_deadline_passing_while_reading_ends_accept_when_the_disconnect_cannot_be_written() {
    // The peer takes the server's first flight, then neither sends nor reads; the pipe has no
    // room for the DISCONNECT that follows.
    let flight: usize = Server::new(config())
        .process(Event::Connected)
        .iter()
        .map(|a| match a {
            Action::Write(b) => b.len(),
            _ => 0,
        })
        .sum();
    let (mut peer, io) = tokio::io::duplex(16);
    let reader = tokio::spawn(async move {
        let mut first = vec![0; flight];
        peer.read_exact(&mut first).await.unwrap();
        std::future::pending::<()>().await;
        drop(peer);
    });
    assert_eq!(closed_within_the_deadline(io).await, ENDED_BY_THE_DEADLINE);
    reader.abort();
}
