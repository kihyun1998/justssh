//! `accept` under a deadline, against peers that stop reading, and its verdicts against
//! `connect`.

use std::future::Future;
use std::num::NonZeroU32;
use std::time::Duration;

use justssh::{
    Action, Client, ClientConfig, Closed, DisconnectReason, Error, Event, HostKey, InfoRequest,
    Phase, Server, ServerConfig, Zeroizing,
};
use justssh_tokio::{Accepted, AuthMethod, ClientHandler, Connected, Deadlines, Verdict};
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
            |_| async { Verdict::Accept(()) },
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

struct Handler;

impl ClientHandler for Handler {
    async fn check_host_key(&mut self, _key: &[u8]) -> bool {
        true
    }

    async fn answer(&mut self, _request: &InfoRequest) -> Vec<Zeroizing<Vec<u8>>> {
        Vec::new()
    }
}

struct Run {
    accepted: Accepted<DuplexStream, ()>,
    connected: Connected<DuplexStream>,
    asked: usize,
}

async fn run<Fut>(max_auth_tries: u32, deadlines: Deadlines, verdict: fn() -> Fut) -> Run
where
    Fut: Future<Output = Verdict<()>> + Send + 'static,
{
    let (server_io, client_io) = tokio::io::duplex(1 << 16);
    let server = tokio::spawn(async move {
        let config = ServerConfig::builder(HostKey::ed25519_from_seed(Zeroizing::new([7; 32])))
            .max_auth_tries(NonZeroU32::new(max_auth_tries).unwrap())
            .build();
        let mut server = Server::new(config);
        let mut asked = 0;
        let accepted = justssh_tokio::accept(server_io, &mut server, &deadlines, |_| {
            asked += 1;
            verdict()
        })
        .await
        .unwrap();
        (accepted, asked)
    });
    let mut client = Client::new(ClientConfig::builder(b"alice").build());
    let connected = tokio::time::timeout(
        Duration::from_secs(10),
        justssh_tokio::connect(
            client_io,
            &mut client,
            &Deadlines::new(),
            &[AuthMethod::Password(Zeroizing::new(b"pw".to_vec()))],
            &mut Handler,
        ),
    )
    .await
    .expect("connect is still waiting")
    .unwrap();
    let (accepted, asked) = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("accept is still waiting")
        .unwrap();
    Run {
        accepted,
        connected,
        asked,
    }
}

const REFUSAL: &str = "대상 서버가 저장된 자격 증명을 거절했습니다";

async fn refuse() -> Verdict<()> {
    Verdict::Refuse {
        reason: DisconnectReason::BY_APPLICATION,
        description: REFUSAL.to_owned(),
    }
}

fn assert_refused(run: Run) {
    match run.connected {
        Connected::Closed(Closed::Peer {
            reason,
            description,
            phase,
        }) => {
            assert_eq!(reason, DisconnectReason::BY_APPLICATION);
            assert_eq!(description, REFUSAL);
            assert_eq!(phase, Phase::Auth);
        }
        other => panic!("the client did not read the refusal: {other:?}"),
    }
    match run.accepted {
        Accepted::Closed(closed) => assert_eq!(
            closed,
            Closed::Requested {
                reason: DisconnectReason::BY_APPLICATION,
                phase: Phase::Auth,
            }
        ),
        other => panic!("{other:?}"),
    }
    assert_eq!(run.asked, 1);
}

#[tokio::test]
async fn a_refusal_reaches_the_client_with_its_reason_and_description_as_given() {
    assert_refused(run(6, Deadlines::new(), refuse).await);
}

#[tokio::test]
async fn a_refusal_at_a_limit_of_one_still_carries_its_own_description() {
    assert_refused(run(1, Deadlines::new(), refuse).await);
}

#[tokio::test]
async fn a_rejection_at_a_limit_of_one_still_ends_in_too_many_authentication_failures() {
    let run = run(1, Deadlines::new(), || async { Verdict::Reject }).await;
    match run.connected {
        Connected::Closed(Closed::Peer {
            reason,
            description,
            ..
        }) => {
            assert_eq!(reason, DisconnectReason::PROTOCOL_ERROR);
            assert_eq!(description, "too many authentication failures");
        }
        other => panic!("{other:?}"),
    }
    assert!(
        matches!(
            run.accepted,
            Accepted::Closed(Closed::Local {
                error: Error::TooManyAuthFailures,
                ..
            })
        ),
        "{:?}",
        run.accepted
    );
    assert_eq!(run.asked, 1);
}

#[tokio::test]
async fn an_accepted_password_authenticates_both_sides() {
    let run = run(1, Deadlines::new(), || async { Verdict::Accept(()) }).await;
    assert!(
        matches!(run.connected, Connected::Authenticated { .. }),
        "{:?}",
        run.connected
    );
    assert!(
        matches!(run.accepted, Accepted::Authenticated { .. }),
        "{:?}",
        run.accepted
    );
    assert_eq!(run.asked, 1);
}

#[tokio::test]
async fn a_refusal_just_inside_the_auth_deadline_still_carries_its_own_description() {
    let deadlines = Deadlines::new().phase(Phase::Auth, Duration::from_secs(2));
    assert_refused(
        run(1, deadlines, || async {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            refuse().await
        })
        .await,
    );
}

#[tokio::test]
async fn a_refusal_that_comes_after_the_auth_deadline_ends_in_the_deadline() {
    let deadlines = Deadlines::new().phase(Phase::Auth, Duration::from_millis(500));
    let run = run(1, deadlines, || async {
        tokio::time::sleep(Duration::from_secs(2)).await;
        refuse().await
    })
    .await;
    match run.connected {
        Connected::Closed(Closed::Peer {
            reason,
            description,
            ..
        }) => {
            assert_eq!(reason, DisconnectReason::BY_APPLICATION);
            assert_eq!(description, "deadline exceeded");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        match run.accepted {
            Accepted::Closed(closed) => closed,
            other => panic!("{other:?}"),
        },
        Closed::Local {
            reason: DisconnectReason::BY_APPLICATION,
            error: Error::DeadlineExceeded,
            phase: Phase::Auth,
        }
    );
}
