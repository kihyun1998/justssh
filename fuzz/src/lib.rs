//! What each fuzz target checks, shared with `crates/justssh/tests/fuzz_regressions.rs`, which
//! replays every input kept in `fuzz/regressions/<target>/` through the same function.

#[path = "../../crates/justssh/tests/common/mod.rs"]
#[allow(dead_code, unused_imports, clippy::all)]
mod common;

use justssh::requests::{Env, Exec, ExitSignal, ExitStatus, PtyReq, Shell, Subsystem};
use justssh::{Action, Client, Event, Phase, Server};
use justssh_wire::Message;

/// Decodes `data` as a transport message and as each typed request. Whatever decodes must
/// decode again, to the same value, from its own encoding.
pub fn wire(data: &[u8]) {
    if let Ok(m) = Message::decode(data) {
        assert_eq!(Message::decode(&m.encode()).as_ref(), Ok(&m), "{data:x?}");
    }
    macro_rules! again {
        ($($t:ty),*) => {$(
            if let Ok(r) = <$t>::decode(data) {
                assert_eq!(<$t>::decode(&r.encode()).as_ref(), Ok(&r), "{data:x?}");
            }
        )*};
    }
    again!(PtyReq, Shell, Exec, Subsystem, Env, ExitStatus, ExitSignal);
}

/// Which side receives the messages, and where it stands when they start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Server,
    Client,
}

/// Where the receiving side stands, as far as this check follows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Before the peer's `KEXINIT`.
    KexInit,
    /// After it, waiting for the peer's half of the exchange.
    KexReply,
    Auth,
    Connected,
}

/// The numbers `side` takes in `state`, written from RFC 4253, 4252 and 4254 and ADR-0002 apart
/// from the table in `crates/justssh/src/transport/allowed.rs`. In `Connected`, a number not
/// listed and not known is answered with `UNIMPLEMENTED` instead.
fn takes(side: Side, state: State, n: u8) -> bool {
    let both = matches!(n, 1..=4);
    both || match (side, state) {
        (_, State::KexInit) => n == 20,
        (Side::Server, State::KexReply) => n == 30,
        (Side::Client, State::KexReply) => n == 31,
        (Side::Server, State::Auth) => matches!(n, 20 | 50),
        (Side::Client, State::Auth) => matches!(n, 7 | 20 | 51..=53 | 60),
        (Side::Server, State::Connected) => matches!(n, 20 | 50 | 80..=82 | 90..=100 | 192 | 193),
        (Side::Client, State::Connected) => matches!(n, 20 | 80..=82 | 90..=100 | 192 | 193),
    }
}

/// The numbers counted as known: those the wire crate decodes, and 60, which the transport reads
/// by the authentication method in progress.
fn known(n: u8) -> bool {
    matches!(n, 1..=7 | 20 | 21 | 30 | 31 | 50..=53 | 60 | 80..=82 | 90..=100 | 192 | 193)
}

/// One side of a connection, receiving.
enum Endpoint {
    Server(Server),
    Client(Client),
}

impl Endpoint {
    fn process(&mut self, bytes: &[u8]) -> Vec<Action> {
        match self {
            Endpoint::Server(s) => s.process(Event::Received(bytes)),
            Endpoint::Client(c) => c.process(Event::Received(bytes)),
        }
    }

    fn phase(&self) -> Phase {
        match self {
            Endpoint::Server(s) => s.phase(),
            Endpoint::Client(c) => c.phase(),
        }
    }
}

/// The other side, which turns each payload into bytes for the receiver and, raw, reads what
/// the receiver answers.
enum Sender {
    /// Bytes before any key exchange: a version line and plaintext packets.
    Plain,
    Server(Server),
    Client(Client),
}

impl Sender {
    fn packet(&mut self, payload: &[u8]) -> Vec<u8> {
        let actions = match self {
            Sender::Plain => return common::plain_packet(payload),
            Sender::Server(s) => s.send_raw(payload),
            Sender::Client(c) => c.send_raw(payload),
        };
        writes(actions)
    }

    /// The payloads the receiver's `actions` carry, where this side reads them raw.
    fn answers(&mut self, actions: &[Action]) -> Option<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        for a in actions {
            if let Action::Write(b) = a {
                let got = match self {
                    Sender::Plain => return None,
                    Sender::Server(s) => s.process(Event::Received(b)),
                    Sender::Client(c) => c.process(Event::Received(b)),
                };
                out.extend(got.into_iter().filter_map(|r| match r {
                    Action::RawReceived(p) => Some(p),
                    _ => None,
                }));
            }
        }
        Some(out)
    }
}

fn writes(actions: Vec<Action>) -> Vec<u8> {
    actions
        .into_iter()
        .filter_map(|a| match a {
            Action::Write(b) => Some(b),
            _ => None,
        })
        .flatten()
        .collect()
}

/// The payloads `data` holds after its first byte: each one byte of length less one, then that
/// many bytes, at most 64 of them.
fn payloads(mut data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while let [len, rest @ ..] = data {
        let len = (usize::from(*len) + 1).min(rest.len());
        if len == 0 || out.len() == 64 {
            break;
        }
        out.push(&rest[..len]);
        data = &rest[len..];
    }
    out
}

/// Puts one side of a connection where the first byte of `data` says, sends it the messages the
/// rest of `data` holds, and checks that a message the side does not take there ends the
/// connection, that an unknown one after authentication is answered with `UNIMPLEMENTED`, and
/// that a server ignores a `USERAUTH_REQUEST` after authentication.
pub fn transport(data: &[u8]) {
    let Some((&scenario, rest)) = data.split_first() else {
        return;
    };
    let (side, state, mut receiver, mut sender) = match scenario % 6 {
        0 => {
            let mut server = common::server();
            server.process(Event::Connected);
            server.process(Event::Received(common::CLIENT_VERSION));
            (
                Side::Server,
                State::KexInit,
                Endpoint::Server(server),
                Sender::Plain,
            )
        }
        1 => {
            let mut client = common::client();
            client.process(Event::Connected);
            client.process(Event::Received(b"SSH-2.0-test\r\n"));
            (
                Side::Client,
                State::KexInit,
                Endpoint::Client(client),
                Sender::Plain,
            )
        }
        2 => {
            let (mut server, mut client) = (common::server(), common::client());
            common::pump(&mut server, &mut client, usize::MAX);
            (
                Side::Server,
                State::Auth,
                Endpoint::Server(server),
                Sender::Client(client),
            )
        }
        3 => {
            let (mut server, mut client) = (common::server(), common::client());
            common::pump(&mut server, &mut client, usize::MAX);
            (
                Side::Client,
                State::Auth,
                Endpoint::Client(client),
                Sender::Server(server),
            )
        }
        4 => {
            let (server, client) = common::connected();
            (
                Side::Server,
                State::Connected,
                Endpoint::Server(server),
                Sender::Client(client),
            )
        }
        _ => {
            let (mut server, client) = common::authenticated_pair();
            server.set_raw_receive(true);
            (
                Side::Client,
                State::Connected,
                Endpoint::Client(client),
                Sender::Server(server),
            )
        }
    };
    let mut state = state;
    for payload in payloads(rest) {
        let n = payload[0];
        let actions = receiver.process(&sender.packet(payload));
        let closed = receiver.phase() == Phase::Closed;
        let unknown = state == State::Connected && !known(n);
        let ignored = (side, state, n) == (Side::Server, State::Connected, 50);
        assert!(
            closed || takes(side, state, n) || unknown,
            "{side:?} in {state:?} took message {n}: {data:x?}"
        );
        assert!(
            !(closed && (unknown || ignored)),
            "{side:?} in {state:?} ended the connection on message {n}: {data:x?}"
        );
        if closed {
            return;
        }
        let answers = sender.answers(&actions);
        if unknown && let Some(answers) = &answers {
            assert!(
                answers.iter().any(|p| p.first() == Some(&3)),
                "{side:?} in {state:?} did not answer message {n} with UNIMPLEMENTED: {data:x?}"
            );
        }
        if ignored {
            assert_eq!(
                answers,
                Some(Vec::new()),
                "a server answered a USERAUTH_REQUEST after authentication: {data:x?}"
            );
        }
        state = match (state, n) {
            (State::KexReply, 30 | 31) | (State::KexReply, 21) => return,
            (_, 20) => State::KexReply,
            (s, _) => s,
        };
    }
}
