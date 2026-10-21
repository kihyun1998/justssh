//! Server password authentication, driven by a client that sends raw requests
//! (`test-support`).

mod common;

use common::*;
use justssh::{Action, Client, Closed, DisconnectReason, Error, Event, Phase, Server};
use justssh_wire::{Message, Ping, UserauthRequest};

const USER: &[u8] = b"\xffsrv1@10.0.0.5:22";

fn password_data(password: &[u8]) -> Vec<u8> {
    let mut d = vec![0];
    d.extend((password.len() as u32).to_be_bytes());
    d.extend(password);
    d
}

fn request(method: &str, data: Vec<u8>) -> Vec<u8> {
    Message::UserauthRequest(UserauthRequest::new(
        USER.to_vec(),
        "ssh-connection",
        method,
        data,
    ))
    .encode()
}

fn password(pw: &[u8]) -> Vec<u8> {
    request("password", password_data(pw))
}

fn none() -> Vec<u8> {
    request("none", Vec::new())
}

/// A server with `max_auth_tries` and a client in raw mode, both past the service request.
fn at_auth(max_auth_tries: u32) -> (Server, Client) {
    at_auth_with(|b| b.max_auth_tries(std::num::NonZeroU32::new(max_auth_tries).unwrap()))
}

fn at_auth_with(
    edit: impl FnOnce(justssh::ServerConfigBuilder) -> justssh::ServerConfigBuilder,
) -> (Server, Client) {
    let mut server = server_with(edit);
    let mut client = client();
    let (s, c) = pump(&mut server, &mut client, usize::MAX);
    assert!(s.closed.is_none() && c.closed.is_none());
    assert_eq!(server.phase(), Phase::Auth);
    client.set_raw_receive(true);
    (server, client)
}

/// What the server did with `payloads` from the client, and the messages the client got back.
struct Exchange {
    server: Vec<Action>,
    replies: Vec<Message>,
}

fn deliver(server: &mut Server, client: &mut Client, payloads: &[Vec<u8>]) -> Exchange {
    let mut bytes = Vec::new();
    for p in payloads {
        for a in client.send_raw(p) {
            if let Action::Write(b) = a {
                bytes.extend(b);
            }
        }
    }
    let actions = server.process(Event::Received(&bytes));
    let replies = replies_to(client, &actions);
    Exchange {
        server: actions,
        replies,
    }
}

fn answer(server: &mut Server, client: &mut Client, event: Event<'_>) -> Exchange {
    let actions = server.process(event);
    let replies = replies_to(client, &actions);
    Exchange {
        server: actions,
        replies,
    }
}

fn replies_to(client: &mut Client, actions: &[Action]) -> Vec<Message> {
    let mut replies = Vec::new();
    for a in actions {
        if let Action::Write(b) = a {
            for r in client.process(Event::Received(b)) {
                if let Action::RawReceived(p) = r {
                    replies.push(Message::decode(&p).unwrap());
                }
            }
        }
    }
    replies
}

fn password_requests(actions: &[Action]) -> Vec<(Vec<u8>, Vec<u8>)> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::PasswordRequest(r) => Some((r.user().to_vec(), r.password().to_vec())),
            _ => None,
        })
        .collect()
}

fn closed(actions: &[Action]) -> Option<&Closed> {
    actions.iter().find_map(|a| match a {
        Action::Closed(c) => Some(c),
        _ => None,
    })
}

fn failure_methods(m: &Message) -> Option<Vec<String>> {
    match m {
        Message::UserauthFailure(f) if !f.partial_success => Some(f.methods.clone()),
        _ => None,
    }
}

#[test]
fn a_password_request_reaches_the_consumer_with_user_and_password_as_sent() {
    let (mut server, mut client) = at_auth(6);
    let x = deliver(&mut server, &mut client, &[password(b"pw\x00\xfe")]);
    assert_eq!(
        password_requests(&x.server),
        vec![(USER.to_vec(), b"pw\x00\xfe".to_vec())]
    );
    assert!(
        x.replies.is_empty(),
        "the server answered before the consumer decided"
    );
}

#[test]
fn an_accepted_password_sends_success_and_enters_the_connected_phase() {
    let (mut server, mut client) = at_auth(6);
    deliver(&mut server, &mut client, &[password(b"pw")]);
    let x = answer(&mut server, &mut client, Event::AuthAccepted);
    assert!(matches!(x.replies[..], [Message::UserauthSuccess(_)]));
    assert_eq!(server.phase(), Phase::Connected);
}

#[test]
fn with_a_limit_of_one_the_first_none_is_free_and_a_wrong_password_disconnects() {
    let (mut server, mut client) = at_auth(1);
    let x = deliver(&mut server, &mut client, &[none()]);
    assert_eq!(
        x.replies
            .iter()
            .filter_map(failure_methods)
            .collect::<Vec<_>>(),
        vec![vec!["password".to_string()]]
    );
    deliver(&mut server, &mut client, &[password(b"wrong")]);
    let x = answer(&mut server, &mut client, Event::AuthRejected);
    match &x.replies[..] {
        [Message::Disconnect(d)] => {
            assert_eq!(d.reason, 2);
            assert_eq!(d.description, "too many authentication failures");
        }
        other => panic!("expected only a disconnect, got {other:?}"),
    }
    assert_eq!(
        closed(&x.server),
        Some(&Closed::Local {
            reason: DisconnectReason::PROTOCOL_ERROR,
            error: Error::TooManyAuthFailures,
            phase: Phase::Auth,
        })
    );
}

#[test]
fn a_second_none_counts_as_a_failure() {
    let (mut server, mut client) = at_auth(1);
    let x = deliver(&mut server, &mut client, &[none(), none()]);
    assert!(matches!(
        x.replies[..],
        [Message::UserauthFailure(_), Message::Disconnect(_)]
    ));
}

#[test]
fn a_method_the_server_does_not_offer_counts_as_a_failure() {
    let (mut server, mut client) = at_auth(2);
    let x = deliver(&mut server, &mut client, &[request("publickey", vec![0])]);
    assert_eq!(x.replies.iter().filter_map(failure_methods).count(), 1);
    deliver(&mut server, &mut client, &[password(b"wrong")]);
    let x = answer(&mut server, &mut client, Event::AuthRejected);
    assert!(matches!(x.replies[..], [Message::Disconnect(_)]));
}

#[test]
fn requests_sent_without_waiting_are_answered_in_order() {
    let (mut server, mut client) = at_auth(6);
    let x = deliver(&mut server, &mut client, &[password(b"one"), none()]);
    assert_eq!(
        password_requests(&x.server).len(),
        1,
        "second request handled too early"
    );
    assert!(x.replies.is_empty());
    let x = answer(&mut server, &mut client, Event::AuthRejected);
    assert_eq!(x.replies.iter().filter_map(failure_methods).count(), 2);
}

#[test]
fn a_request_after_success_is_ignored() {
    let (mut server, mut client) = at_auth(6);
    let x = deliver(
        &mut server,
        &mut client,
        &[password(b"pw"), password(b"again")],
    );
    assert_eq!(password_requests(&x.server).len(), 1);
    let x = answer(&mut server, &mut client, Event::AuthAccepted);
    assert!(matches!(x.replies[..], [Message::UserauthSuccess(_)]));
    assert!(password_requests(&x.server).is_empty());
    assert!(closed(&x.server).is_none());
    assert_eq!(server.phase(), Phase::Connected);
}

#[test]
fn a_service_other_than_ssh_connection_is_refused() {
    let (mut server, mut client) = at_auth(6);
    let req = Message::UserauthRequest(UserauthRequest::new(
        USER.to_vec(),
        "other-service",
        "none",
        Vec::new(),
    ))
    .encode();
    let x = deliver(&mut server, &mut client, &[req]);
    assert!(matches!(
        closed(&x.server),
        Some(Closed::Local {
            reason: DisconnectReason::SERVICE_NOT_AVAILABLE,
            ..
        })
    ));
}

#[test]
fn a_password_change_request_is_a_protocol_error() {
    let (mut server, mut client) = at_auth(6);
    let mut data = password_data(b"old");
    data[0] = 1;
    let x = deliver(&mut server, &mut client, &[request("password", data)]);
    assert!(password_requests(&x.server).is_empty());
    assert!(matches!(
        closed(&x.server),
        Some(Closed::Local {
            reason: DisconnectReason::PROTOCOL_ERROR,
            ..
        })
    ));
}

#[test]
fn a_verdict_with_nothing_pending_is_an_unexpected_event() {
    let (mut server, mut client) = at_auth(6);
    let x = answer(&mut server, &mut client, Event::AuthAccepted);
    assert!(matches!(
        closed(&x.server),
        Some(Closed::Local {
            error: Error::UnexpectedEvent,
            ..
        })
    ));
}

#[test]
fn after_128_attempts_the_server_answers_the_last_and_disconnects() {
    let (mut server, mut client) = at_auth_with(|b| b.unlimited_auth_tries());
    let requests: Vec<Vec<u8>> = (0..128).map(|_| request("publickey", vec![0])).collect();
    let x = deliver(&mut server, &mut client, &requests);
    assert_eq!(x.replies.iter().filter_map(failure_methods).count(), 128);
    match x.replies.last() {
        Some(Message::Disconnect(d)) => {
            assert_eq!(d.reason, 2);
            assert_eq!(d.description, "too many authentication attempts");
        }
        other => panic!("expected a disconnect last, got {other:?}"),
    }
}

#[test]
fn ping_is_answered_with_pong_once_connected() {
    let (mut server, mut client) = at_auth(6);
    deliver(&mut server, &mut client, &[password(b"pw")]);
    answer(&mut server, &mut client, Event::AuthAccepted);
    let ping = Message::Ping(Ping::new(b"tick".to_vec())).encode();
    let x = deliver(&mut server, &mut client, &[ping]);
    assert!(matches!(&x.replies[..], [Message::Pong(p)] if p.data == b"tick"));
}

#[test]
fn ping_before_authentication_closes_the_connection() {
    let (mut server, mut client) = at_auth(6);
    let ping = Message::Ping(Ping::new(b"tick".to_vec())).encode();
    let x = deliver(&mut server, &mut client, &[ping]);
    assert!(closed(&x.server).is_some());
}

#[test]
fn an_exceeded_deadline_closes_with_the_phase_it_was_in() {
    let (mut server, mut client) = at_auth(6);
    let x = answer(&mut server, &mut client, Event::DeadlineExceeded);
    assert_eq!(
        closed(&x.server),
        Some(&Closed::Local {
            reason: DisconnectReason::BY_APPLICATION,
            error: Error::DeadlineExceeded,
            phase: Phase::Auth,
        })
    );
    assert!(matches!(x.replies[..], [Message::Disconnect(_)]));
}

#[test]
fn a_peer_disconnect_reports_the_phase_it_arrived_in() {
    let (mut server, mut client) = at_auth(6);
    let bye = Message::Disconnect(justssh_wire::Disconnect::new(11, "bye", "")).encode();
    let x = deliver(&mut server, &mut client, &[bye]);
    assert!(matches!(
        closed(&x.server),
        Some(Closed::Peer {
            phase: Phase::Auth,
            ..
        })
    ));
}

#[test]
fn input_piling_up_while_a_verdict_is_pending_ends_the_connection() {
    let (mut server, mut client) = at_auth(6);
    deliver(&mut server, &mut client, &[password(b"pw")]);
    let flood = vec![0u8; 512 * 1024];
    let actions = server.process(Event::Received(&flood));
    assert!(matches!(
        closed(&actions),
        Some(Closed::Local {
            error: Error::InputOverflow,
            ..
        })
    ));
}
