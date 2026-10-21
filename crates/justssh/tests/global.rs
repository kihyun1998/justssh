//! Global requests (RFC 4254 §4) and unknown message numbers, driven by a raw client
//! (`test-support`).

mod common;

use common::*;
use justssh::{Action, Closed, Error, Phase};
use justssh_wire::{GlobalRequest, Message, RequestFailure, RequestSuccess};

fn global(kind: &str, want_reply: bool, data: &[u8]) -> Message {
    Message::GlobalRequest(GlobalRequest::new(kind.into(), want_reply, data.to_vec()))
}

fn requests(actions: Vec<Action>) -> Vec<justssh::GlobalRequest> {
    actions
        .into_iter()
        .filter_map(|a| match a {
            Action::GlobalRequest(r) => Some(r),
            _ => None,
        })
        .collect()
}

fn local_error(actions: &[Action]) -> Option<&Error> {
    actions.iter().find_map(|a| match a {
        Action::Closed(Closed::Local { error, .. }) => Some(error),
        _ => None,
    })
}

#[test]
fn an_openssh_keepalive_reaches_the_consumer_and_can_be_answered() {
    let (mut server, mut client) = connected();
    let actions = send(
        &mut server,
        &mut client,
        &[global("keepalive@openssh.com", true, b"")],
    );
    let [request] = &requests(actions)[..] else {
        panic!("not one global request");
    };
    assert_eq!(request.kind(), "keepalive@openssh.com");
    assert!(request.want_reply());
    assert_eq!(request.data(), b"");
    let token = request.reply().expect("no reply token");
    let out = replies(
        &mut client,
        &server.reply_global_request(token, false, Vec::new()),
    );
    assert_eq!(
        out,
        [Message::RequestFailure(RequestFailure::new(Vec::new()))]
    );
}

#[test]
fn replies_leave_in_request_order_with_their_payloads() {
    let (mut server, mut client) = connected();
    let actions = send(
        &mut server,
        &mut client,
        &[
            global("no-more-sessions@openssh.com", false, b""),
            global("tcpip-forward", true, b"\0\0\0\0\0\0\0\0"),
            global("vendor@example.com", true, b"\x01\x02"),
        ],
    );
    let got = requests(actions);
    assert_eq!(got.len(), 3);
    assert!(got[0].reply().is_none(), "want_reply=0 got a token");
    assert_eq!(got[2].data(), b"\x01\x02");
    let (forward, vendor) = (got[1].reply().unwrap(), got[2].reply().unwrap());
    let early = server.reply_global_request(vendor, true, b"second".to_vec());
    assert!(replies(&mut client, &early).is_empty());
    let out = replies(
        &mut client,
        &server.reply_global_request(forward, true, vec![0, 0, 0x9c, 0x40]),
    );
    assert_eq!(
        out,
        [
            Message::RequestSuccess(RequestSuccess::new(vec![0, 0, 0x9c, 0x40])),
            Message::RequestSuccess(RequestSuccess::new(b"second".to_vec())),
        ]
    );
}

#[test]
fn a_token_answered_twice_sends_one_reply() {
    let (mut server, mut client) = connected();
    let actions = send(&mut server, &mut client, &[global("a", true, b"")]);
    let token = requests(actions)[0].reply().unwrap();
    let first = replies(
        &mut client,
        &server.reply_global_request(token, true, Vec::new()),
    );
    let second = replies(
        &mut client,
        &server.reply_global_request(token, false, Vec::new()),
    );
    assert_eq!(
        first,
        [Message::RequestSuccess(RequestSuccess::new(Vec::new()))]
    );
    assert!(second.is_empty(), "{second:?}");
}

#[test]
fn a_request_this_side_sends_gets_its_reply_with_the_payload() {
    let (mut server, mut client) = connected();
    let sent = replies(
        &mut client,
        &server.global_request("hostkeys-prove-00@openssh.com", true, b"keys".to_vec()),
    );
    assert_eq!(
        sent,
        [global("hostkeys-prove-00@openssh.com", true, b"keys")]
    );
    let actions = send(
        &mut server,
        &mut client,
        &[Message::RequestFailure(RequestFailure::new(
            b"why".to_vec(),
        ))],
    );
    assert!(
        matches!(
            &actions[..],
            [Action::GlobalRequestReply { ok: false, data }] if data == b"why"
        ),
        "{actions:?}"
    );
}

#[test]
fn a_reply_no_request_is_waiting_for_is_dropped() {
    let (mut server, mut client) = connected();
    let actions = send(
        &mut server,
        &mut client,
        &[Message::RequestSuccess(RequestSuccess::new(b"x".to_vec()))],
    );
    assert!(actions.is_empty(), "{actions:?}");
    assert_eq!(server.phase(), Phase::Connected);
}

#[test]
fn an_unknown_number_after_authentication_is_answered_unimplemented_and_the_connection_stays() {
    let (mut server, mut client) = connected();
    let actions = send(
        &mut server,
        &mut client,
        &[Message::Unknown(200), Message::Unknown(79)],
    );
    // The client's sequence numbers since NEWKEYS: SERVICE_REQUEST 0, USERAUTH_REQUEST 1.
    assert_eq!(
        replies(&mut client, &actions),
        [
            Message::Unimplemented(justssh_wire::Unimplemented::new(2)),
            Message::Unimplemented(justssh_wire::Unimplemented::new(3)),
        ]
    );
    assert_eq!(server.phase(), Phase::Connected);
    let actions = send(&mut server, &mut client, &[global("x", false, b"")]);
    assert_eq!(requests(actions).len(), 1);
}

#[test]
fn a_known_number_out_of_place_after_authentication_still_ends_the_connection() {
    let (mut server, mut client) = connected();
    let actions = send(
        &mut server,
        &mut client,
        &[Message::UserauthSuccess(Default::default())],
    );
    assert!(matches!(
        local_error(&actions),
        Some(Error::UnexpectedMessage { number: 52 })
    ));
}

/// A server and a raw-mode client in user authentication.
fn authenticating() -> (justssh::Server, justssh::Client) {
    let (mut server, mut client) = (server(), client());
    pump(&mut server, &mut client, usize::MAX);
    assert_eq!(server.phase(), Phase::Auth);
    client.set_raw_receive(true);
    (server, client)
}

#[test]
fn a_global_request_or_reply_before_authentication_ends_the_connection() {
    for (message, number) in [
        (global("keepalive@openssh.com", true, b""), 80),
        (Message::RequestSuccess(RequestSuccess::new(Vec::new())), 81),
        (Message::RequestFailure(RequestFailure::new(Vec::new())), 82),
    ] {
        let (mut server, mut client) = authenticating();
        let actions = send(&mut server, &mut client, &[message]);
        assert!(
            matches!(local_error(&actions), Some(Error::UnexpectedMessage { number: n }) if *n == number),
            "message {number}: {actions:?}"
        );
    }
}

#[test]
fn an_unknown_number_before_authentication_ends_the_connection() {
    let (mut server, mut client) = authenticating();
    let actions = send(&mut server, &mut client, &[Message::Unknown(200)]);
    assert!(matches!(
        local_error(&actions),
        Some(Error::UnexpectedMessage { number: 200 })
    ));
}
