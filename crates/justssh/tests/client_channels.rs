//! The connection protocol between a real client and a real server: channels this side opens,
//! replies to the requests it sends, and the peer's requests and opens.

mod common;

use common::*;
use justssh::{
    Action, ChannelId, Client, Closed, DisconnectReason, Error, OpenFailureReason, RequestToken,
    Server,
};
use justssh_wire::{ChannelOpenConfirmation, ChannelOpenFailure, Message};

fn opened(actions: &[Action]) -> Option<(ChannelId, Vec<u8>)> {
    actions.iter().find_map(|a| match a {
        Action::ChannelOpened { channel, data } => Some((*channel, data.clone())),
        _ => None,
    })
}

fn open_request(actions: &[Action]) -> Option<(ChannelId, String, Vec<u8>)> {
    actions.iter().find_map(|a| match a {
        Action::ChannelOpenRequest(r) => {
            Some((r.channel(), r.kind().to_owned(), r.data().to_vec()))
        }
        _ => None,
    })
}

fn closed(actions: &[Action]) -> Option<&Closed> {
    actions.iter().find_map(|a| match a {
        Action::Closed(c) => Some(c),
        _ => None,
    })
}

/// A channel the client opened and the server accepted: the client's id and the server's.
fn client_channel(server: &mut Server, client: &mut Client) -> (ChannelId, ChannelId) {
    let (id, actions) = client.open_channel("session", Vec::new());
    let at_server = to_server(server, actions);
    let (server_id, _, _) = open_request(&at_server).expect("no open request");
    let back = to_client(client, server.accept_channel(server_id, Vec::new()));
    let (opened_id, _) = opened(&back).expect("not opened");
    assert_eq!(Some(opened_id), id);
    (opened_id, server_id)
}

#[test]
fn a_channel_the_client_opens_is_confirmed_with_the_servers_data() {
    let (mut server, mut client) = authenticated_pair();
    let (id, actions) = client.open_channel("direct-tcpip", b"\x00\x01opaque".to_vec());
    let id = id.expect("no channel id");
    let at_server = to_server(&mut server, actions);
    let (server_id, kind, data) = open_request(&at_server).expect("no open request");
    assert_eq!(
        (kind.as_str(), data.as_slice()),
        ("direct-tcpip", &b"\x00\x01opaque"[..])
    );

    let back = to_client(
        &mut client,
        server.accept_channel(server_id, b"conf".to_vec()),
    );
    assert_eq!(opened(&back), Some((id, b"conf".to_vec())));
    let info = client.channel_info(id).expect("no channel info");
    assert_eq!(info.kind(), "direct-tcpip");
    assert_eq!(info.peer_window(), 64 * 32 * 1024);
}

#[test]
fn a_refused_open_reports_the_servers_reason_and_message() {
    let (mut server, mut client) = authenticated_pair();
    let (id, actions) = client.open_channel("x11", Vec::new());
    let at_server = to_server(&mut server, actions);
    let (server_id, _, _) = open_request(&at_server).unwrap();
    let back = to_client(
        &mut client,
        server.reject_channel(server_id, OpenFailureReason::CONNECT_FAILED, "no route"),
    );
    let failed: Vec<_> = back
        .iter()
        .filter_map(|a| match a {
            Action::ChannelOpenFailed {
                channel,
                reason,
                description,
            } => Some((*channel, *reason, description.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        failed,
        [(
            id.unwrap(),
            OpenFailureReason::CONNECT_FAILED,
            "no route".to_owned()
        )]
    );
    assert!(client.channel_info(id.unwrap()).is_none());
}

#[test]
fn a_confirmation_with_an_invalid_maximum_packet_ends_the_connection() {
    let (mut server, mut client) = authenticated_pair();
    let (id, actions) = client.open_channel("session", Vec::new());
    server.set_raw_receive(true);
    to_server(&mut server, actions);
    let confirm = Message::ChannelOpenConfirmation(ChannelOpenConfirmation::new(
        id.unwrap().get(),
        9,
        1000,
        8,
        Vec::new(),
    ))
    .encode();
    let back = to_client(&mut client, server.send_raw(&confirm));
    assert!(
        matches!(
            closed(&back),
            Some(Closed::Local {
                reason: DisconnectReason::PROTOCOL_ERROR,
                error: Error::InvalidChannelMaxPacket,
                ..
            })
        ),
        "{back:?}"
    );
}

#[test]
fn an_answer_to_an_open_nobody_sent_ends_the_connection() {
    for answer in [
        Message::ChannelOpenConfirmation(ChannelOpenConfirmation::new(
            5,
            9,
            1000,
            1000,
            Vec::new(),
        )),
        Message::ChannelOpenFailure(ChannelOpenFailure::new(5, 1, "no", "")),
    ] {
        let (mut server, mut client) = authenticated_pair();
        server.set_raw_receive(true);
        let back = to_client(&mut client, server.send_raw(&answer.encode()));
        assert!(
            matches!(
                closed(&back),
                Some(Closed::Local {
                    error: Error::UnknownChannel { channel: 5 },
                    ..
                })
            ),
            "{back:?}"
        );
    }
}

#[test]
fn a_second_confirmation_for_an_open_channel_ends_the_connection() {
    let (mut server, mut client) = authenticated_pair();
    let (id, _) = client_channel(&mut server, &mut client);
    server.set_raw_receive(true);
    let again = Message::ChannelOpenConfirmation(ChannelOpenConfirmation::new(
        id.get(),
        9,
        1000,
        1000,
        Vec::new(),
    ))
    .encode();
    let back = to_client(&mut client, server.send_raw(&again));
    assert!(
        matches!(
            closed(&back),
            Some(Closed::Local {
                reason: DisconnectReason::PROTOCOL_ERROR,
                error: Error::UnknownChannel { channel },
                ..
            }) if *channel == id.get()
        ),
        "{back:?}"
    );
}

#[test]
fn each_reply_comes_back_with_the_token_of_its_request() {
    let (mut server, mut client) = authenticated_pair();
    let (id, _) = client_channel(&mut server, &mut client);
    let mut tokens = Vec::new();
    let mut at_server = Vec::new();
    for kind in ["pty-req", "env", "exec"] {
        let (token, actions) = client.channel_request(id, kind, true, Vec::new());
        tokens.push(token.expect("no token for a request wanting a reply"));
        at_server.extend(to_server(&mut server, actions));
    }
    let (none, _) = client.channel_request(id, "window-change", false, Vec::new());
    assert_eq!(none, None);
    assert_eq!(
        tokens
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        3
    );

    let reply_tokens: Vec<_> = at_server
        .iter()
        .filter_map(|a| match a {
            Action::ChannelRequest(r) => r.reply(),
            _ => None,
        })
        .collect();
    let mut back = Vec::new();
    for (token, ok) in reply_tokens.into_iter().zip([true, false, true]) {
        back.extend(to_client(
            &mut client,
            server.reply_channel_request(token, ok),
        ));
    }
    let replies: Vec<(ChannelId, RequestToken, bool)> = back
        .iter()
        .filter_map(|a| match a {
            Action::ChannelRequestReply { channel, token, ok } => Some((*channel, *token, *ok)),
            _ => None,
        })
        .collect();
    assert_eq!(
        replies,
        [
            (id, tokens[0], true),
            (id, tokens[1], false),
            (id, tokens[2], true)
        ]
    );
}

#[test]
fn global_replies_come_back_with_their_tokens_and_payloads() {
    let (mut server, mut client) = authenticated_pair();
    let (first, a) = client.global_request("tcpip-forward", true, b"bind".to_vec());
    let (second, b) = client.global_request("no-more-sessions@openssh.com", true, Vec::new());
    let mut at_server = to_server(&mut server, a);
    at_server.extend(to_server(&mut server, b));
    let tokens: Vec<_> = at_server
        .iter()
        .filter_map(|x| match x {
            Action::GlobalRequest(r) => r.reply(),
            _ => None,
        })
        .collect();
    let mut back = to_client(
        &mut client,
        server.reply_global_request(tokens[0], true, b"\x00\x00\x9c\x40".to_vec()),
    );
    back.extend(to_client(
        &mut client,
        server.reply_global_request(tokens[1], false, Vec::new()),
    ));
    let replies: Vec<_> = back
        .iter()
        .filter_map(|x| match x {
            Action::GlobalRequestReply { token, ok, data } => Some((*token, *ok, data.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        replies,
        [
            (first.unwrap(), true, b"\x00\x00\x9c\x40".to_vec()),
            (second.unwrap(), false, Vec::new())
        ]
    );
}

#[test]
fn a_channel_the_server_opens_can_be_refused_as_prohibited() {
    let (mut server, mut client) = authenticated_pair();
    let (server_id, actions) = server.open_channel("x11", b"\x00\x00\x00\x09127.0.0.1".to_vec());
    let at_client = to_client(&mut client, actions);
    let (client_id, kind, _) = open_request(&at_client).expect("no open request at the client");
    assert_eq!(kind, "x11");
    let back = to_server(
        &mut server,
        client.reject_channel(
            client_id,
            OpenFailureReason::ADMINISTRATIVELY_PROHIBITED,
            "acwbroker does not accept upstream-initiated channels",
        ),
    );
    assert!(
        back.iter().any(|a| matches!(
            a,
            Action::ChannelOpenFailed { channel, reason, description }
                if Some(*channel) == server_id
                    && *reason == OpenFailureReason::ADMINISTRATIVELY_PROHIBITED
                    && description == "acwbroker does not accept upstream-initiated channels"
        )),
        "{back:?}"
    );
}

#[test]
fn the_servers_keepalive_reaches_the_client_and_can_be_answered() {
    let (mut server, mut client) = authenticated_pair();
    let (sent, actions) = server.global_request("keepalive@openssh.com", true, Vec::new());
    let at_client = to_client(&mut client, actions);
    let Some(Action::GlobalRequest(request)) = at_client.first() else {
        panic!("no global request at the client: {at_client:?}");
    };
    assert_eq!(
        (request.kind(), request.want_reply()),
        ("keepalive@openssh.com", true)
    );
    let token = request.reply().unwrap();
    let back = to_server(
        &mut server,
        client.reply_global_request(token, false, Vec::new()),
    );
    assert!(
        back.iter().any(|a| matches!(
            a,
            Action::GlobalRequestReply { token, ok: false, .. } if Some(*token) == sent
        )),
        "{back:?}"
    );
}

#[test]
fn a_token_from_another_connection_answers_nothing() {
    let (mut server_a, mut client_a) = authenticated_pair();
    let (mut server_b, mut client_b) = authenticated_pair();
    let (_, a) = server_a.global_request("keepalive@openssh.com", true, Vec::new());
    let (_, b) = server_b.global_request("keepalive@openssh.com", true, Vec::new());
    let token_of = |actions: Vec<Action>| match actions.into_iter().next() {
        Some(Action::GlobalRequest(r)) => r.reply().unwrap(),
        other => panic!("{other:?}"),
    };
    let token_a = token_of(to_client(&mut client_a, a));
    let token_b = token_of(to_client(&mut client_b, b));

    assert!(
        client_a
            .reply_global_request(token_b, true, Vec::new())
            .is_empty()
    );
    assert!(
        !client_a
            .reply_global_request(token_a, true, Vec::new())
            .is_empty()
    );
}

#[test]
fn a_channel_request_token_from_another_connection_answers_nothing() {
    let (mut server_a, mut client_a) = authenticated_pair();
    let (mut server_b, mut client_b) = authenticated_pair();
    let (a_id, _) = client_channel(&mut server_a, &mut client_a);
    let (b_id, _) = client_channel(&mut server_b, &mut client_b);
    assert_eq!(a_id.get(), b_id.get());
    let token_of = |server: &mut Server, client: &mut Client, id| {
        let (_, actions) = client.channel_request(id, "exec", true, Vec::new());
        match to_server(server, actions).into_iter().next() {
            Some(Action::ChannelRequest(r)) => r.reply().unwrap(),
            other => panic!("{other:?}"),
        }
    };
    let token_a = token_of(&mut server_a, &mut client_a, a_id);
    let token_b = token_of(&mut server_b, &mut client_b, b_id);
    assert!(server_a.reply_channel_request(token_b, true).is_empty());
    assert!(!server_a.reply_channel_request(token_a, true).is_empty());
}

#[test]
fn an_exec_round_trip_carries_output_and_exit_status_in_order() {
    let (mut server, mut client) = authenticated_pair();
    let (id, server_id) = client_channel(&mut server, &mut client);
    let mut cmd = vec![0, 0, 0, 2];
    cmd.extend(b"id");
    let (token, actions) = client.channel_request(id, "exec", true, cmd.clone());
    let at_server = to_server(&mut server, actions);
    let Some(Action::ChannelRequest(r)) = at_server.first() else {
        panic!("{at_server:?}");
    };
    assert_eq!((r.kind(), r.data()), ("exec", cmd.as_slice()));

    let mut out = server.reply_channel_request(r.reply().unwrap(), true);
    out.extend(server.channel_data(server_id, b"uid=0\n"));
    out.extend(server.channel_extended_data(server_id, 1, b"warn\n"));
    let (_, status) = server.channel_request(server_id, "exit-status", false, vec![0, 0, 0, 3]);
    out.extend(status);
    out.extend(server.channel_eof(server_id));
    out.extend(server.channel_close(server_id));
    let back = to_client(&mut client, out);

    let seen: Vec<String> = back
        .iter()
        .filter_map(|a| match a {
            Action::ChannelRequestReply { token: t, ok, .. } if Some(*t) == token => {
                Some(format!("reply {ok}"))
            }
            Action::ChannelData { data, .. } => {
                Some(format!("out {}", String::from_utf8_lossy(data)))
            }
            Action::ChannelExtendedData { code, data, .. } => {
                Some(format!("ext{code} {}", String::from_utf8_lossy(data)))
            }
            Action::ChannelRequest(r) => Some(format!("{} {:?}", r.kind(), r.data())),
            Action::ChannelEof { .. } => Some("eof".into()),
            Action::ChannelClosed { .. } => Some("closed".into()),
            _ => None,
        })
        .collect();
    assert_eq!(
        seen,
        [
            "reply true",
            "out uid=0\n",
            "ext1 warn\n",
            "exit-status [0, 0, 0, 3]",
            "eof",
            "closed"
        ]
    );
}

#[test]
fn data_the_client_sends_reaches_the_server_in_order() {
    let (mut server, mut client) = authenticated_pair();
    let (id, server_id) = client_channel(&mut server, &mut client);
    let mut out = client.channel_data(id, b"ls\n");
    out.extend(client.channel_eof(id));
    let at_server = to_server(&mut server, out);
    assert!(
        matches!(
            &at_server[..],
            [Action::ChannelData { channel, data }, Action::ChannelEof { channel: c2 }]
                if *channel == server_id && data == b"ls\n" && *c2 == server_id
        ),
        "{at_server:?}"
    );
}

#[test]
fn commands_on_a_channel_still_opening_wait_for_its_confirmation() {
    let (mut server, mut client) = authenticated_pair();
    let (id, actions) = client.open_channel("session", Vec::new());
    let id = id.unwrap();
    assert!(client.channel_data(id, b"early").is_empty());
    let (token, request) = client.channel_request(id, "exec", true, Vec::new());
    assert!(token.is_some());
    assert!(request.is_empty());
    assert!(client.channel_eof(id).is_empty());

    let at_server = to_server(&mut server, actions);
    let (server_id, _, _) = open_request(&at_server).unwrap();
    let back = to_client(&mut client, server.accept_channel(server_id, Vec::new()));
    assert_eq!(opened(&back), Some((id, Vec::new())));
    let sent = to_server(&mut server, back);
    let seen: Vec<String> = sent
        .iter()
        .filter_map(|a| match a {
            Action::ChannelData { data, .. } => {
                Some(format!("data {}", String::from_utf8_lossy(data)))
            }
            Action::ChannelRequest(r) => Some(format!("request {}", r.kind())),
            Action::ChannelEof { .. } => Some("eof".into()),
            _ => None,
        })
        .collect();
    assert_eq!(seen, ["data early", "request exec", "eof"]);
}

#[test]
fn a_channel_aborted_while_opening_is_closed_once_confirmed() {
    let (mut server, mut client) = authenticated_pair();
    let (id, actions) = client.open_channel("session", Vec::new());
    let id = id.unwrap();
    client.channel_data(id, b"never");
    assert!(client.channel_abort(id).is_empty());
    let at_server = to_server(&mut server, actions);
    let (server_id, _, _) = open_request(&at_server).unwrap();
    let back = to_client(&mut client, server.accept_channel(server_id, Vec::new()));
    let sent = to_server(&mut server, back);
    assert!(
        !sent.iter().any(|a| matches!(a, Action::ChannelData { .. })),
        "{sent:?}"
    );
    assert!(
        sent.iter()
            .any(|a| matches!(a, Action::ChannelClosed { channel } if *channel == server_id)),
        "{sent:?}"
    );
}

#[test]
fn requests_go_to_the_id_the_peer_confirmed_with() {
    let (mut server, mut client) = authenticated_pair();
    let (id, actions) = client.open_channel("session", Vec::new());
    let id = id.unwrap();
    server.set_raw_receive(true);
    to_server(&mut server, actions);
    let confirm = Message::ChannelOpenConfirmation(ChannelOpenConfirmation::new(
        id.get(),
        77,
        1000,
        1000,
        Vec::new(),
    ))
    .encode();
    let back = to_client(&mut client, server.send_raw(&confirm));
    assert_eq!(opened(&back), Some((id, Vec::new())));

    let (_, request) = client.channel_request(id, "exec", false, Vec::new());
    let got: Vec<_> = to_server(&mut server, request)
        .into_iter()
        .filter_map(|a| match a {
            Action::RawReceived(p) => Some(Message::decode(&p).unwrap()),
            _ => None,
        })
        .collect();
    assert!(
        matches!(&got[..], [Message::ChannelRequest(r)] if r.recipient == 77),
        "{got:?}"
    );
}

#[test]
fn accepting_or_refusing_a_channel_this_side_is_opening_does_nothing() {
    let (mut server, mut client) = authenticated_pair();
    let (id, actions) = client.open_channel("session", Vec::new());
    let id = id.unwrap();
    assert!(client.accept_channel(id, Vec::new()).is_empty());
    assert!(
        client
            .reject_channel(id, OpenFailureReason::CONNECT_FAILED, "no")
            .is_empty()
    );
    let at_server = to_server(&mut server, actions);
    let (server_id, _, _) = open_request(&at_server).unwrap();
    let back = to_client(&mut client, server.accept_channel(server_id, Vec::new()));
    assert_eq!(opened(&back), Some((id, Vec::new())));
}

#[test]
fn the_client_announces_the_window_and_maximum_packet_it_was_configured_with() {
    let mut server = server();
    let mut client = justssh::Client::new(
        justssh::ClientConfig::builder(CLIENT_USER)
            .rng(TestRng(2))
            .channel_window(5000)
            .channel_max_packet(1000)
            .build(),
    );
    let (s, c) = pump(&mut server, &mut client, usize::MAX);
    assert!(s.closed.is_none() && c.closed.is_none());
    let request = client.auth_password(justssh::Zeroizing::new(b"pw".to_vec()));
    to_server(&mut server, request);
    to_client(&mut client, server.process(justssh::Event::AuthAccepted));

    let (_, actions) = client.open_channel("session", Vec::new());
    let at_server = to_server(&mut server, actions);
    let Some(Action::ChannelOpenRequest(r)) = at_server.first() else {
        panic!("{at_server:?}");
    };
    assert_eq!((r.peer_window(), r.peer_max_packet()), (5000, 1000));
}

#[test]
fn nothing_goes_out_on_a_channel_still_opening() {
    let (_server, mut client) = authenticated_pair();
    let (id, _) = client.open_channel("session", Vec::new());
    let id = id.unwrap();
    let (_, request) = client.channel_request(id, "exec", true, Vec::new());
    assert!(request.is_empty(), "{request:?}");
    assert!(client.channel_eof(id).is_empty());
    let aborted = client.channel_abort(id);
    assert!(
        !aborted.iter().any(|a| matches!(a, Action::Write(_))),
        "{aborted:?}"
    );
}

/// The failed replies in `actions`, with the position of the `ChannelClosed` or
/// `ChannelOpenFailed` after them.
fn failed_replies(actions: &[Action]) -> (Vec<RequestToken>, Option<usize>) {
    let tokens = actions
        .iter()
        .filter_map(|a| match a {
            Action::ChannelRequestReply {
                token, ok: false, ..
            } => Some(*token),
            _ => None,
        })
        .collect();
    let end = actions.iter().position(|a| {
        matches!(
            a,
            Action::ChannelClosed { .. } | Action::ChannelOpenFailed { .. }
        )
    });
    (tokens, end)
}

#[test]
fn requests_still_awaiting_a_reply_fail_when_the_peer_closes_the_channel() {
    let (mut server, mut client) = authenticated_pair();
    let (id, server_id) = client_channel(&mut server, &mut client);
    let (first, a) = client.channel_request(id, "exec", true, Vec::new());
    let (second, b) = client.channel_request(id, "env", true, Vec::new());
    to_server(&mut server, a);
    to_server(&mut server, b);
    let back = to_client(&mut client, server.channel_abort(server_id));
    let (tokens, end) = failed_replies(&back);
    assert_eq!(tokens, [first.unwrap(), second.unwrap()]);
    assert_eq!(end, Some(back.len() - 1), "{back:?}");
}

#[test]
fn queued_requests_fail_when_this_side_aborts_the_channel() {
    let (mut server, mut client) = authenticated_pair();
    let (id, actions) = client.open_channel("session", Vec::new());
    let id = id.unwrap();
    let (token, _) = client.channel_request(id, "exec", true, Vec::new());
    let aborted = client.channel_abort(id);
    let (tokens, _) = failed_replies(&aborted);
    assert_eq!(tokens, [token.unwrap()]);
    let _ = to_server(&mut server, actions);
}

#[test]
fn queued_requests_fail_when_the_open_is_refused() {
    let (mut server, mut client) = authenticated_pair();
    let (id, actions) = client.open_channel("session", Vec::new());
    let (token, _) = client.channel_request(id.unwrap(), "exec", true, Vec::new());
    let at_server = to_server(&mut server, actions);
    let (server_id, _, _) = open_request(&at_server).unwrap();
    let back = to_client(
        &mut client,
        server.reject_channel(server_id, OpenFailureReason::CONNECT_FAILED, "no"),
    );
    let (tokens, end) = failed_replies(&back);
    assert_eq!(tokens, [token.unwrap()]);
    assert_eq!(end, Some(back.len() - 1), "{back:?}");
}

#[test]
fn a_request_queued_behind_a_close_fails() {
    let (mut server, mut client) = authenticated_pair();
    let (id, _) = client_channel(&mut server, &mut client);
    let peer_window = client.channel_info(id).unwrap().peer_window() as usize;
    let mut out = client.channel_data(id, &vec![b'x'; peer_window + 1]);
    out.extend(client.channel_close(id));
    let (token, after_close) = client.channel_request(id, "exec", true, Vec::new());
    assert!(after_close.is_empty());
    let more = to_server(&mut server, out);
    let ids: Vec<_> = more
        .iter()
        .filter_map(|a| match a {
            Action::ChannelData { channel, data } => Some((*channel, data.len())),
            _ => None,
        })
        .collect();
    let (server_id, _) = ids[0];
    let back = to_client(
        &mut client,
        server.channel_consumed(server_id, peer_window as u32),
    );
    let (tokens, _) = failed_replies(&back);
    assert_eq!(tokens, [token.unwrap()]);
}

#[test]
fn a_channel_id_from_another_connection_does_nothing() {
    let (mut server_a, mut client_a) = authenticated_pair();
    let (mut server_b, mut client_b) = authenticated_pair();
    let (a_id, _) = client_channel(&mut server_a, &mut client_a);
    let (b_id, _) = client_channel(&mut server_b, &mut client_b);
    assert_eq!(a_id.get(), b_id.get());
    assert_ne!(a_id, b_id);
    assert!(client_a.channel_data(b_id, b"crossed").is_empty());
    assert!(client_a.channel_close(b_id).is_empty());
    assert!(client_a.channel_info(b_id).is_none());
    assert!(!client_a.channel_data(a_id, b"own").is_empty());
}

/// The server-side reply tokens of the channel requests in `actions`, by kind.
fn server_requests(actions: &[Action]) -> Vec<(String, Option<justssh::ReplyToken>)> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::ChannelRequest(r) => Some((r.kind().to_owned(), r.reply())),
            _ => None,
        })
        .collect()
}

#[test]
fn a_request_wanting_a_reply_queued_while_opening_goes_ahead_of_data_once_confirmed() {
    let (mut server, mut client) = authenticated_pair();
    let (id, opening) = client.open_channel("session", Vec::new());
    let id = id.unwrap();
    let at_server = to_server(&mut server, opening);
    let (server_id, _, _) = open_request(&at_server).expect("no open request");
    let window = 2 * 1024 * 1024;
    let mut queued = client.channel_data(id, &vec![b'x'; window + 1000]);
    let (early, more) = client.channel_request(id, "early@example.com", true, Vec::new());
    queued.extend(more);
    assert!(queued.is_empty(), "{queued:?}");

    let back = to_client(&mut client, server.accept_channel(server_id, Vec::new()));
    let first = server_requests(&to_server(&mut server, back));
    assert_eq!(first.len(), 1, "{first:?}");
    assert_eq!(first[0].0, "early@example.com");
    assert!(client.channel_info(id).unwrap().queued() > 0);

    let (late, sent) = client.channel_request(id, "late@example.com", true, Vec::new());
    let second = server_requests(&to_server(&mut server, sent));
    assert_eq!(second.len(), 1);
    let mut answers = server.reply_channel_request(first[0].1.unwrap(), true);
    answers.extend(server.reply_channel_request(second[0].1.unwrap(), false));
    let replies: Vec<_> = to_client(&mut client, answers)
        .into_iter()
        .filter_map(|a| match a {
            Action::ChannelRequestReply { token, ok, .. } => Some((token, ok)),
            _ => None,
        })
        .collect();
    assert_eq!(replies, [(early.unwrap(), true), (late.unwrap(), false)]);
}
