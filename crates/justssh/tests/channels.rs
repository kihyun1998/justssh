//! Server channels (RFC 4254), driven by a raw client (`test-support`).

mod common;

use common::*;
use justssh::{Action, ChannelId, Client, Closed, Error, Event, Server};
use justssh_wire::{
    ChannelClose, ChannelData, ChannelEof, ChannelExtendedData, ChannelOpen, ChannelRequest,
    ChannelWindowAdjust, GlobalRequest, Message, UserauthRequest,
};

const WINDOW: u32 = 2 * 1024 * 1024;
const MAX_PACKET: u32 = 32 * 1024;

/// The peer opens channel `peer_id` with `window` and the server accepts it.
fn open(server: &mut Server, client: &mut Client, peer_id: u32, window: u32) -> ChannelId {
    let actions = send(
        server,
        client,
        &[Message::ChannelOpen(ChannelOpen::new(
            "session".into(),
            peer_id,
            window,
            MAX_PACKET,
            Vec::new(),
        ))],
    );
    let id = actions
        .iter()
        .find_map(|a| match a {
            Action::ChannelOpenRequest(r) => Some(r.channel()),
            _ => None,
        })
        .expect("no open request");
    let confirmed = replies(client, &server.accept_channel(id, Vec::new()));
    assert!(
        matches!(&confirmed[..], [Message::ChannelOpenConfirmation(c)]
        if c.recipient == peer_id && c.window == WINDOW && c.max_packet == MAX_PACKET)
    );
    id
}

fn requests(actions: &[Action]) -> Vec<(String, bool, Vec<u8>)> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::ChannelRequest(r) => Some((
                r.kind().to_str().unwrap().to_owned(),
                r.want_reply(),
                r.data().to_vec(),
            )),
            _ => None,
        })
        .collect()
}

fn request(peer_channel: u32, kind: &str, want_reply: bool, data: Vec<u8>) -> Message {
    Message::ChannelRequest(ChannelRequest::new(
        peer_channel,
        kind.into(),
        want_reply,
        data,
    ))
}

fn pty_req(term: &str, modes: &[(u8, u32)]) -> Vec<u8> {
    let mut d = (term.len() as u32).to_be_bytes().to_vec();
    d.extend(term.as_bytes());
    for v in [80u32, 24, 0, 0] {
        d.extend(v.to_be_bytes());
    }
    let mut m = Vec::new();
    for (op, v) in modes {
        m.push(*op);
        m.extend(v.to_be_bytes());
    }
    m.push(0);
    d.extend((m.len() as u32).to_be_bytes());
    d.extend(m);
    d
}

#[test]
fn an_open_of_any_type_reaches_the_consumer_with_its_data() {
    let (mut server, mut client) = connected();
    let data = b"\0\0\0\x09127.0.0.1\0\0\0\x16\0\0\0\x09127.0.0.1\0\0\xd4\x31".to_vec();
    let actions = send(
        &mut server,
        &mut client,
        &[Message::ChannelOpen(ChannelOpen::new(
            "direct-tcpip".into(),
            3,
            1000,
            1000,
            data.clone(),
        ))],
    );
    let open = actions
        .iter()
        .find_map(|a| match a {
            Action::ChannelOpenRequest(r) => Some(r),
            _ => None,
        })
        .expect("no open request");
    assert_eq!(open.kind(), "direct-tcpip");
    assert_eq!(open.data(), &data[..]);
    assert_eq!((open.peer_window(), open.peer_max_packet()), (1000, 1000));
}

#[test]
fn an_open_can_be_refused_with_a_reason_and_message() {
    let (mut server, mut client) = connected();
    let actions = send(
        &mut server,
        &mut client,
        &[Message::ChannelOpen(ChannelOpen::new(
            "x11".into(),
            9,
            WINDOW,
            MAX_PACKET,
            Vec::new(),
        ))],
    );
    let id = actions
        .iter()
        .find_map(|a| match a {
            Action::ChannelOpenRequest(r) => Some(r.channel()),
            _ => None,
        })
        .unwrap();
    let out = replies(
        &mut client,
        &server.reject_channel(
            id,
            justssh::OpenFailureReason::ADMINISTRATIVELY_PROHIBITED,
            "no",
        ),
    );
    assert!(matches!(&out[..], [Message::ChannelOpenFailure(f)]
        if f.recipient == 9 && f.reason == 1 && f.description == b"no"));
}

#[test]
fn measured_pty_modes_and_vendor_requests_arrive_byte_for_byte() {
    let (mut server, mut client) = connected();
    let id = open(&mut server, &mut client, 0, WINDOW);
    let vectors = [
        pty_req("xterm", &[(3, 127), (42, 1), (128, 38400), (129, 38400)]),
        pty_req(
            "xterm-256color",
            &[
                (1, 3),
                (5, 4),
                (4, 21),
                (8, 17),
                (9, 19),
                (10, 26),
                (12, 18),
                (13, 23),
                (14, 22),
                (2, 28),
                (128, 38400),
                (129, 38400),
            ],
        ),
        pty_req("xterm", &[(128, 38400), (129, 38400)]),
        pty_req(
            "xterm",
            &[(3, 8), (39, 1), (42, 1), (128, 38400), (129, 38400)],
        ),
    ];
    let mut sent: Vec<Message> = vectors
        .iter()
        .map(|v| request(id.get(), "pty-req", true, v.clone()))
        .collect();
    sent.push(request(
        id.get(),
        "simple@putty.projects.tartarus.org",
        false,
        Vec::new(),
    ));
    sent.push(request(
        id.get(),
        "winadj@putty.projects.tartarus.org",
        true,
        Vec::new(),
    ));
    let got = requests(&send(&mut server, &mut client, &sent));
    let expected: Vec<(String, bool, Vec<u8>)> = vectors
        .iter()
        .map(|v| ("pty-req".to_owned(), true, v.clone()))
        .chain([
            (
                "simple@putty.projects.tartarus.org".to_owned(),
                false,
                Vec::new(),
            ),
            (
                "winadj@putty.projects.tartarus.org".to_owned(),
                true,
                Vec::new(),
            ),
        ])
        .collect();
    assert_eq!(got, expected);
}

#[test]
fn replies_leave_in_the_order_the_requests_came_whatever_order_they_are_given() {
    let (mut server, mut client) = connected();
    let id = open(&mut server, &mut client, 0, WINDOW);
    let actions = send(
        &mut server,
        &mut client,
        &[
            request(id.get(), "pty-req", false, pty_req("xterm", &[])),
            request(id.get(), "shell", false, Vec::new()),
            request(id.get(), "env", true, Vec::new()),
            request(id.get(), "exec", true, Vec::new()),
        ],
    );
    let tokens: Vec<_> = actions
        .iter()
        .filter_map(|a| match a {
            Action::ChannelRequest(r) => Some(r.reply()),
            _ => None,
        })
        .collect();
    assert!(
        tokens[0].is_none() && tokens[1].is_none(),
        "want_reply=0 got a token"
    );
    let (env, exec) = (tokens[2].unwrap(), tokens[3].unwrap());
    assert!(replies(&mut client, &server.reply_channel_request(exec, true)).is_empty());
    let out = replies(&mut client, &server.reply_channel_request(env, false));
    assert!(matches!(
        &out[..],
        [Message::ChannelFailure(_), Message::ChannelSuccess(_)]
    ));
}

#[test]
fn a_request_can_be_refused_and_its_channel_closed() {
    let (mut server, mut client) = connected();
    let id = open(&mut server, &mut client, 4, WINDOW);
    let actions = send(
        &mut server,
        &mut client,
        &[request(id.get(), "subsystem", true, Vec::new())],
    );
    let token = actions
        .iter()
        .find_map(|a| match a {
            Action::ChannelRequest(r) => r.reply(),
            _ => None,
        })
        .unwrap();
    let mut out = replies(&mut client, &server.reply_channel_request(token, false));
    out.extend(replies(&mut client, &server.channel_close(id)));
    assert!(matches!(
        &out[..],
        [Message::ChannelFailure(f), Message::ChannelClose(c)] if f.recipient == 4 && c.recipient == 4
    ));
}

#[test]
fn data_eof_and_a_request_wait_behind_data_the_window_holds_back() {
    let (mut server, mut client) = connected();
    let id = open(&mut server, &mut client, 1, 10);
    let mut actions = server.channel_data(id, b"0123456789abcdefghij");
    actions.extend(server.channel_extended_data(id, 1, b"err"));
    actions.extend(server.channel_eof(id));
    actions.extend(
        server
            .channel_request(id, "exit-status", false, 7u32.to_be_bytes().to_vec())
            .1,
    );
    actions.extend(server.channel_close(id));
    let first = replies(&mut client, &actions);
    assert!(
        matches!(&first[..], [Message::ChannelData(d)] if d.data == b"0123456789"),
        "{first:?}"
    );
    assert_eq!(server.channel_info(id).unwrap().queued(), 13);

    let actions = send(
        &mut server,
        &mut client,
        &[Message::ChannelWindowAdjust(ChannelWindowAdjust::new(
            id.get(),
            100,
        ))],
    );
    let rest = replies(&mut client, &actions);
    match &rest[..] {
        [
            Message::ChannelData(d),
            Message::ChannelExtendedData(e),
            Message::ChannelEof(_),
            Message::ChannelRequest(r),
            Message::ChannelClose(_),
        ] => {
            assert_eq!(d.data, b"abcdefghij");
            assert_eq!((e.code, e.data.as_slice()), (1, &b"err"[..]));
            assert_eq!(
                (r.kind.to_str(), r.want_reply),
                (Some("exit-status"), false)
            );
        }
        other => panic!("out of order: {other:?}"),
    }
}

#[test]
fn data_is_split_at_the_peers_maximum_packet() {
    let (mut server, mut client) = connected();
    let actions = send(
        &mut server,
        &mut client,
        &[Message::ChannelOpen(ChannelOpen::new(
            "session".into(),
            2,
            WINDOW,
            9,
            Vec::new(),
        ))],
    );
    let id = actions
        .iter()
        .find_map(|a| match a {
            Action::ChannelOpenRequest(r) => Some(r.channel()),
            _ => None,
        })
        .unwrap();
    replies(&mut client, &server.accept_channel(id, Vec::new()));
    let out = replies(
        &mut client,
        &server.channel_data(id, b"abcdefghijklmnopqrst"),
    );
    let sizes: Vec<usize> = out
        .iter()
        .map(|m| match m {
            Message::ChannelData(d) => d.data.len(),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(sizes, vec![9, 9, 2]);
}

#[test]
fn an_open_announcing_a_maximum_packet_below_9_is_refused_without_the_consumer() {
    let (mut server, mut client) = connected();
    let actions = send(
        &mut server,
        &mut client,
        &[Message::ChannelOpen(ChannelOpen::new(
            "session".into(),
            5,
            WINDOW,
            8,
            Vec::new(),
        ))],
    );
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::ChannelOpenRequest(_)))
    );
    let out = replies(&mut client, &actions);
    assert!(
        matches!(&out[..], [Message::ChannelOpenFailure(f)] if f.recipient == 5 && f.reason == 2)
    );
}

#[test]
fn incoming_data_and_any_extended_data_reach_the_consumer() {
    let (mut server, mut client) = connected();
    let id = open(&mut server, &mut client, 0, WINDOW);
    let actions = send(
        &mut server,
        &mut client,
        &[
            Message::ChannelData(ChannelData::new(id.get(), b"in".to_vec())),
            Message::ChannelExtendedData(ChannelExtendedData::new(id.get(), 7, b"odd".to_vec())),
            Message::ChannelEof(ChannelEof::new(id.get())),
        ],
    );
    let got: Vec<String> = actions
        .iter()
        .filter_map(|a| match a {
            Action::ChannelData { channel, data } if *channel == id => {
                Some(format!("data:{}", String::from_utf8_lossy(data)))
            }
            Action::ChannelExtendedData { code, data, .. } => {
                Some(format!("ext{code}:{}", String::from_utf8_lossy(data)))
            }
            Action::ChannelEof { .. } => Some("eof".into()),
            _ => None,
        })
        .collect();
    assert_eq!(got, vec!["data:in", "ext7:odd", "eof"]);
}

#[test]
fn the_window_is_given_back_only_as_the_consumer_consumes() {
    let (mut server, mut client) = connected();
    let id = open(&mut server, &mut client, 0, WINDOW);
    let chunk = vec![0u8; MAX_PACKET as usize];
    let data: Vec<Message> = (0..4)
        .map(|_| Message::ChannelData(ChannelData::new(id.get(), chunk.clone())))
        .collect();
    let actions = send(&mut server, &mut client, &data);
    assert!(
        replies(&mut client, &actions).is_empty(),
        "window given back before consumption"
    );
    let out = replies(&mut client, &server.channel_consumed(id, 4 * MAX_PACKET));
    assert!(matches!(&out[..], [Message::ChannelWindowAdjust(a)]
        if a.recipient == 0 && a.bytes == 4 * MAX_PACKET));
}

#[test]
fn data_beyond_the_window_ends_the_connection() {
    let (mut server, mut client) = connected();
    let id = open(&mut server, &mut client, 0, WINDOW);
    let chunk = vec![0u8; MAX_PACKET as usize];
    let data: Vec<Message> = (0..=(WINDOW / MAX_PACKET))
        .map(|_| Message::ChannelData(ChannelData::new(id.get(), chunk.clone())))
        .collect();
    let actions = send(&mut server, &mut client, &data);
    assert!(actions.iter().any(|a| matches!(
        a,
        Action::Closed(Closed::Local {
            error: Error::ChannelWindowExceeded,
            ..
        })
    )));
}

#[test]
fn a_peer_close_is_answered_and_reported() {
    let (mut server, mut client) = connected();
    let id = open(&mut server, &mut client, 6, WINDOW);
    let actions = send(
        &mut server,
        &mut client,
        &[Message::ChannelClose(ChannelClose::new(id.get()))],
    );
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, Action::ChannelClosed { channel } if *channel == id))
    );
    let out = replies(&mut client, &actions);
    assert!(matches!(&out[..], [Message::ChannelClose(c)] if c.recipient == 6));
    assert!(server.channel_info(id).is_none());
}

#[test]
fn a_message_for_an_unknown_channel_ends_the_connection() {
    let (mut server, mut client) = connected();
    let actions = send(
        &mut server,
        &mut client,
        &[Message::ChannelData(ChannelData::new(42, b"x".to_vec()))],
    );
    assert!(actions.iter().any(|a| matches!(
        a,
        Action::Closed(Closed::Local {
            error: Error::UnknownChannel { .. },
            ..
        })
    )));
}

#[test]
fn the_peers_window_and_maximum_packet_can_be_read() {
    let (mut server, mut client) = connected();
    let id = open(&mut server, &mut client, 0, 777);
    let info = server.channel_info(id).unwrap();
    assert_eq!(
        (
            info.kind().to_str(),
            info.peer_window(),
            info.peer_max_packet()
        ),
        (Some("session"), 777, MAX_PACKET)
    );
}

#[test]
fn the_default_window_and_maximum_packet_can_be_set() {
    let mut server = server_with(|b| b.channel_window(5000).channel_max_packet(1000));
    let mut client = client();
    pump(&mut server, &mut client, usize::MAX);
    client.set_raw_receive(true);
    let mut pw = vec![0, 0, 0, 0, 2];
    pw.extend(b"pw");
    send(
        &mut server,
        &mut client,
        &[Message::UserauthRequest(UserauthRequest::new(
            b"u".to_vec(),
            "ssh-connection",
            "password",
            pw,
        ))],
    );
    let a = server.process(Event::AuthAccepted);
    replies(&mut client, &a);
    let actions = send(
        &mut server,
        &mut client,
        &[Message::ChannelOpen(ChannelOpen::new(
            "session".into(),
            0,
            WINDOW,
            MAX_PACKET,
            Vec::new(),
        ))],
    );
    let id = actions
        .iter()
        .find_map(|a| match a {
            Action::ChannelOpenRequest(r) => Some(r.channel()),
            _ => None,
        })
        .unwrap();
    let out = replies(&mut client, &server.accept_channel(id, Vec::new()));
    assert!(matches!(&out[..], [Message::ChannelOpenConfirmation(c)]
        if c.window == 5000 && c.max_packet == 1000));
}

/// Opens a channel whose peer id differs from the server's, so a swapped recipient shows.
fn open_with_peer_id(
    server: &mut Server,
    client: &mut Client,
    peer_id: u32,
    window: u32,
) -> ChannelId {
    let id = open(server, client, peer_id, window);
    assert_ne!(
        id.get(),
        peer_id,
        "ids must differ for this test to mean anything"
    );
    id
}

#[test]
fn everything_sent_on_a_channel_is_addressed_to_the_peers_id() {
    let (mut server, mut client) = connected();
    let id = open_with_peer_id(&mut server, &mut client, 77, WINDOW);
    let mut actions = server.channel_data(id, b"d");
    actions.extend(server.channel_extended_data(id, 1, b"e"));
    actions.extend(server.channel_eof(id));
    actions.extend(server.channel_request(id, "r", false, Vec::new()).1);
    let chunk = vec![0u8; (4 * MAX_PACKET) as usize];
    actions.extend(send(&mut server, &mut client, &[]));
    let mut out = replies(&mut client, &actions);
    let data: Vec<Message> = chunk
        .chunks(MAX_PACKET as usize)
        .map(|c| Message::ChannelData(ChannelData::new(id.get(), c.to_vec())))
        .collect();
    send(&mut server, &mut client, &data);
    out.extend(replies(
        &mut client,
        &server.channel_consumed(id, 4 * MAX_PACKET),
    ));
    let recipients: Vec<u32> = out
        .iter()
        .map(|m| match m {
            Message::ChannelData(m) => m.recipient,
            Message::ChannelExtendedData(m) => m.recipient,
            Message::ChannelEof(m) => m.recipient,
            Message::ChannelRequest(m) => m.recipient,
            Message::ChannelWindowAdjust(m) => m.recipient,
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(recipients, vec![77; 5]);
}

#[test]
fn replies_to_our_requests_come_back_in_order() {
    let (mut server, mut client) = connected();
    let id = open_with_peer_id(&mut server, &mut client, 50, WINDOW);
    let (a, _) = server.channel_request(id, "a", true, Vec::new());
    let (b, _) = server.channel_request(id, "b", true, Vec::new());
    let actions = send(
        &mut server,
        &mut client,
        &[
            Message::ChannelFailure(justssh_wire::ChannelFailure::new(id.get())),
            Message::ChannelSuccess(justssh_wire::ChannelSuccess::new(id.get())),
        ],
    );
    let oks: Vec<_> = actions
        .iter()
        .filter_map(|r| match r {
            Action::ChannelRequestReply { channel, token, ok } if *channel == id => {
                Some((Some(*token), *ok))
            }
            _ => None,
        })
        .collect();
    assert_eq!(oks, vec![(a, false), (b, true)]);
}

#[test]
fn a_reply_nobody_asked_for_is_dropped() {
    let (mut server, mut client) = connected();
    let id = open(&mut server, &mut client, 0, WINDOW);
    let actions = send(
        &mut server,
        &mut client,
        &[Message::ChannelSuccess(justssh_wire::ChannelSuccess::new(
            id.get(),
        ))],
    );
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::Closed(_) | Action::ChannelRequestReply { .. }))
    );
}

#[test]
fn data_larger_than_the_announced_maximum_packet_ends_the_connection() {
    let (mut server, mut client) = connected();
    let id = open(&mut server, &mut client, 0, WINDOW);
    let big = vec![0u8; MAX_PACKET as usize + 1];
    let actions = send(
        &mut server,
        &mut client,
        &[Message::ChannelData(ChannelData::new(id.get(), big))],
    );
    assert!(actions.iter().any(|a| matches!(
        a,
        Action::Closed(Closed::Local {
            error: Error::ChannelPacketTooLarge,
            ..
        })
    )));
}

#[test]
fn a_window_adjust_past_two_to_the_32_ends_the_connection() {
    let (mut server, mut client) = connected();
    let id = open(&mut server, &mut client, 0, u32::MAX - 5);
    let actions = send(
        &mut server,
        &mut client,
        &[Message::ChannelWindowAdjust(ChannelWindowAdjust::new(
            id.get(),
            6,
        ))],
    );
    assert!(actions.iter().any(|a| matches!(
        a,
        Action::Closed(Closed::Local {
            error: Error::ChannelWindowOverflow,
            ..
        })
    )));
}

#[test]
fn a_peer_close_drops_what_was_still_queued() {
    let (mut server, mut client) = connected();
    let id = open(&mut server, &mut client, 0, 0);
    server.channel_data(id, b"never sent");
    let actions = send(
        &mut server,
        &mut client,
        &[Message::ChannelClose(ChannelClose::new(id.get()))],
    );
    let out = replies(&mut client, &actions);
    assert!(matches!(&out[..], [Message::ChannelClose(_)]), "{out:?}");
}

#[test]
fn data_and_requests_after_our_close_are_dropped() {
    let (mut server, mut client) = connected();
    let id = open(&mut server, &mut client, 0, WINDOW);
    replies(&mut client, &server.channel_close(id));
    let actions = send(
        &mut server,
        &mut client,
        &[
            Message::ChannelData(ChannelData::new(id.get(), b"late".to_vec())),
            request(id.get(), "late", true, Vec::new()),
        ],
    );
    assert!(!actions.iter().any(|a| matches!(
        a,
        Action::ChannelData { .. } | Action::ChannelRequest(_) | Action::Closed(_)
    )));
}

#[test]
fn consuming_a_little_gives_no_window_back_yet() {
    let (mut server, mut client) = connected();
    let id = open(&mut server, &mut client, 0, WINDOW);
    send(
        &mut server,
        &mut client,
        &[Message::ChannelData(ChannelData::new(
            id.get(),
            vec![0; 100],
        ))],
    );
    assert!(replies(&mut client, &server.channel_consumed(id, 100)).is_empty());
}

#[test]
fn an_abort_closes_at_once_dropping_what_the_window_held_back() {
    let (mut server, mut client) = connected();
    let id = open(&mut server, &mut client, 0, 0);
    server.channel_data(id, b"held");
    let out = replies(&mut client, &server.channel_abort(id));
    assert!(matches!(&out[..], [Message::ChannelClose(_)]), "{out:?}");
}

#[test]
fn a_repeated_eof_is_reported_once() {
    let (mut server, mut client) = connected();
    let id = open(&mut server, &mut client, 0, WINDOW);
    let actions = send(
        &mut server,
        &mut client,
        &[
            Message::ChannelEof(ChannelEof::new(id.get())),
            Message::ChannelEof(ChannelEof::new(id.get())),
        ],
    );
    let eofs = actions
        .iter()
        .filter(|a| matches!(a, Action::ChannelEof { .. }))
        .count();
    assert_eq!(eofs, 1);
}

#[test]
fn a_request_wanting_a_reply_overtakes_data_the_window_holds_back() {
    let (mut server, mut client) = connected();
    let id = open(&mut server, &mut client, 1, 10);
    let mut actions = server.channel_data(id, b"0123456789abcdefghij");
    actions.extend(
        server
            .channel_request(id, "exit-status", false, 0u32.to_be_bytes().to_vec())
            .1,
    );
    let (token, more) = server.channel_request(id, "keepalive@openssh.com", true, Vec::new());
    actions.extend(more);
    assert!(token.is_some());
    let sent = replies(&mut client, &actions);
    match &sent[..] {
        [Message::ChannelData(d), Message::ChannelRequest(r)] => {
            assert_eq!(d.data, b"0123456789");
            assert_eq!(
                (r.kind.to_str(), r.want_reply),
                (Some("keepalive@openssh.com"), true)
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(server.channel_info(id).unwrap().queued(), 10);
}

#[test]
fn a_drained_channel_is_reported_once_the_window_takes_what_was_queued() {
    let (mut server, mut client) = connected();
    let id = open(&mut server, &mut client, 1, 10);
    let actions = server.channel_data(id, b"0123456789abcdefghij");
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::ChannelDrained { .. }))
    );
    let actions = send(
        &mut server,
        &mut client,
        &[Message::ChannelWindowAdjust(ChannelWindowAdjust::new(
            id.get(),
            5,
        ))],
    );
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::ChannelDrained { .. }))
    );
    let actions = send(
        &mut server,
        &mut client,
        &[Message::ChannelWindowAdjust(ChannelWindowAdjust::new(
            id.get(),
            100,
        ))],
    );
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, Action::ChannelDrained { channel } if *channel == id)),
        "{actions:?}"
    );
    assert_eq!(server.channel_info(id).unwrap().queued(), 0);
}

#[test]
fn nothing_is_reported_drained_when_the_window_takes_everything_at_once() {
    let (mut server, mut client) = connected();
    let id = open(&mut server, &mut client, 1, WINDOW);
    let actions = server.channel_data(id, b"all of it");
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::ChannelDrained { .. }))
    );
    let actions = send(
        &mut server,
        &mut client,
        &[Message::ChannelWindowAdjust(ChannelWindowAdjust::new(
            id.get(),
            100,
        ))],
    );
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::ChannelDrained { .. }))
    );
}

#[test]
fn names_that_are_not_utf8_reach_the_consumer_and_go_out_again_as_received() {
    const NAME: &[u8] = b"x\x80\xe9@y";
    let (mut server, mut client) = connected();
    let actions = send(
        &mut server,
        &mut client,
        &[
            Message::ChannelOpen(ChannelOpen::new(
                NAME.into(),
                4,
                WINDOW,
                MAX_PACKET,
                Vec::new(),
            )),
            Message::GlobalRequest(GlobalRequest::new(NAME.into(), false, vec![1])),
        ],
    );
    let Some(Action::ChannelOpenRequest(open)) = actions.first() else {
        panic!("{actions:?}");
    };
    let Some(Action::GlobalRequest(global)) = actions.get(1) else {
        panic!("{actions:?}");
    };
    assert_eq!(
        (open.kind().as_bytes(), global.kind().as_bytes()),
        (NAME, NAME)
    );
    let id = open.channel();
    let confirmed = replies(&mut client, &server.accept_channel(id, Vec::new()));
    let [Message::ChannelOpenConfirmation(c)] = &confirmed[..] else {
        panic!("{confirmed:?}");
    };
    let actions = send(
        &mut server,
        &mut client,
        &[Message::ChannelRequest(ChannelRequest::new(
            c.sender,
            NAME.into(),
            false,
            vec![2],
        ))],
    );
    let Some(Action::ChannelRequest(request)) = actions.first() else {
        panic!("{actions:?}");
    };
    assert_eq!(request.kind().as_bytes(), NAME);

    let mut out = server
        .channel_request(id, request.kind(), false, Vec::new())
        .1;
    out.extend(
        server
            .channel_request(id, request.kind(), true, Vec::new())
            .1,
    );
    out.extend(server.global_request(global.kind(), false, Vec::new()).1);
    out.extend(server.open_channel(open.kind(), Vec::new()).1);
    let sent: Vec<Vec<u8>> = replies(&mut client, &out)
        .into_iter()
        .map(|m| match m {
            Message::ChannelRequest(m) => m.kind.into_bytes(),
            Message::GlobalRequest(m) => m.kind.into_bytes(),
            Message::ChannelOpen(m) => m.kind.into_bytes(),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(sent, [NAME; 4]);
}

#[test]
fn either_role_is_usable_as_a_trait_object() {
    let (server, _client) = connected();
    let mut endpoint: Box<dyn justssh::Endpoint> = Box::new(server);
    let (channel, _) = endpoint.open_channel(b"session", Vec::new());
    assert!(channel.is_some());
}
