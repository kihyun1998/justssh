//! Key re-exchange once connected: started by either side, by a threshold or on request, with
//! what is sent meanwhile held back and delivered in order, and nothing but key exchange taken
//! from a peer that has started one.

mod common;

use common::*;
use justssh::{
    Action, ChannelId, Client, ClientConfig, Closed, Error, Event, Phase, Server, Zeroizing,
};
use justssh_wire::{GlobalRequest, Message};

/// What each side did, other than writing, while their output was delivered back and forth.
#[derive(Default, Debug)]
struct Settled {
    server: Vec<Action>,
    client: Vec<Action>,
    /// Host key verdicts the client asked for, each accepted.
    verdicts: usize,
}

/// Delivers `from_client` and `from_server` to the other side, and whatever that produces, until
/// neither side writes.
fn settle(
    server: &mut Server,
    client: &mut Client,
    mut from_client: Vec<Action>,
    mut from_server: Vec<Action>,
) -> Settled {
    let mut out = Settled::default();
    loop {
        let mut moved = false;
        for a in std::mem::take(&mut from_client) {
            match a {
                Action::Write(b) => {
                    from_server.extend(server.process(Event::Received(&b)));
                    moved = true;
                }
                other => out.client.push(other),
            }
        }
        for a in std::mem::take(&mut from_server) {
            match a {
                Action::Write(b) => {
                    from_client.extend(client.process(Event::Received(&b)));
                    moved = true;
                }
                other => out.server.push(other),
            }
        }
        let mut answered = Vec::new();
        from_client.retain(|a| {
            if matches!(a, Action::VerifyHostKey { .. }) {
                answered.push(());
                false
            } else {
                true
            }
        });
        for () in answered {
            out.verdicts += 1;
            from_client.extend(client.process(Event::HostKeyAccepted));
            moved = true;
        }
        if !moved {
            return out;
        }
    }
}

fn closed(actions: &[Action]) -> Option<&Closed> {
    actions.iter().find_map(|a| match a {
        Action::Closed(c) => Some(c),
        _ => None,
    })
}

/// A channel from the client, accepted by the server: (client's id, server's id).
fn open(server: &mut Server, client: &mut Client) -> (ChannelId, ChannelId) {
    let (id, actions) = client.open_channel("session", Vec::new());
    let s = settle(server, client, actions, Vec::new());
    let server_id = match s.server.first() {
        Some(Action::ChannelOpenRequest(r)) => r.channel(),
        other => panic!("{other:?}"),
    };
    let accepted = server.accept_channel(server_id, Vec::new());
    settle(server, client, Vec::new(), accepted);
    (id.unwrap(), server_id)
}

fn data(actions: &[Action]) -> Vec<u8> {
    actions
        .iter()
        .flat_map(|a| match a {
            Action::ChannelData { data, .. } => data.clone(),
            _ => Vec::new(),
        })
        .collect()
}

fn payload(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i * 31 + 7) as u8).collect()
}

/// A server and client through authentication, each rekeying after `threshold` bytes if given.
fn pair_with_threshold(threshold: Option<u64>) -> (Server, Client) {
    let mut server = server_with(|b| match threshold {
        Some(t) => b.rekey_threshold(t),
        None => b,
    });
    let mut builder = ClientConfig::builder(CLIENT_USER).rng(TestRng(2));
    if let Some(t) = threshold {
        builder = builder.rekey_threshold(t);
    }
    let mut client = Client::new(builder.build());
    let (s, c) = pump(&mut server, &mut client, usize::MAX);
    assert!(s.closed.is_none() && c.closed.is_none());
    let request = client.auth_password(Zeroizing::new(b"pw".to_vec()));
    let s = settle(&mut server, &mut client, request, Vec::new());
    assert!(matches!(s.server.first(), Some(Action::PasswordRequest(_))));
    let accepted = server.process(Event::AuthAccepted);
    settle(&mut server, &mut client, Vec::new(), accepted);
    assert_eq!(client.phase(), Phase::Connected);
    (server, client)
}

#[test]
fn a_lowered_threshold_rekeys_during_a_transfer_and_no_data_is_lost() {
    let (mut server, mut client) = pair_with_threshold(Some(4096));
    let (c_id, s_id) = open(&mut server, &mut client);
    let sent = payload(200_000);
    let (mut verdicts, mut at_server, mut at_client) = (0, Vec::new(), Vec::new());
    for chunk in sent.chunks(1000) {
        let up = client.channel_data(c_id, chunk);
        let down = server.channel_data(s_id, chunk);
        let s = settle(&mut server, &mut client, up, down);
        verdicts += s.verdicts;
        at_server.extend(s.server);
        at_client.extend(s.client);
    }
    assert!(closed(&at_server).is_none() && closed(&at_client).is_none());
    assert_eq!(data(&at_server), sent);
    assert_eq!(data(&at_client), sent);
    assert!(verdicts > 10, "{verdicts} key exchanges");
}

#[test]
fn either_side_can_ask_for_a_rekey_and_the_other_answers() {
    let (mut server, mut client) = authenticated_pair();
    let asked = client.rekey();
    let s = settle(&mut server, &mut client, asked, Vec::new());
    assert_eq!(s.verdicts, 1);
    let asked = server.rekey();
    let s = settle(&mut server, &mut client, Vec::new(), asked);
    assert_eq!(s.verdicts, 1);
    let (c_id, s_id) = open(&mut server, &mut client);
    let sent = payload(5000);
    let up = client.channel_data(c_id, &sent);
    let s = settle(&mut server, &mut client, up, Vec::new());
    assert_eq!(data(&s.server), sent);
    let down = server.channel_data(s_id, &sent);
    let s = settle(&mut server, &mut client, Vec::new(), down);
    assert_eq!(data(&s.client), sent);
}

#[test]
fn both_sides_asking_at_once_make_one_exchange() {
    let (mut server, mut client) = authenticated_pair();
    let up = client.rekey();
    let down = server.rekey();
    let s = settle(&mut server, &mut client, up, down);
    assert_eq!(s.verdicts, 1);
    assert!(closed(&s.server).is_none() && closed(&s.client).is_none());
}

#[test]
fn a_second_request_during_a_rekey_starts_nothing_more() {
    let (mut server, mut client) = authenticated_pair();
    let mut up = client.rekey();
    up.extend(client.rekey());
    let s = settle(&mut server, &mut client, up, Vec::new());
    assert_eq!(s.verdicts, 1);
}

#[test]
fn a_request_before_the_first_exchange_sends_nothing() {
    let mut client = client();
    client.process(Event::Connected);
    assert!(client.rekey().is_empty());
}

#[test]
fn what_is_sent_during_a_rekey_arrives_after_it_in_order() {
    let (mut server, mut client) = authenticated_pair();
    let (c_id, _) = open(&mut server, &mut client);
    let mut up = client.rekey();
    let sent = payload(30_000);
    for chunk in sent.chunks(700) {
        up.extend(client.channel_data(c_id, chunk));
    }
    let s = settle(&mut server, &mut client, up, Vec::new());
    assert_eq!(s.verdicts, 1);
    assert!(closed(&s.server).is_none(), "{:?}", s.server);
    assert_eq!(data(&s.server), sent);
}

#[test]
fn a_rekey_during_authentication_holds_the_request_until_it_is_done() {
    let (mut server, mut client) = (server(), client());
    let (s, c) = pump(&mut server, &mut client, usize::MAX);
    assert!(s.closed.is_none() && c.closed.is_none());
    let mut up = client.rekey();
    up.extend(client.auth_password(Zeroizing::new(b"pw".to_vec())));
    let s = settle(&mut server, &mut client, up, Vec::new());
    assert_eq!(s.verdicts, 1);
    assert!(
        matches!(s.server.last(), Some(Action::PasswordRequest(_))),
        "{:?}",
        s.server
    );
    let accepted = server.process(Event::AuthAccepted);
    settle(&mut server, &mut client, Vec::new(), accepted);
    assert_eq!(client.phase(), Phase::Connected);
}

#[test]
fn a_connection_message_after_the_peers_kexinit_ends_the_connection() {
    let (mut server, mut client) = authenticated_pair();
    let kexinit = client.rekey();
    let mut at_server = Vec::new();
    for a in kexinit {
        if let Action::Write(b) = a {
            at_server.extend(server.process(Event::Received(&b)));
        }
    }
    assert!(closed(&at_server).is_none());
    let request =
        Message::GlobalRequest(GlobalRequest::new("x".into(), false, Vec::new())).encode();
    let mut at_server = Vec::new();
    for a in client.send_raw(&request) {
        if let Action::Write(b) = a {
            at_server.extend(server.process(Event::Received(&b)));
        }
    }
    assert!(
        matches!(
            closed(&at_server),
            Some(Closed::Local {
                error: Error::UnexpectedMessage { number: 80 },
                ..
            })
        ),
        "{at_server:?}"
    );
}

#[test]
fn data_the_peer_sent_before_seeing_this_sides_kexinit_is_still_handled() {
    let (mut server, mut client) = authenticated_pair();
    let (c_id, _) = open(&mut server, &mut client);
    let down = server.rekey();
    let sent = payload(3000);
    let up = client.channel_data(c_id, &sent);
    let s = settle(&mut server, &mut client, up, down);
    assert_eq!(s.verdicts, 1);
    assert!(closed(&s.server).is_none(), "{:?}", s.server);
    assert_eq!(data(&s.server), sent);
}

#[test]
fn strict_key_exchange_holds_across_a_rekey() {
    let (mut server, mut client) = authenticated_pair();
    assert!(client.handshake().negotiated().unwrap().strict_kex());
    let asked = client.rekey();
    settle(&mut server, &mut client, asked, Vec::new());
    assert!(client.handshake().negotiated().unwrap().strict_kex());
    assert!(server.handshake().negotiated().unwrap().strict_kex());
    let (c_id, _) = open(&mut server, &mut client);
    let up = client.channel_data(c_id, b"after");
    let s = settle(&mut server, &mut client, up, Vec::new());
    assert_eq!(data(&s.server), b"after");
}

#[test]
fn a_rekey_kexinit_carries_no_strict_or_ext_info_marker() {
    let (mut server, mut client) = authenticated_pair();
    let asked = client.rekey();
    settle(&mut server, &mut client, asked, Vec::new());
    for k in [
        client.handshake().local_kexinit().unwrap(),
        server.handshake().local_kexinit().unwrap(),
    ] {
        let names = &k.message().kex_algorithms;
        assert!(
            !names
                .iter()
                .any(|n| n.starts_with("kex-strict-") || n.starts_with("ext-info-")),
            "{names:?}"
        );
    }
}

#[test]
fn a_host_key_rejected_on_a_rekey_ends_the_connection() {
    let (mut server, mut client) = authenticated_pair();
    let mut from_client = client.rekey();
    let mut from_server = Vec::new();
    let mut client_actions = Vec::new();
    for _ in 0..10 {
        for a in std::mem::take(&mut from_client) {
            if let Action::Write(b) = a {
                from_server.extend(server.process(Event::Received(&b)));
            }
        }
        for a in std::mem::take(&mut from_server) {
            if let Action::Write(b) = a {
                for r in client.process(Event::Received(&b)) {
                    match r {
                        Action::VerifyHostKey { .. } => {
                            client_actions.extend(client.process(Event::HostKeyRejected));
                        }
                        Action::Write(_) => from_client.push(r),
                        other => client_actions.push(other),
                    }
                }
            }
        }
    }
    assert!(
        matches!(
            closed(&client_actions),
            Some(Closed::Local {
                error: Error::HostKeyRejected,
                phase: Phase::Connected,
                ..
            })
        ),
        "{client_actions:?}"
    );
}

#[test]
fn a_threshold_on_one_side_rekeys_on_what_that_side_receives() {
    let mut server = server();
    let mut client = Client::new(
        ClientConfig::builder(CLIENT_USER)
            .rng(TestRng(2))
            .rekey_threshold(4096)
            .build(),
    );
    let (s, c) = pump(&mut server, &mut client, usize::MAX);
    assert!(s.closed.is_none() && c.closed.is_none());
    let request = client.auth_password(Zeroizing::new(b"pw".to_vec()));
    settle(&mut server, &mut client, request, Vec::new());
    let accepted = server.process(Event::AuthAccepted);
    settle(&mut server, &mut client, Vec::new(), accepted);
    let (_, s_id) = open(&mut server, &mut client);
    let mut verdicts = 0;
    for chunk in payload(50_000).chunks(1000) {
        let down = server.channel_data(s_id, chunk);
        verdicts += settle(&mut server, &mut client, Vec::new(), down).verdicts;
    }
    assert!(verdicts > 3, "{verdicts}");
}

#[test]
fn an_authentication_request_after_the_servers_kexinit_waits_for_the_exchange() {
    let (mut server, mut client) = (server(), client());
    let (s, c) = pump(&mut server, &mut client, usize::MAX);
    assert!(s.closed.is_none() && c.closed.is_none());
    let mut from_server = Vec::new();
    for a in server.rekey() {
        if let Action::Write(b) = a {
            from_server.extend(client.process(Event::Received(&b)));
        }
    }
    let mut up = from_server;
    up.extend(client.auth_password(Zeroizing::new(b"pw".to_vec())));
    assert!(closed(&up).is_none(), "{up:?}");
    let s = settle(&mut server, &mut client, up, Vec::new());
    assert_eq!(s.verdicts, 1);
    assert!(
        matches!(s.server.last(), Some(Action::PasswordRequest(_))),
        "{:?}",
        s.server
    );
}

#[test]
fn a_threshold_on_one_side_rekeys_on_what_that_side_sends() {
    let mut server = server();
    let mut client = Client::new(
        ClientConfig::builder(CLIENT_USER)
            .rng(TestRng(2))
            .rekey_threshold(4096)
            .build(),
    );
    let (s, c) = pump(&mut server, &mut client, usize::MAX);
    assert!(s.closed.is_none() && c.closed.is_none());
    let request = client.auth_password(Zeroizing::new(b"pw".to_vec()));
    settle(&mut server, &mut client, request, Vec::new());
    let accepted = server.process(Event::AuthAccepted);
    settle(&mut server, &mut client, Vec::new(), accepted);
    let (c_id, _) = open(&mut server, &mut client);
    let mut verdicts = 0;
    let sent = payload(50_000);
    let mut at_server = Vec::new();
    for chunk in sent.chunks(1000) {
        let up = client.channel_data(c_id, chunk);
        let s = settle(&mut server, &mut client, up, Vec::new());
        verdicts += s.verdicts;
        at_server.extend(s.server);
    }
    assert_eq!(data(&at_server), sent);
    assert!(verdicts > 3, "{verdicts}");
}

#[test]
fn a_rekey_the_server_starts_before_the_service_request_holds_the_answer_until_it_ends() {
    let (mut server, mut client) = (server(), client());
    let (mut s, mut c) = (Out::default(), Out::default());
    collect(server.process(Event::Connected), &mut s);
    collect(client.process(Event::Connected), &mut c);
    collect(server.process(Event::Received(&c.bytes)), &mut s);
    let c_sent = c.bytes.len();
    collect(client.process(Event::Received(&s.bytes)), &mut c);
    let s_sent = s.bytes.len();
    collect(server.process(Event::Received(&c.bytes[c_sent..])), &mut s);
    let verdict = client.process(Event::Received(&s.bytes[s_sent..]));
    assert!(matches!(verdict.last(), Some(Action::VerifyHostKey { .. })));
    // The client's NEWKEYS, then its SERVICE_REQUEST, each in its own write.
    let writes: Vec<Vec<u8>> = client
        .process(Event::HostKeyAccepted)
        .into_iter()
        .filter_map(|a| match a {
            Action::Write(b) => Some(b),
            _ => None,
        })
        .collect();
    assert_eq!(writes.len(), 2);
    let mut from_server = server.process(Event::Received(&writes[0]));
    from_server.extend(server.rekey());
    from_server.extend(server.process(Event::Received(&writes[1])));
    let settled = settle(&mut server, &mut client, Vec::new(), from_server);
    assert!(closed(&settled.client).is_none(), "{:?}", settled.client);
    assert!(closed(&settled.server).is_none(), "{:?}", settled.server);
    assert_eq!(settled.verdicts, 1);
    assert_eq!(client.phase(), Phase::Auth);
}

#[test]
fn channel_data_waits_in_its_channel_during_an_exchange() {
    let (mut server, mut client) = authenticated_pair();
    let (c_id, _) = open(&mut server, &mut client);
    let mut up = client.rekey();
    up.extend(client.channel_data(c_id, b"held"));
    assert_eq!(client.channel_info(c_id).unwrap().queued(), 4);
    let s = settle(&mut server, &mut client, up, Vec::new());
    assert_eq!(client.channel_info(c_id).unwrap().queued(), 0);
    assert_eq!(data(&s.server), b"held");
}

#[test]
fn a_peer_that_keeps_this_sides_exchange_waiting_cannot_pile_up_its_answers() {
    let (mut server, mut client) = authenticated_pair();
    let kexinit = server.rekey();
    drop(kexinit);
    let ping = Message::Ping(justssh_wire::Ping::new(Vec::new())).encode();
    let mut at_server = Vec::new();
    for _ in 0..1100 {
        for a in client.send_raw(&ping) {
            if let Action::Write(b) = a {
                at_server.extend(server.process(Event::Received(&b)));
            }
        }
        if closed(&at_server).is_some() {
            break;
        }
    }
    assert!(
        matches!(
            closed(&at_server),
            Some(Closed::Local {
                error: Error::ExchangeBacklog,
                ..
            })
        ),
        "{:?}",
        closed(&at_server)
    );
}

#[test]
fn a_threshold_of_zero_keeps_the_default() {
    let mut server = server_with(|b| b.rekey_threshold(0));
    let mut client = Client::new(
        ClientConfig::builder(CLIENT_USER)
            .rng(TestRng(2))
            .rekey_threshold(0)
            .build(),
    );
    let (s, c) = pump(&mut server, &mut client, usize::MAX);
    assert!(s.closed.is_none() && c.closed.is_none());
    let request = client.auth_password(Zeroizing::new(b"pw".to_vec()));
    let s = settle(&mut server, &mut client, request, Vec::new());
    let accepted = server.process(Event::AuthAccepted);
    let t = settle(&mut server, &mut client, Vec::new(), accepted);
    let (c_id, _) = open(&mut server, &mut client);
    let up = client.channel_data(c_id, &payload(20_000));
    let u = settle(&mut server, &mut client, up, Vec::new());
    assert_eq!(s.verdicts + t.verdicts + u.verdicts, 0);
}
