//! Client host key verdict, extension negotiation and user authentication, against the real
//! server or a server sending raw messages (`test-support`).

mod common;

use common::*;
use justssh::{Action, Client, Closed, DisconnectReason, Error, Event, Phase, Server, Zeroizing};
use justssh_wire::{
    ExtInfo, Message, UserauthBanner, UserauthFailure, UserauthSuccess, Writer, number,
};

fn secret(b: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(b.to_vec())
}

/// A server and a client, both waiting for the client's first authentication request.
fn at_auth() -> (Server, Client) {
    let (mut server, mut client) = (server(), client());
    let (s, c) = pump(&mut server, &mut client, usize::MAX);
    assert!(s.closed.is_none() && c.closed.is_none());
    assert_eq!(client.phase(), Phase::Auth);
    (server, client)
}

/// What the client did with `payloads` sent raw by the server.
fn raw_to_client(server: &mut Server, client: &mut Client, payloads: &[Vec<u8>]) -> Vec<Action> {
    let mut out = Vec::new();
    for p in payloads {
        let actions = server.send_raw(p);
        out.extend(to_client(client, actions));
    }
    out
}

/// The payloads the raw-mode server received from `actions` of the client.
fn raw_at_server(server: &mut Server, actions: Vec<Action>) -> Vec<Vec<u8>> {
    to_server(server, actions)
        .into_iter()
        .filter_map(|a| match a {
            Action::RawReceived(p) => Some(p),
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

fn local_error(actions: &[Action]) -> Option<(DisconnectReason, Error)> {
    match closed(actions)? {
        Closed::Local { reason, error, .. } => Some((*reason, error.clone())),
        other => panic!("closed otherwise: {other:?}"),
    }
}

fn failure(actions: &[Action]) -> Option<(Vec<String>, bool)> {
    actions.iter().find_map(|a| match a {
        Action::AuthFailure {
            methods,
            partial_success,
        } => Some((methods.clone(), *partial_success)),
        _ => None,
    })
}

/// `SSH_MSG_USERAUTH_INFO_REQUEST` (RFC 4256 §3.2).
fn info_request(name: &[u8], instruction: &[u8], prompts: &[(&[u8], bool)]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(number::USERAUTH_INFO_REQUEST)
        .string(name)
        .string(instruction)
        .string(b"")
        .u32(prompts.len() as u32);
    for (text, echo) in prompts {
        w.string(text).bool(*echo);
    }
    w.into_bytes()
}

/// A raw-mode server and a client that has asked for keyboard-interactive.
fn in_keyboard_interactive() -> (Server, Client) {
    let (mut server, mut client) = at_auth();
    server.set_raw_receive(true);
    let actions = client.auth_keyboard_interactive();
    let got = raw_at_server(&mut server, actions);
    let Message::UserauthRequest(r) = Message::decode(&got[0]).unwrap() else {
        panic!("not a userauth request");
    };
    assert_eq!(r.user, CLIENT_USER);
    assert_eq!(r.service, "ssh-connection");
    assert_eq!(r.method, "keyboard-interactive");
    // string language tag, string submethods: both empty (RFC 4256 §3.1).
    assert_eq!(r.method_data, [0, 0, 0, 0, 0, 0, 0, 0]);
    (server, client)
}

#[test]
fn the_client_offers_ext_info_c_and_then_the_strict_kex_marker() {
    let mut client = client();
    let mut out = Out::default();
    collect(client.process(Event::Connected), &mut out);
    collect(client.process(Event::Received(CLIENT_VERSION)), &mut out);
    let nl = out.bytes.iter().position(|&b| b == b'\n').unwrap();
    let payloads = split_plain(&out.bytes[nl + 1..]);
    let Message::KexInit(k) = Message::decode(&payloads[0]).unwrap() else {
        panic!("not a KEXINIT");
    };
    let n = k.kex_algorithms.len();
    assert_eq!(
        k.kex_algorithms[n - 2..],
        ["ext-info-c", "kex-strict-c-v00@openssh.com"]
    );
}

#[test]
fn the_host_key_is_judged_before_the_client_sends_new_keys() {
    let (mut server, mut client) = (server(), client());
    let (mut s, mut c) = (Out::default(), Out::default());
    collect(server.process(Event::Connected), &mut s);
    collect(client.process(Event::Connected), &mut c);
    collect(server.process(Event::Received(&c.bytes)), &mut s);
    let c_sent = c.bytes.len();
    collect(client.process(Event::Received(&s.bytes)), &mut c);
    let s_sent = s.bytes.len();
    collect(server.process(Event::Received(&c.bytes[c_sent..])), &mut s);

    let actions = client.process(Event::Received(&s.bytes[s_sent..]));
    let keys: Vec<_> = actions
        .iter()
        .filter_map(|a| match a {
            Action::VerifyHostKey { key } => Some(key.clone()),
            _ => None,
        })
        .collect();
    assert!(
        !actions.iter().any(|a| matches!(a, Action::Write(_))),
        "the client wrote before the verdict"
    );
    let mut blob = vec![0, 0, 0, 11];
    blob.extend(b"ssh-ed25519");
    blob.extend([0, 0, 0, 32]);
    blob.extend(
        ed25519_dalek::SigningKey::from_bytes(&HOST_SEED)
            .verifying_key()
            .to_bytes(),
    );
    assert_eq!(keys, [blob]);

    let after = client.process(Event::HostKeyAccepted);
    let Some(Action::Write(newkeys)) = after.first() else {
        panic!("nothing written after the verdict: {after:?}");
    };
    assert_eq!(split_plain(newkeys), [vec![number::NEWKEYS]]);
}

#[test]
fn a_rejected_host_key_ends_the_connection() {
    let (mut server, mut client) = (server(), client());
    let (mut s, mut c) = (Out::default(), Out::default());
    collect(server.process(Event::Connected), &mut s);
    collect(client.process(Event::Connected), &mut c);
    collect(server.process(Event::Received(&c.bytes)), &mut s);
    let c_sent = c.bytes.len();
    collect(client.process(Event::Received(&s.bytes)), &mut c);
    let s_sent = s.bytes.len();
    collect(server.process(Event::Received(&c.bytes[c_sent..])), &mut s);
    client.process(Event::Received(&s.bytes[s_sent..]));

    let actions = client.process(Event::HostKeyRejected);
    assert_eq!(
        closed(&actions),
        Some(&Closed::Local {
            reason: DisconnectReason::HOST_KEY_NOT_VERIFIABLE,
            error: Error::HostKeyRejected,
            phase: Phase::Handshake,
        })
    );
    assert_eq!(client.phase(), Phase::Closed);
}

#[test]
fn the_server_sig_algs_the_server_sent_can_be_read() {
    let (_server, client) = at_auth();
    assert_eq!(
        client.server_sig_algs(),
        Some(vec![
            "ssh-ed25519",
            "sk-ssh-ed25519@openssh.com",
            "sk-ecdsa-sha2-nistp256@openssh.com",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
            "rsa-sha2-256",
            "rsa-sha2-512",
            "ssh-rsa",
            "ssh-dss",
        ])
    );
}

#[test]
fn a_password_logs_in_after_none_reports_the_methods() {
    let (mut server, mut client) = at_auth();
    let actions = client.auth_none();
    let replies = to_client(&mut client, to_server(&mut server, actions));
    assert_eq!(
        failure(&replies),
        Some((vec!["password".to_owned()], false))
    );

    let actions = client.auth_password(secret(b"hunter2"));
    let at_server = to_server(&mut server, actions);
    let Some(Action::PasswordRequest(request)) = at_server.first() else {
        panic!("no password request: {at_server:?}");
    };
    assert_eq!(
        (request.user(), request.password()),
        (CLIENT_USER, &b"hunter2"[..])
    );

    let replies = to_client(&mut client, server.process(Event::AuthAccepted));
    assert!(closed(&replies).is_none(), "{replies:?}");
    assert_eq!(client.phase(), Phase::Connected);
}

#[test]
fn a_rejected_password_is_a_failure_and_another_attempt_may_follow() {
    let (mut server, mut client) = at_auth();
    let actions = client.auth_password(secret(b"wrong"));
    to_server(&mut server, actions);
    let replies = to_client(&mut client, server.process(Event::AuthRejected));
    assert_eq!(
        failure(&replies),
        Some((vec!["password".to_owned()], false))
    );
    assert_eq!(client.phase(), Phase::Auth);

    let actions = client.auth_password(secret(b"right"));
    let at_server = to_server(&mut server, actions);
    assert!(matches!(
        at_server.first(),
        Some(Action::PasswordRequest(_))
    ));
}

#[test]
fn keyboard_interactive_prompts_reach_the_consumer_and_the_answers_go_back() {
    let (mut server, mut client) = in_keyboard_interactive();
    let actions = raw_to_client(
        &mut server,
        &mut client,
        &[info_request(
            b"PAM",
            b"say it\xff",
            &[(b"Password: ", false), (b"Code: ", true)],
        )],
    );
    let Some(Action::KeyboardInteractive(request)) = actions.first() else {
        panic!("no prompts: {actions:?}");
    };
    assert_eq!(request.name(), b"PAM");
    assert_eq!(request.instruction(), b"say it\xff");
    let prompts: Vec<_> = request
        .prompts()
        .iter()
        .map(|p| (p.text(), p.echo()))
        .collect();
    assert_eq!(
        prompts,
        [(&b"Password: "[..], false), (&b"Code: "[..], true)]
    );

    let actions = client.answer_prompts(vec![secret(b"pw"), secret(b"123456")]);
    let got = raw_at_server(&mut server, actions);
    // byte 61, uint32 2, string "pw", string "123456" (RFC 4256 §3.4).
    let mut expected = vec![61, 0, 0, 0, 2, 0, 0, 0, 2];
    expected.extend(b"pw");
    expected.extend([0, 0, 0, 6]);
    expected.extend(b"123456");
    assert_eq!(got, [expected]);

    let success = Message::UserauthSuccess(UserauthSuccess::default()).encode();
    let actions = raw_to_client(&mut server, &mut client, &[success]);
    assert!(closed(&actions).is_none(), "{actions:?}");
    assert_eq!(client.phase(), Phase::Connected);
}

#[test]
fn a_prompt_with_no_questions_is_answered_with_none() {
    let (mut server, mut client) = in_keyboard_interactive();
    let actions = raw_to_client(&mut server, &mut client, &[info_request(b"", b"hi", &[])]);
    let Some(Action::KeyboardInteractive(request)) = actions.first() else {
        panic!("no prompts: {actions:?}");
    };
    assert!(request.prompts().is_empty());
    let got = raw_at_server(&mut server, client.answer_prompts(Vec::new()));
    assert_eq!(got, [vec![61, 0, 0, 0, 0]]);
}

#[test]
fn answers_of_the_wrong_count_end_the_connection() {
    let (mut server, mut client) = in_keyboard_interactive();
    raw_to_client(
        &mut server,
        &mut client,
        &[info_request(b"", b"", &[(b"Password: ", false)])],
    );
    let actions = client.answer_prompts(vec![secret(b"a"), secret(b"b")]);
    assert_eq!(
        local_error(&actions),
        Some((DisconnectReason::PROTOCOL_ERROR, Error::UnexpectedEvent))
    );
}

#[test]
fn a_keyboard_interactive_failure_reports_the_methods() {
    let (mut server, mut client) = in_keyboard_interactive();
    let f = Message::UserauthFailure(UserauthFailure::new(
        vec!["password".into(), "keyboard-interactive".into()],
        true,
    ))
    .encode();
    let actions = raw_to_client(&mut server, &mut client, &[f]);
    assert_eq!(
        failure(&actions),
        Some((
            vec!["password".to_owned(), "keyboard-interactive".to_owned()],
            true
        ))
    );
}

#[test]
fn a_banner_reaches_the_consumer_as_sent() {
    let (mut server, mut client) = in_keyboard_interactive();
    let banner = Message::UserauthBanner(UserauthBanner::new(
        b"authorised use only\xff\r\n".to_vec(),
        Vec::new(),
    ))
    .encode();
    let actions = raw_to_client(&mut server, &mut client, &[banner]);
    let banners: Vec<_> = actions
        .iter()
        .filter_map(|a| match a {
            Action::AuthBanner { message } => Some(message.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(banners, [b"authorised use only\xff\r\n".to_vec()]);
    assert!(closed(&actions).is_none());
}

#[test]
fn a_password_change_request_counts_as_a_failure() {
    let (mut server, mut client) = at_auth();
    let actions = client.auth_none();
    to_client(&mut client, to_server(&mut server, actions));
    server.set_raw_receive(true);
    let actions = client.auth_password(secret(b"old"));
    raw_at_server(&mut server, actions);

    // SSH_MSG_USERAUTH_PASSWD_CHANGEREQ (RFC 4252 §8): string prompt, string language tag.
    let mut change = vec![60, 0, 0, 0, 8];
    change.extend(b"expired!");
    change.extend([0, 0, 0, 0]);
    let actions = raw_to_client(&mut server, &mut client, &[change]);
    assert_eq!(
        failure(&actions),
        Some((vec!["password".to_owned()], false))
    );
    assert!(closed(&actions).is_none());
}

#[test]
fn an_answer_nobody_asked_for_ends_the_connection() {
    for reply in [
        Message::UserauthSuccess(UserauthSuccess::default()).encode(),
        Message::UserauthFailure(UserauthFailure::new(vec!["password".into()], false)).encode(),
        info_request(b"", b"", &[]),
    ] {
        let (mut server, mut client) = at_auth();
        server.set_raw_receive(true);
        let actions = raw_to_client(&mut server, &mut client, std::slice::from_ref(&reply));
        assert_eq!(
            local_error(&actions),
            Some((
                DisconnectReason::PROTOCOL_ERROR,
                Error::UnexpectedMessage { number: reply[0] }
            )),
            "{reply:?}"
        );
    }
}

#[test]
fn a_second_prompt_before_the_answers_ends_the_connection() {
    let (mut server, mut client) = in_keyboard_interactive();
    let actions = raw_to_client(
        &mut server,
        &mut client,
        &[
            info_request(b"", b"", &[(b"a", false)]),
            info_request(b"", b"", &[(b"b", false)]),
        ],
    );
    assert_eq!(
        local_error(&actions),
        Some((
            DisconnectReason::PROTOCOL_ERROR,
            Error::UnexpectedMessage {
                number: number::USERAUTH_INFO_REQUEST
            }
        ))
    );
}

#[test]
fn an_attempt_while_one_is_outstanding_ends_the_connection() {
    let (_server, mut client) = at_auth();
    let first = client.auth_none();
    let second = client.auth_password(secret(b"pw"));
    assert!(!first.is_empty());
    assert_eq!(
        local_error(&second),
        Some((DisconnectReason::PROTOCOL_ERROR, Error::UnexpectedEvent))
    );
}

#[test]
fn an_attempt_before_the_auth_phase_ends_the_connection() {
    let mut client = client();
    client.process(Event::Connected);
    let actions = client.auth_none();
    assert_eq!(
        local_error(&actions),
        Some((DisconnectReason::PROTOCOL_ERROR, Error::UnexpectedEvent))
    );
}

#[test]
fn one_ext_info_during_an_attempt_is_passed_over_and_a_second_ends_the_connection() {
    let (mut server, mut client) = in_keyboard_interactive();
    let ext = Message::ExtInfo(ExtInfo::new(vec![(
        "server-sig-algs".into(),
        b"ssh-ed25519".to_vec(),
    )]))
    .encode();
    let actions = raw_to_client(&mut server, &mut client, std::slice::from_ref(&ext));
    assert!(closed(&actions).is_none(), "{actions:?}");
    assert_eq!(client.server_sig_algs().unwrap().len(), 10);

    let actions = raw_to_client(&mut server, &mut client, &[ext]);
    assert_eq!(
        local_error(&actions),
        Some((
            DisconnectReason::PROTOCOL_ERROR,
            Error::UnexpectedMessage {
                number: number::EXT_INFO
            }
        ))
    );
}

#[test]
fn a_second_ext_info_before_the_service_is_accepted_ends_the_connection() {
    let (mut server, mut client) = (server(), client());
    server.set_raw_receive(true);
    let (s, c) = pump(&mut server, &mut client, usize::MAX);
    assert!(s.closed.is_none() && c.closed.is_none());
    assert_eq!(
        client.phase(),
        Phase::Handshake,
        "the service request went unanswered"
    );
    assert!(client.server_sig_algs().is_some());

    let ext = Message::ExtInfo(ExtInfo::new(vec![(
        "server-sig-algs".into(),
        b"ssh-rsa".to_vec(),
    )]))
    .encode();
    let actions = raw_to_client(&mut server, &mut client, &[ext]);
    assert_eq!(
        local_error(&actions),
        Some((
            DisconnectReason::PROTOCOL_ERROR,
            Error::UnexpectedMessage {
                number: number::EXT_INFO
            }
        ))
    );
    assert_ne!(client.server_sig_algs(), Some(vec!["ssh-rsa"]));
}

#[test]
fn a_message_60_after_authentication_ends_the_connection() {
    let (mut server, mut client) = at_auth();
    let none = client.auth_none();
    to_client(&mut client, to_server(&mut server, none));
    to_server(&mut server, client.auth_password(secret(b"hunter2")));
    to_client(&mut client, server.process(Event::AuthAccepted));
    assert_eq!(client.phase(), Phase::Connected);
    server.set_raw_receive(true);
    let actions = raw_to_client(
        &mut server,
        &mut client,
        &[info_request(b"", b"", &[(b"a", false)])],
    );
    assert_eq!(
        local_error(&actions),
        Some((
            DisconnectReason::PROTOCOL_ERROR,
            Error::UnexpectedMessage {
                number: number::USERAUTH_INFO_REQUEST
            }
        ))
    );
}
