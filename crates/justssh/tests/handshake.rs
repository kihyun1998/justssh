mod common;

use common::*;
use justssh::{AlgorithmCategory, Closed, DisconnectReason, Error, Event, Phase};
use justssh_wire::{Disconnect, Ignore, KexEcdhInit, Message, NewKeys};

fn ed25519_host_key_blob() -> Vec<u8> {
    let public = ed25519_dalek::SigningKey::from_bytes(&HOST_SEED).verifying_key();
    let mut blob = Vec::new();
    blob.extend(11u32.to_be_bytes());
    blob.extend(b"ssh-ed25519");
    blob.extend(32u32.to_be_bytes());
    blob.extend(public.to_bytes());
    blob
}

fn expect_local_close(out: &Out) -> (DisconnectReason, Error) {
    match out.closed.as_ref().expect("connection stayed open") {
        Closed::Local { reason, error } => (*reason, error.clone()),
        other => panic!("expected a local close, got {other:?}"),
    }
}

fn last_payload(out: &Out) -> Message {
    let (_, payloads) = plain_payloads(&out.bytes);
    Message::decode(payloads.last().expect("no packets")).unwrap()
}

#[test]
fn server_and_client_complete_the_key_exchange_and_reach_user_authentication() {
    let (mut server, mut client) = (server(), client());
    let (s, c) = pump(&mut server, &mut client, usize::MAX);
    assert!(s.closed.is_none(), "server closed: {:?}", s.closed);
    assert!(c.closed.is_none(), "client closed: {:?}", c.closed);
    assert_eq!(server.phase(), Phase::Auth);
    assert_eq!(client.phase(), Phase::Auth);
    assert!(server.session_id().is_some());
    assert_eq!(server.session_id(), client.session_id());
    assert_eq!(client.peer_host_key(), Some(&ed25519_host_key_blob()[..]));

    let algs = server.handshake().negotiated().expect("nothing negotiated");
    assert_eq!(algs.kex(), "curve25519-sha256");
    assert_eq!(algs.host_key(), "ssh-ed25519");
    assert_eq!(
        algs.cipher_client_to_server(),
        "chacha20-poly1305@openssh.com"
    );
    assert_eq!(
        algs.cipher_server_to_client(),
        "chacha20-poly1305@openssh.com"
    );
    assert!(algs.strict_kex());
    assert_eq!(client.handshake().negotiated(), Some(algs));
}

#[test]
fn bytes_delivered_one_at_a_time_give_the_same_session() {
    let (mut a_server, mut a_client) = (server(), client());
    pump(&mut a_server, &mut a_client, usize::MAX);
    let (mut b_server, mut b_client) = (server(), client());
    let (s, c) = pump(&mut b_server, &mut b_client, 1);
    assert!(s.closed.is_none() && c.closed.is_none());
    assert_eq!(b_client.phase(), Phase::Auth);
    assert_eq!(a_server.session_id(), b_server.session_id());
}

#[test]
fn both_versions_and_kexinits_are_kept_after_a_successful_handshake() {
    let (mut server, mut client) = (server(), client());
    pump(&mut server, &mut client, usize::MAX);
    let h = server.handshake();
    assert_eq!(h.local_version(), "SSH-2.0-justssh");
    assert_eq!(h.peer_version(), Some("SSH-2.0-justssh"));
    let peer = h.peer_kexinit().unwrap();
    assert_eq!(
        peer.raw(),
        client.handshake().local_kexinit().unwrap().raw()
    );
    assert_eq!(
        Message::decode(peer.raw()).unwrap(),
        Message::KexInit(peer.message().clone())
    );
}

#[test]
fn no_common_cipher_closes_with_both_kexinits_in_the_error() {
    let kexinit = client_kexinit(|k| {
        k.encryption_algorithms_client_to_server = vec!["aes128-ctr".into()];
    });
    let mut input = CLIENT_VERSION.to_vec();
    input.extend(plain_packet(&kexinit));
    let out = feed_server(&input);

    let (reason, error) = expect_local_close(&out);
    assert_eq!(reason, DisconnectReason::KEY_EXCHANGE_FAILED);
    let Error::NoCommonAlgorithm {
        category,
        handshake,
    } = error
    else {
        panic!("expected NoCommonAlgorithm, got {error:?}");
    };
    assert_eq!(category, AlgorithmCategory::CipherClientToServer);
    assert_eq!(handshake.peer_version(), Some("SSH-2.0-test"));
    assert_eq!(handshake.local_version(), "SSH-2.0-justssh");
    assert_eq!(handshake.peer_kexinit().unwrap().raw(), &kexinit[..]);
    assert!(handshake.local_kexinit().is_some());
    assert!(matches!(last_payload(&out), Message::Disconnect(d) if d.reason == 3));
}

#[test]
fn ignore_during_a_strict_initial_key_exchange_closes_the_connection() {
    let mut input = CLIENT_VERSION.to_vec();
    input.extend(plain_packet(&client_kexinit(|k| {
        k.kex_algorithms.push("kex-strict-c-v00@openssh.com".into());
    })));
    input.extend(plain_packet(
        &Message::Ignore(Ignore::new(vec![1])).encode(),
    ));
    let (reason, error) = expect_local_close(&feed_server(&input));
    assert_eq!(reason, DisconnectReason::PROTOCOL_ERROR);
    assert!(matches!(error, Error::UnexpectedMessage { number: 2 }));
}

#[test]
fn ignore_during_a_non_strict_key_exchange_is_accepted() {
    let mut input = CLIENT_VERSION.to_vec();
    input.extend(plain_packet(&client_kexinit(|_| {})));
    input.extend(plain_packet(
        &Message::Ignore(Ignore::new(vec![1])).encode(),
    ));
    assert!(feed_server(&input).closed.is_none());
}

#[test]
fn strict_kex_requires_kexinit_to_be_the_first_packet() {
    let mut input = CLIENT_VERSION.to_vec();
    input.extend(plain_packet(&Message::Ignore(Ignore::new(vec![])).encode()));
    input.extend(plain_packet(&client_kexinit(|k| {
        k.kex_algorithms.push("kex-strict-c-v00@openssh.com".into());
    })));
    let (reason, _) = expect_local_close(&feed_server(&input));
    assert_eq!(reason, DisconnectReason::PROTOCOL_ERROR);
}

#[test]
fn newkeys_before_the_ecdh_exchange_closes_the_connection() {
    let mut input = CLIENT_VERSION.to_vec();
    input.extend(plain_packet(&client_kexinit(|_| {})));
    input.extend(plain_packet(&Message::NewKeys(NewKeys::default()).encode()));
    let (reason, error) = expect_local_close(&feed_server(&input));
    assert_eq!(reason, DisconnectReason::PROTOCOL_ERROR);
    assert!(matches!(error, Error::UnexpectedMessage { number: 21 }));
}

#[test]
fn an_unknown_message_number_during_key_exchange_closes_the_connection() {
    let mut input = CLIENT_VERSION.to_vec();
    input.extend(plain_packet(&client_kexinit(|_| {})));
    input.extend(plain_packet(&[200, 0]));
    let (_, error) = expect_local_close(&feed_server(&input));
    assert!(matches!(error, Error::UnexpectedMessage { number: 200 }));
}

fn x25519_public(seed: u8) -> Vec<u8> {
    let secret = x25519_dalek::StaticSecret::from([seed; 32]);
    x25519_dalek::PublicKey::from(&secret).as_bytes().to_vec()
}

#[test]
fn a_right_first_kex_guess_is_answered() {
    let mut input = CLIENT_VERSION.to_vec();
    input.extend(plain_packet(&client_kexinit(|k| {
        k.first_kex_packet_follows = true
    })));
    input.extend(plain_packet(
        &Message::KexEcdhInit(KexEcdhInit::new(x25519_public(9))).encode(),
    ));
    let out = feed_server(&input);
    assert!(out.closed.is_none());
    assert!(matches!(
        plain_payloads(&out.bytes)
            .1
            .iter()
            .map(|p| p[0])
            .collect::<Vec<_>>()[..],
        [20, 31, 21]
    ));
}

#[test]
fn a_wrong_first_kex_guess_is_skipped_silently() {
    let mut input = CLIENT_VERSION.to_vec();
    input.extend(plain_packet(&client_kexinit(|k| {
        k.kex_algorithms = vec!["sntrup761x25519-sha512".into(), "curve25519-sha256".into()];
        k.first_kex_packet_follows = true;
    })));
    input.extend(plain_packet(
        &Message::KexEcdhInit(KexEcdhInit::new(x25519_public(9))).encode(),
    ));
    let out = feed_server(&input);
    assert!(out.closed.is_none());
    let numbers: Vec<u8> = plain_payloads(&out.bytes).1.iter().map(|p| p[0]).collect();
    assert_eq!(numbers, vec![20], "the guessed packet was answered");
}

#[test]
fn an_all_zero_curve25519_shared_secret_is_refused() {
    let mut input = CLIENT_VERSION.to_vec();
    input.extend(plain_packet(&client_kexinit(|_| {})));
    input.extend(plain_packet(
        &Message::KexEcdhInit(KexEcdhInit::new(vec![0; 32])).encode(),
    ));
    let (reason, _) = expect_local_close(&feed_server(&input));
    assert_eq!(reason, DisconnectReason::KEY_EXCHANGE_FAILED);
}

#[test]
fn a_curve25519_key_of_the_wrong_length_is_refused() {
    let mut input = CLIENT_VERSION.to_vec();
    input.extend(plain_packet(&client_kexinit(|_| {})));
    input.extend(plain_packet(
        &Message::KexEcdhInit(KexEcdhInit::new(vec![9; 31])).encode(),
    ));
    let (reason, _) = expect_local_close(&feed_server(&input));
    assert_eq!(reason, DisconnectReason::KEY_EXCHANGE_FAILED);
}

#[test]
fn a_peer_disconnect_is_reported_with_its_reason() {
    let mut input = CLIENT_VERSION.to_vec();
    input.extend(plain_packet(
        &Message::Disconnect(Disconnect::new(11, "bye", "")).encode(),
    ));
    match feed_server(&input).closed {
        Some(Closed::Peer {
            reason,
            description,
        }) => {
            assert_eq!(reason, DisconnectReason::BY_APPLICATION);
            assert_eq!(description, "bye");
        }
        other => panic!("expected a peer close, got {other:?}"),
    }
}

#[test]
fn an_unsupported_protocol_version_is_refused() {
    let (reason, error) = expect_local_close(&feed_server(b"SSH-1.5-old\r\n"));
    assert_eq!(reason, DisconnectReason::PROTOCOL_VERSION_NOT_SUPPORTED);
    assert!(matches!(error, Error::BadVersion));
}

#[test]
fn lines_before_the_version_and_a_bare_line_feed_are_accepted() {
    let mut input = b"hello\r\nworld\n".to_vec();
    input.extend(b"SSH-2.0-lf-only\n");
    input.extend(plain_packet(&client_kexinit(|_| {})));
    let mut server = server();
    collect(server.process(Event::Connected), &mut Out::default());
    let mut out = Out::default();
    collect(server.process(Event::Received(&input)), &mut out);
    assert!(out.closed.is_none());
    assert_eq!(server.handshake().peer_version(), Some("SSH-2.0-lf-only"));
}

#[test]
fn a_version_line_longer_than_255_bytes_is_refused() {
    let mut input = b"SSH-2.0-".to_vec();
    input.extend(std::iter::repeat_n(b'x', 260));
    input.extend(b"\r\n");
    let (_, error) = expect_local_close(&feed_server(&input));
    assert!(matches!(error, Error::BadVersion));
}

#[test]
fn data_before_the_connected_event_is_an_unexpected_event() {
    let mut server = server();
    let mut out = Out::default();
    collect(server.process(Event::Received(b"SSH-2.0-x\r\n")), &mut out);
    let (_, error) = expect_local_close(&out);
    assert!(matches!(error, Error::UnexpectedEvent));
}

#[test]
fn an_encrypted_disconnect_reaches_the_peer() {
    let (mut server, mut client) = (server(), client());
    pump(&mut server, &mut client, usize::MAX);
    let mut c = Out::default();
    collect(
        client.disconnect(DisconnectReason::BY_APPLICATION, "done"),
        &mut c,
    );
    let mut s = Out::default();
    collect(server.process(Event::Received(&c.bytes)), &mut s);
    match s.closed {
        Some(Closed::Peer {
            reason,
            description,
        }) => {
            assert_eq!(reason, DisconnectReason::BY_APPLICATION);
            assert_eq!(description, "done");
        }
        other => panic!("expected a peer close, got {other:?}"),
    }
}

#[test]
fn a_tampered_encrypted_packet_fails_the_mac_check() {
    let (mut server, mut client) = (server(), client());
    pump(&mut server, &mut client, usize::MAX);
    let mut c = Out::default();
    collect(
        client.disconnect(DisconnectReason::BY_APPLICATION, "done"),
        &mut c,
    );
    let mut bytes = c.bytes;
    bytes[8] ^= 1;
    let mut s = Out::default();
    collect(server.process(Event::Received(&bytes)), &mut s);
    let (reason, error) = expect_local_close(&s);
    assert_eq!(reason, DisconnectReason::MAC_ERROR);
    assert!(matches!(error, Error::MacMismatch));
}

fn after_kexinit(strict: bool, payload: &[u8]) -> Out {
    let mut input = CLIENT_VERSION.to_vec();
    input.extend(plain_packet(&client_kexinit(|k| {
        if strict {
            k.kex_algorithms.push("kex-strict-c-v00@openssh.com".into());
        }
    })));
    input.extend(plain_packet(payload));
    feed_server(&input)
}

#[test]
fn debug_and_unimplemented_during_a_strict_initial_key_exchange_close_the_connection() {
    let debug = Message::Debug(justssh_wire::Debug::new(false, "x", "")).encode();
    let unimplemented = Message::Unimplemented(justssh_wire::Unimplemented::new(0)).encode();
    for payload in [debug, unimplemented] {
        let out = after_kexinit(true, &payload);
        let (reason, error) = expect_local_close(&out);
        assert_eq!(reason, DisconnectReason::PROTOCOL_ERROR);
        assert_eq!(error, Error::UnexpectedMessage { number: payload[0] });
        assert!(after_kexinit(false, &payload).closed.is_none());
    }
}

#[test]
fn userauth_success_sent_to_a_server_closes_the_connection() {
    let (reason, error) = expect_local_close(&after_kexinit(false, &[52]));
    assert_eq!(reason, DisconnectReason::PROTOCOL_ERROR);
    assert_eq!(error, Error::UnexpectedMessage { number: 52 });
}

#[test]
fn connected_twice_is_an_unexpected_event() {
    let mut server = server();
    collect(server.process(Event::Connected), &mut Out::default());
    let mut out = Out::default();
    collect(server.process(Event::Connected), &mut out);
    let (_, error) = expect_local_close(&out);
    assert_eq!(error, Error::UnexpectedEvent);
}

#[test]
fn a_strict_kex_marker_is_never_chosen_as_the_key_exchange() {
    let mut input = CLIENT_VERSION.to_vec();
    input.extend(plain_packet(&client_kexinit(|k| {
        k.kex_algorithms = vec!["kex-strict-s-v00@openssh.com".into()];
    })));
    let (reason, error) = expect_local_close(&feed_server(&input));
    assert_eq!(reason, DisconnectReason::KEY_EXCHANGE_FAILED);
    assert!(matches!(
        error,
        Error::NoCommonAlgorithm {
            category: AlgorithmCategory::Kex,
            ..
        }
    ));
}

#[test]
fn lines_before_the_version_may_not_exceed_255_bytes_in_total() {
    let mut input = Vec::new();
    for _ in 0..9 {
        input.extend([b'x'; 29]);
        input.extend(b"\r\n");
    }
    input.extend(b"SSH-2.0-late\r\n");
    let (_, error) = expect_local_close(&feed_server(&input));
    assert_eq!(error, Error::BadVersion);
}

#[test]
fn the_server_software_version_can_be_set() {
    let mut server = server_with(|b| b.software_version("Go"));
    let mut client = client();
    let (s, c) = pump(&mut server, &mut client, usize::MAX);
    assert!(s.closed.is_none() && c.closed.is_none());
    assert_eq!(client.handshake().peer_version(), Some("SSH-2.0-Go"));
    assert_eq!(server.handshake().local_version(), "SSH-2.0-Go");
}

#[test]
fn an_untouched_reply_is_accepted_by_the_client() {
    assert!(client_given_reply(|_| {}).closed.is_none());
}

#[test]
fn the_client_refuses_a_reply_whose_signature_does_not_verify() {
    let out = client_given_reply(|r| {
        let last = r.signature.len() - 1;
        r.signature[last] ^= 1;
    });
    let (reason, error) = expect_local_close(&out);
    assert_eq!(reason, DisconnectReason::KEY_EXCHANGE_FAILED);
    assert_eq!(error, Error::HostKeySignature);
}

#[test]
fn the_client_refuses_a_host_key_of_another_type_than_negotiated() {
    let out = client_given_reply(|r| {
        let mut blob = Vec::new();
        blob.extend(7u32.to_be_bytes());
        blob.extend(b"ssh-rsa");
        blob.extend(&r.host_key[15..]);
        r.host_key = blob;
    });
    let (_, error) = expect_local_close(&out);
    assert_eq!(error, Error::HostKeySignature);
}

#[test]
fn the_client_refuses_an_all_zero_server_key() {
    let out = client_given_reply(|r| r.q_s = vec![0; 32]);
    let (reason, error) = expect_local_close(&out);
    assert_eq!(reason, DisconnectReason::KEY_EXCHANGE_FAILED);
    assert_eq!(error, Error::KeyExchange);
}
