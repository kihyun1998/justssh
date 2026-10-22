//! Server host keys of every kind, several at once and restricted to some of their algorithms,
//! and the client's verification of each (`test-support` restricts the client's list).

mod common;

#[path = "common/test_keys.rs"]
mod test_keys;

use common::*;
use justssh::{
    Client, ClientConfig, Closed, EcdsaCurve, Error, Event, HostKey, KeyError, Phase, PrivateKey,
    Server, ServerConfig, Zeroizing,
};
use justssh_wire::{KexInit, Message};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn ed25519() -> PrivateKey {
    PrivateKey::ed25519(Zeroizing::new(HOST_SEED))
}

fn ecdsa(curve: EcdsaCurve, len: usize) -> PrivateKey {
    PrivateKey::ecdsa(curve, Zeroizing::new(vec![1; len])).unwrap()
}

fn rsa() -> PrivateKey {
    PrivateKey::rsa(
        &hex(test_keys::RSA_N),
        &hex(test_keys::RSA_E),
        Zeroizing::new(hex(test_keys::RSA_D)),
        Zeroizing::new(hex(test_keys::RSA_P)),
        Zeroizing::new(hex(test_keys::RSA_Q)),
    )
    .unwrap()
}

fn server_of(first: HostKey, more: Vec<HostKey>) -> Server {
    let mut b = ServerConfig::builder(first).rng(TestRng(1));
    for k in more {
        b = b.host_key(k);
    }
    Server::new(b.build())
}

fn client_offering(algorithm: &str) -> Client {
    client_seeded(algorithm, 2)
}

fn client_seeded(algorithm: &str, seed: u64) -> Client {
    Client::new(
        ClientConfig::builder(CLIENT_USER)
            .rng(TestRng(seed))
            .host_key_algorithms(&[algorithm])
            .build(),
    )
}

/// The `SSH_MSG_KEXINIT` a side sends first, read from its output.
fn first_kexinit(out: &[u8]) -> KexInit {
    let nl = out.iter().position(|&b| b == b'\n').unwrap();
    match Message::decode(&split_plain(&out[nl + 1..])[0]).unwrap() {
        Message::KexInit(k) => k,
        other => panic!("{other:?}"),
    }
}

fn offered(server: &mut Server) -> Vec<String> {
    let mut out = Out::default();
    collect(server.process(Event::Connected), &mut out);
    collect(server.process(Event::Received(CLIENT_VERSION)), &mut out);
    first_kexinit(&out.bytes).server_host_key_algorithms
}

#[test]
fn a_server_like_the_go_broker_offers_ed25519_then_ssh_rsa() {
    let legacy = HostKey::new(rsa()).with_algorithms(&["ssh-rsa"]).unwrap();
    let mut server = server_of(HostKey::new(ed25519()), vec![legacy]);
    assert_eq!(offered(&mut server), ["ssh-ed25519", "ssh-rsa"]);
}

#[test]
fn an_unrestricted_rsa_key_offers_gos_three_rsa_algorithms_in_gos_order() {
    let mut server = server_of(HostKey::new(rsa()), vec![]);
    assert_eq!(
        offered(&mut server),
        ["rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"]
    );
}

#[test]
fn a_restriction_keeps_the_keys_own_order() {
    let k = HostKey::new(rsa())
        .with_algorithms(&["ssh-rsa", "rsa-sha2-512"])
        .unwrap();
    assert_eq!(k.algorithms(), ["rsa-sha2-512", "ssh-rsa"]);
}

#[test]
fn a_restriction_to_nothing_or_to_what_the_key_cannot_sign_is_refused() {
    assert_eq!(
        HostKey::new(rsa()).with_algorithms(&[]).err(),
        Some(KeyError::UnsupportedAlgorithm)
    );
    assert_eq!(
        HostKey::new(ed25519()).with_algorithms(&["ssh-rsa"]).err(),
        Some(KeyError::UnsupportedAlgorithm)
    );
}

#[test]
fn a_second_restriction_narrows_the_first_and_cannot_widen_it() {
    let k = HostKey::new(rsa())
        .with_algorithms(&["ssh-rsa", "rsa-sha2-512"])
        .unwrap();
    assert_eq!(
        k.clone()
            .with_algorithms(&["ssh-rsa"])
            .unwrap()
            .algorithms(),
        ["ssh-rsa"]
    );
    assert_eq!(
        k.with_algorithms(&["rsa-sha2-256"]).err(),
        Some(KeyError::UnsupportedAlgorithm)
    );
}

#[test]
fn keys_are_offered_in_the_order_added_and_a_second_key_of_one_format_replaces_the_first() {
    let mut server = server_of(
        HostKey::new(ecdsa(EcdsaCurve::P384, 48)),
        vec![
            HostKey::new(ed25519()),
            HostKey::new(rsa()).with_algorithms(&["ssh-rsa"]).unwrap(),
            HostKey::new(rsa())
                .with_algorithms(&["rsa-sha2-512"])
                .unwrap(),
        ],
    );
    assert_eq!(
        offered(&mut server),
        ["ecdsa-sha2-nistp384", "ssh-ed25519", "rsa-sha2-512"]
    );
}

#[test]
fn a_host_key_with_a_certificate_is_offered_as_its_plain_key() {
    let mut ca = justssh_wire::Writer::new();
    ca.string(b"ssh-ed25519").string(&[8; 32]);
    let mut signature = justssh_wire::Writer::new();
    signature.string(b"ssh-ed25519").string(&[1; 64]);
    let mut w = justssh_wire::Writer::new();
    w.string(b"ssh-ed25519-cert-v01@openssh.com")
        .string(&[0; 32])
        .string(&ed25519().plain_public_blob()[4 + 11 + 4..])
        .bytes(&[0; 8])
        .u32(2)
        .string(b"host")
        .string(b"")
        .bytes(&[0; 8])
        .bytes(&[0xff; 8])
        .string(b"")
        .string(b"")
        .string(b"")
        .string(&ca.into_bytes())
        .string(&signature.into_bytes());
    let key = ed25519().with_certificate(w.into_bytes()).unwrap();
    let mut server = server_of(HostKey::new(key), vec![]);
    assert_eq!(offered(&mut server), ["ssh-ed25519"]);
}

#[test]
fn the_client_offers_gos_host_key_algorithms_without_certificates_and_dsa() {
    let mut client = client();
    let mut out = Out::default();
    collect(client.process(Event::Connected), &mut out);
    collect(client.process(Event::Received(CLIENT_VERSION)), &mut out);
    assert_eq!(
        first_kexinit(&out.bytes).server_host_key_algorithms,
        [
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
            "rsa-sha2-256",
            "rsa-sha2-512",
            "ssh-rsa",
            "ssh-ed25519",
        ]
    );
}

/// A server with `keys` and a client offering only `algorithm` run the key exchange; the host
/// key blob the client was asked to judge.
fn exchange(keys: Vec<HostKey>, algorithm: &str) -> Vec<u8> {
    let mut keys = keys.into_iter();
    let mut server = server_of(keys.next().unwrap(), keys.collect());
    let mut client = client_offering(algorithm);
    let (s, c) = pump(&mut server, &mut client, usize::MAX);
    assert!(
        s.closed.is_none() && c.closed.is_none(),
        "{algorithm}: {:?} {:?}",
        s.closed,
        c.closed
    );
    assert_eq!(client.phase(), Phase::Auth, "{algorithm}");
    assert_eq!(
        client.handshake().negotiated().unwrap().host_key(),
        algorithm
    );
    client.peer_host_key().unwrap().to_vec()
}

#[test]
fn each_host_key_algorithm_is_signed_by_the_server_and_verified_by_the_client() {
    for (key, algorithm) in [
        (ed25519(), "ssh-ed25519"),
        (ecdsa(EcdsaCurve::P256, 32), "ecdsa-sha2-nistp256"),
        (ecdsa(EcdsaCurve::P384, 48), "ecdsa-sha2-nistp384"),
        (ecdsa(EcdsaCurve::P521, 66), "ecdsa-sha2-nistp521"),
        (rsa(), "rsa-sha2-256"),
        (rsa(), "rsa-sha2-512"),
        (rsa(), "ssh-rsa"),
    ] {
        let blob = exchange(vec![HostKey::new(key.clone())], algorithm);
        assert_eq!(blob, key.plain_public_blob(), "{algorithm}");
    }
}

#[test]
fn the_server_signs_with_the_key_that_offers_the_negotiated_algorithm() {
    let keys = || {
        vec![
            HostKey::new(ed25519()),
            HostKey::new(rsa()).with_algorithms(&["ssh-rsa"]).unwrap(),
            HostKey::new(ecdsa(EcdsaCurve::P256, 32)),
        ]
    };
    assert_eq!(exchange(keys(), "ssh-rsa"), rsa().plain_public_blob());
    assert_eq!(
        exchange(keys(), "ecdsa-sha2-nistp256"),
        ecdsa(EcdsaCurve::P256, 32).plain_public_blob()
    );
    assert_eq!(
        exchange(keys(), "ssh-ed25519"),
        ed25519().plain_public_blob()
    );
}

#[test]
fn a_restricted_key_is_not_used_for_an_algorithm_outside_its_restriction() {
    let mut server = server_of(
        HostKey::new(rsa()).with_algorithms(&["ssh-rsa"]).unwrap(),
        vec![],
    );
    let mut client = client_offering("rsa-sha2-256");
    let (_, c) = pump(&mut server, &mut client, usize::MAX);
    assert!(
        matches!(
            c.closed,
            Some(Closed::Local {
                error: Error::NoCommonAlgorithm { .. },
                ..
            })
        ),
        "{:?}",
        c.closed
    );
}

/// A server with `key` and a client offering only `algorithm`, the signature in the server's
/// `SSH_MSG_KEX_ECDH_REPLY` changed by `tamper`; how the client ends, if it does.
fn tampered(key: PrivateKey, algorithm: &str, tamper: impl FnOnce(&mut Vec<u8>)) -> Option<Closed> {
    tampered_seeded(key, algorithm, 2, tamper)
}

/// As [`tampered`], the client's generator seeded with `seed`.
fn tampered_seeded(
    key: PrivateKey,
    algorithm: &str,
    seed: u64,
    tamper: impl FnOnce(&mut Vec<u8>),
) -> Option<Closed> {
    let mut server = server_of(HostKey::new(key), vec![]);
    let mut client = client_seeded(algorithm, seed);
    let (mut s, mut c) = (Out::default(), Out::default());
    collect(server.process(Event::Connected), &mut s);
    collect(client.process(Event::Connected), &mut c);
    collect(server.process(Event::Received(&c.bytes)), &mut s);
    let c_sent = c.bytes.len();
    collect(client.process(Event::Received(&s.bytes)), &mut c);
    let s_sent = s.bytes.len();
    collect(server.process(Event::Received(&c.bytes[c_sent..])), &mut s);
    let rest = &s.bytes[s_sent..];
    let reply_len = 4 + u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
    let Message::KexEcdhReply(mut reply) =
        Message::decode(&split_plain(&rest[..reply_len])[0]).unwrap()
    else {
        panic!("no ECDH reply");
    };
    tamper(&mut reply.signature);
    let mut forged = plain_packet(&Message::KexEcdhReply(reply).encode());
    forged.extend(&rest[reply_len..]);
    let mut out = Out::default();
    let actions = client.process(Event::Received(&forged));
    collect(accepting_host_keys(&mut client, actions), &mut out);
    out.closed
}

#[test]
fn a_signature_that_does_not_verify_ends_the_exchange_for_each_kind_of_key() {
    for (key, algorithm) in [
        (ecdsa(EcdsaCurve::P256, 32), "ecdsa-sha2-nistp256"),
        (ecdsa(EcdsaCurve::P384, 48), "ecdsa-sha2-nistp384"),
        (ecdsa(EcdsaCurve::P521, 66), "ecdsa-sha2-nistp521"),
        (rsa(), "rsa-sha2-256"),
        (rsa(), "ssh-rsa"),
    ] {
        assert_eq!(
            tampered(key.clone(), algorithm, |_| {}),
            None,
            "{algorithm}"
        );
        let closed = tampered(key, algorithm, |sig| {
            let last = sig.len() - 1;
            sig[last] ^= 1;
        });
        assert!(
            matches!(
                closed,
                Some(Closed::Local {
                    error: Error::HostKeySignature,
                    ..
                })
            ),
            "{algorithm}: {closed:?}"
        );
    }
}

#[test]
fn a_signature_named_for_another_algorithm_than_negotiated_ends_the_exchange() {
    let closed = tampered(rsa(), "rsa-sha2-256", |sig| {
        let at = sig.windows(12).position(|w| w == b"rsa-sha2-256").unwrap();
        sig[at..at + 12].copy_from_slice(b"rsa-sha2-512");
    });
    assert!(
        matches!(
            closed,
            Some(Closed::Local {
                error: Error::HostKeySignature,
                ..
            })
        ),
        "{closed:?}"
    );
}

#[test]
fn an_rsa_signature_shorter_than_the_modulus_is_verified_as_go_and_openssh_do() {
    for seed in 3..3000 {
        let mut short = false;
        let closed = tampered_seeded(rsa(), "rsa-sha2-256", seed, |sig| {
            let mut r = justssh_wire::Reader::new(sig);
            let name = r.string().unwrap().to_vec();
            let body = r.string().unwrap().to_vec();
            if body[0] != 0 {
                return;
            }
            let mut w = justssh_wire::Writer::new();
            w.string(&name).string(&body[1..]);
            *sig = w.into_bytes();
            short = true;
        });
        if short {
            assert_eq!(closed, None, "seed {seed}");
            return;
        }
    }
    panic!("no signature with a leading zero byte in the seeds tried");
}
