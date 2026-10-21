//! Every key exchange, cipher and MAC of x/crypto/ssh v0.55's default lists, between a real client
//! and a real server, each restricted to one (`test-support`).

mod common;

use common::*;
use justssh::{
    Action, Client, ClientConfig, Closed, DisconnectReason, Error, Event, Phase, Server, Zeroizing,
};
use justssh_wire::{KexInit, Message};

/// x/crypto/ssh v0.55's `defaultKexAlgos` with the alias it adds after `curve25519-sha256`
/// (`common.go`).
const GO_KEX: &[&str] = &[
    "mlkem768x25519-sha256",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group14-sha1",
];

/// x/crypto/ssh v0.55's `defaultCiphers`.
const GO_CIPHERS: &[&str] = &[
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
    "chacha20-poly1305@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
];

/// x/crypto/ssh v0.55's `defaultMACs`.
const GO_MACS: &[&str] = &[
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha1",
    "hmac-sha1-96",
];

/// The `SSH_MSG_KEXINIT` a side sends first, read from its output.
fn first_kexinit(out: &[u8]) -> KexInit {
    let nl = out.iter().position(|&b| b == b'\n').unwrap();
    let payloads = split_plain(&out[nl + 1..]);
    match Message::decode(&payloads[0]).unwrap() {
        Message::KexInit(k) => k,
        other => panic!("{other:?}"),
    }
}

fn without_markers(names: &[String]) -> Vec<&str> {
    names
        .iter()
        .map(String::as_str)
        .filter(|n| !n.starts_with("kex-strict-") && !n.starts_with("ext-info-"))
        .collect()
}

#[test]
fn both_sides_offer_gos_default_lists_in_gos_order() {
    let mut client = client();
    let mut out = Out::default();
    collect(client.process(Event::Connected), &mut out);
    collect(client.process(Event::Received(CLIENT_VERSION)), &mut out);
    let c = first_kexinit(&out.bytes);

    let mut server = server();
    let mut out = Out::default();
    collect(server.process(Event::Connected), &mut out);
    collect(server.process(Event::Received(CLIENT_VERSION)), &mut out);
    let s = first_kexinit(&out.bytes);

    for k in [&c, &s] {
        assert_eq!(without_markers(&k.kex_algorithms), GO_KEX);
        assert_eq!(k.encryption_algorithms_client_to_server, GO_CIPHERS);
        assert_eq!(k.encryption_algorithms_server_to_client, GO_CIPHERS);
        assert_eq!(k.mac_algorithms_client_to_server, GO_MACS);
        assert_eq!(k.mac_algorithms_server_to_client, GO_MACS);
    }
}

/// A server and client restricted to `kex`, `cipher` and `mac`, through password authentication;
/// bytes are delivered in pieces of at most `chunk`.
fn authenticated_with(kex: &str, cipher: &str, mac: &str, chunk: usize) -> (Server, Client) {
    let mut server = server_with(|b| b.algorithms(&[kex], &[cipher], &[mac]));
    let mut client = Client::new(
        ClientConfig::builder(CLIENT_USER)
            .rng(TestRng(2))
            .algorithms(&[kex], &[cipher], &[mac])
            .build(),
    );
    let (s, c) = pump(&mut server, &mut client, chunk);
    assert!(
        s.closed.is_none() && c.closed.is_none(),
        "{kex} {cipher} {mac}: {:?} {:?}",
        s.closed,
        c.closed
    );
    assert_eq!(client.phase(), Phase::Auth, "{kex} {cipher} {mac}");
    let negotiated = client.handshake().negotiated().unwrap();
    assert_eq!(
        (negotiated.kex(), negotiated.cipher_client_to_server()),
        (kex, cipher)
    );
    let request = client.auth_password(Zeroizing::new(b"pw".to_vec()));
    let at_server = to_server(&mut server, request);
    assert!(
        matches!(at_server.first(), Some(Action::PasswordRequest(_))),
        "{kex} {cipher} {mac}: {at_server:?}"
    );
    to_client(&mut client, server.process(Event::AuthAccepted));
    assert_eq!(client.phase(), Phase::Connected, "{kex} {cipher} {mac}");
    (server, client)
}

/// Opens a channel from the client and sends `size` bytes each way through it.
fn round_trip(server: &mut Server, client: &mut Client, size: usize) {
    let (id, actions) = client.open_channel("session", Vec::new());
    let at_server = to_server(server, actions);
    let server_id = match at_server.first() {
        Some(Action::ChannelOpenRequest(r)) => r.channel(),
        other => panic!("{other:?}"),
    };
    to_client(client, server.accept_channel(server_id, Vec::new()));
    let payload: Vec<u8> = (0..size).map(|i| (i * 7 + 3) as u8).collect();

    let got: Vec<u8> = to_server(server, client.channel_data(id.unwrap(), &payload))
        .into_iter()
        .flat_map(|a| match a {
            Action::ChannelData { data, .. } => data,
            _ => Vec::new(),
        })
        .collect();
    assert_eq!(got, payload, "client to server");
    let got: Vec<u8> = to_client(client, server.channel_data(server_id, &payload))
        .into_iter()
        .flat_map(|a| match a {
            Action::ChannelData { data, .. } => data,
            _ => Vec::new(),
        })
        .collect();
    assert_eq!(got, payload, "server to client");
}

#[test]
fn every_key_exchange_completes_and_carries_data() {
    for kex in GO_KEX {
        let (mut server, mut client) =
            authenticated_with(kex, "chacha20-poly1305@openssh.com", "hmac-sha2-256", 4096);
        assert_eq!(client.session_id(), server.session_id(), "{kex}");
        round_trip(&mut server, &mut client, 3000);
    }
}

#[test]
fn every_cipher_carries_data_both_ways() {
    for cipher in GO_CIPHERS {
        let (mut server, mut client) =
            authenticated_with("curve25519-sha256", cipher, "hmac-sha2-256", 4096);
        round_trip(&mut server, &mut client, 70_000);
    }
}

#[test]
fn every_mac_carries_data_both_ways_under_each_ctr_cipher() {
    for cipher in ["aes128-ctr", "aes192-ctr", "aes256-ctr"] {
        for mac in GO_MACS {
            let (mut server, mut client) =
                authenticated_with("curve25519-sha256", cipher, mac, 4096);
            assert_eq!(
                client
                    .handshake()
                    .negotiated()
                    .unwrap()
                    .mac_client_to_server(),
                Some(*mac)
            );
            round_trip(&mut server, &mut client, 5000);
        }
    }
}

#[test]
fn packets_split_into_single_bytes_are_reassembled_under_each_cipher_and_mac_kind() {
    for (cipher, mac) in [
        ("aes128-gcm@openssh.com", "hmac-sha1"),
        ("aes256-ctr", "hmac-sha2-512"),
        ("aes128-ctr", "hmac-sha2-256-etm@openssh.com"),
        ("chacha20-poly1305@openssh.com", "hmac-sha1"),
    ] {
        authenticated_with("ecdh-sha2-nistp256", cipher, mac, 1);
    }
}

#[test]
fn a_tampered_packet_ends_the_connection_under_each_protection() {
    for (cipher, mac) in [
        ("aes128-gcm@openssh.com", "hmac-sha1"),
        ("aes256-gcm@openssh.com", "hmac-sha1"),
        ("aes128-ctr", "hmac-sha2-256"),
        ("aes128-ctr", "hmac-sha2-256-etm@openssh.com"),
        ("aes192-ctr", "hmac-sha1-96"),
        ("chacha20-poly1305@openssh.com", "hmac-sha1"),
    ] {
        let (mut server, mut client) = authenticated_with("curve25519-sha256", cipher, mac, 4096);
        let mut sent = Vec::new();
        for a in client.global_request("x", false, vec![0; 40]).1 {
            if let Action::Write(b) = a {
                sent.extend(b);
            }
        }
        let last = sent.len() - 1;
        sent[last - 20] ^= 1;
        let actions = server.process(Event::Received(&sent));
        let closed = actions.iter().find_map(|a| match a {
            Action::Closed(c) => Some(c.clone()),
            _ => None,
        });
        assert!(
            matches!(
                closed,
                Some(Closed::Local {
                    reason: DisconnectReason::MAC_ERROR,
                    error: Error::MacMismatch,
                    ..
                })
            ),
            "{cipher} {mac}: {closed:?}"
        );
    }
}

#[test]
fn no_common_mac_under_a_ctr_cipher_ends_the_key_exchange() {
    let mut server = server_with(|b| b.algorithms(&GO_KEX[1..2], &["aes128-ctr"], &["hmac-sha1"]));
    let mut client = Client::new(
        ClientConfig::builder(CLIENT_USER)
            .rng(TestRng(2))
            .algorithms(&GO_KEX[1..2], &["aes128-ctr"], &["hmac-sha2-256"])
            .build(),
    );
    let (s, _) = pump(&mut server, &mut client, usize::MAX);
    assert!(
        matches!(
            s.closed,
            Some(Closed::Local {
                error: Error::NoCommonAlgorithm { .. },
                ..
            })
        ),
        "{:?}",
        s.closed
    );
}

/// The 2048-bit MODP group's prime (RFC 3526 §3).
const GROUP14_P: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E",
    "3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF",
    "5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D3",
    "9A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08",
    "CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183",
    "995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
);

/// `GROUP14_P - minus` as a positive mpint body.
fn p_minus(minus: u8) -> Vec<u8> {
    let mut n = vec![0u8];
    n.extend(
        (0..GROUP14_P.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&GROUP14_P[i..i + 2], 16).unwrap()),
    );
    let last = n.len() - 1;
    n[last] -= minus;
    n
}

#[test]
fn a_dh_public_value_outside_one_to_p_minus_one_ends_the_exchange() {
    for e in [
        vec![1u8],
        vec![0u8],
        vec![0xff; 256],
        p_minus(1),
        p_minus(0),
    ] {
        let mut server = server_with(|b| {
            b.algorithms(
                &["diffie-hellman-group14-sha256"],
                &["aes128-ctr"],
                &["hmac-sha2-256"],
            )
        });
        let kexinit = client_kexinit(|k| {
            k.kex_algorithms = vec!["diffie-hellman-group14-sha256".into()];
            k.encryption_algorithms_client_to_server = vec!["aes128-ctr".into()];
            k.encryption_algorithms_server_to_client = vec!["aes128-ctr".into()];
            k.mac_algorithms_client_to_server = vec!["hmac-sha2-256".into()];
            k.mac_algorithms_server_to_client = vec!["hmac-sha2-256".into()];
        });
        let mut input = CLIENT_VERSION.to_vec();
        input.extend(plain_packet(&kexinit));
        input.extend(plain_packet(
            &Message::KexEcdhInit(justssh_wire::KexEcdhInit::new(e.clone())).encode(),
        ));
        let mut out = Out::default();
        collect(server.process(Event::Connected), &mut out);
        collect(server.process(Event::Received(&input)), &mut out);
        assert!(
            matches!(
                out.closed,
                Some(Closed::Local {
                    error: Error::KeyExchange,
                    ..
                })
            ),
            "{e:?}: {:?}",
            out.closed
        );
    }
}

#[test]
fn a_largest_packet_under_the_longest_mac_is_held_while_a_verdict_is_pending() {
    let (kex, cipher, mac) = (
        "curve25519-sha256",
        "aes128-ctr",
        "hmac-sha2-512-etm@openssh.com",
    );
    let mut server = server_with(|b| b.algorithms(&[kex], &[cipher], &[mac]));
    let mut client = Client::new(
        ClientConfig::builder(CLIENT_USER)
            .rng(TestRng(2))
            .algorithms(&[kex], &[cipher], &[mac])
            .build(),
    );
    pump(&mut server, &mut client, 4096);
    let at_server = to_server(
        &mut server,
        client.auth_password(Zeroizing::new(b"pw".to_vec())),
    );
    assert!(matches!(
        at_server.first(),
        Some(Action::PasswordRequest(_))
    ));

    // SSH_MSG_IGNORE whose packet_length is 256 KiB: 1 + 262128 + 15 bytes of padding.
    let mut ignore = vec![2u8];
    ignore.extend_from_slice(&262_123u32.to_be_bytes());
    ignore.resize(262_128, 0);
    let held = to_server(&mut server, client.send_raw(&ignore));
    assert!(
        !held.iter().any(|a| matches!(a, Action::Closed(_))),
        "{held:?}"
    );
    to_client(&mut client, server.process(Event::AuthAccepted));
    assert_eq!(client.phase(), Phase::Connected);
}

#[test]
fn without_strict_kex_data_flows_under_a_ctr_cipher() {
    let (kex, cipher, mac) = ("curve25519-sha256", "aes128-ctr", "hmac-sha2-256");
    let mut server = server_with(|b| b.algorithms(&[kex], &[cipher], &[mac]));
    let mut client = Client::new(
        ClientConfig::builder(CLIENT_USER)
            .rng(TestRng(2))
            .algorithms(&[kex], &[cipher], &[mac])
            .strict_kex(false)
            .build(),
    );
    let (s, c) = pump(&mut server, &mut client, 4096);
    assert!(s.closed.is_none() && c.closed.is_none(), "{s:?} {c:?}");
    assert!(!client.handshake().negotiated().unwrap().strict_kex());
    to_server(
        &mut server,
        client.auth_password(Zeroizing::new(b"pw".to_vec())),
    );
    to_client(&mut client, server.process(Event::AuthAccepted));
    assert_eq!(client.phase(), Phase::Connected);
    round_trip(&mut server, &mut client, 5000);
}

#[test]
fn each_direction_carries_data_under_its_own_cipher_and_mac() {
    for (c2s, s2c) in [
        (
            ("aes128-gcm@openssh.com", "hmac-sha2-256"),
            ("aes256-ctr", "hmac-sha1-96"),
        ),
        (
            ("aes192-ctr", "hmac-sha2-512-etm@openssh.com"),
            ("chacha20-poly1305@openssh.com", "hmac-sha2-256"),
        ),
    ] {
        let kex = "curve25519-sha256";
        let mut server = server_with(|b| b.algorithms(&[kex], &[c2s.0, s2c.0], &[c2s.1, s2c.1]));
        let mut client = Client::new(
            ClientConfig::builder(CLIENT_USER)
                .rng(TestRng(2))
                .algorithms(&[kex], &[c2s.0], &[c2s.1])
                .server_to_client(&[s2c.0], &[s2c.1])
                .build(),
        );
        let (s, c) = pump(&mut server, &mut client, 4096);
        assert!(s.closed.is_none() && c.closed.is_none(), "{s:?} {c:?}");
        let n = client.handshake().negotiated().unwrap();
        assert_eq!(
            (n.cipher_client_to_server(), n.cipher_server_to_client()),
            (c2s.0, s2c.0)
        );
        if s2c.0.ends_with("-ctr") {
            assert_eq!(n.mac_server_to_client(), Some(s2c.1));
        }
        if c2s.0.ends_with("-ctr") {
            assert_eq!(n.mac_client_to_server(), Some(c2s.1));
        }
        to_server(
            &mut server,
            client.auth_password(Zeroizing::new(b"pw".to_vec())),
        );
        to_client(&mut client, server.process(Event::AuthAccepted));
        assert_eq!(client.phase(), Phase::Connected);
        round_trip(&mut server, &mut client, 5000);
    }
}
