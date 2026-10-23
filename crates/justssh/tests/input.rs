//! What the buffer of received input keeps once a packet has been decrypted in it and handled.

mod common;

use common::{CLIENT_USER, TestRng, pump, server_with};
use justssh::{Action, Client, ClientConfig, Event, Zeroizing};

const PASSWORD: &[u8] = b"correct horse battery staple";

fn writes(actions: Vec<Action>) -> Vec<u8> {
    let mut out = Vec::new();
    for a in actions {
        if let Action::Write(b) = a {
            out.extend(b);
        }
    }
    out
}

#[test]
fn a_password_is_not_left_in_the_input_buffer_under_any_cipher() {
    for (cipher, mac) in [
        ("chacha20-poly1305@openssh.com", "hmac-sha2-256"),
        ("aes128-gcm@openssh.com", "hmac-sha2-256"),
        ("aes128-ctr", "hmac-sha2-256"),
        ("aes128-ctr", "hmac-sha2-256-etm@openssh.com"),
    ] {
        let algorithms = (["curve25519-sha256"], [cipher], [mac]);
        let mut server = server_with(|b| b.algorithms(&algorithms.0, &algorithms.1, &algorithms.2));
        let mut client = Client::new(
            ClientConfig::builder(CLIENT_USER)
                .rng(TestRng(2))
                .algorithms(&algorithms.0, &algorithms.1, &algorithms.2)
                .build(),
        );
        pump(&mut server, &mut client, usize::MAX);
        let mut bytes = writes(client.auth_password(Zeroizing::new(PASSWORD.to_vec())));
        let request_len = bytes.len();
        // Then the first three bytes of the next packet.
        bytes.extend(&writes(client.send_raw(&[2, 0, 0, 0, 0]))[..3]);
        let handled = server.process(Event::Received(&bytes));
        assert!(
            handled
                .iter()
                .any(|a| matches!(a, Action::PasswordRequest(_))),
            "{cipher} {mac}: {handled:?}"
        );
        let held = server.input_held();
        assert!(
            held.len() >= request_len,
            "{cipher} {mac}: {} bytes held",
            held.len()
        );
        assert!(
            !held.windows(PASSWORD.len()).any(|w| w == PASSWORD),
            "{cipher} {mac}: the password is still in the input buffer"
        );
    }
}

#[test]
fn the_input_buffer_stays_near_its_reads_while_packets_straddle_them() {
    let (mut server, mut client) = (common::server(), common::client());
    pump(&mut server, &mut client, usize::MAX);
    let mut wire = Vec::new();
    for _ in 0..128 {
        wire.extend(writes(client.send_raw(
            &[[2, 0, 0, 0x7f, 0xfb].as_slice(), &[0; 0x7ffb]].concat(),
        )));
    }
    let mut most = 0;
    for piece in wire.chunks(30_000) {
        server.process(Event::Received(piece));
        most = most.max(server.input_capacity());
    }
    assert!(
        most <= 128 << 10,
        "{most} bytes of capacity for 32 KiB packets in 30,000-byte reads"
    );
}
