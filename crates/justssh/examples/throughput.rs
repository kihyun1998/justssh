//! 64 MiB of channel data in 32 KiB packets under chacha20-poly1305@openssh.com: what a server
//! takes to send it, what a client takes to receive it in 32 KiB reads, the same cipher alone in
//! place over packets of the same size, and the client's input buffer afterwards.
//!
//! `cargo run --release -p justssh --example throughput`

#[path = "../tests/common/mod.rs"]
mod common;

use std::time::{Duration, Instant};

use chacha20::ChaCha20Legacy;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use justssh::{Action, Client, ClientConfig, Event, HostKey, Server, ServerConfig, Zeroizing};
use poly1305::Poly1305;
use poly1305::universal_hash::KeyInit;

const TOTAL: usize = 64 << 20;
const CHUNK: usize = 32 << 10;
const RUNS: usize = 5;
const CIPHER: &str = "chacha20-poly1305@openssh.com";

fn mib_per_s(d: Duration) -> f64 {
    (TOTAL as f64 / (1 << 20) as f64) / d.as_secs_f64()
}

/// The buffers `actions` write, as they are.
fn writes(actions: Vec<Action>) -> Vec<Vec<u8>> {
    actions
        .into_iter()
        .filter_map(|a| match a {
            Action::Write(b) => Some(b),
            _ => None,
        })
        .collect()
}

/// A server and a client through password authentication with one session channel open
/// between them: the server's id for it.
fn pair() -> (Server, Client, justssh::ChannelId) {
    let (kex, ciphers, macs) = (["curve25519-sha256"], [CIPHER], ["hmac-sha2-256"]);
    let mut server = Server::new(
        ServerConfig::builder(HostKey::ed25519_from_seed(Zeroizing::new(
            common::HOST_SEED,
        )))
        .rng(common::TestRng(1))
        .algorithms(&kex, &ciphers, &macs)
        .build(),
    );
    let mut client = Client::new(
        ClientConfig::builder(b"u")
            .rng(common::TestRng(2))
            .algorithms(&kex, &ciphers, &macs)
            .channel_window(1 << 30)
            .build(),
    );
    common::pump(&mut server, &mut client, usize::MAX);
    let request = client.auth_password(Zeroizing::new(b"pw".to_vec()));
    common::to_server(&mut server, request);
    common::to_client(&mut client, server.process(Event::AuthAccepted));
    let (_, open) = client.open_channel("session", Vec::new());
    let at_server = common::to_server(&mut server, open);
    let channel = at_server
        .iter()
        .find_map(|a| match a {
            Action::ChannelOpenRequest(r) => Some(r.channel()),
            _ => None,
        })
        .expect("no channel open");
    common::to_client(&mut client, server.accept_channel(channel, Vec::new()));
    (server, client, channel)
}

/// Sending through the channel layer and as encoded packets, receiving through it and as raw
/// packets, and the input buffer's capacity once idle after that and after one large packet.
fn endpoints() -> (Duration, Duration, Duration, Duration, (usize, usize)) {
    let (mut server, mut client, channel) = pair();
    let chunk = vec![0x5a; CHUNK];
    // What the client is given comes from a second pair with the same keys, so that the timed
    // sending can drop each buffer once counted, as an adapter does once it has written it.
    let mut wire = Vec::with_capacity(TOTAL + TOTAL / 16);
    let (mut twin, _, twin_channel) = pair();
    for _ in 0..TOTAL / CHUNK {
        for packet in writes(twin.channel_data(twin_channel, &chunk)) {
            wire.extend_from_slice(&packet);
        }
    }
    let started = Instant::now();
    let mut sent_bytes = 0;
    for _ in 0..TOTAL / CHUNK {
        sent_bytes += writes(server.channel_data(channel, &chunk))
            .iter()
            .map(Vec::len)
            .sum::<usize>();
    }
    let sent = started.elapsed();
    assert_eq!(sent_bytes, wire.len());
    let payload =
        justssh_wire::Message::ChannelData(justssh_wire::ChannelData::new(0, chunk.clone()))
            .encode();
    let started = Instant::now();
    let mut raw = 0;
    for _ in 0..TOTAL / CHUNK {
        raw += writes(server.send_raw(&payload))
            .iter()
            .map(Vec::len)
            .sum::<usize>();
    }
    let sent_raw = started.elapsed();
    assert!(raw > TOTAL);
    let started = Instant::now();
    let mut got = 0;
    for piece in wire.chunks(CHUNK) {
        for a in client.process(Event::Received(piece)) {
            if let Action::ChannelData { data, .. } = a {
                got += data.len();
            }
        }
    }
    let received = started.elapsed();
    let (_, mut raw_client, _) = pair();
    raw_client.set_raw_receive(true);
    let started = Instant::now();
    let mut raw_got = 0;
    for piece in wire.chunks(CHUNK) {
        for a in raw_client.process(Event::Received(piece)) {
            if let Action::RawReceived(p) = a {
                raw_got += p.len();
            }
        }
    }
    let received_raw = started.elapsed();
    assert!(raw_got > TOTAL);
    assert_eq!(got, TOTAL);
    let after_data = client.input_capacity();
    let ignore =
        justssh_wire::Message::Ignore(justssh_wire::Ignore::new(vec![0; 250 << 10])).encode();
    let (mut fresh_server, mut fresh_client, _) = pair();
    let big: Vec<u8> = writes(fresh_server.send_raw(&ignore)).concat();
    for piece in big.chunks(CHUNK) {
        for a in fresh_client.process(Event::Received(piece)) {
            if let Action::Closed(c) = a {
                panic!("{c:?} {}", big.len());
            }
        }
    }
    let after_big = fresh_client.input_capacity();
    (
        sent,
        sent_raw,
        received,
        received_raw,
        (after_data, after_big),
    )
}

/// The same cipher alone, sealing then opening each packet in place: the length field and the
/// body each under their own key, and a Poly1305 tag over both.
fn cipher_alone() -> (Duration, Duration) {
    let (main, header) = ([1u8; 32], [2u8; 32]);
    let stream = |key: &[u8; 32], seq: u32, block: u64| {
        let mut c = ChaCha20Legacy::new(key.into(), &u64::from(seq).to_be_bytes().into());
        c.seek(block * 64);
        c
    };
    let tag = |seq: u32, data: &[u8]| -> [u8; 16] {
        let mut key = [0u8; 32];
        stream(&main, seq, 0).apply_keystream(&mut key);
        Poly1305::new(&key.into()).compute_unpadded(data).into()
    };
    let packets = TOTAL / CHUNK;
    let mut wire: Vec<Vec<u8>> = (0..packets)
        .map(|_| vec![0x5a; 4 + 1 + 9 + CHUNK + 15 + 16])
        .collect();
    let started = Instant::now();
    for (seq, p) in wire.iter_mut().enumerate() {
        let seq = seq as u32;
        let end = p.len() - 16;
        stream(&header, seq, 0).apply_keystream(&mut p[..4]);
        stream(&main, seq, 1).apply_keystream(&mut p[4..end]);
        let t = tag(seq, &p[..end]);
        p[end..].copy_from_slice(&t);
    }
    let sealed = started.elapsed();
    let started = Instant::now();
    for (seq, p) in wire.iter_mut().enumerate() {
        let seq = seq as u32;
        let end = p.len() - 16;
        assert_eq!(tag(seq, &p[..end]), p[end..]);
        stream(&main, seq, 1).apply_keystream(&mut p[4..end]);
    }
    (sealed, started.elapsed())
}

fn median(v: impl Into<Vec<f64>>) -> f64 {
    let mut v = v.into();
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

fn main() {
    let (mut send, mut send_raw, mut receive) = (Vec::new(), Vec::new(), Vec::new());
    let mut receive_raw = Vec::new();
    let (mut seal, mut open) = (Vec::new(), Vec::new());
    let mut capacity = (0, 0);
    for _ in 0..RUNS {
        let (s, raw, r, rr, c) = endpoints();
        receive_raw.push(mib_per_s(rr));
        send.push(mib_per_s(s));
        send_raw.push(mib_per_s(raw));
        receive.push(mib_per_s(r));
        capacity = c;
        let (s, o) = cipher_alone();
        seal.push(mib_per_s(s));
        open.push(mib_per_s(o));
    }
    println!("median of {RUNS} runs, 64 MiB in 32 KiB packets, {CIPHER}");
    println!(
        "send    {:7.0} MiB/s   cipher alone sealing {:7.0} MiB/s",
        median(send.clone()),
        median(seal.clone())
    );
    println!(
        "send as encoded packets {:7.0} MiB/s",
        median(send_raw.clone())
    );
    println!(
        "receive {:7.0} MiB/s   cipher alone opening {:7.0} MiB/s",
        median(receive.clone()),
        median(open.clone())
    );
    println!(
        "receive as raw packets {:7.0} MiB/s",
        median(receive_raw.clone())
    );
    let ratio =
        |a: &[f64], b: &[f64]| median(a.iter().zip(b).map(|(x, y)| x / y).collect::<Vec<f64>>());
    println!(
        "against the cipher alone, run by run: send {:.2}, receive {:.2}, receive raw {:.2}",
        ratio(&send, &seal),
        ratio(&receive, &open),
        ratio(&receive_raw, &open)
    );
    println!(
        "client input buffer, idle: {} bytes after the data, {} after one 250 KiB IGNORE",
        capacity.0, capacity.1
    );
}
