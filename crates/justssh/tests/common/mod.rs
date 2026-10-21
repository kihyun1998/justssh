#![allow(dead_code)]

use core::convert::Infallible;

use justssh::{Action, Client, ClientConfig, Closed, Event, HostKey, Server, ServerConfig};
use justssh_wire::{KexInit, Message};

/// A deterministic generator for tests (splitmix64). Not for production use.
pub struct TestRng(pub u64);

impl rand_core::TryRng for TestRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(self.try_next_u64()? as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        Ok(z ^ (z >> 31))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for chunk in dst.chunks_mut(8) {
            let v = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for TestRng {}

pub const HOST_SEED: [u8; 32] = [7; 32];

pub fn server() -> Server {
    server_with(|b| b)
}

pub fn server_with(
    edit: impl FnOnce(justssh::ServerConfigBuilder) -> justssh::ServerConfigBuilder,
) -> Server {
    let builder = ServerConfig::builder(HostKey::ed25519_from_seed(justssh::Zeroizing::new(
        HOST_SEED,
    )))
    .rng(TestRng(1));
    Server::new(edit(builder).build())
}

pub fn client() -> Client {
    Client::new(ClientConfig::builder().rng(TestRng(2)).build())
}

/// What one side produced: bytes for the peer and, if it ended, how.
#[derive(Default, Debug)]
pub struct Out {
    pub bytes: Vec<u8>,
    pub closed: Option<Closed>,
}

pub fn collect(actions: Vec<Action>, out: &mut Out) {
    for a in actions {
        match a {
            Action::Write(b) => out.bytes.extend(b),
            Action::Closed(c) => {
                assert!(out.closed.is_none(), "closed twice");
                out.closed = Some(c);
            }
            _ => {}
        }
    }
}

/// Runs a server and a client against each other in memory, delivering each side's output to
/// the other in pieces of at most `chunk` bytes, until neither has anything left to say.
pub fn pump(server: &mut Server, client: &mut Client, chunk: usize) -> (Out, Out) {
    let mut s = Out::default();
    let mut c = Out::default();
    collect(server.process(Event::Connected), &mut s);
    collect(client.process(Event::Connected), &mut c);
    let (mut s_sent, mut c_sent) = (0, 0);
    loop {
        let mut moved = false;
        while c_sent < c.bytes.len() {
            let end = c_sent.saturating_add(chunk).min(c.bytes.len());
            let piece = c.bytes[c_sent..end].to_vec();
            c_sent = end;
            collect(server.process(Event::Received(&piece)), &mut s);
            moved = true;
        }
        while s_sent < s.bytes.len() {
            let end = s_sent.saturating_add(chunk).min(s.bytes.len());
            let piece = s.bytes[s_sent..end].to_vec();
            s_sent = end;
            collect(client.process(Event::Received(&piece)), &mut c);
            moved = true;
        }
        if !moved {
            return (s, c);
        }
    }
}

/// A plaintext binary packet (RFC 4253 §6) around `payload`, padded to a multiple of 8.
pub fn plain_packet(payload: &[u8]) -> Vec<u8> {
    let mut pad = 8 - (4 + 1 + payload.len()) % 8;
    if pad < 4 {
        pad += 8;
    }
    let len = (1 + payload.len() + pad) as u32;
    let mut p = len.to_be_bytes().to_vec();
    p.push(pad as u8);
    p.extend_from_slice(payload);
    p.extend(std::iter::repeat_n(0u8, pad));
    p
}

/// Splits server output into its version line and the payloads of the plaintext packets after it.
pub fn plain_payloads(bytes: &[u8]) -> (String, Vec<Vec<u8>>) {
    let nl = bytes
        .iter()
        .position(|&b| b == b'\n')
        .expect("no version line");
    let version = String::from_utf8(bytes[..nl].to_vec()).unwrap();
    (version, split_plain(&bytes[nl + 1..]))
}

/// The payloads of consecutive plaintext packets.
pub fn split_plain(mut rest: &[u8]) -> Vec<Vec<u8>> {
    let mut payloads = Vec::new();
    while rest.len() >= 4 {
        let len = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
        let pad = rest[4] as usize;
        payloads.push(rest[5..4 + len - pad].to_vec());
        rest = &rest[4 + len..];
    }
    payloads
}

/// Runs a real server and client up to the server's `SSH_MSG_KEX_ECDH_REPLY`, lets `tamper`
/// change that reply, and returns what the client does with it.
pub fn client_given_reply(tamper: impl FnOnce(&mut justssh_wire::KexEcdhReply)) -> Out {
    let (mut server, mut client) = (server(), client());
    let (mut s, mut c) = (Out::default(), Out::default());
    collect(server.process(Event::Connected), &mut s);
    collect(client.process(Event::Connected), &mut c);
    collect(server.process(Event::Received(&c.bytes)), &mut s);
    let c_sent = c.bytes.len();
    collect(client.process(Event::Received(&s.bytes)), &mut c);
    let s_sent = s.bytes.len();
    collect(server.process(Event::Received(&c.bytes[c_sent..])), &mut s);

    let payloads = split_plain(&s.bytes[s_sent..]);
    let Message::KexEcdhReply(mut reply) = Message::decode(&payloads[0]).unwrap() else {
        panic!("server did not reply to ECDH_INIT");
    };
    tamper(&mut reply);
    let mut forged = plain_packet(&Message::KexEcdhReply(reply).encode());
    for p in &payloads[1..] {
        forged.extend(plain_packet(p));
    }
    let mut out = Out::default();
    collect(client.process(Event::Received(&forged)), &mut out);
    out
}

/// A client KEXINIT offering what the server supports, with `edit` applied.
pub fn client_kexinit(edit: impl FnOnce(&mut KexInit)) -> Vec<u8> {
    let mut k = KexInit::default();
    k.cookie = [3; 16];
    k.kex_algorithms = vec!["curve25519-sha256".into()];
    k.server_host_key_algorithms = vec!["ssh-ed25519".into()];
    k.encryption_algorithms_client_to_server = vec!["chacha20-poly1305@openssh.com".into()];
    k.encryption_algorithms_server_to_client = vec!["chacha20-poly1305@openssh.com".into()];
    k.compression_algorithms_client_to_server = vec!["none".into()];
    k.compression_algorithms_server_to_client = vec!["none".into()];
    edit(&mut k);
    Message::KexInit(k).encode()
}

pub const CLIENT_VERSION: &[u8] = b"SSH-2.0-test\r\n";

/// Starts a server and feeds it `input` in one piece.
pub fn feed_server(input: &[u8]) -> Out {
    let mut server = server();
    let mut out = Out::default();
    collect(server.process(Event::Connected), &mut out);
    collect(server.process(Event::Received(input)), &mut out);
    out
}
