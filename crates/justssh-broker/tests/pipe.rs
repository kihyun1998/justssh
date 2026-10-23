//! The broker binary over its stdin and stdout, as acwbroker's blackbox harness starts it
//! (`blackbox/harness_test.go` `startBroker`): `-listen 127.0.0.1:0 -logpath DIR -host-key FILE`.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use justssh_keys::KeyFile;

const HELLO: &str = "01000000040000000b020000001241435742524f4b45522050524f544f203131";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn rec(tag: u8, val: &[u8]) -> Vec<u8> {
    [&[tag][..], &(val.len() as u32).to_be_bytes(), val].concat()
}

fn records(mut p: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    while !p.is_empty() {
        let n = u32::from_be_bytes(p[1..5].try_into().unwrap()) as usize;
        out.push((p[0], p[5..5 + n].to_vec()));
        p = &p[5 + n..];
    }
    out
}

fn field(p: &[u8], tag: u8) -> Option<Vec<u8>> {
    records(p)
        .into_iter()
        .find(|(t, _)| *t == tag)
        .map(|(_, v)| v)
}

struct Broker {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
}

impl Broker {
    fn start(dir: &Path, host_key: &Path, listen: &str) -> Broker {
        let mut child = Command::new(env!("CARGO_BIN_EXE_justssh-broker"))
            .args(["-listen", listen, "-profile", "prod A", "-logpath"])
            .arg(dir)
            .arg("-host-key")
            .arg(host_key)
            .env("ACRA_HOME", dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        Broker {
            child,
            stdin,
            stdout,
        }
    }

    fn send_raw(&mut self, bytes: &[u8]) {
        self.stdin.as_mut().unwrap().write_all(bytes).unwrap();
    }

    fn send(&mut self, kind: u8, payload: &[u8]) {
        let frame = [&[kind][..], &(payload.len() as u32).to_be_bytes(), payload].concat();
        self.send_raw(&frame);
    }

    /// The next frame, or `None` when stdout ends first.
    fn next(&mut self) -> Option<(u8, Vec<u8>)> {
        let mut header = [0u8; 5];
        self.stdout.read_exact(&mut header).ok()?;
        let mut payload = vec![0; u32::from_be_bytes(header[1..].try_into().unwrap()) as usize];
        self.stdout.read_exact(&mut payload).unwrap();
        Some((header[0], payload))
    }

    fn close(&mut self) {
        self.stdin = None;
    }

    /// Closes stdin and waits; the exit code, and whether stdout held anything more.
    fn finish(mut self) -> (i32, Vec<u8>) {
        self.close();
        let mut rest = Vec::new();
        self.stdout.read_to_end(&mut rest).unwrap();
        (self.child.wait().unwrap().code().unwrap(), rest)
    }

    /// Completes the version exchange; the address and host key LISTENING announced.
    fn ready(&mut self) -> (String, Vec<u8>) {
        assert_eq!(self.next(), Some((1, unhex(HELLO))));
        self.send(1, &unhex(HELLO));
        let (kind, payload) = self.next().expect("no LISTENING");
        assert_eq!(kind, 4);
        let addr = String::from_utf8(field(&payload, 0x21).unwrap()).unwrap();
        (addr, field(&payload, 0x22).unwrap())
    }

    /// The reply to an ISSUE: `Ok(token)` or `Err(message)`.
    fn issue(&mut self, payload: &[u8]) -> Result<String, String> {
        self.send(2, payload);
        let (kind, reply) = self.next().expect("no reply to ISSUE");
        let text = |tag| String::from_utf8(field(&reply, tag).unwrap()).unwrap();
        match kind {
            3 => Ok(text(0x20)),
            5 => Err(text(0x30)),
            other => panic!("reply {other:#x}"),
        }
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("justssh-broker-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn password_issue(upstream: &[u8], extra: &[u8]) -> Vec<u8> {
    [
        rec(0x10, b"password"),
        rec(0x15, b"srv-7@10.0.0.9"),
        rec(0x16, upstream),
        extra.to_vec(),
        rec(0x11, b"real-secret"),
    ]
    .concat()
}

/// The ERROR the broker answers `frame` with after the version exchange, and its exit code.
fn ending(name: &str, frame: &[u8]) -> (Option<String>, i32) {
    let dir = scratch(name);
    let mut b = Broker::start(&dir, &dir.join("hostkey"), "127.0.0.1:0");
    b.ready();
    b.send_raw(frame);
    b.close();
    let reply = b.next().map(|(kind, p)| {
        assert_eq!(kind, 5, "{name}");
        String::from_utf8(field(&p, 0x30).unwrap()).unwrap()
    });
    let (code, rest) = b.finish();
    assert!(rest.is_empty(), "{name}: {rest:x?}");
    (reply, code)
}

#[test]
fn the_broker_announces_itself_and_hands_out_a_token_per_issue() {
    let dir = scratch("tokens");
    let key_path = dir.join("store").join("hostkey");
    let mut b = Broker::start(&dir, &key_path, "127.0.0.1:0");
    let (addr, host_key) = b.ready();

    let bound: std::net::SocketAddr = addr.parse().unwrap();
    assert!(bound.ip().is_loopback() && bound.port() != 0, "{addr}");
    std::net::TcpStream::connect(bound).expect("nothing listens where LISTENING said");
    let text = std::fs::read(&key_path).unwrap();
    assert!(text.starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----\n"));
    let file = KeyFile::from_openssh(&text, None).unwrap();
    assert_eq!(file.comment(), b"acwbroker");
    assert_eq!(file.private_key().plain_public_blob(), host_key);
    assert!(host_key.starts_with(b"\0\0\0\x0bssh-ed25519"));

    let first = b.issue(&password_issue(b"127.0.0.7:51201", &[])).unwrap();
    let second = b.issue(&password_issue(b"127.0.0.7:51201", &[])).unwrap();
    for token in [&first, &second] {
        assert!(
            token.len() == 32
                && token
                    .bytes()
                    .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')),
            "{token}"
        );
    }
    assert_ne!(first, second);

    assert_eq!(
        b.issue(&password_issue(b"10.0.0.9:22", &[])),
        Err("upstream is not a loopback address".into())
    );
    assert_eq!(
        b.issue(&password_issue(b"127.0.0.1", &[])),
        Err("credential refused".into())
    );
    assert_eq!(
        b.issue(&password_issue(b"127.0.0.1:22", &rec(0x18, b"\x02"))),
        Err("credential refused".into())
    );
    assert_eq!(
        b.issue(&password_issue(
            b"127.0.0.1:22",
            &rec(0x17, b"\x10\0\0\x04")
        )),
        Err("terminal to bind the token to was not found".into())
    );
    b.send(
        8,
        &[rec(0x20, first.as_bytes()), rec(0x51, b"\0\0\xbe\xef")].concat(),
    );
    assert_eq!(b.next(), Some((9, Vec::new())));
    for refused in [
        [
            rec(0x20, b"00112233445566778899aabbccddeeff"),
            rec(0x51, b"\0\0\xbe\xef"),
        ]
        .concat(),
        [
            rec(0x20, second.as_bytes()),
            rec(0x50, dir.join("x").to_str().unwrap().as_bytes()),
        ]
        .concat(),
    ] {
        b.send(8, &refused);
        let (kind, reply) = b.next().unwrap();
        assert_eq!(
            (kind, field(&reply, 0x30)),
            (5, Some(b"attach refused".to_vec()))
        );
    }
    assert!(b.issue(&password_issue(b"127.0.0.7:51201", &[])).is_ok());

    assert_eq!(b.finish(), (0, Vec::new()));
    let log = std::fs::read_to_string(dir.join("acwbroker.log")).unwrap();
    for want in [
        r#"level=WARN msg="terminal binding refused" profile="prod A" terminal=268435460 err="peer: terminal binding is not implemented on this platform""#,
        r#"level=WARN msg="attach refused" profile="prod A" err="acwbroker: no live token matches the presented password""#,
        r#"level=WARN msg="attach refused" profile="prod A" err="acwbroker: the path is not directly under an attach root""#,
    ] {
        assert!(
            log.contains(want),
            "{want}
not in
{log}"
        );
    }
    for secret in ["real-secret", &first, &second] {
        assert!(
            !log.contains(secret),
            "{secret} in
{log}"
        );
    }
}

#[test]
fn a_second_start_serves_the_host_key_the_first_one_made() {
    let dir = scratch("restart");
    let key_path = dir.join("hostkey");
    let mut first = Broker::start(&dir, &key_path, "127.0.0.1:0");
    let (_, key) = first.ready();
    first.finish();
    let made = std::fs::read(&key_path).unwrap();
    let mut second = Broker::start(&dir, &key_path, "127.0.0.1:0");
    assert_eq!(second.ready().1, key);
    second.finish();
    assert_eq!(std::fs::read(&key_path).unwrap(), made);
    let mut left: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    left.sort();
    assert_eq!(left, ["acwbroker.log", "hostkey"]);
}

#[test]
fn without_a_host_key_flag_the_key_lives_under_acra_home() {
    let dir = scratch("acrahome");
    let mut b = Command::new(env!("CARGO_BIN_EXE_justssh-broker"))
        .args(["-listen", "127.0.0.1:0"])
        .env("ACRA_HOME", &dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut broker = Broker {
        stdin: b.stdin.take(),
        stdout: b.stdout.take().unwrap(),
        child: b,
    };
    let (_, key) = broker.ready();
    broker.finish();
    let text = std::fs::read(dir.join(".store").join("acwbroker").join("hostkey")).unwrap();
    let file = KeyFile::from_openssh(&text, None).unwrap();
    assert_eq!(file.private_key().plain_public_blob(), key);
}

#[test]
fn the_version_exchange_refuses_anything_but_an_echo_of_version_11() {
    let cases: [(&str, Vec<u8>, Option<&str>); 5] = [
        (
            "v10",
            [&[1, 0, 0, 0, 9][..], &rec(1, &10u32.to_be_bytes())].concat(),
            Some("protocol version mismatch"),
        ),
        (
            "issue first",
            [&[2, 0, 0, 0, 0][..]].concat(),
            Some("expected a version echo"),
        ),
        (
            "no version",
            [&[1, 0, 0, 0, 5][..], &rec(2, b"")].concat(),
            Some("malformed version echo"),
        ),
        ("cut", vec![1, 0, 0], None),
        ("nothing", Vec::new(), None),
    ];
    for (name, frame, expected) in cases {
        let dir = scratch("hello");
        let mut b = Broker::start(&dir, &dir.join("hostkey"), "127.0.0.1:0");
        assert_eq!(b.next(), Some((1, unhex(HELLO))));
        b.send_raw(&frame);
        b.close();
        let reply = b.next().map(|(kind, p)| {
            assert_eq!(kind, 5, "{name}");
            String::from_utf8(field(&p, 0x30).unwrap()).unwrap()
        });
        assert_eq!(reply.as_deref(), expected, "{name}");
        let (code, rest) = b.finish();
        assert_eq!((code, rest), (1, Vec::new()), "{name}");
        assert!(
            !dir.join("hostkey").exists(),
            "{name}: a key was made before the version settled"
        );
    }
}

#[test]
fn what_the_session_cannot_go_on_from_ends_it_as_acwbroker_ends_it() {
    let frame = |kind: u8, payload: &[u8]| {
        [&[kind][..], &(payload.len() as u32).to_be_bytes(), payload].concat()
    };
    let unparsable = [password_issue(b"127.0.0.1:22", &[]), rec(0x11, b"x")].concat();
    let cases: [(&str, Vec<u8>, Option<&str>); 9] = [
        (
            "malformed issue",
            frame(2, &unparsable),
            Some("malformed credential"),
        ),
        ("revoke", frame(6, &[]), Some("unknown frame kind")),
        (
            "hello again",
            frame(1, &unhex(HELLO)),
            Some("unknown frame kind"),
        ),
        ("token", frame(3, &[]), Some("unknown frame kind")),
        (
            "freeze of no process",
            frame(7, &rec(0x40, b"\xff\xff\xff\xfc")),
            Some("tunnel could not be watched"),
        ),
        (
            "bad freeze",
            frame(7, &rec(0x40, b"\0\0\0\0")),
            Some("malformed freeze"),
        ),
        (
            "bad attach",
            frame(8, &rec(0x50, b"C:\\x")),
            Some("malformed attach"),
        ),
        ("over 1 MiB", vec![2, 0, 0x10, 0, 1], None),
        ("cut frame", vec![2, 0, 0, 0, 9, 1, 2], None),
    ];
    for (name, bytes, expected) in cases {
        let (reply, code) = ending(name, &bytes);
        assert_eq!((reply.as_deref(), code), (expected, 1), "{name}");
    }
}

#[test]
fn a_listen_address_or_host_key_that_cannot_be_used_is_reported_before_exiting() {
    for (name, listen, key) in [
        ("not loopback", "10.0.0.9:0", None),
        ("bindable, not loopback", "0.0.0.0:0", None),
        ("no port", "127.0.0.1", None),
        ("unusable key", "127.0.0.1:0", Some(&b"not a key"[..])),
    ] {
        let dir = scratch("unusable");
        let key_path = dir.join("hostkey");
        if let Some(text) = key {
            std::fs::write(&key_path, text).unwrap();
        }
        let mut b = Broker::start(&dir, &key_path, listen);
        assert_eq!(b.next(), Some((1, unhex(HELLO))));
        b.send(1, &unhex(HELLO));
        let (kind, payload) = b.next().expect(name);
        let expected: &[u8] = if key.is_some() {
            b"host key unavailable"
        } else {
            b"listener unavailable"
        };
        assert_eq!(
            (kind, field(&payload, 0x30).as_deref()),
            (5, Some(expected)),
            "{name}"
        );
        assert_eq!(b.finish(), (1, Vec::new()), "{name}");
    }
}

/// A frozen broker refuses ISSUE, outlives the pipe and ends when the tunnel it watches does
/// (acwbroker `cmd/acwbroker/freeze_test.go`). Windows only: elsewhere no process is watched.
#[cfg(windows)]
#[test]
fn a_frozen_broker_outlives_the_pipe_and_ends_with_its_tunnel() {
    let dir = scratch("freeze");
    let mut tunnel = Command::new("cmd")
        .args(["/c", "ping -n 30 127.0.0.1 >nul"])
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let mut b = Broker::start(&dir, &dir.join("hostkey"), "127.0.0.1:0");
    let (addr, _) = b.ready();
    b.send(7, &rec(0x40, &tunnel.id().to_be_bytes()));
    assert_eq!(
        b.issue(&password_issue(b"127.0.0.7:51201", &[])),
        Err("frozen".into())
    );
    b.send(7, &rec(0x40, b"\0\0\0\0"));
    assert_eq!(
        b.issue(&password_issue(b"127.0.0.7:51201", &[])),
        Err("frozen".into()),
        "a second FREEZE is not read"
    );
    b.close();
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert!(
        b.child.try_wait().unwrap().is_none(),
        "the broker ended with the pipe"
    );
    assert!(
        std::net::TcpStream::connect(&addr).is_err(),
        "the listener is still open"
    );
    tunnel.kill().unwrap();
    tunnel.wait().unwrap();
    assert_eq!(b.finish(), (0, Vec::new()));
    let log = std::fs::read_to_string(dir.join("acwbroker.log")).unwrap();
    let frozen = format!(
        r#"msg="frozen: no new connections; staying until the tunnel exits" profile="prod A" tunnel={}"#,
        tunnel.id()
    );
    for want in [
        frozen.as_str(),
        r#"msg="the app has let go; staying until the tunnel exits" profile="prod A""#,
        r#"msg="the tunnel exited; shutting down" profile="prod A""#,
    ] {
        assert!(
            log.contains(want),
            "{want}
not in
{log}"
        );
    }
}
