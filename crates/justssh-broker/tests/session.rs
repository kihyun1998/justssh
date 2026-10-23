//! The handoff session in process, with what it asks of the broker faked (acwbroker
//! `internal/infrastructure/handoff` freeze, attach and claimed tests).

use std::io::{Cursor, Write};
use std::sync::{Arc, Mutex};

use justssh_broker::handoff::{self, Kind};
use justssh_broker::session::{Hooks, Session};
use justssh_broker::tokens::{Config, Tokens};

fn rec(tag: u8, val: &[u8]) -> Vec<u8> {
    [&[tag][..], &(val.len() as u32).to_be_bytes(), val].concat()
}

fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    [&[kind][..], &(payload.len() as u32).to_be_bytes(), payload].concat()
}

fn issue() -> Vec<u8> {
    frame(
        2,
        &[
            rec(0x10, b"password"),
            rec(0x15, b"srv-7@10.0.0.9"),
            rec(0x16, b"127.0.0.7:51201"),
            rec(0x11, b"real-secret"),
        ]
        .concat(),
    )
}

fn freeze(pid: &[u8]) -> Vec<u8> {
    frame(7, &rec(0x40, pid))
}

fn attach(token: &str, path: Option<&str>, pid: Option<u32>) -> Vec<u8> {
    let mut p = rec(0x20, token.as_bytes());
    if let Some(path) = path {
        p.extend(rec(0x50, path.as_bytes()));
    }
    if let Some(pid) = pid {
        p.extend(rec(0x51, &pid.to_be_bytes()));
    }
    frame(8, &p)
}

/// What the session wrote, shared with the test.
#[derive(Clone, Default)]
struct Out(Arc<Mutex<Vec<u8>>>);

impl Write for Out {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = buf.len().min(3);
        self.0.lock().unwrap().extend_from_slice(&buf[..n]);
        std::thread::yield_now();
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Out {
    /// Every frame written after HELLO: its kind, its message if an ERROR, its payload.
    fn frames(&self) -> Vec<(u8, Option<String>, Vec<u8>)> {
        let bytes = self.0.lock().unwrap().clone();
        let mut r = Cursor::new(bytes);
        let mut out = Vec::new();
        while let Ok(f) = handoff::read_frame(&mut r) {
            let msg = (f.kind == Kind::Error as u8).then(|| {
                let rs = f.payload[5..].to_vec();
                String::from_utf8(rs).unwrap()
            });
            out.push((f.kind, msg, f.payload.to_vec()));
        }
        out.remove(0);
        out
    }
}

struct Closed;

impl Write for Closed {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Freezes as told and admits paths as told, recording what it was asked.
#[derive(Default)]
struct Fake {
    frozen: Vec<u32>,
    unwatchable: bool,
    outside: bool,
}

impl Hooks for Fake {
    fn freeze(&mut self, tunnel: u32) -> Result<(), String> {
        self.frozen.push(tunnel);
        match self.unwatchable {
            true => Err("no such process".to_owned()),
            false => Ok(()),
        }
    }

    fn admit(&self, _path: &str) -> Result<(), String> {
        match self.outside {
            true => Err("outside the roots".to_owned()),
            false => Ok(()),
        }
    }
}

/// Runs a session over `input` after the version exchange; whether it ended cleanly, whether
/// it froze, and what it wrote.
fn run(
    runtime: &tokio::runtime::Runtime,
    tokens: &Tokens,
    hooks: &mut Fake,
    input: &[Vec<u8>],
) -> (bool, bool, Out) {
    let hello = frame(1, &handoff::hello(handoff::VERSION));
    let bytes = [&[hello][..], input].concat().concat();
    let out = Out::default();
    let mut s = Session::new(Cursor::new(bytes), out.clone());
    s.handshake().unwrap();
    let _entered = runtime.enter();
    let ended = s.serve(tokens, hooks).is_ok();
    (ended, s.frozen(), out)
}

fn setup() -> (tokio::runtime::Runtime, Tokens) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let tokens = Tokens::new(Config::default(), runtime.handle().clone());
    (runtime, tokens)
}

#[test]
fn after_a_freeze_an_issue_is_refused_a_second_freeze_is_not_read_and_the_session_goes_on() {
    let (rt, tokens) = setup();
    let mut hooks = Fake::default();
    let (clean, frozen, out) = run(
        &rt,
        &tokens,
        &mut hooks,
        &[freeze(b"\0\0\xbe\xef"), issue(), freeze(b""), issue()],
    );
    assert!(clean && frozen);
    assert_eq!(hooks.frozen, [48879]);
    assert_eq!(tokens.len(), 0);
    let kinds: Vec<_> = out.frames().into_iter().map(|(k, m, _)| (k, m)).collect();
    assert_eq!(
        kinds,
        [
            (5, Some("frozen".to_owned())),
            (5, Some("frozen".to_owned()))
        ]
    );
}

#[test]
fn a_freeze_that_cannot_be_honoured_ends_the_session_unfrozen() {
    let (rt, tokens) = setup();
    let mut hooks = Fake {
        unwatchable: true,
        ..Fake::default()
    };
    let (clean, frozen, out) = run(
        &rt,
        &tokens,
        &mut hooks,
        &[freeze(b"\0\0\xbe\xef"), issue()],
    );
    assert!(!clean && !frozen);
    let kinds: Vec<_> = out.frames().into_iter().map(|(k, m, _)| (k, m)).collect();
    assert_eq!(kinds, [(5, Some("tunnel could not be watched".to_owned()))]);
}

#[test]
fn a_malformed_freeze_ends_the_session_without_asking() {
    let (rt, tokens) = setup();
    let mut hooks = Fake::default();
    let (clean, _, out) = run(&rt, &tokens, &mut hooks, &[frame(7, b"")]);
    assert!(!clean && hooks.frozen.is_empty());
    assert_eq!(out.frames()[0].1.as_deref(), Some("malformed freeze"));
}

#[test]
fn an_attach_is_answered_with_whether_the_token_was_used() {
    let (rt, tokens) = setup();
    let _entered = rt.enter();
    let unused = tokens.issue(issue_payload());
    let used = tokens.issue(issue_payload());
    let mut caller = justssh_broker::caller::Caller::new(9);
    caller.ancestry = vec![9];
    let _open = tokens
        .authorize(used.as_bytes(), b"srv-7@10.0.0.9", &caller)
        .unwrap();
    let mut hooks = Fake::default();
    let (clean, _, out) = run(
        &rt,
        &tokens,
        &mut hooks,
        &[
            attach(&unused, Some(r"C:\cache\5f1c"), None),
            attach(&used, None, Some(48879)),
        ],
    );
    assert!(clean);
    let frames: Vec<_> = out.frames().into_iter().map(|(k, _, p)| (k, p)).collect();
    assert_eq!(frames, [(9, vec![]), (9, rec(0x52, &[1]))]);
}

fn issue_payload() -> justssh_broker::issue::Issue {
    justssh_broker::issue::decode(&issue()[5..]).unwrap()
}

#[test]
fn a_refused_attach_is_an_error_and_the_session_goes_on() {
    let (rt, tokens) = setup();
    let _entered = rt.enter();
    let token = tokens.issue(issue_payload());
    for (outside, attached) in [
        (true, attach(&token, Some(r"C:\cache\5f1c"), None)),
        (
            false,
            attach("00112233445566778899aabbccddeeff", None, Some(1)),
        ),
    ] {
        let mut hooks = Fake {
            outside,
            ..Fake::default()
        };
        let (clean, _, out) = run(&rt, &tokens, &mut hooks, &[attached, issue()]);
        assert!(clean);
        let kinds: Vec<_> = out.frames().into_iter().map(|(k, m, _)| (k, m)).collect();
        assert_eq!(kinds, [(5, Some("attach refused".to_owned())), (3, None)]);
    }
}

#[test]
fn a_malformed_attach_ends_the_session() {
    let (rt, tokens) = setup();
    let mut hooks = Fake::default();
    let (clean, _, out) = run(&rt, &tokens, &mut hooks, &[attach("abc", None, None)]);
    assert!(!clean);
    assert_eq!(out.frames()[0].1.as_deref(), Some("malformed attach"));
}

#[test]
fn claimed_and_disposed_are_written_whole_from_many_threads_and_dropped_on_a_closed_pipe() {
    let out = Out::default();
    let s: Session<Cursor<Vec<u8>>, Out> = Session::new(Cursor::new(Vec::new()), out.clone());
    let pipe = s.pipe();
    let threads: Vec<_> = (1..=200u32)
        .map(|i| {
            let pipe = pipe.clone();
            std::thread::spawn(move || {
                pipe.claimed(i);
                pipe.disposed(i);
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let bytes = out.0.lock().unwrap().clone();
    let mut r = Cursor::new(bytes);
    let mut seen = Vec::new();
    while let Ok(f) = handoff::read_frame(&mut r) {
        assert_eq!(&f.payload[..5], &[0x51, 0, 0, 0, 4]);
        seen.push((
            f.kind,
            u32::from_be_bytes(f.payload[5..].try_into().unwrap()),
        ));
    }
    seen.sort();
    let mut want: Vec<_> = (1..=200u32).flat_map(|i| [(0x0a, i), (0x0b, i)]).collect();
    want.sort();
    assert_eq!(seen, want);

    let closed = Session::new(Cursor::new(Vec::new()), Closed);
    closed.pipe().claimed(1);
    closed.pipe().disposed(1);
}
