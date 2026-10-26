//! The broker's SSH side in process: a justssh client downstream, the broker in the middle, and
//! a justssh server upstream standing in for acwbroker's test upstream (`internal/testutil`):
//! `exec` answers `out:<cmd>` on stdout, `err:<cmd>` on stderr and exit status 7; `shell` echoes
//! until EOF.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use justssh::requests::{Exec, ExitStatus, Subsystem};
use justssh::{
    Action, ChannelId, Client, ClientConfig, HostKey, InfoRequest, OpenFailureReason, Server,
    ServerConfig, Zeroizing,
};
use justssh_broker::caller::Caller;
use justssh_broker::log::Log;
use justssh_broker::tokens::{Config, Tokens};
use justssh_broker::{broker, issue};
use justssh_tokio::{Accepted, AuthMethod, ClientHandler, Connected, Deadlines, Session};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(30);
/// The process every downstream connection measures as owned by.
const CALLER: u32 = 4242;
const USER: &[u8] = b"srv-7@10.0.0.9";
const SECRET: &[u8] = b"real-secret";
/// What the upstream refuses a channel type other than `session` with: not UTF-8.
const REFUSAL: &[u8] = b"no \x80 such type";

struct AcceptAll;

impl ClientHandler for AcceptAll {
    async fn check_host_key(&mut self, _key: &[u8]) -> bool {
        true
    }

    async fn answer(&mut self, _request: &InfoRequest) -> Vec<Zeroizing<Vec<u8>>> {
        Vec::new()
    }
}

fn rec(tag: u8, val: &[u8]) -> Vec<u8> {
    [&[tag][..], &(val.len() as u32).to_be_bytes(), val].concat()
}

/// The channel requests that reached the upstream, by kind and data, across its connections.
type Seen = Arc<Mutex<Vec<(Vec<u8>, Vec<u8>)>>>;

/// The test upstream, serving connections until the test ends.
async fn upstream() -> String {
    upstream_seeing().await.0
}

/// The test upstream and the channel requests that reach it.
async fn upstream_seeing() -> (String, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let seen = Seen::default();
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(upstream_connection(stream, log.clone()));
        }
    });
    (addr, seen)
}

async fn upstream_connection(stream: TcpStream, seen: Seen) {
    let mut server = Server::new(
        ServerConfig::builder(HostKey::ed25519_from_seed(Zeroizing::new([9; 32]))).build(),
    );
    let Ok(Accepted::Authenticated { io, events, .. }) =
        justssh_tokio::accept(stream, &mut server, &Deadlines::new(), |r| {
            let ok = r.user() == USER && r.password() == SECRET;
            async move { ok.then_some(()) }
        })
        .await
    else {
        return;
    };
    let mut s = Session::new(io, server, events);
    let mut shell: Option<ChannelId> = None;
    // The exec channel waiting to be told how a channel this side opened was answered.
    let mut reporting: Option<ChannelId> = None;
    while let Ok(Some(action)) = s.next().await {
        if let Action::ChannelRequest(r) = &action {
            seen.lock()
                .unwrap()
                .push((r.kind().as_bytes().to_vec(), r.data().to_vec()));
        }
        match action {
            Action::ChannelRequest(r)
                if r.kind() == "exec"
                    && Exec::decode(r.data()).unwrap().command() == b"open-back" =>
            {
                if let Some(token) = r.reply() {
                    s.reply(token, true).await.unwrap();
                }
                reporting = Some(r.channel());
                s.open_channel("x11", Vec::new()).await.unwrap();
            }
            Action::ChannelOpenFailed {
                reason,
                description,
                ..
            } => {
                let ch = reporting.take().unwrap();
                let report = [
                    format!("refused {} ", reason.code()).as_bytes(),
                    &description,
                ]
                .concat();
                s.queue_data(ch, &report).await.unwrap();
                s.close(ch).await.unwrap();
            }
            Action::GlobalRequest(r) => {
                if let Some(token) = r.reply() {
                    s.reply_global(token, true, [b"pong:", r.kind().as_bytes()].concat())
                        .await
                        .unwrap();
                }
            }
            Action::ChannelOpenRequest(r) if r.kind() == "session" => {
                s.accept_channel(r.channel(), Vec::new()).await.unwrap()
            }
            Action::ChannelOpenRequest(r) => s
                .reject_channel(
                    r.channel(),
                    OpenFailureReason::ADMINISTRATIVELY_PROHIBITED,
                    REFUSAL,
                )
                .await
                .unwrap(),
            Action::ChannelRequest(r) if r.kind() == "exec" => {
                let cmd = Exec::decode(r.data()).unwrap().command().to_vec();
                if let Some(token) = r.reply() {
                    s.reply(token, true).await.unwrap();
                }
                let ch = r.channel();
                s.queue_data(ch, &[b"out:", &cmd[..]].concat())
                    .await
                    .unwrap();
                s.queue_extended_data(ch, 1, &[b"err:", &cmd[..]].concat())
                    .await
                    .unwrap();
                s.request(ch, ExitStatus::KIND, false, ExitStatus::new(7).encode())
                    .await
                    .unwrap();
                s.close(ch).await.unwrap();
            }
            Action::ChannelRequest(r) => {
                if r.kind() == "shell" {
                    shell = Some(r.channel());
                }
                if let Some(token) = r.reply() {
                    s.reply(token, true).await.unwrap();
                }
            }
            Action::ChannelData { channel, data } if Some(channel) == shell => {
                s.queue_data(channel, &data).await.unwrap();
                s.consumed(channel, data.len() as u32).await.unwrap();
            }
            Action::ChannelEof { channel } if Some(channel) == shell => {
                s.request(
                    channel,
                    ExitStatus::KIND,
                    false,
                    ExitStatus::new(0).encode(),
                )
                .await
                .unwrap();
                s.close(channel).await.unwrap();
            }
            _ => {}
        }
    }
}

/// Tokens judged by acwbroker's defaults, with nothing asked of this machine.
fn tokens() -> Tokens {
    Tokens::new(Config::default(), tokio::runtime::Handle::current())
}

/// The broker serving `tokens` to callers that all measure as [`CALLER`]; its address.
async fn broker(tokens: Tokens) -> String {
    broker_logging(tokens, Log::discard()).await
}

/// [`broker`] logging to `log`.
async fn broker_logging(tokens: Tokens, log: Log) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let host_key = HostKey::ed25519_from_seed(Zeroizing::new([7; 32]));
    tokio::spawn(broker::serve(
        listener,
        justssh_broker::hostkey::HostKeys::new(host_key),
        tokens,
        Duration::from_secs(15),
        Arc::new(|_| {
            let mut c = Caller::new(CALLER);
            c.described = "pid=4242 image=putty.exe".to_owned();
            c
        }),
        log,
    ));
    addr
}

/// The lines a log has written, shared with the test.
#[derive(Clone, Default)]
struct Lines(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Lines {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Lines {
    fn log(&self) -> Log {
        Log::clocked(self.clone(), None, || {
            (std::time::SystemTime::UNIX_EPOCH, 0)
        })
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }

    /// Waits until a line holds `part`, and returns everything written by then.
    async fn wait_for(&self, part: &str) -> String {
        for _ in 0..500 {
            let text = self.text();
            if text.contains(part) {
                return text;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("no line holds {part:?}:\n{}", self.text());
    }
}

/// A token for a password credential to `upstream`.
fn issue(tokens: &Tokens, upstream: &str) -> Zeroizing<String> {
    issue_with(tokens, upstream, SECRET)
}

/// A token for a password credential `password` to `upstream`.
fn issue_with(tokens: &Tokens, upstream: &str, password: &[u8]) -> Zeroizing<String> {
    let payload = [
        rec(0x10, b"password"),
        rec(0x15, USER),
        rec(0x16, upstream.as_bytes()),
        rec(0x11, password),
    ]
    .concat();
    tokens.issue(issue::decode(&payload).unwrap())
}

/// A token for a password credential to `upstream` whose connections may not transfer files.
fn issue_without_file_transfer(tokens: &Tokens, upstream: &str) -> Zeroizing<String> {
    let payload = [
        rec(0x10, b"password"),
        rec(0x15, USER),
        rec(0x16, upstream.as_bytes()),
        rec(0x11, SECRET),
        rec(0x18, &[1]),
    ]
    .concat();
    tokens.issue(issue::decode(&payload).unwrap())
}

async fn downstream(addr: &str, token: &[u8]) -> Option<Session<TcpStream, Client>> {
    downstream_as(addr, USER, token).await
}

async fn downstream_as(
    addr: &str,
    user: &[u8],
    token: &[u8],
) -> Option<Session<TcpStream, Client>> {
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut client = Client::new(ClientConfig::builder(user).build());
    match justssh_tokio::connect(
        stream,
        &mut client,
        &Deadlines::new(),
        &[AuthMethod::Password(Zeroizing::new(token.to_vec()))],
        &mut AcceptAll,
    )
    .await
    .unwrap()
    {
        Connected::Authenticated { io, events } => Some(Session::new(io, client, events)),
        _ => None,
    }
}

/// What a channel brought until it closed.
#[derive(Debug, Default, PartialEq)]
struct Outcome {
    replied: Option<bool>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit: Option<Vec<u8>>,
    eof: bool,
}

/// Opens a session channel, sends `request`, `input` and EOF, and reads until it closes.
async fn run(
    s: &mut Session<TcpStream, Client>,
    request: (&str, Vec<u8>),
    input: &[u8],
) -> Outcome {
    let ch = s
        .open_channel("session", Vec::new())
        .await
        .unwrap()
        .unwrap();
    let mut out = Outcome::default();
    loop {
        match s.next().await.unwrap() {
            Some(Action::ChannelOpened { .. }) => {
                s.request(ch, request.0, true, request.1.clone())
                    .await
                    .unwrap();
                if !input.is_empty() {
                    s.queue_data(ch, input).await.unwrap();
                }
                s.eof(ch).await.unwrap();
            }
            Some(Action::ChannelRequestReply { ok, .. }) => out.replied = Some(ok),
            Some(Action::ChannelData { data, .. }) => {
                s.consumed(ch, data.len() as u32).await.unwrap();
                out.stdout.extend(data);
            }
            Some(Action::ChannelExtendedData { data, .. }) => {
                s.consumed(ch, data.len() as u32).await.unwrap();
                out.stderr.extend(data);
            }
            Some(Action::ChannelRequest(r)) if r.kind() == ExitStatus::KIND => {
                out.exit = Some(r.data().to_vec());
            }
            Some(Action::ChannelEof { .. }) => out.eof = true,
            Some(Action::ChannelClosed { .. }) => return out,
            Some(Action::Closed(c)) => panic!("{c:?}"),
            None => panic!("ended"),
            Some(_) => {}
        }
    }
}

#[tokio::test]
async fn an_exec_through_the_broker_brings_stdout_stderr_and_the_exit_status() {
    let tokens = tokens();
    let token = issue(&tokens, &upstream().await);
    let addr = broker(tokens).await;
    let mut s = downstream(&addr, token.as_bytes()).await.expect("refused");
    let out = timeout(
        LIMIT,
        run(
            &mut s,
            ("exec", Exec::new(b"whoami".to_vec()).encode()),
            b"",
        ),
    )
    .await
    .expect("the channel never closed");
    assert_eq!(
        out,
        Outcome {
            replied: Some(true),
            stdout: b"out:whoami".to_vec(),
            stderr: b"err:whoami".to_vec(),
            exit: Some(ExitStatus::new(7).encode()),
            eof: true,
        }
    );
}

#[tokio::test]
async fn a_shell_through_the_broker_echoes_and_ends_on_eof() {
    let tokens = tokens();
    let token = issue(&tokens, &upstream().await);
    let addr = broker(tokens).await;
    let mut s = downstream(&addr, token.as_bytes()).await.expect("refused");
    let started = std::time::Instant::now();
    let out = timeout(LIMIT, run(&mut s, ("shell", Vec::new()), b"hello-shell\n"))
        .await
        .expect("the channel never closed");
    assert_eq!(out.replied, Some(true));
    assert_eq!(out.stdout, b"hello-shell\n");
    assert_eq!(out.exit, Some(ExitStatus::new(0).encode()));
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_wrong_token_is_refused() {
    let tokens = tokens();
    let _ = issue(&tokens, &upstream().await);
    let addr = broker(tokens).await;
    assert!(downstream(&addr, &[b'a'; 32]).await.is_none());
}

#[tokio::test]
async fn a_channel_the_upstream_refuses_is_refused_downstream_with_its_reason_and_message() {
    let tokens = tokens();
    let token = issue(&tokens, &upstream().await);
    let addr = broker(tokens).await;
    let mut s = downstream(&addr, token.as_bytes()).await.expect("refused");
    let ch = s
        .open_channel("no-such-type@justssh", Vec::new())
        .await
        .unwrap();
    let refused = timeout(LIMIT, async {
        loop {
            if let Some(Action::ChannelOpenFailed {
                channel,
                reason,
                description,
            }) = s.next().await.unwrap()
            {
                return (Some(channel), reason, description);
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        refused,
        (
            ch,
            OpenFailureReason::ADMINISTRATIVELY_PROHIBITED,
            REFUSAL.to_vec()
        )
    );
}

#[tokio::test]
async fn a_channel_the_upstream_opens_is_refused_as_prohibited() {
    let tokens = tokens();
    let token = issue(&tokens, &upstream().await);
    let addr = broker(tokens).await;
    let mut s = downstream(&addr, token.as_bytes()).await.expect("refused");
    let out = timeout(
        LIMIT,
        run(
            &mut s,
            ("exec", Exec::new(b"open-back".to_vec()).encode()),
            b"",
        ),
    )
    .await
    .expect("the channel never closed");
    assert_eq!(
        out.stdout,
        b"refused 1 acwbroker does not accept upstream-initiated channels"
    );
}

#[tokio::test]
async fn a_global_request_goes_upstream_and_its_answer_comes_back() {
    let tokens = tokens();
    let token = issue(&tokens, &upstream().await);
    let addr = broker(tokens).await;
    let mut s = downstream(&addr, token.as_bytes()).await.expect("refused");
    let sent = s
        .global_request("probe@justssh", true, b"x".to_vec())
        .await
        .unwrap();
    let reply = timeout(LIMIT, async {
        loop {
            if let Some(Action::GlobalRequestReply { token, ok, data }) = s.next().await.unwrap() {
                return (Some(token), ok, data);
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(reply, (sent, true, b"pong:probe@justssh".to_vec()));
}

#[tokio::test]
async fn an_upstream_that_refuses_the_credential_fails_the_downstream_authentication() {
    let tokens = tokens();
    let token = issue_with(&tokens, &upstream().await, b"not-the-secret");
    let addr = broker(tokens).await;
    assert!(downstream(&addr, token.as_bytes()).await.is_none());
}

#[tokio::test]
async fn a_token_presented_by_another_user_is_refused() {
    let tokens = tokens();
    let token = issue(&tokens, &upstream().await);
    let addr = broker(tokens).await;
    assert!(
        downstream_as(&addr, b"someone-else", token.as_bytes())
            .await
            .is_none()
    );
}

/// Opens a session channel and waits for it to be confirmed.
async fn open(s: &mut Session<TcpStream, Client>) -> ChannelId {
    let ch = s
        .open_channel("session", Vec::new())
        .await
        .unwrap()
        .unwrap();
    loop {
        match s.next().await.unwrap() {
            Some(Action::ChannelOpened { channel, .. }) if channel == ch => return ch,
            Some(Action::Closed(c)) => panic!("{c:?}"),
            None => panic!("ended"),
            Some(_) => {}
        }
    }
}

/// Sends `kind` with `data` on `ch` and waits for the reply. A refused request's channel is
/// waited for until it closes, which it must.
async fn ask(s: &mut Session<TcpStream, Client>, ch: ChannelId, kind: &str, data: Vec<u8>) -> bool {
    s.request(ch, kind, true, data).await.unwrap();
    let ok = loop {
        match s.next().await.unwrap() {
            Some(Action::ChannelRequestReply { ok, .. }) => break ok,
            Some(Action::Closed(c)) => panic!("{c:?}"),
            None => panic!("ended"),
            Some(_) => {}
        }
    };
    if !ok {
        timeout(Duration::from_secs(2), closed(s, ch))
            .await
            .expect("the refused channel stayed open");
    }
    ok
}

/// Waits for `ch` to close.
async fn closed(s: &mut Session<TcpStream, Client>, ch: ChannelId) {
    loop {
        match s.next().await.unwrap() {
            Some(Action::ChannelClosed { channel }) if channel == ch => return,
            Some(Action::ChannelData { channel, data }) => {
                s.consumed(channel, data.len() as u32).await.unwrap()
            }
            Some(Action::Closed(c)) => panic!("{c:?}"),
            None => panic!("ended"),
            Some(_) => {}
        }
    }
}

/// Writes `line` to the shell on `ch` and reads its echo.
async fn echo(s: &mut Session<TcpStream, Client>, ch: ChannelId, line: &[u8]) -> Vec<u8> {
    s.queue_data(ch, line).await.unwrap();
    let mut got = Vec::new();
    while got.len() < line.len() {
        match s.next().await.unwrap() {
            Some(Action::ChannelData { channel, data }) if channel == ch => {
                s.consumed(ch, data.len() as u32).await.unwrap();
                got.extend(data);
            }
            Some(Action::ChannelClosed { channel }) if channel == ch => break,
            Some(Action::Closed(c)) => panic!("{c:?}"),
            None => panic!("ended"),
            Some(_) => {}
        }
    }
    got
}

/// Runs `command` on a channel of its own to its close, so that everything sent upstream
/// before it on this connection has been seen there.
async fn settle(s: &mut Session<TcpStream, Client>, command: &[u8]) -> Outcome {
    run(s, ("exec", exec(command)), b"").await
}

fn sftp() -> Vec<u8> {
    Subsystem::new(b"sftp".to_vec()).encode()
}

fn exec(command: &[u8]) -> Vec<u8> {
    Exec::new(command.to_vec()).encode()
}

/// How many requests of `kind` reached the upstream.
fn count(seen: &Seen, kind: &[u8]) -> usize {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|(k, _)| k == kind)
        .count()
}

#[tokio::test]
async fn a_token_without_file_transfer_refuses_sftp_and_scp_and_keeps_the_shell() {
    let tokens = tokens();
    let (up, seen) = upstream_seeing().await;
    let token = issue_without_file_transfer(&tokens, &up);
    let addr = broker(tokens).await;
    let mut s = downstream(&addr, token.as_bytes()).await.expect("refused");
    timeout(LIMIT, async {
        let shell = open(&mut s).await;
        assert!(ask(&mut s, shell, "shell", Vec::new()).await);
        for (kind, data) in [
            ("subsystem", sftp()),
            ("exec", exec(b"scp -t /tmp")),
            ("exec", exec(b"/usr/bin/scp -f x")),
            ("exec", exec(b"scp/ -t")),
            ("exec", exec(" \u{3000}sftp-server".as_bytes())),
            ("exec", exec(b"/usr/lib/openssh/sftp-server/")),
        ] {
            let ch = open(&mut s).await;
            assert!(
                !ask(&mut s, ch, kind, data.clone()).await,
                "{kind} {data:?} was allowed"
            );
        }
        assert_eq!(echo(&mut s, shell, b"still-here\n").await, b"still-here\n");
        assert_eq!(settle(&mut s, b"echo scp").await.stdout, b"out:echo scp");
    })
    .await
    .expect("timed out");
    let seen = seen.lock().unwrap();
    let kinds: Vec<&[u8]> = seen.iter().map(|(k, _)| &k[..]).collect();
    assert_eq!(kinds, [&b"shell"[..], b"exec"], "{seen:?}");
}

#[tokio::test]
async fn what_only_looks_like_a_file_transfer_crosses_a_token_without_it() {
    let tokens = tokens();
    let token = issue_without_file_transfer(&tokens, &upstream().await);
    let addr = broker(tokens).await;
    let mut s = downstream(&addr, token.as_bytes()).await.expect("refused");
    timeout(LIMIT, async {
        for data in [
            Subsystem::new(b"sftp2".to_vec()).encode(),
            Subsystem::new(b"SFTP".to_vec()).encode(),
            [&sftp()[..], b"x"].concat(),
        ] {
            let ch = open(&mut s).await;
            assert!(ask(&mut s, ch, "subsystem", data.clone()).await, "{data:?}");
        }
        for command in [&b"scpx -t"[..], b"sftp", b"echo scp", b""] {
            let out = settle(&mut s, command).await;
            assert_eq!(out.replied, Some(true), "{command:?}");
        }
    })
    .await
    .expect("timed out");
}

#[tokio::test]
async fn a_token_with_file_transfer_allows_sftp_beside_the_shell_and_scp() {
    let tokens = tokens();
    let token = issue(&tokens, &upstream().await);
    let addr = broker(tokens).await;
    let mut s = downstream(&addr, token.as_bytes()).await.expect("refused");
    timeout(LIMIT, async {
        let shell = open(&mut s).await;
        assert!(ask(&mut s, shell, "shell", Vec::new()).await);
        let second = open(&mut s).await;
        assert!(ask(&mut s, second, "subsystem", sftp()).await);
        assert_eq!(settle(&mut s, b"scp -t /tmp").await.replied, Some(true));
    })
    .await
    .expect("timed out");
}

#[tokio::test]
async fn one_shell_per_token_across_its_connections_given_back_when_it_ends() {
    let tokens = tokens();
    let (up, seen) = upstream_seeing().await;
    let token = issue(&tokens, &up);
    let addr = broker(tokens).await;
    let mut first = downstream(&addr, token.as_bytes()).await.expect("refused");
    let mut second = downstream(&addr, token.as_bytes()).await.expect("refused");
    timeout(LIMIT, async {
        let shell = open(&mut first).await;
        assert!(ask(&mut first, shell, "shell", Vec::new()).await);
        let refused = open(&mut second).await;
        assert!(!ask(&mut second, refused, "shell", Vec::new()).await);
        settle(&mut second, b"probe").await;
        assert_eq!(count(&seen, b"shell"), 1);

        first.eof(shell).await.unwrap();
        closed(&mut first, shell).await;
        let again = open(&mut second).await;
        assert!(ask(&mut second, again, "shell", Vec::new()).await);
    })
    .await
    .expect("timed out");
}

#[tokio::test]
async fn a_shell_is_given_back_when_its_connection_drops() {
    let tokens = tokens();
    let token = issue(&tokens, &upstream().await);
    let addr = broker(tokens).await;
    timeout(LIMIT, async {
        let mut first = downstream(&addr, token.as_bytes()).await.expect("refused");
        let shell = open(&mut first).await;
        assert!(ask(&mut first, shell, "shell", Vec::new()).await);
        drop(first);
        let mut second = downstream(&addr, token.as_bytes()).await.expect("refused");
        loop {
            let ch = open(&mut second).await;
            if ask(&mut second, ch, "shell", Vec::new()).await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the shell was never given back");
}

#[tokio::test]
async fn a_second_shell_request_on_the_channel_holding_the_shell_crosses() {
    let tokens = tokens();
    let (up, seen) = upstream_seeing().await;
    let token = issue(&tokens, &up);
    let addr = broker(tokens).await;
    let mut s = downstream(&addr, token.as_bytes()).await.expect("refused");
    timeout(LIMIT, async {
        let shell = open(&mut s).await;
        assert!(ask(&mut s, shell, "shell", Vec::new()).await);
        assert!(ask(&mut s, shell, "shell", Vec::new()).await);
    })
    .await
    .expect("timed out");
    assert_eq!(count(&seen, b"shell"), 2);
}

#[tokio::test]
async fn a_disposed_token_ends_its_upstream_and_refuses_new_channels() {
    let tokens = tokens();
    let token = issue(&tokens, &upstream().await);
    let addr = broker(tokens.clone()).await;
    let mut s = downstream(&addr, token.as_bytes()).await.expect("refused");
    timeout(LIMIT, async {
        let shell = open(&mut s).await;
        assert!(ask(&mut s, shell, "shell", Vec::new()).await);
        assert!(tokens.revoke(&token));
        s.eof(shell).await.unwrap();
        closed(&mut s, shell).await;
        s.open_channel("session", Vec::new()).await.unwrap();
        loop {
            match s.next().await.unwrap() {
                Some(Action::ChannelOpenFailed {
                    reason,
                    description,
                    ..
                }) => {
                    assert_eq!(reason, OpenFailureReason::CONNECT_FAILED);
                    assert_eq!(description, b"upstream channel open failed");
                    break;
                }
                Some(Action::ChannelOpened { .. }) => panic!("a channel opened after disposal"),
                Some(Action::Closed(c)) => panic!("{c:?}"),
                None => panic!("ended"),
                Some(_) => {}
            }
        }
    })
    .await
    .expect("timed out");
}

#[tokio::test]
async fn an_authenticated_connection_logs_its_caller_channels_and_requests_but_no_secret() {
    let tokens = tokens();
    let token = issue(&tokens, &upstream().await);
    let lines = Lines::default();
    let addr = broker_logging(tokens, lines.log()).await;
    let mut s = downstream(&addr, token.as_bytes()).await.expect("refused");
    timeout(LIMIT, async {
        settle(&mut s, b"secret-command-text").await;
        settle(&mut s, b"again").await;
        s.global_request("probe@justssh", false, Vec::new())
            .await
            .unwrap();
        s.global_request("keepalive@openssh.com", false, Vec::new())
            .await
            .unwrap();
        lines.wait_for("global request").await;
        drop(s);
        let text = lines.wait_for("closed: ").await;
        let l = format!("listener={addr}");
        for want in [
            format!(
                r#"level=INFO msg="authenticated: {l} caller=pid=4242 image=putty.exe verdict=unmeasured admitted=claim live=1""#
            ),
            format!(r#"level=INFO msg="channel: {l} id=1 type=session opened chans=1""#),
            format!(r#"level=INFO msg="request: {l} id=1 type=exec""#),
            format!(r#"level=INFO msg="channel: {l} id=1 type=session closed chans=0""#),
            format!(r#"level=INFO msg="channel: {l} id=2 type=session opened chans=1""#),
            format!(r#"level=INFO msg="global request: {l} type=probe@justssh""#),
            format!(r#"level=INFO msg="closed: {l} live=0 reason=clean""#),
        ] {
            assert!(text.contains(&want), "{want}\nnot in\n{text}");
        }
        assert!(!text.contains("keepalive"), "{text}");
        for secret in ["secret-command-text", &*token, "real-secret"] {
            assert!(!text.contains(secret), "{secret} in\n{text}");
        }
    })
    .await
    .expect("timed out");
}

#[tokio::test]
async fn a_refused_authentication_logs_why_and_what_each_side_offered() {
    let tokens = tokens();
    let token = issue(&tokens, &upstream().await);
    let lines = Lines::default();
    let addr = broker_logging(tokens, lines.log()).await;
    assert!(
        downstream(&addr, b"0123456789abcdef0123456789abcdef")
            .await
            .is_none()
    );
    let text = lines.wait_for("downstream handshake offers").await;
    let l = format!("listener={addr}");
    for want in [
        format!(
            r#"level=WARN msg="authentication failed: {l} caller=pid=4242 image=putty.exe verdict=unmeasured user=\"srv-7@10.0.0.9\" reason=acwbroker: no live token matches the presented password""#
        ),
        r#"level=ERROR msg="downstream handshake failed: "#.to_owned(),
        format!(
            r#"level=ERROR msg="downstream handshake offers: {l} client version=\"SSH-2.0-justssh\" kex="#
        ),
        "; server version=\\\"SSH-2.0-justssh\\\" kex=".to_owned(),
    ] {
        assert!(text.contains(&want), "{want}\nnot in\n{text}");
    }
    assert!(!text.contains("0123456789abcdef"), "{text}");
    assert!(!text.contains(&*token), "{text}");
}

#[tokio::test]
async fn an_upstream_that_refuses_the_credential_is_logged() {
    let tokens = tokens();
    let up = upstream().await;
    let token = issue_with(&tokens, &up, b"not-the-secret");
    let lines = Lines::default();
    let addr = broker_logging(tokens, lines.log()).await;
    assert!(downstream(&addr, token.as_bytes()).await.is_none());
    let text = lines.wait_for("upstream authentication failed").await;
    let want = format!(
        r#"level=ERROR msg="upstream authentication failed: upstream {up}: unable to authenticate, attempted methods [none password], no supported methods remain""#
    );
    assert!(text.contains(&want), "{want}\nnot in\n{text}");
    assert!(!text.contains("not-the-secret"), "{text}");
}

#[tokio::test]
async fn refusals_are_logged_with_their_reason() {
    let tokens = tokens();
    let token = issue_without_file_transfer(&tokens, &upstream().await);
    let lines = Lines::default();
    let addr = broker_logging(tokens, lines.log()).await;
    let mut first = downstream(&addr, token.as_bytes()).await.expect("refused");
    let mut second = downstream(&addr, token.as_bytes()).await.expect("refused");
    timeout(LIMIT, async {
        let shell = open(&mut first).await;
        assert!(ask(&mut first, shell, "shell", Vec::new()).await);
        let ch = open(&mut first).await;
        assert!(!ask(&mut first, ch, "subsystem", sftp()).await);
        let ch = open(&mut second).await;
        assert!(!ask(&mut second, ch, "shell", Vec::new()).await);
    })
    .await
    .expect("timed out");
    let text = lines.wait_for("already open").await;
    let l = format!("listener={addr}");
    for want in [
        format!(r#"level=INFO msg="request: {l} id=2 type=subsystem name=sftp""#),
        format!(
            r#"level=WARN msg="request refused: {l} id=2 type=subsystem reason=the node does not allow file transfer""#
        ),
        format!(
            r#"level=WARN msg="request refused: {l} id=1 type=shell reason=a shell is already open on this token""#
        ),
    ] {
        assert!(text.contains(&want), "{want}\nnot in\n{text}");
    }
}
