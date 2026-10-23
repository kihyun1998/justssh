//! The broker's SSH side in process: a justssh client downstream, the broker in the middle, and
//! a justssh server upstream standing in for acwbroker's test upstream (`internal/testutil`):
//! `exec` answers `out:<cmd>` on stdout, `err:<cmd>` on stderr and exit status 7; `shell` echoes
//! until EOF.

use std::time::Duration;

use justssh::requests::{Exec, ExitStatus};
use justssh::{
    Action, ChannelId, Client, ClientConfig, HostKey, InfoRequest, OpenFailureReason, Server,
    ServerConfig, Zeroizing,
};
use justssh_broker::tokens::Tokens;
use justssh_broker::{broker, issue};
use justssh_tokio::{Accepted, AuthMethod, ClientHandler, Connected, Deadlines, Session};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(30);
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

/// The test upstream, serving connections until the test ends.
async fn upstream() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(upstream_connection(stream));
        }
    });
    addr
}

async fn upstream_connection(stream: TcpStream) {
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

/// The broker serving `tokens`; its address.
async fn broker(tokens: Tokens) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let host_key = HostKey::ed25519_from_seed(Zeroizing::new([7; 32]));
    tokio::spawn(broker::serve(
        listener,
        host_key,
        tokens,
        Duration::from_secs(15),
    ));
    addr
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
    let tokens = Tokens::default();
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
    let tokens = Tokens::default();
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
    let tokens = Tokens::default();
    let _ = issue(&tokens, &upstream().await);
    let addr = broker(tokens).await;
    assert!(downstream(&addr, &[b'a'; 32]).await.is_none());
}

#[tokio::test]
async fn a_channel_the_upstream_refuses_is_refused_downstream_with_its_reason_and_message() {
    let tokens = Tokens::default();
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
    let tokens = Tokens::default();
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
    let tokens = Tokens::default();
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
    let tokens = Tokens::default();
    let token = issue_with(&tokens, &upstream().await, b"not-the-secret");
    let addr = broker(tokens).await;
    assert!(downstream(&addr, token.as_bytes()).await.is_none());
}

#[tokio::test]
async fn a_token_presented_by_another_user_is_refused() {
    let tokens = Tokens::default();
    let token = issue(&tokens, &upstream().await);
    let addr = broker(tokens).await;
    assert!(
        downstream_as(&addr, b"someone-else", token.as_bytes())
            .await
            .is_none()
    );
}
