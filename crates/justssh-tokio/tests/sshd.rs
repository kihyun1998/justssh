//! `connect` against real OpenSSH servers: one taking `password`, one taking only
//! keyboard-interactive through PAM. CI starts both (`.github/workflows/test.yml`) and names them
//! in `JUSTSSH_SSHD_PASSWORD_ADDR` and `JUSTSSH_SSHD_PAM_ADDR`, with the account in
//! `JUSTSSH_SSHD_USER` and `JUSTSSH_SSHD_SECRET`. Without them each test is skipped, unless
//! `JUSTSSH_REQUIRE_SSHD` is set.

use justssh::{Action, Client, ClientConfig, InfoRequest, Phase, Zeroizing};
use justssh_tokio::{AuthMethod, ClientHandler, Connected, Deadlines, Session};
use tokio::net::TcpStream;

/// The address in `var`, and the account, or `None` to skip.
fn target(var: &str) -> Option<(String, Vec<u8>, Vec<u8>)> {
    let found = (|| {
        Some((
            std::env::var(var).ok()?,
            std::env::var("JUSTSSH_SSHD_USER").ok()?.into_bytes(),
            std::env::var("JUSTSSH_SSHD_SECRET").ok()?.into_bytes(),
        ))
    })();
    if found.is_none() {
        assert!(
            std::env::var_os("JUSTSSH_REQUIRE_SSHD").is_none(),
            "JUSTSSH_REQUIRE_SSHD is set but {var}, JUSTSSH_SSHD_USER or JUSTSSH_SSHD_SECRET is not"
        );
        eprintln!("skipped: {var} not set");
    }
    found
}

/// Accepts any host key, as the broker does, and answers every question with the password.
struct Broker {
    password: Vec<u8>,
    prompts: Vec<Vec<u8>>,
    host_key: Option<Vec<u8>>,
}

impl ClientHandler for Broker {
    async fn check_host_key(&mut self, key: &[u8]) -> bool {
        self.host_key = Some(key.to_vec());
        true
    }

    async fn answer(&mut self, request: &InfoRequest) -> Vec<Zeroizing<Vec<u8>>> {
        request
            .prompts()
            .iter()
            .map(|p| {
                self.prompts.push(p.text().to_vec());
                Zeroizing::new(self.password.clone())
            })
            .collect()
    }
}

/// Connects to `addr` with the broker's methods: password, then keyboard-interactive.
async fn log_in(addr: &str, user: &[u8], password: &[u8]) -> (Client, Broker) {
    let io = TcpStream::connect(addr).await.unwrap();
    let mut client = Client::new(ClientConfig::builder(user).build());
    let mut broker = Broker {
        password: password.to_vec(),
        prompts: Vec::new(),
        host_key: None,
    };
    let methods = [
        AuthMethod::Password(Zeroizing::new(password.to_vec())),
        AuthMethod::KeyboardInteractive,
    ];
    let connected =
        justssh_tokio::connect(io, &mut client, &Deadlines::new(), &methods, &mut broker)
            .await
            .unwrap();
    assert!(
        matches!(connected, Connected::Authenticated { .. }),
        "{connected:?}"
    );
    (client, broker)
}

#[tokio::test]
async fn logs_in_to_sshd_with_a_password() {
    let Some((addr, user, password)) = target("JUSTSSH_SSHD_PASSWORD_ADDR") else {
        return;
    };
    let (client, broker) = log_in(&addr, &user, &password).await;
    assert_eq!(client.phase(), Phase::Connected);
    assert!(broker.prompts.is_empty(), "{:?}", broker.prompts);
    assert!(broker.host_key.is_some());
    eprintln!("server: {:?}", client.handshake().peer_version());
}

#[tokio::test]
async fn logs_in_to_a_pam_only_sshd_with_keyboard_interactive() {
    let Some((addr, user, password)) = target("JUSTSSH_SSHD_PAM_ADDR") else {
        return;
    };
    let (client, broker) = log_in(&addr, &user, &password).await;
    assert_eq!(client.phase(), Phase::Connected);
    assert!(
        !broker.prompts.is_empty(),
        "no keyboard-interactive question"
    );
    eprintln!(
        "prompts: {:?}",
        broker
            .prompts
            .iter()
            .map(|p| String::from_utf8_lossy(p))
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn sshd_announces_its_server_sig_algs() {
    let Some((addr, user, password)) = target("JUSTSSH_SSHD_PASSWORD_ADDR") else {
        return;
    };
    let (client, _) = log_in(&addr, &user, &password).await;
    let algs = client.server_sig_algs().expect("no server-sig-algs");
    assert!(algs.contains(&"rsa-sha2-256"), "{algs:?}");
    eprintln!("server-sig-algs: {algs:?}");
}

/// A session to `addr` past authentication.
async fn session_to(addr: &str, user: &[u8], password: &[u8]) -> Session<TcpStream, Client> {
    let io = TcpStream::connect(addr).await.unwrap();
    let mut client = Client::new(ClientConfig::builder(user).build());
    let mut broker = Broker {
        password: password.to_vec(),
        prompts: Vec::new(),
        host_key: None,
    };
    let methods = [
        AuthMethod::Password(Zeroizing::new(password.to_vec())),
        AuthMethod::KeyboardInteractive,
    ];
    match justssh_tokio::connect(io, &mut client, &Deadlines::new(), &methods, &mut broker)
        .await
        .unwrap()
    {
        Connected::Authenticated { io, events } => Session::new(io, client, events),
        other => panic!("not authenticated: {other:?}"),
    }
}

/// The next action that is not a request from the server; requests wanting a reply are refused
/// and keepalives counted in `keepalives`.
async fn next_answering(
    session: &mut Session<TcpStream, Client>,
    keepalives: &mut usize,
) -> Action {
    loop {
        match session.next().await.unwrap().expect("connection ended") {
            Action::GlobalRequest(r) => {
                *keepalives += usize::from(r.kind() == "keepalive@openssh.com");
                if let Some(token) = r.reply() {
                    session
                        .reply_global(token, false, Vec::new())
                        .await
                        .unwrap();
                }
            }
            Action::ChannelRequest(r) if r.kind() == "keepalive@openssh.com" => {
                *keepalives += 1;
                if let Some(token) = r.reply() {
                    session.reply(token, false).await.unwrap();
                }
            }
            other => return other,
        }
    }
}

/// What a command run on a session channel produced.
struct Exec {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    status: u32,
    keepalives: usize,
}

/// Runs `command` on a new session channel.
async fn exec(session: &mut Session<TcpStream, Client>, command: &str) -> Exec {
    let mut keepalives = 0;
    let channel = session
        .open_channel("session", Vec::new())
        .await
        .unwrap()
        .unwrap();
    match next_answering(session, &mut keepalives).await {
        Action::ChannelOpened { channel: c, .. } if c == channel => {}
        other => panic!("not opened: {other:?}"),
    }
    let mut data = (command.len() as u32).to_be_bytes().to_vec();
    data.extend(command.as_bytes());
    let token = session.request(channel, "exec", true, data).await.unwrap();
    let (mut stdout, mut stderr, mut status, mut replied) = (Vec::new(), Vec::new(), None, false);
    loop {
        match next_answering(session, &mut keepalives).await {
            Action::ChannelRequestReply { token: t, ok, .. } if Some(t) == token => {
                assert!(ok, "exec refused");
                replied = true;
            }
            Action::ChannelData { data, .. } => {
                session.consumed(channel, data.len() as u32).await.unwrap();
                stdout.extend(data);
            }
            Action::ChannelExtendedData { code: 1, data, .. } => {
                session.consumed(channel, data.len() as u32).await.unwrap();
                stderr.extend(data);
            }
            Action::ChannelRequest(r) if r.kind() == "exit-status" => {
                status = Some(u32::from_be_bytes(r.data().try_into().unwrap()));
            }
            Action::ChannelClosed { channel: c } if c == channel => break,
            _ => {}
        }
    }
    assert!(replied, "no reply to exec");
    Exec {
        stdout,
        stderr,
        status: status.expect("no exit-status"),
        keepalives,
    }
}

/// Runs a command with output on both streams and a non-zero status on the sshd in `var`.
async fn exec_on(var: &str) {
    let Some((addr, user, password)) = target(var) else {
        return;
    };
    let mut session = session_to(&addr, &user, &password).await;
    let run = exec(&mut session, "echo out; echo err >&2; exit 3").await;
    assert_eq!(
        (run.stdout.as_slice(), run.stderr.as_slice(), run.status),
        (&b"out\n"[..], &b"err\n"[..], 3)
    );
    eprintln!(
        "server: {:?}",
        session.endpoint().handshake().peer_version()
    );
}

#[tokio::test]
async fn exec_on_sshd_returns_stdout_stderr_and_exit_status() {
    exec_on("JUSTSSH_SSHD_PASSWORD_ADDR").await;
}

#[tokio::test]
async fn exec_on_openssh_8_7_returns_stdout_stderr_and_exit_status() {
    exec_on("JUSTSSH_SSHD_RHEL9_ADDR").await;
}

#[tokio::test]
async fn openssh_8_7_is_what_the_rhel9_variable_names() {
    let Some((addr, user, password)) = target("JUSTSSH_SSHD_RHEL9_ADDR") else {
        return;
    };
    let session = session_to(&addr, &user, &password).await;
    let version = session
        .endpoint()
        .handshake()
        .peer_version()
        .unwrap()
        .to_owned();
    assert!(version.starts_with("SSH-2.0-OpenSSH_8.7"), "{version}");
}

/// Opens a channel of a type the sshd in `var` does not know, and checks its refusal.
async fn unknown_channel_type_on(var: &str) {
    let Some((addr, user, password)) = target(var) else {
        return;
    };
    let mut session = session_to(&addr, &user, &password).await;
    let channel = session
        .open_channel("no-such-type@justssh", Vec::new())
        .await
        .unwrap();
    let mut keepalives = 0;
    match next_answering(&mut session, &mut keepalives).await {
        Action::ChannelOpenFailed {
            channel: c,
            reason,
            description,
        } => {
            assert_eq!(Some(c), channel);
            assert_eq!(
                (reason, description.as_str()),
                (justssh::OpenFailureReason::CONNECT_FAILED, "open failed")
            );
        }
        other => panic!("not refused: {other:?}"),
    }
}

#[tokio::test]
async fn sshd_refuses_an_unknown_channel_type_with_its_reason_and_message() {
    unknown_channel_type_on("JUSTSSH_SSHD_PASSWORD_ADDR").await;
}

#[tokio::test]
async fn openssh_8_7_refuses_an_unknown_channel_type_with_its_reason_and_message() {
    unknown_channel_type_on("JUSTSSH_SSHD_RHEL9_ADDR").await;
}

#[tokio::test]
async fn keepalives_from_sshd_are_answered_and_the_connection_lives_on() {
    // The sshd on this address runs with ClientAliveInterval 1 and ClientAliveCountMax 2.
    let Some((addr, user, password)) = target("JUSTSSH_SSHD_PASSWORD_ADDR") else {
        return;
    };
    let mut session = session_to(&addr, &user, &password).await;
    let mut keepalives = 0;
    let until = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while let Ok(next) = tokio::time::timeout_at(until, session.next()).await {
        match next.unwrap().expect("connection ended") {
            Action::GlobalRequest(r) if r.kind() == "keepalive@openssh.com" => {
                assert!(r.want_reply());
                keepalives += 1;
                session
                    .reply_global(r.reply().unwrap(), false, Vec::new())
                    .await
                    .unwrap();
            }
            Action::Closed(c) => panic!("closed: {c:?}"),
            _ => {}
        }
    }
    assert!(keepalives >= 3, "{keepalives} keepalives in 5 s");
    let run = exec(&mut session, "echo alive").await;
    assert_eq!((run.stdout.as_slice(), run.status), (&b"alive\n"[..], 0));
}

#[tokio::test]
async fn a_long_exec_lives_through_the_keepalives_sshd_sends_on_its_channel() {
    // The sshd on this address runs with ClientAliveInterval 1 and ClientAliveCountMax 2.
    let Some((addr, user, password)) = target("JUSTSSH_SSHD_PASSWORD_ADDR") else {
        return;
    };
    let mut session = session_to(&addr, &user, &password).await;
    let run = exec(&mut session, "sleep 4; echo done").await;
    assert_eq!((run.stdout.as_slice(), run.status), (&b"done\n"[..], 0));
    assert!(run.keepalives >= 3, "{} keepalives in 4 s", run.keepalives);
}
