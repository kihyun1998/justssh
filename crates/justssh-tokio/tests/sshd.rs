//! `connect` against the real OpenSSH servers CI starts (`.github/workflows/test.yml`), each named
//! in a `JUSTSSH_SSHD_*_ADDR` variable, with the account in `JUSTSSH_SSHD_USER` and
//! `JUSTSSH_SSHD_SECRET`. Without them each test is skipped, unless `JUSTSSH_REQUIRE_SSHD` is set.

use justssh::requests::{self, ExitStatus, PtyReq};
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
    session_configured(addr, user, password, |b| b).await
}

/// As [`session_to`], with the client configured by `edit`.
async fn session_configured(
    addr: &str,
    user: &[u8],
    password: &[u8],
    edit: impl FnOnce(justssh::ClientConfigBuilder) -> justssh::ClientConfigBuilder,
) -> Session<TcpStream, Client> {
    let io = TcpStream::connect(addr).await.unwrap();
    let mut client = Client::new(edit(ClientConfig::builder(user)).build());
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

/// What [`next_answering`] answered on the way.
#[derive(Default)]
struct Answered {
    keepalives: usize,
    /// Host keys accepted on key re-exchanges.
    rekeys: usize,
}

/// The next action that is not a request from the server or a host key to judge; requests
/// wanting a reply are refused, host keys accepted, and both counted in `seen`.
async fn next_answering(session: &mut Session<TcpStream, Client>, seen: &mut Answered) -> Action {
    loop {
        match session.next().await.unwrap().expect("connection ended") {
            Action::VerifyHostKey { .. } => {
                seen.rekeys += 1;
                session.answer_host_key(true).await.unwrap();
            }
            Action::GlobalRequest(r) => {
                seen.keepalives += usize::from(r.kind() == "keepalive@openssh.com");
                if let Some(token) = r.reply() {
                    session
                        .reply_global(token, false, Vec::new())
                        .await
                        .unwrap();
                }
            }
            Action::ChannelRequest(r) if r.kind() == "keepalive@openssh.com" => {
                seen.keepalives += 1;
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
    rekeys: usize,
}

/// Runs `command` on a new session channel.
async fn exec(session: &mut Session<TcpStream, Client>, command: &str) -> Exec {
    exec_with(session, command, None).await
}

/// Runs `command` on a new session channel, with a terminal from `pty` when given.
async fn exec_with(
    session: &mut Session<TcpStream, Client>,
    command: &str,
    pty: Option<PtyReq>,
) -> Exec {
    let mut seen = Answered::default();
    let channel = session
        .open_channel("session", Vec::new())
        .await
        .unwrap()
        .unwrap();
    match next_answering(session, &mut seen).await {
        Action::ChannelOpened { channel: c, .. } if c == channel => {}
        other => panic!("not opened: {other:?}"),
    }
    let pty_token = match pty {
        Some(pty) => session
            .request(channel, PtyReq::KIND, true, pty.encode())
            .await
            .unwrap(),
        None => None,
    };
    let token = session
        .request(
            channel,
            requests::Exec::KIND,
            true,
            requests::Exec::new(command.as_bytes().to_vec()).encode(),
        )
        .await
        .unwrap();
    let (mut stdout, mut stderr, mut status, mut replied) = (Vec::new(), Vec::new(), None, false);
    loop {
        match next_answering(session, &mut seen).await {
            Action::ChannelRequestReply { token: t, ok, .. } if Some(t) == pty_token => {
                assert!(ok, "pty-req refused");
            }
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
            Action::ChannelRequest(r) if r.kind() == ExitStatus::KIND => {
                status = Some(ExitStatus::decode(r.data()).unwrap().status());
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
        keepalives: seen.keepalives,
        rekeys: seen.rekeys,
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
async fn sshd_gives_a_command_the_terminal_a_pty_request_built_from_modes_asks_for() {
    let Some((addr, user, password)) = target("JUSTSSH_SSHD_PASSWORD_ADDR") else {
        return;
    };
    let mut session = session_to(&addr, &user, &password).await;
    // MobaXterm's modes as measured (#5): VERASE ^H, IXANY and IUTF8 on, 38400 baud.
    let modes = [(3, 8), (39, 1), (42, 1), (128, 38400), (129, 38400)];
    let pty = PtyReq::new(b"xterm-mono".to_vec(), 97, 31, 0, 0, &modes);
    let run = exec_with(
        &mut session,
        "[ -t 0 ] && echo tty; echo $TERM; stty size; stty -a",
        Some(pty),
    )
    .await;
    let out = String::from_utf8_lossy(&run.stdout);
    assert!(out.starts_with("tty\r\nxterm-mono\r\n31 97\r\n"), "{out}");
    let flags: Vec<&str> = out.split_whitespace().collect();
    assert!(
        out.contains("erase = ^H;") && flags.contains(&"ixany") && flags.contains(&"iutf8"),
        "{out}"
    );
    assert_eq!(run.status, 0);
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
    let mut seen = Answered::default();
    match next_answering(&mut session, &mut seen).await {
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

#[path = "../../justssh/tests/common/test_keys.rs"]
mod test_keys;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(BASE64[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The keys the public key sshd authorises, by name.
fn authorised_keys() -> Vec<(&'static str, justssh::PrivateKey)> {
    use justssh::{EcdsaCurve, PrivateKey};
    vec![
        ("ed25519", PrivateKey::ed25519(Zeroizing::new([3; 32]))),
        (
            "ecdsa-p256",
            PrivateKey::ecdsa(EcdsaCurve::P256, Zeroizing::new(vec![2; 32])).unwrap(),
        ),
        (
            "ecdsa-p384",
            PrivateKey::ecdsa(EcdsaCurve::P384, Zeroizing::new(vec![2; 48])).unwrap(),
        ),
        (
            "ecdsa-p521",
            PrivateKey::ecdsa(EcdsaCurve::P521, Zeroizing::new(vec![1; 66])).unwrap(),
        ),
        (
            "rsa",
            PrivateKey::rsa(
                &hex(test_keys::RSA_N),
                &hex(test_keys::RSA_E),
                Zeroizing::new(hex(test_keys::RSA_D)),
                Zeroizing::new(hex(test_keys::RSA_P)),
                Zeroizing::new(hex(test_keys::RSA_Q)),
            )
            .unwrap(),
        ),
    ]
}

/// A key the sshd does not authorise, certified by the CA it trusts.
fn certified_key(dir: &str) -> justssh::PrivateKey {
    let key = justssh::PrivateKey::ed25519(Zeroizing::new([4; 32]));
    certify(dir, "ed25519", key)
}

/// `key` under a certificate the CA in `dir` issues for user `justssh`, signed by `ssh-keygen`.
fn certify(dir: &str, name: &str, key: justssh::PrivateKey) -> justssh::PrivateKey {
    let cert = certificate(dir, name, &key);
    key.with_certificate(cert).unwrap()
}

/// The keys directory the public key sshd reads, set up once: `authorized_keys` with every
/// [`authorised_keys`] entry, and a CA from `ssh-keygen` in `ca.pub`.
fn keys_dir() -> Option<String> {
    let Ok(dir) = std::env::var("JUSTSSH_SSHD_KEYS_DIR") else {
        assert!(
            std::env::var_os("JUSTSSH_REQUIRE_SSHD").is_none(),
            "JUSTSSH_REQUIRE_SSHD is set but JUSTSSH_SSHD_KEYS_DIR is not"
        );
        eprintln!("skipped: JUSTSSH_SSHD_KEYS_DIR not set");
        return None;
    };
    static SETUP: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    SETUP.get_or_init(|| {
        let mut lines: String = authorised_keys()
            .iter()
            .map(|(name, key)| {
                let blob = key.public_blob();
                let mut r = justssh_wire::Reader::new(&blob);
                format!("{} {} {name}\n", r.utf8().unwrap(), base64(&blob))
            })
            .collect();
        for (name, _) in KEY_FILES {
            lines.push_str(&std::fs::read_to_string(key_file(&format!("{name}.pub"))).unwrap());
        }
        for name in PEM_FILES {
            lines.push_str(&std::fs::read_to_string(pem_file(&format!("{name}.pub"))).unwrap());
        }
        for (name, encrypted) in PPK_FILES {
            let source = std::fs::read(ppk_file(&format!("{name}.openssh"))).unwrap();
            let key = justssh_keys::KeyFile::from_openssh(
                &source,
                encrypted.then_some(&b"correct horse"[..]),
            )
            .unwrap();
            let blob = key.private_key().plain_public_blob();
            let key_type = justssh_wire::Reader::new(&blob).utf8().unwrap().to_owned();
            lines.push_str(&format!(
                "{key_type} {} {name}-ppk
",
                base64(&blob)
            ));
        }
        std::fs::write(format!("{dir}/authorized_keys"), lines).unwrap();
        let ca = format!("{dir}/ca");
        let _ = std::fs::remove_file(&ca);
        let _ = std::fs::remove_file(format!("{ca}.pub"));
        ssh_keygen(&["-q", "-t", "ed25519", "-N", "", "-f", &ca]);
    });
    Some(dir)
}

fn ssh_keygen(args: &[&str]) {
    let status = std::process::Command::new("ssh-keygen")
        .args(args)
        .status()
        .expect("ssh-keygen");
    assert!(status.success(), "ssh-keygen {args:?}");
}

/// The certificate the CA in `dir` issues for `key`, for user `justssh`, under file name `name`.
fn certificate(dir: &str, name: &str, key: &justssh::PrivateKey) -> Vec<u8> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _held = LOCK.lock().unwrap();
    let blob = key.public_blob();
    let key_type = justssh_wire::Reader::new(&blob).utf8().unwrap().to_owned();
    let user = format!("{dir}/user-{name}.pub");
    std::fs::write(&user, format!("{key_type} {}\n", base64(&blob))).unwrap();
    ssh_keygen(&[
        "-q",
        "-s",
        &format!("{dir}/ca"),
        "-I",
        "justssh-test",
        "-n",
        "justssh",
        "-V",
        "-5m:+1h",
        &user,
    ]);
    let text = std::fs::read_to_string(format!("{dir}/user-{name}-cert.pub")).unwrap();
    justssh_keys::certificate_from_line(text.as_bytes()).unwrap()
}

/// Connects to the sshd in `var` with `keys` and nothing else; how it ended and the client.
async fn log_in_with_keys(
    var: &str,
    keys: Vec<justssh::PrivateKey>,
) -> Option<(Connected<TcpStream>, Client)> {
    let (addr, user, _) = target(var)?;
    keys_dir()?;
    let io = TcpStream::connect(&addr).await.unwrap();
    let mut client = Client::new(ClientConfig::builder(&user).build());
    let mut broker = Broker {
        password: Vec::new(),
        prompts: Vec::new(),
        host_key: None,
    };
    let connected = justssh_tokio::connect(
        io,
        &mut client,
        &Deadlines::new(),
        &[AuthMethod::PublicKeys(keys)],
        &mut broker,
    )
    .await
    .unwrap();
    Some((connected, client))
}

#[tokio::test]
async fn logs_in_to_sshd_with_ed25519_ecdsa_and_rsa_keys() {
    for (name, key) in authorised_keys() {
        let Some((connected, client)) =
            log_in_with_keys("JUSTSSH_SSHD_KEYS_ADDR", vec![key.clone()]).await
        else {
            return;
        };
        assert!(
            matches!(connected, Connected::Authenticated { .. }),
            "{name}: {connected:?}"
        );
        let sig_algs = client.server_sig_algs();
        let algorithm = key.algorithm_for(sig_algs.as_deref());
        if name == "rsa" {
            assert_eq!(algorithm, "rsa-sha2-256");
        }
        eprintln!("{name}: signed under {algorithm}");
    }
}

/// The OpenSSH key files `ssh-keygen` made for `justssh-keys`' tests, with their passphrases.
const KEY_FILES: [(&str, Option<&str>); 7] = [
    ("ed25519", None),
    ("ed25519-pass", Some("correct horse")),
    ("ecdsa256", None),
    ("ecdsa384", None),
    ("ecdsa521-pass-cbc", Some("correct horse")),
    ("rsa2048", None),
    ("rsa3072-pass", Some("correct horse")),
];

fn key_file(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../justssh-keys/tests/keys")
        .join(name)
}

/// The PPK files WinSCP made for `justssh-keys`' tests from the OpenSSH key beside each, with
/// whether they are encrypted (passphrase `correct horse`).
const PPK_FILES: [(&str, bool); 8] = [
    ("ed25519", false),
    ("ed25519-enc", true),
    ("ecdsa256", false),
    ("ecdsa384", false),
    ("ecdsa384-enc", true),
    ("ecdsa521", false),
    ("rsa", false),
    ("rsa-enc", true),
];

fn ppk_file(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../justssh-keys/tests/ppk")
        .join(name)
}

/// The PEM key files `ssh-keygen` and `openssl` made for `justssh-keys`' tests that an SSH
/// client signs with; those whose names say `aes` or `des` are encrypted (`correct horse`).
const PEM_FILES: [&str; 12] = [
    "rsa-pkcs1",
    "rsa-pkcs1-aes128",
    "rsa-pkcs1-des",
    "rsa-pkcs1-des3",
    "rsa-pkcs8",
    "ec256-sec1",
    "ec256-sec1-aes192",
    "ec256-sec1-aes256",
    "ec384-sec1-aes128",
    "ec521-sec1",
    "ec256-pkcs8",
    "ed25519-pkcs8",
];

fn pem_file(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../justssh-keys/tests/pem")
        .join(name)
}

#[tokio::test]
async fn logs_in_to_sshd_with_the_pem_files_ssh_keygen_and_openssl_wrote() {
    for name in PEM_FILES {
        let encrypted = name.contains("aes") || name.contains("des");
        let text = std::fs::read(pem_file(name)).unwrap();
        let key = justssh_keys::KeyFile::read(&text, encrypted.then_some(&b"correct horse"[..]))
            .unwrap()
            .private_key()
            .clone();
        let Some((connected, _)) = log_in_with_keys("JUSTSSH_SSHD_KEYS_ADDR", vec![key]).await
        else {
            return;
        };
        assert!(
            matches!(connected, Connected::Authenticated { .. }),
            "{name}: {connected:?}"
        );
    }
}

#[tokio::test]
async fn logs_in_to_sshd_with_the_ppk_files_winscp_wrote() {
    for (name, encrypted) in PPK_FILES {
        let text = std::fs::read(ppk_file(&format!("{name}.ppk"))).unwrap();
        let key =
            justssh_keys::KeyFile::from_ppk(&text, encrypted.then_some(&b"correct horse"[..]))
                .unwrap()
                .private_key()
                .clone();
        let Some((connected, _)) = log_in_with_keys("JUSTSSH_SSHD_KEYS_ADDR", vec![key]).await
        else {
            return;
        };
        assert!(
            matches!(connected, Connected::Authenticated { .. }),
            "{name}: {connected:?}"
        );
    }
}

#[tokio::test]
async fn logs_in_to_sshd_with_the_openssh_key_files_ssh_keygen_wrote() {
    for (name, passphrase) in KEY_FILES {
        let text = std::fs::read(key_file(name)).unwrap();
        let key = justssh_keys::KeyFile::from_openssh(&text, passphrase.map(str::as_bytes))
            .unwrap()
            .private_key()
            .clone();
        let Some((connected, _)) = log_in_with_keys("JUSTSSH_SSHD_KEYS_ADDR", vec![key]).await
        else {
            return;
        };
        assert!(
            matches!(connected, Connected::Authenticated { .. }),
            "{name}: {connected:?}"
        );
    }
}

#[tokio::test]
async fn logs_in_to_sshd_with_an_openssh_certificate() {
    let (Some(_), Some(dir)) = (target("JUSTSSH_SSHD_KEYS_ADDR"), keys_dir()) else {
        return;
    };
    let key = certified_key(&dir);
    let (connected, _) = log_in_with_keys("JUSTSSH_SSHD_KEYS_ADDR", vec![key])
        .await
        .unwrap();
    assert!(
        matches!(connected, Connected::Authenticated { .. }),
        "{connected:?}"
    );
}

#[tokio::test]
async fn a_key_sshd_does_not_authorise_is_refused() {
    let stranger = justssh::PrivateKey::ed25519(Zeroizing::new([4; 32]));
    let Some((connected, _)) = log_in_with_keys("JUSTSSH_SSHD_KEYS_ADDR", vec![stranger]).await
    else {
        return;
    };
    assert!(
        matches!(&connected, Connected::NoMethodLeft { tried, .. } if tried.contains(&"publickey")),
        "{connected:?}"
    );
}

#[tokio::test]
async fn rsa_signs_with_ssh_rsa_where_sshd_accepts_only_ssh_rsa() {
    let rsa = authorised_keys().pop().unwrap().1;
    let Some((connected, client)) =
        log_in_with_keys("JUSTSSH_SSHD_SSH_RSA_ADDR", vec![rsa.clone()]).await
    else {
        return;
    };
    let sig_algs = client.server_sig_algs();
    eprintln!("server-sig-algs: {sig_algs:?}");
    assert_eq!(rsa.algorithm_for(sig_algs.as_deref()), "ssh-rsa");
    assert!(
        matches!(connected, Connected::Authenticated { .. }),
        "{connected:?}"
    );
}

/// The authorised RSA key.
fn rsa_key() -> justssh::PrivateKey {
    authorised_keys().pop().unwrap().1
}

#[tokio::test]
async fn logs_in_to_sshd_with_rsa_and_ecdsa_certificates() {
    let (Some(_), Some(dir)) = (target("JUSTSSH_SSHD_KEYS_ADDR"), keys_dir()) else {
        return;
    };
    let p256 =
        justssh::PrivateKey::ecdsa(justssh::EcdsaCurve::P256, Zeroizing::new(vec![5; 32])).unwrap();
    for (name, key) in [
        ("rsa", certify(&dir, "rsa", rsa_key())),
        ("ecdsa-p256", certify(&dir, "ecdsa-p256", p256)),
    ] {
        let (connected, client) = log_in_with_keys("JUSTSSH_SSHD_KEYS_ADDR", vec![key.clone()])
            .await
            .unwrap();
        assert!(
            matches!(connected, Connected::Authenticated { .. }),
            "{name}: {connected:?}"
        );
        let algorithm = key.algorithm_for(client.server_sig_algs().as_deref());
        eprintln!("{name} certificate: signed under {algorithm}");
        if name == "rsa" {
            assert_eq!(algorithm, "rsa-sha2-256-cert-v01@openssh.com");
        }
    }
}

#[tokio::test]
async fn an_rsa_certificate_signs_with_ssh_rsa_where_sshd_accepts_only_ssh_rsa() {
    let (Some(_), Some(dir)) = (target("JUSTSSH_SSHD_SSH_RSA_ADDR"), keys_dir()) else {
        return;
    };
    let key = certify(&dir, "rsa", rsa_key());
    let (connected, client) = log_in_with_keys("JUSTSSH_SSHD_SSH_RSA_ADDR", vec![key.clone()])
        .await
        .unwrap();
    assert_eq!(
        key.algorithm_for(client.server_sig_algs().as_deref()),
        "ssh-rsa-cert-v01@openssh.com"
    );
    assert!(
        matches!(connected, Connected::Authenticated { .. }),
        "{connected:?}"
    );
}

#[tokio::test]
async fn logs_in_to_openssh_8_7_with_keys_and_a_certificate() {
    let (Some(_), Some(dir)) = (target("JUSTSSH_SSHD_RHEL9_ADDR"), keys_dir()) else {
        return;
    };
    for (name, key) in authorised_keys()
        .into_iter()
        .chain([("ed25519 certificate", certified_key(&dir))])
    {
        let (connected, client) = log_in_with_keys("JUSTSSH_SSHD_RHEL9_ADDR", vec![key.clone()])
            .await
            .unwrap();
        assert!(
            matches!(connected, Connected::Authenticated { .. }),
            "{name}: {connected:?}"
        );
        let algorithm = key.algorithm_for(client.server_sig_algs().as_deref());
        eprintln!("8.7 {name}: signed under {algorithm}");
        if name == "rsa" {
            eprintln!("8.7 server-sig-algs: {:?}", client.server_sig_algs());
        }
    }
}

/// Logs in to the sshd in `var` by password with the client offering only `kex`, `cipher` and
/// `mac`; the algorithms the connection used.
async fn password_login_with(
    var: &str,
    kex: &str,
    cipher: &str,
    mac: &str,
) -> Option<justssh::Algorithms> {
    password_login_offering(var, kex, cipher, mac, true).await
}

/// As [`password_login_with`], offering strict KEX only when `strict`.
async fn password_login_offering(
    var: &str,
    kex: &str,
    cipher: &str,
    mac: &str,
    strict: bool,
) -> Option<justssh::Algorithms> {
    password_login_configured(var, &format!("{kex} {cipher} {mac}"), |b| {
        b.algorithms(&[kex], &[cipher], &[mac]).strict_kex(strict)
    })
    .await
}

/// A password login to the sshd `var` names with the client configured by `edit`; the
/// negotiated algorithms, or `None` to skip.
async fn password_login_configured(
    var: &str,
    label: &str,
    edit: impl FnOnce(justssh::ClientConfigBuilder) -> justssh::ClientConfigBuilder,
) -> Option<justssh::Algorithms> {
    let (addr, user, password) = target(var)?;
    let io = TcpStream::connect(&addr).await.unwrap();
    let mut client = Client::new(edit(ClientConfig::builder(&user)).build());
    let mut broker = Broker {
        password: password.clone(),
        prompts: Vec::new(),
        host_key: None,
    };
    let connected = justssh_tokio::connect(
        io,
        &mut client,
        &Deadlines::new(),
        &[AuthMethod::Password(Zeroizing::new(password))],
        &mut broker,
    )
    .await
    .unwrap();
    assert!(
        matches!(connected, Connected::Authenticated { .. }),
        "{var} {label}: {connected:?}"
    );
    Some(client.handshake().negotiated().unwrap().clone())
}

const CTR_MACS: &[&str] = &[
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha1",
    "hmac-sha1-96",
];

#[tokio::test]
async fn the_client_logs_in_to_sshd_under_each_key_exchange_cipher_and_mac() {
    for kex in [
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group14-sha1",
    ] {
        let Some(algs) = password_login_with(
            "JUSTSSH_SSHD_PASSWORD_ADDR",
            kex,
            "aes128-ctr",
            "hmac-sha2-256",
        )
        .await
        else {
            return;
        };
        assert_eq!(algs.kex(), kex);
    }
    for cipher in [
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
        "chacha20-poly1305@openssh.com",
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
    ] {
        let algs = password_login_with(
            "JUSTSSH_SSHD_PASSWORD_ADDR",
            "curve25519-sha256",
            cipher,
            "hmac-sha2-256",
        )
        .await
        .unwrap();
        assert_eq!(algs.cipher_server_to_client(), cipher);
    }
    for mac in CTR_MACS {
        let algs = password_login_with(
            "JUSTSSH_SSHD_PASSWORD_ADDR",
            "curve25519-sha256",
            "aes256-ctr",
            mac,
        )
        .await
        .unwrap();
        assert_eq!(algs.mac_server_to_client(), Some(*mac));
    }
}

#[tokio::test]
async fn the_client_logs_in_to_openssh_9_9_with_mlkem768x25519() {
    let Some(algs) = password_login_with(
        "JUSTSSH_SSHD_MLKEM_ADDR",
        "mlkem768x25519-sha256",
        "aes128-gcm@openssh.com",
        "hmac-sha2-256",
    )
    .await
    else {
        return;
    };
    assert_eq!(algs.kex(), "mlkem768x25519-sha256");
}

#[tokio::test]
async fn the_client_logs_in_to_sshd_without_strict_kex() {
    for mac in ["hmac-sha2-256", "hmac-sha2-256-etm@openssh.com"] {
        let Some(algs) = password_login_offering(
            "JUSTSSH_SSHD_PASSWORD_ADDR",
            "curve25519-sha256",
            "aes128-ctr",
            mac,
            false,
        )
        .await
        else {
            return;
        };
        assert!(!algs.strict_kex(), "{mac}");
    }
}

#[tokio::test]
async fn the_client_verifies_each_host_key_algorithm_of_sshd() {
    for (var, algorithms) in [
        (
            "JUSTSSH_SSHD_HOSTKEYS_ADDR",
            &[
                "ssh-rsa",
                "rsa-sha2-256",
                "rsa-sha2-512",
                "ecdsa-sha2-nistp384",
                "ecdsa-sha2-nistp521",
                "ssh-ed25519",
            ][..],
        ),
        (
            "JUSTSSH_SSHD_RHEL9_ADDR",
            &[
                "rsa-sha2-256",
                "rsa-sha2-512",
                "ecdsa-sha2-nistp256",
                "ssh-ed25519",
            ][..],
        ),
        (
            "JUSTSSH_SSHD_MLKEM_ADDR",
            &[
                "rsa-sha2-256",
                "rsa-sha2-512",
                "ecdsa-sha2-nistp256",
                "ssh-ed25519",
            ][..],
        ),
    ] {
        for algorithm in algorithms {
            let Some(algs) =
                password_login_configured(var, algorithm, |b| b.host_key_algorithms(&[algorithm]))
                    .await
            else {
                break;
            };
            assert_eq!(algs.host_key(), *algorithm, "{var}");
        }
    }
}

/// The client offering only chacha20-poly1305, whose nonce is the sequence number, so a sequence
/// number that is not reset as strict KEX asks fails the next packet; AES-GCM would not show it.
fn chacha(b: justssh::ClientConfigBuilder) -> justssh::ClientConfigBuilder {
    b.algorithms(
        &["curve25519-sha256"],
        &["chacha20-poly1305@openssh.com"],
        &["hmac-sha2-256"],
    )
}

/// Runs five commands, each printing 60,000 bytes, on the sshd in `var` with the client
/// configured by `edit`; the host keys accepted on key re-exchanges meanwhile.
async fn large_outputs_from(
    var: &str,
    edit: impl FnOnce(justssh::ClientConfigBuilder) -> justssh::ClientConfigBuilder,
) -> Option<usize> {
    let (addr, user, password) = target(var)?;
    let mut session = session_configured(&addr, &user, &password, edit).await;
    let mut rekeys = 0;
    for _ in 0..5 {
        let run = exec(&mut session, "head -c 60000 /dev/zero").await;
        assert_eq!((run.stdout.len(), run.status), (60_000, 0));
        rekeys += run.rekeys;
    }
    Some(rekeys)
}

#[tokio::test]
async fn the_client_answers_the_rekeys_an_sshd_with_a_low_rekey_limit_starts() {
    let Some(rekeys) = large_outputs_from("JUSTSSH_SSHD_REKEY_ADDR", chacha).await else {
        return;
    };
    assert!(rekeys > 10, "{rekeys} rekeys");
}

#[tokio::test]
async fn sshd_answers_the_rekeys_the_client_starts_after_a_low_threshold() {
    let Some(rekeys) = large_outputs_from("JUSTSSH_SSHD_PASSWORD_ADDR", |b| {
        chacha(b).rekey_threshold(4096)
    })
    .await
    else {
        return;
    };
    assert!(rekeys >= 4, "{rekeys} rekeys");
}
