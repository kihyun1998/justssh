//! justssh against x/crypto/ssh v0.55 (`ci/go-interop`): the lists each side offers, and every key
//! exchange, cipher, MAC and host key algorithm in both directions. Without `go` each test is skipped, unless
//! `JUSTSSH_REQUIRE_GO` is set.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::Duration;

use justssh::{
    Action, Algorithms, Client, ClientConfig, DisconnectReason, EcdsaCurve, HostKey, InfoRequest,
    KexInitRecord, PrivateKey, Server, ServerConfig, Zeroizing,
};
use justssh_tokio::{Accepted, AuthMethod, ClientHandler, Connected, Deadlines, Session};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio::time::timeout;

#[path = "../../justssh/tests/common/test_keys.rs"]
mod test_keys;

const LIMIT: Duration = Duration::from_secs(60);

/// The built harness, or `None` to skip.
fn harness() -> Option<PathBuf> {
    static BUILT: OnceLock<Option<PathBuf>> = OnceLock::new();
    BUILT
        .get_or_init(|| {
            let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../ci/go-interop");
            let out = std::env::temp_dir().join(format!(
                "justssh-go-interop{}",
                std::env::consts::EXE_SUFFIX
            ));
            let built = std::process::Command::new("go")
                .args(["build", "-o"])
                .arg(&out)
                .arg(".")
                .current_dir(&dir)
                .status()
                .is_ok_and(|s| s.success());
            if !built {
                assert!(
                    std::env::var_os("JUSTSSH_REQUIRE_GO").is_none(),
                    "JUSTSSH_REQUIRE_GO is set but ci/go-interop does not build"
                );
                eprintln!("skipped: go is not available");
                return None;
            }
            Some(out)
        })
        .clone()
}

struct AcceptAll;

impl ClientHandler for AcceptAll {
    async fn check_host_key(&mut self, _key: &[u8]) -> bool {
        true
    }

    async fn answer(&mut self, _request: &InfoRequest) -> Vec<Zeroizing<Vec<u8>>> {
        Vec::new()
    }
}

fn args(kex: &str, cipher: &str, mac: &str) -> Vec<String> {
    let mut a = Vec::new();
    for (flag, value) in [("-kex", kex), ("-cipher", cipher), ("-mac", mac)] {
        if !value.is_empty() {
            a.push(flag.to_owned());
            a.push(value.to_owned());
        }
    }
    a
}

/// A Go client with `kex`, `cipher` and `mac` (empty for its defaults) against the justssh
/// server; the server once it authenticated the client.
async fn go_client(go: &PathBuf, kex: &str, cipher: &str, mac: &str) -> Server {
    let config = ServerConfig::builder(HostKey::ed25519_from_seed(Zeroizing::new([7; 32]))).build();
    go_client_with(go, args(kex, cipher, mac), config).await
}

/// A Go client with the flags `args` against a justssh server with `config`; the server once it
/// authenticated the client.
async fn go_client_with(go: &PathBuf, args: Vec<String>, config: ServerConfig) -> Server {
    let label = args.join(" ");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let child = Command::new(go)
        .arg("client")
        .args(["-addr", &addr])
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let (stream, _) = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
    let mut server = Server::new(config);
    let accepted = timeout(
        LIMIT,
        justssh_tokio::accept(stream, &mut server, &Deadlines::new(), |r| {
            let ok = r.user() == b"alice" && r.password() == b"pw";
            async move { ok.then_some(()) }
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        matches!(accepted, Accepted::Authenticated { .. }),
        "{label}: {accepted:?}"
    );
    let out = timeout(LIMIT, child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        out.status.success(),
        "Go client {label}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    server
}

/// The justssh client against a Go server with `kex`, `cipher` and `mac` (empty for its
/// defaults); the client once authenticated.
async fn go_server(go: &PathBuf, kex: &str, cipher: &str, mac: &str) -> Client {
    go_server_offering(go, kex, cipher, mac, true).await
}

/// As [`go_server`], the client offering strict KEX only when `strict`.
async fn go_server_offering(
    go: &PathBuf,
    kex: &str,
    cipher: &str,
    mac: &str,
    strict: bool,
) -> Client {
    let config = ClientConfig::builder(b"alice").strict_kex(strict).build();
    go_server_with(go, args(kex, cipher, mac), config).await
}

/// The justssh client with `config` against a Go server with the flags `args`; the client once
/// authenticated.
async fn go_server_with(go: &PathBuf, args: Vec<String>, config: ClientConfig) -> Client {
    let label = args.join(" ");
    let mut child = Command::new(go)
        .arg("server")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let port = timeout(LIMIT, lines.next_line())
        .await
        .unwrap()
        .unwrap()
        .expect("no port from the Go server");
    let io = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let mut client = Client::new(config);
    let connected = timeout(
        LIMIT,
        justssh_tokio::connect(
            io,
            &mut client,
            &Deadlines::new(),
            &[AuthMethod::Password(Zeroizing::new(b"pw".to_vec()))],
            &mut AcceptAll,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        matches!(connected, Connected::Authenticated { .. }),
        "Go server {label}: {connected:?}"
    );
    let line = timeout(LIMIT, lines.next_line()).await.unwrap().unwrap();
    assert_eq!(line.as_deref(), Some("authenticated"));
    client
}

/// A KEXINIT's key exchange, cipher and MAC lists, without the strict KEX and ext-info markers.
fn lists(k: &KexInitRecord) -> [Vec<String>; 5] {
    let m = k.message();
    [
        m.kex_algorithms
            .iter()
            .filter(|n| !n.starts_with("kex-strict-") && !n.starts_with("ext-info-"))
            .cloned()
            .collect(),
        m.encryption_algorithms_client_to_server.clone(),
        m.encryption_algorithms_server_to_client.clone(),
        m.mac_algorithms_client_to_server.clone(),
        m.mac_algorithms_server_to_client.clone(),
    ]
}

#[tokio::test]
async fn the_server_offers_what_a_go_client_offers() {
    let Some(go) = harness() else { return };
    let server = go_client(&go, "", "", "").await;
    let h = server.handshake();
    assert_eq!(
        lists(h.local_kexinit().unwrap()),
        lists(h.peer_kexinit().unwrap())
    );
}

#[tokio::test]
async fn the_client_offers_what_a_go_server_offers() {
    let Some(go) = harness() else { return };
    let client = go_server(&go, "", "", "").await;
    let h = client.handshake();
    assert_eq!(
        lists(h.local_kexinit().unwrap()),
        lists(h.peer_kexinit().unwrap())
    );
}

const KEX: &[&str] = &[
    "mlkem768x25519-sha256",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group14-sha1",
];
const CIPHERS: &[&str] = &[
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
    "chacha20-poly1305@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
];
const MACS: &[&str] = &[
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha1",
    "hmac-sha1-96",
];

/// Every key exchange, cipher, and MAC under AES-CTR, as `(kex, cipher, mac)` for the Go side.
fn combinations() -> Vec<(&'static str, &'static str, &'static str)> {
    let mut all: Vec<_> = KEX.iter().map(|k| (*k, "", "")).collect();
    all.extend(CIPHERS.iter().map(|c| ("", *c, "")));
    all.extend(MACS.iter().map(|m| ("", "aes128-ctr", *m)));
    all
}

fn check(algs: &Algorithms, kex: &str, cipher: &str, mac: &str) {
    if !kex.is_empty() {
        assert_eq!(algs.kex(), kex);
    }
    if !cipher.is_empty() {
        assert_eq!(algs.cipher_client_to_server(), cipher);
        assert_eq!(algs.cipher_server_to_client(), cipher);
    }
    if !mac.is_empty() {
        assert_eq!(algs.mac_client_to_server(), Some(mac));
        assert_eq!(algs.mac_server_to_client(), Some(mac));
    }
}

#[tokio::test]
async fn a_go_client_connects_to_the_server_under_each_algorithm() {
    let Some(go) = harness() else { return };
    for (kex, cipher, mac) in combinations() {
        let server = go_client(&go, kex, cipher, mac).await;
        check(server.handshake().negotiated().unwrap(), kex, cipher, mac);
    }
}

#[tokio::test]
async fn the_client_connects_to_a_go_server_under_each_algorithm() {
    let Some(go) = harness() else { return };
    for (kex, cipher, mac) in combinations() {
        let client = go_server(&go, kex, cipher, mac).await;
        check(client.handshake().negotiated().unwrap(), kex, cipher, mac);
    }
}

#[tokio::test]
async fn the_client_connects_to_a_go_server_without_strict_kex() {
    let Some(go) = harness() else { return };
    for mac in ["hmac-sha2-256", "hmac-sha2-256-etm@openssh.com"] {
        let client = go_server_offering(&go, "", "aes128-ctr", mac, false).await;
        let algs = client.handshake().negotiated().unwrap();
        check(algs, "", "aes128-ctr", mac);
        assert!(!algs.strict_kex(), "{mac}");
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn rsa() -> PrivateKey {
    PrivateKey::rsa(
        &hex(test_keys::RSA_N),
        &hex(test_keys::RSA_E),
        Zeroizing::new(hex(test_keys::RSA_D)),
        Zeroizing::new(hex(test_keys::RSA_P)),
        Zeroizing::new(hex(test_keys::RSA_Q)),
    )
    .unwrap()
}

fn ed25519() -> HostKey {
    HostKey::ed25519_from_seed(Zeroizing::new([7; 32]))
}

/// The Go broker's host keys: ed25519, then RSA offered only as `ssh-rsa`.
fn broker_config() -> ServerConfig {
    ServerConfig::builder(ed25519())
        .host_key(HostKey::new(rsa()).with_algorithms(&["ssh-rsa"]).unwrap())
        .build()
}

const HOST_KEY_ALGORITHMS: &[&str] = &[
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-256",
    "rsa-sha2-512",
    "ssh-rsa",
    "ssh-ed25519",
];

fn host_key_algorithms(k: &KexInitRecord) -> Vec<String> {
    k.message().server_host_key_algorithms.clone()
}

#[tokio::test]
async fn the_server_offers_the_go_brokers_host_keys_as_a_go_server_does() {
    let Some(go) = harness() else { return };
    let client = go_server_with(
        &go,
        vec!["-hostkeys".into(), "broker".into()],
        ClientConfig::builder(b"alice").build(),
    )
    .await;
    let go_offers = host_key_algorithms(client.handshake().peer_kexinit().unwrap());
    let server = go_client_with(&go, Vec::new(), broker_config()).await;
    let we_offer = host_key_algorithms(server.handshake().local_kexinit().unwrap());
    assert_eq!(we_offer, go_offers);
    assert_eq!(we_offer, ["ssh-ed25519", "ssh-rsa"]);
}

#[tokio::test]
async fn a_go_client_offering_only_ssh_rsa_connects_to_the_go_brokers_host_keys() {
    let Some(go) = harness() else { return };
    let server = go_client_with(
        &go,
        vec!["-hostkeyalgs".into(), "ssh-rsa".into()],
        broker_config(),
    )
    .await;
    assert_eq!(
        server.handshake().negotiated().unwrap().host_key(),
        "ssh-rsa"
    );
}

#[tokio::test]
async fn a_go_client_verifies_each_host_key_algorithm_of_the_server() {
    let Some(go) = harness() else { return };
    for algorithm in HOST_KEY_ALGORITHMS {
        let config = ServerConfig::builder(ed25519())
            .host_key(HostKey::new(rsa()))
            .host_key(HostKey::new(
                PrivateKey::ecdsa(EcdsaCurve::P256, Zeroizing::new(vec![1; 32])).unwrap(),
            ))
            .host_key(HostKey::new(
                PrivateKey::ecdsa(EcdsaCurve::P384, Zeroizing::new(vec![1; 48])).unwrap(),
            ))
            .host_key(HostKey::new(
                PrivateKey::ecdsa(EcdsaCurve::P521, Zeroizing::new(vec![1; 66])).unwrap(),
            ))
            .build();
        let server = go_client_with(
            &go,
            vec!["-hostkeyalgs".into(), (*algorithm).into()],
            config,
        )
        .await;
        assert_eq!(
            server.handshake().negotiated().unwrap().host_key(),
            *algorithm
        );
    }
}

#[tokio::test]
async fn the_client_verifies_each_host_key_algorithm_of_a_go_server() {
    let Some(go) = harness() else { return };
    for algorithm in HOST_KEY_ALGORITHMS {
        let client = go_server_with(
            &go,
            vec!["-hostkeys".into(), "all".into()],
            ClientConfig::builder(b"alice")
                .host_key_algorithms(&[algorithm])
                .build(),
        )
        .await;
        assert_eq!(
            client.handshake().negotiated().unwrap().host_key(),
            *algorithm
        );
    }
}

#[tokio::test]
async fn the_client_offers_a_go_clients_host_key_algorithms_without_certificates_and_dsa() {
    let Some(go) = harness() else { return };
    let server = go_client(&go, "", "", "").await;
    let go_offers: Vec<String> = host_key_algorithms(server.handshake().peer_kexinit().unwrap())
        .into_iter()
        .filter(|a| !a.contains("-cert-") && a != "ssh-dss")
        .collect();
    let client = go_server(&go, "", "", "").await;
    let we_offer = host_key_algorithms(client.handshake().local_kexinit().unwrap());
    assert_eq!(we_offer, go_offers);
}

/// The cipher the rekey tests run under: its nonce is the sequence number, so a sequence number
/// that is not reset as strict KEX asks fails the next packet. AES-GCM would not show it.
const CHACHA: &str = "chacha20-poly1305@openssh.com";

/// Whether a KEXINIT is one of a key re-exchange: without the strict KEX and ext-info markers.
fn rekeyed(k: &KexInitRecord) -> bool {
    !k.message()
        .kex_algorithms
        .iter()
        .any(|n| n.starts_with("kex-strict-") || n.starts_with("ext-info-"))
}

/// A Go client with `args` against a justssh server with `config`, run through the connection
/// protocol until the client leaves; the global requests answered, and whether the server's last
/// KEXINIT was one of a key re-exchange.
async fn go_client_session(go: &PathBuf, args: Vec<String>, config: ServerConfig) -> (usize, bool) {
    let label = args.join(" ");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let child = Command::new(go)
        .arg("client")
        .args(["-addr", &addr])
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let (stream, _) = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
    let mut server = Server::new(config);
    let accepted = timeout(
        LIMIT,
        justssh_tokio::accept(stream, &mut server, &Deadlines::new(), |r| {
            let ok = r.user() == b"alice" && r.password() == b"pw";
            async move { ok.then_some(()) }
        }),
    )
    .await
    .unwrap()
    .unwrap();
    let Accepted::Authenticated { io, events, .. } = accepted else {
        panic!("{label}: {accepted:?}");
    };
    let mut session = Session::new(io, server, events);
    let mut answered = 0;
    loop {
        match timeout(LIMIT, session.next()).await.unwrap() {
            Ok(Some(Action::GlobalRequest(r))) => {
                answered += 1;
                if let Some(token) = r.reply() {
                    session
                        .reply_global(token, false, Vec::new())
                        .await
                        .unwrap();
                }
            }
            Ok(Some(Action::Closed(_)) | None) | Err(_) => break,
            Ok(Some(_)) => {}
        }
    }
    let out = timeout(LIMIT, child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        out.status.success(),
        "Go client {label}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let local = session.endpoint().handshake().local_kexinit().unwrap();
    (answered, rekeyed(local))
}

/// The justssh client with `config` against a Go server with `args` that stays, sending
/// `requests` global requests one after another; the replies, and the host keys accepted on key
/// re-exchanges meanwhile.
async fn go_server_session(
    go: &PathBuf,
    args: Vec<String>,
    config: ClientConfig,
    requests: usize,
) -> (usize, usize) {
    let label = args.join(" ");
    let mut child = Command::new(go)
        .arg("server")
        .arg("-serve")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let port = timeout(LIMIT, lines.next_line())
        .await
        .unwrap()
        .unwrap()
        .expect("no port from the Go server");
    let io = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let mut client = Client::new(config);
    let connected = timeout(
        LIMIT,
        justssh_tokio::connect(
            io,
            &mut client,
            &Deadlines::new(),
            &[AuthMethod::Password(Zeroizing::new(b"pw".to_vec()))],
            &mut AcceptAll,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let Connected::Authenticated { io, events } = connected else {
        panic!("Go server {label}: {connected:?}");
    };
    let mut session = Session::new(io, client, events);
    let (mut replies, mut rekeys) = (0, 0);
    for _ in 0..requests {
        let token = session
            .global_request("justssh-test@example.com", true, vec![0; 1024])
            .await
            .unwrap();
        loop {
            match timeout(LIMIT, session.next()).await.unwrap().unwrap() {
                Some(Action::VerifyHostKey { .. }) => {
                    rekeys += 1;
                    session.answer_host_key(true).await.unwrap();
                }
                Some(Action::GlobalRequestReply { token: t, .. }) if Some(t) == token => {
                    replies += 1;
                    break;
                }
                Some(Action::Closed(c)) => panic!("Go server {label}: {c:?}"),
                None => panic!("Go server {label}: ended"),
                Some(_) => {}
            }
        }
    }
    session
        .disconnect(DisconnectReason::BY_APPLICATION, "done")
        .await
        .unwrap();
    let _ = timeout(LIMIT, child.wait()).await;
    (replies, rekeys)
}

#[tokio::test]
async fn the_server_answers_the_rekeys_a_go_client_starts() {
    let Some(go) = harness() else { return };
    let args = vec![
        "-rekey".into(),
        "4096".into(),
        "-requests".into(),
        "100".into(),
    ];
    let (answered, rekeyed) = go_client_session(&go, args, broker_config()).await;
    assert_eq!(answered, 100);
    assert!(rekeyed);
}

#[tokio::test]
async fn a_go_client_answers_the_rekeys_the_server_starts() {
    let Some(go) = harness() else { return };
    let config = ServerConfig::builder(ed25519())
        .rekey_threshold(4096)
        .build();
    let (answered, rekeyed) = go_client_session(
        &go,
        vec![
            "-cipher".into(),
            CHACHA.into(),
            "-requests".into(),
            "100".into(),
        ],
        config,
    )
    .await;
    assert_eq!(answered, 100);
    assert!(rekeyed);
}

#[tokio::test]
async fn the_client_answers_the_rekeys_a_go_server_starts() {
    let Some(go) = harness() else { return };
    let (replies, rekeys) = go_server_session(
        &go,
        vec![
            "-cipher".into(),
            CHACHA.into(),
            "-rekey".into(),
            "4096".into(),
        ],
        ClientConfig::builder(b"alice").build(),
        100,
    )
    .await;
    assert_eq!(replies, 100);
    assert!(rekeys > 10, "{rekeys} rekeys");
}

#[tokio::test]
async fn a_go_server_answers_the_rekeys_the_client_starts() {
    let Some(go) = harness() else { return };
    let (replies, rekeys) = go_server_session(
        &go,
        Vec::new(),
        ClientConfig::builder(b"alice")
            .rekey_threshold(4096)
            .build(),
        100,
    )
    .await;
    assert_eq!(replies, 100);
    assert!(rekeys > 10, "{rekeys} rekeys");
}

#[tokio::test]
async fn a_go_client_naming_requests_and_a_channel_type_in_bytes_that_are_not_utf8_gets_answers() {
    let Some(go) = harness() else {
        return;
    };
    const NAME: &[u8] = b"x\x80\xe9@y";
    let hex: String = NAME.iter().map(|b| format!("{b:02x}")).collect();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let child = Command::new(&go)
        .arg("client")
        .args(["-addr", &addr, "-namehex", &hex])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let (stream, _) = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
    let mut server = Server::new(ServerConfig::builder(ed25519()).build());
    let accepted = timeout(
        LIMIT,
        justssh_tokio::accept(stream, &mut server, &Deadlines::new(), |r| {
            let ok = r.user() == b"alice" && r.password() == b"pw";
            async move { ok.then_some(()) }
        }),
    )
    .await
    .unwrap()
    .unwrap();
    let Accepted::Authenticated { io, events, .. } = accepted else {
        panic!("{accepted:?}");
    };
    let mut session = Session::new(io, server, events);
    let mut names = Vec::new();
    loop {
        match timeout(LIMIT, session.next()).await.unwrap() {
            Ok(Some(Action::GlobalRequest(r))) => {
                names.push(r.kind().clone());
                if let Some(token) = r.reply() {
                    session.reply_global(token, true, Vec::new()).await.unwrap();
                }
            }
            Ok(Some(Action::ChannelOpenRequest(r))) => {
                names.push(r.kind().clone());
                session
                    .accept_channel(r.channel(), Vec::new())
                    .await
                    .unwrap();
            }
            Ok(Some(Action::ChannelRequest(r))) => {
                names.push(r.kind().clone());
                if let Some(token) = r.reply() {
                    session.reply(token, true).await.unwrap();
                }
            }
            Ok(Some(Action::ChannelClosed { .. }))
            | Ok(Some(Action::Closed(_)) | None)
            | Err(_) => {
                break;
            }
            Ok(Some(_)) => {}
        }
    }
    let out = timeout(LIMIT, child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        out.status.success(),
        "Go client: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let names: Vec<&[u8]> = names.iter().map(|n| n.as_bytes()).collect();
    assert_eq!(names, [NAME; 3]);
}

/// What the harness printed for `args`, which must succeed.
fn go_output(go: &PathBuf, args: &[&str]) -> String {
    let out = std::process::Command::new(go).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "go-interop {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// `blob`'s authorized_keys line without a comment, as Go's `MarshalAuthorizedKey` writes it.
fn authorized_line(blob: &[u8]) -> String {
    let key_type = justssh_wire::Reader::new(blob).utf8().unwrap().to_owned();
    format!(
        "{key_type} {}\n",
        <base64ct::Base64 as base64ct::Encoding>::encode_string(blob)
    )
}

/// A Go client with `args` against a server with `config`; what the client printed.
async fn go_client_printing(go: &PathBuf, args: &[&str], config: ServerConfig) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let child = Command::new(go)
        .arg("client")
        .args(["-addr", &addr])
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let (stream, _) = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
    let mut server = Server::new(config);
    let accepted = timeout(
        LIMIT,
        justssh_tokio::accept(stream, &mut server, &Deadlines::new(), |r| {
            let ok = r.user() == b"alice" && r.password() == b"pw";
            async move { ok.then_some(()) }
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        matches!(accepted, Accepted::Authenticated { .. }),
        "{accepted:?}"
    );
    let out = timeout(LIMIT, child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        out.status.success(),
        "Go client: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[tokio::test]
async fn the_server_presents_the_host_key_a_go_broker_wrote_as_the_go_broker_does() {
    let Some(go) = harness() else {
        return;
    };
    for (key_type, only) in [("ed25519", None), ("rsa", Some("ssh-rsa"))] {
        let path = std::env::temp_dir().join(format!(
            "justssh-go-hostkey-{key_type}-{}",
            std::process::id()
        ));
        let file = path.to_str().unwrap();
        let go_public = go_output(&go, &["hostkey", "-type", key_type, "-out", file]);
        let text = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let key = justssh_keys::KeyFile::from_openssh(&text, None).unwrap();
        assert_eq!(key.comment(), b"acwbroker");
        let mut host_key = HostKey::new(key.private_key().clone());
        let mut args = vec!["-printhostkey"];
        if let Some(algorithm) = only {
            host_key = host_key.with_algorithms(&[algorithm]).unwrap();
            args.extend(["-hostkeyalgs", algorithm]);
        }
        let printed = go_client_printing(&go, &args, ServerConfig::builder(host_key).build()).await;
        assert_eq!(
            printed.lines().next(),
            go_public.lines().next(),
            "{key_type}"
        );
    }
}

#[tokio::test]
async fn go_reads_the_key_files_justssh_keys_writes() {
    let Some(go) = harness() else {
        return;
    };
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../justssh-keys/tests/keys");
    for (name, passphrase) in [
        ("ed25519", None),
        ("ed25519-pass", Some(&b"correct horse"[..])),
        ("ecdsa256", None),
        ("ecdsa384", None),
        ("ecdsa521-pass-cbc", Some(&b"correct horse"[..])),
        ("rsa2048", None),
        ("rsa3072-pass", Some(&b"correct horse"[..])),
    ] {
        let key = justssh_keys::KeyFile::from_openssh(
            &std::fs::read(dir.join(name)).unwrap(),
            passphrase,
        )
        .unwrap();
        let path = std::env::temp_dir().join(format!("justssh-key-{name}-{}", std::process::id()));
        std::fs::write(&path, key.to_openssh().as_bytes()).unwrap();
        let go_public = go_output(&go, &["readkey", "-in", path.to_str().unwrap()]);
        let _ = std::fs::remove_file(&path);
        assert_eq!(
            go_public,
            authorized_line(&key.private_key().plain_public_blob()),
            "{name}"
        );
    }
}

#[tokio::test]
async fn justssh_keys_reads_what_ssh_keygen_and_go_read_alike() {
    let Some(go) = harness() else {
        return;
    };
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../justssh-keys/tests/keys");
    for (name, passphrase) in [("ed25519-pass", "correct horse"), ("rsa2048", "")] {
        let path = dir.join(name);
        let go_public = go_output(
            &go,
            &[
                "readkey",
                "-in",
                path.to_str().unwrap(),
                "-passphrase",
                passphrase,
            ],
        );
        let key = justssh_keys::KeyFile::from_openssh(
            &std::fs::read(&path).unwrap(),
            (!passphrase.is_empty()).then_some(passphrase.as_bytes()),
        )
        .unwrap();
        assert_eq!(
            go_public,
            authorized_line(&key.private_key().plain_public_blob()),
            "{name}"
        );
    }
}

#[path = "../../justssh/tests/common/certs.rs"]
mod certs;

#[tokio::test]
async fn go_takes_or_refuses_each_certificate_as_the_core_does() {
    let Some(go) = harness() else {
        return;
    };
    let mut differ = Vec::new();
    for (name, blob, valid) in certs::variants() {
        let hex: String = blob.iter().map(|b| format!("{b:02x}")).collect();
        let out = std::process::Command::new(&go)
            .args(["readcert", "-hex", &hex])
            .output()
            .unwrap();
        if out.status.success() != valid {
            differ.push(format!(
                "Go: {name}: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        if certs::certified_key().with_certificate(blob).is_ok() != valid {
            differ.push(format!("core: {name}"));
        }
    }
    assert!(differ.is_empty(), "{differ:#?}");
}

#[path = "../../justssh-keys/tests/common/lines.rs"]
mod lines;

#[tokio::test]
async fn go_reads_each_certificate_line_as_justssh_keys_does() {
    let Some(go) = harness() else {
        return;
    };
    let cert = certs::Cert::valid().encode();
    let plain = certs::certified_key().plain_public_blob();
    let mut differ = Vec::new();
    for (name, line, _) in lines::lines(&cert, &plain) {
        let path = std::env::temp_dir().join(format!("justssh-cert-line-{}", std::process::id()));
        std::fs::write(&path, &line).unwrap();
        let out = std::process::Command::new(&go)
            .args(["readline", "-in", path.to_str().unwrap()])
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&path);
        let go_read = out.status.success().then(|| {
            let hex = String::from_utf8(out.stdout).unwrap();
            (0..hex.trim().len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex.trim()[i..i + 2], 16).unwrap())
                .collect::<Vec<u8>>()
        });
        let read = justssh_keys::certificate_from_line(line.as_bytes()).ok();
        if go_read != read {
            differ.push(format!(
                "{name}: Go {:?}, justssh-keys {:?}",
                go_read.is_some(),
                read.is_some()
            ));
        }
    }
    assert!(differ.is_empty(), "{differ:#?}");
}
