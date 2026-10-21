//! justssh against x/crypto/ssh v0.55 (`ci/go-interop`): the lists each side offers, and every key
//! exchange, cipher, MAC and host key algorithm in both directions. Without `go` each test is skipped, unless
//! `JUSTSSH_REQUIRE_GO` is set.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::Duration;

use justssh::{
    Algorithms, Client, ClientConfig, EcdsaCurve, HostKey, InfoRequest, KexInitRecord, PrivateKey,
    Server, ServerConfig, Zeroizing,
};
use justssh_tokio::{Accepted, AuthMethod, ClientHandler, Connected, Deadlines};
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
