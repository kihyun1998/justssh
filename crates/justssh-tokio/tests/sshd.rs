//! `connect` against real OpenSSH servers: one taking `password`, one taking only
//! keyboard-interactive through PAM. CI starts both (`.github/workflows/test.yml`) and names them
//! in `JUSTSSH_SSHD_PASSWORD_ADDR` and `JUSTSSH_SSHD_PAM_ADDR`, with the account in
//! `JUSTSSH_SSHD_USER` and `JUSTSSH_SSHD_SECRET`. Without them each test is skipped, unless
//! `JUSTSSH_REQUIRE_SSHD` is set.

use justssh::{Client, ClientConfig, InfoRequest, Phase, Zeroizing};
use justssh_tokio::{AuthMethod, ClientHandler, Connected, Deadlines};
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
