//! The real OpenSSH client against the justssh server. `ssh` must be on PATH, or named by
//! `JUSTSSH_SSH`; passwords reach it through `SSH_ASKPASS`.

use std::num::NonZeroU32;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use justssh::{
    Closed, DisconnectReason, EcdsaCurve, Error, HostKey, Phase, PrivateKey, Server, ServerConfig,
    ServerConfigBuilder, Zeroizing,
};
use justssh_tokio::{Accepted, Deadlines, Session};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::timeout;

#[path = "../../justssh/tests/common/test_keys.rs"]
mod test_keys;

const LIMIT: Duration = Duration::from_secs(60);
const PASSWORD: &str = "s3cret";

fn config(edit: impl FnOnce(ServerConfigBuilder) -> ServerConfigBuilder) -> ServerConfig {
    edit(ServerConfig::builder(HostKey::ed25519_from_seed(
        Zeroizing::new([7; 32]),
    )))
    .build()
}

/// A script that prints `password`, for `SSH_ASKPASS`.
fn askpass(name: &str, password: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("justssh-askpass-{name}-{}", std::process::id()));
    std::fs::write(&path, format!("#!/bin/sh\necho '{password}'\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    path
}

/// Runs `ssh -vvv` against `port` with `password` and returns its log.
async fn ssh(port: u16, password: &str) -> String {
    ssh_with(
        port,
        password,
        &["-o", "Ciphers=chacha20-poly1305@openssh.com"],
    )
    .await
}

/// `ssh` with `options`, which choose its algorithms.
async fn ssh_with(port: u16, password: &str, options: &[&str]) -> String {
    let known_hosts = std::env::temp_dir().join(format!("justssh-known-hosts-{port}"));
    let askpass = askpass(&port.to_string(), password);
    let ssh = std::env::var("JUSTSSH_SSH").unwrap_or_else(|_| "ssh".to_owned());
    let output = timeout(
        LIMIT,
        Command::new(ssh)
            .args(["-vvv", "-F", "none", "-p", &port.to_string()])
            .args(["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"])
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", known_hosts.display()))
            .args(options)
            .args(["-o", "PreferredAuthentications=password"])
            .args(["-o", "NumberOfPasswordPrompts=1"])
            .env("SSH_ASKPASS", &askpass)
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env("DISPLAY", ":0")
            .stdin(Stdio::null())
            .args(["srv1@10.0.0.5:22@127.0.0.1", "true"])
            .output(),
    )
    .await
    .expect("ssh did not finish")
    .expect("could not run ssh");
    let _ = std::fs::remove_file(&known_hosts);
    let _ = std::fs::remove_file(&askpass);
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The accepted value, or how the connection closed before authentication.
type Outcome = (std::io::Result<Result<String, Closed>>, Server);

/// Accepts one connection and authenticates it, accepting the password `PASSWORD` and handing
/// back the user name as the accepted value.
async fn accept_one(max_auth_tries: u32, gate: Option<Arc<Notify>>) -> (u16, JoinHandle<Outcome>) {
    let limit = NonZeroU32::new(max_auth_tries).unwrap();
    accept_one_with(config(|b| b.max_auth_tries(limit)), gate).await
}

/// As [`accept_one`], for a server with `config`.
async fn accept_one_with(
    config: ServerConfig,
    gate: Option<Arc<Notify>>,
) -> (u16, JoinHandle<Outcome>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut server = Server::new(config);
        let accepted = justssh_tokio::accept(stream, &mut server, &Deadlines::new(), |req| {
            let gate = gate.clone();
            async move {
                if let Some(gate) = gate {
                    gate.notified().await;
                }
                (req.password() == PASSWORD.as_bytes())
                    .then(|| String::from_utf8_lossy(req.user()).into_owned())
            }
        })
        .await;
        // Dropping the stream closes the connection once authenticated.
        let accepted = accepted.map(|a| match a {
            Accepted::Authenticated { value, .. } => Ok(value),
            Accepted::Closed(closed) => Err(closed),
            _ => panic!("unknown outcome"),
        });
        (accepted, server)
    });
    (port, task)
}

async fn finish(task: JoinHandle<Outcome>) -> Outcome {
    timeout(LIMIT, task)
        .await
        .expect("server did not finish")
        .unwrap()
}

fn authenticated(outcome: std::io::Result<Result<String, Closed>>) -> String {
    match outcome.expect("accept failed") {
        Ok(value) => value,
        Err(closed) => panic!("closed instead: {closed:?}"),
    }
}

fn closed(outcome: std::io::Result<Result<String, Closed>>) -> Closed {
    outcome
        .expect("accept failed")
        .expect_err("authenticated instead")
}

#[tokio::test]
async fn openssh_completes_key_exchange_and_reaches_user_authentication() {
    let (port, task) = accept_one(6, None).await;
    let log = ssh(port, "wrong").await;
    for expected in [
        "kex: algorithm: ",
        "will use strict KEX ordering",
        "SSH2_MSG_SERVICE_ACCEPT received",
    ] {
        assert!(log.contains(expected), "missing {expected:?}:\n{log}");
    }
    let (_, server) = finish(task).await;
    let peer = server.handshake().peer_version().unwrap();
    assert!(peer.starts_with("SSH-2.0-OpenSSH"), "peer version {peer}");
}

#[tokio::test]
async fn openssh_receives_the_same_ext_info_as_from_x_crypto_ssh() {
    let (port, task) = accept_one(6, None).await;
    let log = ssh(port, "wrong").await;
    let sig_algs = "server-sig-algs=<ssh-ed25519,sk-ssh-ed25519@openssh.com,\
        sk-ecdsa-sha2-nistp256@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,\
        ecdsa-sha2-nistp521,rsa-sha2-256,rsa-sha2-512,ssh-rsa,ssh-dss>";
    assert!(log.contains(sig_algs), "server-sig-algs differs:\n{log}");
    assert!(
        log.contains("ping@openssh.com=<0>"),
        "no ping extension:\n{log}"
    );
    let ext_info = log.find("SSH2_MSG_EXT_INFO received").expect("no EXT_INFO");
    let accept = log
        .find("service_accept: ssh-userauth")
        .expect("no SERVICE_ACCEPT");
    assert!(
        ext_info < accept,
        "EXT_INFO did not come first after NEWKEYS"
    );
    let _ = finish(task).await;
}

#[tokio::test]
async fn openssh_authenticates_with_the_right_password() {
    let (port, task) = accept_one(1, None).await;
    let log = ssh(port, PASSWORD).await;
    assert!(
        log.contains("Authenticated to 127.0.0.1"),
        "not authenticated:\n{log}"
    );
    let (outcome, server) = finish(task).await;
    assert_eq!(authenticated(outcome), "srv1@10.0.0.5:22");
    assert_eq!(server.phase(), Phase::Connected);
}

#[tokio::test]
async fn a_wrong_password_with_a_limit_of_one_ends_in_too_many_authentication_failures() {
    let (port, task) = accept_one(1, None).await;
    let log = ssh(port, "wrong").await;
    assert!(
        log.contains(":2: too many authentication failures"),
        "no disconnect 2:\n{log}"
    );
    assert_eq!(
        closed(finish(task).await.0),
        Closed::Local {
            reason: DisconnectReason::PROTOCOL_ERROR,
            error: Error::TooManyAuthFailures,
            phase: Phase::Auth,
        }
    );
}

#[tokio::test]
async fn a_pending_verdict_does_not_hold_up_another_connection() {
    let gate = Arc::new(Notify::new());
    let (held_port, held) = accept_one(1, Some(gate.clone())).await;
    let (free_port, free) = accept_one(1, None).await;
    let held_ssh = tokio::spawn(async move { ssh(held_port, PASSWORD).await });

    let log = ssh(free_port, PASSWORD).await;
    assert!(
        log.contains("Authenticated to 127.0.0.1"),
        "not authenticated:\n{log}"
    );
    authenticated(finish(free).await.0);
    assert!(
        !held.is_finished(),
        "the held connection finished before its verdict"
    );

    gate.notify_one();
    let held_log = timeout(LIMIT, held_ssh).await.unwrap().unwrap();
    assert!(
        held_log.contains("Authenticated to 127.0.0.1"),
        "not authenticated:\n{held_log}"
    );
    authenticated(finish(held).await.0);
}

#[tokio::test]
async fn an_auth_deadline_closes_with_the_phase() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut server = Server::new(config(|b| b));
        let deadlines = Deadlines::new().phase(Phase::Auth, Duration::from_secs(3));
        justssh_tokio::accept(stream, &mut server, &deadlines, |_| async {
            std::future::pending::<Option<()>>().await
        })
        .await
    });
    let log = ssh(port, PASSWORD).await;
    assert!(
        log.contains(":11: deadline exceeded"),
        "no deadline disconnect:\n{log}"
    );
    match timeout(LIMIT, task).await.unwrap().unwrap().unwrap() {
        Accepted::Closed(closed) => assert_eq!(
            closed,
            Closed::Local {
                reason: DisconnectReason::BY_APPLICATION,
                error: Error::DeadlineExceeded,
                phase: Phase::Auth,
            }
        ),
        _ => panic!("not closed"),
    }
}

/// The names `ssh -Q query` lists.
fn supported(query: &str) -> Vec<String> {
    let ssh = std::env::var("JUSTSSH_SSH").unwrap_or_else(|_| "ssh".to_owned());
    let out = std::process::Command::new(ssh)
        .args(["-Q", query])
        .output()
        .expect("could not run ssh -Q");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Logs in with `ssh` under `options` and returns its log.
async fn log_in_with(options: &[&str]) -> String {
    let (port, task) = accept_one(6, None).await;
    let log = ssh_with(port, PASSWORD, options).await;
    let (outcome, _) = finish(task).await;
    assert!(
        matches!(outcome, Ok(Ok(_))),
        "{options:?} not authenticated: {outcome:?}
{log}"
    );
    log
}

#[tokio::test]
async fn openssh_connects_under_each_key_exchange_cipher_and_mac() {
    let (kex, ciphers, macs) = (supported("kex"), supported("cipher"), supported("mac"));
    for k in [
        "mlkem768x25519-sha256",
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group14-sha1",
    ] {
        if !kex.iter().any(|s| s == k) {
            eprintln!("skipped: this ssh has no {k}");
            continue;
        }
        let log = log_in_with(&["-o", &format!("KexAlgorithms={k}")]).await;
        assert!(
            log.contains(&format!("kex: algorithm: {k}")),
            "{k}:
{log}"
        );
    }
    for c in [
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
        "chacha20-poly1305@openssh.com",
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
    ] {
        assert!(ciphers.iter().any(|s| s == c), "this ssh has no {c}");
        let log = log_in_with(&["-o", &format!("Ciphers={c}")]).await;
        assert!(
            log.contains(&format!("client->server cipher: {c}")),
            "{c}:
{log}"
        );
    }
    for m in [
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
        "hmac-sha2-256",
        "hmac-sha2-512",
        "hmac-sha1",
        "hmac-sha1-96",
    ] {
        assert!(macs.iter().any(|s| s == m), "this ssh has no {m}");
        let log = log_in_with(&["-o", "Ciphers=aes128-ctr", "-o", &format!("MACs={m}")]).await;
        assert!(
            log.contains(&format!("client->server cipher: aes128-ctr MAC: {m}")),
            "{m}:
{log}"
        );
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

/// Logs in with `ssh` offering only host key algorithm `algorithm` to a server with `config`, and
/// checks that it was the one used.
async fn log_in_under_host_key(config: ServerConfig, algorithm: &str) {
    let (port, task) = accept_one_with(config, None).await;
    let log = ssh_with(
        port,
        PASSWORD,
        &["-o", &format!("HostKeyAlgorithms={algorithm}")],
    )
    .await;
    let (outcome, _) = finish(task).await;
    assert!(
        matches!(outcome, Ok(Ok(_))),
        "{algorithm} not authenticated: {outcome:?}
{log}"
    );
    assert!(
        log.contains(&format!("kex: host key algorithm: {algorithm}")),
        "{algorithm}:
{log}"
    );
}

#[tokio::test]
async fn openssh_verifies_each_host_key_algorithm_of_the_server() {
    let supported = supported("HostKeyAlgorithms");
    for algorithm in [
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "rsa-sha2-256",
        "rsa-sha2-512",
        "ssh-rsa",
        "ssh-ed25519",
    ] {
        assert!(
            supported.iter().any(|s| s == algorithm),
            "this ssh has no {algorithm}"
        );
        let config = config(|b| {
            b.host_key(HostKey::new(rsa()))
                .host_key(HostKey::new(
                    PrivateKey::ecdsa(EcdsaCurve::P256, Zeroizing::new(vec![1; 32])).unwrap(),
                ))
                .host_key(HostKey::new(
                    PrivateKey::ecdsa(EcdsaCurve::P384, Zeroizing::new(vec![1; 48])).unwrap(),
                ))
                .host_key(HostKey::new(
                    PrivateKey::ecdsa(EcdsaCurve::P521, Zeroizing::new(vec![1; 66])).unwrap(),
                ))
        });
        log_in_under_host_key(config, algorithm).await;
    }
}

#[tokio::test]
async fn openssh_offering_only_ssh_rsa_connects_to_the_go_brokers_host_keys() {
    let config = config(|b| b.host_key(HostKey::new(rsa()).with_algorithms(&["ssh-rsa"]).unwrap()));
    log_in_under_host_key(config, "ssh-rsa").await;
}

/// Bytes the server prints for an `exec`.
const OUTPUT: usize = 300_000;

/// Serves one connection with `config`: an `exec` on a session channel prints [`OUTPUT`] bytes
/// and exits 0; everything else is refused.
async fn serve_output(config: ServerConfig) -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut server = Server::new(config);
        let accepted = justssh_tokio::accept(stream, &mut server, &Deadlines::new(), |r| {
            let ok = r.password() == PASSWORD.as_bytes();
            async move { ok.then_some(()) }
        })
        .await
        .unwrap();
        let Accepted::Authenticated { io, events, .. } = accepted else {
            panic!("{accepted:?}");
        };
        let mut session = Session::new(io, server, events);
        loop {
            let Ok(Some(action)) = session.next().await else {
                return;
            };
            match action {
                justssh::Action::ChannelOpenRequest(r) => {
                    session
                        .accept_channel(r.channel(), Vec::new())
                        .await
                        .unwrap();
                }
                justssh::Action::ChannelRequest(r) if r.kind() == "exec" => {
                    let channel = r.channel();
                    if let Some(token) = r.reply() {
                        session.reply(token, true).await.unwrap();
                    }
                    for _ in 0..OUTPUT / 1000 {
                        session.data(channel, &[b'x'; 1000]).await.unwrap();
                    }
                    // A second of handling input before the channel closes.
                    let _ = timeout(Duration::from_secs(1), async {
                        while let Ok(Some(_)) = session.next().await {}
                    })
                    .await;
                    session
                        .request(channel, "exit-status", false, 0u32.to_be_bytes().to_vec())
                        .await
                        .unwrap();
                    session.eof(channel).await.unwrap();
                    session.close(channel).await.unwrap();
                }
                justssh::Action::ChannelRequest(r) => {
                    if let Some(token) = r.reply() {
                        session.reply(token, false).await.unwrap();
                    }
                }
                justssh::Action::GlobalRequest(r) => {
                    if let Some(token) = r.reply() {
                        session
                            .reply_global(token, false, Vec::new())
                            .await
                            .unwrap();
                    }
                }
                justssh::Action::Closed(_) => return,
                _ => {}
            }
        }
    });
    (port, task)
}

/// `ssh` with `options` running a command on a server from [`serve_output`]; the bytes it
/// printed and its log.
async fn ssh_output(config: ServerConfig, options: &[&str]) -> (usize, String) {
    let (port, task) = serve_output(config).await;
    let askpass = askpass(&format!("out{port}"), PASSWORD);
    let known_hosts = std::env::temp_dir().join(format!("justssh-known-hosts-out-{port}"));
    let ssh = std::env::var("JUSTSSH_SSH").unwrap_or_else(|_| "ssh".to_owned());
    let output = timeout(
        LIMIT,
        Command::new(ssh)
            .args(["-vvv", "-F", "none", "-p", &port.to_string()])
            .args(["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"])
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", known_hosts.display()))
            .args(options)
            .args(["-o", "PreferredAuthentications=password"])
            .args(["-o", "NumberOfPasswordPrompts=1"])
            .env("SSH_ASKPASS", &askpass)
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env("DISPLAY", ":0")
            .stdin(Stdio::null())
            .args(["justssh@127.0.0.1", "print"])
            .output(),
    )
    .await
    .expect("ssh did not finish")
    .expect("could not run ssh");
    let _ = std::fs::remove_file(&known_hosts);
    let _ = std::fs::remove_file(&askpass);
    let log = String::from_utf8_lossy(&output.stderr).into_owned();
    timeout(LIMIT, task)
        .await
        .expect("server did not finish")
        .unwrap();
    (output.stdout.len(), log)
}

#[tokio::test]
async fn the_server_answers_the_rekeys_openssh_starts_with_a_low_rekey_limit() {
    let (printed, log) = ssh_output(config(|b| b), &["-o", "RekeyLimit=4K"]).await;
    assert_eq!(printed, OUTPUT, "{log}");
    let exchanges = log.matches("SSH2_MSG_NEWKEYS received").count();
    assert!(
        exchanges >= 2,
        "{exchanges} key exchanges:
{log}"
    );
}

#[tokio::test]
async fn openssh_answers_the_rekeys_the_server_starts_after_a_low_threshold() {
    let (printed, log) = ssh_output(config(|b| b.rekey_threshold(4096)), &[]).await;
    assert_eq!(printed, OUTPUT, "{log}");
    let exchanges = log.matches("SSH2_MSG_NEWKEYS received").count();
    assert!(
        exchanges > 10,
        "{exchanges} key exchanges:
{log}"
    );
}
