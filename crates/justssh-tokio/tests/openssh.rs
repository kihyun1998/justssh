//! The real OpenSSH client against the justssh server. `ssh` must be on PATH, or named by
//! `JUSTSSH_SSH`.

use std::time::Duration;

use justssh::{Closed, DisconnectReason, HostKey, Server, ServerConfig, Zeroizing};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(60);

#[tokio::test]
async fn openssh_completes_key_exchange_and_reaches_user_authentication() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let config =
            ServerConfig::builder(HostKey::ed25519_from_seed(Zeroizing::new([7; 32]))).build();
        let mut server = Server::new(config);
        let closed = justssh_tokio::serve(stream, &mut server).await;
        (closed, server)
    });

    let known_hosts = std::env::temp_dir().join(format!("justssh-known-hosts-{port}"));
    let ssh = std::env::var("JUSTSSH_SSH").unwrap_or_else(|_| "ssh".to_owned());
    let output = timeout(
        LIMIT,
        Command::new(ssh)
            .args(["-vvv", "-F", "none", "-p", &port.to_string()])
            .args(["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no"])
            .args(["-o", "ConnectTimeout=10"])
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", known_hosts.display()))
            .args(["-o", "Ciphers=chacha20-poly1305@openssh.com"])
            .args(["tester@127.0.0.1", "true"])
            .output(),
    )
    .await
    .expect("ssh did not finish")
    .expect("could not run ssh");
    let _ = std::fs::remove_file(&known_hosts);
    let log = String::from_utf8_lossy(&output.stderr);

    assert!(
        log.contains("kex: algorithm: curve25519-sha256"),
        "curve25519-sha256 was not negotiated:\n{log}"
    );
    assert!(
        log.contains("will use strict KEX ordering"),
        "strict KEX not in force:\n{log}"
    );
    assert!(
        log.contains("SSH2_MSG_SERVICE_ACCEPT received"),
        "no service accept:\n{log}"
    );
    assert!(
        log.contains("14: no authentication methods available"),
        "no disconnect at user authentication:\n{log}"
    );

    let (closed, server) = timeout(LIMIT, server)
        .await
        .expect("server did not finish")
        .unwrap();
    match closed.unwrap() {
        Closed::Local { reason, .. } => {
            assert_eq!(reason, DisconnectReason::NO_MORE_AUTH_METHODS_AVAILABLE)
        }
        other => panic!("server ended with {other:?}"),
    }
    let peer = server.handshake().peer_version().unwrap();
    assert!(peer.starts_with("SSH-2.0-OpenSSH"), "peer version {peer}");
}
