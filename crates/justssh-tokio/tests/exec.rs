//! The example exec server against the real OpenSSH client. `ssh` must be on PATH, or named by
//! `JUSTSSH_SSH`.

#[path = "../examples/exec_server.rs"]
mod exec_server;

use std::process::Stdio;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(60);

#[tokio::test]
async fn openssh_exec_gets_stdout_stderr_and_exit_status_built_from_opaque_requests() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        exec_server::serve_connection(stream).await
    });

    let known_hosts = std::env::temp_dir().join(format!("justssh-known-hosts-exec-{port}"));
    let askpass = std::env::temp_dir().join(format!("justssh-askpass-exec-{port}"));
    std::fs::write(&askpass, "#!/bin/sh\necho pw\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&askpass, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let ssh = std::env::var("JUSTSSH_SSH").unwrap_or_else(|_| "ssh".to_owned());
    let output = timeout(
        LIMIT,
        Command::new(ssh)
            .args(["-F", "none", "-p", &port.to_string()])
            .args(["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"])
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", known_hosts.display()))
            .args(["-o", "PreferredAuthentications=password"])
            .env("SSH_ASKPASS", &askpass)
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env("DISPLAY", ":0")
            .stdin(Stdio::null())
            .args(["user@127.0.0.1", "hello world"])
            .output(),
    )
    .await
    .expect("ssh did not finish")
    .expect("could not run ssh");
    let _ = std::fs::remove_file(&known_hosts);
    let _ = std::fs::remove_file(&askpass);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stdout, "out:hello world\n", "stderr was:\n{stderr}");
    assert!(
        stderr.contains("err:hello world\n"),
        "stderr was:\n{stderr}"
    );
    assert_eq!(output.status.code(), Some(7), "stderr was:\n{stderr}");
    timeout(LIMIT, server).await.unwrap().unwrap().unwrap();
}
