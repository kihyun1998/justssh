//! OpenSSH's `ServerAliveInterval` keepalives against a justssh server that answers them.
//! `ssh` must be on PATH, or named by `JUSTSSH_SSH`.

use std::process::Stdio;
use std::time::Duration;

use justssh::{Action, HostKey, Server, ServerConfig, Zeroizing};
use justssh_tokio::{Accepted, Deadlines, Session};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(60);

/// Keepalives to wait for before the command ends; more than the `ServerAliveCountMax` given to
/// `ssh`.
const KEEPALIVES: usize = 4;

/// Serves one connection: accepts a session, answers `exec`, refuses every global request, and
/// ends the command with exit status 0 once `KEEPALIVES` global requests have arrived. Returns
/// each global request's name, want_reply and data.
async fn serve(listener: TcpListener) -> std::io::Result<Vec<(String, bool, Vec<u8>)>> {
    let (stream, _) = listener.accept().await?;
    let config = ServerConfig::builder(HostKey::ed25519_from_seed(Zeroizing::new([7; 32]))).build();
    let mut server = Server::new(config);
    let Accepted::Authenticated { io, events, .. } =
        justssh_tokio::accept(stream, &mut server, &Deadlines::new(), |_| async {
            Some(())
        })
        .await?
    else {
        panic!("not authenticated");
    };
    let mut session = Session::new(io, server, events);
    let mut globals = Vec::new();
    let mut exec = None;
    while let Some(action) = session.next().await? {
        match action {
            Action::ChannelOpenRequest(open) => {
                session.accept_channel(open.channel(), Vec::new()).await?;
            }
            Action::ChannelRequest(request) => {
                if request.kind() == "exec" {
                    exec = Some(request.channel());
                }
                if let Some(token) = request.reply() {
                    session.reply(token, request.kind() == "exec").await?;
                }
            }
            Action::GlobalRequest(request) => {
                globals.push((
                    request.kind().to_owned(),
                    request.want_reply(),
                    request.data().to_vec(),
                ));
                if let Some(token) = request.reply() {
                    session.reply_global(token, false, Vec::new()).await?;
                }
                if let (true, Some(channel)) = (globals.len() == KEEPALIVES, exec) {
                    session
                        .request(channel, "exit-status", false, vec![0; 4])
                        .await?;
                    session.close(channel).await?;
                }
            }
            Action::Closed(_) => break,
            _ => {}
        }
    }
    Ok(globals)
}

#[tokio::test]
async fn openssh_keepalives_arrive_as_opaque_requests_and_their_answers_keep_ssh_alive() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(serve(listener));

    let known_hosts = std::env::temp_dir().join(format!("justssh-known-hosts-alive-{port}"));
    let askpass = std::env::temp_dir().join(format!("justssh-askpass-alive-{port}"));
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
            .args(["-o", "ServerAliveInterval=1", "-o", "ServerAliveCountMax=2"])
            .env("SSH_ASKPASS", &askpass)
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env("DISPLAY", ":0")
            .stdin(Stdio::null())
            .args(["user@127.0.0.1", "wait"])
            .output(),
    )
    .await
    .expect("ssh did not finish")
    .expect("could not run ssh");
    let _ = std::fs::remove_file(&known_hosts);
    let _ = std::fs::remove_file(&askpass);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "stderr was:\n{stderr}");
    let globals = timeout(LIMIT, server).await.unwrap().unwrap().unwrap();
    assert_eq!(
        globals,
        vec![("keepalive@openssh.com".to_owned(), true, Vec::new()); KEEPALIVES]
    );
}

/// Data the server offers a command whose output nobody reads.
const OFFERED: usize = 64 << 20;

/// Serves one connection: on `exec`, queues data while little waits, answers every global
/// request, and once `KEEPALIVES` have arrived aborts the channel and disconnects. Returns how
/// many keepalives arrived while data was waiting for the window.
async fn serve_unread(listener: TcpListener) -> std::io::Result<usize> {
    let (stream, _) = listener.accept().await?;
    let config = ServerConfig::builder(HostKey::ed25519_from_seed(Zeroizing::new([7; 32]))).build();
    let mut server = Server::new(config);
    let Accepted::Authenticated { io, events, .. } =
        justssh_tokio::accept(stream, &mut server, &Deadlines::new(), |_| async {
            Some(())
        })
        .await?
    else {
        panic!("not authenticated");
    };
    let mut session = Session::new(io, server, events);
    let (mut exec, mut offered, mut keepalives, mut while_waiting) = (None, 0, 0, 0);
    let chunk = vec![b'x'; 32 * 1024];
    loop {
        if let Some(channel) = exec {
            while offered < OFFERED
                && session
                    .endpoint()
                    .channel_info(channel)
                    .is_some_and(|i| i.queued() < 256 * 1024)
            {
                session.queue_data(channel, &chunk).await?;
                offered += chunk.len();
            }
        }
        let Some(action) = session.next().await? else {
            break;
        };
        match action {
            Action::ChannelOpenRequest(open) => {
                session.accept_channel(open.channel(), Vec::new()).await?;
            }
            Action::ChannelRequest(request) => {
                if request.kind() == "exec" {
                    exec = Some(request.channel());
                }
                if let Some(token) = request.reply() {
                    session.reply(token, request.kind() == "exec").await?;
                }
            }
            Action::GlobalRequest(request) => {
                keepalives += 1;
                let waiting = exec
                    .and_then(|c| session.endpoint().channel_info(c))
                    .is_some_and(|i| i.queued() > 0);
                while_waiting += usize::from(waiting);
                if let Some(token) = request.reply() {
                    session.reply_global(token, false, Vec::new()).await?;
                }
                if keepalives == KEEPALIVES {
                    session.abort(exec.expect("exec before keepalives")).await?;
                    session
                        .disconnect(justssh::DisconnectReason::BY_APPLICATION, "done")
                        .await?;
                }
            }
            Action::Closed(_) => break,
            _ => {}
        }
    }
    Ok(while_waiting)
}

#[tokio::test]
async fn keepalives_are_answered_while_output_waits_for_a_window_ssh_does_not_open() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(serve_unread(listener));

    let known_hosts = std::env::temp_dir().join(format!("justssh-known-hosts-unread-{port}"));
    let askpass = std::env::temp_dir().join(format!("justssh-askpass-unread-{port}"));
    std::fs::write(&askpass, "#!/bin/sh\necho pw\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&askpass, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let ssh = std::env::var("JUSTSSH_SSH").unwrap_or_else(|_| "ssh".to_owned());
    // stdout is piped and never read.
    let mut child = Command::new(ssh)
        .args(["-F", "none", "-p", &port.to_string()])
        .args(["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"])
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", known_hosts.display()))
        .args(["-o", "PreferredAuthentications=password"])
        .args(["-o", "ServerAliveInterval=1", "-o", "ServerAliveCountMax=2"])
        .env("SSH_ASKPASS", &askpass)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", ":0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .args(["user@127.0.0.1", "print"])
        .spawn()
        .unwrap();
    let while_waiting = timeout(LIMIT, server).await.unwrap().unwrap().unwrap();
    let _ = child.kill().await;
    let output = child.wait_with_output().await.unwrap();
    let _ = std::fs::remove_file(&known_hosts);
    let _ = std::fs::remove_file(&askpass);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("Timeout"), "stderr was:\n{stderr}");
    assert_eq!(while_waiting, KEEPALIVES, "stderr was:\n{stderr}");
}
