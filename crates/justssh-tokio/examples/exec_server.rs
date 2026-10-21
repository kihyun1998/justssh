//! A server that answers `exec` with fixed output built from opaque requests only: stdout
//! `out:<command>`, stderr `err:<command>` and exit status 7. Any password is accepted; global
//! requests are refused.
//!
//! `cargo run -p justssh-tokio --example exec_server -- 127.0.0.1:2222`, then
//! `ssh -p 2222 -o StrictHostKeyChecking=no user@127.0.0.1 hello`.

use justssh::{Action, HostKey, OpenFailureReason, Server, ServerConfig, Zeroizing};
use justssh_tokio::{Accepted, Deadlines, Session};
use tokio::net::{TcpListener, TcpStream};

/// The command in an `exec` request's data: `string command`.
fn command(data: &[u8]) -> Option<&[u8]> {
    let len = u32::from_be_bytes(data.get(..4)?.try_into().ok()?) as usize;
    data.get(4..4 + len)
}

/// Serves one connection until it ends.
pub async fn serve_connection(stream: TcpStream) -> std::io::Result<()> {
    let config = ServerConfig::builder(HostKey::ed25519_from_seed(Zeroizing::new([7; 32]))).build();
    let mut server = Server::new(config);
    let (io, events) =
        match justssh_tokio::accept(stream, &mut server, &Deadlines::new(), |_| async {
            Some(())
        })
        .await?
        {
            Accepted::Authenticated { io, events, .. } => (io, events),
            _ => return Ok(()),
        };
    let mut session = Session::new(io, server, events);
    while let Some(action) = session.next().await? {
        match action {
            Action::ChannelOpenRequest(open) if open.kind() == "session" => {
                session.accept_channel(open.channel(), Vec::new()).await?;
            }
            Action::ChannelOpenRequest(open) => {
                let reason = OpenFailureReason::ADMINISTRATIVELY_PROHIBITED;
                session
                    .reject_channel(open.channel(), reason, "prohibited")
                    .await?;
            }
            Action::ChannelData { channel, data } => {
                session.consumed(channel, data.len() as u32).await?;
            }
            Action::ChannelRequest(request) => {
                let channel = request.channel();
                let exec = (request.kind() == "exec")
                    .then(|| command(request.data()))
                    .flatten();
                if let Some(token) = request.reply() {
                    let ok = exec.is_some() || matches!(request.kind(), "pty-req" | "env");
                    session.reply(token, ok).await?;
                }
                if let Some(cmd) = exec {
                    let cmd = String::from_utf8_lossy(cmd).into_owned();
                    session
                        .data(channel, format!("out:{cmd}\n").as_bytes())
                        .await?;
                    session
                        .extended_data(channel, 1, format!("err:{cmd}\n").as_bytes())
                        .await?;
                    session.eof(channel).await?;
                    let status = 7u32.to_be_bytes().to_vec();
                    session
                        .request(channel, "exit-status", false, status)
                        .await?;
                    session.close(channel).await?;
                }
            }
            Action::GlobalRequest(request) => {
                if let Some(token) = request.reply() {
                    session.reply_global(token, false, Vec::new()).await?;
                }
            }
            Action::Closed(_) => break,
            _ => {}
        }
    }
    Ok(())
}

#[allow(dead_code)]
#[tokio::main]
async fn main() -> std::io::Result<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:2222".to_owned());
    let listener = TcpListener::bind(&addr).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(serve_connection(stream));
    }
}
