//! Tokio adapter that drives the justssh sans-IO core over TCP.

use std::io;

use justssh::{Action, Closed, Event, Server};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Runs `server` over `io` until the connection ends, and returns how it ended. `server` stays
/// with the caller, so its handshake record can be read afterwards. An I/O error,
/// or the peer closing the stream without `SSH_MSG_DISCONNECT`, is returned as `Err`.
pub async fn serve<IO>(mut io: IO, server: &mut Server) -> io::Result<Closed>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 32 * 1024];
    let mut actions = server.process(Event::Connected);
    loop {
        for action in actions {
            match action {
                Action::Write(bytes) => io.write_all(&bytes).await?,
                Action::Closed(closed) => {
                    io.flush().await?;
                    return Ok(closed);
                }
                _ => {}
            }
        }
        io.flush().await?;
        let n = io.read(&mut buf).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        actions = server.process(Event::Received(&buf[..n]));
    }
}
