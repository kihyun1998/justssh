//! The handoff session over one pipe pair, in acwbroker's order: the version exchange, the
//! announcement of the listener, then requests until the pipe closes
//! (`cmd/acwbroker/main.go` `run`, `internal/infrastructure/handoff/pipe.go`).

use std::io::{Read, Write};

use zeroize::Zeroizing;

use crate::handoff::{self, Kind, ReadError};
use crate::issue::{self, Issue, IssueError};

/// Why the session ended other than by the pipe closing between frames.
#[derive(Debug)]
#[non_exhaustive]
pub enum End {
    /// The pipe failed, ended inside a frame, or declared a payload over the cap.
    Pipe(ReadError),
    /// The peer sent something the session cannot go on from; `0` is the ERROR message sent.
    Refused(&'static str),
    /// Writing a frame failed.
    Write(std::io::Error),
}

/// The tokens issued, each with its credential.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct Tokens {
    pub issued: Vec<(Zeroizing<String>, Issue)>,
}

/// One handoff pipe: frames in on `input`, out on `output`.
#[derive(Debug)]
pub struct Session<R, W> {
    input: R,
    output: W,
}

impl<R: Read, W: Write> Session<R, W> {
    pub fn new(input: R, output: W) -> Self {
        Session { input, output }
    }

    fn write(&mut self, kind: Kind, payload: &[u8]) -> Result<(), End> {
        handoff::write_frame(&mut self.output, kind, payload).map_err(End::Write)
    }

    /// Tells the peer why the exchange stopped, in words of this side's.
    pub fn fail(&mut self, message: &'static str) -> Result<(), End> {
        self.write(Kind::Error, &handoff::error(message))
    }

    fn refuse(&mut self, message: &'static str) -> End {
        match self.fail(message) {
            Ok(()) => End::Refused(message),
            Err(e) => e,
        }
    }

    /// Announces this side's version and requires the peer to echo it.
    pub fn handshake(&mut self) -> Result<(), End> {
        self.write(Kind::Hello, &handoff::hello(handoff::VERSION))?;
        let frame = handoff::read_frame(&mut self.input).map_err(End::Pipe)?;
        if frame.kind != Kind::Hello as u8 {
            return Err(self.refuse("expected a version echo"));
        }
        match handoff::decode_hello(&frame.payload) {
            Ok(handoff::VERSION) => Ok(()),
            Ok(_) => Err(self.refuse("protocol version mismatch")),
            Err(_) => Err(self.refuse("malformed version echo")),
        }
    }

    /// Reports the address bound and the host public key served there, in SSH wire form.
    pub fn announce(&mut self, addr: &str, host_key: &[u8]) -> Result<(), End> {
        self.write(Kind::Listening, &handoff::listening(addr, host_key))
    }

    /// Answers requests until the pipe closes between frames, which ends it cleanly.
    pub fn serve(&mut self, tokens: &mut Tokens) -> Result<(), End> {
        loop {
            let frame = match handoff::read_frame(&mut self.input) {
                Ok(frame) => frame,
                Err(ReadError::Closed) => return Ok(()),
                Err(e) => return Err(End::Pipe(e)),
            };
            match frame.kind {
                k if k == Kind::Issue as u8 => match issue::decode(&frame.payload) {
                    Ok(issue) if issue.terminal.is_some() => {
                        self.fail("terminal to bind the token to was not found")?;
                    }
                    Ok(issue) => {
                        let token = mint(tokens);
                        tokens.issued.push((token.clone(), issue));
                        self.write(Kind::Token, &handoff::token(&token))?;
                    }
                    Err(IssueError::NotLoopback) => {
                        self.fail("upstream is not a loopback address")?;
                    }
                    Err(IssueError::Refused) => self.fail("credential refused")?,
                    Err(_) => return Err(self.refuse("malformed credential")),
                },
                k if k == Kind::Freeze as u8 => {
                    return Err(match handoff::decode_freeze(&frame.payload) {
                        Ok(_) => self.refuse("freeze is not supported"),
                        Err(_) => self.refuse("malformed freeze"),
                    });
                }
                k if k == Kind::Attach as u8 => match handoff::decode_attach(&frame.payload) {
                    Ok(()) => self.fail("attach is not supported")?,
                    Err(_) => return Err(self.refuse("malformed attach")),
                },
                _ => return Err(self.refuse("unknown frame kind")),
            }
        }
    }
}

/// A token of 16 random bytes in lowercase hex, not one already issued.
fn mint(tokens: &Tokens) -> Zeroizing<String> {
    loop {
        let mut bytes = Zeroizing::new([0u8; 16]);
        getrandom::fill(&mut bytes[..]).expect("system random number generator");
        let mut token = Zeroizing::new(String::with_capacity(32));
        for b in bytes.iter() {
            token.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
            token.push(char::from(b"0123456789abcdef"[usize::from(b & 15)]));
        }
        if !tokens.issued.iter().any(|(t, _)| *t == token) {
            return token;
        }
    }
}
