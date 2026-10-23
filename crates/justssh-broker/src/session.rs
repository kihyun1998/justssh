//! The handoff session over one pipe pair, in acwbroker's order: the version exchange, the
//! announcement of the listener, then requests until the pipe closes
//! (`cmd/acwbroker/main.go` `run`, `internal/infrastructure/handoff/pipe.go`).

use std::io::{Read, Write};
use std::sync::{Arc, Mutex, PoisonError};

use crate::handoff::{self, Kind, ReadError};
use crate::issue::{self, IssueError};
use crate::log::Log;
use crate::tokens::Tokens;

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

/// What a session asks of the rest of the broker.
pub trait Hooks {
    /// Carries out a FREEZE: watch `tunnel`, stop taking new connections and keep the open
    /// ones. An error means the tunnel cannot be watched, and nothing was changed.
    fn freeze(&mut self, tunnel: u32) -> Result<(), String>;

    /// Whether an ATTACH may hand over `path`.
    fn admit(&self, path: &str) -> Result<(), String>;
}

/// The writing half of a pipe, shared by its session and what tells the app unasked. One
/// frame is written at a time.
#[derive(Debug)]
pub struct Pipe<W>(Arc<Mutex<W>>);

impl<W> Clone for Pipe<W> {
    fn clone(&self) -> Self {
        Pipe(self.0.clone())
    }
}

impl<W: Write> Pipe<W> {
    fn write(&self, kind: Kind, payload: &[u8]) -> std::io::Result<()> {
        let mut out = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        handoff::write_frame(&mut *out, kind, payload)
    }

    /// Tells the app that the token it reported `pid` for has been used. A write that fails is
    /// dropped: the app closed the pipe after a FREEZE.
    pub fn claimed(&self, pid: u32) {
        let _ = self.write(Kind::Claimed, &handoff::pid(pid));
    }

    /// Tells the app that the token it reported `pid` for was disposed of before its first
    /// use. A write that fails is dropped.
    pub fn disposed(&self, pid: u32) {
        let _ = self.write(Kind::Disposed, &handoff::pid(pid));
    }
}

/// One handoff pipe: frames in on `input`, out on `output`.
#[derive(Debug)]
pub struct Session<R, W> {
    input: R,
    output: Pipe<W>,
    frozen: bool,
    log: Log,
}

impl<R: Read, W: Write> Session<R, W> {
    pub fn new(input: R, output: W) -> Self {
        Session {
            input,
            output: Pipe(Arc::new(Mutex::new(output))),
            frozen: false,
            log: Log::discard(),
        }
    }

    /// Logs why a request was refused to `log`.
    pub fn set_log(&mut self, log: Log) {
        self.log = log;
    }

    /// The writing half, for what tells the app unasked.
    pub fn pipe(&self) -> Pipe<W> {
        self.output.clone()
    }

    /// Whether a FREEZE has been carried out.
    pub fn frozen(&self) -> bool {
        self.frozen
    }

    fn write(&mut self, kind: Kind, payload: &[u8]) -> Result<(), End> {
        self.output.write(kind, payload).map_err(End::Write)
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
    pub fn serve(&mut self, tokens: &Tokens, hooks: &mut dyn Hooks) -> Result<(), End> {
        loop {
            let frame = match handoff::read_frame(&mut self.input) {
                Ok(frame) => frame,
                Err(ReadError::Closed) => return Ok(()),
                Err(e) => return Err(End::Pipe(e)),
            };
            match frame.kind {
                k if k == Kind::Issue as u8 && self.frozen => self.fail("frozen")?,
                k if k == Kind::Issue as u8 => match issue::decode(&frame.payload) {
                    Ok(issue) if issue.terminal.is_some() => {
                        self.log.warn(
                            "terminal binding refused",
                            &[
                                ("terminal", issue.terminal.unwrap_or(0).into()),
                                (
                                    "err",
                                    "peer: terminal binding is not implemented on this platform"
                                        .into(),
                                ),
                            ],
                        );
                        self.fail("terminal to bind the token to was not found")?;
                    }
                    Ok(issue) => {
                        let token = tokens.issue(issue);
                        self.write(Kind::Token, &handoff::token(&token))?;
                    }
                    Err(IssueError::NotLoopback) => {
                        self.fail("upstream is not a loopback address")?;
                    }
                    Err(IssueError::Refused) => self.fail("credential refused")?,
                    Err(_) => return Err(self.refuse("malformed credential")),
                },
                k if k == Kind::Freeze as u8 && self.frozen => {}
                k if k == Kind::Freeze as u8 => {
                    let Ok(tunnel) = handoff::decode_freeze(&frame.payload) else {
                        return Err(self.refuse("malformed freeze"));
                    };
                    if hooks.freeze(tunnel).is_err() {
                        return Err(self.refuse("tunnel could not be watched"));
                    }
                    self.frozen = true;
                }
                k if k == Kind::Attach as u8 => {
                    let Ok(a) = handoff::decode_attach(&frame.payload) else {
                        return Err(self.refuse("malformed attach"));
                    };
                    let taken =
                        tokens.take_attachment(&a.token, a.path.as_deref(), a.pid, |path| {
                            hooks.admit(path)
                        });
                    match taken {
                        Ok(used) => self.write(Kind::Attached, &handoff::attached(used))?,
                        Err(e) => {
                            self.log
                                .warn("attach refused", &[("err", e.to_string().into())]);
                            self.fail("attach refused")?
                        }
                    }
                }
                _ => return Err(self.refuse("unknown frame kind")),
            }
        }
    }
}
