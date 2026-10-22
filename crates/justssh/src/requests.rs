//! Typed codecs for channel requests: each builds and reads the data of one request type, the
//! bytes of an Opaque Request, and encodes back the bytes it read.

use justssh_wire::{DecodeError, Reader, Writer};

/// `pty-req` (RFC 4254 §6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtyReq {
    term: Vec<u8>,
    columns: u32,
    rows: u32,
    width: u32,
    height: u32,
    modes: Vec<u8>,
}

impl PtyReq {
    pub const KIND: &'static str = "pty-req";

    /// A request for terminal `term` of `columns` x `rows` characters and `width` x `height`
    /// pixels, with `modes` as opcode/value pairs in that order, closed by TTY_OP_END.
    pub fn new(
        term: Vec<u8>,
        columns: u32,
        rows: u32,
        width: u32,
        height: u32,
        modes: &[(u8, u32)],
    ) -> Self {
        let mut w = Writer::new();
        for &(opcode, value) in modes {
            w.u8(opcode).u32(value);
        }
        w.u8(0);
        PtyReq::from_encoded_modes(term, columns, rows, width, height, w.into_bytes())
    }

    /// As [`PtyReq::new`], with `modes` already encoded, such as another request's
    /// [`encoded_modes`](PtyReq::encoded_modes).
    pub fn from_encoded_modes(
        term: Vec<u8>,
        columns: u32,
        rows: u32,
        width: u32,
        height: u32,
        modes: Vec<u8>,
    ) -> Self {
        PtyReq {
            term,
            columns,
            rows,
            width,
            height,
            modes,
        }
    }

    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(data);
        let request = PtyReq {
            term: r.string()?.to_vec(),
            columns: r.u32()?,
            rows: r.u32()?,
            width: r.u32()?,
            height: r.u32()?,
            modes: r.string()?.to_vec(),
        };
        r.finish()?;
        Ok(request)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.string(&self.term)
            .u32(self.columns)
            .u32(self.rows)
            .u32(self.width)
            .u32(self.height)
            .string(&self.modes);
        w.into_bytes()
    }

    /// The `TERM` value, such as `xterm`.
    pub fn term(&self) -> &[u8] {
        &self.term
    }

    pub fn columns(&self) -> u32 {
        self.columns
    }

    pub fn rows(&self) -> u32 {
        self.rows
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    /// The encoded terminal modes, as sent.
    pub fn encoded_modes(&self) -> &[u8] {
        &self.modes
    }

    /// The terminal modes as opcode/value pairs, in the order sent, up to TTY_OP_END, an
    /// opcode from 160 on, or the end of the encoded modes (RFC 4254 §8).
    pub fn modes(&self) -> impl Iterator<Item = (u8, u32)> + '_ {
        let mut r = Reader::new(&self.modes);
        core::iter::from_fn(move || {
            let opcode = r.u8().ok().filter(|&o| (1..160).contains(&o))?;
            Some((opcode, r.u32().ok()?))
        })
        .fuse()
    }
}

/// `shell` (RFC 4254 §6.5), which carries no data.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Shell(());

impl Shell {
    pub const KIND: &'static str = "shell";

    pub fn new() -> Self {
        Shell(())
    }

    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        Reader::new(data).finish()?;
        Ok(Shell(()))
    }

    pub fn encode(&self) -> Vec<u8> {
        Vec::new()
    }
}

/// `exec` (RFC 4254 §6.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exec {
    command: Vec<u8>,
}

impl Exec {
    pub const KIND: &'static str = "exec";

    pub fn new(command: Vec<u8>) -> Self {
        Exec { command }
    }

    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(data);
        let command = r.string()?.to_vec();
        r.finish()?;
        Ok(Exec { command })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.string(&self.command);
        w.into_bytes()
    }

    pub fn command(&self) -> &[u8] {
        &self.command
    }
}

/// `subsystem` (RFC 4254 §6.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subsystem {
    name: Vec<u8>,
}

impl Subsystem {
    pub const KIND: &'static str = "subsystem";

    pub fn new(name: Vec<u8>) -> Self {
        Subsystem { name }
    }

    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(data);
        let name = r.string()?.to_vec();
        r.finish()?;
        Ok(Subsystem { name })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.string(&self.name);
        w.into_bytes()
    }

    /// The subsystem's name, such as `sftp`.
    pub fn name(&self) -> &[u8] {
        &self.name
    }
}

/// `env` (RFC 4254 §6.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Env {
    name: Vec<u8>,
    value: Vec<u8>,
}

impl Env {
    pub const KIND: &'static str = "env";

    pub fn new(name: Vec<u8>, value: Vec<u8>) -> Self {
        Env { name, value }
    }

    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(data);
        let request = Env {
            name: r.string()?.to_vec(),
            value: r.string()?.to_vec(),
        };
        r.finish()?;
        Ok(request)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.string(&self.name).string(&self.value);
        w.into_bytes()
    }

    pub fn name(&self) -> &[u8] {
        &self.name
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

/// `exit-status` (RFC 4254 §6.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitStatus {
    status: u32,
}

impl ExitStatus {
    pub const KIND: &'static str = "exit-status";

    pub fn new(status: u32) -> Self {
        ExitStatus { status }
    }

    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(data);
        let status = r.u32()?;
        r.finish()?;
        Ok(ExitStatus { status })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.status.to_be_bytes().to_vec()
    }

    pub fn status(&self) -> u32 {
        self.status
    }
}

/// `exit-signal` (RFC 4254 §6.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitSignal {
    signal: Vec<u8>,
    core_dumped: u8,
    message: Vec<u8>,
    language: Vec<u8>,
}

impl ExitSignal {
    pub const KIND: &'static str = "exit-signal";

    pub fn new(signal: Vec<u8>, core_dumped: bool, message: Vec<u8>, language: Vec<u8>) -> Self {
        ExitSignal {
            signal,
            core_dumped: u8::from(core_dumped),
            message,
            language,
        }
    }

    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(data);
        let request = ExitSignal {
            signal: r.string()?.to_vec(),
            core_dumped: r.u8()?,
            message: r.string()?.to_vec(),
            language: r.string()?.to_vec(),
        };
        r.finish()?;
        Ok(request)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.string(&self.signal)
            .u8(self.core_dumped)
            .string(&self.message)
            .string(&self.language);
        w.into_bytes()
    }

    /// The signal's name without the `SIG` prefix, such as `TERM`.
    pub fn signal(&self) -> &[u8] {
        &self.signal
    }

    pub fn core_dumped(&self) -> bool {
        self.core_dumped != 0
    }

    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// The message's language tag (RFC 3066).
    pub fn language(&self) -> &[u8] {
        &self.language
    }
}
