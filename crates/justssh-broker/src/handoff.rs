//! acwbroker's handoff pipe: frames of `kind(1) length(4, BE) payload` on stdin and stdout,
//! each payload a run of `tag(1) length(4, BE) value` records (`internal/infrastructure/handoff`).

use std::io::{self, Read, Write};

use zeroize::Zeroizing;

/// The protocol version this broker speaks; the app's must be the same.
pub const VERSION: u32 = 11;

/// The largest payload a frame may carry.
pub const MAX_PAYLOAD: usize = 1 << 20;

/// A frame's message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum Kind {
    Hello = 0x01,
    Issue = 0x02,
    Token = 0x03,
    Listening = 0x04,
    Error = 0x05,
    Freeze = 0x07,
    Attach = 0x08,
    Attached = 0x09,
    Claimed = 0x0a,
    Disposed = 0x0b,
}

pub(crate) const TAG_VERSION: u8 = 0x01;
pub(crate) const TAG_BANNER: u8 = 0x02;
pub(crate) const TAG_TOKEN: u8 = 0x20;
pub(crate) const TAG_ADDR: u8 = 0x21;
pub(crate) const TAG_HOST_KEY: u8 = 0x22;
pub(crate) const TAG_MESSAGE: u8 = 0x30;
pub(crate) const TAG_REASON: u8 = 0x31;
pub(crate) const TAG_TUNNEL_PID: u8 = 0x40;
pub(crate) const TAG_PATH: u8 = 0x50;
pub(crate) const TAG_PID: u8 = 0x51;
pub(crate) const TAG_USED: u8 = 0x52;

/// One frame as read; the payload is zeroed when dropped.
#[derive(Debug)]
#[non_exhaustive]
pub struct Frame {
    pub kind: u8,
    pub payload: Zeroizing<Vec<u8>>,
}

/// Why no frame was read.
#[derive(Debug)]
#[non_exhaustive]
pub enum ReadError {
    /// The peer closed the pipe between frames.
    Closed,
    /// The pipe ended inside a frame.
    Truncated,
    /// The header declared a payload over [`MAX_PAYLOAD`].
    TooLong(u32),
    Io(io::Error),
}

/// A payload that does not hold the records its kind allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Malformed;

/// Reads one frame.
pub fn read_frame(r: &mut impl Read) -> Result<Frame, ReadError> {
    let mut header = [0u8; 5];
    let mut filled = 0;
    while filled < header.len() {
        match r.read(&mut header[filled..]) {
            Ok(0) if filled == 0 => return Err(ReadError::Closed),
            Ok(0) => return Err(ReadError::Truncated),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(ReadError::Io(e)),
        }
    }
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    if len as usize > MAX_PAYLOAD {
        return Err(ReadError::TooLong(len));
    }
    let mut payload = Zeroizing::new(vec![0; len as usize]);
    r.read_exact(&mut payload).map_err(|e| match e.kind() {
        io::ErrorKind::UnexpectedEof => ReadError::Truncated,
        _ => ReadError::Io(e),
    })?;
    Ok(Frame {
        kind: header[0],
        payload,
    })
}

/// Writes one frame in a single write, from a buffer zeroed afterwards.
pub fn write_frame(w: &mut impl Write, kind: Kind, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "handoff payload over 1 MiB",
        ));
    }
    let mut frame = Zeroizing::new(Vec::with_capacity(5 + payload.len()));
    frame.push(kind as u8);
    frame.extend((payload.len() as u32).to_be_bytes());
    frame.extend(payload);
    w.write_all(&frame)?;
    w.flush()
}

pub(crate) fn record(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    out.push(tag);
    out.extend((value.len() as u32).to_be_bytes());
    out.extend(value);
}

/// The records of `payload`, each tag in `allowed` and none twice.
pub(crate) fn records<'a>(
    mut payload: &'a [u8],
    allowed: &[u8],
) -> Result<Vec<(u8, &'a [u8])>, Malformed> {
    let mut out: Vec<(u8, &[u8])> = Vec::new();
    while !payload.is_empty() {
        let [tag, a, b, c, d, rest @ ..] = payload else {
            return Err(Malformed);
        };
        let len = u32::from_be_bytes([*a, *b, *c, *d]) as usize;
        if len > rest.len() {
            return Err(Malformed);
        }
        let (value, rest) = rest.split_at(len);
        out.push((*tag, value));
        payload = rest;
    }
    for (i, (tag, _)) in out.iter().enumerate() {
        if !allowed.contains(tag) || out[..i].iter().any(|(t, _)| t == tag) {
            return Err(Malformed);
        }
    }
    Ok(out)
}

pub(crate) fn find<'a>(records: &[(u8, &'a [u8])], tag: u8) -> Option<&'a [u8]> {
    records.iter().find(|(t, _)| *t == tag).map(|(_, v)| *v)
}

fn be32(value: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(value.try_into().ok()?))
}

/// A HELLO payload announcing `version`.
pub fn hello(version: u32) -> Vec<u8> {
    let mut out = Vec::new();
    record(&mut out, TAG_VERSION, &version.to_be_bytes());
    record(
        &mut out,
        TAG_BANNER,
        format!("ACWBROKER PROTO {VERSION}").as_bytes(),
    );
    out
}

/// The version a HELLO payload announces.
pub fn decode_hello(payload: &[u8]) -> Result<u32, Malformed> {
    let rs = records(payload, &[TAG_VERSION, TAG_BANNER])?;
    find(&rs, TAG_VERSION).and_then(be32).ok_or(Malformed)
}

/// A TOKEN payload, zeroed when dropped.
pub fn token(token: &str) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(5 + token.len()));
    record(&mut out, TAG_TOKEN, token.as_bytes());
    out
}

/// A LISTENING payload: the address bound and the host public key served there, in SSH wire
/// form.
pub fn listening(addr: &str, host_key: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    record(&mut out, TAG_ADDR, addr.as_bytes());
    record(&mut out, TAG_HOST_KEY, host_key);
    out
}

/// An ERROR payload with no reason.
pub fn error(message: &str) -> Vec<u8> {
    let mut out = Vec::new();
    record(&mut out, TAG_MESSAGE, message.as_bytes());
    out
}

/// An ERROR payload with a reason code.
pub fn refusal(message: &str, reason: u8) -> Vec<u8> {
    let mut out = error(message);
    record(&mut out, TAG_REASON, &[reason]);
    out
}

/// The tunnel pid a FREEZE payload names: four bytes, not zero.
pub fn decode_freeze(payload: &[u8]) -> Result<u32, Malformed> {
    let rs = records(payload, &[TAG_TUNNEL_PID])?;
    match find(&rs, TAG_TUNNEL_PID).and_then(be32) {
        Some(pid) if pid != 0 => Ok(pid),
        _ => Err(Malformed),
    }
}

/// What an ATTACH hands over: the token's path, the process launched to use it, or both.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Attachment {
    pub token: Zeroizing<String>,
    pub path: Option<String>,
    pub pid: Option<u32>,
}

/// An ATTACH payload: a token, and a path that is not empty, a pid that is not zero, or both.
pub fn decode_attach(payload: &[u8]) -> Result<Attachment, Malformed> {
    let rs = records(payload, &[TAG_TOKEN, TAG_PATH, TAG_PID])?;
    let token = match find(&rs, TAG_TOKEN) {
        Some(t) if !t.is_empty() => Zeroizing::new(String::from_utf8_lossy(t).into_owned()),
        _ => return Err(Malformed),
    };
    let path = find(&rs, TAG_PATH);
    if path.is_some_and(<[u8]>::is_empty) {
        return Err(Malformed);
    }
    let pid = match find(&rs, TAG_PID) {
        Some(v) => match be32(v) {
            Some(pid) if pid != 0 => Some(pid),
            _ => return Err(Malformed),
        },
        None => None,
    };
    if path.is_none() && pid.is_none() {
        return Err(Malformed);
    }
    Ok(Attachment {
        token,
        path: path.map(|p| String::from_utf8_lossy(p).into_owned()),
        pid,
    })
}

/// An ATTACHED payload: empty, or saying the token had already been used.
pub fn attached(used: bool) -> Vec<u8> {
    let mut out = Vec::new();
    if used {
        record(&mut out, TAG_USED, &[1]);
    }
    out
}

/// A CLAIMED or DISPOSED payload naming `pid`.
pub fn pid(pid: u32) -> Vec<u8> {
    let mut out = Vec::new();
    record(&mut out, TAG_PID, &pid.to_be_bytes());
    out
}
