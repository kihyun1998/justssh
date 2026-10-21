//! The identification line exchange (RFC 4253 §4.2).

/// Most bytes accepted for the identification line and every line before it, together, as
/// x/crypto/ssh does.
pub(crate) const MAX_TOTAL: usize = 255;

pub(crate) enum Line {
    /// Not yet a whole line.
    Incomplete,
    /// A line before the identification line, already consumed.
    Other,
    /// The peer's identification line, without CR LF.
    Version(String),
}

pub(crate) enum VersionError {
    TooLong,
    Unsupported,
}

/// Takes one line from the front of `buf`, charging its length to `budget`. Lines not starting
/// with `SSH-` are skipped; a line ending in a bare LF is accepted.
pub(crate) fn take_line(buf: &mut Vec<u8>, budget: &mut usize) -> Result<Line, VersionError> {
    let Some(nl) = buf.iter().take(*budget).position(|&b| b == b'\n') else {
        return if buf.len() >= *budget {
            Err(VersionError::TooLong)
        } else {
            Ok(Line::Incomplete)
        };
    };
    *budget -= nl + 1;
    let mut line: Vec<u8> = buf.drain(..=nl).collect();
    line.pop();
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    if !line.starts_with(b"SSH-") {
        return Ok(Line::Other);
    }
    if !(line.starts_with(b"SSH-2.0-") || line.starts_with(b"SSH-1.99-")) {
        return Err(VersionError::Unsupported);
    }
    String::from_utf8(line)
        .map(Line::Version)
        .map_err(|_| VersionError::Unsupported)
}
