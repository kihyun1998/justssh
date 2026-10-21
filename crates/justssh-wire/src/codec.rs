//! RFC 4251 §5 data types: byte, boolean, uint32, string, mpint and name-list.

use core::fmt;

/// Why a payload could not be decoded.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The payload ended before a field was complete.
    Truncated,
    /// Bytes were left over after the last field of the message.
    TrailingBytes,
    /// A name-list or text field was not valid UTF-8.
    InvalidUtf8,
    /// A boolean or fixed-value field held a value the format does not allow.
    InvalidValue,
    /// The payload was empty, so it had no message number.
    Empty,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            DecodeError::Truncated => "payload ended before a field was complete",
            DecodeError::TrailingBytes => "bytes left over after the last field",
            DecodeError::InvalidUtf8 => "text field is not valid UTF-8",
            DecodeError::InvalidValue => "field holds a value the format does not allow",
            DecodeError::Empty => "empty payload",
        };
        f.write_str(s)
    }
}

impl std::error::Error for DecodeError {}

/// Reads RFC 4251 data types from a byte slice, front to back.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    /// A reader over `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf }
    }

    /// The bytes not yet read.
    pub fn remaining(&self) -> &'a [u8] {
        self.buf
    }

    /// Takes the next `n` raw bytes.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.buf.len() < n {
            return Err(DecodeError::Truncated);
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    /// `byte`.
    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.bytes(1)?[0])
    }

    /// `boolean`: zero is false, any other value true (RFC 4251 §5).
    pub fn bool(&mut self) -> Result<bool, DecodeError> {
        Ok(self.u8()? != 0)
    }

    /// `uint32`, big-endian.
    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// `string`: a uint32 length and that many bytes.
    pub fn string(&mut self) -> Result<&'a [u8], DecodeError> {
        let len = self.u32()? as usize;
        self.bytes(len)
    }

    /// A `string` that must be valid UTF-8.
    pub fn utf8(&mut self) -> Result<&'a str, DecodeError> {
        core::str::from_utf8(self.string()?).map_err(|_| DecodeError::InvalidUtf8)
    }

    /// `name-list`: a comma-separated `string` of names. The empty string is the empty list.
    pub fn name_list(&mut self) -> Result<Vec<String>, DecodeError> {
        let s = self.utf8()?;
        if s.is_empty() {
            return Ok(Vec::new());
        }
        Ok(s.split(',').map(str::to_owned).collect())
    }

    /// Succeeds only if every byte has been read.
    pub fn finish(&self) -> Result<(), DecodeError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}

/// Appends RFC 4251 data types to a byte vector.
#[derive(Debug, Clone, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// An empty writer.
    pub fn new() -> Self {
        Writer::default()
    }

    /// The bytes written so far.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Raw bytes with no length prefix.
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }

    /// `byte`.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    /// `boolean`, written as 0 or 1.
    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(u8::from(v))
    }

    /// `uint32`, big-endian.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.bytes(&v.to_be_bytes())
    }

    /// `string`.
    ///
    /// # Panics
    /// If `s` is longer than `u32::MAX` bytes.
    pub fn string(&mut self, s: &[u8]) -> &mut Self {
        let len = u32::try_from(s.len()).expect("SSH string longer than u32::MAX");
        self.u32(len).bytes(s)
    }

    /// `name-list`.
    pub fn name_list<S: AsRef<str>>(&mut self, names: &[S]) -> &mut Self {
        let joined = names
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>()
            .join(",");
        self.string(joined.as_bytes())
    }

    /// `mpint` holding the unsigned big-endian integer `magnitude`: leading zero bytes are
    /// dropped, and a zero byte is prepended when the top bit is set.
    pub fn mpint_unsigned(&mut self, magnitude: &[u8]) -> &mut Self {
        let start = magnitude
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(magnitude.len());
        let m = &magnitude[start..];
        if m.first().is_some_and(|&b| b & 0x80 != 0) {
            let len = u32::try_from(m.len() + 1).expect("mpint longer than u32::MAX");
            self.u32(len).u8(0).bytes(m)
        } else {
            self.string(m)
        }
    }
}
