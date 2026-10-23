//! acwbroker's log lines: what `log/slog`'s text handler writes for the broker's events
//! (acwbroker `cmd/acwbroker/logging.go`), one line per event, to its sinks.

use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How much a line matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Level {
    Info,
    Warn,
    Error,
}

/// One attribute's value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Value {
    Text(Vec<u8>),
    Int(i64),
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::Text(s.as_bytes().to_vec())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::Text(s.into_bytes())
    }
}

impl From<u32> for Value {
    fn from(n: u32) -> Self {
        Value::Int(n.into())
    }
}

impl From<i32> for Value {
    fn from(n: i32) -> Self {
        Value::Int(n.into())
    }
}

impl From<usize> for Value {
    fn from(n: usize) -> Self {
        Value::Int(n as i64)
    }
}

/// Where the lines go, the profile every line carries, and the clock and offset that stamp
/// them. Clones share the sink.
#[derive(Clone)]
pub struct Log(Option<Arc<Inner>>);

struct Inner {
    sink: Mutex<Box<dyn Write + Send>>,
    profile: Option<String>,
    clock: Box<dyn Fn() -> (SystemTime, i32) + Send + Sync>,
}

impl std::fmt::Debug for Log {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Log").finish_non_exhaustive()
    }
}

impl Log {
    /// A log writing to `sink`, each line carrying `profile` when there is one, stamped with
    /// the local time.
    pub fn new(sink: impl Write + Send + 'static, profile: Option<String>) -> Self {
        Log::clocked(sink, profile, || (SystemTime::now(), local_offset()))
    }

    /// [`new`](Log::new) with `clock` giving the time and its offset from UTC in minutes.
    pub fn clocked(
        sink: impl Write + Send + 'static,
        profile: Option<String>,
        clock: impl Fn() -> (SystemTime, i32) + Send + Sync + 'static,
    ) -> Self {
        Log(Some(Arc::new(Inner {
            sink: Mutex::new(Box::new(sink)),
            profile: profile.filter(|p| !p.is_empty()),
            clock: Box::new(clock),
        })))
    }

    /// A log that writes nothing.
    pub fn discard() -> Self {
        Log(None)
    }

    pub fn info(&self, msg: impl AsRef<[u8]>, attrs: &[(&str, Value)]) {
        self.write(Level::Info, msg.as_ref(), attrs);
    }

    pub fn warn(&self, msg: impl AsRef<[u8]>, attrs: &[(&str, Value)]) {
        self.write(Level::Warn, msg.as_ref(), attrs);
    }

    pub fn error(&self, msg: impl AsRef<[u8]>, attrs: &[(&str, Value)]) {
        self.write(Level::Error, msg.as_ref(), attrs);
    }

    fn write(&self, level: Level, msg: &[u8], attrs: &[(&str, Value)]) {
        let Some(inner) = &self.0 else {
            return;
        };
        let (now, offset) = (inner.clock)();
        let profile = inner
            .profile
            .as_deref()
            .map(|p| ("profile", Value::from(p)));
        let all: Vec<(&str, Value)> = profile.into_iter().chain(attrs.iter().cloned()).collect();
        let text = line(now, offset, level, msg, &all);
        let mut sink = inner.sink.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = sink.write_all(&text);
    }
}

/// One line as slog's text handler writes it: `time=`, `level=`, `msg=`, then each attribute,
/// every value quoted when it would not read back as one token, and a newline.
pub fn line(
    time: SystemTime,
    offset_minutes: i32,
    level: Level,
    msg: &[u8],
    attrs: &[(&str, Value)],
) -> Vec<u8> {
    let mut out = b"time=".to_vec();
    out.extend(rfc3339_millis(time, offset_minutes).as_bytes());
    out.extend(b" level=");
    out.extend(match level {
        Level::Info => &b"INFO"[..],
        Level::Warn => b"WARN",
        Level::Error => b"ERROR",
    });
    out.extend(b" msg=");
    text(&mut out, msg);
    for (key, value) in attrs {
        out.push(b' ');
        text(&mut out, key.as_bytes());
        out.push(b'=');
        match value {
            Value::Text(t) => text(&mut out, t),
            Value::Int(n) => out.extend(n.to_string().as_bytes()),
        }
    }
    out.push(b'\n');
    out
}

fn text(out: &mut Vec<u8>, s: &[u8]) {
    if needs_quoting(s) {
        out.extend(quote(s).as_bytes());
    } else {
        out.extend(s);
    }
}

/// Whether slog's text handler quotes `s`: empty, or holding a space, `=`, `"`, a control
/// character, bytes that are not UTF-8, or a character that is white space or not printable.
fn needs_quoting(s: &[u8]) -> bool {
    if s.is_empty() {
        return true;
    }
    let mut rest = s;
    while let Some(&b) = rest.first() {
        if b < 0x80 {
            if b != b'\\' && (b == b' ' || b == b'=' || b == b'"' || !(0x20..0x7f).contains(&b)) {
                return true;
            }
            rest = &rest[1..];
            continue;
        }
        let Some((c, n)) = decode(rest) else {
            return true;
        };
        if c == char::REPLACEMENT_CHARACTER || c.is_whitespace() || !printable(c) {
            return true;
        }
        rest = &rest[n..];
    }
    false
}

/// `s` as Go's `strconv.Quote` writes it: in double quotes, with `"` and `\` backslashed,
/// printable characters as they are, the usual escapes, `\xNN` for bytes that are not UTF-8
/// and for other control characters below U+0080, and `\uNNNN` or `\UNNNNNNNN` for the rest.
pub fn quote(s: &[u8]) -> String {
    let mut out = String::from("\"");
    let mut rest = s;
    while !rest.is_empty() {
        let Some((c, n)) = decode(rest) else {
            out.push_str(&format!("\\x{:02x}", rest[0]));
            rest = &rest[1..];
            continue;
        };
        rest = &rest[n..];
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            c if printable(c) => out.push(c),
            '\x07' => out.push_str("\\a"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x0b' => out.push_str("\\v"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c if (c as u32) < 0x10000 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    out.push('"');
    out
}

/// The character `s` starts with and its length, when it starts with one in UTF-8.
fn decode(s: &[u8]) -> Option<(char, usize)> {
    let n = match s.first()? {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return None,
    };
    let c = std::str::from_utf8(s.get(..n)?).ok()?.chars().next()?;
    Some((c, n))
}

/// Whether Go's `strconv.IsPrint` takes `c` as printable: a letter, mark, number, punctuation
/// or symbol, or the ASCII space. Without Unicode's category tables this treats every
/// assigned-looking character as printable but control, white space other than the space,
/// format characters and private use.
fn printable(c: char) -> bool {
    if c == ' ' {
        return true;
    }
    if c.is_control() || c.is_whitespace() {
        return false;
    }
    let u = c as u32;
    let format = matches!(u,
        0xad | 0x600..=0x605 | 0x61c | 0x6dd | 0x70f | 0x890..=0x891 | 0x8e2 | 0x180e
        | 0x200b..=0x200f | 0x202a..=0x202e | 0x2060..=0x2064 | 0x2066..=0x206f | 0xfeff
        | 0xfff9..=0xfffb | 0x110bd | 0x110cd | 0x13430..=0x1343f | 0x1bca0..=0x1bca3
        | 0x1d173..=0x1d17a | 0xe0001 | 0xe0020..=0xe007f);
    let private = matches!(u, 0xe000..=0xf8ff | 0xf0000..=0x10ffff);
    let nonchar = (u & 0xfffe) == 0xfffe || (0xfdd0..=0xfdef).contains(&u);
    !(format || private || nonchar)
}

/// `t` in RFC 3339 with milliseconds, at `offset_minutes` from UTC, as slog writes it.
pub fn rfc3339_millis(t: SystemTime, offset_minutes: i32) -> String {
    let ms = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis() as i64,
        Err(e) => -(e.duration().as_millis() as i64),
    };
    let local = ms + i64::from(offset_minutes) * 60_000;
    let (days, day_ms) = (local.div_euclid(86_400_000), local.rem_euclid(86_400_000));
    let (y, m, d) = civil(days);
    let secs = day_ms / 1000;
    let zone = match offset_minutes {
        0 => "Z".to_owned(),
        o => format!(
            "{}{:02}:{:02}",
            if o < 0 { '-' } else { '+' },
            o.abs() / 60,
            o.abs() % 60
        ),
    };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}{zone}",
        secs / 3600,
        secs / 60 % 60,
        secs % 60,
        day_ms % 1000
    )
}

/// The calendar date `days` after 1970-01-01.
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// `d` as Go's `time.Duration` prints a whole number of seconds: `3m0s`, `1h0m5s`, `15s`.
pub fn go_duration(d: Duration) -> String {
    let s = d.as_secs();
    match (s / 3600, s / 60 % 60, s % 60) {
        (0, 0, sec) => format!("{sec}s"),
        (0, min, sec) => format!("{min}m{sec}s"),
        (h, min, sec) => format!("{h}h{min}m{sec}s"),
    }
}

/// This machine's offset from UTC now, in minutes. Read on Windows; elsewhere UTC.
pub fn local_offset() -> i32 {
    crate::peer::utc_offset_minutes()
}
