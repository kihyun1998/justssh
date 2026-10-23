//! acwbroker's log file: appended, owner-only, rotated by size, and shared by every profile's
//! broker (acwbroker `infrastructure/logfile`).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// The log file's name in its folder.
pub const NAME: &str = "acwbroker.log";
/// The size at which it rotates.
pub const LIMIT: u64 = 5 << 20;
/// How many files there are in all, the current one included.
pub const KEEP: usize = 3;

/// Lines appended to `path`, which is moved to `path.1` (and `path.1` to `path.2`, up to
/// `keep - 1`) when the next line would take it past `limit`. Before every line the file held
/// is checked against the one at `path`, and reopened when another process rotated or removed
/// it.
#[derive(Debug)]
pub struct LogFile {
    path: PathBuf,
    limit: u64,
    keep: usize,
    file: File,
}

impl LogFile {
    pub fn open(path: &Path, limit: u64, keep: usize) -> io::Result<Self> {
        if limit == 0 || keep == 0 {
            return Err(io::Error::other(
                "logfile: the limit and keep must be positive",
            ));
        }
        Ok(LogFile {
            path: path.to_owned(),
            limit,
            keep,
            file: open_append(path)?,
        })
    }

    /// Reopens the file at `path` when the one held is no longer it.
    fn follow(&mut self) -> io::Result<()> {
        match same_file(&self.file, &self.path) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        self.reopen()
    }

    fn rotate(&mut self) -> io::Result<()> {
        for i in (1..self.keep).rev() {
            let from = match i {
                1 => self.path.clone(),
                _ => numbered(&self.path, i - 1),
            };
            match fs::rename(&from, numbered(&self.path, i)) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => break,
                _ => {}
            }
        }
        if self.keep == 1 {
            let _ = fs::remove_file(&self.path);
        }
        self.reopen()
    }

    fn reopen(&mut self) -> io::Result<()> {
        self.file = open_append(&self.path)?;
        Ok(())
    }
}

impl Write for LogFile {
    /// Appends `buf` as one unit: a line is never split across two files, even one over the
    /// limit by itself.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.follow()?;
        let size = self.file.metadata()?.len();
        if size > 0 && size + buf.len() as u64 > self.limit {
            self.rotate()?;
        }
        self.file.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn numbered(path: &Path, n: usize) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(format!(".{n}"));
    PathBuf::from(s)
}

/// Writes every line to each of its writers, and reports success whatever they do.
#[derive(Debug)]
pub struct Tee<A, B>(A, B);

impl<A, B> Tee<A, B> {
    pub fn new(a: A, b: B) -> Self {
        Tee(a, b)
    }

    /// The first writer.
    pub fn first(&self) -> &A {
        &self.0
    }
}

impl<A: Write, B: Write> Write for Tee<A, B> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let _ = self.0.write_all(buf);
        let _ = self.1.write_all(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let _ = self.0.flush();
        let _ = self.1.flush();
        Ok(())
    }
}

/// Opens `path` for appending, creating it; shared for reading, writing and deleting so that
/// another process can rotate it.
#[cfg(windows)]
fn open_append(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;
    OpenOptions::new()
        .append(true)
        .create(true)
        .share_mode(SHARE_ALL)
        .open(path)
}

/// Opens `path` for appending, creating it owner-only.
#[cfg(not(windows))]
fn open_append(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)
}

/// Whether `held` is the file now at `path`.
#[cfg(windows)]
fn same_file(held: &File, path: &Path) -> io::Result<bool> {
    crate::peer::same_file(held, path)
}

/// Whether `held` is the file now at `path`.
#[cfg(not(windows))]
fn same_file(held: &File, path: &Path) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let (h, at) = (held.metadata()?, fs::metadata(path)?);
    Ok(h.dev() == at.dev() && h.ino() == at.ino())
}
