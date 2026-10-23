//! Removing what the app wrote a token into: each file is overwritten with zeros and flushed,
//! then the path is removed (acwbroker `infrastructure/shred`).

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How long [`Shredder::shred`] keeps trying a path it could not remove.
pub const DEFAULT_RETRY: Duration = Duration::from_secs(5);
/// The pause between tries.
pub const DEFAULT_EVERY: Duration = Duration::from_millis(200);

/// Shreds entries directly under its roots, never a root itself.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Shredder {
    pub roots: Vec<PathBuf>,
    pub retry: Duration,
    pub every: Duration,
}

impl Shredder {
    pub fn new(roots: Vec<PathBuf>) -> Self {
        Shredder {
            roots,
            retry: DEFAULT_RETRY,
            every: DEFAULT_EVERY,
        }
    }

    /// Whether `path` may be shredded: an absolute path to an existing entry directly under a
    /// root, and not a link.
    pub fn admit(&self, path: &str) -> Result<(), String> {
        self.check(path).map_err(|e| e.to_string())
    }

    fn check(&self, path: &str) -> Result<(), io::Error> {
        let outside = || io::Error::other("the path is not directly under an attach root");
        if !Path::new(path).is_absolute() {
            return Err(outside());
        }
        let cleaned = clean(path);
        let parent = dir(&cleaned);
        if !self
            .roots
            .iter()
            .filter(|r| !r.as_os_str().is_empty())
            .any(|r| same_path(&parent, &clean(&r.to_string_lossy())))
        {
            return Err(outside());
        }
        let meta = fs::symlink_metadata(&cleaned)?;
        if is_link(&cleaned, &meta) {
            return Err(io::Error::other("the path is a link"));
        }
        Ok(())
    }

    /// Zero-fills and removes `path`, a file or a whole folder, trying again for
    /// [`retry`](Shredder::retry). A path already gone is done; one still failing at the
    /// deadline is left as it is.
    pub fn shred(&self, path: &str) -> Result<(), String> {
        match self.check(path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.to_string()),
        }
        let deadline = Instant::now() + self.retry;
        let path = clean(path);
        loop {
            match shred_once(Path::new(&path)) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(e) if Instant::now() >= deadline => return Err(e.to_string()),
                Err(_) => std::thread::sleep(self.every),
            }
        }
    }
}

/// Zero-fills every regular file under `path`, then removes `path`.
fn shred_once(path: &Path) -> io::Result<()> {
    let mut first = None;
    zero_tree(path, &mut first)?;
    if let Some(e) = first {
        return Err(e);
    }
    let meta = fs::symlink_metadata(path)?;
    if meta.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
}

/// Zero-fills the regular files under `path`, without following links, keeping the first
/// failure to fill one.
fn zero_tree(path: &Path, first: &mut Option<io::Error>) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.is_dir() {
        for entry in fs::read_dir(path)? {
            zero_tree(&entry?.path(), first)?;
        }
    } else if meta.is_file()
        && let Err(e) = zero_fill(path)
        && first.is_none()
    {
        *first = Some(e);
    }
    Ok(())
}

/// Overwrites a file's bytes in place with zeros, and flushes them.
fn zero_fill(path: &Path) -> io::Result<()> {
    let mut f = OpenOptions::new().write(true).open(path)?;
    let len = f.metadata()?.len();
    io::copy(&mut io::Read::take(io::repeat(0), len), &mut f)?;
    f.flush()?;
    f.sync_all()
}

#[cfg(windows)]
use crate::rule::{clean, dir};

#[cfg(windows)]
fn same_path(a: &str, b: &str) -> bool {
    crate::rule::fold_eq(a, b)
}

/// Whether `meta`, read without following links, is a link: on Windows any reparse point but
/// a deduplicated file or a Unix socket, as Go's `os.Lstat` reports them.
#[cfg(windows)]
fn is_link(path: &str, meta: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const REPARSE_POINT: u32 = 0x400;
    const DEDUP: u32 = 0x8000_0013;
    const AF_UNIX: u32 = 0x8000_0023;
    if meta.file_attributes() & REPARSE_POINT == 0 {
        return false;
    }
    !matches!(crate::peer::reparse_tag(path), Some(DEDUP | AF_UNIX))
}

#[cfg(not(windows))]
fn clean(path: &str) -> String {
    let rooted = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => match parts.last() {
                Some(&p) if p != ".." => {
                    parts.pop();
                }
                _ if rooted => {}
                _ => parts.push(".."),
            },
            p => parts.push(p),
        }
    }
    let out = format!("{}{}", if rooted { "/" } else { "" }, parts.join("/"));
    if out.is_empty() { ".".to_owned() } else { out }
}

#[cfg(not(windows))]
fn dir(path: &str) -> String {
    clean(path.rfind('/').map_or("", |i| &path[..=i]))
}

#[cfg(not(windows))]
fn same_path(a: &str, b: &str) -> bool {
    a == b
}

#[cfg(not(windows))]
fn is_link(_path: &str, meta: &fs::Metadata) -> bool {
    meta.file_type().is_symlink()
}
