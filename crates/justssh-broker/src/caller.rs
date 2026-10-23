//! Who is on the other end of a downstream connection: the process that owns it, measured
//! from the operating system at one instant (acwbroker `domain/model/caller.go`,
//! `infrastructure/peer/chain.go`, `identify.go`). Measuring is [`crate::peer`]'s; judging is
//! [`crate::tokens`]'s.

use std::collections::HashSet;
use std::time::SystemTime;

/// The measured identity of whoever opened a downstream connection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Caller {
    pub pid: u32,
    /// The caller's own executable, empty when it could not be read.
    pub image_path: String,
    /// The caller and its ancestors, nearest first, as far as the walk got.
    pub ancestry: Vec<u32>,
    /// `ancestry` with each process's start time.
    pub lineage: Vec<ProcessKey>,
    /// Why the measurement failed, when it did.
    pub error: Option<String>,
    /// The Windows logon session, when it was read.
    pub session: Option<u32>,
    /// The account's SID, when it was read.
    pub user: Option<String>,
}

/// A process named so that a reused pid cannot match it: whatever takes the pid later starts
/// later. `created` is `None` when the start time could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProcessKey {
    pub pid: u32,
    pub created: Option<SystemTime>,
}

/// One process in a snapshot of the process list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProcessInfo {
    pub pid: u32,
    pub parent: u32,
    pub created: Option<SystemTime>,
    /// The executable's name, for a log line only.
    pub name: String,
}

/// One process of this session with its full executable path, or why that could not be read.
/// `name` is the executable's file name, which the process list carries even then.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProcessImage {
    pub pid: u32,
    pub name: String,
    pub image: String,
    pub created: Option<SystemTime>,
    pub error: Option<String>,
}

impl ProcessImage {
    pub fn new(pid: u32, image: &str, created: Option<SystemTime>) -> Self {
        ProcessImage {
            pid,
            image: image.to_owned(),
            created,
            ..ProcessImage::default()
        }
    }

    /// A process whose path could not be read, known by its file name.
    pub fn unreadable(pid: u32, name: &str, error: &str) -> Self {
        ProcessImage {
            pid,
            name: name.to_owned(),
            error: Some(error.to_owned()),
            ..ProcessImage::default()
        }
    }
}

/// A snapshot of the process list.
pub trait ProcessTable {
    fn info(&self, pid: u32) -> Result<ProcessInfo, String>;
}

/// How far up an ancestry walk goes.
pub const MAX_DEPTH: usize = 12;

/// Why an ancestry walk stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Stop {
    NoParent,
    ParentGone,
    /// The recorded parent started after its child, so the pid was reused.
    StaleParent,
    Cycle,
    Depth,
    /// The caller itself is not in the snapshot.
    Unreadable,
}

/// The processes an ancestry walk reached, nearest first, and why it stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Chain {
    pub links: Vec<ProcessInfo>,
    pub stop: Stop,
    pub error: Option<String>,
}

/// The owner of a connection as the operating system reports it, before its ancestry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Owner {
    pub pid: u32,
    pub image_path: String,
    pub error: Option<String>,
    pub session: Option<u32>,
    pub user: Option<String>,
}

impl ProcessKey {
    pub fn new(pid: u32, created: Option<SystemTime>) -> Self {
        ProcessKey { pid, created }
    }
}

impl ProcessInfo {
    pub fn new(pid: u32, parent: u32, created: Option<SystemTime>) -> Self {
        ProcessInfo {
            pid,
            parent,
            created,
            name: String::new(),
        }
    }
}

impl Owner {
    /// An owner that could not be measured at all.
    pub fn unmeasured(error: impl Into<String>) -> Self {
        Owner {
            error: Some(error.into()),
            ..Owner::default()
        }
    }
}

/// Walks `pid`'s ancestry in `table`, nearest first, up to [`MAX_DEPTH`] processes.
pub fn walk(table: &dyn ProcessTable, pid: u32) -> Chain {
    let mut cur = match table.info(pid) {
        Ok(p) => p,
        Err(e) => {
            return Chain {
                links: Vec::new(),
                stop: Stop::Unreadable,
                error: Some(e),
            };
        }
    };
    let mut links = Vec::new();
    let mut seen = HashSet::new();
    let stop = loop {
        seen.insert(cur.pid);
        let parent_pid = cur.parent;
        let child = cur.clone();
        links.push(cur);
        if links.len() >= MAX_DEPTH {
            break Stop::Depth;
        }
        if parent_pid == 0 || parent_pid == child.pid {
            break Stop::NoParent;
        }
        if seen.contains(&parent_pid) {
            break Stop::Cycle;
        }
        let Ok(parent) = table.info(parent_pid) else {
            break Stop::ParentGone;
        };
        if let (Some(p), Some(c)) = (parent.created, child.created)
            && p > c
        {
            break Stop::StaleParent;
        }
        cur = parent;
    };
    Chain {
        links,
        stop,
        error: None,
    }
}

impl Caller {
    pub fn new(pid: u32) -> Self {
        Caller {
            pid,
            ..Caller::default()
        }
    }

    /// The caller `owner` describes, with the ancestry `table` gives it. Without a table the
    /// ancestry is left unmeasured.
    pub fn measure(owner: Owner, table: Option<Result<&dyn ProcessTable, String>>) -> Self {
        let mut c = Caller {
            pid: owner.pid,
            image_path: owner.image_path,
            error: owner.error,
            session: owner.session,
            user: owner.user,
            ..Caller::default()
        };
        if c.error.is_some() {
            return c;
        }
        match table {
            None => {}
            Some(Err(e)) => c.error = Some(e),
            Some(Ok(t)) => {
                let chain = walk(t, c.pid);
                if chain.stop == Stop::Unreadable {
                    c.error = chain.error;
                    return c;
                }
                c.ancestry = chain.links.iter().map(|l| l.pid).collect();
                c.lineage = chain
                    .links
                    .iter()
                    .map(|l| ProcessKey::new(l.pid, l.created))
                    .collect();
            }
        }
        c
    }

    fn walked(&self) -> bool {
        self.error.is_none() && !self.ancestry.is_empty()
    }

    /// No process owning the connection was found.
    pub fn unowned(&self) -> bool {
        self.error.is_some() && self.pid == 0
    }

    /// Whether `root` is the caller or one of its ancestors. An unmeasured caller descends
    /// from nothing.
    pub fn descends_from(&self, root: u32) -> bool {
        self.error.is_none() && root != 0 && self.ancestry.contains(&root)
    }

    /// Whether the caller or one of its ancestors is one of `holders`, by pid and start time.
    pub fn descends_from_any(&self, holders: &[ProcessKey]) -> bool {
        self.walked() && self.lineage.iter().any(|k| holders.contains(k))
    }

    /// The process ids a token may be pinned to: inside the tree of `app`, the caller and its
    /// ancestors below `app`; outside it, the caller alone.
    pub fn identity(&self, app: u32) -> Vec<u32> {
        if !self.walked() {
            return match self.pid {
                0 => Vec::new(),
                pid => vec![pid],
            };
        }
        if !self.descends_from(app) {
            return vec![self.ancestry[0]];
        }
        self.ancestry
            .iter()
            .copied()
            .take_while(|&p| p != app)
            .collect()
    }

    /// Whether the caller is one of `pinned`, or descends from one.
    pub fn matches(&self, pinned: &[u32]) -> bool {
        if !self.walked() {
            return self.pid != 0 && pinned.contains(&self.pid);
        }
        self.ancestry.iter().any(|a| pinned.contains(a))
    }
}
