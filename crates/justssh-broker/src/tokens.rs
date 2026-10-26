//! The tokens issued over the pipe, each standing for the credential it was issued for, and
//! who may present them for how long (acwbroker `service/tokens`).

use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, SystemTime};

use subtle::ConstantTimeEq;
use tokio::runtime::Handle as Runtime;
use tokio::sync::{Notify, oneshot};
use tokio::task::AbortHandle;
use tokio::time::{Instant, sleep_until};
use zeroize::Zeroizing;

use crate::caller::{Caller, ProcessImage, ProcessKey};
use crate::credential::Credential;
use crate::issue::Issue;
use crate::rule::{self, ImageMetadata};

/// How long a token stays live with nothing having used it.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(60);
/// How long after the first connection other processes may still claim the token.
pub const DEFAULT_GRACE: Duration = Duration::from_secs(5);
/// How long a credential outlives its last connection.
pub const DEFAULT_IDLE: Duration = Duration::from_secs(60);
/// How long after the first connection the token accepts new connections.
pub const DEFAULT_ADMIT: Duration = Duration::from_secs(60);

/// How the tokens are judged. A zero duration turns its limit off.
#[derive(Clone)]
#[non_exhaustive]
pub struct Config {
    pub window: Duration,
    pub grace: Duration,
    pub idle: Duration,
    pub admit: Duration,
    /// The process every program the app launches descends from. Zero puts nothing in tree.
    pub app: u32,
    pub peer: Peer,
    /// Told, each, the processes reported for a token when it is first used.
    pub claimed: Option<Tell>,
    /// Told, each, the processes reported for a token disposed of before its first use.
    pub unclaimed: Option<Tell>,
    /// Handed each path attached to a token once the token is used, expires, is disposed of
    /// or the tokens freeze. Without it every attached path is kept.
    pub shred: Option<Shred>,
    /// Told why each token disposed of was, and how many are left; a token that expired is
    /// not told.
    pub disposed: Option<Disposed>,
    /// Told each pinned process that could not be watched for its exit, and why.
    pub hold_failed: Option<HoldFailed>,
}

/// Told why a token was disposed of, and how many tokens are live after it.
pub type Disposed = Arc<dyn Fn(&str, usize) + Send + Sync>;

/// Told a pinned process that could not be watched, and why.
pub type HoldFailed = Arc<dyn Fn(u32, &str) + Send + Sync>;

/// Told a process id, on the tokens' runtime.
pub type Tell = Arc<dyn Fn(u32) + Send + Sync>;

/// Handed a path to shred, on the tokens' runtime.
pub type Shred = Arc<dyn Fn(String) + Send + Sync>;

/// Lists the processes of this session with their executables.
pub type Candidates = Arc<dyn Fn() -> Result<Vec<ProcessImage>, String> + Send + Sync>;

/// What the tokens ask of this machine. Every field left empty turns its check off.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct Peer {
    /// This process's logon session; a caller in another, or in none read, is refused.
    pub own_session: Option<u32>,
    /// This process's account SID; a caller of another, or of none read, is refused.
    pub own_user: Option<String>,
    /// Reads an executable's version resource, for the caller rules that fall back to it.
    pub metadata: Option<ReadImage>,
    /// Watches pinned processes, and launched ones before use, for their exit.
    pub hold: Option<Arc<dyn Hold>>,
    /// What else in this session could present a token whose launched process has gone.
    /// Without it such a token is left to its window.
    pub candidates: Option<Candidates>,
}

/// Reads an executable's version resource.
pub type ReadImage = Arc<dyn Fn(&str) -> Result<ImageMetadata, String> + Send + Sync>;

/// Watches processes for their exit.
pub trait Hold: Send + Sync {
    fn hold(&self, pid: u32) -> Result<Held, String>;
}

/// One process watched for its exit: the sender firing is the exit, and the sender dropped
/// without firing is a watch that ended without seeing one. Dropping this stops the watch.
#[derive(Debug)]
pub struct Held(oneshot::Receiver<()>);

impl Held {
    pub fn channel() -> (oneshot::Sender<()>, Held) {
        let (tx, rx) = oneshot::channel();
        (tx, Held(rx))
    }

    /// Resolves when the watch ends, to whether it saw the process exit.
    pub async fn exited(self) -> bool {
        self.0.await.is_ok()
    }
}

/// Why a presented token was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    Frozen,
    SessionUnknown,
    OtherSession,
    OwnerUnknown,
    UserUnknown,
    OtherUser,
    UnknownToken,
    UsernameMismatch,
    NotTheProgram(String),
    WrongTerminal,
    TokenExpired,
    AdmissionClosed,
    CallerNotPinned,
}

/// Why an ATTACH was not taken.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttachError {
    UnknownToken,
    AlreadyAttached,
    /// The path may not be shredded.
    Refused(String),
}

impl std::fmt::Display for Refusal {
    /// acwbroker's words for it (`domain/model`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Refusal::Frozen => "frozen; no new connections",
            Refusal::SessionUnknown => "the caller's Windows session could not be read",
            Refusal::OtherSession => "the caller runs in another Windows session",
            Refusal::OwnerUnknown => {
                "the process owning the caller's connection could not be found"
            }
            Refusal::UserUnknown => "the caller's Windows user could not be read",
            Refusal::OtherUser => "the caller runs as another Windows user",
            Refusal::UnknownToken => "no live token matches the presented password",
            Refusal::UsernameMismatch => {
                "the presented username is not the one bound to this token"
            }
            Refusal::NotTheProgram(why) => {
                return write!(
                    f,
                    "acwbroker: the caller is not the program the token was issued for: {why}"
                );
            }
            Refusal::WrongTerminal => {
                "this caller is not running in the terminal the token was issued for"
            }
            Refusal::TokenExpired => "the token expired before anything used it",
            Refusal::AdmissionClosed => "admission closed",
            Refusal::CallerNotPinned => "this caller is not the one that claimed the token",
        };
        write!(f, "acwbroker: {text}")
    }
}

impl std::fmt::Display for AttachError {
    /// acwbroker's words for it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttachError::UnknownToken => {
                f.write_str("acwbroker: no live token matches the presented password")
            }
            AttachError::AlreadyAttached => {
                f.write_str("acwbroker: the token already has a path attached")
            }
            AttachError::Refused(why) => f.write_str(why),
        }
    }
}

/// Which pin rule let an accepted connection in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Admission {
    /// Nothing had used the token, and this caller claimed it.
    Claim,
    /// The caller's own pid is pinned.
    Pin,
    /// One of the caller's ancestors is pinned.
    Descendant,
    /// Nothing pinned matched, but the grace after the first connection was open.
    Grace,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            window: DEFAULT_WINDOW,
            grace: DEFAULT_GRACE,
            idle: DEFAULT_IDLE,
            admit: DEFAULT_ADMIT,
            app: 0,
            peer: Peer::default(),
            claimed: None,
            unclaimed: None,
            shred: None,
            disposed: None,
            hold_failed: None,
        }
    }
}

/// A live token and everything it authorises.
struct Entry {
    id: u64,
    token: Zeroizing<String>,
    issue: Issue,
    /// The processes a terminal-bound token's callers must descend from.
    holders: Option<Vec<ProcessKey>>,
    grace: Duration,
    issued_at: Instant,
    first_at: Option<Instant>,
    conns: usize,
    /// Each connection's signal to close its upstream, by connection.
    ups: Vec<(u64, Arc<Notify>)>,
    shells: u32,
    pins: Vec<u32>,
    holds: Vec<AbortHandle>,
    /// Pinned processes watched and not yet exited.
    alive: usize,
    expiry: Option<AbortHandle>,
    idle: Option<AbortHandle>,
    /// The path the app wrote the token into, until it is handed to the shredder.
    attached: Option<String>,
    /// The processes the app launched for the token, until its first use.
    reported: Vec<u32>,
    /// While nothing has used the token, the processes that could still present it.
    launch: Vec<(u32, AbortHandle)>,
    /// When the launched process exited with the token unused.
    launched_gone: Option<SystemTime>,
}

#[derive(Default)]
struct Issued {
    next: u64,
    entries: Vec<Entry>,
    /// No authorization is taken any more.
    frozen: bool,
}

struct Inner {
    config: Config,
    runtime: Runtime,
    issued: Mutex<Issued>,
}

/// The issued tokens. Clones share them.
#[derive(Clone)]
pub struct Tokens(Arc<Inner>);

/// What a presented token stands for: where to connect and as whom, and the connection it
/// was presented on.
#[derive(Debug)]
#[non_exhaustive]
pub struct Grant {
    pub upstream: Vec<u8>,
    pub username: Vec<u8>,
    pub credential: Credential,
    pub admission: Admission,
    pub conn: Conn,
}

/// A handle back to a token. A token no longer issued allows nothing.
#[derive(Clone)]
pub struct Handle {
    tokens: Weak<Inner>,
    id: u64,
}

/// One connection counted against its token until dropped.
pub struct Conn {
    handle: Handle,
    key: u64,
    disposed: Arc<Notify>,
}

/// The shell open on a token, given back when dropped.
pub struct Shell(Handle);

impl std::fmt::Debug for Tokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tokens").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conn").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Shell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shell").finish_non_exhaustive()
    }
}

impl Tokens {
    /// Tokens judged by `config`, whose timers run on `runtime`.
    pub fn new(config: Config, runtime: Runtime) -> Self {
        Tokens(Arc::new(Inner {
            config,
            runtime,
            issued: Mutex::new(Issued::default()),
        }))
    }

    /// Registers `issue` under a new token, which it returns.
    pub fn issue(&self, issue: Issue) -> Zeroizing<String> {
        self.register(issue, None)
    }

    /// [`issue`](Tokens::issue) for a token whose callers must descend from one of `holders`.
    pub fn issue_bound(&self, issue: Issue, holders: Vec<ProcessKey>) -> Zeroizing<String> {
        self.register(issue, Some(holders))
    }

    fn register(&self, issue: Issue, holders: Option<Vec<ProcessKey>>) -> Zeroizing<String> {
        let c = &self.0.config;
        let mut issued = self.lock();
        let token = loop {
            let token = mint();
            if !issued.entries.iter().any(|e| e.token == token) {
                break token;
            }
        };
        let id = issued.next;
        issued.next += 1;
        let expiry = (!c.window.is_zero()).then(|| {
            self.after(c.window, move |t| {
                let mut issued = t.lock();
                if issued.find(id).is_some_and(|e| e.first_at.is_none()) {
                    t.dispose(&mut issued, id, None);
                }
            })
        });
        issued.entries.push(Entry {
            id,
            token: token.clone(),
            grace: issue.grace.unwrap_or(c.grace),
            issue,
            holders,
            issued_at: Instant::now(),
            first_at: None,
            conns: 0,
            ups: Vec::new(),
            shells: 0,
            pins: Vec::new(),
            holds: Vec::new(),
            alive: 0,
            expiry,
            idle: None,
            attached: None,
            reported: Vec::new(),
            launch: Vec::new(),
            launched_gone: None,
        });
        token
    }

    /// Stops taking authorizations for good, wipes every credential and shreds every attached
    /// path. Connections already open go on, and the tokens' timers and watches still end them.
    pub fn freeze(&self) {
        let mut issued = self.lock();
        issued.frozen = true;
        for e in issued.entries.iter_mut() {
            e.issue.credential.wipe();
            self.shred(e);
        }
    }

    /// Carries out an ATTACH: `path`, once `admit` takes it, is attached to `token`, then
    /// `pid` is recorded as launched to use it. Says whether the token was already used.
    pub fn take_attachment(
        &self,
        token: &str,
        path: Option<&str>,
        pid: Option<u32>,
        admit: impl FnOnce(&str) -> Result<(), String>,
    ) -> Result<bool, AttachError> {
        if let Some(path) = path {
            admit(path).map_err(AttachError::Refused)?;
            self.attach(token, path)?;
        }
        match pid {
            Some(pid) => self.launched(token, pid),
            None => Ok(false),
        }
    }

    /// Hands `path` to `token`, to be shredded once the token is used, expires or is disposed
    /// of; at once when it already was used or the tokens are frozen.
    pub fn attach(&self, token: &str, path: &str) -> Result<(), AttachError> {
        let mut issued = self.lock();
        let frozen = issued.frozen;
        let e = issued.by_token(token).ok_or(AttachError::UnknownToken)?;
        if e.attached.is_some() {
            return Err(AttachError::AlreadyAttached);
        }
        e.attached = Some(path.to_owned());
        if frozen || e.first_at.is_some() {
            self.shred(e);
        }
        Ok(())
    }

    /// Records `pid` as the process the app launched to use `token`, to be told when the token
    /// is first used, and watches it: when it exits with the token unused, whatever in this
    /// session could still present the token is watched in its place, and with nothing left
    /// the token is disposed of. Says whether the token was already used, when nothing is
    /// recorded.
    pub fn launched(&self, token: &str, pid: u32) -> Result<bool, AttachError> {
        let mut issued = self.lock();
        let frozen = issued.frozen;
        let e = issued.by_token(token).ok_or(AttachError::UnknownToken)?;
        if e.first_at.is_some() {
            return Ok(true);
        }
        e.reported.push(pid);
        if !frozen {
            self.watch_launch(e, pid);
        }
        Ok(false)
    }

    /// Watches `pid` for `e` while it is unused, and says whether it could.
    fn watch_launch(&self, e: &mut Entry, pid: u32) -> bool {
        if e.launch.iter().any(|(p, _)| *p == pid) {
            return true;
        }
        let Some(Ok(held)) = self.0.config.peer.hold.as_ref().map(|h| h.hold(pid)) else {
            return false;
        };
        let (tokens, id) = (Arc::downgrade(&self.0), e.id);
        let watch = self.0.runtime.spawn(async move {
            if held.exited().await
                && let Some(inner) = tokens.upgrade()
            {
                Tokens(inner).launch_gone(id, pid);
            }
        });
        e.launch.push((pid, watch.abort_handle()));
        true
    }

    /// A process watched for unused token `id` has exited. With none left, the processes of
    /// this session that the token's rule admits and that started before the first such exit
    /// are watched in its place; with none of those either, the token is disposed of. Without
    /// a rule or a process list, or with a process named like the program that cannot be
    /// read, it is left to its window.
    fn launch_gone(&self, id: u64, pid: u32) {
        let c = &self.0.config;
        let mut issued = self.lock();
        let Some(e) = issued.find(id) else {
            return;
        };
        if let Some(i) = e.launch.iter().position(|(p, _)| *p == pid) {
            e.launch.remove(i).1.abort();
        }
        if !e.launch.is_empty() {
            return;
        }
        let cutoff = *e.launched_gone.get_or_insert_with(SystemTime::now);
        let (Some(rule), Some(read)) = (e.issue.rule.clone(), c.peer.candidates.clone()) else {
            return;
        };
        drop(issued);

        let Ok(list) = read() else {
            return;
        };
        let metadata = c
            .peer
            .metadata
            .as_deref()
            .map(|m| m as rule::ReadMetadata<'_>);
        let mut users = Vec::new();
        for p in list.iter().filter(|p| p.pid != pid) {
            if p.error.is_some() {
                if rule::named_like(&rule, &p.name) {
                    return;
                }
                continue;
            }
            if rule::admits(Some(&rule), &p.image, metadata).is_err() {
                continue;
            }
            if p.created.is_some_and(|t| t > cutoff) {
                continue;
            }
            users.push(p.pid);
        }

        let mut issued = self.lock();
        let Some(e) = issued.find(id) else {
            return;
        };
        if e.first_at.is_some() || !e.launch.is_empty() {
            return;
        }
        for u in users {
            if !self.watch_launch(e, u) {
                return;
            }
        }
        if e.launch.is_empty() {
            self.dispose(&mut issued, id, Some("program gone before use"));
        }
    }

    /// Hands `e`'s attached path to the shredder, once.
    fn shred(&self, e: &mut Entry) {
        let (Some(path), Some(shred)) = (e.attached.take(), self.0.config.shred.clone()) else {
            return;
        };
        self.0.runtime.spawn(async move { shred(path) });
    }

    /// Tells `tell` each of `pids`.
    fn tell(&self, tell: Option<&Tell>, pids: Vec<u32>) {
        let Some(tell) = tell.cloned() else {
            return;
        };
        if pids.is_empty() {
            return;
        }
        self.0.runtime.spawn(async move {
            for pid in pids {
                tell(pid);
            }
        });
    }

    /// Disposes of token `id`: the processes reported for it are told it went unused, its
    /// path is shredded, its live upstreams are told to close, its timers and watches stop,
    /// and its token and credential are zeroed as they drop. `reason`, when there is one, is
    /// reported with how many tokens are left.
    fn dispose(&self, issued: &mut Issued, id: u64, reason: Option<&'static str>) {
        let Some(mut e) = issued.remove(id) else {
            return;
        };
        if let (Some(reason), Some(report)) = (reason, self.0.config.disposed.clone()) {
            let live = issued.entries.len();
            self.0.runtime.spawn(async move { report(reason, live) });
        }
        self.tell(
            self.0.config.unclaimed.as_ref(),
            std::mem::take(&mut e.reported),
        );
        self.shred(&mut e);
        for (_, up) in &e.ups {
            up.notify_one();
        }
        let launch = e.launch.iter().map(|(_, t)| t);
        for t in e.holds.iter().chain(&e.expiry).chain(&e.idle).chain(launch) {
            t.abort();
        }
    }

    /// The process every program the app launches descends from.
    pub fn app(&self) -> u32 {
        self.0.config.app
    }

    /// Disposes of `token` and everything it holds, and says whether there was one.
    pub fn revoke(&self, token: &str) -> bool {
        let mut issued = self.lock();
        let Some(id) = issued
            .entries
            .iter()
            .find(|e| e.token.as_str() == token)
            .map(|e| e.id)
        else {
            return false;
        };
        self.dispose(&mut issued, id, Some("requested"));
        true
    }

    /// How many tokens are live.
    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// What `presented` stands for when `caller` may use it as `username`, checked in
    /// acwbroker's order: the freeze, the logon session, the connection's owner, the user, the token
    /// (every one compared in constant time, with no early return), the username, the caller
    /// rule, then the pin rules.
    pub fn authorize(
        &self,
        presented: &[u8],
        username: &[u8],
        caller: &Caller,
    ) -> Result<Grant, Refusal> {
        let c = &self.0.config;
        let mut issued = self.lock();
        let peer = &c.peer;
        if issued.frozen {
            return Err(Refusal::Frozen);
        }
        if let Some(own) = peer.own_session {
            match caller.session {
                None => return Err(Refusal::SessionUnknown),
                Some(s) if s != own => return Err(Refusal::OtherSession),
                Some(_) => {}
            }
        }
        if caller.unowned() {
            return Err(Refusal::OwnerUnknown);
        }
        if let Some(own) = &peer.own_user {
            match &caller.user {
                None => return Err(Refusal::UserUnknown),
                Some(u) if u != own => return Err(Refusal::OtherUser),
                Some(_) => {}
            }
        }
        let mut found = None;
        for e in issued.entries.iter() {
            if bool::from(e.token.as_bytes().ct_eq(presented)) {
                found = Some(e.id);
            }
        }
        let id = found.ok_or(Refusal::UnknownToken)?;
        let e = issued.find(id).expect("found");
        if e.issue.username != username {
            return Err(Refusal::UsernameMismatch);
        }
        let read = peer
            .metadata
            .as_deref()
            .map(|m| m as rule::ReadMetadata<'_>);
        rule::admits(e.issue.rule.as_ref(), &caller.image_path, read)
            .map_err(Refusal::NotTheProgram)?;
        let admission = self.pin(&mut issued, id, caller)?;

        let e = issued.find(id).expect("pinned");
        e.conns += 1;
        if let Some(t) = e.idle.take() {
            t.abort();
        }
        let key = issued.next;
        issued.next += 1;
        let disposed = Arc::new(Notify::new());
        let e = issued.find(id).expect("pinned");
        e.ups.push((key, disposed.clone()));
        Ok(Grant {
            upstream: e.issue.upstream.clone(),
            username: e.issue.username.clone(),
            credential: e.issue.credential.clone(),
            admission,
            conn: Conn {
                handle: self.handle(id),
                key,
                disposed,
            },
        })
    }

    /// Whether `caller` may use the otherwise correct token `id`, pinning it when it may. A
    /// terminal-bound token first requires the caller to descend from the terminal's holders;
    /// then, nothing having used the token, the window applies and the caller claims it;
    /// within the grace of the first connection anyone else may claim it too; after that
    /// only the pinned processes and their descendants get in, until admission closes.
    fn pin(&self, issued: &mut Issued, id: u64, caller: &Caller) -> Result<Admission, Refusal> {
        let c = &self.0.config;
        let now = Instant::now();
        let e = issued.find(id).expect("found");
        if let Some(holders) = &e.holders
            && !caller.descends_from_any(holders)
        {
            return Err(Refusal::WrongTerminal);
        }
        let Some(first) = e.first_at else {
            if !c.window.is_zero() && now - e.issued_at > c.window {
                self.dispose(issued, id, None);
                return Err(Refusal::TokenExpired);
            }
            e.first_at = Some(now);
            if let Some(t) = e.expiry.take() {
                t.abort();
            }
            self.shred(e);
            self.tell(c.claimed.as_ref(), std::mem::take(&mut e.reported));
            for (_, t) in e.launch.drain(..) {
                t.abort();
            }
            self.claim(issued, id, caller);
            return Ok(Admission::Claim);
        };
        if !c.admit.is_zero() && now - first > c.admit {
            return Err(Refusal::AdmissionClosed);
        }
        if caller.matches(&e.pins) {
            return Ok(match e.pins.contains(&caller.pid) {
                true => Admission::Pin,
                false => Admission::Descendant,
            });
        }
        if now - first <= e.grace {
            self.claim(issued, id, caller);
            return Ok(Admission::Grace);
        }
        Err(Refusal::CallerNotPinned)
    }

    /// Pins `caller` to token `id` and watches each process pinned, disposing of the token
    /// once every watched one has exited. A process that cannot be watched stays pinned.
    fn claim(&self, issued: &mut Issued, id: u64, caller: &Caller) {
        let hold = self.0.config.peer.hold.clone();
        let e = issued.find(id).expect("claimed");
        for pid in caller.identity(self.0.config.app) {
            if e.pins.contains(&pid) {
                continue;
            }
            e.pins.push(pid);
            let held = match hold.as_ref().map(|h| h.hold(pid)) {
                Some(Ok(held)) => held,
                Some(Err(why)) => {
                    if let Some(report) = self.0.config.hold_failed.clone() {
                        self.0.runtime.spawn(async move { report(pid, &why) });
                    }
                    continue;
                }
                None => continue,
            };
            let tokens = Arc::downgrade(&self.0);
            let watch = self.0.runtime.spawn(async move {
                if held.exited().await
                    && let Some(inner) = tokens.upgrade()
                {
                    Tokens(inner).gone(id, pid);
                }
            });
            e.holds.push(watch.abort_handle());
            e.alive += 1;
        }
    }

    /// Pinned process `pid` of token `id` has exited.
    fn gone(&self, id: u64, pid: u32) {
        let mut issued = self.lock();
        let Some(e) = issued.find(id) else {
            return;
        };
        e.pins.retain(|&p| p != pid);
        e.alive -= 1;
        if e.alive == 0 {
            self.dispose(&mut issued, id, Some("program exited"));
        }
    }

    /// Connection `key` of token `id` has ended. With none left, the token is disposed of
    /// after the idle time, or when admission closes if that is sooner.
    fn closed(&self, id: u64, key: u64) {
        let c = &self.0.config;
        let mut issued = self.lock();
        let Some(e) = issued.find(id) else {
            return;
        };
        e.conns -= 1;
        e.ups.retain(|(k, _)| *k != key);
        if e.conns > 0 {
            return;
        }
        let mut delay = (!c.idle.is_zero()).then_some((c.idle, "idle"));
        if !c.admit.is_zero()
            && let Some(first) = e.first_at
        {
            let left = (first + c.admit).saturating_duration_since(Instant::now());
            if delay.is_none_or(|(d, _)| left < d) {
                delay = Some((left, "admission closed"));
            }
        }
        let Some((delay, reason)) = delay else {
            return;
        };
        if let Some(t) = e.idle.take() {
            t.abort();
        }
        e.idle = Some(self.after(delay, move |t| {
            let mut issued = t.lock();
            if issued.find(id).is_some_and(|e| e.conns == 0) {
                t.dispose(&mut issued, id, Some(reason));
            }
        }));
    }

    /// Runs `f` once `delay` from now has passed, unless the tokens are gone by then.
    fn after(&self, delay: Duration, f: impl FnOnce(&Tokens) + Send + 'static) -> AbortHandle {
        let tokens = Arc::downgrade(&self.0);
        let deadline = Instant::now() + delay;
        self.0
            .runtime
            .spawn(async move {
                sleep_until(deadline).await;
                if let Some(inner) = tokens.upgrade() {
                    f(&Tokens(inner));
                }
            })
            .abort_handle()
    }

    fn handle(&self, id: u64) -> Handle {
        Handle {
            tokens: Arc::downgrade(&self.0),
            id,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Issued> {
        self.0.issued.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Issued {
    fn find(&mut self, id: u64) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|e| e.id == id)
    }

    fn by_token(&mut self, token: &str) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|e| e.token.as_str() == token)
    }

    fn remove(&mut self, id: u64) -> Option<Entry> {
        let i = self.entries.iter().position(|e| e.id == id)?;
        Some(self.entries.swap_remove(i))
    }
}

impl Handle {
    /// The token's one shell, across all its connections, or `None` while it is taken.
    pub fn open_shell(&self) -> Option<Shell> {
        self.with(|e| {
            (e.shells == 0).then(|| {
                e.shells += 1;
                Shell(self.clone())
            })
        })
        .flatten()
    }

    /// Whether the token's connections may open SFTP or SCP.
    pub fn file_transfer_allowed(&self) -> bool {
        self.with(|e| !e.issue.no_file_transfer).unwrap_or(false)
    }

    fn with<T>(&self, f: impl FnOnce(&mut Entry) -> T) -> Option<T> {
        let inner = self.tokens.upgrade()?;
        Tokens(inner).lock().find(self.id).map(f)
    }
}

impl Conn {
    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    /// Resolves once the token is disposed of, when this connection's upstream must close.
    pub async fn disposed(&self) {
        self.disposed.notified().await
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        if let Some(inner) = self.handle.tokens.upgrade() {
            Tokens(inner).closed(self.handle.id, self.key);
        }
    }
}

impl Drop for Shell {
    fn drop(&mut self) {
        self.0.with(|e| e.shells = e.shells.saturating_sub(1));
    }
}

/// A token of 16 random bytes in lowercase hex.
fn mint() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; 16]);
    getrandom::fill(&mut bytes[..]).expect("system random number generator");
    let mut token = Zeroizing::new(String::with_capacity(32));
    for b in bytes.iter() {
        token.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
        token.push(char::from(b"0123456789abcdef"[usize::from(b & 15)]));
    }
    token
}
