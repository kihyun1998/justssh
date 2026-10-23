//! The tokens issued over the pipe, each standing for the credential it was issued for, and
//! who may present them for how long (acwbroker `service/tokens`).

use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;

use subtle::ConstantTimeEq;
use tokio::runtime::Handle as Runtime;
use tokio::sync::{Notify, oneshot};
use tokio::task::AbortHandle;
use tokio::time::{Instant, sleep_until};
use zeroize::Zeroizing;

use crate::caller::{Caller, ProcessKey};
use crate::issue::{Issue, Method};
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
}

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
    /// Watches pinned processes for their exit.
    pub hold: Option<Arc<dyn Hold>>,
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
}

#[derive(Default)]
struct Issued {
    next: u64,
    entries: Vec<Entry>,
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
    pub method: Method,
    pub password: Option<Zeroizing<Vec<u8>>>,
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
                    issued.remove(id);
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
        });
        token
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
        issued.remove(id);
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
    /// acwbroker's order: the logon session, the connection's owner, the user, the token
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
            method: e.issue.method,
            password: e.issue.password.clone(),
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
                issued.remove(id);
                return Err(Refusal::TokenExpired);
            }
            e.first_at = Some(now);
            if let Some(t) = e.expiry.take() {
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
            let Some(Ok(held)) = hold.as_ref().map(|h| h.hold(pid)) else {
                continue;
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
            issued.remove(id);
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
        let mut delay = (!c.idle.is_zero()).then_some(c.idle);
        if !c.admit.is_zero()
            && let Some(first) = e.first_at
        {
            let left = (first + c.admit).saturating_duration_since(Instant::now());
            if delay.is_none_or(|d| left < d) {
                delay = Some(left);
            }
        }
        let Some(delay) = delay else {
            return;
        };
        if let Some(t) = e.idle.take() {
            t.abort();
        }
        e.idle = Some(self.after(delay, move |t| {
            let mut issued = t.lock();
            if issued.find(id).is_some_and(|e| e.conns == 0) {
                issued.remove(id);
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

    /// Disposes of token `id`: its live upstreams are told to close, its timers and watches
    /// stop, and its token and credential are zeroed as they drop.
    fn remove(&mut self, id: u64) {
        let Some(i) = self.entries.iter().position(|e| e.id == id) else {
            return;
        };
        let e = self.entries.swap_remove(i);
        for (_, up) in &e.ups {
            up.notify_one();
        }
        for t in e.holds.iter().chain(&e.expiry).chain(&e.idle) {
            t.abort();
        }
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
