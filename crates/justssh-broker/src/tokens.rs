//! The tokens issued over the pipe, each standing for the credential it was issued for, shared
//! between the pipe and the connections that present them.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::issue::{Issue, Method};

/// A token, the issue it stands for, and the shells open on it across its connections.
#[derive(Debug)]
struct Entry {
    id: u64,
    token: Zeroizing<String>,
    issue: Issue,
    shells: u32,
}

#[derive(Debug, Default)]
struct Issued {
    next: u64,
    entries: Vec<Entry>,
}

/// The issued tokens. Clones share them.
#[derive(Debug, Clone, Default)]
pub struct Tokens {
    issued: Arc<Mutex<Issued>>,
}

/// What a presented token stands for: where to connect and as whom, and the token itself.
#[derive(Debug)]
#[non_exhaustive]
pub struct Grant {
    pub upstream: Vec<u8>,
    pub username: Vec<u8>,
    pub method: Method,
    pub password: Option<Zeroizing<Vec<u8>>>,
    pub handle: Handle,
}

/// One connection's handle back to the token it presented. A token no longer issued allows
/// nothing.
#[derive(Debug, Clone)]
pub struct Handle {
    tokens: Tokens,
    id: u64,
}

/// The shell open on a token, given back when dropped.
#[derive(Debug)]
pub struct Shell(Handle);

impl Tokens {
    /// Registers `issue` under a new token, which it returns.
    pub fn issue(&self, issue: Issue) -> Zeroizing<String> {
        let mut issued = self.lock();
        let token = loop {
            let token = mint();
            if !issued.entries.iter().any(|e| e.token == token) {
                break token;
            }
        };
        let id = issued.next;
        issued.next += 1;
        issued.entries.push(Entry {
            id,
            token: token.clone(),
            issue,
            shells: 0,
        });
        token
    }

    /// What `presented` stands for when it is a token issued for `username`. Every token is
    /// compared in constant time, with no early return.
    pub fn authorize(&self, presented: &[u8], username: &[u8]) -> Option<Grant> {
        let issued = self.lock();
        let mut found = None;
        for e in issued.entries.iter() {
            if bool::from(e.token.as_bytes().ct_eq(presented)) {
                found = Some(e);
            }
        }
        let e = found.filter(|e| e.issue.username == username)?;
        Some(Grant {
            upstream: e.issue.upstream.clone(),
            username: e.issue.username.clone(),
            method: e.issue.method,
            password: e.issue.password.clone(),
            handle: Handle {
                tokens: self.clone(),
                id: e.id,
            },
        })
    }

    fn lock(&self) -> MutexGuard<'_, Issued> {
        self.issued.lock().unwrap_or_else(PoisonError::into_inner)
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
        let mut issued = self.tokens.lock();
        issued.entries.iter_mut().find(|e| e.id == self.id).map(f)
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
