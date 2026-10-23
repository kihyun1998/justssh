//! The tokens issued over the pipe, each standing for the credential it was issued for, shared
//! between the pipe and the connections that present them.

use std::sync::{Arc, Mutex, PoisonError};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::issue::{Issue, Method};

/// A token and the issue it stands for.
type Entry = (Zeroizing<String>, Issue);

/// The issued tokens. Clones share them.
#[derive(Debug, Clone, Default)]
pub struct Tokens {
    issued: Arc<Mutex<Vec<Entry>>>,
}

/// What a presented token stands for: where to connect and as whom.
#[derive(Debug)]
#[non_exhaustive]
pub struct Grant {
    pub upstream: Vec<u8>,
    pub username: Vec<u8>,
    pub method: Method,
    pub password: Option<Zeroizing<Vec<u8>>>,
}

impl Tokens {
    /// Registers `issue` under a new token, which it returns.
    pub fn issue(&self, issue: Issue) -> Zeroizing<String> {
        let mut issued = self.issued.lock().unwrap_or_else(PoisonError::into_inner);
        let token = loop {
            let token = mint();
            if !issued.iter().any(|(t, _)| *t == token) {
                break token;
            }
        };
        issued.push((token.clone(), issue));
        token
    }

    /// What `presented` stands for when it is a token issued for `username`. Every token is
    /// compared in constant time, with no early return.
    pub fn authorize(&self, presented: &[u8], username: &[u8]) -> Option<Grant> {
        let issued = self.issued.lock().unwrap_or_else(PoisonError::into_inner);
        let mut found = None;
        for (token, issue) in issued.iter() {
            if bool::from(token.as_bytes().ct_eq(presented)) {
                found = Some(issue);
            }
        }
        let issue = found.filter(|i| i.username == username)?;
        Some(Grant {
            upstream: issue.upstream.clone(),
            username: issue.username.clone(),
            method: issue.method,
            password: issue.password.clone(),
        })
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
