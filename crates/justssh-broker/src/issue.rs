//! An ISSUE payload: one credential, where it is going and the terms of its token, read as
//! acwbroker's `DecodeIssue` reads it.

use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::credential::Credential;
use crate::handoff::{find, records};

const TAG_METHOD: u8 = 0x10;
const TAG_PASSWORD: u8 = 0x11;
const TAG_PRIVATE_KEY: u8 = 0x12;
const TAG_PASSPHRASE: u8 = 0x13;
const TAG_CERTIFICATE: u8 = 0x14;
const TAG_USERNAME: u8 = 0x15;
const TAG_UPSTREAM: u8 = 0x16;
const TAG_TERMINAL: u8 = 0x17;
const TAG_NO_FILE_TRANSFER: u8 = 0x18;
const TAG_RULE_KIND: u8 = 0x19;
const TAG_RULE_PATH: u8 = 0x1a;
const TAG_RULE_COMPANY: u8 = 0x1b;
const TAG_RULE_PRODUCT: u8 = 0x1c;
const TAG_RULE_ORIGINAL: u8 = 0x1d;
const TAG_RULE_EXTRA_PATHS: u8 = 0x1e;
const TAG_GRACE: u8 = 0x1f;

const MAX_GRACE: Duration = Duration::from_secs(60);

/// How the credential authenticates upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Method {
    Password,
    Key,
    Certificate,
}

/// Which programs may present the token: a kind (1 exact path, 2 same folder, 3 folder or
/// metadata), a path, and for kind 3 the company, product and original filename.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Rule {
    pub kind: u8,
    pub path: Vec<u8>,
    pub metadata: Option<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    pub extra_paths: Vec<Vec<u8>>,
}

/// One ISSUE.
#[derive(Debug)]
#[non_exhaustive]
pub struct Issue {
    pub credential: Credential,
    pub username: Vec<u8>,
    pub upstream: Vec<u8>,
    pub terminal: Option<i32>,
    pub no_file_transfer: bool,
    pub rule: Option<Rule>,
    pub grace: Option<Duration>,
}

/// Why an ISSUE was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IssueError {
    /// The payload does not parse: the pipe is out of step.
    Malformed,
    /// It parses, and the upstream is not a loopback address.
    NotLoopback,
    /// It parses, and something else in it cannot be used.
    Refused,
}

/// Reads an ISSUE payload, copying each secret out of it.
pub fn decode(payload: &[u8]) -> Result<Issue, IssueError> {
    let rs = records(
        payload,
        &[
            TAG_METHOD,
            TAG_USERNAME,
            TAG_UPSTREAM,
            TAG_TERMINAL,
            TAG_NO_FILE_TRANSFER,
            TAG_RULE_KIND,
            TAG_RULE_PATH,
            TAG_RULE_COMPANY,
            TAG_RULE_PRODUCT,
            TAG_RULE_ORIGINAL,
            TAG_RULE_EXTRA_PATHS,
            TAG_GRACE,
            TAG_PASSWORD,
            TAG_PRIVATE_KEY,
            TAG_PASSPHRASE,
            TAG_CERTIFICATE,
        ],
    )
    .map_err(|_| IssueError::Malformed)?;
    let refused = IssueError::Refused;
    let method = find(&rs, TAG_METHOD).ok_or(refused)?;
    let username = find(&rs, TAG_USERNAME).ok_or(refused)?;
    let upstream = find(&rs, TAG_UPSTREAM).ok_or(refused)?;
    require_loopback(upstream)?;
    let terminal = match find(&rs, TAG_TERMINAL) {
        Some(v) => Some(i32::from_be_bytes(v.try_into().map_err(|_| refused)?)),
        None => None,
    };
    let no_file_transfer = match find(&rs, TAG_NO_FILE_TRANSFER) {
        Some([1]) => true,
        Some(_) => return Err(refused),
        None => false,
    };
    let rule = rule(&rs)?;
    let grace = match find(&rs, TAG_GRACE) {
        Some(v) => {
            let ms = u32::from_be_bytes(v.try_into().map_err(|_| refused)?);
            let grace = Duration::from_millis(ms.into());
            if grace > MAX_GRACE {
                return Err(refused);
            }
            Some(grace)
        }
        None => None,
    };
    let secret = |tag| find(&rs, tag).map(|v| Zeroizing::new(v.to_vec()));
    let (password, private_key) = (secret(TAG_PASSWORD), secret(TAG_PRIVATE_KEY));
    let certificate = secret(TAG_CERTIFICATE);
    let present = |s: &Option<Zeroizing<Vec<u8>>>| s.as_ref().is_some_and(|v| !v.is_empty());
    let method = match method {
        b"password" if present(&password) => Method::Password,
        b"key" if present(&private_key) => Method::Key,
        b"certificate" if present(&private_key) && present(&certificate) => Method::Certificate,
        _ => return Err(refused),
    };
    Ok(Issue {
        credential: Credential {
            method,
            password,
            private_key,
            passphrase: secret(TAG_PASSPHRASE),
            certificate,
        },
        username: username.to_vec(),
        upstream: upstream.to_vec(),
        terminal,
        no_file_transfer,
        rule,
        grace,
    })
}

/// The caller rule: every field its kind needs, and none it does not use.
fn rule(rs: &[(u8, &[u8])]) -> Result<Option<Rule>, IssueError> {
    let refused = IssueError::Refused;
    let fields = [
        TAG_RULE_PATH,
        TAG_RULE_COMPANY,
        TAG_RULE_PRODUCT,
        TAG_RULE_ORIGINAL,
        TAG_RULE_EXTRA_PATHS,
    ];
    let Some(kind) = find(rs, TAG_RULE_KIND) else {
        if fields.iter().any(|&t| find(rs, t).is_some()) {
            return Err(refused);
        }
        return Ok(None);
    };
    let kind = match kind {
        [k @ 1..=3] => *k,
        _ => return Err(refused),
    };
    let path = match find(rs, TAG_RULE_PATH) {
        Some(p) if !p.is_empty() => p.to_vec(),
        _ => return Err(refused),
    };
    let company = find(rs, TAG_RULE_COMPANY);
    let product = find(rs, TAG_RULE_PRODUCT);
    let original = find(rs, TAG_RULE_ORIGINAL);
    let metadata = match (kind, company, product, original) {
        (3, Some(c), Some(p), Some(o)) if !o.is_empty() => {
            Some((c.to_vec(), p.to_vec(), o.to_vec()))
        }
        (3, ..) => return Err(refused),
        (_, None, None, None) => None,
        _ => return Err(refused),
    };
    let mut extra_paths = Vec::new();
    if let Some(v) = find(rs, TAG_RULE_EXTRA_PATHS) {
        for p in v.split(|&b| b == 0) {
            if p.is_empty() {
                return Err(refused);
            }
            extra_paths.push(p.to_vec());
        }
    }
    Ok(Some(Rule {
        kind,
        path,
        metadata,
        extra_paths,
    }))
}

/// Whether `addr` is `host:port` with a loopback IP literal for its host and a port that is not
/// empty, as acwbroker's `model.RequireLoopback` reads it through Go's `net.SplitHostPort` and
/// `net.ParseIP`.
pub fn require_loopback(addr: &[u8]) -> Result<(), IssueError> {
    let (host, port) = split_host_port(addr).ok_or(IssueError::Refused)?;
    if port.is_empty() {
        return Err(IssueError::Refused);
    }
    let ip = std::str::from_utf8(host)
        .ok()
        .and_then(|h| h.parse::<IpAddr>().ok());
    let loopback = match ip {
        Some(IpAddr::V4(v4)) => v4.is_loopback(),
        Some(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.is_loopback(),
            None => v6 == Ipv6Addr::LOCALHOST,
        },
        None => false,
    };
    if loopback {
        Ok(())
    } else {
        Err(IssueError::NotLoopback)
    }
}

/// Go's `net.SplitHostPort`.
fn split_host_port(hostport: &[u8]) -> Option<(&[u8], &[u8])> {
    let i = hostport.iter().rposition(|&b| b == b':')?;
    let (host, j, k) = if hostport[0] == b'[' {
        let end = hostport.iter().position(|&b| b == b']')?;
        if end + 1 != i {
            return None;
        }
        (&hostport[1..end], 1, end + 1)
    } else {
        let host = &hostport[..i];
        if host.contains(&b':') {
            return None;
        }
        (host, 0, 0)
    };
    if hostport[j..].contains(&b'[') || hostport[k..].contains(&b']') {
        return None;
    }
    Some((host, &hostport[i + 1..]))
}
