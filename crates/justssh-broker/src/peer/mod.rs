//! Which local process owns the other end of a loopback connection, and the other facts the
//! tokens ask of this machine (acwbroker `infrastructure/peer`). Measured on Windows and macOS;
//! on any other platform nothing is, and every caller then reads as having no owner.

#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(windows))]
mod other;
#[cfg(not(any(windows, target_os = "macos")))]
mod stub;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "macos")]
pub use macos::*;
#[cfg(not(windows))]
pub use other::*;
#[cfg(not(any(windows, target_os = "macos")))]
pub use stub::*;
#[cfg(windows)]
pub use windows::*;

use std::sync::Arc;

#[cfg(not(target_os = "macos"))]
use crate::caller::ProcessKey;
use crate::log::Log;
use crate::tokens::{Config, Peer};

/// The tokens' configuration on this machine: acwbroker's defaults, this process's session
/// and account, the version-resource reader, the exit watch, the processes of this session,
/// and the parent as the app. What cannot be read and leaves a check off is logged to `log`.
pub fn config(log: &Log) -> Result<Config, String> {
    let session = own_session()?;
    let own_user = own_user();
    if cfg!(windows) && own_user.is_none() {
        log.warn(
            "own user unavailable; the user check is off",
            &[("err", "peer: own user could not be read".into())],
        );
    }
    let app = parent().unwrap_or(0);
    if app == 0 {
        log.warn(
            "parent process id unavailable; no caller will be measured as in-tree",
            &[],
        );
    }
    Ok(Config {
        app,
        peer: Peer {
            own_session: session,
            own_user,
            metadata: Some(Arc::new(metadata)),
            hold: Some(Arc::new(Holder)),
            candidates: Some(Arc::new(move || candidates(session))),
        },
        ..Config::default()
    })
}

/// Who holds a terminal: not read here.
#[cfg(not(target_os = "macos"))]
pub fn terminal_holders(_terminal: i32) -> Result<Vec<ProcessKey>, String> {
    Err("peer: terminal binding is not implemented on this platform".to_owned())
}
