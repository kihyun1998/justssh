//! Which local process owns the other end of a loopback connection, and the other facts the
//! tokens ask of this machine (acwbroker `infrastructure/peer`). Measured on Windows; on any
//! other platform nothing is, and every caller then reads as having no owner.

#[cfg(not(windows))]
mod other;
#[cfg(windows)]
mod windows;

#[cfg(not(windows))]
pub use other::*;
#[cfg(windows)]
pub use windows::*;

use std::sync::Arc;

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
