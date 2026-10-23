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

use crate::tokens::{Config, Peer};

/// The tokens' configuration on this machine: acwbroker's defaults, this process's session
/// and account, the version-resource reader, the exit watch, and the parent as the app.
pub fn config() -> Result<Config, String> {
    Ok(Config {
        app: parent().unwrap_or(0),
        peer: Peer {
            own_session: own_session()?,
            own_user: own_user(),
            metadata: Some(Arc::new(metadata)),
            hold: Some(Arc::new(Holder)),
        },
        ..Config::default()
    })
}
