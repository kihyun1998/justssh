use std::net::SocketAddr;

use crate::caller::{Caller, Owner, ProcessKey};
use crate::tokens::{Held, Hold};

const UNSUPPORTED: &str = "peer: this is not implemented on this platform";

/// The caller on the other end of `addr`: never measured here.
pub fn probe(_addr: SocketAddr) -> Caller {
    Caller::measure(Owner::unmeasured(UNSUPPORTED), None, false)
}

/// Watches nothing.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct Holder;

impl Hold for Holder {
    fn hold(&self, _pid: u32) -> Result<Held, String> {
        Err(UNSUPPORTED.to_owned())
    }
}

/// Who holds a terminal: never read here, since only the macOS Terminal binds a token to one.
pub fn terminal_holders(_terminal: i32) -> Result<Vec<ProcessKey>, String> {
    Err("peer: terminal binding is not implemented on this platform".to_owned())
}
