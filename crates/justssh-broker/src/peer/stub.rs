use std::net::SocketAddr;

use crate::caller::{Caller, Owner};
use crate::tokens::{Held, Hold};

const UNSUPPORTED: &str = "peer: this is not implemented on this platform";

/// The caller on the other end of `local`: never measured here.
pub fn probe(_local: SocketAddr, _remote: SocketAddr) -> Caller {
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
