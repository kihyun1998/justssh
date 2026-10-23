use std::net::SocketAddr;

use crate::caller::{Caller, Owner, ProcessImage};
use crate::rule::ImageMetadata;
use crate::tokens::{Held, Hold};

const UNSUPPORTED: &str = "peer: this is not implemented on this platform";

/// The caller on the other end of `addr`: never measured here.
pub fn probe(_addr: SocketAddr) -> Caller {
    Caller::measure(Owner::unmeasured(UNSUPPORTED), None, false)
}

/// No logon session: no caller's session is compared.
pub fn own_session() -> Result<Option<u32>, String> {
    Ok(None)
}

/// No account: no caller's account is compared.
pub fn own_user() -> Option<String> {
    None
}

/// This process's parent.
pub fn parent() -> Option<u32> {
    Some(std::os::unix::process::parent_id()).filter(|&p| p > 0)
}

/// UTC: no offset is read here.
pub fn utc_offset_minutes() -> i32 {
    0
}

/// The processes of a session: never listed here.
pub fn candidates(_session: Option<u32>) -> Result<Vec<ProcessImage>, String> {
    Err(UNSUPPORTED.to_owned())
}

pub fn metadata(_path: &str) -> Result<ImageMetadata, String> {
    Err(UNSUPPORTED.to_owned())
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
