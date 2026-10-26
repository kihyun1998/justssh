use crate::caller::ProcessImage;
use crate::rule::ImageMetadata;

const UNSUPPORTED: &str = "peer: this is not implemented on this platform";

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
