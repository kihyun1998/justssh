use crate::caller::ProcessImage;
use crate::rule::ImageMetadata;

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
    Err("peer: candidates are not read on this platform".to_owned())
}

/// No version resource: never read here.
pub fn metadata(_path: &str) -> Result<ImageMetadata, String> {
    Err("peer: no version resources on this platform".to_owned())
}
