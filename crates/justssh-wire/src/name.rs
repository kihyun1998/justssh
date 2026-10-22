//! The name of a global request, a channel request or a channel type, as bytes.

use core::fmt;

/// A request name or channel type exactly as sent, which need not be UTF-8. It compares equal
/// to a `str` holding the same bytes, and shows as [`escape_ascii`](slice::escape_ascii) does.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(Vec<u8>);

impl Name {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// The name as text, if it is UTF-8.
    pub fn to_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.0).ok()
    }
}

impl From<Vec<u8>> for Name {
    fn from(bytes: Vec<u8>) -> Self {
        Name(bytes)
    }
}

impl From<&[u8]> for Name {
    fn from(bytes: &[u8]) -> Self {
        Name(bytes.to_vec())
    }
}

impl From<String> for Name {
    fn from(s: String) -> Self {
        Name(s.into_bytes())
    }
}

impl From<&str> for Name {
    fn from(s: &str) -> Self {
        Name(s.as_bytes().to_vec())
    }
}

impl AsRef<[u8]> for Name {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl PartialEq<str> for Name {
    fn eq(&self, other: &str) -> bool {
        self.0 == other.as_bytes()
    }
}

impl PartialEq<&str> for Name {
    fn eq(&self, other: &&str) -> bool {
        self.0 == other.as_bytes()
    }
}

impl PartialEq<[u8]> for Name {
    fn eq(&self, other: &[u8]) -> bool {
        self.0 == other
    }
}

impl PartialEq<Name> for str {
    fn eq(&self, other: &Name) -> bool {
        self.as_bytes() == other.0
    }
}

impl PartialEq<Name> for &str {
    fn eq(&self, other: &Name) -> bool {
        self.as_bytes() == other.0
    }
}

impl<const N: usize> PartialEq<[u8; N]> for Name {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.0 == other
    }
}

impl<const N: usize> PartialEq<&[u8; N]> for Name {
    fn eq(&self, other: &&[u8; N]) -> bool {
        self.0 == *other
    }
}

impl PartialEq<String> for Name {
    fn eq(&self, other: &String) -> bool {
        self.0 == other.as_bytes()
    }
}

impl PartialEq<Name> for String {
    fn eq(&self, other: &Name) -> bool {
        self.as_bytes() == other.0
    }
}

impl core::borrow::Borrow<[u8]> for Name {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.0.escape_ascii().to_string())
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", self.0.escape_ascii())
    }
}
