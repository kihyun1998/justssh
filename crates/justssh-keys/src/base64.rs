//! Base64 as Go's `encoding/base64` reads it.

use justssh::Zeroizing;

/// Standard padded base64 decoded as Go's `base64.StdEncoding` decodes it, which takes the
/// unused bits of the last character whatever they are, into a buffer that zeroizes on drop.
pub(crate) fn decode(text: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if !text.len().is_multiple_of(4) {
        return None;
    }
    let value = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let mut out = Zeroizing::new(Vec::with_capacity(text.len() / 4 * 3));
    let quads = text.len() / 4;
    for (i, quad) in text.chunks(4).enumerate() {
        let pad = quad.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && i + 1 != quads) {
            return None;
        }
        let mut bits = Zeroizing::new(0u32);
        for &c in &quad[..4 - pad] {
            *bits = *bits << 6 | u32::from(value(c)?);
        }
        *bits <<= 6 * pad;
        let bytes = Zeroizing::new(bits.to_be_bytes());
        out.extend(&bytes[1..4 - pad]);
    }
    Some(out)
}
