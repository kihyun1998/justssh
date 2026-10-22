//! A certificate given as an `authorized_keys` line, read as x/crypto/ssh's `ParseAuthorizedKey`
//! reads one: `[options] type base64 [comment]`.

use justssh_wire::Reader;

use crate::KeyFileError;

const CERTIFICATE_SUFFIX: &[u8] = b"-cert-v01@openssh.com";

pub(crate) fn certificate(text: &[u8]) -> Result<Vec<u8>, KeyFileError> {
    let mut last = KeyFileError::NotThisFormat;
    for line in text.split(|&b| b == b'\n') {
        let line = line.split(|&b| b == b'\r').next().unwrap_or_default();
        let line = trim_space(line);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        let Some(i) = blank(line) else {
            continue;
        };
        match key(&line[..i], &line[i..]) {
            Ok(blob) => return Ok(blob),
            Err(e @ KeyFileError::UnsupportedKeyType(_)) => return Err(e),
            Err(e) => last = e,
        }
        let Some(rest) = after_options(line) else {
            continue;
        };
        let Some(i) = blank(rest) else {
            continue;
        };
        match key(&rest[..i], &rest[i..]) {
            Ok(blob) => return Ok(blob),
            Err(e @ KeyFileError::UnsupportedKeyType(_)) => return Err(e),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Where the first space or tab of `field` is.
fn blank(field: &[u8]) -> Option<usize> {
    field.iter().position(|&b| b == b' ' || b == b'\t')
}

/// The certificate in `rest`, a base64 key and a comment, whose type must be `declared`.
fn key(declared: &[u8], rest: &[u8]) -> Result<Vec<u8>, KeyFileError> {
    let rest = trim_space(rest);
    let encoded = &rest[..blank(rest).unwrap_or(rest.len())];
    let blob = crate::base64::decode(encoded)
        .ok_or(KeyFileError::Malformed)?
        .to_vec();
    let key_type = Reader::new(&blob)
        .string()
        .map_err(|_| KeyFileError::Malformed)?;
    if key_type != declared {
        return Err(KeyFileError::Malformed);
    }
    if !key_type.ends_with(CERTIFICATE_SUFFIX) {
        return Err(KeyFileError::UnsupportedKeyType(
            String::from_utf8_lossy(key_type).into_owned(),
        ));
    }
    Ok(blob)
}

/// `line` after its options field, which runs to the first space or tab outside double quotes,
/// and the blanks after it; `None` if a quote is left open.
fn after_options(line: &[u8]) -> Option<&[u8]> {
    let mut quoted = false;
    let mut end = line.len();
    for (i, &b) in line.iter().enumerate() {
        if !quoted && (b == b' ' || b == b'\t') {
            end = i;
            break;
        }
        if b == b'"' && (i == 0 || line[i - 1] != b'\\') {
            quoted = !quoted;
        }
    }
    let rest = &line[end..];
    let rest = &rest[rest.iter().position(|&b| b != b' ' && b != b'\t')?..];
    Some(rest)
}

/// `bytes` without the white space at either end that Go's `bytes.TrimSpace` takes off: ASCII
/// white space and, in UTF-8, any character Unicode counts as white space.
fn trim_space(mut bytes: &[u8]) -> &[u8] {
    while let Some(len) = space_at(bytes, true) {
        bytes = &bytes[len..];
    }
    while let Some(len) = space_at(bytes, false) {
        bytes = &bytes[..bytes.len() - len];
    }
    bytes
}

/// The length of the white space character that starts (`front`) or ends `bytes`, if one does.
fn space_at(bytes: &[u8], front: bool) -> Option<usize> {
    (1..=4.min(bytes.len())).find(|&len| {
        let part = if front {
            &bytes[..len]
        } else {
            &bytes[bytes.len() - len..]
        };
        core::str::from_utf8(part)
            .is_ok_and(|s| s.chars().count() == 1 && s.chars().all(char::is_whitespace))
    })
}
