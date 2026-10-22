//! `authorized_keys` lines for the certificate line tests, in `justssh-keys` and against Go.
#![allow(dead_code)]

use base64ct::{Base64, Encoding};

const CERT_TYPE: &str = "ssh-ed25519-cert-v01@openssh.com";

/// Lines holding the certificate `cert` in each shape x/crypto/ssh's `ParseAuthorizedKey` reads,
/// and lines it refuses, one with the plain key `plain`; with whether a certificate is read.
pub fn lines(cert: &[u8], plain: &[u8]) -> Vec<(&'static str, String, bool)> {
    let b64 = Base64::encode_string(cert);
    let plain = Base64::encode_string(plain);
    // The same base64 with an unused bit of its last character set, which Go decodes alike.
    let padding = b64.len() - b64.trim_end_matches('=').len();
    assert!(
        padding > 0,
        "the certificate's base64 needs padding for this case"
    );
    let mut loose = b64.clone().into_bytes();
    let last = b64.len() - padding - 1;
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let value = alphabet.iter().position(|&c| c == loose[last]).unwrap();
    loose[last] = alphabet[value ^ 1];
    let loose = String::from_utf8(loose).unwrap();
    vec![
        (
            "unused base64 bits set",
            format!("{CERT_TYPE} {loose} c"),
            true,
        ),
        (
            "a vertical tab before and a no-break space after",
            format!("\u{b}{CERT_TYPE} {b64} c\u{a0}"),
            true,
        ),
        (
            "a quote escaped inside the options",
            format!("command=\"echo \\\"a b\\\"\" {CERT_TYPE} {b64} c"),
            true,
        ),
        (
            "type, key and comment",
            format!("{CERT_TYPE} {b64} justssh@host\n"),
            true,
        ),
        ("no comment", format!("{CERT_TYPE} {b64}"), true),
        (
            "after comments and blank lines",
            format!("# made by ssh-keygen\n\n   \n{CERT_TYPE} {b64} c\n"),
            true,
        ),
        ("CR LF", format!("{CERT_TYPE} {b64} c\r\n"), true),
        ("tabs", format!("\t{CERT_TYPE}\t{b64}\tc"), true),
        (
            "options",
            format!("cert-authority,from=\"10.0.0.1, 10.0.0.2\" {CERT_TYPE} {b64} c"),
            true,
        ),
        (
            "a declared type that is not the certificate's",
            format!("ssh-ed25519 {b64} c"),
            false,
        ),
        ("a plain key", format!("ssh-ed25519 {plain} c"), false),
        (
            "a quote left open",
            format!("from=\"10.0.0.1 {CERT_TYPE} {b64}"),
            false,
        ),
        (
            "base64 that does not decode",
            format!("{CERT_TYPE} !!!! c"),
            false,
        ),
        ("nothing", String::new(), false),
        ("only comments", "# nothing here\n".to_owned(), false),
        (
            "a certificate line commented out",
            format!("# {CERT_TYPE} {b64} c\n"),
            false,
        ),
    ]
}
