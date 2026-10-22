//! Certificates given as `authorized_keys` lines.

#[path = "../../justssh/tests/common/certs.rs"]
mod certs;
#[path = "common/lines.rs"]
mod lines;

use base64ct::{Base64, Encoding};
use justssh_keys::{KeyFileError, certificate_from_line};
use proptest::prelude::*;

const CERT_TYPE: &str = "ssh-ed25519-cert-v01@openssh.com";

fn blob() -> Vec<u8> {
    certs::Cert::valid().encode()
}

#[test]
fn each_line_gives_the_certificate_or_an_error() {
    let plain = certs::certified_key().plain_public_blob();
    for (name, line, valid) in lines::lines(&blob(), &plain) {
        let result = certificate_from_line(line.as_bytes());
        if valid {
            assert_eq!(result, Ok(blob()), "{name}");
        } else {
            assert!(result.is_err(), "{name}: {result:?}");
        }
    }
}

#[test]
fn a_plain_key_is_refused_by_its_type() {
    let plain = Base64::encode_string(&certs::certified_key().plain_public_blob());
    assert_eq!(
        certificate_from_line(format!("ssh-ed25519 {plain}").as_bytes()),
        Err(KeyFileError::UnsupportedKeyType("ssh-ed25519".into()))
    );
}

#[test]
fn the_certificate_read_from_a_line_is_one_the_key_can_be_used_under() {
    let line = format!("{CERT_TYPE} {} c\n", Base64::encode_string(&blob()));
    let cert = certificate_from_line(line.as_bytes()).unwrap();
    assert!(certs::certified_key().with_certificate(cert).is_ok());
}

proptest! {
    #[test]
    fn any_text_is_a_certificate_or_an_error_never_a_panic(text in ".{0,200}") {
        let _ = certificate_from_line(text.as_bytes());
    }

    #[test]
    fn any_bytes_are_a_certificate_or_an_error_never_a_panic(
        text in prop::collection::vec(any::<u8>(), 0..300)
    ) {
        let _ = certificate_from_line(&text);
    }
}
