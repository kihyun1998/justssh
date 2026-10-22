//! A certificate is read whole before a key is used under it, as x/crypto/ssh's `parseCert` reads
//! it.

mod common;

use common::certs::{certified_key, variants};
use justssh::KeyError;

#[test]
fn a_certificate_is_taken_or_refused_by_the_rules_x_crypto_ssh_parses_it_with() {
    for (name, blob, valid) in variants() {
        let result = certified_key().with_certificate(blob);
        if valid {
            assert!(result.is_ok(), "{name}: {:?}", result.err());
        } else {
            assert_eq!(result.err(), Some(KeyError::MalformedCertificate), "{name}");
        }
    }
}

proptest::proptest! {
    #[test]
    fn any_bytes_are_a_certificate_or_an_error_never_a_panic(
        bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512)
    ) {
        let _ = certified_key().with_certificate(bytes);
    }

    #[test]
    fn a_certificate_cut_and_followed_by_any_bytes_is_an_error_or_taken_never_a_panic(
        cut in proptest::prelude::any::<proptest::sample::Index>(),
        tail in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64),
    ) {
        let mut blob = common::certs::Cert::valid().encode();
        blob.truncate(cut.index(blob.len()));
        blob.extend(tail);
        let _ = certified_key().with_certificate(blob);
    }
}
