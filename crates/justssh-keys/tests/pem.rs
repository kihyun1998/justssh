//! PEM private keys: PKCS#1, PKCS#8, SEC1 and legacy encrypted PEM. The fixtures in `tests/pem/`
//! were made by `ssh-keygen` and `openssl` (`tests/pem/README.md`); each `.pub` beside them is
//! `ssh-keygen -y`'s public key line.

use base64ct::{Base64, Encoding};
use justssh_keys::{KeyFile, KeyFileError};
use proptest::prelude::*;

const PASSPHRASE: &[u8] = b"correct horse";

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/pem/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn public_blob(name: &str) -> Vec<u8> {
    let line = String::from_utf8(fixture(&format!("{name}.pub"))).unwrap();
    Base64::decode_vec(line.split_whitespace().nth(1).unwrap()).unwrap()
}

/// The fixtures that hold a key x/crypto/ssh signs with, with whether each is encrypted.
const READABLE: [(&str, bool); 13] = [
    ("rsa-pkcs1", false),
    ("rsa-pkcs1-aes128", true),
    ("rsa-pkcs1-des", true),
    ("rsa-pkcs1-des3", true),
    ("rsa-pkcs8", false),
    ("ec256-sec1", false),
    ("ec256-sec1-aes192", true),
    ("ec256-sec1-aes256", true),
    ("ec384-sec1-aes128", true),
    ("ec521-sec1", false),
    ("ec256-pkcs8", false),
    ("ed25519-pkcs8", false),
    ("rsa-pkcs1-3primes", false),
];

#[test]
fn each_pem_key_reads_as_ssh_keygen_reads_it() {
    for (name, encrypted) in READABLE {
        if name == "rsa-pkcs1-3primes" {
            continue;
        }
        let key = KeyFile::from_pem(&fixture(name), encrypted.then_some(PASSPHRASE))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            key.private_key().plain_public_blob(),
            public_blob(name),
            "{name}"
        );
    }
}

#[test]
fn a_multi_prime_rsa_key_is_refused_by_name() {
    assert_eq!(
        KeyFile::from_pem(&fixture("rsa-pkcs1-3primes"), None).err(),
        Some(KeyFileError::UnsupportedKeyType("multi-prime RSA".into()))
    );
}

#[test]
fn keys_ssh_cannot_sign_with_are_refused_by_type() {
    for (name, kind) in [
        ("dsa", "ssh-dss"),
        ("dsa-pkcs8", "ssh-dss"),
        ("x25519-pkcs8", "X25519"),
    ] {
        assert_eq!(
            KeyFile::from_pem(&fixture(name), None).err(),
            Some(KeyFileError::UnsupportedKeyType(kind.into())),
            "{name}"
        );
    }
}

#[test]
fn an_encrypted_pkcs8_key_is_refused_as_x_crypto_ssh_refuses_it() {
    for passphrase in [None, Some(PASSPHRASE)] {
        assert_eq!(
            KeyFile::from_pem(&fixture("rsa-pkcs8-encrypted"), passphrase).err(),
            Some(KeyFileError::UnsupportedEncryption("PKCS#8".into()))
        );
    }
}

#[test]
fn passphrases_are_asked_for_only_where_they_are_needed() {
    for (name, encrypted) in READABLE {
        if encrypted {
            assert_eq!(
                KeyFile::from_pem(&fixture(name), None).err(),
                Some(KeyFileError::PassphraseNeeded),
                "{name}"
            );
            assert_eq!(
                KeyFile::from_pem(&fixture(name), Some(b"wrong")).err(),
                Some(KeyFileError::WrongPassphrase),
                "{name}"
            );
        }
    }
    assert_eq!(
        KeyFile::from_pem(&fixture("rsa-pkcs1"), Some(PASSPHRASE)).err(),
        Some(KeyFileError::NotEncrypted)
    );
    // A cipher named without Proc-Type, and Proc-Type without a cipher, as
    // `x509.IsEncryptedPEMBlock` reads them.
    let text = String::from_utf8(fixture("rsa-pkcs1-aes128")).unwrap();
    for header in ["Proc-Type", "DEK-Info"] {
        let without: String = text
            .lines()
            .filter(|l| !l.starts_with(header))
            .map(|l| format!("{l}\n"))
            .collect();
        assert_eq!(
            KeyFile::from_pem(without.as_bytes(), Some(PASSPHRASE)).err(),
            Some(KeyFileError::NotEncrypted),
            "{header}"
        );
    }
}

#[test]
fn only_the_first_block_is_read_and_its_end_must_match() {
    let mut two = b"text before\n".to_vec();
    two.extend(fixture("rsa-pkcs1"));
    two.extend(fixture("ec256-sec1"));
    let key = KeyFile::from_pem(&two, None).unwrap();
    assert_eq!(
        key.private_key().plain_public_blob(),
        public_blob("rsa-pkcs1")
    );

    let text = String::from_utf8(fixture("ec256-sec1")).unwrap();
    let mismatched = text.replace(
        "-----END EC PRIVATE KEY-----",
        "-----END RSA PRIVATE KEY-----",
    );
    assert_eq!(
        KeyFile::from_pem(mismatched.as_bytes(), None).err(),
        Some(KeyFileError::NotThisFormat)
    );
    let trailed = text.replace(
        "-----END EC PRIVATE KEY-----",
        "-----END EC PRIVATE KEY-----x",
    );
    assert_eq!(
        KeyFile::from_pem(trailed.as_bytes(), None).err(),
        Some(KeyFileError::NotThisFormat)
    );
    let indented = format!(" {text}");
    assert_eq!(
        KeyFile::from_pem(indented.as_bytes(), None).err(),
        Some(KeyFileError::NotThisFormat)
    );
    let crlf = text.replace('\n', "\r\n");
    assert!(KeyFile::from_pem(crlf.as_bytes(), None).is_ok());
}

#[test]
fn an_unknown_dek_cipher_is_refused_by_name() {
    let text = String::from_utf8(fixture("rsa-pkcs1-aes128")).unwrap();
    let text = text.replacen("DEK-Info: AES-128-CBC,", "DEK-Info: CAMELLIA-128-CBC,", 1);
    assert_eq!(
        KeyFile::from_pem(text.as_bytes(), Some(PASSPHRASE)).err(),
        Some(KeyFileError::UnsupportedEncryption(
            "CAMELLIA-128-CBC".into()
        ))
    );
}

#[test]
fn read_tells_the_formats_apart_as_acwbroker_does() {
    let dir = env!("CARGO_MANIFEST_DIR");
    let ppk = std::fs::read(format!("{dir}/tests/ppk/ed25519.ppk")).unwrap();
    let openssh = std::fs::read(format!("{dir}/tests/keys/ed25519")).unwrap();
    for (text, expected) in [
        (ppk.clone(), KeyFile::from_ppk(&ppk, None).unwrap()),
        (
            openssh.clone(),
            KeyFile::from_openssh(&openssh, None).unwrap(),
        ),
        (
            fixture("rsa-pkcs1"),
            KeyFile::from_pem(&fixture("rsa-pkcs1"), None).unwrap(),
        ),
    ] {
        let key = KeyFile::read(&text, None).unwrap();
        assert_eq!(
            key.private_key().plain_public_blob(),
            expected.private_key().plain_public_blob()
        );
    }
    let mut padded = b"\r\n  ".to_vec();
    padded.extend(&ppk);
    assert!(KeyFile::read(&padded, None).is_ok());
    assert_eq!(
        KeyFile::read(b"nothing", None).err(),
        Some(KeyFileError::NotThisFormat)
    );
}

#[test]
fn every_cut_of_a_pem_key_is_an_error_not_a_panic() {
    for name in ["rsa-pkcs1", "ec384-sec1-aes128", "ed25519-pkcs8"] {
        let text = fixture(name);
        for end in 0..text.len() {
            let _ = KeyFile::from_pem(&text[..end], Some(PASSPHRASE));
            let _ = KeyFile::from_pem(&text[..end], None);
        }
    }
}

proptest! {
    #[test]
    fn any_bytes_are_a_key_or_an_error_never_a_panic(text in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = KeyFile::from_pem(&text, None);
        let _ = KeyFile::read(&text, Some(PASSPHRASE));
    }

    #[test]
    fn a_der_body_with_one_byte_changed_is_a_key_or_an_error_never_a_panic(
        name in prop::sample::select(vec!["rsa-pkcs1", "ec256-sec1", "rsa-pkcs8", "ed25519-pkcs8"]),
        index in any::<prop::sample::Index>(),
        value in any::<u8>(),
    ) {
        let text = String::from_utf8(fixture(name)).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        let body: String = lines[1..lines.len() - 1].concat();
        let mut der = Base64::decode_vec(&body).unwrap();
        let at = index.index(der.len());
        der[at] = value;
        let encoded = Base64::encode_string(&der);
        let (first, last) = (lines[0], lines[lines.len() - 1]);
        lines.clear();
        let changed = format!("{first}\n{encoded}\n{last}\n");
        let _ = KeyFile::from_pem(changed.as_bytes(), None);
    }
}

/// A legacy encrypted `RSA PRIVATE KEY` block holding `plain`, padded as RFC 1423 pads it and
/// encrypted with AES-128-CBC under `passphrase` as OpenSSL encrypts it.
fn encrypted_block(plain: &[u8], passphrase: &[u8]) -> Vec<u8> {
    use cbc::cipher::block_padding::Pkcs7;
    use cbc::cipher::{BlockModeEncrypt, KeyIvInit};
    use md5::Digest;
    let iv = [7u8; 16];
    let key = md5::Md5::new()
        .chain_update(passphrase)
        .chain_update(&iv[..8])
        .finalize();
    let mut buf = plain.to_vec();
    buf.resize(plain.len() + 16, 0);
    let len = plain.len();
    let ct = cbc::Encryptor::<aes::Aes128>::new_from_slices(&key, &iv)
        .unwrap()
        .encrypt_padded::<Pkcs7>(&mut buf, len)
        .unwrap()
        .to_vec();
    let hex: String = iv.iter().map(|b| format!("{b:02X}")).collect();
    format!(
        "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,{hex}\n\n{}\n-----END RSA PRIVATE KEY-----\n",
        Base64::encode_string(&ct)
    )
    .into_bytes()
}

#[test]
fn a_block_whose_padding_holds_but_whose_key_does_not_parse_reads_as_a_wrong_passphrase() {
    let text = encrypted_block(b"this is not DER", b"some passphrase");
    assert_eq!(
        KeyFile::from_pem(&text, Some(b"some passphrase")).err(),
        Some(KeyFileError::WrongPassphrase)
    );
}

#[test]
fn a_block_with_no_body_is_an_error_not_a_panic() {
    for text in [
        &b"-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----\n"[..],
        b"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n-----END RSA PRIVATE KEY-----\n",
        b"-----BEGIN A-----\n\n-----END A-----\n",
    ] {
        assert!(KeyFile::from_pem(text, None).is_err());
        assert!(KeyFile::read(text, Some(PASSPHRASE)).is_err());
    }
}

#[test]
fn many_headers_without_an_end_are_searched_in_linear_time() {
    let text = "-----BEGIN A:-----\n-----END A:-----\n".repeat(20_000);
    let started = std::time::Instant::now();
    assert!(KeyFile::from_pem(text.as_bytes(), None).is_err());
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
}

/// DER: `tag`, its length and `content`.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match content.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n < 0x100 => out.extend([0x81, n as u8]),
        n => out.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend(content);
    out
}

const OID_EC: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];

fn pem(label: &str, der: &[u8]) -> Vec<u8> {
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        Base64::encode_string(der)
    )
    .into_bytes()
}

#[test]
fn a_pkcs8_ec_key_takes_its_curve_from_the_algorithm_as_go_does() {
    let scalar = [0x11u8; 32];
    let sec1 = der(
        0x30,
        &[
            &[0x02, 0x01, 0x01][..],
            &der(0x04, &scalar),
            &der(0xa0, OID_P384),
        ]
        .concat(),
    );
    let pkcs8 = der(
        0x30,
        &[
            &[0x02, 0x01, 0x00][..],
            &der(0x30, &[OID_EC, OID_P256].concat()),
            &der(0x04, &sec1),
        ]
        .concat(),
    );
    let key = KeyFile::from_pem(&pem("PRIVATE KEY", &pkcs8), None).unwrap();
    let p256 = KeyFile::ecdsa(
        justssh::EcdsaCurve::P256,
        justssh::Zeroizing::new(scalar.to_vec()),
    )
    .unwrap();
    assert_eq!(
        key.private_key().plain_public_blob(),
        p256.private_key().plain_public_blob()
    );
}

const OID_ED25519: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

#[test]
fn a_pkcs8_ed25519_key_has_no_parameters_and_may_trail_bytes_as_go_reads_it() {
    let seed = [0x22u8; 32];
    let pkcs8 = |algorithm: &[u8], private: &[u8]| {
        let body = [
            &[0x02, 0x01, 0x00][..],
            &der(0x30, algorithm),
            &der(0x04, private),
        ]
        .concat();
        pem("PRIVATE KEY", &der(0x30, &body))
    };
    let expected = KeyFile::ed25519(justssh::Zeroizing::new(seed))
        .private_key()
        .plain_public_blob();
    let inner = der(0x04, &seed);
    let trailing = [&inner[..], &[0x00, 0x01]].concat();
    for private in [&inner[..], &trailing] {
        let key = KeyFile::from_pem(&pkcs8(OID_ED25519, private), None).unwrap();
        assert_eq!(key.private_key().plain_public_blob(), expected);
    }
    let with_null = [OID_ED25519, &[0x05, 0x00]].concat();
    assert_eq!(
        KeyFile::from_pem(&pkcs8(&with_null, &inner), None).err(),
        Some(KeyFileError::Malformed)
    );
}

#[test]
fn an_rsa_key_whose_crt_values_do_not_follow_from_its_primes_is_refused() {
    let text = String::from_utf8(fixture("rsa-pkcs1")).unwrap();
    let body: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
    let mut der = Base64::decode_vec(&body).unwrap();
    // The coefficient is the last INTEGER, so the last byte is its lowest.
    *der.last_mut().unwrap() ^= 1;
    assert_eq!(
        KeyFile::from_pem(&pem("RSA PRIVATE KEY", &der), None).err(),
        Some(KeyFileError::InvalidKey)
    );
}

#[test]
fn read_and_from_openssh_take_the_same_block_of_a_file_with_a_cut_one_before_it() {
    let whole = std::fs::read(format!(
        "{}/tests/keys/ecdsa256",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let text = String::from_utf8(whole.clone()).unwrap();
    let cut: String = text.lines().take(3).map(|l| format!("{l}\n")).collect();
    let mixed = [cut.as_bytes(), &whole].concat();
    let expected = KeyFile::from_openssh(&whole, None)
        .unwrap()
        .private_key()
        .plain_public_blob();
    for key in [
        KeyFile::read(&mixed, None),
        KeyFile::from_openssh(&mixed, None),
    ] {
        assert_eq!(key.unwrap().private_key().plain_public_blob(), expected);
    }
}
