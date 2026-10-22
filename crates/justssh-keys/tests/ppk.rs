//! PuTTY private key files. The fixtures in `tests/ppk/` were made by WinSCP and PuTTYgen from
//! keys `ssh-keygen` made (`tests/ppk/README.md`); each WinSCP file has its source key beside it.

use justssh_keys::{KeyFile, KeyFileError};
use proptest::prelude::*;

const WINSCP_PASS: &[u8] = b"correct horse";
const PUTTYGEN_PASS: &[u8] = b"test1234";

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/ppk/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// The WinSCP files, with whether each is encrypted.
const WINSCP: [(&str, bool); 8] = [
    ("ed25519", false),
    ("ed25519-enc", true),
    ("ecdsa256", false),
    ("ecdsa384", false),
    ("ecdsa384-enc", true),
    ("ecdsa521", false),
    ("rsa", false),
    ("rsa-enc", true),
];

fn ppk(name: &str, passphrase: Option<&[u8]>) -> Result<KeyFile, KeyFileError> {
    KeyFile::from_ppk(&fixture(&format!("{name}.ppk")), passphrase)
}

#[test]
fn each_ppk_holds_the_key_it_was_made_from() {
    for (name, encrypted) in WINSCP {
        let pass = encrypted.then_some(WINSCP_PASS);
        let key = ppk(name, pass).unwrap_or_else(|e| panic!("{name}: {e}"));
        let source = KeyFile::from_openssh(&fixture(&format!("{name}.openssh")), pass).unwrap();
        assert_eq!(
            key.private_key().plain_public_blob(),
            source.private_key().plain_public_blob(),
            "{name}"
        );
        assert_eq!(
            key.comment(),
            format!("acwbroker-test-{name}").as_bytes(),
            "{name}"
        );
    }
}

#[test]
fn a_puttygen_v2_file_holds_the_key_its_v3_file_holds() {
    let v2 = KeyFile::from_ppk(&fixture("puttygen_rsa_enc_v2.ppk"), Some(PUTTYGEN_PASS)).unwrap();
    let v3 = KeyFile::from_ppk(&fixture("puttygen_rsa_enc_v3.ppk"), Some(PUTTYGEN_PASS)).unwrap();
    assert_eq!(
        v2.private_key().plain_public_blob(),
        v3.private_key().plain_public_blob()
    );
    assert_eq!(v2.comment(), b"rsa-key-20260623");
}

#[test]
fn passphrases_are_asked_for_where_they_are_needed_and_ignored_elsewhere() {
    assert_eq!(
        ppk("ed25519-enc", None).err(),
        Some(KeyFileError::PassphraseNeeded)
    );
    assert_eq!(
        ppk("ed25519-enc", Some(b"")).err(),
        Some(KeyFileError::PassphraseNeeded)
    );
    assert_eq!(
        ppk("ed25519-enc", Some(b"wrong")).err(),
        Some(KeyFileError::WrongPassphrase)
    );
    assert_eq!(
        KeyFile::from_ppk(&fixture("puttygen_rsa_enc_v2.ppk"), Some(b"wrong")).err(),
        Some(KeyFileError::WrongPassphrase)
    );
    assert!(ppk("ed25519", Some(b"anything")).is_ok());
}

/// The `name` fixture with `from` replaced by `to` in its text.
fn edited(name: &str, from: &str, to: &str) -> Vec<u8> {
    let text = String::from_utf8(fixture(name)).unwrap();
    assert!(text.contains(from), "{name} has no {from:?}");
    text.replacen(from, to, 1).into_bytes()
}

#[test]
fn a_file_whose_mac_does_not_match_is_refused() {
    let text = edited(
        "ed25519.ppk",
        "Comment: acwbroker-test-ed25519",
        "Comment: acwbroker-test-ed25519!",
    );
    assert_eq!(
        KeyFile::from_ppk(&text, None).err(),
        Some(KeyFileError::Malformed)
    );
}

#[test]
fn every_line_ending_putty_reads_is_read() {
    let lf = fixture_text("ed25519.ppk");
    assert!(lf.contains('\n') && !lf.contains('\r'));
    let crlf = lf.replace('\n', "\r\n");
    let cr = lf.replace('\n', "\r");
    for text in [lf.clone(), crlf, cr, format!("\n \t{lf}")] {
        assert!(KeyFile::from_ppk(text.as_bytes(), None).is_ok());
    }
}

fn fixture_text(name: &str) -> String {
    String::from_utf8(fixture(name)).unwrap()
}

#[test]
fn an_argon2d_file_is_refused_by_name() {
    let text = edited(
        "ed25519-enc.ppk",
        "Key-Derivation: Argon2id",
        "Key-Derivation: Argon2d",
    );
    assert_eq!(
        KeyFile::from_ppk(&text, Some(WINSCP_PASS)).err(),
        Some(KeyFileError::UnsupportedEncryption("Argon2d".into()))
    );
}

#[test]
fn the_argon2_flavour_is_taken_from_the_file() {
    let text = edited(
        "ed25519-enc.ppk",
        "Key-Derivation: Argon2id",
        "Key-Derivation: Argon2i",
    );
    assert_eq!(
        KeyFile::from_ppk(&text, Some(WINSCP_PASS)).err(),
        Some(KeyFileError::WrongPassphrase)
    );
}

#[test]
fn argon2_settings_beyond_the_budget_are_refused_before_deriving() {
    for (from, to) in [
        ("Argon2-Memory: 8192", "Argon2-Memory: 1048577"),
        ("Argon2-Passes: 13", "Argon2-Passes: 513"),
    ] {
        let text = edited("ed25519-enc.ppk", from, to);
        let started = std::time::Instant::now();
        assert_eq!(
            KeyFile::from_ppk(&text, Some(WINSCP_PASS)).err(),
            Some(KeyFileError::KdfTooCostly),
            "{to}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "{to}"
        );
    }
    for (from, to) in [
        ("Argon2-Passes: 13", "Argon2-Passes: 0"),
        ("Argon2-Parallelism: 1", "Argon2-Parallelism: 256"),
    ] {
        let text = edited("ed25519-enc.ppk", from, to);
        assert_eq!(
            KeyFile::from_ppk(&text, Some(WINSCP_PASS)).err(),
            Some(KeyFileError::Malformed),
            "{to}"
        );
    }
}

#[test]
fn versions_ciphers_and_key_types_outside_the_format_are_refused_by_name() {
    let cases = [
        (
            "PuTTY-User-Key-File-3:",
            "PuTTY-User-Key-File-1:",
            KeyFileError::UnsupportedVersion(1),
        ),
        (
            "Encryption: none",
            "Encryption: aes128-cbc",
            KeyFileError::UnsupportedEncryption("aes128-cbc".into()),
        ),
        (
            "ssh-ed25519\nEncryption",
            "ssh-dss\nEncryption",
            KeyFileError::UnsupportedKeyType("ssh-dss".into()),
        ),
    ];
    for (from, to, error) in cases {
        let text = edited("ed25519.ppk", from, to);
        assert_eq!(KeyFile::from_ppk(&text, None).err(), Some(error), "{to}");
    }
}

#[test]
fn a_refusal_never_quotes_the_file() {
    // A file whose line breaks were lost carries its private lines inside the algorithm name.
    let text = fixture_text("ed25519.ppk").replace('\n', " ");
    let error = KeyFile::from_ppk(text.as_bytes(), None).unwrap_err();
    let shown = format!("{error} {error:?}");
    assert!(!shown.contains("AAAA"), "{shown}");
}

#[test]
fn headers_out_of_place_are_malformed() {
    let text = fixture_text("ed25519.ppk");
    let lines: Vec<&str> = text.split('\n').collect();
    let mut swapped = lines.clone();
    swapped.swap(1, 2);
    assert_eq!(
        KeyFile::from_ppk(swapped.join("\n").as_bytes(), None).err(),
        Some(KeyFileError::Malformed)
    );
    assert_eq!(
        KeyFile::from_ppk(b"not a key", None).err(),
        Some(KeyFileError::NotThisFormat)
    );
}

#[test]
fn every_cut_of_a_ppk_is_an_error_not_a_panic() {
    for name in ["ed25519.ppk", "rsa.ppk", "ecdsa384-enc.ppk"] {
        let text = fixture(name);
        for end in 0..text.len() {
            let _ = KeyFile::from_ppk(&text[..end], Some(WINSCP_PASS));
        }
    }
}

proptest! {
    #[test]
    fn any_bytes_are_a_key_or_an_error_never_a_panic(text in prop::collection::vec(any::<u8>(), 0..512)) {
        let mut with_magic = b"PuTTY-User-Key-File-3: ssh-rsa\n".to_vec();
        with_magic.extend(&text);
        let _ = KeyFile::from_ppk(&text, None);
        let _ = KeyFile::from_ppk(&with_magic, Some(WINSCP_PASS));
    }

    #[test]
    fn a_ppk_with_one_byte_changed_is_a_key_or_an_error_never_a_panic(
        index in any::<prop::sample::Index>(),
        value in any::<u8>(),
    ) {
        let mut text = fixture("rsa.ppk");
        let at = index.index(text.len());
        text[at] = value;
        let _ = KeyFile::from_ppk(&text, None);
    }
}

/// An unencrypted v3 file made from the `name` fixture with `comment` as its comment, its MAC
/// computed afresh as PuTTY computes one for a file without a passphrase: HMAC-SHA-256 under
/// an empty key.
fn with_comment(name: &str, comment: &[u8]) -> Vec<u8> {
    use hmac::{KeyInit, Mac};
    let text = fixture(name);
    let lines: Vec<&[u8]> = text.split(|&b| b == b'\n').collect();
    let field = |prefix: &[u8]| {
        lines
            .iter()
            .find_map(|l| l.strip_prefix(prefix))
            .unwrap()
            .to_vec()
    };
    let block = |name: &[u8]| {
        let at = lines.iter().position(|l| l.starts_with(name)).unwrap();
        let count: usize = std::str::from_utf8(&lines[at][name.len() + 2..])
            .unwrap()
            .parse()
            .unwrap();
        let text: Vec<u8> = lines[at + 1..=at + count].concat();
        base64ct_decode(&text)
    };
    let algorithm = field(b"PuTTY-User-Key-File-3: ");
    let (public, private) = (block(b"Public-Lines"), block(b"Private-Lines"));
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(b"").unwrap();
    for f in [&algorithm[..], b"none", comment, &public, &private] {
        mac.update(&(f.len() as u32).to_be_bytes());
        mac.update(f);
    }
    let mac: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut out = Vec::new();
    for line in &lines {
        if line.starts_with(b"Comment: ") {
            out.extend(b"Comment: ");
            out.extend(comment);
        } else if line.starts_with(b"Private-MAC: ") {
            out.extend(format!("Private-MAC: {mac}").as_bytes());
        } else {
            out.extend(*line);
        }
        out.push(b'\n');
    }
    out
}

fn base64ct_decode(text: &[u8]) -> Vec<u8> {
    use base64ct::{Base64, Encoding};
    Base64::decode_vec(std::str::from_utf8(text).unwrap()).unwrap()
}

#[test]
fn a_comment_that_is_not_utf8_is_kept_as_its_bytes() {
    // "한국" in CP949, as a Korean Windows PuTTYgen may write a comment.
    let comment = [0xc7, 0xd1, 0xb1, 0xb9];
    let key = KeyFile::from_ppk(&with_comment("ed25519.ppk", &comment), None).unwrap();
    assert_eq!(key.comment(), comment);
}

#[test]
fn argon2_memory_below_eight_blocks_a_lane_is_raised_as_go_raises_it() {
    let text = edited("ed25519-enc.ppk", "Argon2-Memory: 8192", "Argon2-Memory: 4");
    assert_eq!(
        KeyFile::from_ppk(&text, Some(WINSCP_PASS)).err(),
        Some(KeyFileError::WrongPassphrase)
    );
}

#[test]
fn hex_with_a_sign_is_malformed() {
    let text = fixture_text("ed25519-enc.ppk");
    let salt = text
        .lines()
        .find(|l| l.starts_with("Argon2-Salt: "))
        .unwrap();
    let signed = format!("Argon2-Salt: +{}", &salt[14..]);
    let text = text.replacen(salt, &signed, 1);
    assert_eq!(
        KeyFile::from_ppk(text.as_bytes(), Some(WINSCP_PASS)).err(),
        Some(KeyFileError::Malformed)
    );
}
