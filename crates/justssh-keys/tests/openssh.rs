//! OpenSSH private key files. The keys in `tests/keys/` were made by `ssh-keygen` 10.0 for these
//! tests and are not secret; each `.pub` beside them is `ssh-keygen`'s own public key line.

use base64ct::{Base64, Encoding};
use justssh::Zeroizing;
use justssh_keys::{KeyFile, KeyFileError};
use proptest::prelude::*;

const PASSPHRASE: &[u8] = b"correct horse";

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/keys/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// The public key blob and comment of `ssh-keygen`'s `.pub` line for `name`.
fn public_line(name: &str) -> (Vec<u8>, Vec<u8>) {
    let line = String::from_utf8(fixture(&format!("{name}.pub"))).unwrap();
    let mut fields = line.split_whitespace();
    fields.next();
    let blob = Base64::decode_vec(fields.next().unwrap()).unwrap();
    (blob, fields.next().unwrap_or("").as_bytes().to_vec())
}

/// Every fixture `ssh-keygen` made, with whether it is encrypted.
const FIXTURES: [(&str, bool); 7] = [
    ("ed25519", false),
    ("ed25519-pass", true),
    ("ecdsa256", false),
    ("ecdsa384", false),
    ("ecdsa521-pass-cbc", true),
    ("rsa2048", false),
    ("rsa3072-pass", true),
];

fn read(name: &str, encrypted: bool) -> KeyFile {
    KeyFile::from_openssh(&fixture(name), encrypted.then_some(PASSPHRASE))
        .unwrap_or_else(|e| panic!("{name}: {e}"))
}

#[test]
fn keys_ssh_keygen_wrote_read_as_its_public_key_lines_say() {
    for (name, encrypted) in FIXTURES {
        let key = read(name, encrypted);
        let (blob, comment) = public_line(name);
        assert_eq!(key.private_key().plain_public_blob(), blob, "{name}");
        assert_eq!(key.comment(), comment, "{name}");
    }
}

#[test]
fn a_key_written_reads_back_as_the_same_key_and_comment() {
    for (name, encrypted) in FIXTURES {
        let key = read(name, encrypted);
        let text = key.to_openssh();
        assert!(
            text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"),
            "{name}"
        );
        let again = KeyFile::from_openssh(text.as_bytes(), None).unwrap();
        assert_eq!(
            again.private_key().plain_public_blob(),
            key.private_key().plain_public_blob(),
            "{name}"
        );
        assert_eq!(again.comment(), key.comment(), "{name}");
    }
}

#[test]
fn a_key_built_from_its_material_is_written_as_that_key() {
    let key = KeyFile::ed25519(Zeroizing::new([7; 32])).with_comment("acwbroker");
    let again = KeyFile::from_openssh(key.to_openssh().as_bytes(), None).unwrap();
    assert_eq!(
        again.private_key().plain_public_blob(),
        justssh::PrivateKey::ed25519(Zeroizing::new([7; 32])).plain_public_blob()
    );
    assert_eq!(again.comment(), b"acwbroker");
}

#[test]
fn passphrases_are_asked_for_only_where_they_are_needed() {
    assert_eq!(
        KeyFile::from_openssh(&fixture("ed25519-pass"), None).err(),
        Some(KeyFileError::PassphraseNeeded)
    );
    assert_eq!(
        KeyFile::from_openssh(&fixture("ed25519-pass"), Some(b"wrong")).err(),
        Some(KeyFileError::WrongPassphrase)
    );
    assert_eq!(
        KeyFile::from_openssh(&fixture("ecdsa521-pass-cbc"), Some(b"wrong")).err(),
        Some(KeyFileError::WrongPassphrase)
    );
    assert_eq!(
        KeyFile::from_openssh(&fixture("ed25519"), Some(PASSPHRASE)).err(),
        Some(KeyFileError::NotEncrypted)
    );
}

#[test]
fn a_cipher_x_crypto_ssh_does_not_read_is_refused_by_name() {
    assert_eq!(
        KeyFile::from_openssh(&fixture("ed25519-gcm"), Some(PASSPHRASE)).err(),
        Some(KeyFileError::UnsupportedEncryption(
            "aes256-gcm@openssh.com".into()
        ))
    );
}

#[test]
fn text_that_is_not_an_openssh_key_is_refused() {
    assert_eq!(
        KeyFile::from_openssh(
            b"-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n",
            None
        )
        .err(),
        Some(KeyFileError::NotThisFormat)
    );
    assert_eq!(
        KeyFile::from_openssh(b"", None).err(),
        Some(KeyFileError::NotThisFormat)
    );
}

// Containers built by hand, after PROTOCOL.key.

fn string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend((s.len() as u32).to_be_bytes());
    out.extend(s);
}

/// An unencrypted container holding `keys` copies of the private section `inner`, padded to 8.
fn container(public: &[u8], inner: &[u8], keys: u32) -> Vec<u8> {
    container_under(b"none", b"none", b"", public, inner, keys)
}

/// As [`container`], naming `cipher`, `kdf` and its `options` while leaving the section as it is.
fn container_under(
    cipher: &[u8],
    kdf: &[u8],
    options: &[u8],
    public: &[u8],
    inner: &[u8],
    keys: u32,
) -> Vec<u8> {
    let mut section = vec![0, 0, 0, 9, 0, 0, 0, 9];
    section.extend(inner);
    let mut i = 1;
    while section.len() % 8 != 0 {
        section.push(i);
        i += 1;
    }
    let mut bin = b"openssh-key-v1\0".to_vec();
    string(&mut bin, cipher);
    string(&mut bin, kdf);
    string(&mut bin, options);
    bin.extend(keys.to_be_bytes());
    for _ in 0..keys {
        string(&mut bin, public);
    }
    string(&mut bin, &section);
    armor(&bin)
}

fn armor(bin: &[u8]) -> Vec<u8> {
    format!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
        Base64::encode_string(bin)
    )
    .into_bytes()
}

fn unarmor(text: &[u8]) -> Vec<u8> {
    let body: String = String::from_utf8_lossy(text)
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    Base64::decode_vec(&body).unwrap()
}

/// The private section of an ed25519 key with seed `seed` and public key `public`.
fn ed25519_inner(seed: [u8; 32], public: &[u8]) -> Vec<u8> {
    ed25519_inner_with(seed, public, public)
}

/// As [`ed25519_inner`], with `tail` as the public key half of the private key field.
fn ed25519_inner_with(seed: [u8; 32], public: &[u8], tail: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    string(&mut inner, b"ssh-ed25519");
    string(&mut inner, public);
    let mut private = seed.to_vec();
    private.extend(tail);
    string(&mut inner, &private);
    string(&mut inner, b"comment");
    inner
}

fn ed25519_public(seed: [u8; 32]) -> Vec<u8> {
    let blob = justssh::PrivateKey::ed25519(Zeroizing::new(seed)).plain_public_blob();
    blob[blob.len() - 32..].to_vec()
}

fn ed25519_blob(public: &[u8]) -> Vec<u8> {
    let mut blob = Vec::new();
    string(&mut blob, b"ssh-ed25519");
    string(&mut blob, public);
    blob
}

#[test]
fn a_hand_built_container_reads_as_its_key() {
    let public = ed25519_public([5; 32]);
    let text = container(&ed25519_blob(&public), &ed25519_inner([5; 32], &public), 1);
    let key = KeyFile::from_openssh(&text, None).unwrap();
    assert_eq!(key.private_key().plain_public_blob(), ed25519_blob(&public));
    assert_eq!(key.comment(), b"comment");
}

#[test]
fn a_file_of_two_keys_is_refused() {
    let public = ed25519_public([5; 32]);
    let text = container(&ed25519_blob(&public), &ed25519_inner([5; 32], &public), 2);
    assert_eq!(
        KeyFile::from_openssh(&text, None).err(),
        Some(KeyFileError::MultipleKeys)
    );
}

#[test]
fn a_public_half_that_does_not_match_the_private_key_is_refused() {
    let public = ed25519_public([5; 32]);
    let other = ed25519_public([6; 32]);
    let text = container(&ed25519_blob(&other), &ed25519_inner([5; 32], &other), 1);
    assert_eq!(
        KeyFile::from_openssh(&text, None).err(),
        Some(KeyFileError::InvalidKey)
    );
    let text = container(&ed25519_blob(&other), &ed25519_inner([5; 32], &public), 1);
    assert_eq!(
        KeyFile::from_openssh(&text, None).err(),
        Some(KeyFileError::InvalidKey)
    );
    let text = container(
        &ed25519_blob(&public),
        &ed25519_inner_with([5; 32], &public, &other),
        1,
    );
    assert_eq!(
        KeyFile::from_openssh(&text, None).err(),
        Some(KeyFileError::InvalidKey)
    );
}

#[test]
fn a_file_naming_only_one_of_its_cipher_and_kdf_none_is_refused() {
    let public = ed25519_public([5; 32]);
    let mut options = Vec::new();
    string(&mut options, &[1; 16]);
    options.extend(16u32.to_be_bytes());
    let text = container_under(
        b"none",
        b"bcrypt",
        &options,
        &ed25519_blob(&public),
        &ed25519_inner([5; 32], &public),
        1,
    );
    assert_eq!(
        KeyFile::from_openssh(&text, Some(PASSPHRASE)).err(),
        Some(KeyFileError::UnsupportedEncryption("none".into()))
    );
}

#[test]
fn a_dsa_key_is_refused_by_its_type() {
    let mut inner = Vec::new();
    string(&mut inner, b"ssh-dss");
    for part in [&[1u8][..], &[2], &[3], &[4], &[5]] {
        string(&mut inner, part);
    }
    string(&mut inner, b"");
    let mut public = Vec::new();
    string(&mut public, b"ssh-dss");
    assert_eq!(
        KeyFile::from_openssh(&container(&public, &inner, 1), None).err(),
        Some(KeyFileError::UnsupportedKeyType("ssh-dss".into()))
    );
}

#[test]
fn an_rsa_key_with_a_zero_part_is_invalid() {
    for zero_at in [0, 1, 2, 4, 5] {
        let mut inner = Vec::new();
        string(&mut inner, b"ssh-rsa");
        for i in 0..6 {
            let part = if i == zero_at {
                Vec::new()
            } else {
                vec![0x01, 0x01]
            };
            string(&mut inner, &part);
        }
        string(&mut inner, b"");
        let mut public = Vec::new();
        string(&mut public, b"ssh-rsa");
        assert_eq!(
            KeyFile::from_openssh(&container(&public, &inner, 1), None).err(),
            Some(KeyFileError::InvalidKey),
            "zero at {zero_at}"
        );
    }
}

#[test]
fn the_armor_must_begin_a_line() {
    let mut text = b"junk ".to_vec();
    text.extend(fixture("ed25519"));
    assert_eq!(
        KeyFile::from_openssh(&text, None).err(),
        Some(KeyFileError::NotThisFormat)
    );
    let mut text = b"Comment: before\n".to_vec();
    text.extend(fixture("ed25519"));
    assert!(KeyFile::from_openssh(&text, None).is_ok());
}

#[test]
fn padding_that_does_not_count_up_is_malformed() {
    let public = ed25519_public([5; 32]);
    let mut bin = unarmor(&container(
        &ed25519_blob(&public),
        &ed25519_inner([5; 32], &public),
        1,
    ));
    let last = bin.len() - 1;
    bin[last] ^= 0x40;
    assert_eq!(
        KeyFile::from_openssh(&armor(&bin), None).err(),
        Some(KeyFileError::Malformed)
    );
}

#[test]
fn more_key_derivation_rounds_than_x_crypto_ssh_allows_are_refused() {
    let mut bin = unarmor(&fixture("ed25519-pass"));
    // magic, "aes256-ctr", "bcrypt", then the KDF options: a string holding the salt and the rounds.
    let options = 15 + 4 + 10 + 4 + 6;
    let salt = u32::from_be_bytes(bin[options + 4..options + 8].try_into().unwrap()) as usize;
    let rounds = options + 8 + salt;
    assert_eq!(
        u32::from_be_bytes(bin[rounds..rounds + 4].try_into().unwrap()),
        4
    );
    bin[rounds..rounds + 4].copy_from_slice(&2049u32.to_be_bytes());
    assert_eq!(
        KeyFile::from_openssh(&armor(&bin), Some(PASSPHRASE)).err(),
        Some(KeyFileError::TooManyRounds(2049))
    );
    bin[rounds..rounds + 4].copy_from_slice(&2048u32.to_be_bytes());
    assert_eq!(
        KeyFile::from_openssh(&armor(&bin), Some(b"wrong")).err(),
        Some(KeyFileError::WrongPassphrase)
    );
}

#[test]
fn every_cut_of_a_key_file_is_an_error_not_a_panic() {
    for (name, encrypted) in FIXTURES {
        let bin = unarmor(&fixture(name));
        for end in 0..bin.len() {
            let result =
                KeyFile::from_openssh(&armor(&bin[..end]), encrypted.then_some(PASSPHRASE));
            assert!(result.is_err(), "{name} cut at {end}");
        }
    }
}

proptest! {
    #[test]
    fn any_bytes_are_an_error_or_a_key_never_a_panic(text in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = KeyFile::from_openssh(&text, None);
        let _ = KeyFile::from_openssh(&armor(&text), Some(PASSPHRASE));
    }

    #[test]
    fn a_key_file_with_one_byte_changed_is_an_error_or_a_key_never_a_panic(
        index in any::<prop::sample::Index>(),
        value in any::<u8>(),
    ) {
        let mut bin = unarmor(&fixture("rsa2048"));
        let at = index.index(bin.len());
        bin[at] = value;
        let _ = KeyFile::from_openssh(&armor(&bin), None);
    }
}

/// Runs `ssh-keygen` with `args`; its output, or `None` to skip where it is not installed.
fn ssh_keygen(args: &[&str]) -> Option<std::process::Output> {
    match std::process::Command::new("ssh-keygen").args(args).output() {
        Ok(out) => Some(out),
        Err(e) => {
            assert!(
                std::env::var_os("JUSTSSH_REQUIRE_SSHD").is_none(),
                "JUSTSSH_REQUIRE_SSHD is set but ssh-keygen does not run: {e}"
            );
            eprintln!("skipped: ssh-keygen does not run: {e}");
            None
        }
    }
}

#[test]
fn ssh_keygen_reads_the_key_files_written() {
    for (name, encrypted) in FIXTURES {
        let key = read(name, encrypted);
        let path = std::env::temp_dir().join(format!("justssh-keys-{name}-{}", std::process::id()));
        std::fs::write(&path, key.to_openssh().as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        // A file in %TEMP% inherits the folder's ACEs, which Windows OpenSSH rejects as "too
        // open"; narrow it to the current user alone, as `0o600` does on unix.
        #[cfg(windows)]
        {
            let user = std::env::var("USERNAME").unwrap();
            let ok = std::process::Command::new("icacls")
                .args([path.to_str().unwrap(), "/inheritance:r", "/grant:r"])
                .arg(format!("{user}:F"))
                .output()
                .unwrap()
                .status
                .success();
            assert!(ok, "icacls did not narrow {}", path.display());
        }
        let out = ssh_keygen(&["-y", "-f", path.to_str().unwrap()]);
        let _ = std::fs::remove_file(&path);
        let Some(out) = out else {
            return;
        };
        assert!(
            out.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let line = String::from_utf8(out.stdout).unwrap();
        let blob = Base64::decode_vec(line.split_whitespace().nth(1).unwrap()).unwrap();
        assert_eq!(blob, public_line(name).0, "{name}");
    }
}

/// The mpints of the RSA key in an unencrypted container: n, e, d, iqmp, p, q.
fn rsa_parts(text: &[u8]) -> Vec<Vec<u8>> {
    let bin = unarmor(text);
    let mut r = justssh_wire::Reader::new(&bin[15..]);
    for _ in 0..3 {
        r.string().unwrap();
    }
    r.u32().unwrap();
    r.string().unwrap();
    let section = r.string().unwrap();
    let mut r = justssh_wire::Reader::new(&section[8..]);
    r.string().unwrap();
    (0..6).map(|_| r.string().unwrap().to_vec()).collect()
}

#[test]
fn a_written_rsa_key_stores_the_parts_ssh_keygen_stored() {
    let text = fixture("rsa2048");
    let written = KeyFile::from_openssh(&text, None).unwrap().to_openssh();
    assert_eq!(rsa_parts(written.as_bytes()), rsa_parts(&text));
}
