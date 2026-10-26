//! The credential an ISSUE carries, read on arrival as acwbroker's `upstream.Check` reads it and
//! refused with `refusalFor`'s message and reason. `tests/credential/check.tsv` is what
//! acwbroker itself answered for each case.

use std::path::PathBuf;

use justssh_broker::credential::{self, Reason};
use justssh_broker::issue;

fn crates() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn rec(tag: u8, val: &[u8]) -> Vec<u8> {
    [&[tag][..], &(val.len() as u32).to_be_bytes(), val].concat()
}

/// An ISSUE of `method` with these secrets, for a loopback upstream.
fn issue(method: &str, key: &[u8], passphrase: Option<&[u8]>, cert: Option<&[u8]>) -> Vec<u8> {
    let mut p = [
        rec(0x10, method.as_bytes()),
        rec(0x15, b"srv42@10.0.0.9"),
        rec(0x16, b"127.0.0.7:51201"),
        rec(0x12, key),
    ]
    .concat();
    if let Some(pass) = passphrase {
        p.extend(rec(0x13, pass));
    }
    if let Some(cert) = cert {
        p.extend(rec(0x14, cert));
    }
    p
}

/// The key a dial of `iss` signs with.
fn dial_key(iss: &issue::Issue) -> justssh::PrivateKey {
    credential::private_key(&iss.credential).unwrap()
}

fn file(path: &str) -> Vec<u8> {
    std::fs::read(crates().join(path)).unwrap()
}

#[test]
fn each_credential_is_judged_as_acwbroker_judges_it() {
    let golden =
        std::fs::read_to_string(crates().join("justssh-broker/tests/credential/check.tsv"))
            .unwrap();
    let mut differ = Vec::new();
    let mut cases = 0;
    for line in golden.lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<&str> = line.split('\t').collect();
        let [method, key, pass, cert, message, reason] = f[..] else {
            panic!("bad golden line {line:?}");
        };
        let pass = (pass != "-").then(|| pass.as_bytes().to_vec());
        let cert = (cert != "-").then(|| file(cert));
        let payload = issue(method, &file(key), pass.as_deref(), cert.as_deref());
        let iss = issue::decode(&payload).unwrap();
        let got = match credential::check(&iss.credential) {
            Ok(()) => ("ok".to_owned(), 0),
            Err(r) => (r.reason.message().to_owned(), r.reason.code()),
        };
        // A DSA key and an RSA key of three primes, which Go reads and this side refuses.
        let refused_here = key.ends_with("pem/dsa") || key.ends_with("pem/rsa-pkcs1-3primes");
        let want = if refused_here && reason == "0" {
            ("unreadable private key or certificate".to_owned(), 4)
        } else {
            (message.to_owned(), reason.parse().unwrap())
        };
        if got != want {
            differ.push(format!("{line}\n    got {got:?}"));
        }
        cases += 1;
    }
    assert_eq!(cases, 134);
    assert!(
        differ.is_empty(),
        "{} differ:\n{}",
        differ.len(),
        differ.join("\n")
    );
}

#[test]
fn the_reasons_keep_acwbrokers_codes_and_words() {
    let all = [
        (Reason::WrongPassphrase, 1, "wrong passphrase"),
        (Reason::PassphraseRequired, 2, "passphrase required"),
        (Reason::UnsupportedKey, 3, "unsupported private key"),
        (
            Reason::Malformed,
            4,
            "unreadable private key or certificate",
        ),
    ];
    for (r, code, message) in all {
        assert_eq!((r.code(), r.message()), (code, message));
    }
}

#[test]
fn a_password_credential_is_not_read() {
    let payload = [
        rec(0x10, b"password"),
        rec(0x15, b"srv42@10.0.0.9"),
        rec(0x16, b"127.0.0.7:51201"),
        rec(0x11, b"pw"),
    ]
    .concat();
    assert!(credential::check(&issue::decode(&payload).unwrap().credential).is_ok());
}

#[test]
fn the_key_a_credential_dials_with_is_the_one_its_file_holds() {
    let iss = issue::decode(&issue(
        "key",
        &file("justssh-keys/tests/ppk/ed25519-enc.ppk"),
        Some(b"correct horse"),
        None,
    ))
    .unwrap();
    let key = dial_key(&iss);
    let source = justssh_keys::KeyFile::read(
        &file("justssh-keys/tests/ppk/ed25519-enc.openssh"),
        Some(b"correct horse"),
    )
    .unwrap();
    assert_eq!(key.public_blob(), source.private_key().public_blob());
    assert!(key.certificate().is_none());

    let cert = file("justssh-broker/tests/credential/user-cert.pub");
    let iss = issue::decode(&issue(
        "certificate",
        &file("justssh-broker/tests/credential/user"),
        None,
        Some(&cert),
    ))
    .unwrap();
    let key = dial_key(&iss);
    let blob = justssh_keys::certificate_from_line(&cert).unwrap();
    assert_eq!(key.certificate(), Some(&blob[..]));
}

/// The key parse runs off the async worker (#71): its future yields on the first poll (the work
/// is handed to a blocking thread), so another task spawned on the same single-threaded runtime
/// gets to run during the parse. An inline parse would finish in one poll without yielding, and
/// the other task could not run until it returned.
#[test]
fn the_key_parse_yields_the_async_worker() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let iss = issue::decode(&issue(
        "key",
        &file("justssh-keys/tests/keys/ed25519-pass"),
        Some(b"correct horse"),
        None,
    ))
    .unwrap();

    let ran_during_parse = rt.block_on(async move {
        let flag = Arc::new(AtomicBool::new(false));
        let other = flag.clone();
        // Completes on its first poll; it only gets that poll if the parse future yields.
        tokio::spawn(async move { other.store(true, Ordering::Relaxed) });
        let key = credential::private_key_off_thread(iss.credential)
            .await
            .unwrap();
        assert!(key.certificate().is_none());
        flag.load(Ordering::Relaxed)
    });
    assert!(ran_during_parse, "the parse did not yield the worker");
}
