//! Client public key and certificate authentication against a server answering raw
//! (`test-support`): the query, the signed request and the algorithm chosen for it.

mod common;

#[path = "common/test_keys.rs"]
mod test_keys;

use common::*;
use justssh::{
    Action, Client, Closed, DisconnectReason, EcdsaCurve, Error, KeyError, Phase, PrivateKey,
    Server, Zeroizing,
};
use justssh_wire::{
    ExtInfo, Message, Reader, ServiceAccept, UserauthFailure, UserauthSuccess, Writer,
};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn ed25519() -> PrivateKey {
    PrivateKey::ed25519(Zeroizing::new([9; 32]))
}

fn ecdsa(curve: EcdsaCurve, len: usize) -> PrivateKey {
    PrivateKey::ecdsa(curve, Zeroizing::new(vec![1; len])).unwrap()
}

fn rsa() -> PrivateKey {
    PrivateKey::rsa(
        &hex(test_keys::RSA_N),
        &hex(test_keys::RSA_E),
        Zeroizing::new(hex(test_keys::RSA_D)),
        Zeroizing::new(hex(test_keys::RSA_P)),
        Zeroizing::new(hex(test_keys::RSA_Q)),
    )
    .unwrap()
}

/// A client at user authentication with a server answering raw, which sent `server-sig-algs`
/// with `sig_algs` before accepting the service, or no `SSH_MSG_EXT_INFO` at all.
fn at_auth_with(sig_algs: Option<&str>) -> (Server, Client) {
    let mut server = server_with(|b| b.send_ext_info(false));
    let mut client = client();
    server.set_raw_receive(true);
    let (s, c) = pump(&mut server, &mut client, usize::MAX);
    assert!(s.closed.is_none() && c.closed.is_none());
    let mut payloads = Vec::new();
    if let Some(algs) = sig_algs {
        payloads.push(
            Message::ExtInfo(ExtInfo::new(vec![(
                "server-sig-algs".into(),
                algs.as_bytes().to_vec(),
            )]))
            .encode(),
        );
    }
    payloads.push(Message::ServiceAccept(ServiceAccept::new("ssh-userauth")).encode());
    for p in payloads {
        to_client(&mut client, server.send_raw(&p));
    }
    assert_eq!(client.phase(), Phase::Auth);
    (server, client)
}

const GO_SIG_ALGS: &str = "ssh-ed25519,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,\
    ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-256,rsa-sha2-512,ssh-rsa,ssh-dss";

/// A `publickey` request as the server received it.
#[derive(Debug)]
struct Request {
    user: Vec<u8>,
    signed: bool,
    algorithm: String,
    blob: Vec<u8>,
    signature: Option<Vec<u8>>,
}

fn raw_requests(server: &mut Server, actions: Vec<Action>) -> Vec<Request> {
    to_server(server, actions)
        .into_iter()
        .filter_map(|a| match a {
            Action::RawReceived(p) => Some(p),
            _ => None,
        })
        .map(|p| {
            let mut r = Reader::new(&p[1..]);
            assert_eq!(p[0], 50, "not a userauth request: {p:?}");
            let user = r.string().unwrap().to_vec();
            assert_eq!(r.utf8().unwrap(), "ssh-connection");
            assert_eq!(r.utf8().unwrap(), "publickey");
            let signed = r.bool().unwrap();
            let algorithm = r.utf8().unwrap().to_owned();
            let blob = r.string().unwrap().to_vec();
            let signature = signed.then(|| r.string().unwrap().to_vec());
            r.finish().unwrap();
            Request {
                user,
                signed,
                algorithm,
                blob,
                signature,
            }
        })
        .collect()
}

fn pk_ok(algorithm: &str, blob: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(60).string(algorithm.as_bytes()).string(blob);
    w.into_bytes()
}

/// The data a `publickey` signature covers (RFC 4252 §7).
fn signed_data(session_id: &[u8], algorithm: &str, blob: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.string(session_id)
        .u8(50)
        .string(CLIENT_USER)
        .string(b"ssh-connection")
        .string(b"publickey")
        .bool(true)
        .string(algorithm.as_bytes())
        .string(blob);
    w.into_bytes()
}

/// Checks `signature` over `data` with the public key in `blob`, using RustCrypto directly.
fn verify(blob: &[u8], signature: &[u8], data: &[u8]) -> String {
    let mut sig = Reader::new(signature);
    let sig_algorithm = sig.utf8().unwrap().to_owned();
    let sig_bytes = sig.string().unwrap().to_vec();
    sig.finish().unwrap();
    let mut key = Reader::new(blob);
    let key_type = key.utf8().unwrap();
    match key_type {
        "ssh-ed25519" => {
            use ed25519_dalek::Verifier;
            let pk: [u8; 32] = key.string().unwrap().try_into().unwrap();
            let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
            ed25519_dalek::VerifyingKey::from_bytes(&pk)
                .unwrap()
                .verify(data, &sig)
                .expect("ed25519 signature does not verify");
        }
        t if t.starts_with("ecdsa-sha2-") => {
            let _curve = key.utf8().unwrap();
            let q = key.string().unwrap();
            let mut rs = Reader::new(&sig_bytes);
            let (r, s) = (rs.string().unwrap(), rs.string().unwrap());
            rs.finish().unwrap();
            for m in [r, s] {
                assert!(is_canonical_positive_mpint(m), "not an mpint: {m:?}");
            }
            ecdsa_verify(t, q, r, s, data);
        }
        "ssh-rsa" => {
            let e = key.string().unwrap();
            let n = key.string().unwrap();
            let public = rsa::RsaPublicKey::new(
                rsa::BigUint::from_bytes_be(n),
                rsa::BigUint::from_bytes_be(e),
            )
            .unwrap();
            use rsa::signature::Verifier;
            let sig = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice()).unwrap();
            match sig_algorithm.as_str() {
                "rsa-sha2-256" => {
                    rsa::pkcs1v15::VerifyingKey::<rsa_sha2::Sha256>::new(public).verify(data, &sig)
                }
                "rsa-sha2-512" => {
                    rsa::pkcs1v15::VerifyingKey::<rsa_sha2::Sha512>::new(public).verify(data, &sig)
                }
                "ssh-rsa" => {
                    rsa::pkcs1v15::VerifyingKey::<rsa_sha1::Sha1>::new(public).verify(data, &sig)
                }
                other => panic!("RSA signature algorithm {other}"),
            }
            .expect("RSA signature does not verify");
        }
        other => panic!("key type {other}"),
    }
    sig_algorithm
}

/// Whether `m` is a positive mpint as RFC 4251 §5 writes it: no sign bit set, and no leading
/// zero byte unless the next byte has its top bit set.
fn is_canonical_positive_mpint(m: &[u8]) -> bool {
    match m {
        [] => true,
        [first, ..] if first & 0x80 != 0 => false,
        [0, next, ..] => next & 0x80 != 0,
        [0] => false,
        _ => true,
    }
}

fn ecdsa_verify(kind: &str, q: &[u8], r: &[u8], s: &[u8], data: &[u8]) {
    fn fixed(x: &[u8], len: usize) -> Vec<u8> {
        let x = &x[x.iter().position(|&b| b != 0).unwrap_or(x.len())..];
        let mut out = vec![0; len - x.len()];
        out.extend(x);
        out
    }
    use p256::ecdsa::signature::Verifier;
    match kind {
        "ecdsa-sha2-nistp256" => {
            let sig = p256::ecdsa::Signature::from_scalars(
                p256::FieldBytes::try_from(fixed(r, 32).as_slice()).unwrap(),
                p256::FieldBytes::try_from(fixed(s, 32).as_slice()).unwrap(),
            )
            .unwrap();
            p256::ecdsa::VerifyingKey::from_sec1_bytes(q)
                .unwrap()
                .verify(data, &sig)
                .expect("p256 signature does not verify");
        }
        "ecdsa-sha2-nistp384" => {
            let sig = p384::ecdsa::Signature::from_scalars(
                p384::FieldBytes::try_from(fixed(r, 48).as_slice()).unwrap(),
                p384::FieldBytes::try_from(fixed(s, 48).as_slice()).unwrap(),
            )
            .unwrap();
            p384::ecdsa::VerifyingKey::from_sec1_bytes(q)
                .unwrap()
                .verify(data, &sig)
                .expect("p384 signature does not verify");
        }
        "ecdsa-sha2-nistp521" => {
            let sig = p521::ecdsa::Signature::from_scalars(
                p521::FieldBytes::try_from(fixed(r, 66).as_slice()).unwrap(),
                p521::FieldBytes::try_from(fixed(s, 66).as_slice()).unwrap(),
            )
            .unwrap();
            p521::ecdsa::VerifyingKey::from_sec1_bytes(q)
                .unwrap()
                .verify(data, &sig)
                .expect("p521 signature does not verify");
        }
        other => panic!("ecdsa type {other}"),
    }
}

/// Runs a query and, on `PK_OK`, the signed request for `key` against a server that sent
/// `sig_algs`; returns the algorithm of the request and of the verified signature.
fn log_in(key: &PrivateKey, sig_algs: Option<&str>) -> (String, String) {
    let (mut server, mut client) = at_auth_with(sig_algs);
    let query = raw_requests(&mut server, client.auth_publickey(key));
    assert_eq!(query.len(), 1, "{query:?}");
    let q = &query[0];
    assert!(!q.signed, "the first request is a query");
    assert_eq!(
        (q.user.as_slice(), &q.blob),
        (CLIENT_USER, &key.public_blob())
    );

    let answer = server_raw(&mut server, &pk_ok(&q.algorithm, &q.blob), &mut client);
    let signed = raw_requests(&mut server, answer);
    assert_eq!(signed.len(), 1, "{signed:?}");
    let s = &signed[0];
    assert!(s.signed);
    assert_eq!((&s.algorithm, &s.blob), (&q.algorithm, &q.blob));
    let data = signed_data(client.session_id().unwrap(), &s.algorithm, &s.blob);
    let sig_algorithm = verify(
        &underlying_blob(key, &s.blob),
        s.signature.as_ref().unwrap(),
        &data,
    );

    let done = to_client(
        &mut client,
        server.send_raw(&Message::UserauthSuccess(UserauthSuccess::default()).encode()),
    );
    assert!(closed(&done).is_none(), "{done:?}");
    assert_eq!(client.phase(), Phase::Connected);
    (s.algorithm.clone(), sig_algorithm)
}

/// What the client wrote in answer to `payload` sent raw by the server.
fn server_raw(server: &mut Server, payload: &[u8], client: &mut Client) -> Vec<Action> {
    to_client(client, server.send_raw(payload))
}

/// The plain public key blob of `key`, for a certificate blob too.
fn underlying_blob(key: &PrivateKey, blob: &[u8]) -> Vec<u8> {
    if blob == key.public_blob() && key.certificate().is_none() {
        blob.to_vec()
    } else {
        key.plain_public_blob()
    }
}

fn closed(actions: &[Action]) -> Option<&Closed> {
    actions.iter().find_map(|a| match a {
        Action::Closed(c) => Some(c),
        _ => None,
    })
}

fn refused(actions: &[Action]) -> Option<Vec<String>> {
    actions.iter().find_map(|a| match a {
        Action::PublicKeyRefused { methods } => Some(methods.clone()),
        _ => None,
    })
}

fn failure(actions: &[Action]) -> Option<Vec<String>> {
    actions.iter().find_map(|a| match a {
        Action::AuthFailure { methods, .. } => Some(methods.clone()),
        _ => None,
    })
}

#[test]
fn an_ed25519_key_signs_after_the_server_accepts_the_query() {
    assert_eq!(
        log_in(&ed25519(), Some(GO_SIG_ALGS)),
        ("ssh-ed25519".into(), "ssh-ed25519".into())
    );
}

#[test]
fn ecdsa_keys_of_each_curve_sign_with_their_own_hash() {
    for (curve, len, name) in [
        (EcdsaCurve::P256, 32, "ecdsa-sha2-nistp256"),
        (EcdsaCurve::P384, 48, "ecdsa-sha2-nistp384"),
        (EcdsaCurve::P521, 66, "ecdsa-sha2-nistp521"),
    ] {
        assert_eq!(
            log_in(&ecdsa(curve, len), Some(GO_SIG_ALGS)),
            (name.into(), name.into())
        );
    }
}

#[test]
fn rsa_signs_with_rsa_sha2_256_when_the_server_lists_it() {
    assert_eq!(
        log_in(&rsa(), Some(GO_SIG_ALGS)),
        ("rsa-sha2-256".into(), "rsa-sha2-256".into())
    );
}

#[test]
fn rsa_signs_with_rsa_sha2_512_when_that_is_the_one_the_server_lists() {
    assert_eq!(
        log_in(&rsa(), Some("ssh-ed25519,rsa-sha2-512")),
        ("rsa-sha2-512".into(), "rsa-sha2-512".into())
    );
}

#[test]
fn rsa_signs_with_ssh_rsa_when_the_server_sends_no_server_sig_algs() {
    assert_eq!(log_in(&rsa(), None), ("ssh-rsa".into(), "ssh-rsa".into()));
}

#[test]
fn rsa_signs_with_ssh_rsa_when_the_server_lists_no_rsa_algorithm() {
    assert_eq!(
        log_in(&rsa(), Some("ssh-ed25519")),
        ("ssh-rsa".into(), "ssh-rsa".into())
    );
}

fn certificate(cert_type: &str, plain_blob: &[u8]) -> Vec<u8> {
    let mut plain = Reader::new(plain_blob);
    plain.utf8().unwrap();
    let mut w = Writer::new();
    w.string(cert_type.as_bytes()).string(b"nonce-nonce-nonce");
    w.bytes(plain.remaining());
    // uint64 serial, uint32 type, string key id, string principals, uint64 valid after,
    // uint64 valid before, string critical options, string extensions, string reserved,
    // string signature key, string signature: their content is the server's to check.
    w.bytes(&[0; 8])
        .u32(1)
        .string(b"id")
        .string(b"")
        .bytes(&[0; 8])
        .bytes(&[0xff; 8]);
    w.string(b"")
        .string(b"")
        .string(b"")
        .string(b"ca")
        .string(b"sig");
    w.into_bytes()
}

#[test]
fn a_certificate_is_offered_under_its_own_algorithm_and_signs_as_its_key() {
    let key = ed25519();
    let cert = certificate("ssh-ed25519-cert-v01@openssh.com", &key.public_blob());
    let key = key.with_certificate(cert.clone()).unwrap();
    assert_eq!(key.public_blob(), cert);
    assert_eq!(
        log_in(&key, Some(GO_SIG_ALGS)),
        (
            "ssh-ed25519-cert-v01@openssh.com".into(),
            "ssh-ed25519".into()
        )
    );
}

#[test]
fn an_rsa_certificate_follows_server_sig_algs_like_its_key() {
    let key = rsa();
    let cert = certificate("ssh-rsa-cert-v01@openssh.com", &key.public_blob());
    let key = key.with_certificate(cert).unwrap();
    assert_eq!(
        log_in(&key, Some(GO_SIG_ALGS)),
        (
            "rsa-sha2-256-cert-v01@openssh.com".into(),
            "rsa-sha2-256".into()
        )
    );
    assert_eq!(
        log_in(&key, None),
        ("ssh-rsa-cert-v01@openssh.com".into(), "ssh-rsa".into())
    );
}

#[test]
fn a_certificate_for_another_key_is_refused() {
    let other = PrivateKey::ed25519(Zeroizing::new([5; 32]));
    let cert = certificate("ssh-ed25519-cert-v01@openssh.com", &other.public_blob());
    assert_eq!(
        ed25519().with_certificate(cert).err(),
        Some(KeyError::CertificateMismatch)
    );
    let wrong_type = certificate("ssh-rsa-cert-v01@openssh.com", &ed25519().public_blob());
    assert!(ed25519().with_certificate(wrong_type).is_err());
    assert!(ed25519().with_certificate(b"garbage".to_vec()).is_err());
}

#[test]
fn a_refused_query_is_reported_as_a_refused_key_and_nothing_is_signed() {
    let (mut server, mut client) = at_auth_with(Some(GO_SIG_ALGS));
    raw_requests(&mut server, client.auth_publickey(&ed25519()));
    let f =
        Message::UserauthFailure(UserauthFailure::new(vec!["publickey".into()], false)).encode();
    let back = server_raw(&mut server, &f, &mut client);
    assert_eq!(refused(&back), Some(vec!["publickey".to_owned()]));
    assert_eq!(failure(&back), None);
    assert!(
        !back.iter().any(|a| matches!(a, Action::Write(_))),
        "{back:?}"
    );
}

#[test]
fn a_pk_ok_for_another_key_or_algorithm_is_taken_as_a_refusal() {
    let other = ecdsa(EcdsaCurve::P256, 32);
    for (algorithm, blob) in [
        ("ssh-ed25519", other.public_blob()),
        ("ecdsa-sha2-nistp256", ed25519().public_blob()),
    ] {
        let (mut server, mut client) = at_auth_with(Some(GO_SIG_ALGS));
        let methods =
            Message::UserauthFailure(UserauthFailure::new(vec!["publickey".into()], false))
                .encode();
        // A first refusal gives the client the methods it reports later.
        let actions = client.auth_none();
        raw_requests_any(&mut server, actions);
        server_raw(&mut server, &methods, &mut client);
        raw_requests(&mut server, client.auth_publickey(&ed25519()));
        let back = server_raw(&mut server, &pk_ok(algorithm, &blob), &mut client);
        assert_eq!(
            refused(&back),
            Some(vec!["publickey".to_owned()]),
            "{back:?}"
        );
        assert!(
            !back.iter().any(|a| matches!(a, Action::Write(_))),
            "{back:?}"
        );
    }
}

#[test]
fn a_pk_ok_naming_the_key_type_for_an_rsa_sha2_query_is_accepted() {
    let (mut server, mut client) = at_auth_with(Some(GO_SIG_ALGS));
    let key = rsa();
    raw_requests(&mut server, client.auth_publickey(&key));
    let answer = server_raw(
        &mut server,
        &pk_ok("ssh-rsa", &key.public_blob()),
        &mut client,
    );
    let signed = raw_requests(&mut server, answer);
    assert_eq!(signed.len(), 1);
    assert_eq!(signed[0].algorithm, "rsa-sha2-256");
}

/// Payloads the raw server received, whatever they are.
fn raw_requests_any(server: &mut Server, actions: Vec<Action>) -> Vec<Vec<u8>> {
    to_server(server, actions)
        .into_iter()
        .filter_map(|a| match a {
            Action::RawReceived(p) => Some(p),
            _ => None,
        })
        .collect()
}

#[test]
fn an_algorithm_chosen_by_the_caller_must_belong_to_the_key() {
    let (mut server, mut client) = at_auth_with(Some(GO_SIG_ALGS));
    let key = rsa();
    let sent = raw_requests(&mut server, client.auth_publickey_as(&key, "ssh-rsa"));
    assert_eq!(sent[0].algorithm, "ssh-rsa");

    let (_server, mut client) = at_auth_with(Some(GO_SIG_ALGS));
    let actions = client.auth_publickey_as(&ed25519(), "rsa-sha2-256");
    assert!(matches!(
        closed(&actions),
        Some(Closed::Local {
            reason: DisconnectReason::PROTOCOL_ERROR,
            error: Error::UnexpectedEvent,
            ..
        })
    ));
}

#[test]
fn a_private_key_does_not_show_its_secret_in_debug_output() {
    let shown = format!("{:?}", ed25519());
    assert!(!shown.contains("9, 9, 9"), "{shown}");
    assert!(shown.contains("ssh-ed25519"), "{shown}");
}

#[test]
fn a_failed_signed_request_is_an_ordinary_failure() {
    let (mut server, mut client) = at_auth_with(Some(GO_SIG_ALGS));
    let key = ed25519();
    raw_requests(&mut server, client.auth_publickey(&key));
    let answer = server_raw(
        &mut server,
        &pk_ok("ssh-ed25519", &key.public_blob()),
        &mut client,
    );
    raw_requests(&mut server, answer);
    let f = Message::UserauthFailure(UserauthFailure::new(vec!["password".into()], false)).encode();
    let back = server_raw(&mut server, &f, &mut client);
    assert_eq!(failure(&back), Some(vec!["password".to_owned()]));
    assert_eq!(refused(&back), None);
}

#[test]
fn the_algorithm_a_key_signs_under_follows_server_sig_algs_as_go_picks_it() {
    let key = rsa();
    assert_eq!(key.algorithm_for(None), "ssh-rsa");
    assert_eq!(
        key.algorithm_for(Some(&["rsa-sha2-512", "rsa-sha2-256"])),
        "rsa-sha2-256"
    );
    assert_eq!(key.algorithm_for(Some(&["ssh-ed25519"])), "ssh-rsa");
    assert_eq!(
        key.algorithms(),
        ["rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"]
    );
    assert_eq!(
        ed25519().algorithm_for(Some(&["rsa-sha2-256"])),
        "ssh-ed25519"
    );
}

#[test]
fn an_ecdsa_scalar_with_the_leading_zero_of_an_mpint_is_taken() {
    // A scalar whose top bit is set, as an SSH mpint stores it: with a leading zero byte.
    let mut scalar = vec![0x80; 32];
    scalar[31] = 1;
    let plain = PrivateKey::ecdsa(EcdsaCurve::P256, Zeroizing::new(scalar.clone())).unwrap();
    let mut mpint = vec![0];
    mpint.extend(&scalar);
    let padded = PrivateKey::ecdsa(EcdsaCurve::P256, Zeroizing::new(mpint)).unwrap();
    assert_eq!(padded.public_blob(), plain.public_blob());
    assert_eq!(
        PrivateKey::ecdsa(EcdsaCurve::P256, Zeroizing::new(vec![1; 33])).err(),
        Some(KeyError::InvalidKey)
    );
}

#[test]
fn an_rsa_key_under_1024_bits_is_refused() {
    let small = PrivateKey::rsa(
        &hex(test_keys::SMALL_RSA_N),
        &hex(test_keys::RSA_E),
        Zeroizing::new(hex(test_keys::SMALL_RSA_D)),
        Zeroizing::new(hex(test_keys::SMALL_RSA_P)),
        Zeroizing::new(hex(test_keys::SMALL_RSA_Q)),
    );
    assert_eq!(small.err(), Some(KeyError::InvalidKey));
}
