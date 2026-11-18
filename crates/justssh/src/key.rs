//! Private keys for `publickey` authentication and host keys: ed25519, ECDSA over NIST
//! P-256/384/521 and RSA, each optionally with an OpenSSH certificate (`PROTOCOL.certkeys`); and
//! the verification of a signature by such a public key or an `ssh-dss` one, each optionally
//! under a certificate.

use core::fmt;

use justssh_wire::{Reader, Writer};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

/// The smallest RSA modulus taken, in bits, as OpenSSH's `SSH_RSA_MINIMUM_MODULUS_SIZE`.
const MIN_RSA_BITS: usize = 1024;
/// The largest RSA modulus and public exponent verified against, in bits, as x/crypto/ssh's
/// `parseRSA`.
const MAX_RSA_BITS: usize = 16384;
const MAX_RSA_EXPONENT_BITS: usize = 24;
/// The size of a DSA key's modulus and sub-prime, in bits, as x/crypto/ssh's `checkDSAParams`.
const DSA_P_BITS: usize = 1024;
const DSA_Q_BITS: usize = 160;
/// What a certificate format adds to its key type (`PROTOCOL.certkeys`).
const CERTIFICATE_SUFFIX: &str = "-cert-v01@openssh.com";

/// A NIST curve for an ECDSA key.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaCurve {
    P256,
    P384,
    P521,
}

impl EcdsaCurve {
    fn name(self) -> &'static str {
        match self {
            EcdsaCurve::P256 => "nistp256",
            EcdsaCurve::P384 => "nistp384",
            EcdsaCurve::P521 => "nistp521",
        }
    }

    fn key_type(self) -> &'static str {
        match self {
            EcdsaCurve::P256 => "ecdsa-sha2-nistp256",
            EcdsaCurve::P384 => "ecdsa-sha2-nistp384",
            EcdsaCurve::P521 => "ecdsa-sha2-nistp521",
        }
    }
}

/// Why a key or certificate was not taken.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// The key material does not form a valid key.
    InvalidKey,
    /// The certificate could not be read, or is not a certificate for this kind of key.
    MalformedCertificate,
    /// The certificate certifies another key.
    CertificateMismatch,
    /// No algorithm was named, or one named is not an algorithm the key signs under.
    UnsupportedAlgorithm,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KeyError::InvalidKey => "invalid private key",
            KeyError::MalformedCertificate => "malformed certificate",
            KeyError::CertificateMismatch => "certificate is for another key",
            KeyError::UnsupportedAlgorithm => "algorithm the key does not sign under",
        })
    }
}

impl std::error::Error for KeyError {}

#[derive(Clone)]
enum Secret {
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    P521(p521::ecdsa::SigningKey),
    Rsa(Box<rsa::RsaPrivateKey>),
}

/// A private key, kept in types that zeroize on drop, with the certificate it is used under if
/// any.
#[derive(Clone)]
pub struct PrivateKey {
    secret: Secret,
    certificate: Option<Vec<u8>>,
}

impl PrivateKey {
    /// An `ssh-ed25519` key from its 32-byte secret seed.
    pub fn ed25519(seed: Zeroizing<[u8; 32]>) -> Self {
        PrivateKey {
            secret: Secret::Ed25519(ed25519_dalek::SigningKey::from_bytes(&seed)),
            certificate: None,
        }
    }

    /// An `ecdsa-sha2-nistp*` key from its big-endian secret scalar, leading zero bytes
    /// allowed, as an SSH mpint holds it.
    pub fn ecdsa(curve: EcdsaCurve, scalar: Zeroizing<Vec<u8>>) -> Result<Self, KeyError> {
        let scalar = &scalar[scalar.iter().position(|&b| b != 0).unwrap_or(scalar.len())..];
        let secret = match curve {
            EcdsaCurve::P256 => p256::ecdsa::SigningKey::from_slice(scalar).map(Secret::P256),
            EcdsaCurve::P384 => p384::ecdsa::SigningKey::from_slice(scalar).map(Secret::P384),
            EcdsaCurve::P521 => p521::ecdsa::SigningKey::from_slice(scalar).map(Secret::P521),
        }
        .map_err(|_| KeyError::InvalidKey)?;
        Ok(PrivateKey {
            secret,
            certificate: None,
        })
    }

    /// An `ssh-rsa` key of at least 1024 bits from its big-endian modulus, public and private
    /// exponents and primes.
    pub fn rsa(
        n: &[u8],
        e: &[u8],
        d: Zeroizing<Vec<u8>>,
        p: Zeroizing<Vec<u8>>,
        q: Zeroizing<Vec<u8>>,
    ) -> Result<Self, KeyError> {
        use rsa::BigUint;
        use rsa::traits::PublicKeyParts;
        let key = rsa::RsaPrivateKey::from_components(
            BigUint::from_bytes_be(n),
            BigUint::from_bytes_be(e),
            secret_uint(&d),
            vec![secret_uint(&p), secret_uint(&q)],
        )
        .map_err(|_| KeyError::InvalidKey)?;
        if key.n().bits() < MIN_RSA_BITS {
            return Err(KeyError::InvalidKey);
        }
        Ok(PrivateKey {
            secret: Secret::Rsa(Box::new(key)),
            certificate: None,
        })
    }

    /// The key used under the OpenSSH certificate `blob`, which must certify this key.
    pub fn with_certificate(mut self, blob: Vec<u8>) -> Result<Self, KeyError> {
        let mut r = Reader::new(&blob);
        let cert_type = r.utf8().map_err(|_| KeyError::MalformedCertificate)?;
        if cert_type != certificate_type(self.key_type()) {
            return Err(KeyError::MalformedCertificate);
        }
        r.string().map_err(|_| KeyError::MalformedCertificate)?;
        let key_fields = public_fields(&self.plain_public_blob());
        let certified = r
            .bytes(key_fields.len())
            .map_err(|_| KeyError::MalformedCertificate)?;
        if certified != key_fields {
            return Err(KeyError::CertificateMismatch);
        }
        certificate_rest(&mut r).ok_or(KeyError::MalformedCertificate)?;
        self.certificate = Some(blob);
        Ok(self)
    }

    /// The key without its certificate.
    pub(crate) fn without_certificate(mut self) -> Self {
        self.certificate = None;
        self
    }

    /// The certificate the key is used under, if any.
    pub fn certificate(&self) -> Option<&[u8]> {
        self.certificate.as_deref()
    }

    /// The public key blob sent in authentication: the certificate when there is one.
    pub fn public_blob(&self) -> Vec<u8> {
        self.certificate
            .clone()
            .unwrap_or_else(|| self.plain_public_blob())
    }

    /// The key's own public key blob (RFC 4253 §6.6, RFC 5656 §3.1), without its certificate.
    pub fn plain_public_blob(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.string(self.key_type().as_bytes());
        match &self.secret {
            Secret::Ed25519(k) => {
                w.string(&k.verifying_key().to_bytes());
            }
            Secret::P256(k) => {
                w.string(EcdsaCurve::P256.name().as_bytes())
                    .string(k.verifying_key().to_sec1_point(false).as_bytes());
            }
            Secret::P384(k) => {
                w.string(EcdsaCurve::P384.name().as_bytes())
                    .string(k.verifying_key().to_sec1_point(false).as_bytes());
            }
            Secret::P521(k) => {
                w.string(EcdsaCurve::P521.name().as_bytes())
                    .string(k.verifying_key().to_sec1_point(false).as_bytes());
            }
            Secret::Rsa(k) => {
                use rsa::traits::PublicKeyParts;
                w.mpint_unsigned(&k.e().to_bytes_be())
                    .mpint_unsigned(&k.n().to_bytes_be());
            }
        }
        w.into_bytes()
    }

    /// The key type, such as `ssh-ed25519`, without any certificate.
    fn key_type(&self) -> &'static str {
        match &self.secret {
            Secret::Ed25519(_) => "ssh-ed25519",
            Secret::P256(_) => EcdsaCurve::P256.key_type(),
            Secret::P384(_) => EcdsaCurve::P384.key_type(),
            Secret::P521(_) => EcdsaCurve::P521.key_type(),
            Secret::Rsa(_) => "ssh-rsa",
        }
    }

    /// The public key format the key is offered under: the key type, or its certificate type.
    pub(crate) fn format(&self) -> &'static str {
        match self.certificate {
            Some(_) => certificate_type(self.key_type()),
            None => self.key_type(),
        }
    }

    /// The public key algorithms the key can sign under, in preference order.
    pub fn algorithms(&self) -> &'static [&'static str] {
        match self.format() {
            "ssh-rsa" => &["rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"],
            "ssh-rsa-cert-v01@openssh.com" => &[
                "rsa-sha2-256-cert-v01@openssh.com",
                "rsa-sha2-512-cert-v01@openssh.com",
                "ssh-rsa-cert-v01@openssh.com",
            ],
            "ssh-ed25519" => &["ssh-ed25519"],
            "ssh-ed25519-cert-v01@openssh.com" => &["ssh-ed25519-cert-v01@openssh.com"],
            "ecdsa-sha2-nistp256" => &["ecdsa-sha2-nistp256"],
            "ecdsa-sha2-nistp384" => &["ecdsa-sha2-nistp384"],
            "ecdsa-sha2-nistp521" => &["ecdsa-sha2-nistp521"],
            "ecdsa-sha2-nistp256-cert-v01@openssh.com" => {
                &["ecdsa-sha2-nistp256-cert-v01@openssh.com"]
            }
            "ecdsa-sha2-nistp384-cert-v01@openssh.com" => {
                &["ecdsa-sha2-nistp384-cert-v01@openssh.com"]
            }
            _ => &["ecdsa-sha2-nistp521-cert-v01@openssh.com"],
        }
    }

    /// The algorithm to sign under given the server's `server-sig-algs`: the first of the key's
    /// algorithms the server lists, a certificate algorithm counting as listed when its
    /// underlying algorithm is, and otherwise the key format.
    pub fn algorithm_for(&self, server_sig_algs: Option<&[&str]>) -> &'static str {
        let Some(server) = server_sig_algs else {
            return self.format();
        };
        self.algorithms()
            .iter()
            .find(|a| server.contains(&underlying(a)))
            .copied()
            .unwrap_or(self.format())
    }

    /// The signature blob over `data` for public key algorithm `algorithm`, one of
    /// [`algorithms`](Self::algorithms); `rng` blinds an RSA signature.
    pub(crate) fn sign(&self, algorithm: &str, data: &[u8], rng: &mut dyn CryptoRng) -> Vec<u8> {
        let name = underlying(algorithm);
        let mut w = Writer::new();
        w.string(name.as_bytes());
        match &self.secret {
            Secret::Ed25519(k) => {
                use ed25519_dalek::Signer;
                w.string(&k.sign(data).to_bytes());
            }
            Secret::P256(k) => {
                use p256::ecdsa::signature::Signer;
                let sig: p256::ecdsa::Signature = k.sign(data);
                let (r, s) = sig.split_bytes();
                w.string(&ecdsa_rs(&r, &s));
            }
            Secret::P384(k) => {
                use p384::ecdsa::signature::Signer;
                let sig: p384::ecdsa::Signature = k.sign(data);
                let (r, s) = sig.split_bytes();
                w.string(&ecdsa_rs(&r, &s));
            }
            Secret::P521(k) => {
                use p521::ecdsa::signature::Signer;
                let sig: p521::ecdsa::Signature = k.sign(data);
                let (r, s) = sig.split_bytes();
                w.string(&ecdsa_rs(&r, &s));
            }
            Secret::Rsa(k) => {
                use rsa::signature::{RandomizedSigner, SignatureEncoding};
                const SIZED: &str = "a key of at least 1024 bits signs under every RSA algorithm";
                let key = (**k).clone();
                let mut rng = OldRng(rng);
                let sig = match name {
                    "rsa-sha2-256" => rsa::pkcs1v15::SigningKey::<rsa_sha2::Sha256>::new(key)
                        .try_sign_with_rng(&mut rng, data)
                        .expect(SIZED)
                        .to_vec(),
                    "rsa-sha2-512" => rsa::pkcs1v15::SigningKey::<rsa_sha2::Sha512>::new(key)
                        .try_sign_with_rng(&mut rng, data)
                        .expect(SIZED)
                        .to_vec(),
                    _ => rsa::pkcs1v15::SigningKey::<rsa_sha1::Sha1>::new(key)
                        .try_sign_with_rng(&mut rng, data)
                        .expect(SIZED)
                        .to_vec(),
                };
                w.string(&sig);
            }
        }
        w.into_bytes()
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("format", &self.format())
            .finish_non_exhaustive()
    }
}

/// Whether `signature`, a signature blob, is a valid signature under public key algorithm
/// `algorithm` over `data` by the key whose public key blob is `key`. The blob's key type must be
/// one `algorithm` signs with, and it is a certificate exactly when `algorithm` is a certificate
/// algorithm; the signature is then by the certified key and named for the underlying algorithm.
pub(crate) fn verify(key: &[u8], algorithm: &str, signature: &[u8], data: &[u8]) -> bool {
    let mut sig = Reader::new(signature);
    let parsed = (|| {
        let name = sig.utf8().ok()?;
        let body = sig.string().ok()?;
        sig.finish().ok()?;
        Some((name, body))
    })();
    let Some((name, body)) = parsed else {
        return false;
    };
    let signing = underlying(algorithm);
    if name != signing {
        return false;
    }
    let mut r = Reader::new(key);
    let Ok(format) = r.utf8() else {
        return false;
    };
    let (key_type, fields) = match format.strip_suffix(CERTIFICATE_SUFFIX) {
        Some(key_type) if algorithm != signing => {
            let Some(fields) = certified_fields(&mut r, key_type) else {
                return false;
            };
            (key_type, fields)
        }
        None if algorithm == signing => (format, r.remaining()),
        _ => return false,
    };
    let r = Reader::new(fields);
    match (key_type, signing) {
        ("ssh-ed25519", "ssh-ed25519") => verify_ed25519(r, body, data),
        ("ssh-dss", "ssh-dss") => verify_dsa(r, body, data),
        ("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256") => {
            let Some((point, r, s)) = ecdsa_parts(r, EcdsaCurve::P256, body, 32) else {
                return false;
            };
            use p256::ecdsa::signature::Verifier;
            let (Ok(k), Ok(sig)) = (
                p256::ecdsa::VerifyingKey::from_sec1_bytes(point),
                p256::ecdsa::Signature::from_slice(&[r, s].concat()),
            ) else {
                return false;
            };
            k.verify(data, &sig).is_ok()
        }
        ("ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384") => {
            let Some((point, r, s)) = ecdsa_parts(r, EcdsaCurve::P384, body, 48) else {
                return false;
            };
            use p384::ecdsa::signature::Verifier;
            let (Ok(k), Ok(sig)) = (
                p384::ecdsa::VerifyingKey::from_sec1_bytes(point),
                p384::ecdsa::Signature::from_slice(&[r, s].concat()),
            ) else {
                return false;
            };
            k.verify(data, &sig).is_ok()
        }
        ("ecdsa-sha2-nistp521", "ecdsa-sha2-nistp521") => {
            let Some((point, r, s)) = ecdsa_parts(r, EcdsaCurve::P521, body, 66) else {
                return false;
            };
            use p521::ecdsa::signature::Verifier;
            let (Ok(k), Ok(sig)) = (
                p521::ecdsa::VerifyingKey::from_sec1_bytes(point),
                p521::ecdsa::Signature::from_slice(&[r, s].concat()),
            ) else {
                return false;
            };
            k.verify(data, &sig).is_ok()
        }
        ("ssh-rsa", "ssh-rsa" | "rsa-sha2-256" | "rsa-sha2-512") => {
            verify_rsa(r, signing, body, data)
        }
        _ => false,
    }
}

fn verify_ed25519(mut r: Reader<'_>, body: &[u8], data: &[u8]) -> bool {
    let parsed = (|| {
        let key: [u8; 32] = r.string().ok()?.try_into().ok()?;
        r.finish().ok()?;
        let sig: [u8; 64] = body.try_into().ok()?;
        Some((key, sig))
    })();
    let Some((key, sig)) = parsed else {
        return false;
    };
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&key) else {
        return false;
    };
    key.verify_strict(data, &ed25519_dalek::Signature::from_bytes(&sig))
        .is_ok()
}

/// Verifies a DSA signature over the SHA-1 of `data`: `r || s`, 20 bytes each (RFC 4253 §6.6).
fn verify_dsa(mut r: Reader<'_>, body: &[u8], data: &[u8]) -> bool {
    use dsa::signature::hazmat::PrehashVerifier;
    use sha1::Digest;
    let uint = |m: &Mpint, bits| dsa::BoxedUint::from_be_slice(&m.magnitude, bits).ok();
    let key = (|| {
        let (p, q, g, y) = dsa_fields(&mut r)?;
        r.finish().ok()?;
        if q.negative {
            return None;
        }
        let components = dsa::Components::from_components(
            uint(&p, DSA_P_BITS as u32)?,
            uint(&q, DSA_Q_BITS as u32)?,
            uint(&g, DSA_P_BITS as u32)?,
        )
        .ok()?;
        dsa::VerifyingKey::from_components(components, uint(&y, DSA_P_BITS as u32)?).ok()
    })();
    let Some(key) = key else {
        return false;
    };
    if body.len() != 40 {
        return false;
    }
    let (rr, ss) = body.split_at(20);
    let (Ok(rr), Ok(ss)) = (
        dsa::BoxedUint::from_be_slice(rr, DSA_Q_BITS as u32),
        dsa::BoxedUint::from_be_slice(ss, DSA_Q_BITS as u32),
    ) else {
        return false;
    };
    let Some(signature) = dsa::Signature::from_components(rr, ss) else {
        return false;
    };
    key.verify_prehash(&sha1::Sha1::digest(data), &signature)
        .is_ok()
}

/// An ECDSA key blob's point after its type, checked to name `curve`, and the signature's `r`
/// and `s` as `size`-byte big-endian integers.
fn ecdsa_parts<'a>(
    mut r: Reader<'a>,
    curve: EcdsaCurve,
    body: &[u8],
    size: usize,
) -> Option<(&'a [u8], Vec<u8>, Vec<u8>)> {
    if r.utf8().ok()? != curve.name() {
        return None;
    }
    let point = r.string().ok()?;
    r.finish().ok()?;
    let mut sig = Reader::new(body);
    let rr = fixed(positive_mpint(&mut sig)?, size)?;
    let ss = fixed(positive_mpint(&mut sig)?, size)?;
    sig.finish().ok()?;
    Some((point, rr, ss))
}

fn verify_rsa(mut r: Reader<'_>, algorithm: &str, body: &[u8], data: &[u8]) -> bool {
    use rsa::signature::Verifier;
    let parsed = (|| {
        let e = positive_mpint(&mut r)?;
        let n = positive_mpint(&mut r)?;
        r.finish().ok()?;
        Some((e, n))
    })();
    let Some((e, n)) = parsed else {
        return false;
    };
    let (e, n) = (
        rsa::BigUint::from_bytes_be(e),
        rsa::BigUint::from_bytes_be(n),
    );
    if e.bits() > MAX_RSA_EXPONENT_BITS || n.bits() < MIN_RSA_BITS {
        return false;
    }
    let Ok(key) = rsa::RsaPublicKey::new_with_max_size(n, e, MAX_RSA_BITS) else {
        return false;
    };
    let Some(padded) = fixed(body, rsa::traits::PublicKeyParts::size(&key)) else {
        return false;
    };
    let Ok(sig) = rsa::pkcs1v15::Signature::try_from(padded.as_slice()) else {
        return false;
    };
    match algorithm {
        "rsa-sha2-256" => rsa::pkcs1v15::VerifyingKey::<rsa_sha2::Sha256>::new(key)
            .verify(data, &sig)
            .is_ok(),
        "rsa-sha2-512" => rsa::pkcs1v15::VerifyingKey::<rsa_sha2::Sha512>::new(key)
            .verify(data, &sig)
            .is_ok(),
        _ => rsa::pkcs1v15::VerifyingKey::<rsa_sha1::Sha1>::new(key)
            .verify(data, &sig)
            .is_ok(),
    }
}

/// A non-negative `mpint`'s big-endian magnitude, leading zero bytes removed.
fn positive_mpint<'a>(r: &mut Reader<'a>) -> Option<&'a [u8]> {
    let v = r.string().ok()?;
    if v.first().is_some_and(|&b| b & 0x80 != 0) {
        return None;
    }
    Some(&v[v.iter().position(|&b| b != 0).unwrap_or(v.len())..])
}

/// `magnitude` left-padded to `size` bytes, or `None` if it is longer.
fn fixed(magnitude: &[u8], size: usize) -> Option<Vec<u8>> {
    let mut out = vec![0u8; size.checked_sub(magnitude.len())?];
    out.extend_from_slice(magnitude);
    Some(out)
}

/// The certificate type of key type `key_type`.
fn certificate_type(key_type: &str) -> &'static str {
    match key_type {
        "ssh-rsa" => "ssh-rsa-cert-v01@openssh.com",
        "ssh-ed25519" => "ssh-ed25519-cert-v01@openssh.com",
        "ecdsa-sha2-nistp256" => "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        "ecdsa-sha2-nistp384" => "ecdsa-sha2-nistp384-cert-v01@openssh.com",
        _ => "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    }
}

/// The signature algorithm under public key algorithm `algorithm`: the algorithm without its
/// certificate suffix.
fn underlying(algorithm: &str) -> &str {
    match algorithm {
        "ssh-rsa-cert-v01@openssh.com" => "ssh-rsa",
        "rsa-sha2-256-cert-v01@openssh.com" => "rsa-sha2-256",
        "rsa-sha2-512-cert-v01@openssh.com" => "rsa-sha2-512",
        a => a.strip_suffix(CERTIFICATE_SUFFIX).unwrap_or(a),
    }
}

/// The fields of a public key blob after its type string.
fn public_fields(blob: &[u8]) -> Vec<u8> {
    let mut r = Reader::new(blob);
    r.string().expect("a key blob starts with its type");
    r.remaining().to_vec()
}

/// The key fields of a certificate of key type `key_type`, `r` being just after the certificate's
/// format: the rest of the certificate is read as [`certificate_rest`] reads it.
fn certified_fields<'a>(r: &mut Reader<'a>, key_type: &str) -> Option<&'a [u8]> {
    let count = match key_type {
        "ssh-ed25519" => 1,
        "ssh-rsa" | "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => 2,
        "ssh-dss" => 4,
        _ => return None,
    };
    r.string().ok()?;
    let start = r.remaining();
    for _ in 0..count {
        r.string().ok()?;
    }
    let fields = &start[..start.len() - r.remaining().len()];
    certificate_rest(r)?;
    Some(fields)
}

/// The fields of a certificate after its key, read as x/crypto/ssh's `parseCert` reads them:
/// serial, type, key id, principals, validity, critical options, extensions, reserved, the
/// signature key and the signature, with nothing after. The signature is not verified.
fn certificate_rest(r: &mut Reader<'_>) -> Option<()> {
    r.bytes(8).ok()?;
    r.u32().ok()?;
    r.string().ok()?;
    let mut principals = Reader::new(r.string().ok()?);
    while !principals.remaining().is_empty() {
        principals.string().ok()?;
    }
    r.bytes(16).ok()?;
    options(r.string().ok()?)?;
    options(r.string().ok()?)?;
    r.string().ok()?;
    signature_key(r.string().ok()?)?;
    let mut signature = Reader::new(r.string().ok()?);
    let format = signature.string().ok()?;
    signature.string().ok()?;
    let security_key = matches!(
        format,
        b"sk-ecdsa-sha2-nistp256@openssh.com"
            | b"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"
            | b"sk-ssh-ed25519@openssh.com"
            | b"sk-ssh-ed25519-cert-v01@openssh.com"
    );
    if !security_key {
        signature.finish().ok()?;
    }
    r.finish().ok()
}

/// Critical options or extensions: names in strictly increasing order, each with data that is
/// empty or one string.
fn options(data: &[u8]) -> Option<()> {
    let mut r = Reader::new(data);
    let mut last: Option<&[u8]> = None;
    while !r.remaining().is_empty() {
        let name = r.string().ok()?;
        if last.is_some_and(|l| name <= l) {
            return None;
        }
        last = Some(name);
        let value = r.string().ok()?;
        if !value.is_empty() {
            let mut v = Reader::new(value);
            v.string().ok()?;
            v.finish().ok()?;
        }
    }
    Some(())
}

/// A certificate's signature key, which must be a public key x/crypto/ssh reads and not itself
/// a certificate, with nothing after it.
fn signature_key(blob: &[u8]) -> Option<()> {
    let mut r = Reader::new(blob);
    match r.string().ok()? {
        b"ssh-ed25519" => {
            (r.string().ok()?.len() == 32).then_some(())?;
        }
        b"sk-ssh-ed25519@openssh.com" => {
            (r.string().ok()?.len() == 32).then_some(())?;
            r.string().ok()?;
        }
        b"ssh-rsa" => {
            let e = Mpint::read(&mut r)?;
            let n = Mpint::read(&mut r)?;
            let exponent = &e.magnitude;
            let small = exponent.len() <= 3 && !e.negative;
            let value = exponent.iter().fold(0u32, |v, &b| v << 8 | u32::from(b));
            if !small || value < 3 || value & 1 == 0 || n.bits() > 16384 {
                return None;
            }
        }
        b"ssh-dss" => {
            dsa_fields(&mut r)?;
        }
        name @ (b"ecdsa-sha2-nistp256" | b"ecdsa-sha2-nistp384" | b"ecdsa-sha2-nistp521") => {
            let curve = &name[b"ecdsa-sha2-".len()..];
            (r.string().ok()? == curve).then_some(())?;
            curve_point(curve, r.string().ok()?)?;
        }
        b"sk-ecdsa-sha2-nistp256@openssh.com" => {
            (r.string().ok()? == b"nistp256").then_some(())?;
            curve_point(b"nistp256", r.string().ok()?)?;
            r.string().ok()?;
        }
        _ => return None,
    }
    r.finish().ok()
}

/// A DSA key's `p`, `q`, `g` and `y`, of the sizes and ranges x/crypto/ssh's `parseDSA` takes. It
/// takes a negative `q` here, and such a key verifies nothing.
fn dsa_fields(r: &mut Reader<'_>) -> Option<(Mpint, Mpint, Mpint, Mpint)> {
    let (p, q, g, y) = (
        Mpint::read(r)?,
        Mpint::read(r)?,
        Mpint::read(r)?,
        Mpint::read(r)?,
    );
    let in_group = |x: &Mpint| !x.negative && x.bits() > 0 && x.below(&p);
    let sized = !p.negative && p.bits() == DSA_P_BITS && q.bits() == DSA_Q_BITS;
    (sized && in_group(&g) && in_group(&y)).then_some((p, q, g, y))
}

/// An uncompressed point on `curve`, as Go's `elliptic.Unmarshal` takes it.
fn curve_point(curve: &[u8], point: &[u8]) -> Option<()> {
    let ok = match curve {
        b"nistp256" => point.len() == 65 && p256::PublicKey::from_sec1_bytes(point).is_ok(),
        b"nistp384" => point.len() == 97 && p384::PublicKey::from_sec1_bytes(point).is_ok(),
        b"nistp521" => point.len() == 133 && p521::PublicKey::from_sec1_bytes(point).is_ok(),
        _ => false,
    };
    (ok && point[0] == 4).then_some(())
}

/// An `mpint` as x/crypto/ssh reads one: a sign from its top bit, and its magnitude, the two's
/// complement taken back for a negative number.
struct Mpint {
    negative: bool,
    magnitude: Vec<u8>,
}

impl Mpint {
    fn read(r: &mut Reader<'_>) -> Option<Self> {
        let bytes = r.string().ok()?;
        let negative = bytes.first().is_some_and(|b| b & 0x80 != 0);
        let mut magnitude = bytes.to_vec();
        if negative {
            magnitude.iter_mut().for_each(|b| *b = !*b);
            for b in magnitude.iter_mut().rev() {
                *b = b.wrapping_add(1);
                if *b != 0 {
                    break;
                }
            }
        }
        let start = magnitude
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(magnitude.len());
        magnitude.drain(..start);
        Some(Mpint {
            negative,
            magnitude,
        })
    }

    fn bits(&self) -> usize {
        let m = &self.magnitude;
        m.len() * 8 - m.first().map_or(0, |b| b.leading_zeros() as usize)
    }

    fn below(&self, other: &Mpint) -> bool {
        let (a, b) = (&self.magnitude, &other.magnitude);
        (a.len(), a) < (b.len(), b)
    }
}

/// An ECDSA signature's `mpint r || mpint s` (RFC 5656 §3.1.2).
fn ecdsa_rs(r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.mpint_unsigned(r).mpint_unsigned(s);
    w.into_bytes()
}

/// A secret big-endian integer, reversed in a zeroizing buffer so that no plain copy is left.
fn secret_uint(be: &[u8]) -> rsa::BigUint {
    let mut le = Zeroizing::new(be.to_vec());
    le.reverse();
    rsa::BigUint::from_bytes_le(&le)
}

/// This crate's generator as the rand_core 0.6 generator rsa 0.9 takes.
struct OldRng<'a>(&'a mut dyn CryptoRng);

impl rsa_rand_core::RngCore for OldRng<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0; 4];
        self.0.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0; 8];
        self.0.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa_rand_core::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl rsa_rand_core::CryptoRng for OldRng<'_> {}

#[cfg(test)]
#[path = "../tests/common/certs.rs"]
mod certs;
#[cfg(test)]
#[path = "../tests/common/test_keys.rs"]
mod test_keys;

#[cfg(test)]
mod tests {
    use rand_core::UnwrapErr;

    use super::*;

    /// A DSA key from Go's `crypto/dsa` and its signature over [`DSA_DATA`].
    const DSA_P: &str = "fdca8374555fdb415eb8ab7ffd047b1d10453a1d40aa9de23ca9f6a37471227b88bb85c5b3d014632c67e92f4ddce3b668a74012f5d95954ebcb98ffadf597cb3b147d528ea9b2765d65db0306938dc629bfeb04b4d3a543255a3aa66bcfbdb4d98f96e7a40df69140204fa73fc69cbd2811939d78fd2f4f6092c29727fc469d";
    const DSA_Q: &str = "9db9dc15d5a5d1db8e3c0caf0e5c3c0a7f1b3abb";
    const DSA_G: &str = "401045f7e7e95ca9e0b5884701d1b4c346612dbedb7a6531e8e0e94cf519a9b7377060bf8d9cd1e4da78d0155f60f7057c91541cd1167da1002067f1edebdeaa753b0ea326fc26766ea5719d140b2d4d0148fb7122d615b9748a495123822e9f0639c7ae929337726ebff5d7a1797512ed5ed256d3e865a1a044894d411b4b88";
    const DSA_Y: &str = "e9acc189d64b6ce57b909bc946409950fa832f862aeeb7ea1dc3e2d5d080ac33f0bd9dc460b20f4f8af7884476679f2d68c0cb91bbc6d004de42e5f72ee1f82fec7718b72b73c600c14b5ea752e510efc20406df178a5dbbae9721ff46143cf2341b8e262a09d22b1f54b213d5708c16545c69b2379865014a635dfcdfdfbd95";
    const DSA_R: &str = "419eb3f2ed68d28ad906c272bb60e7595b03943e";
    const DSA_S: &str = "24bb44a587d9c43a7ae389ffd91ea6b2835236e6";
    const DSA_DATA: &[u8] = b"the exchange hash";

    const DATA: &[u8] = b"some exchange hash";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The fields of a DSA public key blob after its type.
    fn dsa_fields_of(p: &[u8], q: &[u8], g: &[u8], y: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        w.mpint_unsigned(p)
            .mpint_unsigned(q)
            .mpint_unsigned(g)
            .mpint_unsigned(y);
        w.into_bytes()
    }

    fn good_dsa_fields() -> Vec<u8> {
        dsa_fields_of(&hex(DSA_P), &hex(DSA_Q), &hex(DSA_G), &hex(DSA_Y))
    }

    fn dsa_blob(fields: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        w.string(b"ssh-dss").bytes(fields);
        w.into_bytes()
    }

    fn signature_blob(name: &str, body: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        w.string(name.as_bytes()).string(body);
        w.into_bytes()
    }

    fn dsa_signature() -> Vec<u8> {
        signature_blob("ssh-dss", &[hex(DSA_R), hex(DSA_S)].concat())
    }

    /// A host certificate of format `format` for the key whose fields after its type are `fields`.
    fn certificate(format: &str, fields: &[u8]) -> Vec<u8> {
        let mut ca = Writer::new();
        ca.string(b"ssh-ed25519").string(&[8; 32]);
        let mut w = Writer::new();
        w.string(format.as_bytes())
            .string(&[0; 32])
            .bytes(fields)
            .bytes(&[0; 8])
            .u32(2)
            .string(b"host")
            .string(b"")
            .bytes(&[0; 8])
            .bytes(&[0xff; 8])
            .string(b"")
            .string(b"")
            .string(b"")
            .string(&ca.into_bytes())
            .string(&signature_blob("ssh-ed25519", &[1; 64]));
        w.into_bytes()
    }

    fn sign(key: &PrivateKey, algorithm: &str, data: &[u8]) -> Vec<u8> {
        key.sign(algorithm, data, &mut UnwrapErr(getrandom::SysRng))
    }

    fn signature_body(signature: &[u8]) -> Vec<u8> {
        let mut r = Reader::new(signature);
        r.string().unwrap();
        r.string().unwrap().to_vec()
    }

    fn rsa_key() -> PrivateKey {
        PrivateKey::rsa(
            &hex(super::test_keys::RSA_N),
            &hex(super::test_keys::RSA_E),
            Zeroizing::new(hex(super::test_keys::RSA_D)),
            Zeroizing::new(hex(super::test_keys::RSA_P)),
            Zeroizing::new(hex(super::test_keys::RSA_Q)),
        )
        .unwrap()
    }

    fn ed25519_key() -> PrivateKey {
        PrivateKey::ed25519(Zeroizing::new([9; 32]))
    }

    fn ecdsa_key(curve: EcdsaCurve, len: usize) -> PrivateKey {
        PrivateKey::ecdsa(curve, Zeroizing::new(vec![1; len])).unwrap()
    }

    #[test]
    fn a_dsa_signature_from_go_verifies_and_a_changed_one_does_not() {
        let key = dsa_blob(&good_dsa_fields());
        assert!(verify(&key, "ssh-dss", &dsa_signature(), DSA_DATA));
        assert!(!verify(&key, "ssh-dss", &dsa_signature(), b"other data"));
        let mut changed = dsa_signature();
        *changed.last_mut().unwrap() ^= 1;
        assert!(!verify(&key, "ssh-dss", &changed, DSA_DATA));
    }

    #[test]
    fn a_dsa_signature_is_exactly_forty_bytes_named_ssh_dss() {
        let key = dsa_blob(&good_dsa_fields());
        let body = [hex(DSA_R), hex(DSA_S)].concat();
        let long = [&[0][..], &body].concat();
        let s_widened = [&body[..20], &[0], &body[20..]].concat();
        for bad in [&body[..39], &long, &s_widened, &[0; 40]] {
            let signature = signature_blob("ssh-dss", bad);
            assert!(!verify(&key, "ssh-dss", &signature, DSA_DATA));
        }
        let renamed = signature_blob("ssh-rsa", &body);
        assert!(!verify(&key, "ssh-dss", &renamed, DSA_DATA));
        assert!(!verify(&key, "ssh-rsa", &renamed, DSA_DATA));
    }

    #[test]
    fn a_dsa_key_a_hostile_server_can_send_is_refused_without_a_panic() {
        let (p, q, g, y) = (hex(DSA_P), hex(DSA_Q), hex(DSA_G), hex(DSA_Y));
        let mut p_minus_1 = p.clone();
        *p_minus_1.last_mut().unwrap() -= 1;
        let mut even_q = q.clone();
        *even_q.last_mut().unwrap() &= 0xfe;
        let short_p = [&[0x7f][..], &p[1..]].concat();
        let short_q = [&[0x7f][..], &q[1..]].concat();
        let long_p = [p.as_slice(), &p].concat();
        let mut q_negated = vec![0xff];
        q_negated.extend(q.iter().map(|b| !b));
        for b in q_negated.iter_mut().rev() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
        let mut negative_q = Writer::new();
        negative_q.mpint_unsigned(&p).string(&q_negated);
        negative_q.mpint_unsigned(&g).mpint_unsigned(&y);
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("p of 1023 bits", dsa_fields_of(&short_p, &q, &g, &y)),
            ("p of 2048 bits", dsa_fields_of(&long_p, &q, &g, &y)),
            ("even p", dsa_fields_of(&p_minus_1, &q, &g, &y)),
            ("q of 159 bits", dsa_fields_of(&p, &short_q, &g, &y)),
            ("q of 256 bits", dsa_fields_of(&p, &[0x80; 32], &g, &y)),
            ("negative q", negative_q.into_bytes()),
            ("even q", dsa_fields_of(&p, &even_q, &g, &y)),
            (
                "even q, y of order 2",
                dsa_fields_of(&p, &even_q, &g, &p_minus_1),
            ),
            ("zero g", dsa_fields_of(&p, &q, &[], &y)),
            ("g above p", dsa_fields_of(&p, &q, &[0xff; 128], &y)),
            ("zero y", dsa_fields_of(&p, &q, &g, &[])),
            ("y of 1", dsa_fields_of(&p, &q, &g, &[1])),
            ("y above p", dsa_fields_of(&p, &q, &g, &[0xff; 128])),
            ("y outside the group", dsa_fields_of(&p, &q, &g, &[2])),
            ("a byte after y", [good_dsa_fields(), vec![0]].concat()),
        ];
        for (name, fields) in cases {
            assert!(
                !verify(&dsa_blob(&fields), "ssh-dss", &dsa_signature(), DSA_DATA),
                "{name}"
            );
        }
    }

    proptest::proptest! {
        /// `y = p - 1` has order 2 for any odd `p`, so with an even `q` the key is taken and the
        /// verification runs on numbers that are not a DSA group.
        #[test]
        fn dsa_verification_of_numbers_that_are_no_group_ends_without_a_panic(
            p in proptest::collection::vec(proptest::prelude::any::<u8>(), 128),
            q in proptest::collection::vec(proptest::prelude::any::<u8>(), 20),
            g in proptest::collection::vec(proptest::prelude::any::<u8>(), 127),
            body in proptest::collection::vec(proptest::prelude::any::<u8>(), 40),
        ) {
            let mut p = p;
            p[0] |= 0x80;
            p[127] |= 1;
            let mut y = p.clone();
            y[127] &= 0xfe;
            let mut q = q;
            q[0] |= 0x80;
            q[19] &= 0xfe;
            let blob = dsa_blob(&dsa_fields_of(&p, &q, &g, &y));
            verify(&blob, "ssh-dss", &signature_blob("ssh-dss", &body), DATA);
        }
    }

    #[test]
    fn a_certificate_verifies_by_the_key_inside_it_under_each_algorithm() {
        let ed25519 = "ssh-ed25519-cert-v01@openssh.com";
        let p256 = "ecdsa-sha2-nistp256-cert-v01@openssh.com";
        let p384 = "ecdsa-sha2-nistp384-cert-v01@openssh.com";
        let p521 = "ecdsa-sha2-nistp521-cert-v01@openssh.com";
        let rsa = "ssh-rsa-cert-v01@openssh.com";
        for (key, format, algorithm) in [
            (ed25519_key(), ed25519, ed25519),
            (ecdsa_key(EcdsaCurve::P256, 32), p256, p256),
            (ecdsa_key(EcdsaCurve::P384, 48), p384, p384),
            (ecdsa_key(EcdsaCurve::P521, 66), p521, p521),
            (rsa_key(), rsa, "rsa-sha2-256-cert-v01@openssh.com"),
            (rsa_key(), rsa, "rsa-sha2-512-cert-v01@openssh.com"),
            (rsa_key(), rsa, rsa),
        ] {
            let plain = key.plain_public_blob();
            let blob = certificate(format, &public_fields(&plain));
            let signature = sign(&key, algorithm, DATA);
            assert!(verify(&blob, algorithm, &signature, DATA), "{algorithm}");
            assert!(
                !verify(&blob, algorithm, &signature, b"other"),
                "{algorithm}"
            );
            assert!(
                !verify(&blob, underlying(algorithm), &signature, DATA),
                "{algorithm}: a certificate under the plain algorithm"
            );
            assert!(
                !verify(&plain, algorithm, &signature, DATA),
                "{algorithm}: a plain key under the certificate algorithm"
            );
        }
        let dss = "ssh-dss-cert-v01@openssh.com";
        let blob = certificate(dss, &good_dsa_fields());
        assert!(verify(&blob, dss, &dsa_signature(), DSA_DATA));
        assert!(!verify(&blob, dss, &dsa_signature(), b"other"));
    }

    #[test]
    fn a_signature_under_a_certificate_is_named_for_the_negotiated_underlying_algorithm() {
        let key = rsa_key();
        let fields = public_fields(&key.plain_public_blob());
        let blob = certificate("ssh-rsa-cert-v01@openssh.com", &fields);
        let algorithm = "rsa-sha2-256-cert-v01@openssh.com";
        let other_hash = sign(&key, "rsa-sha2-512", DATA);
        assert!(!verify(&blob, algorithm, &other_hash, DATA));
        let body = signature_body(&sign(&key, "rsa-sha2-256", DATA));
        let named_for_the_certificate = signature_blob(algorithm, &body);
        assert!(!verify(&blob, algorithm, &named_for_the_certificate, DATA));
    }

    #[test]
    fn a_certificate_of_another_key_type_than_negotiated_is_refused() {
        let key = ed25519_key();
        let fields = public_fields(&key.plain_public_blob());
        let signature = sign(&key, "ssh-ed25519", DATA);
        let blob = certificate("ssh-ed25519-cert-v01@openssh.com", &fields);
        let other = "ecdsa-sha2-nistp256-cert-v01@openssh.com";
        assert!(!verify(&blob, other, &signature, DATA));
        let unknown = certificate("sk-ssh-ed25519-cert-v01@openssh.com", &fields);
        let algorithm = "ssh-ed25519-cert-v01@openssh.com";
        assert!(!verify(&unknown, algorithm, &signature, DATA));
    }

    #[test]
    fn a_host_certificate_is_read_by_the_rules_of_with_certificate_and_go() {
        let key = ed25519_key();
        let algorithm = "ssh-ed25519-cert-v01@openssh.com";
        let signature = sign(&key, algorithm, DATA);
        for (name, blob, go_takes) in super::certs::variants() {
            assert_eq!(
                verify(&blob, algorithm, &signature, DATA),
                go_takes,
                "{name}"
            );
            assert_eq!(
                ed25519_key().with_certificate(blob).is_ok(),
                go_takes,
                "{name}: with_certificate"
            );
        }
    }
}
