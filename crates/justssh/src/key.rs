//! Client private keys for `publickey` authentication: ed25519, ECDSA over NIST P-256/384/521 and
//! RSA, each optionally with an OpenSSH certificate (`PROTOCOL.certkeys`).

use core::fmt;

use justssh_wire::{Reader, Writer};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

/// The smallest RSA modulus taken, in bits, as OpenSSH's `SSH_RSA_MINIMUM_MODULUS_SIZE`.
const MIN_RSA_BITS: usize = 1024;

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
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KeyError::InvalidKey => "invalid private key",
            KeyError::MalformedCertificate => "malformed certificate",
            KeyError::CertificateMismatch => "certificate is for another key",
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
        self.certificate = Some(blob);
        Ok(self)
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
        a => a.strip_suffix("-cert-v01@openssh.com").unwrap_or(a),
    }
}

/// The fields of a public key blob after its type string.
fn public_fields(blob: &[u8]) -> Vec<u8> {
    let mut r = Reader::new(blob);
    r.string().expect("a key blob starts with its type");
    r.remaining().to_vec()
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
