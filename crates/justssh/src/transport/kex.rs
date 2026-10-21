//! Key exchange methods, the exchange hash and key derivation (RFC 4253 §7–8): curve25519-sha256
//! (RFC 8731), ecdh-sha2-nistp* (RFC 5656), diffie-hellman-group14-sha1/-sha256 (RFC 4253,
//! RFC 8268) and mlkem768x25519-sha256 (draft-ietf-sshm-mlkem-hybrid-kex).

use crypto_bigint::modular::{FixedMontyForm, FixedMontyParams};
use crypto_bigint::{Odd, U2048};
use justssh_wire::Writer;
use ml_kem::MlKem768;
use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport, TryKeyInit};
use rand_core::CryptoRng;
use sha2::Digest;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

/// The hash a key exchange method uses for `H` and key derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        self.digest_into(parts, &mut out);
        out
    }

    /// Appends the digest of `parts` to `out`.
    fn digest_into(self, parts: &[&[u8]], out: &mut Vec<u8>) {
        fn run<D: Digest>(parts: &[&[u8]], out: &mut Vec<u8>) {
            let mut d = D::new();
            for p in parts {
                d.update(p);
            }
            out.extend_from_slice(&d.finalize());
        }
        match self {
            Hash::Sha1 => run::<sha1::Sha1>(parts, out),
            Hash::Sha256 => run::<sha2::Sha256>(parts, out),
            Hash::Sha384 => run::<sha2::Sha384>(parts, out),
            Hash::Sha512 => run::<sha2::Sha512>(parts, out),
        }
    }
}

/// A key exchange method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Method {
    MlKem768X25519,
    Curve25519,
    EcdhP256,
    EcdhP384,
    EcdhP521,
    Dh14Sha256,
    Dh14Sha1,
}

impl Method {
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "mlkem768x25519-sha256" => Method::MlKem768X25519,
            "curve25519-sha256" | "curve25519-sha256@libssh.org" => Method::Curve25519,
            "ecdh-sha2-nistp256" => Method::EcdhP256,
            "ecdh-sha2-nistp384" => Method::EcdhP384,
            "ecdh-sha2-nistp521" => Method::EcdhP521,
            "diffie-hellman-group14-sha256" => Method::Dh14Sha256,
            "diffie-hellman-group14-sha1" => Method::Dh14Sha1,
            _ => return None,
        })
    }

    pub(crate) fn hash(self) -> Hash {
        match self {
            Method::Dh14Sha1 => Hash::Sha1,
            Method::EcdhP384 => Hash::Sha384,
            Method::EcdhP521 => Hash::Sha512,
            _ => Hash::Sha256,
        }
    }
}

/// The 2048-bit MODP group's prime (RFC 3526 §3); its generator is 2.
const GROUP14_P: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E",
    "3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF",
    "5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D3",
    "9A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08",
    "CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183",
    "995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
);

fn group14() -> (Odd<U2048>, FixedMontyParams<{ U2048::LIMBS }>) {
    let p = Odd::new(U2048::from_be_hex(GROUP14_P)).expect("an odd prime");
    let params = FixedMontyParams::new_vartime(p);
    (p, params)
}

/// `n`'s big-endian bytes without leading zeros: the body of `mpint n`, whose sign byte the
/// writer adds.
fn magnitude(n: &[u8]) -> &[u8] {
    &n[n.iter().position(|&b| b != 0).unwrap_or(n.len())..]
}

/// `K` as the exchange hash and key derivation take it, given as an mpint magnitude.
fn mpint_k(magnitude: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut w = Writer::new();
    w.mpint_unsigned(magnitude);
    Zeroizing::new(w.into_bytes())
}

/// The canonical `mpint` body of an unsigned big-endian integer, as hashed.
fn mpint_body(n: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.mpint_unsigned(n);
    w.into_bytes()[4..].to_vec()
}

/// A generator behind a reference, as a sized generator.
struct RngRef<'a>(&'a mut dyn CryptoRng);

impl rand_core::TryRng for RngRef<'_> {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.0.next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.0.next_u64())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill_bytes(dst);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for RngRef<'_> {}

/// What a client keeps between sending its public value and receiving the server's.
pub(crate) enum ClientSecret {
    MlKem(Box<<MlKem768 as Kem>::DecapsulationKey>, EphemeralSecret),
    Curve25519(EphemeralSecret),
    P256(p256::ecdh::EphemeralSecret),
    P384(p384::ecdh::EphemeralSecret),
    P521(p521::ecdh::EphemeralSecret),
    Dh(Box<Zeroizing<U2048>>),
}

/// A client's half of a key exchange: its secret and the public value it sends, as hashed.
pub(crate) struct ClientStart {
    pub(crate) secret: ClientSecret,
    pub(crate) public: Vec<u8>,
}

/// Generates a client's secret and public value for `method`.
pub(crate) fn client_start(method: Method, rng: &mut dyn CryptoRng) -> ClientStart {
    match method {
        Method::MlKem768X25519 => {
            let (dk, ek) = MlKem768::generate_keypair_from_rng(&mut RngRef(&mut *rng));
            let x = EphemeralSecret::random_from_rng(&mut *rng);
            let mut public = ek.to_bytes().to_vec();
            public.extend_from_slice(PublicKey::from(&x).as_bytes());
            ClientStart {
                secret: ClientSecret::MlKem(Box::new(dk), x),
                public,
            }
        }
        Method::Curve25519 => {
            let x = EphemeralSecret::random_from_rng(&mut *rng);
            let public = PublicKey::from(&x).as_bytes().to_vec();
            ClientStart {
                secret: ClientSecret::Curve25519(x),
                public,
            }
        }
        Method::EcdhP256 => {
            let s =
                <p256::ecdh::EphemeralSecret as p256::elliptic_curve::Generate>::generate_from_rng(
                    &mut RngRef(&mut *rng),
                );
            let public = s.public_key().to_sec1_bytes().to_vec();
            ClientStart {
                secret: ClientSecret::P256(s),
                public,
            }
        }
        Method::EcdhP384 => {
            let s =
                <p384::ecdh::EphemeralSecret as p384::elliptic_curve::Generate>::generate_from_rng(
                    &mut RngRef(&mut *rng),
                );
            let public = s.public_key().to_sec1_bytes().to_vec();
            ClientStart {
                secret: ClientSecret::P384(s),
                public,
            }
        }
        Method::EcdhP521 => {
            let s =
                <p521::ecdh::EphemeralSecret as p521::elliptic_curve::Generate>::generate_from_rng(
                    &mut RngRef(&mut *rng),
                );
            let public = s.public_key().to_sec1_bytes().to_vec();
            ClientStart {
                secret: ClientSecret::P521(s),
                public,
            }
        }
        Method::Dh14Sha256 | Method::Dh14Sha1 => {
            let (x, e) = dh_pair(rng);
            ClientStart {
                secret: ClientSecret::Dh(Box::new(x)),
                public: mpint_body(&e),
            }
        }
    }
}

/// A random exponent in [2, 2^2047) and `2^x mod p`.
fn dh_pair(rng: &mut dyn CryptoRng) -> (Zeroizing<U2048>, Vec<u8>) {
    let mut bytes = Zeroizing::new([0u8; 256]);
    rng.fill_bytes(&mut *bytes);
    bytes[0] &= 0x7f;
    bytes[255] |= 0x02;
    let x = Zeroizing::new(U2048::from_be_slice(&*bytes));
    let (_, params) = group14();
    let e = FixedMontyForm::new(&U2048::from_u8(2), &params)
        .pow(&*x)
        .retrieve();
    (x, e.to_be_bytes().as_ref().to_vec())
}

/// `peer` read as a group14 public value: a positive integer between 1 and p − 1, exclusive.
fn dh_peer(peer: &[u8]) -> Option<U2048> {
    let body = magnitude(peer);
    if body.len() > 256 || peer.first().is_some_and(|&b| b & 0x80 != 0) {
        return None;
    }
    let mut padded = [0u8; 256];
    padded[256 - body.len()..].copy_from_slice(body);
    let n = U2048::from_be_slice(&padded);
    let (p, _) = group14();
    let p_minus_1 = p.get().wrapping_sub(&U2048::ONE);
    (n > U2048::ONE && n < p_minus_1).then_some(n)
}

fn dh_shared(peer: &U2048, x: &U2048) -> Zeroizing<Vec<u8>> {
    let (_, params) = group14();
    let power = Zeroizing::new(FixedMontyForm::new(peer, &params).pow(x));
    let k = Zeroizing::new(power.retrieve());
    let bytes = Zeroizing::new(k.to_be_bytes().as_ref().to_vec());
    mpint_k(magnitude(&bytes))
}

/// The value a public value is hashed as: a DH public value as its canonical mpint body, any
/// other as sent.
pub(crate) fn hashed_public(method: Method, public: &[u8]) -> Vec<u8> {
    match method {
        Method::Dh14Sha256 | Method::Dh14Sha1 => mpint_body(magnitude(public)),
        _ => public.to_vec(),
    }
}

/// `K` encoded for the exchange hash, from an X25519 output; `None` if it is all zero.
fn x25519_k(shared: &[u8; 32]) -> Option<Zeroizing<Vec<u8>>> {
    (!shared.iter().all(|&b| b == 0)).then(|| mpint_k(magnitude(shared)))
}

/// The mlkem768x25519 `K`: SHA-256 of the ML-KEM and X25519 secrets, as a string.
fn hybrid_k(mlkem: &[u8], x25519: &[u8; 32]) -> Option<Zeroizing<Vec<u8>>> {
    if x25519.iter().all(|&b| b == 0) {
        return None;
    }
    let digest = Zeroizing::new(Hash::Sha256.digest(&[mlkem, x25519]));
    let mut w = Writer::new();
    w.string(&digest);
    Some(Zeroizing::new(w.into_bytes()))
}

const MLKEM_EK: usize = 1184;
const MLKEM_CT: usize = 1088;

/// The client's `K` from its secret and the server's public value, or `None` if the value is
/// invalid.
pub(crate) fn client_finish(secret: ClientSecret, server: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    match secret {
        ClientSecret::MlKem(dk, x) => {
            if server.len() != MLKEM_CT + 32 {
                return None;
            }
            let ct = server[..MLKEM_CT].try_into().ok()?;
            let ss = Zeroizing::new(dk.decapsulate(ct));
            let peer: [u8; 32] = server[MLKEM_CT..].try_into().ok()?;
            let shared = Zeroizing::new(*x.diffie_hellman(&PublicKey::from(peer)).as_bytes());
            hybrid_k(&ss, &shared)
        }
        ClientSecret::Curve25519(x) => {
            let peer: [u8; 32] = server.try_into().ok()?;
            let shared = Zeroizing::new(*x.diffie_hellman(&PublicKey::from(peer)).as_bytes());
            x25519_k(&shared)
        }
        ClientSecret::P256(s) => {
            let peer = p256::PublicKey::from_sec1_bytes(server).ok()?;
            Some(mpint_k(magnitude(
                s.diffie_hellman(&peer).raw_secret_bytes(),
            )))
        }
        ClientSecret::P384(s) => {
            let peer = p384::PublicKey::from_sec1_bytes(server).ok()?;
            Some(mpint_k(magnitude(
                s.diffie_hellman(&peer).raw_secret_bytes(),
            )))
        }
        ClientSecret::P521(s) => {
            let peer = p521::PublicKey::from_sec1_bytes(server).ok()?;
            Some(mpint_k(magnitude(
                s.diffie_hellman(&peer).raw_secret_bytes(),
            )))
        }
        ClientSecret::Dh(x) => Some(dh_shared(&dh_peer(server)?, &x)),
    }
}

/// The server's public value and `K` for the client's public value, or `None` if the client's
/// value is invalid.
pub(crate) fn server_respond(
    method: Method,
    client: &[u8],
    rng: &mut dyn CryptoRng,
) -> Option<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    match method {
        Method::MlKem768X25519 => {
            if client.len() != MLKEM_EK + 32 {
                return None;
            }
            let ek =
                <MlKem768 as Kem>::EncapsulationKey::new_from_slice(&client[..MLKEM_EK]).ok()?;
            let (ct, ss) = ek.encapsulate_with_rng(&mut RngRef(&mut *rng));
            let ss = Zeroizing::new(ss);
            let x = EphemeralSecret::random_from_rng(&mut *rng);
            let public = PublicKey::from(&x);
            let peer: [u8; 32] = client[MLKEM_EK..].try_into().ok()?;
            let shared = Zeroizing::new(*x.diffie_hellman(&PublicKey::from(peer)).as_bytes());
            let mut reply = ct.to_vec();
            reply.extend_from_slice(public.as_bytes());
            Some((reply, hybrid_k(&ss, &shared)?))
        }
        Method::Curve25519 => {
            let peer: [u8; 32] = client.try_into().ok()?;
            let x = EphemeralSecret::random_from_rng(&mut *rng);
            let public = PublicKey::from(&x).as_bytes().to_vec();
            let shared = Zeroizing::new(*x.diffie_hellman(&PublicKey::from(peer)).as_bytes());
            Some((public, x25519_k(&shared)?))
        }
        Method::EcdhP256 | Method::EcdhP384 | Method::EcdhP521 => {
            let start = client_start(method, rng);
            let k = client_finish(start.secret, client)?;
            Some((start.public, k))
        }
        Method::Dh14Sha256 | Method::Dh14Sha1 => {
            let e = dh_peer(client)?;
            let (y, f) = dh_pair(rng);
            Some((mpint_body(&f), dh_shared(&e, &y)))
        }
    }
}

/// The values hashed into `H`, in order.
pub(crate) struct HashInput<'a> {
    pub v_c: &'a [u8],
    pub v_s: &'a [u8],
    pub i_c: &'a [u8],
    pub i_s: &'a [u8],
    pub k_s: &'a [u8],
    pub q_c: &'a [u8],
    pub q_s: &'a [u8],
    /// `K`, already encoded.
    pub k: &'a [u8],
}

pub(crate) fn exchange_hash(hash: Hash, i: &HashInput<'_>) -> Vec<u8> {
    let mut w = Writer::new();
    w.string(i.v_c)
        .string(i.v_s)
        .string(i.i_c)
        .string(i.i_s)
        .string(i.k_s)
        .string(i.q_c)
        .string(i.q_s);
    hash.digest(&[&w.into_bytes(), i.k])
}

/// `len` bytes of key material for `letter` ('A' to 'F'), with `K` already encoded.
pub(crate) fn derive(
    hash: Hash,
    k: &[u8],
    h: &[u8],
    letter: u8,
    session_id: &[u8],
    len: usize,
) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(len + 64));
    hash.digest_into(&[k, h, &[letter], session_id], &mut out);
    while out.len() < len {
        let mut next = Zeroizing::new(Vec::with_capacity(64));
        hash.digest_into(&[k, h, &out], &mut next);
        out.extend_from_slice(&next);
    }
    out.truncate(len);
    out
}
