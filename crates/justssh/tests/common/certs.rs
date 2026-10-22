//! OpenSSH certificates built field by field (`PROTOCOL.certkeys`) for the certificate tests:
//! one well-formed, and variants each breaking or bending one rule x/crypto/ssh's `parseCert`
//! applies.
#![allow(dead_code)]

use justssh::{PrivateKey, Zeroizing};
use justssh_wire::Writer;

/// The key every certificate here certifies.
pub fn certified_key() -> PrivateKey {
    PrivateKey::ed25519(Zeroizing::new([9; 32]))
}

/// The parts of a certificate after the key, each already encoded.
#[derive(Clone)]
pub struct Cert {
    pub cert_type: Vec<u8>,
    pub principals: Vec<u8>,
    pub critical_options: Vec<u8>,
    pub extensions: Vec<u8>,
    pub reserved: Vec<u8>,
    pub signature_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub trailing: Vec<u8>,
}

fn string(s: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.string(s);
    w.into_bytes()
}

fn strings(parts: &[&[u8]]) -> Vec<u8> {
    parts.iter().flat_map(|p| string(p)).collect()
}

/// `name` and `value` pairs as critical options or extensions: a value is empty or one string.
fn tuples(pairs: &[(&[u8], Option<&[u8]>)]) -> Vec<u8> {
    pairs
        .iter()
        .flat_map(|(name, value)| {
            let mut t = string(name);
            t.extend(string(&value.map(string).unwrap_or_default()));
            t
        })
        .collect()
}

/// An `ssh-ed25519` public key blob of `key`.
fn ed25519_blob(key: &[u8]) -> Vec<u8> {
    strings(&[b"ssh-ed25519", key])
}

fn mpint(magnitude: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.mpint_unsigned(magnitude);
    w.into_bytes()
}

impl Cert {
    /// A certificate as `ssh-keygen -s` makes one: principals, the default extensions, an
    /// ed25519 CA.
    pub fn valid() -> Self {
        Cert {
            cert_type: b"ssh-ed25519-cert-v01@openssh.com".to_vec(),
            principals: strings(&[b"justssh", b"alice"]),
            critical_options: tuples(&[
                (b"force-command", Some(b"true")),
                (b"source-address", Some(b"10.0.0.0/8")),
            ]),
            extensions: tuples(&[(b"permit-X11-forwarding", None), (b"permit-pty", None)]),
            reserved: Vec::new(),
            signature_key: ed25519_blob(&[8; 32]),
            signature: strings(&[b"ssh-ed25519", &[1; 64]]),
            trailing: Vec::new(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let key = certified_key().plain_public_blob();
        let mut w = Writer::new();
        w.string(&self.cert_type)
            .string(b"nonce-nonce-nonce-nonce-nonce-no");
        w.bytes(&key[4 + 11..]);
        w.bytes(&7u64.to_be_bytes())
            .u32(1)
            .string(b"key id")
            .string(&self.principals)
            .bytes(&0u64.to_be_bytes())
            .bytes(&u64::MAX.to_be_bytes())
            .string(&self.critical_options)
            .string(&self.extensions)
            .string(&self.reserved)
            .string(&self.signature_key)
            .string(&self.signature)
            .bytes(&self.trailing);
        w.into_bytes()
    }
}

/// Every variant, with whether x/crypto/ssh's `ParsePublicKey` takes it.
pub fn variants() -> Vec<(&'static str, Vec<u8>, bool)> {
    let v = Cert::valid;
    let with = |edit: &dyn Fn(&mut Cert)| {
        let mut c = v();
        edit(&mut c);
        c.encode()
    };
    let rsa_ca = |e: &[u8]| {
        let mut b = string(b"ssh-rsa");
        b.extend(mpint(e));
        b.extend(mpint(&[0xc5; 256]));
        b
    };
    let dsa_ca = |p_bits_top: u8, g: &[u8], y: &[u8]| {
        let mut p = vec![p_bits_top];
        p.extend([0xff; 127]);
        let mut b = string(b"ssh-dss");
        b.extend(mpint(&p));
        b.extend(mpint(&[[0x80].as_slice(), &[1; 19]].concat()));
        b.extend(mpint(g));
        b.extend(mpint(y));
        b
    };
    // A DSA key whose sub-prime is the mpint `q`, given as its raw bytes so that it may be
    // negative, as x/crypto/ssh reads an mpint with its top bit set.
    let dsa_ca_q = |q: &[u8]| {
        let mut p = vec![0x80];
        p.extend([0xff; 127]);
        let mut b = string(b"ssh-dss");
        b.extend(mpint(&p));
        b.extend(string(q));
        b.extend(mpint(&[2]));
        b.extend(mpint(&[3]));
        b
    };
    // An RSA key whose modulus is the mpint `n`, given as its raw bytes.
    let rsa_ca_n = |n: &[u8]| {
        let mut b = string(b"ssh-rsa");
        b.extend(mpint(&[1, 0, 1]));
        b.extend(string(n));
        b
    };
    let ecdsa_ca = |point: &[u8]| {
        let mut b = strings(&[b"ecdsa-sha2-nistp256", b"nistp256"]);
        b.extend(string(point));
        b
    };
    // The P-256 base point, uncompressed.
    let g256: Vec<u8> = [
        &[0x04][..],
        &[
            0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
            0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
            0xd8, 0x98, 0xc2, 0x96,
        ],
        &[
            0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
            0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
            0x37, 0xbf, 0x51, 0xf5,
        ],
    ]
    .concat();
    vec![
        ("valid", v().encode(), true),
        (
            "no principals, options or extensions",
            with(&|c| {
                c.principals.clear();
                c.critical_options.clear();
                c.extensions.clear();
            }),
            true,
        ),
        (
            "a byte after the signature",
            with(&|c| c.trailing = vec![0]),
            false,
        ),
        (
            "principals cut short",
            with(&|c| c.principals.truncate(c.principals.len() - 1)),
            false,
        ),
        (
            "options out of order",
            with(&|c| {
                c.critical_options = tuples(&[(b"source-address", None), (b"force-command", None)])
            }),
            false,
        ),
        (
            "an option twice",
            with(&|c| c.extensions = tuples(&[(b"permit-pty", None), (b"permit-pty", None)])),
            false,
        ),
        (
            "an option value with bytes after its string",
            with(&|c| {
                let mut value = string(b"true");
                value.push(0);
                c.critical_options = [string(b"force-command"), string(&value)].concat();
            }),
            false,
        ),
        (
            "an option value that is not a string",
            with(&|c| c.critical_options = [string(b"force-command"), string(b"ab")].concat()),
            false,
        ),
        (
            "reserved bytes",
            with(&|c| c.reserved = b"future".to_vec()),
            true,
        ),
        (
            "a certificate as the signature key",
            with(&|c| {
                c.signature_key = string(b"ssh-ed25519-cert-v01@openssh.com");
            }),
            false,
        ),
        (
            "an unknown signature key type",
            with(&|c| c.signature_key = string(b"ssh-unknown")),
            false,
        ),
        (
            "a signature key of the wrong length",
            with(&|c| c.signature_key = ed25519_blob(&[8; 31])),
            false,
        ),
        (
            "a signature key with bytes after it",
            with(&|c| c.signature_key.push(0)),
            false,
        ),
        (
            "an RSA signature key",
            with(&|c| c.signature_key = rsa_ca(&[1, 0, 1])),
            true,
        ),
        (
            "an RSA signature key with an even exponent",
            with(&|c| c.signature_key = rsa_ca(&[1, 0, 0])),
            false,
        ),
        (
            "an RSA signature key with a 32-bit exponent",
            with(&|c| c.signature_key = rsa_ca(&[1, 0, 0, 1])),
            false,
        ),
        (
            "an ECDSA signature key",
            with(&|c| c.signature_key = ecdsa_ca(&g256)),
            true,
        ),
        (
            "an ECDSA signature key with a compressed point",
            with(&|c| {
                let mut point = vec![0x03];
                point.extend(&g256[1..33]);
                c.signature_key = ecdsa_ca(&point);
            }),
            false,
        ),
        (
            "an ECDSA signature key off the curve",
            with(&|c| {
                let mut point = g256.clone();
                point[64] ^= 1;
                c.signature_key = ecdsa_ca(&point);
            }),
            false,
        ),
        (
            "an ECDSA signature key naming another curve",
            with(&|c| {
                let mut b = strings(&[b"ecdsa-sha2-nistp256", b"nistp384"]);
                b.extend(string(&g256));
                c.signature_key = b;
            }),
            false,
        ),
        (
            "a DSA signature key",
            with(&|c| c.signature_key = dsa_ca(0x80, &[2], &[3])),
            true,
        ),
        (
            "a DSA signature key of 1023 bits",
            with(&|c| c.signature_key = dsa_ca(0x40, &[2], &[3])),
            false,
        ),
        (
            "a DSA signature key with a zero generator",
            with(&|c| c.signature_key = dsa_ca(0x80, &[], &[3])),
            false,
        ),
        (
            "a DSA signature key with its public value above the modulus",
            with(&|c| c.signature_key = dsa_ca(0x80, &[2], &[0xff; 129][..])),
            false,
        ),
        (
            "a DSA signature key with a negative sub-prime of 159 bits",
            with(&|c| c.signature_key = dsa_ca_q(&[[0xc0].as_slice(), &[0; 19]].concat())),
            false,
        ),
        (
            "a DSA signature key with a negative sub-prime of 160 bits",
            with(&|c| c.signature_key = dsa_ca_q(&[[0xff, 0x80].as_slice(), &[0; 19]].concat())),
            true,
        ),
        (
            "an RSA signature key with a negative modulus",
            with(&|c| c.signature_key = rsa_ca_n(&[0xff; 2049])),
            true,
        ),
        (
            "an RSA signature key with a modulus of 16385 bits",
            with(&|c| c.signature_key = rsa_ca_n(&[[0x01].as_slice(), &[0; 2048]].concat())),
            false,
        ),
        (
            "an empty signature key",
            with(&|c| c.signature_key = Vec::new()),
            false,
        ),
        (
            "a security key ed25519 signature key",
            with(&|c| {
                c.signature_key = strings(&[b"sk-ssh-ed25519@openssh.com", &[8; 32], b"ssh:"]);
                c.signature = [
                    strings(&[b"sk-ssh-ed25519@openssh.com", &[1; 64]]),
                    vec![1, 0, 0, 0, 5],
                ]
                .concat();
            }),
            true,
        ),
        (
            "a security key ECDSA signature key",
            with(&|c| {
                let mut b = strings(&[b"sk-ecdsa-sha2-nistp256@openssh.com", b"nistp256"]);
                b.extend(string(&g256));
                b.extend(string(b"ssh:"));
                c.signature_key = b;
            }),
            true,
        ),
        (
            "a signature with bytes after it",
            with(&|c| c.signature.push(0)),
            false,
        ),
        (
            "a signature cut short",
            with(&|c| c.signature.truncate(10)),
            false,
        ),
    ]
}
