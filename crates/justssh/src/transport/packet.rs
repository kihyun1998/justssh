//! The binary packet protocol (RFC 4253 §6): plaintext; chacha20-poly1305@openssh.com
//! (draft-ietf-sshm-chacha20-poly1305); AES-GCM (RFC 5647); and AES-CTR (RFC 4344) with an HMAC,
//! computed over the plaintext (RFC 4253 §6.4) or over the ciphertext (OpenSSH `PROTOCOL` §1.5,
//! `-etm@openssh.com`).

use aes_gcm::aead::AeadInOut;
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce, Tag};
use chacha20::ChaCha20Legacy;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use hmac::Hmac;
use poly1305::Poly1305;
use poly1305::universal_hash::KeyInit;
use rand_core::CryptoRng;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Largest `packet_length` accepted.
pub(crate) const MAX_PACKET: usize = 256 * 1024;
/// Longest MAC or tag after a packet: hmac-sha2-512's.
pub(crate) const MAX_MAC: usize = 64;
const TAG: usize = 16;

/// The key pair of chacha20-poly1305@openssh.com: `main` (K_1) encrypts the packet,
/// `header` (K_2) the length field.
pub(crate) struct ChaChaKeys {
    main: Zeroizing<[u8; 32]>,
    header: Zeroizing<[u8; 32]>,
}

impl ChaChaKeys {
    /// From 64 bytes of derived key material: K_1 first, then K_2.
    pub(crate) fn from_material(material: &[u8]) -> Self {
        let mut main = Zeroizing::new([0u8; 32]);
        let mut header = Zeroizing::new([0u8; 32]);
        main.copy_from_slice(&material[..32]);
        header.copy_from_slice(&material[32..64]);
        ChaChaKeys { main, header }
    }

    fn stream(key: &[u8; 32], seq: u32, block: u64) -> ChaCha20Legacy {
        let nonce = u64::from(seq).to_be_bytes();
        let mut c = ChaCha20Legacy::new(&(*key).into(), &nonce.into());
        c.seek(block * 64);
        c
    }

    fn poly_key(&self, seq: u32) -> Zeroizing<[u8; 32]> {
        let mut k = Zeroizing::new([0u8; 32]);
        Self::stream(&self.main, seq, 0).apply_keystream(&mut *k);
        k
    }

    fn tag(&self, seq: u32, data: &[u8]) -> [u8; TAG] {
        let key = self.poly_key(seq);
        Poly1305::new(&(*key).into()).compute_unpadded(data).into()
    }
}

/// An AES-GCM key and its nonce: a fixed field and an invocation counter (RFC 5647 §7.1).
pub(crate) struct Gcm {
    aead: GcmAead,
    nonce: [u8; 12],
}

enum GcmAead {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
}

impl Gcm {
    fn seal(&mut self, aad: &[u8], body: &mut [u8]) -> Tag {
        let nonce = Nonce::from(self.nonce);
        let tag = match &self.aead {
            GcmAead::Aes128(a) => a.encrypt_inout_detached(&nonce, aad, body.into()),
            GcmAead::Aes256(a) => a.encrypt_inout_detached(&nonce, aad, body.into()),
        }
        .expect("a packet is shorter than AES-GCM's limit");
        self.advance();
        tag
    }

    fn open(&mut self, aad: &[u8], body: &mut [u8], tag: &[u8]) -> bool {
        let nonce = Nonce::from(self.nonce);
        let tag = Tag::try_from(tag).expect("16-byte tag");
        let ok = match &self.aead {
            GcmAead::Aes128(a) => a.decrypt_inout_detached(&nonce, aad, body.into(), &tag),
            GcmAead::Aes256(a) => a.decrypt_inout_detached(&nonce, aad, body.into(), &tag),
        }
        .is_ok();
        self.advance();
        ok
    }

    fn advance(&mut self) {
        let counter = u64::from_be_bytes(self.nonce[4..].try_into().expect("8 bytes"));
        self.nonce[4..].copy_from_slice(&counter.wrapping_add(1).to_be_bytes());
    }
}

/// An AES-CTR key stream, continuing across packets.
enum CtrStream {
    Aes128(Box<ctr::Ctr128BE<aes::Aes128>>),
    Aes192(Box<ctr::Ctr128BE<aes::Aes192>>),
    Aes256(Box<ctr::Ctr128BE<aes::Aes256>>),
}

impl CtrStream {
    fn apply(&mut self, buf: &mut [u8]) {
        match self {
            CtrStream::Aes128(c) => c.apply_keystream(buf),
            CtrStream::Aes192(c) => c.apply_keystream(buf),
            CtrStream::Aes256(c) => c.apply_keystream(buf),
        }
    }

    /// `buf` decrypted at the current position, without moving it.
    fn peek(&mut self, buf: &mut [u8]) {
        let pos: u64 = match self {
            CtrStream::Aes128(c) => c.current_pos(),
            CtrStream::Aes192(c) => c.current_pos(),
            CtrStream::Aes256(c) => c.current_pos(),
        };
        self.apply(buf);
        match self {
            CtrStream::Aes128(c) => c.seek(pos),
            CtrStream::Aes192(c) => c.seek(pos),
            CtrStream::Aes256(c) => c.seek(pos),
        }
    }
}

/// A keyed HMAC, its output length and whether it covers the ciphertext (`-etm`) rather than
/// the plaintext.
pub(crate) struct Mac {
    keyed: Keyed,
    len: usize,
    etm: bool,
}

enum Keyed {
    Sha256(Box<Hmac<sha2::Sha256>>),
    Sha512(Box<Hmac<sha2::Sha512>>),
    Sha1(Box<Hmac<sha1::Sha1>>),
}

impl Mac {
    fn new(name: &str, key: &[u8]) -> Self {
        fn keyed<M: hmac::KeyInit>(key: &[u8]) -> Box<M> {
            Box::new(M::new_from_slice(key).expect("HMAC takes any key"))
        }
        let (keyed, len) = match name {
            m if m.starts_with("hmac-sha2-256") => (Keyed::Sha256(keyed(key)), 32),
            m if m.starts_with("hmac-sha2-512") => (Keyed::Sha512(keyed(key)), 64),
            "hmac-sha1-96" => (Keyed::Sha1(keyed(key)), 12),
            _ => (Keyed::Sha1(keyed(key)), 20),
        };
        Mac {
            keyed,
            len,
            etm: name.ends_with("-etm@openssh.com"),
        }
    }

    /// The MAC of `data` for sequence number `seq`.
    fn compute(&self, seq: u32, data: &[u8]) -> Vec<u8> {
        fn run<M: hmac::Mac + Clone>(keyed: &M, seq: u32, data: &[u8]) -> Vec<u8> {
            let mut m = keyed.clone();
            m.update(&seq.to_be_bytes());
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
        let mut out = match &self.keyed {
            Keyed::Sha256(m) => run(&**m, seq, data),
            Keyed::Sha512(m) => run(&**m, seq, data),
            Keyed::Sha1(m) => run(&**m, seq, data),
        };
        out.truncate(self.len);
        out
    }

    fn verify(&self, seq: u32, data: &[u8], mac: &[u8]) -> bool {
        bool::from(self.compute(seq, data).ct_eq(mac))
    }
}

/// AES-CTR with its MAC.
pub(crate) struct Ctr {
    stream: CtrStream,
    mac: Mac,
}

/// How packets in one direction are protected.
pub(crate) enum Cipher {
    Plain,
    ChaCha(ChaChaKeys),
    Gcm(Gcm),
    Ctr(Ctr),
}

/// The sizes of a cipher's key and IV, and of a MAC's key.
pub(crate) struct KeySizes {
    pub(crate) key: usize,
    pub(crate) iv: usize,
    pub(crate) mac: usize,
}

/// The key material sizes for `cipher` with `mac`, which is `None` for an AEAD cipher.
pub(crate) fn key_sizes(cipher: &str, mac: Option<&str>) -> KeySizes {
    let (key, iv) = match cipher {
        "chacha20-poly1305@openssh.com" => (64, 0),
        "aes128-gcm@openssh.com" => (16, 12),
        "aes256-gcm@openssh.com" => (32, 12),
        "aes128-ctr" => (16, 16),
        "aes192-ctr" => (24, 16),
        _ => (32, 16),
    };
    let mac = match mac {
        Some(m) if m.starts_with("hmac-sha2-256") => 32,
        Some(m) if m.starts_with("hmac-sha2-512") => 64,
        Some(_) => 20,
        None => 0,
    };
    KeySizes { key, iv, mac }
}

impl Cipher {
    /// The protection for `cipher` with `mac`, from derived key material of [`key_sizes`].
    pub(crate) fn new(
        cipher: &str,
        mac: Option<&str>,
        key: &[u8],
        iv: &[u8],
        mac_key: &[u8],
    ) -> Self {
        match cipher {
            "chacha20-poly1305@openssh.com" => Cipher::ChaCha(ChaChaKeys::from_material(key)),
            "aes128-gcm@openssh.com" | "aes256-gcm@openssh.com" => {
                let aead = if key.len() == 16 {
                    GcmAead::Aes128(Box::new(Aes128Gcm::new_from_slice(key).expect("16 bytes")))
                } else {
                    GcmAead::Aes256(Box::new(Aes256Gcm::new_from_slice(key).expect("32 bytes")))
                };
                Cipher::Gcm(Gcm {
                    aead,
                    nonce: iv.try_into().expect("12-byte nonce"),
                })
            }
            _ => {
                let stream = match key.len() {
                    16 => CtrStream::Aes128(Box::new(
                        ctr::Ctr128BE::new_from_slices(key, iv).expect("key and IV"),
                    )),
                    24 => CtrStream::Aes192(Box::new(
                        ctr::Ctr128BE::new_from_slices(key, iv).expect("key and IV"),
                    )),
                    _ => CtrStream::Aes256(Box::new(
                        ctr::Ctr128BE::new_from_slices(key, iv).expect("key and IV"),
                    )),
                };
                let mac = mac.expect("a CTR cipher comes with a MAC");
                Cipher::Ctr(Ctr {
                    stream,
                    mac: Mac::new(mac, mac_key),
                })
            }
        }
    }

    /// The block size padding aligns to, and whether the length field counts towards it.
    fn alignment(&self) -> (usize, bool) {
        match self {
            Cipher::Plain => (8, true),
            Cipher::ChaCha(_) => (8, false),
            Cipher::Gcm(_) => (16, false),
            Cipher::Ctr(c) => (16, !c.mac.etm),
        }
    }
}

pub(crate) enum OpenError {
    Malformed,
    Mac,
}

/// A received packet's payload and how many buffered bytes it used.
pub(crate) struct Opened {
    pub payload: Zeroizing<Vec<u8>>,
    pub used: usize,
}

fn padding(aligned: usize, block: usize) -> usize {
    let mut pad = block - aligned % block;
    if pad < 4 {
        pad += block;
    }
    pad
}

/// The payload inside `packet_length` bytes of decrypted `padding_length || payload || padding`.
fn unpad(body: &[u8]) -> Result<Zeroizing<Vec<u8>>, OpenError> {
    let pad = usize::from(body[0]);
    if pad < 4 || pad + 1 >= body.len() {
        return Err(OpenError::Malformed);
    }
    Ok(Zeroizing::new(body[1..body.len() - pad].to_vec()))
}

/// A `packet_length` that is in range and whose packet aligns to `block`, counting the length
/// field itself when `with_length`.
fn length_ok(len: usize, block: usize, with_length: bool) -> bool {
    let aligned = if with_length { 4 + len } else { len };
    (5..=MAX_PACKET).contains(&len) && aligned.is_multiple_of(block)
}

impl Cipher {
    /// Takes one packet from the front of `buf`, or `None` until it is all there.
    pub(crate) fn open(&mut self, buf: &[u8], seq: u32) -> Result<Option<Opened>, OpenError> {
        if buf.len() < 4 {
            return Ok(None);
        }
        let (block, with_length) = self.alignment();
        match self {
            Cipher::Plain => {
                let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                if !length_ok(len, block, with_length) {
                    return Err(OpenError::Malformed);
                }
                if buf.len() < 4 + len {
                    return Ok(None);
                }
                Ok(Some(Opened {
                    payload: unpad(&buf[4..4 + len])?,
                    used: 4 + len,
                }))
            }
            Cipher::ChaCha(keys) => {
                let mut len_bytes = [buf[0], buf[1], buf[2], buf[3]];
                ChaChaKeys::stream(&keys.header, seq, 0).apply_keystream(&mut len_bytes);
                let len = u32::from_be_bytes(len_bytes) as usize;
                if !length_ok(len, block, with_length) {
                    return Err(OpenError::Malformed);
                }
                if buf.len() < 4 + len + TAG {
                    return Ok(None);
                }
                let expected = keys.tag(seq, &buf[..4 + len]);
                if !bool::from(expected.ct_eq(&buf[4 + len..4 + len + TAG])) {
                    return Err(OpenError::Mac);
                }
                let mut body = Zeroizing::new(buf[4..4 + len].to_vec());
                ChaChaKeys::stream(&keys.main, seq, 1).apply_keystream(&mut body);
                Ok(Some(Opened {
                    payload: unpad(&body)?,
                    used: 4 + len + TAG,
                }))
            }
            Cipher::Gcm(gcm) => {
                let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                if !length_ok(len, block, with_length) {
                    return Err(OpenError::Malformed);
                }
                if buf.len() < 4 + len + TAG {
                    return Ok(None);
                }
                let mut body = Zeroizing::new(buf[4..4 + len].to_vec());
                if !gcm.open(&buf[..4], &mut body, &buf[4 + len..4 + len + TAG]) {
                    return Err(OpenError::Mac);
                }
                Ok(Some(Opened {
                    payload: unpad(&body)?,
                    used: 4 + len + TAG,
                }))
            }
            Cipher::Ctr(ctr) if ctr.mac.etm => {
                let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                if !length_ok(len, block, with_length) {
                    return Err(OpenError::Malformed);
                }
                let mac_len = ctr.mac.len;
                if buf.len() < 4 + len + mac_len {
                    return Ok(None);
                }
                if !ctr
                    .mac
                    .verify(seq, &buf[..4 + len], &buf[4 + len..4 + len + mac_len])
                {
                    return Err(OpenError::Mac);
                }
                let mut body = Zeroizing::new(buf[4..4 + len].to_vec());
                ctr.stream.apply(&mut body);
                Ok(Some(Opened {
                    payload: unpad(&body)?,
                    used: 4 + len + mac_len,
                }))
            }
            Cipher::Ctr(ctr) => {
                if buf.len() < 16 {
                    return Ok(None);
                }
                let mut first = Zeroizing::new([0u8; 16]);
                first.copy_from_slice(&buf[..16]);
                ctr.stream.peek(&mut *first);
                let len = u32::from_be_bytes([first[0], first[1], first[2], first[3]]) as usize;
                if !length_ok(len, block, with_length) {
                    return Err(OpenError::Malformed);
                }
                let mac_len = ctr.mac.len;
                if buf.len() < 4 + len + mac_len {
                    return Ok(None);
                }
                let mut packet = Zeroizing::new(buf[..4 + len].to_vec());
                ctr.stream.apply(&mut packet);
                if !ctr
                    .mac
                    .verify(seq, &packet, &buf[4 + len..4 + len + mac_len])
                {
                    return Err(OpenError::Mac);
                }
                Ok(Some(Opened {
                    payload: unpad(&packet[4..])?,
                    used: 4 + len + mac_len,
                }))
            }
        }
    }

    /// `payload` framed, padded with random bytes and protected for sequence number `seq`.
    pub(crate) fn seal(&mut self, payload: &[u8], seq: u32, rng: &mut dyn CryptoRng) -> Vec<u8> {
        let (block, with_length) = self.alignment();
        let framed = 1 + payload.len() + if with_length { 4 } else { 0 };
        let pad = padding(framed, block);
        let len = u32::try_from(1 + payload.len() + pad).expect("packet longer than u32::MAX");
        let mut p = Vec::with_capacity(4 + len as usize + 64);
        p.extend_from_slice(&len.to_be_bytes());
        p.push(pad as u8);
        p.extend_from_slice(payload);
        let start = p.len();
        p.resize(start + pad, 0);
        rng.fill_bytes(&mut p[start..]);
        match self {
            Cipher::Plain => {}
            Cipher::ChaCha(keys) => {
                ChaChaKeys::stream(&keys.header, seq, 0).apply_keystream(&mut p[..4]);
                ChaChaKeys::stream(&keys.main, seq, 1).apply_keystream(&mut p[4..]);
                let tag = keys.tag(seq, &p);
                p.extend_from_slice(&tag);
            }
            Cipher::Gcm(gcm) => {
                let (head, body) = p.split_at_mut(4);
                let tag = gcm.seal(head, body);
                p.extend_from_slice(&tag);
            }
            Cipher::Ctr(ctr) if ctr.mac.etm => {
                ctr.stream.apply(&mut p[4..]);
                let mac = ctr.mac.compute(seq, &p);
                p.extend_from_slice(&mac);
            }
            Cipher::Ctr(ctr) => {
                let mac = ctr.mac.compute(seq, &p);
                ctr.stream.apply(&mut p);
                p.extend_from_slice(&mac);
            }
        }
        p
    }
}
