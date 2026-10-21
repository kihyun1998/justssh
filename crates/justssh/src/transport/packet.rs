//! The binary packet protocol (RFC 4253 §6): plaintext, and chacha20-poly1305@openssh.com
//! (draft-ietf-sshm-chacha20-poly1305).

use chacha20::ChaCha20Legacy;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use poly1305::Poly1305;
use poly1305::universal_hash::KeyInit;
use rand_core::CryptoRng;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Largest `packet_length` accepted.
pub(crate) const MAX_PACKET: usize = 256 * 1024;
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

/// How packets in one direction are protected.
pub(crate) enum Cipher {
    Plain,
    ChaCha(ChaChaKeys),
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

fn padding(aligned: usize) -> usize {
    let mut pad = 8 - aligned % 8;
    if pad < 4 {
        pad += 8;
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

impl Cipher {
    /// Takes one packet from the front of `buf`, or `None` until it is all there.
    pub(crate) fn open(&self, buf: &[u8], seq: u32) -> Result<Option<Opened>, OpenError> {
        if buf.len() < 4 {
            return Ok(None);
        }
        match self {
            Cipher::Plain => {
                let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                if !(5..=MAX_PACKET).contains(&len) || !(4 + len).is_multiple_of(8) {
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
                if !(5..=MAX_PACKET).contains(&len) || !len.is_multiple_of(8) {
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
        }
    }

    /// `payload` framed, padded with random bytes and protected for sequence number `seq`.
    pub(crate) fn seal(&self, payload: &[u8], seq: u32, rng: &mut dyn CryptoRng) -> Vec<u8> {
        let pad = match self {
            Cipher::Plain => padding(4 + 1 + payload.len()),
            Cipher::ChaCha(_) => padding(1 + payload.len()),
        };
        let len = u32::try_from(1 + payload.len() + pad).expect("packet longer than u32::MAX");
        let mut p = Vec::with_capacity(4 + len as usize + TAG);
        p.extend_from_slice(&len.to_be_bytes());
        p.push(pad as u8);
        p.extend_from_slice(payload);
        let start = p.len();
        p.resize(start + pad, 0);
        rng.fill_bytes(&mut p[start..]);
        if let Cipher::ChaCha(keys) = self {
            ChaChaKeys::stream(&keys.header, seq, 0).apply_keystream(&mut p[..4]);
            ChaChaKeys::stream(&keys.main, seq, 1).apply_keystream(&mut p[4..]);
            let tag = keys.tag(seq, &p);
            p.extend_from_slice(&tag);
        }
        p
    }
}
