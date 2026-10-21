//! curve25519-sha256 (RFC 8731): exchange hash and key derivation (RFC 4253 §7.2).

use justssh_wire::Writer;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The values hashed into `H`, in order.
pub(crate) struct HashInput<'a> {
    pub v_c: &'a [u8],
    pub v_s: &'a [u8],
    pub i_c: &'a [u8],
    pub i_s: &'a [u8],
    pub k_s: &'a [u8],
    pub q_c: &'a [u8],
    pub q_s: &'a [u8],
    /// The X25519 output, read as a big-endian unsigned integer.
    pub shared: &'a [u8],
}

/// `K` encoded as an mpint.
pub(crate) fn shared_mpint(shared: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut w = Writer::new();
    w.mpint_unsigned(shared);
    Zeroizing::new(w.into_bytes())
}

pub(crate) fn exchange_hash(i: &HashInput<'_>) -> Vec<u8> {
    let mut w = Writer::new();
    w.string(i.v_c)
        .string(i.v_s)
        .string(i.i_c)
        .string(i.i_s)
        .string(i.k_s)
        .string(i.q_c)
        .string(i.q_s);
    let mut h = Sha256::new();
    h.update(w.into_bytes());
    h.update(&*shared_mpint(i.shared));
    h.finalize().to_vec()
}

/// `len` bytes of key material for `letter` ('A' to 'F').
pub(crate) fn derive(
    shared: &[u8],
    h: &[u8],
    letter: u8,
    session_id: &[u8],
    len: usize,
) -> Zeroizing<Vec<u8>> {
    let k = shared_mpint(shared);
    let mut out = Zeroizing::new(
        Sha256::new()
            .chain_update(&*k)
            .chain_update(h)
            .chain_update([letter])
            .chain_update(session_id)
            .finalize()
            .to_vec(),
    );
    while out.len() < len {
        let next = Sha256::new()
            .chain_update(&*k)
            .chain_update(h)
            .chain_update(&*out)
            .finalize();
        out.extend_from_slice(&next);
    }
    out.truncate(len);
    out
}
