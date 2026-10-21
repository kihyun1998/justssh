//! Algorithm negotiation (RFC 4253 §7.1): for each list, the first of the client's names that
//! the server also lists.

use justssh_wire::KexInit;

use crate::handshake::{AlgorithmCategory, Algorithms};

pub(crate) const STRICT_CLIENT: &str = "kex-strict-c-v00@openssh.com";
pub(crate) const STRICT_SERVER: &str = "kex-strict-s-v00@openssh.com";
pub(crate) const EXT_INFO_CLIENT: &str = "ext-info-c";

/// x/crypto/ssh v0.55's `defaultKexAlgos`, with the alias it adds after `curve25519-sha256`.
pub(crate) const KEX: &[&str] = &[
    "mlkem768x25519-sha256",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group14-sha1",
];
/// x/crypto/ssh v0.55's `defaultHostKeyAlgos` without the certificate and DSA algorithms.
pub(crate) const HOST_KEY: &[&str] = &[
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-256",
    "rsa-sha2-512",
    "ssh-rsa",
    "ssh-ed25519",
];
/// x/crypto/ssh v0.55's `defaultCiphers`.
pub(crate) const CIPHER: &[&str] = &[
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
    "chacha20-poly1305@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
];
/// x/crypto/ssh v0.55's `defaultMACs`.
pub(crate) const MAC: &[&str] = &[
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha1",
    "hmac-sha1-96",
];
pub(crate) const COMPRESSION: &[&str] = &["none"];

fn is_aead(cipher: &str) -> bool {
    matches!(
        cipher,
        "chacha20-poly1305@openssh.com" | "aes128-gcm@openssh.com" | "aes256-gcm@openssh.com"
    )
}

/// The names in `offered` that this crate implements, which leaves out markers such as
/// `kex-strict-*` and `ext-info-*`.
fn implemented(offered: &[String], known: &[&str]) -> Vec<String> {
    offered
        .iter()
        .filter(|n| known.contains(&n.as_str()))
        .cloned()
        .collect()
}

fn first_common(
    client: &[String],
    server: &[String],
    category: AlgorithmCategory,
) -> Result<String, AlgorithmCategory> {
    client
        .iter()
        .find(|c| server.contains(c))
        .cloned()
        .ok_or(category)
}

pub(crate) fn negotiate(
    client: &KexInit,
    server: &KexInit,
) -> Result<Algorithms, AlgorithmCategory> {
    use AlgorithmCategory as C;

    let kex = first_common(
        &client.kex_algorithms,
        &implemented(&server.kex_algorithms, KEX),
        C::Kex,
    )?;
    let host_key = first_common(
        &client.server_host_key_algorithms,
        &server.server_host_key_algorithms,
        C::HostKey,
    )?;
    let cipher_client_to_server = first_common(
        &client.encryption_algorithms_client_to_server,
        &server.encryption_algorithms_client_to_server,
        C::CipherClientToServer,
    )?;
    let cipher_server_to_client = first_common(
        &client.encryption_algorithms_server_to_client,
        &server.encryption_algorithms_server_to_client,
        C::CipherServerToClient,
    )?;
    let mac_client_to_server = if is_aead(&cipher_client_to_server) {
        None
    } else {
        Some(first_common(
            &client.mac_algorithms_client_to_server,
            &server.mac_algorithms_client_to_server,
            C::MacClientToServer,
        )?)
    };
    let mac_server_to_client = if is_aead(&cipher_server_to_client) {
        None
    } else {
        Some(first_common(
            &client.mac_algorithms_server_to_client,
            &server.mac_algorithms_server_to_client,
            C::MacServerToClient,
        )?)
    };
    let compression_client_to_server = first_common(
        &client.compression_algorithms_client_to_server,
        &server.compression_algorithms_client_to_server,
        C::CompressionClientToServer,
    )?;
    let compression_server_to_client = first_common(
        &client.compression_algorithms_server_to_client,
        &server.compression_algorithms_server_to_client,
        C::CompressionServerToClient,
    )?;
    let strict_kex = client.kex_algorithms.iter().any(|a| a == STRICT_CLIENT)
        && server.kex_algorithms.iter().any(|a| a == STRICT_SERVER);

    Ok(Algorithms {
        kex,
        host_key,
        cipher_client_to_server,
        cipher_server_to_client,
        mac_client_to_server,
        mac_server_to_client,
        compression_client_to_server,
        compression_server_to_client,
        strict_kex,
    })
}

/// Whether a key exchange packet sent on the strength of `first_kex_packet_follows` guessed
/// right: both sides prefer the same key exchange and host key algorithm.
pub(crate) fn guessed_right(client: &KexInit, server: &KexInit) -> bool {
    client.kex_algorithms.first() == server.kex_algorithms.first()
        && client.server_host_key_algorithms.first() == server.server_host_key_algorithms.first()
}
