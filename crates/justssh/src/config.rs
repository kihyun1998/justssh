//! Server and client configuration.

use core::fmt;
use core::num::NonZeroU32;

use ed25519_dalek::Signer;
use justssh_wire::Writer;
use rand_core::{CryptoRng, UnwrapErr};
use zeroize::Zeroizing;

pub(crate) type BoxRng = Box<dyn CryptoRng + Send>;

fn system_rng() -> BoxRng {
    Box::new(UnwrapErr(getrandom::SysRng))
}

/// A server host key.
#[derive(Clone)]
pub struct HostKey {
    key: ed25519_dalek::SigningKey,
}

impl HostKey {
    /// An `ssh-ed25519` host key from its 32-byte secret seed.
    pub fn ed25519_from_seed(seed: Zeroizing<[u8; 32]>) -> Self {
        HostKey {
            key: ed25519_dalek::SigningKey::from_bytes(&seed),
        }
    }

    pub(crate) fn algorithm(&self) -> &'static str {
        "ssh-ed25519"
    }

    /// The public key blob `K_S` (RFC 8709 §4).
    pub(crate) fn public_blob(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.string(self.algorithm().as_bytes())
            .string(&self.key.verifying_key().to_bytes());
        w.into_bytes()
    }

    /// The signature blob over `data` (RFC 8709 §6).
    pub(crate) fn sign(&self, data: &[u8]) -> Vec<u8> {
        let sig = self.key.sign(data);
        let mut w = Writer::new();
        w.string(self.algorithm().as_bytes())
            .string(&sig.to_bytes());
        w.into_bytes()
    }
}

impl fmt::Debug for HostKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostKey")
            .field("algorithm", &self.algorithm())
            .finish_non_exhaustive()
    }
}

/// How a [`Server`](crate::Server) runs.
pub struct ServerConfig {
    pub(crate) host_key: HostKey,
    pub(crate) rng: BoxRng,
    pub(crate) version: String,
    pub(crate) max_auth_tries: u32,
    pub(crate) channel_window: u32,
    pub(crate) channel_max_packet: u32,
}

/// x/crypto/ssh's channel window: 64 maximum packets.
pub(crate) const DEFAULT_CHANNEL_WINDOW: u32 = 64 * DEFAULT_CHANNEL_MAX_PACKET;
/// x/crypto/ssh's maximum channel data per packet.
pub(crate) const DEFAULT_CHANNEL_MAX_PACKET: u32 = 1 << 15;
/// The largest maximum packet that still fits the transport's largest packet with room for the
/// message header.
const MAX_CHANNEL_MAX_PACKET: u32 = 256 * 1024 - 64;

impl ServerConfig {
    /// A builder for a server presenting `host_key`.
    pub fn builder(host_key: HostKey) -> ServerConfigBuilder {
        ServerConfigBuilder {
            host_key,
            rng: None,
            version: None,
            max_auth_tries: 6,
            channel_window: DEFAULT_CHANNEL_WINDOW,
            channel_max_packet: DEFAULT_CHANNEL_MAX_PACKET,
        }
    }
}

/// Builds a [`ServerConfig`].
pub struct ServerConfigBuilder {
    host_key: HostKey,
    rng: Option<BoxRng>,
    version: Option<String>,
    max_auth_tries: u32,
    channel_window: u32,
    channel_max_packet: u32,
}

impl ServerConfigBuilder {
    /// The window each accepted channel starts with. Defaults to 2 MiB, as x/crypto/ssh.
    ///
    /// # Panics
    /// If `bytes` is 0.
    pub fn channel_window(mut self, bytes: u32) -> Self {
        assert!(bytes > 0, "channel window must not be 0");
        self.channel_window = bytes;
        self
    }

    /// The most data the peer may put in one channel packet. Defaults to 32 KiB, as
    /// x/crypto/ssh.
    ///
    /// # Panics
    /// If `bytes` is 0 or too large for the transport's largest packet.
    pub fn channel_max_packet(mut self, bytes: u32) -> Self {
        assert!(
            (1..=MAX_CHANNEL_MAX_PACKET).contains(&bytes),
            "channel maximum packet {bytes} out of range"
        );
        self.channel_max_packet = bytes;
        self
    }

    /// Failed authentication attempts after which the server disconnects. Defaults to 6,
    /// x/crypto/ssh's `MaxAuthTries` default. The client's first `none` request does not count.
    pub fn max_auth_tries(mut self, limit: NonZeroU32) -> Self {
        self.max_auth_tries = limit.get();
        self
    }

    /// No limit on failed authentication attempts; the cap of 128 attempts of any outcome
    /// still applies.
    pub fn unlimited_auth_tries(mut self) -> Self {
        self.max_auth_tries = 0;
        self
    }

    /// The software version in the identification line: `SSH-2.0-<version>`. Defaults to
    /// `justssh`.
    ///
    /// # Panics
    /// If `version` is empty, longer than 245 bytes, or holds anything but printable US-ASCII
    /// other than space and `-` (RFC 4253 §4.2).
    pub fn software_version(mut self, version: &str) -> Self {
        assert!(
            !version.is_empty()
                && version.len() <= 245
                && version.bytes().all(|b| b.is_ascii_graphic() && b != b'-'),
            "invalid SSH software version {version:?}"
        );
        self.version = Some(version.to_owned());
        self
    }

    /// The random number generator for cookies, padding and ephemeral keys. Defaults to the
    /// operating system's generator.
    pub fn rng(mut self, rng: impl CryptoRng + Send + 'static) -> Self {
        self.rng = Some(Box::new(rng));
        self
    }

    pub fn build(self) -> ServerConfig {
        ServerConfig {
            host_key: self.host_key,
            rng: self.rng.unwrap_or_else(system_rng),
            version: format!("SSH-2.0-{}", self.version.as_deref().unwrap_or("justssh")),
            max_auth_tries: self.max_auth_tries,
            channel_window: self.channel_window,
            channel_max_packet: self.channel_max_packet,
        }
    }
}

/// How a [`Client`](crate::Client) runs.
pub struct ClientConfig {
    pub(crate) user: Vec<u8>,
    pub(crate) rng: BoxRng,
    pub(crate) version: String,
}

impl ClientConfig {
    /// A builder for a client authenticating as `user`, sent as given.
    pub fn builder(user: &[u8]) -> ClientConfigBuilder {
        ClientConfigBuilder {
            user: user.to_vec(),
            rng: None,
        }
    }
}

/// Builds a [`ClientConfig`].
pub struct ClientConfigBuilder {
    user: Vec<u8>,
    rng: Option<BoxRng>,
}

impl ClientConfigBuilder {
    /// The random number generator for cookies, padding and ephemeral keys. Defaults to the
    /// operating system's generator.
    pub fn rng(mut self, rng: impl CryptoRng + Send + 'static) -> Self {
        self.rng = Some(Box::new(rng));
        self
    }

    pub fn build(self) -> ClientConfig {
        ClientConfig {
            user: self.user,
            rng: self.rng.unwrap_or_else(system_rng),
            version: "SSH-2.0-justssh".to_owned(),
        }
    }
}
