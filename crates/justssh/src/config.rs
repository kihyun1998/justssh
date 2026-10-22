//! Server and client configuration.

use core::fmt;
use core::num::NonZeroU32;

use rand_core::{CryptoRng, UnwrapErr};
use zeroize::Zeroizing;

use crate::key::{KeyError, PrivateKey};

pub(crate) type BoxRng = Box<dyn CryptoRng + Send>;

fn system_rng() -> BoxRng {
    Box::new(UnwrapErr(getrandom::SysRng))
}

/// A server host key and the public key algorithms it is offered under.
#[derive(Clone)]
pub struct HostKey {
    key: PrivateKey,
    algorithms: Vec<&'static str>,
}

impl HostKey {
    /// An `ssh-ed25519` host key from its 32-byte secret seed.
    pub fn ed25519_from_seed(seed: Zeroizing<[u8; 32]>) -> Self {
        HostKey::new(PrivateKey::ed25519(seed))
    }

    /// A host key offered under every algorithm `key` signs under, in its order. A certificate
    /// on `key` is not used: the host key is the plain key.
    pub fn new(key: PrivateKey) -> Self {
        let key = key.without_certificate();
        let algorithms = key.algorithms().to_vec();
        HostKey { key, algorithms }
    }

    /// The key offered only under `algorithms`, still in the key's own order, as x/crypto/ssh's
    /// `NewSignerWithAlgorithms`. A key already restricted is narrowed further.
    ///
    /// # Errors
    /// [`KeyError::UnsupportedAlgorithm`] if `algorithms` is empty or names an algorithm the key
    /// is not offered under.
    pub fn with_algorithms(mut self, algorithms: &[&str]) -> Result<Self, KeyError> {
        if algorithms.is_empty() || algorithms.iter().any(|a| !self.algorithms.contains(a)) {
            return Err(KeyError::UnsupportedAlgorithm);
        }
        self.algorithms.retain(|a| algorithms.contains(a));
        Ok(self)
    }

    /// The public key algorithms the key is offered under, in order.
    pub fn algorithms(&self) -> &[&'static str] {
        &self.algorithms
    }

    /// The key's public key format, such as `ssh-rsa`.
    pub(crate) fn format(&self) -> &'static str {
        self.key.format()
    }

    /// The public key blob `K_S`.
    pub(crate) fn public_blob(&self) -> Vec<u8> {
        self.key.plain_public_blob()
    }

    /// The signature blob over `data` under `algorithm`, one of [`algorithms`](Self::algorithms).
    pub(crate) fn sign(&self, algorithm: &str, data: &[u8], rng: &mut dyn CryptoRng) -> Vec<u8> {
        self.key.sign(algorithm, data, rng)
    }
}

impl fmt::Debug for HostKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostKey")
            .field("format", &self.format())
            .field("algorithms", &self.algorithms)
            .finish_non_exhaustive()
    }
}

/// How a [`Server`](crate::Server) runs.
pub struct ServerConfig {
    pub(crate) host_keys: Vec<HostKey>,
    pub(crate) preference: Option<crate::transport::Preference>,
    pub(crate) send_ext_info: bool,
    pub(crate) rng: BoxRng,
    pub(crate) version: String,
    pub(crate) max_auth_tries: u32,
    pub(crate) channel_window: u32,
    pub(crate) channel_max_packet: u32,
    pub(crate) rekey_threshold: Option<u64>,
}

/// x/crypto/ssh's channel window: 64 maximum packets.
pub(crate) const DEFAULT_CHANNEL_WINDOW: u32 = 64 * DEFAULT_CHANNEL_MAX_PACKET;
/// x/crypto/ssh's maximum channel data per packet.
pub(crate) const DEFAULT_CHANNEL_MAX_PACKET: u32 = 1 << 15;
/// The largest maximum packet that still fits the transport's largest packet with room for the
/// message header.
const MAX_CHANNEL_MAX_PACKET: u32 = 256 * 1024 - 64;

impl ServerConfig {
    /// A builder for a server presenting `host_key`, and any added with
    /// [`host_key`](ServerConfigBuilder::host_key).
    pub fn builder(host_key: HostKey) -> ServerConfigBuilder {
        ServerConfigBuilder {
            host_keys: vec![host_key],
            preference: None,
            send_ext_info: true,
            rng: None,
            version: None,
            max_auth_tries: 6,
            channel_window: DEFAULT_CHANNEL_WINDOW,
            channel_max_packet: DEFAULT_CHANNEL_MAX_PACKET,
            rekey_threshold: None,
        }
    }
}

/// Builds a [`ServerConfig`].
pub struct ServerConfigBuilder {
    host_keys: Vec<HostKey>,
    preference: Option<crate::transport::Preference>,
    send_ext_info: bool,
    rng: Option<BoxRng>,
    version: Option<String>,
    max_auth_tries: u32,
    channel_window: u32,
    channel_max_packet: u32,
    rekey_threshold: Option<u64>,
}

impl ServerConfigBuilder {
    /// Exchanges keys again after this many bytes in either direction, as x/crypto/ssh's
    /// `RekeyThreshold`: 0 keeps the default of 64 GiB under AES and 1 GiB under other ciphers,
    /// and less than 256 counts as 256. Keys are also exchanged again after 2^31 packets.
    pub fn rekey_threshold(mut self, bytes: u64) -> Self {
        self.rekey_threshold = (bytes > 0).then(|| bytes.max(256));
        self
    }

    /// Adds `key`, offered after the keys already added; it replaces an added key of the same
    /// format, as x/crypto/ssh's `AddHostKey`.
    pub fn host_key(mut self, key: HostKey) -> Self {
        match self
            .host_keys
            .iter_mut()
            .find(|k| k.format() == key.format())
        {
            Some(k) => *k = key,
            None => self.host_keys.push(key),
        }
        self
    }

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

    /// Offers only `kex`, `ciphers` and `macs`, in that order. For tests only.
    #[cfg(feature = "test-support")]
    pub fn algorithms(mut self, kex: &[&str], ciphers: &[&str], macs: &[&str]) -> Self {
        self.preference
            .get_or_insert_with(Default::default)
            .set_lists(kex, ciphers, macs);
        self
    }

    /// Whether to answer a client's `ext-info-c` with `SSH_MSG_EXT_INFO`. For tests only.
    #[cfg(feature = "test-support")]
    pub fn send_ext_info(mut self, send: bool) -> Self {
        self.send_ext_info = send;
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
            host_keys: self.host_keys,
            preference: self.preference,
            send_ext_info: self.send_ext_info,
            rng: self.rng.unwrap_or_else(system_rng),
            version: format!("SSH-2.0-{}", self.version.as_deref().unwrap_or("justssh")),
            max_auth_tries: self.max_auth_tries,
            channel_window: self.channel_window,
            channel_max_packet: self.channel_max_packet,
            rekey_threshold: self.rekey_threshold,
        }
    }
}

/// How a [`Client`](crate::Client) runs.
pub struct ClientConfig {
    pub(crate) user: Vec<u8>,
    pub(crate) preference: Option<crate::transport::Preference>,
    pub(crate) rng: BoxRng,
    pub(crate) version: String,
    pub(crate) channel_window: u32,
    pub(crate) channel_max_packet: u32,
    pub(crate) rekey_threshold: Option<u64>,
}

impl ClientConfig {
    /// A builder for a client authenticating as `user`, sent as given.
    pub fn builder(user: &[u8]) -> ClientConfigBuilder {
        ClientConfigBuilder {
            user: user.to_vec(),
            preference: None,
            rng: None,
            channel_window: DEFAULT_CHANNEL_WINDOW,
            channel_max_packet: DEFAULT_CHANNEL_MAX_PACKET,
            rekey_threshold: None,
        }
    }
}

/// Builds a [`ClientConfig`].
pub struct ClientConfigBuilder {
    user: Vec<u8>,
    preference: Option<crate::transport::Preference>,
    rng: Option<BoxRng>,
    channel_window: u32,
    channel_max_packet: u32,
    rekey_threshold: Option<u64>,
}

impl ClientConfigBuilder {
    /// Exchanges keys again after this many bytes in either direction, as x/crypto/ssh's
    /// `RekeyThreshold`: 0 keeps the default of 64 GiB under AES and 1 GiB under other ciphers,
    /// and less than 256 counts as 256. Keys are also exchanged again after 2^31 packets.
    pub fn rekey_threshold(mut self, bytes: u64) -> Self {
        self.rekey_threshold = (bytes > 0).then(|| bytes.max(256));
        self
    }

    /// Offers only `kex`, `ciphers` and `macs`, in that order. For tests only.
    #[cfg(feature = "test-support")]
    pub fn algorithms(mut self, kex: &[&str], ciphers: &[&str], macs: &[&str]) -> Self {
        self.preference
            .get_or_insert_with(Default::default)
            .set_lists(kex, ciphers, macs);
        self
    }

    /// Offers `ciphers` and `macs` for the server-to-client direction only. For tests only.
    #[cfg(feature = "test-support")]
    pub fn server_to_client(mut self, ciphers: &[&str], macs: &[&str]) -> Self {
        self.preference
            .get_or_insert_with(Default::default)
            .set_server_to_client(ciphers, macs);
        self
    }

    /// Offers only `algorithms` as host key algorithms, in that order. For tests only.
    #[cfg(feature = "test-support")]
    pub fn host_key_algorithms(mut self, algorithms: &[&str]) -> Self {
        self.preference
            .get_or_insert_with(Default::default)
            .set_host_keys(algorithms);
        self
    }

    /// Whether to offer strict KEX (`kex-strict-c-v00@openssh.com`). Defaults to true. For
    /// tests only.
    #[cfg(feature = "test-support")]
    pub fn strict_kex(mut self, offer: bool) -> Self {
        self.preference
            .get_or_insert_with(Default::default)
            .strict_kex = offer;
        self
    }

    /// The window each channel starts with. Defaults to 2 MiB, as x/crypto/ssh.
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

    /// The random number generator for cookies, padding and ephemeral keys. Defaults to the
    /// operating system's generator.
    pub fn rng(mut self, rng: impl CryptoRng + Send + 'static) -> Self {
        self.rng = Some(Box::new(rng));
        self
    }

    pub fn build(self) -> ClientConfig {
        ClientConfig {
            user: self.user,
            preference: self.preference,
            rng: self.rng.unwrap_or_else(system_rng),
            channel_window: self.channel_window,
            channel_max_packet: self.channel_max_packet,
            rekey_threshold: self.rekey_threshold,
            version: "SSH-2.0-justssh".to_owned(),
        }
    }
}
