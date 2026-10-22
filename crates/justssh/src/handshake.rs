//! What the two sides said during the handshake and what they agreed on.

use core::fmt;

use justssh_wire::KexInit;

/// Both identification lines, both `SSH_MSG_KEXINIT` messages and the negotiated algorithms,
/// each present once it has been sent, received or agreed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    pub(crate) local_version: String,
    pub(crate) peer_version: Option<String>,
    pub(crate) local_kexinit: Option<KexInitRecord>,
    pub(crate) peer_kexinit: Option<KexInitRecord>,
    pub(crate) undecoded_peer_kexinit: Option<Vec<u8>>,
    pub(crate) negotiated: Option<Algorithms>,
}

impl Handshake {
    /// This side's identification line, without CR LF.
    pub fn local_version(&self) -> &str {
        &self.local_version
    }

    /// The peer's identification line, without CR LF.
    pub fn peer_version(&self) -> Option<&str> {
        self.peer_version.as_deref()
    }

    pub fn local_kexinit(&self) -> Option<&KexInitRecord> {
        self.local_kexinit.as_ref()
    }

    pub fn peer_kexinit(&self) -> Option<&KexInitRecord> {
        self.peer_kexinit.as_ref()
    }

    /// The payload of a peer `SSH_MSG_KEXINIT` that could not be decoded, message number
    /// included, as received.
    pub fn undecoded_peer_kexinit(&self) -> Option<&[u8]> {
        self.undecoded_peer_kexinit.as_deref()
    }

    pub fn negotiated(&self) -> Option<&Algorithms> {
        self.negotiated.as_ref()
    }
}

/// An `SSH_MSG_KEXINIT` as its payload bytes and as decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KexInitRecord {
    pub(crate) raw: Vec<u8>,
    pub(crate) message: KexInit,
}

impl KexInitRecord {
    /// The payload exactly as sent or received, message number included.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub fn message(&self) -> &KexInit {
        &self.message
    }
}

/// The algorithms agreed in a key exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Algorithms {
    pub(crate) kex: String,
    pub(crate) host_key: String,
    pub(crate) cipher_client_to_server: String,
    pub(crate) cipher_server_to_client: String,
    pub(crate) mac_client_to_server: Option<String>,
    pub(crate) mac_server_to_client: Option<String>,
    pub(crate) compression_client_to_server: String,
    pub(crate) compression_server_to_client: String,
    pub(crate) strict_kex: bool,
}

impl Algorithms {
    pub fn kex(&self) -> &str {
        &self.kex
    }

    pub fn host_key(&self) -> &str {
        &self.host_key
    }

    pub fn cipher_client_to_server(&self) -> &str {
        &self.cipher_client_to_server
    }

    pub fn cipher_server_to_client(&self) -> &str {
        &self.cipher_server_to_client
    }

    /// `None` when the cipher is an AEAD and no MAC is negotiated.
    pub fn mac_client_to_server(&self) -> Option<&str> {
        self.mac_client_to_server.as_deref()
    }

    /// `None` when the cipher is an AEAD and no MAC is negotiated.
    pub fn mac_server_to_client(&self) -> Option<&str> {
        self.mac_server_to_client.as_deref()
    }

    pub fn compression_client_to_server(&self) -> &str {
        &self.compression_client_to_server
    }

    pub fn compression_server_to_client(&self) -> &str {
        &self.compression_server_to_client
    }

    /// Whether strict key exchange is in force for this connection.
    pub fn strict_kex(&self) -> bool {
        self.strict_kex
    }
}

/// One of the `SSH_MSG_KEXINIT` name-lists.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmCategory {
    Kex,
    HostKey,
    CipherClientToServer,
    CipherServerToClient,
    MacClientToServer,
    MacServerToClient,
    CompressionClientToServer,
    CompressionServerToClient,
}

impl fmt::Display for AlgorithmCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AlgorithmCategory::Kex => "key exchange",
            AlgorithmCategory::HostKey => "host key",
            AlgorithmCategory::CipherClientToServer => "client-to-server cipher",
            AlgorithmCategory::CipherServerToClient => "server-to-client cipher",
            AlgorithmCategory::MacClientToServer => "client-to-server MAC",
            AlgorithmCategory::MacServerToClient => "server-to-client MAC",
            AlgorithmCategory::CompressionClientToServer => "client-to-server compression",
            AlgorithmCategory::CompressionServerToClient => "server-to-client compression",
        })
    }
}
