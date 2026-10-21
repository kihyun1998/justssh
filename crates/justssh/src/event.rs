//! What goes into the state machines and what comes out.

use core::fmt;

use justssh_wire::DecodeError;

use crate::handshake::{AlgorithmCategory, Handshake};

/// Input to [`Server::process`](crate::Server::process) and
/// [`Client::process`](crate::Client::process).
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub enum Event<'a> {
    /// The byte stream to the peer is open. Must come first, exactly once.
    Connected,
    /// Bytes from the peer, split anywhere.
    Received(&'a [u8]),
}

/// Output of the state machines, to be carried out in order.
#[non_exhaustive]
#[derive(Debug)]
pub enum Action {
    /// Bytes to send to the peer.
    Write(Vec<u8>),
    /// The connection is over; nothing more will be written or accepted.
    Closed(Closed),
}

/// How a connection ended.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Closed {
    /// This side ended it because of `error`, after sending `SSH_MSG_DISCONNECT` with `reason`
    /// when the byte stream was already open.
    Local {
        reason: DisconnectReason,
        error: Error,
    },
    /// The consumer asked to disconnect.
    Requested { reason: DisconnectReason },
    /// The peer sent `SSH_MSG_DISCONNECT`.
    Peer {
        reason: DisconnectReason,
        description: String,
    },
}

/// An `SSH_MSG_DISCONNECT` reason code (RFC 4253 §11.1).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DisconnectReason(u32);

impl DisconnectReason {
    pub const HOST_NOT_ALLOWED_TO_CONNECT: Self = Self(1);
    pub const PROTOCOL_ERROR: Self = Self(2);
    pub const KEY_EXCHANGE_FAILED: Self = Self(3);
    pub const MAC_ERROR: Self = Self(5);
    pub const COMPRESSION_ERROR: Self = Self(6);
    pub const SERVICE_NOT_AVAILABLE: Self = Self(7);
    pub const PROTOCOL_VERSION_NOT_SUPPORTED: Self = Self(8);
    pub const HOST_KEY_NOT_VERIFIABLE: Self = Self(9);
    pub const CONNECTION_LOST: Self = Self(10);
    pub const BY_APPLICATION: Self = Self(11);
    pub const TOO_MANY_CONNECTIONS: Self = Self(12);
    pub const AUTH_CANCELLED_BY_USER: Self = Self(13);
    pub const NO_MORE_AUTH_METHODS_AVAILABLE: Self = Self(14);
    pub const ILLEGAL_USER_NAME: Self = Self(15);

    /// The reason with numeric code `code`, including codes this crate has no name for.
    pub const fn from_code(code: u32) -> Self {
        Self(code)
    }

    pub const fn code(self) -> u32 {
        self.0
    }
}

/// Where a connection is.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Version exchange, key exchange and the `ssh-userauth` service request.
    Handshake,
    /// User authentication.
    Auth,
    /// The connection has ended.
    Closed,
}

/// Why this side ended a connection.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// An [`Event`] arrived that the current state does not take.
    UnexpectedEvent,
    /// The peer's identification line was too long or named an unsupported protocol version.
    BadVersion,
    /// A binary packet's length or padding was invalid.
    MalformedPacket,
    /// A packet's MAC did not verify.
    MacMismatch,
    /// A payload could not be decoded.
    Decode(DecodeError),
    /// A message the current state does not allow (ADR-0002).
    UnexpectedMessage { number: u8 },
    /// Strict key exchange was negotiated but `SSH_MSG_KEXINIT` was not the peer's first packet.
    StrictKexViolation,
    /// The two `SSH_MSG_KEXINIT` lists had nothing in common for `category`.
    NoCommonAlgorithm {
        category: AlgorithmCategory,
        handshake: Box<Handshake>,
    },
    /// The key exchange values were invalid: a public key of the wrong length or an all-zero
    /// shared secret.
    KeyExchange,
    /// The server's host key or its signature over the exchange hash did not verify.
    HostKeySignature,
    /// The peer asked for a service other than `ssh-userauth`.
    ServiceNotAvailable,
    /// User authentication was requested and no method is available.
    NoAuthMethods,
    /// A sequence number would wrap before the first key exchange finished.
    SequenceWrap,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnexpectedEvent => f.write_str("unexpected event"),
            Error::BadVersion => f.write_str("invalid or unsupported protocol version"),
            Error::MalformedPacket => f.write_str("malformed packet"),
            Error::MacMismatch => f.write_str("message authentication code incorrect"),
            Error::Decode(e) => write!(f, "malformed message: {e}"),
            Error::UnexpectedMessage { number } => write!(f, "unexpected message {number}"),
            Error::StrictKexViolation => f.write_str("strict key exchange violation"),
            Error::NoCommonAlgorithm { category, .. } => {
                write!(f, "no matching {category} algorithm")
            }
            Error::KeyExchange => f.write_str("key exchange failed"),
            Error::HostKeySignature => f.write_str("host key signature did not verify"),
            Error::ServiceNotAvailable => f.write_str("service not available"),
            Error::NoAuthMethods => f.write_str("no authentication methods available"),
            Error::SequenceWrap => f.write_str("sequence number wrapped during key exchange"),
        }
    }
}

impl std::error::Error for Error {}
