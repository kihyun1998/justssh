//! What goes into the state machines and what comes out.

use core::fmt;

use justssh_wire::DecodeError;
use zeroize::Zeroizing;

use crate::connection::{ChannelId, ChannelOpenRequest, ChannelRequest, GlobalRequest};
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
    /// The consumer accepts the pending [`Action::PasswordRequest`].
    AuthAccepted,
    /// The consumer rejects the pending [`Action::PasswordRequest`].
    AuthRejected,
    /// A deadline the consumer set for the current phase has passed.
    DeadlineExceeded,
}

/// Output of the state machines, to be carried out in order.
#[non_exhaustive]
#[derive(Debug)]
pub enum Action {
    /// Bytes to send to the peer.
    Write(Vec<u8>),
    /// A client asks to authenticate with a password. Nothing further is processed until the
    /// consumer answers with [`Event::AuthAccepted`] or [`Event::AuthRejected`].
    PasswordRequest(PasswordRequest),
    /// A global request from the peer, passed through unparsed.
    GlobalRequest(GlobalRequest),
    /// The reply to a global request this side sent with `want_reply`, with everything after
    /// the message number; replies arrive in the order the requests were sent.
    GlobalRequestReply { ok: bool, data: Vec<u8> },
    /// The peer asks to open a channel.
    ChannelOpenRequest(ChannelOpenRequest),
    /// A channel request from the peer, passed through unparsed.
    ChannelRequest(ChannelRequest),
    /// Data the peer sent on a channel. Report it with `channel_consumed` once taken, so the
    /// peer's window is given back.
    ChannelData { channel: ChannelId, data: Vec<u8> },
    /// Extended data of any type (1 is stderr). Reported to `channel_consumed` like data.
    ChannelExtendedData {
        channel: ChannelId,
        code: u32,
        data: Vec<u8>,
    },
    /// The peer will send no more data on the channel.
    ChannelEof { channel: ChannelId },
    /// The channel is closed in both directions and its id is free.
    ChannelClosed { channel: ChannelId },
    /// The reply to a channel request this side sent with `want_reply`; replies arrive in the
    /// order the requests were sent.
    ChannelRequestReply { channel: ChannelId, ok: bool },
    /// The connection is over; nothing more will be written or accepted.
    Closed(Closed),
    /// A payload received after the first key exchange, handed over undecoded instead of being
    /// handled (`test-support` raw mode).
    #[cfg(feature = "test-support")]
    RawReceived(Vec<u8>),
}

/// A password authentication attempt (RFC 4252 §8).
#[non_exhaustive]
pub struct PasswordRequest {
    pub(crate) user: Vec<u8>,
    pub(crate) password: Zeroizing<Vec<u8>>,
}

impl PasswordRequest {
    /// The user name, as sent.
    pub fn user(&self) -> &[u8] {
        &self.user
    }

    /// The password, as sent.
    pub fn password(&self) -> &[u8] {
        &self.password
    }
}

impl fmt::Debug for PasswordRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordRequest")
            .field("user", &String::from_utf8_lossy(&self.user))
            .field("password", &"<redacted>")
            .finish()
    }
}

/// How a connection ended, and the phase it was in when it did.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Closed {
    /// This side ended it because of `error`, after sending `SSH_MSG_DISCONNECT` with `reason`
    /// when the byte stream was already open.
    Local {
        reason: DisconnectReason,
        error: Error,
        phase: Phase,
    },
    /// The consumer asked to disconnect.
    Requested {
        reason: DisconnectReason,
        phase: Phase,
    },
    /// The peer sent `SSH_MSG_DISCONNECT`.
    Peer {
        reason: DisconnectReason,
        description: String,
        phase: Phase,
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
    /// Authenticated: the connection protocol.
    Connected,
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
    /// The peer asked for a service other than `ssh-userauth`, or authenticated for one other
    /// than `ssh-connection`.
    ServiceNotAvailable,
    /// Failed authentication attempts reached the configured limit.
    TooManyAuthFailures,
    /// Authentication attempts of any outcome reached 128.
    TooManyAuthAttempts,
    /// The consumer reported [`Event::DeadlineExceeded`].
    DeadlineExceeded,
    /// More input arrived while a verdict was pending than one packet could hold.
    InputOverflow,
    /// A message named a channel that is not open.
    UnknownChannel { channel: u32 },
    /// The peer sent more channel data than the window allowed.
    ChannelWindowExceeded,
    /// The peer sent channel data larger than the maximum packet this side announced.
    ChannelPacketTooLarge,
    /// A window adjustment would take the peer's window past 2^32 − 1.
    ChannelWindowOverflow,
    /// A sequence number would repeat under one key.
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
            Error::TooManyAuthFailures => f.write_str("too many authentication failures"),
            Error::TooManyAuthAttempts => f.write_str("too many authentication attempts"),
            Error::DeadlineExceeded => f.write_str("deadline exceeded"),
            Error::InputOverflow => f.write_str("too much input while a verdict was pending"),
            Error::UnknownChannel { channel } => write!(f, "unknown channel {channel}"),
            Error::ChannelWindowExceeded => f.write_str("channel data exceeds the window"),
            Error::ChannelPacketTooLarge => {
                f.write_str("channel data exceeds the maximum packet size")
            }
            Error::ChannelWindowOverflow => f.write_str("channel window overflow"),
            Error::SequenceWrap => f.write_str("sequence number would repeat under one key"),
        }
    }
}

impl std::error::Error for Error {}
