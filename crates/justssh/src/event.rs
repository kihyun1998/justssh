//! What goes into the state machines and what comes out.

use core::fmt;

use justssh_wire::DecodeError;
use zeroize::Zeroizing;

use crate::connection::{
    ChannelId, ChannelOpenRequest, ChannelRequest, GlobalRequest, OpenFailureReason, RequestToken,
};
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
    /// The consumer accepts the host key of the pending [`Action::VerifyHostKey`].
    HostKeyAccepted,
    /// The consumer rejects the host key of the pending [`Action::VerifyHostKey`]; the
    /// connection ends.
    HostKeyRejected,
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
    /// The server's host key blob, its signature over the exchange hash verified. Nothing
    /// further is processed until the consumer answers with [`Event::HostKeyAccepted`] or
    /// [`Event::HostKeyRejected`].
    VerifyHostKey { key: Vec<u8> },
    /// A message the server shows before authentication completes (RFC 4252 §5.4), as sent and
    /// unfiltered.
    AuthBanner { message: Vec<u8> },
    /// The last authentication attempt did not complete authentication; `methods` may continue.
    /// With `partial_success` it succeeded, but more is required.
    AuthFailure {
        methods: Vec<String>,
        partial_success: bool,
    },
    /// The server refused the key of the last `publickey` attempt without a signature being
    /// sent: it answered the query with `SSH_MSG_USERAUTH_FAILURE`, or its
    /// `SSH_MSG_USERAUTH_PK_OK` named another key or an algorithm outside the key's family.
    /// `methods` are those the server last named.
    PublicKeyRefused { methods: Vec<String> },
    /// The server asks the keyboard-interactive questions in it; answer with
    /// [`Client::answer_prompts`](crate::Client::answer_prompts).
    KeyboardInteractive(InfoRequest),
    /// A global request from the peer, passed through unparsed.
    GlobalRequest(GlobalRequest),
    /// The reply to the global request this side sent with `token`, with everything after the
    /// message number.
    GlobalRequestReply {
        token: RequestToken,
        ok: bool,
        data: Vec<u8>,
    },
    /// The peer asks to open a channel.
    ChannelOpenRequest(ChannelOpenRequest),
    /// The peer confirmed a channel this side opened; `data` is the channel-type-specific part
    /// of the confirmation.
    ChannelOpened { channel: ChannelId, data: Vec<u8> },
    /// The peer refused a channel this side opened; the channel id is free.
    ChannelOpenFailed {
        channel: ChannelId,
        reason: OpenFailureReason,
        description: String,
    },
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
    /// The reply to the channel request this side sent with `token`; a failure too when the
    /// channel closed, was aborted or was refused before the peer replied.
    ChannelRequestReply {
        channel: ChannelId,
        token: RequestToken,
        ok: bool,
    },
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

/// A keyboard-interactive information request (RFC 4256 §3.2), its strings as sent and
/// unfiltered.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoRequest {
    pub(crate) name: Vec<u8>,
    pub(crate) instruction: Vec<u8>,
    pub(crate) prompts: Vec<Prompt>,
}

impl InfoRequest {
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    pub fn instruction(&self) -> &[u8] {
        &self.instruction
    }

    /// The questions, each answered in order; there may be none.
    pub fn prompts(&self) -> &[Prompt] {
        &self.prompts
    }
}

/// One keyboard-interactive question.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    pub(crate) text: Vec<u8>,
    pub(crate) echo: bool,
}

impl Prompt {
    pub fn text(&self) -> &[u8] {
        &self.text
    }

    /// Whether the answer may be shown as it is typed.
    pub fn echo(&self) -> bool {
        self.echo
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
    /// An [`Event`] or command arrived that the current state does not take.
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
    /// The consumer rejected the server's host key.
    HostKeyRejected,
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
    /// The peer confirmed a channel with a maximum packet below 9 or above 2^31.
    InvalidChannelMaxPacket,
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
            Error::HostKeyRejected => f.write_str("host key not accepted"),
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
            Error::InvalidChannelMaxPacket => f.write_str("invalid channel maximum packet"),
            Error::SequenceWrap => f.write_str("sequence number would repeat under one key"),
        }
    }
}

impl std::error::Error for Error {}
