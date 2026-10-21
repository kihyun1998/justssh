//! Which message numbers each stage of the connection takes (ADR-0002). Every received packet
//! passes through [`verdict`] before it is decoded.

use justssh_wire::number;

use super::Role;

/// Where the transport is, as far as incoming messages are concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    /// Waiting for the peer's `SSH_MSG_KEXINIT`.
    KexInit,
    /// Waiting for `SSH_MSG_KEX_ECDH_INIT` (server) or `SSH_MSG_KEX_ECDH_REPLY` (client).
    KexEcdh,
    /// This side has sent `SSH_MSG_NEWKEYS` and waits for the peer's.
    NewKeys,
    /// Waiting for `SSH_MSG_SERVICE_REQUEST` (server) or `SSH_MSG_SERVICE_ACCEPT` (client).
    Service,
    /// User authentication.
    Auth,
    /// Authenticated.
    Connected,
}

/// What to do with a received message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Accept,
    Disconnect,
    /// Drop it without a reply (RFC 4252 §5: requests after `SSH_MSG_USERAUTH_SUCCESS`).
    Ignore,
    /// Answer `SSH_MSG_UNIMPLEMENTED` and carry on (RFC 4253 §11.4).
    Unimplemented,
}

/// The verdict for message `n` arriving at `role` in `stage`. `strict_initial` is true while
/// strict key exchange is in force and the first key exchange has not finished.
pub(crate) fn verdict(role: Role, stage: Stage, n: u8, strict_initial: bool) -> Verdict {
    use Verdict::{Accept, Disconnect, Ignore, Unimplemented};

    let accept_if = |ok: bool| if ok { Accept } else { Disconnect };
    match n {
        number::DISCONNECT => Accept,
        number::IGNORE | number::DEBUG | number::UNIMPLEMENTED => accept_if(!strict_initial),
        number::KEXINIT => accept_if(stage == Stage::KexInit),
        number::KEX_ECDH_INIT => accept_if(role == Role::Server && stage == Stage::KexEcdh),
        number::KEX_ECDH_REPLY => accept_if(role == Role::Client && stage == Stage::KexEcdh),
        number::NEWKEYS => accept_if(stage == Stage::NewKeys),
        number::SERVICE_REQUEST => accept_if(role == Role::Server && stage == Stage::Service),
        number::SERVICE_ACCEPT => accept_if(role == Role::Client && stage == Stage::Service),
        number::USERAUTH_REQUEST if role == Role::Server && stage == Stage::Connected => Ignore,
        number::USERAUTH_REQUEST => accept_if(role == Role::Server && stage == Stage::Auth),
        number::PING | number::PONG => accept_if(stage == Stage::Connected),
        number::GLOBAL_REQUEST..=number::REQUEST_FAILURE => accept_if(stage == Stage::Connected),
        number::CHANNEL_OPEN..=number::CHANNEL_FAILURE => accept_if(stage == Stage::Connected),
        n if !number::is_known(n) && stage == Stage::Connected => Unimplemented,
        _ => Disconnect,
    }
}
