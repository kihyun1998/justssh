//! SSH message encoding and decoding, with no dependencies.

pub mod codec;
mod messages;
pub mod number;

pub use codec::{DecodeError, Reader, Writer};
pub use messages::{
    Debug, Disconnect, Ignore, KexEcdhInit, KexEcdhReply, KexInit, Message, NewKeys, ServiceAccept,
    ServiceRequest, Unimplemented,
};
