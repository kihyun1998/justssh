//! SSH message encoding and decoding, with no dependencies.

pub mod codec;
mod messages;
mod name;
pub mod number;

pub use codec::{DecodeError, Reader, Writer};
pub use messages::{
    ChannelClose, ChannelData, ChannelEof, ChannelExtendedData, ChannelFailure, ChannelOpen,
    ChannelOpenConfirmation, ChannelOpenFailure, ChannelRequest, ChannelSuccess,
    ChannelWindowAdjust, Debug, Disconnect, ExtInfo, GlobalRequest, Ignore, KexEcdhInit,
    KexEcdhReply, KexInit, Message, NewKeys, Ping, Pong, RequestFailure, RequestSuccess,
    ServiceAccept, ServiceRequest, Unimplemented, UserauthBanner, UserauthFailure, UserauthRequest,
    UserauthSuccess,
};
pub use name::Name;
