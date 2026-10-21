//! Sans-IO SSH client and server: the transport, authentication and connection state machines.

mod client;
mod config;
mod connection;
mod event;
mod handshake;
mod server;
mod transport;

pub use client::Client;
pub use config::{ClientConfig, ClientConfigBuilder, HostKey, ServerConfig, ServerConfigBuilder};
pub use connection::{
    ChannelId, ChannelInfo, ChannelOpenRequest, ChannelRequest, OpenFailureReason, ReplyToken,
};
pub use event::{Action, Closed, DisconnectReason, Error, Event, PasswordRequest, Phase};
pub use handshake::{AlgorithmCategory, Algorithms, Handshake, KexInitRecord};
pub use rand_core;
pub use server::Server;
pub use zeroize::Zeroizing;
