//! The server side of a connection.

use crate::config::ServerConfig;
use crate::event::{Action, DisconnectReason, Event, Phase};
use crate::handshake::Handshake;
use crate::transport::{Role, Transport};

/// One server connection as a state machine: feed it [`Event`]s, carry out the [`Action`]s.
pub struct Server {
    transport: Transport,
}

impl Server {
    pub fn new(config: ServerConfig) -> Self {
        Server {
            transport: Transport::new(
                Role::Server,
                Some(config.host_key),
                None,
                config.rng,
                config.version,
                config.max_auth_tries,
                config.channel_window,
                config.channel_max_packet,
            ),
        }
    }

    /// Sends `payload` as one packet, whatever it holds. For tests and fuzzing.
    #[cfg(feature = "test-support")]
    pub fn send_raw(&mut self, payload: &[u8]) -> Vec<Action> {
        self.transport.send_raw(payload)
    }

    /// After the first key exchange, hands every received payload over as
    /// [`Action::RawReceived`] instead of handling it. For tests and fuzzing.
    #[cfg(feature = "test-support")]
    pub fn set_raw_receive(&mut self, raw: bool) {
        self.transport.set_raw_receive(raw);
    }

    pub fn process(&mut self, event: Event<'_>) -> Vec<Action> {
        self.transport.process(event)
    }

    /// Sends `SSH_MSG_DISCONNECT` and ends the connection.
    pub fn disconnect(&mut self, reason: DisconnectReason, description: &str) -> Vec<Action> {
        self.transport.disconnect(reason, description)
    }

    pub fn phase(&self) -> Phase {
        self.transport.phase()
    }

    pub fn handshake(&self) -> &Handshake {
        self.transport.handshake()
    }

    /// The exchange hash of the first key exchange, once it has finished.
    pub fn session_id(&self) -> Option<&[u8]> {
        self.transport.session_id()
    }

    crate::endpoint::connection_methods!();
}

crate::endpoint::impl_endpoint!(Server);
