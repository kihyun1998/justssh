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
                config.rng,
                config.version,
                config.max_auth_tries,
            ),
        }
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
}
