//! The client side of a connection.

use crate::config::ClientConfig;
use crate::event::{Action, DisconnectReason, Event, Phase};
use crate::handshake::Handshake;
use crate::transport::{Role, Transport};

/// One client connection as a state machine: feed it [`Event`]s, carry out the [`Action`]s.
pub struct Client {
    transport: Transport,
}

impl Client {
    pub fn new(config: ClientConfig) -> Self {
        Client {
            transport: Transport::new(Role::Client, None, config.rng, config.version),
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

    /// The server's host key blob, once its signature over the exchange hash has verified.
    pub fn peer_host_key(&self) -> Option<&[u8]> {
        self.transport.peer_host_key()
    }
}
