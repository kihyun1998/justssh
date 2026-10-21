//! The client side of a connection.

use crate::config::ClientConfig;
use crate::event::{Action, DisconnectReason, Event, Phase};
use crate::handshake::Handshake;
use crate::key::PrivateKey;
use crate::transport::{Method, Role, Transport};
use zeroize::Zeroizing;

/// One client connection as a state machine: feed it [`Event`]s, carry out the [`Action`]s.
pub struct Client {
    transport: Transport,
}

impl Client {
    pub fn new(config: ClientConfig) -> Self {
        let mut transport = Transport::new(
            Role::Client,
            Vec::new(),
            Some(config.user),
            config.rng,
            config.version,
            0,
            config.channel_window,
            config.channel_max_packet,
        );
        transport.set_preference(config.preference);
        Client { transport }
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

    /// The server's host key blob, once its signature over the exchange hash has verified.
    pub fn peer_host_key(&self) -> Option<&[u8]> {
        self.transport.peer_host_key()
    }

    /// The public key algorithms the server accepts for authentication, from the
    /// `server-sig-algs` extension (RFC 8308 §3.1) of its first `SSH_MSG_EXT_INFO`, if it sent
    /// one.
    pub fn server_sig_algs(&self) -> Option<Vec<&str>> {
        self.transport.server_sig_algs()
    }

    /// Sends an authentication request for method `none`, which reports the methods the server
    /// takes. Every attempt is answered with [`Action::AuthFailure`], or by the phase becoming
    /// [`Phase::Connected`]; attempts are made one at a time, once the phase is [`Phase::Auth`],
    /// and an attempt made otherwise ends the connection.
    pub fn auth_none(&mut self) -> Vec<Action> {
        self.transport.client_attempt(Method::None, &[])
    }

    /// Sends a password authentication request.
    pub fn auth_password(&mut self, password: Zeroizing<Vec<u8>>) -> Vec<Action> {
        self.transport.client_attempt(Method::Password, &password)
    }

    /// Sends a keyboard-interactive authentication request (RFC 4256); the server's questions
    /// arrive as [`Action::KeyboardInteractive`].
    pub fn auth_keyboard_interactive(&mut self) -> Vec<Action> {
        self.transport
            .client_attempt(Method::KeyboardInteractive, &[])
    }

    /// Answers the questions of the last [`Action::KeyboardInteractive`], one answer for each, in
    /// order. A different number of answers, or answers nobody asked for, end the connection.
    pub fn answer_prompts(&mut self, answers: Vec<Zeroizing<Vec<u8>>>) -> Vec<Action> {
        self.transport.answer_prompts(&answers)
    }

    /// Sends a `publickey` query for `key` under the algorithm the server's `server-sig-algs`
    /// leads to, as x/crypto/ssh picks it; once the server accepts the key with
    /// `SSH_MSG_USERAUTH_PK_OK`, the signed request follows. The answer is
    /// [`Action::AuthFailure`] or the phase becoming [`Phase::Connected`], as for the other
    /// methods.
    pub fn auth_publickey(&mut self, key: &PrivateKey) -> Vec<Action> {
        self.transport.client_publickey(key, None)
    }

    /// [`auth_publickey`](Self::auth_publickey) under `algorithm`, which must be one the key
    /// signs under; another ends the connection.
    pub fn auth_publickey_as(&mut self, key: &PrivateKey, algorithm: &str) -> Vec<Action> {
        self.transport.client_publickey(key, Some(algorithm))
    }

    crate::endpoint::connection_methods!();
}

crate::endpoint::impl_endpoint!(Client);
