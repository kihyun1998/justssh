//! The server side of a connection.

use crate::config::ServerConfig;
use crate::connection::{
    ChannelId, ChannelInfo, GlobalReplyToken, OpenFailureReason, OutKind, ReplyToken,
};
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
                config.channel_window,
                config.channel_max_packet,
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

    /// Sends a global request, opaque. A reply, when asked for, arrives as
    /// [`Action::GlobalRequestReply`].
    pub fn global_request(&mut self, kind: &str, want_reply: bool, data: Vec<u8>) -> Vec<Action> {
        self.transport
            .channels(|c| c.global_request(kind, want_reply, data))
    }

    /// Answers a global request with `data` after the message number. Replies leave in the
    /// order the requests arrived, whatever order they are given in.
    pub fn reply_global_request(
        &mut self,
        token: GlobalReplyToken,
        ok: bool,
        data: Vec<u8>,
    ) -> Vec<Action> {
        self.transport.channels(|c| c.global_reply(token, ok, data))
    }

    /// Accepts the peer's channel open; `data` is the channel-type-specific part of the
    /// confirmation, usually empty.
    pub fn accept_channel(&mut self, channel: ChannelId, data: Vec<u8>) -> Vec<Action> {
        self.transport.channels(|c| c.accept(channel, data))
    }

    pub fn reject_channel(
        &mut self,
        channel: ChannelId,
        reason: OpenFailureReason,
        description: &str,
    ) -> Vec<Action> {
        self.transport
            .channels(|c| c.reject(channel, reason, description))
    }

    /// Sends `data` on `channel` after anything already queued there, as the peer's window
    /// allows. Commands for a channel that is not open, or that this side has closed, are
    /// dropped.
    pub fn channel_data(&mut self, channel: ChannelId, data: &[u8]) -> Vec<Action> {
        self.transport
            .channels(|c| c.enqueue(channel, OutKind::Data(data.to_vec())))
    }

    /// Sends extended data of type `code` (1 is stderr), in order like data.
    pub fn channel_extended_data(
        &mut self,
        channel: ChannelId,
        code: u32,
        data: &[u8],
    ) -> Vec<Action> {
        self.transport
            .channels(|c| c.enqueue(channel, OutKind::Extended(code, data.to_vec())))
    }

    /// Sends `SSH_MSG_CHANNEL_EOF` once everything queued before it has gone.
    pub fn channel_eof(&mut self, channel: ChannelId) -> Vec<Action> {
        self.transport
            .channels(|c| c.enqueue(channel, OutKind::Eof))
    }

    /// Sends `SSH_MSG_CHANNEL_CLOSE` once everything queued before it has gone.
    pub fn channel_close(&mut self, channel: ChannelId) -> Vec<Action> {
        self.transport
            .channels(|c| c.enqueue(channel, OutKind::Close))
    }

    /// Sends `SSH_MSG_CHANNEL_CLOSE` now, dropping whatever is still queued for the channel.
    pub fn channel_abort(&mut self, channel: ChannelId) -> Vec<Action> {
        self.transport.channels(|c| c.abort(channel))
    }

    /// Sends a channel request, opaque, once everything queued before it has gone. A reply,
    /// when asked for, arrives as [`Action::ChannelRequestReply`].
    pub fn channel_request(
        &mut self,
        channel: ChannelId,
        kind: &str,
        want_reply: bool,
        data: Vec<u8>,
    ) -> Vec<Action> {
        self.transport
            .channels(|c| c.enqueue(channel, OutKind::Request(kind.to_owned(), want_reply, data)))
    }

    /// Answers a channel request. Replies leave in the order the requests arrived, whatever
    /// order they are given in.
    pub fn reply_channel_request(&mut self, token: ReplyToken, ok: bool) -> Vec<Action> {
        self.transport.channels(|c| c.reply(token, ok))
    }

    /// Reports that `bytes` of the data received on `channel` have been taken, so the peer's
    /// window can be given back.
    pub fn channel_consumed(&mut self, channel: ChannelId, bytes: u32) -> Vec<Action> {
        self.transport.channels(|c| c.consumed(channel, bytes))
    }

    /// The channel's type, the peer's window and maximum packet, and what is queued.
    pub fn channel_info(&self, channel: ChannelId) -> Option<ChannelInfo> {
        self.transport.channel_info(channel)
    }
}
