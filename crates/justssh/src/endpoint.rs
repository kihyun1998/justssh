//! The connection protocol both roles drive once authenticated, as one trait over [`Server`]
//! and [`Client`](crate::Client).

use crate::connection::{
    ChannelId, ChannelInfo, GlobalReplyToken, OpenFailureReason, ReplyToken, RequestToken,
};
use crate::event::{Action, DisconnectReason, Event, Phase};

#[cfg(doc)]
use crate::Server;

mod sealed {
    pub trait Sealed {}
}

/// A [`Server`] or [`Client`](crate::Client): what an adapter needs to run either through the
/// connection protocol. Each method is the inherent method of the same name.
pub trait Endpoint: sealed::Sealed {
    fn process(&mut self, event: Event<'_>) -> Vec<Action>;
    fn phase(&self) -> Phase;
    fn disconnect(&mut self, reason: DisconnectReason, description: &str) -> Vec<Action>;
    fn open_channel(&mut self, kind: &str, data: Vec<u8>) -> (Option<ChannelId>, Vec<Action>);
    fn accept_channel(&mut self, channel: ChannelId, data: Vec<u8>) -> Vec<Action>;
    fn reject_channel(
        &mut self,
        channel: ChannelId,
        reason: OpenFailureReason,
        description: &str,
    ) -> Vec<Action>;
    fn channel_data(&mut self, channel: ChannelId, data: &[u8]) -> Vec<Action>;
    fn channel_extended_data(&mut self, channel: ChannelId, code: u32, data: &[u8]) -> Vec<Action>;
    fn channel_eof(&mut self, channel: ChannelId) -> Vec<Action>;
    fn channel_close(&mut self, channel: ChannelId) -> Vec<Action>;
    fn channel_abort(&mut self, channel: ChannelId) -> Vec<Action>;
    fn channel_request(
        &mut self,
        channel: ChannelId,
        kind: &str,
        want_reply: bool,
        data: Vec<u8>,
    ) -> (Option<RequestToken>, Vec<Action>);
    fn reply_channel_request(&mut self, token: ReplyToken, ok: bool) -> Vec<Action>;
    fn global_request(
        &mut self,
        kind: &str,
        want_reply: bool,
        data: Vec<u8>,
    ) -> (Option<RequestToken>, Vec<Action>);
    fn reply_global_request(
        &mut self,
        token: GlobalReplyToken,
        ok: bool,
        data: Vec<u8>,
    ) -> Vec<Action>;
    fn channel_consumed(&mut self, channel: ChannelId, bytes: u32) -> Vec<Action>;
    fn channel_info(&self, channel: ChannelId) -> Option<ChannelInfo>;
}

/// The connection-protocol methods, written once for both roles; expands inside `impl` blocks
/// of types holding a `transport`.
macro_rules! connection_methods {
    () => {
        /// Opens a channel of type `kind` with its type-specific `data`, returning its id; the
        /// peer's answer arrives as [`Action::ChannelOpened`] or [`Action::ChannelOpenFailed`].
        /// Commands for the channel wait in order until it is opened, and are dropped if it is
        /// refused. Before authentication nothing is sent and the id is `None`.
        pub fn open_channel(
            &mut self,
            kind: &str,
            data: Vec<u8>,
        ) -> (Option<$crate::ChannelId>, Vec<Action>) {
            self.transport.channels_with(|c| c.open_channel(kind, data))
        }

        /// Sends a global request, opaque. When it wants a reply, the token returned comes back
        /// with it in [`Action::GlobalRequestReply`].
        pub fn global_request(
            &mut self,
            kind: &str,
            want_reply: bool,
            data: Vec<u8>,
        ) -> (Option<$crate::RequestToken>, Vec<Action>) {
            self.transport
                .channels_with(|c| c.global_request(kind, want_reply, data))
        }

        /// Answers a global request with `data` after the message number. Replies leave in the
        /// order the requests arrived, whatever order they are given in; a token of another
        /// connection answers nothing.
        pub fn reply_global_request(
            &mut self,
            token: $crate::GlobalReplyToken,
            ok: bool,
            data: Vec<u8>,
        ) -> Vec<Action> {
            self.transport.channels(|c| c.global_reply(token, ok, data))
        }

        /// Accepts the peer's channel open; `data` is the channel-type-specific part of the
        /// confirmation, usually empty.
        pub fn accept_channel(&mut self, channel: $crate::ChannelId, data: Vec<u8>) -> Vec<Action> {
            self.transport.channels(|c| c.accept(channel, data))
        }

        pub fn reject_channel(
            &mut self,
            channel: $crate::ChannelId,
            reason: $crate::OpenFailureReason,
            description: &str,
        ) -> Vec<Action> {
            self.transport
                .channels(|c| c.reject(channel, reason, description))
        }

        /// Sends `data` on `channel` after anything already queued there, as the peer's window
        /// allows. Commands for a channel that is not open, or that this side has closed, are
        /// dropped.
        pub fn channel_data(&mut self, channel: $crate::ChannelId, data: &[u8]) -> Vec<Action> {
            self.transport
                .channels(|c| c.enqueue(channel, $crate::connection::OutKind::Data(data.to_vec())))
        }

        /// Sends extended data of type `code` (1 is stderr), in order like data.
        pub fn channel_extended_data(
            &mut self,
            channel: $crate::ChannelId,
            code: u32,
            data: &[u8],
        ) -> Vec<Action> {
            self.transport.channels(|c| {
                c.enqueue(
                    channel,
                    $crate::connection::OutKind::Extended(code, data.to_vec()),
                )
            })
        }

        /// Sends `SSH_MSG_CHANNEL_EOF` once everything queued before it has gone.
        pub fn channel_eof(&mut self, channel: $crate::ChannelId) -> Vec<Action> {
            self.transport
                .channels(|c| c.enqueue(channel, $crate::connection::OutKind::Eof))
        }

        /// Sends `SSH_MSG_CHANNEL_CLOSE` once everything queued before it has gone.
        pub fn channel_close(&mut self, channel: $crate::ChannelId) -> Vec<Action> {
            self.transport
                .channels(|c| c.enqueue(channel, $crate::connection::OutKind::Close))
        }

        /// Sends `SSH_MSG_CHANNEL_CLOSE` now, dropping whatever is still queued for the channel.
        pub fn channel_abort(&mut self, channel: $crate::ChannelId) -> Vec<Action> {
            self.transport.channels(|c| c.abort(channel))
        }

        /// Sends a channel request, opaque, once everything queued before it has gone. When it
        /// wants a reply, the token returned comes back with it in
        /// [`Action::ChannelRequestReply`]; when the channel closes, is aborted or is refused
        /// first, that reply is a failure. A request on a channel that is not open or opening
        /// is dropped and has no token.
        pub fn channel_request(
            &mut self,
            channel: $crate::ChannelId,
            kind: &str,
            want_reply: bool,
            data: Vec<u8>,
        ) -> (Option<$crate::RequestToken>, Vec<Action>) {
            self.transport
                .channels_with(|c| c.request(channel, kind, want_reply, data))
        }

        /// Answers a channel request. Replies leave in the order the requests arrived, whatever
        /// order they are given in; a token of another connection answers nothing.
        pub fn reply_channel_request(
            &mut self,
            token: $crate::ReplyToken,
            ok: bool,
        ) -> Vec<Action> {
            self.transport.channels(|c| c.reply(token, ok))
        }

        /// Reports that `bytes` of the data received on `channel` have been taken, so the peer's
        /// window can be given back.
        pub fn channel_consumed(&mut self, channel: $crate::ChannelId, bytes: u32) -> Vec<Action> {
            self.transport.channels(|c| c.consumed(channel, bytes))
        }

        /// The channel's type, the peer's window and maximum packet, and what is queued.
        pub fn channel_info(&self, channel: $crate::ChannelId) -> Option<$crate::ChannelInfo> {
            self.transport.channel_info(channel)
        }
    };
}

/// Implements [`Endpoint`] for `$t` by its inherent methods.
macro_rules! impl_endpoint {
    ($t:ty) => {
        impl $crate::endpoint::Sealed for $t {}

        impl $crate::Endpoint for $t {
            fn process(&mut self, event: Event<'_>) -> Vec<Action> {
                <$t>::process(self, event)
            }
            fn phase(&self) -> Phase {
                <$t>::phase(self)
            }
            fn disconnect(&mut self, reason: DisconnectReason, description: &str) -> Vec<Action> {
                <$t>::disconnect(self, reason, description)
            }
            fn open_channel(
                &mut self,
                kind: &str,
                data: Vec<u8>,
            ) -> (Option<$crate::ChannelId>, Vec<Action>) {
                <$t>::open_channel(self, kind, data)
            }
            fn accept_channel(&mut self, channel: $crate::ChannelId, data: Vec<u8>) -> Vec<Action> {
                <$t>::accept_channel(self, channel, data)
            }
            fn reject_channel(
                &mut self,
                channel: $crate::ChannelId,
                reason: $crate::OpenFailureReason,
                description: &str,
            ) -> Vec<Action> {
                <$t>::reject_channel(self, channel, reason, description)
            }
            fn channel_data(&mut self, channel: $crate::ChannelId, data: &[u8]) -> Vec<Action> {
                <$t>::channel_data(self, channel, data)
            }
            fn channel_extended_data(
                &mut self,
                channel: $crate::ChannelId,
                code: u32,
                data: &[u8],
            ) -> Vec<Action> {
                <$t>::channel_extended_data(self, channel, code, data)
            }
            fn channel_eof(&mut self, channel: $crate::ChannelId) -> Vec<Action> {
                <$t>::channel_eof(self, channel)
            }
            fn channel_close(&mut self, channel: $crate::ChannelId) -> Vec<Action> {
                <$t>::channel_close(self, channel)
            }
            fn channel_abort(&mut self, channel: $crate::ChannelId) -> Vec<Action> {
                <$t>::channel_abort(self, channel)
            }
            fn channel_request(
                &mut self,
                channel: $crate::ChannelId,
                kind: &str,
                want_reply: bool,
                data: Vec<u8>,
            ) -> (Option<$crate::RequestToken>, Vec<Action>) {
                <$t>::channel_request(self, channel, kind, want_reply, data)
            }
            fn reply_channel_request(
                &mut self,
                token: $crate::ReplyToken,
                ok: bool,
            ) -> Vec<Action> {
                <$t>::reply_channel_request(self, token, ok)
            }
            fn global_request(
                &mut self,
                kind: &str,
                want_reply: bool,
                data: Vec<u8>,
            ) -> (Option<$crate::RequestToken>, Vec<Action>) {
                <$t>::global_request(self, kind, want_reply, data)
            }
            fn reply_global_request(
                &mut self,
                token: $crate::GlobalReplyToken,
                ok: bool,
                data: Vec<u8>,
            ) -> Vec<Action> {
                <$t>::reply_global_request(self, token, ok, data)
            }
            fn channel_consumed(&mut self, channel: $crate::ChannelId, bytes: u32) -> Vec<Action> {
                <$t>::channel_consumed(self, channel, bytes)
            }
            fn channel_info(&self, channel: $crate::ChannelId) -> Option<$crate::ChannelInfo> {
                <$t>::channel_info(self, channel)
            }
        }
    };
}

pub(crate) use sealed::Sealed;
pub(crate) use {connection_methods, impl_endpoint};
