//! The connection protocol (RFC 4254), shared by both roles: global requests (§4) and channels
//! (§5). Requests and channel opens pass through opaque (ADR-0001); the table keeps ids,
//! windows, reply order and the per-channel order of what the consumer sends.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};

use justssh_wire::{
    ChannelClose, ChannelData, ChannelEof, ChannelExtendedData, ChannelFailure, ChannelOpen,
    ChannelOpenConfirmation, ChannelOpenFailure, ChannelRequest as WireRequest, ChannelSuccess,
    ChannelWindowAdjust, GlobalRequest as WireGlobalRequest, Message, RequestFailure,
    RequestSuccess,
};

use crate::event::{Action, DisconnectReason, Error};

/// A channel, as this side numbers it on one connection; commands given the id of a channel on
/// another connection do nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChannelId {
    connection: u64,
    id: u32,
}

impl ChannelId {
    /// The number this side uses for the channel on the wire.
    pub fn get(self) -> u32 {
        self.id
    }
}

/// The connection a token belongs to; tokens of another connection answer nothing.
static NEXT_CONNECTION: AtomicU64 = AtomicU64::new(0);

/// Identifies a received channel request that asked for a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReplyToken {
    connection: u64,
    channel: u32,
    seq: u64,
}

/// Identifies a received global request that asked for a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GlobalReplyToken {
    connection: u64,
    seq: u64,
}

/// Identifies a channel or global request this side sent with `want_reply`; its reply carries
/// the same token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestToken {
    connection: u64,
    seq: u64,
}

/// A global request from the peer. When it wants a reply, answer it through `reply`.
#[derive(Debug, Clone)]
pub struct GlobalRequest {
    kind: String,
    want_reply: bool,
    data: Vec<u8>,
    reply: Option<GlobalReplyToken>,
}

impl GlobalRequest {
    /// The request name, such as `tcpip-forward` or `keepalive@openssh.com`.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn want_reply(&self) -> bool {
        self.want_reply
    }

    /// The request-specific data, as sent.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// The token to answer with, when the peer wants a reply.
    pub fn reply(&self) -> Option<GlobalReplyToken> {
        self.reply
    }
}

/// An `SSH_MSG_CHANNEL_OPEN_FAILURE` reason code (RFC 4254 §5.1).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpenFailureReason(u32);

impl OpenFailureReason {
    pub const ADMINISTRATIVELY_PROHIBITED: Self = Self(1);
    pub const CONNECT_FAILED: Self = Self(2);
    pub const UNKNOWN_CHANNEL_TYPE: Self = Self(3);
    pub const RESOURCE_SHORTAGE: Self = Self(4);

    /// The reason with numeric code `code`, including codes this crate has no name for.
    pub const fn from_code(code: u32) -> Self {
        Self(code)
    }

    pub const fn code(self) -> u32 {
        self.0
    }
}

/// The peer asks to open a channel; answer with `accept_channel` or `reject_channel`.
#[derive(Debug, Clone)]
pub struct ChannelOpenRequest {
    channel: ChannelId,
    kind: String,
    data: Vec<u8>,
    peer_window: u32,
    peer_max_packet: u32,
}

impl ChannelOpenRequest {
    pub fn channel(&self) -> ChannelId {
        self.channel
    }

    /// The channel type, such as `session` or `direct-tcpip`.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// The channel-type-specific data, as sent.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn peer_window(&self) -> u32 {
        self.peer_window
    }

    pub fn peer_max_packet(&self) -> u32 {
        self.peer_max_packet
    }
}

/// A channel request from the peer. When it wants a reply, answer it through `reply`.
#[derive(Debug, Clone)]
pub struct ChannelRequest {
    channel: ChannelId,
    kind: String,
    want_reply: bool,
    data: Vec<u8>,
    reply: Option<ReplyToken>,
}

impl ChannelRequest {
    pub fn channel(&self) -> ChannelId {
        self.channel
    }

    /// The request type, such as `pty-req` or `exec`.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn want_reply(&self) -> bool {
        self.want_reply
    }

    /// The request-type-specific data, as sent.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// The token to answer with, when the peer wants a reply.
    pub fn reply(&self) -> Option<ReplyToken> {
        self.reply
    }
}

/// What is known about an open channel.
#[derive(Debug, Clone)]
pub struct ChannelInfo {
    kind: String,
    peer_window: u32,
    peer_max_packet: u32,
    queued: usize,
}

impl ChannelInfo {
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Bytes the peer will still accept before adjusting its window.
    pub fn peer_window(&self) -> u32 {
        self.peer_window
    }

    pub fn peer_max_packet(&self) -> u32 {
        self.peer_max_packet
    }

    /// Data and extended data bytes waiting for window space.
    pub fn queued(&self) -> usize {
        self.queued
    }
}

/// One thing the channel table wants done.
pub(crate) enum Step {
    Send(Message),
    Emit(Action),
    Fail(DisconnectReason, Error),
}

/// What the consumer has handed a channel, in order.
enum Out {
    /// Data with extended type `code` (`None` for plain data), of which `sent` bytes are gone.
    Data {
        code: Option<u32>,
        bytes: Vec<u8>,
        sent: usize,
    },
    Eof,
    /// A request, with the sequence number of its token when it wants a reply.
    Request(String, Option<u64>, Vec<u8>),
    Close,
}

struct Channel {
    this: ChannelId,
    peer_id: u32,
    kind: String,
    /// Open in both directions: accepted by the consumer, or confirmed by the peer.
    accepted: bool,
    /// Opened by this side, awaiting the peer's confirmation.
    opening: bool,
    peer_window: u32,
    peer_max_packet: u32,
    window: u32,
    consumed: u32,
    queue: VecDeque<Out>,
    /// Received requests awaiting a reply, in arrival order, with the reply once given.
    replies: VecDeque<(u64, Option<bool>)>,
    /// Sent requests that asked for a reply and have not had one, as token sequence numbers.
    awaiting: VecDeque<u64>,
    sent_close: bool,
    got_eof: bool,
}

pub(crate) struct Channels {
    connection: u64,
    window: u32,
    max_packet: u32,
    next_id: u32,
    next_seq: u64,
    open: BTreeMap<u32, Channel>,
    /// Received global requests awaiting a reply, in arrival order, with the reply once given.
    global_replies: VecDeque<(u64, Option<GlobalReply>)>,
    /// Sent global requests that asked for a reply and have not had one, as token sequence
    /// numbers.
    global_awaiting: VecDeque<u64>,
    /// Whether a key exchange is under way: what is queued on channels waits until it ends.
    paused: bool,
}

/// A global reply the consumer has given: success and the data after the message number.
type GlobalReply = (bool, Vec<u8>);

/// Smallest and largest maximum packet a peer may announce, as x/crypto/ssh accepts.
const PEER_MAX_PACKET: core::ops::RangeInclusive<u32> = 9..=1 << 31;

impl Channels {
    pub(crate) fn new(window: u32, max_packet: u32) -> Self {
        Channels {
            connection: NEXT_CONNECTION.fetch_add(1, Ordering::Relaxed),
            window,
            max_packet,
            next_id: 0,
            next_seq: 0,
            open: BTreeMap::new(),
            global_replies: VecDeque::new(),
            global_awaiting: VecDeque::new(),
            paused: false,
        }
    }

    fn seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        seq
    }

    /// The next channel id not in use.
    fn allocate(&mut self) -> u32 {
        let mut id = self.next_id;
        while self.open.contains_key(&id) {
            id = id.wrapping_add(1);
        }
        self.next_id = id.wrapping_add(1);
        id
    }

    fn channel(
        &self,
        id: u32,
        peer_id: u32,
        kind: String,
        peer_window: u32,
        peer_max_packet: u32,
    ) -> Channel {
        Channel {
            this: ChannelId {
                connection: self.connection,
                id,
            },
            peer_id,
            kind,
            accepted: false,
            opening: false,
            peer_window,
            peer_max_packet,
            window: self.window,
            consumed: 0,
            queue: VecDeque::new(),
            replies: VecDeque::new(),
            awaiting: VecDeque::new(),
            sent_close: false,
            got_eof: false,
        }
    }

    /// The number of `id` when it belongs to this connection.
    fn local(&self, id: ChannelId) -> Option<u32> {
        (id.connection == self.connection).then_some(id.id)
    }

    /// Holds what is queued on channels until [`resume`](Self::resume).
    pub(crate) fn pause(&mut self) {
        self.paused = true;
    }

    /// Sends what the windows allow of what was held.
    pub(crate) fn resume(&mut self) -> Vec<Step> {
        self.paused = false;
        let mut steps = Vec::new();
        for c in self.open.values_mut() {
            flush(c, &mut steps);
        }
        steps
    }

    pub(crate) fn info(&self, id: ChannelId) -> Option<ChannelInfo> {
        self.open.get(&self.local(id)?).map(|c| ChannelInfo {
            kind: c.kind.clone(),
            peer_window: c.peer_window,
            peer_max_packet: c.peer_max_packet,
            queued: c
                .queue
                .iter()
                .map(|o| match o {
                    Out::Data { bytes, sent, .. } => bytes.len() - sent,
                    _ => 0,
                })
                .sum(),
        })
    }

    /// Handles a received connection-protocol message.
    pub(crate) fn handle(&mut self, message: Message) -> Vec<Step> {
        let mut steps = Vec::new();
        let connection = self.connection;
        let channel_id = |id| ChannelId { connection, id };
        match message {
            Message::GlobalRequest(r) => {
                let seq = self.seq();
                let connection = self.connection;
                let reply = r.want_reply.then(|| {
                    self.global_replies.push_back((seq, None));
                    GlobalReplyToken { connection, seq }
                });
                steps.push(Step::Emit(Action::GlobalRequest(GlobalRequest {
                    kind: r.kind,
                    want_reply: r.want_reply,
                    data: r.data,
                    reply,
                })));
            }
            m @ (Message::RequestSuccess(_) | Message::RequestFailure(_)) => {
                let (ok, data) = match m {
                    Message::RequestSuccess(s) => (true, s.data),
                    Message::RequestFailure(f) => (false, f.data),
                    _ => unreachable!(),
                };
                if let Some(seq) = self.global_awaiting.pop_front() {
                    let token = RequestToken {
                        connection: self.connection,
                        seq,
                    };
                    steps.push(Step::Emit(Action::GlobalRequestReply { token, ok, data }));
                }
            }
            Message::ChannelOpen(o) => {
                if !PEER_MAX_PACKET.contains(&o.max_packet) {
                    steps.push(Step::Send(Message::ChannelOpenFailure(
                        ChannelOpenFailure::new(
                            o.sender,
                            OpenFailureReason::CONNECT_FAILED.code(),
                            "invalid request",
                            "",
                        ),
                    )));
                    return steps;
                }
                let id = self.allocate();
                let channel = self.channel(id, o.sender, o.kind.clone(), o.window, o.max_packet);
                self.open.insert(id, channel);
                steps.push(Step::Emit(Action::ChannelOpenRequest(ChannelOpenRequest {
                    channel: channel_id(id),
                    kind: o.kind,
                    data: o.data,
                    peer_window: o.window,
                    peer_max_packet: o.max_packet,
                })));
            }
            Message::ChannelWindowAdjust(a) => {
                let paused = self.paused;
                let Some(c) = self.accepted(a.recipient, &mut steps) else {
                    return steps;
                };
                match c.peer_window.checked_add(a.bytes) {
                    Some(w) => c.peer_window = w,
                    None => {
                        steps.push(Step::Fail(
                            DisconnectReason::PROTOCOL_ERROR,
                            Error::ChannelWindowOverflow,
                        ));
                        return steps;
                    }
                }
                if !paused {
                    flush(c, &mut steps);
                }
            }
            Message::ChannelData(d) => self.data(d.recipient, None, d.data, &mut steps),
            Message::ChannelExtendedData(e) => {
                self.data(e.recipient, Some(e.code), e.data, &mut steps)
            }
            Message::ChannelEof(e) => {
                let Some(c) = self.accepted(e.recipient, &mut steps) else {
                    return steps;
                };
                if !c.sent_close && !c.got_eof {
                    c.got_eof = true;
                    let channel = channel_id(e.recipient);
                    steps.push(Step::Emit(Action::ChannelEof { channel }));
                }
            }
            Message::ChannelClose(m) => {
                let Some(c) = self.accepted(m.recipient, &mut steps) else {
                    return steps;
                };
                if !c.sent_close {
                    steps.push(Step::Send(Message::ChannelClose(ChannelClose::new(
                        c.peer_id,
                    ))));
                }
                fail_awaiting(c, &mut steps);
                fail_queued(c, &mut steps);
                self.open.remove(&m.recipient);
                let channel = channel_id(m.recipient);
                steps.push(Step::Emit(Action::ChannelClosed { channel }));
            }
            Message::ChannelRequest(r) => {
                let (seq, connection) = (self.next_seq, self.connection);
                let Some(c) = self.accepted(r.recipient, &mut steps) else {
                    return steps;
                };
                if c.sent_close {
                    return steps;
                }
                let reply = r.want_reply.then(|| {
                    c.replies.push_back((seq, None));
                    ReplyToken {
                        connection,
                        channel: r.recipient,
                        seq,
                    }
                });
                self.next_seq += 1;
                steps.push(Step::Emit(Action::ChannelRequest(ChannelRequest {
                    channel: channel_id(r.recipient),
                    kind: r.kind,
                    want_reply: r.want_reply,
                    data: r.data,
                    reply,
                })));
            }
            Message::ChannelSuccess(ChannelSuccess { recipient, .. })
            | Message::ChannelFailure(ChannelFailure { recipient, .. }) => {
                let ok = matches!(message, Message::ChannelSuccess(_));
                let connection = self.connection;
                let Some(c) = self.accepted(recipient, &mut steps) else {
                    return steps;
                };
                let Some(seq) = c.awaiting.pop_front() else {
                    return steps;
                };
                let channel = channel_id(recipient);
                let token = RequestToken { connection, seq };
                steps.push(Step::Emit(Action::ChannelRequestReply {
                    channel,
                    token,
                    ok,
                }));
            }
            Message::ChannelOpenConfirmation(m) => {
                let Some(c) = self.open.get_mut(&m.recipient).filter(|c| c.opening) else {
                    steps.push(Step::Fail(
                        DisconnectReason::PROTOCOL_ERROR,
                        Error::UnknownChannel {
                            channel: m.recipient,
                        },
                    ));
                    return steps;
                };
                if !PEER_MAX_PACKET.contains(&m.max_packet) {
                    steps.push(Step::Fail(
                        DisconnectReason::PROTOCOL_ERROR,
                        Error::InvalidChannelMaxPacket,
                    ));
                    return steps;
                }
                c.opening = false;
                c.accepted = true;
                c.peer_id = m.sender;
                c.peer_window = m.window;
                c.peer_max_packet = m.max_packet;
                steps.push(Step::Emit(Action::ChannelOpened {
                    channel: channel_id(m.recipient),
                    data: m.data,
                }));
                if !self.paused {
                    flush(c, &mut steps);
                }
            }
            Message::ChannelOpenFailure(m) => {
                let Some(c) = self.open.get_mut(&m.recipient).filter(|c| c.opening) else {
                    steps.push(Step::Fail(
                        DisconnectReason::PROTOCOL_ERROR,
                        Error::UnknownChannel {
                            channel: m.recipient,
                        },
                    ));
                    return steps;
                };
                fail_queued(c, &mut steps);
                self.open.remove(&m.recipient);
                steps.push(Step::Emit(Action::ChannelOpenFailed {
                    channel: channel_id(m.recipient),
                    reason: OpenFailureReason(m.reason),
                    description: m.description,
                }));
            }
            _ => {}
        }
        steps
    }

    /// The accepted channel `id`, or a failure step when there is none.
    fn accepted(&mut self, id: u32, steps: &mut Vec<Step>) -> Option<&mut Channel> {
        match self.open.get_mut(&id) {
            Some(c) if c.accepted => Some(c),
            _ => {
                steps.push(Step::Fail(
                    DisconnectReason::PROTOCOL_ERROR,
                    Error::UnknownChannel { channel: id },
                ));
                None
            }
        }
    }

    fn data(&mut self, id: u32, code: Option<u32>, data: Vec<u8>, steps: &mut Vec<Step>) {
        let (max_packet, connection) = (self.max_packet, self.connection);
        let Some(c) = self.accepted(id, steps) else {
            return;
        };
        let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        if len > max_packet {
            steps.push(Step::Fail(
                DisconnectReason::PROTOCOL_ERROR,
                Error::ChannelPacketTooLarge,
            ));
            return;
        }
        if len > c.window {
            steps.push(Step::Fail(
                DisconnectReason::PROTOCOL_ERROR,
                Error::ChannelWindowExceeded,
            ));
            return;
        }
        c.window -= len;
        if c.sent_close || data.is_empty() {
            return;
        }
        let channel = ChannelId { connection, id };
        steps.push(Step::Emit(match code {
            None => Action::ChannelData { channel, data },
            Some(code) => Action::ChannelExtendedData {
                channel,
                code,
                data,
            },
        }));
    }

    /// Opens a channel of type `kind`; the peer's answer arrives as [`Action::ChannelOpened`] or
    /// [`Action::ChannelOpenFailed`].
    pub(crate) fn open_channel(
        &mut self,
        kind: &str,
        data: Vec<u8>,
    ) -> (Option<ChannelId>, Vec<Step>) {
        let id = self.allocate();
        let mut channel = self.channel(id, 0, kind.to_owned(), 0, 0);
        channel.opening = true;
        self.open.insert(id, channel);
        let open = ChannelOpen::new(kind.to_owned(), id, self.window, self.max_packet, data);
        let this = ChannelId {
            connection: self.connection,
            id,
        };
        (Some(this), vec![Step::Send(Message::ChannelOpen(open))])
    }

    pub(crate) fn accept(&mut self, id: ChannelId, data: Vec<u8>) -> Vec<Step> {
        let Some(n) = self.local(id) else {
            return Vec::new();
        };
        let (window, max_packet) = (self.window, self.max_packet);
        let Some(c) = self.open.get_mut(&n).filter(|c| !c.accepted && !c.opening) else {
            return Vec::new();
        };
        c.accepted = true;
        vec![Step::Send(Message::ChannelOpenConfirmation(
            ChannelOpenConfirmation::new(c.peer_id, n, window, max_packet, data),
        ))]
    }

    pub(crate) fn reject(
        &mut self,
        id: ChannelId,
        reason: OpenFailureReason,
        description: &str,
    ) -> Vec<Step> {
        let Some(n) = self.local(id) else {
            return Vec::new();
        };
        match self.open.get(&n) {
            Some(c) if !c.accepted && !c.opening => {
                let peer_id = c.peer_id;
                self.open.remove(&n);
                vec![Step::Send(Message::ChannelOpenFailure(
                    ChannelOpenFailure::new(peer_id, reason.code(), description, ""),
                ))]
            }
            _ => Vec::new(),
        }
    }

    /// Queues `out` on channel `id` and sends what the window allows; a channel this side is
    /// opening keeps it until confirmed. Nothing happens for a channel that is not open or
    /// opening, or that this side has closed.
    pub(crate) fn enqueue(&mut self, id: ChannelId, out: OutKind) -> Vec<Step> {
        let Some(n) = self.local(id) else {
            return Vec::new();
        };
        let mut steps = Vec::new();
        let Some(c) = self
            .open
            .get_mut(&n)
            .filter(|c| (c.accepted || c.opening) && !c.sent_close)
        else {
            return steps;
        };
        let out = match out {
            OutKind::Data(d) if d.is_empty() => return steps,
            OutKind::Extended(_, d) if d.is_empty() => return steps,
            OutKind::Data(bytes) => Out::Data {
                code: None,
                bytes,
                sent: 0,
            },
            OutKind::Extended(code, bytes) => Out::Data {
                code: Some(code),
                bytes,
                sent: 0,
            },
            OutKind::Eof => Out::Eof,
            OutKind::Close => Out::Close,
        };
        c.queue.push_back(out);
        if !self.paused {
            flush(c, &mut steps);
        }
        steps
    }

    /// Queues a request on channel `id`; the token, when it wants a reply, comes back with the
    /// reply. Nothing happens for a channel that is not open or that this side has closed.
    pub(crate) fn request(
        &mut self,
        id: ChannelId,
        kind: &str,
        want_reply: bool,
        data: Vec<u8>,
    ) -> (Option<RequestToken>, Vec<Step>) {
        let (seq, connection) = (self.next_seq, self.connection);
        let mut steps = Vec::new();
        let Some(n) = self.local(id) else {
            return (None, steps);
        };
        let Some(c) = self
            .open
            .get_mut(&n)
            .filter(|c| (c.accepted || c.opening) && !c.sent_close)
        else {
            return (None, steps);
        };
        let token = want_reply.then_some(RequestToken { connection, seq });
        c.queue.push_back(Out::Request(
            kind.to_owned(),
            want_reply.then_some(seq),
            data,
        ));
        if !self.paused {
            flush(c, &mut steps);
        }
        if want_reply {
            self.next_seq += 1;
        }
        (token, steps)
    }

    /// Sends `SSH_MSG_CHANNEL_CLOSE` now, dropping whatever is still queued.
    pub(crate) fn abort(&mut self, id: ChannelId) -> Vec<Step> {
        let Some(n) = self.local(id) else {
            return Vec::new();
        };
        let Some(c) = self
            .open
            .get_mut(&n)
            .filter(|c| (c.accepted || c.opening) && !c.sent_close)
        else {
            return Vec::new();
        };
        let mut steps = Vec::new();
        fail_queued(c, &mut steps);
        c.queue.clear();
        c.queue.push_back(Out::Close);
        if !self.paused {
            flush(c, &mut steps);
        }
        steps
    }

    pub(crate) fn reply(&mut self, token: ReplyToken, ok: bool) -> Vec<Step> {
        let mut steps = Vec::new();
        if token.connection != self.connection {
            return steps;
        }
        let Some(c) = self.open.get_mut(&token.channel) else {
            return steps;
        };
        if let Some(entry) = c.replies.iter_mut().find(|(seq, _)| *seq == token.seq) {
            entry.1.get_or_insert(ok);
        }
        while let Some(&(_, Some(ok))) = c.replies.front() {
            c.replies.pop_front();
            if c.sent_close {
                continue;
            }
            steps.push(Step::Send(if ok {
                Message::ChannelSuccess(ChannelSuccess::new(c.peer_id))
            } else {
                Message::ChannelFailure(ChannelFailure::new(c.peer_id))
            }));
        }
        steps
    }

    /// Sends a global request at once; the token, when it wants a reply, comes back with the
    /// reply.
    pub(crate) fn global_request(
        &mut self,
        kind: &str,
        want_reply: bool,
        data: Vec<u8>,
    ) -> (Option<RequestToken>, Vec<Step>) {
        let token = want_reply.then(|| {
            let seq = self.seq();
            self.global_awaiting.push_back(seq);
            RequestToken {
                connection: self.connection,
                seq,
            }
        });
        let request = WireGlobalRequest::new(kind.to_owned(), want_reply, data);
        (token, vec![Step::Send(Message::GlobalRequest(request))])
    }

    pub(crate) fn global_reply(
        &mut self,
        token: GlobalReplyToken,
        ok: bool,
        data: Vec<u8>,
    ) -> Vec<Step> {
        if token.connection != self.connection {
            return Vec::new();
        }
        if let Some(entry) = self
            .global_replies
            .iter_mut()
            .find(|(seq, _)| *seq == token.seq)
        {
            entry.1.get_or_insert((ok, data));
        }
        let mut steps = Vec::new();
        while let Some((_, Some(_))) = self.global_replies.front() {
            let Some((_, Some((ok, data)))) = self.global_replies.pop_front() else {
                unreachable!()
            };
            steps.push(Step::Send(if ok {
                Message::RequestSuccess(RequestSuccess::new(data))
            } else {
                Message::RequestFailure(RequestFailure::new(data))
            }));
        }
        steps
    }

    /// Records that the consumer has taken `n` bytes from channel `id`, and gives window back
    /// once more than three maximum packets have been taken or the window is below half.
    pub(crate) fn consumed(&mut self, id: ChannelId, n: u32) -> Vec<Step> {
        let Some(local) = self.local(id) else {
            return Vec::new();
        };
        let (full, max_packet) = (self.window, self.max_packet);
        let Some(c) = self
            .open
            .get_mut(&local)
            .filter(|c| c.accepted && !c.sent_close)
        else {
            return Vec::new();
        };
        let room = full - c.window - c.consumed;
        c.consumed += n.min(room);
        if c.consumed > 0 && (full - c.window > 3 * max_packet || c.window < full / 2) {
            let bytes = std::mem::take(&mut c.consumed);
            c.window += bytes;
            return vec![Step::Send(Message::ChannelWindowAdjust(
                ChannelWindowAdjust::new(c.peer_id, bytes),
            ))];
        }
        Vec::new()
    }
}

/// What the consumer can hand a channel.
pub(crate) enum OutKind {
    Data(Vec<u8>),
    Extended(u32, Vec<u8>),
    Eof,
    Close,
}

/// Sends from the front of `c`'s queue for as long as the peer's window allows, once the channel
/// is open. Data is split at the peer's maximum packet; nothing overtakes data the window holds
/// back.
fn flush(c: &mut Channel, steps: &mut Vec<Step>) {
    if !c.accepted {
        return;
    }
    while let Some(front) = c.queue.front_mut() {
        match front {
            Out::Data { code, bytes, sent } => {
                let n = (bytes.len() - *sent)
                    .min(c.peer_window as usize)
                    .min(c.peer_max_packet as usize);
                if n == 0 {
                    return;
                }
                let chunk = bytes[*sent..*sent + n].to_vec();
                *sent += n;
                c.peer_window -= n as u32;
                steps.push(Step::Send(match code {
                    Some(code) => Message::ChannelExtendedData(ChannelExtendedData::new(
                        c.peer_id, *code, chunk,
                    )),
                    None => Message::ChannelData(ChannelData::new(c.peer_id, chunk)),
                }));
                if *sent == bytes.len() {
                    c.queue.pop_front();
                }
            }
            Out::Eof => {
                steps.push(Step::Send(Message::ChannelEof(ChannelEof::new(c.peer_id))));
                c.queue.pop_front();
            }
            Out::Request(..) => {
                let Some(Out::Request(kind, reply, data)) = c.queue.pop_front() else {
                    unreachable!()
                };
                if let Some(seq) = reply {
                    c.awaiting.push_back(seq);
                }
                steps.push(Step::Send(Message::ChannelRequest(WireRequest::new(
                    c.peer_id,
                    kind,
                    reply.is_some(),
                    data,
                ))));
            }
            Out::Close => {
                steps.push(Step::Send(Message::ChannelClose(ChannelClose::new(
                    c.peer_id,
                ))));
                c.queue.pop_front();
                fail_queued(c, steps);
                c.queue.clear();
                c.sent_close = true;
                return;
            }
        }
    }
}

/// A failed reply to the request `seq` on `c`.
fn failed(c: &Channel, seq: u64) -> Step {
    let token = RequestToken {
        connection: c.this.connection,
        seq,
    };
    Step::Emit(Action::ChannelRequestReply {
        channel: c.this,
        token,
        ok: false,
    })
}

/// Fails every request on `c` sent with `want_reply` and not yet answered.
fn fail_awaiting(c: &mut Channel, steps: &mut Vec<Step>) {
    while let Some(seq) = c.awaiting.pop_front() {
        steps.push(failed(c, seq));
    }
}

/// Fails every request still queued on `c` that wants a reply.
fn fail_queued(c: &Channel, steps: &mut Vec<Step>) {
    for out in &c.queue {
        if let Out::Request(_, Some(seq), _) = out {
            steps.push(failed(c, *seq));
        }
    }
}
