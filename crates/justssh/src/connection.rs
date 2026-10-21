//! The connection protocol's channels (RFC 4254 §5), shared by both roles. Channel opens and
//! requests pass through opaque (ADR-0001); the table keeps ids, windows and the per-channel
//! order of what the consumer sends.

use std::collections::{BTreeMap, VecDeque};

use justssh_wire::{
    ChannelClose, ChannelData, ChannelEof, ChannelExtendedData, ChannelFailure,
    ChannelOpenConfirmation, ChannelOpenFailure, ChannelRequest as WireRequest, ChannelSuccess,
    ChannelWindowAdjust, Message,
};

use crate::event::{Action, DisconnectReason, Error};

/// A channel, as this side numbers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChannelId(u32);

impl ChannelId {
    /// The number this side uses for the channel on the wire.
    pub fn get(self) -> u32 {
        self.0
    }
}

/// Identifies a received channel request that asked for a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReplyToken {
    channel: u32,
    seq: u64,
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
    Request(String, bool, Vec<u8>),
    Close,
}

struct Channel {
    peer_id: u32,
    kind: String,
    accepted: bool,
    peer_window: u32,
    peer_max_packet: u32,
    window: u32,
    consumed: u32,
    queue: VecDeque<Out>,
    /// Received requests awaiting a reply, in arrival order, with the reply once given.
    replies: VecDeque<(u64, Option<bool>)>,
    /// Sent requests that asked for a reply and have not had one.
    awaiting: usize,
    sent_close: bool,
    got_eof: bool,
}

pub(crate) struct Channels {
    window: u32,
    max_packet: u32,
    next_id: u32,
    next_seq: u64,
    open: BTreeMap<u32, Channel>,
}

/// Smallest and largest maximum packet a peer may announce, as x/crypto/ssh accepts.
const PEER_MAX_PACKET: core::ops::RangeInclusive<u32> = 9..=1 << 31;

impl Channels {
    pub(crate) fn new(window: u32, max_packet: u32) -> Self {
        Channels {
            window,
            max_packet,
            next_id: 0,
            next_seq: 0,
            open: BTreeMap::new(),
        }
    }

    pub(crate) fn info(&self, id: ChannelId) -> Option<ChannelInfo> {
        self.open.get(&id.0).map(|c| ChannelInfo {
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
        match message {
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
                let mut id = self.next_id;
                while self.open.contains_key(&id) {
                    id = id.wrapping_add(1);
                }
                self.next_id = id.wrapping_add(1);
                self.open.insert(
                    id,
                    Channel {
                        peer_id: o.sender,
                        kind: o.kind.clone(),
                        accepted: false,
                        peer_window: o.window,
                        peer_max_packet: o.max_packet,
                        window: self.window,
                        consumed: 0,
                        queue: VecDeque::new(),
                        replies: VecDeque::new(),
                        awaiting: 0,
                        sent_close: false,
                        got_eof: false,
                    },
                );
                steps.push(Step::Emit(Action::ChannelOpenRequest(ChannelOpenRequest {
                    channel: ChannelId(id),
                    kind: o.kind,
                    data: o.data,
                    peer_window: o.window,
                    peer_max_packet: o.max_packet,
                })));
            }
            Message::ChannelWindowAdjust(a) => {
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
                flush(c, &mut steps);
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
                    let channel = ChannelId(e.recipient);
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
                self.open.remove(&m.recipient);
                let channel = ChannelId(m.recipient);
                steps.push(Step::Emit(Action::ChannelClosed { channel }));
            }
            Message::ChannelRequest(r) => {
                let seq = self.next_seq;
                let Some(c) = self.accepted(r.recipient, &mut steps) else {
                    return steps;
                };
                if c.sent_close {
                    return steps;
                }
                let reply = r.want_reply.then(|| {
                    c.replies.push_back((seq, None));
                    ReplyToken {
                        channel: r.recipient,
                        seq,
                    }
                });
                self.next_seq += 1;
                steps.push(Step::Emit(Action::ChannelRequest(ChannelRequest {
                    channel: ChannelId(r.recipient),
                    kind: r.kind,
                    want_reply: r.want_reply,
                    data: r.data,
                    reply,
                })));
            }
            Message::ChannelSuccess(ChannelSuccess { recipient, .. })
            | Message::ChannelFailure(ChannelFailure { recipient, .. }) => {
                let ok = matches!(message, Message::ChannelSuccess(_));
                let Some(c) = self.accepted(recipient, &mut steps) else {
                    return steps;
                };
                if c.awaiting == 0 {
                    return steps;
                }
                c.awaiting -= 1;
                let channel = ChannelId(recipient);
                steps.push(Step::Emit(Action::ChannelRequestReply { channel, ok }));
            }
            Message::ChannelOpenConfirmation(ChannelOpenConfirmation { recipient, .. })
            | Message::ChannelOpenFailure(ChannelOpenFailure { recipient, .. }) => {
                steps.push(Step::Fail(
                    DisconnectReason::PROTOCOL_ERROR,
                    Error::UnknownChannel { channel: recipient },
                ));
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
        let max_packet = self.max_packet;
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
        let channel = ChannelId(id);
        steps.push(Step::Emit(match code {
            None => Action::ChannelData { channel, data },
            Some(code) => Action::ChannelExtendedData {
                channel,
                code,
                data,
            },
        }));
    }

    pub(crate) fn accept(&mut self, id: ChannelId, data: Vec<u8>) -> Vec<Step> {
        let (window, max_packet) = (self.window, self.max_packet);
        let Some(c) = self.open.get_mut(&id.0).filter(|c| !c.accepted) else {
            return Vec::new();
        };
        c.accepted = true;
        vec![Step::Send(Message::ChannelOpenConfirmation(
            ChannelOpenConfirmation::new(c.peer_id, id.0, window, max_packet, data),
        ))]
    }

    pub(crate) fn reject(
        &mut self,
        id: ChannelId,
        reason: OpenFailureReason,
        description: &str,
    ) -> Vec<Step> {
        match self.open.get(&id.0) {
            Some(c) if !c.accepted => {
                let peer_id = c.peer_id;
                self.open.remove(&id.0);
                vec![Step::Send(Message::ChannelOpenFailure(
                    ChannelOpenFailure::new(peer_id, reason.code(), description, ""),
                ))]
            }
            _ => Vec::new(),
        }
    }

    /// Queues `out` on channel `id` and sends what the window allows. Nothing happens for a
    /// channel that is not open or that this side has closed.
    pub(crate) fn enqueue(&mut self, id: ChannelId, out: OutKind) -> Vec<Step> {
        let mut steps = Vec::new();
        let Some(c) = self
            .open
            .get_mut(&id.0)
            .filter(|c| c.accepted && !c.sent_close)
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
            OutKind::Request(kind, want_reply, data) => Out::Request(kind, want_reply, data),
            OutKind::Close => Out::Close,
        };
        c.queue.push_back(out);
        flush(c, &mut steps);
        steps
    }

    /// Sends `SSH_MSG_CHANNEL_CLOSE` now, dropping whatever is still queued.
    pub(crate) fn abort(&mut self, id: ChannelId) -> Vec<Step> {
        let Some(c) = self
            .open
            .get_mut(&id.0)
            .filter(|c| c.accepted && !c.sent_close)
        else {
            return Vec::new();
        };
        c.queue.clear();
        c.queue.push_back(Out::Close);
        let mut steps = Vec::new();
        flush(c, &mut steps);
        steps
    }

    pub(crate) fn reply(&mut self, token: ReplyToken, ok: bool) -> Vec<Step> {
        let mut steps = Vec::new();
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

    /// Records that the consumer has taken `n` bytes from channel `id`, and gives window back
    /// once more than three maximum packets have been taken or the window is below half.
    pub(crate) fn consumed(&mut self, id: ChannelId, n: u32) -> Vec<Step> {
        let (full, max_packet) = (self.window, self.max_packet);
        let Some(c) = self
            .open
            .get_mut(&id.0)
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
    Request(String, bool, Vec<u8>),
    Close,
}

/// Sends from the front of `c`'s queue for as long as the peer's window allows. Data is split
/// at the peer's maximum packet; nothing overtakes data the window holds back.
fn flush(c: &mut Channel, steps: &mut Vec<Step>) {
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
                let Some(Out::Request(kind, want_reply, data)) = c.queue.pop_front() else {
                    unreachable!()
                };
                if want_reply {
                    c.awaiting += 1;
                }
                steps.push(Step::Send(Message::ChannelRequest(WireRequest::new(
                    c.peer_id, kind, want_reply, data,
                ))));
            }
            Out::Close => {
                steps.push(Step::Send(Message::ChannelClose(ChannelClose::new(
                    c.peer_id,
                ))));
                c.queue.clear();
                c.sent_close = true;
                return;
            }
        }
    }
}
