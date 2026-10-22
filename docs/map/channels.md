# Channels

How the connection protocol's channels (`crates/justssh/src/connection.rs`) move data and keep order, and what to watch when changing them.

## The window is given back as the consumer consumes

Data received on a channel is handed over as `Action::ChannelData`; the window is credited only when the consumer reports it with `channel_consumed`, batched the way x/crypto/ssh's `adjustWindow` does (once more than three maximum packets have been received and not yet given back, or the window is below half; `adjustWindow` tests the window, not the bytes consumed). A relay that reports only after forwarding gets x/crypto/ssh's backpressure: when the far side stops taking data, this side's window closes and the peer stops sending.

## Nothing overtakes queued data

What the consumer hands a channel — data, extended data, EOF, requests that want no reply, close — leaves in that order. RFC 4254 §5.3–5.4 lets EOF, CLOSE and requests go out without window space; holding them behind queued data is a choice (decided on #1) so a tail such as `exit-status` cannot overtake its data. The consequence: while the peer's window is closed, a request such as `window-change` waits too, and so does `channel_close`, where x/crypto/ssh sends them at once (`channel.go`).

A request that wants a reply goes out at once, ahead of queued data, unless a close is queued, behind which it fails as before. One queued while the channel opens goes out with the rest on the confirmation, and ahead of whatever data the window then holds back. During a key exchange it is held by the transport, with replies and window adjusts. Without that, a relay whose downstream stops reading could not answer an upstream sshd's channel `keepalive@openssh.com`, and sshd would disconnect after `ClientAliveCountMax`; Go answers it. The maintainer chose this on #26 over letting every request overtake, as Go does, which would let `exit-status` overtake its output, and over leaving keepalives to the consumer. The rule reads `want_reply` only, never the request's name, so a peer sending `exit-status` with a reply wanted gets it ahead of its own output; OpenSSH does not. `channel_abort` is the way out: it sends the close at once and drops what was queued, as x/crypto/ssh's `Close` does. The maintainer chose the pair on #5, shown that a close could otherwise wait for ever behind a window the peer never opens.

## Limits follow x/crypto/ssh

A peer announcing a maximum packet below 9 or above 2^31 has its open refused (`CONNECT_FAILED`, "invalid request") without the consumer seeing it. Data larger than the announced maximum packet, or beyond the window, ends the connection. Defaults are 2 MiB window and 32 KiB maximum packet.

A `CHANNEL_SUCCESS` or `CHANNEL_FAILURE` that answers no request this side sent is dropped, as x/crypto/ssh drops it.

## Every extended data type is passed on

x/crypto/ssh keeps only type 1 (stderr) and discards the rest, crediting the window. Here every type reaches the consumer (ADR-0001), which then reports it consumed like any data.

## The peer's close is answered at once

On `SSH_MSG_CHANNEL_CLOSE` the core sends its own close if it has not already, drops what was still queued for the channel, reports `Action::ChannelClosed` and frees the id. After this side has sent its close, data and requests still arriving for the channel are dropped.

## The adapter's session waits for the window, and is cancel-safe

`Session::data` and `extended_data` return only once the peer's window has taken everything, reading meanwhile and keeping what arrives for `next`, so no request is answered until it returns — the backpressure x/crypto/ssh's blocking `Write` gives `io.Copy`. What arrives meanwhile is kept without a bound.

`queue_data` and `queue_extended_data` only queue, and `Action::ChannelDrained` from `next` reports when what waited for the window has gone. With them one loop per connection answers every request while output waits, which a relay needs: acwbroker's relay forwards requests while its data copies block (`relay.go`). The bound is then the consumer's: forward the far side's data, and give the far side its window back (`consumed`) only once this side's queue is empty, at once or on `ChannelDrained`, checking `queued()` again then since more may have been queued after it was reported; giving it back on forwarding buffers without limit when this side's peer stops reading, which put 6,029,312 bytes behind a stalled downstream in the relay test where the rule kept 2,097,152 (measured on #26). `queued()` counts data only: requests that want no reply wait too, uncounted, so a relay forwarding them while data waits bounds them itself. A request on a channel that has closed returns no token, and a relay answers the far side's request false itself, as acwbroker does when Go's `SendRequest` fails. `crates/justssh-tokio/tests/relay.rs` relays 8 MiB that way to a downstream that takes nothing for two seconds, answering the upstream's channel keepalives meanwhile, with the relay holding at most 4 MiB of upstream output. The maintainer chose this shape on #26 over a policy answering while `data` waits, which cannot forward, and over splitting `Session` into a driver task and handles, Go's shape, which would let stdout, stderr and the tail be reordered again across tasks.

`Session` writes one `write` at a time and remembers how far it got, so a call cancelled in a `select!` leaves no half-written packet; the rest goes out on the next call. A command has taken effect once called, so a cancelled one must not be repeated. Nothing tests cancellation: the proof is the code reading.

## Reply tokens are a contract

Replies to the peer's requests leave in arrival order, so a token the consumer never answers holds back every later reply on its channel. Every request with `want_reply` must be answered.

A request this side sends with `want_reply` returns a `RequestToken`, and its reply comes back with it in `Action::ChannelRequestReply`; the peer answers a channel's requests in the order they were sent (RFC 4254 §5.4), which is how the token is found. When a channel closes, is aborted or is refused before the peer replies, each of its tokens still owed a reply comes back as a failed `ChannelRequestReply`, ahead of the `ChannelClosed` or `ChannelOpenFailed`: x/crypto/ssh's `SendRequest` returns `io.EOF` there and acwbroker answers the downstream request false (`relay.go`), so a relay gets the same answer without a table of its own. A request queued behind this side's close fails when the close goes out. A failure the peer sent and one this side made are not told apart. The maintainer chose the failed reply over a dedicated action and over documenting the end alone on #8. x/crypto/ssh pairs them by blocking `SendRequest` until the reply; a token is that pairing without the wait, so a relay can map it to the downstream request it forwards. The maintainer chose the returned token over a tag the consumer supplies on #8.

Every token and every `ChannelId` carries the connection it came from; a token of another connection answers nothing, the way a token answered twice does, and a command given another connection's channel id does nothing. Without that, a relay that passed a downstream channel id to the upstream connection would act on whichever upstream channel had the same number. The maintainer extended the rule to channel ids on #8. A broker holds a server connection and a client connection side by side, whose sequence numbers both start at 0; x/crypto/ssh's `Request` holds its own channel and cannot be mixed up (`channel.go` `type Request`).

## Channels this side opens

`open_channel` returns the channel id at once and sends `SSH_MSG_CHANNEL_OPEN`; the peer's answer arrives as `Action::ChannelOpened`, with the confirmation's type-specific data, or `Action::ChannelOpenFailed`, with its reason and description, after which the id is free. Commands for the channel wait in its queue, in order, and go out once it is confirmed; a refusal drops them. So a consumer whose downstream goes away while the upstream channel is still opening can `channel_abort` it, and the close goes out right after the confirmation. x/crypto/ssh's `OpenChannel` blocks until the answer, so nothing can be sent or abandoned before it. A confirmation announcing a maximum packet outside 9..2^31 ends the connection (`channel.go` `channelOpenConfirmMsg`), and a confirmation or failure for a channel this side is not opening ends it as an unknown channel. The description is read as lossy UTF-8.

OpenSSH 8.7p1 and 9.6p1 both refuse a channel type they do not know with reason 2 (`CONNECT_FAILED`) and "open failed" (measured on #8 by `crates/justssh-tokio/tests/sshd.rs`).

## Either role through one Session

`justssh::Endpoint` is implemented by `Server` and `Client` with their inherent methods of the same names, written once (`connection_methods!` in `endpoint.rs`), and `justssh_tokio::Session<IO, E>` runs either. The maintainer chose this over a separate client session and over moving the methods to a shared type on #8.

## Channel ids are reused after wrapping

A new channel takes the next id not in use, so ids reach 2^32 before any is reused and a live one is never overwritten.

## The number of channels is the consumer's to limit

Nothing caps how many channels a peer opens. An open stays in the table until the consumer accepts or rejects it, and `Session::next` reads only once its events are taken, so a consumer that answers every open keeps the table bounded by what it accepts. x/crypto/ssh stops reading at 16 unanswered opens and OpenSSH's sshd allows 10 sessions; here the limit is the consumer's policy, and the broker accepts only `session`. The maintainer chose this on #5.

## A key re-exchange holds what is sent

While a key exchange is under way, what is queued on channels stays there, counted by `ChannelInfo::queued`, and goes out once it ends; so `Session::data` waits through the exchange as it waits for the window. A client's re-exchange stops for the host key to be judged, which only the consumer can do: `Session::data` then returns with its data still queued, and `next` hands over the `Action::VerifyHostKey`. Waiting on for the window instead hung the upload, since the server's window adjust waits for the client's `SSH_MSG_NEWKEYS` (measured on #12; against OpenSSH it ended with `InputOverflow`, as sshd sends what it queued after its own `SSH_MSG_NEWKEYS`). Replies, window adjusts and channel opens, which are not queued on a channel, are held by the transport (see `transport-handshake.md`).
