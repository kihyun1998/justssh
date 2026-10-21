# Channels

How the connection protocol's channels (`crates/justssh/src/connection.rs`) move data and keep order, and what to watch when changing them.

## The window is given back as the consumer consumes

Data received on a channel is handed over as `Action::ChannelData`; the window is credited only when the consumer reports it with `channel_consumed`, batched the way x/crypto/ssh's `adjustWindow` does (once more than three maximum packets have been consumed, or the window is below half). A relay that reports only after forwarding gets x/crypto/ssh's backpressure: when the far side stops taking data, this side's window closes and the peer stops sending.

## Nothing overtakes queued data

What the consumer hands a channel — data, extended data, EOF, requests, close — leaves in that order. RFC 4254 §5.3–5.4 lets EOF, CLOSE and requests go out without window space; holding them behind queued data is a choice (decided on #1) so a tail cannot overtake its data. The consequence: while the peer's window is closed, a request such as `window-change` waits too, and so does `channel_close`. `channel_abort` is the way out: it sends the close at once and drops what was queued, as x/crypto/ssh's `Close` does. The maintainer chose the pair on #5, shown that a close could otherwise wait for ever behind a window the peer never opens.

## Limits follow x/crypto/ssh

A peer announcing a maximum packet below 9 or above 2^31 has its open refused (`CONNECT_FAILED`, "invalid request") without the consumer seeing it. Data larger than the announced maximum packet, or beyond the window, ends the connection. Defaults are 2 MiB window and 32 KiB maximum packet.

A `CHANNEL_SUCCESS` or `CHANNEL_FAILURE` that answers no request this side sent is dropped, as x/crypto/ssh drops it.

## Every extended data type is passed on

x/crypto/ssh keeps only type 1 (stderr) and discards the rest, crediting the window. Here every type reaches the consumer (ADR-0001), which then reports it consumed like any data.

## The peer's close is answered at once

On `SSH_MSG_CHANNEL_CLOSE` the core sends its own close if it has not already, drops what was still queued for the channel, reports `Action::ChannelClosed` and frees the id. After this side has sent its close, data and requests still arriving for the channel are dropped.

## The adapter's session waits for the window, and is cancel-safe

`Session::data` and `extended_data` return only once the peer's window has taken everything, reading meanwhile and keeping what arrives for `next` — the backpressure x/crypto/ssh's blocking `Write` gives `io.Copy`. Without it a relay that forwards in a loop buffers without limit when the far side stops reading.

`Session` writes one `write` at a time and remembers how far it got, so a call cancelled in a `select!` leaves no half-written packet; the rest goes out on the next call. A command has taken effect once called, so a cancelled one must not be repeated. Nothing tests cancellation: the proof is the code reading.

## Reply tokens are a contract

Replies to the peer's requests leave in arrival order, so a token the consumer never answers holds back every later reply on its channel. Every request with `want_reply` must be answered.

## Channel ids are reused after wrapping

A new channel takes the next id not in use, so ids reach 2^32 before any is reused and a live one is never overwritten.

## The number of channels is the consumer's to limit

Nothing caps how many channels a peer opens. An open stays in the table until the consumer accepts or rejects it, and `Session::next` reads only once its events are taken, so a consumer that answers every open keeps the table bounded by what it accepts. x/crypto/ssh stops reading at 16 unanswered opens and OpenSSH's sshd allows 10 sessions; here the limit is the consumer's policy, and the broker accepts only `session`. The maintainer chose this on #5.
