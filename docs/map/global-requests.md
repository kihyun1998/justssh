# Global requests

How global requests (RFC 4254 §4) cross the connection protocol (`crates/justssh/src/connection.rs`), and what to watch when changing them.

## Replies are put in arrival order, payload and all

A received global request reaches the consumer as `Action::GlobalRequest`, with a `GlobalReplyToken` when it wants a reply. The core sends replies in the order the requests arrived, whatever order the consumer answers in (RFC 4254 §4), as it does for channel requests. A reply carries everything after its message number, on `SSH_MSG_REQUEST_FAILURE` as well as `SSH_MSG_REQUEST_SUCCESS`. RFC 4254 gives a failure no payload, but x/crypto/ssh (`messages.go` `globalRequestFailureMsg`, `Request.Reply`) sends and reads one, and the broker must relay what Go would.

Every request with want_reply must be answered; that is the consumer's contract, as the number of channels is (#5). A token never answered holds back every later global reply, and the replies given behind it stay queued, payload and all, until the connection ends: nothing caps the queue. Finding a reply's place is a linear search, so answering out of order costs the square of the backlog — measured on #6 with 100k requests: 134 ms answered in order, 2.72 s in reverse, 3.31 s with the first never answered. x/crypto/ssh keeps no such queue (`mux.go` `ackRequest` sends at once) and stops reading after 16 unanswered requests. The maintainer chose the contract over a cap on #6, shown these numbers.

## Keepalives must be answered

OpenSSH's `ServerAliveInterval` sends `keepalive@openssh.com` with want_reply set (`clientloop.c` `server_alive_check`) and gives up after `ServerAliveCountMax` unanswered ones ("Timeout, server … not responding", exit 255). Refusing it counts as an answer. Measured on #6 by `crates/justssh-tokio/tests/keepalive.rs`: with the reply removed and `ServerAliveCountMax=2`, ssh prints that line and exits 255.

The tokio `Session` cannot answer while `data` or `extended_data` waits for the peer's window: requests read meanwhile are kept for `next`. Measured on #6: an ssh whose stdout nobody reads, sent 64 MiB, got no keepalive answered in 3.3 s and exited 255. x/crypto/ssh answers from another goroutine while a `Write` waits. Tracked in #26.

## Sent requests do not wait for channels

`Server::global_request` sends at once; nothing queued on a channel holds it back. A reply arrives as `Action::GlobalRequestReply`, in the order the requests were sent. A reply that answers no request this side sent is dropped, as x/crypto/ssh drops it (`mux.go` `handleGlobalPacket`).

A peer that answers a sent request with `SSH_MSG_UNIMPLEMENTED` instead leaves it awaited for ever, and the next stray reply is taken as its answer. x/crypto/ssh's `SendRequest` waits for ever the same way; no peer was found that does not know message 80. Left so on #6.

## Before authentication they end the connection

Global requests and their replies are accepted only once authenticated; before that they end the connection like any other connection-protocol message. x/crypto/ssh's server does the same: its authentication loop fails on any packet that is not `SSH_MSG_USERAUTH_REQUEST` (`server.go`, `Unmarshal` into `userAuthRequestMsg`).
