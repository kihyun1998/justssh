# User authentication (server)

How the server side of RFC 4252 is counted and paced (`crates/justssh/src/transport/userauth.rs`, `transport/mod.rs`), and what to watch when changing it.

## Counting follows x/crypto/ssh, line for line

`ServerAuth::failed` is x/crypto/ssh v0.55 `server.go` 1005–1009: a failure counts unless it is the first `none` and nothing has failed yet. Reaching the limit disconnects with reason 2 "too many authentication failures" and no final `SSH_MSG_USERAUTH_FAILURE`; reaching 128 attempts sends the `FAILURE` first and then disconnects with "too many authentication attempts". The description strings are Go's, because clients print them.

## Nothing moves while a verdict is pending

A client may send several requests without waiting (RFC 4252 §5). While an `Action::PasswordRequest` awaits `Event::AuthAccepted` or `AuthRejected`, received bytes are buffered but not processed, so later requests are answered in order after the verdict.

## EXT_INFO is the packet after the server's first NEWKEYS

`server-sig-algs` lists x/crypto/ssh's default public key algorithms, in its order, although this server offers only `password`; that is what Go sends. Advertising `ping@openssh.com` commits the server to answer `SSH2_MSG_PING`, which it does once authenticated.

## Deadlines are per phase, counted from the start

`justssh_tokio::Deadlines::phase(p, d)` means the connection must have left phase `p` within `d` of starting. It also bounds every earlier phase, so `phase(Phase::Auth, 3 min)` alone is x/crypto/ssh's handshake timeout. The verdict callback runs under the same deadline as the read.

## A password change request is refused, not answered

A `password` request whose first byte is `TRUE` asks to change the password (RFC 4252 §8). It is treated as malformed and ends the connection, as x/crypto/ssh does (`server.go`, the `payload[0] != 0` check), rather than answered with `SSH_MSG_USERAUTH_PASSWD_CHANGEREQ`.

## The password is read in place

`transport::userauth::request` reads a request from the decrypted payload without copying it, and the payload buffer is zeroized on drop; only the password handed to the consumer is copied, into a zeroizing buffer. Decoding a `USERAUTH_REQUEST` through `justssh_wire::Message` would leave a plain copy in `method_data`.

## The adapter stops at authentication

`justssh_tokio::accept` returns as soon as the client is authenticated, handing back the stream and what the verdict callback returned, the way x/crypto/ssh's `NewServerConn` returns after authentication. The connection protocol runs from there in a separate step, `Session`, which starts from the `events` `accept` returns: whatever the peer sent right behind its authentication request, such as a channel open, is handled with the last authentication step and must not be dropped. The callback runs under the deadline and is dropped if it passes, so whatever it opens must be released on drop.

## A verdict answers whatever request is pending

`Event::AuthAccepted` and `AuthRejected` carry no reference to the request they answer; they apply to the one pending. A consumer of the bare core that answers late or twice could accept a request it never checked. `justssh_tokio::accept` answers one request at a time, and with a limit of one failure the first rejection ends the connection, so neither path reaches it. The maintainer chose to leave it on #4.
