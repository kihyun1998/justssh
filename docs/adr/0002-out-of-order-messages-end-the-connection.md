# Out-of-order messages end the connection

A known message that the current state does not allow ends the connection. Examples are a `USERAUTH_SUCCESS` sent to a server (libssh CVE-2018-10933) and channel traffic arriving during key exchange.

An unknown message number is treated differently depending on when it arrives:
- Before the connection is established (during key exchange or authentication), it ends the connection.
- After that, it is answered with `SSH_MSG_UNIMPLEMENTED`, as RFC 4253 §11.4 requires.

When strict-kex is negotiated, `IGNORE`, `DEBUG` and `UNIMPLEMENTED` during the first key exchange also end the connection. This is OpenSSH's response to Terrapin.

Which messages each state allows is decided in one table, and that table is a fuzzing target. Most ordering vulnerabilities come from that decision being scattered across the code.

This differs from x/crypto/ssh in one place. Go never sends `UNIMPLEMENTED` and closes the connection instead. We follow the RFC here, because the RFC is binding and Go is binding only for behaviour acwbroker can observe.

## Addendum (2026-10-21): the peer is told why

Before closing because of an error, this side sends `SSH_MSG_DISCONNECT` with a reason code (RFC 4253 §11.1) and a description, once its identification line has been sent. x/crypto/ssh closes the socket without one. This is a difference the client can observe ("Received disconnect … 14: no authentication methods available" instead of "Connection closed"); the maintainer chose it for diagnosability (#3).

## Exception (2026-10-21): requests after authentication are ignored

An `SSH_MSG_USERAUTH_REQUEST` that reaches a server after it has sent `SSH_MSG_USERAUTH_SUCCESS` is dropped without a reply, not treated as an out-of-order message. A client may send several requests without waiting (RFC 4252 §5), so one can legitimately arrive after the success it did not wait for; RFC 4252 §5 says to ignore it, and OpenSSH's sshd does (`auth2.c` switches the handler to `dispatch_protocol_ignore`). x/crypto/ssh closes the connection instead. Nothing is granted by ignoring it, since the request is never evaluated. The maintainer chose this on #4, shown the RFC text and the OpenSSH source, and told that no client was found that sends requests without waiting.
