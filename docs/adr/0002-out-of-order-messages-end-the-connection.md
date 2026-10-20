# Out-of-order messages end the connection

A known message that the current state does not allow ends the connection. Examples are a `USERAUTH_SUCCESS` sent to a server (libssh CVE-2018-10933) and channel traffic arriving during key exchange.

An unknown message number is treated differently depending on when it arrives:
- Before the connection is established (during key exchange or authentication), it ends the connection.
- After that, it is answered with `SSH_MSG_UNIMPLEMENTED`, as RFC 4253 §11.4 requires.

When strict-kex is negotiated, `IGNORE`, `DEBUG` and `UNIMPLEMENTED` during the first key exchange also end the connection. This is OpenSSH's response to Terrapin.

Which messages each state allows is decided in one table, and that table is a fuzzing target. Most ordering vulnerabilities come from that decision being scattered across the code.

This differs from x/crypto/ssh in one place. Go never sends `UNIMPLEMENTED` and closes the connection instead. We follow the RFC here, because the RFC is binding and Go is binding only for behaviour acwbroker can observe.
