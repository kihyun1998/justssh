# Transport handshake

How the transport (`crates/justssh/src/transport/`) gets from the identification lines to the `ssh-userauth` service, and what to watch when changing it.

## Symmetric bugs pass the in-memory tests

The server and client in the in-memory tests share one implementation, so an error made identically on both sides passes them. Measured on #3: hashing `K` as raw bytes instead of an mpint, and swapping chacha20-poly1305's `K_1`/`K_2`, both left all 20 in-memory tests green and failed only the OpenSSH test (`crates/justssh-tokio/tests/openssh.rs`). Anything that both sides compute the same way — the exchange hash, key derivation, packet protection — is proven only by a real peer.

## Padding alignment differs by cipher

Plaintext packets align `packet_length || padding_length || payload || padding` to 8. chacha20-poly1305 aligns without the 4-byte length field, which it encrypts separately (draft-ietf-sshm-chacha20-poly1305 §7; OpenSSH and x/crypto/ssh do the same).

## Strict KEX is checked after the fact

Whether strict KEX is in force is known only once the peer's `SSH_MSG_KEXINIT` arrives, so "KEXINIT must be the first packet" is checked then, against a count of packets already received (draft-miller-sshm-strict-kex-01 §3.2). Before that, `IGNORE` and `DEBUG` are accepted. Only the `-v00@openssh.com` markers are sent and recognised: OpenSSH and x/crypto/ssh use no others (#3).

Peers that do not offer strict KEX are still accepted, as x/crypto/ssh does: the legacy clients the broker serves (MobaXterm 10.2 / SecureBlackbox) may not offer it, and the broker listens on loopback, where no one sits on the path. With chacha20-poly1305 as the only cipher such a connection stays open to Terrapin prefix truncation. The maintainer chose this on #3.

## Sequence numbers are counted before dispatch

The incoming sequence number is advanced before a packet is handled, so that the strict-KEX reset in the `SSH_MSG_NEWKEYS` handler leaves the next packet at 0.

## Identification lines share one 255-byte budget

The identification line and every line before it count against 255 bytes together, as in x/crypto/ssh (`transport.go`); a peer cannot hold the version phase open with an endless stream of short lines.

## The table decides, dispatch also refuses

`allowed::verdict` is where a message is accepted or refused. `Transport::dispatch` also refuses any accepted message it has no handler for, so a wrong `Accept` in the table still closes the connection. A test that only checks that the connection closed — `userauth_success_sent_to_a_server_closes_the_connection` — therefore stays green when the table alone is wrong (measured on #3); the table itself is what the fuzz target (#14) is for.

## Unknown means no decoder in justssh-wire

After authentication a message number `justssh_wire::number::is_known` does not list is answered with `SSH_MSG_UNIMPLEMENTED` carrying that packet's sequence number, and the connection stays (ADR-0002; OpenSSH `dispatch.c` `dispatch_protocol_error` sends the same). A number it lists that the table does not allow in that stage still ends the connection, where OpenSSH would answer `UNIMPLEMENTED` too. So adding a decoder for a new number moves that number from "answered" to "refused" until the table allows it; a wire test checks that `is_known` and the decoder agree on all 256 numbers. Before authentication every unknown number ends the connection, as x/crypto/ssh does. `SSH_MSG_USERAUTH_BANNER` (53) is one of these: it is decoded, so after authentication it ends the connection rather than being answered.

Each answer is larger than what it answers: measured on #6, 10k one-byte unknown packets took 280,000 bytes in and 360,000 out (`PING` is 1.00). Only an authenticated peer can do it, and the adapter flushes before it reads, so a peer that does not read stalls the server rather than growing its buffer. Left so on #6.
