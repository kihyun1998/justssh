# Transport handshake

How the transport (`crates/justssh/src/transport/`) gets from the identification lines to the `ssh-userauth` service, and what to watch when changing it.

## Symmetric bugs pass the in-memory tests

The server and client in the in-memory tests share one implementation, so an error made identically on both sides passes them. Measured on #3: hashing `K` as raw bytes instead of an mpint, and swapping chacha20-poly1305's `K_1`/`K_2`, both left all 20 in-memory tests green and failed only the OpenSSH test (`crates/justssh-tokio/tests/openssh.rs`). Anything that both sides compute the same way — the exchange hash, key derivation, packet protection — is proven only by a real peer.

## Padding alignment differs by cipher

Plaintext packets align `packet_length || padding_length || payload || padding` to 8. chacha20-poly1305 aligns without the 4-byte length field, which it encrypts separately (draft-ietf-sshm-chacha20-poly1305 §7; OpenSSH and x/crypto/ssh do the same). AES-GCM aligns to 16 without the length field, which is its associated data (RFC 5647 §7.2). AES-CTR aligns to 16, counting the length field under an Encrypt-and-MAC MAC and not under an `-etm` MAC, whose length stays in the clear (OpenSSH `PROTOCOL` §1.5).

A received packet that does not align is refused under every cipher. x/crypto/ssh does not check GCM's alignment and OpenSSH does, so this follows OpenSSH; a GCM packet aligned to 8 fails against OpenSSH and passes Go (measured on #10).

## Strict KEX is checked after the fact

Whether strict KEX is in force is known only once the peer's `SSH_MSG_KEXINIT` arrives, so "KEXINIT must be the first packet" is checked then, against a count of packets already received (draft-miller-sshm-strict-kex-01 §3.2). Before that, `IGNORE` and `DEBUG` are accepted. Only the `-v00@openssh.com` markers are sent and recognised: OpenSSH and x/crypto/ssh use no others (#3).

Peers that do not offer strict KEX are still accepted, as x/crypto/ssh does: the legacy clients the broker serves (MobaXterm 10.2 / SecureBlackbox) may not offer it, and the broker listens on loopback, where no one sits on the path. Such a connection under chacha20-poly1305 or an `-etm` MAC stays open to Terrapin prefix truncation (CVE-2023-48795); AES-GCM, whose nonce does not follow the sequence number, is not among the modes it names. The maintainer chose this on #3, when chacha20-poly1305 was the only cipher.

Without strict KEX the sequence numbers run on across `SSH_MSG_NEWKEYS`. Resetting them anyway passes the in-memory tests when both sides do it, so `go.rs` and `sshd.rs` log in without strict KEX under AES-CTR with each MAC kind (`ClientConfigBuilder::strict_kex(false)`, `test-support`).

## Sequence numbers are counted before dispatch

The incoming sequence number is advanced before a packet is handled, so that the strict-KEX reset in the `SSH_MSG_NEWKEYS` handler leaves the next packet at 0.

## Identification lines share one 255-byte budget

The identification line and every line before it count against 255 bytes together, as in x/crypto/ssh (`transport.go`); a peer cannot hold the version phase open with an endless stream of short lines.

## The table decides, dispatch also refuses

`allowed::verdict` is where a message is accepted or refused. `Transport::dispatch` also refuses any accepted message it has no handler for, so a wrong `Accept` in the table still closes the connection. A test that only checks that the connection closed — `userauth_success_sent_to_a_server_closes_the_connection` — therefore stays green when the table alone is wrong (measured on #3); the table itself is what the fuzz target (#14) is for.

## Unknown means no decoder in justssh-wire

After authentication a message number `justssh_wire::number::is_known` does not list is answered with `SSH_MSG_UNIMPLEMENTED` carrying that packet's sequence number, and the connection stays (ADR-0002; OpenSSH `dispatch.c` `dispatch_protocol_error` sends the same). A number it lists that the table does not allow in that stage still ends the connection, where OpenSSH would answer `UNIMPLEMENTED` too. So adding a decoder for a new number moves that number from "answered" to "refused" until the table allows it; a wire test checks that `is_known` and the decoder agree on all 256 numbers. Before authentication every unknown number ends the connection, as x/crypto/ssh does. `SSH_MSG_USERAUTH_BANNER` (53) is one of these: it is decoded, so after authentication it ends the connection rather than being answered.

Each answer is larger than what it answers: measured on #6, 10k one-byte unknown packets took 280,000 bytes in and 360,000 out (`PING` is 1.00). Only an authenticated peer can do it, and the adapter flushes before it reads, so a peer that does not read stalls the server rather than growing its buffer. Left so on #6.

## The algorithms are x/crypto/ssh's defaults, in its order

Both roles offer x/crypto/ssh v0.55's default key exchanges, ciphers and MACs (ADR-0005), with `curve25519-sha256@libssh.org` right after `curve25519-sha256` where Go adds it (`common.go`). The MAC lists are offered even though the preferred ciphers are AEADs, as Go does; a MAC is negotiated only for AES-CTR. `crates/justssh-tokio/tests/go.rs` checks the lists against the KEXINIT a Go client and a Go server actually send.

`K` goes into the exchange hash and key derivation as an mpint for the elliptic-curve and DH methods, and as a string for `mlkem768x25519-sha256`, whose `K` is SHA-256 of the ML-KEM and X25519 secrets (Go `mlkem.go`). A DH public value is hashed as the canonical mpint of the number received, as Go re-encodes it. A DH exponent is 2047 random bits, raised in constant time (crypto-bigint `FixedMontyForm::pow`).

## Errors made on both sides need Go or OpenSSH to show

The in-memory tests run justssh against itself. Measured on #10 by mutation: a GCM nonce that does not advance, a GCM tag without the length as associated data, an Encrypt-and-MAC computed over the ciphertext, an EtM MAC without the length, `hmac-sha1-96` sent untruncated, `K` of the hybrid method as an mpint, the wrong hash for `ecdh-sha2-nistp384` or `diffie-hellman-group14-sha1`, and swapped key letters all left the in-memory tests green, and each failed the Go interop test. GCM packets aligned to 8 instead of 16 also pass Go, which does not check, and fail OpenSSH. So the OpenSSH and Go matrices (`openssh.rs`, `sshd.rs`, `go.rs`) are the proof for this layer.

The CI sshd is whatever the runner image installs: 9.6p1 on Ubuntu 24.04, 10.2p1 on the runner on #10. Neither offers `diffie-hellman-group14-sha1` or `hmac-sha1-96` by default, and 10.2p1 offers no `diffie-hellman-group14-sha256` either (measured on #10), so CI adds all three to one sshd. 9.6p1 has no `mlkem768x25519-sha256` (9.9 added it), so CI also runs Alpine 3.21's OpenSSH 9.9p2 for the hybrid method. An `ssh` client without the hybrid method skips it in `openssh.rs`; the Go tests cover it there.

## What the algorithms cost

Measured on #10, release build, one core, a full handshake to `Auth` with an ed25519 host key: curve25519 about 0.15 ms on the server, mlkem768x25519 0.18 ms, nistp256 0.23 ms, nistp384 0.7 ms, nistp521 0.8 ms, and diffie-hellman-group14 about 9 ms, against about 4.5 ms in Go. group14 is the constant-time `FixedMontyForm::pow` over a 2047-bit exponent; it is last in the list, so only a peer offering nothing else pays it.

Bulk data: AES-GCM sealed about 1.6 times as fast as chacha20-poly1305 (1306 against 803 MiB/s). `hmac-sha2-512` is the slow one, because SHA-512 from `sha2` 0.11 ran at 243 MiB/s against SHA-256's 1489 MiB/s. Each HMAC is keyed once per key exchange and cloned per packet: re-keying it per packet cost 446 ns against 176 ns for a 52-byte packet under SHA-256, and 1876 against 1130 ns under SHA-512.

## Host keys are offered as x/crypto/ssh offers them

A server offers each host key's algorithms in the order the keys were added, each key's in its own order: `rsa-sha2-256`, `rsa-sha2-512`, `ssh-rsa` for RSA (Go `handshake.go` `sendKexInit`, `algorithmsForKeyFormat`). `HostKey::with_algorithms` narrows a key as `NewSignerWithAlgorithms` does, keeping the key's order rather than the caller's, and a key added in a format already present replaces the first, as `AddHostKey` does. So acwbroker's keys (`broker.go` `serverConfig`: ed25519, then RSA restricted to `ssh-rsa`) give `ssh-ed25519,ssh-rsa`, which `go.rs` checks against a Go server set up the same way. The server signs with the first key offering the negotiated algorithm (`pickHostKey`). A certificate on the key is not used: the host key is the plain key.

The client offers x/crypto/ssh's `defaultHostKeyAlgos` without the certificate and DSA algorithms, so it cannot reach a server that has only a host certificate or only a DSA key. acwbroker does not check upstream host keys (`InsecureIgnoreHostKey`), so the certificate algorithms would change nothing it sees. The maintainer chose this on #11. With ed25519 last in Go's order, a server offering `ssh-ed25519` and `ssh-rsa`, as acwbroker's does, is reached under `ssh-rsa`, as a Go client reaches it.

The client takes a host key signature only when its algorithm name is the negotiated one, as Go does (`client.go` `verifyHostKeySignature`). An RSA key is taken from 1024 bits to 16384, with a public exponent of at most 24 bits: the maximum and the exponent as Go's `parseRSA`, the minimum as Go's `crypto/rsa` (`rsa1024min`, on for acwbroker's Go 1.25) and OpenSSH. A signature shorter than the modulus is padded with leading zeros before it is checked, as Go (`keys.go` `rsaPublicKey.Verify`) and OpenSSH do; Go's comment names PuTTY up to 0.81 and SSH.NET up to 2024.0.0 as signers that send them, about one signature in 256 for a signer that does.

Measured on #11 (release, one core): a server handshake signing with RSA-2048 takes about 1.3 ms against 0.08 ms with ed25519, the rsa 0.9 signature itself about 1.2 ms against Go's 0.7 ms; the client's RSA-2048 verify about 0.11 ms against Go's 0.02 ms. A hostile server's 16384-bit key costs the client about 6.3 ms to verify, Go about 6.6 ms, and a failed verify ends the connection.

## Keys are exchanged again as x/crypto/ssh exchanges them

Once the first key exchange has ended, either side may start another, in any phase. This side starts one when it has received or sent, under the keys in use, more payload bytes than the threshold in either direction, or 2^31 packets (Go `handshake.go` `readOnePacket`, `writePacket`). The threshold is 64 GiB under AES and 1 GiB under other ciphers (Go `rekeyBytes`), or `rekey_threshold`, raised to Go's minimum of 256. A consumer's own timer calls `rekey`: Go has no time-based rekey, and the maintainer kept it out of the adapter on #12.

What this side sends after its `SSH_MSG_KEXINIT` and before the exchange ends is held and sent in order after the peer's `SSH_MSG_NEWKEYS`, as Go's `pendingPackets`, except what RFC 4253 §7.1 allows during an exchange: messages 1 to 4, `SSH_MSG_EXT_INFO` and 20 to 49. `SSH_MSG_SERVICE_REQUEST` and `SERVICE_ACCEPT` are held too: sent mid-exchange, they ended the connection at a client that had moved on to key exchange messages (#12). Channel output waits in its channel's queue instead (`channels.md`), so what is held is replies, window adjusts and the like; more than 1024 of them ends the connection with `ExchangeBacklog`. Go blocks its writer after 64 (`maxPendingPackets`, the CVE-2025-22869 fix), which a peer that never answers this side's `SSH_MSG_KEXINIT` but keeps sending `SSH_MSG_PING` would otherwise grow without limit. Until the peer's `SSH_MSG_KEXINIT` arrives, the peer has not seen this side's, so its connection messages are still handled; after it, only key exchange messages are taken (ADR-0002).

Strict key exchange is agreed on the first exchange and holds: the sequence numbers go back to 0 at every `SSH_MSG_NEWKEYS`, and the `kex-strict-*` and `ext-info-c` markers are sent only in the first `SSH_MSG_KEXINIT`, as Go (`transport.go` `readPacket`, `writePacket`; `handshake.go` `sendKexInit`). Read from a re-exchange's lists alone, strict KEX would look off, and both sides resetting or not resetting the same way passes the in-memory tests; `go.rs`, `sshd.rs` and `openssh.rs` rekey against real peers both ways. They do so under chacha20-poly1305, whose nonce is the sequence number: under AES-GCM, whose nonce counts invocations instead, not resetting passed against Go and sshd for 17 re-exchanges (measured on #12 by mutation), and failed only under the OpenSSH client, which chose chacha20.

Measured on #12 (release, one core pinned, chacha20, ed25519 host key): one re-exchange costs both sides together about 0.2 ms under curve25519 and 0.3 ms under mlkem768x25519, against Go's 0.3 and 0.45 ms; nistp256 0.4 ms against Go's 0.19. Counting bytes and checking the threshold costs about 2 ns a packet. A peer starting an exchange after every one keeps a core busy at about 10,000 a second with no growth in memory; neither Go nor OpenSSH limits that rate.

An OpenSSH client that only reads rekeys seldom: `ssh -o RekeyLimit=4K` reading 300,000 bytes from this server rekeyed once (measured on #12), where sshd sending them under `RekeyLimit 4K` rekeyed more than ten times. An sshd busy with output answers a re-exchange only after it has sent what is queued, and an ssh that started one near the end leaves when the channel closes, so a test that stops at the channel's close may end before the exchange does: `openssh.rs` handles input for a second before closing, after ssh 10.2p1 in CI left mid-exchange (#12).
