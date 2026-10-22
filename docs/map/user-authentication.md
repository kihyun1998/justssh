# User authentication

How the server side of RFC 4252 is counted and paced, and how the client side asks (`crates/justssh/src/transport/userauth.rs`, `transport/mod.rs`, `crates/justssh-tokio/src/connect.rs`), and what to watch when changing them.

## Counting follows x/crypto/ssh, line for line

`ServerAuth::failed` is x/crypto/ssh v0.55 `server.go` 1005–1009: a failure counts unless it is the first `none` and nothing has failed yet. Reaching the limit disconnects with reason 2 "too many authentication failures" and no final `SSH_MSG_USERAUTH_FAILURE`; reaching 128 attempts sends the `FAILURE` first and then disconnects with "too many authentication attempts". The description strings are Go's, because clients print them.

## Nothing moves while a verdict is pending

A client may send several requests without waiting (RFC 4252 §5). While an `Action::PasswordRequest` awaits `Event::AuthAccepted` or `AuthRejected`, received bytes are buffered but not processed, so later requests are answered in order after the verdict. The buffer holds at most one largest packet with its length field and the longest MAC, hmac-sha2-512's 64 bytes; more ends the connection.

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

## The client core makes one attempt at a time; the adapter picks the method

`Client::auth_none`, `auth_password` and `auth_keyboard_interactive` each send one request, and the answer comes back as `Action::AuthFailure` or as the phase becoming `Connected`. Which method to try next is x/crypto/ssh's loop (`client_auth.go` `clientAuthenticate`), and it lives in `justssh_tokio::connect`: `none` first, then the configured methods in order, only those the last failure named, never one whose name has already failed, at most 64 attempts. A method is identified by its name, so two `Password` entries give one try, as two `ssh.Password` do in Go. The core holds no password: each is taken for the one request that sends it.

A failure read in the same batch as keyboard-interactive questions cancels them: the core has already dropped them, and answering would end the connection. Answers of the wrong number, or a malformed `INFO_REQUEST`, end the connection, where x/crypto/ssh fails that method and tries the next (`client_auth.go` `clientAuthenticate`); the broker's handler always answers every question, so it cannot reach either.

Running out of methods returns `Connected::NoMethodLeft` with the methods tried and the last ones the server allowed, after sending `SSH_MSG_DISCONNECT` reason 14; x/crypto/ssh's error carries the same lists ("attempted methods [none], no supported methods remain"), and acwbroker diagnosed its PAM-only nodes from that text (`ssh_dialer.go`).

## A deadline ends connect even when the peer reads nothing

A deadline stays in force after the core has closed, so the `SSH_MSG_DISCONNECT` that a passed deadline produces is written under it too; a write that does not finish in time ends `connect` with the `Closed` it already has, without trying the write again. Both are tested with a pipe the peer never reads. `justssh_tokio::accept` writes the same way but drops the `Closed` and writes the `DISCONNECT` with no deadline.

## A key is queried before it signs

`Client::auth_publickey` sends the request without a signature first, as x/crypto/ssh's `validateKey` does, and signs only once the server answers `SSH_MSG_USERAUTH_PK_OK`. A `PK_OK` naming an algorithm outside the key's family, or another key, counts as a refusal, as in `confirmKeyAck`; the algorithm may be the key type rather than the one asked under, which OpenSSH and Go both allow. A refusal of the query arrives as `Action::PublicKeyRefused` and a refused signed request as `Action::AuthFailure`, because x/crypto/ssh treats them differently: after a refused query it offers the next key whatever methods the server named, after a refused signature it stops unless `publickey` is still among them (`client_auth.go` `publicKeyCallback.auth`). `justssh_tokio::connect` follows that loop over `AuthMethod::PublicKeys`.

The algorithm is Go's `pickSignatureAlgorithm`: without `server-sig-algs`, the key format (`ssh-rsa` for RSA); with it, the first of the key's algorithms (`rsa-sha2-256`, `rsa-sha2-512`, `ssh-rsa` for RSA) whose underlying algorithm the server lists, and the key format when none is. A certificate signs under its key's algorithm and is offered under the matching certificate name. An RSA certificate refused under `rsa-sha2-*-cert` is offered once more as `ssh-rsa-cert-v01@openssh.com` after every other key; x/crypto/ssh's comment gives OpenSSH 7.2 to 7.7 as the servers that list `rsa-sha2-*` without taking them for certificates, which was not measured here. A key list is not counted against the 64 attempts, in Go either: each `PublicKeys` method is one attempt however many keys it offers (measured on #9: 1000 refused keys, 1000 queries, flat memory).

Measured on #9's servers: OpenSSH 9.6p1 lists `ssh-ed25519`, the three `ecdsa-sha2-nistp*`, two `sk-` types, `rsa-sha2-512` and `rsa-sha2-256`, so an RSA key signs under `rsa-sha2-256`; with `PubkeyAcceptedAlgorithms ssh-rsa,ssh-rsa-cert-v01@openssh.com` it lists only `ssh-rsa`, and the key signs under `ssh-rsa` (SHA-1) and is accepted; an RSA certificate there signs as `ssh-rsa-cert-v01@openssh.com`. OpenSSH 8.7p1 in the Rocky Linux 9.5 container lists `ssh-rsa`, `rsa-sha2-256` and `ssh-dss` among others, as no crypto policy narrows it there, and an RSA key signs under `rsa-sha2-256`. OpenSSH accepts an `ssh-rsa-cert-v01` request signed with SHA-256 too, so a real server does not catch a certificate signed under the wrong hash; the in-memory tests do. No OpenSSH since 7.2 omits `server-sig-algs`, so the `ssh-rsa` fallback for a server without it is shown only in memory. Nothing refuses SHA-1: the choice falls back to `ssh-rsa` as Go's does, where OpenSSH's client has refused it by default since 8.8, and a Terrapin prefix truncation that drops `SSH_MSG_EXT_INFO` on a connection without strict KEX can force the fallback, in Go too. The maintainer kept Go's behaviour over an option to refuse it on #9.

An RSA signature is made with the transport's generator, which blinds the private-key operation; without one rsa 0.9 signs unblinded on variable-time arithmetic. Blinding changes no output, as PKCS#1 v1.5 signatures are deterministic, so no test can see it: the proof is reading `key.rs` against rsa's `RandomizedSigner`. Keys under 1024 bits are refused, as OpenSSH's `SSH_RSA_MINIMUM_MODULUS_SIZE`; smaller ones cannot sign under `rsa-sha2-512`. The secret components are converted from a reversed zeroizing copy, as `BigUint::from_bytes_be` copies its input. An ECDSA scalar may carry the leading zero byte of an SSH mpint.

A `server-sig-algs` of 255,000 bytes makes each key attempt cost 4 to 10 ms against 9 to 15 µs for Go's list, about 2 to 5 times less than x/crypto/ssh spends on the same input (measured on #9). Keys come as their material (`PrivateKey::ed25519`, `ecdsa`, `rsa`, `with_certificate`); reading key files is #21. RSA signing and host key verification use `sha1`/`sha2` 0.10, the digest generation rsa 0.9 works with, kept to `key.rs` as ADR-0004 confines it.

## The host key is judged before NEWKEYS

After the server's signature over the exchange hash verifies, the client emits `Action::VerifyHostKey` and processes nothing more until `Event::HostKeyAccepted` or `HostKeyRejected`; its `SSH_MSG_NEWKEYS` waits for the verdict. This is where x/crypto/ssh calls `HostKeyCallback` (`handshake.go` `client`), on every key exchange, rekeys included. A rejection disconnects with reason 9. Once connected, `Session::next` hands a re-exchange's `Action::VerifyHostKey` to the consumer, who answers with `Session::answer_host_key`; the maintainer chose this over accepting a key equal to the first on #12. `connect` hands over one that arrives together with the authentication's success the same way, in its `events`.

## Message 60 is read by the method in progress

Under keyboard-interactive it is `SSH_MSG_USERAUTH_INFO_REQUEST`; under publickey it is `SSH_MSG_USERAUTH_PK_OK`; under password it is `SSH_MSG_USERAUTH_PASSWD_CHANGEREQ`, which counts as a failure of that attempt with the methods of the last failure, as x/crypto/ssh's `handleAuthResponse` fails it and moves on. It is read in the transport, not by `justssh_wire::Message`, and `number::is_known` leaves it out, so once authenticated a 60 is answered with `SSH_MSG_UNIMPLEMENTED`.

## One EXT_INFO per attempt is passed over

The server's `SSH_MSG_EXT_INFO` before `SSH_MSG_SERVICE_ACCEPT` is kept and read by `Client::server_sig_algs`; a second one there ends the connection, as it breaks x/crypto/ssh's `serviceAccept` decode (`client_auth.go` 44–70). During authentication one per attempt is ignored and a second ends the connection, as x/crypto/ssh's `gotMsgExtInfo`.

The extensions are kept for the whole connection, where x/crypto/ssh frees its map when authentication ends. Measured on #7: one packet of 29,107 one-byte names keeps 1.86 MB (a single 262 KB value keeps 523 KB). The last failure's method list is kept too, for a password change request to report; one failure of 131k one-byte names costs 28.8 ms and keeps about 3.3 MB until the next replaces it, and the 64-attempt cap bounds a hostile server to about 2.3 s of CPU per connection. `ext-info-c` is offered only in the first key exchange, before the strict KEX marker, in Go's order (`handshake.go` `sendKexInit`).

## Secrets leave in one allocation

A password request and a keyboard-interactive response are written into a zeroizing buffer of their final size (`SecretPayload`), so growing leaves no copy, and `Cipher::seal` encrypts that payload's copy in place. Banners, prompt texts, names and instructions are kept as bytes, unfiltered: a server can put terminal escapes in them, which OpenSSH strips (`stravis`) and x/crypto/ssh does not. x/crypto/ssh turns them into Go strings, which never fail.

Nothing bounds the keyboard-interactive rounds of one attempt: a server may send `INFO_REQUEST` after every answer, and the broker answers each prompt with the password. One request of 256 KiB holds about 52k empty prompts, parsed in 2 ms with a 2.6 MB peak (measured on #7). x/crypto/ssh loops the same way; only a deadline on `Phase::Auth` ends it.

## The real sshd tests run only in CI

`crates/justssh-tokio/tests/sshd.rs` logs in to the OpenSSH servers CI starts: with sudo, one with `PasswordAuthentication yes` and `ClientAliveInterval 1`, one with only keyboard-interactive through PAM, which is the case the broker's second method exists for, and two taking only public keys from a directory the test writes (`JUSTSSH_SSHD_KEYS_DIR`: `authorized_keys`, and `ca.pub` from `ssh-keygen`, which also signs the certificate), one of them accepting only `ssh-rsa`; one with RSA, ECDSA P-384 and P-521 host keys and `HostKeyAlgorithms +ssh-rsa` (`JUSTSSH_SSHD_HOSTKEYS_ADDR`), for the host key algorithms that the containers' RSA, P-256 and ed25519 keys leave out; one with `RekeyLimit 4K` (`JUSTSSH_SSHD_REKEY_ADDR`); sshd reads a configuration option's first value, so each server sets `PubkeyAuthentication` itself rather than sharing it; and in a container, OpenSSH 8.7p1, the RHEL 9 version acra_client's upstreams run. A current Rocky Linux 9 image (9.8) installs 9.9p1, while the 9.5, 9.6 and 9.7 vault repositories still give 8.7p1 (measured on #10), so CI pins the 9.5 image and its vault repository, which give `openssh-server-8.7p1-43.el9`. Locally they are skipped unless the variables are set; `JUSTSSH_REQUIRE_SSHD` turns a skip into a failure so CI cannot pass them silently. Running sshd needs root to read passwords, so a local run needs an sshd and an account of one's own.
