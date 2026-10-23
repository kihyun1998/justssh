# Handoff pipe

How the minimal broker (`crates/justssh-broker/src/`) speaks acwbroker's handoff pipe on its stdin and stdout, and what to watch when changing it.

## The pipe is acwbroker's, byte for byte

The broker speaks the handoff protocol of acwbroker as of commit 19d90c5 (`internal/infrastructure/handoff`), which is version 11. #15 named version 10, but acwbroker moved to 11 when it added DISPOSED, and the blackbox harness's `helloGolden` says `ACWBROKER PROTO 11`. A frame is `kind(1) length(4, BE) payload`, a payload is `tag(1) length(4, BE) value` records, and a payload over 1 MiB is refused.

The order is acwbroker's `run` (`cmd/acwbroker/main.go`):
1. HELLO goes out, and the echo must carry the same version.
2. The host key is read or made.
3. The listener is bound and LISTENING announces it.
4. Frames are answered until the pipe closes.

Nothing is read or made on disk before the version is settled.

Where acwbroker writes an ERROR, this broker writes one with the same words. Where it writes none, this broker writes none:
- A declared length over the cap, a frame cut short, or a failed read ends the process with no ERROR, as Go's `ReadFrame` returns before anything is written. #15's acceptance asked for an ERROR there; Go's behaviour is what binds.
- A clean close between frames exits 0. Every other end exits 1.

Records are read as acwbroker's `parseRecords` and `rejectUnknown` read them: an unknown tag or a repeated one is malformed. An ISSUE that does not parse ends the session with `malformed credential`. One that parses but cannot be used is refused, and the session goes on:
- `upstream is not a loopback address` when the upstream host is not loopback;
- `credential refused` for anything else.

The checks run in `DecodeIssue`'s order, because the order picks which message a payload with two faults gets. The codec tests carry acwbroker's hand-written goldens, and the blackbox harness's own tests pass against this binary (see below).

## The upstream must be loopback as Go reads it

The loopback check is Go's `net.SplitHostPort` followed by `net.ParseIP`, ported rather than approximated:
- An IPv4-mapped address (`::ffff:127.0.0.1`) is loopback.
- An IPv4-compatible one (`::127.0.0.1`) is not.
- Any non-empty port passes, even `abc` or bytes that are not UTF-8.
- An address that does not split, or splits with an empty port, is refused as a whole (`credential refused`), not as not loopback.

`the_upstream_must_be_a_loopback_address_as_go_reads_one` holds 37 addresses with the verdict Go 1.26.3 printed for each. Rust's own `is_loopback` disagrees on the mapped form, which is why the check is written out. The listen address goes through the same check before binding, so `0.0.0.0:0` binds nothing and answers `listener unavailable`.

## What is answered without being carried out

These are answered the way acwbroker answers when the matching part of it is not wired:
- **FREEZE:** ends the session with `freeze is not supported`.
- **ATTACH:** answered `attach is not supported`, and the session goes on.
- **An ISSUE bound to a terminal:** refused with `terminal to bind the token to was not found`. The terminal lookup is macOS-only in acwbroker and has no counterpart here.

Several parts of acwbroker are absent:
- Memory sealing of held credentials. Credentials are held in zeroizing buffers instead.
- The arrival check that reads a key and names a wrong passphrase.
- Process hardening.
- The log file.
- The legacy RSA host key.

`-logpath`, `-profile`, `-attach-root` and `-unsafe-no-harden` are accepted, as Go's `flag` package accepts them, and change nothing. `-dial-timeout` bounds the upstream TCP connect, read as Go's `time.ParseDuration` reads it. The SSH side is in `broker-relay.md`. Token lifetime and caller checks are in `broker-tokens.md`. Key credentials (#61), and FREEZE, ATTACH, CLAIMED and DISPOSED (#63), are still to come.

## The host key file

The host key is `-host-key`, or else `<ACRA home>/.store/acwbroker/hostkey`, where the ACRA home is `ACRA_HOME` or `.acrapoint` in the home directory. Any key `KeyFile::read` reads unencrypted is served. One is made when there is no file: an ed25519 OpenSSH key with the comment `acwbroker`, as acwbroker's `hostkey.FileStore` makes it.

The new key is written under a name of its own (`hostkey-<random>.tmp`) and hard-linked into place, so a second start racing the first either reads a whole file or loses the link and reads the winner's. acwbroker measured both simpler shapes failing:
- A shared temp name made concurrent starts fail on Windows.
- Exclusive creation of the final name let a loser read an empty file as a corrupt key.

## Against the blackbox

With `ACWBROKER_BIN` set to this binary, these blackbox tests pass:
- `TestTheHarnessEncodesTheDocumentedLayouts`;
- `TestTheHarnessDecodesTheDocumentedLayouts`;
- `TestAnotherProtocolVersionIsRefusedAndTheBrokerExits`, whose `startBroker` also compares the binary's HELLO with `helloGolden`.

#59 brought the SSH side, and with it 13 more pass (`broker-relay.md`).
