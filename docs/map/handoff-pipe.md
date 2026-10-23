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

## FREEZE, ATTACH, CLAIMED and DISPOSED

These follow acwbroker's `pipe.go` `handle`, `cmd/acwbroker/freeze.go` and `main.go` `wireAttach` (#63).

- **FREEZE:** the tunnel's process is watched first.
  - When it cannot be watched, nothing changes, and the session ends with `tunnel could not be watched`. The maintainer's rule in Go is that a frozen broker with no exit to wait for would never end. Off Windows no process can be watched, so a FREEZE always ends the session there.
  - When it can, the tokens freeze (`broker-tokens.md`) and the listener closes. The serving task is aborted, which drops the listener; connections already accepted are their own tasks and go on.
  - After that, an ISSUE is refused with `frozen` and the session goes on. A second FREEZE is not read.
  - The pipe closing then leaves the process running until the tunnel exits. The tunnel exiting ends the process even with the pipe open, with code 0.
  - Unfrozen, the pipe closing ends the process as before.
  - A tunnel watch that ends without seeing an exit is a gap, not an exit, as in Go's `hold_windows.go`. So a frozen broker whose watch failed keeps waiting, as Go's does.
  - A session thread that ends without reporting (a panic) ends the process with an error. No test reaches either case.
- **ATTACH:** a malformed one ends the session with `malformed attach`.
  - Its path must be admitted by the shredder: an absolute path to an existing entry directly under an `-attach-root` (repeatable), not a link.
  - Then the path is attached to the token, and the pid is recorded as launched for it.
  - A refusal for any reason (path, unknown token, a second path) answers `attach refused`, and the session goes on.
  - Otherwise ATTACHED answers, with `used=1` when the token had already been used.
- **CLAIMED and DISPOSED** are written unasked, from the tokens' runtime. The pipe's writing half is shared behind one lock, so a frame is never cut by another (`Pipe`). A write that fails is dropped, since the app may have closed the pipe after a FREEZE.

The session therefore runs on a thread of its own, and the main thread waits for whichever ends the process first: the pipe or the tunnel. So stdin and stdout are taken unlocked.

## Shredding

`shred.rs` follows Go's `infrastructure/shred`:
- **Admitting a path:** it must be absolute, and its cleaned parent must be one of the roots, compared without regard to case on Windows. Something must exist there that is not a link.
  - On Windows, a link is any reparse point except a deduplicated file or a Unix socket. That is what Go's `os.Lstat` reports as a symlink or irregular file since Go 1.23 (`os/types_windows.go`). The tag is read with `FindFirstFileW`.
  - Elsewhere, only a symlink is a link.
- **Shredding:** every regular file under the path is overwritten with zeros and flushed, links are not followed, and then the path is removed.
  - A file that cannot be zero-filled fails the try and leaves everything in place.
  - Tries repeat every 200 ms for 5 s.
  - A path already gone is done. A path still failing at the deadline is left for the app's next start to clear.
  - Shredding runs on a thread of its own, since the retries block.

## What is answered without being carried out

- **An ISSUE bound to a terminal:** refused with `terminal to bind the token to was not found`. The terminal lookup is macOS-only in acwbroker and is left to #68.

Several parts of acwbroker are absent:
- Memory sealing of held credentials. Credentials are held in zeroizing buffers instead.
- The arrival check that reads a key and names a wrong passphrase.
- Process hardening.
- The legacy RSA host key.

`-unsafe-no-harden` is accepted, as Go's `flag` package accepts it, and changes nothing. `-logpath` and `-profile` name the log's folder and every line's profile (`broker-log.md`). `-dial-timeout` bounds the upstream TCP connect, read as Go's `time.ParseDuration` reads it. `-attach-root` names the roots ATTACH paths may be under. The SSH side is in `broker-relay.md`. Token lifetime and caller checks are in `broker-tokens.md`. Key credentials (#61) are still to come.

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
