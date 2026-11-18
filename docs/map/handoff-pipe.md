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

## A credential is read on arrival

An ISSUE that parses has its credential read before anything else, before the terminal binding, as acwbroker's `handle` runs `upstream.Check` (#61). `credential::check` goes through the same `private_key` a dial does, as Go's `Check` goes through `authMethods`, so a credential that passes the check is one the dial can read; a certificate bound to another key is caught only by binding it. What it builds is dropped, and a dial reads the key again from the ISSUE's bytes, as Go holds no signer for the life of a token. A password credential is not read.

A refusal is an ERROR with `refusalFor`'s message and a reason record, and the session goes on: `wrong passphrase` (1), `passphrase required` (2), `unsupported private key` (3), `unreadable private key or certificate` (4). The log line is `credential refused on arrival` with the message as `reason` and, as `err`, acwbroker's sentence for the reason (`model.ErrWrongPassphrase` and its siblings) before the cause, as `classify` wraps one in the other; the cause past `upstream: …` is justssh's words, where Go's are x/crypto's. Which reason is Go's `classify`, and some of its turns depend on the format, not on the error alone:
- Only a PuTTY file's reader names what it does not support. An OpenSSH key under a cipher Go cannot read, an encrypted PKCS#8 block and an X25519 key are all 4, while a PPK of another version, key type or KDF is 3.
- A PuTTY MAC that fails is 1 when a passphrase came and 4 when none did, even for a file that is not encrypted and so ignores the passphrase (`KeyFileError::MacMismatch`).
- An empty passphrase is none, as Go tests `len > 0`. Without one, an encrypted OpenSSH or PEM key is 2 before its cipher is looked at. A PPK is read in Go's three stages: its headers, where a cipher other than AES-256-CBC or Argon2 settings over the limit are 3; then the passphrase, 2 without one; then the derivation, where Argon2d is 3 and a name that is no Argon2 flavour is 4.

`tests/credential/check.tsv` is what acwbroker answered for 134 credentials: every key under `justssh-keys/tests` with no, the right and a wrong passphrase; seven PPKs edited to a broken MAC, version 4, `ssh-dss`, Argon2d, a flavour that does not exist, Argon2 memory over the limit and `aes128-cbc`; and certificates for the right key, another key, a plain key and nothing. It was made by running acwbroker's own `Check` and `refusalFor` under `go test -overlay`, which adds a test file to the `handoff` package without touching acwbroker's tree. Two lines differ by the maintainer's choice on #45: a DSA key and an RSA key of three primes, which Go reads and signs with, are 4 here.

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
  - When it cannot be watched, nothing changes, and the session ends with `tunnel could not be watched`. The maintainer's rule in Go is that a frozen broker with no exit to wait for would never end. Off Windows and macOS no process can be watched, so a FREEZE always ends the session there.
  - When it can, the tokens freeze (`broker-tokens.md`) and the listener closes. The serving task is aborted, which drops the listener; connections already accepted are their own tasks and go on.
  - After that, an ISSUE is refused with `frozen` and the session goes on. A second FREEZE is not read.
  - The pipe closing then leaves the process running until the tunnel exits. The tunnel exiting ends the process even with the pipe open, with code 0.
  - Unfrozen, the pipe closing ends the process as before.
  - A tunnel watch that ends without seeing an exit is a gap, not an exit, as in Go's `hold_windows.go` and `hold_darwin.go`. So a frozen broker whose watch failed keeps waiting, as Go's does.
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

## What is absent

Several parts of acwbroker are absent:
- Memory sealing of held credentials. Credentials are held in zeroizing buffers instead.
- Process hardening.

`-unsafe-no-harden` is accepted, as Go's `flag` package accepts it, and changes nothing. `-logpath` and `-profile` name the log's folder and every line's profile (`broker-log.md`). `-dial-timeout` bounds the upstream TCP connect, read as Go's `time.ParseDuration` reads it. `-attach-root` names the roots ATTACH paths may be under. The SSH side is in `broker-relay.md`. Token lifetime and caller checks are in `broker-tokens.md`.

## The host key file

The host key is `-host-key`, or else `<ACRA home>/.store/acwbroker/hostkey`, where the ACRA home is `ACRA_HOME` or `.acrapoint` in the home directory. Any key `KeyFile::read` reads unencrypted is served. One is made when there is no file: an ed25519 OpenSSH key with the comment `acwbroker`, as acwbroker's `hostkey.FileStore` makes it.

The new key is written under a name of its own (`hostkey-<random>.tmp`) and hard-linked into place, so a second start racing the first either reads a whole file or loses the link and reads the winner's. acwbroker measured both simpler shapes failing:
- A shared temp name made concurrent starts fail on Windows.
- Exclusive creation of the final name let a loser read an empty file as a corrupt key.

Beside it is `hostkey-rsa`, for clients that know only `ssh-rsa`: acwbroker keeps it for MobaXterm 10.2's SFTP sidebar, whose SecureBlackbox offers only `ssh-rsa` and `ssh-dss`. It is read on each connection, as Go's `serverConfig` reads it, and made on the first connection that finds no file: RSA-2048 from rsa 0.9 (ADR-0004), written and linked as the ed25519 key is. It is offered after the ed25519 key and under `ssh-rsa` alone (Go `NewSignerWithAlgorithms`), so a client offering only `rsa-sha2-256` and `rsa-sha2-512` finds no host key in common. LISTENING announces the ed25519 key only. A file that cannot be read or made is logged at ERROR as `legacy host key unavailable: hostkey: …`, a key that cannot be offered as `ssh-rsa` (an ed25519 key in that file) as `legacy host key unusable: …`, and the connection goes on with the ed25519 key. `tests/hostkey/hostkey-rsa` was written by Go's `MarshalPrivateKey` as acwbroker's `generate` writes it, and a client offering only `ssh-rsa` is shown the public key Go wrote beside it (#61).

Making the key takes seconds unoptimised, and the blackbox starts every broker on an empty folder, so each one makes a key on its first connection. `num-bigint-dig` and `rsa` are built optimised in dev builds (workspace `Cargo.toml`): the test that makes one took 9.2 to 17.9 s without and 0.9 to 3.0 s with, cargo's start included (measured on #61).

The ed25519 key is read once, at start. acwbroker reads it on every connection too, so a file removed while it runs is made again there and not here.

## A terminal-bound ISSUE

An ISSUE carrying a terminal (0x17) is bound, after its credential is read, to the processes whose controlling terminal it is (`Hooks::terminal_holders`, `peer::terminal_holders`), as Go's `holdersOf` binds it (#68). None holding it, or the lookup failing, is refused with `terminal to bind the token to was not found`, logged as `terminal binding refused` with the terminal and why: `no process holds terminal N`, or the lookup's error. Only the macOS Terminal binds a token to one, so elsewhere the lookup answers `peer: terminal binding is not implemented on this platform`, as Go's `holders_other.go` does.

## Against the blackbox

With `ACWBROKER_BIN` set to this binary, these blackbox tests pass:
- `TestTheHarnessEncodesTheDocumentedLayouts`;
- `TestTheHarnessDecodesTheDocumentedLayouts`;
- `TestAnotherProtocolVersionIsRefusedAndTheBrokerExits`, whose `startBroker` also compares the binary's HELLO with `helloGolden`.

#59 brought the SSH side, and with it 13 more pass (`broker-relay.md`).
