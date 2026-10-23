# Fuzzing

How the libFuzzer targets in `fuzz/` check the wire decoders and the transport's message table, and what to watch when changing them.

## Two targets, one check each, kept outside the workspace

`fuzz/` is a cargo-fuzz crate of its own (an empty `[workspace]`), as justrdp keeps its fuzzing (justrdp ADR-0008), so its nightly libFuzzer build never touches the ordinary one. What each target checks lives in `fuzz/src/lib.rs`, and the targets in `fuzz/fuzz_targets/` only hand libFuzzer's input to it:
- `wire` decodes the input as a transport message and as each typed request (`justssh::requests`), and whatever decodes must decode again, to the same value, from its own encoding.
- `transport` reads its first byte as where to put one side of a connection, the rest as messages to send it (each a byte of length less one, then the payload). The six places are a server or a client before key exchange (plaintext packets), in user authentication, and after it (packets from a real peer through `send_raw`).

## What the transport target checks, and what it cannot

The target holds a second table of which numbers each side takes in each place (`takes`), written from the RFCs and ADR-0002 apart from `allowed.rs`. It checks three things:
- A number not taken there ends the connection.
- After authentication, a number the wire crate does not decode is answered with `UNIMPLEMENTED` and does not end it.
- A server ignores a `USERAUTH_REQUEST` after authentication: no reply, and the connection stays.

It follows the side's state only as far as it can: a `KEXINIT` that does not end the connection starts a key exchange, and the target stops checking once the peer's half of the exchange is taken, since what follows is no longer plaintext the target can build.

It cannot tell a wrong `Accept` in the table from a right one. `Transport::dispatch` refuses any message it has no handler for, so the connection ends either way. Measured on #14: letting `allowed.rs` accept `USERAUTH_SUCCESS` at a server, or channel messages before authentication, leaves the target green. The table test in `allowed.rs` turns red on both. The table test checks the table; the target checks the behaviour around it, and the panics and hangs in the handlers.

Known means what `transport-handshake.md` says it means: the numbers the wire crate decodes, and 60, which the transport reads by the method in progress. So after authentication 60 ends the connection at either side, as settled on #34, and 61 is answered with `UNIMPLEMENTED`; both are checked.

## Regressions, and where it runs

An input that crashed a target is kept in `fuzz/regressions/<target>/`, as bytes (`.gitattributes`), named for what it shows. `crates/justssh/tests/fuzz_regressions.rs` replays every kept input through the same function on the stable toolchain, so a pull request runs them all. The kept inputs are also a second corpus for the nightly run. The first ones are the shapes this project already knew to guard:
- a `USERAUTH_SUCCESS` sent to a server (libssh CVE-2018-10933);
- channel data before key exchange, and during a re-exchange;
- an unknown number after authentication;
- a `USERAUTH_REQUEST` after it, to a server and to a client;
- 60 and 61 after it.

`.github/workflows/fuzz.yml` fuzzes each file in `fuzz/fuzz_targets/` for 300 s every night and on demand, keeping its corpus in the Actions cache and uploading a crashing input. It is not a pull-request gate.

libFuzzer does not run on the Windows MSVC host:
- With AddressSanitizer, the built target cannot find its runtime DLL (`STATUS_DLL_NOT_FOUND`).
- With `--sanitizer none`, it does not link (`__stop___sancov_pcs`).

So a local run goes through a Linux container, for example `rust:1` with nightly and cargo-fuzz (measured on #14). There, 120 s ran `wire` about 63,000 times a second and `transport` about 180, since every transport input starts with a whole key exchange; neither found a crash.
