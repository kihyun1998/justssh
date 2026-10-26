# Broker log

What the minimal broker writes to its log and how (#66). It follows acwbroker's `cmd/acwbroker/logging.go`, `infrastructure/logfile` and the log calls in `service/broker`, `cmd/acwbroker` and `handoff/pipe.go`. The code is in `crates/justssh-broker/src/log.rs` and `logfile.rs`; the lines are written where the events happen.

## The file

The file is `acwbroker.log` in `-logpath`, or in the ACRA home when that flag is empty.
- **Sharing:** every profile's broker, Go or Rust, may write the same file. So before each line the file held is compared with the one at the path, and reopened when another process rotated it or removed it.
- **Opening:** on Windows the file is opened shared for reading, writing and deleting, so another process can rotate it. A file handle and the one at the path are compared by volume and file index, as Go's `os.SameFile` compares them. On Unix it is created owner-only and appended.
- **Rotation:** at 5 MB the file moves to `.1`, and `.1` to `.2`. Three files are kept in all. A line is never split across two files. A rename that fails stops the rotation, and the line goes into the current file.
- **stderr:** every line is also written there. A sink that fails does not stop the other.
- **No file:** when the file cannot be opened, lines go to stderr only, and the first says so.

## The lines

Each line is what Go's `log/slog` text handler writes:
- `time=` in RFC 3339 with milliseconds and the local offset, then `level=`, `msg=`, `profile=` when `-profile` is given, and the line's own attributes.
- A value is quoted when slog's `needsQuoting` would quote it, in `strconv.Quote`'s form.
- Debug lines are not written, as slog's default level leaves them out.

Go's `%q` and `%v` build the message before slog quotes it again, so `quote` serves both. `tests/log.rs` holds lines Go 1.26.3 printed from the same inputs (measured on #66).

Two things differ from Go:
- **Printable characters:** without Unicode's category tables, a character counts as printable unless it is a control, white space other than the space, a format character, private use or a noncharacter. Go also escapes unassigned code points, which are printed as they are here.
- **The local offset:** it is read on Windows with `GetTimeZoneInformation`, daylight saving included. Elsewhere lines are in UTC. The maintainer chose that on #66 over adding `chrono` and over UTC everywhere.

## What is logged

The same events as Go, in Go's words:
- **Authentication:**
  - `authenticated` with the caller, the verdict, the admission branch and how many connections are live;
  - `authentication failed` with the user quoted and the refusal in acwbroker's words (`tokens::Refusal`);
  - `upstream authentication failed`.
- **The caller:** written as Go's `Identity.String` and `Chain.String` write it: `pid=` and `image=` (or why not), `session=`, `user=` on Windows, then `chain=`, each link's terminal as `tty=` on macOS, and why the walk stopped (`Caller::described`).
- **Handshakes:**
  - `downstream handshake timed out after 3m0s`;
  - `downstream handshake failed`, then what each side offered: the version line and the KEXINIT name-lists. These are kept from the first 16 KiB each way until authentication, as Go's `kexRecorder` keeps them.
- **The end of a connection:** `closed` with `live` and `reason`.
  - `clean` when the client closed the stream.
  - `error` when it sent `SSH_MSG_DISCONNECT`, or a write failed. x/crypto turns a disconnect into an error that is not `io.EOF` (`transport.go` `readPacket`), so Go's `Wait` reports it that way.
- **Channels:** opened and closed, numbered from 1 per connection, with how many are open.
  - A channel is closed in the log when its downstream half has closed or its open was refused.
  - Any still open are logged closed when the connection ends.
- **Requests:**
  - each `shell`, `exec` and `subsystem` request, with the subsystem's name cut to 32 bytes; never the command;
  - each refusal and why;
  - each global request but `keepalive@` ones, its name cut to 32 bytes.
- **The tokens:** `credential disposed` with the reason and how many are left, for a revoke, idle, admission closed, program exited and program gone before use.
  - An expiry is not reported, as Go's `expire` removes without reporting.
  - A pinned process that could not be watched is reported.
- **The pipe and the process:**
  - `attach refused` with why, and `terminal binding refused`;
  - the freeze, the app letting go, and the tunnel exiting;
  - each shred and each failed one;
  - a parent or own account that could not be read.

Lines for parts the minimal broker does not have are absent: memory sealing and hardening. The ed25519 host key is read before the listener, so its per-connection line has no counterpart; the RSA one is read on each connection and has Go's (`handoff-pipe.md`).

Messages from x/crypto have justssh's words instead: the reason a handshake failed, an upstream's refusal, and why a key or certificate did not read. A credential refused on arrival keeps acwbroker's own sentence for its reason before that cause, as Go's `classify` wraps it (#61). The upstream's lists the methods tried as Go's `unable to authenticate, attempted methods [...]` does.

## How it is proven

- **Format and file:** `tests/log.rs` checks lines against Go's own, and ports `logfile_test.go`.
- **Events:** `tests/relay.rs` reads the lines of an authenticated connection, a refused one, an upstream that refuses the credential, and refusals of requests. It checks that no command, token or password appears.
- **Reports and the caller string:** `tests/tokens.rs` checks the disposal reasons, a failed watch and the caller's rendering.
- **The binary:** `tests/pipe.rs` checks the profile, the pipe's warnings, the freeze's lines on Windows and macOS, and that no secret reaches the file.

Mutating the format, the file and each event turned a test red (measured on #66).
- One mutation could not turn red: a downstream ending with nothing more to read is read as `clean`. That path is never reached, since the session reports the close first.
- No test reaches these: the handshake timeout's line, a file that cannot be opened, and the lines main writes for shreds, disposals and failed watches. Each is the same call as one that is tested.
