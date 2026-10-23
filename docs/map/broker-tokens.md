# Broker tokens

Who may present a token and for how long, in the minimal broker. The code is in `crates/justssh-broker/src/tokens.rs`, `caller.rs`, `rule.rs` and `peer/`. It follows acwbroker's `service/tokens`, `domain/model` and `infrastructure/peer`. Measuring a caller and judging it are kept apart, as in Go: `peer` reads the operating system and `tokens` decides. So the judgement is tested on any platform.

## What is judged, in order

`Tokens::authorize` asks, in Go's `Authorize` order:
1. The logon session, when this process's session is known.
2. Whether any process owns the connection.
3. The account, when this process's account is known.
4. The token. Every live token is compared in constant time, with no early return.
5. The username the token was issued for.
6. The caller rule (`rule.rs`, below).
7. The pin rules (`pin`).

A refusal before the token leaves the token usable.

Go's first check, the freeze, is #63's.

The pin rules have four phases (Go `pinLocked`). A terminal-bound token first requires the caller to descend from one of the terminal's holders, by pid and start time.
1. Nothing has used the token. The window (60 s) still applies, and the caller claims the token.
2. Within the grace of the first connection (5 s, or the ISSUE's 0x1f), any caller that passes the rule may claim it too.
3. After that, only the pinned processes and their descendants get in.
4. Once admission closes (60 s after the first connection), nothing new gets in, pinned or not.

What a claim pins is `Caller::identity`:
- inside the tree of the app (this process's parent), the caller and its ancestors below the app;
- outside it, the caller alone.

## How long a token lives

A token is disposed of when:
- its window closes unused;
- every pinned process that could be watched has exited (Go "program exited");
- its last connection has been gone for the idle time (60 s), or admission closes with nothing connected, whichever is sooner.

A pinned process that cannot be watched stays pinned and does not count towards "every one exited". A timer re-checks under the lock when it fires, as Go's `disposeIfIdle` does. Two guards therefore change nothing alone (measured on #62 by mutation, both survived):
- the early return when another connection remains;
- stopping the idle timer on a reconnection.

Disposal tells each live connection of the token to end its upstream. The relay then sends the upstream `SSH_MSG_DISCONNECT` (`BY_APPLICATION`). Go closes the upstream connection without one. The token and the credential are zeroed as the entry drops.

Go fails the dial of a credential disposed of between the judgement and the dial (`ErrCredentialWiped`). Here the upstream is ended as soon as the relay starts instead: a disposal before it begins leaves a stored notification.

The timers run on the runtime `Tokens::new` is given. Each deadline is fixed when the timer is set. A deadline read when the task first ran came out late by however long the task waited to run. The four tests of idle, admission and window disposal failed on that before it was fixed (measured on #62).

Go's tests move a clock while its timers run in real time. So a token presented after its window, before the timer fires, is refused as expired and removed then. `tests/tokens.rs` reaches that case with `Bench::without_timers`, whose timers run on a runtime nothing drives.

## The caller rule

A rule is one of:
- kind 1: the exact executable;
- kind 2: any executable in its folder;
- kind 3: its folder, or else an executable whose version resource has the company and product contained and the original filename equal.

Further paths are admitted by path alone, whatever the kind. An executable that could not be read is refused for that reason.

Paths are compared as Go compares them on Windows: cleaned as `filepath.Clean` cleans them, and without regard to case. That is done on every platform, since only Windows callers are ever measured. Separators are `\` and `/`, and the volume is `C:` or `\\host\share`. Case is folded by `char::to_lowercase`, where Go uses `strings.EqualFold`'s simple folding; the two differ only for characters no executable path here has carried.

## Measuring a caller on Windows

`peer/windows.rs` holds every Win32 call. It uses `windows-sys` 0.61, as acwbroker uses `x/sys/windows`; the maintainer chose that on #62 over the `windows` crate and over higher-level crates. Those offer no connection owner, session, SID or version resource. The calls and what each relies on:
- `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)` for IPv4 and IPv6, sized and read again while the table grows. The buffer is `u32`-aligned, and each row is read unaligned and only while it fits. A row's port is in network order in the low word of a DWORD, and an IPv4 address is in network order in a DWORD.
- `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`, closed on drop, then:
  - `QueryFullProcessImageNameW` into a 32768-unit buffer, then `GetLongPathNameW`;
  - `GetProcessTimes` for the start time;
  - `OpenProcessToken` and `GetTokenInformation(TokenUser)` into a `u64`-aligned buffer, then `ConvertSidToStringSidW`, whose string is freed with `LocalFree`.
- `ProcessIdToSessionId` from the pid alone, so the session is known even when the image is not.
- `CreateToolhelp32Snapshot` for the ancestry and for this process's parent, which Go's `os.Getppid` reads the same way. Start times are read per process visited.
- `GetFileVersionInfoW` and `VerQueryValueW` for the version resource. The translation table is tried, then `040904b0` and `040904e4`. Results are cached by path, size and modification time.
- `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE)` for the exit watch. One thread owns the handle and waits 500 ms at a time, until the exit or until the hold is dropped. A wait that fails is a watch that ended, not an exit.

The ancestry walk (`caller::walk`) goes up 12 processes at most. It stops where a parent started after its child, since that pid was reused, and on a cycle.

On any other platform nothing is measured, as in Go's `stub_other.go`. Every caller reads as having no owner and is refused. So `tests/relay.rs` gives the broker a probe that always reports the same process.

CI runs on Ubuntu, so the Windows code is linted there with `--target x86_64-pc-windows-msvc` and not run. The maintainer chose that on #62 over a Windows runner. `tests/peer.rs` runs only on Windows. It checks the owner of a connection this process opened (IPv4 and IPv6), its image, session, account and ancestry, a child's exit, and a version resource.

## Not here

- The freeze, the processes the app reports with ATTACH and their watch before use, CLAIMED and DISPOSED, and shredding are #63's.
- The verdict (in-tree, out-of-tree, unmeasured), the admission branch and the reasons for a disposal are only logged in Go, and the minimal broker has no log yet (#66).
- On macOS, Go measures callers with libproc and resolves a terminal binding (0x17) to the processes holding it. That is left to a follow-up, by the maintainer's choice on #62. Meanwhile the pipe refuses a terminal-bound ISSUE (`handoff-pipe.md`), as Go does wherever the lookup is missing.

## How it is proven

`tests/tokens.rs` ports acwbroker's tests of the pin rules, admission, the admission window, disposal, the owner, session and user checks and their order, terminal binding, the caller rule, a failed watch, authorisation, issuing and the shell policy. It also ports the ancestry walk tests. Mutating each rule turned its test red (measured on #62), except the two guards above.

Against acwbroker's blackbox, `TestATokenIsGoneOnceTheProgramThatClaimedItExits` passes with the real measurement: plink is pinned, watched, and its exit disposes of the token.
