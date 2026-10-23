# Broker relay

How the minimal broker (`crates/justssh-broker/src/broker.rs`) takes downstream SSH connections and relays them upstream, and what to watch when changing it. The pipe it is fed by is in `handoff-pipe.md`.

## One connection, one task

Each downstream connection runs in a task of its own, as acwbroker's `broker.go` runs each in a goroutine. The connection's two `Session`s are driven in that one task with `select!`, the shape #26 settled for a relay (`channels.md`), rather than a goroutine per direction and per channel as in Go. `Session` reads while it writes (#37), so the two halves never wait on each other.

Authentication follows acwbroker's `authenticate`:
- One password attempt.
- Three minutes to get past authentication (`Deadlines`).
- The caller is measured from the connection's remote address, and the presented password is judged with it (`broker-tokens.md`).
- The upstream is reached inside that judgement, so an upstream that refuses the credential fails the downstream authentication.

The upstream connection is a TCP connect bounded by `-dial-timeout`, then password and keyboard-interactive, each question answered with the password (Go `passwordAnswers`). There is no deadline after the connect, as there is none in Go (#16, from #7). Any host key is taken (Go `InsecureIgnoreHostKey`), the upstream being acwtunnel on loopback. A channel the upstream opens is refused with `ADMINISTRATIVELY_PROHIBITED` and Go's message.

Both identification lines are `SSH-2.0-justssh`, the server's downstream and the client's upstream, where acwbroker's are Go's default `SSH-2.0-Go`. The blackbox does not look at them. The maintainer chose on #59 to keep justssh's, shown that the downstream line could be set with `software_version` but the upstream one would need a client setter in the core.

## The relay follows acwbroker's

- A downstream channel is opened upstream first. The downstream is answered with the upstream's answer: accepted with no extra data, as Go's `Accept` sends none, or refused with the upstream's reason and its message byte for byte (#41).
- Data and extended data cross both ways. Each side's window is given back to the side it came from only when the side it went to has taken it, at once or on `ChannelDrained` (`channels.md`).
- Requests cross both ways with their replies, channel and global, the global reply's data included. A request on a channel the other side no longer has, or with no upstream left, is answered false.
- An upstream EOF becomes a downstream EOF. A downstream EOF or close becomes an upstream EOF.
- When the upstream half closes, the downstream half is closed once it has sent EOF or closed, or after 5 s (Go `CloseGrace`). A plink exec that never sends EOF therefore takes those 5 s, as it does through Go.
- A host key the upstream presents on a re-exchange is taken.

The replies are kept by which side is owed them. #59 first kept them by which side the request went to, so a reply came back to nobody. `exec` then went unanswered, and plink, given no reply, exited 1 instead of the command's status. The in-process tests check every reply since (measured on #59 with plink's `-sshlog`).

## The token's policy

A downstream channel request is checked before it is sent upstream, as acwbroker's `tapChannelRequests` does (`service/broker/requestlog.go`). Two kinds of request are refused:
- A file transfer, when the ISSUE carried 0x18. That means the subsystem `sftp`, or an `exec` whose first word's base name is `scp` or `sftp-server`. So `/usr/bin/scp -t` counts and `echo scp` does not. The payload is read as Go's `ssh.Unmarshal` reads it: exactly one string and nothing after it, or no file transfer at all. Words split on Unicode white space, as `strings.Fields` splits them, and the base name drops trailing `/`, as `path.Base` does.
- A shell, while the token's one shell is open on any of its connections (`tokens/session.go` `ShellOpened`). A second `shell` on the channel already holding the shell is not a second shell; it crosses, and the upstream answers it. The shell is given back when its channel's pair is dropped: when the channel ends, or when the connection does.

A refused request is answered false and never reaches the upstream. Only its channel is closed; the connection and its other channels stay, as SecureCRT puts its terminal tab and its SFTP tab on one connection.

Go closes both halves at once. Here the upstream half is aborted at once and the downstream half is aborted when the upstream half's close comes back. The order matters because a channel's replies leave in the order of its requests. A `shell` sent right behind a `pty-req` still waiting upstream would otherwise have its refusal dropped by the close; OpenSSH and plink send them that way. Aborting the upstream half fails the waiting request at once (`channels.md`), so both replies go out, and then the close.

No in-process test can see that order. A justssh client fills in a failed reply for a request its channel closed on, and that cannot be told apart from one the peer sent. A mutation closing the downstream half at once survived the test written for it (measured on #60), and that test was removed.

While a refused channel closes, every further request on it is refused without asking the token. Otherwise a `shell` sent there would take the token's shell until the close came back. No test sees that either: the shell is given back the moment the channel closes (a mutation dropping the rule survived, measured on #60).

A token no longer issued allows neither a shell nor a file transfer, as in Go.

When the token is disposed of, the relay sends the upstream `SSH_MSG_DISCONNECT` and goes on as when the upstream ends: each open channel gets its EOF and is closed once its downstream half is done or after the grace, and a new channel is refused with `CONNECT_FAILED`. The downstream connection stays until the client ends it, as in Go.

Go writes each `shell`, `exec` and `subsystem`, and each refusal, to its log. The minimal broker has no log yet.

## How it is proven

`crates/justssh-broker/tests/relay.rs` runs a justssh client downstream and a justssh server upstream standing in for acwbroker's test upstream. It covers:
- an exec's stdout, stderr and exit status;
- a shell's echo;
- a wrong token, and a token presented by another user;
- an upstream that refuses the credential;
- the upstream's refusal of a channel, byte for byte;
- a channel the upstream opens;
- a global request and its answer;
- a token without file transfer: SFTP and SCP are refused, closed within 2 s and never seen upstream, while the shell goes on;
- names that only look like a file transfer cross;
- one shell per token across its connections, given back when its channel ends or its connection drops, and a second `shell` on the channel holding it crossing;
- a disposed token: its upstream ended and a new channel refused.

The broker there is given a probe that measures every connection as one process, since nothing is measured off Windows (`broker-tokens.md`).

Against acwbroker's blackbox, with `ACWBROKER_BIN` set to this binary, these 13 pass besides the three of #15 (measured on #59):
- `TestAnIssueForANonLoopbackUpstreamIsRefusedAndTheSessionGoesOn`
- `TestPlinkRunsARemoteCommandWithTheToken`
- `TestPlinkRefusesAWrongHostKeyPin`
- `TestPlinkShellEchoesThroughTheRelay`
- `TestPsftpListsTheUpstreamDirectory`
- `TestAWrongTokenIsRefusedAndNeverReachesTheUpstream`
- `TestConcurrentSessionsKeepTheirWholeTail`: 128 OpenSSH runs at once
- `TestAnUpstreamGlobalRequestReachesTheClientAndItsReplyGoesBack`
- `TestMeasuredTerminalModesArriveUpstreamByteForByte`
- `TestRequestsWithoutAReplyCrossAndKeepTheReplyOrder`
- `TestSFTPOnASecondChannelBesideTheShellIsAllowed`
- `TestVendorRequestsCrossUnchangedWithTheirReply`
- `TestTheHostKeySurvivesARestart`

With #60 these two pass as well. Built without it, the broker fails both:
- `TestATokenWithoutFileTransferRefusesSFTPAndSCPAndKeepsTheShell`
- `TestOneShellPerTokenAcrossItsConnections`

With #62, `TestATokenIsGoneOnceTheProgramThatClaimedItExits` passes as well. The five that still fail wait on #61 (two) and #63 (three) (measured on #62).
