# Typed requests

How the typed codecs (`crates/justssh/src/requests.rs`) read and build the data of channel requests, and what to watch when changing them.

## A codec never changes the bytes it read

Each codec builds or reads the data of one Opaque Request; there is no typed receive path (ADR-0001). Whatever a codec decodes, it encodes back to the same bytes, for every input it accepts, so a broker can look inside a request and still Pass-through what it received. Three fields are kept as sent for that:

- pty-req's terminal modes are held encoded. `modes()` reads them by RFC 4254 §8: pairs of an opcode and a uint32, stopping at TTY_OP_END, at an opcode from 160 on, or where the encoding is cut short, and staying stopped. An unknown opcode below 160 is read like any other, and nothing after the stop is dropped. russh drops unknown modes, the reason ADR-0001 exists, and refuses bytes after TTY_OP_END and a cut-off pair (`server/encrypted.rs`); x/crypto/ssh hands the modes over as an undecoded `string` (`session.go` `ptyRequestMsg`). So `modes()` does not say whether anything followed the stop: a consumer that cares compares with `encoded_modes()`. To change the terminal or its size and keep a client's modes as sent, build with `from_encoded_modes`; `new` writes the pairs it is given, an opcode of 0 or from 160 on included, after which a reader stops.
- exit-signal's core-dumped flag is held as its byte. RFC 4251 §5 reads any non-zero value as true, as x/crypto/ssh does (`messages.go`, `data[0] != 0`), and writes 1, so a `2` would come back as `1` if it were held as a bool.
- Every text field is held as bytes: the terminal, command, subsystem name, environment name and value, signal name, message and language tag. x/crypto/ssh reads them into Go `string`, which takes any bytes, and a command need not be UTF-8.

## Trailing bytes are refused

A codec refuses data with bytes left after its last field, as x/crypto/ssh's `Unmarshal` does (`messages.go`, `len(data) != 0`). For `exit-status` that is stricter than Go's session, which reads the first four bytes of a longer payload (`session.go`, `len(msg.Payload) < 4`). The request itself still reaches the consumer and passes on unchanged; only the codec declines to read it.

## want_reply is the sender's

A codec holds a request's data only. RFC 4254 has `env`, `exit-status` and `exit-signal` sent without wanting a reply and `pty-req`, `shell`, `exec` and `subsystem` usually wanting one (x/crypto/ssh asks one for each of the latter, `session.go`), but Xshell sends pty-req and shell without (#5), so the flag is left to whoever calls `Session::request`.

## What the proofs cover

`crates/justssh/tests/requests.rs` round-trips every codec on arbitrary data and on the four clients' modes measured through acwbroker (#5), SecureCRT's order included. The real OpenSSH client run with `-tt` and no terminal sends its modes as TTY_OP_END alone, so `openssh_requests_read_through_their_codecs_and_encode_back_to_the_same_bytes` proves the terminal, environment and command bytes, not the modes: a mutation sending the modes as TTY_OP_END alone survived it (measured on #13). That the modes are what a server reads is shown by sshd applying MobaXterm's (`sshd_gives_a_command_the_terminal_a_pty_request_built_from_modes_asks_for`, `stty -a`).

There are codecs for pty-req, shell, exec, subsystem, env, exit-status and exit-signal only (#13). window-change, signal, x11-req and break have none.
