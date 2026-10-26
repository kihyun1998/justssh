# broker-crate test for the keyboard-interactive upstream fallback

The `justssh-broker` crate's own tests will not catch the removal of the
keyboard-interactive method from the upstream dial, and we are not adding a
broker-crate test that would.

## The behaviour (which is real and is kept)

A `PasswordAuthentication no` + PAM upstream takes the password over
keyboard-interactive. Given only `ssh.Password`, x/crypto/ssh gives up with
"attempted methods [none]", so acwbroker offers both methods. `broker::upstream`
does the same: for a password credential it builds
`[AuthMethod::Password, AuthMethod::KeyboardInteractive]` and answers every KI
prompt with the password (`crates/justssh-broker/src/broker.rs`). This is
required and stays.

## Why a broker-crate test for it is out of scope

The behaviour is already proven one layer down, against the real thing:

- `crates/justssh-tokio/tests/connect.rs` tests the multi-method negotiation and
  fallback unconditionally, including the failure that reports the tried methods.
- `crates/justssh-tokio/tests/sshd.rs` logs in to a **real PAM-only sshd** using
  the broker's exact methods (password, then keyboard-interactive).

A broker-crate test would be a duplicate guard, and it cannot be built cheaply.
The fake upstream in `tests/relay.rs` is a justssh `Server`, and justssh's
keyboard-interactive is **client-side only** by design: `transport/allowed.rs`
accepts `USERAUTH_INFO_REQUEST` only for `Role::Client`, and the server-side
`accept` surfaces only a `PasswordRequest`. A justssh server cannot send the
INFO_REQUEST a PAM-only upstream sends.

So a broker-crate behavioural test would need one of:

- **server-side keyboard-interactive in justssh** — a library feature nothing
  needs, since the broker is a password server to its downstream and a client to
  its upstream; it never has to *be* a KI server; or
- **a real PAM-only sshd harness in the broker crate** — the container setup
  `justssh-tokio` already carries, duplicated into a second crate for one test.

A cheaper shape-level guard (asserting the methods vector lists
`KeyboardInteractive`) only checks that the code lists what the code lists; it
proves no behaviour and is the kind of tautological test we avoid.

The regression it would guard — someone deleting the KI method — is caught the
moment the real PAM-only sshd test runs, so the coverage lives where the
behaviour is exercised against a real server, not where it is merely configured.

## Prior requests

- #80: "broker 층 테스트가 keyboard-interactive 상류 폴백을 안 잡는다" (from the #16 stage-1 verification)
