---
name: verify-broker-tokens
description: Model-check the broker's token lifecycle (crates/justssh-broker/src/tokens.rs) with TLA+/TLC. Use when a change touches tokens.rs, Caller::identity or Caller::matches in caller.rs, or the order in which the broker claims, pins, watches, times out, freezes, attaches or disposes of a token.
---

# Verify the broker's token lifecycle

`crates/justssh-broker/verify/tokens/BrokerTokens.tla` models one token of `Tokens` and every step that races on it under `Tokens::lock`: connections, the expiry and idle timers, the exit watches of pinned and launched processes, and the pipe's FREEZE, ATTACH, launched report and revoke. TLC tries every order of those steps within the bounds below and checks eight promises in every state it reaches.

## Does this change touch it?

```sh
git diff 6caf14d2000364b4261c0ce430a43328ddd6f470 -- crates/justssh-broker/src/tokens.rs crates/justssh-broker/src/caller.rs
```

In `caller.rs` only `Caller::identity` and `Caller::matches` are covered. If the diff touches a function in the table below, or adds a step that takes `Tokens::lock` or spawns a task on the tokens' runtime, read the model against the new code before trusting a pass.

| Model action | Code (`tokens.rs` unless named) |
|---|---|
| `Init` | `Tokens::register` (expiry timer set when `window` is non-zero) |
| `Authorize(p)` | `Tokens::authorize` from the freeze check on, then `Tokens::pin` and `Tokens::claim`; `Caller::matches` |
| `Claim(p, ok)` | `Tokens::claim`, `ok` being whether `Hold::hold` succeeded |
| `Grant` | the tail of `Tokens::authorize` (`conns += 1`, idle timer aborted) |
| `ProcExit`, `PidReuse` | the operating system; `Held::exited` firing |
| `Gone(p)` | `Tokens::gone`, run by the task `claim` spawned |
| `ExpiryWake`, `ExpiryFire` | the closure `register` hands to `Tokens::after` |
| `ConnDrop` | `Drop for Conn` then `Tokens::closed` |
| `IdleWake`, `IdleFire(r)` | the closure `closed` hands to `Tokens::after` |
| `Freeze` | `Tokens::freeze` |
| `Attach` | `Tokens::attach` |
| `Revoke` | `Tokens::revoke` |
| `LaunchedReport(l)` | `Tokens::launched` and `Tokens::watch_launch` |
| `LaunchExit`, `LaunchGoneFirst`, `LaunchGoneSecond` | the task `watch_launch` spawns, then `Tokens::launch_gone` before and after it drops the lock |
| `Dispose` | `Tokens::dispose` |
| `ShredAttached` | `Tokens::shred` |

How the model treats a step:
- Each action is one critical section of the code. `launch_gone` drops the lock to read the process list, so it is two actions.
- A task the tokens spawn (a timer in `after`, a watch in `claim` or `watch_launch`) is `"armed"`, then `"woke"`, then `"none"`. `AbortHandle::abort` moves only `"armed"` to `"none"`. A task that has returned from its last `.await` runs its body even when aborted, because it blocks on the std mutex, which is not an await point.
- Every check in `authorize` before the pin rules (session, owner, user, token, username, `rule::admits`) is taken as passed. A refusal changes nothing, so it is not a step.
- A caller's `Caller::identity` is its own pid (outside the app's tree). Ancestors and descendants are not modelled.
- `PidReuse` lets another process take an exited pid unless an armed watch still holds it, as `peer/windows.rs` keeps the process handle open until the exit.
- Time is whole ticks: `Window = 2`, `Grace = 1`, `Idle = 2`, `Admit = 3`.

## Run it

```sh
bash crates/justssh-broker/verify/tokens/check.sh
```

It needs Java 17 or later and `curl`. It downloads TLC v1.7.4 (`tla2tools.jar`) into `$TMPDIR`, `$TEMP` or `/tmp` under `tla2tools-v1.7.4/` and checks its sha256. Set `TLA2TOOLS` to use a jar you already have. Pass config names to run only some of them. The whole run took 42 s on the machine it was written on (4 runs: 27 s, 10 s, 1 s, 2 s).

Each line reads `expected … got …` and `ok` or `UNEXPECTED`. The exit code is 0 only when every run matches. TLC's output for each run is in the `log` path printed on its line.

| Config | Bounds | Expected |
|---|---|---|
| `pins.cfg` | pids `p1`, `p2`, each held by up to 2 processes in turn; no launched process; up to 2 connections; clock 0..5 | pass |
| `launch.cfg` | pid `p1`, one process; launched `l1`, `l2`; candidate `k1`; 1 connection; clock 0..4 | pass |
| `finding-pid-reuse.cfg` | as `pins.cfg` | violates `OnlyPinnedAfterGrace` |
| `finding-idle-race.cfg` | as `launch.cfg` | violates `IdleDisposal` |

`pins.cfg` and `launch.cfg` check `TellOnce ShredOnce NoGrantWhileFrozen PinClock AliveCounts ExitDisposal`.

## The promises

- `TellOnce`: each process the app reports for a token is told CLAIMED or DISPOSED at most once, and never both.
- `ShredOnce`: an attached path is handed to the shredder at most once.
- `NoGrantWhileFrozen`: nothing is granted after a FREEZE.
- `PinClock`: a first claim comes inside the window, a grace claim inside the grace, and nothing comes once admission has closed.
- `OnlyPinnedAfterGrace`: after the grace, only a process the pin rules pinned gets in.
- `AliveCounts`: `Entry::alive` equals the number of pinned processes still watched.
- `IdleDisposal`: a disposal for being idle, or for admission closing, finds no connection open and comes no sooner than its time.
- `ExitDisposal`: "program exited" disposes of a token only once no pinned process is still watched.

## Read every result with `/statechart`

Read each run's log with the pstack `/statechart` skill. For a violation it gives the shortest path to the bad state in plain steps. For a pass it draws how the token moves between states. It runs only when a person invokes it, so give the person the log path and ask them to run it. Until then, read the trace in the log yourself: TLC prints each state after the line `Error: The behavior up to this point is:`, and each `State N:` line names the action that led to it. Tell a counterexample in the code's words, as below.

## The two known findings

Both were found at the sync commit. Both are also in acwbroker (`internal/service/tokens`), which this code ports.

**`OnlyPinnedAfterGrace`: a reused pid gets in after the grace.** `Entry::pins` holds pids (`u32`), and `Caller::matches` compares pids alone.
1. Process 10816 claims the token. `Hold::hold` fails, so 10816 stays pinned and unwatched.
2. 10816 exits. Another process of the same user, session and executable starts and is given pid 10816.
3. 10 s later, past the 5 s grace and inside the 60 s admission, it presents the token. `pin` returns `Admission::Pin`.

With a watch that succeeds, the same happens when the new process connects between the exit and `Tokens::gone`. A scratch test of the real `Tokens` with a `Hold` that always fails confirmed step 3 (`Admission::Pin`). The model with pins compared by pid and process (as `ProcessKey` would compare them) passes `OnlyPinnedAfterGrace`.

**`IdleDisposal`: an idle timer that has woken disposes of the token too early.**
1. The only connection closes at t=0. `closed` sets the idle timer for t=2.
2. At t=2 the timer task returns from `sleep_until` and waits for the lock.
3. The pinned process reconnects. `authorize` aborts the idle timer, which has no effect now.
4. That connection closes. `closed` sets a new timer, "admission closed", for t=3.
5. The old task gets the lock, sees `conns == 0` and disposes of the token as "idle" at t=2, the same instant as the last close, not `Idle` later.

The window for step 3 and step 4 is as long as the woken task waits for the lock. This was not reproduced in the real code.

If a change fixes one of these, its config starts to pass and `check.sh` prints `UNEXPECTED`. Confirm that the model describes the fixed code. Then move the property into `pins.cfg` or `launch.cfg`, delete the finding's config and its line in `check.sh`'s `expected` list, and update this section.

## A real bug or a modelling error?

When a run prints `UNEXPECTED`:
1. Get the counterexample with `/statechart` and write it as steps in the code's words.
2. Check each step against the code it maps to in the table above. Is it one critical section? Does the code check what the model checks, in the same order?
3. If every step can happen in the code, it is a finding. Report it with those steps. Do not weaken the property or the model to make it pass, and do not change product code unless asked.
4. If a step cannot happen in the code, the model is wrong. Fix the model to match the code, then run again.

A config that ends as `broken` means TLC did not run to a verdict, usually a parse or evaluation error. The log says where.

## When a change is intended

1. Change the model to match the new code: the action for each function the change touches, and a new action for each new step that takes the lock or spawns a task.
2. Check that the model can still fail: copy it to a temporary folder, break the guard the change touched, and run that copy with one invariant. Each property was seen failing this way at the sync commit:
   - `TellOnce`: `pin` cloning `reported` instead of `std::mem::take`;
   - `ShredOnce`: `shred` cloning `attached` instead of `take`;
   - `NoGrantWhileFrozen`: the `issued.frozen` check removed;
   - `PinClock`: the admission check removed;
   - `AliveCounts`: `alive += 1` when `Hold::hold` fails;
   - `ExitDisposal`: `gone` disposing without `alive == 0`.
3. Run `check.sh` until every line is `ok`.
4. Then move the sync commit below forward and update the commit hash in the `git diff` command above. Do this only after you have read the covered functions at the new commit against the model.

## Not covered

- More than one token, and the uniqueness of minted tokens (`mint`, `register`'s loop).
- Ancestor and descendant pinning (`Admission::Descendant`, `Caller::identity` inside the app's tree), and terminal binding (`holders`, `WrongTerminal`).
- Shells (`Handle::open_shell`), file transfer, the credential's contents and `wipe`.
- The order in which callbacks run on the runtime (CLAIMED, DISPOSED, shredding, reports). The model checks only what is decided under the lock.
- How the broker uses `Conn::disposed` (`broker.rs`), and the candidate filter's clock (`launched_gone` cutoff): which candidates are listed is left free in the model.
- Liveness, for example that a reported process is eventually told something. Only safety is checked.
- Anything past the bounds above.

## Sync

Last confirmed that the model describes the code at commit `6caf14d2000364b4261c0ce430a43328ddd6f470`.
