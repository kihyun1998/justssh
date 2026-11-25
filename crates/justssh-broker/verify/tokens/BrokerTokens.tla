------------------------------ MODULE BrokerTokens ------------------------------
(***************************************************************************)
(* One token of crates/justssh-broker/src/tokens.rs and the steps that     *)
(* race on it under Tokens::lock. Each action is one critical section of   *)
(* the code; Tokens::launch_gone, which drops the lock, is two. A spawned  *)
(* timer or watch task is "armed", then "woke", then "none".               *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Pids,        \* pids that present the token (Caller::pid, pinned as u32)
    Launched,    \* pids the app reports for the token (Tokens::launched)
    Cands,       \* other processes Peer::candidates may list
    MaxInc,      \* how many processes may hold one pid in turn (pid reuse)
    MaxT,        \* the last instant of the model's clock
    MaxConns,    \* how many Conn values may be open at once
    Window, Grace, Idle, Admit,  \* Config fields, in clock ticks; 0 is off
    HoldMayFail, \* whether Hold::hold may fail on a live process
    NONE

LP == Launched \cup Cands
Reasons == {"idle", "admission closed"}

VARIABLES
    now,          \* tokio::time::Instant / SystemTime, in ticks
    live,         \* the Entry is in Issued::entries
    frozen,       \* Issued::frozen
    firstAt,      \* Entry::first_at
    pins,         \* Entry::pins
    watch,        \* per pid: the claim task watching that pinned pid
    alive,        \* Entry::alive
    inc,          \* which process holds each pid now (ghost)
    procAlive,    \* whether that process runs (environment)
    expiry,       \* Entry::expiry task
    idleSlot,     \* Entry::idle task while abortable: [at, reason] or NONE
    idleWoke,     \* idle tasks past their sleep, per reason
    conns,        \* Entry::conns, and the Conn values still open
    lastClose,    \* when the last connection closed (ghost)
    attached,     \* Entry::attached: "none", "held", "shredded"
    shreds,       \* paths handed to Config::shred (ghost)
    reported,     \* Entry::reported
    toldClaimed,  \* per launched pid, Config::claimed calls (ghost)
    toldDisposed, \* per launched pid, Config::unclaimed calls (ghost)
    launchIn,     \* pids in Entry::launch
    launchTask,   \* per pid: the watch_launch task
    lgReading,    \* launch_gone calls between their two lock sections
    lAlive,       \* whether each launched or candidate process runs
    everReported, \* pids the app has reported (ghost)
    lastGrant,    \* the Grant the last step handed out, or NONE (ghost)
    pinnedProcs,  \* processes the pin rules meant to pin (ghost)
    disposal      \* how the token was disposed of (ghost)

vars == <<now, live, frozen, firstAt, pins, watch, alive, inc, procAlive,
          expiry, idleSlot, idleWoke, conns, lastClose, attached, shreds,
          reported, toldClaimed, toldDisposed, launchIn, launchTask,
          lgReading, lAlive, everReported, lastGrant, pinnedProcs, disposal>>

\* Everything Dispose leaves alone.
notDisposed == <<now, frozen, firstAt, pins, alive, inc, procAlive, idleWoke,
                 conns, lastClose, toldClaimed, launchIn, lgReading, lAlive,
                 everReported, pinnedProcs>>

Init ==
    /\ now = 0
    /\ live = TRUE
    /\ frozen = FALSE
    /\ firstAt = NONE
    /\ pins = {}
    /\ watch = [p \in Pids |-> "none"]
    /\ alive = 0
    /\ inc = [p \in Pids |-> 1]
    /\ procAlive = [p \in Pids |-> TRUE]
    /\ expiry = IF Window > 0 THEN "armed" ELSE "none"   \* register
    /\ idleSlot = NONE
    /\ idleWoke = [r \in Reasons |-> 0]
    /\ conns = 0
    /\ lastClose = 0
    /\ attached = "none"
    /\ shreds = 0
    /\ reported = {}
    /\ toldClaimed = [l \in Launched |-> 0]
    /\ toldDisposed = [l \in Launched |-> 0]
    /\ launchIn = {}
    /\ launchTask = [x \in LP |-> "none"]
    /\ lgReading = {}
    /\ lAlive = [x \in LP |-> TRUE]
    /\ everReported = {}
    /\ lastGrant = NONE
    /\ pinnedProcs = {}
    /\ disposal = NONE

Disarm(t) == IF t = "armed" THEN "none" ELSE t

\* Tokens::shred: Entry::attached.take() handed over once.
ShredAttached ==
    /\ attached' = IF attached = "held" THEN "shredded" ELSE attached
    /\ shreds' = shreds + (IF attached = "held" THEN 1 ELSE 0)

\* Tokens::dispose, given the task states the caller has already moved.
Dispose(reason, w, lt, ex) ==
    /\ live' = FALSE
    /\ toldDisposed' = [l \in Launched |->
                          toldDisposed[l] + (IF l \in reported THEN 1 ELSE 0)]
    /\ reported' = {}
    /\ ShredAttached
    /\ watch' = [p \in Pids |-> Disarm(w[p])]
    /\ expiry' = Disarm(ex)
    /\ idleSlot' = NONE
    /\ launchTask' = [x \in LP |-> Disarm(lt[x])]
    /\ disposal' = [reason |-> reason, at |-> now, conns |-> conns,
                    lastClose |-> lastClose, first |-> firstAt,
                    armed |-> {p \in Pids : w[p] = "armed"}]

HoldOk(running) ==
    IF ~running THEN {FALSE} ELSE IF HoldMayFail THEN BOOLEAN ELSE {TRUE}

\* Tokens::claim for a caller whose Caller::identity is its own pid.
Claim(p, ok) ==
    IF p \in pins
    THEN UNCHANGED <<pins, watch, alive>>
    ELSE /\ pins' = pins \cup {p}
         /\ watch' = IF ok THEN [watch EXCEPT ![p] = "armed"] ELSE watch
         /\ alive' = alive + (IF ok THEN 1 ELSE 0)

\* The tail of Tokens::authorize once pin has admitted the caller.
Grant(p, kind, first) ==
    /\ conns' = conns + 1
    /\ idleSlot' = NONE
    /\ lastGrant' = [pid |-> p, inc |-> inc[p], kind |-> kind,
                      at |-> now, first |-> first, frozen |-> frozen]

Tick == now < MaxT /\ now' = now + 1 /\ UNCHANGED <<live, frozen, firstAt, pins,
          watch, alive, inc, procAlive, expiry, idleSlot, idleWoke, conns,
          lastClose, attached, shreds, reported, toldClaimed, toldDisposed,
          launchIn, launchTask, lgReading, lAlive, everReported, pinnedProcs, disposal>>

\* Tokens::authorize then Tokens::pin. The checks before the token (session,
\* owner, user), the token and username comparison and rule::admits are taken
\* as passed; a refusal changes nothing, so it is no step.
Authorize(p) ==
    /\ procAlive[p] /\ conns < MaxConns /\ live
    /\ ~frozen
    /\ IF firstAt = NONE
       THEN IF Window > 0 /\ now > Window
            THEN /\ Dispose("expired", watch, launchTask, expiry)
                 /\ lastGrant' = NONE
                 /\ UNCHANGED notDisposed
            ELSE \E ok \in HoldOk(TRUE):
                 /\ firstAt' = now
                 /\ expiry' = Disarm(expiry)
                 /\ ShredAttached
                 /\ toldClaimed' = [l \in Launched |->
                        toldClaimed[l] + (IF l \in reported THEN 1 ELSE 0)]
                 /\ reported' = {}
                 /\ launchIn' = {}
                 /\ launchTask' = [x \in LP |-> Disarm(launchTask[x])]
                 /\ Claim(p, ok)
                 /\ Grant(p, "Claim", now)
                 /\ pinnedProcs' = pinnedProcs \cup {<<p, inc[p]>>}
                 /\ UNCHANGED <<now, live, frozen, inc, procAlive, idleWoke,
                                lastClose, toldDisposed, lgReading, lAlive,
                                everReported, disposal>>
       ELSE /\ Admit = 0 \/ now - firstAt <= Admit
            /\ \/ /\ p \in pins
                  /\ Grant(p, "Pin", firstAt)
                  /\ pinnedProcs' = IF now - firstAt <= Grace
                                    THEN pinnedProcs \cup {<<p, inc[p]>>}
                                    ELSE pinnedProcs
                  /\ UNCHANGED <<pins, watch, alive>>
               \/ /\ p \notin pins
                  /\ now - firstAt <= Grace
                  /\ \E ok \in HoldOk(TRUE): Claim(p, ok)
                  /\ Grant(p, "Grace", firstAt)
                  /\ pinnedProcs' = pinnedProcs \cup {<<p, inc[p]>>}
            /\ UNCHANGED <<now, live, frozen, firstAt, inc, procAlive, expiry,
                           idleWoke, lastClose, attached, shreds, reported,
                           toldClaimed, toldDisposed, launchIn, launchTask,
                           lgReading, lAlive, everReported, disposal>>

\* A pinned process exits; its watch, if armed, sees it (Held::exited).
ProcExit(p) ==
    /\ procAlive[p]
    /\ procAlive' = [procAlive EXCEPT ![p] = FALSE]
    /\ watch' = IF watch[p] = "armed" THEN [watch EXCEPT ![p] = "woke"] ELSE watch
    /\ UNCHANGED <<now, live, frozen, firstAt, pins, alive, inc, expiry,
                   idleSlot, idleWoke, conns, lastClose, attached, shreds,
                   reported, toldClaimed, toldDisposed, launchIn, launchTask,
                   lgReading, lAlive, everReported, pinnedProcs, disposal>>

\* Another process starts under an exited pid. An armed watch keeps the pid
\* held (peer/windows.rs keeps the process handle open until the exit).
PidReuse(p) ==
    /\ ~procAlive[p] /\ watch[p] # "armed" /\ inc[p] < MaxInc
    /\ inc' = [inc EXCEPT ![p] = inc[p] + 1]
    /\ procAlive' = [procAlive EXCEPT ![p] = TRUE]
    /\ UNCHANGED <<now, live, frozen, firstAt, pins, watch, alive, expiry,
                   idleSlot, idleWoke, conns, lastClose, attached, shreds,
                   reported, toldClaimed, toldDisposed, launchIn, launchTask,
                   lgReading, lAlive, everReported, pinnedProcs, disposal>>

\* Tokens::gone, run by the claim task once it woke.
Gone(p) ==
    /\ watch[p] = "woke"
    /\ LET w == [watch EXCEPT ![p] = "none"] IN
       IF ~live
       THEN /\ watch' = w
            /\ UNCHANGED <<now, live, frozen, firstAt, pins, alive, inc,
                   procAlive, expiry, idleSlot, idleWoke, conns, lastClose,
                   attached, shreds, reported, toldClaimed, toldDisposed,
                   launchIn, launchTask, lgReading, lAlive, everReported,
                   pinnedProcs, disposal>>
       ELSE /\ pins' = pins \ {p}
            /\ alive' = alive - 1
            /\ IF alive - 1 = 0
               THEN Dispose("program exited", w, launchTask, expiry)
               ELSE /\ watch' = w
                    /\ UNCHANGED <<live, attached, shreds, reported,
                                   toldDisposed, expiry, idleSlot, launchTask,
                                   disposal>>
            /\ UNCHANGED <<now, frozen, firstAt, inc, procAlive, idleWoke,
                           conns, lastClose, toldClaimed, launchIn, lgReading,
                           lAlive, everReported, pinnedProcs>>

\* The expiry closure in Tokens::register.
ExpiryWake ==
    /\ expiry = "armed" /\ now >= Window
    /\ expiry' = "woke"
    /\ UNCHANGED <<now, live, frozen, firstAt, pins, watch, alive, inc,
                   procAlive, idleSlot, idleWoke, conns, lastClose, attached,
                   shreds, reported, toldClaimed, toldDisposed, launchIn,
                   launchTask, lgReading, lAlive, everReported, pinnedProcs, disposal>>

ExpiryFire ==
    /\ expiry = "woke"
    /\ IF live /\ firstAt = NONE
       THEN Dispose("expired", watch, launchTask, "none") /\ UNCHANGED notDisposed
       ELSE /\ expiry' = "none"
            /\ UNCHANGED <<now, live, frozen, firstAt, pins, watch, alive, inc,
                   procAlive, idleSlot, idleWoke, conns, lastClose, attached,
                   shreds, reported, toldClaimed, toldDisposed, launchIn,
                   launchTask, lgReading, lAlive, everReported, pinnedProcs, disposal>>

\* Conn::drop -> Tokens::closed.
ConnDrop ==
    /\ conns > 0
    /\ conns' = conns - 1
    /\ IF ~live \/ conns - 1 > 0
       THEN UNCHANGED <<idleSlot, lastClose>>
       ELSE LET left == IF firstAt + Admit > now THEN firstAt + Admit - now ELSE 0
                byIdle == Idle > 0
                byAdmit == Admit > 0 /\ (~byIdle \/ left < Idle)
            IN /\ idleSlot' = IF byAdmit THEN [at |-> now + left, reason |-> "admission closed"]
                              ELSE IF byIdle THEN [at |-> now + Idle, reason |-> "idle"]
                              ELSE idleSlot
               /\ lastClose' = now
    /\ UNCHANGED <<now, live, frozen, firstAt, pins, watch, alive, inc,
                   procAlive, expiry, idleWoke, attached, shreds, reported,
                   toldClaimed, toldDisposed, launchIn, launchTask, lgReading,
                   lAlive, everReported, pinnedProcs, disposal>>

\* The closure Tokens::closed hands to after.
IdleWake ==
    /\ idleSlot # NONE /\ now >= idleSlot.at
    /\ idleWoke' = [idleWoke EXCEPT ![idleSlot.reason] = @ + 1]
    /\ idleSlot' = NONE
    /\ UNCHANGED <<now, live, frozen, firstAt, pins, watch, alive, inc,
                   procAlive, expiry, conns, lastClose, attached, shreds,
                   reported, toldClaimed, toldDisposed, launchIn, launchTask,
                   lgReading, lAlive, everReported, pinnedProcs, disposal>>

IdleFire(r) ==
    /\ idleWoke[r] > 0
    /\ IF live /\ conns = 0
       THEN /\ Dispose(r, watch, launchTask, expiry)
            /\ idleWoke' = [idleWoke EXCEPT ![r] = @ - 1]
            /\ UNCHANGED <<now, frozen, firstAt, pins, alive, inc, procAlive,
                   conns, lastClose, toldClaimed, launchIn, lgReading, lAlive,
                   everReported, pinnedProcs>>
       ELSE /\ idleWoke' = [idleWoke EXCEPT ![r] = @ - 1]
            /\ UNCHANGED <<now, live, frozen, firstAt, pins, watch, alive, inc,
                   procAlive, expiry, idleSlot, conns, lastClose, attached,
                   shreds, reported, toldClaimed, toldDisposed, launchIn,
                   launchTask, lgReading, lAlive, everReported, pinnedProcs, disposal>>

\* Tokens::freeze.
Freeze ==
    /\ ~frozen
    /\ frozen' = TRUE
    /\ IF live THEN ShredAttached ELSE UNCHANGED <<attached, shreds>>
    /\ UNCHANGED <<now, live, firstAt, pins, watch, alive, inc, procAlive,
                   expiry, idleSlot, idleWoke, conns, lastClose, reported,
                   toldClaimed, toldDisposed, launchIn, launchTask, lgReading,
                   lAlive, everReported, pinnedProcs, disposal>>

\* Tokens::attach; a second path is refused (AlreadyAttached).
Attach ==
    /\ live /\ attached = "none"
    /\ IF frozen \/ firstAt # NONE
       THEN attached' = "shredded" /\ shreds' = shreds + 1
       ELSE attached' = "held" /\ UNCHANGED shreds
    /\ UNCHANGED <<now, live, frozen, firstAt, pins, watch, alive, inc,
                   procAlive, expiry, idleSlot, idleWoke, conns, lastClose,
                   reported, toldClaimed, toldDisposed, launchIn, launchTask,
                   lgReading, lAlive, everReported, pinnedProcs, disposal>>

\* Tokens::revoke.
Revoke ==
    /\ live
    /\ Dispose("requested", watch, launchTask, expiry)
    /\ UNCHANGED notDisposed

\* Tokens::launched, for a pid the app reports once.
LaunchedReport(l) ==
    /\ live /\ l \notin everReported
    /\ everReported' = everReported \cup {l}
    /\ IF firstAt # NONE
       THEN UNCHANGED <<reported, launchIn, launchTask>>
       ELSE /\ reported' = reported \cup {l}
            /\ IF ~frozen /\ l \notin launchIn
               THEN \E ok \in HoldOk(lAlive[l]):
                      /\ launchIn' = IF ok THEN launchIn \cup {l} ELSE launchIn
                      /\ launchTask' = IF ok THEN [launchTask EXCEPT ![l] = "armed"]
                                       ELSE launchTask
               ELSE UNCHANGED <<launchIn, launchTask>>
    /\ UNCHANGED <<now, live, frozen, firstAt, pins, watch, alive, inc,
                   procAlive, expiry, idleSlot, idleWoke, conns, lastClose,
                   attached, shreds, toldClaimed, toldDisposed, lgReading,
                   lAlive, pinnedProcs, disposal>>

LaunchExit(x) ==
    /\ lAlive[x]
    /\ lAlive' = [lAlive EXCEPT ![x] = FALSE]
    /\ launchTask' = IF launchTask[x] = "armed"
                     THEN [launchTask EXCEPT ![x] = "woke"] ELSE launchTask
    /\ UNCHANGED <<now, live, frozen, firstAt, pins, watch, alive, inc,
                   procAlive, expiry, idleSlot, idleWoke, conns, lastClose,
                   attached, shreds, reported, toldClaimed, toldDisposed,
                   launchIn, lgReading, everReported, pinnedProcs,
                   disposal>>

\* Tokens::launch_gone up to drop(issued). Going on needs a rule and
\* Peer::candidates; without them the token is left to its window.
LaunchGoneFirst(x) ==
    /\ launchTask[x] = "woke"
    /\ launchTask' = [launchTask EXCEPT ![x] = "none"]
    /\ IF live /\ launchIn \ {x} = {}
       THEN \E goOn \in BOOLEAN:
              lgReading' = IF goOn THEN lgReading \cup {x} ELSE lgReading
       ELSE UNCHANGED lgReading
    /\ launchIn' = IF live THEN launchIn \ {x} ELSE launchIn
    /\ UNCHANGED <<now, live, frozen, firstAt, pins, watch, alive, inc,
                   procAlive, expiry, idleSlot, idleWoke, conns, lastClose,
                   attached, shreds, reported, toldClaimed, toldDisposed,
                   lAlive, everReported, pinnedProcs, disposal>>

\* Tokens::launch_gone from the second lock: the process list read without
\* the lock either gave up ("abandon": unreadable list, or an unreadable
\* process named like the program) or named the users to watch.
LaunchGoneSecond(x) ==
    /\ x \in lgReading
    /\ lgReading' = lgReading \ {x}
    /\ IF ~live \/ firstAt # NONE \/ launchIn # {}
       THEN UNCHANGED <<live, toldDisposed, reported, attached, shreds, watch,
                        expiry, idleSlot, launchTask, disposal, launchIn>>
       ELSE \E abandon \in BOOLEAN, users \in SUBSET (Cands \ {x}):
              IF abandon
              THEN UNCHANGED <<live, toldDisposed, reported, attached, shreds,
                               watch, expiry, idleSlot, launchTask, disposal,
                               launchIn>>
              ELSE \E ok \in [users -> BOOLEAN]:
                     LET held == {u \in users : ok[u] /\ lAlive[u]}
                         failed == \E u \in users : ~(ok[u] /\ lAlive[u])
                     IN IF held = {} /\ ~failed
                        THEN /\ Dispose("program gone before use", watch,
                                        launchTask, expiry)
                             /\ UNCHANGED launchIn
                        ELSE /\ launchIn' = launchIn \cup held
                             /\ launchTask' = [y \in LP |->
                                    IF y \in held THEN "armed" ELSE launchTask[y]]
                             /\ UNCHANGED <<live, toldDisposed, reported,
                                    attached, shreds, watch, expiry, idleSlot,
                                    disposal>>
    /\ UNCHANGED <<now, frozen, firstAt, pins, alive, inc, procAlive, idleWoke,
                   conns, lastClose, toldClaimed, lAlive, everReported, pinnedProcs>>

\* Every step but a grant clears lastGrant, so each grant is checked in the
\* state it was made in.
Others ==
    \/ Tick
    \/ \E p \in Pids : ProcExit(p) \/ PidReuse(p) \/ Gone(p)
    \/ ExpiryWake \/ ExpiryFire
    \/ ConnDrop \/ IdleWake \/ \E r \in Reasons : IdleFire(r)
    \/ Freeze \/ Attach \/ Revoke
    \/ \E l \in Launched : LaunchedReport(l)
    \/ \E x \in LP : LaunchExit(x) \/ LaunchGoneFirst(x) \/ LaunchGoneSecond(x)

Next ==
    \/ \E p \in Pids : Authorize(p)
    \/ Others /\ lastGrant' = NONE

Spec == Init /\ [][Next]_vars

\* Bounds the idle tasks a reconnect loop at one instant could pile up.
Bounded == \A r \in Reasons : idleWoke[r] <= 2

---------------------------------------------------------------------------
(* The promises, each checked on its own by check.sh.                      *)

\* A launched process is told CLAIMED or DISPOSED, never both, never twice.
TellOnce == \A l \in Launched : toldClaimed[l] + toldDisposed[l] <= 1

\* An attached path is handed to the shredder at most once.
ShredOnce == shreds <= 1

\* Nothing is granted once the tokens are frozen.
NoGrantWhileFrozen == lastGrant # NONE => ~lastGrant.frozen

\* Each grant follows the pin rules' clock: a claim inside the window, a
\* grace claim inside the grace, nothing once admission has closed.
PinClock ==
    LET g == lastGrant IN
    g # NONE =>
        /\ g.kind = "Claim" => (Window = 0 \/ g.at <= Window)
        /\ g.kind = "Grace" => g.at - g.first <= Grace
        /\ Admit = 0 \/ g.at - g.first <= Admit

\* After the grace, only a process the pin rules pinned gets in.
OnlyPinnedAfterGrace ==
    LET g == lastGrant IN
    g # NONE /\ g.at - g.first > Grace => <<g.pid, g.inc>> \in pinnedProcs

\* Entry::alive counts the pinned processes still watched.
AliveCounts ==
    live => alive = Cardinality({p \in Pids : watch[p] # "none"})

\* A disposal for idleness or for admission closing finds nothing connected,
\* and comes no sooner than its time.
IdleDisposal ==
    disposal # NONE =>
        /\ disposal.reason = "idle" =>
              disposal.conns = 0 /\ disposal.at - disposal.lastClose >= Idle
        /\ disposal.reason = "admission closed" =>
              disposal.conns = 0 /\ disposal.at >= disposal.first + Admit

\* "program exited" only once no pinned process is watched any more.
ExitDisposal ==
    disposal # NONE /\ disposal.reason = "program exited" => disposal.armed = {}
=============================================================================
