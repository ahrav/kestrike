# Quint models

[session.qnt](session.qnt) models the session bootstrap of one owner and its
client peers: HELLO, CHALLENGE, CONFIRM, READY, data frames under the active
session, client reboots with fresh boot nonces, a client reopening beside its
active session and a re-key of every endpoint.
The network loses, duplicates, reorders and delays frames until the
environment sets `stable`. [check.py](check.py) runs every case and refuses
any outcome other than the one the case declares; the scheduled and manual
`quint` lane runs it, and `scripts/judge-quint.py` credits the run.

## Handlers and the client rule

The owner keeps, per peer, a pending and an active handshake, the epoch it
last issued, a bootstrap-sequence floor for the active session's client nonce
and one for the most recent other nonce, and the nonce the last activation
displaced. The client keeps its boot nonce, its last bootstrap sequence, its
pending and active handshakes, the CONFIRM repeats it sent for the pending
one and whether an opening is under way. These fields and their handler rules
follow the session table in `crates/kestrike/src/net/session.rs` and the
client endpoint in `crates/kestrike/src/net/client.rs`; the session
table's caps, send sequences and replay windows are the scope of that crate's
tests.

The client's retry repeats the pending CONFIRM at most `REPEATS` times and
then sends a fresh HELLO, which matches `CONFIRM_REPEATS` and the client
endpoint's fallback. `REPEATS = -1` repeats the CONFIRM without bound, which
is the baseline rule and the model's broken variant.

An opening client retries until a READY activates the handshake it opened. An
active client can open a fresh session beside its active one, as the client
endpoint's `session` call does: its HELLO drops the pending handshake and the
active session stays until the new handshake's READY replaces it.

## Properties

| Property | Guarantee |
|---|---|
| `agreement` | A client's active session is the owner's active session for that peer. While the client reopens beside it, the owner may instead hold a later handshake of the same client nonce, activated before its READY reached the client. |
| `activationBinds` | An activation binds the handshake it completes: on CONFIRM the owner's new active session is its pending handshake before the step, and on READY the client's new active session is the owner's active one. |
| `distinctEpochs` | The pending epoch is the last issued in the owner's boot and differs from the active one, which is at most the last issued. |
| `staleChangesNothing` | A frame refused as stale or mismatched changes no session state of the owner or any client. |
| `dataNamesActive` | A data frame is accepted only under the receiver's active session. |
| `bounded` | After stability no frame exceeds the network's copy bound. |
| `progress` | Under weak fairness of stabilization and of each client's retry and bootstrap deliveries, every client ends active. |

## Finite instance and abstractions

Two clients, two boot nonces each, one re-key, at most two distinct bootstrap
frames in flight toward the owner and one toward each client per peer before
stability, one distinct data frame per direction, two copies of a frame, two
CONFIRM repeats, and `FAULTS` interference events before stability: a loss, a
duplication, a reboot, a reopen beside the active session, a re-key or a retry
that fires while a frame of the client's exchange is in flight. The safety case
and `mutant-ready-skips-pending` run at three faults; every other case runs at
two.

- Bootstrap sequences and epochs are relabelled after every step by their
  rank among the values in use, sequences per peer and client nonce and
  epochs per peer. The handlers compare these values only for equality and
  order and create new ones above every value in use, so the relabelled
  system has the same behaviors and finitely many states.
- A re-key drops every frame in flight, since the new keys refuse frames
  sealed under the old ones.
- Data frames are checked for the session they name.
- Counters stay far below their 64-bit limits; the modeled exhaustion is a
  pending handshake whose CONFIRM repeats are spent.
- After stability a retry fires only once the client's exchange has no frame
  in flight, because the retry timer outlasts the round trip.
- The client keeps retrying, so `progress` covers a client whose
  `bootstrap_attempts` outlast the interference, the condition the property
  states.
- A re-key is one step for every endpoint; each `Sessions` re-keys on its own
  call. The owner keeps one boot, so its nonce is fixed within a key epoch.

These are finite checks at the stated constants, and their guarantees cover
this instance.

## Replay against `Sessions`

[replay.qnt](replay.qnt) is the instance at the lane's constants with two
history flags; `quint/check.py` refuses the replay when its `import`
bindings differ from the runner's constants, and records `replay.qnt` as the
case's instance. `crates/kestrike/src/net/q1_replay_tests.rs` drives the
implementation through every action a trace records and compares the
projected owner and client state, the network and each step's verdict with
the trace's state after every action. Four committed ITF fixtures, a clean
activation, the pending displacement, a re-key after a CONFIRM repeat and a
reopen whose new handshake the owner activates before its READY reaches the
client, replay in the workspace lane under plain `cargo test`. The
`connect-replay` case runs the ignored test in which Quint Connect generates
50 seeded traces of `replay.qnt`'s `step` and 10 of its `openThenReopen`
recipe, client c1's handshake without early retries or stability, whose
traces are traces of `step` and reach the reopen that `step`'s random traces
miss, and replays them; its trace count, actions, longest trace and
executions of each action are implementation evidence, reported apart from
the model's results. The runner reads `init` and the choices of
`session.qnt`'s `step` as the model's actions and requires the replay to
reach each one.

## Cases

| Case | Outcome |
|---|---|
| `typecheck` | `quint typecheck` passes. |
| `connect-replay` | Quint Connect replays 60 generated traces of `replay.qnt`, 50 of `step` and 10 of the reopen recipe, against `Sessions` with every projected state matching and every model action reached. |
| `simulation` | 400 seeded simulator traces of 40 steps keep `safety`; trace counts and lengths and each witness's trace count are recorded. |
| `reach-<witness>` | TLC finds a trace to each witness, checked as the inverted invariant `not(<witness>)`. |
| `safety` | Exhaustive TLC check of `safety` at three faults. |
| `progress` | TLC temporal check of `progress` for the corrected rule. |
| `broken-progress` | `progress` fails for `REPEATS = -1` with a lasso in which one peer's pending handshake was displaced and whose loop repeats that peer's CONFIRM, which the owner refuses while its pending handshake names another client nonce. |
| `mutant-reuse-epoch` | An owner that reissues its last epoch fails `distinctEpochs`. |
| `mutant-data-ignores-epoch` | A client that admits data by nonce alone fails `dataNamesActive`. |
| `mutant-hello-drops-active` | An owner whose HELLO also clears the active session fails `agreement`. |
| `mutant-reopen-untracked` | A reopen that leaves the client outside an opening fails `agreement`. |
| `mutant-mismatch-drops-pending` | A client that clears its pending handshake on a mismatched CHALLENGE fails `staleChangesNothing`. |
| `mutant-confirm-shifts-epoch` | An owner that activates a CONFIRM under the next epoch fails `activationBinds`. |
| `mutant-ready-skips-pending` | A client that activates its pending handshake on any READY, at three faults, fails `activationBinds`. |
| `mutant-step-drops-reboot` | A `step` that never reboots a client completes the exhaustive check of `not(witnessReboot)` without a violation, the outcome that `reach-witnessReboot` refuses. |

The runner stops a case at 1100 seconds. `safety` alone declares its own
deadline, 5400 seconds: its search generates 184,286,174 states, 24,353,796
of them distinct, and took 2,561 seconds with eight workers on a 128-core AMD
EPYC 9R14 host. On the CI runner, with eight workers under a four-CPU quota,
the search generated 3.7 and 3.8 million states a minute through its first 18
minutes in two scheduled runs, against 4.6 million on that host, which puts a
complete search there near 53 minutes.

Run locally with Quint 0.33.0 on `PATH`, Java 21 or later, and Apalache
0.62.1 under `QUINT_HOME/apalache-dist-0.62.1`:

```sh
python3 quint/check.py --quint "$(command -v quint)" --workers 8
```

The lane, `bash scripts/rust-lane.sh quint`, installs the pinned tools itself.

### Registry, counts and the recipe step

`verification/quint/expected.json` restates each runner case in its `cases`
map, one line per case, beside the `tests` list of case names and the
`blocked` map. An entry holds `outcome`: `ok` for a typecheck, a replay or the
simulation, and for a TLC case the declared outcome and the property the case
checks, such as `violation distinctEpochs` or `ok safety`, the text an
obligation record's control states for the case. A passing TLC case's entry
also holds `distinct`, the distinct-state count its search must report, a
positive integer, and no other entry holds one or any field other than
`outcome` and `distinct`. The judge refuses as drift, by case name, a map that
names other cases than the runner's, an outcome other than the runner's, a
passing TLC case without a count, any other case with one, an entry that is
not a mapping or holds another field and a count that is not a positive
integer; a registry without a `cases` map is drift as well. A name the runner
declares twice, or the `tests` list names twice, is drift. A name repeated in
one JSON object of the registry, `identity.json` or `results.json`, the JSON
files the judge parses, and a JSON root other than an object are a tool
failure. The judge's self-tests keep the entries in name order, one
line each, as `pins` prints them, and
apply these checks to the committed tree on every pull request, and require
the entry of each control an obligation record cites to equal the text
`control_text` of `scripts/verify-receipts.py` gives for that control, which
`verify-receipts.py admit` requires the control's violation text to equal.

A count is exact and belongs to the tool pins: a tool bump or a model edit
updates the counts in the same change. The judge compares the count the
runner's `judge` reads from each passing TLC case's retained `quint.log` with
the pin and refuses a difference as an outcome mismatch. TLC counts distinct
states by fingerprint, with a fingerprint function it draws for each run, and
prints its estimate of the chance of a collision in the log; a collision
lowers the reported count, so the count is exact up to a fingerprint
collision. A count below its pin on unchanged inputs is rerun by name before
the pin changes, with the pinned tools and worker count and an output
directory that does not exist yet:

```sh
python3 quint/check.py --quint BIN --workers 8 --case NAME --output DIR
```

The case's distinct count is the second element of its `states` in
`DIR/results.json`, and its `DIR/NAME/quint.log` holds TLC's report. The run
is a diagnosis: `pins` and `judge` refuse its output, which is no lane
evidence. A difference that repeats on unchanged inputs goes to the owner. A violation case pins
no count, because an eight-worker search that stops at a violation reports the
count it had reached. After a run, print the entries of its cases with

```sh
python3 scripts/judge-quint.py pins --evidence evidence
```

`pins` applies every check of `judge` except the comparisons with the `cases`
map, the reads of the receipt's inputs included, and prints each entry, with
each count read from the case's log, only for a run those checks credit. It
writes no report or receipt. For any other run it prints nothing on stdout,
writes the refusal to stderr and exits with the refusal's code. That is the
code `judge` gives the same evidence when the `cases` map is current and each
pinned count equals its log. A `cases` map that names other cases or outcomes
than the runner's, or holds a malformed entry, is drift, which `judge`
reports before it reads the run's cases; a well-formed pin that differs from
its case's log is an outcome mismatch at that case. `pins` reads lane
evidence: the directory a `bash scripts/rust-lane.sh quint` run wrote, at the
path its `quint.argv` records, from a checkout at the run's revision. The
output directory of `quint/check.py` alone lacks `identity.json`, `quint.argv`
and `quint.exit`, and evidence moved to another path fails the command check,
so `pins` refuses both.

The scheduled lane runs the cases in two shard jobs, and its `quint` job
judges both raw artifacts into one receipt, the join. To re-derive a join
outside its workflow attempt, as `scripts/verify-receipts.py credit --receipt
--read-only`, `scripts/acceptance.py judge` and `scripts/readiness.py judge`
do, use a checkout at the run's revision and:

1. Extract the `evidence-quint-RUN-ATTEMPT` artifact into a directory at any
   path.
2. Extract both `quint-shard-INDEX-RUN-ATTEMPT` artifacts into
   `shards/quint-shard-INDEX-RUN-ATTEMPT` under it. Copy the files; the judge
   refuses a symbolic link.
3. Set `GITHUB_RUN_ID` and `GITHUB_RUN_ATTEMPT` to the producing run and
   attempt on the command that judges the directory, also inside another
   workflow run, whose own values the judge would otherwise read:

```sh
GITHUB_RUN_ID=RUN GITHUB_RUN_ATTEMPT=ATTEMPT python3 scripts/verify-receipts.py credit \
  --job quint --receipt DIR/receipt.json --evidence DIR --read-only
```

The judge reads the run and attempt from those two variables alone. It
refuses a directory with no `shards/`, which it judges as a single run, and
shards judged with no run identity or with another run's. A passing shard's
artifact is kept 14 days and a failed one's 90, and a refused join's shards
are also kept 90 days as `quint-refused-RUN-ATTEMPT`, so a join is
re-derivable while those artifacts or a saved copy of them exist.

A mutation case that runs under a recipe and declares a violation must violate
at the recipe's last action: its trace holds the initial state and one state
per recipe action. A violation during the recipe's setup fails the case. A
case whose mutated rule breaks the property at an earlier action declares that
trace's length in `trace`, with a comment stating why that state is the kill.
The runner applies the rule in `judge`, and the judge applies it again to each
retained log.

A count equal to its pin shows that TLC reported the same number of distinct
states at the case's bounds, a fact about the model alone, and a fingerprint
collision can hide a difference; the receipt states that no refinement mapping
relates the models to the implementation. A count measures reachable states:
a change that removes transitions between states that stay reachable keeps the
count, and a model whose `safety` conjunction loses a conjunct keeps its
outcome text and its count. A change that edits a model and the registry
together passes, and the registry diff shows it to the reviewer. Pull requests
run the self-tests. The lane runs on the daily schedule and on a manual
dispatch, so the next scheduled run, or a lane the author dispatches on the
branch, finds a changed count. The registry gains one line per case, and a
change that adds a case edits the `cases` map beside the `tests` list, so two
changes that each add a case can conflict there. A skipped or incomplete lane
run is no credit. A count is a pin on the state space and sets no
performance threshold; each case keeps its deadline.

## Detector, nomination and route cores

[detect.qnt](detect.qnt) checks observed-window silence and stalled progress,
duplicate heartbeats, gaps and generation-tagged suspicion, and the arbiter's
flip nomination over that suspicion. Same-boot retracking preserves sequence
and progress high-water. The finite free scheduler uses sequence values 0 to 4,
progress values 0 to 2, either health bit, a seven-turn safety bound,
three-window suspicion, two-window grace, two-window exit and two-tick dwell.
Three observed windows whose every heartbeat reports the sender unhealthy read
a declared failure; a healthy heartbeat resets that count and turns a declared
suspicion gray, and a window with no heartbeat reads it gray. The free
scheduler varies the local kind, the counted gray and declared votes and a
second observer class independently. `HealthyWindowNeverDeclares`,
`DeclaredNeedsOnsetCount` and `GrayNominationHasSecondClass` hold: a gray kind
or a counted gray vote nominates only with a second class, and declared or
silent evidence nominates on one. Controls break the first by counting a
healthy flat window as declared and the last by letting a declared vote mask a
gray one, and further controls break `DeclaredNeedsOnsetCount` by starting the
declared kind at two windows and `HealthyWindowNeverDeclares` by keeping a
declared suspicion across a healthy heartbeat. A window with no heartbeat keeps
the declared count, and a healthy heartbeat in a gap ends it. A nomination
reads the last window close's reading. The host detector's DECLARED-FRESH and
DECLARED-BRAKE rules, which read declared evidence gray after a healthy
heartbeat and under correlated declarations, and its SELF-SUSPICION exemption
of fresh and recovering declarations lie outside the model: after a healthy
heartbeat the model still nominates on the last close's declared reading,
where the host detector refuses. The Rust tests and controls of
`declared-hold-nominates-on-the-ordinary-quorum` check those rules.
`detect-safety-after-declared` and `detect-safety-after-gray` run the free
scheduler for three turns after a declared and a gray prefix, past the
seven-turn bound's reach. The gray prefix admits sequences 0 and 1 and the
declared prefix 1 to 3, and `detect-reach-heartbeat-after-declared` and
`detect-reach-heartbeat-after-gray` show that the scheduler admits a heartbeat
after each prefix and closes its window. `UnhealthyWindowKeepsSilentExit`
holds: a silent suspicion ends after two windows with a healthy heartbeat, a
window whose every heartbeat reports the sender unhealthy keeps that count,
and a window with no heartbeat restarts it. A control breaks it by restarting
the count at an unhealthy window. A nomination's verdict is
the first refusal in the arbiter's order or `Nominate`; it moves no state other
than recording that a nomination was admitted. Placement is caller-validated
evidence.

The progress case runs under `fixedStep`, which schedules only observed
windows, both probes and nomination, with ready evidence and weak fairness of
each of those actions: a peer that sends no heartbeat is eventually
nominated. Removing the second probe's fairness yields a starvation
counterexample. The declared progress case runs under `declareStep`, which
sends one unhealthy heartbeat in every window and nominates on DEAD votes of one
observer class; its heartbeat leaves the stored sequence, which only the
duplicate check reads, so the schedule stays finite. The peer is eventually
nominated, and a verdict that holds a
declared kind to the two-class rule yields a counterexample. AQ-15 withholds
both progress cases and their controls from receipt
credit: the gate was raised against the issuer-uniqueness premise of the
permit model, and credit for the detector-only case stays withheld until the
owner clears it. Gray preservation, gray exit, duplicates, gaps and route safety are
independently credited.

[route.qnt](route.qnt) checks generations 1 and 2, epochs 1 to 3, two holder
identities, two sessions, send stamps 1 to 4 and seven turns of authenticated
frame, READY, withdrawal, request and response actions under the free
scheduler; the directed witness recipes carry their own bounds. The high-water orders tenures by generation, then epoch, so a flip to
a later generation outranks a larger epoch of an earlier one. Equal-`(g, a)`
identity conflicts preserve the tenure in either arrival order and withhold
requests and responses until a higher tenure. A generation has one volume, so
a retirement frame of the held or a later generation darkens that generation
at any epoch and from any state, records no host, and every frame of that
generation keeps it dark and withheld; a late retirement of an earlier
generation changes nothing. An unbound frame keeps a
binding only at the bound tenure. Controls break `RouteMonotonic` by merging
the latest arrival, accepting a response below the high-water, ordering on the
epoch alone, letting a retired generation rebind, letting a late retirement
darken a successor, ignoring a retirement below the held epoch, sending
requests from a dark route, and keeping a binding across a higher candidate.
The model stamps each READY and each not-serving withdrawal with the owner's
send order and delivers them in any order. `binder` is the session whose READY
arrived last at the held tenure, whether or not it moved the route, and a
withdrawal leaves the binding for a Candidate of its tenure only when its
session is the binder and admits it above its highest admitted stamp.
`WithdrawalOrdered`: while the READYs arrived in the order the owner sent them,
the owner sent every withdrawal that takes effect after every READY the route
admitted. Controls break it by withdrawing on a frame the session overtook, by
ignoring the binder, and by leaving the binder unchanged at a READY on a route
that is already Bound. READYs that arrive in the reverse of their send order
are outside the property. `WithdrawalOrdered` covers the READYs that `ready`
delivers. A bound `receive` frame stands for a READY or response of a session
outside the model and clears the binder only when it moves the route, so a
bound `receive` at a tenure already Bound keeps the old binder, where the Rust
table records the READY's session; no property or control checks that reset.
A session's highest admitted stamp rises only at its READY and its newest
withdrawal, since the model has no session-bound response, so the overtaken
witness and its control reach the newest-stamp guard with a withdrawal stamped
below its own session's READY. The owner can send that schedule, a
WrongOwner answering a PROBE before the session's READY (open order 6 on
`ShardRoutes::reply`); the model, which seeds the session's highest stamp with
its READY stamp, keeps the binding there, and the Rust client, whose highest
sequence starts at 0, withdraws. The case checks the guard alone, and the Rust
tests deliver a withdrawal that a later answer of its session overtook. These checks cover the stated finite instances over
candidate, READY and retirement frames and two sessions' READYs and
withdrawals. The committed traces replay the frame, request and response
actions against the Rust route core; `net::client::route::tests` and
`net::owner::tests` cover the withdrawal rule in `ShardRoutes::reply` and the
client's session table.

[detect_route_check.py](detect_route_check.py) declares legal reachability and
control recipes and generates the four committed ITF fixtures. For each family,
run `python3 quint/detect_route_check.py --quint /path/to/quint --family detect --output /path/to/new-directory`
with `detect` or `route`. Rust replay checks the committed model digest, that
each recorded action and its arguments are the declared recipe action, and each
decision's projected state. The lane's replay cases regenerate the traces with
Quint and require them to equal the committed fixtures before replaying. The
driver checks the exact fixture action count. The judge binds credit to the recorded revision, replay sources,
fixtures and retained case inputs.

## Tenure model

[tenure.qnt](tenure.qnt) models one shard record in an asynchronous store:
owner processes bump the attempt counter `E` by a compare-and-swap on
`(g, active volume, owner, E)`, reconcilers flip the shard to its spare by a
compare-and-swap that also names the spare, and the reconciler provisions or
replaces the spare. The store decides each outstanding request once, at any
later step, and a reply may be lost or time out whether or not the request
committed. A process activates `(g, 2n + 2)` only on the acknowledged commit of
its own bump; a timeout refuses. A host may start a new process while an
earlier one is paused with its request outstanding. The owner the shard record
names may issue a Preempt-and-Abort naming its own key once a bump has
committed, or, once its takeover CAS committed, the key of a host whose tenure
that takeover succeeded, directly or through committed takeover writes: the
predecessor it deposed, or, at any depth, the owner an earlier committed
takeover by a host of that chain deposed, the chain successors that stopped
before their preempt leave. This is the model's reading of the parent
amendment's "acknowledged successor of that host's tenure on the same volume":
a successor, directly or through committed takeover writes, of that host's
tenure on the same volume. `deposedBy` computes the chain as the transitive
closure of `lineage` ordered by the `E` each takeover consumed, so the
evidence does not depend on `EMAX`. `preemptAdmitted` states that issuance
rule, with the ended form and the bumped form of amendment A1 beside it, and
`NoPreemptOfForeignKey` checks in every reachable state that every admitted
preempt names the issuer's key, such a host's key or a key of one of those
forms, and that every issued preempt carries admitted key evidence: a self
preempt names its issuer's own key, a takeover preempt names a host whose
tenure the issuer's own acknowledged takeover succeeded, an ended-key preempt
names an ended key that does not hold from the owner past its FB, and a
lineage preempt names the recorded pair of another host that its restart's
Report #1 showed holding, after that restart's own bump and a reread that
named the bumped tenure.

The control plane lists every attachment record of each volume. One foreign
attachment may attach any volume, stale (a fleet host whose attach event the
volume record holds) or unrecorded (software outside the protocol, absent from
the events), and then write it. The owner's poll keeps its volume serving only
on a listing that holds its own attachment and lies inside its admitted set,
and otherwise retires it. The admitted set is the owner and each standby whose
attach event the volume record holds and the poll's caller binds (`bound`), as
the Rust listing admits the owner's attachment and each standby the caller
binds whose attach event the volume record holds; a listing that lacks a
recorded standby retires nothing, as `attachments::check` rules. The stale
attach event names a host that is neither bound nor enrolled, which the poll
retires. The model's poll judges the listing alone: the Rust owner poll's
attach-event check (OWNER-EVENTS, `Trigger::Events`) is outside it. The `kept`
ghost records the listing, the attach events and the bound hosts each kept poll
read, and `AttachOutsideDesiredStateRetires` states the admitted set over them
apart from `admittedSet`, so `admitted-set-ignores-binding`, which drops the
binding from that definition, breaks it as `poll-admits-unbound-attach`, which
drops it at the poll, does. `standbyBind` reads the attach event and no action
removes one, so a bound host has its recorded event in every reached state: no
case of the unmutated model separates a recorded and bound host from a bound
one, and the Rust listing filter `has_attach_event` is a Rust test boundary.
The `admitted-set-ignores-events` control reaches such a host by mutation: its
caller binds a host whose event the record lacks and its admitted set drops the
recorded event, so the poll keeps serving beside that host and breaks
`AttachOutsideDesiredStateRetires` through the ghost's event clause. With that
binding alone, `bind-without-attach-event`, the admitted set excludes the
host, the poll retires the volume, and `RecordedAttachRetiresNothing` breaks.
The ghost reads the control plane's listing
itself and not the value the poll judges, so `poll-filters-listing`, whose
poll judges only the listed attachments with a recorded attach event and keeps
serving beside an unrecorded one, breaks it too. No free-scheduler action
removes the owner's
attachment, so the clause that a kept listing holds the owner holds in every
reached state; the Rust check refuses a listing without the owner and does not
retire on it, which the model does not reach. The model works at host grain:
`bound` grows only, a bound host keeps one instance, and a listing holds no
duplicate record, so a reattach under a new instance and a caller that drops a
peer are Rust test boundaries.

The reconciler attaches a standby in three steps under the free scheduler, in
the order of the parent specification's amendment A3 and D18:
`standbyRecord(h)` records the attach event once an attempt of the owner at the
record's generation reached its FB, the model's stand-in for the page-0 fence
a standby attach waits for; `standbyBind(h)` is the owner poll's caller binding
the host by reading that event; and `standbyAttach(h)` requests the attach,
which the listing then shows. The record is one step, so a flip between the
Rust step's reads, which leaves the attach event on the displaced volume, is
outside the model, and only the owner poll's caller binds: the restart's and a
takeover's binding are outside it. STANDBY-WRITE-ORDER in `failover::reconcile`
now follows the record, bind, request order: `Reconciler::record_standby`
writes the attach entry bound to the host's instance before the request. `RecordedAttachRetiresNothing` checks that no
poll retires a volume whose listing holds the owner and otherwise only
standbys whose attach the reconciler requested, which that order keeps while
the Rust poll reads the volume record; an owner poll whose volume read fails
admits only its caller's peers, so the bind step stays with that caller. The
owner's duties cache the peers that the caller's instance lookup resolved for
its last volume read, so that lookup must return each standby, including one
whose entry binds its instance. The
`poll-judges-recorded-events` control has the poll also require the caller to
bind every recorded attach event other than the owner's, at host grain and
with no enrollment, `E > 0` or attach-count clause, and breaks
`RecordedAttachRetiresNothing` at the poll that follows `standbyRecord`. With
the FB prefix the free scheduler's `BOUND = 9` reaches one standby attach
before a poll and no second one, so in its exhaustive cases a kept listing
holds the owner and at most one standby. A poll over the owner alone reaches an
admitted set of the owner and two bound standbys, neither listed; a poll beside
a listed standby admits the owner and that standby alone. The FB wait bounds
the search and has no control: with `standbyRecord` unguarded, `safety` holds
at `BOUND = 9` over a search about 2.5 times as large. The Report admits each
recorded pair as a non-holding registrant, and `reportPoll` judges no listing.
Adding the admitted set changed the judgment of the owner's `poll` and, of
`reportPoll`, only the frame clause for the new variables. The reclaim
schedule has `reportPoll` judge the holder by attach key, recorded pair and
ended key, judge each registrant by recorded pair and ended key, and record
each ended entry whose key the Report shows absent (see
[Reclaim schedule](#reclaim-schedule)); the takeover and restart schedules
keep their outcomes and state counts. Under the takeover schedules no action
lists a successor's attachment. A standby attach on an active volume requires
`StandbyGate`, which only test builds construct.
The standby's spare check
retires a spare whose listing names another attachment; the
reconciler submits a flip only to a spare whose listing names its standby
alone; and a process at `E = 0`, the fresh path, starts only on a listing of
its own attachment and otherwise refuses and retires the volume. Each check
reads the listing at one instant and retires in that step; the reconciler's
admission of a retirement request, which refuses a request computed before a
flip or an `E` bump, is checked by the Rust tests and lies outside the model.
The local refusal marker that a retained fresh refusal writes, and the refusal
it causes at a later fresh or restart start, are checked by the Rust tests and
lie outside the model.

The model takes two premises of the fresh check as given. A foreign attachment
stays listed: the access-control statement lets only the reconciler detach a
cache-tagged volume, and it binds neither the detach that terminating the
attaching instance causes nor a principal the statement exempts. Every listed
record is visible to the check, although `DescribeVolumes` is eventually
consistent. `FreshIsEmpty` holds at the instant of the fresh check; a foreign
attach and write between the check and the attempt's activation lies outside
it. The listing is a set, so it holds no duplicate record, and every active
volume and named spare lists its holder, so no check reads an empty listing;
the Rust checks retire on a duplicate record and read an empty listing as no
observation.

An active attempt observes a loss from `LOSSES`: a shard record with another
`(g, owner, E)` (`flipped`), a page fence above its session (`newerFence`), a
failed write showing a later tenure (`laterTenure`), a result below its
watermark (`regression`), a retirement trigger (`trigger`) or a planned change
(`planned`). The `observe` action withdraws the attempt in the step that
observes the loss, and the owner's poll that retires its volume records a
`trigger` observation for each active attempt of the owner at the record's
generation and withdraws it in the same step. The `command` action stands for
any medium write, Confirm or reservation command under the attempt's tenure and
runs from an active attempt whose FB is recorded. The write history includes
`command`, the outstanding writes in `midTenure`, and `freshWrite`.

| Property | Guarantee |
|---|---|
| `OneActiveVolumePerShard` | Each generation names one active volume, and no volume is active in two generations. |
| `NoEpochReuse` | No two processes activate one `(g, n)`. |
| `NoBumpAfterFlip` | Every committed bump commits at the generation its process read. |
| `OneFlipPerGeneration` | At most one flip of each source generation commits. |
| `ReplacedSpareNeverActive` | A spare the reconciler replaced or the standby's check retired before a flip activated it is active in no generation. |
| `AttachOutsideDesiredStateRetires` | Every poll that keeps its volume serving read a listing that holds the owner's attachment and otherwise only hosts whose attach event the volume record held and the caller bound at that poll, as the `kept` ghost records them, and left the volume unretired; and the free scheduler's poll or fresh check that read any other listing retired the volume in its step, as did a reclaim poll whose listing held an instance outside the owner and the retained entries. A reclaim poll whose listing holds no such instance retires nothing, whether or not the listing holds the owner: it keeps serving, ends with no verdict (`pollUnobserved`) or, when the owner's own entry is ended or gone, withdraws (`pollWithdrawn`; `missingOwnerPollWithdraws` withdraws on a listing that lacks the owner). This property checks that for the first two, and `EndedAttachNeverRetires` for the withdrawal. `poll-ignores-listing`, `poll-never-retires`, `poll-retires-kept`, whose poll retires on every listing, the kept ones included, `poll-filters-listing`, whose poll judges only the listed attachments with a recorded attach event, `poll-admits-unbound-attach`, whose poll admits every recorded attach event whether its caller binds the host or not, `admitted-set-ignores-binding`, the same widening in the admitted set's definition, and `admitted-set-ignores-events`, whose caller binds a host with no recorded attach event and whose admitted set drops the recorded event, each break it. |
| `RecordedAttachRetiresNothing` | No poll retires a volume whose listing holds the owner's attachment and otherwise only standbys whose attach the reconciler requested. `attach-request-before-record`, whose request needs no attach event, `attach-before-caller-binding`, whose request follows the attach event and precedes the caller's binding, `bind-without-attach-event`, whose caller binds a host with no recorded attach event, so the request follows with no event recorded, `poll-requires-every-standby`, whose poll requires the listing to equal the admitted set, and `poll-judges-recorded-events`, whose poll also requires the caller to bind every recorded attach event, each break it. |
| `FreshIsEmpty` | Every fresh check that passes finds its volume unwritten by any foreign attachment, and every fresh FB has such a check. |
| `NoPreemptOfForeignKey` | Every Preempt-and-Abort the issuance rule admits names its issuer's key, the key of a host whose tenure its committed takeover succeeded, from the record-named owner past its FB an ended key that does not hold (the ended form of the reclaim schedule, amendment A1), or, after its own acknowledged bump at the record's tenure, the key of a recorded pair of another host (the bumped form, amendment A1), and every issued preempt carries admitted key evidence: a self preempt names its issuer's own key, a lineage preempt names the recorded pair of another host that the issuing restart's Report #1 showed holding, after that restart's own acknowledged bump and a reread that named the tenure the bump activated (`armKey`, which reads the `shown` ghost of that Report #1, and `rc.rereads`, fixed at that Report and at the reread, so a preempt that lands after the record moved or after the holder's pair was dropped keeps its evidence, as the reclaim run `armPreemptAfterHolderPairDropped` shows), and a takeover preempt names a host whose tenure the issuing attempt's own committed and acknowledged CAS succeeded, directly or through earlier committed takeover writes at any depth the model's bounds admit (`deposedBy` and `supersedes`). The first clause checks the rule's definition alone, since no action reads `preemptAdmitted`, and `cross-host-preempt`, `foreign-key-preempt` and `takeover-preempt-any-key` rewrite that definition. `takeoverReport1` reads only the record and the Report: a recorded holder other than the issuer while the record names the issuer's tenure. `takeover-preempts-unrecorded-holder` lets it admit a holder outside the recorded hosts, and the `pausedSuccessorRefusesLaterHolder-skips-tenure-check` run drops its tenure check so a paused successor captures the key of a later tenure; each names a key no takeover of the issuer succeeded and breaks the second clause. The lineage arm's `armRereadRefusesMovedRecord-skips-reread`, `armAdmitsUnrecordedHolder`, `armPreemptsUnshownKey`, whose Report #1 captures a recorded pair it did not show holding, and `armPreemptsBeforeBump`, whose Register and reread follow Report #1 with no bump, each break the second clause at the arm's preempt. `preempts` holds a takeover or lineage preempt once the device takes it, an ended-key preempt at its decision and a self preempt when issued, so two further clauses judge the lineage preempt and the takeover preempt in the state their action leaves, whether the device took the command or refused it for a lost registration: the key the command named carries the bumped form's evidence or the takeover's. `armPreemptAfterOwnKeyRemovedRefuses-names-unshown-key`, whose refused lineage preempt names `h3`'s key, which Report #1 did not show, and `preemptAfterOwnKeyRemovedRefuses-names-later-key`, whose refused takeover preempt names `h3`'s key, the key of a later tenure that no takeover of its issuer succeeded, each break their clause. A last clause judges the same key after a failed device step of an attempt whose reread named its tenure, which is the arm's failed lineage preempt (`restartDeviceFail` from `reread`) or its failed Report #2: `armFailedPreemptNamesUnshownKey`, whose failed lineage preempt names `h3`'s key, breaks it. |
| `NamedStandbyTakesOver` | Every committed takeover's and planned transfer's successor is the standby the record named when its write committed; `takeover-unnamed-standby` drops the standby from the start and the CAS condition and breaks it. The takeover schedules check it for the takeover; the handoff roots and the handoff runs check it for the planned transfer, within `safety`. |
| `TakeoverCasBeforeDevice` | Every takeover process that issued a device command activated through its own acknowledged CAS; `takeover-device-before-cas` admits Report #1 while the CAS reply is outstanding and breaks it. Checked under the takeover schedules. |
| `TakeoverIssuesNoBump` | Every outstanding bump of `E` is a fresh attempt's or a restart's: a takeover's one store write is its CAS, and `restartBump` admits restart processes alone. `takeoverBumpsAfterReport1`, whose `restartBump` admits a takeover that its Report #1 left `reported`, breaks it. Checked within `safety`: from the arm root, from the reclaim roots, of which `serving`, `takenOver` and `ended` reach a takeover that its Report #1 left `reported`, and on every run. |
| `InterruptedTakeoverRetainsVolume` | Every committed takeover keeps the generation and the active volume of the record it conditioned on, and that volume is unretired unless `UNRECORDED` holds the reservation, so a successor that stops after its CAS leaves the volume retained, and an unrecorded holder retires it. Checked under the takeover schedules, whose `takeoverStart` does not require a holder, so a takeover between the owner's bump and its fresh Report finds nobody holding, an abstract witness since Rust enrolls a standby only after the owner's fresh Report fenced page 0, whose mid-tenure event is an Abort that keeps the registration and whose self preempt keeps its caller, and whose holders are live attaches; a restart Report #1 with nobody holding refuses `refusedUnheld` with no retirement (NO-HOLDER-HOLD), and `restart-retires-unheld`, which turns that refusal into the flip, breaks it. The no-holder branch tests `holding` alone; registrant membership, host-ID aliases, counts, a registration that ends after it held and a serving Report with nobody holding are Rust test boundaries. |
| `StalePreemptRetainsVolume` | After any issued preempt whose key evidence is admitted, an own-key self preempt, a takeover preempt of the key of a host whose tenure it succeeded, an ended-key preempt whose ended form held or a lineage preempt whose `armKey` evidence held, the record's active volume is unretired unless `UNRECORDED` holds the reservation: the deposed owner's Report hold and its status depositions request no retirement, and an unrecorded holder retires it. Checked under the takeover schedules. |
| `RestartRetiresOnlyOnObservation` | Every retirement a restart refusal requests follows a Report #1 of that restart that showed `UNRECORDED`, a holder outside the recorded set, as the `shown` ghost that `restartReport1` writes records it: a device failure, a recorded holder and nobody holding request none. `restart-retires-device-failure-observation`, which lets `restartRetire` fire from `refusedDevice`, and `restart-retires-recorded-holder-observation` and `restart-retires-unheld-observation`, which relabel those Report #1 refusals `refusedForeign`, break it. Checked under the takeover schedules, which hold `restartRetire`. |
| `DeviceFailureRetainsVolume` | A restart held on a device failure (`refusedDevice`) leaves its volume unretired unless `UNRECORDED` holds the reservation (DEVICE-FAILURE-HOLD); `restart-retires-device-failure-retains` breaks it. Checked under the takeover schedules. |
| `OwnBumpBeforePreempt` | Every attempt that issued a Register or a Preempt-and-Abort, with success or failure, activated through its own acknowledged bump or takeover CAS, as the `fencing` ghost records the issuers, a failed Register or preempt of `restartDeviceFail` included: the lineage arm registers and preempts only after its own bump. `target-activates-on-read`, whose arm registers after Report #1 with no bump, breaks it. Checked under the takeover schedules, whose search at `BOUND = 12` reaches the fencing commands of the fresh path, the takeover and the self preempt and none of the arm's, and within `safety` from the arm root, whose search reaches the arm's Register and preempt. |
| `ArmFbConfirmed` | Every FB a restart reached through the lineage arm follows its host's preempt, with admitted key evidence, of the key its Report #1 captured, and the attempt's own confirming Report #2, whose `fb` grant records the own pair holding under its live key, and each shard read of the attempt, the reread before its preempt and Report #2's, named the tenure its bump activated with its attach live, as `rc.rereads` records them. The preempt is matched by host and key, so an earlier attempt's preempt of the same key by the same host also satisfies it. `armServesWithoutPreempt`, whose failed preempt serves with neither a recorded preempt nor a Report #2, `armServesWithoutReport2`, whose failed Report #2 serves, `armServesWithoutCapturedKeyPreempt`, whose preempt is recorded under its issuer's own key and whose FB, confirmed by Report #2, breaks the preempt clause alone, and `armPausedPreemptRefusesAtReport2-skips-tenure-check`, whose Report #2 grants the FB while the record names another tenure, break it. Checked from the arm root under the takeover schedules (`tenure-takeover-ArmFbConfirmed`), where an arm FB is reachable; the takeover search at `BOUND = 12` ends at the arm's bump. |
| `DetectedLossWithdraws` | No attempt that observed a loss takes a command action at a later turn. The model checks the withdrawal rule only; the Rust tests check the owner's close effects. |

[tenure_check.py](tenure_check.py) declares the cases: each property and
their conjunction at `BOUND = 9` steps, with at most four requests, three
hosts, four volumes and one foreign attachment; thirty-two reachability witnesses,
each checked as the inverted invariant `not(witness)`, `witnessRestartDevice`,
`witnessFreshWrite` and `witnessRerunAfterDeviceRefusal` under `restartStep`, ten takeover witnesses under
`takeoverStep`, `witnessRerunAfterRecordedRefusal` on the `recordedRefusalRerun` recipe, whose rerun lies past
the takeover search's bound and which the arm root's search reaches again, and the rest over the free scheduler, among them
`witnessKeptBesideStandby` (the three-step standby attach followed by a poll
that keeps the owner serving beside the standby), `witnessKeptBeforeStandbyListed`
(a kept poll over the owner alone while a bound standby's attach event is
recorded) and `witnessPollRetiresUnbound` (a poll that retires on a recorded
attach the caller does not bind, which the stale foreign attach reaches, since
the caller never binds its host);
thirty-three runs, each a recipe that restricts the scheduler to one schedule and
passes only when `safety` holds through its last action and that state holds
the end its entry names: the five restart runs below, `v2` retired for the three cross-host runs: `freshForeignAttach`
(a flip to the spare, an unrecorded attach and write of it, the fresh path's
refusal, and a flip to a new spare the next owner activates),
`freshForeignAttachStale` (the same with a stale attach) and `SparePoll` (an
unrecorded attach and write of the idle spare, the standby's check retiring it,
and a new spare activated after the flip), and the twenty-five takeover runs below, which end at their stated states; twenty-one
negative recipes, `midTenureReset-drop-report-2`, `takeoverLosesToRestart-ignores-e`,
`deviceFailThenRerunReachesFb-skips-drain`, the two `postBumpFailRetires-` runs, the two
`reusedAttachmentKey-` controls, `pausedSuccessorRefusesLaterHolder-skips-tenure-check`,
`revisitLaterHolder-skips-tenure-check`, the two `threeHopFreshHostRecovers-` closure controls,
`takeoverBumpsAfterReport1` and the
lineage arm's `armRereadRefusesMovedRecord-skips-reread`, `armAdmitsUnrecordedHolder`, `armPreemptsUnshownKey`,
`armPreemptsBeforeBump`, `armFailedPreemptNamesUnshownKey`, `armServesWithoutPreempt`, `armServesWithoutReport2`,
`armServesWithoutCapturedKeyPreempt` and
`armPausedPreemptRefusesAtReport2-skips-tenure-check`, each a run whose
mutation must break its property at the recipe step the case pins; one mutated run that must pass,
`interruptedTakeoverFreshHostRecovers-one-round`; the prefixed `afterSupersededPreempt` search and its `-reached`
companion, which must reach the search's last turn with the superseded preempt issued; the prefixed
`afterArmReport1` search with `ArmFbConfirmed`'s case at the same root, its four reach cases and its two mutants;
and fifty-one mutations that must each
break one property, the seventeen takeover mutants below and the five DEVICE-FAILURE-HOLD controls included: a withdrawal on a fixed list of two causes, a command from a
withdrawn attempt and a poll that retires the volume but leaves its attempt
active each break `DetectedLossWithdraws`, a non-owner's preempt of the owner's key and an owner's
preempt of another host's key each break `NoPreemptOfForeignKey`, a fresh path that reads the volume record's attach events
in place of the listing breaks `FreshIsEmpty`, a foreign attachment that may
detach, the premise control, breaks `FreshIsEmpty`, a poll that ignores the
listing, a poll that never retires, a poll that retires on every listing, a
poll that filters its listing to recorded attach events, a poll that admits an
unbound recorded attach, an admitted set that ignores the binding and one that
ignores the recorded event under a caller that binds without it each break
`AttachOutsideDesiredStateRetires`, an attach request before the attach
event's record, one before the caller's binding, a binding without a recorded
attach event, a poll that requires every bound standby listed and a poll that
also requires every recorded attach event bound each break `RecordedAttachRetiresNothing`, a flip without its condition breaks
`OneActiveVolumePerShard`, a bump conditioned on `E` alone breaks
`NoBumpAfterFlip`, a process that re-reads after a timeout and adopts the
consumed attempt breaks `NoEpochReuse`, a store that also commits a flip whose
effect the record already holds breaks `OneFlipPerGeneration`, and a flip whose
condition omits the spare breaks `ReplacedSpareNeverActive`. Volume IDs never
recur in the model, so the flip condition's active-volume term refuses a stale
flip on its own: a flip that drops only the generation term breaks no property
at these bounds, and the control removes the whole flip condition. These are
finite checks at the stated bounds.

The restart cases run under `restartStep` at `BOUND = 15`: the owner's start at
`E = 0`, a reconciler's flip, mid-tenure events, landings of the ended
incarnation's writes and the restart sequence. `BumpAtOwnGeneration`,
`NoPredecessorEffectAfterFB` and `NoWriteBeforeFB` check there alone;
`RecordsBeforeDevice` and `OwnBumpBeforeFB` check there and under the takeover
schedules, and
`NoEpochReuse` also gains a `tenure-restart-` case. The runs `midTenureReset`,
`midTenureAbort` and `midTenureQueueDelete` end at the restart's FB, the
`witnessRestartDevice` witness reaches a restart's device command, and six of the
`restart-` mutants under `restartStep` each break one of these properties: `RecordsBeforeDevice`
holds when every device command follows a passing record read, `BumpAtOwnGeneration`
when every committed bump commits at the generation its attempt read, and
`NoPredecessorEffectAfterFB` when no ended incarnation's write lands after the
serving restart's FB, for an attempt that holds the record's current tenure:
its host, generation and `E` are the record's. `held` and `queued` count every
ended incarnation's writes, so the model's ready wait drains a deposed
predecessor's writes as well as the restarting host's own; the Rust ready wait
drains only the restarting host's, so the property claims no cross-host drain
for a successor's restart after a takeover, nor for the lineage arm's FB over
another host's holder: that FB is judged through a drain of the other host's
writes that the Rust restart does not perform. A takeover's FB drains no
predecessor: the deposed owner's write may land after it, so the property
excludes takeover attempts, and the recovery order and the preservation
mechanism carry that residual; `witnessLandAfterTakeoverFb` reaches a landing
after a takeover's FB under `takeoverStep`, and the `takeoverPredecessorLanding`
run lands the deposed owner's card-held write after the successor's FB. The
property excludes an attempt whose tenure the record no longer holds, which may
keep serving until it observes its deposition, and the
`takeoverSuccessorLanding` run lands a successor's write while the deposed
owner's fresh process stays active.

The takeover cases run under `takeoverStep` at `BOUND = 12`: fresh activation,
a mid-tenure Abort that keeps the registration, any owner's restart with a self
preempt that keeps its caller or the lineage arm, standby designations and
takeovers by named and unnamed hosts. The shard record names at most one standby,
`rec.standby`; `nameStandby(h)` is the enrollment write of a function outside
the cache hosts. `takeoverStart(h)` reads the records: a host the record does
not name refuses with no request, and the standby submits the takeover CAS,
the model's field-conditioned form of the exact-version CAS, conditioned on
`(g, active, owner, E)` and the standby, writing itself as owner at `E + 1`
with no standby. The model has no record versions, so a designation changed
away and back, and a checkpoint-only write, are Rust test boundaries.
`takeover-unnamed-reaches-device` admits an unnamed host to the CAS and its
device steps and breaks `RecordsBeforeDevice`. The acknowledged reply activates its
session, and every device step follows it: `takeoverReport1` admits as holder
only a recorded host other than the issuer while the record names the issuer's
tenure, one step for Report #1 and the tenure check before the preempt, and
captures its key, and `takeoverPreempt` names that key even after the record
moves. Matching the
holder transfers the reservation; a different PRKEY leaves the holder in
place. A successor may crash after the CAS; the record then names it with no
standby, and its next process reads the record naming itself. A restart Report
showing a recorded pair of another host holding, of a live attach or an ended
one, takes the lineage arm described below, and a restart Report showing nobody
holding beside only its own and recorded pairs refuses without a flip
(NO-HOLDER-HOLD), which a
registration that ended without a preempt leaves; an unrecorded registrant
keeps the refusal and its flip; the Rust hold also requires a conclusive count and at most one record of the own host ID, under the own key (`unheld_among_recorded`); `restartRetire` models the exact-target retirement request after
Report #1 shows an unrecorded holder. The takeover schedules end no attach;
the reclaim schedule below ends attaches, and a restart Report #1 showing the
holder under an ended attach's recorded pair takes the arm as well
(`endedHolderRestartHolds`, `endedHolderRestartReachesFb`). A recorded pair of
another attach of the restart's own host refuses `refusedRecorded`; no root,
run or control reaches or guards that case at the default constants, since
it needs the restarting host to attach again and enroll while its other
attach's pair holds. A holder under an ended key whose pair the record
dropped holds no recorded pair, so it takes no arm, and refuses
`refusedRecorded` as well (`recordedKey`): `droppedKeyHolderRestartHolds`
reaches that case at six processes, and
`reclaim-restart-retires-dropped-key-holder` guards it. The
`restart-retires-recorded-holder` control turns the arm into the retirement
request, and `restart-retires-unheld` turns the no-holder refusal into it; each
breaks `InterruptedTakeoverRetainsVolume`. `unheldTakeoverRestartHolds` takes over
between the owner's bump and its fresh Report: the successor's Report #1
refuses with no preempt, and its restart refuses `refusedUnheld` with `v1`
retained. That takeover is an abstract witness: Rust enrolls a standby only
after the owner's fresh Report fenced page 0, so no Rust takeover commits
before that Report. In the model the owner's own restart after a timed-out
fresh bump also reaches nobody holding; it stands for a Rust fresh process that
stopped after its bump, since a Rust fresh bump with an unknown outcome refuses
its restart at the local-record step with the flip. The Rust tests under `no-holder-hold-retains-volume`
carry the registrant-membership, host-ID and count checks and the owner-poll
and serving-Report holds. The model checks NO-HOLDER-HOLD retention through
`InterruptedTakeoverRetainsVolume` and, by what Report #1 showed,
`RestartRetiresOnlyOnObservation`, both on the takeover schedule. `takeoverThenOwnRestart` reaches the arm
while the predecessor still holds the volume. A host whose restart refused
at Report #1, or whose arm refused or held, may restart again;
`witnessRerunAfterUnheldRefusal` and `witnessRerunAfterForeignRefusal` reach
such a restart after each Report #1 refusal under the takeover schedules, the
rerun after an unrecorded holder through its Report #1, and
`witnessRerunAfterRecordedRefusal` reaches the rerun after the arm's bump
committed with its reply lost on the `recordedRefusalRerun` recipe, whose rerun
takes the arm again with `v1` retained. The final Report checks the
acknowledged target before recording an FB.

The lineage arm (D20) is the one sequence by which a host the record names
owner reaches FB while a recorded pair of another host holds: a handoff
target, a successor whose takeover CAS committed with its reply lost or that
stopped before its preempt, and a tenure that withdrew because a recorded
holder of another host took the reservation while the record still names it
owner. `restartReport1` captures the holder's key (`reportedHolder`), the
restart bumps `E` on its step-1 read as on the own path, and after the
acknowledged reply `restartRegister` adds its key, `restartReread` rereads the
shard record, which must still name the bumped `(g, owner, E)` with the
restart's attach live, and `restartLineagePreempt` preempts the captured key in
a later step, which another host's takeover can precede; Report #2 then
confirms the own pair and, as for a takeover, that the record still names the
bumped tenure, and records FB. A reread that shows another tenure refuses with
no preempt, and every failed device step of the arm holds through
`restartDeviceFail` with no flip, the one RECORDED-HOLDER-HOLD left to a
restart; a refused or unknown bump ends the restart with no Register and no
preempt. The issuance rule gains the bumped form of amendment A1, and each
lineage preempt records as its key evidence, fixed at Report #1 and at the
reread, that the
reread named the tenure the issuing attempt's own acknowledged bump activated
and that Report #1 showed the key holding as the recorded pair of another
host. `restartBump` admits restart processes alone, so a takeover that its
Report #1 left `reported` issues no bump (`TakeoverIssuesNoBump`).
`OwnBumpBeforePreempt` requires every attempt that issued a Register
or a preempt to have activated through its own acknowledged bump or CAS, and
`target-activates-on-read`, whose Register follows Report #1 with no bump,
breaks it; `ArmFbConfirmed` requires every arm FB to follow the preempt and
the attempt's own confirming Report #2. The runs:
`takeoverUnknownRestartReachesFb` and `takeoverCrashRestartReachesFb` carry a
successor's restart through the arm to FB at `E = 3` on `v1`;
`armRerunReachesFb` reruns after the arm's bump committed unacknowledged and
reaches FB at `E = 4` under the rerun's own session;
`armRegisterFailRerunReachesFb` holds on a failed Register and reruns to FB;
`armRereadRefusesMovedRecord` lets a takeover by a host named over the bumped
tenure commit before the reread, which refuses with no preempt, and its
`-skips-reread` control preempts anyway and breaks `NoPreemptOfForeignKey`;
`armAdmitsUnrecordedHolder` lets Report #1 take the arm for `UNRECORDED` and
breaks it too; and `reusedAttachmentKeyRestartReachesFb`, at `EMAX = 5` and
five requests, carries the deposed tenure of `reusedAttachmentKey` through its
own restart's arm to FB, preempting the stale holder's key (U76-D1); and
`armPausedPreemptRefusesAtReport2`, at `EMAX = 5` and five requests, lets
`h3`'s takeover commit after the arm's reread passed: the paused preempt lands
and takes the reservation, the arm's Report #2 refuses on the tenure check with
no FB, and `h3` recovers through its own restart's arm on `v1`; its
`-skips-tenure-check` control drops that check and reaches the arm's FB while
the record names `h3`, an arm FB whose Report #2 read another tenure, which
breaks `ArmFbConfirmed`.

The arm root. The takeover search at `BOUND = 12` reaches the arm's Report #1
at its eleventh state and the bump's issue at its last, and no acknowledged
arm bump, Register, reread, preempt or arm FB; the two `serving` reclaim roots
reach the arm's Register at their last turn, and the other six reclaim roots
reach no arm state. The prefixed `afterArmReport1` search therefore starts at
the arm: its prefix is `takeoverUnknownThenRestart`'s recipe, `h2`'s committed
takeover with a lost reply and its restart's Report #1 with `h1` holding, and
it then runs `takeoverStep` for 12 turns at `EMAX = 5` and five requests.
`tenure-takeover-afterArmReport1` checks `safety` there and
`tenure-takeover-ArmFbConfirmed` that property alone; each must reach its last
turn. Past the prefix the search reaches an arm FB (`witnessArmFb`), a reread
that refuses (`witnessArmRereadRefused`), a Report #2 that refuses after the
arm's admitted preempt (`witnessArmReport2Refused`) and a rerun after the arm
refused or held (`witnessRerunAfterRecordedRefusal`), and it rejects two
mutants past the prefix: `-mutant-skips-reread`, whose reread admits a moved
record, breaks `NoPreemptOfForeignKey`, and
`-mutant-report2-skips-tenure-check` breaks `ArmFbConfirmed`. The root's search
reaches no lineage preempt of an unregistered issuer; that refusal is the
reclaim run `armPreemptAfterOwnKeyRemovedRefuses`, the one case in which
`NoPreemptOfForeignKey` judges the key of a refused lineage preempt, as
`preemptAfterOwnKeyRemovedRefuses` is for a refused takeover preempt.

DEVICE-FAILURE-HOLD: `restartDeviceFail(p)` ends a restart device step without
success, from `records` (the ready wait), `ready` (the host ID or Report #1),
`bumped` (the self preempt or the arm's Register), `reread` (the arm's
lineage preempt) or `preempted` (Report #2), with the command
issued, into `refusedDevice`: no FB and no retirement. A failed Register or
preempt is an issued fencing command, which `fencing` records. A hold from
`bumped`, `reread` or `preempted` follows the activation of its acknowledged
bump, and no rerun reuses that activation. A bump
without an acknowledged success already ends `refused` through `reply` or
`timeout`, which retire nothing. Both schedules hold the action, and
`restartRecords` admits a rerun after `refusedDevice`. The hold ends by a rerun
or a takeover: `deviceFailThenRerunReachesFb` fails the ready wait with a write
card-held and the rerun reaches FB at `E = 1`, and
`postBumpFailThenRerunReachesFb` fails the self preempt after the bump and the
rerun bumps again and reaches FB at `E = 2` under its own session.
`deviceRefusalThenTakeover` reaches the named standby's FB on the retained
volume after the owner's hold. `witnessRerunAfterDeviceRefusal` reaches a rerun
after the hold under `restartStep`. The holds that keep the volume:
`unknownTakeoverRestartDeviceFailHolds` fails the ready wait of the restart
after a committed CAS with a lost reply, `interruptedTakeoverReport1FailHolds`
fails Report #1 of the restart after a successor stopped before its preempt,
and `unheldThenDeviceFailHolds` fails the ready wait of the rerun after a
`refusedUnheld` refusal; each ends with `v1` unretired.
`restart-retires-device-failure` lets `restartRetire` fire from `refusedDevice`
and breaks `InterruptedTakeoverRetainsVolume`, and its `-observation` and
`-retains` cases break `RestartRetiresOnlyOnObservation` and
`DeviceFailureRetainsVolume`; each variant also admits the bumped target for a
`refusedDevice` process, and the `postBumpFailRetires` runs, the
`postBumpFailThenRerunReachesFb` prefix through the failed self preempt and then
that retirement, break `DeviceFailureRetainsVolume` and
`RestartRetiresOnlyOnObservation` after the bump. Three controls show a held
attempt reaches no FB and
weakens no drain: `restart-device-failure-serves` lets the failed step reach FB
and breaks `OwnBumpBeforeFB`; `restart-rerun-reuses-bump` lets a rerun after a
post-bump hold resume at the held attempt's `E` without its own bump and breaks
`NoEpochReuse`; and `deviceFailThenRerunReachesFb-skips-drain` lets the rerun's
ready wait skip the drain after a hold and breaks `NoPredecessorEffectAfterFB`.
The restart's status values, unparseable bytes and bump error arms are Rust
test boundaries under `restart-device-failure-holds`. Host, shard and volume binding,
local-record and reread validation are Rust test boundaries; `HOSTS`
represents the model's complete recorded set.

The P1 runs: `staleStandbyDesignation` moves the designation between the
standby's read and its CAS, which fails its condition with no device command;
`twoAttachedOneNamed` refuses the unnamed host with no request and reaches the
named standby's FB; `takeoverUnknownThenRestart` loses the reply of a
committed CAS, issues no device command, and the successor's restart takes the
lineage arm over the recorded predecessor. The P9 run `interruptedTakeoverFreshHostRecovers`
stops the successor after its CAS; the host designated over its tenure commits
its CAS, its Report #1 admits the earlier owner, whose tenure the stopped
successor's committed takeover deposed, and it preempts that owner's key and
reaches FB on `v1` at its generation. `pausedSuccessorRefusesLaterHolder` keeps
the middle successor alive: once the later host holds, the middle successor's
Report #1 shows it while the record names the later tenure, so it refuses with
no preempt. `threeHopFreshHostRecovers`, under `EMAX = 4`, stops two
successors in turn and the third preempts the owner three takeovers back;
its `-one-level` control cuts `deposedBy` to the direct predecessor and its
`-one-round` control cuts it to one earlier takeover; each breaks
`NoPreemptOfForeignKey`, while `interruptedTakeoverFreshHostRecovers-one-round`
still holds, so three hops need the closure. `revisitLaterHolder-skips-tenure-check`,
under `EMAX = 4` with Report #1 skipping the tenure check, has the paused middle
successor capture the later host's key while the owner takes the record back over
that later tenure at a higher `E`; the middle successor's preempt of that key breaks
`NoPreemptOfForeignKey` through the closure's `E` ordering alone, and the same run
passes with that ordering removed. `witnessSupersededPreempt` reaches a preempt of a host other than the
direct predecessor under the takeover schedules, and `afterSupersededPreempt`,
at `EMAX = 4` with the middle successor live, runs the free takeover schedule,
restarts included, five turns past the two-hop preempt under every takeover
invariant, and `afterSupersededPreempt-reached` fails unless that search reaches
its last turn with the preempt issued.
`restartTakeoverRace` refuses the losing restart, and `takeoverLosesToRestart`,
the same race with the restart's bump committing first, refuses the losing
takeover at its CAS; `takeoverLosesToRestart-ignores-e`, a takeover CAS
conditioned on `(g, active, owner)` and the standby without `E`, lets both
commit and breaks `NoEpochReuse` on that recipe. The takeover invariants and
controls retain their named `tenure-takeover-` and `tenure-mutant-` cases.
`reportPoll` is the serving owner's Report-aware poll under the takeover schedules:
the own pair holding keeps the owner serving, a recorded foreign holder
withdraws every serving attempt of the record's current tenure, its host,
generation and `E`, active past its FB, with no retirement
(RECORDED-HOLDER-HOLD), and an unrecorded holder retires the volume with the
alarm. `HOSTS` is the complete recorded set, so the one unrecorded holder is
`UNRECORDED`, which `statusDeposition(true)` installs. `statusDeposition` is
the deposed owner's command completing with a deposing status (`0x1B`,
`0x83`) while serving: it withdraws every serving attempt of the record's current tenure, at least one,
and requests nothing (STATUS-IS-DEPOSITION), and each attempt it
withdrew takes one more `reportPoll`, which judges the holder
(STATUS-REJUDGE). `witnessStatusRetires` reaches that Report retiring the
volume under an unrecorded holder. `StalePreemptRetainsVolume` checks that the
volume is unretired unless `UNRECORDED` holds after every issued preempt
with admitted key evidence. A recorded host's preempt holds over a serving
owner only after a stale preempt over a later tenure under a reused key, which
needs four attempts, so the hold is the `reusedAttachmentKey` run's:
`reusedAttachmentKey-poll-retires` restores retirement at the Report and
`reusedAttachmentKey-status-retires` restores it at the status, and each breaks
the invariant at its step. `reusedAttachmentKey` runs at four
allowed attempts and 26 steps: B pauses after its CAS and its Report #1, A,
named standby over B's tenure, takes the record back, refuses at Report #1
because its own pair holds, and serves again through its restart under the
same attachment key, B's stale preempt lands over A's tenure, B's Report #2
refuses admission, A's status completion withdraws A and A's Report holds,
with `v1` unretired. `takeoverReport1` performs Report #1 and the tenure check
in one step and `takeoverPreempt` rechecks nothing, so the model has no state
between Report #1 and the tenure check, and a pause before that check and one
after it are one model state; the Rust test
`a_pause_before_the_tenure_check_issues_no_stale_preempt` shows the refusal of
a pause before the check. Generation, volume and
records stay retained, and the deposed tenure recovers through its own
restart's lineage arm (`reusedAttachmentKeyRestartReachesFb`).

The fresh path's `freshReport` action combines the host ID, Register, Acquire
and fresh Report after the attempt's acknowledged bump. `freshWrite` records
its first medium write after that FB. `witnessFreshFb` and `witnessFreshWrite`
reach these actions. `NoWriteBeforeFB` requires each medium write to follow its
attempt's FB; `OwnBumpBeforeFB` requires the attempt's acknowledged activation
before an FB is present. The `fresh-writes-before-bump` control breaks
`NoWriteBeforeFB`, and `fresh-report-before-bump` breaks `OwnBumpBeforeFB`.

### Reclaim schedule

The reclaim schedule, `reclaimStep` from `reclaimInit`, carries attaches of the
active volume through their recorded steps (D14) under the tenure model's
takeover machinery. `reclaimInit` starts with `h1` serving past the FB of its
fresh activation at `E = 1`, `h2` named standby and the three attach entries of
`RC0` listed: one live, enrolled attach of each of `h1`, `h2` and `h3`. The
entries stand for volume record format 3 (D15), which at this head only the
gated `Reconciler::record_standby` writes: each entry binds its host's instance (A3) and carries its own
reservation key (D16). The first three keys are the host names, so the
takeover and restart schedules keep their keys, and a later entry takes `k4`
to `k7`. A process records its host's attach key when it starts and judges the
entry under that key, which a later attach of its host leaves ended or gone;
`lineage` records the successor process's key and the key under which the
predecessor won its tenure (`tenureKey`: the successor key of its latest
committed takeover, or its attach key when no takeover made it owner), so
`deposedBy` follows tenures of attaches, and a host that attaches again starts
a chain of its own; `reclaim-lineage-newest-key`, which records the
predecessor's newest attach key, breaks `NoPreemptOfForeignKey` on
`staleCasThenFreshHostRecovers`. The reclaim chains admit ended predecessors
and holders under the format-3 design, which Rust's takeover step 1 and
`LineagePreempt::resolve` follow through `VolumeRecord::recorded_beside`;
`reclaim-takeover-refuses-ended-holder` states the live-only holder rule that
`negative_control_live_only_holders_refuse_an_ended_predecessor` plants in
Rust.

- `recordAttach(h)` writes a live entry for a host other than the owner whose
  every earlier entry is gone and with no listed attachment, at `E > 0`, so a
  host holds at most one retained entry (`AttachAfterGone`;
  `reclaim-reattach-before-gone`, which admits a host whose earlier entry is
  ended, breaks it). At `MAX_ATTACHED = 3`
  live entries or `MAX_EVENTS = 4` retained ones it refuses with no write
  (`attachClosed`). The model's `MAX_EVENTS` is a scaled bound on retained
  entries that leaves gone entries out of the count; Rust's `MAX_EVENTS = 16`
  counts every event the record holds, so slot reuse in Rust needs gone events
  compacted out of that count.
- `attachRequest(i, lands)` lands, and the listing shows the instance, or
  fails; `lateLand(i)` lands a failed request later, live or ended, until a
  detach is requested. That cutoff is a premise: a request that lands after
  its entry's detach is outside the model. `reclaim-late-land-after-detach`
  drops the cutoff, and the instance, listed again after its gone mark,
  retires the volume at the next poll.
- `enroll(i)` records the pair of a live, landed entry, and refuses an ended
  one (`enrollRefused`). `nameStandby(h)` names any host whose newest entry is
  live and enrolled (D16). `rc.grants` records an enrollment of an entry whose
  request had not landed and a designation of a host whose newest entry was
  ended or unenrolled when it was written, so each of those three guard
  clauses has a control.
- `endRead(i)` decides to end a live entry whose host the shard record names
  neither owner nor standby at `E > 0`, and `endWrite(i)` writes the end mark,
  conditioned on the entry the decision read, whatever the shard record names
  by then. `rc.roleEnds` records a decision whose shard read named the host
  owner or standby (`EndedHoldsNoRole`). The end is first in the reclamation
  order (D14). The write can land
  after its host became the standby or the owner. The owner's next poll reads
  its own entry ended and withdraws every attempt of its tenure with no
  retirement (ENDED-GRANTS-NOTHING). That is the format-3 design's verdict,
  which #264's poll gives as `Verdict::Withdraw` when the volume record ends
  the holder's own attach.
  `witnessOwnerEntryEnded` reaches that withdrawal on an end decided before
  its host's designation and written after its takeover's FB. Such an owner
  serves nothing after that poll (`EndedOwnerServesNothing`). Its later
  restart refuses at step 1, since `restartRecords` requires the host's
  newest attach live with its pair recorded, the enrolled own pair of Rust's
  step 2, and its entry stays undropped while it is the owner, until another
  host takes over. `reclaim-restart-reads-ended-own-attach` drops that check,
  and its restart's ready wait breaks `RecordsBeforeDevice`.
- The record-named owner serving past its FB decides a Preempt with no abort
  naming an ended key that does not hold (`endedPreempt(k)`), and the preempt
  lands later (`endedPreemptLands(effect)`), however late: it removes the
  key's registrations, or reports success and changes nothing; the next Report
  is its only receipt (D17). One decided preempt is in flight at a time. That
  owner drops an ended entry's pair once one of its serving Reports showed the
  key absent (`dropPair(i)`). The device takes the ended-key preempt only
  while its issuer's key is registered, and a takeover preempt likewise:
  `preemptAfterOwnKeyRemovedRefuses` resumes a paused successor after the
  owner removed its key, and its preempt refuses with no effect, which
  `-ignores-issuer` drops; `-names-later-key` names `h3`'s key in the
  refused command and breaks `NoPreemptOfForeignKey`. The issuer check of the ended-key preempt's
  landing has no control of its own: with it removed, every root and run
  keeps its outcome, since no schedule here lands an unregistered owner's
  preempt on a registered ended key.
- `detachRequest(i)` names an ended entry with no pair, `detachDone(i)`
  removes its instance from the listing, and `markGone(i)` marks it gone after
  its clean listings, one step for the gone rule's two clean listings. The
  model holds at most seven entries; `recordAttach` takes no eighth.
- A standby registers at its takeover (D18). `takeoverReport1` stands for
  Register, Report #1 and the tenure check in one step: Register relies on the
  takeover's record read, and only Reports read the registrations, judging
  each key by its own entry, so a Report between Register and Report #1 judges
  the registration as it does after them. A successor paused before that step
  registers whenever it resumes, and its reread refuses when the entry under
  its key is no longer live. `takeoverStart` refuses a named standby whose
  newest entry is ended or has no enrolled pair, with no request
  (`reattachedUnenrolledRefuses`; `reclaim-takeover-ignores-enrollment` drops
  the pair), and Report #2 grants no FB to an ended attach.
- The owner's poll reads the listing first (`readListing`) and the record
  after it (`pollEntries`), and gives the first verdict of this order that
  applies. It retires on a listing with an instance outside the owner and
  the instances of retained entries, live or ended. It withdraws with no
  retirement when the record shows the owner's own entry ended or gone
  (`pollWithdrawn`), whether or not the listing holds the owner:
  `witnessOwnerEntryEnded` withdraws on a listing that holds the owner and
  the instances of the two other retained entries. It keeps serving on a
  listing that holds the owner. It ends with no verdict on a listing that
  lacks the owner (`pollUnobserved`), as Rust's missing attachment refuses
  without retiring. The schedule reaches no such verdict: the listing drops
  a host only at the detach of its ended entry, so a poll whose listing
  lacks the owner reads the owner's entry ended or gone and withdraws
  (`missingOwnerPollWithdraws`); a record read that finds
  another tenure, another owner or the same owner at another `E`, ends the
  poll with no verdict (`pollSuperseded`). The last step of
  `pollSupersededAtLaterE` offers both arms of the record read, and only the
  superseded end is enabled; `-judges`, whose record read judges under any
  tenure, takes the verdict arm there.
  `reportPoll` classifies each key: the own pair, a recorded pair of a live or
  an ended attach, which holds with no retirement (RECORDED-HOLDER-HOLD), an
  ended key, which is no observation as a non-holding registrant and holds
  like a recorded pair as the holder, since the record keeps its entry after
  the pair drops, and any other key, which retires. Report #1 of a restart
  reads the holder the same way. A serving Report records each ended entry
  whose key it shows absent.

`reclaimStep` holds the record-named owner's restart with its lineage arm and
no mid-tenure event, status deposition, foreign attach, flip, fresh activation
or free-scheduler `poll`. The runs and mutants reach those actions as recipes:
`endedHolderRestartHolds` checks retention at the successor's restart Report
#1 over an ended holder that keeps its recorded pair, which takes the arm with
the volume retained; `witnessReclaimPollRetires` reaches a poll that retires
the volume on a foreign attach, and the `reclaim-poll-` mutants check the
retiring arm of `AttachOutsideDesiredStateRetires` on that recipe. So the
reclaim roots re-derive `NoEpochReuse` over takeovers and those restarts, and
no reclaim case reaches a retirement after a committed takeover or an admitted
preempt: the retiring arms of `InterruptedTakeoverRetainsVolume` and
`StalePreemptRetainsVolume` are checked under the takeover schedules alone. At 10 turns and `EMAX = 3` the two `serving` reclaim roots reach the
arm's Register at their last turn and the other six roots reach no arm state; the arm's reread, preempt and
Report #2 meet the reclaim actions on the recipes only (`endedHolderRestartReachesFb`,
`armRereadRefusesEndedAttach`, `armPreemptAfterOwnKeyRemovedRefuses`, `armPreemptAfterHolderPairDropped`). The
no-move clause of `EndedPreemptSparesLiveAttach` rests on the issuer checks
above and on no ended key reaching the holder between a preempt's decision and its landing: the arm's
preempt passes the reservation only to the key of a restart whose reread found
its attach live, and an attach that ends between that reread and the
preempt's landing lies outside the searched bounds. The roots, which start at most three takeover
processes and commit at most two takeovers, reach no landing that moves the
reservation. Four takeover processes, one more than the roots start, reach one
(`witnessEndedPreemptMovesHolder`, at `EMAX = 5` and `REQUESTS = 5`, where
each of the four commits its takeover): owner
`h1` decides its preempt of `h2`'s ended key; a process of `h2` that paused
after its Report #1 preempts `h1`'s key, which makes `h2`'s key the holder
and removes `h1`'s registration; a superseded takeover process of `h1`
registers `h1`'s key again; and the decided preempt lands on the holder's
key and moves the reservation to `h1`. The clause is open past the roots'
bound: the device takes a Register and a preempt by key, so closing it needs
a rule the parent specification does not state. `rc.retiredOn`, `rc.grants`, `rc.drops`, `rc.detaches`,
`rc.unshown`, `rc.spared` and `rc.endedPolls` record what the reclaim properties judge.

| Property | Guarantee |
|---|---|
| `EndedAttachNeverRetires` | Every attachment a retiring poll found outside its admitted set, and every holder or registrant a retiring Report found outside its recorded pairs and ended keys, is `UNRECORDED`: no retirement follows from a listed attachment of a retained entry, a registrant with a recorded pair or a registrant under an ended key, holding or not. The active volume is retired exactly when such a check found one: a check that finds one retires in its step, and none retires with nothing found; `reclaim-poll-outside-unobserved`, whose poll ends with no verdict on a foreign attachment, and `reclaim-report-retires-kept`, whose Report retires while its own pair holds, break that clause. No root search retires the volume, since the reclaim scheduler holds no foreign attach: the roots check that nothing in them retires, and the recipes reach the retiring arms. `reclaim-report-ignores-recorded-pair`, whose Report reads a registrant with a recorded pair as foreign, breaks it when a paused successor registers under its live attach; `reclaim-judges-ignore-ended-key` breaks it at the Report that judges `lateRegisterAfterDrop`'s late registrant; `reclaim-remove-while-listed` marks an entry gone while it is listed and breaks it at the next poll. `reclaim-report-retires-dropped-key-holder` and `reclaim-restart-retires-dropped-key-holder`, whose serving Report and restart Report #1 read a holder as recorded by its pair alone, break it on `droppedKeyHolderReportHolds` and `droppedKeyHolderRestartHolds`, where an ended key whose pair the record dropped holds the reservation. |
| `EndedGrantsNothing` | No enrollment, takeover CAS or FB belongs to an attach whose entry was ended at the record read it relied on, judged by the entry under the process's key; no enrollment to an attach whose request had not landed (`reclaim-enroll-before-landed`); no takeover CAS to an attach without its enrolled pair; and no designation names a host whose newest attach was ended (`reclaim-designation-names-ended`) or unenrolled (`reclaim-designation-names-unenrolled`) when it was written. A takeover's Register relies on its CAS's read. `reclaim-enroll-admits-ended` enrolls the ended entry of `failedAttachLandsLate` and breaks it; `reclaim-ended-attach-takes-over` lets a named standby with an ended entry submit its CAS and breaks it on `designationRacesEnd`; `reclaim-reread-judges-newest-attach`, whose Reports judge the host's newest attach, gives `staleCasAfterReattach`'s stale CAS an FB under a gone attach's key; `reclaim-report2-skips-reread`, whose Report #2 does not reread the entry, grants the FB of `endLandsBeforeReport2Refuses`, where the end lands between the takeover's preempt and Report #2. Report #1's reread guards the preempt, which the property does not record: `designationRacesEndAfterCas-skips-reread` drops it, and that run's end, the ended standby refused with no preempt, is unreached. |
| `EndedPreemptSparesLiveAttach` | No ended-key preempt, however late it lands, removes a live entry's registration or moves the reservation. `reclaim-key-reused-across-attaches`, whose new entry of a host reuses its earlier key, breaks it on `pausedOwnerEndedPreemptAfterReattach` with the preempt landing after the reattached host registered and before its takeover preempt. The clause that the reservation stays has one control, `reclaim-ended-preempt-moves-holder`, which replaces two texts: the owner names the holder's key, and the device takes the preempt from an unregistered issuer. Either replacement alone moves nothing in this schedule. The roots reach no landing that moves the reservation; `witnessEndedPreemptMovesHolder` reaches one with four takeover processes, one more than the roots' three, each of which commits its takeover, so that clause is established within the roots' bound alone. |
| `EndedOwnerServesNothing` | No attempt serves a tenure after a poll of that tenure read its own entry ended or gone: `pollEntries`, on a listing with no outside instance, withdraws every active or sent attempt of the owner at the record's generation with no retirement when the record shows the entry under the key of the owner's tenure ended or gone (`pollWithdrawn`). `rc.endedPolls` records each such tenure from the record read alone. `witnessOwnerEntryEnded` reaches the withdrawal, and `reclaim-poll-serves-ended-owner`, whose poll keeps serving on that record, breaks it at the poll. |
| `AttachAfterGone` | No host holds two retained entries. |
| `EndOrder` | Every pair drop is the record-named owner's while it serves past its FB and follows the end mark and a recorded absence, so an end write drops no pair; every recorded absence is of an ended entry whose key a serving owner's Report, on which its own pair held, did not list (`rc.unshown` holds any other); and every detach request names an ended entry whose pair the record no longer holds. `reclaim-drop-without-report`, `reclaim-drop-not-serving`, whose drop follows a takeover CAS that deposed the reporting owner, and `reclaim-end-drops-pair`, whose end write drops the pair, break the first clause; `reclaim-report-absent-lists-key`, whose Report records a listed key absent, and `reclaim-hold-report-records-absence`, whose Report records an absence while another host's pair holds, break the second; `reclaim-detach-before-drop` and `reclaim-detach-before-end`, which detaches a recorded, live entry, break the third. |
| `EndedHoldsNoRole` | Every end was decided on a shard read that named the entry's host neither owner nor standby at `E > 0`; the end write lands whatever the record names by then. `reclaim-end-ignores-owner` and `reclaim-end-ignores-standby` break it at the decision. With either clause removed and this property set aside, every root and run keeps its outcome: the takeover's own reads refuse an ended standby, and an end can land on an owner in any case. |
| `HistoryBound` | At most `MAX_ATTACHED` live and `MAX_EVENTS` retained entries exist; `witnessClosedAtLive` and `witnessClosedAtEvents` reach the refusal at each bound, and `reclaim-attach-past-bound`, which admits an attach at any count, breaks it at the live bound. `reclaim-attach-past-events-bound` drops the retained-entry bound alone and breaks it at five hosts: a host holds at most one retained entry, so with four hosts no schedule holds a fifth. |

The reclaim schedule also re-derives `AttachOutsideDesiredStateRetires`
(`reclaim-poll-ignores-listing`, `reclaim-poll-never-retires` and
`reclaim-poll-retires-kept`, whose poll retires on a listing it keeps serving
on), `DetectedLossWithdraws` at the reclaim poll (`reclaim-poll-keeps-attempt`,
whose retiring poll withdraws no attempt, so the owner's attempt takes a
command after the trigger it observed), `RecordedAttachRetiresNothing` (`attach-before-binding`, whose poll reads the
record before the listing, so an attach recorded and landed between the two
reads is listed outside the admitted set it read), `NoPreemptOfForeignKey`
with the ended form (`reclaim-ended-preempt-live-key`,
`reclaim-ended-preempt-holder-key` and `reclaim-ended-preempt-before-fb`),
`NoEpochReuse` (`reclaim-reattach-resumes-epoch`, whose reattached host's
takeover activates at the `E` before its CAS), `NamedStandbyTakesOver`,
`InterruptedTakeoverRetainsVolume` and `StalePreemptRetainsVolume`. The free
scheduler's caller binding keeps its own order control,
`attach-before-caller-binding`; the name `attach-before-binding` now names the
reclaim poll's read-order control.

Two search premises, each with a control that drops it:

- The gone mark. The model's listing is consistent, so one clean read stands
  for the reconciler's two, and `markGone` also waits for every owner poll
  whose listing read showed the instance to read the record. That stands for
  the gone rule's two clean listings being separated by more than an owner
  poll's read-to-read time, a bound the reconciler's gone rule owns and a
  later replay schedules as an environment constraint.
  `reclaim-gone-ignores-open-poll` drops it, and a poll that read the listing
  before the detach retires after the gone mark.
- The gone key. A Register that lands after the Report that let the pair drop
  leaves a registration under the key of an ended or gone entry; the record
  keeps the gone event, the Reports read that key as ended, and the owner's
  ended-key preempt removes it. `reclaim-gone-key-not-ended` reads a gone key as
  unknown, and a Register after the gone mark retires the volume. A gone event
  that leaves the record while its key is still registered is outside the
  model.

[tenure_check.py](tenure_check.py) declares the reclaim cases with the model's
constants replaced per case: three hosts unless a case states four. Each of
four prefix roots runs `reclaimSafety`, `safety` and the eight reclaim
properties, exhaustively at three and four hosts under `EMAX = 3` and
`REQUESTS = 4`, so a root's search commits at most two takeovers, its
prefix's included, and starts at most three takeover processes: `serving` (the initial state,
10 turns), `takenOver` (after `h2`'s takeover to FB, 10 turns), `ended` (after
that takeover and `h1`'s end, 10 turns) and `paused` (after `h2`'s CAS and
`h3`'s takeover over `h2`'s tenure, 10 turns). The runs, each with a
`-reached` companion that must reach its stated end:

- `fourthAttachTakesOver`: `h2` takes over, `h1`'s entry ends, `h4` attaches
  as the fourth entry, is named and takes over to FB at generation 1 on `v1`,
  preempting `h2`'s key (`witnessFourthAttach`).
- `endedPredecessorFreshHostRecovers`: `h2` stops after its CAS, `h1`'s entry
  ends with its pair holding, and `h3`'s Report #1 admits `h1`'s key and
  reaches FB; `reclaim-takeover-refuses-ended-holder`, whose Report #1 refuses
  an ended holder, stops it at that Report with no preempt, and its
  `-reached` companion confirms the refusal.
- `endedHolderRestartHolds` and `endedHolderRestartReachesFb`: the same ended
  holder, and `h2`'s restart takes the lineage arm at Report #1 with `v1`
  retained, then bumps, registers, preempts `h1`'s ended key and reaches FB.
- `endedHolderReportHolds`: `h1`, deposed by `h2`'s stale preempt, still
  serves; `h2`'s entry ends with its pair recorded and holding, and `h1`'s
  Report holds `v1` under that pair with no retirement and withdraws `h1`'s
  attempt. `reclaim-report-retires-ended-holder`, whose Report admits only a
  live attach's pair as holder, retires there.
- `droppedKeyHolderReportHolds` and `droppedKeyHolderRestartHolds`: `h2`
  registers at Report #1 and pauses, and a second process of `h2` stops
  after a later CAS. Owner `h1` ends `h2`'s entry, removes `h2`'s key and
  drops its pair after the Report that showed the key absent. The second
  process then registers the key again, so the first one's preempt of `h1`'s
  key takes effect and the ended key holds the reservation. `h1`'s serving
  Report holds `v1` with no retirement and withdraws `h1`'s attempt, and
  Report #1 of `h1`'s restart refuses `refusedRecorded`. The runs take five
  and six processes (`EMAX` and `REQUESTS` at 5 and 6), past the roots'
  bound. Report #1 of a takeover admits a recorded pair alone, so no
  takeover preempts that holder: the volume stays held, and its recovery is
  outside the model.
- `foreignAttachPollRetires` and `unrecordedHolderReportRetires`: the poll
  retires `v1` on a foreign attachment, and the Report on an unrecorded
  holder, each finding only that one outside the protocol. These two runs
  retire under `reclaimSafety`, so the retiring arms of
  `EndedAttachNeverRetires`, `AttachOutsideDesiredStateRetires` and
  `RecordedAttachRetiresNothing` are checked where a retirement happens; no
  root and no other run retires.
- `endLandsBeforeReport2Refuses`: `h3`'s end is decided before its
  designation and lands between its takeover's preempt and Report #2, which
  rereads the entry under `h3`'s key and grants no FB; `h3`'s recorded pair
  holds `v1`, which stays unretired.
- `lateRegisterAfterDrop`: `h2`, paused before its Register, is deposed,
  ended and dropped, then registers; the Report keeps serving beside the ended
  key, the ended-key preempt removes it and nothing retires.
- `failedAttachLandsLate`: `h4`'s request fails, its entry ends, and the
  instance lands; the poll keeps serving and the enrollment refuses.
- `pausedOwnerEndedPreemptAfterReattach`: `h3` decides an ended-key preempt of
  `h2`'s first attach, `h2` is reclaimed, attaches again under `k4` and takes
  over, and the preempt lands with `k4` holding and registered.
- `staleCasAfterReattach`: `h2`'s CAS is pending while its entry ends and is
  reclaimed and `h2` attaches again under `k4`; the stale CAS commits, and
  Report #1 rereads the entry under `h2`'s first key and refuses.
- `staleCasThenFreshHostRecovers`: after that stale CAS makes `h2` owner under
  its first key, `h3`, named over that tenure, takes over and preempts `h1`'s
  key, whose tenure the stale CAS's takeover deposed.
- `reattachedUnenrolledRefuses`: `h3`'s end is decided before its designation
  and lands after; `h3` is reclaimed and attaches again under `k4` with no
  enrollment, and its takeover under the surviving designation refuses with
  no request.
- `preemptAfterOwnKeyRemovedRefuses`: `h2` registers at Report #1 and pauses,
  `h3` takes over, ends `h2`'s entry and removes `h2`'s key, and `h2`'s
  resumed preempt refuses with no effect.
- `armRereadRefusesEndedAttach`: `h2`'s end is decided while `h3` is named and
  written after `h2`, named again, committed its takeover with a lost reply
  and its restart's arm registered; the arm's reread finds its own attach
  ended and refuses with no preempt, and `h1` keeps the reservation.
  `reclaim-arm-reread-ignores-ended-attach`, whose reread passes on the tenure
  alone, preempts `h1`'s key after a reread that did not name the tenure with
  the attach live and breaks `NoPreemptOfForeignKey`.
- `armPreemptAfterOwnKeyRemovedRefuses`, at `EMAX = 6` and six requests: `h3`,
  paused after the Report #1 of its takeover over `h2`'s tenure, holds `h2`'s
  key captured; `h1` takes the record back and preempts `h2`'s key; `h2`,
  named again, commits a takeover with a lost reply and its restart's arm
  registers and rereads; `h3`'s paused preempt then removes `h2`'s
  registration, and the arm's preempt refuses with no effect, so `h1` keeps
  the reservation. Its `-ignores-issuer` control drops the issuer check, and
  the preempt takes the reservation. Its `-names-unshown-key` control names
  `h3`'s key in the refused command and breaks `NoPreemptOfForeignKey`, which
  judges the named key of a refused lineage preempt as of a taken one.
- `armPreemptAfterHolderPairDropped`, at `EMAX = 4`: `h2`'s arm reads `h1`
  holding at Report #1 and at its reread and pauses; `h3`, named over `h2`'s
  bumped tenure, takes over to FB and preempts `h1`'s key, `h1`'s entry ends,
  `h3`'s Report shows its key absent and `h3` drops its pair. The arm's preempt
  of `h1`'s key then lands with admitted evidence, since Report #1 fixed the
  pair, and changes nothing while `h3` holds; the arm's Report #2 refuses.
- `missingOwnerPollWithdraws`: `h2` takes the record over by its CAS while
  its own entry is ended and detached; its poll's listing lacks `h2` and
  holds no outside instance, and the record read shows `h2`'s entry ended, so
  the poll withdraws and retires nothing.
- `pollSupersededAtLaterE`: a poll whose owner took the record back at a
  higher `E` ends with no verdict and retires nothing.
- `designationRacesEnd` and `designationRacesEndAfterCas`: the end of `h3`'s
  entry is decided before `h3` is named and written after; `h3` refuses with no
  request when the end precedes its CAS, and refuses at its reread with no
  preempt when it follows, and `h2` recovers the volume with nothing retired.
- `endedPreemptNoEffectKeepsPair`: the ended-key preempt reports success and
  changes nothing; the next Report lists the key, the pair stays and no detach
  is requested.
- `standbyReplacedThreeTimes`: the standby is replaced three times through the
  whole lifecycle with at most three live entries, `h2` returns under `k5`, and
  that attach takes over to FB.
- `ownerLostTwiceThenStandbyLost` and `takeoverChainDepthFive`: chains of
  successors that stop after their CAS over ended predecessors, each new
  successor a newly attached host, end with a takeover whose preempt names
  `h1`'s key four and five takeovers back, with at most three live entries and
  the generation unchanged. They run at five and six hosts, six and seven
  attempts and requests, and every entry retained. The `-one-level`,
  `-one-round` and `-three-rounds` controls of the depth-five chain, and the
  `-two-rounds` control of the depth-four chain, cut `deposedBy` below the
  chain's depth and break `NoPreemptOfForeignKey`, so each chain needs its full
  depth. The reached depth is five, below the bound of seven earlier tenures
  with recorded pairs: each stopped successor keeps its recorded pair, since no
  owner serves past its FB to drop it, so a deeper chain needs more retained
  entries than these cases hold. Depths six and seven are an open condition
  for a proof stream.

`witnessFourthEntry` is reached from the `takenOver` root, and
`reclaim-no-end`, the bound control, passes the same 10-turn search, whose
depth the case pins, with no fourth entry recorded, the baseline's limit;
`witnessFourthAttach` is reached from the `ended` root. `reusedAttachmentKey` and its two hold controls keep
their outcomes, and `reusedAttachmentKeyRestartReachesFb` is the witness that
its deposed tenure reaches its FB again by its own restart, through the
lineage arm.

### Handoff schedule

`handoffStep` runs from `reclaimInit`, whose owner `h1` serves past its FB at
`E = 1` with `h2` named standby, and carries a planned transfer (amendment A2,
D19 to D21). `planDrain` stops the serving owner's admission; `command` admits an active
attempt alone, so the schedules hold no command action of a draining attempt,
and the drain's publish and certify are actions of the suffix model, whose
handoff cut blotter pull request 2019 adds. Before its
withdrawal the owner may resume in place (`planResume`) with no `E` consumed.
An attempt whose tenure a takeover deposed during the drain resumes as an
active attempt of the deposed tenure, the state of a deposed attempt that
never drained, and commands under its own tenure until it observes the loss,
which withdraws it (`DetectedLossWithdraws`). The Rust machine resumes the
same way on a passed deadline and on a record that names another tenure
(`Resume::Store`).
It then withdraws for the planned change and either exits for the same-host
restart (`planRestart`, the deploy restart and the roll) or, in the same step,
issues the transfer write (`transferStart`): the model's field-conditioned form
of the exact-version write, conditioned on its own `(g, active, owner, E)` and
the standby the record names, which names that standby owner at `E + 1` and no
standby and mints no session. The model has no record versions, so a
designation changed away and back before the commit is a Rust test boundary.
The transfer issues only with two attempts left at or below `EMAX`, the bound
of the search: it consumes one and reserves the other for the target's own
bump, so a committed transfer leaves its target an attempt to activate with
(`TransferLeavesBump`). At `E = EMAX - 1` the drained owner has no transfer
and withdraws for its same-host restart (`handoffLastAttemptRestarts`). The
request
reuses the attempt's id, so the transfer issues only once the store holds no
other request under that id, and the decision its reply reads is the
transfer's. A serving attempt's earlier request is decided before it serves,
and a takeover issues no bump beside its CAS (`TakeoverIssuesNoBump`), so that
guard passes in every state the schedules reach; `transfer-over-pending-request`
lets a takeover bump from `reported` and drops the guard. Its reply ends the owner (`transferReply`:
`transferred` or `transferRefused`) or is lost (`transferTimeout`:
`transferUnknown`), whether or not the store decided it; those phases are the
withdrawn attempt's exit, which never resumes. Its host's record read is the
owner guard of `restartRecords`: the host restarts only while the record still
names it owner, so a refused or unknown outcome ends in an exit or one
same-host restart. The target activates only through its own restart's
lineage arm. The transfer's condition reads the shard record alone, so a
transfer commits to a target whose attach ended after the designation
(`handoffTargetAttachEndsBeforeCommit`): the reconciler decided the end while
another host was the named standby, and the end write landed between the
transfer's issue and its commit. The record then names the target owner at
the transfer's tenure, the target's restart, whose record read requires its
own attach live and enrolled, starts no process, the outgoing owner's pair
keeps the reservation and nothing retires; the shard serves again when the
enrollment function names another live, enrolled host and that host takes
over (`handoffEndedTargetFreshHostRecovers`). `transferStart` reads the shard
record alone, and the run places the end after the issue. The outgoing
owner's volume read before the write is outside the model: an owner that
reads the target's attach and then sends a separate transfer request leaves
that order open, and the Rust test of the same history (#279) carries it. A committed transfer joins `lineage` as an owner-change write, so
a takeover over the target's transfer tenure preempts the outgoing owner's key
through `deposedBy`; the chain's head is the successor's own committed
request, so the transfer's row admits no preempt by its target, which
preempts through the bumped form after its own bump
(`handoffTransferAdmitsNoTargetPreempt`) or, when its own earlier committed
takeover succeeded a tenure of the outgoing key, through that takeover's
admission: such a target's paused takeover preempt lands after the transfer
and takes the reservation before any bump of the target at the transfer's
tenure (`handoffStalePreemptByTarget`), and that process reaches no FB, since
its Report #2 requires the tenure its own CAS wrote. The transfer write keeps the record's
checkpoint, cut and suffix chain, which the suffix model's recovery reads
unchanged; no Quint case checks that premise, which the transfer writer's Rust
tests (#279) carry. The schedule also holds standby designations and
takeovers, which race the transfer, the record-named owner's restart, command
actions and the serving owner's Report.

| Property | Guarantee |
|---|---|
| `TransferNamesStandby` | Every committed transfer names a host, the standby the record named at its commit, owner, raises the record's `E` by one from its value at the commit and leaves no standby, and every activation of an attempt that issued a transfer is the one its own bump made before it. `transfer-keeps-e`, `transfer-keeps-owner`, whose write raises `E` and clears the standby while the record keeps the outgoing owner, `transfer-ignores-standby`, whose condition omits the standby, `transfer-ignores-e`, whose condition omits `E` so a stale transfer commits over the owner's restart bump, `transfer-to-no-standby`, which issues with no standby named, `transfer-names-new-standby`, which names `h3` standby in the same write, and `transfer-mints-session`, whose acknowledged reply activates the outgoing attempt at the next `E`, break it. |
| `TransferByOwnTenure` | Every committed transfer was issued by an attempt that serves the tenure it transfers: the attempt reached its FB, its host is the owner the record named at the commit, and its generation and `E` are the record's at the commit. `transfer-by-deposed-owner`, whose draining attempt, deposed by `h2`'s takeover, issues the transfer on the record it reads then, breaks it at `EMAX = 4`. |
| `TransferLeavesBump` | Every committed transfer leaves the record's `E` below `EMAX`, so the target's own bump has an attempt. `transfer-spends-last-attempt`, whose transfer issues at `E = EMAX - 1`, breaks it. |
| `TransferAckMatchesCommit` | An attempt whose transfer was acknowledged as committed (`transferred`) has a committed transfer, and one acknowledged as refused (`transferRefused`) has none. `transfer-reply-before-decision`, whose reply reads the attempt's bump decision while the store holds the transfer undecided, breaks it, and so does `transfer-over-pending-request` at `EMAX = 4`, which lets a takeover process bump beside its CAS and whose transfer issues while the store holds that bump, so that request's refusal replaces the transfer's commit as the decision the reply reads. |
| `NoEmissionAfterTransfer` | No attempt takes a command action under the tenure it transferred: from its issue turn the transferring attempt takes none, and every later attempt of its host that takes a command action holds an activation of its own, a same-host restart's bump or a takeover's CAS. An earlier attempt of the host, deposed before the transfer, commands under its own tenure, which `DetectedLossWithdraws` judges (`handoffOlderAttemptCommandsAfterTransfer`). `emit-after-transfer`, a command while the transfer is in flight, and `unknown-transfer-resumes`, a resume after a lost reply, break it; the check covers command actions, and the model's device steps take their process from restart and takeover phases a withdrawn attempt never enters. |
| `TransferRetainsVolume` | No transfer flips the shard or changes its generation or volume, the volume stays unretired unless `UNRECORDED` holds, and the reservation stays held: while the record names the transfer's tenure the outgoing attempt's pair holds, and while it names a later tenure of the target with no owner-change write committed after the transfer, the tenures the target's own bumps name, the outgoing pair or the target's holds, except where a preempt of the outgoing key moved it to the preempting host, as a paused takeover's stale preempt does at the transfer's tenure (`handoffStalePreemptAfterTransfer`) and at the target's bumped tenure (`handoffStalePreemptAfterTargetBump`), both at `EMAX = 6`. At the transfer's tenure that host is another host than the target, or the target when its own earlier committed takeover succeeded a tenure of the outgoing key (`handoffStalePreemptByTarget`, `EMAX = 6`); a target with no such takeover holds only after its own bump, and `handoff-target-preempts-on-read`, whose target registers and preempts on its role read and Report #1, breaks that. `transfer-flips`, `release-by-predecessor`, a release at the withdrawal that leaves no holder, `handoff-target-preempt-releases`, whose target's lineage preempt leaves no holder at its bumped tenure, and `handoff-target-retires-recorded-holder`, whose target's Report #1 turns the outgoing owner's recorded pair into the retirement request, break it. The handoff schedule holds no status deposition and no restart retirement, so its searches reach no retired volume and no state with nobody holding after a transfer; those two clauses are exercised by these controls. |

The cases check `safety`, which holds these six, from five prefix roots:
`serving` (no prefix, 9 turns), `draining` (the drain, 9 turns), `issued`
(the drain and the transfer's issue, 11 turns), `transferred` (the transfer
committed and acknowledged, 12 turns) and `targetBumped` (the target's
acknowledged arm bump, 11 turns), the last two at `EMAX = 4`, so the search
interleaves the takeover, the designation and both hosts' restarts with every
step of the handoff, a takeover can commit over the target's transfer tenure
and over its bumped tenure, and a lost reply or a failed device step
interrupts each. Each root's search must reach its last turn.
`handoff-reach-witnessHandoffFb` reaches the target's FB within the `issued`
root's search, and `handoff-reach-witnessTakeoverOverTargetBump` a takeover
committed over the target's bumped tenure within the `targetBumped` root's.
Six more reach cases show what the searches hold: the `issued` root reaches the
outgoing owner's restart FB after a lost reply
(`witnessTransferUnknownThenRestart`) and after a refusal
(`witnessTransferRefusedThenRestart`) and a command action of that restart
(`witnessLaterAttemptCommands`); the `transferred` root reaches a command
action of the target under its bumped tenure (`witnessTargetCommands`) and a
refused reread of the target's arm (`witnessArmRereadRefused`); and the
`targetBumped` root reaches a Report #2 that refuses after the target's
admitted preempt (`witnessArmReport2Refused`). Each action of `handoffStep`
fires in at least one root's search except the Report's hold and its
retirement, which no handoff root reaches. The roots reach no command action
of an attempt older than the transferring one, no reservation moved by a
stale preempt, since a takeover followed by a transfer needs more attempts
than a root's `EMAX` leaves; the runs `handoffOlderAttemptCommandsAfterTransfer`,
`handoffStalePreemptAfterTransfer`, `handoffStalePreemptByTarget` and
`handoffStalePreemptAfterTargetBump` reach those. The committed transfer with a lost reply followed by the
target's FB lies one turn past the `issued` root's search and is the run
`handoffUnknownCommittedExits`.
A failed Report #1 from `ready`, which changes no shared state, stands for a
target stopped after a successful Report #1 and before its bump, and
`planRestart` stands for a crash between the withdrawal and the transfer's
dispatch. The runs, each
checked with `safety` and its end state beside a `-reached` case, name the
traces a later Rust replay takes, with the scenario of the Rust unit that
writes each step:

| Run | Outcome | Rust scenario |
|---|---|---|
| `handoffTargetReachesFb` | The owner drains, withdraws and transfers; the acknowledged commit ends it; `h2`'s restart takes the arm over `h1`'s pair to FB on `v1` at its generation, the transfer and `h2`'s bump each consuming one `E` (`witnessHandoffFb`). | U45 handoff cycle; U40 transferred record |
| `handoffUnknownCommittedExits` | The transfer commits with its reply lost, the outgoing attempt's exit; `restartRecords`' owner guard, `h1`'s record read, finds `h2` named, so `h1` starts no restart, and `h2` reaches FB (`witnessTransferUnknownCommitted`). | U45 unknown outcome, committed arm |
| `handoffUnknownUncommittedRestarts` | The reply is lost with the transfer undecided; `h1`'s restart bumps first, the transfer fails its condition on `E`, and `h1` reaches FB with the record still naming `h2` standby (`witnessTransferUnknownThenRestart`). | U45 unknown outcome, uncommitted arm |
| `handoffRefusedRestarts` | The designation moves to `h3` before the commit; the transfer is refused and `h1`'s restart reaches FB (`witnessTransferRefusedThenRestart`). | U45 refused outcome |
| `handoffRacesTakeoverTransferWins` | The transfer wins the race with `h2`'s takeover CAS, which refuses with no device command; `h2` activates through its restart. | U45 concurrent takeover and transfer |
| `handoffRacesTakeoverTakeoverWins` | `h2`'s takeover wins; the transfer is refused, `h1` exits, and the takeover reaches FB. | U45 concurrent takeover and transfer |
| `handoffTargetBumpUnknownRerun` | The target's arm bump commits with its reply lost; the rerun reaches FB at the next `E` under its own session. | U40 bump unknown |
| `handoffTargetRegisterFailRerun` | The target's Register fails, a hold with no flip; the rerun reaches FB. | U40 failed step of the arm |
| `handoffTargetLostFreshHostRecovers` | `h2` is lost after the committed transfer; `h3`, named over `h2`'s transfer tenure, takes over, preempts `h1`'s key and reaches FB on `v1`. | U45 target lost before its device steps |
| `handoffTargetAttachEndsBeforeCommit` | The reconciler decides the end of `h2`'s entry while `h3` is the named standby, the designation returns to `h2`, and the end write lands between the transfer's issue and its commit: the committed transfer names `h2` owner at `E = 2` with `h2`'s entry ended. Of the two steps the last step offers, `h2`'s restart and the designation of `h3`, the designation alone is enabled: `h2` starts no process, so it issues no device command and reaches no FB, `h1`'s pair keeps the reservation and the volume stays unretired. | #279's hardening step: the transfer write after the target's attach ended |
| `handoffEndedTargetFreshHostRecovers` | After that transfer `h3`, named over `h2`'s transfer tenure, takes over, preempts `h1`'s key through the transfer's lineage row and reaches FB on `v1` at `E = 3`, with no process of `h2`. | U45 target lost before its device steps |
| `handoffPlannedRestart` | The deploy restart: the drained owner withdraws with no transfer and its restart reaches FB at `E = 2`, owner and standby unchanged. | U45 requested restart |
| `handoffResumeBeforeWithdraw` | A planned exit resumes before the withdrawal and the same tenure commands again. | U42 pre-withdrawal resume |
| `handoffTransferAdmitsNoTargetPreempt` | The committed transfer admits no preempt of `h1`'s key by `h2` before `h2`'s own bump. | U40 transferred record |
| `handoffOlderAttemptCommandsAfterTransfer` | `h1`'s first attempt, deposed by `h2`'s takeover and still active, commands after `h1`'s later attempt's transfer of the record back to `h2` committed. | U42 stale attempt |
| `handoffStalePreemptAfterTransfer` | A paused takeover's stale preempt of `h1`'s key takes the reservation after `h1` transferred the record to `h3`. | U45 concurrent takeover and transfer |
| `handoffStalePreemptAfterTargetBump` | The same stale preempt lands after `h3`'s own acknowledged bump and takes the reservation while the record names `h3`'s bumped tenure. | U45 concurrent takeover and transfer; U40 bumped target |
| `handoffLastAttemptRestarts` | At `E = EMAX - 1` the drained owner has no transfer: of the two withdrawals the last step offers, the planned restart alone is enabled, and the record keeps its owner and standby. | U42 planned machine at the attempt bound |
| `handoffStalePreemptByTarget` | `h1` transfers the record to `h2`, whose paused takeover then lands its stale preempt of `h1`'s key: `h2`'s key holds while the record names `h2`'s transfer tenure, with no bump of `h2` at that tenure. | U45 concurrent takeover and transfer; U40 transferred record |

Each mutant is a recipe over the handoff that must break its property at its
last step: `transfer-keeps-e`, `transfer-keeps-owner`, `transfer-ignores-standby`,
`transfer-mints-session`, `emit-after-transfer`, `unknown-transfer-resumes`,
`release-by-predecessor`, `handoff-target-preempt-releases`,
`handoff-target-preempts-on-read`,
`transfer-by-deposed-owner`, `transfer-spends-last-attempt`,
`transfer-reply-before-decision`, `transfer-over-pending-request` and `transfer-flips` as the table states;
`transfer-leaves-no-lineage`, whose committed transfer joins no lineage, so
`h3`'s takeover over the target's transfer tenure preempts `h1`'s key with no
tenure of that key succeeded, which breaks `NoPreemptOfForeignKey`; and
`handoff-target-serves-on-read`, the serving-too-early control: the target
registers, preempts and takes Report #2 on its role read and Report #1 with no
bump of its own, its reread and Report #2 admitting the transfer's tenure, and
reaches FB, which breaks `OwnBumpBeforeFB`.
`run-handoffTargetAttachEndsBeforeCommit-skips-own-attach` is that run's
control: with `restartRecords` admitting a host whose own attach ended, the
replacement of `reclaim-restart-reads-ended-own-attach`, the run's last step
also starts `h2`'s restart, and the run's end state, which holds no process
of `h2`, fails there. The outgoing owner's resumption after a lost
reply is `unknown-transfer-resumes`; a wrong recovery cut is
`transfer-before-certify`, a control of the suffix model's handoff cut, which
blotter pull request 2019 adds.

A pass shows these properties over one shard, three hosts and the roots'
bounds and nothing beyond them, and nothing about Rust, since no tenure trace
is replayed (#136). No tenure invariant requires the drain before the
withdrawal: a planned restart or a transfer issued from the serving phase
with no `planDrain`, and a command action of a draining attempt, each pass
every handoff root they can fire in, so the order of the drain and the
withdrawal rests on the Rust tests of U42 and U43, among them the planned
machine's `control_transfer_before_certify_fails_the_cut_rule` for
`HandoffCutIsExact` (obligation
`planned-exit-machine-orders-the-drain-and-resumes-only-before-the-withdrawal`),
and on the suffix model's
`TransferAtCertifiedHead`, which blotter pull request 2019 adds. The drain's admission stages, the request's binding and
the store lane are the Rust units U41 to U45, which land after this model. The
model's restart takes the lineage arm at `Check::RecordedHolder`, which the
Rust restart refuses until #279 (U40) adds the arm. `tenure_check.py` writes each search's and run's
instance with only what its case reaches, as the arm root's paragraph above
states, so the handoff schedule's actions reach the instances of the handoff
cases alone.

## Prefix model

[prefix.qnt](prefix.qnt) models one tenure's checkpoint slots against the
store record that names one of them. A capture places its units in the lowest
slot outside the tenure's possibly-named set and its quarantine and submits a
Publish, an exact-version compare-and-swap on the version the host knows;
submitting the Publish adds its slot to the set. A capture is refused before
any unit is submitted when every slot is possibly named or quarantined or its
entries exceed `NMAX`. The store applies a Publish later, once, or never, and
the host learns success, failure or nothing. The host may read the record,
adopting its version and named slot, and submit a Confirm, an exact-version
compare-and-swap of the value it read that keeps the named slot. The set
shrinks to a committed write's slot on that write's acknowledged success when
its version is at least the newest the host knows and every other own write
that has not succeeded was submitted before it, and every slot the shrink
drops that a capture wrote enters the quarantine, which no later capture of
the tenure places into; the slot named at the start, which no capture of the
tenure wrote, goes free. The preservation model quarantines every slot a
shrink drops; this model adds that exception for the start's slot, which rests
on the END premise that the tenure's fence ended every earlier attempt. With no
in-tenure barrier, a tenure of `SLOTS` slots publishes at most `SLOTS` captures.
A stale unit attempt of an earlier capture may land on its slot
whenever a later capture wrote that slot, and recovery reads the named slot
and starts warm only when the slot holds the named capture's units.

The scheduler's `step` takes captures, applications, replies, reads, Confirms
and stale unit attempts; the recovery read runs only in the directed recipes
that name it. One `capture` step runs from placement to
the Publish's submission, so the
properties carry to an implementation that processes no other placement and
no success between a capture's placement and its Publish's submission. The
model has no state between those two events, so it checks no schedule that
interleaves a success or a second placement there. The Rust reservation, which
holds a capture's slot from placement to its Publish, is checked by the tests
of `storage::checkpoint`.

| Property | Guarantee |
|---|---|
| `NamedSlotHoldsItsCapture` | The slot the store names holds the units of the capture its Publish published. |
| `EntriesBounded` | No capture of more than `NMAX` entries submits a unit. |
| `RefusalSubmitsNothing` | A refused capture submits no unit: the set of submitted units and the count of submissions are unchanged. |
| `NamedIsPossible` | The store names a slot in the tenure's possibly-named set. |
| `NoStaleLoad` | A warm recovery loads the named capture's own units. |

[prefix_check.py](prefix_check.py) declares the cases: the first four
properties and their conjunction at `BOUND = 8` steps, with `SLOTS = 3`,
`NMAX = 2` and at most `CAPTURES = 4` captures; four reachability witnesses,
each checked as the inverted invariant `not(witness)`; runs, each a recipe
checked with `BOUND` set to its length: `slotsExhausted` (two captures fill
the slots outside the named one, and a third is refused with two units
submitted), `entriesAboveCap` (a capture within the cap, then one above it
refused with one unit submitted), `cxA2` (a Publish whose reply was lost is
still in flight when a Confirm after a read commits and succeeds; the set
shrinks to the named slot and the delayed Publish fails on the record
version), `cxA2f` (the same, with a capture after the Confirm's success that
takes the third slot, since the shrink quarantined the delayed Publish's
slot; the model's unresolved reply stands for a timeout and a failure reply
alike), `cxA2field` (the `cxA2f` recipe with a field-scoped store condition,
which must violate `safety`), `confirmExact` and `confirmField` (a Confirm
delayed while a Publish into slot 0, which the first shrink freed, commits
and succeeds, and the shrink quarantines the Confirm's slot so the next
capture takes the third slot; the exact-version Confirm fails, and under a
field-scoped condition it commits and `safety` must fail), `ceWarm` (a
published capture with no stale attempt recovers warm) and `ceE4` (three
captures publish and succeed, the first shrink frees slot 0 and the next two
quarantine slots 1 and 0, a fourth capture is refused, and recovery starts
warm), the last two checked with `NoStaleLoad` as well; and eleven mutations
that must each break one property: a shrink that frees the slots it drops
reuses slot 1 on a schedule of three published captures, and the first
capture's attempt landing there breaks `NamedSlotHoldsItsCapture`, and with a
recovery that starts warm whatever the slot holds the same schedule breaks
`NoStaleLoad`, placement that ignores the set and placement
against the named slot alone each break `NamedSlotHoldsItsCapture`, an
unchecked entry count breaks `EntriesBounded`, a slot refusal that writes a
unit, an entries refusal that writes a unit and a slot refusal that resubmits
a unit already written each break `RefusalSubmitsNothing`, and an unresolved
Publish that frees its slot, a shrink while a later own write is unresolved
and a shrink on a late success of an older write each break
`NamedIsPossible`. These are finite checks at the stated bounds.

The model's shrink compares a success's version with the newest version the
host knows, read or acknowledged; `PossiblyNamed` compares it with the version
of the last settling success. They agree for the client, whose calls return
their outcome before the next request, so each success lands above every
version the host read before it. The model sends every write it submits:
`PossiblyNamed`'s removal of a write the client refused before sending and
its supersession of an unsucceeded write by a later retry of the same slot are
checked by the Rust tests of `storage::checkpoint`, outside the model.

## Coverage model

[coverage.qnt](coverage.qnt) models one shard's two coverage pages and the
tenures that fence them, acknowledge INVALIDATEs through them and admit FILLs
against their in-memory coverage. Every page write is an exact-version
compare-and-swap that the store applies later, once, or never, and may reject
as oversized; the host learns success, failure or nothing. A tenure fences
every page before it admits a FILL or acknowledges an INVALIDATE, and adopts a
page's blocked set only on the acknowledged success of its own write that set
or confirmed its fence. A coverage write enters the tenure's coverage before it
is submitted; after a failed condition or a timeout the tenure may re-read the
page as its next basis, and after a size rejection it re-reads and writes the
page saturated.

The instance has three keys of one version each, so an entry is a point
version; a page holds at most `CPAGE = 1` entry, and a second entry saturates
it. Each tenure keeps at most one request per page awaiting its reply, and the
model issues at most `REQUESTS = 6` requests in a run; the fenced-first start
uses two of them, and raising `BOUND` leaves the budget unchanged. The
model always submits the coverage write, including on a saturated page or one
that already blocks the entry, as the implementation does; per-key interval
hulls lie outside the model and are covered by the implementation's tests.

| Property | Guarantee |
|---|---|
| `NoAckBeforeAuthoritative` | An acknowledged INVALIDATE rests on the tenure's own coverage write, learned from its reply, that committed with the tenure's fence after it fenced every page, and whose page value blocks the entry; every coverage write in flight belongs to a tenure that fenced every page. |
| `CoverageNeverDecreases` | No page's fence or blocked set shrinks across its committed writes, and no tenure's covered set shrinks in a step. |
| `FencedCoverageComplete` | A tenure that fenced every page covers every INVALIDATE an earlier tenure acknowledged. |
| `NoCoveredResidency` | No resident FILL is an entry that its tenure or an earlier one acknowledged. |
| `FenceOrder` | Every adoption rests on a committed fence or confirm of the tenure's own on that page. |
| `NoAdoptionFromUnknown` | Every adoption rests on a write whose success the host learned from its reply. |

[coverage_check.py](coverage_check.py) declares the cases at `BOUND = 9` steps
with two tenures. Runs start with every page unfenced; the other cases start
with tenure 1's pages fenced, and `coverage-safety-unfenced` repeats the
safety check unfenced, as the `fence-unconditional` and
`invalidate-before-fenced` mutations do. The cases are each property and their conjunction,
eight reachability witnesses checked as the inverted invariant
`not(witness)`, fifteen directed runs checked with `BOUND` set to the recipe's
length (`successorRefusesAckedFill`, `successorRefusesAckedFillsOnBothPages`,
`coverLosesToSuccessorFence`, `confirmAfterFenceTimeout`, `newerFenceWithdraws`,
`saturationCoveredInFlight`, `ackBeforeSuccessorFence`,
`successorFenceBeforeCover`, `rereadAfterCondition`, `saturateAfterReject`,
`carryAfterConfirm`, `fenceLosesRace`, `successorRefusesFillOfAckedResident`, `successorAdmitsUncoveredKey` and `fencedBeforeFirstFill`), and twelve
mutations that must each break one property; the module docstring states each
run. These are finite checks at the stated bounds.

## Capture model

[capture.qnt](capture.qnt) models one checkpoint capture over three RAM slots
and four payload units, each entry owning one unit. `bind` claims a free unit
for an unpublished entry, `publish` gives it the next insertion step, and
`start` cuts the snapshot at `t0`, the current step. `scan` visits slots in
order and emits members inserted by `t0`; `remove` saves an unvisited snapshot
member into the side list, or abandons the capture when the list would exceed
`CAP = 2`, and moves the entry to retiring; a separate `release` returns its
unit. `complete` joins the emitted entries and the side list into the
checkpoint, `crash` drops every RAM entry, and `load` admits a valid
checkpoint by reserving its units or raises the alarm. Each trace holds one
capture.

| Property | Guarantee |
|---|---|
| `CaptureConsistent` | Emitted and saved entries are disjoint, and a completed checkpoint equals the snapshot. |
| `UnitsExclusive` | Live, bound and retiring entries, the emitted and saved entries, and the checkpoint each name distinct slots, keys and units. |
| `LedgerConserved` | Free and owned counters sum to the unit count, match the free set and the units entries hold, and owned and free units partition the units. |
| `LoadGuardNeverFires` | Loading a completed checkpoint raises no alarm. |
| `SideBounded` | The side list holds at most `CAP` entries. |
| `LoadRetains` | In the state a load produces, the bound entries it installed are exactly the completed checkpoint; a load that installs any other set, an empty one or one with another incarnation included, fails even when it raises no alarm. `loadTurn` marks that state, since later binds, publishes and removals change `bound`. |

[capture_check.py](capture_check.py) checks `safety` with the free scheduler
at `BOUND = 10`, where it reaches a nonempty load and an abandonment, each
checked as the inverted invariant `not(witness)`. Three directed runs
(`cxT1`, `capture-bind-start-publish-scan` and `capture-overflow`) are
checked with `BOUND` set to the recipe's length, each with its reachability
witness. `cxT1` is the unit-reuse trace: a member published before the
start is removed and released before the scan reaches it, a later fill
reuses its unit, the pass completes, and after a crash the checkpoint
loads. Eight mutations each break one property: dropping the removal save,
dropping the scan's `t0` filter (judged by `UnitsExclusive` and by
`LoadGuardNeverFires`), dropping the release's unit return, saving members
the cursor already passed, releasing a live entry before the hook, and, on
`cxT1`'s recipe, a load that admits nothing and raises no alarm and a load
that installs each entry under another incarnation (both judged by
`LoadRetains`). These are finite checks at the stated bounds.

## Preservation model

[preserve.qnt](preserve.qnt) models one shard's volume across host losses
under barrier-gated reuse (BGR), the preservation mechanism this model
qualifies. The P, R, KTD and U labels in this section are the property,
requirement, implementation-decision and unit numbers of the warm host
takeover specification, issue #120; this model is its U0, and its U1, the
store contract and restore gate, is issue #123. The instance has two keys, three payload
units (`PU = 3`), three checkpoint slots of one row unit per key
(`SLOTS = 3`, the minimum slot count) and a journal ring of two blocks
(`J = 2`). It reuses the other models as premises: a capture is one step that
snapshots the live entries (`CaptureConsistent`, capture model), a Publish
names a slot in the possibly named set (`NamedIsPossible`, prefix model), an
acknowledged invalidation is off-volume evidence the successor reads
(`FencedCoverageComplete`, coverage model), and a takeover is an acknowledged
compare-and-swap that issues a new tenure: exact-version in the implementation
and in this model's own takeover action, field-conditioned in the tenure
model, which supplies `NoEpochReuse`.

### Fault model and the premises

Every device write by any tenure, a payload unit, a checkpoint row or a
journal tombstone, leaves a pending attempt. An attempt may land again at any
later step, any number of times: after the guest consumed its completion,
after host loss, and across a chain of successors A, B and C. Completions,
timeouts, Reports, elapsed steps, grace periods and slot counts end no
attempt. A deposed predecessor that is still alive keeps issuing fills,
evictions, tombstones, captures, Publish acknowledgments and barriers under
its own tenure from the successor's takeover CAS until the successor's fence.
A successor writes nothing before its fence, and a successor may crash
between its fence and its recovery (`lose` from `fenced`). `lose` changes only
the phase, so a command the predecessor issues between host loss and the
takeover CAS is modeled as a command issued before `lose`. The store rolls
back only after host loss, and only to the record as it stood before the
first takeover; commands between a store rollback and its reopen fall under
the RESTORE premise. A restore while a successor that took over is still
alive, or during service, is outside the model; a restore after a successor
crashed following its fence is inside it, and a successor that crashed before
its fence is the next takeover, which opens no rollback.

The model states these premises and establishes none of them. Every record
rests on NEW-EXCLUSION, DURABLE and EXPIRY-CLOCK; every record whose cases run
with `END = true` also rests on END, the rollback cases and the free
scheduler's rollbacks rest on RESTORE, and the fence rests on a durable
lineage registrant set, which C reads from tenure arithmetic:

- END-self: a successful Preempt-and-Abort of the issuer's own registration,
  followed by a Report showing the issuer as the sole registrant, ends every
  attempt of every command that registration submitted before it,
  guest-invisible attempts included. The in-tenure barrier uses it.
- END-foreign: a successful Preempt-and-Abort naming the registrations of
  other keys of the lineage, followed by such a Report, ends every attempt
  those registrations submitted before it. The successor's fence uses it.
- NEW-EXCLUSION: after the fence, the reservation type admits no new command
  from a preempted registration.
- DURABLE: a completed payload, row or tombstone write, and a landed attempt,
  is on the volume, and host loss reverts none of them. `fill` and `capture`
  write the media at issue, `tombDone` writes it at completion, and `lose`
  changes only the phase. A backend whose completion precedes durability
  needs a flush before any release and before a Publish is submitted, so the
  payloads and rows a Publish names are durable before the store can name
  them.
- EXPIRY-CLOCK: an expiry excludes an entry at recovery only when the
  successor's clock bound at recovery reaches every deadline the predecessor
  recorded as expired. The model reads one `expired` set that every tenure
  shares.
- RESTORE: a store rollback is detected, no write continues through the old
  store instance, and the reopen restores a tenure floor at the highest
  issued tenure, the latest record and complete coverage.

`END` in the model is END-self and END-foreign together. Six controls set
`END = false`. `barrier-no-end` breaks `Retained` in six steps: a fill, an
invalidation, a barrier, a fill that reuses the unit, a capture, and the
first fill's attempt landing on the reused unit. `premise-no-end` breaks `Retained` on the
`takeoverBeforePreempt` recipe. `both-copies-no-end` lands the first two
captures' row attempts on slots 0 and 1 after the barrier frees them for
reuse. `journal-no-end` lands a stale tombstone over a reused journal block,
and recovery reloads the evicted entry (`NoResurrection`).
`barrier-exposes-free` and `barrier-breaks-agreement` leave an attempt on a
freed unit. Without `END`, a live older attempt can revert a reused payload
unit, row unit or journal block, so no design over a finite set of reused
units retains S. Avoiding that requires a footprint with no reuse, which is
unbounded, or an independent copy that no earlier attempt can reach.

### Definitions

- The cut is the slot the store names, read with every journal record whose
  LSN is at or above the cut's LSN. The possibly named set is the prefix
  model's set of slots the store may name.
- The frontier is the set of tombstones on the media: a completed tombstone,
  and a pending tombstone whose attempt landed.
- S is `eligibleIn(named)`: the payloads the cut's rows name, minus the
  eligible-entry exclusions. An entry is excluded by an acknowledged
  invalidation (coverage page), an expiry (the row's deadline, under
  EXPIRY-CLOCK), a tombstone on the frontier at or above the cut's LSN, or
  accounted damage. `eligibleIn` is the ghost specification and reads the
  ghost sets; `excludedAt` is the media view recovery reads: the coverage set,
  the expiry set and the tombstones on the journal blocks. An eviction whose
  tombstone never reached the media leaves its entry in S, and its payload
  unit stays held.
- A successful same-key replacement excludes its predecessor through one of
  those exclusions. A fill of a key whose evicted entry still has a pending
  tombstone is refused (`refusedReplace`), so a replacement follows its
  predecessor's frontier tombstone, invalidation or expiry.
  `NoResurrection` also refuses a recovered entry that a later fill of its
  key superseded.
- A damage set is the set of entries a damaged unit takes with it: every
  entry with a row or its payload on the unit. In the model each row unit
  holds one row. Recovery adds every eligible entry it could not load to
  `lost`, and `LossIsFaultLocal` requires each of them to have its row or
  payload on a damaged unit. The model's `corrupt` action damages payload and
  row units only, at most two at once; a landing, fill or capture that
  rewrites a damaged unit ends its damage.

### Barrier-gated reuse

- Release. A released unit enters quarantine: a payload unit after its
  entry's invalidation, expiry or completed tombstone, a slot's row units when
  the slot leaves the possibly named set, and a journal block whose completed
  tombstone is below the newly named cut's LSN. No new command writes a
  quarantined unit; an earlier attempt may land on it until a completed
  barrier ends that attempt.
- Barrier. A quarantined unit becomes free only at a completed barrier. In a
  tenure the barrier stops admitting unit commands, drains or fails every
  outstanding fill and capture unit, waits for every outstanding tombstone to
  complete, and issues a self Preempt-and-Abort and a Report. Admission stays
  closed through the Report and the release, and only units quarantined
  before the Preempt-and-Abort become free. A Report that does not show the
  issuer as sole registrant frees nothing, and the tenure withdraws: for the
  serving tenure the model represents that as `lose`, and for a deposed
  tenure as a schedule in which it issues nothing further. In the model the
  barrier is one step, and fills and captures complete at issue, so the guard
  names tombstones. At takeover the fence is a Preempt-and-Abort naming every
  registrant of the lineage since the last completed barrier, A and B when B
  was lost before its fence, followed by a Report showing the successor as
  sole registrant. A fence whose Report does not confirm the successor is
  modeled as a successor that never fenced, followed by a takeover from
  `bumped`. The successor admits no command from its fence until its recovery
  has assigned owners; the model's `srv` is 0 over that interval.
- Eviction evidence. Evicting an entry of a possibly named cut writes a
  tombstone to the journal block at the next LSN, and the entry's unit stays
  held until the tombstone completes. A fill of the same key waits for that
  completion. An entry outside every possibly named cut, an acknowledged
  invalidation and an expiry release the unit to quarantine at once; an
  invalidated entry's unit enters quarantine only after its coverage CAS is
  acknowledged.
- Captures. The model's capture is one step: it snapshots the live entries,
  writes the rows and adds the slot to the possibly named set. A runtime
  capture spans a snapshot at t0, its row writes and its Publish. It treats
  each member of an in-progress capture as a member of a possibly named cut
  from t0: evicting the member writes a tombstone and holds its unit, or the
  capture is abandoned before its Publish. The capture records the journal
  head at t0 as its cut's LSN, so a tombstone written after t0 replays
  against the cut. The model does not exercise this window.
- Publish. A Publish that loses the version race stays pending until the
  acknowledgment of a later committed Publish settles it and shrinks the
  possibly named set, or until recovery clears it. The prefix model's
  Confirm, which settles such a Publish when no later Publish succeeds and
  can shrink the set to an older named slot, is outside this model; a Confirm-driven shrink
  releases rows and blocks under the same rule as the acknowledgment here,
  bounded by the LSN of the slot it names.
- Protected set. The named slot, every possibly named slot, every journal
  block holding a tombstone at or above the oldest possibly named cut's LSN,
  the payload units of eligible entries, and the members and row units of an
  in-progress capture.
- Copies. One named checkpoint copy suffices; recovery validates each row and
  payload unit separately, so a damaged unit loses only its damage set. The
  cases damage one or two units.
- Finite reuse. The quarantine holds at most the units released since the
  last completed barrier. With three slots, the named slot and two others, a
  barrier is needed at least every two settled captures: a third capture
  finds both other slots quarantined. The slot named at a tenure's start holds
  no attempt of that tenure after its fence, so the Rust set and the prefix
  model free it when it leaves the set, and three slots then allow three
  captures per tenure. A journal block is reused only after
  both its tombstone falls below the named cut and a barrier. The journal
  sizing rule, which the model does not check, is at least as many blocks as
  evictions of entries of possibly named cuts in two capture intervals plus
  one barrier interval.
- Exhaustion. Every refusal precedes acknowledgment and changes nothing: a
  fill with no free payload unit (`refusedFull`), a fill whose key's evicted
  entry still has a pending tombstone (`refusedReplace`), a capture with no
  free slot (`refusedSlot`, the cut unchanged), and an eviction whose journal
  block is held (`refusedLog`, the entry stays live and eligible). No entry
  of a possibly named cut leaves it without a durable tombstone. A tombstone
  write that never completes blocks every barrier; its terminal outcome is
  the next takeover, whose fence ends the attempt and whose recovery keeps
  the entry eligible unless the tombstone landed.

### Properties

| Property | Guarantee |
|---|---|
| `Partition` | Every unit is exactly one of free, quarantined or owned; the three memberships are counted. |
| `FreeUnexposed` | No pending attempt targets a free unit. |
| `AttemptsAgree` | Every pending attempt targets a quarantined unit or the unit its own write owns. |
| `OwnedIntact` | Every owned, undamaged unit holds its owner's write, except a journal block whose tombstone is still in flight. |
| `NamedIsPossible` | The store names a slot in the possibly named set, outside a store restoration. |
| `CutsOwned` | Every possibly named cut owns its rows, its eligible payloads and every completed tombstone at or above its LSN. |
| `Support` | Write records agree with attempts, owners, live entries and rows; every pending attempt is of the tenure that issues commands, which is positive, and outside a store restoration none is of a tenure above the current one; the issuing tenure is 0 or an issued tenure, below the current one while a successor's takeover awaits its fence, and 0 with no attempt from a fence to the next recovery; a pending tombstone holds its block and its entry's unit; outside a store restoration the known version is at most the record version, a Publish that can still commit names a possibly named slot, and a committed pending Publish is below the record version and, when it meets the acknowledgment's shrink guard, names the named slot; during a store restoration the discarded record meets the same Publish facts and names a possibly named slot; a serving host issues under the current tenure; cut LSNs follow capture order and stay at or below the journal head; every tombstone's LSN is below the head, and no live entry or later cut names an entry under a tombstone. |
| `Preserved` | The conjunction of the seven above: the state invariant TLC checks in every reachable state at the bound. |
| `Retained` | Every possibly named cut's rows and eligible payloads, and outside a store restoration the named cut's, are on the media or on a damaged unit (retention across host loss). |
| `LossIsFaultLocal` | Recovery loads every eligible entry of the cut whose row unit and payload unit are undamaged. |
| `NoResurrection` | Recovery loads only entries eligible at the cut, and no entry a later fill of its key superseded. |
| `RecoveredInstalled` | Recovery installs exactly the entries it reports recovered. |
| `RefusalChangesNothing` | A refused fill, replacement, capture or tombstone leaves the state unchanged. |
| `TenureUnique` | No tenure is issued twice, across store rollback and reopen included. |

### Per-action argument

This argument is prose; TLC checks the facts it uses in every reachable state
at the bound, and no tool checks closure outside the bound. `Preserved`
implies `Retained`: an owned, undamaged unit holds its owner's write unless a
tombstone in flight owns it, and `CutsOwned` makes every row and eligible
payload of a possibly named cut an owner. Outside a store restoration the
named cut is possibly named; during one, `Retained` reads only the possibly
named cuts. The argument that each action keeps `Preserved` uses the
`Support` facts. `fill` and `capture` take free units, which no attempt
targets, and their new attempts match their owners. `drop` makes an entry of
a possibly named cut ineligible before its unit leaves its owner: the
tombstone's LSN is at or above every cut that holds the entry, or the entry
is acknowledged or expired. The tombstone's LSN comes from the journal head,
which the model carries across recovery. `tombDone` releases the payload once
the tombstone is on the media. `ackPub` releases only rows and blocks that no
remaining possibly named cut requires; the Publish it acknowledges is the
newest, so its cut's LSN bounds every tombstone it releases. `applyPub` names
a slot in the possibly named set. `land` hits a quarantined unit or a unit
whose owner is the landing write. `barrier` ends the issuing tenure's
attempts, which are every pending attempt, before it moves the quarantine to
free; this uses END-self and admission closed for the whole step. `takeover`
bumps the record version, so no earlier Publish commits. `fence` ends every
attempt of the lineage before recovery, which uses END-foreign, so no attempt
remains while `srv` is 0. `recover` assigns owners from intact media, holds
the tombstone blocks at or above the cut and leaves no attempt on a free
unit. `corrupt` changes only damaged units. `rollback`, enabled only after
host loss, closes takeover and Publish application, and `reopen` restores the
latest record's slot at one version above that record, which `Support` keeps
possibly named and consistent with the pending Publishes, and a tenure floor
at the highest issued tenure; the version step is RESTORE's instance change,
so a Publish issued to the rolled-back instance applies as a lost version race.

A mechanized inductiveness check is an open obligation. A hand-encoded
Apalache 0.62.1 probe built an arbitrary typed initial state over write ids 0
to 6, LSNs 0 to 3 and tenures 0 to 3, assumed `Preserved`, took one model
step and checked `Preserved`; it returned no verdict in 29 minutes and was
stopped. It is not a registered case, and the native
`quint verify --inductive-invariant` form remains to run.

### Cases and bounds

[preserve_check.py](preserve_check.py) declares 82 cases. `preserve-safety`
checks `safety` under the free scheduler at `BOUND = 9` steps: 2,565,426
distinct states, 5,317,568 generated, depth 10, 46 seconds at eight workers.
`preserve-safety-damage` steps under `damageStep`, which adds `corrupt` to the
free scheduler, at `BOUND = 8`: 4,148,308 distinct states, 12,222,918
generated, depth 9, 65 seconds at eight workers. The free scheduler offers no
landing on a unit that already holds its bytes and, under `END`, no barrier
with nothing to end or free, since they change no state; the stale-landing
witness offers every landing. Fourteen reachability witnesses are each
checked as the inverted invariant `not(witness)` and reached in 3 to 9
steps, 8 to 31 seconds each, `witnessDamagedLoss` (a recovery that accounts an
entry to a damaged unit) under `damageStep` at `BOUND = 8` and the others
under the free scheduler:
`witnessWarm`, `witnessStaleLanding` (reachability only: under `END` a
landing on a quarantined unit writes the bytes of that unit's last owner),
`witnessBarrierFreed`, `witnessRefusedSlot`, `witnessRefusedFull`,
`witnessRefusedLog`, `witnessRefusedReplace`, `witnessExcluded`,
`witnessTombLanded` (a pending tombstone lands before it completes),
`witnessChain` (tenure 3), `witnessReopen` (a rollback and a reopen),
`witnessDeposedWrite` (a deposed tenure writes after the takeover CAS) and
`witnessFencedCrash`.

At `BOUND = 9` the free scheduler reaches warm recovery, landings on
quarantined units, a barrier that frees units, each refusal, an exclusion at
recovery, a tombstone landing before completion, three tenures, a rollback
and reopen, a deposed tenure's writes and a crash between fence and
recovery, and the damage case adds unit damage to those schedules at
`BOUND = 8`. Under `END` the fence removes every earlier tenure's attempt and
`land` draws only from pending attempts, so no bound of the free scheduler
lands an earlier tenure's attempt after the successor's fence; a deposed
tenure's attempts can land between the takeover CAS and the fence. The recipes offer such attempts
through `landId`, which accepts only an issued write id, and observe
`landEnded`; the `END = false` controls retain the attempts and produce the
landings. Only the recipes reach a reuse of both unnamed slots after a
barrier and a second recovery after ancestor truncation, each of which needs
10 or more steps, a repair of a damaged unit before the recovery of a
published cut, which needs 9 steps against the damage case's bound of 8, and
timing-only release, since `graceRelease` is outside the free scheduler.

Each run is checked with `safety` and its outcome, with `BOUND` set to its
recipe length, and with each intermediate check its table entry names; the
runner refuses an intermediate check outside the recipe. Each `-no-end` run
sets `END = false` and checks the properties its record names,
`RecoveredInstalled`, its outcome and the same intermediate checks. Each
mutant replaces model text and must break its property first at the last
step of its recipe, which the table names: the runner requires the
violation's trace to hold that step's states plus the initial one, numbered
in order. Every run and mutant takes 8 to 11 seconds; TLC explores one state
per recipe step.

| Case | Steps | Outcome |
|---|---|---|
| `run-warmTakeover` | 9 | A published cut of two entries recovers both after host loss. |
| `run-invisibleAttempt` | 19 | The fill at step 9 is refused with payload 1's unit quarantined; after the barrier a fill reuses that unit, payload 1's attempt has ended at step 12, and the two later fills recover. |
| `run-bothCopiesHit` | 24 | The fourth capture, step 11, is refused; after the barrier captures reuse slots 0 and 1, the first two captures' row attempts have ended at steps 16 and 20, and the entry recovers from slot 1. |
| `run-tombCompleted` | 11 | A completed tombstone excludes its entry, and recovery loads the other. |
| `run-tombLanded` | 11 | A tombstone that landed without completing excludes its entry and joins the frontier. |
| `run-tombLost` | 10 | The lost removal record: a tombstone that never reached the media leaves its entry eligible, and both entries recover. |
| `run-replaceRefused` | 13 | A refill while its predecessor's tombstone is pending is refused at step 7; after the tombstone completes the refill succeeds, and recovery excludes the predecessor. |
| `run-chainABC` | 10 | B is lost before its fence; C's fence ends A's attempts, and both entries recover at tenure 3. |
| `run-fencedCrash` | 12 | B is lost after its fence; C recovers both entries of the named cut at tenure 3. |
| `run-chainABCevict` | 22 | B evicts an entry under a completed tombstone and fills a unit; C reuses that unit and names a new cut, and B's fill attempt has ended. |
| `run-deposedWrites` | 14 | After the takeover CAS the deposed tenure invalidates, fills and captures; its Publish fails on the version, and after the successor's fence its fill attempt has ended. |
| `run-slotsExhausted` | 5 | A fourth capture finds every slot possibly named and is refused. |
| `run-logFull` | 12 | An eviction finds its journal block held by a tombstone at or above a possibly named cut and is refused. |
| `run-payloadFull` | 13 | A fill finds no free payload unit and is refused. |
| `run-exhaustedTakeover` | 17 | After both refusals, recovery loads the named cut, the entry whose tombstone never completed included. |
| `run-journalWrap` | 19 | The acknowledgment releases journal block 9, the barrier frees it, and the tombstone at step 14 reuses it; recovery excludes that tombstone's entry. |
| `run-releaseReuse` | 15 | An expiry and a completed tombstone release payload units 1 and 0; after the barrier the fills at steps 10 and 11 reuse them. |
| `run-storeRollback` | 21 | Takeovers by B and C, a store rollback to tenure 1 and a reopen; the next takeover issues tenure 4. |
| `run-rollbackPastReuse` | 23 | A tombstone never lands, the next recovery frees its entry's unit and a refill reuses it; the rollback at step 19 names the slot whose eligible entry that unit held, and after the reopen recovery reads the latest record. |
| `run-faultLocal` | 10 | A corrupted payload unit loses only its entry. |
| `run-faultLocalRow` | 10 | A corrupted row unit of the named slot loses only the entry that row names. |
| `run-faultLocalTwo` | 11 | A corrupted payload unit and a corrupted row unit of one entry lose only that entry. |
| `run-faultRepaired` | 11 | A landing rewrites a corrupted payload unit before host loss, and both entries recover. |
| `run-damageRepairedByFill` | 11 | After recovery a fill rewrites the corrupted payload unit and ends its damage. |
| `run-damageRepairedByCapture` | 15 | After recovery a capture reuses the corrupted row unit and ends its damage. |
| `run-takeoverBeforePreempt` | 15 | B is lost before its fence; after C's fence and a reuse of A's unit, A's attempt has ended. |
| `run-warmTakeover-no-end`, `run-chainABC-no-end`, `run-fencedCrash-no-end` | 9, 10, 12 | With `END = false`: `Retained`, `LossIsFaultLocal`, `NoResurrection`, `RecoveredInstalled` and the outcome hold. |
| `run-faultLocal-no-end`, `run-faultLocalRow-no-end`, `run-faultLocalTwo-no-end`, `run-faultRepaired-no-end` | 10, 10, 11, 11 | With `END = false`: `LossIsFaultLocal`, `RecoveredInstalled`, the outcome and the intermediate checks hold. |
| `mutant-total-eviction` | 9 | Recovery loading nothing breaks `LossIsFaultLocal`. |
| `mutant-all-or-nothing-load` | 10 | Recovery that loads nothing when a payload unit is damaged breaks `LossIsFaultLocal`. |
| `mutant-all-or-nothing-load-row` | 10 | The same recovery with a damaged row unit breaks `LossIsFaultLocal`. |
| `mutant-all-or-nothing-load-two` | 11 | The same recovery with two damaged units breaks `LossIsFaultLocal`. |
| `mutant-skipped-tombstone` | 8 | An eviction of an entry of S without a tombstone frees its unit at the barrier, and a fill overwrites it: `Retained`. |
| `mutant-replay-skips-tombstone` | 11 | Recovery that ignores the journal reloads an entry under a completed tombstone: `NoResurrection`. |
| `mutant-replay-skips-landed-tombstone` | 11 | The same recovery reloads an entry under a landed tombstone: `NoResurrection`. |
| `mutant-replace-before-tombstone` | 11 | A refill admitted while its predecessor's tombstone is pending; the tombstone never lands, and recovery reloads the superseded predecessor: `NoResurrection`. |
| `mutant-reuse-after-grace` | 11 | Timing-only release lets a fill reuse a unit that a pending attempt then overwrites: `Retained`. |
| `mutant-larger-slots` | 10 | Four slots under a rule where a slot leaving the possibly named set returns straight to free: a capture reuses slot 0 and the first capture's row attempt overwrites it: `Retained`. |
| `mutant-premise-no-end` | 15 | `END = false` on the `takeoverBeforePreempt` recipe: A's attempt overwrites the reused unit: `Retained`. |
| `mutant-barrier-no-end` | 6 | `END = false`: the barrier frees a unit an attempt still targets, a fill reuses it and the attempt lands: `Retained`. |
| `mutant-both-copies-no-end` | 20 | `END = false` on the first 20 steps of the `bothCopiesHit` recipe: the first two captures' row attempts have landed on the reused row units of slots 0 and 1. |
| `mutant-retained-reads-restored-named` | 19 | `Retained` that reads the restored named slot breaks at the rollback of `rollbackPastReuse`. |
| `mutant-recover-installs-nothing` | 9 | A recovery that reports its entries and installs none: `RecoveredInstalled`. |
| `mutant-land-unissued-id` | 6 | Without `landId`'s issued-id guard, a Publish id reports an ended attempt. |
| `mutant-journal-no-end` | 24 | `END = false`: a stale tombstone lands over the reused journal block, and recovery reloads the entry the newer tombstone evicted: `NoResurrection`. |
| `mutant-barrier-exposes-free`, `mutant-barrier-breaks-agreement` | 3 | `END = false`: after a fill, an invalidation and a barrier, the fill's attempt targets a free unit: `FreeUnexposed` and `AttemptsAgree`. |
| `mutant-fill-skips-image` | 1 | A fill that takes its unit without writing it: `OwnedIntact`. |
| `mutant-release-named-rows` | 5 | An acknowledgment that releases the named slot's rows: `CutsOwned`. |
| `mutant-shrink-drops-named` | 5 | An acknowledgment that empties the possibly named set: `NamedIsPossible`. |
| `mutant-tomb-keeps-head` | 6 | A tombstone that leaves the journal head in place: `Support`. |
| `mutant-preempt-last-owner-only` | 15 | A fence that spares A leaves A's attempt alive: `Retained`. |
| `mutant-fence-keeps-previous` | 22 | A fence that spares tenure `ten - 1` leaves B's fill attempt alive, and it overwrites C's reused unit: `Retained`. |
| `mutant-fixed-generation-gap` | 19 | A reopen at the snapshot's tenure plus one lets the takeover at step 19 reissue tenure 3: `TenureUnique`. |
| `mutant-ancestor-truncation` | 22 | Recovery that frees the tombstone blocks above the cut lets B's later tombstone overwrite the block, and C's recovery reloads the evicted entry: `NoResurrection`. |
| `mutant-partition-overlap` | 3 | A barrier that keeps its quarantine leaves a unit both free and quarantined: `Partition`. |
| `mutant-refusal-writes` | 12 | A refused eviction that advances the journal head: `RefusalChangesNothing`. |
| `mutant-full-refusal-writes` | 13 | A refused fill that advances the write counter: `RefusalChangesNothing`. |
| `mutant-replace-refusal-writes` | 7 | A refused refill that advances the write counter: `RefusalChangesNothing`. |
| `mutant-slot-refusal-writes` | 5 | A refused capture that advances the write counter: `RefusalChangesNothing`. |

These are finite checks at the stated bounds.

### Evidence state

BGR is qualified at the stated bounds, conditional on `END`, NEW-EXCLUSION,
DURABLE and EXPIRY-CLOCK, on RESTORE for the rollback cases, and on the durable
lineage registrant set the fence reads from tenure arithmetic. The tenure
model's issuance rule admits a takeover's preempt of the key of a host whose
tenure it succeeded, and its takeover CAS keeps the predecessor's volume. The
runtime preempt names one key, the holder's, while this preservation model's
fence ends every lineage registration. In the two-hop chain whose middle
successor stopped before its fence, the fresh host's takeover preempts the
earlier owner, the holder, and the middle successor's registration, which
never held, stays registered. END and that runtime refinement remain open. Reusing an attachment key across
tenures lets a paused successor depose a later tenure, which the deposed
owner's recorded-holder hold turns into a wait, with the volume retained,
until the deposed tenure's own restart preempts the stale holder through the
tenure model's lineage arm. P4 credit, with R2's host-loss clause, which states the same
retention guarantee, sits in `preserve-p4-retention-proposed`, whose runs are
`invisibleAttempt`, `bothCopiesHit`, `takeoverBeforePreempt`,
`chainABCevict`, `deposedWrites`, `faultLocal`, `faultLocalRow`,
`faultLocalTwo` and `faultRepaired`. Its controls are the three END controls
`premise-no-end`, `barrier-no-end` and `both-copies-no-end` and the fence
mutants `preempt-last-owner-only` and `fence-keeps-previous`.
`verification/quint/expected.json` blocks each run on the END provider
contract and the holder-only runtime versus all-registrant fence gap, so the runs still run and reach their outcomes
and the record receives no credit. By inspection each of those runs' `safety`
check needs `END`: with `END = false` the fence leaves a deposed tenure's
attempts while `srv` is 0, which `Support` forbids, and in every run except
`faultRepaired` a later barrier or recovery also frees a unit such an attempt
targets. `faultRepaired` lands its own write's live attempt to repair the
damaged unit.

The unblocked records credit neither P4 nor R2. The barrier-gated reuse
record credits P7, R9 and KTD3 conditional on `END`, the exclusion-evidence
record credits P5's lost removal and same-key replacement and KTD11
conditional on `END`, and the rollback record credits the R12 tenure floor
conditional on `END` and on the RESTORE premise. By inspection their runs
that reach a barrier or a fence need `END` for the same reason; a run that
reaches neither, such as `slotsExhausted`, `logFull` and `payloadFull`, holds
with either value of `END`. Their `safety` checks need the fence to
end the deposed tenure's attempts (`Support` requires an empty attempt set
while fenced), and that fence names other hosts' keys, which the tenure
model's `NoPreemptOfForeignKey` admits only for a host whose tenure the
issuer's committed takeover succeeded. Every record whose runs recover adopts the predecessor's volume, as
the tenure model's takeover CAS does; each record's `reference` says so. P5's capture-removal race lies outside these
records, since the model's capture is one step. The takeover-chain record
credits P9 and R1 through `warmTakeover`, `chainABC` and `fencedCrash`: warm
recovery after host loss at tenure 2 and, after a successor crashes before
or after its fence, at tenure 3; their `-no-end` twins check retention, the
installed index and each outcome with `END = false`, so that record carries
no fence clause. The fault-local record credits R3's loss locality without
`END`: `LossIsFaultLocal`, `RecoveredInstalled`, each outcome and each
intermediate check hold on `faultLocal`, `faultLocalRow`, `faultLocalTwo` and
`faultRepaired` with `END = false`.

Under `END` an earlier attempt can land only on a quarantined unit or on its
own write's unit, so no positive run shows a damaged copy. The controls
`reuse-after-grace`, `larger-slots`, `premise-no-end`, `barrier-no-end`,
`both-copies-no-end` and `journal-no-end` each show a reused unit reverted by
an earlier attempt: three overwrite a reused payload unit, `larger-slots`
overwrites a row of the named slot, `both-copies-no-end` overwrites row units
of slots 0 and 1, and `journal-no-end` overwrites a journal block. The prefix
model's `shrink-frees-slot` mutant is the failure trace of a rule that frees a
slot leaving the possibly named set while an earlier capture's attempts may
still land on it.

### Outcome witnesses through the implementation

The takeover history tests in
`crates/kestrike/src/net/takeover_history_tests.rs` witness model cases'
outcomes through the Rust code and judge each run with the history oracle.
Each test is written by hand to reach the outcome a case's table entry
states. No ITF trace, model digest or registry entry binds a test to its
case, so these witnesses carry no trace-replay credit: a change to a model
run or to its Rust scenario can leave both suites passing. Registered trace
replay of these cases against the Rust steps, bound as the session and
detection replays bind theirs, is part of #136's acceptance and remains open;
the takeover record lists it among the activation blockers. A tenure
writes its payloads and its checkpoint through the volume, the takeover
sequence runs over the store double, the reconciler's steps designate a fresh
host, the successor attaches the same simulated media warm, and a client reads
through an owner over that volume. The oracle then requires every member of
the retained set to be served with its exact bytes or to lie on a unit the
test damaged. Every host's card and every tenure's medium commands share one
reservation table: a read or write a deposed tenure has not yet executed
completes with Reservation Conflict, the NEW-EXCLUSION premise for a command
issued after the preempt. The no-fence control alone clears that scripted
status after the takeover and its preempt, so its deposed write lands. A
command already executed keeps its bytes, and each test asserts that a tenure
it keeps stepping holds no waiting command when a takeover preempts it, so no
test establishes or relies on END. The
device's Reservation Report is answered from a table of the tenure's own,
which takes the shared reservation's registrants once the tenure is deposed.
Each tenure's serving clock reads the elapsed time of the tenure's own rounds
through a strategy. A tenure that a test serves inside another's closure
advances its own clock alone, so in the route control the old owner's clock
stands still while its successor serves. Under the default, a frozen clock, the owner submits no periodic
Report after its first. Under an honest or a slow clock with a finite window
the owner reports periodically, and a deposed tenure's Report table names its
successor as holder, so a Report is one observation that can withdraw it.
Each history prints the withdrawal's cause. The tests assert these causes:
in `so2` the retry's coverage call withdraws the owner with a newer fence
under every clock; in `so3` a page write or a Report withdraws it, and a page
write under a frozen clock; in `so4` under a frozen clock its device read
ends in Reservation Conflict; and the idle-tenure test requires a Report
under an honest clock and leaves its trigger open. In `so1` and in `so4` one
case's withdrawal carries a flip request, which the store client's `retire`
refuses on a record read after the takeover; no test fixes which clock brings
it.

The stale-owner histories in
`crates/kestrike/src/net/takeover_history_tests/stale_owner.rs` run a
deposed owner beside its successor, each under an honest, a slow and a frozen
owner clock. Three of them place the successor inside the owner's coverage
page requests, and one pauses the owner across the takeover. They are hand-written outcome witnesses with no
trace-replay credit, and they meet no acceptance criterion of #136. In `so1`
the successor fences after the store commits and acknowledges the owner's page
write and before the owner receives that reply, so the owner acknowledges
after the fence. The coverage run `ackBeforeSuccessorFence`, in which the
owner acknowledges first, is the nearest run: in both, the successor's fence
carries the entry forward on the page. The successor's miss of the covered
object is the Rust history's observation. `so2` and
`so3` commit the owner's page write with an unknown reply and place the
successor after the retry and after the reread. No directed coverage run
places a successor at either point; `rereadAfterCondition` is the nearest run.
In both the owner acknowledges nothing and withdraws. Every store write of
the old owner reaches the store inside the call that issued it; a write
parked before the takeover that lands after it stays with #136.

A case is listed as witnessed only when a test reaches the outcome the case's
table entry states.

| Model case | Witnessed as |
|---|---|
| `run-warmTakeover`, `run-warmTakeover-no-end` | A warm takeover serves the whole cut at the successor's tenure. |
| `run-chainABC`, `run-chainABC-no-end` | A successor stops after its takeover write and before its preempt; the designated fresh host recovers the cut at the third tenure. |
| `run-fencedCrash`, `run-fencedCrash-no-end` | A successor stops after its preempt, before it attaches; the fresh host preempts it and recovers the cut at the third tenure. |
| `run-faultLocal`, `run-faultLocalRow`, `run-faultLocalTwo` and their `-no-end` twins | A damaged payload unit, row unit or both lose exactly the objects on them. |
| `run-faultRepaired`, `run-faultRepaired-no-end` | A repeated landing of the tenure's own write repairs the damaged unit. |
| `run-tombCompleted` | A certified removal record excludes its object. |
| `run-tombLanded` | A removal record on the media whose suffix the store never certified excludes its object. |
| `run-tombLost`, suffix `run-tombLost` | A removal record that never reached the media leaves its object in the cut, and it is served. |
| suffix `run-wrapRefused` | The store refuses a suffix reservation whose end would take a unit at or above the floor, and with that bound planted away the `SuffixLog` the test drives refuses the append. |
| `mutant-all-or-nothing-load-row` | Planted in the slot reader: a refusal of the whole slot on one damaged row unit loses objects outside the damage set. |
| suffix `mutant-wrap-before-floor` | Planted in both places the capacity rule holds, the store's reservation bound and the log's capacity: a block lands over the replacement record the replay needs, and the replaced label is lost. A plant in either place alone is refused by the other. |

`run-deposedWrites` has no witness. Its deposed commands all precede the
fence and its outcome is an attempt the fence ended. The test
`a_deposed_tenures_fill_after_the_successors_fence_writes_nothing_and_withdraws_it`
runs under a different premise, NEW-EXCLUSION, which the harness supplies: a
deposed successor's fill issued after the later takeover's preempt reaches
the device, and the harness completes it with Reservation Conflict and moves
no byte. The test checks the owner's reaction, that the fill publishes
nothing and the authority withdraws on the conflict, and the order of the
ownership steps the harness records. Its no-fence control lets the deposed
write land and fails the ownership monitor's O1. Neither test establishes END
for a command queued before the fence, and neither witnesses
`run-deposedWrites`.

The suffix model's `run-removeLostInsertRetained`, `run-sameLevelDamage` and
`run-crossLevelDamage` have their outcomes unreached, and the gap is a
qualification failure. The model's `Retained` loses to a damaged certified
block only the entries that depend on it. The Rust warm load refuses the whole
slot on any damaged suffix history, so it ends before the INSERT behind a
damaged REMOVE or the successor's reuse of its unit that those runs need. The
test damages one lone removal block, or the replacement block, and the
successor restores nothing; the oracle fails the objects no damaged unit
holds. The test
`a_damaged_certified_suffix_block_refuses_the_whole_load_and_fails_fault_local_retention`
asserts that refusal and the failing rule, and the record
`takeover-history-suffix-damage-qualification-failure` carries the handoff:
warm takeover stays closed until the load installs what a damaged suffix
leaves, or the specification accepts whole-load refusal as the damage bound.
The decision belongs with the END decision in the U0 handoff tracker below.
The oracle's damage excusal knows an entry's row unit and payload unit only.
Before fault-local suffix outcomes can be credited, it must also count an
entry's suffix dependencies: the blocks of its suffix before its INSERT and
the second block of a record split across two blocks. A load that loses an
entry to a damaged dependency block would otherwise be judged a loss.

These preservation runs have no witness:

| Runs | Reason |
|---|---|
| `invisibleAttempt`, `bothCopiesHit` | Each rests on attempts the in-tenure barrier ended, END-self, which the run checks mid-run after payload or slot reuse behind that barrier, and ends on a recovery; no tenure on this base releases a quarantined unit. |
| `takeoverBeforePreempt`, `chainABCevict` | Each ends on an attempt a successor's fence ended, END-foreign, after reuse of the deposed tenure's unit. |
| `deposedWrites` | Its deposed commands precede the fence, and its outcome is the attempt the fence ended, END-foreign. |
| `replaceRefused`, `releaseReuse`, `journalWrap`, `slotsExhausted`, `logFull`, `payloadFull`, `exhaustedTakeover` | The refusals and releases belong to the owner's suffix and capture writer, which the owner does not run; the saturation tests check the refusals at the library seams. |
| `damageRepairedByCapture` | Needs the successor's capture writer. |
| `damageRepairedByFill` | Tried: the allocator placed the refill on another free unit, and no seam directs it to the damaged one. |
| `storeRollback`, `rollbackPastReuse` | Need the store restoration gate. |

These suffix runs and mutant have no witness:

| Runs | Reason |
|---|---|
| `replaceOther`, `splitCut`, `replaceWhole` | Each needs a record split across two blocks, with one landed or both; every record the tests append or place seals one block, so the replacement test witnesses a one-block REPLACE only. |
| `frontierBehindHole` | Needs a hole inside a landed suffix, which no test builds. |
| `midRegion`, `logFull`, `chainABC`, `ringReuse`, `exhaustedSuccessor`, `staleUnit` | Each needs a checkpoint publish, an extension or a successor's own suffix appends, which belong to the owner's capture and suffix writer. |
| `mutant-release-before-durable` | Varies a rule of that writer. The test `a_payload_unit_reused_before_its_removal_record_landed_leaves_a_retained_entry_unserved` writes the state it reaches as an injected end state. |
| `removeLostInsertRetained`, `sameLevelDamage`, `crossLevelDamage` | Outcomes unreached, as stated above. |

The other mutants have no witness: each varies a model rule (the barrier, the
fence's registrant set, the release of named rows, the refusal steps, the
journal replay) whose Rust counterpart either is checked by that module's own
tests or is not run by the owner on this base. The tenure that writes the cut
is driven from the test, and the earlier tenure's suffix block and the first
record's chain are placed by the test. In every suffix case the owner the
record names runs no volume: the test appends its removal records to a bare
`SuffixLog`, takes the sealed blocks, marks them written with no device write
and copies their bytes onto the media, so the durable-before-reuse rule never
runs. An acknowledged INVALIDATE before the loss is a coverage page write by
the store client. The successor of
`control_fills_opened_before_the_allocator_holds_the_cut_overwrite_it_and_fail`
opens its suffix through `checkpoint::open_suffix`, called from the test: a
warm load requires the log, so the fill publishes only once it is open. These
gaps wait on an owner turn that runs the capture, the checkpoint and the suffix
writer: #1446c (PR blotter pull request 1521), which is on this base, gives `open_suffix` and
`suffix_step` no production caller and adds no owner turn that starts a
capture or stages a checkpoint.

### Handoff

The architecture decision U0 requests, an EBS provider contract for END-self,
END-foreign and NEW-EXCLUSION or the independent-copy architecture, and the
obligations the model hands to U1 through U13 are tracked in
https://github.com/ahrav/kestrike/issues/148.

## Suffix model

[suffix.qnt](suffix.qnt) models one shard's mutation suffix, the U6 mechanism
of issue #120 (KTD4), over a delta region of `J = 4` blocks after the
checkpoint slots, with two keys and two payload units. A tenure appends
INSERT, REMOVE and REPLACE records to its open block, is refused at its
reserved end, seals the block, which takes the next LSN and leaves a write
attempt that may land or stay pending, learns a completion of the lowest
pending block, which advances the durable prefix and releases the payload
units of the tombstones whose record's last part lies in it, raises the
certified end to the durable prefix, raises the reserved end within its
capacity, and publishes a settled cut, the head with the open block sealed,
whose checkpoint is the live set. A capture pass also runs in two steps:
`startPass` seals its cut at the head and takes the live set as its snapshot,
and `publishPass` publishes that snapshot at that cut after membership changes
the suffix recorded above it; the atomic publish runs only with no pass in
flight. The head runs at most `UNCERTIFIED` blocks past the certified end. A
record may be split across two blocks. A
block below the certified end may be damaged. Host loss keeps the open block
and every unlanded attempt from the successor; the successor's fence ends the
attempts, and its recovery replays the checkpoint and then every suffix of
the chain from the cut. The successor's suffix starts at the predecessor's
reserved end.

Capacity follows barrier-gated reuse (see the Preservation model): a tenure's
LSNs lie below `min(floor, start) + J`, where `floor` is the settled cut, so LSN
`L` reuses the unit of `L - J`, a block below the cut that an earlier tenure
wrote and the tenure's fence ended, the barrier that frees it. A settled
publish raises the floor; the capacity never passes `start + J`, because no
in-tenure barrier ends the tenure's own attempts. A tenure therefore writes at
most `J` blocks, and a successor of a tenure that used every block admits
mutations after its first publish.

Replay checks each block before any record applies: a unit holding a block of
another LSN or session, a damaged block or an empty unit is a hole, and a
split record is whole only when the next block is valid too. Tombstones of
whole records exclude their identity whatever the holes; inserts apply only
up to each suffix's first hole, and the inserts behind it are named as
dropped. The checkpoint is level 0 and each suffix its own later level: a
later level's entry supersedes an earlier entry on its unit, and two entries
of one level on a unit are both withheld. A hole below a suffix's certified
end is damage, and the recovery raises each suffix's certified end to the
blocks it read whole.

| Property | Guarantee |
|---|---|
| `OneOwner` | No two recovered entries own one payload unit or one key (P6). |
| `ReplayReflectsCut` | A recovery loads only acknowledged entries, and every checkpoint entry it does not load is excluded by a whole tombstone or superseded by a later level (P5). |
| `NoResurrection` | No recovered entry has a whole tombstone on the medium (FRONTIER). |
| `RecoveredIntact` | A recovered entry's unit holds its own payload, unless the first or last block of one of its own tombstones was damaged. The ghost `tombAt` keeps the first and last block LSNs of every tombstone of an id, so a resurrected entry that the successor removes again keeps the exception its damaged tombstone grants, and damage to another record's block grants none. The ghost `damagedLsns` keeps the LSN of every block a fault damaged, so the exception survives a later landing that replaces the damaged block. The exception records damage and not its effect: it holds for an id from the first damage to the first or last block of any of its tombstones, a split tombstone that never became whole included. It holds per id, so a payload that a later removal of the same resurrected id released before its tombstone was durable falls under it too; the hold in `evict` and `replace` rules that release out, and no invariant checks the hold apart from `RecoveredIntact`. |
| `Retained` | Every entry live at the last durable block recovers unless a whole tombstone excludes it, a later level superseded it after its removal, a block of its suffix before its insert is not intact on the medium, or a block of its own insert is not intact (R2, R3). |
| `NoConflict` | No two entries of one level claim a unit. |
| `HistoryNotReused` | A landing replaces only a block below the cut (P7). |
| `InTenureCapacity` | The head and the reserved end stay at or below the capacity, and the capacity at or below `start + J`; `HistoryNotReused` covers the floor. |
| `RefusalChangesNothing` | A refused append leaves the live set, the held units, the open block, the head and the reserved end unchanged. |
| `UncertifiedBounded` | The head runs at most `UNCERTIFIED` blocks past the certified end, so the acknowledged records a replay could count as an unflushed tail stay bounded (P7, R9). |
| `HandoffCutIsExact` | The recovery after a planned transfer loads exactly the membership at the withdrawal, the drain's checkpoint and its sealed suffix certified through the head, unless a fault damaged a block from the cut to the head and the replay reports damage (#255 FP-HAND-06, END). `prior`, the state the recovery started from, holds that membership and that head, which the transfer fixed. `transfer-before-certify`, `transfer-below-head`, whose transfer needs the certified end only at the durable end, and `transfer-unsealed`, whose mutations stop with a REMOVE in the open block, break it; so do `transfer-before-certify-reports-damage`, whose recovery reports damage where no fault damaged a block, and `handoff-damage-unreported`, whose recovery reports none after a fault damaged X's REMOVE. |
| `TransferAtCertifiedHead` | The planned transfer follows a certify through the head, the durable end of the sealed suffix, with no record in the open block (#255 FP-HAND-06). `transfer-at-durable-head`, whose transfer needs only the durable end at the head, breaks it at the transfer while X's durable REMOVE is uncertified, a state whose recovery still replays the REMOVE, and `transfer-with-open-block` breaks it at the transfer with X's REMOVE in the open block. |
| `TransferFollowsPublish` | At the planned transfer the exit has published its checkpoint after fills stopped (the ghost `drainPublished`), and every block on the medium from the cut on holds REMOVE records alone: the drain's checkpoint holds every entry the recovery loads, and the suffix past it only removes (#255 FP-HAND-06). `transfer-before-publish`, whose mutations stop before the drain's publish, and `fill-after-stop`, whose fill is admitted after that publish, each leave X's INSERT above the cut and break it at the transfer. `transfer-on-earlier-publish`, whose mutations stop before the drain's publish under a checkpoint published before fills stopped, leaves X's REMOVE alone above that cut and breaks it at the transfer. |

[suffix_check.py](suffix_check.py) declares 98 cases. `UNCERTIFIED` is 4,
which never binds inside one tenure of `J = 4` blocks, except in
`UncertifiedBounded`, the `uncertifiedCap` run and the `cap-skipped` mutant,
where it is 2. `suffix-safety` checks
`safety` under the free scheduler at `BOUND = 12`; each of the ten
free-scheduler properties alone and the four witnesses run at `BOUND = 9`.
`HandoffCutIsExact`, `TransferAtCertifiedHead` and `TransferFollowsPublish`
have no case of their own: `handoff-safety` checks them within `safety` under
`drainStep`, and the ten handoff mutants break them. The NO-SKIP and cross-level
supersession hazards need 13 and 14 transitions, so the directed runs and
mutants below cover them, each checked with `safety` over its whole recipe. Each run is a recipe checked with
`safety` and its outcome, with `BOUND` the recipe length, beside a reach case
that shows the recipe ends in a state holding the outcome. Each mutant
replaces model text and must break its property first at the last step of its
recipe.

| Case | Outcome |
|---|---|
| `run-tombLost` | A tombstone that never reached the medium leaves its entry recovered. |
| `run-replaceOther` | A replacement on another unit whose second block never landed leaves the old entry and loses the new one. |
| `run-replaceWhole` | The same replacement with both blocks durable installs the successor and excludes the predecessor. |
| `run-removeLostInsertRetained` | A certified REMOVE X/1 followed by INSERT Y/1 and damage to the REMOVE's block: Y is dropped and named, X resurrects, the damage is accounted. |
| `run-sameLevelDamage` | The same within one suffix: X and Y of one level, Y dropped behind the hole. |
| `run-crossLevelDamage` | A predecessor's certified REMOVE block is damaged after the successor reused its unit: the successor's intact entry supersedes the resurrected one. |
| `run-splitCut` | A split record whose second block never landed applies nothing. |
| `run-midRegion` | Replay starts at a cut inside the region; a tombstone above it excludes. |
| `run-frontierBehindHole` | A whole tombstone behind a hole of its suffix excludes its entry. |
| `run-logFull` | A fill at the reserved end is refused with nothing changed; an extension admits it. |
| `run-exhaustedSuccessor` | A successor of a tenure that used every block is refused, and its first publish raises its capacity. |
| `run-chainABC` | B is lost before its block lands; C replays A's suffix and B's, each from its own start. |
| `run-ringReuse` | A successor's block takes the unit of a block below the cut. |
| `run-wrapRefused` | At the floor's capacity the tenure refuses rather than wrap over required history. |
| `run-staleUnit` | A unit of the predecessor's range with no block of its LSN ends that suffix's tail. |
| `run-publishAfterRecordedRemoval` | A pass publishes after a recorded REMOVE of its snapshot member; the replay from the pass's cut excludes the member and installs the fill that took its unit. |
| `run-uncertifiedCap` | An eviction is refused at the certified end plus the cap and admitted after a certify. |
| `run-damagedTombReused` | X resurrects through its damaged REMOVE over a later fill's payload, with the damage reported, and enters the successor's published cut, which puts the damaged block below the replay's start; a later tenure's landing replaces that block, and the two recoveries after the publish load X and report no damage, with the exception still granted by the ghost's record. |
| `run-splitTombFirstDamaged` | A split REPLACE of X completes and is certified, a fill takes X's released unit, and the REPLACE's first block is damaged: X resurrects over the fill's payload with the damage reported. |
| `run-splitTombLastDamaged` | The same with the REPLACE's second block damaged. |
| `run-removedAgain` | X resurrects through its damaged REMOVE over a fill that took its unit; the successor removes X again, seals that REMOVE and loses its host before the block lands, and the next recovery resurrects X once more, with both tombstones on record and the first one damaged. |

| Mutant | Breaks |
|---|---|
| `skip-holes` | `NoConflict`: the insert behind a hole and the resurrected entry claim one unit at one level. |
| `blind-skip` | `OneOwner`: hole skipping with no ownership check loads two owners of one unit. |
| `partial-record` | `Retained`: a REPLACE cut by a hole excludes its old identity from its first block alone. |
| `no-exclusion` | `NoResurrection`: no record excludes. |
| `frontier-before-hole` | `NoResurrection`: exclusions stop at a suffix's first hole. |
| `withhold-across-levels` | `Retained`: every shared unit withholds all its owners, so the successor's intact entry is lost. |
| `wrap-before-floor` | `HistoryNotReused`: a capacity that ignores the history below the start lets a landing replace a block the replay needs. |
| `rebase-past-start` | `InTenureCapacity`: a publish raises the capacity past the start plus `J`. |
| `recover-installs-nothing` | `ReplayReflectsCut`: a recovery loads nothing, so a checkpoint entry with no tombstone and no later owner is lost. |
| `drop-intact` | `Retained`: an intact insert is dropped and named, with no hole of its suffix before it on the medium. |
| `refusal-writes` | `RefusalChangesNothing`: a refusal empties the live set. |
| `release-before-durable` | `RecoveredIntact`: a unit released at the append is reused while the tombstone is unflushed. |
| `release-beside-damage` | `RecoveredIntact`: the same early release with damage to the block before the lost one-block REMOVE, which grants that tombstone no exception. |
| `tomb-first-block-unread` | `RecoveredIntact`: an exception that reads a tombstone's last block alone refuses `splitTombFirstDamaged`. |
| `tomb-last-block-unread` | `RecoveredIntact`: an exception that reads a tombstone's first block alone refuses `splitTombLastDamaged`. |
| `forgets-damaged-tombstone` | `RecoveredIntact`: a ghost that keeps only an id's latest tombstone refuses `removedAgain`, whose second REMOVE hides the damaged first one. |
| `cut-at-publish` | `RecoveredIntact`: a pass's cut taken at its publication instead of its start skips the recorded REMOVE of its snapshot member. |
| `cap-skipped` | `UncertifiedBounded`: an append past the certified end plus the cap is admitted. |

A planned exit runs under `drainStep`, the free scheduler with four more
actions: `stopFills` refuses fills and REPLACEs while REMOVEs continue,
`stopMutations` stops every append once the open block is sealed, `transfer`
withdraws and transfers once the certified end reaches the head, and
`resumeDrain` resumes in place before the transfer (D21). The free
scheduler's atomic `publish`, taken after `stopFills`, is the drain's
checkpoint: it moves the phase to `published` and sets the ghost
`drainPublished`, which a resume, a host loss and a recovery clear. The host may be lost
at any drain step, and the recovery after the transfer, the target's or the
outgoing owner's same-host restart after a refused or unknown transfer, is
`recover`, which then records `handoffRecover`. `handoff-safety` searches
`safety` with `drainStep` for ten turns after X's block is durable and
certified and must reach its last turn, and its three witnesses, each after
that prefix, reach a recovery after a transfer that loads a nonempty
membership, one that reports damage and one that reports none and excludes
an entry by a REMOVE of the sealed suffix. That search takes every action of
`drainStep`. It reaches no transfer with a capture pass in flight, since
fills stop only with none, and no recovery after a transfer that replays an
earlier tenure's suffix, since the drain's publish drops the chain below its
cut; within its bound every damage report after a transfer comes with a
membership that differs from the withdrawal's. The recovery reads the record's
checkpoint, cut and suffix chain as the drain left them: the tenure model's
transfer write keeps them, a premise no Quint case checks and the transfer
writer's Rust tests (#279) carry.

| Case | Outcome |
|---|---|
| `run-handoffCutExact` | The transfer follows the drain's publish and a certify through the head: the recovery loads exactly the membership at the withdrawal. |
| `run-handoffCutDamageReported` | A block of the sealed suffix below the certified end is damaged after the transfer: the replay reports the damage, the one exception the property admits. |
| `run-handoffLostDuringDrain` | The host is lost after the drain's publish: the successor recovers as after any host loss. |
| `run-handoffResumeAdmitsFill` | A planned exit resumes before the transfer and admits a fill again. |
| `mutant-transfer-before-certify` | Breaks `HandoffCutIsExact`: the transfer ignores the certified end, the fence ends X's pending REMOVE, and X resurrects. |
| `mutant-transfer-below-head` | Breaks `HandoffCutIsExact`: the certified end at the durable end admits a transfer while X's REMOVE is pending. |
| `mutant-transfer-at-durable-head` | Breaks `TransferAtCertifiedHead`: the durable end at the head admits a transfer while X's durable REMOVE is uncertified. |
| `mutant-transfer-unsealed` | Breaks `HandoffCutIsExact`: mutations stop with X's REMOVE in the open block, which never takes an LSN. |
| `mutant-transfer-with-open-block` | Breaks `TransferAtCertifiedHead` at that transfer, one step before the recovery. |
| `mutant-transfer-before-publish` | Breaks `TransferFollowsPublish`: mutations stop before the drain's publish, and X's INSERT lies above the cut at the transfer. |
| `mutant-transfer-on-earlier-publish` | Breaks `TransferFollowsPublish`: mutations stop before the drain's publish under a checkpoint published before fills stopped, so X's REMOVE alone lies above the cut and the transfer follows no publish of the exit. |
| `mutant-fill-after-stop` | Breaks `TransferFollowsPublish`: a fill admitted after the drain's publish leaves its INSERT above the cut at the transfer. |
| `mutant-transfer-before-certify-reports-damage` | Breaks `HandoffCutIsExact`: X resurrects under a damage report with no damaged block. |
| `mutant-handoff-damage-unreported` | Breaks `HandoffCutIsExact`: a fault damages X's REMOVE after the transfer and the recovery reports no damage. |

The model states and does not establish END, DURABLE and NEW-EXCLUSION, as
the preservation model does. The model's atomic publish captures and
publishes in one step and its pass splits the snapshot from the publication,
its removals are all recorded, its blocks hold one record each, its pending blocks land in any order and it has no slots, so
block packing, sequence continuity, the record codec, the slot half of the
one-owner rule, the admission bounds and the damage-or-tail classification of
a hole after a valid block are checked by the Rust tests of
`storage::recovery::delta`, `delta_replay` and `suffix`. A released payload
unit is held until its tombstone's block completes and is then reusable by
the same tenure; the model has no quarantine for a stale payload attempt, so
that rule rests on the preservation model's barrier and on the record format's
identity check at the hit. Unlike the preservation model, journal blocks may
be damaged here: a damaged certified tombstone resurrects its entry, which may
sit on a unit a later fill of its own level took; that entry's checked bytes
then fail the hit's identity check, a safe miss, and `RecoveredIntact` names
that one exception. The model's `recover` installs its load whatever the
damage, and the Rust `SuffixReport::installable` is false for a load with a
damage hole, so `Retained` and the `RecoveredIntact` exception describe the
entries a replay computes.

## Saturation model

[saturation.qnt](saturation.qnt) is the finite-resource accounting of one
shard's recovery history (P7): the LSNs of a delta region of `J = 2`
blocks and three checkpoint slots. Its log part holds the settled floor, the
tenure's first LSN, the head, the durable prefix, the reserved end, the
capacity, the count of recorded suffixes under a cap of two, and whether the
store records the tenure's suffix. Its slot part holds each slot's place in
the possibly named set (free, named, submitted, pending, reserved or
quarantined), the slot the store names, the slots a unit write of the tenure
reached, and the store's in-flight set: the sent Publishes that expect the
store's current version and so may still apply.

A tenure records its suffix, or is refused when the chain is at its cap. It
extends the reserved end within the capacity. An append seals one block at
the head, or is refused with no recorded suffix, at the reserved end, or with
the queue's one block awaiting durability. A settled Publish raises the floor
and the capacity, and a cut at or past the tenure's start drops every
predecessor suffix. A reservation takes a free slot, or is refused when none
is free. A unit write reaches the reserved slot. An abandoned stage and a slot
leaving the set at a settling success go to quarantine when a unit write of
the tenure reached them, and free otherwise; the Rust set also quarantines an
unexposed slot that leaves, except the slot named at the tenure's start, so the
model frees more slots than the Rust rule and its slot invariant covers it. A
Publish is submitted, recorded in the set before it is sent, and a submitted
Publish the client refused before sending leaves the set by the same rule. A
sent Publish is pending and enters the in-flight set; the store applies an
in-flight Publish whatever the set holds, and under the exact-version CAS that
commit empties the in-flight set. An acknowledged success settles the set to
the store's slot alone once no later Publish is in flight. The acknowledged
success of a later own write that names no new checkpoint, a suffix record,
extension or certification, settles the set the same way once no Publish is
recorded and unsent, and its committed version ends every Publish in flight;
the model takes that slot half as its own step beside the write's log half.
The recorded reserved end stays within the capacity, the lower of the floor
and the start plus `J`, which `reserve_suffix` enforces in Rust by refusing a
suffix ending past it. The
takeover starts the successor's suffix at the predecessor's reserved end with
nothing recorded, keeps the chain, and, under `END`, leaves the store's slot
named and every other slot free and unexposed.

| Property | Guarantee |
|---|---|
| `LogInductive` | `logInv` and the log part's typed domain, so a step that leaves the domain the inductive case starts from fails the case. `logInv`: start, durable prefix, head, reserved end and capacity are in order; the capacity is within `J` of the lower of the floor and the start; the blocks awaiting durability are within the queue; the chain is within its cap; a tenure with no recorded suffix has appended nothing. It implies that the required history and the tenure each span at most `J` blocks, so no two of their blocks share a unit (P7). |
| `SlotInductive` | `slotInv`: at most one named and one reserved slot; the store's slot is named or pending in the set; no slot a unit write of the tenure reached is free; every in-flight Publish is pending in the set. It implies the store's slot is never the reserved slot, the only slot a unit write targets (P7). |
| `WriteMissesNamed` | A unit write lands on a slot other than the one the store names. |
| `RefusalChangesNothing` | A refused suffix, append or reservation leaves both parts unchanged. The refusal actions assign both parts unchanged, so this holds by construction and records the model's refusal events rather than evidence for R9. |

### Inductive checks

`saturation-inductive-log` starts from every typed log state that satisfies
`logInv`, with LSNs 0 to 5 and a capacity up to 7, beside the initial slots,
takes one step and checks `LogInductive`: 3,862 distinct states. The start
draws cover head, durable prefix and reserved end up to 7, every value the
model reaches from `init`. `saturation-inductive-slots` starts from every typed
slot state that satisfies `slotInv` beside the initial log and checks
`SlotInductive`: 179,688 distinct states. TLC checks the invariant in the start states too, so each case also
checks that the invariant implies its P7 property over the typed domain. The
two cases cover the conjunction because every action reads and writes one
part: a log step leaves the slots as they were and reads none of them, a slot
step does the same for the log, and the takeover's log half reads the log and
its slot half reads the slots. These are checks over the typed domain at the
stated constants. A closure argument for larger regions, slot counts and LSNs
is not mechanized. A settled Publish raises the floor as a log action that
reads no slot, so the model takes the floor's settlement as given; the Rust
rule `settled_floor`, which returns a floor only once the possibly named set
holds the committed checkpoint alone, and its test
`an_unknown_publish_keeps_the_floor_unsettled` check that coupling, and the
`prefixSaturation` projection of [Cross-model joins](#cross-model-joins)
checks it against the prefix model's Publishes and Confirms at finite bounds.

### Cases

[saturation_check.py](saturation_check.py) declares 26 cases.
`saturation-safety` checks `safety` from the initial state at `BOUND = 8`:
38,984 distinct states. Twelve reachability witnesses are each checked as the
inverted invariant: the chain, queue, reserved-end and slot refusals, a
Publish that clears a full chain, an append past the region's first lap, a
quarantined slot, a settling success, a takeover with a named slot, a unit
write while the store names a slot (the antecedent of `WriteMissesNamed`), a
submitted Publish abandoned before sending, and a later own write's success
that ends a Publish in flight.
Each mutant replaces model text and must break its part's invariant one step
after a start state of the inductive case.

| Mutant | Breaks |
|---|---|
| `grace-release` | `SlotInductive`: a quarantined slot goes free with no barrier. |
| `abandon-frees-pending` | `SlotInductive`: a submitted Publish refused before sending frees its slot although a unit write reached it. |
| `abandon-unknown` | `SlotInductive`: a sent Publish whose outcome is unknown is abandoned as refused before sending while the store may still apply it. |
| `left-frees-exposed` | `SlotInductive`: a slot leaving the set goes free although a unit write reached it. |
| `reserve-pending` | `SlotInductive`: a reservation takes a possibly named slot. |
| `wrap-before-floor` | `LogInductive`: a successor's capacity ignores the required history below its start. |
| `chain-uncapped` | `LogInductive`: a suffix is recorded past the chain's cap. |
| `queue-uncapped` | `LogInductive`: an append is acknowledged with the queue at its bound. |
| `append-past-reserved` | `LogInductive`: an append is acknowledged at the recorded reserved end. |
| `extend-past-capacity` | `LogInductive`: an extension records an end past the capacity. |

The model counts blocks and slots and carries no record, payload or replay;
the suffix and preservation models check those. It states and does not
establish `END`. No refinement maps its counts to the appender, the possibly
named set or the store record: the Rust tests of `storage::checkpoint`,
`storage::recovery::suffix` and `storage::recovery::capture` check those
bounds, and the record `recovery-history-saturation-witnesses` lists them.

## Cross-model joins

Issue #122 asks for the cross-model safety obligations that the single-model
cases leave as assumptions, at three interfaces. [joins.qnt](joins.qnt)
checks each with one composed projection, and the coverage map below names,
for every part of each interface, the exact existing case that checks it at
the same interleaving abstraction or the join case that does. The
single-model cases stay authoritative for their own models. Each join's
`safety` keeps both source models' `safety` under the joint scheduler, and
its own invariants state only the interface between them; none restates a
stand-alone invariant under another name, and no join mutant carries the
mutation list of a registered mutant
([test-quint-check.py](../scripts/test-quint-check.py) checks the mutation
lists, and checks the prefix-saturation floor rule against the prefix
model's text).

A projection module imports two source models as instances (`import
capture(BOUND = BOUND) as C from "./capture"`). Each joint step is one
source action with every variable of the other model unchanged, or one
action of each model taken together; the projection adds a ghost map from
one model's state to the other's and its joint invariants, and its `safety`
is both source models' `safety` with those invariants. `turn` counts joint
steps to `BOUND`, and each source model counts its own actions against the
same `BOUND`, which never binds first. A violation of a join case is a
violation of the composed system; a pass covers every joint schedule from
the projection's prefix root up to its bound and says nothing about
schedules the joint scheduler leaves out.

[join_check.py](join_check.py) declares each projection's source models,
reductions, prefix, bound, witnesses and mutants, and `projection_cases` in
[check.py](check.py) expands each into cases:

- `join-<name>-safety` checks `safety` in every state of every joint
  schedule from the prefix up to `BOUND` and passes only at depth
  `BOUND + 1` with an empty queue.
- `join-<name>-reach-<witness>` must reach the witness, checked as the
  inverted invariant, in a state after the prefix. Every witness holds at a
  recovery, a refusal, a learned success or an append past a settled floor,
  not at the root.
- `join-<name>-mutant-<mutant>` replaces text of the projection module and
  must break its named joint invariant after the prefix, within `BOUND + 1`
  states, with states labelled 1 to N in order.

`join-typecheck` typechecks the three modules beside the six source models.

### Coverage map

| Interface part | Checked by | Abstraction |
|---|---|---|
| 1. A multi-step capture's checkpoint equals its `t0` snapshot under removals before and after the cursor | `capture-safety`, `cxT1`, `capture-mutant-CaptureConsistent`, `capture-mutant-CaptureConsistent-cursor` | capture alone |
| 1. A pass's cut is sealed at its start, published after recorded removals, and its replay excludes the removed member | `suffix-run-publishAfterRecordedRemoval`, `suffix-mutant-cut-at-publish` | suffix alone, atomic snapshot |
| 1. A removed entry's unit stays held until its REMOVE's block is durable | `suffix-run-tombLost`, `suffix-mutant-release-before-durable` | suffix alone, no allocator |
| 1. The published cut's membership is the multi-step capture's checkpoint, and the allocator frees no unit the suffix holds | `join-capture-suffix-safety` (`CutIsCapture`, `AllocatorHonorsHold`), mutants `release-ignores-hold`, `pass-published-at-completion` | new: capture with suffix |
| 1. A recovery from the pass's cut loads every eligible member of S, with abort, refusal and host loss between the boundaries | `join-capture-suffix-safety` (`CheckpointRecovered`); reach `witnessSavedExcluded`, `witnessSavedKept`, `witnessReuseAfterDurable`, `witnessLostMidPass`, `witnessAbandonedRecovered`, `witnessRefusedInPass` | new: capture with suffix |
| 2. Page CAS monotonicity, fencing, carry-forward and refusal of covered FILLs | `coverage-safety`, `coverage-run-ackBeforeSuccessorFence`, `coverage-run-successorFenceBeforeCover`, `coverage-run-carryAfterConfirm`, `coverage-run-successorRefusesAckedFill` | coverage alone; not rechecked |
| 2. Recovery excludes an acknowledged invalidation it reads from the ghost set `acked` | `preserve-safety` (`NoResurrection`, `eligibleIn`) | preservation alone, atomic invalidation |
| 2. Every invalidation exclusion recovery applies is covered by the successor's fenced coverage and no acknowledged INVALIDATE is reinstated, across CAS commit, failed condition, lost reply and timeout; recovery loads key 1's entry, which no INVALIDATE targets, and key 0's entry when its INVALIDATE failed its condition or committed without an acknowledgment | `join-coverage-preserve-safety` (`ExclusionCovered`, `InvalidationNotReinstated`, preservation's `LossIsFaultLocal` and `Retained`); reach `witnessAckedExcludedRetained`, `witnessSuccessorRefusesAcked`, `witnessFailedCasRetained`, `witnessLostReplyRetained`; mutants `recover-before-page-fence`, `exclusion-at-submission` | new: coverage with preservation |
| 3. The possibly named set under exact-version Publishes and Confirms, unknown outcomes, shrink and slot quarantine | `prefix-safety`, `prefix-run-cxA2f`, `prefix-run-confirmExact`, `prefix-mutant-shrink-ignores-later`, `prefix-mutant-timeout-frees-slot` | prefix alone |
| 3. Payload, row and tombstone-block quarantine, barrier-gated reuse, release of rows and of tombstone blocks below the new cut only at a settling acknowledgment, and one owner per unit | `preserve-safety` (`Partition`, `FreeUnexposed`, `CutsOwned`), `preserve-run-releaseReuse`, `preserve-run-journalWrap`, `preserve-mutant-release-named-rows`, `preserve-mutant-shrink-drops-named`, `preserve-mutant-reuse-after-grace` | preservation, Publish-only shrink: cited, discharged at that abstraction |
| 3. One owner per recovered unit and key in a replay | `suffix-OneOwner`, `suffix-mutant-blind-skip` | suffix alone: cited |
| 3. Log and slot accounting within their typed domains | `saturation-inductive-log`, `saturation-inductive-slots` | saturation, each part alone |
| 3. The floor rises only at a success that settles the set, so no block at or above a cut the store names or may still commit is reused, with Confirms and unknown outcomes | `join-prefix-saturation-safety` (`FloorBelowReachable`, `ReachableHistoryIntact`, prefix's `NoStaleLoad`); reach `witnessReuseAfterSettle`, `witnessConfirmSettles`, `witnessPendingKeepsFloor`, `witnessUnknownNamedRecovered`; mutants `floor-on-unknown-outcome`, `floor-at-capture` | new: prefix with saturation's log |

Records: `join-capture-cut-durable-suffix-model`,
`join-coverage-ack-recovered-membership-model` and
`join-named-slots-settled-floor-reuse-model`.

### Reduction maps

`captureSuffix` (capture.qnt as `C`, suffix.qnt as `S`):

| Joint step | Source actions | Other model |
|---|---|---|
| `bind(s, u)` | `C::bind(s, u)` | `S` unchanged |
| `publish(s)` | `C::publish(s)` and `S::fill(s + 1, u, false)`; `idOf` maps the entry's id to the INSERT's | |
| `remove(s)` | `C::remove(s)` and `S::evict(r)` of key `s + 1` | |
| `release(s)` | `C::release(s)` once `S::held` lacks the entry's unit | `S` unchanged |
| `start`, `complete` | `C::start` and `S::startPass`; `C::complete` and `S::publishPass` | |
| `scan` | `C::scan` | `S` unchanged |
| `seal`, `land`, `blockDone`, `certify`, `extend`, `lose`, `recover` | `S::seal`, `S::land(b)`, `S::complete(b)`, `S::certify`, `S::extend`, `S::lose`, `S::recover` | `C` unchanged |
| `refusedPublish`, `refusedRemove` | `S::fill` or `S::evict` at its refusal | `C` unchanged |

State map: capture slot `s` is suffix key `s + 1`; capture units 1 and 2 are
the suffix's units; `LiveAgrees` checks the live sets agree while the
capturing tenure serves. Reductions: the capture side list holds one entry
(`CAP = 1`, a text replacement of the capture copy), so the second saved
member abandons the pass; one pass and one host loss run; fills write one
block each, and replacements, damage, split records and capture
passes of the suffix model alone stay with its cases; the capture model's
own crash and load are unused, since the suffix's recovery is the
successor's.

`coveragePreserve` (coverage.qnt as `C` at `TENURES = 2`, `FENCED_FIRST`;
preserve.qnt as `P`):

| Joint step | Source actions | Other model |
|---|---|---|
| `invalidate(0)` | `C::invalidate(t, 1, 1)` by the issuing tenure | `P` unchanged |
| `apply(i)`, `timeout(i)`, `reply(i)` | `C::applyId(i)`, `C::timeoutId(i)`, `C::replyId(i)` | `P` unchanged |
| `reply(i)` of a committed coverage write | `C::replyId(i)` and `P::drop(k, "invalidate")` | |
| `pageFence(p)`, `reread(p)` | `C::fence(2, p)`, `C::reread(t, p)` while the tenure's host runs | `P` unchanged |
| `fill(k)` | `C::fill(t, k + 1, 1)` and `P::fill(k)` when coverage admits it; `C::fill` alone when it refuses | |
| `capture`, `publish`, `settle`, `lose`, `takeover`, `fence`, `recover` | `P::capture`, `P::applyPub`, `P::ackPub`, `P::lose`, `P::takeover`, `P::fence`, `P::recover` once tenure 2 fenced every page | `C` unchanged |

State map: preservation key `k` is coverage key `k + 1` at version 1 on page
`k`; preservation tenure `t` is coverage tenure `t`; tenure 1's host runs
while it issues commands, deposed between the takeover and the lineage fence
included, and tenure 2's from its takeover on. `AcksAgree` checks that the
acknowledged sets agree. Reductions: only key 0 is invalidated; one takeover;
attempt landings, barriers, eviction, expiry, store rollback, damage, size
rejection and the saturated rewrite stay with each model's own cases; an
entry leaves preservation's live set at its acknowledgment while coverage
evicts it at submission; recovery is preservation's and takes its
invalidation exclusions from `acked`, the acknowledged INVALIDATEs, alone.

`prefixSaturation` (prefix.qnt as `P`, saturation.qnt as `S`):

| Joint step | Source actions | Other model |
|---|---|---|
| `capture` | `P::capture(1)`; `cutOf` records `S::log.head` as its cut | `S` unchanged |
| `succeed` | `P::succeed(p)`, and `S::publish(cutOf(p.capture))` exactly when `settles(p)`, prefix's `newest` and `shrink` | |
| `apply`, `unresolved`, `read`, `confirm`, `stale` | `P::apply(p)`, `P::unresolved(p)`, `P::read`, `P::confirm`, `P::stale(w)` | `S` unchanged |
| `recordSuffix`, `extend`, `appendBlock`, `written` | `S::recordSuffix(r)`, `S::extend(e)`, `S::appendBlock`, `S::written` | `P` unchanged |
| `takeover` | `S::takeover` and `P::recover` | |

State map: capture 0 is the record's initial capture at cut 0; the cuts the
store names or may still commit are the named capture's and, before the
takeover, those of writes in flight at the record's version. Reductions:
captures carry one entry; saturation's slot part stays at its initial value,
since prefix holds the slots; the takeover's version bump ends every Publish
in flight, and prefix takes no step after it.

### Bounds, states and seconds

| Case | Root | `BOUND` | After the root | Distinct states | Depth | Seconds |
|---|---|---|---|---|---|---|
| `join-capture-suffix-safety` | two entries, their INSERT blocks durable (8 steps) | 24 | 16 | 241,513 | 25 | 29.9 |
| `join-coverage-preserve-safety` | both keys filled under tenure 1's fenced coverage, captured, published and settled: S = {1, 2} (5 steps) | 19 | 14 | 5,850,722 | 20 | 149.6 |
| `join-prefix-saturation-safety` | the initial state | 11 | 11 | 8,031,786 | 12 | 79.4 |

Steps of each reach and mutant trace, the states after the initial one, from
one run at eight TLC workers at revision 0a296d414; a parallel search need
not return the shortest trace, and trace lengths vary between runs.
`witnessLostReplyRetained` gained its coverage and key 1 conjuncts after that
run, and its count is from a run of that text:

| Projection | Witnesses (steps) | Mutants (property, steps) |
|---|---|---|
| capture-suffix | `witnessSavedExcluded` (18), `witnessSavedKept` (16), `witnessReuseAfterDurable` (24), `witnessLostMidPass` (11), `witnessAbandonedRecovered` (15), `witnessRefusedInPass` (12) | `release-ignores-hold` (`AllocatorHonorsHold`, 10), `pass-published-at-completion` (`CutIsCapture`, 15) |
| coverage-preserve | `witnessAckedExcludedRetained` (18), `witnessSuccessorRefusesAcked` (19), `witnessFailedCasRetained` (18), `witnessLostReplyRetained` (18) | `recover-before-page-fence` (`ExclusionCovered`, 12), `exclusion-at-submission` (`ExclusionCovered`, 16) |
| prefix-saturation | `witnessReuseAfterSettle` (8), `witnessConfirmSettles` (8), `witnessPendingKeepsFloor` (4), `witnessUnknownNamedRecovered` (5) | `floor-on-unknown-outcome` (`ReachableHistoryIntact`, 7), `floor-at-capture` (`ReachableHistoryIntact`, 6) |

The 23 TLC join cases and `join-typecheck` took 544 seconds at eight
workers on a shared development workstation, one case at a time; these are
not lane measurements.

### What the joins establish

These are exhaustive finite-bound checks of each projection at the stated
constants, bounds and reductions. None is an inductive, parameterized or
refinement proof, and none checks the Rust implementation or the EBS
contract. The saturation inductive cases check finite typed domains and
establish no closure for arbitrary slot counts, region sizes or LSNs, and no
join case adds one. The capture-suffix and coverage-preserve projections
assume `END`, DURABLE and NEW-EXCLUSION as their source models do, and the
coverage-preserve projection rests on the preservation model's lineage fence
and durable registrant set; their retained-S witnesses load a nonempty
eligible set under those premises, so P4 and R2 positive retention stays
conditional on the `END` and NEW-EXCLUSION provider and lineage-fence
premises #148 holds, and `preserve-p4-retention-proposed` keeps that credit
blocked. A warm miss, an empty recovered set or a cold replacement satisfies
no retained-S witness here: each requires a nonempty recovered set.

The coverage-preserve projection checks that the recovering tenure's fenced
coverage covers every invalidation recovery excludes (`ExclusionCovered`). It
checks no exclusion derived from that coverage. `witnessLostReplyRetained`
reaches a recovery that loads key 1's entry beside key 0's entry, whose
INVALIDATE committed its page write while the reply timed out, with key 0's
entry covered by the recovering tenure's fenced coverage. Key 0's entry is in
the model's S, which excludes acknowledged invalidations only. The Rust warm
load omits an entry its tenure's fenced coverage covers
(`storage::volume::warm`, RETAINED-OR-REFUSED), and `oracle::preserved` judges
an entry that only an unknown outcome removes Inconclusive. So key 1's load
is the retention the witness shows, and key 0's load is a model outcome the
Rust load does not produce: an implementation replay of this case (#136)
differs from the model at that entry, and the projection leaves open whether
a committed, unacknowledged INVALIDATE removes its entry from S.

## Key-operation model

[keyops.qnt](keyops.qnt) models one key of a live storage: its fill attempts,
its resident mapping, the rights that name its slots and the unit ledger,
over `UNITS` one-unit slots and a fill table of two records. `begin` grants
an attempt, `reserve` claims a free slot for it, `receive` submits the
record's one write and `writeDone` delivers that write's terminal. `publish`
makes the slot resident under a deadline, returns the object's first lease
and retires an incumbent; a refused publication consumes its fill, and
`abort` ends a fill. `lookup` answers `Hit` with a lease, `Missing`,
`Expired` at or past the deadline, or `RetainLimit` once the object holds
`RIGHTS = 2` leases, and `release` returns a lease. `invalidate` ends the
mapping and revokes the key's current attempt. `expire` removes an unleased
resident at or past its deadline and `evict` an unleased resident while no
attempt is current. A slot whose fill or mapping ended is retired: it stays
held, with its anchor and its rights, until `certify` covers the anchor and
`service` observes the slot's count at zero and returns it. `serviceFills`
frees departed fill records, `close` shuts admission, `closeService` is the
bounded cleanup after it, and `tick` advances the clock one second.

The simulator judges histories against the reference in
`crates/kestrike/src/oracle/key_model.rs`, which states the labels a key
may serve. This model states the slot, fill-table, right and ledger
transitions those rows come from, and its committed traces are replayed
against `Storage` and fed to that oracle as rows.

| Property | Guarantee | Stated in |
|---|---|---|
| `HitIsLive` | A hit returns a label a publication published whose visibility no invalidation, replacement, expiry, eviction or close sweep ended. | The oracle's rules for a hit of a version no fill published, one an acknowledged invalidation covered and one after its recorded removal. |
| `NoServeAtDeadline` | No lookup and no publication hands out a lease at or after the object's deadline. | `storage::slot` documentation of `expires_at_s`; the oracle's rules for a hit and a publication at or past the deadline. |
| `ExpiredIsLapsed` | A lookup answers `Expired` only for a resident at or past its deadline. | The oracle's rule for `Expired` without a published label past its deadline. |
| `PublishComplete` | A fill publishes only after its write's successful terminal released the write right. | PUBLISH-COMPLETE in the `storage` module documentation; #8 P-E-141. |
| `RevokedNeverPublishes` | No attempt an invalidation revoked publishes. | REVOKE; #8 P-E-142. |
| `ReuseAtZero` | A slot returns only at a count of zero, its anchor released after a certification. | REUSE; blotter issue 901 `mc-event-derived-return-oracle`; #19 ebs-cache-n-07. |
| `EvictNoReuse` | Every lease and write right names a held slot at the incarnation it was taken on. | EVICT-NO-REUSE; blotter issue 651 EBS4-E-08. |
| `RejectOwnsNothing` | A refused grant, reservation, receive, lookup or invalidation leaves every slot, the ledger and every right as they were. | REJECT-OWNS-NOTHING; #8 P-E-138. |
| `RefusalKeepsIncumbent` | A refused publication leaves the incumbent's mapping and record as they were. | #19 ebs-cache-n-04; the incident histories' rule for a rejected upload that erased the incumbent. |
| `OneMapping` | The key has at most one resident mapping. | The stopped-boundary observer's rule for two bindings that route one fingerprint. |
| `OneAttempt` | The key has at most one current attempt, and the table holds at most two records. | `storage::attempt` module documentation. |
| `UnitsConserved` | The free, reserved, resident and retired ledger terms equal the slot census and sum to the unit count. | #2 P-N-15. |
| `RemovalLegal` | An expiry removes only an unleased resident at or past its deadline, and an eviction only an unleased resident while no undeparted attempt is current. | `storage::expire` and `storage::evict` module documentation; the oracle's rules for an expiry before the deadline and an eviction while a fill is current. |
| `ClosedAdmitsNothing` | After close no grant, reservation, receive, publication, hit or invalidation is acknowledged. | The `storage` module documentation of close; the oracle's rules for each operation after the cache closed. |

[keyops_check.py](keyops_check.py) declares 72 cases. Every trace issues at
most `SERIALS = 4` attempts and advances the clock at most `MAXT = 2`
seconds. `keyops-safety` checks `safety`, the conjunction of the fourteen
properties, under the free scheduler at `BOUND = 16` over `UNITS = 3`, and
`keyops-safety-two-units` at `BOUND = 16` over `UNITS = 2`; each property
alone runs at `BOUND = 12` over three units. Seventeen reachability
witnesses, each the inverted invariant `not(<witness>)` at `BOUND = 12`,
show the free scheduler reaches a hit, an expired lookup, a replacement of a
leased incumbent, an invalidation that ends the mapping and revokes the
key's current attempt, a publication refused `Superseded`, `Incomplete` and
`Expired`, an expiry removal, an eviction, an eviction refused `Replacing`,
a service visit that finds a retired slot held by a lease, a write terminal
on a retired slot, a grant refused `InProgress` and `FillSlotsFull`, a
lookup refused `RetainLimit`, a refusal after close and, at two units, a
reservation refused `CleanReserve`. Each run below is a recipe at two units
checked with `safety` and its outcome, with `BOUND` the recipe's length,
beside a reach case that shows the recipe ends in a state holding the
outcome. Each mutant replaces model text and must break its property first
at the last step of its recipe. These are finite checks at the stated
bounds.

| Case | Outcome |
|---|---|
| `run-expiry` | A lookup is refused at the right limit; the deadline passes, a lookup answers `Expired`, the sweep waits for the last lease and then removes the object; service returns the unit after a certification, and a second fill reuses it and is hit. |
| `run-replace` | An eviction finds the leased incumbent held while its replacement uploads; the publication replaces the incumbent under its publisher's lease, which holds the retired unit through a service visit, so a third fill finds no unit; the unit returns once the lease is released. |
| `run-revoke` | An invalidation ends the mapping and revokes the attempt uploading beside it; the table refuses a third record until fill service frees a departed one, and the revoked fill's publication is refused. |
| `run-refuse` | An invalidation revokes an attempt before its receive, which is refused, and the abort returns the unit at once; a failed write leaves the next fill unpublishable, and its record stays the key's attempt until fill service frees it. |
| `run-abandon` | An aborted fill's outstanding write holds its unit past a service visit and past the next publication; its late terminal lets service return the unit. |
| `run-evict` | An eviction is refused while an attempt is current; that attempt's publication past its deadline is refused and the incumbent keeps serving; the eviction then removes the unleased incumbent, and after a close a reservation is refused. |
| `run-close` | Close refuses a receive, a grant, a lookup and an invalidation, and the publication of the fill whose receive it refused is refused `Incomplete`; the held leases stay valid, and two close-service calls return every unit. |
| `run-shut` | A written fill's publication after close is refused and close service returns its unit. |

| Mutant | Breaks |
|---|---|
| `invalidate-keeps-mapping` | `HitIsLive`: an invalidation that records the end and keeps the mapping lets the next lookup hit the ended label. |
| `lookup-serves-at-deadline` | `NoServeAtDeadline`: a lookup serves at the deadline's second. |
| `publish-at-deadline` | `NoServeAtDeadline`: a publication is admitted at its deadline's second. |
| `expired-early` | `ExpiredIsLapsed`: a lookup answers `Expired` one second early. |
| `publish-before-terminal` | `PublishComplete`: a publication only requires the write submitted. |
| `publish-after-failure` | `PublishComplete`: a publication accepts a failed write. |
| `publish-ignores-revocation` | `RevokedNeverPublishes`: a publication ignores its attempt's revocation. |
| `service-ignores-count` | `ReuseAtZero`: a service visit returns a slot whatever its count. |
| `service-skips-grace` | `ReuseAtZero`: a service visit releases an anchor no certification covered. |
| `replace-frees-incumbent` | `EvictNoReuse`: a replacement returns the incumbent's unit at once, under its lease. |
| `abort-cancels-written` | `EvictNoReuse`: an abort returns a unit whose write is outstanding. |
| `refused-reserve-keeps-slot` | `RejectOwnsNothing`: a reservation refused `Superseded` keeps the slot it claimed. |
| `refused-receive-submits` | `RejectOwnsNothing`: a receive refused `Revoked` still submits its write. |
| `refused-publish-displaces` | `RefusalKeepsIncumbent`: a publication refused past its deadline still displaces the incumbent. |
| `publish-keeps-incumbent` | `OneMapping`: a publication leaves the incumbent mapped. |
| `begin-ignores-current` | `OneAttempt`: a grant ignores the key's current attempt. |
| `return-skips-ledger` | `UnitsConserved`: a return leaves the ledger as it was. |
| `expire-ignores-deadline` | `RemovalLegal`: the expiry sweep ignores the deadline. |
| `expire-removes-leased` | `RemovalLegal`: the expiry sweep removes a leased object. |
| `evict-ignores-attempt` | `RemovalLegal`: an eviction ignores the key's current attempt. |
| `lookup-ignores-close` | `ClosedAdmitsNothing`: a lookup ignores the close. |

`crates/kestrike/src/storage/keyops_fixtures` holds the eight runs'
traces, each with its recipe and the model's SHA-256.
`crates/kestrike/src/storage/keyops_replay_tests.rs` drives a `Storage`
of two one-unit slots, two fill records and two rights per object through
every recorded action and compares, after each one, the action's typed
result, each slot's state and count, the slot ledger and the raw ledger, the
occupied fill records, the shard's visible key count and the admission
cutoff with the trace's state. It refuses a fixture whose digest differs from
the model's, whose length differs from its recipe's or whose action differs
from its recipe's, and an altered result, slot, ledger, fill table or cutoff
fails at the action it changes. The same traces become history rows, which
the history oracle must pass with its History obligation activated; four
altered traces fail it by the key model's rule. The `keyops-replay` case
regenerates the traces, requires their states to equal the fixtures' and
replays them. The replay shows agreement on these eight schedules; it is no
refinement proof.

The model holds one key, one shard and one write per fill, and its slots
hold one unit each, so `CleanReserve` stands for every space refusal
(`CleanReserve`, `ObjectSlotsFull`, `PayloadFull`). These stay outside it,
each with the Rust tests that check it: fill joins and their followers
(`storage::join_tests`), fingerprint collisions (`storage::publish_tests`,
`storage::lookup_tests`), multi-extent objects and the builder escrow
(`storage::builder_tests`, the `escrow_model` loom kernel), the retired-unit
limit and work budgets (`storage::reserve`, `storage::maintain_tests`), the
lease credit limit (`storage::lookup_tests`, the `credit_model` loom
kernel), recovery (`storage::recovery`) and device faults
(`storage::media_fault_tests`, `storage::lease_fault_tests`). A refused
reservation or publication consumes its fill in the model, as the consuming
Rust calls do. Grace is one flag per retired slot that `certify` sets; the
`grace_model` loom kernel and `storage::grace_tests` check the era protocol
behind it. Every action is one atomic step. The interleavings inside one
operation are the subject of the `fill_model`, `publication_model` and
`lookup_model` loom kernels.

`crates/kestrike/src/net/world_tests/histories/keyops.rs` holds a
scripted simulator history for each witness that no earlier profile or
history reached: the three refused publications, an eviction beside a
current fill, a second fill of a key in progress, a reservation while both
slots of a two-slot storage are held, the refusals and the drain after
close, and a lookup at the right limit, each with a passing sibling and a
control.

## Binder model

[binder.qnt](binder.qnt) models two binders, 0 and 1, that bind and release
an NVMe controller, device 0, and an ENI, device 1. Each binder owns one
state directory with one record. A step is one action of one binder:

- A bind takes its owner lock (`bindOwner`), runs its first checks
  (`bindPreflight`), takes each requested device's lock (`bindDeviceLock`),
  consults the other owner's record (`consultRecords`), resolves the ENI's
  next hops (`resolveHops`) and writes its record (`publish`). For each
  device it then repeats the capture (`secondCapture`) and writes
  `driver_override`, `unbind` and the `vfio-pci` bind (`setOverride`,
  `unbind`, `vfioBind`), and returns (`bindReturn`).
- A refused second capture or driver write rolls back the devices the bind
  wrote an override for, under the locks it holds: up to four driver writes
  for each (`rollbackUnbind`, `rollbackOverride`, `rollbackBind`,
  `rollbackOriginalOverride`), the ENI's four network commands
  (`rollbackNetworkBatch`), the record's removal (`unlink`) and the return
  (`rollbackReturn`).
- A release takes its owner lock (`releaseOwner`), reads its record
  (`readRecord`), takes each recorded device's lock (`releaseDeviceLock`),
  consults the other owner's record (`releaseConsult`) and opens the group
  guard of each recorded device on `vfio-pci` (`groupGuard`) before its
  first write. It restores each device with up to four driver writes
  (`restoreUnbind`, `restoreOverride`, `restoreBind`,
  `restoreOriginalOverride`), runs the four network commands
  (`networkBatch`), removes its record (`unlink`) and returns
  (`releaseReturn`). A restore or rollback of a device starts at the write
  its driver state needs.
- `crash` kills a binder between two steps, at any step after its owner
  lock. `liveOwnerRefusal` is a second call for an owner whose lock a live
  call holds.

The failure model is a `SIGKILL` of the binder's process while the kernel
stays up: every completed record, sysfs and network write stays, and every
lock and guard descriptor closes. What a process keeps of its own call ends
with the call, on a return and on a kill: its request, the devices its bind
moved, its count modulo four of network commands and the names and writes of
its release are empty outside a call. A fresh release recovers a surviving
record. Record and sysfs writes are atomic steps; the record's own write
steps are the subject of `bind::cut_tests`.

`LOCK_GAP` frees a binder's device locks after its consultation, and
`COOPERATING` holds each pair `(a, b)` in which binder `a` consults binder
`b`'s record. The checked instance holds the locks through the move and has
both binders consult each other.

| Property | Guarantee |
|---|---|
| `RecordBeforeDriverExit` | A device is off its kernel driver only while a present record names it. |
| `OneLiveRecordPerVfioDevice` | A device on `vfio-pci` is named by exactly one present record. |
| `ReleaseRestoresOwnRecordOnly` | Every restore write of a release names a device that the release's own raw record decodes to. |

[binder_check.py](binder_check.py) declares 67 cases. `binder-safety` checks
`safety`, the conjunction of the three properties, under the free
scheduler: every action of either binder over every input, with no bound on
the number of steps. The search is exhaustive for this instance: 152,323
distinct states at depth 47, in 9 seconds with eight workers on a shared
128-core development host and in 33 CPU seconds under a four-CPU quota, the
limit of the CI runner service. Two binders are the fewest that reach
contention and a record of another owner; the controller and the ENI are the
fewest devices that reach the per-device driver sequence and the network
commands.
Forty-five reach cases, each the inverted invariant of one action or one
outcome, show the free scheduler takes each of the 31 actions and reaches
each of the 14 outcomes. `binder-campaign` checks `safety` along the
225-action campaign the replay runs and requires its last action.

`binder-rollback-only-moved` checks `RollbackOnlyMoved` over the same instance
under the free scheduler: a binder at a rollback write of a device, or at the
rollback's network commands, moved that device, and a rollback reaches its
record's removal and its return only with every device it moved back on its
kernel driver with the override as found and, for the ENI, the four network
values restored. Two witnesses show the states it reads are reached:
`binder-reach-rollback-of-both`, a failed bind that moved both devices at its
record's removal after its network commands, and
`binder-reach-rollback-of-the-controller-alone`, a failed bind of both
devices that moved the controller alone at its record's removal.

`binder-unlink-only-after-restores` checks `UnlinkOnlyAfterRestores` over the
same instance under the free scheduler: a release is at its record's removal
only with every device its raw record names back on its kernel driver with
the override as found and, when the record names the ENI, the four network
values restored. Two witnesses show that state is reached:
`binder-reach-guarded-unlink`, a release that took both group guards, and
`binder-reach-unlink-with-nothing-to-unbind`, a release of a record of both
devices that took no guard, as after a killed release or a bind killed before
its first driver write.

| Mutant | Breaks |
|---|---|
| `lock-gap` | `OneLiveRecordPerVfioDevice`: with `LOCK_GAP` set, both binders consult before either writes its record, and both records name the controller when it reaches `vfio-pci`. |
| `one-way` | `OneLiveRecordPerVfioDevice`: with binder 1 consulting no record, binder 1 records and moves the controller beside the record a killed binder 0 left. |
| `unrecorded-move` | `RecordBeforeDriverExit`: a record write that leaves the record absent lets the unbind take the device off its driver unrecorded. |
| `release-ignores-record` | `ReleaseRestoresOwnRecordOnly`: a release that restores both devices, whatever its record names, writes a device outside a one-device record. |
| `rollback-follows-request` | `RollbackOnlyMoved`: a rollback that goes on from the controller to the ENI whenever the bind requested the ENI reaches the ENI's rollback writes for a bind that moved the controller alone. |
| `rollback-skips-network` | `RollbackOnlyMoved`: a rollback that goes from its last driver write to its record's removal reaches the removal with the ENI's four network values unrestored. |
| `rollback-always-runs-network` | `RollbackOnlyMoved`: a rollback that runs the network commands whatever it moved reaches them for a bind that moved the controller alone. |
| `rollback-keeps-override` | `RollbackOnlyMoved`: a rollback whose last driver write leaves the override reaches its record's removal with a moved device's override still set. |
| `rollback-skips-rebind` | `RollbackOnlyMoved`: a rollback whose bind write leaves the device driverless reaches its record's removal with a moved device off its kernel driver. |
| `release-skips-network` | `UnlinkOnlyAfterRestores`: a release that goes from its last driver write to its record's removal reaches the removal with the ENI's four network values unrestored. |
| `release-keeps-override` | `UnlinkOnlyAfterRestores`: a release whose last driver write leaves the override reaches its record's removal with a recorded device's override still set. |
| `release-skips-rebind` | `UnlinkOnlyAfterRestores`: a release whose bind write leaves the device driverless reaches its record's removal with a recorded device off its kernel driver. |

`crates/kestrike/src/bind/replay_fixtures` holds two traces, each with its
recipe and the model's SHA-256: `campaign`, and `lock_gap_prefix`, the seven
actions that lead the lock-gap violation up to the second binder's device
lock, which the instance with the lock held refuses.
`crates/kestrike/src/bind/replay_tests.rs` runs each bind and release of a
trace as the real `Binder` in a fresh child process over one fixture tree.
`crates/kestrike/src/bind/checkpoint.rs` names the binder's steps, and a
supervised child stops before and after each one, and around every driver
write and every restoring network command of its fake kernel. The replay
requires the child's next step to be the trace's next action of that binder,
on the action's device, with each network command the next of the restore's
four. `crash` sends `SIGKILL` to a child stopped after a step and confirms
the signal.

After every action, `init` included, the replay compares with the trace's
state:

- both owner locks' and both device locks' holders, read from the lock lines
  of each child's `/proc/<pid>/fdinfo`, with a nonblocking probe of each lock
  no child holds;
- each open group guard, by the descriptor the child reports, checked in
  `/proc/<pid>/fd`;
- each record's presence, the devices its raw lines name and the devices
  `Mappings::read` gives;
- every device's driver and override, and the ENI's network files;
- until a call ends, the devices its bind wrote an override for and the
  devices its release wrote, from the child's journal of kernel writes, with
  the devices the release's record named, and the count, modulo four, of
  network commands its restore ran;
- the outcome the action reported, empty for an action that reports none.

The model's step counter and request sets are its own bookkeeping and are
not compared; the order of the children's steps stands for them. After every
action each device on `vfio-pci` must also be named by exactly one owner's
readable record.

The campaign runs every action, reaches every outcome but a refused guard,
and kills a binder six times: under the controller's lock before its record,
after its record with both devices on their kernel drivers, after the first
network command of a release, with the controller driverless, with the
controller on `vfio-pci`, and binder 1 under the ENI's lock while the
controller is on `vfio-pci`. Binder 1 is refused at the controller's lock by
a live binder 0, at its first checks with the controller driverless and on
`vfio-pci`, and at its consultation by binder 0's surviving record. Fresh
releases restore the controller from driverless and from `vfio-pci` under
its group guard.

The replay refuses a fixture whose digest differs from the model's, whose
length differs from its recipe's or whose action differs from its recipe's.
An altered lock holder, driver, owner lock or outcome fails at the action it
changes, a trace that asks for the consultation where the binder's next step
is its device lock fails at that action, and a second owner's record of a
device on `vfio-pci` fails the census. The `binder-replay` case regenerates
the traces, requires the committed files to equal them and replays them. The
replay shows agreement on these two schedules; it is no refinement proof.

Outside the model: power loss, a third owner, a second ENI or volume, the
steps inside one record write, the content of the two captures, which a
`bindPreflight` or `secondCapture` input accepts or refuses whole, and the
kernel's handling of each write, which the replay's fixture stands in for.
The ENI's network state is one bit for each of its MTU, link state, address
and route and one for its resolved next hops.

## Fill authority model

[fill.qnt](fill.qnt) models the fill authority of one index shard, the record
word of `storage/fill.rs` and the grant, invalidation, departure and service
pass of `storage/attempt.rs` and `storage/remove.rs`. It restates the
properties the loom kernel `storage::fill_model` asserts and the invariant
of the obligation record `fill-record-departs-only-after-its-owner-ends`,
and claims nothing stronger.

The finite instance has two keys, a table of two records and a serial maximum
of 3 in place of `SERIAL_MAX`. A record is Free or carries the serial of the
attempt that occupies it, a departed flag and a revoked flag. `begin` refuses
`AttemptExhausted` once the next serial passes the maximum, `InProgress` while
an unrevoked record holds the key, departed or not, and `FillSlotsFull` with
no Free record; otherwise it writes the key and the next serial into the
lowest Free record and advances the serial. `revoke` is the invalidation: it
sets the revoked flag of the key's unrevoked record. `depart` is the owner's
last access: it sets the departed flag of the record that carries its serial.
`service` is a funded pass: it frees every departed record.

Abstractions:

- Each action is one atomic step, so the model holds the orders the shard
  gate and the departure's compare-exchange give and none of the orderings
  inside them. The `Release` and `Acquire` pairing of a departure and its
  observation stays with the loom kernel.
- Budgets, gate tries, the admission cutoff, the service cursor, an
  under-funded pass, shard custody, followers and the row's observer count,
  the index place refund and the fingerprint comparison are omitted. A pass
  therefore frees every departed record, where production retains one that
  custody names or a follower observes.
- `live` holds the serials whose owner has not departed. `issued` and
  `reissued` are history the invariants read; production keeps neither.

| Property | Guarantee |
|---|---|
| `OneCurrentPerKey` | No two unrevoked records hold one key. |
| `SerialIssuedOnce` | No serial is granted twice. |
| `SerialWithinMaximum` | Every granted serial lies in `1..=MAX`, so no grant follows the maximum. |
| `LiveOwnerKeepsRecord` | A record whose owner has not departed still carries its serial, undeparted: a live owner is never freed. |
| `DepartsAfterOwnerEnded` | A departed record's owner has ended. |
| `WellFormed` | An occupied record carries an issued serial, and a Free record no flag. |

[fill_check.py](fill_check.py) checks `safety`, the conjunction of the six,
with the free scheduler at `BOUND = 8` steps. Twelve reachability witnesses,
each checked as the inverted invariant `not(witness)`, reach every outcome of
every action: a grant, `InProgress` in any state and with every owner
departed,
`FillSlotsFull`, `AttemptExhausted`, a revocation and an invalidation that
finds no record, a departure plain and after a revocation, a pass that frees
and one that finds nothing, and a grant of a key whose revoked attempt is
still live, which takes the other record. `depart` has one more outcome,
`Ended`, for an owner whose record no longer carries its serial. It arises
only in a model whose pass or grant is changed, at every bound, because
`depart` is enabled only for a live serial and `LiveOwnerKeepsRecord` keeps
that serial's record undeparted. Two directed runs are checked with
`BOUND` set to the recipe's length, each with its reachability case:
`fill-run-replacement` (grant, revoke, grant of the same key, both
departures, each followed by a pass, leaving both records Free) and
`fill-run-exhausted` (three grants, the refusal at the maximum, and a last
pass that frees records and leaves no live owner, with the next serial at
4). Six mutations each break the
property that names the case: a grant that skips the same-key refusal
(`OneCurrentPerKey`), a grant that leaves the serial unadvanced
(`SerialIssuedOnce`), a grant that admits one serial past the maximum
(`SerialWithinMaximum`), a pass that frees every occupied record
(`LiveOwnerKeepsRecord`), an invalidation that sets the departed flag
(`DepartsAfterOwnerEnded`) and a release that keeps the departed flag on the
Free word (`WellFormed`). These are finite checks at the stated bounds; no
refinement mapping to the implementation is claimed.

### Replay against the fill table

`python3 quint/fill_check.py --quint QUINT --output DIR` writes nine traces
with `quint run --mbt`: five directed recipes (`replacement`, `exhausted`,
`full`, `in_progress`, `second_record`) and four traces of eight steps of the
model's own `step` under pinned seeds. They are committed under
`crates/kestrike/src/storage/fill_replay_fixtures`, each naming the
model's sha256, its recipe, its seed and its step count, and
`scripts/test-judge-quint.py` requires the committed traces to carry the
names and the metadata `fill_check.fixtures()` declares and one state for
`init` and one for each step. `storage::fill_replay_tests` replays them
against `Storage::begin_fill`, `Storage::invalidate`, `FillAttempt::abort`
and `Storage::service_fills` on the heap-backed test platform, on one
thread. The replay refuses a directed trace whose state records another
action, key or serial than its recipe entry.
After every step the replay compares the call's outcome, the decoded record
table and the next serial with the model's state, and the key stored beside
each occupied record with the key of the model's record. Together the traces reach
`init`, every choice of `step` and every outcome but `Ended`. In
`second_record` each key holds one record, and the `InProgress` refusal and
the revocation name the key of record 1, so both outcomes depend on the key
production stored beside that record. Each trace
replays with the serial counter planted so the model's maximum falls on
`SERIAL_MAX`, and the traces without `AttemptExhausted` also replay
unplanted. The replay covers these traces of gate-ordered steps; it is
evidence for them and for no other schedule.

## PUT owner model

[put.qnt](put.qnt) restates the owner and device half of
[`tla/Lifecycle.tla`](../tla/Lifecycle.tla), the PUT model of
`tla/README.md`, in the steps the owner of `net/put.rs` shows at its frames
and its device terminals, so that its traces can be replayed against the
owner. Four of its five invariants are Lifecycle's `PublishedComplete`,
`PublishedClientBytes`, `WriteCustody` and `SuccessorIsolated` as written
there. The obligation record
`remote-put-publishes-only-complete-current-bytes` cites the first two and
`reads-end-once-and-custody-drains-held` the other two. The fifth,
`HeaderLast`, is Lifecycle's invariant of that name, part of the `Safety`
both records' cases check, with one added conjunct: Lifecycle's ranges
submit in separate steps, so its state formula orders them, while this
model submits both in one step and records their order, which the added
conjunct reads. The client's outcome rules,
source custody, the read, expiry of the retained terminal row, device stops,
volume loss, deadlines and liveness stay with Lifecycle.

The finite instance is one upload of two fragments whose record takes two
write commands, range 0 carrying the record's header and range 1 the rest
of the payload, and at most one successor upload of the same key, of one
fragment and one write command. `begin` and `prepare` answer AUTHORITY and
READY. `data(i)` credits fragment `i` once and answers the cumulative base;
a credited fragment's repeat credits nothing and answers the current base; the fragment that
completes the object submits range 1 and then range 0. A new fragment of a
revoked upload ends it `Contended` when the fragment extends the cumulative
base, which is when the owner hands payload to the fill; a new fragment
behind a missing one is credited and acknowledged like any other, and
`witnessRevokedBehindBase` reaches that branch. `differ(i)` is a copy of a credited
fragment with other bytes and ends the upload `ConflictingData`. `cancel`
ends it `Cancelled`. `invalidate` revokes the upload. `terminal(w, ok)` is
the device terminal of range `w`: a failed write ends the upload
`DeviceError`, the last successful one publishes and answers RESULT, or
ends a revoked upload `Contended`. An upload that ends with a write
outstanding drains until its last terminal. `sbegin` is the successor's
BEGIN, PREPARE and DATA after a revocation, which submits its one write,
and `sterminal(ok)` its terminal, which publishes the successor or fails
it.

Abstractions:

- The owner answers, submits, fails and publishes inside the step that
  enables it. Lifecycle lets each wait; the model keeps the one schedule in
  which none does.
- The owner learns of a revocation at the next new fragment that extends
  the cumulative base or at its last write's terminal, where Lifecycle lets
  `OFail` report it at any step after `OInvalidate`.
- Both ranges submit when the object is whole, in the order range 1, range
  0. Lifecycle submits a payload range once its own fragments arrived.
- A differing copy arrives only for a credited fragment, as in Lifecycle's
  `NConflict`. The successor is one step from BEGIN to its submitted write.
- Frames to an upload that ended, an invalidation outside the ready stage
  and a second successor are outside the model.

No equivalence between this model and `Lifecycle.tla` was checked; the
cases below are claims about the Quint restatement. Of Lifecycle's actions
the model keeps `OBegin`, `OPrepare`, `OData`, `OSubmit`, `OPublish`,
`OFail` (for a cancel, a differing copy, a failed write and a revocation),
`ODrain`, `OInvalidate`, `SBegin`, `SFail`, `SPublish` and `DTerminal`,
folded into the steps above, and `NConflict` as `differ`. It omits every
client action (`CBegin` to `CClose`, `CSupply`, `CSend`, `CNicReturn`),
`OTimeout`, `OExpire`, `OLose`, `DStop` and the read actions `RAdmit`,
`RIssue`, `RTerminal`, `RChunk` and `RDone`; the frames those client
actions send are the inputs of `begin`, `prepare`, `data` and `cancel`.

| Property | Guarantee |
|---|---|
| `PublishedComplete` | The upload publishes only with every fragment credited once, both ranges written, no differing copy and no revocation. |
| `PublishedClientBytes` | The upload publishes the bytes its fragments were credited with. |
| `HeaderLast` | The header range submits after the payload range. |
| `WriteCustody` | An ended upload has no write outstanding. |
| `SuccessorIsolated` | A successor publishes only after its own write's terminal. |

[put_check.py](put_check.py) checks `safety`, the conjunction of the five,
with the free scheduler at `BOUND = 10` steps. Sixteen reachability
witnesses, each checked as the inverted invariant `not(witness)`, reach a
publication, an out-of-order first fragment, a repeated fragment answered
while writes are outstanding, a differing copy that ends the upload at once
and one that leaves it draining, a cancel in the authority stage, which ends
the upload at once, and one that leaves it draining, the terminal that ends a draining upload, a device
error with and without another write outstanding, a revocation learned at a
new fragment and at the last terminal, a fragment credited under a
revocation while the base stays at zero, a successor published beside the old
upload's outstanding write, the old upload's late terminal after that
publication, and a failed successor.

Two of the witnesses name a path that the event and the stage alone do not
tell from another, and each reads a fact its action records in the state:
`repeated`, whether the latest DATA named a fragment already credited, and
`cancelled`, the stage a cancel found the upload in. Each has a
`put-beside-` case: a directed run along the other path. The case passes
when the witness is false in every state of the run, the search reaches the
run's last action, and the run ends in the state the case names.

| Case | Run | Final state |
|---|---|---|
| `put-beside-witnessDuplicate` | `begin`, `prepare`, `data(0)`, `data(1)`: the fragment that completes the object. | A first DATA of fragment 1 answered with both writes submitted |
| `put-beside-witnessCancelAtAuthority` | `begin`, `prepare`, `cancel`: a cancel in the ready stage with no fragment credited. | `Cancelled`, ended, with `cancelled` at `ready` |

Three directed runs are checked with
`BOUND` set to the recipe's length, each with its reachability case:
`put-run-published`, `put-run-late-write-beside-successor`, which passes
through the state of Lifecycle's witness of a late write of the revoked
serial beside its successor and runs on to the old upload's end, and
`put-run-failed-header`. Seven mutations each break the
property their case names: publication with the payload range unwritten,
under a revocation, and with a repeated fragment credited twice
(`PublishedComplete`); a differing copy that replaces the credited bytes
(`PublishedClientBytes`); the header range submitted first (`HeaderLast`); a
cancel that ends the upload with writes outstanding (`WriteCustody`); and a
successor published at its submission (`SuccessorIsolated`). These are
finite checks at the stated bounds. The 33 cases took 179 seconds at eight
workers, one case at a time, on a shared 128-core development host.

## Request identity model

[identity.qnt](identity.qnt) models the owner's request namespace,
`Namespace` of `crates/kestrike/src/net/namespace.rs` over the request
table of `net/requests.rs`. It restates the owner half of
[Identity.tla](../tla/Identity.tla) and five of its invariants, and claims
nothing stronger. Its purpose is a model whose traces replay against
`Namespace`.

The finite instance has two peers of two wire slots each, wire generations 1
to 3 with 3 as the generation limit, two session epochs per peer, a table of
three handles and a per-peer share of two. Zero stands for no watermark, no
bound handle and no peer, as in `Identity.tla`. Each action is one namespace
call:

- `admit` binds a fresh wire identity to a free table handle, raises the
  slot's watermark and clears its row. `refuse` names the refusal an
  admission meets, in the order the namespace checks: `Busy` on a bound slot,
  `Stale` at or below the watermark, `Exhausted` at the generation limit,
  then `PeerPressure` and `TablePressure`. A refusal changes nothing else.
- `end` ends the slot's request. Under its session the slot retains a row
  with the request's operation and epoch; a request whose session was
  replaced ends without one.
- `unbind` frees the wire slot of an ended request whose row is retained and
  marks the record unbound, so a successor admits beside the draining record.
- `release` names a handle and a table generation. The handle's current
  generation frees the record, clears the binding when the slot still binds
  that handle and advances the generation; an earlier generation frees
  nothing. The scheduler offers the current generation and the one before it.
- `replace` retires the peer's session: watermarks and rows clear and live
  bindings stay.
- `route` classifies a frame by generation as `Older`, `Fresh` or `Same`; at
  the watermark a bound request or retained row of the other operation
  counts `WrongOperation` and changes nothing else.

Abstractions:

- The model keeps the owner half of `Identity.tla`. The client's upload, the
  client board and its leases, the frames in flight, the clock and row
  expiry, PUT replay, conflict and `UnknownOutcome` answers and the PUT caps
  stay with the TLA+ cases, so `PutCaps`, `Headroom`, `ResultHasAdmission`,
  `NoExpiredReplay`, `NoCrossedReplay`, `PublishedNeedsResult` and
  `OrphanConservation` are not restated.
- A row keeps its operation and epoch and no expiry or outcome.
- `Namespace::settle` and the refused generation it records are outside the
  model, as they are outside `Identity.tla`.
- `admit` takes any free handle, where the request table takes the one its
  free list names. A handle and the table generation of its admission name
  one admission, which is what a release names.
- `admits`, `freed` and `ev` are history the invariants and witnesses read;
  production keeps none of them. `wrong` is the namespace's
  wrong-operation counter.

| Property | Guarantee |
|---|---|
| `ExactBinding` | A bound handle's record names the slot's peer and wire slot and, while its session lasts, the slot's watermark. |
| `OneBindingPerHandle` | No two wire slots bind one handle; a live record is bound or marked unbound, never both, and a marked record has ended. |
| `OneAdmission` | Each wire identity admits at most once per session epoch. |
| `Capacity` | Live records stay within the table and each peer's within its share. |
| `ExactRelease` | A release frees only the record admitted under the table generation it names. |

[identity_check.py](identity_check.py) checks `safety`, the conjunction of
the five, with the free scheduler at `BOUND = 6` steps. Twenty-one
reachability witnesses, each checked as the inverted invariant
`not(witness)` at five steps, reach every outcome of every action: an
admission, each of the five refusals, an end with and without a row, an
unbind, a release that clears its binding and one that leaves a successor's,
a stale release (at six steps, the fewest that give a handle an earlier
generation), a replacement plain and with a binding still draining, a
successor admitted beside an unbound record, an identity admitted again
under the next session, each of the four routes, and `WrongOperation`
against a retained row alone. Two directed runs are checked with `BOUND` set
to the recipe's length, each with its reachability case:
`identity-run-successor` (a PUT ends and unbinds, its identity is refused as
stale on the free slot and as busy under its successor, whose binding the
PUT's release leaves) and
`identity-run-replacement` (a request outlives its session, drains under its
binding, and the next session admits the same generation once; a release
naming the earlier table generation frees nothing). Five mutations each
break the property that names the case: an admission that skips the
watermark check (`OneAdmission`), one that skips the busy check
(`OneBindingPerHandle`), a release that acts on a handle the slot neither
binds nor marks (`ExactBinding`), an admission that skips the peer's share
(`Capacity`) and a release that frees under an earlier table generation
(`ExactRelease`). These are finite checks at the stated bounds; no
refinement mapping to the implementation is claimed. The 32 cases took 387
seconds at eight workers, one case at a time, on a shared 128-core
development host, `identity-safety` 159 of them over 8,807,695 distinct
states.

Each invariant restates the `Identity.tla` invariant of the same name. The
model's `admit`, `refuse`, `end`, `unbind`, `release` and `replace` restate
that module's `Admit`, `Refuse`, `End`, `Unbind`, `Release` and `Replace`
without its frames and saturating counters, and `route` restates `WrongOp`
and adds the three routes that count nothing. `refuse` names the refusal it
meets, which `Refuse` leaves unnamed, and no PUT cap refuses here. The
omitted `Identity.tla` actions are `Replay`, `Conflict`, `UnknownAnswer`,
`Stale` and `Tick`, the upload's `UBegin`, `URetry`, `UReply`, `Stray`,
`UExpire` and `UAbandon`, the board's `CAdmit`, `CHand`, `CReturn`,
`CReturnStale`, `CClose` and `CAttach`, and `Done`. The restatement was
written by hand. No equivalence between `identity.qnt` and `Identity.tla`
was checked, and every result in this section is about `identity.qnt`.

## Release board model

[board.qnt](board.qnt) models the client's release board, `Releases` of
`crates/kestrike/src/net/fetch.rs` under the request namespace of
`net/client_namespace.rs`. It restates the board half of
[Identity.tla](../tla/Identity.tla) and its invariant `OrphanConservation`,
the invariant of the obligation record
`lease-returns-credit-only-their-core-and-generation`, and claims nothing
stronger. Its purpose is a model whose traces replay against the board.

The finite instance has two table handles, two board cores, wire generations
1 to 5 below a generation limit of 6, and at most two leases handed per
request. Each action is one board or namespace call:

- `admit` opens a request on a closed handle under the current core, the
  next wire generation and the handle's live generation. `exhausted` is the
  admission a board past its last wire generation refuses; it changes
  nothing else.
- `hand` hands the application one more lease of the open request, and
  `giveBack` returns one, which the request is credited.
- `close` ends the request: the leases the application still holds become
  orphans and the handle's generation advances.
- `giveBackStale` returns a lease of a closed request. It credits the
  handle's open request only when that request has the lease's core and
  generation, and otherwise frees one orphan.
- `attach` destroys the namespace, which closes every open request, and
  attaches its successor under the next core, where handle generations
  restart.

Abstractions:

- The model keeps the board half of `Identity.tla`: its `CAdmit`, `CHand`,
  `CReturn`, `CReturnStale`, `CClose` and `CAttach`. `exhausted` is added to
  name the refusal `CAdmit`'s guard leaves silent. Every owner and upload
  action of `Identity.tla` is omitted, with the invariants that read them.
- A handle keeps the stale leases of one closed request, as in
  `Identity.tla`: a request closes, and a namespace is destroyed, only once
  the handle's earlier stale leases are returned.
- Fragments, receive windows and the grants a credited release feeds are
  outside the model. `ev` is history the witnesses read.
- The restatement was written by hand. No equivalence between `board.qnt`
  and `Identity.tla` was checked, and every result in this section is about
  `board.qnt`.

| Property | Guarantee |
|---|---|
| `OrphanConservation` | The board's orphans equal the leases of closed requests the application still holds. |

[board_check.py](board_check.py) checks `safety`, which is
`OrphanConservation`, with the free scheduler at `BOUND = 12` steps. Twelve
reachability witnesses, each checked as the inverted invariant
`not(witness)`, reach every outcome of every action: an admission and its
refusal at the last generation, a hand, a credited return, a stale return
that frees an orphan under its own core and under a later one, one beside an
open request on the same handle, a close with and without held leases, an
attach with and without open requests, and four orphans at once. Two
directed runs are checked with `BOUND` set to the recipe's length, each with
its reachability case: `board-run-later-generation` (a lease outlives its
request and is returned while the handle's next request is open, which is
credited only its own lease) and `board-run-later-core` (two leases outlive
their core and are returned beside the successor's request on the same
handle and generation, which is credited neither). Two mutations break
`OrphanConservation`, as the record's TLA+ controls do: a stale return that
credits without comparing the core (`lease-without-core`) and one that
credits without comparing the generation (`lease-without-generation`).
These are finite checks at the stated bounds; no refinement mapping to the
implementation is claimed.

`giveBackStale` has one more outcome, `CreditedStale`, for a stale lease
that credits the handle's open request. No state of the unmutated model
reaches it at these bounds: a closed request's lease carries the generation
its handle had before the close advanced it, or the core before the attach,
so `OrphanConservation` holds only because that branch is never taken. The
outcome exists for the two mutations, which reach it.
## Volume read model

[read.qnt](read.qnt) restates the read half of
[`tla/Lifecycle.tla`](../tla/Lifecycle.tla) in the steps the volume of
`storage/volume/read.rs` shows, so that its traces can be replayed against
the volume. Its two invariants are Lifecycle's `OneDone` and
`ChunksVerified` as written there, with the model's handed-off command
count in place of Lifecycle's `r.chunks`; the obligation record
`reads-end-once-and-custody-drains-held` cites both, and
`read-one-done-ordered-verified-chunks` states the same guarantee for the
volume. No equivalence between this model and `Lifecycle.tla` was checked;
the cases below are claims about the Quint restatement.

The finite instance is one read whose record takes three read commands on a
volume that reads one command ahead, so the read holds the current command,
the lowest not handed off, and at most one command ahead of it. `admit`
issues command 1. `grant` issues the next command while fewer than two
commands are issued and not handed off (`Added`); otherwise the read keeps
one grant (`Added`, and `Merged` for a further one), which issues the next
command once the current command handed off; after the last command it is
`Exhausted`, and after the read ended `Stale`. `terminal(k, ok)` is the
device terminal of command `k`. The current command hands off once its
terminal arrived as read, and then every later command whose terminal
already arrived, in order; a failed current command ends the read
`DeviceError`, at once or when the commands before it handed off; the last
hand-off ends it `Complete`. `cancel` ends a reading read `Cancelled` with
its commands still outstanding and is `Stale` afterwards. The read is
drained once it ended and its last terminal arrived.

Of Lifecycle's actions the model keeps `RAdmit`, `RIssue` (as `admit`,
`grant` and the kept grant), `RTerminal`, `RChunk` and `RDone`, with
`RChunk` and `RDone` folded into the step that enables them. `RIssue` is
narrowed: Lifecycle issues while fewer than two commands are outstanding,
the model while fewer than two are issued and not handed off, as the volume
does. `cancel` is the client-cancel case of `RDone`'s `Deadlines` disjunct;
the deadline itself, the device-stop cause, `DStop`, a second read and
every PUT action are outside the model. Lifecycle's terminal has no failure; the model adds
the failed terminal the volume reports as `DeviceError`. Header and chunk
verification are the terminal's `ok` flag.

| Property | Guarantee |
|---|---|
| `OneDone` | The read ends at most once, and no command hands off after its end. |
| `ChunksVerified` | Every handed-off command's terminal arrived as read. |

[read_check.py](read_check.py) checks `safety`, the conjunction of the two,
with the free scheduler at `BOUND = 10` steps. Twelve reachability
witnesses, each checked as the inverted invariant `not(witness)`, reach a
complete read, a step that hands off commands 1 and 2 together because the
command ahead ended first, a kept grant issued at a terminal, a merged, an
exhausted and a stale grant, a stale cancel, a cancel with two commands
outstanding, the terminal that drains a cancelled read, a failed current
command, a failure reported when the command before it hands off, and a
failed command ahead that waits. Four directed runs are checked with `BOUND`
set to the recipe's length, each with its reachability case:
`read-run-complete`, `read-run-ahead-first`, `read-run-cancel-two-out` and
`read-run-failed-ahead`. Four mutations each break the property their case
names: a cancel after the end that ends the read again and a terminal after
the end that hands off (`OneDone`); a command ahead handed off before the
current command's terminal and a failed command counted as handed off
(`ChunksVerified`). These are finite checks at the stated bounds.

## Burst custody model

[burst.qnt](burst.qnt) models the transmit custody of one burst transport of
`native/burst.rs`: `Burst::transmit`, the device's return of the chains it
holds, `reclaim` with its quiesced recovery, and `into_port`. It restates the
invariant of the obligation record
`burst-custody-follows-accept-and-stop-proof` and claims nothing stronger.

The finite instance is one transport over one device queue pair, a header
pool of eight buffers, one chain per datagram and at most two datagrams per
send. `held` counts the header buffers off the free stack and `dev` the
chains the device holds. `send(n, k, unc)` offers `n` chains to a device that
takes `min(k, n)`. With `unc` other than `no`, a short post is uncertain and
its first refused chain is quarantined: `kept` when the device kept it,
`untaken` when it did not, `freed` when the device took it and returned it
inside the post. A send on a link that is not up answers `Closed`, and a
send while a chain is quarantined answers `Poisoned`. `complete` is the
device's return of every chain it holds. `reclaim(reset, proven, restart,
again)` is one turn: with a reset pending or a quarantined chain it runs
recovery, whose first stop is `proven` or not, whose restart succeeds
(`ok`), fails at the registration's recheck (`stale`) or fails at the
device's start (`fail`), and whose second stop after a failed restart is
proven when `again` holds. A proven stop returns every chain the device
holds and settles the quarantine once, as a device return or as a local
release. `close(proven)` is `into_port`: it stops the device only while a
chain is quarantined, settles the quarantine at a proven stop, and ends the
transport; every later step answers `Gone`.

Abstractions:

- Each action is one atomic step of one thread. The device's answers are
  the action's arguments, chosen freely.
- Chains are counted, not named. A chain is one header buffer; payload
  descriptors, source references, the receive ring and the buffers a start
  posts are omitted, as are prepare refusals, unsendable datagrams and pool
  exhaustion: a send is enabled only while the pool can hold its batch.
- The recovery watchdog is omitted, so no episode expires or is refused. The
  recheck, reset, re-initialization and start are one restart outcome.
- `sent`, `quarantined`, `returned`, `released`, `resets` and `recoveries`
  are the report's counters. `admittedPoisoned` and `unprovenReleased` are
  history the invariants read; production keeps neither. `arg` records each
  action's arguments for the replay.

| Property | Guarantee |
|---|---|
| `HeldUntilProvenStop` | Every chain the device holds, and a quarantined chain it never took, keeps its header buffer off the free stack. |
| `UncertainPoisons` | No send is admitted while a chain is quarantined. |
| `UnprovenStopKeepsHeld` | A stop that is not proven leaves the held buffers, the device's chains and the quarantine as they were, and a recovery's unproven first stop loses the link. |

[burst_check.py](burst_check.py) checks `safety`, the conjunction of the
three, with the free scheduler at `BOUND = 6` steps. Twenty-four
reachability witnesses, each checked as the inverted invariant
`not(witness)`, reach every outcome of every action: a send that the device
takes, one a full ring refuses whole, the three uncertain posts, the
poisoned and the closed refusal; a device return with and without chains,
and one that returns the quarantined chain; a reclaim on a closed link, one
that only cleans up, a lost link with chains and a quarantine held, a
recovery plain, with a local release and with a device return, a link left
down and a link lost at the second stop; and a close that hands the port
back, one that settles, one that settles on a lost link, one that leaves
the quarantine, and a step after the close. Two directed runs are checked
with `BOUND` set to the recipe's length, each with its reachability case:
`burst-run-uncertain-settles` (an uncertain post the device never took, the
refused send, the recovery that releases the chain and a send after it) and
`burst-run-unproven-holds` (a kept uncertain post beside accepted chains, an
unproven stop that keeps all four held, the device's later return and the
close that settles the quarantine as returned). Three mutations each break
the property that names the case: an uncertain post that leaves its chain
uncharged (`HeldUntilProvenStop`), a send that skips the poison refusal
(`UncertainPoisons`) and a recovery that settles after an unproven stop
(`UnprovenStopKeepsHeld`). These are finite checks at the stated bounds; no
refinement mapping to the implementation is claimed.

### Replay against the burst transport

`python3 quint/burst_fixtures.py --quint QUINT --output DIR` writes fourteen
traces with `quint run --mbt`: ten directed recipes (`uncertain_settles`,
`unproven_holds`, `down`, `lost_after_restart`, `freed`, `kept_unsettled`,
`lost_then_settled`, `unsettled_kept`, `unsettled_untaken`, `cleanup`) and
four traces of ten steps of the model's own `step` under pinned seeds. They
are committed under
`crates/kestrike/src/native/burst_tests/replay_fixtures`, each naming the
model's sha256, its recipe, its seed and its step count, and
`scripts/test-judge-quint.py` requires the committed traces to carry the
names and the metadata `burst_fixtures.fixtures()` declares and one state
for `init` and one for each step. `native::burst_tests::replay` replays them
against the production `Burst` over the mock port and the mock arena, on one
thread. The replay refuses a directed trace whose state records another
action or argument than its recipe entry. Each step sets the mock device's
answers from the step's recorded arguments and runs one production call: a
send of one-segment datagrams, the device's return of every chain it holds,
a reclaim, or `into_port`. After every step the replay compares the call's
outcome, the header pool's held count, the chains the mock device holds, the
link, the poison and the burst report's counters with the model's state.
While the burst is live, it also compares the quarantine kind: a disarmed
retained header is `returned`, an armed header held by the device is `kept`,
and an armed header outside the device's held list is `untaken`.
After the model's `close` it compares the header pool and the device only.
Together the traces reach `init`, every choice of `step` and every outcome
of every action.

Two controls fail in those comparisons. A driver whose device proves every
stop, or never reports a post uncertain, fails at the outcome, and one that
drops the device's return fails at the header pool's count. A trace with a
changed link, held count, device count, poison, quarantine kind, counter or
outcome fails at the changed state. The quarantine-kind control substitutes
each other kind and an invalid label in kept, untaken, immediate-return and
delayed-return states. The recovery watchdog runs with the mock's one-minute
deadline and never expires; the model does not describe it. The replay
covers these traces over the mock device; it is evidence for them and for no
other schedule.

## Mempool transmit custody model

[mempool.qnt](mempool.qnt) models the transmit custody the packet mempool ops
of `native/mempool.rs` keep: the header pool's enqueue (`return_header`), the
payload pool's descriptor take and enqueue (`OpsState::take_payload`,
`return_descriptor`, `disarm`), the device-reference token each transmit mbuf
carries (`Token::write`), and the storage pool calls the burst logic makes
around them, `Buffer::into_device` for a header and `NicHold::into_raw` for a
payload segment. It restates the clauses of the obligation record
`burst-transmit-custody-characterization` that the ops own, "every object is
out once and back once with no stray or mismatched return", "each segment
carries one armed token naming its own buffer's incarnation", the equality of
a header's one-write hand-off with a raw hold and its handle's drop, and the
record's test `a_source_frees_once_both_owner_and_device_released_it_in_either_order`,
and claims nothing stronger.

The finite instance has two header buffers `h0` and `h1`, one read-response
source buffer `s0` and two payload descriptors `0` and `1`, whose stack starts
as `[0, 1]` with its top last. A buffer has an owner flag, a count of device
references, an incarnation and a free flag. `acquire` takes a free buffer.
`send` hands an owned header to the device in one write: the handle ends, one
reference starts and the header's token names the buffer's incarnation.
`drop` ends a handle; a buffer with no reference returns to the free stack and
starts its next incarnation, and one with references stays held. `take` moves
the stack's top out, or refuses an empty stack. `attach` gives an out
descriptor one reference to the owned source, with a token naming the
source's incarnation. `giveHeader` and `giveDesc` are one enqueue each: they
disarm the token, return the reference it names, and for a descriptor push it
back on the stack; a descriptor with no token goes back with nothing returned.
The last reference of a buffer whose handle ended frees it.

Abstractions:

- Each action is one call on the owner thread, so the model holds no
  interleaving; the ops run only inside port calls on that thread.
- An enqueue is the same call whether the device returns the object or the
  burst logic releases a chain the device never took, so the model does not
  distinguish them, and it models no device queue: any object with an armed
  token, or any out descriptor, may come back, once, in any order.
- Returns stay legal: the model never enqueues an object that is not out or a
  header whose token is disarmed. The ops' stray and mismatch counting of
  such objects is outside this model; the counters exist so the mutations can
  reach `NoStrayNoMismatch`.
- Incarnations are counted from 0 per buffer, the reference cap, the
  incarnation wrap and retirement are omitted, and the receive pool, the
  native pool's free and the pool's device lease are not modeled.
- Buffer names are roles, not indices: any free header of production is the
  model's free header, since free buffers of one kind are interchangeable for
  custody. Descriptor indices are production's indices.

| Property | Guarantee |
|---|---|
| `OutOnceBackOnce` | Every descriptor is on the stack or out, never both, and the stack holds each once. |
| `NoStrayNoMismatch` | No enqueue counts a stray object or a mismatched reference. |
| `TokenNamesLiveIncarnation` | Every armed token names its own buffer's live incarnation, and each buffer's device references are exactly the armed tokens naming it. |
| `FreesOnlyWhenBothReleased` | A buffer is free exactly when its handle ended and no device reference remains. |

[mempool_check.py](mempool_check.py) checks `safety`, the conjunction of the
four, with the free scheduler at `BOUND = 8` steps. Twelve reachability
witnesses, each checked as the inverted invariant `not(witness)`, reach every
outcome of every action: an acquire, an acquire of a buffer in a later
incarnation, a header sent, a drop that frees and one that leaves the buffer
held, a take and a refused take, an attach, a header returned and freed, a
descriptor returned with the source still held, one whose return frees the
source, and one returned without a token. Four directed runs are checked with
`BOUND` set to the recipe's length, each with its reachability case:
`mempool-run-drop-then-return` and `mempool-run-return-then-drop` (a source
attached to a descriptor, its handle dropped before and after the
descriptor's return, freed either way in its next incarnation),
`mempool-run-header-reuse` (a header sent, returned and sent again under its
next incarnation) and `mempool-run-two-segments` (two segments on one source,
a refused third take, both returned and the stack restored). Four mutations
each break the property that names the case: a descriptor return that leaves
it out (`OutOnceBackOnce`), an attach whose token names the next incarnation
(`NoStrayNoMismatch`), a send that takes no reference (`TokenNamesLiveIncarnation`)
and a drop that frees a buffer the device still holds (`FreesOnlyWhenBothReleased`).
These are finite checks at the stated bounds; no refinement mapping to the
implementation is claimed.

## Transmit custody model

[custody.qnt](custody.qnt) models how a transmit chain leaves custody in the
burst logic of `native/burst.rs`: `Burst::transmit`, the device's returns
through the pools' ops, the turn's reclaim with `recover`, `restore` and
`reconcile`, and `into_port`. It restates the native clauses of the
obligation record `burst-custody-exits-via-port-return`, "a chain the device
accepted or kept uncertain stays off its pools' free stacks and exits only by
a port return: the proven stop of a failed restart returns every chain", "and
an unproven first stop leaves the link lost with every chain held", and
claims nothing stronger. The record's clauses about the composed owner, its
ledgers and its close are outside the model.

The finite instance has one burst logic over one device, four header buffers
and sends of one to three datagrams. A chain is named by the order it was
built in. `dev` holds the chains the device holds and `pool` the chains whose
buffers are off the header pool's free stack. `send(n, accept, fault)` builds
as many of `n` chains as free header buffers allow, the device accepts the
first `accept` of them, and `fault` scripts the first refused chain: `none`
is a full ring, `kept` an uncertain post the device keeps, `unkept` an
uncertain post the device never took, and `freed` an uncertain post the
device took and returned inside the burst. An uncertain chain is quarantined
and later sends are refused `Poisoned`. `devReturn` is the device's return of
its oldest chain. `reclaim(reset, stop, recheck, start, again)` is one turn:
with a reset pending or a quarantine recorded it runs recovery, whose first
stop is proven or not (`stop`), whose recheck and start succeed or fail, and
whose second stop after a failed restart is proven or not (`again`). A proven
stop returns every chain the device holds and settles the quarantine: a
chain the device never took is released locally, any other counts as
returned. `close(stop)` hands the port back, stopping first when a quarantine
is recorded. `rest` is the only step after the hand-back besides a device
return.

Abstractions:

- Each action is one atomic step on one thread, as the owner thread runs the
  burst logic.
- Chains are header-only. Payload descriptors, source references, tokens and
  incarnations, the wire bytes, the receive path, validation refusals and the
  prepare stage are omitted.
- The recovery watchdog never expires and always arms; the reset and
  re-initialization stages always succeed.
- The device returns chains oldest first, one per `devReturn`, and returns
  whole chains.
- `took`, `local`, `prevDev` and `prevPool` are history the invariants read;
  production keeps none of them. `took` holds every chain the device took,
  and `local` every chain released without a device return.

| Property | Guarantee |
|---|---|
| `DeviceHeldStaysCharged` | Every chain the device holds is off the free stack. |
| `ExitsOnlyByPortReturn` | No chain the device took is released locally. |
| `FailedRestartReturnsEvery` | After a failed restart whose stops were proven, the device holds no chain and none of the chains it held stays off the free stack. |
| `UnprovenStopKeepsHeld` | An unproven first stop loses the link, and an unproven stop, in recovery or at the hand-back, leaves the device's chains and the pool as they were. |

[custody_check.py](custody_check.py) checks `safety`, the conjunction of the
four, with the free scheduler at `BOUND = 5` steps: 214,106 distinct
states. Twenty-three reachability witnesses, each checked as the inverted
invariant `not(witness)`, reach every outcome of every action:

- a full send, a full ring, and a send cut short by the header pool;
- an uncertain post kept, never taken, and freed inside the burst;
- a poisoned send and a closed send;
- a device return of an accepted chain and of the quarantined chain;
- an idle turn and a quiet turn;
- an unproven first stop with chains out;
- a recovery, one that releases, and one that counts a return;
- a link left down, and a link lost after a failed restart;
- a hand-back that keeps chains with the device, one whose stop is unproven,
  one that settles, and one that settles after the link was lost;
- a rest.

Five
directed runs are checked with `BOUND` set to the recipe's length, each with
its reachability case. Five mutations each break the property their case
names: an uncertain post that leaves the kept chain uncharged
(`DeviceHeldStaysCharged`), a settlement that releases every quarantined
chain locally (`ExitsOnlyByPortReturn`), a proven stop that leaves the
device's chains with it and one that empties the device and leaves its
chains off the free stack (`FailedRestartReturnsEvery`), and an unproven
stop that frees the device's chains (`UnprovenStopKeepsHeld`). These are finite
checks at the stated bounds; no refinement mapping to the implementation is
claimed.

## Settle rule model

[settle.qnt](settle.qnt) models how the owner's request namespace,
`Namespace` of `crates/kestrike/src/net/namespace.rs`, records an identity
an operation answers without admitting it. It restates the settle rule of
that module's documentation and the rule the incident histories judge as
"a settled GET's row held an admitted request" and "a settled upload's row
held an admitted attempt", and claims nothing stronger. No TLA+ model states
this rule: `Identity.tla` and `identity.qnt` have no settle. Its purpose is
a model whose traces replay against `Namespace`.

The finite instance has one peer with one wire slot, wire generations 1 to 4
with 4 as the generation limit, two session epochs and a table of two
handles. Zero stands for no watermark, no bound handle and no refused
generation. Each action is one namespace call:

- `admit` binds a generation above the watermark to a free handle on a free
  binding, and `refuse` names the refusal an admission meets: `Busy`,
  `Stale`, `Exhausted`, then `Pressure`.
- `settle` answers a generation without admitting it. A generation at or
  below the watermark or a recorded refusal, and the limit, are `Ignored`.
  On a free binding the generation becomes the watermark and its answer the
  row, kept or none (`Settled`). While a request holds the binding the
  generation is recorded as refused and nothing else changes (`Refused`).
- `end` ends the bound request, which retains a row under its session.
  `unbind` and `release` free the binding; with a refused generation
  recorded they raise the watermark to it and drop the row.
- `replace` retires the session: the watermark, the row and the refused
  generation clear and the binding stays.
- `route` classifies a generation as `Older`, `Same` or `Fresh`.

Abstractions:

- One peer, one wire slot and one operation: bindings across slots and
  peers, table generations and wrong-operation routing are
  [identity.qnt](identity.qnt)'s.
- A row is present or absent; its epoch, expiry and outcome are not modeled.
- `answered` and `readmitted` are history the invariants read: the
  identities admitted, settled or refused in each session, and whether an
  admission took one of them. `raised` is history the stale-after-refusal
  witness reads: it is true while the watermark is a refused generation that
  a freed binding raised. All three exist only in the model.
- The model was written by hand from the module documentation. No
  equivalence with another model was checked, and every result in this
  section is about `settle.qnt`.

| Property | Guarantee |
|---|---|
| `AnsweredOnce` | An identity admitted, settled or refused in a session is not admitted later in that session. |
| `RefusedOnlyWhileBound` | A refused generation is recorded only while a request holds the binding, and lies above the watermark. |
| `WatermarkCoversAnswered` | Every identity the session answered lies at or below the watermark or the recorded refusal. |

[settle_check.py](settle_check.py) checks `safety`, the conjunction of the
three, with the free scheduler at `BOUND = 8` steps. Twenty-two reachability
witnesses, each checked as the inverted invariant `not(witness)`, reach
every outcome of every action: an admission and each refusal, a stale
refusal of the generation a freed binding raised from its recorded refusal
(`witnessStaleAfterRefusal`, which reads `raised`), a settle on a free
binding with and without a row, a recorded refusal, an ignored settle and
one below a higher recorded refusal, an end with and without a row, an
unbind and a release each with and without a raise of the watermark, a
replacement plain and over a recorded refusal, and the three routes. Three
directed runs are checked with `BOUND` set to the recipe's length, each with
its reachability case: `settle-run-refused-order` (a higher and then a lower
generation are answered under a held binding, the lower is ignored, and
both are stale once the binding unbinds), `settle-run-free-slot` (a
settled generation keeps its row, refuses its own admission, and the next
generation admits) and `settle-run-rowless-settle` (a generation settled
without a row on a free binding is stale and leaves
`witnessStaleAfterRefusal` false). Three mutations each break the property
that names the
case: an admission that skips the watermark check (`AnsweredOnce`), a settle
that ignores the recorded refusal and so lowers it
(`WatermarkCoversAnswered`) and a release that keeps the refused generation
after the binding frees (`RefusedOnlyWhileBound`). These are finite checks
at the stated bounds; no refinement mapping to the implementation is
claimed. The 33 cases took 174 seconds at eight workers, one case at a time,
on a shared 128-core development host.

Two more directed runs check the recipes of the committed replay traces
that the first two leave out, each with its reachability case, so every
directed fixture recipe of `net::settle_replay_tests` is also a TLC-checked
run with a stated end. `settle-run-pressure` fills the table with two
draining records, meets the pressure and limit refusals and an ignored
settle of the limit, and releases both records unbound, ending with the
watermark at the second generation and no record. `settle-run-replaced`
records a refusal, replaces the session, which forgets it, records a lower
one that the old request's release raises, and ends after the next
request's unbind raised its own refusal, with five identities answered over
the two sessions. `settle.qnt` is unchanged, so the fixtures' digests stand.

### Replay against `Namespace` with settle

`python3 quint/settle_fixtures.py --quint QUINT --output DIR` writes eight
traces with `quint run --mbt`: four directed recipes (`refused_order`,
`free_slot`, `pressure`, `replaced`) and four traces of 24 steps of the
model's own `step` under pinned seeds. They are committed under
`crates/kestrike/src/net/settle_replay_fixtures`, each naming the model's
sha256, its recipe, its seed and its step count, and
`scripts/test-judge-quint.py` requires the committed traces to carry the
names and the metadata `settle_fixtures.fixtures()` declares and one state
for `init` and one for each step. `net::settle_replay_tests` replays them
against `Namespace` with one peer, a width of one and a table of two. The
replay refuses a trace whose states differ in number from its recorded steps
and a directed trace whose state records another action or argument than
its recipe entry. Each action is the namespace call it names; `settle`
returns nothing, so its outcome is judged by the state after it. At an `end`
the replay reads the slot before the call and retains a row exactly when the
slot holds a watermark, and it requires the recorded result to be `Ended`
then and `EndedReplaced` otherwise. After every action the replay
compares the slot's
watermark, binding, row and refused generation, each record's draining
state and the census with the model's state, and it counts admissions
itself. Together the traces reach `init`, every choice of `step` and every
outcome an action records, among them a lower generation settled after a
higher one under a held binding. A driver that drops a settle while a
request holds the binding fails the refused-generation comparison at that
settle, and a trace with one recorded field changed fails at that state.
The replay covers these traces of single namespace calls on one thread; it
is evidence for them and for no other schedule.

## Rearmable watchdog model

[watchdog.qnt](watchdog.qnt) models the one worker a recovery watch starts
and every recovery episode rearms: `Rearmable::rearm`, `Rearmable::disarm`
and the worker loop `run` of `crates/kestrike/src/native/watchdog.rs`. It
restates five clauses of the obligation record
`recovery-arms-the-watchdog-before-every-blocking-stage` (the expiry asks to
contain once, successive episodes rearm the one worker, an idle worker never
contains, each deadline runs from its own arm, an expired worker refuses
later arms) and claims nothing stronger. The record's other clauses, about
the recovery stages and the buffers a stall saw held, are outside the model.

The finite instance has one worker, a deadline of 2 ticks and clock advances
of 0 to 3 ticks. `rearm` is the owner's arm: an expired worker refuses it,
and otherwise it stamps the clock's reading and wakes the worker. `disarm`
clears the stamp and reports whether the worker expired; it wakes nothing.
`pass` advances the clock in silence. `wake` advances the clock and wakes the
worker, which then waits without bound while idle, waits for the rest of a
running deadline, or, once the deadline has passed on the clock, marks the
expiry, asks to contain and ends. A wake of an ended worker does nothing.

Abstractions:

- Each owner call and each pass of the woken worker is one atomic step, which
  is the order the state's mutex gives. The lock itself, the condition
  variable and the unlocked window before the supervisor runs are omitted.
- The worker reads the clock only when woken, as it does over the tests'
  scripted timer. The production timer's timed wait is a wake at the
  deadline, which `wake` covers.
- `rearm` is enabled only while no deadline runs or the worker expired, the
  order the recovery watch keeps and a debug build asserts.
- The drop of the watchdog, a worker thread that cannot start, a containment
  that unwinds and the join of an expired worker are omitted.
- `waits` and `wait` are the count of waits the worker entered and the
  timeout of the last, which the scripted timer records. `armedAt`, `arms`,
  `idleContained`, `early` and `rearmedExpired` are history the invariants
  and witnesses read; production keeps none of them.

| Property | Guarantee |
|---|---|
| `ContainsAtMostOnce` | The worker asks to contain at most once. |
| `IdleNeverContains` | No containment request leaves a worker with no running deadline. |
| `DeadlineFromOwnArm` | A containment request comes at least a deadline after the clock reading of the arm it ends. |
| `ExpiredRefusesRearm` | No arm is honored after the expiry. |
| `WorkerOutlivesDisarm` | The worker ends only by expiring, so a disarmed worker serves the next arm. |

[watchdog_check.py](watchdog_check.py) checks `safety`, the conjunction of
the five, with the free scheduler at `BOUND = 8` steps. Thirteen
reachability witnesses, each checked as the inverted invariant
`not(witness)`, reach every outcome of every action (an honored and a
refused arm, a disarm before and after the expiry, a silent advance, a wake
that leaves the worker idle, waiting, contained or already ended) and four
further states: a wait shorter than the deadline, a second honored arm, a
disarm that arrives with the clock past the deadline and still finds the
worker running, and an idle wake with the clock past the deadline. Two
directed runs are checked with `BOUND` set to the recipe's length, each with
its reachability case: `watchdog-run-idle-then-full-deadline` (an idle wake
past the deadline, an arm, a partial wait, the expiry, the disarm that
reports it and the refused arm) and `watchdog-run-disarm-then-rearm` (two
episodes that disarm in time, the second with the clock past its deadline).
Five mutations each break the property that names the case: a worker that
keeps running after its expiry (`ContainsAtMostOnce`), an idle worker that
times the clock (`IdleNeverContains`), an arm that stamps reading zero
(`DeadlineFromOwnArm`), an arm that ignores the expiry
(`ExpiredRefusesRearm`) and a disarm that ends the worker
(`WorkerOutlivesDisarm`). These are finite checks at the stated bounds; no
refinement mapping to the implementation is claimed.

### Replay against the rearmable worker

`python3 quint/watchdog_fixtures.py --quint QUINT --output DIR` writes ten
traces with `quint run --mbt`: four directed recipes
(`idle_then_full_deadline`, `disarm_then_rearm`, `partial_then_expiry`,
`three_episodes`) and six traces of ten steps of the model's own `step`
under pinned seeds. They are committed under
`crates/kestrike/src/native/watchdog_tests/replay_fixtures`, each naming
the model's sha256, its recipe, its seed and its step count, and
`scripts/test-judge-quint.py` requires the committed traces to carry the
names and the metadata `watchdog_fixtures.fixtures()` declares and one state
for `init` and one for each step. `native::watchdog_tests::replay` replays
them against the production `Rearmable` and its worker thread over the
tests' scripted timer, one tick a second on that clock. The replay refuses a
directed trace whose state records another action or `dt` than its recipe
entry. A `pass` or `wake`
advances that clock by the step's recorded `dt`. After a step that wakes the
worker the replay waits until the worker entered its next wait or its
containment. After every step it compares the call's outcome, the clock, the
expiry flag, the containment count, the count of waits the worker entered
and the timeout of the last with the model's state, so a trace with a
changed `dt` on a `pass` or `wake`, or a changed clock reading in any state,
fails at the changed state. Together the traces reach `init`, every choice
of `step` and every outcome of every action.

The replay reads no production stamp: it checks `armed` through the
timeouts and the expiry the stamp leads to. A wake of an ended worker is
checked by the wait count staying the model's. Two controls fail in that
comparison: a driver that drops the disarm or the silent advance fails at
the next wake, and a trace with a changed outcome or wait fails at the
changed state. The replay covers these traces over a scripted clock; it is
evidence for them and for no other schedule, and it runs no real-time wait.

## Recovery episode model

[episode.qnt](episode.qnt) models one burst transport's quiesced recovery
under its watchdog, the episode `Burst::recover`, `restore`, `restart_under`
and `staged` of `native/burst.rs` run and `RecoveryEpisode` records, and
`into_port` after it. It restates the episode clauses of the obligation
record `recovery-arms-the-watchdog-before-every-blocking-stage` and claims
nothing stronger. The watchdog's worker is the subject of the watchdog
model, and the custody of chains outside an episode that of the burst
custody model.

The finite instance is one transport with at most one quarantined chain.
`ARMABLE` states whether the watchdog's worker started. `send(unc)` offers
two chains to a device that takes one and, with `unc` other than `no`,
quarantines the other as `kept` or `untaken`. `complete` is the device's
return of every chain it holds. `reclaim(reset, stall, proven, restart,
again)` is one turn. With a reset pending or a quarantined chain it runs an
episode: the stop, the registration's recheck, the reset, the
re-initialization and the start, and after a restart that fails at the
recheck (`stale`) or at the start (`fail`) a second stop, proven when `again`
holds. `stall` names the one stage whose call expires the watchdog before it
returns: `Stop` is the first stop and `Stop2` the second; a stall in a stage
the episode does not reach expires nothing. `log` holds the stages the
episode began and `ep` its record. `close(proven)` is `into_port`.

Abstractions:

- Each action is one atomic step of the owner thread. An expiry is the
  model's choice of a stalled stage: the worker's clock, lock and wake are
  omitted, so a watchdog expires only inside a stage. An expiry that falls
  between two stages, or after the last stage and before the disarm, is not
  modeled.
- Chains are counted, as in the burst custody model, and a send is two
  chains of which the device takes one. Receive buffers a start posts are
  omitted.
- A watchdog that cannot arm is the constant `ARMABLE`, fixed for a run.
- `expiredSettled` and `containedStopped` are history the invariants read;
  production keeps neither.

| Property | Guarantee |
|---|---|
| `RefusedBeforeAnyStage` | An episode whose watchdog cannot arm begins no stage, records the refusal and loses the link without a containment request. |
| `NoStageAfterExpiry` | The stage an expiry fell on is the last stage the episode began and the one it records. |
| `ExpiryLosesLinkAndContainsOnce` | An expired episode loses the link, records the request and leaves exactly one containment request; no run holds more than one. |
| `ExpiryKeepsQuarantine` | An episode that expires in its first stop settles no quarantine, and `into_port` after an expiry changes nothing. |
| `FaultFreeDisarms` | An episode that leaves the link up began every stage, records no expiry and asked for no containment. |

[episode_check.py](episode_check.py) checks `safety`, the conjunction of the
five, with the free scheduler at `BOUND = 5` steps, once with a watchdog
that can arm and once with one that cannot. Thirty reachability witnesses,
each checked as the inverted invariant `not(witness)`, reach every outcome
of every action: the sends, the device's returns, a reclaim on a closed
link and one that only cleans up, an unproven first stop, a recovery and a
second recovery on the rearmed watchdog, a link left down after a failed
start and after a stale recheck, a link lost at the second stop, an expiry
in each of the five stages, in a proven first stop that leaves the
quarantine, in the second stop and in a second episode, each close, a close
after a containment that leaves a quarantined chain, and a step after the
close; two of the thirty, the refusal and the close that settles after it,
run with a watchdog that cannot arm. Four directed runs are checked with
`BOUND` set to the recipe's length, each with its reachability case:
`episode-run-stalled-reset`, `episode-run-stalled-stop-keeps-quarantine`,
`episode-run-rearms` (two recoveries, then an expiry in the second stop of
the third episode) and `episode-run-refused`. Six mutations each break the
property their case names: a refused episode that begins the stop
(`RefusedBeforeAnyStage`), an expired reset followed by the
re-initialization (`NoStageAfterExpiry`), an expired start that leaves the
link up (`ExpiryLosesLinkAndContainsOnce`), an expired proven stop that
settles the quarantine and a close that stops the device after a
containment (`ExpiryKeepsQuarantine`), and a clean recovery that asks to
contain (`FaultFreeDisarms`). These are finite checks at the stated bounds;
no refinement mapping to the implementation is claimed.

## Fill claims model

[claims.qnt](claims.qnt) models the claims a fill of one index shard takes at
its reservation and how each ends: the additional-key claim and pending place
of `storage/place_claim.rs`, the two lease credits its owner holds, their
spending in `storage/publication.rs`, and their refunds by a refused
publication, the service pass of `storage/attempt.rs` and the invalidation of
`storage/remove.rs`. It restates the intact-table clauses of the invariant of
the obligation record `fill-claims-index-place-and-credit-before-upload` that
the abstractions below keep, and claims nothing stronger.

The finite instance has two keys, a visible limit of 2 and a lease limit of
3. The ledger is three counters: `v` visible objects, `p` places claimed and
`c` lease credits reserved. Each key has a visible version or none, the
record of its current fill, a count of revoked fills whose owners still
live, and a count of leases. `reserve` refuses `InProgress` while the key has
a current record, `IndexFull` when `v + p` is at the limit and `LeaseLimit`
when two more credits pass the lease limit; both refusals leave a departed
record with no place. Otherwise the fill holds one place and two credits.
`publishFill` publishes the reserved fill: it spends the place, makes the
key's object visible or replaces it, and turns one credit into a lease and
returns the other; a late publication refuses `Expired` and returns the
place and both credits. `abort` returns both credits and leaves a departed
record that still holds its place. `service` frees every departed record and
refunds the places they hold. `invalidate` ends the key's visible object and
its current record: it refunds the record's place, and a reserved fill
becomes a revoked one that keeps its credits. `endRevoked` is a revoked
fill's publication, which refuses `Superseded` and returns its credits.
`release` drops a lease and returns its credit.

Abstractions:

- Each action is one atomic step: one call of a fill's owner, an
  invalidation, a pass or a lease's holder. The orders inside a gate hold
  stay with the loom kernels.
- The place is one counter, where production holds a pending pair and the
  additional-key claim together; the pair's place on its key's chain stays
  with `storage/publication_tests.rs`. The fill table is large enough that
  no reservation finds it full, and serials are omitted;
  [fill.qnt](fill.qnt) models both. A departed record blocks its key until a
  pass or an invalidation, as that model's `InProgress` does.
- Followers, the terminal credit a joined follower keeps, a publication that
  finds the shard terminal or the volume closed, malformed tables and their
  `Corrupt` refusal, unwinds, budgets and gate
  tries are omitted. A fill uploads at its reservation, so every publication
  is of a complete fill.
- `kept` and the event are history the invariants read; production keeps
  neither.

| Property | Guarantee |
|---|---|
| `UploadHoldsClaims` | A reserved fill holds its place, and the credits reserved cover two for every reserved fill. |
| `ReadyNeverRefusesFull` | A publication never refuses for index room or for credit: both refuse at the reservation. |
| `ClaimsReturnOnce` | `p` equals the places records hold and `c` the credits fills and leases hold: each claim is spent or refunded once. |
| `RefusalKeepsIncumbent` | A refused reservation or publication leaves every key's visible object as it was. |

[claims_check.py](claims_check.py) checks `safety`, the conjunction of the
four, with the free scheduler at `BOUND = 8` steps. Twenty-one reachability
witnesses, each checked as the inverted invariant `not(witness)`, reach every
outcome the unmutated model can produce: a reservation and its three refusals, with
`InProgress` against a reserved and against a departed record and
`IndexFull` also for a key that has a visible object; an activation, a
replacement and a late publication, the last also beside an incumbent; an
abort; a pass that refunds a place, one that only frees records and one that
finds none; an invalidation that removes, that revokes a reserved fill, that
revokes a departed one, that does both and that finds nothing; a revoked
fill's refused publication; and a lease's release. Two directed runs are
checked with `BOUND` set to the recipe's length, each with its reachability
case: `claims-run-refunds` (an aborted fill refunded by a pass, then a late
publication refunded under its own hold, the ledger at zero after each) and
`claims-run-revoked` (a published key, a replacement revoked by an
invalidation, the revoked fill's refusal and the lease's release, the ledger
at zero). Four mutations each break the property that names the case: a
reservation that reserves one credit (`UploadHoldsClaims`), a reservation
that takes no place, at a limit of 1, so a complete fill refuses `IndexFull`
(`ReadyNeverRefusesFull`), an abort that returns the place at once
(`ClaimsReturnOnce`) and a late publication that ends the incumbent
(`RefusalKeepsIncumbent`). These are finite checks at the stated bounds; no
refinement mapping to the implementation is claimed.

## Buffer pool model

[pool.qnt](pool.qnt) models one buffer pool of the arena, the obligation set,
device reference count and incarnation that `storage/device/pool.rs` keeps for
each buffer under the decisions of `storage/device/custody.rs`. It restates
the invariant of the obligation record `nic-references-keep-buffer-off-stack`
and, for the two properties the table below marks, clauses of the records
`census-and-free-stack-match-an-independent-per-buffer-oracle` and
`terminal-identities-issue-last-and-never-repeat`. It claims nothing stronger.

The finite instance has two buffers, incarnations 0 to 3 in place of the
64-bit count, and at most two device references per buffer. A buffer is
`Free` on the free stack, `App` behind a live handle, `Storage` inside a
command record, `Quarantined` once its command was cancelled, `Posted` to a
device for receive, `Nic` once its handle ended while a device still reads
it, or `Retired`. `acquire` and `post` pop the top of the free stack and
report `Exhausted` on an empty one. `drop` ends a handle: the buffer frees,
or becomes `Nic` while references remain. `lend` takes a reference the caller
keeps and `unlend` returns it; `give` takes a reference the device owns, and
`handoff` takes one and ends the handle in the same call. `ret` is a raw
return naming a buffer and an incarnation: it ends one reference of the
buffer's current incarnation, and any other return only counts as
mismatched. The last reference to end frees a `Nic` buffer and leaves a
handle's buffer `App`. `view` asks a handle for a mutable view, refused while
a reference is out. `store`, `restore`, `detach` and `discard` are the
command table's moves, and `complete` and `unpost` end a posting. A buffer
that frees starts its next incarnation on top of the free stack, and one
that frees at the last incarnation retires.

Abstractions:

- Each action is one call, taken whole, on one thread, as the pool's cells
  require.
- Bytes, spans and addresses, the other pools, the by-index posting run, the
  packet-pool view and the mempool service that close a kind to `acquire` and
  `post`,
  held bytes and the high-water mark are omitted.
- The cap of two references per buffer keeps the model finite: at the cap,
  `lend`, `give` and `handoff` are disabled. The pool's `HoldError::Cap`
  refusal at `u16::MAX` references is omitted. `store` is enabled only with
  no reference out; with one out, production's `into_storage` panics.
- `lent` and `raw` are the references the caller keeps and the device owns.
  The device returns only a reference it owns, and `ret` is otherwise enabled
  only for a return that names no reference of the current incarnation.
  `issued` and `reissued` are history the last invariant reads; production
  keeps neither.

| Property | Guarantee | Record clause |
|---|---|---|
| `HeldStaysOffStack` | A buffer with a reference out is off the free stack, behind its handle or `Nic`. | `nic-references-keep-buffer-off-stack`: "while a device reference is out the buffer stays off the free stack" |
| `ReferencesCounted` | A buffer's count equals the references out for its current incarnation, so an older incarnation's return ends none of them. | the same record: "an older incarnation's return frees nothing newer" |
| `NoMutableViewWhileHeld` | A mutable view is granted only with no reference out. | the same record: "and refuses a mutable view" |
| `Partition` | The free stack holds each `Free` buffer once and no other, the retired count equals the `Retired` buffers, and only an `App` or `Nic` buffer carries references. | `census-and-free-stack-match-an-independent-per-buffer-oracle`: each pool's census and free stack equal a per-buffer count |
| `IncarnationIssuedOnce` | No buffer leaves the free stack twice at one incarnation. | `terminal-identities-issue-last-and-never-repeat`: "no identity repeats", for the buffer incarnation |

[pool_check.py](pool_check.py) checks `safety`, the conjunction of the five,
with the free scheduler at `BOUND = 11` steps. Twenty-five reachability
witnesses, each checked as the inverted invariant `not(witness)`, reach every
action and outcome: an acquire and a posting, each also on an empty stack, a
handle's end that frees, that leaves the buffer `Nic` and that retires it, a
kept reference taken and returned to a handle's buffer and to a `Nic` one, a
device reference given and handed off, a matched return, one that frees the
buffer and one that leaves a count, a mismatched return and one that names
an older incarnation of a held buffer, a view granted and refused, and each
custody and posting move. Five directed runs are checked with `BOUND` set to
the recipe's length, each with its reachability case:
`pool-run-heldThroughDrop` (two references keep a dropped buffer off the
stack until the second returns), `pool-run-olderIncarnation` (a return that
names the previous incarnation is mismatched and the reference of the
current one still refuses a view), `pool-run-retire` (a buffer retires after
its last incarnation and the pool goes on with the other),
`pool-run-quarantine` (a detached buffer frees through its own path and
comes back at the next incarnation) and `pool-run-posting` (a completed
posting becomes a handle, and an unposted one a new incarnation). Five
mutations each break the property their case checks: a handle's end that
frees a held buffer (`HeldStaysOffStack`), a return that ignores the
incarnation (`ReferencesCounted`), a view that ignores the count
(`NoMutableViewWhileHeld`), a free that pushes nothing (`Partition`) and a
free that keeps the incarnation (`IncarnationIssuedOnce`). These are finite
checks at the stated bounds; no refinement mapping to the implementation is
claimed.

## Attach gate model

[gate.qnt](gate.qnt) models the attach gate of one volume under a serving
machine that holds the tenure's token before the fencing boundary:
`gate_step`, `gate_terminal`, `gate_judged`, `pass_gate` and
`gate_authority_lost` in `crates/kestrike/src/storage/volume/fence.rs`,
with the judgment of the gate's Report in `storage/volume/authority.rs`. It
restates the obligation record `attach-gate-precedes-every-medium-command`
and claims nothing stronger.

The gate issues Register, Acquire and Report, one command at a time. `tick`
is one poll of the volume: it submits the next gate command, and the driver
accepts it, refuses it for a full queue, which leaves the step for a later
poll, refuses it otherwise, which ends the attach with the command's
refusal, or reports the device gone, which loses the volume. `register` and
`acquire` complete their command with success or with a reservation
conflict; the conflict ends the attach with the command's refusal and, as a
deposing status, withdraws the serving machine with no flip request.
`report` completes the Report with one of nine views. The view of the own
pair as the one holder and registrant of a type-2 reservation passes the
gate: the driver admits medium commands once, the machine crosses the
boundary, the readiness word loads and the bootstrap submits its first
medium command. A foreign registrant, a foreign holder, another reservation
type and an own pair that does not hold refuse and withdraw the machine with
the flip request. A second record of the own host ID, withheld bytes and a
failed status refuse and leave the machine before the boundary. A deposing
status ends the attach as lost authority and withdraws the machine with no
flip request. `expire`, `withdraw` and `close` are serving-machine events
while the gate runs, and `timeout` is the Report's deadline; each ends the
attach as lost authority.

Abstractions:

- One own pair and at most one foreign entry. Each completion carries its
  view, so the model holds no registrant table.
- The Report deadline is one action. The serving window, the clock and the
  machine's later Reports are outside the model.
- `Storage::withdraw` and a volume close during the gate, a driver without
  reservation commands, the fencing-boundary values of the restart, the
  fresh acquisition and the takeover, and a standby without a token are
  outside the model.
- The bootstrap after the gate is one flag, `medium`. `sole` is history the
  invariants read; production keeps the Report's evidence in `Fenced`.

| Property | Guarantee |
|---|---|
| `NoMediumBeforeTheGate` | A medium command was submitted only after the gate passed. |
| `PassNeedsTheSoleReport` | The gate passed only on a Report that showed the own pair as the one holder and registrant, after all three gate commands. |
| `AdmitsExactlyOnce` | The driver admitted medium commands once when the gate passed and never otherwise. |
| `RefusalEndsWithNoMedium` | A refused gate has no medium command and no admission, and fill admission is withdrawn. |
| `LoadingOnlyAfterTheGate` | The readiness word loads only when the gate passed. |

[gate_check.py](gate_check.py) checks `safety`, the conjunction of the five,
with the free scheduler at `BOUND = 8` steps. Twenty-four reachability
witnesses, each checked as the inverted invariant `not(witness)`, reach a
submitted command, a busy submit, a lost device, an idle poll before and
after the pass, a refused submit; each of the Register's and the Acquire's
two completions; each of the nine Report views; an expiry, also after a gate
command and before the Report, a withdrawal, a close and the Report's
timeout. Four directed runs are checked with `BOUND` set to the recipe's
length, each with its reachability case: `gate-run-passes`,
`gate-run-busy-then-foreign-registrant`, `gate-run-acquire-conflict` and
`gate-run-report-times-out`. Five mutations each break the property that
names the case: a medium command submitted with the Report
(`NoMediumBeforeTheGate`); a gate that passes on the Acquire
(`PassNeedsTheSoleReport`); a refusal that admits (`AdmitsExactlyOnce`); a
foreign-registrant refusal with a medium command
(`RefusalEndsWithNoMedium`); and a readiness word that loads at the first
gate command (`LoadingOnlyAfterTheGate`). These are finite checks at the
stated bounds.

[gate_replay.rs](../crates/kestrike/src/storage/volume/gate_replay.rs)
(`storage::volume::fence::tests::gate_replay`) replays the committed traces
against the volume's attach and compares the projected state at each trace
state; it covers the committed schedules only. Its driver delivers the model's
`withdraw`, which carries the flip request, as `Cause::Attachment`, a
retirement trigger. A withdrawal for a planned exit during the gate, which
requests no flip, is outside the model; the Rust tests
`storage::volume::attach::tests::a_withdrawal_close_or_window_expiry_during_any_gate_step_ends_the_attach`
and
`storage::volume::attach::tests::a_planned_withdrawal_before_the_first_gate_command_ends_the_attach_with_no_command`
step it before the first gate command and while each gate command is
outstanding.

## Grace model

[grace.qnt](grace.qnt) models the grace protocol of one slot: the `pin`,
`unpin`, `bump`, `PassCursor` and `releasable` of `storage/grace.rs`, with
the callers' acts that the protocol orders, a reader's observation of the
entry, the entry's removal, the anchor's release and the slot's reuse. It
restates the invariant of the obligation record
`grace-sc-points-protect-pinned-reader`, "a pinned reader never observes a
released anchor or a reused slot", as `Protected`, its only property.

The finite instance has two readers with one registration record each, one
slot whose entry is retired once, one maintainer, and a terminal band that
starts at era 3. The era starts at 1. A record holds zero or the era its
reader pinned. `pin` refuses `Terminal` from era 3 on, refuses `Active` on a
record that still holds a pin, and otherwise stores the era. `observe` is a
pinned reader's look at the entry: the reader holds a copy exactly when the
entry was visible at its latest observation, and `unpin` clears both its
record and its copy.
`remove` ends the entry's visibility, and `retire` is the bump of the
removed entry: it stamps the retirement with the era it found, advances the
era and marks the anchor. `elsewhere` is the bump of a retirement of some
other slot, which only advances the era. Either bump reports that it closes
admission when the era it found is 2 or more: the last era below the
terminal band, or any era in it. `begin` starts a pass at the current era, `visit` reads the
next record and keeps the smallest pin seen, and `complete`, enabled once
both records are visited, raises the certified era to the smaller of the
start era and that pin when that is higher, and otherwise keeps it. `release` asks whether the stamp lies strictly below
the certified era and releases the anchor when it does; `reuse` follows a
release.

Abstractions:

- Each action is one call of the `grace` module or one act of its callers,
  taken whole, and the actions interleave in one total order. The model
  assumes the `SeqCst` order the module's argument establishes; the loom
  kernel `storage::grace_model` and the GenMC and RC11 lanes own the memory
  orderings.
- A reader's state is its pin and its copy. The copy stands for every read
  the interval protects: lease rights, the slot's lifetime word, the
  fingerprint the stamp overlays and the payload. The loom kernel
  `storage::grace_model` covers these.
- The claimed bound is fixed at both records, the pass cursor has one
  holder, and the admission cutoff that a closing bump stores is the
  caller's and is recorded only as the bump's flag.
- `copies` and the event `ev` are history that the invariant and the
  witnesses read; `released` and `reused` are state that the invariant also
  reads.

| Property | Guarantee |
|---|---|
| `Protected` | No reader holds a copy it observed under its current pin once the anchor is released or the slot reused. |

[grace_check.py](grace_check.py) checks `safety`, which is `Protected`,
with the free scheduler at `BOUND = 10` steps. Twenty-two reachability
witnesses, each checked as the inverted invariant `not(witness)`, reach
every action and every outcome: a pin that succeeds, one after a bump, one
refused `Active` and one refused `Terminal`; an observation that finds the
entry and one that finds it gone; an unpin, the removal, a retirement and a
bump elsewhere, each with and without the closing flag; a pass's start, a
visit of a pinned and of an inactive record, a completion that raises the
certified era to the start era, one that raises it to a pin and one that
keeps it; a release that succeeds, one that is held and one that is held
while a reader holds a copy; and the reuse. Four directed runs are checked
with `BOUND` set to the recipe's length, each with its reachability case:
`grace-run-readerBeforePass` (a reader pinned before the retirement holds
the anchor through a complete pass), `grace-run-passBeforeReader` (a reader
that pins between two visits of a pass that began first holds it as well),
`grace-run-releaseAfterUnpin` (the next pass after the unpin releases and
the slot is reused) and `grace-run-terminalRefusesPins` (two bumps reach the
terminal era, later pins are refused and the earlier pin stays). Four
mutations each break `Protected`: a release at a stamp equal to the
certified era, a completion from a pass that visited one record, a bound
that ignores the pins seen, and a retirement before the removal. These are
finite checks of the model at the stated bounds. The replay below ties the
model to the implementation for the schedules its traces record.

### Replay against the grace words

`crates/kestrike/src/storage/grace_replay_tests.rs` replays committed
traces of the model against the module's `pin`, `unpin`, `bump`,
`PassCursor` and `releasable` at the production strength `Sequential`, over
`std` atomics on one thread. After every step it requires the call's
return, and the outcome the replay derives from it, to equal the step's
event, and the era word, both pin words, the certified
word and the pass cursor to equal the model's state; `observe`, `remove` and
`reuse` are the callers' acts, and the replay checks that the words stay
unchanged across them. A nonzero model era `e` is production era
`ERA_TERMINAL - 3 + e`, and zero, the inactive record and the unset
certificate, stays zero, so the model's terminal era is the production
one. [grace_fixtures.py](grace_fixtures.py) writes the traces
with `quint run --mbt`: seven directed recipes and six traces of sixteen
steps of the model's own `step` under pinned seeds, which together reach
`init` and every choice of `step` with each outcome; the test asserts that
set. Each trace names the model's sha256. Controls: a driver that releases
at a stamp equal to the certified era, one that skips the second visit and
one that skips the unpin each fail at the step they change, and a trace
with a raised certified era fails at its state. The replay is evidence for
exactly the schedules these traces record.

## Receive window model

[window.qnt](window.qnt) models the client's receive core for one GET, as
`FetchCore` in `crates/kestrike/src/net/fetch.rs` keeps it: the manifest
START binds, the fragments held in the window, handed to the application
and released, the grant, and the request's one outcome. Its family in
[check.py](check.py) is `window`. It restates five sentences of that
module's documentation, each of which the code checks with a refusal, and
claims nothing stronger: a fragment is accepted only at or above the receipt
base and below the grant; DATA before START is held without exposure, and a
fragment naming another manifest is dropped; only fragments below the base
are handed out, in order; success requires START, every fragment and
COMPLETE; and a request that ends otherwise after a fragment was handed out
ends `Incomplete`.

The finite instance is one request of three fragments through a window of
two, under two manifests, `A` and `B`, of three fragments each, and a third,
`Big`, above the GET's caps. Each step is one call on the core or one owner
frame, and its event records what the call shows:

- `poll` folds the released grant in and sends the one due frame, a CANCEL,
  a GET before START or an ACK with the receipt base and the grant. The
  transport takes the frame or refuses it, which leaves it due.
- `start`, `data`, `complete` and `error` deliver one owner frame. START
  binds its manifest, repeats, is ignored under another manifest, or ends
  the request when it names `Big`. A DATA frame is held or dropped. An ERROR
  is a miss, a pressure refusal or a failure.
- `take` hands the application the next fragment in order, `release` drops
  the application's lease of a fragment, `cancel` ends the request and
  `close` retires it once it is decided and its CANCEL went out.
- `retry` is the retry timer, `deadline` the request's deadline and
  `endSession` the end of its session.

The model keeps the credit rule that decides when a grant raised by releases
goes out by itself: the highest fragment received, the base and the grant
the owner last learned, and the burst, the most fragments received beyond
that base. An ACK is due for the raised grant once the advertised grant
admits at most one burst beyond the highest fragment received.

Abstractions:

- The owner is the environment: any frame may arrive in any state, under
  either manifest. Frames whose index, offset or length disagree with the
  manifest they name are not modeled, because the frame parser refuses them
  before the core.
- Time is the three timer actions. The resend budget and its doubling wait,
  the gap ACK's wait and receipt mask, receive-pool pressure, fragment bytes
  and lengths, the wire identity and a second request are omitted.
- `foreign` and `completed` are history the invariants read; production
  keeps neither.

| Property | Guarantee |
|---|---|
| `InWindow` | A held fragment lies at or above the fragments handed out and below the grant. |
| `BoundManifest` | Nothing is handed out and the base stays at zero before START; after it every held fragment and every fragment handed out names the bound manifest. |
| `InOrder` | The fragments handed out are those below the receipt base, in order. |
| `CompleteNeedsAll` | `Complete` follows START, a base at the fragment count and an accepted COMPLETE. |
| `ExposedIsIncomplete` | A miss, a pressure refusal or a failure is the outcome only when no fragment was handed out, and `Incomplete` only when one was. |

[window_check.py](window_check.py) checks `safety`, the conjunction of the
five, with the free scheduler at `BOUND = 14` steps. Forty-two reachability
witnesses, each checked as the inverted invariant `not(witness)` at
`BOUND = 14`, reach every action and every result an action records, among
them a START that drops every fragment held for another manifest, one that
exposes held fragments, a fragment at the grant, a resent fragment below the
base, an ACK that carries a raised grant, a fragment handed out after
`Complete`, and a lease released after close. Seven directed runs are
checked with `BOUND` set to the recipe's length, each with its reachability
case: `window-run-complete`, `window-run-heldBeforeStart`,
`window-run-incomplete`, `window-run-cancel`, `window-run-otherManifest`,
`window-run-deadline` and `window-run-startHoldingNothing`, a START with no
fragment held, which does not meet the dropped-fragments witness. Five
mutations each break the property that names the
case: a fragment accepted at the grant (`InWindow`), a START that keeps the
fragments of another manifest (`BoundManifest`), a `take` that hands out the
fragment at the base (`InOrder`), a COMPLETE accepted with fragments missing
(`CompleteNeedsAll`) and an ERROR after a handoff that keeps its status's
outcome (`ExposedIsIncomplete`). These are finite checks at the stated
bounds; no refinement mapping to the implementation is claimed.

## Visit model

[visit.qnt](visit.qnt) models how the service pass of `storage/release.rs`
returns a retired object that holds several extents: one extent a visit,
from the last, while the anchor that a visit releases once
`storage/grace.rs` certifies its era and a lease's right each hold the
object. It restates three clauses of the
obligation record `service-returns-one-extent-per-visit` and claims nothing
stronger: a minimum-funded visit returns at most one extent, the last held
one, moving its charge to free; the slot persists until the final visit,
which returns the last extent and the slot once; and the anchor before
grace and a lease's right each withheld alone hold the object.

The finite instance has two keys, objects of one, two or three extents, and
at most one retired object. `publish` makes an object of `n` extents visible
under a key that has none; the publisher keeps its lease or drops it.
`invalidate` retires the key's object while no other object is retired: the
retired object holds all its extents, its anchor, and its lease's right if
the publisher kept it. `certify` releases the anchor. `release` drops the
retired object's lease, and `read` reads the retired object under it.
`visit` is one minimum-funded service call: it returns nothing while no
object is retired or while the anchor or the right holds it; otherwise it
returns the last held extent, and when that was the only one, the slot.
`charge` counts the extents the retired object's charge covers.

Abstractions:

- Each action is one atomic step: one call. The orders inside the pool gate
  and the anchor's compare-exchange stay with the loom kernels.
- One object is retired at a time, so a visit's choice among several
  eligible slots, the pass cursor and its coverage are outside the model.
  The parked phase, device access as a third blocker, maintenance, close and
  finalization stay with the record's own tests.
- An extent stands for its record's units and a publication for a fill's
  whole upload; the fill's steps stay with
  `storage/sequence_write_tests.rs`. A lease is one right, kept from the
  publication; lookups that retain further rights are omitted.
- `single`, `heldBack` and the event are history the invariants read;
  production keeps none of them.

| Property | Guarantee |
|---|---|
| `OneExtentPerVisit` | A visit returns at most one extent, and the one it returns is the last the object held. |
| `BlockersHold` | A visit returns nothing from an object its anchor or a lease's right holds. |
| `SlotUntilLastExtent` | The retired object keeps its slot exactly while it holds an extent. |
| `ChargeFollowsExtents` | The retired charge equals the extents the retired object holds. |

[visit_check.py](visit_check.py) checks `safety`, the conjunction of the
four, with the free scheduler at `BOUND = 8` steps. Fifteen reachability
witnesses, each checked as the inverted invariant `not(witness)`, reach every
outcome the unmutated model can produce: a publication with its lease
dropped and kept; a retirement without and with a right; a certification
that releases an anchor and one that finds none; a lease's drop; a read of a
retired object that holds every extent; a visit held by the anchor alone,
by the right alone, and one that finds nothing retired; the first and the
second partial return of a three-extent object; and the final return of a
three-extent and of a one-extent object. Two directed runs are checked with
`BOUND` set to the recipe's length, each with its reachability case:
`visit-run-three-extents` (a visit held by the anchor, the certification,
two partial returns, the final return and an idle visit, the charge at
zero) and `visit-run-right-held` (a kept lease that holds a certified
object through a visit and a read, then its drop, a partial return and the
final return). Four mutations each break the property that names the case:
a visit that returns two extents (`OneExtentPerVisit`), a visit that checks
the anchor alone (`BlockersHold`), a final return that keeps the slot
(`SlotUntilLastExtent`) and a partial return that leaves the charge
(`ChargeFollowsExtents`). These are finite checks at the stated bounds; no
refinement mapping to the implementation is claimed.

### Replay of the visit model

`python3 quint/visit_check.py --quint QUINT --output DIR` writes eight
traces with `quint run --mbt`, with `BOUND` set to each trace's length: four
directed recipes (`three_extents`, `right_held`, `beside`, `direct`) and four
traces of sixteen steps of the model's own `step` under pinned seeds. They
are committed under `crates/kestrike/src/storage/visit_replay_fixtures`,
each naming the model's sha256, and `storage::visit_replay_tests` replays
them through the storage facade and the simulated device, on one thread,
with objects a fill streamed to the device and published: `Storage::invalidate`
for the retirement, `Storage::certify`, the lease's drop, a read of the
whole retired object under its lease, and one `Storage::service` call funded
at `service_minimum` for a visit. After every step the replay compares the
call's outcome with the step's, a visit's from the report's serviced and
partial counts, then the raw ledger's free, reserved, resident and retired
bytes with arithmetic over the model's visible objects and the extents its
retired object holds, through the record layout, and each key's lookup with
the model's visible version. A `read` step compares the bytes read under
the retired object's lease with its version's payload. Together the traces
reach `init`, every choice of `step` and every outcome of the unmutated
model. The replay covers these traces of gate-ordered steps; it is evidence
for them and for no other schedule.

## Reclaim model

[reclaim.qnt](reclaim.qnt) models the reclamation of one slot on a live
storage: a reader's entry into a protected interval and its exit, lease
rights, the object's retirement, `Storage::certify`, `Storage::service` and
the publication of the next object into the returned slot. It restates the
first clause of the invariant of the obligation record
`mc-cas-result-reclamation`, "a reader's payload read precedes the slot's
reuse, the slot returns once per incarnation and is reused as incarnation
two", as its three properties.

The finite instance has one slot, two readers with one registration record
each, at most two lease rights and one maintainer. The era starts at 1 and
the first object is resident under incarnation 1 with its anchor and one
lease. `enter` pins the current era in the reader's record, and the reader
watches the object when the object is resident at that moment; `exit` clears
the pin. `lease` duplicates a held right and `unlease` drops one. `retire`
stamps the object with the era it found and advances the era; the anchor
stays counted. `certify` is one call funded for one record: with no pass in
progress it begins one only when the era exceeds the certified era and
otherwise reports the certified era; it visits one record, keeping the
smallest pin seen, and completes the pass when that was the second record,
raising the certified era to the smaller of the start era and that pin when
that is higher. `service` is one call: on a retired slot it releases the
anchor when the stamp lies strictly below the certified era, then returns
the slot when neither the anchor nor a right is counted, and otherwise
holds it; on a resident or free slot it visits nothing. `republish` gives
the returned slot to the next object under the next incarnation, with its
anchor and one lease.

Abstractions:

- Each action is one storage operation, taken whole, and the operations
  interleave in one total order; the loom kernel `storage::grace_model` and
  the GenMC and RC11 lanes own the memory orderings inside an operation.
- A reader's payload read is its protected interval: `watch` records the
  incarnation a reader pinned while the object was resident, and
  `ReadersPrecedeReuse` holds that incarnation's slot until the reader
  exits.
- The object is one direct extent in one slot, every operation takes a
  free gate and is funded, and every retirement is recorded under the
  gate.
- The terminal band lies above every era the instance reaches.
- `watch`, `returns` and `published` are history that the invariants read;
  the event `ev` is history that the witnesses read.

| Property | Record clause | Guarantee |
|---|---|---|
| `ReadersPrecedeReuse` | "a reader's payload read precedes the slot's reuse" | While a lease right is out, or a reader that entered while the object was resident is still pinned, the slot is neither returned nor reused. |
| `ReturnsOnce` | "the slot returns once per incarnation" | An incarnation's slot returns at most once. |
| `ReusedAsNext` | "and is reused as incarnation two" | The object published into a returned slot carries the next incarnation. |

[reclaim_check.py](reclaim_check.py) checks `safety`, the conjunction of
the three, with the free scheduler at `BOUND = 11` steps. Eighteen
reachability witnesses, each checked as the inverted invariant
`not(witness)`, reach every action and every outcome: an entry, and one
after the retirement; an exit; a lease taken and one dropped; a retirement,
and one of the second incarnation; a certification call that is idle, one
that advances, one that certifies and one that certifies below the current
era; a service call that visits nothing, one held while its anchor awaits a certified
era above the stamp, one held by a right, one that releases the anchor under a right, a return with the anchor
last and one with a right last; and the next publication. Four directed
runs are checked with `BOUND` set to the recipe's length, each with its
reachability case: `reclaim-run-anchorLast` (with every right dropped, the
call that releases the anchor returns the slot), `reclaim-run-rightLast`
(the anchor is released under a right and the slot returns after the right
drops), `reclaim-run-pinnedReaderHolds` (a reader pinned before the
retirement holds the slot through a complete pass, and the pass after its
exit releases it) and `reclaim-run-reuse` (two lifecycles end in
incarnation 3). Five mutations each break the property their case checks: a
return under a right, a bound that ignores the pins seen and a release at a
stamp equal to the certified era (`ReadersPrecedeReuse`), a return that
keeps the slot retired (`ReturnsOnce`) and a publication that keeps the
incarnation (`ReusedAsNext`). These are finite checks of the model at the
stated bounds. The replay below ties the model to the implementation for
the schedules its traces record.

### Replay against a live storage

`crates/kestrike/src/storage/reclaim_replay_tests.rs` replays committed
traces of the model against a `Storage` on the heap-backed platform with
one slot and two registered readers. Each step runs the storage code for
one model action: `Registration::enter` or the exit of its guard, a
lease's test-only `duplicate` or its drop, the resident's test-only
`retire` over the production retirement, `Storage::certify` funded for one
record, `Storage::service`, or the next object's publication through the
`grace_tests` helper (reserve, complete, handoff). After every step the
replay requires the call's return, and the outcome the replay derives from
it, to equal the step's event, and the era report, both records' pins, the
slot's state, incarnation, count and stamp, the pass cursor and
`Storage::outstanding` to equal the model's state. Each reader runs on its
own thread, which owns its registration and holds its guard between an
entry and the exit; the replay sends one command at a time and waits for
the reply, so one call runs at a time and the replay covers the order of
whole calls, with the orderings inside a call left to the loom kernel
`storage::grace_model` and the GenMC and RC11 lanes.
[reclaim_fixtures.py](reclaim_fixtures.py) writes the traces with
`quint run --mbt`: five directed recipes and six traces of eighteen steps
of the model's own `step` under pinned seeds, which together reach `init`
and every choice of `step` with each outcome; the test asserts that set.
Each trace names the model's sha256. Controls: a driver that keeps a guard
past its exit, one that keeps a dropped lease and one that skips the
certification call that completes a pass each fail at the step they
change, and a trace with a raised certified era fails at its state. The
replay is evidence for exactly the schedules these traces record.

## Extent allocator model

[extent.qnt](extent.qnt) models the placement of one volume's extent
allocator, the reservation and the return of `storage/extent/allocator.rs`
over the capped run index of `storage/extent/index.rs` and the first fit of
`storage/extent/bitmap.rs`. It restates four clauses of the invariant of
the obligation record `index-names-maximal-free-runs-placement-follows-fit`
and, for the property the table below marks, two clauses of the record
`owned-extents-disjoint-ledger-matches-census`. It claims nothing stronger.

The finite instance has eight units and an index of at most two runs, and
reserves one to three units. A run is a length and a start, ordered by
length and then start, as the index keys are. `reserve` refuses `NoFit` when
no maximal free run holds the units. Otherwise it takes the units from the
low end of the smallest indexed run that holds them, removes that run's key
and indexes its remainder, the outcome `Indexed`; with no such indexed run
it takes them from the lowest free run that holds them and offers that run's
remainder to the index, the outcome `Fallback`. `release` refuses `NotHeld`
when the extent passes the volume's end or covers a free unit. Otherwise it
frees the extent's units: with no free unit on either side it offers the
extent as a run, the outcome `Alone`, and with one it removes the
neighbours' keys and offers the joined run, the outcome `Joined`. An offer
to an index below its capacity adds the run. An offer to a full index counts
one drop and keeps the larger of the offered run and the smallest entry.

Abstractions:

- Each action is one call, taken whole, on one thread.
- The index is a set of keys. Its trees, leaves and descents, the bitmap's
  words and the run summaries are omitted, with the visits they count, the
  work limit, the budget and the `Length`, `BudgetExhausted` and `Ledger`
  refusals.
- The ledger's terms, the placeable count and its charge, the saturated
  length of a run of 2^24 - 1 units or more, a run reservation with its
  count and tail, `publish`, `retire` and the restoring constructors are
  omitted.
- `held` holds the extents reserved and not returned. The caller returns
  only an extent it holds or one the allocator refuses; a return that names
  taken units of another extent is outside the model, as it is outside the
  allocator's held check. `misplaced` is history the fit invariant reads.
  The allocator keeps neither.

| Property | Guarantee | Record clause |
|---|---|---|
| `IndexNamesMaximalRuns` | Every indexed run is a maximal free run. | `index-names-maximal-free-runs-placement-follows-fit`: "index keys name maximal free runs" |
| `NoDropsMeansWholeFreeSet` | While the drop count is zero, the index holds every maximal free run. | the same record: "zero drops means the index holds the whole free set" |
| `IndexWithinCapacity` | The index holds at most its capacity. | the same record: "a full-index offer drops its smallest key" |
| `PlacementFollowsFit` | No reservation passed over a smaller indexed run that held it, or, without one, over a lower free run that held it. | the same record: "a reservation takes the best indexed fit by length then start, else first fit, else NoFit" |
| `HeldDisjoint` | Held extents lie inside the volume and share no unit, and the free units are exactly the units no held extent covers. | `owned-extents-disjoint-ledger-matches-census`: "owned slots hold disjoint in-volume locators" and "a return frees only its own record's extent" |

[extent_check.py](extent_check.py) checks `safety`, the conjunction of the
five, with the free scheduler at `BOUND = 15` steps. Fourteen reachability
witnesses, each checked as the inverted invariant `not(witness)`, reach every
outcome of both actions: an indexed fit, one that takes its whole run and
one that passes a lower free run for a smaller indexed one, a fallback, a
refusal with no fit and one with enough free units scattered, a return that
stays alone, one that joins and one that joins on both sides, a refused
return, a drop, a return after a drop whose start lies in an indexed run, a
state with a free run outside the index, and a whole volume indexed again after a drop. Four
directed runs are checked with `BOUND` set to the recipe's length, each with
its reachability case: `extent-run-bestFit` (a one-unit reservation takes
the two-unit run at unit 6, the smaller indexed run, and the three-unit run
at unit 0 stays indexed),
`extent-run-fullIndexDrop` (a one-unit run offered to the full index is left
out, and the joined run that follows replaces the smallest entry),
`extent-run-fallback` (with the indexed runs used up, a reservation falls
back to the dropped run by first fit) and `extent-run-notHeld` (a return
that covers a free unit and a second return of one extent are refused and
change nothing). Five mutations each break the property their case checks:
a join that keeps a neighbour's key (`IndexNamesMaximalRuns`), a split that
forgets its remainder (`NoDropsMeansWholeFreeSet`), a full offer that keeps its
smallest entry beside a larger offered run (`IndexWithinCapacity`), an
indexed fit chosen by start (`PlacementFollowsFit`) and a reservation that leaves its units free
(`HeldDisjoint`). These are finite checks at the stated bounds; no
refinement mapping to the implementation is claimed.

## Watermark client model

[watermark.qnt](watermark.qnt) models the store client's watermark,
`Client` of `crates/kestrike/src/storage/store/client.rs` over
`Watermark::observe` of `storage/store/watermark.rs`. It restates what those
two module docs state and the client refuses by: a result below the
watermark is a regression that withdraws the client, a failed record of a
raised watermark withdraws it, a withdrawn client issues no further request,
and while the client is not withdrawn the watermark it checks against is the
one its log holds. It claims nothing stronger. Its purpose is a model whose
traces replay against the client.

The finite instance has one shard record with at most four versions, one
client process at a time, one other writer and one host log. A record value
stands for the record's `(g, E)` in its order: the attempt counter at the
first generation, and ten plus the attempt counter after the one flip. Each
action is one client call, one store event or one host event:

- `readPass` reads the current value, `readStale` the previous version, and
  `readUnavailable` returns no value.
- `bumpPass` is the client's exact-version bump of the value it holds under
  a store that follows its contract. `bumpLost` and `bumpDoubleWin` are the
  kill arms: an acknowledgment of a write the store never applies, and a
  write applied whether or not its condition holds. `bumpTimeoutCommit` and
  `bumpTimeoutNoCommit` lose the reply of a write that commits under its
  condition or does not.
- `other`, `otherKeeps` and `otherFlips` are another writer's bump, its
  replace that keeps the value, and its flip to the next generation.
- `restart` ends the client process and starts the next one from the log.
  `logBreak` and `logMend` make the log fail its records and record again.

Abstractions:

- One record stands for every shard record and coverage page; volume
  records have no watermark entry and are outside the model. The adopted
  checkpoint and its `Regression::Checkpoint` are outside the model.
- The client bumps the value its last acknowledged read or bump returned, so
  the value it holds is never older than its mark. The client's refusal of
  an acknowledged commit at or below the mark is therefore reached only
  together with its refusal of a commit at an unexpected version.
- An absent record, a create, the namespace check and the successor rule are
  outside the model. A restart needs a log that records, as `Client::open`
  does.
- `adopted`, `late` and `ev` are history the invariants and witnesses read.
  `late` counts the calls that reach the store while the client is
  withdrawn.

| Property | Guarantee |
|---|---|
| `NoAdoptionBelowMark` | No call returns a value below the mark the client held: a lower version, a lower value, or the mark's version with another value. |
| `RefusalWithdraws` | A regression and a failed record of the raised mark each leave the client withdrawn. |
| `WithdrawnIsSilent` | No call reaches the store while the client is withdrawn. |
| `MarkIsDurable` | While the client is not withdrawn, the mark it checks results against equals the one its log holds. |

[watermark_check.py](watermark_check.py) checks `safety`, the conjunction of
the four, and each invariant alone, with the free scheduler at `BOUND = 9`
steps. Twenty-five reachability witnesses, each checked as the inverted
invariant `not(witness)`, reach every step choice and every outcome of the
unmutated model: a read admitted, a stale read admitted above the mark and
refused below it, each unknown outcome, a refused condition, a lost write
acknowledged and then found by the next read, a double win that commits and
one that regresses, a regression on the version alone, on the value alone
and on a reused version, a failed record, a call of a withdrawn client, and
a restart that keeps its mark, also above the store. The committed unknown
outcome is witnessed at the second step, where the record is at the held
version and the bump's append is the second version. Seven directed runs are
checked with `BOUND` set to the recipe's length, each with its reachability
case; `watermark-run-timeout-after-other`, a bump whose reply is lost behind
another writer's commit, appends nothing and does not meet that witness.
Eight mutations each break the invariant the table names for them:
`observe-accepts-any-result`, `observe-ignores-version`,
`observe-ignores-value` and `observe-ignores-reuse` break
`NoAdoptionBelowMark`; `refusal-keeps-serving` breaks `RefusalWithdraws`;
`withdrawn-issues-request`, a `readPass` that reads the store without the
withdrawn refusal, breaks `WithdrawnIsSilent`; `raise-without-record` and
`restart-from-empty-mark` break `MarkIsDurable`. Two more cases check a
mutation through the conjunctions the positive cases use:
`observe-accepts-any-result` through `safety`, and `restart-from-empty-mark`
through the `runSafety` of the run `watermark-run-restart-keeps-the-mark`.
`watermark-uncommitted-timeout-is-unwitnessed` checks the committed-timeout
witness itself: with a `bumpTimeoutCommit` that never commits, no state
meets the witness.
These are finite checks at the stated bounds; no refinement mapping to the
implementation is claimed.

## Volume loss model

[loss.qnt](loss.qnt) models the replacement of a lost volume for two shards
of one AZ: `Reconciler::replacement`, `create_replacement`, `release_hold`,
`retire` with `abandon`, and `add_spare` with `flip` in
`crates/kestrike/src/failover/reconcile.rs`, under the decision `decide`
and the `Receipt` of `failover/loss.rs`. It restates what those modules'
documentation states (LOSS-NEEDS-EVIDENCE, CORRELATED-HOLD,
CREATE-AFTER-ISSUE, IDEMPOTENT-PROVISIONING, ACTIVATION-FENCE) and claims
nothing stronger.

The finite instance has two shards, each with a shard record, a replacement
receipt and a first active volume (volumes 1 and 2), the volume records, two
hosts, host `h` owning shard `h`, two reconciler processes, one operator
process and a provider. A step is one operation of a process. Each action is
one store request, one provider call, one process event or one
control-plane event:

- `begin(p, op, shard)` starts a step and takes its observation: the lost
  volumes of its shard, kept by `replacement` and `abandon` until the read
  that decides on them, and whether the other shard has an impaired or lost
  volume, kept by `replacement`, `create` and `abandon`. That second value is
  the model's form of the `others` argument of the Rust steps, which counts
  the other impaired or lost volumes of the AZ; the model counts the other
  shard's. The step holds it twice: `others`, the count the step is passed
  and decides on, and `seen`, the control plane's state at that moment,
  which the invariants and witnesses read and no step does. The two are
  equal in the model, and the mutation `others-forced-to-zero` separates
  them. The operator runs `release`; a reconciler runs `replacement`,
  `create`, `abandon` or `flip`. A flip starts only for the volume the
  shard's current receipt records as created, which either reconciler reads.
- `request(p)` sends the process's next store request and returns its reply.
  A create commits only on an absent record, and every other write only at
  the version the process read. `unknown(p)` commits the next write when its
  condition holds and loses the reply. `crash(p)` ends the step before its
  pending request, the first one included, which also stands for a lost
  write that never committed. Either reconciler and the operator can crash.
- `call(p, result, reply)` sends the create under the token of the receipt's
  shard and attempt. A token the provider has seen returns the outcome it
  kept; a new token makes a volume (`make`), refuses for good (`fail`) or
  never arrives (`drop`), and the reply may be lost.
- `lose(v)`, `impair(v)` and `recover(v)` change a volume's health; a lost
  volume stays lost. `hostLoss(h)` loses a host, changes no record and no
  volume's health, and is read only by `witnessHostLossRetains` and the
  `decide-reads-host-loss` mutation.

The steps make the store requests below, in the Rust order; the
abstractions name the Rust requests the model abstracts.

- `replacement` reads the shard record and retains unless the observation
  shows its active volume lost. It then reads the receipt and creates it at
  attempt 1, held when the other shard has an impaired or lost volume. Over
  an existing receipt it writes the hold under that observation when the
  receipt is neither released nor held, and otherwise returns the receipt
  unchanged.
- `create` reads the receipt and refuses a held one. Under that observation
  over an unreleased receipt it writes the hold and refuses. It reads the
  shard record, returns a recorded volume, writes `issued` over an open
  receipt and calls the provider. A `Failed` reply writes the next attempt
  over the issued read, held under that observation unless released. A
  volume creates its volume record, or reads it provisioned after a refused
  create, and is written into the receipt over the issued read. A record
  found retired rereads the receipt and writes nothing.
- `release` reads the receipt, writes a held one unheld and released,
  returns an existing unheld one unchanged, and reports an absent one.
- `abandon` observes a receipt that records a lost volume and is not held,
  reads that volume's record and the shard record, refuses while the shard
  record names the volume active or spare, and writes the record retired
  over its read. It then reads the receipt again: the next attempt already
  open returns, a hold latched at the observed attempt refuses, and any
  other change refuses stale. Last it reads the shard record and writes the
  next attempt.
- `flip` reads the shard record, the volume record and the receipt, refuses a
  held receipt that records its volume, and names the volume spare; a volume
  already named spare skips to the flip. The flip rereads the shard record and
  the volume record, raises the volume record's version (ACTIVATION-FENCE),
  rereads the receipt, refuses a held receipt that records its volume, and
  flips the shard to generation 2, the one after the generation 1 its shard
  reread admits, with the volume active. A hold that latches after a receipt
  read leaves the write that read admitted in place, as `unheld` documents.

Abstractions:

- Each shard has one replacement generation. `replacement` decides only at
  the first generation, and the flip moves the shard to the second. A loss
  after the flip, a later generation's receipt and SUPERSESSION-FENCE are
  outside the model. The token is the pair of the shard and the attempt.
- The shard record holds the generation, the active volume and the spare, so
  the model's tenure check is the generation alone; the owner, `E`, the
  standby and the takeover, bump and designation writes are outside the
  model. The model's flip acts on the volume it started for and refuses
  another spare at its reread, where the Rust `flip` and `flip_for` activate
  the spare the shard names. The two agree in this instance, since only
  `retire_spare` and a second `add_spare`, both outside the model, replace a
  named spare.
- The layout and its floor, a layout conflict and the `Exhausted` refusal at
  the last generation are outside the model.
- Some refusals the steps restate never decide in this instance, since a
  shard has one replacement volume at a time and the flip is its only
  generation change: the generation check before the create step's issue
  write and before the abandon step's raise, the generation checks of the
  flip's two shard reads, which its check of the active volume shadows, the
  flip's refusal of another named spare, and the abandon step's refusal of a
  receipt that moved otherwise than to the next attempt or into a hold. With
  any one of them removed, every root's search has the same distinct-state
  count, so the searches are no evidence for those refusals; the Rust tests
  cover them. The decision's rule that loss evidence about another volume
  than the active one retains is not exercised either, since a shard's
  replacement volume is lost only after its first volume.
- A step observes every volume at once when it starts. The model has no
  incomplete view and no repeated-error rule for a `Lost` verdict: the
  observation's lost set is the model's input, and the Rust steps take the
  caller's evidence. The other-shard observation covers the other shard's
  first volume and its replacements; the judged shard's own volumes are
  outside it. A lost volume stays lost, so it counts for the other shard
  after its own shard flips away from it, and a later loss of the other
  shard's volume starts held. `CorrelatedHold` judges each step against
  `seen`, so a step passed a smaller count than the control plane showed
  breaks it; the Rust loop that computes the count is outside the model.
- The model assumes two entry rules. A flip starts only for the volume the
  current receipt records as created; the Rust `add_spare`, `flip` and
  `flip_for` proceed with no receipt. An abandon starts from its own
  observation of a lost recorded volume; the Rust `abandon` refuses unless
  the caller's observed receipt is unheld, records the volume of the
  `Retired` witness and still equals the stored receipt, and takes no health
  evidence, and the Rust `retire` checks neither rule. The receipt clause of
  `HostLossCreatesNothing` checks the replacement step's decision, its
  provider-call clause follows from the create step's receipt read, which
  refuses an absent receipt as `create_replacement` does, and its
  generation clause follows from the flip entry rule, so that clause is no
  evidence for the loop's flip gate.
- One volume state, `PROVISIONED`, stands for both the provisioning record
  and the fresh record with its attach event. `record_attach`, its write,
  the attach event and the attachment listing a spare needs (LISTED-SPARE)
  are outside the model. A duplicate create over a record still
  provisioning ends at the refused receipt write in the model and in Rust.
  Over a record that `record_attach` made fresh, the model's duplicate
  create also ends `condition` at its record write, where the Rust step
  returns the volume record, with the same records stored.
- These Rust requests have no model action: the volume read that ends each
  `created` return of `create_replacement`, and the flip's read and write of
  the displaced volume's record and its receipt write-back. A new
  retirement in Rust ends with a settling shard write over the shard read
  the model makes before the retire write; a volume found already retired
  takes a fresh shard read and then that write. The model has neither the
  settling write nor the fresh read, and `retire_spare` is outside the
  model. A replacement retired while named spare therefore stays spare, and
  a later flip of another volume refuses on it; the racing root can open the
  next attempt while the shard still names the retired volume spare, which
  the Rust settling write refuses. A lost volume named spare but not retired
  can still be activated by a pending flip, since no flip step reads volume
  health, as `flip_read` reads none.
- Every record a step reads is a well-formed record of this store instance.
  `Receipt::decode`'s refusals, the successor check `Receipt::succeeds`
  makes on a proposed receipt write, the namespace check and a volume record
  of another value under the returned name are outside the model; the Rust
  tests cover them.
- A store write and a provider call each take effect at one action. A
  process may wait at its pending request while every other process runs,
  so a request that lands after the other reconciler or the operator moved
  on is in the model; a process that starts a new step while its own
  earlier request is still in flight is outside it.
- `prov` is the provider's kept outcomes. `issued`, `made`, `recorded`,
  `calls`, `spares`, `flips` and `ev` are history the invariants and
  witnesses read. They read the last action through the definition `ev`
  and not through `st.ev`: Quint hands Apalache each case as one JSON
  string that repeats the type of `st` at every mention, and Apalache
  refuses a string above 20,000,000 characters with the message
  `error: error`. The largest case's string holds 15.7 million. A spare or
  flip record notes the generation of the shard record its write replaced
  and whether the step carries a receipt from a read; a flip starts only
  over an existing receipt, so every read carries one. A flip step drops the
  receipt it carries at its shard reread and again when its fence is
  acknowledged, so its flip record counts only a receipt read after the
  fence.

`safety` conjoins ten invariants. Eight of them conjoin named statements,
25 statements in all, and each statement has witnesses that reach the states
it constrains and mutations that must violate it by name:

| Invariant | Statement | Guarantee | Reached by | Broken by |
|---|---|---|---|---|
| `HostLossCreatesNothing` | `receiptNeedsLoss` | A shard has a receipt only when the control plane reported its first active volume lost. The replacement step's decision reads volume loss alone. | `witnessIsolatedStart`; the retaining side by `witnessHostLossRetains` and `witnessImpairedRetains` | `decide-reads-host-loss`, `decide-reads-impairment` |
| | `callNeedsLoss` | A provider call names only such a shard. The create step's receipt read refuses an absent receipt. | `witnessMade` | `create-ignores-absent` |
| | `flipNeedsLoss` | A generation changes only for such a shard. This follows from the flip entry rule. | `witnessFlipped` | `host-loss-flips` |
| `CorrelatedHold` | `opensHeld` | A receipt write that opens an attempt in a step that started beside an impaired or lost volume of the other shard holds it unless the operator released the replacement. | `witnessCorrelatedStart`, `witnessAbandonOpensHeld` | `start-opens-unheld`, `next-attempt-opens-unheld` |
| | `latchFollows` | A replacement or create step that reads an existing unheld, unreleased receipt after such a start goes on to latch it. | `witnessLatchDue` | `replacement-skips-latch`, `create-ignores-others` |
| | `latchKeeps` | A committed latch leaves the receipt held at the same attempt, phase and volume. | `witnessReplacementLatch`, `witnessCreateLatch` | `latch-writes-unheld`, `hold-writes-unheld`, `latch-drops-volume`, `hold-drops-volume` |
| | `callNeedsIsolation` | No provider call comes from a step that started beside an impaired or lost volume of the other shard, unless the receipt the step carries is released. | `witnessCreateAfterRelease` | `hold-continues-to-call`, `others-forced-to-zero` |
| | `holdNeedsImpairment` | A write holds a receipt only in a step that started beside an impaired or lost volume of the other shard, so a loss observed alone is never held. | `witnessCorrelatedStart`, `witnessReplacementLatch`, `witnessCreateLatch`, `witnessAbandonOpensHeld` | `start-holds-isolated`, `replacement-latches-isolated`, `create-holds-isolated`, `next-attempt-holds-isolated` |
| `HeldReadCreatesNothing` | | Every provider call follows a receipt the caller carries unheld. A hold that commits before an open receipt's issue write refuses that write, so the step makes no call; a hold that latches after the step holds an issued receipt leaves the call in place, and the record write that follows is refused. | `witnessMade`, `witnessCallOverLatchedHold` | `create-ignores-held` |
| `OnlyOperatorReleases` | `clearIsRelease` | Only the operator's write clears a hold, and it marks the receipt released at the same attempt, phase and volume. | `witnessRelease` | `isolated-observation-clears-hold`, `release-leaves-unmarked`, `release-drops-volume` |
| | `markIsRelease` | A write first marks a receipt released only when it is the operator's and clears a hold. | `witnessRelease` | `release-unheld`, `release-keeps-hold`, `reconciler-releases` |
| `ReleaseIsFinal` | `releasedUnheld` | A released receipt is unheld. | `witnessRelease`, `witnessOpensOverReleased` | `next-attempt-ignores-release`, `latch-ignores-release`, `hold-ignores-release` |
| | `releaseStays` | A write over a released receipt leaves it released. | `witnessOpensOverReleased` | `next-attempt-drops-release` |
| `CreateAfterIssue` | `callCarriesIssued` | The receipt a provider call's step carries shows the attempt issued, from the acknowledged issue write or from a read of an issued receipt. | `witnessMade` | `create-calls-over-created` |
| | `callFollowsIssue` | Every provider call under a token follows the committed `issued` write of its attempt. | `witnessMade`, `witnessKeptVolume` | `create-skips-issue` |
| `OneVolumePerToken` | | One token makes at most one volume. | `witnessKeptVolume`, `witnessMadeUnknown` | `provider-forgets-tokens` |
| `AttemptAdvancesOnlyOnTerminal` | `advanceIsTerminal` | A receipt's attempt moves past an earlier one only when the provider kept a refusal for that attempt's token or the volume it made is retired. It reads the provider's kept outcome, so an unknown create keeps its attempt. | `witnessFailedRaise`, `witnessAbandoned`, `witnessProvisionRetired` | `abandon-skips-retire`, `dropped-create-raises-attempt`, `provision-overwrites-record` |
| | `retiredIsLost` | Only a volume the control plane reported lost is retired. | `witnessRetired` | `abandon-ignores-loss` |
| `EveryVolumeRecorded` | `madeIsRecorded` | A volume a token made is recorded before the receipt moves past that token's attempt. A volume made under the current attempt may be unrecorded, as after a lost create reply. | `witnessNextTokenMakes`, `witnessStaleToken` | `unknown-raises-attempt`, `provider-forgets-refusals` |
| | `createdIsMade` | A created receipt records a volume its attempt's token made. | `witnessRecorded` | `record-writes-another-volume`, `token-omits-shard` |
| | `recordedHasRecord` | A created receipt records a volume whose volume record exists, since the create step writes that record first. | `witnessRecorded` | `record-skips-provision` |
| `ActivatesOnlyUnheld` | `spareReadUnheld` | Every spare write of a volume follows a receipt read that showed no hold of that volume. A hold that latches after that read leaves the write in place. | `witnessSpareNamed` | `spare-skips-receipt-read`, `held-check-ignores-hold`, `spare-ignores-hold` |
| | `flipReadUnheld` | Every flip of a volume follows a receipt read, after its fence, that showed no hold of that volume. | `witnessFlipped` | `flip-ignores-hold`, `flip-skips-recheck`, `flip-rechecks-before-fence` |
| | `activeNotRetired` | No activated replacement is retired. | `witnessFlipped`, `witnessAbandonNamedActive` | `flip-skips-fence`, `abandon-retires-active`, `abandon-retires-spare` |
| | `activatesOnce` | Every committed flip replaced a shard record of the first generation, so a shard flips at most once: one flip activates one replacement. | `witnessFlipped`, `witnessFlipRefused` | `flip-write-ignores-version` |

[loss_check.py](loss_check.py) checks `safety`, the conjunction of the ten,
from fifteen roots. A root is a fixed prefix of actions followed by an
exhaustive search of every free action up to `BOUND`: `init` searches 13
actions from the initial state, and every other root searches 9 actions
after its prefix. The roots are an open receipt (`opened`), an attempt
issued with its reconciler at the provider call (`issued`), a recorded
volume (`created`), a flip that named it spare (`spared`), a receipt held
beside an impaired volume (`held`), that hold released (`released`), a hold
latched by the second reconciler while the first stands at its call
(`latched`), a hold latched over the recorded volume (`covered`), an abandon
step at the retirement write of its lost volume (`failed`), that step beside
a flip at its spare write (`racing`), a flip at its receipt recheck after
its fence over the lost recorded volume (`fenced`), a flip that activated
the recorded volume after its loss (`flipped`), both reconcilers' flips of
the recorded volume at their flip writes (`dueling`), and a reconciler at
its provider call under the first attempt's token after the other recorded
that attempt's volume, retired it and opened the second attempt (`stale`).
Within 9 free actions of the other roots no second flip reaches its write
and no repeat of a token follows its volume's retirement, so `dueling` and
`stale` are the roots that search a flip write under contention and a
volume record create over a retired record. Each nonempty
root's safety case also checks, at the prefix's last turn, the root's
`STANDS` predicate in `loss_check.py`, which reads the receipt, a volume
record, the spare or the position of the processes that root names. A
mutation case takes its first free action only from a state that meets that
predicate, so a mutation that changes the prefix's path finds no violation.
The searches on this revision:

| Root | Prefix | `BOUND` | States generated | Distinct states | Depth |
|---|---|---|---|---|---|
| `init` | 0 | 13 | 29,638,727 | 3,897,847 | 14 |
| `opened` | 5 | 14 | 2,633,905 | 467,458 | 15 |
| `issued` | 9 | 18 | 14,378,780 | 2,375,464 | 19 |
| `created` | 12 | 21 | 9,899,424 | 1,469,139 | 22 |
| `spared` | 17 | 26 | 9,290,703 | 1,483,637 | 27 |
| `held` | 6 | 15 | 1,957,223 | 294,960 | 16 |
| `released` | 9 | 18 | 2,250,458 | 397,222 | 19 |
| `latched` | 13 | 22 | 11,583,148 | 1,788,011 | 23 |
| `covered` | 16 | 25 | 8,860,519 | 1,233,048 | 26 |
| `failed` | 17 | 26 | 5,395,378 | 919,579 | 27 |
| `racing` | 21 | 30 | 7,099,690 | 1,283,197 | 31 |
| `fenced` | 21 | 30 | 3,916,138 | 647,674 | 31 |
| `flipped` | 23 | 32 | 2,632,114 | 390,586 | 33 |
| `dueling` | 28 | 37 | 7,507,285 | 1,206,524 | 38 |
| `stale` | 24 | 33 | 2,411,838 | 410,007 | 34 |

Forty-four reachability witnesses, each checked as the inverted invariant
`not(witness)` under the root the runner names for it, reach the host-loss
path (`witnessHostLossRetains`), a replacement step that retains an impaired
volume, a receipt started unheld and held, a receipt read after which a
latch is due, the replacement's latch and the create's latch, a create
refused on a held receipt, also after the impairment recovered, the release,
a release that finds no receipt and one that finds it unheld, a provider
call after the release by a create step that started beside the impairment,
a next attempt opened unheld over a released receipt beside an impaired
volume, a provider call made while the stored receipt carries a hold latched
after the caller's issued read, both shards held, the issue write, a made
volume, a failed create, a new token's volume whose reply was lost, a repeat
that returns the kept volume and one that returns the kept refusal, a call
under the token of an attempt the receipt moved past, a token that made a
volume, the recorded volume, a record write
refused after a hold latched over its issued read, the attempt raised on a
refusal, a crash at the provider call after the issue write, a receipt write
committed with its reply lost, the retirement, the abandon, an abandon that
opens the next attempt held, an abandon that finds the next attempt open,
one refused by a hold, one refused on the volume a flip named spare and one
refused on the volume the flip activated, a volume record found provisioned
and one found retired after a refused create, the next token's volume, the spare write, a flip over an already named
spare, the flip, a flip write refused after the other reconciler's flip
committed, a retirement write refused while the flip's fence keeps a volume
provisioned, and a flip refused by a hold. `REACHED_BY` in `loss_check.py`
names, for each statement, the witnesses that reach the states it
constrains.

Seven directed runs are checked with `BOUND` set to the recipe's length,
each with its reachability case: `loss-run-host-loss` (a lost host whose
replacement, create and abandon steps write nothing),
`loss-run-isolated-replacement` (a create that makes the volume and loses
its reply, the second reconciler's repeat of the token, which returns the
kept volume with no new one, and the flip; the run checks both calls at
their own turns), `loss-run-crash-at-call` (the issuer crashes at its
provider call, checked at that turn with the receipt still issued and no
call made, and the second reconciler calls under the same token and records
the one volume at attempt 1), `loss-run-correlated-release` (a held receipt
refused before and after the impairment recovers, the release and the flip),
`loss-run-latch-after-issue` (a hold latched while the first create stands at
its call, its record write refused, the release, and the second reconciler's
repeat of the token recording the one volume), `loss-run-stale-token` (a
reconciler whose issued read predates the volume's recording and retirement
repeats the first attempt's token, finds the volume record retired and writes
nothing) and `loss-run-retirement` (the recorded volume lost, retired and
abandoned, the second attempt refused for good, and the third attempt's
volume flipped active).

Fifty-one mutations each break the statement the runner names for them, and
the table above lists them by statement. Forty-nine are found by the search
of their root. Two violate their statement at the last action of a
recipe: `host-loss-flips`, in which a decision that reads host loss as
volume loss carries a lost host through the receipt and the create to the
flip, and `token-omits-shard`, in which the second shard's create under a
token without the shard returns the first shard's volume and records it.
The mutations change one guard or one write each. `decide-reads-host-loss`
and `decide-reads-impairment` change the decision's evidence.
`others-forced-to-zero` passes every step a count of 0 while the control
plane shows an impaired volume, which is the control "`others` forced to 0
creates" of FP-LOOP-03 in issue #255. The four `-isolated` mutations hold a
receipt in a step that started beside no impaired volume, at the start, the
replacement's latch, the create's hold and the next attempt.
`provider-forgets-tokens`, a
provider that answers every repeat as a new token, breaks
`OneVolumePerToken`, so uniqueness rests on the provider's retention, and
`provider-forgets-refusals`, a provider that forgets a refusal once the
receipt moved past its attempt, lets a stale caller's repeat make an
unrecorded volume. `unknown-raises-attempt` and
`dropped-create-raises-attempt` are one mutation, a create that opens the
next attempt after a lost reply, checked against `madeIsRecorded` and
against `advanceIsTerminal`. `flip-rechecks-before-fence`, a flip that reads
the receipt with its volume read and goes from its fence to the flip write,
flips after a receipt read that predates the fence.
`flip-write-ignores-version`, a flip write that commits at any shard
version, lets both flips of the `dueling` root commit; each writes
generation 2, so the shard record does not show the second commit, and its
flip record shows that it replaced a record of generation 2.
`provision-overwrites-record`, a volume record create that commits over an
existing record, lets the stale repeat of the `stale` root write a retired
volume's record back to provisioned.

The 125 cases took 1,455 and 1,402 seconds in two runs at eight workers on 16
cores of a 96-vCPU Graviton4 (Neoverse V2) host under Quint 0.33.0 and
Apalache 0.62.1, with that host's aarch64 builds of Node.js v24.22.3 and
Temurin 21.0.12.1; `loss-safety-init` took 88 and 86 seconds of them. These
are finite checks at the stated bounds. The replay below ties the model to
the reconciler for the schedules its committed traces record.

### Replay against the reconciler

`crates/kestrike/src/failover/loss_replay_tests.rs` replays committed
traces of [loss.qnt](loss.qnt) against `Reconciler::replacement`,
`create_replacement`, `release_hold`, `retire` and `abandon`, and
`record_attach`, `add_spare` and `flip`, over the simulated store and the
`Provisioner` provider double, through the shared driver of
`failover::reconcile_tests::replay_driver`. Each production operation runs
on its own thread over a proxy that parks every store request and every
provider create until the trace's step answers it. The evidence is sampled:
it covers the schedules of the committed traces alone. The link leaves out
layouts, since every receipt and provider call carries the replay's one
layout; the token's text beyond its equality with the production
`Receipt::token` of the model's shard and attempt, which the expected token
also uses; and the real provider, since `Provisioner` keeps each token's
outcome by construction.

[loss_fixtures.py](loss_fixtures.py) declares the 110 traces committed under
`crates/kestrike/src/failover/loss_replay_fixtures`: the recipe of each of
the seven directed runs of [loss_check.py](loss_check.py), 43 recipes of its
own (`REPLAY_RECIPES`), and 60 seeded traces, four for each of the fifteen
roots of `loss_check.py`, each the root's prefix followed by 20 free steps of
the model's `step` under its seed. The recipes of its own reach the results
and faults the runs leave out: a lost reply after the start, latch, hold,
issue, provision, record, abandon raise, spare, fence and flip writes, a
refused version condition on the start, latch, hold, issue, spare,
fence, flip and abandon raise writes, a create whose call never arrives, a
refusal whose reply is lost, kept volumes and refusals, the hold a create
latches, a create that finds its volume recorded at its shard read or at its
receipt reread or is stale, creates of both shards under one provider, an
abandon that is replayed, held, stale or opens a held attempt, a flip that is
past at its first shard read and at its reread, held at its receipt read and
at its recheck, refused at its volume record, refused by `add_spare`'s volume
read after a retirement, or refused at its attach and then past at its shard
read, a fence that refuses a retirement, a replacement that retains an
impaired volume, one that finds a released receipt and latches nothing, a
hold that stays when the other volumes recover, a settling write that keeps
another volume in the spare slot, an abandon stale after two later raises,
and crashes and lost replies of each operation at the steps the replay test
pins. The directed traces alone reach every step, result, request and
provider answer the replay test pins, so that coverage holds whatever the
seeded traces draw. The 1,200 free steps of the seeded traces hold 461 begins,
231 crashes, 214 reads, 12 writes, 14 lost replies, 7 provider calls and 261
environment steps; of the 461 operations they begin, 190 crash before their
first request and 134 end at their first read. Each trace records the model's
digest and its recipe, or its root, the root's prefix and its seed.
Generation refuses an output directory that holds any entry, a trace whose
states equal another trace's and a trace that holds an interleaving
`left_out` names, listed below, and writes no trace of a refused run. The `loss-replay` case regenerates every trace with Quint, up to eight
runs at a time, requires it equal to the committed fixture, states and
metadata, and replays it.

Abstraction map. Model shard `s` is shard `s`, owned by host `s`, whose
shard record starts at generation 1 with volume `s` active and no spare.
Model volumes 1 and 2 are `vol-0a1` and `vol-0a2`, whose records start
active; model volume `v` from 3 is `vol-0c` followed by `v - 3` in decimal,
the name `Provisioner` gives its `(v - 2)`th created volume. The model's token
`(s, a)` is the token of shard `s`'s receipt for generation 2 at attempt `a`.
After every step the replay compares, in model units, read from the stored
records and the provider double:

- `st.shards`: each shard record's generation, active volume, spare and
  version, the version counting the record's commits less the settling
  writes of `retire`; a spare must name the shard's owner;
- `st.rcpts`: each receipt's existence, attempt, phase, volume, hold, release
  and version, its commit count; a receipt must name shard `s`'s replacement
  at generation 2 and the replay's layout;
- `st.vrecs`: each volume record's state, `ABSENT` for no record,
  `PROVISIONED` for provisioning or fresh, `ACTIVE` or `RETIRED`, and its
  version, its commits less the attach write of `record_attach`;
- `st.prov`: the outcome the provider keeps for each token, a volume or a
  refusal;
- `st.calls`: the `(shard, attempt)` of each provider call, from the tokens
  the provider received.

The driver passes each step the observation the model's `begin` records in
the process: `replacement` the evidence `(volume s, health)`, the health
`st.vols` gives shard `s`'s first volume in the begin state, `Lost` exactly
when its lost volumes hold that volume, `Impaired` or `Available`, with
`others`; `create` and `abandon` `others`; `abandon` the lost volumes it
may retire; `flip` the volume its receipt records. The variables fall in
three groups:

- compared: `st.shards`, `st.rcpts`, `st.vrecs`, `st.prov` and `st.calls`;
- driven: `st.ev`, which names each step's action, process, operation,
  shard, `pc`, result and kept answer; each process's `lost`, `others` and
  `vol`; each process's `op` after its step, which says whether the operation
  ended, its `pc` before a request, a provider call or a crash, and its `op`,
  `shard` and `pc` at the end of the trace; the
  attempt and volume of the receipt a process carries, read for the call's
  token and the volume a create reads; `st.vols`, through those
  observations; and `st.prov` before a call, which says whether the token is
  kept;
- unseen: `st.hostLost`, `st.next`, `st.issued`, `st.made`, `st.recorded`,
  `st.spares`, `st.flips`, each call's `phase`, `readHeld`, `seen` and
  `released`, each process's other fields, and `turn`.

A host loss reaches the code only as the volume health it leaves unchanged:
`replacement` takes volume evidence alone, so the host-loss runs show that an
available volume's evidence writes no receipt and calls no provider, and the
mapping of a host loss to volume evidence lies with the zone loop, outside
this link. The `abandon` step's observation, whether the receipt records an
unheld volume among its lost volumes, is the driver's own decision, standing
for the caller's; its result `nothing` shows only that the step read the
receipt.

Action map. Every choice of the model's `step` runs.

| Model action | Production |
|---|---|
| `begin` of `replacement` | `replacement` with the evidence above, `others` and the replay's layout |
| `begin` of `create` | `create_replacement` with `others` and the proxy as provider; a create that returns its volume then runs its caller's `record_attach` for host `s` |
| `begin` of `release` | `release_hold` under `OperatorRelease` for shard `s`'s replacement |
| `begin` of `abandon` | the caller's receipt read through `Reconciler::read`; a receipt that records an unheld volume among the step's lost volumes goes to `retire` of that volume and then `abandon` with that receipt, the `Retired` witness and `others`, and any other receipt ends the step `nothing` |
| `begin` of `flip` | the caller's `record_attach` for host `s`, answered at this step, then `add_spare` and `flip` of the generation 1 tenure |
| `request` | the pending read, or the pending write under the store's pass arm |
| `unknown` | the pending write under `Timeout { commit: true }` |
| `crash` | the event must name the operation and shard the process runs, at the `pc` the process stood at, and end it `crash`; the operation's pending request must be the one that `pc` names, a provider create under the model's token and the replay's layout included, and for a flip that already ended at its attach the `pc` must be its next skipped read; the operation is then dropped, so that request reaches no store and every later request fails |
| `call` | the parked provider create, whose token must be the model's and whose layout the replay's; `Provisioner` keeps a seen token's outcome, makes the next volume for `make`, keeps a refusal for `fail`, keeps no outcome for `drop`, and loses the reply when the model's reply is lost |
| `lose`, `impair`, `recover`, `hostLoss` | no request; later `begin` steps read the health through the process's observation |

Atomicity. One production store request falls on each model step, and each
request must be the read or write of the record the step's `pc` names, under
the operation and shard its `begin` named, with these stated exceptions. The
step that ends a create with its volume, as its shard read finds the receipt
created, its record write lands or its receipt reread finds the volume
recorded, also answers the create's read of the volume record, except after
the record write, and its caller's `record_attach`: a read of the volume
record and, while the stored record is provisioned with no attach event, its
attach write, which must then follow; the attach may refuse only a retired
volume record, and any other refusal fails the step. After a record write that
lands or a receipt reread that finds the volume recorded, that step also
answers `create_replacement`'s second read of the shard record, before the
caller's `record_attach`. The model holds no step for that read: a flip needs
a created receipt, so after the record write the read finds the generation the
create's first shard read found. After the reread the code returns `Stale`
when a flip committed since that first read, where the model ends the create
`created`; no committed trace holds that schedule. A flip's `begin` answers
its caller's `record_attach` the same way; the attach may refuse only a
retired volume record, and the operation then ends at its `begin` with that
refusal, and the model's shard read and then its volume read of that flip make
no request. The
retired-state write of `retire` also answers its settling write of the shard
record, and the volume read of `abandon` that finds the volume retired also
answers `retire`'s shard read and settling write. The receipt recheck of a
flip also answers `flip`'s read of the displaced active volume's record,
before the receipt read. A write request is matched by its key, and its
condition and value are compared through the stored records once it commits.
At the end of a trace each operation still running must be the operation and
shard its process names and stand at the request its process's `pc` names.

Results. `replacement`'s `Ok(None)` stands for `outside` and `retain`, its
`Ok(Some)` after a receipt write for `start` and `held`, and otherwise for
`returned`. `create_replacement`'s `Ok` stands for `created` and `record`,
`Held` for `held`, `Stale` for `stale`, `Create(Failed)` for `raise` and a
store `Absent` for `absent`. `release_hold`'s `Ok` after its write stands for
`release` and otherwise for `unheld`. `abandon`'s `Ok` after its receipt write
stands for `raise` and otherwise for `replayed`; `retire`'s `Named` stands for
`named`. `add_spare`'s `Stale` at the shard read and `flip`'s `Past` at the
reread stand for `past`; a flip's refused attach stands for `conflict` at the
volume read and for `past` at the shard read, where the model finds the
shard's generation moved on before its volume read; and `Conflict` and a flip
with no spare stand for `conflict`. A lost
reply, a write's or the provider's, is `unknown` in both, and a refused
version condition `condition`. The replay test pins the `(operation, pc,
result)` of every step that ends an operation, the `(operation, pc, act)` of
every request step, the step's actions and the nine provider answers. No
committed trace reaches `create`'s `conflict` at its receipt reread, a reread
equal to the issued receipt the create carried; `release`'s `condition`,
which needs a second writer of a held receipt; `abandon`'s `stale` at its
`due` read; or `flip`'s `conflict` at its first shard read, at its reread and
at its unused read. A crash is pinned at 19 of the 32 points an operation
stands at; no committed trace crashes `abandon` at its `due`, `named` or
`volume` read, `create` at its `issue`, `provRead`, `provision`, `raise`,
`record` or `reread` step, `flip` at its `fence`, `receipt` or `volume` step,
or `replacement` at its `latch` write.

The code writes three records the model leaves out: the attach event of
`record_attach`, after a create returns its volume and at a flip's start,
when the volume record is provisioned with no attach; and `retire`'s settling
write of the shard record, which conditions on its shard read and clears the
retired volume from the spare slot. `left_out` refuses a trace in which such
a write changes what a later model step reads:

- an attach write while an abandon of that volume holds its volume read and
  that abandon then sends a retirement write the model commits, which fails
  its condition in the code;
- a create's provision read of a provisioned volume whose attach is written,
  which the code finds of another value than it provisions;
- a retirement whose settling write fails because a shard write committed
  since its shard read, another abandon's settling write included;
- a settling write that clears the retired volume from the spare slot;
- a settling write followed by a shard write of a flip of that shard that read
  the shard record before it and has not reread it, which then fails its
  condition in the code.

Controls. A driver that passes `create_replacement` the other shard fails at
that create's receipt read with `the operation reads Replacement(Shard(2))`.
A provider that forgets the kept volume of a repeated token fails at that
call through the provider comparison. A create whose caller reads the
volume record and makes no attach write fails at the step that ends the
create, and a replacement asked with another layout at its start write. A
fixture altered in one compared field fails at its state through the
comparison: each field of either shard record and of either receipt, a
volume record's state and version, the set of volume records, a kept
provider outcome's kind, volume and token, the set of kept outcomes and the
set of calls (22 fields, one control each). An altered event result fails
through the result comparison at an ending step and where only the receipt
write tells two results apart. A step that leaves its operation running may
carry no result or `ok` at a request and the kind of the provider's kept
outcome at a call, and an altered result fails there at a read and at a
call. A process altered to end at a step its operation continues past, or to
continue at the step that ends it, fails at that step. An altered event `pc`
fails through the request match, at a read and at a write; one that names
another step with the same request, or another step than the call, fails
against the `pc` its process stood at. An altered read
or write kind, kept flag, recorded action, begin over a running process,
health against the lost volumes, and the model reads of a refused flip out
of order each fail at their step; and an altered carried attempt fails at
the provider call through the token check. A stale model digest or a
missing state is refused before any state replays. A flip whose `Past` is reported as `stale`
fails at its reread with `result stale, modeled past`; a flip whose attach
names the other shard's owner fails at its `begin` with `the flip ended
attach conflict over`; a crash event that names another shard or another
`pc`, and a trace whose last state names another `pc` for a running
operation, fail at that crash or at the end of the trace. Mutants of the
replay's own comparisons, one disabled at a time: of 45, 41 fail a control.
That count excludes the check of a continuing step's result and the check of
the `pc` a process stood at, each of which has the control named above.
The other four checks have no control: the call's layout, which the
receipt's layout check precedes; a token bound to two attempts, which only
a production token that drops the shard or the attempt reaches, and mutants
of `Receipt::token` fail the token comparison first; a spare named on a
host other than the shard's owner, which `add_spare` writes only for the
host its attach witness names; and the provider script's unused-answer
check, which guards the driver.

What the controls measured (110 traces; the runs are research and are not
committed). The mutant counts of the production code stand in the section
"Replay against the reconciler" of the standby census model. Every surviving
mutant of the loss operations lies in code the committed traces do not reach
or that the driver's fixed inputs make vacuous:

- the record-shape checks `provisioned`, `origin_intact` and `created`, and
  `record_attach`'s guard: every volume record of the replay is provisioned
  with no lineage and no modification;
- `replacement` over a receipt of another request, and `prior`'s reading of
  it: each shard has one request, generation 2;
- in `flip_read`, the displaced volume's write to `Active` and the receipt
  fence write (`fence`): the displaced volume is the shard's first, whose
  record starts active, and no receipt records it;
- `create_replacement`'s `Stale` for a receipt that is not issued once the
  shard's generation has moved: the model flips only over a created receipt;
- `abandon`'s refusal of an observation that is held, of another phase or of
  another shard: the driver's observe decision passes none;
- `add_spare`'s `Conflict` over another spare: the model holds one unretired
  created volume a shard at a time;
- the settling write's clearing of the retired volume from the spare slot,
  which `left_out` leaves out;
- `decide`'s generation ceiling and `Phase::rank`, the receipt's successor
  order, which the store client applies before any request.

Mutants of the model, one at a time, as for the standbys model: of the 51
mutants of `loss_check.py`, the replay failed at a named step for 40, such
as `read at 11: the operation ended held` for a create that ignores the
hold; for 8 the committed recipes could not be regenerated; and 3 change
what the driver itself supplies (the count of other impaired volumes, who
may release, and the abandon's loss observation), on which the replay
passes, as the action map says it must. Two of the 40 fail on recipes this
measurement added (`replay_impairedRetained`, `replay_releasedNotLatched`),
and a third it added, `replay_heldStaysWhenIsolated`, cannot be regenerated
under its mutant.

## Lookup model

[lookup.qnt](lookup.qnt) models the lookups of two keys on a live indexed
storage beside the operations that change what a key names: publication,
replacement, removal, the clock passing the deadline, the close of
admission, certification and service. It restates the first clause of the
invariant of the obligation record
`lookup-samples-before-cutoff-and-sequence-loads`, "a hit is retained under
protection and witnessed on a visible mapping", as its two properties. The
record's second clause, "an era never counts as identity", needs a key
whose fingerprint equals a retirement era, and the order the record is
named for, the sample before the cutoff read and the sequence loads, lies
inside one lookup; the loom kernel `storage::lookup_model` checks both.

The finite instance has two keys, four objects numbered in publication
order, at most two leases on an object and one
deadline shared by every object. The era starts at 1. `publish` makes the
next object visible under a key that names none, with its anchor counted.
`remove` ends the mapping of the object a key names: the retirement stamps
the object with the era it found and advances the era. `replace` ends the
named object's mapping the same way and publishes the next object under the
key. `lookup` refuses `Closed` once admission is closed, reports `Missing`
for a key that names no object and `Expired` for a named object once the
clock is at or past the deadline, and otherwise returns a lease on the
named object, one more right on it. `drop` gives one lease back. `expire`
moves the clock to the deadline and `close` closes admission; publication
and replacement run only while admission is open, and removal runs after
the close as well. `certify` is one funded call: the one registered
reader holds no pin between two operations, so the pass certifies the
current era when that is higher.
`service` is one funded call that visits every retired object: it releases
an anchor whose stamp lies strictly below the certified era, and an object
returns when neither its anchor nor a lease is counted.

Abstractions:

- Each action is one storage operation, taken whole, and the operations
  interleave in one total order; the loom kernel `storage::lookup_model`
  and the paused-race tests of `storage::lookup_tests` cover a lookup that
  overlaps a removal, a replacement, an expiry or the close.
- An object is its number; its slot, bytes, fingerprint and chain position
  are the storage's. The instance stays below the lease limit, the
  per-object right limit and the index's capacity, and every call is
  funded.
- The clock has two positions, before the deadline and at it.
- `bad` is history that `HitOnVisible` reads: a lookup sets it when it
  returns a lease while admission is closed or the clock is at the
  deadline, or when the leased object is another than the one its key
  names, carries another key or has left the Visible phase. The event `ev` is history
  that the witnesses read.

| Property | Record clause | Guarantee |
|---|---|---|
| `HitOnVisible` | "a hit is ... witnessed on a visible mapping" | Every lease a lookup returned named the object visible under its key at that step, with admission open and the clock before the deadline. |
| `HitRetained` | "a hit is retained under protection" | An object with a lease out has not returned. |

[lookup_check.py](lookup_check.py) checks `safety`, the conjunction of the
two, with the free scheduler at `BOUND = 8` steps. Twenty-one reachability
witnesses, each checked as the inverted invariant `not(witness)`, reach
every action and every outcome: a publication, a replacement, a removal and
one after the close; a hit, and one on an object published after another
under the same key; a `Missing` verdict, and one after a removal; an
`Expired` and a `Closed` verdict; a dropped lease, and one on a retired
object; the clock passing the deadline and the close; a certification that
certifies and one that is idle; a service call that visits nothing, one
that holds an object, one that releases an anchor, one that returns an
object and one that visits two. Three directed runs are checked with
`BOUND` set to the recipe's length, each with its reachability case:
`lookup-run-replaceUnderLease` (a lease taken before a replacement holds
the replaced object through certification and service, a later lookup
leases the new object, and the old one returns after its lease drops),
`lookup-run-removeThenReclaim` (a lookup after the removal is `Missing` and
the object returns) and `lookup-run-expiryAndClose` (lookups at the
deadline and after the close return no lease, and a removal still runs).
Six mutations each break the property their case checks: a hit on the
replaced object, a hit on the other key's object, a hit after the removal,
a hit at the deadline and a hit after the close (`HitOnVisible`), and a
return under a lease (`HitRetained`). These are finite checks of the model at the stated
bounds. The replay below ties the model to the implementation for the
schedules its traces record.

### Replay against a live indexed storage

`crates/kestrike/src/storage/lookup_replay_tests.rs` replays committed
traces of the model against an indexed `Storage` on the heap-backed
platform with one registered reader. Each step except `expire` runs
storage code for one model action. A publication or a replacement goes
through the `lookup_tests` helpers: `Storage::reserve`, then the test-only
`complete` and `Completed::publish` or `Completed::replace`, which share
their preparation and commit with the fill's publication. A removal goes
through the test-only `Storage::remove`, which routes the key and calls
the removal that eviction and expiry use. The other steps are
`Registration::lookup` under a clock sample the replay queues, a lease's
drop, `Storage::close`, one funded `Storage::certify` and one funded
`Storage::service`. `expire` calls no storage code: it moves the sample
the replay queues before each later lookup from one nanosecond before the
deadline to the deadline. After every step the replay requires the call's
return, and the outcome the replay derives from it, to equal the step's
event: a hit must name the object the model names, through the
`AllocationId` the replay recorded when that object was published. It also
requires the era report, the reserved lease credits,
`Storage::outstanding`, and every published object's slot state and count
to equal the model's state, and each slot's incarnation to equal the one
recorded at publication. One operation runs at a
time, so the replay covers the order of whole operations; the order of
the sample, the cutoff read and the sequence loads inside a lookup stays
with the loom kernel.
[lookup_fixtures.py](lookup_fixtures.py) writes the traces with
`quint run --mbt`: four directed recipes and six traces of sixteen steps
of the model's own `step` under pinned seeds, which together reach `init`
and every choice of `step` with each outcome; the test asserts that set.
Each trace names the model's sha256. Controls: a driver that looks up the
other key, one that keeps a dropped lease and one that skips a removal
each fail at the step they change, and a trace with a raised certified
era fails at its state. The replay is evidence for exactly the schedules
these traces record.

## Escrow model (family escrow)

[escrow.qnt](escrow.qnt) models the escrow of a storage's multi-extent
objects, as the pool gate's holders drive it: `Storage::promise` and its
gate-held half `promise_locked`, `Builder::place`, `Builder::cancel` and the
builder's drop in `crates/kestrike/src/storage/builder.rs`, a direct
one-extent claim through `Storage::reserve` and `claimable_units` in
`storage/reserve.rs`, and a parked slot's return by `Storage::service` in
`storage/release.rs`. It restates clauses of the obligation record
`escrow-equals-builders-remaining-charge`: a promise succeeds only when the
free units less the escrow cover the charge plus the clean reserve; a
refused promise leaves the tables and the escrow unchanged; the escrow
equals the builders' remaining charge and never passes the free units, and
the free, placed and claimed units sum to the volume; a direct claim spends
no promised unit; every cancellation cut refunds the remaining charge once;
placement completes a builder only at its last extent. The model claims
nothing stronger.

The finite instance counts in the storage's own units. Every object's body
is a whole number of extent payloads, so every extent, a builder's and a
direct claim's alike, is `E = 63` units, and the clean reserve is `R = 1`
unit. There are two builder handles, each holding at most one builder of 2
or 3 extents at a time, and at most two direct claims. `promise(k, n)`
succeeds when `free - u >= n * E + R`, adding the charge to the escrow `u`,
and otherwise refuses `clean_reserve` with nothing changed. `place(k)`
places the next extent: its units leave the free units, the escrow and the
builder's remaining charge together, and the builder is complete at its
last extent. `cancel(k)` subtracts the remaining charge from the escrow and
returns the placed extents in the same hold. The drop, `release(k)`,
refunds the remaining charge and parks the slot with its placed extents.
`service` is one visit funded at `service_minimum`: it returns the parked
slot's last held extent, and the visit that leaves none returns the slot
too. `claim` succeeds when `free - u >= E + R` and otherwise refuses
`clean_reserve`; `unclaim` returns the latest claim. Since every move is a
whole extent, `free - u` stays `VOLUME` modulo 63. Two volumes cover the
clean reserve from both sides: at `VOLUME = 316` a promise or a claim can
leave exactly `R` free, and at `VOLUME = 315` the clean reserve alone can
refuse one.

Abstractions:

- One call completes before the next starts, each under one gate hold. The
  gate-free refund of a cancel that finds the gate busy, and its race with a
  gate holder, are the loom kernel's (`storage::escrow_model`), not this
  model's.
- The builder handles are the replay's variables, not slots: a dropped
  builder's slot stays parked while its handle promises again. At most one
  slot is parked at a time, so a service visit names its slot.
- Bodies of whole extent payloads keep every free run a multiple of 63
  units, so no placement or claim the escrow admits finds no free run.
  `PayloadFull`, the waiting flag, multi-extent runs in one hold, the work
  budget, gate contention, readiness and closure refusals, retired
  pressure, slot and arena exhaustion stay with the Rust tests.
- `pre` is the state before the step and `ev` records the step's inputs;
  production keeps neither.

| Property | Clause it restates |
|---|---|
| `PromiseNeedsAllocatable` | A promise succeeds only when the free units less the escrow cover the charge plus the clean reserve. |
| `RefusalChangesNothing` | A refused promise or claim leaves the state unchanged. |
| `EscrowIsRemaining` | The escrow equals the builders' remaining charge. |
| `EscrowWithinFree` | The escrow never passes the free units. |
| `Conservation` | The free units, the placed units (a parked slot's included) and the claimed units sum to the volume. |
| `ClaimSparesPromised` | A direct claim spends no promised unit: after it, the free units still cover the escrow and the reserve. |
| `RefundOnce` | A cancel or a drop takes exactly the builder's remaining charge out of the escrow. |
| `CompleteAtLast` | A builder's remaining charge is zero exactly when every extent is placed, and a placement reports completion only at the last extent. |

[escrow_check.py](escrow_check.py) checks `safety`, the conjunction of the
eight, with the free scheduler at `BOUND = 12` steps at both volumes.
Twenty-three reachability witnesses, each checked as the inverted invariant
`not(witness)`, reach every outcome of every action: promises of 2 and 3
extents, one that leaves exactly the reserve, one an extent short, one
refused beside a promise and, at `VOLUME = 315`, one the reserve alone
refuses; a partial and a completing placement; a cancel and a drop of an
unplaced, a partly placed and a complete builder; an idle service call, a
partial visit, a final visit that returns an extent and one that returns
only the slot; a claim, one beside a promise, a refused claim and an
unclaim; and two builders at once. Four directed runs are checked with
`BOUND` set to the recipe's length, each with its reachability case:
`escrow-run-an-exact-promise-succeeds-and-a-short-one-refuses`,
`escrow-run-a-claim-beside-a-promise-spares-the-promised-units`,
`escrow-run-two-builders-interleave-and-each-exit-refunds-once` and, at
`VOLUME = 315`,
`escrow-run-the-reserve-refuses-a-promise-of-exactly-the-allocatable-units`.
Nine mutations each break the property that names the case: a promise one
extent short of its charge (`PromiseNeedsAllocatable`), and at
`VOLUME = 315` a promise that skips the clean reserve (the same property); a
refused promise that adds its charge (`RefusalChangesNothing`); a placement
that keeps its units in the escrow (`EscrowIsRemaining`); a promise that
ignores the escrow (`EscrowWithinFree`); an unclaim that frees two extents
(`Conservation`); a claim that ignores the escrow (`ClaimSparesPromised`); a
cancel that refunds twice (`RefundOnce`); and a placement that completes
one extent early (`CompleteAtLast`). These are finite checks at the stated
bounds. The replay against the Rust code is
`storage::builder_tests::escrow_replay`, which replays committed traces
that [escrow_fixtures.py](escrow_fixtures.py) regenerates.

## Allowance model

[allowance.qnt](allowance.qnt) models the retired allowance of one volume:
the retired charge that `storage/reserve.rs` holds against the allowance `T`
at every claim, its growth when a retirement that `storage/remove.rs` or
`storage/publish.rs` starts is recorded, and its return by the service pass of
`storage/release.rs`. It restates three clauses of the obligation record
`retired-allowance-gates-claims-and-discretionary-victims` and claims
nothing stronger: the retired charge counts every retired slot's units from
retirement to return, also after grace releases a reader-held object's
anchor; at or above `T` every claim, a replacement included, refuses
`RetiredPressure` with nothing changed and the incumbent current; and
mandatory invalidation retires past `T` while funded return restores claims.

The finite instance has five keys of one-unit objects and an allowance of
two units. `publish` claims a unit and makes an object visible under a
vacant key, keeping its lease or dropping it; it may keep the lease only
while no other lease is held. `replace` claims a
unit, makes a new object visible under an occupied key and retires the old
one. Both refuse `RetiredPressure` while the charge is at or above `T`.
`invalidate` retires the key's object whatever the charge. A retired object
holds its anchor until `certify` and the right of a kept lease until
`release`. `visit` is a funded service call: it returns every retired
object that neither its anchor nor a right holds. `charge` counts the
retired objects' units.

Abstractions:

- Each action is one atomic step: one call. The orders inside the pool gate
  stay with the loom kernels.
- Every object charges one unit, so the charge is a count of retired
  objects and a funded visit returns every eligible one; objects of several
  extents and their one-extent-per-visit return are
  [visit.qnt](visit.qnt)'s. The validation of `T` against the largest
  object's charge, headroom, discretionary victims, the clean reserve and
  the slot limit are outside the model: the instance's volume holds every
  object the five keys can have.
- One lease exists at a time, kept from a publication.
- `gated`, `kept` and the event are history the invariants read; production
  keeps none of them.

| Property | Guarantee |
|---|---|
| `PressureGatesClaims` | A publication or a replacement refuses `RetiredPressure` exactly when the charge is at or above `T`. |
| `RefusalChangesNothing` | A refused claim leaves the visible objects, the retired objects and the charge as they were. |
| `ChargeCountsRetired` | The charge equals the retired objects' units, from retirement to return, anchored or not. |

[allowance_check.py](allowance_check.py) checks `safety`, the conjunction of
the three, with the free scheduler at `BOUND = 8` steps. Thirteen
reachability witnesses, each checked as the inverted invariant
`not(witness)`, reach every outcome the unmutated model can produce: a
publication with its lease dropped and kept and one refused at the
allowance; a replacement and one refused at the allowance; a retirement
below the allowance and one that passes it; a certification that releases
an anchor; a lease's drop; a return, one that brings the charge back under
the allowance, a visit that leaves a certified object its reader holds, and
an idle visit. Two directed runs are checked with `BOUND` set to the
recipe's length, each with its reachability case:
`allowance-run-mass-invalidation` (three retirements past the allowance, a
refused claim, the certification, the return and a claim that succeeds) and
`allowance-run-reader-held` (a certified object its reader holds through a
visit, a replacement that brings the charge to the allowance, a refused
claim, the lease's drop and the return of both). Three mutations each break
the property that names the case: a replacement that claims at the
allowance (`PressureGatesClaims`), a refused replacement that ends the
incumbent (`RefusalChangesNothing`) and a return that leaves the charge
(`ChargeCountsRetired`). These are finite checks at the stated bounds; no
refinement mapping to the implementation is claimed.

## Reservation report model

[report.qnt](report.qnt) models reservation commands on the command table of
one device: the Report submit, its timeout, its snapshot and the reserve of
retained buffers in `storage/device/table.rs` (`submit_reservation`,
`timeout_report`, `reservation_report`, the reservation terminal and the
data-submit share rule). It restates three clauses of the invariant of the
obligation record `spdk-reservation-custody-and-reserved-progress`, the
healthy-poll rule of its test and the tick quota its transition names. It
claims nothing stronger. The record's
own tests drive the scripted SPDK driver; this model and its cases describe
the table alone.

The finite instance has three slots, a reservation share of two retained
buffers, two data buffers, ordinals 0 to 3 and at most three posted
completions. A token is a slot and the generation the slot issued. A reserve
entry is idle with its buffer or lent to an outstanding command, and an idle
entry may hold the snapshot of one token. `submitReport` refuses by
admission, then `NotBefore` for an ordinal below the Report's not-before
ordinal, `TickQuota` for an ordinal at or below the last accepted one and
`TableFull` with no idle entry, each without a token and without a driver
call. Otherwise it takes the lowest idle entry, clears that entry's
snapshot, and the driver's answer decides the rest: an accepted Report holds
the buffer and sets the quota to its ordinal, a refusal returns the buffer
to its entry, and an unwound call holds the buffer reserved and loses the
device. `submitData` refuses `TableFull` while the free slots would not
leave one for each idle reserve entry. `post` is the device finishing a
command, healthy or failed, and for a Report with bytes that pass the
identity check or not. `poll` picks posted completions in order: a Report's
terminal returns its buffer to the lowest lent entry, and that entry takes
the Report's token as its snapshot only when the Report was still attached,
its status healthy and its bytes passed the check. `timeout` marks an
accepted or cancelled Report timed out once, detaching it if attached; a
data read, a stale token and a second timeout are refused. `cancel` detaches
an attached command while admission is Open or Lost. `read` reports whether
an idle entry holds the token's snapshot, as `reservation_report` does.
`quiesce` closes admission. Before a stop it makes one pick and asks the
device; with a proven stop it ends outstanding records from the table's own
records in slot order, as many as the output has room for, a Report without
a status. A free slot spends no room, and later calls and polls continue the
drain.

Abstractions:

- Each action is one public call or one device act, taken whole, on one
  thread.
- Only Report commands are modeled. Register, Acquire and the
  Preempt-and-Abort forms, payload encoding, Report parsing, the driver's
  limits beyond the share, and a table with no reservation share are
  omitted.
- Data commands are reads of one kind. Injected stale completions, slot
  retirement, output room below one event per picked completion, geometry
  and arena refusals are omitted; the command table model covers the first.
- A timed-out Report's late completion is a terminal like any other: it
  ends custody and publishes nothing. The model follows
  `complete_reservation`, the `timeout_report` documentation and the
  record's test.
- The entry's snapshot is the one `reservation_report` reads. The table also
  keeps the bytes of a successful, attached Report that the driver's identity
  check refused, and `refused_report` returns them to the same-host restart
  (`host/fencer.rs`) until a later reservation submit takes the buffer. The
  model's entry holds `NOTOK` for that Report, and this second reader is
  omitted. The implementation's tests cover it:
  `host::fencer_tests::a_refused_report_snapshot_binds_to_its_token` (the
  bytes bind to their token, a later submit that takes the buffer clears
  them, and a Report ended by a proven stop has none), and in
  `storage::device::spdk::reservation_tests` the `refused_report` assertions
  of `a_report_timeout_keeps_custody_until_its_certified_late_terminal` (a
  timed-out Report's late terminal has none),
  `a_report_snapshot_is_readable_only_after_healthy_success_and_before_its_buffer_reuse`
  (a failed Report has none) and, through the `report_through` helper,
  `own_record_by_host_id_not_controller_id` (a Report whose check passed
  has none while its snapshot is readable).
- `dev` and `posted` are the device's side. `timedOut`, `healthy` and
  `requoted` are history the invariants read; production keeps none of them.

| Property | Guarantee | Record clause |
|---|---|---|
| `TimedOutEstablishesNothing` | No reserve entry holds the snapshot of a token that timed out. | `spdk-reservation-custody-and-reserved-progress`: "timed-out Reports keep custody and establish nothing" |
| `SnapshotOnlyAfterHealthySuccess` | A snapshot sits in an idle entry and names a Report the device finished healthy with bytes that pass the check. | the same record's test: a Report snapshot is readable only after healthy success |
| `ReserveRetained` | The idle entries and the outstanding reservation commands sum to the share, and the abandoned count equals the detached records. | the same record: "one volume retains its physical buffers" |
| `DataLeavesShare` | The free slots number at least the idle reserve entries. | the same record: "data and metadata saturation leaves the reservation share" |
| `TickAdvances` | Accepted ordinals strictly increase. | the same record's transition: "tick quota" |

[report_check.py](report_check.py) checks `safety`, the conjunction of the
five, with the free scheduler at `BOUND = 7` steps. Twenty-nine reachability
witnesses, each checked as the inverted invariant `not(witness)`, reach every
action and these outcomes: each Report submit outcome, a data submit accepted and
refused with a slot still free, a post, a poll that leaves a snapshot readable,
one that delivers an identity-refused Report, a failed one and the late
terminal of a timed-out one, a returned and an abandoned data read, a
timeout taken and refused, a cancel taken and stale, a read with and without
a snapshot, a close, each quiesce outcome and a Report ended by a proven
stop. Ten directed runs are checked with `BOUND` set to the recipe's
length, each with its reachability case: `report-run-lateTerminal` (a
timed-out Report's late healthy completion returns the buffer and publishes
nothing), `report-run-snapshotReuse` (a snapshot is readable until a later
submit, here a refused one, takes its buffer), `report-run-identityRefused`
(a Report that fails the identity check and a failed Report publish
nothing), `report-run-shareLeft` (one data read fills the one slot outside
the share, a second is refused, and a third Report finds no idle entry),
`report-run-quota` (the not-before and tick refusals, then the next
ordinal), `report-run-stopAcrossCalls` (a pending quiesce keeps a timed-out
Report and a cancelled read, and a proven stop ends them across two calls),
`report-run-cancelThenTimeout` (a cancelled Report still times out once,
and its late completion publishes nothing), `report-run-dataBesideReport` (a
timeout naming a data read is refused, and a failed read returns beside a
healthy Report), `report-run-unwoundStop` (an unwound submit holds its
buffer until the proven stop returns it) and `report-run-stopPastFreeSlot`
(a proven stop with room for one event passes a free slot and ends the read
behind it in the same call). Five mutations each break the
property their case checks: a late terminal that publishes
(`TimedOutEstablishesNothing`), an identity-refused Report that publishes
(`SnapshotOnlyAfterHealthySuccess`), a refusal that keeps the buffer lent
(`ReserveRetained`), a data submit that ignores the share
(`DataLeavesShare`) and an unchecked quota (`TickAdvances`). These are
finite checks at the stated bounds; no refinement mapping to the
implementation is claimed.

## Reconciler creation model

[creation.qnt](creation.qnt) models the reconciler's creation steps over the
store: `Reconciler::create_shard`, `provision` and `record_attach` in
`crates/kestrike/src/failover/reconcile.rs`, with the store client's
shard creation, one store request per step. It restates the creation rules
that merged commits `c7e99c60b` and `8862ec7ce` (blotter issue 1185) and that module's
documentation state (ACKNOWLEDGED-ONLY, WRITE-ORDER) and claims nothing
stronger.

The finite instance has one shard record, which is absent or records one of
two creations, its two coverage pages, one volume record (absent,
provisioning, or fresh with one host's attach event), two hosts and two
processes. `begin` starts an operation on an idle process and `request`
performs its next store request:

- `createShard` reads the shard record and returns it when it records the
  same creation, or refuses a record of another. Otherwise it creates page
  0 and page 1, reading a page whose create refused and going on only when
  that page is empty at its first version, creates the shard record, and
  after a refused create or a refused page reads the shard record and
  judges it as at the first read.
- `provision` creates the volume record and, when the create refuses, reads
  it and returns a provisioning record or refuses any other.
- `attach` reads the volume record: an absent record is an error, a
  provisioning record takes the host's attach event by an exact-version
  write, a fresh record with the same host's event returns the witness with
  no write, and a fresh record with another host's event refuses.

A create commits only on an absent record and an exact-version write only at
its version. `unknown` ends an operation at its next write with no reply:
the write commits, is lost, or is held, and `release` delivers the one held
write later. `fence` is the owner's fence of a page once the shard record
exists.

Abstractions:

- A creation is one of two identities; the record's other fields, the
  unclean-record refusal, the layout floor, the attach era, namespaces and
  the principals' denials are outside the model, as are the spare, flip and
  retirement steps and the standby writes of the families above.
- A page changes only by its create and the owner's fence, and the owner
  fences only once the shard record exists, so the refusal of a shard
  creation that meets a changed page and then no shard record is never
  reached.
- At most one write is held at a time.
- `witnesses`, `hosts` and `returned` are history the invariants read: the
  hosts whose attach returned its witness, the hosts an attach write
  recorded, and the creations a shard creation returned.

| Property | Guarantee |
|---|---|
| `WitnessMeansRecorded` | An attach witness exists only for the host whose attach event the fresh volume record holds. |
| `OneAttachForLife` | The volume record takes the attach event of one host. |
| `CreationReturnsItsOwnRecord` | A shard creation returns a record only when the stored shard record records its creation. |
| `PagesBeforeTheShard` | The shard record exists only with both pages. |

[creation_check.py](creation_check.py) checks `safety`, the conjunction of
the four, with the free scheduler at `BOUND = 14` steps. Twenty-one
reachability witnesses, each checked as the inverted invariant
`not(witness)`, reach every result each operation's reads and writes give,
a page create refused on an empty page, a race lost to the same creation,
each kind of unknown outcome, a held write that commits and one that
refuses, the fence, a page create that meets a fenced page under the
creation's own shard record, and a held shard create refused after the
winner.

Five of the witnesses name a path through `createShard`, and each reads the
program counter the operation's process holds after the event. A shard read
that ends its operation at counter 0 is the creation's first read, and one
that ends at counter 6 follows a refused create or a changed page. A page-0
read that leaves counter 3 found the page empty at its first version, and
one that leaves counter 6 found it changed.

| Witness | State |
|---|---|
| `ShardFoundAtTheFirstRead` | A first read finds the creation's own record. |
| `ShardConflictAtTheFirstRead` | A first read finds another creation's record. |
| `RaceLostToTheSameCreation` | A read after a refusal finds the creation's own record. |
| `PageCreateRefusedOnAnEmptyPage` | A read after a refused page-0 create finds the page empty. |
| `FencedPageUnderARetry` | A read after a refused page-0 create finds the page fenced while the shard record holds the creation. |

Each of the five has a `creation-beside-` case: a directed run along the
path that the event alone does not tell from the witness's path. The case
passes when the witness is false in every state of the run, the search
reaches the run's last action, and the run ends in the state the case names.

| Case | Run | Final state |
|---|---|---|
| `creation-beside-ShardFoundAtTheFirstRead` | Two creations of one record race. | `RaceLostToTheSameCreation` |
| `creation-beside-ShardConflictAtTheFirstRead` | Creations of two records race. | A conflict read at counter 6 |
| `creation-beside-PageCreateRefusedOnAnEmptyPage` | A page-0 create meets a fenced page. | `FencedPageUnderARetry` |
| `creation-beside-RaceLostToTheSameCreation` | A second creation of a stored record. | `ShardFoundAtTheFirstRead` |
| `creation-beside-FencedPageUnderARetry` | A second creation of a stored record whose page 0 is fenced. | `ShardFoundAtTheFirstRead` with page 0 fenced |

Three directed runs are checked with `BOUND` set to the recipe's length,
each with its reachability case: `creation-run-create-then-replay`,
`creation-run-racing-creations` and `creation-run-attach-once`. Four
mutations each break the property that names the case: an attach that
returns its witness when its write has no reply (`WitnessMeansRecorded`); an
attach that writes over another host's event (`OneAttachForLife`); a replay
check that accepts any held record (`CreationReturnsItsOwnRecord`); and a
shard record created before its pages (`PagesBeforeTheShard`). These are
finite checks at the stated bounds.

`crates/kestrike/src/failover/creation_replay_tests.rs` replays the
committed traces against `Reconciler::create_shard`, `provision` and
`record_attach` over the simulated store.
`failover::reconcile_tests::creation_replay::committed_creation_traces_replay_and_reach_every_step_choice`
compares each request, each result and the stored shard record, pages and
volume record with the model's at every state. A success takes its model
result only when it returns the value its arguments name: the shard record
of its creation, the provisioning record of the volume, or the attach
witness of the volume and its host. The `creation-replay` case regenerates
the traces with Quint, requires their states to equal the committed
fixtures and replays them.

[creation_fixtures.py](creation_fixtures.py) and
[detect_witness_fixtures.py](detect_witness_fixtures.py) declare the traces
committed under `crates/kestrike/src/failover/creation_replay_fixtures`
and `crates/kestrike/src/failover/detect_witness_fixtures`.
`scripts/test-judge-quint.py` binds each directory to its declaration: the
trace names, each trace's model digest, its recipe, its seed and step count
where the declaration names them, and one state more than its steps. The
`creation-replay` and `detect-witness-replay` cases check the same binding,
regenerate each declared trace with Quint and require its states to equal
the committed fixture before the replay; the detect witness traces replay
against the detector and arbiter cores.

## Reconciler standby census model

[standbys.qnt](standbys.qnt) models the reconciler's standby census steps
and a standby's attach and enrollment over the store:
`Reconciler::reserve`, `release`, `designate` and `record_standby` in
`crates/kestrike/src/failover/reconcile.rs` with the admission rule of
`Population::admit` and the release rule of `Census::released` in
`failover/standbys.rs`, and `enroll_standby`, one store request per step.
It restates the rules those modules' documentation states (POPULATION-CAP,
ONE-HOST-PER-SLOT, CENSUS-COVERS, HEADROOM, FEASIBLE-SLOT,
STANDBY-WRITE-ORDER) with the host role limit of decision D29 of the parent
specification, issue #255, whose D labels this section cites, and claims
nothing stronger. Per-shard invariants stay with the tenure
model; this model carries the state shards share: the zone census, the shard
records and their active volume records, under two reconcilers.

Each reconciler runs one operation at a time. `begin` starts an operation
and makes its first request, and `request` makes each next one:

- `reserve(s, h)` reads the census, the shard record and the active volume's
  record, and decides by `Population::admit` over those reads, host `h`'s
  current report and the reconciler's loss evidence: `Ineligible` for the
  owner or `E = 0`, the slot already listed for `h` at the record's tenure
  with no write, `Closed` for a host with no live attach of a volume at
  `MAX_ATTACHED` live attaches, `Headroom` for such a host whose report
  shows no attachment slot left after the pending entries of other shards
  that name it, `Taken` while the incumbent (the entry's host unless the
  record names it owner, or else the record's standby) is another host the
  evidence does not show lost, `Full` for a new slot in a census at `CAP`,
  or the census write, a create while the census is absent. An acknowledged
  write or a listed slot leaves the reconciler holding the slot. HEADROOM
  counts as pending the entries of the census the reservation read for other
  shards that name the host and whose shard the report does not list in the
  standby role. The model reads the gauge and the roles from one report at
  the decision; the code's caller captures the report before it calls
  `reserve`, so the model's report is the freshest a caller could hold, and
  the premise below covers the window from capture to the census write. The loop's
  candidate filter runs at `begin`: a host that would gain a role at the
  host role limit is excluded with no request. A host gains no role on a
  shard it owns or whose slot lists it, so the filter passes it there and
  the owner's reservation reads the records and refuses `Ineligible`.
  `Closed` needs a volume at
  `MAX_ATTACHED` live attaches and a candidate with none, which three hosts
  cannot reach, so no case of S2, S2H or S2E reaches it.
- `release(s)` reads the census and ends with no write when the census is
  absent. It then reads the shard record and the active volume's record. A
  census that lists no entry for the shard takes no write; a listed entry
  stays while the record names a standby, holds the entry's tenure, or shows
  the entry's host, not the owner, live and not lost; otherwise the release
  writes the census without it. The model adds a keep case that
  `Census::released` does not have: it stands for the loop's stuck bound
  (see the premises below), and a release whose entry would drop on any
  grounds ends `keptRecording` while an attach record of that shard and host
  is in flight or its write is held.
- `designate` uses the slot its reconciler holds. It reads the volume
  record, then the shard record, and refuses `Stale` at another tenure than
  the slot's; it reads the census and refuses `Conflict` when the census
  lists another entry or none for the shard; a record that already names
  the host returns as it is; a host whose live attach the volume record
  enrolls no pair for refuses, the code's `Conflict`; otherwise it writes
  the shard record naming the host.
- `record(s, h)` runs only for the host of the slot its reconciler holds.
  It reads the volume record and the shard record, refuses a record that
  fails STANDBY-TENURE or a volume that admits no new attach, writes the
  host's live attach event, and reads the shard record again. The closed
  volume refusal is unreachable with three hosts, since the attach record
  starts only for a host with no live attach.
- `enroll(s, h)` runs once host `h`'s attach completed and while it has no
  pair. It reads the volume record and the shard record, refuses `Tenure`,
  then `Unattached` for a host the volume record shows no live attach,
  writes the pair, and reads the shard record again. It has no Register
  step: a standby registers at its takeover (D18). `enroll_standby` refuses
  `Enrollment(Unattached)` on the live attach event alone, as the model
  does; the model reaches the refusal only for an owner that an end left
  its attachment and a takeover then deposed, a takeover Rust refuses at
  this head (see the `takeover` abstraction). The order after the
  completed attach is a caller obligation (below). In the code the standby
  host runs `enroll_standby`
  with its own store client; the model runs it on a reconciler process, so
  an enrollment shares the two processes with the reservations and releases
  and ends at that process's crash.

A census, shard or volume write commits only at the version its operation
read. `unknown` ends an operation at its next write with no reply: the
write commits, is lost, or is held, and `deliver` delivers the one held
write later. `crash` stops a reconciler, which loses the slot it held. The
environment loses a host (`lose`), a reconciler learns a loss (`learn`) or
falsely suspects a live host (`suspect`), the control plane answers a
recorded attach (`attachEnds`: it completes, or fails for good and stays
live with no pair, and a failure for good is final), the reconciler ends a
live attach whose host the shard record names neither owner nor standby
(`endRead` and `endWrite`, described below),
an actor outside the census takes an attachment slot
of a host under its limit (`occupy`), and each shard record moves by the
owner's bump (`bump`), the named standby's takeover (`takeover`), the live
owner's planned transfer to its named standby (`transfer`, amendment A2 and
D19), which, as the takeover does, names the standby owner at the next
attempt and leaves no standby, a flip to the next generation on a volume its
new owner alone attaches (`flip`), and the fresh first acquisition after a
flip (`fresh`). The transfer is one of the shard-record moves of every
scheduler, and 21 of the 27 rooted searches hold one, so the census invariants
are checked where a transfer clears the standby: the `transferred` and
`redesignating` roots in their prefixes, and 19 roots past them, each with
the reach case `standbys-<root>-reach-witnessTransferred`: `reserved`,
`designated`, `designating`, `racing`, `replacing`, `moved`, `crashed`,
`cross`, `cross-bumped`, `cross-both`, `storm`, `storm-taken`,
`storm-racing`, `storm-shared`, `storm-recorded`, `storm-designating`,
`ending`, `endingDesignation` and `endingCross`. The free search at
`BOUND = 7` ends before a designation names a standby, so it takes no
transfer. Six roots complete their searches with none: `unenrolled`,
`cross-fresh`, `begun` and `failed`, and `releasing` and `bumped`, whose
prefixes bump shard 1 to `E = 2`, where one attempt remains. One
inverted-invariant search of each of the six on the model of this revision
showed that; no registered case repeats it.
The transfer's guards are the record naming a standby whose live, enrolled
attach the volume record shows, the owner's liveness, and two attempts left
at or below `EMAX`: the transfer takes one and the new owner's own bump the
other, the tenure model's rule (`TransferLeavesBump`, with the control
`transfer-spends-last-attempt`). No invariant of this model reads the owner's
liveness: a transfer by a lost owner passes every root, since the census,
coverage and slot rules judge the record the write leaves, and the writer's
authority is the tenure model's `TransferByOwnTenure`. The cleared standby
has the control `transfer-keeps-standby`, and the step's read of the target's
attach has `transfer-ignores-target-attach`, a transfer with no such read;
the abstractions below state what that one-step read leaves out. The new
owner is read by
`witnessMovedFromOwner` from the `transferred` root, and the raised attempt
by `transferThenRedesignate`'s end state. A transfer that leaves the
record's version unchanged passes every root as well, and no invariant of
this model reads that version. The version the transfer writes refuses a
designation of another host that read the record before the transfer. With
the version unchanged that designation's write commits over the transferred
record at a tenure its slot does not hold, and `safety` still holds: no
invariant compares a designation's tenure at its commit with its slot's.
One write is held at a
time: a held exact-version write is a write whose reconciler went on to
other operations, so two reconcilers and one held write run three
operations at once. `attachEnds` stands for the attach request and its
answer together: it answers any live attach event, one whose write
returned unknown or landed late included, so it also stands for the
caller's confirming retry of `record_standby` and its `StandbyRecorded`
witness, which the model omits. It admits more histories than a caller
that requests the attach only after that witness.

The instance is a set of constants: the shards, hosts and `CAP`; each
shard's initial owner and standby and the hosts whose live attach of its
volume has an enrolled pair (the census starts listing each named standby);
the hosts lost at
the start; a host's attachment limit `ATTACH`, the attachments `USED` each
host holds outside the modeled volumes, and the host role limit `ROLES`;
and the environment's further losses, false suspicions, outside
attachments and generations.

| Instance | Shards, hosts, `CAP` | Start | `ATTACH`, `USED`, `ROLES` |
|---|---|---|---|
| S2 | 2, 3, 1 | Host 1 owns shard 1, host 2 owns shard 2; every host is attached and enrolled on shard 1's volume, and hosts 2 and 3 on shard 2's. | 9, 0, 9 (slack) |
| S2H | 2, 3, 2 | Host 1 owns shard 1 and stands by shard 2, host 2 owns shard 2 and stands by shard 1; host 3 is on neither volume. | 3; host 3 holds 2; 2 (`ATTACH` binds; two shards give a host at most two roles) |
| S3 | 3, 4, 2 | Host 1, lost at the start, owned shards 1 and 2 and stood by shard 3; host 2 stands by shard 1, host 3 owns shard 3, host 4 is on no volume. | 3; host 4 holds 1; 2 (`ROLES` binds) |
| S2E | 2, 3, 2 | Each shard attached to its owner alone, with no standby. | 3, 0, 2 |
| S4 | 2, 4, 1 | S2 with a fourth host on neither volume, while shard 1's volume holds `MAX_ATTACHED` live attaches. | 9, 0, 9 (slack) |

S2 allows one further host loss, one false suspicion and two generations;
S2H one further loss and one outside attachment; S3 neither. S2H and S3
make no false suspicion, since a host is lost only on report silence plus
instance evidence (D9). The host invariants range over live hosts, and S3
starts with lost host 1 holding three roles.
`E` is at most 3 and `MAX_ATTACHED` is 3, the owner's `N_reg` is at least 3
and no volume record reaches `MAX_EVENTS`, so `Attach::of` closes a volume
only at `MAX_ATTACHED` live attaches, and an ended attach frees its slot
under that bound once the whole combined end step below has run: the model
has no state for a Rust record whose end mark landed with the ended pair
still recorded, where Rust's format-2 `Attach::of` still counts the pair and
the event (slot reuse in Rust waits for U31 and U37).

The attach end, which the ticket calls `endAttach`, is
`Reconciler::end_attach`, `detachable` and `release_attach` in Rust, which
the zone loop's reclaim calls. The model takes it in
two steps. `endRead(s, h)` decides the end of a live attach whose host the
shard record names neither owner nor standby at `E > 0`. The decision reads
no census, as `Reconciler::end_attach` of #264 reads none, so a census entry
may still name the host for the shard. The decision keeps the
volume record's version and the standby its reads saw. `endWrite(s, h)` lands
it later, whatever the shard record and the census name by then, as a write
conditioned on that volume version: it refuses with no write when the volume
record moved (`endRefusedOnMovedVolume`). A landed end removes the attach from
the volume record's live attaches and enrolled pairs and frees its slot; the
host's attachment is released unless the shard record names the host owner by
then, and an attach that failed for good stays failed for the shard. An
attach the control plane had not answered when its end landed is never
answered, since `attachEnds` answers only a live attach: a premise of
`HostAttachmentsWithinLimit`, stated below with its control
`ended-attach-completes`.
`end-keeps-enrolled`, whose end leaves the pair, breaks
`DesignatedIsEnrolled`: a designation names the ended host. The end
mark, the owner's pair drop, the detach and the gone mark are this one step;
the tenure model's reclaim schedule checks their order. One end decision is
open at a time, and a flip drops an end decided on the displaced volume.
Four rules of the end have a witness or a stated bound and no control: the
write's version condition, whose refusal `endRefusedOnMovedVolume` reaches,
the flip's drop of an open decision, the limit of one open decision, and the
release of the ended host's attachment, after which `endingCross` reaches a
reservation that takes the freed slot (`witnessMovedOnLoss`). With each
removed, `safety` holds in the `ending`, `endingDesignation`, `endingCross`,
`moved`, `cross-bumped`, `cross-fresh`, `cross-both` and `failed` roots. The
rule that a failed attach stays failed after its end has a control, since
the end decision reads no census: in `end-clears-failed` the census entry
that named the host owes an attach again after an attachment outside the
census took its slot, which breaks `HostAttachmentsWithinLimit`; the `cross`
and `cross-bumped` roots' searches find it too. An
end can land on a host that took the shard over after the decision
(`endLandsOnOwner`): the owner keeps its attach and its pair is gone from the
record, so the code's serving check, which requires the owner's enrolled
pair, refuses standby steps that the model's tenure-only checks admit.
The model's `takeover` checks the named standby's attach and nothing of the
owner it deposes, so it admits a takeover of that shard; at this head
`Takeover::records` refuses it `Check::Predecessor` (see the abstractions),
so in Rust a shard whose owner an end landed on admits neither a standby
step nor a takeover. In the model, once another host takes the shard over,
the former owner holds a completed attach and no live attach, and its
enrollment refuses `Unattached` (`enrollRefusedUnattached`).
`enroll-unattached`, which drops the refusal, lets it enroll with no attach
record and be reserved and designated, and breaks `DesignatedIsEnrolled`.
Both follow that second takeover, a history Rust cannot produce at this
head: they check the model's refusal and show no route to
`Enrollment(Unattached)` in the code. The end
ghosts (`ending`, `ended`, `raced`, `endedOwners`, `closed`, `reopenable`,
`releasedEnded`) are a state variable `en` of their own beside `st`.

Abstractions:

- The `serving` and STANDBY-TENURE checks of `designate`, `record` and
  `enroll` reduce to the record's tenure (for `record` and `enroll`, the
  generation of the volume they read, so the record names that volume
  active, and another owner at `E > 0`; for `designate`, the slot's tenure)
  and, for `designate`, the enrolled pair, since every modeled owner holds
  an enrolled attach of an intact fresh or active volume until an end lands
  on it (`OwnerHoldsItsAttach`). The code reads
  coverage page 0 only after the checks before it pass: a designation reads
  it after its census read once the record passes STANDBY-TENURE and the
  volume passes the origin, state and owner-enrollment checks, so its write
  path, its refusal for a fence of another generation and its refusal for a
  candidate with no enrolled pair follow a page-0 read, and its `Stale`,
  census `Conflict`, as-is and STANDBY-TENURE refusals read none;
  `record_standby` and `enroll_standby` read it after a shard read under the
  same checks. The model has no page-0 step. An attach record begun after a
  flip refuses at `E = 0` with no step between its reads; a refusal after
  an earlier check passed needs a flip, a fresh acquisition or a takeover
  after that check, and the recipe cases reach the flip forms in S2. The
  owner-enrollment check is taken from the current volume record, where the
  code checks the volume record the operation read; every modeled owner is
  enrolled in the current record, and a same-generation takeover by a host
  enrolled after the operation's volume read is accepted where the code
  refuses. `reserve`'s `Conflict` refusal, for an active volume whose
  origin or state no designation accepts, is a code step with no model
  outcome, since every modeled volume passes that test. `enroll_standby`'s
  `Enrollment(Full)`, `Persist` and `Binding` refusals are outside the
  model.
- `takeover` reads the named standby's live, enrolled attach and writes the
  shard record in one step. `Takeover::run` reads the volume record, then
  the shard record, and issues a CAS on the shard record it read, so an end
  that lands between its volume read and its CAS makes owner a host whose
  attach ended and was detached. This model has no such history, and
  `OwnerHoldsItsAttach` says nothing about it. The tenure model's reclaim
  schedule splits the takeover and reaches it: in
  `missingOwnerPollWithdraws` that owner's poll withdraws and retires
  nothing. The step checks nothing of the owner it deposes, so it admits a
  takeover over an owner whose attach ended (the second takeover of the
  `enrollRefusedUnattached` recipe, after the end landed on the owner as
  in `endLandsOnOwner`), as the tenure model's reclaim chains admit an
  ended predecessor under the format-3 design. At this head
  `Takeover::records` refuses that takeover at step 1 with
  `Check::Predecessor`, before the CAS: `VolumeRecord::enrolled` gives a
  pair only for a live attach
  (`failover::takeover::tests::a_predecessor_recorded_for_an_ended_attach_refuses_before_the_cas`).
  The model admits more takeovers than the code there, so the difference
  removes no history from a search; `enrollRefusedUnattached` and
  `enroll-unattached`, the model's one route to the `Unattached` refusal,
  follow a takeover the code refuses.
- `transfer` reads the named standby's live, enrolled attach and writes the
  shard record in one step, as `takeover` does. The volume record and the
  shard record are separate records, and the planned transfer writer (#279)
  reads the volume record and then issues its CAS on the shard record as two
  requests, so an end that lands between them makes owner a host whose
  attach ended and was detached. This model has no such history, and
  `OwnerHoldsItsAttach` says nothing about it:
  `transfer-ignores-target-attach` shows only that a transfer with no read
  of the target's attach breaks the invariant. The tenure model's run
  `handoffTargetAttachEndsBeforeCommit` reaches the record that history
  leaves: the end write lands between the transfer's issue and its commit,
  the target's restart starts no process and nothing retires, and in
  `handoffEndedTargetFreshHostRecovers` a host named over the transfer's
  tenure takes over. Its `transferStart` reads the shard record alone, so
  the order of the writer's volume read and its CAS is outside both models;
  the Rust test of that history is #279's.
- The reservation and the release read the record of the shard's current
  active volume, where the code reads the volume its shard read named.
  After a flip between the two reads the model can drop an entry the code
  keeps, and can keep (`keptLive`) an entry the code drops; a reservation
  can judge the candidate live or the volume open differently from the code.
  Volume records are keyed by shard, so the version condition also stands
  for the volume's identity: a volume write conditioned on the displaced
  volume's version fails in the model, where the code commits it to the
  retired record and then refuses at its shard read.
  `volume-write-ignores-version` shows that identity role, a write landing
  on the replacement's record, which the code cannot make;
  `volumeConditionLost` is the same-volume version race. A flip
  leaves the displaced volume's completed and failed attaches behind and
  stops counting them as used, though the host still holds them; the flip
  premise below keeps flips out of the instances where the limits bind.
- A store read returns its record's latest committed version at one point
  during the read, as the store contract promises; the model's read step
  stands for that point, and reads of different records form no snapshot.
  A read always returns and changes no record, so a failed read followed by
  a retry is a pause and then a fresh `begin`. A census write
  sets one slot of the stored census, which equals the code's write of the
  whole record under the version condition; `census-write-ignores-version`
  shows that the condition holds the cap.
- A flip names a new owner other than the current one. This restricts the
  model: the code and the tenure model's takeover also admit a spare on the
  current owner's host. A takeover, a flip back to the earlier owner and a
  fresh acquisition reach a shard record that differs from a slot in its
  generation alone. Right after a flip only the new owner is attached and
  enrolled on the shard's volume, and within the S2 search bounds (7 steps
  from the initial state, 6 past a root) no designation write of that shard
  commits at the second generation, which needs a fresh acquisition, a
  reservation, an attach record, its answer, an enrollment and a
  designation after the flip. A designation whose volume read and shard
  read both preceded the flip decides over the first-generation record, and
  returns that record as it is with no write when it names the
  designation's host.
- The loss evidence is each reconciler's set of hosts it holds lost, with
  each host whose attach of the shard's volume failed for good, the
  caller's `lost` closure. Every reconciler sees a failure for good at
  once, where the code's caller must pass it in. The model makes moves and
  drops the code would make later, and it omits the histories in which a
  reconciler that has not learned the failure reserves or renews the failed
  host, refuses `Taken` or keeps the entry as live.
- A host's report shows the attachments it holds, the modeled completed
  attaches and its attachments outside the volumes, and lists a shard in
  the standby role when the volume record enrolls the host's pair and the
  host does not own the shard (`RecordedRole::Standby`). A reservation
  counts the entries of the census it read and classifies them by the
  current report at its decision. The recovery gauge is outside the model.
- Each reconciler holds at most one slot, from its own reservation, and
  loses it when it starts another reservation or crashes. `need` is outside
  the model: any operation may start on any shard. An attach record runs
  for a host with no live attach of the volume, and an enrollment for a
  host with no pair; their retries, which write nothing, are outside the
  model.
- The compiled model, which Quint sends to Apalache as one JSON value, must
  stay under Apalache's 20,000,000-character limit; the reconcilers'
  processes, the last event and the attach ends are state variables of
  their own to keep it under that limit, and each search, reach, run,
  mutant and recipe instance holds only the actions, definitions and values
  its case reaches (`standbys_check.py`'s `prune`). At this revision `quint
  compile --target json`, given the case's main module, invariant and step,
  gives 18,485,017 characters for `standbys-cross-both-safety`, the largest
  instance, 18,257,013 for `standbys-cross-safety` and 13,405,944 for
  `standbys-run-attachFailedMovesSlot`, where the whole model gives
  20,108,166 for `standbys-run-attachFailedMovesSlot`, past the limit. The
  fresh contender's run, `standbys-run-freshTakesStaleEntry`, gives
  13,767,216 on the model with that run's cases.
- The host invariants range over live hosts: a lost host completes no
  attach, takes no outside attachment and takes no shard over, so the
  entries that still name it hold no physical slot.
- `hw`, `displaced`, `barred`, `reserved`, `recorded` and the flags
  `regressed`, `unevidenced` and `overturned` are history the invariants
  read, and `orphan` and `ev` are history the witnesses read. A census write
  carries its writer's grounds for the host of the entry its census read
  returned: the owner its shard read named, a loss the reconciler learned,
  that host's attach of the volume failing for good, its false suspicion,
  or, for a release, a volume read that shows no live attach. The witnesses
  name a move by those grounds. That host is the one the write replaces or
  drops, because the write commits only at the version it read.

The model takes these obligations from its caller as guards, with the
host role limit (D29) among them:

- `record` starts only for the host that holds the shard's slot, while the
  census lists that slot when the record starts; the model reads the census
  in the step of the record's volume read, and `record_standby` reads no
  census. Nothing requires the entry to stay listed when the volume write
  commits. A caller that checks the listing earlier leaves a window in
  which a release can commit its drop; only the stuck-bound obligation on
  the holder covers that window. `attach-before-reservation` drops the
  guard for a reconciler that holds no slot, a pair never listed, and shows
  historical membership only. `record-ignores-listing` drops the listing
  comparison alone: a holder records its host's attach after a release
  dropped the entry, an outside attachment takes the slot the entry held,
  and the completed attach breaks `HostAttachmentsWithinLimit`.
- `enroll` runs only after the control plane completed the host's attach
  (`enroll-before-attach` drops it): an enrollment before that answer stops
  counting the entry as pending while the attach is not yet used.
- Every reconciler maps each shard to zone 1 (`zoneOf`) and applies one
  `CAP` (`capOf`); `zones-disagree` and `storm-mutant-caps-disagree` drop
  them.
- A reservation decides on the host's current report, which the model
  reads at the decision (`stale-report` counts the outside attachments
  published at the start while the completed attaches and standby roles
  stay current).
- The candidate filter excludes a host at the role limit from a
  reservation that would add a role, on every reservation and on every
  retry after a lost census write; a host gains no role on a shard it owns
  or whose census entry already names it. It counts the census version
  the reservation's write is conditioned on. In the model the filter reads
  the census and the shard owners in the step of the reservation's census
  read. A loop that filters over an earlier survey must recheck the role
  count on the reservation's own census read, or refuse a plan whose census
  version no longer matches; that recheck belongs to the role filter of U25
  as the loop of U26 applies it, and `Population::admit` does not make it
  today. A matching census version does not validate shard owners read
  before that census, so the recheck needs owners no older than the census
  it counts. A filter over an earlier census is outside this guarantee.
  `storm-shared-mutant-roles-unfiltered` and `retry-without-replan` drop
  the filter. A reservation names no host its reconciler's evidence holds
  lost.

`HostAttachmentsWithinLimit` and `StandbyRolesWithinHostLimit` also rest on
these premises of the environment:

- Loss evidence names only lost hosts (D9): S2H and S3 make no false
  suspicion. `false-suspicion-headroom` shows the attach of a falsely
  suspected host, recorded before its slot moved, counted nowhere until it
  completes, and `false-suspicion-roles`, at `ROLES = 1`, a host whose
  census entry moved off it on a false suspicion and that still takes its
  shard over as the named standby, a role the census no longer counts.
- The control plane answers only a recorded attach: `attachEnds` runs for
  a host the volume record shows live, so the attach event precedes the
  attach call (STANDBY-WRITE-ORDER). `attach-before-record` drops it: host
  3 attaches both volumes with no attach record and no census entry that
  owes the slots, past `ATTACH`. `DesignatedIsEnrolled` does not rest on
  this premise: an enrollment refuses `Unattached` for a host the volume
  record shows no live attach.
- An attach that failed for good never completes afterward. The model
  assumes it, the loop of U26 and U27 owns the classification of a failure
  for good, and a timed-out attach with no answer is not one.
  `failed-attach-completes` drops it: the failed attach's entry stops owing
  a slot, an outside attachment takes that slot, and the attach then
  completes past `ATTACH`.
- No attach is answered after its end. `endRead` decides the end of any
  live attach its role check admits, one the control plane has not answered
  included, and `endWrite` stands for the end mark through the gone mark,
  so the model's end also ends an attach call still in flight and frees the
  host's slot in that step. STANDBY-WRITE-ORDER does not give this. It is
  the tenure model's cutoff, that no request lands after its entry's
  detach, taken at the one step; `reclaim-late-land-after-detach` drops it
  there. `ended-attach-completes` drops it here: host 3's recorded attach
  ends before its answer, a release drops its entry on the ended record, an
  attachment outside the census takes the slot the entry owed, and the
  attach then completes past `ATTACH`. The model has no state between the
  end mark and the gone mark, where the tenure model lets a request land on
  an ended entry (`failedAttachLandsLate`) and the attachment stays until
  its detach, so a release that reads the ended record in that window and a
  slot taken before the gone mark are outside this model. The code does
  not hold this premise (FP-LOOP-07, unit blotter issue 1813 step 7): the loop moves the
  census slot off an ended attach after the end write, so the host's entry
  leaves at the end mark, and an attach request that lands after its end is
  in neither count. `HostAttachmentsWithinLimit` is therefore a property of
  the model and no evidence for the code; the code's bound is HEADROOM at
  the reservation and the provider's limit.
- The loop's stuck bound: an entry whose release would drop it stays while
  an attach record of its shard and host is in flight
  (`release-ignores-recording`) or its write is held
  (`release-ignores-held-record`, where the late live event lets a new
  reservation skip `Headroom` after an outside attachment fills the host),
  and no attach record starts while a release's decided drop of its slot is
  unsent (`record-after-drop-decision`, which drops the guard on a recipe
  whose release write is unsent) or held (`record-after-held-drop`, which
  drops the held clause alone).
  The model's release and record read the other reconcilers' processes and
  the held write, which no production loop can do. No production form of
  this premise is known yet, and this model verifies none: U26 and U27 must
  establish the ordering, that no attach record starts after a release's
  deciding volume read and before its drop commits or fails, and that the
  release decides on a volume read taken after every permitted record
  write, including one of a holder paused before it sent the write and one
  whose timed-out write can still land, has landed or can no longer land. A
  timed design needs a cutoff the holder itself observes, since a holder
  cannot observe another reconciler's volume read, with the store's bound
  on late delivery and a clock-drift bound as stated external premises; a
  timeout is not evidence that a write did not run (R8). A tenure-fenced
  `record_standby`, which refuses unless the shard record holds the slot's
  `(g, owner, E)` at both shard reads, withholds the witness from a record
  that starts after the release's shard read, but a record already in
  flight or held can still commit its volume write after the drop and
  leave a live event with no entry, which a later reservation admits as
  `Attach::Live` with no headroom check; the fence alone does not replace
  the ordering, and no case checks it.
  `cross-bumped-mutant-release-before-stuck-bound` drops all three rules,
  and the `cross-bumped` root's search finds it.
- The report a reservation decides on stays accurate from the caller's
  capture through the census write. An actor outside the census takes a
  host's slot only while the host's attachments plus the entries that still
  owe it an attach stay under `ATTACH` (`cross-mutant-occupy-ignores-owed`
  drops that), and takes none while a reservation for that host has decided
  on its report and its census write is unsent or held
  (`cross-mutant-occupy-during-reservation` drops both clauses, and its
  counterexample uses the unsent write;
  `occupy-during-held-reservation` drops the held clause alone). The runs
  `headroomAfterTakeoverBetweenReads` and
  `reservedAfterEnrollBetweenReads` show the results for a report current
  at the decision, which a caller obtains only when no takeover or
  enrollment lands after its capture. Production attachers read no census, so an attachment
  outside the census can break either premise. The standby attach can then
  fail for good; once its attach event is recorded it spends one of the
  volume's `MAX_ATTACHED` attaches until the zone loop's reclaim ends it. The
  invariant states the census's accounting under these premises, and no
  host enforces it.
- No flip runs where the host limits bind (`GMAX = 1` in S2H and S3): a flip
  makes its spare's host the owner with no role or headroom check, and
  stops counting the displaced volume's attaches. The spare's selection
  and its headroom and role check are outside the model and are a caller
  obligation of the flip path. `flip-at-attach-limit` (S2H) and
  `flip-at-role-limit` (S3) raise `GMAX` to 2: two flips to one host put
  it past `ATTACH` and past `ROLES`.

| Property | Guarantee |
|---|---|
| `CensusUnderCap` | Each zone's census lists at most `CAP` shards. |
| `StandbyCovered` | Every shard record that names a standby has an entry in zone 1's census. |
| `StandbysUnderCap` | At most `CAP` shard records name a standby; with one zone map it follows from the two above. |
| `SlotMovesOnlyOnEvidence` | Every committed census write that moved a slot from host x, or dropped x's entry, had grounds for x: its reconciler's evidence that x is lost or that x's attach failed for good, a shard read that names x owner, or, for a drop, a volume read that shows x no live attach. |
| `NewerDesignationStands` | After the slot moved away from x and a designation write named its new host, no designation of x commits at that `(g, owner, E)` unless the slot moved back to x. A designation that finds its host already named writes nothing, so it fences no older designation of x still in flight. |
| `EntryTargetAdvances` | No committed census entry names an earlier `(g, E)` of its shard than an entry the census listed for it before. |
| `FeasibleSlot` | No census entry names its target's owner or `E = 0`, and no shard record names its owner standby. |
| `DesignatedIsEnrolled` | Every standby a shard record names holds a live attach of the volume with an enrolled pair, or its attach ended in a race with its designation (`en.raced`): the end was decided while the shard record did not name the host standby and landed after a designation named the host (`designationBeforeEndLands`), or landed between the volume read, which showed the attach live and enrolled, and the shard write of the designation that named the host (`designationRacesEnd`, and `designationBehindRivalRacesEnd`, where another host's designation commits between the two). The second race is credited at the designation's own write: `designate-unenrolled-after-race`, a designation with no enrollment check that begins after the end, breaks the invariant though an earlier designation of the host was in flight when the end landed. The race ends at an enrollment of the host, a designation of another host or a flip. The end conditions on the volume record and the designation on the shard record, so the two commit in either order; the tenure model's `designationRacesEnd` shows such a standby refusing before any device command, and `designationRacesEndAfterCas` refusing at its reread after Register and Report #1 with no preempt. `moved-mutant-end-ignores-standby`, whose end decision ignores the record's standby, breaks it. |
| `OwnerHoldsItsAttach` | Every owner at `E > 0` holds a live attach of its volume with an enrolled pair, or its attach ended after it became owner: a takeover makes owner only a standby with a live, enrolled attach, which the step reads and writes at once (see the abstractions). `takeover-ignores-end`, a takeover of a standby whose attach ended in a designation race, breaks it. |
| `TransferLeavesBump` | Every planned transfer writes an `E` below `EMAX`, so the owner it names has an attempt for its own bump. `transfer-spends-last-attempt`, whose transfer issues at `E = EMAX - 1`, breaks it. |
| `AttachFollowsReservation` | Every attach event a reconciler recorded is for a shard and host some census listed at some time, at any tenure; this is historical membership. The `record` guard checks the writer's listed slot when the record starts, and no check requires the entry to stay listed when the write commits. |
| `HostAttachmentsWithinLimit` | For every live host, its attachments plus the census entries that still owe it an attach stay within `ATTACH`, under the premises above. |
| `StandbyRolesWithinHostLimit` | For every live host, the shards it owns plus the census entries that name it on other shards stay within `ROLES`, given that loss evidence names only lost hosts (D9) and that no flip runs where the limits bind. A takeover turns the new owner's entry for the shard it took over into its owner role, so that entry counts once. |

[standbys_check.py](standbys_check.py) checks `safety`, the conjunction of
the thirteen. `standbys-safety` searches every history of `BOUND = 7` steps
of S2 from the initial state, which reaches at most one reservation and
part of a designation. The other searches start from prefix roots, each a
legal history, in the `projection_cases` form, each with its own `safety`
case:

| Root | Instance | Steps past the prefix | Prefix ends with |
|---|---|---|---|
| `reserved` | S2 | 6 | Reconciler 0 holds shard 1's slot for host 2. |
| `designated` | S2 | 6 | Shard 1 names host 2, and reconciler 0 still holds the slot. |
| `designating` | S2 | 6 | Reconciler 0's designation of host 2 has read the census and writes next. |
| `racing` | S2 | 6 | Reconciler 1 moved the slot to host 3 on its false suspicion while reconciler 0's designation of host 2 has read the volume and shard records and reads the census next. |
| `replacing` | S2 | 6 | Reconciler 1 moved the slot to host 3 and its designation has read the shard record. |
| `releasing` | S2 | 6 | Reconciler 1's release read the census at shard 1's first tenure; then the owner bumped and reconciler 0 reserved and designated host 2 at the new tenure. |
| `moved` | S2 | 6 | Shard 1 names host 2, and reconciler 1 moved the slot to host 3. |
| `unenrolled` | S2 | 6 | Reconciler 0 holds shard 2's slot for host 1, which holds no attach of that volume. |
| `crashed` | S2 | 6 | Reconciler 0 stopped holding shard 1's slot, and reconciler 1 found it listed. |
| `begun` | S2 | 6 | Both reconcilers began reservations of different shards over the absent census. |
| `bumped` | S2 | 6 | Reconciler 0's reservation read shard 1's record at its first tenure; the owner bumped, and reconciler 1's reservation at the new tenure writes next. |
| `cross` | S2H | 12 | Host 1 is lost, and both reconcilers know it. |
| `cross-bumped` | S2H | 11 | Host 2 took shard 1 over, reconciler 0 reserved host 3 for it, and the owner bumped. |
| `cross-fresh` | S2H, two losses | 6 | Shard 1's owner and standby are lost, and host 3 is reserved, attached and enrolled for it. |
| `cross-both` | S2H, host 3 standing by shard 1 with one free slot at the start | 6 | Host 1 is lost, and host 3's designation for shard 2 writes next, with every slot of host 3 used or owed. |
| `storm` | S3 | 11 | Both reconcilers know host 1 lost. |
| `storm-taken` | S3 | 7 | Host 2 took shard 1 over, and the release dropped shard 1's entry. |
| `storm-racing` | S3 | 6 | After shard 1's slot was freed, both reconcilers read one census and decided to reserve host 2 for shards 2 and 3; both census writes are next. |
| `storm-shared` | S3 | 6 | Host 2 owns shard 1 and holds shard 2's slot, at the role limit. |
| `storm-recorded` | S3 | 6 | Host 2 took shard 1 over, and host 3's attach of shard 1's volume is recorded under its new slot. |
| `storm-designating` | S3 | 8 | Host 2 took shard 1 over, and host 3 is reserved, attached and enrolled for shard 1. |
| `failed` | S2E | 6 | Host 2's recorded attach of shard 1's volume failed for good, so host 2 is live with no pair, and reconciler 0 still holds the slot. |
| `transferred` | S2 | 5 | Shard 1 names host 2, and its owner transferred it to host 2, which clears the standby. |
| `redesignating` | S2 | 5 | After that transfer, reconciler 0 moved the census entry off the new owner to host 3. |

`standbys-cross-safety` and `standbys-storm-safety`, the cases issue blotter issue 1805
names, search every continuation of the `cross` and `storm` roots up to the
bounds in the table: 12 steps of S2H and 11 steps of S3 after host 1's loss
is known to both reconcilers.
Each witness is checked as the inverted invariant `not(witness)` from the
initial state or the root that reaches it within the search. From S2: the
census create, `Ineligible`, `Taken`, `Full`, a census write that lost its
version condition, a reservation whose pending census write names an
earlier tenure than an entry the census listed for its shard, each unknown
outcome, a delivered held write, the release
of an absent census, the release of a shard the census does not list, a
designation, a designation write that lost its version condition, `Stale`,
the releases kept for the current target, a live attach and a named
standby, a dropped entry, slots moved on true loss evidence, on a false
suspicion and away from the host the
record names owner, a listed slot, the as-it-is designation, a replaced
designation, `Conflict`, a designation refused for a host with no enrolled
pair, a crash between reservation and designation after which the other
reconciler designates the shard, a planned transfer, and a designation that
names a standby again after one. From S2H: both shards needing the one
remaining host, the `Headroom` refusal, an attachment taken outside the
census that fills the last free slot of host 3, the one live host that
owns no shard, a release kept while its entry's attach is recorded, a fresh host
designated after owner and standby loss, one host standing by both
shards, and a planned transfer. From S2E: a slot moved on a failed attach,
and a designation
refused for a host whose attach failed for good and is live with no pair.
From S3: a `Full` refusal for a host with no attach, a live candidate
excluded at the role limit from a reservation of a shard it does not own
that the census rules would admit, a reservation that
finds its slot listed for a live host at the role limit, a census write
that lost its version condition, a third shard taking the slot released
after a takeover, the cap refusing the taken-over shard's re-reservation
(the re-enrollment issue blotter issue 1805 names), an attach that failed for good, the
`Closed` refusal, an enrollment after a takeover, a designation, and a
planned transfer. The
closed-volume refusal of `record` has no witness. `Closed` is also reached
by the `reopenedAfterEnd` recipe in instance S4, a fourth host on neither
volume.

Twenty-three directed runs check interleavings one store request per step, each
with `BOUND` set to the recipe's length. A run's case holds `safety` at
every step, each result the run names at a given turn, and the final state
at the last turn; its `-reached` case fails unless the recipe reaches that
final state, with a trace of one state more than the recipe's length. The
turn checks name the refusals, races, unknown results, attach and
enrollment results and record versions the final state does not show. The
table names, for each run, a related Rust test and how it differs from the
run.

| Run | Instance | Checked results, ending in the final state | Related Rust test |
|---|---|---|---|
| `capRefusesSecond` | S2 | Shard 1 designated, shard 2's reservation refused `Full`, one entry and the census unchanged. | `failover::standbys::tests::the_population_cap_admits_listed_shards_and_refuses_a_new_one_at_the_cap`, which checks the admit rule with no store request |
| `racingReservations` | S2 | Both reconcilers read the absent census; one create commits, the other loses its condition and its retry refuses `Full`. | `failover::reconcile_tests::concurrent_reservations_share_one_census_under_the_cap`, its first race: the same create conflict and retry, with the other reservation run whole before the loser's write |
| `earlierTenureLosesCondition` | S2 | Reconciler 0's reservation reads shard 1's record before the owner's bump and decides after reconciler 1's reservation at the new tenure created the census; its write, an entry at the first tenure, loses its condition and the entry at the new tenure stays. | none |
| `staleReconcilerRefused` | S2 | Reconciler 1 refused `Taken`, then moves the slot on loss evidence and designates host 3; reconciler 0's designation refuses `Conflict` with no shard write and its retried reservation `Taken`. | `failover::reconcile_tests::a_stale_reconciler_cannot_replace_a_newer_designation`, the same sequence one call at a time |
| `designateReadsCensusAfterShard` | S2 | Reconciler 1 moves the slot and designates between reconciler 0's shard read and its census read; reconciler 0 refuses `Conflict`. | `failover::reconcile_tests::designate_reads_the_census_after_the_shard`, whose hook runs the other reconciler's reservation and designation after the shard read |
| `releaseReadsShardAfterCensus` | S2 | Between the release's census read and its shard read, the owner bumps and the slot is reserved at the new tenure; the release's write loses its condition and the new entry stays. | `failover::reconcile_tests::concurrent_reservations_share_one_census_under_the_cap`, its last race, in which the release has read the census, the shard and the volume after a detach and the reservation runs before its write; `failover::reconcile_tests::release_reads_the_shard_after_the_census` hooks after the shard read, so both reads precede the bump and the release writes nothing |
| `restartConverges` | S2 | A reservation write of unknown outcome commits and grants no slot; the retry finds the slot listed, the reconciler crashes holding it, and the other reconciler finds the slot listed and designates it: one entry and one designation. | `failover::reconcile_tests::a_restarted_reconciler_converges_on_one_reservation`, whose retry in a new reconciler runs to completion after each unknown outcome; the run restates the committed outcome |
| `flipReleasesEntry` | S2 | After a flip with no standby named, the release drops the entry. | `failover::standbys::tests::a_census_entry_leaves_only_after_its_tenure_moved_with_no_standby`, which checks the release rule with no store request |
| `enrollOne` | S2E | One shard reserved, its attach recorded and completed, the pair enrolled and the host designated: one entry, one enrolled live attach, the standby named, no Register step. | `failover::reconcile_tests::the_standby_persists_before_enrollment_and_returns_the_enrolled_pair`, which calls `enroll_standby` alone through its `Tenure` and `Unattached` refusals, then runs `record_standby` and checks that the local record is persisted before the pair write |
| `hostInTwoRolesLost` | S2H | Host 1 is lost and host 2 takes shard 1 over; both shards reserve host 3, one slot short of `ATTACH`: one reservation and one `Headroom` refusal, after which the refused reconciler holds no slot and the census is at the version of the one reservation. | none |
| `ownerAtRoleLimit` | S2H | Host 2 owns shard 2 and stands by shard 1, two roles. The role filter passes its reservation for shard 2, which reads the records and refuses `Ineligible`. A second reservation reads the census, host 1 takes shard 2 over, and the write moves the slot from host 1, the new owner, to host 2, which holds two roles. | `failover::reconcile_tests::a_designation_names_an_enrolled_standby_and_replaces_it`, which checks that `reserve` refuses the owner `Ineligible` with no census write, with no role limit and no takeover |
| `reEnrollAfterTakeover` | S2H | After host 2's takeover of shard 1, host 3 is reserved, recorded, enrolled and designated under the new owner: the record keeps the promoted owner and attempt and names host 3. | none |
| `headroomAfterTakeoverBetweenReads` | S2H, host 3 standing by shard 1 | Host 3 takes shard 1 over between a reservation's census read and its volume read; the current report lists shard 1 as owned, so its still-listed entry counts as pending and the reservation refuses `Headroom`. | none |
| `reservedAfterEnrollBetweenReads` | S2E, host 3 holding one outside attachment | Host 3 enrolls on shard 1 between a reservation's census read and its volume read; the current report lists shard 1 in the standby role, so the reservation of shard 2 commits. | none |
| `renewedEntryKeptWhileRecording` | S2E, host 3 holding two outside attachments | While reconciler 0 records host 3's attach under its first slot, reconciler 1 renews host 3's entry at the next attempt; after another bump the release keeps the renewed entry, and the record completes with the entry listed. | none |
| `freshHostAfterDoubleLoss` | S2H, two losses | Shard 1's owner and standby lost; host 3 reserved, recorded, enrolled and designated, with the volume record keeping hosts 1 and 2 beside host 3; the recipe has no flip, so the generation is unchanged by construction. | `failover::takeover::tests::a_fresh_host_takes_over_the_retained_volume_after_owner_and_standby_loss`, whose helper runs `reserve`, `record_standby`, `enroll_standby` and `designate` with no control-plane attach answer, checks that the designation refuses before the attach record and before the enrollment, and goes on to the fresh host's takeover |
| `stormOwnerOfTwo` | S3 | After shard 1's takeover its re-reservation keeps its slot and host 3 is attached, enrolled and designated for it; the cap refuses shard 2's fresh host while shards 1 and 3 name standbys. | none |
| `slotTakenAfterTakeover` | S3 | With the housekeeping release ahead of the re-reservation, shard 2 takes the slot shard 1's takeover freed, and the cap refuses shard 1. | none |
| `slotKeptUnderLoopOrder` | S3 | With the re-reservation first, the loop's order for a `Standby` contender, shard 1 keeps its slot, the release keeps it, and the cap refuses shard 2. | `failover::zone_loop::tests::fresh_first::a_standby_contender_leaves_a_taken_over_shard_its_slot`, whose contender's owner serves |
| `freshTakesStaleEntry` | S3 | The loop's order for a fresh contender: the release drops the entry shard 1's takeover left, shard 2 reserves host 4, which is recorded, attached, enrolled and designated, and the cap refuses shard 1's re-reservation. | `failover::zone_loop::tests::fresh_first::a_refused_fresh_need_takes_the_slot_of_a_taken_over_shards_stale_entry`, the same order in six shards under a cap of five, through the loop's planner |
| `listedAfterUnknownAtLimit` | S3 | Reconciler 0's reservation of shard 2 for host 2 commits with no reply, leaving host 2 at the role limit and no reconciler holding the slot; reconciler 1's reservation of the same shard and host finds it listed and holds it, the census unchanged. | none |
| `renewedAtLimitAfterBump` | S3 | Host 3, at the role limit with shard 1's entry, has its attach recorded; after the owner's bump reconciler 1 renews host 3's entry at the new attempt. | none |
| `designationBehindRivalRacesEnd` | S2 | Host 2's end is decided. Host 3's designation writes next, the slot moves to host 2 on a false suspicion of host 3, and host 2's designation reads the volume record before the end lands. Host 3's designation commits and host 2's then replaces it: the record names host 2, whose attach ended in a race with its designation. | none |
| `attachFailedMovesSlot` | S2E | Host 2's recorded attach fails for good and stays live with no pair; the slot moves to host 3 on that evidence, and host 3 is designated while host 2 holds no pair. | `failover::reconcile_tests::a_reserved_host_whose_attach_failed_releases_its_slot_on_the_callers_evidence`, whose fixture has the replacement host attached and enrolled: it records x's attach, refuses `Taken` with no evidence, passes the failure to `reserve` as the caller's evidence, designates the replacement and checks that the stranded slot's designation refuses `Conflict`, with no attach answer or enrollment step |
| `transferThenRedesignate` | S2 | Shard 1's owner transfers it to host 2, its named standby, at `E = 2` with no standby; reconciler 0 moves the census entry off the new owner to host 3 and designates host 3: one entry, the standby named again. | none; the transfer writer is #279 (U39) |

The order of a re-reservation and a release after a takeover depends on the
contender. The model's reservation reads no need, so a run fixes the order
by its recipe, and a recipe runs the same schedule for either contender.
The zone loop's planner (FRESH-FIRST in `failover/zone_loop/plan.rs`) runs
the re-reservation first for a `Standby` contender, a shard whose owner
serves, which is the schedule of `slotKeptUnderLoopOrder`, and the
contender stays refused `Full`. For a fresh contender, a shard whose owner
is lost with no standby and whose need a full census refuses on that tick,
it withholds the re-reservation and runs the release first, the schedule of
`freshTakesStaleEntry` and of `slotTakenAfterTakeover`. In S3 shard 2's
owner is lost in every run, so no S3 recipe has a `Standby` contender of its
own; the Rust tests
`failover::zone_loop::tests::fresh_first::a_standby_contender_leaves_a_taken_over_shard_its_slot`
and
`failover::zone_loop::tests::fresh_first::a_fresh_need_after_an_admitted_re_reservation_stays_refused`
check, through the planner, a `Standby` contender and a fresh need that
appears after the re-reservation was written, which keeps its entry.

Root mutants show that a root's exhaustive search finds the race or the
rule a guard covers: `reserved-mutant-reserve-moves-live-incumbent`, whose
reservation takes the slot from a host its reconciler's evidence does not
show lost, and `reserved-mutant-release-ignores-live`, whose release drops
the entry of a host with a live attach (`SlotMovesOnlyOnEvidence`),
`designating-mutant-release-at-current-target` and
`releasing-mutant-release-reads-shard-first` (`StandbyCovered`),
`racing-mutant-designate-reads-census-first` and
`replacing-mutant-designate-skips-census` (`NewerDesignationStands`),
`bumped-mutant-census-write-ignores-version` (`EntryTargetAdvances`), whose
earlier reservation lands its entry at the first tenure over the entry at
the second,
`designated-mutant-designate-skips-stale` (`FeasibleSlot`),
`unenrolled-mutant-designate-unenrolled` and
`failed-mutant-designate-unenrolled`, the second for a host live with no
pair (`DesignatedIsEnrolled`),
`cross-bumped-mutant-release-before-stuck-bound` (`HostAttachmentsWithinLimit`),
`storm-mutant-attach-before-reservation` (`AttachFollowsReservation`),
`storm-racing-mutant-census-write-ignores-version` (`CensusUnderCap`),
whose violation needs a third reservation, of shard 1, over a census read
before shard 2's write landed,
`storm-racing-mutant-census-write-ignores-version-roles`, whose two pending
census writes both land and give host 2 three roles through the model's
one-slot census write, which shows nothing about a stale whole-record
replacement in Rust,
`storm-racing-mutant-retry-without-replan`, whose reservation retries a lost
census write with the host it planned, and
`storm-shared-mutant-roles-unfiltered`, a loop with no candidate filter
(all three `StandbyRolesWithinHostLimit`), and the premise controls
`cross-mutant-stale-report`, whose reservation counts the outside
attachments published at the start, `cross-mutant-occupy-ignores-owed` and
`cross-mutant-occupy-during-reservation` (all `HostAttachmentsWithinLimit`)
and `storm-mutant-caps-disagree`, whose second reconciler applies `CAP + 1`
(`CensusUnderCap`). Forty-seven mutants each break their property on a recipe whose last action
reaches the violation: `admit-ignores-cap` and
`census-write-ignores-version` (`CensusUnderCap`);
`release-at-current-target`, `release-ignores-standby`,
`release-reads-shard-first`, and `stale-ignores-attempt` and
`stale-ignores-generation`, `Stale` checks that leave out the attempt or the
generation (`StandbyCovered`); `release-at-current-target-two-shards`,
`fresh-takes-live-standby-entry`, a release with neither the standby nor
the live-attach guard that hands shard 1's entry, whose live named standby
stays named, to shard 2's fresh host, and the premise control
`zones-disagree`, whose second reconciler maps shard 2 to another zone
(`StandbysUnderCap`); `reserve-moves-live-incumbent`,
`release-ignores-live`, `census-write-ignores-version-one-shard`, two
reservations of one shard over one read of the empty census, and
`census-write-ignores-version-stale-release`, a release whose grounds name
a host the slot has since moved from (`SlotMovesOnlyOnEvidence`);
`designate-skips-census`, `designate-reads-census-first` and
`designate-write-ignores-version` (`NewerDesignationStands`);
`volume-write-ignores-version`, an enrollment whose write lands on the new
volume's record after a flip, `end-keeps-enrolled`, `enroll-unattached`
and `designate-unenrolled-after-race` (`DesignatedIsEnrolled`);
`takeover-ignores-end` (`OwnerHoldsItsAttach`);
`attach-before-reservation`, an attach record by a reconciler that holds
no slot (`AttachFollowsReservation`); `pending-uncounted` and
`record-ignores-listing`, an attach record begun after a release dropped
its slot's entry (`HostAttachmentsWithinLimit`);
`reserve-reads-shard-first` (`EntryTargetAdvances`);
`designate-skips-stale`, `owner-as-candidate`,
`ineligible-ignores-unacquired` and `transfer-keeps-standby`, a transfer that
keeps the standby it names owner (`FeasibleSlot`); `transfer-ignores-target-attach`,
a transfer to a standby whose attach ended (`OwnerHoldsItsAttach`);
`transfer-spends-last-attempt`, a transfer after the owner's bump at
`E = EMAX - 1` (`TransferLeavesBump`); `retry-without-replan`
and the premise controls `false-suspicion-roles`, which lowers `ROLES` to
1, and `flip-at-role-limit` (`StandbyRolesWithinHostLimit`); and the
premise controls `enroll-before-attach`, `release-ignores-recording`,
`release-ignores-held-record`, `record-after-drop-decision`,
`record-after-held-drop`, `occupy-during-held-reservation`,
`false-suspicion-headroom`, `attach-before-record`,
`failed-attach-completes`, `ended-attach-completes` and
`flip-at-attach-limit`, and `end-clears-failed`
(`HostAttachmentsWithinLimit`), the first three stuck-bound controls each
dropping one rule of the stuck bound and `record-after-held-drop` the held
clause of the third rule. The two-shard
`StandbysUnderCap` violation and `zones-disagree` are checked only on their
recipes, because their shortest violating schedules are longer than the
search bounds, and the two false-suspicion controls and the two flip
controls run in instances, with false suspicions or a second generation,
that no root searches. With two shards a host holds at
most two roles, so the role limit binds in S3 alone. The S2H cases check
`HEADROOM` against `HostAttachmentsWithinLimit`; no S3 case checks a
`Headroom` refusal.

Nineteen recipe cases of the unmodified model each reach a named state at
their last action: `conflictBeforeDesignation`, reconciler 0's `Conflict` after
the move with shard 1 unwritten; `designationOvertaken`, reconciler 0's
pending designation losing its version condition to host 3's at the same
tenure; `heldDeliveryRefused`, a held designation refused at delivery after
a bump; `suspicionHeldAcrossLoss`, a move admitted on the suspicion that
keeps that grounds when its held write lands after host 2's loss;
`releaseDropsOnLoss`, a release that drops an entry on a learned loss; and
`unlistedKeepsCensus`, a release of an unlisted shard that leaves the
census as it is; `unenrolledKeepsLive`, a release that keeps the entry of a
host with a live attach and no pair, the census version unchanged;
`recordRefusedAtFlip` and `enrollRefusedAtFlip`, an attach record and an
enrollment that read the volume before a flip and refuse at their shard
read with no write; `recordRefusedAfterFlip` and `enrollRefusedAfterFlip`,
the same operations refusing at their last shard read after their volume
write committed and a flip and a fresh acquisition named a new volume; and
`volumeConditionLost`, two attach records over one volume version, the
second losing its condition with the record as the first wrote it; and three over the end: `releasedAfterEnd`
(`witnessReleasedAfterEnd`), an end decided before the host's reservation
that lands after it, and a release that drops the entry whose host's attach
ended, `reopenedAfterEnd` (`witnessReopenedAfterEnd`, in S4), a
reservation that refuses `Closed` at `MAX_ATTACHED` live attaches and,
after another host's attach ends, a reservation and attach record that take
the freed slot, `designationRacesEnd` (`witnessNamedEnded`), a
designation that commits naming a host whose attach ended after its volume
read; and four more over the end: `designationBeforeEndLands`, an end
decided while the record named no standby that lands after the designation
of its host committed; `endLandsOnOwner`, an end that lands on the host that
took the shard over after the decision, which keeps its attach;
`endRefusedOnMovedVolume`, an end that refuses after an attach record moved
the volume record; and `enrollRefusedUnattached`, the enrollment of an
owner that an end left its attachment and a takeover deposed, refusing
`Unattached`. `standbys-safety` and every root's search run with `endRead` and
`endWrite` in the scheduler, so `StandbyCovered` and `CensusUnderCap` hold when attaches end.
Three roots search the end's races: `ending` (host 2's end decided, then its
slot reserved, 6 steps), `endingDesignation` (the end decided before a
designation of host 2 that writes next, 6 steps) and `endingCross` (S2H
with host 3 attached and enrolled on shard 1's volume, where it holds no
role, which takes its last attachment slot; after host 1's loss host 3 is
shard 2's one candidate, and the end of its attach is decided, 12 steps).
In `endingCross` a reservation of shard 2 for host 3 refuses `Headroom`
before the end lands (`witnessHeadroom`) and moves the slot off the lost
host after it (`witnessMovedOnLoss`), and the search goes on through the
attach record, the completed attach and the enrollment's write. With no
census read in the end decision, an end can land on an attach that a
census entry names: every case of the family keeps its declared outcome,
`StandbyCovered`, `CensusUnderCap` and, under the premise that no attach is
answered after its end, `HostAttachmentsWithinLimit` included, and 19
passing searches grow (`standbys-safety` from 8,070,491 to
8,075,657 distinct states). The end decision's owner guard has no control,
since an end can land on an owner anyway. A
recipe case's trace holds one state more than its
recipe's actions, and a reach case from the initial state holds 2 to
`BOUND + 1` states.

Eleven rules of the model broke none of the eleven invariants of #262's
model, which this model extends with the attach end and
`OwnerHoldsItsAttach`. No registered case removes them; on #262's host, a
copy of #262's model with each one removed left all 23 `safety` searches
passing, so a pass of `safety` says nothing about them. The reach, recipe and run cases named below are
their only registered checks, and four have none: the closed-volume
refusal of `record`, the record-standby clause and the two start
conditions.

- The `Closed` refusal of a reservation, which `witnessClosed` reaches. The
  model has no invariant on a volume's count of live attaches, so neither
  closed refusal guards one.
- The closed-volume refusal of `record`, which has no witness; removing
  it left the number of reachable states of every search unchanged.
- STANDBY-TENURE before the write of `record` and of `enroll`, which
  `recordRefusedAtFlip` and `enrollRefusedAtFlip` reach; removing the
  enrollment's left the number of reachable states of every search
  unchanged.
- The designation that finds its host named and writes nothing, which
  `witnessAsIs` reaches.
- The reservation that finds its slot listed and writes nothing, which
  `witnessListed` reaches, `restartConverges` asserts at two turns and
  `listedAfterUnknownAtLimit` asserts in its final state.
- The designation's `Conflict` for a census entry of another host at the
  slot's tenure while the shard record names no standby, which
  `conflictBeforeDesignation` reaches.
- The rule that an unknown reservation returns no slot. A slot granted on
  a lost write, or on a held write before its delivery, refuses `Conflict`
  at its designation's census read unless the census then lists an equal
  entry, which another reservation of that shard for that host at that
  tenure can write. That slot, and one granted on a write that commits,
  equals the slot an acknowledged write or a later confirming read
  returns. `restartConverges` asserts the committed arm at a turn, which
  is not a conjunct of `safety`; no registered case checks the lost or
  held arms.
- The record-standby clause of the incumbent, which decides between
  `Taken` and the outcome the reservation reaches without it; removing it
  left the number of reachable states of every search unchanged.
- Two start conditions: a reservation names no host its reconciler holds
  lost, and an attach record starts only for a host with no live attach.

On a 16-vCPU Graviton4 host (aarch64, a share of the socket) with Quint
0.33.0, Apalache 0.62.1, Temurin 21.0.12.1 and Node.js v24.22.3 built for
aarch64, at eight workers, with the attach end and the S3 storm in the model:

| Case | Distinct states | Depth | Seconds |
|---|---|---|---|
| `standbys-safety` | 8,075,657 | 8 | 171 |
| `standbys-cross-safety` | 4,898,037 | 16 | 153 |
| `standbys-storm-safety` | 6,238,702 | 14 | 255 |

These figures are from one run of 215 of the 216 cases at eight workers on
the pruned instances, with #262's S3 storm and the attach end both in the
model and nothing else running on the host; `ended-attach-completes`,
added after that run, took 9 seconds in a run of its own. The other rooted `safety` cases
found 25,625 to 4,171,148 distinct states in 9 to 106 seconds, every reach,
run, recipe and mutant case took under 43 seconds
(`designating-mutant-release-at-current-target` 42 and
`ending-reach-witnessReleasedAfterEnd` 30 above 30), and those 215 cases took
3,222 case-seconds, above the 20 minutes and about 75 cases issue blotter issue 1805
assumed for the family.
The three cases of the fresh contender's order,
`standbys-run-freshTakesStaleEntry`, its `-reached` case and
`standbys-mutant-fresh-takes-live-standby-entry`, took 8.4, 6.6 and 6.7
seconds, one case at a time beside other checks, on a 16-vCPU Graviton4 host
under Quint 0.33.0, Apalache 0.62.1 and the aarch64 builds of Temurin
21.0.12.1 and Node.js v24.22.3.
With the planned transfer in the scheduler, the suite's figures are in the
Quint lane paragraph of [the CI guide](../docs/agents/ci.md).

These are finite checks at the stated bounds; they establish nothing about
the Rust code, instances beyond the four above, coverage of S2H and S3
outside their prefix roots, progress or absence of deadlock, the census
codec, report authentication and age, or that the production loop applies
the guards and meets the premises above.

### Replay against the reconciler

`crates/kestrike/src/failover/standbys_replay_tests.rs` replays committed
traces of [standbys.qnt](standbys.qnt) against `Reconciler::reserve`,
`release`, `designate`, `record_standby` and `end_attach`, `detachable`,
`release_attach` and `enroll_standby` over the simulated store, through the
shared driver of `failover::reconcile_tests::replay_driver`. Each production
operation runs on its own thread over a proxy store that parks every request
until the trace's step answers it. The evidence is sampled: it covers the
schedules of the committed traces alone.

[standbys_fixtures.py](standbys_fixtures.py) declares the 93 traces
committed under `crates/kestrike/src/failover/standbys_replay_fixtures`:
the recipe of every run and recipe case of [standbys_check.py](standbys_check.py)
in that case's instance but `renewedEntryKeptWhileRecording` (43), eighteen
recipes of its own (`REPLAY_RECIPES`) that reach the designation's `stale`,
`asis` and `unenrolled` results, a designation stale by the attempt alone
and one stale by the generation alone, the candidate filter's exclusion by a
process that holds a slot, unknown outcomes of the attach record's, the
enrollment's and the release's writes, a held write of the attach record
that a `deliver` step commits, an enrollment that loses its version
condition, a release of an absent census and one that keeps an entry for the
named standby alone, its tenure past and its host suspected, a reservation
refused for headroom after an outside actor took the host's slot and one
ineligible on a tenure no owner has acquired, and the end of an attach that
`record_standby` wrote, of one whose pair `enroll_standby` wrote and of one
that failed for good, and 32 seeded runs of 24 steps of the model's `step`,
16 in S2, 8 in S2H and 8 in S3. The seeded runs begin reservations and releases alone; they reach
crashes, unknown write outcomes, held writes, ends and the environment's
steps, planned transfers among them. Every event `act`, every result and
every delivery of a held census, shard or volume write the
replay test pins is reached by at least one directed trace, so a model
change that moves the seeded runs leaves that coverage standing. Each trace
records the model's digest, its instance's settings and its census cap and
attachment limit, and generation refuses a trace whose states equal another
trace's. Three seeds are passed over for that reason: `5b03`, `5b33` and
`5b34` draw the traces of `5b00`, `5b30` and `5b31`, so S2 and S3 take the
next seeds past their ranges. A model change moves every seeded run; a
regenerated seeded trace that fails the replay at one of the differences
listed below is left out with that difference named beside its seed in
[standbys_fixtures.py](standbys_fixtures.py), as `LEFT_OUT` names a run, and
the next seed takes its place. The `standbys-replay` case regenerates every trace with Quint,
up to eight runs at a time, requires it equal to the committed fixture, states and
metadata, and replays it. `renewedEntryKeptWhileRecording` is left out: its
release keeps an entry under the loop's stuck bound, which
`Census::released` does not apply.

Abstraction map. Model shard `s` is shard `s`, model host `h` is host `h`
bound to the tests' instance of `h`, and model zone 1 is census zone 1. Shard
`s`'s volume at generation `g` is `vol-` followed by `s` and `g` in two
hexadecimal digits each. After every step the replay compares, in model
units, read from the stored records:

- `st.census`: each zone's version and each shard's entry `(g, owner, E, host)`;
- `st.shards`: each shard record's `(g, owner, E, standby)` and version;
- `st.volumes`: the live hosts, the hosts with a recorded pair and the
  version of each shard's active volume record. The model keeps one volume
  record per shard across a flip, so the version is the commit count of every
  volume record of the shard, less the writes the end step merges;
- `st.held.on`: whether the store holds a parked write;
- each process's slot `(ss, slot)`: the slot `reserve` returned;
- each process's `(op, s, h, pc)`: an idle process runs no operation, and a
  running one runs the model's operation for its shard and host with the
  request `order(op)[pc]` names pending, a release that returned at its
  census read standing at the model read it skips next;
- `en.ending`: the decided end's shard and host, with its volume write
  pending.

A version is the record's commit count. The driver rebuilds each
reconciler's loss evidence from the trace's `learn`, `suspect` and failed
`attachEnds` events, drops a shard's failed attaches at that shard's
`flip`, and passes that evidence to the `lost` closure of `reserve` and
`release`. It builds a
reservation's candidate report from `st.attached`, `st.outside` and the
volume and shard records of the model's state at that reservation's volume
read: the attachment gauge counts the host's attachments outside the modeled
volumes and its completed attaches, and the report lists in the standby role
each shard whose volume enrolls the host and names another owner. The
replay reads no other variable: `st.gone`, `st.seen`, `st.failed`,
`st.suspicions`, `st.occupied`, the rest of `en`, the other fields of a
process, the history variables and `turn` stay unseen.

Action map. Every choice of the model's `step` runs.

| Model action | Production |
|---|---|
| `begin` of `reserve`, `release`, `designate`, `record`, `enroll` | the operation's first request, answered |
| `begin` whose event is `plan` | no call: the loop's candidate filter at the role limit, which lies in `zone_loop`; the process's slot is dropped |
| `request` | the pending request: a read, or a write under the store's pass arm |
| `unknown` | the pending write under `Timeout { commit: true }`, `Timeout { commit: false }` or `Hold` |
| `deliver` | `Shared::release` |
| `crash` | the operation's thread ends with no reply, and its slot is dropped |
| `bump`, `fresh`, `takeover` | `Client::bump` and `Client::take_over`; `fresh` also fences page 0 at the new generation |
| `transfer` | the driver's own write of the shard record: the standby as owner at the next attempt, no standby. No production code runs: the planned transfer's writer reads the volume record and writes the shard record in two requests, and this branch does not hold it |
| `flip` | the driver's own writes of the new volume's record and the flipped shard record; an end decided on the flipped shard is dropped before its volume write |
| `lose`, `occupy` | no request; `occupy` reaches the candidate report |
| `learn`, `suspect`, `attachEnds` | the `lost` closure; a completed attach reaches the candidate report |
| `endRead` | `end_attach`'s shard and volume reads; the driver passes `end_attach` the shard's active volume and the number of the host's latest entry, read from the stored records at this step, standing for the caller's survey |
| `endWrite` | `end_attach`'s write and shard reread, whose `named` bit must equal whether the model's shard record names the host owner or standby, the driver's write of the owner's pair drop through `Client::replace`, which the volume record's successor rule judges, `detachable`, and `release_attach`, whose requests must be two reads and one write of the volume record, after which the entry must read gone |

Atomicity. One production store request falls on each model step, with four
stated exceptions, and each request event must name the operation, shard and
host its `begin` step named. The read of coverage page 0 of the operation's shard that
follows the shard read in `record_standby` and `enroll_standby`, and the
census read in `designate`, is a code step with no model step; the driver
answers one such read there and refuses any other page read. `endRead` is
one model step for the end's shard and volume reads. `endWrite` is one model
step for four calls by two actors; the replay skips the record of an ended
entry that keeps its pair and the record of an ended entry with no pair
before the gone mark, and schedules no operation between the end's calls, so
those interleavings lie outside this link and the tenure model's reclaim
schedule checks their order. An end that lands on the owner drops its pair
and leaves the entry ended. A release whose census exists and lists no entry
for the shard returns at its census read, so the model's shard and volume
reads of that release are model steps with no code request; the driver
accepts them only in that order. A write request is matched by its key: its
condition and value are compared through the stored records once it commits
or a `deliver` step releases it, and the value of a write the store loses is
compared nowhere. A `deliver` step requires the held write to be one of the
record its event names.

Results. `Conflict` from `record_standby` stands for `notServing` and
`attachClosed`, and from `designate` for `conflict` and `unenrolled`.
`release` returns `Ok(false)` for `unlisted`, `absent` and, after its write,
`released`, and `Ok(true)` for `keptStandby`, `keptCurrent` and `keptLive`.
A reservation or a designation that wrote nothing is `listed` or `asis`.
`enroll_standby`'s `Enrollment(Unattached)` stands for `unattached`. The
committed traces end operations with every result of the model but
`record`'s `attachClosed`, which no instance of the check reaches, and
`release`'s `keptRecording`; the replay test pins that list. The
designation's read, `StandbyRecorded` and the enrolled pair are compared by
their status alone.

What the link credits to the model alone. A `transfer` step runs no
production code, so the replay shows nothing about the planned transfer's
writer. The model reads the target's attach and writes the shard record in
one step; the production writer makes two requests, and an attach end
decided before the target was designated can commit between them, after
which the record names an owner whose attach is ended. `OwnerHoldsItsAttach`
is therefore the model's invariant across a transfer and is no property of
the code through this link. `HostAttachmentsWithinLimit` rests on the
model's premise that no attach is answered after its end: the model's
`endWrite` runs from the end mark through the gone mark in one step, and
the replay runs the end's calls back to back with no operation between
them, so the traces that cross an end (those with an `endWrite` event) show
the records after the whole end and nothing about a host's attachment count
between the end mark and the gone mark. The replay compares no device
command, so a preempt, refused or accepted, is outside it; the tenure model
judges those.

The committed traces hold none of the schedules on which the code and the
model differ:

- `designate` refuses `Conflict` for a named host with no enrolled pair on a
  live attach before its replay return, where the model's designation returns
  `asis` first; the two differ only after an end raced a designation.
- A record or enrollment write after a flip lands on the displaced volume's
  record and the step then refuses at its shard read, where the model's write
  loses its version condition.
- `reserve` counts a named standby with no live attach lost, which the
  model's evidence counts only through `lostTo`.
- An end that landed on the owner drops the owner's pair, after which
  `serving` refuses the standby steps the model admits.
- The model's release keeps an entry while an attach record of its shard and
  host is outstanding (`keptRecording`), the loop's stuck bound, which
  `Census::released` does not apply; the zone loop owns that bound, and this
  link does not drive it.
- `release` keeps an entry other than the one its caller judged; the driver
  passes the entry the census holds, so the model has no such step.
- A `reserve` or `release` that reads the shard record, then a flip of that
  shard, then the volume record reads the displaced volume its shard read
  named, where the model's read returns the new volume; the driver then
  refuses the trace at that read.
- A `designate` whose census read follows a flip and a fresh acquisition of
  its shard gets `Conflict` from the page 0 fence check, where the model's
  designation goes on to its write.
- An end decided before a flip of its shard: a production end write that
  kept running would land on the displaced volume's record while its version
  still matches, where the model's end lands nowhere; the driver drops that
  end at the flip, so its write returns `Outcome::Unknown` with no store
  write.

Controls. A driver that passes a designation the other reconciler's slot
fails at that designation's census read with `the operation ended conflict`.
A release that returns `unlisted` at a census read that lists its shard
fails at that read, and one that returns it only after its shard read fails
there; an end that reports its host unnamed while the shard record names it
standby fails at its `endWrite`, as do a cleanup that makes no
`release_attach` call and a gone mark that leaves the entry ended; an end
asked for another entry number fails at its `endRead`, where no volume write
is pending; an attach
record that reads page 0 after its volume read, or another page after its
shard read, fails where the model's process stands at its next request; a
census write planted with an entry outside the instance and a volume write
planted with a live attach outside it fail at their writes.
A fixture altered in one compared field fails at its state through the
check that reads it: each field of the census of either zone, of a census
entry, of either shard record, of either shard's volume record, the held
flag and each field of a process's slot (26 fields, one control each), a
process's `pc` and `op`, the decided end, an event's result at an ending and
at a continuing step, its key at a read and at a write, its shard, a begin
over a running process, a `deliver` event's record for a held census write
and for a held volume write and its landing, an `endWrite` recorded as refused, the
recorded action, the model reads of an early release out of order, an
attach result, an event host outside the instance, the initial generation
and the outside attachment count. A stale model digest or a missing state
is refused before any state replays.

Mutants of the replay's own comparisons, one disabled at a time: of 48 that
compile, 45 fail a control; the other three are a result check the standing
check now repeats, the owner's ended entry, which the live-set comparison
repeats, and an arm of the end's result match that the request match
precedes.

What the controls measured (this section's replay at 91 traces, the
committed ones but `replay_recordHeldDelivered` and
`run_freshTakesStaleEntry`, which later commits added; the runs are
research and are not committed). Mutants of the production code, one at a
time, with the standbys and the loss replay tests as the only tests:
of 317 cargo-mutants mutants of the `Reconciler` methods and helpers both
replays call in `failover/reconcile.rs`, 62 did not compile, 191 failed a
replay test and 64 passed; of 113 of `Population::admit`, `Census::released`,
`Attach::of` and their helpers in `failover/standbys.rs` and of `decide` and
the token in `failover/loss.rs`, 8 did not compile, 69 failed and 36 passed.
Every surviving mutant of the standbys operations lies in code the committed
traces do not reach or that the driver's fixed inputs make vacuous:

- `record_standby`'s return over the host's own live entry at the same era
  and instance: the model starts a record only for a host whose attach the
  volume record, read in that step, does not show live;
- `end_attach`'s refusals before its write (`E = 0`, another active volume,
  another entry number, the owner or the named standby, an unbound entry, a
  foreign key) and its return over an ended entry: the model's `endRead`
  holds them as guards, and the driver passes the active volume and the
  host's latest entry number;
- `release_attach`'s return over an entry already gone, its listing rule
  (`omits`) and its settle timing: the driver passes two empty listings one
  time unit apart, right after `detachable`;
- `detach_ready`'s shared-instance clause and `end_ready`'s key clause:
  every entry of the replay binds its own instance and its own key;
- `standby_successor`'s unbound-instance and full-record branches: the
  driver passes no unbound instance and no listing, and no record reaches
  `MAX_EVENTS`;
- the `E > 0` clause of STANDBY-TENURE as the only refusing clause: a shard
  at `E = 0` has no activated page 0, so `serving` refuses with it;
- `reserve`'s loss of a named standby with no live attach (`standby_ended`),
  one of the differences listed above;
- the record-shape checks `provisioned`, `origin_intact`, `reservable` and
  `owner_recorded`: every volume record of the replay is provisioned with
  no lineage and holds its owner's pair;
- the boundaries of `Attach::of` and `Closed::of` at `MAX_ATTACHED`, the
  pair cap and `MAX_EVENTS`, and the zone loop's `feasible`, `admitted`,
  `shared`, `lists_standby` and `Census::releases`, which no `Reconciler`
  method of this link calls.

Mutants of the model, one at a time: each of the 46 mutants of
`standbys_check.py` regenerated the directed traces from the mutated model,
and the replay ran on them with the digest check off. For 27 the replay
failed at a named step, such as `read at 7: the operation ended full` for a
model without the cap: on a committed recipe for 25, and for 2 the committed
recipe could not be regenerated and the mutant's own recipe failed. The
other 19 change a caller guard or an environment premise the driver follows
(the loop's stuck bound, the record's start guards, `occupy`, `attachEnds`,
the `flip`, `takeover` and `transfer` guards, the evidence kept for a failed
attach), and the replay passes on them, as the action map says it must.

A wider sample: 432 traces, each of the 27 prefix roots of
`standbys_check.py` followed by 16 free steps under 16 seeds, replayed with
418 passing and 14 failing, each failure one of two differences listed
above (a reservation or release whose shard read precedes a flip and whose
volume read follows it, 11; a designation whose census read follows a flip
and a fresh acquisition, 3).

## Parked table model

[parked.qnt](parked.qnt) models the owner's table of parked GETs, as
`Parked` in `crates/kestrike/src/net/parked.rs` keeps it: which entries
are owed a visit, the wake pass with its cursor and its allowance, the fills
the table tracks with their followers, and the checks of fills whose
departure the owner does not see. Its family in [check.py](check.py) is
`parked`. It restates the wake-allowance clause of the obligation record
`mixed-get-and-put-progress-holds-every-bound`, the detach clause of
`parked-gets-follow-under-their-own-caps-and-deadlines` and the sentences of
the module's documentation that the pass limit and the owing calls enforce,
and claims nothing stronger.

The finite instance is five request slots, five fills, the table's four
tracking places and a wake allowance of three visits a pass, with one peer.
The owner sees an even fill depart; an odd fill is watched by checks. Each
step is one call on the table, in the order the owner's turn makes them, and
its event records what the call returns:

- Between passes: `park` parks a GET behind a fill, which follows the fill's
  place, takes a free place for it, or stays untracked; `owe` owes a visit
  to an entry whose request ended; `oweAll` owes every entry; `departed`
  reports a fill's departure; `elapse` lets a check period pass.
- `beginPass` starts a pass under the owner's read admission: a changed
  admission owes every entry, a due check marks the watched fills or, beside
  an untracked entry, owes every entry, and the check takes the whole
  allowance with no visit owed and otherwise half of it, the odd unit on
  every other pass.
- `check` observes the next marked fill through one of its followers, and
  `notePending` or `oweFillOf` records what the owner saw.
- `beginVisits` turns the pass to the visits owed now, `visit` returns the
  next owed entry from the cursor, wrapping, `take` removes an entry a visit
  of this pass returned, `owe` owes one of them again, and `endPass` ends
  the pass.

Abstractions:

- What a visit does to its request (its read, its end, its detach) is the
  owner's and is omitted; so are the follower caps, a second peer and every
  time but whether a check period elapsed.
- A step parks a GET in the lowest free slot, behind that slot's own fill or
  behind fill 1; the directed runs park in any slot.
- `phase`, `checked`, `passed`, `repeated`, `unowed` and `wrapped` are
  history the guards and invariants read; production keeps none of them.

| Property | Guarantee | Clause it restates |
|---|---|---|
| `WithinWake` | A pass's checks and visits together number at most the wake allowance. | "its visits and its checks of fills together number at most `wake` per turn"; the record's "the wake allowance's visits". |
| `OncePerPass` | A pass visits each entry at most once. | "each entry at most once per pass". |
| `OwedIsParked` | Only parked entries are owed a visit, and a check under way names only watched fills. | `Parked::take`'s contract, "settles any visit it was owed; its fill's last follower frees the fill's tracking place", which is how the table keeps the record's "a follower's end detaches only its own interest". |
| `DepartureOwesFollowers` | After a departure every entry that follows the departed fill is owed a visit, and every entry while some entry is untracked. | "a fill's departure owes visits to its followers"; "An entry whose fill is untracked makes ... each departure owe every entry a visit". |
| `OnlyOwedVisited` | A visit returns only an entry owed a visit. | "The wake and detach pass visits only entries owed a visit". |

[parked_check.py](parked_check.py) checks `safety`, the conjunction of the
five, with the free scheduler at `BOUND = 12` steps. Twenty-six reachability
witnesses, each checked as the inverted invariant `not(witness)` at
`BOUND = 12`, reach every action and every result an action records, among
them an untracked entry, a check that owes every entry, a check that takes
half the allowance, a visit that wraps, and a pass that spends its
allowance with visits still owed. Six directed runs are checked with
`BOUND` set to the recipe's length, each with its reachability case:
`parked-run-allowance`, `parked-run-departure`, `parked-run-check`,
`parked-run-untracked`, `parked-run-admission` and `parked-run-owedAtStart`,
a pass that stops at the one entry owed at its start, which does not meet
the spent-allowance witness. Five mutations each break
the property that names the case: a visit phase without the allowance cap
(`WithinWake`), a visit phase that ignores how many entries were owed at its
start (`OncePerPass`), a `take` that leaves the owed mark (`OwedIsParked`),
a departure of a tracked fill beside an untracked entry that owes that
fill's followers alone (`DepartureOwesFollowers`) and a visit that takes the lowest parked entry
(`OnlyOwedVisited`). These are finite checks at the stated bounds; no
refinement mapping to the implementation is claimed.

## Register model

[register.qnt](register.qnt) models reader registration on a live storage:
`Storage::register`, a protected interval's entry and exit, a leaked
guard, the drop of a registration, a forgotten registration and the close
of admission. It restates sentences of the `storage/register.rs`
documentation, the module's and its `PinError` type's, each enforced by a
refusal the module returns, as its three properties; the obligation
record `mc-pin-before-cutoff` states the second as "a refused entry
clears its new pin before any observation".

The finite instance has two registration records and one era, 1. A
record is vacant or claimed, and the replay holds a claimed record's
handle until it drops or forgets it. `register` refuses `Closed` once
admission is closed and `ReaderLimit` when both records are claimed, and
otherwise claims the lowest vacant record. `registerRacingClose` is a
registration that the close lands inside, between its claim and the
cutoff read that follows: it gives the record back and refuses `Closed`.
`interval` is one entry and its exit on a held handle: a record that
holds a leaked pin refuses `Leaked` and keeps that pin; otherwise the
entry pins the era and reads the cutoff, closed admission clears the new
pin and refuses `Closed`, and an admitted entry counts one interval
before its exit clears the pin. `leak` is an admitted entry whose guard
is forgotten, so the pin stays. `intervalRacingClose` is an entry that
the close lands inside, between its pin and its cutoff read: it clears
the pin and refuses `Closed`. `drop` returns a record, clearing a leaked
pin, and keeps the record's interval count for its next claimant.
`forget` forgets a handle, which leaves the record claimed. `close`
closes admission.

Abstractions:

- Each action is one call, taken whole, and the calls interleave in one
  total order. The close lands inside a call at two points only, the ones
  `register.rs` exposes to its tests; the GenMC cutoff kernel owns the
  memory orderings of the pin and the cutoff, and the grace loom kernel
  those of the claimed bound and the claim flag's `Release` return.
- The era stays at 1, below the terminal band, so every entry passes the
  pin's terminal check and the model's refusals are `Leaked` and
  `Closed`. Lease credits and the claimed bound are other models'
  subjects.
- `held` says whether the replay still holds a record's handle. `late`
  and `kept` are history that the invariants read: an admission sets
  `late` when the cutoff is closed before the call or lands inside it, and
  a refused entry sets `kept` when a `Closed` refusal leaves a pin or a
  `Leaked` refusal changes the pin it found. The event `ev` is history
  that the witnesses read.

| Property | Source sentence | Guarantee |
|---|---|---|
| `AdmittedOnlyWhileOpen` | "a close that landed first gives the record back and refuses"; "a close that landed first clears the new pin and refuses" | No registration and no interval is admitted once admission is closed, a close that lands inside the call included. |
| `RefusedEntryKeepsNoNewPin` | `PinError`: "On return the record holds no new pin; `Leaked` leaves the earlier pin intact" | An entry refused `Closed` leaves the record inactive, and one refused `Leaked` leaves the pin it found. |
| `LeakedPinStays` | "a leaked guard keeps its pin ... Only dropping the registration clears that pin" | A record whose guard was leaked holds its pin until the registration drops. |

[register_check.py](register_check.py) checks `safety`, the conjunction
of the three, with the free scheduler at `BOUND = 8` steps. Sixteen
reachability witnesses, each checked as the inverted invariant
`not(witness)`, reach every action and every outcome: a registration, one
of the second record and one of a record that already counted an
interval; a `ReaderLimit` and a `Closed` refusal; a registration the
close lands inside; an interval that is admitted, one refused `Closed`,
one refused `Leaked` and one refused `Leaked` after the close; a leaked
guard; an entry the close lands inside; a drop, and one that clears a
leaked pin; a forgotten handle; and the close. Three directed runs are
checked with `BOUND` set to the recipe's length, each with its
reachability case: `register-run-closeRacesAnEntry` (a close inside an
entry clears its pin, and later entries and registrations are refused),
`register-run-leakedGuardBlocks` (a leaked guard refuses the next entry
until the registration drops, and the record's next claimant enters) and
`register-run-limitAndReturn` (a third registration is refused, and a
registration the close lands inside leaves the returned record vacant).
Six mutations each break the property their case checks: a registration
after the close, a registration across a close inside it and an entry
across a close inside it (`AdmittedOnlyWhileOpen`), a refused entry that
keeps its pin and an entry that clears a leaked pin
(`RefusedEntryKeepsNoNewPin`), and a leaked guard whose pin is dropped
(`LeakedPinStays`). These are finite checks of the model at the stated
bounds. The replay below ties the model to the implementation for the
schedules its traces record.

### Replay against the registration records

`crates/kestrike/src/storage/register_replay_tests.rs` replays
committed traces of the model against a `Storage` on the heap-backed
platform with two registration records. Each step runs the storage code
for one model action: `Storage::register`; `Registration::enter` followed
by the guard's test-only `exit` or by `mem::forget` of the guard; the
registration's drop or `mem::forget`; and `Storage::close`. For the two
actions that land the close inside a call, the replay arms the hook
`register.rs` offers its tests at that point, `INTERPOSE_BEFORE_CUTOFF`
or `INTERPOSE_AFTER_PIN`, with a function that stores the cutoff, and
requires that the hook ran. After every step the replay requires the
call's return to equal the step's event, and both records' reports
(claimed, pinned era, intervals), the cutoff and the count of outstanding
registrations to equal the model's state. One call runs at a time, so the
replay covers the order of whole calls and a close at the two hooks.
[register_fixtures.py](register_fixtures.py) writes the traces with
`quint run --mbt`: five directed recipes and six traces of fourteen steps
of the model's own `step` under pinned seeds; the eleven traces together
reach `init` and every choice of `step` with each outcome, and the test
asserts that set.
Each trace names the model's sha256. Controls: a driver that enters
without arming the close, one that exits a guard the model leaks and one
that keeps a dropped registration each fail at the step they change, and
a trace with a raised interval count fails at its state. The replay is
evidence for exactly the schedules these traces record.

## Marklog model

[marklog.qnt](marklog.qnt) models the watermark's log file, `FileLog` of
`crates/kestrike/src/storage/store/watermark.rs`, under in-place raises,
whole replacements, crashes inside a log write and restarts. It restates the
file-log clauses of that module's documentation and of `FileLog`'s and
claims nothing stronger: a raise rewrites the slots of its marks in place
and takes the next free slot for the one new mark it may bring, a raise that
brings two or more new marks replaces the file whole, a crash leaves each
written slot's previous or new bytes, and a load refuses a mark after a free
slot and two slots of one key. The client's regression rule over one mark,
`Watermark::check` of that module, is outside this model; this one covers the
file that keeps the marks.

The finite instance has three coverage pages, versions 1 to 3 of each, one
client process at a time, one other writer and six slots. Each action is one
step:

- `read` reads a batch of pages in one call. The log records the raised
  marks before the call returns: in place when at most one of them is new,
  and by a whole replacement otherwise.
- `crash` is a batch whose log write a crash interrupts. An in-place raise
  leaves the slots of any subset of its marks written and the others as they
  were. A whole replacement leaves the previous file or the new one. The
  next process loads the file.
- `write` is the other writer advancing a page, and `restart` ends the
  process between calls.

Abstractions:

- A crash image holds each slot whole, previous or new, and a replaced file
  whole, previous or new. That is the module documentation's assumption of a
  device that writes a sector atomically and of an atomic rename; the model
  takes it as given and checks nothing about it.
- A page's value is its version, so the mark's value rule, the value
  comparison of `Watermark::check`, is outside the model, as are the slot's
  digest and the file's header.
- The file has 64 slots and the model six, with three keys, so a raise with
  no free slot is not reached. A failing log write, which the client answers
  with `StoreError::Log` and its withdrawal, is outside the model.
- `acked`, `before`, `after` and `ev` are history the invariants and
  witnesses read.

| Property | Guarantee |
|---|---|
| `MarksFillPrefix` | No mark follows a free slot. |
| `OneSlotPerKey` | No two slots hold one key. |
| `LoadsBeforeOrAfter` | After a crash the file loads each mark as it was before the interrupted write or as that write made it. |
| `ReturnedMarksAreDurable` | The file holds every mark at or above the watermark of the last call that returned, and the client's watermark is the file's. |

[marklog_check.py](marklog_check.py) checks `safety`, the conjunction of the
four, and each invariant alone, with the free scheduler at `BOUND = 6`
steps. Fourteen reachability witnesses, each checked as the inverted
invariant `not(witness)`, reach every step choice and every outcome of the
unmutated model: a first mark, an in-place raise that leaves a mark above version 1 and one
that leaves two, a whole replacement, a batch that raises nothing, slots out of key
order, a crash of an in-place raise that lands nothing, part and all of it,
one that loses a new mark, a crash of a whole replacement that leaves the
previous file and one that leaves the new one, the other writer's write, and
a restart that loads a mark. Three directed runs are checked with `BOUND`
set to the recipe's length, each with its reachability case. Five mutations
each break one invariant: `two-new-marks-in-place`
and `new-mark-skips-a-slot` break `MarksFillPrefix`;
`held-key-takes-a-new-slot` breaks `OneSlotPerKey`;
`whole-replacement-tears` breaks `LoadsBeforeOrAfter`;
`restart-forgets-the-file` breaks `ReturnedMarksAreDurable`. Two more cases
check a mutation through the conjunctions the positive cases use:
`two-new-marks-in-place` through `safety`, and `whole-replacement-tears`
through the `runSafety` of a directed run. These are finite checks at the
stated bound; no refinement mapping to the implementation is claimed.

### Replay of the marklog model

`python3 quint/marklog_fixtures.py --quint QUINT --output DIR` writes twelve
traces with `quint run --mbt`, with `BOUND` set to each trace's length: six
directed recipes and six traces of fourteen steps of the model's own `step`
under pinned seeds. Each state after the first names the action taken and
its arguments. They are committed under
`crates/kestrike/src/storage/marklog_replay_fixtures`, each naming the
model's sha256 and its number of steps; the replay refuses a trace of
another model text, or one whose state count differs from its named steps
plus one, before any state replays.
`storage::store_crash_tests::marklog_replay` replays
them against `Client::read_all` over the simulated store and a `FileLog` on
a file of the replay's own directory, each replay on one thread. A `read` is one
`read_all` of the batch's pages. A `crash` makes the same call and then
writes the file a crash in its log write leaves, composed from the file's
bytes before and after the call: the landed pages' slots new and the others
previous for an in-place raise, and the previous or the new file for a whole
replacement. The next client opens on that file. After every action the
replay compares the file's slots with the model's, requires the client's
watermark to equal the one the file loads, and requires each page's version
in the store to equal the model's `store`; after a `read` and a `crash` it
tells an in-place raise from a whole replacement by the file's inode. The crash images are the ones the
model's abstraction allows; the replay writes no torn slot. Together the
traces reach `init` and every choice of `step` with each way the log
records. The replay covers these traces; it is evidence for them and for no
other schedule.
