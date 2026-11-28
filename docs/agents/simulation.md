# Simulation testing and findings

Apply this guide when you write or change a simulation profile or scripted
history, run or monitor a deterministic simulation campaign, triage one of its
results, report a finding from one, or add or change a kestrike
determinism-lint exception. The simulator exists to find safety and
correctness defects in the cache. Every finding you report carries a class,
the agreed property it was judged against, and replayable evidence.

## Determinism lint

The kestrike Clippy gate checks direct uses of the clocks, entropy sources,
threads, sockets and hash collections listed in `crates/kestrike/clippy.toml`.
Clippy matches each use against the listed paths. A use of another path to the
same source passes the gate: `SystemTime::elapsed` on `UNIX_EPOCH` reads the
wall clock and `TcpStream::connect_timeout` opens a socket.
The non-test build checks production code outside `bind`, `native`, `soak` and
`storage::device::spdk`. The `bind` exception also covers helpers called from
simulated code. The library test build and worker check listed methods in the
harness trees: `sim`, `oracle`, `net::world_tests` and the worker's cases. Those
two builds allow hash collections in the harness trees, except in
`sim::lint_tests::plants`. `net::takeover_history_tests::fleet` checks both
lists in both builds.
`sim::fork` and `sim::fork_tests` allow the method lint for the whole module;
other harness exceptions cover one site each. Other test-only code in those two
builds allows both lints, including simulation doubles such as
`storage::device::sim`. Each integration-test root checks both lists unless it
opts out. Give each exception a reason naming the seam or explaining why the use
lies outside simulation. For a listed use in simulated code with no confirmed
seam, [classify the finding](#classify-every-result) and obtain owner approval
before recording the open point in an exception. Fresh-process replay checks
determinism on the paths the worker runs with recovery helpers inline, and
with a store lane inline when a path starts one under the worker's flag.
Thread timing needs separate evidence.

## Classify every result

| Class | It is this when | Priority |
|---|---|---|
| Safety bug | The cache serves or publishes bytes other than the object's, loses an object it published or an upload whose publication it acknowledged, admits one wire identity twice, releases custody a device still holds, or crosses a session or owner isolation boundary. | Critical |
| Correctness bug | The cache breaks any other agreed property: an assertion in cache code fails, a frame states something false, a state machine reaches a state its invariant excludes, or a model invariant fails. | Critical |
| Minor bug | An agreed property breaks and the effect stays in a report counter, a diagnostic, a status more conservative than the contract states, a document or comment that misstates a contract the code keeps, or the test harness. | Normal; fix it |
| Availability or performance observation | Every agreed property holds, and the cache refuses, delays or spends more than it could: a typed refusal or a timeout inside the request's deadline, latency, memory, or repeated work. | Owner decides |
| Design question | The cache does what its agreed contract says, and you propose a different contract. | Owner decides |
| Harness result | The run ended `unsuccessful` or `inconclusive`, or the scenario's own goal or generator stopped it. | Fix when it costs coverage |

Classify a violation by the effect its replay shows. When the effects with
and without debug assertions fall in different rows, the earlier row of the
table sets the class. A campaign replay runs with debug assertions, so list
the effect without them under `Unknown` until a build without them shows it.
Report each class under its own name, so its priority is visible.

A profile that arms chaos points, such as `contended`, makes production
functions return rare outcomes at the seeded places
`crates/kestrike/src/sim/chaos.rs` catalogs. A finding from such a run
lists each point its bundle fired and states the production cause of each
fired outcome, the `cause` its catalog row names: a production path that
holds the same lock at that place, or other writers that win every
exchange the budget pays for. A fired `exchange-lost` counts each of
those exchanges as lost, so a one-thread run's lease report can show
failed credit exchanges.
Read a point's reached and fired counts from the finding's saved bundle
with `sim::chaos::census`, a `cfg(test)` function a library test build
reaches: load the bundle with `sim::trace::load` and pass the loaded
bundle's tape. Build that test from the source that built the bundle's
pinned worker, with the build-time checkout for a dirty build, since the
catalog and the choice layout are that source's; report counts read from
another checkout as unverified. A bundle that fails to load, or a census
that returns nothing, is unavailable evidence and not zero fires. Report
counts you did not read as unavailable. The counts
cover the tape the bundle holds: a bundle cut by a record cap or by a
panic ends before its run did, and a panic's bundle holds none of the
decisions of the turn that panicked. In that turn, a point may have fired
at each armed reach inside an action: a `Gate::try_lock` that read the word
open, a `Pool::capture_membership_lock` call, and, once per `update_after`
call, the last attempt, which its budget paid and its `next` admitted. These
are possible fires, not fires the tape records. State the causes before you
classify the finding. When production cannot return a fired
outcome at its place, the finding is a
harness result. A `contended` run whose one upload a
fired point refused issues no read. It finishes once the world drains and
ends unsuccessful under `the upload published`, which is the expected
ending of that run and is not a finding. An inconclusive `contended` run
is triaged as any other.

## An agreed property

A finding is a bug only when it breaks an agreed property. A property is
agreed when it existed before your finding in one of these places:

1. An obligation record in `verification/obligations.json`.
2. A rule text in `crates/kestrike/src/net/world_tests/narrate/rules.rs`
   that an existing profile or history already judges.
3. An invariant in the tracker spec for the feature or for
   [the campaign](https://github.com/ahrav/kestrike/issues/31).
4. An invariant a module's documentation states and its code asserts.
5. An invariant of a model under `tla/` or `quint/`.
6. The stated invariant or the disclosed behavior of a merged pull request.

Cite the place and the identifier. Search all six before you classify. A
merged pull request or a module's documentation that states the behavior you
observed makes that behavior the contract unless another of the six places
forbids it, and your finding is then an observation or a design question.

A bound, deadline or expectation that you introduce is a hypothesis. A run
that exceeds it is an observation until the owner adopts the bound as a
property. When two sources disagree, such as a comment and a merged pull
request's notes, or a merged pull request's disclosure and an obligation
record, report the disagreement, classify the finding against the source
that forbids the behavior, and ask the owner which one holds. Correct the
other text after the owner answers; that correction is a minor bug fix.

## Write a profile or scripted history

- Start from one agreed property. Name it, with its citation, in the
  history's documentation.
- Judge through existing rule texts and cataloged bounds, such as a request's
  one deadline. A new rule text enters with the citation of the property it
  states and with its catalog line, in the same change.
- Keep premises apart from judgments. A premise that fails to form ends the
  run `Unsuccessful` under the premise's name. Read each premise from state
  that exists with and without the defect.
- Judge cumulative evidence when the property is about history: a count that
  stays unchanged, a collected outcome, a delivered frame.
- Add a sibling history that runs the same steps without the fault and
  passes. For a new check, add a control that fails through the named rule
  and list it in its family's control test, such as
  `every_incident_control_fails_through_its_named_check` for an incident.
  For a check that judges swept runs, declare the control beside its
  profile in the supervisor's `controls.rs`, sweep the profile, and confirm
  that `campaign sweep-status` lists the rule under `rules.caught`. A
  sweep takes the registered histories in turn, one batch in 16, and
  judges a control history by the failure its `Expect` declares. Sweep
  the control history by name and confirm that its rule is listed there
  too. Violation rules use their full catalog text; unsuccessful witnesses
  appear as printed by the summary, at most 41 bytes. An unsuccessful
  control history earns credit when its run completes unsuccessful and
  its printed witness equals a declaration shorter than 41 bytes.
- Run the history under a range of roots, 500 for a scripted history, and
  record the tally in the pull request. Pin two or three roots in a seeded
  test. A history whose ending changes with the root declares the premise
  that separates the endings, so each root ends as registered or
  `Unsuccessful` under that premise.
- Register the history and run the [commands](#commands).

## Run a campaign and triage

Follow `crates/campaign-supervisor/README.md`. Explore with `campaign sweep`,
then run `campaign confirm` on its root: each listed suspect of a profile
that is no control becomes a supervised job in `confirm/state`, which is
the `$STATE` of the commands below. A sweep's `uncredited` counts are
`unsuccessful` and `inconclusive` runs; read them by the table, and admit
one of its `uncredited_runs` as a supervised job, with the campaign and
counts `sweep-status` prints, when you need its bundle. A sweep also runs
its profiles' controls and takes the scripted histories its worker lists
in turn. A
history that expects a failure is a control there: a run of it that
passes is a suspect of class `control passed` under the history's name.
When its totals carry `alarm`, a control's plant
took effect and no check failed, or such a history passed. A passing run
of a pin, the history a row of the known-findings table names, shows that
the real defect did not reproduce under the suspect's seed: the row's fix merged
without retiring the pin, or the pin's ending changes with the root and
its premise is undeclared. Read it as one of those two causes, and not as
a check that let a planted defect through. Replay the suspect's seed as
[Replay a control run](#replay-a-control-run) directs. When the row's fix has merged and
the pin passes under root 3, the seed of the checks every history runs,
flip the pin to a pass and delete the row, and update any seeded test of
its family that pins it under other roots. When the fix has merged and
the pin still ends in its violation under root 3, keep the pin as
declared and examine that run as an incomplete fix or a second defect
under the row's issue. While the fix has not merged, the pin's ending
changes with the root: declare the premise that separates the endings, as
[Write a profile or scripted history](#write-a-profile-or-scripted-history)
directs. Before you
call a sweep's histories clean, compare `histories.ran` with
`histories.profiles` in `sweep-status`: a history with no run was not
reached, and its regression is unchecked in that root. When the missed control is `asserting`
and the archive's worker was built without debug assertions, rebuild the
archive and sweep a new root. Report any other missed control that is not
a passing pin as a candidate minor bug in the
harness, with the suspect's line from `suspects.jsonl`. Report
no pass of that sweep as evidence until the missed control is explained.
A control
run counted under `controls.no_effect` finished before its plant took
effect; it is no evidence about the checks either way. No alarm fires for
a control whose plant never takes effect, nor, in an archive whose worker
reports no plant effect, for a `cluster-` control the checks stop
catching, whose runs are counted under `controls.other`. Before you
report a sweep's `cluster-` passes as evidence, compare each `cluster-`
control's `caught` with its `runs` under `profiles` in `sweep-status`.
Report a `cluster-` control with runs and none caught as a candidate
minor bug in the harness, and give its run count. A `cluster-swarm-`
control's run can end with no effect with every check working, as on a
member of one owner, so a few such runs alone show no defect. A
`cluster-order-` control is caught only on a root whose run forms its
premise, about one run in a hundred at depth 3 (roots 1 to 300 at
generator version 4 and the default counts), so give its run count and
report none caught as a candidate minor bug in the harness only from
about 1,000 finished runs at the default counts, a working value. Count
the no-effect endings the supervisor lists as uncredited, leave out runs
stopped at a `turns`, `same_time` or `no_progress` limit, and check the
sweep's count overrides first. A no-effect run of such a control shows neither
that the checks work nor that they missed a plant; a positive
`controls.missed` keeps its response at any run count.
When the totals carry `no_pass`, a listed profile had 64 runs or more and
none was counted under `pass` or `caught`. The entry shows that the
profile earned nothing; find the cause before you class it. Read the
profile's `uncredited` rules and its suspects. When the cache's behavior
keeps the scenario from completing, classify that behavior by
[the class table](#classify-every-result): a bug only when it breaks an
agreed property. When the profile, its generator, its goal or the root's
counts are the cause, it is a harness result.
When `unreached` lists an event, the checkpoint records zero covered passes
of that profile that reached it. Those passes give evidence only for events they reached.
Classify the entry as a harness result. Report the root's `counts` alongside
the entry. The [required-event table](../../crates/campaign-supervisor/src/campaign/seeds/required.rs)
was measured with `counts: {}`. An override can equal the default. The
gate applies to roots swept with either setting.

A positive `covered` with an empty `reached` map means every covered pass
reported unavailable coverage. A drawn pass creates the counter entries even
when all counts are zero. For mixed coverage, the checkpoint records the
covered-pass total and per-event totals. A `replay differs` suspect can also
carry the replay's summary. To inspect one execution, admit the same campaign,
profile and run number with the pinned archive and count overrides. Run
`campaign dispatch` against that state and archive. If the attempt passes,
read its `run.stdout` coverage line. It describes that execution.
If a cache change prevented the event, classify that behavior separately under [Classify every result](#classify-every-result).
Fix the generator or shape, or correct the required-event table
and cite the rate measured at the table's stated counts in the same change.
Keep the root's entry as the finding.
Sweep a new root only for a new build or a corrected table.

Before reporting passes for a recovery profile, check its `windows` totals
in `sweep-status`. An empty `windows` map means coverage is unknown.
A `windows_missing` entry is a harness result to explain: eligible runs
counted zero cuts under that stored name. Inspect or reproduce a contributing
run. Check its Skipped and Checked events. For an activation, use the cut
index into the recorded profile's ordered `Recovery::table` in
`crates/kestrike/src/sim/recovery.rs` from the source that built the
archive. For a dirty build, use the build-time checkout with its local changes.
If only the revision is available, report the comparison as unverified.
Compare the observed class and landing with that cut. In `drained_evidence`,
`yes` means the expected disposal disposition and zero pending commands;
`no` leaves the individual results unknown. Read the evidence code alongside
it. During reproduction, record the disposal return and the pending-command
count immediately afterward. Classify
an underlying failure when replay shows which agreed property broke.

The default `restarts=1` can leave later cuts at zero. Sweep a new root with
`--set restarts=20` to allow every built-in cut. With reported totals, a
profile absent from `windows_missing` has a positive count per stored planned
name. Limit the report to those names. In a root whose counts set `restarts`
to 20 or more, `no_window` lists the `windows_missing` entries of each profile
with 64 runs or more, and the sweep exits 1 while it holds one. Classify each
such entry as a `windows_missing` entry is classified, and report the root's
`counts` with it. `no_window` also lists a name whose total sums distinct
counted rows under a shortened name or `other`: `null` under the profile's
`windows_folded`, or, for a profile with no such record, `other` or a name of
251 escaped bytes or more. A name can be both at zero and folded. A folded
positive total shows neither a missed cut nor full coverage: read the full
names and counts from contributing runs with the pinned worker before you
report a gap, and state that one run gives that run's rows only.
See [Recovery crash windows](../../crates/campaign-supervisor/README.md#recovery-crash-windows)
for the evidence a cut requires.

Each `rules.scopes.<scope>.uncaught` list contains texts with zero catches
credited to that scope. Check the
scopes each run reaches: `boundary`, `world` and `cluster` for live runs,
and `history` and, when the history records rows, `oracle` for histories.
A passing result records its observed outcome; only a caught control
shows that a check can reject its planted defect. Shared texts can be
credited to an earlier scope even when they appear in a later scope's
`uncaught` list. Once every history has a credited run, the status's
`unlisted_uncaught` names the uncaught texts outside the committed list
of texts a sweep may leave uncaught, as
[Rules in a sweep](../../crates/campaign-supervisor/README.md#rules-in-a-sweep)
describes. A text in the key is a catalog text outside that list that no
caught control run or failing history run of the root ended under. A
catch credits the text, not the check that raised it, and each text
counts under its first catalog scope. The key carries no verdict: the
sweep's exit code reads `alarm`, `no_pass`, `unreached` and `no_window`.
Its texts are coverage gaps of the root, which need no triage or
classification; a finding that names the same text is triaged as the
table below directs.
Read each result as follows.

| Result | Meaning | Action |
|---|---|---|
| `findings` holds an unresolved `verified` row of a `violation`, a crash, `oom` or `watchdog` class | Unclassified triage result | Replay it on its pinned build, or rerun it when it retains no bundle, then reduce it, narrate it and classify it. A finding whose profile and key a row of `known` lists goes to that row's issue, as the paragraph on `known` below directs |
| `findings` holds a row with `held_code` `capture-missing` | An attempt whose non-pass outcome is not yet captured; the row blocks release | Rerun `campaign dispatch` and list the findings again. Read a row that turns `verified` by its class, as this section directs. Report a row that stays held as a capture hold, with its attempt id |
| `findings` holds a row with another `held_code` | The supervisor could not read or verify a record; the row blocks release | Report the row's `held` text and `held_code`, and repair the state that text names before you triage |
| `unsuccessful` | A premise or a coverage minimum was not reached | Harness result; record the profile and the rule |
| `inconclusive` | A turn, time or progress limit ended the run before its verdict, or the run counted no verdict for another cause, such as an oracle verdict, the recorder's cap or a pass that earned no credit | Harness result. For a limit, narrate the last progress and what the world waited for. For another cause, report the cause its summary names and the coverage left unjudged, as far as the replay shows them |
| `pass` | The checks completed with their witnesses | None |

```sh
campaign findings --state "$STATE"
campaign triage --state "$STATE" --from-run <finding> --step replay
sim_worker --narrate BUNDLE --output FILE --events
```

The table lists the results with a fixed reading. Examine any other result
once, such as a verified `engine` or `truncated` finding, a limit class, or a
profile that starts ending `inconclusive`, then classify it and state what
you could not determine.

A suspect under `known` in `sweep-status` is the finding of its row's
issue and needs no new triage, within the limits
[Known findings in a sweep](../../crates/campaign-supervisor/README.md#known-findings-in-a-sweep)
lists. Examine as new a row whose `suspects` per run of its profiles,
read from `runs` under `profiles`, rises well above its rate in earlier
roots of the same profiles and counts, and a suspect of
the row's rule whose profile and key no row lists under `keys`. Such a
suspect counts under `new_suspects`. Triage each suspect that
`new_suspects` counts as this section directs. `confirm` admits each
listed known suspect as it admits any other, and a job that fails records
its finding under `campaign findings`. A verified finding whose profile
and key a row lists under `keys` goes to that row's issue: report it
there. The match routes the finding by its signature alone. When the
replay shows another trigger or mechanism, classify the finding as new.

A simulation pass is evidence about the simulated device. Before you report
a pass as evidence about how the production driver or an EBS volume
behaves, read the differences table in
`crates/kestrike/src/storage/device/fidelity_tests.rs`. Each row states
one behavior in which the simulated device and the production driver
differ, and a pass on the simulated device, a campaign's or a disk
contract run's, shows nothing about a row's production side. A row's
treatment describes the disk contract, a shared test over any `Disk`
implementation: `Within` names how the contract runs over the
difference, and `Outside` names the condition that keeps it out of every
contract run. When a defect escaped simulation because the two devices
differ, add a row and a pin for each side in the fix's pull request. The
guard `every_listed_difference_is_pinned` checks each pin against the
obligation catalog, the test inventory and the hardware manifest, and names
what is missing. The owner approves, in that pull request, each new
or changed row whose treatment is `Outside`.

### Replay a control run

A control or a failing history can also end in a `violation` other than
its declared one, or in a `panic`. Such a suspect raises no alarm, and
`confirm` refuses it, since campaign admission takes no control. Keep
its `suspects.jsonl` line. Copy `manifests/PROFILE.manifest` from the
sweep root to a directory outside it, change only its
`root` to the suspect's exact `seed`, and use the same pinned archive and
counts. Capture it with
`campaign sim run --archive DIR --manifest PATH --artifacts DIR`, then
replay the returned run directory with
`campaign sim replay --from-run DIR`. Keep the original evidence if
capture is incomplete or replay differs, and classify the observed effect
by [the class table](#classify-every-result).

### Score the planted defects

`verification/plants/` holds one directory a planted defect: `plant.patch`,
a diff against the head that restores a fixed defect, and `plant.json`, which
names the fix, its regression test (`proof`), the profiles the run sweeps for
it, which the rule below selects (`expected`), and the cause of a miss
(`miss_cause`). No crate compiles a plant. The runner refuses a plant whose
files differ from the commit it scores. Commit the plants, then run the store
from a checkout of the head, with that head's `campaign` on `PATH` and a
`Cargo.lock` built there:

```sh
bash scripts/tool.sh plant-runner
```

The work directory, by default under `$TMPDIR`, must lie outside the
checkout, on a mount `campaign` accepts (xfs, or ext4 with a journal), under
ancestors only you or root can write. Where `$TMPDIR` is unset or shared, as
`/tmp` is, the bare command is rejected: pass `--work DIR` or set `TMPDIR` to
such a directory. The runner runs on Linux alone and reads its umask from
`/proc/thread-self/status`. It starts `python3`, the first on `PATH`, for
each proof rerun and for each check of a rerun's verdict by the head's copy
of `scripts/reproduce-test.py`. The runner sweeps each plant's archive
in a scratch worktree and writes `verification/plants/score.json`, which reads
"k of n plants at commit C". A run with `--plant` writes a score over the
selected plants and names them in its `settings`. A swept miss is one
sample: a rerun at the same commit builds another archive and sweeps other
seeds, and the work directory the run prints holds the archives and roots
that replay it. A plant with no expected profile is missed with no sweep, on
its `miss_cause` alone. `bash scripts/tool.sh plant-runner --help` gives each
result, the score's fields and the exit codes. Before you push a change to the
tool or to the library modules under `crates/kestrike-tools/src/plants/`, run
those modules' unit tests with the unit tests of
`crates/kestrike-tools/src/process.rs`, then the tool's cases:

```sh
CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_DEV_DEBUG=line-tables-only cargo test -p kestrike-tools --lib -- plants:: process::
CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_DEV_DEBUG=line-tables-only cargo test -p kestrike-tools --test tools -- plant_runner::
```

Before you add a plant, show that its `proof` exits 0 on the head and 1 on the
plant, with a Cargo target directory of each tree's own:

```sh
python3 scripts/reproduce-test.py --package kestrike --target lib --test PROOF --attempts 1
```

`PROOF` is the plant's `proof`. On the plant it must exit 1 through the
regression's own assertion: name that assertion from the planted attempt's
output, since a fixture panic or an earlier guard also exits 1. The runner
reruns that command at the scored head, on the head and on each plant that
applies, before it builds the plant's archive. Both reruns use the head's
copy of the helper, kept outside the tree a patch changes, and that copy's
own check reads the verdict. A
rerun counts when it exits 0 or 1, prints last the verdict of that exit,
`not reproduced` or `reproduced`, and leaves the run's `Cargo.lock` in the
tree as it was. Any other ending on either the head or the plant leaves the
plant with no verdict. So does an apply or a reset that fails in the proof's
worktree, or a rerun that changes the `Cargo.lock`, for that plant and each
later one; the lockfile is checked after a rerun whose output is UTF-8 text,
so one that prints no UTF-8 text leaves its own plant with no verdict and
the next proof still reruns. When both reruns count, the plant is live only when its proof
exits 0 on the head and 1 on the plant; the runner then builds its archive.
Any other pair of exits makes the plant `not live`: `n` does not count it,
the score names it under `not_live`, and the run exits 3. The runner removes
no plant. Name each `not live` plant in the pull request that changes the
store, and in that pull request repair its patch or remove its directory
from the store.

Start a plant's scratch traces from the cluster profiles for a plant under
`net/`, and from `upload`, `faulted` and the cluster profiles for one under
`storage/`. List in `expected` each traced profile one of whose runs executes
a planted line, as a scratch trace at that line shows, and no other, with one
exception. Leave out a profile with no passing run on the unpatched head at
the default counts, such as `cluster-long`, when other expected profiles
remain, and give the reason in the evidence sentence. The runner does not
sweep the head: a `no_pass` in the planted sweep blocks a miss, and a plant
that lets such a profile pass could still miss. Give a plant that sweeps miss
a `miss_cause` with one sentence of evidence and one of these causes:

- `environment`: the planted file lies in code that no profile, control or
  history a sweep schedules runs. Name in the evidence any worker case outside
  the sweep, such as an ignored long-run case, that runs it.
- `workload`: profiles run the planted file and no run reaches the planted
  line or state.
- `ordering`: runs reach the planted code and the defect needs an order of
  events no run took.
- `property`: runs execute the defect and no rule judges its effect.

The runner checks that the cause is one of these words and that the evidence
is there; the evidence carries its meaning. When a confirmed suspect's seed
also fails on the unpatched head, the plant's record lists it under
`head_failures`, beside a catch too, and a plant without a catch ends with no
verdict. A suspect whose profile, run and seed also have a `replay differs`
line in the root gives no catch, since its seed does not determine its run;
it leaves the plant with no verdict unless another suspect's seed catches.
The sweep lists the first eight suspects of a key and counts the rest. When
a profile's status counts more suspects than the list holds under a `replay
differs` key or under `other`, gives no count by key, or gives one that does
not sum to its suspects or counts fewer under a key than the list holds, a
differing replay of any of its runs may be unlisted, so no suspect of that
profile gives a catch. Classify each such suspect by
[the class table](#classify-every-result) before you report it.

## Triage a fuzz finding

`campaign fuzz` stores the first failure of each key as `failures/ID/`
under its root and lists it in `findings.jsonl`, as
[the supervisor README](../../crates/campaign-supervisor/README.md#findings)
describes. A finding is a candidate until this section classifies it. Its
build is an aarch64 archive, so rerun it on an aarch64 host, with the
archive whose build digest `record.json` names. The campaign adds no rule:
a failure with a claim is a violation of a rule text that the scenario's
profile judges, a harness defect or a panic. A finding without a claim,
under a `libfuzzer:` or `worker:` key of
[the key table](../../crates/campaign-supervisor/README.md#findings), is
a process end that the driver did not judge; read its `stderr.tail`.
The key `worker: input without a claim` is the exception: the worker
kept the input as a failure and its claim file is missing, and
`stderr.tail` can hold the worker's line for it.

1. Read `record.json`: the key, the run, the build digest, the revision,
   `dirty` and `untracked`, and the rerun's result. A revision from a
   dirty checkout does not name its source; report it as such. A record
   without `revision`, `dirty` and `untracked` is a failure that another
   build's run left: read the three from the `build` file of the archive
   with the recorded digest.
2. Rerun the input with the recorded rerun arguments, `rerun_arguments`
   in `record.json`, into a new empty artifact directory, since the
   worker keeps the first failure of a directory. The block runs the
   worker only when `$ARCHIVE` is the recorded build, the SHA-256 of its
   `build` file, and `campaign sim capabilities` verifies the archive's
   files into `$CHECK`, a private directory as the archive's is. Each
   check holds at its own time; keep the archive unchanged through the
   triage. `env -i` starts the worker with no inherited loader
   variable. For a finding of the `campaign` target:

   ```sh
   BUILD=$(sed -n 's/.*"build":"\([0-9a-f]*\)".*/\1/p' \
     "$ROOT/failures/$ID/record.json")
   [ "$(sha256sum < "$ARCHIVE/build" | cut -d' ' -f1)" = "$BUILD" ] &&
     campaign sim capabilities --archive "$ARCHIVE" \
       --artifacts "$CHECK" > /dev/null &&
     mkdir "$OUT" &&
     env -i LD_LIBRARY_PATH="$ARCHIVE/lib" "$ARCHIVE/worker" \
       --fuzz campaign --artifacts "$OUT" -- "$ROOT/failures/$ID/input"
   ```

   A block that stopped before the worker gives no result: `$OUT` is
   absent or older than the block.

   The rerun repeats the key when `$OUT/first-failure.claim` and
   `failures/$ID/claim` hold one text through the bytes of its JSON form
   that the key keeps: 256, or 249 for a claim keyed with the `claim: `
   prefix. For a finding with no `claim`, it repeats the
   key when the worker ran the input, ended nonzero and wrote no claim;
   a worker whose output shows that it ended before it ran the input
   gives no result. The stored `rerun` also compares the two runs'
   bundles, so report a stored `diverged` beside a rerun that repeats
   the key. A `worker:` key whose directory holds
   no `input` has nothing to rerun; read its `stderr.tail`. A panic keeps
   no bundle, and a failure whose feed ended before
   its run did keeps a bundle that a replay refuses as exhausted, so the
   rerun is the first check of every finding.
3. When `bundle` exists and its run reached its terminal, replay and
   narrate it with the archived worker's own forms. A fuzzed run's
   manifest pins a placeholder build in place of the archive's, so
   `campaign sim replay` refuses its bundle:

   ```sh
   env -i LD_LIBRARY_PATH="$ARCHIVE/lib" "$ARCHIVE/worker" \
     --replay "$ROOT/failures/$ID/bundle" --output "$OUT/replay"
   env -i LD_LIBRARY_PATH="$ARCHIVE/lib" "$ARCHIVE/worker" \
     --narrate "$ROOT/failures/$ID/bundle" --output "$OUT/narrative" --failure
   ```

4. Classify the result by [the class table](#classify-every-result), with
   the agreed property it breaks, before you call it a bug. Its fix is a
   separate change.

Read the rerun result of a `libfuzzer: timeout` or `libfuzzer: oom` key as
weak evidence. The rerun passes the input alone, so libFuzzer's defaults
apply in place of the run's `-timeout=60` and `-rss_limit_mb`, which
`worker` in `record.json` lists (6144 under the default `--memory`): 1,200
seconds for an input, past the 600 seconds at which the supervisor ends
a rerun, and 2,048 MiB of memory. A timeout finding whose input ends
within 600 seconds reads `unreproduced`, and `reproduced` on an oom
finding shows only that the input passes 2,048 MiB. Rerun it by hand
with those two flags before you judge it. One memory cause can
appear under two keys, `libfuzzer: oom` and `worker: out of memory`:
libFuzzer's limit lies a quarter below the cgroup's, and the kernel
kills the cgroup when its charge reaches the limit before libFuzzer's
check; read
the two together. A `diverged` or `unreproduced` finding keeps its first
failure: report both results.

## Prove a bug

A safety or correctness bug is proven when all of these hold. Until then,
report it as a candidate.

1. The failing bundle replays to an equal digest on its pinned build.
2. The mechanism is traced to named code, and the agreed property is cited.
3. A regression test or scripted history fails on the unfixed code and passes
   on the fix; [the lane evidence rules](ci.md#lane-evidence-and-flaky-tests)
   name the receipt the pull request cites. A planted mutation that restores
   the defect fails the test or history again.
4. Two read-only reviewers on different models judge it independently and
   agree. A split verdict keeps it a candidate at its class; report both
   verdicts. A verdict that depends on the owner's intent makes it a design
   question. When that intent is which of two disagreeing sources holds, the
   finding keeps the class that disagreement gives it until the owner
   answers.
5. When a model under `tla/` or `quint/` covers the property, its model case
   passes.
6. The effect is stated for builds with and without debug assertions, and the
   data at risk is named.

Reproduced bugs become permanent tests, and unresolved violations of a
release guarantee are listed as release blockers, as the campaign spec
requires.

## Act on each class

- **Safety, correctness and minor bugs.** Preview a ticket with the class,
  the property, the trigger, the effect and the evidence, and open it after
  approval of the exact preview, as [the tracker guide](issue-tracker.md)
  directs. Land the fix and its regression in one pull request that names the
  invariant.
  When the ticket opens ahead of its fix and a scripted history can reach
  the finding's defect with no plant, register the finding: add that
  history, declaring the violation it ends in, list it in its family's control test, record its 500-root
  tally, and add its row to `KNOWN` in
  `crates/campaign-supervisor/src/campaign/known.rs`, as
  [Known findings in a sweep](../../crates/campaign-supervisor/README.md#known-findings-in-a-sweep)
  describes. List in the row each passing profile whose runs can reach the
  defect's trigger. When the pin alone reaches it, leave the row's profile
  list empty, so the row explains no suspect and a violation of its rule in
  a sibling history counts under `new_suspects` unless another row lists
  that history. A finding that no scripted history reaches gets no row of its
  own: its violations count under a row whose obligation and rule they
  fail in one of that row's profiles, and otherwise under `new_suspects`.
  Panics and audit failures get no row and count under `new_suspects`.
  A second open finding that fails an existing row's obligation and rule
  in one of that row's profiles shares that row, and `defects` refuses a
  second row for it. When the first finding's fix deletes the row and the
  second finding's issue is still open, register the second finding with
  its own pin and row. The fix flips the history to a pass and deletes the row in the
  same pull request; the protocol contract case fails while a row's pin
  declares no violation. Delete a row when its issue closes for any reason.
- **Observations and design questions.** Report the finding under its class
  and state the current contract. A pull request may pin the current behavior
  with tests and correct documentation.
- **Improvements.** A pull request that improves availability or performance
  proceeds when it preserves every agreed property. Title and describe it as
  an improvement. State each model or obligation-catalog edit it makes, and
  report its cost: memory per unit, work added to a hot path, and
  model-checking time. A large cost goes to the owner for a decision before
  the change continues.
- **Harness results.** Fix the profile, generator or goal when the result
  costs coverage, and report the lost coverage until then.

## Report format

```text
Class:     safety bug | correctness bug (prefix "candidate" until proven) |
           minor bug | availability observation | performance observation |
           design question | harness result
Property:  the citation, or "none found" with the six places searched
Trigger:   the steps and faults that reach it
Effect:    with debug assertions; without them; the data at risk
Evidence:  build, roots, bundle digest, replay result, tests and controls
Unknown:   what you could not determine
```

## Examples

| Finding | Class | Why |
|---|---|---|
| After a device write submit unwinds, the owner still counts a fragment it dropped. Later turns fail the held-count assertion, and a build without assertions acknowledges the dropped fragment. | Correctness bug | The module documents the invariant and asserts it, and the ACK states something false. |
| A GET refused on a bound wire slot, whose one ERROR the link lost, ends `TimedOut` at its deadline. | Availability observation | The request ends inside its one deadline, and a merged change states that this path keeps no answer to replay. |
| A request on an ended upload's wire slot is refused `RequestPressure` until the upload's write drains. | Availability observation | The client receives a typed refusal inside its deadline. Freeing the slot earlier is an improvement. |
| A run idles to its no-progress limit because the workload never collects a decided upload. | Harness result | The service finished its work, and the generator offered no further action. |

## Commands

After a change under `crates/kestrike/src/net/world_tests/`, run these
with the checks `AGENTS.md` lists for Rust changes:

```sh
cargo test -p kestrike --lib -- net::world_tests
cargo test -p kestrike --test sim_worker -- --exact histories::each_history_replays_in_a_fresh_process
python3 scripts/test-select-tests.py
python3 scripts/verify-receipts.py admit
```

After a change to `KNOWN` or to a history a row pins, also run the
protocol contract case. It compiles only under its own cfg, so build it in
a target directory of its own, and check that the output holds the line
`test contract::the_supervisor_parses_every_worker_form ... ok`:

```sh
env -u CARGO_ENCODED_RUSTFLAGS RUSTFLAGS="--cfg protocol_contract" CARGO_TARGET_DIR=target/contract cargo test -p kestrike --test sim_worker -- --exact contract::the_supervisor_parses_every_worker_form
```

### Measure the typed-outcome register

`verification/reach/<family>.json` holds one row for each variant of each
listed enum of `crates/kestrike/src/<family>/`: an enum of a non-test
file there whose name ends in `Error`, `Refusal`, `Refused`, `Rejection`,
`Reason` or `Failure`. The families are `storage`, `net` and `failover`.
A row's state is `reached` with the named run's
count at the sites the tool can count (a lower bound; see the limits
below), `unreached` with how far the run came (`measured`) and a reason row,
`unplaced` when the mapping rules cannot place it, or `unmeasured` for a
variant declared after the named run. The header names the run and keeps
the live count of `unplaced` rows. The tool under `verification/reach/tool/`
writes the register; `oracle::reach_guard_tests` in the workspace suite
fails when register and source disagree.

Each reason row that an `unreached` row names carries `kind` and
`missing`. `kind` is `step` (a workload step no profile takes), `fault` (a
fault no profile draws, a corrupted in-memory word or a panic under a
gate included), `configuration` (a setting or count no profile uses),
`environment` (a part of production the simulation replaces or leaves
out) or `unconstructible` (no code of the workspace's non-test build
constructs the outcome, whatever its inputs, with memory holding only what
the code wrote). An outcome whose only construction path is a function no
non-test code calls is `unconstructible`. For an eager argument or a
function value, constructing means the variant left its function through
the `?` that ends the chain, as for `reached` below. `missing` is one
sentence, written from the construction sites and the conditions that
guard them. For the first four kinds it names the step, fault, setting or
part concretely enough that a reader could add it; for `unconstructible`
it names the condition that rules the outcome out. Rows that lack the same
thing share a reason row. A reason row serves rows of one `measured`
value, because `measure` keeps a row's reason only while the row's
`measured` equals the reason's, so a key whose rows span `measured`
values keeps one reason row per value, `<measured>:<key>`, with equal
`kind` and `missing`. `measure` writes each new group's reason row with
`id`, `measured`, `functions` for a function group, and an empty
`sentence`; `kind` and `missing` are written by hand. `sentence` is the
tool's own field: the reader requires it, `measure` keeps what it finds
there, and no check reads its text, so the text a reader wants is
`missing` and `sentence` stays empty. On every reason row
an `unreached` row cites, the guard requires a listed `kind` and a
nonempty `missing`, a `measured` value equal to that of each citing row,
and equal `kind` and `missing` across the rows of one key. On every reason
row, cited or not, it requires one row per id, the tool's key order with
`id`, `measured` and `sentence` present, text values, a `measured` value of
`file-not-run`, `function-not-entered` or `not-constructed`, an `id` that
opens with that value and a colon, no empty `functions`, `kind` or
`missing`, which `render` leaves out, and the layout `render` writes. It
fails a reason row that no `unreached` row names: `sync` and `measure` keep
such a row, so delete it when the guard reports it.

When the guard reports a variant without a row or a row without a variant,
run the command it prints for the family that failed and commit the
register. The command parses the source alone and takes seconds:

```sh
cargo run --locked --release --manifest-path verification/reach/tool/Cargo.toml -- sync storage
```

`sync` adds an `unmeasured` row for each new variant, removes the row of
each deleted one, and leaves every other row as it stands; it also keeps
every reason row, so delete a reason row that no row names before you
commit. `sync --status`
prints the number of `unmeasured` rows and the rows. This line reads the
date of the oldest `unmeasured` row of any family on `main`:

```sh
for family in storage net failover; do git blame --first-parent --line-porcelain origin/main -- "verification/reach/$family.json" | awk '/^committer-time / { t = $2 } /^\t.*"state":"unmeasured"/ { print t }'; done | sort -n | head -1 | xargs -r -I{} date -u -d @{} +%F
```

The register's maintainer, whom the owner names, measures again when a row
stays `unmeasured` for more than seven days. The pull-request tier checks
neither the number nor the age of `unmeasured` rows. To measure, run this
on an aarch64 worker from a clean checkout, inside the delegated cgroup of
the supervisor's [host requirements](../../crates/campaign-supervisor/README.md#host-requirements),
with `rustup component add llvm-tools` done once:

```sh
verification/reach/measure.sh storage /data/dst/reach-1 "$TMPDIR/reach-1"
```

The second argument is a new directory that meets the supervisor's state
requirements and receives the coverage-instrumented archive and three sweep
roots that freeze the manifests: default counts, `restarts=20` for the
profiles the worker's listing marks `class=recovery`, and `turns`,
`records` and `bytes` raised for `cluster-long`. The third is a new
scratch directory, which the script creates with mode 0700, for the
build, the profiles and the export. The named run is roots 1 to 50 of each live and
recovery profile the worker lists. The script starts the batches of five
roots itself, at most `BATCH_WORKERS` at once (28 by default) and never
more than the count `nproc` prints. No supervisor check counts these
workers, so size the delegated cgroup's limits for them as well. When
SIGHUP, SIGINT or SIGTERM ends the script, it sends SIGTERM to every batch.
The script refuses a host that is not aarch64 and a checkout with an
uncommitted change or an untracked file. Before the merge it stops with
status 2 at a root whose run was refused, panicked, did not load or ended
in an infrastructure terminal, that ran another profile, or whose `code`,
`counts` and `terminal` disagree. A complete run that does not count adds
its coverage and no pass. The script names each root that ended in a
violation on standard error, after the tallies and again as its last
lines, and still writes the register: state that root in the pull request
and [classify it](#classify-every-result) before you call it a bug.
The script prints each profile's passing
roots, then, through `compare`, each row whose state or count the new run
changes, and writes the register. `compare`
writes nothing and exits 0. The script writes the register of the family
it names. To write another family's register from the same run, so that
every header names one run, run the tool's `compare` and then its
`measure` on the export and the run record the script left in the scratch
directory. Run them only after the script exited 0, from the checkout it
ran in, while `crates/kestrike/src` equals the commit `run.json` names:
the tool maps the export's lines and columns onto the source it parses and
checks neither. Run `compare` first when the family's register exists,
since `measure` overwrites the register `compare` reads; `compare` checks
each row's state and count, so an empty report shows that both are equal
for every row. It shows neither the source's identity nor equal sites,
`measured` values or reasons:

```sh
commit=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["commit"])' "$TMPDIR/reach-1/run.json")
git diff --quiet "$commit" -- crates/kestrike/src &&
  cargo run --locked --release --manifest-path verification/reach/tool/Cargo.toml -- compare net --export "$TMPDIR/reach-1/export.json" &&
  cargo run --locked --release --manifest-path verification/reach/tool/Cargo.toml -- measure net --export "$TMPDIR/reach-1/export.json" --run "$TMPDIR/reach-1/run.json"
```

Before committing, give each reason row `measure` added for a new group
its `kind` and `missing` from the construction sites' guards, or point the
rows that name that reason row at an existing reason row of the same
`measured` value that fits them, add the new row's `functions` pairs to
the kept row's `functions` (each pair once), and delete the new row.
`measure` and `sync` keep every earlier reason row as written: after
either, delete each reason row that no row names, and recheck the
`missing` of each kept reason row whose rows, construction sites or run
changed, a figure tied to the named run included, against the new run's
profiles and the rows' construction sites: an equal `measured` value or an
empty `compare` output does not show that the cause still holds. Run the
guard, then commit the register with the run's figures. To compare another
export with the committed register, from a checkout whose
`crates/kestrike/src` equals the export's commit:

```sh
cargo run --locked --release --manifest-path verification/reach/tool/Cargo.toml -- compare storage --export "$TMPDIR/reach-1/export.json"
```

Run directly, `measure` and `compare` map the export they are given onto
the checked-out source and attach the run record they are given; they
check neither against the other. `measure.sh` builds the export from the
clean checkout at `HEAD` and checks the archive's commit and flags.

The register's limits: "reached" means the named run constructed the
variant at a construction site of the crate's non-test build, and branches
that end in one outcome count as one. A `reached` row's count sums the
sites the tool can count, so it is a lower bound when another of the row's
sites is a function value or a closure that no counted `?` ends, as for
`net::namespace::Refusal::Pressure`, whose tail `map_err` in
`Namespace::admissible` is not counted. A variant that only a test-gated
part of the simulation constructs, such as `net::datagram::DatagramError::Failed`,
which the in-memory link of `crates/kestrike/src/net/link.rs` returns,
reads as not reached. The tool reads enum declarations as written: an enum
that a macro declares has no rows, as `failover::report::Refusal`, which
the `labels!` macro of `crates/kestrike/src/failover/report.rs` declares
with 11 variants, has none. For the eager argument of `ok_or`
(`x.ok_or(E::V)?`) and the function value of `map_err`
(`.map_err(E::V)?`), "reached" means the variant left its function
through the `?` that ends the chain. An argument of another eager method,
of a call nested in such an argument, or of any other call a `?` ends
takes no `?` count, and reads `unplaced` when the run evaluated it. These
rules read method names alone and assume the standard library's
`ok_or`, `map_err` and `ok_or_else`. A construction inside an operand of
`==` or `!=` or of the first two arguments of an `assert_eq!`-style macro
is no reach, inside a call argument of the operand too.
A path that names an enum and a variant counts for the one crate enum of
that name that holds the variant, whatever module or crate its qualifier
names; the qualifier chooses only among several crate enums of one name.
A construction of another crate's enum that shares a listed enum's name
and variant therefore counts for the listed variant.
The instrumented worker is the test build of `sim_worker`, and every root
of the named run adds its counts, the roots that did not pass included.
The rows list construction sites of the non-test build only, so an
`unreached` row leaves open a construction at a test-only site such as
the simulated device or store.
The record is evidence about that run of the simulated environment only. An `unreached` row is a record of reach, not a
finding. A drop of a `reached` row fails no sweep; the required-event table
stays the sweep's gate. The 50 roots of each profile, the seven days,
the guard's bound of 5 seconds in the pull-request tier and `measure.sh`'s
bound of 3600 seconds for each batch of five roots (`BATCH_SECONDS`, a
positive integer) are working values for the owner's adoption.

The tool's own checks run in no lane. After a change under
`verification/reach/tool/` or to `verification/reach/measure.sh`, run:

```sh
cargo test --locked --manifest-path verification/reach/tool/Cargo.toml
cargo clippy --locked --manifest-path verification/reach/tool/Cargo.toml --all-targets -- -D warnings
```
