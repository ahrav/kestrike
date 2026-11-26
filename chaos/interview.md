# Owner interview: the simulated Kestrike

This file holds every question of the interview of the skill `chaos-enrollment`
(its `references/owner-interview.md`, plugin `chaos-testing` release 0.4.0), numbered
as the skill numbers them. The ledger's `source.ref` values of the first ledger's four rows
(`ks-get-not-older-than-collected`, `ks-bound-record-passes-its-checks`, `ks-upload-no-fault`
and `ks-cluster-link-faults`) point at these lines; the two rows of M0-5 (#304) cite #298
and the merged sources of the escape, and the two rows of M2-4 (#315) cite #180, blotter pull request 1703,
#297's unit M2-4 and #315 themselves.

An answer stands only with the place where the owner agreed to it, named on its
"Agreed at" line, or with a ruling made for the owner, named on its "Ruled" line.
Three kinds of place count:

- **the request**: the owner's request of 2026-11-23, as #297 states it: to enroll
  Kestrike for chaos testing and run the full loop, then seven coverage items
  with five statements true across all. Where #297, the specification cut from that
  request, settles how the request applies, the line names its section;
- **place N**: one of the six places of `docs/agents/simulation.md`, "An agreed
  property", by its number;
- **#31**: the campaign specification.

Two kinds of ruling count, and "Ruled for the owner" states each ruling with who made
it and when:

- **the delegate's ruling**: made on the owner's behalf by the owner's delegate;
- **the lead's ruling**: made by the workstream's lead, on the owner's delegation of
  25 November 2026 (the owner's words to its delegate, at about 06:14 UTC: "the rest
  is your call").

A question that only the owner can answer and that no ruling settles is open, with no
default, and stands under "Open for the owner": OQ-3, OQ-4 and OQ-7 of #297, the
second part of A1, the fleets of A5's probe, the registry rule's row of A6, the hours
and the spend of A10, B1, the proposed stops of B2, B3 and B5 of the approval policy,
and the confirmation of each invariant. OQ-1, OQ-2, OQ-5, OQ-6, OQ-8 and OQ-12 of
#297 and the first part of A1 are ruled, and six stop notes of `chaos/loop/stops/`
are answered. Every number of a row of
`chaos/ledger.json` and of `chaos/project.yaml` stands under "Numbers" with its source
and its adoption.

## A. The copy, the fences and what must hold

- **A1. The copy.** Kestrike as the archived simulation worker runs it under
  `campaign`: the archive that `campaign sim archive` writes on this aarch64 worker,
  named by its build digest, and swept into a new root for each run.
  Agreed at: the request, as #297 settles it in "Words" (copy, build) and KTD1.
  Who else uses the worker and `/data/tsw/campaigns`, and when: ruled in part. For the
  time of the workstream that built this contract, each of its workers and that
  worker's `/data/tsw/campaigns` were used by that workstream alone.
  Ruled: on the owner's behalf by the owner's delegate, 24 November 2026. This file
  holds the ruling from 25 November 2026, and the last record of this part says how
  it entered.
  Still open: who else uses the host on which the owner runs the loop afterwards, and
  when. A fresh root per run keeps runs apart; it says nothing of other users. The
  open part blocks a scenario run on that host until the owner answers, and the drafts
  go on without it.
  The records that follow were written before the ruling entered this file. Where one
  says that this part had no answer, this file held none on the day of that record.
  Added by #304 (M0-5 of #297) after the interview, as a record of what ran and no
  answer: every sweep of the rehearsal started while this part had no answer. Those
  sweeps are the entry-gate sweep of `chaos/survey.md`, the fixture sweeps under
  `chaos/tests/runs/`, the four runs of M0-3 (`upload-live`, `upload-corrupted`,
  `cluster-live`, `cluster-stale-read`), this unit's seven runs of record
  (`record-escape-live`, `record-escape-judged-open`, `record-loop-1`, `record-upload-1`,
  `record-upload-2`, `record-cluster-1`, `record-cluster-2`), and the earlier makes of
  those runs, all of which the git history keeps.
  #297 orders each of them in its milestones M0-1 to M0-5 and states no gate on this
  part, and `chaos/loop/log.md` names the workstream lead's decisions for this unit's
  runs. The sentence "Until then no scenario run starts" of `chaos/approval-policy.md`
  is this contract's proposal; it stands unchanged, and the owner adopts or amends it.
  Added by #315 (M2-4 of #297), as the same kind of record and no answer: this unit's
  runs `reach-live` and `reach-control`, which the git history keeps, its fixture sweep
  `chaos/tests/runs/fixture-reach-live`, the earlier makes of those three, of which the
  git history keeps the committed ones, and the sweeps of four defective worlds in this
  unit's probe step, whose records stay outside the repository, also started while this
  part had no answer. #297 orders this unit's witness and control in M2-4 and states no
  gate on this part, and pull request blotter pull request 2129 names the workstream lead's decisions for
  the steps that made them.
  What the campaign found, which is the campaign's statement and no answer of the
  owner: the record that the campaign's driver gives each session, outside the
  repository, says that nothing but the campaign's own sessions runs on the worker
  and that `/data/tsw/campaigns` belongs to the worker's user at mode 0700. A reader
  of the repository cannot check that record, and it names no hours. The workstream's
  lead states (decision L222, 2026-11-24 20:03 UTC) that each sweep of this campaign ran
  on a worker the campaign's driver built for one chain of tickets, that a chain runs
  one session at a time, that review-loop sessions of the campaign's pull requests
  follow on the same worker one at a time, that `/data/tsw/campaigns` on a worker is
  written by those sessions' sweeps alone, each into a new root, and that the workers
  are removed at the campaign's teardown. That statement is about the campaign's own
  workers, and it is no answer to this part and writes no default.
  Added by #311 (M6-2 of #297), as a record of what ran and no answer: this unit's
  runs `ordering-live-r7` and `ordering-premise-unmet-r7`, which the git history keeps, its four
  fixture sweeps `chaos/tests/runs/fixture-ordering-*`, the earlier makes of those six,
  of which the git history keeps the committed ones, and the sweeps of its probe step,
  whose records stay outside the repository, also started while this part had no
  answer. #311 orders this unit's witness run, its control run and the recorded
  evidence of its judges' tests and states no gate on this part, and pull request
  blotter pull request 2130 names the workstream lead's decisions for the steps that made them.
  Added on 2026-11-25 with the runs of record made again
  (`chaos/loop/stops/escape-restoration-text.md`), as a record of what ran: the eleven
  runs under `chaos/runs/` whose ids end in `-1125b` replace the seven runs of record,
  the two reach runs and the two ordering runs named above, which left the tree with them.
  Their last makes stand at commit `5755aacea` (the seven of build `7899890b4d5f`), and the
  rehearsal's own seven of build `3b9e5e9f1598` at commit `caded992b`. Their sweeps started on 2026-11-25 from 06:51Z to
  07:19Z, after the session's fence check and its listing of the worker's processes and of
  `/data/tsw/campaigns`, which showed no other session (`chaos/loop/log.md`, amendment of
  2026-11-25). One sweep of an earlier series started at 06:45Z the same day; its records
  stay outside the repository. The fixture sweep `chaos/tests/runs/fixture-reach-live` was
  recorded again at 07:35Z on the same footing. That is thirteen sweeps. The footing of these sweeps is the workstream lead's
  statement in the step's instruction (decision L269) that this part was answered on the
  owner's behalf on 24 November 2026 for the campaign's own workers. This file recorded no
  such answer when they started: its one entry of 24 November was the lead's statement
  L222 above, which it calls no answer, and the delegation the stop notes name is of
  25 November. So these
  thirteen sweeps, like the rehearsal's, started before this file held an answer to this
  part, and the gate of `docs/agents/chaos.md`, "Run a scenario", was not met by this
  file.
  Added on 2026-11-25 with the rulings, after every sweep named above: the delegate's
  ruling at the head of this part entered this file. It is dated 24 November 2026, and
  the workstream's lead relayed it to the session that wrote it here on 25 November
  2026 (decision L275); the repository holds no other record of it. It answers this
  part for the workers of the workstream that built this contract, in that
  workstream's time: on those workers no one else ran. The sweeps recorded above ran
  on such workers, by the lead's statement L222 for the campaign's sweeps and by the
  amendment of 2026-11-25 in `chaos/loop/log.md` for the thirteen sweeps of that day.
  The records above stand as written: each of those sweeps started before this file
  held the ruling. The second part, the host on which the owner runs the loop
  afterwards, stays under "Open for the owner". The sentence of
  `chaos/approval-policy.md` that the first record quotes reads since then: "On any
  other host no scenario run starts until the owner has said who else uses it, and
  when".
- **A2. Differences from production.** Every result is evidence about the
  simulation. `project.yaml` lists the differences: the 11 rows of the device
  differences table in `crates/kestrike/src/storage/device/fidelity_tests.rs`, the
  determinism lint's exceptions of `docs/agents/simulation.md`, "Determinism lint",
  with the production-code exceptions whose effect is unverified, the copy's build
  form, its one thread per world, its small worlds and its in-process links, the
  scope sentence of #297's R8 for every reach count, and the turn controller's
  clock rule, which bounds the orders an ordering figure covers.
  Agreed at: the request, as #297 settles it in KTD1 and R8; place 6 for the
  differences table, which merged with its guard `every_listed_difference_is_pinned`.
- **A3. Reference load.** No production figure applies. A sweep runs seeds in virtual
  time at the rate the worker's cores allow, so a scenario's load is a profile set at
  default counts, swept by 28 workers in batches of 30 s for 120 s, or for 600 s in
  `ks-ordering-figure`, and its multiple is 1.
  Agreed at: the request, as #297 settles it in KTD8 and in "The first ledger". The
  sizing is the workstream lead's (see "Numbers").
- **A4. What the copy touches that someone else owns.** Nothing during the traced
  sweep: the entry gate of `chaos/survey.md` swept `upload`, with the controls and the
  three histories its 60 s reached, in a network namespace with no interface up, and
  the sweep exited 0 with no network call but local socket pairs. No traced sweep
  covered `cluster-broad`; its links are in-process datagram links of one world.
  The worker's credentials reach further: an AWS role and a GitHub token. Their
  fences are under A5.
  Agreed at: the request, as #297 settles it in KTD4.
- **A5. Fences.** The campaign runs as the worker's Unix user `tsw`, with the AWS
  role `bsw-ct1-worker-host` and the GitHub login of the owner. It must be unable to
  reach the live fleets' object storage and compute resources, to create a paid
  resource and to push a workflow file. Each of the four has a fence row with a probe
  and a refused receipt under `chaos/receipts/fences/`. The two fleet probes reach no
  fleet resource: the object-storage probe reads the role's own account and the
  compute probe dry-runs a stop of this worker's own instance, so a grant of a named
  fleet bucket or a stop permission scoped to fleet instances stays unprobed. The
  workstream's lead ruled that these account-level probes stand (request
  `2078-fence-targets`, decision L037); only the owner can name the fleets for a probe
  from a session the owner runs. Four reaches have no boundary
  and stand in `trusted_base`, each with the owner's act that closes it in
  `chaos/survey.md`, "Reach": that question is OQ-3, open.
  Agreed at: the request, as #297 settles it in KTD4.
- **A6. Invariants.** Items 1 and 2 are two rule texts, each judged today by a merged
  profile and caught by a merged control; item 3 is a threshold over planted ordering
  controls, and item 4 a threshold row on reach:
  1. "a GET returned a version older than one collected or removed before it",
     array `CLUSTER` of `crates/kestrike/src/net/world_tests/narrate/rules.rs`,
     raised by the cluster checker and caught under the control `cluster-stale-read`
     (`crates/campaign-supervisor/src/campaign/calibration/controls.rs`, `STALE_READ`,
     obligation code 2, History). Row `ks-get-not-older-than-collected`.
  2. "a bound slot's record fails its header or chunk checks", array `OBSERVER` of the
     same file, raised by the stopped-boundary observer and caught under the control
     `corrupted` (`CORRUPTED_UPLOAD`, obligation code 1, Bytes). Row
     `ks-bound-record-passes-its-checks`. The observer reads the record from the
     simulated device itself, takes its expected session, version and allocation from
     the storage's own slot facts and index bindings, and checks it with the cache's
     own record verifier; `trusted_base` lists the tables and the verifier as shared
     with the code under test. A candidate whose expected content comes from outside
     the cache, the registry rule "a bound slot's bytes match no registered content",
     still reads the bound records through the storage's bindings and the cache's
     framing, layout and verifier; it is listed for the owner as a row after the
     freeze (decision L036, stated in pull request blotter pull request 2104, "Asking the lead for help").
  Each of these two rows' `property.text` quotes its rule text in full, and its
  `control.expect` is that rule text alone, which a broken receipt's detail holds.
  Agreed at: place 2, a rule text that an existing profile judges; #31, Acceptance:
  "Cross-window stale-read, early-reuse, late-completion and accumulating-leak
  controls fail their named checks" for the first, and "Credited activation requires
  applicable healthy/faulty controls" for the first two. A rule text judged this way
  stands as `property.agreed: owner`: OQ-6, ruled by the workstream's lead on 25 November
  2026 ("Ruled for the owner"). `trusted_base` of `chaos/project.yaml` prints that
  agreement as ruled.
  Added by #304 (M0-5 of #297) after the interview: a third rule text, "a fill
  admitted after the cache closed", arrays `ORACLE` and `HISTORY_SHARED` of the same
  file, raised by the own check of the scripted history `k9-placement-across-close`
  (obligation code 2, History) and caught under the control history
  `k9-placement-judged-open`. Row `ks-no-fill-admitted-after-close`. That control plants
  no cache defect: it skips the owner's close, so the check fails an open owner's legal
  grant.
  Agreed at: place 2, the rule text that the history `k5-closed-admits-nothing` judges;
  place 4, the module documentation of `storage::writable`. #298 records the incident.
  The text of `storage::writable` holds: OQ-12, ruled by the workstream's lead on
  25 November 2026 ("Ruled for the owner").
  3. Each planted ordering control of depth 1 to 3 beside `cluster-broad`
     (`cluster-order-1`, `cluster-order-2` and `cluster-order-3`, the `ORDERING` table
     of `crates/campaign-supervisor/src/campaign/calibration/controls.rs`, #307) is
     caught at least once in at least 1,000 runs of one sweep and missed in none,
     under "a GET returned bytes no upload of its key wrote", array `CLUSTER` of the
     same file as rule 1. Row `ks-ordering-controls-caught`, kind `threshold`, judged
     by `chaos/judges/ordering/figure.py`, whose receipt reports each control's
     caught runs over its runs with a one-sided 95% lower bound, and the figure's
     scope. The numbers 1,000 and 95% are ruled as they read (OQ-2; see "Numbers").
     Agreed at: the request, as #297 settles it in R18, R19 and KTD15; place 2 for
     the rule text.
  4. M2-4 (#315) adds the threshold row `ks-required-events-reached`: each cluster
     profile with at least 64 covered passes has, for each event the required-event
     table requires of it, a covered pass that reached the event, and no profile of
     the scenario is listed under `no_pass`. Its control,
     `requires-invalidated-of-cluster-pressure`, is a campaign binary built outside
     the repository from a table that requires an event `cluster-pressure` never
     reaches. The label names that pair, and the control's broken detail reads the
     sweep's unreached entry for it; the row's `control.expect` is its property text,
     which every broken detail holds.
     Agreed at: #180, R3 and KTD2 to KTD4, adopted at the merge of blotter pull request 1703, for the
     required-event clause; the request, as #297 settles it in unit M2-4 with #315,
     Scope, for the `no_pass` clause and the control.
- **A7. Expected degradation.** The class table of `docs/agents/simulation.md`,
  "Classify every result": a typed refusal or a timeout inside a request's deadline
  is an availability observation and breaks no agreed property, and an
  `unsuccessful` or `inconclusive` run is a harness result. One ending is ruled apart:
  a run that ends `unsuccessful` under "a healed owner kept the resources of finished
  work" breaks an agreed property (OQ-5, ruled by the workstream's lead on 25 November
  2026; "Ruled for the owner"). The ledger excludes that property until a row with a
  witness and the control `cluster-swarm-leak` is added.
  Agreed at: the classification guide merged with place 6; #31, C4 (honest results).
- **A8. Scenarios.**
  1. `ks-upload-no-fault`: the merged profile `upload` with the controls its control
     batches reach in the run's 120 s, in the control table's order, fault `none`.
  2. `ks-cluster-link-faults`: the merged profile `cluster-broad` with its controls,
     whose links lose, duplicate, reorder and delay datagrams, with at least one
     covered pass that reaches `hits`, one that reaches `invalidated` and one that
     reaches `faults`.
  3. `ks-ordering-figure`: the three ordering controls of A6, item 3, named in
     `--profiles`, each running `cluster-broad`'s scenario with its link faults, at
     default counts, 28 workers, `--batch 30` and `--for 600`. Its validity judge is
     `chaos/judges/ordering/validity.py`, since a control passes no run: each control
     needs runs, a replay, no suspect and delivered link faults. Its control run is
     the same sweep on a scratch archive whose depth-1 plant selects no read, so
     `cluster-order-1` is caught in none of its runs. The run's label begins with the
     name of that control. On a control run the figure judge reports zero caught as
     broken only for the control the label names, and a miss of any swept control as
     broken, as on a live run. The row's miss clause has no control run: a
     miss raises the alarm, which makes its run invalid, so the judges' test of a
     built miss stands for it.
     Agreed at: the request, as #297 settles it in M6-2 and KTD15.
  4. `ks-reach-required-events` (M2-4, #315): one sweep of `cluster-swarm`,
     `cluster-broad` and `cluster-pressure` at default counts, with the link faults of
     the second and at least one covered pass of each that reaches `faults`. Its
     validity holds a sound sweep whatever its reach verdict.
  The first two controls are seeded defects the merged supervisor runs beside their
  profile: `cluster-stale-read` for the first invariant, `corrupted` for the second.
  The fourth scenario's control runs its three profiles again under the scratch
  campaign binary of A6, item 4, and run.json records its defect as a label. A hold
  needs `runs_required` valid held runs. The number is 2, and two held runs miss a
  break that shows in half of all runs one time in four (OQ-2, ruled by the
  workstream's lead on 25 November 2026; "Ruled for the owner").
  Agreed at: the request, as #297 settles it in "The first ledger"
  (`source.kind: survey`) for the first two scenarios and in unit M2-4 with #315,
  Scope, for the fourth and its control; #31, Acceptance, for the merged controls.
  Added by #304 after the interview: `ks-escape-2075`, the scripted history
  `k9-placement-across-close` by name, fault `none`, with at least 500 caught runs, at
  least 500 passing runs of its twin `k9-placement-across-storage-close`, and the control
  history `k9-placement-judged-open`.
  Agreed at: the request, as #297 settles it in "The first ledger" (M0-4 adds the
  scenario `ks-escape-<id>`). #298 records the incident (`source.kind: incident`), and
  #303 registered its history.
- **A9. Telemetry.** A judge reads the records `campaign` writes for a sweep root:
  the status document of `campaign sweep-status`, `suspects.jsonl` and the output of
  `campaign findings`, copied into a run's evidence directory with the harness's own
  `history.jsonl` and `run.json`. It ignores the wall-clock keys `elapsed_s`,
  `runs_per_s`, `operations_per_s` and `busy_us`.
  Agreed at: the request, as #297 settles it in "Words" (evidence) and KTD7.
- **A10. Budgets.** A run deadline of 3,600 s for one campaign process, and a
  rehearsal budget of 12 runs or 3 hours for the whole campaign, the six hours of #297
  shortened for the rehearsal of record. The ruling on OQ-2 rules both as they read
  (see "Numbers").
  Ruled: by the workstream's lead on 25 November 2026, under OQ-2 ("Ruled for the
  owner").
  During which hours a run may start, and what the campaign may spend, model usage
  included: no answer on record, open for the owner.
- **A11. Existing evidence.** The supervisor's controls and the histories a sweep
  runs, read from `crates/campaign-supervisor/README.md`, and the sweeps that #297's
  "Property Catalog" records at its baseline. The confirmation of #241 and the
  revisit of the reach numbers of #180 are OQ-8, ruled ("Ruled for the owner"): the
  confirmation stays with #238, the specification of #241, and the reach numbers
  stand.
  Agreed at: #31, Acceptance, for the controls; place 6 for the merged README.
- **A12. Trusted.** The harness, the judges, `campaign` and the worker's own checks,
  the interpreter, the three controls and the three ordering controls as stand-ins,
  the scratch archive behind the ordering figure's control run, and the identity of
  A13.
  `trusted_base` in `project.yaml` lists each, with the four unfenced reaches and
  the numbers ruled under "Numbers".
  Agreed at: the request, as #297 settles it in KTD4 and R26.
  Added by #304 after the interview: the own check of the history
  `k9-placement-across-close` and the control history `k9-placement-judged-open` are
  trusted too, and `trusted_base` covers both by its items on each invariant's own check
  and control. Commit `cb9ad9321`, by the workstream lead's decision L067, amended two of
  its items: the 64-pass item names `ks-upload-no-fault` and `ks-cluster-link-faults` and
  states the 500 caught runs and 500 passes of `ks-escape-2075`, and the control item
  excepts `k9-placement-judged-open` as a control that plants no cache defect.
  `chaos/loop/stops/trusted-base.md` asked for the confirmation of that edit of the
  frozen `chaos/project.yaml`, and the workstream's lead confirmed it on 25 November
  2026 ("Ruled for the owner").
  Added by the review of pull request blotter pull request 2230, before the freeze: one item states that
  the commit the reach control's binary was built from stands in the dated note of
  `chaos/loop/log.md` alone, which no receipt binds and no freeze check reads. The
  review's panel of three judges chose it over a harness or judge change, which makes
  every receipt stale and binds a stated commit, not the binary's source.
- **A13. Who runs it.** During the rehearsal, one identity, the worker's user with
  its AWS role, runs the harness, writes the receipts and sets each status.
  Agreed at: the request, as #297 settles it in KTD4 and OQ-1.
  After the rehearsal, a session of a workstream runs the harness on a worker that
  workstream alone uses, after the session's fence check. After the freeze, a status
  of `held` or `fixed` is set as a record: a pull request's first lines and its entry
  in the loop's log give the contract check's exit with the freeze id, the build and
  the run ids, run in an uncommitted copy of the tree that carries the status, and
  its merge into `main` puts that record on `main` and sets the status. No commit
  carries `held` or `fixed` in `chaos/ledger.json`, on a branch or on `main`. The
  freeze commit is the commit of `main` that merges pull request blotter pull request 2230, on the
  condition the ruling states.
  Ruled: on the owner's behalf by the owner's delegate, 25 November 2026, as OQ-1
  ("Ruled for the owner").

## B. Approval policy

The answers are in `chaos/approval-policy.md`, each with a "Set at" line. Three parts
have no place the owner set them and no ruling. They stand as this contract's
proposals, open for the owner: what ships without asking beyond the draft branch, the
archive and the committed statuses (B1), the stops of B2 marked as this contract's
proposal, and B3, the form of a stop. B4 is the review, B6 the findings and B7 the
stop that waits while the loop goes on. B5, telemetry the loop may add, has no answer
and is open with them: a signal the harness records for a judge lies under
`frozen_paths`, and the owner has said nothing of other signals.
Two parts of that file state rulings. "Who runs it" states the ruling on OQ-1. "Ships
without asking" lets a sweep of a new root ship on a worker that the session's
workstream alone uses, after the session's fence check, since A1 is answered on the
owner's behalf for such workers; on any other host a sweep waits for the owner's answer.

## Confirmation of each invariant

Not yet asked. The witness and control runs of the first two rule-text invariants land
with M0-3 of #297, those of `ks-no-fill-admitted-after-close` with M0-5 (#304):
`record-escape-live-1125b`, `record-loop-1-1125b` and the control
`record-escape-judged-open-1125b`, and those of `ks-required-events-reached` with M2-4
(#315): `reach-live-1125b` and `reach-control-1125b`. The owner is then shown, for each row, the receipt of the run its check
passes and the receipt of the run it rejects.

## Numbers

Every number of a row of `chaos/ledger.json` and of `chaos/project.yaml`. A number
that the owner adopted at no place was a working value of the workstream. The ruling on
OQ-2 and OQ-2.1 ("Ruled for the owner") rules each of them as it reads, and the column
says so on its row. `trusted_base` of `chaos/project.yaml` and the claim print each
with the same words.

| Number | Where | Source | Adoption |
| --- | --- | --- | --- |
| 3,600 s, the run deadline | `deadline_s` of each scenario; `budgets`; `trusted_base` | the workstream lead's sizing in #297, "Thresholds" | ruled as it reads by the workstream's lead on the owner's delegation of 25 November 2026; OQ-2 |
| 2 valid held runs | `runs_required` of each scenario; `trusted_base` | the validator's floor, `references/ledger-schema.md` of the skill | ruled as it reads by the workstream's lead on the owner's delegation of 25 November 2026; OQ-2 |
| 64 passes, the witness minimum | `load_delivery.min_passes_per_profile` of `ks-upload-no-fault` and `load_delivery.min_covered_per_profile` of `ks-cluster-link-faults`; `trusted_base` | `REQUIRED_PASSES` of `crates/campaign-supervisor/src/campaign/seeds/required.rs`, adopted in #180 as the reach floor | ruled as it reads by the workstream's lead on the owner's delegation of 25 November 2026, as a witness minimum of those two scenarios; OQ-2 |
| 64 covered passes, the reach floor | `threshold.min_covered_passes` of `ks-required-events-reached`; `load_delivery.min_covered_per_profile` of `ks-reach-required-events`; `trusted_base` | `REQUIRED_PASSES` of `crates/campaign-supervisor/src/campaign/seeds/required.rs` | adopted by the owner in #180; the ruling on OQ-2 names it |
| 1 covered pass reaching an event | `threshold.min_reaching_passes` of `ks-required-events-reached`; `reach.faults` of `ks-reach-required-events` | `crates/campaign-supervisor/README.md`, "Events reached by passing runs" | an existence check; no threshold |
| 64 runs, the `no_pass` floor | `trusted_base`; the core validity judge's verdict `invalid`, and the reach judge's `broken` when it names a profile of the scenario | `NO_PASS_RUNS` of `crates/campaign-supervisor/src/campaign/seeds.rs`; `crates/campaign-supervisor/README.md`, "Profiles with no pass" | ruled as it reads by the workstream's lead on the owner's delegation of 25 November 2026; OQ-2 |
| 12 runs or 3 hours, the rehearsal budget | `budgets`; `trusted_base` | the owner's measure of six hours a stage, #297, "Thresholds", shortened to three hours by the workstream's lead for the rehearsal of record (#304) | ruled as it reads by the workstream's lead on the owner's delegation of 25 November 2026; OQ-2 |
| 5 s added to the suites of the pull-request tier, measured on the unit's worker | `trusted_base` | the workstream lead's working bound, #297, R27 | ruled as it reads by the workstream's lead on the owner's delegation of 25 November 2026 |
| `restarts` 20 in a swept recovery assignment | `trusted_base`; the second example assignment of `docs/agents/sim-hosts.md` | `EVERY_CUT` of `crates/campaign-supervisor/src/campaign/seeds.rs`; the supervisor's README, "Recovery crash windows"; #297, "Thresholds" | ruled as it reads by the workstream's lead on the owner's delegation of 25 November 2026; OQ-2.1 |
| 64 runs, the missing-window floor | `trusted_base` | `NO_PASS_RUNS` of `crates/campaign-supervisor/src/campaign/seeds.rs`, the floor `no_pass` uses; #297, "Thresholds" | ruled as it reads by the workstream's lead on the owner's delegation of 25 November 2026; OQ-2.1 |
| 120 s, `STOP_WAIT_S` | `chaos/harness/run_scenario.py`; `trusted_base`; `constants` of each `run.json` | the harness's own wait from the SIGTERM of a stopped `campaign` command to its SIGKILL; unrelated to `--for 120` | ruled as it reads by the workstream's lead on the owner's delegation of 25 November 2026 |
| 0.5 s, `POLL_S` | `chaos/harness/run_scenario.py`; `trusted_base`; `constants` of each `run.json` | the harness's longest wait between two looks at a running command; it bounds a wait and promises no scheduling latency | ruled as it reads by the workstream's lead on the owner's delegation of 25 November 2026 |
| 600 s, `JUDGE_WAIT_S` | `chaos/harness/run_scenario.py`; `trusted_base`; `constants` of each `run.json` | the harness's wait for one judge; a judge past it leaves no accepted receipt and the harness's result is incomplete | ruled as it reads by the workstream's lead on the owner's delegation of 25 November 2026 |
| 2^24, 2^28 and 2^22 bytes, the read bounds | `chaos/harness/run_scenario.py` (`LEDGER_BYTES`, `RECEIPT_BYTES`, `CHECKPOINT_BYTES`, `LINE_BYTES`, `OUTPUT_BYTES`) and `chaos/judges/core/common.py` (`LEDGER_BYTES`, `EVIDENCE_BYTES`, `SOURCE_BYTES`); `trusted_base` | `CHECKPOINT_BOUND` and `LINE_BOUND` of `crates/campaign-supervisor/src/campaign/seeds.rs` for sweep.json and a suspect line; the others are the harness's and the judges' own | ruled as it reads by the workstream's lead on the owner's delegation of 25 November 2026; a record past a bound is refused, and no count is compared with one |
| 28 workers, `--batch 30`, `--for 120` | `load.workers`, `load.batch_s` and `text` of each scenario; `load.for_s` of each but `ks-ordering-figure` | the workstream lead's sizing, #297, "The first ledger" | the run's form; no threshold |
| 1, the load multiple | `load.multiple` of each scenario | #297, KTD8: the smallest honest value | settled by KTD8; no threshold |
| 1 pass reaching `hits`, 1 reaching `invalidated`, 1 reaching `faults` | `reach` of `ks-cluster-link-faults` | #297, "The first ledger"; one covered pass reaching an event clears it from `unreached` (`crates/campaign-supervisor/README.md`, "Events reached by passing runs") | an existence check; no threshold |
| obligation codes 2 and 1 | `witness.obligation` of each rule-text invariant; `ks-required-events-reached` and `ks-ordering-controls-caught` have none | `Failure::Violation(2, ...)` of `STALE_READ` and `Failure::Certain(1, ...)` of `corrupted` in `crates/campaign-supervisor/src/campaign/calibration/controls.rs`; for `ks-no-fill-admitted-after-close`, code 2, `Obligation::History` of the check of `k9-placement-across-close` in `crates/kestrike/src/net/world_tests/histories/keyops.rs` | identifiers of merged code; no threshold |
| 500 caught runs and 500 passes, the witness minimums of a history that declares its violation and of its passing twin | `load_delivery.min_caught_per_profile` and `load_delivery.min_passes_per_profile` of `ks-escape-2075`; `trusted_base` | the 500-root tally of a scripted history, `docs/agents/simulation.md` ("Run the history under a range of roots, 500 for a scripted history"); #297, "Thresholds" | the merged guide's tally; no threshold of its own |
| 1 GiB in `us-west-2a` | the probe of `ks-no-new-paid-resource` | the smallest volume of a dry run, in the worker's region | a probe argument; the dry run creates nothing |
| 0, `left_a_process` | `restoration` of each scenario | #297, KTD8: `restoration` records `left_a_process: 0` and `archive_verified: true` | settled by KTD8; no process may outlive a run |
| exit codes 0, 1, 2, 3 and 4 of `campaign sweep` | `stop_conditions` and `restoration` of each scenario | `crates/campaign-supervisor/README.md`, "Exit codes"; #297, "Verdict mapping" | identifiers of merged code; no threshold |
| 1, the ledger schema | `schema` | the skill's ledger schema | the format; no threshold |
| 1,000 runs a control | `threshold.min_runs_per_control` of `ks-ordering-controls-caught`; `trusted_base` | #297, "Thresholds": runs a control, proposed; it counts the runs that ended caught, missed or with no effect, as `docs/agents/simulation.md` counts finished runs | ruled as it reads by the workstream's lead on the owner's delegation of 25 November 2026; OQ-2 |
| 95%, one-sided | `threshold.confidence` of `ks-ordering-controls-caught`; `trusted_base` | #297, "Thresholds" and KTD15: the confidence of the Clopper-Pearson lower bound, proposed; the bound takes each control's run count as fixed, while `--for` sets it by the wall clock | ruled as it reads by the workstream's lead on the owner's delegation of 25 November 2026; OQ-2 |
| greatest planted depth 3; one control a depth | `trusted_base`; the profile set of `ks-ordering-figure` | #297, "Thresholds"; the `ORDERING` table of #307 | ruled as it reads by the workstream's lead on the owner's delegation of 25 November 2026; OQ-2 |
| 0.9999999, the greatest confidence | `MOST_CONFIDENCE` of `chaos/judges/ordering/figure.py`; `trusted_base` | the range in which the judges' test holds the written bound at or below an exact calculation; the bound of a few catches is proportional to 1 minus the confidence, which a binary float holds to 2^-54: at this value that error is below a hundredth of the judge's allowance of a relative 1e-7, and near 1 it passes the allowance | ruled as it reads by the workstream's lead on the owner's delegation of 25 November 2026; a row with a higher confidence is invalid |
| 10,000,000 runs a control | `MOST_RUNS` of `chaos/judges/ordering/figure.py`; `trusted_base` | the range in which the judges' test holds the bound's arithmetic to its closed forms and an exact calculation; 23 times the 430,791 runs of `cluster-order-1` in the `--for 600` sweep `ordering-live-r7` on the worker, and 23 times the 426,713 runs of its replacement `ordering-live-1125b` | ruled as it reads by the workstream's lead on the owner's delegation of 25 November 2026; a control with more runs is invalid |
| depth 1, 2 and 3; n 26; k 20,000 | `threshold.<control>.depth`, `.n` and `.k` of `ks-ordering-controls-caught` | `ORDERING` of `crates/campaign-supervisor/src/campaign/calibration/controls.rs`: n the checked-in listing's `actors` count, k the default `turns` count (#307) | read from their sources; each control's own numbers, which describe its premise; no verdict uses n or k, and a depth above 3 is invalid |
| `--for 600` | `load.for_s` and `text` of `ks-ordering-figure` | #297, M6-2 | the run's form; no threshold |
| 1 run, the load-delivery minimum | `load_delivery.min_runs_per_profile` of `ks-ordering-figure` | #297, M6-2: each control has runs | an existence check; no threshold |
| 0 of 300 roots, 0 of 60,000 control runs | `differs_from_production`; the figure judge's scope sentence | the measurement of blotter pull request 2117 (#307) | measured counts; no threshold |

## Ruled for the owner

Each question here was open for the owner and is ruled. Each ruling names who made it
and when: the owner's delegate, on the owner's behalf, on the date given, or the
workstream's lead, on the owner's delegation of 25 November 2026 (the owner's words to
its delegate, at about 06:14 UTC: "the rest is your call"), on that day. The
workstream's lead relayed each ruling on 25 November 2026 (decision L275, and decisions
L280 and L281 for the six stop notes) to the session that wrote it here. The repository
holds no other record of the rulings, and the owner wrote none of them.

`chaos/project.yaml`, `chaos/approval-policy.md`, the excluded entry of OQ-5 in
`chaos/ledger.json`, the claim `chaos/READINESS.md` and `docs/agents/chaos.md` state
the rulings on the questions of #297 and on A1 from the commit that follows the one
that added this section. The
workstream's lead ordered that on 25 November 2026 (decision L278), with the correction
of the rehearsal budget, the date of the first part of OQ-8 and the seven working
values noted below.

- **OQ-1** The freeze commit, who sets a status after it, and who runs the harness
  after the rehearsal (R1, R2).
  Ruled on the owner's behalf by the owner's delegate, 25 November 2026:
  - The freeze commit is the commit of `main` that merges pull request blotter pull request 2230, the pull
    request that carries this ruling. That commit has no id while this is written, so
    this file names it as the merge of that pull request. The condition: the contract
    check at that commit, with that commit as the freeze id and the build digest of
    that pull request's archive, prints nothing and renders the claim.
  - The pinned validator, `chaos/tools/validate_contract.py`, joins `frozen_paths` at
    that commit. `frozen_paths` of `chaos/project.yaml` lists it beside the four
    entries of #301.
  - A status of `held` or `fixed` is set by a pull request whose first lines give the
    check's exit with the freeze id, the build and the run ids, and the merge into
    `main` sets it.
    The workstream's lead, who proposed that sentence, stated on 25 November 2026
    (decision L285) what it rules: the status is set as a record. The pull request's
    first lines and its entry in the loop's log give the contract check's exit with
    the freeze id, the build and the run ids, run in an uncommitted copy of the tree
    that carries the status, and its merge into `main` puts that record on `main` and
    sets the status. No commit carries `held` or `fixed` in `chaos/ledger.json`, on a
    branch or on `main`: KTD9 of #297 stands, and the validator and the pre-push
    check stay as they are.
  - The harness is run by a session of a workstream on a worker that workstream alone
    uses, after the session's fence check.
  - A later change to a frozen path follows the order of `docs/agents/chaos.md`, "When
    the receipts of record are made again", and its pull request proposes the next
    freeze commit.
- **OQ-2** Adoption of each number marked open in "Thresholds" of #297, and
  `runs_required` with the break rate it may miss (R26).
  Ruled by the workstream's lead, on the owner's delegation of 25 November 2026, on
  that day: the working values under "Numbers" are ruled as they read. The ruling
  names these:
  - `runs_required` 2: two held runs miss a break that shows in half of all runs one
    time in four;
  - the run deadline of 3,600 s;
  - the rehearsal budget of 12 runs or 3 hours, the six hours of #297 shortened for
    the rehearsal of record;
  - the witness minimum, the reach floor and the `no_pass` floor of 64;
  - for the ordering figure, 1,000 complete runs of a control, a one-sided confidence
    of 95 percent, and the greatest planted depth 3 with one control a depth.

  The admission rate of a required event, 1 covered pass in 8 over at least 2,000,
  stands as #180 adopted it.
  The ruling's first sentence also rules, as they read, seven working values that its
  list leaves out: the 5 s that a pull request may add to the suites of the
  pull-request tier, `STOP_WAIT_S`, `POLL_S`, `JUDGE_WAIT_S`, the read bounds,
  `MOST_CONFIDENCE` and `MOST_RUNS`. The workstream's lead confirmed that reading on
  25 November 2026 (decision L278).
  The ruling as first relayed named a budget of 12 runs or 6 hours, the figure of
  #297's "Thresholds". The workstream's lead corrected it the same day (decision
  L278) to the 3 hours that `budgets` of `chaos/project.yaml` holds.
  - **OQ-2.1** Adoption of `restarts` 20 in a swept recovery assignment, and of the
    missing-window floor of 64 runs of a profile, the floor `no_pass` uses.
    Ruled by the workstream's lead with OQ-2, on the same authority and day:
    `restarts` 20 with the missing-window floor of 64 runs, as they read. From that
    count and floor, `campaign sweep` lists each stored planned crash window with a
    zero or folded total under `no_window` and exits 1; a profile with an empty
    `windows` map stays off it, its coverage unknown (`EVERY_CUT` and `NO_PASS_RUNS`
    of `crates/campaign-supervisor/src/campaign/seeds.rs`; the supervisor's README,
    "Recovery crash windows"). The second example assignment of
    `docs/agents/sim-hosts.md`, "Measured partition", puts the count of 20 into use.
- **OQ-5** Whether a run that ends `unsuccessful` under "a healed owner kept the
  resources of finished work" (#31) breaks an agreed property.
  Ruled by the workstream's lead, on the owner's delegation of 25 November 2026, on
  that day: it breaks an agreed property. Swept profiles judge the rule, and the
  planted control `cluster-swarm-leak` is caught by it. The ledger's exclusion of the
  property stands until a row with a witness and that control is added. The row needs
  no adopted number, since the rule's ending judges it.
- **OQ-6** Whether a rule text judged by an existing profile stands as
  `property.agreed: owner` in the chaos ledger.
  Ruled by the workstream's lead, on the owner's delegation of 25 November 2026, on
  that day: a rule text that an existing profile judges stands as
  `property.agreed: owner`.
- **OQ-8** Confirmation of #241, the revisit of the reach numbers of #180, and which
  source holds in each recorded disagreement (M7-1).
  Ruled in two parts. The first part, on #241, was ruled on the owner's behalf by the
  owner's delegate, 25 November 2026. The two other parts were ruled by the
  workstream's lead, on the owner's delegation of 25 November 2026, on that day.
  - The confirmation that #241 waits for stays with that ticket's own specification,
    #238: #241 is conditional until that specification's first tally is read.
  - The reach numbers of #180 stand.
  - In each recorded disagreement of `verification/intake/`, the text that states the
    property holds, and the other text describes a defect whose repair changes cache
    behavior. For a fill after close (`disagreement-fill-after-close`), the module
    documentation of `crates/kestrike/src/storage/writable.rs` holds: "Close
    refuses new receives, reservations and publications." For first-pass fills
    (`disagreement-first-pass-fills`), the comment in `Storage::cut_intact` holds. For
    the root slots (`disagreement-root-slot-layout`), the invariant
    ONE-QUALIFIED-WRITE-PER-BLOCK holds. For the waiting pass
    (`disagreement-waiting-pass-quota`), the obligation record's bound holds.
- **OQ-12** Which text holds for candidate 1 of M0-4: "Close refuses new receives,
  reservations and publications." (`crates/kestrike/src/storage/writable.rs`) or
  "Fills and builders admitted earlier keep their reservations or escrowed extents in
  every state." (`crates/kestrike/src/storage/readiness.rs`).
  Ruled by the workstream's lead, on the owner's delegation of 25 November 2026, on
  that day: the text of `storage/writable.rs` holds. A hold granted after the close is
  a new reservation, and the one-extent path already refuses it. #298 is a defect of
  the several-extent path.
- **From A1, the first part** Who else used the workers of the workstream that built
  this contract, and when.
  Ruled on the owner's behalf by the owner's delegate, 24 November 2026: for the time
  of that workstream, each of its workers and that worker's `/data/tsw/campaigns` were
  used by that workstream alone. A1 records the sweeps that started before this file
  held the ruling.

Six stop notes of `chaos/loop/stops/` are answered, and each note's section "Answer"
states its answer with its undo. Three are design rulings of the workstream's lead:

- **Stop note `oracle-text.md`** The `oracle` sentence of
  `ks-no-fill-admitted-after-close`, which commit `cb9ad9321` amended.
  Ruled by the workstream's lead, on the owner's delegation of 25 November 2026, on
  that day: option 1, confirmed as made. The amended sentence stands: the check fails
  the run when the closed cache grants the placement and then the shard hold, or
  refuses either `Closed` and keeps an additional-key claim. Every run of that row in
  the tree was made under it.
- **Stop note `trusted-base.md`** The two `trusted_base` items of
  `chaos/project.yaml` that commit `cb9ad9321` amended (A12).
  Ruled by the workstream's lead, on the owner's delegation of 25 November 2026, on
  that day: option 1, confirmed as made. The 64-pass item names `ks-upload-no-fault`
  and `ks-cluster-link-faults`, and the control `k9-placement-judged-open` is stated
  as a control that plants no cache defect.
- **Stop note `2075-fix.md`** The fix of #298, which changes cache behavior.
  Ruled by the workstream's lead, on the owner's delegation of 25 November 2026, on
  that day: option 1. #298 is a defect, by the ruling on OQ-12 above. The fix is a
  pull request of its own that flips `k9-placement-across-close` to a pass and removes
  its known-findings row in the same change. The pull requests of the workstream that
  built this contract leave the shipped crates' non-test builds unchanged, so the fix
  is ticketed in the workstream that follows. The scenario `ks-escape-2075` stays
  `broken` until that pull request merges.

Three are confirmations on the owner's behalf, under the same words of the owner. Each
approves an act on the rehearsal's records:

- **Stop note `rehearsal-freeze.md`** The rehearsal's freeze and the two holds logged
  under it.
  Ruled on the owner's behalf by the owner's delegate, 25 November 2026 (the
  delegate's notice 050): option 1, confirmed.
  `1a76d225bcf1aa0c3145755138f577716bfae5d1` is the rehearsal's freeze. The holds of
  `ks-upload-no-fault` and `ks-cluster-link-faults` stand as rehearsal holds of build
  `3b9e5e9f1598` for the records at commit `caded992b`, in the log. The tree at the
  head gets its hold from the freeze that the merge of pull request blotter pull request 2230 makes
  (OQ-1 above) and from a hold check of its own.
- **Stop note `record-retirement.md`** The retirement of three interim escape runs and
  of four interim copies of blotter issue 2080's runs, made before the rehearsal's freeze.
  Ruled on the owner's behalf by the owner's delegate, 25 November 2026 (the
  delegate's notice 050): option 1, confirmed. The tree keeps the replacements, and
  the retired pairs stay at `981c9d811` and `74b137023`. Each verdict they carried is
  carried by a run of the rows and judges that stand.
- **Stop note `merge-of-start-c05.md`** The retirement of three run and receipt pairs
  at the merge of `bsw/bsw-ct1/start-c05`.
  Ruled on the owner's behalf by the owner's delegate, 25 November 2026 (the
  delegate's notice 050): option 1, confirmed. The retirement stands as made, and the
  earlier pairs stay at `74b137023`.

The last two notes were written after the commits they ask about. The confirmations
accept that for those commits and for no later one: `docs/agents/chaos.md`, "When the
receipts of record are made again", states the order for every later commit.

## Open for the owner

Each is open, with no default, and no ruling settles it. Each stays open at the freeze
commit that the ruling on OQ-1 names. The top-level items OQ-3, OQ-4 and OQ-7 are
#297's; the sub-items OQ-4.1 to OQ-4.4 are M4-4's (#310).

- **OQ-3** The four unfenced reaches (KTD4): protection of `main` applied to admins, a
  token scoped to this repository, a second Unix user that owns the frozen paths and
  the receipts, and the name of the simulation hosts' bucket.
  A fine-grained token reports no OAuth scope list, so `reach.py token-scope` cannot
  read it and exits 2: that act also needs a new probe and row for
  `ks-no-workflow-file-push`, agreed with the owner's answer.
  The second example assignment of `docs/agents/sim-hosts.md`, "Measured partition",
  sweeps from a bucket of its own, so the bucket name stands for each bucket the
  simulation hosts sweep from, and a refusal probed at one bucket closes the reach for
  that bucket alone.
- **OQ-4** Approval of each exclusion: the escapes in `bind` and `failover` and up to 4
  that need a panic during unwinding (M1-1); the three exclusions of M4-4, where the
  repository records no reason for the lifecycle dimensions. Each of the three is an
  `excluded` entry of `chaos/ledger.json`, OQ-4.1 to OQ-4.3. OQ-4.4 is a fourth
  exclusion of M4-4, which stands in place of the scenario the unit withdrew:
  - **OQ-4.1** Approval of the exclusion of lying device faults in generated
    profiles: no generated profile draws one of the six lying kinds, and the
    production-cause table of M4-1 gives each the lying reason with #216, gap G3.
  - **OQ-4.2** Approval of the exclusion of device faults outside the simulated
    device's fault contract, volatile-cache loss, timeout callbacks and queue-pair
    failures: the production-cause table of M4-1 gives each its reason, with #60,
    #216, #221 and the `fault-kinds` row of `storage::device::fidelity_tests`.
  - **OQ-4.3** Approval of the exclusion of the cluster world's unsupported
    lifecycle dimensions, node lifecycle, session lifecycle, membership and
    placement: the cluster world reports them as unavailable dimensions, the
    repository records no reason, and #31 assigns the cluster workload to the
    open #38.
  - **OQ-4.4** Approval of the exclusion of the recovery profiles' planned crash
    windows, the windows past the first included: a sweep at `restarts=20` lets a
    run of each profile take every cut of its table, the recovery world raises a
    violation only through the restart check and the conservation rule, both
    excluded already, the bound-record observer does not run in that world, and no
    judge of this contract reads the `windows` totals. A scenario waits for an
    invariant that a check of the recovery world raises, with a judge and a control.
- **OQ-7** The workflow lines: a scheduled contract check with the freeze id. #297
  lists a scheduled job for M6-2's figure under this question too. By the workstream
  lead's instruction of 25 November 2026 (decision L275), that job is asked no more.
- **From A1, the second part** Who else uses the host on which the owner runs the loop
  after the workstream that built this contract, and when. No scenario run starts on
  that host before the owner answers; the drafts go on without it.
- **From A5** The fleets for a fence probe from a session the owner runs.
- **From A6, item 2** A ledger row after the freeze for the registry rule "a bound
  slot's bytes match no registered content".
- **From A10** During which hours a run may start, and what the campaign may spend,
  model usage included.
- **From B** Three proposals of `chaos/approval-policy.md` that no place of the
  owner's sets: what ships without asking beyond the draft branch, the archive and the
  committed statuses (B1), the stops of B2 marked as this contract's proposal, and the
  form of a stop (B3). With them B5, telemetry the loop may add, which has no answer.
- **From "Confirmation of each invariant"** The confirmation of each of the ledger's
  invariants, which that part records as not yet asked.
