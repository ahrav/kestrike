## Chaos finding audit: ks-escape-2075, loop-escape-1

Note of 2026-11-24T04:15Z, added after the review of pull request blotter pull request 2126 and no part of
the auditor's report: the run figures, digests and receipts in this record are those of build
`9e1936bceaef`, which stand at commit `74b137023`. `chaos/runs/` and
`chaos/receipts/` now hold interim runs of build `a1875b9eafec` under the ids
`escape-live`, `escape-judged-open` and `loop-escape-1`, with the same verdicts
(`chaos/loop/log.md`, amendment of 2026-11-24T03:10Z).

Item type: break        Starts from: the receipt `chaos/receipts/loop-escape-1/ks-no-fill-admitted-after-close.json`
Contract: chaos/ at freeze 4626ec2457a1ce6fe2b376216a0503b2f917043c (the id the run rules name; see "Not checked")
Validator: exit 0; findings on the item: none; flags left out: none
Build on the copy: 9e1936bceaef13ec2057667f6b0f44843beec7a53541ceeb6d8f54e779739110, read from the copy as the SHA-256 of `/data/tsw/campaigns/2082/archive/build`, and named by the worker brief as the rehearsal's one archive (revision 806337a84bf8bebaacce63bdaccf7101934bc1ae)
Verdict: accept

The run `loop-escape-1` is a live run of the agreed scenario `ks-escape-2075` on the build on
the copy. Its evidence shows 1,289,604 runs of the scripted history `k9-placement-across-close`,
and every one of them ended in the violation "a fill admitted after the cache closed" of
obligation 2, the rule of the invariant `ks-no-fill-admitted-after-close`. The frozen judges,
run again on a scratch copy of the evidence, give the same verdicts as the receipts. The
break stands as the row states it.

### The contract command

```text
$ timeout 300 python3 chaos/tools/validate_contract.py chaos/ledger.json --root . \
    --project chaos/project.yaml --receipts chaos/receipts \
    --build 9e1936bceaef13ec2057667f6b0f44843beec7a53541ceeb6d8f54e779739110 \
    --freeze-commit 4626ec2457a1ce6fe2b376216a0503b2f917043c; echo "exit $?"
exit 0
```

The validator is the pinned copy. Its digest matches the recorded one and the skill's script:

```text
$ cat chaos/tools/validate_contract.py.sha256
ffe2105082fe6c9d700362905554df56f56aff2b72103745976676c10fa155ec  validate_contract.py
$ sha256sum chaos/tools/validate_contract.py <chaos-enrollment>/scripts/validate_contract.py
ffe2105082fe6c9d700362905554df56f56aff2b72103745976676c10fa155ec  chaos/tools/validate_contract.py
ffe2105082fe6c9d700362905554df56f56aff2b72103745976676c10fa155ec  .../chaos-enrollment/scripts/validate_contract.py
```

The frozen paths and the ledger are as the freeze commit has them:

```text
$ git diff --stat 4626ec2457a1ce6fe2b376216a0503b2f917043c -- chaos/harness chaos/judges \
    chaos/project.yaml chaos/approval-policy.md chaos/ledger.json; echo "diff exit $?"
diff exit 0
$ git rev-parse HEAD
4626ec2457a1ce6fe2b376216a0503b2f917043c
```

### Checks

| Check | Result | Evidence (command and decisive output, or file and field) |
| --- | --- | --- |
| 1. The run counts | pass | `chaos/receipts/loop-escape-1/ks-no-fill-admitted-after-close.json`: `key.mode` `live`, `key.defect` `""`, `key.outcome` `broken`, `key.row` `ks-no-fill-admitted-after-close`. The ledger's `ks-escape-2075.invariants` is `["ks-no-fill-admitted-after-close"]`. `chaos/runs/loop-escape-1/run.json`: `mode` `live`, `defect` `""`, `complete` true. The validator printed no `inconsistent-receipts`, `malformed-run`, `duplicate-evidence`, `incomplete-receipts`, `receipts-without-run`, `stale-receipt` or `row-changed-after-run` (exit 0). The five evidence digests in both receipts equal `sha256sum chaos/runs/loop-escape-1/*` (findings.json b1ad033a..., history.jsonl 7e1aadb3..., run.json 385e1d9a..., suspects.jsonl e3b0c442..., sweep-status.json b979950b...). The receipts' `judge` and `harness` digests equal `sha256sum` of the files at the freeze (common.py 06098132..., invariant.py ca749964..., validity.py 02c383b4..., reach.py 6ce5d781..., run_scenario.py 8c0119cc...). The receipts' `rows` digests equal the row digests of the current ledger, computed as `common.row_digest` does: scenario 9dc43267..., invariant bc03a372...; `run.json` `scenario_row` is 9dc43267.... |
| 2. The evidence shows it | pass | See "Recomputing the detail" below. `sweep-status.json` `profiles["k9-placement-across-close"]`: `runs` 1289604, `caught` 1289604, `caught_rules` `{"a fill admitted after the cache closed": 1289604}`, `pass` 0, `missed` 0, `suspects` 0, `failing_history` true. The root's own record `/data/tsw/campaigns/2082/loop-escape-1/sweep.json` holds the same counts. The row's rule text (`control.expect`) and obligation (`witness.obligation` 2) match the receipt's detail. No operation without an answer enters the verdict: the rule counts runs that ended in a declared violation. |
| 3. The conditions were the row's | pass | `chaos/receipts/loop-escape-1/ks-escape-2075.json`: `outcome` `held`, `detail` "valid: k9-placement-across-close 1289604 caught of 500 required, 89 replays". `run.json`: `workers` 28, `batch_s` 30, `for_s` 120, `sweep_elapsed_s` 120.661, `sweep_exit` 0, `deadline_fired` false, `signal` null, `restored` `{"archive_verified": true, "left_a_process": 0}`, `root_build` equals `system_build`. The row's `load` is workers 28, batch_s 30, for_s 120, `fault.kind` `none`, `load_delivery.min_caught_per_profile` 500. The root also ran seven h1 histories (78,987 runs); see "Conditions of the run". |
| 4. The build | pass | Both receipts: `key.system_build` 9e1936bceaef13ec2057667f6b0f44843beec7a53541ceeb6d8f54e779739110. `sha256sum /data/tsw/campaigns/2082/archive/build` prints the same digest, so that build is on the copy now. The archive's build record names `revision` 806337a84bf8bebaacce63bdaccf7101934bc1ae, `dirty` false. No finding report exists for this run (`chaos/loop/findings/` is absent), so no report names a build. |
| 5. The fault's part | n/a: the scenario has no fault | The row's `fault.kind` is `none`. The break occurs under the scripted history alone. No other no-fault scenario has a run at this build: `ks-upload-no-fault` ran only at build 3689c1ea48e9 (`chaos/receipts/upload-live/*.json`, `key.system_build`). The statement below carries no fault. |
| 6. The count | 2 of 2 | Live runs of `ks-escape-2075` at build 9e1936bceaef: `escape-live` (invariant `broken`, validity `held`, 1,276,757 caught) and `loop-escape-1` (invariant `broken`, validity `held`, 1,289,604 caught). Both are decided and both broke. `escape-judged-open` is a control run (`mode` `control`, `defect` `k9-placement-judged-open`) and is outside the count. The ledger's status is `broken` at the freeze and in the working tree, and the validator prints no status finding. |

### Recomputing the detail (check 2)

The invariant is of kind `history`. Its row says the property breaks when a run "ends in the
violation 'a fill admitted after the cache closed', of the obligation History". The frozen
judge `chaos/judges/core/invariant.py` reports broken in a live run through path (b): a
history of the scenario that declares its violation and counts a caught run under the rule
text in its `caught_rules`. I recomputed each input from the evidence files:

```text
run.json  listing["k9-placement-across-close"] = {"class": "history", "cluster": false,
          "fails": "violation 2 a fill admitted after the cache closed"}
sweep-status.json profiles["k9-placement-across-close"]:
  runs 1289604, next 1289604, caught 1289604, pass 0, missed 0, suspects 0,
  caught_rules {"a fill admitted after the cache closed": 1289604}, replays 89,
  failing_history true, faults_delivered 0
sweep-status.json suspects 0, new_suspects 0; suspects.jsonl is empty (0 bytes)
findings.json {"findings": [], "release_blockers": []}
history.jsonl {"build": "9e1936bc...", "campaign": "loop-escape-1", "counts": {},
  "profile": "k9-placement-across-close", "runs": {"first": 0, "next": 1289604}}
/data/tsw/campaigns/2082/loop-escape-1/sweep.json profiles["k9-placement-across-close"]:
  runs 1289604, caught 1289604, pass 0, missed 0,
  caught_rules {"a fill admitted after the cache closed": 1289604}
```

`crates/campaign-supervisor/README.md`, "Histories in a sweep", says what `caught` means for a
history whose listing declares a failure: "A run that ends in the declared complete failure is
counted under `caught`. A run that passes ... is a suspect". So each of the 1,289,604 runs ended
complete in the declared violation, and none passed. The rule text in `caught_rules` is byte
for byte the row's `control.expect`, and the listing's obligation 2 is the row's
`witness.obligation`.

I then ran the frozen judges on a scratch copy of the evidence (made with `mktemp -d` under
`$TMPDIR`, holding `chaos/ledger.json`, `chaos/judges/` and `chaos/runs/loop-escape-1/`), with
no `--receipt`, so they wrote nothing:

```text
$ timeout 120 python3 -I -B chaos/judges/core/invariant.py ks-no-fill-admitted-after-close \
    --evidence chaos/runs/loop-escape-1; echo "exit $?"
ks-no-fill-admitted-after-close: broken: the history k9-placement-across-close of the scenario
declares its violation and was caught 1289604 times under the row's rule "a fill admitted after
the cache closed" (obligation 2)
exit 1
$ timeout 120 python3 -I -B chaos/judges/core/validity.py ks-escape-2075 \
    --evidence chaos/runs/loop-escape-1; echo "exit $?"
ks-escape-2075: held: valid: k9-placement-across-close 1289604 caught of 500 required, 89 replays
exit 0
```

Both lines equal the receipts' `key.detail` and `key.outcome`.

**A declared failure is no control run here.** The README calls a history that expects a
failure "a control", and the skill rejects a break in a control run. This run is no control
run in the contract's sense. Its `mode` is `live` and it names no defect. The contract names
its own control for this invariant: `k9-placement-judged-open` (the ledger's `control.defect`),
which skips the owner's close and was run as `escape-judged-open`. The history
`k9-placement-across-close` plants nothing. Its steps (`K9_ACROSS` in
`crates/kestrike/src/net/world_tests/histories/keyops.rs`) are `promise-placement`, `close`,
`place-after-close` and the judge. They call the cache's library code: `begin_fill`,
`decide_admission`, `promise_storage`, `PlacingFill::place` and `PlacingFill::reserve_storage`
of `crates/kestrike/src/storage/writable.rs`, and `owner.close` with `owner.quiesce`. The
run fails through the rule only when `reserve_storage` returns `Ok` after the close
(`place_after_close`, the `Ok(fill) => ... fail(world, Obligation::History, ADMITTED_CLOSED)`
arm). The history is wrapped in `control(..., &[PLACEMENT_PROMISED, OWNER_CLOSED])`, whose doc
comment in `histories.rs` says the failure "counts only once `premise` is marked". By that
source, each caught run had a promise made before the close and an owner that closed and
quiesced. The failure is declared because #298 is open and its `KNOWN` row in
`crates/campaign-supervisor/src/campaign/known.rs` pins this history, and the row's
`witness.check` states it: "a live run of the unfixed cache is broken through the row's rule".
`git diff --name-only 806337a84bf8 4626ec2457a1` lists only files under `chaos/`, so the code I
read at HEAD is the code of the archive's revision.

### Conditions of the run (check 3)

The validity receipt is `held`, so every condition the frozen validity judge checks was met:
the sweep returned by itself with exit 0, the totals carry no `alarm`, `no_pass` or
`unreached`, the root holds the archive's build, the archive verified after the last run, no
process was left, and the profile met 500 caught runs (1,289,604) with 89 replays in a fresh
process.

The root also ran seven h1 histories that `--profiles` did not name: `h1-get` 11,310,
`h1-get-one-request` 11,275, `h1-get-reused` 11,749, `h1-get-stale` 11,430, `h1-get-unheld`
11,340, `h1-put` 10,528, `h1-put-wrong` 10,355 runs (`sweep-status.json`, `profiles`). The
README's "Histories in a sweep" says a sweep runs one history batch in every 16 from the
root's tenth batch "whatever `--profiles` names", taking the histories in turn. The enrollment
run `escape-live` shows the same seven histories at the same scale. This is the sweep's
documented rotation and the same in both counted runs. It adds no fault and no load to the
k9 runs, which are separate seeded runs. I did not show from the evidence that the rotated
runs share no state with the k9 runs; the frozen judges do not check it.

### Statement the evidence supports

At build 9e1936bceaef13ec2057667f6b0f44843beec7a53541ceeb6d8f54e779739110 (revision
806337a84bf8), one sweep of the scripted history `k9-placement-across-close` on the simulated
Kestrike, with 28 workers in batches of 30 s for 120 s and no fault, ended 1,289,604 of
1,289,604 runs in the violation "a fill admitted after the cache closed" (obligation 2). The
invariant `ks-no-fill-admitted-after-close` is broken in 2 of 2 decided live runs of
`ks-escape-2075` at that build (`escape-live`, `loop-escape-1`). This is evidence about the
simulation: one process runs the owner and the client in virtual time, the device is the
simulated device, and the load is the scripted history (`differs_from_production` in
`chaos/project.yaml`).

### Cause

Not shown by the run's evidence. The evidence holds counts of runs by ending, and no run's
step-by-step record. The module documentation of K9 in `histories/keyops.rs` and #298 state a
mechanism: "The owner's close closes its volume's readiness and leaves the storage's cutoff
open, and the hold reads only the cutoff, so the hold grants the fill". That is a claim. Two
things would show it: an accepted fix whose diff removes it and nothing else, or a replayed
run's trace showing the cutoff open at the grant. The sibling history
`k9-placement-across-storage-close` (`Expect::Pass`) runs the same steps with the storage's own
close and is declared to pass. A sweep of it at this build would show the history's check can
pass when the storage's cutoff is closed. No run of it is in the evidence: its `runs` is 0 in
both sweeps.

### To the owner

- No stop note is needed for this item. The verdict is accept, and the break goes to the owner
  as a finding in the form of `docs/agents/simulation.md`, "Report format", with the class, the
  agreed property and its citation, as the approval policy asks.
- The invariant's source records an open question of the owner, OQ-12 of #297: the text of
  `storage::readiness`, ALLOCATION-READY ("Fills and builders admitted earlier keep their
  reservations or escrowed extents in every state"), reads the other way from the
  `storage::writable` text the row cites. The row is frozen and `agreed: owner`, and its words
  are clear, so the break of the row stands. How the finding is classed against those two
  texts is the owner's answer to OQ-12.
- The run adds no new information over `escape-live` beyond the count: both runs are of the
  same build and break in every k9 run.
- At the time of this audit the evidence `chaos/runs/loop-escape-1/` and the receipts
  `chaos/receipts/loop-escape-1/` are untracked files of the checkout, and the five fence
  receipts under `chaos/receipts/fences/` are modified and uncommitted (`git status --short`).
  The validator read the working tree.
- Who ran the harness and wrote the receipts: the approval policy's "Who runs it" names one
  identity, the worker's Unix user `tsw` with its AWS role, and `trusted_base` lists it. The
  validator compares files and cannot show who wrote them.

### Not checked

- The freeze as the owner's. Check 2 of a break needs no freeze id. I ran the validator with
  the id the run rules name, 4626ec2457a1ce6fe2b376216a0503b2f917043c, and it exited 0. That id
  is the campaign's statement. The owner's rules for ticket 2082 say the lead confirms the
  rehearsal freeze at review. No owner's own output of the freeze check was given to me.
- A per-run trace of the mechanism: `campaign` replay of a listed run of
  `k9-placement-across-close` from the root `/data/tsw/campaigns/2082/loop-escape-1` would show
  the steps. The audit starts no run.
- That the rotated h1 histories share no state with the k9 runs. The frozen judges do not
  check it, and the evidence holds no per-run state.
- A sweep of `k9-placement-across-storage-close` at this build, which would support the
  history's check passing on a closed storage. The command would be `campaign sweep --root
  <new root> --archive /data/tsw/campaigns/2082/archive --profiles
  k9-placement-across-storage-close --workers 28 --batch 30 --for 120`. This history is in no
  scenario row, so the coordinator decides whether to ask for it.

### What this audit did

It read files, ran the validator on the checkout, and ran the two frozen judges without
`--receipt` on a scratch copy under `$TMPDIR`, removed at the end. It started no run, set no
status, and wrote only this file.
