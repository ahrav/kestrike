# Chaos finding audit: ks-cluster-link-faults, hold at build 3b9e5e9f1598

Note of 2026-11-24T20:00Z, added after the review of pull request blotter pull request 2126 and no part of
the auditor's report: the run figures, digests and receipts in this record are those of
build `3b9e5e9f1598`, which stand at commit `caded992b`. `chaos/runs/` and
`chaos/receipts/` then held runs of build `7899890b4d5f` under the same ids, with the same
verdicts (`chaos/loop/log.md`, amendment of 2026-11-24T14:05Z;
`chaos/loop/stops/remakes-after-the-record.md`). The control receipts that check 3 cites,
of `upload-corrupted` and `cluster-stale-read`, and the runs `upload-live` and
`cluster-live` are those of build `3689c1ea48e9` at that commit too; the tree now holds
blotter issue 2080's runs of build `9277dc4c7c8f` under those four ids, with the same verdicts and
other counts (`chaos/loop/final-report.md`, "After the campaign"). The hold this report checks counts for
the records at `caded992b` only: at commit `6cffb0a49` the contract check with the
rehearsal freeze id exits 1, as that stop note states.

Note of 2026-11-25, added with the runs of record made again that day and no part of
the auditor's report: the runs of build `7899890b4d5f` stand at commit `5755aacea`.
`chaos/runs/` and `chaos/receipts/` now hold their replacements of build `c948fcfa86a0`
under new ids, `record-cluster-1-1125b` and `record-cluster-2-1125b`, with the same verdicts
(`chaos/loop/log.md`, amendment of 2026-11-25;
`chaos/loop/stops/escape-restoration-text.md`).

```text
Item type: hold        Starts from: the hold logged in chaos/loop/log.md, entry 5 (runs
           record-cluster-1 and record-cluster-2); the scenario never broke, so no fix
           audit is needed
Contract: chaos/ at rehearsal freeze 1a76d225bcf1aa0c3145755138f577716bfae5d1, named by
          the coordinator's item; it is no freeze of the owner's
Validator: chaos/tools/validate_contract.py (SHA-256 ffe21050..., equal to
           chaos/tools/validate_contract.py.sha256 and to the installed skill's copy).
           Checkout as committed (status open): exit 0, no line.
           Scratch worktree with ks-cluster-link-faults set held: exit 0, no line.
           Findings on the item: none. Flags left out: none
Build on the copy: 3b9e5e9f1598aa6f593107750d9770f3ba5c9ad6fa1385603e1b89cff156c6a5, read
           from the copy: sha256sum /data/tsw/campaigns/2082r/archive/build prints it;
           the archive's provenance is revision cb9ad932154b5569783cc0e5bc64ba09dcd40d36,
           dirty false, untracked 0. The owner's word on it was not available
Verdict: needs-owner
```

Every check of a hold passes on the files. The one open question is the owner's: the
freeze. The contract check passes with `--freeze-commit 1a76d225b...`, but that commit is
a rehearsal freeze that the campaign recorded under a rule of the owner's, and the
workstream's lead has still to confirm it at review. The skill says that a freeze commit
the campaign chose freezes nothing, and the approval policy lists the freeze as a stop
for the owner. When the owner (or the lead, under the owner's rule for #304) confirms
`1a76d225bcf1aa0c3145755138f577716bfae5d1` as the freeze this hold is quoted under, the
verdict becomes accept with no further run. When the owner names another freeze, the
contract command of check 1 runs again with that id.

The auditor is a worker session with its own context. It wrote none of the harness, the
judges, the rows or the runs, and none of the coordinator's reasoning reached it. It
started no run and no sweep, set no status, and changed no file of the checkout other
than this report. The hold check with status `held` ran in a scratch worktree under
`$TMPDIR`, which was removed afterwards.

## Checks

| Check | Result | Evidence (command and decisive output, or file and field) |
| --- | --- | --- |
| 1. The contract | pass under the rehearsal freeze; owner: the freeze id | In the checkout: `python3 -I chaos/tools/validate_contract.py chaos/ledger.json --root . --project chaos/project.yaml --receipts chaos/receipts --build 3b9e5e9f1598aa6f593107750d9770f3ba5c9ad6fa1385603e1b89cff156c6a5 --freeze-commit 1a76d225bcf1aa0c3145755138f577716bfae5d1` printed nothing, exit 0. In a scratch worktree (`git worktree add --detach "$TMPDIR/audit-hold-cluster" HEAD`, the checkout's `chaos/` copied in, only `status` of `ks-cluster-link-faults` changed to `held`, `git diff --stat chaos/ledger.json` = 1 line), the same command printed nothing, exit 0. The check is live: the same scratch tree with `--build 000...0` printed `ks-cluster-link-faults: build-without-runs: the latest live run is of build 3b9e5e9f1598; no status stands for build 000000000000` (exit 1), and with `record-cluster-2`'s run and receipt directories moved aside it printed `ks-cluster-link-faults: too-few-held-runs: 1 valid held runs of the latest build; the row requires 2` (exit 1). `git diff --stat 1a76d225b HEAD -- chaos/harness chaos/judges chaos/project.yaml chaos/approval-policy.md chaos/ledger.json` prints nothing. Freeze: `1a76d225b` (2026-11-24T04:39:24Z, "chaos: freeze the escape's live and control runs as the rehearsal baseline") is an ancestor of HEAD `d49145adf`. The `--check-claim` run is under "Not checked". |
| 2. Each counted run did the work | pass | Receipts `chaos/receipts/record-cluster-{1,2}/*.json`: `mode` live, `defect` "", `outcome` held for all three rows, `system_build` 3b9e5e9f.... Validity detail: record-cluster-1 "valid: cluster-broad 194930 covered of 64 required, 77 replays; reached faults, hits, invalidated; 21223 control runs, 6130 caught"; record-cluster-2 "189521 covered of 64 required, 77 replays; ... 20804 control runs, 6181 caught". Recomputed from `sweep-status.json` `profiles["cluster-broad"]`: run 1 `runs` 231817, `pass` = `covered` 194930, `suspect_keys` {}, `reached.faults.runs` 194930 (total 4476447), `reached.hits.runs` 194930, `reached.invalidated.runs` 194929, `faults_delivered` 5290527; run 2 `runs` 225666, `covered` 189521, `suspect_keys` {}, `reached.faults.runs` 189521, `hits.runs` 189521, `invalidated.runs` 189520, `faults_delivered` 5154450. The row's `reach` (hits 1, invalidated 1, faults 1) and `load_delivery.min_covered_per_profile` 64 are met by far. Injection oracle (`reached.faults.runs` positive): met; it is the link's own record, which the row and `trusted_base` state. `run.json` of each: `workers` 28, `batch_s` 30, `for_s` 120, `sweep_elapsed_s` 120.664 / 120.669, `deadline_fired` false, `signal` null, `sweep_exit` 0, `confirm_exit` 0, `findings_exit` 0, `restored` {`archive_verified` true, `left_a_process` 0}, `root_build` and `archive_build_after` 3b9e5e9f.... Witness: both invariant details begin "no violation under the row's rule", each row's `witness.expect`. `sha256sum chaos/runs/record-cluster-{1,2}/*` equals every `key.evidence` digest. The root's own records agree: `campaign sweep-status --root /data/tsw/campaigns/2082r/<run>` (binary SHA-256 52cff29a..., as `run.json` `campaign_binary.sha256`) differs from the evidence copy only in `busy_us`, `elapsed_s`, `operations_per_s` and `runs_per_s`, the harness's `WALL_CLOCK_KEYS` (`chaos/harness/run_scenario.py` line 96). Each root's `manifests/cluster-broad.manifest` names `build = 3b9e5e9f...` and `executable = 34cdad78...`, the archive's `record.executable`. Spread: started 2026-11-24T04:51:48Z and 04:54:28Z, one host, one after the other, so both ran under the same host conditions. |
| 3. Each judge rejects a bad run | pass, with two limits | The validator's control checks print nothing for either invariant (check 1). Control receipts, read by hand: `chaos/receipts/cluster-stale-read/ks-get-not-older-than-collected.json` `mode` control, `outcome` broken, detail "the control cluster-stale-read was caught 62025 times under the row's rule \"a GET returned a version older than one collected or removed before it\" (obligation 2)"; `chaos/receipts/upload-corrupted/ks-bound-record-passes-its-checks.json` `mode` control, `outcome` broken, detail "the control corrupted was caught 475128 times under the row's rule \"a bound slot's record fails its header or chunk checks\" (obligation 1)". Both carry the same `key.judge` digests (common.py 03ede287..., invariant.py d26be9f0..., validity.py 0bb3ad41...) and `key.harness` digests (reach.py fcb258d6..., run_scenario.py d79d8dc1...) as the counted runs. Limit 1, the build: both control runs have `system_build` 3689c1ea48e9c4130f090593ed2c866c645d15131e48070e6e543aeee9cb5f91, another build than the hold's. They show that the judges and the harness reject the defects; no control receipt shows the defects reachable in build 3b9e5e9f. Supporting, from sweep records and not receipts: in the counted sweeps the control profile `cluster-stale-read` ran beside cluster-broad at build 3b9e5e9f and was caught under the row's rule 3508 of 4144 runs (record-cluster-1) and 3501 of 4122 (record-cluster-2), `missed` 0; the control `corrupted` ran in the upload sweeps `record-upload-1` and `record-upload-2` at build 3b9e5e9f and was caught under the row's rule 9658 of 9658 and 9434 of 9434, `missed` 0 (`sweep-status.json` `profiles`). Limit 2, the bound-record row in a cluster root: no control in a cluster root catches the rule "a bound slot's record fails its header or chunk checks". `record-cluster-1/sweep-status.json` lists it under `rules.scopes.boundary.uncaught`, and `trusted_base` in `chaos/project.yaml` states this limit. The row's `control.scenario` is `ks-upload-no-fault`, as frozen. |
| 4. Each judge refuses an empty run | pass | `vacuity_check.py` of chaos-scenario-harness, run from the checkout on `chaos/runs/record-cluster-1` for `ks-cluster-link-faults`, `ks-get-not-older-than-collected` and `ks-bound-record-passes-its-checks`. Without flags: exit 1 for each row, the one mark `VACUOUS empty suspects.jsonl`, which the script explains: "No record as recorded, and the judge held: suspects.jsonl". The recorded `suspects.jsonl` is 0 bytes, as a run with no suspect writes it, and the invariant judge decides from `sweep-status.json` `suspect_keys` (`chaos/judges/core/invariant.py` line 217), cross-checked against `suspects.jsonl` (`chaos/judges/core/common.py` lines 727-756). No file was marked as never opened, so no `--ignores` was declared. With `--may-be-empty suspects.jsonl`: exit 0, "no finding over 18 cases; the judge decides from 4 of 4 files beside run.json, and 1 of them may be empty", for all three rows on record-cluster-1 and on record-cluster-2 (six runs of the script). Every damaged case ended exit 2 (invalid) or 3 (incomplete): no-evidence, all-emptied, each file removed, emptied or garbled, and run.json removed, garbled or marked incomplete. Outputs: `~/.tmp/audit-vac/`. |
| 5. The sentence fits the rows | pass | The item's words, `chaos/loop/log.md` entry 5: "Hold of ks-cluster-link-faults at build 3b9e5e9f1598, runs record-cluster-1 and record-cluster-2", with "the committed status stays open". This matches the row: `load.multiple` 1 of `cluster-broad`, `fault.kind` `link-faults` on the simulated datagram links, `runs_required` 2, and the receipts' `system_build`. It claims no more. `differs_from_production` and `excluded` are quoted in the statement below. |
| 6. Who ran it | stated | `chaos/approval-policy.md`, "Who runs it": one identity, the worker's Unix user with its AWS role, runs the harness, writes the receipts and sets each status. `trusted_base` in `chaos/project.yaml`: "one identity, the Unix user tsw ... runs the harness and the fence probes, writes the receipts and sets each status, and it can also edit the ledger with its probe commands, the judges, the harness and the receipts", and "no second Unix user owns the frozen paths and the receipts". The coordinator's session started both runs and set the status in the scratch tree (log entries 4 and 5). The hold rests on that session's files. The checks compare files with each other and with the freeze; they cannot show who wrote a receipt. A sentence that calls this hold independently verified would claim more than the rows. |

## Counts

Live runs of `ks-cluster-link-faults` in `chaos/receipts/`, by `system_build`:

- Build 3b9e5e9f1598: `record-cluster-1` and `record-cluster-2`. Both are valid, and both
  invariants held in both. That is 2 decided runs, 2 held and 0 broken, against
  `runs_required` 2.
- Build 3689c1ea48e9: `cluster-live`, valid with both invariants held. That is 1 decided
  run of an earlier build, and it does not count toward this hold.
- No live run of this scenario broke at any build, so the scenario needs no fix count.

The control run `cluster-stale-read` (build 3689c1ea48e9, `mode` control) is not counted.

## Statement the evidence supports

No invariant broke in 2 valid runs of `ks-cluster-link-faults` at 1 times `cluster-broad`
(28 workers, 120 s, link faults on the simulated datagram links) on the copy. The copy is
the simulated Kestrike as the archived simulation worker runs it, at build
`3b9e5e9f1598`. The invariants are `ks-get-not-older-than-collected` and
`ks-bound-record-passes-its-checks`. The runs covered 194,930 and 189,521 passes of
`cluster-broad`. Each run reached faults, hits and invalidations in every covered pass
but one or two. The contract check holds under the rehearsal freeze `1a76d225b`, which is
no freeze of the owner's.

Limits that go with the sentence:

- Every result is about the simulation: one process, virtual time, small worlds and
  in-process datagram links (`differs_from_production` in `chaos/project.yaml`).
- The fault is recorded only by the injector's own record.
- The controls of both invariants ran at build `3689c1ea48e9`. At build `3b9e5e9f` only
  the sweeps' own control counts show them caught.
- For `ks-bound-record-passes-its-checks`, no control exercises the rule in a cluster
  root.
- `runs_required` 2 and the witness minimum of 64 covered passes are working values that
  the owner has not adopted.
- The properties under `excluded` in the ledger are not covered. These include the
  recovery and conservation rules, a lying device fault, and device faults outside the
  simulated device's contract.

Uncredited runs were outside the covered count. Of the `cluster-broad` runs, 36,887 of
231,817 in run 1 and 36,145 of 225,666 in run 2 were uncredited, about 16 percent. Most
were "unsuccessful: fewer exact reads than the profile requires" (27,359 and 26,851), and
the rest were "inconclusive: limit same_time" or fewer publications. That classification
is `campaign`'s, and `trusted_base` lists it. No row bounds the share.

Cause: n/a, since a hold states no cause.

## To the owner

- The freeze. Confirm `1a76d225bcf1aa0c3145755138f577716bfae5d1` as the freeze for this
  hold, or name the owner's freeze and have check 1 run again with that id. On the files,
  the commit meets the words of the owner's rule for #304, "the first commit of this
  branch that holds the enrolled escape and at which the first gate command prints
  nothing", as far as two commits show. The gate command of `AGENTS.md`
  (`validate_contract.py ... --check-claim chaos/READINESS.md`) printed nothing at
  `1a76d225b` (exit 0). At its parent `f69ee42b5`, which has the escape's rows but no
  escape runs, it printed `witness-missing`, `control-missing` and
  `status-without-receipts` (exit 1). The earlier rehearsal freeze of #304's first pass,
  `4626ec2457a1ce6fe2b376216a0503b2f917043c`, also stands on this branch. The choice of
  the later commit rests on the lead's decisions L056 and L067, which `chaos/loop/log.md`
  quotes. They are claims here, and the lead confirms them at review.
- Who ran it. One identity ran the harness, wrote the receipts and set the status (check 6).
- The claim file. `chaos/READINESS.md` is stale: the gate with `--check-claim` prints
  `stale-claim: chaos/READINESS.md differs from the claim this contract renders` (exit 1).
  It still reports `ks-cluster-link-faults` from `cluster-live` at build `3689c1ea48e9`.
  Before the claim quotes this hold, render it again.

## Not checked

- The claim file against this hold. `--check-claim chaos/READINESS.md` fails with
  `stale-claim`, and the claim states the status `open`, so the claim quotes no hold of
  this scenario. After it is rendered again, check it with
  `python3 -I chaos/tools/validate_contract.py chaos/ledger.json --root . --project chaos/project.yaml --receipts chaos/receipts --build 3b9e5e9f1598aa6f593107750d9770f3ba5c9ad6fa1385603e1b89cff156c6a5 --freeze-commit 1a76d225bcf1aa0c3145755138f577716bfae5d1 --check-claim chaos/READINESS.md`.
- A control receipt at build 3b9e5e9f, which only a run can supply. One control run of
  each invariant on the copy's archive would show the defects still reachable in this
  build, with a receipt:
  `run-in-scope.sh ks-cluster-link-faults <run-id> --control cluster-stale-read` and
  `run-in-scope.sh ks-upload-no-fault <run-id> --control corrupted`. That is 2 runs of the
  rehearsal budget, and the validator does not ask for them.
- The owner's own output of the freeze check, which was not available.

The checkout's working tree held uncommitted edits by the coordinator under `chaos/loop/`
while this audit ran: the final report renamed, three stop notes and the finding edited,
and a new stop note. The validator does not read those files, and this audit left them
alone.
