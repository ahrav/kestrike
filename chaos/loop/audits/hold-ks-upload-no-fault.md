# Chaos finding audit: ks-upload-no-fault, runs record-upload-1 and record-upload-2

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
under new ids, `record-upload-1-1125b` and `record-upload-2-1125b`, with the same verdicts
(`chaos/loop/log.md`, amendment of 2026-11-25;
`chaos/loop/stops/escape-restoration-text.md`).

```text
Item type: hold        Starts from: no fix (the scenario was never broken; no fix audit applies)
Contract: chaos/ at the rehearsal freeze 1a76d225bcf1aa0c3145755138f577716bfae5d1
Validator: exit 0; findings on the item: none; flags left out: none
Build on the copy: 3b9e5e9f1598aa6f593107750d9770f3ba5c9ad6fa1385603e1b89cff156c6a5,
  from /data/tsw/campaigns/2082r/archive/build (its SHA-256 is this digest; it records
  revision cb9ad932154b5569783cc0e5bc64ba09dcd40d36, dirty false, untracked 0) and from
  each run.json's system_build, root_build and archive_build_after
Verdict: needs-owner
Panel: none. This session was dispatched as the one reviewer and dispatched no one.
```

Every check of a hold passed. The one open item is the freeze id. The commit
`1a76d225bcf1aa0c3145755138f577716bfae5d1` is a rehearsal freeze that the campaign
recorded and that the workstream's lead confirms at review (`chaos/loop/log.md`, "The
rehearsal of record (`2082-record`): session start"). It is no freeze of the owner's, and
the audit skill counts a freeze the campaign chose as no freeze. The owner's rule for this
campaign names the rehearsal freeze by a test ("the first commit of this branch that holds
the enrolled escape and at which the first gate command prints nothing ... the lead
confirms it at review"). The commit passes that test on the amended rows (check 1b below).
The lead has not yet confirmed it. When the lead confirms it, this audit's result is
accept for the sentence under "Statement the evidence supports", quoted as a rehearsal
hold.

## Checks

| Check | Result | Evidence (command and decisive output, or file and field) |
| --- | --- | --- |
| 1. The contract, committed status | pass | In `/data/tsw/checkout` at HEAD `d49145adf`: `python3 -I chaos/tools/validate_contract.py chaos/ledger.json --root . --project chaos/project.yaml --receipts chaos/receipts --build 3b9e5e9f1598aa6f593107750d9770f3ba5c9ad6fa1385603e1b89cff156c6a5 --freeze-commit 1a76d225bcf1aa0c3145755138f577716bfae5d1` printed nothing, exit 0. The validator file's SHA-256 `ffe2105082fe6c9d...c6a5` equals `chaos/tools/validate_contract.py.sha256` and the installed skill's `chaos-enrollment/scripts/validate_contract.py`. |
| 1a. The contract, status `held` | pass | `git worktree add --detach $TMPDIR/audit-hold-upload HEAD`, the checkout's `chaos/` copied in, `status` of `ks-upload-no-fault` set to `held` in its ledger (the only ledger change), the same command from that root: printed nothing, exit 0. The same copy with `--build 0000...0000`: `ks-upload-no-fault: build-without-runs: the latest live run is of build 3b9e5e9f1598; no status stands for build 000000000000`, exit 1, so the check reads the build flag. The worktree was removed. |
| 1b. The freeze id | owner: the lead's confirmation of `1a76d225` | `git diff --quiet 1a76d225... -- chaos/harness chaos/judges chaos/project.yaml chaos/approval-policy.md` exit 0. In a detached worktree, the gate of `AGENTS.md` (`validate_contract.py chaos/ledger.json --root . --project chaos/project.yaml --receipts chaos/receipts --check-claim chaos/READINESS.md`) printed nothing at `1a76d225` (exit 0, runs `record-escape-live` and `record-escape-judged-open` present). At its parents `f69ee42b5` and `cb9ad9321` (the row amendment) it exited 1 with `witness-missing`, `control-missing` and `status-without-receipts` on the escape's rows. So `1a76d225` is the first commit after the row amendment that meets the owner's test. Under the earlier rows the first pass named `4626ec2457a1...` (log, first entries); the second freeze rests on the lead's decisions L056 and L067, which the log cites. |
| 1c. Fences | pass | The validator reads every fence receipt and printed no fence finding. `chaos/receipts/fences/*.json`: the four credential fences have `exit_status` 1 and `refused` true; `ks-run-keeps-earlier-runs` has `exit_status` 2 and `refused` true. |
| 1d. Runs and receipts as committed | pass | `git diff --quiet HEAD -- chaos/runs chaos/receipts chaos/ledger.json` exit 0. The runs were committed in `158f8e974` ("keep the loop's two runs of ks-upload-no-fault"). `sha256sum chaos/runs/record-upload-{1,2}/*` equals every `key.evidence` digest in both receipts of each run. |
| 2. Each counted run did the work | pass | Both receipts of each run: `mode` live, `outcome` held, `defect` "", `system_build` 3b9e5e9f1598.... Validity detail, record-upload-1: "valid: upload 966305 pass of 64 required, 74 replays; 61289 control runs, 59451 caught". record-upload-2: "valid: upload 971915 pass of 64 required, 74 replays; 61628 control runs, 59775 caught". The invariant detail of each holds the row's `witness.expect` "no violation under the row's rule". `run.json` of each: `complete` true, `sweep_exit` 0, `confirm_exit` 0, `findings_exit` 0, `deadline_fired` false, `signal` null, `restored.left_a_process` 0, `restored.archive_verified` true, `workers` 28, `batch_s` 30, `for_s` 120, `profiles` ["upload"], `sweep_elapsed_s` 120.664. |
| 2a. The evidence agrees with the sweep root | pass | Each root under `/data/tsw/campaigns/2082r/` copied to `$TMPDIR` and read with `/data/tsw/campaigns/2082r/campaign sweep-status --root <copy>` (binary SHA-256 `52cff29a...faa20`, as `run.json` records): exit 0, and the output equals the committed `sweep-status.json` once the wall-clock keys the harness strips (`WALL_CLOCK_KEYS` of `chaos/harness/run_scenario.py`: `elapsed_s`, `runs_per_s`, `operations_per_s`, `busy_us`) are removed. |
| 2b. The load, the fault and the reach | pass | From each `sweep-status.json`: profile `upload` `pass` = `runs` (966305; 971915), `suspects` 0, `missed` 0, `faults_delivered` 0, `operations` 19044719 and 19153751; top-level `suspects` 0, `new_suspects` 0, `controls.missed` 0, `histories.missed` 0 and `histories.suspects` 0. `suspects.jsonl` is empty in both runs. The row's fault is `none` and the row names no `injection_oracle` and no `reach`, so no injection record applies. The upload run of blotter issue 2080 at build 3689c1ea48e9 (`upload-live`) passed 939000 runs with 59928 control runs, so these runs did comparable work. |
| 2c. The spread | limit | `run.started` 2026-11-24T04:46:47Z and 04:49:01Z, 2 min 14 s apart, on one host. Both runs ran under the same host conditions. |
| 3. Each judge rejects a bad run | pass, with a build limit | The validator checks the control and printed no `control-missing`, `control-not-rejected`, `control-run-invalid` or `stale-control`. The control run is `upload-corrupted`: `chaos/receipts/upload-corrupted/ks-bound-record-passes-its-checks.json` has `mode` control, `defect` corrupted, `outcome` broken, detail "the control corrupted was caught 475128 times under the row's rule \"a bound slot's record fails its header or chunk checks\" (obligation 1)". Its `judge` and `harness` digests equal those of the counted runs' receipts, and so do its `rows` digests. Its `system_build` is `3689c1ea48e9c413...5f91` (blotter issue 2080's archive under `/data/tsw/campaigns/2080/`), not the hold's build. That control shows that the judge and the harness reject the defect. Inside the counted runs, at the hold's build, the sweep's own control batches give the second half: `profiles.corrupted` caught 9658 of 9658 runs (record-upload-1) and 9434 of 9434 (record-upload-2), and `profiles.planted` 8169 of 8169 and 8256 of 8256, every one under the row's rule in `caught_rules`, with `missed` 0. Those counts are `campaign`'s classification, which `trusted_base` lists; no judge receipt at build 3b9e5e9f1598 records them as a control verdict. |
| 4. Each judge refuses an empty run | pass | `vacuity_check.py` of the installed `chaos-scenario-harness` skill, from the checkout, with `--run 'python3 -I -B {judge} --evidence {evidence}'`. Without flags, on record-upload-1, for `ks-upload-no-fault` and for `ks-bound-record-passes-its-checks`: exit 1, one mark each, `VACUOUS empty suspects.jsonl`; the script says "No record as recorded, and the judge held: suspects.jsonl", because the recorded file is already empty. No other case held; `no-evidence` and `all-emptied` exit 2; no `READS`, `CRASH`, `HUNG` or `NOFORM`. The judge decides from 4 of 4 files beside `run.json`, so no file needs `--ignores`. With `--may-be-empty suspects.jsonl`, on both runs and both rows: "no finding over 18 cases", exit 0 four times. `chaos/judges/core/invariant.py` (line 217) and `common.py` (lines 727-756) decide from `suspect_keys` in `sweep-status.json` and require `suspects.jsonl` to agree with it, so an empty list beside zero counted suspects is the sound case. Saved outputs: `~/research/2082/audit-hold-upload/*.txt`. |
| 5. The sentence fits the rows | pass | The only sentence is the log's (entry 3): "Hold of ks-upload-no-fault at build 3b9e5e9f1598, runs record-upload-1 and record-upload-2 ... This hold is quoted nowhere outside the campaign and has no audit." It names the build, the runs and the row and claims nothing wider. The claim the validator renders with `held` set (`--claim`, saved as `~/research/2082/audit-hold-upload/audit-hold-upload-claim.md`) gives "2 held, 0 broken and 0 without a verdict of 2 live runs of build 3b9e5e9f1598" and lists each `differs_from_production` item of `chaos/project.yaml` as a limit. |
| 6. Who ran it | limit | `chaos/approval-policy.md`, "Who runs it": "One identity, the worker's Unix user with its AWS role, runs the harness, writes the receipts and sets each status." `trusted_base` in `chaos/project.yaml`: that identity "can also edit the ledger with its probe commands, the judges, the harness and the receipts", and "no second Unix user owns the frozen paths and the receipts, and the campaign's user can run commands as root through sudo". The campaign's coordinator ran the harness and wrote these receipts. The hold rests on that session's files; the checks above compare files with each other. |

## Statement the evidence supports

No invariant broke in 2 valid runs of `ks-upload-no-fault` at 1 times upload on the copy,
the simulated Kestrike as the archived simulation worker runs it under `campaign`, at
build `3b9e5e9f1598aa6f593107750d9770f3ba5c9ad6fa1385603e1b89cff156c6a5`. Each run was
one sweep of the profile upload at default counts with no fault drawn, 28 workers, 30 s
batches, 120 s, on a new root under `/data/tsw/campaigns/2082r/`, and passed 966305 and
971915 upload runs. The invariant checked is `ks-bound-record-passes-its-checks` only. The
statement holds under the rehearsal freeze `1a76d225...`, not under a freeze of the
owner's, and every item of `differs_from_production` limits it: every result is about the
simulation, on one thread, with small worlds and synthetic load, in the cfg(test) build.
Production, the native driver and an EBS volume are outside it. "Independently verified" is
wrong wording for it (check 6).

Cause: n/a. A hold states no cause.

## To the owner

- The freeze id. The lead confirms `1a76d225bcf1aa0c3145755138f577716bfae5d1` at review,
  under the owner's rule for this campaign. Until then the hold is quoted as a rehearsal
  hold, and it is no hold under the owner's freeze (OQ-1 of #297).
- The control's build. The judge's control receipt is of build `3689c1ea48e9`. At the
  hold's build, only the sweep's own control counts show that the corrupted plant is
  still caught. A control run at build `3b9e5e9f1598` would add a judge receipt for it:
  `systemd-run --user --scope -p Delegate=yes --unit=chaos-2082r-<run-id> -- bash
  /data/tsw/campaigns/2082r/run-in-scope.sh ks-upload-no-fault <run-id> --control
  corrupted`, one run, expected `broken` on `ks-bound-record-passes-its-checks` with
  "a bound slot's record fails its header or chunk checks" in its detail. The contract
  asks for no such run.
- Who ran it. One identity ran the harness, wrote the receipts and checked the hold (check
  6).
- The claim file. `chaos/READINESS.md` as committed fails `--check-claim` (`claim:
  stale-claim: chaos/READINESS.md differs from the claim this contract renders`). It
  lists `ks-upload-no-fault` as open with one run of build `3689c1ea48e9`, so it quotes
  no hold of this scenario. It is to be rendered again before a hold is cited through it.
- A panel. The audit skill asks for two reviewers working alone before a hold is quoted
  outside the team. This report is one reviewer.

## Not checked

- The owner's own output of the freeze check: none exists. The freeze result above is
  this session's run in the checkout.
- Whether a run was removed together with its evidence and receipts: the validator cannot
  see it. `ls chaos/runs` holds the six earlier directories the log's session-start entry
  lists and the five of this campaign.
- Whether the sweep's classification of pass, caught and suspect is right: `campaign`
  and the simulation worker's checks are in `trusted_base`.

## Scope of this audit

This session ran the contract check, the vacuity check and `campaign sweep-status` on
copies of the two roots. It changed no repository file other than this report, started no
run and no sweep, set no status, and removed both scratch worktrees
(`$TMPDIR/audit-hold-upload`, `$TMPDIR/audit-hold-upload-freeze`) and the copied roots.
The checkout held the coordinator's uncommitted edits under `chaos/loop/` while this audit
ran. They touch no file under `chaos/runs/`, `chaos/receipts/` or the ledger, and this
session left them as they were.
