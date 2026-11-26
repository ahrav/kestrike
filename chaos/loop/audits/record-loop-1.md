# Chaos finding audit: ks-escape-2075, record-loop-1

Note of 2026-11-24T20:00Z, added after the review of pull request blotter pull request 2126 and no part of
the auditor's report: the run figures, digests and receipts in this record are those of
build `3b9e5e9f1598`, which stand at commit `caded992b`. `chaos/runs/` and
`chaos/receipts/` then held runs of build `7899890b4d5f` under the same ids, with the same
verdicts (`chaos/loop/log.md`, amendment of 2026-11-24T14:05Z;
`chaos/loop/stops/remakes-after-the-record.md`).

Note of 2026-11-25, added with the runs of record made again that day and no part of
the auditor's report: the runs of build `7899890b4d5f` stand at commit `5755aacea`.
`chaos/runs/` and `chaos/receipts/` now hold their replacements of build `c948fcfa86a0`
under new ids, `record-loop-1-1125b`, `record-escape-live-1125b` and
`record-escape-judged-open-1125b`, with the same verdicts
(`chaos/loop/log.md`, amendment of 2026-11-25;
`chaos/loop/stops/escape-restoration-text.md`).

```text
Item type: break        Starts from: the receipts of run record-loop-1
Contract: chaos/ at rehearsal freeze 1a76d225bcf1aa0c3145755138f577716bfae5d1 (named by the
          coordinator's item; no owner's freeze exists for this rehearsal)
Validator: exit 1 at 2026-11-24T04:47:54Z; findings on the item: none; the one line printed was
           "record-upload-1: incomplete-receipts: the run has a receipt directory and no receipt;
           judge its evidence", about a run of ks-upload-no-fault that was still being judged
           (its receipts appeared untracked minutes later); flags left out: none
Build on the copy: 3b9e5e9f1598aa6f593107750d9770f3ba5c9ad6fa1385603e1b89cff156c6a5, from the
           coordinator's item and from chaos/runs/record-loop-1/run.json (system_build,
           root_build, archive_build_after); the owner's word on it was not available
Verdict: accept
```

The auditor is a worker session with its own context. It wrote none of the history, the
harness, the judges or the run. It started no run and changed no file other than this
report.

## Checks

| Check | Result | Evidence (command and decisive output, or file and field) |
| --- | --- | --- |
| 1. The run counts | pass | `chaos/receipts/record-loop-1/ks-no-fill-admitted-after-close.json`: `key.mode` `live`, `key.outcome` `broken`, `key.defect` "", `key.row` `ks-no-fill-admitted-after-close`, which is the only invariant of the scenario row `ks-escape-2075` (`chaos/ledger.json`, `invariants`). `run.json`: `mode` `live`, `defect` "", `complete` true. The validator printed no `inconsistent-receipts`, `malformed-run`, `duplicate-evidence`, `incomplete-receipts`, `receipts-without-run`, `stale-receipt` or `row-changed-after-run` line against record-loop-1. By hand: `sha256sum chaos/runs/record-loop-1/*` equals each digest of `key.evidence` in both receipts; `sha256sum chaos/judges/core/*.py chaos/harness/*.py` equals `key.judge` and `key.harness`, and `git show 1a76d225b:<file> \| sha256sum` gives the same five digests; `git diff --quiet 1a76d225b -- chaos/harness chaos/judges chaos/project.yaml chaos/approval-policy.md` exits 0; the two ledger rows equal the freeze's rows in every field except `status` (`broken` at both). |
| 2. The evidence shows it | pass | The judge took its path (b): a history of the scenario whose listing declares exactly the row's violation and whose `caught_rules` counts caught runs under the row's text (`chaos/judges/core/invariant.py`, `decide`). Recomputed from the evidence: `run.json` `listing["k9-placement-across-close"]["fails"]` = "violation 2 a fill admitted after the cache closed", which is the row's `witness.obligation` 2 and `control.expect`. `sweep-status.json` `profiles["k9-placement-across-close"]`: `runs` 609978, `caught` 609978, `caught_rules` {"a fill admitted after the cache closed": 609978}, `pass` 0, `missed` 0, `replays` 48. This equals the receipt's detail ("caught 609978 times under the row's rule"). Path (a) was not used: `suspects.jsonl` is empty, `suspect_keys` is {} and `findings.json` holds no finding. The root's own records agree: `campaign sweep-status --root /data/tsw/campaigns/2082r/record-loop-1` (binary SHA-256 52cff29a..., the same as `run.json` `campaign_binary.sha256`) differs from the evidence copy only in the field `busy_us`, which the harness drops as a wall-clock key (`chaos/harness/run_scenario.py` line 96, `WALL_CLOCK_KEYS`). No operation without an answer is involved: the violation is the history's own check of the cache's return value in one in-process world, not a lost or phantom write. |
| 3. The conditions were the row's | pass | `chaos/receipts/record-loop-1/ks-escape-2075.json`: `outcome` `held`, detail "valid: k9-placement-across-close 609978 caught of 500 required, 48 replays; k9-placement-across-storage-close 599132 pass of 500 required, 48 replays". `run.json`: `workers` 28, `batch_s` 30, `for_s` 120 (the row's `load`), `sweep_elapsed_s` 120.664, `deadline_fired` false, `signal` null, `sweep_exit` 0, `confirm_exit` 0, `restored` {`archive_verified` true, `left_a_process` 0, `cause` null}; the root `/data/tsw/campaigns/2082r/record-loop-1` is a new root under the run's own campaign name. The fault is `none` in the row, and `sweep-status.json` `faults_delivered` is 0. One difference from the row's words: the sweep also ran seven `h1-*` histories (74,347 runs, `h1-get` and `h1-put` passing, the five others caught under their own declared rules), beside the two profiles the command named. The enrollment runs `record-escape-live` and `record-escape-judged-open` show the same seven. Each history runs its own world, and the judge reads only the scenario's two profiles, so this changes neither profile's runs. |
| 4. The build | pass, with a note | Both receipts: `key.system_build` 3b9e5e9f1598aa6f593107750d9770f3ba5c9ad6fa1385603e1b89cff156c6a5; `run.json` `system_build`, `root_build` and `archive_build_after` are the same; the root's manifest `manifests/k9-placement-across-close.manifest` names `build = 3b9e5e9f...` and `executable = 34cdad78...`, which is `record.executable` in `/data/tsw/campaigns/2082r/archive/build`, whose provenance is `revision` cb9ad932154b5569783cc0e5bc64ba09dcd40d36, `dirty` false, `untracked` 0. This is the build on the copy now. Note: the only finding report in the tree, `chaos/loop/findings/2075-fill-admitted-after-close.md`, names run `loop-escape-1` and build 9e1936bceaef..., and neither is in the tree now. It is no report of this run. |
| 5. The fault's part | pass | The scenario's own `fault.kind` is `none`, so the break is under the load alone: a scripted history at default counts. The statement below names no fault. The passing twin in the same sweep, `k9-placement-across-storage-close`, replaces only the step `close` (`Owner::close`) by `close-storage` (the storage's own close) (`crates/kestrike/src/net/world_tests/histories/keyops.rs` at cb9ad932, `K9_ACROSS_STORAGE`), and passed 599132 of 599132 runs (`sweep-status.json` `profiles["k9-placement-across-storage-close"]`: `pass` 599132, `caught` 0). |
| 6. The count | pass | Live decided runs of `ks-escape-2075` at build 3b9e5e9f, from `chaos/receipts/*/`: `record-escape-live` (validity held; invariant broken, 613009 caught) and `record-loop-1` (validity held; invariant broken, 609978 caught). 2 of 2 broke. `record-escape-judged-open` is a control run (`mode` `control`, `defect` `k9-placement-judged-open`) and is not counted. The status `broken` in `chaos/ledger.json` fits. |

## What the history does, read at the archive's commit

The scenario row says the history reaches the defect "with no plant". Read in
`crates/kestrike/src/net/world_tests/histories/keyops.rs` at cb9ad932 (`git show
cb9ad932:<path>`), the pin's steps are `K9_ACROSS`:

1. `promise-placement`: `begin_fill` of key 2, `decide_admission` for two extents and
   `promise_storage`, kept with no extent placed; marks `PLACEMENT_PROMISED`.
2. `close` (`close_admission`): calls `Owner::close(now)` and marks `OWNER_CLOSED` once
   `Owner::quiesce()` returns `Some`.
3. `place-after-close`: `PlacingFill::place`, then `PlacingFill::reserve_storage(2, ..)`;
   `closed_placement_judged` fails the run under the rule when the answer is `Ok`, or when it
   is `Err(Closed)` and the storage's additional-key claims differ from those before the step.

Each call is to the cache's own code. The history is wrapped in `control(..., &[PLACEMENT_PROMISED,
OWNER_CLOSED])`, which counts a caught run only once both premises are marked
(`histories.rs`, `const fn control`). The table at the end of `keyops.rs` lists the history as
`Expect::Violation(Obligation::History, ADMITTED_CLOSED)`. A planted defect would be a step
that skips or replaces a cache call; the control `K9_JUDGED_OPEN` is that (the close replaced
by `removed_step`), and it is not in this run's profiles (`run.json` `profiles`).

The evidence holds counts by rule only. It does not say which of the two failing branches each
run took: the granted hold, or a `Closed` refusal that kept an additional-key claim. Both are
in the row's `oracle` text.

## Statement the evidence supports

At build 3b9e5e9f1598 (the simulation worker archived from cb9ad932, compiled under cfg(test)),
with no fault, the scripted history `k9-placement-across-close` ended in the violation "a fill
admitted after the cache closed" (obligation History) in 609,978 of 609,978 runs of
`record-loop-1` (28 workers, 120 s, 48 runs replayed), with both premises marked: a fill
promised before `Owner::close` was then placed, and the closed owner either granted its shard
hold or refused it `Closed` while keeping an additional-key claim. In the same sweep the twin
that closes the storage itself passed 599,132 of 599,132 runs. The scenario broke in 2 of 2
decided live runs at this build.

The archive's debug-assertion setting is not recorded in its `build` file. It is inferred
from the build command (`cargo test ... --no-run` with the dev profile and
`CARGO_PROFILE_DEV_OPT_LEVEL=3`, and no `debug-assertions` key in the workspace
`Cargo.toml` at cb9ad932), which leaves them on. A build without debug assertions was not run.

## Cause

Not shown. The run's evidence is counts by ending and rule; it holds no per-run record of the
steps. The module documentation of `keyops.rs` states a mechanism: `Owner::close` closes the
volume's readiness and leaves the storage's cutoff open, and the shard hold reads only the
cutoff. The twin's 599,132 passes, where only the close step differs, are consistent with it
and are support, not proof: no accepted fix whose diff removes that cause exists, and no run
record shows the hold reading the open cutoff. The break keeps its verdict without the cause.

## To the coordinator and the owner

- The finding report for this break still has to be written for this run. The file
  `chaos/loop/findings/2075-fill-admitted-after-close.md` cites run `loop-escape-1`, build
  9e1936bceaef and the earlier freeze 4626ec24; before it goes to the owner it should cite
  `record-loop-1` (and `record-escape-live`), build 3b9e5e9f1598, the rehearsal freeze
  1a76d225 and the counts above, in the form of `docs/agents/simulation.md`, "Report format".
- The row's validity asks for 500 caught runs of the pin while the worker's listing declares
  its violation, and 500 passing runs once the listing declares a pass
  (`chaos/judges/core/common.py`, `witnessed`). At a build where the defect is gone and the
  history still declares the violation, each run of the scenario would be invalid, never
  held. How a fix of #298 is shown `fixed` under this row, with or without a change of the
  history's declaration, is the owner's question for rule 8; it does not affect this break.
- The class of the finding is the owner's: the row's sources include
  `storage::readiness` ALLOCATION-READY, which the history's own documentation says reads the
  other way for this history (OQ-12 of #297, as `keyops.rs` and the earlier finding quote it).

## Not checked

- The freeze as the owner's: no owner's freeze exists; the rehearsal freeze came from the
  coordinator's item. A break needs none (check 2 recomputed against the row).
- Which failing branch the runs took: an in-process run of the history with a trace of the
  answer of `reserve_storage`, or a bundle saved by `campaign confirm`, would show it; the
  test `every_history_records_its_declared_failure` (`histories.rs` at cb9ad932) checks only
  the declared ending. The coordinator starts runs; none was started here.
- The effect without debug assertions: one sweep of the same row from an archive built
  without them would show it.
- `PlacingFill::retry`, a follower joined to the granted fill and a restart with the fill
  held: the history does not drive them.

## Audit hygiene

`git status --porcelain --untracked-files=all --ignored -- chaos` before writing this report
listed only the coordinator's untracked `chaos/runs/record-upload-1/`,
`chaos/receipts/record-upload-1/` and `chaos/runs/record-upload-2/run.json`. This session
wrote only `chaos/loop/audits/record-loop-1.md` and scratch files under `$TMPDIR/audit-rl1/`
and `$TMPDIR/keyops-cb9.rs`.

