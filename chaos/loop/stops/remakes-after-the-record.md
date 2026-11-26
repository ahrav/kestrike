# Stop: the frozen paths changed after the rehearsal of record, and its seven runs were made again twice under their run ids

Rehearsal of record of #304, under the rehearsal freeze
`1a76d225bcf1aa0c3145755138f577716bfae5d1`. Request: confirm the retirement of fourteen run
and receipt pairs, made after the contract changed under that freeze. Found by the review
of pull request blotter pull request 2126 at 2026-11-24T19:39Z, after the campaign's end and after both
retirements.

## The finding

After the rehearsal of record ended, the review loops of #302 and blotter pull request 2116 changed three
files under `frozen_paths`, and `main` changed a fourth. Two things follow.

**The contract changed after the rehearsal freeze.** `chaos/harness/run_scenario.py`,
`chaos/judges/core/common.py` and `chaos/judges/core/validity.py` changed at #302's commit
`dc6fc3ba0` and blotter pull request 2116's commit `fd691f4a7`; `chaos/project.yaml` changed at `main`'s blotter pull request 2165
(the atomic-unit line of `differs_from_production`). The hold audits pin the first three at
the freeze (`chaos/loop/audits/hold-ks-cluster-link-faults.md`, check 3), and every receipt
in the tree now names their later digests. At commit `6cffb0a49`, the contract check with
`--freeze-commit 1a76d225bcf1aa0c3145755138f577716bfae5d1` and
`--build 7899890b4d5f811d6efe62f35980e91f2d87ae46e8661d9ed36404eb1106baf5` exits 1. It
prints 4 `frozen-path-changed` findings, one for each of those files, and 78
`stale-receipt` findings: three for each of the 26 receipts of the eleven runs, since each
receipt was produced by files that differ from the freeze's. `render_loop.py` runs that
check first, so with this freeze id it exits 1 and renders no brief, and the hold check
of `docs/agents/chaos.md` ("Statuses") cannot pass. The contract check without the freeze
id prints nothing and exits 0.

**The seven runs were made again twice under their run ids.** Each change made the 16
receipts of `record-escape-live`, `record-escape-judged-open`, `record-loop-1`,
`record-upload-1`, `record-upload-2`, `record-cluster-1` and `record-cluster-2` stale.

| Made again | Decision of the workstream's lead | Merge | Runs (UTC, 2026-11-24) | Commit | Build | Retired pairs stand at |
| --- | --- | --- | --- | --- | --- | --- |
| first | L166 | `e15750fc4` (#302's `316efc5a8`) | 07:38:36Z to 07:52:58Z | `e908959ed` | `43209a6be9d4` | `caded992b`, build `3b9e5e9f1598` |
| second | L195 | `4f693c6e6` (blotter pull request 2116's `111b017f7`) and `1c668a88a` | 13:46:08Z to 14:00:29Z | `73c936f73` | `7899890b4d5f` | `6703ba74d`, build `43209a6be9d4` |

Each time the seven evidence directories and the seven receipt directories of the earlier
build left the tree before the runs started, since the harness refuses a run id whose run
or receipt directory exists (fence `ks-run-keeps-earlier-runs`). That is fourteen run and
receipt pairs. The runs the audits, the finding and the final report describe, of build
`3b9e5e9f1598`, stand at commit `caded992b` and no longer in the tree.

`docs/agents/chaos.md`, "When the receipts of record are made again", asks for a stop
note pushed before the change, an answer of the owner or of the person a recorded owner
delegation names, and new run ids. Each step had a decision of the workstream's lead,
which `chaos/loop/log.md` names in its amendments of 08:05Z and 14:05Z, and #304 says
under "Resolved: receipts of record" that this unit's session makes its runs, receipts
and claim again when a later change to the harness or a judge lands. The repository
records no owner delegation that names the lead for a retirement, no stop note preceded
commit `e908959ed` or `73c936f73`, and both steps kept the run ids. The validator cannot
see a pair whose evidence and receipts left the tree together, so the git history at the
two commits in the table is the one record of the fourteen pairs.

`docs/agents/chaos.md`, "Run a scenario", asks for the fence check before the first run
of a session. The log records none before the sweeps of 07:38Z or of 13:46Z, and the
worker's records of those two steps hold no probe log. The four credential fence receipts
in the tree are the probes of 04:42:53Z to 04:42:56Z, on the same worker, and the harness
fence's receipt is blotter pull request 2116's probe at `fd691f4a7`. A probe made after the fact shows a
refusal at its own time and nothing about 07:38Z or 13:46Z, so this step made none.

The verdicts match at all three builds: `record-escape-live` and `record-loop-1` hold
`ks-escape-2075` and break `ks-no-fill-admitted-after-close`, the control of
`record-escape-judged-open` breaks it with none missed, and the upload and cluster runs
hold their rows (`chaos/loop/log.md`, both amendments). The audits, the finding, the final
report and the stop notes `2075-fix.md` and `rehearsal-freeze.md` describe the pairs of
build `3b9e5e9f1598`, and each now names commit `caded992b`.

## Options

1. **Confirm both retirements as made.** The runs of build `7899890b4d5f` keep the seven
   ids as the receipts of record, and the rehearsal's holds and audits count for the
   records at `caded992b` only. The confirmation also accepts seven runs whose session
   made no fence check before its first sweep. Undo: restore the seven pairs from
   `caded992b` or from `6703ba74d`, which brings back a `stale-receipt` finding for each
   of their 16 receipts.
2. **Restore the audited pairs and give the later runs new ids.** A run id stands in
   `run.json` and in each receipt, so this takes seven more sweeps, about 15 minutes on
   this worker, after the fence check of their session. They wait for the owner's answer
   to A1 of `chaos/interview.md`. The
   restored receipts are stale against the merged judges, so the contract check reports
   them until the owner retires them again. Undo: remove the new runs and the restored
   pairs.

## Recommendation

Option 1. The audited evidence stays readable at `caded992b`, the verdicts agree at every
build, and the receipts in the tree are current against `main`'s harness and judges. The
answer is the owner's: the validator's messages say to remove or retire a run only with
the owner. A hold under a freeze needs a freeze at or after `main`'s current harness and
judges, which is the owner's to name (OQ-1 of #297).

## Answer

Option 1, confirmed on the owner's behalf on 25 November 2026. The owner's words to its
delegate, at about 06:14 UTC of that day: "the rest is your call". The confirmation is the
workstream's lead's (decision L271), made outside the sessions in the owner's place under
the owner's delegation of that day. The lead relayed the confirmation and the owner's
words to the session that wrote this section, and the repository holds no other record of
them; the owner did not write this answer.

Both retirements stand as made. The runs of build `7899890b4d5f` held the seven ids as the
receipts of record until the replacements of the pull request that carries this answer.
The audited pairs of build `3b9e5e9f1598` stand at `caded992b`, and those of build
`43209a6be9d4` at `6703ba74d`.

The reasons are this note's own: the verdicts agree at all three builds, the receipts in
the tree were current against `main`'s harness and judges, and Option 2 would bring sixteen
stale receipts back.

The confirmation accepts two things as they happened: seven runs whose session made its
first sweep ahead of a fence check, and two steps that kept the run ids and had their stop
note written after them.

Its condition: from this answer on, the guide's order holds for every remake. The stop
note comes first, then the answer, then the session's fence check, then the runs under new
run ids (`docs/agents/chaos.md`, "When the receipts of record are made again" and "Run a
scenario").

The ruling of the workstream's lead that goes with it (decision L271): the pull request
that carries this answer makes the four other runs of record again as well,
`record-upload-1`, `record-upload-2`, `record-cluster-1` and `record-cluster-2`, after its
session's fence check, so that every receipt of the record comes from a session that
checked the fences first. `chaos/loop/stops/escape-restoration-text.md` names the eleven
runs that pull request makes again and the pairs it retires.

Note of 2026-11-25T07:35Z: the replacements are `record-escape-live-1125b`,
`record-escape-judged-open-1125b`, `record-loop-1-1125b`, `record-upload-1-1125b`,
`record-upload-2-1125b`, `record-cluster-1-1125b` and `record-cluster-2-1125b`, of build
`c948fcfa86a0`, each with the verdicts of the run it replaces (`chaos/loop/log.md`,
amendment of 2026-11-25T07:35Z). The runs of build `7899890b4d5f` stand at commit
`5755aacea`.
