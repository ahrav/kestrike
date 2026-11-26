# Stop: the merge of start-c05 changed the frozen paths, and three runs were made again under their run ids

Rehearsal campaign of #304, under the rehearsal freeze
`4626ec2457a1ce6fe2b376216a0503b2f917043c`. Request: confirm the retirement of three run
and receipt pairs, made after the contract changed under that freeze. Found by the review
of pull request blotter pull request 2126 at 2026-11-24T04:15Z, after the campaign's run and after the
retirement.

## The finding

The merge of `bsw/bsw-ct1/start-c05` (commit `d09a4bb92`) changed the judges, the harness,
`chaos/project.yaml` and `chaos/approval-policy.md`. Two things follow.

**The contract changed after the rehearsal freeze.** Since the merge, the contract check
with `--freeze-commit 4626ec2457a1ce6fe2b376216a0503b2f917043c` exits 1. At commit
`a50b03fce`, with `--build a1875b9eafecdf5b50a4e1cfa2cba56df40bc9e50caba5360adb10e3f077a9da`,
it prints 7 `frozen-path-changed` findings, 8 `frozen-row-changed` findings and 80
`stale-receipt` findings over the 16 receipts of the 7 runs. `render_loop.py` runs that
check first, so with this freeze id it exits 1 and renders no brief, and the hold check
of `docs/agents/chaos.md` ("Statuses") cannot pass. The contract check without the freeze
id prints nothing and exits 0.

**Three runs were made again under their run ids.** The merge made the receipts of
`escape-live`, `escape-judged-open` and `loop-escape-1` stale. Commit `a50b03fce` replaced
the evidence and receipts of those runs, of build `9e1936bceaef`, with runs of build
`a1875b9eafec` under the same ids. The earlier pairs stand at commit `74b137023`. The
harness refuses a run id whose run or receipt directory exists (fence
`ks-run-keeps-earlier-runs`), so the earlier directories left the tree before the three
runs started.

`docs/agents/chaos.md`, "When the receipts of record are made again", asks for a stop
note pushed before the change, an answer of the owner or of the person a recorded owner
delegation names, and new run ids. This step had the workstream's lead's ruling of
2026-11-24 02:58 UTC, which the worker holds at
`~/requests/2082-loop-runs-at-merge.answer.md`, outside the repository: "Do as you
propose: the three runs again with the same ids at the merge head as interim copies, the
dated note in `chaos/loop/log.md` that the audit, the finding and the final report
describe the earlier runs at build `9e1936bceaef` (evidence in the branch's history at
`74b137023`), the claim rendered, the short checks, the push. `2082-record` makes the
rehearsal of record on blotter issue 2080's final head. Make them once here and not again in this
step." The repository records no owner delegation that names the lead for a retirement,
and no stop note preceded commit `a50b03fce`.

The verdicts match at both builds: both live runs hold `ks-escape-2075` and break
`ks-no-fill-admitted-after-close`, and the control breaks it (`chaos/loop/log.md`,
amendment of 2026-11-24T03:10Z). The audit, the finding, the final report and the stop
notes `2075-fix.md` and `oracle-text.md` describe the earlier pairs, and each names
commit `74b137023`.

## Options

1. **Confirm the retirement as made.** The interim runs keep the three ids until the
   step that runs the rehearsal of record replaces them under its own freeze, with new
   run ids and a stop note pushed first, as the guide asks. Undo: restore the three pairs
   from `74b137023`, which brings back a `stale-receipt` finding for each of their six
   receipts.
2. **Restore the earlier pairs now and give the interim runs new ids.** A run id stands
   in `run.json` and in each receipt, so this takes three more sweeps, against the lead's
   "not again in this step". The restored receipts are stale against the merged judges,
   so the contract check reports them until the owner retires them again. Undo: remove
   the three new runs and the restored pairs.

## Recommendation

Option 1. The earlier evidence stays readable at `74b137023`, the verdicts agree, and the
rehearsal of record replaces the interim runs under a freeze of its own. The answer is
the owner's: the validator's messages say to remove or retire a run only with the owner.

## Answer

Option 1, confirmed on the owner's behalf on 25 November 2026. The owner's words to its
delegate, at about 06:14 UTC of that day: "the rest is your call". The confirmation is the
owner's delegate's (the delegate's notice 050), made outside the sessions in the owner's
place under those words. It approves an act on the rehearsal's records. The workstream's
lead relayed the confirmation and the owner's words to the session that wrote this section
(decisions L280 and L281), and the repository holds no other record of them; the owner did
not write this answer.

The retirement stands as made, and the earlier pairs stay at `74b137023`.

This note was written after the commit it asks about, `a50b03fce`. The confirmation
accepts that for that commit and for no later one (`docs/agents/chaos.md`, "When the
receipts of record are made again").

Undo, as option 1 states it: restore the three pairs from `74b137023`, which brings back
a `stale-receipt` finding for each of their six receipts.
