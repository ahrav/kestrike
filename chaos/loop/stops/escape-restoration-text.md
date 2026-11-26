# Stop: the restoration text of three scenario rows says less than the harness records

Rehearsal of record of #304, under the rehearsal freeze
`1a76d225bcf1aa0c3145755138f577716bfae5d1`. Request: amend three scenario rows, one
sentence of an invariant row and one docstring clause of a judge, which makes receipts
stale. Found for the row `ks-escape-2075`
by the review of pull request blotter pull request 2126 at 2026-11-24T19:39Z, after the campaign's end. Written
again on 2026-11-25 to name the rows `ks-reach-required-events` and `ks-ordering-figure`,
which carry the same sentence, the docstring clause and the control sentence of
`ks-required-events-reached` that go with them, the seven runs the change makes stale, and
the four other runs of the rehearsal's record, which the answer has made again with them. Commit `0003afb72` holds the first text, which named the one row
and its three runs.

## The finding

The rows `ks-escape-2075`, `ks-reach-required-events` and `ks-ordering-figure` of
`chaos/ledger.json` each say in `restoration`: "The harness records in run.json
left_a_process 0, no process found in the sweep's worker cgroups at its end, and
archive_verified true, the sweep's own verification of the archive after its last run, and
the validity judge requires both."

The harness at the head records more than that sentence says. `chaos/harness/run_scenario.py`
counts the processes in the worker groups the run's sweep made, adds the groups
`campaign confirm` made, and after the last command adds every other group under the
cgroup root: "So left_a_process counts every cgroup under the root". The rows
`ks-upload-no-fault` and `ks-cluster-link-faults` state that count, and they state how
`archive_verified` is read: `campaign sweep`'s return with exit 0, or with its verdict
exit 1 for alarm, no_pass or unreached. blotter pull request 2116 gave those two rows that text with its
harness change `fd691f4a7`; these three rows carry the wording from before it.

The verdicts stand. Each family's validity judge reads `restored.left_a_process` and
`restored.archive_verified` from `run.json` and no sentence of a row
(`chaos/judges/core/common.py`, "restoration not shown"), and the seven runs below record
0 and true. The rows' sentence is true of them and narrower than the record: no process
in any cgroup under the root includes no process in the sweep's worker groups.

## The change

1. The `restoration` text of `ks-escape-2075`, of `ks-reach-required-events` and of
   `ks-ordering-figure` becomes the `restoration` text of `ks-upload-no-fault`, word for
   word. No other field of a row changes, and no status.
2. The docstring of `chaos/judges/ordering/figure.py` says of `figure_rounding`: "at most
   nine fraction digits, as the lead's ruling L097 sets, so no value serializes with twelve
   digits in a row". The clause "as the lead's ruling L097 sets," leaves, so the sentence
   names no ruling. It keeps its one rule of nine fraction digits, where `written` of that
   file writes nine significant digits below 0.0001; the docstring states that with the
   next change that makes the ordering runs again. No other byte of a judge or of the harness
   changes.
3. `control.how` of the invariant row `ks-required-events-reached` says that the control's
   campaign binary is built "in a scratch copy of commit
   b987797454fd7c422d8cec2a516410d1acf0a3df, whose crates/campaign-supervisor the witness's
   binary was built from". At `main`'s head `crates/campaign-supervisor` differs from that
   commit's in nine files, so a witness whose binary is built at the head and a control
   built from that commit would differ by more than the one change to `required.rs`, which
   is byte-equal at both. The sentence comes to name no commit id: the control's binary is
   built in a scratch copy of the commit the witness's binary was built from, with the one
   change to `crates/campaign-supervisor/src/campaign/seeds/required.rs`, and the dated note
   of the run in `chaos/loop/log.md` names that commit. The sentence then holds at any later
   remake. No other field of the row changes.

## The runs whose receipts go stale

The digest of a scenario row covers `restoration`, and a receipt names the SHA-256 of each
judge file of its family. The change makes the fourteen receipts of these seven runs
stale, two for each run, and the runs stop counting until they are made again:

| Scenario row | Run ids | Made stale by |
| --- | --- | --- |
| `ks-escape-2075` | `record-escape-live`, `record-escape-judged-open`, `record-loop-1` | the row's text |
| `ks-reach-required-events` | `reach-live`, `reach-control` | the row's text and `control.how` of its invariant `ks-required-events-reached` |
| `ks-ordering-figure` | `ordering-live-r7`, `ordering-premise-unmet-r7` | the row's text and the docstring clause |

The eight other runs under `chaos/runs/` name none of these rows, `ks-required-events-reached`
included, and no file of `chaos/judges/ordering/`, so their receipts stay current.

## The four other runs of the record

The rehearsal's record is seven runs: the three of `ks-escape-2075` above, and
`record-upload-1`, `record-upload-2` (`ks-upload-no-fault`) and `record-cluster-1`,
`record-cluster-2` (`ks-cluster-link-faults`). The rows of these four stay as they are and
their ten receipts are current. `chaos/loop/stops/remakes-after-the-record.md` states that
the session which made the seven runs recorded no fence check before its first sweep. The
answer below has these four made again beside the three, so that all seven runs of the
record come from one session that checked the fences first and from one archive.

The eleven runs this note names, which the answer lets the session make again:
`record-escape-live`, `record-escape-judged-open`, `record-loop-1`, `record-upload-1`,
`record-upload-2`, `record-cluster-1`, `record-cluster-2`, `reach-live`, `reach-control`,
`ordering-live-r7` and `ordering-premise-unmet-r7`.

## Options

1. **Amend the text with the next change that makes these runs again.** Copy the
   `restoration` text of `ks-upload-no-fault` into the three rows in the commit that next
   changes a judge, the harness or one of these rows, and make the seven runs again once,
   as `docs/agents/chaos.md`, "When the receipts of record are made again", describes.
   Undo: restore the sentence, the clause and the seven pairs.
2. **Amend it now.** Five sweeps of about 123 s each and two of about 603 s on this
   worker, and a new render of the claim, after the owner's answer to A1. The answer to
   this option also covers retiring the seven pairs in the commit that adds their
   replacements. Undo: the same.
3. **Keep it.** The verdicts are unaffected, and the three rows describe their restoration
   record in fewer words than their two siblings.

## Recommendation

Option 1, before the owner's freeze. After the freeze the edit is a frozen-row change,
which stops for the owner in any case. The answer is the owner's:
`chaos/approval-policy.md` stops a change to a scenario row's frozen fields for the
owner once a freeze stands, and the retirement of a run is the owner's.

## Answer

Option 2, for the three rows `ks-escape-2075`, `ks-reach-required-events` and
`ks-ordering-figure`, with the docstring clause and the control sentence of
`ks-required-events-reached` that "The change" states as its items 2 and 3. Item 3 makes
stale only receipts of `reach-live` and `reach-control`, which item 1 makes stale as well,
so it adds no run to the eleven below.

The answer lets the session retire exactly these eleven run and receipt pairs, in the
commit that adds their replacements under new run ids: the seven whose receipts the change
makes stale, `record-escape-live`, `record-escape-judged-open`, `record-loop-1`,
`reach-live`, `reach-control`, `ordering-live-r7` and `ordering-premise-unmet-r7`, and the
four other runs of the record, `record-upload-1`, `record-upload-2`, `record-cluster-1`
and `record-cluster-2`. It covers no other run. Each replacement's verdict is to equal the
verdict of the run it replaces, and a run whose verdict differs keeps its pair in the tree
until the lead rules. The session checks the fences before its first sweep, as
`docs/agents/chaos.md`, "Run a scenario", asks, and makes the eleven runs on archives built
at its branch's head.

This is the answer of the workstream's lead (decisions L269 and L271, and L274 for item 3
of "The change"), made outside the sessions under the owner's delegation of 25 November
2026, by which the owner gave this answer to the workstream's lead. It is no freeze of the
owner's, and it changes no status.

## Carried out

Commit `bba1b428a` holds the change. The eleven runs were made again on 2026-11-25 from
06:51Z to 07:29Z, after the session's fence check of 06:33Z, and each new verdict equals
the verdict of the run it replaces (`chaos/loop/log.md`, amendment of 2026-11-25T07:35Z):

| Retired, at commit `5755aacea` | Replacement |
| --- | --- |
| `record-escape-live` | `record-escape-live-1125b` |
| `record-escape-judged-open` | `record-escape-judged-open-1125b` |
| `record-loop-1` | `record-loop-1-1125b` |
| `record-upload-1` | `record-upload-1-1125b` |
| `record-upload-2` | `record-upload-2-1125b` |
| `record-cluster-1` | `record-cluster-1-1125b` |
| `record-cluster-2` | `record-cluster-2-1125b` |
| `reach-live` | `reach-live-1125b` |
| `reach-control` | `reach-control-1125b` |
| `ordering-live-r7` | `ordering-live-1125b` |
| `ordering-premise-unmet-r7` | `ordering-premise-unmet-1125b` |
