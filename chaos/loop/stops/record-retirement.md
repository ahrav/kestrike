# Stop: the rehearsal of record retired three interim runs and four earlier copies

Rehearsal of record of #304, under the rehearsal freeze
`1a76d225bcf1aa0c3145755138f577716bfae5d1`. Request: confirm the retirement of run and
receipt pairs made before that freeze. Written by the step `2082-record` after the
retirement.

## The finding

Two commits of this step took run and receipt pairs out of the tree before the freeze:

- The merge `a308ae838` of blotter issue 2080's final head (`93316e397`) took blotter issue 2080's side for its four
  runs of record, `upload-live`, `upload-corrupted`, `cluster-live` and
  `cluster-stale-read`. It replaced this chain's interim copies of them, made at the merge
  of `main` `686c3597b` (build `0153f79d6397`), with blotter issue 2080's runs of build `3689c1ea48e9`.
  The interim copies stand at commit `981c9d811`.
- Commit `cb9ad932154b5569783cc0e5bc64ba09dcd40d36` amended the rows of `ks-escape-2075`
  and `ks-no-fill-admitted-after-close`, which made every receipt of `escape-live`,
  `escape-judged-open` and `loop-escape-1` stale (`row-changed-after-run`,
  `stale-receipt`), and removed those three pairs. The interim copies of build
  `a1875b9eafec` stand at commit `981c9d811`, and the first pass's runs of build
  `9e1936bceaef` at commit `74b137023`.

The replacements are the enrollment runs `record-escape-live` and
`record-escape-judged-open`, made under the amended rows on one archive built at
`cb9ad9321` (build `3b9e5e9f1598`). Both retirements rest on rulings of the workstream's
lead: the answer to `2082-c05-main-merge` (2026-11-24 01:42 UTC, "take its records whole
for the files it and #302 own and drop yours for them") and decisions L056, L067 and L127,
which added this step and its row changes. `docs/agents/chaos.md` ("When the receipts of
record are made again") asks for the owner's answer before a retirement and a stop note
before the commit that makes receipts stale; this note follows the commits.

Note of 2026-11-25, added with the runs of record made again that day: the runs of
`ks-escape-2075` in the tree are now `record-escape-live-1125b`,
`record-escape-judged-open-1125b` and `record-loop-1-1125b`, of build `c948fcfa86a0`
(`chaos/loop/log.md`, amendment of 2026-11-25;
`chaos/loop/stops/escape-restoration-text.md`).
The enrollment runs this note describes, of build `3b9e5e9f1598`, stand at commit
`caded992b`. The runs that held the ids `record-escape-live` and
`record-escape-judged-open` last, of build `7899890b4d5f`, stand at commit `5755aacea`.

## Options

1. **Confirm the retirement.** The tree keeps the replacements, and the retired pairs stay
   in the branch's history at the commits named above. Undo: restore the pairs from those
   commits, which brings back their `stale-receipt` findings.
2. **Restore the retired pairs beside the replacements.** The contract check reports
   `row-changed-after-run` and `stale-receipt` for each, renders no claim, and the
   pre-push check refuses the push, so the restored records stand only on a branch the
   owner reads. Undo: remove them again.

## Recommendation

Option 1. The retired pairs bind rows, judges or harness files that no longer stand, and
each verdict they carried is carried again by a run of the current rows and judges.

## Answer

Option 1, confirmed on the owner's behalf on 25 November 2026. The owner's words to its
delegate, at about 06:14 UTC of that day: "the rest is your call". The confirmation is the
owner's delegate's (the delegate's notice 050), made outside the sessions in the owner's
place under those words. It approves an act on the rehearsal's records. The workstream's
lead relayed the confirmation and the owner's words to the session that wrote this section
(decisions L280 and L281), and the repository holds no other record of them; the owner did
not write this answer.

The tree keeps the replacements, and the retired pairs stay at `981c9d811` and
`74b137023`, as this note names them. Each verdict they carried is carried by a run of
the rows and judges that stand.

This note was written after the two commits it asks about, `a308ae838` and `cb9ad9321`.
The confirmation accepts that for those two commits and for no later one
(`docs/agents/chaos.md`, "When the receipts of record are made again").

Undo, as option 1 states it: restore the pairs from those commits, which brings back
their `stale-receipt` findings.
