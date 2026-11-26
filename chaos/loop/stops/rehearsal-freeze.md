# Stop: the holds of ks-upload-no-fault and ks-cluster-link-faults wait on the rehearsal freeze

Rehearsal of record of #304, under the rehearsal freeze
`1a76d225bcf1aa0c3145755138f577716bfae5d1`. Request: confirm the freeze, an item that
`chaos/approval-policy.md` stops for the owner ("the freeze: the merge that fixes the
contract, named by its full commit id"). Corrected at 2026-11-24T20:00Z by the review of
pull request blotter pull request 2126: option 1 now says for which records the holds stand, and commit
`6cffb0a49` holds the first text.

Note of 2026-11-25, added with the runs of record made again that day: the audits and the
holds below are of the runs of build `3b9e5e9f1598` at commit `caded992b`, and they count
for those runs alone. The four runs these holds name are replaced in the tree by
`record-upload-1-1125b`, `record-upload-2-1125b`, `record-cluster-1-1125b` and
`record-cluster-2-1125b`, of build `c948fcfa86a0`, with the same verdicts and no hold of
their own. blotter issue 2080's runs `upload-live`, `upload-corrupted`, `cluster-live` and
`cluster-stale-read`, of build `9277dc4c7c8f`, stay beside them
(`chaos/loop/log.md`, amendment of 2026-11-25;
`chaos/loop/stops/escape-restoration-text.md`).

## The finding

The hold audits of both scenarios returned needs-owner:
`chaos/loop/audits/hold-ks-upload-no-fault.md` (runs `record-upload-1` and
`record-upload-2`) and `chaos/loop/audits/hold-ks-cluster-link-faults.md` (runs
`record-cluster-1` and `record-cluster-2`), both at build `3b9e5e9f1598`. Every check of a
hold passed on the files: the contract check with `--build` and `--freeze-commit` exits 0 and
prints nothing with each scenario set `held` in a scratch copy, the evidence digests match
the receipts, and the judges refuse empty evidence. The one open item is the freeze. The
step `2082-record` recorded it by the rule the owner gave for #304 (the first commit of the
branch that holds the enrolled escape and at which the first gate command prints nothing),
and the workstream's lead confirms it at review. The audit skill counts a freeze that the
campaign chose as no freeze, so neither hold is quoted as held. Both audits also state that
the invariants' control receipts are of build `3689c1ea48e9`, and that one identity ran the
harness, wrote the receipts and checked the holds.

## Options

1. **Confirm `1a76d225bcf1aa0c3145755138f577716bfae5d1` as the rehearsal's freeze.** Both
   audits then read accept for the records at commit `caded992b`, and the holds stand as
   rehearsal holds of build `3b9e5e9f1598` for those records only, in the log only. The
   tree at the head gives them no hold: the harness and two judge files changed after this
   freeze and the seven runs were made again, so the contract check with this freeze id
   exits 1 there (`chaos/loop/stops/remakes-after-the-record.md`). A hold of the runs in
   the tree needs a freeze at or after those changes and its own hold check. Undo:
   withdraw the confirmation.
2. **Name another freeze.** The holds are checked again under it; a freeze at which the
   rows or the judges differ makes the runs stale, and the runs are made again. Undo: name
   this freeze.

## Recommendation

Option 1. The commit meets the stated rule: the gate prints nothing there, and it prints
findings at its parent `f69ee42b5` and at `cb9ad9321`, the commit of the amended rows.

## Answer

Option 1, confirmed on the owner's behalf on 25 November 2026. The owner's words to its
delegate, at about 06:14 UTC of that day: "the rest is your call". The confirmation is the
owner's delegate's (the delegate's notice 050), made outside the sessions in the owner's
place under those words. It approves an act on the rehearsal's records. The workstream's
lead relayed the confirmation and the owner's words to the session that wrote this section
(decisions L280 and L281), and the repository holds no other record of them; the owner did
not write this answer.

`1a76d225bcf1aa0c3145755138f577716bfae5d1` is the rehearsal's freeze. The holds of
`ks-upload-no-fault` and `ks-cluster-link-faults` stand as rehearsal holds of build
`3b9e5e9f1598` for the records at commit `caded992b`, in the log. The tree at the head
gets its hold from the freeze that the merge of pull request blotter pull request 2230 makes, the pull request
that carries this answer (`chaos/interview.md`, the ruling on OQ-1), and from a hold check
of its own.

Undo, as option 1 states it: withdraw the confirmation.
