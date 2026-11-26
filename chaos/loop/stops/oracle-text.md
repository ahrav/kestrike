# Stop: the oracle text of ks-no-fill-admitted-after-close overstates when the check fails

Rehearsal campaign of #304, under the rehearsal freeze
`4626ec2457a1ce6fe2b376216a0503b2f917043c`. Request: the invariant or its number is wrong.
Found by the pre-PR review of #304 (doc-verify), after the campaign's run. Corrected at
2026-11-24T04:15Z by the review of pull request blotter pull request 2126: the check has a second failing
case, which the finding and option 1 now state; commit `74b137023` holds the first text.

## The finding

The row's `oracle` says the history's check "fails the run through the rule text when the
closed cache grants either" the placement or the shard hold. In
`crates/kestrike/src/net/world_tests/histories/keyops.rs`, `place_after_close` and
`closed_placement_judged` fail the run through the rule in two cases: the placement
answers `Ok(true)` and `PlacingFill::reserve_storage` then answers `Ok`, or the placement
or the hold answers `Closed` and the storage's additional-key claims differ from their
count before the step. A `Closed` with the claims as they stood passes. The module
documentation agrees: "the closed owner must refuse the placement or the hold `Closed`",
and the check "fails a `Closed` that kept a claim through the same rule". The verdicts
stand: the judge reads only the rule text and the obligation, and run `loop-escape-1`'s
receipts and its audit (`chaos/loop/audits/loop-escape-1.md`) rest on the counts, not on
this sentence. Those receipts are the ones of build `9e1936bceaef` at commit `74b137023`;
`chaos/receipts/loop-escape-1/` now holds an interim run of build `a1875b9eafec` under
the same id, with the same verdicts (`chaos/loop/log.md`, amendment of
2026-11-24T03:10Z). The text is a frozen row, so the loop changes none of it.

## Options

1. **Amend the text at the rehearsal of record:** "it fails the run through the rule text
   when the closed cache grants the placement and then the shard hold, or refuses either
   `Closed` and keeps an additional-key claim". The row digest
   changes, so the invariant receipts `ks-no-fill-admitted-after-close.json` of
   `escape-live`, `escape-judged-open` and `loop-escape-1` go stale and those three runs
   stop counting. That step records the live and control runs again under its new
   freeze, as it does anyway, and the owner's answer to this option also covers retiring
   the three runs in the commit that adds their replacements. Undo: restore the sentence
   and the three runs with their receipts.
2. **Amend it now:** a new freeze and three more sweeps in this step, against the lead's
   limit of two or three runs, with the same three runs going stale and the same
   retirement. Undo: the same.
3. **Keep it:** the verdicts are unaffected, and the row misdescribes its oracle.

## Recommendation

Option 1. The answer is the owner's: `chaos/approval-policy.md` stops a change to an
invariant for the owner. The workstream's lead's decision L067 of 2026-11-23 22:52 UTC,
recorded in the section "For the lead" of pull request blotter pull request 2126, places the amendment in the
step that runs the rehearsal of record.

## Made at the rehearsal of record

Commit `cb9ad932154b5569783cc0e5bc64ba09dcd40d36`, before the rehearsal freeze
`1a76d225bcf1aa0c3145755138f577716bfae5d1`, made option 1 by the workstream's lead's
decision L067: the `oracle` now says the check fails "when the closed cache grants the
placement and then the shard hold, or refuses either Closed and keeps an additional-key
claim". The same commit retired the three interim runs, and the enrollment runs of record
`record-escape-live` and `record-escape-judged-open` were made under the amended row.

Note of 2026-11-25, added with the runs of record made again that day: the runs of
`ks-escape-2075` in the tree are now `record-escape-live-1125b`,
`record-escape-judged-open-1125b` and `record-loop-1-1125b`, of build `c948fcfa86a0`, made
under the same amended `oracle` text (`chaos/loop/log.md`, amendment of 2026-11-25;
`chaos/loop/stops/escape-restoration-text.md`).

## Answer

Option 1, confirmed as made, on 25 November 2026. The amended `oracle` sentence of
`ks-no-fill-admitted-after-close` (commit `cb9ad9321`) stands: the check fails the run
when the closed cache grants the placement and then the shard hold, or refuses either
`Closed` and keeps an additional-key claim. Every run of that row in the tree was made
under it.

This is the answer of the workstream's lead, made outside the sessions on the owner's
delegation of 25 November 2026 (the owner's words to its delegate, at about 06:14 UTC:
"the rest is your call"). It is a design ruling. The lead relayed it to the session that
wrote this section (decisions L280 and L281), and the repository holds no other record of
it; the owner did not write this answer.

The retirement of the three interim runs that option 1 names is confirmed in
`chaos/loop/stops/record-retirement.md`, "Answer".

Undo, as option 1 states it: restore the sentence and the three runs with their receipts.
