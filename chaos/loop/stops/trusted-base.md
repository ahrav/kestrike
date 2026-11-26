# Stop: the 64-pass item of trusted_base reads as every scenario's witness minimum

Rehearsal campaign of #304, under the rehearsal freeze
`4626ec2457a1ce6fe2b376216a0503b2f917043c`. Request: the contract is wrong. Found by
the review of pull request blotter pull request 2126, after the campaign's run. Rewritten at
2026-11-24T04:15Z: the merge of `bsw/bsw-ct1/start-c05` (commit `d09a4bb92`) replaced the
`trusted_base` items the first text quoted, and commit `74b137023` holds that text.

## The finding

`trusted_base` in `chaos/project.yaml`, which `chaos/READINESS.md` prints, lists "the
simulation worker's own checks that raise the rule texts the invariants name, each named
in its row's oracle" and "each invariant's control, the control profile or failing history
its row names, as a stand-in for the real defect it imitates". Those two items cover the
row `ks-no-fill-admitted-after-close`: the own check of the scripted history
`k9-placement-across-close` and the control history `k9-placement-judged-open`. Two
statements of the list misdescribe that row's scenario and control:

- The item "working value, not adopted: the witness minimum of 64 passes for each profile
  of a scenario, counted as covered passes for a cluster profile" reads as every
  scenario's minimum. The scenario `ks-escape-2075` counts 500 caught runs
  (`load_delivery.min_caught_per_profile`), the tally of `docs/agents/simulation.md` for
  a scripted history.
- The control item calls each control "a stand-in for the real defect it imitates". The
  control `k9-placement-judged-open` plants no cache defect: it skips the owner's close,
  so the check fails an open owner's legal grant (`chaos/interview.md`, A6).

`chaos/project.yaml` is a frozen path, so the loop changes none of it. The verdicts do not
rest on that list.

## Options

1. **Amend `trusted_base` at the next freeze:** scope the 64-pass item to
   `ks-upload-no-fault` and `ks-cluster-link-faults`, and state
   `k9-placement-judged-open` as a control that plants no cache defect and fails an open
   owner's legal grant; render the claim again. The 500 caught runs stay the merged
   guide's tally, `docs/agents/simulation.md`, and no working value. The edit is under
   `frozen_paths`, so it lands with a new freeze. Undo: restore the items.
2. **Keep it:** the claim keeps printing the 64-pass minimum with no scenario named and
   the stand-in wording for every control.

## Recommendation

Option 1, made with the other amendments of the step that runs the rehearsal of record.
The answer is the owner's: `chaos/approval-policy.md` stops an edit under `frozen_paths`
for the owner.

## Made at the rehearsal of record

Commit `cb9ad932154b5569783cc0e5bc64ba09dcd40d36`, before the rehearsal freeze
`1a76d225bcf1aa0c3145755138f577716bfae5d1`, made option 1 with the other amendments of the
workstream's lead's decision L067: the 64-pass item names `ks-upload-no-fault` and
`ks-cluster-link-faults` and states the 500 caught runs and 500 passes of `ks-escape-2075`,
and the control item states that `k9-placement-judged-open` plants no cache defect. The
claim prints both.

## Answer

Option 1, confirmed as made, on 25 November 2026. The amended `trusted_base` items (commit
`cb9ad9321`) stand: the 64-pass item names `ks-upload-no-fault` and
`ks-cluster-link-faults`, and the control `k9-placement-judged-open` is stated as a
control that plants no cache defect. Commit `e7ea1572d` gave the 64-pass item the first
words "ruled as it reads by the workstream's lead on the owner's delegation of 25 November
2026", for the ruling on OQ-2 (`chaos/interview.md`, "Ruled for the owner"); the scenarios
it names and the control item read as `cb9ad9321` wrote them.

This is the answer of the workstream's lead, made outside the sessions on the owner's
delegation of 25 November 2026 (the owner's words to its delegate, at about 06:14 UTC:
"the rest is your call"). It is a design ruling. The lead relayed it to the session that
wrote this section (decisions L280 and L281), and the repository holds no other record of
it; the owner did not write this answer.

Undo, as option 1 states it: restore the items.
