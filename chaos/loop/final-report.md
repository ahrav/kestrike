# Final report: the rehearsal of record of #304

The rehearsal of record ran under the rehearsal freeze
`1a76d225bcf1aa0c3145755138f577716bfae5d1`, from its session start at
2026-11-24T04:42:51Z to its end at 2026-11-24T05:06Z. The freeze is a rehearsal freeze: the step
`2082-record` records it as the first commit of its branch that holds the enrolled escape on
the amended rows at which the contract check prints nothing, and the workstream's lead
confirms it at review. No status or hold of this campaign is quoted as held under the
owner's freeze. The coordinator was the session of the step `2082-record`. The first pass
of #304 ran under the earlier rehearsal freeze `4626ec2457a1ce6fe2b376216a0503b2f917043c`;
its final report is `chaos/loop/first-pass-final-report.md`, and its log entries stand at
the top of `chaos/loop/log.md`.

Note of 2026-11-24T20:00Z, added after the review of pull request blotter pull request 2126: this report
describes the tree at commit `caded992b`. The runs, the receipts and three frozen files
changed after it, as "After the campaign: the runs of record made again" below states.

## The end

The campaign ended by this ticket's reading of the loop's rule on ends: `runs_required`
decided runs of the rehearsal's build for each scenario, or the budget (#304, "One
campaign"). At the end of iteration 5 each of the three scenarios had its 2 decided runs at
build `3b9e5e9f1598`. That reading is the ticket's, and it is none of rule 11's four ends:
rule 11's first end also asks for 10 iterations on derived scenarios with no new break, and
the campaign ran no derived scenario. The budget was not spent.

## Each scenario at the end

The build on the copy for the whole campaign is
`3b9e5e9f1598aa6f593107750d9770f3ba5c9ad6fa1385603e1b89cff156c6a5`, the archive built with
`CARGO_PROFILE_DEV_OPT_LEVEL=3 campaign sim archive` at
`cb9ad932154b5569783cc0e5bc64ba09dcd40d36` (clean). Every run below swept 28 workers in
batches of 30 s for 120 s at default counts on a new root under `/data/tsw/campaigns/2082r/`,
and each `run.json` names the build, the campaign name, the profiles, the counts and each
profile's run range.

| Scenario | Committed status | Runs at build `3b9e5e9f1598` | Logged hold and its audit |
| --- | --- | --- | --- |
| `ks-escape-2075` | broken | 2 live, both broken: `record-escape-live` (enrollment; 613,009 of 613,009 caught, twin 603,203 passes) and `record-loop-1` (the campaign's; 609,978 of 609,978 caught, twin 599,132 passes); control `record-escape-judged-open`, `k9-placement-judged-open` caught 404,227 times, none missed | none; stop note `2075-fix.md` waiting |
| `ks-upload-no-fault` | open | 2 held: `record-upload-1` (966,305 passes, 74 replays) and `record-upload-2` (971,915 passes, 74 replays) | held at this build, log entry 3; audit needs-owner, `chaos/loop/audits/hold-ks-upload-no-fault.md` |
| `ks-cluster-link-faults` | open | 2 held: `record-cluster-1` (194,930 covered, 77 replays) and `record-cluster-2` (189,521 covered, 77 replays); both reached `faults`, `hits` and `invalidated` | held at this build, log entry 5; audit needs-owner, `chaos/loop/audits/hold-ks-cluster-link-faults.md` |

The committed status of a held scenario stays `open` by the approval policy; each hold
stands in the log with the hold check's exit 0, its build and its run ids. The runs
`upload-live`, `upload-corrupted`, `cluster-live` and `cluster-stale-read` of blotter issue 2080 (build
`3689c1ea48e9`) stood before the campaign and count toward no hold here.

The fence probes on this host ran at 04:32:15Z to 04:32:19Z, before the enrollment runs, and
again at the session start, 04:42:52Z to 04:42:55Z; each of the four credential fences was
refused with its expected text. The harness fence `ks-run-keeps-earlier-runs` keeps blotter issue 2080's
receipt.

## The break, its audit and the stop notes

The campaign met one break, in its own run `record-loop-1`: the invariant
`ks-no-fill-admitted-after-close` broke under "a fill admitted after the cache closed"
(obligation 2). A general-purpose worker with its own context and none of the
coordinator's conversation audited it with `/chaos-testing:chaos-finding-audit` and
returned accept, with a command or a file for each check:
`chaos/loop/audits/record-loop-1.md`. Its brief was `worker-prompt.md`, with the path of
`run-rules.md` and its one item. It wrote no part of the history, which #303 added. The
finding, in the report format of `docs/agents/simulation.md`, is
`chaos/loop/findings/2075-fill-admitted-after-close.md`, class candidate correctness bug.
The fix changes cache behavior, which stops for the owner: `chaos/loop/stops/2075-fix.md`.

Stop notes open for the owner at the end:

- `chaos/loop/stops/2075-fix.md`: the fix of #298, and OQ-12 (which module text holds).
  Answered on 25 November 2026: option 1, by the workstream's lead on the owner's
  delegation of that day. The fix is a pull request of its own, ticketed in the
  workstream that follows (the note's section "Answer").
- `chaos/loop/stops/rehearsal-freeze.md`: both hold audits returned needs-owner, since the
  rehearsal freeze waits for the lead's confirmation at review; every other check of each
  hold passed, and neither hold is quoted as held. Answered on 25 November 2026: option 1,
  confirmed on the owner's behalf by the owner's delegate. The two holds stand as
  rehearsal holds of build `3b9e5e9f1598` for the records at `caded992b`, in the log (the
  note's section "Answer").
- `chaos/loop/stops/record-retirement.md`: confirm the retirement of the three interim
  escape runs and of this chain's interim copies of blotter issue 2080's four runs. Answered on
  25 November 2026: option 1, confirmed on the owner's behalf by the owner's delegate
  (the note's section "Answer").
- `chaos/loop/stops/oracle-text.md` and `chaos/loop/stops/trusted-base.md`: made at
  `cb9ad9321` by the lead's decision L067, open for the owner's confirmation. Both
  answered on 25 November 2026: option 1, confirmed as made, by the workstream's lead on
  the owner's delegation of that day (each note's section "Answer").
- `chaos/loop/stops/merge-of-start-c05.md`: the first pass's freeze findings and its
  retirement, from the first pass. Answered on 25 November 2026: option 1, confirmed on
  the owner's behalf by the owner's delegate (the note's section "Answer").

With these six answers, every stop note under `chaos/loop/stops/` carries its answer.

No change shipped to the copy and none was dropped.

## Runs and hours spent

The budget is the rehearsal budget of `chaos/project.yaml`: at most 12 runs or 3 hours for
the whole campaign, whichever ends first, a working value the owner has not adopted, which
the claim prints. The workstream's lead's decision L127 shortened the hours from M0-1's 6
to 3 for this step, since the workstation's session that the lead's rulings need ends at
16:08 UTC on 24 November.

- The campaign started 5 runs of its 12 (`record-loop-1`, `record-upload-1`,
  `record-upload-2`, `record-cluster-1`, `record-cluster-2`), 614.5 s of harness time, and
  spent 23 minutes of wall clock (04:42:51Z, the first contract check, to
  2026-11-24T05:06Z) of its 3 hours.
- With the two enrollment runs this step ran 7 sweeps in all, 859.8 s of harness time.

## What was never run

No derived scenario ran. No run of `ks-upload-no-fault` or `ks-cluster-link-faults` named
a control with `--control` at this build: their sweeps ran the profiles' controls unnamed
(59,451 and 59,775 caught of 61,289 and 61,628 upload control runs; 6,130 and 6,181 caught
of 21,223 and 20,804 cluster control runs), and their invariants' control receipts are
blotter issue 2080's, of build `3689c1ea48e9`. No archive without debug assertions was built, so no
effect of the break without them is on record. The siblings of the escape's history,
`k9-promise-after-close` and its controls, are in no scenario row.

## The render

`render_loop.py` of the installed skill `chaos-loop` (plugin `chaos-testing`) exited 0 at
04:42:11Z with the pinned validator, the rehearsal freeze id and
`chaos/loop/driver-tools.txt` (SHA-256
`11a80b38cb1dbcde3beff3835b611ad841ed5206b4550f72353f9baf05fdb6da`), into
`/data/tsw/campaigns/2082r/briefs/`, outside the checkout. The tools section holds the
driver's text, with no unfilled slot:

| File | SHA-256 |
| --- | --- |
| `run-rules.md` | `533ff412ae37f80fee37ded008c6d9a396ea88b05cf7d87e5a6d53b6206c0ff6` |
| `coordinator-prompt.md` | `4537cdeb67403a25a59b561f7ed338bf9ee0f640b0301b29c84436317ace8ef7` |
| `worker-prompt.md` | `5734c4963ed8a46e01532b183d99d6ff110cb4f80e6b5e63c613927617fc9190` |

## The boundary

One Unix user runs the sessions, the harness and the judges, so no write under a frozen
path, `chaos/runs/` or `chaos/receipts/` is refused from inside a session. The contract
check with the freeze id finds an edit to a frozen path or a frozen row field after the
fact. Under `chaos/runs/` and `chaos/receipts/` it checks only that the records present
agree with each other: it reads each receipt's outcome as written, reruns no judge, and
cannot see a run whose evidence and receipts were both removed. It printed nothing at each
check of this campaign. The sessions also hold the owner's GitHub login, so an answer on the
pull request is the owner's only when the owner confirms it outside the sessions.

## The claim

`chaos/READINESS.md`, rendered with the contract check's `--claim` flag at the end, from
the committed statuses: 0 of 3 scenarios held, 1 broken, 2 open. Its trusted base prints
OQ-12 as open for the owner.

## After the campaign: the runs of record made again

The sections above describe the tree at commit `caded992b`. These records changed after
it:

- `chaos/harness/run_scenario.py`, `chaos/judges/core/common.py` and
  `chaos/judges/core/validity.py` changed at #302's `dc6fc3ba0` and blotter pull request 2116's `fd691f4a7`,
  and `chaos/project.yaml` changed at `main`'s blotter pull request 2165. Each change of the first three made
  the 16 receipts of the seven runs stale.
- The seven runs were made again twice under their ids, by the workstream lead's
  decisions L166 and L195: at `e908959ed` on build `43209a6be9d4`, and at `73c936f73` on
  build `7899890b4d5f`. `chaos/runs/` and `chaos/receipts/` held the second set, with the
  same verdicts, until the runs of 25 November below; that set stands at commit
  `5755aacea`. The evidence and receipts of build `3b9e5e9f1598` that the table, the
  audits and the finding cite stand at commit `caded992b`; the first set made again
  stands at `6703ba74d`. `chaos/loop/log.md` gives each set's counts in its amendments
  of 08:05Z and 14:05Z.
- Since those changes, the contract check with the rehearsal freeze id exits 1. At
  commit `6cffb0a49` it prints 4 `frozen-path-changed` findings and 78 `stale-receipt`
  findings over the 26 receipts of the eleven runs. `render_loop.py` runs that check
  first, so with this freeze id it renders no brief, and the hold check of
  `docs/agents/chaos.md` ("Statuses") cannot pass. The two logged holds count for the
  records at `caded992b` only. The contract check without the freeze id prints nothing.
- No stop note preceded either retirement, the run ids stayed, and the log records no
  fence check before the sweeps of 07:38Z or 13:46Z.
  `chaos/loop/stops/remakes-after-the-record.md` states this and asks the owner to
  confirm the fourteen retired pairs.
- The runs `upload-live`, `upload-corrupted`, `cluster-live` and `cluster-stale-read` in
  the tree are blotter issue 2080's runs of record of build `9277dc4c7c8f`, started at 10:21Z to
  10:27Z and brought in by the merge `1c668a88a` of blotter issue 2080's `d5178f999`. The build
  `3689c1ea48e9` that the table's paragraph, "What was never run", the log's session
  header and the audits name is the one their receipts named at `caded992b`. The two
  control receipts that check 3 of the hold audits cites said 62,025 catches for
  `cluster-stale-read` and 475,128 for `upload-corrupted` there; in the tree they say
  60,803 and 490,828, under the same rule texts. At `6703ba74d` the four runs were
  blotter issue 2080's of build `0796d5fc23c3`.
- The harness fence's receipt is blotter pull request 2116's probe at `fd691f4a7`.

Stop notes added after the campaign:

- `chaos/loop/stops/remakes-after-the-record.md`: the frozen-path changes and the two
  retirements above. Answered on 25 November 2026: option 1, confirmed on the owner's
  behalf by the workstream's lead under the owner's delegation of that day, with the
  condition that the guide's order holds for every later remake (the
  note's section "Answer").
- `chaos/loop/stops/escape-restoration-text.md`: the `restoration` text of
  `ks-escape-2075`, `ks-reach-required-events` and `ks-ordering-figure` described
  `left_a_process` and `archive_verified` in fewer words than the harness at the head
  records. Answered on 25 November 2026: option 2, by the workstream's lead under the
  owner's delegation (the note's section "Answer"), carried out by the runs of 25
  November below.

`chaos/interview.md`, A1, records that every sweep of the rehearsal started before the
owner said who else uses the worker, and on what footing.

## After the campaign: eleven runs made again on 25 November 2026

`chaos/loop/stops/escape-restoration-text.md` was answered on 25 November 2026 with its
option 2: three scenario rows state what the harness records as restoration, `control.how`
of `ks-required-events-reached` names the commit the witness's binary was built from, and
one docstring clause of `chaos/judges/ordering/figure.py` left. That change made the
fourteen receipts of seven runs stale. The answer also had the four other runs of the
record made again, so that all seven come from one session that checked the fences before
its first sweep and from one archive, ten of the eleven; the ordering control sweeps its
own scratch archive of the same commit.

The order, as the commits show it: the stop note with the answer for the seven stale pairs
was pushed first (`18a47cfb5`); the session's fence check followed at 06:33Z
(`77a6e4828`); the two additions to the answer, the four other pairs and the change to
`control.how`, were pushed after the fence check (`86c155548`, `ffd5f1396`); the change
`bba1b428a` came after all three; every sweep came after the fence check; and the runs
took new ids. The five fence receipts in the tree are this session's probes, so the bullet
above on the harness fence's receipt describes the tree before `77a6e4828`.

The thirteen sweeps of that day, the eleven runs, one run of an earlier series and the
fixture `chaos/tests/runs/fixture-reach-live`, started while `chaos/interview.md` listed
A1 as open for the owner, on the workstream lead's statement that it was answered on the
owner's behalf. A1 records them for the owner to confirm or overrule, as it does the
rehearsal's sweeps.

The eleven runs, their builds, their times and their counts stand in `chaos/loop/log.md`,
amendment of 2026-11-25T07:35Z. Each new run's verdict equals the verdict of the run it
replaces, and the committed statuses stay: `ks-escape-2075` broken, the four other
scenarios open.

| Run in the tree | Replaces | Build | Verdicts |
| --- | --- | --- | --- |
| `record-escape-live-1125b` | `record-escape-live` | `c948fcfa86a0` | `ks-escape-2075` held; `ks-no-fill-admitted-after-close` broken |
| `record-escape-judged-open-1125b` | `record-escape-judged-open` | `c948fcfa86a0` | `ks-escape-2075` held; `ks-no-fill-admitted-after-close` broken |
| `record-loop-1-1125b` | `record-loop-1` | `c948fcfa86a0` | `ks-escape-2075` held; `ks-no-fill-admitted-after-close` broken |
| `record-upload-1-1125b` | `record-upload-1` | `c948fcfa86a0` | `ks-upload-no-fault` held; `ks-bound-record-passes-its-checks` held |
| `record-upload-2-1125b` | `record-upload-2` | `c948fcfa86a0` | `ks-upload-no-fault` held; `ks-bound-record-passes-its-checks` held |
| `record-cluster-1-1125b` | `record-cluster-1` | `c948fcfa86a0` | `ks-cluster-link-faults` held; `ks-bound-record-passes-its-checks` held; `ks-get-not-older-than-collected` held |
| `record-cluster-2-1125b` | `record-cluster-2` | `c948fcfa86a0` | `ks-cluster-link-faults` held; `ks-bound-record-passes-its-checks` held; `ks-get-not-older-than-collected` held |
| `reach-live-1125b` | `reach-live` | `c948fcfa86a0` | `ks-reach-required-events` held; `ks-required-events-reached` held |
| `reach-control-1125b` | `reach-control` | `c948fcfa86a0` | `ks-reach-required-events` held; `ks-required-events-reached` broken |
| `ordering-live-1125b` | `ordering-live-r7` | `c948fcfa86a0` | `ks-ordering-figure` held; `ks-ordering-controls-caught` held |
| `ordering-premise-unmet-1125b` | `ordering-premise-unmet-r7` | `d490e18bd0e6` | `ks-ordering-figure` held; `ks-ordering-controls-caught` broken |

The eleven retired pairs stand at commit `5755aacea`. The table of "Each scenario at the end" above, the
break, the audits and the finding describe the runs of build `3b9e5e9f1598` at commit
`caded992b`, under the ids those runs had; the two holds of the log count for that build
alone, and no hold check ran for the runs of this section.
