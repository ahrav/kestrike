# Final report: the rehearsal chaos loop of #304

The rehearsal campaign ran under the rehearsal freeze
`4626ec2457a1ce6fe2b376216a0503b2f917043c`, from its first iteration at
2026-11-23T22:29:24Z to its end at 2026-11-23T22:40Z. The freeze is a rehearsal freeze:
this ticket names it as the first commit of its branch that holds the enrolled escape and
at which the contract check prints nothing, and the workstream's lead confirms it at
review. No status or hold of this campaign is quoted as held under the owner's freeze.

Note of 2026-11-24T04:15Z: this report describes the tree at commit `74b137023`. The
merge of start-c05 changed the runs, the receipts and the frozen paths after it, as
"After the campaign: the merge of start-c05" below states.

## The end

The campaign ended when the workstream's lead limited this step's runs at 22:32 UTC.
#297 sends a unit's stop conditions and the rehearsal freeze to the workstream's lead
("Stop conditions", M0-5) and names no delegation of a campaign's end. The run rules'
rule 11 names four ends, and this end is none of them: it is the lead's ruling, relayed to
this session by the campaign, and no owner message or commit outside the sessions
confirms it. The ruling, as the campaign gave it to this session: "So in
this step build the whole of your ticket and prove the path end to end (the escape's
enrollment, the render, a short loop with the audit, the guide), open your draft, and say
at its top that the rehearsal of record, with its freeze id, is run again by a later step
of this chain that I add once the three tickets below you are final. Keep this step's
runs few: two or three, not the budget of twelve." The body of pull request blotter pull request 2126 quotes
it too. This ticket's reading of the loop's rule on ends is
`runs_required` decided runs of the rehearsal's build for each scenario, or the budget;
the campaign stopped before it, with one scenario at its count. The lead adds a later
step of this chain that runs the rehearsal of record again, with its own freeze id, once
the tickets below this one are final.

## Each scenario at the end

The build on the copy for the whole campaign is
`9e1936bceaef13ec2057667f6b0f44843beec7a53541ceeb6d8f54e779739110`, the archive built at
`806337a84bf8bebaacce63bdaccf7101934bc1ae` (clean).

| Scenario | Status | Live runs at build `9e1936bceaef` | Earlier runs |
| --- | --- | --- | --- |
| `ks-escape-2075` | broken | 2 decided, both broken: `escape-live` (enrollment, 1,276,757 of 1,276,757 caught) and `loop-escape-1` (the campaign's, 1,289,604 of 1,289,604 caught); control `escape-judged-open`, `k9-placement-judged-open` caught 637,460 times | none |
| `ks-upload-no-fault` | open | none | `upload-live` held and `upload-corrupted` (control) at build `3689c1ea48e9` |
| `ks-cluster-link-faults` | open | none | `cluster-live` held and `cluster-stale-read` (control) at build `3689c1ea48e9` |

Each run at build `9e1936bceaef` swept 28 workers in batches of 30 s for 120 s at default
counts on a new root under `/data/tsw/campaigns/2082/`, and each `run.json` names the
build, the campaign name, the profiles, the counts and each profile's run range.

The two enrollment runs started before any fence probe on this worker was on record:
`escape-live` at 22:19:35Z and `escape-judged-open` at 22:21:51Z, while the fence
receipts at the rehearsal freeze name another instance. The probes on this worker, which
the receipts under `chaos/receipts/fences/` hold, ran from 22:28:58Z to 22:29:02Z, so only
`loop-escape-1` followed a recorded probe set on its host. This is missing evidence for
the two enrollment runs, and no record shows a fence that was open. The rehearsal of
record makes its enrollment runs after its probes.

## The break, its audit and the stop note

The campaign met one break, in its own run `loop-escape-1`: the invariant
`ks-no-fill-admitted-after-close` broke under "a fill admitted after the cache closed"
(obligation 2). A worker with its own context and none of the coordinator's conversation
audited it with `chaos-finding-audit` and returned accept, with a command or a file for
each check: `chaos/loop/audits/loop-escape-1.md`. Its brief was `worker-prompt.md`, with
the path of `run-rules.md` and its one item, the audit of the run `loop-escape-1`, as the
tool text states; the contract paths came from those files. That worker wrote no part of the
history, which #303 added. The finding, in the report format of
`docs/agents/simulation.md`, is `chaos/loop/findings/2075-fill-admitted-after-close.md`.
The fix changes cache behavior, which stops for the owner: `chaos/loop/stops/2075-fix.md`
is open. The pre-PR review of #304 found that the invariant row's `oracle` text
overstates when its check fails; the row is frozen, so that is the stop note
`chaos/loop/stops/oracle-text.md`, also open and the owner's to answer, since
`chaos/approval-policy.md` stops a change to an invariant for the owner. The review of
pull request blotter pull request 2126 found that `trusted_base` described two invariants. The merge of
start-c05 replaced those items with ones that cover every invariant's check and control,
and the stop note `chaos/loop/stops/trusted-base.md`, open for the owner, asks for the
scope of the 64-pass item and the wording for a control that plants no defect. No change
shipped and none was dropped.

## Runs and hours spent

The budget is the rehearsal budget of `chaos/project.yaml`, 12 runs or 6 hours for the
whole campaign, a working value the owner has not adopted, which the claim prints.

- The campaign started 1 run (`loop-escape-1`, 122.9 s) of its 12, and spent 11 minutes
  of wall clock (22:28:57Z, the first contract check, to 22:40Z) of its 6 hours.
- With the enrollment runs this step ran 3 sweeps in all, 368.6 s of harness time.

## What was never run

`ks-upload-no-fault` and `ks-cluster-link-faults` have no run at the rehearsal's build,
so the campaign states no hold for them. No derived scenario ran. The sibling histories
`k9-placement-across-storage-close` and `k9-promise-after-close` are in no scenario row
and were not swept here; #303 records their 500-root tally.

## The render

`render_loop.py` of the installed skill `chaos-loop` (plugin `chaos-testing` 0.4.0)
exited 0 with the pinned validator, the rehearsal freeze id and `chaos/loop/driver-tools.txt`
(SHA-256 `8b2a5371fb0cb329d23a75cb56f32740b3d66adfb3e3f267a404e8a12a95e2c9`), into
`/data/tsw/campaigns/2082/briefs/`, outside the checkout. The tools section holds the
driver's text, with no unfilled slot:

| File | SHA-256 |
| --- | --- |
| `run-rules.md` | `fe1f7c713496df4722155139be4838a4580d9951c80109a05a17ecb376ec2f19` |
| `coordinator-prompt.md` | `f127c68a63ef86286308e2d43e9be6b9a2b5ffb065f020623c20a710fa0fdf1e` |
| `worker-prompt.md` | `25caff60fdc71eb682829ae7c2047d3b7d91ec0bce48c71b68fb170ef6873fe7` |

## The boundary

One Unix user runs the sessions, the harness and the judges, so no write under a frozen
path, `chaos/runs/` or `chaos/receipts/` is refused from inside a session. The contract
check with the freeze id finds an edit to a frozen path or a frozen row field after the
fact. Under `chaos/runs/` and `chaos/receipts/` it checks only that the records present
agree with each other: it reads each receipt's outcome as written, reruns no judge, and
cannot see a run whose evidence and receipts were both removed. It printed nothing at
each check of this campaign. The sessions also hold the owner's GitHub
login, so an answer on the pull request is the owner's only when the owner confirms it
outside the sessions.

## The claim

`chaos/READINESS.md`, rendered with the contract check's `--claim` flag at the end: 0 of
3 scenarios held, 1 broken, 2 open.

## After the campaign: the merge of start-c05

The sections above describe the tree at commit `74b137023`. The merge of
`bsw/bsw-ct1/start-c05` (commit `d09a4bb92`) changed the judges, the harness,
`chaos/project.yaml` and `chaos/approval-policy.md`, and these records changed with it:

- `chaos/runs/` and `chaos/receipts/` hold interim runs of build `a1875b9eafec` under
  the ids `escape-live`, `escape-judged-open` and `loop-escape-1` (commit `a50b03fce`),
  with the same verdicts. The evidence and receipts of build `9e1936bceaef` that the
  table, the audit and the finding cite stand at commit `74b137023`.
- The runs `upload-live`, `upload-corrupted`, `cluster-live` and `cluster-stale-read`
  in the tree are start-c05's, of build `0153f79d6397`. The build `3689c1ea48e9` in the
  table is the one their receipts named at `74b137023`.
- Four fence receipts are start-c05's probes of 2026-11-23T23:21:46Z to 23:21:49Z. The
  receipt of `ks-run-keeps-earlier-runs` is this campaign's probe of 22:29:02Z, and the
  other four probes of 22:28:58Z to 22:29:02Z stand at `74b137023`.
- Since the merge, the contract check with the rehearsal freeze id exits 1. At commit
  `a50b03fce` it prints 7 `frozen-path-changed` findings, 8 `frozen-row-changed`
  findings and 80 `stale-receipt` findings over the 16 receipts of the 7 runs.
  `render_loop.py` runs that check first, so with this freeze id it exits 1 and renders
  no brief, and the hold check of `docs/agents/chaos.md` ("Statuses") cannot pass. The
  contract check without the freeze id prints nothing. The rehearsal of record names
  its own freeze.
- The three earlier run and receipt pairs were retired by the workstream's lead's
  ruling of 2026-11-24 02:58 UTC. `chaos/loop/stops/merge-of-start-c05.md` quotes it
  and asks the owner to confirm the retirement.
