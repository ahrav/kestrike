# Approval policy

The loop reads this before it ships a change or stops. Each item or stop names its
source on a "Set at" line: a section of #297, the specification cut from the owner's
request of 2026-11-23, or a repository guide that #297 makes binding. An item with no
such source is marked as this contract's proposal, listed for the owner. The copy is
the simulated Kestrike, so a change reaches the copy as a commit on a pull
request's branch and a new archive built from it.

- **Ships without asking.** A commit pushed to a draft pull request's branch of this
  work that a later commit can revert and that changes no file under `frozen_paths`,
  no cache behavior and no workflow file: a scripted history, a control, a test, a
  guard, a register row, a record under `chaos/runs/` or `chaos/receipts/` that the
  harness wrote, and a scenario status of `open` or a `broken` that a receipt of a
  live run supports. No commit carries `held` or `fixed`: the loop sets either only
  in an uncommitted copy of the tree, runs the contract check there with `--build`
  and `--freeze-commit`, and writes the check's exit, the build digest and the run
  ids in its log. A commit carries `open` for a held scenario and `broken` for a
  fixed one. Building an archive ships without asking. Sweeping a new root under
  `/data/tsw/campaigns` ships without asking, inside the budgets of `project.yaml`,
  on a worker that the session's workstream alone uses and after the session's fence
  check, since A1 is answered on the owner's behalf for such workers
  (`chaos/interview.md`, A1 and "Ruled for the owner"). On any other host no scenario
  run starts until the owner has said who else uses it, and when (`chaos/interview.md`,
  "Open for the owner"), and work that runs no scenario goes on.
  Set at: #297, "Landing and Review Policy" (each pull request opens as a draft),
  "Milestones and Dependencies" (a campaign run uses one archive and a new root) and
  KTD9 (committed statuses); the rest is this contract's proposal, listed for the
  owner.
- **Stops for the owner.** Each of these waits for the owner's answer, and the loop
  goes on with work that does not depend on it:
  - a merge of a pull request, and marking a pull request ready for review. Set at:
    #297, "Landing and Review Policy" (a pull request opens as a draft; the owner
    merges);
  - a change to an existing issue: the loop adds, edits and deletes no issue comment,
    and an edit or a close of an issue waits for the owner's approval of the exact
    change. Set at: #297, "Landing and Review Policy", which binds
    `docs/agents/issue-tracker.md`;
  - a change to a workflow file under `.github/workflows/`. Set at: #297, "Out of
    Scope" and the stop conditions of "Milestones and Dependencies";
  - a change of cache behavior: a change to the non-test build of `kestrike`,
    `kestrike-aws` or `spdk-sys`. Set at: #297, "Out of Scope" and R23;
  - the adoption of a number: every working value that `trusted_base` lists. Set at:
    #297, OQ-2;
  - an exclusion: a property moved to `excluded`, and the approval of one listed
    there. Set at: #297, OQ-4;
  - the freeze: the merge that fixes the contract, named by its full commit id. Set
    at: #297, OQ-1 and "Out of Scope";
  - an edit under `frozen_paths`. Set at: #297, KTD5 (a harness change makes every
    receipt stale);
  - a change to an invariant or its number, a scenario outside an agreed scenario's
    envelope, and a change to a profile, its default counts, a control or a history
    that a scenario row's profiles run, whether the row names it or the sweep
    schedules it, a rule text that a ledger row names, a check that a ledger row's
    oracle names, even with its rule text unchanged, or `campaign`'s classification
    of a run. A commit that one of these stops names waits for the owner, whatever
    "Ships without asking" lists. Set at: this contract's proposal, listed for the
    owner;
  - a new or changed `probe.identity` or `probe.command` of a fence row, and a new
    or changed file under `chaos/harness/`, before `probe_fence.py` runs: the script
    starts both strings as written, with the campaign's credentials, and they start
    `chaos/harness/reach.py` from the working tree in python3's isolated mode, so
    that file runs with those credentials as the working tree holds it. A new
    fence row, such as a later unit's harness fence, and a new or changed file
    there run once the reviewed pull request holds them, at the reviewed commit.
    Set at: this contract's proposal, listed for the owner.
- **What a stop contains.** A file under `chaos/loop/stops/` with the finding or the
  question, the run id and the receipts it rests on, the options with what each costs
  to undo, and one recommendation. The loop names the stop in its log and continues
  with the next scenario. Set at: this contract's proposal, listed for the owner.
- **Review.** Each pull request opens as a draft and passes its review lanes before
  the owner reads it. The owner merges. Set at: #297, "Landing and Review Policy".
- **Findings.** Every broken invariant is reported in the form of
  `docs/agents/simulation.md`, "Report format", with the class, the agreed property
  and its citation. A result that breaks no agreed property is reported under its
  class, an observation or a design question, and changes no cache behavior. Set at:
  #297, "Out of Scope" for cache behavior; `AGENTS.md`, "Simulation testing", which
  binds `docs/agents/simulation.md` for the class and the report.
- **Who runs it.** During the rehearsal one identity, the worker's Unix user with its
  AWS role, runs the harness, writes the receipts and sets each status. After the
  rehearsal a session of a workstream runs the harness on a worker that workstream
  alone uses, after the session's fence check. After the freeze a status of `held` or
  `fixed` is set as a record: a pull request's first lines and its entry in the
  loop's log give the contract check's exit with the freeze id, the build and the run
  ids, run in an uncommitted copy of the tree that carries the status, and its merge
  into `main` puts that record on `main` and sets the status. No commit carries `held`
  or `fixed` in `chaos/ledger.json`, on a branch or on `main`. Set at: #297, KTD4,
  for the rehearsal; for the rest, the ruling on OQ-1 of #297, made on the owner's
  behalf by the owner's delegate on 25 November 2026 (`chaos/interview.md`, "Ruled for
  the owner").
