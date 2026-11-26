# Review policy

Review for correctness, security, performance, simplicity, and coherence, in
that order. Prefer the smallest change that preserves the contract, not the
fewest lines.
Stay read-only. Review the diff; read callers, contracts, and tests to verify impact.
Do not turn a PR review into a repository-wide redesign. A review request does
not authorize fixes, commits, pushes, or tracker changes.

## Review inputs and completion

- Read this file, `AGENTS.md`, and the [writing rules](docs/agents/writing.md)
  in full. A gate reviewer also reads its selected skill's whole `SKILL.md` and
  the references that cover the changed mechanism.
- State the base and head you reviewed, the inputs you loaded, and any input
  that was missing, truncated, or partly read. A partial input gives a partial
  review; report it as one.
- Verify each finding against the code at that head. State missing evidence
  instead of inventing certainty.
- Do not claim an unrun, skipped, blocked, or timed-out check passed. Separate
  application from infrastructure failures and report verification gaps.

## Project contracts

- Follow repository and scoped directory instructions from the review
  environment. Use this policy when local guidance is unavailable.
- The workspace's main crate is `kestrike`. Read `crates/kestrike/src/lib.rs`
  for its modules, process model and host requirements.
- Preserve wire representations. Check encoders, decoders, message routing, and
  malformed-input handling together. Do not silently change encoded bytes.
- Comments explain behavior and invariants, not tracking IDs, review history,
  or private implementation names.
  Never propose comment-lint override markers.
- Use [the issue workflow](docs/agents/issue-tracker.md) for tracker operations.
  Return review findings without posting comments or mutating issues.
- [Escape/contract](docs/agents/ci.md#intake)

## Review priorities

- **Correctness:** Name the safety or liveness property each protocol change
  affects. Check reordered, duplicate, delayed, and stale messages.
- **Recovery:** Check restart recovery, checkpoint boundaries, and trimming.
  Distinguish process-restart recovery from power-loss durability; flushing a
  writer is not filesystem synchronization. A timeout does not prove rollback.
  Check retries, callback ownership, cancellation, shutdown, and bounded queues
  without losing a completion.
- **Security:** Check runtime validation at network and storage boundaries,
  cross-cluster or cross-machine input, frame and allocation limits, path and
  symlink safety, and unsafe Rust. A decoded type alone does not
  prove that its sender, slot, or configuration is valid for this request.
- **Simplicity:** Look for existing code, standard-library functions, platform
  features, and installed dependencies before proposing new machinery. Challenge
  dead code, duplicated logic, speculative configuration, and pass-through layers.
  Name what can be removed and what replaces it. Preserve validation, cleanup,
  safety checks, supported behavior, and useful regression tests.
- **Coherence:** Keep invariants and mutable state with a clear owner. Check
  dependency direction, module responsibilities, naming, and public contracts.
  An abstraction should protect a present invariant, lifecycle, boundary, or
  required variation. One implementation alone is not grounds for deletion.
  Prefer local changes over extracted helpers and moved files.

## Tests and evidence

- For each changed test, check the legal operations that reach the behavior,
  the observation point, and the wrong implementation the assertion rejects.
  Assertions inspect the result, relevant state, and forbidden side effects
  before cleanup erases them, and compare bytes, identity, and order where the
  claim needs them. Avoid circular expected values.
- When a change adds a negative control, claims one fails, or adds a guard ahead
  of an existing control's target assertion, the test or PR names the planted
  mutation and the assertion that failed; report an uncited claim as unverified.
  A failure at an earlier guard, a fixture panic, or an argued mutant does not
  count.
- Covered fixtures, their `crates/kestrike/format-fixtures.sha256` lines
  and stored-generation expected values only grow: flag an edit to one, and a
  deletion that keeps its decoder.
- Changed code that grants test, receipt, or lane credit, such as
  `scripts/verify-receipts.py`, a judge, or an oracle, treats producer-written
  fields as hostile. On every credit path, direct or imported, it re-derives
  credit from raw evidence bound to the manifest or inventory that declares it.
  A producer's flag, summary, substring match, empty set, or exit status after a
  timeout never credits alone; a count credits only when checked against that
  declaration. A conjunction needs one execution that meets all of it. Name one
  input each credit rule refuses and the test that feeds it.
- Request the smallest test that distinguishes the bug from correct behavior.
  Reuse existing clock and seeded-scheduling controls when timing or
  message order matters. Do not demand a framework or coverage for its own sake.
- Suggest test deletion only when a named surviving test covers the same inputs,
  invariant, failure modes, and supported configurations. Consolidation must
  preserve every original case. Keep bug regressions, unique boundary cases,
  readable usage anchors, and the last ungated baseline.
- For Rust changes, require the format, check, clippy and module-test commands
  `AGENTS.md` lists, and documentation verification; CI runs
  `cargo test --workspace`. Use `git ls-files -z '*.rs' | xargs -0 rustfmt --check`
  during read-only review.
- Lane results count as evidence only as
  [the lane evidence rules](docs/agents/ci.md#lane-evidence-and-flaky-tests)
  state. A test that failed once in CI follows the flaky-test policy there.
  Each ignored test has a `scripts/test-registry.json` row whose class matches
  its cause. Report each `select-tests: policy gap:` line that
  `scripts/select-tests.py` prints as a `policy gap`, without blocking the PR.
  A nightly pass or a "not reproduced" result is not evidence of a fix.
- Read [the TLA+ guide](tla/README.md) when reviewing protocol models. Finite
  safety checks do not establish unbounded correctness, liveness, or
  equivalence to implementation. Inspect assumptions, explored bounds, and
  negative controls. Check that a proof's proposition states the claimed
  property and that callers establish its premises on success and refusal
  paths. Report a production caller of modeled code the model omits. Kani
  harnesses and TLC run only in their lanes; model results do not replace
  implementation tests.

## Findings

Report actionable issues introduced or worsened by this change, ordered by
impact, including a pre-existing defect the change newly reaches and an unfixed
sibling of a defect the change fixes. For each, give severity, location,
consequence, smallest fix, and trigger: a concrete input or sequence and the
caller that delivers it at this head, or evidence when no input applies.

Severity follows the trigger's source:

- **Blocker:** a safety, liveness, fail-open, or crash defect that ordinary
  use, a fault the design tolerates, or hostile input triggers. Hostile input
  is unreviewed bytes from the network, another machine, or storage, and
  evidence a run or CI job wrote.
- **Suggestion:** every other finding, such as one that needs a committed,
  reviewed file or an operator's argument to be wrong, a second writer racing
  a single-operator tool, output that credits nothing, or syntax neither the
  tree nor the formatter produces.

Skip cosmetic preferences, speculative future needs, and formatter/linter noise.

For each changed guard, bound, refusal, error mapping, or paginated or listing
read, search its parallel implementations: other constructors and entry
points, the paired client or server path, other callers and readers. For a
changed cross-file constant, limit, or public name, search every file type for
the old value. Report every instance of one missing check as one finding that
names the invariant they share. A stacked child reports base code only where
it newly reaches it.

A review covers the whole diff. A follow-up that can identify the commits since
the last complete review covers them as the change, the open findings, and
otherwise only blockers. No findings is a valid result. Keep the summary short.

A finding closes by a fix commit on the head, a test that shows the claim
false, or a reply citing code, or upstream source at its pinned revision, that
refutes it. A suggestion also closes by a reply weighing cost against benefit,
or by a documented limit a test pins. A closed finding reopens on evidence its
reply left unanswered; cite the reply. For a blocker, "by design", "out of
scope", parity with a reference implementation, or a deferral closes it only
with the contract that permits the behavior, and a deferral needs a tracker
link naming the defect. A summary counts earlier findings still open at the
head beside the new ones, without re-posting them.

## Sub-agents

Delegate only if the user or applicable instructions authorize it. A ticket's
pre-PR gate requires each selected review in its own fresh-context sub-agent on
the same diff and base. Run at most four at once; queue the rest. Give each a
distinct scope. Outside a gate, delegate only independent risky areas. Every
sub-agent is read-only and returns findings only to the main reviewer, who
verifies and deduplicates them.
