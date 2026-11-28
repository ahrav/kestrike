# AGENTS.md

Rust workspace, edition 2024. The main crate, `crates/kestrike`, implements
Kestrike, a hardware-oriented cache whose objects live on an EBS-backed
block device.

- Never stash or discard working changes. Preserve concurrent user edits.
- Before changing Rust code, read `docs/agents/code-style.md` and
  `docs/agents/design.md`. Search for existing functionality before
  adding types or helpers. Name the safety invariant each protocol change preserves.
- After Rust changes, run
  `git ls-files -z --cached --others --exclude-standard '*.rs' | xargs -0 rustfmt && cargo check --workspace && cargo clippy --workspace --all-targets -- -D warnings`,
  then only the tests for the changed code and `/doc-rigor`. Select tests by
  the crate and module touched, for example
  `cargo test -p kestrike --lib -- net::` for a change under
  `crates/kestrike/src/net/`, and add the tests of any module whose
  callers the change reaches. Run `cargo test --workspace` only when a change
  crosses crate boundaries, edits a trait, type or config that every module
  consumes, or alters the test harness itself, and state that reason before
  running it. Every other change, a merge that touches many files included,
  runs the selected modules' tests and leaves the full run to CI. For
  multi-file changes, run `cargo check --workspace` after each file edit.
- Prefix the `cargo check`, `cargo clippy` and `cargo test` commands of the
  rule above with
  `CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_DEV_DEBUG=line-tables-only`,
  the profile values `scripts/rust-lane.sh` gives the `workspace` lane; debug
  assertions and overflow checks stay on. The library and simulation tests
  then run several times faster, and a change of the values rebuilds the
  affected artifacts. Put the values on those commands only and do not export
  them for the shell: the hardware lane, `scripts/reproduce-test.py`,
  `scripts/scan-barriers.py` and `campaign sim archive` read or record the
  environment they are given. To reproduce a CI failure use the failing lane's
  own recipe (`docs/agents/ci.md`), and use the plain dev profile when
  debugging needs full symbols.
- Before pushing changes to the test inventory, test registry, test-selection
  scripts, obligation catalog, its list of control-less records
  (`verification/control-less.json`), intake register (`verification/intake/`), or
  receipt validation scripts, run
  `python3 scripts/test-select-tests.py` and
  `python3 scripts/verify-receipts.py admit`. Both must pass; Cargo checks do
  not exercise these Python contracts. While editing qualified inventory rows,
  get quick fixture-coverage feedback with
  `python3 scripts/test-select-tests.py SelectTests.test_every_qualified_test_row_has_exactly_one_witness_fixture`;
  this does not replace the full script before pushing. `admit` compares no
  base list, so review reports a pull request that adds an entry to
  `verification/control-less.json`, as
  [the lane evidence rules](docs/agents/ci.md#lane-evidence-and-flaky-tests)
  state.
- Before pushing changes to `verification/verus/inventory.json` or any source
  file it names, run `python3 scripts/judge-verus.py reconcile`. Resolve stale
  source digests or trust declarations before pushing; do not weaken the
  inventory to make reconciliation pass. With
  `git config --local core.hooksPath .githooks`, the pre-push hook runs these
  checks on the pushed commits; see
  [the pre-push checks](docs/agents/ci.md#pre-push-checks).
- Before pushing a change under `chaos/`, run
  `python3 -I chaos/tools/validate_contract.py chaos/ledger.json --root . --project chaos/project.yaml --receipts chaos/receipts --check-claim chaos/READINESS.md`.
  It must print nothing. Then run `python3 -I scripts/chaos-receipt-replay.py`,
  which runs each run receipt's judge again on its evidence, compares the
  receipt it writes with the stored one and must exit 0.
  After a change to the ledger, the project file or a
  receipt, render the claim again as
  [the chaos guide](docs/agents/chaos.md#the-readiness-claim) shows: into a
  new file that `mktemp` makes in `chaos/`, which `chmod 644` and
  `mv -T` then put in place of `chaos/READINESS.md` once the validator exits 0.
  After a change under `chaos/harness/`, `chaos/judges/`, `chaos/tests/`,
  `chaos/tools/` or `chaos/receipts/`, or to the ledger, `chaos/project.yaml`
  or `chaos/approval-policy.md`, also run `python3 -I chaos/tests/test_judges.py`.
  Run it too after a change to
  `crates/campaign-supervisor/src/campaign/calibration/controls.rs`,
  `crates/campaign-supervisor/src/campaign/seeds/required.rs`,
  `crates/campaign-supervisor/src/campaign/seeds.rs` or
  `crates/campaign-supervisor/src/protocol/summary.rs`. That run checks each
  of those files only where a test under `chaos/tests/` reads it; where none
  does, a pass says nothing about it.
  With `git config --local core.hooksPath .githooks`, the pre-push hook runs
  each of them on the pushed tips that need it; no CI job runs them. See
  [the pre-push checks](docs/agents/ci.md#pre-push-checks).
- Before pushing a change to `verification/models/links.json`, a model it
  enrolls, a file one of its rows names, `tla/check.py`,
  `scripts/judge-verus.py`, `scripts/judge-rc11.py`, `scripts/model-links.py`
  or `scripts/test-model-links.py`, run `python3 scripts/model-links.py check`.
  After a change to a script in that list, also run
  `python3 scripts/test-model-links.py`. The pre-push hook runs both on the
  pushed commits; in a clone without the hook, run them yourself. When the
  check reports a changed item, read the item and the row, update the row when
  the pairing changed, and only then record the digest it prints. Before you
  cite a pass as evidence, read the header of `scripts/model-links.py`, which
  states what a pass shows and what it leaves unchecked.
- Before pushing a change to `scripts/gameday-judge.py`, its self-test, a
  file under `scripts/gameday-fixtures/` or a file the self-test reads (the
  header of `scripts/pre-push-checks.py` lists them), run
  `python3 -I scripts/test-gameday-judge.py`. The pre-push hook runs it on the
  pushed tips that need it; no CI job runs it yet.
- Before pushing a change to `scripts/host-stop-controller.py`, its self-test,
  a file under `scripts/host-stop-fixtures/` or `scripts/gameday-fixtures/`, or
  a file the self-test reads (the header of `scripts/pre-push-checks.py` lists
  them), run `python3 -I scripts/test-host-stop-controller.py`. The pre-push
  hook runs it on the pushed tips that need it; no CI job runs it yet.
- Do not run Miri unless the user asks for it or a change touches `unsafe`
  code in a way the test suite cannot otherwise check. A Miri pass over
  `kestrike` takes many minutes; when it is needed, run it after the push,
  not as a gate before it.
- Never append a comment-lint `allow(...)` override marker. Rewrite or delete
  the comment instead. `.githooks/pre-commit` checks staged additions with
  `scripts/forbid-comment-markers.sh --staged`.

## What gets committed

Apply these rules to every commit and PR.

- Commit only production code and tests that stay. Exploratory code,
  comparison arms, benchmarks, and research plans run in a temporary campaign
  outside the repo. A PR lands the selected implementation and its tests, not
  the candidates or the measurements that chose it.
- Ship one implementation per mechanism. Do not add a fallback, a second
  backend, or a runtime switch between approaches unless the user approves a
  specific reason. Runtime CPU-feature dispatch over a reference path is one
  mechanism.
- This system chooses performance over simplicity. A change made for
  performance records the figure, its baseline, the host and the workload in
  the pull request or a commit message. A gain recorded that way outranks a
  simpler form, a hand-written or CPU-specific kernel included. A claimed gain
  without that record is unverified. A warm-recovery change also needs the
  measurement frame's PASS receipt; see
  [Hardware and FIS](docs/agents/ci.md#hardware-and-fis).
- Before committing, check the diff for a benchmark, feature flag, or code
  path that exists only to compare or measure alternatives. Remove it, or stop
  and ask.

## Documentation

Follow `docs/agents/writing.md` for prose, comments, and agent instructions.
Before changing source comments, read `docs/agents/comments.md`.
Keep source-implementation names out of published code and docs. Keep
existing local policy/spec files ignored.

Keep agent guidance in `docs/agents/`. A clone may also hold local-only rules
under `docs/policies/`. When it does, read every file there whenever you read a
`docs/agents/` guide; `docs/agents/` wins where the two conflict. Specs and implementation plans belong in the issue tracker,
not new local copies. Existing local references are not tracker state.

## Simulation testing

Before you write or change a simulation profile or scripted history, run,
monitor or triage a simulation campaign, report a finding from one, or add or
change a kestrike determinism-lint exception, read
`docs/agents/simulation.md`. Classify each finding there, with the agreed
property it breaks, before you call it a bug or change cache behavior for it.

Before you prepare, run or change a simulation host, the publisher, the
watch host or the fuzz host, or change `crates/sim-host`, read
`docs/agents/sim-hosts.md`.

Before you deploy, configure or run the zone reconciler service, or change
`crates/kestrike-reconciler`, read `docs/agents/reconciler.md`.

Before you start, add or change a tool under `crates/kestrike-tools`, change
`scripts/tool.sh`, port a script to a tool, or change a Python file that a row
of [Rules held twice](docs/agents/tools.md#rules-held-twice) names, read
`docs/agents/tools.md`.

Before you read, change or validate a file under `chaos/`, or report what a
chaos campaign on the simulated Kestrike shows, read `docs/agents/chaos.md`.

## Agent skills

### Work tracking

Specs and implementation tickets use the backend configured in
`docs/agents/issue-tracker.md`. Read that file before any tracker operation.
Read `REVIEW.md` before code review. Read `docs/agents/ci.md` before changing
workflows or reasoning about CI lane order and runner capacity. Apply its
nightly/manual admission rule before adding or reclassifying a CI lane. When a test
fails in CI or needs an ignore, follow the flaky-test policy in
[the lane evidence rules](docs/agents/ci.md#lane-evidence-and-flaky-tests).
Tracker mutations require approval of the exact preview. Do not publish
private source references in GitHub issues.
