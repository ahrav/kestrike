#!/usr/bin/env python3
"""Admit verification obligation records and credit them from lane receipts.

Usage:
  verify-receipts.py admit
  verify-receipts.py gate --event EVENT [--action ACTION]
  verify-receipts.py aggregate --lanes DIR --event EVENT --revision SHA --run ID --run-attempt N
  verify-receipts.py receipt --job JOB [--module NAME] --evidence DIR [--revision SHA]
  verify-receipts.py credit --job JOB [--module NAME] --evidence DIR [--revision SHA]
      [--receipt FILE]

Quint's manifest maps blocked cases to external gates. Credit and aggregation
withhold records requiring those cases, and summaries name each gate. Every
blocked case still must reach its declared outcome.

The catalog is the committed `verification/obligations.json`: a `baseline`
revision and one record per obligation naming its `property`, `transition`,
`invariant`, the workflow `job` (and Loom `module`) that exercises it, the
positive `tests`, the distinguishing `controls` (each a test and the violation
text it asserts), and the independent `reference` the expected result comes
from. `admit` refuses a catalog whose baseline differs from the inventory's, a
record missing a field, a repeated id, a test absent from the inventory (an
ordinary test must be a required witness of its crate, and one its catalog
target derives from the catalog must also be a `#[test]` fn under its module
path in the crate sources, read as written: the workspace lane's listing
judges which of those fns its target and `cfg` predicates build; a Loom test
must be declared for its module; a Miri or sweep test must be one of its
scoped selection's IDs; a qualified lane's test must be one of its rows'
tests in the inventory's `qualified` map), a required test the inventory or
registry ignores, a
job the workflow lacks or the `rust-gate` job does not need, a control without
violation text or whose text is absent from the control's own attributes and
body, a missing reference, and a required job that lacks `timeout-minutes` at
least ten minutes over its step budgets, an evidence upload with `if:
always()` and `if-no-files-found: error`, or a credit step running this script
under `if: always()`. A job the workflow lacks, or `rust-gate` itself, is
`missing-job`; a job outside `rust-gate`'s needs or with a weaker structure is
`gate-structure`; a job with a credit step, or a Loom module in the inventory,
that no record names is `uncovered-lane`. The `admit` command also checks the
atomic-site census against the catalog and inventory through
scripts/classify-atomics.py, refuses each census refusal as `census` and
reports the census's needs-kernel obligations, which admission credits as nothing, under
`census_needs_kernel`; the top-level `credited` speaks for catalog admission.
The `admit` command also judges the intake register `verification/intake/`,
one JSON object a file whose `id` is its file name and whose `kind` is
`escape`, `incident`, `contract-change` or `disagreement`, with exclusion
files under `exclusions/`, and refuses under the code `intake`: a register
directory that is a link, missing or cannot be listed, an `exclusions/`
directory that is a link or cannot be listed, an entry whose type cannot be
read, a link, a special file or any other entry in the register, each judged
on the descriptor it is read from, a file of more than `REGISTER_BYTES` bytes,
that is no object, repeats a member name or holds `NaN` or an infinity,
another id or kind; an escape without `class` (a safety or correctness bug),
`property` (its text, a pointer and one of the six places of
docs/agents/simulation.md, "An agreed property"; an obligation pointer names a
shape-valid catalog record, a rule property's text is a rule text: a string
literal, in code, of an array of the narrator's `rules.rs` that its `scoped`
catalog names; a model property's pointer is a property the model's runner
checks for its `model`), `site` (a path relative to the checkout and a
function; while the fix is not delivered the path names a file) or `fix`
(`merged` with its pull request number, or `not-delivered`; a named
regression's path is a Rust file under the `src/` or `tests/` of a crate, a
directory of `crates/` that holds its `Cargo.toml`, its tests a list without
repeats, each a test ID whose modules the declarations of the file's target
lead from its root to that file, with a `#[test]` fn in code under that
module path), a `cause` outside `CAUSE_EVIDENCE` or without
its evidence keys, an evidence `sweep` that names no archive digest of 64
hexadecimal characters, a row without a cause that holds `evidence`, a
`catch` or an `exclusion`, a `catch` without `history`, `rule` and a nonempty
object `tally`, whose tally lacks that digest under `build`, a `missed` or a
`runs`, or holds a `missed` other than 0 or a `runs` that records no run, or
whose history or `control` is no quoted history name (the first literal of a
constructor call in a history array that `every` or `scenarios` chains), whose
`control` repeats its history or stands beside a tally that lacks the counted
entry named for the history under `history` or for the control in `controls`,
or whose rule is no rule text, or whose `site` is blank, or absent beside
`also`, or whose `also` is no nonempty list of further histories, each an
object with a quoted history name that the catch holds once, a nonblank `site`
and a tally under the same rules, an `exclusion` that names no exclusion file
covering the row; an
incident or contract change whose `property_action` is neither `none` with a
reason nor `added` with a reference present in its place (a catalog record
id, a rule text, or a property of its `model`, a `.tla` file of `tla/` or a
`.qnt` file of `quint/`, that a case passing on the committed text checks:
for TLC, an invariant or property of a completing case whose target or root
module is the file, which its configuration does not rebind, with the
conjuncts of the file's `Safety`; for Quint, a case of the family the file
names, or a `join` case of its projection's module of `joins.qnt`, with the
bare-name conjuncts the property reaches through the case's added definitions
and the model's, comments removed); a disagreement without two distinct
`sources`, or whose `holds` states no answer or has no `corrected` pull
request number; an exclusion file without its id, a `reason`, or `covers`
naming each escape row that names it once, or with an empty `approval`. Open
rows pass and are listed under `open_escapes`, `open_disagreements` and
`open_exclusions`. Each indexed source (the narrator's rules, the history
sources, a crate file on a module path, a model and its TLC configuration)
is read once as a regular UTF-8 file under its directory of at most
`SOURCE_BYTES` bytes, a Rust file with no block comment left open; a model
or a file on a regression's module path that is not is a refusal of its row,
and any other source that is not, and a model runner that cannot list its
cases, are crashes.
The `admit` command also holds the control ratchet, refused under the code
`control-ratchet`: a record whose `controls` list is empty carries a
`no_control` member, the text of the reason it has no control, or stands on
the committed list `verification/control-less.json`, the sorted ids of the
records that had neither when the ratchet began. `admit` refuses a record
with neither, a `no_control` member that a record with a control carries or
that is blank or no text, a list that is no sorted list of distinct ids, and a list
entry whose record is absent, has a control or carries a reason; an entry
whose record is malformed carries the record's `malformed-record` refusal.
`admit` compares no base list: that a removed entry stays removed and that
no pull request adds an entry, the rule of docs/agents/ci.md, are held in
review. It prints the list's length under `control_less`.

Each refusal carries a code from REFUSALS.

`receipt` writes `receipt.json` into the lane's evidence directory: the
checked-out revision, the sha256 of every evidence file and committed input
the judgment reads, the tool and its provenance from the lane's pins, the
assumptions and bounds the lane states, the completion category, the judged
execution count, the names executed `ok`, the per-target counts, the replay
command and the CI run. A miri receipt also carries `controls`, the lane's
`controls.txt`: one line per inventory control run with its exit and whether
its diagnostic appeared. The inventory's miri controls credit a record only
from a line whose exit is failing and outside the interrupted codes with the
diagnostic found; any other line, or none, is `missing-result`, and a
completed receipt without the file is also `unbound-input`. The cargo lanes
complete as `completed`, `timeout`
(exit 124, 130 or 143, or a cancel marker), `skipped` (no evidence) or `tool
failure` (a `failure.txt` beside a credited report or no report, an unjudged
run or a crashed selector; a refused selection keeps `completed` and refuses
as `selection-refused`); the fuzz lanes add `violation` for a crash input.
`exhausted`, `unsupported` and a `violation` with named text arrive from
checker lanes through `--receipt`, and the GenMC judge's `correspondence
drift`, a kernel that no longer transcribes production, refuses credit as
`correspondence-drift`. The RC11, GenMC, Verus, Kani, TLC and Quint
lanes are checker lanes: `scripts/judge-rc11.py`, `scripts/judge-genmc.py`,
`scripts/judge-verus.py`, `scripts/judge-kani.py`, `scripts/judge-tlc.py` and
`scripts/judge-quint.py` write their receipts, and their tests are the litmus
names, case names, verified items or harness names each declaration lists. A GenMC, Kani or TLC
record and receipt name a profile as their module, as a Loom one names its module, and a record cites only its
profile's tests. `credit` writes that receipt, or reads
`--receipt` (an imported receipt must equal the one derived from its
evidence, `ci` aside, or it is `unbound-input`; a cargo lane's is derived
here and a checker lane's by its judge, which re-judges the recorded
checker output, a profiled one under the credited profile, so a PR receipt
never credits the scheduled domain), admits the catalog, then
judges every record of the job and module (a `scheduled` GenMC or Kani
receipt also judges the `pr` records, whose cases its run judges) and writes
`credit.json` beside the
receipt: credit needs a catalog that `admit`'s record checks and the census
admit (the intake register and the control ratchet are judged by the `admit`
command alone), a receipt bound to the expected
revision, to the requested job (and Loom module), and to unchanged inputs,
tool provenance equal to the lane's pins, completion `completed` (a cargo lane
also needs a credited selection report), a nonzero execution count, no raw
`FAILED` outcome, and every positive test and control executed `ok`. An
admission refusal refuses credit under its own code before the receipt is
judged, and a receipt whose provenance is empty or differs from `pins.txt` is
`missing-provenance`. Under Actions, `credit` appends its verdict to
`GITHUB_STEP_SUMMARY`. `credit --receipt R --read-only` judges the same way and
prints the same report, but leaves the evidence directory and the step summary
as they were: it creates no directory and writes neither `credit.json` nor a
summary line. A bound receipt names a digest for the inventory, the
registry and the catalog, a checker lane's receipt also names one for its
declaration and every input the declaration binds (each litmus test the RC11
declaration lists; the recipe, patches and kernel package the GenMC
declaration builds), and a `completed`
lane receipt also names one for the evidence its counts come from (`run.txt`,
`report.json` and `pins.txt` for a cargo lane, and `controls.txt` as well
for the Miri lane, `kani-run.json` and each declared batch's command, output and exit code for a Kani
profile, as `scripts/judge-kani.py` names them, `fuzz.json` and `pins.txt` for the fuzz lanes, a qualified test lane a cargo
lane judged under the `qualified` cfg for its own lane, and `list.txt`, `ignored.txt` and `exit.txt` as well for every
lane whose report `select-tests.py` writes); a missing digest is
`unbound-input`, and a receipt from another job or module is `unbound-lane`.
A completed lane whose `report.json` `select-tests.py run` writes (the
workspace, Loom, Miri, sweep, ASan and QEMU lanes and the qualified test
lanes) has a receipt that takes its selection verdict, its
per-target counts and its execution count from `select-tests.py run`'s
judgment, run in this process under the lane's cfg arguments
(`selection_args`) on the lane's `list.txt`, `ignored.txt`, `run.txt` and
`exit.txt` against the committed inventory, registry and catalog; no test
runs again. The receipt also records the saved `report.json`'s verdict and the
fields of `VERDICT_FIELDS` (`code`, `credited`, `cfg`, `module`, `rows`,
`targets`) in which it differs from that judgment. Credit refuses a missing raw
file or an exit code that is no integer as `unbound-input`, a saved report
that refused as `selection-refused` whatever the judgment, and a saved
positive report that differs as `raw-selection-mismatch`, a report judged
under another cfg or lane included.
A `violation` receipt credits a record with controls and no positive test only
when its text equals each control's. A fuzz lane completes only when each of
its `qualified` rows ran at least its `executions` inputs past its seeds and
libFuzzer's empty input, and each worker target met its checkpoint: its
record holds a positive `nonseed_pass`, the count of generated inputs the
oracle judged a pass. A shortfall is a tool failure naming each blocked row
or unmet checkpoint. Its counted quantity is the frame run's execution count.
A completion other than `completed` refuses under its own hyphenated code.

The ASan and QEMU lanes are enveloped domains (`ENVELOPED`), each credited
from its own receipt: admission checks the job's workflow structure
directly (an enveloped domain without a workflow job is `missing-job`), a
catalog record that names it is judged as any other, and its credit needs
every control the domain requires executed `ok` (the asan entry's required
tests, or the qemu entry's exact IDs; a control without an `ok` outcome is
`missing-result`). The receipt also carries the `qualified` envelope the
lane writes to `qualified.json` (bound by digest), whose shared core names
the domain, the run and its attempt, the target, the rustc flags, the
install record with its header digest, the generated output directory with
its generator digest and toolchain, the native archives' compilers,
configure and archive digests, and the deadlines with the measurement they
derive from. The asan envelope
adds the sanitizer and the Rust sanitizer runtime archive with its digest,
compiler and LLVM version. The qemu envelope adds the portable artifact
reference, the host and the guest inputs file, executable and initrd with
their digests, and the receipt adds the harness's `guest.json` record.
Credit needs a readable envelope whose domain is the job, whose run and
attempt are present and equal the receipt's when the receipt names them,
whose fields are filled with each admissible value and record subfield,
whose measurement and deadlines pass the rules `scripts/qualified-envelope.py`
writes them under (a record of the job's domain with every figure a
positive number and the peak within its memory, and each deadline a positive
whole number of minutes at least the lane's own factor times the measured
seconds), and, for asan, whose selection report attributes at least one
executed test to each module the inventory's `asan` entry requires. A qemu
receipt further needs a measurement taken on the envelope's host machine that
names its runner among the measured registrations, and a guest record of a
qualified pass at the receipt's CI run and attempt whose initrd digest
equals the envelope's and whose reports hold every report of
`GUEST_REPORTS` in order (the default refusal, the substituted-node and
holder refusals, the namespace's claim, bind and release) with the
controller's IOMMU group, whose `reports_overflow` is `false`, whose
`console_truncated` is unset, and whose console log is shorter than the
harness's `CONSOLE_BYTES` and holds the record's reports, in order and at
most `REPORT_BOUND` of them, with
the identity, digested inputs, ready facts naming the guest kernel, modules
and IOMMU, QEMU version, IOMMU settings, bounds and removed backing
recorded. A receipt short of any of these is `unqualified`.

`gate` judges the Rust gate's `needs` results, read as JSON from the
`RESULTS` environment variable: on `pull_request` (opened, synchronize or
reopened) and `push` every fast job must succeed and every heavy job must be
skipped, and on `schedule` and `workflow_dispatch` every job must succeed,
except that an advisory job (`ADVISORY_JOBS`, the ASan lane) may also end in
failure or cancellation; a pending job (`PENDING_JOBS`, whose workflow `if:`
disables it) must be skipped on every event. `FAST_JOBS`, `HEAVY_JOBS`,
`ADVISORY_JOBS`, `PENDING_JOBS` and `EVENT_HEAVY` declare that policy once; a
missing, extra or mismatched result is `lane-result` and another event or
pull request action is `unsupported-event`.

`aggregate` reads every lane's evidence under `--lanes` (one directory per
downloaded artifact) and credits the Rust gate only when each lane the
event selects credited its exact declared domain: the workspace, RC11,
campaigns, search and fuzz-smoke lanes on every event, each
qualified test lane executing its rows' tests once each, and on `schedule`
or `workflow_dispatch` also the long-run, search-nightly and enabled
architecture qualification lanes, the
ten Miri IDs, every sweep seed of every sweep kernel, each Loom module's
tests, the Verus, GenMC, Kani, TLC and fuzz lanes, and the guest lane's one
ID once `qemu` is in `HEAVY_JOBS`. A `schedule` run needs a GenMC
`scheduled` receipt, crediting the
`pr` cases and the scheduled two-reader cases, and a `workflow_dispatch`
run a `pr` receipt, crediting only the `pr` cases, so a `pr` receipt never
credits the two-reader domain. The advisory ASan lane is judged the same
way on those events, and the summary reports its reason, but an
incomplete ASan lane leaves the gate credited.
A lane is incomplete without its receipt (an unavailable runner, a skipped
prerequisite, a missing artifact, or a saved receipt that parses and has
another shape than `receipt_shaped` reads), with a refused credit, a completion
other than `completed`, zero executions, executed names other than its
domain (a count-matched wrong domain included) or a repeated receipt. The
expected identity is the `--revision`, `--run` and `--run-attempt` the
workflow passes from its own context, all three required; each lane's
receipt, the barrier report included, must record a nonempty revision, run
and attempt equal to them, or the lane is incomplete with a reason naming
the component, an advisory lane's gap staying advisory. The barrier report's
embedded build identity must also equal the lane's `identity.json`.
The credit of a lane whose `report.json` `select-tests.py run` writes is
judged again in this process from its evidence, with no catalog admission: the
receipt derived from the evidence, under the run identity the saved receipt
records, must equal the saved one, or it is `unbound-input`; evidence that
cannot be read or judged is that lane's `unbound-input`, and its saved
`credit.json` is left unread. The barrier lane's refusals come from its scan
report and `identity.json`, and every other lane's from its `credit.json`,
whose `refusals` must be a list of records that each name a `code`; a saved
credit of another shape is that lane's `missing-result`.
Evidence from another run attempt is reported and left unread, so a rerun
never replaces an earlier attempt's first failure; a rerun of only the
failed jobs therefore leaves the gate incomplete, and a full rerun credits
it. The summary names each
lane's executed domain and every incomplete lane's reason. Pending lanes
are listed separately with their missing prerequisite and no coverage credit;
a receipt from a pending lane refuses aggregation as an unselected lane.

Each command prints one JSON report. Exit 0 admits or credits, 1 refuses with
named codes, 2 is a crash or an unreadable input; an argument error exits 2
without a report.
"""

import argparse
import collections
import hashlib
import importlib.util
import json
import math
import os
import re
import stat
import subprocess
import sys
from functools import cache, partial
from pathlib import Path
from types import MappingProxyType
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "verification/obligations.json"
WORKFLOW = ROOT / ".github/workflows/agent-checks.yml"
GATE = "rust-gate"
MARGIN_MINUTES = 10
FIELDS = ("id", "property", "transition", "invariant", "job", "tests", "controls", "reference")
COMPLETED, VIOLATION, TIMEOUT, EXHAUSTED, UNSUPPORTED, SKIPPED, TOOL_FAILURE, DRIFT = (
    "completed", "violation", "timeout", "exhausted", "unsupported", "skipped", "tool failure", "correspondence drift",
)
REFUSALS = {
    "baseline-mismatch", "malformed-record", "duplicate-record", "nonexistent-test", "ignored-required-test",
    "missing-job", "missing-violation", "missing-reference", "gate-structure",
    "unbound-revision", "unbound-input", "unbound-lane", "selection-refused", "raw-selection-mismatch", "zero-executions", "raw-failed", "identity",
    "missing-result", "wrong-violation", "missing-provenance", "uncovered-lane", "incomplete", "unsupported-event", "lane-result", "unqualified", TIMEOUT, EXHAUSTED, UNSUPPORTED, SKIPPED, "tool-failure", "correspondence-drift", "census", "intake", "control-ratchet",
}
ADMITTED, REFUSED, CRASHED = 0, 1, 2
# The guest lane's run record, written by scripts/guest-binder.py.
GUEST_RECORD = "guest.json"
INPUTS = ("list.txt", "ignored.txt", "run.txt", "report.json", "selection.json", "exit.txt", "fuzz.json", "pins.txt", "failure.txt", "replay.txt", "qualified.json", "controls.txt", GUEST_RECORD)
COMMITTED = (ROOT / "scripts/test-inventory.json", ROOT / "scripts/test-registry.json", CATALOG)
# The inventory's qualified test lanes name a target; its fuzz lanes do not.
LANES = json.loads(COMMITTED[0].read_text())["qualified"]
QUALIFIED = tuple(lane for lane, declared in LANES.items() if "target" in declared)
FUZZ = tuple(lane for lane, declared in LANES.items() if "target" not in declared)
# The tag comparison inspection lanes, one per architecture, share one declaration and one inspection script.
TAG_COMPARE = ("tag-compare-x86-64", "tag-compare-aarch64")
# The raw files a selection judge reads: the two listings, the run and its exit code.
SELECTED = ("list.txt", "ignored.txt", "run.txt", "exit.txt")
LANE_EVIDENCE = {
    "workspace": ("report.json", "pins.txt", *SELECTED), "loom": ("report.json", "pins.txt", *SELECTED),
    **{lane: ("report.json", "pins.txt", *SELECTED) for lane in QUALIFIED},
    **{lane: ("fuzz.json", "pins.txt") for lane in FUZZ},
    "asan": ("report.json", "pins.txt", "qualified.json", *SELECTED),
    "qemu": ("report.json", "pins.txt", "qualified.json", "guest.json", *SELECTED),
    "miri": ("report.json", "pins.txt", "controls.txt", *SELECTED), "sweep": ("report.json", "pins.txt", *SELECTED),
    "rc11": ("report.json", "identity.json", "pins.txt"),
    "verus": ("report.json", "identity.json", "pins.txt", "verus.txt", "verus.d", "cargo.d", "tree.txt"),
    "genmc": ("report.json", "identity.json", "pins.txt"), "kani": ("report.json", "identity.json", "pins.txt", "kani-list.json", "Cargo.lock"),
    "tlc": ("report.json", "identity.json", "pins.txt", "tlc.txt", "results.json"),
    "quint": ("report.json", "identity.json", "pins.txt", "quint.txt", "results.json"),
    **{job: ("report.json", "identity.json", "pins.txt", "extents.json", "callers.txt", "exit.txt") for job in TAG_COMPARE},
}
CHECKER_JOBS = {
    "rc11": ROOT / "verification/rc11/expected.json", "genmc": ROOT / "verification/genmc/expected.json",
    "verus": ROOT / "verification/verus/expected.json", "kani": ROOT / "verification/kani/expected.json",
    "tlc": ROOT / "verification/tlc/expected.json", "quint": ROOT / "verification/quint/expected.json",
}
CHECKER_JOBS.update({job: ROOT / "verification/tag-compare/expected.json" for job in TAG_COMPARE})
CHECKER_JUDGES = {name: ROOT / ("scripts/scan-tag-compare.py" if name in TAG_COMPARE else f"scripts/judge-{name}.py")
                  for name in CHECKER_JOBS}
PROFILED = ("genmc", "kani", "tlc")


def lane_evidence(job, module):
    """Return the evidence files a completed receipt of `job` and `module` binds: the lane's fixed files, and for a
    Kani profile also the run record and every batch's command, output and exit code, as its judge declares them."""
    if job == "kani" and module in checker_declaration("kani")["profiles"]:
        return (*LANE_EVIDENCE[job], *judge_call("kani", lambda judge: judge.evidence_files(judge.declaration(), module)))
    return LANE_EVIDENCE.get(job, ())


def modules_of(job, inventory):
    """Return the modules a job's records and receipts name: Loom modules, GenMC, Kani or TLC profiles, or none."""
    if job == "loom":
        return sorted(inventory["loom"])
    if job in PROFILED:
        return sorted(checker_declaration(job)["profiles"])
    return [None]
MIRI_SELECTIONS = {"miri": "miri", "sweep": "miri_sweep"}
LANE_CFG = {"workspace": "ordinary", "loom": "loom", "miri": "miri", "sweep": "miri-sweep", "asan": "asan", "qemu": "qemu",
            **{lane: "qualified" for lane in QUALIFIED}}
# `ENVELOPE` holds every enveloped domain's envelope fields and `ENVELOPED` each domain's additions. `None`
# needs the field filled, a string names its one admissible value, and a tuple names the subfields its
# record must fill.
ENVELOPED = {
    "asan": {"sanitizer": "address", "runtime": ("archive", "sha256", "rustc", "llvm")},
    "qemu": {
        "artifact": ("target", "rustflags", "generated", "header_digest", "generator_digest", "archives", "install", "source"),
        "host": ("kernel", "machine", "runner", "accel"), "inputs": ("path", "sha256"),
        "executable": ("path", "sha256"), "initrd": ("path", "sha256"),
    },
}
ENVELOPE = {
    "target": None, "rustflags": None, "install": None, "generated": None, "header_digest": None, "generator_digest": None,
    "generator": None, "native": ("compilers", "configure", "archives", "lineage"), "deadlines": None, "measured": None,
}
# The run records a domain's receipt carries beside its envelope: the receipt field and the evidence file.
DOMAIN_RECORDS = {"qemu": ("guest", GUEST_RECORD)}
# The reports a guest run's qualified pass holds in order, and the harness's name for that outcome, as
# scripts/guest-binder.py writes them.
GUEST_REPORTS = ("default refused", "substituted file refused", "other block node refused", "holder refused", "claimed", "bound", "released")
GUEST_PASS = "qualified pass"
ASSUMPTIONS = {
    "loom": ["covers the shimmed model only", "release profile: debug assertions disabled"],
    "fuzz": ["claims robustness only: parse never panics and accepted frames re-encode"],
    "fuzz-smoke": ["claims robustness only over the smoke budgets: parse never panics and accepted frames re-encode"],
    "long-run": [
        "one fixed manifest, crates/kestrike/src/sim/long_run.manifest, pins the churn seed, its key collision and the mixed root; other seeds and roots are outside its evidence",
        "fixed scaled and suffix manifests: seeds 0 to 11 at 409,600 actions on three geometries; trees to depth 4 by 3 and 7 by 2",
        "workspace dev profile: opt-level 1, debug assertions and overflow checks on",
    ],
    "campaigns": ["the worker's cases on one thread under the workspace dev profile"],
    "search": ["the pull-request bound: depth 5, one fault and one advance over the fixed two-peer core"],
    "search-nightly": [
        "the nightly bound: depth 6, two faults and four advances over the fixed two-peer core",
        "the seeded bounds: depth 5, two faults and four advances from the pre-final-ACK and completed-held roots, each reached by a fixed prefix from the fresh core",
        "the reply-pressure bound: depth 7 at a batch of two with no fault and no advance from the fresh core; its staging lookahead polls six times, the other peer queuing every refusal it can draw before each poll",
    ],
    "asan": [
        "address sanitizer over the Rust and native code of the spdk-sys and kestrike library tests; leak detection is off and earns no credit",
        "the sanitized install's compilers and the Rust sanitizer runtime are recorded, and their compatibility is evidenced by the shim overflow control alone",
        "the unfiltered run attributes the bind, native and index modules; the three stay attributable beside it through the selection report",
    ],
    "qemu": [
        "one disposable QEMU guest over an emulated NVMe controller behind the guest IOMMU; physical DMA and containment stay with the hardware lanes",
        "the guest's test executable and kernel are runner inputs recorded by digest; the host listing at the same revision binds the guest's census",
        "the portable artifact reference is checked against the committed bindings, and the lane requires its install to select them and to hold the archives it names",
    ],
    "miri": [
        "interpreted heap and simulated-device paths only; the SPDK and DPDK pins are build-time inputs",
        "default Stacked Borrows and detectors, seed 0, one test thread",
        "one sampled schedule; weak-memory emulation is bounded and incomplete",
        "integer-to-pointer casts accepted without warning; strict provenance unestablished",
    ],
    "sweep": [
        "seeds are samples of the interpreter's schedules and weak-memory outcomes",
        "SC-fence weakening evidence belongs to the RC11 lanes",
        "removing the sequence bracket's Release fence went undetected over all 64 seeds",
        "the publication bracket's physical clock sample lies outside the kernels",
    ],
}
CANCELLED = "cancel or timeout marker"
INTERRUPTED = (124, 130, 143)
BUDGET = re.compile(r"timeout --kill-after=\d+s (\d+)m")


class Crash(Exception):
    pass


def load_script(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise Crash(f"{path.relative_to(ROOT)} cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def judge_call(job, call):
    """Return `call(judge)` for the loaded judge of checker lane `job`.

    Each judge's `Refusal` derives from `Exception` alone, so it is raised here as `Crash`, which `main` reports as
    a JSON crash report; the refusal is caught against the class of the same load that raised it.
    """
    judge = load_script(f"judge_{job}", CHECKER_JUDGES[job])
    try:
        return call(judge)
    except judge.Refusal as error:
        raise Crash(str(error)) from error


def load_select_tests():
    return load_script("select_tests", ROOT / "scripts/select-tests.py")


def checker_declaration(job):
    """Return a checker lane's declaration; the Kani judge expands its band families into harnesses."""
    if job == "kani":
        return judge_call("kani", lambda judge: judge.declaration())
    return read_json(CHECKER_JOBS[job])


def derive_checker_receipt(job, module, evidence, revision):
    """Return the receipt the checker lane's judge derives from the evidence directory, and whether the lane's
    `report.json` is the report that judgment produces.

    A profiled (GenMC, Kani or TLC) judgment is derived under `module`, the credited profile.
    """
    judge = load_script(f"judge_{job}", CHECKER_JUDGES[job])
    report, derived = judge.derive(Path(evidence), revision, *([module] if job in PROFILED else []))
    return derived, report == read_json(Path(evidence) / "report.json")


def credited_modules(job, module):
    """Return the modules whose records a receipt for `module` credits.

    A GenMC, Kani or TLC run judges every test of `profile_cases(module)`, so its receipt also credits each profile
    whose declared tests that run judges: a `scheduled` receipt credits the `pr` records, and a `pr` receipt
    never credits the scheduled domain. A TLC profile that the runner defines and the declaration omits credits the
    declared tiers whose cases that run judges. Every other lane credits its own module.
    """
    if job not in PROFILED:
        return {module}
    expected = checker_declaration(job)
    if module not in expected["profiles"] and not (
            job == "tlc" and module in judge_call("tlc", lambda judge: judge.runner().PROFILES)):
        return {module}
    judged = set(judge_call(job, lambda judge: judge.profile_cases(expected, module)))
    return {name for name, tests in expected["profiles"].items() if set(tests) <= judged}


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as error:
        raise Crash(f"unreadable {path}: {error}") from error


def read_catalog():
    """Return the obligation catalog, decoded by `strict_json`; a catalog that cannot be read or decoded is a crash."""
    try:
        return strict_json(CATALOG.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as error:
        raise Crash(f"unreadable {CATALOG}: {error}") from error


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def committed_inputs():
    """Return the digest of each committed file the judgment reads, keyed by its repository path."""
    return {str(path.relative_to(ROOT)): sha256(path) for path in COMMITTED}


def checker_inputs(job):
    """Return the repository paths of a checker lane's declaration and every input it binds.

    An RC11 declaration lists litmus tests beside it. A GenMC declaration's cases
    name RC11 litmus tests, so its inputs include `verification/rc11/expected.json`,
    and it names the kernel package it builds under the recipe and patches beside
    it; the sources are the ones `judge-genmc.py` digests: the package's, the
    production sources its `#[path]` attributes include, and the production
    sources the declaration lists as transcribed. A Verus lane's judge names
    its inputs: the declaration, the trust inventory, the package sources and
    the production sources the declaration lists. A Kani lane's judge names
    its inputs: the declaration, the Verus declaration and trust inventory its
    gap closures are checked against, the workspace and package manifests, which
    can configure Kani, and every tracked file of `kestrike` and its path
    dependency `spdk-sys`, which the harness build compiles. A TLC lane binds
    its declaration and every model, configuration and the runner under `tla/`,
    and a Quint lane its declaration, the model and the runner under `quint/`,
    and the manifests and tracked package files the Kani judge lists, which its
    replay cases compile.
    """
    if job in ("verus", "kani"):
        return judge_call(job, lambda judge: judge.committed())
    if job in ("tlc", "quint"):
        return [CHECKER_JOBS[job], *judge_call(job, lambda judge: judge.model_files())]
    if job in TAG_COMPARE:
        return [CHECKER_JOBS[job], CHECKER_JUDGES[job], ROOT / "scripts/scan-barriers.py"]
    declaration = CHECKER_JOBS[job]
    declared = read_json(declaration)
    if "tests" in declared:
        return [declaration, *(declaration.parent / "litmus" / f"{name}.litmus" for name in sorted(declared["tests"]))]
    sources = judge_call(job, lambda judge: judge.declared_sources(declared))
    return [
        declaration, ROOT / "verification/rc11/expected.json", declaration.parent / "provision.sh",
        *sorted((declaration.parent / "patches").glob("*.patch")), *sources,
    ]


def workflow_jobs(text):
    """Return each job's needs, timeout, step budgets and whether an upload step is unconditional and strict."""
    jobs, job, step = {}, None, None
    lines = text.splitlines()
    start = lines.index("jobs:") + 1
    for line in lines[start:]:
        if re.match(r"^  [\w-]+:$", line):
            job = jobs.setdefault(line.strip()[:-1], {"needs": [], "timeout": None, "budget": 0, "upload": False, "steps": []})
            step = None
            continue
        if job is None or not line.strip():
            continue
        if line.startswith("      - "):
            step = {"always": False, "upload": False, "strict": False, "credit": False}
            job["steps"].append(step)
        if step is not None:
            step["always"] |= "if: always()" in line
            step["upload"] |= "uses: actions/upload-artifact" in line
            step["strict"] |= "if-no-files-found: error" in line
            step["credit"] |= "verify-receipts.py credit" in line
        needs = re.match(r"^    needs: \[?([^\]]+)\]?$", line)
        if needs:
            job["needs"] = [name.strip() for name in needs.group(1).split(",")]
        timeout = re.match(r"^    timeout-minutes: (\d+)$", line)
        if timeout:
            job["timeout"] = int(timeout.group(1))
        job["budget"] += sum(int(minutes) for minutes in BUDGET.findall(line))
    for job in jobs.values():
        job["upload"] = any(s["upload"] and s["always"] and s["strict"] for s in job["steps"])
        job["credit"] = any(s["credit"] and s["always"] for s in job["steps"])
    return jobs


def check_shape(record):
    if not isinstance(record, dict) or set(FIELDS) - set(record):
        return f"needs the fields {list(FIELDS)}"
    if not all(isinstance(record[key], str) and record[key] for key in ("id", "property", "transition", "invariant", "job")):
        return "id, property, transition, invariant and job need text"
    if not isinstance(record["tests"], list) or not all(isinstance(t, str) for t in record["tests"]):
        return "tests must be a list of names"
    if not isinstance(record["controls"], list) or not all(
        isinstance(c, dict) and isinstance(c.get("test"), str) and "violation" in c for c in record["controls"]
    ):
        return "controls must be a list of {test, violation}"
    if "module" in record and not isinstance(record["module"], str):
        return "module must be a name"
    if not record["tests"] and not record["controls"] and record["job"] not in FUZZ:
        return "needs a test or a control"
    return None


def known_tests(inventory, record):
    """Return (declared, ignored) names the record's job and module may cite."""
    if record["job"] == "loom":
        module = inventory["loom"].get(record.get("module"))
        if module is None:
            return set(), set()
        return set(module["tests"]), set(module["ignored"])
    if record["job"] in PROFILED:
        return set(checker_declaration(record["job"])["profiles"].get(record.get("module"), [])), set()
    if record["job"] in CHECKER_JOBS:
        return set(read_json(CHECKER_JOBS[record["job"]])["tests"]), set()
    if record["job"] in MIRI_SELECTIONS:
        return set(inventory[MIRI_SELECTIONS[record["job"]]]["tests"]), set(inventory["miri"]["ignored"])
    if record["job"] in QUALIFIED:
        return set(load_select_tests().selection_of(inventory["qualified"][record["job"]])), set()
    if record["job"] == "qemu":
        return set(inventory["qemu"]["tests"]), set()
    if record["job"] == "asan":
        asan = inventory["asan"]
        return (
            {name for witnesses in asan["required"].values() for name in witnesses["tests"]},
            {name for names in asan["ignored"].values() for name in names},
        )
    declared = {
        name for crate in inventory["ordinary"].values()
        for witnesses in crate.get("required", {}).values() for name in witnesses["tests"]
    }
    ignored = {name for crate in inventory["ordinary"].values() for names in crate["ignored"].values() for name in names}
    return declared, ignored


@cache
def module_scopes(test, crate="*"):
    """Return the text of every module scope under `crate` (any crate by default) that the test's module path
    resolves to in full from one of the crate's roots, one direct declaration at a time, each beside the crate
    directory it came from. A path that resolves in no crate returns none."""
    parents = tuple(test.split("::")[:-1])
    scopes = []
    for source in sorted(ROOT.glob(f"crates/{crate}/src")):
        for root, directory in crate_roots(source):
            scopes += [(text, source) for text, left in module_texts(root, directory, parents) if not left]
    return tuple(scopes)


def module_file(test, crate="*"):
    """Return the text of the first module scope that the test's module path resolves to, with no names left, or
    an empty text beside the unresolved names."""
    scopes = module_scopes(test, crate)
    return (scopes[0][0], ()) if scopes else ("", tuple(test.split("::")[:-1]))


def crate_roots(source):
    """Return each crate root of the package whose sources are `source`, `lib.rs` then `main.rs`: the root file's
    text with each `include!` of a sibling file in its code replaced by that file's text, beside the directory its
    modules resolve under. An `include!` line inside a comment or a literal stays as written. A package with a
    library and a binary has both roots, and a directory with neither has none."""
    roots = []
    for name in ("lib.rs", "main.rs"):
        path = source / name
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            code = masked(text)
            include = r'^[ \t]*(?:::)?(?:core::|std::)?include!\("([^"/]+)"\);'
            text = re.sub(
                include,
                lambda m, code=code: (source / m.group(1)).read_text(encoding="utf-8") if code[m.end() - 1] == ";" else m.group(0),
                text, flags=re.M)
            roots.append((text, source))
    return roots


# The attributes before a `mod` declaration in masked code, each of which may wrap across lines and nest brackets
# one level deep.
ATTRIBUTES = r"(?:#\[(?:[^\[\]]|\[[^\[\]]*\])*\]\s*)*"
PATH_ATTRIBUTE = r'#\[\s*path\s*=\s*(?:r#*)?"([^"]+)"#*\s*\]'
# `#[cfg(any())]` holds for no build, so rustc compiles nothing under a declaration that carries it.
NEVER_COMPILED = r"#\[\s*cfg\s*\(\s*any\s*\(\s*\)\s*\)\s*\]"


def module_texts(text, directory, names, file_dir=None, inline=False):
    """Return `(scope, names left)` for each module scope that the module `names` lead to from the scope `text`,
    whose child modules resolve under `directory`.

    Each name resolves through every declaration of it made directly in the current scope, outside any inline `mod`
    block, comment or literal: an inline `mod name {` block becomes the scope, its children resolving under
    `directory/name` or under its `#[path]` directory; a `#[path = "file"] mod name;` declaration moves the scope
    into that file, relative to the declaring file's directory, or to the children's directory inside an inline
    block, and its children resolve beside it; and a plain `mod name;` moves it into `directory/name.rs` or
    `directory/name/mod.rs`, whose children resolve under `directory/name`. A declaration's attributes are read
    from its code, each across the lines it wraps over, so an attribute inside a comment is none. A declaration
    whose path override this reader cannot parse, as under `cfg_attr`, leads to a scope it cannot read, returned as
    an empty text with no names left. A declaration whose file is missing, whose block has no closing brace, or
    which carries `#[cfg(any())]` leads nowhere; a name with no declaration that leads somewhere ends the walk with
    the names left."""
    file_dir = directory if file_dir is None else file_dir
    if not names:
        return [(text, ())]
    found = []
    for kind, path in module_declarations(text, names[0]):
        if kind == "unreadable":
            found.append(("", ()))
            continue
        base = directory if inline else file_dir
        if isinstance(kind, tuple):
            opened, closed = kind
            child = base / path if path else directory / names[0]
            found += module_texts(text[opened + 1:closed - 1], child, names[1:], file_dir, True)
        elif path:
            target = base / path
            if target.is_file():
                found += module_texts(target.read_text(encoding="utf-8"), target.parent, names[1:], target.parent)
        else:
            files = [file for file in (directory / f"{names[0]}.rs", directory / names[0] / "mod.rs") if file.is_file()]
            if files:
                found += module_texts(files[0].read_text(encoding="utf-8"), directory / names[0], names[1:], files[0].parent)
    return found or [(text, names)]


@cache
def module_declarations(text, name):
    """Return each declaration of the module `name` made directly in the scope `text`, in source order, as
    `(kind, path)`, for `module_texts` to follow: kind `"unreadable"` for a path override this reader cannot parse,
    the `(opened, closed)` brace span of an inline block, or `"file"` for a declaration ending in `;`, beside the
    `#[path]` value it carries or None. A declaration inside a comment, a literal or an inline `mod` block with a
    matched closing brace is left out, and so is one under `#[cfg(any())]`. The unreadable-override check comes
    before the closing-brace check, so an unreadable override is listed even on a block with no closing brace,
    and a readable block with no closing brace is left out. The answer depends on the text alone."""
    code = masked(text)
    header = pattern(r"^[ \t]*(" + ATTRIBUTES + r")(?:pub(?:\([^)]*\))?\s+)?mod\s+" + re.escape(name) + r"\s*(;|\{)",
                     re.MULTILINE)
    modules = module_spans(text)
    found = []
    for declared in header.finditer(code):
        if any(opened < declared.start() < closed for opened, closed in modules):
            continue
        if re.search(NEVER_COMPILED, declared.group(1)):
            continue
        attributes = text[declared.start(1):declared.end(1)]
        path = next((found for found in re.finditer(PATH_ATTRIBUTE, attributes)
                     if code[declared.start(1) + found.start()] == "#"), None)
        if path is None and re.search(r"\bpath\b", code[declared.start(1):declared.end(1)]):
            found.append(("unreadable", None))
            continue
        if declared.group(2) == "{":
            opened = declared.end() - 1
            closed = next((end for start, end in modules if start <= opened < end), None)
            if closed is None:
                continue
            found.append(((opened, closed), path.group(1) if path else None))
        else:
            found.append(("file", path.group(1) if path else None))
    return tuple(found)


@cache
def pattern(source, flags=0):
    """Return `source` compiled with `flags`, once per process for each pattern text."""
    return re.compile(source, flags)


@cache
def rust_lexer():
    """Return the Rust comment and literal lexer of scripts/judge-rc11.py."""
    return load_script("judge_rc11", Path(__file__).resolve().parent / "judge-rc11.py").rust_lexemes


@cache
def masked(text):
    """Return `text` with every comment and the contents of every string and char literal replaced by spaces, line
    breaks kept, so offsets into it are offsets into `text` and only code matches a pattern."""
    out = list(text)
    lexemes = rust_lexer()
    for _, start, end in lexemes(text):
        for index in range(start, end):
            if out[index] != "\n":
                out[index] = " "
    return "".join(out)


def source_of(test, crate="*"):
    """Return the text of the innermost module scope, a module file or the body of an inline `mod` block, that the
    test's module path resolves to from a crate root, or an empty text for a path that resolves nowhere."""
    return module_file(test, crate)[0]


def spans(source, header):
    """Yield the (start, end) span of each item whose header `header` matches in the code of `source`, from its
    attributes through its closing brace, counting braces outside comments and literals."""
    code = masked(source)
    yield from closed_items(code, (found.span() for found in pattern(header, re.M).finditer(code)))


def fn_spans(source, name):
    """Yield the span `spans(source, fn_header(name))` yields for each fn `name` of `source`, its header found
    by `fn_matches`."""
    code = masked(source)
    yield from closed_items(code, fn_matches(name, code))


def closed_items(code, headers):
    """Yield (start, end) for each header `(start, end)` of `headers` whose first `{` at or after the header's end
    has a closing brace in `code`: the header's start through that brace."""
    closes = brace_closes(code)
    for opened, ended in headers:
        start = code.find("{", ended)
        if start in closes:
            yield opened, closes[start] + 1


@cache
def brace_closes(code):
    """Return the offset of the brace that closes each opening brace of `code` that one closes, keyed by the
    opening brace's offset: the first `}` after it at which the braces between them balance. The map is read-only,
    so every caller reads the one cached for the text."""
    closes, opened = {}, []
    for brace in re.finditer(r"[{}]", code):
        if brace.group() == "{":
            opened.append(brace.start())
        elif opened:
            closes[opened.pop()] = brace.start()
    return MappingProxyType(closes)


# The header of a fn up to its name: its attribute lines, captured as group 1, then its signature.
FN_PREFIX = r"^((?:[ \t]*#\[[^\n]*\]\n)*)[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+"
# `FN_PREFIX` followed by the fn's name, captured as group 2.
FN_WORD = FN_PREFIX + r"(\w+)"


def fn_header(name):
    """Return the header pattern of the fn `name`: its attribute lines, captured as group 1, then its signature."""
    return FN_PREFIX + re.escape(name) + r"\b"


@cache
def fn_headers(code):
    """Return, for each name, the (start, end) of every line start in `code` where `FN_PREFIX` matches and the
    word after it is that name, in offset order. The prefix reads each attribute line, the whitespace, `pub`,
    `async` and `fn` in one way only, so at each line start it ends at one offset, and `fn_header(name)` matches
    there exactly when the word at that offset is `name`. The map and its sequences are read-only."""
    headers = {}
    for found in pattern(r"^(?=" + FN_WORD[1:] + r")", re.M).finditer(code):
        headers.setdefault(found.group(2), []).append((found.start(), found.end(2)))
    return MappingProxyType({name: tuple(offsets) for name, offsets in headers.items()})


def fn_matches(name, code):
    """Yield the (start, end) of each match `re.finditer(fn_header(name), code, re.M)` yields. For a name of word
    characters they come from `fn_headers`, taking each match that starts at or after the end of the one before."""
    if not re.fullmatch(r"\w+", name):
        yield from (found.span() for found in pattern(fn_header(name), re.M).finditer(code))
        return
    ended = 0
    for start, end in fn_headers(code).get(name, ()):
        if start >= ended:
            yield start, end
            ended = end


MODULE_HEADER = r"^[ \t]*(?:#\[[^\n]*?\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*(?=\{)"


@cache
def module_spans(scope):
    """Return inline module spans shared by tests in the same immutable source text."""
    return tuple(spans(scope, MODULE_HEADER))


@cache
def direct_items(scope, name):
    """Return the text of each fn `name` that `scope` declares directly, outside any inline `mod` block it holds;
    the answer depends on the two texts alone."""
    modules = module_spans(scope)
    return tuple(scope[start:end] for start, end in fn_spans(scope, name)
                 if not any(opened < start < closed for opened, closed in modules))


def direct_tests(scope, name):
    """Yield the text of each `#[test]` fn `name` that `scope` declares directly. For a name of word characters
    one shared pattern reads each item's header, and the word it captures must be the name, which is where
    `fn_header(name)` matches."""
    word = re.fullmatch(r"\w+", name) is not None
    header = pattern(FN_WORD, re.M) if word else pattern(fn_header(name), re.M)
    for item in direct_items(scope, name):
        match = header.match(item)
        if match is not None and (not word or match.group(2) == name) \
                and re.search(r"^[ \t]*#\[test\]$", match.group(1), re.M):
            yield item


@cache
def declares_test(test, crate):
    """Return whether `crate`'s sources hold the test as a `#[test]` fn under its module path.

    `module_scopes` resolves the module path from the crate root, and the
    fn with `#[test]` among its attributes is a direct item of a resolved
    scope. A path that leaves names unresolved, a production fn or method
    of the same name, a test under another module or a test of another
    crate is no witness.
    """
    name = test.rsplit("::", 1)[-1]
    return any(next(direct_tests(scope, name), None) is not None for scope, _ in module_scopes(test, crate))


@cache
def control_text(test, job=None, crate="*"):
    """Return the named test fn's item text: its attributes, signature and body.

    A control's violation text is bound to the control itself, so a
    `should_panic(expected = ...)` attribute or an assertion in the body
    satisfies admission and text asserted elsewhere in the module does not.
    The fn is a direct item of the scope its module path resolves to in
    `crate`; with no crate named, the path must resolve to a fn in one
    crate only, and a path that leaves names unresolved, or a nested fn of
    the same name, supplies no text. Every scope the path reaches in that
    crate must define the fn as a direct item, and every definition must
    be the same text: one file that two declarations reach supplies its
    fn, while definitions that differ, as under exclusive `cfg`
    predicates, a reached scope with no direct fn of that name, and a
    declaration whose path override the reader cannot parse supply no
    text. The reader evaluates no `cfg` predicate and expands no macro
    and, outside a crate root, no `include!`. A fn that one of those
    supplies in the same scope as a visible fn of the name is not seen,
    and the visible fn supplies the text; review of the committed
    sources covers that layout, and the lane's receipt records only that
    a fn of the name ran and passed. The fn's own attributes are read
    one per line.
    A TLC control is a runner case, and its text is the outcome the case
    declares; a Quint control's is its declared outcome and the property
    it checks, which the control's violation text must equal. Either judge refuses a runner it cannot load, and
    that refusal is a crash. The text comes from committed sources, so one process reads
    each control once however many records cite it.
    """
    if job in ("tlc", "quint"):
        cases = runner_cases(job)
        if test not in cases:
            return ""
        case = cases[test]
        return case.expected if job == "tlc" else f"{case.expected} {case.invariant or case.temporal}"
    if job in TAG_COMPARE:
        return next((site.get("flags", "") for site in read_json(CHECKER_JOBS[job])["sites"] if site["site"] == test), "")
    name = test.rsplit("::", 1)[-1]
    held = [(direct_items(scope, name), source) for scope, source in module_scopes(test, crate)]
    crates = {source for items, source in held if items}
    texts = {item for items, _ in held for item in items}
    if len(crates) != 1 or len(texts) != 1 or any(not items for items, source in held if source in crates):
        return ""
    return texts.pop()


# The cases of each checker runner that the running `admit` pass has read, keyed by job, or None outside a pass.
# The sources stay unchanged for the length of a pass, so a pass loads each runner at most once. A later pass loads
# a runner only for a control that the process-wide `control_text` cache has yet to answer.
PASS_CASES = None


def runner_cases(job):
    """Return the cases of checker lane `job`'s runner keyed by name, read at most once per `admit` pass and on
    every call outside one. Callers read the map and its cases. A judge refusal to load the runner is a `Crash`."""
    if PASS_CASES is not None and job in PASS_CASES:
        return PASS_CASES[job]
    cases = judge_call(job, lambda judge: {case.name: case for case in judge.runner().cases()})
    if PASS_CASES is not None:
        PASS_CASES[job] = cases
    return cases


def admit(catalog, inventory, jobs):
    """Return the catalog's refusals against the inventory and the workflow jobs. For the length of this call,
    `PASS_CASES` holds each checker runner's cases once loaded; it is None again when the call returns or raises."""
    global PASS_CASES
    PASS_CASES = {}
    try:
        return catalog_refusals(catalog, inventory, jobs)
    finally:
        PASS_CASES = None


def catalog_refusals(catalog, inventory, jobs):
    """Return the refusals `admit` reports, census refusals excluded."""
    refusals, seen, covered = [], set(), set()

    def refuse(code, record, reason):
        refusals.append({"code": code, "record": record, "reason": reason})

    if catalog.get("baseline") != inventory["baseline"]:
        refuse("baseline-mismatch", None, f"catalog baseline {catalog.get('baseline')!r}, inventory {inventory['baseline']}")
    gate = jobs.get(GATE, {"needs": []})
    derived = {
        name: crate for crate, declaration in inventory["ordinary"].items()
        for witnesses in declaration.get("required", {}).values() if "catalog" in witnesses for name in witnesses["tests"]
    }
    for index, record in enumerate(catalog.get("records", [])):
        problem = check_shape(record)
        if problem:
            refuse("malformed-record", record.get("id") if isinstance(record, dict) else index, problem)
            continue
        covered.add((record["job"], record.get("module")))
        name = record["id"]
        if name in seen:
            refuse("duplicate-record", name, "id repeats an earlier record")
        seen.add(name)
        if record["job"] not in jobs or record["job"] == GATE:
            refuse("missing-job", name, f"job {record['job']!r} is not a workflow job")
        else:
            for reason in structure_gaps(record["job"], jobs[record["job"]], gate):
                refuse("gate-structure", name, reason)
        if record["job"] in ("loom", *PROFILED) and record.get("module") not in modules_of(record["job"], inventory):
            refuse("nonexistent-test", name, f"module {record.get('module')!r} is not among the {record['job']} modules {modules_of(record['job'], inventory)}")
        declared, ignored = known_tests(inventory, record)
        for test in [*record["tests"], *(c["test"] for c in record["controls"])]:
            if test in ignored:
                refuse("ignored-required-test", name, f"{test} is a declared ignore")
            elif test not in declared:
                refuse("nonexistent-test", name, f"{test} is not in the inventory for job {record['job']}")
            elif test in derived and not declares_test(test, derived[test]):
                refuse("nonexistent-test", name, f"{test} is no #[test] fn under its module path in the {derived[test]} sources")
        for control in record["controls"]:
            if not isinstance(control["violation"], str) or not control["violation"].strip():
                refuse("missing-violation", name, f"control {control['test']} names no violation text")
            elif control["test"] in declared and (control["violation"] != control_text(control["test"], record["job"])
                                                  if record["job"] == "quint"
                                                  else control["violation"] not in control_text(
                                                      control["test"], record["job"], derived.get(control["test"], "*"))):
                refuse("missing-violation", name, f"{control['violation']!r} differs from the outcome of {control['test']}"
                       if record["job"] == "quint" else
                       f"{control['violation']!r} is absent from the attributes and body of {control['test']}")
        if not isinstance(record["reference"], str) or not record["reference"].strip():
            refuse("missing-reference", name, "the record names no independent reference")
    lanes = [(job, module) for job in jobs if jobs[job]["credit"] and job not in ENVELOPED for module in modules_of(job, inventory)]
    for job, module in lanes:
        if (job, module) not in covered:
            lane = f"{job} {module}" if module else job
            refuse("uncovered-lane", lane, f"no record names the credited lane {lane}; its credit step would credit nothing")
    # An enveloped domain credits itself, so its job's structure is checked here rather than through a record.
    for name in ENVELOPED:
        if name not in jobs:
            refuse("missing-job", name, f"the enveloped domain {name} has no workflow job")
            continue
        for reason in structure_gaps(name, jobs[name], gate):
            refuse("gate-structure", name, reason)
    return refusals


def census_judgment(catalog, inventory):
    """Return the atomic-site census's refusals against this catalog's shape-valid records and the inventory, each
    under the code `census`, and the needs-kernel obligations it reports. `admit` reports the malformed records."""
    classify = load_script("classify_atomics", ROOT / "scripts/classify-atomics.py")
    admitted = {**catalog, "records": [r for r in catalog.get("records", []) if check_shape(r) is None]}
    refusals, _, reported = classify.Census(admitted, inventory, control_text).judge(read_json(classify.CENSUS))
    return [{"code": "census", "record": r["surface"], "reason": f"{r['code']}: {r['reason']}"} for r in refusals], reported


SOURCE_BYTES = 8 << 20
REGISTER_BYTES = 1 << 20


class Unreadable(Crash):
    """A source a judgment reads that is no regular UTF-8 file of at most its byte bound under its directory."""


def bounded_read(descriptor, limit):
    """Return the bytes of the open file `descriptor`, which it closes; ValueError when the descriptor names no
    regular file or the file holds more than `limit` bytes."""
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("it is no regular file")
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"it holds more than {limit} bytes")
    return data


@cache
def bounded_text(path, under, limit=SOURCE_BYTES):
    """Return the UTF-8 text of the file `path` names and its resolved path. The path resolves, through any link, to
    a file under the directory `under`, which is a regular file of at most `limit` bytes on the descriptor the text
    is read from; any other path raises Unreadable. One process reads each path once."""
    try:
        file = Path(path).resolve(strict=True)
        if not file.is_relative_to(Path(under).resolve(strict=True)):
            raise ValueError(f"it resolves outside {under}")
        data = bounded_read(os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), limit)
        return data.decode("utf-8"), file
    except (OSError, ValueError, RuntimeError) as error:
        raise Unreadable(f"{path} cannot be read: {error}") from error


def rust_views(source, path):
    """Return the code of the Rust `source`, with each comment blanked to spaces, its masked code, with each string
    and char literal also blanked after its first character, and the value of each string literal by its offset:
    the text between its quotes, escapes as written. Newlines stay, so offsets and lines index `source`. Comments
    nest as rustc nests them; a block comment that never closes raises Unreadable for `path`."""
    code, masked, strings, start = [], [], {}, 0
    for kind, begin, end in rust_lexer()(source):
        if kind == "unclosed":
            raise Unreadable(f"{path}:{source.count(chr(10), 0, begin) + 1} opens a block comment that never closes")
        blank = re.sub(r"[^\n]", " ", source[begin:end])
        if kind == "comment":
            code += [source[start:begin], blank]
            masked += [source[start:begin], blank]
        else:
            code.append(source[start:end])
            masked += [source[start:begin + 1], blank[1:]]
            if kind == "string":
                raw = re.fullmatch(r'r(#*)"(.*)"\1', source[begin:end], re.S)
                strings[begin] = raw[2] if raw else source[begin + 1:end - 1]
        start = end
    return "".join([*code, source[start:]]), "".join([*masked, source[start:]]), strings


@cache
def crate_source(path, under):
    """Return the resolved path, text, code, masked code and string values of the Rust file `path` under the
    directory `under`, read once by `bounded_text`."""
    text, file = bounded_text(path, under)
    return (file, text, *rust_views(text, file))


ATTRIBUTE = r"#\[(?:[^\[\]]|\[(?:[^\[\]]|\[[^\[\]]*\])*\])*\]"
VISIBILITY = r"(?:pub(?:\([^)]*\))?\s+)?"


BRACE = re.compile(r"[{}]")


def closing(masked, opened):
    """Return the offset past the brace that closes the one at `opened` in masked code, or None."""
    depth = 0
    for brace in BRACE.finditer(masked, opened):
        depth += 1 if brace[0] == "{" else -1
        if depth == 0:
            return brace.end()
    return None


ITEM = re.compile(rf"^((?:[ \t]*(?:{ATTRIBUTE}[ \t]*)*\n)*)[ \t]*{VISIBILITY}(?:(?:async\s+)?(fn)|(mod))\s+(\w+)\b"
                  r"\s*([;{]?)", re.M)


@cache
def item_index(masked):
    """Return the fn and `mod` items of masked code by kind and name, each the match of its header: its attribute
    lines, captured as group 1, among which blank lines may stand, then its signature, and for a `mod` the `;` or
    `{` that ends its header as group 5."""
    index = {}
    for match in ITEM.finditer(masked):
        index.setdefault((match[2] or match[3], match[4]), []).append(match)
    return index


@cache
def inline_modules(masked):
    """Return the span of each inline `mod` block of masked code, from its header match through its closing brace.
    Masked code holds no comment and no literal content, so every brace counted is code."""
    return tuple((match.start(), closing(masked, match.end(5) - 1) or len(masked))
                 for (kind, _), matches in item_index(masked).items() if kind == "mod"
                 for match in matches if match[5] == "{")


UNBUILT = re.compile(r"#\[\s*cfg\s*\(\s*(?:any\s*\(\s*\)|false)\s*\)\s*\]")


def direct_matches(masked, scope, kind, name):
    """Yield the header match of each `kind` item `name`, `fn` or `mod`, that the scope `(start, end)` of masked
    code declares directly: inside the scope and outside every inline `mod` block nested in it. An item under
    `#[cfg(any())]` or `#[cfg(false)]` is compiled by no build, so cargo lists no test under it and it is skipped."""
    start, end = scope
    modules = inline_modules(masked)
    for match in item_index(masked).get((kind, name), ()):
        at = match.start()
        if start <= at < end and not any(start <= opened < at < closed for opened, closed in modules) \
                and not UNBUILT.search(match[1]):
            yield match


INCLUDE = r'^[ \t]*(?:(?:::)?(?:core|std)::)?include!\(\s*(?=")'


def declaration(state, name, under, depth=0):
    """Return the state of the walk at the `mod` item `name` that the scope of `state` declares directly, or that a
    file it textually includes with `include!` declares, and that item's match; None when neither does."""
    file, code, masked, scope, directory, base = state
    match = next((match for match in direct_matches(masked, scope, "mod", name) if match[5]), None)
    if match is not None:
        return state, match
    modules = inline_modules(masked)
    for included in re.compile(INCLUDE, re.M).finditer(masked, *scope):
        if any(scope[0] <= opened < included.start() < closed for opened, closed in modules):
            continue
        named = re.compile(r'"([^"]+)"\s*\)\s*;').match(code, included.end())
        if named and depth < 4:
            other, _, other_code, other_masked, _ = crate_source(file.parent / named[1], under)
            found = declaration((other, other_code, other_masked, (0, len(other_masked)), directory, base), name,
                                under, depth + 1)
            if found:
                return found
    return None


def module_walk(root, names, under, owner=True):
    """Return the file and the scope `(start, end)` of its masked code that the module path `names` names from the
    file `root`, with the inline modules the walk entered in that file; None when a module is undeclared.

    Each name is a `mod` item the scope before declares directly, itself or through a file it includes with
    `include!`: an inline block, the file `#[path]` names, or its `<name>.rs` or `<name>/mod.rs`, looked up as
    rustc looks it up. A file module of a crate root, a `mod.rs` or a `#[path]` file (an `owner`) lies beside it;
    one of any other file lies in the directory of that file's stem. A `#[path]` outside an inline block is
    relative to its file's directory, and inside one to the module directory the blocks name. Every file read lies
    under `under`.
    """
    file, _, code, masked, _ = crate_source(root, under)
    state = (file, code, masked, (0, len(masked)), file.parent if owner else file.parent / file.stem, file.parent)
    inline = []
    for name in names:
        found = declaration(state, name, under)
        if found is None:
            return None
        (file, code, masked, _, directory, base), match = found
        if match[5] == "{":
            directory = directory / name
            state = (file, code, masked, (match.end(5) - 1, closing(masked, match.end(5) - 1) or len(masked)),
                     directory, directory)
            inline.append(name)
            continue
        moved = re.search(r'#\[path\s*=\s*"([^"]+)"\s*\]', code[match.start(1):match.end(1)])
        candidates = [base / moved[1]] if moved else [
            path for path in (directory / f"{name}.rs", directory / name / "mod.rs") if os.path.lexists(path)]
        if len(candidates) != 1:
            return None
        file, _, code, masked, _ = crate_source(candidates[0], under)
        owner = bool(moved) or file.name == "mod.rs"
        state = (file, code, masked, (0, len(masked)), file.parent if owner else file.parent / file.stem, file.parent)
        inline = []
    return state[0], state[3], tuple(inline)


def target_roots(crate_dir):
    """Return the library and binary roots of the crate directory `crate_dir` that exist, in that order."""
    return [path for path in (crate_dir / "src/lib.rs", crate_dir / "src/main.rs") if path.is_file()]


def scope_declares_test(found, leaf, under):
    """Whether the scope `found` of `module_walk` declares a `#[test]` fn `leaf` directly, read in its masked code."""
    masked = crate_source(found[0], under)[3]
    return any(re.search(r"^[ \t]*#\[test\][ \t]*$", match[1], re.M)
               for match in direct_matches(masked, found[1], "fn", leaf))


INTAKE = ROOT / "verification/intake"
INTAKE_KINDS = ("escape", "incident", "contract-change", "disagreement")
ESCAPE_CLASSES = ("safety bug", "correctness bug")
AGREED_PLACES = ("obligation", "rule", "spec", "documentation", "model", "pull-request")
CAUSE_EVIDENCE = {
    "workload": ("steps", "sweep"), "environment": ("gap", "standing_check"),
    "ordering": ("constraint", "sweep"), "property": ("unjudged", "sweep"),
}
CATCH_FIELDS = ("history", "rule", "tally")
FIX_STATES = ("merged", "not-delivered")
ACTION_PLACES = ("obligation", "rule", "model")
MODEL_SUFFIXES = {"tla": ".tla", "quint": ".qnt"}
MODEL_JOBS = {"tla": "tlc", "quint": "quint"}
WORLD_TESTS = ROOT / "crates/kestrike/src/net/world_tests"
TEST_ID = re.compile(r"[A-Za-z_]\w{0,199}(?:::[A-Za-z_]\w{0,199})*")
DIGEST = re.compile(r"(?<![0-9A-Za-z])[0-9a-f]{64}(?![0-9A-Za-z])")
RUN_RANGE = re.compile(r"([0-9]{1,18})\.\.([0-9]{1,18})")
NAME = re.compile(r"[A-Za-z_]\w*")


def nonblank(value):
    return isinstance(value, str) and value.strip() != ""


def repo_relative(path):
    """Whether `path` is a nonblank path relative to the checkout without a `..` step."""
    return nonblank(path) and not Path(path).is_absolute() and ".." not in Path(path).parts


def repo_file(path, roots=None):
    """Return the regular file that the relative path `path` names in the checkout, under one of `roots` when
    given, resolved through any link; None for a path `repo_relative` refuses, a path whose resolved file lies
    outside the checkout or that root, or a path that names no regular file."""
    parts = Path(path).parts if repo_relative(path) else ()
    if not parts or (roots and parts[0] not in roots):
        return None
    try:
        base = ROOT.resolve(strict=True)
        file = (ROOT / path).resolve(strict=True)
        inside = file.is_relative_to(base / parts[0] if roots else base)
        return file if inside and file.is_file() else None
    except (OSError, ValueError, RuntimeError):
        return None


def array_bodies(masked, pattern):
    """Return the `(start, end)` span of the bracketed body of each array whose declaration `pattern` matches in
    masked code, by the name its group 1 captures."""
    bodies = {}
    for match in re.finditer(pattern, masked):
        depth = 0
        for index in range(match.end() - 1, len(masked)):
            depth += {"[": 1, "]": -1}.get(masked[index], 0)
            if depth == 0:
                bodies[match[1]] = (match.end(), index)
                break
    return bodies


def fn_body(masked, name):
    """Return the masked text of the body of the fn `name`, or the empty string when the code defines none."""
    header = re.search(rf"^[ \t]*{VISIBILITY}fn {re.escape(name)}\b[^{{;]*\{{", masked, re.M)
    end = closing(masked, header.end() - 1) if header else None
    return masked[header.end():end] if header and end else ""


@cache
def rule_texts():
    """Return the rule texts: the string literals of each `&[&str]` array of the narrator's `rules.rs` that its
    `scoped` catalog names, outside comments."""
    _, _, _, masked, strings = crate_source(WORLD_TESTS / "narrate/rules.rs", WORLD_TESTS)
    arrays = array_bodies(masked, r"\bconst (\w+): &\[&str\] = &\[")
    listed = set(re.findall(r"\b[A-Z][A-Z0-9_]*\b", fn_body(masked, "scoped"))) & set(arrays)
    return frozenset(value for at, value in strings.items()
                     if any(arrays[name][0] <= at < arrays[name][1] for name in listed))


@cache
def history_names():
    """Return the quoted history names, so a history resolves by its name without a build: the string literal each
    constructor call passes first inside a `[History; N]` array that `every` or `scenarios` of `histories.rs`
    chains, read from the file its module path declares. A constructor is a fn of `histories.rs` or of a chained
    file whose first parameter is `name: &'static str` and that returns a `History`. Text inside comments is
    skipped, and a chained source that cannot be read is a crash."""
    root = WORLD_TESTS / "histories.rs"
    masked = crate_source(root, WORLD_TESTS)[3]
    chained = {}
    for path, name in re.findall(r"\b((?:\w+::)*)([A-Z][A-Z0-9_]*)\s*\.iter\(\)",
                                 fn_body(masked, "every") + fn_body(masked, "scenarios")):
        found = module_walk(root, [part for part in path.split("::") if part], WORLD_TESTS, owner=False)
        if found is None:
            raise Crash(f"histories.rs chains {path}{name}, whose module it does not declare")
        chained.setdefault(found[0], set()).add(name)
    sources = {file: crate_source(file, WORLD_TESTS) for file in [root.resolve(), *chained]}
    constructors = {name for source in sources.values() for name in re.findall(
        r"\bfn (\w+)\(\s*name: &'static str[^)]*\)\s*->\s*History\b", source[2])}
    if not constructors:
        return frozenset()
    call = re.compile(rf"\b(?:{'|'.join(sorted(constructors))})\(\s*(?=\")")
    names = set()
    for file, arrays in chained.items():
        _, _, _, masked, strings = sources[file]
        bodies = array_bodies(masked, r"\bconst (\w+): \[History; \d+\] = \[")
        for name in arrays:
            if name not in bodies:
                raise Crash(f"histories.rs chains {name}, which {file.name} declares as no [History; N] array")
            start, end = bodies[name]
            names.update(strings[match.end()] for match in call.finditer(masked, start, end))
    return frozenset(names)


@cache
def model_runner(root):
    """Return the runner `root/check.py` of the models under `root`, `tla` or `quint`, as the judge of its lane loads
    it, once; a runner that cannot load is a crash."""
    job = MODEL_JOBS[root]
    try:
        judge = load_script(f"judge_{job}", CHECKER_JUDGES[job])
        return judge.runner()
    except Crash:
        raise
    except (Exception, SystemExit) as error:
        raise Crash(f"{root}/check.py cannot be loaded: {error}") from error


QUINT_LEXEME = re.compile(r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*.*?(?:\*/|\Z)', re.S)
QUINT_DEFINITION = r"^ {2}(?:pure )?(?:val|temporal) (\w+)\b"
# A definition's body runs to the next line that opens at an indent of two spaces or less with a character other
# than a closing brace, or to a closing brace at column 0, which ends the module.
QUINT_BODY = re.compile(r"^ {2}(?:pure )?(?:val|temporal) (\w+)(?:\s*:[^=\n]*)? = (.*?)(?=^(?:\}| ?[^\s}]| {2}[^\s}])|\Z)",
                        re.M | re.S)


def quint_code(source):
    """Return Quint `source` with each `//` and `/* */` comment blanked to spaces, newlines kept; a comment marker
    inside a string literal stays."""
    return QUINT_LEXEME.sub(lambda token: token[0] if token[0][0] == '"' else re.sub(r"[^\n]", " ", token[0]), source)


def top_level(text, separator):
    """Return the pieces of `text` between each `separator` outside parentheses, brackets and braces, stripped."""
    pieces, depth, start, at = [], 0, 0, 0
    while at < len(text):
        depth += {"(": 1, "[": 1, "{": 1, ")": -1, "]": -1, "}": -1}.get(text[at], 0)
        if depth == 0 and text.startswith(separator, at):
            pieces.append(text[start:at].strip())
            start = at = at + len(separator)
            continue
        at += 1
    return [*pieces, text[start:].strip()]


def outside(text):
    """Return `text` without what its parentheses, brackets and braces enclose."""
    kept, depth = [], 0
    for char in text:
        depth += {"(": 1, "[": 1, "{": 1}.get(char, 0)
        if depth == 0:
            kept.append(char)
        depth -= {")": 1, "]": 1, "}": 1}.get(char, 0)
    return "".join(kept)


def quint_conjuncts(body):
    """Return the bare-name operands of a definition body that is a conjunction: a chain `a and b and ...`, whose
    top level holds no other connective, conditional or binding, or a block `and { a, b, ... }`. Qualified,
    parenthesized and other operands are skipped."""
    block = re.fullmatch(r"and \{(.*)\}", body)
    if block:
        pieces = top_level(block[1], ",")
    else:
        pieces = top_level(body, " and ")
        if any(re.search(r"\b(?:or|implies|iff|xor|if|else|match|val|def|nondet|pure|all|any)\b", outside(piece))
               for piece in pieces):
            return []
    return [piece for piece in pieces if NAME.fullmatch(piece)]


def quint_reached(scope, extra, name):
    """Return the names `name` reaches through the conjunctions of the definitions of `extra`, a case's added
    definitions, and `scope`, the model text the case checks, each comment-blanked."""
    bodies = {}
    for text in (scope, extra):
        bodies.update((match[1], " ".join(match[2].split())) for match in QUINT_BODY.finditer(text))
    found, pending = set(), [name]
    while pending:
        name = pending.pop()
        if name not in found:
            found.add(name)
            pending += quint_conjuncts(bodies.get(name, ""))
    return found


def unmutated(runner, case, source):
    """Whether the Quint case runs on committed text: it applies no mutation, and every model copy its inputs hold
    equals the committed file of that name."""
    if case.mutations:
        return False
    copies = runner.inputs(case, source)
    return all(text == bounded_text(source / name, source)[0] for name, text in copies.items() if (source / name).is_file())


def quint_properties(file, text):
    """Return the properties the Quint runner checks in a passing `tlc` or `simulate` case on committed text, each a
    definition of the model `file`: the case's invariant or temporal property and the conjuncts it reaches. A case of
    family F checks `F.qnt`, and a `join` case its projection's module of `joins.qnt`."""
    runner, source, code = model_runner("quint"), file.parent, quint_code(text)
    found = set()
    for case in runner.cases():
        if case.command not in ("tlc", "simulate") or case.expected != "ok" or not (
                case.family == file.stem or (case.family == "join" and file.name == "joins.qnt")):
            continue
        if not unmutated(runner, case, source):
            continue
        scope = runner.join_checks.module_text(code, runner.join_checks.projection(case)[1]["module"]) \
            if case.family == "join" else code
        defined = set(re.findall(QUINT_DEFINITION, scope, re.M))
        found |= quint_reached(scope, quint_code(case.extra), case.invariant or case.temporal) & defined
    return found


def tla_properties(file, text):
    """Return the properties the TLC runner checks in a completing case on committed text whose target or root
    module is the model `file`, each a definition of `file` as the runner reads them: the invariants and
    properties of the case's configuration, with the conjuncts of the file's `Safety` when the case checks it, less
    every name a `<-` of that configuration rebinds."""
    runner, source = model_runner("tla"), file.parent
    defined = runner.definitions(text)
    found, conjuncts = set(), None
    for case in runner.cases():
        if case.mutation or not runner.completes(case) or file.name not in (case.target, f"{case.module}.tla"):
            continue
        bounded_text(source / case.base, source)
        config = runner.configuration(case, source)
        checked = runner.checked(config)
        rebound = {operands[at - 1] for keyword, operands in runner.statements(config)
                   if keyword in ("CONSTANT", "CONSTANTS") for at, word in enumerate(operands) if word == "<-" and at}
        names = {*checked["invariants"], *checked["properties"]} - rebound
        if "Safety" in names and "Safety" in defined:
            if conjuncts is None:
                conjuncts = set(runner.safety(text) or ())
            names |= conjuncts - rebound
        found |= names
    return {name for name in found if name in defined}


@cache
def model_properties(model):
    """Return the properties the runner checks for the model file `model`, a path `<root>/<file>` of a `.tla` file
    of `tla/` or a `.qnt` file of `quint/`, in a case that passes on the committed text; None when `model` names no
    such file. A definition a case adds, a reachability witness a case expects to be violated, a property only a
    mutated or reduced copy is checked against, and a definition no passing case checks are no properties. A cited
    file that cannot be read as UTF-8 text raises Unreadable; a runner that cannot list its cases is a crash."""
    parts = Path(model).parts if repo_relative(model) else ()
    if len(parts) != 2 or parts[0] not in MODEL_SUFFIXES or Path(parts[1]).suffix != MODEL_SUFFIXES[parts[0]]:
        return None
    root = ROOT / parts[0]
    if repo_file(model, (parts[0],)) is None:
        return None
    text, file = bounded_text(root / parts[1], root)
    if file.parent != root.resolve():
        return None
    try:
        return frozenset((tla_properties if parts[0] == "tla" else quint_properties)(file, text))
    except Crash:
        raise
    except (Exception, SystemExit) as error:
        raise Crash(f"{parts[0]}/check.py cannot list the properties of {file.name}: {error}") from error


def model_gap(model, name):
    """Return why `name` is no property the runner checks for the model file `model`, or None when it is one."""
    if not isinstance(model, str):
        return f"model {model!r} is no file under tla/ or quint/ that its runner reads: a .tla file of tla/ or a .qnt file of quint/"
    try:
        properties = model_properties(model)
    except Unreadable as error:
        return f"model {model!r} cannot be read: {error}"
    if properties is None:
        return f"model {model!r} is no file under tla/ or quint/ that its runner reads: a .tla file of tla/ or a .qnt file of quint/"
    return None if name in properties else f"{name!r} is no invariant of the model {model!r}"


def regression_target(path):
    """Return the file, crate directory and target roots of the regression file `path`, a Rust file of a workspace
    package: a directory `crates/<crate>` that holds its `Cargo.toml`, which the root manifest's `crates/*` member
    glob makes a package. A `crates/<crate>/src` file's roots are the crate's library and binary roots, and a
    `crates/<crate>/tests` file's is the root of its integration test: the file itself directly under `tests/`, and
    for a file under `tests/<name>/` the root `tests/<name>/main.rs` or `tests/<name>.rs`, whichever exists; None
    for any other path."""
    file = repo_file(path)
    parts = Path(path).parts if file else ()
    if file is None or len(parts) < 4 or parts[0] != "crates" or parts[2] not in ("src", "tests") or file.suffix != ".rs" \
            or repo_file(f"crates/{parts[1]}/Cargo.toml") is None:
        return None
    crate_dir = ROOT / "crates" / parts[1]
    if parts[2] == "src":
        return file, crate_dir, target_roots(crate_dir)
    tests = crate_dir / "tests"
    roots = [tests / parts[3]] if len(parts) == 4 else [tests / parts[3] / "main.rs", tests / f"{parts[3]}.rs"]
    roots = [root for root in roots if root.is_file()]
    return (file, crate_dir, roots) if roots else None


def regression_gap(target, test):
    """Return why the test ID `test` names no `#[test]` fn of the regression file of `target`, a value of
    `regression_target`: an ID that is no path of names, a module path that no root of the target declares or whose
    declarations lead to another file, no `#[test]` fn under that module path, or a source on the way that cannot
    be read; None when it names one."""
    if not (isinstance(test, str) and TEST_ID.fullmatch(test)):
        return f"fix.regression test {test!r} is no test ID"
    file, crate_dir, roots = target
    names, leaf = test.split("::")[:-1], test.rsplit("::", 1)[-1]
    try:
        found = next((walked for root in roots if (walked := module_walk(root, names, crate_dir))), None)
        if found is None or found[0] != file or not scope_declares_test(found, leaf, crate_dir):
            return f"fix.regression {str(file.relative_to(ROOT.resolve()))!r} declares no #[test] fn {test!r}"
    except Unreadable as error:
        return f"fix.regression test {test!r} cannot be resolved: {error}"
    return None


def place_gap(place, reference, records, model=None):
    """Return why `reference`, a string, is absent from `place`: a record id of the catalog for `obligation`, a
    rule text for `rule`, or a property the runner checks for the model file `model` for `model`; None when it is
    present or the place keeps no index."""
    if place == "obligation" and reference not in records:
        return f"{reference!r} is no record id of verification/obligations.json"
    if place == "rule" and reference not in rule_texts():
        return f"{reference!r} is no rule text of narrate/rules.rs"
    if place == "model":
        return model_gap(model, reference)
    return None


def covered_ids(exclusion):
    """Return the `covers` list of an exclusion file, or an empty list when it holds none."""
    covers = exclusion.get("covers")
    return covers if isinstance(covers, list) else []


def repeats(values):
    """Return the string values that occur more than once in `values`, sorted."""
    counted = collections.Counter(value for value in values if isinstance(value, str))
    return sorted(value for value, count in counted.items() if count > 1)


def fix_gaps(fix):
    """Return why an escape's `fix` is refused: no object or a state outside `FIX_STATES`, a merged fix with no pull
    request number, or a `regression` that is no object, whose path `regression_target` refuses, whose `tests` is
    no nonempty list or repeats an ID, or with a test ID `regression_gap` refuses."""
    if not isinstance(fix, dict) or fix.get("state") not in FIX_STATES:
        return [f"fix needs a state among {', '.join(FIX_STATES)}"]
    gaps = []
    if fix["state"] == "merged" and not positive(fix.get("pull_request")):
        gaps.append("a merged fix names its pull request by number")
    if "regression" not in fix:
        return gaps
    regression = fix["regression"] if isinstance(fix["regression"], dict) else {}
    tests = regression.get("tests")
    if not isinstance(tests, list) or not tests:
        return [*gaps, "fix.regression needs a path and its tests"]
    target = regression_target(regression.get("path"))
    if target is None:
        return [*gaps, f"fix.regression {regression.get('path')!r} is no Rust source of a crate's src or tests"]
    gaps += [f"fix.regression lists the test {test!r} more than once" for test in repeats(tests)]
    return gaps + list(dict.fromkeys(gap for test in tests if (gap := regression_gap(target, test))))


def property_gaps(agreed, records):
    """Return why an escape's `property` is refused: no object with nonblank `text` and `pointer`, a place outside
    `AGREED_PLACES`, or a reference `place_gap` finds absent from its place: the pointer for `obligation` and
    `model` (with the property's `model` file), the text for `rule`."""
    if not isinstance(agreed, dict) or agreed.get("place") not in AGREED_PLACES or not (
            nonblank(agreed.get("text")) and nonblank(agreed.get("pointer"))):
        return [f"property needs its text, a pointer and a place among {', '.join(AGREED_PLACES)}"]
    if agreed["place"] == "rule":
        gap = place_gap("rule", agreed["text"], records)
    else:
        gap = place_gap(agreed["place"], agreed["pointer"], records, agreed.get("model"))
    return [f"property {gap}"] if gap else []


def cause_gaps(row):
    """Return why an escape's `cause` is refused: a word outside `CAUSE_EVIDENCE`, an evidence key of its cause
    that `evidence` lacks or holds blank, `evidence` that is no object lacking them all, or a `sweep` that names
    no archive digest: a run of 64 lowercase hexadecimal characters."""
    cause = row["cause"]
    if not isinstance(cause, str) or cause not in CAUSE_EVIDENCE:
        return [f"cause {cause!r} is none of {', '.join(CAUSE_EVIDENCE)}"]
    evidence = row.get("evidence") if isinstance(row.get("evidence"), dict) else {}
    gaps = [f"cause {cause} lacks evidence key {key}" for key in CAUSE_EVIDENCE[cause] if not nonblank(evidence.get(key))]
    if "sweep" in CAUSE_EVIDENCE[cause] and nonblank(evidence.get("sweep")) and not DIGEST.search(evidence["sweep"]):
        gaps.append("evidence.sweep names no archive digest of 64 hexadecimal characters")
    return gaps


def members(value, name):
    """Yield the value of each member `name` at any depth of the JSON value `value`."""
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            if name in item:
                yield item[name]
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)


def tally_gaps(holder, label):
    """Return why the `tally` of `holder`, a catch or one of its further histories named `label`, is refused: no
    object or an empty one, a `build` that is no digest of 64 lowercase hexadecimal characters, or, at any depth,
    no `missed` or one other than the integer 0, or no `runs` or one that records no run: the run a catch cites ran
    and missed no violation. A `runs` records a run as a positive integer or as the text `first..last` of two
    decimal numbers, the last no smaller. A holder without a tally has no gap here."""
    if "tally" not in holder:
        return []
    tally = holder["tally"]
    if not isinstance(tally, dict):
        return [f"{label}.tally is no object"]
    if not tally:
        return [f"{label}.tally is empty"]
    gaps = []
    build = tally.get("build")
    if not (isinstance(build, str) and DIGEST.fullmatch(build)):
        gaps.append(f"{label}.tally lacks its build digest: build holds 64 hexadecimal characters")
    missed, runs = list(members(tally, "missed")), list(members(tally, "runs"))
    gaps += [f"{label}.tally holds missed {count!r}: each missed count of a catch is 0"
             for count in missed if type(count) is not int or count != 0]
    gaps += [] if missed else [f"{label}.tally holds no missed count"]
    if not runs or not all((type(count) is int and count > 0) or (
            isinstance(count, str) and (span := RUN_RANGE.fullmatch(count)) and int(span[1]) <= int(span[2])) for count in runs):
        gaps.append(f"{label}.tally records no run: each runs is a positive integer or first..last")
    return gaps


def catch_gaps(caught):
    """Return why an escape's `catch` is refused: a field of `CATCH_FIELDS` it lacks, a history or a `control`
    that is no quoted history name, a `control` that repeats the history, a rule that is no rule text, a tally
    `tally_gaps` refuses, beside a `control` a tally whose `history` is no object named for the history or whose
    list `controls` holds no object named for the control, each with its own `runs` and `missed`, a `site` that
    is no nonblank text, an `also` beside no `site`, or an `also` that is no nonempty list of objects, each with
    a `history` that is a quoted history name and names no other history of the catch, its `control` included, a
    nonblank `site`, and a `tally` judged as the catch's own.

    The name check reads the history sources: it shows that a history constructor quotes the name, and leaves
    the history's ending to review. A `control` ends in the rule and its `history` passes, so one name cannot
    fill both fields. The tally's two names show that the row counts the histories it names; the run behind
    each count stays with review. The row states that each history of `also` fails `rule`; this judgment reads
    no history's declared ending, so review checks that."""
    caught = caught if isinstance(caught, dict) else {}
    gaps = [f"catch lacks {field}" for field in CATCH_FIELDS if field not in caught]
    for field in ("history", "control"):
        if field in caught and not (nonblank(caught[field]) and caught[field] in history_names()):
            gaps.append(f"catch.{field} {caught[field]!r} is no quoted history name in the history sources")
    if "control" in caught and nonblank(caught["control"]) and caught["control"] == caught.get("history"):
        gaps.append(f"catch.control {caught['control']!r} repeats catch.history")
    if "rule" in caught and not (nonblank(caught["rule"]) and caught["rule"] in rule_texts()):
        gaps.append(f"catch.rule {caught['rule']!r} is no rule text of narrate/rules.rs")
    gaps += tally_gaps(caught, "catch")
    tally = caught.get("tally")
    if nonblank(caught.get("control")) and isinstance(tally, dict) and tally:
        controls = tally["controls"] if isinstance(tally.get("controls"), list) else []
        for field, entries in (("history", [tally.get("history")]), ("control", controls)):
            if not any(isinstance(entry, dict) and entry.get("name") == caught.get(field) and {"runs", "missed"} <= set(entry)
                       for entry in entries):
                gaps.append(f"catch.tally holds no entry named for catch.{field} {caught.get(field)!r} with its own runs and "
                            "missed: a catch with a control tallies its history under history and each control in controls")
    if "site" in caught and not nonblank(caught["site"]):
        gaps.append("catch.site is no nonblank text")
    if "also" not in caught:
        return gaps
    if "site" not in caught:
        gaps.append("catch lacks site: a catch with further histories names its own site")
    if not (isinstance(caught["also"], list) and caught["also"]):
        return [*gaps, "catch.also is no nonempty list"]
    named = [caught.get("history"), caught.get("control")]
    for at, entry in enumerate(caught["also"]):
        label = f"catch.also[{at}]"
        if not isinstance(entry, dict):
            gaps.append(f"{label} is no object")
            continue
        gaps += [f"{label} lacks {field}" for field in ("history", "site", "tally") if field not in entry]
        if "history" in entry:
            history = entry["history"]
            if not (nonblank(history) and history in history_names()):
                gaps.append(f"{label}.history {history!r} is no quoted history name in the history sources")
            elif history in named:
                gaps.append(f"{label}.history {history!r} repeats a history of the catch")
            named.append(history)
        if "site" in entry and not nonblank(entry["site"]):
            gaps.append(f"{label}.site is no nonblank text")
        gaps += tally_gaps(entry, label)
    return gaps


def site_gaps(row):
    """Return why an escape's `site` is refused: no object with a nonblank function and a path relative to the
    checkout, or a path that names no file of the checkout while the fix is not delivered."""
    site = row["site"]
    if not (isinstance(site, dict) and repo_relative(site.get("path")) and nonblank(site.get("function"))):
        return ["site needs a path and a function, the path relative to the checkout"]
    if isinstance(row.get("fix"), dict) and row["fix"].get("state") == "not-delivered" and repo_file(site["path"]) is None:
        return [f"site.path {site['path']!r} is no file of the repository"]
    return []


def escape_gaps(name, row, records, exclusions):
    """Return why the escape row `name` is refused and, for a row with neither `catch` nor `exclusion`, what it
    lacks to leave the open list, else None.

    A row is refused for a required field missing or malformed (a class outside `ESCAPE_CLASSES`, a property
    `property_gaps` refuses, a site `site_gaps` refuses, a fix `fix_gaps` refuses), a cause `cause_gaps` refuses,
    evidence, a catch or an exclusion without a cause, a catch `catch_gaps` refuses, or an exclusion whose file is
    missing or does not cover the row. An open row lacks its cause, evidence its cause accepts, and a catch or an
    exclusion.
    """
    gaps = [f"lacks {field}" for field in ("class", "property", "site", "fix") if field not in row]
    if "class" in row and row["class"] not in ESCAPE_CLASSES:
        gaps.append(f"class {row['class']!r} is none of {', '.join(ESCAPE_CLASSES)}")
    if "property" in row:
        gaps += property_gaps(row["property"], records)
    if "site" in row:
        gaps += site_gaps(row)
    if "fix" in row:
        gaps += fix_gaps(row["fix"])
    if "cause" in row:
        causes = cause_gaps(row)
        gaps += causes
        lacks = [] if not causes else ["evidence"]
    else:
        gaps += [f"holds {field} and no cause" for field in ("evidence", "catch", "exclusion") if field in row]
        lacks = ["cause", "evidence"]
    if "catch" in row:
        gaps += catch_gaps(row["catch"])
    if "exclusion" in row:
        exclusion = exclusions.get(row["exclusion"]) if isinstance(row["exclusion"], str) else None
        if exclusion is None:
            gaps.append(f"exclusion {row['exclusion']!r} names no file under verification/intake/exclusions/")
        elif name not in covered_ids(exclusion):
            gaps.append(f"exclusion {row['exclusion']} does not cover {name}")
    opened = None if "catch" in row or "exclusion" in row else [*lacks, "catch or exclusion"]
    return gaps, opened


def action_gaps(action, records):
    """Return why an incident or contract-change row's `property_action` is refused: absent, or neither `none`
    with a nonblank `reason` nor `added` with a place of `ACTION_PLACES` and a nonblank `reference` that
    `place_gap` finds present there."""
    if not isinstance(action, dict):
        return ["lacks property_action"]
    if action.get("action") == "none":
        return [] if nonblank(action.get("reason")) else ["property_action none needs a reason"]
    if action.get("action") != "added" or action.get("place") not in ACTION_PLACES or not nonblank(action.get("reference")):
        return [f"property_action is neither none with a reason nor added with a reference and a place among "
                f"{', '.join(ACTION_PLACES)}"]
    gap = place_gap(action["place"], action["reference"], records, action.get("model"))
    return [f"property_action added {gap}"] if gap else []


def cited_sources(row):
    """Return a disagreement row's `sources` when they are two distinct nonblank citations, else None."""
    sources = row.get("sources")
    if isinstance(sources, list) and len(sources) == 2 and all(map(nonblank, sources)) \
            and sources[0].strip() != sources[1].strip():
        return sources
    return None


def disagreement_gaps(row):
    """Return why a disagreement row is refused: `sources` `cited_sources` refuses, a `holds` that states no
    answer, a `holds` without a `corrected` pull request number, or a `corrected` without `holds`."""
    gaps = [] if cited_sources(row) else ["sources needs two citations"]
    if "holds" in row and not nonblank(row["holds"]):
        gaps.append("holds, when present, states the owner's answer")
    if "holds" in row and not positive(row.get("corrected")):
        gaps.append("holds and no corrected pull request by number")
    if "corrected" in row and "holds" not in row:
        gaps.append("holds corrected and no holds")
    return gaps


def exclusion_gaps(name, exclusion, rows):
    """Return why an exclusion file is refused: another id, no reason, an empty `covers`, a covered id that repeats
    or is no escape row naming this exclusion, or an `approval` that is present and blank."""
    gaps = [] if exclusion.get("id") == name else [f"id {exclusion.get('id')!r} differs from its file name"]
    gaps += [] if nonblank(exclusion.get("reason")) else ["lacks reason"]
    covers = covered_ids(exclusion)
    if not covers:
        return [*gaps, "covers needs the escape ids it excludes"]
    gaps += [f"covers {escape!r} more than once" for escape in repeats(covers)]
    gaps += [f"covers {escape!r}, which is no escape row naming {name}" for escape in covers
             if not isinstance(escape, str) or rows.get(escape, {}).get("kind") != "escape"
             or rows[escape].get("exclusion") != name]
    if "approval" in exclusion and not nonblank(exclusion["approval"]):
        gaps.append("approval, when present, cites the owner's approval")
    return gaps


def strict_object(pairs):
    """Return the JSON object of `pairs`; a member name that repeats in one object raises ValueError."""
    found = {}
    for name, value in pairs:
        if name in found:
            raise ValueError(f"repeats the member {name!r}")
        found[name] = value
    return found


def no_constant(token):
    raise ValueError(f"holds {token}, which is no JSON value")


def finite_float(token):
    value = float(token)
    if not math.isfinite(value):
        raise ValueError(f"holds {token}, which is no finite number")
    return value


def strict_json(text):
    """Decode `text` as JSON that repeats no member name in one object and holds no `NaN` or infinity."""
    return json.loads(text, object_pairs_hook=strict_object, parse_constant=no_constant, parse_float=finite_float)


def open_directory(name, refuse, record, parent=None):
    """Return a descriptor of the directory `name`, relative to the directory descriptor `parent` when given, opened
    without following a link; None after refusing `record` when it is a link or cannot be opened as a directory."""
    try:
        if stat.S_ISLNK(os.stat(name, dir_fd=parent, follow_symlinks=False).st_mode):
            refuse(record, "is a link; the register holds regular files")
            return None
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    except OSError as error:
        refuse(record, f"the register directory cannot be listed: {error}")
        return None


def read_register(directory, refuse, prefix=""):
    """Return the JSON objects of the `*.json` regular files of the open directory descriptor `directory` by file
    name, and the names of the subdirectories it holds.

    Each entry is judged on its own descriptor, opened relative to `directory` without following a link, and each
    refusal names the entry under `prefix`: a directory that cannot be listed, an entry whose type cannot be read,
    a link, a special file, a file with another suffix or no name before it, and a file of more than
    `REGISTER_BYTES` bytes or that is no JSON object, repeats a member name in one object or holds `NaN` or an
    infinity.
    """
    found, nested = {}, []
    try:
        with os.scandir(directory) as listing:
            names = sorted(entry.name for entry in listing)
    except OSError as error:
        refuse(prefix.rstrip("/") or ".", f"the register directory cannot be listed: {error}")
        return found, nested
    for entry in names:
        name = prefix + entry
        try:
            mode = os.stat(entry, dir_fd=directory, follow_symlinks=False).st_mode
        except OSError as error:
            refuse(name, f"cannot be read: {error}")
            continue
        if stat.S_ISLNK(mode):
            refuse(name, "is a link; the register holds regular files")
        elif stat.S_ISDIR(mode):
            nested.append(entry)
        elif not (stat.S_ISREG(mode) and entry.endswith(".json") and entry != ".json"):
            refuse(name, "is no row or exclusion of the register")
        else:
            stem = prefix + entry[:-len(".json")]
            try:
                data = bounded_read(os.open(entry, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory),
                                    REGISTER_BYTES)
                value = strict_json(data.decode("utf-8"))
            except (OSError, ValueError, RecursionError) as error:
                refuse(stem, f"{entry} is no JSON object: {error}")
                continue
            if isinstance(value, dict):
                found[entry[:-len(".json")]] = value
            else:
                refuse(stem, f"{entry} is no JSON object")
    return found, nested


def read_exclusions(root, nested, refuse):
    """Return the exclusion files of the register descriptor `root` by name, from its subdirectory `exclusions/`
    when `nested` names it; every other subdirectory, and any under `exclusions/`, is refused."""
    exclusions = {}
    for name in nested:
        if name != "exclusions":
            refuse(name, "is no row or exclusion of the register")
            continue
        directory = open_directory(name, refuse, name, root)
        if directory is None:
            continue
        try:
            exclusions, deeper = read_register(directory, refuse, "exclusions/")
        finally:
            os.close(directory)
        for other in deeper:
            refuse(f"exclusions/{other}", "is no row or exclusion of the register")
    return exclusions


def intake_judgment(catalog, directory):
    """Return the intake register's refusals, each under the code `intake`, and its open rows.

    The register is `directory`'s `*.json` rows and its `exclusions/*.json` files, read by `read_register`; a
    register directory that is a link, missing or cannot be listed is refused under `.`, and an absent
    `exclusions/` holds no exclusion. An escape row with neither `catch` nor `exclusion` lists under
    `open_escapes` with what it lacks, a disagreement without `holds` under `open_disagreements` with its sources
    once `cited_sources` accepts them, and an exclusion without `approval` under `open_exclusions` with its count
    of distinct covered escapes. Open rows are admitted. Obligation pointers resolve against the catalog's
    shape-valid records.
    """
    refusals = []

    def refuse(record, reason):
        refusals.append({"code": "intake", "record": record, "reason": reason})

    rows, exclusions = {}, {}
    root = open_directory(directory, refuse, ".")
    if root is not None:
        try:
            rows, nested = read_register(root, refuse)
            exclusions = read_exclusions(root, nested, refuse)
        finally:
            os.close(root)
    records = {record["id"] for record in catalog.get("records", []) if check_shape(record) is None}
    kinds = dict.fromkeys(INTAKE_KINDS, 0)
    opened = {"open_escapes": [], "open_disagreements": [], "open_exclusions": []}
    for name, row in rows.items():
        if row.get("id") != name:
            refuse(name, f"id {row.get('id')!r} differs from its file name")
        if row.get("kind") not in INTAKE_KINDS:
            refuse(name, f"kind {row.get('kind')!r} is none of {', '.join(INTAKE_KINDS)}")
            continue
        kinds[row["kind"]] += 1
        if row["kind"] == "escape":
            gaps, lacks = escape_gaps(name, row, records, exclusions)
            if lacks is not None:
                opened["open_escapes"].append({"id": name, "lacks": lacks})
        elif row["kind"] == "disagreement":
            gaps = disagreement_gaps(row)
            if "holds" not in row:
                opened["open_disagreements"].append({"id": name, "sources": cited_sources(row) or []})
        else:
            gaps = action_gaps(row.get("property_action"), records)
        for gap in gaps:
            refuse(name, gap)
    for name, exclusion in exclusions.items():
        for gap in exclusion_gaps(name, exclusion, rows):
            refuse(f"exclusions/{name}", gap)
        if "approval" not in exclusion:
            distinct = {escape for escape in covered_ids(exclusion) if isinstance(escape, str)}
            opened["open_exclusions"].append({"id": name, "covers": len(distinct)})
    return refusals, {"intake": {**kinds, "exclusion": len(exclusions)}, **opened}


CONTROL_LESS = ROOT / "verification/control-less.json"


def ratchet_judgment(catalog, path):
    """Return the control ratchet's refusals, each under the code `control-ratchet`, and the length of the list at
    `path`. A record without a control carries a `no_control` reason or stands on the list; a list entry names a
    record without a control or a reason. Only records `check_shape` admits are judged: `admit` reports the
    malformed records and a repeated id."""
    refusals = []

    def refuse(record, reason):
        refusals.append({"code": "control-ratchet", "record": record, "reason": reason})

    listed = read_json(path)
    if not isinstance(listed, list) or not all(isinstance(name, str) for name in listed):
        refuse(None, f"{path.name} is no list of record ids")
        return refusals, 0
    entries = set(listed)
    if listed != sorted(entries):
        refuse(None, f"{path.name} is no sorted list of distinct record ids")
    named = {record.get("id") for record in catalog.get("records", []) if isinstance(record, dict) and isinstance(record.get("id"), str)}
    records = {record["id"]: record for record in catalog.get("records", []) if check_shape(record) is None}
    for name, record in records.items():
        if "no_control" in record:
            if record["controls"]:
                refuse(name, "the record has a control: remove its no_control member")
            elif not nonblank(record["no_control"]):
                refuse(name, "no_control must state the reason the record has no control")
        elif not record["controls"] and name not in entries:
            refuse(name, f"has no control, no no_control reason and no entry on {path.name}: "
                         "add a control, or record the reason it has none in no_control")
    for name in listed:
        record = records.get(name)
        if record is None:
            if name not in named:
                refuse(name, f"the {path.name} entry names no catalog record: remove the entry")
        elif record["controls"]:
            refuse(name, f"the record has a control: remove its entry from {path.name}")
        elif nonblank(record.get("no_control")):
            refuse(name, f"the record carries a no_control reason: remove its entry from {path.name}")
    return refusals, len(listed)


def structure_gaps(name, job, gate):
    """Return why a credited job's workflow structure falls short: outside the gate's needs, a timeout under its
    step budgets plus the margin, or an evidence upload or credit step that is conditional."""
    if name not in gate["needs"]:
        return [f"job {name} is outside {GATE}'s needs {gate['needs']}"]
    gaps = []
    if job["timeout"] is None or job["timeout"] < job["budget"] + MARGIN_MINUTES:
        gaps.append(f"job {name} needs timeout-minutes at least {job['budget'] + MARGIN_MINUTES}")
    if not job["upload"]:
        gaps.append(f"job {name} lacks an evidence upload with if: always() and if-no-files-found: error")
    if not job["credit"]:
        gaps.append(f"job {name} lacks a verify-receipts.py credit step under if: always()")
    return gaps


def git_revision():
    try:
        return subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise Crash(f"git rev-parse failed: {error}") from error


def fuzz_rows(record, rows):
    """Each fuzz row whose run in `record` executed fewer than its executions past its seeds, with the reason."""
    runs = {"frame": record, "campaign": record.get("campaign") or {}, **record.get("parsers", {})}
    past = {target: int(run.get("runs", 0)) - int(run.get("seeds", 0)) - 1 for target, run in runs.items()}
    return [f"{row['id']} ran {max(past.get(row['target'], 0), 0)} inputs past its seeds, declared at least {row['executions']}"
            for row in rows if past.get(row["target"], 0) < row["executions"]]


def fuzz_checkpoints(record):
    """Each worker target checkpoint `record` leaves unmet: the campaign and each parser must report a positive
    count of generated inputs the oracle judged a pass."""
    runs = [("campaign", record.get("campaign") or {}), *sorted(record.get("parsers", {}).items())]
    return [f"no generated input passed the oracle for {target}" for target, run in runs
            if not positive(run.get("nonseed_pass"))]


def positive(value):
    """Whether `value` is a positive integer count; JSON `true` decodes as `bool`, an `int` subclass, and is refused."""
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def fuzz_completion(evidence, failure, exit_code, rows):
    retained = ("artifacts", "campaign-artifacts", "record-artifacts", "wire-artifacts")
    crashes = [p.name for name in retained if (evidence / name).is_dir()
               for p in sorted((evidence / name).glob("*")) if not p.name.startswith("slow-unit-")]
    if crashes:
        return VIOLATION, f"crash inputs {crashes}"
    if exit_code in INTERRUPTED:
        return TIMEOUT, failure or f"the fuzz run exited {exit_code}"
    if failure is not None:
        return TOOL_FAILURE, failure
    if not (evidence / "fuzz.json").exists():
        return SKIPPED, "the fuzz lane wrote no fuzz.json"
    record = read_json(evidence / "fuzz.json")
    if "runs" not in record:
        return TOOL_FAILURE, "the run reported no executions"
    if "campaign" not in record:
        return TOOL_FAILURE, "the campaign run did not finish"
    if set(record.get("parsers", {})) != {"record", "wire"}:
        return TOOL_FAILURE, "the parser runs did not finish"
    blocked = fuzz_rows(record, rows)
    if blocked:
        return TOOL_FAILURE, f"blocked fuzz rows: {' | '.join(blocked)}"
    unmet = fuzz_checkpoints(record)
    if unmet:
        return TOOL_FAILURE, f"unmet fuzz checkpoints: {' | '.join(unmet)}"
    return COMPLETED, None


def test_completion(evidence, failure, report, exit_code):
    if exit_code in INTERRUPTED or (report is not None and CANCELLED in (report.get("reason") or "")):
        return TIMEOUT, (report or {}).get("reason") or failure or f"the run exited {exit_code}"
    if report is None and failure is None and not (evidence / "run.txt").exists():
        return SKIPPED, "the lane wrote no report.json"
    if failure is not None and (report is None or report.get("credited")):
        return TOOL_FAILURE, failure
    if report is None:
        return TOOL_FAILURE, failure or "the run was not judged"
    if report.get("code") == 2:
        return TOOL_FAILURE, report.get("reason")
    return COMPLETED, None


def completion_of(evidence, job, report, exit_code):
    """Return the lane's completion category and its detail from the evidence files."""
    failure = (evidence / "failure.txt").read_text().strip() if (evidence / "failure.txt").exists() else None
    if job in FUZZ:
        return fuzz_completion(evidence, failure, exit_code, read_json(COMMITTED[0])["qualified"][job]["rows"])
    return test_completion(evidence, failure, report, exit_code)


def qualified_record(evidence, name):
    """Return the lane's record `name` (`qualified.json` or a domain's run record), or None for a missing or
    unreadable one, which credit refuses as `unqualified`."""
    try:
        return read_json(evidence / name)
    except Crash:
        return None


def control_runs(evidence):
    """The lane's `controls.txt` as records: each line is a control's test, its exit and `found` or `absent`
    for its diagnostic; a missing file or a malformed line yields no record for that line."""
    path = Path(evidence) / "controls.txt"
    runs = []
    for line in path.read_text(encoding="utf-8").splitlines() if path.exists() else []:
        fields = line.split("\t")
        if len(fields) == 3 and fields[1].isdigit():
            runs.append({"test": fields[0], "exit": int(fields[1]), "diagnostic": fields[2] == "found"})
    return runs


def control_gaps(receipt, inventory):
    """Return the inventory's miri controls whose recorded run does not credit them: no line, a passing exit,
    an interrupted exit, or the diagnostic absent."""
    runs = {run["test"]: run for run in receipt.get("controls") or []}
    gaps = []
    for control in inventory["miri"]["controls"]:
        run = runs.get(control["test"])
        if run is None:
            gaps.append(f"control {control['test']} has no recorded failing run")
        elif run["exit"] == 0 or run["exit"] in INTERRUPTED or not run["diagnostic"]:
            gaps.append(f"control {control['test']} exited {run['exit']} with its diagnostic {'found' if run['diagnostic'] else 'absent'}")
    return gaps


VERDICT_FIELDS = ("code", "credited", "cfg", "module", "rows", "targets")
EXIT_CODE = re.compile(r"-?[0-9]{1,9}")


def selection_args(job, module):
    """Return the `select-tests.py` cfg arguments the lane script passes for `job` and `module`, or None for a lane
    whose `report.json` no selection judge writes."""
    cfg = LANE_CFG.get(job)
    if cfg in ("qualified", "loom"):
        return [f"--cfg={cfg}", f"--module={job if cfg == 'qualified' else module}"]
    return None if cfg is None else [f"--cfg={cfg}"]


def judged_selection(select, cfg_args, evidence, exit_text):
    """Return the report `select-tests.py run` writes under `cfg_args` for the lane's `SELECTED` files, judged in this process
    against the committed inventory, registry and catalog; the run's parsed summaries, or None when the judgment
    stopped before it parsed the run; and the reasons no judgment ran: a missing file or an exit code that is no
    integer."""
    unbound = [f"the lane holds no {name} to judge its selection from" for name in SELECTED if not (evidence / name).is_file()]
    if exit_text is not None and not EXIT_CODE.fullmatch(exit_text):
        unbound.append(f"exit.txt holds {exit_text[:40]!r}, which is no exit code")
    if unbound:
        return None, None, unbound
    try:
        judged, args = select.verdict(["run", *cfg_args, "--list", str(evidence / "list.txt"),
                                   "--ignored", str(evidence / "ignored.txt"), "--output", str(evidence / "run.txt"),
                                   "--exit", exit_text])
    except SystemExit as error:
        return None, None, [f"the selection judge refused its arguments {cfg_args}: exit {error.code}"]
    return judged, getattr(args, "summaries", None), []


def build_receipt(select, job, module, evidence, revision):
    """Return the receipt of the lane's evidence. A completed lane whose report a selection judge writes takes its
    selection verdict, per-target counts and execution count from `judged_selection`, and records beside them the
    saved `report.json`'s verdict and the `VERDICT_FIELDS` in which it differs."""
    evidence = Path(evidence)
    report = read_json(evidence / "report.json") if (evidence / "report.json").exists() else None
    if report is not None and not isinstance(report, dict):
        raise Crash(f"{evidence / 'report.json'} holds no JSON object")
    exit_text = (evidence / "exit.txt").read_text().strip() if (evidence / "exit.txt").exists() else None
    cfg_args = selection_args(job, module)
    raw = cfg_args is not None
    exit_code = None if exit_text is None or (raw and not EXIT_CODE.fullmatch(exit_text)) else int(exit_text)
    completion, detail = completion_of(evidence, job, report, exit_code)
    derived = raw and completion == COMPLETED
    judged, summaries, unbound = judged_selection(select, cfg_args, evidence, exit_text) if derived else (None, None, [])
    basis = (judged if derived else report) or {}
    executed, failed, executions = [], [], 0
    if job in FUZZ:
        fuzz = read_json(evidence / "fuzz.json") if (evidence / "fuzz.json").exists() else {}
        executions = int(fuzz.get("runs", 0))
    elif (evidence / "run.txt").exists():
        if summaries is None:
            try:
                summaries = select.parse_summaries(select.read(str(evidence / "run.txt")))
            except select.Refusal as refusal:
                summaries = {}
                if CANCELLED in str(refusal):
                    completion, detail = TIMEOUT, str(refusal)
                elif completion == COMPLETED:
                    completion, detail = TOOL_FAILURE, str(refusal)
        for summary in summaries.values():
            executed += summary["ok"]
            failed += summary["FAILED"]
        executions = sum(dict_of(counts).get("executed", 0) for counts in dict_of(basis.get("targets")).values())
    pins = (evidence / "pins.txt").read_text().strip().splitlines() if (evidence / "pins.txt").exists() else []
    lane = f"loom {module}" if job == "loom" else job
    assumptions = ASSUMPTIONS.get(job, [])
    inputs = {name: sha256(evidence / name) for name in INPUTS if (evidence / name).exists()}
    inputs.update(committed_inputs())
    qualified = qualified_record(evidence, "qualified.json") if job in ENVELOPED else None
    field, record = DOMAIN_RECORDS.get(job, (None, None))
    selection = {"credited": bool(basis.get("credited")), "reason": basis.get("reason"), "cfg": basis.get("cfg"),
                 "module": basis.get("module")}
    if derived:
        saved = report or {}
        differs = [] if judged is None else [name for name in VERDICT_FIELDS if judged.get(name) != saved.get(name)]
        selection.update(unbound=unbound, report={"credited": bool(saved.get("credited")), "reason": saved.get("reason"),
                                                  "differs": differs})
    return {
        **({"qualified": qualified} if job in ENVELOPED else {}),
        **({field: qualified_record(evidence, record)} if field else {}),
        **({"controls": control_runs(evidence)} if job == "miri" else {}),
        "job": job, "module": module, "lane": lane, "revision": revision,
        "inputs": inputs,
        "tool": {"name": "cargo fuzz" if job in FUZZ else {"miri": "cargo miri test", "sweep": "cargo miri test", "asan": "cargo test -Zbuild-std -Zsanitizer=address", "qemu": "scripts/guest-binder.py"}.get(job, "cargo test"), "provenance": pins},
        "assumptions": assumptions,
        "bounds": {"targets": basis.get("targets", {}), "exit": exit_code},
        "completion": completion, "violation": detail if completion == VIOLATION else None, "detail": detail,
        "selection": selection,
        "executions": executions, "executed": sorted(executed), "failed": sorted(failed),
        "replay": f"bash scripts/rust-lane.sh {lane}",
        "ci": {key: os.environ.get(key) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")},
    }


def quint_blocks(catalog):
    """Quint obligation records withheld by the manifest's named external gates."""
    declared = read_json(CHECKER_JOBS["quint"])
    judge = load_script("quint_gates", CHECKER_JUDGES["quint"])
    try:
        blocked = judge.blocked_cases(declared)
    except judge.Refusal as error:
        raise Crash(str(error)) from error
    result = {}
    for record in catalog["records"]:
        if record["job"] == "quint":
            names = {*record["tests"], *(control["test"] for control in record["controls"])}
            gates = {name: gate for name, gate in blocked.items() if name in names}
            if gates:
                result[record["id"]] = gates
    return result


def blocked_lines(blocked):
    return [f"- {record}: {case} withheld at {gate}; no credit"
            for record, cases in sorted(blocked.items()) for case, gate in sorted(cases.items())]


def credit(catalog, receipt, job, module, revision, evidence, inventory):
    """Judge the records of `job` (and `module`) against `receipt`; an enveloped domain's envelope and controls
    are judged against `inventory`. Quint records requiring blocked cases are
    withheld, with their external gates retained in the credit report."""
    refusals = []

    def refuse(code, record, reason):
        refusals.append({"code": code, "record": record, "reason": reason})

    keyed = job in ("loom", *PROFILED)
    modules = credited_modules(job, module) if keyed else set()
    blocks = quint_blocks(catalog) if job == "quint" else {}
    records = [r for r in catalog["records"] if r["job"] == job and r["id"] not in blocks
               and (not keyed or r.get("module") in modules)]
    if not records and job not in ENVELOPED:
        lane = f"{job} {module}" if module else job
        refuse("uncovered-lane", lane, f"no record names the lane {lane}; nothing to credit")
    if receipt.get("revision") != revision:
        refuse("unbound-revision", None, f"receipt revision {receipt.get('revision')!r}, expected {revision}")
    if receipt.get("job") != job or (keyed and receipt.get("module") != module):
        refuse("unbound-lane", None, f"receipt lane {receipt.get('job')!r} module {receipt.get('module')!r}, expected {job!r} module {module!r}")
    completion = receipt.get("completion")
    inputs = receipt.get("inputs") or {}
    committed = [*COMMITTED, *(checker_inputs(job) if job in CHECKER_JOBS else ())]
    evidence_files = lane_evidence(job, module)
    if job == "quint" and "quint-shards.json" in inputs:
        evidence_files = ("report.json", "pins.txt", "quint-shards.json")
    required = [*(str(path.relative_to(ROOT)) for path in committed), *(evidence_files if completion == COMPLETED else ())]
    for name in required:
        if name not in inputs:
            refuse("unbound-input", None, f"the receipt binds no digest for {name}")
    repository = {str(path.relative_to(ROOT)) for path in committed}
    for name, digest in inputs.items():
        path = ROOT / name if "/" in name or name in repository else Path(evidence) / name
        if not path.exists() or sha256(path) != digest:
            refuse("unbound-input", None, f"{name} changed since the receipt or is missing")
    if completion not in (COMPLETED, VIOLATION):
        code = completion.replace(" ", "-") if completion in (TIMEOUT, EXHAUSTED, UNSUPPORTED, SKIPPED, TOOL_FAILURE, DRIFT) else "tool-failure"
        refuse(code, None, receipt.get("detail") or f"completion {completion!r}")
    elif completion == COMPLETED and selection_args(job, module) is not None and (gaps := raw_gaps(receipt)):
        for code, reason in gaps:
            refuse(code, None, reason)
    elif job not in FUZZ and not receipt.get("selection", {}).get("credited"):
        refuse("selection-refused", None, receipt["selection"].get("reason") or "the selection report is not credited")
    elif completion == COMPLETED and job in LANE_CFG and receipt["selection"].get("cfg") != LANE_CFG[job]:
        refuse("unbound-lane", None, f"the selection was judged under cfg {receipt['selection'].get('cfg')!r}, expected {LANE_CFG[job]!r}")
    elif completion == COMPLETED and job in QUALIFIED and receipt["selection"].get("module") != job:
        refuse("unbound-lane", None, f"the selection was judged for lane {receipt['selection'].get('module')!r}, expected {job!r}")
    if receipt.get("failed"):
        refuse("raw-failed", None, f"FAILED outcomes {receipt['failed']}")
    provenance = (receipt.get("tool") or {}).get("provenance")
    pins = Path(evidence) / "pins.txt"
    if not provenance:
        refuse("missing-provenance", None, "the receipt names no tool provenance; the lane wrote no pins")
    elif pins.exists() and provenance != pins.read_text(encoding="utf-8").strip().splitlines():
        refuse("missing-provenance", None, "the receipt's tool provenance differs from the lane's pins.txt")
    if not receipt.get("executions"):
        refuse("zero-executions", None, "the receipt counts no executions")
    executed = set(receipt.get("executed", []))
    if job == "qemu":
        console = Path(evidence) / "run.txt"
        text = console.read_text() if console.exists() else ""
        lines = text.splitlines()
        reports = [line.split("guest-binder: ", 1)[1] for line in lines if "guest-binder: " in line]
        harness = load_script("guest_binder", ROOT / "scripts/guest-binder.py")
        for gap in harness.namespace_gaps(reports):
            refuse("unqualified", None, f"guest console: {gap}")
        if harness.overflowed(lines):
            refuse("unqualified", None, f"guest console: the report count exceeded its bound of {harness.REPORT_BOUND}")
        log = text.partition("\n")[2]
        if len(log) >= harness.CONSOLE_BYTES:
            refuse("unqualified", None, f"guest console: the log reached its bound of {harness.CONSOLE_BYTES} characters")
        recorded = dict_of(receipt.get("guest")).get("reports") or []
        if harness.console_reports(lines)[:harness.REPORT_BOUND] != recorded:
            refuse("unqualified", None, "guest console reports differ from the guest record")
    if job in ENVELOPED:
        for code, reason in qualification_gaps(job, receipt, inventory):
            refuse(code, None, reason)
    if job == "miri":
        for reason in control_gaps(receipt, inventory):
            refuse("missing-result", None, reason)
    for record in records:
        for test in record["tests"]:
            if test not in executed:
                refuse("missing-result", record["id"], f"{test} has no ok outcome")
        for control in record["controls"]:
            if completion == VIOLATION:
                if receipt.get("violation") != control["violation"]:
                    refuse("wrong-violation", record["id"], f"receipt violation {receipt.get('violation')!r}, record {control['violation']!r}")
            elif control["test"] not in executed:
                refuse("missing-result", record["id"], f"control {control['test']} has no ok outcome")
        if completion == VIOLATION and (record["tests"] or not record["controls"]):
            refuse("wrong-violation", record["id"], f"a positive obligation met the violation {receipt.get('violation')!r}")
    return records, refusals


def raw_gaps(receipt):
    """Return the (code, reason) refusals a completed receipt earns from the selection judged again from its raw
    evidence: `unbound-input` for each raw file that is missing or malformed, `selection-refused` for a saved
    `report.json` that refused, and `raw-selection-mismatch` for a saved positive whose verdict fields differ from
    the judgment. A saved refusal stays refused whatever the judgment."""
    selection = dict_of(receipt.get("selection"))
    saved = dict_of(selection.get("report"))
    if selection.get("unbound"):
        return [("unbound-input", reason) for reason in selection["unbound"]]
    if not saved.get("credited"):
        return [("selection-refused", saved.get("reason") or "the saved report.json is not credited")]
    if saved.get("differs"):
        return [("raw-selection-mismatch", f"report.json differs from the selection judged again from the raw evidence in "
                                           f"{saved['differs']}: {selection.get('reason') or 'the judgment credits the run'}")]
    return []


def qualification_gaps(job, receipt, inventory):
    """Return the (code, reason) refusals an enveloped domain's receipt earns: `unqualified` for a missing or
    unreadable envelope, a domain other than the job, a missing run or attempt or one other than the
    receipt's, an unfilled field or subfield, a field off its one admissible value, a measurement or
    deadlines the envelope's writer would refuse, a required module with zero attributed executions, or, for
    qemu, a measurement from another host or a guest record `guest_gaps` refuses; `missing-result` for a
    required control without an `ok` outcome."""
    envelope = receipt.get("qualified")
    gaps = envelope_gaps(job, receipt, envelope, inventory) if isinstance(envelope, dict) else [
        "the receipt carries no qualified envelope; the lane wrote no readable qualified.json"
    ]
    if job == "qemu":
        gaps += guest_gaps(receipt, envelope if isinstance(envelope, dict) else {})
    refusals = [("unqualified", gap) for gap in gaps]
    executed = set(receipt.get("executed", []))
    for target, witnesses in sorted(required_controls(job, inventory).items()):
        refusals += [("missing-result", f"the {target} control {test} has no ok outcome") for test in witnesses if test not in executed]
    return refusals


@cache
def envelope_rules():
    """The measurement and deadline rules `scripts/qualified-envelope.py` writes an envelope under."""
    return load_script("qualified_envelope", ROOT / "scripts/qualified-envelope.py")


def basis_gaps(job, envelope, missing):
    """Return why the envelope's measurement and deadlines fail the rules its writer applies, leaving a
    `missing` field to the presence check; the guest lane's measurement must also be of its host, and its
    guest settings must equal the measured `guest` record."""
    if "measured" in missing:
        return []
    rules = envelope_rules()
    gaps = rules.measurement_gaps(envelope["measured"], job)
    if gaps:
        return gaps
    if job == "qemu":
        gaps += rules.host_gaps(envelope["measured"], dict_of(envelope.get("host")))
        gaps += rules.guest_resource_gaps(envelope["measured"], envelope.get("guest"))
    if "deadlines" in missing:
        return gaps
    return gaps + rules.deadline_gaps(envelope["measured"], envelope["deadlines"], job)


def required_controls(job, inventory):
    """The tests an enveloped domain's run must execute `ok`, keyed by target: the asan entry's required tests,
    or the qemu entry's exact IDs."""
    if job == "asan":
        return {target: witnesses["tests"] for target, witnesses in inventory["asan"]["required"].items()}
    return {inventory["qemu"]["target"]: inventory["qemu"]["tests"]}


def guest_gaps(receipt, envelope):
    """Return why the guest record leaves a qemu receipt unqualified: a run outside CI, a missing record, an
    outcome other than a qualified pass, a run or attempt other than the receipt's, an initrd other than the one
    the lane built at this revision, a witness short of the ordered `GUEST_REPORTS` with the
    controller's IOMMU group, a `reports_overflow` other than `False`, a set `console_truncated`, ready facts
    without the guest's kernel,
    modules and IOMMU, missing identity,
    input, IOMMU, backing or bound fields, bounds other than the measurement's `guest` record, an accelerator
    other than the envelope's, or backing the harness left behind."""
    guest = receipt.get("guest")
    if not isinstance(guest, dict):
        return ["the receipt carries no guest record; the harness wrote no guest.json"]
    gaps = []
    if guest.get("outcome") != GUEST_PASS:
        gaps.append(f"the guest run ended {guest.get('outcome')!r}: {guest.get('reason')}")
    ci = receipt.get("ci") or {}
    ran, run_id = ci.get("GITHUB_RUN_ATTEMPT"), ci.get("GITHUB_RUN_ID")
    if ran is None or run_id is None:
        gaps.append("the guest run has no CI run ID and attempt; the guest domain credits a CI run alone")
    else:
        if str(guest.get("run_id")) != str(run_id):
            gaps.append(f"the guest record names run {guest.get('run_id')!r}, the receipt is of run {run_id!r}")
        if str(guest.get("run_attempt")) != str(ran):
            gaps.append(f"the guest record names attempt {guest.get('run_attempt')!r}, the run is attempt {ran!r}")
    ran_initrd = (dict_of(dict_of(guest.get("inputs")).get("initrd"))).get("sha256")
    built = dict_of(envelope.get("initrd")).get("sha256")
    if not built or ran_initrd != built:
        gaps.append(f"the guest ran initrd {ran_initrd!r}, not the one the lane built at this revision ({built!r})")
    facts = dict(fact.split("=", 1) for fact in str(guest.get("ready") or "").split() if "=" in fact)
    unstated = [key for key in ("kernel", "modules", "iommu") if not facts.get(key)]
    if unstated:
        gaps.append(f"the guest's ready facts state no {unstated}")
    reports = [report for report in guest.get("reports") or [] if isinstance(report, str)]
    found = [reports.index(report) for report in GUEST_REPORTS if report in reports]
    if len(found) != len(GUEST_REPORTS) or found != sorted(found):
        gaps.append(f"the guest reports {reports} lack the ordered witnesses {list(GUEST_REPORTS)}")
    gaps += load_script("guest_binder", ROOT / "scripts/guest-binder.py").namespace_gaps(reports)
    overflow = guest.get("reports_overflow")
    if overflow is not False:
        gaps.append("the guest report count exceeded its bound" if overflow is True
                    else f"the guest record states no report overflow flag: {overflow!r}")
    if guest.get("console_truncated"):
        gaps.append("the guest console passed its log's bound")
    if not any(report.startswith("controller ") and " group " in report for report in reports):
        gaps.append("the guest reports name no controller with its IOMMU group")
    identity = dict_of(guest.get("identity"))
    missing = [field for field in ("volume", "instance", "model", "pci") if not identity.get(field)]
    if missing:
        gaps.append(f"the guest identity lacks {missing}")
    inputs = dict_of(guest.get("inputs"))
    unhashed = [name for name in ("qemu", "kernel", "initrd") if not dict_of(inputs.get(name)).get("sha256")]
    if unhashed:
        gaps.append(f"the guest inputs {unhashed} carry no digest")
    if not guest.get("qemu_version"):
        gaps.append("the guest record lacks qemu_version")
    argv = [word for word in guest.get("argv") or [] if isinstance(word, str)]
    if not any("intel-iommu" in word for word in argv) or not any("intel_iommu=on" in word for word in argv):
        gaps.append("the guest ran without the IOMMU settings (an intel-iommu device and intel_iommu=on)")
    bounds = dict_of(guest.get("bounds"))
    gaps += envelope_rules().guest_resource_gaps(envelope.get("measured"), bounds)
    short = [name for name in ("memory_mib", "cpus", "backing_mib", "handshake_seconds", "deadline_seconds", "accel") if not bounds.get(name)]
    if short:
        gaps.append(f"the guest bounds lack {short}")
    elif bounds["accel"] != dict_of(envelope.get("host")).get("accel"):
        gaps.append(f"the guest ran under accelerator {bounds['accel']!r}, the envelope names {dict_of(envelope.get('host')).get('accel')!r}")
    if not dict_of(guest.get("backing")).get("bytes") or not dict_of(guest.get("cleanup")).get("backing_removed"):
        gaps.append("the guest backing is unrecorded or was left behind")
    return gaps


def dict_of(value):
    """`value` when it is a record, else an empty one, so a malformed field reads as missing."""
    return value if isinstance(value, dict) else {}


def lineage_gaps(envelope):
    """Return why the envelope's `native.lineage` differs from the committed install record's identity: the
    record's sha256 when it carries a lineage line, `unrecorded` when it carries none. The record must lie
    directly under `crates/spdk-sys/src/generated/installs`. An absent `native.lineage` yields no gap here;
    the `ENVELOPE` field check reports it."""
    native = envelope.get("native") if isinstance(envelope.get("native"), dict) else {}
    if native.get("lineage") is None:
        return []
    installs = ROOT / "crates/spdk-sys/src/generated/installs"
    named = Path(str(envelope.get("install")))
    # A lane that records the absolute path of its own checkout names the record by its place under `installs`,
    # which is read in the judging checkout.
    within = named.is_absolute() and named.parts[-6:-1] == installs.relative_to(ROOT).parts
    record = installs / named.name if within else (ROOT / named).resolve()
    if record.parent != installs or not record.is_file():
        return [f"the envelope names install {envelope.get('install')!r}, no committed record under {installs.relative_to(ROOT)}"]
    text = record.read_text(encoding="utf-8")
    expected = sha256(record) if re.search(r"^(Source|Patches|Build inputs|Compilers|Configure|Archive): ", text, re.M) else "unrecorded"
    if native["lineage"] != expected:
        return [f"the envelope's lineage {native['lineage']} is not {expected}, the identity of the committed "
                f"{envelope.get('install')}; the record is stale"]
    return []


def envelope_gaps(job, receipt, envelope, inventory):
    """Return why a present envelope leaves `job`'s receipt unqualified."""
    gaps = []
    if envelope.get("domain") != job:
        gaps.append(f"the envelope names domain {envelope.get('domain')!r}, expected {job!r}")
    attempt = envelope.get("attempt")
    ci = receipt.get("ci") or {}
    ran = ci.get("GITHUB_RUN_ATTEMPT")
    if not attempt:
        gaps.append("the envelope names no run attempt")
    elif ran is not None and str(attempt) != str(ran):
        gaps.append(f"the envelope names attempt {attempt!r}, the run is attempt {ran!r}")
    run, run_id = envelope.get("run"), ci.get("GITHUB_RUN_ID")
    if not run:
        gaps.append("the envelope names no run")
    elif run_id is not None and str(run) != str(run_id):
        gaps.append(f"the envelope names run {run!r}, the receipt is of run {run_id!r}")
    fields = {**ENVELOPE, **ENVELOPED[job]}
    missing = [field for field in fields if not envelope.get(field)]
    if missing:
        gaps.append(f"the envelope lacks {missing}")
    for field, admissible in fields.items():
        if field in missing or admissible is None:
            continue
        if isinstance(admissible, tuple):
            record = envelope[field] if isinstance(envelope[field], dict) else {}
            unfilled = [name for name in admissible if not record.get(name)]
            if unfilled:
                gaps.append(f"the envelope's {field} lacks {unfilled}")
        elif envelope[field] != admissible:
            gaps.append(f"the envelope names {field} {envelope[field]!r}, expected {admissible!r}")
    gaps += basis_gaps(job, envelope, missing)
    gaps += lineage_gaps(envelope)
    targets = dict_of(dict_of(receipt.get("bounds")).get("targets"))
    for target, witnesses in inventory[job].get("required", {}).items():
        executed = dict_of(dict_of(dict_of(targets.get(target)).get("witnesses")).get("executed_modules"))
        unattributed = sorted(module for module in witnesses["modules"] if not executed.get(module))
        if unattributed:
            gaps.append(f"{target} attributes no executed test to the required modules {unattributed}")
    return gaps


EVENT_HEAVY = {"pull_request": False, "push": False, "schedule": True, "workflow_dispatch": True}
PULL_REQUEST_ACTIONS = {"opened", "synchronize", "reopened"}
FAST_JOBS = ("comment-policy", "lane-script", "rust-format", "preflight", "workspace", "rc11", "campaigns", "search", "fuzz-smoke")
HEAVY_JOBS = ("long-run", "search-nightly", "verus", "loom", "miri", "sweep", "genmc", "kani", "tlc", "quint", "fuzz", "asan", "qemu",
              "isa-x86-64")
ADVISORY_JOBS = ("asan",)
ADVISORY_RESULTS = {"success", "failure", "cancelled"}
# Disabled gate dependencies name the missing prerequisite; none receives coverage credit.
PENDING_JOBS = {
    "barriers": "native AArch64 Linux runner is not provisioned",
    "isa-aarch64": "qualified native AArch64 Linux runner is not provisioned",
    "tag-compare-x86-64": "security and build owner confirmation is missing",
    "tag-compare-aarch64": "security and build owner confirmation is missing",
}
FAST_LANES = ("workspace", "rc11", "campaigns", "search", "fuzz-smoke")
BARRIERS = ROOT / "verification/barriers/expected.json"


def selected_jobs(event):
    """The jobs the Rust gate requires to succeed on `event`; every other gate dependency must be skipped."""
    return set(FAST_JOBS) | set(HEAVY_JOBS) if EVENT_HEAVY[event] else set(FAST_JOBS)


def gate_command(event, action, results):
    """Judge the gate's `needs` results: each selected job succeeded, or for an advisory job ended in any of
    `ADVISORY_RESULTS`, and each unselected one was skipped.

    A successful job is not evidence that its lane ran its domain; `aggregate` judges that from the receipts.
    """
    if event not in EVENT_HEAVY:
        return emit("gate", [{"code": "unsupported-event", "record": None, "reason": f"unsupported CI event {event!r}"}])
    if event == "pull_request" and action not in PULL_REQUEST_ACTIONS:
        return emit("gate", [{"code": "unsupported-event", "record": None, "reason": f"unsupported pull request action {action!r}"}])
    selected = selected_jobs(event)
    expected = {name: "success" if name in selected else "skipped" for name in (*FAST_JOBS, *HEAVY_JOBS, *PENDING_JOBS)}
    actual = {name: result.get("result") if isinstance(result, dict) else None for name, result in json.loads(results).items()}
    admissible = {name: ADVISORY_RESULTS if name in selected and name in ADVISORY_JOBS else {state} for name, state in expected.items()}
    refusals = [
        {"code": "lane-result", "record": name, "reason": f"{name} is {actual.get(name)!r}, the {event} policy needs {expected.get(name)!r}"}
        for name in sorted(set(expected) | set(actual)) if actual.get(name) not in admissible.get(name, ())
    ]
    return emit("gate", refusals, {"event": event, "expected": expected, "actual": actual, "pending": PENDING_JOBS})


def lane_domains(event, inventory):
    """Each lane the event selects, keyed (job, module), with its exact executed names, or None where any
    nonzero credited execution counts, and its exact execution count where one is declared."""
    domains: dict = {(job, None): (None, None) for job in FAST_LANES}
    domains[("rc11", None)] = (set(read_json(CHECKER_JOBS["rc11"])["tests"]), None)
    if "barriers" in selected_jobs(event):
        domains[("barriers", None)] = ({site["site"] for site in read_json(BARRIERS)["sites"]}, None)
    select = load_select_tests()
    for lane in QUALIFIED:
        if lane in selected_jobs(event):
            tests = select.selection_of(inventory["qualified"][lane])
            domains[(lane, None)] = (set(tests), len(tests))
    if not EVENT_HEAVY[event]:
        return domains
    sweep = inventory["miri_sweep"]
    domains[("miri", None)] = (set(inventory["miri"]["tests"]), None)
    domains[("sweep", None)] = (set(sweep["tests"]), sweep["seeds"] * len(sweep["tests"]))
    for module, declared in inventory["loom"].items():
        domains[("loom", module)] = (set(declared["tests"]) - set(declared["ignored"]), None)
    profile = "scheduled" if event == "schedule" else "pr"
    cases = judge_call("genmc", lambda judge: judge.profile_cases(checker_declaration("genmc"), profile))
    domains[("genmc", profile)] = (set(cases), None)
    for job in ("fuzz", "verus", "asan"):
        domains[(job, None)] = (None, None)
    quint = read_json(CHECKER_JOBS["quint"])
    domains[("quint", None)] = (set(quint["tests"]) - set(quint.get("blocked", {})), None)
    if "qemu" in HEAVY_JOBS:
        domains[("qemu", None)] = (set(inventory["qemu"]["tests"]), len(inventory["qemu"]["tests"]))
    for job in TAG_COMPARE:
        if job in HEAVY_JOBS:
            domains[(job, None)] = (set(read_json(CHECKER_JOBS[job])["tests"]), None)
    for job in ("kani", "tlc"):
        domains[(job, profile)] = (None, None)
    return domains


def barrier_receipt(evidence):
    """The barrier lane's scan report as a receipt: its passing sites are its executed names, and its build
    identity's revision and CI run are the revision and run it records. A scan whose own CI record differs from
    its build identity's is refused: the identity binds the scanned executable to a revision and run. So is a
    report whose embedded identity differs from the lane's `identity.json`, or that has none to read: the scan
    embeds the file the build step wrote."""
    report = read_json(evidence / "report.json")
    identity = report.get("identity") or {}
    passed = [site.get("site") for site in report.get("sites", []) if site.get("verdict") == "pass"]
    refusals = [] if report.get("credited") else [
        {"code": "raw-failed", "reason": report.get("reason") or "a declared site lacks a sufficient barrier"}]
    if (report.get("ci") or {}) != (identity.get("ci") or {}):
        refusals.append({"code": "identity",
                         "reason": f"the scan records CI {report.get('ci')}, its build identity {identity.get('ci')}"})
    try:
        recorded = read_json(evidence / "identity.json")
    except Crash as error:
        refusals.append({"code": "identity", "reason": f"the lane left no build identity to read: {error}"})
    else:
        if recorded != report.get("identity"):
            refusals.append({"code": "identity", "reason": "the report's build identity differs from identity.json"})
    return {"job": "barriers", "module": None, "completion": "completed" if report.get("sites") else "tool failure",
            "executions": len(passed), "executed": sorted(passed), "ci": identity.get("ci") or {},
            "revision": identity.get("revision")}, refusals


def identity_gap(receipt, expected):
    """The first identity component a lane receipt records empty or other than `expected`, the revision, run and
    attempt the workflow passed, as a reason, or None when all three match."""
    ci = receipt.get("ci") or {}
    recorded = {"revision": receipt.get("revision"), "run": ci.get("GITHUB_RUN_ID"),
                "attempt": ci.get("GITHUB_RUN_ATTEMPT")}
    for name, value in recorded.items():
        if not value or str(value) != str(expected[name]):
            return f"the receipt records {name} {value!r}, not the expected {expected[name]!r}"
    return None


def recredit(select, catalog, inventory, receipt, evidence, revision):
    """Return the refusals credit gives a lane whose report a selection judge writes, judged in this process from the
    lane's evidence at `revision` against the committed catalog, inventory and registry, with no admission. The
    receipt derived from the evidence carries the saved receipt's `ci`, the run identity the lane recorded, and must
    equal the saved receipt, or it is `unbound-input`. Evidence that cannot be read or judged is the lane's own
    `unbound-input`, so the other lanes are still judged. The saved `credit.json` is left unread."""
    job, module = receipt.get("job"), receipt.get("module")
    try:
        derived = {**build_receipt(select, job, module, evidence, revision), "ci": receipt.get("ci")}
        judged = credit(catalog, derived, job, module, revision, evidence, inventory)[1]
    except (Crash, OSError, ValueError, KeyError, TypeError, select.Refusal) as error:
        return [{"code": "unbound-input", "record": None, "reason": f"the lane's evidence cannot be judged again: {error}"}]
    refusals = [] if receipt == derived else [
        {"code": "unbound-input", "record": None, "reason": "the receipt differs from the receipt derived from the evidence"}]
    return refusals + judged


def receipt_shaped(receipt):
    """Whether a saved receipt has the shape aggregation reads: a JSON object whose `ci` is an object or empty, whose
    `job` and `module` are text or null and whose `executed` is a list of text."""
    if not isinstance(receipt, dict) or not isinstance(receipt.get("ci") or {}, dict):
        return False
    executed = receipt.get("executed", [])
    return (all(isinstance(receipt.get(name), (str, type(None))) for name in ("job", "module"))
            and isinstance(executed, list) and all(isinstance(name, str) for name in executed))


def saved_refusals(path):
    """The refusals of the lane's saved `credit.json` at `path`: its `refusals`, a list of records that each name
    their `code` as text. A missing file or a document of another shape is one `missing-result` refusal."""
    refusals = dict_of(read_json(path)).get("refusals") if path.is_file() else None
    if isinstance(refusals, list) and all(isinstance(dict_of(refusal).get("code"), str) for refusal in refusals):
        return refusals
    reason = "credit.json holds no list of refusals" if path.is_file() else "no credit.json"
    return [{"code": "missing-result", "reason": reason}]


def aggregate(lanes, event, expected, inventory):
    """The aggregate verdict over the lane evidence under `lanes`: per lane, its executed domain or why it is incomplete.

    `expected` holds the `revision`, `run` and `attempt` the workflow passed; a receipt of another attempt is listed
    and left unread, and one of this attempt credits only when it records all three."""
    if not all(expected.get(name) for name in ("revision", "run", "attempt")):
        raise ValueError(f"the aggregate needs a nonempty expected revision, run and attempt: {expected}")
    attempt = expected["attempt"]
    domains = lane_domains(event, inventory)
    select, catalog = load_select_tests(), read_catalog()
    found, other, unread = {}, [], []
    for evidence in sorted(path for path in lanes.iterdir() if path.is_dir()) if lanes.is_dir() else []:
        if (evidence / "receipt.json").is_file():
            receipt, refusals = read_json(evidence / "receipt.json"), None
            if not receipt_shaped(receipt):
                unread.append(evidence.name)
                continue
        elif evidence.name.startswith("evidence-barriers-") and (evidence / "report.json").is_file():
            receipt, refusals = barrier_receipt(evidence)
        else:
            unread.append(evidence.name)
            continue
        ran = (receipt.get("ci") or {}).get("GITHUB_RUN_ATTEMPT")
        if ran is not None and str(ran) != str(attempt):
            other.append({"lane": evidence.name, "attempt": ran})
            continue
        if refusals is None and selection_args(receipt.get("job"), receipt.get("module")) is None:
            refusals = saved_refusals(evidence / "credit.json")
        key = (receipt.get("job"), receipt.get("module"))
        found.setdefault(key, []).append((evidence, receipt, refusals))
    lanes_out, complete = [], True
    for key in sorted(set(domains) | set(found), key=lambda key: (key[0] or "", key[1] or "")):
        job, module = key
        name = f"{job} {module}" if module else job
        entries = found.get(key, [])
        names, count = domains.get(key, (None, None))
        reason = None
        if key not in domains:
            reason = f"a receipt for {name}, which the {event} event does not select"
        elif not entries:
            prefix = f"evidence-{job}-{module}-" if job == "loom" else f"evidence-{job}-"
            held = [artifact for artifact in unread if artifact.startswith(prefix)]
            reason = (f"the lane ran, and its artifact {held[0]} holds no receipt" if held else
                      "no receipt: the lane did not run (an unavailable runner, a skipped prerequisite or a missing artifact)")
        elif len(entries) > 1:
            reason = f"{len(entries)} receipts: {[entry[0].name for entry in entries]}"
        else:
            evidence, receipt, refusals = entries[0]
            executed = set(receipt.get("executed", []))
            if (gap := identity_gap(receipt, expected)) is not None:
                reason = gap
            elif receipt.get("completion") != COMPLETED:
                reason = f"completion {receipt.get('completion')}"
            elif (refusals := recredit(select, catalog, inventory, receipt, evidence, expected["revision"])
                  if refusals is None else refusals):
                reason = f"credit refused: {sorted({refusal['code'] for refusal in refusals})}"
            elif not receipt.get("executions"):
                reason = "zero executions"
            elif names is not None and executed != names:
                reason = f"executed {len(executed)} names, missing {sorted(names - executed)[:5]}, outside the domain {sorted(executed - names)[:5]}"
            elif count is not None and receipt.get("executions") != count:
                reason = f"{receipt.get('executions')} executions, declared {count}"
        entry = {"lane": name, "complete": reason is None, "reason": reason}
        if job == "quint":
            entry["blocked"] = quint_blocks(read_catalog())
        if len(entries) == 1:
            receipt = entries[0][1]
            entry.update(executions=receipt.get("executions"), executed=len(receipt.get("executed", [])),
                         artifact=entries[0][0].name)
        advisory = job in ADVISORY_JOBS and key in domains
        if advisory:
            entry["advisory"] = True
        complete &= reason is None or advisory
        lanes_out.append(entry)
    for job, reason in PENDING_JOBS.items():
        if not any(key[0] == job for key in found):
            lanes_out.append({"lane": job, "complete": False, "pending": True, "reason": reason})
    return complete, lanes_out, other


def aggregate_command(lanes, event, expected):
    select = load_select_tests()
    inventory = select.load_inventory(select.INVENTORY)
    complete, entries, other = aggregate(lanes, event, expected, inventory)
    lines = [f"### Rust gate evidence: {'complete' if complete else 'incomplete'} ({event})"]
    for entry in entries:
        if entry["complete"]:
            lines.append(f"- {entry['lane']}: {entry['executions']} executions over {entry['executed']} names, `{entry['artifact']}`")
        elif entry.get("pending"):
            lines.append(f"- {entry['lane']}: pending, no coverage credit, {entry['reason']}")
        elif entry.get("advisory"):
            lines.append(f"- {entry['lane']}: advisory, incomplete, {entry['reason']}")
        else:
            lines.append(f"- {entry['lane']}: incomplete, {entry['reason']}")
        lines.extend(blocked_lines(entry.get("blocked", {})))
    lines += [f"- `{item['lane']}`: attempt {item['attempt']}, kept and not read" for item in other]
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
            summary.write("\n".join(lines) + "\n")
    print("\n".join(lines), file=sys.stderr)
    refusals = [{"code": "incomplete", "record": entry["lane"], "reason": entry["reason"]}
                for entry in entries if not entry["complete"] and not entry.get("advisory") and not entry.get("pending")]
    return emit("aggregate", refusals, {"lanes": entries, "other_attempts": other, "event": event})


def emit(command, refusals, extra=None):
    code = REFUSED if refusals else ADMITTED
    print(json.dumps({"command": command, "code": code, "credited": code == ADMITTED, "refusals": refusals, **(extra or {})}, sort_keys=True))
    for refusal in refusals:
        print(f"verify-receipts: {refusal['code']}: {refusal['reason']}", file=sys.stderr)
    return code


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Admit obligation records and credit them from lane receipts.",
        formatter_class=partial(argparse.HelpFormatter, width=78),
    )
    parser.add_argument("command", choices=["admit", "receipt", "credit", "aggregate", "gate"])
    parser.add_argument("--lanes")
    parser.add_argument("--event")
    parser.add_argument("--action", default="")
    parser.add_argument("--run")
    parser.add_argument("--run-attempt")
    parser.add_argument("--job")
    parser.add_argument("--module")
    parser.add_argument("--evidence")
    parser.add_argument("--revision")
    parser.add_argument("--receipt")
    parser.add_argument("--read-only", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "gate":
        try:
            return gate_command(args.event, args.action, os.environ["RESULTS"])
        except (KeyError, ValueError, AttributeError) as error:
            print(json.dumps({"command": "gate", "code": CRASHED, "credited": False, "refusals": [], "crash": f"{type(error).__name__}: {error}"}))
            return CRASHED
    if args.command == "aggregate":
        if args.lanes is None or args.event not in EVENT_HEAVY:
            parser.error(f"aggregate needs --lanes and --event, one of {sorted(EVENT_HEAVY)}")
        if not (args.revision and args.run and args.run_attempt):
            parser.error("aggregate needs the expected --revision, --run and --run-attempt")
        try:
            expected = {"revision": args.revision, "run": args.run, "attempt": args.run_attempt}
            return aggregate_command(Path(args.lanes), args.event, expected)
        except (Crash, OSError, ValueError, KeyError, TypeError) as error:
            print(json.dumps({"command": "aggregate", "code": CRASHED, "credited": False, "refusals": [], "crash": f"{type(error).__name__}: {error}"}))
            return CRASHED
    if args.command != "admit" and (args.job is None or args.evidence is None):
        parser.error(f"{args.command} needs --job and --evidence")
    if args.job in ("loom", *PROFILED) and args.module is None:
        parser.error(f"the {args.job} job needs --module")
    refusal_types = (Crash, OSError, ValueError, KeyError, TypeError)
    try:
        select = load_select_tests()
        refusal_types += (select.Refusal,)
        catalog = read_catalog()
        inventory = select.load_inventory(select.INVENTORY)
        admission, reported = [], []
        if args.command != "receipt":
            admission = admit(catalog, inventory, workflow_jobs(WORKFLOW.read_text()))
            census, reported = census_judgment(catalog, inventory)
            admission += census
        if args.command == "admit":
            intake, opened = intake_judgment(catalog, INTAKE)
            ratchet, listed = ratchet_judgment(catalog, CONTROL_LESS)
            return emit("admit", admission + intake + ratchet,
                        {"records": len(catalog.get("records", [])), "census_needs_kernel": reported,
                         "control_less": listed, **opened})
        revision = args.revision or git_revision()
        if args.read_only and not (args.command == "credit" and args.receipt):
            parser.error("--read-only judges an imported receipt: it needs credit --receipt")
        if not args.read_only:
            Path(args.evidence).mkdir(parents=True, exist_ok=True)
        imported = []
        if args.receipt:
            receipt = read_json(args.receipt)
            if args.job in LANE_EVIDENCE:
                if args.job in CHECKER_JOBS:
                    derived, reported = derive_checker_receipt(args.job, args.module, args.evidence, revision)
                    if not reported:
                        imported.append({"code": "unbound-input", "record": None, "reason": "report.json differs from the report derived from the evidence"})
                else:
                    derived = build_receipt(select, args.job, args.module, args.evidence, revision)
                if {k: v for k, v in receipt.items() if k != "ci"} != {k: v for k, v in derived.items() if k != "ci"}:
                    imported.append({"code": "unbound-input", "record": None, "reason": "the imported receipt differs from the receipt derived from the evidence"})
        else:
            receipt = build_receipt(select, args.job, args.module, args.evidence, revision)
            (Path(args.evidence) / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        if args.command == "receipt":
            return emit("receipt", [], {"receipt": str(Path(args.evidence) / "receipt.json"), "completion": receipt["completion"]})
        records, refusals = ([], admission) if admission else credit(catalog, receipt, args.job, args.module, revision, args.evidence, inventory)
        refusals = imported + refusals
        extra = {
            "job": args.job, "module": args.module, "obligations": [r["id"] for r in records],
            "executions": receipt.get("executions"), "completion": receipt.get("completion"),
        }
        if args.job == "quint":
            extra["blocked"] = quint_blocks(catalog)
        if args.read_only:
            return emit("credit", refusals, extra)
        (Path(args.evidence) / "credit.json").write_text(json.dumps({"refusals": refusals, **extra}, indent=2, sort_keys=True) + "\n")
        lane = f"{args.job} {args.module}" if args.module else args.job
        verdict = f"credited {len(records)}" if not refusals else f"refused {' '.join(sorted({r['code'] for r in refusals}))}; {len(records)} judged"
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
                summary.write(f"- obligations for {lane}: {verdict}\n")
                summary.writelines(line + "\n" for line in blocked_lines(extra.get("blocked", {})))
        return emit("credit", refusals, extra)
    except refusal_types as error:
        print(json.dumps({"command": args.command, "code": CRASHED, "credited": False, "refusals": [], "crash": f"{type(error).__name__}: {error}"}))
        print(f"verify-receipts: crash: {error}", file=sys.stderr)
        return CRASHED


if __name__ == "__main__":
    sys.exit(main())
