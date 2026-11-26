#!/usr/bin/env python3
"""Credit a Rust test run only when it ran the declared inventory.

Usage:
  select-tests.py listing --cfg loom --module NAME --list FILE --ignored FILE
  select-tests.py listing --cfg ordinary [--crate NAME]... [--target NAME]...
      --list FILE --ignored FILE
  select-tests.py listing --cfg miri|miri-sweep --list FILE --ignored FILE
  select-tests.py listing --cfg qualified --module LANE --list FILE --ignored FILE
  select-tests.py listing --cfg asan --list FILE --ignored FILE
  select-tests.py listing --cfg qemu --list FILE --ignored FILE
  select-tests.py run <listing flags> --output FILE --exit CODE

Every input is cargo's combined stdout and stderr (`2>&1`), with ANSI color
sequences stripped before parsing: `--list` and
`--ignored` hold `cargo test ... -- --list` and `-- --list --ignored`, and
`--output` holds the run. The `Running` and `Doc-tests` headers name each
target, and cargo prints every header in both listings, so a test line before
any header or an `--ignored` capture that lacks a listed target's header is a
tool failure. Each listed target ends in libtest's `N tests, M benchmarks`
footer, whose count must equal the names parsed for it; a doc-test target
prints a merged and a standalone footer, which are summed like its two
summaries; a listing cut short by a kill or timeout lacks that footer. The
inventory is the committed `test-inventory.json` beside this script. Its
`baseline` names the revision its census was reconciled against, and
each report repeats it. The inventory declares no ignores: each cfg's
declared ignores are the registry rows for its targets, Loom modules or Miri
target, and a row for a target the inventory does not declare is an
inventory mismatch.

An ordinary crate may declare `required` witnesses per target: `modules`,
each of which must list at least one runnable test under its `::` prefix, and
`tests`, named controls that must be listed and runnable. A target whose
witnesses name a `catalog` job also requires every test and control that
job's records in the committed `verification/obligations.json` cite, except
those another required target of its crate lists; its own `tests` list holds
only anchors the catalog does not cite. After the ignore and
zero-selection checks, a selected target that omits a module witness or a
control is an inventory mismatch that names it; a listing of unrelated tests
alone is refused. After a run every control must report `ok` and every witness
module must execute a test, which the run's exact outcome identity check
enforces. The target's `witnesses` report names the
controls and counts each module's runnable tests under `runnable_modules`
and, once a run is judged, its executed tests under `executed_modules`.
Witnesses bind the targets a command selects; `--target` names the targets
to judge and the lanes pass none.

Every ignored test in the listing needs one row in the committed
`test-registry.json` beside this script for its cfg, target and ID, with one
class; a missing, repeated or unknown-class row is an inventory mismatch. The
registry's `baseline` names the revision its rows were reconciled against and
must equal the inventory's; a registry at another revision is an inventory
mismatch, and a registry or inventory whose `baseline` is missing or is not a
40-digit lowercase hexadecimal revision is a tool failure. A flaky row that
lacks text for its ticket, date, expiry, recipe or first failure, is dated
after `--today`, expires before its date or after `--today`, or expires more
than 90 days after its date is listed under `policy_gaps` and on stderr
without changing the exit code.

`listing` judges the listings before a run. `run` repeats that judgment, then
judges the run's `test result:` summaries and exit code. A unit or integration
target reports one summary; a doc-test target may report a merged and a
standalone summary, which are summed. After its arguments parse, each command
prints one JSON report on stdout with `cfg`, `baseline`, `code`, `verdict`,
`credited`, `reason`, `policy_gaps` and per-target counts: `listed`, `runnable`, `declared_ignored` and, after a
run, `executed`, `failed`, `observed_ignored` and `filtered`, plus `witnesses` for
a target that declares them. Loom reports are
keyed by module, ordinary reports by target. An ordinary run names no filter,
so its summaries must report zero filtered out: the same `--skip` on both
listings and the run would otherwise drop a runnable test from each and keep
listed and executed in agreement. A Loom run filters by module name, so its
filtered count is reported for information only, and its listing must name
the module's declared binary. In both cfgs the run's per-test outcome lines,
`test NAME ... ok|FAILED|ignored`, must agree with each target's summary in
number, hold only `ok` and `ignored` results, execute exactly the listed
runnable names and ignore exactly the declared ignores. libtest appends a
mode suffix to some outcome lines, ` - should panic` for a `should_panic`
test and ` - compile fail` or ` - compile` for a `compile_fail` or `no_run`
doc-test, while both listings carry the bare name, so the outcome parser
drops the suffix before the comparison. A selection with zero
runnable tests is refused as a zero selection. The identity check ties a run to its listing
when another selection matches its counts.

The miri cfg judges one scoped selection: the inventory's `miri` entry names
one crate, its library target, the exact test IDs the interpreter runs and the
tests it ignores. Both listings are of the whole library target under
`cargo miri test`, so `--ignored` holds every test the interpreter ignores.
Each selected ID must be listed once and runnable; a missing ID, a selected ID
in the `--ignored` listing, a listing that spans another target and an empty
listing are refused, the last as a zero selection. The interpreter's ignores
are reconciled whole: the `--ignored` listing must equal the declared ignores,
so each needs its one `miri` registry row, and a `miri` row for a test the
listing does not ignore is an inventory mismatch. The run filters by the exact
IDs, so its one summary must execute exactly the selected IDs, ignore none and
filter out every other listed test, with outcome lines that agree.

The miri-sweep cfg judges the same listings against the inventory's
`miri_sweep` entry, the exact kernel IDs and the seed count, and a run under
`-Zmiri-many-seeds=0..N` with one rustc thread, which prints `Trying seed: S`
before each seed's libtest run. The run must hold one block per seed from 0
to N - 1 in order, each executing exactly the kernel IDs with `ok` in one
summary that filters out every other listed test, so a partial range, a
repeated or skipped seed, a substitute or duplicate ID, a `FAILING SEED`
line and a nonzero exit are execution mismatches, and an `unsupported
operation` is a tool failure. Its report counts every seed's executions.

The qualified cfg judges the test lane `--module` names in the inventory's
`qualified` map: one crate and target, whether it runs among the target's
declared ignores (`ignored`), its `tier` (`pr` or `nightly`) and rows. A
fuzz lane names its tier and fuzz rows, each a `target` and `seconds`; the
fuzz lanes judge those. Every row has an `id` unique across the map; a
fuzz lane has one row per fuzz target, each with a positive `executions`.
A lane of `isa` rows, an architecture qualification lane, holds no other
kind and names its `arch` (`x86_64` or `aarch64`) and the unique CPU
`features`, in `/proc/cpuinfo`'s names, its host must report.
A test row's `kind` is `campaign`, `search`, `cohort` or `isa`; it lists its exact
`tests` and the expressions its
output must match on exactly one line each, any `witnesses` and its
`bound`, which a `search` row needs. Its `member` expression's one group
must name each of its `members` once, each followed by ` seed N` for every
N below its `seeds` when declared; a `cohort` row needs members and every
test row a witness or members. Both listings are of the lane's target
alone, and their ignores reconcile with the target's declared ignores and
their `ordinary` registry rows; an empty listing is a zero selection, and
a selected test on the wrong side of the ignores is an inventory mismatch.
The run's one summary must execute exactly every row's tests with `ok`,
filter out every other listed test and exit 0, and the report's `rows`
names each row blocked by a test that did not pass or ran more than once,
an incomplete bound such as a capped search, a missing or repeated witness,
or a skipped, repeated or unexpected member, which refuses the run as an
execution mismatch, as an interruption does.

The qemu cfg judges the inventory's `qemu` entry: one crate, one target and
the exact ignored IDs the guest lane runs by exact ID inside its disposable
guest, judged as a qualified lane's selection among its ignores. The
listings are the host build of that target at the same revision, so the
guest's filtered-out count must equal the host's listing less the selection,
which binds the guest's test executable to the revision's census.

The asan cfg judges the inventory's `asan` entry: the lane's targets, each
an ordinary target of some crate, and that entry's own `required` witnesses
per target, judged as the ordinary cfg judges a crate's. The targets' ignores
are their `ordinary` registry rows, since the sanitized build compiles the
same library test targets, plus their `asan` rows, which declare the ignored
tests that only the sanitized build compiles; an `asan` row that repeats an
`ordinary` ignore of its target is an inventory mismatch. The witnesses name the
sanitized build's own controls and the modules whose tests the run attributes
beside the unfiltered run; a listing from an unsanitized build omits those
controls and is refused.

Exit 0 credits the selection or run, 1 is an inventory mismatch, 2 is a tool
failure, 3 is a zero selection and 4 is an execution mismatch. An argument
error exits 2 without a report.
"""

import argparse
import copy
import json
import os
import re
import sys
import time
from collections import Counter
from datetime import date, timedelta
from functools import partial

INVENTORY = os.path.join(os.path.dirname(os.path.realpath(__file__)), "test-inventory.json")
REGISTRY = os.path.join(os.path.dirname(os.path.realpath(__file__)), "test-registry.json")
CATALOG = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "verification", "obligations.json")
CLASSES = {
    "flaky-quarantine",
    "diagnostic-replay",
    "hardware-privileged",
    "guest-privileged",
    "compatibility-exclusion",
    "brittle-bound",
    "interpreter-exclusion",
    "search-bound",
}
QUARANTINE_FIELDS = ("ticket", "date", "expiry", "recipe", "first_failure")
MAX_QUARANTINE_DAYS = 90

CREDITED, INVENTORY_MISMATCH, TOOL_FAILURE, ZERO_SELECTION, EXECUTION_MISMATCH = 0, 1, 2, 3, 4
# The sanitized lane's cfg and the inventory entry it judges.
ASAN = "asan"
REGISTRY_ROWS = {"qualified": ("ordinary",), ASAN: ("ordinary", ASAN), "qemu": ("ordinary",)}
# The cfgs that select exact ignored IDs of one ordinary target, keyed by the inventory entry each judges.
SCOPED = {"qemu": "qemu"}
VERDICTS = {
    CREDITED: "credited",
    INVENTORY_MISMATCH: "inventory mismatch",
    TOOL_FAILURE: "tool failure",
    ZERO_SELECTION: "zero selection",
    EXECUTION_MISMATCH: "execution mismatch",
}

RUNNING = re.compile(r"^\s*Running (?:unittests )?(\S+) \((?:.*/)?([^/()]+?)(?:-[0-9a-f]+)?(?:\.exe)?\)\s*$")
DOC_TESTS = re.compile(r"^\s*Doc-tests (\S+)\s*$")
LISTED = ": test"
FOOTER = re.compile(r"^(\d+) tests?, \d+ benchmarks?$")
OUTCOME = re.compile(r"^test (.+?)( - (?:should panic|compile fail|compile))? \.\.\. (ok|FAILED|ignored)(?:, .*)?$")
# Under `--nocapture`, libtest prints `test NAME ... ` before the case runs, the case's own output after it on
# that line and the following ones, and the outcome alone on a later line.
STARTED = re.compile(r"^test (.+?)( - (?:should panic|compile fail|compile))? \.\.\.(?: (.*))?$")
FINISHED = re.compile(r"^(ok|FAILED|ignored)(?:, .*)?$")
SUMMARY = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
    r"(\d+) measured; (\d+) filtered out; finished in [0-9.]+s$"
)
INTERRUPTED = re.compile(
    r"##\[error\].*(?:was canceled|timed out)"
    r"|.*\(signal: \d+, SIG(?:KILL|TERM)"
    r"|(?:Killed|Terminated)$"
)
DEFAULT_TARGET = "<listing>"
DOC_PREFIX = "doc:"
REVISION = re.compile(r"^[0-9a-f]{40}$")
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


class Refusal(Exception):
    def __init__(self, code, reason, report=None):
        super().__init__(reason)
        self.code = code
        self.report = report or {}


def target_of(stripped):
    if stripped.startswith("Running "):
        running = RUNNING.match(stripped)
        return running.group(2) if running else None
    if stripped.startswith("Doc-tests "):
        doc = DOC_TESTS.match(stripped)
        return DOC_PREFIX + doc.group(1) if doc else None
    return None


def parse_listing(text, source):
    targets, footers = {}, {}
    current = DEFAULT_TARGET
    for line in text.splitlines():
        if line.endswith(LISTED) and len(line) > len(LISTED):
            targets.setdefault(current, []).append(line[: -len(LISTED)])
            continue
        footer = FOOTER.match(line)
        if footer is not None:
            targets.setdefault(current, [])
            if current in footers and not current.startswith(DOC_PREFIX):
                raise Refusal(TOOL_FAILURE, f"{source} prints two test count footers for {current}")
            footers[current] = footers.get(current, 0) + int(footer.group(1))
            continue
        header = target_of(line.strip())
        if header is not None:
            current = header
            targets.setdefault(current, [])
    if DEFAULT_TARGET in targets:
        raise Refusal(TOOL_FAILURE, f"{source} lists {targets[DEFAULT_TARGET]} before any Running header")
    for target, names in targets.items():
        if target not in footers:
            raise Refusal(TOOL_FAILURE, f"{source} lacks the test count footer for {target}")
        if footers[target] != len(names):
            raise Refusal(TOOL_FAILURE, f"{source} counts {footers[target]} tests in {target} but lists {len(names)}")
        repeated = sorted(name for name, count in Counter(names).items() if count > 1)
        if repeated:
            raise Refusal(INVENTORY_MISMATCH, f"{source} lists {repeated} twice in {target}")
    return targets


def new_summary():
    return {"lines": 0, "passed": 0, "failed": 0, "ignored": 0, "filtered": 0, "ok": [], "FAILED": [], "ignored_names": []}


def parse_summaries(text):
    """Parse each target's outcome lines and `test result:` summaries. A case run under `--nocapture` counts
    with the last outcome that arrives alone after it starts, committed when the next case starts, a target
    header or a summary follows, or the text ends; an outcome alone with no started case counts nothing."""
    summaries = {}
    current = DEFAULT_TARGET
    started = verdict = None

    def record(target, name, outcome):
        names = summaries.setdefault(target, new_summary())
        names["ignored_names" if outcome == "ignored" else outcome].append(name)

    def commit():
        nonlocal started, verdict
        if started is not None and verdict is not None:
            record(current, started, verdict)
        started = verdict = None

    for line in text.splitlines():
        stripped = line.strip()
        header = target_of(stripped)
        if header is not None:
            commit()
            current = header
            continue
        if INTERRUPTED.match(stripped):
            raise Refusal(EXECUTION_MISMATCH, f"cancel or timeout marker: {stripped!r}")
        outcome = OUTCOME.match(stripped)
        if outcome is not None:
            commit()
            record(current, outcome.group(1), outcome.group(3))
            continue
        finished = FINISHED.match(stripped) if started is not None else None
        if finished is not None:
            verdict = finished.group(1)
            continue
        begun = STARTED.match(stripped)
        if begun is not None:
            commit()
            started = begun.group(1)
            continue
        if not stripped.startswith("test result:"):
            continue
        commit()
        summary = SUMMARY.match(stripped)
        if summary is None:
            raise Refusal(EXECUTION_MISMATCH, f"malformed summary in {current}: {stripped!r}")
        if (summary.group(1) == "FAILED") != (int(summary.group(3)) != 0):
            raise Refusal(EXECUTION_MISMATCH, f"summary status disagrees with its failed count in {current}: {stripped!r}")
        counts = summaries.setdefault(current, new_summary())
        counts["lines"] += 1
        for key, group in (("passed", 2), ("failed", 3), ("ignored", 4), ("filtered", 6)):
            counts[key] += int(summary.group(group))
    commit()
    return summaries


def names_list(value):
    return isinstance(value, list) and all(isinstance(name, str) for name in value) and len(set(value)) == len(value)


def check_required(scope, declared, anchors=True):
    """Check `scope`'s `required` map: each target's witnesses name nonempty unique modules and a unique tests
    list and, with `anchors`, tests or a catalog job."""
    required = declared.get("required", {})
    if not isinstance(required, dict):
        return f"{scope} needs a required map"
    for target, witnesses in required.items():
        if (
            target not in declared["targets"]
            or not isinstance(witnesses, dict)
            or not {"modules", "tests"} <= set(witnesses) <= {"modules", "tests", "catalog"}
            or not names_list(witnesses["modules"])
            or not witnesses["modules"]
            or not names_list(witnesses["tests"])
            or not isinstance(witnesses.get("catalog", ""), str)
        ):
            return f"{scope} needs nonempty unique required modules and tests lists for a declared target, not {target}"
        if anchors and not (witnesses["tests"] or witnesses.get("catalog")):
            return f"{scope} needs required tests or a catalog job for {target}"
    return None


def check_asan(inventory, owners):
    """Check the asan entry: a nonempty list of declared ordinary targets and its required witnesses, which name
    every target it lists."""
    asan = inventory.get(ASAN)
    if not isinstance(asan, dict) or not names_list(asan.get("targets")) or not asan["targets"]:
        return "the asan entry needs a nonempty unique targets list"
    outside = sorted(set(asan["targets"]) - set(owners))
    if outside:
        return f"the asan entry names targets outside the ordinary crates: {outside}"
    problem = check_required("the asan entry", asan, anchors=False)
    if problem:
        return problem
    unrequired = sorted(set(asan["targets"]) - set(asan.get("required", {})))
    if unrequired:
        return f"the asan entry requires no witnesses of its targets {unrequired}"
    return None


def check_inventory(inventory):
    if not isinstance(inventory, dict) or not {"baseline", "loom", "ordinary", "miri"} <= inventory.keys():
        return "it lacks the baseline and the loom, ordinary and miri cfgs"
    if not isinstance(inventory["baseline"], str) or not REVISION.fullmatch(inventory["baseline"]):
        return "the baseline must be a 40-digit lowercase hexadecimal revision"
    if not isinstance(inventory["loom"], dict) or not isinstance(inventory["ordinary"], dict):
        return "the loom and ordinary cfgs must be maps"
    for module, declared in inventory["loom"].items():
        if not isinstance(declared, dict) or not isinstance(declared.get("target"), str) or not names_list(declared.get("tests")):
            return f"loom module {module} needs a target and a unique tests list"
    miri = inventory["miri"]
    if (
        not isinstance(miri, dict)
        or not isinstance(miri.get("crate"), str)
        or not isinstance(miri.get("target"), str)
        or not names_list(miri.get("tests"))
        or not miri["tests"]
    ):
        return "the miri cfg needs a crate, a target and a nonempty unique tests list"
    sweep = inventory.get("miri_sweep")
    if (
        not isinstance(sweep, dict)
        or not names_list(sweep.get("tests"))
        or not sweep["tests"]
        or not isinstance(sweep.get("seeds"), int)
        or isinstance(sweep["seeds"], bool)
        or sweep["seeds"] < 1
    ):
        return "the miri_sweep entry needs a nonempty unique tests list and a positive seed count"
    for entry in SCOPED.values():
        scoped = inventory.get(entry)
        if (
            not isinstance(scoped, dict)
            or not isinstance(scoped.get("crate"), str)
            or not isinstance(scoped.get("target"), str)
            or not names_list(scoped.get("tests"))
            or not scoped["tests"]
        ):
            return f"the {entry} entry needs a crate, a target and a nonempty unique tests list"
    owners, jobs = {}, {}
    for crate, declared in inventory["ordinary"].items():
        if not isinstance(declared, dict) or not names_list(declared.get("targets")):
            return f"crate {crate} needs a targets list"
        for target in declared["targets"]:
            if target in owners:
                return f"target {target} is declared by crates {owners[target]} and {crate}"
            owners[target] = crate
        problem = check_required(f"crate {crate}", declared)
        if problem:
            return problem
        for target, witnesses in declared.get("required", {}).items():
            job = witnesses.get("catalog")
            if job and job in jobs:
                return f"targets {jobs[job]} and {target} both hold the catalog's {job} tests"
            if job:
                jobs[job] = target
    ignores = [name for name in ("ignored",) if name in miri]
    ignores += [f"loom {module}" for module, declared in inventory["loom"].items() if "ignored" in declared]
    ignores += [f"crate {crate}" for crate, declared in inventory["ordinary"].items() if "ignored" in declared]
    if ignores:
        return f"{', '.join(ignores)} declare ignores; the registry declares every ignore"
    for entry in SCOPED.values():
        scoped = inventory[entry]
        crate = inventory["ordinary"].get(scoped["crate"])
        if crate is None or scoped["target"] not in crate["targets"]:
            return f"the {entry} entry names target {scoped['target']} outside crate {scoped['crate']}"
    problem = check_qualified(inventory)
    if problem:
        return problem
    return check_asan(inventory, owners)


TEST_KINDS, FUZZ_TARGETS = ("campaign", "search", "cohort", "isa"), ("frame", "campaign", "record", "wire")
ISA_ARCHES = ("x86_64", "aarch64")


def positive(value):
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def compiled(value):
    try:
        return re.compile(value)
    except (re.error, TypeError):
        return None


def members_of(row):
    """The members a row's member lines must name: each member, followed by ` seed N` for each declared seed."""
    return [f"{member} seed {seed}" for member in row["members"] for seed in range(row["seeds"])] if "seeds" in row else row["members"]


def check_row(row, fuzz):
    """Return why a qualified row breaks the row schema, or None."""
    name = row.get("id") if isinstance(row, dict) else row
    if not isinstance(row, dict) or not isinstance(name, str):
        return f"qualified row {name!r} needs an id"
    if fuzz:
        good = row.get("target") in FUZZ_TARGETS and positive(row.get("seconds")) and positive(row.get("executions"))
        return None if good else f"fuzz row {name} needs a target of {list(FUZZ_TARGETS)}, positive seconds and positive executions"
    if row.get("kind") not in TEST_KINDS or not names_list(row.get("tests")) or not row["tests"]:
        return f"row {name} needs a kind of {list(TEST_KINDS)} and a unique tests list"
    witnesses = row.get("witnesses", [])
    if not isinstance(witnesses, list) or None in map(compiled, [*witnesses, row.get("bound", "")]):
        return f"row {name} needs regular expressions for its witnesses and bound"
    if row["kind"] == "search" and "bound" not in row:
        return f"search row {name} needs a bound"
    if "members" not in row and "member" not in row and row["kind"] != "cohort":
        return None if witnesses else f"row {name} needs a witness or members"
    member = compiled(row.get("member"))
    if not names_list(row.get("members")) or not row["members"]:
        return f"row {name} needs unique members"
    if member is None or member.groups != 1:
        return f"row {name} needs a member expression with one group"
    if "seeds" in row and not positive(row["seeds"]):
        return f"row {name} needs positive seeds"
    return None


def check_qualified(inventory):
    """Return why the `qualified` map breaks its schema, or None."""
    lanes, ids = inventory.get("qualified"), Counter()
    if not isinstance(lanes, dict) or not lanes:
        return "the qualified entry needs a map of lanes"
    for lane, declared in lanes.items():
        if not isinstance(declared, dict) or declared.get("tier") not in ("pr", "nightly") or not isinstance(declared.get("rows"), list) or not declared["rows"]:
            return f"qualified lane {lane} needs a tier of pr or nightly and rows"
        fuzz = "target" not in declared
        problem = next(filter(None, (check_row(row, fuzz) for row in declared["rows"])), None)
        if problem:
            return problem
        ids.update(row["id"] for row in declared["rows"])
        names = [row["target"] for row in declared["rows"]] if fuzz else selection_of(declared)
        repeated = sorted(name for name, count in Counter(names).items() if count > 1)
        if repeated:
            return f"qualified lane {lane} names {repeated} in more than one row"
        if fuzz and sorted(names) != sorted(FUZZ_TARGETS):
            return f"fuzz lane {lane} needs one row for each target of {list(FUZZ_TARGETS)}"
        if fuzz:
            continue
        crate = inventory["ordinary"].get(declared.get("crate"))
        if crate is None or declared.get("target") not in crate["targets"] or not isinstance(declared.get("ignored"), bool):
            return f"qualified lane {lane} needs a crate, one of its targets and an ignored flag"
        isa = [row["kind"] == "isa" for row in declared["rows"]]
        if any(isa) and not (all(isa) and declared.get("arch") in ISA_ARCHES and names_list(declared.get("features"))
                             and declared["features"]):
            return f"qualified lane {lane} of isa rows needs only isa rows, an arch of {list(ISA_ARCHES)} and unique features"
    repeated = sorted(name for name, count in ids.items() if count > 1)
    return f"qualified row ids {repeated} repeat" if repeated else None


def cited_tests(record):
    """Return the test names a catalog record's `tests` list and its controls' `test` fields name."""
    tests = record.get("tests") if isinstance(record.get("tests"), list) else []
    controls = record.get("controls") if isinstance(record.get("controls"), list) else []
    return [t for t in tests if isinstance(t, str)] + [
        c["test"] for c in controls if isinstance(c, dict) and isinstance(c.get("test"), str)
    ]


def declare(inventory, registry, catalog):
    """Return the inventory with each cfg's ignores from the registry and each catalog target's controls from the catalog.

    A registry row's target names the ordinary target, the Loom module or the
    Miri target that ignores its test; a row for another target is an
    inventory mismatch. A required target that names a catalog job holds
    every test and control of that job's records that no other required
    target of its crate lists and the registry does not ignore for it, and
    its own list names only tests the catalog does not. A catalog test the
    registry ignores stays out so admission can refuse it by record. The
    target keeps its `catalog` job name, so a reader can tell the tests it
    derives from the ones the inventory lists itself. Each test lane of the
    `qualified` map selects only tests on its declared side of its target's
    registry rows: among them when it runs with `--ignored --exact`, outside
    them otherwise.
    """
    declared = copy.deepcopy(inventory)
    for declaration in declared["loom"].values():
        declaration["ignored"] = []
    declared["miri"]["ignored"] = []
    for crate in declared["ordinary"].values():
        crate["ignored"] = {}
    owners = {target: crate for crate in declared["ordinary"].values() for target in crate["targets"]}
    sanitized = {target: [] for target in declared[ASAN]["targets"]}
    for (cfg, target, name) in registry:
        if cfg == "loom" and target in declared["loom"]:
            declared["loom"][target]["ignored"].append(name)
        elif cfg == "miri" and target == declared["miri"]["target"]:
            declared["miri"]["ignored"].append(name)
        elif cfg == "ordinary" and target in owners:
            owners[target]["ignored"].setdefault(target, []).append(name)
        elif cfg == ASAN and target in sanitized:
            sanitized[target].append(name)
        else:
            raise Refusal(INVENTORY_MISMATCH, f"registry row {name} names {cfg} target {target}, which the inventory does not declare")
    for module, declaration in declared["loom"].items():
        if not set(declaration["ignored"]) <= set(declaration["tests"]):
            raise Refusal(INVENTORY_MISMATCH, f"loom module {module} ignores tests it does not declare")
    miri = declared["miri"]
    for scope, tests in (("miri cfg", miri["tests"]), ("miri sweep", declared["miri_sweep"]["tests"])):
        if set(tests) & set(miri["ignored"]):
            raise Refusal(INVENTORY_MISMATCH, f"the {scope} selects tests the interpreter ignores: {sorted(set(tests) & set(miri['ignored']))}")
    for crate, declaration in declared["ordinary"].items():
        derive_witnesses(f"crate {crate}", declaration.get("required", {}), declaration["ignored"], catalog)
    asan = declared[ASAN]
    asan["ignored"] = {}
    for target in asan["targets"]:
        ordinary = owners[target]["ignored"].get(target, [])
        repeated = sorted(set(sanitized[target]) & set(ordinary))
        if repeated:
            raise Refusal(INVENTORY_MISMATCH, f"the asan registry rows repeat ordinary ignores of {target}: {repeated}")
        asan["ignored"][target] = ordinary + sanitized[target]
    derive_witnesses("the asan entry", asan["required"], asan["ignored"], catalog)
    for entry in SCOPED.values():
        scoped = declared[entry]
        unignored = sorted(set(scoped["tests"]) - set(declared["ordinary"][scoped["crate"]]["ignored"].get(scoped["target"], [])))
        if unignored:
            raise Refusal(INVENTORY_MISMATCH, f"the {entry} entry selects tests its target does not ignore: {unignored}")
    for lane, declaration in declared["qualified"].items():
        if "target" not in declaration:
            continue
        names = set(selection_of(declaration))
        ignores = set(declared["ordinary"][declaration["crate"]]["ignored"].get(declaration["target"], []))
        wrong = sorted(names - ignores if declaration["ignored"] else names & ignores)
        if wrong:
            raise Refusal(INVENTORY_MISMATCH, f"qualified lane {lane} selects tests on the wrong side of its target's ignores: {wrong}")
    return declared


def derive_witnesses(scope, required, ignored, catalog):
    """Refuse a required control `scope` ignores, and extend each target that names a catalog job with that
    job's cited tests the other targets omit and the registry does not ignore."""
    for target, witnesses in required.items():
        ignored_controls = set(witnesses["tests"]) & set(ignored.get(target, []))
        if ignored_controls:
            raise Refusal(INVENTORY_MISMATCH, f"{scope} requires controls it ignores in {target}: {sorted(ignored_controls)}")
    for target, witnesses in required.items():
        job = witnesses.get("catalog")
        if not job:
            continue
        # A field of another shape contributes nothing here; admission refuses the record as malformed.
        named = list(dict.fromkeys(
            test for record in catalog.get("records", []) if isinstance(record, dict) and record.get("job") == job
            for test in cited_tests(record)
        ))
        repeated = sorted(set(witnesses["tests"]) & set(named))
        if repeated:
            raise Refusal(INVENTORY_MISMATCH, f"{scope} repeats catalog {job} tests in {target}: {repeated}")
        excluded = {name for other, w in required.items() if other != target for name in w["tests"]}
        excluded |= set(ignored.get(target, []))
        witnesses["tests"] += [name for name in named if name not in excluded]


def load_inventory(path):
    """Return the declared inventory: the committed file with its ignores from the registry and its catalog controls."""
    try:
        inventory = json.loads(read(path))
    except ValueError as error:
        raise Refusal(TOOL_FAILURE, f"unreadable inventory {path}: {error}") from error
    problem = check_inventory(inventory)
    if problem:
        raise Refusal(TOOL_FAILURE, f"malformed inventory {path}: {problem}")
    registry = load_registry(REGISTRY, inventory["baseline"])
    try:
        catalog = json.loads(read(CATALOG))
    except ValueError as error:
        raise Refusal(TOOL_FAILURE, f"unreadable catalog {CATALOG}: {error}") from error
    return declare(inventory, registry, catalog)


def read(path):
    try:
        with open(path, encoding="utf-8") as file:
            return ANSI.sub("", file.read())
    except (OSError, UnicodeDecodeError) as error:
        raise Refusal(TOOL_FAILURE, f"unreadable input {path}: {error}") from error


def check_ignores(scope, names, listed_ignored, declared_ignored, report):
    undeclared = sorted(set(listed_ignored) - set(declared_ignored))
    if undeclared:
        raise Refusal(INVENTORY_MISMATCH, f"{scope} ignores undeclared tests {undeclared}", report)
    missing = sorted(set(declared_ignored) - set(listed_ignored))
    if missing:
        raise Refusal(INVENTORY_MISMATCH, f"{scope} declares ignores absent from the --ignored listing {missing}", report)
    absent = sorted(set(listed_ignored) - set(names))
    if absent:
        raise Refusal(INVENTORY_MISMATCH, f"{scope} ignores tests absent from the --list listing {absent}", report)


def check_ignored_capture(listing, ignored, report):
    lacking = sorted(set(listing) - set(ignored))
    if lacking:
        raise Refusal(TOOL_FAILURE, f"the --ignored listing lacks targets {lacking}", report)


def judge_loom(inventory, module, listing, ignored):
    declared = inventory["loom"].get(module)
    if declared is None:
        raise Refusal(TOOL_FAILURE, f"module {module!r} is not in the inventory")
    if len(set(listing) | set(ignored)) > 1:
        raise Refusal(INVENTORY_MISMATCH, f"module {module} listing spans targets {sorted(set(listing) | set(ignored))}")
    target = next(iter(listing), DEFAULT_TARGET)
    names = listing.get(target, [])
    report = {module: {"listed": len(names), "declared": len(declared["tests"]), "target": target}}
    if not names:
        raise Refusal(ZERO_SELECTION, f"module {module} listed no tests in --list", report)
    if target != declared["target"]:
        raise Refusal(INVENTORY_MISMATCH, f"module {module} listing names binary {target}, declared {declared['target']}", report)
    check_ignored_capture(listing, ignored, report)
    listed_ignored = ignored[target]
    missing = sorted(set(declared["tests"]) - set(names))
    if missing:
        raise Refusal(INVENTORY_MISMATCH, f"module {module} omits declared tests {missing}", report)
    extra = sorted(set(names) - set(declared["tests"]))
    if extra:
        raise Refusal(INVENTORY_MISMATCH, f"module {module} lists undeclared tests {extra}", report)
    check_ignores(f"module {module}", names, listed_ignored, declared["ignored"], report)
    report[module].update(
        runnable=len(names) - len(declared["ignored"]),
        declared_ignored=len(declared["ignored"]),
    )
    return report, {module: (set(names) - set(declared["ignored"]), set(declared["ignored"]))}


def module_counts(names, modules):
    return {module: sum(name.startswith(module + "::") for name in names) for module in modules}


def check_witnesses(target, runnable, required, report):
    """Refuse a listing whose runnable names omit a required module or control."""
    modules = module_counts(runnable, required["modules"])
    absent = sorted(module for module, count in modules.items() if count == 0)
    if absent:
        raise Refusal(INVENTORY_MISMATCH, f"{target} lists no runnable test of required modules {absent}", report)
    missing = sorted(set(required["tests"]) - runnable)
    if missing:
        raise Refusal(INVENTORY_MISMATCH, f"{target} omits required controls {missing}", report)
    report[target]["witnesses"] = {"runnable_modules": modules, "controls": sorted(required["tests"])}


def judge_ordinary(inventory, crates, targets, listing, ignored, entry=None):
    """Judge the listings of `crates`' targets, or of `targets` among them, against the crates' required
    witnesses and ignores, or against the `required` witnesses and `ignored` tests of `entry` when given."""
    declared_targets, declared_ignored, required = set(), {}, {}
    for crate in crates:
        if crate not in inventory["ordinary"]:
            raise Refusal(TOOL_FAILURE, f"crate {crate!r} is not in the inventory")
        declared_targets |= set(inventory["ordinary"][crate]["targets"])
        declared_ignored.update(inventory["ordinary"][crate]["ignored"])
        required.update(inventory["ordinary"][crate].get("required", {}))
    if entry is not None:
        declared_ignored.update(entry["ignored"])
        required = dict(entry["required"])
    if targets:
        unknown = sorted(set(targets) - declared_targets)
        if unknown:
            raise Refusal(TOOL_FAILURE, f"targets {unknown} are not declared for crates {crates}")
        declared_targets = set(targets)
    report, identities = {}, {}
    if sum(len(names) for names in listing.values()) == 0:
        raise Refusal(ZERO_SELECTION, "the --list listing holds no tests", report)
    missing = sorted(declared_targets - set(listing))
    if missing:
        raise Refusal(INVENTORY_MISMATCH, f"declared targets absent from the --list listing {missing}", report)
    extra = sorted(set(listing) - declared_targets)
    if extra:
        raise Refusal(INVENTORY_MISMATCH, f"the --list listing holds undeclared targets {extra}", report)
    stray = sorted(set(ignored) - set(listing))
    if stray:
        raise Refusal(INVENTORY_MISMATCH, f"the --ignored listing names targets absent from --list {stray}", report)
    check_ignored_capture(listing, ignored, report)
    for target, names in listing.items():
        expected = declared_ignored.get(target, [])
        report[target] = {"listed": len(names), "runnable": len(names) - len(expected), "declared_ignored": len(expected)}
        check_ignores(target, names, ignored[target], expected, report)
        identities[target] = (set(names) - set(expected), set(expected))
    if sum(counts["runnable"] for counts in report.values()) == 0:
        raise Refusal(ZERO_SELECTION, "the --list listing holds no runnable tests", report)
    for target in sorted(set(report) & set(required)):
        check_witnesses(target, identities[target][0], required[target], report)
    return report, identities


def judge_asan(inventory, listing, ignored):
    """Judge the sanitized lane's listings: the asan entry's targets with its own witnesses, ignoring what their
    ordinary and asan registry rows ignore."""
    asan = inventory[ASAN]
    crates = sorted(crate for crate, declared in inventory["ordinary"].items() if set(declared["targets"]) & set(asan["targets"]))
    return judge_ordinary(inventory, crates, asan["targets"], listing, ignored, entry=asan)


def judge_miri(inventory, listing, ignored, selection):
    declared = inventory["miri"]
    target = declared["target"]
    report = {target: {"listed": sum(len(names) for names in listing.values()), "selected": len(selection)}}
    if report[target]["listed"] == 0:
        raise Refusal(ZERO_SELECTION, "the --list listing holds no tests", report)
    if set(listing) != {target}:
        raise Refusal(INVENTORY_MISMATCH, f"the miri listing spans targets {sorted(listing)}, declared {target}", report)
    check_ignored_capture(listing, ignored, report)
    names, listed_ignored = listing[target], ignored[target]
    missing = sorted(set(selection) - set(names))
    if missing:
        raise Refusal(INVENTORY_MISMATCH, f"{target} omits selected tests {missing}", report)
    selected_ignored = sorted(set(selection) & set(listed_ignored))
    if selected_ignored:
        raise Refusal(INVENTORY_MISMATCH, f"{target} ignores selected tests {selected_ignored}", report)
    check_ignores(target, names, listed_ignored, declared["ignored"], report)
    report[target].update(runnable=len(selection), declared_ignored=0, interpreter_ignored=len(listed_ignored))
    return report, {target: (set(selection), set())}


def selection_of(declared):
    """The exact IDs a qualified test lane runs: every test of its rows."""
    return [test for row in declared["rows"] for test in row["tests"]]


def judge_scoped(inventory, cfg, listing, ignored):
    """Judge a scoped lane's listings: its entry's one target, whose declared ignores hold the IDs it selects."""
    declared = inventory[SCOPED[cfg]]
    return judge_selection(inventory, cfg, declared["crate"], declared["target"], declared["tests"], True, listing, ignored)


def judge_qualified(inventory, lane, listing, ignored):
    """Judge a qualified test lane's listings: its one target, with its selection on its declared side of the ignores."""
    declared = inventory["qualified"][lane]
    return judge_selection(inventory, lane, declared["crate"], declared["target"], selection_of(declared), declared["ignored"], listing, ignored)


def judge_selection(inventory, lane, crate, target, selection, among_ignored, listing, ignored):
    """Judge listings of one target for `lane`'s exact selection, which lies among the target's ignores when
    `among_ignored` and outside them otherwise."""
    report = {target: {"listed": sum(len(names) for names in listing.values()), "selected": len(selection)}}
    if report[target]["listed"] == 0:
        raise Refusal(ZERO_SELECTION, "the --list listing holds no tests", report)
    if set(listing) != {target}:
        raise Refusal(INVENTORY_MISMATCH, f"the {lane} listing spans targets {sorted(listing)}, declared {target}", report)
    check_ignored_capture(listing, ignored, report)
    expected = inventory["ordinary"][crate]["ignored"].get(target, [])
    check_ignores(target, listing[target], ignored[target], expected, report)
    side = set(ignored[target]) if among_ignored else set(listing[target]) - set(ignored[target])
    absent = sorted(set(selection) - side)
    if absent:
        raise Refusal(INVENTORY_MISMATCH, f"{target} lists no {'ignored' if among_ignored else 'runnable'} tests {absent}", report)
    report[target].update(runnable=len(selection), declared_ignored=0)
    return report, {target: (set(selection), set())}


def judge_rows(declared, text, summaries):
    """Judge every row of a qualified lane from its run output; return each row's verdict and blocked reasons."""
    lines = [line.strip() for line in text.splitlines()]
    passed = Counter(name for summary in summaries.values() for name in summary["ok"])
    verdicts = []
    for row in declared["rows"]:
        unpassed = [test for test in row["tests"] if test not in passed]
        repeated = [test for test in row["tests"] if passed[test] > 1]
        reasons = [f"tests {unpassed} did not pass"] if unpassed else []
        reasons += [f"tests {repeated} ran more than once"] if repeated else []
        bound = [(row["bound"], "bound")] if "bound" in row else []
        for pattern, role in bound + [(witness, "witness") for witness in row.get("witnesses", [])]:
            found = sum(1 for line in lines if re.search(pattern, line))
            if found != 1:
                reasons.append(f"bound incomplete: {found} lines match {pattern!r}" if role == "bound"
                               else f"{'missing' if found == 0 else 'repeated'} witness {pattern!r}")
        if "members" in row:
            named = Counter(found.group(1) for found in (re.search(row["member"], line) for line in lines) if found)
            for verb, names in (("skipped", set(members_of(row)) - set(named)), ("unexpected", set(named) - set(members_of(row))),
                                ("repeated", {name for name, count in named.items() if count > 1})):
                if names:
                    reasons.append(f"{verb} members {sorted(names)}")
        verdicts.append({"id": row["id"], "kind": row["kind"], "credited": not reasons, "reasons": reasons})
    return verdicts


def check_scoped_filter(report):
    """Refuse a scoped run that filtered out other than every listed test outside the selection."""
    for target, counts in report.items():
        expected = counts["listed"] - counts["selected"]
        if counts["filtered"] != expected:
            raise Refusal(EXECUTION_MISMATCH, f"{target} filtered out {counts['filtered']} tests, expected {expected}", report)


MIRI_SELECTIONS = {"miri": "miri", "miri-sweep": "miri_sweep"}
TRYING_SEED = re.compile(r"^Trying seed: (\d+)$")
FAILING_SEED = re.compile(r"^FAILING SEED: (\d+)")
UNSUPPORTED = "unsupported operation"


def judge_sweep(text, seeds, report, identities, exit_code):
    """Judge a many-seeds run block by block; every seed's run is one ordinary miri run of the kernels."""
    target = next(iter(report))
    blocks, current = [], None
    for line in text.splitlines():
        stripped = line.strip()
        if UNSUPPORTED in stripped:
            raise Refusal(TOOL_FAILURE, f"the interpreter met an {stripped}", report)
        failing = FAILING_SEED.match(stripped)
        if failing:
            raise Refusal(EXECUTION_MISMATCH, f"seed {failing.group(1)} failed", report)
        trying = TRYING_SEED.match(stripped)
        if trying:
            current = [int(trying.group(1)), []]
            blocks.append(current)
        elif current is not None:
            current[1].append(line)
    found = [seed for seed, _ in blocks]
    if found != list(range(seeds)):
        raise Refusal(EXECUTION_MISMATCH, f"the run covered seeds {found[:3]}..{found[-3:]} ({len(found)}), declared 0..{seeds}", report)
    executions = 0
    for seed, lines in blocks:
        counts = dict(report[target])
        summaries = parse_summaries("\n".join(lines))
        stray = sorted(set(summaries) - {DEFAULT_TARGET})
        if stray:
            raise Refusal(EXECUTION_MISMATCH, f"seed {seed} reports other targets {stray}", report)
        block = {target: summaries.get(DEFAULT_TARGET, new_summary())}
        try:
            judged = judge_run({target: counts}, identities, block, 0, unfiltered=False)
            check_scoped_filter(judged)
        except Refusal as refusal:
            raise Refusal(refusal.code, f"seed {seed}: {refusal}", report) from refusal
        executions += judged[target]["executed"]
    if exit_code != 0:
        raise Refusal(EXECUTION_MISMATCH, f"the run exited {exit_code}", report)
    report[target].update(executed=executions, seeds=seeds, failed=0, observed_ignored=0)
    return report


def record_witness_outcomes(witnesses, passed):
    """Record each required module's executed count for a run whose executed names equal the listing."""
    witnesses["executed_modules"] = module_counts(passed, witnesses["runnable_modules"])


def check_outcomes(target, counts, summary, expected, report):
    if summary["FAILED"]:
        raise Refusal(EXECUTION_MISMATCH, f"{target} reports failed outcomes {sorted(summary['FAILED'])}", report)
    executed = summary["ok"] + summary["FAILED"]
    partitions = (
        ("executed", executed, counts["executed"], expected[0]),
        ("ignored", summary["ignored_names"], counts["observed_ignored"], expected[1]),
    )
    for verb, names, count, _ in partitions:
        if len(names) != count:
            raise Refusal(EXECUTION_MISMATCH, f"{target} reports {len(names)} {verb} outcomes for a summary of {count}", report)
    for verb, names, _, expected_names in partitions:
        outside = sorted(set(names) - expected_names)
        if outside:
            raise Refusal(EXECUTION_MISMATCH, f"{target} {verb} tests outside the listing {outside}", report)
        missing = sorted(expected_names - set(names))
        if missing:
            raise Refusal(EXECUTION_MISMATCH, f"{target} omits listed {verb} tests {missing}", report)
    if "witnesses" in counts:
        record_witness_outcomes(counts["witnesses"], set(summary["ok"]))


def judge_run(report, identities, summaries, exit_code, unfiltered):
    for target, counts in report.items():
        summary = summaries.get(target)
        if summary is None:
            raise Refusal(EXECUTION_MISMATCH, f"{target} produced no summary", report)
        if summary["lines"] != 1 and not target.startswith(DOC_PREFIX):
            raise Refusal(EXECUTION_MISMATCH, f"{target} produced {summary['lines']} summaries", report)
        counts.update(
            executed=summary["passed"] + summary["failed"],
            failed=summary["failed"],
            observed_ignored=summary["ignored"],
            filtered=summary["filtered"],
        )
    stray = sorted(set(summaries) - set(report))
    if stray:
        raise Refusal(EXECUTION_MISMATCH, f"summaries from unlisted targets {stray}", report)
    for target, counts in report.items():
        if counts["failed"]:
            raise Refusal(EXECUTION_MISMATCH, f"{target} failed {counts['failed']} tests", report)
        if counts["executed"] != counts["runnable"]:
            raise Refusal(
                EXECUTION_MISMATCH,
                f"{target} executed {counts['executed']} of {counts['runnable']} runnable tests",
                report,
            )
        if counts["observed_ignored"] != counts["declared_ignored"]:
            raise Refusal(
                EXECUTION_MISMATCH,
                f"{target} ignored {counts['observed_ignored']}, declared {counts['declared_ignored']}",
                report,
            )
        if unfiltered and counts["filtered"]:
            raise Refusal(EXECUTION_MISMATCH, f"{target} filtered out {counts['filtered']} tests", report)
        check_outcomes(target, counts, summaries[target], identities[target], report)
    if exit_code != 0:
        raise Refusal(EXECUTION_MISMATCH, f"the run exited {exit_code}", report)
    return report


def loom_summaries(summaries, module, report):
    target = report[module]["target"]
    summary = summaries.get(target)
    if len(summaries) != 1 or summary is None or summary["lines"] != 1:
        found = {name: counts["lines"] for name, counts in summaries.items()}
        raise Refusal(EXECUTION_MISMATCH, f"a loom run needs one summary from {target}, found {found}", report)
    return {module: summary}


def load_registry(path, baseline):
    """Return the rows keyed by (cfg, target, id); `baseline` is the inventory revision the rows must record."""
    try:
        document = json.loads(read(path))
        rows, recorded = document["rows"], document["baseline"]
    except (ValueError, KeyError, TypeError) as error:
        raise Refusal(TOOL_FAILURE, f"unreadable registry {path}: {error}") from error
    if not isinstance(recorded, str) or not REVISION.fullmatch(recorded):
        raise Refusal(TOOL_FAILURE, f"malformed registry {path}: the baseline must be a 40-digit lowercase hexadecimal revision")
    if recorded != baseline:
        raise Refusal(INVENTORY_MISMATCH, f"the registry records baseline {recorded}, the inventory {baseline}")
    registry = {}
    for row in rows:
        if not isinstance(row, dict) or not all(isinstance(row.get(k), str) for k in ("cfg", "target", "id")) or not row.get("cause"):
            raise Refusal(TOOL_FAILURE, f"registry row {row!r} needs cfg, target, id and cause text")
        if not isinstance(row.get("class"), str) or row["class"] not in CLASSES:
            raise Refusal(INVENTORY_MISMATCH, f"registry row {row['id']} has class {row.get('class')!r}, not one of {sorted(CLASSES)}")
        if row["class"] == "flaky-quarantine" and not str(row["cause"]).startswith("flaky"):
            raise Refusal(INVENTORY_MISMATCH, f"registry row {row['id']} is flaky-quarantine but its cause states no flakiness")
        key = (row["cfg"], row["target"], row["id"])
        if key in registry:
            raise Refusal(INVENTORY_MISMATCH, f"registry lists {row['id']} in {row['target']} twice")
        registry[key] = row
    return registry


def policy_gaps(rows, today):
    gaps = []
    for row in rows:
        if row["class"] != "flaky-quarantine":
            continue
        missing = [field for field in QUARANTINE_FIELDS if not isinstance(row.get(field), str) or not row[field]]
        if missing:
            gaps.append(f"{row['id']} lacks text for {', '.join(missing)}")
            continue
        try:
            dated, expiry = (date.fromisoformat(row[field]) for field in ("date", "expiry"))
        except ValueError:
            gaps.append(f"{row['id']} needs ISO date and expiry fields")
            continue
        if dated > today:
            gaps.append(f"{row['id']} is dated {dated}, after {today}")
        elif expiry < dated:
            gaps.append(f"{row['id']} expires on {expiry}, before its date {dated}")
        elif expiry < today:
            gaps.append(f"{row['id']} expired on {expiry}")
        elif expiry > dated + timedelta(days=MAX_QUARANTINE_DAYS):
            gaps.append(f"{row['id']} expires more than {MAX_QUARANTINE_DAYS} days after {dated}")
    return gaps


def judge_registry(registry, cfgs, module, ignored, today):
    """Return the policy gaps of the rows that declare `ignored`, each test's row being the first of the registry
    `cfgs` that names it; a test that no row of `cfgs` names is an inventory mismatch."""
    keys, missing = [], []
    for target, name in sorted((target, name) for target, names in ignored.items() for name in names):
        candidates = [(cfg, module if cfg == "loom" else target, name) for cfg in cfgs]
        key = next((key for key in candidates if key in registry), None)
        if key is None:
            missing.append(f"{candidates[0][1]}: {name}")
        else:
            keys.append(key)
    if missing:
        raise Refusal(INVENTORY_MISMATCH, f"ignored tests without a registry row {missing}")
    return policy_gaps([registry[key] for key in sorted(keys)], today)


def judge(args):
    inventory = load_inventory(INVENTORY)
    args.baseline = inventory["baseline"]
    registry = load_registry(REGISTRY, args.baseline)
    listing = parse_listing(read(args.list), "--list")
    ignored = parse_listing(read(args.ignored), "--ignored")
    if args.cfg == "loom" and args.module not in inventory["loom"]:
        raise Refusal(TOOL_FAILURE, f"the loom cfg needs --module; module {args.module!r} is not in the inventory")
    if args.cfg == "qualified" and "target" not in inventory["qualified"].get(args.module, {}):
        raise Refusal(TOOL_FAILURE, f"the qualified cfg needs --module naming a test lane; {args.module!r} is not one")
    selection = MIRI_SELECTIONS.get(args.cfg)
    rows = ("miri",) if selection else REGISTRY_ROWS.get(args.cfg, (args.cfg,))
    args.gaps = judge_registry(registry, rows, args.module, ignored, date.fromisoformat(args.today))
    if args.cfg == "loom":
        report, identities = judge_loom(inventory, args.module, listing, ignored)
    elif args.cfg in SCOPED:
        report, identities = judge_scoped(inventory, args.cfg, listing, ignored)
    elif args.cfg == "qualified":
        report, identities = judge_qualified(inventory, args.module, listing, ignored)
    elif args.cfg == ASAN:
        report, identities = judge_asan(inventory, listing, ignored)
    elif selection:
        report, identities = judge_miri(inventory, listing, ignored, inventory[selection]["tests"])
    else:
        crates = args.crate or sorted(inventory["ordinary"])
        report, identities = judge_ordinary(inventory, crates, args.target, listing, ignored)
    if args.command == "run" and args.cfg == "miri-sweep":
        return judge_sweep(read(args.output), inventory["miri_sweep"]["seeds"], report, identities, args.exit)
    if args.command == "run":
        text = read(args.output)
        try:
            summaries = args.summaries = parse_summaries(text)
        except Refusal as refusal:
            if args.cfg == "qualified":
                args.rows = [{"id": row["id"], "kind": row["kind"], "credited": False, "reasons": [str(refusal)]}
                             for row in inventory["qualified"][args.module]["rows"]]
            raise
        if args.cfg == "loom":
            summaries = loom_summaries(summaries, args.module, report)
        if args.cfg == "qualified":
            args.rows = judge_rows(inventory["qualified"][args.module], text, summaries)
        report = judge_run(report, identities, summaries, args.exit, unfiltered=args.cfg in ("ordinary", ASAN))
        if args.cfg in ("miri", "qualified") or args.cfg in SCOPED:
            check_scoped_filter(report)
        blocked = [f"{row['id']}: {'; '.join(row['reasons'])}" for row in args.rows if not row["credited"]]
        if blocked:
            raise Refusal(EXECUTION_MISMATCH, f"blocked rows: {' | '.join(blocked)}", report)
    return report


def document(args, code, reason, report):
    """The JSON report of a judgment that ended with `code`."""
    return {
        "cfg": args.cfg, "baseline": args.baseline, "code": code, "verdict": VERDICTS[code],
        "credited": code == CREDITED, "reason": reason, "targets": report, "policy_gaps": list(args.gaps),
        "module": args.module, "rows": args.rows,
    }


def verdict(argv=None):
    """Judge the command line `argv` and return its JSON report and its parsed arguments. A run's arguments also
    carry `summaries`, the run's parsed summaries, once the run has been parsed; the miri-sweep cfg parses each
    seed's block apart and leaves them unset."""
    # argparse imports shutil at startup to measure the terminal unless the
    # formatter has a width. Width 78 is argparse's width off a terminal.
    parser = argparse.ArgumentParser(
        description="Credit a Rust test run only when it ran the declared inventory.",
        formatter_class=partial(argparse.HelpFormatter, width=78),
    )
    parser.add_argument("command", choices=["listing", "run"])
    parser.add_argument("--cfg", choices=["ordinary", "loom", "miri", "miri-sweep", "qualified", ASAN, "qemu"], required=True)
    parser.add_argument("--module")
    parser.add_argument("--crate", action="append")
    parser.add_argument("--target", action="append")
    parser.add_argument("--list", required=True)
    parser.add_argument("--ignored", required=True)
    parser.add_argument("--output")
    parser.add_argument("--exit", type=int)
    parser.add_argument("--today", default=time.strftime("%Y-%m-%d"))
    args = parser.parse_args(argv)
    if args.command == "run" and (args.output is None or args.exit is None):
        parser.error("run needs --output and --exit")
    args.gaps, args.baseline, args.rows = [], None, []
    try:
        return document(args, CREDITED, None, judge(args)), args
    except Refusal as refusal:
        return document(args, refusal.code, str(refusal), refusal.report), args
    except Exception as error:
        return document(args, TOOL_FAILURE, f"unexpected {type(error).__name__}: {error}", {}), args


def main(argv=None):
    report, args = verdict(argv)
    print(json.dumps(report, sort_keys=True))
    if report["reason"]:
        print(f"select-tests: {report['reason']}", file=sys.stderr)
    for gap in args.gaps:
        print(f"select-tests: policy gap: {gap}", file=sys.stderr)
    return report["code"]


if __name__ == "__main__":
    sys.exit(main())
