#!/usr/bin/env python3
"""Pin the Quint installation and credit the session, detector, route, tenure, prefix, coverage, capture, preserve, suffix, saturation, key-operation, fill, watchdog and burst cases only when the runner reached every declared outcome.

Usage:
  judge-quint.py trees --node DIR --modules DIR
  judge-quint.py identity --java PATH --node PATH --apalache DIR --quint PATH --evidence DIR
  judge-quint.py judge --evidence DIR [--revision SHA]
  judge-quint.py shard --shard 0|1
  judge-quint.py pins --evidence DIR [--revision SHA]

`verification/quint/expected.json` declares the JDK, Node.js, Apalache and
Quint archives with their sha256, the JDK and Node.js versions and the
digests of their installed trees, the Apalache version and the digest of its
installed distribution, launcher and jar alike, the Quint version and the
digest of its installed `node_modules` tree, which holds every dependency
`verification/quint/package-lock.json` pins, the worker count, and the case
names, which must equal the cases of `quint/check.py`, each named once by the
list and by the runner. Its `cases` map
restates every runner case on one line: the outcome, `ok` for a typecheck,
replay or simulation and otherwise the declared outcome and the property the
case checks, as `control_text` of `scripts/verify-receipts.py` reads a Quint
control, and, for a passing TLC-backend case alone, `distinct`, the
distinct-state count its search must report, a positive integer. An entry
holds no other field. A `cases` map that names other
cases than the runner's, an entry whose outcome differs from the runner's, a
passing TLC-backend entry without a count, any other entry with one, an entry
that is not a mapping or holds another field and a count that is not a
positive integer are drift, refused by case name; a registry without a `cases`
map is drift as well. The self-tests keep the committed entries in name order,
one line each. A name repeated in one JSON object of the registry,
`identity.json` or `results.json`, the JSON files the judge parses, and a JSON
root other than an object, is a tool failure. `trees` checks a
staged Node.js tree and `node_modules` tree against their declared digests
before the lane publishes its cache entry. The runner owns
each case's instance, mutation, property and outcome, and refuses any other
outcome. `identity` records `java -version`, the digest of the installed JDK
tree, `node --version` and the digest of the Node.js tree, the digest of the
Apalache distribution Quint launches from `QUINT_HOME`, `quint --version`,
the Apalache version Quint launches, the
digest of the `node_modules` tree that holds Quint and the digests of the
model and the runner under `quint/`, of the workspace and `kestrike`
manifests and of every tracked file of `kestrike` and its path dependency
`spdk-sys`, which the replay cases compile.

`judge` credits only when the identity matches the declaration and the
committed model, runner and compiled sources, `quint.argv` is the runner with the identified
quint, the declared workers and the evidence's `quint` directory,
`quint.exit` is 0, and `results.json`, the lane's copy of the runner's
results, is complete, names no failure, ran on a worktree with no modified
tracked file, ran under the declared JDK and Quint and names exactly the
declared cases, each with the runner's declared outcome and command, its own
port for a TLC case and none for another case, exit
status 0 for a passing check or the simulation and nonzero for a declared
violation, the raw model and instance files and digests, and raw command logs from which every family's outcomes are re-derived,
with `replay.qnt` at the runner's constants as the Connect replay's instance,
explored states for every TLC case, the pinned distinct-state count for each
passing TLC case, a counterexample for each violation of the length the
runner's `judge` requires, which for a recipe mutant that declares no `trace`
is the initial state and one state per recipe action, so the trace ends at
the recipe's last action, the
loop for the broken variant, every witness's trace count for the
simulation, and for the Connect replay the declared trace count, more
actions than traces and every model action reached, reported apart from the
model's results. A runner exit of 124, 130 or 143 is incomplete. Any other
nonzero exit is an outcome mismatch when `results.json` names the refused
case, and a tool failure when the runner exited before recording one. It writes
`report.json` and `receipt.json` in the form `verify-receipts.py credit
--receipt` imports. Exit 0 credits, 1 is an outcome mismatch, 2 is a tool
failure or drift, 3 is incomplete. A report or receipt the judge cannot write
exits 2. A count that differs from its pin is an outcome mismatch; the count
compared is the one the runner's `judge` reads from the retained `quint.log`.

`pins` prints the `cases` entry of each case of the run, one line each in name
order, with each passing TLC case's count read from its retained log. It
applies every check of `judge` except the comparisons with the `cases` map,
the reads of the receipt's inputs included, and writes no report or receipt.
For a run those checks refuse it prints nothing on stdout, writes the refusal
to stderr and exits with the refusal's code, which is the code `judge` gives
the same evidence when the `cases` map is current and each pinned count equals
its log: a stale but well-formed count is an outcome mismatch at its case. It
reads lane evidence: the
directory a `bash scripts/rust-lane.sh quint` run wrote, at the path its
`quint.argv` records, from a checkout at the run's revision. The output
directory of `quint/check.py` alone lacks `identity.json`, `quint.argv` and
`quint.exit`, and evidence moved to another path fails the command check, so
both are refused.

The CI shards select a disjoint partition of the same declaration. Their
producer identities and result records bind the run and attempt. The join
reconstructs each shard's argv from its recorded producer paths, reads the
case files only from the downloaded artifact, and credits one full receipt
only after both exact case sets pass. The receipt binds the raw artifact
names and their input digests in `quint-shards.json`. A refused join writes
the same files: its manifest and `pins.txt` hold the shards judged before the
refusal, so its receipt binds the sharded evidence whatever the verdict.

The join takes the run and attempt it requires of the shards from
`GITHUB_RUN_ID` and `GITHUB_RUN_ATTEMPT` alone. Outside its workflow attempt,
as `verify-receipts.py credit --receipt --read-only` and the acceptance and
readiness judges run it, a join is re-derived from a checkout at the run's
revision and a directory, at any path, that holds the files of the
`evidence-quint` artifact and, under `shards/`, a copy of both raw artifacts
as directories named `quint-shard-INDEX-RUN-ATTEMPT`, with the two variables
set to the producing run and attempt for that command. A directory with no
`shards/` is judged as a single run and refused, and shards judged with no
run identity, or with another run's, are refused.

The manifest's optional `blocked` mapping names declared cases and nonempty
external gates. Each case must still reach its outcome; its report sets
`credited: false`, and its name is omitted from receipt executions.
"""

import argparse
import collections
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = ROOT / "verification/quint/expected.json"
MODELS = ROOT / "quint"
CREDITED, MISMATCH, TOOL_FAILURE, INCOMPLETE = 0, 1, 2, 3
VERDICTS = {CREDITED: "credited", MISMATCH: "outcome mismatch", TOOL_FAILURE: "tool failure", INCOMPLETE: "incomplete"}
INTERRUPTED = (124, 130, 143)
SHARDS = (0, 1)
SHARD_INPUTS = ("identity.json", "quint.argv", "quint.exit", "quint.txt", "results.json")
# RuntimeError covers RecursionError, which a fixture nested past the parser's recursion limit raises.
MALFORMED = (TypeError, ValueError, KeyError, AttributeError, IndexError, RuntimeError, SyntaxError, ImportError)


class Refusal(Exception):
    def __init__(self, code, reason, completion=None):
        super().__init__(reason)
        self.code = code
        self.completion = completion or {INCOMPLETE: "exhausted", TOOL_FAILURE: "tool failure"}.get(code, "completed")


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def text_digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def repeated(names):
    """The names that occur more than once in `names`, sorted."""
    return sorted(name for name, count in collections.Counter(names).items() if count > 1)


def unique(pairs):
    """A JSON object's members as a dict; a name repeated in one object raises ValueError."""
    names = repeated(name for name, _ in pairs)
    if names:
        raise ValueError(f"the object repeats {names}")
    return dict(pairs)


def read_json(path):
    """The JSON object in `path`; an unreadable file, a repeated name or a root other than an object is a tool failure."""
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique)
    except (OSError, ValueError, RecursionError) as error:
        raise Refusal(TOOL_FAILURE, f"unreadable {path}: {error}") from error
    if not isinstance(value, dict):
        raise Refusal(TOOL_FAILURE, f"unreadable {path}: the JSON root is not an object")
    return value


def resolved(path):
    """`path` with its links resolved. A path that exists is resolved strictly, so a link loop or another resolution
    error is a tool failure; a missing path resolves to its normalized spelling."""
    try:
        target = Path(path).resolve()
        target.stat()
    except FileNotFoundError:
        return Path(path).resolve()
    except (OSError, RuntimeError) as error:
        raise Refusal(TOOL_FAILURE, f"{path} cannot be resolved: {error}") from error
    return target


def model_files():
    """Return the files a judgment binds: every `.qnt` model and `.py` script directly under `quint/`, and the
    manifests and every tracked file of the local packages the replay cases compile, as the Kani judge lists them."""
    kani = load("judge_kani", ROOT / "scripts/judge-kani.py")
    try:
        sources = kani.compiled_sources()
    except kani.Refusal as error:
        raise Refusal(TOOL_FAILURE, str(error)) from error
    return [*sorted([*MODELS.glob("*.qnt"), *MODELS.glob("*.py")]), *sources]


def model_digests():
    """Return the digest of each of `model_files`, keyed by its repository path."""
    return {str(path.relative_to(ROOT)): sha256(path) for path in model_files()}


def load(name, path):
    """Execute the module at `path` as `name` and return it; a module that cannot be loaded, or that raises while it
    executes, is a tool failure."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise Refusal(TOOL_FAILURE, f"{path} cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        raise Refusal(TOOL_FAILURE, f"{path} fails to load: {error!r}") from error
    return module


def runner():
    return load("quint_check", MODELS / "check.py")


def runner_cases():
    """Return the runner's cases keyed by name; a name the runner declares more than once is drift."""
    declared = list(runner().cases())
    names = repeated(case.name for case in declared)
    if names:
        raise Refusal(TOOL_FAILURE, f"the runner declares {names} more than once")
    return {case.name: case for case in declared}


def install_digest(root):
    """Return the digest and file count of the installed tree under `root`, as the Verus judge computes it."""
    return load("judge_verus", ROOT / "scripts/judge-verus.py").install_digest(root)


def apalache_tag(modules):
    """Return the Apalache version the installed Quint launches by default."""
    source = (Path(modules) / "@informalsystems/quint/dist/src/apalache.js").read_text()
    match = re.search(r"DEFAULT_APALACHE_VERSION_TAG = '([^']+)'", source)
    return match.group(1) if match else None


def trees(args):
    """Refuse a staged Node.js or `node_modules` tree other than the declared one."""
    expected = read_json(EXPECTED)
    try:
        declarations = (("node", args.node, expected["node"]["install"]),
                        ("node_modules", args.modules, expected["quint"]["install"]))
    except (KeyError, TypeError) as error:
        raise Refusal(TOOL_FAILURE, f"{EXPECTED} declares no node or quint install digest: {error!r}") from error
    for name, root, declared in declarations:
        found = install_digest(root)["sha256"]
        if found != declared:
            raise Refusal(TOOL_FAILURE, f"the staged {name} tree digests to {found}, declared {declared}")
    return CREDITED


def outcome(case):
    """The outcome a `cases` entry states for `case`: `ok` for a typecheck, replay or simulation, and for a TLC case its
    declared outcome and the property it checks, the text `control_text` of `scripts/verify-receipts.py` gives."""
    return f"{case.expected} {case.invariant or case.temporal}" if case.command == "tlc" else case.expected


def counted(case):
    """Whether `case` is a passing TLC-backend case, whose entry pins its distinct-state count."""
    return case.command == "tlc" and case.expected == "ok"


def entry(case, distinct=None):
    """The `cases` entry of `case`: its outcome, and `distinct` when it is given."""
    return {"outcome": outcome(case), **({} if distinct is None else {"distinct": distinct})}


def declared_cases(expected, *, pinned=True):
    """Return the runner's cases keyed by name after checking the declaration names exactly them, each once, and,
    unless `pinned` is false, that `check_entries` accepts the `cases` map."""
    cases = runner_cases()
    names = repeated(expected["tests"])
    if names:
        raise Refusal(TOOL_FAILURE, f"the declaration names {names} more than once")
    if sorted(cases) != sorted(expected["tests"]):
        raise Refusal(TOOL_FAILURE, f"the declaration names {sorted(set(expected['tests']) - set(cases))} the runner lacks "
                                    f"and omits {sorted(set(cases) - set(expected['tests']))}")
    blocked_cases(expected)
    if pinned:
        check_entries(expected.get("cases"), cases)
    return cases


def check_entries(declared, cases):
    """Check that the `cases` map `declared` restates the runner's `cases`: its names, then in the runner's case order
    each entry's outcome, the presence of its count, its fields, an outcome and at most a count, and the count, a
    positive integer. The first breach is drift and names its case."""
    if not isinstance(declared, dict):
        raise Refusal(TOOL_FAILURE, "the registry declares no cases map")
    if sorted(declared) != sorted(cases):
        raise Refusal(TOOL_FAILURE, f"the registry's cases omit {sorted(set(cases) - set(declared))} and add "
                                    f"{sorted(set(declared) - set(cases))}")
    for name, case in cases.items():
        pin = declared[name]
        if not isinstance(pin, dict):
            raise Refusal(TOOL_FAILURE, f"{name}: the registry entry {pin!r} is not a mapping")
        if pin.get("outcome") != outcome(case):
            raise Refusal(TOOL_FAILURE, f"{name}: the registry declares outcome {pin.get('outcome')!r}, the runner {outcome(case)!r}")
        if ("distinct" in pin) != counted(case):
            raise Refusal(TOOL_FAILURE, f"{name}: the registry pins " + ("a count on a case other than a passing TLC check"
                                        if "distinct" in pin else "no count on a passing TLC check"))
        if set(pin) - {"outcome", "distinct"}:
            raise Refusal(TOOL_FAILURE, f"{name}: the registry entry {pin} holds fields other than its outcome and count")
        if "distinct" in pin and (type(pin["distinct"]) is not int or pin["distinct"] <= 0):
            raise Refusal(TOOL_FAILURE, f"{name}: the registry count {pin['distinct']!r} is not a positive integer")


def shard_cases(cases, index):
    """Partition the entire declaration by fixed case IDs, independent of declaration order."""
    selected = {name: case for name, case in sorted(cases.items())
                if hashlib.sha256(name.encode()).digest()[-1] % len(SHARDS) == index}
    if not selected:
        raise Refusal(TOOL_FAILURE, f"Quint shard {index!r} selects no cases")
    return selected


def shard_attempt():
    """Read the numeric run identity of this assembly, not the runner's recorded identity."""
    ci = {key: os.environ.get(key) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")}
    if not all(re.fullmatch(r"[1-9][0-9]*", value or "") for value in ci.values()):
        raise Refusal(TOOL_FAILURE, "Quint shards require a GitHub run and attempt")
    return ci


def producer_path(value):
    """Read a normalized absolute producer path for argv comparison, without opening that path."""
    if not isinstance(value, str) or any(ch in value for ch in "\r\n\0"):
        raise Refusal(TOOL_FAILURE, f"Quint producer path is invalid: {value!r}")
    path = Path(value)
    if path.root != "/" or str(path) != value or ".." in path.parts:
        raise Refusal(TOOL_FAILURE, f"Quint producer path is not normalized: {value!r}")
    return path


def blocked_cases(expected):
    """External gates withhold case credit after the declared outcome is checked."""
    blocked = expected.get("blocked", {})
    if not isinstance(blocked, dict) or any(name not in expected["tests"] or not isinstance(gate, str) or not gate for name, gate in blocked.items()):
        raise Refusal(TOOL_FAILURE, "the blocked mapping names an undeclared case or empty gate")
    return blocked


def output(argv):
    completed = subprocess.run(argv, capture_output=True, text=True, check=False)
    return ((completed.stdout or "") + (completed.stderr or "")).strip()


def identity(args):
    modules = Path(args.quint).absolute().parents[1]
    record = {
        "java": {"path": args.java, "version": (output([args.java, "-version"]).splitlines() or [""])[0],
                 "install": install_digest(Path(args.java).resolve().parents[1])},
        "node": {"path": args.node, "version": output([args.node, "--version"]),
                 "install": install_digest(Path(args.node).resolve().parents[1])},
        "apalache": {"path": str(Path(args.apalache).resolve()), "install": install_digest(Path(args.apalache).resolve())},
        "quint": {"path": args.quint, "install": install_digest(modules), "apalache": apalache_tag(modules),
                  "version": output([args.quint, "--version"])},
        "models": model_digests(),
    }
    evidence = Path(args.evidence)
    evidence.mkdir(parents=True, exist_ok=True)
    if args.shard is not None:
        record["shard"] = {"index": args.shard, "ci": shard_attempt(),
                           "output": str((evidence / "quint").resolve()),
                           "executable": str(Path(args.quint).resolve())}
    (evidence / "identity.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    (evidence / "pins.txt").write_text("\n".join([
        f"- {record['java']['version']} at {args.java}; install sha256 {record['java']['install']['sha256']}",
        f"- node {record['node']['version']} at {args.node}; install sha256 {record['node']['install']['sha256']}",
        f"- apalache at {record['apalache']['path']}; install sha256 {record['apalache']['install']['sha256']}",
        f"- quint {record['quint']['version']}; node_modules sha256 {record['quint']['install']['sha256']}",
        *(f"- model or runner {name} sha256 {digest}" for name, digest in record["models"].items()
          if name.startswith("quint/")),
    ]) + "\n")
    return CREDITED


def check_identity(expected, record):
    if f'"{expected["java"]["version"]}"' not in record.get("java", {}).get("version", ""):
        raise Refusal(TOOL_FAILURE, f"java reports {record.get('java', {}).get('version')!r}, declared {expected['java']['version']}")
    if (record["java"].get("install") or {}).get("sha256") != expected["java"]["install"]:
        raise Refusal(TOOL_FAILURE, f"the JDK install tree differs from the declared sha256 {expected['java']['install']}")
    if record.get("node", {}).get("version") != expected["node"]["version"]:
        raise Refusal(TOOL_FAILURE, f"node reports {record.get('node', {}).get('version')!r}, declared {expected['node']['version']}")
    if (record["node"].get("install") or {}).get("sha256") != expected["node"]["install"]:
        raise Refusal(TOOL_FAILURE, f"the Node.js install tree differs from the declared sha256 {expected['node']['install']}")
    if (record["apalache"].get("install") or {}).get("sha256") != expected["apalache"]["install"]:
        raise Refusal(TOOL_FAILURE, f"the Apalache install tree differs from the declared sha256 {expected['apalache']['install']}")
    quint = record.get("quint", {})
    if quint.get("version") != expected["quint"]["version"] or (quint.get("install") or {}).get("sha256") != expected["quint"]["install"]:
        raise Refusal(TOOL_FAILURE, f"quint {quint.get('version')!r} or its node_modules tree differs from the declared "
                                    f"{expected['quint']['version']} install")
    if quint.get("apalache") != expected["apalache"]["version"]:
        raise Refusal(TOOL_FAILURE, f"quint launches Apalache {quint.get('apalache')!r}, declared {expected['apalache']['version']}")
    if record.get("models") != model_digests():
        raise Refusal(TOOL_FAILURE, "the model, runner or replay source changed since the identity was taken")


def finite(value):
    """Whether `value` is an integer or a float from zero through the largest finite float.

    `json.dumps` writes a float outside the finite range as `Infinity` or `NaN`, tokens outside RFC 8259. The judge
    puts a case's recorded time and a simulation's average trace length in the receipt only when this accepts them.
    The comparison reads an integer of any length exactly; a conversion to a float raises `OverflowError` for one
    past that range.
    """
    return type(value) in (int, float) and 0 <= value <= sys.float_info.max


def check_result(check, case, result, directory, quint, pin=None, *, producer_directory=None, evidence_digest=None):
    """Return the bounds a passing result records, or raise. `pin`, when given, is the case's `cases` entry, whose
    count a passing TLC case's retained log must report."""
    name = case.name
    port = result.get("port")
    if not (type(port) is int and 0 < port < 65536 if case.command == "tlc" else port is None):
        raise Refusal(MISMATCH, f"{name} names port {port!r}; a TLC case requires its own integer port; other cases require none")
    if result.get("expected") != case.expected or result.get("command") != check.command(
            case, quint, producer_directory or directory, port)[1:]:
        raise Refusal(MISMATCH, f"{name} ran {result.get('command')} for {result.get('expected')!r}, declared {case.expected!r}")
    passing = case.expected == "ok"
    if type(result.get("returncode")) is not int:
        raise Refusal(MISMATCH, f"{name} records exit status {result.get('returncode')!r}, not an integer")
    if (result.get("returncode") == 0) != passing:
        raise Refusal(MISMATCH, f"{name} exited {result.get('returncode')} for a declared {case.expected!r}")
    try:
        texts = check.inputs(case, MODELS)
    except ValueError as error:
        raise Refusal(TOOL_FAILURE, f"{name}: {error}") from error
    if result.get("inputs") != {filename: text_digest(text) for filename, text in texts.items()}:
        raise Refusal(TOOL_FAILURE, f"{name} checked a model or an instance other than the runner's")
    if evidence_digest is not None and (directory.is_symlink()
            or any((directory / name).is_symlink() for name in (*texts, "quint.log"))):
        raise Refusal(TOOL_FAILURE, f"{name}: a case artifact contains a symbolic link")
    for filename, text in texts.items():
        try:
            retained = (directory / filename).read_bytes()
        except OSError as error:
            raise Refusal(TOOL_FAILURE, f"{name} retains no {filename}: {error}") from error
        if retained != text.encode():
            raise Refusal(TOOL_FAILURE, f"{name}: executed input differs from the declared instance")
    try:
        log = (directory / "quint.log").read_text()
        facts = check.judge(case, log, result["returncode"])
        if evidence_digest is not None:
            evidence_digest.update(text_digest(log).encode())
    except (OSError, RuntimeError) as error:
        raise Refusal(MISMATCH, f"{name}: raw evidence refused: {error}") from error
    if any(result.get(key) != value for key, value in facts.items()):
        raise Refusal(MISMATCH, f"{name}: summary differs from raw evidence")
    seconds = result.get("seconds")
    if not finite(seconds):
        raise Refusal(TOOL_FAILURE, f"malformed evidence: {name} records {seconds!r} seconds, not a finite count at or above zero")
    bounds = {"command": case.command, "seconds": seconds, "constants": check.constants(case)}
    if check.replay_traces(case) is not None:
        bounds.update(traces=result["traces"], actions=result["actions"])
    elif case.command == "replay":
        per_action = result.get("per_action") or {}
        if result.get("traces") != check.REPLAY_TRACES or not result.get("longest") \
                or (result.get("actions") or 0) <= check.REPLAY_TRACES \
                or any(per_action.get(action, 0) == 0 for action in check.REPLAY_ACTIONS):
            raise Refusal(MISMATCH, f"{name} replayed {result.get('traces')} traces of {result.get('actions')} actions "
                                    f"reaching {per_action}, declared {check.REPLAY_TRACES} traces reaching every action")
        bounds.update(traces=result["traces"], actions=result["actions"], longest=result["longest"], per_action=per_action)
    elif case.command == "simulate":
        witnessed = result.get("witnessed") or {}
        if result.get("traces") != int(check.SAMPLES) or sorted(witnessed) != sorted(check.WITNESSES):
            raise Refusal(MISMATCH, f"{name} records {result.get('traces')} traces or other witnesses")
        # `float` converts out-of-range decimal strings such as `1e999` to infinity.
        average = result["lengths"]["average"]
        if not finite(average):
            raise Refusal(TOOL_FAILURE, f"malformed evidence: {name} records an average trace length of {average!r}, "
                                        "not a finite number at or above zero")
        bounds.update(traces=result["traces"], lengths=result.get("lengths"), witnessed=witnessed)
    elif case.command == "tlc":
        distinct = facts["states"][1]
        if pin is not None and passing and distinct != pin["distinct"]:
            raise Refusal(MISMATCH, f"{name}'s quint.log records {distinct} distinct states, the registry pins {pin['distinct']}")
        bounds.update(distinct=distinct, depth=result.get("depth"))
        if not passing:
            if not result.get("trace"):
                raise Refusal(MISMATCH, f"{name} records no counterexample")
            bounds["trace"] = result["trace"]
        if case.lasso != bool(result.get("lasso")):
            raise Refusal(MISMATCH, f"{name} {'lacks' if case.lasso else 'adds'} the broken variant's loop")
        if case.lasso:
            bounds["lasso"] = result["lasso"]
    return bounds


def judge(evidence, expected, record, revision=None, *, pinned=True):
    """Return each case's bounds for evidence that credits, or raise. `pinned` false leaves out the comparisons with the
    `cases` map, as `pins` reads a run."""
    cases = declared_cases(expected, pinned=pinned)
    outcomes = judge_cases(evidence, expected, record, revision, runner(), cases, pinned=pinned)
    return mark_blocked(outcomes, expected)


def judge_cases(evidence, expected, record, revision, check, cases, *, pinned, shard=None, evidence_digest=None):
    """Judge one exact case set; read imported artifacts only under the evidence directory."""
    check_identity(expected, record)
    try:
        argv = (evidence / "quint.argv").read_text().splitlines()
        exit_code = int((evidence / "quint.exit").read_text().strip())
    except (OSError, ValueError) as error:
        raise Refusal(TOOL_FAILURE, f"the lane recorded no runner command or exit: {error}") from error
    directory = evidence / "quint"
    if shard is not None and (directory.is_symlink() or not directory.is_dir()):
        raise Refusal(TOOL_FAILURE, f"Quint shard {shard} has no raw case directory")
    directory = resolved(directory)
    output = directory
    options = []
    if shard is None:
        quint = str(resolved(record["quint"]["path"]))
        ran = [*argv[:-1], str(resolved(argv[-1]))] if len(argv) == 8 else argv
    else:
        marker = record.get("shard")
        if not isinstance(marker, dict) or type(marker.get("index")) is not int or marker["index"] != shard \
                or marker.get("ci") != shard_attempt():
            raise Refusal(TOOL_FAILURE, f"Quint shard {shard} records another shard, run or attempt")
        output = producer_path(marker.get("output"))
        executable = producer_path(marker.get("executable"))
        launcher = producer_path(record["quint"]["path"])
        if output.name != "quint" or len(launcher.parents) < 2 or not executable.is_relative_to(launcher.parents[1]):
            raise Refusal(TOOL_FAILURE, f"Quint shard {shard} has a foreign output or Quint executable")
        quint = str(executable)
        options = [arg for name in cases for arg in ("--case", name)]
        ran = argv
    want = ["quint/check.py", "--quint", record["quint"]["path"], "--workers", str(expected["workers"]),
            "--output", str(output), *options]
    if not argv or not Path(argv[0]).name.startswith("python3") or ran[1:] != want:
        raise Refusal(TOOL_FAILURE, "the lane's runner command differs from its declared Quint argv")
    if exit_code in INTERRUPTED:
        raise Refusal(INCOMPLETE, f"the run was interrupted (exit {exit_code})", "timeout")
    if exit_code != 0:
        failure = read_json(evidence / "results.json").get("failure") if (evidence / "results.json").is_file() else None
        if not isinstance(failure, dict) or not failure.get("case"):
            raise Refusal(TOOL_FAILURE, f"the runner exited {exit_code} before recording a case outcome")
        raise Refusal(MISMATCH, f"the runner exited {exit_code}: it refused {failure['case']} by its outcome: "
                                f"{failure.get('reason')}")
    results = read_json(evidence / "results.json")
    if results.get("revision") != revision:
        raise Refusal(TOOL_FAILURE, f"runner revision {results.get('revision')!r} differs from receipt revision {revision!r}")
    if shard is not None and results.get("ci") != shard_attempt():
        raise Refusal(TOOL_FAILURE, f"Quint shard {shard}'s results record another run or attempt")
    if results.get("failure") is not None:
        raise Refusal(MISMATCH, f"the runner's record names a failure: {results.get('failure')}")
    if results.get("complete") is not True:
        raise Refusal(MISMATCH, "the runner's record is incomplete")
    if results.get("dirty") != []:
        raise Refusal(MISMATCH, f"the runner ran on a worktree with modified tracked files: {results.get('dirty')}")
    if f'"{expected["java"]["version"]}"' not in results.get("runtime", ""):
        raise Refusal(TOOL_FAILURE, f"the runner ran under {results.get('runtime')!r}, declared java {expected['java']['version']}")
    if results.get("quint") != expected["quint"]["version"]:
        raise Refusal(TOOL_FAILURE, f"the runner ran quint {results.get('quint')!r}, declared {expected['quint']['version']}")
    by_name = {str(result.get("case")): result for result in results.get("results", [])}
    if sorted(by_name) != sorted(cases) or len(by_name) != len(results.get("results", [])):
        missing, extra = sorted(set(cases) - set(by_name)), sorted(set(by_name) - set(cases))
        raise Refusal(TOOL_FAILURE, f"the results miss {missing}, add {extra} or repeat a case")
    return {name: check_result(check, case, by_name[name], directory / name, quint,
                               expected["cases"][name] if pinned else None, producer_directory=output / name,
                               evidence_digest=evidence_digest)
            for name, case in sorted(cases.items())}


def mark_blocked(outcomes, expected):
    for name, gate in expected.get("blocked", {}).items():
        outcomes[name].update(blocked=gate, credited=False)
    return outcomes


def judge_shards(evidence, expected, revision, shards, *, pinned):
    """Rejudge every artifact for the same attempt before forming a full Quint receipt. Each shard that passes adds
    its manifest entry to `shards`, in index order, so a refusal leaves the entries of the shards judged before it."""
    ci = shard_attempt()
    directory = evidence / "shards"
    names = {index: f"quint-shard-{index}-{ci['GITHUB_RUN_ID']}-{ci['GITHUB_RUN_ATTEMPT']}" for index in SHARDS}
    if directory.is_symlink() or {path.name for path in directory.iterdir()} != set(names.values()):
        raise Refusal(INCOMPLETE, f"Quint needs precisely this attempt's shard artifacts: {list(names.values())}")
    check, cases = runner(), declared_cases(expected, pinned=pinned)
    outcomes = {}
    for index, name in names.items():
        raw = directory / name
        if raw.is_symlink() or not raw.is_dir():
            raise Refusal(TOOL_FAILURE, f"Quint shard {index} is not an artifact directory")
        if any((raw / name).is_symlink() for name in SHARD_INPUTS):
            raise Refusal(TOOL_FAILURE, f"Quint shard {index} contains a symbolic link")
        record = read_json(raw / "identity.json")
        digest = hashlib.sha256()
        judged = judge_cases(raw, expected, record, revision, check, shard_cases(cases, index),
                             pinned=pinned, shard=index, evidence_digest=digest)
        if outcomes.keys() & judged.keys():
            raise Refusal(TOOL_FAILURE, "Quint shard results overlap")
        outcomes.update(judged)
        shards[name] = {"inputs": {key: sha256(raw / key) for key in SHARD_INPUTS},
                        "case_logs_sha256": digest.hexdigest(), "cases": len(judged)}
    if outcomes.keys() != cases.keys():
        raise Refusal(INCOMPLETE, "Quint shard cases do not cover the declaration")
    return mark_blocked(outcomes, expected)


def shard_manifest(shards):
    return json.dumps(shards, indent=2, sort_keys=True) + "\n"


def shard_pins(expected, shards):
    """One provenance line per manifest entry. `judge_shards` adds entries in index order, each after its shard's
    identity matched the declared tools."""
    return [f"- Quint shard {index}: " + "; ".join(
        f"{name} {expected[name]['version']} tree sha256 {expected[name]['install']}"
        for name in ("java", "node", "apalache", "quint")) for index, _ in zip(SHARDS, shards)]


def pins(evidence, revision):
    """The `cases` entries of the run's cases, one line each in name order and joined by commas, for a run that
    `derive` credits when it leaves out the comparisons with the `cases` map, or raise the refusal. Each count is the one
    `judge` reads from the case's retained `quint.log`."""
    report, _ = derive(evidence, revision, pinned=False)
    if report["code"] != CREDITED:
        raise Refusal(report["code"], report["reason"])
    cases = runner_cases()
    lines = []
    for name, bounds in sorted(report["cases"].items()):
        distinct = bounds["distinct"] if counted(cases[name]) else None
        lines.append(f"    {json.dumps(name)}: {json.dumps(entry(cases[name], distinct))}")
    return ",\n".join(lines)


def derive(evidence, revision, *, pinned=True):
    """Judge the evidence directory and return the report and the receipt it supports, writing neither. `pinned` false
    leaves out the comparisons with the `cases` map."""
    code, reason, results, expected, completion = CREDITED, None, {}, {}, "completed"
    shards = None
    try:
        expected = read_json(EXPECTED)
        if (evidence / "shards").is_dir():
            shards = {}
            results = judge_shards(evidence, expected, revision, shards, pinned=pinned)
        else:
            results = judge(evidence, expected, read_json(evidence / "identity.json"), revision, pinned=pinned)
    except Refusal as refusal:
        code, reason, completion = refusal.code, str(refusal), refusal.completion
    except MALFORMED as error:
        code, reason, completion = TOOL_FAILURE, f"malformed evidence: {error!r}", "tool failure"
    except OSError as error:
        code, reason, completion = TOOL_FAILURE, f"unreadable input: {error}", "tool failure"
    inputs, provenance, constants = {}, [], None
    try:
        names = ["identity.json", "pins.txt", "report.json", "quint.argv", "quint.exit", "quint.txt", "results.json"]
        inputs = {name: sha256(evidence / name) for name in names if (evidence / name).is_file()}
        for path in (ROOT / "scripts/test-inventory.json", ROOT / "scripts/test-registry.json",
                     ROOT / "verification/obligations.json", EXPECTED, *model_files()):
            if path.is_file():
                inputs[str(path.relative_to(ROOT))] = sha256(path)
        pins_path = evidence / "pins.txt"
        if shards is not None:
            provenance = shard_pins(expected, shards)
            inputs["pins.txt"] = text_digest("\n".join(provenance) + "\n")
            inputs["quint-shards.json"] = text_digest(shard_manifest(shards))
        else:
            provenance = pins_path.read_text(encoding="utf-8").strip().splitlines() if pins_path.is_file() else []
        constants = runner().CONSTANTS
    except Refusal as refusal:
        code, reason, completion = refusal.code, str(refusal), refusal.completion
    except (OSError, ValueError, SyntaxError, AttributeError) as error:
        code, reason, completion = TOOL_FAILURE, f"unreadable receipt input: {error!r}", "tool failure"
    credited_cases = {name: bounds for name, bounds in results.items() if "blocked" not in bounds}
    report = {"code": code, "verdict": VERDICTS[code], "credited": code == CREDITED, "reason": reason, "cases": results}
    if shards is not None:
        report["shards"] = shards
    receipt = {
        "job": "quint", "module": None, "lane": "quint", "revision": revision, "inputs": inputs,
        "tool": {"name": "quint", "provenance": provenance},
        "assumptions": ["a finite instance at the constants each case states, with session sequences and epochs relabelled by rank; "
                        "no refinement mapping to the implementation",
                        "progress holds under weak fairness of stabilization and of each client's retry and bootstrap "
                        "deliveries, after which no frame is lost, duplicated or delayed past a retry (session family)",
                        "detect and route use each case's finite BOUND; detector progress runs under fixedStep, which "
                        "schedules only observed windows, both probes and nomination, with ready evidence, weak fairness of each "
                        "of those actions, and caller-validated placement",
                        "AQ-15 withholds the credit of detector progress until the owner clears the gate for the detector-only case",
                        "preserve cases assume END-self and END-foreign unless a case sets END = false, and NEW-EXCLUSION, "
                        "DURABLE and EXPIRY-CLOCK; the model establishes none of these provider, storage and clock premises",
                        "preserve rollback cases assume RESTORE: detection of the restore, no continued writes through the old "
                        "store instance, a tenure floor at the highest issued tenure, the latest record and complete coverage",
                        "preserve cases adopt the predecessor's volume at recovery and fence it with a Preempt-and-Abort naming "
                        "every lineage registrant; both rest on the U4 revision of the tenure model's flip and issuance rule "
                        "(NoPreemptOfForeignKey), and the fence reads the lineage registrant set from tenure arithmetic, a "
                        "premise the model does not establish",
                        "suffix cases assume END for the successor's fence, DURABLE for a completed block write and "
                        "NEW-EXCLUSION; the model's blocks hold one record each, its atomic publish captures in one step, "
                        "its pass splits the snapshot from the publication, and landings are unordered, so block packing, sequence continuity and the tail-or-damage classification of a hole "
                        "are checked by the Rust tests alone",
                        "join cases check composed projections: two accepted models imported as instances, whose "
                        "every joint step is one model's action with the other's variables unchanged or one action of "
                        "each, from a declared prefix root up to the case's BOUND; a passing join case is a finite "
                        "check of that projection under its stated reductions and no inductive or refinement proof",
                        "saturation cases check each part's invariant from every typed state of that part within LSNs 0 "
                        "to 5, a region of two blocks, three slots, a chain cap of two and a queue of one block, with the "
                        "other part at its initial value; the takeover assumes END, and no refinement maps the counts to "
                        "the appender, the possibly-named set or the store record",
                        "keyops cases model one key of one live storage with one-unit objects, one write per fill and no reader "
                        "pinned across a certification; joins, fingerprint collisions, sequences, the retired allowance, budgets "
                        "and gate contention are checked by the Rust tests alone, and the replay shows agreement with Storage "
                        "and the history oracle on the eight committed traces only",
                        "binder cases model two binders, one NVMe controller and one ENI, with a kill as a SIGKILL between "
                        "two steps while the kernel stays up; power loss, a third owner and the kernel's handling of each "
                        "write are outside the model, and the replay shows agreement with two binder processes over the "
                        "bind fixture's fake kernel on the two committed traces only"],
        "bounds": {"workers": expected.get("workers"), "constants": constants, "cases": results},
        "completion": completion, "violation": None, "detail": reason,
        "selection": {"credited": code == CREDITED, "reason": reason},
        "executions": len(credited_cases) if code == CREDITED else 0,
        "executed": sorted(credited_cases) if code == CREDITED else [], "failed": [],
        "blocked": expected.get("blocked", {}),
        "replay": "bash scripts/rust-lane.sh quint",
        "ci": {key: os.environ.get(key) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")},
    }
    return report, receipt


def print_pins(evidence, revision):
    """Print the `pins` entries of the run in `evidence` and return the exit code: 0 once the entries are printed, and
    for a refused run the refusal's code, with the refusal on stderr and nothing on stdout. That is the code `judge`
    gives the same evidence when `check_entries` accepts the `cases` map and each pinned count equals its log."""
    try:
        entries = pins(evidence, revision)
    except Refusal as refusal:
        print(f"judge-quint: {refusal}", file=sys.stderr)
        return refusal.code
    print(entries)
    return CREDITED


def main(argv=None):
    parser = argparse.ArgumentParser(description="Pin the Quint installation and judge the Quint models' cases.")
    parser.add_argument("command", choices=["trees", "identity", "judge", "pins", "shard"])
    parser.add_argument("--shard", type=int, choices=SHARDS)
    for flag in ("--java", "--node", "--apalache", "--quint", "--modules", "--evidence", "--revision"):
        parser.add_argument(flag)
    args = parser.parse_args(argv)
    needs = {"trees": ("node", "modules"), "identity": ("java", "node", "apalache", "quint", "evidence"), "judge": ("evidence",),
             "pins": ("evidence",), "shard": ()}
    if args.command == "shard" and args.shard is None:
        parser.error("shard needs --shard")
    if args.shard is not None and args.command not in ("shard", "identity"):
        parser.error("--shard selects a shard or records its producer identity")
    if not all(getattr(args, flag) for flag in needs[args.command]):
        parser.error(f"{args.command} needs its arguments; see the usage")
    try:
        if args.command == "shard":
            print("\n".join(shard_cases(declared_cases(read_json(EXPECTED)), args.shard)))
            return CREDITED
        if args.command == "trees":
            return trees(args)
        if args.command == "identity":
            return identity(args)
        evidence = Path(args.evidence)
        revision = args.revision or subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True,
                                                   text=True, check=False).stdout.strip() or None
        if args.command == "pins":
            return print_pins(evidence, revision)
        report, receipt = derive(evidence, revision)
        if "shards" in report:
            (evidence / "quint-shards.json").write_text(shard_manifest(report["shards"]))
            (evidence / "pins.txt").write_text("\n".join(receipt["tool"]["provenance"]) + "\n")
        (evidence / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        receipt["inputs"]["report.json"] = sha256(evidence / "report.json")
        (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    except (Refusal, OSError, KeyError) as error:
        print(f"judge-quint: {error}", file=sys.stderr)
        return TOOL_FAILURE
    print(json.dumps(report, sort_keys=True))
    if report["reason"]:
        print(f"judge-quint: {report['reason']}", file=sys.stderr)
    return report["code"]


if __name__ == "__main__":
    sys.exit(main())
