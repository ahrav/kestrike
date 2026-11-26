#!/usr/bin/env python3
"""Pin the TLC installation and credit a profile of TLA+ cases only when the runner reached every declared outcome.

Usage:
  judge-tlc.py identity --java PATH --jar PATH --evidence DIR
  judge-tlc.py judge --profile pr|scheduled --evidence DIR [--revision SHA]
  judge-tlc.py pins --evidence DIR

`verification/tlc/expected.json` declares the JDK and `tla2tools.jar`
archives with their sha256, the JDK version and the digest of its installed
tree, the TLC version the jar's manifest names, the worker count, and each
tier's case names, which must equal the runner's cases of that tier in
`tla/check.py`. It also restates every runner case in `cases`: the declared
outcome, the invariants and properties of the generated configuration and,
for a case that completes, its distinct-state count; and it lists each
model's `Safety` conjuncts (`models`), the conjuncts no mutation case kills
(`uncontrolled`) and the mutation cases `TypeOK` kills (`type_kills`).
`static_contract` refuses as drift, by case or conjunct name, a registry that
differs from the runner's cases and the committed models and configurations,
and a kill case, a mutation case whose outcome is an invariant or
action-property violation, without a passing baseline, whose text
`kill_basis` in `tla/check.py` refuses to read, or whose mutation lies in a
definition its killing property references or in one no action reaches; it
runs before every judgment. A profile judges
the cases of the tiers `PROFILES` in `tla/check.py` names: `pr` its own
tier, and `scheduled` every `pr` case as well as its own. The runner owns
each case's model, configuration, outcome, required coverage and mutation,
and refuses any other outcome. `identity` records `java -version`, the
digest of the installed JDK tree, the jar's digest and manifest version, and
the digests of every file under `tla/`.

`judge` credits the profile only when the identity matches the declaration,
including the JDK tree, and the committed models, `tlc.argv` is the runner with the identified jar,
the declared workers, the profile and the evidence's `tlc` directory,
`tlc.exit` is 0, and `results.json`, the lane's copy of the runner's
results, ran under the declared JDK and names exactly the profile's cases,
each with the runner's declared outcome, tier and coverage, the exit status
TLC reports for that outcome, `-lncheck final` exactly for a liveness case,
explored states, model digests equal to the committed files with the case's
one mutation applied, and the configuration the runner generates for the
case from the committed files. The models and the configuration the runner
left under the evidence's `tlc/<case>` directory must be present with those
same digests. Each result also records the digests of its
case's `sany.log` and `tlc.log`, which must be present under the evidence's
`tlc/<case>` directory with those digests; from them the judge rederives
SANY's clean parse of the case's module, the declared outcome as the log's one terminal line (TLC's completion
report or an `Error: ` line other than a trace heading), the
coverage of a passing case and the final state counts, which must equal the
result's. A result without the digests, a missing or substituted log, a
missing or substituted retained model or configuration and a
log that disagrees with its result are refused by name. The distinct-state
count of a completing case's log must equal the registry's pin, and a kill
case's counterexample must take a step of an action that reaches its
mutation; either difference is an outcome mismatch. The receipt records each
kill case's passing baseline and that action set. A runner exit of 124, 130 or 143 is incomplete and
any other nonzero exit is a refused case (its outcome, coverage, parse,
mutation anchor or mutated step), judged an outcome mismatch. It
writes `report.json` and `receipt.json` in the form `verify-receipts.py
credit --receipt` imports, with the profile as the module. Exit 0 credits,
1 is an outcome mismatch, 2 is a tool failure or drift, 3 is incomplete. A
report or receipt the judge cannot write exits 2.

A credited report also holds `unreached`: for each of `tla/Recovery.tla`,
`tla/Lifecycle.tla` and `tla/Identity.tla`, the listed spans of model text
that the rule `tla/README.md` states under "Unreached spans" classifies as
unreached over the profile's completing cases without a mutation, as
`{section, at, text}` entries in a fixed order, or a refusal string when they
cannot be read. The string is `<case>: <reason>` when a case's log fails its
digest check, when the runner's `listed` refuses it, when its last report does
not show an action of the case's `coverage` as a section that ran, or when it
lists a section span outside its module's committed text; the case is the
first by name whose log causes it. The string is
`<case>: the span report failed: <error>` when the rule or anything else
fails, and there the case is the model's first case by name, a label rather
than the cause. The string is `<model file>: <reason>`, with the bare file
name such as `Recovery.tla`, when the profile has no such case, when a failure
comes before the model's cases are selected, or when the setup shared by the
models fails.
`unreached_read` counts the cases and the span lines of sections read for
the models whose value is a list.
`derive` builds both, so the credit step's rederived report equals the
retained one. They decide no verdict, code or credit, and a report whose code
is not 0 holds neither.

`pins` prints the registry entry of each case of the run, with the count of
each completing case derived from its `tlc.log`, under the profile `tlc.argv`
names. It applies
every check of `judge` except the comparisons with the `cases` map, and for
a run those checks refuse it prints nothing and exits with the refusal's code.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = ROOT / "verification/tlc/expected.json"
MODELS = ROOT / "tla"
CREDITED, MISMATCH, TOOL_FAILURE, INCOMPLETE = 0, 1, 2, 3
# The errors malformed evidence raises under `judge` and `pins`, each a tool failure.
MALFORMED = (TypeError, ValueError, LookupError, AttributeError, ArithmeticError)
VERDICTS = {CREDITED: "credited", MISMATCH: "outcome mismatch", TOOL_FAILURE: "tool failure", INCOMPLETE: "incomplete"}
INTERRUPTED = (124, 130, 143)


class Refusal(Exception):
    def __init__(self, code, reason, completion=None):
        super().__init__(reason)
        self.code = code
        self.completion = completion or {INCOMPLETE: "exhausted", TOOL_FAILURE: "tool failure"}.get(code, "completed")


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def unique(pairs):
    """A JSON object's members as a dict; a name repeated in one object raises ValueError naming each repeated name."""
    found, repeated = {}, set()
    for name, value in pairs:
        if name in found:
            repeated.add(name)
        found[name] = value
    if repeated:
        raise ValueError(f"the object repeats {sorted(repeated)}")
    return found


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique)
    except (OSError, ValueError, RecursionError) as error:
        raise Refusal(TOOL_FAILURE, f"unreadable {path}: {error}") from error


def model_files():
    return sorted([*MODELS.glob("*.tla"), *MODELS.glob("*.cfg"), MODELS / "check.py"])


def model_digests():
    """The digest of each model, configuration and the runner under `tla/`; an unreadable one is a tool failure."""
    try:
        return {path.name: sha256(path) for path in model_files()}
    except OSError as error:
        raise Refusal(TOOL_FAILURE, f"a committed model is unreadable: {error}") from error


def registry():
    """The registry `EXPECTED` holds; a file that is unreadable or holds no JSON object is a tool failure."""
    declared = read_json(EXPECTED)
    if not isinstance(declared, dict):
        raise drift(f"{EXPECTED} holds {type(declared).__name__}, not a JSON object")
    return declared


def load(name, path):
    """Execute the module at `path` as `name` and return it; a module that cannot be loaded, or that raises while it
    executes, is a tool failure."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise Refusal(TOOL_FAILURE, f"{path.relative_to(ROOT)} cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        raise Refusal(TOOL_FAILURE, f"{path} fails to load: {error!r}") from error
    return module


def runner():
    return load("tlc_check", MODELS / "check.py")


def install_digest(root):
    """Return the digest and file count of the installed tree under `root`, as the Verus judge computes it."""
    return load("judge_verus", ROOT / "scripts/judge-verus.py").install_digest(root)


def profile_cases(expected, profile, cases=None, source=MODELS):
    """Return the runner's cases a run of `profile` judges, keyed by name, after `static_contract` accepts the
    declaration, the case list (the runner's unless `cases` is given) and the source directory, and the declaration
    names the profile's cases."""
    return contract(runner(), expected, profile, cases, source)[0]


def contract(check, expected, profile, cases, source, *, pinned=True):
    """The cases of `profile`, keyed by name, and the kill basis `static_contract` derives, keyed by kill case name,
    after checking that the declaration names the profile's cases. `check` is the loaded runner."""
    cases = list(check.cases() if cases is None else cases)
    basis = static_contract(check, expected, cases, source, pinned=pinned)
    tiers = check.PROFILES[profile]
    selected = {case.name: case for case in cases if case.tier in tiers}
    profiles = section(expected, "profiles", dict)
    if not all(isinstance(profiles.get(tier, []), list) for tier in tiers):
        raise drift(f"the registry's profiles for {profile} are no JSON lists")
    declared = {name for tier in tiers for name in profiles.get(tier, [])}
    if set(selected) != declared:
        raise Refusal(TOOL_FAILURE, f"profile {profile} declares {sorted(declared - set(selected))} the runner lacks and omits {sorted(set(selected) - declared)}")
    return selected, basis


def drift(reason):
    return Refusal(TOOL_FAILURE, reason)


def section(expected, name, kind):
    """The registry's `name` section; a section that is absent or not a `kind` is drift naming it."""
    value = expected.get(name)
    if not isinstance(value, kind):
        raise drift(f"the registry's {name} is {value!r}, not a JSON {'object' if kind is dict else 'list'}")
    return value


def entry(check, case, source, distinct=None):
    """The registry entry the runner's `case` declares: its outcome, the invariants and the properties, when it has
    any, of the configuration the runner generates from `source`, and `distinct` when it is given."""
    names = check.checked(check.configuration(case, source))
    return {"outcome": case.expected, "invariants": names["invariants"],
            **({"properties": names["properties"]} if names["properties"] else {}),
            **({} if distinct is None else {"distinct": distinct})}


def static_contract(check, expected, cases, source, *, pinned=True):
    """Check the registry `expected` against the runner's `cases` and the models and configurations under `source`,
    and return each kill case's passing baseline and the actions that reach its mutation, keyed by case name.

    The checks run in this order and the first breach is drift: the runner names each case once, in a tier a profile
    runs; the `cases` map names each case once; every `.cfg` is a case's base, and every case's base and mutation
    target exist; each entry's `outcome` is the case's declared outcome, and it pins a positive `distinct` exactly
    when the case completes; its `invariants` and `properties` are the generated configuration's, in order, and it
    holds no other member; `models` lists each `Safety` conjunct of every model that defines `Safety`, and no other
    model; each kill case has a passing baseline; `kill_basis` reads each kill case, and its mutation lies outside
    the definitions its killing property references and inside a definition an action of `Next` reaches; and
    `uncontrolled` and `type_kills` are the lists the cases derive. A kill case is a mutation case whose outcome is
    an invariant or action-property violation. `pinned` false leaves out the checks of the `cases` map. A model or
    configuration that is missing, unreadable or that the runner's readers cannot read is drift.
    """
    try:
        names, repeated = set(), set()
        for case in cases:
            (repeated if case.name in names else names).add(case.name)
        if repeated:
            raise drift(f"the runner names the cases {sorted(repeated)} more than once")
        run = {tier for tiers in check.PROFILES.values() for tier in tiers}
        for case in cases:
            if case.tier not in run:
                raise drift(f"{case.name}: no profile runs the tier {case.tier!r}")
        declared = section(expected, "cases", dict) if pinned else {}
        if pinned and sorted(declared) != sorted(names):
            raise drift(f"the registry's cases omit {sorted(names - set(declared))} and add {sorted(set(declared) - names)}")
        configs, modules = {path.name for path in source.glob("*.cfg")}, {path.name for path in source.glob("*.tla")}
        unused = sorted(configs - {case.base for case in cases})
        if unused:
            raise drift(f"{unused[0]} is the base of no case")
        for case in cases:
            if case.base not in configs or (case.mutation and case.target not in modules):
                raise drift(f"{case.name}: the source holds no {case.base if case.base not in configs else case.target}")
        if pinned:
            check_entries(check, declared, cases, source)
        listed_models = section(expected, "models", dict)
        if not all(isinstance(listed, list) for listed in listed_models.values()):
            raise drift(f"the registry's models {listed_models} hold a value that is no JSON list")
        models = {}
        for path in sorted(source.glob("*.tla")):
            try:
                conjuncts = check.safety(path.read_text())
            except ValueError as error:
                raise drift(f"{path.name}: {error}") from error
            if conjuncts is not None:
                models[path.name] = conjuncts
        for name in sorted({*models, *listed_models}):
            listed, found = listed_models.get(name, []), models.get(name, [])
            order = " in another order" if sorted(listed) == sorted(found) else ""
            if listed != found:
                raise drift(f"the registry's models for {name} omit the Safety conjuncts {[c for c in found if c not in listed]} and add {[c for c in listed if c not in found]}{order}")
        if set(listed_models) != set(models):
            raise drift(f"the registry's models name {sorted(listed_models)}, the models that define Safety are {sorted(models)}")
        kills = sorted((case for case in cases if check.killing(case)), key=lambda case: case.name)
        basis = {case.name: {"baseline": baseline(check, case, cases, source, models)} for case in kills}
        for case in kills:
            found = check.kill_basis(case, source)
            if found["definition"] in found["references"]:
                raise drift(f"{case.name}: the mutation edits {found['definition']}, which its killing property {check.killing(case)} references")
            if not found["actions"]:
                raise drift(f"{case.name}: no action of Next reaches {found['definition']}, the definition the mutation edits")
            basis[case.name]["mutated"] = found["actions"]
    except (ValueError, OSError) as error:
        raise drift(str(error)) from error
    uncontrolled = section(expected, "uncontrolled", dict)
    for name, conjuncts in models.items():
        killed = {check.killing(case) for case in kills if case.target == name}
        derived = [c for c in conjuncts if c not in killed]
        if uncontrolled.get(name) != derived:
            raise drift(f"the registry's uncontrolled list for {name} is {uncontrolled.get(name)}; no mutation case kills {derived}")
    if set(uncontrolled) != set(models):
        raise drift(f"the registry's uncontrolled lists name {sorted(uncontrolled)}, the models that define Safety are {sorted(models)}")
    typed = sorted(case.name for case in cases if case.mutation and case.expected == check.violation("TypeOK"))
    if section(expected, "type_kills", list) != typed:
        raise drift(f"the registry's type_kills {expected['type_kills']} differ from the mutation cases TypeOK kills, {typed}")
    return basis


def check_entries(check, declared, cases, source):
    """The checks of `static_contract` on the entries of the `cases` map, in its order and the runner's case order:
    every outcome and count, then every entry's lists and members."""
    for case in cases:
        pin = declared[case.name]
        if not isinstance(pin, dict):
            raise drift(f"{case.name}: the registry's entry {pin!r} is no JSON object")
        if pin.get("outcome") != case.expected:
            raise drift(f"{case.name}: the registry declares outcome {pin.get('outcome')!r}, the runner {case.expected!r}")
        if ("distinct" in pin) != check.completes(case):
            raise drift(f"{case.name}: the registry pins {'a count on a violation' if 'distinct' in pin else 'no count on a case that completes'}")
        if "distinct" in pin and (type(pin["distinct"]) is not int or pin["distinct"] <= 0):
            raise drift(f"{case.name}: the registry pins the count {pin['distinct']!r}, not a positive integer")
    for case in cases:
        pin, derived = declared[case.name], entry(check, case, source)
        listed = {key: value for key, value in pin.items() if key != "distinct"}
        if (pin.get("invariants"), pin.get("properties", [])) != (derived["invariants"], derived.get("properties", [])):
            raise drift(f"{case.name}: the registry's lists {pin.get('invariants')} and {pin.get('properties', [])} differ from the generated configuration's {derived['invariants']} and {derived.get('properties', [])}")
        if listed != derived:
            raise drift(f"{case.name}: the registry's entry holds the members {sorted(listed)}, the generated configuration's {sorted(derived)}")


def baseline(check, case, cases, source, models):
    """The first case by name that is a passing baseline of kill case `case`: it completes, has no mutation, shares the
    module, base, specification, settings and symmetry, generates the same configuration apart from its invariant
    and property statements, runs in every profile that runs `case`, and checks the killing property in the kill's
    own kind: an invariant directly or as a `Safety` conjunct of the target, and an action property as a property."""
    prop = check.killing(case)

    def shape(other):
        return other.module, other.base, other.spec, other.settings, other.symmetry

    statements = check.unchecked(check.configuration(case, source))
    for other in sorted(cases, key=lambda other: other.name):
        runs_with = all(other.tier in tiers for tiers in check.PROFILES.values() if case.tier in tiers)
        if other.mutation or not check.completes(other) or not runs_with or shape(other) != shape(case):
            continue
        generated = check.configuration(other, source)
        names = check.checked(generated)
        if case.expected == check.violation(prop):
            checks = prop in names["invariants"] or ("Safety" in names["invariants"] and prop in models.get(case.target, []))
        else:
            checks = prop in names["properties"]
        if check.unchecked(generated) == statements and checks:
            return other.name
    raise drift(f"{case.name} has no passing baseline that checks {prop} at its module, base, specification, settings, symmetry, configuration and tier")


def identity(args):
    with zipfile.ZipFile(args.jar) as archive:
        version = re.search(r"(?m)^Implementation-Version: (.+?)\s*$", archive.read("META-INF/MANIFEST.MF").decode())
    java = subprocess.run([args.java, "-version"], capture_output=True, text=True, check=False)
    record = {
        "java": {"path": args.java, "version": ((java.stderr or java.stdout).splitlines() or [""])[0],
                 "install": install_digest(Path(args.java).resolve().parents[1])},
        "jar": {"path": str(Path(args.jar).resolve()), "sha256": sha256(args.jar), "version": version and version.group(1)},
        "models": model_digests(),
    }
    evidence = Path(args.evidence)
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "identity.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    (evidence / "pins.txt").write_text("\n".join([
        f"- {record['java']['version']} at {args.java}; install sha256 {record['java']['install']['sha256']}",
        f"- tla2tools.jar {record['jar']['version']}; sha256 {record['jar']['sha256']}",
        *(f"- tla/{name} sha256 {digest}" for name, digest in record["models"].items()),
    ]) + "\n", encoding="utf-8")
    return CREDITED


def judge(evidence, expected, record, profile, *, pinned=True, check=None):
    """The bounds of each case of a run of `profile` the evidence credits, or a Refusal. `check` is the loaded runner,
    loaded here when it is None, and `pinned` false leaves out the comparisons with the `cases` map."""
    if (record.get("jar", {}).get("sha256"), record["jar"].get("version")) != (expected["jar"]["sha256"], expected["jar"]["version"]):
        raise Refusal(TOOL_FAILURE, f"the jar {record.get('jar')} differs from the declared {expected['jar']['sha256']}")
    if f'"{expected["java"]["version"]}"' not in record.get("java", {}).get("version", ""):
        raise Refusal(TOOL_FAILURE, f"java reports {record.get('java', {}).get('version')!r}, declared {expected['java']['version']}")
    if (record["java"].get("install") or {}).get("sha256") != expected["java"]["install"]:
        raise Refusal(TOOL_FAILURE, f"the JDK install tree differs from the declared sha256 {expected['java']['install']}")
    if record.get("models") != model_digests():
        raise Refusal(TOOL_FAILURE, "the models changed since the identity was taken")
    check = check or runner()
    cases, basis = contract(check, expected, profile, None, MODELS, pinned=pinned)
    try:
        argv = (evidence / "tlc.argv").read_text(encoding="utf-8").splitlines()
        exit_code = int((evidence / "tlc.exit").read_text().strip())
    except (OSError, ValueError) as error:
        raise Refusal(TOOL_FAILURE, f"the lane recorded no runner command or exit: {error}") from error
    try:
        want = ["tla/check.py", "--jar", record["jar"]["path"], "--workers", str(expected["workers"]),
                "--tier", profile, "--output", str((evidence / "tlc").resolve())]
        ran = [str(Path(arg).resolve()) if index in (3, 9) else arg for index, arg in enumerate(argv)]
    except (OSError, RuntimeError) as error:
        raise Refusal(TOOL_FAILURE, f"the lane's command {argv} names a path that does not resolve: {error}") from error
    if len(argv) != len(want) + 1 or not Path(argv[0]).name.startswith("python3") or ran[1:] != want:
        raise Refusal(TOOL_FAILURE, f"the lane ran {argv}, not python3 {' '.join(want)}")
    if exit_code in INTERRUPTED:
        raise Refusal(INCOMPLETE, f"the run was interrupted (exit {exit_code})", "timeout")
    if exit_code != 0:
        raise Refusal(MISMATCH, f"the runner exited {exit_code}: it refused a case, by its outcome, coverage, parse, mutation anchor or mutated step")
    results = read_json(evidence / "results.json")
    if f'"{expected["java"]["version"]}"' not in results.get("runtime", ""):
        raise Refusal(TOOL_FAILURE, f"the runner ran under {results.get('runtime')!r}, declared java {expected['java']['version']}")
    by_name = {str(result.get("case")): result for result in results.get("results", [])}
    if results.get("jar_sha256") != expected["jar"]["sha256"]:
        raise Refusal(TOOL_FAILURE, "the runner ran under a jar other than the declared one")
    if sorted(by_name) != sorted(cases) or len(by_name) != len(results.get("results", [])):
        missing, extra = sorted(set(cases) - set(by_name)), sorted(set(by_name) - set(cases))
        raise Refusal(TOOL_FAILURE, f"the results for profile {profile} miss {missing}, add {extra} or repeat a case")
    committed = {path.name: sha256(path) for path in sorted(MODELS.glob("*.tla"))}
    bounds = {}
    for name, case in sorted(cases.items()):
        result, models = by_name[name], dict(committed)
        if case.mutation:
            models[case.target] = hashlib.sha256((MODELS / case.target).read_text().replace(*case.mutation).encode()).hexdigest()
        models["model.cfg"] = hashlib.sha256(check.configuration(case, MODELS).encode()).hexdigest()
        if result.get("expected") != case.expected or result.get("returncode") != check.exit_status(case.expected):
            raise Refusal(MISMATCH, f"{name} exited {result.get('returncode')} for {result.get('expected')!r}, declared {case.expected!r}")
        if case.liveness != (result.get("command", [])[-5:-3] == ["-lncheck", "final"]):
            raise Refusal(TOOL_FAILURE, f"{name} {'lacks' if case.liveness else 'adds'} -lncheck final")
        if result.get("coverage") != list(case.coverage) or result.get("tier") != case.tier:
            raise Refusal(TOOL_FAILURE, f"{name} records coverage or a tier other than the runner's case")
        if result.get("inputs") != models:
            raise Refusal(TOOL_FAILURE, f"{name} checked models or a configuration other than the committed ones")
        for filename, declared in models.items():
            try:
                retained = sha256(evidence / "tlc" / name / filename)
            except OSError as error:
                raise Refusal(TOOL_FAILURE, f"{name} retains no {filename}: {error}") from error
            if retained != declared:
                source = ("configuration the runner generates" if filename == "model.cfg" else
                          "committed model with the case's mutation applied" if case.mutation and filename == case.target else
                          "committed model")
                raise Refusal(TOOL_FAILURE, f"{name}'s retained {filename} differs from the {source}")
        states = result.get("states")
        if states is not None and not (isinstance(states, list) and len(states) == 2
                                       and all(isinstance(count, str) and count.isdecimal() for count in states)):
            raise Refusal(TOOL_FAILURE, f"malformed evidence: {name} records the states {states!r}, not two decimal counts")
        if states is None or int(states[1]) == 0:
            raise Refusal(MISMATCH, f"{name} records no explored state")
        sany, tlc = case_logs(evidence, name, result)
        completes = check.completes(case)
        if not check.parsed(case, sany):
            raise Refusal(MISMATCH, f"{name}'s sany.log records no clean parse of module {case.module}")
        if (found := check.outcomes(tlc)) != [case.expected]:
            raise Refusal(MISMATCH, f"{name}'s tlc.log records outcomes {found}, declared {case.expected!r}")
        if completes and (missing := check.uncovered(case, tlc)):
            raise Refusal(MISMATCH, f"{name}'s tlc.log records no coverage for {missing}")
        if (counts := check.state_counts(tlc)) != states:
            raise Refusal(MISMATCH, f"{name}'s tlc.log records states {counts}, results.json {states}")
        distinct = int(counts[1])
        if pinned and completes and distinct != expected["cases"][name]["distinct"]:
            raise Refusal(MISMATCH, f"{name}'s tlc.log records {distinct} distinct states, the registry pins {expected['cases'][name]['distinct']}")
        if name in basis and not check.takes_step(tlc, basis[name]["mutated"]):
            raise Refusal(MISMATCH, f"{name}'s tlc.log records a counterexample that takes no step of {basis[name]['mutated']}")
        bounds[name] = {"distinct": distinct, "seconds": seconds(name, result), "liveness": case.liveness,
                        **basis.get(name, {})}
    return bounds


def seconds(name, result):
    """Return the case's recorded run time, refusing a value other than a finite count of seconds at or above zero.

    Python's JSON reader decodes `1e999` and `NaN`, which `json.dumps` writes back as tokens outside RFC 8259, so a
    receipt holds only an integer or a float from zero through the largest finite float. The comparison reads an
    integer of any length exactly; a conversion to a float raises `OverflowError` for one past that range.
    """
    value = result.get("seconds")
    if type(value) not in (int, float) or not 0 <= value <= sys.float_info.max:
        raise Refusal(TOOL_FAILURE, f"malformed evidence: {name} records {value!r} seconds, not a finite count at or above zero")
    return value


def pins(evidence):
    """The registry entries of the run's cases, one line each in name order and joined by commas, for a run that
    `judge` credits under the profile `tlc.argv` names when it leaves out the comparisons with the `cases` map.
    Each count is the one `judge` derives from the case's retained `tlc.log`."""
    try:
        argv = (evidence / "tlc.argv").read_text(encoding="utf-8").splitlines()
    except (OSError, ValueError) as error:
        raise Refusal(TOOL_FAILURE, f"the lane recorded no runner command: {error}") from error
    profile = argv[argv.index("--tier") + 1] if "--tier" in argv[:-1] else None
    check = runner()
    if profile not in check.PROFILES:
        raise Refusal(TOOL_FAILURE, f"the lane recorded no runner command with a profile: {argv}")
    bounds = judge(evidence, registry(), read_json(evidence / "identity.json"), profile, pinned=False, check=check)
    lines = []
    for case in sorted((case for case in check.cases() if case.name in bounds), key=lambda case: case.name):
        distinct = bounds[case.name]["distinct"] if check.completes(case) else None
        lines.append(f"    {json.dumps(case.name)}: {json.dumps(entry(check, case, MODELS, distinct))}")
    return ",\n".join(lines)


def case_logs(evidence, name, result):
    """The SANY and TLC logs the runner left for case `name` under the evidence's `tlc` directory, each read once and
    matched to the digest `result` records for it; a result without both digests, a missing log or a log whose
    bytes differ is refused by name."""
    logs = result.get("logs")
    if not (isinstance(logs, dict) and set(logs) == {"sany.log", "tlc.log"}):
        raise Refusal(TOOL_FAILURE, f"{name} records no per-case sany.log and tlc.log digests")
    texts = []
    for log in ("sany.log", "tlc.log"):
        path = evidence / "tlc" / name / log
        try:
            data = path.read_bytes()
        except OSError as error:
            raise Refusal(TOOL_FAILURE, f"{name} has no {log}: {error}") from error
        if hashlib.sha256(data).hexdigest() != logs[log]:
            raise Refusal(TOOL_FAILURE, f"{name}'s {log} differs from the digest results.json records")
        texts.append(data.decode(errors="replace"))
    return texts


SPAN_MODELS = ("Recovery.tla", "Lifecycle.tla", "Identity.tla")


def contains(outer, inner):
    """Whether span `outer` contains span `inner`: the same module, a start no later and an end no earlier."""
    return outer[0] == inner[0] and outer[1] <= inner[1] and inner[2] <= outer[2]


def positive(spans, target):
    """Whether an occurrence of span `target` in one section's span lines has a positive count. An occurrence is a
    line whose location contains `target` and under which no nested line's location also contains it. The scan under
    a line ends at the first nested line that contains `target`, so the scans of one call share no line."""
    for at, (depth, location, count) in enumerate(spans):
        if count > 0 and contains(location, target):
            below = at + 1
            while below < len(spans) and spans[below][0] > depth and not contains(spans[below][1], target):
                below += 1
            if below == len(spans) or spans[below][0] <= depth:
                return True
    return False


def reached(spans):
    """The locations one section's span lines list that have an occurrence with a positive count."""
    return {location for location in {location for _, location, _ in spans} if positive(spans, location)}


def evaluated(target, listings):
    """Whether span `target` was evaluated in `listings`, each one section's span lines with their `reached`
    locations: an occurrence of `target`, or of a listed span inside it, has a positive count."""
    return any(positive(spans, target) or any(contains(target, location) for location in inside)
               for spans, inside in listings)


def unreached(listings):
    """The unreached spans of one model's listings, as `(section, location)` pairs sorted by location, then section,
    outermost only.

    For a section that ran in one case or more, a span it lists with count 0 in a case where it ran is unreached
    when it is not evaluated in that section's span lines of the cases where it ran. For a section that ran in no
    case, a span it lists is unreached when it is not evaluated in any section of any case. Of two unreached spans
    of one section, one inside the other, only the outer one is kept. The work is at most a constant times the
    square of the number of span lines in `listings`.
    """
    ran, every = {}, []
    for listing in listings:
        for section in listing:
            lines = (section.spans, reached(section.spans))
            every.append(lines)
            if section.ran:
                ran.setdefault(section.name, []).append(lines)
    candidates = {(section.name, location) for listing in listings for section in listing
                  for _, location, count in section.spans if section.name not in ran or (section.ran and count == 0)}
    found = {(name, location) for name, location in candidates if not evaluated(location, ran.get(name, every))}
    kept = [(name, location) for name, location in found
            if not any(other == name and outer != location and contains(outer, location) for other, outer in found)]
    return sorted(kept, key=lambda entry: (entry[1], entry[0]))


def source_lines(module):
    """The lines of the committed `tla/<module>.tla`, each tab expanded to the next multiple of eight plus one, as
    SANY counts columns, or no line when the file is absent or cannot be read."""
    path = MODELS / f"{module}.tla"
    try:
        return [line.expandtabs(8) for line in path.read_text(encoding="utf-8").split("\n")] if path.is_file() else []
    except OSError:
        return []


def span_text(location, sources=None):
    """The committed model text at a span's location, from its start to its end column inclusive, its runs of white
    space joined into single spaces on one line. Columns count characters, a tab moving to the next multiple of
    eight plus one, which matches SANY's columns for text inside the Basic Multilingual Plane. `sources` caches
    `source_lines` by module. Raises ValueError for a location with its end before its start, and for a location
    outside the module's file or in a module file that is absent or cannot be read."""
    module, (first, start), (last, end) = location
    if (first, start) > (last, end):
        raise ValueError(f"span {module} {first}:{start}-{last}:{end} ends before its start")
    sources = {} if sources is None else sources
    if module not in sources:
        sources[module] = source_lines(module)
    lines = sources[module]
    if not (1 <= first <= last <= len(lines) and 1 <= start <= len(lines[first - 1]) and 1 <= end <= len(lines[last - 1])):
        raise ValueError(f"span {module} {first}:{start}-{last}:{end} lies outside the text of tla/{module}.tla")
    chunk = lines[first - 1:last]
    chunk[-1] = chunk[-1][:end]
    chunk[0] = chunk[0][start - 1:]
    return " ".join(" ".join(chunk).split())


def span_report(evidence, judged):
    """The `unreached` and `unreached_read` members of a credited report. `judged` names the cases the judgment
    credited, the profile's cases, which its static contract accepted.

    For each kestrike model, the cases of the profile that target it, complete and have no mutation; the model
    maps to its unreached spans as `{section, at, text}` entries, or to `<case>: <reason>` when the reader refuses
    a case's log or the log lists a section span outside its module's committed text, naming the first such case by
    name, or when anything else fails, naming the model's first case. A model maps to `<model file>: <reason>`, the
    bare file name such as `Recovery.tla`, when the profile has no such case, when the failure comes before its
    cases are selected, or when the setup shared by the three models fails.
    `at` is `line:col-line:col` in the file of the span's module,
    after the module's name and a space for a module other than the model. `unreached_read` counts the cases and
    the span lines of sections read for the models whose value is a list. No failure leaves this function.
    """
    report, read = {}, {"cases": 0, "span_lines": 0}
    try:
        check = runner()
        results = {result.get("case"): result for result in read_json(evidence / "results.json")["results"]}
        cases = {case.name: case for case in check.cases() if case.name in judged}
    except Exception as error:
        return {f"tla/{model}": f"{model}: the span report failed: {error!r}" for model in SPAN_MODELS}, read
    for model in SPAN_MODELS:
        names = []
        try:
            names = sorted(name for name, case in cases.items()
                           if case.target == model and check.completes(case) and not case.mutation)
            if names:
                value, listings = model_spans(check, evidence, model, names, cases, results)
            else:
                value, listings = f"{model}: the profile has no completing case of the model without a mutation", {}
        except Exception as error:
            value, listings = f"{names[0] if names else model}: the span report failed: {error!r}", {}
        report[f"tla/{model}"] = value
        if isinstance(value, list):
            read["cases"] += len(listings)
            read["span_lines"] += sum(len(section.spans) for listing in listings.values() for section in listing)
    return report, read


def model_spans(check, evidence, model, names, cases, results):
    """One model's `unreached` value, its entries or its refusal string, and the listings read for it. An action of a
    case's `coverage` ran when the last section of that operator in the listing ran, located or not, as `uncovered`
    lets an action's last coverage line decide. Every section span of each listing is checked against its module's
    committed text before the rule reads it, so a location outside that text cannot decide containment."""
    listings, sources = {}, {}
    for name in names:
        try:
            listing = check.listed(case_logs(evidence, name, results[name])[1])
            for section in listing:
                for _, location, _ in section.spans:
                    span_text(location, sources)
        except Exception as error:
            return f"{name}: {error}", {}
        ran = {section.name.split(" ")[0]: section.ran for section in listing}
        missing = next((action for action in cases[name].coverage if not ran.get(action)), None)
        if missing:
            return f"{name}: tlc.log's last complete coverage report does not show {missing} as a section that ran", {}
        listings[name] = listing
    entries = []
    for section, location in unreached([listings[name] for name in names]):
        module, (first, start), (last, end) = location
        at = ("" if f"{module}.tla" == model else f"{module} ") + f"{first}:{start}-{last}:{end}"
        entries.append({"section": section, "at": at, "text": span_text(location, sources)})
    return entries, listings


def derive(evidence, revision, profile):
    """Judge the evidence directory under the profile and return the report and the receipt it supports, writing neither."""
    code, reason, results, expected, completion = CREDITED, None, {}, {}, "completed"
    try:
        expected = registry()
        results = judge(evidence, expected, read_json(evidence / "identity.json"), profile)
    except Refusal as refusal:
        code, reason, completion = refusal.code, str(refusal), refusal.completion
    except MALFORMED as error:
        code, reason, completion = TOOL_FAILURE, f"malformed evidence: {error!r}", "tool failure"
    inputs, provenance = {}, []
    try:
        for name in ["identity.json", "report.json", "tlc.argv", "tlc.exit", "tlc.txt", "results.json"]:
            if (evidence / name).exists():
                inputs[name] = sha256(evidence / name)
        if (evidence / "pins.txt").exists():
            data = (evidence / "pins.txt").read_bytes()
            inputs["pins.txt"] = hashlib.sha256(data).hexdigest()
            provenance = data.decode("utf-8").strip().splitlines()
        for path in (ROOT / "scripts/test-inventory.json", ROOT / "scripts/test-registry.json",
                     ROOT / "verification/obligations.json", EXPECTED, *model_files()):
            inputs[str(path.relative_to(ROOT))] = sha256(path)
    except (OSError, ValueError) as error:
        unread = f"a receipt input is unreadable: {error}"
        code, reason, completion, results = TOOL_FAILURE, f"{reason}; {unread}" if reason else unread, "tool failure", {}
    report = {"code": code, "verdict": VERDICTS[code], "credited": code == CREDITED, "reason": reason,
              "profile": profile, "cases": results}
    if code == CREDITED:
        report["unreached"], report["unreached_read"] = span_report(evidence, results)
    receipt = {
        "job": "tlc", "module": profile, "lane": "tlc", "revision": revision, "inputs": inputs,
        "tool": {"name": "tlc", "provenance": provenance},
        "assumptions": ["finite instances at the bounds each configuration states; no refinement mapping to the implementation",
                        "liveness cases hold under the fairness their specifications name"],
        "bounds": {"workers": expected.get("workers"), "cases": results},
        "completion": completion, "violation": None, "detail": reason,
        "selection": {"credited": code == CREDITED, "reason": reason},
        "executions": len(results) if code == CREDITED else 0,
        "executed": sorted(results) if code == CREDITED else [], "failed": [],
        "replay": f"bash scripts/rust-lane.sh tlc {profile}",
        "ci": {key: os.environ.get(key) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")},
    }
    return report, receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description="Pin the TLC installation and judge a profile of TLA+ cases.")
    parser.add_argument("command", choices=["identity", "judge", "pins"])
    parser.add_argument("--profile", choices=["pr", "scheduled"])
    parser.add_argument("--java")
    parser.add_argument("--jar")
    parser.add_argument("--evidence")
    parser.add_argument("--revision")
    args = parser.parse_args(argv)
    if (args.command == "judge" and not args.profile) or not args.evidence \
            or (args.command == "identity" and not (args.java and args.jar)):
        parser.error(f"{args.command} needs its arguments; see the usage")
    try:
        if args.command == "identity":
            return identity(args)
    except (Refusal, OSError, KeyError, zipfile.BadZipFile) as error:
        print(f"judge-tlc: {error}", file=sys.stderr)
        return TOOL_FAILURE
    if args.command == "pins":
        try:
            print(pins(Path(args.evidence)))
        except Refusal as refusal:
            print(f"judge-tlc: {refusal}", file=sys.stderr)
            return refusal.code
        except MALFORMED as error:
            print(f"judge-tlc: malformed evidence: {error!r}", file=sys.stderr)
            return TOOL_FAILURE
        return CREDITED
    evidence = Path(args.evidence)
    revision = args.revision or subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True,
                                               text=True, check=False).stdout.strip() or None
    try:
        report, receipt = derive(evidence, revision, args.profile)
        (evidence / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        receipt["inputs"]["report.json"] = sha256(evidence / "report.json")
        (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    except (Refusal, OSError, KeyError) as error:
        print(f"judge-tlc: {error}", file=sys.stderr)
        return TOOL_FAILURE
    print(json.dumps(report, sort_keys=True))
    if report["reason"]:
        print(f"judge-tlc: {report['reason']}", file=sys.stderr)
    return report["code"]


if __name__ == "__main__":
    sys.exit(main())
