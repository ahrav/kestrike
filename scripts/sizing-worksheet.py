#!/usr/bin/env python3
"""Size shared-volume warm recovery per measured resource, as conditional scenarios with no fleet probability.

Usage:
  sizing-worksheet.py check [--worksheet F] [--records DIR] [--manifest F]
  sizing-worksheet.py evaluate --inputs F [--worksheet F] [--records DIR] [--manifest F] [--output F]

Both commands validate the measurement records under `--records` and their revision log against the qualification of
the manifest `--manifest` (the hit gate's by default), as `scripts/measurement-frame.py check` does; resolving the
frame's and the worksheet's Rust anchors runs `cargo`, so the commands need the pinned toolchain. `evaluate` reads its
inputs file before that validation.

The worksheet is `verification/measurement/sizing.json`. It pins the measurement frame and statistics versions it
reads, which must be the committed ones, maps the parent's R14 and R17 to #120 properties, and holds:
  assumptions  named texts a row or scenario carries into its output. `store-qualification` is the frame's store
               column label; `store-outage`, `store-restore` and `store-throttle` keep a store outage, an operator
               store restore and a throttled store visible; `host-loss-keeps-volume` and `actual-volume-loss` separate
               host loss from volume loss.
  inputs       each named input, its unit and its kind: `structural`, a Rust constant with its value and the
               `{path, symbol}` anchor that declares it, which must resolve as a production declaration whose value,
               evaluated from that declaration and the production constants it names in its file and its crate, is
               the recorded one; a test-gated constant, a comment or a string of the same name counts for nothing;
               `envelope`, a key of the frame's envelope; `measured`, a frame field or stage with its unit, the class
               (one the frame reports the field for) and stratum of the receipt cell that measures it, optionally the
               evidence kinds it admits (the field's by default) and optionally `at`, cell header keys every admitted
               kind carries that must equal an envelope, structural or owner input's value; `calibrated`, a frame C2
               calibration term with its unit; `handoff`, an input with no measured source yet, with its owner and
               draft; and `owner`, an owner-supplied value recorded here, null until its owner records it, a whole
               number in a unit of COUNTS, and at least the value of its `floor`, a structural input of its unit,
               when it names one. A handoff or owner input may name the class it is bound to. `store` marks a
               store-dependent input and `persisted` a persisted-layout constant.
  rows         each resource row: its level, `host` for the successor host's L_h or `shared` for L_S (the shared
               volume, the store, the AZ census and the provider), its resource, its unit (`s` for a time row,
               `ratio` for an occupancy row), its value as an arithmetic expression of at most MAX_EXPRESSION
               characters over inputs (names, the literals 1 and 2, `+`, `-`, `*`, `/`, parentheses and `ceil`), its
               assumptions and its meaning. A limit or a size enters an expression only as a named input, so the
               input-kind rules below reach it.
  scenarios    each conditional scenario: its frame class, trigger, the owner's recorded quantile (null until
               recorded), assumptions, dependency `steps` of time rows (optionally scaled by a measured `ratio`
               input) and `capacity` occupancy rows.
`check` refuses, with exit 2, a worksheet whose shape breaks these rules: pins other than the committed records'; an
input of a unit outside UNITS, which holds no probability unit, or scenario keys other than SCENARIO_KEYS (a weight,
probability or frequency is none); an input no scenario reads or a row no scenario uses; a name an expression uses
that no input declares; a measured input whose field, unit or class is not the frame's, a calibrated input that is
no C2 term of its unit, an envelope input the frame's envelope lacks; a step row not in `s`, a step ratio that is no
measured ratio input or that is a store input, whose store assumptions no row carries, or a capacity row not a
`ratio`; a scenario using an input bound to another class, so a host-loss scenario never cites the cold refill or a
replacement volume's inputs, and a row serving both a host-loss scenario and the volume-loss control; a
store-qualification text other than the frame's store column label; a warm scenario without `host-loss-keeps-volume`
or the volume-loss control without `actual-volume-loss`; a row using a store input without every store assumption;
a `ram` row using a persisted-layout input, since the 96-byte persisted rows are extent records and no runtime memory
estimate. It prints the open items: each unrecorded owner input, each handoff input, each unrecorded quantile and
each null envelope key the worksheet reads.

`evaluate` reads an inputs file the campaign analysis writes:
  receipt  {path, sha256} of the comparison receipt `scripts/measurement-frame.py report` wrote for a campaign that
           declared a contrast. The receipt admits no measured or calibrated input when it is off its digest, its
           format envelope is not measurement-frame's, its `records` are not the committed frame, statistics and
           policy pins, its judge is not the committed measurement-frame.py or its manifest not the one checked, it
           holds no comparison, a field `evaluate` reads is off its shape, or it holds a reason other than its
           withheld control notes, such as an unestablished registration or a header off the envelope. These checks
           compare the digests the receipt states with the committed judge, manifest and records; the judgments it
           states stay the producer's.
  values   {input: [{statistic, cell, value, samples, censored, evidence: {path, sha256}}]} for measured inputs only:
           the quantile the value states, the receipt cell key that measured it, a positive value in the input's
           unit, the count of observations the quantile ranks, how many of them were censored (ranked above every
           completed one) and its raw evidence. The value and both counts are the campaign analysis's declarations;
           the evaluator checks the evidence digest and the cell identity. A value for any other kind is refused, so
           an advertised limit never enters as a measurement and an owner value or store qualification never enters
           through this file.
A measured input is admitted for a scenario when its value at the scenario's quantile reaches the frame's quantile
floor (at least 10 expected exceedances over its samples) and ranks among the completed observations, names a cell of
the receipt's campaign with the input's field, class and stratum, judged as one of the input's evidence kinds on an
admitted host with a trusted clock, a cell of the receipt's sizing hand-off for a field the frame hands to sizing,
whose effective header holds every non-null frame envelope key it carries at the envelope's value and each `at` key at
the named input's value, so a value measured at another envelope is never extrapolated, and the value's evidence file
matches its digest. Its conditions carry the declared counts, the cell's verdict and reasons, its evidence column's
label and the conditions of its `at` inputs. A calibrated input is admitted when the receipt's calibration holds no
reason, every term holds a drift range under measurement-frame's `term_drift`, the statistics version declares a
drift band, no term's range reaches past it, and its floor, the lower of value less uncertainty at the start and the
end, is positive; it carries the hardware column's label. Paths are opened as given.

Each row evaluates per scenario. A row with a missing input reads `unscored` and names every missing input and why. A
row whose expression divides by zero or less reads `unbounded`: the resource has no capacity at these inputs.
`evaluate` refuses, with exit 2, a row that evaluates to a negative or non-finite number, and a row whose derivative
at the admitted values is positive in a calibrated input or negative in a measured one, since a calibrated floor is
conservative only for a capacity and an upper-quantile measurement only for a cost; `check` evaluates no row. Any
other row reads `conditional` with its value, unit, level, the elasticity d ln(value) / d ln(input) of every input its
value varies with, and its conditions: the owner inputs it rests on, each measured and calibrated input's conditions
and its assumptions. The elasticity is the forward derivative with each `ceil` relaxed to its argument: the row's
response to a change that crosses many rounding steps, while a change inside one step leaves the rounded row
unchanged. A step's L_h and L_S are its largest host and shared rows, null without a row of that level, its time the
larger of the two times its ratio, and its binding row the largest; rows tied at the largest are listed as `tied`. A
scenario's time is the sum of its step times, its binding path the binding row of each step and its binding row, with
that row's resource and level, the binding row of its longest step, with the binding rows of steps tied for longest as
`tied`; an unbounded row binds. Its sensitivity is each input's elasticity of the time: null at a zero time or while a
step's binding row ties, and absent while the time is unbounded or withheld. Each scored capacity row holds `fits`,
true at a finite ratio up to 1; the largest row is the tightest, with rows tied for it as `tied`, and the scenario
lists every row that does not fit as `unfit`: the time and binding hold only while that list is empty. No binding or
tightest row is named while a row it ranges over is unscored; the output names those rows instead. Every scenario
reads `conditional scenario` with probability `not identified`, states how its time combines quantiles, and lists its
assumptions.

The output holds the envelope, the worksheet's, the inputs file's and this script's SHA-256, the record pins, the
receipt reference and its control notes or problem, PROVENANCE, which states whose declarations the receipt's
judgments and the values are and which digests `evaluate` compares, the open items and the scenarios. `check` and
`evaluate` exit 0, and 2 for a refused input.
"""

import argparse
import ast
import functools
import hashlib
import importlib.util
import json
import math
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORKSHEET = HERE.parent / "verification/measurement/sizing.json"
ENVELOPE = {"version": 1, "section": "sizing-worksheet"}


def frame_module():
    spec = importlib.util.spec_from_file_location("measurement_frame", HERE / "measurement-frame.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("scripts/measurement-frame.py cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mf = frame_module()
gate = mf.gate
Refusal = gate.Refusal
PINNED = ("frame", "statistics")
KEYS = {"record", "version", *PINNED, "properties", "assumptions", "inputs", "rows", "scenarios"}
PROPERTIES = {"R14", "R17"}
STORE = ("store-qualification", "store-outage", "store-restore", "store-throttle")
WARM, COLD = "host-loss-keeps-volume", "actual-volume-loss"
COUNTS = {"ops", "extents", "objects", "shards", "attachments", "slots", "recoveries", "volumes", "units", "entries",
          "requests", "attempts", "passes", "suffixes"}
UNITS = mf.UNITS | COUNTS | {"extents/object", "mutations/s", "requests/s"}
INPUT_KEYS = {"structural": {"path", "symbol", "value"}, "envelope": set(), "measured": {"field", "class", "stratum"},
              "calibrated": {"term"}, "handoff": {"owner", "draft"}, "owner": {"owner", "value"}}
OPTIONAL = {"store", "persisted"}
OPTIONAL_BY_KIND = {"measured": {"at", "evidence"}, "handoff": {"class"}, "owner": {"class", "floor"}}
AT = ("envelope", "structural", "owner")
LITERALS = (1, 2)
CASTS = {f"{sign}{bits}": (1 << bits - (sign == "i")) - 1 for sign in "ui" for bits in (8, 16, 32, 64, 128)}
CASTS.update(usize=CASTS["u64"], isize=CASTS["i64"])
MAX_EXPRESSION = 2048
LEVELS = ("host", "shared")
RESOURCES = {"stage", "store", "volume-bandwidth", "volume-iops", "io-share", "link", "iops", "ram", "cpu",
             "attachments", "volume-bytes", "extents", "census", "quota"}
ROW_KEYS = {"level", "resource", "unit", "value", "meaning"}
SCENARIO_KEYS = {"class", "trigger", "quantile", "assumptions", "steps", "capacity"}
PROVENANCE = ("the receipt's judgments and the inputs file's values, sample counts and censored counts are their "
              "producer's declarations; evaluate compares the receipt file and each evidence file with its referenced "
              "SHA-256, and the judge, manifest and record digests the receipt states with the committed ones")
ESTIMATE = ("each measured input enters at the scenario's quantile and the rows combine them, so the time is no "
            "quantile of the recovery time, and a count times a per-unit quantile is no quantile or mean of the "
            "aggregate it sizes")


def need(condition, message, what="sizing worksheet"):
    if not condition:
        raise Refusal(f"malformed {what}: {message}")


def finite(value):
    return value if value is None or math.isfinite(value) else "unbounded"


def names(expression):
    """The input names `expression` reads, or a Refusal when it is no arithmetic of names, LITERALS and `ceil` of at
    most MAX_EXPRESSION characters."""
    need(len(expression) <= MAX_EXPRESSION, f"an expression holds more than {MAX_EXPRESSION} characters")
    try:
        tree = ast.parse(expression, mode="eval")
    except (SyntaxError, ValueError, RecursionError, MemoryError) as error:
        raise Refusal(f"malformed sizing worksheet: expression {expression!r} does not parse: {error}") from error
    nodes = list(ast.walk(tree))
    callees = {id(node.func) for node in nodes if isinstance(node, ast.Call)}
    found = set()
    for node in nodes:
        if isinstance(node, ast.Call):
            need(isinstance(node.func, ast.Name) and node.func.id == "ceil" and len(node.args) == 1
                 and not node.keywords, f"expression {expression!r} calls something other than ceil(x)")
        elif isinstance(node, ast.Name):
            if id(node) not in callees:
                found.add(node.id)
        else:
            need(isinstance(node, (ast.Expression, ast.BinOp, ast.Load, ast.Add, ast.Sub, ast.Mult, ast.Div))
                 or isinstance(node, ast.Constant) and type(node.value) is int and node.value in LITERALS,
                 f"expression {expression!r} holds {type(node).__name__}, not arithmetic of names and {LITERALS}")
    return found


class Unbounded(Exception):
    pass


def derive(node, env):
    """(value, {input: d value / d input}) of an expression node over `env`; Unbounded on a divisor at or below zero."""
    if isinstance(node, ast.Expression):
        return derive(node.body, env)
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return float(node.value), {}
    if isinstance(node, ast.Name):
        return float(env[node.id]), {node.id: 1.0}
    if isinstance(node, ast.Call):
        value, partial = derive(node.args[0], env)
        return float(math.ceil(value)), partial
    if not isinstance(node, ast.BinOp):
        raise Refusal(f"malformed sizing worksheet: {type(node).__name__} is no arithmetic")
    (a, da), (b, db) = derive(node.left, env), derive(node.right, env)
    keys = set(da) | set(db)
    if isinstance(node.op, ast.Add):
        return a + b, {k: da.get(k, 0) + db.get(k, 0) for k in keys}
    if isinstance(node.op, ast.Sub):
        return a - b, {k: da.get(k, 0) - db.get(k, 0) for k in keys}
    if isinstance(node.op, ast.Mult):
        return a * b, {k: da.get(k, 0) * b + a * db.get(k, 0) for k in keys}
    if b <= 0:
        raise Unbounded
    quotient = a / b
    return quotient, {k: (da.get(k, 0) - quotient * db.get(k, 0)) / b for k in keys}


def load(path):
    return gate.parse(gate.read_file(path, "sizing worksheet"), "sizing worksheet")


@functools.cache
def anchored(path, symbol):
    """Why `symbol` is no production declaration of `path`, or None; memoized per anchor."""
    return mf.resolve({"path": path, "symbol": symbol}, producer=True)


@functools.cache
def rust_constants(path):
    """{name: [(symbol, initializer)]} of the production `const` items of the Rust file at `path`, as
    `crates/source-anchors` lists them: each item's text and its `value` row's integer arithmetic, None for an item
    with no such row. The file is read as `gate.read_file` reads, so a FIFO, a device or an oversized file is
    refused, and so is a file the lister does not parse."""
    try:
        rows = mf.rust_declarations(gate.read_file(path, "Rust source").decode(errors="replace"))
    except Refusal as error:
        raise Refusal(f"Rust source {path}: {error}") from error
    values = dict(text.split(" = ", 1) for build, kind, text in rows if (build, kind) == ("production", "value"))
    found = {}
    for build, kind, text in rows:
        if (build, kind) == ("production", "item") and re.fullmatch(r"(pub(\([^)]*\))? )?const \w+", text):
            found.setdefault(text.split()[-1], []).append((text, values.get(text)))
    return found


@functools.cache
def crate_constants(path):
    """{name: [file]} of the Rust files in the crate holding `path` whose text holds `const NAME`, the keyword and an
    upper-case name apart by whitespace alone: the files under the nearest ancestor inside the repository with a
    Cargo.toml. A crate-wide lookup reads the declarations of the table's files, so the lister runs on those files
    alone."""
    found = {}
    for parent in Path(path).parents:
        if parent == mf.ROOT or mf.ROOT not in parent.parents:
            break
        if (parent / "Cargo.toml").is_file():
            for source in sorted(p for p in parent.rglob("*.rs") if p.is_file()):
                text = gate.read_file(source, "Rust source").decode(errors="replace")
                for name in set(re.findall(r"\bconst\s+([A-Z][A-Z0-9_]*)\b", text)):
                    found.setdefault(name, []).append(str(source))
            break
    return found


def declared(path, name):
    """[(file, initializer)] of the production declarations of the constant `name` in the Rust file at `path`: its
    `const` items of a build without `test`, in a file `mf.resolve` reads as production code."""
    return [(path, value) for symbol, value in rust_constants(path).get(name, []) if anchored(path, symbol) is None]


def constant(path, name, depth=8, crate=False):
    """The integer value of the Rust constant `name` as the file at `path` names it, from its one production
    declaration: in that file, its inline modules and impl blocks included, or, when `crate` holds, among the files of
    its crate. An initializer is integer literals, `+ - * /`, `<<` and `>>`, parentheses, casts and other such
    constants over non-negative values, Rust's truncating division agreeing with floor division there. A cast keeps
    its operand's value when its target is a type of CASTS whose largest value is at least the operand's, `usize` and
    `isize` at the 64 bits Kestrike builds for; Rust wraps any other operand, which reads as None. A shift
    keeps every bit, which is Rust's value while the result fits the operand's type. A bare name in it reads as the
    file that names it declares it, so a name that file imports reads as None, and a `crate::` path as the crate's one
    production declaration of its last name. None for a constant with no production declaration or several, and for
    any other initializer, cast target or path."""
    found = ([d for source in crate_constants(path).get(name, []) for d in declared(source, name)] if crate
             else declared(path, name))
    if len(found) != 1 or found[0][1] is None or depth == 0 or len(found[0][1]) > MAX_EXPRESSION:
        return None
    source, text = found[0]
    ops = {ast.Add: lambda a, b: a + b, ast.Sub: lambda a, b: a - b, ast.Mult: lambda a, b: a * b,
           ast.Div: lambda a, b: a // b if b else None, ast.LShift: lambda a, b: a << b, ast.RShift: lambda a, b: a >> b}

    def value(node):
        if isinstance(node, ast.Expression):
            return value(node.body)
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.Name):
            return constant(source, node.id, depth - 1)
        if isinstance(node, ast.Attribute):
            root = node.value
            while isinstance(root, ast.Attribute):
                root = root.value
            rooted = isinstance(root, ast.Name) and root.id == "crate"
            return constant(source, node.attr, depth - 1, crate=True) if rooted else None
        if isinstance(node, ast.Call):
            held = CASTS.get(node.func.id) if isinstance(node.func, ast.Name) else None
            operand = value(node.args[0]) if len(node.args) == 1 and not node.keywords else None
            return operand if held is not None and operand is not None and operand <= held else None
        if not isinstance(node, ast.BinOp) or type(node.op) not in ops:
            return None
        a, b = value(node.left), value(node.right)
        result = None if a is None or b is None or a < 0 or b < 0 else ops[type(node.op)](a, b)
        return result if result is None or result >= 0 else None

    try:
        return value(ast.parse(text.replace("::", "."), mode="eval"))
    except (SyntaxError, RecursionError):
        return None


def check_input(name, entry, frame):
    kind = entry.get("kind") if isinstance(entry, dict) else None
    optional = OPTIONAL | OPTIONAL_BY_KIND.get(str(kind), set())
    need(kind in INPUT_KEYS and {"kind", "unit", *INPUT_KEYS[kind]} <= set(entry)
         <= {"kind", "unit", *INPUT_KEYS[kind], *optional}, f"input {name} is no {sorted(INPUT_KEYS)} input")
    need(entry["unit"] in UNITS, f"input {name} unit {entry['unit']!r} is not one of {sorted(UNITS)}")
    need(set(entry) & {"store", "persisted"} <= {k for k, v in entry.items() if v is True},
         f"input {name} marks store or persisted with other than true")
    need(entry.get("class", next(iter(mf.CLASSES))) in mf.CLASSES, f"input {name} names no frame class")
    if kind == "structural":
        need(gate.positive(entry["value"]) and mf.text(entry["path"]) and mf.text(entry["symbol"]),
             f"structural input {name} has no positive value, path or symbol")
        problem = anchored(entry["path"], entry["symbol"])
        need(problem is None, f"structural input {name}: {problem}")
        _, target = mf.repository_path(entry["path"])
        symbol = entry["symbol"].split()[-1]
        value = constant(str(target), symbol)
        need(value == entry["value"], f"structural input {name} records {entry['value']}, but {entry['path']} "
                                      f"declares {symbol} as {value if value is not None else 'no integer constant'}")
    elif kind == "envelope":
        need(name in frame["envelope"], f"envelope input {name} is no key of the frame's envelope")
    elif kind == "measured":
        term = {**frame["fields"], **frame["stages"]}.get(entry["field"])
        need(term is not None and term["unit"] == entry["unit"] and mf.text(entry["stratum"])
             and entry["class"] in frame["comparison"]["row_classes"].get(entry["field"], mf.CLASSES),
             f"measured input {name} is no frame field of its unit, class and stratum")
        field_kinds = term["evidence"] if term else []
        kinds = entry.get("evidence", field_kinds)
        need(isinstance(kinds, list) and kinds and set(kinds) <= set(field_kinds),
             f"measured input {name} admits evidence kinds outside its field's")
        at = entry.get("at", {})
        need(isinstance(at, dict) and all(isinstance(v, str) for v in at.values())
             and all(key in mf.HEADER and set(kinds) <= set(mf.HEADER[key]) for key in at),
             f"measured input {name} holds `at` keys outside the frame header of its evidence kinds")
    elif kind == "calibrated":
        term = frame["calibration"].get(entry["term"])
        need(term is not None and term["unit"] == entry["unit"], f"calibrated input {name} is no C2 term of its unit")
    elif kind == "handoff":
        need(mf.text(entry["owner"]) and mf.text(entry["draft"]), f"handoff input {name} names no owner or draft")
    else:
        value = entry["value"]
        number = gate.integer(value) if entry["unit"] in COUNTS else mf.finite(value, zero=True) is not None
        need(mf.text(entry["owner"]) and (value is None or number),
             f"owner input {name} names no owner or holds a value that is no finite non-negative number, a whole one "
             "in a count unit")


def check(worksheet, records):
    """Validate `worksheet` against the committed `records` and return its open items; a Refusal for a broken rule."""
    need(isinstance(worksheet, dict) and set(worksheet) == KEYS and worksheet["record"] == "sizing"
         and gate.integer(worksheet["version"], 1), f"the worksheet keys are not {sorted(KEYS)}")
    for kind in PINNED:
        need(worksheet[kind] == mf.pin(records, kind), f"the worksheet pins another {kind} than the committed one")
    frame = records["frame"][0]
    need(isinstance(worksheet["properties"], dict) and set(worksheet["properties"]) == PROPERTIES,
         f"the property map does not name {sorted(PROPERTIES)}")
    assumptions, inputs, rows = worksheet["assumptions"], worksheet["inputs"], worksheet["rows"]
    need(isinstance(assumptions, dict) and {*STORE, WARM, COLD} <= set(assumptions)
         and all(map(mf.text, assumptions.values())), "the assumptions omit a store, host-loss or volume-loss text")
    need(assumptions["store-qualification"] == mf.COLUMNS["store"],
         "the store-qualification assumption is not the frame's store column label")
    need(isinstance(inputs, dict) and isinstance(rows, dict) and isinstance(worksheet["scenarios"], dict),
         "the inputs, rows or scenarios are no objects")
    for name, entry in inputs.items():
        check_input(name, entry, frame)
    for name, entry in inputs.items():
        need(all(inputs.get(v, {}).get("kind") in AT for v in entry.get("at", {}).values()),
             f"input {name} is measured at no {'/'.join(AT)} input")
        if "floor" in entry:
            low = inputs.get(entry["floor"], {}) if isinstance(entry["floor"], str) else {}
            need((low.get("kind"), low.get("unit")) == ("structural", entry["unit"])
                 and (entry["value"] is None or entry["value"] >= low["value"]),
                 f"owner input {name} is below its floor {entry['floor']} or names no structural input of its unit")
    used, reads, families = set(), {}, {}
    for name, row in rows.items():
        need(isinstance(row, dict) and ROW_KEYS <= set(row) <= ROW_KEYS | {"assumptions"} and row["level"] in LEVELS
             and row["resource"] in RESOURCES and row["unit"] in ("s", "ratio") and mf.text(row["meaning"])
             and isinstance(row["value"], str), f"row {name} breaks the row shape")
        reads[name] = names(row["value"])
        missing = reads[name] - set(inputs)
        need(not missing, f"row {name} reads undeclared inputs {sorted(missing)}")
        held = row.get("assumptions", [])
        need(isinstance(held, list) and set(held) <= set(assumptions), f"row {name} names an unknown assumption")
        need(not any(inputs[i].get("store") for i in reads[name]) or set(STORE) <= set(held),
             f"row {name} reads a store input without every store assumption {list(STORE)}")
        need(row["resource"] != "ram" or not any(inputs[i].get("persisted") for i in reads[name]),
             f"row {name} sizes RAM from persisted extent rows, which are no runtime memory estimate")
    open_items, placed = [], set()
    for name, scenario in worksheet["scenarios"].items():
        need(isinstance(scenario, dict) and set(scenario) == SCENARIO_KEYS,
             f"scenario {name} keys are not {sorted(SCENARIO_KEYS)}")
        need(scenario["class"] in mf.CLASSES and mf.text(scenario["trigger"]),
             f"scenario {name} names no frame class or no trigger")
        quantile, steps, capacity = scenario["quantile"], scenario["steps"], scenario["capacity"]
        need(quantile is None or quantile in gate.QUANTILES,
             f"scenario {name} quantile is none of {list(gate.QUANTILES)}")
        need(isinstance(steps, list) and steps and all(
            isinstance(s, dict) and set(s) <= {"rows", "ratio"} and isinstance(s.get("rows"), list) and s["rows"]
            and all(r in rows and rows[r]["unit"] == "s" for r in s["rows"]) for s in steps),
             f"scenario {name} has a step that is no list of time rows with an optional ratio input")
        ratios = [s["ratio"] for s in steps if "ratio" in s]
        need(all(inputs.get(r, {}).get("kind") == "measured" and inputs[r]["unit"] == "ratio" for r in ratios),
             f"scenario {name} scales a step by no measured ratio input")
        need(not any(inputs[r].get("store") for r in ratios),
             f"scenario {name} scales a step by a store input, whose store assumptions no row carries")
        need(isinstance(capacity, list) and all(r in rows and rows[r]["unit"] == "ratio" for r in capacity),
             f"scenario {name} has a capacity row that is no ratio row")
        cold = scenario["class"] == mf.COLD
        carried = scenario["assumptions"]
        need(isinstance(carried, list) and set(carried) <= set(assumptions),
             f"scenario {name} names an unknown assumption")
        need((COLD if cold else WARM) in carried, f"scenario {name} does not carry {COLD if cold else WARM}")
        mine = {r for s in steps for r in s["rows"]} | set(capacity)
        placed |= mine
        for r in mine:
            families.setdefault(r, set()).add(cold)
        needs = {i for r in mine for i in reads[r]} | set(ratios)
        needs |= {other for i in needs for other in (*inputs[i].get("at", {}).values(), inputs[i].get("floor", i))}
        used |= needs
        for i in sorted(needs):
            need(inputs[i].get("class", scenario["class"]) == scenario["class"],
                 f"scenario {name} of class {scenario['class']} reads {i}, bound to {inputs[i].get('class')}")
        if quantile is None:
            open_items.append(f"scenario {name} records no quantile")
    need(set(rows) == placed, f"rows {sorted(set(rows) - placed)} belong to no scenario")
    need(set(inputs) == used, f"inputs {sorted(set(inputs) - used)} are read by no scenario")
    mixed = sorted(r for r, kinds in families.items() if len(kinds) > 1)
    need(not mixed, f"rows {mixed} serve both a host-loss scenario and the volume-loss control")
    for name, entry in inputs.items():
        if entry["kind"] == "owner" and entry["value"] is None:
            open_items.append(f"owner input {name} is unrecorded ({entry['owner']})")
        elif entry["kind"] == "handoff":
            open_items.append(f"input {name} has no measured source: {entry['owner']}: {entry['draft']}")
        elif entry["kind"] == "envelope" and frame["envelope"][name] is None:
            open_items.append(f"the frame envelope declares no {name}")
    return open_items


def check_values(inputs, values):
    """Refuse an inputs file's `values` that are not positive, quantile-labeled measured values with a cell, sample
    and censored counts and evidence, one per input and quantile."""
    need(isinstance(values, dict), "its values are no object", "inputs file")
    for name, entries in values.items():
        need(inputs.get(name, {}).get("kind") == "measured",
             f"it supplies {name}, which is no measured input; its value comes from its own source", "inputs file")
        need(isinstance(entries, list) and all(
            isinstance(e, dict) and set(e) == {"statistic", "cell", "value", "samples", "censored", "evidence"}
            and e["statistic"] in gate.QUANTILES and isinstance(e["cell"], str) and gate.positive(e["value"])
            and gate.integer(e["samples"], 1) and gate.integer(e["censored"], 0, e["samples"]) for e in entries)
             and len({e["statistic"] for e in entries}) == len(entries),
             f"the values of {name} are not one positive value per quantile with its cell, samples, censored count "
             "and evidence", "inputs file")


def receipt_shape(receipt):
    """Whether every receipt field `admit` reads holds its type: cells with a verdict, text reasons, an optional header
    object and an optional text evidence kind; the four evidence columns, each with a null or text label; host
    objects; the sizing hand-off's cell list; and the receipt's reasons and withheld control notes as texts."""
    cells, columns, hosts = receipt.get("cells"), receipt.get("columns"), receipt.get("hosts")
    sizing, ranking = receipt.get("sizing"), receipt.get("ranking")

    def texts(value):
        return isinstance(value, list) and all(map(mf.text, value))

    return (isinstance(cells, dict) and all(
        isinstance(c, dict) and c.get("verdict") in mf.VERDICT_NAMES and texts(c.get("reasons", []))
        and isinstance(c.get("header", {}), dict) and mf.text(c.get("evidence", "none")) for c in cells.values())
        and isinstance(columns, dict) and set(columns) == set(mf.EVIDENCE) and all(
            isinstance(c, dict) and "label" in c and (c["label"] is None or mf.text(c["label"]))
            for c in columns.values())
        and isinstance(hosts, dict) and all(isinstance(h, dict) for h in hosts.values())
        and isinstance(sizing, dict) and isinstance(sizing.get("cells"), list)
        and texts(receipt.get("reasons")) and isinstance(ranking, dict) and texts(ranking.get("withheld"))
        and mf.text(receipt.get("campaign")))


def receipt_problem(ref, records, manifest_sha256):
    """Why the comparison receipt at `ref` admits no input, or None; and the receipt."""
    problem, data = mf.evidence_problem(ref, "comparison receipt")
    if problem:
        return problem, None
    try:
        receipt = gate.parse(data, "comparison receipt")
    except Refusal as error:
        return str(error), None
    if not isinstance(receipt, dict) or receipt.get("envelope") != mf.ENVELOPE:
        return f"the receipt's format envelope is not {mf.ENVELOPE}", None
    if receipt.get("records") != {kind: mf.pin(records, kind) for kind in mf.KINDS}:
        return "the receipt was judged under other records than the committed ones", None
    judge = hashlib.sha256(gate.read_file(mf.__file__, "judge")).hexdigest()
    if (receipt.get("judge_sha256"), receipt.get("manifest_sha256")) != (judge, manifest_sha256):
        return "the receipt was judged by another measurement-frame.py or manifest than the committed ones", None
    if not isinstance(receipt.get("comparison"), dict):
        return "the receipt holds no comparison, so it has no calibration", None
    if not receipt_shape(receipt):
        return "the receipt's cells, columns, hosts, sizing hand-off, reasons or campaign are off their shape", None
    faults = [r for r in receipt["reasons"] if r not in receipt["ranking"]["withheld"]]
    if faults:
        return f"the receipt's campaign is unestablished: {'; '.join(faults)}", None
    return None, receipt


def calibration_problem(receipt, statistics):
    """Why the receipt's calibration is no stable floor, or None. Each term needs a drift range under
    measurement-frame's `term_drift`; a term drifted when the low end of its range exceeds the drift band, and its
    uncertainty spans the band when only the high end does."""
    calibration = receipt["comparison"].get("calibration")
    if not (isinstance(calibration, dict) and isinstance(calibration.get("reasons"), list)
            and all(map(mf.text, calibration["reasons"])) and isinstance(calibration.get("terms"), dict)):
        return "the receipt's calibration holds no list of reasons and table of terms"
    if calibration["reasons"]:
        return f"the receipt's calibration holds reasons: {'; '.join(calibration['reasons'])}"
    band = statistics["drift_band"]
    if band is None:
        return "the statistics version declares no drift band, so no calibration is stable"
    drifted, spanned = [], []
    for name, term in sorted(calibration["terms"].items()):
        pair = [term.get(p) if isinstance(term, dict) else None for p in ("start", "end")]
        problem, entry = mf.term_drift(name, pair)
        if problem:
            return problem
        low, high = entry["range"]
        if low > band:
            drifted.append(name)
        elif high > band:
            spanned.append(name)
    if drifted:
        return f"calibration terms {drifted} drift past the band {band}"
    return f"the uncertainty of calibration terms {spanned} spans the drift band {band}" if spanned else None


def admit(name, entry, scenario, ctx):
    """(value, conditions) of input `name` for `scenario`, or (None, [why it is missing])."""
    kind, frame = entry["kind"], ctx["frame"]
    if kind == "structural":
        return entry["value"], []
    if kind == "envelope":
        value = frame["envelope"][name]
        return (value, []) if value is not None else (None, [f"the frame envelope declares no {name}"])
    if kind == "owner":
        if entry["value"] is None:
            return None, [f"owner input {name} is unrecorded ({entry['owner']})"]
        return entry["value"], [f"owner input {name} = {entry['value']} ({entry['owner']})"]
    if kind == "handoff":
        return None, [f"{name} has no measured source: {entry['owner']}: {entry['draft']}"]
    receipt = ctx["receipt"]
    if receipt is None:
        return None, [f"{name}: {ctx['problem']}"]
    notes = [f"{name}: the receipt withholds its ranking on {len(receipt['reasons'])} control notes, listed in "
             "receipt_reasons"] if receipt["reasons"] else []
    if kind == "calibrated":
        if ctx["calibration"]:
            return None, [f"{name}: {ctx['calibration']}"]
        term = receipt["comparison"]["calibration"]["terms"].get(entry["term"])
        if term is None:
            return None, [f"{name}: the receipt's calibration holds no term {entry['term']}"]
        floor = min(term[p]["value"] - term[p]["uncertainty"] for p in ("start", "end"))
        if floor <= 0:
            return None, [f"{name}'s calibrated floor {floor} is not positive"]
        label = receipt["columns"]["hardware"]["label"]
        return floor, [f"{name}: floor of calibration term {entry['term']}", *notes,
                       *([f"{name}: {label}"] if label else [])]
    quantile = scenario["quantile"]
    if quantile is None:
        return None, [f"{name}: the owner records no quantile for this scenario"]
    found = [e for e in ctx["values"].get(name, []) if e["statistic"] == quantile]
    if not found:
        return None, [f"{name} has no measured value at {quantile}"]
    (value,) = found
    samples, censored, q = value["samples"], value["censored"], gate.QUANTILES[quantile]
    floor = mf.floor_kind(samples, q)
    if floor != "quantile":
        return None, [f"{name}: {quantile} over {samples} samples reads {floor}, so it reports no quantile"]
    if math.ceil(q * samples) > samples - censored:
        return None, [f"{name}: {quantile} over {samples} samples ranks among its {censored} censored runs"]
    key = value["cell"]
    cell = receipt["cells"].get(key)
    if cell is None:
        return None, [f"{name}: the receipt holds no cell {key}"]
    identity = mf.identity_values(key)
    if not identity:
        return None, [f"{name}: cell {key} is no cell identity of {len(mf.IDENTITY)} values"]
    if [identity[k] for k in ("field", "class", "stratum")] != [entry[k] for k in ("field", "class", "stratum")]:
        return None, [f"{name}: cell {key} measures {identity['field']}/{identity['class']}/{identity['stratum']}, "
                      f"not {entry['field']}/{entry['class']}/{entry['stratum']}"]
    if identity["campaign"] != receipt["campaign"]:
        return None, [f"{name}: cell {key} belongs to campaign {identity['campaign']}, not the receipt's"]
    kinds = entry.get("evidence", {**frame["fields"], **frame["stages"]}[entry["field"]]["evidence"])
    host = receipt["hosts"].get(identity["host"]) if isinstance(identity["host"], str) else None
    if not (cell.get("evidence") == identity["evidence"] and identity["evidence"] in kinds
            and cell.get("degraded") is False and isinstance(host, dict) and host.get("admitted") is True):
        return None, [f"{name}: cell {key} is no {'/'.join(kinds)} evidence of an admitted host with a trusted clock"]
    if entry["field"] in frame["comparison"]["sizing"]["fields"] and key not in receipt["sizing"]["cells"]:
        return None, [f"{name}: cell {key} is not in the receipt's sizing hand-off"]
    header = cell.get("header", {})
    for k, v in frame["envelope"].items():
        if v is not None and k in header and header[k] != v:
            return None, [f"{name}: cell {key} was measured at {k} {header[k]!r}, not the envelope's {v!r}, and no "
                          "value is extrapolated"]
    conditions = []
    for k, other in entry.get("at", {}).items():
        at, why = admit(other, ctx["inputs"][other], scenario, ctx)
        if at is None or header.get(k) != at:
            return None, [f"{name}: cell {key} was measured at {k} {header.get(k)!r}, not {other} {at!r}, and no "
                          "value is extrapolated"]
        conditions += why
    ref = json.dumps(value["evidence"], sort_keys=True)
    if ref not in ctx["evidence"]:
        ctx["evidence"][ref] = mf.evidence_problem(value["evidence"], "evidence")[0]
    if ctx["evidence"][ref]:
        return None, [f"{name}: {ctx['evidence'][ref]}"]
    label = receipt["columns"][identity["evidence"]]["label"]
    return value["value"], [f"{name}: {quantile} over {samples} samples with {censored} censored, "
                            f"{float(samples * (1 - q)):g} expected exceedances, as the inputs file states",
                            f"{name}: cell verdict {cell['verdict']}", *(f"{name}: {r}" for r in cell.get("reasons", [])),
                            *notes, *([f"{name}: {label}"] if label else []), *conditions]


def evaluate_row(name, row, scenario, ctx):
    inputs, missing, conditions, env = ctx["inputs"], [], [], {}
    for i in sorted(names(row["value"])):
        value, notes = admit(i, inputs[i], scenario, ctx)
        (missing if value is None else conditions).extend(notes)
        env[i] = value
    base = {"level": row["level"], "resource": row["resource"], "unit": row["unit"], "meaning": row["meaning"]}
    if missing:
        return {**base, "status": "unscored", "missing": missing}
    conditions += [ctx["assumptions"][a] for a in row.get("assumptions", [])]
    try:
        value, partial = derive(ast.parse(row["value"], mode="eval"), env)
    except Unbounded:
        return {**base, "status": "unbounded", "conditions": conditions}
    except OverflowError:
        value, partial = math.inf, {}
    need(math.isfinite(value) and value >= 0, f"row {name} evaluates to {value}, no finite non-negative number")
    rising = sorted(k for k, d in partial.items() if inputs[k]["kind"] == "calibrated" and d > 0)
    need(not rising, f"row {name} rises with calibrated inputs {rising}, whose floor is conservative only for a capacity")
    falling = sorted(k for k, d in partial.items() if inputs[k]["kind"] == "measured" and d < 0)
    need(not falling, f"row {name} falls as measured inputs {falling} rise, so an upper quantile of them is no "
                      "conservative cost")
    elasticity = {k: d * env[k] / value for k, d in sorted(partial.items()) if value and d}
    return {**base, "status": "conditional", "value": value, "elasticity": elasticity, "conditions": conditions}


def size(row):
    """A scored row's value, infinite for an unbounded row."""
    return row.get("value", math.inf)


def bind(scored, rows):
    """The scenario time, its binding and its sensitivity over fully scored steps of (step, binding row, time, tied)."""
    times = [time for _, _, time, _ in scored]
    total = sum(times)
    longest = scored[times.index(max(times))][1]
    binding = {"row": longest, "resource": rows[longest]["resource"], "level": rows[longest]["level"],
               "path": [b for _, b, _, _ in scored]}
    tied = [b for _, b, time, _ in scored if time == max(times)]
    if len(tied) > 1:
        binding["tied"] = tied
    if not math.isfinite(total):
        return {"time": "unbounded", "binding": binding}
    if total == 0 or any(tie for *_, tie in scored):
        return {"time": total, "binding": binding, "sensitivity": None}
    sensitivity = {}
    for step, row, time, _ in scored:
        for name, e in [*rows[row]["elasticity"].items(), *([(step["ratio"], 1.0)] if "ratio" in step else [])]:
            sensitivity[name] = sensitivity.get(name, 0.0) + e * time / total
    return {"time": total, "binding": binding, "sensitivity": dict(sorted(sensitivity.items()))}


def evaluate_scenario(scenario, ctx):
    rows = {r: evaluate_row(r, ctx["rows"][r], scenario, ctx)
            for r in [*(r for s in scenario["steps"] for r in s["rows"]), *scenario["capacity"]]}
    out = {"class": scenario["class"], "trigger": scenario["trigger"], "label": "conditional scenario",
           "probability": "not identified", "quantile": scenario["quantile"], "estimate": ESTIMATE,
           "assumptions": {a: ctx["assumptions"][a] for a in [*scenario["assumptions"], *(
               a for r in rows for a in ctx["rows"][r].get("assumptions", []))]}, "rows": rows, "steps": []}
    withheld, scored = [], []
    for step in scenario["steps"]:
        ratio, notes = (1.0, []) if "ratio" not in step else admit(step["ratio"], ctx["inputs"][step["ratio"]],
                                                                   scenario, ctx)
        unscored = [f"row {r} is unscored" for r in step["rows"] if rows[r]["status"] == "unscored"]
        if ratio is None or unscored:
            withheld += [*(notes if ratio is None else []), *unscored]
            out["steps"].append({"rows": step["rows"], "binding": None})
            continue
        level = {lv: max((size(rows[r]) for r in step["rows"] if rows[r]["level"] == lv), default=None)
                 for lv in LEVELS}
        binding = max(step["rows"], key=lambda r: size(rows[r]))
        tied = [r for r in step["rows"] if size(rows[r]) == size(rows[binding])]
        time = ratio * size(rows[binding])
        scored.append((step, binding, time, len(tied) > 1))
        out["steps"].append({"rows": step["rows"], "L_h": finite(level["host"]), "L_S": finite(level["shared"]),
                             "ratio": ratio, "time": finite(time), "binding": binding,
                             **({"tied": tied} if len(tied) > 1 else {}), **({"conditions": notes} if notes else {})})
    out.update({"binding": None, "withheld": withheld} if withheld else bind(scored, rows))
    capacity = {r: rows[r] for r in scenario["capacity"]}
    for row in capacity.values():
        if row["status"] != "unscored":
            row["fits"] = row["status"] == "conditional" and row["value"] <= 1
    out["unfit"] = [r for r, row in capacity.items() if row.get("fits") is False]
    unscored = [f"row {r} is unscored" for r, row in capacity.items() if row["status"] == "unscored"]
    tightest = max(capacity, key=lambda r: size(capacity[r]), default=None)
    tied = [r for r in capacity if tightest is not None and size(capacity[r]) == size(capacity[tightest])]
    out["capacity"] = {"rows": scenario["capacity"], **({"withheld": unscored} if unscored else {
        "tightest": tightest, **({"tied": tied} if len(tied) > 1 else {})})}
    return out


def evaluate(worksheet, records, document, worksheet_sha256, inputs_sha256, manifest_sha256):
    """The worksheet output for the inputs file `document` under the committed `records` and the manifest of SHA-256
    `manifest_sha256`."""
    need(isinstance(document, dict) and set(document) == {"receipt", "values"}, "its keys are not receipt and values",
         "inputs file")
    open_items = check(worksheet, records)
    check_values(worksheet["inputs"], document["values"])
    problem, receipt = receipt_problem(document["receipt"], records, manifest_sha256)
    ctx = {"frame": records["frame"][0], "inputs": worksheet["inputs"], "rows": worksheet["rows"],
           "assumptions": worksheet["assumptions"], "values": document["values"], "receipt": receipt,
           "problem": problem, "evidence": {},
           "calibration": receipt and calibration_problem(receipt, records["statistics"][0])}
    return {"envelope": ENVELOPE, "worksheet_sha256": worksheet_sha256, "inputs_sha256": inputs_sha256,
            "judge_sha256": hashlib.sha256(gate.read_file(__file__, "judge")).hexdigest(),
            "records": {kind: mf.pin(records, kind) for kind in mf.KINDS}, "receipt": document["receipt"],
            "provenance": PROVENANCE,
            "receipt_reasons": receipt["reasons"] if receipt else [problem], "open": open_items,
            "scenarios": {name: evaluate_scenario(s, ctx) for name, s in worksheet["scenarios"].items()}}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check and evaluate the shared-volume warm-recovery worksheet.")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "evaluate"):
        command = commands.add_parser(name)
        command.add_argument("--worksheet", default=str(WORKSHEET))
        command.add_argument("--records", default=str(mf.RECORDS))
        command.add_argument("--manifest", default=str(gate.MANIFEST))
    commands.choices["evaluate"].add_argument("--inputs", required=True)
    commands.choices["evaluate"].add_argument("--output")
    args = parser.parse_args(argv)
    try:
        raw, inputs = b"", None
        if args.command == "evaluate":
            raw = gate.read_file(args.inputs, "inputs file")
            inputs = gate.parse(raw, "inputs file")
        data = gate.read_file(args.worksheet, "sizing worksheet")
        worksheet = gate.parse(data, "sizing worksheet")
        records, log = mf.load(args.records)
        document, manifest_sha256 = gate.read_document(args.manifest, gate.lane_module())
        mf.check(records, log, document["qualification"])
        if args.command == "check":
            print(json.dumps({"open": check(worksheet, records)}, indent=1))
            return 0
        out = json.dumps(evaluate(worksheet, records, inputs, hashlib.sha256(data).hexdigest(),
                                  hashlib.sha256(raw).hexdigest(), manifest_sha256), indent=1, sort_keys=True) + "\n"
        if args.output:
            gate.write_receipt(args.output, out)
        else:
            sys.stdout.write(out)
    except gate.FAULTS as error:
        print(f"sizing-worksheet: refused: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
