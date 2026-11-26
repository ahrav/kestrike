#!/usr/bin/env python3
"""Judge one run of the game-day package GD-2 from its evidence directory and write the run record that
`scripts/readiness.py judge` reads.

Usage:
  gameday-judge.py --evidence DIR --record FILE

The judge reads DIR in the layout `docs/agents/ci.md` states, GD-2 from `verification/readiness/gamedays.json` and
`scripts/fis-profiles.json`, both of its own tree, and nothing else; it makes no git or network call. It writes FILE
once and replaces no entry. Exit 0 delivers a HELD record, 1 any other record, 2 no record of this run. The layout
(each file, its writer and its keys), the texts, the reach, the eleven rules, the record and every refusal are stated
once, in the subsection "The evidence layout, the rules and the record" of `docs/agents/ci.md`; its capitalized names
are this script's constants.
"""

import argparse
import contextlib
import datetime
import decimal
import fractions
import hashlib
import importlib.util
import json
import math
import os
import re
import stat
import sys
from collections import namedtuple
from pathlib import Path

HERE = Path(__file__).resolve().parent
CATALOG = HERE.parent / "verification/readiness/gamedays.json"
PROFILES = HERE / "fis-profiles.json"
PACKAGE = "GD-2"
FILE_LIMIT = 64 << 20
MIN_OWNED, MIN_STOOD, ATTEMPTS_MAX = 2, 1, (1 << 31) - 2
MAX_INTERVALS = 10 ** 6
OBSERVATION_FILES = {"origin": "origin.jsonl", "provider": "provider.jsonl", "re-enrollment": "blockers.jsonl"}
LAYOUT_DIRS = ("injection", "records")
CAUSES = ("guardrail", "deadline", "exception", "signal", "reach", "stop-not-shown")
OUTCOMES = ("hit", "miss", "error")
KINDS = {"staging": "causal", "simulation": "simulation"}
COMMIT = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
SHARD = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")

WITNESS = ("each of the filled package's witness keys from the certified pre-fault cut, at least one per shard, is "
           "first hit on the successor with its recorded bytes and no origin request for that key before the hit")
WRITTEN = {
    "clauses": [
        ("each owned shard is taken over by its named standby at the same generation and volume", None),
        ("every shard the stopped host did not own keeps its owner", None),
        ("no volume is created, no generation changes and each shard has one owner per tenure", None),
        ("each shard the stopped host owned or stood by for has an enrolled standby again within the re-enrollment "
         "drain or reports a named blocker", "re-enrollment-drain"),
        ("the zone's origin request rate above its baseline before the injection stays within the origin-load budget",
         "origin-load"),
    ],
    "guardrails": [
        "any generation change", "any CreateVolume by the reconciler principal",
        "any replacement receipt written by the reconciler principal",
        "a takeover of a shard with no role on the stopped host", "a shard that changes hands twice",
        "the zone's origin request rate above its baseline past the origin-load budget",
        "a shard without a standby or a named blocker past the re-enrollment drain",
        "two hosts activating one tenure of a shard"],
    # The SHA-256 of the UTF-8 bytes of GD-2's `oracle.reach` and `oracle.expected` in
    # `verification/readiness/gamedays.json`, as the rules were written from them.
    "reach": "61ee57c75da6a905e9388ddd4e88da65966475424b199077be2f74734d47cc0b",
    "expected": "20bea5125462d542f16749914573e4dedf7c844746d10f0390268583b2b9f575",
}


class Refusal(Exception):
    """Evidence or a catalog the judge cannot read as the layout states: exit 2, no record of this run. `written` marks
    the refusal after which this run's record may stand: its directory sync failed and its removal is not durable."""

    def __init__(self, message, written=False):
        super().__init__(message)
        self.written = written


def need(condition, message):
    if not condition:
        raise Refusal(message)


def load_readiness():
    """`scripts/readiness.py` of this tree, loaded by its path, for its `package_digest`."""
    spec = importlib.util.spec_from_file_location("readiness", HERE / "readiness.py")
    if spec is None or spec.loader is None:
        raise Refusal("scripts/readiness.py cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def distinct_keys(pairs):
    if len({k for k, _ in pairs}) != len(pairs):
        raise ValueError("an object repeats a key")
    return dict(pairs)


def double(literal):
    """A fractional JSON number as the double whose shortest decimal form is the literal's value."""
    if not math.isfinite(value := float(literal)):
        raise ValueError(f"the number {literal} is beyond a double's range")
    if decimal.Decimal(literal) != decimal.Decimal(repr(value)):
        raise ValueError(f"the number {literal} holds more digits than a double carries")
    return value


def no_constant(literal):
    raise ValueError(f"the constant {literal} is no number")


DECODER = json.JSONDecoder(object_pairs_hook=distinct_keys, parse_constant=no_constant, parse_float=double)


def decode(text, what):
    """`text` decoded as one JSON value with distinct object keys and finite numbers, or a Refusal naming `what`."""
    try:
        return DECODER.decode(text)
    except (ValueError, RecursionError, decimal.InvalidOperation) as error:
        raise Refusal(f"{what} is not strict JSON: {error!r}") from error


def exact(v):
    """The decimal value of a decoded JSON number as a fraction; `double` makes a float's shortest form that value."""
    return fractions.Fraction(repr(v)) if isinstance(v, float) else fractions.Fraction(v, 1)


def shown(x):
    """A fraction of a time, a duration or a count as the text of a detail."""
    return str(x.numerator) if x.denominator == 1 else repr(float(x))


def read_bytes(path, what, dir_fd=None):
    """The bytes of the regular file at `path` (relative to `dir_fd`), at most FILE_LIMIT, opened with no link."""
    try:
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd),
                       "rb") as handle:
            need(stat.S_ISREG(os.fstat(handle.fileno()).st_mode), f"{what} is no regular file")
            data = handle.read(FILE_LIMIT + 1)
    except OSError as error:
        raise Refusal(f"{what} cannot be read: {error.strerror}") from error
    need(len(data) <= FILE_LIMIT, f"{what} holds more than {FILE_LIMIT} bytes")
    return data


def parsed(data, rel):
    """A `.json` file as one value, a `.jsonl` file as its lines; a blank or unterminated last line is refused."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Refusal(f"{rel} is not UTF-8: {error}") from error
    if not rel.endswith(".jsonl"):
        return decode(text, rel)
    need(text == "" or text.endswith("\n"), f"{rel} ends in a line with no newline: it may be truncated")
    return [decode(line, f"{rel} line {n}") for n, line in enumerate(text.split("\n")[:-1], 1)]


def finite(v):
    """A JSON number of at most 2^53 in magnitude, compared without a conversion, so NaN and the infinities fail."""
    return not isinstance(v, bool) and isinstance(v, (int, float)) and abs(v) <= 1 << 53


def encodable(v):
    return v.isascii() or not any(0xD800 <= ord(c) <= 0xDFFF for c in v)


def calendar(v):
    try:
        return isinstance(v, str) and DATE.fullmatch(v) is not None and bool(datetime.date.fromisoformat(v))
    except ValueError:
        return False


def member_of(kind):
    """A scalar check that its value is one of the package's names of `kind`."""
    return lambda v, names: isinstance(v, str) and v in names[kind]


# A schema is a dict (an object with exactly its keys), a one-element list (a list of its element), a tuple of dicts
# (one of them, chosen by its keys), a frozenset (one of its members), an Each (a map) or a scalar name, which a
# trailing "?" makes nullable. `names` holds the package's hosts, shards and witness keys.
Each = namedtuple("Each", "keys value exact")
SCALARS = {
    "name": lambda v, names: isinstance(v, str) and v.strip() != "" and encodable(v),
    "time": lambda v, names: finite(v),
    "positive": lambda v, names: finite(v) and v > 0,
    "nonnegative": lambda v, names: finite(v) and v >= 0,
    "count": lambda v, names: isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 1 << 53,
    "generation": lambda v, names: SCALARS["count"](v, names) and 1 <= v < 1 << 32,
    "attempts": lambda v, names: SCALARS["count"](v, names) and v <= ATTEMPTS_MAX,
    "epoch": lambda v, names: SCALARS["count"](v, names) and v <= 2 * ATTEMPTS_MAX,
    "digest": lambda v, names: isinstance(v, str) and DIGEST.fullmatch(v) is not None,
    "commit": lambda v, names: isinstance(v, str) and COMMIT.fullmatch(v) is not None,
    "date": lambda v, names: calendar(v),
    "file-name": lambda v, names: isinstance(v, str) and SHARD.fullmatch(v) is not None and v != "receipts",
    "guardrail": lambda v, names: v in WRITTEN["guardrails"],
    **{kind: member_of(kind) for kind in ("host", "shard", "key")},
}


def conform(v, schema, what, names, path=()):
    """Refuse `v` unless it has the shape `schema` states; `what` and `path` name it in a refusal."""
    def refuse(text):
        parts, link = [], path
        while link:
            link, key = link
            parts.append(str(key))
        raise Refusal(" ".join([what, *reversed(parts), text]))

    kind = type(schema)
    if kind is str:
        if not (v is None and schema[-1] == "?") and not SCALARS[schema.rstrip("?")](v, names):
            refuse(f"is no {schema.rstrip('?')} of the layout: {v!r}")
    elif kind is dict:
        if type(v) is not dict:
            refuse("is no object")
        if v.keys() != schema.keys():
            refuse(f"holds the keys {sorted(v)}, not {sorted(schema)}")
        for key, s in schema.items():
            if type(s) is not str or not (v[key] is None and s[-1] == "?" or SCALARS[s.rstrip("?")](v[key], names)):
                conform(v[key], s, what, names, (path, key))
    elif kind is tuple:
        conform(v, next((s for s in schema if isinstance(v, dict) and v.keys() == s.keys()), schema[0]), what, names,
                path)
    elif kind is list:
        if type(v) is not list:
            refuse("is no list")
        for i, item in enumerate(v):
            conform(item, schema[0], what, names, (path, f"[{i}]"))
    elif kind is Each:
        if type(v) is not dict:
            refuse("is no object")
        keys = set(names[schema.keys])
        if not (set(v) == keys if schema.exact else set(v) <= keys):
            refuse(f"names {sorted(v)}, not {'exactly' if schema.exact else 'only'} the {schema.keys}s {sorted(keys)}")
        for key, item in v.items():
            conform(item, schema.value, what, names, (path, key))
    elif not (isinstance(v, str) and v in schema):
        refuse(f"{v!r} is none of {sorted(schema)}")


WINDOW = {"start": "time", "end": "time"}
VERSION = {"owner": "host", "standby": "host?", "generation": "generation", "volume": "name", "attempts": "attempts"}
REQUEST = {"instance": "name", "time": "time", "identity": "name"}
PACKAGE_SCHEMA = {
    "id": frozenset({PACKAGE}), "kind": frozenset(KINDS), "revision": "commit", "date": "date", "clock": "name",
    "target": {"host": "host", "instance": "name"}, "hosts": ["name"], "shards": ["file-name"],
    "witness": [{"key": "name", "shard": "shard", "sha256": "digest"}], "baseline": WINDOW, "run": WINDOW,
    "interval": "positive", "reconciler_principal": "name", "working_budgets": Each("budget", "positive", False),
    "outside": Each("observation", "name", False), "clock_error_seconds": "nonnegative"}
# Each file of the layout but `package.json` and `records/<shard>.jsonl`, with its schema and whether it is optional.
LAYOUT = {
    "injection/roles.json": ({"package_sha256": "digest", "time": "time", "shards": Each("shard", VERSION, True),
                              "standbys": Each("host", {"instance": "name", "instance_state": "name",
                                                        "host_report": "name"}, False)}, False),
    "injection/stop.json": (REQUEST, True),
    "injection/stopped.json": ({"instance": "name", "state": "name", "time": "time", "request": REQUEST}, True),
    "injection/abort.json": ({"cause": frozenset(CAUSES), "guardrail": "guardrail?", "time": "time",
                              "detail": "name?"}, True),
    "injection/restoration.json": ({"instance": "name", "state": "name", "time": "time",
                                    "reviewed_sha256": "digest?"}, True),
    "records/receipts.jsonl": ({"time": "time", "shard": "shard", "principal": "name"}, False),
    "activations.jsonl": ({"host": "host", "activations": [{"shard": "shard", "generation": "generation",
                                                             "attempt": "epoch", "time": "time"}]}, False),
    "witness.jsonl": ({"key": "key", "host": "host", "time": "time", "outcome": frozenset(OUTCOMES),
                       "sha256": "digest?"}, False),
    "origin.jsonl": ({"time": "time", "key": "name"}, False),
    "provider.jsonl": (({"event": frozenset({"volume"}), "volume": "name", "time": "time"},
                        {"event": frozenset({"CreateVolume"}), "principal": "name", "time": "time"}), False),
    "blockers.jsonl": ({"shard": "shard", "time": "time", "name": "name"}, False),
    "coverage.json": (Each("observed", {"from": "time", "to": "time", "lines": "count"}, True), False),
}
# The files a collector writes, which `coverage.json` spans: each `records/` file and these.
COLLECTED = ("activations.jsonl", "witness.jsonl", "origin.jsonl", "provider.jsonl", "blockers.jsonl")


def check_package(p):
    """Refuse a package object off its schema or its windows; return the names its other files are read against."""
    for field in ("hosts", "shards"):
        conform(p.get(field), ["name"], f"package.json {field}", {})
        need(p[field] and len(set(p[field])) == len(p[field]), f"package.json {field} is empty or repeats a name")
    names = {"host": set(p["hosts"]), "shard": set(p["shards"]), "observation": set(OBSERVATION_FILES),
             "budget": {b for _, b in WRITTEN["clauses"] if b is not None}}
    conform({k: v for k, v in p.items() if k != "note"}, PACKAGE_SCHEMA, "package.json", names)
    conform(p.get("note", "-"), "name", "package.json note", names)
    names["key"] = {w["key"] for w in p["witness"]}
    need(len(names["key"]) == len(p["witness"]), "package.json repeats a witness key")
    base, run = p["baseline"], p["run"]
    need(base["start"] < base["end"] <= run["end"] and run["start"] <= base["end"] and run["start"] < run["end"],
         "the windows are empty, or the baseline window ends after the run window or before it starts")
    intervals = (exact(run["end"]) - exact(run["start"])) / exact(p["interval"])
    need(intervals.denominator == 1 and 1 <= intervals <= MAX_INTERVALS,
         f"the run window is not a whole number of origin intervals, from 1 to {MAX_INTERVALS}")
    need(p["kind"] == "staging" or p["clock_error_seconds"] == 0, "a simulation package names a clock error other "
         "than 0")
    need(p["kind"] == "simulation" or not p["outside"], f"a staging package names {sorted(p['outside'])} as outside "
         "its world")
    return names


def open_dir(path, what, dir_fd=None):
    """A descriptor of the directory at `path`, following no link at its last component, or a Refusal."""
    try:
        return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
    except OSError as error:
        raise Refusal(f"{what} is no directory: {error.strerror}") from error


def entries(fd, prefix):
    """{relative path: whether a directory} of the directory open at `fd`, refusing what the layout holds not."""
    try:
        names = sorted(os.listdir(fd))
    except OSError as error:
        raise Refusal(f"{prefix or 'the evidence directory'} cannot be listed: {error.strerror}") from error
    found = {}
    for name in names:
        rel = prefix + name
        try:
            mode = os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode
        except OSError as error:
            raise Refusal(f"{rel} cannot be read: {error.strerror}") from error
        need(stat.S_ISDIR(mode) or stat.S_ISREG(mode), f"{rel} is a link or a special file")
        need(stat.S_ISREG(mode) or rel in LAYOUT_DIRS, f"{rel} is no directory of the layout")
        found[rel] = stat.S_ISDIR(mode)
    return found


def ordered(rows):
    return all(rows[i]["time"] <= rows[i + 1]["time"] for i in range(len(rows) - 1))


def read_evidence(root):
    """The evidence directory at `root`, each file read relative to its listed directory, judged by `load_evidence`."""
    need(os.fspath(root) != "", "no evidence directory is named")
    with contextlib.ExitStack() as held:
        top = open_dir(str(Path(root)), root)
        held.callback(os.close, top)
        where = {}
        for rel, is_dir in entries(top, "").items():
            if not is_dir:
                where[rel] = (top, rel)
                continue
            fd = open_dir(rel, rel, top)
            held.callback(os.close, fd)
            where.update({sub: (fd, sub[len(rel) + 1:]) for sub in entries(fd, rel + "/")})
        need("package.json" in where, "package.json is missing")
        package = read_bytes("package.json", "package.json", top)
        admit(package_of(package)[0], set(where))
        files = {rel: package if rel == "package.json" else read_bytes(name, rel, fd)
                 for rel, (fd, name) in sorted(where.items())}
    return load_evidence(files)


def package_of(data):
    """`package.json`'s bytes parsed and checked: (package, the names its files are read against)."""
    p = parsed(data, "package.json")
    if not isinstance(p, dict):
        raise Refusal("package.json is no object")
    return p, check_package(p)


def layout_of(p):
    """{relative path: (schema, optional)} of every file the package's layout holds but `package.json`."""
    return {**{f"records/{s}.jsonl": ({"time": "time", **VERSION}, False) for s in p["shards"]}, **LAYOUT}


def admit(p, rels):
    """Refuse a path of `rels` outside the layout of package `p`, or the file of an observation it names outside."""
    layout, absent = layout_of(p), {OBSERVATION_FILES[o] for o in p["outside"]}
    for rel in sorted(rels - {"package.json"}):
        need(rel in layout, f"{rel} is no file of the layout")
        need(rel not in absent, f"{rel} stands, but the package names its observation outside its world")
    for rel, (_, optional) in layout.items():
        need(optional or rel in rels or rel in absent, f"{rel} is missing")


def load_evidence(files):
    """`files`, {relative path: bytes}, parsed and checked against the layout."""
    need("package.json" in files, "package.json is missing")
    p, names = package_of(files["package.json"])
    admit(p, set(files))
    ev = {"package": p, "package_sha256": hashlib.sha256(files["package.json"]).hexdigest(),
          "outside": set(p["outside"])}
    names["observed"] = {rel for rel in files if rel.startswith("records/") or rel in COLLECTED}
    for rel, (schema, _) in layout_of(p).items():
        if rel not in files:
            ev[rel] = None
            continue
        ev[rel] = value = parsed(files[rel], rel)
        for n, row in enumerate(value, 1) if rel.endswith(".jsonl") else [(None, value)]:
            conform(row, schema, rel if n is None else f"{rel} line {n}", names)
    check_order(ev, p)
    return ev


def check_order(ev, p):
    """Refuse what the schemas leave open: order, roles off the records, digests, marks, coverage and the stop. Set
    `ev["anchor"]` to the index of the first version of each shard, in commit order, that the roles read can have
    seen and that equals it: -1 for a shard with none."""
    roles, error = ev["injection/roles.json"], exact(p["clock_error_seconds"])
    ev["anchor"] = {}
    for s in p["shards"]:
        rows, pin = ev[f"records/{s}.jsonl"], roles["shards"][s]
        need(ordered(rows), f"records/{s}.jsonl is not in commit order")
        # `last` is the last version surely before the read; the read can also have seen one within the clock error.
        last = sum(later(roles["time"], v["time"], error) is True for v in rows) - 1
        read = [i for i, v in enumerate(rows) if (i == last or error and later(v["time"], roles["time"], error) is None)
                and all(v[k] == pin[k] for k in VERSION)]
        need(last < 0 or read, f"injection/roles.json reads shard {s} other than "
             "its last version committed before the read or one within the clock error of it")
        ev["anchor"][s] = read[0] if read else -1
    witness, stop, abort = ev["witness.jsonl"], ev["injection/stop.json"], ev["injection/abort.json"]
    restoration, stopped = ev["injection/restoration.json"], ev["injection/stopped.json"]
    if stop is not None:
        need(p["baseline"]["end"] <= stop["time"], "the baseline window ends after the stop")
        need(p["run"]["start"] <= stop["time"] < p["run"]["end"], "the run window does not hold the stop")
    need(restoration is None or (abort is None) == (restoration["reviewed_sha256"] is None), "injection/"
         "restoration.json names a reviewed record without an abort mark, or none after one")
    if restoration is not None:
        need(restoration["instance"] == (p["target"] if stop is None else stop)["instance"], "injection/restoration"
             ".json names another instance than the stop request's")
        need(restoration["state"] == "running", "injection/restoration.json reads a state other than running")
        shown = stopped if stopped and stopped["time"] < p["run"]["end"] else None
        marks = [m["time"] for m in (stop, shown, abort) if m and m.get("instance", restoration["instance"]) ==
                 restoration["instance"]]
        need(all(restoration["time"] >= t for t in marks), "injection/restoration.json precedes the stop request, "
             "the stopped report or the abort mark")
    need(ordered(witness), "witness.jsonl is not in send order")
    for n, row in enumerate(witness, 1):
        need(row["outcome"] != "hit" or row["sha256"] is not None, f"witness.jsonl line {n} is a hit with no digest "
             "(a hit needs one; another outcome may read null)")
        need(stop is None or later(row["time"], stop["time"], error) is not False, f"witness.jsonl line {n} "
             "precedes the stop")
    for rel, span in ev["coverage.json"].items():
        need(span["from"] <= span["to"] and span["lines"] == len(ev[rel]), f"coverage.json spans {rel} backwards or "
             f"counts {span['lines']} lines, not its {len(ev[rel])}")
    hosts = [row["host"] for row in ev["activations.jsonl"]]
    need(len(set(hosts)) == len(hosts), "activations.jsonl repeats a host")
    need(abort is None or (abort["cause"] == "guardrail") == (abort["guardrail"] is not None), "injection/abort.json "
         "guardrail is not a GD-2 guardrail text with cause guardrail and null otherwise")


def inside(t, span):
    return span["start"] <= t < span["end"]


def in_run(ev, rows):
    return [r for r in rows if inside(r["time"], ev["package"]["run"])]


def observed(ev):
    """`ev` with each row file cut at the end of observation, `end`: the run window's end, or the restoration's time
    less the clock error when it lies inside the run window (`restored`), since a row within the error may follow it.
    An unread takeover write or first hit lies at or after `end`; a drain ending within the error of `end` is open.
    A row's time compares with `end` as the decimal value its digits state. `short` holds the end of each
    collection that ends before `end`. `cut` tells a restoration inside the run window; `restored` tells it too,
    until `graded` sets `restored` for a rule that reads a short collection."""
    p, mark, error = ev["package"], ev["injection/restoration.json"], exact(ev["package"]["clock_error_seconds"])
    back = mark["time"] if mark is not None and inside(mark["time"], p["run"]) else None
    end = p["run"]["end"] if back is None else exact(back) - error if error else back
    limit, near = exact(end), float(end)
    cut = {rel: [r for r in rows if r["time"] < near or r["time"] == near and exact(r["time"]) < limit]
           for rel, rows in ev.items() if rel.endswith(".jsonl") and rows is not None and rel != "activations.jsonl"}
    cut["activations.jsonl"] = [{**r, "activations": [a for a in r["activations"] if a["time"] < near
                                                      or a["time"] == near and exact(a["time"]) < limit]}
                                for r in ev["activations.jsonl"]]
    short = {rel: c["to"] for rel, c in ev["coverage.json"].items() if exact(c["to"]) < limit}
    return {**ev, **cut, "end": end, "restored": back is not None, "cut": back is not None, "short": short}


def history(ev, facts, s):
    """(the versions of shard `s` its rules may read from, in commit order; the versions surely after them, before the
    end of observation). After a roles read before the stop the reference is the version of `roles.json` and the
    later versions are those committed after the one the read names (`ev["anchor"]`), so commit order decides for a
    version stamped within the clock error of the read. After a read at or after the stop the reference is the last
    version before the stop, which may be the last version surely before it or any version within the clock error
    of it: with candidates `refs`, each place of the stop gives (refs[i], refs[i + 1:] + the later versions). A
    shard with no version before the stop reads from its first version."""
    roles, rows, stop = ev["injection/roles.json"], ev[f"records/{s}.jsonl"], facts["stop"]
    if stop is None or roles["time"] < stop:
        return [roles["shards"][s]], rows[ev["anchor"][s] + 1:]
    sides = [later(v["time"], stop, facts["error"]) for v in rows]
    first = max(sides.count(False) - 1, 0)
    after = max(len(rows) - sides.count(True), first + 1)
    return (rows[first:after], rows[after:]) if rows else ([roles["shards"][s]], [])


def placed(facts, finding):
    """(sure, unsure) findings of `finding(s, reference, later versions)` over every shard, for a rule whose findings
    on a shard never grow as its reference moves later: `sure` holds at every place of the stop among the versions
    within the clock error of it, `unsure` only where the stop precedes them."""
    sure, unsure = [], []
    for s, (refs, after) in facts["history"].items():
        last = finding(s, refs[-1], after)
        sure += last
        if not last and len(refs) > 1:
            unsure += [f"{d}, if the stop precedes each version of {s} within the clock error of it"
                       for d in finding(s, refs[0], refs[1:] + after)]
    return sure, unsure


def later(t, mark, error):
    """Whether stamp `t` is at or after `mark` of another writer; None when within the clock error `error`."""
    if not error:
        return t >= mark
    gap = exact(t) - exact(mark)
    return None if abs(gap) <= error else gap > 0


def found_or_held(found, held, met=False, unknown=()):
    """A rule's (result, detail, guardrail met): disproven on a finding, unobserved on an unknown, else held."""
    if found:
        return "disproven", found, met
    return ("unobserved", list(unknown), False) if unknown else ("held", [held], False)


def takeover_write(ev, s):
    """The versions of `s` in commit order from its first after the roles read naming another owner, or none."""
    rows, after, target = ev[f"records/{s}.jsonl"], ev["injection/roles.json"]["time"], ev["package"]["target"]["host"]
    return rows[next((i for i, v in enumerate(rows) if after < v["time"] and v["owner"] != target), len(rows)):]


def takeover(ev, facts):
    wrong = []
    for s in facts["owned"]:
        before = ev["injection/roles.json"]["shards"][s]
        pinned, rows = (before["generation"], before["volume"]), ev[f"records/{s}.jsonl"]
        last = rows[-1] if rows else None
        if not ev["restored"] and (last is None or (last["owner"], last["generation"], last["volume"]) != (
                before["standby"], *pinned)):
            wrong.append(f"{s} ends the run window as {last}, not owned by {before['standby']} at generation "
                         f"{before['generation']} and volume {before['volume']}")
        wrong += [f"{s} names generation {v['generation']} and volume {v['volume']} at {v['time']}, from its takeover "
                  f"write on, not {before['generation']} and {before['volume']}"
                  for v in facts["write"][s] if (v["generation"], v["volume"]) != pinned]
    return found_or_held(wrong, f"each owned shard {facts['owned']} is taken over and ends owned by its standby at its "
                         "generation and volume")


def others_keep_owner(ev, facts):
    """A shard changes owner at every place of the stop when a later version names another owner than its last
    candidate reference; the rule reads it when no candidate names the target owner, and its guardrail is met when
    none names the target standby either. Two candidates stand only under an unmet reach, which reads the guardrail
    alone."""
    changed, target = [], facts["target"]
    for s, (refs, after) in facts["history"].items():
        if all(r["owner"] != target for r in refs):
            changed += [(all(r["standby"] != target for r in refs), f"{s} names owner {v['owner']} at {v['time']}, "
                         f"not {refs[-1]['owner']}") for v in after if v["owner"] != refs[-1]["owner"]]
    return found_or_held([d for _, d in changed], "every shard the target did not own keeps its owner",
                         any(roleless for roleless, _ in changed))


def no_volume_created(ev, facts):
    principal = ev["package"]["reconciler_principal"]
    rows = in_run(ev, ev["provider.jsonl"])
    called = [f"CreateVolume by {principal} at {r['time']}" for r in rows if r.get("principal") == principal]
    found = [f"volume {r['volume']} created at {r['time']}" for r in rows if r["event"] == "volume"] + called
    return found_or_held(found, "the provider lists no volume created and no CreateVolume by the reconciler principal "
                         "in the run window", bool(called))


def no_generation_change(ev, facts):
    found, unsure = placed(facts, lambda s, base, later: [
        f"{s} reads generation {v['generation']} at {v['time']}, not {base['generation']}" for v in later
        if v["generation"] != base["generation"]])
    return found_or_held(found, "no shard's generation changes after its reference version", True, unsure)


def one_owner_per_tenure(ev, facts):
    """One owner per (generation, attempts); each activation made once, by that owner, at epoch 2 x attempts. A
    conflict counts when one of its observations follows the reference version `history` reads from. It is undecided
    when its only activations after the reference lie within the clock error of it. An activation with no owning
    version is undecided when it lies at or after the end of the collections read, or when its shard's versions are
    not read to the run window's end, where the owning version may stand."""
    end, roles, owners, made, scored = ev["package"]["run"]["end"], ev["injection/roles.json"], {}, {}, {}
    for s, pinned in roles["shards"].items():
        refs, after = facts["history"][s]
        # A tenure follows the reference surely when a version surely after it holds it.
        scored.update({(s, v["generation"], v["attempts"]): False for v in refs[1:]})
        scored.update({(s, v["generation"], v["attempts"]): True for v in after})
        for v in [pinned] * (roles["time"] < end) + ev[f"records/{s}.jsonl"]:
            owners.setdefault((s, v["generation"], v["attempts"]), set()).add(v["owner"])
    found, unsure = [], []
    for (s, g, a), o in sorted(owners.items()):
        if len(o) > 1 and (s, g, a) in scored:
            (found if scored[(s, g, a)] else unsure).append(f"{s} names owners {sorted(o)} at generation {g} attempts "
                                                            f"{a}")
    for row in ev["activations.jsonl"]:
        for a in row["activations"]:
            epoch, now = a["attempt"], facts["after_ref"](a["time"])
            made.setdefault((a["shard"], a["generation"], epoch), []).append((row["host"], now))
            if now is False:
                continue
            if epoch < 2 or epoch % 2:
                (found if now else unsure).append(f"{row['host']} activates {a['shard']} at generation "
                                                  f"{a['generation']} with epoch {epoch}, which no attempt counter "
                                                  "doubles to")
            elif row["host"] not in owners.get((a["shard"], a["generation"], epoch // 2), ()):
                read = not ev["cut"] and f"records/{a['shard']}.jsonl" not in ev["short"]
                (found if now and read and a["time"] < ev["end"] else unsure).append(
                    f"{row['host']} activates {a['shard']} at generation {a['generation']} epoch {epoch}, but no "
                    f"version names it owner at attempts {epoch // 2}")
    counted = {t: {h for h, _ in m} for t, m in made.items() if any(now for _, now in m)}
    found += [f"{s} is activated {len(made[(s, g, a)])} times at generation {g} epoch {a}, by {sorted(h)}"
              for (s, g, a), h in sorted(counted.items()) if len(made[(s, g, a)]) > 1]
    unsure += [f"{s} is activated {len(m)} times at generation {g} epoch {a}" for (s, g, a), m in sorted(made.items())
               if len(m) > 1 and (s, g, a) not in counted and any(now is None for _, now in m)]
    lines = {row["host"] for row in ev["activations.jsonl"]}
    missing = [f"host {h} has no activation records" for h in ev["package"]["hosts"] if h not in lines]
    return found_or_held(found, "each tenure has one owner, and each activation is made once by its owner at twice "
                         "its attempt counter", any(len(h) > 1 for h in counted.values()),
                         missing + [f"{u}: within the clock error of the reference or past the versions read"
                                    for u in unsure])


def in_drain(sure, write, stop, limit, error, versions, blockers):
    """Whether an enrollment or a blocker lies inside the drain of length `limit`, surely or possibly. The drain
    starts at the later of the takeover write `write` (none for a stood-by shard) and the stop. A version shares the
    write's clock: it is inside from the write on, once past the stop, up to `limit` from the write or from the
    stop. A blocker is another writer's against both ends. Every time is the decimal value its digits state."""
    ok, stop = (lambda side: side is True) if sure else (lambda side: side is not False), exact(stop)
    start = stop if write is None else max(write, stop)
    return any((write is None or t >= write) and ok(later(t, stop, error))
               and (write is not None and t <= write + limit or ok(later(stop + limit, t, error)))
               for t in versions) or any(ok(later(t, start, error)) and ok(later(start + limit, t, error))
                                         for t in blockers)


def standby_again(ev, facts):
    bound, stop, run_end, target = facts["bounds"]["re-enrollment-drain"], facts["stop"], ev["end"], facts["target"]
    if bound is None:
        return "unobserved", ["the re-enrollment drain has neither a catalog value nor a working value"], False
    late, unknown, error, limit = [], [], facts["error"], exact(bound)
    for s in facts["owned"] + facts["stood"]:
        tail = facts["write"].get(s)
        if tail == []:
            unknown.append(f"owned shard {s} has no takeover write in the run window, so its drain does not start")
            continue
        write = None if tail is None else exact(tail[0]["time"])
        start = exact(stop) if write is None else max(write, exact(stop))
        marks = ([exact(v["time"]) for v in (ev[f"records/{s}.jsonl"] if tail is None else tail)
                  if v["standby"] not in (None, target, v["owner"])],
                 [exact(b["time"]) for b in ev["blockers.jsonl"] if b["shard"] == s])
        if in_drain(True, write, stop, limit, error, *marks):
            continue
        if in_drain(False, write, stop, limit, error, *marks) or \
                start + limit + error * ev["restored"] >= exact(run_end):
            unknown.append(f"{s} names no enrolled standby and no blocker surely inside [{shown(start)}, "
                           f"{shown(start + limit)}], observation ending at {shown(exact(run_end))}")
        else:
            late.append(f"{s} names no enrolled standby and no blocker in [{shown(start)}, {shown(start + limit)}]")
    return found_or_held(late, f"each shard the target owned or stood by for has an enrolled standby or a blocker "
                         f"within {bound} s", True, unknown)


def origin_load(ev, facts):
    """Clause 5 from the stop on: each interval's rate less the baseline's, compared exactly. The part of the stop's
    interval after the stop joins the next interval, unless the stop's interval is the last. A request within the
    clock error of the stop counts as unsure in the first graded interval at the earliest."""
    bound, p = facts["bounds"]["origin-load"], ev["package"]
    if bound is None:
        return "unobserved", ["the origin-load budget has neither a catalog value nor a working value"], False
    base, run = p["baseline"], p["run"]
    step, start, end = exact(p["interval"]), exact(run["start"]), exact(run["end"])
    since = start if facts["stop"] is None else max(start, exact(facts["stop"]))
    cut = int((since - start) // step)
    fold = since > start + cut * step and start + (cut + 1) * step < end
    base_n = sum(inside(r["time"], base) for r in ev["origin.jsonl"])
    base_len, limit = exact(base["end"]) - exact(base["start"]), exact(bound)
    counts, unsure = {}, {}
    for r in ev["origin.jsonl"]:
        side = True if facts["stop"] is None else later(r["time"], facts["stop"], facts["error"])
        if side is not False and ((t := exact(r["time"])) >= start or side is None):
            i = max(int((t - start) // step), cut + fold)
            (counts if side else unsure)[i] = (counts if side else unsure).get(i, 0) + 1
    over, maybe = [], []
    for i in sorted(set(counts) | set(unsure)):
        lo, hi, n = since if fold and i == cut + 1 else max(start + i * step, since), start + (i + 1) * step, \
            counts.get(i, 0)
        more = f", {unsure[i]} more within the clock error of the stop," if unsure.get(i) else ""
        text = (f"[{shown(lo)}, {shown(hi)}) holds {n} origin requests in {shown(hi - lo)} s{more} against the "
                f"baseline's {base_n} in {shown(base_len)} s")
        for k, into in ((n, over), (n + unsure.get(i, 0), maybe)):
            if (k / (hi - lo) - fractions.Fraction(base_n) / base_len > limit if hi > lo else k > 0):
                into.append(text)
                break
    return found_or_held(over, f"each interval from {shown(since)} stays within {bound} requests/s above the "
                         f"baseline's {base_n} requests in {shown(base_len)} s", True, maybe)


def unhit(ev, facts):
    """The requested keys with no first hit before an end of observation earlier than the run window's, as unknowns."""
    return [f"{w['key']} is requested and never hit before the end of observation" for w in ev["package"]["witness"]
            if ev["restored"] and w["key"] in facts["requested"] and w["key"] not in facts["first_hit"]]


def witness_first_hit(ev, facts):
    wrong, unsure, roles, first = [], [], ev["injection/roles.json"]["shards"], facts["first_hit"]
    for w in ev["package"]["witness"]:
        if w["key"] not in facts["requested"]:
            continue
        hit, host, tail = first.get(w["key"]), roles[w["shard"]]["standby"], facts["write"][w["shard"]]
        write = tail[0]["time"] if tail else ev["end"] if ev["restored"] else None
        if hit is None:
            wrong += [] if ev["restored"] else [f"{w['key']} is requested and never hit before the end of observation"]
        elif (hit["host"], hit["sha256"]) != (host, w["sha256"]):
            wrong.append(f"{w['key']} is first hit at {hit['time']} on {hit['host']} with {hit['sha256']}, not on "
                         f"{host} with {w['sha256']}")
        elif write is None or later(hit["time"], write, facts["error"]) is False:
            wrong.append(f"{w['key']} is first hit at {hit['time']}, before its shard's takeover write")
        elif later(hit["time"], write, facts["error"]) is None:
            unsure.append(f"{w['key']} is first hit within the clock error of its shard's takeover write")
    return found_or_held(wrong, "each witness key is first hit on its successor with its pinned digest",
                         unknown=facts["never"] + unhit(ev, facts) + unsure)


def no_origin_before_hit(ev, facts):
    error, early, unsure = facts["error"], [], []
    for r in ev["origin.jsonl"]:
        if r["key"] in facts["requested"]:
            hit = facts["first_hit"].get(r["key"])
            mark = hit["time"] if hit else ev["end"] if ev["restored"] else None
            after = later(r["time"], facts["stop"], error)
            before = True if mark is None else (None if (x := later(r["time"], mark, error)) is None else not x)
            if after and before:
                early.append(f"{r['key']} is requested from the origin at {r['time']}, before its first hit")
            elif after is not False and before is not False:
                unsure.append(f"{r['key']} is requested from the origin at {r['time']}, within the clock error of "
                              "the stop or its first hit")
    return found_or_held(early, "no witness key is requested from the origin between the stop and its first hit",
                         unknown=facts["never"] + unhit(ev, facts) + unsure)


def no_replacement_receipt(ev, facts):
    principal = ev["package"]["reconciler_principal"]
    return found_or_held([f"a replacement receipt of {r['shard']} by {principal} at {r['time']}"
                          for r in in_run(ev, ev["records/receipts.jsonl"]) if r["principal"] == principal],
                         "no replacement receipt by the reconciler principal in the run window", True)


def changes_hands_once(ev, facts):
    def twice(s, base, later):
        owners = [base["owner"]] + [v["owner"] for v in later]
        changes = sum(owners[i] != owners[i + 1] for i in range(len(owners) - 1))
        return [f"{s} changes hands {changes} times"] if changes > 1 else []

    found, unsure = placed(facts, twice)
    return found_or_held(found, "no shard changes hands more than once in the versions the rules read", True, unsure)


# Each rule's GD-2 text (clause or guardrail by index, or the witness sentence), evaluator, collected files ("records":
# each shard's), guardrail index, observation a simulated world may lack, safety, its guardrail read under an unmet
# reach ("any", "shown" when the stop is shown, or None), and whether its window can close before the run window's end.
Rule = namedtuple("Rule", "text evaluate reads guardrail needs safety unmet closes",
                  defaults=(None, None, False, None, False))
RECORDS = ("records",)
RULES = {
    "takeover": Rule(("clause", 0), takeover, RECORDS),
    "others-keep-owner": Rule(("clause", 1), others_keep_owner, RECORDS, guardrail=3, unmet="any"),
    "no-volume-created": Rule(("clause", 2), no_volume_created, ("provider.jsonl",), guardrail=1, needs="provider",
                              safety=True),
    "no-generation-change": Rule(("clause", 2), no_generation_change, RECORDS, guardrail=0, safety=True),
    "one-owner-per-tenure": Rule(("clause", 2), one_owner_per_tenure, RECORDS + ("activations.jsonl",), guardrail=7,
                                 safety=True),
    "standby-again": Rule(("clause", 3), standby_again, RECORDS + ("blockers.jsonl",), guardrail=6,
                          needs="re-enrollment", unmet="shown", closes=True),
    "origin-load": Rule(("clause", 4), origin_load, ("origin.jsonl",), guardrail=5, needs="origin", unmet="any"),
    "witness-first-hit": Rule(("witness", None), witness_first_hit, RECORDS + ("witness.jsonl",), closes=True),
    "no-origin-before-hit": Rule(("witness", None), no_origin_before_hit, ("witness.jsonl", "origin.jsonl"),
                                 needs="origin", closes=True),
    "no-replacement-receipt": Rule(("guardrail", 2), no_replacement_receipt, ("records/receipts.jsonl",),
                                   guardrail=2, safety=True),
    "changes-hands-once": Rule(("guardrail", 4), changes_hands_once, RECORDS, guardrail=4, safety=True),
}
BUDGETS = [b for _, b in WRITTEN["clauses"] if b is not None]


def rule_text(gd2, rule):
    kind, i = RULES[rule].text
    return WITNESS if kind == "witness" else gd2["hypothesis"][i]["clause"] if kind == "clause" else gd2["guardrail"][i]


def gd2_entry(catalog):
    """GD-2 of the parsed catalog, refused unless its mode and texts are WRITTEN's."""
    need(isinstance(catalog, dict) and isinstance(catalog.get("entries"), list)
         and isinstance(catalog.get("budgets"), dict) and isinstance(catalog.get("run_rule"), str),
         "the game-day catalog holds no entries, budgets and run rule")
    found = [e for e in catalog["entries"] if isinstance(e, dict) and e.get("id") == PACKAGE]
    need(len(found) == 1, f"the game-day catalog holds {len(found)} entries {PACKAGE}, not one")
    gd2, written = found[0], "the texts the judge's rules were written from"
    need(gd2.get("mode") == "causal", f"{PACKAGE} is not a causal package")
    clauses = gd2.get("hypothesis")
    need(isinstance(clauses, list) and all(isinstance(h, dict) and "bound" in h for h in clauses)
         and [(h.get("clause"), h.get("bound")) for h in clauses] == WRITTEN["clauses"],
         f"{PACKAGE}'s hypothesis clauses or their bounds differ from {written}")
    need(gd2.get("guardrail") == WRITTEN["guardrails"], f"{PACKAGE}'s guardrails differ from {written}")
    for key in ("reach", "expected"):
        text = gd2["oracle"].get(key) if isinstance(gd2.get("oracle"), dict) else None
        need(isinstance(text, str) and encodable(text) and hashlib.sha256(text.encode()).hexdigest() == WRITTEN[key]
             and (key == "reach" or WITNESS in text), f"{PACKAGE}'s oracle.{key} differs from {written}")
    return gd2


def bounds(catalog, p):
    """{budget: {value, source}}: the catalog's value, else the package's working value, else none."""
    used = {}
    for budget in BUDGETS:
        entry = catalog["budgets"].get(budget)
        need(isinstance(entry, dict) and "value" in entry
             and (entry["value"] is None or SCALARS["positive"](entry["value"], {})),
             f"the catalog holds no budget {budget} with a null or positive value")
        working = p["working_budgets"].get(budget)
        used[budget] = {"value": entry["value"], "source": "catalog"} if entry["value"] is not None else \
            {"value": working, "source": None if working is None else "package"}
    return used


def roles_reach(roles, p):
    """The reach's pre-stop conditions unmet, from the roles mark and the package alone (the controller's check)."""
    unmet, target, instance = [], p["target"]["host"], p["target"]["instance"]
    owned = [s for s in p["shards"] if roles["shards"][s]["owner"] == target]
    stood = [s for s in p["shards"] if roles["shards"][s]["standby"] == target]
    if len(owned) < MIN_OWNED:
        unmet.append(f"the target owns {len(owned)} shards, fewer than {MIN_OWNED}")
    if len(stood) < MIN_STOOD:
        unmet.append(f"the target stands by for {len(stood)} shards, fewer than {MIN_STOOD}")
    for s in owned:
        standby = roles["shards"][s]["standby"]
        state = roles["standbys"].get(standby)
        if standby in (None, target):
            unmet.append(f"owned shard {s} names no standby other than the target")
        elif state is None:
            unmet.append(f"standby host {standby} of {s} has no instance state and host report read before the stop")
        elif state["instance"] == instance:
            unmet.append(f"standby host {standby} of {s} reports the target's instance {instance}")
        elif (state["instance_state"], state["host_report"]) != ("running", "healthy"):
            unmet.append(f"standby host {standby} of {s} reads {state['instance_state']} and {state['host_report']}")
    return unmet


def reach(ev, facts):
    """(the reach oracle's unmet conditions, empty when it is met; whether the stop is shown)."""
    roles, p = ev["injection/roles.json"], ev["package"]
    unmet, instance, error = roles_reach(roles, p), p["target"]["instance"], exact(p["clock_error_seconds"])
    stop, stopped, unshown = ev["injection/stop.json"], ev["injection/stopped.json"], []
    if stop is None or stop["instance"] != instance:
        unshown.append(f"no stop request of the target's instance {instance} stands in injection/stop.json")
    elif roles["time"] >= stop["time"]:
        unshown.append("the roles were read at or after the stop")
    elif roles["time"] < p["baseline"]["start"]:
        unshown.append("the baseline and run windows leave part of the span from the roles read to the stop unobserved")
    else:
        unshown += [f"the collection of records/{s}.jsonl spans [{c['from']}, {c['to']}], short of the span from the "
                    "roles read to the stop" for s in p["shards"]
                    if (c := ev["coverage.json"][f"records/{s}.jsonl"])["from"] > roles["time"]
                    or c["to"] < stop["time"]]
        unshown += [f"shard {s} names owner {v['owner']} and standby {v['standby']} at {v['time']}, between the roles "
                    "read and the stop or within the clock error of either" for s in p["shards"]
                    for v in ev[f"records/{s}.jsonl"]
                    if later(roles["time"], v["time"], error) is not True
                    and later(v["time"], stop["time"], error) is not True
                    and (v["owner"], v["standby"]) != (roles["shards"][s]["owner"], roles["shards"][s]["standby"])]
    if stopped is None or (stopped["instance"], stopped["state"]) != (instance, "stopped"):
        unshown.append(f"injection/stopped.json shows no report of instance {instance} stopped")
    elif stop is None or (stopped["request"]["instance"], stopped["request"]["identity"]) != (
            stop["instance"], stop["identity"]) or abs(exact(stopped["request"]["time"]) - exact(stop["time"])) > error:
        unshown.append("the control plane's record of the stop request names another instance or identity than "
                       "injection/stop.json, or a time beyond the clock error of its")
    elif not stop["time"] <= stopped["time"] < p["run"]["end"]:
        unshown.append(f"the report of the instance stopped was read at {stopped['time']}, outside [the stop, the run "
                       "window's end)")
    return unmet + unshown, not unshown


def verdict_of(rules, unmet, abort):
    """`run_status` and `verdict` by the first row of the verdict table that applies."""
    words = {r["result"] for r in rules.values()}
    if unmet:
        kept = any(rules[name]["result"] == "disproven" for name, rule in RULES.items() if rule.safety)
        return ("HALTED", "DISPROVEN") if kept else ("FAILED_TO_INJECT", "INCONCLUSIVE")
    status = "COMPLETED" if abort is None else "HALTED"
    if "disproven" in words:
        return status, "DISPROVEN"
    return status, "INCONCLUSIVE" if "unobserved" in words or abort is not None else "HELD"


def graded(ev, facts, rule, unmet):
    """(result, detail, whether the guardrail is met) of `rule`: outside, unobserved under an unmet reach, or judged.
    A rule that reads a collection ending before the end of observation is judged as if observation ended at the
    earliest such end."""
    if rule.needs in ev["outside"]:
        return "outside", [f"the package names {rule.needs} outside its world: "
                           f"{ev['package']['outside'][rule.needs]}"], False
    if not unmet or rule.safety:
        p, end = ev["package"], ev["end"]
        both = rule.evaluate is one_owner_per_tenure
        start = p["baseline" if both or rule.evaluate is origin_load else "run"]["start"]
        since = min(start, ev["injection/roles.json"]["time"])
        rels = [(f, since if both or n == "records" else start) for n in rule.reads
                for f in ([f"records/{s}.jsonl" for s in p["shards"]] if n == "records" else [n])]
        gaps = [f"the collection of {f} spans [{c['from']}, {c['to']}], short of [{lo}, {shown(exact(end))})"
                for f, lo in rels if (c := ev["coverage.json"][f])["from"] > lo or f in ev["short"]] + [
            f"observation ends on the restoration at {shown(exact(end))}"] * (ev["restored"] and not rule.closes)
        ends = [ev["short"][f] for f, _ in rels if f in ev["short"]]
        word, detail, met = rule.evaluate({**ev, "end": min(ends), "restored": True} if ends else ev, facts)
        return (word, detail, met) if word == "disproven" or not gaps else ("unobserved", gaps, False)
    reads = rule.unmet == "any" or rule.unmet == "shown" and facts["shown"]
    _, found, met = rule.evaluate(ev, facts) if reads else (None, [], False)
    return "unobserved", ["the reach oracle is unmet, so the phase grades none of its clauses",
                          *(found if met else [])], met


def judge(ev, catalog, fis, readiness):
    """The run record of parsed evidence `ev` under `catalog` and the profiles `fis`; Refusal for exit 2."""
    gd2, p, roles, abort = gd2_entry(catalog), ev["package"], ev["injection/roles.json"], ev["injection/abort.json"]
    need(roles["package_sha256"] == ev["package_sha256"], "package.json differs from the digest in "
         "injection/roles.json")
    target, stop = p["target"]["host"], ev["injection/stop.json"]
    owned = [s for s in p["shards"] if roles["shards"][s]["owner"] == target]
    keyed = {w["shard"] for w in p["witness"]}
    stopped, error, seen = ev["injection/stopped.json"], exact(p["clock_error_seconds"]), observed(ev)
    effect = stopped["time"] if stopped and (stopped["instance"], stopped["state"]) == (p["target"]["instance"],
                                                                                          "stopped") else None
    budgets, first, rows = bounds(catalog, p), {}, in_run(seen, seen["witness.jsonl"])
    side = {id(r): True if effect is None else later(r["time"], effect, error) for r in rows}
    asked = [r for r in rows if side[id(r)]]
    surely = {r["key"] for r in asked}
    # A GET within the clock error of the stop leaves its key undecided when it is a hit, which may be the first hit
    # after the stop, or when no GET surely after the stop shows the key requested.
    blurred = {r["key"] for r in rows if side[id(r)] is None and (r["outcome"] == "hit" or r["key"] not in surely)}
    for r in (r for r in asked if r["outcome"] == "hit"):
        first.setdefault(r["key"], r)
    requested = surely - blurred
    facts = {"target": target, "owned": owned, "stop": effect, "error": error,
             "stood": [s for s in p["shards"] if roles["shards"][s]["standby"] == target],
             "requested": requested, "first_hit": first, "bounds": {b: v["value"] for b, v in budgets.items()},
             "never": [f"witness key {w['key']} is never requested" for w in p["witness"] if w["key"] not in requested
                       and w["key"] not in blurred] + [f"witness key {k} has a hit, or its only GETs, within the "
                                                       "clock error of the stop" for k in sorted(blurred)],
             "write": {s: takeover_write(seen, s) for s in owned},
             "after_ref": (lambda t: later(t, roles["time"], error) and t > roles["time"]) if effect is None
             or roles["time"] < effect else (lambda t: later(t, effect, error))}
    facts["history"] = {s: history(seen, facts, s) for s in p["shards"]}
    held = [s for s in p["shards"] if all(r["owner"] == target for r in facts["history"][s][0]) and s not in keyed]
    need(not held, f"owned shards {held} have no witness key")
    unmet, facts["shown"] = reach(ev, facts)
    need(unmet or keyed <= set(owned), f"witness keys name shards {sorted(keyed - set(owned))} the target did not own")
    rules = {}
    for name, rule in RULES.items():
        word, detail, met = graded(seen, facts, rule, unmet)
        guardrail = gd2["guardrail"][rule.guardrail] if met else None
        stopped_for = abort is not None and abort["cause"] == "guardrail" and abort["guardrail"] == guardrail
        rules[name] = {"result": word, "text": rule_text(gd2, name), "guardrail": guardrail,
                       "past_stop_condition": guardrail is not None and not stopped_for, "detail": detail}
    status, verdict = verdict_of(rules, unmet, abort)
    early = abort is not None and stop is not None and abort["time"] < stop["time"]
    try:
        digest = readiness.package_digest(gd2, catalog["run_rule"], catalog["budgets"], fis)
    except (KeyError, TypeError, AttributeError) as error:
        raise Refusal(f"the catalog or the fault-injection profiles lack a field the package digest reads: "
                      f"{type(error).__name__} {error}") from error
    return {"id": PACKAGE, "mode": KINDS[p["kind"]], "kind": p["kind"], "revision": p["revision"], "date": p["date"],
            "run_status": status, "verdict": verdict, "package_sha256": ev["package_sha256"],
            "catalog_sha256": digest, "reach": {"met": not unmet, "detail": unmet},
            "abort": None if abort is None else {"cause": abort["cause"], "guardrail": abort["guardrail"],
                                                 "before_stop": early},
            "rules": rules, "budgets": budgets,
            "result": summary(rules, p["kind"]) + ("; the abort mark precedes the stop request" if early else "")}


def summary(rules, kind):
    named = {w: [r for r, v in rules.items() if v["result"] == w] for w in ("held", "disproven", "unobserved",
                                                                              "outside")}
    line = f"held on {len(named['held'])} rules" + (f", {len(named['outside'])} outside its world"
                                                    if kind == "simulation" else "")
    for word in ("disproven", "unobserved"):
        if named[word]:
            line += f"; {word}: " + ", ".join(f"{r} (guardrail \"{rules[r]['guardrail']}\"" + (
                ", past its stop condition" if rules[r]["past_stop_condition"] else "") + ")" if rules[r]["guardrail"]
                else r for r in named[word])
    return line


def encode(record):
    return (json.dumps(record, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode()


def check_target(evidence, record):
    """(a descriptor of the record's directory, opened as the kernel resolves the path given, the record's name),
    refused when an entry stands at that name or the opened directory lies inside the evidence directory."""
    name = os.path.basename(record)
    need(name not in ("", os.curdir, os.pardir), f"{record} names no file")
    try:
        dirfd = os.open(os.path.dirname(record) or os.curdir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError as error:
        raise Refusal(f"the directory of {record} cannot be opened: {error.strerror}") from error
    try:
        parent, root = os.readlink(f"/proc/self/fd/{dirfd}"), os.path.realpath(evidence)
        need(os.path.commonpath([root, parent]) != root, f"{record} lies inside the evidence directory")
        with contextlib.suppress(FileNotFoundError):
            os.stat(name, dir_fd=dirfd, follow_symlinks=False)
            raise Refusal(f"{record} exists: the judge writes a new file and replaces none")
    except BaseException:
        os.close(dirfd)
        raise
    return dirfd, name


def write_record(dirfd, name, record, data):
    """Write `data` to a new file in the directory open at `dirfd`, sync it, link it as `name` and sync the directory;
    when that sync fails, remove it and sync again. Every entry is named relative to `dirfd`."""
    temporary = f".{name}.{os.urandom(8).hex()}"
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o666,
                     dir_fd=dirfd)
    except OSError as error:
        raise Refusal(f"no file can be made beside {record}: {error.strerror}") from error
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, name, src_dir_fd=dirfd, dst_dir_fd=dirfd)
    except FileExistsError as error:
        raise Refusal(f"{record} appeared while the judge wrote it; it is left as it stands") from error
    except OSError as error:
        raise Refusal(f"the record cannot be written: {error.strerror}") from error
    finally:
        with contextlib.suppress(OSError):
            os.unlink(temporary, dir_fd=dirfd)
    try:
        os.fsync(dirfd)
    except OSError as error:
        try:
            os.unlink(name, dir_fd=dirfd)
            os.fsync(dirfd)
        except OSError as second:
            raise Refusal(f"{record} may stand: its directory cannot be synced ({error.strerror}) and its removal "
                          f"is not known to be durable ({second.strerror}), so it is no judged record",
                          written=True) from error
        raise Refusal(f"the record's directory cannot be synced, so the record is removed: {error.strerror}") \
            from error


def run(evidence, record, catalog, fis, readiness):
    """Judge `evidence` under `catalog` and write the record: 0 for HELD, 1 for any other record. Raises Refusal."""
    dirfd, name = check_target(evidence, record)
    try:
        result = judge(read_evidence(evidence), catalog, fis, readiness)
        write_record(dirfd, name, record, encode(result))
    finally:
        with contextlib.suppress(OSError):
            os.close(dirfd)
    return 0 if result["verdict"] == "HELD" else 1


def report(text):
    """Write `text` to standard error; a stream that fails is dropped, so the exit code stays the caller's."""
    try:
        print(f"gameday-judge: {text}", file=sys.stderr, flush=True)
    except (OSError, ValueError):
        sys.stderr = None


def main(argv=None):
    parser = argparse.ArgumentParser(description="Judge one run of GD-2 from its evidence directory.")
    parser.add_argument("--evidence", required=True, help="the evidence directory")
    parser.add_argument("--record", required=True, help="the run record to create")
    args = parser.parse_args(argv)
    try:
        # The catalog and the profiles are parsed as `readiness.py` parses them, so both read the same values.
        readiness = load_readiness()
        catalog, fis = (readiness.parse(read_bytes(path, what), what) for path, what in (
            (CATALOG, "the game-day catalog"), (PROFILES, "the fault-injection profiles")))
        return run(args.evidence, args.record, catalog, fis, readiness)
    except Refusal as error:
        report(f"{error}{'' if error.written else '; no record written'}")
    except Exception as error:
        # An unforeseen failure writes no record, so it exits 2 and never reads as a judged record's exit 1.
        report(f"{type(error).__name__}: {error}; no record written")
    return 2


if __name__ == "__main__":
    sys.exit(main())
