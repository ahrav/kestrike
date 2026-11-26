#!/usr/bin/env python3
"""Validate a chaos campaign contract and render its readiness claim.

    validate_contract.py chaos/ledger.json [--root DIR] [--project chaos/project.yaml]
        [--receipts DIR] [--build ID] [--freeze-commit FULL-ID | --frozen FILE]
        [--claim | --check-claim FILE]

Prints one finding per line as `<row>: <code>: <detail>` and exits 1, or prints nothing and
exits 0. Exit 2 means an input was unreadable or a flag is missing its companion. `--claim`
validates first and prints READINESS.md only for a valid contract. With `--claim` the findings
go to standard error, so a redirected claim file never holds them.

The script reads files and git objects. It runs no judge and contacts no service. It checks
that receipts agree with each other, with the ledger, with the evidence under runs/ and with
the tree. It sees what is on disk: a run whose evidence and receipts were both removed leaves
no trace here, and it cannot tell who wrote a receipt. Whoever runs the harness is part of the
trusted base, and a campaign that must count every run keeps its runs where the loop cannot
write.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import NoReturn

ID = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
CHUNK = 1 << 20
KINDS = ("history", "threshold", "recovery", "state")
STATUSES = ("open", "held", "broken", "fixed")
CONTROLS = ("seeded-defect", "seeded-evidence")
SOURCES = ("owner", "incident", "survey")
REASONS = ("hypothesis", "no-control", "no-oracle", "out-of-envelope", "owner-declined")
PROJECT_LISTS = {
    "scope": "no-scope", "differs_from_production": "no-differences", "tools": "no-tools",
    "telemetry": "no-telemetry", "budgets": "no-budgets", "trusted_base": "no-trusted-base",
    "frozen_paths": "no-frozen-paths",
}
FIELDS = {
    "top": {"schema", "system", "fences", "invariants", "scenarios", "excluded"},
    "fence": {"id", "text", "enforced_by", "probe"},
    "probe": {"command", "expect", "identity"},
    "invariant": {"id", "property", "kind", "judge", "threshold", "oracle", "witness", "control"},
    "property": {"text", "agreed", "source"},
    "source": {"kind", "ref"},
    "control": {"kind", "how", "scenario", "expect", "defect"},
    "scenario": {"id", "text", "source", "load", "fault", "injection_oracle", "reach", "load_delivery",
                 "restoration", "stop_conditions", "deadline_s", "judge", "invariants", "runs_required",
                 "status", "parent"},
    "excluded": {"property", "reason", "detail"},
}
TEXT_KEYS = {"witness": {"check", "expect"}, "threshold": {"measured"}, "load": {"reference"},
             "fault": {"kind", "target"}, "reach": {"text"}, "load_delivery": set()}
DERIVED_OWN = {"id", "parent", "text", "source", "status", "judge", "fault", "invariants"}


def fatal(message: str) -> NoReturn:
    print(f"validate_contract: {message}", file=sys.stderr)
    raise SystemExit(2)


def text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def number(value: object) -> bool:
    """True for a finite number. An integer of any size is finite."""
    if isinstance(value, bool):
        return False
    return isinstance(value, int) or (isinstance(value, float) and math.isfinite(value))


def positive(value: object) -> bool:
    return number(value) and value > 0  # type: ignore[operator]


def out_of_range(key: str, value: float) -> str | None:
    """Why a parameter's value means nothing for its name, or None.

    A limit that every run meets is no limit, so a maximum share stays below 1 and a minimum stays above 0.
    """
    if value < 0:
        return "is a number of at least 0"
    if key.endswith("_share"):
        if value > 1 or (key.startswith("max_") and value == 1) or (key.startswith("min_") and value == 0):
            return "is a share: from 0 to 1, below 1 for a maximum and above 0 for a minimum, so that some run can miss it"
    elif key.startswith("min_") and value == 0:
        return "is a minimum above 0: a minimum of 0 asks for nothing"
    elif key == "quantile" and not 0 < value <= 1:
        return "is a quantile above 0 and at most 1"
    return None


def digests(value: object) -> bool:
    """True for a non-empty map from a path to a SHA-256 digest."""
    return isinstance(value, dict) and bool(value) and all(text(path) and isinstance(digest, str) and SHA256.match(digest)
                                                            for path, digest in value.items())


def as_dict(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def as_list(value: object) -> list:
    return value if isinstance(value, list) else []


def row_id(row: object) -> str | None:
    """A row's id when it is a string. Any other value is reported by the shape check."""
    value = as_dict(row).get("id")
    return value if isinstance(value, str) else None


def names(value: object) -> list[str]:
    return [item for item in as_list(value) if isinstance(item, str)]


def rows_by_id(section: object) -> dict[str, dict]:
    """The rows of one ledger section that carry a string id, keyed by it."""
    rows: dict[str, dict] = {}
    for row in as_list(section):
        ident = row_id(row)
        if ident is not None:
            rows[ident] = as_dict(row)
    return rows


def inside(path: object) -> bool:
    """True for a relative path with no `..` part, the only form a ledger may name."""
    return text(path) and not str(path).startswith("/") and ".." not in Path(str(path)).parts


def row_digest(row: dict) -> str:
    """Digest of a row without its status. A judge writes the same digest into its receipt."""
    kept = {key: value for key, value in row.items() if key != "status"}
    return hashlib.sha256(json.dumps(kept, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def yaml_list(source: str, key: str, wrapped: list[str] | None = None) -> list[str]:
    """Read a top-level `key:` followed by `  - item` lines, one item per line.

    A line under the key that continues an item is reported through `wrapped`, because the
    claim would print the item cut short.
    """
    items: list[str] = []
    active = False
    for line in source.splitlines():
        if re.match(rf"^{re.escape(key)}:\s*$", line):
            active = True
        elif active and re.match(r"^\s+-\s+\S", line):
            items.append(line.split("-", 1)[1].strip())
        elif active and line.strip() and not line.startswith((" ", "#")):
            break
        elif active and line.strip() and not line.lstrip().startswith("#") and wrapped is not None:
            wrapped.append(f"{key}: {line.strip()}")
    return items


def under(path: str, frozen: list[str]) -> bool:
    return any(path == entry.rstrip("/") or path.startswith(entry.rstrip("/") + "/") for entry in frozen)


def git(root: Path, *argv: str, why: list[str] | None = None) -> str | None:
    """Git's output, or None when git failed. `why` receives the first line git wrote about the failure."""
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")
    result = subprocess.run(["git", "-C", str(root), *argv], capture_output=True, check=False, env=env)
    if result.returncode != 0 and why is not None:
        why.append((result.stderr.decode("utf-8", "replace").strip().splitlines() or ["git gave no reason"])[0][:200])
    return result.stdout.decode("utf-8", "surrogateescape") if result.returncode == 0 else None


def git_bytes(root: Path, *argv: str) -> bytes | None:
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")
    result = subprocess.run(["git", "-C", str(root), *argv], capture_output=True, check=False, env=env)
    return result.stdout if result.returncode == 0 else None


def tree_mode(path: Path) -> str:
    """The mode git records for a file on disk: a link, an executable file or a plain file. Any other entry has none."""
    try:
        info = os.lstat(path)
    except OSError:
        return ""
    if stat.S_ISLNK(info.st_mode):
        return "120000"
    if stat.S_ISREG(info.st_mode):
        return "100755" if info.st_mode & stat.S_IXUSR else "100644"
    return ""


def blob_id(path: Path, like: str) -> str:
    """The git object id of a file's bytes, computed here so that no git filter or attribute takes part."""
    digest = hashlib.new("sha256" if len(like) == 64 else "sha1", usedforsecurity=False)
    try:
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode):
            data = os.fsencode(os.readlink(path))
            digest.update(b"blob %d\0" % len(data) + data)
        elif stat.S_ISREG(info.st_mode):
            digest.update(b"blob %d\0" % info.st_size)
            with open(path, "rb") as file:
                for chunk in iter(lambda: file.read(CHUNK), b""):
                    digest.update(chunk)
        else:
            return "unreadable"
    except OSError:
        return "unreadable"
    return digest.hexdigest()


def stamp(value: object) -> bool:
    """True for a UTC time written as 2026-11-20T22:58:00Z, with every field padded, and at most a day ahead of this clock.

    The padded form orders as text the way it orders in time.
    """
    if not isinstance(value, str) or not STAMP.fullmatch(value):
        return False
    try:
        moment = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return moment <= datetime.now(timezone.utc) + timedelta(days=1)


def sha256_file(path: Path) -> str | None:
    """The digest of a regular file. A link, a pipe, a device and a missing file have none."""
    digest = hashlib.sha256()
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return None
        with open(path, "rb") as file:
            for chunk in iter(lambda: file.read(CHUNK), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def read_object(path: Path) -> dict | None:
    """A regular file's JSON object, or None."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def load(path: str) -> dict:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as error:
        fatal(f"cannot read {path}: {error.__class__.__name__}: {str(error)[:200]}")
    if not isinstance(doc, dict):
        fatal(f"{path} is not a JSON object")
    return doc


class Checker:
    def __init__(self, doc: dict, args: argparse.Namespace) -> None:
        self.doc = doc
        self.args = args
        self.root = Path(args.root) if args.root else None
        self.findings: list[str] = []
        self.invariants = rows_by_id(doc.get("invariants"))
        self.scenarios = rows_by_id(doc.get("scenarios"))
        self.summaries: dict[str, str] = {}
        self.runs: list[dict] = []
        self.frozen: list[str] = []

    def add(self, row: object, code: str, detail: str) -> None:
        self.findings.append(f"{row or 'ledger'}: {code}: {detail}")

    def unknown(self, row: object, name: str, value: dict) -> None:
        for key in sorted(set(value) - FIELDS[name]):
            self.add(row, "unknown-field", f"{name} field {key!r} is not part of the schema")

    def parameters(self, row: object, name: str, value: object) -> None:
        """Harness and judge parameters are numbers, so a parameter object cannot carry a note."""
        if value is not None and not isinstance(value, dict):
            self.add(row, "bad-parameter", f"{name} must be an object")
        for key, item in as_dict(value).items():
            if key in TEXT_KEYS[name]:
                if not text(item):
                    self.add(row, "bad-parameter", f"{name}.{key} must be text")
            elif not number(item):
                self.add(row, "bad-parameter", f"{name}.{key} must be a number; only "
                                               f"{', '.join(sorted(TEXT_KEYS[name])) or 'no field'} may hold text")
            elif out_of_range(key, item):
                self.add(row, "bad-parameter", f"{name}.{key} {out_of_range(key, item)}")

    def judge(self, row: object, command: object) -> None:
        if not text(command):
            self.add(row, "missing-judge", "the row needs the command that decides it")
            return
        script, *words = str(command).split()
        if not inside(script):
            self.add(row, "bad-judge-path", f"{script!r} must be a path inside the repository with no `..`")
        elif self.root and not (self.root / script).is_file():
            self.add(row, "missing-judge-script", f"{script} does not exist under --root")
        other = next((word for word in words if word != row and word in {**self.invariants, **self.scenarios}), None)
        if other:
            self.add(row, "judge-names-another-row", f"the judge command names the row {other}, so its receipts can never be this row's")

    def shape(self) -> None:
        doc = self.doc
        self.unknown(None, "top", doc)
        if type(doc.get("schema")) is not int or doc["schema"] != 1:
            self.add(None, "bad-schema", "schema must be the integer 1")
        if not text(doc.get("system")):
            self.add(None, "bad-schema", "system must name the enrolled system")
        for section, code in (("fences", "no-fences"), ("invariants", "no-invariants"), ("scenarios", "no-scenarios")):
            if not as_list(doc.get(section)):
                self.add(None, code, f"{section} must hold at least one row")
        seen: set[str] = set()
        for section in ("fences", "invariants", "scenarios"):
            for row in as_list(doc.get(section)):
                ident = row_id(row)
                if ident is None or not ID.match(ident):
                    self.add(str(as_dict(row).get("id"))[:40], "bad-id",
                             f"a {section} id must be lowercase words joined by hyphens")
                elif ident in seen:
                    self.add(ident, "duplicate-id", "the id is used by another row")
                else:
                    seen.add(ident)

    def fences(self) -> None:
        for raw in as_list(self.doc.get("fences")):
            row = as_dict(raw)
            ident = row_id(row)
            self.unknown(ident, "fence", row)
            probe = as_dict(row.get("probe"))
            self.unknown(ident, "probe", probe)
            if not text(row.get("text")) or not text(row.get("enforced_by")):
                self.add(ident, "missing-fence", "a fence states what is out of reach and which boundary enforces it")
            if not all(text(probe.get(key)) for key in ("command", "expect", "identity")):
                self.add(ident, "missing-fence-probe",
                         "a fence needs a probe: identity (a command that prints who the campaign runs as), "
                         "command (the forbidden action) and expect (text of its refusal)")

    def invariant_rows(self) -> None:
        used = {name for row in self.scenarios.values() for name in names(row.get("invariants"))}
        for ident, row in self.invariants.items():
            self.unknown(ident, "invariant", row)
            prop = as_dict(row.get("property"))
            source = as_dict(prop.get("source"))
            self.unknown(ident, "property", prop)
            self.unknown(ident, "source", source)
            if not text(prop.get("text")):
                self.add(ident, "missing-property", "the invariant needs its text in the owner's words")
            if prop.get("agreed") != "owner":
                self.add(ident, "bad-agreed", "an invariant enters the ledger when the owner agreed to it")
            if not text(source.get("kind")) or not text(source.get("ref")):
                self.add(ident, "missing-source", "property.source needs kind and ref: where the agreement is recorded")
            kind = row.get("kind")
            if kind not in KINDS:
                self.add(ident, "bad-kind", f"kind must be one of {', '.join(KINDS)}")
            self.judge(ident, row.get("judge"))
            threshold = as_dict(row.get("threshold"))
            self.parameters(ident, "threshold", row.get("threshold"))
            if kind in ("threshold", "recovery") and not (
                    text(threshold.get("measured")) and any(number(value) for value in threshold.values())):
                self.add(ident, "missing-threshold",
                         "a threshold or recovery invariant needs the owner's number and where it is measured")
            if not text(row.get("oracle")):
                self.add(ident, "missing-oracle", "say where the expected result comes from, apart from the system under test")
            witness = as_dict(row.get("witness"))
            self.parameters(ident, "witness", row.get("witness"))
            if not text(witness.get("check")) or not text(witness.get("expect")):
                self.add(ident, "missing-witness", "witness needs check and expect: what shows the check ran on real data")
            control = as_dict(row.get("control"))
            self.unknown(ident, "control", control)
            scenario = control.get("scenario")
            if control.get("kind") not in CONTROLS or not all(text(control.get(key)) for key in ("how", "expect")):
                self.add(ident, "missing-control",
                         "control needs kind (seeded-defect or seeded-evidence), how, scenario and expect: "
                         "a known-bad case this judge must report as broken")
            elif control["kind"] == "seeded-defect" and not text(control.get("defect")):
                self.add(ident, "missing-control", "a seeded-defect control names its defect, as the harness's switch spells it")
            elif not isinstance(scenario, str) or ident not in names(self.scenarios.get(scenario, {}).get("invariants")):
                self.add(ident, "bad-control-scenario", "control.scenario must name a scenario that checks this invariant")
            if ident not in used:
                self.add(ident, "unused-invariant", "no scenario checks this invariant")

    def scenario_rows(self) -> None:
        for ident, row in self.scenarios.items():
            self.unknown(ident, "scenario", row)
            source = as_dict(row.get("source"))
            self.unknown(ident, "source", source)
            if not text(row.get("text")):
                self.add(ident, "missing-text", "the scenario needs one sentence saying what happens")
            if source.get("kind") not in SOURCES or not text(source.get("ref")):
                self.add(ident, "missing-source", f"source needs kind ({', '.join(SOURCES)}) and ref: where the owner accepted it")
            load_row = as_dict(row.get("load"))
            self.parameters(ident, "load", row.get("load"))
            if not text(load_row.get("reference")) or not positive(load_row.get("multiple")):
                self.add(ident, "missing-load", "load needs reference (the real traffic figure and its source) and multiple")
            fault = as_dict(row.get("fault"))
            self.parameters(ident, "fault", row.get("fault"))
            if not text(fault.get("kind")):
                self.add(ident, "missing-fault", "fault.kind is required; write none for a load-only scenario")
            elif fault["kind"] != "none":
                if not text(fault.get("target")):
                    self.add(ident, "missing-fault", "fault.target names what the fault is injected on")
                if not text(row.get("injection_oracle")):
                    self.add(ident, "missing-injection-oracle",
                             "say what independent observation shows the fault happened on its target")
                if not text(as_dict(row.get("reach")).get("text")):
                    self.add(ident, "missing-reach", "reach.text states the activity the fault must land in")
            elif "injection_oracle" in row and not text(row["injection_oracle"]):
                self.add(ident, "missing-injection-oracle", "injection_oracle must be text")
            self.parameters(ident, "reach", row.get("reach"))
            delivery = as_dict(row.get("load_delivery"))
            self.parameters(ident, "load_delivery", row.get("load_delivery"))
            if not any(number(value) for value in delivery.values()):
                self.add(ident, "missing-load-delivery", "load_delivery needs the limit below which the load counts as delivered")
            if not text(row.get("restoration")):
                self.add(ident, "missing-restoration", "say what returns the copy to its state before the run")
            stops = as_list(row.get("stop_conditions"))
            if not stops or not all(text(stop) for stop in stops):
                self.add(ident, "missing-stop-conditions", "stop_conditions lists what ends a run early")
            if not positive(row.get("deadline_s")):
                self.add(ident, "missing-deadline", "deadline_s is the wall-clock limit after which the harness ends the run as incomplete")
            self.judge(ident, row.get("judge"))
            listed = as_list(row.get("invariants"))
            if not listed:
                self.add(ident, "missing-invariants", "a scenario checks at least one invariant")
            for name in listed:
                if not isinstance(name, str) or name not in self.invariants:
                    self.add(ident, "unknown-invariant", f"{name!r} is not an invariant row")
            runs = row.get("runs_required")
            if not isinstance(runs, int) or isinstance(runs, bool) or runs < 2:
                self.add(ident, "bad-runs-required", "runs_required is an integer of at least 2")
            if row.get("status") not in STATUSES:
                self.add(ident, "bad-status", f"status must be one of {', '.join(STATUSES)}")
            elif row["status"] != "open" and not self.args.receipts:
                self.add(ident, "status-unchecked", f"status {row['status']} was not compared with receipts; pass --receipts")
            if "parent" in row:
                self.derived(ident, row)

    def derived(self, ident: object, row: dict) -> None:
        parent_id = row.get("parent")
        parent = self.scenarios.get(parent_id) if isinstance(parent_id, str) else None
        if parent is None or "parent" in parent:
            self.add(ident, "unknown-parent", "parent must name a scenario that was agreed with the owner")
            return
        reasons = [f"another {key}" for key in sorted(FIELDS["scenario"] - DERIVED_OWN) if row.get(key) != parent.get(key)]
        script, *words = str(parent.get("judge", "")).split() or [""]
        if str(row.get("judge", "")).split() != [script, *(str(ident) if word == parent_id else word for word in words)]:
            reasons.append("another judge command")
        for key in ("kind", "target"):
            if as_dict(row.get("fault")).get(key) != as_dict(parent.get("fault")).get(key):
                reasons.append(f"another fault {key}")
        if not set(names(parent.get("invariants"))) <= set(names(row.get("invariants"))):
            reasons.append("fewer invariants")
        if reasons:
            self.add(ident, "outside-envelope",
                     f"a derived scenario has its own id, text and source, its parent's judge command under its own id, "
                     f"its parent's invariants or more, and other parameters of the same fault, and equals its parent "
                     f"in every other field; this one has {', '.join(reasons)}, so it is a new scenario for the owner")

    def excluded(self) -> None:
        if not isinstance(self.doc.get("excluded"), list):
            self.add("excluded", "bad-excluded", "excluded is a list of entries, empty when no property was left out")
        for index, raw in enumerate(as_list(self.doc.get("excluded"))):
            entry = as_dict(raw)
            self.unknown(f"excluded[{index}]", "excluded", entry)
            if not text(entry.get("property")) or entry.get("reason") not in REASONS or not text(entry.get("detail")):
                self.add(f"excluded[{index}]", "bad-excluded",
                         f"an excluded entry needs property, reason ({', '.join(REASONS)}) and detail")

    def project(self) -> list[str]:
        try:
            source = Path(self.args.project).read_text(encoding="utf-8")
        except (OSError, ValueError) as error:
            fatal(f"cannot read {self.args.project}: {error}")
        wrapped: list[str] = []
        for key, code in PROJECT_LISTS.items():
            if not yaml_list(source, key, wrapped):
                self.add("project", code, f"project.yaml needs at least one entry under {key}")
        for line in wrapped:
            self.add("project", "wrapped-list-item", f"write each list item on one line; this line continues one: {line}")
        listed = yaml_list(source, "frozen_paths")
        for entry in listed:
            if not inside(entry):
                self.add(entry, "frozen-path-outside-root", "a frozen path is relative to the repository root and has no `..` part")
        frozen = [entry for entry in listed if inside(entry)]
        self.frozen = frozen
        if frozen:
            for ident, row in {**self.invariants, **self.scenarios}.items():
                script = str(row.get("judge", "")).split()[0] if text(row.get("judge")) else ""
                if script and inside(script) and not under(script, frozen):
                    self.add(ident, "judge-not-frozen", f"{script} is outside frozen_paths, so a campaign could edit its own judge")
            relative = self.relative(self.args.project)
            if relative and not under(relative, frozen):
                self.add("project", "project-not-frozen", f"{relative} must be listed under frozen_paths")
            policy = self.relative(str(Path(self.args.project).parent / "approval-policy.md"))
            if policy and not under(policy, frozen):
                self.add("project", "policy-not-frozen", f"{policy} must be listed under frozen_paths")
        return frozen

    def relative(self, path: str) -> str:
        """A path relative to --root, or the empty string when there is no root or the path is outside it."""
        if not self.root:
            return ""
        try:
            return Path(path).resolve().relative_to(self.root.resolve()).as_posix()
        except ValueError:
            return ""

    def read_receipts(self) -> tuple[list[dict], dict[str, dict]]:
        """Read <receipts>/<run-id>/<row>.json and <receipts>/fences/<fence>.json. Anything else is a finding."""
        base = Path(self.args.receipts).resolve()
        grouped: dict[str, dict[str, dict]] = {}
        probes: dict[str, dict] = {}
        try:
            for entry in sorted(base.iterdir()):
                if entry.is_symlink() or not entry.is_dir():
                    self.add(entry.name, "unexpected-receipt-file", "the receipt directory holds one directory per run and fences/")
                    continue
                found: dict[str, dict] = {}
                for path in sorted(entry.iterdir()):
                    if path.is_symlink() or not path.is_file() or path.suffix != ".json":
                        self.add(f"{entry.name}/{path.name}", "unexpected-receipt-file",
                                 "a receipt directory holds one <row>.json per judged row and nothing else")
                        continue
                    doc = as_dict(json.loads(path.read_text(encoding="utf-8")))
                    key, run = as_dict(doc.get("key")), as_dict(doc.get("run"))
                    found[path.stem] = doc if entry.name == "fences" else dict(
                        key, run_id=run.get("run_id"), started=run.get("started"), judged=run.get("judged"))
                if entry.name == "fences":
                    probes = found
                else:
                    grouped[entry.name] = found
            runs = [self.run_of(name, receipts) for name, receipts in grouped.items()]
            self.evidence(base.parent / "runs", runs)
        except (OSError, ValueError, RecursionError) as error:
            fatal(f"cannot read receipts under {self.args.receipts}: {error.__class__.__name__}: {str(error)[:200]}")
        seen: dict[str, str] = {}
        for run in sorted(runs, key=lambda run: str(run["started"])):
            if not run["usable"] or run["mode"] != "live":
                continue  # a control counts toward no status, and an edited copy of a run is a control by design
            if run["records"] in seen:
                self.add(run["id"], "duplicate-evidence", f"its operation history equals that of live run {seen[run['records']]}; "
                                                          "one run counts once")
                run["usable"] = False
            seen.setdefault(run["records"], run["id"])
        return runs, probes

    def evidence(self, directory: Path, runs: list[dict]) -> None:
        """Receipts count with the evidence they name: runs/<run-id>/ beside the receipt directory, as real files.

        The receipts' own fields are compared with the run record they name by digest, and the
        run record with the scenario row as it stands: a row that has a run changes only in status.
        """
        real = directory.is_dir() and not directory.is_symlink()
        present = {path.name: path for path in directory.iterdir() if path.is_dir() and not path.is_symlink()} if real else {}
        for run in runs:
            run["records"] = json.dumps(run["evidence"], sort_keys=True)
            if run["id"] not in present:
                self.add(run["id"], "receipts-without-run",
                         f"no evidence directory {directory.name}/{run['id']}; a receipt counts with the evidence it names")
                run["usable"] = False
                continue
            folder = present[run["id"]]
            record = read_object(folder / "run.json")
            row = self.scenarios.get(str(as_dict(record).get("scenario")))
            if record is not None and row is not None and not text(record.get("scenario_row")):
                self.add(run["id"], "malformed-run", "run.json holds no scenario_row, the digest of the scenario row the run started with")
                run["usable"] = False
            elif record is not None and row is not None and record["scenario_row"] != row_digest(row):
                self.add(run["id"], "row-changed-after-run",
                         f"the row {row.get('id')} differs from the row this run started with; a row that has a run "
                         "changes only in status, so restore the row or retire the run with the owner")
                run["usable"] = False
            if not run["usable"]:
                continue
            files = {path.name: sha256_file(path) for path in sorted(folder.iterdir()) if path.is_symlink() or path.is_file()}
            if files != run["evidence"]:
                self.add(run["id"], "stale-receipt",
                         f"the files under {directory.name}/{run['id']} differ from the evidence its receipts name")
                run["usable"] = False
                continue
            first = next(iter(run["receipts"].values()))
            named = {"run_id": run["id"], "scenario": run["scenario"], "mode": run["mode"], "defect": run["defect"],
                     "system_build": run["system_build"], "started": run["started"], "harness": first.get("harness")}
            differs = sorted(key for key, value in named.items() if record is None or record.get(key) != value)
            if differs:
                self.add(run["id"], "inconsistent-receipts",
                         f"the receipts disagree with {directory.name}/{run['id']}/run.json on {', '.join(differs)}")
                run["usable"] = False
                continue
            # A history that does not parse keeps the digest of its bytes as its identity.
            with contextlib.suppress(OSError, ValueError, RecursionError):
                lines = (folder / "history.jsonl").read_text(encoding="utf-8").splitlines()
                canonical = [json.dumps(json.loads(line), sort_keys=True, separators=(",", ":")) for line in lines if line.strip()]
                run["records"] = hashlib.sha256("\n".join(canonical).encode()).hexdigest()
        for name in sorted(set(present) - {run["id"] for run in runs}):
            self.add(name, "run-without-receipts",
                     "the evidence directory has no receipts; judge it, and remove a run only with the owner")

    def run_of(self, name: str, receipts: dict[str, dict]) -> dict:
        """One run from its receipts. A run whose receipts disagree, are malformed or are stale is reported and counts for nothing."""
        first = next(iter(receipts.values()), {})
        run = {"id": name, "receipts": receipts, "usable": True, "evidence": first.get("evidence"), "records": "",
               **{key: first.get(key) for key in ("scenario", "mode", "defect", "system_build", "started")}}
        shared = ("scenario", "mode", "defect", "system_build", "harness", "evidence", "started")
        problem = None
        for stem, receipt in receipts.items():
            if receipt.get("row") != stem or receipt.get("run_id") != name:
                problem = f"receipt {stem}.json names row {receipt.get('row')!r} of run {receipt.get('run_id')!r}"
            elif any(receipt.get(key) != first.get(key) for key in shared):
                problem = f"receipt {stem}.json disagrees with the run's other receipts on its scenario, mode, build, harness or evidence"
        if not receipts:
            self.add(name, "incomplete-receipts", "the run has a receipt directory and no receipt; judge its evidence")
        elif problem:
            self.add(name, "inconsistent-receipts", problem)
        elif (run["mode"] not in ("live", "control") or not text(run["scenario"]) or not text(run["system_build"])
              or not stamp(run["started"]) or not isinstance(run["defect"], str) or (run["mode"] == "live" and run["defect"])
              or any(not stamp(receipt.get("judged")) or receipt["judged"] < run["started"] for receipt in receipts.values())):
            self.add(name, "malformed-run",
                     "the receipts need mode live or control, no seeded defect for a live run, a scenario, a build, and a "
                     "start time before each judgement, each time written as 2026-11-20T22:58:00Z and no later than this clock")
        elif any(not digests(receipt.get(kind)) for receipt in receipts.values() for kind in ("judge", "harness", "evidence")) \
                or "run.json" not in as_dict(run["evidence"]) \
                or (len(as_dict(run["evidence"])) < 2 and any(receipt.get("outcome") != "incomplete" for receipt in receipts.values())):
            self.add(name, "malformed-run",
                     "each receipt needs the SHA-256 digests of its judge files, of the harness files and of the evidence "
                     "files, run.json among them and a record file beside it for any verdict but incomplete, so that the "
                     "verdict is bound to the code and the records that produced it")
        else:
            for stem, receipt in receipts.items():
                reason = self.stale(stem, receipt)
                if reason:
                    self.add(name, "stale-receipt", f"{stem}: {reason}")
                    run["usable"] = False
            return run
        run["usable"] = False
        return run

    def stale(self, stem: str, receipt: dict) -> str | None:
        """Why a receipt no longer describes the ledger and the tree, or None."""
        scenario = self.scenarios.get(str(receipt.get("scenario")))
        row = self.scenarios.get(stem) or self.invariants.get(stem)
        if scenario is None or row is None:
            return "its row or scenario is not in the ledger"
        expected = {stem: row_digest(row), str(receipt.get("scenario")): row_digest(scenario)}
        if receipt.get("rows") != expected:
            return "the row or its scenario changed since the judgement"
        if stem != scenario.get("id") and stem not in names(scenario.get("invariants")):
            return "its scenario does not judge this row"
        if receipt.get("command") != str(row.get("judge", "")).split():
            return "it was judged by another command than the row's judge"
        command = as_list(receipt.get("command"))
        if not command or command[0] not in as_dict(receipt.get("judge")):
            return "its judge digests leave out the script that judged it"
        if self.root:
            for kind in ("judge", "harness"):
                for path, digest in as_dict(receipt.get(kind)).items():
                    if not inside(path) or sha256_file(self.root / path) != digest:
                        return f"{path} differs from the file that produced it"
        return None

    def verdict(self, row: dict, run: dict) -> str:
        """One run of a scenario: held, broken, incomplete (a receipt is missing) or none."""
        listed = names(row.get("invariants"))
        receipts = run["receipts"]
        if row["id"] not in receipts or any(name not in receipts for name in listed):
            return "incomplete"
        outcomes = [receipts[name].get("outcome") for name in listed]
        if "broken" in outcomes:
            return "broken"
        if receipts[row["id"]].get("outcome") == "held" and all(outcome == "held" for outcome in outcomes):
            return "held"
        return "none"

    def receipts(self) -> None:
        runs, probes = self.read_receipts()
        self.runs = runs
        if self.frozen:
            for kind in ("harness", "judge"):
                named = {path for run in runs if run["usable"] for receipt in run["receipts"].values()
                         for path in as_dict(receipt.get(kind))}
                for path in sorted(named):
                    if not under(path, self.frozen):
                        self.add(path, f"{kind}-not-frozen",
                                 f"a receipt names this file as its {kind} and frozen_paths leaves it out, so a campaign "
                                 "could edit what produces or judges its evidence")
        fences = {row_id(raw) for raw in as_list(self.doc.get("fences"))}
        for raw in as_list(self.doc.get("fences")):
            self.probe(as_dict(raw), probes)
        for stem in sorted(set(probes) - fences):
            self.add(f"fences/{stem}.json", "unexpected-receipt-file", "the ledger has no fence of this name")
        usable = sorted((run for run in runs if run["usable"]), key=lambda run: run["started"])
        for run in usable:
            row = self.scenarios.get(str(run["scenario"]))
            if row is not None and self.verdict(row, run) == "incomplete":
                self.add(run["id"], "incomplete-receipts",
                         f"a {run['mode']} run of {run['scenario']} lacks a receipt for a listed invariant or for validity")
                run["usable"] = False
        usable = [run for run in usable if run["usable"]]
        controls = {run["id"] for name in self.invariants for run in self.rejected_controls(name, usable)[0]}
        for run in usable:
            if run["mode"] == "control" and run["id"] not in controls:
                self.add(run["id"], "control-without-row",
                         f"no invariant's control names scenario {run['scenario']} with the defect {run['defect']!r}")
        for name in self.invariants:
            self.invariant_evidence(name, usable)
        for ident, row in self.scenarios.items():
            self.status(ident, row, usable)

    def probe(self, fence: dict, probes: dict[str, dict]) -> None:
        ident = row_id(fence)
        wanted = as_dict(fence.get("probe"))
        record = probes.get(ident or "")
        status = as_dict(record).get("exit_status")
        if record is None:
            self.add(ident, "probe-missing", "no probe receipt: run scripts/probe_fence.py for this fence")
        elif record.get("fence") != ident:
            self.add(ident, "stale-probe", f"the probe receipt was recorded for fence {record.get('fence')!r}")
        elif record.get("command") != wanted.get("command") or as_dict(record.get("identity")).get("command") != wanted.get("identity"):
            self.add(ident, "stale-probe", "the probe receipt is for another command than the row's")
        elif not text(as_dict(record.get("identity")).get("output")):
            self.add(ident, "probe-without-identity", "the probe receipt does not show who the campaign ran as")
        elif (type(status) is not int or status == 0 or record.get("refused") is not True or not stamp(record.get("ran"))
              or not isinstance(record.get("output"), str) or not text(wanted.get("expect")) or wanted["expect"] not in record["output"]):
            self.add(ident, "probe-not-refused",
                     "the probe receipt does not record a refusal: a non-zero exit status, the expected text in the "
                     "output and the time it ran; the fence does not hold")

    def valid(self, run: dict) -> bool:
        return as_dict(run["receipts"].get(run["scenario"])).get("outcome") == "held"

    def rejected_controls(self, name: str, runs: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
        """Control runs for an invariant: all, those that were valid runs, and those its judge rejected as expected.

        A run of a seeded-defect control counts when it names the row's defect.
        """
        control = as_dict(self.invariants[name].get("control"))
        seeded = control.get("kind") == "seeded-defect"
        every = [run for run in runs if run["mode"] == "control" and run["scenario"] == control.get("scenario")
                 and name in run["receipts"] and (not seeded or run["defect"] == control.get("defect"))]
        valid = [run for run in every if self.valid(run)]
        met = [run for run in valid if run["receipts"][name].get("outcome") == "broken"
               and str(control.get("expect")) in str(run["receipts"][name].get("detail", ""))]
        return every, valid, met

    def invariant_evidence(self, name: str, runs: list[dict]) -> None:
        """What enrollment owes each invariant: a live run its judge decided and a control its judge rejected.

        A decided live run held on a valid run with the witness text, or broke. Either shows the
        check ran on real data that met its minimums.
        """
        invariant = self.invariants[name]
        expect = as_dict(invariant.get("witness")).get("expect")
        outcomes = [(run, as_dict(run["receipts"].get(name))) for run in runs if run["mode"] == "live"]
        witnessed = [run for run, receipt in outcomes if receipt.get("outcome") == "broken" or (
            self.valid(run) and receipt.get("outcome") == "held" and text(expect) and str(expect) in str(receipt.get("detail", "")))]
        if not witnessed:
            self.add(name, "witness-missing", f"no live run broke this invariant, and no valid one held it with the witness text {expect!r}")
        control = as_dict(invariant.get("control"))
        every, valid, met = self.rejected_controls(name, runs)
        if not every:
            self.add(name, "control-missing",
                     f"no control run of {control.get('scenario')} with the row's defect has a receipt for this "
                     "invariant. A run started without its defect records mode live and counts as a witness")
        elif not valid:
            self.add(name, "control-run-invalid", "every control run was an invalid run of its scenario, so it rejected nothing")
        elif not met:
            self.add(name, "control-not-rejected",
                     f"no valid control run was reported broken with {control.get('expect')!r} in the detail")

    def status(self, ident: str, row: dict, runs: list[dict]) -> None:
        """Compare a scenario's status with its live runs. A break at any build stays on record until a fix outweighs it."""
        status = row.get("status")
        live = [run for run in runs if run["mode"] == "live" and run["scenario"] == ident]
        latest = {run["system_build"] for run in live if run["started"] == live[-1]["started"]}
        if len(latest) > 1:
            self.add(ident, "latest-build-ambiguous",
                     f"live runs of {len(latest)} builds started at {live[-1]['started']}, the latest start, so no build "
                     "is the latest and no status stands")
            return
        build = live[-1]["system_build"] if live else None
        current = [run for run in live if run["system_build"] == build]
        verdicts = [self.verdict(row, run) for run in current]
        others: dict[str, list[str]] = {}
        for run in live:
            if run["system_build"] != build:
                others.setdefault(run["system_build"], []).append(self.verdict(row, run))
        broke = {name: group for name, group in others.items() if "broken" in group}
        past = [verdict for group in broke.values() for verdict in group]
        held, broken = verdicts.count("held"), verdicts.count("broken")
        broke_before, decided_before = past.count("broken"), past.count("held") + past.count("broken")
        # Each build that broke sets its own number of held runs, and the largest stands.
        bars = {name: math.ceil(3 * (group.count("held") + group.count("broken")) / group.count("broken")) for name, group in broke.items()}
        bar = max(bars.items(), key=lambda item: item[1], default=None)
        unsound = [as_dict(run["receipts"].get(ident)) for run in live
                   if self.verdict(row, run) == "broken" and not self.valid(run)]
        on_invalid = (f"; {len(unsound)} of the broken runs were no valid run of the scenario, the first because: "
                      f"{str(unsound[0].get('detail', 'no validity detail'))[:160]}") if unsound else ""
        self.summaries[ident] = "no live run" if not live else (
            f"{held} held, {broken} broken and {len(verdicts) - held - broken} without a verdict "
            f"of {len(verdicts)} live runs of build {str(build)[:12]}"
            + (f"; build {str(bar[0])[:12]} broke {broke[bar[0]].count('broken')} of "
               f"{broke[bar[0]].count('held') + broke[bar[0]].count('broken')} runs, the most a fix has to outweigh" if bar else "")
            + on_invalid)
        if status not in ("held", "broken", "fixed"):
            if broken:
                self.add(ident, "broken-run-not-recorded",
                         f"{broken} of {len(verdicts)} live runs of the latest build broke an invariant; the status is broken{on_invalid}")
            elif broke_before:
                self.add(ident, "broken-run-not-recorded",
                         f"{broke_before} of {decided_before} live runs of another build broke an invariant; the status "
                         f"is broken until the latest build has the held runs that fixed needs{on_invalid}")
            return
        if not current:
            self.add(ident, "status-without-receipts", f"status {status} has no usable live run")
            return
        if self.args.build and str(build) != self.args.build and status != "broken":
            self.add(ident, "build-without-runs",
                     f"the latest live run is of build {str(build)[:12]}; no status stands for build {self.args.build[:12]}")
        elif not self.args.build and status in ("held", "fixed"):
            self.add(ident, "build-unchecked",
                     f"status {status} was not compared with the build on the copy; pass --build with the digest "
                     "the harness records for it")
        if status in ("held", "fixed") and not self.root:
            self.add(ident, "root-unchecked",
                     f"status {status} was not compared with the tree; pass --root so that each receipt's judge and "
                     "harness digests are checked against the files")
        if status in ("held", "fixed") and not self.args.freeze_commit:
            self.add(ident, "freeze-unchecked",
                     f"status {status} was not compared with the files of the freeze; pass --freeze-commit with the full id "
                     "the owner named, which a session other than the owner's asks the owner for")
        if status == "broken":
            if not broken and not broke_before:
                self.add(ident, "broken-without-receipt", "no live run has a broken invariant receipt")
            return
        if broken:
            self.add(ident, "held-with-broken-run",
                     f"{broken} of {len(verdicts)} runs of the same build broke an invariant; "
                     f"a scenario that breaks in some runs is broken{on_invalid}")
        stated = row.get("runs_required")
        required = stated if isinstance(stated, int) and not isinstance(stated, bool) else 2
        if status == "held" and broke_before:
            self.add(ident, "held-after-broken-build",
                     f"{broke_before} of {decided_before} live runs of another build broke an invariant; a hold after "
                     "a break is the status fixed, which needs more held runs")
        if status == "fixed":
            if bar is None:
                self.add(ident, "fixed-without-broken",
                         "fixed needs a broken run at another build and held runs at the latest one; "
                         "no other build has a broken receipt")
            else:
                group, needed = broke[bar[0]], max(required, bar[1])
                if held < needed:
                    self.add(ident, "too-few-held-runs-for-fix",
                             f"{group.count('broken')} of {group.count('held') + group.count('broken')} runs of build "
                             f"{str(bar[0])[:12]} were broken, so a fix needs {needed} held runs and no broken one; "
                             f"there are {held}")
        if held < required:
            self.add(ident, "too-few-held-runs", f"{held} valid held runs of the latest build; the row requires {required}")
        counted = [current[index] for index, verdict in enumerate(verdicts) if verdict == "held"]
        signatures = {json.dumps({stem: [receipt.get("judge"), receipt.get("harness")]
                                  for stem, receipt in run["receipts"].items()}, sort_keys=True) for run in counted}
        if len(signatures) > 1:
            self.add(ident, "receipts-differ", "the held runs were produced under different judge or harness digests")
        for name in names(row.get("invariants")):
            expect = as_dict(self.invariants.get(name, {}).get("witness")).get("expect", "")
            if any(text(expect) and expect not in str(run["receipts"][name].get("detail", "")) for run in counted):
                self.add(ident, "witness-not-in-receipt", f"a held receipt for {name} lacks the witness text {expect!r}")
            met = self.rejected_controls(name, runs)[2] if name in self.invariants else []
            code = [{json.dumps([run["receipts"][name].get(kind) for kind in ("judge", "harness")], sort_keys=True)
                     for run in group} for group in (counted, met)]
            if met and code[0] and not code[0] & code[1]:
                self.add(ident, "stale-control", f"the control for {name} ran under another judge or harness than the held runs")

    def freeze(self) -> None:
        if self.args.frozen:
            baseline = load(self.args.frozen)
        else:
            if self.root is None:
                fatal("--freeze-commit needs --root")
            ledger, project = self.relative(self.args.ledger), self.relative(self.args.project)
            if not ledger or not project:
                fatal("--freeze-commit needs the ledger and the project file inside --root")
            why: list[str] = []
            resolved = git(self.root, "rev-parse", "--verify", "--end-of-options", f"{self.args.freeze_commit}^{{commit}}", why=why)
            if (resolved or "").strip() != self.args.freeze_commit:
                fatal(f"{self.args.freeze_commit} is no commit of this repository" + (f": {why[0]}" if why else ""))
            blob = git(self.root, "show", f"{self.args.freeze_commit}:./{ledger}")
            if blob is None:
                fatal(f"cannot read {ledger} at {self.args.freeze_commit}")
            try:
                baseline = as_dict(json.loads(blob))
            except (ValueError, RecursionError) as error:
                fatal(f"{ledger} at {self.args.freeze_commit} is not JSON: {error.__class__.__name__}")
            self.frozen_paths(self.root, ledger, project)
        for key in ("schema", "system"):
            if baseline.get(key) != self.doc.get(key):
                self.add(None, "frozen-ledger-changed", f"{key} differs from the frozen ledger")
        for section in ("fences", "invariants", "scenarios"):
            now = rows_by_id(self.doc.get(section))
            for raw in as_list(baseline.get(section)):
                old = as_dict(raw)
                new = now.pop(row_id(old) or "", None)
                if new is None:
                    self.add(row_id(old), "frozen-row-removed", f"the {section} row existed at the freeze")
                elif row_digest(old) != row_digest(new):
                    self.add(row_id(old), "frozen-row-changed", "a frozen row changes only in status")
            for ident, row in now.items():
                if section != "scenarios" or "parent" not in row:
                    self.add(ident, "unfrozen-row",
                             f"a {section} row added after the freeze goes to the owner; only a derived scenario "
                             "with a parent may be added")
        kept = [json.dumps(entry, sort_keys=True) for entry in as_list(self.doc.get("excluded"))]
        for entry in as_list(baseline.get("excluded")):
            if json.dumps(entry, sort_keys=True) not in kept:
                self.add("excluded", "frozen-exclusion-removed", f"{as_dict(entry).get('property')!r} was listed at the freeze")

    def frozen_paths(self, root: Path, ledger: str, project: str) -> None:
        """Compare the bytes on disk with the blobs of the freeze commit, under the freeze commit's own path list."""
        commit = self.args.freeze_commit
        blob = git(root, "show", f"{commit}:./{project}")
        if blob is None:
            fatal(f"cannot read {project} at {commit}")
        listed = yaml_list(blob, "frozen_paths")
        for entry in listed:
            if not inside(entry):
                self.add(entry, "frozen-path-outside-root", f"{project} at {commit} lists a path outside the repository")
        paths = [entry for entry in listed if inside(entry)]
        if not paths:
            self.add("project", "no-frozen-paths", f"{project} at {commit} lists no frozen path")
            return
        listing = git(root, "ls-tree", "-r", "-z", commit, "--", *paths) or ""
        blobs = {entry.split("\t", 1)[1]: entry.split()[2] for entry in listing.split("\0") if "\t" in entry}
        modes = {entry.split("\t", 1)[1]: entry.split()[0] for entry in listing.split("\0") if "\t" in entry}
        for entry in paths:
            if not any(under(path, [entry]) for path in blobs):
                self.add(entry, "frozen-path-empty", f"the entry matches no file at {commit}, so it freezes nothing")
        present: set[str] = set()
        unread: list[str] = []
        for entry in paths:
            target = root / entry
            above = [part for part in reversed(Path(entry).parents) if part.parts]
            through = next((part for part in above if (root / part).is_symlink()), None)
            if through is not None:
                self.add(entry, "frozen-path-changed", f"{through.as_posix()} is a symbolic link, so the entry is no longer the frozen tree")
                unread.append(entry)
                continue
            if target.is_symlink() and entry.rstrip("/") not in blobs:
                self.add(entry.rstrip("/"), "frozen-path-changed", f"the frozen directory is now a symbolic link, so it differs from {commit}")
                unread.append(entry)
                continue
            if target.is_symlink() or target.is_file():
                present.add(entry.rstrip("/"))
                continue
            for folder, folders, files in os.walk(target):
                linked = [name for name in folders if (Path(folder) / name).is_symlink()]
                present.update((Path(folder) / name).relative_to(root).as_posix() for name in files + linked)
        for path in sorted(set(blobs) | present):
            if path == ledger or under(path, unread):
                continue
            if blob_id(root / path, blobs.get(path, "")) != blobs.get(path, "absent at the freeze") \
                    or tree_mode(root / path) != modes.get(path):
                self.add(path, "frozen-path-changed", f"the file differs from {commit}")
        frozen: dict[str, str | None] = {}
        unfrozen: set[tuple[str, str]] = set()
        for run in self.runs:
            for stem, receipt in run["receipts"].items() if run["usable"] else ():
                for kind in ("judge", "harness"):
                    for path, digest in as_dict(receipt.get(kind)).items():
                        if path not in blobs:
                            unfrozen.add((path, kind))
                            continue
                        if path not in frozen:
                            data = git_bytes(root, "cat-file", "blob", blobs[path])
                            frozen[path] = hashlib.sha256(data).hexdigest() if data is not None else None
                        if frozen[path] != digest:
                            self.add(run["id"], "stale-receipt", f"{stem}: {path} differed from {commit} when it produced the receipt")
        for path, kind in sorted(unfrozen):
            self.add(path, f"{kind}-not-frozen", f"a receipt names this file as its {kind} and {commit} froze no such file")

def validate(args: argparse.Namespace, doc: dict) -> Checker:
    checker = Checker(doc, args)
    checker.shape()
    checker.fences()
    checker.invariant_rows()
    checker.scenario_rows()
    checker.excluded()
    if args.project:
        checker.project()
    if args.receipts:
        checker.receipts()
    if args.frozen or args.freeze_commit:
        checker.freeze()
    return checker


def cell(value: object) -> str:
    """One line of plain text for the claim: whitespace collapsed, table and heading characters escaped."""
    flat = " ".join(str(value).split())
    return flat.replace("\\", "\\\\").replace("|", "\\|").replace("#", "\\#").replace("<", "&lt;")


def claim(args: argparse.Namespace, doc: dict, summaries: dict[str, str]) -> str:
    """Render READINESS.md. Every sentence comes from a ledger field, a project.yaml list or the receipts."""
    project = Path(args.project).read_text(encoding="utf-8")
    scenarios = [as_dict(row) for row in doc["scenarios"]]
    invariants = {row["id"]: row for row in doc["invariants"]}
    counts = {status: sum(row["status"] == status for row in scenarios) for status in STATUSES}
    lines = [f"# Readiness claim: {cell(doc['system'])}", "",
             "Generated from `chaos/ledger.json`, `chaos/project.yaml` and the receipts. Edit those and render again.", "",
             f"{counts['held'] + counts['fixed']} of {len(scenarios)} scenarios held on the copy under test: "
             f"{counts['held']} held, {counts['fixed']} held after a fix, {counts['broken']} broken, {counts['open']} open.",
             "", "## Scenarios", "",
             "| Id | Scenario | Status | Live runs | Load | Fault | Invariants checked | Held runs required |",
             "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for row in scenarios:
        load_row = row["load"]
        ident = f"`{row['id']}`" + (f", derived from `{row['parent']}`" if "parent" in row else "")
        lines.append(f"| {ident} | {cell(row['text'])} | {row['status']} | "
                     f"{cell(summaries.get(row['id'], 'not compared with receipts'))} | "
                     f"{load_row['multiple']} times {cell(load_row['reference'])} | {cell(row['fault']['kind'])} | "
                     f"{', '.join(f'`{name}`' for name in row['invariants'])} | {row['runs_required']} |")
    lines += ["", "## Invariants", "",
              "| Id | Property | Kind | Agreed by | Threshold | Control |", "| --- | --- | --- | --- | --- | --- |"]
    for row in invariants.values():
        threshold = as_dict(row.get("threshold"))
        shown = ", ".join(f"{key} {value}" for key, value in threshold.items() if number(value)) or "none"
        lines.append(f"| `{row['id']}` | {cell(row['property']['text'])} | {row['kind']} | {row['property']['agreed']} | "
                     f"{cell(shown)} | {row['control']['kind']} |")
    lines += ["", "## Fences", ""]
    lines += [f"- `{row['id']}`: {cell(row['text'])} Enforced by: {cell(row['enforced_by'])}" for row in doc["fences"]]
    lines += ["", "## What this claim does not show", ""]
    lines += [f"- The copy differs from production: {cell(item)}" for item in yaml_list(project, "differs_from_production")]
    lines += [f"- Out of scope by the owner's answer: {cell(item)}" for item in yaml_list(project, "out_of_scope")]
    lines += [f"- `{row['id']}` is {row['status']} and carries no hold." for row in scenarios
              if row["status"] in ("open", "broken")]
    lines += [f"- The control for `{row['id']}` is edited evidence. It shows the judge can report broken. "
              "It does not show that a run can reach the defect." for row in invariants.values()
              if row["control"]["kind"] == "seeded-evidence"]
    lines += [f"- {cell(entry['property'])} ({entry['reason']}): {cell(entry['detail'])}" for entry in as_list(doc.get("excluded"))]
    lines += ["", "## Trusted base", ""]
    lines += [f"- {cell(item)}" for item in yaml_list(project, "trusted_base")]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a chaos campaign contract and render its readiness claim.")
    parser.add_argument("ledger")
    parser.add_argument("--root", help="repository root: check judge scripts, receipt digests and frozen paths against the tree")
    parser.add_argument("--project", help="chaos/project.yaml")
    parser.add_argument("--receipts", help="directory of judge and probe receipts: check every status against them")
    parser.add_argument("--build", help="full digest of the build now on the copy, as the harness records it: "
                                        "a status about another build is a finding")
    group = parser.add_argument_group("freeze").add_mutually_exclusive_group()
    group.add_argument("--freeze-commit", metavar="FULL-ID",
                       help="compare rows and frozen paths with this commit, which the owner names by its full id")
    group.add_argument("--frozen", help="compare rows with a saved copy of the frozen ledger")
    output = parser.add_argument_group("claim").add_mutually_exclusive_group()
    output.add_argument("--claim", action="store_true", help="print READINESS.md for a valid contract")
    output.add_argument("--check-claim", metavar="FILE", help="report a READINESS.md that differs from what --claim prints")
    args = parser.parse_args()
    if args.freeze_commit and not (args.root and args.project):
        fatal("--freeze-commit needs --root and --project: the frozen paths are read from the project file")
    if args.freeze_commit and not COMMIT.match(args.freeze_commit):
        fatal("--freeze-commit takes the full id of the freeze commit, 40 or 64 hexadecimal digits: a tag, a branch "
              "and a short id can each come to name another commit")
    if (args.claim or args.check_claim) and not args.project:
        fatal("a claim needs --project: it prints the differences from production and the trusted base")
    if args.receipts and not Path(args.receipts).is_dir():
        fatal(f"--receipts must name a directory: {args.receipts}")
    if args.root:
        root = Path(args.root).resolve()
        for label, path in (("the ledger", args.ledger), ("--project", args.project)):
            if path and root not in Path(path).resolve().parents:
                fatal(f"{label} must be a file inside --root: {path}")
        if args.receipts and root not in Path(args.receipts).resolve().parents:
            fatal(f"--receipts must name a directory inside --root, reached through no link that leaves it: {args.receipts}")
    doc = load(args.ledger)
    checker = validate(args, doc)
    if not checker.findings and args.check_claim:
        try:
            written = Path(args.check_claim).read_text(encoding="utf-8")
        except (OSError, ValueError) as error:
            fatal(f"cannot read {args.check_claim}: {error}")
        if written != claim(args, doc, checker.summaries):
            checker.add("claim", "stale-claim", f"{args.check_claim} differs from the claim this contract renders")
    if checker.findings:
        stream = sys.stderr if args.claim else sys.stdout
        stream.write("".join(line.encode("utf-8", "backslashreplace").decode("utf-8") + "\n" for line in checker.findings))
        return 1
    if args.claim:
        sys.stdout.write(claim(args, doc, checker.summaries))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Exception, RecursionError) as error:
        fatal(f"the check itself failed and decided nothing: {error.__class__.__name__}: {str(error)[:200]}")
