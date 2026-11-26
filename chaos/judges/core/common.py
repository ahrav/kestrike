"""The shared module of the chaos judges: exit codes, the run-record reader, the campaign reads and the receipt writer.

A judge decides one ledger row from one run's evidence directory, by the verdict mapping from a
`campaign` sweep's records, and never contacts the copy:

    exit 0  held        the evidence is complete and the row's check passed
    exit 1  broken      the evidence is complete and the row's check failed
    exit 2  invalid     the evidence supports no verdict, or the judge itself failed
    exit 3  incomplete  the run stopped before its evidence was complete

A judge starts as `python3 -I -B <judge file> <row-id> --evidence <run directory> [--receipt FILE]`.
It loads this file by its path, reads the ledger `chaos/ledger.json` of its own tree, its own row,
the scenario row the run names and the evidence directory, and nothing else. It writes a receipt
only when --receipt names one, and only into a directory under chaos/receipts/ of its own tree.

The interface below is fixed. A judge of a later family lives in a directory of its own under
chaos/judges/, imports this file and nothing else of chaos/judges/core/, and its receipt's `judge`
map then names every file of both directories:

    HELD, BROKEN, INVALID, INCOMPLETE   the exit codes; OUTCOMES maps each to its word
    WALL_CLOCK_KEYS                     the status keys a judge never reads
    EVIDENCE_BYTES, LEDGER_BYTES, SOURCE_BYTES
                                        the most bytes one evidence file, the ledger and one judge file may hold
    Verdict(code, detail)               raised to leave a judge with a decided exit and its detail
    row_digest(row)                     SHA-256 of a ledger row without its status, as the validator computes it
    rule_digest(text)                   SHA-256 of a rule text, as a failure identity carries it
    identity(key)                       a suspect key read as (class, obligation code, rule digest)
    minimum(row, group, key)            a count minimum of a row: an integer of at least 1
    count(entry, key, what)             a count of a campaign record: an integer of at least 0
    scenario_profiles(scenario)         the ordered sweep list of a scenario row, from load.reference; a weighted
                                        row names a profile more than once
    distinct(profiles)                  the names of a profile list once each, in the order they first stand
    scenario_counts(scenario)           the counts a scenario row sets, each load parameter named count_<key>
    Evidence(directory)                 the run record and the evidence files, each read once, as recorded
    recorded_exit(evidence)             the recorded exit of campaign sweep, 0 or 1, or the verdict it gives
    declaration(evidence, profile)      a swept profile's recorded fails line, parsed: None, ("violation", code,
                                        rule) or ("unsuccessful", None, witness)
    kinds(evidence, status, profile)    whether a swept profile is a declared-failure history and a cluster profile
    recorded(scenario, evidence)        the status document of a run whose records agree with each other and with the row
    trusted(scenario, evidence)         recorded, and the core rules a verdict rests on: no totals flag, exit 0, a sound
                                        control, no missed run
    held(scenario, evidence, status)    the detail of a valid run, from the status trusted returned, or the Verdict
    validity(scenario, evidence)        trusted, then held: the detail of a valid run, or the Verdict that makes it
                                        invalid or incomplete
    main(section, decide)               the judge's whole life: start, read, decide, report, receipt

Every function that takes an Evidence reads a run record that `Evidence.check` accepted first:
`main` runs that check before `decide`, and a direct caller runs it itself.

A judge checks its start (`-I -B`), refuses a link or a directory beside it or in this
directory, and runs this file from the bytes it read and hashed, compiled into a module of its
own, so no bytecode cache and no module search path takes part. The loader block of validity.py
is the one each judge copies; it sets LOADED_SHA256, which `main` compares with the digest the
receipt names.

`decide(row, scenario, evidence)` returns (code, detail) or raises Verdict. Every path out of a
judge that is not a decided check exits 2 or 3, including an exception while the verdict is printed
or the receipt is written. Each number a judge compares a count with stands in a ledger row; the
judges compare counts by predicate, and the byte bounds above refuse a file too large to read.
Agreement between the counts of one status document shows that the document is consistent; it
shows nothing about a document written consistently by someone other than the sweep.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import math
import os
import platform
import re
import stat
import sys
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any, NamedTuple

HELD, BROKEN, INVALID, INCOMPLETE = 0, 1, 2, 3
OUTCOMES = {HELD: "held", BROKEN: "broken", INVALID: "invalid", INCOMPLETE: "incomplete"}
WALL_CLOCK_KEYS = frozenset({"elapsed_s", "runs_per_s", "operations_per_s", "busy_us"})
EVIDENCE_BYTES = 1 << 28
LEDGER_BYTES = 1 << 24
SOURCE_BYTES = 1 << 22
SWEEP_FLAGS = ("alarm", "no_pass", "unreached")
CORE = Path(__file__).resolve().parent
CHAOS = CORE.parents[1]
ROOT = CHAOS.parent
STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
HEX = re.compile(r"[0-9a-f]+")
DIGEST = re.compile(r"[0-9a-f]{64}")
NAME = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")
COUNT_KEY = re.compile(r"[a-z0-9_]+")
DECIMAL = re.compile(r"0|[1-9][0-9]*")
COUNT_PREFIX = "count_"
LOAD_KEYS = frozenset({"reference", "multiple", "workers", "batch_s", "for_s"})
U64_MAX = (1 << 64) - 1
U32_MAX = (1 << 32) - 1


def warn(text: str) -> None:
    """One line on standard error, written by one system call; a closed standard error loses the line and nothing else."""
    with contextlib.suppress(OSError):
        os.write(2, f"{text}\n".encode("utf-8", "backslashreplace"))


class Verdict(Exception):
    """Raised to leave a judge with a decided exit code and its detail line."""

    def __init__(self, code: int, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def row_digest(row: dict) -> str:
    """Digest of a ledger row without its status: sorted keys, separators `,` and `:`, ASCII escapes."""
    kept = {key: value for key, value in row.items() if key != "status"}
    return hashlib.sha256(json.dumps(kept, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def rule_digest(text: str) -> str:
    """The SHA-256 of a rule text's bytes, the digest a version 2 failure identity carries."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def stamp(value: object) -> bool:
    """True for a UTC time written as 2026-11-20T22:58:00Z, with every field padded."""
    if not isinstance(value, str) or not STAMP.fullmatch(value):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def same(left: object, right: object) -> bool:
    """Equality of two JSON values by their canonical text, so true differs from 1 and 1.0 from 1."""
    return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)


def unique(pairs: list[tuple[str, Any]]) -> dict:
    """A JSON object's members as a dict; a name that stands twice in one object raises ValueError."""
    value: dict = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"the member {key[:80]!r} stands twice in one object")
        value[key] = item
    return value


def parse(data: bytes) -> object:
    """One JSON document from UTF-8 bytes, each object's member names once; other bytes raise ValueError."""
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique)
    except RecursionError:
        raise ValueError("the document nests deeper than the parser reads") from None


def read_regular(path: str | Path, bound: int, dir_fd: int | None = None) -> bytes:
    """The bytes of a regular file opened without following a link at its name and without blocking.

    Any other file, and a file of more than `bound` bytes, raises OSError; the bound applies to the
    bytes read, whatever the file's size said before.
    """
    handle = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    with os.fdopen(handle, "rb") as file:
        if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
            raise OSError(f"{os.fspath(path)} is no regular file")
        data = file.read(bound + 1)
    if len(data) > bound:
        raise OSError(f"{os.fspath(path)} holds more than {bound} bytes")
    return data


def identity(key: str) -> tuple[str, int | None, str | None]:
    """A suspect key of `suspect_keys` read as its class, and for a version 2 violation its obligation and rule digest.

    The key is `<class>: <identity>`. A violation's identity is 88 lowercase hexadecimal digits:
    version 02, variant 01 or 02, the obligation code in digits 5 and 6 and the rule's SHA-256 in
    digits 15 to 78, as the supervisor's control table reads it. Variant 04, an audit identity,
    reads as obligation 0 with no rule digest: it is under no rule row. Any other key gives no code
    and no digest, and a violation key of that form is one whose rule the judge cannot read.
    """
    cls, _, rest = key.partition(": ")
    if cls == "violation" and len(rest) == 88 and HEX.fullmatch(rest) and rest[:2] == "02":
        if rest[2:4] in ("01", "02"):
            return cls, int(rest[4:6], 16), rest[14:78]
        if rest[2:4] == "04":
            return cls, 0, None
    return cls, None, None


def minimum(row: dict, group: str, key: str) -> int:
    """A minimum count that a row sets for its check: an integer of at least 1.

    Every run meets a minimum of 0 or less, so a check against one passes every run.
    """
    held = row.get(group)
    value = held.get(key) if isinstance(held, dict) else None
    if type(value) is not int or value < 1:
        raise Verdict(INVALID, f"{row.get('id')}: {group}.{key} is {value!r}: a minimum is an integer of at least 1")
    return value


def count(entry: object, key: str, what: str) -> int:
    """A count of a campaign record: an integer of at least 0. Any other value makes the record unreadable."""
    value = entry.get(key) if isinstance(entry, dict) else None
    if type(value) is not int or value < 0:
        raise Verdict(INVALID, f"{what} records {key} as {value!r}, which is no count")
    return value


def scenario_profiles(scenario: dict) -> list[str]:
    """The scenario's ordered sweep list: load.reference up to its first `;`, a comma-separated list of profile names.

    A weighted row names a profile more than once, and the list keeps every name as --profiles takes
    it; `distinct` gives each name once.
    """
    load = scenario.get("load")
    reference = load.get("reference") if isinstance(load, dict) else None
    names = [name.strip() for name in reference.split(";", 1)[0].split(",")] if isinstance(reference, str) else []
    if not names or not all(NAME.fullmatch(name) for name in names):
        raise Verdict(INVALID, f"{scenario.get('id')}: load.reference names no profile set before its first `;`")
    return names


def distinct(profiles: list[str]) -> list[str]:
    """Each name of a profile list once, in the order it first stands."""
    return list(dict.fromkeys(profiles))


def scenario_counts(scenario: dict) -> dict[str, int]:
    """The counts a scenario row sets, as the harness passes and records them: each load parameter named count_<key>.

    The key is lowercase letters, digits and underscores and the value an integer of at least 0. A
    load parameter that is neither one of LOAD_KEYS nor a count, a near miss such as counts_restarts
    included, is one no sweep reads, so the row is refused.
    """
    load = scenario.get("load")
    if not isinstance(load, dict):
        raise Verdict(INVALID, f"{scenario.get('id')}: load is no object")
    counts = {}
    for name, value in load.items():
        if name in LOAD_KEYS:
            continue
        key = name[len(COUNT_PREFIX):] if name.startswith(COUNT_PREFIX) else ""
        if not COUNT_KEY.fullmatch(key) or type(value) is not int or value < 0:
            raise Verdict(INVALID, f"{scenario.get('id')}: load.{name} is {value!r}; a load parameter is one of "
                                   f"{', '.join(sorted(LOAD_KEYS))} or count_<key> with a whole number of at least 0")
        counts[key] = value
    return counts


def finite(value: object) -> bool:
    """True for an integer or a finite float, and never for a boolean."""
    return type(value) is int or (type(value) is float and math.isfinite(value))


def without_wall_clock(value: object) -> object:
    """The value with every key of WALL_CLOCK_KEYS removed at any depth."""
    if isinstance(value, dict):
        return {key: without_wall_clock(item) for key, item in value.items() if key not in WALL_CLOCK_KEYS}
    if isinstance(value, list):
        return [without_wall_clock(item) for item in value]
    return value


class Evidence:
    """One run's evidence directory, each file read once, as recorded.

    The directory is opened once without following a link at its name, listed once, and every file
    is opened relative to it, without following a link and without blocking; a file is read only
    when the listing holds it as a regular file of at most EVIDENCE_BYTES bytes. A name the listing
    lacks reads as absent. The receipt's `evidence` map names every entry of that listing, a link
    with no digest, and each digest is of the bytes the judge read: a parsed file is hashed as it is
    read, the others once, at the receipt. Each file is bound to its bytes; the files are not read
    at one instant.
    """

    def __init__(self, directory: Path) -> None:
        self.directory = Path(directory)
        self.name = os.path.basename(os.path.normpath(os.path.abspath(self.directory)))
        self.run: dict = {}
        self.problem: Verdict | None = None
        self._digests: dict[str, str] = {}
        self._refused: set[str] = set()
        self._parsed: dict[str, Any] = {}
        missing = Verdict(INCOMPLETE, "the run wrote no run.json, so it stopped before campaign started")
        try:
            self._fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except FileNotFoundError:
            raise missing from None
        except OSError as error:
            raise Verdict(INVALID, f"the evidence directory is no directory of its own, or is a link: "
                                   f"{error.__class__.__name__}") from None
        try:
            entries = sorted(os.scandir(self._fd), key=lambda entry: entry.name)
            self._regular = [entry.name for entry in entries if entry.is_file(follow_symlinks=False)]
            self._links = [entry.name for entry in entries if entry.is_symlink()]
        except OSError as error:
            raise Verdict(INVALID, f"the evidence directory is unreadable: {error.__class__.__name__}") from None
        other = next((entry.name for entry in entries if entry.name not in self._regular), None)
        if other is not None:
            self.problem = Verdict(INVALID, f"the evidence directory holds {other!r}, which is no regular file")
        if not any(entry.name == "run.json" for entry in entries):
            raise missing
        if "run.json" not in self._regular:
            raise Verdict(INVALID, "the evidence directory's run.json is no regular file")
        self.run = self._json("run.json", INCOMPLETE, missing.detail)

    def _read(self, name: str) -> bytes:
        """The bytes of one listed regular file, hashed as they are read; a name the listing lacks raises FileNotFoundError."""
        if name not in self._regular:
            raise FileNotFoundError(name)
        try:
            data = read_regular(name, EVIDENCE_BYTES, dir_fd=self._fd)
        except OSError:
            self._refused.add(name)
            raise
        self._digests.setdefault(name, hashlib.sha256(data).hexdigest())
        return data

    def _json(self, name: str, missing: int, reason: str) -> dict:
        if name not in self._parsed:
            try:
                value = parse(self._read(name))
            except FileNotFoundError:
                raise Verdict(missing, reason) from None
            except (OSError, ValueError, RecursionError) as error:
                raise Verdict(INVALID, f"{name} is unreadable: {error.__class__.__name__}: {str(error)[:120]}") from None
            if not isinstance(value, dict):
                raise Verdict(INVALID, f"{name} is not a JSON object")
            self._parsed[name] = value
        return self._parsed[name]

    def _lines(self, name: str) -> list:
        """The parsed records of a JSON-lines evidence file, each framed by a line feed, blank lines left out.

        A file whose last record lacks its line feed was cut while it was written, so it is unreadable.
        """
        if name not in self._parsed:
            try:
                data = self._read(name)
                if data and not data.endswith(b"\n"):
                    raise ValueError("its last record has no line feed")
                self._parsed[name] = [parse(frame) for frame in data.split(b"\n")[:-1] if frame.strip()]
            except (OSError, ValueError, RecursionError) as error:
                raise Verdict(INVALID, f"{name} is unreadable: {error.__class__.__name__}: {str(error)[:120]}") from None
        return self._parsed[name]

    def check(self, scenario: dict) -> None:
        """The run record is well formed, marks a run that ended by itself, is a run of the scenario row as it stands,
        and records each command's exit the evidence calls for.

        The checks run in that order, so a well-formed record of a stopped run is incomplete even when
        the row changed since, and the detail names the first one that fails. A record of a sweep that
        returned 0 or 1 also needs the listing, sweep-status, confirm and findings each to have exited 0,
        confirm to have emptied its dispatch queue, and the campaign binary's digest after the last
        command to equal its digest before the first. Equal digests show the endpoints agree; they do
        not show the binary between them.
        """
        if self.problem is not None:
            raise self.problem
        run = self.run
        if run.get("run_id") != self.name:
            raise Verdict(INVALID, f"run.json names run {run.get('run_id')!r} and sits in {self.name!r}")
        fields = (
            ("schema 1", type(run.get("schema")) is int and run["schema"] == 1),
            ("scenario", isinstance(run.get("scenario"), str) and bool(run.get("scenario"))),
            ("system_build", isinstance(run.get("system_build"), str) and bool(DIGEST.fullmatch(run["system_build"]))),
            ("campaign, which is the run id", run.get("campaign") == self.name),
            ("mode, live or control", run.get("mode") in ("live", "control")),
            ("defect", isinstance(run.get("defect"), str) and (not run.get("defect") or bool(NAME.fullmatch(run["defect"])))),
            ("harness", isinstance(run.get("harness"), dict) and bool(run.get("harness"))),
            ("started", stamp(run.get("started"))),
            ("counts", isinstance(run.get("counts"), dict)),
            ("profiles", isinstance(run.get("profiles"), list) and bool(run.get("profiles"))
             and all(isinstance(profile, str) and NAME.fullmatch(profile) for profile in run["profiles"])),
        )
        missing = next((field for field, present in fields if not present), None)
        if missing is not None:
            raise Verdict(INVALID, f"run.json lacks its {missing}")
        if (run["mode"] == "live") == bool(run["defect"]):
            raise Verdict(INVALID, f"run.json records mode {run['mode']} with the defect {run['defect']!r}; "
                                   "a live run names no defect and a control names one")
        if run.get("complete") is not True:
            raise Verdict(INCOMPLETE, "run.json does not mark the run complete: campaign sweep did not return by itself "
                                      "or the evidence was not written")
        if run.get("deadline_fired") is not False or run.get("signal") is not None:
            raise Verdict(INCOMPLETE, f"the run was stopped: deadline fired {run.get('deadline_fired')!r}, "
                                      f"signal {run.get('signal')!r}")
        recorded_exit(self)
        if run.get("scenario_row") != row_digest(scenario):
            raise Verdict(INVALID, "the scenario row differs from the row the run started with")
        binary = run.get("campaign_binary")
        lifecycle = [(f"campaign {name} exited {run.get(key)!r}", type(run.get(key)) is int and run[key] == 0)
                     for name, key in (("sim capabilities", "listing_exit"), ("sweep-status", "status_exit"),
                                       ("confirm", "confirm_exit"), ("findings", "findings_exit"))]
        lifecycle += [
            (f"campaign confirm reported dispatch {run.get('confirm_dispatch')!r}", run.get("confirm_dispatch") == "queue_empty"),
            ("the campaign binary hashed otherwise after the last command than before the first",
             isinstance(binary, dict) and isinstance(binary.get("sha256"), str) and bool(DIGEST.fullmatch(binary["sha256"]))
             and binary.get("sha256_after") == binary["sha256"] and binary.get("source_sha256_after") == binary["sha256"]),
        ]
        failed = next((text for text, holds in lifecycle if not holds), None)
        if failed is not None:
            raise Verdict(INVALID, f"run.json marks the run complete and {failed}")

    def status(self) -> dict:
        """The copy of `campaign sweep-status`, without its wall-clock keys. An empty or partial document is unreadable."""
        refusal = self.run.get("status_refusal")
        status = self._json("sweep-status.json", INVALID,
                            f"the run has no sweep-status.json; campaign sweep-status exited "
                            f"{self.run.get('status_exit')!r}: {str(refusal)[:200]}")
        if not isinstance(status.get("profiles"), dict) or not isinstance(status.get("campaign"), str):
            raise Verdict(INVALID, "sweep-status.json is unreadable: it names no campaign and no profiles")
        status = {key: without_wall_clock(value) for key, value in status.items() if key not in WALL_CLOCK_KEYS}
        if status.get("campaign") != self.run["campaign"] or not same(status.get("counts"), self.run["counts"]):
            raise Verdict(INVALID, f"the status names campaign {status.get('campaign')!r} with counts "
                                   f"{status.get('counts')!r}, and the run swept {self.run['campaign']!r} with "
                                   f"{self.run['counts']!r}")
        return status

    def suspects(self) -> list[dict]:
        """The copy of the root's suspects.jsonl: one listed suspect a line, each naming its key, profile, class, run and seed."""
        records = self._lines("suspects.jsonl")
        for record in records:
            if not isinstance(record, dict) or not all(isinstance(record.get(key), str) for key in ("key", "profile", "class")) \
                    or not all(type(record.get(key)) is int and record[key] >= 0 for key in ("run", "seed")):
                raise Verdict(INVALID, f"suspects.jsonl holds a line without its key, profile, class, run or seed: "
                                       f"{str(record)[:80]}")
        return records

    def findings(self) -> list[dict]:
        """The rows of the copy of `campaign findings` for the root's confirm state, each in one of the producer's two forms.

        A verified row holds its id, a `verified` record with its kind, and `resolved` and `blocker`
        flags; a held row holds its id, the `held` reason, its `held_code` and `blocker` true. Two rows
        of one form never share an id; a held row may share the id of a verified one.
        """
        findings = self._json("findings.json", INVALID, f"the run has no findings.json; campaign confirm exited "
                                                         f"{self.run.get('confirm_exit')!r} and campaign findings exited "
                                                         f"{self.run.get('findings_exit')!r}")
        rows = findings.get("findings")
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            raise Verdict(INVALID, "findings.json holds no list of findings")
        seen: set[tuple[str, str]] = set()
        for row in rows:
            if not isinstance(row.get("id"), str) or not row["id"]:
                raise Verdict(INVALID, "findings.json holds a finding without its id")
            verified = row.get("verified")
            if isinstance(verified, dict) and "held" not in row and isinstance(verified.get("kind"), str) \
                    and type(row.get("resolved")) is bool and type(row.get("blocker")) is bool:
                form = "verified"
            elif "verified" not in row and isinstance(row.get("held"), str) and isinstance(row.get("held_code"), str) \
                    and row.get("blocker") is True:
                form = "held"
            else:
                raise Verdict(INVALID, f"findings.json holds the finding {row['id'][:80]!r} in neither the verified "
                                       "nor the held form")
            if (form, row["id"]) in seen:
                raise Verdict(INVALID, f"findings.json holds two {form} findings {row['id'][:80]!r}")
            seen.add((form, row["id"]))
        return rows

    def history(self) -> dict[str, dict]:
        """The harness's history.jsonl by profile: each swept profile's campaign, counts, build and run range, once."""
        records = self._lines("history.jsonl")
        by_profile = {record["profile"]: record for record in records
                      if isinstance(record, dict) and isinstance(record.get("profile"), str)}
        if len(by_profile) != len(records) or sorted(by_profile) != sorted(set(self.run["profiles"])):
            raise Verdict(INVALID, "history.jsonl does not hold one line for each swept profile")
        return by_profile

    def read_digests(self) -> dict[str, str | None]:
        """The digests of the files read so far, and of each listed link, None, by name."""
        return dict(sorted({**dict.fromkeys(self._links), **self._digests}.items()))

    def digests(self) -> dict[str, str | None]:
        """The SHA-256 of each listed regular file, from the bytes this judge read, and None for each listed link.

        A listed file read here for the first time is read once, under the bound; a file that cannot
        be read raises OSError. A file whose read the verdict already refused stays out of the map.
        """
        for name in self._regular:
            if name not in self._digests and name not in self._refused:
                self._read(name)
        return self.read_digests()


def recorded_exit(evidence: Evidence) -> int:
    """The exit `campaign sweep` returned by itself, 0 or 1. A recorded 3 or 4 or a kill is incomplete, any other exit invalid.

    Exit 3 means another sweep held the root and exit 4 a held record, such as an archive that failed
    its closing verification; neither run's records describe the sweep it was asked for. A negative
    exit is a sweep a signal ended. Exit 2 means the sweep refused an argument or an input record and
    ran nothing.
    """
    code = evidence.run.get("sweep_exit")
    if type(code) is int and code in (3, 4):
        raise Verdict(INCOMPLETE, f"campaign sweep exited {code}, so the root's records are no complete sweep")
    if type(code) is int and code < 0:
        raise Verdict(INCOMPLETE, f"campaign sweep was ended by signal {-code}")
    if type(code) is not int or code not in (0, 1):
        raise Verdict(INVALID, f"campaign sweep exited {code!r}: it refused its arguments or an input record")
    return code


class Kinds(NamedTuple):
    """What the worker's listing says of one swept profile."""

    failing: bool  # a history that declares its failure
    cluster: bool  # a profile with a cluster declaration


def listing_line(evidence: Evidence, profile: str) -> dict:
    """The recorded listing line of a swept profile: its class, its cluster declaration and its fails line."""
    listing = evidence.run.get("listing")
    line = listing.get(profile) if isinstance(listing, dict) else None
    if not isinstance(line, dict) or not isinstance(line.get("class"), str) or not isinstance(line.get("cluster"), bool) \
            or not (line.get("fails") is None or isinstance(line.get("fails"), str)):
        raise Verdict(INVALID, f"run.json records no listing line for the swept profile {profile}")
    return line


def declaration(evidence: Evidence, profile: str) -> tuple[str, int | None, str] | None:
    """A swept profile's fails line as the worker's listing declares it, parsed; None when it declares none.

    A declaration is `violation <code> <rule>`, with an obligation code of 1 to 255 written without
    leading zeros, or `unsuccessful <witness>`, and only a profile of class history carries one. Any
    other fails line makes the run invalid.
    """
    line = listing_line(evidence, profile)
    fails = line["fails"]
    if fails is None:
        return None
    word, _, rest = fails.partition(" ")
    code, _, rule = rest.partition(" ")
    if line["class"] != "history":
        raise Verdict(INVALID, f"the listing declares a failure of {profile}, whose class is {line['class']!r}, not history")
    if word == "violation" and DECIMAL.fullmatch(code) and 0 < int(code) < 256 and rule:
        return "violation", int(code), rule
    if word == "unsuccessful" and rest:
        return "unsuccessful", None, rest
    raise Verdict(INVALID, f"the listing declares {profile}'s failure as {fails[:200]!r}, which is neither "
                           "`violation <code> <rule>` nor `unsuccessful <witness>`")


def kinds(evidence: Evidence, status: dict, profile: str) -> Kinds:
    """Whether a swept profile is a history that declares its failure, and whether it is a cluster profile.

    The worker's listing, which the harness records in run.json, says both: a `fails` line and a
    `cluster` declaration. A status entry whose `failing_history` marker disagrees with the listing
    either way contradicts it, and so does one whose `history` marker disagrees with the listing's
    class; the sweep leaves a false marker out, so an absent one reads as false.
    """
    line = listing_line(evidence, profile)
    failing = declaration(evidence, profile) is not None
    entry = status["profiles"].get(profile)
    if isinstance(entry, dict):
        marker, history = entry.get("failing_history", False), entry.get("history", line["class"] == "history")
        if type(marker) is not bool or marker != failing:
            raise Verdict(INVALID, f"the status marks {profile}'s failing_history {entry.get('failing_history')!r} and the "
                                   f"worker's listing {'declares' if failing else 'declares no'} failure of it")
        if type(history) is not bool or history != (line["class"] == "history"):
            raise Verdict(INVALID, f"the status marks {profile}'s history {entry.get('history')!r} and the worker's listing "
                                   f"gives it class {line['class']!r}")
    return Kinds(failing, line["cluster"])


def sweep_options(argv: object) -> tuple[dict[str, str], dict[str, int]]:
    """The options of the recorded `campaign sweep` command line, and its --set counts.

    Each option takes one value and stands once, except --set, whose keys stand once each with a
    whole number written as campaign reads one. Any other word refuses the command line.
    """
    singles = ("--root", "--archive", "--campaign", "--profiles", "--workers", "--batch", "--for")
    words = argv if isinstance(argv, list) and all(isinstance(word, str) for word in argv) else []
    if len(words) < 2 or words[1] != "sweep" or len(words) % 2:
        raise Verdict(INVALID, "run.json records no sweep command line of option and value pairs")
    options: dict[str, str] = {}
    sets: dict[str, int] = {}
    for index in range(2, len(words), 2):
        flag, value = words[index], words[index + 1]
        key, _, number = value.partition("=")
        if flag == "--set" and COUNT_KEY.fullmatch(key) and DECIMAL.fullmatch(number) and key not in sets:
            sets[key] = int(number)
        elif flag in singles and flag not in options:
            options[flag] = value
        else:
            raise Verdict(INVALID, f"the recorded sweep command repeats or holds an option no run passes: {flag} {value[:80]}")
    return options, sets


def swept_setup(scenario: dict, evidence: Evidence) -> None:
    """The run swept what the row sets: its workers, batch, --for, deadline, counts and profiles, as run.json and the
    sweep's command line record them, into the root and from the archive the record names.

    The command line's --set counts, the run record's counts and the row's counts are one map, each
    value a whole number. The command line holds --root and --archive, and each equals the path the
    record names. This shows the recorded command agrees with the row and the record; it does not
    show what the campaign binary ran.
    """
    run = evidence.run
    load: dict = scenario["load"] if isinstance(scenario.get("load"), dict) else {}
    counts = scenario_counts(scenario)
    profiles = scenario_profiles(scenario)
    allowed = [profiles] if run["mode"] == "live" else [profiles, [*profiles, run["defect"]]]
    options, sets = sweep_options(run.get("commands", {}).get("sweep") if isinstance(run.get("commands"), dict) else None)

    def agrees(key: str, flag: str) -> bool:
        value = run.get(key)
        return type(value) is int and same(value, load.get(key)) and options.get(flag) == str(value)

    def names(key: str, flag: str) -> bool:
        value = run.get(key)
        return isinstance(value, str) and bool(value) and options.get(flag) == value
    fields = (
        ("workers", agrees("workers", "--workers")),
        ("batch_s", agrees("batch_s", "--batch")),
        ("for_s", agrees("for_s", "--for")),
        ("deadline_s", same(run.get("deadline_s"), scenario.get("deadline_s"))),
        ("counts", same(run["counts"], counts) and same(sets, counts)),
        ("profiles", run["profiles"] in allowed and options.get("--profiles") == ",".join(run["profiles"])),
        ("campaign", options.get("--campaign") == run["campaign"]),
        ("root", names("root", "--root")),
        ("archive", names("archive", "--archive")),
    )
    differs = next((field for field, agreed in fields if not agreed), None)
    if differs is not None:
        raise Verdict(INVALID, f"run.json or the sweep's command line records a {differs} the scenario row does not set")


def entry_counts(profile: str, entry: dict) -> None:
    """A status entry's counts are ones a sweep writes: `covered` at most `pass`; `pass` and `caught` together at
    most `runs`, since a sweep counts each run under one ending; each caught_rules count at most `caught` and
    their sum too; and each reached event's runs at most `covered` and at most its total, which is at most its
    runs times 2^32 - 1. `replays` counts replay attempts, which no other count bounds."""
    what = f"profile {profile}"
    held = {name: count(entry, name, what) for name in ("runs", "pass", "covered", "caught", "replays") if name in entry}
    runs = held.get("runs", 0)
    rules = entry.get("caught_rules", {})
    if not isinstance(rules, dict):
        raise Verdict(INVALID, f"{what} records caught_rules as {rules!r}")
    buckets = [count(rules, name, what) for name in rules]
    caught = held.get("caught", 0)
    if held.get("pass", 0) + caught > runs or held.get("covered", 0) > held.get("pass", 0) \
            or any(bucket > caught for bucket in buckets) or sum(buckets) > caught:
        raise Verdict(INVALID, f"{profile} records counts no sweep writes: {json.dumps(held, sort_keys=True)}, "
                               f"caught_rules summing to {sum(buckets)}")
    reached = entry.get("reached", {})
    if not isinstance(reached, dict):
        raise Verdict(INVALID, f"{what} records reached as {reached!r}")
    for event, counts in reached.items():
        got = count(counts, "runs", f"{profile}'s reached.{event}")
        total = count(counts, "total", f"{profile}'s reached.{event}")
        if got > held.get("covered", 0):
            raise Verdict(INVALID, f"{profile} records {got} covered passes that reached {event}, more than its covered passes")
        if not got <= total <= got * U32_MAX:
            raise Verdict(INVALID, f"{profile} records {got} passes that reached {event} {total} times, which no sweep writes")


def uncredited(profile: str, entry: dict) -> int:
    """The runs of a status entry that ended unsuccessful or inconclusive: the sum of its `uncredited` counts by rule.

    Any other value than an object of counts makes the record unreadable.
    """
    rules = entry.get("uncredited")
    if not isinstance(rules, dict):
        raise Verdict(INVALID, f"profile {profile} records uncredited as {rules!r}")
    return sum(count(rules, rule, f"profile {profile}'s uncredited") for rule in rules)


def recorded(scenario: dict, evidence: Evidence) -> dict:
    """The status document of a run whose records agree with each other and with the row, or raise the Verdict that
    makes it invalid or incomplete.

    The records agree when `campaign sweep` returned by itself with exit 0 or 1 and the status's
    final elapsed time is finite and at least --for, which a sweep that an outside signal stopped
    within its last drain also reports; the sweep ran what the row sets; the root holds the
    archive's build and the archive verified after the sweep; no process was left in a cgroup
    under the run's cgroup root; the status names the run's campaign and counts, each of its profile entries
    holds a boolean control marker, positive suspect_keys counts that sum to its `suspects` and
    counts a sweep writes (`entry_counts`), and its controls totals equal the sums over the entries
    marked as controls: their number, their runs, their caught and missed runs, and their
    uncredited runs, which the totals hold as `no_effect` and `other`;
    run.json's run ranges and history.jsonl agree with the status and hold room for each profile's
    runs; each listed suspect is a run of this campaign, build and counts, under a key its profile
    counts at least as often as the copy lists it, `other` included, and of that key's class; no
    profile of the root,
    a control or a rotating history included, lists or counts a suspect of class `replay
    differs`, or counts more suspects under `other` than it lists distinct lines; and the finding
    copy is readable. A later judge family whose verdict does not rest on the core rules of
    `trusted` starts from here.
    """
    run = evidence.run
    recorded_exit(evidence)
    if run.get("root_build") != run["system_build"]:
        raise Verdict(INVALID, f"the root names build {run.get('root_build')!r} and the archive's build is {run['system_build']}")
    restored = run.get("restored")
    if not isinstance(restored, dict) or type(restored.get("left_a_process")) is not int \
            or restored["left_a_process"] != 0 or restored.get("archive_verified") is not True \
            or run.get("archive_build_after") != run["system_build"]:
        raise Verdict(INVALID, f"restoration not shown: run.json records {restored!r}, and a valid run left no process "
                               "in a cgroup under its cgroup root and verified its archive after its last run")
    if not (finite(run.get("sweep_elapsed_s")) and type(run.get("for_s")) is int and run["sweep_elapsed_s"] >= run["for_s"]):
        raise Verdict(INVALID, f"run.json marks the run complete and the sweep's status records "
                               f"{run.get('sweep_elapsed_s')!r} s against a --for of {run.get('for_s')!r} s")
    swept_setup(scenario, evidence)
    status = evidence.status()
    entries = status["profiles"]
    for profile, entry in entries.items():
        if not isinstance(entry, dict) or type(entry.get("control")) is not bool \
                or not isinstance(entry.get("suspect_keys"), dict) \
                or not all(type(value) is int and value > 0 for value in entry["suspect_keys"].values()):
            raise Verdict(INVALID, f"the status's entry for {profile} has no control marker true or false, or no "
                                   "suspect_keys counts of at least 1")
        entry_counts(profile, entry)
        suspects, keyed = count(entry, "suspects", f"profile {profile}"), sum(entry["suspect_keys"].values())
        if suspects != keyed:
            raise Verdict(INVALID, f"{profile} counts {suspects} suspects and {keyed} under its suspect_keys, "
                                   "and a sweep counts each suspect once in both")
    marked = {profile: entry for profile, entry in entries.items() if entry["control"]}
    totals = status.get("controls")
    reported = [count(totals, key, "the status's controls") for key in ("profiles", "runs", "caught", "missed")]
    reported.append(min(sum(count(totals, key, "the status's controls") for key in ("no_effect", "other")), U64_MAX))
    summed = [len(marked), *(min(sum(count(entry, key, "a control") for entry in marked.values()), U64_MAX)
                             for key in ("runs", "caught", "missed")),
              min(sum(uncredited(profile, entry) for profile, entry in marked.items()), U64_MAX)]
    if reported != summed:
        raise Verdict(INVALID, f"the status's controls count {reported[0]} profiles, {reported[1]} runs, {reported[2]} "
                               f"caught, {reported[3]} missed and {reported[4]} with no effect or another ending, and its "
                               f"entries marked as controls hold {', '.join(str(value) for value in summed)}")
    history = evidence.history()
    ranges = run.get("runs")
    if not isinstance(ranges, dict) or sorted(ranges) != sorted(distinct(run["profiles"])):
        raise Verdict(INVALID, "run.json's run ranges name other profiles than the swept ones")
    for profile in distinct(run["profiles"]):
        line, entry = history[profile], entries.get(profile)
        spans = [line.get("runs"), ranges[profile]]
        cursor = count(entry, "next", f"profile {profile}")
        fields = (("campaign", line.get("campaign") == run["campaign"]), ("counts", same(line.get("counts"), run["counts"])),
                  ("build", line.get("build") == run["system_build"]),
                  ("first run", all(isinstance(span, dict) and count(span, "first", profile) == 0 for span in spans)),
                  ("next run", all(count(span, "next", profile) == cursor and sorted(span) == ["first", "next"]
                                   for span in spans)),
                  ("room for its runs", count(entry, "runs", f"profile {profile}") <= cursor))
        differs = next((field for field, agrees in fields if not agrees), None)
        if differs is not None:
            raise Verdict(INVALID, f"history.jsonl's line for {profile} disagrees with the run record or the status on its {differs}")
    lines = evidence.suspects()
    listed: dict[tuple[str, str], int] = {}
    others: dict[str, set[str]] = {}
    for line in lines:
        entry = entries.get(line["profile"])
        if line.get("campaign") != run["campaign"] or line.get("build") != run["system_build"] \
                or not same(line.get("counts"), run["counts"]) or not isinstance(entry, dict) \
                or not line["run"] < count(entry, "next", f"profile {line['profile']}"):
            raise Verdict(INVALID, f"suspects.jsonl lists run {line['run']} of {line['profile']} under another campaign, "
                                   "build, counts or run range than this run's")
        place = (line["profile"], line["key"])
        listed[place] = listed.get(place, 0) + 1
        if line["key"] == "other":
            others.setdefault(line["profile"], set()).add(json.dumps(line, sort_keys=True))
        elif identity(line["key"])[0] != line["class"]:
            raise Verdict(INVALID, f"suspects.jsonl lists a suspect of class {line['class'][:80]!r} under the key "
                                   f"{line['key'][:120]!r} of another class")
        if entry["suspect_keys"].get(line["key"], 0) < listed[place]:
            raise Verdict(INVALID, f"suspects.jsonl lists {listed[place]} suspects of {line['profile']} under "
                                   f"{line['key'][:120]!r}, and the status counts {entry['suspect_keys'].get(line['key'], 0)}")
    differing = sorted(f"{profile}: {key}" for profile, entry in entries.items()
                       for key in entry["suspect_keys"] if identity(key)[0] == "replay differs")
    differing += sorted(f"{line['profile']}: {line['key']}" for line in lines if line["class"] == "replay differs")
    if differing:
        raise Verdict(INVALID, f"a run replayed with another ending in a fresh process, so the build's runs are not shown "
                               f"deterministic: {differing[0][:200]}")
    for profile, entry in entries.items():
        held = len(others.get(profile, ()))
        if entry["suspect_keys"].get("other", 0) > held:
            raise Verdict(INVALID, f"{profile} counts {entry['suspect_keys']['other']} suspects under other and lists "
                                   f"{held}, so no record shows that none of them replayed with another ending")
    evidence.findings()
    return status


def trusted(scenario: dict, evidence: Evidence) -> dict:
    """The status document of a run whose records a verdict can rest on, or raise the Verdict that makes it invalid or incomplete.

    The records stand when they agree (`recorded`), `campaign sweep` exited 0, and the totals carry
    no `alarm`, `no_pass` or `unreached` key, whatever its value (a missed control means a check
    let a planted defect through). A control run also names its defect among the swept profiles,
    and the defect has runs, a replay, no miss and suspects of class violation only: a run or a
    replay of it that the wall limit, the memory limit or another end stopped before its own exit
    is no replay of the control. Each profile entry of the status counts zero missed runs. A
    sweep sets `alarm` from that count, and the judges read the count itself, so a status with a
    missed run and no flag is invalid as well. An invariant judge reports a break only on such
    records, and a valid run needs them.
    """
    run = evidence.run
    status = recorded(scenario, evidence)
    code = recorded_exit(evidence)
    flags = {flag: status[flag] for flag in SWEEP_FLAGS if flag in status}
    if flags:
        raise Verdict(INVALID, f"the totals carry {json.dumps(flags, sort_keys=True)[:300]}")
    if code != 0:
        raise Verdict(INVALID, f"campaign sweep exited {code} and its totals carry none of {', '.join(SWEEP_FLAGS)}")
    if run["mode"] == "control":
        defect = run["defect"]
        if defect not in run["profiles"] or defect not in status["profiles"]:
            raise Verdict(INVALID, f"the control {defect} is the run's label and no swept profile")
        entry = status["profiles"][defect]
        runs, replays, missed = (count(entry, key, defect) for key in ("runs", "replays", "missed"))
        if runs == 0 or replays == 0 or missed != 0:
            raise Verdict(INVALID, f"the control {defect} has {runs} runs, {replays} replays and {missed} missed; "
                                   "a valid control run has runs, a replay and no miss")
        ended = sorted(key for key in entry["suspect_keys"] if identity(key)[0] != "violation")
        if ended:
            raise Verdict(INVALID, f"the control {defect} has a suspect of class {identity(ended[0])[0][:120]!r}: a run or "
                                   "replay of it ended other than by its own exit, so it is no replay of the control")
    for profile, entry in status["profiles"].items():
        missed = count(entry, "missed", f"profile {profile}")
        if missed > 0:
            raise Verdict(INVALID, f"{profile} counts {missed} missed runs: a control's plant met no check, or a history "
                                   "that declares its failure passed")
    return status


def witnessed(scenario: dict, evidence: Evidence, status: dict) -> list[str]:
    """The detail of each scenario profile that met its witness minimum, or raise the Verdict that makes the run invalid.

    Each profile of the scenario meets its minimum (`caught` for a history that declares its failure,
    `covered` for a cluster profile, `pass` otherwise), was replayed in a fresh process and lists
    suspects of class violation only.
    """
    entries, parts = status["profiles"], []
    for profile in distinct(scenario_profiles(scenario)):
        if profile not in evidence.run["profiles"] or profile not in entries:
            raise Verdict(INVALID, f"the status holds no entry for the scenario's profile {profile}")
        entry = entries[profile]
        failing, cluster = kinds(evidence, status, profile)
        field, key = ("caught", "min_caught_per_profile") if failing else \
            ("covered", "min_covered_per_profile") if cluster else ("pass", "min_passes_per_profile")
        need, got = minimum(scenario, "load_delivery", key), count(entry, field, f"profile {profile}")
        if got < need:
            raise Verdict(INVALID, f"minimum unmet: {profile} has {got} runs under {field}, and the row requires {need}")
        replays = count(entry, "replays", f"profile {profile}")
        if replays == 0:
            raise Verdict(INVALID, f"{profile} has no replay, so no run of it was shown to replay in a fresh process")
        other = sorted(key for key in entry["suspect_keys"] if identity(key)[0] != "violation")
        if other:
            raise Verdict(INVALID, f"{profile} has a suspect of another class than violation: {other[0][:200]}")
        parts.append(f"{profile} {got} {field} of {need} required, {replays} replays")
    return parts


def reached(scenario: dict, evidence: Evidence, status: dict) -> list[str]:
    """The detail of the row's reach minimums met by each cluster profile of the scenario, or raise INVALID.

    A row with a fault names a reach event the core judge counts, and a row of link faults names
    `faults`, so a held run of a faulted row shows the fault delivered.
    """
    reach = scenario.get("reach", {})
    fault = scenario.get("fault")
    kind = fault.get("kind") if isinstance(fault, dict) else None
    if not isinstance(reach, dict) or not isinstance(kind, str):
        raise Verdict(INVALID, f"{scenario.get('id')}: reach is no object or fault names no kind")
    events = sorted(key for key in reach if key != "text")
    if kind != "none" and (not events or (kind == "link-faults" and "faults" not in events)):
        raise Verdict(INVALID, f"{scenario.get('id')}: the row's fault {kind} names no reach event the core judge "
                               "counts, so no run of it shows the fault delivered")
    if not events:
        return []
    clusters = [profile for profile in distinct(scenario_profiles(scenario)) if kinds(evidence, status, profile).cluster]
    if not clusters:
        raise Verdict(INVALID, "the row's reach names coverage events and no profile of the scenario is a cluster profile")
    for event in events:
        need = minimum(scenario, "reach", event)
        for profile in clusters:
            events_of = status["profiles"][profile].get("reached")
            got = count(events_of.get(event) if isinstance(events_of, dict) else None, "runs", f"{profile}'s reached.{event}")
            if got < need:
                raise Verdict(INVALID, f"reach unmet: {got} covered passes of {profile} reached {event}, "
                                       f"and the row requires {need}")
    return [f"reached {', '.join(events)}"]


def held(scenario: dict, evidence: Evidence, status: dict) -> str:
    """The detail of a valid run of `scenario` from the status `trusted` returned for it, or raise the Verdict that makes
    the run invalid.

    Each profile of the scenario met its witness minimum (`witnessed`) and the row's reach minimums
    (`reached`), and when the root holds controls, or its controls totals record runs, they have
    runs and at least one caught run, which shows that a check of this build fails on a planted
    defect. The status counts control runs for the whole root, so in a row of several profiles the
    controls of one of them meet this check for all.
    """
    parts = witnessed(scenario, evidence, status) + reached(scenario, evidence, status)
    controls = count(status.get("controls"), "runs", "the status's controls")
    if controls > 0 or any(entry["control"] for entry in status["profiles"].values()):
        caught = count(status.get("controls"), "caught", "the status's controls")
        if controls == 0:
            raise Verdict(INVALID, "the root holds controls of the scenario's profiles and controls.runs is 0")
        if caught == 0:
            raise Verdict(INVALID, f"the root's {controls} control runs caught none, so no check of this build was "
                                   "shown to fail on a planted defect")
        parts.append(f"{controls} control runs, {caught} caught")
    if evidence.run["mode"] == "control":
        entry = status["profiles"][evidence.run["defect"]]
        parts.append(f"control {evidence.run['defect']} {entry['runs']} runs, {entry['replays']} replays, none missed")
    return "valid: " + "; ".join(parts)


def validity(scenario: dict, evidence: Evidence) -> str:
    """The detail of a valid run of `scenario`, or raise the Verdict that makes the run invalid or incomplete: the
    records stand (`trusted`) and the run meets the row (`held`)."""
    return held(scenario, evidence, trusted(scenario, evidence))


def sources(judge: Path) -> dict[str, str]:
    """Digests of every file of the judge's directory and of this module's directory, as they are on disk now.

    A judge imports what sits beside it, so the receipt names all of it. A __pycache__ or a link there
    could stand in for a source file, so either is refused; each file is opened relative to its listed
    directory without following a link or blocking, and read under SOURCE_BYTES.
    """
    digests: dict[str, str] = {}
    for folder in sorted({judge.parent, CORE}):
        handle = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for entry in sorted(os.scandir(handle), key=lambda entry: entry.name):
                if not entry.is_file(follow_symlinks=False):
                    raise ValueError(f"the judge directory holds {entry.name}, which is no regular file; a judge runs "
                                     "beside source files only")
                data = read_regular(entry.name, SOURCE_BYTES, dir_fd=handle)
                digests[(folder / entry.name).relative_to(ROOT).as_posix()] = hashlib.sha256(data).hexdigest()
        finally:
            os.close(handle)
    if judge.relative_to(ROOT).as_posix() not in digests or "chaos/judges/core/common.py" not in digests:
        raise ValueError("the judge and the shared module are regular files of the judge directories")
    return digests


def receipt_for(row_id: str, script: str, judge: dict[str, str], row: dict | None, scenario: dict | None,
                evidence: Evidence | None, code: int, detail: str) -> dict:
    """The receipt of one judgement. Its `evidence` map holds the digest of each file the judge read, which `main` makes
    every listed file before it calls this; a later family that adds fields wraps this function."""
    run = evidence.run if evidence else {}
    rows = {row_id: row_digest(row)} if row else {}
    if scenario:
        rows[scenario["id"]] = row_digest(scenario)
    return {
        "key": {
            "row": row_id, "scenario": run.get("scenario"), "mode": run.get("mode"), "defect": run.get("defect"),
            "command": [script, row_id],
            "evidence": evidence.read_digests() if evidence else {},
            "system_build": run.get("system_build"), "harness": run.get("harness"),
            "judge": judge,
            "rows": rows, "outcome": OUTCOMES[code], "detail": detail,
        },
        "run": {"run_id": run.get("run_id"), "started": run.get("started"),
                "judged": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "interpreter": platform.python_version()},
    }


def rows_of(section: str, row_id: str) -> tuple[dict, dict]:
    """The judged row and the ledger's scenario rows by id.

    The ledger is a regular file of at most LEDGER_BYTES bytes, read without following a link, each
    object's member names once; an id that two rows of the ledger share is ambiguous.
    """
    try:
        ledger = parse(read_regular(CHAOS / "ledger.json", LEDGER_BYTES))
        if not isinstance(ledger, dict):
            raise TypeError("the ledger is no JSON object")
        ids = [row["id"] for name in ("fences", "invariants", "scenarios") for row in ledger.get(name, [])]
        rows = {row["id"]: row for row in ledger[section]}
        scenarios = {row["id"]: row for row in ledger["scenarios"]}
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError) as error:
        raise Verdict(INVALID, f"chaos/ledger.json is unreadable: {error.__class__.__name__}: {error}") from None
    shared = sorted({str(name) for name in ids if ids.count(name) > 1})
    if shared:
        raise Verdict(INVALID, f"chaos/ledger.json gives the id {shared[0]!r} to more than one row")
    if row_id not in rows:
        raise Verdict(INVALID, f"no row {row_id!r} under {section} in chaos/ledger.json")
    return rows[row_id], scenarios


def receipt_directory(path: str) -> tuple[int, str]:
    """The directory a receipt goes into, opened once, and the receipt's file name.

    The directory lies under chaos/receipts/ of the judge's own tree, and no component of the path
    named is a link: each component below chaos/receipts/ is opened relative to the one above it
    without following a link. Any other path raises ValueError or OSError.
    """
    target = os.path.normpath(os.path.abspath(path))
    parent, name = os.path.split(target)
    base = CHAOS / "receipts"
    if not name or name in (".", "..") or os.path.realpath(parent) != parent or base.is_symlink():
        raise ValueError(f"the receipt {path!r} names a path through a link")
    relative = os.path.relpath(parent, os.path.realpath(base))
    if relative == "." or relative.split(os.sep)[0] == "..":
        raise ValueError(f"the receipt {path!r} lies outside a directory under chaos/receipts/")
    handle = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    for part in relative.split(os.sep):
        try:
            inner = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=handle)
        finally:
            os.close(handle)
        handle = inner
    return handle, name


def report(text: str) -> None:
    """Write the verdict line to standard output whole, through the descriptor; a failed write raises OSError."""
    data = text.encode("ascii", "backslashreplace")
    while data:
        data = data[os.write(1, data):]


def main(section: str, decide: Callable[[dict, dict, Evidence], tuple[int, str]]) -> int:
    """Judge one row of `section` ("scenarios" or "invariants") and return the exit code.

    Every start that is not a judgement of a row, a request for help, a refused argument and a
    refused receipt path included, exits 2, whether or not standard error is open. An evidence file
    that cannot be read for the receipt's digest makes the verdict incomplete, and the receipt says so.
    """
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("row")
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--receipt")
    try:
        args = parser.parse_args()
    except (SystemExit, Exception):
        warn(f"start the judge as python3 -I -B {sys.argv[0]} <row-id> --evidence DIR [--receipt FILE]")
        return INVALID
    if not sys.flags.isolated or not sys.flags.dont_write_bytecode:
        warn(f"{args.row}: start the judge as python3 -I -B {sys.argv[0]} ...")
        return INVALID
    row = scenario = evidence = None
    script = Path(sys.argv[0]).resolve()
    try:
        loaded = sources(script)
        if globals().get("LOADED_SHA256") != loaded.get("chaos/judges/core/common.py"):
            raise ValueError("common.py was not loaded from the bytes its digest names")
    except (OSError, ValueError) as error:
        warn(f"{args.row}: cannot read the judge: {error.__class__.__name__}: {error}")
        return INVALID
    folder = None
    try:
        if args.receipt:
            folder = receipt_directory(args.receipt)
    except (OSError, ValueError) as error:
        warn(f"{args.row}: refused the receipt path: {error.__class__.__name__}: {error}")
        return INVALID
    try:
        row, scenarios = rows_of(section, args.row)
        evidence = Evidence(Path(args.evidence))
        scenario = scenarios.get(evidence.run.get("scenario"))
        if evidence.problem is not None:
            raise evidence.problem
        if scenario is None:
            raise Verdict(INVALID, f"run.json names scenario {evidence.run.get('scenario')!r}, which the ledger lacks")
        evidence.check(scenario)
        listed = scenario.get("invariants")
        if section == "invariants" and (not isinstance(listed, list) or args.row not in listed):
            raise Verdict(INVALID, f"{args.row} does not apply to scenario {scenario['id']}")
        if section == "scenarios" and scenario["id"] != args.row:
            raise Verdict(INVALID, f"the evidence is a run of {scenario['id']!r}")
        code, detail = decide(row, scenario, evidence)
    except Verdict as verdict:
        code, detail = verdict.code, verdict.detail
    except Exception as error:
        code, detail = INVALID, f"judge fault: {error.__class__.__name__}: {error}"
    if evidence is not None:
        try:
            evidence.digests()
        except OSError as error:
            code, detail = INCOMPLETE, f"an evidence file could not be read for the receipt's digest: {error}"[:600]
    created = False
    try:
        if sources(script) != loaded:
            code, detail = INVALID, "a judge file changed while the judge ran"
        if folder is not None:
            receipt = receipt_for(args.row, script.relative_to(ROOT).as_posix(), loaded, row, scenario, evidence,
                                  code, detail)
            # Exclusive creation preserves an existing entry at the receipt path, a symbolic link included.
            handle = os.open(folder[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=folder[0])
            created = True
            with os.fdopen(handle, "w", encoding="utf-8") as file:
                file.write(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        report(f"{args.row}: {OUTCOMES[code]}: {detail}\n")
    except Exception as error:
        # No verdict was reported, so none stays on file. Each step runs whatever the one before it did.
        with contextlib.suppress(Exception):
            if created and folder is not None:
                os.unlink(folder[1], dir_fd=folder[0])
        warn(f"{args.row}: cannot report the verdict: {error.__class__.__name__}")
        return INVALID
    return code
