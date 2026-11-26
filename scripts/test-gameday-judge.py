#!/usr/bin/env python3
"""Exercise scripts/gameday-judge.py over the committed held fixture `scripts/gameday-fixtures/held/` and copies of it
that each carry one named plant. Most cases hand the planted files to the judge's `load_evidence` as bytes; the cases
that read a directory, write a record or run the command line go through the disk. `Held` runs under the committed
game-day catalog and `HeldUnderSetCatalog` runs every one of its cases again under a catalog copy whose GD-2 has both
budgets set to values other than the fixture's working values, its prerequisites met and a runbook named. `Refusals`
holds the cases that refuse before a budget is read. The cases cover the held record and its byte-equal rerun, the
controls of each of the eleven rules with the vacuity check that replaces each rule by one that holds, the boundaries
of the rules' windows and counts, the end of observation at a restoration inside the run window, the reach oracle, the
abort mark, unobserved rules, the refusals that write no record, the simulation kind, the grade `scripts/readiness.py`
gives each record, and the command line."""

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("gameday_judge", ROOT / "scripts/gameday-judge.py")
assert SPEC is not None and SPEC.loader is not None
gj = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gj)
rd = gj.load_readiness()
HELD = ROOT / "scripts/gameday-fixtures/held"
CATALOG = rd.parse(gj.read_bytes(gj.CATALOG, "catalog"), "catalog")
FIS = rd.parse(gj.read_bytes(gj.PROFILES, "profiles"), "profiles")
HELD_BYTES = {p.relative_to(HELD).as_posix(): p.read_bytes() for p in sorted(HELD.rglob("*")) if p.is_file()}
# The held fixture parsed strictly once; each Evidence copies it through the standard decoder.
HELD_TEXT = {rel: (gj.parsed(data, rel), data.decode())[1] for rel, data in HELD_BYTES.items()}
FAILOVER = rd.parse(rd.RECORD.read_bytes(), "readiness record")
GD2 = next(e for e in CATALOG["entries"] if e["id"] == "GD-2")
GUARD = {"generation": "any generation change", "create": "any CreateVolume by the reconciler principal",
         "receipt": "any replacement receipt written by the reconciler principal",
         "roleless": "a takeover of a shard with no role on the stopped host",
         "twice": "a shard that changes hands twice",
         "origin": "the zone's origin request rate above its baseline past the origin-load budget",
         "drain": "a shard without a standby or a named blocker past the re-enrollment drain",
         "activation": "two hosts activating one tenure of a shard"}
WITNESS_WORDS = ("is first hit on the successor with its recorded bytes and no origin request for that key before "
                 "the hit")
# The GD-2 text each rule judges, located in the catalog independently of the judge's table.
TEXT_AT = {"takeover": ("clause", 0), "others-keep-owner": ("clause", 1), "no-volume-created": ("clause", 2),
           "no-generation-change": ("clause", 2), "one-owner-per-tenure": ("clause", 2),
           "standby-again": ("clause", 3), "origin-load": ("clause", 4), "witness-first-hit": ("witness", None),
           "no-origin-before-hit": ("witness", None), "no-replacement-receipt": ("guardrail", GUARD["receipt"]),
           "changes-hands-once": ("guardrail", GUARD["twice"])}
SAFETY = ("no-volume-created", "no-generation-change", "one-owner-per-tenure", "no-replacement-receipt",
          "changes-hands-once")
UNGRADED = {"takeover", "others-keep-owner", "standby-again", "origin-load", "witness-first-hit",
            "no-origin-before-hit"}
OUTSIDE_REASONS = {"origin": "the simulated world runs no origin", "provider": "it runs no provider",
                   "re-enrollment": "it runs no reconciler"}
SET_BUDGETS = {"re-enrollment-drain": 100, "origin-load": 2}
SEAL = "injection/collected.json"
PLAIN = json.JSONDecoder()


def names(directory):
    """The names of the entries of `directory`, sorted."""
    return sorted(p.name for p in Path(directory).iterdir())


def umask():
    """The process umask, read by setting it and setting it back."""
    mask = os.umask(0)
    os.umask(mask)
    return mask


def blocked_catalog():
    """A copy of the committed catalog whose GD-2 budgets are both null, so GD-2 is blocked and the fixture's working
    values bound its rules, whatever the committed catalog's budgets read."""
    catalog = copy.deepcopy(CATALOG)
    for budget in SET_BUDGETS:
        catalog["budgets"][budget]["value"] = None
    return catalog


def set_catalog():
    """A copy of the committed catalog whose GD-2 has both budgets set, its prerequisites met and a runbook named."""
    catalog = copy.deepcopy(CATALOG)
    for budget, value in SET_BUDGETS.items():
        catalog["budgets"][budget]["value"] = value
    gd2 = next(e for e in catalog["entries"] if e["id"] == "GD-2")
    gd2["prerequisites"] = [p.replace(": " + rd.TBD, ": met in the operator file") for p in gd2["prerequisites"]]
    gd2["runbooks"] = ["host-loss"]
    return catalog


class Evidence:
    """The held fixture's files parsed, plants applied to them in place, and their bytes. The bytes carry the digest of
    the planted `package.json` in `roles.json` unless `keep_digest` is set."""

    def __init__(self):
        self.files: dict[str, Any] = {
            rel: [PLAIN.decode(line) for line in text.split("\n")[:-1]] if rel.endswith(".jsonl")
            else PLAIN.decode(text)
            for rel, text in HELD_TEXT.items()}
        self.keep_digest = self.keep_coverage = self.keep_seal = False

    def __getitem__(self, rel):
        return self.files[rel]

    def __setitem__(self, rel, value):
        self.files[rel] = value

    def __delitem__(self, rel):
        del self.files[rel]

    @property
    def package(self):
        return self.files["package.json"]

    @property
    def roles(self):
        return self.files["injection/roles.json"]

    def records(self, shard):
        return self.files[f"records/{shard}.jsonl"]

    def version(self, shard, at, **changes):
        """The version of `shard` at time `at`, changed in place by `changes`."""
        row = next(v for v in self.records(shard) if v["time"] == at)
        row.update(changes)
        return row

    def role(self, shard, **changes):
        """Change the roles read of `shard` and every version committed before that read alike."""
        self.roles["shards"][shard].update(changes)
        for v in self.records(shard):
            if v["time"] <= self.roles["time"]:
                v.update(changes)

    def give_away(self, *shards):
        """Move each of `shards` off the target to h2, standby h3, with its witness key and rows."""
        for shard in shards:
            self.role(shard, owner="h2", standby="h3")
        moved = [a for a in self.activations("h1") if a["shard"] in shards]
        self.activations("h1")[:] = [a for a in self.activations("h1") if a["shard"] not in shards]
        self.activations("h2").extend(moved)
        keys = {w["key"] for w in self.package["witness"] if w["shard"] in shards}
        self.package["witness"] = [w for w in self.package["witness"] if w["key"] not in keys]
        self.files["witness.jsonl"] = [r for r in self.files["witness.jsonl"] if r["key"] not in keys]

    def activations(self, host):
        return next(r for r in self.files["activations.jsonl"] if r["host"] == host)["activations"]

    def bytes(self):
        package = (json.dumps(self.files.get("package.json"), indent=1) + "\n").encode()
        if not self.keep_digest and "injection/roles.json" in self.files:
            self.roles["package_sha256"] = hashlib.sha256(package).hexdigest()
        if not self.keep_coverage and "coverage.json" in self.files and "package.json" in self.files:
            spans, end = self.files["coverage.json"], self.package["run"]["end"]
            self.files["coverage.json"] = {
                rel: {**spans.get(rel, {"from": 0, "to": end}), "lines": len(rows)} for rel, rows in self.files.items()
                if rel.startswith("records/") or rel in gj.COLLECTED}
        files = {rel: package if rel == "package.json" else serialized(rel, value) for rel, value in self.files.items()}
        if not self.keep_seal and SEAL in self.files:
            # `keep_seal` preserves the original digests so changes to sealed files produce a digest mismatch.
            self.files[SEAL]["files"] = {rel: hashlib.sha256(data).hexdigest() for rel, data in files.items()
                                         if rel.startswith("records/") or rel in (*gj.COLLECTED, *gj.MARKS,
                                                                                  "coverage.json")}
            files[SEAL] = serialized(SEAL, self.files[SEAL])
        return files

    def write(self, root):
        for rel, data in self.bytes().items():
            path = Path(root, rel)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)


def serialize(rel, value):
    if rel.endswith(".jsonl"):
        return "".join(json.dumps(r) + "\n" for r in value).encode()
    return (json.dumps(value, indent=1) + "\n").encode()


# Each held file's value and its bytes as `Evidence.bytes` writes them, reused for a file a plant leaves unchanged.
PRISTINE = {rel: (value, serialize(rel, value)) for rel, value in Evidence().files.items()}


def serialized(rel, value):
    pristine = PRISTINE.get(rel)
    return pristine[1] if pristine is not None and pristine[0] == value else serialize(rel, value)


def judged(ev, catalog):
    """(exit code, record or None, refusal text or None) of the judge over the bytes of `ev`, through the loading and
    judging steps of `run`; the cases that read a directory or write a record call `run` itself."""
    try:
        record = gj.judge(gj.load_evidence(ev.bytes()), catalog, FIS, rd)
    except gj.Refusal as error:
        return 2, None, str(error)
    return 0 if record["verdict"] == "HELD" else 1, gj.decode(gj.encode(record).decode(), "record"), None


def simulation(ev):
    """`ev` as a simulation package whose world lacks the three observations, their files removed."""
    ev.package["kind"] = "simulation"
    ev.package["outside"] = dict(OUTSIDE_REASONS)
    for rel in gj.OBSERVATION_FILES.values():
        del ev[rel]
    return ev


def flood(start, n=100, prefix="flood"):
    """`n` origin requests four a second from `start`."""
    def plant(ev):
        ev["origin.jsonl"] += [{"time": start + i / 4, "key": f"img/{prefix}-{i}"} for i in range(n)]
        ev["origin.jsonl"].sort(key=lambda r: r["time"])
    return plant


def witness_rows(key, *rows):
    """Replace the witness rows of `key` by (host, time, outcome) rows, a hit carrying the key's pinned digest."""
    def plant(ev):
        digest = next(w["sha256"] for w in ev.package["witness"] if w["key"] == key)
        kept = [r for r in ev["witness.jsonl"] if r["key"] != key]
        kept += [{"key": key, "host": h, "time": t, "outcome": o, "sha256": digest if o == "hit" else None}
                 for h, t, o in rows]
        ev["witness.jsonl"] = sorted(kept, key=lambda r: r["time"])
    return plant


def receipt(time, principal="reconciler", shard="s2"):
    return lambda ev: ev["records/receipts.jsonl"].append({"time": time, "shard": shard, "principal": principal})


def provider(row):
    return lambda ev: ev["provider.jsonl"].append(row)


def collected(rel, **span):
    """The collection of the row file `rel` spans `span`, and holds no row after the span's end."""
    def plant(ev):
        ev["coverage.json"][rel].update(span)
        ev[rel] = [r for r in ev[rel] if r["time"] <= ev["coverage.json"][rel]["to"]]
    return plant


def takeover_by(host):
    def plant(ev):
        for t in (125, 150):
            ev.version("s1", t, owner=host)
        ev.activations("h2")[:] = [a for a in ev.activations("h2") if a["shard"] != "s1"]
        ev.activations(host).append({"shard": "s1", "generation": 7, "attempt": 4, "time": 125})
    return plant


def volume_at(*times):
    def plant(ev):
        for t in times:
            ev.version("s1", t, volume="vol-s1-replaced")
    return plant


def taken_over_before_stop(ev):
    ev.version("s1", 125, time=107)
    next(a for a in ev.activations("h2") if a["shard"] == "s1")["time"] = 107


def roleless_takeover(ev):
    ev.records("s5").append({"time": 200, "owner": "h4", "standby": "h3", "generation": 5, "volume": "vol-s5",
                             "attempts": 2})


def stood_by_takeover(ev):
    ev.records("s4").append({"time": 200, "owner": "h3", "standby": "h2", "generation": 3, "volume": "vol-s4",
                             "attempts": 2})


def two_record_owners(ev):
    """s1's successor h2 commits at 150 under the tenure (generation 7, attempts 1) that roles.json pins on h1."""
    ev.version("s1", 150, attempts=1)


def two_record_owners_before_the_read(ev):
    ev.records("s5")[1:1] = [{"time": 60, "owner": "h4", "standby": "h3", "generation": 5, "volume": "vol-s5",
                              "attempts": 1},
                             {"time": 70, "owner": "h3", "standby": "h4", "generation": 5, "volume": "vol-s5",
                              "attempts": 1}]


def two_activating_hosts(ev):
    ev.activations("h4").append({"shard": "s1", "generation": 7, "attempt": 4, "time": 126})


def hands_twice(ev):
    ev.version("s1", 125, owner="h3")
    ev.version("s1", 150, attempts=3)
    next(a for a in ev.activations("h2") if a["shard"] == "s1")["attempt"] = 6
    ev.activations("h3").append({"shard": "s1", "generation": 7, "attempt": 4, "time": 125})


def history_from_takeover(ev):
    """s1's history starts at its takeover and reuses the tenure (generation 7, attempts 1) that roles.json pins on h1."""
    del ev.records("s1")[0]
    for t in (125, 150):
        ev.version("s1", t, attempts=1)
    next(a for a in ev.activations("h2") if a["shard"] == "s1")["attempt"] = 2
    ev.activations("h1")[:] = [a for a in ev.activations("h1") if a["shard"] != "s1"]


def generation_changed(ev):
    ev.version("s4", 180, generation=4)


def no_enrolled_standby(ev):
    ev.version("s1", 150, standby=None)


def wrong_first_host(ev):
    witness_rows("img/k3", ("h3", 142, "hit"), ("h2", 350, "hit"))(ev)


def other_bytes(ev):
    next(r for r in ev["witness.jsonl"] if r["key"] == "img/k3")["sha256"] = hashlib.sha256(b"other").hexdigest()


def origin_before_hit(ev):
    ev["origin.jsonl"].append({"time": 120, "key": "img/k2"})
    ev["origin.jsonl"].sort(key=lambda r: r["time"])


# Each rule's controls: (name, plant, the guardrail its condition meets or None). Each leaves every other rule held.
CONTROLS = {
    "takeover": [("volume", volume_at(125, 150), None), ("last version only", volume_at(150), None),
                 ("takeover write only", volume_at(125), None), ("another host", takeover_by("h3"), None)],
    "others-keep-owner": [("no role", roleless_takeover, "roleless"), ("stood by", stood_by_takeover, None)],
    "no-volume-created": [("reconciler call", provider({"event": "CreateVolume", "principal": "reconciler",
                                                         "time": 200}), "create"),
                          ("volume listed", provider({"event": "volume", "volume": "vol-x", "time": 200}), None)],
    "no-generation-change": [("generation", generation_changed, "generation")],
    "one-owner-per-tenure": [("activations", two_activating_hosts, "activation"),
                             ("record versions", two_record_owners, None),
                             ("the tenure roles.json pins", history_from_takeover, None)],
    "standby-again": [("no standby", no_enrolled_standby, "drain"),
                      ("owner as standby", lambda ev: ev.version("s1", 150, standby="h2"), "drain"),
                      ("target as standby", lambda ev: ev.version("s4", 180, standby=ev.package["target"]["host"]),
                       "drain")],
    "origin-load": [("flood", flood(190), "origin"), ("first interval", flood(100, 200), "origin"),
                    ("last interval", flood(370), "origin")],
    "witness-first-hit": [("host", wrong_first_host, None), ("bytes", other_bytes, None),
                          ("never hit", witness_rows("img/k3", ("h2", 142, "miss"), ("h2", 200, "error")), None),
                          ("hit after the window", witness_rows("img/k3", ("h2", 142, "miss"), ("h2", 410, "hit")),
                           None),
                          ("hit before the takeover", witness_rows("img/k1", ("h2", 113, "hit")), None)],
    "no-origin-before-hit": [("origin request", origin_before_hit, None)],
    "no-replacement-receipt": [("receipt", receipt(200), "receipt"), ("last interval", receipt(380), "receipt")],
    "changes-hands-once": [("two changes", hands_twice, "twice")],
}


REVIEWED = hashlib.sha256(b"the operator's record of the abort steps").hexdigest()


def aborted(cause, guardrail=None, time=390):
    """An abort mark, and the restoration naming the operator's record of the abort steps."""
    def plant(ev):
        ev["injection/abort.json"] = {"cause": cause, "guardrail": guardrail, "time": time, "detail": None}
        ev["injection/restoration.json"]["reviewed_sha256"] = REVIEWED
    return plant


def planted(*plants):
    ev = Evidence()
    for plant in plants:
        plant(ev)
    return ev


def control(rule):
    return CONTROLS[rule][0][1]


def located(at):
    kind, where = at
    if kind == "clause":
        return GD2["hypothesis"][where]["clause"]
    if kind == "guardrail":
        return GD2["guardrail"][GD2["guardrail"].index(where)]
    sentence = GD2["oracle"]["expected"]
    start = sentence.index("each of the filled package's witness keys")
    return sentence[start:sentence.index(WITNESS_WORDS) + len(WITNESS_WORDS)]


class Judging(unittest.TestCase):
    """Helpers of the cases that read the record the judge writes; it holds no case of its own."""

    catalog = blocked_catalog()
    blocked = True

    def judge(self, ev):
        return judged(ev, self.catalog)

    def bound(self, budget):
        value = self.catalog["budgets"][budget]["value"]
        return Evidence().package["working_budgets"][budget] if value is None else value

    def record(self, ev):
        """(exit code, record) of a run that writes a record."""
        code, record, refusal = self.judge(ev)
        if record is None:
            self.fail(f"the judge refused: {refusal}")
        return code, record

    def assert_pair(self, ev, status, verdict):
        code, record = self.record(ev)
        self.assertEqual((record["run_status"], record["verdict"]), (status, verdict), record["result"])
        self.assertEqual(code, 0 if verdict == "HELD" else 1)
        return record

    def results(self, record, word):
        return {r for r, v in record["rules"].items() if v["result"] == word}

    def assert_disproven(self, ev, rules, status="COMPLETED"):
        record = self.assert_pair(ev, status, "DISPROVEN")
        self.assertEqual(self.results(record, "disproven"), set(rules))
        return record


class Held(Judging):
    """Every case whose outcome the catalog's budgets or package state can change, under the committed catalog: GD-2
    blocked, both budgets null, the fixture's working values used."""

    def test_the_committed_directory_ends_completed_held_and_two_runs_write_equal_bytes(self):
        with tempfile.TemporaryDirectory(prefix="gameday-judge-") as top:
            written = []
            mode = 0o666 & ~umask()
            for name in ("one.json", "two.json"):
                self.assertEqual(gj.run(str(HELD), os.path.join(top, name), self.catalog, FIS, rd), 0)
                written.append(Path(top, name).read_bytes())
                self.assertEqual(Path(top, name).stat().st_mode & 0o777, mode)
            self.assertEqual(written[0], written[1])
        record = gj.decode(written[0].decode(), "record")
        self.assertEqual(written[0], (json.dumps(record, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode())
        package = Evidence().package
        self.assertEqual([record[k] for k in ("id", "kind", "revision", "date")],
                         [package[k] for k in ("id", "kind", "revision", "date")])
        self.assertEqual((record["run_status"], record["verdict"], record["mode"]), ("COMPLETED", "HELD", "causal"))
        self.assertEqual(record["result"], "held on 11 rules")
        self.assertEqual(self.results(record, "held"), set(TEXT_AT))
        self.assertEqual(record["package_sha256"], hashlib.sha256((HELD / "package.json").read_bytes()).hexdigest())
        seal = (HELD / SEAL).read_bytes()
        self.assertEqual(record["seal"], {"sha256": hashlib.sha256(seal).hexdigest(),
                                          "time": gj.decode(seal.decode(), SEAL)["time"]})
        set_values = self.catalog["budgets"]["origin-load"]["value"] is not None
        self.assertEqual(record["budgets"], {b: {"value": SET_BUDGETS[b], "source": "catalog"} if set_values else
                                             {"value": Evidence().package["working_budgets"][b], "source": "package"}
                                             for b in SET_BUDGETS})
        self.assertIn("synthetic", Evidence().package["note"])
        owned = {s for s, v in Evidence().roles["shards"].items() if v["owner"] == Evidence().package["target"]["host"]}
        self.assertEqual({w["shard"] for w in Evidence().package["witness"]}, owned)

    def test_each_rule_has_controls_that_end_completed_disproven_naming_it_and_its_text(self):
        self.assertEqual(set(CONTROLS), set(gj.RULES))
        self.assertEqual(set(TEXT_AT), set(gj.RULES))
        self.assertEqual([rule for rule, controls in CONTROLS.items() if not controls], [])
        for rule, controls in CONTROLS.items():
            for name, plant, guard in controls:
                with self.subTest(rule=rule, control=name):
                    named = self.assert_disproven(planted(plant), {rule})["rules"][rule]
                    self.assertEqual(named["guardrail"], GUARD[guard] if guard else None)
                    self.assertEqual(named["past_stop_condition"], guard is not None)
                    self.assertEqual(named["text"], located(TEXT_AT[rule]))

    def test_each_rule_replaced_by_one_that_holds_no_longer_ends_its_controls_disproven(self):
        def holds(ev, facts):
            return gj.found_or_held([], "stands in for the rule")

        for rule, controls in CONTROLS.items():
            for name, plant, _ in controls:
                with self.subTest(rule=rule, control=name), \
                        mock.patch.dict(gj.RULES, {rule: gj.RULES[rule]._replace(evaluate=holds)}):
                    _, record = self.record(planted(plant))
                    self.assertNotEqual(record["verdict"], "DISPROVEN")
        self.assertEqual([r.evaluate.__name__ for r in gj.RULES.values()],
                         [name.replace("-", "_") for name in gj.RULES])

    def test_the_rules_read_their_windows_and_counts_at_their_boundaries(self):
        def owns_two(ev):
            ev.give_away("s3")

        def enrolled_at_the_drains_end(ev):
            ev.version("s2", 160, time=130 + self.bound("re-enrollment-drain"))

        def blocked(ev):
            ev.version("s1", 150, standby=None)
            ev["blockers.jsonl"].append({"shard": "s1", "time": 200, "name": "no host has room"})

        def baseline_raised(ev):
            flood(0, 200, "base")(ev)
            flood(190, 90, "run")(ev)

        def generation_before_the_read(ev):
            ev.records("s5")[1:1] = [{**ev.records("s5")[0], "time": 101, "generation": 4},
                                     {**ev.records("s5")[0], "time": 103}]

        def changed_before_the_read(ev):
            ev.records("s5")[1:1] = [{"time": 101, "owner": "h3", "standby": "h4", "generation": 5, "volume": "vol-s5",
                                      "attempts": 1},
                                     {"time": 103, "owner": "h4", "standby": "h3", "generation": 5, "volume": "vol-s5",
                                      "attempts": 2}]
            ev.roles["shards"]["s5"].update(owner="h4", standby="h3", attempts=2)

        held = [("a flood before the stop in the baseline window", flood(40)),
                ("an owner change before the roles read", changed_before_the_read),
                ("an attempts change between the roles read and the stop", lambda ev: ev.records("s5").append({
                    **ev.records("s5")[0], "time": 107, "attempts": 2})),
                ("a generation change before the roles read", generation_before_the_read),
                ("the run's flood less a raised baseline", baseline_raised),
                ("an enrollment at the last instant of the drain from the takeover write", enrolled_at_the_drains_end),
                ("a named blocker in place of a standby", blocked),
                ("a receipt at the run window's end", receipt(400)),
                ("an owner change of another shard at the run window's end", lambda ev: ev.records("s5").append({
                    **ev.records("s5")[0], "time": 400, "owner": "h4", "generation": 6})),
                ("another volume of an owned shard at the run window's end", lambda ev: ev.records("s1").append({
                    **ev.records("s1")[-1], "time": 400, "volume": "vol-s1-replaced"})),
                ("a reconciler CreateVolume at the run window's end", provider({
                    "event": "CreateVolume", "principal": "reconciler", "time": 400})),
                ("a shard with no version before the roles read", lambda ev: ev.records("s5").clear()),
                ("another principal's CreateVolume", provider({"event": "CreateVolume", "principal": "operator",
                                                                "time": 200})),
                ("owning exactly MIN_OWNED shards", owns_two)]
        for name, plant in held:
            with self.subTest(held=name):
                self.assertTrue(self.assert_pair(planted(plant), "COMPLETED", "HELD")["reach"]["met"])
        self.assertEqual((gj.MIN_OWNED, gj.MIN_STOOD), (2, 1))
        # An enrollment or a blocker past the drain's end, or a blocker before the stop, leaves the shard unenrolled.
        drain = self.bound("re-enrollment-drain")
        def unenrolled_with_blocker(time):
            def plant(ev):
                ev.version("s1", 150, standby=None)
                ev["blockers.jsonl"].append({"shard": "s1", "time": time, "name": "no host has room"})
            return plant

        past_drain = (("an enrollment past the drain", lambda ev: ev.version("s2", 160, time=130 + drain + 5)),
                      ("a stood-by shard's enrollment past the drain",
                       lambda ev: ev.version("s4", 180, time=110 + drain + 5)),
                      ("a blocker past the drain", unenrolled_with_blocker(125 + drain + 5)),
                      ("a blocker before the stop", unenrolled_with_blocker(108)))
        for name, plant in past_drain:
            with self.subTest(disproven=name):
                self.assert_disproven(planted(plant), {"standby-again"})
        # The origin rule counts each request: one request fewer than the bound allows holds, one more is over it.
        base = Evidence()
        rows, bound = base["origin.jsonl"], self.bound("origin-load")
        baseline = sum(0 <= r["time"] < 100 for r in rows) / 100
        present = sum(190 <= r["time"] < 220 for r in rows)
        allowed = int((bound + baseline) * 30) - present
        self.assert_pair(planted(flood(190, allowed, "edge")), "COMPLETED", "HELD")
        self.assert_disproven(planted(flood(190, allowed + 1, "edge")), {"origin-load"})
        # Without the raised baseline the same run flood is over the budget.
        self.assert_disproven(planted(flood(190, 90, "run")), {"origin-load"})
        # A key requested and never hit opens its origin window to the run window's end.
        never = witness_rows("img/k3", ("h2", 142, "miss"))

        def late(ev):
            ev["origin.jsonl"].append({"time": 300, "key": "img/k3"})

        self.assert_disproven(planted(never, late), {"witness-first-hit", "no-origin-before-hit"})

    def test_an_unmet_reach_fails_to_inject_and_keeps_a_safety_violation(self):
        def roles(**changes):
            return lambda ev: ev.roles.update(changes)

        def standby_state(host, **changes):
            return lambda ev: ev.roles["standbys"][host].update(changes)

        def mark(rel, **changes):
            return lambda ev: ev[rel].update(changes)

        def drop(rel):
            def plant(ev):
                del ev[rel]
            return plant

        def other_instance(ev):
            for mark in (ev["injection/stop.json"], ev["injection/stopped.json"]["request"],
                         ev["injection/restoration.json"]):
                mark["instance"] = "i-h2"

        def stands_by_for_none(ev):
            ev.role("s4", standby="h3")

        def target_as_its_own_standby(ev):
            ev.role("s3", standby="h1")
            ev.roles["standbys"]["h1"] = {"instance": "i-h1-other", "instance_state": "running",
                                          "host_report": "healthy"}

        unmet = [("stands by for none", stands_by_for_none),
                 ("owns one", lambda ev: ev.give_away("s2", "s3")),
                 ("an owned shard without a standby", lambda ev: ev.role("s3", standby=None)),
                 ("an owned shard whose standby is the target", target_as_its_own_standby),
                 ("an unhealthy standby", standby_state("h3", host_report="unhealthy")),
                 ("a stopped standby", standby_state("h2", instance_state="stopped")),
                 ("an unread standby", lambda ev: ev.roles["standbys"].pop("h3")),
                 ("no stopped.json", drop("injection/stopped.json")),
                 ("no stop.json", drop("injection/stop.json")),
                 ("a report that reads stopping", mark("injection/stopped.json", state="stopping")),
                 ("a report read before the stop", mark("injection/stopped.json", time=90)),
                 ("a report read after the run", mark("injection/stopped.json", time=5000)),
                 ("a report read at the run window's end", mark("injection/stopped.json", time=400)),
                 ("another request recorded", lambda ev: ev["injection/stopped.json"]["request"].update(
                     identity="someone-else")),
                 ("a stop of another instance", other_instance),
                 ("roles read at the stop request's time", roles(time=110)),
                 ("roles read after the stop request", roles(time=111)),
                 ("a takeover before the stop", taken_over_before_stop),
                 ("an owner change that keeps the standby before the stop", lambda ev: ev.records("s5").append({
                     **ev.records("s5")[0], "time": 107, "owner": "h2", "attempts": 2})),
                 ("a standby dropped before the stop", lambda ev: ev.records("s1").insert(1, {
                     **ev.records("s1")[0], "time": 107, "standby": None})),
                 ("a stood-by role moved before the stop", lambda ev: ev.records("s4").insert(1, {
                     **ev.records("s4")[0], "time": 107, "standby": "h3"}))]
        for name, plant in unmet:
            with self.subTest(unmet=name):
                record = self.assert_pair(planted(plant), "FAILED_TO_INJECT", "INCONCLUSIVE")
                self.assertFalse(record["reach"]["met"])
                self.assertEqual(self.results(record, "unobserved"), UNGRADED)
        for violation in SAFETY:
            with self.subTest(violation=violation):
                self.assert_disproven(planted(stands_by_for_none, control(violation)), {violation}, "HALTED")
        # A contradiction of an ungraded clause is not kept, and a met guardrail still names itself.
        self.assert_pair(planted(stands_by_for_none, control("takeover")), "FAILED_TO_INJECT", "INCONCLUSIVE")
        record = self.assert_pair(planted(stands_by_for_none, roleless_takeover), "FAILED_TO_INJECT", "INCONCLUSIVE")
        named = record["rules"]["others-keep-owner"]
        self.assertEqual((named["result"], named["guardrail"], named["past_stop_condition"]),
                         ("unobserved", GUARD["roleless"], True))
        def never_stopped(ev):
            del ev["injection/stopped.json"]
            for s in ("s1", "s2", "s3", "s4"):
                ev[f"records/{s}.jsonl"] = ev.records(s)[:1]
            for host in ("h2", "h3"):
                ev.activations(host)[:] = [a for a in ev.activations(host) if a["time"] < 100]

        record = self.assert_pair(planted(never_stopped), "FAILED_TO_INJECT", "INCONCLUSIVE")
        self.assertIsNone(record["rules"]["standby-again"]["guardrail"])
        record = self.assert_pair(planted(drop("injection/stop.json"), roleless_takeover), "FAILED_TO_INJECT",
                                  "INCONCLUSIVE")
        self.assertEqual(record["rules"]["others-keep-owner"]["guardrail"], GUARD["roleless"])
        # The controller's own mark of an unmet reach leaves the reach row first.
        unshown = (drop("injection/stopped.json"), aborted("stop-not-shown", time=130))
        self.assert_pair(planted(*unshown), "FAILED_TO_INJECT", "INCONCLUSIVE")
        self.assert_disproven(planted(*unshown, control("no-replacement-receipt")), {"no-replacement-receipt"},
                              "HALTED")

    def test_an_abort_mark_halts_and_keeps_a_contradiction(self):
        abort = aborted
        for cause in ("deadline", "exception", "signal"):
            with self.subTest(cause=cause):
                record = self.assert_pair(planted(abort(cause)), "HALTED", "INCONCLUSIVE")
                self.assertEqual(record["abort"], {"cause": cause, "guardrail": None, "before_stop": False})
        receipt_control = control("no-replacement-receipt")
        for mark, past in ((abort("guardrail", GUARD["receipt"]), False), (abort("deadline"), True),
                           (abort("guardrail", GUARD["twice"]), True)):
            with self.subTest(past=past):
                record = self.assert_disproven(planted(receipt_control, mark), {"no-replacement-receipt"}, "HALTED")
                self.assertEqual(record["rules"]["no-replacement-receipt"]["past_stop_condition"], past)
                self.assertEqual(record["result"], "held on 10 rules; disproven: no-replacement-receipt (guardrail \""
                                 + GUARD["receipt"] + "\"" + (", past its stop condition" if past else "") + ")")
        self.assert_disproven(planted(control("takeover"), abort("deadline")), {"takeover"}, "HALTED")
        record = self.assert_pair(planted(abort("signal", time=50)), "HALTED", "INCONCLUSIVE")
        self.assertTrue(record["abort"]["before_stop"])
        self.assertEqual(record["result"], "held on 11 rules; the abort mark precedes the stop request")
        # The mark is compared with the stop request at 110, the controller's own stamp: one between the request
        # and the stopped report at 112 follows the stop request.
        for time in (110, 111):
            with self.subTest(abort_at=time):
                record = self.assert_pair(planted(abort("signal", time=time)), "HALTED", "INCONCLUSIVE")
                self.assertFalse(record["abort"]["before_stop"])
                self.assertEqual(record["result"], "held on 11 rules")

    def test_owner_changes_after_an_early_roles_read_are_read(self):
        def read_early(ev):
            ev.roles["time"] = 60
            ev.records("s5")[1:1] = [{"time": 70, "owner": "h4", "standby": "h3", "generation": 5, "volume": "vol-s5",
                                      "attempts": 2},
                                     {"time": 90, "owner": "h3", "standby": "h4", "generation": 5, "volume": "vol-s5",
                                      "attempts": 3}]

        # A shard that leaves and returns between an early read and the run window's start changes hands twice, and
        # the role change before the stop leaves the reach unmet with the safety violation kept.
        self.assert_disproven(planted(read_early), {"changes-hands-once"}, "HALTED")

    def test_an_unobserved_rule_ends_completed_inconclusive(self):
        def no_activation_line(ev):
            ev["activations.jsonl"] = [r for r in ev["activations.jsonl"] if r["host"] != "h4"]

        def never_requested(ev):
            ev["witness.jsonl"] = [r for r in ev["witness.jsonl"] if r["key"] != "img/k3"]

        def drain_past_the_window(ev):
            ev.package["run"]["end"] = 190
            ev["records/s4.jsonl"] = [v for v in ev.records("s4") if v["time"] != 180]

        for plant, rules in ((no_activation_line, {"one-owner-per-tenure"}),
                             (never_requested, {"witness-first-hit", "no-origin-before-hit"}),
                             (drain_past_the_window, {"standby-again"})):
            with self.subTest(plant=plant.__name__):
                record = self.assert_pair(planted(plant), "COMPLETED", "INCONCLUSIVE")
                self.assertEqual(self.results(record, "unobserved"), rules)
                self.assertEqual(record["result"], f"held on {11 - len(rules)} rules; unobserved: "
                                 + ", ".join(r for r in gj.RULES if r in rules))
        # A contradiction outranks an unobserved rule.
        record = self.assert_disproven(planted(no_activation_line, control("takeover")), {"takeover"})
        self.assertEqual(record["result"], "held on 9 rules; disproven: takeover; unobserved: one-owner-per-tenure")

    def test_a_null_budget_with_no_working_value_leaves_its_rule_unobserved(self):
        for budget, rule in (("origin-load", "origin-load"), ("re-enrollment-drain", "standby-again")):
            with self.subTest(budget=budget):
                ev = Evidence()
                del ev.package["working_budgets"][budget]
                set_value = self.catalog["budgets"][budget]["value"]
                record = self.assert_pair(ev, "COMPLETED", "HELD" if set_value is not None else "INCONCLUSIVE")
                self.assertEqual(record["budgets"][budget],
                                 {"value": set_value, "source": "catalog" if set_value is not None else None})
                if set_value is None:
                    self.assertEqual(self.results(record, "unobserved"), {rule})
                    self.assertIsNone(record["rules"][rule]["guardrail"])

    def test_a_simulation_package_holds_inside_its_world_and_reads_outside_for_the_rest(self):
        record = self.assert_pair(simulation(Evidence()), "COMPLETED", "HELD")
        self.assertEqual((record["mode"], record["kind"]), ("simulation", "simulation"))
        self.assertEqual(record["result"], "held on 7 rules, 4 outside its world")
        self.assertEqual(self.results(record, "outside"),
                         {"no-volume-created", "standby-again", "origin-load", "no-origin-before-hit"})
        ev = simulation(Evidence())
        ev.package["outside"] = {"provider": OUTSIDE_REASONS["provider"]}
        ev["origin.jsonl"], ev["blockers.jsonl"] = Evidence()["origin.jsonl"], []
        record = self.assert_pair(ev, "COMPLETED", "HELD")
        self.assertEqual(record["result"], "held on 10 rules, 1 outside its world")
        ev.package["outside"] = {}
        ev["provider.jsonl"] = Evidence()["provider.jsonl"]
        record = self.assert_pair(ev, "COMPLETED", "HELD")
        self.assertEqual((record["mode"], record["result"]), ("simulation", "held on 11 rules, 0 outside its world"))
        self.assert_disproven(planted(simulation, control("takeover")), {"takeover"})
        named = simulation(Evidence())
        named.package["outside"]["origin"] = "le monde simul\u00e9 n'a pas d'origine"
        written = gj.encode(gj.judge(gj.load_evidence(named.bytes()), self.catalog, FIS, rd))
        self.assertIn("simul\u00e9".encode(), written)
    def grade(self, record, catalog, source=None, revision=None):
        """Each GD-2 item's grade from `scripts/readiness.py` for `record`, the package report built from `catalog`
        as `check` builds it, with no readiness context, bound to the package bytes and revision of the judged
        `source` (the held fixture by default) or to `revision`, under the record's own seal and with a rerun that
        reproduces the record, so the grader's rules after the rerun are what decide."""
        source = source or Evidence()
        entries = {e["id"]: e for e in catalog["entries"]}
        report, _ = rd.check_gamedays(FAILOVER, {"packages": entries, "gamedays": catalog, "fis": FIS})
        self.assertEqual(record["catalog_sha256"], report["GD-2"]["digest"])
        ev = {"record": record, "identity": {"record_sha256": "judged in process"},
              "input": {"package_sha256": hashlib.sha256(source.bytes()["package.json"]).hexdigest(),
                        "catalog_sha256": record["catalog_sha256"], "seal_sha256": record["seal"]["sha256"]},
              "rerun": {"record": copy.deepcopy(record)}}
        revision = revision or source.package["revision"]
        return {item: rd.gameday_grade(item, entries["GD-2"], ev, revision, report["GD-2"])
                for item in entries["GD-2"]["items"]}

    def test_the_judge_takes_the_zone_the_coverage_and_the_revision_as_their_writers_declare_them(self):
        # The stated limit of the record: these directories read as an honest one does, since every file of the
        # directory is a producer's and nothing outside it is read. A collection that holds no provider row when the
        # controller seals it is one of them; the seal shows a row removed after it.
        def without_s5(ev):
            ev.package["shards"].remove("s5")
            del ev["records/s5.jsonl"], ev.roles["shards"]["s5"]
            for rel in ("blockers.jsonl", "records/receipts.jsonl"):
                ev[rel] = [r for r in ev[rel] if r["shard"] != "s5"]
            for row in ev["activations.jsonl"]:
                row["activations"] = [a for a in row["activations"] if a["shard"] != "s5"]

        def no_provider_rows(ev):
            ev["provider.jsonl"] = []

        def relabeled(ev):
            ev.package.update(revision="f" * 40, date="2026-12-31")

        self.assert_pair(planted(without_s5), "COMPLETED", "HELD")
        self.assert_disproven(planted(control("no-volume-created")), {"no-volume-created"})
        self.assert_pair(planted(control("no-volume-created"), no_provider_rows), "COMPLETED", "HELD")
        held, record = self.record(Evidence())[1], self.assert_pair(planted(relabeled), "COMPLETED", "HELD")
        self.assertEqual((record["revision"], record["date"]), ("f" * 40, "2026-12-31"))
        # The relabeled package carries another digest, which the grader compares with its inputs entry.
        self.assertNotEqual(record["package_sha256"], held["package_sha256"])

    def test_the_readiness_grader_reads_the_held_record_by_the_package_state_and_refuses_a_simulation_one(self):
        _, held = self.record(Evidence())
        blocked = bool(rd.check_gamedays(FAILOVER, {"packages": {e["id"]: e for e in self.catalog["entries"]},
                                                    "gamedays": self.catalog, "fis": FIS})[0]["GD-2"]["blocked"])
        self.assertEqual(blocked, self.blocked)
        grades = self.grade(held, self.catalog)
        self.assertEqual(sorted(grades), ["host-loss-multi-shard-staging", "host-loss-multi-shard-staging-safety"])
        for item, grade in grades.items():
            with self.subTest(item=item):
                self.assertEqual(grade["grade"], "UNVERIFIED" if blocked else "VERIFIED", grade["reason"])
                if blocked:
                    self.assertIn("the committed package is blocked", grade["reason"])
        _, sim = self.record(simulation(Evidence()))
        for item, grade in self.grade(sim, self.catalog).items():
            with self.subTest(item=item, mode="simulation"):
                self.assertEqual(grade["grade"], "MISSING", grade["reason"])
        _, disproven = self.record(planted(control("no-replacement-receipt")))
        self.assertEqual({g["grade"] for g in self.grade(disproven, self.catalog).values()}, {"FAILED"})
        _, failed = self.record(planted(lambda ev: ev.roles["standbys"].pop("h3")))
        self.assertEqual({g["grade"] for g in self.grade(failed, self.catalog).values()}, {"MISSING"})
        # The record copies the package's revision and date. The grader marks every GD-2 item STALE when the grading
        # revision differs from the record's revision.
        other = planted(lambda ev: ev.package.update(revision="0000000000000000000000000000000000000002",
                                                     date="2026-12-01"))
        _, moved = self.record(other)
        self.assertEqual((moved["revision"], moved["date"]), (other.package["revision"], other.package["date"]))
        for item, grade in self.grade(moved, self.catalog, other).items():
            with self.subTest(item=item, revision="other"):
                self.assertEqual(grade["grade"], "UNVERIFIED" if blocked else "VERIFIED", grade["reason"])
        self.assertEqual({g["grade"] for g in self.grade(moved, self.catalog, other, Evidence().package[
            "revision"]).values()}, {"STALE"})
        noted = planted(lambda ev: ev.package.update(note="another synthetic fixture"))
        for item, grade in self.grade(held, self.catalog, noted).items():
            with self.subTest(item=item, package="another"):
                self.assertEqual(grade["grade"], "UNVERIFIED")
                self.assertIn("another filled package", grade["reason"])


class HeldUnderSetCatalog(Held):
    """Every case of `Held` under a catalog copy whose GD-2 has both budgets set to values other than the fixture's
    working values, its prerequisites met and a runbook named."""

    catalog = set_catalog()
    blocked = False


class Refusals(Judging):
    """Evidence or a catalog the judge refuses before it reads a budget: exit 2, no record."""

    def assert_refused(self, ev, words, catalog=None):
        code, record, refusal = judged(ev, self.catalog if catalog is None else catalog)
        self.assertEqual((code, record), (2, None))
        self.assertIn(words, str(refusal))

    def test_a_collection_shortened_after_the_seal_with_its_count_lowered_is_refused(self):
        # The collector drops the CreateVolume row that disproves no-volume-created and lowers the file's count in
        # coverage.json to match; the controller's seal still names the bytes it sealed.
        ev = planted(control("no-volume-created"))
        self.assert_disproven(ev, {"no-volume-created"})
        ev.keep_seal = True
        ev["provider.jsonl"] = [r for r in ev["provider.jsonl"] if r["time"] != 200]
        files = ev.bytes()
        self.assertEqual(gj.decode(files["coverage.json"].decode(), "coverage")["provider.jsonl"]["lines"], 3)
        self.assert_refused(ev, "provider.jsonl differs from the bytes injection/collected.json seals")
        # A seal written again over the shortened files reads as the first, and the record's seal digest tells them
        # apart.
        first = self.record(planted(control("no-volume-created")))[1]["seal"]
        ev.keep_seal = False
        again = self.assert_pair(ev, "COMPLETED", "HELD")["seal"]
        self.assertEqual((first["time"], again["time"]), (430, 430))
        self.assertNotEqual(first["sha256"], again["sha256"])
        # A wider span claimed after the seal is refused by the seal of coverage.json.
        widened = planted(lambda ev: ev["coverage.json"]["origin.jsonl"].update({"to": 399}))
        widened.bytes()
        widened.keep_seal = widened.keep_coverage = True
        widened["coverage.json"]["origin.jsonl"]["to"] = 400
        self.assert_refused(widened, "coverage.json differs from the bytes injection/collected.json seals")

        def sealed(edit):
            def plant(ev):
                ev.bytes()
                ev.keep_seal = True
                edit(ev[SEAL])
            return plant

        cases = [(sealed(lambda seal: seal["files"].pop("witness.jsonl")), "injection/collected.json seals no "
                  "witness.jsonl"),
                 (sealed(lambda seal: seal["files"].pop("coverage.json")), "injection/collected.json seals no "
                  "coverage.json"),
                 (sealed(lambda seal: seal["files"].update({"records/s9.jsonl": "0" * 64})), "not only the sealeds"),
                 (sealed(lambda seal: seal["files"].update({"package.json": "0" * 64})), "not only the sealeds"),
                 (sealed(lambda seal: seal["files"].update({"injection/collected.json": "0" * 64})),
                  "not only the sealeds"),
                 (sealed(lambda seal: seal.update({"time": 399.5})), "before the run window's end 400"),
                 (lambda ev: ev["coverage.json"]["witness.jsonl"].update({"to": 431}),
                  "to 431, after the seal's time 430"),
                 (sealed(lambda seal: seal.update({"files": []})), "files is no object")]
        for plant, words in cases:
            with self.subTest(words=words):
                self.assert_refused(planted(plant), words)
        # A seal at the run window's end, and a span that ends at the seal, are read.
        self.assert_pair(planted(lambda ev: ev[SEAL].update(time=400)), "COMPLETED", "HELD")
        self.assert_pair(planted(lambda ev: ev["coverage.json"]["witness.jsonl"].update({"to": 430})), "COMPLETED",
                         "HELD")

    def test_the_seal_binds_every_mark_that_stood_when_it_was_written(self):
        # Abort and restoration marks can affect the verdict even when the collections stay the same.
        def resealed(*plants, after):
            ev = planted(*plants)
            ev.bytes()
            ev.keep_seal = True
            after(ev)
            return ev

        def unaborted(ev):
            del ev["injection/abort.json"]
            ev["injection/restoration.json"]["reviewed_sha256"] = None

        self.assert_pair(planted(aborted("deadline")), "HALTED", "INCONCLUSIVE")
        self.assert_pair(planted(restored(390)), "COMPLETED", "INCONCLUSIVE")
        cases = [(resealed(aborted("deadline"), after=unaborted),
                  "injection/collected.json seals injection/abort.json, which is missing"),
                 (resealed(restored(390), after=lambda ev: ev.files.pop("injection/restoration.json")),
                  "injection/collected.json seals injection/restoration.json, which is missing"),
                 (resealed(after=aborted("deadline")), "injection/abort.json stands unsealed, and only a restoration may"),
                 (resealed(after=lambda ev: ev["injection/roles.json"].update(time=99)),
                  "injection/roles.json differs from the bytes injection/collected.json seals"),
                 (resealed(after=lambda ev: ev["injection/stopped.json"].update(state="terminated")),
                  "injection/stopped.json differs from the bytes injection/collected.json seals"),
                 (resealed(aborted("deadline"), after=lambda ev: ev["injection/abort.json"].update(detail="changed")),
                  "injection/abort.json differs from the bytes injection/collected.json seals"),
                 (resealed(after=lambda ev: ev["injection/stop.json"].update(time=149)),
                  "injection/stop.json differs from the bytes injection/collected.json seals"),
                 (resealed(after=restored(421)),
                  "injection/restoration.json differs from the bytes injection/collected.json seals")]
        for ev, words in cases:
            with self.subTest(words=words):
                self.assert_refused(ev, words)

        def restored_after_the_seal(time, *plants):
            return resealed(lambda ev: ev.files.pop("injection/restoration.json"), *plants,
                            after=lambda ev: ev.files.__setitem__("injection/restoration.json", {
                                "instance": "i-h1", "state": "running", "time": time, "reviewed_sha256": None}))

        # An unsealed restoration at or after the run window's end, less the clock error, ends no observation.
        for time in (400, 429, 430):
            with self.subTest(unsealed=time):
                self.assert_pair(restored_after_the_seal(time), "COMPLETED", "HELD")
        self.assert_refused(restored_after_the_seal(399), "injection/restoration.json stands unsealed and dates 399, "
                            "less than the clock error after the run window's end 400, so it may end observation")
        # With a clock error of 2, a restoration at 401 may precede rows other writers stamped before 400.
        erred = planted(clock_error(2), restored(401))
        self.assertEqual(self.record(erred)[1]["run_status"], "COMPLETED")
        self.assertNotEqual(self.record(erred)[1]["verdict"], "HELD")
        self.assert_pair(planted(clock_error(2), restored(402)), "COMPLETED", "HELD")
        for time, refused in ((401, True), (402, False)):
            with self.subTest(erred=time):
                ev = restored_after_the_seal(time, clock_error(2))
                if refused:
                    self.assert_refused(ev, "injection/restoration.json stands unsealed and dates 401")
                else:
                    self.assert_pair(ev, "COMPLETED", "HELD")

    def test_lists_past_the_fleets_declared_bounds_are_refused_before_any_set_is_built(self):
        # The test reads MAX_HOSTS and MAX_SLOTS from their Rust declarations so its boundary cases track the fleet
        # limits.
        def declared(rel, name):
            text = gj.read_file(ROOT / rel, rel).replace(b"\r\n", b"\n").decode("utf-8")
            found = re.findall(rf"^pub const {name}: usize = ([0-9]+);$", text, re.MULTILINE)
            self.assertEqual(len(found), 1, f"{rel} declares {name} once")
            return int(found[0])

        hosts = declared("crates/kestrike/src/failover/zone_loop/directory.rs", "MAX_HOSTS")
        slots = declared("crates/kestrike/src/failover/standbys.rs", "MAX_SLOTS")
        entry = {"hosts": lambda i: f"x{i}", "shards": lambda i: f"x{i}",
                 "witness": lambda i: {"key": f"img/x{i}", "shard": "s1", "sha256": "0" * 64}}
        for field, bound in (("hosts", hosts), ("shards", slots), ("witness", slots)):
            with self.subTest(field=field):
                package = Evidence().package
                package[field] += [entry[field](i) for i in range(bound - len(package[field]))]
                gj.check_package(package)
                package[field].append(entry[field](bound))
                with self.assertRaisesRegex(gj.Refusal, f"package.json {field} holds {bound + 1} entries, more "
                                            f"than the {bound}"):
                    gj.check_package(package)
                # An unhashable last entry shows that the count is checked before the entries are hashed.
                package[field][-1] = [[]]
                with self.assertRaisesRegex(gj.Refusal, f"holds {bound + 1} entries"):
                    gj.check_package(package)

    def test_a_file_past_the_limit_is_refused_before_it_is_read_and_one_that_grows_before_it_is_synced(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch, "big.json")
            path.write_bytes(b"12345")
            opened = len(os.listdir("/proc/self/fd"))
            # The size read by fstat refuses the file before any byte is read.
            with mock.patch.object(gj, "FILE_LIMIT", 4), \
                    mock.patch.object(gj.os, "fdopen", side_effect=AssertionError("the file was read")), \
                    self.assertRaisesRegex(gj.Refusal, "big holds more than 4 bytes"):
                gj.read_file(path, "big", sync=True)
            self.assertEqual(len(os.listdir("/proc/self/fd")), opened)
            # A file that grows past its fstat size while read is refused before it is synced.
            real = os.fstat

            def smaller(fd):
                return os.stat_result((*real(fd)[:6], 4, *real(fd)[7:]))
            with mock.patch.object(gj.os, "fstat", side_effect=smaller), \
                    mock.patch.object(gj.os, "fsync", side_effect=AssertionError("the file was synced")), \
                    self.assertRaisesRegex(gj.Refusal, "big grew while it was read"):
                gj.read_file(path, "big", sync=True)
            self.assertEqual(len(os.listdir("/proc/self/fd")), opened)
            # A signal during fstat ends the read with the descriptor closed.
            with mock.patch.object(gj.os, "fstat", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                gj.read_file(path, "big")
            self.assertEqual(len(os.listdir("/proc/self/fd")), opened)
            self.assertEqual(gj.read_file(path, "big", sync=True), b"12345")
            with self.assertRaises(TypeError):
                gj.read_file(path, "big", None, True)

    def test_a_fleet_bound_is_read_from_its_own_declaration_or_refused(self):
        # Planted declarations with distinct values show which constant bounds each list; the cache is cleared around
        # each variant so neither the tree's values nor planted ones mask a read.
        gj.declared_bound.cache_clear()
        self.addCleanup(gj.declared_bound.cache_clear)
        # The scratch directory's parent holds regex metacharacters, so a path matched as a pattern fails.
        parent = Path(tempfile.mkdtemp(prefix="review[2]+("))
        self.addCleanup(shutil.rmtree, parent)
        with tempfile.TemporaryDirectory(dir=parent) as scratch:
            hosts, slots = Path(scratch, "hosts.rs"), Path(scratch, "slots.rs")
            bounds = {"hosts": (str(hosts), "MAX_HOSTS"), "shards": (str(slots), "MAX_SLOTS"),
                      "witness": (str(slots), "MAX_SLOTS")}
            hosts.write_bytes(b"/// The most hosts.\r\npub const MAX_HOSTS: usize = 4;\r\n")
            slots.write_bytes(b"pub const MAX_SLOTS: usize = 5;\n")
            with mock.patch.dict(gj.FLEET_BOUNDS, bounds):
                self.assertEqual([gj.fleet_bound(f) for f in ("hosts", "shards", "witness")], [4, 5, 5])
                package = Evidence().package
                package["witness"] += [{"key": f"img/x{i}", "shard": "s1", "sha256": "0" * 64} for i in range(2)]
                gj.check_package(package)
                for field, entry, count, bound in (("hosts", "h5", 5, 4), ("shards", "s6", 6, 5),
                                                   ("witness", {"key": "img/x9", "shard": "s1", "sha256": "0" * 64},
                                                    6, 5)):
                    with self.subTest(field=field):
                        planted_package = copy.deepcopy(package)
                        planted_package[field].append(entry)
                        with self.assertRaisesRegex(gj.Refusal, f"{field} holds {count} entries, more than the "
                                                    f"{bound} that"):
                            gj.check_package(planted_package)
            for text, words in ((b"pub const MAX_HOSTS: usize = 1 << 12;\n", "declares MAX_HOSTS 0 times"),
                                (b"pub const MAX_HOSTS: usize = 4;\npub const MAX_HOSTS: usize = 4;\n",
                                 "declares MAX_HOSTS 2 times"),
                                (b"pub const MAX_HOSTS: usize = 18446744073709551616;\n",
                                 "declares MAX_HOSTS as a value past a 64-bit usize"),
                                (b"pub const MAX_HOSTS: usize = " + b"9" * 5000 + b";\n",
                                 "declares MAX_HOSTS as a value past a 64-bit usize"),
                                (b"pub const MAX_HOSTS: usize = 4;\npub const MAX_HOSTS: usize = " + b"9" * 30 + b";\n",
                                 "declares MAX_HOSTS 2 times"),
                                (b"pub const MAX_HOSTS: usize = 4;\n\xff\n", "is not UTF-8")):
                with self.subTest(words=words):
                    hosts.write_bytes(text)
                    gj.declared_bound.cache_clear()
                    with mock.patch.dict(gj.FLEET_BOUNDS, bounds):
                        with self.assertRaisesRegex(gj.Refusal, re.escape(f"{hosts} {words}")):
                            gj.check_package(Evidence().package)
            hosts.write_bytes(b"pub const MAX_HOSTS: usize = 18446744073709551615;\n")
            gj.declared_bound.cache_clear()
            with mock.patch.dict(gj.FLEET_BOUNDS, bounds):
                self.assertEqual(gj.fleet_bound("hosts"), (1 << 64) - 1)
            # A missing file, a link to a valid declaration and a named pipe with no writer are each refused, the
            # pipe without blocking.
            valid = Path(scratch, "valid.rs")
            valid.write_bytes(b"pub const MAX_HOSTS: usize = 4;\n")
            hosts.unlink()
            for make, words in ((lambda: None, "cannot be read"),
                                (lambda: hosts.symlink_to(valid), "cannot be read"),
                                (lambda: os.mkfifo(hosts), "is no regular file")):
                if os.path.lexists(hosts):
                    hosts.unlink()
                with self.subTest(words=words, kind=make):
                    make()
                    gj.declared_bound.cache_clear()
                    # An alarm ends a read that blocks, so a reader that waits on the pipe fails the case.
                    previous = signal.signal(signal.SIGALRM, lambda *_: self.fail(f"reading {hosts} blocked"))
                    signal.alarm(10)
                    try:
                        with mock.patch.dict(gj.FLEET_BOUNDS, bounds):
                            with self.assertRaisesRegex(gj.Refusal, re.escape(f"{hosts} {words}")):
                                gj.check_package(Evidence().package)
                    finally:
                        signal.alarm(0)
                        signal.signal(signal.SIGALRM, previous)

    def test_incomplete_or_inconsistent_evidence_is_refused(self):
        def missing(rel):
            def plant(ev):
                del ev[rel]
            return plant

        def off_digest(ev):
            ev.keep_digest = True
            ev.package["note"] += " (changed after the roles were read)"

        def unkeyed(ev):
            ev.package["witness"] = [w for w in ev.package["witness"] if w["shard"] != "s3"]
            ev["witness.jsonl"] = [r for r in ev["witness.jsonl"] if r["key"] != "img/k3"]

        def stop_at(time):
            def plant(ev):
                for rel in ("injection/stop.json", "injection/stopped.json"):
                    ev[rel]["time"] = time
                ev["injection/stopped.json"]["request"]["time"] = time
            return plant

        def set_package(**changes):
            return lambda ev: ev.package.update(changes)

        cases = [(missing(rel), "is missing") for rel in ("package.json", "witness.jsonl", "origin.jsonl",
                                                          "records/s2.jsonl", "injection/roles.json",
                                                          "activations.jsonl", "records/receipts.jsonl",
                                                          "provider.jsonl", "blockers.jsonl", "coverage.json",
                                                          "injection/collected.json")]
        cases += [(lambda ev, value=value: ev.version("s1", 150, attempts=value),
                   f"no attempts of the layout: {value!r}") for value in (-1, True, 1.5)]
        cases += [(lambda ev: ev.package["hosts"].append(None), "hosts [4] is no name of the layout"),
                  (lambda ev: ev["injection/stop.json"].update(identity=None), "identity is no name of the layout"),
                  (set_package(baseline={"start": 100, "end": 100}), "the windows are empty"),
                  (lambda ev: ev.records("s2").__setitem__(slice(1, 3), ev.records("s2")[:0:-1]),
                   "records/s2.jsonl is not in commit order")]
        cases += [(off_digest, "differs from the digest in injection/roles.json"),
                  (unkeyed, "have no witness key"),
                  (lambda ev: ev.package["witness"].append({"key": "img/k4", "shard": "s4",
                                                            "sha256": hashlib.sha256(b"k4").hexdigest()}),
                   "the target did not own"),
                  (set_package(outside={"origin": OUTSIDE_REASONS["origin"]}), "a staging package names"),
                  (lambda ev: ev.files.__setitem__("records/s9.jsonl", []), "no file of the layout"),
                  (lambda ev: ev["injection/stop.json"].update(reason="planned"), "holds the keys"),
                  (lambda ev: ev["witness.jsonl"][0].update(host="h9"),
                   "witness.jsonl line 1 host is no host of the layout"),
                  (lambda ev: ev.roles["shards"].update(s9=ev.roles["shards"]["s5"]), "not exactly the shards"),
                  (lambda ev: ev.roles["shards"]["s4"].update(owner="h3"), "other than its last version"),
                  (lambda ev: ev.records("s1").reverse(), "not in commit order"),
                  (lambda ev: ev["witness.jsonl"][0].update(time=100), "precedes the stop"),
                  (lambda ev: ev["witness.jsonl"][1].update(sha256=None),
                   "witness.jsonl line 2 is a hit with no digest"),
                  (lambda ev: ev.files.__setitem__("injection/abort.json", {"cause": "guardrail", "guardrail":
                                                                            "an alarm", "time": 390, "detail": None}),
                   "no guardrail of the layout"),
                  (aborted("deadline", GUARD["twice"]), "with cause guardrail"),
                  (lambda ev: (aborted("deadline")(ev), ev["injection/restoration.json"].update(reviewed_sha256=None)),
                   "restoration.json names a reviewed record"),
                  (lambda ev: ev["injection/restoration.json"].update(reviewed_sha256=REVIEWED),
                   "restoration.json names a reviewed record"),
                  (stop_at(500), "does not hold the stop"),
                  (stop_at(400), "does not hold the stop"),
                  (stop_at(90), "the baseline window ends after the stop"),
                  (set_package(interval=29), "a whole number of origin intervals"),
                  (set_package(interval=0.0001), "a whole number of origin intervals"),
                  (set_package(date="2026-02-30"), "no date of the layout"),
                  (set_package(revision="HEAD"), "no commit of the layout"),
                  (set_package(id="GD-3"), "is none of"),
                  (set_package(clock="  "), "no name of the layout"),
                  (set_package(clock_error_seconds=-1), "no nonnegative of the layout"),
                  (lambda ev: ev.package["shards"].append("receipts"), "no file-name of the layout: 'receipts'"),
                  (lambda ev: ev.package["shards"].append("a/b"), "no file-name of the layout: 'a/b'"),
                  (lambda ev: ev.package["target"].update(host="h9"), "target host is no host of the layout"),
                  (lambda ev: ev.package["witness"][0].update(sha256=ev.package["witness"][0]["sha256"].upper()),
                   "no digest of the layout"),
                  (lambda ev: ev["activations.jsonl"].append({"host": "h4", "activations": []}), "repeats a host"),
                  (at("s5", {"time": 80, "attempts": 2}), "other than its last version"),
                  (aborted("operator"), "'operator' is none of"),
                  (lambda ev: ev["witness.jsonl"][0].update(outcome="stale"), "'stale' is none of")]
        for plant, words in cases:
            with self.subTest(words=words):
                self.assert_refused(planted(plant), words)
        files = Evidence().bytes()
        files["package.json"] += b"\n"
        with self.assertRaisesRegex(gj.Refusal, "differs from the digest in injection/roles.json"):
            gj.judge(gj.load_evidence(files), self.catalog, FIS, rd)

    def test_malformed_bytes_are_refused(self):
        def appended(rel, text):
            files = Evidence().bytes()
            files[rel] += text.encode() if isinstance(text, str) else text
            return files

        cases = [(appended("origin.jsonl", '{"time": 1, "key": "k"'), "no newline"),
                 (appended("origin.jsonl", "\n"), "origin.jsonl line 28 is not strict JSON"),
                 (appended("origin.jsonl", '{"time": 1, "key": "k", "key": "j"}\n'), "repeats a key"),
                 (appended("origin.jsonl", '{"time": NaN, "key": "k"}\n'), "not strict JSON"),
                 (appended("origin.jsonl", '{"time": 1e400, "key": "k"}\n'), "beyond a double's range"),
                 (appended("origin.jsonl", '{"time": true, "key": "k"}\n'), "no time of the layout"),
                 (appended("origin.jsonl", f'{{"time": {2 ** 53 + 1}, "key": "k"}}\n'), "no time of the layout"),
                 (appended("witness.jsonl", b"\xff\n"), "not UTF-8"),
                 ({**Evidence().bytes(), "package.json": b"[]\n"}, "package.json is no object")]
        for files, words in cases:
            with self.subTest(words=words):
                with self.assertRaises(gj.Refusal) as caught:
                    gj.load_evidence(files)
                self.assertIn(words, str(caught.exception))

    def test_a_directory_holding_a_link_or_another_directory_is_refused(self):
        def link(root):
            (root / "blockers.jsonl").rename(root / "elsewhere")
            (root / "blockers.jsonl").symlink_to("elsewhere")

        for edit, words in ((link, "a link or a special file"),
                            (lambda root: (root / "records-old").mkdir(), "no directory of the layout"),
                            (lambda root: (root / "records/old").mkdir(), "no directory of the layout")):
            with self.subTest(words=words), tempfile.TemporaryDirectory(prefix="gameday-judge-") as top:
                root = Path(top, "evidence")
                Evidence().write(root)
                edit(root)
                with self.assertRaises(gj.Refusal) as caught:
                    gj.run(str(root), os.path.join(top, "record.json"), self.catalog, FIS, rd)
                self.assertIn(words, str(caught.exception))
                self.assertFalse(os.path.lexists(os.path.join(top, "record.json")))

    def test_a_gd2_text_other_than_the_rules_were_written_from_is_exit_2(self):
        def changed(edit):
            catalog = copy.deepcopy(self.catalog)
            edit(next(e for e in catalog["entries"] if e["id"] == "GD-2"))
            return catalog

        def clause(i):
            return lambda e: e["hypothesis"][i].update(clause=e["hypothesis"][i]["clause"] + " within the run")

        edits = [(clause(i), "hypothesis clauses") for i in range(5)]
        edits += [(lambda e: e["hypothesis"][4].update(bound="re-enrollment-drain"), "hypothesis clauses"),
                  (lambda e: e["guardrail"].insert(2, e["guardrail"].pop(4)), "guardrails"),
                  (lambda e: e["guardrail"].__setitem__(4, "a shard that changes hands three times"), "guardrails"),
                  (lambda e: e["guardrail"].pop(), "guardrails"),
                  (lambda e: e["oracle"].update(expected=e["oracle"]["expected"].replace("first hit", "hit")),
                   "oracle.expected"),
                  (lambda e: e["oracle"].update(expected=e["oracle"]["expected"].replace(
                      "no tenure activated twice", "no tenure activated three times")), "oracle.expected"),
                  (lambda e: e["hypothesis"].insert(0, e["hypothesis"].pop(1)), "hypothesis clauses"),
                  (lambda e: e["hypothesis"].append({"clause": "every host reports healthy", "bound": None}),
                   "hypothesis clauses"),
                  (lambda e: e["guardrail"].append("any alarm"), "guardrails"),
                  (lambda e: e["oracle"].update(reach=e["oracle"]["reach"] + "."), "oracle.reach"),
                  (lambda e: e.update(mode="rehearsal"), "not a causal package")]
        for edit, words in edits:
            with self.subTest(words=words):
                self.assert_refused(Evidence(), words, changed(edit))
        self.assertIn("no tenure activated twice", GD2["oracle"]["expected"])
        twice = copy.deepcopy(self.catalog)
        twice["entries"].append(copy.deepcopy(GD2))
        self.assert_refused(Evidence(), "holds 2 entries GD-2", twice)
        for field, edit in (("run_rule", lambda c: c.pop("run_rule")), ("budgets", lambda c: c.pop("budgets")),
                            ("entries", lambda c: c.update(entries={}))):
            with self.subTest(catalog_without=field):
                shapeless = copy.deepcopy(self.catalog)
                edit(shapeless)
                self.assert_refused(Evidence(), "holds no entries, budgets and run rule", shapeless)
        # Prerequisites, runbooks and budget values are read as they stand.
        free = changed(lambda e: e.update(prerequisites=["met"], runbooks=["a", "b"]))
        self.assertEqual(judged(Evidence(), free)[0], 0)

    def test_an_existing_record_path_or_one_inside_the_evidence_is_refused_and_left_as_it_stands(self):
        with tempfile.TemporaryDirectory(prefix="gameday-judge-") as top:
            record = Path(top, "record.json")
            record.write_bytes(b"an earlier record\n")
            with self.assertRaisesRegex(gj.Refusal, "replaces none"):
                gj.run(str(HELD), str(record), self.catalog, FIS, rd)
            self.assertEqual(record.read_bytes(), b"an earlier record\n")
            Path(top, "dangling.json").symlink_to("nowhere")
            with self.assertRaisesRegex(gj.Refusal, "replaces none"):
                gj.run(str(HELD), os.path.join(top, "dangling.json"), self.catalog, FIS, rd)
            Path(top, "dangling.json").unlink()
            root = Path(top, "evidence")
            Evidence().write(root)
            with self.assertRaisesRegex(gj.Refusal, "inside the evidence directory"):
                gj.run(str(root), str(root / "injection/record.json"), self.catalog, FIS, rd)
            self.assertFalse(os.path.lexists(root / "injection/record.json"))
            self.assertEqual(sorted(p.name for p in Path(top).iterdir()), ["evidence", "record.json"])



    def test_a_failed_directory_sync_leaves_no_record_or_says_that_one_stands(self):
        real_unlink = os.unlink

        def unlink_all_but(record):
            def unlink(path, *args, **kwargs):
                if path == os.path.basename(record) and kwargs.get("dir_fd") is not None:
                    raise OSError(5, "Input/output error")
                return real_unlink(path, *args, **kwargs)
            return unlink

        for removable, resynced in ((True, True), (True, False), (False, True)):
            with self.subTest(removable=removable, resynced=resynced), \
                    tempfile.TemporaryDirectory(prefix="gameday-judge-") as top:
                record = os.path.join(top, "record.json")
                syncs = [None, OSError(5, "EIO"), None if resynced else OSError(5, "EIO")]
                with contextlib.ExitStack() as stack:
                    fsync = stack.enter_context(mock.patch.object(gj.os, "fsync", side_effect=syncs))
                    if not removable:
                        stack.enter_context(mock.patch.object(gj.os, "unlink", side_effect=unlink_all_but(record)))
                    with self.assertRaises(gj.Refusal) as caught:
                        gj.run(str(HELD), record, self.catalog, FIS, rd)
                    if not removable:
                        Path(record).unlink()
                        stack.enter_context(mock.patch.object(gj.os, "fsync", side_effect=syncs))
                        stderr = stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
                        self.assertEqual(gj.main(["--evidence", str(HELD), "--record", record]), 2)
                        self.assertIn("may stand", stderr.getvalue())
                        self.assertNotIn("no record written", stderr.getvalue())
                stands = not (removable and resynced)
                self.assertEqual(caught.exception.written, stands)
                self.assertEqual(fsync.call_count, 3 if removable else 2)
                fsync = None
                self.assertEqual(os.path.lexists(record), not removable)
                self.assertEqual(sorted(p.name for p in Path(top).iterdir()), [] if removable else ["record.json"])
                self.assertIn("may stand" if stands else "the record is removed", str(caught.exception))


def late_read(*versions, **pinned):
    """A roles read at 120, after the stop, over s5 versions committed between the stop and the read; `pinned`
    changes s5's version in `roles.json` to the last of them."""
    def plant(ev):
        ev.roles["time"] = 120
        ev.records("s5")[1:1] = [{**ev.records("s5")[0], **v} for v in versions]
        ev.roles["shards"]["s5"].update(pinned)
    return plant


def short_run(ev):
    """The run window ends at 190, inside each shard's drain, and s4 has no version after the roles read."""
    ev.package["run"]["end"] = 190
    ev["records/s4.jsonl"] = [v for v in ev.records("s4") if v["time"] != 180]


def stands_by_for_none(ev):
    ev.role("s4", standby="h3")


def second_key(ev):
    """A second witness key of the owned shard s1, first hit on its successor at 145 with its pinned digest."""
    digest = hashlib.sha256(b"k1b").hexdigest()
    ev.package["witness"].append({"key": "img/k1b", "shard": "s1", "sha256": digest})
    ev["witness.jsonl"] = sorted(ev["witness.jsonl"] + [{"key": "img/k1b", "host": "h2", "time": 145,
                                                        "outcome": "hit", "sha256": digest}], key=lambda r: r["time"])


def origin_rows(*rows):
    """Replace origin.jsonl by `rows` of (time, key), in time order."""
    def plant(ev):
        ev["origin.jsonl"] = [{"time": t, "key": k} for t, k in sorted(rows)]
    return plant


class HeldBoundaries(Judging):
    """The windows, the counts and the reach conditions the rules read at their edges, under the blocked catalog
    copy; `HeldBoundariesUnderSetCatalog` runs them again under the set copy."""

    def test_an_unmet_reach_reads_witness_keys_of_shards_the_target_lost_and_the_guardrails_it_can_show(self):
        def lost(ev):
            for s in ("s2", "s3"):
                ev.role(s, owner="h2", standby="h3")
            moved = [a for a in ev.activations("h1") if a["shard"] in ("s2", "s3")]
            ev.activations("h1")[:] = [a for a in ev.activations("h1") if a not in moved]
            ev.activations("h2").extend(moved)

        self.assert_pair(planted(lost), "FAILED_TO_INJECT", "INCONCLUSIVE")
        self.assert_disproven(planted(lost, two_activating_hosts), {"one-owner-per-tenure"}, "HALTED")
        self.assert_disproven(planted(stands_by_for_none, history_from_takeover), {"one-owner-per-tenure"}, "HALTED")
        cases = (("standby-again", no_enrolled_standby, "drain", "s1 names no enrolled standby"),
                 ("origin-load", flood(190), "origin", "holds"))
        for rule, plant, guard, words in cases:
            with self.subTest(rule=rule):
                record = self.assert_pair(planted(stands_by_for_none, plant), "FAILED_TO_INJECT", "INCONCLUSIVE")
                named = record["rules"][rule]
                self.assertEqual((named["result"], named["guardrail"], named["past_stop_condition"]),
                                 ("unobserved", GUARD[guard], True))
                self.assertTrue(any(words in d for d in named["detail"][1:]), named["detail"])

    def test_the_drain_counts_nothing_at_or_after_the_run_windows_end(self):
        def enrolled(t):
            return lambda ev: ev.records("s4").append({**ev.records("s4")[0], "time": t, "standby": "h3"})

        def blocker(t):
            return lambda ev: ev["blockers.jsonl"].append({"shard": "s4", "time": t, "name": "no host has room"})

        for name, at in (("enrollment", enrolled), ("blocker", blocker)):
            with self.subTest(observation=name):
                record = self.assert_pair(planted(short_run, at(190)), "COMPLETED", "INCONCLUSIVE")
                self.assertEqual(self.results(record, "unobserved"), {"standby-again"})
                self.assertIsNone(record["rules"]["standby-again"]["guardrail"])
                self.assert_pair(planted(short_run, at(189)), "COMPLETED", "HELD")

    def test_an_owned_shard_never_taken_over_starts_no_drain(self):
        def kept(ev):
            ev["records/s1.jsonl"] = ev.records("s1")[:1]
            ev.activations("h2")[:] = [a for a in ev.activations("h2") if a["shard"] != "s1"]

        def taken_over_at_the_window_end(ev):
            ev["records/s1.jsonl"] = [ev.records("s1")[0], {**ev.records("s1")[1], "time": 400}]
            next(a for a in ev.activations("h2") if a["shard"] == "s1")["time"] = 400

        for plant in (kept, taken_over_at_the_window_end):
            with self.subTest(plant=plant.__name__):
                record = self.assert_disproven(planted(plant), {"takeover", "witness-first-hit"})
                named = record["rules"]["standby-again"]
                self.assertEqual((named["result"], named["guardrail"], named["past_stop_condition"]),
                                 ("unobserved", None, False))
                self.assertEqual(named["detail"], ["owned shard s1 has no takeover write in the run window, so its "
                                                   "drain does not start"])

    def test_origin_load_grades_the_requests_from_the_stop_on_exactly(self):
        # The rule grades requests from the stop on: a dense burst wholly before the stop, inside the run window,
        # leaves the rule HELD.
        def early_burst(ev):
            ev["origin.jsonl"] = sorted(ev["origin.jsonl"] + [{"time": 100 + i / 16, "key": f"img/early-{i}"}
                                                             for i in range(160)], key=lambda r: r["time"])

        record = self.assert_pair(planted(early_burst), "COMPLETED", "HELD")
        self.assertIsNone(record["rules"]["origin-load"]["guardrail"])
        # 120 baseline requests in 100 s and 30 s intervals: an excess equal to the bound holds, one request over it
        # is disproven.
        base = [(i * 0.8, f"img/base-{i}") for i in range(120)]
        allowed = int((self.bound("origin-load") + 1.2) * 30 + 0.5)
        for n, held in ((allowed - 1, True), (allowed, True), (allowed + 1, False)):
            with self.subTest(requests=n):
                plant = origin_rows(*base, *((190 + i * 0.25, f"img/run-{i}") for i in range(n)))
                if held:
                    self.assert_pair(planted(plant), "COMPLETED", "HELD")
                else:
                    self.assert_disproven(planted(plant), {"origin-load"})

        # Intervals of a tenth of a second at a decimal edge whose double sum lands below it: two requests in
        # [165.1, 165.2) breach a bound one request per interval keeps; the same two across the edge hold.
        def tenths(*times):
            rows = [(i / 12, f"img/base-{i}") for i in range(1200)] + [(t, f"img/edge-{t}") for t in times]

            def plant(ev):
                ev.package["interval"] = 0.1
                origin_rows(*rows)(ev)
            return plant

        record = self.assert_disproven(planted(tenths(165.1, 165.15)), {"origin-load"})
        self.assertEqual(record["rules"]["origin-load"]["detail"],
                         ["[165.1, 165.2) holds 2 origin requests in 0.1 s against the baseline's 1200 in 100 s"])
        self.assert_pair(planted(tenths(165.05, 165.1)), "COMPLETED", "HELD")

    def test_a_contradiction_outranks_an_unobserved_cause_inside_one_rule(self):
        def no_h4_line(ev):
            ev["activations.jsonl"] = [r for r in ev["activations.jsonl"] if r["host"] != "h4"]

        def h3_activates(ev):
            ev.activations("h3").append({"shard": "s1", "generation": 7, "attempt": 4, "time": 126})

        for status, extra in (("COMPLETED", ()), ("HALTED", (stands_by_for_none,))):
            with self.subTest(status=status):
                named = self.assert_disproven(planted(*extra, h3_activates, no_h4_line),
                                              {"one-owner-per-tenure"}, status)["rules"]["one-owner-per-tenure"]
                self.assertEqual(named["guardrail"], GUARD["activation"])

        def k2_on_h2(ev):
            next(r for r in ev["witness.jsonl"] if r["key"] == "img/k2" and r["outcome"] == "hit")["host"] = "h2"

        def never(ev):
            ev["witness.jsonl"] = [r for r in ev["witness.jsonl"] if r["key"] != "img/k3"]

        record = self.assert_pair(planted(never, k2_on_h2), "COMPLETED", "DISPROVEN")
        self.assertEqual(record["rules"]["witness-first-hit"]["result"], "disproven")


class HeldBoundariesUnderSetCatalog(HeldBoundaries):
    """Every case of `HeldBoundaries` under the catalog copy with both budgets set."""

    catalog = set_catalog()
    blocked = False


class ClockAndCoverage(Judging):
    """The stop as its effect, the clock error between writers, the stop request's record, collection coverage, the
    activation join and the pre-stop half of the reach, under the committed catalog."""

    assert_refused = Refusals.assert_refused

    def test_a_get_the_target_serves_before_it_is_reported_stopped_is_no_hit_after_the_stop(self):
        self.assert_pair(planted(witness_rows("img/k1", ("h1", 110, "hit"), ("h2", 140, "hit"))), "COMPLETED", "HELD")
        self.assert_disproven(planted(witness_rows("img/k1", ("h1", 113, "hit"), ("h2", 140, "hit"))),
                              {"witness-first-hit"})

    def test_stamps_of_two_writers_within_the_clock_error_are_undecided(self):
        def error(seconds):
            return lambda ev: ev.package.update(clock_error_seconds=seconds)

        # A GET stamped exactly one clock error after the stop leaves the run INCONCLUSIVE.
        self.assert_pair(planted(error(1)), "COMPLETED", "HELD")
        record = self.assert_pair(planted(error(1), witness_rows("img/k1", ("h2", 113, "hit"))), "COMPLETED",
                                  "INCONCLUSIVE")
        self.assertEqual(self.results(record, "unobserved"), {"witness-first-hit", "no-origin-before-hit"})
        # The same GET with no clock error is a first hit, before the takeover write at 125.
        self.assert_disproven(planted(witness_rows("img/k1", ("h2", 113, "hit"))), {"witness-first-hit"})
        self.assert_refused(planted(simulation, error(1)), "a simulation package names a clock error")

        def burst_near_the_stop(ev):
            ev["origin.jsonl"] = sorted(ev["origin.jsonl"] + [{"time": 111.5, "key": f"img/near-{i}"}
                                                             for i in range(80)], key=lambda r: r["time"])

        def blocker_at_the_drains_end(past=0):
            def plant(ev):
                ev.version("s1", 150, standby=None)
                ev["blockers.jsonl"].append({"shard": "s1", "time": 125 + self.bound("re-enrollment-drain") + past,
                                             "name": "no host has room"})
            return plant

        def origin_near_the_hit(ev):
            ev["origin.jsonl"] = sorted(ev["origin.jsonl"] + [{"time": 139.5, "key": "img/k1"}],
                                        key=lambda r: r["time"])

        def blocker_at_the_drains_start(time=112.5):
            def plant(ev):
                ev["records/s4.jsonl"] = ev.records("s4")[:1]
                ev["blockers.jsonl"].append({"shard": "s4", "time": time, "name": "no host has room"})
            return plant

        def lone_request_near_the_stop(ev):
            ev.package["interval"] = 0.5
            ev["origin.jsonl"] = [r for r in ev["origin.jsonl"] if r["time"] < 100] + [
                {"time": 112.25, "key": "img/near"}]

        def requests_around_the_stops_interval(before):
            # The stop at 112 splits [111.25, 113.125), so the rule grades [112, 115).
            def plant(ev):
                ev.package["interval"] = 1.875
                ev["origin.jsonl"] = sorted(ev["origin.jsonl"] + [{"time": 111.125, "key": "img/near"}] * before + [
                    {"time": 113.25, "key": f"img/after-{i}"} for i in range(3)], key=lambda r: r["time"])
            return plant

        def activation(host, epoch, time):
            return lambda ev: ev.activations(host).append({"shard": "s5", "generation": 5, "attempt": epoch,
                                                           "time": time})

        def burst_before_a_stop_at_the_run_windows_start(time):
            def plant(ev):
                ev.roles["time"] = 95
                ev["injection/stop.json"]["time"] = ev["injection/stopped.json"]["request"]["time"] = 100.25
                ev["injection/stopped.json"]["time"] = 100.5
                ev["origin.jsonl"] = sorted(ev["origin.jsonl"] + [{"time": time, "key": f"img/near-{i}"}
                                                                 for i in range(200)], key=lambda r: r["time"])
            return plant

        self.assert_pair(planted(error(1), burst_before_a_stop_at_the_run_windows_start(99.25)), "COMPLETED", "HELD")
        self.assert_pair(planted(error(1), requests_around_the_stops_interval(0)), "COMPLETED", "HELD")
        self.assert_pair(planted(error(1), activation("h4", 3, 103.5)), "COMPLETED", "HELD")
        self.assert_disproven(planted(error(1), activation("h4", 3, 106.5)), {"one-owner-per-tenure"})
        for name, plant, rules in (("a first hit beside the takeover write",
                                    witness_rows("img/k1", ("h2", 124, "hit")), {"witness-first-hit"}),
                                   ("origin requests beside the stop", burst_near_the_stop, {"origin-load"}),
                                   ("a blocker beside the drain's end", blocker_at_the_drains_end(), {"standby-again"}),
                                   ("a blocker beside the drain's start", blocker_at_the_drains_start(),
                                    {"standby-again"}),
                                   ("a blocker the clock error before the drain's start",
                                    blocker_at_the_drains_start(111), {"standby-again"}),
                                   ("a blocker the clock error past the drain's end",
                                    blocker_at_the_drains_end(1), {"standby-again"}),
                                   ("an origin request beside the first hit", origin_near_the_hit,
                                    {"no-origin-before-hit"}),
                                   ("one origin request beside the stop, alone in a half-second interval",
                                    lone_request_near_the_stop, {"origin-load"}),
                                   ("an origin request beside the stop, stamped in the interval before the stop's",
                                    requests_around_the_stops_interval(1), {"origin-load"}),
                                   ("origin requests beside the stop, stamped before the run window",
                                    burst_before_a_stop_at_the_run_windows_start(99.75), {"origin-load"}),
                                   ("an activation by a host no version names owner, beside the roles read",
                                    activation("h4", 3, 104.5), {"one-owner-per-tenure"}),
                                   ("a tenure activated a second time beside the roles read",
                                    activation("h3", 2, 104.5), {"one-owner-per-tenure"})):
            with self.subTest(within_the_clock_error=name):
                record = self.assert_pair(planted(error(1), plant), "COMPLETED", "INCONCLUSIVE")
                self.assertEqual(self.results(record, "unobserved"), rules)

        def read_beside_a_version(ev):
            ev.records("s5").append({**ev.records("s5")[0], "time": 105.5, "attempts": 2})
            ev.roles["shards"]["s5"]["attempts"] = 2

        self.assert_pair(planted(error(1), read_beside_a_version), "COMPLETED", "HELD")

        def changed_after_the_version_the_read_names(ev):
            # Both stamps precede the read at 105 by less than the clock error of 1. The read names generation 6,
            # so commit order places generation 7 after the read.
            first = ev.records("s5")[0]
            ev.records("s5").extend([{**first, "time": 104.5, "generation": 6},
                                     {**first, "time": 104.75, "generation": 7}])
            ev.roles["shards"]["s5"]["generation"] = 6

        self.assert_disproven(planted(error(1), changed_after_the_version_the_read_names), {"no-generation-change"})

        def enrolled_late_in_a_drain_from_a_write_at_the_stop(ev):
            ev.version("s1", 125, time=112)
            next(a for a in ev.activations("h2") if a["shard"] == "s1")["time"] = 112
            ev.version("s1", 150, time=112 + self.bound("re-enrollment-drain") - 0.5)

        self.assert_pair(planted(error(1), enrolled_late_in_a_drain_from_a_write_at_the_stop), "COMPLETED", "HELD")
        self.assert_refused(planted(read_beside_a_version), "other than its last version")
        def moved(time):
            return lambda ev: ev.records("s4").insert(1, {**ev.records("s4")[0], "time": time, "standby": "h3"})

        for time in (105.5, 110.5):
            with self.subTest(role_change_at=time):
                record = self.assert_pair(planted(error(1), moved(time)), "FAILED_TO_INJECT", "INCONCLUSIVE")
                self.assertTrue(any("within the clock error" in d for d in record["reach"]["detail"]))

    def test_a_role_change_stamped_the_clock_error_from_the_roles_read_or_the_stop_fails_to_inject(self):
        def error(ev):
            ev.package["clock_error_seconds"] = 1

        def taken_over_at(time):
            return lambda ev: ev.version("s1", 125, time=time)

        def standby_moved_and_back(time):
            # s4 names standby h3 at `time` and h1 again at 104.5, the version the read at 105 names.
            return at("s4", {"time": time, "standby": "h3"}, {"time": 104.5, "standby": "h1"}, before=180)

        # The stop request is stamped 110 and the roles read 105: a stamp exactly the clock error from either is
        # undecided against it, and one beyond the error is decided.
        for name, plant in (("the stop", taken_over_at(111)), ("the roles read", standby_moved_and_back(104))):
            with self.subTest(a_role_change_the_clock_error_from=name):
                record = self.assert_pair(planted(error, plant), "FAILED_TO_INJECT", "INCONCLUSIVE")
                self.assertEqual(len([d for d in record["reach"]["detail"] if "within the clock error" in d]), 1)
        for name, plant in (("the stop", taken_over_at(111.25)), ("the roles read", standby_moved_and_back(103.75))):
            with self.subTest(a_role_change_beyond_the_clock_error_of=name):
                self.assert_pair(planted(error, plant), "COMPLETED", "HELD")
        # With no clock error a version at the stop request's time follows it.
        self.assert_pair(planted(taken_over_at(110)), "COMPLETED", "HELD")

    def test_a_stamp_within_the_clock_error_before_a_controllers_mark_is_read_and_not_refused(self):
        def error(ev):
            ev.package["clock_error_seconds"] = 1

        def first_get_at(time):
            # img/k2's first GET, an error, is the first line of the witness log; the stop request is at 110.
            return lambda ev: ev["witness.jsonl"][0].update(time=time)

        def standby_moved_at(time):
            # s4 names standby h3 from `time` on; the roles read at 105 names h1, as the version at 50 does.
            return lambda ev: ev.records("s4").insert(1, {**ev.records("s4")[0], "time": time, "standby": "h3"})

        # A GET the client stamps within the clock error before the stop request may follow it. It precedes the
        # stopped report at 112 beyond the error, so it is no request after the stop and the key's hit at 141 is
        # judged.
        for time in (109, 109.5):
            with self.subTest(a_get_within_the_clock_error_before_the_stop_request=time):
                self.assert_pair(planted(error, first_get_at(time)), "COMPLETED", "HELD")
        self.assert_refused(planted(error, first_get_at(108.75)), "witness.jsonl line 1 precedes the stop")
        self.assert_refused(planted(first_get_at(109.5)), "witness.jsonl line 1 precedes the stop")
        # A version stamped within the clock error before the roles read may follow the read, so the read may name
        # the version before it; the role change then stands within the clock error of the read and nothing is
        # injected.
        for time in (104, 104.5):
            with self.subTest(a_version_within_the_clock_error_before_the_roles_read=time):
                record = self.assert_pair(planted(error, standby_moved_at(time)), "FAILED_TO_INJECT", "INCONCLUSIVE")
                self.assertEqual(len([d for d in record["reach"]["detail"] if "within the clock error" in d]), 1)
        self.assert_refused(planted(error, standby_moved_at(103.75)), "other than its last version")
        self.assert_refused(planted(standby_moved_at(104.5)), "other than its last version")

        # s5's two versions both lie within the clock error before the read, which names the second: commit order
        # places the first, of another owner, before the reference, so it changes no owner after it.
        def owned_by_h4_then_h3(ev):
            last = ev.records("s5")[0]
            ev["records/s5.jsonl"] = [{**last, "time": 104.3, "owner": "h4", "standby": "h3"}, {**last, "time": 104.6}]

        record = self.assert_pair(planted(error, owned_by_h4_then_h3), "FAILED_TO_INJECT", "INCONCLUSIVE")
        self.assertEqual(self.results(record, "held"), set(SAFETY))
        self.assertIsNone(record["rules"]["others-keep-owner"]["guardrail"])

    def test_a_blocker_stamped_the_clock_error_inside_a_drains_end_is_undecided(self):
        def error(ev):
            ev.package["clock_error_seconds"] = 1

        def s4_blocked_at(time):
            # s4's drain starts at the stop, 112; its only enrollment or blocker is one blocker at `time`.
            def plant(ev):
                ev["records/s4.jsonl"] = ev.records("s4")[:1]
                ev["blockers.jsonl"].append({"shard": "s4", "time": time, "name": "no host has room"})
            return plant

        end = 112 + self.bound("re-enrollment-drain")
        for time in (113, end - 1):
            with self.subTest(a_blocker_the_clock_error_inside_the_drain_at=time):
                record = self.assert_pair(planted(error, s4_blocked_at(time)), "COMPLETED", "INCONCLUSIVE")
                self.assertEqual(self.results(record, "unobserved"), {"standby-again"})
        for time in (113.25, end - 1.25):
            with self.subTest(a_blocker_beyond_the_clock_error_inside_the_drain_at=time):
                self.assert_pair(planted(error, s4_blocked_at(time)), "COMPLETED", "HELD")
        # With no clock error the drain holds both of its ends.
        for time in (112, end):
            with self.subTest(a_blocker_at_the_drains_end=time):
                self.assert_pair(planted(s4_blocked_at(time)), "COMPLETED", "HELD")

    def test_a_takeover_write_within_the_clock_error_of_the_stop_leaves_the_drains_start_undecided(self):
        def error(ev):
            ev.package["clock_error_seconds"] = 1

        def s1_taken_over_and_enrolled(write, past_the_drain):
            # s1's takeover write at `write` and its enrollment `past_the_drain` seconds after the drain from it.
            def plant(ev):
                ev.version("s1", 125, time=write)
                ev.version("s1", 150, time=write + self.bound("re-enrollment-drain") + past_the_drain)
            return plant

        # The stop is the stopped report at 112. A write stamped 112.5 may precede a stop as late as 113 on the
        # records' clock, so the drain may start at 113 and hold an enrollment half a second past the drain from
        # the write. A write stamped 113.25 surely follows the stop and starts the drain by its own stamp.
        record = self.assert_pair(planted(error, s1_taken_over_and_enrolled(112.5, 0.5)), "COMPLETED", "INCONCLUSIVE")
        self.assertEqual(self.results(record, "unobserved"), {"standby-again"})
        self.assert_disproven(planted(error, s1_taken_over_and_enrolled(112.5, 1.5)), {"standby-again"})
        self.assert_disproven(planted(error, s1_taken_over_and_enrolled(113.25, 0.5)), {"standby-again"})
        self.assert_pair(planted(error, s1_taken_over_and_enrolled(113.25, 0)), "COMPLETED", "HELD")
        self.assert_disproven(planted(s1_taken_over_and_enrolled(112.5, 0.5)), {"standby-again"})

        # With no clock error a version stamped at the stop's own time is inside the drain, whatever its digits:
        # 112.2 is a double above its decimal. s4's drain starts at the stop; s1's takeover write names a standby.
        def stopped_and_enrolled_at(time, shard, at):
            def plant(ev):
                ev["injection/stopped.json"]["time"] = time
                ev.version(shard, at, time=time, standby="h4" if shard == "s1" else "h3")
                for a in ev.activations("h2"):
                    a["time"] = time if (a["shard"], a["time"]) == (shard, at) else a["time"]
                ev[f"records/{shard}.jsonl"] = [v for v in ev.records(shard) if v["time"] <= time]
            return plant

        for shard, at in (("s4", 180), ("s1", 125)):
            with self.subTest(enrolled_at_the_stop=shard):
                self.assert_pair(planted(stopped_and_enrolled_at(112.2, shard, at)), "COMPLETED", "HELD")

        # 112.3 is a double below its decimal: an enrollment stamped the drain and the clock error after it is
        # still possibly inside the drain from the stop.
        def enrolled_the_clock_error_past_the_drain(ev):
            ev["injection/stopped.json"]["time"] = 112.3
            ev.version("s4", 180, time=112.3 + self.bound("re-enrollment-drain") + 1)

        self.assertEqual(Evidence().records("s4")[1]["time"], 180)
        record = self.assert_pair(planted(error, enrolled_the_clock_error_past_the_drain), "COMPLETED",
                                  "INCONCLUSIVE")
        self.assertEqual(self.results(record, "unobserved"), {"standby-again"})

        # An enrollment stamped within the clock error of the stop may precede the drain's start.
        def enrolled_at(time):
            def plant(ev):
                ev.version("s1", 125, time=112.25)
                ev.version("s1", 150, time=time)
            return plant

        record = self.assert_pair(planted(error, enrolled_at(112.5)), "COMPLETED", "INCONCLUSIVE")
        self.assertEqual(self.results(record, "unobserved"), {"standby-again"})
        self.assert_pair(planted(error, enrolled_at(113.25)), "COMPLETED", "HELD")
        self.assert_pair(planted(enrolled_at(112.5)), "COMPLETED", "HELD")

    def test_a_get_within_the_clock_error_of_the_stop_leaves_the_keys_later_gets_graded(self):
        def error(ev):
            ev.package["clock_error_seconds"] = 1

        def origin_request(time, key):
            def plant(ev):
                ev["origin.jsonl"] = sorted(ev["origin.jsonl"] + [{"time": time, "key": key}],
                                            key=lambda r: r["time"])
            return plant

        # The stop is the stopped report at 112, so a GET at 113 is within the clock error of it. A GET that is no
        # hit decides nothing about the key's first hit, which the later GETs show.
        near = ("h2", 113, "miss")
        self.assert_pair(planted(error, witness_rows("img/k3", near, ("h2", 142, "hit"))), "COMPLETED", "HELD")
        self.assert_disproven(planted(error, witness_rows("img/k3", near, ("h3", 140, "hit"), ("h2", 350, "hit"))),
                              {"witness-first-hit"})
        self.assert_disproven(planted(error, witness_rows("img/k3", near, ("h2", 142, "hit")),
                                      origin_request(120, "img/k3")), {"no-origin-before-hit"})
        self.assert_disproven(planted(error, witness_rows("img/k3", near, ("h2", 142, "miss"))),
                              {"witness-first-hit"})
        # A hit within the clock error may be the first hit after the stop, and a key whose only GETs lie within it
        # may be unrequested: either leaves both witness rules unobserved.
        witness = {"witness-first-hit", "no-origin-before-hit"}
        for name, rows in (("a hit beside the stop, then a hit on another host",
                            (("h2", 113, "hit"), ("h3", 140, "hit"))),
                           ("a hit beside the stop, then a hit on the successor",
                            (("h2", 113, "hit"), ("h2", 142, "hit"))),
                           ("no GET but one beside the stop", (near,))):
            with self.subTest(undecided=name):
                record = self.assert_pair(planted(error, witness_rows("img/k3", *rows)), "COMPLETED",
                                          "INCONCLUSIVE")
                self.assertEqual(self.results(record, "unobserved"), witness)
                self.assertEqual(record["rules"]["witness-first-hit"]["detail"], [
                    "witness key img/k3 has a hit, or its only GETs, within the clock error of the stop"])

    def test_the_control_planes_record_of_the_request_matches_the_stop_request_within_the_clock_error(self):
        def recorded(**changes):
            return lambda ev: ev["injection/stopped.json"]["request"].update(changes)

        self.assert_pair(planted(recorded(time=111)), "FAILED_TO_INJECT", "INCONCLUSIVE")
        self.assert_pair(planted(recorded(identity="another-role")), "FAILED_TO_INJECT", "INCONCLUSIVE")
        self.assert_pair(planted(recorded(instance="i-h2")), "FAILED_TO_INJECT", "INCONCLUSIVE")
        self.assert_pair(planted(recorded(time=111), lambda ev: ev.package.update(clock_error_seconds=1)),
                         "COMPLETED", "HELD")

    def test_coverage_counts_every_file_and_a_short_span_leaves_its_rules_unobserved(self):
        def count(rel, lines):
            def plant(ev):
                ev.keep_coverage = True
                ev["coverage.json"][rel]["lines"] = lines
            return plant

        def entries(edit):
            def plant(ev):
                ev.bytes()
                ev.keep_coverage = True
                edit(ev["coverage.json"])
            return plant

        self.assert_refused(planted(count("origin.jsonl", 3)), "counts 3 lines")
        self.assert_refused(planted(count("origin.jsonl", 1 << 53)), f"counts {1 << 53} lines")
        self.assert_refused(planted(count("origin.jsonl", (1 << 53) + 1)), "lines is no count of the layout")
        self.assert_refused(planted(entries(lambda c: c.pop("witness.jsonl"))), "not exactly the observeds")
        self.assert_refused(planted(entries(lambda c: c.update({"records/s9.jsonl": c["records/s1.jsonl"]}))),
                            "not exactly the observeds")
        short = entries(lambda c: c["provider.jsonl"].update({"to": 300}))
        record = self.assert_pair(planted(short), "COMPLETED", "INCONCLUSIVE")
        self.assertEqual(self.results(record, "unobserved"), {"no-volume-created"})
        empty = entries(lambda c: c["provider.jsonl"].update({"from": 0, "to": 0}))
        self.assertEqual(self.results(self.assert_pair(planted(empty), "COMPLETED", "INCONCLUSIVE"), "unobserved"),
                         {"no-volume-created"})
        # A contradiction in a log that spans less of the window still stands.
        self.assert_disproven(planted(control("no-volume-created"), short), {"no-volume-created"})
        def spanning(rel, **span):
            return entries(lambda c: c[rel].update(span))

        self.assert_refused(planted(spanning("witness.jsonl", **{"from": 500})), "backwards")
        records = set(gj.RULES) - {"no-volume-created", "origin-load", "no-origin-before-hit",
                                   "no-replacement-receipt"}
        for name, plant, rules in (("the origin log from inside the baseline window",
                                    spanning("origin.jsonl", **{"from": 50}), {"origin-load"}),
                                   ("a shard's record history short of the run window's end",
                                    spanning("records/s5.jsonl", to=399), records)):
            with self.subTest(short=name):
                record = self.assert_pair(planted(plant), "COMPLETED", "INCONCLUSIVE")
                self.assertEqual(self.results(record, "unobserved"), rules)

    def test_the_tenure_rule_needs_its_collections_from_the_baseline_windows_start(self):
        def spanning(rel, start):
            def plant(ev):
                ev.bytes()
                ev.keep_coverage = True
                ev["coverage.json"][rel]["from"] = start
            return plant

        def activated_again(ev):
            # h2 first activated s4's tenure (generation 3, attempts 1) at 5, inside the baseline window.
            ev.activations("h2").append({"shard": "s4", "generation": 3, "attempt": 2, "time": 200})

        def from_the_run_window(ev):
            for row in ev["activations.jsonl"]:
                row["activations"] = [a for a in row["activations"] if a["time"] >= 100]
            spanning("activations.jsonl", 100)(ev)

        def owned_before(ev):
            # h4 owned s4's tenure at 30, which h2 holds from 50 on, after a version at 40 of another tenure.
            first = ev.records("s4")[0]
            ev.records("s4")[:0] = [{**first, "time": 30, "owner": "h4"}, {**first, "time": 40, "attempts": 2}]

        def from_the_second_version(ev):
            del ev.records("s4")[0]
            spanning("records/s4.jsonl", 40)(ev)

        tenure = {"one-owner-per-tenure"}
        self.assert_disproven(planted(activated_again), tenure)
        self.assert_disproven(planted(owned_before), tenure)
        for name, plants in (("the activations from the run window's start", (activated_again, from_the_run_window)),
                             ("a clean activation log from the run window's start", (from_the_run_window,)),
                             ("the activations from just inside the baseline window",
                              (spanning("activations.jsonl", 0.5),)),
                             ("s4's versions from its second one", (owned_before, from_the_second_version)),
                             ("s4's versions from just inside the baseline window",
                              (spanning("records/s4.jsonl", 0.5),))):
            with self.subTest(short=name):
                record = self.assert_pair(planted(*plants), "COMPLETED", "INCONCLUSIVE")
                self.assertEqual(self.results(record, "unobserved"), tenure)
        # The other rules keep their spans: with the roles read at 95, the provider's log from the run window's
        # start is whole.
        self.assert_pair(planted(lambda ev: ev.roles.update(time=95), spanning("provider.jsonl", 100)), "COMPLETED",
                         "HELD")
        # A contradiction the rows show outranks the short span, and a span from the baseline's start is whole.
        self.assert_disproven(planted(activated_again, spanning("activations.jsonl", 100)), tenure)
        self.assert_pair(planted(lambda ev: ev.package["baseline"].update(start=50),
                                 *(spanning(rel, 50) for rel in Evidence()["coverage.json"])), "COMPLETED", "HELD")

    def test_a_record_history_collected_from_after_the_roles_read_or_to_before_the_stop_shows_no_stop(self):
        def read_at_95(ev):
            ev.roles["time"] = 95
            del ev.records("s5")[0]

        # A history collected from the roles read on shows the stop; the tenure rule alone, which reads both
        # windows, needs it from the baseline window's start.
        record = self.assert_pair(planted(read_at_95, collected("records/s5.jsonl", **{"from": 95})), "COMPLETED",
                                  "INCONCLUSIVE")
        self.assertTrue(record["reach"]["met"])
        self.assertEqual(self.results(record, "unobserved"), {"one-owner-per-tenure"})
        self.assert_pair(planted(read_at_95), "COMPLETED", "HELD")
        record = self.assert_pair(planted(read_at_95, collected("records/s5.jsonl", **{"from": 100})),
                                  "FAILED_TO_INJECT", "INCONCLUSIVE")
        self.assertEqual([d for d in record["reach"]["detail"] if "records/s5.jsonl" in d], [
            "the collection of records/s5.jsonl spans [100, 400], short of the span from the roles read to the stop"])
        self.assertEqual(self.results(record, "held"), {"no-volume-created", "no-replacement-receipt"})
        stop = Evidence()["injection/stop.json"]["time"]
        record = self.assert_pair(planted(collected("records/s5.jsonl", to=stop - 1)), "FAILED_TO_INJECT",
                                  "INCONCLUSIVE")
        self.assertTrue(any("short of the span from the roles read to the stop" in d
                            for d in record["reach"]["detail"]), record["reach"]["detail"])
        self.assertTrue(self.record(planted(collected("records/s5.jsonl", to=stop)))[1]["reach"]["met"])

    def test_a_row_a_short_collection_lacks_contradicts_no_rule(self):
        records = set(gj.RULES) - {"no-volume-created", "origin-load", "no-origin-before-hit",
                                   "no-replacement-receipt"}
        drain_end = 125 + self.bound("re-enrollment-drain")
        for name, plants, rules in (
                ("img/k2's first hit at 141, after the witness log's end", (collected("witness.jsonl", to=140),),
                 {"witness-first-hit", "no-origin-before-hit"}),
                ("s4's enrollment at 180, after its record history's end", (collected("records/s4.jsonl", to=170),),
                 records),
                ("s1's takeover write at 125, after its record history's end",
                 (collected("records/s1.jsonl", to=120),), records),
                ("s1's drain end, after its record history's end",
                 (unenrolled, collected("records/s1.jsonl", to=drain_end - 1)), records)):
            with self.subTest(uncollected=name):
                record = self.assert_pair(planted(*plants), "COMPLETED", "INCONCLUSIVE")
                self.assertEqual(self.results(record, "unobserved"), rules)
        for name, plants, rule in (
                ("a drain that ends inside the collection with no enrollment",
                 (unenrolled, collected("records/s1.jsonl", to=drain_end + 1)), "standby-again"),
                ("a first hit on another host", (wrong_first_host, collected("witness.jsonl", to=145)),
                 "witness-first-hit"),
                ("s1's other volume at 150, after the end of s2's record history",
                 (volume_at(150), collected("records/s2.jsonl", to=140)), "takeover")):
            with self.subTest(collected=name):
                self.assert_disproven(planted(*plants), {rule})

    def test_what_leaves_the_first_hit_rule_undecided_leaves_the_origin_rule_judged(self):
        never_hit = witness_rows("img/k3", ("h2", 142, "miss"))

        def result(rule, *plants):
            return self.record(planted(*plants))[1]["rules"][rule]["result"]

        # img/k3 is requested and never hit, and s5's record history ends a second early: witness-first-hit, which
        # reads the records, cannot tell a missing hit from an unread one, while no-origin-before-hit reads the
        # witness log and the origin log to the run window's end.
        short = collected("records/s5.jsonl", to=399)
        self.assertEqual(result("witness-first-hit", never_hit, short), "unobserved")
        self.assertEqual(result("no-origin-before-hit", never_hit, short), "held")
        self.assert_disproven(planted(never_hit, origin_request(300, "img/k3")),
                              {"witness-first-hit", "no-origin-before-hit"})
        self.assertEqual(result("no-origin-before-hit", never_hit, short, origin_request(300, "img/k3")),
                         "disproven")
        # A first hit within the clock error of the takeover write is a first hit all the same: an origin request
        # before it contradicts no-origin-before-hit.
        beside = (lambda ev: ev.package.update(clock_error_seconds=1), witness_rows("img/k1", ("h2", 124, "hit")))
        self.assertEqual(result("no-origin-before-hit", *beside), "held")
        self.assertEqual(result("no-origin-before-hit", *beside, origin_request(118, "img/k1")), "disproven")

    def test_each_activation_is_made_once_by_the_owner_at_twice_its_attempt_counter(self):
        def activation(host, epoch, shard="s1", generation=7):
            return lambda ev: ev.activations(host).append({"shard": shard, "generation": generation,
                                                           "attempt": epoch, "time": 200})

        def zero_epoch(ev):
            ev.role("s5", attempts=0)
            activation("h3", 0, "s5", 5)(ev)

        for name, plant, guard in (("a host other than the owner", activation("h4", 6), None),
                                   ("a tenure activated twice", activation("h2", 4), None),
                                   ("the stopped owner activating its old tenure again", activation("h1", 2), None),
                                   ("an odd epoch", activation("h2", 5), None),
                                   ("a zero epoch by the owner at attempts zero", zero_epoch, None),
                                   ("a generation no version holds", activation("h3", 2, "s5", 6), None),
                                   ("two hosts on one tenure", activation("h3", 4), "activation")):
            with self.subTest(plant=name):
                named = self.assert_disproven(planted(plant), {"one-owner-per-tenure"})["rules"]["one-owner-per-tenure"]
                self.assertEqual(named["guardrail"], GUARD[guard] if guard else None)
        self.assertEqual(self.record(planted(activation("h4", 6)))[1]["rules"]["one-owner-per-tenure"]["detail"], [
            "h4 activates s1 at generation 7 epoch 6, but no version names it owner at attempts 3"])

    def test_the_pre_stop_half_of_the_reach_reads_the_roles_and_the_package_alone(self):
        ev = Evidence()
        self.assertEqual(gj.roles_reach(ev.roles, ev.package), [])
        ev.role("s4", standby="h3")
        ev.roles["standbys"]["h3"]["host_report"] = "unhealthy"
        self.assertEqual(len(gj.roles_reach(ev.roles, ev.package)), 2)


def at(shard, *versions, before=None):
    """Insert `versions` of `shard`, each a change of the version committed before it, ahead of the version at time
    `before` (at the end when None)."""
    def plant(ev):
        rows = ev.records(shard)
        i = len(rows) if before is None else next(i for i, v in enumerate(rows) if v["time"] == before)
        rows[i:i] = [{**rows[max(i - 1, 0)], **v} for v in versions]
    return plant


def unenrolled(ev):
    ev.version("s1", 150, standby=None)


class Edges(Judging):
    """The edges of each rule's window and reference, under the blocked catalog copy: each plant moves one
    observation to a boundary or one reference version, and its twin shows the other side."""

    assert_refused = Refusals.assert_refused

    def test_a_late_read_reads_from_the_last_version_before_the_stop_or_the_first_after_it(self):
        def late(*versions, **pinned):
            def plant(ev):
                ev.roles["time"] = 120
                del ev.records("s5")[0]
                ev.records("s5")[:0] = [{"owner": "h4", "standby": "h3", "generation": 5, "volume": "vol-s5", **v}
                                        for v in versions]
                ev.roles["shards"]["s5"] = {k: ev.records("s5")[-1][k] for k in gj.VERSION}
                ev.roles["shards"]["s5"].update(pinned)
            return plant

        # When the shard's history starts after the stop, its first version establishes the reference.
        one = late({"time": 113, "attempts": 2}, {"time": 115, "owner": "h3", "standby": "h4", "attempts": 3})
        self.assert_pair(planted(one), "FAILED_TO_INJECT", "INCONCLUSIVE")
        two = late({"time": 113, "attempts": 2}, {"time": 115, "owner": "h3", "standby": "h4", "attempts": 3},
                   {"time": 118, "attempts": 4})
        self.assert_disproven(planted(two), {"changes-hands-once"}, "HALTED")
        # The judge compares the version in effect at the late read with the last version before the stop, and reads
        # a version committed at the stop itself.
        self.assert_disproven(planted(late_read({"time": 112, "generation": 6}, generation=6)),
                              {"no-generation-change"}, "HALTED")
        moved_before = late_read({"time": 108, "owner": "h4", "standby": "h3", "attempts": 2},
                                 {"time": 115, "owner": "h4", "standby": "h3", "attempts": 2}, owner="h4",
                                 standby="h3", attempts=2)
        record = self.assert_pair(planted(moved_before), "FAILED_TO_INJECT", "INCONCLUSIVE")
        self.assertIsNone(record["rules"]["others-keep-owner"]["guardrail"])
        self.assert_pair(planted(late_read({"time": 400, "generation": 6})), "FAILED_TO_INJECT", "INCONCLUSIVE")

        def read_at_the_stop(ev):
            late_read({"time": 112, "generation": 6}, generation=6)(ev)
            ev.roles["time"] = 112

        self.assert_disproven(planted(read_at_the_stop), {"no-generation-change"}, "HALTED")
        # With the roles read at 120, `one-owner-per-tenure` counts h4's activation at the stop (112).
        def stray(ev):
            ev.roles["time"] = 112
            ev.activations("h4").append({"shard": "s1", "generation": 7, "attempt": 8, "time": 112})

        self.assert_disproven(planted(stray), {"one-owner-per-tenure"}, "HALTED")
        record = self.assert_pair(planted(late_read({"time": 115, "owner": "h4", "attempts": 2}, owner="h4",
                                                    attempts=2)), "FAILED_TO_INJECT", "INCONCLUSIVE")
        self.assertEqual(record["rules"]["others-keep-owner"]["guardrail"], GUARD["roleless"])
        gained = late_read({"time": 115, "owner": "h1", "standby": "h4"}, owner="h1", standby="h4")
        self.assert_disproven(planted(gained), {"one-owner-per-tenure"}, "HALTED")
        self.assert_pair(planted(late_read({"time": 115, "owner": "h1", "standby": "h4", "attempts": 2}, owner="h1",
                                           standby="h4", attempts=2)), "FAILED_TO_INJECT", "INCONCLUSIVE")
        self.assert_pair(planted(lambda ev: ev.roles.update(time=95)), "COMPLETED", "HELD")

    def test_a_late_read_leaves_a_version_within_the_clock_error_of_the_stop_undecided(self):
        # The roles are read at 120 and the stop is the stopped report at 112, so with a clock error of 1 a version
        # of s5 stamped from 111 to 113 may precede the stop, as the reference, or follow it.
        def late(*versions, **pinned):
            return clock_error(1), late_read(*versions, **pinned)

        def word(rule, *plants):
            return self.record(planted(*plants))[1]["rules"][rule]["result"]

        other = {"owner": "h4", "standby": "h3"}
        for time, result in ((110.75, "held"), (111, "unobserved"), (111.5, "unobserved"), (112.5, "unobserved"),
                             (113, "unobserved"), (113.25, "disproven")):
            with self.subTest(generation_changed_at=time):
                record = self.record(planted(*late({"time": time, "generation": 6}, generation=6)))[1]
                self.assertEqual(record["rules"]["no-generation-change"]["result"], result)
                self.assertEqual((record["run_status"], record["verdict"]), ("HALTED", "DISPROVEN")
                                 if result == "disproven" else ("FAILED_TO_INJECT", "INCONCLUSIVE"))
        # A change that every placement of the stop shows is kept.
        for name, versions in (("a second generation surely after the stop",
                                ({"time": 112.5, "generation": 6}, {"time": 115, "generation": 7})),
                               ("a generation surely after the stop, past an undecided version that keeps it",
                                ({"time": 112.5, "attempts": 2}, {"time": 113.5, "attempts": 2, "generation": 6}))):
            with self.subTest(kept=name):
                self.assert_disproven(planted(*late(*versions, generation=versions[-1]["generation"],
                                                    attempts=versions[-1].get("attempts", 1))),
                                      {"no-generation-change"}, "HALTED")
        # h3's shard goes to h4 and then to h2: two changes after the stop only when the first follows it.
        twice = ({**other, "attempts": 2}, {"owner": "h2", "standby": "h3", "attempts": 3})
        undecided = late({"time": 112.5, **twice[0]}, {"time": 115, **twice[1]}, **twice[1])
        self.assertEqual(word("changes-hands-once", *undecided), "unobserved")
        self.assertEqual(self.record(planted(*undecided))[1]["rules"]["others-keep-owner"]["guardrail"],
                         GUARD["roleless"])
        self.assert_disproven(planted(*late({"time": 113.5, **twice[0]}, {"time": 115, **twice[1]}, **twice[1])),
                              {"changes-hands-once"}, "HALTED")
        # h4 owns the tenure (generation 5, attempts 1) that h3 held: a conflict when that version follows the stop.
        self.assertEqual(word("one-owner-per-tenure", *late({"time": 112.5, **other}, **other)), "unobserved")
        self.assert_disproven(planted(*late({"time": 113.5, **other}, **other)), {"one-owner-per-tenure"}, "HALTED")
        # Where the stop may follow a version naming the target owner, s5 may be the target's own: the guardrail of
        # a shard with no role on the target is not met, and the shard needs a witness key only when every version
        # the stop may follow names the target.
        gained = ({"time": 111.5, "owner": "h1", "attempts": 2}, {"time": 112.5, **other, "attempts": 3},
                  {"time": 115, "owner": "h2", "standby": "h3", "attempts": 4})
        record = self.assert_pair(planted(*late(*gained, owner="h2", standby="h3", attempts=4)), "FAILED_TO_INJECT",
                                  "INCONCLUSIVE")
        self.assertIsNone(record["rules"]["others-keep-owner"]["guardrail"])
        self.assert_refused(planted(*late({"time": 100, "owner": "h1"}, {"time": 112.5, "owner": "h1", "attempts": 2},
                                          owner="h1", attempts=2)), "owned shards ['s5'] have no witness key")
        for name, versions in (("the target owns s5 surely before the stop, and h4 within the clock error of it",
                                ({"time": 100, "owner": "h1"}, {"time": 112.5, **other, "attempts": 2})),
                               ("h3 owns s5 surely before the stop, and the target within the clock error of it",
                                ({"time": 112.5, "owner": "h1", "attempts": 2},))):
            with self.subTest(no_witness_key_needed=name):
                pinned = {k: versions[-1].get(k, Evidence().records("s5")[0][k]) for k in ("owner", "standby",
                                                                                          "attempts")}
                self.assert_pair(planted(*late(*versions, **pinned)), "FAILED_TO_INJECT", "INCONCLUSIVE")

    def test_a_late_reads_result_is_that_of_every_place_of_the_stop_among_the_undecided_versions(self):
        # s5 holds its version at 50, two versions within the clock error of the stop and one or two after it. Each
        # rule that reads a history is disproven when the judge with no clock error disproves it wherever the stop
        # falls among the two, held when it holds it at each place, and unobserved otherwise; the guardrail of
        # others-keep-owner is named when each place names it.
        other = {"owner": "h4", "standby": "h3"}
        near = [{}, other, {"generation": 6}, {"standby": "h1"}, {"owner": "h1", "attempts": 2}]
        tails = [[{}], [other], [{"generation": 6}], [{**other, "attempts": 2}, {"owner": "h2", "attempts": 3}]]
        ev = planted(lambda ev: ev.roles.update(time=120))
        ev.package["witness"].append({"key": "img/k5", "shard": "s5", "sha256": hashlib.sha256(b"k5").hexdigest()})
        loaded = gj.load_evidence(ev.bytes())
        loaded["origin.jsonl"] = []
        first, rules = loaded["records/s5.jsonl"][0], ("no-generation-change", "one-owner-per-tenure",
                                                       "changes-hands-once")

        def judged_at(error, times, versions):
            loaded["package"]["clock_error_seconds"] = error
            rows = [first] + [{**first, **v, "time": times[i]} for i, v in enumerate(versions)]
            loaded["records/s5.jsonl"] = rows
            loaded["injection/roles.json"]["shards"]["s5"] = {k: rows[-1][k] for k in gj.VERSION}
            record = gj.judge(loaded, self.catalog, FIS, rd)["rules"]
            return [record[r]["result"] for r in rules] + [record["others-keep-owner"]["guardrail"]]

        # The stop, the stopped report at 112, after both near versions, between them, and before both.
        places = ((111.5, 111.75, 115, 118), (111.5, 112.5, 115, 118), (112.25, 112.5, 115, 118))
        seen = []
        for versions in ([a, b, *tail] for a in near for b in near for tail in tails):
            each = [judged_at(0, times, versions) for times in places]
            expected = [each[0][i] if len({e[i] for e in each}) == 1 else "unobserved" for i in range(3)]
            expected.append(each[0][3] if len({e[3] for e in each}) == 1 else None)
            self.assertEqual(judged_at(1, places[1], versions), expected, versions)
            seen.append(expected)
        for i in range(3):
            self.assertEqual({s[i] for s in seen}, {"held", "disproven", "unobserved"}, rules[i])
        self.assertEqual({s[3] for s in seen}, {None, GUARD["roleless"]})

    def test_one_owner_per_tenure_counts_a_conflict_with_an_observation_after_the_reference(self):
        def activation(host, epoch, time):
            return lambda ev: ev.activations(host).append({"shard": "s1", "generation": 7, "attempt": epoch,
                                                           "time": time})

        for name, plant in (("record owners before the read", two_record_owners_before_the_read),
                            ("an activation at the roles read's time", activation("h4", 2, 105)),
                            ("an activation at the run window's end", activation("h4", 4, 400)),
                            ("a version at the run window's end", at("s1", {"time": 400, "owner": "h3"}))):
            with self.subTest(held=name):
                self.assert_pair(planted(plant), "COMPLETED", "HELD")
        self.assert_disproven(planted(activation("h4", 4, 399)), {"one-owner-per-tenure"})

    def test_the_takeover_write_is_found_by_commit_order_and_by_owner(self):
        self.assert_disproven(planted(at("s1", {"time": 125, "standby": "h4"}, before=125), unenrolled),
                              {"standby-again"})
        self.assert_pair(planted(at("s1", {"time": 125, "volume": "vol-x"}, before=125)), "COMPLETED", "HELD")
        self.assert_pair(planted(unenrolled, at("s1", {"time": 125, "standby": "h4"}, before=150)), "COMPLETED",
                         "HELD")
        kept = at("s1", {"time": 115}, before=125)
        self.assert_disproven(planted(kept, witness_rows("img/k1", ("h2", 120, "hit"))), {"witness-first-hit"})
        self.assert_pair(planted(kept, witness_rows("img/k1", ("h2", 125, "hit"))), "COMPLETED", "HELD")
        # Two versions at the roles read's time, the first naming another owner: the takeover write is the version
        # at 125, after the read, so a first hit at 113 precedes it.
        at_the_read = at("s1", {"time": 105, "owner": "h2", "standby": "h4", "attempts": 5}, {"time": 105}, before=125)
        self.assert_disproven(planted(at_the_read, witness_rows("img/k1", ("h2", 113, "hit"))), {"witness-first-hit"})
        # The stopped owner commits the record again after its successor's takeover.
        self.assert_disproven(planted(at("s1", {"time": 300, "owner": "h1", "standby": "h2"})),
                              {"takeover", "one-owner-per-tenure", "changes-hands-once"})

    def test_origin_load_joins_the_stops_cut_interval_to_the_next_and_reads_no_stop_from_another_instance(self):
        def stopped_at(t):
            return lambda ev: ev["injection/stopped.json"].update(time=t)

        self.assert_pair(planted(stopped_at(129.9), lambda ev: ev["origin.jsonl"].append(
            {"time": 129.95, "key": "img/edge"})), "COMPLETED", "HELD")
        self.assert_disproven(planted(stopped_at(129.9), flood(129.9, 200)), {"origin-load"})

        def one_interval(ev):
            ev.package["interval"] = 300
            flood(190, 400)(ev)

        spans = (((flood(112, 432),), ("[112, 160) holds 195 origin requests in 48 s",
                                       "[160, 190) holds 122 origin requests in 30 s",
                                       "[190, 220) holds 121 origin requests in 30 s")),
                 ((stopped_at(130), flood(130, 120)), ("[130, 160) holds 122 origin requests in 30 s",)),
                 ((stopped_at(345), flood(345, 220)), ("[345, 400) holds 223 origin requests in 55 s",)),
                 ((one_interval,), ("[112, 400) holds 415 origin requests in 288 s",)))
        for plants, graded in spans:
            with self.subTest(graded=graded):
                record = self.assert_disproven(planted(*plants), {"origin-load"})
                self.assertEqual(record["rules"]["origin-load"]["detail"],
                                 [f"{span} against the baseline's 11 in 100 s" for span in graded])

        def foreign(ev):
            for mark in (ev["injection/stop.json"], ev["injection/stopped.json"],
                         ev["injection/stopped.json"]["request"], ev["injection/restoration.json"]):
                mark["instance"] = "i-h2"

        def unstopped(ev):
            del ev["injection/stop.json"], ev["injection/stopped.json"]

        for name, plant in (("another instance", foreign), ("no stop", unstopped)):
            with self.subTest(stop=name):
                named = self.assert_pair(planted(plant, flood(100, 40)), "FAILED_TO_INJECT", "INCONCLUSIVE")[
                    "rules"]["origin-load"]
                self.assertEqual((named["guardrail"], named["past_stop_condition"]), (GUARD["origin"], True))
        self.assert_pair(planted(foreign), "FAILED_TO_INJECT", "INCONCLUSIVE")
        self.assert_disproven(planted(foreign, receipt(200)), {"no-replacement-receipt"}, "HALTED")

    def test_each_rule_reads_its_window_from_its_first_instant_to_its_last_interval(self):
        def listed(time, *callers):
            def plant(ev):
                ev["provider.jsonl"] += [{"event": "CreateVolume", "principal": c, "time": time} for c in callers]
                ev["provider.jsonl"].append({"event": "volume", "volume": "vol-x", "time": time})
            return plant

        def at_the_end(ev):
            ev["origin.jsonl"] += [{"time": 400, "key": f"img/end-{i}"} for i in range(80)]

        def one_generation_for_two_shards(ev):
            ev.role("s5", generation=3)
            next(a for a in ev.activations("h3") if a["shard"] == "s5")["generation"] = 3

        def taken_over_at_the_stop_request(ev):
            ev.version("s1", 125, time=110)
            next(a for a in ev.activations("h2") if a["shard"] == "s1")["time"] = 110

        never_hit = witness_rows("img/k3", ("h2", 142, "miss"))

        def at_the_limits(ev):
            ev.package["note"] = "synthetic, na\u00efve"
            ev.role("s5", generation=1, attempts=gj.ATTEMPTS_MAX)
            next(a for a in ev.activations("h3") if a["shard"] == "s5").update(generation=1,
                                                                              attempt=2 * gj.ATTEMPTS_MAX)

        def version_at_the_read(ev):
            at("s5", {"time": 105, "owner": "h4", "standby": "h3", "attempts": 2},
               {"time": 105, "owner": "h3", "standby": "h4", "attempts": 3})(ev)
            ev.roles["shards"]["s5"]["attempts"] = 3

        def stop_at_the_run_windows_start(ev):
            ev.roles["time"] = 95
            ev["injection/stop.json"]["time"] = ev["injection/stopped.json"]["request"]["time"] = 100

        def read_at_the_baselines_start(ev):
            ev.package["baseline"]["start"] = ev.roles["time"] = 70

        def blocked_after_the_takeover_write(ev):
            del ev.records("s1")[2]
            ev["blockers.jsonl"].append({"shard": "s1", "time": 200, "name": "no host has room"})

        def later_baseline(ev):
            ev.package["baseline"]["start"] = 50
            flood(190, 32, "edge")(ev)

        held = [("a name beyond ASCII and a generation, attempts and epoch at the layout's limits", at_the_limits),
                ("two versions committed at the roles read's time", version_at_the_read),
                ("a stop request at the run window's start", stop_at_the_run_windows_start),
                ("a roles read at the baseline window's start", read_at_the_baselines_start),
                ("a takeover write with no later version and a blocker", blocked_after_the_takeover_write),
                ("a baseline window that ends at the stop request", lambda ev: ev.package["baseline"].update(end=110)),
                ("a stopped report read at the stop request's time",
                 lambda ev: ev["injection/stopped.json"].update(time=110)),
                ("the owner's activation at epoch two after the reference",
                 lambda ev: next(a for a in ev.activations("h2") if a["shard"] == "s4").update(time=181)),
                ("an excess equal to the bound over a baseline window that starts at 50", later_baseline)]
        left_and_returned = at("s5", {"time": 200, "owner": "h4", "standby": "h3", "attempts": 2},
                               {"time": 385, "owner": "h3", "standby": "h4", "attempts": 3})
        cases = [("a volume listed at the run window's start", listed(100), {"no-volume-created"}),
                 ("a volume listed in the last interval beside an operator's call", listed(399, "operator"),
                  {"no-volume-created"}),
                 ("a receipt at the run window's start", receipt(100), {"no-replacement-receipt"}),
                 ("a receipt of a shard with no role on the target", receipt(200, shard="s5"),
                  {"no-replacement-receipt"}),
                 ("a first hit in the last interval", witness_rows("img/k3", ("h2", 142, "miss"), ("h2", 399, "hit")),
                  set()),
                 ("origin requests at the run window's end", at_the_end, set()),
                 ("an origin request at the run window's end for a key never hit",
                  lambda ev: (never_hit(ev), ev["origin.jsonl"].append({"time": 400, "key": "img/k3"})),
                  {"witness-first-hit"}),
                 ("another host owning an owned shard in the last interval", at("s1", {"time": 385, "owner": "h3"}),
                  {"takeover", "one-owner-per-tenure", "changes-hands-once"}),
                 ("a shard with no role that leaves and returns in the last interval", left_and_returned,
                  {"others-keep-owner", "changes-hands-once"}),
                 ("a takeover write at another generation", lambda ev: ev.version("s1", 125, generation=8),
                  {"takeover", "no-generation-change"}),
                 ("a lower generation", at("s5", {"time": 200, "generation": 4}), {"no-generation-change"}),
                 ("two shards at one generation and attempt counter", one_generation_for_two_shards, set()),
                 ("a takeover write at the stop request's time", taken_over_at_the_stop_request, set()),
                 *((name, plant, set()) for name, plant in held)]
        for name, plant, rules in cases:
            with self.subTest(case=name):
                if rules:
                    record = self.assert_disproven(planted(plant), rules)
                else:
                    record = self.assert_pair(planted(plant), "COMPLETED", "HELD")
                self.assertTrue(record["reach"]["met"])
                if rules == {"no-volume-created"}:
                    self.assertIsNone(record["rules"]["no-volume-created"]["guardrail"])

    def test_a_witness_keys_origin_requests_count_from_the_stop_to_its_first_hit(self):
        for t, disproven in ((112, True), (139.5, True), (140, False), (140.5, False), (111.5, False)):
            with self.subTest(origin=t):
                plant = planted(lambda ev, t=t: ev["origin.jsonl"].append({"time": t, "key": "img/k1"}))
                plant["origin.jsonl"].sort(key=lambda r: r["time"])
                if disproven:
                    self.assert_disproven(plant, {"no-origin-before-hit"})
                else:
                    self.assert_pair(plant, "COMPLETED", "HELD")

    def test_a_contradiction_outranks_an_unknown_in_the_drain_and_the_origin_rules(self):
        def ends_at_240(ev):
            ev.package.update(interval=10)
            ev.package["run"]["end"] = 240
            unenrolled(ev)

        def s4_unenrolled(ev):
            ev["records/s4.jsonl"] = ev.records("s4")[:1]

        named = self.assert_disproven(planted(ends_at_240, s4_unenrolled), {"standby-again"})["rules"]["standby-again"]
        self.assertEqual(named["guardrail"], GUARD["drain"])
        record = self.assert_pair(planted(ends_at_240), "COMPLETED", "INCONCLUSIVE")
        self.assertEqual(self.results(record, "unobserved"), {"standby-again"})

        def drain_ends_with_the_window(ev):
            ev.package.update(interval=5)
            ev.package["run"]["end"] = 125 + self.bound("re-enrollment-drain")
            unenrolled(ev)

        record = self.assert_pair(planted(drain_ends_with_the_window), "COMPLETED", "INCONCLUSIVE")
        self.assertEqual(self.results(record, "unobserved"), {"standby-again"})

        def never(ev):
            ev["witness.jsonl"] = [r for r in ev["witness.jsonl"] if r["key"] != "img/k3"]

        record = self.assert_disproven(planted(never, origin_before_hit), {"no-origin-before-hit"})
        self.assertEqual(record["rules"]["witness-first-hit"]["result"], "unobserved")

    def test_a_catalog_that_sets_one_budget_bounds_that_rule_alone(self):
        base = [(i * 0.8, f"img/base-{i}") for i in range(120)]
        plants = (origin_rows(*base, *((190 + i * 0.25, f"img/run-{i}") for i in range(80))),
                  lambda ev: ev.version("s2", 160, time=240))
        for budget, value, disproven in (("origin-load", 2, set()),
                                         ("re-enrollment-drain", 100, {"origin-load", "standby-again"})):
            with self.subTest(set=budget):
                catalog = blocked_catalog()
                catalog["budgets"][budget]["value"] = value
                code, record, refusal = judged(planted(*plants), catalog)
                if record is None:
                    self.fail(f"the judge refused: {refusal}")
                self.assertEqual(self.results(record, "disproven"), disproven)
                other = next(b for b in SET_BUDGETS if b != budget)
                self.assertEqual(record["budgets"], {budget: {"value": value, "source": "catalog"}, other: {
                    "value": Evidence().package["working_budgets"][other], "source": "package"}})

    def test_a_catalog_is_read_as_readiness_reads_it_and_a_digest_input_it_lacks_is_exit_2(self):
        text = gj.read_bytes(gj.CATALOG, "catalog").decode()
        start = text.index('"planned-handoff-dark-time"')
        at_value = text.index('"value": null', start)
        raw = text[:at_value] + '"value": 0.10000000000000001' + text[at_value + len('"value": null'):]
        catalog = rd.parse(raw.encode(), "catalog")
        for budget in SET_BUDGETS:
            catalog["budgets"][budget]["value"] = None
        code, record, refusal = judged(Evidence(), catalog)
        if record is None:
            self.fail(f"the judge refused: {refusal}")
        report, _ = rd.check_gamedays(FAILOVER, {"packages": {e["id"]: e for e in catalog["entries"]},
                                                 "gamedays": catalog, "fis": FIS})
        self.assertEqual((code, record["catalog_sha256"]), (0, report["GD-2"]["digest"]))
        del next(e for e in catalog["entries"] if e["id"] == "GD-2")["injection"]
        self.assert_refused(Evidence(), "lack a field the package digest reads", catalog)

    def test_the_reader_and_the_writer_refuse_paths_the_kernel_resolves_otherwise(self):
        for literal in ("1e-999999999999999999999", "0e999999999999999999999"):
            with self.subTest(literal=literal):
                files = Evidence().bytes()
                files["origin.jsonl"] += f'{{"time": {literal}, "key": "k"}}\n'.encode()
                with self.assertRaisesRegex(gj.Refusal, "origin.jsonl line"):
                    gj.load_evidence(files)
        with tempfile.TemporaryDirectory(prefix="gameday-judge-") as top:
            root, out = Path(top, "evidence"), Path(top, "out")
            Evidence().write(root)
            out.mkdir()
            (out / "file").write_bytes(b"")
            Path(top, "link").symlink_to(root)
            with self.assertRaisesRegex(gj.Refusal, "no evidence directory is named"):
                gj.read_evidence("")
            for spelling in ("", *(str(Path(top, "link")) + tail for tail in ("/.", "/./", "//."))):
                with self.subTest(root=spelling), self.assertRaises(gj.Refusal):
                    gj.read_evidence(spelling)
            for record in ("missing/../record.json", "file/../record.json"):
                with self.subTest(record=record), self.assertRaisesRegex(gj.Refusal, "cannot be opened"):
                    gj.run(str(root), str(out / record), self.catalog, FIS, rd)
            self.assertEqual(names(out), ["file"])
            (root / "witness.jsonl").unlink()
            read, real = [], gj.read_bytes

            def recorded(path, what, dir_fd=None):
                read.append(what)
                return real(path, what, dir_fd)

            with mock.patch.object(gj, "read_bytes", side_effect=recorded), \
                    self.assertRaisesRegex(gj.Refusal, "witness.jsonl is missing"):
                gj.read_evidence(str(root))
            self.assertEqual(read, ["package.json"])

    def test_a_late_roles_read_keeps_the_changes_committed_after_the_stop(self):
        generation = late_read({"time": 115, "generation": 6}, {"time": 118})
        owners = late_read({"time": 115, "owner": "h4", "attempts": 2}, {"time": 118, "attempts": 3}, attempts=3)
        for name, plant, rule, guard in (("a generation change", generation, "no-generation-change", "generation"),
                                         ("two owner changes", owners, "changes-hands-once", "twice")):
            with self.subTest(late=name):
                record = self.assert_disproven(planted(plant), {rule}, "HALTED")
                self.assertIn("the roles were read at or after the stop", record["reach"]["detail"])
                self.assertEqual(record["rules"][rule]["guardrail"], GUARD[guard])

    def test_a_reach_whose_roles_precede_the_windows_or_name_the_target_as_a_standby_fails_to_inject(self):
        def before_the_windows(ev):
            ev.package["baseline"]["start"] = 70
            ev.roles["time"] = 60

        def alias(ev):
            ev.roles["standbys"]["h2"]["instance"] = ev.package["target"]["instance"]

        for name, plant, words in (("a read before the windows", before_the_windows, "leave part of the span"),
                                   ("a standby reporting the target's instance", alias, "reports the target's")):
            with self.subTest(unmet=name):
                record = self.assert_pair(planted(plant), "FAILED_TO_INJECT", "INCONCLUSIVE")
                self.assertTrue(any(words in d for d in record["reach"]["detail"]), record["reach"]["detail"])

    def test_every_pinned_witness_key_is_judged(self):
        self.assert_pair(planted(second_key), "COMPLETED", "HELD")

        def other_digest(ev):
            next(r for r in ev["witness.jsonl"] if r["key"] == "img/k1b")["sha256"] = hashlib.sha256(b"x").hexdigest()

        def origin_between(ev):
            ev["origin.jsonl"] = sorted(ev["origin.jsonl"] + [{"time": 143, "key": "img/k1b"}],
                                        key=lambda r: r["time"])

        self.assert_disproven(planted(second_key, other_digest), {"witness-first-hit"})
        self.assert_disproven(planted(second_key, origin_between), {"no-origin-before-hit"})

    def test_a_failed_close_of_the_records_directory_leaves_the_outcome(self):
        real_check, real_close, opened = gj.check_target, os.close, []

        def check(evidence, record):
            opened.append(real_check(evidence, record)[0])
            return opened[-1], os.path.basename(record)

        def close(fd):
            real_close(fd)
            if opened and fd == opened[-1]:
                raise OSError(5, "Input/output error")

        for syncs, outcome in (((), 0), ((None, OSError(5, "EIO"), OSError(5, "EIO")), "may stand")):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory(prefix="gameday-judge-") as top:
                record = os.path.join(top, "record.json")
                with contextlib.ExitStack() as stack:
                    stack.enter_context(mock.patch.object(gj, "check_target", side_effect=check))
                    stack.enter_context(mock.patch.object(gj.os, "close", side_effect=close))
                    if syncs:
                        stack.enter_context(mock.patch.object(gj.os, "fsync", side_effect=list(syncs)))
                    if outcome == 0:
                        self.assertEqual(gj.run(str(HELD), record, self.catalog, FIS, rd), 0)
                    else:
                        with self.assertRaisesRegex(gj.Refusal, str(outcome)) as caught:
                            gj.run(str(HELD), record, self.catalog, FIS, rd)
                        self.assertTrue(caught.exception.written)


def restored(time):
    """The restoration mark at `time`."""
    return lambda ev: ev["injection/restoration.json"].update(time=time)


def clock_error(seconds):
    return lambda ev: ev.package.update(clock_error_seconds=seconds)


def origin_request(time, key="img/k2"):
    def plant(ev):
        ev["origin.jsonl"].append({"time": time, "key": key})
        ev["origin.jsonl"].sort(key=lambda r: r["time"])
    return plant


def holds(ev, facts):
    return gj.found_or_held([], "stands in for the rule")


class Restoration(Judging):
    """A restoration inside the run window ends observation at its time: no row at or after it is read, a rule whose
    window that time leaves open reads unobserved unless a row before it contradicts the rule, a contradiction before
    it is kept, and a rule whose window closed before it is judged. At the run window's end it changes nothing."""

    # The rules whose window can close before the run window's end; every other rule reads that window to its end.
    CLOSING = {"standby-again", "witness-first-hit", "no-origin-before-hit"}

    def assert_cut(self, record, at, held):
        """Every rule but `held` reads unobserved, and each that reads the run window to its end names `at`."""
        self.assertEqual(self.results(record, "held"), held)
        self.assertEqual(self.results(record, "unobserved"), set(gj.RULES) - held)
        for rule in set(gj.RULES) - self.CLOSING:
            self.assertEqual(record["rules"][rule]["detail"], [f"observation ends on the restoration at {at}"])
        self.assertEqual(record["result"], f"held on {len(held)} rules; unobserved: "
                         + ", ".join(r for r in gj.RULES if r not in held))

    def test_a_restoration_before_the_drains_end_leaves_the_drain_unobserved(self):
        record = self.assert_pair(planted(restored(145)), "COMPLETED", "INCONCLUSIVE")
        # Every witness key is first hit by 142, so both witness rules are complete and judged.
        self.assert_cut(record, 145, {"witness-first-hit", "no-origin-before-hit"})
        drain = record["rules"]["standby-again"]["detail"]
        self.assertEqual([d.split(" ")[0] for d in drain], ["s1", "s2", "s3", "s4"])
        self.assertTrue(all(d.endswith("observation ending at 145") for d in drain), drain)
        # s4's enrollment at 180 closes the last drain.
        for at, held in ((180, set()), (181, {"standby-again"})):
            with self.subTest(at=at):
                record = self.assert_pair(planted(restored(at)), "COMPLETED", "INCONCLUSIVE")
                self.assert_cut(record, at, {"witness-first-hit", "no-origin-before-hit"} | held)
        record = self.record(planted(restored(180)))[1]
        self.assertEqual([d.split(" ")[0] for d in record["rules"]["standby-again"]["detail"]], ["s4"])

    def test_a_contradiction_before_the_restoration_is_kept_and_one_at_it_is_not_read(self):
        drain_end = 125 + self.bound("re-enrollment-drain")
        # (rule, a restoration after its first control's contradiction, a restoration at the contradiction's time)
        cases = [("takeover", 126, 125), ("others-keep-owner", 201, 200), ("no-volume-created", 201, 200),
                 ("no-generation-change", 181, 180), ("one-owner-per-tenure", 127, 126),
                 ("standby-again", drain_end + 1, drain_end), ("origin-load", 215, 190),
                 ("witness-first-hit", 143, 142), ("no-origin-before-hit", 121, 120),
                 ("no-replacement-receipt", 201, 200), ("changes-hands-once", 151, 150)]
        self.assertEqual([rule for rule, _, _ in cases], list(gj.RULES))
        for rule, after, at in cases:
            _, plant, guard = CONTROLS[rule][0]
            with self.subTest(rule=rule):
                named = self.assert_disproven(planted(plant, restored(after)), {rule})["rules"][rule]
                self.assertEqual(named["guardrail"], GUARD[guard] if guard else None)
                self.assertEqual(self.record(planted(plant, restored(at)))[1]["rules"][rule]["result"], "unobserved")
                # The verdict DISPROVEN depends on this rule's contradiction.
                with mock.patch.dict(gj.RULES, {rule: gj.RULES[rule]._replace(evaluate=holds)}):
                    self.assertNotEqual(self.record(planted(plant, restored(after)))[1]["verdict"], "DISPROVEN")
        # The record version at 150 names a second owner for the same tenure.
        self.assert_disproven(planted(two_record_owners, restored(151)), {"one-owner-per-tenure"})
        record = self.assert_pair(planted(two_record_owners, restored(150)), "COMPLETED", "INCONCLUSIVE")
        self.assertEqual(record["rules"]["one-owner-per-tenure"]["result"], "unobserved")
        # A drain that ends within the clock error of the end of observation stays open.
        for at, word in ((drain_end + 2, "unobserved"), (drain_end + 2.5, "disproven")):
            with self.subTest(drain_end=drain_end, at=at):
                record = self.record(planted(clock_error(1), no_enrolled_standby, restored(at)))[1]
                self.assertEqual(record["rules"]["standby-again"]["result"], word)

    def test_a_contradiction_only_after_the_restoration_is_not_read(self):
        # img/k2 is first hit at 141, so an origin request for it at 137 contradicts no-origin-before-hit.
        self.assert_disproven(planted(origin_request(137)), {"no-origin-before-hit"})
        record = self.assert_pair(planted(origin_request(137), restored(135)), "COMPLETED", "INCONCLUSIVE")
        self.assert_cut(record, 135, set())
        self.assertIn("img/k2 is requested and never hit before the end of observation",
                      record["rules"]["no-origin-before-hit"]["detail"])
        # Every key is requested before a restoration at 141.5 and img/k3 is first hit after it, at 142.
        record = self.record(planted(witness_rows("img/k3", ("h2", 120, "miss"), ("h2", 142, "hit")),
                                     restored(141.5)))[1]
        for rule in ("witness-first-hit", "no-origin-before-hit"):
            self.assertEqual((record["rules"][rule]["result"], record["rules"][rule]["detail"]), (
                "unobserved", ["img/k3 is requested and never hit before the end of observation"]))
        for error, at, word in ((0, 121, "disproven"), (1, 121, "unobserved"), (1, 122, "unobserved"),
                                (1, 122.5, "disproven")):
            with self.subTest(error=error, at=at):
                record = self.record(planted(clock_error(error), origin_request(120), restored(at)))[1]
                self.assertEqual(record["rules"]["no-origin-before-hit"]["result"], word)

    def test_rows_after_the_end_of_observation_keep_the_planned_intervals_and_the_clock_error(self):
        # The stop's cut interval [112, 130) joins [130, 160) as the run window plans it: 30 requests in 48 s.
        record = self.record(planted(flood(113, 30), restored(125)))[1]
        self.assertEqual(record["rules"]["origin-load"]["result"], "unobserved")
        # s1's takeover write at 125 is cut, so a first hit at 123.5 compares with the end of observation.
        for at, word in ((125.5, "unobserved"), (126, "disproven")):
            with self.subTest(at=at):
                ev = planted(clock_error(1), witness_rows("img/k1", ("h2", 123.5, "hit")), restored(at))
                self.assertEqual(self.record(ev)[1]["rules"]["witness-first-hit"]["result"], word)
        # A collection that covers the window up to the end of observation leaves a closed rule judged.
        ev = planted(restored(145))
        ev["coverage.json"]["witness.jsonl"]["to"] = 145
        self.assertEqual(self.results(self.record(ev)[1], "held"), {"witness-first-hit", "no-origin-before-hit"})
        # A restoration before the run window's start, with no stop, leaves every row read.
        ev = planted(restored(90))
        for rel in ("injection/stop.json", "injection/stopped.json"):
            del ev[rel]
        record = self.assert_pair(ev, "FAILED_TO_INJECT", "INCONCLUSIVE")
        self.assertEqual(self.results(record, "held"), set(SAFETY))

    def test_a_row_stamped_at_the_end_of_observation_is_not_read_whatever_its_digits(self):
        # In decimal arithmetic, 200.3 - 0.1 equals 200.2 exactly, so the receipt stamped 200.2 falls at the end of
        # observation in both cases.
        for plants in ((restored(200.2),), (clock_error(0.1), restored(200.3))):
            with self.subTest(plants=len(plants)):
                record = self.assert_pair(planted(receipt(200.2), *plants), "COMPLETED", "INCONCLUSIVE")
                self.assertEqual(record["rules"]["no-replacement-receipt"]["result"], "unobserved")
                self.assert_disproven(planted(receipt(200.1), *plants), {"no-replacement-receipt"})
                # Coverage includes the end of observation; the receipt's cut there is strict.
                ev = planted(*plants)
                for span in ev["coverage.json"].values():
                    span["to"] = 200.2
                self.assertEqual(self.results(self.record(ev)[1], "held"), self.CLOSING)

    def test_a_restoration_at_the_run_windows_end_changes_nothing(self):
        self.assert_pair(planted(restored(400)), "COMPLETED", "HELD")
        record = self.assert_pair(planted(restored(399)), "COMPLETED", "INCONCLUSIVE")
        self.assert_cut(record, 399, self.CLOSING)

    def test_an_early_halt_and_restoration_read_no_missed_recovery(self):
        def no_recovery(ev):
            for shard in ev.package["shards"]:
                ev[f"records/{shard}.jsonl"] = [v for v in ev.records(shard) if v["time"] < 121]
            for row in ev["activations.jsonl"]:
                row["activations"] = [a for a in row["activations"] if a["time"] < 121]
            ev["witness.jsonl"] = [r for r in ev["witness.jsonl"] if r["time"] < 121]

        halted = (no_recovery, aborted("signal", time=120))
        record = self.assert_pair(planted(*halted), "HALTED", "DISPROVEN")
        self.assertLessEqual({"takeover", "standby-again", "witness-first-hit"}, self.results(record, "disproven"))
        record = self.assert_pair(planted(*halted, restored(121)), "HALTED", "INCONCLUSIVE")
        self.assert_cut(record, 121, set())
        self.assert_disproven(planted(*halted, receipt(115), restored(121)), {"no-replacement-receipt"}, "HALTED")

    def test_an_activation_whose_owning_version_may_follow_the_versions_read_is_undecided(self):
        def result(*plants):
            return self.record(planted(*plants))[1]["rules"]["one-owner-per-tenure"]["result"]

        def activation(host, epoch, time=200):
            return lambda ev: ev.activations(host).append({"shard": "s1", "generation": 7, "attempt": epoch,
                                                           "time": time})

        def spanning(rel, to):
            def plant(ev):
                ev.bytes()
                ev.keep_coverage = True
                ev["coverage.json"][rel]["to"] = to
            return plant

        # h2 activates s1 at 125 under the version stamped 125.6, which a restoration within the clock error of it
        # leaves unread.
        late_version = (clock_error(1), lambda ev: ev.version("s1", 125, time=125.6))
        for at in (126.4, 126.6):
            with self.subTest(restored=at):
                record = self.assert_pair(planted(*late_version, restored(at)), "COMPLETED", "INCONCLUSIVE")
                self.assertEqual(record["rules"]["one-owner-per-tenure"]["result"], "unobserved")
        # `hands_twice` has h2 activate s1 at 125 under the attempts the version at 150 names: held over the run
        # window, and undecided when s1's versions end before that version.
        self.assertEqual(result(hands_twice), "held")
        self.assertEqual(result(hands_twice, restored(150)), "unobserved")
        self.assertEqual(result(hands_twice, collected("records/s1.jsonl", to=140)), "unobserved")
        # No version names h4 owner of s1 at attempts 3. That contradicts the rule where s1's versions are read to the
        # run window's end, whatever other collection ends early, and is undecided where they are not.
        stray = activation("h4", 6)
        for name, plant, word in (("the run window read to its end", lambda ev: None, "disproven"),
                                  ("another shard's versions end early", spanning("records/s5.jsonl", 300),
                                   "disproven"),
                                  ("the activations end early", spanning("activations.jsonl", 300), "disproven"),
                                  ("s1's versions end early", collected("records/s1.jsonl", to=300), "unobserved"),
                                  ("a restoration", restored(300), "unobserved")):
            with self.subTest(no_owning_version_and=name):
                self.assertEqual(result(stray, plant), word)
        # An activation stamped after the end of the activations' collection is undecided.
        self.assertEqual(result(activation("h4", 6, 350), spanning("activations.jsonl", 300)), "unobserved")
        # A tenure activated twice and an odd epoch need no unread version to contradict the rule.
        for name, plant in (("a tenure activated twice", activation("h2", 4)), ("an odd epoch", activation("h2", 5))):
            with self.subTest(before_a_restoration=name):
                self.assertEqual(result(plant, restored(300)), "disproven")


class Loading(Judging):
    """Refusals of the loader, the reader and the writer: numbers, names, counts, marks, budgets, special files, links
    and the record's directory, each exit 2 with no record."""

    def assert_refused(self, ev, words, catalog=None):
        code, record, refusal = judged(ev, self.catalog if catalog is None else catalog)
        self.assertEqual((code, record), (2, None))
        self.assertIn(words, str(refusal))

    def test_numbers_decode_to_their_literal_value_or_are_refused(self):
        def raw(text):
            files = Evidence().bytes()
            files["origin.jsonl"] += text.encode()
            return files

        refused = [('{"time": 140.00000000000001, "key": "k"}\n', "more digits than a double carries"),
                   ('{"time": 9007199254740993.0, "key": "k"}\n', "more digits than a double carries"),
                   ('{"time": 0.10000000000000001, "key": "k"}\n', "more digits than a double carries"),
                   ('{"time": ' + "9" * 400 + ', "key": "k"}\n', "no time of the layout")]
        for text, words in refused:
            with self.subTest(literal=text[:40]):
                with self.assertRaises(gj.Refusal) as caught:
                    gj.load_evidence(raw(text))
                self.assertIn(words, str(caught.exception))
                self.assertIn("origin.jsonl line", str(caught.exception))
        for literal in ("0.1", "100.15", "1.5e2", "9007199254740992.0"):
            with self.subTest(literal=literal):
                self.assertEqual(gj.exact(gj.decode(literal, "a number")), gj.fractions.Fraction(literal))
        self.assertFalse(gj.finite(10 ** 400))
        self.assertTrue(gj.finite(1 << 53))

    def test_the_origin_rule_compares_rates_exactly_whatever_their_size(self):
        def judged_origin(base, run, interval, times):
            ev = {"package": {"baseline": base, "run": run, "interval": interval},
                  "origin.jsonl": [{"time": t, "key": f"k{i}"} for i, t in enumerate(times)]}
            return gj.origin_load(ev, {"bounds": {"origin-load": 1}, "stop": run["start"], "error": 0})

        base, run = {"start": 0, "end": 1e-310}, {"start": 1e-310, "end": 3e-310}
        result, detail, met = judged_origin(base, run, 1e-310, [0.0, 1e-310, 1.5e-310])
        self.assertEqual((result, met), ("disproven", True))
        self.assertNotIn("inf", " ".join(detail))
        self.assertEqual(judged_origin(base, run, 1e-310, [0.0, 1e-310])[0], "held")
        # A whole number of intervals is read from the decimal values, at epoch scale too.
        package = Evidence().package
        package.update(baseline={"start": 1700000000, "end": 1700000100.1}, interval=0.1,
                       run={"start": 1700000100.1, "end": 1700000400.4})
        gj.check_package(package)
        package["run"]["end"] = 1700000400.45
        with self.assertRaisesRegex(gj.Refusal, "a whole number of origin intervals"):
            gj.check_package(package)
        most = Evidence().package
        most["interval"] = 0.0003
        self.assertEqual(300 / gj.exact(most["interval"]), gj.MAX_INTERVALS)
        gj.check_package(most)

    def test_marks_names_counts_and_budgets_off_the_layout_are_refused(self):
        def restore(**changes):
            return lambda ev: ev["injection/restoration.json"].update(changes)

        cases = [(restore(instance="i-h2"), "names another instance"),
                 (restore(state="stopped"), "reads a state other than running"),
                 (restore(time=109), "restoration.json precedes the stop request"),
                 (restore(time=111), "restoration.json precedes the stop request, the stopped report"),
                 (lambda ev: ev.package["baseline"].update(end=400), "the baseline window ends after the stop"),
                 (lambda ev: ev.package["baseline"].update(end=90), "or before it starts"),
                 ((lambda ev: (aborted("deadline", time=395)(ev),
                               ev["injection/restoration.json"].update(time=390))), "or the abort mark"),
                 (lambda ev: ev.package.__setitem__("note", "\ud800 a lone surrogate"), "package.json note is no name"),
                 (lambda ev: ev.package["witness"][0].__setitem__("key", "img/\udfff"), "is no name"),
                 (lambda ev: ev.package["shards"].append("s1"), "repeats a name"),
                 (lambda ev: ev["witness.jsonl"].insert(2, {**ev["witness.jsonl"][1], "host": "h3", "time": 139}),
                  "not in send order"),
                 (lambda ev: ev.role("s5", generation=1 << 32), "generation is no generation of the layout"),
                 (lambda ev: ev.role("s5", generation=0), "generation is no generation of the layout"),
                 (lambda ev: ev.version("s1", 150, attempts=gj.ATTEMPTS_MAX + 1), "no attempts of the layout"),
                 (lambda ev: ev.activations("h2")[0].__setitem__("attempt", 2 * gj.ATTEMPTS_MAX + 1),
                  "no epoch of the layout"),
                 (lambda ev: ev.package["witness"].append({**ev.package["witness"][0], "shard": "s3"}),
                  "repeats a witness key")]
        for plant, words in cases:
            with self.subTest(words=words):
                self.assert_refused(planted(plant), words)
        self.assert_pair(planted(lambda ev: ev.__delitem__("injection/restoration.json")), "COMPLETED", "HELD")
        self.assert_pair(planted(aborted("deadline"), restore(time=390)), "HALTED", "INCONCLUSIVE")
        # Only a stopped report read before the run window's end bounds the restoration's time.
        self.assert_pair(planted(lambda ev: ev["injection/stopped.json"].update(time=400), restore(time=399)),
                         "FAILED_TO_INJECT", "INCONCLUSIVE")
        for observation, rel in gj.OBSERVATION_FILES.items():
            with self.subTest(outside=observation):
                ev = simulation(Evidence())
                ev[rel] = Evidence()[rel]
                self.assert_refused(ev, f"{rel} stands, but the package names its observation outside")
        for budget in SET_BUDGETS:
            for value in (0, -1, True, "missing"):
                with self.subTest(budget=budget, value=value), \
                        tempfile.TemporaryDirectory(prefix="gameday-judge-") as top:
                    catalog = copy.deepcopy(self.catalog)
                    if value == "missing":
                        del catalog["budgets"][budget]["value"]
                    else:
                        catalog["budgets"][budget]["value"] = value
                    with self.assertRaisesRegex(gj.Refusal, f"no budget {budget} with a null or positive value"):
                        gj.run(str(HELD), os.path.join(top, "record.json"), catalog, FIS, rd)
                    self.assertEqual(list(Path(top).iterdir()), [])
        catalog = copy.deepcopy(self.catalog)
        del next(e for e in catalog["entries"] if e["id"] == "GD-2")["hypothesis"][0]["bound"]
        self.assert_refused(Evidence(), "hypothesis clauses or their bounds", catalog)

    def test_the_reader_waits_on_no_fifo_follows_no_link_and_reads_no_file_outside_the_layout(self):
        with tempfile.TemporaryDirectory(prefix="gameday-judge-") as top:
            root = Path(top, "evidence")
            Evidence().write(root)
            (root / "blockers.jsonl").unlink()
            os.mkfifo(root / "blockers.jsonl")

            def hung(signum, frame):
                raise TimeoutError("the reader waited on a FIFO")

            previous = signal.signal(signal.SIGALRM, hung)
            signal.setitimer(signal.ITIMER_REAL, 10)
            try:
                for read, words in ((lambda: gj.read_evidence(str(root)), "blockers.jsonl is a link or a special file"),
                                    (lambda: gj.read_bytes(str(root / "blockers.jsonl"), "the FIFO"),
                                     "the FIFO is no regular file")):
                    with self.subTest(fifo=words), self.assertRaisesRegex(gj.Refusal, words):
                        read()
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, previous)
            link = Path(top, "link")
            link.symlink_to(root)
            for spelling in (str(link), str(link) + "/"):
                with self.subTest(root=spelling), self.assertRaisesRegex(gj.Refusal, "is no directory"):
                    gj.read_evidence(spelling)

        with tempfile.TemporaryDirectory(prefix="gameday-judge-") as top:
            root = Path(top, "evidence")
            Evidence().write(root)
            Path(root, "records/s9.jsonl").write_bytes(b"not read\n")
            read = []
            real = gj.read_bytes

            def recorded(path, what, dir_fd=None):
                read.append(what)
                return real(path, what, dir_fd)

            with mock.patch.object(gj, "read_bytes", side_effect=recorded), \
                    self.assertRaisesRegex(gj.Refusal, "records/s9.jsonl is no file of the layout"):
                gj.read_evidence(str(root))
            self.assertEqual(read, ["package.json"])

        # A records directory replaced by a link after the listing: the judge reads the directory it listed.
        with tempfile.TemporaryDirectory(prefix="gameday-judge-") as top:
            root, other = Path(top, "evidence"), Path(top, "other")
            Evidence().write(root)
            planted(control("takeover")).write(other)
            real = gj.read_bytes

            def swapped(path, what, dir_fd=None):
                if what == "package.json":
                    (root / "records").rename(Path(top, "listed"))
                    (root / "records").symlink_to(other / "records")
                return real(path, what, dir_fd)

            with mock.patch.object(gj, "read_bytes", side_effect=swapped):
                ev = gj.read_evidence(str(root))
            self.assertEqual(ev["records/s1.jsonl"], Evidence().records("s1"))

    def test_a_file_above_the_size_limit_is_refused(self):
        path = HELD / "origin.jsonl"
        size = path.stat().st_size
        with mock.patch.object(gj, "FILE_LIMIT", size):
            self.assertEqual(len(gj.read_bytes(str(path), "the log")), size)
        with mock.patch.object(gj, "FILE_LIMIT", size - 1), \
                self.assertRaisesRegex(gj.Refusal, f"the log holds more than {size - 1} bytes"):
            gj.read_bytes(str(path), "the log")

    def test_the_record_goes_where_the_kernel_resolves_its_path_with_the_umask_mode_and_no_replacement(self):
        with tempfile.TemporaryDirectory(prefix="gameday-judge-") as top:
            root, out = Path(top, "evidence"), Path(top, "out")
            Evidence().write(root)
            out.mkdir()
            (out / "link").symlink_to(root / "injection")
            before = {p: names(p) for p in (root, out)}
            with self.assertRaisesRegex(gj.Refusal, "inside the evidence directory"):
                gj.run(str(root), str(out / "link/../record.json"), self.catalog, FIS, rd)
            self.assertEqual({p: names(p) for p in (root, out)}, before)
            old = os.umask(0o077)
            try:
                self.assertEqual(gj.run(str(root), str(out / "private.json"), self.catalog, FIS, rd), 0)
            finally:
                os.umask(old)
            self.assertEqual((out / "private.json").stat().st_mode & 0o777, 0o600)
            # The file is synced before it is linked, the link replaces no entry and the directory is synced last.
            order, real_fsync, real_link = [], os.fsync, os.link

            def fsync(fd):
                order.append("dir sync" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file sync")
                return real_fsync(fd)

            def link(src, dst, *args, **kwargs):
                order.append("link")
                return real_link(src, dst, *args, **kwargs)

            target = str(out / "ordered.json")
            dirfd = os.open(out, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(gj.os, "fsync", side_effect=fsync), \
                        mock.patch.object(gj.os, "link", side_effect=link):
                    gj.write_record(dirfd, "ordered.json", target, b"first\n")
                self.assertEqual(order, ["file sync", "link", "dir sync"])
                with self.assertRaisesRegex(gj.Refusal, "appeared while the judge wrote it"):
                    gj.write_record(dirfd, "ordered.json", target, b"second\n")
                self.assertEqual(Path(target).read_bytes(), b"first\n")
                with mock.patch.object(gj.os, "fsync", side_effect=OSError(5, "EIO")), \
                        self.assertRaisesRegex(gj.Refusal, "the record cannot be written"):
                    gj.write_record(dirfd, "unsynced.json", str(out / "unsynced.json"), b"x\n")
                with mock.patch.object(gj.os, "link", side_effect=OSError(13, "Permission denied")), \
                        self.assertRaisesRegex(gj.Refusal, "the record cannot be written: Permission denied"):
                    gj.write_record(dirfd, "denied.json", str(out / "denied.json"), b"x\n")
            finally:
                os.close(dirfd)
            self.assertEqual(names(out), ["link", "ordered.json", "private.json"])
            # A directory swapped for a link after the check: the record lands in the directory the check opened.
            elsewhere, real_read = Path(top, "elsewhere"), gj.read_evidence
            elsewhere.mkdir()

            def swap(path):
                out.rename(Path(top, "checked"))
                out.symlink_to(elsewhere)
                return real_read(path)

            with mock.patch.object(gj, "read_evidence", side_effect=swap):
                self.assertEqual(gj.run(str(root), str(out / "swapped.json"), self.catalog, FIS, rd), 0)
            self.assertEqual(names(elsewhere), [])
            self.assertIn("swapped.json", names(Path(top, "checked")))


class CommandLine(unittest.TestCase):
    def test_the_command_writes_once_exits_by_the_verdict_and_matches_an_in_process_run(self):
        with tempfile.TemporaryDirectory(prefix="gameday-judge-") as top:
            record = os.path.join(top, "record.json")
            # An isolated interpreter, with its own random hash seed and stdout closed, matches the in-process run's
            # exit code and record bytes.
            first = subprocess.Popen(("sh", "-c", '"$0" -I -B "$1" --evidence "$2" --record "$3" >&-',
                                      sys.executable, str(ROOT / "scripts/gameday-judge.py"), str(HELD), record),
                                     stderr=subprocess.PIPE, text=True)
            # A refusal whose message cannot be written to a full device still exits 2; it runs beside the first.
            Path(top, "existing.json").write_bytes(b"")
            with Path("/dev/full").open("w") as full:
                refused = subprocess.Popen((sys.executable, "-I", "-B", str(ROOT / "scripts/gameday-judge.py"),
                                            "--evidence", str(HELD), "--record", os.path.join(top, "existing.json")),
                                           stderr=full)
            stderr_text = first.communicate()[1]
            self.assertEqual(first.returncode, gj.run(str(HELD), os.path.join(top, "in-process.json"), CATALOG, FIS,
                                                      rd), stderr_text)
            self.assertEqual(refused.wait(30), 2)
            written = gj.read_bytes(record, "the record")
            self.assertEqual(gj.read_bytes(os.path.join(top, "in-process.json"), "the record"), written)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(gj.main(["--evidence", str(HELD), "--record", record]), 2)
            self.assertIn("no record written", stderr.getvalue())
            self.assertEqual(gj.read_bytes(record, "the record"), written)
            root = os.path.join(top, "evidence")
            planted(control("takeover")).write(root)
            disproven = os.path.join(top, "disproven.json")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(gj.main(["--evidence", root, "--record", disproven]), 1)
            self.assertEqual(stdout.getvalue(), "")
            record = gj.decode(gj.read_bytes(disproven, "the record").decode(), "record")
            self.assertEqual((record["run_status"], record["verdict"]), ("COMPLETED", "DISPROVEN"))
            self.assertEqual(record["rules"]["takeover"]["result"], "disproven")
            unobserved, inconclusive = os.path.join(top, "unobserved"), os.path.join(top, "inconclusive.json")
            planted(lambda ev: ev["activations.jsonl"].pop()).write(unobserved)
            self.assertEqual(gj.main(["--evidence", unobserved, "--record", inconclusive]), 1)
            record = gj.decode(gj.read_bytes(inconclusive, "the record").decode(), "record")
            self.assertEqual((record["run_status"], record["verdict"]), ("COMPLETED", "INCONCLUSIVE"))

    def test_an_unforeseen_failure_exits_2_and_writes_no_record(self):
        with tempfile.TemporaryDirectory(prefix="gameday-judge-") as top:
            record = os.path.join(top, "record.json")
            stderr = io.StringIO()
            with mock.patch.object(gj, "judge", side_effect=RuntimeError("planted")), \
                    contextlib.redirect_stderr(stderr):
                self.assertEqual(gj.main(["--evidence", str(HELD), "--record", record]), 2)
            self.assertIn("RuntimeError: planted; no record written", stderr.getvalue())
            self.assertEqual(list(Path(top).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
