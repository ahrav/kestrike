#!/usr/bin/env python3
"""Exercise readiness.py check over mutated copies of a base record (the committed record with every gate unlifted, the
alarm catalog pin null and the runbook index pin on the test's empty index EMPTY_INDEX) against contexts whose evidence
each case fixes: the acceptance check's open gates, the Quint cases of the END obligation that stay blocked, the
acceptance record's unrun domains, the open items of the hit-gate check, the hit-gate profile's disposition, the
preservation qualification, the platform rows and the optional pinned files. Every context carries the committed
game-day catalog with each package's runbooks emptied, since EMPTY_INDEX holds no entry, so an edit to it can change the
base and game-day cases; a sibling landing the alarm catalog, an index entry or setting a platform row supported changes
none of them, a change to a file whose pin is not null still needs its pin updated, and the live cases and the command
line read the committed record and files. The class cases cover evidence-kind separation, one home per receipt, the
delegated rows and the failure-class map over the live acceptance record's classes, sources, catalog records, packages
and unrun kinds; the item cases cover the item table, floors, waves and authority, the runbook index and the alarm
cross-check; the game-day cases cover the catalog's shape, its budgets, bindings and fault actions, each package's
digest, the links between packages, items and class rows, and the gates the catalog keeps open. The judge cases run
readiness.py judge over Fake owning-judge results the test supplies: the grade rules, aging, the exception register, the
verdict, the gates a lift contradicts and the class cells, each grade row under the tests' ages and under the committed
null ages. The adapter cases run the real owning-judge adapters over files in a temp directory, with a stub hardware
lane where the lane must refuse or credit. One command case runs the script as a process."""

import copy
import functools
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from contextlib import nullcontext, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("readiness", ROOT / "scripts/readiness.py")
assert SPEC is not None and SPEC.loader is not None
rd = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rd)
gate, mf = rd.gate, rd.mf

LIVE = rd.context(gate.lane_module())
GATES = ("end-contract", "store-qualification", "real-path", "suffix-damage", "platform-row", "acceptance",
         "trace-replay", "models", "simulation", "monitors", "runbooks", "gamedays", "hardware-multi-shard",
         "fis-multi-attach", "attach-slots", "deploy-gate", "budgets", "authority", "evidence-age")
HARDWARE = ("platform-row", "real-path", "hardware-multi-shard", "fis-multi-attach")
OWNER_INPUTS = ("budgets", "authority", "evidence-age")
OPTIONAL = ("gamedays_sha256", "runbooks_sha256", "alarms_sha256")
EMPTY_INDEX = b'{"index": "failover-runbooks", "version": 1, "entries": []}'
UNJUDGED = ("models", "simulation", "attach-slots", "deploy-gate")
ALARMS = "crates/kestrike/src/failover/report/alarms.json"
STORE = mf.COLUMNS["store"]
ROW = "aarch64-r8gb-4xlarge-ebs"
ROW_8X = "aarch64-r8gb-8xlarge-ebs"
X86 = "x86_64-nitro-ebs"
PLATFORM = "no aarch64-r8gb-* platform row of machine aarch64 reads supported: true"
OBLIGATION = LIVE["document"]["qualification"]["preservation"]["obligation"]
HIT = "the manifest's hit-gate qualification is open: "
HIT_OPEN = (f"platform row {X86} is unsupported", "workload request-weighted is blocked: no fleet records",
            "the workload manifest declares no offered_rate", "recovery is blocked: no recovery record",
            f"preservation {OBLIGATION} is unqualified: warm takeover stays closed")
CLEAR = {"hit_open": (), "runs": {ROW}, "supported": {ROW}}


def state(acceptance_gates=(STORE, "another acceptance gate"), end_blocked=True, replayed=False, hit_open=HIT_OPEN,
          runs=(), preserved=False, supported=(), machines=None, files=None, root=None):
    """A context over the live acceptance record and manifest whose evidence the test fixes: the acceptance check's
    open gates; the END obligation's cases, one of them blocked or none; trace-replay unrun or not; the open items
    of the hit-gate check; the platform rows on which the hit-gate profile reads runs; the preservation
    qualification; the platform rows that read supported and their machines; the optional pinned files present (only
    the committed runbook index EMPTY_INDEX and the committed game-day catalog by default, `files` applied last), with
    no package naming a runbook that index lacks; and optionally a root its runbook files resolve against."""
    ctx = copy.deepcopy(LIVE)
    ctx["acceptance_gates"] = list(acceptance_gates)
    ctx["end_cases"] = ["preserve-run-faultLocal", "preserve-run-faultRepaired"]
    ctx["quint_blocked"] = {"detect-progress": "AQ-15"}
    if end_blocked:
        ctx["quint_blocked"]["preserve-run-faultLocal"] = "a provider premise no case establishes"
    unrun = ctx["acceptance"]["unrun"]
    unrun.pop("trace-replay", None)
    if not replayed:
        unrun["trace-replay"] = "no trace replays"
    ctx["hit_gate_open"] = list(hit_open)
    document = ctx["document"]
    q = document["qualification"]
    dispositions = document["profiles"][q["profile"]]["platforms"]
    for name in dispositions:
        if name.startswith("aarch64-"):
            dispositions[name] = "runs" if name in runs else "pending"
    q["preservation"]["qualified"] = preserved
    for name, row in document["platforms"].items():
        row["supported"] = name in supported
        row["machine"] = (machines or {}).get(name, row["machine"])
    ctx["files"] = {key: None if key in OPTIONAL and key != "gamedays_sha256" else data
                    for key, data in LIVE["files"].items()}
    ctx["files"]["runbooks_sha256"] = EMPTY_INDEX
    for e in ctx["gamedays"]["entries"]:
        e["runbooks"] = []
    ctx["files"].update(files or {})
    if root is not None:
        ctx["root"] = root
    return ctx


CTX = state()
RECORD = rd.parse(gate.read_file(rd.RECORD, "readiness record"), "readiness record")
BASE = copy.deepcopy(RECORD)
BASE["pins"].update(dict.fromkeys(key for key in OPTIONAL if key != "gamedays_sha256"),
                   runbooks_sha256=hashlib.sha256(EMPTY_INDEX).hexdigest())
for gate_entry in BASE["gates"].values():
    gate_entry["lifted"] = False
CONTRADICTED = [name for name in GATES if name not in UNJUDGED]
CYCLES = "warm-cycle-histories-judge-four-verdicts-and-conserve-at-the-boundary"
FAILURE_CLASS_MAP = {
    "FC1": ["same-host-restart", "controller-reset", "process-kill", "deploy-restart"],
    "FC2": ["host-loss", "host-loss-multi-shard", "isolated-live-owner", "isolated-live-owner-fleet"],
    "FC3": ["observed-deposition"], "FC4": ["unknown-write"], "FC5": ["store-outage"], "FC6": ["az-loss-return"],
    "FC7": ["volume-impairment-hold"], "FC8": ["actual-volume-loss", "isolated-volume-loss", "correlated-volume-loss"],
    "FC9": ["owner-standby-loss"], "FC10": ["successor-death"], "FC11": ["retirement-request"],
    "FC12": ["partition-loss"]}
REQUIREMENT_ROWS = {"planned-handoff": "R5", "rollback-refusal": "R6", "control-plane-outage": "R2",
                    "reconciler-stop": "R2", "census-full": "R8", "attach-slots-exhausted": "R4", "power-loss": "R7",
                    "physical-hot-removal": "R7", "store-restore-reopen": "#120 R12"}


def edited(*edits):
    record = copy.deepcopy(BASE)
    for edit in edits:
        edit(record)
    return record


def drop_class(name):
    """An edit that removes class row `name` and the items that name it."""
    def edit(record):
        record["classes"].pop(name)
        record["items"] = [i for i in record["items"] if i["class"] != name]
    return edit


def source(name, kind):
    """An edit that adds a readiness source `name` of `kind`."""
    def edit(record):
        record["sources"][name] = {"kind": kind, "owner": "#290", "evidence": f"a {kind} receipt"}
    return edit


def cite(cls, kind, *cites):
    """An edit that drops any exclusion of `kind` from class `cls` and makes it cite `cites` under `kind`."""
    def edit(record):
        record["classes"][cls]["excluded"].pop(kind, None)
        record["classes"][cls]["evidence"].setdefault(kind, []).extend(cites)
    return edit


def lift(name):
    return edited(lambda r: r["gates"][name].update(lifted=True))


def item(record, name):
    """Item `name` of `record`."""
    return next(i for i in record["items"] if i["id"] == name)


def sha(data):
    return hashlib.sha256(data).hexdigest()


WAIVED = ["rollback-refusal-retention", "correlated-volume-loss-retention"]
CONTAINMENT = ["host-loss-containment", "same-host-restart-containment", "controller-reset-containment",
               "process-kill-containment", "actual-volume-loss-containment", "isolated-volume-loss-containment",
               "correlated-volume-loss-containment"]
STANDING = ("this check holds no inventory of operator actions, so the coverage of operator procedures (item "
            "operator-procedures) is judged outside it")


class Check(unittest.TestCase):
    def refused(self, record, message, ctx=None):
        with self.assertRaises(rd.Refusal) as caught:
            rd.check(record, ctx or CTX)
        self.assertIn(message, str(caught.exception))

    def admitted(self, name, ctx):
        report = rd.check(lift(name), ctx)
        self.assertNotIn(name, report["gates"], name)
        self.assertNotIn(name, report["open"], name)
        self.assertEqual(report["verdict"], "NOT READY")

    def test_the_base_record_lists_every_gate_open_and_reads_not_ready(self):
        report = rd.check(BASE, CTX)
        self.assertEqual(report["gates"], list(GATES))
        self.assertEqual(report["verdict"], "NOT READY")
        reasons = {"end-contract": ["1 cases of obligation preserve-p4-retention-proposed stay blocked in "
                                    "verification/quint/expected.json"],
                   "store-qualification": [f"acceptance.py check lists the store gate {STORE!r}"],
                   "real-path": [*(f"{HIT}{item}" for item in HIT_OPEN), PLATFORM],
                   "suffix-damage": [f"preservation {OBLIGATION} is unqualified"],
                   "platform-row": [PLATFORM],
                   "acceptance": ["acceptance.py check lists 2 open gates, so no receipt is accepted"],
                   "trace-replay": ["the acceptance record lists trace-replay as an unrun domain"],
                   "monitors": [f"pin alarms_sha256 is null, so the record pins no {ALARMS}",
                                "the alarm catalog is absent, so the alarm cross-check is skipped"],
                   "runbooks": ["the runbook index holds no entry",
                                "the alarm catalog is absent, so no runbook slug is checked", STANDING],
                   "hardware-multi-shard": [PLATFORM, "#255 defers the multi-shard hardware cells"],
                   "fis-multi-attach": [PLATFORM, "#255 defers the two-role fault-injection episode"],
                   "authority": ["authority role launch is null", "authority role risk is null",
                                 *(f"item {name} reads not applicable with no approver: " for name in WAIVED)],
                   "evidence-age": [f"POLICY UNDEFINED: item {i['id']} has a null max_age_days"
                                    for i in RECORD["items"]]}
        self.assertEqual(list(report["open"]), CONTRADICTED)
        for name, prefixes in reasons.items():
            self.assertEqual(len(report["open"][name]), len(prefixes), (name, report["open"][name]))
            for index, prefix in enumerate(prefixes):
                why = report["open"][name][index]
                self.assertTrue(why.startswith(prefix), (name, why))
        self.assertTrue(report["open"]["gamedays"][0].startswith("GD-1 is blocked: a staging environment"))
        self.assertEqual(report["open"]["budgets"][0], "budget planned-handoff-dark-time is null")
        self.assertEqual(report["alarm_cross_check"], "skipped: the alarm catalog is absent")
        self.assertEqual({fc: sorted(rows) for fc, rows in report["failure_classes"].items()},
                         {fc: sorted(rows) for fc, rows in FAILURE_CLASS_MAP.items()})
        self.assertEqual(report["unmapped"], {})
        classes = report["classes"]
        self.assertEqual({name: row["requirement"] for name, row in classes.items() if row["failure_class"] is None},
                         REQUIREMENT_ROWS)
        own = {"failure_class": "FC2", "requirement": None, "delegated": None, "excluded": [],
               "open": [k for k in rd.KINDS if k != "staging"]}
        self.assertEqual(classes["host-loss-multi-shard"], own)
        self.assertEqual(classes["correlated-volume-loss"], {**own, "failure_class": "FC8", "excluded": ["staging"]})
        self.assertEqual(classes["isolated-volume-loss"], {**own, "failure_class": "FC8", "excluded": ["staging"]})
        self.assertEqual(classes["isolated-live-owner-fleet"]["open"], ["simulation", "rehearsal", "review"])
        self.assertEqual(classes["isolated-live-owner"]["open"], [])
        self.assertEqual(classes["power-loss"]["excluded"], list(rd.KINDS))
        self.assertEqual((classes["planned-handoff"]["failure_class"], classes["planned-handoff"]["requirement"]),
                         (None, "R5"))
        self.assertEqual(classes["store-restore-reopen"]["requirement"], "#120 R12")
        self.assertEqual(classes["controller-reset"], {"failure_class": "FC1", "requirement": None,
                                                       "delegated": "acceptance", "open": [],
                                                       "excluded": ["staging", "rehearsal", "review"],
                                                       "unrun": ["model", "store"]})
        self.assertEqual(classes["host-loss"]["unrun"], ["store"])

    def test_the_live_repository_checks_and_reads_not_ready(self):
        self.assertEqual(list(RECORD["gates"]), list(GATES))
        self.assertLessEqual({ROW, X86}, set(LIVE["document"]["platforms"]))
        report = rd.check(RECORD, LIVE)
        self.assertEqual(report["gates"], [name for name in GATES if not RECORD["gates"][name]["lifted"]])
        self.assertEqual(report["verdict"], "NOT READY")
        self.assertTrue(RECORD["pins"]["gamedays_sha256"] and RECORD["pins"]["runbooks_sha256"])
        quint = rd.parse(gate.read_file(ROOT / "verification/quint/expected.json", "Quint manifest"), "Quint manifest")
        catalog = rd.parse(gate.read_file(ROOT / "verification/obligations.json", "catalog"), "catalog")
        row = next(r for r in catalog["records"] if r["id"] == "preserve-p4-retention-proposed")
        cases = [*row["tests"], *(control["test"] for control in row["controls"])]
        self.assertGreater(len(cases), len(row["tests"]))
        self.assertEqual(LIVE["end_cases"], cases)
        self.assertEqual("end-contract" in report["open"], any(case in quint.get("blocked", {}) for case in cases))
        document = LIVE["document"]
        q = document["qualification"]
        real_path = report["open"]["real-path"]
        for row, disposition in document["profiles"][q["profile"]]["platforms"].items():
            self.assertEqual(f"{HIT}platform row {row} is unsupported" in real_path,
                             disposition == "runs" and not document["platforms"][row]["supported"], row)
        self.assertEqual(any(why.startswith(f"{HIT}preservation {OBLIGATION} is unqualified") for why in real_path),
                         not q["preservation"]["qualified"])
        self.assertTrue(any(why.startswith(f"{HIT}recovery is blocked: ") for why in real_path), real_path)

    def test_a_gate_dropped_added_or_reshaped_is_refused(self):
        self.refused(edited(lambda r: r["gates"].pop("runbooks")), "gates are not")
        self.refused(edited(lambda r: r["gates"].update(extra={"owner": "x", "lifts_when": "y", "lifted": False})),
                     "gates are not")
        self.refused(edited(lambda r: r["gates"].update(runbooks=r["gates"].pop("runbooks"))), "in order")
        for edit in (lambda g: g.pop("owner"), lambda g: g.update(lifted="no"), lambda g: g.update(owner=""),
                     lambda g: g.update(lifts_when=""), lambda g: g.update(owner="   "),
                     lambda g: g.update(lifts_when="\n"), lambda g: g.update(extra=1)):
            self.refused(edited(lambda r, edit=edit: edit(r["gates"]["runbooks"])), "gate runbooks is not")

    def test_a_lift_the_repository_evidence_contradicts_is_refused(self):
        for name in CONTRADICTED:
            self.refused(lift(name), f"gate {name} is lifted while")
        self.refused(lift("store-qualification"),
                     f"gate store-qualification is lifted while acceptance.py check lists the store gate {STORE!r}")
        self.refused(lift("acceptance"), "gate acceptance is lifted while acceptance.py check lists 1 open gates",
                     state(acceptance_gates=["another acceptance gate"]))

    def test_a_lift_is_admitted_once_the_evidence_that_contradicted_it_is_gone(self):
        supported = {ROW}
        cases = {"end-contract": state(end_blocked=False), "store-qualification": state(acceptance_gates=["a gate"]),
                 "acceptance": state(acceptance_gates=[]), "trace-replay": state(replayed=True),
                 "suffix-damage": state(preserved=True), "platform-row": state(supported=supported),
                 "real-path": state(**CLEAR)}
        for name, ctx in cases.items():
            self.admitted(name, ctx)

    def test_each_hardware_gate_keeps_its_own_contradiction_on_a_supported_row(self):
        ctx = state(**CLEAR)
        self.refused(lift("hardware-multi-shard"), "#255 defers the multi-shard hardware cells", ctx)
        self.refused(lift("fis-multi-attach"), "#255 defers the two-role fault-injection episode", ctx)
        self.refused(lift("real-path"), f"gate real-path is lifted while {PLATFORM}", state(hit_open=(), runs={ROW}))
        for item in HIT_OPEN:
            ctx = state(**{**CLEAR, "hit_open": (item,)})
            self.assertEqual(rd.check(BASE, ctx)["open"]["real-path"], [f"{HIT}{item}"], item)
            self.refused(lift("real-path"), f"gate real-path is lifted while {HIT}{item}", ctx)
        pending = state(**{**CLEAR, "runs": ()})
        self.assertEqual(rd.check(BASE, pending)["open"]["real-path"],
                         ["profile hit-gate reads runs on no supported aarch64-r8gb-* row"])
        self.refused(lift("real-path"), "gate real-path is lifted while profile hit-gate reads runs on no", pending)
        undeclared = state(**{**CLEAR, "hit_open": ("the recovery manifest declares no n_max",)})
        why = f"{HIT}the recovery manifest declares no n_max"
        self.assertEqual(rd.check(BASE, undeclared)["open"]["real-path"], [why])
        self.refused(lift("real-path"), f"gate real-path is lifted while {why}", undeclared)
        self.assertLessEqual({ROW, ROW_8X}, set(LIVE["document"]["platforms"]))
        self.admitted("real-path", state(hit_open=(), runs={ROW}, supported={ROW, ROW_8X}))

    def test_a_row_counts_only_with_its_prefix_its_machine_and_supported(self):
        for ctx in (state(supported={X86}), state(supported={ROW}, machines={ROW: "x86_64"}),
                    state(supported={X86}, machines={X86: "aarch64"})):
            report = rd.check(BASE, ctx)
            for name in HARDWARE:
                self.assertIn(PLATFORM, report["open"][name], name)
                self.refused(lift(name), f"gate {name} is lifted while", ctx)

    def test_a_lift_the_repository_holds_no_evidence_for_leaves_the_gate_off_the_open_list(self):
        for name in UNJUDGED:
            self.admitted(name, CTX)

    def test_a_pin_other_than_the_committed_bytes_is_refused(self):
        for key, path in (("acceptance_sha256", "verification/measurement/acceptance.json"),
                          ("hardware_profiles_sha256", "scripts/hardware-profiles.json"),
                          ("fis_profiles_sha256", "scripts/fis-profiles.json")):
            def off(r, key=key):
                value = r["pins"][key]
                r["pins"][key] = value[:-1] + ("0" if value[-1] != "0" else "1")
            self.refused(edited(off), f"pin {key} is not the SHA-256 of {path}")
            self.refused(edited(lambda r, key=key: r["pins"].update({key: None})), f"pin {key} is null")
        self.refused(edited(lambda r: r["pins"].pop("alarms_sha256")), "pins are not")
        self.refused(edited(lambda r: r["pins"].update(extra_sha256=None)), "pins are not")

    def test_a_null_pin_is_an_open_item_and_never_a_match(self):
        catalog = b'{"rows": []}'
        present = state(files={"alarms_sha256": catalog})
        self.assertEqual(rd.check(BASE, present)["open"]["monitors"][0],
                         f"pin alarms_sha256 is null, so the record pins no {ALARMS} although the file exists")
        record = edited(lambda r: r["pins"].update(alarms_sha256=hashlib.sha256(catalog).hexdigest()))
        self.assertEqual(rd.check(record, present)["open"]["monitors"], ["the alarm catalog holds no row",
                                                                          rd.STANDING["monitors"]])
        lifted = copy.deepcopy(record)
        lifted["gates"]["monitors"]["lifted"] = True
        self.refused(lifted, "gate monitors is lifted while the alarm catalog holds no row", present)
        one = alarm_catalog(("a1", "page", SLUG))
        lifted["pins"]["alarms_sha256"] = hashlib.sha256(one).hexdigest()
        report = rd.check(lifted, state(files={"alarms_sha256": one}))
        self.assertNotIn("monitors", report["gates"])
        self.assertNotIn("monitors", report["open"])
        for basis in (None, {}):
            row = json.dumps({"rows": [{"id": "a1", "severity": "page", "runbook": SLUG,
                                        "basis": basis}]}).encode()
            lifted["pins"]["alarms_sha256"] = hashlib.sha256(row).hexdigest()
            self.refused(lifted, "gate monitors is lifted while alarm rows ['a1'] state no basis",
                         state(files={"alarms_sha256": row}))
        self.refused(record, f"pin alarms_sha256 names {ALARMS}, which is absent")
        self.refused(record, f"pin alarms_sha256 is not the SHA-256 of {ALARMS}", state(files={"alarms_sha256": b"[]"}))

    def test_a_lane_source_beside_the_delegated_acceptance_citation_has_two_homes(self):
        record = edited(cite("host-loss", "simulation", f"cycles:{CYCLES}"))
        self.refused(record, f"class host-loss cites cycles:{CYCLES}, whose receipt has two homes: the acceptance "
                     "record cites cycles")
        record = edited(source("fleet", "simulation"),
                        cite("host-loss-multi-shard", "simulation", "fleet:run-1", f"fleet:{CYCLES}"))
        self.refused(record, f"class host-loss-multi-shard cites fleet:{CYCLES}, whose receipt has two homes: the "
                     f"acceptance record cites {CYCLES}")
        self.refused(edited(source("cycles", "simulation")),
                     "are named like the acceptance record or one of its sources")
        self.refused(edited(source("acceptance", "model")), "are named like the acceptance record")

    def test_a_citation_under_another_kind_than_its_source_is_refused(self):
        record = edited(source("tabletop", "rehearsal"), cite("unknown-write", "staging", "tabletop:run-11"))
        self.refused(record, "class unknown-write cites rehearsal source tabletop under staging")
        record = edited(source("drill", "staging"), cite("host-loss-multi-shard", "hardware", "drill:run-2"))
        self.refused(record, "class host-loss-multi-shard cites staging source drill under hardware")
        record = edited(source("drill", "staging"), cite("successor-death", "staging", "drill:run-10"))
        row = rd.check(record, CTX)["classes"]["successor-death"]
        self.assertEqual((row["excluded"], row["open"]), ([], [k for k in rd.KINDS if k != "staging"]))
        record = edited(source("tabletop", "rehearsal"),
                        cite("az-loss-return", "rehearsal", "tabletop:run-5"),
                        cite("host-loss-multi-shard", "staging", "tabletop:run-11"))
        self.refused(record, "class host-loss-multi-shard cites rehearsal source tabletop under staging")

    def test_a_row_may_cite_every_kind(self):
        others = [k for k in rd.KINDS if k != "staging"]
        record = edited(*(source(f"{k}-drill", k) for k in others),
                        *(cite("census-full", k, f"{k}-drill:run-9") for k in others))
        row = rd.check(record, CTX)["classes"]["census-full"]
        self.assertEqual((row["open"], row["excluded"]), ([], []))

    def test_a_citation_list_is_distinct_and_non_empty_under_a_known_kind(self):
        self.refused(edited(lambda r: r["classes"]["census-full"]["evidence"].update(staging=[])),
                     "class census-full evidence is no distinct non-empty")
        twice = cite("census-full", "staging", "drill:run-9", "drill:run-9")
        self.refused(edited(source("drill", "staging"), twice), "class census-full evidence is no distinct non-empty")
        self.refused(edited(source("drill", "staging"), cite("census-full", "canary", "drill:run-9")),
                     "class census-full evidence is no distinct non-empty")

    def test_a_package_the_acceptance_record_judges_has_one_home(self):
        record = edited(source("recovery", "hardware"), cite("deploy-restart", "hardware", "recovery:run-1",
                                                             "recovery:CR-1"))
        self.refused(record, "class deploy-restart cites recovery:CR-1, whose receipt has two homes: the acceptance "
                     "record cites CR-1")
        for padded in ("recovery:CR-1 ", "recovery: CR-1", "recovery:CR-1\t"):
            record = edited(source("recovery", "hardware"), cite("deploy-restart", "hardware", padded))
            self.refused(record, f"class deploy-restart cites {padded!r}, which holds whitespace")
        record = edited(source("drill", "staging"), cite("census-full", "staging", "drill:run-9", "drill:run-9 "))
        self.refused(record, "class census-full cites 'drill:run-9 ', which holds whitespace")

    def test_a_row_of_its_own_that_names_a_failure_class_keeps_a_kind(self):
        def exclude_all(r):
            r["classes"]["deploy-restart"]["evidence"] = {}
            r["classes"]["deploy-restart"]["excluded"] = {k: {"reason": "not measured yet", "owner": "#255"}
                                                          for k in rd.KINDS}
        self.refused(edited(exclude_all), "class deploy-restart names FC1 and excludes every kind")

    def test_sources_are_cited_known_and_of_a_kind(self):
        self.refused(edited(source("drill", "staging")), "sources ['drill'] are cited by no class")
        self.refused(edited(source("drill", "canary"), cite("census-full", "staging", "drill:run-9")),
                     "source drill is not {kind, owner, evidence} with a kind of")
        self.refused(edited(cite("census-full", "staging", "drill:run-9")),
                     "class census-full cites drill:run-9, whose source drill is not in the source table")
        self.refused(edited(cite("census-full", "staging", "drill")), "which names no source and item")
        self.refused(edited(source("drill", "staging"), lambda r: r["sources"]["drill"].pop("owner"),
                            cite("census-full", "staging", "drill:run-9")),
                     "source drill is not {kind, owner, evidence}")
        for delegate in ("", " "):
            self.refused(edited(lambda r, d=delegate: r["classes"]["census-full"].update(delegated=d)),
                         "class census-full delegate is neither null nor a text")
        for field in ("owner", "evidence"):
            def blank(r, field=field):
                r["sources"]["drill"][field] = " "
            self.refused(edited(source("drill", "staging"), blank, cite("census-full", "staging", "drill:run-9")),
                         "source drill is not")
        self.refused(edited(source("drill", "staging"), lambda r: r["sources"]["drill"].update(extra=1),
                            cite("census-full", "staging", "drill:run-9")), "source drill is not")
        self.refused(edited(lambda r: r.update(sources=[])), "sources is no map of sources")
        self.refused(edited(cite("census-full", "staging", "drill: ")), "which names no source and item")

    def test_the_acceptance_record_is_cited_only_by_its_own_delegated_class(self):
        self.refused(edited(cite("census-full", "simulation", "acceptance:host-loss")),
                     "only a row delegated to the acceptance record cites it")
        self.refused(edited(lambda r: r["classes"]["host-loss"]["evidence"].update(model=["acceptance:process-kill"])),
                     "class host-loss is delegated to the acceptance record and cites anything but")
        self.refused(edited(lambda r: r["classes"]["host-loss"]["evidence"].pop("store")),
                     "cites anything but acceptance:host-loss under each of")
        self.refused(edited(cite("host-loss", "staging", "acceptance:host-loss")), "cites anything but "
                     "acceptance:host-loss under each of")
        self.refused(edited(lambda r: r["classes"]["host-loss"].update(delegated=None)),
                     "only a row delegated to the acceptance record cites it")

        def undelegate(r):
            r["classes"]["process-kill"].update(delegated=None, evidence={})
        self.refused(edited(undelegate), "the rows delegated to the acceptance record are not its classes")

        def rename(r):
            r["classes"]["host-loss-v2"] = r["classes"].pop("host-loss")
            r["classes"]["host-loss-v2"]["evidence"] = {k: ["acceptance:host-loss-v2"] for k in mf.EVIDENCE}
        self.refused(edited(rename), "class host-loss-v2 is delegated to the acceptance record, which holds no such "
                     "class")

    def test_a_delegated_row_names_the_failure_class_its_acceptance_class_evidences(self):
        def swap(r):
            r["classes"]["host-loss"]["failure_class"] = "FC8"
            r["classes"]["actual-volume-loss"]["failure_class"] = "FC2"
        self.refused(edited(swap), "class host-loss is delegated to the acceptance record, whose host-loss class "
                     "evidences FC2, and names FC8")
        self.refused(edited(lambda r: r["classes"]["process-kill"].update(failure_class="FC2")),
                     "whose process-kill class evidences FC1, and names FC2")
        self.refused(edited(lambda r: r["classes"]["process-kill"].update(failure_class=None, requirement="R2")),
                     "whose process-kill class evidences FC1, and names None")

    def test_the_failure_class_bindings_name_exactly_the_acceptance_classes(self):
        added = copy.deepcopy(CTX)
        added["acceptance"]["classes"]["torn-write"] = copy.deepcopy(added["acceptance"]["classes"]["process-kill"])

        def add(r):
            r["classes"]["torn-write"] = copy.deepcopy(r["classes"]["process-kill"])
            r["classes"]["torn-write"].update(failure_class=None, requirement="R7",
                                              evidence={k: ["acceptance:torn-write"] for k in mf.EVIDENCE})
        self.refused(edited(add), "readiness.py binds failure classes to the acceptance classes", added)
        removed = copy.deepcopy(CTX)
        removed["acceptance"]["classes"].pop("process-kill")
        self.refused(edited(lambda r: r["classes"].pop("process-kill")),
                     "readiness.py binds failure classes to the acceptance classes", removed)

    def test_a_row_delegated_to_named_owners_cites_nothing_and_excludes_every_kind(self):
        self.refused(edited(lambda r: r["classes"]["isolated-live-owner"]["excluded"].pop("model")),
                     "class isolated-live-owner is delegated to #148 and #137 and cites evidence or leaves a kind "
                     "unexcluded")
        self.refused(edited(source("drill", "staging"), cite("isolated-live-owner", "staging", "drill:run-2")),
                     "class isolated-live-owner is delegated to #148 and #137 and cites evidence")

        def kept(r):
            r["classes"]["isolated-live-owner"]["evidence"]["staging"] = ["gameday:GD-2"]
        self.refused(edited(kept), "class isolated-live-owner both cites and excludes ['staging']")

    def test_a_failure_class_keeps_a_row_that_can_hold_its_evidence(self):
        every = {k: {"reason": "graded elsewhere", "owner": "#255"} for k in rd.KINDS}
        self.refused(edited(lambda r: r["classes"]["observed-deposition"].update(delegated="blotter pull request 1999", excluded=every)),
                     "failure classes ['FC3'] are named only by rows that exclude every kind")

        def two(r):
            r["classes"]["observed-deposition"].update(delegated="blotter pull request 1999", excluded=copy.deepcopy(every))
            r["classes"]["observed-deposition-fleet"] = copy.deepcopy(r["classes"]["observed-deposition"])
        self.refused(edited(two), "failure classes ['FC3'] are named only by rows that exclude every kind")
        report = rd.check(edited(lambda r: r["classes"]["power-loss"].update(excluded=every, evidence={}),
                                 lambda r: r.update(items=[i for i in r["items"] if i["class"] != "power-loss"])), CTX)
        self.assertEqual(report["classes"]["power-loss"]["open"], [])

    def test_a_kind_is_cited_or_excluded_never_both(self):
        self.refused(edited(source("drill", "staging"),
                            lambda r: r["classes"]["actual-volume-loss"]["evidence"].update(staging=["drill:run-8"])),
                     "class actual-volume-loss both cites and excludes ['staging']")
        self.refused(edited(lambda r: r["classes"]["power-loss"]["excluded"]["staging"].pop("owner")),
                     "class power-loss exclusions are not a {reason, owner} of text per kind")
        for field in ("reason", "owner"):
            blank = edited(lambda r, f=field: r["classes"]["host-loss"]["excluded"]["staging"].update({f: "\t "}))
            self.refused(blank, "class host-loss exclusions are not a {reason, owner} of text per kind")
        self.refused(edited(lambda r: r["classes"]["power-loss"]["excluded"]["staging"].update(extra="x")),
                     "class power-loss exclusions are not")

        def typo(r):
            r["classes"]["deploy-restart"]["excluded"] = {k: {"reason": "graded elsewhere", "owner": "#255"}
                                                          for k in (*rd.KINDS, "canary")}
        self.refused(edited(typo), "class deploy-restart exclusions are not")

    def test_every_failure_class_is_named_or_explained(self):
        self.refused(edited(drop_class("successor-death")),
                     "failure classes ['FC10'] are named by no class row and explained by no unmapped entry")
        record = edited(drop_class("successor-death"),
                        lambda r: r["unmapped"].update(FC10="a successor death is judged under owner-standby-loss"))
        report = rd.check(record, CTX)
        self.assertEqual((report["failure_classes"]["FC10"], report["unmapped"]),
                         ([], {"FC10": "a successor death is judged under owner-standby-loss"}))
        self.refused(edited(drop_class("successor-death"), drop_class("partition-loss"),
                            lambda r: r["unmapped"].update(FC10="judged under owner-standby-loss")),
                     "failure classes ['FC12'] are named by no class row and explained by no unmapped entry")
        self.refused(edited(lambda r: r["unmapped"].update(FC10="judged elsewhere")),
                     "failure classes ['FC10'] are named by a class row and listed unmapped")
        self.refused(edited(lambda r: r["classes"]["successor-death"].update(failure_class="FC13")),
                     "class successor-death holds neither a failure class")
        self.refused(edited(lambda r: r["classes"]["census-full"].update(requirement=None)),
                     "class census-full holds neither a failure class")
        self.refused(edited(lambda r: r["classes"]["successor-death"].update(requirement="R5")),
                     "class successor-death holds neither a failure class")
        self.refused(edited(lambda r: r["classes"]["census-full"].update(requirement="R13")),
                     "class census-full holds neither a failure class")
        for reason in ("", " ", "\t"):
            self.refused(edited(drop_class("successor-death"), lambda r, why=reason: r["unmapped"].update(FC10=why)),
                         "unmapped is no reason per failure class")
        self.refused(edited(lambda r: r["unmapped"].update(FC13="x")), "unmapped is no reason per failure class")

    def test_the_parent_is_the_contract_the_acceptance_record_pins_and_the_plan(self):
        self.refused(edited(lambda r: r["parent"]["specification"].update(body_sha256="0" * 64)),
                     "parent specification is not #120")
        self.refused(edited(lambda r: r["parent"].update(digest="another digest")), "parent specification is not")
        self.refused(edited(lambda r: r["parent"]["plan"].update(issue="#120")), "parent plan is not #255")
        self.refused(edited(lambda r: r["parent"]["plan"].update(body_sha256="0" * 63)), "parent plan is not #255")
        self.refused(edited(lambda r: r["parent"]["plan"].update(extra=1)), "parent plan keys are not")
        self.refused(edited(lambda r: r["parent"]["plan"].pop("issue")), "parent plan keys are not")
        self.refused(edited(lambda r: r["parent"].pop("plan")), "parent keys are not")
        self.refused(edited(lambda r: r["parent"].update(extra=1)), "parent keys are not")

    def test_the_record_shape_kinds_and_version_are_fixed(self):
        self.refused(edited(lambda r: r.update(extra=1)), "keys are not")
        self.refused(edited(lambda r: r.update(version=0)), "record kind and version")
        self.refused(edited(lambda r: r.update(version=True)), "record kind and version")
        self.refused(edited(lambda r: r.update(record="acceptance")), "record kind and version")
        self.refused(edited(lambda r: r.update(version=1 << 64)), "record kind and version")
        self.assertEqual(rd.check(edited(lambda r: r.update(version=(1 << 64) - 1)), CTX)["verdict"], "NOT READY")
        self.refused(edited(lambda r: r["kinds"].reverse()), "kinds are not")
        self.refused(edited(lambda r: r["classes"]["census-full"].pop("meaning")), "class census-full keys")
        for meaning in ("", "  "):
            self.refused(edited(lambda r, m=meaning: r["classes"]["census-full"].update(meaning=m)),
                         "class census-full meaning is no text")
        self.refused(edited(lambda r: r.update(classes={})), "classes is no non-empty map of class rows")
        self.refused(edited(lambda r: r.update(classes=["census-full"])), "classes is no non-empty map of class rows")
        self.refused(edited(lambda r: r.update(unmapped=[])), "unmapped is no reason per failure class")
        self.refused(edited(lambda r: r["classes"]["census-full"].update(extra=1)), "class census-full keys")

    def test_a_container_of_another_json_type_is_refused_by_its_own_rule(self):
        def names(path):
            """An edit that replaces the object at `path` with the list of its keys."""
            def edit(r):
                for part in path[:-1]:
                    r = r[part]
                r[path[-1]] = list(r[path[-1]])
            return edit
        for edit, message in (
                (names(("pins",)), "pins are not"), (names(("gates",)), "gates are not"),
                (names(("gates", "runbooks")), "gate runbooks is not"),
                (names(("classes", "census-full")), "class census-full keys are not"),
                (names(("classes", "census-full", "evidence")), "class census-full evidence is no distinct"),
                (lambda r: r["classes"]["census-full"].update(excluded=["model"]),
                 "class census-full exclusions are not"),
                (names(("classes", "power-loss", "excluded", "staging")), "class power-loss exclusions are not"),
                (lambda r: r["sources"].update(drill=["kind", "owner", "evidence"]), "source drill is not"),
                (lambda r: item(r, "support-model").update(applicability=["not_applicable", "approver"]),
                 "item support-model applicability"),
                (lambda r: item(r, "support-model").update(requirement=5), "item support-model names no requirement"),
                (lambda r: r.update(items=5), "items are no list"), (names(("items", 0)), "items are no list"),
                (names(("floors",)), "floors are not"), (names(("waves",)), "waves are not"),
                (names(("authority",)), "authority is not the roles"), (names(("parent",)), "parent keys are not"),
                (names(("parent", "plan")), "parent plan keys are not")):
            self.refused(edited(edit), message)
        self.refused(list(BASE), "keys are not")

    def test_a_rule_names_what_it_refuses_before_a_later_rule_can(self):
        self.refused(edited(cite("census-full", "staging", ":run-9")), "which names no source and item")
        self.refused(edited(cite("census-full", "simulation", "cycles:run-9")),
                     "class census-full cites cycles:run-9, whose receipt has two homes: the acceptance record cites "
                     "cycles")
        self.refused(edited(lambda r: r.update(items=[])), "items are no list")
        self.refused(edited(lambda r: r.update(unmapped=dict.fromkeys(rd.FAILURE_CLASSES, "judged elsewhere"))),
                     "are named by a class row and listed unmapped")

        def swap(r):
            item(r, "end-contract")["source"], item(r, "suffix-damage")["source"] = (
                "gate:suffix-damage", "gate:end-contract")
        self.assertEqual(rd.ACTIVATION["end-contract"], rd.ACTIVATION["suffix-damage"])
        self.refused(edited(swap), "a gate source belongs to the activation floor item named for that gate")

    def test_class_and_source_names_are_lowercase_words_joined_by_hyphens(self):
        for key in ("", " successor-death", "successor-death ", "Successor-death", "successor_death",
                    "successor--death", "-successor-death", "successor-death-"):
            record = edited(lambda r, k=key: r["classes"].update({k: r["classes"].pop("successor-death")}))
            self.refused(record, f"names [{key!r}] are not lowercase words joined by hyphens")
        self.refused(edited(source("Game Day", "staging"), cite("census-full", "staging", "Game Day:run-9")),
                     "names ['Game Day'] are not lowercase words joined by hyphens")
        record = edited(source("Cycles", "simulation"), cite("host-loss-multi-shard", "simulation", "Cycles:run-1"))
        self.refused(record, "names ['Cycles'] are not lowercase words joined by hyphens")


class Context(unittest.TestCase):
    """The context judges the acceptance record, the hardware manifest and the Quint manifest from the bytes their
    digests name, and reads the always-pinned files before the acceptance context."""

    def judged(self, **changes):
        quint = (ROOT / "verification/quint/expected.json").read_bytes()
        return {"manifest_sha256": hashlib.sha256(LIVE["files"]["hardware_profiles_sha256"]).hexdigest(),
                "quint_sha256": hashlib.sha256(quint).hexdigest(), "document": {"judged": True},
                "catalog": {rd.END: {"tests": ["case-a", "case-b"],
                                     "controls": [{"test": "control-a"}, {"test": "control-b"}]}}, **changes}

    def context(self, files, judged, checked=(["gate-a", "gate-b"], ["unrun-a"])):
        with mock.patch.object(rd, "pinned_files", return_value=files), \
                mock.patch.object(rd.acc, "context", return_value=(judged, None)), \
                mock.patch.object(rd.acc, "check", return_value=checked) as check, \
                mock.patch.object(rd.gate, "check", return_value=["item-a", "item-b"]) as hit:
            return rd.context(None), check, hit

    def reading(self, quint):
        """Patch the Quint manifest's bytes to `quint`; every other file reads from disk."""
        read = rd.gate.read_file
        return mock.patch.object(rd.gate, "read_file",
                                 lambda path, name: quint if path == rd.acc.QUINT else read(path, name))

    def test_the_context_carries_the_evidence_of_the_bytes_it_pins(self):
        acceptance = copy.deepcopy(LIVE["acceptance"])
        acceptance["unrun"].pop("trace-replay", None)
        acceptance["unrun"]["only-in-these-bytes"] = "a domain the committed record lacks"
        files = {**LIVE["files"], "acceptance_sha256": json.dumps(acceptance).encode()}
        ctx, check, hit = self.context(files, self.judged())
        quint = rd.parse(gate.read_file(ROOT / "verification/quint/expected.json", "Quint manifest"), "Quint manifest")
        self.assertEqual(check.call_args.args[0], acceptance)
        self.assertEqual(hit.call_args.args, ({"judged": True}, {rd.END}))
        self.assertEqual(ctx["hit_gate_open"], ["item-a", "item-b"])
        self.assertEqual(ctx["acceptance"], acceptance)
        self.assertEqual(ctx["acceptance_gates"], ["gate-a", "gate-b"])
        self.assertEqual(ctx["quint_blocked"], quint["blocked"])
        self.assertEqual(ctx["end_cases"], ["case-a", "case-b", "control-a", "control-b"])
        self.assertEqual(ctx["document"], {"judged": True})
        self.assertIs(ctx["files"], files)
        self.assertEqual(ctx["root"], ROOT)

    def test_a_blocked_control_of_the_end_obligation_contradicts_the_end_contract_lift(self):
        quint = json.dumps({"blocked": {"control-b": "a provider premise no case establishes"}}).encode()
        with self.reading(quint):
            judged, *_ = self.context(dict(LIVE["files"]), self.judged(quint_sha256=hashlib.sha256(quint).hexdigest()))
        ctx = {**state(), "end_cases": judged["end_cases"], "quint_blocked": judged["quint_blocked"]}
        why = "1 cases of obligation preserve-p4-retention-proposed stay blocked in verification/quint/expected.json"
        self.assertEqual(rd.check(BASE, ctx)["open"]["end-contract"], [why])
        with self.assertRaises(rd.Refusal) as caught:
            rd.check(lift("end-contract"), ctx)
        self.assertIn(f"gate end-contract is lifted while {why}", str(caught.exception))

    def test_evidence_other_than_the_judged_bytes_is_refused(self):
        for changes, message in (({"manifest_sha256": "0" * 64}, "scripts/hardware-profiles.json changed"),
                                 ({"quint_sha256": "0" * 64}, "verification/quint/expected.json changed")):
            with self.assertRaises(rd.Refusal) as caught:
                self.context(dict(LIVE["files"]), self.judged(**changes))
            self.assertIn(message, str(caught.exception))
        def repeat(data, member):
            changed = data.decode().replace(member, f"{member} {member}", 1).encode()
            self.assertNotEqual(changed, data, member)
            return changed

        def refused(what, files, judged, quint=None):
            with self.reading(quint or (ROOT / "verification/quint/expected.json").read_bytes()), \
                    self.assertRaises(rd.FAULTS) as caught:
                self.context(files, judged)
            self.assertIn(f"{what} repeats an object key", str(caught.exception))

        acceptance = repeat(LIVE["files"]["acceptance_sha256"], '"record": "acceptance",')
        refused("acceptance record", {**LIVE["files"], "acceptance_sha256": acceptance}, self.judged())
        manifest = repeat(LIVE["files"]["hardware_profiles_sha256"], '"version": 1,')
        refused("hardware manifest", {**LIVE["files"], "hardware_profiles_sha256": manifest},
                self.judged(manifest_sha256=hashlib.sha256(manifest).hexdigest()))
        quint = (ROOT / "verification/quint/expected.json").read_bytes().replace(b"{", b'{"java": {},', 1)
        refused("Quint manifest", dict(LIVE["files"]), self.judged(quint_sha256=hashlib.sha256(quint).hexdigest()),
                quint)
        gamedays = repeat(LIVE["files"]["gamedays_sha256"], '"version": 1,')
        refused("game-day catalog", {**LIVE["files"], "gamedays_sha256": gamedays}, self.judged())

    def test_an_absent_always_pinned_file_is_refused_before_the_acceptance_context(self):
        absent = {**rd.PINS, "fis_profiles_sha256": ("scripts/absent-fis-profiles.json", None)}
        with mock.patch.object(rd, "PINS", absent), \
                mock.patch.object(rd.acc, "context", side_effect=AssertionError("acceptance context built")), \
                self.assertRaises(rd.Refusal) as caught:
            rd.context(None)
        self.assertIn("scripts/absent-fis-profiles.json", str(caught.exception))

    def test_a_fault_injection_table_without_a_profiles_map_is_refused_before_the_acceptance_context(self):
        for table, message in ((b'{"profiles": "fis-pause"}',
                                "scripts/fis-profiles.json holds no profiles map of profile objects"),
                               (b'{"profiles": ["fis-pause"]}', "holds no profiles map of profile objects"),
                               (b'{"profiles": {"fis-pause": 1}}', "holds no profiles map of profile objects"),
                               (b'{"profiles": {"fis-pause": {}, "fis-stop": 1}}',
                                "holds no profiles map of profile objects"),
                               (b'[]', "holds no profiles map of profile objects"),
                               (b'{"profiles": {}, "profiles": {}}', "fault-injection profiles repeats an object key")):
            files = {**LIVE["files"], "fis_profiles_sha256": table}
            with mock.patch.object(rd, "pinned_files", return_value=files), \
                    mock.patch.object(rd.acc, "context", side_effect=AssertionError("acceptance context built")), \
                    self.assertRaises(rd.Refusal) as caught:
                rd.context(None)
            self.assertIn(message, str(caught.exception))

ANCHOR = {"path": "scripts/readiness.py", "symbol": "def check"}
RUNBOOK = "docs/runbooks/failover/hold-device.md"
SLUG = "RB-hold-device"


def alarm_catalog(*rows):
    """Alarm catalog bytes holding `rows`, each (id, severity, runbook slug), with one derived number each."""
    return json.dumps({"record": "failover-alarms", "rows": [
        {"id": a, "severity": severity, "runbook": slug, "basis": {"window.reports": "derived"}}
        for a, severity, slug in rows]}).encode()


ACTION = {**ANCHOR, "sha256": hashlib.sha256((ROOT / ANCHOR["path"]).read_bytes()).hexdigest()}


def entry(slug=SLUG, /, **changes):
    """A DRAFT runbook index entry for `slug` over the fixture runbook whose action anchor resolves."""
    value = {"id": slug, "file": RUNBOOK, "kind": "procedure", "actions": [{**ANCHOR, "sha256": None}],
             "alarms": [], "status": "DRAFT", "verified_sha256": None, "verified_revision": None, "rungs": [],
             "paths": [], "limitations": [], "rehearsal": None}
    value.update(changes)
    return value


def rehearsed(body, **rehearsal):
    """Changes that mark an entry VERIFIED over runbook bytes `body` and the action source's bytes, rehearsed by a
    non-author over both anchors of the fixture runbook."""
    return {"status": "VERIFIED", "verified_sha256": hashlib.sha256(body).hexdigest(), "verified_revision": "c" * 40,
            "actions": [dict(ACTION)], "rungs": ["tabletop"], "paths": ["rb-hold-device", "rb-hold-store"],
            "rehearsal": {
                "record_sha256": "d" * 64, "executor": "operator-b", "author": "operator-a", "date": "2026-11-21",
                "result": "MET", **rehearsal}}


class Items(unittest.TestCase):
    refused = Check.refused

    def test_an_item_with_no_criterion_is_refused(self):
        for criterion in ("", "  "):
            self.refused(edited(lambda r, c=criterion: item(r, "support-model").update(criterion=c)),
                         "item support-model has no criterion")
        self.refused(edited(lambda r: item(r, "support-model").pop("criterion")), "items are no list")

    def test_a_null_max_age_prints_policy_undefined_under_evidence_age(self):
        def aged(r):
            for i in r["items"]:
                i["max_age_days"] = 30
        report = rd.check(edited(aged), CTX)
        self.assertNotIn("evidence-age", report["open"])
        report = rd.check(edited(aged, lambda r: item(r, "alarm-basis").update(max_age_days=None)), CTX)
        self.assertEqual(report["open"]["evidence-age"], ["POLICY UNDEFINED: item alarm-basis has a null max_age_days"])
        self.refused(edited(lambda r: r["gates"]["evidence-age"].update(lifted=True)), "gate evidence-age is lifted "
                     "while POLICY UNDEFINED")
        self.refused(edited(lambda r: item(r, "alarm-basis").update(max_age_days=0)), "item alarm-basis "
                     "max_age_days")

    def approve(self, r):
        for i in r["items"]:
            if i["applicability"] != "applicable":
                i["applicability"]["approver"] = "the owner"

    def test_every_authority_role_is_null_and_an_unset_role_keeps_the_gate_open(self):
        self.assertEqual(RECORD["authority"], {"launch": None, "risk": None})
        report = rd.check(edited(self.approve, lambda r: r["authority"].update(launch="launch-authority")), CTX)
        self.assertEqual(report["open"]["authority"], ["authority role risk is null"])
        roles = edited(self.approve, lambda r: r["authority"].update(launch="launch-authority", risk="risk-authority"),
                       lambda r: r["gates"]["authority"].update(lifted=True))
        self.assertNotIn("authority", rd.check(roles, CTX)["gates"])
        self.refused(edited(lambda r: r["authority"].update(extra=None)), "authority is not the roles")
        self.refused(edited(lambda r: r["authority"].update(launch=" ")), "authority is not the roles")
        one = edited(self.approve, lambda r: r["authority"].update(launch="release-board", risk=" Release-Board"))
        self.assertEqual(rd.check(one, CTX)["open"]["authority"], [
            "authority roles launch and risk name one role, and the launch authority is never the only accepter of "
            "the residual risk"])

    def test_a_not_applicable_item_is_reported_and_stays_open_until_approved(self):
        report = rd.check(BASE, CTX)
        self.assertEqual(list(report["not_applicable"]), WAIVED)
        self.assertEqual(report["not_applicable"]["rollback-refusal-retention"]["approver"], None)
        for name in ("census-full-retention", "attach-slots-exhausted-retention"):
            self.assertNotIn(name, report["not_applicable"])
        def roles(r):
            r["authority"].update(launch="launch-authority", risk="risk-board")
        approved = rd.check(edited(self.approve, roles), CTX)
        self.assertNotIn("authority", approved["open"])
        self.assertEqual(approved["not_applicable"]["rollback-refusal-retention"]["approver"], "the owner")
        pending = edited(self.approve, roles,
                         lambda r: item(r, "rollback-refusal-retention")["applicability"].update(approver=None))
        self.assertEqual(rd.check(pending, CTX)["open"]["authority"], [
            "item rollback-refusal-retention reads not applicable with no approver: no shard recovers in this "
            "scenario, so it has no retained set to keep"])
        pending["gates"]["authority"]["lifted"] = True
        self.refused(pending, "gate authority is lifted while item rollback-refusal-retention reads not applicable")

    def test_an_item_source_names_evidence_of_the_item_kind(self):
        self.refused(edited(lambda r: item(r, "route-monotonic").update(kind="model")),
                     "item route-monotonic cites record client-route-high-water of job workspace, which is no model")
        self.refused(edited(lambda r: item(r, "route-monotonic").update(source="record:no-such-record")),
                     "which the catalog lacks")
        cited = "takeover-history-preserves-the-retained-set"
        self.refused(edited(lambda r: item(r, "route-monotonic").update(source=f"record:{cited}")),
                     f"item route-monotonic cites {cited}, whose receipt has two homes")
        self.refused(edited(lambda r: item(r, "hit-latency").update(kind="staging")), "a hit-gate or fault")
        self.refused(edited(lambda r: item(r, "fis-pause").update(source="fis:fis-unknown")),
                     "a hit-gate or fault")
        self.refused(edited(lambda r: item(r, "support-model").update(kind="staging")),
                     "item support-model cites a reviewer but is of kind staging")
        self.refused(edited(lambda r: item(r, "alarm-controls").update(kind="review", source="hit-gate")),
                     "is a review item whose source 'hit-gate' is a machine receipt")
        self.refused(edited(lambda r: item(r, "host-loss-containment").update(
            source="acceptance:process-kill/containment")),
                     "an acceptance item reads one acceptance kind cell of its own delegated class")
        self.refused(edited(lambda r: item(r, "host-loss-safety").update(source="acceptance:process-kill/safety")),
                     "item host-loss-safety is a safety floor item of acceptance class host-loss, so it cites "
                     "acceptance:host-loss/safety or is an open gap")
        self.refused(edited(lambda r: item(r, "host-loss-safety").update(source="record:client-route-high-water")),
                     "item host-loss-safety is a safety floor item of acceptance class host-loss, so it cites "
                     "acceptance:host-loss/safety or is an open gap, and cites record:client-route-high-water")
        self.assertIn("host-loss-safety", rd.check(edited(lambda r: item(r, "host-loss-safety").update(source=None)),
                                                    CTX)["gaps"])
        opened = edited(lambda r: r["classes"]["host-loss"]["excluded"].pop("rehearsal"),
                        lambda r: item(r, "host-loss-containment").update(kind="rehearsal"))
        self.refused(opened, "item host-loss-containment cites acceptance:host-loss/containment: an acceptance item "
                     "reads one acceptance kind cell of its own delegated class")
        self.refused(edited(lambda r: item(r, "census-full-safety").update(source="acceptance:census-full/safety")),
                     "item census-full-safety cites acceptance:census-full/safety: an acceptance item reads one "
                     "acceptance kind cell of its own delegated class")
        self.refused(edited(lambda r: item(r, "host-loss-containment").update(source="acceptance:x/containment")),
                     "an acceptance item reads one acceptance kind cell")
        self.refused(edited(lambda r: item(r, "host-loss-containment").update(source="acceptance:host-loss/health")),
                     "an acceptance item reads one acceptance kind cell")
        self.refused(edited(lambda r: item(r, "actual-volume-loss-safety").update(
            source="acceptance:actual-volume-loss/safety")), "a cell the acceptance record cites nothing in")
        self.refused(edited(lambda r: item(r, "runbook-coverage").update(source="runbook:RB-missing")),
                     "a runbook item is a rehearsal of an index entry")
        self.refused(edited(lambda r: item(r, "end-contract").update(source="gate:no-gate")), "which is no gate")
        self.refused(edited(lambda r: item(r, "route-monotonic").update(source="lane:x")), "names no source")

    def test_a_record_source_reads_its_job_kind(self):
        sweep = "sweep-seqlock-accepts-only-coherent-copies"
        self.assertIn("route-monotonic", rd.check(edited(lambda r: item(r, "route-monotonic").update(
            kind="model", source=f"record:{sweep}")), CTX)["domains"]["overload-and-client-behavior"])
        self.refused(edited(lambda r: item(r, "route-monotonic").update(source=f"record:{sweep}")),
                     f"item route-monotonic cites record {sweep} of job sweep, which is no simulation evidence")
        miri = "miri-arena-rollback-releases-once"
        self.refused(edited(lambda r: item(r, "route-monotonic").update(kind="model", source=f"record:{miri}")),
                     f"item route-monotonic cites record {miri} of job miri, which is no model evidence")

    def test_each_lane_job_reads_as_model_or_simulation_evidence(self):
        kinds = {**dict.fromkeys(("quint", "tlc", "kani", "verus", "loom", "genmc", "rc11", "sweep"), "model"),
                 **dict.fromkeys(("workspace", "long-run", "campaigns", "search", "search-nightly"), "simulation")}
        ctx = {**CTX, "catalog": {**CTX["catalog"], **{f"lane-{job}": {"job": job} for job in kinds}}}
        for job, kind in kinds.items():
            other = "simulation" if kind == "model" else "model"
            with self.subTest(job):
                cited = edited(lambda r, kind=kind, job=job: item(r, "route-monotonic").update(
                    kind=kind, source=f"record:lane-{job}"))
                self.assertIn("route-monotonic", rd.check(cited, ctx)["domains"]["overload-and-client-behavior"])
                item(cited, "route-monotonic")["kind"] = other
                self.refused(cited, f"item route-monotonic cites record lane-{job} of job {job}, which is no {other} "
                             "evidence", ctx)

    def test_a_gate_source_belongs_to_the_activation_item_of_that_gate_and_kind(self):
        def swap(r):
            item(r, "real-path")["source"], item(r, "store-qualification")["source"] = (
                "gate:store-qualification", "gate:real-path")
        self.refused(edited(swap), "a gate source belongs to the activation floor item named for that gate")
        for name, kind in (("end-contract", "store"), ("store-qualification", "review"), ("real-path", "rehearsal"),
                           ("suffix-damage", "hardware")):
            self.refused(edited(lambda r, n=name, k=kind: item(r, n).update(kind=k)), f"item {name} ")
        self.refused(edited(lambda r: item(r, "wave-authorization").update(source="gate:deploy-gate")),
                     "item wave-authorization cites gate:deploy-gate: a gate source belongs to the activation floor")
        self.refused(edited(lambda r: item(r, "suffix-damage").update(source=None)),
                     "the activation floor is not the items of gates")
        self.refused(edited(lambda r: item(r, "suffix-damage").update(floor=None)),
                     "item suffix-damage cites gate:suffix-damage: a gate source belongs to the activation floor")

    def test_the_floors_cover_activation_safety_retention_the_wave_halt_and_the_safety_alarms(self):
        report = rd.check(BASE, CTX)
        self.assertEqual(sorted(report["floors"]["activation"]),
                         ["end-contract", "real-path", "store-qualification", "suffix-damage"])
        self.assertEqual(report["floors"]["wave-halt"], ["wave-halt"])
        self.assertEqual(sorted(report["floors"]["safety-alarms"]),
                         ["safety-alarm-routing-production", "safety-alarm-routing-staging"])
        self.assertIn("host-loss-safety", report["floors"]["safety"])
        self.assertNotIn("actual-volume-loss-retention", report["floors"]["retention"])
        self.refused(edited(lambda r: item(r, "census-full-safety").update(floor=None)),
                     "class census-full holds 0 safety floor items, not at least one and at most one per kind")
        self.refused(edited(lambda r: item(r, "census-full-retention").update(floor=None)),
                     "class census-full holds 0 retention floor items")
        self.refused(edited(lambda r: item(r, "host-loss-safety").update(source="acceptance:host-loss/retention")),
                     "item host-loss-safety is a safety floor item of acceptance class host-loss, so it cites "
                     "acceptance:host-loss/safety")
        cold = {"id": "actual-volume-loss-retention", "class": "actual-volume-loss", "floor": None,
                "source": "acceptance:actual-volume-loss/retention"}
        self.refused(edited(lambda r: r["items"].append({**item(r, "host-loss-retention"), **cold})),
                     "starts cold and claims no retention")
        doubled = {"floor": "retention", "class": "host-loss", "kind": "simulation", "source": None}
        self.refused(edited(lambda r: item(r, "support-model").update(doubled)),
                     "class host-loss holds 2 retention floor items, not at least one and at most one per kind")
        self.refused(edited(lambda r: item(r, "wave-halt").update(floor=None)),
                     "floors ['wave-halt'] hold no item")
        self.refused(edited(lambda r: item(r, "wave-halt").update(floor="halt")), "item wave-halt floor")
        self.refused(edited(lambda r: r["floors"].pop("wave-halt")), "floors are not")

    def test_the_halt_and_alarm_floors_hold_an_item_of_each_named_kind(self):
        self.refused(edited(lambda r: item(r, "safety-alarm-routing-production").update(floor=None)),
                     "the safety-alarms floor lacks ['safety-alarm-routing-production (review)']")
        self.refused(edited(lambda r: item(r, "safety-alarm-routing-production").update(floor=None),
                            lambda r: item(r, "operator-training").update(floor="safety-alarms")),
                     "the safety-alarms floor lacks ['safety-alarm-routing-production (review)']")
        self.refused(edited(lambda r: item(r, "wave-halt").update(floor=None),
                            lambda r: item(r, "safety-alarm-routing-staging").update(floor="wave-halt")),
                     "the wave-halt floor lacks ['wave-halt (staging)']")
        extra = edited(lambda r: item(r, "deploy-gate-table").update(floor="wave-halt"))
        self.assertIn("deploy-gate-table", rd.check(extra, CTX)["floors"]["wave-halt"])
        self.refused(edited(lambda r: item(r, "safety-alarm-routing-staging").update(floor=None)),
                     "the safety-alarms floor lacks ['safety-alarm-routing-staging (staging)']")

    def test_two_kinds_share_one_class_floor(self):
        staged = {**item(RECORD, "census-full-safety"), "id": "census-full-safety-staging", "kind": "staging"}
        report = rd.check(edited(lambda r: r["items"].append(dict(staged))), CTX)
        self.assertIn("census-full-safety", report["floors"]["safety"])
        self.assertIn("census-full-safety-staging", report["floors"]["safety"])

    def test_a_cold_class_holds_no_retention_item_and_a_warm_acceptance_class_keeps_its_own(self):
        cold = {**item(RECORD, "host-loss-multi-shard-retention"), "id": "actual-volume-loss-retention",
                "class": "actual-volume-loss", "source": None}
        self.refused(edited(lambda r: r["items"].append(dict(cold))), "class actual-volume-loss starts cold and "
                     "claims no retention, but holds retention floor items ['actual-volume-loss-retention']")
        waived = {"not_applicable": "asserted", "approver": None}
        for name in ("host-loss", "same-host-restart"):
            self.refused(edited(lambda r, n=name: item(r, f"{n}-retention").update(applicability=dict(waived))),
                         f"class {name} is a warm acceptance class, so its retention floor items")
        for name in ("census-full", "attach-slots-exhausted"):
            self.assertNotIn(f"{name}-retention", rd.check(BASE, CTX)["not_applicable"])
        self.refused(edited(lambda r: item(r, "host-loss-retention").update(source="record:client-route-high-water")),
                     "item host-loss-retention is a retention floor item of acceptance class host-loss, so it cites "
                     "acceptance:host-loss/retention or is an open gap, and cites record:client-route-high-water")

    def test_a_row_that_excludes_simulation_keeps_its_staging_safety_item_alone(self):
        def staged_only(r):
            r["classes"]["planned-handoff"]["excluded"]["simulation"] = {"reason": "judged in staging only",
                                                                         "owner": "#290"}
            r["items"] = [i for i in r["items"] if i["id"] != "planned-handoff-safety"]
            item(r, "planned-handoff-retention").update(kind="staging")
        report = rd.check(edited(staged_only), CTX)
        self.assertEqual(report["classes"]["planned-handoff"]["excluded"], ["simulation"])
        self.assertIn("planned-handoff-staging-safety", report["floors"]["safety"])

    def test_each_delegated_class_and_each_fleet_volume_loss_row_holds_a_containment_item(self):
        report = rd.check(BASE, CTX)
        self.assertEqual([i for i in report["domains"]["resilience-tests"] if i.endswith("-containment")], CONTAINMENT)
        for name in CONTAINMENT:
            self.assertNotIn(name, [i for held in report["floors"].values() for i in held])
        for cls in ("isolated-volume-loss", "correlated-volume-loss", "host-loss"):
            self.assertEqual(item(RECORD, f"{cls}-safety")["criterion"],
                             "the scenario keeps one owner per shard per tenure and loses no acknowledged invalidation")

    def test_an_applicable_item_holds_no_kind_its_class_excludes(self):
        self.refused(edited(lambda r: item(r, "security-review").update(**{"class": "host-loss"})),
                     "item security-review is an applicable review item of class host-loss, which excludes review")
        self.refused(edited(lambda r: item(r, "fis-pause").update(**{"class": "isolated-live-owner"})),
                     "item fis-pause is an applicable hardware item of class isolated-live-owner")
        waived = {"not_applicable": "the class excludes review", "approver": None}
        report = rd.check(edited(lambda r: item(r, "security-review").update(
            **{"class": "host-loss"}, applicability=waived)), CTX)
        self.assertIn("security-review", report["not_applicable"])

    def test_every_domain_holds_an_item_and_the_item_shape_is_fixed(self):
        self.refused(edited(lambda r: r.update(items=[i for i in r["items"] if i["domain"] != "security"])),
                     "domains ['security'] hold no item")
        self.refused(edited(lambda r: item(r, "support-model").update(domain="support")), "item support-model "
                     "domain")
        self.refused(edited(lambda r: r["items"].append(dict(r["items"][0]))), "item ids are no distinct texts")
        self.refused(edited(lambda r: item(r, "support-model").update(id=" ")), "item ids are no distinct texts")
        self.refused(edited(lambda r: r["floors"].update(safety=" ")), "floors are not")
        self.refused(edited(lambda r: item(r, "alarm-controls").update(kind="canary")),
                     "item alarm-controls kind 'canary' is none of")
        self.refused(edited(lambda r: item(r, "support-model").update(applicability="not applicable: no reason")),
                     "item support-model applicability")
        for invalidators in (["moon"], [" "], ["policy", "policy"], []):
            self.refused(edited(lambda r, v=invalidators: item(r, "support-model").update(invalidators=v)),
                         "item support-model invalidators")
        for owner in ("", " "):
            self.refused(edited(lambda r, o=owner: item(r, "support-model").update(gap_owner=o)),
                         "names no gap owner")
        self.refused(edited(lambda r: item(r, "support-model").update(requirement="R99")), "names no requirement")
        self.refused(edited(lambda r: item(r, "support-model").update(**{"class": "no-class"})),
                     "item support-model names no class row")
        report = rd.check(edited(lambda r: item(r, "vendor-escalation").update(
            applicability={"not_applicable": "the store service has no vendor", "approver": None})), CTX)
        self.assertIn("vendor-escalation", report["domains"]["dependencies"])

    def test_an_item_carries_every_invalidator_label_and_an_age_of_one_day(self):
        labels = ["revision", "manifest", "catalog", "runbook", "format", "incident", "guardrail", "policy"]
        report = rd.check(edited(lambda r: item(r, "support-model").update(invalidators=labels, max_age_days=1)), CTX)
        self.assertEqual(len(report["open"]["evidence-age"]), len(RECORD["items"]) - 1)
        self.assertFalse(any("item support-model " in why for why in report["open"]["evidence-age"]))

    def test_the_report_lists_each_applicable_item_with_no_source_as_a_gap_with_its_owner(self):
        gaps = rd.check(BASE, CTX)["gaps"]
        self.assertEqual(gaps["alarm-controls"], item(RECORD, "alarm-controls")["gap_owner"])
        self.assertEqual(set(gaps), {i["id"] for i in RECORD["items"]
                                     if i["source"] is None and i["applicability"] == "applicable"})
        for name in ("support-model", "wave-halt", "rollback-refusal-retention"):
            self.assertNotIn(name, gaps)
        self.assertIsNone(item(RECORD, "rollback-refusal-retention")["source"])

    def test_only_a_retention_floor_item_may_read_not_applicable(self):
        waived = {"not_applicable": "asserted", "approver": "someone"}
        for name in ("host-loss-safety", "suffix-damage", "wave-halt", "safety-alarm-routing-staging"):
            self.refused(edited(lambda r, name=name: item(r, name).update(applicability=waived)),
                         f"item {name} is a ")
        self.assertIn("census-full-retention", rd.check(BASE, CTX)["floors"]["retention"])

    def test_an_item_names_its_class_requirement_and_typed_fields(self):
        self.refused(edited(lambda r: item(r, "census-full-safety").update(requirement="R7")),
                     "item census-full-safety names R7, but its class census-full evidences R8")
        self.refused(edited(lambda r: item(r, "support-model").update(**{"class": ["x"]})),
                     "item support-model names no class row")
        self.refused(edited(lambda r: item(r, "support-model").update(source=5)),
                     "item support-model source is neither null nor a text")
        self.refused(edited(lambda r: item(r, "vendor-escalation").update(
            applicability={"not_applicable": "no vendor"})), "item vendor-escalation applicability")
        for waiver in ({"not_applicable": " ", "approver": None}, {"not_applicable": "no vendor", "approver": " "}):
            self.refused(edited(lambda r, w=waiver: item(r, "vendor-escalation").update(applicability=w)),
                         "item vendor-escalation applicability")

    def test_the_wave_plan_is_one_az_color_at_a_time_with_a_fixed_authorization(self):
        self.refused(edited(lambda r: r["waves"].update(unit="az")), "waves are not one az-color unit")
        self.refused(edited(lambda r: r["waves"]["authorization"].pop()), "waves are not one az-color unit")
        self.refused(edited(lambda r: r["waves"].update(order=[" "])), "waves are not one az-color unit")
        for order in ([], "ab", ["staging", " "], ["staging", "staging"]):
            self.refused(edited(lambda r, o=order: r["waves"].update(order=o)), "waves are not one az-color unit")
        self.refused(edited(lambda r: r["waves"].update(extra=1)), "waves are not one az-color unit")


class Runbooks(unittest.TestCase):
    refused = Check.refused

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="readiness-runbooks-")
        self.root = Path(self.temp.name).resolve()
        (self.root / RUNBOOK).parent.mkdir(parents=True)
        self.body = b'# Hold on one impaired volume\n\n<a id="rb-hold-device"></a>\n\n## RB hold store\n'
        (self.root / "docs/x.md").write_bytes(self.body)
        (self.root / "docs/runbooks/failover/other.md").write_bytes(self.body)
        (self.root / RUNBOOK).write_bytes(self.body)

    def tearDown(self):
        self.temp.cleanup()

    def pair(self, *entries, alarms=None, record=BASE, pin_alarms=True, index=None):
        """A record and a context over the index `entries` (or the index bytes `index`) and the alarm catalog bytes
        `alarms`, resolving under the temp root, the record pinning the bytes the context holds unless `pin_alarms`
        is false."""
        index = index if index is not None else json.dumps({**rd.INDEX, "entries": list(entries)}).encode()
        files = {"runbooks_sha256": index, **({"alarms_sha256": alarms} if alarms is not None else {})}
        record = copy.deepcopy(record)
        record["pins"].update(runbooks_sha256=sha(index),
                              alarms_sha256=sha(alarms) if alarms is not None and pin_alarms else None)
        return record, state(files=files, root=self.root)

    def check(self, *entries, **pairing):
        return rd.check(*self.pair(*entries, **pairing))

    def refuse(self, message, *entries, **pairing):
        record, ctx = self.pair(*entries, **pairing)
        self.refused(record, message, ctx)

    def test_the_index_is_judged_from_the_bytes_its_pin_covers(self):
        slug = SLUG
        record, ctx = self.pair(entry())
        self.assertEqual(rd.check(record, ctx)["runbooks"], {slug: "DRAFT"})
        ctx["files"]["runbooks_sha256"] = json.dumps({**rd.INDEX, "entries": [entry(**rehearsed(self.body))]}).encode()
        self.refused(record, "pin runbooks_sha256 is not the SHA-256 of docs/runbooks/failover/index.json", ctx)
        for version in ("true", "1.0", "2"):
            self.refuse("the index is not", index=b'{"index": "failover-runbooks", "version": %s, "entries": []}'
                        % version.encode())
        self.refuse("runbook index repeats an object key",
                    index=b'{"index": "failover-runbooks", "version": 1, "version": 1, "entries": []}')

    def test_an_absent_index_reads_empty_and_a_pin_of_an_absent_index_is_refused(self):
        unpinned = edited(lambda r: r["pins"].update(runbooks_sha256=None))
        report = rd.check(unpinned, state(files={"runbooks_sha256": None}))
        self.assertEqual(report["runbooks"], {})
        self.assertEqual(report["open"]["runbooks"][:2], [
            "pin runbooks_sha256 is null, so the record pins no docs/runbooks/failover/index.json",
            "the runbook index holds no entry"])
        self.refused(BASE, "pin runbooks_sha256 names docs/runbooks/failover/index.json, which is absent",
                     state(files={"runbooks_sha256": None}))

    def test_an_absent_alarm_catalog_lists_monitors_open_and_skips_the_cross_check(self):
        report = self.check(entry(alarms=["any-alarm"]))
        self.assertEqual(report["alarm_cross_check"], "skipped: the alarm catalog is absent")
        self.assertIn("the alarm catalog is absent, so the alarm cross-check is skipped", report["open"]["monitors"])
        self.assertEqual(report["runbooks"], {SLUG: "DRAFT"})

    def test_a_paging_slug_with_no_index_entry_is_an_open_runbooks_item(self):
        alarms = alarm_catalog(("hold-device", "page", "RB-missing"),
                               ("hold-recorded", "ticket", SLUG))
        report = self.check(entry(alarms=["hold-recorded"]), alarms=alarms)
        self.assertIn("page alarm hold-device names runbook RB-missing, which has "
                      "no index entry", report["open"]["runbooks"])
        self.assertFalse(any("hold-recorded" in why for why in report["open"]["runbooks"]))
        self.assertEqual(report["alarm_cross_check"], "checked: 2 alarm rows against 1 index entries")

    def test_an_unpinned_alarm_catalog_keeps_the_runbooks_gate_open(self):
        slug = SLUG
        alarms = alarm_catalog(("hold-device", "page", slug))
        verified = entry(alarms=["hold-device"], **rehearsed(self.body))
        self.assertEqual(self.check(verified, alarms=alarms)["open"]["runbooks"], [STANDING])
        self.assertEqual(self.check(verified, alarms=alarms, pin_alarms=False)["open"]["runbooks"], [
            "pin alarms_sha256 is null, so the rows these entries answer are unpinned", STANDING])

    def test_an_entry_naming_an_unknown_alarm_is_refused(self):
        alarms = alarm_catalog(("hold-device", "page", SLUG))
        self.refuse(f"runbook {SLUG} names unknown alarms ['no-such-alarm']",
                    entry(alarms=["no-such-alarm"]), alarms=alarms)

    def test_a_runbook_edited_after_verification_reads_stale_and_exits_clean(self):
        cited = edited(lambda r: item(r, "runbook-coverage").update(source=f"runbook:{SLUG}"))
        record, ctx = self.pair(entry(**rehearsed(self.body)), record=cited)
        self.assertEqual(rd.check(record, ctx)["runbooks"], {SLUG: "VERIFIED"})
        (self.root / RUNBOOK).write_bytes(self.body + b"An edited step.\n")
        report = rd.check(record, ctx)
        self.assertEqual(report["runbooks"], {SLUG: "STALE"})
        self.assertIn(f"runbook {SLUG} is STALE: {RUNBOOK} changed after its verified_sha256 was "
                      "recorded", report["open"]["runbooks"])

    def test_a_lift_with_every_alarm_runbook_verified_is_left_to_the_judge_until_a_runbook_reads_stale(self):
        slug = SLUG
        lifted = edited(lambda r: r["gates"]["runbooks"].update(lifted=True))
        record, ctx = self.pair(entry(alarms=["hold-device"], **rehearsed(self.body)),
                                alarms=alarm_catalog(("hold-device", "page", slug)), record=lifted)
        self.assertNotIn("runbooks", rd.check(record, ctx)["open"])
        unlifted, _ = self.pair(entry(alarms=["hold-device"], **rehearsed(self.body)),
                                alarms=alarm_catalog(("hold-device", "page", slug)))
        self.assertEqual(rd.check(unlifted, ctx)["open"]["runbooks"], [STANDING])
        (self.root / RUNBOOK).write_bytes(self.body + b"An edited step.\n")
        self.refused(record, f"gate runbooks is lifted while runbook {slug} is STALE", ctx)

    def test_an_action_source_changed_after_its_digest_reads_stale(self):
        slug = SLUG
        moved = {**rehearsed(self.body), "actions": [{**ACTION, "sha256": "0" * 64}]}
        report = self.check(entry(**moved))
        self.assertEqual(report["runbooks"], {slug: "STALE"})
        self.assertEqual(report["open"]["runbooks"][0], f"runbook {slug} is STALE: its action source "
                         "scripts/readiness.py changed after its sha256 was recorded")
        limited = {**moved, "status": "VERIFIED WITH LIMITATIONS", "limitations": ["no release"]}
        (self.root / RUNBOOK).write_bytes(self.body + b"An edited step.\n")
        self.assertEqual(self.check(entry(**limited))["open"]["runbooks"], [
            f"runbook {slug} is STALE: {RUNBOOK} changed after its verified_sha256 was recorded; runbook {slug} is "
            "STALE: its action source scripts/readiness.py changed after its sha256 was recorded",
            "the alarm catalog is absent, so no runbook slug is checked", STANDING])
        (self.root / RUNBOOK).write_bytes(self.body)
        self.assertEqual(self.check(entry(**rehearsed(self.body)))["runbooks"], {slug: "VERIFIED"})
        unbound = {**rehearsed(self.body), "actions": [{**ACTION, "sha256": None}]}
        self.refuse(f"runbook {slug} is verified without the sha256 of its action source scripts/readiness.py",
                    entry(**unbound))
        self.refuse("sha256 is neither null nor a SHA-256", entry(actions=[{**ANCHOR, "sha256": "x"}]))

    def test_an_action_source_decodes_as_its_language_reads_it(self):
        self.assertTrue(rd.source_text("a.rs", b"fn a() {}\n"))
        self.assertFalse(rd.source_text("a.rs", b"fn a() {}\n// \xff\n"))
        self.assertFalse(rd.source_text("a.py", b"def a():\n    pass\n# \xff\n"))
        self.assertTrue(rd.source_text("a.py", b"# -*- coding: latin-1 -*-\ndef a():\n    pass\n# \xff\n"))
        self.assertFalse(rd.source_text("a.py", b"# -*- coding: no-such-codec -*-\n"))
        with mock.patch.object(rd, "source_text", return_value=False):
            self.refuse(f"runbook {SLUG} is STALE: its action source scripts/readiness.py does not "
                        "decode as its language reads it", entry())

    def test_a_runbook_or_optional_file_over_the_input_limit_is_refused_before_its_read(self):
        with mock.patch.object(rd, "INPUT_LIMIT", len(self.body)):
            self.assertIn(SLUG, self.check(entry(actions=[]))["runbooks"])
        record, ctx = self.pair(entry())
        stat = Path.stat

        def empty(path, *args, **kwargs):
            """`path`'s status with a size of zero, as a path check reads a file that grows before it is opened."""
            info = stat(path, *args, **kwargs)
            return os.stat_result((*info[:6], 0, *info[7:10]))

        # The limit is judged on the open file: a size the path reported earlier admits no read.
        with mock.patch.object(rd, "INPUT_LIMIT", len(self.body) - 1), mock.patch.object(Path, "stat", empty), \
                mock.patch.object(gate.os, "fdopen", side_effect=AssertionError("the file was read")):
            self.refused(record, f"runbook {SLUG} {self.root / RUNBOOK!r} exceeds {len(self.body) - 1} bytes", ctx)
        with mock.patch.object(rd, "INPUT_LIMIT", 10), \
                mock.patch.object(rd, "PINS", {"runbooks_sha256": rd.PINS["runbooks_sha256"]}), \
                mock.patch.object(gate.os, "fdopen", side_effect=AssertionError("the file was read")), \
                self.assertRaises(rd.Refusal) as caught:
            rd.pinned_files()
        self.assertIn("docs/runbooks/failover/index.json", str(caught.exception))
        self.assertIn("exceeds 10 bytes", str(caught.exception))
        fstat = os.fstat

        def shrunk(descriptor):
            """The open file's status with one byte fewer, as the size reads before the file grows during its read."""
            info = fstat(descriptor)
            return os.stat_result((*info[:6], info.st_size - 1, *info[7:10]))

        with mock.patch.object(gate.os, "fstat", shrunk):
            self.refused(record, f"runbook {SLUG} {self.root / RUNBOOK!r} grew while it was read", ctx)
        with self.assertRaises(rd.Refusal) as caught:
            gate.read_file(self.root / "docs/runbooks/failover/absent.md", "runbook absent", rd.INPUT_LIMIT)
        self.assertIn("is unreadable", str(caught.exception))

    def test_an_action_source_over_the_input_limit_is_refused_before_its_read(self):
        source = ROOT / ANCHOR["path"]
        size, fdopen = source.stat().st_size, os.fdopen
        record, ctx = self.pair(entry())

        def unread(descriptor, *args, **kwargs):
            self.assertFalse(os.path.samestat(os.fstat(descriptor), source.stat()), "the action source was read")
            return fdopen(descriptor, *args, **kwargs)

        with mock.patch.object(rd, "INPUT_LIMIT", size):
            self.assertEqual(rd.check(record, ctx)["runbooks"], {SLUG: "DRAFT"})
        with mock.patch.object(rd, "INPUT_LIMIT", size - 1), mock.patch.object(gate.os, "fdopen", unread):
            self.refused(record, f"runbook {SLUG} action source {source!r} exceeds {size - 1} bytes", ctx)

    def test_an_action_names_its_source_by_its_repository_relative_path(self):
        # Another spelling of the same file resolves on one checkout and names nothing on the next.
        for spelling in (str(ROOT / ANCHOR["path"]), "./" + ANCHOR["path"], "scripts/../" + ANCHOR["path"]):
            self.refuse(f"runbook {SLUG} action {spelling} is not its source's repository-relative path",
                        entry(actions=[{**ANCHOR, "path": spelling, "sha256": None}]))

    def test_an_action_source_rewritten_while_it_is_checked_is_refused(self):
        source, read, resolve, resolved = ROOT / ANCHOR["path"], gate.read_file, mf.resolve, []

        def resolving(action, producer):
            resolved.append(action)
            return resolve(action, producer)

        def rewritten(path, what, limit=None):
            """The file's bytes, with one more line once the anchor has been resolved."""
            return read(path, what, limit) + (b"\n" if resolved and Path(path) == source else b"")

        # The digest and the anchor are judged from one version of the source: bytes that differ after the
        # anchor resolved show that the two were read from different ones.
        with mock.patch.object(mf, "resolve", resolving), mock.patch.object(gate, "read_file", rewritten):
            self.refuse(f"runbook {SLUG} action source {ANCHOR['path']} changed while the check read it", entry())
        self.assertEqual(self.check(entry())["runbooks"], {SLUG: "DRAFT"})

    def test_a_draft_entry_holds_no_action_digest(self):
        for digest in (ACTION["sha256"], "0" * 64):
            self.refuse(f"runbook {SLUG} is DRAFT with the sha256 of its action source {ANCHOR['path']}",
                        entry(actions=[{**ANCHOR, "sha256": digest}]))
        self.refuse(f"runbook {SLUG} is verified without the sha256 of its action source {ANCHOR['path']}",
                    entry(**{**rehearsed(self.body), "actions": [{**ANCHOR, "sha256": None}]}))

    def test_a_limited_entry_keeps_the_runbooks_gate_open_with_its_limitations(self):
        slug = SLUG
        limited = {**rehearsed(self.body), "status": "VERIFIED WITH LIMITATIONS",
                   "limitations": ["the release path is unrehearsed"]}
        lifted = edited(lambda r: r["gates"]["runbooks"].update(lifted=True))
        record, ctx = self.pair(entry(alarms=["hold-device"], **limited),
                                alarms=alarm_catalog(("hold-device", "page", slug)), record=lifted)
        self.refused(record, f"gate runbooks is lifted while runbook {slug} reads VERIFIED WITH LIMITATIONS, so it "
                     "holds the gate until a later rehearsal lets it read VERIFIED: the release path is unrehearsed",
                     ctx)
        unlifted = self.check(entry(alarms=["hold-device"], **limited),
                              alarms=alarm_catalog(("hold-device", "page", slug)))
        self.assertEqual(unlifted["runbooks"], {slug: "VERIFIED WITH LIMITATIONS"})

    def test_an_unresolved_action_anchor_reads_stale_with_the_anchor_named(self):
        anchor = {"path": "scripts/readiness.py", "symbol": "def release_hold", "sha256": None}
        self.refuse(f"runbook {SLUG} is STALE: its action anchor scripts/readiness.py "
                    "'def release_hold' does not resolve", entry(actions=[anchor]))

    def test_an_action_anchor_in_test_code_reads_stale(self):
        anchor = {"path": "scripts/test-readiness.py", "symbol": "def state", "sha256": None}
        self.refuse(f"runbook {SLUG} is STALE: its action anchor scripts/test-readiness.py 'def "
                    "state' does not resolve as production code: producer scripts/test-readiness.py is test code",
                    entry(actions=[anchor]))

    def test_a_rehearsal_names_its_executor_and_author(self):
        for blank in ({"executor": "  "}, {"author": "\t"}):
            self.refuse("rehearsal names no executor and author", entry(**rehearsed(self.body, **blank)))

    def test_a_rehearsal_executed_by_its_author_is_refused(self):
        for executor in ("operator-a", " Operator-A"):
            self.refuse(f"runbook {SLUG} was rehearsed by its author: a rehearsal counts only "
                        "when someone other than the author executes it",
                        entry(**rehearsed(self.body, executor=executor)))

    def test_entries_sharing_a_file_agree_on_verification_and_rehearsal(self):
        one = entry(**rehearsed(self.body))
        two = entry("RB-hold-store", **rehearsed(self.body))
        self.assertEqual(len(self.check(one, two)["runbooks"]), 2)
        self.refuse(f"runbook entries of {RUNBOOK} differ", one, entry("RB-hold-store"))
        other = entry("RB-hold-store", **rehearsed(self.body, record_sha256="e" * 64))
        self.refuse(f"runbook entries of {RUNBOOK} differ", one, other)
        limited = {**rehearsed(self.body), "status": "VERIFIED WITH LIMITATIONS", "limitations": ["no release"]}
        self.refuse(f"runbook entries of {RUNBOOK} differ", entry(**limited),
                    entry("RB-hold-store", **{**limited, "limitations": ["no hold"]}))
        draft = {**rehearsed(self.body), "status": "DRAFT", "actions": [{**ANCHOR, "sha256": None}]}
        self.refuse(f"runbook entries of {RUNBOOK} differ", one, entry("RB-hold-store", **draft))
        for field, value in (("verified_sha256", sha(self.body)), ("verified_revision", "c" * 40),
                             ("rungs", ["tabletop"]), ("paths", ["rb-hold-device"])):
            with self.subTest(field):
                self.assertEqual(len(self.check(entry(**{field: value}))["runbooks"]), 1)
                self.refuse(f"runbook entries of {RUNBOOK} differ", entry(), entry("RB-hold-store", **{field: value}))

    def test_an_entry_takes_each_kind_rung_and_rehearsal_result_the_index_names(self):
        report = self.check(entry(kind="investigation", rungs=["tabletop", "isolated-live", "game-day"]))
        self.assertEqual(report["runbooks"], {SLUG: "DRAFT"})
        for result in ("PARTIAL", "NOT_MET", "INVALID"):
            draft = {**rehearsed(self.body, result=result), "status": "DRAFT", "actions": [{**ANCHOR, "sha256": None}]}
            self.assertEqual(self.check(entry(**draft))["runbooks"], {SLUG: "DRAFT"}, result)

    def test_a_verified_entry_names_a_rehearsed_path_and_each_path_is_an_anchor_of_its_file(self):
        covered = {**rehearsed(self.body), "paths": ["rb-hold-device"]}
        self.assertEqual(self.check(entry(**covered), entry("RB-hold-store", **covered))["runbooks"],
                         {SLUG: "VERIFIED", "RB-hold-store": "VERIFIED"})
        self.refuse(f"runbook {SLUG} reads VERIFIED, but its rehearsal names no path of {RUNBOOK}",
                    entry(**{**rehearsed(self.body), "paths": []}))
        self.refuse(f"runbook {SLUG} paths ['release'] are no anchors of {RUNBOOK}",
                    entry(**{**rehearsed(self.body), "paths": ["rb-hold-device", "release"]}))

    def test_an_entry_shape_outside_the_index_contract_is_refused(self):
        for changes, message in (({"id": f"{RUNBOOK}#rb-hold-device"}, "is no slug"),
                                 ({"id": "RB hold"}, "is no slug"), ({"id": "-RB"}, "is no slug"),
                                 ({"id": ""}, "is no slug"), ({"id": None}, "is no slug"),
                                 ({"file": ""}, "names no file"), ({"file": None}, "names no file"),
                                 ({"file": "docs/x.md"}, "which is no file under docs/runbooks/failover/"),
                                 ({"file": "docs/runbooks/x.md"}, "which is no file under docs/runbooks/failover/"),
                                 ({"file": "docs/runbooks/failover/../../x.md"},
                                  "which is no file under docs/runbooks/failover/ in its own spelling"),
                                 ({"file": "docs/runbooks/failover/absent.md"},
                                  "which is no file under docs/runbooks/failover/ in its own spelling"),
                                 ({"file": "docs/runbooks/failover/../../../.."},
                                  "which is no file under docs/runbooks/failover/ in its own spelling"),
                                 ({"status": "VERIFIED", "actions": [dict(ACTION)]},
                                  "reads VERIFIED without a MET rehearsal"),
                                 ({"status": "DONE"}, "status is none of"),
                                 ({"rungs": ["live"]}, "rungs are no distinct list of"),
                                 ({"rungs": [["tabletop"]]}, "rungs are no distinct list of"),
                                 ({"rungs": ["tabletop", "tabletop"]}, "rungs are no distinct list of"),
                                 ({"rungs": {"tabletop": 1}}, "rungs are no distinct list of"),
                                 ({"limitations": "none"}, "paths and limitations are no lists of text"),
                                 ({"paths": "rb-hold-device"}, "paths and limitations are no lists of text"),
                                 ({"kind": "guide"}, "kind is neither procedure nor investigation"),
                                 ({"actions": {"path": "x"}}, "actions are no ['path', 'sha256', 'symbol'] list"),
                                 ({"actions": {}}, "actions are no ['path', 'sha256', 'symbol'] list"),
                                 ({"actions": [dict(ANCHOR)]}, "actions are no ['path', 'sha256', 'symbol'] list"),
                                 ({"actions": [{**ANCHOR, "sha256": None}, {**ANCHOR, "sha256": None, "note": "x"}]},
                                  "actions are no ['path', 'sha256', 'symbol'] list"),
                                 ({"extra": 1}, "an entry is not"),
                                 ({"limitations": [" "]}, "paths and limitations are no lists of text"),
                                 ({"alarms": "a1"}, "alarms are no list of alarm ids"),
                                 ({"alarms": [" "]}, "alarms are no list of alarm ids"),
                                 ({"paths": [" "]}, "paths and limitations are no lists of text"),
                                 ({"verified_sha256": "f" * 63}, "verified_sha256 is neither null nor a SHA-256"),
                                 ({"verified_revision": "abc"}, "verified_revision is neither null nor a commit")):
            self.refuse(message, entry(**changes))
        self.refuse("a runbook id repeats", entry(), entry())
        for changes, message in (({"rehearsal": ["record_sha256", "executor", "author", "date", "result"]},
                                  "rehearsal is neither null nor"),
                                 ({"actions": [["path", "symbol", "sha256"]]}, "actions are no"),
                                 ({"verified_revision": 5}, "verified_revision is neither null nor a commit")):
            self.refuse(message, entry(**changes))
        self.refuse("malformed runbook index: an entry is not", list(entry()))
        self.refuse("malformed runbook index: the index is not", index=b'["index", "version", "entries"]')
        self.refuse("malformed alarm catalog: it holds no rows list", alarms=b'{"rows": ["a1"]}')
        (self.root / "docs/runbooks/failover/folder").mkdir()
        self.refuse("which is no file under docs/runbooks/failover/ in its own spelling",
                    entry(file="docs/runbooks/failover/folder"))
        self.refuse("it holds no rows list of {id, severity page or ticket",
                    alarms=alarm_catalog(("hold-device", "sev1", SLUG)))
        self.refuse("it holds no rows list", alarms=b"{}")
        self.refuse("malformed alarm catalog: it holds no rows list", alarms=alarm_catalog((" ", "page", SLUG)))
        for slug in (f"{RUNBOOK}#rb-hold-device", "#rb-a", "RB#x", RUNBOOK, "RB hold", " RB", "-RB", "", None):
            self.refuse("malformed alarm catalog: it holds no rows list", alarms=alarm_catalog(("a1", "page", slug)))
        self.refuse("malformed alarm catalog: an alarm id repeats",
                    alarms=alarm_catalog(("a1", "page", "RB-m"),
                                         ("a1", "page", SLUG)))
        self.refuse("alarm catalog repeats an object key", alarms=b'{"rows": [], "rows": []}')
        for index in (b'{"index": "other", "version": 1, "entries": []}',
                      b'{"index": "failover-runbooks", "version": 1, "entries": [], "extra": 1}',
                      b'{"index": "failover-runbooks", "version": 1, "entries": {}}', b'[]'):
            self.refuse("malformed runbook index: the index is not", index=index)

    def test_a_runbook_file_is_named_in_its_own_spelling_inside_the_runbook_directory(self):
        for path in ("docs/runbooks/failover/./hold-device.md", "docs/runbooks/failover//hold-device.md"):
            self.refuse("in its own spelling", entry(file=path))
        (self.root / "docs/runbooks/failover/link.md").symlink_to(self.root / "docs/x.md")
        self.refuse("which is no file under docs/runbooks/failover/ in its own spelling",
                    entry(file="docs/runbooks/failover/link.md"))
        (self.root / "docs/runbooks/failover/loop.md").symlink_to(self.root / "docs/runbooks/failover/loop.md")
        self.refuse("in its own spelling", entry(file="docs/runbooks/failover/loop.md"))
        (self.root / "docs/runbooks/failover/bytes.md").write_bytes(b'<a id="rb-x"></a>\n\xff\n')
        self.refuse("which is no UTF-8 text", entry(file="docs/runbooks/failover/bytes.md"))

    def test_a_pinned_alarm_catalog_lists_its_assumed_and_unstated_bases_under_monitors(self):
        slug = SLUG
        rows = [{"id": "a1", "severity": "ticket", "runbook": slug, "basis": {"condition.value": "assumed"}},
                {"id": "a2", "severity": "page", "runbook": slug, "basis": {"window.reports": "derived"}},
                {"id": "a3", "severity": "page", "runbook": slug},
                {"id": "a4", "severity": "page", "runbook": slug, "basis": None},
                {"id": "a5", "severity": "page", "runbook": slug, "basis": {}},
                {"id": "a6", "severity": "ticket", "runbook": slug,
                 "basis": {"window.reports": "derived", "condition.value": " Assumed"}}]
        report = self.check(entry(alarms=[r["id"] for r in rows]), alarms=json.dumps({"rows": rows}).encode())
        self.assertEqual(report["open"]["monitors"], [
            "alarm rows ['a1', 'a6'] carry basis assumed", "alarm rows ['a3', 'a4', 'a5'] state no basis",
            rd.STANDING["monitors"]])
        for basis in ("assumed", ["assumed"], {"condition.value": 3}, {"condition.value": " "}):
            row = {"id": "a1", "severity": "ticket", "runbook": slug, "basis": basis}
            self.refuse("malformed alarm catalog: a row's basis is neither null nor an object of labels",
                        alarms=json.dumps({"rows": [row]}).encode())

    def test_a_draft_entry_and_an_empty_catalog_keep_the_runbooks_gate_open(self):
        slug = SLUG
        record, ctx = self.pair(entry(alarms=["hold-device"]), alarms=alarm_catalog(("hold-device", "page", slug)))
        self.assertEqual(rd.check(record, ctx)["open"]["runbooks"], [f"runbook {slug} is DRAFT", STANDING])
        record["gates"]["runbooks"]["lifted"] = True
        self.refused(record, "gate runbooks is lifted", ctx)
        empty = self.check(entry(**rehearsed(self.body)), alarms=alarm_catalog())
        self.assertEqual(empty["open"]["runbooks"], ["the alarm catalog holds no row", STANDING])

    def test_every_row_without_an_entry_is_listed_whatever_its_severity(self):
        alarms = alarm_catalog(("p", "page", "RB-p"),
                               ("t", "ticket", "RB-t"))
        report = self.check(entry(**rehearsed(self.body)), alarms=alarms)
        self.assertEqual(report["open"]["runbooks"], [
            "page alarm p names runbook RB-p, which has no index entry",
            "ticket alarm t names runbook RB-t, which has no index entry", STANDING])

    def test_an_entry_and_the_catalog_rows_that_link_it_name_each_other(self):
        slug = SLUG
        alarms = alarm_catalog(("a1", "page", slug), ("a2", "page", "RB-other"))
        self.refuse("names alarms ['a1', 'a2'], but the alarm catalog rows that link it are ['a1']",
                    entry(alarms=["a1", "a2"]), alarms=alarms)
        self.refuse("names alarms [], but the alarm catalog rows that link it are ['a1']", entry(), alarms=alarms)
        unnamed = self.check(entry(kind="investigation"), alarms=alarm_catalog(("a1", "page", "RB-other")))
        self.assertEqual(unnamed["runbooks"], {SLUG: "DRAFT"})
        self.assertEqual(unnamed["alarm_cross_check"], "checked: 1 alarm rows against 1 index entries")

    def test_a_verified_entry_needs_a_met_tabletop_rehearsal_with_its_paths(self):
        for changes, rehearsal, message in (
                ({}, {"result": "NOT_MET"}, "reads VERIFIED without a MET rehearsal"),
                ({}, {"result": "PARTIAL"}, "reads VERIFIED without a MET rehearsal"),
                ({"rehearsal": None}, {}, "reads VERIFIED without a MET rehearsal"),
                ({"rungs": ["isolated-live"]}, {}, "reads VERIFIED without the tabletop rung"),
                ({"paths": []}, {}, f"reads VERIFIED, but its rehearsal names no path of {RUNBOOK}"),
                ({"limitations": ["no release"]}, {}, "reads VERIFIED with limitations"),
                ({"verified_sha256": None}, {}, "reads VERIFIED without a verified digest and revision"),
                ({"verified_revision": None}, {}, "reads VERIFIED without a verified digest and revision"),
                ({"status": "VERIFIED WITH LIMITATIONS"}, {}, "reads VERIFIED WITH LIMITATIONS without limitations"),
                ({"status": "VERIFIED WITH LIMITATIONS", "limitations": ["no release"]}, {"result": "PARTIAL"},
                 "reads VERIFIED WITH LIMITATIONS without a MET rehearsal")):
            self.refuse(f"runbook {SLUG} {message}",
                        entry(**{**rehearsed(self.body, **rehearsal), **changes}))
        limited = {**rehearsed(self.body), "status": "VERIFIED WITH LIMITATIONS",
                   "limitations": ["the release path is unrehearsed"]}
        self.assertEqual(self.check(entry(**limited))["runbooks"],
                         {SLUG: "VERIFIED WITH LIMITATIONS"})
        partial = {**rehearsed(self.body, result="PARTIAL"), "status": "DRAFT", "actions": [{**ANCHOR, "sha256": None}]}
        self.assertEqual(self.check(entry(**partial))["runbooks"], {SLUG: "DRAFT"})
        for rehearsal, message in (({"date": "2099-13-45"}, "rehearsal date is no YYYY-MM-DD calendar date"),
                                   ({"date": "20261121"}, "rehearsal date is no YYYY-MM-DD calendar date"),
                                   ({"result": "PASSED"}, "rehearsal result is none of"),
                                   ({"record_sha256": "d" * 63}, "rehearsal record_sha256 is no SHA-256"),
                                   ({"executor": " "}, "rehearsal names no executor and author handle"),
                                   ({"author": ""}, "rehearsal names no executor and author handle"),
                                   ({"extra": 1}, "rehearsal is neither null nor")):
            self.refuse(message, entry(**rehearsed(self.body, **rehearsal)))

    def test_heading_anchors_follow_the_rendered_slugs(self):
        content = "## Steps\n## Steps\n## Title ##\n```\n# fenced\n```\n## [Link](http://x) text\n## C#\n"
        self.assertEqual(rd.anchors(content), {"steps", "steps-1", "title", "link-text", "c"})
        links = "## [Restore](manual_(ops))\n## [Release](manual_(staging).md) now\n## [Open](x(y) end\n"
        self.assertEqual(rd.anchors(links), {"restore", "release-now", "openxy-end"})
        collisions = "# Foo\n\n# Foo\n\n# Foo-1\n\n# Bar-1\n\n# Bar\n\n# Bar\n\n# Foo\n"
        self.assertEqual(rd.anchors(collisions), {"foo", "foo-1", "foo-1-1", "bar-1", "bar", "bar-2", "foo-2"})
        hidden = ('````\n<a id="in-fence"></a>\n```\n# still fenced\n````\n'
                  '`<a id="in-code">` <!-- <a id="in-note"> -->\n## Real {#custom}\n<a name="live"></a>\n')
        self.assertEqual(rd.anchors(hidden), {"real-custom", "live"})
        self.assertEqual(rd.anchors("##" + " " * 20000 + "Wide   gap" + " " * 20000 + "#\n"), {"wide---gap"})
        comment = ('<!--\n# Hidden\n<a id="hidden"></a>\n```\n-->\n# Shown\n  <!-- note -->\n# After\n'
                   'text <!--\n# Still shown\n')
        self.assertEqual(rd.anchors(comment), {"shown", "after", "still-shown"})
        spans = '```span``` text\n# Visible\n```\n# fenced\n```\n~~~ `info`\n# tilde fenced\n~~~\n# Last\n'
        self.assertEqual(rd.anchors(spans), {"visible", "last"})

    def test_an_anchor_after_a_comment_or_code_span_on_its_line_counts_nothing(self):
        for line, shown in (('<!----> <a id="v"> <!-- <a id="h"> -->', set()),
                            ('--> <!-- <a id="h"> --> <a id="v">', set()),
                            ('text <!--<a id="v">', set()),
                            ('text <!-- note --><a id="v">', set()),
                            ("# Use `code`", {"use-code"}),
                            ('text `<a id="h">` <a id="v">', set()),
                            ('`` open ` <a id="v">', set()),
                            ('` <a id="v"> `` <a id="w">', set()),
                            ('`a` <a id="v"> `b`', set()),
                            ('text ` open\n`<a id="h">` <a id="v">', set()),
                            ('text <a id="v"> `', set()),
                            ('x <!--<a id="v">', set()),
                            ('<!-- <!---> <a id="v"> <!-- note -->', set()),
                            ('`` <a id="h"> ```a`` <a id="v">', set()),
                            ("# Matrix x", {"matrix-x"})):
            self.assertEqual(rd.anchors(line + "\n"), shown, line)
        self.assertIn("out", rd.anchors("## ##\n# Out\n"))

    def test_a_fence_or_comment_block_hides_its_opening_line_and_closes_only_on_its_own_mark(self):
        for content in ("~~~\n# fenced\n```\n# still fenced\n~~~\n# Out\n",
                        "```\n# fenced\n``` info\n# still fenced\n```\n# Out\n",
                        "````\n# fenced\n ```\n# still fenced\n````\n# Out\n",
                        "```\n# fenced\n ```\n# Out\n",
                        '~~~ <a id="in-info">\n# fenced\n~~~\n# Out\n',
                        '<!-- <a id="in-opener">\n# Hidden\n-->\n# Out\n',
                        " ``` `code` text\n# Out\n"):
            self.assertEqual(rd.anchors(content), {"out"}, content)

    def test_an_explicit_anchor_counts_on_a_line_indented_under_four_columns_past_its_markers(self):
        anchor = '<a id="release"></a>'
        # Each line renders as an indented code block, alone or inside the list item or quote its marker opens.
        for code in (f"    {anchor}", f"\t{anchor}", f"  \t{anchor}", f"-     {anchor}", f">     {anchor}",
                     "> " * 40 + f"    {anchor}", f"    printed\u2028{anchor}"):
            self.assertEqual(rd.anchors(f"# Shown\n\n{code}\n"), {"shown"}, code)
        for shown in (f"   {anchor}", f"- {anchor} step", f"-    {anchor} step", f"1. {anchor} step",
                      f"> {anchor} quoted", f">    {anchor}", "> " * 40 + anchor):
            self.assertEqual(rd.anchors(f"# Shown\n\n{shown}\n"), {"shown", "release"}, shown)
        # The rule reads the line alone, so a continuation line and list content indented four columns, which
        # render the anchor, define none; the anchor on the item's marker line counts.
        self.assertEqual(rd.anchors(f"Text.\n    {anchor}\n"), set())
        self.assertEqual(rd.anchors(f"1. Step one.\n\n    {anchor}\n"), set())
        self.assertEqual(rd.anchors(f"# A\r\n{anchor}\r# B\n"), {"a", "release", "b"})

    def test_an_explicit_anchor_counts_only_where_its_whole_open_tag_leads_the_line(self):
        # Nothing earlier on its line can own a tag that leads it. The page shows each tag below as code or as part
        # of a link, an image or another tag, and each follows other content on its line.
        for owned in ('<a href="`"></a> `<a id="y"></a>`', '<a title="<!--"></a> `--> <a id="y"></a>`',
                      '<http://a/`b> `<a id="y"></a>`', "<img alt='<a id=\"y\">'>", '[t](u "`") `<a id="y"></a>`',
                      '[t](<a id="y">)', "[t](u '<a id=\"y\">')", '![<a id="y"></a>](u)', '[foo]: <a id="y">',
                      'see \\` then `use <a id="y"></a> here`', '\\<a id="y"></a>'):
            self.assertEqual(rd.anchors(f"# Shown\n\n{owned}\n"), {"shown"}, owned)
        # The page shows each anchor below. It follows other content on its line, and counts once it leads one.
        for later in ('step <a id="y"></a>', '`c` <a id="y"></a>', '<!-- c --><a id="y"></a>',
                      '\\\\<a id="y"></a>'):
            self.assertEqual(rd.anchors(f"# Shown\n\n{later}\n"), {"shown"}, later)
        self.assertEqual(rd.anchors('<a id="y"></a><a id="x"></a>\n'), {"y"})
        self.assertNotIn("y", rd.anchors('## <a id="y"></a>Title\n'))
        for leading in ('<a id="y"></a> step', '1. <a id="y"></a> Run `fleetctl drain`', '<a\tid="y"></a>',
                        '<a\x0cid="y"></a>', '<a id="y"\t>'):
            self.assertEqual(rd.anchors(f"# Shown\n\n{leading}\n"), {"shown", "y"}, leading)
        self.assertEqual(rd.anchors('<a id="x`y`"></a>\n<a id="id-\u00e9"></a>\n'), {"x`y`", "id-\u00e9"})

    def test_a_comment_closes_on_the_dashes_of_its_own_opener(self):
        anchor = '<a id="release"></a>'
        # `<!-->` and `<!--->` are whole comments and open no block: the line after one stays visible.
        for whole in ("<!-->", "<!--->", "   <!--->"):
            self.assertEqual(rd.anchors(f"{whole}\n{anchor}\n"), {"release"}, whole)
        for opened in ("<!--", "<!---", "<!-- note"):
            self.assertEqual(rd.anchors(f"{opened}\n{anchor}\n-->\n# Shown\n"), {"shown"}, opened)

    def test_a_fence_closes_on_a_run_at_the_start_of_a_line(self):
        # The run at column 0 ends the list item and opens a fence of its own, which holds the tag.
        self.assertEqual(rd.anchors('- ```sh\n  cmd\n```\n<a id="fake"></a>\n```\n'), set())
        # A fence run stands behind at most three spaces, and only spaces and tabs follow a closing one: a run
        # behind a tab, or before a no-break space or a form feed, is a line of the block it stands in.
        anchor = '<a id="release"></a>'
        for inside in ("\t```", "```\u00a0", "```\x0c", "    ```"):
            self.assertEqual(rd.anchors(f"```\n{inside}\n{anchor}\n```\n"), set(), inside)
        self.assertEqual(rd.anchors(f"```\nx\n``` \t\n{anchor}\n"), {"release"})
        self.assertEqual(rd.anchors(f"\t```\n{anchor}\n"), {"release"})

    def test_the_scan_reads_each_line_alone_and_keeps_no_quote_list_or_paragraph_structure(self):
        anchor = '<a id="release"></a>'
        # The page shows each tag below as code or hides it in a comment. The scan counts it: the fence, comment
        # block, code span or comment opens behind a marker or on an earlier line, out of the line's sight.
        for unseen in (f"> ```\n> {anchor}\n> ```\n", f"> <!--\n> {anchor}\n> -->\n",
                       f"A <!-- note\n{anchor}\n-->\n", f"Run `the\n{anchor}\n` step\n"):
            self.assertEqual(rd.anchors(unseen), {"release"}, unseen)
        # The run that closes a fence opened on a marker line opens one in the scan, which hides the heading after.
        self.assertEqual(rd.anchors(f"- ```\n  {anchor}\n  ```\n\n# Steps\n"), {"release"})
        # A fence run behind a tab or four spaces opens a fence inside a list item and none at the top level. The
        # scan reads it as none in both, so it counts the lines of the item's fence that stand under four columns.
        self.assertEqual(rd.anchors(f"- Release the hold:\n\t```sh\n  {anchor}\n  # release the hold\n\t```\n"),
                         {"release", "release-the-hold"})
        self.assertEqual(rd.anchors(f"- Step\n    ```\n  {anchor}\n    ```\n"), {"release"})
        self.assertEqual(rd.anchors(f"- Step\n\n    ```sh\n    {anchor}\n    # comment\n    ```\n"), set())
        # The page closes an item's fence on a run behind a tab or four spaces, and where the item ends. The scan
        # closes it on the next run at the start of a line, and from there reads the fenced block after it as text.
        for closed in ("\t```\n", "    ```\n", "\nAfter the list.\n\n"):
            self.assertEqual(rd.anchors(f"- Step\n  ```\n  cmd\n{closed}```\n{anchor}\n```\n"), {"release"}, closed)
        self.assertEqual(rd.anchors("- Hold:\n  ```\n  fleetctl hold\n\t```\n```\n# drain the host\n```\n"),
                         {"drain-the-host"})
        self.assertEqual(rd.anchors(f"- Step\n  ```\n  cmd\n  ```\n\n```\n{anchor}\n```\n<a id=\"real\"></a>\n"),
                         {"real"})
        # A raw HTML block holds its lines up to the next blank line, or up to its closing tag when `<pre>` opens
        # it. The page shows an ATX line inside it as text and opens no fence on a run inside it. The scan reads the
        # ATX line as a heading and opens a fence on the run, which the next run then closes.
        self.assertEqual(rd.anchors(f"<details>\n```\n</details>\n\n```\n{anchor}\n```\n"), {"release"})
        self.assertEqual(rd.anchors("<pre>\n\n## Release the hold\n</pre>\n"), {"release-the-hold"})
        self.assertEqual(rd.anchors("<details>\n<summary>Release</summary>\n## Release the hold\n</details>\n"),
                         {"release-the-hold"})
        self.assertEqual(rd.anchors('# Steps\n\n<a id="hold"/>\n## Hold the device\n'),
                         {"steps", "hold", "hold-the-device"})
        self.assertEqual(rd.anchors("<details>\n<summary>Release</summary>\n\n## Release the hold\n</details>\n"),
                         {"release-the-hold"})
        # A lone complete tag opens such a block on a line that continues no paragraph: after a heading and on the
        # file's first line, as after a blank line. Continuing a paragraph, it opens none, and both read the heading.
        for led in ("# Steps\n", "", "Text\n"):
            self.assertLessEqual({"hold", "hold-the-device"}, rd.anchors(f'{led}<a id="hold"/>\n## Hold the device\n'))
        # A comment block closes on the line holding `-->`, wherever on the line it stands.
        self.assertEqual(rd.anchors(f"<!--\ntext -->\n{anchor}\n"), {"release"})
        # A quote changes no state of the scan: after a quoted fence, closed or left open, and after an item's
        # fence that opens and closes behind four columns, a top-level fence hides its lines in both.
        for before in ("> ```\n> x\n> ```\n\n", "> ```\n> x\n\n", "- Step\n\n    ```\n    x\n    ```\n\n"):
            self.assertEqual(rd.anchors(f"{before}```\n{anchor}\n```\n"), set(), before)
        # The page slugs a heading's rendered text, and the scan its source text, which keeps a tag, emphasis
        # markers and an entity.
        self.assertEqual(rd.anchors("## <em>Restore</em>\n## _Restore_ now\n## A &amp; B\n"),
                         {"emrestoreem", "_restore_-now", "a-amp-b"})
        # The page shows each anchor below, and the scan reads its line as comment or as a marker's content.
        self.assertEqual(rd.anchors(f"\\<!-- {anchor} -->\n"), set())
        self.assertEqual(rd.anchors("> # Quoted\n- # Listed\n"), set())

    def test_a_tag_counts_only_when_the_rest_of_it_is_a_whole_open_tag(self):
        # The page shows each line below as text: the tag is never closed, or what follows its id is no attribute.
        for broken in ('<a id="x"', '<a id="x"--> text', '<a id="x" =1>', '<a id="x" <b>', '<a `c` id="x"></a>',
                       '<a <!-- c --> id="x"></a>'):
            self.assertEqual(rd.anchors(f"# Shown\n\n{broken}\n"), {"shown"}, broken)
        # A no-break space, a vertical tab and a non-ASCII attribute name stand outside the tag grammar.
        for foreign in ('<a\u00a0id="x"></a>', '<a id="x"\u00a0>', '<a id="x" d\u00e9>', '<a\x0bid="x"></a>'):
            self.assertEqual(rd.anchors(f"# Shown\n\n{foreign}\n"), {"shown"}, foreign)
        # The page's id is `q&x`, so the source's spelling names no anchor.
        self.assertEqual(rd.anchors('# Shown\n\n<a id="q&amp;x"></a>\n'), {"shown"})
        for whole in ('<a id="x" href="#u">link</a>', '<a id="x"/>', '<a id="x" hidden></a>',
                      "<a id=\"x\" title='t' data-n=1 ></a>", '<a  id="x">'):
            self.assertEqual(rd.anchors(f"# Shown\n\n{whole}\n"), {"shown", "x"}, whole)
        self.assertEqual(rd.anchors('<a id="y" ' + "a=1 " * 100000 + ">\n"), {"y"})
        self.assertEqual(rd.anchors('<a id="x"' + " a" * 300000 + "\n"), set())
        self.assertEqual(rd.anchors("> " * 100000 + '    <a id="x"></a>\n'), set())

    def test_heading_anchors_scan_long_unclosed_delimiters_in_linear_time(self):
        line = "text " + "<!--" * 100000 + '<a id="after-comments">' + "`" * 3 + " `` " * 50000 + "\n"
        heading = "# " + "[" * 100000 + "[a](" * 50000 + " Tail\n"
        self.assertEqual(rd.anchors(line + heading + '<a name="end"></a>\n'),
                         {"a" * 50000 + "-tail", "end"})

    def test_a_rehearsal_path_names_an_anchor_the_index_sees_rendered(self):
        (self.root / RUNBOOK).write_bytes(b'<!--\n<a id="rb-hold-device"></a>\n-->\n# Shown\n')
        self.refuse(f"runbook {SLUG} paths ['rb-hold-device'] are no anchors of {RUNBOOK}",
                    entry(paths=["rb-hold-device"]))
        self.assertEqual(self.check(entry(paths=["shown"]))["runbooks"], {SLUG: "DRAFT"})
        (self.root / RUNBOOK).write_bytes(b'# Shown\n\n    <a id="rb-hold-device"></a>\n')
        self.refuse(f"runbook {SLUG} paths ['rb-hold-device'] are no anchors of {RUNBOOK}",
                    entry(paths=["rb-hold-device"]))
        (self.root / RUNBOOK).write_bytes(b'# Shown\n\n   <a id="rb-hold-device"></a>\n')
        self.assertEqual(self.check(entry(paths=["rb-hold-device"]))["runbooks"], {SLUG: "DRAFT"})
        (self.root / RUNBOOK).write_bytes(b'# Shown\n\nStep <a id="rb-hold-device"></a>\n')
        self.refuse(f"runbook {SLUG} paths ['rb-hold-device'] are no anchors of {RUNBOOK}",
                    entry(paths=["rb-hold-device"]))
        (self.root / RUNBOOK).write_bytes(b'# Shown\n\n<a id="rb-hold-device"></a> Step\n')
        self.assertEqual(self.check(entry(paths=["rb-hold-device"]))["runbooks"], {SLUG: "DRAFT"})

    def test_a_rehearsal_path_the_file_lacks_is_refused(self):
        self.refuse(f"runbook {SLUG} paths ['rb-gone'] are no anchors of {RUNBOOK}", entry(paths=["rb-gone"]))
        self.assertEqual(self.check(entry(paths=["rb-hold-store"]))["runbooks"], {SLUG: "DRAFT"})
        (self.root / RUNBOOK).write_bytes(b"# Steps\n\n# Steps\n\n# Steps-1\n")
        self.assertEqual(self.check(entry(paths=["steps-1-1"]))["runbooks"], {SLUG: "DRAFT"})

    def test_one_runbook_file_serves_several_slugs_and_any_slug_form_reads_as_an_id(self):
        alarms = alarm_catalog(("a1", "page", SLUG), ("a2", "ticket", "RB-hold-store"), ("a3", "page", "rb_9"))
        report = self.check(entry(alarms=["a1"]), entry("RB-hold-store", alarms=["a2"]), entry("rb_9", alarms=["a3"]),
                            alarms=alarms)
        self.assertEqual(report["runbooks"], {SLUG: "DRAFT", "RB-hold-store": "DRAFT", "rb_9": "DRAFT"})
        self.assertEqual(report["alarm_cross_check"], "checked: 3 alarm rows against 3 index entries")

    def test_a_runbook_item_of_another_kind_and_a_junk_entry_are_refused(self):
        slug = SLUG
        record = edited(lambda r: item(r, "runbook-coverage").update(source=f"runbook:{slug}", kind="simulation"))
        self.refuse("a runbook item is a rehearsal of an index entry", entry(), record=record)
        self.refuse("malformed runbook index: an entry is not", "junk")

    def test_a_package_names_runbooks_the_index_holds(self):
        record, ctx = self.pair(entry())
        package(ctx["gamedays"], "GD-8")["runbooks"] = [SLUG]
        self.assertIn("GD-8", rd.check(record, ctx)["gamedays"])
        self.assertIn("it names no runbook to walk", rd.check(record, ctx)["gamedays"]["GD-11"]["blocked"])
        package(ctx["gamedays"], "GD-11")["runbooks"] = [SLUG]
        self.assertNotIn("it names no runbook to walk", rd.check(record, ctx)["gamedays"]["GD-11"]["blocked"])

    def test_a_runbook_item_cites_an_index_entry(self):
        slug = SLUG
        record = edited(lambda r: item(r, "runbook-coverage").update(source=f"runbook:{slug}"))
        report = self.check(entry(), record=record)
        self.assertIn("runbook-coverage", report["domains"]["runbooks-and-training"])
        # A source names where the item's grade is read: the DRAFT entry is listed under its gate, and the item,
        # which names a source, is no gap.
        self.assertNotIn("runbook-coverage", report["gaps"])
        self.assertIn(f"runbook {slug} is DRAFT", report["open"]["runbooks"])

    def test_a_delegated_class_holds_a_floor_item_of_a_kind_outside_the_acceptance_record(self):
        rehearsed_safety = {**item(RECORD, "host-loss-safety"), "id": "host-loss-safety-rehearsal",
                            "kind": "rehearsal", "source": f"runbook:{SLUG}"}
        record = edited(lambda r: r["classes"]["host-loss"]["excluded"].pop("rehearsal"),
                        lambda r: r["items"].append(dict(rehearsed_safety)))
        self.assertIn("host-loss-safety-rehearsal", self.check(entry(), record=record)["floors"]["safety"])


def packages(*edits):
    """A context whose game-day catalog is the committed one after `edits`; the rest of the context is shared."""
    ctx = {**CTX, "gamedays": copy.deepcopy(CTX["gamedays"])}
    for edit in edits:
        edit(ctx["gamedays"])
    return ctx


def package(catalog, name):
    return next(e for e in catalog["entries"] if e["id"] == name)


def ready(c):
    """An edit that sets every budget and marks every prerequisite met: each stays listed without its marker."""
    for b in c["budgets"].values():
        b["value"] = 60
    for e in c["entries"]:
        e["prerequisites"] = [p.replace(rd.TBD, "named in the filled package") for p in e["prerequisites"]]


def without_catalog(record):
    """An edit that leaves the record valid with no game-day catalog: a null pin, a drill source of the cell's kind
    cited in place of each package citation, and no item citing a package."""
    record["pins"]["gamedays_sha256"] = None
    for kind in ("staging", "rehearsal"):
        source(f"{kind}-drill", kind)(record)
    for name, row in record["classes"].items():
        for kind, cites in row["evidence"].items():
            row["evidence"][kind] = [f"{kind}-drill:{name}" if c.startswith("gameday:") else c for c in cites]
    for i in record["items"]:
        if (i["source"] or "").startswith("gameday:"):
            i["source"] = None


def unbind(name, budget, graded):
    """An edit that nulls the bound `budget` of each clause of package `name` that grades `graded`."""
    def edit(c):
        for h in package(c, name)["hypothesis"]:
            if h["bound"] == budget and graded in h["items"]:
                h["bound"] = None
    return edit


HOST_STOPPING = ("GD-2", "GD-3", "GD-4", "GD-5", "GD-7", "GD-10", "GD-12", "GD-13")
GUARDS = ("any generation change", "any CreateVolume by the reconciler principal")
BUDGETS = {"planned-handoff-dark-time": "s", "fresh-host-recovery-time": "s", "re-enrollment-drain": "s",
           "origin-load": "requests/s", "alarm-delivery-time": "s"}
NO_STAGING = "has neither a staging citation nor a written staging exclusion"


class Gamedays(unittest.TestCase):
    refused = Check.refused

    def test_the_committed_catalog_holds_gd_1_to_gd_14_each_with_mode_oracle_guardrail_and_restoration(self):
        catalog = CTX["gamedays"]
        self.assertEqual([e["id"] for e in catalog["entries"]], [f"GD-{n}" for n in range(1, 15)])
        self.assertEqual([e["mode"] for e in catalog["entries"]],
                         ["rehearsal", "causal", "causal", "causal", "rehearsal", "causal", "causal", "causal",
                          "causal", "causal", "tabletop", "rehearsal", "rehearsal", "rehearsal"])
        self.assertEqual(rd.HOST_STOPS, HOST_STOPPING)
        for e in catalog["entries"]:
            self.assertTrue(e["oracle"]["reach"] and e["oracle"]["expected"] and e["guardrail"], e["id"])
            self.assertIn(e["restoration"]["class"], rd.RESTORATIONS)
            if e["id"] in HOST_STOPPING:
                self.assertTrue(set(GUARDS) <= set(e["guardrail"]), e["id"])
                self.assertNotEqual(e["restoration"]["class"], "automatic", e["id"])
            self.assertEqual({i for h in e["hypothesis"] for i in h["items"]}, set(e["items"]), e["id"])
        self.assertEqual(package(catalog, "GD-8")["injection"]["profile"], "fis-pause")
        self.assertTrue(rd.filled(catalog.get("run_rule")))
        self.assertEqual({k: b["unit"] for k, b in catalog["budgets"].items()}, BUDGETS)
        self.assertEqual(list(catalog["budgets"]), list(BUDGETS))
        self.assertTrue(all(b["value"] is None for b in catalog["budgets"].values()))
        report = rd.check(BASE, CTX)
        self.assertEqual(report["gamedays"]["GD-11"]["kind"], "rehearsal")
        self.assertEqual(report["gamedays"]["GD-2"]["kind"], "staging")
        self.assertEqual({name: g["mode"] for name, g in report["gamedays"].items()},
                         {e["id"]: e["mode"] for e in catalog["entries"]})
        for e in catalog["entries"]:
            self.assertTrue(any(rd.TBD in p for p in e["prerequisites"]), e["id"])
            self.assertTrue(report["gamedays"][e["id"]]["blocked"], e["id"])
        staged = [i for i in RECORD["items"] if i["id"].endswith("-staging-safety")]
        self.assertEqual({i["floor"] for i in staged}, {"safety"})
        self.assertIn("GD-1 is blocked: budget planned-handoff-dark-time is null", report["open"]["gamedays"])
        self.assertEqual(report["open"]["budgets"], [f"budget {b} is null" for b in BUDGETS])

    def test_each_package_digest_covers_its_entry_its_budgets_and_its_profile_only(self):
        digests = {name: g["digest"] for name, g in rd.check(BASE, CTX)["gamedays"].items()}
        self.assertEqual(len(set(digests.values())), 14)
        catalog, fis = CTX["gamedays"], CTX["fis"]
        gd2 = package(catalog, "GD-2")
        self.assertEqual(digests["GD-2"], mf.canonical({"entry": gd2, "run_rule": catalog["run_rule"], "budgets": {
            b: catalog["budgets"][b] for b in ("origin-load", "re-enrollment-drain")}, "profile": None}))
        pause = fis["profiles"]["fis-pause"]
        self.assertEqual(digests["GD-8"], mf.canonical({
            "entry": package(catalog, "GD-8"), "run_rule": catalog["run_rule"], "budgets": {}, "profile": {
                "row": pause, "eligible_types": fis["eligible_types"][pause["action"]],
                "production_timeout_io_us": fis["production_timeout_io_us"], "bounds": fis["bounds"]}}))

        def changed(ctx):
            return {n for n, g in rd.check(BASE, ctx)["gamedays"].items() if g["digest"] != digests[n]}
        self.assertEqual(changed(packages(lambda c: package(c, "GD-9")["guardrail"].append("a new abort"))), {"GD-9"})
        self.assertEqual(changed(packages(lambda c: c["budgets"]["origin-load"].update(value=50))), {"GD-2", "GD-5"})
        self.assertEqual(changed(packages(lambda c: c.update(run_rule="another rule"))), set(digests))
        for edit in (lambda f: f["profiles"]["fis-pause"].update(duration_seconds=90),
                     lambda f: f["eligible_types"]["aws:ebs:pause-volume-io"].remove("io2"),
                     lambda f: f.update(production_timeout_io_us=1)):
            edited_fis = copy.deepcopy(fis)
            edit(edited_fis)
            self.assertEqual(changed({**CTX, "fis": edited_fis}), {"GD-8"})
        unnamed = copy.deepcopy(fis)
        unnamed["profiles"]["fis-read-latency"]["duration_seconds"] = 90
        self.assertEqual(changed({**CTX, "fis": unnamed}), set())

    def test_every_class_row_names_its_staging_evidence_or_exclusion(self):
        def hardware_instead(r):
            r["classes"]["census-full"]["evidence"].pop("staging")
            r["classes"]["census-full"]["excluded"]["hardware"] = {"reason": "none", "owner": "#290"}
        for label, edit, name in (
                ("cited row uncited", lambda r: r["classes"]["census-full"]["evidence"].pop("staging"), "census-full"),
                ("excluded row unexcluded", lambda r: r["classes"]["successor-death"]["excluded"].pop("staging"),
                 "successor-death"),
                ("delegated row unexcluded", lambda r: r["classes"]["host-loss"]["excluded"].pop("staging"),
                 "host-loss"),
                ("another kind excluded", hardware_instead, "census-full"),
                ("a rehearsal citation alone", lambda r: r["classes"]["unknown-write"]["excluded"].pop("staging"),
                 "unknown-write")):
            with self.subTest(label):
                self.refused(edited(edit), f"class {name} {NO_STAGING}")

    def test_a_package_grades_exactly_the_items_citing_it(self):
        self.refused(BASE, "package GD-9 grades no item", packages(lambda c: package(c, "GD-9").update(items=[])))
        moved = edited(lambda r: item(r, "census-full-staging").update(source="gameday:GD-10"))
        self.refused(moved, "package GD-9 grades ['census-full-staging'], but the items citing it are []")
        self.refused(BASE, "GD-9 hypothesis is no clause list", packages(
            lambda c: package(c, "GD-9")["items"].append("support-model")))

        def extra(r):
            r["items"].append({**item(r, "census-full-staging"), "id": "census-full-staging-again"})
        self.refused(edited(extra), "package GD-9 grades ['census-full-staging'], but the items citing it are "
                     "['census-full-staging', 'census-full-staging-again']")
        self.refused(edited(lambda r: item(r, "census-full-staging").update(source="gameday:GD-99")),
                     "item census-full-staging cites gameday:GD-99, which names no package of the game-day catalog")

    def test_a_package_and_the_classes_it_grades_name_each_other(self):
        self.refused(edited(lambda r: r["classes"]["census-full"]["evidence"].update(staging=["gameday:GD-2"])),
                     "class census-full cites gameday:GD-2, which grades items of ['host-loss-multi-shard'] only")

        def drilled_instead(cls):
            return lambda r: r["classes"][cls]["evidence"].update(staging=["drill:run-1"])
        self.refused(edited(source("drill", "staging"), drilled_instead("census-full")), "class census-full holds "
                     "items GD-9 grades and cites it under no staging cell")
        self.refused(edited(source("drill", "staging"), drilled_instead("reconciler-stop")), "class reconciler-stop "
                     "holds items GD-7 grades and cites it under no staging cell")
        for cls, graded in (("store-outage", "['census-full']"), (None, "['census-full']")):
            self.refused(BASE, f"GD-9 names class {cls}, but its items grade the classes {graded}",
                         packages(lambda c, cls=cls: package(c, "GD-9").update({"class": cls})))
        self.refused(BASE, "GD-14 names class census-full, but its items grade the classes []",
                     packages(lambda c: package(c, "GD-14").update({"class": "census-full"})))

    def test_only_the_gameday_source_cites_a_package_id(self):
        for item_id in ("GD-11", "gd-11"):
            with self.subTest(item_id):
                self.refused(edited(source("drill", "staging"), cite("census-full", "staging", f"drill:{item_id}")),
                             f"class census-full cites drill:{item_id}: only gameday:<GD-n> cites a game-day package")
        self.refused(edited(source("gameday", "staging")), "source gameday names the game-day catalog")
        record = edited(source("drill", "staging"), cite("successor-death", "staging", "drill:run-10"))
        self.assertNotIn("staging", rd.check(record, CTX)["classes"]["successor-death"]["excluded"])

    def test_a_malformed_item_is_refused_before_a_package_reads_it(self):
        self.refused(edited(lambda r: item(r, "census-full-staging").pop("id")), "items are no list of")
        self.refused(edited(lambda r: item(r, "census-full-staging").update({"class": ["census-full"]})),
                     "item census-full-staging names no class row")

    def test_a_tabletop_result_never_grades_a_staging_or_floor_item(self):
        self.assertEqual(BASE["classes"]["unknown-write"]["evidence"], {"rehearsal": ["gameday:GD-11"]})
        tabletop = edited(lambda r: item(r, "census-full-staging").update(source="gameday:GD-11"))
        self.refused(tabletop, "item census-full-staging cites gameday:GD-11: a game-day item is of the evidence kind")
        cited = edited(lambda r: r["classes"]["unknown-write"]["excluded"].pop("staging"),
                       lambda r: r["classes"]["unknown-write"]["evidence"].update(staging=["gameday:GD-11"]))
        self.refused(cited, "class unknown-write cites rehearsal source gameday under staging")
        self.refused(edited(lambda r: r["classes"]["census-full"]["evidence"].update(staging=["gameday:GD-15"])),
                     "class census-full cites gameday:GD-15, which names no package of the game-day catalog")
        staged = edited(lambda r: item(r, "unknown-write-tabletop").update(source="gameday:GD-2"))
        self.refused(staged, "item unknown-write-tabletop cites gameday:GD-2: a game-day item is of the evidence kind")
        self.refused(edited(lambda r: item(r, "unknown-write-tabletop").update(floor="safety")),
                     "GD-11 is a tabletop and grades a floor item")
        second = {**item(RECORD, "unknown-write-tabletop"), "id": "unknown-write-tabletop-safety", "floor": "safety"}

        def graded(c):
            package(c, "GD-11")["items"].append(second["id"])
            package(c, "GD-11")["hypothesis"][0]["items"].append(second["id"])
        self.refused(edited(lambda r: r["items"].append(dict(second))), "GD-11 is a tabletop and grades a floor item",
                     packages(graded))

    def test_a_tabletop_injects_no_fault_and_changes_no_state(self):
        self.refused(BASE, "GD-11 injection is no action with a null profile", packages(
            lambda c: package(c, "GD-11")["injection"].update(profile="fis-pause")))
        for restoration in ("destructive", "persistent-manual"):
            with self.subTest(restoration):
                self.refused(BASE, "GD-11 is a tabletop, which injects no fault", packages(
                    lambda c, r=restoration: package(c, "GD-11")["restoration"].update({"class": r})))
        self.refused(BASE, "GD-11 mode is not tabletop", packages(lambda c: package(c, "GD-11").update(
            mode="rehearsal")))
        self.refused(BASE, "GD-11 binds the budgets [('alarm-delivery-time', 'unknown-write-tabletop')]", packages(
            lambda c: package(c, "GD-11")["hypothesis"][0].update(bound="alarm-delivery-time")))

    def test_a_package_that_stops_or_restarts_hosts_carries_the_volume_guardrails_and_a_manual_restoration(self):
        for name in HOST_STOPPING:
            with self.subTest(name):
                for guard in GUARDS:
                    self.refused(BASE, f"{name} stops or restarts hosts, a partition or an AZ without the abort "
                                 "guardrails", packages(
                                     lambda c, name=name, guard=guard: package(c, name)["guardrail"].remove(guard)))
                self.refused(BASE, f"{name} stops or restarts hosts, which stay down until an operator step",
                             packages(lambda c, name=name: package(c, name)["restoration"].update(
                                 {"class": "automatic"})))
        only = rd.check(BASE, packages(lambda c: package(c, "GD-4").update(guardrail=list(GUARDS))))
        self.assertIn("GD-4", only["gamedays"])

    def test_a_package_off_its_shape_is_refused(self):
        clause = {"clause": "x", "bound": None, "items": ["census-full-staging"]}
        for label, edit, message in (
                ("blank reach", lambda e: e["oracle"].update(reach=""), "names no reach of its intended fault"),
                ("blank expected", lambda e: e["oracle"].update(expected=" "), "and no expected outcome"),
                ("oracle key", lambda e: e["oracle"].update(extra="x"), "and no expected outcome"),
                ("mode type", lambda e: e.update(mode=["causal"]), "GD-9 mode is not causal"),
                ("mode", lambda e: e.update(mode="rehearsal"), "GD-9 mode is not causal"),
                ("foreign item", lambda e: e["hypothesis"][0].update(items=["support-model"]),
                 "hypothesis is no clause list"),
                ("empty items", lambda e: e["hypothesis"][0].update(items=[]), "hypothesis is no clause list"),
                ("blank clause", lambda e: e["hypothesis"][0].update(clause=" "), "hypothesis is no clause list"),
                ("clause key", lambda e: e["hypothesis"][0].pop("bound"), "hypothesis is no clause list"),
                ("unknown bound", lambda e: e["hypothesis"].append({**clause, "bound": "no-budget"}),
                 "hypothesis is no clause list"),
                ("bound type", lambda e: e["hypothesis"].append({**clause, "bound": 3}),
                 "hypothesis is no clause list"),
                ("no clause", lambda e: e.update(hypothesis=[]), "hypothesis is no clause list"),
                ("no guardrail", lambda e: e.update(guardrail=[]), "names no abort guardrail"),
                ("blank guardrail", lambda e: e.update(guardrail=[" "]), "names no abort guardrail"),
                ("one blank guardrail", lambda e: e["guardrail"].append(" "), "names no abort guardrail"),
                ("one blank not_claimed", lambda e: e["not_claimed"].append(" "), "GD-9 claim and not_claimed"),
                ("one blank item", lambda e: e["items"].append(" "), "package GD-9 grades no item"),
                ("injection key", lambda e: e["injection"].update(extra=1), "injection is no action"),
                ("restoration key", lambda e: e["restoration"].update(extra=1), "restoration is no class"),
                ("restoration class", lambda e: e["restoration"].update({"class": "manual"}),
                 "restoration is no class"),
                ("blank steps", lambda e: e["restoration"].update(steps=""), "restoration is no class"),
                ("blank action", lambda e: e["injection"].update(action=""), "injection is no action"),
                ("runbook", lambda e: e.update(runbooks=["RB-missing"]), "names a runbook the index lacks"),
                ("runbooks type", lambda e: e.update(runbooks={}), "names a runbook the index lacks"),
                ("class type", lambda e: e.update({"class": 3}), "GD-9 class is neither null nor a text"),
                ("blank claim", lambda e: e.update(claim=""), "GD-9 claim and not_claimed"),
                ("no not_claimed", lambda e: e.update(not_claimed=[]), "GD-9 claim and not_claimed"),
                ("blank not_claimed", lambda e: e.update(not_claimed=[" "]), "GD-9 claim and not_claimed"),
                ("prerequisites type", lambda e: e.update(prerequisites="none"), "GD-9 prerequisites"),
                ("blank prerequisite", lambda e: e.update(prerequisites=[""]), "GD-9 prerequisites"),
                ("no prerequisite", lambda e: e.update(prerequisites=[]), "GD-9 prerequisites"),
                ("prerequisite deleted", lambda e: e["prerequisites"].pop(), "GD-9 prerequisites"),
                ("prerequisite added", lambda e: e["prerequisites"].append("another"), "GD-9 prerequisites"),
                ("prerequisite repeated", lambda e: e["prerequisites"].__setitem__(1, e["prerequisites"][0]),
                 "GD-9 prerequisites"),
                ("entry key", lambda e: e.pop("runbooks"), "entries are not"),
                ("unknown class", lambda e: e.update({"class": "no-class"}), "GD-9 names class no-class")):
            with self.subTest(label):
                self.refused(BASE, message, packages(lambda c, edit=edit: edit(package(c, "GD-9"))))
        self.refused(BASE, "entries are not", packages(lambda c: c["entries"].reverse()))
        for label, edit, message in (
                ("budgets", lambda c: c.update(budgets=list(c["budgets"])), "budgets are not"),
                ("budget", lambda c: c["budgets"].update({"origin-load": ["unit", "meaning", "value"]}),
                 "budgets are not"),
                ("entries", lambda c: c.update(entries=5), "entries are not"),
                ("entry", lambda c: c["entries"].__setitem__(8, list(c["entries"][8])), "entries are not"),
                ("hypothesis", lambda c: package(c, "GD-9").update(hypothesis=5), "hypothesis is no clause list"),
                ("clause", lambda c: package(c, "GD-9")["hypothesis"].__setitem__(0, ["clause", "bound", "items"]),
                 "hypothesis is no clause list"),
                ("bound", lambda c: package(c, "GD-9")["hypothesis"][0].update(bound=["origin-load"]),
                 "hypothesis is no clause list"),
                ("injection", lambda c: package(c, "GD-9").update(injection=["action", "profile"]),
                 "injection is no action"),
                ("oracle", lambda c: package(c, "GD-9").update(oracle=["reach", "expected"]),
                 "oracle names no reach"),
                ("restoration", lambda c: package(c, "GD-9").update(restoration=["class", "steps"]),
                 "restoration is no class")):
            with self.subTest(label):
                self.refused(BASE, message, packages(edit))

    def test_the_catalog_head_and_budgets_are_fixed(self):
        for label, edit in (("catalog", lambda c: c.update(catalog="gamedays")), ("version", lambda c: c.update(
                version=0)), ("extra key", lambda c: c.update(extra=1)), ("no budgets", lambda c: c.pop("budgets")),
                ("no run rule", lambda c: c.pop("run_rule", None)),
                ("blank run rule", lambda c: c.update(run_rule=" "))):
            with self.subTest(label):
                self.refused(BASE, "the head is not", packages(edit))
        for label, edit in (
                ("negative", lambda c: c["budgets"]["origin-load"].update(value=-1)),
                ("zero", lambda c: c["budgets"]["origin-load"].update(value=0)),
                ("empty", lambda c: c.update(budgets={})), ("pruned", lambda c: c["budgets"].pop("origin-load")),
                ("no unit", lambda c: c["budgets"]["origin-load"].pop("unit")),
                ("unit", lambda c: c["budgets"]["origin-load"].update(unit="s")),
                ("blank meaning", lambda c: c["budgets"]["origin-load"].update(meaning=" ")),
                ("extra", lambda c: c["budgets"].update(extra={"unit": "s", "meaning": "x", "value": None}))):
            with self.subTest(label):
                self.refused(BASE, "budgets are not", packages(edit))

    def test_each_package_keeps_the_budget_bindings_and_the_fault_action_the_ticket_fixes(self):
        self.refused(BASE, "GD-2 binds the budgets [('re-enrollment-drain', 'host-loss-multi-shard-staging')]",
                     packages(unbind("GD-2", "origin-load", "host-loss-multi-shard-staging")))
        self.refused(BASE, "GD-7 binds the budgets [('re-enrollment-drain', 'control-plane-outage-staging')]",
                     packages(unbind("GD-7", "re-enrollment-drain", "reconciler-stop-staging")))
        for profile in ("fis-read-latency", "fis-unknown", None):
            with self.subTest(profile):
                self.refused(BASE, "GD-8 injection is no action with a fault-injection profile of the action "
                             "aws:ebs:pause-volume-io", packages(lambda c, profile=profile: package(
                                 c, "GD-8")["injection"].update(profile=profile)))
        self.refused(BASE, "GD-1 injection is no action with a null profile",
                     packages(lambda c: package(c, "GD-1")["injection"].update(profile="fis-pause")))
        fis = copy.deepcopy(CTX["fis"])
        fis["eligible_types"].pop("aws:ebs:pause-volume-io")
        self.refused(BASE, "GD-8 injection is no action", {**CTX, "fis": fis})

    def test_a_fault_injection_manifest_without_its_maps_is_refused_with_or_without_the_catalog(self):
        absent = {**CTX, "files": {**CTX["files"], "gamedays_sha256": None}, "gamedays": None}
        for fis in ({"profiles": "fis-pause", "eligible_types": {}}, {"profiles": {}}, [],
                    {"profiles": {"fis-pause": None}, "eligible_types": {}},
                    {**CTX["fis"], "profiles": {**CTX["fis"]["profiles"], "fis-unstated": None}}):
            with self.subTest(fis=fis):
                self.refused(BASE, "malformed fault-injection profiles: it holds no profiles map", {**CTX, "fis": fis})
                self.refused(edited(without_catalog), "malformed fault-injection profiles", {**absent, "fis": fis})

    def test_a_floor_item_carries_no_budget_and_a_staging_safety_item_keeps_its_simulation_twin(self):
        self.refused(edited(lambda r: item(r, "planned-handoff-staging").update(floor="retention")),
                     "GD-1 bounds a clause that grades the floor items ['planned-handoff-staging']")
        self.refused(edited(lambda r: item(r, "host-loss-multi-shard-safety").update(floor=None)),
                     "class host-loss-multi-shard holds no simulation safety floor item")
        self.assertIn("host-loss-multi-shard-staging-safety", rd.check(BASE, CTX)["floors"]["safety"])

    def test_a_package_keeps_its_staging_safety_items_and_no_other_on_the_safety_floor(self):
        for name, package_id, held in (("planned-handoff-staging-safety", "GD-1", []),
                                       ("reconciler-stop-staging-safety", "GD-7",
                                        ["control-plane-outage-staging-safety"])):
            with self.subTest(name):
                self.refused(edited(lambda r, name=name: item(r, name).update(floor=None)),
                             f"{package_id} holds the safety floor items {held}, not the items")
        self.refused(edited(lambda r: item(r, "census-full-staging").update(floor="safety")),
                     "GD-9 holds the safety floor items ['census-full-staging'], not the items []")
        on_floor = {i["id"] for i in BASE["items"] if i["floor"] == "safety" and i["kind"] == "staging"}
        self.assertEqual(on_floor, {i for held in rd.GAMEDAY_SAFETY.values() for i in held})

    def test_a_tabletop_item_is_invalidated_by_a_runbook_change(self):
        self.assertIn("runbook", item(BASE, "unknown-write-tabletop")["invalidators"])
        self.refused(edited(lambda r: item(r, "unknown-write-tabletop").update(invalidators=["revision", "catalog"])),
                     "GD-11 is a tabletop of a runbook, and its items ['unknown-write-tabletop'] lack the runbook "
                     "invalidator")

    def test_a_package_item_is_invalidated_by_a_guardrail_and_by_the_manifest_of_its_profile(self):
        for name, package_id, label, owed in (
                ("census-full-staging", "GD-9", "guardrail", ["guardrail"]),
                ("unknown-write-tabletop", "GD-11", "guardrail", ["guardrail"]),
                ("volume-impairment-hold-staging-safety", "GD-8", "manifest", ["guardrail", "manifest"])):
            with self.subTest(name):
                self.assertIn(label, item(BASE, name)["invalidators"])
                self.refused(edited(lambda r, n=name, gone=label: item(r, n)["invalidators"].remove(gone)),
                             f"{package_id} items ['{name}'] lack the invalidators {owed}")

    def test_the_base_context_checks_when_the_committed_catalog_names_a_runbook(self):
        live = copy.deepcopy(LIVE)
        package(live["gamedays"], "GD-11")["runbooks"] = [SLUG]
        with mock.patch.dict(globals(), LIVE=live):
            ctx = state()
        self.assertEqual(rd.check(BASE, ctx)["verdict"], "NOT READY")

    def test_a_catalog_file_that_holds_no_object_is_refused(self):
        for data, parsed in ((b"null", None), (b"[]", [])):
            ctx = {**CTX, "files": {**CTX["files"], "gamedays_sha256": data}, "gamedays": parsed}
            pinned = edited(lambda r, d=data: r["pins"].update(gamedays_sha256=hashlib.sha256(d).hexdigest()))
            self.refused(pinned, "the head is not", ctx)

    def test_set_budgets_and_met_prerequisites_unblock_the_packages(self):
        report = rd.check(BASE, packages(ready))
        self.assertEqual(report["open"]["gamedays"],
                         ["GD-11 is blocked: it names no runbook to walk", rd.STANDING["gamedays"]])
        self.assertEqual(report["gamedays"]["GD-11"]["blocked"], ["it names no runbook to walk"])
        self.assertEqual(report["gamedays"]["GD-2"]["blocked"], [])
        self.refused(edited(lambda r: r["gates"]["gamedays"].update(lifted=True)),
                     "gate gamedays is lifted while GD-11 is blocked: it names no runbook to walk", packages(ready))
        self.assertNotIn("budgets", report["open"])
        self.assertEqual(report["gamedays"]["GD-8"]["blocked"], [])

    def test_a_package_lists_exactly_its_missing_prerequisites_and_its_own_null_budgets(self):
        missing = package(CTX["gamedays"], "GD-2")["prerequisites"][1]

        def mixed(c):
            e = package(c, "GD-2")
            e["prerequisites"] = [p.replace(rd.TBD, "named in the filled package") if p != missing else p
                                  for p in e["prerequisites"]]
            c["budgets"]["origin-load"]["value"] = 50
        report = rd.check(BASE, packages(mixed))
        self.assertEqual(report["gamedays"]["GD-2"]["blocked"], [missing, "budget re-enrollment-drain is null"])
        self.assertEqual(report["open"]["budgets"], [f"budget {b} is null" for b in BUDGETS if b != "origin-load"])

        def met(c):
            for e in c["entries"]:
                e["prerequisites"] = [p.replace(rd.TBD, "named in the filled package") for p in e["prerequisites"]]
        self.assertEqual(rd.check(BASE, packages(met))["gamedays"]["GD-7"]["blocked"],
                         ["budget re-enrollment-drain is null"])

    def test_an_unpinned_catalog_keeps_the_budgets_gate_open(self):
        unpinned = edited(lambda r: r["pins"].update(gamedays_sha256=None))
        report = rd.check(unpinned, packages(ready))
        self.assertEqual(report["open"]["budgets"], ["pin gamedays_sha256 is null, so the record pins no budget "
                                                     "value"])
        self.refused(edited(lambda r: r["pins"].update(gamedays_sha256=None),
                            lambda r: r["gates"]["budgets"].update(lifted=True)), "gate budgets is lifted while",
                     packages(ready))

    def test_an_absent_catalog_lists_no_package_and_keeps_its_gates_open(self):
        ctx = {**CTX, "files": {**CTX["files"], "gamedays_sha256": None}, "gamedays": None}
        self.refused(edited(lambda r: r["pins"].update(gamedays_sha256=None)), "class host-loss-multi-shard cites "
                     "gameday:GD-2, which names no package of the game-day catalog", ctx)
        report = rd.check(edited(without_catalog), ctx)
        self.assertEqual(report["gamedays"], {})
        self.assertEqual(report["open"]["budgets"], ["the game-day catalog verification/readiness/gamedays.json is "
                                                     "absent, so no budget value is set"])
        self.assertEqual(report["open"]["gamedays"], ["pin gamedays_sha256 is null, so the record pins no "
                                                      "verification/readiness/gamedays.json"])
        for name in ("gamedays", "budgets"):
            self.refused(edited(without_catalog, lambda r, n=name: r["gates"][n].update(lifted=True)),
                         f"gate {name} is lifted while", ctx)

    def test_a_citation_of_a_package_needs_the_catalog(self):
        absent = copy.deepcopy(CTX)
        absent["gamedays"] = None
        absent["files"] = {**absent["files"], "gamedays_sha256": None}
        self.refused(edited(lambda r: r["pins"].update(gamedays_sha256=None)), "class host-loss-multi-shard cites "
                     "gameday:GD-2", absent)


REV = "c" * 40


class Fake:
    """Owning judges whose results the test supplies by path, so the readiness judge's own rules are what run."""

    def __init__(self, results):
        self.results, self.seen = results, {}

    def _get(self, key):
        result = self.results[key]
        if isinstance(result, Exception):
            raise result
        return copy.deepcopy(result)

    def acceptance(self, path):
        return self._get(path)

    def lane(self, job, module, evidence, revision):
        return self._get(evidence)

    def hit_gate(self, path):
        return self._get(path)

    def fis(self, profile, files, revision):
        return self._get(files["episode"])

    def gameday(self, path):
        return self._get(path)

    def rerun(self, evidence):
        """The result supplied for `evidence`; MIRROR stands for a directory whose rerun reproduces the GD-2 record the
        results hold, whatever it states."""
        if self.results.get(evidence) is not MIRROR:
            return self._get(evidence)
        stated = self.results["gd-GD-2"]
        return {"record": copy.deepcopy(stated["record"]), "identity": {"seal_sha256": SEAL_PIN}} \
            if "record" in stated else copy.deepcopy(stated)

    def rehearsal(self, path):
        return self._get(path)


def acceptance_receipt(verdict="pass", revision=REV, accepted=True):
    classes = {name: {"verdict": verdict, "columns": {column: {"structural": {"kinds": {
        k: {"verdict": verdict} for k in mf.EVIDENCE}}} for column in rd.acc.COLUMNS}} for name in RECORD_CLASSES}
    return {"receipt": {"classes": classes, "accepted": accepted, "evidence": {"lanes": {"lane": "3" * 64}}},
            "revision": revision, "identity": {"inputs_sha256": "1" * 64, "receipt_sha256": "2" * 64,
                                               "accepted": accepted}}


RECORD_CLASSES = [n for n, c in RECORD["classes"].items() if c["delegated"] == "acceptance"]
LANE_RECORDS = sorted({i["source"][7:] for i in RECORD["items"] if (i["source"] or "").startswith("record:")})


def digest_of(ctx, name):
    """The digest `check` reports for package `name` under `ctx`'s catalog and profiles."""
    return rd.package_digest(package(ctx["gamedays"], name), ctx["gamedays"]["run_rule"], ctx["gamedays"]["budgets"],
                             ctx["fis"])


FIXTURES = tempfile.TemporaryDirectory(prefix="readiness-fixtures-")
(Path(FIXTURES.name) / RUNBOOK).parent.mkdir(parents=True)
(Path(FIXTURES.name) / RUNBOOK).write_bytes(b"# Hold\n")


def budgeted(ctx):
    """`ctx` with every game-day budget set, every prerequisite met and each tabletop naming the fixture runbook, as
    `passing()` records it, so no package is blocked once the index holds that runbook."""
    for b in ctx["gamedays"]["budgets"].values():
        b["value"] = 60
    for e in ctx["gamedays"]["entries"]:
        e["prerequisites"] = [p.replace(rd.TBD, "named in the filled package") for p in e["prerequisites"]]
        if e["mode"] == "tabletop" and not e["runbooks"]:
            e["runbooks"] = [SLUG]
    return ctx


BUDGETED = budgeted(copy.deepcopy(CTX))
# The seal a GD-2 inputs entry pins and its run record carries, and the evidence whose rerun reproduces that record.
SEAL_PIN, MIRROR = "d" * 64, object()


def run_record(name, verdict=None, status="COMPLETED", revision=REV, objectives=None, date="2026-11-20", **fields):
    entry = package(BUDGETED["gamedays"], name)
    causal = entry["mode"] == "causal"
    people = {"executor": "operator-b", "author": "operator-a"} if entry["mode"] == "tabletop" else {}
    return {"record": {"id": name, "mode": entry["mode"], "revision": revision, "run_status": status,
                       "verdict": verdict or ("HELD" if causal else "MET"), "package_sha256": "9" * 64,
                       "catalog_sha256": digest_of(BUDGETED, name), "objectives": objectives, "date": date,
                       **people, **({"seal": {"sha256": SEAL_PIN, "time": 430}} if name == rd.RERUN else {}),
                       **fields},
            "identity": {"record_sha256": "8" * 64, "date": date}}


PAUSE = mf.canonical(LIVE["fis"]["profiles"]["fis-pause"])
FIS_MANIFEST = hashlib.sha256(LIVE["files"]["fis_profiles_sha256"]).hexdigest()
LANE_ENVELOPE = {"version": 1, "section": "hardware"}
EPISODE_ENVELOPE = {"version": 1, "section": "fis"}


def observed(name, ordinal, mark):
    """An event the lane relayed from its case, with `mark` the controller's latest ordinal when it was appended."""
    return {"kind": "observed", "name": name, "ordinal": ordinal, "after": {} if mark is None else {"fis": mark}}


WINDOW = {"start_ordinal": 2, "end_ordinal": 4}
WITNESSED = [observed("timeout", 3, 2), observed("restored", 5, 4)]


def episode(**changes):
    """A judged fault-injection episode of fis-pause that the controller closed HELD with its release proof, its
    fault window, and its bindings to the lane receipt bytes and the pinned profile; the lane receipt observed a
    timeout after the fault-start mark and restored bytes after the fault-end mark."""
    value = {"episode": {"profile": "fis-pause", "episode": "ep-1", "status": "COMPLETED", "verdict": "HELD",
                         "abort": None, "release_proof": True, "hardware_manifest": {"sha256": "e" * 64},
                         "lane_receipt_sha256": "f" * 64, "profile_sha256": PAUSE,
                         "fis_profiles_sha256": FIS_MANIFEST, "effect_window": dict(WINDOW)},
             "lane": True, "revision": REV, "reasons": [], "drift": [], "lane_manifest": "e" * 64,
             "profile_sha256": PAUSE, "fis_profiles_sha256": FIS_MANIFEST, "observed": copy.deepcopy(WITNESSED),
             "identity": {"episode_sha256": "6" * 64, "lane_sha256": "f" * 64}}
    value["episode"].update(changes)
    return value


def passing():
    """A record, context, inputs file and evidence under which every item passes and every gate is lifted except
    gamedays, monitors and runbooks: the simulation items of an own class row with no source read a simulation
    catalog record, the other items with no machine source become reviewer items, their class rows leave review open,
    the not-applicable reasons carry an approver, and no game-day package is blocked: the index holds the fixture
    runbook the tabletop names, as a DRAFT entry whose file lies under the fixture root."""
    record = copy.deepcopy(BASE)
    for i in record["items"]:
        own = record["classes"].get(i["class"], {}).get("delegated") is None
        if i["source"] is None and i["kind"] == "simulation" and own:
            i["source"] = "record:client-route-high-water"
        elif i["source"] is None:
            i.update(kind="review", source="review")
            record["classes"].get(i["class"], {}).get("excluded", {}).pop("review", None)
        if i["applicability"] != "applicable":
            i["applicability"]["approver"] = "risk-authority"
        i["max_age_days"] = 30
    record["authority"] = {"launch": "launch-authority", "risk": "risk-authority"}
    ctx = budgeted(state(acceptance_gates=[], end_blocked=False, replayed=True, preserved=True, **CLEAR))
    with_index(record, ctx, entry(actions=[]))
    ctx["root"] = Path(FIXTURES.name)
    for name in rd.GATES:
        if name not in ("gamedays", "monitors", "runbooks"):
            record["gates"][name]["lifted"] = True
    results = {"acc": acceptance_receipt(), "lane": {"obligations": LANE_RECORDS, "refusals": [], "revision": REV,
                                                     "receipt_sha256": "3" * 64, "judge_sha256": "4" * 64},
               "hit": {"receipt": {"verdict": "pass", "candidate": REV, "pacing": {"verdict": "pass"}, "cells": {}},
                       "identity": {"campaign_sha256": "5" * 64, "receipt_sha256": "a" * 64}},
               "fis": episode(), **{f"gd-{g}": run_record(g) for g in rd.GAMEDAYS}, f"ev-{rd.RERUN}": MIRROR}
    reviews = [{"item": i["id"], "reviewer": "reviewer-a", "revision": REV, "date": "2026-11-20",
                "artifact_sha256": "7" * 64, "grade": "VERIFIED", "reason": "inspected"}
               for i in record["items"] if i["source"] == "review"]
    inputs = {"revision": REV, "date": "2026-11-21", "acceptance": "acc", "hit_gate": "hit",
              "lanes": [{"job": "workspace", "module": None, "evidence": "lane"}],
              "fis": {"fis-pause": {"episode": "fis", "lane": "fis-lane"}},
              "gamedays": [{"id": g, "package_sha256": "9" * 64, "catalog_sha256": digest_of(ctx, g),
                            "record": f"gd-{g}",
                            **({"seal_sha256": SEAL_PIN, "evidence": f"ev-{g}"} if g == rd.RERUN else {})}
                           for g in rd.GAMEDAYS], "reviews": reviews}
    return record, ctx, inputs, results


def with_index(record, ctx, *entries):
    """Put a runbook index of `entries` in `ctx` and pin it in `record`."""
    index = json.dumps({**rd.INDEX, "entries": list(entries)}).encode()
    ctx["files"]["runbooks_sha256"] = index
    record["pins"]["runbooks_sha256"] = hashlib.sha256(index).hexdigest()


def all_lifted(root):
    """`passing()` with every gate lifted: a pinned alarm catalog whose one row links a VERIFIED runbook under
    `root`."""
    record, ctx, inputs, results = passing()
    (root / RUNBOOK).parent.mkdir(parents=True, exist_ok=True)
    body = b'# Hold\n<a id="rb-hold-device"></a>\n<a id="rb-hold-store"></a>\n'
    (root / RUNBOOK).write_bytes(body)
    slug = SLUG
    catalog = json.dumps({"rows": [{"id": "hold-device", "severity": "page", "runbook": slug,
                                    "basis": {"window.reports": "derived"}}]}).encode()
    ctx["files"]["alarms_sha256"] = catalog
    record["pins"]["alarms_sha256"] = hashlib.sha256(catalog).hexdigest()
    with_index(record, ctx, entry(alarms=["hold-device"], **rehearsed(body)))
    ctx["root"] = root
    for name in ("gamedays", "monitors", "runbooks"):
        record["gates"][name]["lifted"] = True
    return record, ctx, inputs, results


def judged(record, ctx, inputs, results):
    return rd.judge(record, inputs, ctx, Fake(results), "a" * 64, "b" * 64)


def unaged(record):
    """Null every item's `max_age_days`, as the committed record holds them, and leave the evidence-age gate open."""
    for i in record["items"]:
        i["max_age_days"] = None
    record["gates"]["evidence-age"]["lifted"] = False


class Judge(unittest.TestCase):
    """The judge over a record whose deferred hardware scope is taken as delivered, so every gate can lift; the check
    cases cover the deferral itself."""

    def setUp(self):
        deferred = mock.patch.dict(rd.DEFERRED, clear=True)
        deferred.start()
        self.addCleanup(deferred.stop)

    def test_no_evidence_grades_every_applicable_item_missing_and_reads_not_ready(self):
        receipt = judged(BASE, CTX, {"revision": REV}, {})
        applicable = [i["id"] for i in BASE["items"] if i["applicability"] == "applicable"]
        self.assertEqual({receipt["items"][n]["grade"] for n in applicable}, {"MISSING"})
        self.assertEqual(receipt["recommended_verdict"], "NOT READY")
        self.assertFalse(receipt["ready"])
        self.assertEqual(list(receipt["gates"]), list(BASE["gates"]))
        self.assertEqual(receipt["contradicted"], {})
        self.assertEqual(receipt["domains"]["dependencies"], [i["id"] for i in BASE["items"]
                                                              if i["domain"] == "dependencies"])

    def test_every_item_passing_with_gates_open_is_not_ready_and_names_them(self):
        receipt = judged(*passing())
        self.assertEqual({i["grade"] for i in receipt["items"].values()}, {"VERIFIED", "NOT APPLICABLE"})
        self.assertEqual(receipt["recommended_verdict"], "READY")
        self.assertFalse(receipt["ready"])
        self.assertIn("gamedays", receipt["gates"])
        self.assertTrue(all(i.get("reviewer_graded") for i in receipt["items"].values()
                            if i["source"] == "review" and i["grade"] == "VERIFIED"))

    def test_a_lifted_gate_whose_items_are_unresolved_is_contradicted(self):
        record, ctx, inputs, results = passing()
        record["gates"]["gamedays"]["lifted"] = True
        results["gd-GD-9"] = run_record("GD-9", verdict="DISPROVEN")
        receipt = judged(record, ctx, inputs, results)
        self.assertEqual(receipt["contradicted"]["gamedays"],
                         "gate gamedays is lifted while its items ['census-full-staging'] are unresolved")
        self.assertEqual(receipt["items"]["census-full-staging"]["grade"], "FAILED")
        self.assertEqual(receipt["classes"]["census-full"]["staging"]["grade"], "FAILED")
        self.assertFalse(receipt["ready"])

    def test_a_lifted_runbooks_gate_with_operator_procedures_ungraded_is_contradicted(self):
        with tempfile.TemporaryDirectory(prefix="readiness-judge-") as temp:
            record, ctx, inputs, results = all_lifted(Path(temp))
            inputs["reviews"] = [r for r in inputs["reviews"] if r["item"] != "operator-procedures"]
            receipt = judged(record, ctx, inputs, results)
        self.assertEqual(receipt["items"]["operator-procedures"]["grade"], "MISSING")
        self.assertEqual(receipt["contradicted"]["runbooks"],
                         "gate runbooks is lifted while its items ['operator-procedures'] are unresolved")
        self.assertFalse(receipt["ready"])

    def test_a_lifted_runbooks_gate_with_a_runbook_item_unresolved_is_contradicted(self):
        with tempfile.TemporaryDirectory(prefix="readiness-judge-") as temp:
            record, ctx, inputs, results = all_lifted(Path(temp))
            item(record, "runbook-coverage").update(kind="rehearsal", source=f"runbook:{SLUG}")
            inputs["reviews"] = [r for r in inputs["reviews"] if r["item"] != "runbook-coverage"]
            inputs["runbooks"], results["rehearsal"] = {SLUG: "rehearsal"}, {"record_sha256": "d" * 64}
            receipt = judged(record, ctx, inputs, results)
            self.assertEqual((receipt["contradicted"], receipt["ready"]), ({}, True))
            receipt = judged(record, ctx, {**inputs, "runbooks": {}}, results)
        self.assertEqual(receipt["items"]["runbook-coverage"]["grade"], "MISSING")
        self.assertEqual(receipt["contradicted"], {
            "runbooks": "gate runbooks is lifted while its items ['runbook-coverage'] are unresolved"})
        self.assertFalse(receipt["ready"])

    def test_a_runbook_edited_after_verification_grades_its_item_stale(self):
        record, ctx, inputs, results = passing()
        with tempfile.TemporaryDirectory(prefix="readiness-judge-") as temp:
            root = Path(temp)
            (root / RUNBOOK).parent.mkdir(parents=True)
            body = b'# Hold\n<a id="rb-hold-device"></a>\n<a id="rb-hold-store"></a>\n'
            (root / RUNBOOK).write_bytes(body)
            slug = SLUG
            (root / "docs/runbooks/failover/other.md").write_bytes(b"# Another procedure\n")
            other = entry("RB-other", file="docs/runbooks/failover/other.md")
            with_index(record, ctx, other, entry(**rehearsed(body)))
            ctx["root"] = root
            item = next(i for i in record["items"] if i["id"] == "runbook-coverage")
            item.update(kind="rehearsal", source=f"runbook:{slug}")
            # The inputs name each rehearsal record by its file, and the judge compares the digest of the bytes it
            # read with the one the index entry records. The entry's digest copied into the inputs names no file.
            unread = rd.Refusal(f"rehearsal record {'d' * 64!r} is unreadable")
            results.update({"rehearsal": {"record_sha256": "d" * 64}, "other": {"record_sha256": "e" * 64},
                            "d" * 64: unread})
            inputs["runbooks"] = {slug: "rehearsal"}
            inputs["reviews"] = [r for r in inputs["reviews"] if r["item"] != "runbook-coverage"]
            verified = judged(record, ctx, inputs, results)["items"]["runbook-coverage"]
            self.assertEqual((verified["grade"], verified["identity"]),
                             ("VERIFIED", {"record_sha256": "d" * 64, "date": "2026-11-21"}))
            for runbooks, grade in (({slug: "other"}, "STALE"), ({}, "MISSING"), ({slug: "d" * 64}, "UNVERIFIED")):
                self.assertEqual(judged(record, ctx, {**inputs, "runbooks": runbooks}, results)["items"][
                    "runbook-coverage"]["grade"], grade, runbooks)
            copied = judged(record, ctx, {**inputs, "runbooks": {slug: "d" * 64}}, results)["items"]["runbook-coverage"]
            self.assertEqual(copied["reason"], f"refused: Refusal: {unread}")
            for runbooks in ({slug + "x": "rehearsal"}, {slug: ""}, {slug: 5}, {slug: None}):
                with self.assertRaises(rd.Refusal, msg=runbooks):
                    judged(record, ctx, {**inputs, "runbooks": runbooks}, results)
            gap = "the release path is unrehearsed"
            partial = {**rehearsed(body), "status": "VERIFIED WITH LIMITATIONS", "limitations": [gap]}
            limited_record, limited = copy.deepcopy(record), copy.deepcopy(ctx)
            with_index(limited_record, limited, entry(**partial))
            item = judged(limited_record, limited, inputs, results)["items"]["runbook-coverage"]
            self.assertEqual((item["grade"], item["reason"]),
                             ("UNVERIFIED", f"runbook {slug} is VERIFIED WITH LIMITATIONS: {gap}"))
            draft_record, draft = copy.deepcopy(record), copy.deepcopy(ctx)
            with_index(draft_record, draft, entry())
            self.assertEqual(judged(draft_record, draft, inputs, results)["items"]["runbook-coverage"]["grade"],
                             "UNVERIFIED")
            for runbooks in ({}, {slug: "d" * 64}):
                item = judged(draft_record, draft, {**inputs, "runbooks": runbooks}, results)["items"][
                    "runbook-coverage"]
                self.assertEqual((item["grade"], item["reason"]), ("UNVERIFIED", f"runbook {slug} is DRAFT"), runbooks)
            unaged(draft_record)
            self.assertEqual(judged(draft_record, draft, inputs, results)["items"]["runbook-coverage"]["grade"],
                             "UNVERIFIED")
            for today, grade in (("2026-12-21", "VERIFIED"), ("2026-12-22", "STALE"), ("2026-11-20", "UNVERIFIED")):
                self.assertEqual(judged(record, ctx, {**inputs, "date": today}, results)["items"]["runbook-coverage"][
                    "grade"], grade, today)
            # A runbook binds by its bytes: the entry's `verified_revision` names the commit the rehearsal ran
            # against, an earlier commit than any that holds the entry, and the judge compares it with no revision.
            earlier_record, earlier = copy.deepcopy(record), copy.deepcopy(ctx)
            with_index(earlier_record, earlier, other, entry(**{**rehearsed(body), "verified_revision": "d" * 40}))
            self.assertEqual(judged(earlier_record, earlier, inputs, results)["items"]["runbook-coverage"]["grade"],
                             "VERIFIED")
            (root / RUNBOOK).write_bytes(body + b"An edited step.\n")
            for runbooks in (inputs["runbooks"], {slug: "d" * 64}):
                self.assertEqual(judged(record, ctx, {**inputs, "runbooks": runbooks}, results)["items"][
                    "runbook-coverage"]["grade"], "STALE", runbooks)

    def test_a_record_of_another_catalog_entry_or_revision_grades_stale(self):
        record, ctx, inputs, results = passing()
        next(g for g in inputs["gamedays"] if g["id"] == "GD-9")["catalog_sha256"] = "0" * 64
        results["gd-GD-10"] = run_record("GD-10", revision="d" * 40)
        receipt = judged(record, ctx, inputs, results)
        self.assertEqual(receipt["items"]["census-full-staging"]["grade"], "STALE")
        self.assertEqual(receipt["items"]["attach-slots-exhausted-staging"]["grade"], "STALE")

    def test_a_failed_injection_with_a_green_service_grades_missing(self):
        record, ctx, inputs, results = passing()
        results["gd-GD-2"] = run_record("GD-2", verdict="HELD", status="FAILED_TO_INJECT")
        results["fis"]["episode"]["status"] = "FAILED_TO_INJECT"
        receipt = judged(record, ctx, inputs, results)
        self.assertEqual(receipt["items"]["host-loss-multi-shard-staging"]["grade"], "MISSING")
        self.assertEqual(receipt["items"]["fis-pause"]["grade"], "MISSING")
        self.assertEqual(receipt["recommended_verdict"], "NOT READY")

    def test_a_tabletop_result_offered_for_a_staging_item_is_refused(self):
        record, ctx, inputs, results = passing()
        results["gd-GD-11"] = run_record("GD-11", verdict="PARTIAL",
                                         objectives={"unknown-write-tabletop": "MET", "census-full-staging": "MET"})
        inputs["gamedays"] = [g for g in inputs["gamedays"] if g["id"] != "GD-9"]
        receipt = judged(record, ctx, inputs, results)
        self.assertEqual(receipt["items"]["census-full-staging"]["grade"], "MISSING")
        self.assertEqual(receipt["items"]["unknown-write-tabletop"]["grade"], "VERIFIED")
        self.assertTrue(receipt["evidence"]["gamedays"]["GD-11"]["refused"][0].startswith(
            "objective census-full-staging names an item GD-11 does not grade"))

    def test_a_partial_rehearsal_grades_each_objective_on_its_own_result(self):
        record, ctx, inputs, results = passing()
        results["gd-GD-12"] = run_record("GD-12", verdict="PARTIAL",
                                         objectives={"deploy-restart-staging": "MET", "wave-halt": "NOT_MET"})
        receipt = judged(record, ctx, inputs, results)
        self.assertEqual(receipt["items"]["deploy-restart-staging"]["grade"], "VERIFIED")
        self.assertEqual(receipt["items"]["wave-halt"]["grade"], "FAILED")

    def exception(self, item, **changes):
        value = {"item": item, "reason": "accepted for one wave", "risk_owner": "service-owner",
                 "approver": "risk-authority", "expiry": "2026-12-31", "compensating_control": "manual watch"}
        value.update(changes)
        return value

    def test_a_floor_item_admits_no_exception(self):
        record, ctx, inputs, results = passing()
        results["gd-GD-12"] = run_record("GD-12", verdict="PARTIAL",
                                         objectives={"deploy-restart-staging": "MET", "wave-halt": "NOT_MET"})
        inputs["exceptions"] = [self.exception("wave-halt")]
        receipt = judged(record, ctx, inputs, results)
        self.assertEqual(receipt["recommended_verdict"], "NOT READY")
        self.assertEqual(receipt["reasons"],
                         ["floor items ['wave-halt', 'deploy-restart-staging-safety'] are unresolved"])
        self.assertEqual(receipt["exceptions"][0]["state"], "rejected: the item is a floor, which no exception covers")

    def test_an_exception_covers_an_item_of_no_floor(self):
        record, ctx, inputs, results = passing()
        record["gates"]["end-contract"]["lifted"] = False
        results["acc"] = acceptance_receipt(verdict="fail")
        results["gd-GD-12"] = run_record("GD-12", verdict="PARTIAL", objectives={
            "deploy-restart-staging": "MET", "deploy-restart-staging-safety": "MET", "wave-halt": "NOT_MET"})
        inputs["reviews"] = [r for r in inputs["reviews"] if r["item"] != "safety-alarm-routing-production"]
        floors = {"activation": "end-contract", "safety": "host-loss-safety", "retention": "host-loss-retention",
                  "wave-halt": "wave-halt", "safety-alarms": "safety-alarm-routing-production"}
        self.assertEqual({item(record, name)["floor"]: name for name in floors.values()}, floors)
        self.assertEqual(list(floors), list(record["floors"]))
        inputs["exceptions"] = [self.exception(name) for name in floors.values()]
        receipt = judged(record, ctx, inputs, results)
        self.assertEqual({name: receipt["items"][name]["grade"] for name in floors.values()}, {
            "end-contract": "MISSING", "host-loss-safety": "FAILED", "host-loss-retention": "FAILED",
            "wave-halt": "FAILED", "safety-alarm-routing-production": "MISSING"})
        self.assertEqual([e["state"] for e in receipt["exceptions"]],
                         ["rejected: the item is a floor, which no exception covers"] * len(floors))
        self.assertEqual(receipt["recommended_verdict"], "NOT READY")
        for name in floors.values():
            self.assertIn(f"'{name}'", receipt["reasons"][0])

    def test_an_incomplete_exception_counts_as_none_and_a_complete_one_reads_ready_with_exceptions(self):
        record, ctx, inputs, results = passing()
        inputs["reviews"] = [r for r in inputs["reviews"] if r["item"] != "support-model"]
        inputs["exceptions"] = [self.exception("support-model", expiry=None)]
        receipt = judged(record, ctx, inputs, results)
        self.assertEqual(receipt["items"]["support-model"]["grade"], "MISSING")
        self.assertEqual(receipt["recommended_verdict"], "NOT READY")
        self.assertEqual(receipt["reasons"],
                         ["items ['support-model'] are unresolved and no accepted exception covers them"])
        self.assertTrue(receipt["exceptions"][0]["state"].startswith("rejected: incomplete"))
        absent = {k: v for k, v in self.exception("support-model").items() if k != "expiry"}
        listed = judged(record, ctx, {**inputs, "exceptions": [absent]}, results)["exceptions"][0]
        self.assertEqual((set(listed), listed["state"]),
                         (set(absent) | {"state"}, "rejected: incomplete, it lacks ['expiry']"))
        inputs["exceptions"] = [self.exception("support-model")]
        receipt = judged(record, ctx, inputs, results)
        self.assertEqual(receipt["recommended_verdict"], "READY WITH EXPLICIT EXCEPTIONS")
        self.assertFalse(receipt["ready"])
        inputs["exceptions"] = [self.exception("support-model", expiry="2026-11-01")]
        self.assertEqual(judged(record, ctx, inputs, results)["recommended_verdict"], "NOT READY")

    def test_lane_receipts_of_another_revision_grade_stale(self):
        record, ctx, inputs, results = passing()
        results["lane"] = {"obligations": [], "refusals": [], "revision": "d" * 40, "receipt_sha256": "3" * 64,
                           "judge_sha256": None}
        receipt = judged(record, ctx, inputs, results)
        self.assertEqual({receipt["items"][i]["grade"] for i in ("route-monotonic", "deposition-withdraws")}, {"STALE"})
        self.assertEqual(receipt["items"]["route-monotonic"]["identity"], {
            "job": "workspace", "module": None, "receipt_sha256": "3" * 64, "judge_sha256": None})
        self.assertEqual(receipt["evidence"]["lanes"]['["workspace", null]']["receipt_sha256"], "3" * 64)

    def test_an_unaccepted_acceptance_receipt_reads_its_verdict_and_keeps_the_acceptance_gate_open(self):
        record, ctx, inputs, results = passing()
        results["acc"] = acceptance_receipt(verdict="fail", accepted=False)
        record["gates"]["acceptance"]["lifted"] = False
        receipt = judged(record, ctx, inputs, results)
        self.assertEqual(receipt["items"]["host-loss-safety"]["grade"], "FAILED")
        self.assertEqual(receipt["classes"]["host-loss"]["simulation"]["grade"], "FAILED")
        self.assertIn("acceptance", receipt["gates"])
        stale = acceptance_receipt(revision="d" * 40)
        aged = judged(record, ctx, {**inputs, "acceptance": "stale"}, {**results, "stale": stale})
        self.assertEqual((aged["items"]["host-loss-safety"]["grade"], aged["items"]["host-loss-safety"]["identity"]),
                         ("STALE", stale["identity"]))

    def test_a_null_launch_authority_reads_not_ready_and_names_the_authority_gate(self):
        record, ctx, inputs, results = passing()
        record["authority"]["launch"] = None
        record["gates"]["authority"]["lifted"] = False
        receipt = judged(record, ctx, inputs, results)
        self.assertEqual(receipt["recommended_verdict"], "NOT READY")
        self.assertIn("the authority gate is open: role launch is null", receipt["reasons"])
        self.assertIn("authority", receipt["gates"])
        record["authority"].update(launch="launch-authority", risk=None)
        receipt = judged(record, ctx, inputs, results)
        self.assertEqual((receipt["recommended_verdict"], receipt["reasons"]),
                         ("NOT READY", ["the authority gate is open: role risk is null"]))

    def test_evidence_older_than_its_age_grades_stale(self):
        record, ctx, inputs, results = passing()
        receipt = judged(record, ctx, {**inputs, "date": "2027-06-01"}, results)
        self.assertEqual(receipt["items"]["support-model"]["grade"], "STALE")
        self.assertEqual(receipt["items"]["census-full-staging"]["grade"], "STALE")
        aged = receipt["items"]["support-model"]
        self.assertEqual((aged["reviewer_graded"], aged["identity"]["reviewer"]), (True, "reviewer-a"))
        self.assertEqual(aged["reason"], "the evidence of 2026-11-20 is older than 30 days")
        self.assertIsNone(receipt["valid_until"])

    def test_with_every_age_null_dated_evidence_binds_by_revision_and_digest_alone(self):
        record, ctx, inputs, results = passing()
        unaged(record)
        for today in ("2026-11-21", "2036-01-01", "2026-01-01", None):
            receipt = judged(record, ctx, {**inputs, "date": today}, results)
            self.assertEqual({i["grade"] for i in receipt["items"].values()}, {"VERIFIED", "NOT APPLICABLE"}, today)
            self.assertIsNone(receipt["valid_until"], today)
            self.assertEqual(receipt["recommended_verdict"], "READY")
            self.assertIn("evidence-age", receipt["gates"])

    def test_the_receipt_names_every_input_and_reads_as_a_recommendation(self):
        record, ctx, inputs, results = passing()
        receipt = judged(record, ctx, inputs, results)
        self.assertEqual((receipt["record_sha256"], receipt["inputs_sha256"]), ("a" * 64, "b" * 64))
        self.assertEqual((receipt["judge_sha256"], receipt["pins"]), (rd.JUDGE_SHA256, record["pins"]))
        self.assertEqual((receipt["envelope"], receipt["revision"], receipt["date"]),
                         ({"version": 1, "section": "readiness"}, REV, "2026-11-21"))
        owning = ("acceptance.py", "verify-receipts.py", "hit-gate.py", "hardware-lane.py", "recovery-packages.py",
                  "measurement-frame.py", "sizing-worksheet.py", "reproduce-test.py", "select-tests.py",
                  "gameday-judge.py")
        self.assertEqual(receipt["owning_judges_sha256"],
                         {name: sha((ROOT / "scripts" / name).read_bytes()) for name in owning})

        def scripts_of(module, seen):
            """The repository scripts `module` holds as loaded modules, followed through each of them."""
            for value in vars(module).values():
                file = getattr(value, "__file__", None) if isinstance(value, types.ModuleType) else None
                if file and Path(file).parent == ROOT / "scripts" and Path(file).name not in seen:
                    seen.add(Path(file).name)
                    scripts_of(value, seen)
            return seen

        # Every script the judge loads into its own process is named: the game-day judge, those the acceptance judge
        # loads and those the hardware lane loads, whose code decides a fault-injection grade.
        loaded = scripts_of(rd, set()) | scripts_of(gate.lane_module(), set())
        self.assertLessEqual({"sizing-worksheet.py", "reproduce-test.py", "select-tests.py", "gameday-judge.py"},
                             loaded)
        self.assertLessEqual(loaded, set(receipt["owning_judges_sha256"]))
        self.assertEqual(receipt["items"]["support-model"]["identity"],
                         {"reviewer": "reviewer-a", "date": "2026-11-20", "artifact_sha256": "7" * 64,
                          "revision": REV})
        self.assertEqual(receipt["owning_judges_sha256"]["hardware-lane.py"], hashlib.sha256(
            (ROOT / "scripts/hardware-lane.py").read_bytes()).hexdigest())
        evidence = receipt["evidence"]
        self.assertEqual(evidence["hit_gate"], {"campaign_sha256": "5" * 64, "receipt_sha256": "a" * 64})
        self.assertEqual(evidence["gamedays"]["GD-1"]["identity"]["record_sha256"], "8" * 64)
        self.assertEqual(evidence["lanes"], {'["workspace", null]': {"receipt_sha256": "3" * 64,
                                                                     "judge_sha256": "4" * 64, "revision": REV}})
        self.assertEqual(evidence["fis"]["fis-pause"], {"episode_sha256": "6" * 64, "lane_sha256": "f" * 64})
        self.assertEqual(evidence["acceptance"], {"inputs_sha256": "1" * 64, "receipt_sha256": "2" * 64,
                                                  "accepted": True, "evidence": {"lanes": {"lane": "3" * 64}}})
        self.assertEqual(receipt["exception_register_sha256"], mf.canonical([]))
        self.assertIn("a named human authorizes each wave", receipt["authorization"])

    def test_a_refused_input_names_the_digest_of_the_bytes_it_refused(self):
        with tempfile.TemporaryDirectory(prefix="readiness-judge-") as temp:
            judges = rd.Judges(LIVE, gate.lane_module())
            paths, digests = [], []
            for name, data in (("a.json", b"[]"), ("b.json", b"null")):
                path = Path(temp) / name
                path.write_bytes(data)
                paths.append(str(path))
                digests.append(hashlib.sha256(data).hexdigest())
            record, ctx, inputs, results = passing()
            receipts = []
            for path in (*paths, str(Path(temp) / "absent.json")):
                inputs["gamedays"][8]["record"] = path
                receipts.append(rd.judge(record, inputs, ctx, judges, "a" * 64, "b" * 64))
            grades = [r["items"]["census-full-staging"]["grade"] for r in receipts]
            self.assertEqual(grades, ["UNVERIFIED"] * 3)
            reads = [r["evidence"]["gamedays"]["GD-9"]["identity"]["read"] for r in receipts]
            self.assertEqual(reads, [{paths[0]: digests[0]}, {paths[1]: digests[1]}, {}])
            self.assertEqual(receipts[0]["items"]["census-full-staging"]["identity"], {"read": {paths[0]: digests[0]}})

    def test_all_gates_lifted_and_every_item_passing_reads_ready(self):
        with tempfile.TemporaryDirectory(prefix="readiness-judge-") as temp:
            record, ctx, inputs, results = all_lifted(Path(temp))
            receipt = judged(record, ctx, inputs, results)
            self.assertEqual((receipt["recommended_verdict"], receipt["ready"], receipt["gates"],
                              receipt["contradicted"]), ("READY", True, {}, {}))
            self.assertEqual(receipt["domains"], {d: [] for d in rd.DOMAINS})
            record["gates"]["budgets"]["lifted"] = False
            receipt = judged(record, ctx, inputs, results)
            self.assertEqual((receipt["ready"], list(receipt["gates"])), (False, ["budgets"]))
            record["gates"]["budgets"]["lifted"] = True
            results["gd-GD-9"] = run_record("GD-9", verdict="DISPROVEN")
            receipt = judged(record, ctx, inputs, results)
            self.assertIn("gamedays", receipt["contradicted"])
            self.assertEqual(receipt["items"]["census-full-staging"]["grade"], "FAILED")

    def test_each_evidence_verdict_maps_to_its_grade(self):
        def gd(name, **changes):
            def edit(record, ctx, inputs, results):
                results[f"gd-{name}"] = run_record(name, **changes)
            return edit

        def at(key, path, value):
            def edit(record, ctx, inputs, results):
                target = results[key]
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = value
            return edit

        def review(grade):
            def edit(record, ctx, inputs, results):
                next(r for r in inputs["reviews"] if r["item"] == "support-model")["grade"] = grade
            return edit

        def unapproved(record, ctx, inputs, results):
            waived = next(i for i in record["items"] if i["id"] == "rollback-refusal-retention")
            waived["applicability"]["approver"] = None
            record["gates"]["authority"]["lifted"] = False

        def edits(*each):
            def edit(*args):
                for one in each:
                    one(*args)
            return edit

        def hit(**fields):
            return at("hit", ("receipt",), {"candidate": REV, "cells": {}, "pacing": {"verdict": "pass"}, **fields})

        handoff = {"verdict": "handoff", "handoff": {"obligation": "#123", "reason": "preservation is unqualified"}}
        episode_at = functools.partial(at, "fis")
        gd12 = {"deploy-restart-staging": "INVALID", "wave-halt": "MET"}
        safety = ("receipt", "classes", "host-loss", "columns", "safety", "structural", "kinds")

        def uncited(record, ctx, inputs, results):
            target = results["acc"]
            for part in safety:
                target = target[part]
            target.pop("simulation")

        rows = [(gd("GD-9", verdict="INVALID"), "census-full-staging", "MISSING"),
                (gd("GD-9", verdict="INCONCLUSIVE"), "census-full-staging", "UNVERIFIED"),
                (gd("GD-9", status="HALTED"), "census-full-staging", "UNVERIFIED"),
                (gd("GD-12", verdict="PARTIAL", objectives={}), "wave-halt", "UNVERIFIED"),
                (gd("GD-11", verdict="NOT_MET"), "unknown-write-tabletop", "FAILED"),
                (at("hit", ("receipt", "verdict"), "handoff"), "hit-latency", "FAILED"),
                (at("hit", ("receipt", "verdict"), "inconclusive"), "hit-latency", "UNVERIFIED"),
                (at("hit", ("receipt", "candidate"), "d" * 40), "hit-latency", "STALE"),
                (at("fis", ("reasons",), ["role owner has 0 receipts"]), "fis-pause", "UNVERIFIED"),
                (at("fis", ("revision",), "d" * 40), "fis-pause", "STALE"),
                (at("fis", ("episode", "verdict"), "DISPROVEN"), "fis-pause", "FAILED"),
                (at("fis", ("episode", "status"), "NOT_STARTED"), "fis-pause", "UNVERIFIED"),
                (at("acc", ("receipt", "classes", "host-loss", "columns", "safety", "structural", "reasons"),
                    ["preservation is unqualified"]), "host-loss-safety", "UNVERIFIED"),
                (review("FAILED"), "support-model", "FAILED"),
                (review("UNVERIFIED"), "support-model", "UNVERIFIED"),
                (unapproved, "rollback-refusal-retention", "MISSING"),
                (gd("GD-9", verdict="INVALID", status="HALTED"), "census-full-staging", "MISSING"),
                (gd("GD-9", status="FAILED_TO_INJECT", revision="d" * 40), "census-full-staging", "STALE"),
                (gd("GD-9", revision=None), "census-full-staging", "UNVERIFIED"),
                (gd("GD-9", catalog_sha256="0" * 64), "census-full-staging", "STALE"),
                (gd("GD-9", package_sha256="0" * 64), "census-full-staging", "UNVERIFIED"),
                (gd("GD-9", mode="rehearsal"), "census-full-staging", "MISSING"),
                (gd("GD-12", objectives={"wave-halt": "NOT_MET"}), "wave-halt", "FAILED"),
                (gd("GD-12", objectives={"wave-halt": "NOT_MET"}), "deploy-restart-staging", "VERIFIED"),
                (gd("GD-12", objectives={"wave-halt": "MET"}), "wave-halt", "VERIFIED"),
                (gd("GD-12", objectives={"wave-halt": "maybe"}), "wave-halt", "UNVERIFIED"),
                (gd("GD-12", verdict="PARTIAL", objectives=gd12), "deploy-restart-staging", "MISSING"),
                (gd("GD-12", verdict="PARTIAL", objectives=gd12), "wave-halt", "VERIFIED"),
                (gd("GD-11", executor="Operator-A ", author="operator-a"), "unknown-write-tabletop", "UNVERIFIED"),
                (gd("GD-11", executor=None), "unknown-write-tabletop", "UNVERIFIED"),
                (edits(episode_at(("revision",), "d" * 40), episode_at(("reasons",), [
                    "role owner ran at revision d, not c"])), "fis-pause", "STALE"),
                (episode_at(("drift",), ["the episode ran 'aws:ebs:volume-io-latency'"]), "fis-pause", "STALE"),
                (edits(episode_at(("episode", "status"), "HALTED"), episode_at(("episode", "verdict"), "INVALID")),
                 "fis-pause", "MISSING"),
                (edits(episode_at(("episode", "verdict"), "DISPROVEN"), episode_at(("reasons",), [
                    "role owner is uncredited"])), "fis-pause", "FAILED"),
                (edits(episode_at(("episode", "status"), "HALTED"), episode_at(("episode", "abort"), "stopped")),
                 "fis-pause", "VERIFIED"),
                (episode_at(("episode", "status"), "HALTED"), "fis-pause", "UNVERIFIED"),
                (episode_at(("episode", "release_proof"), False), "fis-pause", "UNVERIFIED"),
                (episode_at(("episode", "quarantine"), "marker stays"), "fis-pause", "UNVERIFIED"),
                (episode_at(("episode", "hardware_manifest"), {"sha256": "0" * 64}), "fis-pause", "UNVERIFIED"),
                (hit(**handoff), "hit-latency", "UNVERIFIED"),
                (hit(**handoff), "suffix-damage", "FAILED"),
                (hit(**{**handoff, "pacing": {"verdict": "handoff"}}), "hit-latency", "FAILED"),
                (hit(**{**handoff, "cells": {"request-weighted/idle/0": {"verdict": "fail"}}}), "hit-latency",
                 "FAILED"),
                (hit(**{**handoff, "cells": {"request-weighted/publish/50": {"verdict": "fail"}}}), "hit-latency",
                 "UNVERIFIED"),
                (hit(**{**handoff, "candidate": "d" * 40}), "suffix-damage", "VERIFIED"),
                (gd("GD-9", verdict="DISPROVEN", status="HALTED"), "census-full-staging", "FAILED"),
                (gd("GD-12", status="HALTED", objectives={"wave-halt": "NOT_MET"}), "wave-halt", "FAILED"),
                (gd("GD-12", status="HALTED", objectives={"wave-halt": "NOT_MET"}), "deploy-restart-staging",
                 "UNVERIFIED"),
                (gd("GD-11", verdict="NOT_MET", executor="operator-a"), "unknown-write-tabletop", "FAILED"),
                (gd("GD-11", author=None), "unknown-write-tabletop", "UNVERIFIED"),
                (gd("GD-12", objectives={"wave-halt": None}), "wave-halt", "UNVERIFIED"),
                (gd("GD-12", objectives=["wave-halt"]), "wave-halt", "UNVERIFIED"),
                (gd("GD-12", objectives={"deploy-restart-staging": "MET"}), "wave-halt", "VERIFIED"),
                (gd("GD-9", id="GD-10"), "census-full-staging", "MISSING"),
                (episode_at(("episode", "lane_receipt_sha256"), None), "fis-pause", "UNVERIFIED"),
                (episode_at(("episode", "lane_receipt_sha256"), "0" * 64), "fis-pause", "UNVERIFIED"),
                (episode_at(("episode", "profile_sha256"), None), "fis-pause", "UNVERIFIED"),
                (episode_at(("episode", "fis_profiles_sha256"), None), "fis-pause", "UNVERIFIED"),
                (episode_at(("episode", "custody_unknown"), "the lane was killed"), "fis-pause", "UNVERIFIED"),
                (episode_at(("episode", "fault_end_unconfirmed"), True), "fis-pause", "UNVERIFIED"),
                (edits(episode_at(("episode", "status"), "HALTED"), episode_at(("episode", "abort"), "issued")),
                 "fis-pause", "UNVERIFIED"),
                (edits(episode_at(("episode", "status"), "FAILED_TO_INJECT"), episode_at(("revision",), "d" * 40)),
                 "fis-pause", "STALE"),
                (edits(episode_at(("episode", "verdict"), "DISPROVEN"), episode_at(("drift",), ["moved"])),
                 "fis-pause", "STALE"),
                (edits(episode_at(("episode", "status"), "HALTED"), episode_at(("episode", "verdict"), "DISPROVEN")),
                 "fis-pause", "FAILED"),
                (hit(candidate=None), "hit-latency", "UNVERIFIED"),
                (hit(candidate=None, **handoff), "suffix-damage", "VERIFIED"),
                (at("hit", ("receipt", "verdict"), "inconclusive"), "real-path", "UNVERIFIED"),
                (at("hit", ("receipt", "verdict"), "fail"), "real-path", "FAILED"),
                (gd("GD-9", verdict="MET"), "census-full-staging", "UNVERIFIED"),
                (gd("GD-9", verdict="PASSED"), "census-full-staging", "UNVERIFIED"),
                (gd("GD-9", verdict="MET", objectives={"census-full-staging": "MET"}), "census-full-staging",
                 "UNVERIFIED"),
                (gd("GD-9", verdict="PARTIAL", objectives={"census-full-staging": "MET"}), "census-full-staging",
                 "UNVERIFIED"),
                (gd("GD-12", verdict="HELD"), "wave-halt", "UNVERIFIED"),
                (gd("GD-12", verdict="PARTIAL"), "wave-halt", "UNVERIFIED"),
                (gd("GD-12", verdict="NOT_MET", objectives={"wave-halt": "MET"}), "wave-halt", "FAILED"),
                (gd("GD-12", verdict="INCONCLUSIVE", objectives={"wave-halt": "MET"}), "wave-halt", "UNVERIFIED"),
                (gd("GD-12", status="FAILED_TO_INJECT"), "wave-halt", "MISSING"),
                (gd("GD-11", status="FAILED_TO_INJECT"), "unknown-write-tabletop", "MISSING"),
                (gd("GD-9", verdict="DISPROVEN", revision="d" * 40), "census-full-staging", "STALE"),
                (gd("GD-11", verdict="NOT_MET", revision="d" * 40), "unknown-write-tabletop", "STALE"),
                (gd("GD-9", verdict="DISPROVEN", catalog_sha256="0" * 64), "census-full-staging", "STALE"),
                (gd("GD-9", revision="not-a-commit"), "census-full-staging", "UNVERIFIED"),
                (episode_at(("episode", "hardware_manifest"), None), "fis-pause", "UNVERIFIED"),
                (episode_at(("episode", "verdict"), "PASSED"), "fis-pause", "UNVERIFIED"),
                (episode_at(("episode", "verdict"), "MET"), "fis-pause", "UNVERIFIED"),
                (uncited, "host-loss-safety", "MISSING"),
                (at("acc", (*safety, "simulation"), {}), "host-loss-safety", "MISSING"),
                (at("acc", (*safety, "simulation", "verdict"), "inconclusive"), "host-loss-safety", "UNVERIFIED"),
                (at("acc", (*safety, "simulation", "verdict"), "credited"), "host-loss-safety", "UNVERIFIED"),
                (at("hit", ("receipt",), {"candidate": REV, "cells": {}, "verdict": "pass"}), "hit-latency",
                 "VERIFIED"),
                (hit(verdict="fail", handoff=handoff["handoff"]), "hit-latency", "FAILED"),
                (hit(verdict="credited"), "hit-latency", "UNVERIFIED"),
                (hit(**handoff), "end-contract", "VERIFIED"),
                (hit(**handoff), "store-qualification", "VERIFIED"),
                (review("STALE"), "support-model", "STALE"),
                (review("MISSING"), "support-model", "MISSING"),
                (at("lane", ("refusals",), [{"record": None, "code": "stale-evidence", "reason": "a step is unbound"}]),
                 "route-monotonic", "UNVERIFIED")]
        for ages in (30, None):
            for number, (edit, item, grade) in enumerate(rows):
                record, ctx, inputs, results = passing()
                if ages is None:
                    unaged(record)
                edit(record, ctx, inputs, results)
                self.assertEqual(judged(record, ctx, inputs, results)["items"][item]["grade"], grade,
                                 (ages, number, item))

    def test_each_grade_states_the_reason_its_evidence_gives(self):
        def reason(name, **changes):
            record, ctx, inputs, results = passing()
            for key, value in changes.items():
                target = results[key]
                for part in value[0][:-1]:
                    target = target[part]
                target[value[0][-1]] = value[1]
            return judged(record, ctx, inputs, results)["items"][name]["reason"]

        handoff = {"obligation": "#123", "reason": "preservation is unqualified"}
        rows = [("census-full-staging", {"gd-GD-9": (("record", "mode"), "rehearsal")},
                 "a rehearsal record of GD-9 offered for the causal package GD-9 is refused"),
                ("census-full-staging", {"gd-GD-9": (("record", "id"), "GD-10")},
                 "a causal record of GD-10 offered for the causal package GD-9 is refused"),
                ("wave-halt", {"gd-GD-12": (("record", "objectives"), {"wave-halt": "NOT_MET"})},
                 "GD-12 reads MET and its objective for wave-halt reads NOT_MET"),
                ("fis-pause", {"fis": (("episode",), {**episode()["episode"], "verdict": "DISPROVEN",
                                                    "first_failure": "a takeover command was issued"})},
                 "the episode reads DISPROVEN: a takeover command was issued"),
                ("hit-latency", {"hit": (("receipt",), {"verdict": "fail", "candidate": REV, "cells": {},
                                                       "reasons": ["the scan phase missed its bound"],
                                                       "pacing": {"verdict": "fail", "reason": "pacing fell short"}})},
                 "the hit gate reads fail: the scan phase missed its bound; pacing fell short"),
                ("hit-latency", {"hit": (("receipt",), {"verdict": "handoff", "candidate": REV, "cells": {},
                                                       "pacing": {"verdict": "pass"}, "handoff": handoff})},
                 "the hit gate reads inconclusive: preservation #123 hands off: preservation is unqualified"),
                ("hit-latency", {}, "the hit gate reads pass"),
                ("real-path", {"hit": (("receipt", "verdict"), "fail")},
                 "gate real-path is lifted, and the hit gate it qualifies reads FAILED: the hit gate reads fail"),
                ("route-monotonic", {}, "credited"),
                ("route-monotonic", {"lane": (("refusals",), [{"record": None, "code": "stale-evidence",
                                                                "reason": "a step is unbound"}])},
                 "stale-evidence: a step is unbound")]
        for name, changes, expected in rows:
            self.assertEqual(reason(name, **changes), expected, (name, changes))
        record, ctx, inputs, results = passing()
        inputs["lanes"] = []
        self.assertEqual(judged(record, ctx, inputs, results)["items"]["route-monotonic"]["reason"],
                         "no lane evidence for job workspace")

    def test_a_refused_run_record_grades_unverified_and_the_receipt_is_written(self):
        record, ctx, inputs, results = passing()
        results["gd-GD-9"] = rd.Refusal("the game-day run record is no object")
        receipt = judged(record, ctx, inputs, results)
        self.assertEqual(receipt["items"]["census-full-staging"]["grade"], "UNVERIFIED")
        self.assertTrue(receipt["evidence"]["gamedays"]["GD-9"]["identity"]["refused"].startswith("refused"))

    def test_a_grade_read_from_a_run_record_carries_the_run_record_mark(self):
        record, ctx, inputs, results = passing()
        results["gd-GD-2"] = run_record("GD-2", verdict="DISPROVEN")
        results["gd-GD-11"] = rd.Refusal("the game-day run record is no object")
        inputs["gamedays"] = [g for g in inputs["gamedays"] if g["id"] != "GD-12"]
        items = judged(record, ctx, {**inputs, "date": "2027-06-01"}, results)["items"]
        read = {i["id"] for i in record["items"] if (i["source"] or "").startswith("gameday:")
                and i["source"] not in ("gameday:GD-11", "gameday:GD-12")}
        self.assertEqual({name for name, i in items.items() if "run_record_graded" in i}, read)
        # A failed run and an aged one keep the mark; a record its judge refused and an absent one were never read.
        self.assertEqual([(items[name]["grade"], items[name].get("run_record_graded")) for name in (
            "host-loss-multi-shard-staging", "census-full-staging", "unknown-write-tabletop", "wave-halt")],
            [("FAILED", True), ("STALE", True), ("UNVERIFIED", None), ("MISSING", None)])
        # A record of another package is parsed, and its id and mode are read, before it is refused.
        record, ctx, inputs, results = passing()
        results["gd-GD-9"] = run_record("GD-11")
        offered = judged(record, ctx, inputs, results)["items"]["census-full-staging"]
        self.assertEqual((offered["grade"], offered.get("run_record_graded")), ("MISSING", True))

    def test_a_tabletop_record_offered_under_a_causal_package_is_refused(self):
        record, ctx, inputs, results = passing()
        results["gd-GD-9"] = run_record("GD-11")
        self.assertEqual(judged(record, ctx, inputs, results)["items"]["census-full-staging"]["grade"], "MISSING")

    def test_a_reviewer_cannot_grade_not_applicable(self):
        record, ctx, inputs, results = passing()
        next(r for r in inputs["reviews"] if r["item"] == "support-model")["grade"] = "NOT APPLICABLE"
        with self.assertRaises(rd.Refusal):
            judged(record, ctx, inputs, results)

    def test_a_reviewer_entry_of_another_revision_grades_stale(self):
        record, ctx, inputs, results = passing()
        other, named = "d" * 40, ("support-model", "safety-alarm-routing-production", "vendor-escalation")
        for review in inputs["reviews"]:
            if review["item"] in named:
                review["revision"] = other
            if review["item"] == "vendor-escalation":
                review["grade"] = "FAILED"
        receipt = judged(record, ctx, inputs, results)
        # The binding decides before the reviewer's grade, whatever invalidators the item lists.
        for name in named:
            item = receipt["items"][name]
            self.assertEqual((item["grade"], item["reason"], item["reviewer_graded"]),
                             ("STALE", f"the evidence names revision {other}, not {REV}", True), name)
            self.assertEqual(item["identity"], {"reviewer": "reviewer-a", "date": "2026-11-20",
                                                "artifact_sha256": "7" * 64, "revision": other}, name)
        self.assertEqual(receipt["items"]["security-review"]["grade"], "VERIFIED")
        self.assertEqual(receipt["recommended_verdict"], "NOT READY")
        self.assertIn("floor items ['safety-alarm-routing-production'] are unresolved", receipt["reasons"][0])

    def test_dated_evidence_ages_at_its_limit_and_undated_or_future_evidence_is_unverified(self):
        record, ctx, inputs, results = passing()
        reasons = {"2026-12-21": "the evidence of 2026-11-20 is older than 30 days",
                   "2026-11-19": "the evidence is dated 2026-11-20, after the judging day 2026-11-19"}
        for today, grade in (("2026-12-20", "VERIFIED"), ("2026-12-21", "STALE"), ("2026-11-19", "UNVERIFIED")):
            receipt = judged(record, ctx, {**inputs, "date": today}, results)
            self.assertEqual(receipt["items"]["census-full-staging"]["grade"], grade, today)
            if today in reasons:
                self.assertEqual(receipt["items"]["census-full-staging"]["reason"], reasons[today])
                self.assertIsNone(receipt["valid_until"])
        results["gd-GD-9"]["identity"]["date"] = None
        undated = judged(record, ctx, inputs, results)["items"]["census-full-staging"]
        self.assertEqual((undated["grade"], undated["reason"]),
                         ("UNVERIFIED", "the inputs or the evidence name no date to age it by"))
        self.assertEqual(judged(record, ctx, {k: v for k, v in inputs.items() if k != "date"}, results)["items"][
            "support-model"]["grade"], "UNVERIFIED")
        self.assertEqual(judged(*passing())["valid_until"], "2026-12-20")

    def test_the_exception_register_rejects_each_flaw(self):
        record, ctx, inputs, results = passing()
        inputs["reviews"] = [r for r in inputs["reviews"] if r["item"] != "support-model"]
        for changes, state in (({"note": "x"}, "rejected: it holds keys ['note']"),
                               ({"item": "no-item"}, "rejected: it names no item"),
                               ({"item": "oncall-coverage"}, "rejected: the item is resolved"),
                               ({"approver": "service-owner"}, "rejected: its approver is not the risk authority"),
                               ({"approver": "someone"}, "rejected: its approver is not the risk authority"),
                               ({"approver": "Risk-Authority"}, "rejected: its approver is not the risk authority"),
                               ({"approver": " risk-authority "}, "rejected: its approver is not the risk authority"),
                               ({"expiry": "2026-11-21"}, "accepted")):
            inputs["exceptions"] = [{**self.exception("support-model"), **changes}]
            self.assertTrue(judged(record, ctx, inputs, results)["exceptions"][0]["state"].startswith(state), state)
        inputs["exceptions"] = [self.exception("support-model")]
        receipt = judged(record, ctx, {k: v for k, v in inputs.items() if k != "date"}, results)
        self.assertEqual(receipt["exceptions"][0]["state"], "rejected: the inputs name no date to check its expiry by")

    def test_objectives_off_their_shape_grade_unverified_and_list_no_refusal(self):
        record, ctx, inputs, results = passing()
        for objectives in (5, "abc", ["wave-halt"]):
            results["gd-GD-12"] = run_record("GD-12", verdict="PARTIAL", objectives=objectives)
            receipt = judged(record, ctx, inputs, results)
            self.assertEqual(receipt["items"]["wave-halt"]["grade"], "UNVERIFIED")
            self.assertEqual(receipt["evidence"]["gamedays"]["GD-12"]["refused"], [])

    def test_a_lifted_monitors_gate_with_unresolved_items_is_contradicted(self):
        with tempfile.TemporaryDirectory(prefix="readiness-judge-") as temp:
            for removed in ("alarm-basis", "safety-alarm-routing-production"):
                record, ctx, inputs, results = all_lifted(Path(temp))
                inputs["reviews"] = [r for r in inputs["reviews"] if r["item"] != removed]
                receipt = judged(record, ctx, inputs, results)
                self.assertEqual(receipt["contradicted"], {"monitors": f"gate monitors is lifted while its items "
                                                                       f"['{removed}'] are unresolved"})
                self.assertFalse(receipt["ready"])

    def test_a_lifted_acceptance_gate_needs_an_accepted_receipt(self):
        record, ctx, inputs, results = passing()
        self.assertNotIn("acceptance", judged(record, ctx, inputs, results)["contradicted"])
        results["acc"] = acceptance_receipt(accepted=False)
        receipt = judged(record, ctx, inputs, results)
        self.assertIn("acceptance", receipt["contradicted"])
        self.assertEqual(receipt["items"]["host-loss-safety"]["grade"], "VERIFIED")
        results["acc"] = acceptance_receipt(revision="d" * 40)
        receipt = judged(record, ctx, inputs, results)
        self.assertIn("acceptance", receipt["contradicted"])
        self.assertEqual(receipt["classes"]["host-loss"]["simulation"]["grade"], "STALE")
        receipt = judged(record, ctx, {k: v for k, v in inputs.items() if k != "acceptance"}, results)
        self.assertEqual(receipt["contradicted"], {
            "acceptance": "gate acceptance is lifted while no acceptance receipt bound to the revision is accepted"})

    def test_class_cells_read_their_own_items_and_the_acceptance_binding(self):
        record, ctx, inputs, results = passing()
        results["acc"] = acceptance_receipt(revision="d" * 40)
        results["gd-GD-12"] = run_record("GD-12", verdict="PARTIAL",
                                         objectives={"deploy-restart-staging": "MET", "wave-halt": "NOT_MET",
                                                     "deploy-restart-staging-safety": "MET"})
        cells = judged(record, ctx, inputs, results)["classes"]
        self.assertEqual(cells["host-loss"]["simulation"]["grade"], "STALE")
        self.assertEqual(cells["deploy-restart"]["staging"]["grade"], "VERIFIED")
        self.assertEqual(cells["power-loss"]["staging"], {
            "grade": "EXCLUDED", "reason": record["classes"]["power-loss"]["excluded"]["staging"]["reason"]})
        self.assertEqual(cells["host-loss"]["acceptance_verdict"], {
            "grade": "STALE", "reason": f"the evidence names revision {'d' * 40}, not {REV}"})
        self.assertNotIn("model", record["classes"]["host-loss-multi-shard"]["evidence"])
        self.assertEqual(cells["host-loss-multi-shard"]["model"], {"grade": "MISSING", "citations": []})
        self.assertNotIn("acceptance_verdict", cells["host-loss-multi-shard"])
        absent = judged(record, ctx, {k: v for k, v in inputs.items() if k != "acceptance"}, results)["classes"]
        self.assertEqual(absent["host-loss"]["acceptance_verdict"], {"grade": "MISSING",
                                                                    "reason": "no acceptance inputs"})

    def test_a_class_cell_reads_a_not_applicable_item_as_worse_than_a_verified_one(self):
        record, ctx, inputs, results = passing()
        waived = item(record, "rollback-refusal-staging")
        self.assertEqual((waived["source"], waived["floor"]), ("gameday:GD-13", None))
        waived["applicability"] = {"not_applicable": "no refusal path in this wave", "approver": "risk-authority"}
        receipt = judged(record, ctx, inputs, results)
        self.assertEqual(receipt["items"]["rollback-refusal-staging"]["grade"], "NOT APPLICABLE")
        self.assertEqual(receipt["items"]["rollback-refusal-staging-safety"]["grade"], "VERIFIED")
        self.assertEqual(receipt["classes"]["rollback-refusal"]["staging"]["grade"], "NOT APPLICABLE")

    def test_a_contradicted_lift_or_an_accepted_exception_alone_keeps_ready_false(self):
        with tempfile.TemporaryDirectory(prefix="readiness-judge-") as temp:
            record, ctx, inputs, results = all_lifted(Path(temp))
            inputs["reviews"] = [r for r in inputs["reviews"] if r["item"] != "support-model"]
            inputs["exceptions"] = [self.exception("support-model")]
            receipt = judged(record, ctx, inputs, results)
            self.assertEqual((receipt["recommended_verdict"], receipt["gates"], receipt["contradicted"],
                              receipt["ready"]), ("READY WITH EXPLICIT EXCEPTIONS", {}, {}, False))
            self.assertEqual(receipt["valid_until"], "2026-12-20")
            inputs["exceptions"] = [self.exception("support-model", expiry="2026-12-01")]
            self.assertEqual(judged(record, ctx, inputs, results)["valid_until"], "2026-12-01")
            record, ctx, inputs, results = all_lifted(Path(temp))
            results["acc"] = acceptance_receipt(accepted=False)
            receipt = judged(record, ctx, inputs, results)
            self.assertEqual((receipt["recommended_verdict"], receipt["gates"], list(receipt["contradicted"]),
                              receipt["ready"]), ("READY", {}, ["acceptance"], False))

    def test_a_failure_class_no_row_names_keeps_the_verdict_not_ready(self):
        with tempfile.TemporaryDirectory(prefix="readiness-judge-") as temp:
            record, ctx, inputs, results = all_lifted(Path(temp))
            dropped = {i["id"] for i in record["items"] if i["class"] == "successor-death"}
            record["classes"].pop("successor-death")
            record["items"] = [i for i in record["items"] if i["id"] not in dropped]
            record["unmapped"]["FC10"] = "the owner defers the successor-death scenario"
            inputs["reviews"] = [r for r in inputs["reviews"] if r["item"] not in dropped]
            receipt = judged(record, ctx, inputs, results)
            self.assertEqual((receipt["recommended_verdict"], receipt["ready"]), ("NOT READY", False))
            self.assertIn("failure class FC10 has no class row: the owner defers the successor-death scenario",
                          receipt["reasons"])

    def test_a_lifted_real_path_gate_and_its_hit_gate_must_agree(self):
        with tempfile.TemporaryDirectory(prefix="readiness-judge-") as temp:
            record, ctx, inputs, results = all_lifted(Path(temp))
            results["hit"]["receipt"]["verdict"] = "fail"
            inputs["exceptions"] = [self.exception("hit-latency")]
            receipt = judged(record, ctx, inputs, results)
            self.assertEqual(receipt["items"]["real-path"]["grade"], "FAILED")
            self.assertEqual(receipt["exceptions"][0]["state"], "accepted")
            self.assertIn("real-path", receipt["contradicted"])
            self.assertEqual((receipt["recommended_verdict"], receipt["ready"]), ("NOT READY", False))

    def test_a_non_finite_exception_field_is_listed_empty_and_the_receipt_renders(self):
        record, ctx, inputs, results = passing()
        inputs["reviews"] = [r for r in inputs["reviews"] if r["item"] != "support-model"]
        for bad in (float("inf"), [float("nan")], {"x": float("-inf")}):
            inputs["exceptions"] = [{**self.exception("support-model"), "reason": bad}]
            receipt = judged(record, ctx, inputs, results)
            self.assertEqual(receipt["exceptions"][0]["state"], "rejected: incomplete, it lacks ['reason']")
            self.assertIsNone(receipt["exceptions"][0]["reason"])
            self.assertEqual(receipt["exception_register_sha256"], mf.canonical(receipt["exceptions"]))
            try:
                json.dumps(receipt, allow_nan=False)
            except ValueError as error:
                self.fail(f"the receipt holds a non-finite number: {error}")

    def test_a_refused_lane_keeps_the_digest_of_the_bytes_its_items_read(self):
        record, ctx, inputs, results = passing()
        results["lane"] = {"missing": "refused: Refusal: the lane receipt is not JSON", "read": {"lane": "3" * 64}}
        receipt = judged(record, ctx, inputs, results)
        self.assertEqual(receipt["items"]["route-monotonic"]["grade"], "UNVERIFIED")
        self.assertEqual(receipt["items"]["route-monotonic"]["identity"], {"read": {"lane": "3" * 64}})
        self.assertEqual(receipt["evidence"]["lanes"]['["workspace", null]']["read"], {"lane": "3" * 64})

    def test_a_null_lane_passes_the_inputs_check_only_for_a_failed_injection(self):
        record, ctx, inputs, results = passing()
        inputs["fis"] = {"fis-pause": {"episode": "fis", "lane": None}}
        results["fis"] = {"episode": {**episode()["episode"], "status": "FAILED_TO_INJECT"}, "lane": False,
                          "identity": {"episode_sha256": "6" * 64}}
        self.assertEqual(judged(record, ctx, inputs, results)["items"]["fis-pause"]["grade"], "MISSING")

    def test_owning_judges_that_change_during_a_run_refuse_the_receipt(self):
        changed = {**rd.OWNING_SHA256, "hardware-lane.py": "0" * 64}
        with mock.patch.object(rd, "owning_digests", return_value=changed), self.assertRaises(rd.Refusal) as caught:
            judged(*passing())
        self.assertIn("owning judges ['hardware-lane.py'] changed while the judge ran", str(caught.exception))

    def test_a_budget_change_stales_its_runs_and_a_blocked_package_earns_nothing(self):
        record, ctx, inputs, results = passing()
        ctx["gamedays"]["budgets"]["planned-handoff-dark-time"]["value"] = 30
        receipt = judged(record, ctx, inputs, results)
        self.assertEqual(receipt["items"]["planned-handoff-staging"]["grade"], "STALE")
        self.assertEqual(receipt["items"]["census-full-staging"]["grade"], "VERIFIED")
        record, ctx, inputs, results = passing()
        package(ctx["gamedays"], "GD-9")["prerequisites"] = list(package(CTX["gamedays"], "GD-9")["prerequisites"])
        inputs["gamedays"][8]["catalog_sha256"] = digest_of(ctx, "GD-9")
        results["gd-GD-9"]["record"]["catalog_sha256"] = digest_of(ctx, "GD-9")
        item = judged(record, ctx, inputs, results)["items"]["census-full-staging"]
        self.assertEqual(item["grade"], "UNVERIFIED")
        self.assertIn("the committed package is blocked", item["reason"])
        results["gd-GD-9"]["record"]["verdict"] = "DISPROVEN"
        self.assertEqual(judged(record, ctx, inputs, results)["items"]["census-full-staging"]["grade"], "FAILED")

    def test_an_exception_approver_is_the_risk_authority_apart_from_the_owner_and_the_launch_authority(self):
        record, ctx, inputs, results = passing()
        inputs["reviews"] = [r for r in inputs["reviews"] if r["item"] != "support-model"]
        for changes, state in (({"risk_owner": "risk-authority"}, "rejected: its approver approves its own risk"),
                               ({"risk_owner": " Risk-Authority "}, "rejected: its approver approves its own risk"),
                               ({"expiry": "never"}, "rejected: its expiry is no YYYY-MM-DD"),
                               ({"expiry": "2026-13-45"}, "rejected: its expiry is no YYYY-MM-DD"),
                               ({"reason": "  "}, "rejected: incomplete, it lacks ['reason']"),
                               ({"risk_owner": "", "compensating_control": " "},
                                "rejected: incomplete, it lacks ['compensating_control', 'risk_owner']")):
            inputs["exceptions"] = [{**self.exception("support-model"), **changes}]
            self.assertEqual(judged(record, ctx, inputs, results)["exceptions"][0]["state"], state, changes)
        record["authority"]["launch"] = "Risk-Authority"
        record["gates"]["authority"]["lifted"] = False
        inputs["exceptions"] = [self.exception("support-model")]
        receipt = judged(record, ctx, inputs, results)
        self.assertTrue(receipt["exceptions"][0]["state"].startswith("rejected: its approver is the launch authority"))
        self.assertEqual(receipt["recommended_verdict"], "NOT READY")
        record["authority"]["launch"] = None
        receipt = judged(record, ctx, inputs, results)
        self.assertEqual(receipt["exceptions"][0]["state"], "accepted")
        self.assertEqual((receipt["recommended_verdict"], receipt["reasons"]),
                         ("NOT READY", ["the authority gate is open: role launch is null"]))

    def test_a_rejected_exception_keeps_only_its_declared_fields(self):
        record, ctx, inputs, results = passing()
        inputs["reviews"] = [r for r in inputs["reviews"] if r["item"] != "support-model"]
        inputs["exceptions"] = [{**self.exception("support-model"), "note": float("nan")}]
        receipt = judged(record, ctx, inputs, results)
        self.assertEqual(set(receipt["exceptions"][0]), rd.EXCEPTION_KEYS | {"state"})
        self.assertTrue(receipt["exceptions"][0]["state"].startswith("rejected: it holds keys ['note']"))
        try:
            json.dumps(receipt, allow_nan=False)
        except ValueError as error:
            self.fail(f"the receipt holds a non-finite number: {error}")

    def test_an_age_past_the_calendar_bounds_valid_until_at_the_last_date(self):
        record, ctx, inputs, results = passing()
        next(i for i in record["items"] if i["id"] == "census-full-staging")["max_age_days"] = 10 ** 12
        receipt = judged(record, ctx, inputs, results)
        self.assertEqual(receipt["items"]["census-full-staging"]["grade"], "VERIFIED")
        self.assertEqual(receipt["valid_until"], "2026-12-20")
        for i in record["items"]:
            i["max_age_days"] = 10 ** 12
        self.assertEqual(judged(record, ctx, inputs, results)["valid_until"], "9999-12-31")

    def test_a_run_record_judged_without_a_catalog_lists_its_objectives_refused(self):
        record = copy.deepcopy(BASE)
        without_catalog(record)
        ctx = copy.deepcopy(CTX)
        ctx["gamedays"], ctx["files"]["gamedays_sha256"] = None, None
        inputs = {"revision": REV, "gamedays": [{"id": "GD-12", "package_sha256": "9" * 64,
                                                 "catalog_sha256": "1" * 64, "record": "gd"}]}
        receipt = judged(record, ctx, inputs, {"gd": run_record("GD-12", objectives={"wave-halt": "MET"})})
        self.assertEqual(len(receipt["evidence"]["gamedays"]["GD-12"]["refused"]), 1)
        self.assertEqual(receipt["items"]["wave-halt"]["grade"], "MISSING")

    def test_an_inputs_file_off_its_shape_is_refused(self):
        record, ctx, inputs, results = passing()
        review = inputs["reviews"][0]
        bad = [{"date": "2026-02-30"}, {"acceptance": ""}, {"lanes": [{"job": "workspace", "module": None}]},
               {"lanes": inputs["lanes"] * 2}, {"fis": {"fis-unknown": {"episode": "e", "lane": "l"}}},
               {"fis": {"fis-pause": {"episode": "", "lane": "l"}}}, {"gamedays": [{**inputs["gamedays"][0],
                                                                                  "id": "GD-15"}]},
               {"gamedays": [{**inputs["gamedays"][0], "package_sha256": "x"}]},
               {"gamedays": inputs["gamedays"][:1] * 2}, {"runbooks": {"RB-missing": "d" * 64}},
               {"runbooks": []}, {"reviews": [{**review, "reviewer": "  "}]}, {"reviews": [{**review, "reason": ""}]},
               {"reviews": [review, review]}, {"exceptions": [{"reason": "x"}]}, {"exceptions": {}},
               {"hit_gate": ""}, {"lanes": [{**inputs["lanes"][0], "job": ""}]},
               {"lanes": [{**inputs["lanes"][0], "evidence": ""}]}, {"lanes": [{**inputs["lanes"][0], "module": ""}]},
               {"fis": {"fis-pause": {"episode": "fis", "lane": ""}}},
               {"fis": {"fis-pause": {"episode": "fis", "lane": "fis-lane", "extra": 1}}},
               {"gamedays": [{**inputs["gamedays"][0], "extra": 1}]},
               {"gamedays": [{**inputs["gamedays"][0], "record": ""}]},
               {"gamedays": [{**inputs["gamedays"][0], "catalog_sha256": "x"}]},
               {"reviews": [{**review, "artifact_sha256": "7" * 63}]}, {"reviews": [{**review, "date": "2026-02-30"}]},
               {"reviews": [{**review, "extra": 1}]}, {"lanes": {}}, {"gamedays": {}}, {"reviews": {}},
               {"reviews": [{k: v for k, v in review.items() if k != "revision"}]},
               {"reviews": [{**review, "revision": "d" * 39}]}, {"reviews": [{**review, "revision": None}]}]
        for change in bad:
            with self.assertRaises(rd.Refusal, msg=change):
                judged(record, ctx, {**inputs, **change}, results)
        typed = [list(inputs), {**inputs, "revision": 5}, {**inputs, "lanes": [["job", "module", "evidence"]]},
                 {**inputs, "fis": ["fis-pause"]}, {**inputs, "fis": {"fis-pause": ["episode", "lane"]}},
                 {**inputs, "gamedays": [list(inputs["gamedays"][0])]}, {**inputs, "reviews": [list(review)]},
                 {**inputs, "exceptions": ["item"]}, {k: v for k, v in inputs.items() if k != "revision"}]
        for value in typed:
            with self.assertRaises(rd.Refusal, msg=value) as caught:
                judged(record, ctx, value, results)
            self.assertIn("malformed inputs file", str(caught.exception))

    def test_an_inputs_file_may_name_every_input_every_profile_and_lanes_that_differ_in_job_or_module(self):
        record, ctx, inputs, results = passing()
        results["lane-m"] = results["lane-k"] = results["lane"]
        inputs.update(runbooks={}, exceptions=[], fis=dict.fromkeys(ctx["fis"]["profiles"], inputs["fis"]["fis-pause"]))
        inputs["lanes"] += [{"job": "workspace", "module": "kestrike", "evidence": "lane-m"},
                            {"job": "kani", "module": None, "evidence": "lane-k"}]
        self.assertEqual(set(inputs), rd.INPUT_KEYS)
        self.assertGreater(len(inputs["fis"]), 1)
        receipt = judged(record, ctx, inputs, results)
        self.assertEqual({i["grade"] for i in receipt["items"].values()}, {"VERIFIED", "NOT APPLICABLE"})
        self.assertEqual(set(receipt["evidence"]["lanes"]), {'["workspace", null]', '["workspace", "kestrike"]',
                                                             '["kani", null]'})

    def test_a_record_of_a_lane_with_a_module_reads_that_lane(self):
        record, ctx, inputs, results = passing()
        ctx["catalog"]["lane-loom"] = {"job": "loom", "module": "kestrike"}
        item(record, "route-monotonic").update(kind="model", source="record:lane-loom")
        inputs["lanes"].append({"job": "loom", "module": "kestrike", "evidence": "lane-m"})
        results["lane-m"] = {**results["lane"], "obligations": ["lane-loom"]}
        self.assertEqual(judged(record, ctx, inputs, results)["items"]["route-monotonic"]["grade"], "VERIFIED")
        results["lane-m"] = {"obligations": [], "refusals": [], "revision": "d" * 40, "receipt_sha256": "3" * 64,
                             "judge_sha256": None}
        stale = judged(record, ctx, inputs, results)["items"]["route-monotonic"]
        self.assertEqual((stale["grade"], stale["identity"]["module"]), ("STALE", "kestrike"))

    def test_a_refused_receipt_grades_unverified_and_a_malformed_inputs_file_is_refused(self):
        record, ctx, inputs, results = passing()
        results["hit"] = rd.Refusal("the campaign is not an object")
        self.assertEqual(judged(record, ctx, inputs, results)["items"]["hit-latency"]["grade"], "UNVERIFIED")
        with self.assertRaises(rd.Refusal):
            judged(record, ctx, {**inputs, "packages": {}}, results)
        with self.assertRaises(rd.Refusal):
            judged(record, ctx, {**inputs, "reviews": [{**inputs["reviews"][0], "item": "route-monotonic"}]}, results)

    def test_class_cells_take_the_worst_citation_and_name_what_grades_nothing(self):
        record, ctx, inputs, results = passing()
        results["acc"]["receipt"]["classes"]["host-loss"]["columns"]["containment"]["structural"]["kinds"][
            "simulation"]["verdict"] = "fail"
        results["acc"]["receipt"]["classes"]["host-loss"]["verdict"] = "fail"
        results["acc"]["receipt"]["classes"]["host-loss"]["columns"]["conservation"]["structural"]["kinds"][
            "simulation"]["verdict"] = "fail"
        record["sources"]["drill"] = {"kind": "simulation", "owner": "#290", "evidence": "a drill receipt"}
        record["classes"]["host-loss-multi-shard"]["excluded"].pop("simulation", None)
        record["classes"]["host-loss-multi-shard"]["evidence"]["simulation"] = ["drill:host-loss-drill"]
        cells = judged(record, ctx, inputs, results)["classes"]
        self.assertEqual(cells["host-loss"]["simulation"]["grade"], "FAILED")
        self.assertEqual(cells["host-loss"]["model"]["grade"], "VERIFIED")
        self.assertEqual(cells["host-loss"]["acceptance_verdict"]["grade"], "FAILED")
        self.assertEqual(cells["process-kill"]["acceptance_verdict"], {"grade": "VERIFIED",
                                                                       "reason": "the acceptance class reads pass"})
        results["acc"]["receipt"]["classes"]["process-kill"]["verdict"] = "credited"
        self.assertEqual(judged(record, ctx, inputs, results)["classes"]["process-kill"]["acceptance_verdict"], {
            "grade": "UNVERIFIED", "reason": "the acceptance class reads credited"})
        self.assertEqual(cells["host-loss-multi-shard"]["simulation"], {
            "grade": "MISSING", "citations": ["drill:host-loss-drill"], "ungraded": ["drill:host-loss-drill"]})
        record["sources"]["fleet"] = {"kind": "staging", "owner": "#290", "evidence": "a fleet drill receipt"}
        record["classes"]["census-full"]["evidence"]["staging"].append("fleet:census-drill")
        cell = judged(record, ctx, inputs, results)["classes"]["census-full"]["staging"]
        self.assertEqual((cell["grade"], cell["ungraded"]), ("MISSING", ["fleet:census-drill"]))

HELD_EVIDENCE = ROOT / "scripts/gameday-fixtures/held"
GD2_ITEMS = ("host-loss-multi-shard-staging", "host-loss-multi-shard-staging-safety")
# GD-2's two budgets at values under which the game-day judge reads its held fixture HELD, as its self-test sets them.
HOLDING = {"re-enrollment-drain": 100, "origin-load": 2}


def evidence_copy(root, edit=None):
    """A copy of the game-day judge's held fixture at `root / "evidence"`. `edit(directory)` changes its files, and the
    copy is then sealed again as a writer of the directory can: each digest `injection/collected.json` names follows
    its file's bytes."""
    target = root / "evidence"
    shutil.copytree(HELD_EVIDENCE, target)
    if edit:
        edit(target)
        seal = json.loads((target / "injection/collected.json").read_text())
        seal["files"] = {rel: sha((target / rel).read_bytes()) for rel in seal["files"]}
        (target / "injection/collected.json").write_text(json.dumps(seal))
    return target


def origin_row_dropped(directory):
    """Drop the last origin request and lower its count in `coverage.json`, as a writer who shortens a collection
    after the seal and keeps the coverage consistent does."""
    origin = directory / "origin.jsonl"
    rows = origin.read_text().splitlines(keepends=True)
    origin.write_text("".join(rows[:-1]))
    coverage = json.loads((directory / "coverage.json").read_text())
    coverage["origin.jsonl"]["lines"] -= 1
    (directory / "coverage.json").write_text(json.dumps(coverage))


class Admission(unittest.TestCase):
    """GD-2's admission through `judge`: the run record against the seal its inputs entry pins and the game-day judge's
    own rerun over the evidence directory that entry names, over copies of the judge's held fixture. Every other
    input is `passing()`'s; the GD-2 entry binds the fixture's package and revision, under a catalog whose GD-2
    budgets let the judge read the fixture HELD (`holding`) or under `passing()`'s budgets, under which it reads
    DISPROVEN."""

    def setUp(self):
        deferred = mock.patch.dict(rd.DEFERRED, clear=True)
        deferred.start()
        self.addCleanup(deferred.stop)
        self.temp = tempfile.TemporaryDirectory(prefix="readiness-admission-")
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    @staticmethod
    def holding(ctx):
        for budget, value in HOLDING.items():
            ctx["gamedays"]["budgets"][budget]["value"] = value
        return ctx

    def admitted(self, evidence, stated=None, pinned=None, holding=True, around=None):
        """(GD-2's two item grades, the receipt's GD-2 evidence entry) when `judge` admits the run record `stated`
        (the held fixture's record by default, or a function of it) with the seal `pinned` (the fixture's by default)
        for the directory `evidence`, which the real game-day judge reruns inside the context `around`."""
        record, ctx, inputs, results = passing()
        if holding:
            self.holding(ctx)
        fixture = rd.rerun(str(HELD_EVIDENCE), ctx["gamedays"], ctx["fis"])["record"]
        with around or nullcontext():
            again = rd.rerun(None if evidence is None else str(evidence), ctx["gamedays"], ctx["fis"])
        run = fixture if stated is None else stated(copy.deepcopy(fixture)) if callable(stated) else stated
        entry = next(g for g in inputs["gamedays"] if g["id"] == "GD-2")
        entry.update(package_sha256=sha((HELD_EVIDENCE / "package.json").read_bytes()),
                     catalog_sha256=digest_of(ctx, "GD-2"), evidence=None if evidence is None else str(evidence),
                     seal_sha256=pinned or fixture["seal"]["sha256"])
        results["gd-GD-2"] = {"record": run, "identity": {"record_sha256": "8" * 64, "date": run["date"]}}
        results[None if evidence is None else str(evidence)] = again
        receipt = judged(record, ctx, {**inputs, "revision": fixture["revision"], "date": fixture["date"]}, results)
        return {i: receipt["items"][i] for i in GD2_ITEMS}, receipt["evidence"]["gamedays"]["GD-2"]

    def grades(self, items):
        return {i["grade"] for i in items.values()}

    def test_the_judges_held_fixture_is_admitted_on_its_pinned_seal_and_its_rerun(self):
        items, shown = self.admitted(HELD_EVIDENCE)
        self.assertEqual(self.grades(items), {"VERIFIED"}, items)
        self.assertEqual({i["reason"] for i in items.values()}, {"GD-2 reads HELD"})
        self.assertEqual(shown["rerun"], {"seal_sha256": sha((HELD_EVIDENCE / "injection/collected.json").read_bytes()),
                                          "run_status": "COMPLETED", "verdict": "HELD"})
        # Under `passing()`'s budgets the judge reads the fixture DISPROVEN, and a record stating so is admitted.
        items, _ = self.admitted(HELD_EVIDENCE, holding=False)
        self.assertEqual(self.grades(items), {"FAILED"}, items)

    def test_a_directory_sealed_again_after_its_collection_changed_is_refused_against_the_pinned_seal(self):
        pinned = sha((HELD_EVIDENCE / "injection/collected.json").read_bytes())
        resealed = evidence_copy(self.root, origin_row_dropped)
        again = rd.rerun(str(resealed), self.holding(passing()[1])["gamedays"], LIVE["fis"])
        # The game-day judge alone reads the resealed directory as it reads an honest one.
        self.assertEqual((again["record"]["run_status"], again["record"]["verdict"]), ("COMPLETED", "HELD"))
        resealed_sha = again["record"]["seal"]["sha256"]
        self.assertNotEqual(resealed_sha, pinned)
        # The record the judge writes for the resealed directory carries its new seal.
        items, _ = self.admitted(resealed, stated=again["record"], pinned=pinned)
        self.assertEqual(self.grades(items), {"MISSING"}, items)
        for item in items.values():
            self.assertEqual(item["reason"], f"the record's seal {resealed_sha} differs from the seal_sha256 {pinned} "
                             "its inputs entry pins: the record is refused")
        # The record of the first seal, kept, beside the resealed directory.
        items, _ = self.admitted(resealed, pinned=pinned)
        self.assertEqual(self.grades(items), {"MISSING"}, items)
        for item in items.values():
            self.assertEqual(item["reason"], f"the evidence's seal {resealed_sha} differs from the seal_sha256 "
                             f"{pinned} its inputs entry pins: the collection was sealed again after the pinned seal, "
                             "and the record is refused")

    def test_a_seal_refusal_reads_missing_over_a_rerun_that_reads_disproven(self):
        other = "5" * 64

        def of_another_seal(run):
            return {**run, "seal": {**run["seal"], "sha256": other}}

        # Under `passing()`'s budgets the judge reads the fixture DISPROVEN. A record of another seal beside the
        # pinned evidence is refused on its seal, and the receipt's rerun holds the DISPROVEN.
        fixture_sha = sha((HELD_EVIDENCE / "injection/collected.json").read_bytes())
        items, shown = self.admitted(HELD_EVIDENCE, stated=of_another_seal, holding=False)
        self.assertEqual(shown["rerun"]["verdict"], "DISPROVEN")
        self.assertEqual(self.grades(items), {"MISSING"}, items)
        for item in items.values():
            self.assertEqual(item["reason"], f"the record's seal {other} differs from the seal_sha256 {fixture_sha} "
                             "its inputs entry pins: the record is refused")
        # The same record under a pin of its own seal: the evidence's seal is the one that differs.
        items, shown = self.admitted(HELD_EVIDENCE, stated=of_another_seal, pinned=other, holding=False)
        self.assertEqual(shown["rerun"]["verdict"], "DISPROVEN")
        self.assertEqual(self.grades(items), {"MISSING"}, items)
        for item in items.values():
            self.assertEqual(item["reason"], f"the evidence's seal {fixture_sha} differs from the seal_sha256 {other} "
                             "its inputs entry pins: the collection was sealed again after the pinned seal, and the "
                             "record is refused")

    def test_a_record_stating_its_objectives_met_over_the_held_fixture_is_refused_by_name(self):
        def met(run):
            run.update(run_status="COMPLETED", verdict="HELD", result="held on 11 rules")
            for rule in run["rules"].values():
                rule.update(result="held", guardrail=None, past_stop_condition=False)
            return run

        # Under `passing()`'s budgets the judge reads the fixture DISPROVEN, and the record states it HELD.
        items, shown = self.admitted(HELD_EVIDENCE, stated=met, holding=False)
        self.assertEqual(shown["rerun"]["verdict"], "DISPROVEN")
        self.assertEqual(self.grades(items), {"FAILED"}, items)
        for item in items.values():
            self.assertEqual(item["reason"], "the record states COMPLETED HELD and the game-day judge's rerun over the "
                             "evidence reads COMPLETED DISPROVEN: the record differs from the rerun's in ['result', "
                             "'rules', 'verdict'] and is refused")
        # A record that adds per-item objectives the judge does not write, all MET, over a rerun that reads HELD.
        items, _ = self.admitted(HELD_EVIDENCE, stated=lambda run: {**run, "objectives": dict.fromkeys(GD2_ITEMS,
                                                                                                      "MET")})
        self.assertEqual(self.grades(items), {"MISSING"}, items)
        self.assertTrue(all(i["reason"].endswith("differs from the rerun's in ['objectives'] and is refused")
                            for i in items.values()), items)
        # A record that states less than the rerun is refused too: the rerun's record is the only one admitted.
        items, _ = self.admitted(HELD_EVIDENCE, stated=lambda run: {**run, "verdict": "INCONCLUSIVE"})
        self.assertEqual(self.grades(items), {"MISSING"}, items)

    def test_absent_evidence_leaves_a_held_record_unverified_with_its_reason(self):
        absent = self.root / "never-written"
        for evidence, reason in ((absent, f"the evidence directory {str(absent)!r} is absent"),
                                 (None, "the inputs entry names no evidence directory")):
            with self.subTest(evidence=evidence):
                items, shown = self.admitted(evidence)
                self.assertEqual(self.grades(items), {"UNVERIFIED"}, items)
                for item in items.values():
                    self.assertEqual(item["reason"], f"GD-2 reads HELD, but {reason}, so no rerun of the game-day "
                                     "judge confirms the record")
                self.assertEqual(shown["rerun"]["refused"], f"{reason}, so no rerun of the game-day judge confirms "
                                 "the record")
        # A stated failure stays a failure without its evidence.
        items, _ = self.admitted(absent, stated=lambda run: {**run, "verdict": "DISPROVEN"})
        self.assertEqual(self.grades(items), {"FAILED"}, items)

    def test_a_wrong_shaped_or_oversized_directory_is_the_judges_refusal_passed_on(self):
        def stray(directory):
            (directory / "notes.txt").write_text("an operator's note\n")

        wrong = evidence_copy(self.root, stray)
        items, _ = self.admitted(wrong)
        self.assertEqual(self.grades(items), {"UNVERIFIED"}, items)
        refusal = (f"the game-day judge refuses the evidence directory {str(wrong)!r}: notes.txt is no file of the "
                   "layout")
        self.assertTrue(all(i["reason"] == f"GD-2 reads HELD, but {refusal}" for i in items.values()), items)
        items, shown = self.admitted(HELD_EVIDENCE, around=mock.patch.object(rd.gj, "FILE_LIMIT", 1 << 10))
        self.assertEqual(self.grades(items), {"UNVERIFIED"}, items)
        self.assertIn("holds more than 1024 bytes", shown["rerun"]["refused"])
        failing = mock.patch.object(rd.gj, "judge", side_effect=KeyError("time"))
        items, shown = self.admitted(HELD_EVIDENCE, around=failing)
        self.assertEqual(self.grades(items), {"UNVERIFIED"}, items)
        self.assertEqual(shown["rerun"]["refused"], f"the game-day judge fails on the evidence directory "
                         f"{str(HELD_EVIDENCE)!r}: KeyError: 'time'")

    def test_the_gd2_entry_names_its_seal_and_evidence_and_no_other_entry_does(self):
        record, ctx, inputs, results = passing()
        gd2 = next(g for g in inputs["gamedays"] if g["id"] == "GD-2")
        shapes = {"no seal": {k: v for k, v in gd2.items() if k != "seal_sha256"},
                  "no evidence key": {k: v for k, v in gd2.items() if k != "evidence"},
                  "a seal off its shape": {**gd2, "seal_sha256": "D" * 64},
                  "an empty evidence path": {**gd2, "evidence": ""}}
        for label, entry in shapes.items():
            with self.subTest(label=label), self.assertRaises(rd.Refusal) as caught:
                judged(record, ctx, {**inputs, "gamedays": [entry]}, results)
            self.assertIn("a GD-2 entry with its seal_sha256 and its evidence directory or null", str(caught.exception))
        gd9 = next(g for g in inputs["gamedays"] if g["id"] == "GD-9")
        with self.assertRaises(rd.Refusal):
            judged(record, ctx, {**inputs, "gamedays": [{**gd9, "seal_sha256": SEAL_PIN, "evidence": None}]}, results)
        judged(record, ctx, {**inputs, "gamedays": [{**gd2, "evidence": None}]}, results)


class Adapters(unittest.TestCase):
    """The real owning-judge adapters over files in a temp directory, with a stub hardware lane where a case needs
    the lane to refuse."""

    def setUp(self):
        deferred = mock.patch.dict(rd.DEFERRED, clear=True)
        deferred.start()
        self.addCleanup(deferred.stop)
        self.temp = tempfile.TemporaryDirectory(prefix="readiness-adapters-")
        self.root = Path(self.temp.name)
        self.judges = rd.Judges(LIVE, gate.lane_module())

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value))
        return str(path)

    def test_the_rerun_adapter_judges_the_named_directory_and_keeps_the_output_out_of_it(self):
        evidence = evidence_copy(self.root)
        result = self.judges.rerun(str(evidence))
        # The committed catalog leaves GD-2's budgets null, so the fixture's working values bound its rules.
        self.assertEqual((result["record"]["verdict"], result["identity"]["seal_sha256"]),
                         ("HELD", sha((evidence / "injection/collected.json").read_bytes())))
        with self.assertRaises(rd.Refusal) as caught:
            rd.guard_output(str(evidence / "receipt.json"), self.judges)
        self.assertIn("names evidence this run read", str(caught.exception))
        rd.guard_output(str(self.root / "receipt.json"), self.judges)
        self.assertEqual(self.judges.rerun(None), rd.rerun(None, LIVE["gamedays"], LIVE["fis"]))
        self.assertIn("is absent", self.judges.rerun(str(self.root / "absent"))["missing"])

    def test_a_run_record_is_parsed_with_its_digest_and_date(self):
        path = self.write("gd.json", {"id": "GD-9", "date": "2026-11-20"})
        result = self.judges.gameday(path)
        self.assertEqual(result["record"], {"id": "GD-9", "date": "2026-11-20"})
        self.assertEqual(result["identity"]["date"], "2026-11-20")
        self.assertEqual(result["identity"]["record_sha256"], hashlib.sha256(Path(path).read_bytes()).hexdigest())
        with self.assertRaises(rd.Refusal):
            self.judges.gameday(self.write("list.json", []))

    def test_a_rehearsal_record_is_hashed_from_its_bytes_whatever_they_hold(self):
        record = self.root / "rehearsal.txt"
        record.write_bytes(b"Walked RB-hold-device on 2026-11-21.\n\xff")
        self.assertEqual(self.judges.rehearsal(str(record)),
                         {"record_sha256": hashlib.sha256(record.read_bytes()).hexdigest()})
        with self.assertRaises(rd.Refusal) as caught:
            rd.guard_output(str(record), self.judges)
        self.assertIn("names evidence this run read", str(caught.exception))
        with self.assertRaises(rd.Refusal) as caught:
            self.judges.rehearsal("d" * 64)
        self.assertIn("is unreadable", str(caught.exception))

    def test_a_fault_injection_episode_binds_to_its_lane_receipt(self):
        def receipt(**fields):
            return {"envelope": EPISODE_ENVELOPE, "fis": {"profile": "fis-pause", "episode": "ep-1",
                                                         "status": "COMPLETED", "verdict": "HELD", **fields}}
        episode = self.write("e.json", receipt())
        other = self.write("l.json", {"hardware": {"episode": "ep-2", "revision": REV}})
        with self.assertRaises(rd.Refusal) as caught:
            self.judges.fis("fis-pause", {"episode": episode, "lane": other}, REV)
        self.assertIn("not the fault-injection episode 'ep-1'", str(caught.exception))
        hardware = {"episode": "ep-1", "revision": REV, "profile": "fis-read", "role": "owner"}
        lane = self.write("m.json", {"envelope": LANE_ENVELOPE, "hardware": hardware})
        for other in ({"hardware": hardware}, {"envelope": LANE_ENVELOPE, "hardware": {**hardware, "role": "client"}},
                      {"envelope": LANE_ENVELOPE, "hardware": {**hardware, "profile": "fis-stop"}}):
            with self.assertRaises(rd.Refusal) as caught:
                self.judges.fis("fis-pause", {"episode": episode, "lane": self.write("o.json", other)}, REV)
            self.assertIn("no hardware lane receipt of profile fis-read role owner", str(caught.exception))
        with self.assertRaises(rd.Refusal) as caught:
            self.judges.fis("fis-read-latency", {"episode": episode, "lane": lane}, REV)
        self.assertIn("the episode receipt is profile 'fis-pause', not fis-read-latency", str(caught.exception))
        unnamed = self.write("u.json", receipt(episode=""))
        with self.assertRaises(rd.Refusal) as caught:
            self.judges.fis("fis-pause", {"episode": unnamed, "lane": self.write("n.json", {
                "envelope": LANE_ENVELOPE, "hardware": {**hardware, "episode": ""}})}, REV)
        self.assertIn("the lane receipt is episode '', not the fault-injection episode ''", str(caught.exception))
        for field in ("profile", "episode", "status", "verdict"):
            unstated = receipt()
            unstated["fis"].pop(field)
            with self.assertRaises(rd.Refusal, msg=field) as caught:
                self.judges.fis("fis-pause", {"episode": self.write("s.json", unstated), "lane": lane}, REV)
            self.assertIn("with a text profile, episode, status and verdict", str(caught.exception))
        result = self.judges.fis("fis-pause", {"episode": episode, "lane": lane}, REV)
        self.assertTrue(result["reasons"])
        self.assertEqual(result["drift"][0], "the episode ran None, not the pinned profile's 'aws:ebs:pause-volume-io'")
        self.assertEqual(result["identity"], {"episode_sha256": hashlib.sha256(Path(episode).read_bytes()).hexdigest(),
                                              "lane_sha256": hashlib.sha256(Path(lane).read_bytes()).hexdigest()})
        pinned = LIVE["fis"]["profiles"]["fis-pause"]
        bound = {"action": pinned["action"], "timeouts": {"test_timeout_io_us": pinned["timeout_io_us"]},
                 "profile_sha256": PAUSE}
        self.assertEqual(self.judges.fis("fis-pause", {"episode": self.write("p.json", receipt(**bound)),
                                                       "lane": lane}, REV)["drift"], [])
        for changes, why in (({"timeouts": {"test_timeout_io_us": 1}}, "test timeout is 1 us"),
                             ({"profile_sha256": "0" * 64}, "ran profile definition " + "0" * 64),
                             ({"fis_profiles_sha256": "0" * 64},
                              f"ran under fault-injection manifest {'0' * 64}, not the pinned {FIS_MANIFEST}")):
            drift = self.judges.fis("fis-pause", {"episode": self.write("p.json", receipt(**{**bound, **changes})),
                                                  "lane": lane}, REV)["drift"]
            self.assertEqual(len(drift), 1)
            self.assertIn(why, drift[0])
        moved = self.write("mm.json", {"envelope": LANE_ENVELOPE,
                                       "hardware": {**hardware, "manifest_sha256": "0" * 64}})
        drift = self.judges.fis("fis-pause", {"episode": self.write("p.json", receipt(**bound)), "lane": moved},
                                REV)["drift"]
        self.assertEqual(drift, [f"the lane receipt ran under manifest {'0' * 64}, not the pinned "
                                 f"{hashlib.sha256(LIVE['files']['hardware_profiles_sha256']).hexdigest()}"])
        pinned_lane = self.write("pm.json", {"envelope": LANE_ENVELOPE, "hardware": {
            **hardware, "manifest_sha256": sha(LIVE["files"]["hardware_profiles_sha256"])}})
        self.assertEqual(self.judges.fis("fis-pause", {"episode": self.write("p.json", receipt(**bound)),
                                                       "lane": pinned_lane}, REV)["drift"], [])
        duplicated = self.root / "dup.json"
        duplicated.write_bytes(b'{"envelope": {"version": 1, "section": "fis"}, "fis": {"verdict": "DISPROVEN", '
                               b'"verdict": "HELD"}}')
        with self.assertRaises(rd.FAULTS):
            self.judges.fis("fis-pause", {"episode": str(duplicated), "lane": lane}, REV)
        for bad in ({"fis": receipt()["fis"]}, {**receipt(), "envelope": {"version": 2, "section": "fis"}},
                    receipt(verdict=["HELD"]), ["envelope", "fis"]):
            with self.assertRaises(rd.Refusal):
                self.judges.fis("fis-pause", {"episode": self.write("b.json", bad), "lane": lane}, REV)
        with self.assertRaises(rd.Refusal) as caught:
            self.judges.fis("fis-pause", {"episode": episode, "lane": self.write("t.json", {
                "envelope": LANE_ENVELOPE, "hardware": ["episode", "revision"]})}, REV)
        self.assertIn("the lane receipt is episode None, not the fault-injection episode 'ep-1'",
                      str(caught.exception))
        invalid = self.write("i.json", receipt(status="NOT_STARTED", verdict="INVALID"))
        result = self.judges.fis("fis-pause", {"episode": invalid, "lane": None}, REV)
        self.assertEqual(rd.fis_grade(result, REV)["grade"], "MISSING")
        with self.assertRaises(rd.Refusal):
            self.judges.fis("fis-pause", {"episode": episode, "lane": None}, REV)

    def test_a_held_episode_bound_to_its_lane_receipt_verifies_through_the_adapter(self):
        real = gate.lane_module()
        manifest = sha(LIVE["files"]["hardware_profiles_sha256"])
        pinned = LIVE["fis"]["profiles"]["fis-pause"]
        calls = []

        class Lane:
            """The hardware lane with a profile judge that credits every receipt and records what it was asked."""
            Stop, ENVELOPE = real.Stop, real.ENVELOPE
            check_manifest, registry_rows = staticmethod(real.check_manifest), staticmethod(real.registry_rows)

            @staticmethod
            def judge_profile(platforms, name, profile, receipts, manifest_sha256, revision):
                calls.append((name, profile, receipts, manifest_sha256, revision))
                return True, []

        judges = rd.Judges(LIVE, Lane)

        def lane_receipt(cases):
            return {"envelope": LANE_ENVELOPE, "hardware": {"episode": "ep-1", "revision": REV, "profile": "fis-read",
                                                            "role": "owner", "manifest_sha256": manifest,
                                                            "cases": cases}}

        receipt = lane_receipt([{"observed": WITNESSED}])
        held = {"profile": "fis-pause", "episode": "ep-1", "status": "COMPLETED", "verdict": "HELD",
                "release_proof": True, "action": pinned["action"],
                "timeouts": {"test_timeout_io_us": pinned["timeout_io_us"]}, "profile_sha256": PAUSE,
                "fis_profiles_sha256": FIS_MANIFEST, "hardware_manifest": {"sha256": manifest},
                "effect_window": WINDOW}

        def judged_episode(changes=None, revision=REV, cases=None):
            lane = self.write("l.json", receipt if cases is None else lane_receipt(cases))
            episode = self.write("e.json", {"envelope": EPISODE_ENVELOPE, "fis": {
                **held, "lane_receipt_sha256": sha(Path(lane).read_bytes()), **(changes or {})}})
            return rd.fis_grade(judges.fis("fis-pause", {"episode": episode, "lane": lane}, REV), revision)

        self.assertEqual(judged_episode()["grade"], "VERIFIED")
        profiles = real.check_manifest(rd.parse(LIVE["files"]["hardware_profiles_sha256"], "hardware manifest"))[1]
        self.assertEqual(calls[0], ("fis-read", profiles["fis-read"], [receipt], manifest, REV))
        self.assertEqual(judged_episode(revision="d" * 40)["grade"], "STALE")
        for changes in ({"lane_receipt_sha256": "0" * 64}, {"hardware_manifest": {"sha256": "0" * 64}},
                        {"profile_sha256": None}, {"fis_profiles_sha256": None}, {"release_proof": False}):
            self.assertEqual(judged_episode(changes)["grade"], "UNVERIFIED", changes)
        # An episode run under another manifest file than the pinned one reads STALE though its profile row is the
        # pinned row: the controller admits targets by the file's top-level fields.
        relaxed = judged_episode({"fis_profiles_sha256": "0" * 64})
        self.assertEqual((relaxed["grade"], relaxed["reason"]), (
            "STALE", f"the episode ran under fault-injection manifest {'0' * 64}, not the pinned {FIS_MANIFEST}"))
        other = judged_episode({"action": "aws:ebs:volume-io-latency"})
        self.assertEqual((other["grade"], other["reason"]), (
            "STALE", "the episode ran 'aws:ebs:volume-io-latency', not the pinned profile's 'aws:ebs:pause-volume-io'"))

    def test_a_held_episode_verifies_only_under_the_fault_window_its_lane_receipt_witnesses(self):
        real = gate.lane_module()
        manifest = sha(LIVE["files"]["hardware_profiles_sha256"])
        pinned = LIVE["fis"]["profiles"]["fis-pause"]

        class Lane:
            """The hardware lane with a profile judge that credits every receipt."""
            Stop, ENVELOPE = real.Stop, real.ENVELOPE
            check_manifest, registry_rows = staticmethod(real.check_manifest), staticmethod(real.registry_rows)
            judge_profile = staticmethod(lambda *args: (True, []))

        judges = rd.Judges(LIVE, Lane)
        held = {"profile": "fis-pause", "episode": "ep-1", "status": "COMPLETED", "verdict": "HELD",
                "release_proof": True, "action": pinned["action"],
                "timeouts": {"test_timeout_io_us": pinned["timeout_io_us"]}, "profile_sha256": PAUSE,
                "fis_profiles_sha256": FIS_MANIFEST, "hardware_manifest": {"sha256": manifest},
                "effect_window": WINDOW}
        stopped = {"status": "HALTED", "abort": "stopped", "stop_under_fault": 5, "effect_window": {**WINDOW,
                                                                                                   "end_ordinal": 6}}
        stop = [observed("timeout", 3, 2), observed("stop", 5, 2)]

        def grade(changes=None, cases=({"observed": WITNESSED},)):
            lane = self.write("l.json", {"envelope": LANE_ENVELOPE, "hardware": {
                "episode": "ep-1", "revision": REV, "profile": "fis-read", "role": "owner",
                "manifest_sha256": manifest, "cases": cases}})
            episode = self.write("e.json", {"envelope": EPISODE_ENVELOPE, "fis": {
                **held, "lane_receipt_sha256": sha(Path(lane).read_bytes()), **(changes or {})}})
            return rd.fis_grade(judges.fis("fis-pause", {"episode": episode, "lane": lane}, REV), REV)["grade"]

        def events(*each):
            return ({"observed": list(each)},)

        self.assertEqual(grade(), "VERIFIED")
        self.assertEqual(grade(stopped, events(*stop)), "VERIFIED")
        # The window an episode names is checked against the controller marks the lane recorded with each event, so
        # a rewritten ordinal, an event before its mark and an event the receipt lacks each withhold the grade.
        refused = {
            "both ordinals rewritten to 0": ({"effect_window": {"start_ordinal": 0, "end_ordinal": 0}}, None),
            "a start one below its mark": ({"effect_window": {**WINDOW, "start_ordinal": 1}}, None),
            "an end one past its mark": ({"effect_window": {**WINDOW, "end_ordinal": 5}}, None),
            "an end at the start mark": ({"effect_window": {"start_ordinal": 2, "end_ordinal": 2}},
                                         events(observed("timeout", 3, 2), observed("restored", 5, 2))),
            "restored before the fault ended": (None, events(observed("timeout", 3, 2), observed("restored", 5, 2))),
            "no restored bytes": (None, events(observed("timeout", 3, 2))),
            "no timeout": (None, events(observed("restored", 5, 4))),
            "a timeout before the fault started": (None, events(observed("timeout", 1, None),
                                                                observed("restored", 5, 4))),
            "events naming no controller mark": (None, events(observed("timeout", 3, None),
                                                              observed("restored", 5, None))),
            "no mark and no window": ({"effect_window": None}, events(observed("timeout", 3, None),
                                                                      observed("restored", 5, None))),
            "no window": ({"effect_window": None}, None),
            "a window of another type": ({"effect_window": [2, 4]}, None),
            "ordinals of another type": ({"effect_window": {"start_ordinal": "2", "end_ordinal": True}}, None),
            "events of another kind": (None, events(*({**e, "kind": "ready"} for e in WITNESSED))),
            "no observed events": (None, ({},)),
            "no cases": (None, []),
            "cases of another type": (None, 5),
            "an event of another type": (None, events("timeout", "restored")),
            "a frontier of another type": (None, events(*({**e, "after": 2} for e in WITNESSED))),
            "an event ordinal of another type": (None, events(observed("timeout", "3", 2),
                                                              observed("restored", 5, 4))),
            "a stop at another ordinal": ({**stopped, "stop_under_fault": 4}, events(*stop)),
            "a stop after the fault ended": (stopped, events(observed("timeout", 3, 2), observed("stop", 5, 6))),
            "a stop before the timeout": ({**stopped, "stop_under_fault": 3},
                                          events(observed("stop", 3, 2), observed("timeout", 5, 2))),
            "a stop the receipt lacks": (stopped, events(observed("timeout", 3, 2))),
        }
        for name, (changes, cases) in refused.items():
            self.assertEqual(grade(changes, *([] if cases is None else [cases])), "UNVERIFIED", name)

    def test_a_lane_receipt_of_another_revision_is_hashed_and_not_credited(self):
        (self.root / "lane").mkdir()
        (self.root / "lane" / "receipt.json").write_text(json.dumps({"revision": "d" * 40}))
        before = sorted(p.name for p in (self.root / "lane").iterdir())
        result = self.judges.lane("workspace", None, str(self.root / "lane"), REV)
        self.assertEqual((result["revision"], result["obligations"]), ("d" * 40, []))
        self.assertEqual(len(result["receipt_sha256"]), 64)
        self.assertEqual(sorted(p.name for p in (self.root / "lane").iterdir()), before)
        route = item(RECORD, "route-monotonic")
        self.assertEqual(route["source"], "record:client-route-high-water")
        grade = rd.source_grade(route, RECORD, LIVE, {"lanes": {("workspace", None): result}}, REV)
        self.assertEqual((grade["grade"], grade["identity"]["receipt_sha256"]), ("STALE", result["receipt_sha256"]))

    def test_a_lane_receipt_of_the_revision_is_credited_by_the_acceptance_lane_runner_and_keeps_its_revision(self):
        (self.root / "lane").mkdir()
        (self.root / "lane" / "receipt.json").write_text(json.dumps({"revision": REV}))
        credit = {"obligations": ["client-route-high-water"], "refusals": [], "receipt_sha256": "3" * 64,
                  "judge_sha256": "4" * 64}
        with mock.patch.object(self.judges.acc, "lane", return_value=dict(credit)) as runner:
            result = self.judges.lane("workspace", None, str(self.root / "lane"), REV)
        self.assertEqual(runner.call_args.args, ("workspace", None, str(self.root / "lane"), REV))
        self.assertEqual(result, {**credit, "revision": REV})
        grade = rd.source_grade(item(RECORD, "route-monotonic"), RECORD, LIVE,
                                {"lanes": {("workspace", None): result}}, REV)
        self.assertEqual(grade["grade"], "VERIFIED")

    def test_a_lane_tree_with_a_link_or_a_receipt_naming_no_revision_is_refused(self):
        (self.root / "lane").mkdir()
        (self.root / "outside.json").write_text(json.dumps({"revision": "d" * 40}))
        (self.root / "lane" / "receipt.json").symlink_to(self.root / "outside.json")
        with self.assertRaises(rd.Refusal) as caught:
            self.judges.lane("workspace", None, str(self.root / "lane"), REV)
        self.assertIn("a symbolic link or special file", str(caught.exception))
        self.assertEqual(self.judges.seen, {})
        (self.root / "lane" / "receipt.json").unlink()
        for receipt in ([], {"revision": None}):
            (self.root / "lane" / "receipt.json").write_text(json.dumps(receipt))
            with self.assertRaises(rd.Refusal):
                self.judges.lane("workspace", None, str(self.root / "lane"), REV)
        (self.root / "lane" / "receipt.json").write_text(json.dumps({"revision": "d" * 40}))
        (self.root / "elsewhere").mkdir()
        for name, plant in (("linked", lambda path: path.symlink_to(self.root / "elsewhere")), ("pipe", os.mkfifo)):
            plant(self.root / "lane" / name)
            with self.assertRaises(rd.Refusal) as caught:
                self.judges.lane("workspace", None, str(self.root / "lane"), REV)
            self.assertIn(f"holds {name!r}, a symbolic link or special file", str(caught.exception))
            (self.root / "lane" / name).unlink()
        self.assertEqual(self.judges.lane("workspace", None, str(self.root / "lane"), REV)["revision"], "d" * 40)
        with self.assertRaises(rd.Refusal) as caught:
            self.judges.lane("workspace", None, str(self.root / "outside.json"), REV)
        self.assertIn("is no directory", str(caught.exception))
        with self.assertRaises(rd.Refusal) as caught:
            self.judges.lane("workspace", None, "lane\x00evidence", REV)
        self.assertIn("does not resolve", str(caught.exception))

    def test_a_lane_path_that_loops_or_a_tree_that_cannot_be_listed_is_refused(self):
        (self.root / "loop").symlink_to(self.root / "loop")
        with self.assertRaises(rd.Refusal):
            self.judges.lane("workspace", None, str(self.root / "loop"), REV)
        tree = self.root / "lane"
        (tree / "sealed").mkdir(parents=True)
        (tree / "receipt.json").write_text(json.dumps({"revision": "d" * 40}))
        if os.geteuid() == 0:
            self.skipTest("root lists a directory of mode 000")
        (tree / "sealed").chmod(0)
        try:
            with self.assertRaises(rd.Refusal) as caught:
                self.judges.lane("workspace", None, str(tree), REV)
        finally:
            (tree / "sealed").chmod(0o700)
        self.assertIn("cannot be listed", str(caught.exception))
        self.assertEqual(self.judges.seen, {})

    def test_a_lane_path_of_the_acceptance_inputs_that_loops_is_refused_evidence_and_the_receipt_is_built(self):
        loop = self.root / "loop"
        loop.symlink_to(loop)
        try:
            loop.resolve()
        except RuntimeError:
            looping = [{"job": "workspace", "module": None, "evidence": str(loop)}]
        else:
            looping = None
        for lanes in (5, looping):
            if lanes is None:
                self.skipTest("this Python resolves a symbolic link loop to itself, which the lane runner judges")
            acceptance = self.write("acc.json", {"revision": REV, "lanes": lanes})
            receipt = rd.judge(RECORD, {"revision": REV, "acceptance": acceptance}, LIVE, self.judges, "a" * 64,
                               "b" * 64)
            refused = receipt["evidence"]["acceptance"]
            self.assertTrue(refused["refused"].startswith("refused: Refusal: "), refused)
            self.assertEqual(refused["read"], {acceptance: sha(Path(acceptance).read_bytes())})
            self.assertEqual(receipt["items"]["host-loss-safety"]["grade"], "UNVERIFIED")
            self.assertEqual(receipt["recommended_verdict"], "NOT READY")

    def test_the_episode_is_judged_under_the_pinned_manifest_bytes_the_hardware_lane_checks(self):
        real = gate.lane_module()

        class Lane:
            Stop, ENVELOPE = real.Stop, real.ENVELOPE

            def __init__(self, refuse=None):
                self.refuse, self.checked = refuse, 0

            def read_judged_manifest(self, path):
                raise AssertionError("the manifest was read again")

            def check_manifest(self, document):
                self.checked += 1
                if self.refuse == "manifest":
                    raise real.Stop(real.REJECTED, "malformed hardware manifest: x")
                return real.check_manifest(document)

            def registry_rows(self, profiles):
                if self.refuse == "registry":
                    raise real.Stop(real.REJECTED, "the registry differs")
                return real.registry_rows(profiles)

            def judge_profile(self, *args):
                return real.judge_profile(*args)

        episode = self.write("e.json", {"envelope": EPISODE_ENVELOPE, "fis": {
            "profile": "fis-pause", "episode": "ep-1", "status": "COMPLETED", "verdict": "HELD"}})
        lane = self.write("l.json", {"envelope": LANE_ENVELOPE, "hardware": {
            "episode": "ep-1", "revision": REV, "profile": "fis-read", "role": "owner"}})
        for refuse in ("manifest", "registry"):
            judges = rd.Judges(LIVE, Lane(refuse))
            for _ in range(2):
                with self.assertRaises(rd.Refusal) as caught:
                    judges.fis("fis-pause", {"episode": episode, "lane": lane}, REV)
                self.assertIn("the hardware lane refuses its manifest", str(caught.exception))
                self.assertEqual(set(judges.seen), {episode, lane})
        stub = Lane()
        judges = rd.Judges(LIVE, stub)
        for _ in range(2):
            judges.fis("fis-pause", {"episode": episode, "lane": lane}, REV)
        self.assertEqual(stub.checked, 1)

    def test_a_run_record_with_a_repeated_key_or_a_field_off_its_type_is_refused(self):
        path = self.root / "dup.json"
        path.write_bytes(b'{"id": "GD-9", "verdict": "DISPROVEN", "verdict": "HELD"}')
        with self.assertRaises(rd.FAULTS) as caught:
            self.judges.gameday(str(path))
        self.assertIn("repeats an object key", str(caught.exception))
        for field in ("id", "mode", "revision", "run_status", "verdict", "package_sha256", "catalog_sha256",
                      "executor", "author"):
            with self.assertRaises(rd.Refusal, msg=field) as caught:
                self.judges.gameday(self.write("typed.json", {"id": "GD-9", field: ["HELD"]}))
            self.assertIn(f"the game-day run record's ['{field}'] are not text", str(caught.exception))

    def test_the_real_acceptance_and_hit_gate_judges_grade_a_bare_input(self):
        path = self.write("acc.json", {"revision": REV})
        accepted = self.judges.acceptance(path)
        self.assertEqual((accepted["revision"], accepted["identity"]["accepted"]), (REV, False))
        self.assertEqual(accepted["identity"], {"inputs_sha256": sha(Path(path).read_bytes()), "accepted": False,
                                                "receipt_sha256": mf.canonical(accepted["receipt"])})
        cell = rd.acceptance_cell(accepted, "host-loss", "safety", "simulation", REV)
        self.assertEqual(cell["grade"], "MISSING")
        path = self.write("hit.json", {"campaign": "hit-gate-x", "main": "a" * 40, "candidate": REV, "runs": []})
        campaign = self.judges.hit_gate(path)
        self.assertEqual(campaign["identity"], {"campaign_sha256": sha(Path(path).read_bytes()),
                                                "receipt_sha256": mf.canonical(campaign["receipt"])})
        self.assertEqual(campaign["receipt"]["verdict"], "handoff")
        self.assertEqual(rd.hit_grade(campaign, REV, "publish")["grade"], "UNVERIFIED")
        self.assertIn("handoff", campaign["receipt"])

    def test_an_output_naming_a_file_or_a_lane_tree_a_judge_read_is_refused(self):
        record = self.write("gd.json", {"id": "GD-9"})
        for name in ("lane", "nested"):
            (self.root / name).mkdir()
            (self.root / name / "receipt.json").write_text(json.dumps({"revision": "d" * 40}))
        acceptance = self.write("acc.json", {"revision": REV, "lanes": [
            5, {"job": "workspace", "module": None}, {"job": "workspace", "module": None, "evidence": None},
            {"job": "workspace", "module": None, "evidence": str(self.root / "nested")}]})
        free = str(self.root / "receipt.json")
        rd.guard_output(free, self.judges)
        self.judges.gameday(record)
        self.judges.lane("workspace", None, str(self.root / "lane"), REV)
        with mock.patch.object(rd.acc, "judge", return_value={"revision": REV, "accepted": False}):
            self.judges.acceptance(acceptance)
        rd.guard_output(free, self.judges)
        for output in (record, acceptance, str(self.root / "lane" / "out.json"),
                       str(self.root / "lane" / "deep" / "out.json"), str(self.root / "nested" / "out.json"),
                       str(self.root / "lane" / "receipt.json")):
            with self.assertRaises(rd.Refusal, msg=output) as caught:
                rd.guard_output(output, self.judges)
            self.assertIn("names evidence this run read", str(caught.exception))
        with self.assertRaises(rd.Refusal) as caught:
            rd.guard_output("receipt\x00.json", self.judges)
        self.assertIn("does not resolve", str(caught.exception))
        # A file no adapter recorded, as one a campaign names in turn is, a directory and a dangling link each
        # exist at their path, so none can be the output; the path beside them holds no entry and is admitted.
        samples, dangling = self.root / "samples.jsonl", self.root / "dangling.json"
        samples.write_text("{}\n")
        dangling.symlink_to(self.root / "absent.json")
        (self.root / "evidence").mkdir()
        for output in (samples, dangling, self.root / "evidence"):
            with self.assertRaises(rd.Refusal, msg=output) as caught:
                rd.guard_output(str(output), self.judges)
            self.assertIn("names an existing entry", str(caught.exception))
        self.assertEqual(samples.read_text(), "{}\n")
        rd.guard_output(free, self.judges)

    def test_an_output_naming_a_committed_input_or_a_file_the_acceptance_inputs_name_is_refused(self):
        named = {key: str(self.root / f"{key}.json") for key in ("package", "comparison", "sizing")}
        acceptance = self.write("acc.json", {"revision": REV, "packages": {"host-loss": named["package"]},
                                             "comparisons": {"host-loss": named["comparison"]},
                                             "sizing": named["sizing"]})
        # Pin INPUT_KEYS so each new key prompts a check for evidence paths that `guard_output` must protect.
        self.assertEqual(rd.acc.INPUT_KEYS, {"revision", "lanes", "packages", "comparisons", "sizing"})
        with mock.patch.object(rd.acc, "judge", return_value={"revision": REV, "accepted": False}):
            self.judges.acceptance(acceptance)
        committed = [*(ROOT / path for path, _ in rd.PINS.values()), ROOT / "scripts/readiness.py",
                     *(ROOT / "scripts" / name for name in rd.OWNING)]
        for output in (*named.values(), *map(str, committed)):
            with self.assertRaises(rd.Refusal, msg=output) as caught:
                rd.guard_output(output, self.judges)
            self.assertIn("names evidence this run read", str(caught.exception))
        rd.guard_output(str(self.root / "receipt.json"), self.judges)

    def test_acceptance_inputs_naming_files_off_their_type_reach_the_acceptance_judge(self):
        for named in ({"packages": 5, "comparisons": ["c.json"], "sizing": 5},
                      {"packages": {"host-loss": 5}, "comparisons": {"host-loss": None}, "sizing": None}):
            acceptance = self.write("acc.json", {"revision": REV, **named})
            with mock.patch.object(rd.acc, "judge", return_value={"revision": REV, "accepted": False}) as judge:
                self.judges.acceptance(acceptance)
            self.assertEqual(judge.call_args.args[1], {"revision": REV, **named})
            self.assertEqual(self.judges.opened, {Path(acceptance).resolve()})
        for named in ({"sizing": "sizing\x00.json"}, {"packages": {"host-loss": "package\x00.json"}}):
            with mock.patch.object(rd.acc, "judge", side_effect=AssertionError("acceptance judge ran")), \
                    self.assertRaises(rd.Refusal) as caught:
                self.judges.acceptance(self.write("acc.json", {"revision": REV, **named}))
            self.assertIn("does not resolve", str(caught.exception))


class Command(unittest.TestCase):
    def main(self, *argv, checkout=REV, modified=()):
        """The command's status, output and error text, run as from a checkout at commit `checkout` whose tracked
        files `modified` differ from it."""
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), \
                mock.patch.object(rd, "checkout_commit", return_value=checkout), \
                mock.patch.object(rd, "modified_files", return_value=list(modified)):
            status = rd.main(list(argv))
        return status, out.getvalue(), err.getvalue()

    def test_judge_refuses_a_checkout_with_a_tracked_file_that_differs_from_its_commit(self):
        with tempfile.TemporaryDirectory(prefix="readiness-") as temp:
            inputs, output = Path(temp) / "inputs.json", Path(temp) / "receipt.json"
            inputs.write_text(json.dumps({"revision": REV}))
            # A checker the lane's child process loads, modified at the right commit, is named by no digest.
            with mock.patch.object(rd, "judge") as judge:
                status, out, err = self.main("judge", "--inputs", str(inputs), "--output", str(output),
                                             modified=["scripts/judge-kani.py"])
            self.assertEqual((status, out, judge.call_count, output.exists()), (2, "", 0, False))
            self.assertIn("readiness: refused: ", err)
            self.assertIn("scripts/judge-kani.py", err)
            # `check` judges no revision and reads no tree state.
            with mock.patch.object(rd, "modified_files", side_effect=AssertionError("check read the tree")), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(rd.main(["check"]), 0)

            def git(*args):
                subprocess.run(["git", "-C", temp, "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                                *args], capture_output=True, check=True)

            # The tree state is git's: an untracked file is admitted, and a tracked file edited in the working tree
            # or in the index is listed.
            tracked = Path(temp) / "tracked.txt"
            tracked.write_text("committed\n")
            git("init", "--quiet")
            git("add", "tracked.txt")
            git("commit", "--quiet", "-m", "one")
            self.assertEqual(rd.modified_files(Path(temp)), [])
            tracked.write_text("edited\n")
            self.assertEqual(rd.modified_files(Path(temp)), ["tracked.txt"])
            git("add", "tracked.txt")
            self.assertEqual(rd.modified_files(Path(temp)), ["tracked.txt"])
            # A file git is told to leave out of its comparison is listed whatever its bytes: the two index flags
            # hide an edit from `git status`.
            git("commit", "--quiet", "-m", "two")
            self.assertEqual(rd.modified_files(Path(temp)), [])
            for flag, clear in (("--assume-unchanged", "--no-assume-unchanged"),
                                ("--skip-worktree", "--no-skip-worktree")):
                git("update-index", flag, "tracked.txt")
                self.assertEqual(rd.modified_files(Path(temp)), ["tracked.txt"], flag)
                tracked.write_text(f"edited under {flag}\n")
                self.assertEqual(rd.modified_files(Path(temp)), ["tracked.txt"], flag)
                git("update-index", clear, "tracked.txt")
                git("commit", "--quiet", "-am", flag)
                self.assertEqual(rd.modified_files(Path(temp)), [], flag)
            with self.assertRaises(rd.Refusal) as caught:
                rd.modified_files(Path(temp) / "absent")
            self.assertIn("cannot be read", str(caught.exception))

    def test_judge_refuses_a_checkout_at_another_commit_than_the_inputs_revision(self):
        with tempfile.TemporaryDirectory(prefix="readiness-") as temp:
            inputs, output = Path(temp) / "inputs.json", Path(temp) / "receipt.json"
            inputs.write_text(json.dumps({"revision": REV}))
            other = "d" * 40
            with mock.patch.object(rd, "judge") as judge:
                status, out, err = self.main("judge", "--inputs", str(inputs), "--output", str(output), checkout=other)
            self.assertEqual((status, out, judge.call_count, output.exists()), (2, "", 0, False))
            self.assertIn("readiness: refused: ", err)
            self.assertIn(REV, err)
            self.assertIn(other, err)
            # The commit is read from the checkout this script runs in, and a checkout git cannot read is refused.
            head = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True,
                                  check=True).stdout.strip()
            lane = gate.lane_module()
            self.assertEqual(rd.checkout_commit(lane), head)
            with mock.patch.object(lane, "git_revision", side_effect=lane.Stop(2, "git rev-parse HEAD exited 128")), \
                    self.assertRaises(rd.Refusal) as caught:
                rd.checkout_commit(lane)
            self.assertIn("exited 128", str(caught.exception))
            # `check` judges no revision and reads no commit.
            with mock.patch.object(rd, "checkout_commit", side_effect=AssertionError("check read the commit")), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(rd.main(["check"]), 0)

    def test_check_prints_the_open_gates_and_the_line_not_ready(self):
        status, out, err = self.main("check")
        self.assertEqual((status, err), (0, ""))
        body, _, verdict = out.rstrip("\n").rpartition("\n")
        self.assertEqual(verdict, "NOT READY")
        try:
            report = json.loads(body)
        except ValueError as error:
            self.fail(f"check printed no JSON report before its verdict line: {error}")
        self.assertEqual(report["gates"], [name for name in GATES if not RECORD["gates"][name]["lifted"]])
        self.assertEqual(report["verdict"], "NOT READY")
        self.assertEqual(body, json.dumps(report, indent=1))

    def test_a_command_line_without_its_command_or_inputs_is_a_usage_error(self):
        for argv in ([], ["judge"], ["verdict"]):
            with self.assertRaises(SystemExit) as caught, redirect_stderr(io.StringIO()) as err:
                rd.main(argv)
            self.assertEqual(caught.exception.code, 2, argv)
            self.assertIn("usage:", err.getvalue())

    def write(self, temp, text):
        path = Path(temp) / "failover.json"
        path.write_text(text)
        return str(path)

    def test_judge_exits_1_with_no_evidence_and_writes_its_receipt(self):
        with tempfile.TemporaryDirectory(prefix="readiness-") as temp:
            inputs, output = Path(temp) / "inputs.json", Path(temp) / "receipt.json"
            inputs.write_text(json.dumps({"revision": REV}))
            status, out, _ = self.main("judge", "--inputs", str(inputs), "--output", str(output))
            try:
                receipt = json.loads(output.read_text())
            except (OSError, ValueError) as error:
                self.fail(f"judge wrote no JSON receipt: {error}")
            self.assertEqual((status, out, receipt["ready"], receipt["recommended_verdict"]),
                             (1, "", False, "NOT READY"))
            self.assertEqual(output.read_text(), json.dumps(receipt, indent=1, sort_keys=True) + "\n")
            self.assertEqual((receipt["inputs_sha256"], receipt["record_sha256"]), (
                hashlib.sha256(inputs.read_bytes()).hexdigest(), hashlib.sha256(rd.RECORD.read_bytes()).hexdigest()))
            before = inputs.read_bytes()
            status, _, err = self.main("judge", "--inputs", str(inputs), "--output", str(inputs))
            self.assertEqual((status, inputs.read_bytes()), (2, before))
            self.assertIn("names evidence this run read", err)
            # A second run names the first run's receipt: the judge creates its receipt and replaces no file.
            written = output.read_bytes()
            with mock.patch.object(rd.gate, "write_receipt") as write:
                status, out, err = self.main("judge", "--inputs", str(inputs), "--output", str(output))
            self.assertEqual((status, out, write.call_count, output.read_bytes()), (2, "", 0, written))
            self.assertIn("names an existing entry", err)
            # The mock keeps the pinned file intact when the guard admits it, so the case checks `write.call_count`.
            with mock.patch.object(rd.gate, "write_receipt") as write:
                status, _, err = self.main("judge", "--inputs", str(inputs), "--output",
                                           str(ROOT / rd.PINS["fis_profiles_sha256"][0]))
            self.assertEqual((status, write.call_count), (2, 0))
            self.assertIn("names evidence this run read", err)
            loop = Path(temp) / "loop.json"
            loop.symlink_to(loop)
            status, out, err = self.main("judge", "--inputs", str(inputs), "--output", str(loop))
            self.assertEqual((status, out), (2, ""))
            self.assertIn("readiness: refused: ", err)
            for ready, verdict, code in ((True, "READY", 0), (False, "READY", 1)):
                with mock.patch.object(rd, "judge", return_value={"ready": ready, "recommended_verdict": verdict}):
                    status, out, _ = self.main("judge", "--inputs", str(inputs))
                try:
                    printed = json.loads(out)
                except ValueError as error:
                    self.fail(f"judge printed no JSON receipt: {error}")
                self.assertEqual((status, printed["ready"]), (code, ready))
            inputs.write_text(json.dumps({"revision": "x"}))
            status, _, err = self.main("judge", "--inputs", str(inputs))
        self.assertEqual(status, 2)
        self.assertIn("malformed inputs file", err)

    def test_check_exits_2_on_a_refused_record(self):
        with tempfile.TemporaryDirectory(prefix="readiness-") as temp:
            record = copy.deepcopy(RECORD)
            record["gates"].pop("authority")
            status, out, err = self.main("check", "--record", self.write(temp, json.dumps(record)))
        self.assertEqual((status, out), (2, ""))
        self.assertIn("readiness: refused: malformed readiness record: gates are not", err)

    def test_the_script_run_as_a_command_exits_with_the_status_of_its_check(self):
        script = str(ROOT / "scripts/readiness.py")
        done = subprocess.run([sys.executable, script, "check"], capture_output=True, text=True, check=False)
        self.assertEqual((done.returncode, done.stderr), (0, ""))
        self.assertTrue(done.stdout.endswith("\nNOT READY\n"), done.stdout[-80:])
        with tempfile.TemporaryDirectory(prefix="readiness-") as temp:
            record = copy.deepcopy(RECORD)
            record["gates"].pop("authority")
            done = subprocess.run([sys.executable, script, "check", "--record", self.write(temp, json.dumps(record))],
                                  capture_output=True, text=True, check=False)
        self.assertEqual((done.returncode, done.stdout), (2, ""))
        self.assertIn("readiness: refused: malformed readiness record: gates are not", done.stderr)

    def test_check_exits_2_on_a_repeated_key(self):
        text = json.dumps(RECORD)
        model = '"model": ["acceptance:host-loss"]'
        repeated = {"class": ('"successor-death": {', '"successor-death": {}, "successor-death": {'),
                    "kind": (model, '"model": [], ' + model)}
        with tempfile.TemporaryDirectory(prefix="readiness-") as temp:
            path = Path(temp) / "failover.json"
            path.write_text(text)
            self.assertEqual(self.main("check", "--record", str(path))[0], 0)
            for name, (old, new) in repeated.items():
                self.assertEqual(text.count(old), 1, name)
                path.write_text(text.replace(old, new))
                status, out, err = self.main("check", "--record", str(path))
                self.assertEqual((status, out), (2, ""), name)
                self.assertIn("readiness: refused: readiness record repeats an object key", err)

    def test_check_exits_2_on_a_record_over_its_byte_limit(self):
        data = rd.RECORD.read_bytes()
        with tempfile.TemporaryDirectory(prefix="readiness-") as temp:
            path = self.write(temp, data.decode())
            with mock.patch.object(rd, "RECORD_LIMIT", len(data)):
                self.assertEqual(self.main("check", "--record", path)[0], 0)
            with mock.patch.object(rd, "RECORD_LIMIT", len(data) - 1), \
                    mock.patch.object(gate.os, "fdopen", side_effect=AssertionError("a file was read")):
                status, out, err = self.main("check", "--record", path)
        self.assertEqual((status, out), (2, ""))
        self.assertIn(f"exceeds {len(data) - 1} bytes", err)

    def test_check_exits_2_when_the_report_cannot_be_rendered(self):
        """The serializer fails for `readiness.py` alone: the acceptance context serializes with the shared `json`
        module while it is built, so the failing call is the one that renders the finished report."""
        renderer = mock.Mock(wraps=json)
        renderer.dumps.side_effect = MemoryError
        with mock.patch.object(rd, "json", renderer):
            status, out, _ = self.main("check")
        self.assertEqual((status, out), (2, ""))
        renderer.dumps.assert_called_once()
        self.assertEqual(renderer.dumps.call_args.args[0]["verdict"], "NOT READY")

    def test_check_refuses_a_repeated_key_or_an_unreadable_record_before_it_builds_the_context(self):
        text = json.dumps(RECORD, indent=1)
        repeated = (text.replace('"lifted": false', '"lifted": true, "lifted": false', 1),
                    text.replace('"gates": {', '"gates": {\n  "models": {}, ', 1))
        with tempfile.TemporaryDirectory(prefix="readiness-") as temp, \
                mock.patch.object(rd, "context", side_effect=AssertionError("context built")):
            for body in repeated:
                status, out, err = self.main("check", "--record", self.write(temp, body))
                self.assertEqual((status, out), (2, ""))
                self.assertIn("readiness record repeats an object key", err)
            status, out, err = self.main("check", "--record", str(Path(temp) / "absent.json"))
        self.assertEqual((status, out), (2, ""))
        self.assertIn("readiness record", err)
        self.assertIn("is unreadable", err)


if __name__ == "__main__":
    unittest.main()
