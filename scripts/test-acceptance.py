#!/usr/bin/env python3
"""Exercise acceptance.py's record rules, open gates and unrun domains, and its per-class judgment over synthetic
lane credits, package, comparison and sizing receipts: evidence-kind separation, class binding, cold-control
retention, retention terms, the store-restore reopen claim, the #122 case families, lane, package and comparison
credit, H and F rows, the preservation gate, the inputs refusals and the command line with the real judges."""

import copy
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("acceptance", ROOT / "scripts/acceptance.py")
assert SPEC is not None and SPEC.loader is not None
acc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acc)
mf, gate = acc.mf, acc.gate

LANE = gate.lane_module()
ARGS = SimpleNamespace(manifest=str(gate.MANIFEST), obligations=str(gate.OBLIGATIONS), records=str(mf.RECORDS))
CTX, _ = acc.context(ARGS, LANE)
RECORD = gate.parse(gate.read_file(acc.RECORD, "acceptance record"), "acceptance record")
REV = "c" * 40
CYCLES = "warm-cycle-histories-judge-four-verdicts-and-conserve-at-the-boundary"
SEEDS = "warm-cycle-histories-pass-on-seeds-1-to-16-as-unpowered-discovery"
HISTORY = "takeover-history-preserves-the-retained-set"
PROXY = "warm-cycle-packages-keep-the-retained-set-across-a-controller-reset-and-a-process-kill"
LOSS = "volume-loss-provisions-only-on-isolated-permanent-loss"
DOUBLE = "takeover-reservation-provider-premises"
UNUSED = "no-more-work-means-clean-coverage"
STORE_RECORD, COVERAGE_RECORD = "store-namespace-fixture", "store-coverage-fixture"
STORE_CTX = {**CTX, "catalog": {**CTX["catalog"], **{r: {"id": r, "job": "workspace", "module": None, "tests": [],
                                                          "controls": [], "property": f"#123 {r}"}
                                                      for r in (STORE_RECORD, COVERAGE_RECORD)}}}
JOIN = "join-capture-cut-durable-suffix-model"
VERIFIER_SHA256 = hashlib.sha256((ROOT / "scripts/verify-receipts.py").read_bytes()).hexdigest()


def lane(*judged, refusals=(), blocked=None):
    """A verify-receipts credit result that judged `judged`, with `refusals` as (code, record) pairs."""
    return {"credited": not refusals, "obligations": list(judged), "receipt_sha256": "b" * 64, "judge_sha256": "d" * 64,
            "refusals": [{"code": code, "record": record, "reason": f"{code} reason"} for code, record in refusals],
            **({"blocked": blocked} if blocked else {})}


def package(name, verdicts=None, credited=True, revision=REV):
    return {"campaign_sha256": "a" * 64, "package": name, "class": CTX["document"]["packages"]["packages"][name][
        "class"], "revision": revision, "credited": credited, "open": [] if credited else ["no repeat count"],
        "reasons": [], "verdicts": {**dict.fromkeys(acc.rp.KINDS, "pass"), **(verdicts or {})}}


def comparison(rows=None, label=None, withheld=(), outcome="pass", revision=REV, classes=tuple(mf.CLASSES),
               outcomes=None, patch=mf.NO_PATCH):
    """A report receipt whose hardware rows read `rows` (default pass) for `classes` and whose outcomes read
    `outcome`, with `outcomes` overriding single (frame class, member) cells."""
    cells = [f"{f}/{s}" for f, strata in CTX["records"]["frame"][0]["comparison"]["cells"].items() for s in strata]
    receipt = {"campaign_sha256": "e" * 64, "verdict": "inconclusive", "reasons": list(withheld),
               "columns": {"hardware": {"label": label, "rows": {
                   cls: {cell: (rows or {}).get(cell, "pass") for cell in cells} if cls in classes else
                   dict.fromkeys(cells, "inconclusive") for cls in mf.CLASSES}}},
               "ranking": {"withheld": list(withheld)},
               "outcomes": {cls: {m: (outcomes or {}).get((cls, m), outcome) for m in mf.FAMILY} for cls in mf.CLASSES},
               "hit_gate": {"verdict": "inconclusive", "reasons": [], "receipt_sha256": "f" * 64, "gate": {}}}
    return {"receipt": receipt, "revision": revision, "patch": patch}


class Fake:
    """Judges whose results the test supplies by path, so acceptance's own rules are what the tests exercise."""

    def __init__(self, results):
        self.results = results
        self.calls = []

    def _get(self, path):
        self.calls.append(path)
        result = self.results[path]
        if isinstance(result, Exception):
            raise result
        return copy.deepcopy(result)

    def lane(self, job, module, evidence, revision):
        return self._get(evidence)

    def package(self, path):
        return self._get(path)

    def comparison(self, path):
        return self._get(path)

    def sizing(self, path):
        return self._get(path)


def every_lane():
    """Lanes crediting every record the committed record cites, under their catalog jobs."""
    return [{"job": job, "module": None, "evidence": job} for job in ("workspace", "long-run", "quint")]


def credited_results():
    ids = {job: [r for r, entry in STORE_CTX["catalog"].items() if entry["job"] == job]
           for job in ("workspace", "long-run", "quint")}
    return {"workspace": lane(*ids["workspace"]), "long-run": lane(*ids["long-run"]), "quint": lane(*ids["quint"]),
            "cr": package("CR-1"), "pk": package("PK-1"), "cmp": comparison()}


def full_inputs(**changes):
    inputs = {"revision": REV, "lanes": every_lane(), "packages": {"CR-1": "cr", "PK-1": "pk"},
              "comparisons": dict.fromkeys(("host-loss", "same-host-restart", "actual-volume-loss"), "cmp")}
    inputs.update(changes)
    return inputs


def run(record=None, inputs=None, results=None, ctx=None):
    fake = Fake(results if results is not None else credited_results())
    receipt = acc.judge(record or RECORD, inputs or {"revision": REV}, ctx or CTX, fake, "1" * 64, "2" * 64)
    return receipt, fake


def edited(edit):
    record = copy.deepcopy(RECORD)
    edit(record)
    return record


def steps(*edits):
    """One record edit that applies `edits` in order."""
    def edit(record):
        for step in edits:
            step(record)
    return edit


def column(receipt, cls, name):
    return receipt["classes"][cls]["columns"][name]


def store_source(record, *records):
    record["sources"]["store"] = {"issue": "#123", "kind": "store", "judge": "obligation", "evidence": "store",
                                  "classes": ["host-loss", "same-host-restart"], "columns": list(acc.COLUMNS),
                                  "records": list(records)}


WIDE_ROWS = {**acc.ROWS, "safety": {"first_safe_hit"}, "containment": {"first_safe_hit"}}


def lifted():
    """A context whose owner gates are lifted (preservation qualified, a class list, a population manifest and
    envelope, accepted alpha and power, every applicable budget, F's percentile and the readiness band and window,
    and a #123 store record) and a record pinning its records. The record is synthetic: it adds a store source, cites
    it in every warm column, adds host loss's
    model containment and progress, cites the cycle record under simulation conservation and first_safe_hit under
    hardware safety and containment, which WIDE_ROWS admits, and widens those sources' columns to match."""
    ctx = copy.deepcopy(STORE_CTX)
    ctx["document"]["qualification"]["preservation"]["qualified"] = True
    docs = {kind: ctx["records"][kind][0] for kind in mf.KINDS}
    policy = docs["policy"]
    policy["class_list"] = list(mf.CLASSES)
    for cls, rows in policy["budgets"].items():
        rows.update({m: 1 for m in rows if m not in (mf.H, mf.F) and mf.outcome(policy, cls, m) == "unscored"})
    policy["f"].update(budget_ms=1, percentile=0.99)
    policy["readiness"].update(fill_band=1, fill_window_s=1)
    docs["frame"]["population"]["manifest"] = {"sha256": "9" * 64}
    docs["frame"]["envelope"].update(dict.fromkeys(docs["frame"]["envelope"], 1))
    for key in ("familywise_alpha", "power"):
        docs["statistics"][key]["status"] = "accepted"
    ctx["records"] = {kind: (doc, hashlib.sha256(json.dumps(doc).encode()).hexdigest()) for kind, doc in docs.items()}
    record = copy.deepcopy(RECORD)
    record["records"].update({kind: mf.pin(ctx["records"], kind) for kind in mf.KINDS})
    store_source(record, STORE_RECORD)
    for source in ("components", "comparisons", "cycles"):
        record["sources"][source]["columns"] = list(acc.COLUMNS)
    for name in ("host-loss", "same-host-restart"):
        evidence = record["classes"][name]["evidence"]
        record["classes"][name]["unrun"].pop("store")
        evidence["store"] = {c: [f"store:{STORE_RECORD}"] for c in acc.COLUMNS}
        evidence["simulation"]["conservation"] = [f"cycles:{CYCLES}"]
        evidence["hardware"].update(safety=["comparisons:first_safe_hit/recovery"],
                                    containment=["comparisons:first_safe_hit/recovery"])
    record["classes"]["host-loss"]["evidence"]["model"].update(progress=[f"components:{JOIN}"],
                                                               containment=[f"components:{JOIN}"])
    return record, ctx


class Record(unittest.TestCase):
    def refused(self, edit, message, ctx=None):
        with self.assertRaises(acc.Refusal) as caught:
            acc.check(edited(edit), ctx or CTX)
        self.assertIn(message, str(caught.exception))

    def test_the_committed_record_checks_and_lists_its_gates_and_unrun_domains(self):
        gates, unrun = acc.check(RECORD, CTX)
        for item in ("class controller-reset has no frame stratum or policy budget row, so its quantitative members "
                     "read unscored", "25 budget rows hold no accepted budget and read unscored",
                     "the policy names no readiness-review class list", "the frame names no frozen population manifest",
                     "F declares no accepted budget_ms", "F declares no accepted percentile",
                     "the policy declares no fill_band", "the statistics version declares no horizon block count",
                     "the package interface declares no repeat count", "package CR-1 declares no injection authority",
                     "Conditional: #123 records no ST1 to ST8 qualification",
                     "platform row x86_64-nitro-ebs is unsupported", "4 model cases are blocked on AQ-15"):
            self.assertIn(item, gates)
        self.assertTrue(any(g.startswith("preservation takeover-history-suffix-damage-qualification-failure is "
                                         "unqualified") for g in gates))
        self.assertIn("the protocol declares no blocks", gates)
        self.assertTrue(any(g.startswith("no native class and credit interface: #30") for g in gates))
        owned = ("the reopen claim", "phase ", "recovery is")
        self.assertFalse(any(" leg " in g or g.startswith(owned) for g in gates))
        for prefix in ("power-loss: ", "provider-phenomena: ", "store-restore: ", "trace-replay: ",
                       "package-retention: ", "package PK-1 leg reboot: ", "hit-gate phase publish: ",
                       "hit-gate phase takeover: ", "hit-gate phase scan: ", "recovery qualification: ",
                       "certified_cut is no comparison row", "eligible_exclusions is no comparison row",
                       "interruption_ancestry is no comparison row", "first_correct_recovered_hit is no comparison row",
                       "class same-host-restart model: ", "class host-loss cites no hardware evidence under safety",
                       "the reopen claim is closed: no namespace record of #123",
                       "the reopen claim is closed: no coverage record of #123"):
            self.assertTrue(any(u.startswith(prefix) for u in unrun), prefix)
        self.assertNotIn("class actual-volume-loss cites no hardware evidence under retention", unrun)

    def test_the_owner_items_the_unrun_list_takes_must_still_be_named(self):
        ctx = {**CTX, "open": [item for item in CTX["open"] if not item.startswith("package PK-1 leg reboot")]}
        self.refused(lambda r: None, "the owners' open items no longer name each unrun leg, phase and recovery", ctx)

    def test_the_owning_judges_validate_the_records_and_manifest(self):
        document = copy.deepcopy(CTX["document"])
        document["qualification"]["preservation"]["qualified"] = True
        with tempfile.TemporaryDirectory(prefix="acceptance-") as temp:
            path = Path(temp) / "manifest.json"
            path.write_text(json.dumps(document))
            with self.assertRaises(acc.Refusal) as caught:
                acc.context(SimpleNamespace(**{**vars(ARGS), "manifest": str(path)}), LANE)
            self.assertIn("the frame pins another hit gate", str(caught.exception))
            document = copy.deepcopy(CTX["document"])
            document["packages"]["credit"] = {}
            path.write_text(json.dumps(document))
            with self.assertRaises(acc.rp.Refusal) as caught:
                acc.context(SimpleNamespace(**{**vars(ARGS), "manifest": str(path)}), LANE)
            self.assertIn("credit interface", str(caught.exception))
            catalog = gate.parse(gate.read_file(gate.OBLIGATIONS, "catalog"), "catalog")
            catalog["records"].append(catalog["records"][0])
            path.write_text(json.dumps(catalog))
            with self.assertRaises(acc.Refusal) as caught:
                acc.context(SimpleNamespace(**{**vars(ARGS), "obligations": str(path)}), LANE)
            self.assertIn("a record id repeats", str(caught.exception))

    def test_the_record_quotes_each_ticket_under_its_own_receipt_identity(self):
        issues = {name: s["issue"] for name, s in RECORD["sources"].items()}
        self.assertEqual(issues, {"cycles": "blotter issue 1193", "components": "#122", "histories": "#136", "proxies": "#140",
                                  "packages": "#140", "volume-loss": "#134", "comparisons": "#139"})

        def uncite_histories(r):
            for c in r["classes"].values():
                for cites in c["evidence"].get("simulation", {}).values():
                    cites[:] = [cite for cite in cites if not cite.startswith("histories:")]

        def drop_histories(r):
            uncite_histories(r)
            r["sources"].pop("histories")

        self.refused(drop_histories, "sources quote no receipt of [('#136', 'simulation')]")

        def packages_unrun(r):
            r["sources"].pop("packages")
            for name in ("controller-reset", "process-kill"):
                r["classes"][name]["evidence"].pop("hardware")
                r["classes"][name]["unrun"]["hardware"] = "no package runs"
        self.refused(packages_unrun, "sources quote no receipt of [('#140', 'hardware')]")

        def volume_loss_unrun(r):
            r["sources"].pop("volume-loss")
            r["classes"]["actual-volume-loss"]["evidence"].pop("simulation")
            r["classes"]["actual-volume-loss"]["unrun"]["simulation"] = "no simulation runs"
        self.refused(volume_loss_unrun, "sources quote no receipt of [('#134', 'simulation')]")
        self.refused(lambda r: r["sources"]["packages"].update(issue="#122"),
                     "source packages quotes #122, whose join records only an obligation source binds")
        self.refused(uncite_histories, "sources ['histories'] are cited by no class or reopen requirement")
        self.refused(lambda r: r["sources"]["histories"]["records"].append(CYCLES),
                     f"record {CYCLES} belongs to sources cycles and histories")
        self.refused(lambda r: r["sources"]["histories"]["records"].append(UNUSED),
                     f"records ['{UNUSED}'] are cited by no class or reopen requirement")

    def test_a_simulation_source_never_fills_a_hardware_cell(self):
        def edit(r):
            r["classes"]["host-loss"]["evidence"]["hardware"]["safety"] = [f"cycles:{CYCLES}"]
        self.refused(edit, "class host-loss cites simulation source cycles under hardware: a column credits only its "
                           "own evidence kind (P-N-341)")
        self.refused(lambda r: r["classes"]["controller-reset"]["evidence"]["hardware"]["safety"].append(
            f"proxies:{PROXY}"), "cites simulation source proxies under hardware")

        def relabel(r):
            r["sources"]["proxies"]["kind"] = "hardware"
        self.refused(relabel, "source proxies: judge 'obligation' produces no hardware evidence")

    def test_no_class_inherits_another_class_receipt(self):
        cases = {
            "a package cited by a warm class": (
                lambda r: r["classes"]["host-loss"]["evidence"]["hardware"].update(retention=["packages:retention"]),
                "class host-loss cites source packages, which credits ['controller-reset', 'process-kill']"),
            "a package of another class": (
                lambda r: r["classes"]["controller-reset"].update(package="PK-1"),
                "class controller-reset names package 'PK-1', whose manifest class is not controller-reset"),
            "a comparison cited by a package class": (
                lambda r: r["classes"]["process-kill"]["evidence"]["hardware"].update(
                    progress=["comparisons:first_safe_hit/recovery"]),
                "class process-kill cites source comparisons"),
            "a package read by a class without one": (
                steps(lambda r: r["sources"]["packages"]["classes"].append("host-loss"),
                      lambda r: r["classes"]["host-loss"]["evidence"]["hardware"].update(
                          retention=["packages:retention"])),
                "a class reads its own package's retention verdict"),
            "another package verdict under a column": (
                lambda r: r["classes"]["controller-reset"]["evidence"]["hardware"].update(
                    retention=["packages:safety"]),
                "a class reads its own package's retention verdict"),
            "a comparison row by a class without a frame class": (
                steps(lambda r: r["sources"]["comparisons"]["classes"].append("controller-reset"),
                      lambda r: r["classes"]["controller-reset"]["evidence"]["hardware"].update(
                          progress=["comparisons:first_safe_hit/recovery"])),
                "which is no hardware comparison row of its frame class"),
            "a comparison stratum the frame holds no row of": (
                lambda r: r["classes"]["host-loss"]["evidence"]["hardware"]["progress"].append(
                    "comparisons:first_safe_hit/idle"), "which is no hardware comparison row of its frame class"),
            "a timing row under a column it does not measure": (
                lambda r: r["classes"]["host-loss"]["evidence"]["hardware"]["conservation"].append(
                    "comparisons:first_safe_hit/recovery"), "under conservation, which that row never measures"),
            "a source cited under a column it does not credit": (
                lambda r: r["classes"]["host-loss"]["evidence"]["hardware"].update(
                    safety=["comparisons:first_safe_hit/recovery"]), "class host-loss cites source comparisons under "
                                                                    "safety"),
            "a record outside its source": (
                lambda r: r["classes"]["host-loss"]["evidence"]["simulation"]["safety"].append(f"cycles:{HISTORY}"),
                f"cites cycles:{HISTORY}, a record outside source cycles"),
            "a citation naming no item": (
                lambda r: r["classes"]["host-loss"]["evidence"]["simulation"]["safety"].append("cycles"),
                "which names no source and item"),
            "the proxies cited by the host-loss class": (
                lambda r: r["classes"]["host-loss"]["evidence"]["simulation"]["safety"].append(f"proxies:{PROXY}"),
                "class host-loss cites source proxies"),
            "two classes of one frame class": (
                lambda r: r["classes"]["host-loss"].update(frame="same-host-restart"),
                "the classes do not hold the frame classes"),
            "swapped warm frame classes": (
                steps(lambda r: r["classes"]["host-loss"].update(frame="same-host-restart"),
                      lambda r: r["classes"]["same-host-restart"].update(frame="warm-takeover")),
                "the classes do not hold the frame classes"),
            "a timing row under safety once the source lists safety": (
                steps(lambda r: r["sources"]["comparisons"]["columns"].append("safety"),
                      lambda r: r["classes"]["host-loss"]["evidence"]["hardware"].update(
                          safety=["comparisons:first_safe_hit/recovery"])), "under safety, which that row never"),
        }
        for label, (edit, message) in cases.items():
            with self.subTest(label):
                self.refused(edit, message)
        ctx = copy.deepcopy(CTX)
        ctx["records"]["frame"][0]["comparison"]["row_classes"]["first_safe_hit"] = ["volume-loss-control"]
        self.refused(lambda r: None, "class host-loss cites comparisons:first_safe_hit/recovery, which is no hardware "
                                     "comparison row of its frame class", ctx)
        ctx = copy.deepcopy(CTX)
        ctx["records"]["frame"][0]["fields"]["first_safe_hit"]["evidence"] = ["simulation"]
        self.refused(lambda r: None, "class host-loss cites comparisons:first_safe_hit/recovery, which is no hardware "
                                     "comparison row of its frame class", ctx)

    def test_the_cold_control_claims_no_retention_and_no_warm_class_cites_it(self):
        cases = {
            "cold retention": (lambda r: r["classes"]["actual-volume-loss"]["evidence"]["hardware"].update(
                retention=["comparisons:s_membership/recovery"]), "actual volume loss starts cold and claims no "
                                                                   "retention of S"),
            "the cold refill in a warm class": (lambda r: r["classes"]["host-loss"]["evidence"]["hardware"][
                "progress"].append("comparisons:cold_refill/recovery"), "class host-loss cites the cold refill"),
            "the volume-loss record in a warm class": (lambda r: r["classes"]["host-loss"]["evidence"]["simulation"][
                "containment"].append(f"volume-loss:{LOSS}"), "class host-loss cites source volume-loss"),
            "the volume-loss source widened to a warm class": (steps(
                lambda r: r["sources"]["volume-loss"]["classes"].append("host-loss"),
                lambda r: r["classes"]["host-loss"]["evidence"]["simulation"]["containment"].append(
                    f"volume-loss:{LOSS}")),
                "source volume-loss credits the cold control beside a warm class"),
            "a cold host-loss class": (lambda r: r["classes"]["host-loss"].update(cold=True),
                                       "class host-loss is cold exactly when its frame class is the volume-loss"),
        }
        for label, (edit, message) in cases.items():
            with self.subTest(label):
                self.refused(edit, message)

    def test_warm_hardware_retention_accounts_for_damage_and_the_unprotected_suffix(self):
        self.refused(lambda r: r["classes"]["host-loss"]["evidence"]["hardware"]["retention"].remove(
            "comparisons:recent_unprotected_suffix/recovery"), "without ['recent_unprotected_suffix/recovery']")
        self.refused(lambda r: r["classes"]["same-host-restart"]["evidence"]["hardware"]["retention"].remove(
            "comparisons:fault_local_damage/recovery"), "without ['fault_local_damage/recovery']")

    def test_retention_exclusions_and_the_outcomes_that_never_preserve_are_fixed(self):
        self.refused(lambda r: r["retention"]["exclusions"].append("stale"), "eligible exclusions are not R2's")
        self.refused(lambda r: r["retention"]["never"].remove("safe miss"), "never satisfy preservation")
        self.refused(lambda r: r["retention"]["terms"].remove("recent_unprotected_suffix"), "retention terms")

    def test_a_store_restore_reopen_rests_on_namespace_and_coverage_evidence_alone(self):
        for key in ("table_id", "generation_jump"):
            with self.subTest(key):
                self.refused(lambda r, key=key: r["reopen"]["requires"].update({key: [STORE_RECORD]}),
                             "TableId detection or a generation jump alone reopens nothing")
        self.refused(lambda r: r["reopen"]["requires"].pop("coverage"), "TableId detection or a generation jump")
        message = "reopen requirements name records of a #123 store source or null"
        self.refused(lambda r: r["reopen"]["requires"].update(namespace=["no-such-record"]), message)
        self.refused(lambda r: r["reopen"]["requires"].update(coverage=[CYCLES]), message)

        def outside_owner(r):
            store_source(r, STORE_RECORD)
            r["sources"]["store"]["issue"] = "blotter issue 1193"
            r["reopen"]["requires"].update(namespace=[STORE_RECORD])
        self.refused(outside_owner, "source store: store evidence belongs to #123", STORE_CTX)

        def double_as_store(r):
            store_source(r, DOUBLE)
            r["reopen"]["requires"].update(namespace=[DOUBLE])
        self.refused(double_as_store, f"record {DOUBLE} declares no #123 property, so it is no store evidence")
        self.refused(lambda r: r["reopen"]["insufficient"].pop(), "reopen claim")

    def test_the_component_records_bind_their_expected_case_families(self):
        self.refused(lambda r: r["sources"]["components"]["families"].append("preserve-run-"),
                     "family preserve-run- holds a case no record of source components names")
        quint = copy.deepcopy(CTX["quint"])
        quint["tests"].remove("join-coverage-preserve-safety")
        self.refused(lambda r: None, "source components names a case expected.json lacks", {**CTX, "quint": quint})
        floor = "join-named-slots-settled-floor-reuse-model"
        self.refused(lambda r: r["sources"]["components"]["records"].remove(floor),
                     "family join-prefix-saturation- holds a case no record of source components names")

        def drop_floor(r):
            r["sources"]["components"]["records"].remove(floor)
            r["sources"]["components"]["families"].remove("join-prefix-saturation-")
            r["classes"]["host-loss"]["evidence"]["model"]["conservation"].remove(f"components:{floor}")
        self.refused(drop_floor, "source components binds no families")
        self.refused(lambda r: r["sources"]["components"].pop("families"), "source components keys are not")
        self.refused(lambda r: r["sources"]["components"]["families"].append("capture-component-pass-"),
                     "family capture-component-pass- holds a case no record of source components names")
        self.refused(steps(lambda r: r["sources"]["components"]["records"].append(LOSS),
                           lambda r: r["sources"]["volume-loss"]["records"].remove(LOSS)),
                     f"record {LOSS} of job workspace is not model evidence")
        tlc = "remote-put-publishes-only-complete-current-bytes"
        self.refused(lambda r: r["sources"]["cycles"]["records"].append(tlc),
                     "of job tlc is not simulation evidence")
        self.refused(lambda r: r["sources"]["cycles"]["records"].append("tenure-takeover-retains-volume-model"),
                     "record tenure-takeover-retains-volume-model of job quint is not simulation evidence")

    def test_the_classes_hold_every_frame_class_the_frame_owns(self):
        """A frame class the measurement frame adds has a budget row and comparison rows of its own, so a record
        whose classes leave it out is refused rather than accepted without it."""
        with mock.patch.dict(mf.CLASSES, {"reboot": "reported apart"}):
            self.refused(lambda r: None, "are not the frame classes ['reboot', 'same-host-restart', "
                                         "'volume-loss-control', 'warm-takeover']")

    def test_each_evidence_kind_is_cited_or_declared_unrun_never_both(self):
        self.refused(lambda r: r["classes"]["host-loss"]["unrun"].pop("store"), "cites or declares unrun each")
        self.refused(lambda r: r["classes"]["controller-reset"]["unrun"].update(hardware="none"),
                     "cites or declares unrun each")

    def test_the_record_pins_its_records_parents_family_and_exclusions(self):
        def dropping(name):
            def edit(r):
                r["classes"].pop(name)
                for source in r["sources"].values():
                    source["classes"] = [c for c in source["classes"] if c != name]
            return edit

        drop_restart, drop_kill = dropping("same-host-restart"), dropping("process-kill")

        cases = {
            "another sizing worksheet": (lambda r: r["records"].update(sizing="0" * 64), "the record pins are not"),
            "another policy": (lambda r: r["records"]["policy"].update(version=1), "the record pins are not"),
            "another specification digest": (lambda r: r["parent"]["specification"].update(body_sha256="0" * 64),
                                             "parent digests are not the frame's"),
            "another ticket": (lambda r: r["parent"]["ticket"].update(issue="#141"), "the ticket pin"),
            "a ticket pin with an extra key": (lambda r: r["parent"]["ticket"].update(note="x"), "the ticket pin"),
            "a ticket pin that is no object": (lambda r: r["parent"].update(ticket="#142"), "the ticket pin"),
            "a family member left out": (lambda r: r["quantitative"]["progress"].remove("fill_latency"),
                                         "does not cover the policy family once"),
            "a family member twice": (lambda r: r["quantitative"]["safety"].append("rto"),
                                      "does not cover the policy family once"),
            "a dropped manifest exclusion": (lambda r: r["excluded"].pop("fis"), "keep every manifest exclusion"),
            "dropped staging owners": (lambda r: r["excluded"].pop("staging"), "and the staging owners"),
            "a class excluded": (lambda r: r["excluded"].update({"host-loss": "x"}), "keep every manifest exclusion"),
            "a dropped unmeasured domain": (lambda r: r["unrun"].pop("power-loss"), "unrun domains do not keep"),
            "a dropped assumption": (lambda r: r["assumptions"].pop("model"), "assumptions are not one per"),
            "a repeated source record": (lambda r: r["sources"]["cycles"]["records"].append(CYCLES),
                                         "source cycles records are no distinct non-empty list"),
            "an unknown source record": (lambda r: r["sources"]["cycles"]["records"].append("no-such-record"),
                                         "source cycles names an unknown record"),
            "a dropped package class": (drop_kill, "the classes do not cover every manifest package"),
            "another P-N-341": (lambda r: r["properties"]["P-N-341"].update(maps=["#120 P4"]),
                                "properties are not the frame's P-N-341"),
            "two cold classes": (lambda r: r["classes"].update({"second-loss": {
                "frame": "volume-loss-control", "cold": True, "package": None, "meaning": "a second cold class",
                "evidence": {}, "unrun": dict.fromkeys(mf.EVIDENCE, "unrun")}}), "one class is the cold control"),
            "an unknown column": (lambda r: r["classes"]["host-loss"]["evidence"]["model"].update(speed=[]),
                                  "class host-loss model columns"),
            "an extra top-level key": (lambda r: r.update(note="x"), "keys are not"),
            "another record version": (lambda r: r.update(version=0), "record kind and version"),
            "a column out of order": (lambda r: r.update(columns=dict(reversed(list(r["columns"].items())))),
                                      "columns are not"),
            "a column entry that is no object": (lambda r: r["columns"].update(safety=["maps", "meaning"]),
                                                 "columns are not"),
            "a property no column maps": (lambda r: r["columns"]["containment"]["maps"].remove("#120 P9"),
                                          "together mapped to #120 P1 to P10"),
            "a source issue that is no ticket": (lambda r: r["sources"]["cycles"].update(issue="1193"),
                                                 "source cycles"),
            "another issue of the earlier tracker": (lambda r: r["sources"]["cycles"].update(
                issue="blotter issue 1194"), "source cycles"),
            "a source class outside the record": (lambda r: r["sources"]["cycles"]["classes"].append("reboot"),
                                                  "source cycles classes"),
            "a source column outside the five": (lambda r: r["sources"]["cycles"]["columns"].append("speed"),
                                                 "source cycles columns"),
            "records on a hardware source": (lambda r: r["sources"]["packages"].update(records=[PROXY]),
                                             "source packages keys are not"),
            "an unknown frame class": (lambda r: r["classes"]["host-loss"].update(frame="reboot"),
                                       "class host-loss frame class 'reboot'"),
            "an empty citation list": (lambda r: r["classes"]["host-loss"]["evidence"]["model"].update(safety=[]),
                                       "citations are no distinct non-empty list"),
            "a repeated citation": (lambda r: r["classes"]["host-loss"]["evidence"]["model"]["safety"].append(
                f"components:{JOIN}"), "citations are no distinct non-empty list"),
            "a dropped class": (drop_restart, "the classes do not hold the frame classes"),
            "a quantitative map that is no list": (lambda r: r["quantitative"].update(
                conservation={"held_capacity": 1, "peak_ram": 1}), "the quantitative map is no member list"),
            "reopen requirements that are no object": (lambda r: r["reopen"].update(requires=["namespace", "coverage"]),
                                                       "a store-restore reopen rests on namespace"),
            "another reopen owner": (lambda r: r["reopen"].update(owner="#142"), "reopen claim"),
            "an empty assumption": (lambda r: r["assumptions"].update(model=""), "assumptions are not one per"),
        }
        for label, (edit, message) in cases.items():
            with self.subTest(label):
                self.refused(edit, message)


class Judge(unittest.TestCase):
    def test_without_evidence_every_class_is_inconclusive_and_every_cited_kind_unrun(self):
        receipt, _ = run()
        self.assertEqual((receipt["verdict"], receipt["accepted"]), ("inconclusive", False))
        for name, cls in receipt["classes"].items():
            self.assertEqual(cls["verdict"], "inconclusive", name)
            for col, entry in cls["columns"].items():
                expected = "not claimed" if (name, col) == ("actual-volume-loss", "retention") else "unrun"
                self.assertEqual(entry["structural"]["verdict"], expected, (name, col))
        self.assertEqual(column(receipt, "host-loss", "safety")["quantitative"]["verdict"], "none")
        store = column(receipt, "host-loss", "safety")["structural"]["kinds"]["store"]
        self.assertEqual(store["verdict"], "unrun")
        self.assertIn("#123", store["reason"])
        self.assertEqual(receipt["reopen"]["verdict"], "closed")

    def test_the_receipt_binds_every_verdict_to_its_hashes(self):
        receipt, _ = run(inputs=full_inputs())
        for key in ("manifest_sha256", "catalog_sha256", "quint_sha256"):
            self.assertEqual(receipt[key], CTX[key])
        self.assertEqual((receipt["record_sha256"], receipt["inputs_sha256"]), ("1" * 64, "2" * 64))
        self.assertEqual(receipt["records"], RECORD["records"])
        self.assertEqual(receipt["parent"]["ticket"]["issue"], "#142")
        self.assertEqual(receipt["evidence"]["packages"]["CR-1"]["receipt_sha256"], mf.canonical(package("CR-1")))
        self.assertEqual(receipt["evidence"]["comparisons"]["host-loss"]["receipt_sha256"],
                         mf.canonical(comparison()["receipt"]))
        budgets = receipt["classes"]["host-loss"]["budgets"]
        self.assertEqual(budgets["sha256"], mf.canonical(CTX["records"]["policy"][0]["budgets"]["warm-takeover"]))
        self.assertEqual(receipt["classes"]["controller-reset"]["budgets"], {"row": None, "sha256": None})
        cite = column(receipt, "host-loss", "retention")["structural"]["kinds"]["simulation"]["citations"][0]
        self.assertEqual(cite, {"source": "cycles", "issue": "blotter issue 1193", "item": CYCLES, "verdict": "pass", "reasons": [],
                                "identity": {"job": "workspace", "module": None, "receipt_sha256": "b" * 64,
                                             "judge_sha256": "d" * 64}})
        self.assertEqual(receipt["evidence"]["lanes"]['["workspace", null]'].get("judge_sha256"), "d" * 64)
        hardware = column(receipt, "controller-reset", "safety")["structural"]["kinds"]["hardware"]["citations"][0]
        self.assertEqual(hardware["identity"], receipt["evidence"]["packages"]["CR-1"])

    def test_a_catalog_record_credits_only_when_its_lane_judged_it_without_a_refusal(self):
        def verdict(result):
            receipt, _ = run(inputs={"revision": REV, "lanes": [{"job": "workspace", "module": None,
                                                                 "evidence": "w"}]}, results={"w": result})
            cites = column(receipt, "host-loss", "safety")["structural"]["kinds"]["simulation"]["citations"]
            return cites[0]["verdict"], cites[0]["reasons"]

        self.assertEqual(verdict(lane(CYCLES)), ("pass", []))
        self.assertEqual(verdict(lane(CYCLES, refusals=[("missing-result", "other-record")])), ("pass", []))
        self.assertEqual(verdict(lane(CYCLES, refusals=[("missing-result", CYCLES)])),
                         ("inconclusive", ["missing-result: missing-result reason"]))
        self.assertEqual(verdict(lane(CYCLES, refusals=[("unbound-revision", None)])),
                         ("inconclusive", ["unbound-revision: unbound-revision reason"]))
        self.assertEqual(verdict(lane("other-record")), ("inconclusive", ["the lane's credit judged no such record"]))
        self.assertEqual(verdict(lane(CYCLES, blocked={CYCLES: {"case": "END"}})),
                         ("inconclusive", ["withheld at ['END']"]))
        self.assertEqual(verdict(acc.Refusal("verify-receipts credited nothing")),
                         ("inconclusive", ["refused: Refusal: verify-receipts credited nothing"]))
        receipt, _ = run(inputs={"revision": REV, "lanes": [{"job": "workspace", "module": None, "evidence": "w"}]},
                         results={"w": lane(CYCLES)})
        seeds = column(receipt, "host-loss", "progress")["structural"]["kinds"]["simulation"]["citations"][1]
        self.assertEqual((seeds["item"], seeds["verdict"], seeds["reasons"]),
                         (SEEDS, "unrun", ["no lane evidence for job long-run"]))
        self.assertEqual(column(receipt, "host-loss", "progress")["structural"]["kinds"]["simulation"]["verdict"],
                         "inconclusive")
        conservation = column(receipt, "host-loss", "conservation")["structural"]["kinds"]["simulation"]
        self.assertEqual((conservation["verdict"], conservation["reason"]),
                         ("unrun", "no simulation citation for this column"))

    def test_an_unrun_kind_keeps_a_structural_column_from_passing(self):
        self.assertEqual([acc.combine(v) for v in (["pass", "unrun"], ["unrun", "unrun"], ["pass", "pass"], [])],
                         ["inconclusive", "unrun", "pass", "inconclusive"])
        record, ctx = lifted()
        results = credited_results()
        results["quint"] = lane()
        with mock.patch.dict(acc.ROWS, WIDE_ROWS):
            receipt, _ = run(record, full_inputs(), results, ctx)
        safety = column(receipt, "host-loss", "safety")["structural"]
        self.assertEqual({k: v["verdict"] for k, v in safety["kinds"].items()},
                         {"model": "inconclusive", "simulation": "pass", "hardware": "pass", "store": "pass"})
        safety = column(receipt, "same-host-restart", "safety")["structural"]
        self.assertEqual(({k: v["verdict"] for k, v in safety["kinds"].items()}, safety["verdict"]), (
            {"model": "unrun", "simulation": "pass", "hardware": "pass", "store": "pass"}, "inconclusive"))

    def test_a_package_verdict_passes_only_from_a_credited_package_of_its_class_at_the_revision(self):
        def hardware(result, col="retention"):
            receipt, _ = run(inputs={"revision": REV, "packages": {"CR-1": "cr"}}, results={"cr": result})
            return receipt, column(receipt, "controller-reset", col)["structural"]["kinds"]["hardware"]

        _, kind = hardware(package("CR-1"))
        self.assertEqual(kind["verdict"], "pass")
        _, kind = hardware(package("CR-1", credited=False))
        self.assertEqual(kind["verdict"], "inconclusive")
        self.assertIn("the package is uncredited: no repeat count", kind["citations"][0]["reasons"])
        receipt, kind = hardware(package("CR-1", {"retention": "fail RetainedSetServed"}, credited=False))
        self.assertEqual((kind["verdict"], kind["citations"][0]["reasons"][0]), ("fail", "fail RetainedSetServed"))
        self.assertEqual(receipt["classes"]["controller-reset"]["verdict"], "fail")
        safety = column(receipt, "controller-reset", "safety")["structural"]["kinds"]["hardware"]["citations"][0]
        self.assertEqual((safety["verdict"], safety["reasons"][0]), ("inconclusive", "the package is uncredited: "
                                                                                     "no repeat count"))
        self.assertEqual(receipt["classes"]["process-kill"]["verdict"], "inconclusive")
        _, kind = hardware(package("CR-1", revision="d" * 40))
        self.assertEqual(kind["verdict"], "inconclusive")
        _, kind = hardware(package("CR-1", {"retention": "fail RetainedSetServed"}, revision="d" * 40))
        self.assertEqual(kind["verdict"], "inconclusive")
        self.assertIn(f"the package ran at {'d' * 40}, not {REV}", kind["citations"][0]["reasons"])
        _, kind = hardware(package("PK-1"))
        self.assertEqual((kind["verdict"], kind["citations"][0]["reasons"]), (
            "inconclusive", ["the campaign is package PK-1 of class process-kill, not CR-1 of controller-reset"]))
        _, kind = hardware(package("PK-1", {"retention": "fail RetainedSetServed"}))
        self.assertEqual(kind["verdict"], "inconclusive")
        receipt, _ = run(inputs={"revision": REV, "packages": {"CR-1": "cr", "PK-1": "cr"}},
                         results={"cr": package("CR-1")})
        self.assertEqual(column(receipt, "process-kill", "safety")["structural"]["kinds"]["hardware"]["verdict"],
                         "inconclusive")
        for col in ("conservation",):
            _, kind = hardware(package("CR-1"), col)
            self.assertEqual((kind["verdict"], kind["reason"]), ("unrun", "no hardware citation for this column"))
        _, kind = hardware(acc.rp.Refusal("the campaign names no 40-hex revision"))
        self.assertEqual((kind["verdict"], kind["citations"][0]["reasons"]),
                         ("inconclusive", ["refused: Refusal: the campaign names no 40-hex revision"]))

    def test_a_comparison_row_reads_only_its_own_frame_class_and_credits_only_unfaulted(self):
        def kinds(result, cls="host-loss", col="progress"):
            paths = dict.fromkeys(("host-loss", "same-host-restart"), "cmp")
            receipt, fake = run(inputs={"revision": REV, "comparisons": paths},
                                results={"cmp": result})
            self.assertEqual(fake.calls, ["cmp"])
            return column(receipt, cls, col)["structural"]["kinds"]["hardware"]

        only_restart = comparison(classes=("same-host-restart",))
        self.assertEqual(kinds(only_restart, "same-host-restart")["verdict"], "pass")
        self.assertEqual(kinds(only_restart, "host-loss")["verdict"], "inconclusive")
        labeled = kinds(comparison(label=mf.COLUMNS["hardware"]))
        self.assertEqual((labeled["verdict"], labeled["citations"][0]["reasons"]),
                         ("inconclusive", ["Inconclusive: platform row unsupported"]))
        labeled = kinds(comparison(label=mf.COLUMNS["hardware"], rows={"first_safe_hit/recovery": "fail"}))
        self.assertEqual(labeled["verdict"], "inconclusive")
        for name in ("always-miss", "leaked-capacity"):
            for col in ("progress", "retention", "conservation"):
                withheld = kinds(comparison(withheld=[f"control {name} is unrun"]), col=col)
                self.assertEqual(withheld["verdict"], "inconclusive", (name, col))
                self.assertIn(f"control {name} is unrun", withheld["citations"][0]["reasons"])
        faulted = comparison()
        faulted["receipt"]["reasons"] = ["header rate 5 is not the qualification's offered rate 4"]
        self.assertEqual(kinds(faulted)["verdict"], "inconclusive")
        self.assertEqual(kinds(comparison(rows={"first_safe_hit/recovery": "fail"}))["verdict"], "fail")
        self.assertEqual(kinds(comparison(rows={"first_safe_hit/recovery": "fail"}), col="conservation")["verdict"],
                         "pass")
        self.assertEqual(kinds(comparison(revision="d" * 40))["verdict"], "inconclusive")
        self.assertEqual(kinds(comparison(rows={"first_safe_hit/recovery": "fail"}, revision="d" * 40))["verdict"],
                         "inconclusive")
        patched = kinds(comparison(patch="7" * 64))
        self.assertEqual(patched["verdict"], "inconclusive")
        self.assertIn(f"with patch {'7' * 64}", patched["citations"][0]["reasons"][0])
        exploratory = {"receipt": {"campaign_sha256": "e" * 64, "verdict": "exploratory",
                                   "reasons": ["the campaign names no policy version, so it counts for nothing"]},
                       "revision": None, "patch": None}
        self.assertEqual(kinds(exploratory)["citations"][0]["reasons"], [
            "the comparison reads exploratory: the campaign names no policy version, so it counts for nothing"])

    def test_h_is_scored_under_r6_and_the_frozen_policy_and_f_is_declared_apart(self):
        receipt, _ = run(inputs={"revision": REV, "comparisons": {"host-loss": "cmp"}},
                         results={"cmp": comparison(outcome="inconclusive")})
        members = column(receipt, "host-loss", "progress")["quantitative"]["members"]
        policy, frame = CTX["records"]["policy"][0], CTX["records"]["frame"][0]
        h = members["hit_latency"]
        self.assertEqual(h["ceilings"], {"nominal": {"p90_ms": 1.0, "p99_ms": 3.0},
                                         "large_object": {"p90_ms": 1.0, "p99_ms": 5.0}})
        self.assertEqual((h["source"], h["boundary"], h["qualification_sha256"]),
                         ("#137", policy["h"]["boundary"], frame["hit_gate"]["qualification_sha256"]))
        self.assertEqual(h["hit_gate"], {"verdict": "inconclusive", "receipt_sha256": "f" * 64})
        self.assertEqual(members["fill_latency"], {
            "budget_ms": None, "verdict": "inconclusive", "boundary": policy["f"]["boundary"], "percentile": None,
            "reasons": ["fill_latency declares no accepted budget",
                        "the policy declares no F percentile, so fill_latency's measured value is undefined"]})
        self.assertEqual(set(members), {"first_safe_hit", "sustained_fill_readiness", "rto", "request_tail",
                                        "goodput", "hit_latency", "fill_latency"})
        unscored = column(receipt, "process-kill", "progress")["quantitative"]["members"]
        self.assertEqual((unscored["hit_latency"]["verdict"], set(unscored["fill_latency"])),
                         ("unscored", {"budget_ms", "verdict", "reasons"}))
        self.assertEqual(column(receipt, "same-host-restart", "conservation")["quantitative"]["members"]["peak_ram"][
            "verdict"], "unrun")

    @mock.patch.dict(acc.ROWS, WIDE_ROWS)
    def test_a_quantitative_member_reads_its_own_class_and_member_and_passes_only_with_its_inputs(self):
        record, ctx = lifted()
        result = comparison(outcome="inconclusive", outcomes={("warm-takeover", "rto"): "pass"})
        receipt, _ = run(record, {"revision": REV, "comparisons": dict.fromkeys(("host-loss", "same-host-restart"),
                                                                               "cmp")}, {"cmp": result}, ctx)
        rows = {(cls, m): row["verdict"] for cls in ("host-loss", "same-host-restart")
                for m, row in column(receipt, cls, "progress")["quantitative"]["members"].items()}
        self.assertEqual({key for key, v in rows.items() if v == "pass"}, {("host-loss", "rto")})
        unbudgeted = copy.deepcopy(ctx)
        unbudgeted["records"]["policy"][0]["budgets"]["warm-takeover"]["rto"] = None
        receipt, _ = run(record, {"revision": REV, "comparisons": {"host-loss": "cmp"}}, {"cmp": comparison()},
                         unbudgeted)
        self.assertEqual((member(receipt)["verdict"], member(receipt)["reasons"]),
                         ("inconclusive", ["rto declares no accepted budget"]))
        for label, result in (("another revision", comparison(revision="d" * 40)),
                              ("a labeled column", comparison(label=mf.COLUMNS["hardware"])),
                              ("a withheld control", comparison(withheld=["control always-miss is unrun"]))):
            with self.subTest(label):
                receipt, _ = run(record, {"revision": REV, "comparisons": {"host-loss": "cmp"}}, {"cmp": result}, ctx)
                self.assertEqual(member(receipt)["verdict"], "inconclusive")
        receipt, _ = run(record, {"revision": REV, "comparisons": {"host-loss": "cmp"}},
                         {"cmp": acc.Refusal("no campaign")}, ctx)
        self.assertEqual((member(receipt)["verdict"], member(receipt)["reasons"]),
                         ("inconclusive", ["refused: Refusal: no campaign"]))

    def test_missing_owner_inputs_keep_passing_evidence_inconclusive(self):
        receipt, _ = run(inputs=full_inputs())
        retention = column(receipt, "host-loss", "retention")
        handoff = CTX["document"]["qualification"]["preservation"]["handoff"]
        self.assertEqual(retention["structural"]["kinds"]["simulation"]["verdict"], "pass")
        self.assertEqual(retention["structural"]["kinds"]["hardware"]["verdict"], "pass")
        self.assertEqual(retention["structural"]["verdict"], "inconclusive")
        self.assertIn(handoff, retention["structural"]["reasons"])
        quantitative = retention["quantitative"]
        self.assertEqual((quantitative["verdict"], [m["verdict"] for m in quantitative["members"].values()]),
                         ("inconclusive", ["inconclusive", "inconclusive"]))
        self.assertIn("retained_hit_recovery declares no accepted budget",
                      quantitative["members"]["retained_hit_recovery"]["reasons"])
        self.assertIn("the frame names no frozen population manifest, so the blocks' workload is unfrozen",
                      quantitative["reasons"])
        self.assertIn("the envelope declares no n_max, so the blocks' header is unfrozen", quantitative["reasons"])
        self.assertIn(handoff, quantitative["reasons"])
        cold = column(receipt, "actual-volume-loss", "retention")
        self.assertEqual((cold["structural"]["verdict"], list(cold["quantitative"]["members"])),
                         ("not claimed", ["origin_demand"]))
        self.assertNotIn(handoff, cold["quantitative"]["reasons"])
        self.assertEqual(list(column(receipt, "actual-volume-loss", "conservation")["quantitative"]["members"]),
                         ["peak_ram"])
        self.assertEqual(receipt["classes"]["controller-reset"]["columns"]["safety"]["structural"]["kinds"]["model"][
            "verdict"], "unrun")
        self.assertEqual((receipt["verdict"], receipt["accepted"]), ("inconclusive", False))

    def test_a_warm_class_passes_only_once_every_kind_and_owner_gate_is_lifted(self):
        record, ctx = lifted()
        with mock.patch.dict(acc.ROWS, WIDE_ROWS):
            receipt, _ = run(record, full_inputs(), ctx=ctx)
            self.assertEqual(receipt["classes"]["host-loss"]["verdict"], "pass")
            self.assertEqual(receipt["classes"]["same-host-restart"]["verdict"], "inconclusive")
            self.assertEqual(receipt["classes"]["controller-reset"]["verdict"], "inconclusive")
            self.assertFalse(receipt["accepted"])
            for missing in ("preservation", "population", "envelope", "class list", "alpha", "power", "lane", "budget"):
                with self.subTest(missing):
                    r_ctx, results = copy.deepcopy(ctx), credited_results()
                    if missing == "preservation":
                        r_ctx["document"]["qualification"]["preservation"]["qualified"] = False
                    elif missing == "population":
                        r_ctx["records"]["frame"][0]["population"]["manifest"] = None
                    elif missing == "envelope":
                        r_ctx["records"]["frame"][0]["envelope"]["n_max"] = None
                    elif missing == "class list":
                        r_ctx["records"]["policy"][0]["class_list"] = None
                    elif missing in ("alpha", "power"):
                        key = {"alpha": "familywise_alpha", "power": "power"}[missing]
                        r_ctx["records"]["statistics"][0][key]["status"] = "provisional"
                    elif missing == "budget":
                        r_ctx["records"]["policy"][0]["budgets"]["warm-takeover"]["goodput"] = None
                    else:
                        results["workspace"] = lane(*(r for r in results["workspace"]["obligations"] if r != CYCLES))
                    receipt, _ = run(record, full_inputs(), results, r_ctx)
                    self.assertEqual(receipt["classes"]["host-loss"]["verdict"], "inconclusive")
                    if missing == "preservation":
                        retention = column(receipt, "host-loss", "retention")
                        self.assertEqual((retention["structural"]["verdict"], retention["quantitative"]["verdict"]),
                                         ("inconclusive", "inconclusive"))
                        self.assertEqual(column(receipt, "host-loss", "progress")["quantitative"]["verdict"], "pass")

    def test_acceptance_needs_every_class_to_pass_and_no_open_gate(self):
        def accepted(gates, verdicts):
            classes = iter(verdicts)
            with mock.patch.object(acc, "check", return_value=(gates, [])), \
                    mock.patch.object(acc, "judge_class", side_effect=lambda *_: {"verdict": next(classes)}):
                return run()[0]["accepted"]

        count = len(RECORD["classes"])
        self.assertTrue(accepted([], ["pass"] * count))
        self.assertFalse(accepted(["a gate"], ["pass"] * count))
        self.assertFalse(accepted([], ["pass"] * (count - 1) + ["inconclusive"]))
        with mock.patch.object(acc, "judge", return_value={"accepted": True}), \
                tempfile.TemporaryDirectory(prefix="acceptance-") as temp:
            (Path(temp) / "in.json").write_text("{}")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(acc.main(["judge", "--inputs", str(Path(temp) / "in.json")]), 0)

    def test_the_reopen_claim_opens_only_on_credited_namespace_and_coverage_records(self):
        def requiring(**requires):
            def edit(r):
                store_source(r, STORE_RECORD, COVERAGE_RECORD)
                r["reopen"]["requires"].update(requires)
            return edited(edit)

        record = requiring(namespace=[STORE_RECORD], coverage=[COVERAGE_RECORD])
        inputs = {"revision": REV, "lanes": [{"job": "workspace", "module": None, "evidence": "w"}]}
        receipt, _ = run(record, inputs, {"w": lane(STORE_RECORD, COVERAGE_RECORD)}, STORE_CTX)
        self.assertEqual((receipt["reopen"]["verdict"], receipt["reopen"]["reasons"]), ("open", []))
        receipt, _ = run(record, inputs, {"w": lane(STORE_RECORD)}, STORE_CTX)
        self.assertEqual(receipt["reopen"]["verdict"], "closed")
        self.assertEqual(receipt["reopen"]["reasons"],
                         [f"coverage record {COVERAGE_RECORD} is uncredited: the lane's credit judged no such record"])
        receipt, _ = run(requiring(namespace=[STORE_RECORD, COVERAGE_RECORD]), inputs,
                         {"w": lane(STORE_RECORD, COVERAGE_RECORD)}, STORE_CTX)
        self.assertEqual((receipt["reopen"]["verdict"], receipt["reopen"]["reasons"]),
                         ("closed", ["no coverage record"]))

    def test_sizing_scenarios_join_their_frame_class_with_no_verdict(self):
        sizing = {"scenarios": {
            "standby-takeover": {"class": "warm-takeover", "label": "conditional scenario",
                                 "probability": "not identified", "binding": "volume_read"},
            "actual-volume-loss": {"class": "volume-loss-control", "label": "conditional scenario",
                                   "probability": "not identified", "binding": None, "withheld": ["row x"]}}}
        receipt, _ = run(inputs={"revision": REV, "sizing": "s"}, results={"s": sizing})
        self.assertEqual(receipt["classes"]["host-loss"]["sizing"], [
            {"scenario": "standby-takeover", "label": "conditional scenario", "probability": "not identified",
             "binding": "volume_read", "withheld": None, "verdict": "none"}])
        self.assertEqual([s["scenario"] for s in receipt["classes"]["actual-volume-loss"]["sizing"]],
                         ["actual-volume-loss"])
        self.assertEqual(receipt["classes"]["same-host-restart"]["sizing"], [])
        self.assertEqual(receipt["classes"]["controller-reset"]["sizing"], [])
        self.assertEqual(receipt["evidence"]["sizing"], mf.canonical(sizing))

    def test_the_inputs_file_is_refused_off_its_shape(self):
        lanes = [{"job": "workspace", "module": None, "evidence": "w"}]
        cases = {
            "a short revision": ({"revision": "c" * 39}, "no 40-hex revision"),
            "an extra key": ({"revision": REV, "receipts": []}, "keys within"),
            "an unknown package": ({"revision": REV, "packages": {"FIS": "f"}}, "packages name paths of"),
            "a comparison for a class without a frame class": (
                {"revision": REV, "comparisons": {"controller-reset": "c"}}, "comparisons name paths of"),
            "two lanes of one job": ({"revision": REV, "lanes": lanes * 2}, "two lanes name one job and module"),
            "a lane without its module": ({"revision": REV, "lanes": [{"job": "workspace", "evidence": "w"}]},
                                          "a lane is not {job, module, evidence}"),
            "a sizing input that is no path": ({"revision": REV, "sizing": 7}, "sizing names an inputs file"),
        }
        for label, (inputs, message) in cases.items():
            with self.subTest(label), self.assertRaises(acc.Refusal) as caught:
                run(inputs=inputs, results={})
            self.assertIn(message, str(caught.exception))

    def test_lane_identities_are_keyed_by_job_and_module(self):
        lanes = [{"job": "a b", "module": None, "evidence": "x"}, {"job": "a", "module": "b", "evidence": "y"}]
        receipt, _ = run(inputs={"revision": REV, "lanes": lanes}, results={"x": lane(), "y": lane("other")})
        self.assertEqual(set(receipt["evidence"]["lanes"]), {'["a b", null]', '["a", "b"]'})


class LaneAdapter(unittest.TestCase):
    """Judges.lane against a stubbed credit child, so the adapter's own binding, deadline and report rules decide."""

    def credit(self, evidence, child):
        with mock.patch.object(acc.subprocess, "run", side_effect=child):
            return acc.Judges(CTX, LANE, None).lane("workspace", None, evidence, REV)

    def refused(self, evidence, child, message):
        with self.assertRaises(acc.Refusal) as caught:
            self.credit(evidence, child)
        self.assertIn(message, str(caught.exception))

    def test_the_adapter_binds_the_receipt_the_child_judged_and_names_each_failure(self):
        seen = []

        def child(argv, **_):
            seen.append(argv)
            return subprocess.CompletedProcess(argv, 0, b'{"obligations": [], "refusals": []}\n', b"")

        with tempfile.TemporaryDirectory(prefix="acceptance-") as temp:
            d = Path(temp) / "nested" / "lane"
            d.mkdir(parents=True)
            (d / "receipt.json").write_text("{}")
            here = os.getcwd()
            os.chdir(temp)
            try:
                result = self.credit("nested/lane", child)
            finally:
                os.chdir(here)
            self.assertEqual(result["receipt_sha256"], hashlib.sha256(b"{}").hexdigest())
            self.assertEqual(result.get("judge_sha256"), VERIFIER_SHA256)
            self.assertEqual(seen[0][seen[0].index("--evidence") + 1], str(d.resolve()))
            self.assertIn("--read-only", seen[0])

            def swap(argv, **kwargs):
                (d / "receipt.json").write_text('{"swapped": true}')
                return child(argv, **kwargs)
            self.refused(str(d), swap, "changed while it was judged")
            (d / "receipt.json").write_text("{}")
            (Path(temp) / "verify-receipts.py").write_text("judge")

            def rewrite(argv, **kwargs):
                (Path(temp) / "verify-receipts.py").write_text("another judge")
                return child(argv, **kwargs)
            with mock.patch.object(acc, "HERE", Path(temp)):
                self.refused(str(d), rewrite, "changed while it was judged")

            def late(argv, **_):
                raise subprocess.TimeoutExpired(argv, acc.LANE_TIMEOUT)
            self.refused(str(d), late, f"ran past {acc.LANE_TIMEOUT} s")

            def silent(argv, **_):
                return subprocess.CompletedProcess(argv, 2, b"", b"usage\nthe tlc job needs --module\n")
            self.refused(str(d), silent, "(exit 2): no report; the tlc job needs --module")
            self.refused(str(Path(temp) / "missing"), child, "is no directory")
            (d / "artifacts").mkdir()
            for name, make in (("run.txt", lambda path: path.symlink_to("/dev/zero")), ("run.txt", os.mkfifo),
                               ("artifacts/input", lambda path: path.symlink_to(d / "receipt.json"))):
                make(d / name)
                self.refused(str(d), child, f"holds {name!r}, a symbolic link or special file")
                (d / name).unlink()
            (d / "run.txt").symlink_to("/dev/zero")
            os.chmod(d, 0o100)
            try:
                self.refused(str(d), child, "cannot be listed" if os.geteuid() else "holds 'run.txt'")
            finally:
                os.chmod(d, 0o700)
            (d / "run.txt").unlink()
            (d / "artifacts/input").write_text("a regular file")
            self.credit(str(d), child)
            (d / "receipt.json").write_text(json.dumps({"inputs": {"/dev/zero": "0"}}))
            self.refused(str(d), child, "names an input outside the repository and its evidence")
            self.assertEqual(len(seen), 4)


def member(receipt):
    return column(receipt, "host-loss", "progress")["quantitative"]["members"]["rto"]


def written(directory):
    return gate.parse(gate.read_file(directory / "out.json", "acceptance receipt"), "acceptance receipt")


class Command(unittest.TestCase):
    def main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = acc.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_the_cli_checks_and_judges_through_the_real_judges_and_refuses_with_exit_2(self):
        code, out, _ = self.main("check")
        self.assertEqual(code, 0)
        self.assertEqual(gate.parse(out, "check output")["gates"], acc.check(RECORD, CTX)[0])
        with tempfile.TemporaryDirectory(prefix="acceptance-") as temp:
            d = Path(temp)
            (d / "lane").mkdir()
            (d / "lane/receipt.json").write_text("{}")
            (d / "cmp.json").write_text(json.dumps({"campaign": "measure-0"}))
            (d / "pkg.json").write_text(json.dumps({"campaign": "x", "package": "CR-1", "runs": []}))
            (d / "sizing.json").write_text(json.dumps({"receipt": {"path": "no-such-receipt.json",
                                                                   "sha256": "0" * 64}, "values": {}}))
            revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True,
                                      check=True).stdout.strip()
            lanes = [{"job": "workspace", "module": None, "evidence": str(d / "lane")}]
            inputs = {"revision": revision, "lanes": lanes, "sizing": str(d / "sizing.json"),
                      "packages": {"CR-1": str(d / "pkg.json")}, "comparisons": {"host-loss": str(d / "cmp.json")}}
            (d / "in.json").write_text(json.dumps(inputs))
            (d / "summary.md").write_text("")
            (d / "lane/credit.json").write_text("kept")
            os.chmod(d / "lane", 0o500)
            try:
                with mock.patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(d / "summary.md")}):
                    code, _, err = self.main("judge", "--inputs", str(d / "in.json"), "--output", str(d / "out.json"))
            finally:
                os.chmod(d / "lane", 0o700)
            self.assertEqual(code, 1, err)
            self.assertEqual(sorted(p.name for p in (d / "lane").iterdir()), ["credit.json", "receipt.json"])
            self.assertEqual((d / "lane/credit.json").read_text(), "kept")
            self.assertEqual((d / "summary.md").read_text(), "")
            receipt = written(d)
            self.assertEqual(receipt["verdict"], "inconclusive")
            lanes = receipt["evidence"]["lanes"]
            self.assertIsInstance(lanes.get('["workspace", null]'), dict, lanes)
            self.assertFalse(lanes['["workspace", null]']["credited"])
            cite = column(receipt, "host-loss", "safety")["structural"]["kinds"]["simulation"]["citations"][0]
            self.assertEqual(cite["verdict"], "inconclusive")
            self.assertIn(f"unbound-revision: receipt revision None, expected {revision}", cite["reasons"])
            self.assertIn("the campaign names no 40-hex revision", receipt["evidence"]["packages"]["CR-1"])
            hardware = column(receipt, "host-loss", "retention")["structural"]["kinds"]["hardware"]
            self.assertEqual(hardware["citations"][0]["reasons"], [
                "the comparison reads exploratory: the campaign names no policy version, so it counts for nothing"])
            sizing = {s["scenario"]: s["label"] for s in receipt["classes"]["host-loss"]["sizing"]}
            self.assertTrue(sizing and all(label for label in sizing.values()), sizing)
            self.assertTrue(receipt["classes"]["actual-volume-loss"]["sizing"])
            self.assertEqual(receipt["record_sha256"], hashlib.sha256(acc.RECORD.read_bytes()).hexdigest())
            self.assertEqual(receipt["evidence"]["lanes"]['["workspace", null]']["receipt_sha256"],
                             hashlib.sha256(b"{}").hexdigest())
            self.assertEqual(receipt["evidence"]["lanes"]['["workspace", null]'].get("judge_sha256"), VERIFIER_SHA256)
            records = CTX["records"]
            campaign = {**{k: mf.pin(records, k) for k in mf.KINDS}, "header": dict.fromkeys(mf.HEADER),
                        "revision": {"commit": revision, "patch_sha256": mf.NO_PATCH}}
            campaign["campaign"] = mf.campaign_id({k: (None, campaign[k]["sha256"]) for k in mf.KINDS}, revision,
                                                  mf.NO_PATCH)
            (d / "cmp2.json").write_text(json.dumps(campaign))
            (d / "pkg2.json").write_text(json.dumps({"campaign": "x", "package": "CR-1", "revision": revision,
                                                     "runs": []}))
            (d / "in2.json").write_text(json.dumps({"revision": revision, "packages": {"CR-1": str(d / "pkg2.json")},
                                                    "comparisons": {"host-loss": str(d / "cmp2.json")}}))
            code, _, err = self.main("judge", "--inputs", str(d / "in2.json"), "--output", str(d / "out.json"))
            self.assertEqual(code, 1, err)
            real = written(d)
            package_cite = column(real, "controller-reset", "safety")["structural"]["kinds"]["hardware"]["citations"][0]
            self.assertEqual(package_cite["verdict"], "inconclusive")
            self.assertTrue(any(r.startswith("the package is uncredited") for r in package_cite["reasons"]))
            row = column(real, "host-loss", "progress")["structural"]["kinds"]["hardware"]["citations"][0]
            self.assertEqual(row["verdict"], "inconclusive")
            self.assertIn(mf.COLUMNS["hardware"], row["reasons"])
            self.assertIn("control always-miss is unrun", row["reasons"])
            members = column(real, "host-loss", "progress")["quantitative"]["members"]
            self.assertEqual(members["rto"]["verdict"], "inconclusive")
            self.assertIsNone(members["hit_latency"]["hit_gate"]["receipt_sha256"])
            catalog = d / "catalog.json"
            catalog.write_bytes(gate.read_file(gate.OBLIGATIONS, "catalog") + b"\n")
            code, _, err = self.main("judge", "--inputs", str(d / "in.json"), "--obligations", str(catalog),
                                     "--output", str(d / "out.json"))
            self.assertEqual(code, 1, err)
            self.assertIn("credits against the committed catalog", written(d)["evidence"]["lanes"][
                '["workspace", null]'])
            (d / "bad.json").write_text(json.dumps({"revision": "HEAD"}))
            code, _, err = self.main("judge", "--inputs", str(d / "bad.json"))
            self.assertEqual(code, 2)
            self.assertIn("acceptance: refused: malformed inputs file: no 40-hex revision", err)
            (d / "record.json").write_text(json.dumps(edited(lambda r: r["retention"]["never"].pop())))
            code, _, err = self.main("check", "--record", str(d / "record.json"))
            self.assertEqual(code, 2)
            self.assertIn("never satisfy preservation", err)


if __name__ == "__main__":
    unittest.main()
