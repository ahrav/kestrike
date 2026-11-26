#!/usr/bin/env python3
"""Judge the recorded runs and the cases built from them, and check the harness and the shared module.

    python3 chaos/tests/test_judges.py

The runs under chaos/tests/runs/ are real runs of the harness, recorded as chaos/tests/README.md
states. Every other case is built here from one of them in a temporary directory: each edits a
copy of a recorded run the way one falsifier of the verdict mapping describes. The validity judge
shows exits 0, 2 and 3, and the invariant judge exits 0, 1, 2 and 3. The harness runs against a
fake campaign binary in a temporary tree, so this test starts no sweep. That tree's harness takes
its plain directory for a cgroup v2 one; the refusal of a plain directory is tested on the
harness as it stands.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
import py_compile
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from typing import Any

TESTS = Path(__file__).resolve().parent
CHAOS = TESTS.parent
ROOT = CHAOS.parent
RUNS = TESTS / "runs"
RECEIPTS = TESTS / "receipts"
VALIDITY = "chaos/judges/core/validity.py"
INVARIANT = "chaos/judges/core/invariant.py"
UPLOAD, CLUSTER, H1 = "ks-upload-no-fault", "ks-cluster-link-faults", "ks-h1-get-stale-declared"
BOUND, NEWER, H1_RULE_ROW = "ks-bound-record-passes-its-checks", "ks-get-not-older-than-collected", "ks-qualified-get-reads-visible-bytes"
BOUND_RULE = "a bound slot's record fails its header or chunk checks"
REACHED = "ks-required-events-reached"
NEWER_RULE = "a GET returned a version older than one collected or removed before it"
ORDERING = "ks-ordering-controls-caught"
H1_RULE = "a qualified GET missed the visible version's exact bytes"
HELD, BROKEN, INVALID, INCOMPLETE = 0, 1, 2, 3

# RECORDED maps each recorded run to its ledger tree and each judged row to its exit code and a detail substring.
RECORDED = {
    "fixture-upload-live": ("ledger", {UPLOAD: (HELD, "valid: upload"), BOUND: (HELD, "no violation under the row's rule")}),
    "fixture-cluster-live": ("ledger", {CLUSTER: (HELD, "reached faults, hits, invalidated"),
                                        NEWER: (HELD, "no violation under the row's rule"),
                                        BOUND: (HELD, "no violation under the row's rule")}),
    "fixture-upload-corrupted": ("ledger", {UPLOAD: (HELD, "control corrupted"), BOUND: (BROKEN, BOUND_RULE)}),
    "fixture-cluster-stale-read": ("ledger", {CLUSTER: (HELD, "control cluster-stale-read"), NEWER: (BROKEN, NEWER_RULE),
                                              BOUND: (INVALID, "no caught run under the row's rule")}),
    "fixture-upload-asserting": ("ledger", {UPLOAD: (INVALID, "alarm"), BOUND: (INVALID, "alarm")}),
    "fixture-upload-interrupted": ("ledger", {UPLOAD: (INCOMPLETE, "does not mark the run complete"),
                                              BOUND: (INCOMPLETE, "does not mark the run complete")}),
    "fixture-h1-get-stale-live": ("tests", {H1: (HELD, "h1-get-stale"), H1_RULE_ROW: (BROKEN, H1_RULE)}),
}


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


sys.dont_write_bytecode = True
common = load_module("chaos_common", CHAOS / "judges" / "core" / "common.py")
harness = load_module("chaos_harness", CHAOS / "harness" / "run_scenario.py")
validator = load_module("chaos_validator", CHAOS / "tools" / "validate_contract.py")


def defaults() -> None:
    """Set the three stop signals to their defaults in a child the test starts."""
    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(number, signal.SIG_DFL)


def violation_key(code: int, rule: str) -> str:
    """A version 2 failure identity of a check's violation, in the supervisor's record format, with the rule's SHA-256."""
    return f"violation: 0201{code:02x}00010000{hashlib.sha256(rule.encode('utf-8')).hexdigest()}0000000000"


class Trees:
    """The temporary repository trees the judges run in: the repository's own, and one whose ledger is the test's."""

    def __init__(self) -> None:
        self.scratch = Path(tempfile.mkdtemp(prefix="chaos-judges-"))
        self.trees = {"ledger": ROOT, "tests": self.tree("tests", TESTS / "ledger.json"),
                      "judged": self.tree("judged", CHAOS / "ledger.json")}
        self.cases = 0

    def tree(self, name: str, ledger: Path) -> Path:
        top = self.scratch / name
        (top / "chaos").mkdir(parents=True)
        shutil.copytree(CHAOS / "judges", top / "chaos" / "judges")
        shutil.copytree(CHAOS / "harness", top / "chaos" / "harness")
        shutil.copy(ledger, top / "chaos" / "ledger.json")
        return top

    def receipt(self, name: str, tree: Path | None = None) -> Path:
        """A receipt path under chaos/receipts/ of a temporary tree, by default the copy of the repository's tree."""
        folder = (tree or self.trees["judged"]) / "chaos" / "receipts" / "cases"
        folder.mkdir(parents=True, exist_ok=True)
        return folder / name

    def case(self, run_id: str, name: str | None = None) -> Path:
        """A fresh copy of a recorded run's evidence, in a directory named `name` (the run id unless given)."""
        self.cases += 1
        target = self.scratch / "cases" / str(self.cases) / (name or run_id)
        shutil.copytree(RUNS / run_id, target)
        return target


def judge(tree: Path, script: str, row: str, evidence: Path, receipt: Path | None = None,
          flags: tuple[str, ...] = ("-I", "-B")) -> tuple[int, str]:
    argv = [sys.executable, *flags, str(tree / script), row, "--evidence", str(evidence)]
    if receipt is not None:
        argv += ["--receipt", str(receipt)]
    done = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=120)
    return done.returncode, done.stdout + done.stderr


def zero_controls(status: dict, *keys: str) -> None:
    """Set `keys` to zero in every entry marked as a control, with its caught_rules emptied when caught is among them."""
    for entry in status["profiles"].values():
        if entry["control"]:
            entry.update(dict.fromkeys(keys, 0))
            if "caught" in keys:
                entry["caught_rules"] = {}


def keyed(status: dict, profile: str, keys: dict[str, int], only: bool = False) -> None:
    """Count suspects of `profile` under `keys`, beside its other keys unless `only`, and in its `suspects` total."""
    entry = status["profiles"][profile]
    entry["suspect_keys"] = {**({} if only else entry["suspect_keys"]), **keys}
    entry["suspects"] = sum(entry["suspect_keys"].values())


def rebound(evidence: Path, ledger: Path, scenario: str) -> None:
    """Record in the run the digest of `scenario`'s row as `ledger` holds it, so the run reads as one of that row."""
    row = next(row for row in json.loads(ledger.read_text(encoding="utf-8"))["scenarios"] if row["id"] == scenario)
    edit_json(evidence / "run.json", lambda run: run.update(scenario_row=common.row_digest(row)))


def edit_json(path: Path, change) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    change(value)
    path.write_text(json.dumps(value, indent=1, sort_keys=True) + "\n", encoding="utf-8")


class Recorded(unittest.TestCase):
    """Each recorded run gets the exit its record names from each judge, with the full rule text in a broken detail."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.trees = Trees()

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.trees.scratch, ignore_errors=True)

    def test_each_recorded_run_gets_its_exit_from_each_judge(self) -> None:
        seen: dict[str, set[int]] = {VALIDITY: set(), INVARIANT: set()}
        for run_id, (tree, rows) in RECORDED.items():
            for row, (code, text) in rows.items():
                script = VALIDITY if row in (UPLOAD, CLUSTER, H1) else INVARIANT
                with self.subTest(run=run_id, row=row):
                    exit_code, output = judge(self.trees.trees[tree], script, row, self.trees.case(run_id))
                    self.assertEqual(exit_code, code, output)
                    self.assertIn(text, output)
                    seen[script].add(exit_code)
        self.assertEqual(seen[VALIDITY], {HELD, INVALID, INCOMPLETE})
        self.assertEqual(seen[INVARIANT], {HELD, BROKEN, INVALID, INCOMPLETE})

    def test_an_unnamed_control_caught_under_the_rule_leaves_the_live_run_held(self) -> None:
        status = json.loads((RUNS / "fixture-cluster-live" / "sweep-status.json").read_text(encoding="utf-8"))
        self.assertGreater(status["profiles"]["cluster-stale-read"]["caught_rules"].get(NEWER_RULE, 0), 0)
        code, output = judge(ROOT, INVARIANT, NEWER, self.trees.case("fixture-cluster-live"))
        self.assertEqual(code, HELD, output)

    def test_each_run_record_names_build_campaign_profiles_counts_and_run_ranges(self) -> None:
        # What replays a run stands in its record.
        for run_id in RECORDED:
            with self.subTest(run=run_id):
                run = json.loads((RUNS / run_id / "run.json").read_text(encoding="utf-8"))
                self.assertEqual(run["campaign"], run_id)
                self.assertRegex(run["system_build"], "^[0-9a-f]{64}$")
                self.assertRegex(run["campaign_binary"]["sha256"], "^[0-9a-f]{64}$")
                self.assertTrue(run["profiles"])
                self.assertEqual(run["counts"], {})
                self.assertIn("root", run)
                if run["complete"]:
                    self.assertEqual(run["root_build"], run["system_build"])
                    self.assertEqual(sorted(run["runs"]), sorted(run["profiles"]))
                    self.assertTrue(all(span["first"] == 0 and span["next"] > 0 for span in run["runs"].values()))

    def test_the_fifth_fences_probe_is_refused_as_its_receipt_records(self) -> None:
        ledger = json.loads((CHAOS / "ledger.json").read_text(encoding="utf-8"))
        fence = next(row for row in ledger["fences"] if row["id"] == "ks-run-keeps-earlier-runs")
        receipt = json.loads((CHAOS / "receipts" / "fences" / f"{fence['id']}.json").read_text(encoding="utf-8"))
        words = fence["probe"]["command"].split()
        self.assertEqual(words[:2], ["python3", "chaos/harness/run_scenario.py"])
        self.assertIn("--dry-run", words)
        done = subprocess.run([sys.executable, *words[1:]], cwd=ROOT, capture_output=True, text=True, check=False, timeout=60)
        self.assertEqual((done.returncode, done.stdout), (2, ""))
        self.assertIn(fence["probe"]["expect"], done.stderr)
        self.assertEqual((receipt["command"], receipt["exit_status"], receipt["output"], receipt["refused"]),
                         (fence["probe"]["command"], done.returncode, done.stderr, True))
        self.assertFalse((CHAOS / "runs" / words[3]).exists())

    def test_each_recorded_run_keeps_receipts_that_name_the_rows_judges_and_harness_of_the_tree(self) -> None:
        # A recorded run stays current only while the rows, the judge files and the harness it ran with are the tree's:
        # whoever changes one records the runs again, and this case fails until then.
        harness_files = harness.directory_digests([CHAOS / "harness"])
        judge_files = harness.directory_digests([CHAOS / "judges" / "core"])
        self.assertEqual(sorted(path.name for path in RECEIPTS.iterdir()), sorted(RECORDED))
        for run_id, (tree, judged) in RECORDED.items():
            ledger = json.loads(((CHAOS if tree == "ledger" else TESTS) / "ledger.json").read_text(encoding="utf-8"))
            rows = {row["id"]: row for name in ("scenarios", "invariants") for row in ledger[name]}
            run = json.loads((RUNS / run_id / "run.json").read_text(encoding="utf-8"))
            with self.subTest(run=run_id):
                self.assertEqual(run["scenario_row"], common.row_digest(rows[run["scenario"]]))
                self.assertEqual(run["harness"], harness_files)
                self.assertEqual(sorted(path.name for path in (RECEIPTS / run_id).iterdir()),
                                 sorted(f"{row}.json" for row in judged))
            for row, (code, _) in judged.items():
                with self.subTest(run=run_id, row=row):
                    receipt = json.loads((RECEIPTS / run_id / f"{row}.json").read_text(encoding="utf-8"))
                    key = receipt["key"]
                    self.assertEqual((key["row"], key["outcome"], key["scenario"], key["mode"], key["defect"],
                                      key["system_build"]),
                                     (row, common.OUTCOMES[code], run["scenario"], run["mode"], run["defect"],
                                      run["system_build"]))
                    self.assertEqual(key["rows"], {row: common.row_digest(rows[row]),
                                                   run["scenario"]: common.row_digest(rows[run["scenario"]])})
                    self.assertEqual(key["judge"], judge_files)
                    self.assertEqual(key["harness"], harness_files)
                    self.assertEqual(key["evidence"], harness.evidence_digests(RUNS / run_id))
                    self.assertEqual((receipt["run"]["run_id"], receipt["run"]["started"]), (run_id, run["started"]))

    def test_no_copy_holds_a_wall_clock_field(self) -> None:
        for run_id in RECORDED:
            for name in ("sweep-status.json", "findings.json", "suspects.jsonl", "history.jsonl"):
                path = RUNS / run_id / name
                if path.exists():
                    text = path.read_text(encoding="utf-8")
                    for key in common.WALL_CLOCK_KEYS:
                        self.assertNotIn(f'"{key}"', text, f"{run_id}/{name}")
            self.assertFalse((RUNS / run_id / "sweep.json").exists())


class Built(unittest.TestCase):
    """Each falsifier of the verdict mapping, built from a recorded run, gets the exit its record names."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.trees = Trees()

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.trees.scratch, ignore_errors=True)

    def both(self, evidence: Path, validity: int, invariant: int, text: str = "", scenario: str = UPLOAD,
             row: str = BOUND, tree: str = "ledger") -> None:
        top = self.trees.trees[tree]
        for script, name, code in ((VALIDITY, scenario, validity), (INVARIANT, row, invariant)):
            exit_code, output = judge(top, script, name, evidence)
            self.assertEqual(exit_code, code, f"{script}: {output}")
            if text:
                self.assertIn(text, output, script)

    def run_edit(self, run_id: str, change) -> Path:
        evidence = self.trees.case(run_id)
        edit_json(evidence / "run.json", change)
        return evidence

    def status_edit(self, run_id: str, change) -> Path:
        evidence = self.trees.case(run_id)
        edit_json(evidence / "sweep-status.json", change)
        return evidence

    # An incomplete or absent run record, and a recorded exit 3 or 4, are incomplete.

    def test_an_absent_run_record_is_incomplete(self) -> None:
        evidence = self.trees.case("fixture-upload-live")
        (evidence / "run.json").unlink()
        self.both(evidence, INCOMPLETE, INCOMPLETE, "no run.json")

    def test_a_run_record_without_complete_is_incomplete(self) -> None:
        self.both(self.run_edit("fixture-upload-live", lambda run: run.pop("complete")), INCOMPLETE, INCOMPLETE)
        # Both judges require the JSON value true in `complete`; a caught control beside any other value is incomplete.
        for value in (False, None, 1, "true"):
            with self.subTest(complete=value):
                evidence = self.run_edit("fixture-upload-corrupted", lambda run, value=value: run.update(complete=value))
                self.both(evidence, INCOMPLETE, INCOMPLETE, "does not mark the run complete")

    def test_a_clean_status_beside_a_recorded_exit_4_is_incomplete(self) -> None:
        self.both(self.run_edit("fixture-upload-live", lambda run: run.update(sweep_exit=4)), INCOMPLETE, INCOMPLETE,
                  "exited 4")

    def test_a_recorded_exit_3_is_incomplete(self) -> None:
        self.both(self.run_edit("fixture-upload-live", lambda run: run.update(sweep_exit=3)), INCOMPLETE, INCOMPLETE)

    def test_a_recorded_exit_4_is_incomplete_even_beside_a_declared_break(self) -> None:
        evidence = self.run_edit("fixture-h1-get-stale-live", lambda run: run.update(sweep_exit=4))
        self.both(evidence, INCOMPLETE, INCOMPLETE, scenario=H1, row=H1_RULE_ROW, tree="tests")

    def test_a_fired_deadline_is_incomplete(self) -> None:
        self.both(self.run_edit("fixture-upload-live", lambda run: run.update(deadline_fired=True)), INCOMPLETE, INCOMPLETE)
        # Both judges require the JSON value false in `deadline_fired`; a caught control beside any other value is incomplete.
        for name, change in (("absent", lambda run: run.pop("deadline_fired")),
                             ("null", lambda run: run.update(deadline_fired=None)),
                             ("zero", lambda run: run.update(deadline_fired=0))):
            with self.subTest(deadline_fired=name):
                self.both(self.run_edit("fixture-upload-corrupted", change), INCOMPLETE, INCOMPLETE, "the run was stopped")

    # The validity judge holds only under the mapping's held row.

    def test_a_clean_status_beside_a_recorded_exit_1_is_never_held(self) -> None:
        self.both(self.run_edit("fixture-upload-live", lambda run: run.update(sweep_exit=1)), INVALID, INVALID,
                  "carry none of")

    def test_a_recorded_exit_2_is_invalid(self) -> None:
        self.both(self.run_edit("fixture-upload-live", lambda run: run.update(sweep_exit=2)), INVALID, INVALID)

    def test_an_empty_status_document_is_invalid(self) -> None:
        evidence = self.trees.case("fixture-upload-live")
        (evidence / "sweep-status.json").write_text("{}\n", encoding="utf-8")
        self.both(evidence, INVALID, INVALID, "unreadable")

    def test_an_unreadable_status_document_is_invalid(self) -> None:
        for text in ("", "{\"campaign\":", "[]\n"):
            with self.subTest(text=text):
                evidence = self.trees.case("fixture-upload-live")
                (evidence / "sweep-status.json").write_text(text, encoding="utf-8")
                self.both(evidence, INVALID, INVALID)

    def test_an_absent_evidence_file_is_invalid(self) -> None:
        for name in ("sweep-status.json", "suspects.jsonl", "findings.json", "history.jsonl"):
            with self.subTest(file=name):
                evidence = self.trees.case("fixture-upload-live")
                (evidence / name).unlink()
                self.assertEqual(judge(ROOT, VALIDITY, UPLOAD, evidence)[0], INVALID)

    def test_a_profile_without_a_replay_is_invalid(self) -> None:
        self.both(self.status_edit("fixture-upload-live", lambda s: s["profiles"]["upload"].update(replays=0)),
                  INVALID, INVALID, "no replay")

    def test_a_panic_suspect_key_is_invalid(self) -> None:
        def change(s: dict) -> None:
            keyed(s, "upload", {"panic: crates/kestrike/src/lib.rs:1:1": 1})
        self.both(self.status_edit("fixture-upload-live", change), INVALID, INVALID, "another class than violation")

    def test_a_declared_failure_history_with_no_caught_run_is_invalid(self) -> None:
        def change(s: dict) -> None:
            s["profiles"]["h1-get-stale"].update(caught=0, caught_rules={})
        self.both(self.status_edit("fixture-h1-get-stale-live", change), INVALID, INVALID, "minimum unmet",
                  scenario=H1, row=H1_RULE_ROW, tree="tests")

    def test_a_witness_minimum_unmet_is_invalid(self) -> None:
        self.both(self.status_edit("fixture-upload-live", lambda s: s["profiles"]["upload"].update(**{"pass": 63})),
                  INVALID, INVALID, "minimum unmet")

    def test_a_reach_minimum_unmet_is_invalid(self) -> None:
        def change(s: dict) -> None:
            s["profiles"]["cluster-broad"]["reached"]["hits"].update(runs=0, total=0)
        self.both(self.status_edit("fixture-cluster-live", change), INVALID, INVALID, "reach unmet", scenario=CLUSTER,
                  row=NEWER)

    def test_a_reach_minimum_counts_covered_passes_and_a_blank_suspect_line_is_left_out(self) -> None:
        ledger = json.loads((CHAOS / "ledger.json").read_text(encoding="utf-8"))
        next(row for row in ledger["scenarios"] if row["id"] == CLUSTER)["reach"]["hits"] = 5
        changed = self.trees.scratch / "reach-5.json"
        changed.write_text(json.dumps(ledger), encoding="utf-8")
        tree = self.trees.tree("reach-5", changed)
        for runs, verdict in ((4, INVALID), (5, HELD)):
            with self.subTest(runs=runs):
                evidence = self.status_edit("fixture-cluster-live", lambda s, runs=runs: s["profiles"]["cluster-broad"][
                    "reached"]["hits"].update(runs=runs, total=9))
                rebound(evidence, changed, CLUSTER)
                for script, row in ((VALIDITY, CLUSTER), (INVARIANT, NEWER)):
                    code, output = judge(tree, script, row, evidence)
                    self.assertEqual(code, verdict, output)
                    self.assertIn("reach unmet: 4 covered passes" if verdict == INVALID else "reached faults, hits", output)
        evidence = self.trees.case("fixture-upload-live")
        (evidence / "suspects.jsonl").write_text("\n \n", encoding="utf-8")
        self.both(evidence, HELD, HELD)

    def test_controls_without_runs_are_invalid(self) -> None:
        def change(s: dict) -> None:
            zero_controls(s, "runs", "caught")
            s["controls"].update(runs=0, caught=0)
        self.both(self.status_edit("fixture-upload-live", change), INVALID, INVALID, "controls.runs is 0")

    def test_the_totals_flags_are_invalid(self) -> None:
        for flag, value in (("alarm", 1), ("no_pass", ["upload"]), ("unreached", {"cluster-broad": ["hits"]})):
            with self.subTest(flag=flag):
                evidence = self.status_edit("fixture-upload-live", lambda s, flag=flag, value=value: s.update({flag: value}))
                edit_json(evidence / "run.json", lambda run: run.update(sweep_exit=1))
                self.both(evidence, INVALID, INVALID, flag)

    def test_records_of_another_run_are_invalid(self) -> None:
        cases = {
            "the root names build": lambda run: run.update(root_build="0" * 64),
            "restoration not shown": lambda run: run["restored"].update(left_a_process=1),
            "differs from the row the run started with": lambda run: run.update(scenario_row="0" * 64),
            "a live run names no defect": lambda run: run.update(defect="corrupted"),
        }
        for text, change in cases.items():
            with self.subTest(case=text):
                self.both(self.run_edit("fixture-upload-live", change), INVALID, INVALID, text)
        self.both(self.status_edit("fixture-upload-live", lambda s: s.update(campaign="another")), INVALID, INVALID,
                  "the status names campaign")
        self.both(self.trees.case("fixture-upload-live", "another-name"), INVALID, INVALID, "sits in")

    def test_a_control_whose_defect_is_only_its_label_is_invalid(self) -> None:
        def change(run: dict) -> None:
            run.update(defect="another-binary", profiles=["upload"], runs={"upload": run["runs"]["upload"]})
            sweep = run["commands"]["sweep"]
            sweep[sweep.index("--profiles") + 1] = "upload"
        evidence = self.run_edit("fixture-upload-corrupted", change)
        lines = (evidence / "history.jsonl").read_text(encoding="utf-8").splitlines()
        (evidence / "history.jsonl").write_text("".join(line + "\n" for line in lines if '"upload"' in line),
                                                encoding="utf-8")
        self.both(evidence, INVALID, INVALID, "label")

    def test_control_runs_with_none_caught_are_invalid(self) -> None:
        def change(s: dict) -> None:
            zero_controls(s, "caught")
            s["controls"].update(caught=0)
        self.both(self.status_edit("fixture-upload-live", change), INVALID, INVALID, "caught none")

    def test_control_totals_that_disagree_with_the_control_entries_are_invalid(self) -> None:
        cases = {
            "a positive summary over entries that caught none": lambda s: zero_controls(s, "caught"),
            "a summary of fewer runs": lambda s: s["controls"].update(runs=s["controls"]["runs"] - 1),
            "a summary of no catches over entries that caught": lambda s: s["controls"].update(caught=0),
            "a summary of one more profile": lambda s: s["controls"].update(profiles=s["controls"]["profiles"] + 1),
            "a summary of one missed run": lambda s: s["controls"].update(missed=1),
            "a summary of one more run with no effect": lambda s: s["controls"].update(no_effect=s["controls"]["no_effect"] + 1),
            "a summary of one fewer other run": lambda s: s["controls"].update(other=s["controls"]["other"] - 1),
        }
        for name, change in cases.items():
            with self.subTest(case=name):
                self.both(self.status_edit("fixture-upload-live", change), INVALID, INVALID,
                          "its entries marked as controls hold")
        for key in ("missed", "no_effect", "other"):
            with self.subTest(absent=key):
                self.both(self.status_edit("fixture-upload-live", lambda s, key=key: s["controls"].pop(key)), INVALID, INVALID,
                          f"the status's controls records {key} as None")
        self.both(self.status_edit("fixture-upload-live", lambda s: s["profiles"]["corrupted"].pop("uncredited")),
                  INVALID, INVALID, "profile corrupted records uncredited as None")

        def more_caught_than_runs(s: dict) -> None:
            entry = s["profiles"]["corrupted"]
            s["controls"]["caught"] += entry["runs"] + 1 - entry["caught"]
            entry["caught"] = entry["runs"] + 1
        self.both(self.status_edit("fixture-upload-live", more_caught_than_runs), INVALID, INVALID, "counts no sweep writes")

    def test_a_missed_run_is_invalid_whatever_the_totals_flags_say(self) -> None:
        def control(s: dict) -> None:
            entry = s["profiles"]["asserting"]
            rule = next(iter(entry["caught_rules"]))
            entry["caught_rules"][rule] -= 5
            entry.update(caught=entry["caught"] - 5, missed=5)
            s["controls"].update(caught=s["controls"]["caught"] - 5, missed=5)

        def history(s: dict) -> None:
            s["profiles"]["h1-get-stale"].update(missed=1)
        for change in (control, history):
            with self.subTest(change=change.__name__):
                evidence = self.status_edit("fixture-upload-live", change)
                self.assertNotIn("alarm", json.loads((evidence / "sweep-status.json").read_text(encoding="utf-8")))
                self.both(evidence, INVALID, INVALID, "missed")
        for value in (None, -1, True, "0"):
            with self.subTest(missed=value):
                evidence = self.status_edit("fixture-upload-live",
                                            lambda s, value=value: s["profiles"]["h1-get"].update(missed=value))
                self.both(evidence, INVALID, INVALID, "which is no count")

    def test_a_suspect_total_that_disagrees_with_the_suspect_keys_is_invalid(self) -> None:
        cases = {
            "a suspect no key counts": lambda entry: entry.update(suspects=1),
            "a key the total leaves out": lambda entry: entry["suspect_keys"].update({violation_key(2, NEWER_RULE): 1}),
            "no total": lambda entry: entry.pop("suspects"),
        }
        for name, change in cases.items():
            with self.subTest(case=name):
                evidence = self.status_edit("fixture-upload-live", lambda s, change=change: change(s["profiles"]["upload"]))
                self.both(evidence, INVALID, INVALID, "suspects")

    def test_a_run_counted_as_a_pass_and_as_caught_is_invalid(self) -> None:
        def change(s: dict) -> None:
            entry = s["profiles"]["upload"]
            entry.update(caught=1)
            self.assertEqual(entry["pass"], entry["runs"])
        self.both(self.status_edit("fixture-upload-live", change), INVALID, INVALID, "counts no sweep writes")

    def test_a_control_marker_that_is_no_boolean_or_is_absent_is_invalid(self) -> None:
        def ones(s: dict) -> None:
            zero_controls(s, "caught")
            s["controls"].update(caught=0)
            for entry in s["profiles"].values():
                entry["control"] = 1 if entry["control"] else 0

        def removed(s: dict) -> None:
            zero_controls(s, "caught")
            s["controls"].update(caught=0)
            for entry in s["profiles"].values():
                del entry["control"]
        for change in (ones, removed, lambda s: s["profiles"].update(extra=[]),
                       lambda s: s["profiles"]["h1-get"].pop("control")):
            with self.subTest(change=change.__name__):
                self.both(self.status_edit("fixture-upload-live", change), INVALID, INVALID, "no control marker true or false")

    def test_a_totals_flag_beside_a_recorded_exit_0_is_invalid(self) -> None:
        for flag, value in (("alarm", 1), ("no_pass", ["upload"]), ("unreached", {"cluster-broad": ["hits"]})):
            with self.subTest(flag=flag):
                evidence = self.status_edit("fixture-upload-live", lambda s, flag=flag, value=value: s.update({flag: value}))
                self.both(evidence, INVALID, INVALID, "the totals carry")

    def test_a_control_defect_without_runs_or_a_replay_or_with_a_miss_is_invalid(self) -> None:
        def no_runs(s: dict) -> None:
            entry = s["profiles"]["corrupted"]
            s["controls"]["runs"] -= entry["runs"]
            s["controls"]["caught"] -= entry["caught"]
            entry.update(runs=0, caught=0, caught_rules={})
        def missed(s: dict) -> None:
            s["profiles"]["corrupted"].update(missed=1)
            s["controls"].update(missed=1)
        for change in (lambda s: s["profiles"]["corrupted"].update(replays=0), no_runs, missed):
            with self.subTest(change=change):
                self.both(self.status_edit("fixture-upload-corrupted", change), INVALID, INVALID,
                          "a valid control run has runs, a replay and no miss")

    def test_a_named_control_whose_run_or_replay_a_kill_ended_is_invalid(self) -> None:
        for key in ("wall limit: ", "out of memory: ", "worker ended during the run: ", "left a process: "):
            with self.subTest(key=key):
                evidence = self.status_edit("fixture-upload-corrupted",
                                            lambda s, key=key: keyed(s, "corrupted", {key: 1}))
                self.both(evidence, INVALID, INVALID, "is no replay of the control")

    def test_a_cluster_profile_is_judged_by_its_covered_passes(self) -> None:
        def change(s: dict) -> None:
            entry = s["profiles"]["cluster-broad"]
            entry.update(covered=63)
            for event in entry["reached"].values():
                event.update(runs=min(event["runs"], 63))
        self.both(self.status_edit("fixture-cluster-live", change), INVALID, INVALID, "under covered", scenario=CLUSTER,
                  row=NEWER)

    def test_other_counts_a_signal_or_an_unverified_archive_leave_no_verdict(self) -> None:
        self.both(self.status_edit("fixture-upload-live", lambda s: s.update(counts={"restarts": 20})), INVALID, INVALID,
                  "with counts")
        self.both(self.run_edit("fixture-upload-live", lambda run: run.update(signal=15)), INCOMPLETE, INCOMPLETE,
                  "signal 15")
        self.both(self.run_edit("fixture-upload-live", lambda run: run.update(sweep_exit=-9)), INCOMPLETE, INCOMPLETE,
                  "ended by signal 9")
        self.both(self.run_edit("fixture-upload-live", lambda run: run["restored"].update(archive_verified=False)),
                  INVALID, INVALID, "restoration not shown")

    def test_a_break_on_records_a_verdict_cannot_rest_on_is_no_break(self) -> None:
        # An invariant judge checks the sweep's own records before it reports a break.
        def alarm(s: dict) -> None:
            s.update(alarm="5 control runs were missed")
            s["profiles"]["corrupted"].update(missed=5)
            s["controls"].update(missed=5)
        evidence = self.status_edit("fixture-upload-corrupted", alarm)
        edit_json(evidence / "run.json", lambda run: run.update(sweep_exit=1))
        self.both(evidence, INVALID, INVALID, "alarm")
        self.both(self.run_edit("fixture-upload-corrupted", lambda run: run.update(root_build="0" * 64)), INVALID, INVALID,
                  "the root names build")
        self.both(self.run_edit("fixture-h1-get-stale-live", lambda run: run.update(root_build="0" * 64)), INVALID, INVALID,
                  "the root names build", scenario=H1, row=H1_RULE_ROW, tree="tests")

    def test_a_profile_at_its_minimum_is_held(self) -> None:
        self.both(self.status_edit("fixture-upload-live", lambda s: s["profiles"]["upload"].update(**{"pass": 64})),
                  HELD, HELD)

    def test_a_replay_that_differs_anywhere_in_the_root_is_invalid(self) -> None:
        for profile in ("upload", "corrupted", "h1-get"):
            with self.subTest(profile=profile):
                def change(s: dict, profile: str = profile) -> None:
                    keyed(s, profile, {"replay differs: 1 then 0": 1})
                self.both(self.status_edit("fixture-upload-live", change), INVALID, INVALID, "replay")

    def test_a_malformed_suspect_or_history_line_is_invalid(self) -> None:
        for name, text in (("suspects.jsonl", '{"key": "x"}\n'), ("suspects.jsonl", "not json\n"),
                           ("history.jsonl", '{"profile": "upload"}\n'), ("history.jsonl", "not json\n")):
            with self.subTest(file=name, text=text):
                evidence = self.trees.case("fixture-upload-live")
                (evidence / name).write_text(text, encoding="utf-8")
                self.both(evidence, INVALID, INVALID)
        for fields in ({"run": -1}, {"run": True}, {"seed": -1}, {"seed": 1.0}, {"class": 5}):
            with self.subTest(line=fields):
                evidence = self.trees.case("fixture-upload-live")
                self.suspect_line(evidence, **fields)
                self.both(evidence, INVALID, INVALID, "without its key, profile, class, run or seed")

    def test_a_history_line_that_disagrees_with_the_record_is_invalid(self) -> None:
        line = json.loads((RUNS / "fixture-upload-live" / "history.jsonl").read_text(encoding="utf-8"))
        cases = {"build": dict(line, build="0" * 64), "next run": dict(line, runs={"first": 0, "next": 1}),
                 "first run": dict(line, runs=dict(line["runs"], first=1)), "campaign": dict(line, campaign="another"),
                 "counts": dict(line, counts={"restarts": 1})}
        for field, edited in cases.items():
            with self.subTest(field=field):
                evidence = self.trees.case("fixture-upload-live")
                (evidence / "history.jsonl").write_text(json.dumps(edited) + "\n", encoding="utf-8")
                self.both(evidence, INVALID, INVALID, f"on its {field}")
        evidence = self.trees.case("fixture-upload-live")
        (evidence / "history.jsonl").write_text((json.dumps(line) + "\n") * 2, encoding="utf-8")
        self.both(evidence, INVALID, INVALID, "one line for each swept profile")

    # An invariant judge reports broken only through its own row's rule.

    def test_a_violation_in_a_profile_outside_the_scenario_is_no_break(self) -> None:
        code, output = judge(ROOT, INVARIANT, BOUND, self.violation(violation_key(1, BOUND_RULE), finding=True,
                                                                     profile="corrupted"))
        self.assertEqual(code, HELD, output)

    def test_a_live_profile_caught_under_the_rule_is_no_break(self) -> None:
        def change(s: dict) -> None:
            entry = s["profiles"]["upload"]
            entry.update(caught=3, caught_rules={BOUND_RULE: 3}, **{"pass": entry["pass"] - 3})
        code, output = judge(ROOT, INVARIANT, BOUND, self.status_edit("fixture-upload-live", change))
        self.assertEqual(code, HELD, output)

    def test_a_declared_history_caught_under_another_rule_is_no_break(self) -> None:
        def change(s: dict) -> None:
            entry = s["profiles"]["h1-get-stale"]
            entry["caught_rules"] = {"another declared text": entry["caught"]}
        evidence = self.status_edit("fixture-h1-get-stale-live", change)
        edit_json(evidence / "run.json",
                  lambda run: run["listing"]["h1-get-stale"].update(fails="violation 2 another declared text"))
        self.both(evidence, HELD, HELD, scenario=H1, row=H1_RULE_ROW, tree="tests")

    def test_a_history_that_declares_the_rows_violation_and_counts_no_catch_under_its_text_is_never_held(self) -> None:
        maps = ({}, {"another declared text": 5}, {f"unlisted rule {common.rule_digest(H1_RULE)}": 5})
        for rules in maps:
            with self.subTest(rules=rules):
                evidence = self.status_edit("fixture-h1-get-stale-live",
                                            lambda s, rules=rules: s["profiles"]["h1-get-stale"].update(caught_rules=rules))
                code, output = judge(self.trees.trees["tests"], INVARIANT, H1_RULE_ROW, evidence)
                self.assertEqual(code, INVALID, output)
                self.assertIn("none of which caught_rules counts under the row's text", output)

    def test_a_listing_that_declares_a_failure_out_of_form_or_against_the_status_is_invalid(self) -> None:
        cases = {
            "not history": lambda run: run["listing"]["h1-get-stale"].update({"class": "live"}),
            "neither `violation <code> <rule>`": lambda run: run["listing"]["h1-get-stale"].update(fails="violation two x"),
            "is neither `violation": lambda run: run["listing"]["h1-get-stale"].update(fails="violation 02 x"),
            "nor `unsuccessful <witness>`": lambda run: run["listing"]["h1-get-stale"].update(fails="broken somehow"),
            "'violation 0 x', which is neither": lambda run: run["listing"]["h1-get-stale"].update(fails="violation 0 x"),
            "'violation 256 x', which is neither": lambda run: run["listing"]["h1-get-stale"].update(fails="violation 256 x"),
        }
        for text, change in cases.items():
            with self.subTest(case=text):
                self.both(self.run_edit("fixture-h1-get-stale-live", change), INVALID, INVALID, text, scenario=H1,
                          row=H1_RULE_ROW, tree="tests")
        for marker in (False, 1):
            evidence = self.status_edit("fixture-h1-get-stale-live",
                                        lambda s, marker=marker: s["profiles"]["h1-get-stale"].update(failing_history=marker))
            self.both(evidence, INVALID, INVALID, "failing_history", scenario=H1, row=H1_RULE_ROW, tree="tests")
        evidence = self.status_edit("fixture-h1-get-stale-live", lambda s: s["profiles"]["h1-get-stale"].pop("failing_history"))
        self.both(evidence, INVALID, INVALID, "failing_history", scenario=H1, row=H1_RULE_ROW, tree="tests")
        evidence = self.status_edit("fixture-h1-get-stale-live", lambda s: s["profiles"]["h1-get-stale"].update(history=False))
        self.both(evidence, INVALID, INVALID, "the status marks h1-get-stale's history False", scenario=H1,
                  row=H1_RULE_ROW, tree="tests")

    def named_history(self, name: str, row_change, fails: str | None = None, rules: dict | None = None) -> tuple[int, str]:
        """Judge the h1-get-stale run as a control that names the history, against a ledger whose invariant row `row_change` edits."""
        ledger = json.loads((TESTS / "ledger.json").read_text(encoding="utf-8"))
        row_change(next(row for row in ledger["invariants"] if row["id"] == H1_RULE_ROW))
        changed = self.trees.scratch / f"{name}.json"
        changed.write_text(json.dumps(ledger), encoding="utf-8")
        evidence = self.run_edit("fixture-h1-get-stale-live", lambda run: run.update(mode="control", defect="h1-get-stale"))
        if fails is not None:
            edit_json(evidence / "run.json", lambda run: run["listing"]["h1-get-stale"].update(fails=fails))
        if rules is not None:
            edit_json(evidence / "sweep-status.json", lambda s: s["profiles"]["h1-get-stale"].update(
                caught_rules=dict.fromkeys(rules, s["profiles"]["h1-get-stale"]["caught"])))
        return judge(self.trees.tree(name, changed), INVARIANT, H1_RULE_ROW, evidence)

    def test_a_named_history_breaks_only_the_violation_it_declares(self) -> None:
        code, output = self.named_history("named-same", lambda row: None)
        self.assertEqual(code, BROKEN, output)
        self.assertIn(f"\"{H1_RULE}\" (obligation 2)", output)
        code, output = self.named_history("named-obligation", lambda row: row["witness"].update(obligation=3))
        self.assertEqual(code, INVALID, output)
        self.assertIn("and the row checks the violation", output)
        code, output = self.named_history("named-unsuccessful", lambda row: row["control"].update(expect="stale read"),
                                          fails="unsuccessful stale read", rules={"stale read": 1})
        self.assertEqual(code, INVALID, output)
        self.assertIn("declares 'unsuccessful stale read'", output)

    def test_an_unreadable_or_unreproduced_suspect_does_not_hide_a_break_shown_beside_it(self) -> None:
        key, unreadable = violation_key(1, BOUND_RULE), "violation: 0201"
        for first in (key, unreadable):
            with self.subTest(first=first):
                evidence = self.violation(key, finding=True)

                def both_keys(s: dict, first: str = first) -> None:
                    other = unreadable if first == key else key
                    keyed(s, "upload", {first: 3, other: 3}, only=True)
                edit_json(evidence / "sweep-status.json", both_keys)
                code, output = judge(ROOT, INVARIANT, BOUND, evidence)
                self.assertEqual(code, BROKEN, output)
                self.assertIn(BOUND_RULE, output)
        tests = self.trees.trees["tests"]
        for added in (unreadable, violation_key(2, H1_RULE)):
            with self.subTest(added=added):
                evidence = self.status_edit("fixture-h1-get-stale-live",
                                            lambda s, added=added: keyed(s, "h1-get-stale", {added: 1}))
                code, output = judge(tests, INVARIANT, H1_RULE_ROW, evidence)
                self.assertEqual(code, BROKEN, output)
                edit_json(evidence / "sweep-status.json", lambda s: s["profiles"]["h1-get-stale"].update(
                    caught_rules={}, caught=0, **{"pass": s["profiles"]["h1-get-stale"]["runs"]}))
                edit_json(evidence / "run.json", lambda run: run["listing"]["h1-get-stale"].update(fails=None))
                edit_json(evidence / "sweep-status.json", lambda s: s["profiles"]["h1-get-stale"].pop("failing_history"))
                code, output = judge(tests, INVARIANT, H1_RULE_ROW, evidence)
                self.assertEqual(code, INVALID, output)

    def test_an_incomplete_run_of_a_row_that_changed_since_is_incomplete(self) -> None:
        def stale(run: dict) -> None:
            run.update(scenario_row="0" * 64)
        evidence = self.run_edit("fixture-upload-interrupted", stale)
        self.both(evidence, INCOMPLETE, INCOMPLETE, "does not mark the run complete")
        for code in (3, 4, -15):
            evidence = self.run_edit("fixture-upload-live", lambda run, code=code: run.update(scenario_row="0" * 64, sweep_exit=code))
            self.both(evidence, INCOMPLETE, INCOMPLETE)
        self.both(self.run_edit("fixture-upload-live", stale), INVALID, INVALID, "differs from the row the run started with")


    def violation(self, key: str, finding: bool, profile: str = "upload", run: int = 5, observed: str | None = None,
                  kind: str = "violation") -> Path:
        """A live upload run with three suspects under `key`, one line listed, and confirm's finding for it when `finding`.

        The finding's confirmed run ended under the identity `observed`, by default the key's own.
        """
        evidence = self.trees.case("fixture-upload-live")
        edit_json(evidence / "sweep-status.json", lambda s: keyed(s, profile, {key: 3}))
        self.suspect_line(evidence, key=key, profile=profile, run=run, seed=7)
        if finding:
            build = json.loads((evidence / "run.json").read_text(encoding="utf-8"))["system_build"]
            experiment = {"campaign": "fixture-upload-live", "profile": profile, "run": run, "counts": {"turns": 64},
                          "pins": {"build": build}}
            identity = observed if observed is not None else key.partition(": ")[2]
            row = {"id": "f1", "resolved": False, "blocker": True,
                   "verified": {"kind": kind, "admission": {"job": {"experiment": experiment, "seed": 7}},
                                "artifact": {"summary": {"identity": identity}}}}
            edit_json(evidence / "findings.json", lambda f: f["findings"].append(row))
        return evidence

    def test_a_violation_under_the_rule_that_confirm_reproduced_is_broken(self) -> None:
        evidence = self.violation(violation_key(1, BOUND_RULE), finding=True)
        code, output = judge(ROOT, INVARIANT, BOUND, evidence)
        self.assertEqual(code, BROKEN, output)
        self.assertIn(f"\"{BOUND_RULE}\" (obligation 1)", output)
        self.assertIn("f1", output)
        self.assertEqual(judge(ROOT, VALIDITY, UPLOAD, evidence)[0], HELD)

    def test_a_violation_of_identity_variant_02_or_of_an_obligation_above_nine_breaks_its_row(self) -> None:
        key = violation_key(1, BOUND_RULE)
        code, output = judge(ROOT, INVARIANT, BOUND, self.violation(key[:13] + "02" + key[15:], finding=True))
        self.assertEqual(code, BROKEN, output)
        ledger = json.loads((CHAOS / "ledger.json").read_text(encoding="utf-8"))
        next(row for row in ledger["invariants"] if row["id"] == BOUND)["witness"]["obligation"] = 26
        changed = self.trees.scratch / "obligation-26.json"
        changed.write_text(json.dumps(ledger), encoding="utf-8")
        tree = self.trees.tree("obligation-26", changed)
        self.assertIn("02011a", violation_key(26, BOUND_RULE))
        code, output = judge(tree, INVARIANT, BOUND, self.violation(violation_key(26, BOUND_RULE), finding=True))
        self.assertEqual(code, BROKEN, output)
        self.assertIn(f"\"{BOUND_RULE}\" (obligation 26)", output)
        code, output = judge(tree, INVARIANT, BOUND, self.violation(violation_key(1, BOUND_RULE), finding=True))
        self.assertEqual(code, HELD, output)

    def test_a_finding_of_another_run_profile_or_campaign_is_no_reproduction(self) -> None:
        cases = (("run", 6), ("run", 5.0), ("run", True), ("profile", "corrupted"), ("campaign", "another"),
                 ("pins", {"build": "0" * 64}), ("pins", None), ("seed", 8), ("seed", 7.0), ("seed", None))
        for field, value in cases:
            with self.subTest(field=field, value=value):
                evidence = self.violation(violation_key(1, BOUND_RULE), finding=True)

                def change(f: dict, field: str = field, value: object = value) -> None:
                    job = f["findings"][-1]["verified"]["admission"]["job"]
                    (job if field == "seed" else job["experiment"])[field] = value
                edit_json(evidence / "findings.json", change)
                code, output = judge(ROOT, INVARIANT, BOUND, evidence)
                self.assertEqual(code, INVALID, output)
                self.assertIn("reproduced none", output)

    def test_a_finding_of_a_suspect_under_another_rule_is_no_reproduction_of_the_rows_suspect(self) -> None:
        own, other = violation_key(1, BOUND_RULE), violation_key(2, NEWER_RULE)
        evidence = self.violation(own, finding=False)
        edit_json(evidence / "sweep-status.json", lambda s: keyed(s, "upload", {other: 1}))
        listed = json.loads((evidence / "suspects.jsonl").read_text(encoding="utf-8"))
        with open(evidence / "suspects.jsonl", "a", encoding="utf-8") as file:
            file.write(json.dumps(dict(listed, key=other, run=6, seed=8), sort_keys=True) + "\n")
        experiment = {"campaign": "fixture-upload-live", "profile": "upload", "run": 6, "counts": {"turns": 64},
                      "pins": {"build": listed["build"]}}
        row = {"id": "f2", "resolved": False, "blocker": True,
               "verified": {"kind": "violation", "admission": {"job": {"experiment": experiment, "seed": 8}},
                            "artifact": {"summary": {"identity": other.partition(": ")[2]}}}}
        edit_json(evidence / "findings.json", lambda f: f["findings"].append(row))
        code, output = judge(ROOT, INVARIANT, BOUND, evidence)
        self.assertEqual(code, INVALID, output)
        self.assertIn("campaign confirm reproduced none of their 1 listed runs", output)
        self.assertEqual(judge(ROOT, VALIDITY, UPLOAD, evidence)[0], HELD)

    def test_a_violation_a_known_row_explains_cites_its_issue(self) -> None:
        key = violation_key(1, BOUND_RULE)
        evidence = self.violation(key, finding=True)
        known = [{"issue": 225, "rule": BOUND_RULE, "suspects": 3, "keys": {"upload": [key]}}]
        edit_json(evidence / "sweep-status.json", lambda s: s.update(known=known))
        code, output = judge(ROOT, INVARIANT, BOUND, evidence)
        self.assertEqual(code, BROKEN, output)
        self.assertIn("#225", output)
        rows = ({"issue": 0, "keys": {"upload": [key]}}, {"issue": -1, "keys": {"upload": [key]}},
                {"issue": "1700", "keys": {"upload": [key]}}, {"keys": {"upload": [key]}},
                {"issue": True, "keys": {"upload": [key]}}, {"issue": 225, "keys": {"upload": f"x{key}x"}},
                {"issue": 225, "keys": {"corrupted": [key]}}, {"issue": 225, "keys": {"upload": [violation_key(1, NEWER_RULE)]}})
        for row in rows:
            with self.subTest(known=row):
                edit_json(evidence / "sweep-status.json", lambda s, row=row: s.update(known=[row]))
                code, output = judge(ROOT, INVARIANT, BOUND, evidence)
                self.assertEqual(code, BROKEN, output)
                self.assertNotIn("#", output)

    def test_a_violation_under_the_rule_that_confirm_did_not_reproduce_is_invalid(self) -> None:
        code, output = judge(ROOT, INVARIANT, BOUND, self.violation(violation_key(1, BOUND_RULE), finding=False))
        self.assertEqual(code, INVALID, output)
        self.assertIn("reproduced none", output)

    def test_a_violation_of_another_rule_or_obligation_leaves_the_row_held(self) -> None:
        for key in (violation_key(1, NEWER_RULE), violation_key(2, BOUND_RULE)):
            with self.subTest(key=key):
                code, output = judge(ROOT, INVARIANT, BOUND, self.violation(key, finding=True))
                self.assertEqual(code, HELD, output)

    def test_suspects_counted_under_other_are_invalid(self) -> None:
        evidence = self.status_edit("fixture-upload-live", lambda s: keyed(s, "upload", {"other": 1}))
        self.suspect_line(evidence, profile="upload", **{"class": "panic"})
        self.both(evidence, INVALID, INVALID, "upload has a suspect of another class than violation: other")

    def test_two_lines_that_read_alike_count_once_under_other(self) -> None:
        evidence = self.status_edit("fixture-upload-live", lambda s: keyed(s, "h1-get", {"other": 2}))
        self.suspect_line(evidence, **{"class": "panic"})
        line = (evidence / "suspects.jsonl").read_text(encoding="utf-8")
        (evidence / "suspects.jsonl").write_text(line * 2, encoding="utf-8")
        self.both(evidence, INVALID, INVALID, "under other and lists 1")
        (evidence / "suspects.jsonl").write_text(line + line.replace('"run": 0', '"run": 1'), encoding="utf-8")
        self.both(evidence, HELD, HELD)

    def test_a_listed_suspect_the_status_does_not_count_or_of_another_class_is_invalid(self) -> None:
        key = violation_key(1, BOUND_RULE)
        evidence = self.violation(key, finding=True)
        edit_json(evidence / "sweep-status.json", lambda s: keyed(s, "upload", {}, only=True))
        self.both(evidence, INVALID, INVALID, "and the status counts 0")
        evidence = self.trees.case("fixture-upload-live")
        self.suspect_line(evidence, key="panic: src/lib.rs:1:1", profile="upload", **{"class": "panic"})
        self.both(evidence, INVALID, INVALID, "and the status counts 0")
        # The overflow key counts its lines as every other key does.
        for profile in ("upload", "h1-get"):
            with self.subTest(other=profile):
                evidence = self.trees.case("fixture-upload-live")
                self.suspect_line(evidence, profile=profile, **{"class": "panic"})
                self.both(evidence, INVALID, INVALID, "under 'other', and the status counts 0")
        evidence = self.violation(key, finding=True)
        self.suspect_line(evidence, key=key, profile="upload", run=5, seed=7, **{"class": "panic"})
        self.both(evidence, INVALID, INVALID, "of another class")
        evidence = self.violation(key, finding=True)
        line = (evidence / "suspects.jsonl").read_text(encoding="utf-8")
        (evidence / "suspects.jsonl").write_text(line * 4, encoding="utf-8")
        self.both(evidence, INVALID, INVALID, "and the status counts 3")

    def test_a_json_lines_copy_cut_before_its_last_line_feed_is_invalid(self) -> None:
        evidence = self.violation(violation_key(1, BOUND_RULE), finding=True)
        text = (evidence / "suspects.jsonl").read_text(encoding="utf-8")
        (evidence / "suspects.jsonl").write_text(text.rstrip("\n"), encoding="utf-8")
        self.both(evidence, INVALID, INVALID, "its last record has no line feed")
        evidence = self.trees.case("fixture-upload-live")
        text = (evidence / "history.jsonl").read_text(encoding="utf-8")
        (evidence / "history.jsonl").write_text(text.rstrip("\n"), encoding="utf-8")
        self.both(evidence, INVALID, INVALID, "its last record has no line feed")
        (evidence / "history.jsonl").write_text(text.rstrip("\n") + "\r" + text, encoding="utf-8")
        self.both(evidence, INVALID, INVALID, "history.jsonl is unreadable")

    def test_a_control_with_no_catch_under_the_rule_is_invalid(self) -> None:
        def change(s: dict) -> None:
            s["profiles"]["corrupted"].update(caught_rules={})
        code, output = judge(ROOT, INVARIANT, BOUND, self.status_edit("fixture-upload-corrupted", change))
        self.assertEqual(code, INVALID, output)
        self.assertIn(BOUND_RULE, output)

    def test_a_totals_flag_of_any_value_is_invalid(self) -> None:
        for flag in ("alarm", "no_pass", "unreached"):
            for value in (None, "", [], {}, False):
                with self.subTest(flag=flag, value=value):
                    evidence = self.status_edit("fixture-upload-live", lambda s, f=flag, v=value: s.update({f: v}))
                    self.both(evidence, INVALID, INVALID, "the totals carry")

    def suspect_line(self, evidence: Path, **fields: object) -> None:
        """Write one suspects.jsonl line of this run, with `fields` over its defaults."""
        build = json.loads((evidence / "run.json").read_text(encoding="utf-8"))["system_build"]
        line = {"build": build, "campaign": evidence.name, "class": "violation", "code": 1, "counts": {},
                "key": "other", "profile": "h1-get", "run": 0, "seed": 1, "summary": None, **fields}
        (evidence / "suspects.jsonl").write_text(json.dumps(line, sort_keys=True) + "\n", encoding="utf-8")

    def test_a_replay_difference_listed_under_other_or_an_unlisted_other_is_invalid(self) -> None:
        evidence = self.status_edit("fixture-upload-live", lambda s: keyed(s, "h1-get", {"other": 1}))
        self.suspect_line(evidence, **{"class": "replay differs"})
        self.both(evidence, INVALID, INVALID, "replayed with another ending")
        evidence = self.status_edit("fixture-upload-live", lambda s: keyed(s, "h1-get", {"other": 9}))
        self.suspect_line(evidence)
        self.both(evidence, INVALID, INVALID, "under other and lists 1")

    def test_a_status_entry_without_its_control_flag_or_suspect_counts_is_invalid(self) -> None:
        def unflagged(s: dict) -> None:
            for entry in s["profiles"].values():
                if entry.get("control"):
                    del entry["control"]
            s["controls"].update(runs=0)

        def unmarked(s: dict) -> None:
            for entry in s["profiles"].values():
                entry["control"] = False
            s["controls"].update(runs=0)
        self.both(self.status_edit("fixture-upload-live", unflagged), INVALID, INVALID, "no control marker true or false")
        self.both(self.status_edit("fixture-upload-live", unmarked), INVALID, INVALID, "controls count 9 profiles")
        for keys in ("upload", None, {"violation: x": -1}, {"violation: x": 0}, {"violation: x": True}):
            with self.subTest(keys=keys):
                evidence = self.status_edit("fixture-upload-live",
                                            lambda s, keys=keys: s["profiles"]["h1-get"].update(suspect_keys=keys))
                self.both(evidence, INVALID, INVALID, "no suspect_keys counts of at least 1")

    def test_a_finding_that_confirmed_another_violation_or_kind_is_no_reproduction(self) -> None:
        key = violation_key(1, BOUND_RULE)
        cases = {"another rule": {"observed": violation_key(1, NEWER_RULE).partition(": ")[2]},
                 "another obligation": {"observed": violation_key(2, BOUND_RULE).partition(": ")[2]},
                 "no identity": {"observed": ""}, "another kind": {"kind": "panic"}}
        for name, change in cases.items():
            with self.subTest(case=name):
                code, output = judge(ROOT, INVARIANT, BOUND, self.violation(
                    key, finding=True, observed=change.get("observed"), kind=change.get("kind", "violation")))
                self.assertEqual(code, INVALID, output)
                self.assertIn("reproduced none", output)

    def test_a_violation_whose_rule_cannot_be_read_is_invalid_and_an_audit_identity_is_held(self) -> None:
        for key in ("violation: ", "violation: 03" + "0" * 86, "violation: 0201"):
            with self.subTest(key=key):
                code, output = judge(ROOT, INVARIANT, BOUND, self.violation(key, finding=False))
                self.assertEqual(code, INVALID, output)
                self.assertIn("cannot read", output)
        versioned = "violation: 03" + violation_key(1, BOUND_RULE).partition(": ")[2][2:]
        code, output = judge(ROOT, INVARIANT, BOUND, self.violation(versioned, finding=True))
        self.assertEqual(code, INVALID, output)
        self.assertIn("cannot read", output)
        code, output = judge(ROOT, INVARIANT, BOUND, self.violation("violation: 0204" + "0" * 84, finding=False))
        self.assertEqual(code, HELD, output)

    def test_a_declared_history_breaks_only_the_violation_it_declares(self) -> None:
        ledger = json.loads((TESTS / "ledger.json").read_text(encoding="utf-8"))
        next(row for row in ledger["invariants"] if row["id"] == H1_RULE_ROW)["witness"]["obligation"] = 3
        changed = self.trees.scratch / "other-obligation.json"
        changed.write_text(json.dumps(ledger), encoding="utf-8")
        tree = self.trees.tree("other-obligation", changed)
        code, output = judge(tree, INVARIANT, H1_RULE_ROW, self.trees.case("fixture-h1-get-stale-live"))
        self.assertEqual(code, HELD, output)
        evidence = self.run_edit("fixture-h1-get-stale-live",
                                 lambda run: run["listing"]["h1-get-stale"].update(fails=f"unsuccessful {H1_RULE}"))
        code, output = judge(self.trees.trees["tests"], INVARIANT, H1_RULE_ROW, evidence)
        self.assertEqual(code, HELD, output)

    def test_a_failing_history_flag_the_listing_does_not_declare_is_invalid(self) -> None:
        evidence = self.status_edit("fixture-upload-live", lambda s: s["profiles"]["upload"].update(failing_history=True))
        self.both(evidence, INVALID, INVALID, "declares no failure")

    def test_a_control_relabeled_as_live_is_invalid(self) -> None:
        evidence = self.run_edit("fixture-upload-corrupted", lambda run: run.update(mode="live", defect=""))
        self.both(evidence, INVALID, INVALID, "records a profiles")

    def test_a_run_record_that_disagrees_with_its_lifecycle_or_its_row_is_invalid(self) -> None:
        def profiles(run: dict) -> None:
            sweep = run["commands"]["sweep"]
            sweep[sweep.index("--profiles") + 1] = "upload,corrupted"
        cases = {
            "campaign confirm exited 2": lambda run: run.update(confirm_exit=2),
            "campaign sweep-status exited True": lambda run: run.update(status_exit=True),
            "campaign findings exited None": lambda run: run.update(findings_exit=None),
            "against a --for": lambda run: run.update(sweep_elapsed_s=float("nan")),
            "records a workers": lambda run: run.update(workers=27),
            "records a for_s": lambda run: run["commands"]["sweep"].__setitem__(-1, "60"),
            "records a profiles": profiles,
            "on its next run": lambda run: run["runs"]["upload"].update(next=1),
            "records first as False": lambda run: run["runs"]["upload"].update(first=False),
            "run ranges name other profiles": lambda run: run["runs"].update(corrupted={"first": 0, "next": 1}),
            "campaign sim capabilities exited 1": lambda run: run.update(listing_exit=1),
            "campaign sim capabilities exited False": lambda run: run.update(listing_exit=False),
            "campaign sweep-status exited False": lambda run: run.update(status_exit=False),
            "reported dispatch 'interrupted'": lambda run: run.update(confirm_dispatch="interrupted"),
            "reported dispatch None": lambda run: run.pop("confirm_dispatch"),
            "hashed otherwise after the last command": lambda run: run["campaign_binary"].update(sha256_after="0" * 64),
            "hashed otherwise after the last": lambda run: run["campaign_binary"].pop("source_sha256_after"),
            "lacks its schema 1": lambda run: run.update(schema=2),
            "against a --for of 120": lambda run: run.update(sweep_elapsed_s=119.9),
            "records a batch_s": lambda run: run.update(batch_s=31),
            "records a deadline_s": lambda run: run.update(deadline_s=3601),
            "records a campaign": lambda run: run["commands"]["sweep"].__setitem__(
                run["commands"]["sweep"].index("--campaign") + 1, "another"),
            "records a root": lambda run: run.update(root="/elsewhere"),
            "records a archive": lambda run: run.update(archive="/elsewhere"),
            "records a counts": lambda run: run["commands"]["sweep"].extend(["--set", "restarts=20"]),
            "repeats or holds an option": lambda run: run["commands"]["sweep"].extend(["--workers", "28"]),
            "restoration not shown": lambda run: run.update(archive_build_after="0" * 64),
            "lacks its system_build": lambda run: run.update(system_build="55bf8b81"),
            "lacks its counts": lambda run: run.pop("counts"),
            "lacks its started": lambda run: run.update(started="yesterday"),
            "lacks its harness": lambda run: run.update(harness={}),
            "lacks its profiles": lambda run: run.update(profiles=[]),
            "lacks its defect": lambda run: run.update(defect=None),
            "lacks its campaign, which is the run id": lambda run: run.update(campaign="another"),
            "records no sweep command line": lambda run: run["commands"]["sweep"].__setitem__(1, "fuzz"),
        }
        for text, change in cases.items():
            with self.subTest(case=text):
                self.both(self.run_edit("fixture-upload-live", change), INVALID, INVALID, text)

        def without(option: str, key: str):
            def change(run: dict) -> None:
                sweep = run["commands"]["sweep"]
                del sweep[sweep.index(option):sweep.index(option) + 2]
                run.pop(key)
            return change
        for option, key in (("--archive", "archive"), ("--root", "root")):
            with self.subTest(absent=option):
                self.both(self.run_edit("fixture-upload-live", without(option, key)), INVALID, INVALID, f"records a {key}")

    def test_a_suspect_line_of_another_run_is_invalid(self) -> None:
        for field, value in (("campaign", "another"), ("build", "0" * 64), ("counts", {"restarts": 1}), ("run", 10 ** 9)):
            with self.subTest(field=field):
                evidence = self.violation(violation_key(1, NEWER_RULE), finding=False)
                lines = (evidence / "suspects.jsonl").read_text(encoding="utf-8").splitlines()
                line = dict(json.loads(lines[0]), **{field: value})
                (evidence / "suspects.jsonl").write_text(json.dumps(line) + "\n", encoding="utf-8")
                self.both(evidence, INVALID, INVALID, "under another campaign")
        evidence = self.violation(violation_key(1, NEWER_RULE), finding=False)
        cursor = json.loads((evidence / "run.json").read_text(encoding="utf-8"))["runs"]["upload"]["next"]
        for run, verdict in ((cursor - 1, HELD), (cursor, INVALID)):
            with self.subTest(run=run):
                line = dict(json.loads((evidence / "suspects.jsonl").read_text(encoding="utf-8")), run=run)
                (evidence / "suspects.jsonl").write_text(json.dumps(line) + "\n", encoding="utf-8")
                self.both(evidence, verdict, verdict, "under another campaign" if verdict == INVALID else "")

    def test_a_finding_without_its_id_is_invalid(self) -> None:
        for row in ({}, {"id": ""}, {"id": 5}):
            with self.subTest(row=row):
                evidence = self.trees.case("fixture-upload-live")
                edit_json(evidence / "findings.json", lambda f, row=row: f["findings"].append(row))
                self.both(evidence, INVALID, INVALID, "without its id")
        held = {"id": "f2", "held": "authoritative outcome awaits capture", "held_code": "capture-missing", "blocker": True}
        verified = {"id": "f2", "verified": {"kind": "panic"}, "resolved": False, "blocker": False}
        for row in ({"id": "f2"}, dict(held, blocker=False), dict(held, held_code=4), dict(verified, verified={}),
                    dict(verified, resolved=1), dict(verified, held="both forms")):
            with self.subTest(row=row):
                evidence = self.trees.case("fixture-upload-live")
                edit_json(evidence / "findings.json", lambda f, row=row: f["findings"].append(row))
                self.both(evidence, INVALID, INVALID, "in neither the verified nor the held form")
        evidence = self.trees.case("fixture-upload-live")
        edit_json(evidence / "findings.json", lambda f: f["findings"].extend([held, verified]))
        self.both(evidence, HELD, HELD)
        edit_json(evidence / "findings.json", lambda f: f["findings"].append(held))
        self.both(evidence, INVALID, INVALID, "two held findings")

    def test_counts_no_sweep_writes_are_invalid(self) -> None:
        def passes(s: dict) -> None:
            entry = s["profiles"]["upload"]
            entry["pass"] = entry["runs"] + 1
        self.both(self.status_edit("fixture-upload-live", passes), INVALID, INVALID, "counts no sweep writes")

        def reach(s: dict) -> None:
            entry = s["profiles"]["cluster-broad"]
            entry["reached"]["hits"]["runs"] = entry["covered"] + 1
        self.both(self.status_edit("fixture-cluster-live", reach), INVALID, INVALID, "more than its covered passes",
                  scenario=CLUSTER, row=NEWER)
        relations = {
            "covered above pass": lambda entry: entry.update(covered=entry["pass"] + 1),
            "caught above runs": lambda entry: entry.update(caught=entry["runs"] + 1),
        }
        for name, change in relations.items():
            with self.subTest(relation=name):
                evidence = self.status_edit("fixture-upload-live", lambda s, change=change: change(s["profiles"]["upload"]))
                self.both(evidence, INVALID, INVALID, "counts no sweep writes")
        totals = {"no time": lambda event: event.update(total=0),
                  "past a pass's capacity": lambda event: event.update(total=event["runs"] * (1 << 32))}
        for name, change in totals.items():
            with self.subTest(total=name):
                evidence = self.status_edit("fixture-cluster-live", lambda s, change=change: change(
                    s["profiles"]["cluster-broad"]["reached"]["hits"]))
                self.both(evidence, INVALID, INVALID, "which no sweep writes", scenario=CLUSTER, row=NEWER)

    def test_replay_attempts_above_the_runs_leave_the_run_held(self) -> None:
        def change(s: dict) -> None:
            entry = s["profiles"]["upload"]
            entry.update(replays=entry["runs"] + 2)
        self.both(self.status_edit("fixture-upload-live", change), HELD, HELD)

    def test_a_room_for_its_runs_and_whole_number_ranges_are_required(self) -> None:
        def cursor(s: dict) -> None:
            s["profiles"]["upload"].update(next=1)
        evidence = self.status_edit("fixture-upload-live", cursor)
        edit_json(evidence / "run.json", lambda run: run["runs"]["upload"].update(next=1))
        line = json.loads((evidence / "history.jsonl").read_text(encoding="utf-8"))
        line["runs"]["next"] = 1
        (evidence / "history.jsonl").write_text(json.dumps(line) + "\n", encoding="utf-8")
        self.both(evidence, INVALID, INVALID, "room for its runs")
        for field, value in (("first", False), ("first", 0.0), ("next", None)):
            with self.subTest(field=field, value=value):
                evidence = self.trees.case("fixture-upload-live")
                line = json.loads((evidence / "history.jsonl").read_text(encoding="utf-8"))
                line["runs"][field] = float(line["runs"]["next"]) if value is None else value
                (evidence / "history.jsonl").write_text(json.dumps(line) + "\n", encoding="utf-8")
                self.both(evidence, INVALID, INVALID)
        evidence = self.trees.case("fixture-upload-live")
        line = json.loads((evidence / "history.jsonl").read_text(encoding="utf-8"))
        line["runs"]["last"] = line["runs"]["next"] - 1
        (evidence / "history.jsonl").write_text(json.dumps(line) + "\n", encoding="utf-8")
        self.both(evidence, INVALID, INVALID, "on its next run")
        evidence = self.run_edit("fixture-upload-live", lambda run: run["runs"]["upload"].update(last=0))
        self.both(evidence, INVALID, INVALID, "on its next run")

    def test_a_count_override_the_row_does_not_set_is_invalid_though_every_record_agrees(self) -> None:
        evidence = self.trees.case("fixture-upload-live")
        counts = {"restarts": 20}
        edit_json(evidence / "run.json", lambda run: (run.update(counts=counts),
                                                      run["commands"]["sweep"].extend(["--set", "restarts=20"])))
        edit_json(evidence / "sweep-status.json", lambda s: s.update(counts=counts))
        line = json.loads((evidence / "history.jsonl").read_text(encoding="utf-8"))
        (evidence / "history.jsonl").write_text(json.dumps(dict(line, counts=counts)) + "\n", encoding="utf-8")
        self.both(evidence, INVALID, INVALID, "records a counts")
        # The record and the status name a count that the row and the sweep's command line leave at its default.
        evidence = self.trees.case("fixture-upload-live")
        edit_json(evidence / "run.json", lambda run: run.update(counts=counts))
        edit_json(evidence / "sweep-status.json", lambda s: s.update(counts=counts))
        (evidence / "history.jsonl").write_text(json.dumps(dict(line, counts=counts)) + "\n", encoding="utf-8")
        self.both(evidence, INVALID, INVALID, "records a counts")

    def test_a_finding_at_other_counts_than_the_runs_is_no_reproduction(self) -> None:
        counts = {"restarts": 20}
        ledger = json.loads((CHAOS / "ledger.json").read_text(encoding="utf-8"))
        next(row for row in ledger["scenarios"] if row["id"] == UPLOAD)["load"]["count_restarts"] = 20
        changed = self.trees.scratch / "counted-row.json"
        changed.write_text(json.dumps(ledger), encoding="utf-8")
        tree = self.trees.tree("counted-row", changed)
        cases = (({"restarts": 20, "turns": 64}, BROKEN), ({"restarts": 19, "turns": 64}, INVALID), ({"turns": 64}, INVALID),
                 ({"restarts": 20.0, "turns": 64}, INVALID), ({"restarts": True}, INVALID))
        for held, verdict in cases:
            with self.subTest(counts=held):
                evidence = self.violation(violation_key(1, BOUND_RULE), finding=True)
                edit_json(evidence / "run.json", lambda run: (run.update(counts=counts),
                                                              run["commands"]["sweep"].extend(["--set", "restarts=20"])))
                edit_json(evidence / "sweep-status.json", lambda s: s.update(counts=counts))
                for name in ("history.jsonl", "suspects.jsonl"):
                    lines = [json.loads(line) for line in (evidence / name).read_text(encoding="utf-8").splitlines()]
                    (evidence / name).write_text("".join(json.dumps(dict(line, counts=counts)) + "\n" for line in lines),
                                                 encoding="utf-8")
                rebound(evidence, changed, UPLOAD)
                edit_json(evidence / "findings.json", lambda f, held=held: f["findings"][-1]["verified"]["admission"]["job"][
                    "experiment"].update(counts=held))
                code, output = judge(tree, INVARIANT, BOUND, evidence)
                self.assertEqual(code, verdict, output)
                self.assertIn("campaign confirm reproduced 1 as findings f1" if verdict == BROKEN else "reproduced none", output)

    def test_a_caught_rules_count_above_the_caught_runs_or_caught_runs_above_the_runs_are_invalid(self) -> None:
        def bucket(s: dict) -> None:
            entry = s["profiles"]["corrupted"]
            entry["caught_rules"][BOUND_RULE] = entry["caught"] + 1

        def runs(s: dict) -> None:
            entry = s["profiles"]["corrupted"]
            s["controls"]["runs"] -= entry["runs"] - (entry["caught"] - 1)
            entry.update(runs=entry["caught"] - 1)
        for change in (bucket, runs):
            with self.subTest(change=change.__name__):
                self.both(self.status_edit("fixture-upload-corrupted", change), INVALID, INVALID, "counts no sweep writes")

        def history(s: dict) -> None:
            s["profiles"]["h1-get-stale"].update(runs=0)
        self.both(self.status_edit("fixture-h1-get-stale-live", history), INVALID, INVALID, "counts no sweep writes",
                  scenario=H1, row=H1_RULE_ROW, tree="tests")

    def test_a_link_or_a_fifo_in_the_evidence_is_invalid(self) -> None:
        for name in ("run.json", "findings.json", "suspects.jsonl"):
            with self.subTest(link=name):
                evidence = self.trees.case("fixture-upload-live")
                kept = evidence.parent / f"kept-{name}"
                (evidence / name).rename(kept)
                (evidence / name).symlink_to(kept)
                self.both(evidence, INVALID, INVALID)
        evidence = self.trees.case("fixture-upload-live")
        (evidence / "suspects.jsonl").unlink()
        os.mkfifo(evidence / "suspects.jsonl")
        self.both(evidence, INVALID, INVALID, "no regular file")
        evidence = self.trees.case("fixture-upload-live")
        (evidence / "extra").mkdir()
        self.both(evidence, INVALID, INVALID, "no regular file")


class Judge(unittest.TestCase):
    """How a judge starts, what it reads and what its receipt holds."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.trees = Trees()

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.trees.scratch, ignore_errors=True)

    def test_the_receipt_names_the_row_the_judge_files_the_evidence_and_the_verdict(self) -> None:
        evidence, receipt = self.trees.case("fixture-upload-corrupted"), self.trees.receipt("receipt.json")
        self.assertEqual(judge(self.trees.trees["judged"], INVARIANT, BOUND, evidence, receipt)[0], BROKEN)
        written = json.loads(receipt.read_text(encoding="utf-8"))
        key, run = written["key"], written["run"]
        ledger = json.loads((CHAOS / "ledger.json").read_text(encoding="utf-8"))
        rows = {row["id"]: row for section in ("invariants", "scenarios") for row in ledger[section]}
        self.assertEqual(key["command"], rows[BOUND]["judge"].split())
        self.assertEqual(key["rows"], {name: validator.row_digest(rows[name]) for name in (BOUND, UPLOAD)})
        self.assertEqual(sorted(key["judge"]), [f"chaos/judges/core/{name}" for name in
                                                ("common.py", "invariant.py", "validity.py")])
        self.assertEqual(key["evidence"]["run.json"], hashlib.sha256((evidence / "run.json").read_bytes()).hexdigest())
        self.assertEqual((key["outcome"], key["mode"], key["defect"]), ("broken", "control", "corrupted"))
        self.assertIn(BOUND_RULE, key["detail"])
        self.assertTrue(common.stamp(run["judged"]) and run["judged"] >= run["started"])

    def test_the_receipt_names_every_file_of_the_judge_directories(self) -> None:
        tree = self.trees.tree("extra", CHAOS / "ledger.json")
        (tree / "chaos" / "judges" / "core" / "notes.txt").write_text("a file beside the judges\n", encoding="utf-8")
        receipt = self.trees.receipt("extra.json", tree)
        self.assertEqual(judge(tree, VALIDITY, UPLOAD, self.trees.case("fixture-upload-live"), receipt)[0], HELD)
        named = json.loads(receipt.read_text(encoding="utf-8"))["key"]["judge"]
        files = {path.relative_to(tree).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in (tree / "chaos" / "judges" / "core").iterdir()}
        self.assertEqual(named, files)
        self.assertIn("chaos/judges/core/notes.txt", named)

    def test_the_validator_accepts_a_receipt_of_a_recorded_run(self) -> None:
        tree = self.trees.tree("validated", CHAOS / "ledger.json")
        for name in ("project.yaml", "approval-policy.md", "tools"):
            source = CHAOS / name
            (shutil.copytree if source.is_dir() else shutil.copy)(source, tree / "chaos" / name)
        shutil.copytree(CHAOS / "receipts" / "fences", tree / "chaos" / "receipts" / "fences")
        shutil.copytree(RUNS / "fixture-upload-corrupted", tree / "chaos" / "runs" / "fixture-upload-corrupted")
        receipts = tree / "chaos" / "receipts" / "fixture-upload-corrupted"
        receipts.mkdir()
        evidence = tree / "chaos" / "runs" / "fixture-upload-corrupted"
        # The validator ties each receipt to the harness files as they stand; the recorded run names the tree's harness.
        current = {path.relative_to(tree).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                   for path in sorted((tree / "chaos" / "harness").iterdir())}
        self.assertEqual(json.loads((evidence / "run.json").read_text(encoding="utf-8"))["harness"], current)
        self.assertEqual(judge(tree, VALIDITY, UPLOAD, evidence, receipts / f"{UPLOAD}.json")[0], HELD)
        self.assertEqual(judge(tree, INVARIANT, BOUND, evidence, receipts / f"{BOUND}.json")[0], BROKEN)
        done = subprocess.run([sys.executable, str(tree / "chaos/tools/validate_contract.py"), "chaos/ledger.json",
                               "--root", ".", "--project", "chaos/project.yaml", "--receipts", "chaos/receipts"],
                              cwd=tree, capture_output=True, text=True, check=False, timeout=120)
        # The validator read both receipts: the control receipt clears the row's control-missing, and only the
        # findings of rows no run has a receipt for stay, the reach row's and the ordering figure's invariant among them.
        self.assertEqual((done.returncode, done.stderr), (1, ""), done.stdout)
        self.assertEqual([line.split(": ")[:2] for line in done.stdout.splitlines()],
                         [[NEWER, "witness-missing"], [NEWER, "control-missing"], [BOUND, "witness-missing"],
                          ["ks-no-fill-admitted-after-close", "witness-missing"],
                          ["ks-no-fill-admitted-after-close", "control-missing"],
                          [REACHED, "witness-missing"], [REACHED, "control-missing"],
                          [ORDERING, "witness-missing"], [ORDERING, "control-missing"],
                          ["ks-escape-2075", "status-without-receipts"]], done.stdout)

    def test_a_refused_start_exits_2_with_standard_error_closed(self) -> None:
        evidence = self.trees.case("fixture-upload-live")
        cached = self.trees.tree("cached-closed", CHAOS / "ledger.json")
        (cached / "chaos" / "judges" / "core" / "__pycache__").mkdir()
        starts = {
            "without -I": [sys.executable, "-B", str(ROOT / VALIDITY), UPLOAD, "--evidence", str(evidence)],
            "without -B": [sys.executable, "-I", str(ROOT / VALIDITY), UPLOAD, "--evidence", str(evidence)],
            "beside a cache directory": [sys.executable, "-I", "-B", str(cached / VALIDITY), UPLOAD, "--evidence", str(evidence)],
            "without its evidence": [sys.executable, "-I", "-B", str(ROOT / INVARIANT), BOUND],
            "asking for help": [sys.executable, "-I", "-B", str(ROOT / INVARIANT), "-h"],
            "with an abbreviated flag": [sys.executable, "-I", "-B", str(ROOT / VALIDITY), UPLOAD, "--evid", str(evidence)],
        }
        for name, argv in starts.items():
            for closed in (True, False):
                with self.subTest(start=name, closed=closed):
                    shell = ["sh", "-c", 'exec 2>&-; exec "$@"', "sh", *argv] if closed else argv
                    done = subprocess.run(shell, capture_output=not closed, check=False, timeout=120)
                    self.assertEqual(done.returncode, INVALID)

    def test_a_second_judgement_to_one_receipt_keeps_the_first(self) -> None:
        receipt, tree = self.trees.receipt("once.json"), self.trees.trees["judged"]
        self.assertEqual(judge(tree, VALIDITY, UPLOAD, self.trees.case("fixture-upload-live"), receipt)[0], HELD)
        first = receipt.read_bytes()
        code, output = judge(tree, VALIDITY, UPLOAD, self.trees.case("fixture-upload-interrupted"), receipt)
        self.assertEqual(code, INVALID, output)
        self.assertEqual(receipt.read_bytes(), first)

    def test_cached_bytecode_or_a_linked_shared_module_never_runs(self) -> None:
        marker = self.trees.scratch / "marker"
        planted = self.trees.scratch / "planted.py"
        planted.write_text(f"open({str(marker)!r}, 'w').write('ran')\n", encoding="utf-8")
        tree = self.trees.tree("planted", CHAOS / "ledger.json")
        core = tree / "chaos" / "judges" / "core"
        py_compile.compile(str(planted), cfile=str(core / "__pycache__" / f"common.{sys.implementation.cache_tag}.pyc"),
                           invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
        evidence = self.trees.case("fixture-upload-live")
        self.assertEqual(judge(tree, VALIDITY, UPLOAD, evidence)[0], INVALID)
        self.assertEqual(judge(tree, INVARIANT, BOUND, evidence)[0], INVALID)
        self.assertFalse(marker.exists())
        linked = self.trees.tree("linked", CHAOS / "ledger.json")
        common_py = linked / "chaos" / "judges" / "core" / "common.py"
        common_py.unlink()
        common_py.symlink_to(planted)
        self.assertEqual(judge(linked, VALIDITY, UPLOAD, evidence)[0], INVALID)
        self.assertEqual(judge(linked, INVARIANT, BOUND, evidence)[0], INVALID)
        self.assertFalse(marker.exists())

    def test_a_row_judged_on_a_run_of_another_scenario_is_invalid(self) -> None:
        evidence = self.trees.case("fixture-upload-live")
        code, output = judge(ROOT, INVARIANT, NEWER, evidence)
        self.assertEqual(code, INVALID, output)
        self.assertIn("does not apply to scenario", output)
        code, output = judge(ROOT, VALIDITY, CLUSTER, evidence)
        self.assertEqual(code, INVALID, output)
        self.assertIn("the evidence is a run of", output)

    def test_a_ledger_that_gives_one_id_to_two_rows_is_invalid(self) -> None:
        ledger = json.loads((CHAOS / "ledger.json").read_text(encoding="utf-8"))
        ledger["scenarios"].insert(0, dict(next(row for row in ledger["scenarios"] if row["id"] == UPLOAD), multiple=2))
        doubled = self.trees.scratch / "doubled.json"
        doubled.write_text(json.dumps(ledger), encoding="utf-8")
        tree = self.trees.tree("doubled", doubled)
        code, output = judge(tree, VALIDITY, UPLOAD, self.trees.case("fixture-upload-live"))
        self.assertEqual(code, INVALID, output)
        self.assertIn("more than one row", output)

    def family(self, name: str, body: str, ledger: Path | None = None) -> tuple[Path, str]:
        """A tree whose second judge family holds check.py: validity.py with `body` as the statements of its decide."""
        tree = self.trees.tree(name, ledger or CHAOS / "ledger.json")
        folder = tree / "chaos" / "judges" / "family"
        folder.mkdir()
        source = (CHAOS / "judges" / "core" / "validity.py").read_text(encoding="utf-8")
        old = "    return HELD, validity(scenario, evidence)\n"
        self.assertIn(old, source)
        (folder / "check.py").write_text(source.replace(old, body), encoding="utf-8")
        return tree, "chaos/judges/family/check.py"

    def test_a_judge_file_that_changes_while_the_judge_runs_gives_invalid(self) -> None:
        written = ("    with open(Path(__file__).resolve().parent / {target!r}, 'a', encoding='utf-8') as file:\n"
                   "        file.write('# written while judging\\n')\n")
        cases = {"appears": (written.format(target="added.py"), "a judge file changed while the judge ran", True),
                 "changes": (written.format(target="check.py"), "a judge file changed while the judge ran", True),
                 "cache": ("    os.mkdir(Path(__file__).resolve().parent / '__pycache__')\n", "cannot report the verdict", False)}
        for name, (statements, text, kept) in cases.items():
            with self.subTest(file=name):
                tree, script = self.family(f"changing-{name}", statements + "    return HELD, validity(scenario, evidence)\n")
                receipt = self.trees.receipt(f"changing-{name}.json", tree)
                code, output = judge(tree, script, UPLOAD, self.trees.case("fixture-upload-live"), receipt)
                self.assertEqual(code, INVALID, output)
                self.assertIn(text, output)
                self.assertEqual(receipt.exists(), kept)
                if kept:
                    self.assertEqual(json.loads(receipt.read_text(encoding="utf-8"))["key"]["outcome"], "invalid")

    def ledger_with(self, name: str, change, source: Path = CHAOS / "ledger.json") -> Path:
        ledger = json.loads(source.read_text(encoding="utf-8"))
        change(ledger)
        changed = self.trees.scratch / f"{name}.json"
        changed.write_text(json.dumps(ledger), encoding="utf-8")
        return changed

    def test_a_receipt_goes_only_into_a_directory_of_its_own_under_chaos_receipts(self) -> None:
        tree, evidence = self.trees.trees["judged"], self.trees.case("fixture-upload-live")
        (tree / "chaos" / "receipts").mkdir(exist_ok=True)
        elsewhere = self.trees.scratch / "elsewhere"
        elsewhere.mkdir()
        (tree / "chaos" / "receipts" / "linked").symlink_to(elsewhere)
        paths = {"lies outside": elsewhere / "r.json", "lies outside a": tree / "chaos" / "receipts" / "r.json",
                 "through a link": tree / "chaos" / "receipts" / "linked" / "r.json",
                 "lies outside a directory": tree / "chaos" / "receipts" / "cases" / ".." / ".." / "r.json"}
        for text, path in paths.items():
            with self.subTest(path=path):
                code, output = judge(tree, VALIDITY, UPLOAD, evidence, path)
                self.assertEqual(code, INVALID, output)
                self.assertIn("refused the receipt path", output)
                self.assertIn(text, output)
                self.assertFalse(path.exists())
        self.assertEqual(list(elsewhere.iterdir()), [])
        kept = self.trees.scratch / "receipts-elsewhere"
        linked = self.trees.tree("linked-receipts", CHAOS / "ledger.json")
        (kept / "cases").mkdir(parents=True)
        (linked / "chaos" / "receipts").symlink_to(kept)
        code, output = judge(linked, VALIDITY, UPLOAD, evidence, linked / "chaos" / "receipts" / "cases" / "r.json")
        self.assertEqual(code, INVALID, output)
        self.assertEqual(list((kept / "cases").iterdir()), [])

    @unittest.skipIf(os.geteuid() == 0, "a privileged user reads a file of mode 0")
    def test_an_evidence_file_unreadable_at_the_digest_gives_incomplete_with_a_receipt_that_says_so(self) -> None:
        for script, row in ((VALIDITY, UPLOAD), (INVARIANT, BOUND)):
            with self.subTest(script=script):
                evidence = self.trees.case("fixture-upload-live")
                (evidence / "notes.bin").write_bytes(b"unread")
                (evidence / "notes.bin").chmod(0)
                receipt = self.trees.receipt(f"unreadable-{row}.json")
                code, output = judge(self.trees.trees["judged"], script, row, evidence, receipt)
                self.assertEqual(code, INCOMPLETE, output)
                key = json.loads(receipt.read_text(encoding="utf-8"))["key"]
                self.assertEqual(key["outcome"], "incomplete")
                self.assertIn("could not be read for the receipt's digest", key["detail"])
                self.assertNotIn("notes.bin", key["evidence"])
                self.assertEqual(key["evidence"]["run.json"], hashlib.sha256((evidence / "run.json").read_bytes()).hexdigest())

    def test_an_evidence_file_over_its_byte_bound_is_invalid(self) -> None:
        tree = self.trees.tree("bounded", CHAOS / "ledger.json")
        module = tree / "chaos" / "judges" / "core" / "common.py"
        text = module.read_text(encoding="utf-8")
        self.assertIn("EVIDENCE_BYTES = 1 << 28", text)
        module.write_text(text.replace("EVIDENCE_BYTES = 1 << 28", "EVIDENCE_BYTES = 1 << 16"), encoding="utf-8")
        for script, row in ((VALIDITY, UPLOAD), (INVARIANT, BOUND)):
            code, output = judge(tree, script, row, self.trees.case("fixture-upload-live"))
            self.assertEqual(code, INVALID, output)
            self.assertIn("holds more than 65536 bytes", output)

    def test_a_stray_entry_gives_invalid_with_a_receipt_that_names_the_run(self) -> None:
        for kind in ("directory", "link"):
            with self.subTest(kind=kind):
                evidence = self.trees.case("fixture-upload-live")
                if kind == "directory":
                    (evidence / "extra").mkdir()
                else:
                    (evidence / "extra").symlink_to(evidence / "run.json")
                receipt = self.trees.receipt(f"stray-{kind}.json")
                code, output = judge(self.trees.trees["judged"], VALIDITY, UPLOAD, evidence, receipt)
                self.assertEqual(code, INVALID, output)
                self.assertIn("'extra', which is no regular file", output)
                written = json.loads(receipt.read_text(encoding="utf-8"))
                self.assertEqual(written["run"]["run_id"], "fixture-upload-live")
                digests = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in evidence.iterdir()
                           if path.is_file() and not path.is_symlink()}
                self.assertEqual(written["key"]["evidence"], {**digests, **({"extra": None} if kind == "link" else {})})

    def test_a_linked_evidence_directory_is_invalid(self) -> None:
        evidence = self.trees.case("fixture-upload-live")
        link = evidence.parent / "linked" / "fixture-upload-live"
        link.parent.mkdir()
        link.symlink_to(evidence)
        for script, row in ((VALIDITY, UPLOAD), (INVARIANT, BOUND)):
            code, output = judge(ROOT, script, row, link)
            self.assertEqual(code, INVALID, output)
            self.assertIn("is a link", output)
            self.assertEqual(judge(ROOT, script, row, Path(f"{evidence}/"))[0], HELD)

    def test_a_run_record_that_is_no_object_is_cut_or_names_no_scenario_of_the_ledger_is_invalid(self) -> None:
        for text, detail in (("[]\n", "run.json is not a JSON object"), ('{"run_id": ', "run.json is unreadable")):
            with self.subTest(text=text):
                evidence = self.trees.case("fixture-upload-live")
                (evidence / "run.json").write_text(text, encoding="utf-8")
                for script, row in ((VALIDITY, UPLOAD), (INVARIANT, BOUND)):
                    code, output = judge(ROOT, script, row, evidence)
                    self.assertEqual(code, INVALID, output)
                    self.assertIn(detail, output)
        evidence = self.trees.case("fixture-upload-live")
        edit_json(evidence / "run.json", lambda run: run.update(scenario="ks-unknown"))
        for script, row in ((VALIDITY, UPLOAD), (INVARIANT, BOUND)):
            code, output = judge(ROOT, script, row, evidence)
            self.assertEqual(code, INVALID, output)
            self.assertIn("names scenario 'ks-unknown', which the ledger lacks", output)

    def test_the_receipt_names_the_bytes_the_judge_read(self) -> None:
        body = ('    detail = validity(scenario, evidence)\n'
                '    (evidence.directory / "sweep-status.json").write_text("{}")\n'
                '    return HELD, detail\n')
        tree, script = self.family("rewriting", body)
        evidence = self.trees.case("fixture-upload-live")
        before = hashlib.sha256((evidence / "sweep-status.json").read_bytes()).hexdigest()
        receipt = self.trees.receipt("rewriting.json", tree)
        code, output = judge(tree, script, UPLOAD, evidence, receipt)
        self.assertEqual(code, HELD, output)
        self.assertEqual((evidence / "sweep-status.json").read_text(encoding="utf-8"), "{}")
        self.assertEqual(json.loads(receipt.read_text(encoding="utf-8"))["key"]["evidence"]["sweep-status.json"], before)

    def test_a_file_that_appears_after_the_listing_is_absent_to_the_judge(self) -> None:
        body = ('    (evidence.directory / "findings.json").write_text(\'{"findings": []}\')\n'
                '    return HELD, validity(scenario, evidence)\n')
        tree, script = self.family("appearing", body)
        evidence = self.trees.case("fixture-upload-live")
        (evidence / "findings.json").unlink()
        receipt = self.trees.receipt("appearing.json", tree)
        code, output = judge(tree, script, UPLOAD, evidence, receipt)
        self.assertEqual(code, INVALID, output)
        self.assertIn("the run has no findings.json", output)
        self.assertNotIn("findings.json", json.loads(receipt.read_text(encoding="utf-8"))["key"]["evidence"])

    def test_a_family_judge_that_loads_the_shared_module_without_its_digest_is_refused(self) -> None:
        tree = self.trees.tree("plain-loader", CHAOS / "ledger.json")
        folder = tree / "chaos" / "judges" / "family"
        folder.mkdir()
        (folder / "check.py").write_text(
            "import importlib.util, sys\nfrom pathlib import Path\n"
            "path = Path(__file__).resolve().parents[1] / 'core' / 'common.py'\n"
            "spec = importlib.util.spec_from_file_location('common', path)\n"
            "common = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(common)\n"
            "sys.exit(common.main('scenarios', lambda row, scenario, evidence: (0, common.validity(scenario, evidence))))\n",
            encoding="utf-8")
        receipt = self.trees.receipt("plain.json", tree)
        code, output = judge(tree, "chaos/judges/family/check.py", UPLOAD, self.trees.case("fixture-upload-live"), receipt)
        self.assertEqual(code, INVALID, output)
        self.assertIn("common.py was not loaded from the bytes its digest names", output)
        self.assertFalse(receipt.exists())

    def test_an_entry_beside_the_judge_with_a_name_that_is_no_text_or_a_fifo_is_refused_with_exit_2(self) -> None:
        evidence = self.trees.case("fixture-upload-live")
        for kind in ("bytes", "fifo"):
            tree = self.trees.tree(f"beside-{kind}", CHAOS / "ledger.json")
            core = os.fsencode(tree / "chaos" / "judges" / "core")
            if kind == "bytes":
                os.mkdir(core + b"/bad\xff")
            else:
                os.mkfifo(core + b"/notes")
            for script, row in ((VALIDITY, UPLOAD), (INVARIANT, BOUND)):
                with self.subTest(kind=kind, script=script):
                    receipt = self.trees.receipt(f"{kind}-{row}.json", tree)
                    done = subprocess.run([sys.executable, "-I", "-B", str(tree / script), row, "--evidence", str(evidence),
                                           "--receipt", str(receipt)], capture_output=True, check=False, timeout=60)
                    self.assertEqual(done.returncode, INVALID, done.stderr)
                    self.assertIn(b"is no regular file", done.stderr)
                    self.assertFalse(receipt.exists())

    def test_a_judge_started_with_standard_output_closed_keeps_its_verdict_and_its_receipt(self) -> None:
        tree, evidence = self.trees.trees["judged"], self.trees.case("fixture-upload-corrupted")
        for script, row, code in ((VALIDITY, UPLOAD, HELD), (INVARIANT, BOUND, BROKEN)):
            with self.subTest(script=script):
                receipt = self.trees.receipt(f"closed-{row}.json")
                argv = [sys.executable, "-I", "-B", str(tree / script), row, "--evidence", str(evidence),
                        "--receipt", str(receipt)]
                done = subprocess.run(["sh", "-c", 'exec 1>&-; exec "$@"', "sh", *argv], capture_output=False,
                                      stderr=subprocess.PIPE, check=False, timeout=60)
                self.assertEqual(done.returncode, code, done.stderr)
                self.assertEqual(json.loads(receipt.read_text(encoding="utf-8"))["key"]["outcome"], common.OUTCOMES[code])

    def test_both_judges_start_through_one_loader_block(self) -> None:
        def block(name: str) -> str:
            text = (CHAOS / "judges" / "core" / name).read_text(encoding="utf-8")
            return text[text.index("import contextlib"):text.index("    from common import")]
        self.assertEqual(block("validity.py"), block("invariant.py"))
        self.assertIn("LOADED_SHA256", block("validity.py"))

    def test_a_held_invariant_reads_the_records_once(self) -> None:
        tree = self.trees.tree("counted", CHAOS / "ledger.json")
        module = tree / "chaos" / "judges" / "core" / "common.py"
        text = module.read_text(encoding="utf-8")
        log = self.trees.scratch / "recorded.log"
        signature = "def recorded(scenario: dict, evidence: Evidence) -> dict:\n"
        self.assertIn(signature, text)
        module.write_text(text.replace(signature, f"{signature}    open({str(log)!r}, 'a').write('x')\n"), encoding="utf-8")
        code, output = judge(tree, INVARIANT, BOUND, self.trees.case("fixture-upload-live"))
        self.assertEqual(code, HELD, output)
        self.assertEqual(log.read_text(encoding="utf-8"), "x")

    def test_a_held_detail_is_the_judges_own_phrase_and_not_the_rows_witness_text(self) -> None:
        def change(ledger: dict) -> None:
            next(row for row in ledger["invariants"] if row["id"] == BOUND)["witness"]["expect"] = "a distinctive expectation"
        tree = self.trees.tree("witness-text", self.ledger_with("witness-text", change))
        receipt = self.trees.receipt("witness.json", tree)
        code, output = judge(tree, INVARIANT, BOUND, self.trees.case("fixture-upload-live"), receipt)
        self.assertEqual(code, HELD, output)
        detail = json.loads(receipt.read_text(encoding="utf-8"))["key"]["detail"]
        self.assertIn("no violation under the row's rule", detail)
        self.assertNotIn("a distinctive expectation", detail)

    def test_a_row_with_a_load_parameter_no_sweep_reads_or_a_fault_no_reach_event_shows_is_invalid(self) -> None:
        def scenario(ledger: dict, name: str) -> dict:
            return next(row for row in ledger["scenarios"] if row["id"] == name)
        cases = {
            "load.restarts is 20": (UPLOAD, BOUND, "fixture-upload-live",
                                    lambda ledger: scenario(ledger, UPLOAD)["load"].update(restarts=20)),
            "load.counts_restarts is 20": (UPLOAD, BOUND, "fixture-upload-live",
                                           lambda ledger: scenario(ledger, UPLOAD)["load"].update(counts_restarts=20)),
            "names no reach event the core judge counts": (
                CLUSTER, NEWER, "fixture-cluster-live",
                lambda ledger: scenario(ledger, CLUSTER).update(reach={"text": "prose alone"})),
            "names no reach event the core judge": (
                CLUSTER, NEWER, "fixture-cluster-live",
                lambda ledger: scenario(ledger, CLUSTER)["reach"].pop("faults")),
            "no profile of the scenario is a cluster profile": (
                UPLOAD, BOUND, "fixture-upload-live",
                lambda ledger: scenario(ledger, UPLOAD).update(reach={"text": "a hit", "hits": 1})),
        }
        for index, (text, (name, row, run_id, change)) in enumerate(cases.items()):
            with self.subTest(case=text):
                changed = self.ledger_with(f"row-{index}", change)
                tree = self.trees.tree(f"row-{index}", changed)
                evidence = self.trees.case(run_id)
                rebound(evidence, changed, name)
                for script, judged in ((VALIDITY, name), (INVARIANT, row)):
                    code, output = judge(tree, script, judged, evidence)
                    self.assertEqual(code, INVALID, output)
                    self.assertIn(text, output)

    def test_an_invariant_row_without_its_rule_text_or_its_obligation_code_is_invalid(self) -> None:
        changes = {"an empty text": lambda row: row["control"].update(expect=""),
                   "no text": lambda row: row["control"].pop("expect"),
                   "obligation 0": lambda row: row["witness"].update(obligation=0),
                   "obligation 256": lambda row: row["witness"].update(obligation=256),
                   "obligation as text": lambda row: row["witness"].update(obligation="1"),
                   "obligation true": lambda row: row["witness"].update(obligation=True)}
        for index, (name, change) in enumerate(changes.items()):
            with self.subTest(row=name):
                changed = self.ledger_with(f"rule-{index}", lambda ledger, change=change: change(
                    next(row for row in ledger["invariants"] if row["id"] == BOUND)))
                tree = self.trees.tree(f"rule-{index}", changed)
                for run_id in ("fixture-upload-live", "fixture-upload-corrupted"):
                    code, output = judge(tree, INVARIANT, BOUND, self.trees.case(run_id))
                    self.assertEqual(code, INVALID, output)
                    self.assertIn("the row needs its rule text as control.expect and its obligation code", output)


class Interface(unittest.TestCase):
    """The interface of chaos/judges/core/common.py that a later judge family builds on."""

    def test_the_module_exports_its_interface(self) -> None:
        for name in ("HELD", "BROKEN", "INVALID", "INCOMPLETE", "OUTCOMES", "WALL_CLOCK_KEYS", "Verdict", "row_digest",
                     "rule_digest", "identity", "minimum", "count", "scenario_profiles", "distinct", "scenario_counts",
                     "Evidence", "recorded_exit", "declaration", "kinds", "recorded", "trusted", "held", "validity", "main",
                     "EVIDENCE_BYTES", "LEDGER_BYTES", "SOURCE_BYTES"):
            self.assertTrue(hasattr(common, name), name)
        self.assertEqual((common.HELD, common.BROKEN, common.INVALID, common.INCOMPLETE), (0, 1, 2, 3))
        self.assertEqual(common.OUTCOMES, {0: "held", 1: "broken", 2: "invalid", 3: "incomplete"})
        self.assertEqual(common.WALL_CLOCK_KEYS, {"elapsed_s", "runs_per_s", "operations_per_s", "busy_us"})

    def test_digests_agree_with_the_validator_and_the_failure_identity(self) -> None:
        ledger = json.loads((CHAOS / "ledger.json").read_text(encoding="utf-8"))
        for row in ledger["invariants"] + ledger["scenarios"]:
            self.assertEqual(common.row_digest(row), validator.row_digest(row))
        self.assertEqual(common.identity(violation_key(1, BOUND_RULE)), ("violation", 1, common.rule_digest(BOUND_RULE)))
        self.assertEqual(common.identity("panic: src/lib.rs:1:1"), ("panic", None, None))
        self.assertEqual(common.identity("violation: 02" + "0" * 85), ("violation", None, None))

    def test_the_harness_and_the_judges_strip_the_same_keys_and_refuse_the_same_profile_sets(self) -> None:
        status = json.loads((RUNS / "fixture-upload-live" / "sweep-status.json").read_text(encoding="utf-8"))
        status.update(elapsed_s=1.0, runs_per_s=2.0, operations_per_s=3.0)
        status["profiles"]["upload"]["busy_us"] = 4
        self.assertEqual(harness.without_wall_clock(status), common.without_wall_clock(status))
        self.assertNotIn("busy_us", common.without_wall_clock(status)["profiles"]["upload"])
        self.assertEqual(harness.profiles_of({"load": {"reference": "upload, cs0-tenure-binding-unread; text"}}),
                         common.scenario_profiles({"load": {"reference": "upload, cs0-tenure-binding-unread; text"}}))
        for reference in ("upload,; text", "; text", ", ; text", "Upload; text", "upload cluster-broad; text", "up_load; text"):
            with self.subTest(reference=reference):
                row = {"id": "r", "load": {"reference": reference}}
                with self.assertRaises(ValueError):
                    harness.profiles_of(row)
                with self.assertRaises(common.Verdict):
                    common.scenario_profiles(row)

    def test_a_suspect_key_is_read_by_its_version_its_variant_and_its_hexadecimal_obligation(self) -> None:
        digest = common.rule_digest(BOUND_RULE)
        body = violation_key(26, BOUND_RULE).partition(": ")[2]
        self.assertEqual((len(body), body[:6]), (88, "02011a"))
        self.assertEqual(common.identity(f"violation: {body}"), ("violation", 26, digest))
        self.assertEqual(common.identity(f"violation: {body[:2]}02{body[4:]}"), ("violation", 26, digest))
        self.assertEqual(common.identity(f"violation: {body[:2]}04{body[4:]}"), ("violation", 0, None))
        unread = ("01" + body[2:], "03" + body[2:], body[:2] + "03" + body[4:], body[:-1], body + "0", body.upper(),
                  body[:20] + "g" + body[21:], "")
        for other in unread:
            with self.subTest(identity=other):
                self.assertEqual(common.identity(f"violation: {other}"), ("violation", None, None))
        self.assertEqual(common.identity(f"panic: {body}"), ("panic", None, None))
        self.assertEqual(common.identity("other"), ("other", None, None))

    def test_counts_and_minimums_refuse_what_no_run_can_fail(self) -> None:
        for value in (0, -1, True, 1.5, None):
            with self.subTest(value=value), self.assertRaises(common.Verdict) as raised:
                common.minimum({"id": "r", "load_delivery": {"k": value}}, "load_delivery", "k")
            self.assertEqual(raised.exception.code, common.INVALID)
        self.assertEqual(common.count({"k": 0}, "k", "x"), 0)
        self.assertEqual(common.scenario_profiles({"load": {"reference": "upload, cluster-broad; text"}}),
                         ["upload", "cluster-broad"])

    def test_a_later_family_imports_common_alone_and_its_receipt_names_both_directories(self) -> None:
        trees = Trees()
        try:
            tree = trees.tree("family", CHAOS / "ledger.json")
            family = tree / "chaos" / "judges" / "family"
            family.mkdir()
            # A later family's judge is the loader block of validity.py in a directory of its own.
            shutil.copy(CHAOS / "judges" / "core" / "validity.py", family / "check.py")
            receipt = trees.receipt("family.json", tree)
            code, output = judge(tree, "chaos/judges/family/check.py", UPLOAD, trees.case("fixture-upload-live"), receipt)
            self.assertEqual(code, HELD, output)
            named = sorted(json.loads(receipt.read_text(encoding="utf-8"))["key"]["judge"])
            self.assertEqual(named, ["chaos/judges/core/common.py", "chaos/judges/core/invariant.py",
                                     "chaos/judges/core/validity.py", "chaos/judges/family/check.py"])
        finally:
            shutil.rmtree(trees.scratch, ignore_errors=True)

    def test_recorded_returns_the_status_of_a_run_trusted_refuses_and_refuses_records_that_disagree(self) -> None:
        ledger = json.loads((CHAOS / "ledger.json").read_text(encoding="utf-8"))
        scenario = next(row for row in ledger["scenarios"] if row["id"] == UPLOAD)
        trees = Trees()
        try:
            def checked(folder: Path):
                evidence = common.Evidence(folder)
                evidence.check(scenario)
                return evidence
            status = common.recorded(scenario, checked(RUNS / "fixture-upload-asserting"))
            self.assertIn("alarm", status)
            with self.assertRaises(common.Verdict) as raised:
                common.trusted(scenario, checked(RUNS / "fixture-upload-asserting"))
            self.assertEqual((raised.exception.code, "alarm" in raised.exception.detail), (common.INVALID, True))
            another = trees.case("fixture-upload-asserting")
            edit_json(another / "run.json", lambda run: run.update(root_build="0" * 64))
            differing = trees.case("fixture-upload-asserting")
            edit_json(differing / "sweep-status.json",
                      lambda s: keyed(s, "h1-get", {"replay differs: 1 then 0": 1}))
            for folder, text in ((another, "the root names build"), (differing, "replayed with another ending")):
                with self.assertRaises(common.Verdict) as raised:
                    common.recorded(scenario, checked(folder))
                self.assertEqual(raised.exception.code, common.INVALID)
                self.assertIn(text, raised.exception.detail)
        finally:
            shutil.rmtree(trees.scratch, ignore_errors=True)

    def test_a_weighted_row_keeps_its_sweep_list_and_names_each_profile_once(self) -> None:
        row = {"load": {"reference": "upload,cluster-broad,upload; text"}}
        self.assertEqual(common.scenario_profiles(row), ["upload", "cluster-broad", "upload"])
        self.assertEqual(common.distinct(common.scenario_profiles(row)), ["upload", "cluster-broad"])


FAKE_CAMPAIGN = '''#!/usr/bin/env python3
import hashlib, json, os, signal, subprocess, sys, time
from pathlib import Path
here = Path(SETTINGS_DIR)
settings = json.loads((here / "fake.json").read_text())
argv = sys.argv[1:]
record = Path(settings["record"]) if settings.get("record") else None
state = json.loads(record.read_text()).get("complete") if record and record.is_file() else None
with open(here / "argv.jsonl", "a") as log:
    log.write(json.dumps({"argv": argv, "exe": __file__, "record_complete": state, "env": sorted(os.environ),
                          "cgroup": os.environ.get("CAMPAIGN_CGROUP_ROOT")}) + "\\n")
H1_RULE = "a qualified GET missed the visible version's exact bytes"
def arg(name):
    return argv[argv.index(name) + 1]
def stand(group):
    group.mkdir(parents=True, exist_ok=True)
    for above in list(group.parents)[:len(group.relative_to(os.environ["CAMPAIGN_CGROUP_ROOT"]).parts) - 1]:
        if not (above / "cgroup.procs").exists():
            (above / "cgroup.procs").write_text("")
for name, procs in settings.get("left", {}).get(argv[0], {}).items():
    group = Path(os.environ["CAMPAIGN_CGROUP_ROOT"]) / name
    stand(group)
    if procs is not None:
        (group / "cgroup.procs").write_text(procs)
    (group / "cgroup.kill").write_text("")
def build_of():
    return hashlib.sha256((Path(arg("--archive")) / "build").read_bytes()).hexdigest()
if argv[:2] == ["sim", "capabilities"]:
    print(settings.get("listing_text") or json.dumps({"capabilities": (
        "capabilities: 5\\nprofile: upload class=live\\nprofile: cluster-broad class=live\\n"
        "profile: corrupted class=control\\nprofile: h1-get-stale class=history\\n"
        "cluster: cluster-broad generator=4\\nfails: h1-get-stale violation 2 " + H1_RULE + "\\n")}))
    sys.exit(settings.get("listing_exit", 0))
elif argv[0] == "sweep":
    if settings.get("ignore_term"):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    if settings.get("descendant"):
        ready = Path(settings["descendant"])
        subprocess.Popen([sys.executable, "-c", "import signal, sys, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                          "open(sys.argv[1], 'w').write('ready'); time.sleep(600)", str(ready)])
        while not ready.exists():
            time.sleep(0.05)
    if settings.get("replace_source"):
        source = Path(settings["replace_source"])
        (here / "source.saved").write_bytes(source.read_bytes())
        source.write_text("#!/bin/sh\\necho replaced >> " + str(here / "replaced.log") + "\\nexit 9\\n")
    (here / "sweeping").write_text("")
    pens = Path(os.environ["CAMPAIGN_CGROUP_ROOT"]) / "sweep"
    for name, procs in settings.get("pens", {}).items():
        if name in settings.get("remade", []):
            (pens / (name + "-new")).mkdir(parents=True)
            for entry in os.listdir(pens / name):
                os.unlink(pens / name / entry)
            os.rmdir(pens / name)
            os.rename(pens / (name + "-new"), pens / name)
        stand(pens / name)
        if procs is not None:
            (pens / name / "cgroup.procs").write_text(procs)
        (pens / name / "cgroup.kill").write_text("")
    if settings.get("linked_kill"):
        stand(pens / "linked")
        (pens / "linked" / "cgroup.procs").write_text("")
        (pens / "linked" / "cgroup.kill").symlink_to(settings["linked_kill"])
    if settings.get("fifo_kill"):
        stand(pens / "piped")
        (pens / "piped" / "cgroup.procs").write_text("")
        os.mkfifo(pens / "piped" / "cgroup.kill")
    if settings.get("remove_build") == "before":
        (Path(arg("--archive")) / "build").unlink()
    if settings.get("sweep_exit"):
        sys.stderr.write("sweep: refused by the fake campaign\\n")
        sys.exit(settings["sweep_exit"])
    time.sleep(settings.get("sweep_s", 0))
    root = Path(arg("--root"))
    root.mkdir(mode=0o700)
    build = build_of()
    if settings.get("remove_build") == "after":
        (Path(arg("--archive")) / "build").unlink()
    if settings.get("archive_changes"):
        (Path(arg("--archive")) / "build").write_text("another build record\\n")
    if settings.get("binary_changes"):
        Path(__file__).write_text(Path(__file__).read_text() + "# changed\\n")
    checkpoint = settings.get("checkpoint")
    if checkpoint == "link":
        (root / "sweep.json").symlink_to(Path(arg("--archive")) / "build")
    elif checkpoint == "large":
        (root / "sweep.json").write_text(json.dumps({"build": build, "pad": "x" * (1 << 24)}))
    else:
        (root / "sweep.json").write_text(json.dumps({"build": settings.get("root_build", build),
                                                     "campaign": arg("--campaign")}))
    rules, history_rules = settings.get("caught_rules", {}), settings.get("history_rules", {H1_RULE: 100})
    profiles = {}
    for name in arg("--profiles").split(","):
        caught = sum(rules.values()) if name == "corrupted" else sum(history_rules.values()) if name == "h1-get-stale" else 0
        entry = {"next": 100, "busy_us": 4, "runs": 100, "pass": 0 if caught else settings.get("pass", 100),
                 "covered": 100 if name == "cluster-broad" else 0, "caught": caught, "replays": 1, "missed": 0,
                 "control": name == "corrupted", "history": name == "h1-get-stale", "suspects": 0, "suspect_keys": {},
                 "uncredited": {},
                 "caught_rules": rules if name == "corrupted" else history_rules if name == "h1-get-stale" else {}}
        if name == "h1-get-stale":
            entry["failing_history"] = True
        entry.update(settings.get("profile_counts", {}).get(name, {}))
        profiles[name] = entry
    violation = settings.get("violation")
    if violation:
        profiles["upload"].update(suspects=1, suspect_keys={violation["key"]: 1})
    counts = {}
    for index, word in enumerate(argv):
        if word == "--set":
            key, _, value = argv[index + 1].partition("=")
            counts[key] = int(value)
    if "suspects" in settings:
        (root / "suspects.jsonl").write_bytes(settings["suspects"].encode())
    elif "suspects_hex" in settings:
        (root / "suspects.jsonl").write_bytes(bytes.fromhex(settings["suspects_hex"]))
    elif settings.get("suspects_link"):
        (root / "suspects.jsonl").symlink_to(settings["suspects_link"])
    elif violation:
        line = {"build": build, "campaign": arg("--campaign"), "class": "violation", "code": 1, "counts": counts,
                "key": violation["key"], "profile": "upload", "run": violation["run"], "seed": violation["seed"],
                "elapsed_s": 3.5, "summary": None}
        (root / "suspects.jsonl").write_text(json.dumps(line) + "\\n")
    marked = [entry for entry in profiles.values() if entry["control"]]
    (root / "status").write_text(json.dumps({
        "campaign": arg("--campaign"), "counts": counts, "elapsed_s": settings.get("elapsed_s", 1000.5),
        "profiles": profiles, "controls": {"runs": sum(e["runs"] for e in marked), "profiles": len(marked),
                                           "caught": sum(e["caught"] for e in marked),
                                           "missed": sum(e["missed"] for e in marked), "no_effect": 0,
                                           "other": sum(sum(e["uncredited"].values()) for e in marked)}}))
    if settings.get("sweep_killed"):
        os.kill(os.getpid(), signal.SIGKILL)
elif argv[0] == "sweep-status":
    root = Path(arg("--root"))
    time.sleep(settings.get("status_s", 0))
    if settings.get("status_err"):
        log = Path("sweep-status.err")
        log.unlink()
        if settings["status_err"] == "fifo":
            os.mkfifo(log)
        else:
            log.symlink_to("/dev/zero")
    if settings.get("status_exit") or not (root / "status").is_file():
        sys.stderr.write("sweep-status: no sweep has written this root\\n")
        sys.exit(settings.get("status_exit") or 2)
    print((root / "status").read_text())
    sys.exit(settings.get("status_exit_after", 0))
elif argv[0] == "confirm":
    for name, procs in settings.get("attempts", {}).items():
        group = Path(os.environ["CAMPAIGN_CGROUP_ROOT"]) / name
        stand(group)
        if procs is not None:
            (group / "cgroup.procs").write_text(procs)
        (group / "cgroup.kill").write_text("")
    print(json.dumps({"dispatch": settings.get("dispatch", "queue_empty"), "findings": []}))
    sys.exit(settings.get("confirm_exit", 0))
elif argv[0] == "findings":
    if settings.get("remove_root_procs"):
        (Path(os.environ["CAMPAIGN_CGROUP_ROOT"]) / "cgroup.procs").unlink()
    if settings.get("replace_source"):
        Path(settings["replace_source"]).write_bytes((here / "source.saved").read_bytes())
    rows = []
    violation = settings.get("violation")
    if violation:
        root = Path(arg("--state")).parents[1]
        status = json.loads((root / "status").read_text())
        build = json.loads((root / "sweep.json").read_text())["build"]
        experiment = {"campaign": status["campaign"], "profile": "upload", "run": violation["run"], "counts": {},
                      "pins": {"build": build}}
        rows.append({"id": "f1", "resolved": False, "blocker": True, "verified": {
            "kind": "violation", "admission": {"job": {"experiment": experiment, "seed": violation["seed"]}},
            "artifact": {"summary": {"identity": violation["key"].partition(": ")[2]}}}})
    print(json.dumps({"findings": rows, "release_blockers": [], "elapsed_s": 2.5,
                      "triage": {"busy_us": 7, "runs_per_s": 1.5, "operations_per_s": 2.5, "stalled": False}}))
    sys.exit(settings.get("findings_exit", 0))
'''

# STUB_JUDGE writes the baseline receipt for harness tests.
STUB_JUDGE = '''import hashlib, json, os, sys, time
from pathlib import Path
core = Path(__file__).resolve().parent
tree = core.parents[2]
row = sys.argv[1]
evidence = Path(sys.argv[sys.argv.index("--evidence") + 1])
receipt = sys.argv[sys.argv.index("--receipt") + 1]
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def row_digest(entry):
    kept = {key: value for key, value in entry.items() if key != "status"}
    return hashlib.sha256(json.dumps(kept, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
judge = {path.relative_to(tree).as_posix(): digest(path) for path in sorted(core.iterdir())}
run = json.loads((evidence / "run.json").read_text())
ledger = json.loads((tree / "chaos" / "ledger.json").read_text())
rows = {entry["id"]: entry for section in ("scenarios", "invariants") for entry in ledger[section]}
key = {"row": row, "scenario": run["scenario"], "mode": run["mode"], "defect": run["defect"],
       "command": ["chaos/judges/core/validity.py", row],
       "evidence": {path.name: digest(path) for path in sorted(evidence.iterdir())},
       "system_build": run["system_build"], "harness": run["harness"], "judge": judge,
       "rows": {row: row_digest(rows[row]), run["scenario"]: row_digest(rows[run["scenario"]])},
       "outcome": "held", "detail": "valid: stub"}
meta = {"run_id": run["run_id"], "started": run["started"], "judged": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
code, text = 0, None
MODE
open(receipt, "w").write(text if text is not None else json.dumps({"key": key, "run": meta}))
AFTER
sys.exit(code)
'''


class Harness(unittest.TestCase):
    """The harness against a fake campaign binary, in a temporary tree of its own.

    The tree's harness reads any directory as a cgroup v2 one: its on_cgroup2 returns true. The test
    of that check runs a tree whose harness is unchanged.
    """

    def setUp(self) -> None:
        self.trees = Trees()
        self.tree = self.trees.tree("harness", CHAOS / "ledger.json")
        ledger = json.loads((CHAOS / "ledger.json").read_text(encoding="utf-8"))
        upload = next(row for row in ledger["scenarios"] if row["id"] == UPLOAD)
        added = {"ks-two-profiles": {"reference": "upload,cluster-broad; no production figure applies",
                                     "workers": 7, "batch_s": 11, "for_s": 13},
                 "ks-short-deadline": {"reference": "upload,cluster-broad; no production figure applies"},
                 "ks-with-counts": {"reference": "upload,cluster-broad; no production figure applies",
                                    "count_restarts": 20, "count_bytes": 9600},
                 "ks-weighted": {"reference": "upload,upload; no production figure applies"},
                 "ks-history": {"reference": "h1-get-stale; no production figure applies"}}
        for name, load in added.items():
            row = json.loads(json.dumps(upload))
            row.update(id=name, judge=f"{VALIDITY} {name}",
                       load_delivery={"min_passes_per_profile": 64, "min_covered_per_profile": 64,
                                      "min_caught_per_profile": 64})
            row["load"].update(load)
            ledger["scenarios"].append(row)
        next(row for row in ledger["scenarios"] if row["id"] == "ks-short-deadline")["deadline_s"] = 2
        self.ledger = ledger
        self.write_ledger(lambda ledger: None)
        self.place = self.trees.scratch / "host"
        for name in ("archive", "roots", "cgroup", "campaign"):
            (self.place / name).mkdir(parents=True, mode=0o700)
        (self.place / "cgroup" / "cgroup.procs").write_text("", encoding="utf-8")
        (self.place / "archive" / "build").write_text("build record\n", encoding="utf-8")
        self.binary = self.place / "campaign" / "campaign"
        self.binary.write_text(FAKE_CAMPAIGN.replace("SETTINGS_DIR", repr(str(self.place / "campaign"))), encoding="utf-8")
        self.binary.chmod(0o755)
        self.log = self.place / "campaign" / "argv.jsonl"
        self.patch("def on_cgroup2(handle: int) -> bool:\n", "def on_cgroup2(handle: int) -> bool:\n    return True\n")

    def tearDown(self) -> None:
        shutil.rmtree(self.trees.scratch, ignore_errors=True)

    def write_ledger(self, change) -> None:
        """Write the tree's ledger: the repository's rows, the test's own scenario rows, and `change` applied to a copy."""
        ledger = json.loads(json.dumps(self.ledger))
        change(ledger)
        (self.tree / "chaos" / "ledger.json").write_text(json.dumps(ledger), encoding="utf-8")

    def patch(self, old: str, new: str, tree: Path | None = None) -> None:
        source = (tree or self.tree) / "chaos" / "harness" / "run_scenario.py"
        text = source.read_text(encoding="utf-8")
        self.assertIn(old, text)
        source.write_text(text.replace(old, new, 1), encoding="utf-8")

    def argv(self, scenario: str, run_id: str, *extra: str, tree: Path | None = None) -> list[str]:
        return [sys.executable, str((tree or self.tree) / "chaos/harness/run_scenario.py"), scenario, run_id, *extra,
                "--archive", str(self.place / "archive"), "--campaign", str(self.binary),
                "--roots", str(self.place / "roots"), "--cgroup-root", str(self.place / "cgroup")]

    def group(self, name: str, procs: str) -> Path:
        """Make the group `name` under the cgroup root before a run, with its process list and an empty one in each group above it."""
        group = self.place / "cgroup" / name
        group.mkdir(parents=True)
        for above in list(group.parents)[:len(Path(name).parts) - 1]:
            if not (above / "cgroup.procs").exists():
                (above / "cgroup.procs").write_text("", encoding="utf-8")
        (group / "cgroup.procs").write_text(procs, encoding="utf-8")
        (group / "cgroup.kill").write_text("", encoding="utf-8")
        return group

    def settle(self, run_id: str, settings: dict) -> None:
        settings.setdefault("record", str(self.tree / "chaos" / "runs" / run_id / "run.json"))
        (self.place / "campaign" / "fake.json").write_text(json.dumps(settings), encoding="utf-8")

    def start(self, scenario: str, run_id: str, *extra: str, **settings: object) -> subprocess.Popen:
        """Start the harness with the three stop signals at their defaults, whatever the test runner inherited."""
        self.settle(run_id, settings)
        return subprocess.Popen(self.argv(scenario, run_id, *extra), cwd=self.tree, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, preexec_fn=defaults)

    def calls(self) -> list[dict]:
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def sweep_of(self, run_id: str) -> list[str]:
        return next(call["argv"] for call in self.calls()
                    if call["argv"][0] == "sweep" and call["argv"][call["argv"].index("--campaign") + 1] == run_id)

    def swept(self, run_id: str) -> list[str]:
        sweep = self.sweep_of(run_id)
        return sweep[sweep.index("--profiles") + 1].split(",")

    def record(self, run_id: str) -> dict:
        return json.loads((self.tree / "chaos" / "runs" / run_id / "run.json").read_text(encoding="utf-8"))

    def receipt(self, run_id: str, row: str) -> dict:
        return json.loads((self.tree / "chaos" / "receipts" / run_id / f"{row}.json").read_text(encoding="utf-8"))

    def finish(self, running: subprocess.Popen, timeout: float = 120) -> str:
        return running.communicate(timeout=timeout)[0]

    def ended(self, scenario: str, run_id: str, code: int, *extra: str, **settings: object) -> tuple[dict, str]:
        """Run the harness to its end, check its exit, and return the run record and the output."""
        running = self.start(scenario, run_id, *extra, **settings)
        output = self.finish(running)
        self.assertEqual(running.returncode, code, output)
        return self.record(run_id), output

    def wait_for(self, path: Path) -> None:
        for _ in range(600):
            if path.exists():
                return
            time.sleep(0.05)
        self.fail(f"{path} never appeared")

    def wait_for_sweep(self) -> None:
        """Wait until the fake sweep has set its signal handling and is running."""
        self.wait_for(self.place / "campaign" / "sweeping")

    def stub(self, mode: str, after: str = "") -> None:
        """Make the tree's validity judge a stub: STUB_JUDGE with `mode` before its receipt write and `after` after it."""
        (self.tree / "chaos" / "judges" / "core" / "validity.py").write_text(
            STUB_JUDGE.replace("MODE", mode).replace("AFTER", after), encoding="utf-8")

    def test_the_harness_and_the_judges_compute_one_digest_one_profile_set_and_one_count_rule(self) -> None:
        for row in self.ledger["scenarios"]:
            self.assertEqual(harness.row_digest(row), common.row_digest(row))
            self.assertEqual(harness.profiles_of(row), common.scenario_profiles(row))
            self.assertEqual(harness.counts_of(row), common.scenario_counts(row))
        self.assertEqual(harness.counts_of(next(row for row in self.ledger["scenarios"] if row["id"] == "ks-with-counts")),
                         {"restarts": 20, "bytes": 9600})
        for load in ({"count_restarts": -1}, {"count_restarts": True}, {"count_restarts": 2.0}, {"count_restarts": "20"},
                     {"count_Restarts": 1}, {"count_": 1}, {"restarts": 20}, {"counts_restarts": 20}):
            with self.subTest(load=load):
                row = {"id": "r", "load": {"reference": "upload; text", **load}}
                with self.assertRaises(ValueError):
                    harness.counts_of(row)
                with self.assertRaises(common.Verdict) as raised:
                    common.scenario_counts(row)
                self.assertEqual(raised.exception.code, common.INVALID)
        self.assertEqual(harness.WALL_CLOCK_KEYS, common.WALL_CLOCK_KEYS)
        self.assertEqual(harness.OUTCOMES, common.OUTCOMES)
        self.assertEqual((harness.LOAD_KEYS, harness.LEDGER_BYTES), (common.LOAD_KEYS, common.LEDGER_BYTES))

    def test_an_existing_run_id_is_refused_with_its_refusal_text(self) -> None:
        for folder in ("runs", "receipts"):
            (self.tree / "chaos" / folder / f"taken-{folder}").mkdir(parents=True)
            for extra in (("--dry-run",), ()):
                with self.subTest(folder=folder, extra=extra):
                    running = self.start(UPLOAD, f"taken-{folder}", *extra)
                    output = self.finish(running)
                    self.assertEqual(running.returncode, 2, output)
                    self.assertIn(f"run id taken-{folder} names an earlier run: chaos/{folder}/taken-{folder} exists", output)
        (self.tree / "chaos" / "receipts" / ".taken-staging.staging").mkdir()
        (self.tree / "chaos" / "runs" / "taken-link").symlink_to("nowhere")
        (self.tree / "chaos" / "receipts" / "taken-dangling").symlink_to("nowhere")
        taken = {"taken-staging": "chaos/receipts/.taken-staging.staging", "taken-link": "chaos/runs/taken-link",
                 "taken-dangling": "chaos/receipts/taken-dangling"}
        for run_id, path in taken.items():
            for extra in (("--dry-run",), ()):
                with self.subTest(run=run_id, extra=extra):
                    running = self.start(UPLOAD, run_id, *extra)
                    output = self.finish(running)
                    self.assertEqual(running.returncode, 2, output)
                    self.assertIn(f"run id {run_id} names an earlier run: {path} exists", output)
                    self.assertFalse((self.tree / "chaos" / "runs" / run_id).is_dir())
        self.assertFalse(self.log.exists())

    def test_a_dry_run_creates_nothing(self) -> None:
        running = self.start(UPLOAD, "fresh", "--dry-run")
        self.assertEqual(self.finish(running).strip(), f"{UPLOAD}: would sweep upload into chaos/runs/fresh")
        self.assertEqual(running.returncode, 0)
        self.assertFalse((self.tree / "chaos" / "runs").exists() or (self.tree / "chaos" / "receipts").exists())

    def test_a_row_that_lists_two_profiles_sweeps_both_and_holds(self) -> None:
        stamp = "%Y-%m-%dT%H:%M:%SZ"
        before = time.strftime(stamp, time.gmtime())
        run, output = self.ended("ks-two-profiles", "two", HELD, profile_counts={"upload": {"next": 130}})
        self.assertTrue(before <= run["started"] <= time.strftime(stamp, time.gmtime()), run["started"])
        sweep = self.sweep_of("two")
        self.assertEqual(self.swept("two"), ["upload", "cluster-broad"])
        self.assertEqual([sweep[sweep.index(flag) + 1] for flag in ("--workers", "--batch", "--for")], ["7", "11", "13"])
        binary = run["campaign_binary"]
        self.assertTrue(all(call["exe"] == binary["staged"] for call in self.calls()))
        self.ended(UPLOAD, "defaults", HELD)
        default = self.sweep_of("defaults")
        self.assertEqual([default[default.index(flag) + 1] for flag in ("--workers", "--batch", "--for")], ["28", "30", "120"])
        self.assertEqual((run["profiles"], run["complete"], run["mode"]), (["upload", "cluster-broad"], True, "live"))
        self.assertEqual(run["runs"], {"upload": {"first": 0, "next": 130}, "cluster-broad": {"first": 0, "next": 100}})
        folder = self.tree / "chaos" / "runs" / "two"
        history = [json.loads(line) for line in (folder / "history.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual([(line["profile"], line["runs"], line["build"], line["campaign"]) for line in history],
                         [(name, run["runs"][name], run["system_build"], "two") for name in ("upload", "cluster-broad")])
        self.assertEqual(sorted(path.name for path in folder.iterdir()),
                         ["findings.json", "history.jsonl", "run.json", "suspects.jsonl", "sweep-status.json"])
        findings = (folder / "findings.json").read_text(encoding="utf-8")
        self.assertIn('"stalled"', findings)
        for key in common.WALL_CLOCK_KEYS:
            self.assertNotIn(f'"{key}"', findings)
        sources = sorted((self.tree / "chaos" / "harness").iterdir())
        self.assertEqual([path.name for path in sources], ["reach.py", "run_scenario.py"])
        self.assertEqual(run["harness"], {f"chaos/harness/{path.name}": hashlib.sha256(path.read_bytes()).hexdigest()
                                          for path in sources})
        self.assertTrue(run["listing"]["cluster-broad"]["cluster"])
        self.assertEqual(run["restored"], {"left_a_process": 0, "archive_verified": True, "cause": None})
        self.assertEqual(run["confirm_dispatch"], "queue_empty")
        self.assertEqual((binary["sha256_after"], binary["source_sha256_after"]), (binary["sha256"], binary["sha256"]))
        copy = (self.tree / "chaos" / "runs" / "two" / "sweep-status.json").read_text(encoding="utf-8")
        self.assertNotIn("elapsed_s", copy)
        self.assertNotIn("busy_us", copy)
        receipts = sorted(path.name for path in (self.tree / "chaos" / "receipts" / "two").iterdir())
        self.assertEqual(receipts, [f"{BOUND}.json", "ks-two-profiles.json"])
        self.assertFalse((self.tree / "chaos" / "receipts" / ".two.staging").exists())
        self.assertIn("ks-two-profiles: held", output)
        self.assertIn("valid: upload 100 pass of 64 required, 1 replays; cluster-broad 100 covered", output)
        self.assertTrue(all(call["cgroup"] == str(self.place / "cgroup") for call in self.calls()))
        evidence = self.trees.scratch / "second" / "two"
        shutil.copytree(self.tree / "chaos" / "runs" / "two", evidence)
        edit_json(evidence / "sweep-status.json", lambda s: s["profiles"]["cluster-broad"].update(covered=63))
        for script, row in ((VALIDITY, "ks-two-profiles"), (INVARIANT, BOUND)):
            code, said = judge(self.tree, script, row, evidence)
            self.assertEqual(code, INVALID, said)
            self.assertIn("cluster-broad has 63 runs under covered", said)

    def test_a_row_that_lists_a_profile_twice_sweeps_it_weighted_and_holds(self) -> None:
        run, _ = self.ended("ks-weighted", "weighted", HELD)
        self.assertEqual(self.swept("weighted"), ["upload", "upload"])
        self.assertEqual(run["profiles"], ["upload", "upload"])
        history = (self.tree / "chaos" / "runs" / "weighted" / "history.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual([json.loads(line)["profile"] for line in history], ["upload"])

    def test_the_rows_counts_reach_the_sweep_and_the_record(self) -> None:
        run, output = self.ended("ks-with-counts", "counted", HELD)
        sweep = self.sweep_of("counted")
        sets = [sweep[index + 1] for index, word in enumerate(sweep) if word == "--set"]
        self.assertEqual(sets, ["restarts=20", "bytes=9600"], output)
        self.assertEqual(run["counts"], {"restarts": 20, "bytes": 9600})
        history = [json.loads(line) for line in
                   (self.tree / "chaos" / "runs" / "counted" / "history.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual([line["counts"] for line in history], [{"restarts": 20, "bytes": 9600}] * 2)
        self.ended(UPLOAD, "default-counts", HELD)
        self.assertEqual(self.record("default-counts")["counts"], {})
        self.assertNotIn("--set", self.sweep_of("default-counts"))

    def test_a_listed_defect_joins_the_sweep_and_the_worst_judge_exit_is_the_runs(self) -> None:
        run, output = self.ended(UPLOAD, "listed", INVALID, "--control", "corrupted", caught_rules={"another rule": 3})
        self.assertEqual(self.swept("listed"), ["upload", "corrupted"])
        self.assertTrue(run["complete"])
        self.assertEqual((self.receipt("listed", UPLOAD)["key"]["outcome"], self.receipt("listed", BOUND)["key"]["outcome"]),
                         ("held", "invalid"))
        self.assertIn(f"{UPLOAD}: held", output)
        self.assertIn(f"{BOUND}: invalid", output)
        self.finish(self.start(UPLOAD, "label", "--control", "another-binary"))
        self.assertEqual(self.swept("label"), ["upload"])
        run = self.record("label")
        self.assertEqual((run["mode"], run["defect"], run["profiles"]), ("control", "another-binary", ["upload"]))

    def test_the_run_record_is_on_file_incomplete_before_any_campaign_command(self) -> None:
        self.finish(self.start(UPLOAD, "first"))
        calls = self.calls()
        self.assertEqual([call["argv"][0] for call in calls], ["sim", "sweep", "sweep-status", "confirm", "findings"])
        self.assertTrue(all(call["record_complete"] is False for call in calls))
        self.assertTrue(self.record("first")["complete"])

    def test_a_run_without_its_findings_copy_is_incomplete(self) -> None:
        run, _ = self.ended(UPLOAD, "no-findings", INCOMPLETE, findings_exit=1)
        self.assertEqual((run["complete"], run["findings_exit"]), (False, 1))
        self.assertFalse((self.tree / "chaos" / "runs" / "no-findings" / "findings.json").exists())

    def test_a_stopped_run_is_incomplete_and_says_why_once(self) -> None:
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            with self.subTest(signal=number):
                marker = self.place / "campaign" / "sweeping"
                if marker.exists():
                    marker.unlink()
                run_id = f"stopped-{number}"
                running = self.start(UPLOAD, run_id, sweep_s=30)
                self.wait_for_sweep()
                running.send_signal(number)
                output = self.finish(running)
                self.assertEqual(running.returncode, INCOMPLETE, output)
                run = self.record(run_id)
                self.assertEqual((run["complete"], run["signal"], run["deadline_fired"], run["sweep_exit"]),
                                 (False, number, False, -signal.SIGTERM))
                self.assertEqual(output.count(f"stopped by signal {number}"), 1, output)

    def test_a_stop_between_commands_is_recorded_and_said_once(self) -> None:
        self.patch("    before = pens_of(cgroup)\n", "    os.kill(os.getpid(), signal.SIGTERM)\n    before = pens_of(cgroup)\n")
        run, output = self.ended(UPLOAD, "between", INCOMPLETE)
        self.assertEqual((run["signal"], run["complete"], run["sweep_exit"]), (signal.SIGTERM, False, None))
        self.assertEqual(output.count("stopped by signal 15"), 1, output)
        self.assertEqual([call["argv"][0] for call in self.calls()], ["sim"])

    def test_a_stop_after_the_last_command_still_ends_the_run_incomplete(self) -> None:
        marker = '        after = record["campaign_binary"]\n'
        self.patch(marker, "        os.kill(os.getpid(), signal.SIGTERM)\n" + marker)
        run, output = self.ended(UPLOAD, "late-stop", INCOMPLETE)
        self.assertEqual((run["signal"], run["complete"], run["findings_exit"]), (signal.SIGTERM, False, 0))
        self.assertEqual([call["argv"][0] for call in self.calls()], ["sim", "sweep", "sweep-status", "confirm", "findings"])
        self.assertEqual(output.count("stopped by signal 15"), 1, output)

    def test_a_sweep_that_a_signal_from_outside_killed_is_incomplete(self) -> None:
        run, output = self.ended(UPLOAD, "killed", INCOMPLETE, sweep_killed=True)
        self.assertEqual((run["complete"], run["sweep_exit"], run["signal"], run["deadline_fired"]),
                         (False, -signal.SIGKILL, None, False))
        self.assertEqual([call["argv"][0] for call in self.calls()], ["sim", "sweep"])
        self.assertEqual(run["restored"]["left_a_process"], 0)
        for row in (UPLOAD, BOUND):
            self.assertEqual(self.receipt("killed", row)["key"]["outcome"], "incomplete")

    def test_a_sweep_status_that_prints_its_document_and_fails_leaves_the_run_incomplete(self) -> None:
        run, output = self.ended(UPLOAD, "status-failed", INCOMPLETE, status_exit_after=4)
        self.assertEqual((run["complete"], run["status_exit"], run["confirm_exit"], run["error"]), (False, 4, None, None))
        self.assertEqual([call["argv"][0] for call in self.calls()], ["sim", "sweep", "sweep-status"])
        self.assertEqual([path.name for path in (self.tree / "chaos" / "runs" / "status-failed").iterdir()], ["run.json"])

    def test_the_roots_build_is_read_from_the_root(self) -> None:
        run, output = self.ended(UPLOAD, "other-root", INVALID, root_build="0" * 64)
        self.assertEqual((run["root_build"], run["complete"]), ("0" * 64, True))
        self.assertNotEqual(run["system_build"], run["root_build"])
        self.assertIn("the root names build", self.receipt("other-root", UPLOAD)["key"]["detail"])

    def test_a_campaign_command_gets_the_named_variables_of_the_environment_alone(self) -> None:
        self.settle("clean-env", {})
        given = {**os.environ, "CHAOS_PLANTED_VARIABLE": "1", "CAMPAIGN_STATE": "/nonexistent"}
        running = subprocess.Popen(self.argv(UPLOAD, "clean-env"), cwd=self.tree, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, preexec_fn=defaults, env=given)
        output = self.finish(running)
        self.assertEqual(running.returncode, HELD, output)
        named = {*harness.ENVIRONMENT, "CAMPAIGN_CGROUP_ROOT"}
        coerced_by_the_interpreter = {"LC_CTYPE"}
        calls = self.calls()
        self.assertEqual(len(calls), 5)
        for call in calls:
            self.assertLessEqual(set(call["env"]) - coerced_by_the_interpreter, named, call["argv"][0])
        self.assertEqual(self.record("clean-env")["environment"],
                         sorted(name for name in named if name in given or name == "CAMPAIGN_CGROUP_ROOT"))

    def test_a_stop_at_the_final_handoff_acts_as_the_caller_set_it(self) -> None:
        marker = "    signal.pthread_sigmask(signal.SIG_BLOCK, STOP_SIGNALS)\n    record.update("
        self.patch(marker, marker.replace("    record.update(", "    os.kill(os.getpid(), signal.SIGTERM)\n    record.update("))
        running = self.start(UPLOAD, "handoff")
        output = self.finish(running)
        self.assertEqual(running.returncode, -signal.SIGTERM, output)
        self.assertFalse(any((self.tree / "chaos" / "receipts" / "handoff").iterdir()))

    def test_a_signal_the_caller_ignores_stays_ignored(self) -> None:
        self.settle("ignored", {"sweep_s": 2})

        def ignore() -> None:
            defaults()
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
        running = subprocess.Popen(self.argv(UPLOAD, "ignored"), cwd=self.tree, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, preexec_fn=ignore)
        self.wait_for_sweep()
        running.send_signal(signal.SIGHUP)
        output = self.finish(running)
        self.assertEqual(running.returncode, HELD, output)
        self.assertEqual((self.record("ignored")["signal"], self.record("ignored")["complete"]), (None, True))

    def test_a_command_that_outlives_a_signal_is_killed_with_its_process_group_stop_wait_later(self) -> None:
        self.patch("STOP_WAIT_S = 120", "STOP_WAIT_S = 2")
        ready = self.place / "campaign" / "descendant"
        running = self.start(UPLOAD, "stubborn", sweep_s=60, ignore_term=True, descendant=str(ready))
        self.wait_for_sweep()
        self.wait_for(ready)
        survivor = subprocess.run(["pgrep", "-f", str(ready)], capture_output=True, text=True, check=False).stdout.split()
        self.assertEqual(len(survivor), 1, survivor)
        running.send_signal(signal.SIGTERM)
        output = self.finish(running, timeout=30)
        self.assertEqual(running.returncode, INCOMPLETE, output)
        run = self.record("stubborn")
        self.assertEqual((run["sweep_exit"], run["signal"], run["deadline_fired"]), (-signal.SIGKILL, signal.SIGTERM, False))
        self.assertGreaterEqual(run["seconds"], 2)
        self.assertLess(run["seconds"], 20)
        try:
            for _ in range(100):
                if not Path(f"/proc/{survivor[0]}").exists() or "Z" in Path(f"/proc/{survivor[0]}/stat").read_text().split()[2]:
                    break
                time.sleep(0.05)
            else:
                self.fail("the sweep's descendant outlived the kill of its process group")
        finally:
            with contextlib.suppress(OSError):
                os.kill(int(survivor[0]), signal.SIGKILL)

    def test_a_stop_with_an_unread_standard_error_still_records_cleans_and_judges(self) -> None:
        self.patch("STOP_WAIT_S = 120", "STOP_WAIT_S = 1")
        reader, writer = os.pipe()
        os.set_blocking(writer, False)
        with contextlib.suppress(BlockingIOError):
            while True:
                os.write(writer, b"x" * 65536)
        os.set_blocking(writer, True)
        self.settle("unread", {"sweep_s": 60, "ignore_term": True, "pens": {"sweep-0000": "4242\n"}})
        running = subprocess.Popen(self.argv(UPLOAD, "unread"), cwd=self.tree, stdout=subprocess.DEVNULL, stderr=writer,
                                   preexec_fn=defaults)
        os.close(writer)
        try:
            self.wait_for_sweep()
            running.send_signal(signal.SIGTERM)
            receipts = self.tree / "chaos" / "receipts" / "unread"
            for _ in range(600):
                if receipts.is_dir() and len(list(receipts.iterdir())) == 2:
                    break
                time.sleep(0.05)
            run = self.record("unread")
            self.assertEqual((run["complete"], run["signal"], run["restored"]["left_a_process"]), (False, 15, 1))
            self.assertEqual(sorted(path.name for path in receipts.iterdir()), [f"{BOUND}.json", f"{UPLOAD}.json"])
            kill = self.place / "cgroup" / "sweep" / "sweep-0000" / "cgroup.kill"
            self.assertEqual(kill.read_text(encoding="utf-8"), "1")
        finally:
            with os.fdopen(reader, "rb") as drained:
                drained.read()
            running.wait(timeout=60)
        self.assertEqual(running.returncode, INCOMPLETE)

    def test_the_deadline_ends_the_run_incomplete(self) -> None:
        running = self.start("ks-short-deadline", "late", sweep_s=60)
        output = self.finish(running, timeout=180)
        self.assertEqual(running.returncode, INCOMPLETE, output)
        run = self.record("late")
        self.assertEqual((run["complete"], run["deadline_fired"], run["signal"]), (False, True, None))

    def test_the_deadline_bounds_the_campaign_commands_together(self) -> None:
        run, output = self.ended("ks-short-deadline", "summed", INCOMPLETE, sweep_s=1.2, status_s=1.5)
        self.assertEqual((run["deadline_fired"], run["complete"], run["signal"]), (True, False, None))
        self.assertIn("passed its deadline of 2 s", output)

    def test_a_long_poll_does_not_delay_the_deadline(self) -> None:
        self.patch("POLL_S = 0.5", "POLL_S = 30")
        run, output = self.ended("ks-short-deadline", "past", INCOMPLETE, sweep_s=3)
        self.assertEqual((run["complete"], run["deadline_fired"]), (False, True), output)
        self.assertEqual([call["argv"][0] for call in self.calls()], ["sim", "sweep"])

    def test_a_refused_sweep_or_status_is_recorded(self) -> None:
        run, _ = self.ended(UPLOAD, "held-root", INCOMPLETE, sweep_exit=3)
        self.assertEqual((run["complete"], run["sweep_exit"], run["status_exit"]), (True, 3, 2))
        self.assertIn("no sweep has written this root", run["status_refusal"])
        self.assertEqual(sorted(path.name for path in (self.tree / "chaos" / "runs" / "held-root").iterdir()), ["run.json"])
        run, _ = self.ended(UPLOAD, "no-status", INCOMPLETE, status_exit=1)
        self.assertEqual((run["complete"], run["sweep_exit"], run["status_exit"]), (False, 0, 1))

    def test_a_sweep_that_accepted_no_root_gets_no_cgroup_kill(self) -> None:
        for code in (2, 3):
            with self.subTest(exit=code):
                run, _ = self.ended(UPLOAD, f"refused-{code}", INVALID if code == 2 else INCOMPLETE, sweep_exit=code,
                                    pens={f"sweep-{code:04}": "4242\n"})
                self.assertEqual((run["restored"]["left_a_process"], run["complete"]), (None, True))
                self.assertIn("accepted no root", run["restored"]["cause"])
                kill = self.place / "cgroup" / "sweep" / f"sweep-{code:04}" / "cgroup.kill"
                self.assertEqual(kill.read_text(encoding="utf-8"), "")

    def test_a_refused_sweep_with_its_build_removed_is_recorded_and_judged_invalid(self) -> None:
        run, _ = self.ended(UPLOAD, "refused-build", INVALID, sweep_exit=2, remove_build="before")
        self.assertEqual((run["complete"], run["sweep_exit"], run["status_exit"]), (True, 2, 2))
        self.assertFalse(run["restored"]["archive_verified"])
        self.assertIn("no sweep has written this root", run["status_refusal"])
        for row in (UPLOAD, BOUND):
            self.assertEqual(self.receipt("refused-build", row)["key"]["outcome"], "invalid")
        self.assertEqual([line for line in self.validated() if line.startswith("refused-build: ")], [])
        evidence = self.tree / "chaos" / "runs" / "refused-build"
        self.assertEqual(sorted(path.name for path in evidence.iterdir()), ["run.json", "sweep-refusal.txt"])
        self.assertEqual((evidence / "sweep-refusal.txt").read_text(encoding="utf-8"), "sweep: refused by the fake campaign\n")
        self.assertEqual(sorted(self.receipt("refused-build", UPLOAD)["key"]["evidence"]), ["run.json", "sweep-refusal.txt"])

    def validated(self) -> list[str]:
        """The findings the pinned validator prints for the tree's ledger, runs and receipts."""
        for name in ("project.yaml", "approval-policy.md", "tools"):
            source = CHAOS / name
            (shutil.copytree if source.is_dir() else shutil.copy)(source, self.tree / "chaos" / name)
        shutil.copytree(CHAOS / "receipts" / "fences", self.tree / "chaos" / "receipts" / "fences")
        done = subprocess.run([sys.executable, str(self.tree / "chaos/tools/validate_contract.py"), "chaos/ledger.json",
                               "--root", ".", "--project", "chaos/project.yaml", "--receipts", "chaos/receipts"],
                              cwd=self.tree, capture_output=True, text=True, check=False, timeout=120)
        self.assertEqual((done.returncode, done.stderr), (1, ""), done.stdout)
        return done.stdout.splitlines()

    def test_a_build_removed_after_the_sweep_leaves_the_count_taken_and_the_run_incomplete(self) -> None:
        run, _ = self.ended(UPLOAD, "gone-build", INCOMPLETE, remove_build="after", pens={"sweep-0000": "4242\n"})
        self.assertEqual((run["complete"], run["sweep_exit"], run["restored"]["left_a_process"]), (False, 0, 1))
        self.assertIn("does not exist", run["error"])
        kill = self.place / "cgroup" / "sweep" / "sweep-0000" / "cgroup.kill"
        self.assertEqual(kill.read_text(encoding="utf-8"), "1")

    def test_an_early_end_with_standard_error_on_a_broken_pipe_still_records_and_judges(self) -> None:
        self.settle("broken-pipe", {"listing_text": "not json"})
        reader, writer = os.pipe()
        os.close(reader)
        done = subprocess.run(self.argv(UPLOAD, "broken-pipe"), cwd=self.tree, stdout=subprocess.DEVNULL, stderr=writer,
                              check=False, timeout=120, preexec_fn=defaults)
        os.close(writer)
        self.assertEqual(done.returncode, INCOMPLETE)
        run = self.record("broken-pipe")
        self.assertIn("cannot read", run["error"])
        self.assertEqual(sorted(path.name for path in (self.tree / "chaos" / "receipts" / "broken-pipe").iterdir()),
                         [f"{BOUND}.json", f"{UPLOAD}.json"])

    def test_a_broken_invariant_is_the_runs_result(self) -> None:
        _, output = self.ended(UPLOAD, "broken", BROKEN, "--control", "corrupted", caught_rules={BOUND_RULE: 3})
        self.assertIn(f"{BOUND}: broken", output)
        self.assertIn(f"{UPLOAD}: held", output)
        _, output = self.ended(UPLOAD, "broken-invalid", BROKEN, "--control", "corrupted", caught_rules={BOUND_RULE: 3},
                               **{"pass": 10})
        self.assertIn(f"{BOUND}: broken", output)
        self.assertIn(f"{UPLOAD}: invalid", output)

    def test_a_live_violation_carried_through_the_harness_breaks_its_row(self) -> None:
        key = violation_key(1, BOUND_RULE)
        run, output = self.ended(UPLOAD, "live-break", BROKEN, violation={"key": key, "run": 5, "seed": 7})
        lines = (self.tree / "chaos" / "runs" / "live-break" / "suspects.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("elapsed_s", lines)
        self.assertIn(f"{BOUND}: broken", output)
        self.assertIn("f1", self.receipt("live-break", BOUND)["key"]["detail"])
        self.assertTrue(run["complete"])

    def test_the_suspect_copy_keeps_complete_lines_without_wall_clock_keys(self) -> None:
        raw = '{"b": 1, "elapsed_s": 2, "a": {"busy_us": 3}}\nnot json\r\n{"tail": true}'
        self.ended(UPLOAD, "copied", INVALID, suspects=raw)
        copy = (self.tree / "chaos" / "runs" / "copied" / "suspects.jsonl").read_bytes()
        self.assertEqual(copy, b'{"a": {}, "b": 1}\nnot json\r\n')

    def test_the_suspect_copy_keeps_a_line_the_judges_refuse_as_it_is(self) -> None:
        refused = (b'{"run": 1, "class": "replay differs", "run": 2, "class": "violation"}\n', b'{"note": "\xff"}\n')
        for index, line in enumerate(refused):
            with self.subTest(line=line):
                raw = b'{"b": 1, "elapsed_s": 2}\n' + line
                self.ended(UPLOAD, f"kept-{index}", INVALID, suspects_hex=raw.hex())
                copy = (self.tree / "chaos" / "runs" / f"kept-{index}" / "suspects.jsonl").read_bytes()
                self.assertEqual(copy, b'{"b": 1}\n' + line)
                self.assertIn("suspects.jsonl is unreadable", self.receipt(f"kept-{index}", UPLOAD)["key"]["detail"])

    def test_a_linked_suspect_log_or_checkpoint_ends_the_run_incomplete(self) -> None:
        cases = {"linked-log": {"suspects_link": str(self.place / "archive" / "build")},
                 "linked-checkpoint": {"checkpoint": "link"}, "large-checkpoint": {"checkpoint": "large"}}
        for run_id, settings in cases.items():
            with self.subTest(case=run_id):
                run, _ = self.ended(UPLOAD, run_id, INCOMPLETE, **settings)
                self.assertFalse(run["complete"])
                self.assertIsNotNone(run["error"])

    def test_a_suspect_line_over_its_byte_bound_ends_the_run_incomplete(self) -> None:
        self.patch("LINE_BYTES = 1 << 24", "LINE_BYTES = 64")
        run, _ = self.ended(UPLOAD, "long-line", INCOMPLETE, suspects=json.dumps({"pad": "x" * 200}) + "\n")
        self.assertIn("holds a line of more than 64 bytes", run["error"])
        self.assertFalse(run["complete"])
        self.ended(UPLOAD, "short-line", INVALID, suspects=json.dumps({"pad": "x" * 20}) + "\n")
        self.assertIsNone(self.record("short-line")["error"])

    def test_a_declared_history_listed_second_breaks_its_row_through_the_harness(self) -> None:
        own = json.loads((TESTS / "ledger.json").read_text(encoding="utf-8"))

        def change(ledger: dict) -> None:
            ledger["invariants"].append(next(row for row in own["invariants"] if row["id"] == H1_RULE_ROW))
            row = next(row for row in ledger["scenarios"] if row["id"] == "ks-two-profiles")
            row["load"]["reference"] = "upload,h1-get-stale; no production figure applies"
            row["invariants"] = [H1_RULE_ROW]
        self.write_ledger(change)
        run, output = self.ended("ks-two-profiles", "second-history", BROKEN)
        self.assertEqual(run["profiles"], ["upload", "h1-get-stale"])
        self.assertIn(f"{H1_RULE_ROW}: broken: the history h1-get-stale of the scenario declares the row's violation and was "
                      f"caught 100 times under the row's rule \"{H1_RULE}\" (obligation 2)", output)
        self.assertIn("ks-two-profiles: held", output)
        self.write_ledger(lambda ledger: None)

    def test_a_status_refusal_log_that_is_a_fifo_or_a_link_reads_as_unreadable(self) -> None:
        for kind in ("fifo", "link"):
            with self.subTest(kind=kind):
                running = self.start(UPLOAD, f"refusal-{kind}", status_exit=1, status_err=kind)
                output = self.finish(running, timeout=60)
                self.assertEqual(running.returncode, INCOMPLETE, output)
                self.assertIn("unreadable", self.record(f"refusal-{kind}")["status_refusal"])

    def test_every_command_runs_from_the_staged_copy_while_the_source_path_is_replaced(self) -> None:
        run, output = self.ended(UPLOAD, "replaced-source", HELD, replace_source=str(self.binary))
        self.assertEqual({call["exe"] for call in self.calls()}, {run["campaign_binary"]["staged"]}, output)
        self.assertFalse((self.place / "campaign" / "replaced.log").exists())
        self.assertEqual(run["campaign_binary"]["source_sha256_after"], run["campaign_binary"]["sha256"])

    def test_processes_left_in_the_sweeps_groups_are_counted_then_killed_through_their_cgroup_kill(self) -> None:
        target = self.place / "elsewhere"
        target.write_text("kept\n", encoding="utf-8")
        run, _ = self.ended(UPLOAD, "left", INVALID, pens={"sweep-0000": "4242\n4243\n", "sweep-0001": ""},
                            linked_kill=str(target))
        self.assertEqual(run["restored"]["left_a_process"], 2)
        pens = self.place / "cgroup" / "sweep"
        self.assertEqual((pens / "sweep-0000" / "cgroup.kill").read_text(encoding="utf-8"), "1")
        self.assertEqual((pens / "sweep-0001" / "cgroup.kill").read_text(encoding="utf-8"), "1")
        self.assertEqual(target.read_text(encoding="utf-8"), "kept\n")
        self.assertFalse((pens / "cgroup.kill").exists())
        self.assertIn("restoration not shown", self.receipt("left", UPLOAD)["key"]["detail"])

    def test_processes_left_in_the_groups_confirm_made_are_counted_then_killed(self) -> None:
        root = self.place / "cgroup"
        attempts = {"attempt-0": "4242\n", "attempt-0/nested": "4243\n4244\n", "attempt-1": ""}
        run, _ = self.ended(UPLOAD, "attempts", INVALID, attempts=attempts, left={"confirm": {"controller": "4245\n"}})
        self.assertEqual((run["confirm_exit"], run["complete"], run["restored"]["left_a_process"]), (0, True, 4))
        for name in attempts:
            self.assertEqual((root / name / "cgroup.kill").read_text(encoding="utf-8"), "1", name)
        self.assertEqual((root / "controller" / "cgroup.kill").read_text(encoding="utf-8"), "")
        self.assertIn("restoration not shown", self.receipt("attempts", UPLOAD)["key"]["detail"])

    def test_the_processes_the_sweep_and_confirm_left_are_one_count(self) -> None:
        run, _ = self.ended(UPLOAD, "both-left", INVALID, pens={"sweep-0000": "4242\n4243\n"}, attempts={"attempt-0": "9\n"})
        self.assertEqual(run["restored"]["left_a_process"], 3)

    def test_a_confirm_that_failed_has_its_groups_counted_and_killed(self) -> None:
        run, _ = self.ended(UPLOAD, "confirm-left", INCOMPLETE, confirm_exit=4, attempts={"attempt-0": "4242\n"})
        self.assertEqual((run["confirm_exit"], run["complete"], run["restored"]["left_a_process"]), (4, False, 1))
        self.assertEqual((self.place / "cgroup" / "attempt-0" / "cgroup.kill").read_text(encoding="utf-8"), "1")

    def test_a_group_confirm_made_without_its_process_list_leaves_the_count_unshown(self) -> None:
        run, _ = self.ended(UPLOAD, "attempt-no-procs", INCOMPLETE, attempts={"attempt-0": None, "attempt-1": "4242\n"})
        self.assertEqual((run["confirm_exit"], run["complete"], run["restored"]["left_a_process"]), (0, False, None))
        self.assertIn("holds no cgroup.procs", run["error"])
        self.assertEqual((self.place / "cgroup" / "attempt-1" / "cgroup.kill").read_text(encoding="utf-8"), "1")

    def test_every_group_is_counted_before_any_group_is_killed(self) -> None:
        order = self.trees.scratch / "order.log"
        for head, word in (("def processes_in(group: int, name: str, parent: int) -> int:\n", "count"),
                           ("def kill_group(group: int) -> None:\n", "kill")):
            self.patch(head, head + f"    with open({str(order)!r}, 'a', encoding='utf-8') as spy:\n"
                                    f"        spy.write('{word}\\n')\n")
        run, _ = self.ended(UPLOAD, "ordered", INVALID,
                            pens={"sweep-0000": "4242\n", "sweep-0000/nested": "4243\n4244\n", "sweep-0001": ""})
        # The last count is the read of the sweep group itself after the last command, which kills nothing.
        self.assertEqual(order.read_text(encoding="utf-8").split(), ["count"] * 3 + ["kill"] * 3 + ["count"])
        self.assertEqual(run["restored"]["left_a_process"], 3)
        for name in ("sweep-0000", "sweep-0000/nested", "sweep-0001"):
            self.assertEqual((self.place / "cgroup" / "sweep" / name / "cgroup.kill").read_text(encoding="utf-8"), "1")

    def test_every_group_under_the_root_is_counted_and_only_the_groups_this_sweep_made_are_killed(self) -> None:
        pens = self.group("sweep/old", "4240\n").parent
        (pens / "cgroup.kill").write_text("", encoding="utf-8")
        others = ("controller", "sweep/controller", "sweep/sweep-0000")
        run, _ = self.ended(UPLOAD, "owned", INVALID, pens={"sweep-0000": "4242\n"},
                            left={"sweep": {f"sweep/{name}": "4243\n" for name in others}})
        self.assertEqual(run["restored"]["left_a_process"], 5)
        self.assertEqual((pens / "sweep-0000" / "cgroup.kill").read_text(encoding="utf-8"), "1")
        for name in ("", "old", *others):
            with self.subTest(group=name or "the base"):
                self.assertEqual((pens / name / "cgroup.kill").read_text(encoding="utf-8"), "")

    def test_one_process_left_in_a_group_the_run_did_not_make_is_counted_and_makes_the_run_invalid(self) -> None:
        cases = {"controller": ("findings", "controller"), "sweep-controller": ("sweep", "sweep/controller"),
                 "nested-sweep": ("sweep", "sweep/sweep/sweep-0000"), "confirm-controller": ("confirm", "controller")}
        for run_id, (command, group) in cases.items():
            with self.subTest(group=group, left_by=command):
                run, _ = self.ended(UPLOAD, run_id, INVALID, left={command: {group: "4242\n"}})
                self.assertEqual((run["complete"], run["restored"]["left_a_process"]), (True, 1))
                self.assertEqual((self.place / "cgroup" / group / "cgroup.kill").read_text(encoding="utf-8"), "")
                self.assertIn("restoration not shown", self.receipt(run_id, UPLOAD)["key"]["detail"])
                shutil.rmtree(self.place / "cgroup" / group.split("/")[0])

    def test_a_root_whose_groups_hold_a_process_before_the_run_is_refused(self) -> None:
        for number, group in enumerate(("controller", "sweep/controller", "sweep/sweep/sweep-0000")):
            with self.subTest(group=group):
                held = self.group(group, "4242\n")
                running = self.start(UPLOAD, f"held-{number}")
                output = self.finish(running)
                self.assertEqual(running.returncode, 2, output)
                self.assertIn("holds a process before the run: 1 listed", output)
                self.assertFalse((self.tree / "chaos" / "runs" / f"held-{number}").exists())
                self.assertFalse((self.tree / "chaos" / "receipts" / f"held-{number}").exists())
                self.assertFalse(self.log.exists())
                self.assertEqual((held / "cgroup.kill").read_text(encoding="utf-8"), "")
                shutil.rmtree(self.place / "cgroup" / group.split("/")[0])

    def test_an_earlier_sweeps_worker_group_that_holds_a_process_refuses_no_start(self) -> None:
        self.group("sweep/sweep-0007", "4242\n")
        run, _ = self.ended(UPLOAD, "after-an-earlier-sweep", INVALID)
        self.assertEqual((run["complete"], run["restored"]["left_a_process"]), (True, 1))

    def test_a_group_the_run_did_not_make_without_its_process_list_leaves_the_count_unshown(self) -> None:
        run, _ = self.ended(UPLOAD, "controller-no-procs", INCOMPLETE, left={"findings": {"controller": None}})
        self.assertEqual((run["findings_exit"], run["complete"], run["restored"]["left_a_process"]), (0, False, None))
        self.assertIn("holds no cgroup.procs", run["error"])

    def test_a_cgroup_root_that_is_gone_at_the_runs_end_leaves_the_count_unshown(self) -> None:
        run, _ = self.ended(UPLOAD, "root-gone", INCOMPLETE, remove_root_procs=True)
        self.assertEqual((run["findings_exit"], run["complete"], run["restored"]["left_a_process"]), (0, False, None))
        self.assertIn("the cgroup root holds no cgroup.procs at the run's end", run["error"])

    def test_a_group_this_sweep_made_again_under_an_earlier_name_is_counted_and_killed(self) -> None:
        pen = self.group("sweep/sweep-0000", "9\n")
        earlier = pen.stat().st_ino
        run, _ = self.ended(UPLOAD, "remade", INVALID, pens={"sweep-0000": "4242\n4243\n"}, remade=["sweep-0000"])
        self.assertNotEqual(pen.stat().st_ino, earlier)
        self.assertEqual(run["restored"]["left_a_process"], 2)
        self.assertEqual((pen / "cgroup.kill").read_text(encoding="utf-8"), "1")

    @unittest.skipUnless(os.path.isfile("/sys/fs/cgroup/cgroup.controllers"), "the host mounts cgroup v2 at /sys/fs/cgroup")
    def test_a_directory_of_a_cgroup_v2_mount_is_told_from_a_plain_one(self) -> None:
        for path, held in (("/sys/fs/cgroup", True), (str(self.place), False)):
            with self.subTest(path=path):
                handle = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    self.assertEqual(harness.on_cgroup2(handle), held)
                finally:
                    os.close(handle)

    def test_a_fifo_at_cgroup_kill_blocks_no_cleanup(self) -> None:
        running = self.start(UPLOAD, "piped", fifo_kill=True)
        output = self.finish(running, timeout=60)
        self.assertEqual(running.returncode, HELD, output)

    def test_a_group_that_stands_without_its_process_list_leaves_the_count_unshown(self) -> None:
        run, _ = self.ended(UPLOAD, "no-procs", INCOMPLETE, pens={"sweep-0000": None, "sweep-0001": "4242\n"})
        self.assertIsNone(run["restored"]["left_a_process"])
        self.assertIn("holds no cgroup.procs", run["error"])
        self.assertEqual((self.place / "cgroup" / "sweep" / "sweep-0001" / "cgroup.kill").read_text(encoding="utf-8"), "1")

    def test_a_group_the_harness_cannot_list_leaves_the_count_unshown_and_the_run_incomplete(self) -> None:
        listing = "        children = [entry.name for entry in os.scandir(handle) if entry.is_dir(follow_symlinks=False)]\n"
        self.patch(listing, '        if name == "sweep-0000":\n            raise OSError("injected")\n' + listing)
        run, _ = self.ended(UPLOAD, "unlisted", INCOMPLETE, pens={"sweep-0000": "", "sweep-0001": "4242\n"})
        self.assertEqual((run["sweep_exit"], run["restored"]["left_a_process"], run["complete"]), (0, None, False))
        self.assertIn("cannot list the group sweep-0000", run["error"])
        self.assertEqual((self.place / "cgroup" / "sweep" / "sweep-0001" / "cgroup.kill").read_text(encoding="utf-8"), "1")

    def test_the_groups_of_another_command_holding_the_sweep_lock_are_left_alone_and_the_run_is_incomplete(self) -> None:
        pens = self.group("sweep/other", "4242\n").parent
        handle = os.open(pens, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            run, output = self.ended(UPLOAD, "shared", INCOMPLETE)
        finally:
            os.close(handle)
        self.assertEqual((run["restored"]["left_a_process"], run["complete"], run["sweep_exit"]), (None, False, 0))
        self.assertIn("another command holds the lock", run["restored"]["cause"])
        self.assertEqual((pens / "other" / "cgroup.kill").read_text(encoding="utf-8"), "")
        self.assertIn("another command holds", output)
        for row in (UPLOAD, BOUND):
            self.assertEqual(self.receipt("shared", row)["key"]["outcome"], "incomplete")

    def test_a_cgroup_root_that_is_no_cgroup_v2_directory_of_its_own_is_refused_before_any_command(self) -> None:
        plain = self.trees.tree("plain", CHAOS / "ledger.json")
        pens = self.place / "cgroup" / "sweep" / "sweep-0000"
        pens.mkdir(parents=True)
        (pens / "cgroup.kill").write_text("kept", encoding="utf-8")
        self.settle("plain", {})
        done = subprocess.run(self.argv(UPLOAD, "plain", tree=plain), cwd=plain, capture_output=True, text=True,
                              check=False, timeout=60)
        self.assertEqual(done.returncode, 2, done.stderr)
        self.assertIn("no directory of the cgroup v2 file system", done.stderr)
        self.assertEqual((pens / "cgroup.kill").read_text(encoding="utf-8"), "kept")
        linked = self.place / "linked-cgroup"
        linked.symlink_to(self.place / "cgroup")
        argv = self.argv(UPLOAD, "linked")
        argv[argv.index("--cgroup-root") + 1] = str(linked)
        done = subprocess.run(argv, cwd=self.tree, capture_output=True, text=True, check=False, timeout=60)
        self.assertEqual(done.returncode, 2, done.stderr)
        self.assertIn("no link", done.stderr)
        shutil.rmtree(self.place / "cgroup" / "sweep")
        (self.place / "cgroup" / "unrecorded").mkdir()
        done = subprocess.run(self.argv(UPLOAD, "unrecorded"), cwd=self.tree, capture_output=True, text=True, check=False,
                              timeout=60)
        self.assertEqual(done.returncode, 2, done.stderr)
        self.assertIn("'unrecorded'", done.stderr)
        self.assertFalse(self.log.exists())
        self.assertFalse((self.tree / "chaos" / "runs").exists() or (plain / "chaos" / "runs").exists())

    def judged(self, run_id: str, code: int, mode: str = "pass", after: str = "", **settings: object) -> tuple[dict, str]:
        """A control run whose validity judge is the stub, and whose invariant judge breaks the row."""
        self.stub(mode, after)
        return self.ended(UPLOAD, run_id, code, "--control", "corrupted", caught_rules={BOUND_RULE: 3}, **settings)

    def test_a_conforming_receipt_is_kept(self) -> None:
        _, output = self.judged("judge-conforming", BROKEN)
        self.assertIn(f"{UPLOAD}: held", output)
        self.assertEqual(self.receipt("judge-conforming", UPLOAD)["key"]["outcome"], "held")

    def test_a_judge_outside_its_contract_decides_nothing_and_leaves_the_run_incomplete(self) -> None:
        cases = {
            "exits 5 beside a full receipt": ("code = 5", ""),
            "omits a file from its receipt": ("judge.pop('chaos/judges/core/common.py')", ""),
            "names another outcome": ("key['outcome'] = 'broken'", ""),
            "names another row": ("key['row'] = 'another-row'", ""),
            "names another run": ("meta['run_id'] = 'another-run'", ""),
            "names another start": ("meta['started'] = '2000-01-01T00:00:00Z'", ""),
            "names another command": ("key['command'] = ['chaos/judges/core/other.py', row]", ""),
            "names other evidence": ("key['evidence']['run.json'] = '0' * 64", ""),
            "names no rows": ("key['rows'] = {}", ""),
            "names other harness files": ("key['harness'] = {}", ""),
            "names another build": ("key['system_build'] = '0' * 64", ""),
            "names another scenario": (f"key['scenario'] = '{CLUSTER}'", ""),
            "names another mode": ("key['mode'] = 'live'", ""),
            "names another defect": ("key['defect'] = 'planted'", ""),
            "is judged before the run started": ("meta['judged'] = '2000-01-01T00:00:00Z'", ""),
            "holds a detail that is no text": ("key['detail'] = 5", ""),
            "writes the three-field form": ("text = json.dumps({'key': {'judge': judge, 'row': row, 'outcome': 'held'}})", ""),
            "nests its receipt past the parser": ("text = '[' * 200000 + ']' * 200000", ""),
            "writes no receipt": ("sys.exit(0)", ""),
            "is ended by a signal": ("pass", "os.kill(os.getpid(), 9)"),
            "exits 1 with a broken receipt as the scenario's judge": ("key['outcome'] = 'broken'; code = 1", ""),
        }
        for index, (name, (mode, after)) in enumerate(cases.items()):
            with self.subTest(judge=name):
                run_id = f"judge-{index}"
                _, output = self.judged(run_id, INCOMPLETE, mode, after)
                self.assertIn(f"{UPLOAD}: no receipt", output)
                self.assertIn(f"{BOUND}: broken", output)
                self.assertFalse((self.tree / "chaos" / "receipts" / run_id / f"{UPLOAD}.json").exists())
                self.assertTrue((self.tree / "chaos" / "receipts" / run_id / f"{BOUND}.json").exists())
                self.assertFalse((self.tree / "chaos" / "receipts" / f".{run_id}.staging").exists())

    def test_a_broken_receipt_whose_detail_lacks_the_rows_rule_text_decides_nothing(self) -> None:
        source = self.tree / "chaos" / "judges" / "core" / "invariant.py"
        text = source.read_text(encoding="utf-8")
        quoted = '    quoted = f"\\"{rule}\\" (obligation {code})"\n'
        self.assertEqual(text.count(quoted), 1)
        source.write_text(text.replace(quoted, quoted.replace("{rule}", "{rule[:20]}")), encoding="utf-8")
        _, output = self.ended(UPLOAD, "cut-rule", INCOMPLETE, "--control", "corrupted", caught_rules={BOUND_RULE: 3})
        self.assertIn(f"{BOUND}: no receipt", output)
        self.assertIn(f"{BOUND}: broken: the control corrupted was caught 3 times under the row's rule \"{BOUND_RULE[:20]}\"",
                      output)
        self.assertFalse((self.tree / "chaos" / "receipts" / "cut-rule" / f"{BOUND}.json").exists())
        self.assertEqual(self.receipt("cut-rule", UPLOAD)["key"]["outcome"], "held")

    def test_a_receipt_over_its_byte_bound_decides_nothing(self) -> None:
        self.patch("RECEIPT_BYTES = 1 << 24", "RECEIPT_BYTES = 1 << 14")
        _, output = self.judged("oversized", INCOMPLETE, "key['detail'] = 'x' * 20000")
        self.assertIn(f"{UPLOAD}: no receipt", output)
        self.assertTrue((self.tree / "chaos" / "receipts" / "oversized" / f"{BOUND}.json").exists())

    def test_a_judge_past_its_wait_is_killed_and_its_output_relayed(self) -> None:
        self.patch("JUDGE_WAIT_S = 600", "JUDGE_WAIT_S = 3")
        _, output = self.judged("slow", INCOMPLETE, "sys.stderr.write('slow judge marker\\n'); sys.stderr.flush()",
                                "time.sleep(30)")
        self.assertIn("slow judge marker", output)
        self.assertIn("ran past JUDGE_WAIT_S, 3 s", output)
        self.assertFalse((self.tree / "chaos" / "receipts" / "slow" / f"{UPLOAD}.json").exists())

    def test_a_receipt_already_at_its_final_name_stays_and_the_row_decides_nothing(self) -> None:
        placed = f"(Path(receipt).parents[1] / run['run_id'] / '{BOUND}.json').write_text('placed')"
        _, output = self.judged("placed", INCOMPLETE, placed)
        self.assertIn(f"{BOUND}: no receipt", output)
        self.assertEqual((self.tree / "chaos" / "receipts" / "placed" / f"{BOUND}.json").read_text(encoding="utf-8"), "placed")
        self.assertEqual(self.receipt("placed", UPLOAD)["key"]["outcome"], "held")

    def test_a_refused_listing_is_incomplete_before_the_sweep(self) -> None:
        run, _ = self.ended(UPLOAD, "no-listing", INCOMPLETE, listing_exit=1)
        self.assertEqual((run["listing_exit"], run["sweep_exit"], run["error"]), (1, None, None))
        self.assertEqual([call["argv"][0] for call in self.calls()], ["sim"])

    def test_a_confirm_that_did_not_empty_its_queue_or_failed_is_incomplete(self) -> None:
        for name, settings in (("interrupted", {"dispatch": "interrupted"}), ("paused", {"dispatch": "paused"}),
                               ("failed", {"confirm_exit": 4})):
            with self.subTest(case=name):
                run, _ = self.ended(UPLOAD, f"confirm-{name}", INCOMPLETE, **settings)
                self.assertEqual((run["complete"], run["error"]), (False, None))
                self.assertEqual(run["confirm_exit"], settings.get("confirm_exit", 0))
                self.assertNotIn("findings", run["commands"])

    def test_a_sweep_whose_status_shows_less_than_its_for_or_no_finite_time_is_incomplete(self) -> None:
        for index, elapsed in enumerate((119, float("nan"), float("inf"), True)):
            with self.subTest(elapsed=elapsed):
                run_id = f"short-{index}"
                run, _ = self.ended(UPLOAD, run_id, INCOMPLETE, elapsed_s=elapsed)
                self.assertFalse(run["complete"])
                self.assertNotIn("confirm", run["commands"])
        run, _ = self.ended(UPLOAD, "exact", HELD, elapsed_s=120)
        self.assertTrue(run["complete"])

    def test_a_campaign_binary_that_changes_between_its_first_hash_and_its_copy_runs_no_command(self) -> None:
        marker = '    staged = stage(Path(record["campaign_binary"]["path"]),'
        self.patch(marker, '    with open(record["campaign_binary"]["path"], "a", encoding="utf-8") as changed:\n'
                           '        changed.write("# changed after its first hash\\n")\n' + marker)
        run, output = self.ended(UPLOAD, "restaged", INCOMPLETE)
        self.assertIn("changed between its first hash and its copy", run["error"])
        self.assertEqual((run["complete"], run["commands"]), (False, {}))
        self.assertFalse(self.log.exists())

    def test_a_campaign_binary_replaced_during_the_run_is_incomplete(self) -> None:
        run, _ = self.ended(UPLOAD, "replaced", INCOMPLETE, binary_changes=True)
        self.assertNotEqual(run["campaign_binary"]["sha256_after"], run["campaign_binary"]["sha256"])
        self.assertFalse(run["complete"])

    def test_an_archive_changed_during_the_sweep_is_not_verified(self) -> None:
        run, _ = self.ended(UPLOAD, "changed", INVALID, archive_changes=True)
        self.assertFalse(run["restored"]["archive_verified"])

    def test_a_history_swept_by_a_row_keeps_its_declared_violation_and_holds(self) -> None:
        run, output = self.ended("ks-history", "history", HELD)
        self.assertEqual(run["listing"]["h1-get-stale"],
                         {"class": "history", "cluster": False, "fails": f"violation 2 {H1_RULE}"})
        self.assertIn("h1-get-stale 100 caught of 64 required", output)
        self.assertEqual(harness.parse_listing("profile: h1-get-stale class=history\nfails: h1-get-stale unsuccessful a b\n"),
                         {"h1-get-stale": {"class": "history", "cluster": False, "fails": "unsuccessful a b"}})

    def test_a_harness_whose_outputs_are_closed_still_judges_and_keeps_every_receipt(self) -> None:
        self.settle("closed", {})
        done = subprocess.run(["sh", "-c", 'exec 1>&- 2>&-; exec "$@"', "sh", *self.argv("ks-two-profiles", "closed")],
                              cwd=self.tree, check=False, timeout=120, preexec_fn=defaults)
        self.assertEqual(done.returncode, HELD)
        receipts = sorted(path.name for path in (self.tree / "chaos" / "receipts" / "closed").iterdir())
        self.assertEqual(receipts, [f"{BOUND}.json", "ks-two-profiles.json"])

    def refused(self, scenario: str, run_id: str, *extra: str, text: str = "", dry: bool = True) -> None:
        """The harness refuses the start with exit 2 and its own text, in the dry-run form too when `dry`, and runs and creates nothing."""
        for form in ((("--dry-run",), ()) if dry else ((),)):
            with self.subTest(scenario=scenario, run_id=run_id, extra=extra, form=form):
                running = self.start(scenario, run_id, *extra, *form)
                output = self.finish(running)
                self.assertEqual(running.returncode, 2, output)
                self.assertIn(text, output)
        self.assertFalse(self.log.exists())
        for folder in (self.tree / "chaos" / "runs" / run_id, self.tree / "chaos" / "receipts" / run_id,
                       self.place / "roots" / run_id):
            self.assertFalse(folder.exists() or folder.is_symlink(), folder)

    def test_a_malformed_run_id_defect_or_ledger_is_refused_before_anything_runs(self) -> None:
        self.refused(UPLOAD, "fences\n", text="is no id")
        self.refused(UPLOAD, "Upper", text="is no id")
        self.refused(UPLOAD, "fine", "--control", "two words", text="no profile name or label")
        self.refused("ks-missing", "fine", text="no scenario")

        def scenario(ledger: dict) -> dict:
            return next(row for row in ledger["scenarios"] if row["id"] == UPLOAD)

        def escaping(ledger: dict) -> None:
            scenario(ledger)["invariants"].append("../escape")
            ledger["invariants"].append(dict(ledger["invariants"][0], id="../escape", judge=f"{INVARIANT} ../escape"))
        cases = (
            (escaping, "invariants lists row ids"),
            (lambda ledger: scenario(ledger)["invariants"].append(UPLOAD), "invariants lists row ids"),
            (lambda ledger: scenario(ledger).update(judge=f"{VALIDITY} {CLUSTER}"), "a judge is chaos/judges"),
            (lambda ledger: scenario(ledger).update(judge=f"chaos/harness/run_scenario.py {UPLOAD}"), "a judge is chaos/judges"),
            (lambda ledger: scenario(ledger).update(judge=f"chaos/judges/core/absent.py {UPLOAD}"), "no regular file"),
            (lambda ledger: ledger["invariants"].append(dict(ledger["invariants"][0])), "more than one row"),
            (lambda ledger: scenario(ledger)["load"].update(restarts=20), "load.restarts is 20"),
            (lambda ledger: scenario(ledger)["load"].update(count_restarts="20"), "load.count_restarts is '20'"),
            (lambda ledger: scenario(ledger)["load"].update(count_restarts=-1), "load.count_restarts is -1"),
            (lambda ledger: scenario(ledger)["load"].update(count_restarts=True), "load.count_restarts is True"),
            (lambda ledger: scenario(ledger)["load"].update(count_restarts=1.5), "load.count_restarts is 1.5"),
            (lambda ledger: scenario(ledger)["load"].update({"count_Re": 1}), "load.count_Re is 1"),
            (lambda ledger: scenario(ledger)["invariants"].append(BOUND), "invariants lists row ids"),
            (lambda ledger: scenario(ledger)["load"].update(workers=0), "are positive integers"),
            (lambda ledger: scenario(ledger)["load"].update(for_s=True), "are positive integers"),
            (lambda ledger: scenario(ledger)["load"].update(batch_s="30"), "are positive integers"),
            (lambda ledger: scenario(ledger).update(deadline_s=0), "are positive integers"),
        )
        for change, text in cases:
            self.write_ledger(change)
            self.refused(UPLOAD, "fine", text=text)
        self.write_ledger(lambda ledger: None)

    def test_a_ledger_that_is_linked_special_or_repeats_a_key_is_refused_by_the_harness_and_the_judges(self) -> None:
        ledger = self.tree / "chaos" / "ledger.json"
        text = ledger.read_text(encoding="utf-8")
        kept = self.place / "ledger-elsewhere.json"
        cases = {"linked": lambda: (kept.write_text(text, encoding="utf-8"), ledger.unlink(), ledger.symlink_to(kept)),
                 "a fifo": lambda: (ledger.unlink(), os.mkfifo(ledger)),
                 "repeated": lambda: ledger.write_text('{"scenarios": [], ' + text[1:], encoding="utf-8")}
        evidence = self.trees.case("fixture-upload-live")
        for name, change in cases.items():
            with self.subTest(ledger=name):
                change()
                self.refused(UPLOAD, "fine", text="cannot read chaos/ledger.json")
                for script, row in ((VALIDITY, UPLOAD), (INVARIANT, BOUND)):
                    code, said = judge(self.tree, script, row, evidence)
                    self.assertEqual(code, INVALID, said)
                    self.assertIn("ledger.json is unreadable", said)
                ledger.unlink()
                ledger.write_text(text, encoding="utf-8")

    def test_a_run_without_its_host_inputs_is_refused(self) -> None:
        (self.place / "cgroup" / "cgroup.procs").unlink()
        self.refused(UPLOAD, "no-cgroup", text="holds no cgroup.procs", dry=False)
        (self.place / "cgroup" / "cgroup.procs").write_text("", encoding="utf-8")
        self.binary.chmod(0o644)
        self.refused(UPLOAD, "no-exec", text="is no executable file", dry=False)
        self.binary.chmod(0o755)
        build = (self.place / "archive" / "build").read_text(encoding="utf-8")
        (self.place / "archive" / "build").unlink()
        self.refused(UPLOAD, "no-build", text="holds no build record", dry=False)
        (self.place / "archive" / "build").write_text(build, encoding="utf-8")
        for name in ("taken-root", "taken-root.harness"):
            with self.subTest(taken=name):
                (self.place / "roots" / name).mkdir(parents=True)
                running = self.start(UPLOAD, "taken-root")
                output = self.finish(running)
                self.assertEqual(running.returncode, 2, output)
                self.assertIn("exists: a run sweeps a new root", output)
                self.assertFalse(self.log.exists() or (self.tree / "chaos" / "runs" / "taken-root").exists())
                (self.place / "roots" / name).rmdir()

    def test_a_linked_runs_or_receipts_directory_and_help_are_refused(self) -> None:
        for folder in ("runs", "receipts"):
            with self.subTest(folder=folder):
                target = self.place / f"{folder}-target"
                target.mkdir()
                (self.tree / "chaos" / folder).symlink_to(target)
                self.refused(UPLOAD, "fine", text="is a symbolic link")
                self.assertEqual(list(target.iterdir()), [])
                (self.tree / "chaos" / folder).unlink()
        running = subprocess.run([sys.executable, str(self.tree / "chaos/harness/run_scenario.py"), "--help"],
                                 capture_output=True, text=True, check=False, timeout=60)
        self.assertEqual(running.returncode, 2)
        self.assertIn("usage", running.stdout)


class Clocked(unittest.TestCase):
    """harness.Stopper at its command boundaries, under a clock the test sets."""

    def setUp(self) -> None:
        self.scratch = Path(tempfile.mkdtemp(prefix="chaos-stopper-"))
        self.saved = harness.time
        self.now = 0.0
        vars(harness)["time"] = types.SimpleNamespace(monotonic=lambda: self.clock())
        self.reading = lambda: self.now

    def tearDown(self) -> None:
        vars(harness)["time"] = self.saved
        shutil.rmtree(self.scratch, ignore_errors=True)

    def clock(self) -> float:
        return self.reading()

    def command(self, stopper: Any, name: str, script: str) -> int | None:
        return stopper.run(["sh", "-c", script], {"PATH": os.environ["PATH"]}, self.scratch,
                           self.scratch / f"{name}.out", self.scratch / f"{name}.err")

    def test_a_command_that_ends_on_time_leaves_the_deadline_unfired(self) -> None:
        stopper = harness.Stopper(10)
        self.assertEqual(self.command(stopper, "first", "exit 0"), 0)
        self.assertFalse(stopper.deadline_fired)

    def test_the_deadline_passed_between_commands_starts_no_command(self) -> None:
        stopper = harness.Stopper(10)
        self.assertEqual(self.command(stopper, "first", "exit 0"), 0)
        self.now = 11.0
        self.assertIsNone(self.command(stopper, "second", f"touch {self.scratch / 'ran'}"))
        self.assertTrue(stopper.deadline_fired)
        self.assertFalse((self.scratch / "second.out").exists() or (self.scratch / "ran").exists())

    def test_a_command_whose_end_is_seen_past_the_deadline_fires_it(self) -> None:
        stopper = harness.Stopper(10)
        seen = {"started": False}

        def reading() -> float:
            if stopper.child is not None:
                seen["started"] = True
            return 100.0 if seen["started"] and stopper.child is None else 0.0
        self.reading = reading
        self.assertEqual(self.command(stopper, "first", "sleep 0.3; exit 0"), 0)
        self.assertTrue(stopper.deadline_fired)

    def test_a_deadline_passed_while_the_logs_are_made_starts_no_command(self) -> None:
        stopper = harness.Stopper(10)
        readings = iter([0.0])
        self.reading = lambda: next(readings, 100.0)
        self.assertIsNone(self.command(stopper, "first", f"touch {self.scratch / 'ran'}"))
        self.assertTrue(stopper.deadline_fired)
        self.assertFalse((self.scratch / "ran").exists())


def reach_suite(script: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """Run the reach suite's script in a process of its own, as ReachFamily starts it: in isolated mode, so its
    imports come from the interpreter's installation, as those of this test do under the pre-push hook."""
    return subprocess.run([sys.executable, "-I", str(script)], capture_output=True, text=True, check=False,
                          timeout=600, env=env)


class ReachFamily(unittest.TestCase):
    """The reach judges' own suite, run in its own process so its load of common.py stays its own."""

    def test_the_reach_suite_passes(self) -> None:
        done = reach_suite(TESTS / "test_reach.py")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_the_reach_suite_runs_on_the_interpreters_own_modules(self) -> None:
        # A module beside the suite's script and one on PYTHONPATH both shadow its import and exit 0,
        # so the script reaches its own exit only when it starts on the interpreter's own module.
        with tempfile.TemporaryDirectory() as scratch:
            beside, path = Path(scratch) / "tests", Path(scratch) / "path"
            for folder in (beside, path):
                folder.mkdir()
                (folder / "colorsys.py").write_text("raise SystemExit(0)\n")
            (beside / "test_reach.py").write_text("import colorsys\nraise SystemExit(7)\n")
            done = reach_suite(beside / "test_reach.py", {**os.environ, "PYTHONPATH": str(path)})
            self.assertEqual(done.returncode, 7, done.stdout + done.stderr)


class Collected(unittest.TestCase):
    """The program run by name runs the tests of each family beside it."""

    def test_a_run_by_name_collects_the_ordering_familys_tests(self) -> None:
        def cases(suite):
            for test in suite:
                yield from cases(test) if isinstance(test, unittest.TestSuite) else [test]
        named = load_tests(unittest.TestLoader(), unittest.TestSuite(), None)
        found = {type(test).__module__ for test in cases(named)}
        self.assertIn("chaos_test_ordering", found)
        self.assertNotIn("chaos_test_reach", found)
        self.assertEqual(list(cases(load_tests(unittest.TestLoader(), unittest.TestSuite(), "test*.py"))), [])


class ContractRows(unittest.TestCase):
    """What the contract's own ledger rows share."""

    def test_every_scenario_row_states_one_restoration(self) -> None:
        """One harness writes `restored` for every scenario, so the contract's scenario rows hold one restoration text.

        A scenario whose restoration differs by design is named here with its reason.
        """
        rows = json.loads((CHAOS / "ledger.json").read_text(encoding="utf-8"))["scenarios"]
        by_text: dict[str, list[str]] = {}
        for row in rows:
            by_text.setdefault(row["restoration"], []).append(row["id"])
        self.assertGreaterEqual(len(rows), 2)
        self.assertEqual(len(by_text), 1, f"the scenario rows state {len(by_text)} restoration texts: {sorted(by_text.values())}")


OWN_PROCESS = {"test_reach.py"}


def load_tests(loader: unittest.TestLoader, tests: unittest.TestSuite, pattern: str | None) -> unittest.TestSuite:
    """This program's tests and, when it runs by name, those of every other test_*.py beside it but OWN_PROCESS.

    Discovery passes its pattern and collects each file itself. ReachFamily runs each OWN_PROCESS file as a
    program of its own.
    """
    for path in sorted(TESTS.glob("test_*.py")) if pattern is None else ():
        if path != Path(__file__).resolve() and path.name not in OWN_PROCESS:
            tests.addTests(loader.loadTestsFromModule(load_module(f"chaos_{path.stem}", path)))
    return tests


if __name__ == "__main__":
    unittest.main()
