#!/usr/bin/env python3
"""Judge the recorded runs of the ordering figure and the cases built from them.

    python3 chaos/tests/test_ordering.py

test_judges.py runs these tests too. The runs under chaos/tests/runs/ named fixture-ordering-*
are real runs of the harness, of the scenarios ks-ordering-figure-short and
ks-ordering-figure-few of this directory's ledger.json, recorded as README.md states. Every other
case edits a copy of one of them in a temporary directory. The figure judge shows exits 0, 1, 2
and 3, and this family's validity judge exits 0, 2 and 3.
"""
from __future__ import annotations

import importlib.util
import json
import math
import re
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from decimal import Decimal, localcontext
from pathlib import Path
from typing import Any

TESTS = Path(__file__).resolve().parent
CHAOS = TESTS.parent
ROOT = CHAOS.parent
RUNS = TESTS / "runs"
VALIDITY, FIGURE = "chaos/judges/ordering/validity.py", "chaos/judges/ordering/figure.py"
ROW, SHORT, FEW = "ks-ordering-controls-caught", "ks-ordering-figure-short", "ks-ordering-figure-few"
LIVE, UNMET, FEW_RUN = "fixture-ordering-live", "fixture-ordering-premise-unmet", "fixture-ordering-few"
MISSED_RUN = "fixture-ordering-missed"
CONTROLS = ("cluster-order-1", "cluster-order-2", "cluster-order-3")
RULE = "a GET returned bytes no upload of its key wrote"
LIMIT = "inconclusive: limit same_time"
HELD, BROKEN, INVALID, INCOMPLETE = 0, 1, 2, 3

# RECORDED maps each recorded run to each judged row's exit code and a detail substring.
RECORDED = {
    LIVE: {SHORT: (HELD, "valid: cluster-order-1"), ROW: (HELD, "each planted ordering control caught")},
    UNMET: {SHORT: (HELD, "control cluster-order-1-premise-unmet"),
            ROW: (BROKEN, "cluster-order-1 (depth 1, n 26, k 20000): not found in")},
    FEW_RUN: {FEW: (INVALID, "has no replay"),
              ROW: (INCOMPLETE, "cluster-order-3 has 0 runs that ended caught, missed or with no effect")},
    MISSED_RUN: {SHORT: (INVALID, 'the totals carry {"alarm": "8658 control runs were missed"}'),
                 ROW: (BROKEN, "cluster-order-1 missed 5740 runs whose plant took effect and met no check under the row's rule")},
}
# Each control's counts in the status of fixture-ordering-live: runs, caught, no effect, ended at the limit.
LIVE_COUNTS = {"cluster-order-1": (85653, 5551, 76994, 3108), "cluster-order-2": (85389, 1739, 80450, 3200),
               "cluster-order-3": (85367, 1098, 80961, 3308)}
# exact_bound below gives each control's one-sided 95% Clopper-Pearson lower bound, to 12 significant digits.
LIVE_BOUNDS = {"cluster-order-1": 0.0634294390954, "cluster-order-2": 0.0195767600809, "cluster-order-3": 0.0122341795158}
# The same calculation gives the bound at 10,000,000 runs, by caught runs.
MOST_BOUNDS = {5: 1.970149768015017693e-7, 1234567: 0.123285622123658822}
# The control of fixture-ordering-premise-unmet that its build leaves uncaught: runs, no effect, ended at the limit.
UNMET_COUNTS = (82020, 78890, 3130)
# Each control's counts in the status of fixture-ordering-missed: runs, missed, no effect, ended at the limit.
MISSED_COUNTS = {"cluster-order-1": (86264, 5740, 77413, 3111), "cluster-order-2": (86184, 1819, 81122, 3243),
                 "cluster-order-3": (86007, 1099, 81683, 3225)}

sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location("chaos_ordering_figure", CHAOS / "judges" / "ordering" / "figure.py")
assert _spec is not None and _spec.loader is not None
figure = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(figure)
_spec = importlib.util.spec_from_file_location("chaos_ordering_harness", CHAOS / "harness" / "run_scenario.py")
assert _spec is not None and _spec.loader is not None
harness = importlib.util.module_from_spec(_spec)
sys.modules["chaos_ordering_harness"] = harness
_spec.loader.exec_module(harness)


def exact_bound(caught: int, runs: int, confidence: str) -> Decimal:
    """The one-sided Clopper-Pearson lower bound in 60-digit decimals, by bisection on 1 - P(X < caught), for a few catches."""
    with localcontext() as context:
        context.prec = 60
        alpha, low, high = 1 - Decimal(confidence), Decimal(0), Decimal(caught) / runs
        for _ in range(200):
            middle = (low + high) / 2
            below = sum(Decimal(math.comb(runs, index)) * middle ** index * (1 - middle) ** (runs - index)
                        for index in range(caught))
            low, high = (middle, high) if 1 - below < alpha else (low, middle)
        return low


def edit_json(path: Path, change) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    change(value)
    path.write_text(json.dumps(value, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def edit_history(evidence: Path, profile: str, change) -> None:
    """Edit the history.jsonl line of `profile` in place."""
    lines = [json.loads(line) for line in (evidence / "history.jsonl").read_text(encoding="utf-8").splitlines()]
    for line in lines:
        if line["profile"] == profile:
            change(line)
    (evidence / "history.jsonl").write_text("".join(json.dumps(line, sort_keys=True) + "\n" for line in lines),
                                            encoding="utf-8")


class Tree:
    """A temporary repository tree whose chaos/ledger.json is this directory's, and the cases copied beside it.

    `need` and `confidence` replace the row's min_runs_per_control and confidence in the tree's
    ledger, `threshold` sets other keys of its threshold and `row` edits the row; a run's record
    digests its scenario row alone, so the recorded runs stay runs of their scenario.
    """

    def __init__(self, need: int | None = None, confidence: object = None, threshold: dict | None = None,
                 row=None) -> None:
        self.scratch = Path(tempfile.mkdtemp(prefix="chaos-ordering-"))
        self.top = self.scratch / "tree"
        (self.top / "chaos").mkdir(parents=True)
        shutil.copytree(CHAOS / "judges", self.top / "chaos" / "judges", ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copy(TESTS / "ledger.json", self.top / "chaos" / "ledger.json")
        changed = {key: value for key, value in (("min_runs_per_control", need), ("confidence", confidence))
                   if value is not None}
        changed.update(threshold or {})
        if changed:
            edit_json(self.top / "chaos" / "ledger.json", lambda ledger: next(
                row for row in ledger["invariants"] if row["id"] == ROW)["threshold"].update(changed))
        if row is not None:
            edit_json(self.top / "chaos" / "ledger.json", lambda ledger: row(next(
                entry for entry in ledger["invariants"] if entry["id"] == ROW)))
        self.cases = 0
        self.receipts = 0

    def receipt(self, name: str) -> Path:
        """A new receipt path under the tree's chaos/receipts/, where a judge writes its receipts."""
        self.receipts += 1
        folder = self.top / "chaos" / "receipts" / f"case-{self.receipts}"
        folder.mkdir(parents=True)
        return folder / f"{name}.json"

    def case(self, run_id: str, run=None, status=None) -> Path:
        """A fresh copy of a recorded run, with run.json and sweep-status.json edited by `run` and `status`."""
        self.cases += 1
        target = self.scratch / "cases" / str(self.cases) / run_id
        shutil.copytree(RUNS / run_id, target)
        for name, change in (("run.json", run), ("sweep-status.json", status)):
            if change is not None:
                edit_json(target / name, change)
        return target

    def judge(self, script: str, row: str, evidence: Path, receipt: Path | None = None) -> tuple[int, str]:
        argv = [sys.executable, "-I", "-B", str(self.top / script), row, "--evidence", str(evidence)]
        argv += ["--receipt", str(receipt)] if receipt is not None else []
        done = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=120)
        return done.returncode, done.stdout + done.stderr


class Recorded(unittest.TestCase):
    """Each recorded run gets the exit its record names from each judge, and the receipt holds the figure and the scope."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tree = Tree()

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tree.scratch, ignore_errors=True)

    def test_each_recorded_run_gets_its_exit_from_each_judge(self) -> None:
        for run_id, rows in RECORDED.items():
            for row, (code, text) in rows.items():
                with self.subTest(run=run_id, row=row):
                    exit_code, output = self.tree.judge(FIGURE if row == ROW else VALIDITY, row, self.tree.case(run_id))
                    self.assertEqual(exit_code, code, output)
                    self.assertIn(text, output)

    def test_a_run_whose_status_names_another_campaign_is_invalid(self) -> None:
        # run.json names its own campaign, and the status another.
        evidence = self.tree.case(LIVE, status=lambda s: s.update(campaign="another-campaign"))
        for script, row in ((FIGURE, ROW), (VALIDITY, SHORT)):
            code, output = self.tree.judge(script, row, evidence)
            self.assertEqual(code, INVALID, output)
            self.assertIn("the status names campaign 'another-campaign'", output)
        counted = self.tree.case(LIVE, status=lambda s: s.update(counts={"turns": 9}))
        for script, row in ((FIGURE, ROW), (VALIDITY, SHORT)):
            code, output = self.tree.judge(script, row, counted)
            self.assertEqual(code, INVALID, output)
            self.assertIn("with counts {'turns': 9}, and the run swept 'fixture-ordering-live' with {}", output)

    def test_the_broken_receipt_names_the_control_its_rule_and_its_counts(self) -> None:
        # A break names the control, the full rule text and its counts; zero caught gives the rule of three.
        receipt = self.tree.receipt("unmet")
        code, output = self.tree.judge(FIGURE, ROW, self.tree.case(UNMET), receipt)
        self.assertEqual(code, BROKEN, output)
        key = json.loads(receipt.read_text(encoding="utf-8"))["key"]
        line = key["figure"][0]
        runs, no_effect, limited = UNMET_COUNTS
        self.assertEqual((line["control"], line["runs"], line["caught"], line["no_effect"], line["missed"], line["other"],
                          line["eligible"]), ("cluster-order-1", runs, 0, no_effect, 0, limited, no_effect))
        self.assertEqual(line["other_endings"], {LIMIT: limited})
        for text in (f"not found in {runs} runs; rate below 3/{runs} at 95%", f'"{RULE}"',
                     f"runs {runs}, caught 0, no effect {no_effect}, missed 0, other {limited}"):
            self.assertIn(text, key["detail"])
        self.assertEqual([other["caught"] > 0 for other in key["figure"]], [False, True, True])

    def test_the_recorded_miss_is_broken_for_each_control_under_the_supervisors_suspect_key(self) -> None:
        evidence, receipt = self.tree.case(MISSED_RUN), self.tree.receipt("missed")
        status = json.loads((evidence / "sweep-status.json").read_text(encoding="utf-8"))
        run = json.loads((evidence / "run.json").read_text(encoding="utf-8"))
        self.assertEqual((run["sweep_exit"], run["mode"], status["alarm"]), (1, "live", "8658 control runs were missed"))
        code, output = self.tree.judge(FIGURE, ROW, evidence, receipt)
        self.assertEqual(code, BROKEN, output)
        key = json.loads(receipt.read_text(encoding="utf-8"))["key"]
        self.assertEqual(key["outcome"], "broken")
        for line in key["figure"]:
            runs, missed, no_effect, limited = MISSED_COUNTS[line["control"]]
            with self.subTest(control=line["control"]):
                self.assertEqual(status["profiles"][line["control"]]["suspect_keys"], {"control met no check: ": missed})
                self.assertEqual((line["runs"], line["caught"], line["missed"], line["no_effect"], line["other"], line["suspects"],
                                  line["unaccounted"], line["eligible"]),
                                 (runs, 0, missed, no_effect, limited, missed, 0, missed + no_effect))
                self.assertIn(f"{line['control']} missed {missed} runs whose plant took effect and met no check under the "
                              f"row's rule \"{RULE}\": {line['control']} (depth {line['depth']}, n 26, k 20000): not found in "
                              f"{runs} runs; rate below 3/{runs} at 95%; runs {runs}, caught 0, no effect {no_effect}, "
                              f"missed {missed}, other {limited}", key["detail"])

    def test_the_receipt_carries_the_scope_and_the_figure_of_each_control(self) -> None:
        # The receipt holds the figure of each control, and scope fields equal to run.json's.
        evidence, receipt = self.tree.case(LIVE), self.tree.receipt("live")
        self.assertEqual(self.tree.judge(FIGURE, ROW, evidence, receipt)[0], HELD)
        key = json.loads(receipt.read_text(encoding="utf-8"))["key"]
        run = json.loads((evidence / "run.json").read_text(encoding="utf-8"))
        scope = key["scope"]
        self.assertEqual((scope["build"], scope["campaign"], scope["counts"], scope["profiles"]),
                         (run["system_build"], run["campaign"], run["counts"], run["profiles"]))
        self.assertEqual(scope["runs"], {name: counts[0] for name, counts in LIVE_COUNTS.items()})
        self.assertEqual(scope["sentence"], (
            f"Per-run rate at which `campaign sweep` of archive build {run['system_build']}, campaign "
            "fixture-ordering-live, counts default, catches each planted ordering control of depth 1 to 3 beside "
            "`cluster-broad`, over 85653, 85389 and 85367 runs each, with a 95% lower bound: one thread, turn "
            "granularity, this profile, these counts and this build, and orders the turn controller can select. "
            "Each rate counts every run the sweep finished, those that ended at a limit among them, the row's floor "
            "of runs counts those that ended caught, missed or with no effect, and each bound holds for its own "
            "control and takes its run count as fixed, while --for sets that count by the wall clock. A caught run "
            "is a run that ended in the row's rule, which the sweep does not tie to the read the plant changed. Each "
            "control measures how often a drawn run reaches a rare interleaving of link deliveries with the upload: "
            "the chooser picks each GET's issue and orders the events ready at one instant, and link draws and the "
            "turn controller's clock rule decide when the others become ready. A read of version 0 that completes "
            "before the upload's session reports it published is an order of the real code that no run of this "
            "controller reaches: in the probes of blotter pull request 2117 the order formed in 0 of 300 `cluster-broad` roots and in 0 "
            "of 60,000 control runs, and the reason offered is that the turn controller holds the clock still while "
            "an event is runnable."))
        self.assertTrue(key["detail"].endswith(scope["sentence"]))
        self.assertTrue(key["detail"].startswith(
            f"each planted ordering control caught under the row's rule \"{RULE}\": cluster-order-1 (depth 1, "), key["detail"])
        self.assertEqual([line["control"] for line in key["figure"]], list(CONTROLS))
        self.assertEqual(key["figure_rounding"], figure.ROUNDING)
        self.assertIsNone(re.search(r"[0-9]{12}", json.dumps(key["figure"])))
        for depth, line in enumerate(key["figure"], 1):
            runs, caught, no_effect, limited = LIVE_COUNTS[line["control"]]
            with self.subTest(control=line["control"]):
                self.assertEqual((line["depth"], line["n"], line["k"]), (depth, 26, 20000))
                self.assertEqual((line["runs"], line["caught"], line["no_effect"], line["missed"], line["other"]),
                                 (runs, caught, no_effect, 0, limited))
                self.assertEqual(line["other_endings"], {LIMIT: limited})
                self.assertEqual((line["rate"], line["confidence"]), (round(caught / runs, 9), 0.95))
                self.assertAlmostEqual(line["lower_bound"], LIVE_BOUNDS[line["control"]], delta=1e-8)
                self.assertLessEqual(line["lower_bound"], LIVE_BOUNDS[line["control"]])
                self.assertEqual(line["eligible"], caught + no_effect)
                self.assertEqual(line["yardstick"], (0.038461538, 1.92307692e-06, 9.61538462e-11)[depth - 1])
                self.assertTrue(line["yardstick_comparison"].startswith("not applicable"))
                self.assertEqual((line["suspects"], line["unaccounted"]), (0, 0))
                self.assertIsNone(line["not_found"])
                printed = re.search(rf"{line['control']} .*?95% lower bound ([0-9.e-]+);", key["detail"])
                assert printed is not None
                self.assertLessEqual(float(printed.group(1)), line["lower_bound"])
                self.assertGreater(float(printed.group(1)), line["lower_bound"] * 0.999)

    def test_each_run_record_names_build_campaign_profiles_counts_and_run_ranges(self) -> None:
        # Each run record holds the inputs that replay the run.
        for run_id in RECORDED:
            with self.subTest(run=run_id):
                run = json.loads((RUNS / run_id / "run.json").read_text(encoding="utf-8"))
                self.assertEqual(run["campaign"], run_id)
                self.assertRegex(run["system_build"], "^[0-9a-f]{64}$")
                self.assertEqual((run["profiles"], run["counts"], run["root_build"]),
                                 (list(CONTROLS), {}, run["system_build"]))
                self.assertTrue(all(run["runs"][name]["first"] == 0 and type(run["runs"][name]["next"]) is int
                                    for name in CONTROLS))


    def test_the_harness_keeps_every_receipt_the_judges_write_breaks_of_a_live_run_among_them(self) -> None:
        # The harness keeps a receipt only when receipt_accepted accepts it, and a broken one only when
        # its detail holds the row's control.expect. Each receipt goes to the harness's own check with the binding
        # judge_all builds for the run.
        ledger = json.loads((self.tree.top / "chaos" / "ledger.json").read_text(encoding="utf-8"))
        rows = {row["id"]: row for section in ("scenarios", "invariants") for row in ledger[section]}
        cases: list[tuple[str, str, int, Any]] = [(run_id, row, code, None) for run_id, judged in RECORDED.items()
                                                  for row, (code, _) in judged.items()]
        cases.append((LIVE, ROW, BROKEN, lambda s: uncaught(s, "cluster-order-2")))
        cases.append((LIVE, ROW, INVALID, lambda s: s.update(campaign="another-campaign")))
        for run_id, name, code, change in cases:
            with self.subTest(run=run_id, row=name, code=code):
                evidence, receipt = self.tree.case(run_id, status=change), self.tree.receipt(name)
                script = FIGURE if name == ROW else VALIDITY
                exit_code, output = self.tree.judge(script, name, evidence, receipt)
                self.assertEqual(exit_code, code, output)
                run = json.loads((evidence / "run.json").read_text(encoding="utf-8"))
                folders = sorted({(self.tree.top / script).parent, self.tree.top / "chaos" / "judges" / "core"})
                judge = {path.relative_to(self.tree.top).as_posix(): harness.sha256(path)
                         for folder in folders for path in sorted(folder.iterdir())}
                control = rows[name].get("control") if name != run["scenario"] else None
                expected = {**{key: run[key] for key in ("scenario", "mode", "defect", "system_build", "harness",
                                                         "run_id", "started")},
                            "evidence": harness.evidence_digests(evidence), "row": name, "command": [script, name],
                            "rows": {name: harness.row_digest(rows[name]),
                                     run["scenario"]: harness.row_digest(rows[run["scenario"]])},
                            "judge": judge, "rule": control.get("expect") if isinstance(control, dict) else None}
                self.assertTrue(harness.receipt_accepted(receipt.read_bytes(), expected, exit_code),
                                receipt.read_text(encoding="utf-8"))

def more_runs(evidence: Path, control: str, runs: int, **fields) -> None:
    """Record `runs` more runs of `control` in the status, its control totals, run.json and history.jsonl, and set
    `fields` in its status entry."""
    def status(s: dict) -> None:
        entry = s["profiles"][control]
        s["controls"]["missed"] += fields.get("missed", entry["missed"]) - entry["missed"]
        entry.update(fields, runs=entry["runs"] + runs, next=entry["next"] + runs)
        s["controls"]["runs"] += runs
    edit_json(evidence / "sweep-status.json", status)
    edit_json(evidence / "run.json", lambda run: run["runs"][control].update(next=run["runs"][control]["next"] + runs))
    edit_history(evidence, control, lambda line: line["runs"].update(next=line["runs"]["next"] + runs))


def endings_of(entry: dict) -> tuple[int, int]:
    """The runs of a status entry that ended with no effect, and those under its other uncredited endings."""
    no_effect = entry["uncredited"].get(figure.NO_EFFECT, 0)
    return no_effect, sum(entry["uncredited"].values()) - no_effect


def recount(evidence: Path, control: str, caught: int, no_effect: int, limited: int = 0) -> None:
    """Record that `control` finished `caught` + `no_effect` + `limited` runs, in the status, its control totals,
    run.json and history.jsonl."""
    runs = caught + no_effect + limited

    def status(s: dict) -> None:
        entry = s["profiles"][control]
        before = endings_of(entry)
        s["controls"]["runs"] += runs - entry["runs"]
        s["controls"]["caught"] += caught - entry["caught"]
        s["controls"]["no_effect"] += no_effect - before[0]
        s["controls"]["other"] += limited - before[1]
        endings = {key: value for key, value in ((figure.NO_EFFECT, no_effect), (LIMIT, limited)) if value}
        entry.update(runs=runs, next=runs, caught=caught, caught_rules={RULE: caught} if caught else {}, uncredited=endings)
    edit_json(evidence / "sweep-status.json", status)
    edit_json(evidence / "run.json", lambda run: run["runs"][control].update(next=runs))
    edit_history(evidence, control, lambda line: line["runs"].update(next=runs))


def missed_in(evidence: Path, control: str, runs: int, key: str = "control met no check: ") -> None:
    """Record `runs` more runs of `control`, each missed, with the alarm and the sweep exit 1 that a miss brings.

    `key` is the suspect key the supervisor counts a run under whose plant took effect while no check failed.
    """
    def status(s: dict) -> None:
        missed = sum(entry["missed"] for entry in s["profiles"].values())
        s.update(alarm=f"{missed} control runs were missed")
        s["profiles"][control]["suspect_keys"][key] = runs
    more_runs(evidence, control, runs, missed=runs, suspects=runs)
    edit_json(evidence / "sweep-status.json", status)
    edit_json(evidence / "run.json", lambda run: run.update(sweep_exit=1))


def uncaught(s: dict, control: str) -> None:
    """Move every caught run of `control` to the no-effect ending."""
    entry = s["profiles"][control]
    entry["uncredited"][figure.NO_EFFECT] += entry["caught"]
    s["controls"]["caught"] -= entry["caught"]
    s["controls"]["no_effect"] += entry["caught"]
    entry.update(caught=0, caught_rules={})


class Built(unittest.TestCase):
    """Each falsifier of the figure's mapping, built from a recorded run, gets the exit its record names."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tree = Tree()

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tree.scratch, ignore_errors=True)

    def exits(self, evidence: Path, figure_code: int, validity_code: int | None = None, text: str = "",
              tree: Tree | None = None) -> None:
        top = tree or self.tree
        cases = [(FIGURE, ROW, figure_code)] + ([(VALIDITY, SHORT, validity_code)] if validity_code is not None else [])
        for script, row, code in cases:
            exit_code, output = top.judge(script, row, evidence)
            self.assertEqual(exit_code, code, f"{script}: {output}")
            if script == FIGURE:
                self.assertIn(text, output)

    def test_a_missed_control_is_broken_and_its_run_invalid(self) -> None:
        # The supervisor counts a missed run under `control met no check` or `control passed`.
        for key in ("control met no check: ", "control passed: "):
            with self.subTest(key=key):
                evidence = self.tree.case(LIVE)
                missed_in(evidence, "cluster-order-2", 3, key)
                self.exits(evidence, BROKEN, INVALID, "cluster-order-2 missed 3 runs whose plant took effect and met no "
                                                      f"check under the row's rule \"{RULE}\"")
        # A run with no ending in the missed control and in a sibling leaves both lines without a rate or bound.
        beside, receipt = self.tree.case(LIVE), self.tree.receipt("beside")
        missed_in(beside, "cluster-order-2", 3)
        more_runs(beside, "cluster-order-2", 1, suspects=4, suspect_keys={"control met no check: ": 3, "wall limit: ": 1})
        more_runs(beside, "cluster-order-3", 1, suspects=1, suspect_keys={"wall limit: ": 1})
        code, output = self.tree.judge(FIGURE, ROW, beside, receipt)
        self.assertEqual(code, BROKEN, output)
        self.assertIn("suspects under no ending 1; no rate, since 1 of its runs have no ending", output)
        lines = json.loads(receipt.read_text(encoding="utf-8"))["key"]["figure"]
        self.assertEqual([(line["missed"], line["suspects"], line["unaccounted"]) for line in lines[1:]], [(3, 4, 1), (0, 1, 1)])
        # A missed run ended, so the floor counts it beside the caught and no-effect runs of fixture-ordering-live.
        self.assertEqual([line["eligible"] for line in lines], [5551 + 76994, 1739 + 3 + 80450, 1098 + 80961])
        for line in lines[1:]:
            self.assertEqual((line["rate"], line["lower_bound"], line["not_found"]), (None, None, None))
        self.assertIsNotNone(lines[0]["rate"])

    def test_a_miss_outranks_a_zero_catch_and_too_few_runs(self) -> None:
        evidence = self.tree.case(LIVE, status=lambda s: uncaught(s, "cluster-order-1"))
        missed_in(evidence, "cluster-order-2", 3)
        self.exits(evidence, BROKEN, INVALID, "cluster-order-2 missed 3 runs")
        self.assertNotIn("no run was caught", self.tree.judge(FIGURE, ROW, evidence)[1])
        tree = Tree(need=10**6)
        try:
            short = tree.case(LIVE)
            missed_in(short, "cluster-order-2", 3)
            self.exits(short, BROKEN, None, "cluster-order-2 missed 3 runs", tree=tree)
        finally:
            shutil.rmtree(tree.scratch, ignore_errors=True)

    def test_a_miss_without_a_suspect_of_a_missed_class_is_invalid(self) -> None:
        evidence = self.tree.case(LIVE)
        missed_in(evidence, "cluster-order-2", 3)
        edit_json(evidence / "sweep-status.json", lambda s: s["profiles"]["cluster-order-2"].update(
            suspect_keys={"violation: 02": 3}))
        self.exits(evidence, INVALID, None, "count no suspect of the classes control passed, control met no check")
        # A missed count requires a suspect key of class `control passed` or `control met no check`.
        other = self.tree.case(LIVE)
        missed_in(other, "cluster-order-2", 3, "wall limit: ")
        self.exits(other, INVALID, None, "count no suspect of the classes control passed, control met no check")

    def test_a_positive_missed_count_alone_is_no_valid_run(self) -> None:
        evidence = self.tree.case(LIVE)
        more_runs(evidence, "cluster-order-2", 3, missed=3)
        code, output = self.tree.judge(VALIDITY, SHORT, evidence)
        self.assertEqual(code, INVALID, output)
        self.assertIn("cluster-order-2 counts 3 missed runs", output)

    def test_an_alarm_or_a_miss_without_its_partner_is_invalid(self) -> None:
        alarm = self.tree.case(LIVE, run=lambda run: run.update(sweep_exit=1), status=lambda s: s.update(alarm="3 control runs were missed"))
        self.exits(alarm, INVALID, INVALID, "no control of the scenario missed a run")
        quiet = self.tree.case(LIVE)
        missed_in(quiet, "cluster-order-2", 3)
        edit_json(quiet / "sweep-status.json", lambda s: s.pop("alarm"))
        self.exits(quiet, INVALID, INVALID, "a miss stands on exit 1 with the alarm alone")
        flagged = self.tree.case(LIVE)
        missed_in(flagged, "cluster-order-2", 3)
        edit_json(flagged / "sweep-status.json", lambda s: s.update(no_pass=["cluster-order-1"]))
        self.exits(flagged, INVALID, INVALID, "a miss stands on exit 1 with the alarm alone")
        unexited = self.tree.case(LIVE)
        missed_in(unexited, "cluster-order-2", 3)
        edit_json(unexited / "run.json", lambda run: run.update(sweep_exit=0))
        self.exits(unexited, INVALID, INVALID, "a miss stands on exit 1 with the alarm alone")
        self.exits(self.tree.case(LIVE, status=lambda s: s.update(no_pass=["x"])), INVALID, INVALID, "no_pass")
        self.exits(self.tree.case(LIVE, run=lambda run: run.update(sweep_exit=1)), INVALID, INVALID, "exited 1")

    def test_a_planned_window_flag_is_invalid_beside_a_clean_exit_and_beside_a_miss(self) -> None:
        window = {"cluster-order-1": ["a planned window"]}
        quiet = self.tree.case(LIVE, status=lambda s: s.update(no_window=window))
        self.exits(quiet, INVALID, INVALID, "with the totals flags ['no_window']")
        beside = self.tree.case(LIVE)
        missed_in(beside, "cluster-order-2", 3)
        edit_json(beside / "sweep-status.json", lambda s: s.update(no_window=window))
        self.exits(beside, INVALID, INVALID, "a miss stands on exit 1 with the alarm alone")

    def test_an_alarm_that_does_not_name_the_statuss_missed_runs_is_invalid(self) -> None:
        for alarm in ("4 control runs were missed", {"control runs": 3}, ["3 control runs were missed"], True):
            with self.subTest(alarm=alarm):
                evidence = self.tree.case(LIVE)
                missed_in(evidence, "cluster-order-2", 3)
                edit_json(evidence / "sweep-status.json", lambda s, a=alarm: s.update(alarm=a))
                self.exits(evidence, INVALID, INVALID, "a miss stands on exit 1 with the alarm alone")

    def test_the_alarm_counts_the_missed_runs_of_every_profile(self) -> None:
        def history(s: dict) -> None:
            s["profiles"]["h1-get-stale"]["missed"] = 2
            s["histories"]["missed"] = 2
        # The supervisor's alarm sums `missed` over every profile, so a history's missed runs raise it too.
        self.exits(self.tree.case(LIVE, status=history), INVALID, INVALID,
                   "call for the alarm '2 control runs were missed', and its totals carry the alarm None")
        both = self.tree.case(LIVE, status=history)
        missed_in(both, "cluster-order-2", 3)
        self.assertEqual(json.loads((both / "sweep-status.json").read_text(encoding="utf-8"))["alarm"],
                         "5 control runs were missed")
        self.exits(both, BROKEN, INVALID, "cluster-order-2 missed 3 runs")
        edit_json(both / "sweep-status.json", lambda s: s.update(alarm="3 control runs were missed"))
        self.exits(both, INVALID, INVALID, "a miss stands on exit 1 with the alarm alone")

        def idle(s: dict) -> None:
            s["profiles"]["cluster-order-4"] = dict(s["profiles"]["cluster-order-3"], runs=0, next=0, caught=0,
                                                    caught_rules={}, uncredited={}, replays=0, missed=5)
            s["controls"].update(profiles=4, missed=5)
        self.exits(self.tree.case(LIVE, status=idle), INVALID, INVALID, "call for the alarm '5 control runs were missed'")

    def test_control_totals_that_differ_from_the_control_entries_are_invalid(self) -> None:
        # The core's record checks compare the missed total and the sum of the no-effect and other totals; a move of
        # one run from one of those two totals to the other reaches the family's own comparison.
        for key in ("missed", "no_effect", "other"):
            with self.subTest(total=key):
                evidence = self.tree.case(LIVE, status=lambda s, k=key: s["controls"].update({k: s["controls"][k] + 1}))
                self.exits(evidence, INVALID, INVALID, "and its entries marked as controls hold 3, 256409, 8388, 0, 248021")
        moved = self.tree.case(LIVE, status=lambda s: s["controls"].update(no_effect=s["controls"]["no_effect"] + 1,
                                                                            other=s["controls"]["other"] - 1))
        self.exits(moved, INVALID, None,
                   "and its entries marked as controls hold 0 missed, 238405 with no effect and 9616 under other endings")

    def test_a_totals_flag_of_any_value_is_invalid(self) -> None:
        for value in (None, "", [], {}, False):
            with self.subTest(value=value):
                quiet = self.tree.case(LIVE, status=lambda s, v=value: s.update(no_pass=v))
                self.exits(quiet, INVALID, INVALID, "with the totals flags ['no_pass']")
                beside = self.tree.case(LIVE)
                missed_in(beside, "cluster-order-2", 3)
                edit_json(beside / "sweep-status.json", lambda s, v=value: s.update(unreached=v))
                self.exits(beside, INVALID, INVALID, "a miss stands on exit 1 with the alarm alone")
                empty = self.tree.case(LIVE)
                missed_in(empty, "cluster-order-2", 3)
                edit_json(empty / "sweep-status.json", lambda s, v=value: s.update(alarm=v))
                self.exits(empty, INVALID, INVALID, "a miss stands on exit 1 with the alarm alone")

    def test_a_campaign_binary_that_hashed_otherwise_after_the_run_is_invalid(self) -> None:
        for name, change in (("another digest", lambda binary: binary.update(sha256_after="0" * 64)),
                             ("no closing digest", lambda binary: binary.pop("sha256_after")),
                             ("no digest", lambda binary: binary.update(sha256="a digest", sha256_after="a digest"))):
            with self.subTest(edit=name):
                evidence = self.tree.case(LIVE, run=lambda run, c=change: c(run["campaign_binary"]))
                self.exits(evidence, INVALID, INVALID, "the campaign binary hashed otherwise")

    def test_zero_caught_at_the_runs_the_row_requires_is_broken_and_one_run_short_incomplete(self) -> None:
        # The floor counts runs that ended caught, missed or with no effect, so a limit ending in place of a no-effect
        # ending takes one run from it. UNMET's other two controls fall short, so the break outranks incomplete.
        def limited(s: dict) -> None:
            endings = s["profiles"]["cluster-order-1"]["uncredited"]
            endings[figure.NO_EFFECT] -= 1
            endings[LIMIT] += 1
            s["controls"].update(no_effect=s["controls"]["no_effect"] - 1, other=s["controls"]["other"] + 1)
        runs, no_effect, _ = UNMET_COUNTS
        cases = ((no_effect, UNMET, None, BROKEN,
                  f"not found in {runs} runs; rate below 3/{runs} at 95%; runs {runs}, caught 0, no effect {no_effect}, missed 0, "
                  f"other {runs - no_effect}; no run was caught under the row's rule \"{RULE}\", and the row requires a catch in "
                  f"{no_effect} runs that ended caught, missed or with no effect"),
                 (no_effect, UNMET, limited, INCOMPLETE,
                  f"cluster-order-1 has {no_effect - 1} runs that ended caught, missed or with no effect, of its {runs} runs"),
                 (no_effect + 1, UNMET, None, INCOMPLETE, f"cluster-order-1 has {no_effect} runs that ended"),
                 (82059, LIVE, None, HELD, "each planted ordering control caught"),
                 (82060, LIVE, None, INCOMPLETE, "cluster-order-3 has 82059 runs that ended caught, missed or with no effect"))
        for need, run_id, change, code, text in cases:
            tree = Tree(need=need)
            try:
                with self.subTest(need=need, run=run_id, limited=change is not None):
                    self.exits(tree.case(run_id, status=change), code, None, text, tree=tree)
            finally:
                shutil.rmtree(tree.scratch, ignore_errors=True)

    def test_zero_caught_in_the_rows_own_thousand_runs_is_broken_and_in_one_fewer_incomplete(self) -> None:
        # Caught, missed and no-effect runs count toward the row's minimum of 1,000 runs.
        at_floor = self.tree.case(UNMET)
        recount(at_floor, "cluster-order-1", 0, 1000, 37)
        self.exits(at_floor, BROKEN, HELD, "cluster-order-1 (depth 1, n 26, k 20000): not found in 1037 runs; rate below "
                                           "3/1037 at 95%; runs 1037, caught 0, no effect 1000, missed 0, other 37; no run "
                                           f"was caught under the row's rule \"{RULE}\", and the row requires a catch in 1000 runs")
        below = self.tree.case(UNMET)
        recount(below, "cluster-order-1", 0, 999, 38)
        self.exits(below, INCOMPLETE, HELD, "cluster-order-1 has 999 runs that ended caught, missed or with no effect, of "
                                            "its 1037 runs, and the row requires 1000")
        caught = self.tree.case(LIVE)
        recount(caught, "cluster-order-1", 1, 999, 37)
        self.exits(caught, HELD, HELD, "cluster-order-1 (depth 1, n 26, k 20000): runs 1037, caught 1, no effect 999")

    def test_a_zero_catch_without_a_replay_or_a_delivered_link_fault_is_no_break(self) -> None:
        for field in ("replays", "faults_delivered"):
            with self.subTest(field=field):
                evidence = self.tree.case(UNMET, status=lambda s, f=field: s["profiles"]["cluster-order-1"].update({f: 0}))
                self.exits(evidence, INVALID, INVALID, "cluster-order-1 was caught in none of its runs, and it has no replay")

                def later(s: dict, f: str = field) -> None:
                    uncaught(s, "cluster-order-1")
                    uncaught(s, "cluster-order-3")
                    s["profiles"]["cluster-order-3"].update({f: 0})
                self.exits(self.tree.case(LIVE, status=later), INVALID, INVALID,
                           "cluster-order-3 was caught in none of its runs, and it has no replay")

    def test_each_scope_field_that_differs_from_run_json_is_invalid(self) -> None:
        edits = {
            "run range of cluster-order-2": (lambda run: run["runs"]["cluster-order-2"].update(next=7), None),
            "root build": (lambda run: run.update(root_build="0" * 64), None),
            "profiles": (None, lambda s: s["profiles"].update({"cluster-broad": s["profiles"]["cluster-order-1"]})),
            "run range of cluster-order-3": (lambda run: run["runs"]["cluster-order-3"].update(last=1), None),
        }
        for name, (run, status) in edits.items():
            with self.subTest(edit=name):
                code, output = self.tree.judge(FIGURE, ROW, self.tree.case(LIVE, run=run, status=status))
                self.assertEqual(code, INVALID, output)
                self.assertIn("scope: ", output)
                self.assertIn(name.split(" of ")[0], output)
        lines = {"run range": lambda line: line["runs"].update(next=1), "build": lambda line: line.update(build="0" * 64),
                 "campaign": lambda line: line.update(campaign="another"),
                 "counts": lambda line: line.update(counts={"turns": 9})}
        for control in CONTROLS:
            for field, change in lines.items():
                with self.subTest(control=control, history=field):
                    evidence = self.tree.case(LIVE)
                    edit_history(evidence, control, change)
                    code, output = self.tree.judge(FIGURE, ROW, evidence)
                    self.assertEqual(code, INVALID, output)
                    self.assertIn(f"scope: the evidence shows history line's {field} of {control} ", output)
            with self.subTest(control=control, edit="a range that starts at run 5"):
                later = self.tree.case(LIVE, run=lambda run, c=control: run["runs"][c].update(first=5))
                edit_history(later, control, lambda line: line["runs"].update(first=5))
                self.exits(later, INVALID, INVALID, f"scope: the evidence shows run range of {control} {{'first': 0, ")
        absent = self.tree.case(LIVE, run=lambda run: run.pop("runs"))
        self.exits(absent, INVALID, INVALID, "run range of cluster-order-1")
        self.exits(self.tree.case(LIVE, run=lambda run: run["runs"].pop("cluster-order-2")), INVALID, INVALID,
                   "run range of cluster-order-2")
        third = self.tree.case(LIVE, run=lambda run: run["runs"]["cluster-order-3"].update(last=1))
        self.exits(third, INVALID, None, "which is no pair of run numbers first and next")

    def test_a_profile_beside_the_controls_that_ran_is_invalid(self) -> None:
        def broad(**fields):
            return lambda s: s["profiles"].update({"cluster-broad": {
                **s["profiles"]["cluster-order-1"], "control": False, "history": False, "suspect_keys": {}, **fields}})
        # A positive range cursor or a positive run count shows that an unswept profile ran.
        idle = {"caught": 0, "caught_rules": {}, "uncredited": {}, "replays": 0, "pass": 0}
        for name, change in (("runs and a cursor", broad()), ("a run and no cursor", broad(runs=1, next=0, **idle)),
                             ("a cursor and no run", broad(runs=0, next=1, **idle)),
                             ("a history marker that is no boolean", broad(history=1))):
            with self.subTest(beside=name):
                self.exits(self.tree.case(LIVE, status=change), INVALID, INVALID, "scope: the status shows the profiles")

    def test_a_history_marker_the_status_totals_do_not_count_is_invalid(self) -> None:
        # `histories.profiles` counts the profiles marked `history: true`, `histories.ran` counts the marked
        # profiles with runs, and `histories.runs` sums the marked profiles' runs.
        def marked(s: dict) -> None:
            s["profiles"]["cluster-broad"] = dict(s["profiles"]["cluster-order-1"], control=False, history=True,
                                                  suspect_keys={})
        self.exits(self.tree.case(LIVE, status=marked), INVALID, INVALID, "scope: the status's histories count")
        for key in ("profiles", "ran", "runs"):
            with self.subTest(total=key):
                evidence = self.tree.case(LIVE, status=lambda s, k=key: s["histories"].update({k: s["histories"][k] + 1}))
                self.exits(evidence, INVALID, INVALID, "scope: the status's histories count")
        # An unswept entry marked as a control is no rotating history, whatever its history marker.
        def both(s: dict) -> None:
            entry = s["profiles"]["cluster-order-1"]
            s["profiles"]["cluster-broad"] = dict(entry, history=True)
            totals, (no_effect, other) = s["controls"], endings_of(entry)
            totals.update(profiles=4, runs=totals["runs"] + entry["runs"], caught=totals["caught"] + entry["caught"],
                          no_effect=totals["no_effect"] + no_effect, other=totals["other"] + other)
        self.exits(self.tree.case(LIVE, status=both), INVALID, INVALID, "scope: the status shows the profiles")
        # A swept control's `history` marker must be the boolean false; the integer 0 compares equal and is refused.
        numbered = self.tree.case(LIVE, status=lambda s: s["profiles"]["cluster-order-2"].update(history=0))
        self.exits(numbered, INVALID, INVALID, "the status marks cluster-order-2's history 0")

    def test_a_range_end_that_is_no_run_number_or_a_build_that_is_no_digest_is_invalid(self) -> None:
        ends = {"first": False, "next": float(LIVE_COUNTS["cluster-order-1"][0])}
        for key, value in ends.items():
            with self.subTest(place="run.json", end=key):
                evidence = self.tree.case(LIVE, run=lambda run, k=key, v=value: run["runs"]["cluster-order-1"].update({k: v}))
                self.exits(evidence, INVALID, INVALID, "is no count")
            with self.subTest(place="history.jsonl", end=key):
                evidence = self.tree.case(LIVE)
                edit_history(evidence, "cluster-order-1", lambda line, k=key, v=value: line["runs"].update({k: v}))
                for script, row in ((FIGURE, ROW), (VALIDITY, SHORT)):
                    code, output = self.tree.judge(script, row, evidence)
                    self.assertEqual(code, INVALID, output)
                    self.assertIn("is no count", output)
        named = self.tree.case(LIVE, run=lambda run: run.update(system_build="a build", root_build="a build",
                                                               archive_build_after="a build"))
        for control in CONTROLS:
            edit_history(named, control, lambda line: line.update(build="a build"))
        for script, row in ((FIGURE, ROW), (VALIDITY, SHORT)):
            code, output = self.tree.judge(script, row, named)
            self.assertEqual(code, INVALID, output)
            self.assertIn("run.json lacks its system_build", output)

    def test_a_run_count_that_is_not_its_run_ranges_length_is_invalid(self) -> None:
        def one_more(s: dict) -> None:
            entry = s["profiles"]["cluster-order-1"]
            entry["runs"] += 1
            entry["uncredited"][figure.NO_EFFECT] += 1
            s["controls"].update(runs=s["controls"]["runs"] + 1, no_effect=s["controls"]["no_effect"] + 1)
        receipt = self.tree.receipt("length")
        evidence = self.tree.case(LIVE, status=one_more)
        code, output = self.tree.judge(FIGURE, ROW, evidence, receipt)
        self.assertEqual(code, INVALID, output)
        self.assertIn("the status counts 85654 runs of cluster-order-1, and its run range holds 85653", output)
        key = json.loads(receipt.read_text(encoding="utf-8"))["key"]
        self.assertEqual(("figure" in key, "scope" in key), (False, False))
        self.assertEqual(self.tree.judge(VALIDITY, SHORT, evidence)[0], INVALID)

        def one_fewer(s: dict) -> None:
            entry = s["profiles"]["cluster-order-1"]
            entry["runs"] -= 1
            entry["uncredited"][figure.NO_EFFECT] -= 1
            s["controls"].update(runs=s["controls"]["runs"] - 1, no_effect=s["controls"]["no_effect"] - 1)
        fewer = self.tree.case(LIVE, status=one_fewer)
        for script, row in ((FIGURE, ROW), (VALIDITY, SHORT)):
            code, output = self.tree.judge(script, row, fewer)
            self.assertEqual(code, INVALID, output)
            self.assertIn("the status counts 85652 runs of cluster-order-1, and its run range holds 85653", output)

    def test_swept_profiles_that_are_not_the_scenarios_controls_are_invalid(self) -> None:
        fourth = self.tree.case(LIVE)

        def record(run: dict) -> None:
            run["profiles"].append("cluster-order-4")
            run["runs"]["cluster-order-4"] = dict(run["runs"]["cluster-order-1"])
            run["listing"]["cluster-order-4"] = dict(run["listing"]["cluster-order-1"])
        edit_json(fourth / "run.json", record)
        edit_json(fourth / "sweep-status.json",
                  lambda s: s["profiles"].update({"cluster-order-4": s["profiles"]["cluster-order-1"]}))
        lines = (fourth / "history.jsonl").read_text(encoding="utf-8").splitlines()
        lines.append(json.dumps(dict(json.loads(lines[0]), profile="cluster-order-4"), sort_keys=True))
        (fourth / "history.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.exits(fourth, INVALID, INVALID, "run.json records the swept profiles")
        for fields, text in (({"history": True}, "the status marks cluster-order-2's history True and the worker's listing "
                                                 "gives it class 'control'"),
                             ({"failing_history": True}, "the status marks cluster-order-2's failing_history True"),
                             ({"control": False}, "the status does not count cluster-order-2 as a control")):
            with self.subTest(edit=fields):
                evidence = self.tree.case(LIVE, status=lambda s, f=fields: s["profiles"]["cluster-order-2"].update(f))
                self.exits(evidence, INVALID, INVALID, text)
        unlisted = self.tree.case(LIVE, run=lambda run: run["listing"]["cluster-order-1"].update({"class": "live"}))
        self.exits(unlisted, INVALID, INVALID, "does not list cluster-order-1 as a control")

    def test_a_status_copy_of_a_failed_sweep_status_is_invalid_and_an_interrupted_sweep_stays_incomplete(self) -> None:
        for value in (1, False, None):
            with self.subTest(status_exit=value):
                evidence = self.tree.case(LIVE, run=lambda run, v=value: run.update(status_exit=v))
                self.exits(evidence, INVALID, INVALID, "campaign sweep-status exited")
        self.exits(self.tree.case(LIVE, run=lambda run: run.update(sweep_exit=3, status_exit=1)), INCOMPLETE, INCOMPLETE)

    def test_records_that_do_not_stand_give_no_break(self) -> None:
        for name, change in (("left a process", {"left_a_process": 2, "archive_verified": True}),
                             ("unverified archive", {"left_a_process": 0, "archive_verified": False})):
            with self.subTest(edit=name):
                self.exits(self.tree.case(UNMET, run=lambda run, c=change: run.update(restored=c)), INVALID, INVALID,
                           "restoration not shown")
        unreadable = self.tree.case(UNMET)
        (unreadable / "suspects.jsonl").write_text("{\n", encoding="utf-8")
        self.exits(unreadable, INVALID, INVALID, "suspects.jsonl is unreadable")
        absent = self.tree.case(UNMET)
        (absent / "findings.json").unlink()
        self.exits(absent, INVALID, INVALID, "no findings.json")

        def replay(s: dict) -> None:
            s["profiles"]["cluster-order-1"].update(suspect_keys={"replay differs: 02": 1}, suspects=1)
        self.exits(self.tree.case(UNMET, status=replay), INVALID, INVALID, "replayed with another ending")

        def history(s: dict) -> None:
            s["profiles"]["r1-get"].update(suspect_keys={"replay differs: 02": 1}, suspects=1)
        self.exits(self.tree.case(UNMET, status=history), INVALID, INVALID, "not shown deterministic: r1-get")

        def listed_line(evidence: Path, cls: str) -> None:
            run = json.loads((evidence / "run.json").read_text(encoding="utf-8"))
            line = {"key": "other", "profile": "h1-get", "run": 3, "seed": 7, "class": cls, "campaign": run["campaign"],
                    "build": run["system_build"], "counts": run["counts"]}
            (evidence / "suspects.jsonl").write_text(json.dumps(line) + "\n", encoding="utf-8")
        listed = self.tree.case(LIVE, status=lambda s: s["profiles"]["h1-get"].update(suspect_keys={"other": 1}, suspects=1))
        listed_line(listed, "replay differs")
        for script, row in ((FIGURE, ROW), (VALIDITY, SHORT)):
            code, output = self.tree.judge(script, row, listed)
            self.assertEqual(code, INVALID, output)
            self.assertIn("replayed with another ending in a fresh process", output)
            self.assertIn("h1-get", output)
        overflow = self.tree.case(LIVE, status=lambda s: s["profiles"]["h1-get"].update(suspect_keys={"other": 2}, suspects=2))
        listed_line(overflow, "wall limit")
        for script, row in ((FIGURE, ROW), (VALIDITY, SHORT)):
            code, output = self.tree.judge(script, row, overflow)
            self.assertEqual(code, INVALID, output)
            self.assertIn("h1-get counts 2 suspects under other and lists 1", output)

    def test_an_absent_control_or_a_catch_count_its_rules_disagree_with_is_invalid(self) -> None:
        def absent(s: dict) -> None:
            del s["profiles"]["cluster-order-3"]
        self.exits(self.tree.case(LIVE, status=absent), INVALID, INVALID, "cluster-order-3")
        rules = {"another rule": ("cluster-order-1", lambda e: {"another rule": e["caught"]}),
                 "fewer under the rule": ("cluster-order-1", lambda e: {RULE: e["caught"] - 1}),
                 "a rule beside it": ("cluster-order-1", lambda e: {RULE: e["caught"], "another rule": 2}),
                 "no rule of a caught control": ("cluster-order-1", lambda e: {}),
                 "rules of an uncaught control": ("cluster-order-1", lambda e: {RULE: 5})}
        for name, (control, value) in rules.items():
            with self.subTest(edit=name):
                run_id = UNMET if name == "rules of an uncaught control" else LIVE
                evidence = self.tree.case(run_id, status=lambda s, c=control, v=value: s["profiles"][c].update(
                    caught_rules=v(s["profiles"][c])))
                text = ("records counts no sweep writes" if name in ("a rule beside it", "rules of an uncaught control")
                        else "every caught run of the figure counts under the row's rule")
                self.exits(evidence, INVALID, None, text)

    def test_counts_that_do_not_account_for_a_controls_runs_are_invalid(self) -> None:
        def ending(value: int):
            def change(s: dict) -> None:
                endings = s["profiles"]["cluster-order-1"]["uncredited"]
                s["controls"]["other"] += value - endings[LIMIT]
                endings[LIMIT] = value
            return change
        for name, change in (("fewer endings than runs", ending(1)), ("more endings than runs", ending(4000)),
                             ("a rule count that is no count", lambda s: s["profiles"]["cluster-order-1"]["caught_rules"]
                              .update({"another rule": None}))):
            with self.subTest(edit=name):
                self.exits(self.tree.case(LIVE, status=change), INVALID, None,
                           "is no count" if "no count" in name else "do not account for its 85653 runs")

    def test_suspects_bound_the_runs_under_no_ending(self) -> None:
        unlisted = self.tree.case(LIVE)
        more_runs(unlisted, "cluster-order-1", 1)
        self.exits(unlisted, INVALID, None, "do not account for its 85654 runs")
        unlisted = self.tree.case(LIVE)
        missed_in(unlisted, "cluster-order-2", 3)
        edit_json(unlisted / "sweep-status.json", lambda s: s["profiles"]["cluster-order-2"].update(suspects=0,
                                                                                                    suspect_keys={}))
        self.exits(unlisted, INVALID, None, "do not account for its 85392 runs")

    def test_a_suspect_of_another_class_than_a_miss_gives_no_figure(self) -> None:
        for control in CONTROLS:
            with self.subTest(control=control):
                held = self.tree.case(LIVE)
                more_runs(held, control, 1, suspects=1, suspect_keys={"wall limit: ": 1})
                self.exits(held, INVALID, INVALID, f"{control} lists 1 suspects and no control of the scenario missed a run")
        tree = Tree(need=UNMET_COUNTS[1])
        try:
            receipt = tree.receipt("suspect")
            zero = tree.case(UNMET)
            more_runs(zero, "cluster-order-1", 1, suspects=1, suspect_keys={"wall limit: ": 1})
            code, output = tree.judge(FIGURE, ROW, zero, receipt)
            self.assertEqual(code, INVALID, output)
            key = json.loads(receipt.read_text(encoding="utf-8"))["key"]
            self.assertEqual(("figure" in key, "scope" in key), (False, False))
        finally:
            shutil.rmtree(tree.scratch, ignore_errors=True)

    def test_a_control_run_breaks_only_on_the_control_its_label_names(self) -> None:
        label = "cluster-order-1-premise-unmet"

        def control(run: dict) -> None:
            run.update(mode="control", defect=label)
        other = self.tree.case(LIVE, run=control, status=lambda s: uncaught(s, "cluster-order-2"))
        self.exits(other, INVALID, None, f"cluster-order-1 was caught in 5551 of its 85653 runs, and the control run '{label}'")
        self.exits(self.tree.case(LIVE, status=lambda s: uncaught(s, "cluster-order-2")), BROKEN, None,
                   "cluster-order-2 (depth 2, n 26, k 20000): not found in 85389 runs")
        two = self.tree.case(LIVE, status=lambda s: [uncaught(s, name) for name in ("cluster-order-1", "cluster-order-3")])
        self.exits(two, BROKEN, None, "cluster-order-1 (depth 1, n 26, k 20000): not found in 85653 runs")
        self.assertIn("cluster-order-3 (depth 3, n 26, k 20000): not found in 85367 runs", self.tree.judge(FIGURE, ROW, two)[1])
        for name in ("cluster-order-10-premise-unmet", "cluster-order-1", "premise-unmet"):
            with self.subTest(label=name):
                self.exits(self.tree.case(UNMET, run=lambda run, n=name: run.update(defect=n)), INVALID, None,
                           "begins with the name of no one control")
        # With two zeros the break names the labeled control alone.
        both = self.tree.case(UNMET, status=lambda s: uncaught(s, "cluster-order-2"))
        self.exits(both, BROKEN, None, "cluster-order-1 (depth 1, n 26, k 20000): not found in 82020 runs")
        self.assertNotIn("cluster-order-2 (depth 2, n 26, k 20000): not found", self.tree.judge(FIGURE, ROW, both)[1])
        tree = Tree(need=78622)
        try:
            named = tree.case(UNMET, run=lambda run: run.update(defect="cluster-order-2-premise-unmet"),
                              status=lambda s: uncaught(s, "cluster-order-2"))
            self.exits(named, INCOMPLETE, None, "cluster-order-2 has 78621 runs that ended", tree=tree)
        finally:
            shutil.rmtree(tree.scratch, ignore_errors=True)

    def test_a_miss_on_a_control_run_whose_label_does_not_stand_is_invalid(self) -> None:
        for name, defect in (("no control", "premise-unmet"), ("a caught control", "cluster-order-2-premise-unmet")):
            with self.subTest(label=name):
                receipt = self.tree.receipt(f"label-{name.replace(' ', '-')}")
                evidence = self.tree.case(UNMET, run=lambda run, d=defect: run.update(defect=d))
                missed_in(evidence, "cluster-order-3", 3)
                code, output = self.tree.judge(FIGURE, ROW, evidence, receipt)
                self.assertEqual(code, INVALID, output)
                key = json.loads(receipt.read_text(encoding="utf-8"))["key"]
                self.assertEqual(("figure" in key, "scope" in key), (False, False))
        named = self.tree.case(UNMET)
        missed_in(named, "cluster-order-3", 3)
        self.exits(named, BROKEN, None, "cluster-order-3 missed 3 runs")

    def test_runs_past_the_bounds_checked_range_or_a_depth_past_three_are_invalid(self) -> None:
        many = self.tree.case(LIVE)
        more = figure.MOST_RUNS + 1 - 85653
        more_runs(many, "cluster-order-1", more)

        def past(s: dict) -> None:
            s["profiles"]["cluster-order-1"]["uncredited"][LIMIT] += more
            s["controls"]["other"] += more
        edit_json(many / "sweep-status.json", past)
        self.exits(many, INVALID, None, "cluster-order-1 has 10000001 runs, and the lower bound's arithmetic is checked up to 10000000")
        most = self.tree.case(LIVE)
        more_runs(most, "cluster-order-1", more - 1)

        def limited(s: dict) -> None:
            s["profiles"]["cluster-order-1"]["uncredited"][LIMIT] += more - 1
            s["controls"]["other"] += more - 1
        edit_json(most / "sweep-status.json", limited)
        self.exits(most, HELD, None, "cluster-order-1 (depth 1, n 26, k 20000): runs 10000000")
        tree = Tree(threshold={"cluster-order-3.depth": 4})
        try:
            self.exits(tree.case(LIVE), INVALID, None, "threshold.cluster-order-3.depth is 4, and the figure covers depth 1 to 3",
                       tree=tree)
        finally:
            shutil.rmtree(tree.scratch, ignore_errors=True)

    def test_a_judge_started_otherwise_or_beside_a_special_entry_refuses_with_exit_2(self) -> None:
        for script, row in ((FIGURE, ROW), (VALIDITY, SHORT)):
            with self.subTest(script=script, start="without -I -B"):
                done = subprocess.run([sys.executable, str(self.tree.top / script), row, "--evidence", "x"],
                                      capture_output=True, check=False, timeout=120)
                self.assertEqual(done.returncode, INVALID, done.stderr)
                self.assertIn(b"start the judge as python3 -I -B", done.stderr)
            tree = Tree()
            try:
                with self.subTest(script=script, start="beside a directory"):
                    (tree.top / "chaos" / "judges" / "ordering" / "na\udcffme").mkdir()
                    for stderr in (subprocess.PIPE, subprocess.DEVNULL):
                        done = subprocess.run([sys.executable, "-I", "-B", str(tree.top / script), row, "--evidence", "x"],
                                              stdout=subprocess.PIPE, stderr=stderr, check=False, timeout=120)
                        self.assertEqual(done.returncode, INVALID, done.stderr)
                        if stderr == subprocess.PIPE:
                            self.assertIn(b"beside the judge is no regular file", done.stderr)
            finally:
                shutil.rmtree(tree.scratch, ignore_errors=True)

    def test_a_shared_module_without_a_name_the_judge_binds_is_no_verdict(self) -> None:
        tree = Tree()
        try:
            with (tree.top / "chaos" / "judges" / "core" / "common.py").open("a", encoding="utf-8") as file:
                file.write("\ndel receipt_for\n")
            code, output = tree.judge(FIGURE, ROW, tree.case(UNMET))
            self.assertEqual(code, INVALID, output)
            self.assertIn("cannot load the judge", output)
        finally:
            shutil.rmtree(tree.scratch, ignore_errors=True)

    def test_a_records_py_that_changed_on_disk_after_the_judge_loaded_it_is_no_verdict(self) -> None:
        tree = Tree()
        try:
            with (tree.top / "chaos" / "judges" / "ordering" / "records.py").open("a", encoding="utf-8") as file:
                file.write("\nwith open(__file__, 'a', encoding='utf-8') as _file:\n    _file.write('# a later line\\n')\n")
            for script, row in ((FIGURE, ROW), (VALIDITY, SHORT)):
                with self.subTest(script=script):
                    code, output = tree.judge(script, row, tree.case(LIVE))
                    self.assertEqual(code, INVALID, output)
                    self.assertIn("records.py was not loaded from the bytes its digest names", output)
        finally:
            shutil.rmtree(tree.scratch, ignore_errors=True)

    def test_a_row_without_its_rule_text_is_invalid(self) -> None:
        for name, change in (("absent", lambda row: row["control"].pop("expect")),
                             ("empty", lambda row: row["control"].update(expect="")),
                             ("no text", lambda row: row["control"].update(expect=7))):
            tree = Tree(row=change)
            try:
                for run_id in (LIVE, UNMET, MISSED_RUN):
                    with self.subTest(rule=name, run=run_id):
                        self.exits(tree.case(run_id), INVALID, None,
                                   "the row needs the rule text a caught run counts under as control.expect", tree=tree)
            finally:
                shutil.rmtree(tree.scratch, ignore_errors=True)

    def test_a_held_detail_is_the_judges_own_phrase_and_not_the_rows_witness_text(self) -> None:
        tree = Tree(row=lambda row: row["witness"].update(expect="a distinctive expectation"))
        try:
            code, output = tree.judge(FIGURE, ROW, tree.case(LIVE))
            self.assertEqual(code, HELD, output)
            self.assertIn(f"{ROW}: held: {figure.WITNESSED} under the row's rule \"{RULE}\": cluster-order-1 ", output)
            self.assertNotIn("a distinctive expectation", output)
        finally:
            shutil.rmtree(tree.scratch, ignore_errors=True)

    def test_an_invalid_receipt_carries_no_figure_and_a_measured_one_does(self) -> None:
        receipt = self.tree.receipt("invalid")
        evidence = self.tree.case(LIVE, status=lambda s: s.update(no_pass=["x"]))
        self.assertEqual(self.tree.judge(FIGURE, ROW, evidence, receipt)[0], INVALID)
        key = json.loads(receipt.read_text(encoding="utf-8"))["key"]
        self.assertEqual((key["outcome"], "figure" in key, "scope" in key), ("invalid", False, False))
        # A judge writes a new receipt file only, so the second judgement names another path.
        receipt = self.tree.receipt("incomplete")
        self.assertEqual(self.tree.judge(FIGURE, ROW, self.tree.case(FEW_RUN), receipt)[0], INCOMPLETE)
        key = json.loads(receipt.read_text(encoding="utf-8"))["key"]
        self.assertEqual((key["outcome"], len(key["figure"]), key["figure"][2]["rate"], key["figure"][2]["not_found"]),
                         ("incomplete", 3, None, None))
        measured = types.SimpleNamespace(run={}, read_digests=dict, figure={"scope": {"build": "b"}, "figure": [{}]})
        for code in (HELD, BROKEN, INVALID, INCOMPLETE):
            with self.subTest(code=code):
                key = figure.receipt_for(ROW, FIGURE, {}, None, None, measured, code, "a detail")["key"]
                self.assertEqual(("figure" in key, "scope" in key), (code != INVALID, code != INVALID))

    def test_a_confidence_outside_one_half_to_the_most_the_bound_is_checked_for_is_invalid(self) -> None:
        self.assertEqual(figure.MOST_CONFIDENCE, 0.9999999)
        refused = "which is no share from 0.5 to 0.9999999"
        cases = ((0.4, LIVE, INVALID, refused), (0.4999999, LIVE, INVALID, refused),
                 (1.0, LIVE, INVALID, refused), (1, LIVE, INVALID, refused),
                 (0.99999991, LIVE, INVALID, refused), (0.9999999999999999, UNMET, INVALID, refused),
                 (0.5, LIVE, HELD, ", 50% lower bound"),
                 (0.5, LIVE, HELD, "runs each, with a 50% lower bound: one thread"),
                 (0.9999999, LIVE, HELD, ", 99.99999% lower bound"),
                 (0.9999999, UNMET, BROKEN, "/82020 at 99.99999%"),
                 (0.5, UNMET, BROKEN, "not found in 82020 runs; rate below 0.7/82020 at 50%"))
        for value, run_id, code, text in cases:
            tree = Tree(confidence=value)
            try:
                with self.subTest(confidence=value, run=run_id):
                    exit_code, output = tree.judge(FIGURE, ROW, tree.case(run_id))
                    self.assertEqual(exit_code, code, output)
                    self.assertIn(text, output)
                    self.assertNotIn("100%", output)
            finally:
                shutil.rmtree(tree.scratch, ignore_errors=True)

    def test_an_incomplete_run_record_or_a_recorded_exit_3_or_4_is_incomplete(self) -> None:
        absent = self.tree.case(LIVE)
        (absent / "run.json").unlink()
        self.exits(absent, INCOMPLETE, INCOMPLETE, "no run.json")
        self.exits(self.tree.case(LIVE, run=lambda run: run.update(complete=False)), INCOMPLETE, INCOMPLETE)
        for code in (3, 4):
            self.exits(self.tree.case(LIVE, run=lambda run, code=code: run.update(sweep_exit=code)), INCOMPLETE, INCOMPLETE)

    def test_an_unreadable_status_is_invalid(self) -> None:
        evidence = self.tree.case(LIVE)
        (evidence / "sweep-status.json").write_text("{", encoding="utf-8")
        self.exits(evidence, INVALID, INVALID, "unreadable")

    def test_a_control_without_runs_a_replay_a_link_fault_or_with_a_suspect_is_no_valid_run(self) -> None:
        edits = {"no replay": {"replays": 0}, "delivered no link fault": {"faults_delivered": 0},
                 "lists 1 suspects: ['wall limit: ']": {"suspects": 1, "suspect_keys": {"wall limit: ": 1}},
                 "lists 1 suspects: ['violation: 02']": {"suspects": 1, "suspect_keys": {"violation: 02": 1}}}
        for text, fields in edits.items():
            with self.subTest(edit=text):
                evidence = self.tree.case(LIVE, status=lambda s, f=fields: s["profiles"]["cluster-order-2"].update(f))
                code, output = self.tree.judge(VALIDITY, SHORT, evidence)
                self.assertEqual(code, INVALID, output)
                self.assertIn(text, output)
        code, output = self.tree.judge(VALIDITY, FEW, self.tree.case(FEW_RUN, status=lambda s: [
            s["profiles"][name].update(replays=1, faults_delivered=1) for name in CONTROLS]))
        self.assertEqual(code, INVALID, output)
        self.assertIn("minimum unmet: cluster-order-3 has 0 runs, and the row requires 1", output)
        least = self.tree.case(LIVE)
        recount(least, "cluster-order-3", 1, 0)
        code, output = self.tree.judge(VALIDITY, SHORT, least)
        self.assertEqual(code, HELD, output)
        self.assertIn("cluster-order-3 1 runs of 1 required", output)


def decoded_values(text: str) -> list[str]:
    """Each key, string and integer of the JSON document text as text; a Boolean, a float and null are skipped."""
    pending: list[Any] = [json.loads(text, object_pairs_hook=lambda pairs: [part for pair in pairs for part in pair])]
    found = []
    while pending:
        value = pending.pop()
        if isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, str):
            found.append(value)
        elif isinstance(value, int) and not isinstance(value, bool):
            found.append(str(value))
    return found


class Figure(unittest.TestCase):
    """The lower bound's arithmetic and the row's numbers against their sources."""

    def test_the_lower_bound_meets_its_closed_forms_and_its_tail(self) -> None:
        alpha = 0.05
        self.assertEqual(figure.lower_bound(0, 1000, 0.95), 0.0)
        for runs in (1, 10, 1000, 156663):
            self.assertAlmostEqual(figure.lower_bound(1, runs, 0.95), 1 - (1 - alpha) ** (1 / runs), delta=1e-12)
            self.assertAlmostEqual(figure.lower_bound(runs, runs, 0.95), alpha ** (1 / runs), delta=1e-12)
        for caught, runs in ((2, 7), (1885, 85958), (10381, 156663)):
            with self.subTest(caught=caught, runs=runs):
                self.assertAlmostEqual(figure.tail(caught, runs, figure.lower_bound(caught, runs, 0.95)), alpha, delta=1e-9)
        # With many catches the bound lies near the normal approximation's.
        rate = 10381 / 156663
        normal = rate - 1.6449 * math.sqrt(rate * (1 - rate) / 156663)
        self.assertAlmostEqual(figure.lower_bound(10381, 156663, 0.95), normal, delta=5e-5)

    def test_the_lower_bound_holds_at_the_most_runs_the_judge_measures(self) -> None:
        most = figure.MOST_RUNS
        self.assertEqual(most, 10_000_000)
        one = figure.lower_bound(1, most, 0.95)
        self.assertAlmostEqual(one / -math.expm1(math.log(0.95) / most), 1, delta=1e-7)
        for caught, bound in MOST_BOUNDS.items():
            with self.subTest(caught=caught):
                self.assertAlmostEqual(figure.lower_bound(caught, most, 0.95) / bound, 1, delta=1e-7)
        self.assertAlmostEqual(figure.lower_bound(most, most, 0.95), 0.05 ** (1 / most), delta=1e-12)

    def test_the_written_bound_lies_at_or_below_the_exact_bound(self) -> None:
        contract = json.loads((CHAOS / "ledger.json").read_text(encoding="utf-8"))
        row = next(row for row in contract["invariants"] if row["id"] == ROW)
        for runs in (figure.MOST_RUNS - 1, 2_600_000, 85653):
            for caught in (1, 2, 3, 5):
                for confidence in ("0.95",) if runs > 85653 else ("0.95", "0.5", "0.999", repr(figure.MOST_CONFIDENCE)):
                    with self.subTest(runs=runs, caught=caught, confidence=confidence):
                        entry = {"runs": runs, "caught": caught, "missed": 0, "suspects": 0, "caught_rules": {RULE: caught},
                                 "uncredited": {figure.NO_EFFECT: runs - caught}}
                        written = figure.measured(row, CONTROLS[0], entry, RULE, float(confidence))["lower_bound"]
                        exact = exact_bound(caught, runs, confidence)
                        self.assertLessEqual(Decimal(repr(written)), exact)
                        self.assertGreater(Decimal(repr(written)), exact * Decimal("0.9999997"))

    def test_records_py_is_held_to_the_bytes_the_judge_executed(self) -> None:
        name = "chaos/judges/ordering/records.py"
        loaded = figure.records.LOADED_SHA256
        self.assertEqual(figure.records.bound_sources(lambda judge: {name: loaded})(None), {name: loaded})
        with self.assertRaisesRegex(ValueError, "records.py was not loaded from the bytes its digest names"):
            figure.records.bound_sources(lambda judge: {name: "0" * 64})(None)

    def test_the_line_control_how_names_stands_in_the_plant(self) -> None:
        source = (ROOT / "crates/kestrike/src/net/world_tests/cluster/order.rs").read_text(encoding="utf-8")
        contract = json.loads((CHAOS / "ledger.json").read_text(encoding="utf-8"))
        how = next(row for row in contract["invariants"] if row["id"] == ROW)["control"]["how"]
        self.assertIn("`Plant::Depth1 => true,`", how)
        self.assertEqual(source.count("Plant::Depth1 => true,"), 1)

    def test_a_printed_bound_lies_at_or_below_the_bound_and_a_percentage_below_one_hundred(self) -> None:
        cases = ((0.0656068, "0.06560"), (0.0206599, "0.02065"), (0.05 ** (1 / 7), "0.6518"), (1.2349e-9, "1.234e-9"), (0.0, "0"))
        for bound, text in cases:
            with self.subTest(bound=bound):
                self.assertEqual(figure.floored(bound), text)
                self.assertLessEqual(float(text), bound)
        self.assertEqual([figure.percent(value) for value in (0.5, 0.95, 0.9999999, 0.9999999999999999)],
                         ["50%", "95%", "99.99999%", "99.9999999%"])

    def test_no_number_of_a_figure_line_is_written_with_twelve_digits_in_a_row(self) -> None:
        contract = json.loads((CHAOS / "ledger.json").read_text(encoding="utf-8"))
        row = next(row for row in contract["invariants"] if row["id"] == ROW)
        cases = ((1, 4096, 0.000244141), (1, 3, 0.333333333), (1, 8192, 0.000122070), (1, 16384, 6.10351562e-05))
        for caught, runs, rate in cases:
            entry = {"runs": runs, "caught": caught, "missed": 0, "suspects": 0, "caught_rules": {RULE: caught},
                     "uncredited": {figure.NO_EFFECT: runs - caught}}
            for control in CONTROLS:
                with self.subTest(caught=caught, runs=runs, control=control):
                    line = figure.measured(row, control, entry, RULE, 0.9999999999999999)
                    self.assertIsNone(re.search(r"[0-9]{12}", json.dumps(line)), json.dumps(line))
                    self.assertEqual((line["rate"], line["confidence"]), (rate, 0.999999999))
                    self.assertGreater(line["yardstick"], 0)
        self.assertEqual([figure.written(1 / (26 * 20000 ** depth)) for depth in (0, 1, 2)],
                         [0.038461538, 1.92307692e-06, 9.61538462e-11])
        self.assertEqual((figure.written(0.0656068999999, down=True), figure.written(0.0)), (0.065606899, 0.0))
        for value in (0.000244140625, 0.000123456789, 0.99999999999, 1.2345678912345e-7):
            with self.subTest(value=value):
                self.assertIsNone(re.search(r"[0-9]{12}", json.dumps([figure.written(value), figure.written(value, down=True)])))
                self.assertLessEqual(figure.written(value, down=True), value)

    def test_no_string_of_a_receipt_holds_what_the_hook_reads_as_an_account_number(self) -> None:
        # What the pre-push hook refuses in a chaos record as a possible AWS account number: 12 ASCII digits
        # with no ASCII letter or digit beside them, or three groups of 4 joined by `-` with no ASCII
        # letter, digit or `-` beside them, matched in each key, string and integer the record decodes to.
        account_number = re.compile(r"(?<![0-9A-Za-z])[0-9]{12}(?![0-9A-Za-z])"
                                    r"|(?<![0-9A-Za-z-])[0-9]{4}-[0-9]{4}-[0-9]{4}(?![0-9A-Za-z-])")
        self.assertTrue(account_number.search("a 123456789012 b"))
        self.assertTrue(account_number.search("account 1234-5678-9012"))
        for run_id in (LIVE, UNMET):
            tree = Tree(confidence=0.95123456789012)
            try:
                with self.subTest(run=run_id):
                    receipt = tree.receipt("digits")
                    code, output = tree.judge(FIGURE, ROW, tree.case(run_id), receipt)
                    self.assertIn(code, (HELD, BROKEN), output)
                    key = json.loads(receipt.read_text(encoding="utf-8"))["key"]
                    text = json.dumps({name: key[name] for name in ("detail", "scope", "figure", "figure_rounding")})
                    values = decoded_values(text)
                    self.assertEqual([value for value in values if account_number.search(value)], [])
                    self.assertIn("95.1234567%", output)
            finally:
                shutil.rmtree(tree.scratch, ignore_errors=True)

    def test_the_scope_states_the_runs_counts_and_the_rows_confidence(self) -> None:
        build, counts = "ab" * 32, {"turns": 9000, "actors": 7}
        runs = {name: 5 + index for index, name in enumerate(CONTROLS)}
        run = {"system_build": build, "root_build": build, "campaign": "a-campaign", "counts": counts,
               "profiles": list(CONTROLS), "runs": {name: {"first": 0, "next": runs[name]} for name in CONTROLS}}
        history = {name: {"runs": dict(run["runs"][name]), "build": build, "campaign": "a-campaign", "counts": counts}
                   for name in CONTROLS}
        status = {"profiles": {name: {"runs": runs[name], "next": runs[name]} for name in CONTROLS}}
        found = figure.scope(types.SimpleNamespace(run=run, history=lambda: history), status, list(CONTROLS), 0.9)
        self.assertEqual((found["build"], found["campaign"], found["counts"], found["profiles"], found["runs"]),
                         (build, "a-campaign", counts, list(CONTROLS), runs))
        self.assertTrue(found["sentence"].startswith(
            f"Per-run rate at which `campaign sweep` of archive build {build}, campaign a-campaign, counts actors=7, "
            "turns=9000, catches each planted ordering control of depth 1 to 3 beside `cluster-broad`, over 5, 6 and 7 "
            "runs each, with a 90% lower bound: one thread,"), found["sentence"])

    def test_the_rows_numbers_are_the_tickets_and_the_project_lists_each_as_ruled(self) -> None:
        contract = json.loads((CHAOS / "ledger.json").read_text(encoding="utf-8"))
        row = next(row for row in contract["invariants"] if row["id"] == ROW)
        scenario = next(row for row in contract["scenarios"] if row["id"] == "ks-ordering-figure")
        self.assertEqual(scenario["load"], dict(scenario["load"], multiple=1, workers=28, batch_s=30, for_s=600))
        self.assertEqual(sorted(scenario["load"]), ["batch_s", "for_s", "multiple", "reference", "workers"])
        self.assertEqual((scenario["deadline_s"], scenario["runs_required"], scenario["load_delivery"], scenario["invariants"]),
                         (3600, 2, {"min_runs_per_profile": 1}, [ROW]))
        self.assertEqual((row["kind"], row["threshold"]["min_runs_per_control"], row["threshold"]["confidence"]),
                         ("threshold", 1000, 0.95))
        self.assertEqual((row["control"]["expect"], row["control"]["scenario"]), (RULE, "ks-ordering-figure"))
        self.assertEqual((row["witness"]["expect"], figure.WITNESSED),
                         ("each planted ordering control caught", "each planted ordering control caught"))
        # Each source file the row's property cites holds the rule text a caught run counts under.
        ref = row["property"]["source"]["ref"]
        cited = re.findall(r"crates/[A-Za-z0-9_/.-]+\.rs", ref)
        self.assertIn("#297", ref)
        self.assertEqual(len(cited), 2, ref)
        for path in cited:
            with self.subTest(cited=path):
                self.assertIn(f'"{RULE}"', (ROOT / path).read_text(encoding="utf-8"))
        project = (CHAOS / "project.yaml").read_text(encoding="utf-8")
        for text in ("at least 1,000 runs of each planted ordering control", "the one-sided confidence of 95%",
                     "at most 10,000,000 runs of one planted ordering control",
                     f"at most a confidence of {figure.MOST_CONFIDENCE} of that lower bound", "the greatest planted depth of 3",
                     "the run deadline of 3600 s", "runs_required of 2"):
            with self.subTest(ruled=text):
                ruled = "ruled as it reads by the workstream's lead on the owner's delegation of 25 November 2026"
                self.assertRegex(project, rf"(?m)^\s*- {re.escape(ruled)}: {re.escape(text)}")

    def test_the_suspect_classes_endings_and_flags_the_judges_read_are_the_supervisors(self) -> None:
        supervisor = ROOT / "crates/campaign-supervisor/src/campaign"
        seeds = (supervisor / "seeds.rs").read_text(encoding="utf-8")
        controls = (supervisor / "calibration/controls.rs").read_text(encoding="utf-8")
        missed = re.search(r"const MISSED: \[&str; [0-9]+\] = \[([^\]]*)\];", seeds)
        flags = re.search(r"fn carries_verdict\(status: &Value\) -> bool \{\s*\[([^\]]*)\]", seeds)
        no_effect = re.search(r'const NO_EFFECT: &str = "([^"]*)";', controls)
        assert missed is not None and flags is not None and no_effect is not None
        self.assertEqual(sorted(re.findall(r'"([^"]*)"', missed.group(1))), sorted(figure.records.MISSED))
        self.assertEqual(sorted(re.findall(r'"([^"]*)"', flags.group(1))), sorted(figure.records.FLAGS))
        self.assertIn('format!("unsuccessful: {rule}")', seeds)
        self.assertEqual(figure.NO_EFFECT, f"unsuccessful: {no_effect.group(1)}")

    def test_the_rows_depth_n_and_k_equal_the_control_table(self) -> None:
        source = (ROOT / "crates/campaign-supervisor/src/campaign/calibration/controls.rs").read_text(encoding="utf-8")
        self.assertIn(f'const FOREIGN: &str = "{RULE}";', source)
        depths = dict(re.findall(r'ordering\("(cluster-order-\d)", (\d)\)', source))
        body = source[source.index("const fn ordering("):]
        n, k = (int(found[0].replace("_", "")) for found in
                (re.findall(rf"\b{key}: ([0-9_]+),", body) for key in ("n", "k")))
        contract = json.loads((CHAOS / "ledger.json").read_text(encoding="utf-8"))
        row = next(row for row in contract["invariants"] if row["id"] == ROW)
        self.assertEqual(sorted(depths), list(CONTROLS))
        for name, depth in depths.items():
            self.assertEqual([row["threshold"][f"{name}.{key}"] for key in ("depth", "n", "k")], [int(depth), n, k])
        scenario = next(row for row in contract["scenarios"] if row["id"] == "ks-ordering-figure")
        self.assertEqual(scenario["load"]["reference"].split(";")[0], ",".join(CONTROLS))
        tests = json.loads((TESTS / "ledger.json").read_text(encoding="utf-8"))
        self.assertEqual(next(row for row in tests["invariants"] if row["id"] == ROW), row)


if __name__ == "__main__":
    unittest.main()
