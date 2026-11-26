#!/usr/bin/env python3
"""Check that judge-tlc.py credits a profile only when every case reached its declared outcome under the pinned tools.

Each judge test brings one evidence directory to the state the lane writes
it in, with the runner's results and logs for every case of the PR profile,
runs the judge's command, then breaks one property and checks the refusal
names it. The reader tests give the runner's log readers text at the line
and digit boundaries where each decides.
"""

import contextlib
import copy
import dataclasses
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/judge-tlc.py"
spec = importlib.util.spec_from_file_location("judge_tlc", SCRIPT)
assert spec is not None and spec.loader is not None
judge_tlc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(judge_tlc)
EXPECTED = judge_tlc.read_json(judge_tlc.EXPECTED)
CHECK = judge_tlc.runner()
CASES = {case.name: case for case in CHECK.cases() if case.tier == "pr"}
SCHEDULED = {case.name: case for case in CHECK.cases() if case.tier == "scheduled"}
JAR = "/opt/tlc/tla2tools.jar"
MODELS = {path.name: path.read_bytes() for path in sorted((ROOT / "tla").glob("*.tla"))}
RETAINED = {}
INPUTS = {}
STEPS = {}
REPORT_OPEN = ("The coverage statistics at 2026-11-20 08:18:21 (see https://explain.tlapl.us/module-coverage-statistics"
               " for how to interpret the following statistics).\n")
REPORT_END = "End of statistics.\n"
# The fixture's one unreached span: `put` lists a span of line 2 under `CBegin` with 0, and no other Lifecycle case
# lists it. Line 2 of `tla/Lifecycle.tla` opens a comment, `(* One remote PUT`, so its first three columns are `(* `.
HEALTHY = {"tla/Recovery.tla": [], "tla/Identity.tla": [],
           "tla/Lifecycle.tla": [{"section": "CBegin", "at": "2:1-2:3", "text": "(*"}]}
# The registry's count for each case that completes; the fixture's log for that case reports it.
PINNED = {name: entry.get("distinct") for name, entry in EXPECTED["cases"].items()}
PUT = PINNED["put"]
CHECK_FIRST = next(CHECK.cases()).name
# TLC introduces the trace of a temporal-property violation with `COUNTEREXAMPLE` and the trace of an invariant,
# action-property or deadlock violation with `TRACE`.
TRACE = "Error: The behavior up to this point is:"
COUNTEREXAMPLE = "Error: The following behavior constitutes a counter-example:"
# Each line opens a report TLC prints when the run itself fails.
FAILURES = ("Error: TLC threw an unexpected exception.",
            "Error: Java ran out of memory.  Running Java with a larger memory allocation",
            "Error: This was a Java StackOverflowError. It was probably the result",
            "Error: Evaluating invariant TypeOK failed.")


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def retained_inputs(case):
    """A fresh mapping, by file name, of the bytes the runner leaves in `case`'s directory: each committed model,
    with the case's one mutation applied to its target, and the configuration the runner generates. The committed
    files stay fixed for the run, so each case's bytes are built once."""
    if case.name not in RETAINED:
        models = dict(MODELS)
        if case.mutation:
            models[case.target] = (ROOT / "tla" / case.target).read_text().replace(*case.mutation).encode()
        RETAINED[case.name] = {**models, "model.cfg": CHECK.configuration(case, ROOT / "tla").encode()}
    return dict(RETAINED[case.name])


def first_mutated_action(case):
    """The first action of the committed kill case `case`'s mutated-action set, which its fixture log steps through.
    The committed files stay fixed for the run, so each case's action is derived once."""
    if case.name not in STEPS:
        STEPS[case.name] = CHECK.kill_basis(case, ROOT / "tla")["actions"][0]
    return STEPS[case.name]


def recorded_inputs(case):
    """A fresh copy of the input digests the runner records for `case`: the sha256 of each retained input."""
    if case.name not in INPUTS:
        INPUTS[case.name] = {name: hashlib.sha256(data).hexdigest() for name, data in retained_inputs(case).items()}
    return dict(INPUTS[case.name])


class JudgeTlc(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """One evidence directory serves every test of the class. `written` maps each log and retained input the
        directory holds to its bytes, and `write` brings the directory to the running test's files before each
        judgment."""
        directory = tempfile.TemporaryDirectory(prefix="kestrike-tlc-")
        cls.addClassCleanup(directory.cleanup)
        cls.evidence = Path(directory.name) / "evidence"
        cls.evidence.mkdir()
        cls.written = {}

    def setUp(self):
        self.identity = {
            "java": {"path": "/opt/jdk/bin/java", "version": f'openjdk version "{EXPECTED["java"]["version"]}" 2026-08-18 LTS',
                     "install": {"sha256": EXPECTED["java"]["install"], "files": 249}},
            "jar": {"path": JAR, "sha256": EXPECTED["jar"]["sha256"], "version": EXPECTED["jar"]["version"]},
            "models": judge_tlc.model_digests(),
        }
        self.argv = ["/usr/bin/python3", "tla/check.py", "--jar", JAR, "--workers", str(EXPECTED["workers"]),
                     "--tier", "pr", "--output", str(self.evidence / "tlc")]
        self.logs = {}
        self.inputs = {}
        self.results = {name: self.result(case) for name, case in CASES.items()}
        self.profile = "pr"
        self.exit = 0
        self.jar_sha = EXPECTED["jar"]["sha256"]
        self.runtime = f'openjdk version "{EXPECTED["java"]["version"]}" 2026-08-18 LTS\n'

    def result(self, case):
        command = ["java", "tlc2.TLC", "-coverage", "1", *(["-lncheck", "final"] if case.liveness else []),
                   "-config", "model.cfg", f"{case.module}.tla"]
        sany = f"Parsing file /evidence/{case.module}.tla\nSemantic processing of module {case.module}\n"
        states = ["10", "7"]
        if CHECK.completes(case):
            module = case.target.removesuffix(".tla")
            body = REPORT_OPEN + "".join(
                f"<{action} line 1, col 1 to line 1, col 2 of module {module}>: 3:5\n"
                f"  line 1, col 1 to line 1, col 4 of module {module}: 2\n"
                + ("  line 2, col 1 to line 2, col 3 of module Lifecycle: 0\n" if (case.name, action) == ("put", "CBegin") else "")
                for action in case.coverage or ("Tick",)) + REPORT_END
            states = [str(PINNED[case.name] + 3), str(PINNED[case.name])]
        else:
            heading = COUNTEREXAMPLE if case.expected.startswith("Error: Temporal property") else TRACE
            body = f"{heading}\nState 1: <Initial predicate>\n"
            if CHECK.killing(case):
                action = first_mutated_action(case)
                body += f'State 2: <{action}(1,"x") line 1, col 1 to line 1, col 2 of module M>\n'
        tlc = f"{case.expected}\n{body}{states[0]} states generated, {states[1]} distinct states found, 0 states left on queue.\n"
        self.logs[case.name] = {"sany.log": sany, "tlc.log": tlc}
        self.inputs[case.name] = retained_inputs(case)
        return {"case": case.name, "tier": case.tier, "expected": case.expected,
                "returncode": CHECK.exit_status(case.expected),
                "coverage": list(case.coverage), "liveness": case.liveness, "seconds": 1.0, "command": command,
                "states": states, "inputs": recorded_inputs(case),
                "logs": {"sany.log": digest(sany), "tlc.log": digest(tlc)}}

    def write(self):
        """Leaves the evidence directory as the lane writes it for this test: each log and retained input the test
        declares, with its bytes, no other file in a case's directory, and no report or receipt of an earlier
        judgment. A file that already holds its declared bytes stays as it is."""
        declared = {(name, log): text.encode() for name, logs in self.logs.items() for log, text in logs.items()}
        declared.update(((name, file), data) for name, files in self.inputs.items() for file, data in files.items())
        for name, log in self.written.keys() - declared.keys():
            (self.evidence / "tlc" / name / log).unlink()
            del self.written[name, log]
        for (name, log), text in declared.items():
            if self.written.get((name, log)) != text:
                directory = self.evidence / "tlc" / name
                directory.mkdir(parents=True, exist_ok=True)
                (directory / log).write_bytes(text)
                self.written[name, log] = text
        for name in ("report.json", "receipt.json"):
            (self.evidence / name).unlink(missing_ok=True)
        (self.evidence / "identity.json").write_text(json.dumps(self.identity))
        (self.evidence / "pins.txt").write_text("- tla2tools.jar\n")
        (self.evidence / "tlc.argv").unlink(missing_ok=True)
        if self.argv is not None:
            (self.evidence / "tlc.argv").write_text("\n".join(self.argv) + "\n")
        (self.evidence / "tlc.exit").write_text(f"{self.exit}\n")
        (self.evidence / "tlc.txt").write_text("All expected outcomes verified.\n")
        (self.evidence / "results.json").write_text(json.dumps({
            "jar_sha256": self.jar_sha, "runtime": self.runtime, "results": list(self.results.values())}))

    def command(self):
        return ["judge", "--profile", self.profile, "--evidence", str(self.evidence), "--revision", "0" * 40]

    def judge(self, write=True):
        """Writes the evidence unless `write` is false, runs the judge's command in this process and returns the report
        and receipt it wrote."""
        if write:
            self.write()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = judge_tlc.main(self.command())
        report = self.document((self.evidence / "report.json").read_text(), "report.json")
        receipt = self.document((self.evidence / "receipt.json").read_text(), "receipt.json")
        self.assertEqual(code, report["code"], report)
        return report, receipt

    def refused(self, code, text, write=True):
        report, receipt = self.judge(write)
        self.assertEqual(report["code"], code, report)
        self.assertIn(text, report["reason"])
        self.assertFalse({"unreached", "unreached_read"} & set(report), report)
        self.assertEqual((receipt["executed"], receipt["executions"]), ([], 0))
        return report, receipt

    def test_the_declaration_lists_every_runner_case_in_one_profile(self):
        names = [case.name for case in CHECK.cases()]
        self.assertEqual(sorted(names), sorted(name for listed in EXPECTED["profiles"].values() for name in listed))
        self.assertEqual(len(names), len(set(names)))

    def test_a_complete_profile_credits_every_case_with_its_bounds(self):
        report, receipt = self.judge()
        self.assertEqual((report["code"], report["reason"]), (0, None), report)
        self.assertEqual(receipt["executed"], sorted(CASES))
        self.assertEqual((receipt["job"], receipt["module"], receipt["completion"]), ("tlc", "pr", "completed"))
        self.assertEqual(receipt["bounds"]["cases"]["live-drain"]["liveness"], True)
        self.assertEqual(receipt["bounds"]["cases"]["put"]["distinct"], PUT)
        self.assert_kill_basis(receipt)
        self.assertEqual(report["unreached"], HEALTHY)
        self.assertEqual(report["unreached_read"], self.read_counts())
        with mock.patch.object(judge_tlc, "static_contract", wraps=judge_tlc.static_contract) as contract:
            self.assertEqual(report, judge_tlc.derive(self.evidence, "0" * 40, "pr")[0])
        self.assertEqual(contract.call_count, 1)

    def test_a_failure_of_the_span_rule_keeps_the_credit(self):
        """Planted: the rule raises `RuntimeError`; each model's value names its first case by name and the error, and
        the verdict, code, reason and receipt stay."""
        with mock.patch.object(judge_tlc, "unreached", side_effect=RuntimeError("x")):
            report, receipt = self.judge()
        self.assertEqual((report["code"], report["reason"], receipt["executed"]), (0, None, sorted(CASES)))
        self.assertEqual(report["unreached"], {
            "tla/Recovery.tla": "recovery: the span report failed: RuntimeError('x')",
            "tla/Lifecycle.tla": "live-drain: the span report failed: RuntimeError('x')",
            "tla/Identity.tla": "identity: the span report failed: RuntimeError('x')"})
        self.assertEqual(report["unreached_read"], {"cases": 0, "span_lines": 0})

    def test_a_failure_of_the_shared_span_setup_keeps_the_credit(self):
        """Planted: the runner loads for the judgment and fails its second load, the span report's; each model's
        value names its file and the error, and the verdict, code, reason and receipt stay."""
        with mock.patch.object(judge_tlc, "runner", side_effect=[CHECK, RuntimeError("x")]):
            report, receipt = self.judge()
        self.assertEqual((report["code"], report["reason"], receipt["executed"]), (0, None, sorted(CASES)))
        self.assertEqual(report["unreached"], {f"tla/{model}": f"{model}: the span report failed: RuntimeError('x')"
                                               for model in judge_tlc.SPAN_MODELS})
        self.assertEqual(report["unreached_read"], {"cases": 0, "span_lines": 0})

    def read_counts(self, *unread):
        """The `unreached_read` of the unedited fixture when the span report reads every kestrike model but the
        files `unread`: the completing cases without a mutation of the models it reads, and their span lines, one for
        each action of a case's `coverage`, or one for its `Tick`, and one more for `put`'s unreached span."""
        cases = [case for case in CASES.values() if case.target in judge_tlc.SPAN_MODELS and case.target not in unread
                 and CHECK.exit_status(case.expected) == 0 and not case.mutation]
        return {"cases": len(cases),
                "span_lines": sum(len(case.coverage or ("Tick",)) + (case.name == "put") for case in cases)}

    def selected(self, edit):
        """The judge's report when the runner's second load, the span report's, lists the real cases after `edit`
        changes them; the verdict still judges the real cases."""
        edited = judge_tlc.runner()
        edited.cases = lambda: iter(edit({case.name: case for case in CHECK.cases()}).values())
        with mock.patch.object(judge_tlc, "runner", side_effect=[CHECK, edited]):
            report, receipt = self.judge()
        self.assertEqual((report["code"], report["reason"], receipt["executed"]), (0, None, sorted(CASES)))
        return report

    def test_a_mutation_case_s_span_changes_no_list(self):
        """Planted: `put`, the one case that lists the fixture's unreached span, carries a mutation in the cases the
        span report selects from, so Lifecycle's list is empty."""
        report = self.selected(lambda cases: {**cases, "put": dataclasses.replace(cases["put"], mutation=("a", "b"))})
        self.assertEqual(report["unreached"], {**HEALTHY, "tla/Lifecycle.tla": []})

    def test_a_model_with_no_completing_case_is_unread(self):
        """Planted: the span report sees no Recovery case; Recovery's value names its file, and the other models'
        values and the read counts of their cases and span lines stay."""
        report = self.selected(lambda cases: {name: case for name, case in cases.items() if case.target != "Recovery.tla"})
        self.assertEqual(report["unreached"], {
            **HEALTHY, "tla/Recovery.tla": "Recovery.tla: the profile has no completing case of the model without a mutation"})
        self.assertEqual(report["unreached_read"], self.read_counts("Recovery.tla"))

    def test_a_span_of_the_root_module_is_listed_under_the_model_with_its_module(self):
        """Planted: `put` lists `OneRange`'s body in `LifecycleMC` at 7:13-7:31 with 0; the entry names the module and
        takes its text from `tla/LifecycleMC.tla`."""
        self.rewrite("put", "tlc.log", lambda text: text.replace(
            REPORT_END, "  line 7, col 13 to line 7, col 31 of module LifecycleMC: 0\n" + REPORT_END))
        report, _ = self.judge()
        self.assertEqual(report["unreached"]["tla/Lifecycle.tla"], HEALTHY["tla/Lifecycle.tla"] + [
            {"section": "ODrain", "at": "LifecycleMC 7:13-7:31", "text": "[i \\in Frags |-> 1]"}])

    def test_an_action_shown_only_by_located_headers_ran_by_its_last_one(self):
        """Planted: `put`'s `CBegin` header carries a location, after a located `CBegin` header that ran in no
        state; the last of them ran, so the log is read and the entry names the located section."""
        header = "<CBegin line 1, col 1 to line 1, col 2 of module Lifecycle>: 3:5"
        self.rewrite("put", "tlc.log", lambda text: text.replace(header, header.replace(">", " (1 5 1 6)>").replace("3:5", "0:0")
                                                                 + "\n" + header.replace(">", " (1 1 1 2)>")))
        report, _ = self.judge()
        self.assertEqual((report["code"], report["unreached"]["tla/Lifecycle.tla"]),
                         (0, [{**HEALTHY["tla/Lifecycle.tla"][0], "section": "CBegin (1 1 1 2)"}]))

    def test_a_violation_or_mutation_case_s_report_changes_no_list(self):
        """Planted: complete coverage reports with a span of 0 at line 3 in the logs of the violation case
        `NoPublication` and the mutation case `publish-missing-range`, digests rebound; the lists stay."""
        planted = REPORT_OPEN + "<CBegin line 1, col 1 to line 1, col 2 of module Lifecycle>: 3:5\n" \
            "  line 3, col 1 to line 3, col 3 of module Lifecycle: 0\n" + REPORT_END
        for name in ("NoPublication", "publish-missing-range"):
            self.rewrite(name, "tlc.log", lambda text: text + planted)
        report, _ = self.judge()
        self.assertEqual((report["code"], [entry["at"] for entry in report["unreached"]["tla/Lifecycle.tla"]]), (0, ["2:1-2:3"]))

    def test_a_log_the_span_reader_refuses_names_its_case_and_keeps_the_credit(self):
        """Each planted log of a completing case, its digest rebound, leaves the run credited with code 0, its model's
        value the refusal string naming the case, the other models' values as the unedited fixture gives them, and
        the read counts those of the other models alone, whichever cases of the refused model were read before it: an
        unknown line inside a complete report; a span line above the report's first header; a span line past the end
        of the committed file, listed by `recovery-replacement` and `recovery-fence`, which names `recovery-fence`,
        the first by name, though the runner runs `recovery-replacement` first; a span whose end precedes its start,
        one whose start lies past its line, one whose end lies past its line, and one ending at column 0 of a later
        line; a span of a module with no file and one whose name is too long for a file; a report without its end
        line; `identity-cap-without-pressure`'s complete report with no section; a complete report showing `CBegin`
        with a second count of 0, then a later report cut short showing it positive, so that `uncovered` passes,
        and the same with a located `CBegin` that ran before a last located `CBegin` that did not; a start column
        of 0; a positive span past the end of the file around `put`'s unreached span, which the rule would
        otherwise count as its evaluation; two bad spans, the later location in `recovery-fence`, the first case
        by name; and, of two refused logs, `put-three-ranges` without its end line and `put-and-get` with an unknown line,
        `put-and-get`, the first in name order, though the runner runs `put-three-ranges` first."""
        late = REPORT_OPEN + "<CBegin line 1, col 1 to line 1, col 2 of module Lifecycle>: 3:5\n"
        long = "A" * 300
        def span(line):
            return lambda text: text.replace(REPORT_END, f"  {line}: 0\n" + REPORT_END)
        past = span("line 9999, col 1 to line 9999, col 2 of module Recovery")
        for name, edits, model, refusal in (
            ("an unknown line", {"put": lambda text: text.replace(REPORT_END, "  line 9 of module Lifecycle: 1\n" + REPORT_END)},
             "tla/Lifecycle.tla", "put: tlc.log's coverage report holds a line that is neither a header nor a span line: "
             "'  line 9 of module Lifecycle: 1'"),
            ("a span line above the first header", {"identity": lambda text: text.replace(
                REPORT_OPEN, REPORT_OPEN + "  line 1, col 1 to line 1, col 4 of module Identity: 2\n")},
             "tla/Identity.tla", "identity: tlc.log's coverage report holds a span line before its first header: "
             "'  line 1, col 1 to line 1, col 4 of module Identity: 2'"),
            ("a span past the end of the file", {"recovery-replacement": past, "recovery-fence": past},
             "tla/Recovery.tla", "recovery-fence: span Recovery 9999:1-9999:2 lies outside the text of tla/Recovery.tla"),
            ("a span whose end precedes its start", {"identity": span("line 2, col 9 to line 2, col 3 of module Identity")},
             "tla/Identity.tla", "identity: span Identity 2:9-2:3 ends before its start"),
            ("a span whose start column is 0", {"identity": span("line 2, col 0 to line 2, col 3 of module Identity")},
             "tla/Identity.tla", "identity: span Identity 2:0-2:3 lies outside the text of tla/Identity.tla"),
            ("a positive span past the end of the file around the unreached span", {"put": lambda text: text.replace(
                "  line 2, col 1 to line 2, col 3 of module Lifecycle: 0\n",
                "  line 1, col 1 to line 9999, col 5 of module Lifecycle: 7\n  line 2, col 1 to line 2, col 3 of module Lifecycle: 0\n")},
             "tla/Lifecycle.tla", "put: span Lifecycle 1:1-9999:5 lies outside the text of tla/Lifecycle.tla"),
            ("two bad spans, the later location in the case first by name", {
                "recovery-replacement": span("line 9998, col 1 to line 9998, col 2 of module Recovery"),
                "recovery-fence": past},
             "tla/Recovery.tla", "recovery-fence: span Recovery 9999:1-9999:2 lies outside the text of tla/Recovery.tla"),
            ("a span whose start lies past its line", {"identity": span("line 2, col 200 to line 3, col 1 of module Identity")},
             "tla/Identity.tla", "identity: span Identity 2:200-3:1 lies outside the text of tla/Identity.tla"),
            ("a span whose end lies past its line", {"identity": span("line 2, col 1 to line 2, col 500 of module Identity")},
             "tla/Identity.tla", "identity: span Identity 2:1-2:500 lies outside the text of tla/Identity.tla"),
            ("a span ending at column 0", {"identity": span("line 2, col 1 to line 3, col 0 of module Identity")},
             "tla/Identity.tla", "identity: span Identity 2:1-3:0 lies outside the text of tla/Identity.tla"),
            ("a span of a module with no file", {"identity": span("line 1, col 1 to line 1, col 2 of module Absent")},
             "tla/Identity.tla", "identity: span Absent 1:1-1:2 lies outside the text of tla/Absent.tla"),
            ("a module name too long for a file", {"identity": span(f"line 1, col 1 to line 1, col 2 of module {long}")},
             "tla/Identity.tla", f"identity: span {long} 1:1-1:2 lies outside the text of tla/{long}.tla"),
            ("no end line", {"identity": lambda text: text.replace(REPORT_END, "")},
             "tla/Identity.tla", "identity: tlc.log has no complete coverage report"),
            ("no section", {"identity-cap-without-pressure": lambda text: text.replace(
                "<Tick line 1, col 1 to line 1, col 2 of module Identity>: 3:5\n  line 1, col 1 to line 1, col 4 of module Identity: 2\n",
                "<epoch line 49, col 5 to line 49, col 9 of module Identity>: 1\n")},
             "tla/Identity.tla", "identity-cap-without-pressure: tlc.log's last complete coverage report has no section"),
            ("an action that ran only in a report cut short", {"put": lambda text: text.replace(
                "<CBegin line 1, col 1 to line 1, col 2 of module Lifecycle>: 3:5", "<CBegin line 1, col 1 to line 1, col 2 of module Lifecycle>: 0:0") + late},
             "tla/Lifecycle.tla", "put: tlc.log's last complete coverage report does not show CBegin as a section that ran"),
            ("a located section that ran before a last one of its operator that did not", {"put": lambda text: text.replace(
                "<CBegin line 1, col 1 to line 1, col 2 of module Lifecycle>: 3:5",
                "<CBegin line 1, col 1 to line 1, col 2 of module Lifecycle (1 1 1 2)>: 3:5\n"
                "<CBegin line 1, col 1 to line 1, col 2 of module Lifecycle (1 5 1 6)>: 0:0") + late},
             "tla/Lifecycle.tla", "put: tlc.log's last complete coverage report does not show CBegin as a section that ran"),
            ("two refused logs", {"put-three-ranges": lambda text: text.replace(REPORT_END, ""),
                                  "put-and-get": lambda text: text.replace(REPORT_END, "x\n" + REPORT_END)},
             "tla/Lifecycle.tla", "put-and-get: tlc.log's coverage report holds a line that is neither a header nor a span "
             "line: 'x'"),
        ):
            with self.subTest(name):
                self.setUp()
                for case, edit in edits.items():
                    before = self.logs[case]["tlc.log"]
                    self.rewrite(case, "tlc.log", edit)
                    self.assertNotEqual(self.logs[case]["tlc.log"], before)
                report, receipt = self.judge()
                self.assertEqual((report["code"], report["reason"]), (0, None), report)
                self.assertEqual(report["unreached"], {**HEALTHY, model: refusal})
                self.assertEqual(report["unreached_read"], self.read_counts(model.removeprefix("tla/")))
                self.assertEqual(receipt["executed"], sorted(CASES))

    def test_a_later_refused_log_is_refused_on_its_own(self):
        """Planted: `put-three-ranges`'s log alone without its end line is refused for that reason, so the two refused
        logs above each refuse on their own. The seven Lifecycle cases before it by name were read, and the read counts
        are those of the other two models."""
        self.rewrite("put-three-ranges", "tlc.log", lambda text: text.replace(REPORT_END, ""))
        report, _ = self.judge()
        self.assertEqual(report["unreached"]["tla/Lifecycle.tla"], "put-three-ranges: tlc.log has no complete coverage report")
        self.assertEqual(report["unreached_read"], self.read_counts("Lifecycle.tla"))

    def assert_kill_basis(self, receipt):
        """The receipt records, for each kill case of the profile, its passing baseline and the actions that reach its
        mutation: `put` and an action set holding `OPublish` and neither `Next` nor `Spec` for
        `publish-missing-range`, `identity-share-of-one` for `admit-over-share`, `identity-put-caps` for
        `admit-over-put-cap`, `identity-peer-put-cap` for `admit-over-peer-put-cap` and `identity` for
        `replay-without-watermark`, `replay-without-epoch` and `result-after-replacement`."""
        bounds = receipt["bounds"]["cases"]
        kills = [name for name, case in CASES.items() if CHECK.killing(case)]
        self.assertEqual(len(kills), 51)
        for name in kills:
            self.assertTrue(bounds[name].get("baseline") and bounds[name].get("mutated"), name)
        self.assertEqual(bounds["publish-missing-range"]["baseline"], "put")
        self.assertIn("OPublish", bounds["publish-missing-range"]["mutated"])
        self.assertFalse({"Next", "Spec"} & set(bounds["publish-missing-range"]["mutated"]))
        self.assertEqual(bounds["admit-over-share"]["baseline"], "identity-share-of-one")
        self.assertEqual(bounds["admit-over-share"]["mutated"], ["Admit", "Refuse"])
        self.assertEqual((bounds["admit-over-put-cap"]["baseline"], bounds["admit-over-put-cap"]["mutated"]),
                         ("identity-put-caps", ["Admit", "Refuse"]))
        self.assertEqual((bounds["admit-over-peer-put-cap"]["baseline"], bounds["admit-over-peer-put-cap"]["mutated"]),
                         ("identity-peer-put-cap", ["Admit", "Refuse"]))
        self.assertEqual((bounds["replay-without-watermark"]["baseline"], bounds["replay-without-watermark"]["mutated"]),
                         ("identity", ["Replay"]))
        self.assertEqual((bounds["replay-without-epoch"]["baseline"], bounds["replay-without-epoch"]["mutated"]),
                         ("identity", ["Conflict", "Replay", "UnknownAnswer"]))
        self.assertEqual((bounds["result-after-replacement"]["baseline"], bounds["result-after-replacement"]["mutated"]),
                         ("identity", ["End"]))

    def test_the_kill_basis_assertion_fails_on_a_receipt_without_it(self):
        """A credited receipt whose kill case lacks its baseline, or its mutated-action set, fails the assertion."""
        _, receipt = self.judge()
        for field in ("baseline", "mutated"):
            with self.subTest(field):
                bare = copy.deepcopy(receipt)
                del bare["bounds"]["cases"]["publish-missing-range"][field]
                with self.assertRaises(AssertionError):
                    self.assert_kill_basis(bare)

    def test_a_count_other_than_the_registry_s_is_a_mismatch(self):
        """The registry's `put` count raised by one, with the evidence unchanged, is refused against the count the
        judge derives from the retained log."""
        declared = declaration(lambda d: d["cases"]["put"].update(distinct=PUT + 1))
        self.write()
        with self.assertRaises(judge_tlc.Refusal) as caught:
            judge_tlc.judge(self.evidence, declared, self.identity, self.profile)
        self.assertEqual(caught.exception.code, 1)
        self.assertIn(f"put's tlc.log records {PUT} distinct states, the registry pins {PUT + 1}", str(caught.exception))

    def test_a_counterexample_without_a_mutated_step_is_a_mismatch(self):
        """Planted: `publish-missing-range`'s step of `OPublish`, the one action that reaches its mutation, becomes a
        step of `OData`, with the result's digest rebound."""
        self.rewrite("publish-missing-range", "tlc.log", lambda text: text.replace("State 2: <OPublish", "State 2: <OData"))
        self.refused(1, "publish-missing-range's tlc.log records a counterexample that takes no step of ['OPublish']")

    def test_a_kill_credits_from_a_step_of_any_one_of_its_actions(self):
        """`admit-over-share`'s step of `Admit`, the first of its actions `Admit` and `Refuse`, becomes a step of
        `Refuse` alone, with the result's digest rebound, and the profile still credits."""
        self.rewrite("admit-over-share", "tlc.log", lambda text: text.replace("State 2: <Admit(", "State 2: <Refuse("))
        self.assertIn("State 2: <Refuse(", self.logs["admit-over-share"]["tlc.log"])
        report, _ = self.judge()
        self.assertEqual((report["code"], report["reason"]), (0, None), report)

    def registry(self, change):
        """Points the judge's registry path, for this test, at a copy of the committed registry with `change` applied."""
        temp = tempfile.TemporaryDirectory(prefix="kestrike-tlc-")
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / "expected.json"
        path.write_text(json.dumps(declaration(change)))
        patch = mock.patch.object(judge_tlc, "EXPECTED", path)
        patch.start()
        self.addCleanup(patch.stop)

    def pins(self, write=True):
        """Writes the evidence unless `write` is false, runs the `pins` command in this process and returns its exit
        code and output."""
        if write:
            self.write()
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = judge_tlc.main(["pins", "--evidence", str(self.evidence)])
        return code, out.getvalue(), err.getvalue()

    def assert_committed_entries(self, out):
        """`out` is the committed `cases` entry of each case of the profile, one line each in name order."""
        committed = {line.strip().rstrip(","): line.rstrip().rstrip(",")
                     for line in (ROOT / "verification/tlc/expected.json").read_text().splitlines() if line.startswith('    "')}
        lines = out.rstrip("\n").split(",\n")
        self.assertEqual(lines, [committed[line.strip()] for line in lines])
        self.assertEqual([self.document("{" + line + "}", "a pins line").popitem()[0] for line in lines], sorted(CASES))

    def test_pins_prints_the_committed_entry_of_each_case_of_the_run(self):
        code, out, err = self.pins()
        self.assertEqual(code, 0, err)
        self.assert_committed_entries(out)

    def test_pins_leaves_out_only_the_comparisons_with_the_cases_map(self):
        """Planted in a registry copy, one at a time: `put`'s entry removed, `put`'s outcome changed, its count
        removed, a count on the violation `NoPublication`, and `put`'s invariants reduced. `judge` refuses each, and
        `pins` prints the committed entries of the run for each."""
        for name, change, refusal in (
            ("an entry removed", lambda d: d["cases"].pop("put"), "the registry's cases omit ['put']"),
            ("an outcome changed", lambda d: d["cases"]["put"].update(outcome=CHECK.violation("TypeOK")),
             "put: the registry declares outcome"),
            ("a count removed", lambda d: d["cases"]["put"].pop("distinct"), "put: the registry pins no count"),
            ("a count on a violation", lambda d: d["cases"]["NoPublication"].update(distinct=7),
             "NoPublication: the registry pins a count on a violation"),
            ("an invariant dropped", lambda d: d["cases"]["put"].update(invariants=["TypeOK"]),
             "put: the registry's lists ['TypeOK']"),
        ):
            with self.subTest(name):
                self.write()
                with self.assertRaises(judge_tlc.Refusal) as caught:
                    judge_tlc.judge(self.evidence, declaration(change), self.identity, self.profile)
                self.assertIn(refusal, str(caught.exception))
                self.registry(change)
                code, out, err = self.pins(write=False)
                self.assertEqual(code, 0, err)
                self.assert_committed_entries(out)

    def test_pins_derives_each_count_from_the_retained_log(self):
        """A run whose `put` log and result report two more states than the registry pins prints that count, while
        `judge` refuses the same run against the pin."""
        self.rewrite("put", "tlc.log", lambda text: text.replace(f"{PUT} distinct", f"{PUT + 2} distinct"))
        self.results["put"]["states"][1] = str(PUT + 2)
        code, out, err = self.pins()
        self.assertEqual(code, 0, err)
        self.assertIn(f'"put": {json.dumps({**EXPECTED["cases"]["put"], "distinct": PUT + 2})}', out)
        self.refused(1, f"put's tlc.log records {PUT + 2} distinct states, the registry pins {PUT}")

    def test_pins_prints_no_entry_for_a_run_the_judge_refuses(self):
        """Refused by the checks `pins` keeps, so it prints nothing: a runner exit of 1, a missing result, a missing
        `tlc.argv`, a command without a profile and one with an unknown profile, `publish-missing-range`'s step of
        `OPublish` turned into one of `OData`, `put`'s result count changed with its log unchanged, a result that is
        no object, Recovery's `models` list reversed, Lifecycle's `uncontrolled` list short by one, Identity's empty
        `uncontrolled` list given a stale `PutCaps` and `type_kills` emptied in the registry."""
        for name, edit, code, reason in (
                ("a runner failure", lambda: setattr(self, "exit", 1), 1, "it refused a case"),
                ("a missing result", lambda: self.results.pop("put"), 2, "miss ['put']"),
                ("no runner command", lambda: setattr(self, "argv", None), 2, "the lane recorded no runner command:"),
                ("a command without a profile", lambda: setattr(self, "argv", [arg for arg in self.argv if arg not in ("--tier", "pr")]), 2, "the lane recorded no runner command with a profile"),
                ("an unknown profile", lambda: self.argv.__setitem__(self.argv.index("--tier") + 1, "nightly"), 2,
                 "the lane recorded no runner command with a profile"),
                ("a counterexample without a mutated step", lambda: self.rewrite(
                    "publish-missing-range", "tlc.log", lambda text: text.replace("State 2: <OPublish", "State 2: <OData")), 1,
                 "publish-missing-range's tlc.log records a counterexample that takes no step of ['OPublish']"),
                ("a result count the log does not report", lambda: self.results["put"]["states"].__setitem__(1, str(PUT + 1)), 1,
                 f"put's tlc.log records states ['{PUT + 3}', '{PUT}'], results.json ['{PUT + 3}', '{PUT + 1}']"),
                ("a result that is no object", lambda: setattr(self, "results", {"put": "put"}), 2, "malformed evidence"),
                ("Safety conjuncts in another order", lambda: self.registry(lambda d: d["models"]["Recovery.tla"].reverse()), 2,
                 "the registry's models for Recovery.tla omit the Safety conjuncts [] and add [] in another order"),
                ("an uncontrolled list short by one", lambda: self.registry(
                    lambda d: d["uncontrolled"]["Lifecycle.tla"].remove("HeaderLast")), 2,
                 "the registry's uncontrolled list for Lifecycle.tla is ['SupplyAfterReady']"),
                ("a stale entry on an empty uncontrolled list", lambda: self.registry(
                    lambda d: d["uncontrolled"]["Identity.tla"].append("PutCaps")), 2,
                 "the registry's uncontrolled list for Identity.tla is ['PutCaps']; no mutation case kills []"),
                ("a TypeOK kill left out", lambda: self.registry(lambda d: d["type_kills"].clear()), 2,
                 "the registry's type_kills [] differ")):
            with self.subTest(name):
                self.setUp()
                edit()
                found, out, err = self.pins()
                self.assertEqual((found, out), (code, ""), err)
                self.assertIn(reason, err)

    def test_an_undecodable_command_is_refused_by_name(self):
        """A `tlc.argv` that is not UTF-8 is the missing command under `pins` and `judge`, and `pins` prints nothing."""
        self.write()
        (self.evidence / "tlc.argv").write_bytes(b"\xff\xfe\n")
        code, out, err = self.pins(write=False)
        self.assertEqual((code, out), (2, ""), err)
        self.assertIn("the lane recorded no runner command:", err)
        self.refused(2, "the lane recorded no runner command or exit:", write=False)

    def test_the_script_exits_with_the_code_of_the_report_it_prints(self):
        """The script run as the lane runs it prints its report and exits with the report's code: 0 for a complete
        profile and 2 once a case's result is missing."""
        for missing, code in ((None, 0), ("put", 2)):
            with self.subTest(missing=missing):
                self.results.pop(missing, None)
                self.write()
                result = subprocess.run([sys.executable, str(SCRIPT), *self.command()], capture_output=True, text=True,
                                        check=False)
                self.assertEqual(result.returncode, code, result.stderr)
                printed = self.document(result.stdout, "the script's output")
                self.assertEqual(printed, self.document((self.evidence / "report.json").read_text(), "report.json"))
                self.assertEqual(printed["code"], code)

    def document(self, text, what):
        """The JSON document `text` holds; text that does not parse fails the test naming `what`."""
        try:
            return json.loads(text)
        except ValueError as error:
            self.fail(f"{what} is not JSON: {error}")

    def scheduled(self):
        self.profile = "scheduled"
        self.argv[self.argv.index("--tier") + 1] = "scheduled"

    def test_a_scheduled_profile_judges_the_pr_cases_as_well(self):
        self.scheduled()
        self.results.update({name: self.result(case) for name, case in SCHEDULED.items()})
        report, receipt = self.judge()
        self.assertEqual((report["code"], report["reason"]), (0, None), report)
        self.assertEqual((receipt["module"], receipt["executed"]), ("scheduled", sorted({*CASES, *SCHEDULED})))

    def test_a_scheduled_profile_without_the_pr_cases_is_refused(self):
        self.scheduled()
        self.results = {name: self.result(case) for name, case in SCHEDULED.items()}
        self.refused(2, f"miss ['{sorted(CASES)[0]}'")

    def test_a_result_off_its_case_tier_is_refused(self):
        self.scheduled()
        self.results.update({name: self.result(case) for name, case in SCHEDULED.items()})
        self.results["put"]["tier"] = "scheduled"
        self.refused(2, "put records coverage or a tier")

    def test_a_missing_case_is_a_tool_failure(self):
        self.results.pop("put")
        self.refused(2, "miss ['put']")

    def test_a_jar_other_than_the_declared_one_is_drift(self):
        self.identity["jar"]["sha256"] = "0" * 64
        self.refused(2, "the jar")

    def test_a_result_with_another_outcome_is_a_mismatch(self):
        self.results["NoPublication"]["expected"] = CASES["put"].expected
        self.refused(1, "NoPublication exited")

    def test_a_liveness_case_without_the_final_check_is_a_tool_failure(self):
        self.results["live-drain"]["command"].remove("-lncheck")
        self.refused(2, "live-drain lacks -lncheck final")

    def test_an_edited_model_is_drift(self):
        self.results["publish-revoked"]["inputs"]["Lifecycle.tla"] = "0" * 64
        self.refused(2, "publish-revoked checked models or a configuration other than the committed ones")

    def test_a_configuration_other_than_the_generated_one_is_drift(self):
        self.results["put"]["inputs"]["model.cfg"] = digest("CONSTANTS Frags = {1}\nSPECIFICATION Spec\n")
        self.refused(2, "put checked models or a configuration other than the committed ones")

    def test_a_jdk_tree_other_than_the_declared_one_is_drift(self):
        self.identity["java"]["install"]["sha256"] = "0" * 64
        self.refused(2, "the JDK install tree differs")

    def test_a_violation_followed_by_a_failure_exit_is_a_mismatch(self):
        self.results["duplicate-credit"]["returncode"] = 255
        self.refused(1, "duplicate-credit exited 255")
        self.results["duplicate-credit"]["returncode"] = 12
        self.results["stalled-supplier"]["returncode"] = 12
        self.refused(1, "stalled-supplier exited 12")

    def test_the_runner_refuses_a_violation_followed_by_a_failure_exit(self):
        """A stub TLC that prints the declared violation and then fails is refused by the runner on each ground
        alone: a failure exit with the one declared outcome in its log, a second terminal line, each failure
        TLC reports, under the exit status the violation declares, and a counterexample that takes no step of an
        action reaching the mutation. The violation followed by its trace heading and a step of `OData`, the one
        action that reaches the mutated definition, under that exit status is the case's outcome."""
        temp = tempfile.TemporaryDirectory(prefix="kestrike-tlc-")
        self.addCleanup(temp.cleanup)
        bin_dir = Path(temp.name) / "bin"
        bin_dir.mkdir()
        java = bin_dir / "java"
        case = CASES["duplicate-credit"]
        declared = CHECK.exit_status(case.expected)
        path = os.environ["PATH"]
        os.environ["PATH"] = f"{bin_dir}{os.pathsep}{path}"
        self.addCleanup(os.environ.__setitem__, "PATH", path)

        def run(after, exit_code):
            """Runs the case under a stub TLC that prints the violation, then the lines `after`, and exits `exit_code`."""
            lines = "".join(f'echo "{line}"\n' for line in (case.expected, *after))
            java.write_text(f'#!/bin/sh\ncase "$*" in *tla2sany.SANY*) echo "Semantic processing of module {case.module}"; exit 0 ;; esac\n'
                            f'{lines}exit {exit_code}\n')
            java.chmod(0o755)
            with contextlib.redirect_stdout(io.StringIO()):
                return CHECK.run_case(case, ROOT / "tla", Path(tempfile.mkdtemp(dir=temp.name)), Path(JAR), 1)

        for name, after, exit_code in (("a failure exit", (), 255),
                                       *((failure, (failure,), declared) for failure in FAILURES)):
            with self.subTest(name):
                with self.assertRaisesRegex(RuntimeError, f"duplicate-credit: unexpected TLC outcome or exit {exit_code}"):
                    run(after, exit_code)
        initial = (TRACE, "State 1: <Initial predicate>")
        with self.subTest("a counterexample without a mutated step"):
            with self.assertRaisesRegex(RuntimeError, r"duplicate-credit: the counterexample takes no step of \['OData'\]"):
                run((*initial, "State 2: <CBegin line 82, col 5 to line 83, col 77 of module Lifecycle>"), declared)
        result = run((*initial, "State 2: <OData line 193, col 5 to line 201, col 16 of module Lifecycle>"), declared)
        self.assertEqual((result["expected"], result["returncode"]), (case.expected, declared))
        case = CASES["admit-over-share"]
        declared = CHECK.exit_status(case.expected)
        with self.subTest("a step of the second of two mutated actions"):
            result = run((*initial, 'State 2: <Refuse(1,1,1,"GET") line 114, col 5 to line 121, col 50 of module Identity>'),
                         declared)
            self.assertEqual((result["case"], result["returncode"]), ("admit-over-share", declared))

    def test_the_runner_refuses_an_unread_kill_case_before_it_starts_tlc(self):
        """A mutation case declaring the violation of `TypeOK` by the initial state, and one whose mutation edits
        `Next`, which no action reaches, raise before the runner writes a configuration or starts TLC."""
        temp = tempfile.TemporaryDirectory(prefix="kestrike-tlc-")
        self.addCleanup(temp.cleanup)
        case = CASES["admit-over-share"]
        for name, planted, refusal in (
                ("an initial-state violation", dataclasses.replace(
                    case, expected="Error: Invariant TypeOK is violated by the initial state:"),
                 "admit-over-share: the kill rules read no violated property"),
                ("a mutation of Next", dataclasses.replace(case, mutation=("    \\/ CAttach\n", "    \\/ CAttach \\/ Tick\n")),
                 "admit-over-share: no action of Next reaches the definition the mutation edits")):
            with self.subTest(name):
                output = Path(tempfile.mkdtemp(dir=temp.name))
                with self.assertRaisesRegex(ValueError, refusal):
                    CHECK.run_case(planted, ROOT / "tla", output, Path(JAR), 1)
                self.assertFalse((output / planted.name / "model.cfg").exists())

    def test_an_expected_violation_with_a_zero_exit_is_a_mismatch(self):
        self.results["duplicate-credit"]["returncode"] = 0
        self.refused(1, "duplicate-credit exited 0")

    def test_a_model_drift_since_the_identity_is_refused(self):
        self.identity["models"]["Lifecycle.tla"] = "0" * 64
        self.refused(2, "the models changed")

    def test_another_command_is_a_tool_failure(self):
        self.argv[self.argv.index("--workers") + 1] = "1"
        self.refused(2, "the lane ran")

    def test_an_interrupted_run_is_incomplete(self):
        self.exit = 124
        _, receipt = self.refused(3, "interrupted")
        self.assertEqual(receipt["completion"], "timeout")

    def test_a_runner_under_another_jdk_or_jar_is_drift(self):
        self.runtime = 'openjdk version "17.0.2" 2022-01-18\n'
        self.refused(2, "the runner ran under")
        self.runtime = f'openjdk version "{EXPECTED["java"]["version"]}"'
        self.jar_sha = "0" * 64
        self.refused(2, "a jar other than the declared one")

    def test_a_duplicate_result_is_a_tool_failure(self):
        self.results["twin"] = dict(self.results["put"])
        self.refused(2, "repeat a case")

    def test_a_safety_case_with_the_final_check_is_a_tool_failure(self):
        self.results["put"]["command"][-3:-3] = ["-lncheck", "final"]
        self.refused(2, "put adds -lncheck final")

    def test_a_liveness_control_with_a_zero_exit_is_a_mismatch(self):
        self.results["stalled-supplier"]["returncode"] = 0
        self.refused(1, "stalled-supplier exited 0")

    def test_a_case_without_states_or_with_other_coverage_is_refused(self):
        """A result without states, a violation whose result and log report zero distinct states, and a result with
        other coverage are refused by name."""
        self.results["put"]["states"] = None
        self.refused(1, "put records no explored state")
        self.setUp()
        self.rewrite("NoPublication", "tlc.log", lambda text: text.replace("7 distinct", "0 distinct"))
        self.results["NoPublication"]["states"] = ["10", "0"]
        self.refused(1, "NoPublication records no explored state")
        self.setUp()
        self.results["put"]["coverage"] = []
        self.refused(2, "put records coverage or a tier")

    def test_malformed_results_are_a_tool_failure_with_a_report(self):
        """A states value other than two decimal strings is malformed evidence: two words, one count, two numbers, a
        string, a count with a sign, a count with a decimal point and each falsy value other than null."""
        for states in (["x", "y"], ["5"], [10, 7], "107", ["10", "-7"], ["10", "7.0"], [], 0, False, "", {}):
            with self.subTest(states=states):
                self.results["put"]["states"] = states
                self.refused(2, "malformed evidence")

    def test_a_recorded_time_other_than_a_finite_count_of_seconds_is_a_tool_failure(self):
        """A `seconds` value of infinity, NaN, a negative count, a string, null, a boolean or an integer past the largest
        finite float is malformed evidence, so no receipt carries a token outside RFC 8259 JSON."""
        for seconds in (float("inf"), float("nan"), -1.0, "1.0", None, True, 10 ** 400):
            with self.subTest(seconds=seconds):
                self.results["put"]["seconds"] = seconds
                self.refused(2, "malformed evidence: put records")

    def test_results_json_the_decoder_cannot_hold_is_a_tool_failure_under_judge_and_pins(self):
        """`results.json` written with a count of `1e999`, which decodes to infinity, or nested 100000 arrays deep is a
        tool failure: `judge` writes its report and `pins` prints nothing."""
        for name, change, reason in (
                ("an infinite count", lambda text: text.replace(f'"{PUT}"', "1e999", 1), "malformed evidence"),
                ("deep nesting", lambda text: text.replace('"results": [', '"results": [' + "[" * 100000 + "]" * 100000 + ", ", 1),
                 "unreadable")):
            with self.subTest(name):
                self.write()
                path = self.evidence / "results.json"
                text = path.read_text()
                path.write_text(change(text))
                self.assertNotEqual(path.read_text(), text)
                self.refused(2, reason, write=False)
                code, out, err = self.pins(write=False)
                self.assertEqual((code, out), (2, ""), err)
                self.assertIn(reason, err)

    def test_a_runner_that_fails_to_load_is_a_tool_failure_under_judge_and_pins(self):
        """A runner that raises while it loads is a tool failure: `judge` writes its report and `pins` prints nothing."""
        broken = self.evidence.parent / "broken.py"
        for error in ("ImportError('no module')", "NameError('undefined')", "SyntaxError('invalid syntax')"):
            with self.subTest(error=error):
                broken.write_text(f"raise {error}\n")
                with mock.patch.object(judge_tlc, "runner", lambda: judge_tlc.load("broken_runner", broken)), \
                        mock.patch.dict(sys.modules):
                    self.refused(2, f"{broken} fails to load: {error.split('(')[0]}")
                    code, out, err = self.pins(write=False)
                self.assertEqual((code, out), (2, ""), err)
                self.assertIn("fails to load", err)

    def test_a_path_resolution_failure_is_a_tool_failure(self):
        """Resolving a path of the recorded command raises, as Python 3.9 does on a symbolic-link loop: the judge
        refuses the command by that reason and writes its report."""
        self.write()
        with mock.patch.object(judge_tlc.Path, "resolve", side_effect=RuntimeError("Symlink loop")):
            report, _ = self.refused(2, "names a path that does not resolve: Symlink loop", write=False)
        self.assertEqual(report["credited"], False)

    def test_an_unreadable_receipt_input_is_a_tool_failure_with_a_report(self):
        """A `pins.txt` that is not UTF-8, a directory named `pins.txt`, an unreadable `results.json` and a directory
        named `Extra.tla` among the committed models each give a tool-failure report and receipt with no case, and
        `pins` exits 2 printing nothing for the unreadable model."""
        for name, plant, reason in (
                ("an undecodable pins.txt", lambda: (self.evidence / "pins.txt").write_bytes(b"\xff\n"), "a receipt input is unreadable"),
                ("a directory named pins.txt", lambda: ((self.evidence / "pins.txt").unlink(), (self.evidence / "pins.txt").mkdir()),
                 "a receipt input is unreadable"),
        ):
            with self.subTest(name):
                self.write()
                plant()
                self.addCleanup(lambda: (self.evidence / "pins.txt").is_dir() and (self.evidence / "pins.txt").rmdir())
                report, receipt = self.refused(2, reason, write=False)
                self.assertEqual((report["cases"], receipt["bounds"]["cases"]), ({}, {}))
                if (self.evidence / "pins.txt").is_dir():
                    (self.evidence / "pins.txt").rmdir()
        with self.subTest("an unreadable results.json"):
            self.write()
            real = judge_tlc.sha256

            def refuse(path):
                """The digest of `path`, except that reading `results.json` is denied."""
                if Path(path).name == "results.json":
                    raise PermissionError(f"denied: {path}")
                return real(path)

            with mock.patch.object(judge_tlc, "sha256", side_effect=refuse):
                report, receipt = self.refused(2, "a receipt input is unreadable: denied:", write=False)
            self.assertEqual(report["cases"], {})
        with self.subTest("an unreadable committed model"):
            temp = tempfile.TemporaryDirectory(prefix="kestrike-tlc-")
            self.addCleanup(temp.cleanup)
            models = Path(temp.name) / "tla"
            shutil.copytree(ROOT / "tla", models)
            (models / "Extra.tla").mkdir()
            self.write()
            with mock.patch.object(judge_tlc, "MODELS", models):
                self.refused(2, "a committed model is unreadable", write=False)
                code, out, err = self.pins(write=False)
            self.assertEqual((code, out), (2, ""), err)
            self.assertIn("a committed model is unreadable", err)

    def test_a_registry_that_is_no_object_is_a_tool_failure(self):
        """The registry file holds a JSON list: `judge` writes a tool-failure report and `pins` prints nothing."""
        temp = tempfile.TemporaryDirectory(prefix="kestrike-tlc-", dir=ROOT / "verification")
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / "expected.json"
        path.write_text("[]")
        self.write()
        with mock.patch.object(judge_tlc, "EXPECTED", path):
            report, receipt = self.refused(2, "holds list, not a JSON object", write=False)
            code, out, err = self.pins(write=False)
        self.assertEqual((receipt["executions"], receipt["bounds"]["workers"]), (0, None))
        self.assertEqual((code, out), (2, ""), err)

    def test_a_step_labelled_next_is_no_mutated_step(self):
        """`publish-missing-range`'s step of `OPublish` becomes the step TLC labels `Next`, with the digest rebound."""
        self.rewrite("publish-missing-range", "tlc.log", lambda text: text.replace(
            'State 2: <OPublish(1,"x") line 1, col 1 to line 1, col 2 of module M>',
            "State 2: <Next line 376, col 28 to line 376, col 55 of module Lifecycle>"))
        self.assertIn("State 2: <Next line", self.logs["publish-missing-range"]["tlc.log"])
        self.refused(1, "publish-missing-range's tlc.log records a counterexample that takes no step of ['OPublish']")

    def test_a_command_path_that_loops_is_a_tool_failure(self):
        """The output directory `tlc.argv` names is a symbolic link to itself: resolving it raises on this Python or
        names another directory, and either way the judge refuses the command as a tool failure with a report."""
        loop = self.evidence.parent / "loop"
        loop.unlink(missing_ok=True)
        loop.symlink_to(loop)
        self.addCleanup(loop.unlink)
        self.argv[self.argv.index("--output") + 1] = str(loop / "tlc")
        report, _ = self.refused(2, "the lane")
        self.assertRegex(report["reason"], "names a path that does not resolve|the lane ran")

    def test_each_case_credits_only_from_its_own_present_logs_that_rederive_its_result(self):
        """A passing summary stands only on the case's SANY and TLC logs: a result without their digests, a missing or
        substituted log, a SANY failure and a log whose outcome, coverage or states disagree are refused by name."""
        violating = "duplicate-credit"
        self.assertNotEqual(CHECK.exit_status(CASES[violating].expected), 0)
        log = self.logs["put"]["tlc.log"]
        for name, edit, code, reason in (
            ("no log digests", lambda: self.results["put"].pop("logs"), 2,
             "put records no per-case sany.log and tlc.log digests"),
            ("a deleted sany.log", lambda: self.logs["put"].pop("sany.log"), 2, "put has no sany.log"),
            ("a deleted tlc.log", lambda: self.logs["put"].pop("tlc.log"), 2, "put has no tlc.log"),
            ("a substituted tlc.log", lambda: self.logs["put"].update({"tlc.log": log.replace(f"{PUT} distinct", f"{PUT + 1} distinct")}), 2,
             "put's tlc.log differs from the digest results.json records"),
            ("a substituted sany.log", lambda: self.logs["put"].update({"sany.log": "Parsing file other.tla\n"}), 2,
             "put's sany.log differs from the digest results.json records"),
            ("a SANY failure", lambda: self.rewrite("put", "sany.log", lambda text: text + "*** Errors: 1\n"), 1,
             "put's sany.log records no clean parse of module"),
            ("a fatal SANY error", lambda: self.rewrite("put", "sany.log", lambda text: text + "Fatal errors while parsing\n"), 1,
             "put's sany.log records no clean parse of module"),
            ("a parse of another module", lambda: self.rewrite("put", "sany.log", lambda text: text.replace(
                f"module {CASES['put'].module}", "module Other")), 1, "put's sany.log records no clean parse of module"),
            ("a log without the declared outcome", lambda: self.rewrite("put", "tlc.log", lambda text: text.replace(
                CASES["put"].expected, "Error: Invariant TypeOK is violated.")), 1,
             "put's tlc.log records outcomes ['Error: Invariant TypeOK is violated.'], declared"),
            ("a passing log without coverage", lambda: self.rewrite("put", "tlc.log", lambda text: "".join(
                line for line in text.splitlines(True) if not line.startswith("<"))), 1, "put's tlc.log records no coverage for"),
            ("a log disagreeing with the result's states", lambda: self.rewrite("put", "tlc.log", lambda text: text.replace(
                f"{PUT} distinct", f"{PUT + 2} distinct")), 1,
             f"put's tlc.log records states ['{PUT + 3}', '{PUT + 2}'], results.json ['{PUT + 3}', '{PUT}']"),
            ("an expected violation whose log passes", lambda: self.rewrite(violating, "tlc.log", lambda text: text.replace(
                CASES[violating].expected, "Model checking completed. No error has been found.")), 1,
             f"{violating}'s tlc.log records outcomes ['Model checking completed. No error has been found.'], declared"),
            ("an expected violation whose log also passes", lambda: self.rewrite(violating, "tlc.log", lambda text: text.replace(
                CASES[violating].expected, CASES[violating].expected + "\nModel checking completed. No error has been found.")), 1,
             f"{violating}'s tlc.log records outcomes {[CASES[violating].expected, CASES['put'].expected]}, declared"),
            ("a passing log that also reports a violation", lambda: self.rewrite("put", "tlc.log", lambda text: text.replace(
                CASES["put"].expected, "Error: Invariant TypeOK is violated.\n" + CASES["put"].expected)), 1,
             f"put's tlc.log records outcomes {['Error: Invariant TypeOK is violated.', CASES['put'].expected]}, declared"),
            ("a log repeating the declared outcome", lambda: self.rewrite("put", "tlc.log", lambda text: text.replace(
                CASES["put"].expected, CASES["put"].expected + "\n" + CASES["put"].expected)), 1,
             f"put's tlc.log records outcomes {[CASES['put'].expected] * 2}, declared"),
            ("a violation whose log then records a TLC failure", lambda: self.rewrite(violating, "tlc.log", lambda text: text.replace(
                CASES[violating].expected, CASES[violating].expected + "\nError: TLC threw an unexpected exception.")), 1,
             f"{violating}'s tlc.log records outcomes {[CASES[violating].expected, 'Error: TLC threw an unexpected exception.']}"),
            ("a violation whose log then records an invariant TLC cannot evaluate", lambda: self.rewrite(violating, "tlc.log", lambda text: text.replace(
                CASES[violating].expected, CASES[violating].expected + "\n" + FAILURES[3])), 1,
             f"{violating}'s tlc.log records outcomes {[CASES[violating].expected, FAILURES[3]]}, declared"),
            ("a passing log that then records an exhausted heap", lambda: self.rewrite("put", "tlc.log", lambda text: text.replace(
                CASES["put"].expected, CASES["put"].expected + "\n" + FAILURES[1])), 1,
             f"put's tlc.log records outcomes {[CASES['put'].expected, FAILURES[1]]}, declared"),
        ):
            with self.subTest(name):
                self.setUp()
                edit()
                self.refused(code, reason)

    def test_each_case_credits_only_from_its_own_retained_inputs(self):
        """The digests a result records stand only on the modules and the configuration the runner left in the case's
        directory: a missing one, one with other bytes, and a mutation case that retains its committed target are
        refused by name while `results.json` records the expected digests."""
        mutated = "publish-missing-range"
        target = CASES[mutated].target
        self.assertNotEqual(retained_inputs(CASES[mutated])[target], MODELS[target])
        for name, edit, reason in (
            ("a deleted module", lambda: self.inputs["put"].pop("Recovery.tla"), "put retains no Recovery.tla"),
            ("a deleted configuration", lambda: self.inputs["put"].pop("model.cfg"), "put retains no model.cfg"),
            ("a substituted module", lambda: self.inputs["put"].update({"Recovery.tla": b"---- MODULE Recovery ----\n====\n"}),
             "put's retained Recovery.tla differs from the committed model"),
            ("a substituted configuration", lambda: self.inputs["put"].update({"model.cfg": b"SPECIFICATION Spec\n"}),
             "put's retained model.cfg differs from the configuration the runner generates"),
            ("a mutation case retaining its committed target", lambda: self.inputs[mutated].update({target: MODELS[target]}),
             f"{mutated}'s retained {target} differs from the committed model with the case's mutation applied"),
        ):
            with self.subTest(name):
                self.setUp()
                edit()
                self.refused(2, reason)

    def rewrite(self, name, log, change):
        """Changes one case's log and rebinds the result's digest to the changed bytes."""
        self.logs[name][log] = change(self.logs[name][log])
        self.results[name]["logs"][log] = digest(self.logs[name][log])

    def test_a_runner_failure_is_a_mismatch(self):
        self.exit = 1
        self.refused(1, "it refused a case")

    def test_a_report_the_judge_cannot_write_exits_2_without_a_receipt(self):
        self.write()
        report = self.evidence / "report.json"
        report.mkdir()
        self.addCleanup(lambda: report.is_dir() and report.rmdir())
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as stderr:
            code = judge_tlc.main(self.command())
        self.assertEqual(code, 2, stderr.getvalue())
        self.assertTrue(stderr.getvalue().startswith("judge-tlc: "), stderr.getvalue())
        self.assertFalse((self.evidence / "receipt.json").exists())


def declaration(change):
    """A copy of the committed registry with `change` applied to it."""
    declared = copy.deepcopy(EXPECTED)
    change(declared)
    return declared


def replaced(name, **fields):
    """The runner's case list with the fields of case `name` replaced."""
    return [dataclasses.replace(case, **fields) if case.name == name else case for case in CHECK.cases()]


class StaticContract(unittest.TestCase):
    """The static contract over the committed tree, and one control per rule: each changes one input, the registry,
    the runner's case list or the source directory, and the rule it plants against refuses it as drift by name."""

    def source(self, edits):
        """A copy of the committed models and configurations under a fresh directory, with each file of `edits`
        replaced by what its function returns for the committed text, added when absent, or removed when the
        function returns None."""
        temp = tempfile.TemporaryDirectory(prefix="kestrike-tlc-")
        self.addCleanup(temp.cleanup)
        source = Path(temp.name)
        for path in [*(ROOT / "tla").glob("*.tla"), *(ROOT / "tla").glob("*.cfg")]:
            (source / path.name).write_text(path.read_text())
        for name, edit in edits.items():
            path = source / name
            text = edit(path.read_text() if path.exists() else "")
            if text is None:
                path.unlink()
            else:
                path.write_text(text)
        return source

    def refused(self, text, declared=EXPECTED, cases=None, source=ROOT / "tla"):
        with self.assertRaises(judge_tlc.Refusal) as caught:
            judge_tlc.profile_cases(declared, "pr", cases=cases, source=source)
        self.assertEqual(caught.exception.code, 2)
        self.assertIn(text, str(caught.exception))

    def unpinned(self, text, cases=None, source=ROOT / "tla"):
        """The static contract without the checks of the `cases` map, as `pins` applies it, refuses by `text`."""
        with self.assertRaises(judge_tlc.Refusal) as caught:
            judge_tlc.static_contract(CHECK, EXPECTED, list(CHECK.cases() if cases is None else cases), source, pinned=False)
        self.assertEqual(caught.exception.code, 2)
        self.assertIn(text, str(caught.exception))

    def test_the_committed_tree_meets_the_contract_with_every_kill_case(self):
        """The committed registry, cases and models pass, and the kill rules cover all 51 kill cases, the identity
        cases `admit-over-put-cap` and `admit-over-peer-put-cap`, which kill `PutCaps`, and
        `replay-without-watermark`, `replay-without-epoch` and `result-after-replacement`, which kill
        `ResultHasAdmission`, among them."""
        basis = judge_tlc.static_contract(CHECK, EXPECTED, list(CHECK.cases()), ROOT / "tla")
        self.assertEqual(len(basis), 51)
        self.assertEqual(basis["admit-over-share"], {"baseline": "identity-share-of-one", "mutated": ["Admit", "Refuse"]})
        self.assertEqual(basis["admit-over-put-cap"], {"baseline": "identity-put-caps", "mutated": ["Admit", "Refuse"]})
        self.assertEqual(basis["admit-over-peer-put-cap"], {"baseline": "identity-peer-put-cap", "mutated": ["Admit", "Refuse"]})
        self.assertEqual(basis["replay-without-watermark"], {"baseline": "identity", "mutated": ["Replay"]})
        self.assertEqual(basis["replay-without-epoch"], {"baseline": "identity", "mutated": ["Conflict", "Replay", "UnknownAnswer"]})
        self.assertEqual(basis["result-after-replacement"], {"baseline": "identity", "mutated": ["End"]})
        self.assertEqual(EXPECTED["uncontrolled"]["Identity.tla"], [])
        self.assertEqual(sorted(judge_tlc.profile_cases(EXPECTED, "pr")), sorted(CASES))

    def test_each_registry_control_is_refused_by_its_rule(self):
        """Planted in the registry: an entry removed, a stray entry, one outcome changed, one invariant dropped
        from an entry, `put`'s invariants and `live-drain`'s properties reversed, an empty `properties` list and a
        stray member on `identity`, a completing entry without its count, a violation entry with one, `put`'s
        count as null, a Boolean, a float, zero, a negative number and a fraction, `untyped-read-version` removed
        from `type_kills`, Lifecycle's `uncontrolled` list short by `HeaderLast`, Identity's empty `uncontrolled` list
        given a stale `PutCaps`, an `uncontrolled` list for
        `LifecycleMC.tla`, which defines no `Safety`, Lifecycle's `uncontrolled` list reversed, Recovery's `models`
        list reversed, `put` left out of the `pr` profile, `profiles` removed or a list, `cases` null or a list of
        the names, the first case's entry null or a list, Recovery's `models` value null, an empty `models` list for
        `LifecycleMC.tla`, and `models`, `uncontrolled` and `type_kills` each removed or of another JSON type."""
        cases = EXPECTED["cases"]
        for name, change, refusal in (
            ("an entry removed", lambda d: d["cases"].pop("put"), "the registry's cases omit ['put'] and add []"),
            ("a stray entry", lambda d: d["cases"].update(stray=cases["put"]), "the registry's cases omit [] and add ['stray']"),
            ("an outcome changed", lambda d: d["cases"]["NoPublication"].update(outcome=CHECK.violation("NoFailure")),
             "NoPublication: the registry declares outcome 'Error: Invariant NoFailure is violated.'"),
            ("an invariant dropped", lambda d: d["cases"]["put"].update(invariants=["TypeOK"]),
             "put: the registry's lists ['TypeOK'] and ['ClosedIsFinal'] differ from the generated configuration's"),
            ("invariants in another order", lambda d: d["cases"]["put"]["invariants"].reverse(),
             "put: the registry's lists ['Safety', 'TypeOK'] and ['ClosedIsFinal'] differ from the generated configuration's ['TypeOK', 'Safety']"),
            ("properties in another order", lambda d: d["cases"]["live-drain"]["properties"].reverse(),
             "live-drain: the registry's lists ['TypeOK', 'Safety'] and ['Releases', 'ReadDrains', 'Drains', 'Decides', 'ClosedIsFinal'] differ"),
            ("an empty properties list", lambda d: d["cases"]["identity"].update(properties=[]),
             "identity: the registry's entry holds the members ['invariants', 'outcome', 'properties'], the generated configuration's ['invariants', 'outcome']"),
            ("a stray member", lambda d: d["cases"]["identity"].update(note="x"),
             "identity: the registry's entry holds the members ['invariants', 'note', 'outcome'], the generated configuration's ['invariants', 'outcome']"),
            ("a completing entry without a count", lambda d: d["cases"]["put"].pop("distinct"),
             "put: the registry pins no count on a case that completes"),
            *((f"a count of {count!r}", lambda d, count=count: d["cases"]["put"].update(distinct=count),
               f"put: the registry pins the count {count!r}, not a positive integer")
              for count in (None, True, float(PUT), 0, -PUT, PUT + 0.5)),
            ("a violation entry with a count", lambda d: d["cases"]["NoPublication"].update(distinct=7),
             "NoPublication: the registry pins a count on a violation"),
            ("a TypeOK kill left out", lambda d: d["type_kills"].clear(),
             "the registry's type_kills [] differ from the mutation cases TypeOK kills, ['untyped-read-version']"),
            ("an uncontrolled list short by one", lambda d: d["uncontrolled"]["Lifecycle.tla"].remove("HeaderLast"),
             "the registry's uncontrolled list for Lifecycle.tla is ['SupplyAfterReady']; no mutation case kills ['SupplyAfterReady', 'HeaderLast']"),
            ("a stale entry on an empty uncontrolled list", lambda d: d["uncontrolled"]["Identity.tla"].append("PutCaps"),
             "the registry's uncontrolled list for Identity.tla is ['PutCaps']; no mutation case kills []"),
            ("an uncontrolled list of a model without Safety", lambda d: d["uncontrolled"].update({"LifecycleMC.tla": []}),
             "the registry's uncontrolled lists name ['Identity.tla', 'Lifecycle.tla', 'LifecycleMC.tla', 'Recovery.tla']"),
            ("an uncontrolled list in another order", lambda d: d["uncontrolled"]["Lifecycle.tla"].reverse(),
             "the registry's uncontrolled list for Lifecycle.tla is ['HeaderLast', 'SupplyAfterReady']"),
            ("Safety conjuncts in another order", lambda d: d["models"]["Recovery.tla"].reverse(),
             "the registry's models for Recovery.tla omit the Safety conjuncts [] and add [] in another order"),
            ("a profile list short by one", lambda d: d["profiles"]["pr"].remove("put"),
             "profile pr declares [] the runner lacks and omits ['put']"),
            ("profiles removed", lambda d: d.pop("profiles"), "the registry's profiles is None, not a JSON object"),
            ("profiles as a list", lambda d: d.update(profiles=[]), "the registry's profiles is [], not a JSON object"),
            ("cases as null", lambda d: d.update(cases=None), "the registry's cases is None, not a JSON object"),
            ("cases as a list of the names", lambda d: d.update(cases=sorted(d["cases"])), "the registry's cases is ["),
            ("an entry as null", lambda d: d["cases"].update({CHECK_FIRST: None}), f"{CHECK_FIRST}: the registry's entry None is no JSON object"),
            ("an entry as a list", lambda d: d["cases"].update({CHECK_FIRST: []}), f"{CHECK_FIRST}: the registry's entry [] is no JSON object"),
            ("a models value as null", lambda d: d["models"].update({"Recovery.tla": None}), "hold a value that is no JSON list"),
            ("a models list of a model without Safety", lambda d: d["models"].update({"LifecycleMC.tla": []}),
             "the registry's models name ['Identity.tla', 'Lifecycle.tla', 'LifecycleMC.tla', 'Recovery.tla']"),
            *((f"{section} {how}", lambda d, section=section, value=value: d.update({section: value}) if value != "absent" else d.pop(section),
               f"the registry's {section} is")
              for section, other in (("models", []), ("uncontrolled", []), ("type_kills", {}))
              for how, value in (("removed", "absent"), ("of another type", other))),
        ):
            with self.subTest(name):
                self.refused(refusal, declared=declaration(change))

    def test_each_source_control_is_refused_by_its_rule(self):
        """Planted in the source directory: a `.cfg` no case uses, `Lifecycle.cfg` checking `TypeOK` alone,
        `Recovery.cfg` opening with a word before any keyword, Identity's `Safety` without `PutCaps`, `Capacity`
        defined in `IdentityMC.tla` in place of its target, Lifecycle's `Spec` with a fairness conjunct,
        Identity's `Next` renamed, a definition with an operator parameter and one with a function domain in
        `Identity.tla`, forms the definition reader does not parse, an indented definition and a second definition
        on one line, which would fold into the definition above them, `Lifecycle.cfg` removed and `Recovery.tla`
        removed, a directory named `Extra.tla`, `Lifecycle.cfg` selecting `FairSpec`, assigning `Safety`, or with an
        indented `CONSTRAINTS` statement, `Recovery.cfg` with an unterminated string, a string value before an
        assignment of `Capacity` in `Identity.cfg` and before a substitution the killing property reads in
        `Lifecycle.cfg`, `Capacity` defined after the end of `Identity.tla` and before its header, where SANY reads
        neither, and a name defined twice."""
        capacity = "Capacity == Cardinality(Live) <= Table /\\ \\A p \\in Peers : Cardinality(Held(p)) <= Share\n"
        for name, edits, refusal in (
            ("a .cfg no case uses", {"Extra.cfg": lambda _: (ROOT / "tla/Lifecycle.cfg").read_text()},
             "Extra.cfg is the base of no case"),
            ("a .cfg that drops an invariant", {"Lifecycle.cfg": lambda text: text.replace("INVARIANTS TypeOK Safety", "INVARIANTS TypeOK")},
             "put: the registry's lists ['TypeOK', 'Safety'] and ['ClosedIsFinal'] differ from the generated configuration's ['TypeOK'] and ['ClosedIsFinal']"),
            ("a configuration word before any keyword", {"Recovery.cfg": lambda text: "Stray\n" + text},
             "configuration text 'Stray' precedes every keyword"),
            ("a Safety body without one name", {"Identity.tla": lambda text: text.replace(" /\\ PutCaps /\\", " /\\")},
             "the registry's models for Identity.tla omit the Safety conjuncts [] and add ['PutCaps']"),
            ("a killing property outside the target", {"Identity.tla": lambda text: text.replace(capacity, ""),
                                                       "IdentityMC.tla": lambda text: text.replace("====", capacity + "====", 1)},
             "admit-over-share: Identity.tla does not define Capacity"),
            ("a specification other than Init and Next", {"Lifecycle.tla": lambda text: text.replace(
                "Spec == Init /\\ [][Next]_vars", "Spec == Init /\\ [][Next]_vars /\\ WF_vars(Next)")},
             "chunk-after-done: the specification Spec is not Init /\\ [][Next]_vars of Lifecycle.tla"),
            ("a target without Next", {"Identity.tla": lambda text: text.replace("\nNext ==", "\nStep ==")},
             "admit-busy-slot: Identity.tla does not define Next"),
            ("a definition the reader cannot parse", {"Identity.tla": lambda text: text.replace("\nInit ==", "\nApply(F(_)) == F(1)\nInit ==")},
             "module line 'Apply(F(_)) == F(1)' opens no definition the reader knows"),
            ("a function definition", {"Identity.tla": lambda text: text.replace("\nInit ==", "\nF[x \\in Peers] == x\nInit ==")},
             "module line 'F[x \\\\in Peers] == x' opens no definition the reader knows"),
            ("an indented definition", {"Identity.tla": lambda text: text.replace("\nInit ==", "\nOne == 1\n  Two == 2\nInit ==")},
             "the span of module line 'One == 1' holds a definition outside a LET"),
            ("two definitions on one line", {"Identity.tla": lambda text: text.replace("\nInit ==", "\nOne == 1 Two == 2\nInit ==")},
             "the span of module line 'One == 1 Two == 2' holds a definition outside a LET"),
            ("a base removed", {"Lifecycle.cfg": lambda _: None}, "put: the source holds no Lifecycle.cfg"),
            ("a mutation target removed", {"Recovery.tla": lambda _: None},
             "successor-before-exclusion: the source holds no Recovery.tla"),
            ("a configuration selecting another specification", {"Lifecycle.cfg": lambda text: text.replace(
                "SPECIFICATION Spec", "SPECIFICATION FairSpec")},
             "put: the configuration selects ['SPECIFICATION FairSpec'], not SPECIFICATION Spec alone"),
            ("a configuration overriding a definition", {"Lifecycle.cfg": lambda text: text.replace(
                "    Get = FALSE\n", "    Get = FALSE\n    Safety = TRUE\n")},
             "chunk-after-done: the configuration overrides ['Safety'], which Lifecycle.tla defines"),
            ("an indented plural constraint", {"Lifecycle.cfg": lambda text: text + "  CONSTRAINTS Bound\n"},
             "put: search pruning, a view or a deadlock override is not allowed: ['CONSTRAINTS']"),
            ("an unterminated string", {"Recovery.cfg": lambda text: text + 'CONSTANT Label = "open\n'},
             "recovery: the configuration from Recovery.cfg: configuration text"),
            ("a substitution of a definition", {"Lifecycle.cfg": lambda text: text.replace(
                "    Cover <- OneRange\n", "    Cover <- OneRange\n    Safety <- OneRange\n")},
             "chunk-after-done: the configuration overrides ['Safety'], which Lifecycle.tla defines"),
            ("a parameterized assignment of a definition", {"Identity.cfg": lambda text: text.replace(
                "    Linger = 1\n", "    Linger = 1\n    Held(1) = {}\n")},
             "admit-busy-slot: the configuration overrides ['Held'], which Identity.tla defines"),
            ("a substitution the killing property reads", {"Lifecycle.cfg": lambda text: text.replace(
                "    Chunks = 2\n", "    Chunks <- RAdmit\n")},
             "untyped-read-version: the mutation edits RAdmit, which its killing property TypeOK references"),
            ("a constraint after a closing brace", {"Lifecycle.cfg": lambda text: text.replace(
                "    Ranges = {0, 1}\n", "    Ranges = {0, 1}CONSTRAINT Bound\n")},
             "put: search pruning, a view or a deadlock override is not allowed: ['CONSTRAINT']"),
            ("a keyword where a value stands", {"Lifecycle.cfg": lambda text: text.replace(
                "    Get = FALSE\n", "    Get = ALIAS Safety <- Weak\n")},
             "configuration keyword ALIAS stands where = needs a value"),
            ("an indented symmetry statement", {"Lifecycle.cfg": lambda text: text + "  SYMMETRY Perms\n"},
             "put: the configuration holds a SYMMETRY statement the case does not declare"),
            ("an indented definition after a closed LET", {"Identity.tla": lambda text: text.replace(
                "\nInit ==", "\nOne == LET x == 1 IN x\n  Two == 2\nInit ==")},
             "the span of module line 'One == LET x == 1 IN x' holds a definition outside a LET"),
            ("an indented definition under VARIABLES", {"Identity.tla": lambda text: text.replace(
                "\nvars ==", "\n    Helper == 1\nvars ==")},
             "Identity.tla: the span of module line 'VARIABLES' holds a definition outside a LET"),
            ("a quoted LET before an indented definition", {"Identity.tla": lambda text: text.replace(
                "\nInit ==", '\nOne == "LET \\" x"\n  Two == 2\nInit ==')},
             "the span of module line 'One == \"LET \\\\\" x\"' holds a definition outside a LET"),
            ("a local definition at column 0", {"Identity.tla": lambda text: text.replace(
                "\nInit ==", "\nOne == LET\nx == 1\n  IN x\nInit ==")},
             "the span of module line 'One == LET' leaves a LET open"),
            ("text before the first line at column 0", {"Identity.tla": lambda text: "  Lead == 1\n" + text},
             "Identity.tla: module text 'Lead' precedes its first line at column 0"),
            ("an instance in the target", {"Identity.tla": lambda text: text.replace(
                "\nInit ==", "\nI == INSTANCE Naturals\nInit ==")},
             "admit-busy-slot: Identity.tla instantiates a module"),
            ("an assignment of a definition after a string value", {"Identity.cfg": lambda text: text.replace(
                "    Linger = 1\n", '    Linger = 1\n    Label = "x"\n    Capacity = TRUE\n')},
             "admit-busy-slot: the configuration overrides ['Capacity'], which Identity.tla defines"),
            ("a substitution the killing property reads after a string value", {"Lifecycle.cfg": lambda text: text.replace(
                "    Chunks = 2\n", '    Label = "x"\n    Chunks <- RAdmit\n')},
             "untyped-read-version: the mutation edits RAdmit, which its killing property TypeOK references"),
            ("a definition after the module's end", {"Identity.tla": lambda text: text + "Capacity == TRUE\n"},
             "Identity.tla: module text 'Capacity' follows the end of its module"),
            ("a definition before the module's header", {"Identity.tla": lambda text: "Capacity == TRUE\n" + text},
             "Identity.tla: module line 'Capacity == TRUE' precedes the module header"),
            ("a definition named twice", {"Identity.tla": lambda text: text.replace("\nInit ==", "\nOne == 1\nOne == 2\nInit ==")},
             "Identity.tla: the module defines One twice"),
        ):
            with self.subTest(name):
                source = self.source(edits)
                if any(not (source / file).exists() for file in edits):
                    self.assertEqual([(source / file).exists() for file in edits], [False] * len(edits))
                    self.refused(refusal, source=source)
                    self.unpinned(refusal, source=source)
                    continue
                self.assertNotEqual([(source / file).read_text() for file in edits],
                                    [(ROOT / "tla" / file).read_text() if (ROOT / "tla" / file).exists() else "" for file in edits])
                self.refused(refusal, source=source)

    def test_a_module_the_reader_cannot_read_is_drift(self):
        """A directory named `Extra.tla` beside the committed models is drift that names the error."""
        source = self.source({})
        (source / "Extra.tla").mkdir()
        self.refused("Is a directory", source=source)

    def test_a_string_holding_keywords_keeps_its_definition_whole(self):
        """Strings holding `==`, `IN` and an escaped quote beside a real `LET` stay inside their definition, and an
        `ASSUME` whose string holds `) ==` is a module line, not a definition."""
        found = CHECK.definitions('---- MODULE M ----\nA == LET x == "==" IN x \\o "IN \\" =="\nB == 2\n====\n')
        self.assertEqual(sorted(found), ["A", "B"])
        found = CHECK.definitions('---- MODULE M ----\nASSUME ("x) ==" = "y")\nB == 2\n====\n')
        self.assertEqual(sorted(found), ["B"])

    def test_the_reader_takes_the_text_from_the_header_to_the_end_of_the_module(self):
        """The module runs from its header to the first run of four `=` after it, at any column and outside
        comments and strings. Comments and blank lines around it are read as empty; a definition after the end, a
        module without a header or an end, and a name defined twice are refused."""
        for name, module in (
            ("comments around the module", "\\* lead\n(* block *)\n---- MODULE M ----\nA == 1\n====\n\\* history\n(* B == 2 *)\n\n"),
            ("an indented end", "---- MODULE M ----\nA == 1\n  ====\n"),
            ("a run of four = in a string and in a comment", '---- MODULE M ----\nA == "====" \\* ====\n====\n'),
        ):
            with self.subTest(name):
                self.assertEqual(sorted(CHECK.definitions(module)), ["A"])
        for name, module, refusal in (
            ("a definition after an indented end", "---- MODULE M ----\nA == 1\n  ====\nA == 2\n", "module text 'A' follows the end of its module"),
            ("text on the line of the end", "---- MODULE M ----\nA == 1\n==== B == 2\n", "module text 'B' follows the end of its module"),
            ("a second end", "---- MODULE M ----\nA == 1\n====\n====\n", "module text '====' follows the end of its module"),
            ("no header", "A == 1\n====\n", "module line 'A == 1' precedes the module header"),
            ("a separator in place of the header", "----\nA == 1\n====\n", "module line '----' precedes the module header"),
            ("no end", "---- MODULE M ----\nA == 1\n", "the module has no end"),
            ("a name defined twice", "---- MODULE M ----\nA == 1\nB == 2\nA == 3\n====\n", "the module defines A twice"),
            ("a wrapped name before the end", "---- MODULE M ----\nA == 1 /\\\nB\n====\n", "module line 'B' opens no definition"),
            ("a wrapped call before the end", "---- MODULE M ----\nA == 1 /\\\nIsFiniteSet(B)\n====\n",
             "module line 'IsFiniteSet(B)' opens no definition"),
        ):
            with self.subTest(name):
                with self.assertRaises(ValueError) as caught:
                    CHECK.definitions(module)
                self.assertIn(refusal, str(caught.exception))
        with self.assertRaises(ValueError) as caught:
            CHECK.safety("---- MODULE M ----\nA == 1\nSafety == A\n====\nSafety == B\n")
        self.assertIn("module text 'Safety' follows the end of its module", str(caught.exception))

    def test_each_case_list_control_is_refused_by_its_rule(self):
        """Planted in the runner's case list: `publish-missing-range` at `Window = 2`, under symmetry and with an extra
        constant statement, `put` moved to the scheduled tier and given a mutation, `admit-over-share`'s anchor moved
        into its killing property `Capacity`, across `Live` and `Held`, and into `Free`, which `Init` reaches,
        `publish-without-evidence`'s anchor moved into `Holds`, which `AdmissionNeedsEvidence` reaches through
        `Durable`, an anchor that occurs twice, a replacement that adds a definition, `put` named twice,
        `publish-missing-range` under `FairSpec` at `live-publish`'s settings and with a `VIEW` statement,
        `admit-over-share`'s anchor moved into the module header, a replacement that adds a conjunct to `Fresh`,
        a mutation of `Next`, which no action reaches, `result-after-close`'s anchor moved into `vars`, which its
        killing property names as a subscript, `receipt-as-publication`, Lifecycle's one kill of
        `PublishedNeedsResult`, without its mutation while Identity still kills a conjunct of that name, and
        `admit-over-share` in the tier `nightly`, which no profile runs, so no lane would run the one kill of
        `Capacity`."""
        mutant = CASES["admit-over-share"].mutation[1]
        for name, cases, refusal in (
            ("settings no passing case has", replaced("publish-missing-range", settings={"Window": "2"}),
             "publish-missing-range has no passing baseline that checks PublishedComplete"),
            ("a baseline under other symmetry", replaced("publish-missing-range", symmetry=True),
             "publish-missing-range has no passing baseline that checks PublishedComplete"),
            ("a baseline of another configuration", replaced("publish-missing-range", extra="CONSTANT Cover <- EachRange\n"),
             "publish-missing-range has no passing baseline that checks PublishedComplete"),
            ("a baseline in a tier the profile does not run", replaced("put", tier="scheduled"),
             "data-after-end has no passing baseline that checks NoDataAfterEnd"),
            ("a baseline with a mutation", replaced("put", mutation=("TypeOK ==", "TypeOK ==")),
             "data-after-end has no passing baseline that checks NoDataAfterEnd"),
            ("an anchor in a definition its killing property reaches through another", replaced(
                "publish-without-evidence", mutation=("Holds(u, r) == per.media[u] = r", "Holds(u, r) == TRUE")),
             "publish-without-evidence: the mutation edits Holds, which its killing property AdmissionNeedsEvidence references"),
            ("an anchor that occurs twice", replaced("admit-over-share", mutation=("Cardinality(Live)", mutant)),
             "admit-over-share: the mutation anchor occurs"),
            ("a mutation that adds a definition", replaced("admit-over-share", mutation=(
                CASES["admit-over-share"].mutation[0], mutant + "\nExtra == TRUE")),
             "admit-over-share: the mutation changes definitions of Identity.tla other than Room"),
            ("an anchor in its killing property", replaced("admit-over-share", mutation=(
                "Capacity == Cardinality(Live) <= Table", "Capacity == TRUE")),
             "admit-over-share: the mutation edits Capacity, which its killing property Capacity references"),
            ("an anchor across two definitions", replaced("admit-over-share", mutation=("# Free}\nHeld(p) ==", mutant)),
             "admit-over-share: the mutation anchor spans the definitions ['Live', 'Held'] of Identity.tla"),
            ("an anchor in a definition Init reaches", replaced("admit-over-share", mutation=('Free == [peer |-> 0, op |-> "none"', 'Free == [peer |-> 1, op |-> "none"')),
             "admit-over-share: the mutation edits Free, which Init reaches"),
            ("a case named twice", [*CHECK.cases(), CASES["put"]], "the runner names the cases ['put'] more than once"),
            ("a specification other than Spec", replaced("publish-missing-range", spec="FairSpec",
                                                         settings={"Deadlines": "FALSE", "WriteFaults": "FALSE"}),
             "publish-missing-range: the specification FairSpec is not Init /\\ [][Next]_vars of Lifecycle.tla"),
            *((f"a {keyword} statement", replaced("publish-missing-range", extra=f"{keyword} vars\n"),
               f"publish-missing-range: search pruning, a view or a deadlock override is not allowed: ['{keyword}']")
              for keyword in ("VIEW", "CONSTRAINT", "ACTION_CONSTRAINT", "ACTION_CONSTRAINTS", "CHECK_DEADLOCK")),
            ("a symmetry statement a liveness case does not declare", replaced("live-publish", extra="SYMMETRY Perms\n"),
             "live-publish: the configuration holds a SYMMETRY statement the case does not declare"),
            ("an anchor in no definition", replaced("admit-over-share", mutation=("MODULE Identity ", "MODULE Identity ")),
             "admit-over-share: the mutation anchor spans the definitions [] of Identity.tla"),
            ("an anchor from a definition into a module line", replaced("admit-over-share", mutation=(
                "tg |-> 0]\n\nVARIABLES\n", "tg |-> 1]\n\nVARIABLES\n")),
             "admit-over-share: the mutation anchor reaches module text of Identity.tla outside Free"),
            ("a replacement that adds a module line", replaced("admit-over-share", mutation=(
                CASES["admit-over-share"].mutation[0], mutant + "\nASSUME TRUE")),
             "admit-over-share: the mutation changes module text of Identity.tla outside its definitions"),
            ("a replacement that changes another definition's body", replaced("admit-over-share", mutation=(
                CASES["admit-over-share"].mutation[0], "    /\\ FALSE\n" + mutant)),
             "admit-over-share: the mutation changes definitions of Identity.tla other than Room"),
            ("a mutation no action reaches", replaced("admit-over-share", mutation=("    \\/ CAttach\n", "    \\/ CAttach \\/ Tick\n")),
             "admit-over-share: no action of Next reaches Next, the definition the mutation edits"),
            ("an anchor in its killing property's subscript", replaced("result-after-close", mutation=(
                "vars == <<c, net, o, ws, dev, stop, store, r>>", "vars == <<c, net, o, ws, dev, stop, r>>")),
             "result-after-close: the mutation edits vars, which its killing property ClosedIsFinal references"),
            ("a conjunct one model's kill leaves uncontrolled", replaced("receipt-as-publication", mutation=None),
             "the registry's uncontrolled list for Lifecycle.tla is ['SupplyAfterReady', 'HeaderLast']; no mutation case kills"),
            ("a kill case in a tier no profile runs", replaced("admit-over-share", tier="nightly"),
             "admit-over-share: no profile runs the tier 'nightly'"),
        ):
            with self.subTest(name):
                self.refused(refusal, cases=cases)
                if name not in ("a conjunct one model's kill leaves uncontrolled",
                                "a symmetry statement a liveness case does not declare"):
                    self.unpinned(refusal, cases=cases)

    def test_each_unpinned_control_is_refused_by_its_rule(self):
        """The static contract as `pins` applies it, without the `cases` map, so a planted case's entry does not refuse
        it first. Planted in the runner's case list: `put` checking `PublishedComplete` alone, `put`
        checking `TypeOK` alone, then also `NoDataAfterEnd` under `PROPERTY` or under `_POSSIBLE`, both outside its
        invariants, and `admit-over-share` declaring the violation of `TypeOK` by the initial state. Planted in the
        source: `Lifecycle.cfg` without `PROPERTY ClosedIsFinal`, and with `ClosedIsFinal` moved among its
        invariants, so no baseline checks `result-after-close`'s action property as a property, and Lifecycle's
        `Safety` and the registry's `models` without `NoDataAfterEnd`, so `put`'s `Safety` no longer holds it."""
        for name, cases, refusal in (
            ("a baseline without the killing property", replaced("put", invariant="PublishedComplete"),
             "data-after-end has no passing baseline that checks NoDataAfterEnd"),
            ("a baseline without the Safety route", replaced("put", invariant="TypeOK"),
             "data-after-end has no passing baseline that checks NoDataAfterEnd"),
            ("a baseline checking an invariant kill's predicate as a property", replaced(
                "put", invariant="TypeOK", extra="PROPERTY NoDataAfterEnd\n"),
             "data-after-end has no passing baseline that checks NoDataAfterEnd"),
            ("a baseline naming the predicate under another keyword", replaced(
                "put", invariant="TypeOK", extra="_POSSIBLE NoDataAfterEnd\n"),
             "data-after-end has no passing baseline that checks NoDataAfterEnd"),
            ("an initial-state violation", replaced(
                "admit-over-share", expected="Error: Invariant TypeOK is violated by the initial state:"),
             "admit-over-share: the kill rules read no violated property in the outcome"),
        ):
            with self.subTest(name):
                self.unpinned(refusal, cases=cases)
        lifecycle = (ROOT / "tla/Lifecycle.cfg").read_text()
        for name, config in (
                ("no action property", lifecycle.replace("PROPERTY ClosedIsFinal\n", "")),
                ("the action property among the invariants", lifecycle.replace(
                    "PROPERTY ClosedIsFinal\nINVARIANTS TypeOK Safety", "INVARIANTS TypeOK Safety ClosedIsFinal"))):
            with self.subTest(name):
                self.assertNotEqual(config, lifecycle)
                self.unpinned("result-after-close has no passing baseline that checks ClosedIsFinal at its module",
                              source=self.source({"Lifecycle.cfg": lambda _, config=config: config}))
        with self.subTest("a predicate outside the target's Safety"):
            source = self.source({"Lifecycle.tla": lambda text: text.replace("/\\ SourceCustody /\\ NoDataAfterEnd", "/\\ SourceCustody")})
            declared = declaration(lambda d: d["models"]["Lifecycle.tla"].remove("NoDataAfterEnd"))
            with self.assertRaises(judge_tlc.Refusal) as caught:
                judge_tlc.static_contract(CHECK, declared, list(CHECK.cases()), source, pinned=False)
            self.assertIn("data-after-end has no passing baseline that checks NoDataAfterEnd", str(caught.exception))

    def test_a_registry_that_names_a_case_twice_is_unreadable(self):
        """Planted: the registry text with the `put` entry repeated; the judge reads no registry from it."""
        text = judge_tlc.EXPECTED.read_text()
        line = next(line for line in text.splitlines() if line.startswith('    "put": '))
        temp = tempfile.TemporaryDirectory(prefix="kestrike-tlc-")
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / "expected.json"
        path.write_text(text.replace(line, f"{line.rstrip(',')},\n{line}", 1))
        with self.assertRaises(judge_tlc.Refusal) as caught:
            judge_tlc.read_json(path)
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("the object repeats ['put']", str(caught.exception))

    def test_references_follow_every_identifier_through_definitions(self):
        """A name after a backslash operator written without spaces is a reference, and a reference two definitions
        away is reached."""
        found = CHECK.definitions("---- MODULE M ----\nA == B\\C\nB == {}\nC == D\nD == 1\nE == 2\n====\n")
        self.assertEqual(CHECK.reached(found, "A"), {"A", "B", "C", "D"})

    def test_a_subscript_names_its_definition(self):
        """The subscript of an action property, of an angle-bracket action and of weak and strict fairness names the
        definition, beside whole names that hold an underscore; `ClosedIsFinal` reaches Lifecycle's `vars`."""
        for body in ("[][x' = x]_v", "<<x' = x>>_v", "WF_v(A)", "SF_v(A)", "my_v"):
            with self.subTest(body):
                found = CHECK.definitions(f"---- MODULE M ----\nP == {body}\nv == <<x>>\nA == x' = x\nmy_v == 1\n====\n")
                self.assertIn("v", CHECK.reached(found, "P"))
        found = CHECK.definitions("---- MODULE M ----\nP == my_v\nmy_v == 1\n====\n")
        self.assertEqual(CHECK.reached(found, "P"), {"P", "my_v"})
        lifecycle = CHECK.definitions((ROOT / "tla/Lifecycle.tla").read_text())
        self.assertIn("vars", CHECK.reached(lifecycle, "ClosedIsFinal"))

    def test_local_definitions_stay_inside_their_definition(self):
        """A `LET` on one line, across lines and nested keeps its definitions in the body of the definition that holds
        it."""
        for body in ("LET x == 1 IN x", "\n    LET x == 1\n        y == 2\n    IN x + y", "LET x == LET y == 1 IN y IN x"):
            with self.subTest(body):
                found = CHECK.definitions(f"---- MODULE M ----\nA == {body}\nB == 2\n====\n")
                self.assertEqual(sorted(found), ["A", "B"])

    def test_the_safety_reader_takes_both_layouts_and_bare_names_only(self):
        module = "---- MODULE M ----\nA == 1\nB == 2\nC == 3\n{}====\n"
        for name, body, conjuncts in (
            ("one line", "Safety == A /\\ B /\\ C\n", ["A", "B", "C"]),
            ("one line continued", "Safety == A /\\ B\n          /\\ C\n", ["A", "B", "C"]),
            ("bulleted, with comments", "Safety ==\n    /\\ A \\* first\n    /\\ (* second *) B /\\ C\n", ["A", "B", "C"]),
            ("no Safety", "", None),
        ):
            with self.subTest(name):
                self.assertEqual(CHECK.safety(module.format(body)), conjuncts)
        for body in ("Safety == A /\\ (B \\/ C)\n", "Safety == A /\\ B'\n", "Safety == A /\\\n"):
            with self.subTest(body):
                with self.assertRaisesRegex(ValueError, "is not a bare definition name"):
                    CHECK.safety(module.format(body))


# Excerpts cut from the `tlc.log` files of one `pr` run of the lane with the pinned tools at eight workers.
# Shape 1, `identity-peer-put-cap`: one report a minute, ended by `End of statistics.` and by the longer
# line of a large model, with progress lines between reports. The excerpt ends inside the next report, which the
# log completes: that cut-short report is a planted edit.
SHAPE_REPORTS = (
    'Progress(13) at 2026-11-20 08:18:21: 14,957,466 states generated (14,492,585 s/min), 2,160,477 distinct states found (2,072,895 ds/min), 945,610 states left on queue.' "\n"
    'The coverage statistics at 2026-11-20 08:18:21 (see https://explain.tlapl.us/module-coverage-statistics for how to interpret the following statistics).' "\n"
    '<UAbandon line 293, col 1 to line 293, col 8 of module Identity>: 51019:279932' "\n"
    '  line 294, col 8 to line 294, col 33 of module Identity: 1495918' "\n"
    '  |line 294, col 8 to line 294, col 21 of module Identity: 1215986' "\n"
    '  line 294, col 38 to line 294, col 54 of module Identity: 684991' "\n"
    '  |line 294, col 39 to line 294, col 54 of module Identity: 405059' "\n"
    'End of statistics.' "\n"
    'Progress(16) at 2026-11-20 08:21:21: 55,572,434 states generated (12,974,854 s/min), 7,243,587 distinct states found (1,573,954 ds/min), 2,066,530 states left on queue.' "\n"
    'Progress(17) at 2026-11-20 08:22:21: 68,693,451 states generated (13,121,017 s/min), 8,640,737 distinct states found (1,397,150 ds/min), 2,067,767 states left on queue.' "\n"
    'The coverage statistics at 2026-11-20 08:22:21 (see https://explain.tlapl.us/module-coverage-statistics for how to interpret the following statistics).' "\n"
    '<UAbandon line 293, col 1 to line 293, col 8 of module Identity>: 259353:1904572' "\n"
    '  line 294, col 8 to line 294, col 33 of module Identity: 8477662' "\n"
    '  |line 294, col 8 to line 294, col 21 of module Identity: 6573090' "\n"
    '  line 294, col 38 to line 294, col 54 of module Identity: 5108052' "\n"
    '  |line 294, col 39 to line 294, col 54 of module Identity: 3203480' "\n"
    'End of statistics (please note that for performance reasons large models' "\n"
    'are best checked with coverage and cost statistics disabled).' "\n"
    'Progress(17) at 2026-11-20 08:23:21: 81,214,080 states generated (12,520,629 s/min), 10,019,940 distinct states found (1,379,203 ds/min), 2,012,613 states left on queue.' "\n"
    'Progress(18) at 2026-11-20 08:24:21: 92,939,935 states generated (11,725,855 s/min), 11,224,478 distinct states found (1,204,538 ds/min), 1,666,752 states left on queue.' "\n"
    'The coverage statistics at 2026-11-20 08:24:21 (see https://explain.tlapl.us/module-coverage-statistics for how to interpret the following statistics).' "\n"
    '<UAbandon line 293, col 1 to line 293, col 8 of module Identity>: 344937:2780919' "\n"
    '  line 294, col 8 to line 294, col 33 of module Identity: 12338734' "\n"
    '  |line 294, col 8 to line 294, col 21 of module Identity: 9557815' "\n"
)
# Shape 2, `identity-mismatch`: the two guarded `URetry` disjuncts of `Next`, located headers of one operator;
# the first ran and the second did not.
SHAPE_LOCATED = (
    '<Next line 368, col 1 to line 368, col 4 of module Identity (376 28 376 55)>: 1124:37980' "\n"
    '  line 376, col 28 to line 376, col 35 of module Identity: 37980' "\n"
    '  line 256, col 8 to line 256, col 22 of module Identity: 282810' "\n"
    '  |line 256, col 8 to line 256, col 18 of module Identity: 244830' "\n"
    '  line 256, col 27 to line 256, col 64 of module Identity: 275580' "\n"
    '  |line 256, col 27 to line 256, col 40 of module Identity: 237600' "\n"
    '  |line 256, col 46 to line 256, col 64 of module Identity: 237600' "\n"
    '  line 256, col 69 to line 256, col 85 of module Identity: 201600' "\n"
    '  |line 256, col 70 to line 256, col 85 of module Identity: 163620' "\n"
    '  line 259, col 9 to line 259, col 20 of module Identity: 140580' "\n"
    '  |line 259, col 9 to line 259, col 9 of module Identity: 102600' "\n"
    '  |line 259, col 18 to line 259, col 20 of module Identity: 102600' "\n"
    '  line 74, col 12 to line 74, col 30 of module Identity: 37980' "\n"
    '  |line 74, col 19 to line 74, col 30 of module Identity: 37980' "\n"
    '  ||line 74, col 19 to line 74, col 21 of module Identity: 37980' "\n"
    '  ||line 74, col 28 to line 74, col 30 of module Identity: 37980:84496' "\n"
    '  |||line 74, col 29 to line 74, col 29 of module Identity: 37980' "\n"
    '  line 259, col 30 to line 259, col 30 of module Identity: 37980' "\n"
    '  line 260, col 8 to line 260, col 42 of module Identity: 37980' "\n"
    '<Next line 368, col 1 to line 368, col 4 of module Identity (376 62 376 88)>: 0:0' "\n"
    '  line 74, col 12 to line 74, col 30 of module Identity: 0' "\n"
    '  line 260, col 8 to line 260, col 42 of module Identity: 0' "\n"
)
# Shape 3, `put`: `SBegin` did not run and lists 255:8-255:41 and 255:46-255:84 apart, each with 0.
SHAPE_SPLIT = (
    '<SBegin line 253, col 1 to line 253, col 6 of module Lifecycle>: 0:0' "\n"
    '  line 254, col 8 to line 254, col 55 of module Lifecycle: 5255' "\n"
    '  line 255, col 8 to line 255, col 41 of module Lifecycle: 0' "\n"
    '  line 255, col 46 to line 255, col 84 of module Lifecycle: 0' "\n"
    '  line 256, col 8 to line 256, col 43 of module Lifecycle: 0' "\n"
    '  line 256, col 48 to line 256, col 83 of module Lifecycle: 0' "\n"
)
# Shape 3, `put-revocation`: `SBegin` ran and lists one span 255:8-255:84 with 7,292.
SHAPE_MERGED = (
    '<SBegin line 253, col 1 to line 253, col 6 of module Lifecycle>: 1431:7292' "\n"
    '  line 254, col 8 to line 254, col 16 of module Lifecycle: 56299' "\n"
    '  |line 254, col 8 to line 254, col 8 of module Lifecycle: 49007' "\n"
    '  line 254, col 21 to line 254, col 35 of module Lifecycle: 51044' "\n"
    '  |line 254, col 21 to line 254, col 26 of module Lifecycle: 43752' "\n"
    '  line 254, col 40 to line 254, col 55 of module Lifecycle: 14584' "\n"
    '  |line 254, col 40 to line 254, col 43 of module Lifecycle: 7292' "\n"
    '  line 255, col 8 to line 255, col 84 of module Lifecycle: 7292' "\n"
    '  line 256, col 8 to line 256, col 43 of module Lifecycle: 7292' "\n"
    '  |line 256, col 15 to line 256, col 43 of module Lifecycle: 7292' "\n"
    '  ||line 256, col 15 to line 256, col 17 of module Lifecycle: 7292' "\n"
    '  ||line 256, col 24 to line 256, col 43 of module Lifecycle: 7292:41862' "\n"
    '  |||line 256, col 25 to line 256, col 42 of module Lifecycle: 7292' "\n"
    '  line 256, col 48 to line 256, col 83 of module Lifecycle: 7292' "\n"
)
# Shape 4, `put-revocation`: `OFail` lists the body of `Fail` (175:8-175:76) once per call, two calls with 0.
SHAPE_HELPER = (
    '<OFail line 222, col 1 to line 222, col 5 of module Lifecycle>: 1926:9989' "\n"
    '  line 223, col 8 to line 223, col 41 of module Lifecycle: 54258' "\n"
    '  |line 223, col 8 to line 223, col 14 of module Lifecycle: 49007' "\n"
    '  |line 223, col 20 to line 223, col 41 of module Lifecycle: 49007' "\n"
    '  line 224, col 11 to line 224, col 34 of module Lifecycle: 8247' "\n"
    '  |line 224, col 11 to line 224, col 26 of module Lifecycle: 5498' "\n"
    '  |line 224, col 32 to line 224, col 34 of module Lifecycle: 5498' "\n"
    '  line 175, col 8 to line 175, col 76 of module Lifecycle: 2749' "\n"
    '  line 53, col 12 to line 53, col 30 of module Lifecycle: 2749' "\n"
    '  |line 53, col 19 to line 53, col 30 of module Lifecycle: 2749' "\n"
    '  ||line 53, col 19 to line 53, col 21 of module Lifecycle: 2749' "\n"
    '  ||line 53, col 28 to line 53, col 30 of module Lifecycle: 2749:5498' "\n"
    '  |||line 53, col 29 to line 53, col 29 of module Lifecycle: 2749' "\n"
    '  line 176, col 13 to line 176, col 38 of module Lifecycle: 2749' "\n"
    '  line 225, col 11 to line 225, col 20 of module Lifecycle: 5498' "\n"
    '  line 175, col 8 to line 175, col 76 of module Lifecycle: 0' "\n"
    '  line 53, col 12 to line 53, col 30 of module Lifecycle: 0' "\n"
    '  line 226, col 29 to line 226, col 47 of module Lifecycle: 13544' "\n"
    '  |line 226, col 29 to line 226, col 36 of module Lifecycle: 10996' "\n"
    '  line 175, col 8 to line 175, col 76 of module Lifecycle: 2548' "\n"
    '  line 53, col 12 to line 53, col 30 of module Lifecycle: 2548' "\n"
    '  |line 53, col 19 to line 53, col 30 of module Lifecycle: 2548' "\n"
    '  ||line 53, col 19 to line 53, col 21 of module Lifecycle: 2548' "\n"
    '  ||line 53, col 28 to line 53, col 30 of module Lifecycle: 2548:5096' "\n"
    '  |||line 53, col 29 to line 53, col 29 of module Lifecycle: 2548' "\n"
    '  line 176, col 13 to line 176, col 38 of module Lifecycle: 2548' "\n"
    '  line 226, col 20 to line 226, col 25 of module Lifecycle: 5498' "\n"
    '  line 227, col 11 to line 227, col 19 of module Lifecycle: 10190' "\n"
    '  |line 227, col 11 to line 227, col 11 of module Lifecycle: 5498' "\n"
    '  line 175, col 8 to line 175, col 76 of module Lifecycle: 4692' "\n"
    '  line 53, col 12 to line 53, col 30 of module Lifecycle: 4692' "\n"
    '  |line 53, col 19 to line 53, col 30 of module Lifecycle: 4692' "\n"
    '  ||line 53, col 19 to line 53, col 21 of module Lifecycle: 4692' "\n"
    '  ||line 53, col 28 to line 53, col 30 of module Lifecycle: 4692:9384' "\n"
    '  |||line 53, col 29 to line 53, col 29 of module Lifecycle: 4692' "\n"
    '  line 176, col 13 to line 176, col 38 of module Lifecycle: 4692' "\n"
    '  line 228, col 11 to line 228, col 16 of module Lifecycle: 5498' "\n"
    '  line 175, col 8 to line 175, col 76 of module Lifecycle: 0' "\n"
    '  line 53, col 12 to line 53, col 30 of module Lifecycle: 0' "\n"
    '  line 170, col 14 to line 170, col 53 of module Lifecycle: 9989' "\n"
)
# `identity-board`'s final report: `CReturnStale` ran and lists 333:27-333:41, `UNCHANGED board`, with 0.
STALE_RAN = (
    '<CReturnStale line 330, col 1 to line 330, col 15 of module Identity>: 333826:2118850' "\n"
    '  line 331, col 8 to line 331, col 26 of module Identity: 2118850' "\n"
    '  |line 331, col 8 to line 331, col 22 of module Identity: 6793990' "\n"
    '  line 332, col 8 to line 332, col 51 of module Identity: 2118850' "\n"
    '  line 333, col 11 to line 333, col 20 of module Identity: 2118850' "\n"
    '  |line 328, col 15 to line 328, col 94 of module Identity: 2118850' "\n"
    '  ||line 328, col 15 to line 328, col 60 of module Identity: 2118850' "\n"
    '  |||line 328, col 15 to line 328, col 28 of module Identity: 2118850' "\n"
    '  |||line 328, col 33 to line 328, col 60 of module Identity: 710840' "\n"
    '  ||line 328, col 65 to line 328, col 94 of module Identity: 464780' "\n"
    '  |line 333, col 19 to line 333, col 19 of module Identity: 2118850' "\n"
    '  line 333, col 27 to line 333, col 41 of module Identity: 0' "\n"
    '  line 333, col 48 to line 333, col 88 of module Identity: 2118850' "\n"
    '  line 334, col 8 to line 334, col 120 of module Identity: 2118850' "\n"
    '  |line 334, col 18 to line 334, col 120 of module Identity: 2118850' "\n"
    '  ||line 334, col 19 to line 334, col 24 of module Identity: 2118850' "\n"
    '  ||line 334, col 46 to line 334, col 119 of module Identity: 2118850' "\n"
    '  |||line 334, col 51 to line 334, col 118 of module Identity: 2118850' "\n"
    '  ||||line 334, col 54 to line 334, col 104 of module Identity: 2118850' "\n"
    '  |||||line 334, col 54 to line 334, col 81 of module Identity: 2118850' "\n"
    '  |||||line 334, col 86 to line 334, col 104 of module Identity: 738180' "\n"
    '  line 335, col 8 to line 335, col 73 of module Identity: 2118850' "\n"
)
# `identity-board`'s final report: `Init`, then `CReturn`, which found no distinct state and generated 1,325,990.
BOARD_INIT_AND_RETURN = (
    '<Init line 77, col 1 to line 77, col 4 of module Identity>: 1:1' "\n"
    '  line 78, col 16 to line 78, col 34 of module Identity: 1:1' "\n"
    '<CReturn line 320, col 1 to line 320, col 10 of module Identity>: 0:1325990' "\n"
    '  line 321, col 8 to line 321, col 27 of module Identity: 1325990' "\n"
)
# `identity-two-slots`'s final report: `CReturnStale` did not run.
STALE_IDLE = (
    '<CReturnStale line 330, col 1 to line 330, col 15 of module Identity>: 0:0' "\n"
    '  line 331, col 8 to line 331, col 26 of module Identity: 6779920' "\n"
    '  line 332, col 8 to line 332, col 51 of module Identity: 0' "\n"
    '  line 333, col 27 to line 333, col 41 of module Identity: 0' "\n"
    '  line 333, col 48 to line 333, col 88 of module Identity: 0' "\n"
    '  line 334, col 8 to line 334, col 120 of module Identity: 0' "\n"
    '  line 335, col 8 to line 335, col 73 of module Identity: 0' "\n"
)

# `identity`'s final report: `WrongOp` ran and lists its call `Count("wrong")` at 183:8-183:21 with 514,380 and no
# line of `Count`'s body, 75:13-75:50.
FOLDED_RAN = (
    '<WrongOp line 179, col 1 to line 179, col 7 of module Identity>: 3582:514380' "\n"
    '  line 181, col 8 to line 181, col 45 of module Identity: 26367910' "\n"
    '  |line 181, col 8 to line 181, col 13 of module Identity: 25978770' "\n"
    '  |line 181, col 19 to line 181, col 45 of module Identity: 25978770' "\n"
    '  line 181, col 50 to line 181, col 72 of module Identity: 11227080' "\n"
    '  |line 181, col 50 to line 181, col 56 of module Identity: 10837940' "\n"
    '  |line 181, col 60 to line 181, col 72 of module Identity: 10837940' "\n"
    '  line 173, col 13 to line 173, col 22 of module Identity: 6299940' "\n"
    '  |line 173, col 13 to line 173, col 18 of module Identity: 5910800' "\n"
    '  |line 173, col 22 to line 173, col 22 of module Identity: 5910800' "\n"
    '  line 182, col 11 to line 182, col 30 of module Identity: 5910800' "\n"
    '  line 182, col 33 to line 182, col 37 of module Identity: 5910800' "\n"
    '  line 175, col 8 to line 175, col 19 of module Identity: 3080380' "\n"
    '  |line 175, col 8 to line 175, col 15 of module Identity: 2913020' "\n"
    '  line 175, col 24 to line 175, col 46 of module Identity: 1306680' "\n"
    '  |line 175, col 24 to line 175, col 41 of module Identity: 1139320' "\n"
    '  |line 175, col 45 to line 175, col 46 of module Identity: 1139320' "\n"
    '  line 176, col 8 to line 176, col 20 of module Identity: 3260040' "\n"
    '  |line 176, col 8 to line 176, col 12 of module Identity: 2913020' "\n"
    '  |line 176, col 16 to line 176, col 20 of module Identity: 2913020' "\n"
    '  line 176, col 25 to line 176, col 37 of module Identity: 3127200' "\n"
    '  |line 176, col 25 to line 176, col 32 of module Identity: 2780180' "\n"
    '  |line 176, col 36 to line 176, col 37 of module Identity: 2780180' "\n"
    '  line 182, col 49 to line 182, col 68 of module Identity: 2913020' "\n"
    '  line 182, col 71 to line 182, col 74 of module Identity: 2913020' "\n"
    '  line 182, col 80 to line 182, col 95 of module Identity: 514380' "\n"
    '  |line 182, col 80 to line 182, col 91 of module Identity: 1028760' "\n"
    '  line 183, col 8 to line 183, col 21 of module Identity: 514380' "\n"
    '  line 184, col 8 to line 184, col 77 of module Identity: 514380' "\n"
    '  line 180, col 14 to line 180, col 16 of module Identity: 5745910' "\n"
)
# `identity`'s final report: `Conflict` did not run and lists `Count`'s body at 75:13-75:50 with 0.
FOLDED_IDLE = (
    '<Conflict line 204, col 1 to line 204, col 8 of module Identity>: 0:0' "\n"
    '  line 192, col 8 to line 192, col 37 of module Identity: 25978770' "\n"
    '  line 192, col 42 to line 192, col 53 of module Identity: 10837940' "\n"
    '  line 192, col 58 to line 192, col 80 of module Identity: 10837940' "\n"
    '  line 193, col 8 to line 193, col 40 of module Identity: 5910800' "\n"
    '  |line 193, col 10 to line 193, col 39 of module Identity: 5910800' "\n"
    '  ||line 193, col 10 to line 193, col 21 of module Identity: 5910800' "\n"
    '  ||line 193, col 26 to line 193, col 39 of module Identity: 2913020' "\n"
    '  |||line 175, col 5 to line 176, col 37 of module Identity: 2913020' "\n"
    '  ||||line 175, col 8 to line 175, col 46 of module Identity: 2913020' "\n"
    '  |||||line 175, col 8 to line 175, col 19 of module Identity: 2913020' "\n"
    '  |||||line 175, col 24 to line 175, col 46 of module Identity: 1139320' "\n"
    '  ||||line 176, col 8 to line 176, col 37 of module Identity: 2578300' "\n"
    '  |||||line 176, col 8 to line 176, col 20 of module Identity: 2578300' "\n"
    '  |||||line 176, col 25 to line 176, col 37 of module Identity: 2529700' "\n"
    '  |||line 193, col 32 to line 193, col 32 of module Identity: 2913020' "\n"
    '  |||line 193, col 35 to line 193, col 38 of module Identity: 2913020' "\n"
    '  line 193, col 45 to line 193, col 101 of module Identity: 5132520' "\n"
    '  |line 193, col 47 to line 193, col 100 of module Identity: 5132520' "\n"
    '  ||line 193, col 47 to line 193, col 74 of module Identity: 5132520' "\n"
    '  |||line 193, col 47 to line 193, col 58 of module Identity: 5132520' "\n"
    '  |||line 193, col 63 to line 193, col 74 of module Identity: 2134740' "\n"
    '  ||line 193, col 79 to line 193, col 100 of module Identity: 804600' "\n"
    '  line 206, col 16 to line 206, col 16 of module Identity: 25978770' "\n"
    '  line 206, col 19 to line 206, col 19 of module Identity: 5910800' "\n"
    '  line 206, col 25 to line 206, col 41 of module Identity: 5083920' "\n"
    '  line 75, col 13 to line 75, col 50 of module Identity: 0' "\n"
    '  line 208, col 8 to line 208, col 77 of module Identity: 0' "\n"
    '  line 205, col 14 to line 205, col 16 of module Identity: 5745910' "\n"
)


def report(*blocks):
    """One complete coverage report holding `blocks`."""
    return REPORT_OPEN + "".join(blocks) + REPORT_END


def plant(text, old, new):
    """`text` with its one `old` replaced by `new`."""
    assert text.count(old) == 1, old
    return text.replace(old, new)


class Counted(list):
    """A list that counts each element it hands out: one for each element an iteration yields or an index returns, and
    the length of each slice."""

    reads = 0

    def __iter__(self):
        for item in super().__iter__():
            self.reads += 1
            yield item

    def __getitem__(self, index):
        item = super().__getitem__(index)
        self.reads += len(item) if isinstance(index, slice) else 1
        return item


STALE = ("Identity", (333, 27), (333, 41))


class SpanRule(unittest.TestCase):
    """The runner's reader of the last complete coverage report and the judge's rule for an unreached span, on
    excerpts cut from real logs and on edits of them named as planted."""

    def unreached(self, *logs):
        return judge_tlc.unreached([CHECK.listed(log) for log in logs])

    def test_a_section_ran_by_its_second_count_and_init_is_no_section(self):
        """`identity-board`'s `Init` and `CReturn`, whose header reports 0 distinct and 1,325,990 generated states."""
        listing = CHECK.listed(report(BOARD_INIT_AND_RETURN))
        self.assertEqual([(section.name, section.ran) for section in listing], [("CReturn", True)])

    def test_the_text_of_a_span_is_its_committed_columns_on_one_line(self):
        """Known answers from the real run: `UNCHANGED board` at 333:27-333:41 and `CAttach`'s four-line span
        353:8-356:109, cut by hand from `tla/Identity.tla`. Line 356 ends at column 109."""
        self.assertEqual(judge_tlc.span_text(STALE), "UNCHANGED board")
        self.assertEqual(
            judge_tlc.span_text(("Identity", (353, 8), (356, 109))),
            "leases' = [h \\in 1..Table |-> [leases[h] EXCEPT !.open = FALSE, !.live = 1, !.handed = 0,"
            " !.stale = IF leases[h].open THEN leases[h].handed ELSE @,"
            " !.score = IF leases[h].open THEN leases[h].core ELSE @,"
            " !.sgen = IF leases[h].open THEN leases[h].gen ELSE @]]")

    def test_each_shape_parses_with_its_names_counts_and_nesting(self):
        located = CHECK.listed(report(SHAPE_LOCATED))
        self.assertEqual([(section.name, section.ran) for section in located],
                         [("Next (376 28 376 55)", True), ("Next (376 62 376 88)", False)])
        self.assertIn((3, ("Identity", (74, 29), (74, 29)), 37980), located[0].spans)
        self.assertIn((2, ("Identity", (74, 28), (74, 30)), 37980), located[0].spans)
        split, merged, helper = (CHECK.listed(report(text))[0] for text in (SHAPE_SPLIT, SHAPE_MERGED, SHAPE_HELPER))
        self.assertEqual((split.name, split.ran, merged.ran), ("SBegin", False, True))
        self.assertIn((0, ("Lifecycle", (255, 8), (255, 41)), 0), split.spans)
        self.assertIn((0, ("Lifecycle", (255, 8), (255, 84)), 7292), merged.spans)
        self.assertEqual([count for _, location, count in helper.spans if location == ("Lifecycle", (175, 8), (175, 76))],
                         [2749, 0, 2548, 4692, 0])

    def test_the_last_complete_report_decides_and_either_end_line_ends_one(self):
        """The second complete report of shape 1 decides, ended by the longer line; with that end line planted as
        `End of statistics.` it still decides; with it removed, the first report decides; the report cut short
        alone is no complete report."""
        def first(log):
            return CHECK.listed(log)[0].spans[0][2]
        long_end = "End of statistics (please note that for performance reasons large models\n"
        self.assertEqual(first(SHAPE_REPORTS), 8477662)
        self.assertEqual(first(plant(SHAPE_REPORTS, long_end, REPORT_END)), 8477662)
        self.assertEqual(first(plant(SHAPE_REPORTS, long_end, "")), 1495918)
        with self.assertRaisesRegex(ValueError, "tlc.log has no complete coverage report"):
            CHECK.listed(SHAPE_REPORTS[SHAPE_REPORTS.rindex(CHECK.REPORT_OPENS):])
        with self.subTest("planted: the report cut short before a complete report of another case"):
            cut = SHAPE_REPORTS[SHAPE_REPORTS.rindex(CHECK.REPORT_OPENS):]
            self.assertEqual(CHECK.listed(cut + report(STALE_RAN)), CHECK.listed(report(STALE_RAN)))

    def test_an_unknown_line_or_a_report_without_a_section_raises(self):
        """Planted: a span line without its columns inside the second report of shape 1, a span line there that ends
        with a carriage return, since lines are cut at `\\n` alone, and a report holding a variable's one-count header
        alone."""
        line = "  line 294 of module Identity: 5"
        with self.assertRaisesRegex(ValueError, f"neither a header nor a span line: '{line}'"):
            CHECK.listed(plant(SHAPE_REPORTS, "End of statistics (", line + "\nEnd of statistics ("))
        with self.assertRaisesRegex(ValueError, "neither a header nor a span line: '.*: 3203480\\\\r'"):
            CHECK.listed(plant(SHAPE_REPORTS, ": 3203480\n", ": 3203480\r\n"))
        with self.assertRaisesRegex(ValueError, "tlc.log's last complete coverage report has no section"):
            CHECK.listed(report("<epoch line 49, col 5 to line 49, col 9 of module Identity>: 1\n"))

    def test_a_span_with_0_wherever_its_section_ran_is_unreached(self):
        """`CReturnStale` ran in `identity-board` and, planted, in a second case with its counts unchanged, and did
        not run in `identity-two-slots`; its span 333:27-333:41 has 0 wherever it ran."""
        twin = plant(STALE_RAN, ": 333826:2118850", ": 12:40")
        self.assertEqual(self.unreached(report(STALE_RAN), report(twin), report(STALE_IDLE)), [("CReturnStale", STALE)])
        idle = plant(STALE_IDLE, "333, col 27 to line 333, col 41 of module Identity: 0",
                     "333, col 27 to line 333, col 41 of module Identity: 5")
        with self.subTest("planted: the span positive in the case that did not run the section"):
            self.assertEqual(self.unreached(report(STALE_RAN), report(twin), report(idle)), [("CReturnStale", STALE)])

    def test_the_same_span_positive_in_one_case_that_ran_it_is_evaluated(self):
        """Planted: the second case lists 333:27-333:41 with 5."""
        twin = plant(STALE_RAN, "333, col 27 to line 333, col 41 of module Identity: 0",
                     "333, col 27 to line 333, col 41 of module Identity: 5")
        self.assertEqual(self.unreached(report(STALE_RAN), report(twin), report(STALE_IDLE)), [])

    def test_a_0_span_inside_a_span_positive_in_another_case_is_evaluated(self):
        """Shape 3. Planted: `put`'s `SBegin` header given a positive second count, so its spans listed apart with 0
        are candidates; `put-revocation` lists the merged span with 7,292. The real excerpts give the same list."""
        ran = plant(SHAPE_SPLIT, ": 0:0", ": 1:3")
        self.assertEqual(self.unreached(report(ran), report(SHAPE_MERGED)), [])
        self.assertEqual(self.unreached(report(SHAPE_SPLIT), report(SHAPE_MERGED)), [])
        self.assertEqual(self.unreached(report(ran)), [("SBegin", ("Lifecycle", (255, 8), (255, 41))),
                                                       ("SBegin", ("Lifecycle", (255, 46), (255, 84))),
                                                       ("SBegin", ("Lifecycle", (256, 8), (256, 43))),
                                                       ("SBegin", ("Lifecycle", (256, 48), (256, 83)))])

    def test_a_helper_body_with_0_at_one_call_and_a_count_at_another_is_evaluated(self):
        """Shape 4: `OFail` lists `Fail`'s body with 0 at two calls and positive at three."""
        self.assertEqual(self.unreached(report(SHAPE_HELPER)), [])

    def test_a_section_that_ran_in_no_case_reports_only_spans_no_section_evaluates(self):
        """Shape 2: the second located section ran in no case, and the first evaluates its two spans. Planted: a
        third span under it, 377:1-377:9, that no section lists."""
        self.assertEqual(self.unreached(report(SHAPE_LOCATED)), [])
        planted = SHAPE_LOCATED + "  line 377, col 1 to line 377, col 9 of module Identity: 0\n"
        self.assertEqual(self.unreached(report(planted)), [("Next (376 62 376 88)", ("Identity", (377, 1), (377, 9)))])

    def test_an_occurrence_is_the_innermost_line_that_contains_the_span(self):
        """Planted: under 333:48-333:88, positive, a nested line of the same location with 0; that nested line is
        the span's one occurrence, so the span is unreached."""
        outer = "  line 333, col 48 to line 333, col 88 of module Identity: 2118850\n"
        nested = plant(STALE_RAN, outer, outer + "  |line 333, col 48 to line 333, col 88 of module Identity: 0\n")
        self.assertEqual(self.unreached(report(STALE_RAN)), [("CReturnStale", STALE)])
        self.assertEqual(self.unreached(report(nested)),
                         [("CReturnStale", STALE), ("CReturnStale", ("Identity", (333, 48), (333, 88)))])

    def test_a_nested_0_span_is_reported_once_by_its_outermost_span(self):
        """Planted: a line nested under 333:27-333:41 with 0, of `Identity` and then of `IdentityMC`; a span of
        another module with the same lines is no span inside it."""
        outer = "  line 333, col 27 to line 333, col 41 of module Identity: 0\n"
        for module, found in (("Identity", [("CReturnStale", STALE)]),
                              ("IdentityMC", [("CReturnStale", STALE),
                                              ("CReturnStale", ("IdentityMC", (333, 27), (333, 35)))])):
            with self.subTest(module):
                nested = plant(STALE_RAN, outer, outer + f"  |line 333, col 27 to line 333, col 35 of module {module}: 0\n")
                self.assertEqual(self.unreached(report(nested), report(STALE_IDLE)), found)

    def test_a_helper_listed_apart_with_0_and_merged_with_a_count_is_evaluated(self):
        """Planted: `Act` calls a helper twice; the first call lists its parts 20:8-20:12 and 20:17-20:30 apart with
        0, the second the merged span 20:8-20:30 with 4. Nothing is reported when `Act` ran, nor when `Act` ran in no
        case and `Other` of another case lists the merged span with 4; with the merged count at 0 the helper's body
        is reported once, by the merged span."""
        parts = ("  line 11, col 8 to line 11, col 20 of module M: 5\n"
                 "  |line 20, col 8 to line 20, col 12 of module M: 0\n"
                 "  |line 20, col 17 to line 20, col 30 of module M: 0\n")
        merged = "  line 12, col 8 to line 12, col 20 of module M: 5\n  |line 20, col 8 to line 20, col 30 of module M: {}\n"
        act = "<Act line 10, col 1 to line 10, col 3 of module M>: {}\n"
        self.assertEqual(self.unreached(report(act.format("1:2") + parts + merged.format(4))), [])
        self.assertEqual(self.unreached(report(act.format("0:0") + parts),
                                        report("<Other line 30, col 1 to line 30, col 5 of module M>: 1:2\n" + merged.format(4))), [])
        self.assertEqual(self.unreached(report(act.format("1:2") + parts + merged.format(0))),
                         [("Act", ("M", (20, 8), (20, 30)))])


    def test_a_helper_body_folded_into_an_evaluated_call_is_reported_where_listed_at_0(self):
        """`WrongOp` evaluates `Count` through a call line that does not contain `Count`'s body, and `Conflict`, which
        ran in neither case, lists the body and its own last action-level line with 0; both are reported."""
        self.assertEqual(self.unreached(report(FOLDED_RAN), report(FOLDED_IDLE)),
                         [("Conflict", ("Identity", (75, 13), (75, 50))), ("Conflict", ("Identity", (208, 8), (208, 77)))])

    def test_sections_compare_apart_and_entries_sort_by_location_then_section(self):
        """Planted: four sections that ran. `Aa` lists 20:8-20:30 with 4, `Bb` and `Dd` list it with 0, and `Cc` lists
        18:1-22:40, which contains it, with 0. Each section compares within itself, so `Bb` and `Dd` keep their
        entries, and `Cc`'s outer entry keeps neither out; entries sort by location, then section, which puts `Cc`
        before `Bb`."""
        inner = "  line 20, col 8 to line 20, col 30 of module M: {}\n"
        header = "<{} line 10, col 1 to line 10, col 2 of module M>: 1:2\n"
        log = report(header.format("Aa") + inner.format(4), header.format("Bb") + inner.format(0),
                     header.format("Cc") + "  line 18, col 1 to line 22, col 40 of module M: 0\n",
                     header.format("Dd") + inner.format(0))
        self.assertEqual(self.unreached(log), [("Cc", ("M", (18, 1), (22, 40))), ("Bb", ("M", (20, 8), (20, 30))),
                                               ("Dd", ("M", (20, 8), (20, 30)))])

    def test_an_occurrence_ends_where_the_next_line_at_its_depth_starts(self):
        """Planted: in one section that ran, 20:8-20:30 positive at depth 0, a sibling 11:8-11:20 at depth 0, and under
        the sibling 20:8-20:30 with 0. The positive line's nested lines end at the sibling, so it is an occurrence and
        the span is evaluated."""
        log = report("<Act line 10, col 1 to line 10, col 3 of module M>: 1:2\n"
                     "  line 20, col 8 to line 20, col 30 of module M: 4\n"
                     "  line 11, col 8 to line 11, col 20 of module M: 5\n"
                     "  |line 20, col 8 to line 20, col 30 of module M: 0\n")
        self.assertEqual(self.unreached(log), [])

    def test_a_nested_line_that_contains_the_span_decides_after_one_that_does_not(self):
        """Planted: in one section that ran, 20:1-20:40 positive at depth 0 and, nested under it, 20:1-20:5 with 3 and
        then 20:8-20:30 with 0. The second nested line is the one occurrence of 20:8-20:30, though the first nested
        line does not contain it, so the span is unreached."""
        log = report("<Act line 10, col 1 to line 10, col 3 of module M>: 1:2\n"
                     "  line 20, col 1 to line 20, col 40 of module M: 4\n"
                     "  |line 20, col 1 to line 20, col 5 of module M: 3\n"
                     "  |line 20, col 8 to line 20, col 30 of module M: 0\n")
        self.assertEqual(self.unreached(log), [("Act", ("M", (20, 8), (20, 30)))])

    def test_the_rule_s_reads_grow_with_the_square_of_the_span_lines(self):
        """Planted: one section of `lines` span lines and one more, all at depth 0. A half of the lines are spans
        around line 1000 with 0, each inside the next; a half are spans of line 1000 with 0, each inside the one
        before; the last is 2000:1-2000:2 with 3. The one unreached span is the outermost, whether the section ran or
        not. Twice the lines cost at most five times the reads of the section's span lines, where the square costs
        four times, and the rule reads each line."""
        def reads(lines, generated):
            half = lines // 2
            around = "".join(f"  line {999 - at}, col 1 to line {1001 + at}, col 9 of module M: 0\n" for at in range(half))
            within = "".join(f"  line 1000, col {1 + at} to line 1000, col {lines - at} of module M: 0\n" for at in range(half))
            listing = CHECK.listed(report(f"<Act line 10, col 1 to line 10, col 3 of module M>: 1:{generated}\n" + around
                                          + within + "  line 2000, col 1 to line 2000, col 2 of module M: 3\n"))
            spans = listing[0].spans = Counted(listing[0].spans)
            self.assertEqual(len(spans), lines + 1)
            self.assertEqual(judge_tlc.unreached([listing]), [("Act", ("M", (1000 - half, 1), (1000 + half, 9)))])
            return spans.reads
        for generated in (2, 0):
            with self.subTest(generated=generated):
                small, large = reads(64, generated), reads(128, generated)
                self.assertGreater(small, 64)
                self.assertLessEqual(large, 5 * small)

    def test_a_0_span_with_a_positive_listed_span_inside_it_is_evaluated(self):
        """Planted: under 333:27-333:41, listed with 0, a nested line 333:37-333:41 with 3."""
        outer = "  line 333, col 27 to line 333, col 41 of module Identity: 0\n"
        inside = plant(STALE_RAN, outer, outer + "  |line 333, col 37 to line 333, col 41 of module Identity: 3\n")
        self.assertEqual(self.unreached(report(STALE_RAN)), [("CReturnStale", STALE)])
        self.assertEqual(self.unreached(report(inside)), [])

    def test_a_span_listed_only_where_its_section_did_not_run_is_no_candidate(self):
        """Planted: `identity-board`'s `CReturnStale` without its line 333:27-333:41, beside `identity-two-slots`, which
        lists that span with 0 where the section did not run."""
        ran = plant(STALE_RAN, "  line 333, col 27 to line 333, col 41 of module Identity: 0\n", "")
        self.assertEqual(self.unreached(report(ran), report(STALE_IDLE)), [])

    def test_headers_other_than_sections_keep_their_span_lines_out_of_the_section_above(self):
        """Planted: after `CReturnStale`, an invariant's header with no count and a variable's header with one count,
        each with a span line of 0; the section's spans and the unreached list stay."""
        planted = STALE_RAN + ("<Inv line 90, col 1 to line 90, col 3 of module Identity>\n"
                               "  line 91, col 1 to line 91, col 5 of module Identity: 0\n"
                               "<epoch line 49, col 5 to line 49, col 9 of module Identity>: 1\n"
                               "  line 49, col 5 to line 49, col 9 of module Identity: 0\n")
        self.assertEqual(CHECK.listed(report(planted)), CHECK.listed(report(STALE_RAN)))
        self.assertEqual(self.unreached(report(planted)), [("CReturnStale", STALE)])

    def test_a_span_line_above_the_first_header_raises(self):
        """Planted: a span line of `CReturnStale` moved above its header."""
        line = "  line 331, col 8 to line 331, col 26 of module Identity: 2118850"
        with self.assertRaisesRegex(ValueError, f"a span line before its first header: '{line}'"):
            CHECK.listed(report(line + "\n" + STALE_RAN))

    def test_a_tab_moves_the_column_to_the_next_multiple_of_eight_plus_one(self):
        """Planted: a module whose line 2 is `A ==` and a tab before `UNCHANGED v`, and whose line 3 is `B ==` and two
        tabs before it. SANY puts the `U` of line 2 at column 9, as the pinned TLC reports a symbol after a tab, and
        eight-column stops put the `U` of line 3 at column 17, where four-column stops would put it at 13. A span
        ending at column 1 of line 4 takes that line's first character."""
        with tempfile.TemporaryDirectory(prefix="kestrike-tlc-") as directory:
            (Path(directory) / "T.tla").write_text("---- MODULE T ----\nA ==\tUNCHANGED v\nB ==\t\tUNCHANGED w\n====\n")
            with mock.patch.object(judge_tlc, "MODELS", Path(directory)):
                self.assertEqual(judge_tlc.span_text(("T", (2, 9), (2, 19))), "UNCHANGED v")
                self.assertEqual(judge_tlc.span_text(("T", (3, 17), (3, 27))), "UNCHANGED w")
                self.assertEqual(judge_tlc.span_text(("T", (3, 17), (4, 1))), "UNCHANGED w =")

    def test_a_module_file_that_cannot_be_read_is_refused_by_its_relative_path(self):
        """Planted: reading `tla/Identity.tla` raises `PermissionError` naming its absolute path; the refusal names
        the span and the relative file alone."""
        error = PermissionError(13, "Permission denied", str(ROOT / "tla/Identity.tla"))
        with mock.patch.object(Path, "read_text", side_effect=error) as read, self.assertRaises(ValueError) as refused:
            judge_tlc.span_text(STALE)
        read.assert_called_once()
        self.assertEqual(str(refused.exception), "span Identity 333:27-333:41 lies outside the text of tla/Identity.tla")


class LogReaders(unittest.TestCase):
    """The runner's readers of a TLC log, at the line and digit boundaries where each decides."""

    BREAKS = ("\n", "\r", "\r\n", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029")
    ROW = "<{} line 3, col 1 to line 3, col 9 of module M>: 0:{}\n"
    REPORT = "{} states generated, {} distinct states found"

    def test_a_terminal_line_runs_from_the_start_of_a_line_to_its_end(self):
        """Each declared outcome and each failure TLC reports is an outcome after every line break
        `str.splitlines` cuts at and as the log's only text, and is none when other text precedes it on its line."""
        for prefix in (*(prefix for prefix, _ in CHECK.EXIT_STATUS), *FAILURES):
            line = prefix + " tail"
            self.assertEqual(CHECK.outcomes(line), [line])
            for end in self.BREAKS:
                with self.subTest(prefix=prefix, end=end):
                    self.assertEqual(CHECK.outcomes(f"before{end}{line}{end}after"), [line])
            for inside in (" ", "\t", "\x1f", "\x00", "\u00a0", "> "):
                with self.subTest(prefix=prefix, inside=inside):
                    self.assertEqual(CHECK.outcomes(f"before{inside}{line}\n"), [])

    def test_the_outcomes_keep_the_log_s_order_and_leave_out_the_trace_headings(self):
        log = (f"{TRACE}\n"
               "Error: Invariant A is violated.\n"
               "Model checking completed. No error has been found.\n"
               "State 2: Error: Invariant B is violated.\n"
               f"{COUNTEREXAMPLE}\n"
               "Error: TLC threw an unexpected exception.\n"
               f"{FAILURES[1]}\n"
               "Error: Deadlock reached.")
        self.assertEqual(CHECK.outcomes(log), [
            "Error: Invariant A is violated.", "Model checking completed. No error has been found.",
            "Error: TLC threw an unexpected exception.", FAILURES[1], "Error: Deadlock reached."])

    def test_a_trace_heading_is_no_outcome_only_as_a_whole_line(self):
        """Each trace heading is no outcome as the log's only text and between any two line breaks. A line that
        extends or shortens a heading is an error line of its own, so it is an outcome."""
        for heading in (TRACE, COUNTEREXAMPLE):
            self.assertEqual(CHECK.outcomes(heading), [])
            for end in self.BREAKS:
                with self.subTest(heading=heading, end=end):
                    self.assertEqual(CHECK.outcomes(f"before{end}{heading}{end}after"), [])
            for line in (heading + " ", heading + "x", heading[:-1]):
                with self.subTest(line=line):
                    self.assertEqual(CHECK.outcomes(f"before\n{line}\nafter"), [line])

    def test_an_action_is_covered_by_its_last_coverage_line_with_a_generated_state(self):
        """The second count of a coverage line, the states the action generated, decides; the first, its distinct
        states, does not."""
        case = CHECK.Case("reader", base="Lifecycle.cfg", module="LifecycleMC", target="Lifecycle.tla",
                          coverage=("A", "B", "C"))
        row = self.ROW.format
        rest = row("B", 2) + row("C", 3)
        for name, log, missing in (
            ("every action covered", row("A", 1) + rest, []),
            ("distinct states without a generated one", row("A", 0).replace(": 0:0", ": 4:0") + rest, ["A"]),
            ("an empty log", "", ["A", "B", "C"]),
            ("a later zero", row("A", 1) + row("A", 0) + rest, ["A"]),
            ("an earlier zero", row("A", 0) + row("A", 1) + rest, []),
            ("a zero after the other actions", row("A", 1) + rest + row("A", 0), ["A"]),
            ("a line of a longer name", row("Ax", 1) + rest, ["A"]),
            ("an indented line", " " + row("A", 1) + rest, ["A"]),
            ("text after the count", row("A", "1 ") + rest, ["A"]),
            ("a count of zeros", row("A", "00") + rest, ["A"]),
            ("a last line without a line break", row("A", 1) + rest[:-1], []),
            ("a location that runs to the next line's count", "<A line 3\n" + rest, []),
            ("a location that runs to the next line's zero", "<A line 3\n" + row("B", 0) + row("C", 3), ["A", "B"]),
            ("Arabic-Indic digits", row("A", "\u0663") + row("B", "\u0660") + row("C", 3), ["B"]),
        ):
            with self.subTest(name):
                self.assertEqual(CHECK.uncovered(case, log), missing)

    def test_a_step_is_a_whole_state_line_that_names_an_action(self):
        """A counterexample step is a whole `State N: <Action ...>` line, with or without arguments; the initial
        state, a line with text before or after the step, a step line without its location and a step cut at a
        carriage return name no action."""
        step = "State 2: <OData line 193, col 5 to line 201, col 16 of module Lifecycle>"
        call = 'State 3: <Admit(1,2,1,"GET") line 106, col 5 to line 112, col 64 of module Identity>'
        for name, log, actions in (
            ("a step and a call", f"State 1: <Initial predicate>\n{step}\n{call}\n", ["OData", "Admit"]),
            ("text before a step", f"> {step}\n", []),
            ("text after a step", f"{step} x\n", []),
            ("a step without its location", "State 2: <OData>\n", []),
            ("a step cut at a carriage return", f"{step}\r\n", []),
        ):
            with self.subTest(name):
                self.assertEqual(CHECK.steps(log), actions)

    def test_configuration_words_keep_strings_whole(self):
        """A string literal is one word, so a keyword inside it starts no statement and two strings that differ in
        their spacing differ; a keyword of TLC's grammar ends the statement before it."""
        self.assertEqual(CHECK.checked('CONSTANT L = "a INVARIANT B"\nINVARIANT A\n'), {"invariants": ["A"], "properties": []})
        self.assertNotEqual(CHECK.unchecked('CONSTANT L = "a  b"\n'), CHECK.unchecked('CONSTANT L = "a b"\n'))
        self.assertEqual(CHECK.words('CONSTANT L = "a \\" b"'), ["CONSTANT", "L", "=", '"a \\" b"'])
        for keyword in ("POSTCONDITIONS", "_PERIODIC", "_RL_REWARD", "_POSSIBLE"):
            with self.subTest(keyword):
                config = f"INVARIANTS TypeOK\n{keyword} Capacity\n"
                self.assertEqual(CHECK.checked(config)["invariants"], ["TypeOK"])
                self.assertEqual(CHECK.unchecked(config), [(keyword, ["Capacity"])])

    def test_comments_are_blanked_in_place(self):
        """Comments become spaces with line breaks kept, so every offset keeps its place; nested block comments
        close at their own end, a stray block closer is text, a line-comment opener and a quote inside a block
        comment are comment, and a string's comment opener is text. A block comment and a string without their
        closer run to the end of the text, the `*` of `(*)` opens a comment and closes none, and a carriage return
        inside a comment becomes a space."""
        for text, kept in (
            ("A (* x (* y *) z *) B", "A                   B"),
            ('A == "(*" \\* c', 'A == "(*"     '),
            ('A == "\\"(*" \\* c\nB', 'A == "\\"(*"     \nB'),
            ("A (* x\ny *) B \\* tail", "A     \n     B        "),
            ("A *) B", "A *) B"),
            ("(* a \\* b *) C", "             C"),
            ('(* " *) B', "        B"),
            ("A (* x\ny", "A     \n "),
            ('A == "(* x', 'A == "(* x'),
            ('A == "x\\', 'A == "x\\'),
            ("(*) a *) B", "         B"),
            ("(* a\r\n*) B", "     \n   B"),
            ("A \\* c\r\nB", "A      \nB"),
        ):
            with self.subTest(text=text):
                self.assertEqual(CHECK.uncommented(text), kept)

    def test_the_state_counts_are_those_of_the_last_complete_report(self):
        report = self.REPORT.format
        for name, log, counts in (
            ("no report", "Model checking completed. No error has been found.\n", None),
            ("one report", report(10, 7) + ", 0 states left on queue.\n", ["10", "7"]),
            ("a later report", report(3, 2) + "\n" + report(10, 7) + "\n", ["10", "7"]),
            ("a report inside a line", "Progress(5): " + report(10, 7) + "\n", ["10", "7"]),
            ("a later report cut short", report(10, 7) + "\n" + report(55, 4)[:-1], ["10", "7"]),
            ("a later report without its second count", report(10, 7) + "\n55 states generated, ", ["10", "7"]),
            ("a later report without its first count", report(10, 7) + "\n" + report("", 4), ["10", "7"]),
            ("a report across two lines", "10 states generated,\n7 distinct states found", None),
            ("leading zeros", report("010", "07"), ["010", "07"]),
            ("Arabic-Indic digits", report("\u0661\u0660", "\u0667"), ["\u0661\u0660", "\u0667"]),
        ):
            with self.subTest(name):
                self.assertEqual(CHECK.state_counts(log), counts)


if __name__ == "__main__":
    unittest.main()
