#!/usr/bin/env python3
"""Check that judge-quint.py credits the Quint models' cases only when each reached its declared outcome under the pinned tools.

The judge tests build an evidence directory as the lane writes it, with the
runner's results for every case; the complete evidence credits, and each
refusal test breaks one property and checks the refusal names it. The pins
tests check that `pins` prints the committed `cases` block for passing
evidence, reads each count from the retained log, writes no report or receipt,
and prints nothing for evidence the judge refuses apart from the `cases`
comparisons. The registry tests check the committed registry against the
runner's cases statically and plant one change to a copy of it per refusal. The runner
tests feed `quint/check.py`'s outcome parser logs it must refuse, and check
each mutation's target text.
"""

import argparse
import contextlib
import copy
import dataclasses
import hashlib
import importlib.util
import io
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/judge-quint.py"
spec = importlib.util.spec_from_file_location("judge_quint", SCRIPT)
assert spec is not None and spec.loader is not None
judge_quint = importlib.util.module_from_spec(spec)
spec.loader.exec_module(judge_quint)
EXPECTED = json.loads((ROOT / "verification/quint/expected.json").read_text())
CHECK = judge_quint.runner()
CASES = {case.name: case for case in CHECK.cases()}
CREATION_FIXTURES = CHECK.creation_fixtures
STANDBYS_FIXTURES = CHECK.standbys_fixtures
LOSS_FIXTURES = CHECK.loss_fixtures
# `JudgeQuint.result` reuses each case name's first computed input texts across calls in the same process.
INPUTS = {}
WITNESS_FIXTURES = CHECK.detect_witness_fixtures
# The replay cases that regenerate committed traces, each with its ignored test.
CORE_REPLAYS = {
    "detect-replay": "failover::detect_route_replay_tests::generated_detect_traces_replay",
    "route-replay": "failover::detect_route_replay_tests::generated_route_traces_replay",
    "detect-witness-replay": "failover::detect_route_replay_tests::witness::generated_detect_witness_traces_replay",
    "creation-replay": "failover::reconcile_tests::creation_replay::generated_creation_traces_replay",
    "standbys-replay": "failover::reconcile_tests::standbys_replay::generated_standbys_traces_replay",
    "loss-replay": "failover::reconcile_tests::loss_replay::generated_loss_traces_replay",
}
QUINT = "/opt/quint/npm/node_modules/.bin/quint"
OBLIGATIONS = json.loads((ROOT / "verification/obligations.json").read_text())
VERIFY = judge_quint.load("verify_receipts", ROOT / "scripts/verify-receipts.py")
PORTS = {name: 40000 + rank for rank, name in enumerate(sorted(CASES)) if CASES[name].command == "tlc"}
MODEL_DIGESTS = judge_quint.model_digests()


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def stopped(pid, seconds=5):
    """Whether process `pid` exits, or becomes a zombie, within `seconds`."""
    status = Path(f"/proc/{pid}/stat")
    limit = time.monotonic() + seconds
    while time.monotonic() < limit:
        try:
            if status.read_text().split()[2] == "Z":
                return True
        except FileNotFoundError:
            return True
        time.sleep(0.05)
    return False


def default_sigint():
    """Give a process the default SIGINT before it starts a runner. A terminal starts the runner with it, and the
    runner handles SIGINT only when Python starts it with its default handler; a test run started as a shell's
    background job passes an ignored SIGINT to its children."""
    signal.signal(signal.SIGINT, signal.SIG_DFL)


def recording_stub(directory, child="sleep 60"):
    """A `quint` stand-in that records its pid and a background `child`'s pid, then waits on the child."""
    pids = directory / "pids"
    stub = directory / "quint"
    stub.write_text(f'#!/bin/sh\necho $$ >> "{pids}"\n{child} &\necho $! >> "{pids}"\nwait\n')
    stub.chmod(0o755)
    return stub, pids



def trace_states(case):
    """The number of states in a fixture violation trace: the declared `trace`; for a recipe mutant without one, the
    initial state and one state per recipe action; otherwise one more than the case's `after` bound, and at least 4."""
    if case.trace:
        return case.trace
    return len(case.recipe) + 1 if case.mutations and case.recipe else max(4, (case.after or 0) + 1)


def distinct_states(case):
    """The distinct-state count of a TLC case's fixture log: a passing case's pin, and 7 for a violation or for a
    passing case the committed registry pins no usable count for, which the judge then refuses by name."""
    pins = EXPECTED.get("cases")
    pin = pins.get(case.name) if isinstance(pins, dict) else None
    count = pin.get("distinct") if isinstance(pin, dict) else None
    return count if judge_quint.counted(case) and type(count) is int and count > 0 else 7


def generated_states(case):
    """The generated-state count of a TLC case's fixture log, 10 more than its distinct count."""
    return distinct_states(case) + 10


def cited_controls_unequal_to_their_text(registry):
    """The Quint controls an obligation record cites whose `cases` entry in `registry` states another outcome than
    `control_text` gives for it."""
    return sorted({control["test"] for record in OBLIGATIONS["records"] if record["job"] == "quint"
                   for control in record["controls"]
                   if registry["cases"].get(control["test"], {}).get("outcome") != VERIFY.control_text(control["test"], "quint")})


class JudgeQuint(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kestrike-quint-")
        self.addCleanup(self.temp.cleanup)
        self.evidence = Path(self.temp.name) / "evidence"
        self.evidence.mkdir()
        self.identity = {
            "java": {"path": "/opt/jdk/bin/java", "version": f'openjdk version "{EXPECTED["java"]["version"]}" 2026-08-18 LTS',
                     "install": {"sha256": EXPECTED["java"]["install"], "files": 249}},
            "node": {"path": "/opt/node/bin/node", "version": EXPECTED["node"]["version"],
                     "install": {"sha256": EXPECTED["node"]["install"], "files": 4797}},
            "apalache": {"path": "/opt/home/apalache-dist-0.62.1", "install": {"sha256": EXPECTED["apalache"]["install"], "files": 4}},
            "quint": {"path": QUINT, "version": EXPECTED["quint"]["version"], "apalache": EXPECTED["apalache"]["version"],
                      "install": {"sha256": EXPECTED["quint"]["install"], "files": 4678}},
            "models": dict(MODEL_DIGESTS),
        }
        self.argv = ["/usr/bin/python3", "quint/check.py", "--quint", QUINT, "--workers", str(EXPECTED["workers"]),
                     "--output", str(self.evidence / "quint")]
        self.results = {name: self.result(case) for name, case in CASES.items()}
        self.exit = 0
        self.runtime = f'openjdk version "{EXPECTED["java"]["version"]}" 2026-08-18 LTS\n'
        self.version = EXPECTED["quint"]["version"]
        self.complete = True
        self.failure = None
        self.dirty = []

    def result(self, case):
        directory = (self.evidence / "quint" / case.name).resolve()
        port = PORTS.get(case.name)
        if case.name not in INPUTS:
            INPUTS[case.name] = CHECK.inputs(case, ROOT / "quint")
        texts = INPUTS[case.name]
        result = {"case": case.name, "command": CHECK.command(case, str(Path(QUINT).resolve()), directory, port)[1:],
                  "expected": case.expected, "returncode": 0 if case.expected == "ok" else 1, "seconds": 1.0, "port": port,
                  "inputs": {name: digest(text) for name, text in texts.items()}}
        steps = CHECK.replay_steps(case)
        if steps is not None:
            result.update(traces=len(steps), actions=sum(steps))
        elif case.command == "replay":
            result.update(traces=CHECK.REPLAY_TRACES, actions=2050, longest=41,
                          per_action=dict.fromkeys(CHECK.REPLAY_ACTIONS, 3))
        elif case.command == "simulate":
            result.update(traces=int(CHECK.SAMPLES), lengths={"max": 41, "min": 41, "average": 41.0},
                          witnessed=dict.fromkeys(CHECK.WITNESSES, 1))
        elif case.command == "tlc":
            result.update(states=[generated_states(case), distinct_states(case), 0], depth=case.depth or (len(case.recipe) + 1 if case.recipe and case.expected == "ok" else 5))
            if case.expected == "violation":
                result["trace"] = trace_states(case)
            if case.lasso:
                result["lasso"] = [3, 4]
        directory.mkdir(parents=True, exist_ok=True)
        for filename, text in texts.items():
            (directory / filename).write_text(text)
        if steps is not None:
            log = f"core replay: traces={result['traces']} actions={result['actions']} agreement=all\ntest result: ok. 1 passed;\n"
        elif case.command == "replay":
            per_action = ','.join(f'{name}:3' for name in CHECK.REPLAY_ACTIONS)
            log = f"q1 connect replay: traces={CHECK.REPLAY_TRACES} actions=2050 longest=41 per_action={per_action} agreement=all\ntest result: ok. 1 passed;\n"
        elif case.command == "simulate":
            log = "[ok] No violation found\nTrace length statistics: max=41, min=41, average=41.0\n" + ''.join(f'{name} was witnessed in 1 trace(s) out of {CHECK.SAMPLES} explored\n' for name in CHECK.WITNESSES)
        elif case.command == "typecheck":
            log = "typecheck completed\n"
        else:
            log = (f"{generated_states(case)} states generated, {distinct_states(case)} distinct states found, 0 states left on queue\n"
                   f"The depth of the complete state graph search is {result['depth']}\n")
            if case.expected == "ok":
                log += "Model checking completed. No error has been found.\n[ok] No violation found\n"
            else:
                prop = "Invariant q_inv is violated." if case.invariant else "Temporal property q_temporalProps was violated."
                log += f"Error: {prop}\n[violation] Found an issue\n" + "".join(f"State {i}: fixture\n" for i in range(1, trace_states(case) + 1))
                if case.lasso:
                    log += ('State 1: prefix\n/\\ q1case_session_last = [ pendingDisplaced |-> TRUE, peer |-> "c1" ]\n'
                            'State 2: prefix\nState 3: retry\n/\\ q1case_session_last = [ act |-> "retry", verdict |-> "confirm", peer |-> "c1" ]\n'
                            'State 4: mismatch\n/\\ q1case_session_last = [ act |-> "deliverToOwner", kind |-> "confirm", verdict |-> "mismatch", pendingForeign |-> TRUE, peer |-> "c1" ]\nBack to state 3\n')
        (directory / "quint.log").write_text(log)
        return result

    def test_core_replay_refuses_shortened_or_inflated_action_counts(self):
        for name in CORE_REPLAYS:
            case = CASES[name]
            steps = CHECK.replay_steps(case)
            for traces, actions in ((len(steps), 2), (len(steps), sum(steps) - 1), (len(steps), sum(steps) + 1),
                                    (len(steps) - 1, sum(steps)), (len(steps) + 1, sum(steps))):
                log = f"core replay: traces={traces} actions={actions} agreement=all\ntest result: ok. 1 passed;\n"
                with self.subTest(name=name, traces=traces, actions=actions), self.assertRaisesRegex(RuntimeError, "core replay"):
                    CHECK.judge(case, log, 0)

    def test_core_replay_counts_are_the_declared_traces_and_steps(self):
        for name, family in (("detect-replay", "detect"), ("route-replay", "route")):
            recipes = CHECK.detect_route_checks.fixture_recipes(family)
            with self.subTest(name=name):
                self.assertEqual(sorted(CHECK.replay_steps(CASES[name])), sorted(map(len, recipes.values())))
        seeded = [CREATION_FIXTURES.STEPS] * len(CREATION_FIXTURES.SEEDS)
        self.assertEqual(sorted(CHECK.replay_steps(CASES["creation-replay"])),
                         sorted([*map(len, CREATION_FIXTURES.RECIPES.values()), *seeded]))
        seeded = [steps for _, seeds, steps in STANDBYS_FIXTURES.SEEDED.values() for _ in seeds]
        directed = [len(recipe) for recipe, _ in STANDBYS_FIXTURES.directed().values()]
        self.assertEqual(sorted(CHECK.replay_steps(CASES["standbys-replay"])), sorted([*directed, *seeded]))
        seeded = [len(CHECK.loss_checks.ROOTS[root][0]) + LOSS_FIXTURES.FREE
                  for root, seeds in LOSS_FIXTURES.SEEDED.items() for _ in seeds]
        directed = [len(recipe) for recipe in LOSS_FIXTURES.directed().values()]
        self.assertEqual(sorted(CHECK.replay_steps(CASES["loss-replay"])), sorted([*directed, *seeded]))
        self.assertEqual(sorted(CHECK.replay_steps(CASES["detect-witness-replay"])),
                         sorted(map(len, WITNESS_FIXTURES.witness_recipes().values())))
        self.assertIsNone(CHECK.replay_steps(CASES["connect-replay"]))

    def test_new_replay_inputs_refuse_a_drifted_declaration(self):
        for name, module, trace in (("creation-replay", CREATION_FIXTURES, "racing_attaches"),
                                    ("standbys-replay", STANDBYS_FIXTURES, "run_enrollOne"),
                                    ("loss-replay", LOSS_FIXTURES, "run_retirement"),
                                    ("detect-witness-replay", WITNESS_FIXTURES, "ExhaustedThenSilent")):
            declared = module.fixtures()
            model, metadata = declared[trace]
            drifted = {**declared, trace: (model, {**metadata, "recipe": metadata["recipe"][::-1]})}
            with self.subTest(name=name), mock.patch.object(module, "fixtures", lambda drifted=drifted: drifted), \
                    self.assertRaisesRegex(ValueError, "drifted"):
                CHECK.inputs(CASES[name], ROOT / "quint")

    def test_a_core_replay_case_records_the_model_text_its_traces_bind(self):
        # Each trace records the digest of its family's whole model file, so the case's input must be that file.
        for name in CORE_REPLAYS:
            model = CASES[name].family + ".qnt"
            with self.subTest(name=name):
                recorded = CHECK.inputs(CASES[name], ROOT / "quint")[model]
                self.assertEqual(hashlib.sha256(recorded.encode()).hexdigest(),
                                 hashlib.sha256((ROOT / "quint" / model).read_bytes()).hexdigest())

    def test_core_replay_refuses_fixtures_recorded_from_another_recipe_of_equal_length(self):
        for family, name in (("detect", "incident"), ("route", "conflict_ab")):
            declared = CHECK.detect_route_checks.fixture_recipes
            def drifted(asked, family=family, name=name):
                recipes = declared(asked)
                if asked == family:
                    recipes[name] = recipes[name][1:] + recipes[name][:1]
                return recipes
            with self.subTest(family=family), mock.patch.object(CHECK.detect_route_checks, "fixture_recipes", drifted), \
                    self.assertRaisesRegex(ValueError, "drifted"):
                CHECK.inputs(CASES[family + "-replay"], ROOT / "quint")

    def test_core_fixture_inputs_are_bound_to_the_runner_identity(self):
        self.assertIn("crates/kestrike/src/failover/detect_route_fixtures/incident.itf.json", self.identity["models"])
        self.assertIn("crates/kestrike/src/failover/detect_route_fixtures/conflict_ab.itf.json", self.identity["models"])

    def test_a_passing_blocked_case_reports_its_gate_and_receives_no_credit(self):
        report = self.judge()
        receipt = json.loads((self.evidence / "receipt.json").read_text())
        self.assertEqual(report["cases"]["detect-progress"]["blocked"], "AQ-15")
        self.assertFalse(report["cases"]["detect-progress"]["credited"])
        self.assertNotIn("detect-progress", receipt["executed"])

    def test_unblocked_cases_keep_their_outcomes_and_credit(self):
        report = self.judge()
        receipt = json.loads((self.evidence / "receipt.json").read_text())
        self.assertIn("route-safety", receipt["executed"])
        self.assertNotIn("blocked", report["cases"]["route-safety"])

    def test_a_blocked_name_absent_from_declared_cases_is_refused(self):
        expected = {**EXPECTED, "blocked": {"absent": "AQ-15"}}
        with self.assertRaisesRegex(judge_quint.Refusal, "undeclared case"):
            judge_quint.declared_cases(expected)

    def test_case_summaries_need_matching_raw_evidence(self):
        name = "tenure-reach-witnessFlip"
        (self.evidence / "quint" / name / "quint.log").unlink()
        self.refused(judge_quint.MISMATCH, "raw evidence refused")
        self.setUp()
        self.results[name]["trace"] += 1
        self.refused(judge_quint.MISMATCH, "summary differs from raw evidence")

    def test_a_passing_join_log_with_a_nonempty_queue_or_malformed_labels_is_refused(self):
        name = "join-capture-suffix-safety"
        log = self.evidence / "quint" / name / "quint.log"
        log.write_text(log.read_text().replace("0 states left on queue", "3 states left on queue"))
        self.results[name]["states"][2] = 3
        self.refused(judge_quint.MISMATCH, "left on its queue")
        self.setUp()
        name = "join-capture-suffix-mutant-release-ignores-hold"
        log = self.evidence / "quint" / name / "quint.log"
        log.write_text(log.read_text().replace("State 2: ", "State 02: "))
        self.refused(judge_quint.MISMATCH, "states 1 to N in order")
        self.setUp()
        log = self.evidence / "quint" / name / "quint.log"
        log.write_text(log.read_text().split("State 1: ")[0] + "".join(f"State {n}: fixture\n" for n in range(1, 27)))
        self.results[name]["trace"] = 26
        self.refused(judge_quint.MISMATCH, "states 1 to N in order")

    def test_a_typecheck_error_log_or_a_non_integer_exit_status_is_refused(self):
        case = CASES["capture-typecheck"]
        with self.assertRaisesRegex(RuntimeError, "does not typecheck"):
            CHECK.judge(case, "capture.qnt:3:1 - error: [QNT404] Name 'x' not found\n", 0)
        for status in (float("nan"), False, 0.0):
            with self.subTest(status=status), self.assertRaisesRegex(RuntimeError, "not an integer"):
                CHECK.judge(case, "", status)
        for name, status in (("capture-mutant-UnitsExclusive", float("nan")), ("capture-typecheck", False)):
            self.setUp()
            self.results[name]["returncode"] = status
            with self.subTest(name=name):
                self.refused(judge_quint.MISMATCH, "not an integer")


    def test_core_replay_refuses_incomplete_raw_logs(self):
        for name in CORE_REPLAYS:
            log = (self.evidence / "quint" / name / "quint.log").read_text()
            self.assertTrue(CHECK.judge(CASES[name], log, 0))
            for broken, code in (("", 0), (log, -9), (log, 137), (log.replace("1 passed", "0 passed"), 0),
                                 (log.replace("actions=", "actions=1", 1), 0)):
                with self.subTest(name=name, code=code), self.assertRaises(RuntimeError):
                    CHECK.judge(CASES[name], broken, code)

    def test_raw_instance_must_match_the_declared_input(self):
        (self.evidence / "quint/tenure-safety/case.qnt").write_text("different executed model")
        self.refused(judge_quint.TOOL_FAILURE, "executed input differs")

    def test_core_replays_regenerate_their_traces_with_quint(self):
        for name, test in CORE_REPLAYS.items():
            argv = CHECK.command(CASES[name], 'quint', ROOT, None)
            with self.subTest(name=name):
                self.assertIn('--ignored', argv)
                self.assertEqual(argv[argv.index('--exact') + 1], test)

    def assert_fixtures_bind(self, fixtures, key, declared, name, fields):
        """The committed traces pass; each drifted field, a truncated trace, a malformed trace and an undeclared trace are refused."""
        source = ROOT / 'quint'
        CHECK.verify_fixtures(fixtures, source, key, declared)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for path in fixtures.glob('*.itf.json'):
                (directory / path.name).write_text(path.read_text())
            path = directory / f'{name}.itf.json'
            original = path.read_text()
            for field, value in fields:
                data = json.loads(original)
                data['#meta'][key][field] = value
                path.write_text(json.dumps(data))
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'drifted'):
                    CHECK.verify_fixtures(directory, source, key, declared)
            data = json.loads(original)
            data['states'] = data['states'][:1]
            path.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, 'final action'):
                CHECK.verify_fixtures(directory, source, key, declared)
            for malformed in ('{"states": []}', '{"#meta": {}, "states": []}', f'{{"#meta": {{"{key}": []}}, "states": []}}', 'not json'):
                path.write_text(malformed)
                with self.subTest(malformed=malformed), self.assertRaisesRegex(ValueError, 'malformed'):
                    CHECK.verify_fixtures(directory, source, key, declared)
            path.write_text(original)
            (directory / 'extra.itf.json').write_text(original)
            with self.assertRaisesRegex(ValueError, 'names differ'):
                CHECK.verify_fixtures(directory, source, key, declared)

    def test_core_fixtures_bind_model_recipes_and_final_action(self):
        recipe = CHECK.detect_route_checks.fixture_recipes('route')['conflict_ab']
        self.assert_fixtures_bind(ROOT / CHECK.DETECT_ROUTE_FIXTURES, 'cores', CHECK.detect_route_checks.fixtures(),
                                  'conflict_ab', (('model_sha256', '0' * 64), ('recipe', recipe[::-1])))

    def test_fill_burst_watchdog_settle_and_put_fixtures_bind_model_recipes_seeds_steps_and_final_action(self):
        generators = {'fill': CHECK.fill_checks,
                      'put': CHECK.put_checks,
                      'burst': judge_quint.load('burst_fixtures', ROOT / 'quint/burst_fixtures.py'),
                      'watchdog': judge_quint.load('watchdog_fixtures', ROOT / 'quint/watchdog_fixtures.py'),
                      'settle': judge_quint.load('settle_fixtures', ROOT / 'quint/settle_fixtures.py')}
        for key, generator in generators.items():
            with self.subTest(family=key):
                seeded = next(name for name, (_, metadata) in generator.fixtures().items() if metadata['recipe'] == [])
                self.assert_fixtures_bind(ROOT / generator.FIXTURES, key, generator.fixtures(), seeded,
                                          (('model_sha256', '0' * 64), ('recipe', ['init']), ('seed', '0x0'), ('steps', 0)))

    def test_creation_fixtures_bind_model_recipes_seeds_and_lengths(self):
        declared = CREATION_FIXTURES.fixtures()
        recipe = declared['racing_attaches'][1]['recipe']
        directory = ROOT / CREATION_FIXTURES.FIXTURES
        self.assert_fixtures_bind(directory, 'creation', declared, 'racing_attaches',
                                  (('model_sha256', '0' * 64), ('recipe', recipe[::-1]), ('steps', len(recipe) - 1)))
        self.assert_fixtures_bind(directory, 'creation', declared, 'step_2185',
                                  (('model_sha256', '0' * 64), ('seed', '0x2186'), ('steps', 0)))

    def test_standbys_fixtures_bind_model_instances_recipes_seeds_and_lengths(self):
        declared = STANDBYS_FIXTURES.fixtures()
        recipe = declared['run_enrollOne'][1]['recipe']
        directory = ROOT / STANDBYS_FIXTURES.FIXTURES
        self.assert_fixtures_bind(directory, 'standbys', declared, 'run_enrollOne',
                                  (('model_sha256', '0' * 64), ('recipe', recipe[::-1]), ('steps', len(recipe) - 1),
                                   ('settings', {}), ('limits', {'cap': 1, 'attach': 9})))
        self.assert_fixtures_bind(directory, 'standbys', declared, 'step_5b20',
                                  (('model_sha256', '0' * 64), ('seed', '0x5b21'), ('steps', 0)))

    def test_loss_fixtures_bind_model_recipes_roots_seeds_and_lengths(self):
        declared = LOSS_FIXTURES.fixtures()
        recipe = declared['run_retirement'][1]['recipe']
        directory = ROOT / LOSS_FIXTURES.FIXTURES
        self.assert_fixtures_bind(directory, 'loss', declared, 'run_retirement',
                                  (('model_sha256', '0' * 64), ('recipe', recipe[::-1]), ('steps', len(recipe) - 1)))
        prefix = declared['step_racing_7900'][1]['prefix']
        self.assert_fixtures_bind(directory, 'loss', declared, 'step_racing_7900',
                                  (('model_sha256', '0' * 64), ('seed', '0x7901'), ('root', 'failed'),
                                   ('prefix', prefix[::-1]), ('steps', 0)))

    def test_detect_witness_fixtures_bind_model_recipes_and_final_action(self):
        declared = WITNESS_FIXTURES.fixtures()
        recipe = declared['ExhaustedThenSilent'][1]['recipe']
        self.assert_fixtures_bind(ROOT / WITNESS_FIXTURES.FIXTURES, 'cores', declared, 'ExhaustedThenSilent',
                                  (('model_sha256', '0' * 64), ('recipe', recipe[::-1])))

    def test_every_model_and_checker_under_quint_is_an_identity_input(self):
        for path in sorted([*(ROOT / 'quint').glob('*.qnt'), *(ROOT / 'quint').glob('*check.py'), *(ROOT / 'quint').glob('*fixtures.py')]):
            with self.subTest(path=path.name):
                self.assertIn(str(path.relative_to(ROOT)), self.identity['models'])

    def test_core_rust_and_fixture_digests_are_identity_inputs(self):
        failover = 'crates/kestrike/src/failover/'
        self.assertIn(failover + 'route.rs', self.identity['models'])
        self.assertIn(failover + 'detect_route_replay_tests.rs', self.identity['models'])
        for name in (failover + 'route.rs', failover + 'detect_route_fixtures/conflict_ab.itf.json'):
            with self.subTest(name=name):
                previous = self.identity['models'][name]
                self.identity['models'][name] = '0' * 64
                self.refused(judge_quint.TOOL_FAILURE, 'changed since the identity')
                self.identity['models'][name] = previous

    def test_the_ownership_codec_is_an_identity_input(self):
        ownership = 'crates/kestrike/src/net/ownership.rs'
        self.assertIn(ownership, self.identity['models'])
        self.identity['models'][ownership] = '0' * 64
        self.refused(judge_quint.TOOL_FAILURE, 'changed since the identity')

    def test_the_compiled_packages_are_identity_and_receipt_inputs(self):
        sources = ("crates/kestrike/src/storage/publish.rs", "crates/kestrike/src/sim/round.rs",
                   "crates/kestrike/src/net/q1_replay_tests.rs", "crates/kestrike/src/storage/record/layout.rs",
                   "crates/kestrike/src/storage/recovery/layout.rs", "crates/spdk-sys/src/lib.rs",
                   "crates/kestrike/Cargo.toml", "Cargo.toml")
        self.write()
        _, receipt = judge_quint.derive(self.evidence, "0" * 40)
        for name in sources:
            with self.subTest(name=name):
                self.assertIn(name, self.identity["models"])
                self.assertEqual(receipt["inputs"][name], judge_quint.sha256(ROOT / name))
                previous = self.identity["models"][name]
                self.identity["models"][name] = "0" * 64
                self.refused(judge_quint.TOOL_FAILURE, "changed since the identity")
                self.identity["models"][name] = previous

    def test_every_model_a_case_reads_and_every_family_runner_is_an_identity_and_receipt_input(self):
        models = ROOT / "quint"
        read = {"quint/check.py"}
        for case in CASES.values():
            read.update(f"quint/{name}" for name in CHECK.inputs(case, models) if (models / name).is_file())
            family = CHECK.family_checks(case)
            if family is not None:
                read.add(str(Path(family.__file__).relative_to(ROOT)))
        self.assertIn("quint/settle.qnt", read)
        self.assertIn("quint/settle_check.py", read)
        self.write()
        _, receipt = judge_quint.derive(self.evidence, "0" * 40)
        for name in sorted(read):
            with self.subTest(name=name):
                self.assertTrue(name in self.identity["models"], f"{name} is no identity input")
                self.assertEqual(receipt["inputs"].get(name), judge_quint.sha256(ROOT / name))
        self.identity["models"]["quint/settle_check.py"] = "0" * 64
        self.refused(judge_quint.TOOL_FAILURE, "changed since the identity")

    def test_the_fill_burst_and_watchdog_models_and_check_modules_are_identity_and_receipt_inputs(self):
        sources = [f"quint/{family}{suffix}" for family in ("fill", "burst", "watchdog") for suffix in (".qnt", "_check.py")]
        self.write()
        _, receipt = judge_quint.derive(self.evidence, "0" * 40)
        for name in sources:
            with self.subTest(name=name):
                self.assertIn(name, self.identity["models"])
                self.assertEqual(receipt["inputs"][name], judge_quint.sha256(ROOT / name))
                previous = self.identity["models"][name]
                self.identity["models"][name] = "0" * 64
                self.refused(judge_quint.TOOL_FAILURE, "changed since the identity")
                self.identity["models"][name] = previous

    def test_every_tracked_model_and_script_under_quint_is_an_identity_and_receipt_input(self):
        listed = subprocess.run(["git", "-C", str(ROOT), "ls-files", "--", "quint/*.qnt", "quint/*.py"],
                                capture_output=True, text=True, check=True).stdout.split()
        self.assertIn("quint/check.py", listed)
        self.write()
        _, receipt = judge_quint.derive(self.evidence, "0" * 40)
        for name in listed:
            with self.subTest(name=name):
                self.assertIn(name, self.identity["models"])
                self.assertEqual(receipt["inputs"][name], judge_quint.sha256(ROOT / name))

    def test_a_package_listing_git_refuses_is_a_tool_failure(self):
        self.write()
        with mock.patch.object(subprocess, "run", side_effect=OSError("no git")):
            report, receipt = judge_quint.derive(self.evidence, "0" * 40)
        self.assertEqual(report["code"], judge_quint.TOOL_FAILURE)
        self.assertIn("git ls-files", report["reason"])
        self.assertEqual(receipt["executions"], 0)

    def test_a_missing_model_source_is_a_tool_failure(self):
        self.write()
        missing = ROOT / "crates/kestrike/src/net/absent.rs"
        with mock.patch.object(judge_quint, "model_files", lambda original=judge_quint.model_files: [*original(), missing]):
            report, receipt = judge_quint.derive(self.evidence, "0" * 40)
        self.assertEqual(report["code"], judge_quint.TOOL_FAILURE)
        self.assertIn("absent.rs", report["reason"])
        self.assertEqual(receipt["executions"], 0)

    def test_receipt_revision_must_equal_the_runner_revision(self):
        self.write()
        report, receipt = judge_quint.derive(self.evidence, "1" * 40)
        self.assertEqual(report["code"], judge_quint.TOOL_FAILURE)
        self.assertIn("runner revision", report["reason"])
        self.assertEqual(receipt["executions"], 0)

    def write(self):
        (self.evidence / "identity.json").write_text(json.dumps(self.identity))
        (self.evidence / "pins.txt").write_text("- quint\n")
        (self.evidence / "quint.argv").write_text("\n".join(self.argv) + "\n")
        (self.evidence / "quint.exit").write_text(f"{self.exit}\n")
        (self.evidence / "quint.txt").write_text("All expected outcomes verified.\n")
        (self.evidence / "results.json").write_text(json.dumps({
            "quint": self.version, "runtime": self.runtime, "results": list(self.results.values()),
            "complete": self.complete, "failure": self.failure, "dirty": self.dirty, "revision": "0" * 40}))

    def judge(self):
        self.write()
        result = subprocess.run([sys.executable, str(SCRIPT), "judge", "--evidence", str(self.evidence), "--revision", "0" * 40],
                                capture_output=True, text=True, check=False)
        report = json.loads((self.evidence / "report.json").read_text())
        self.assertEqual(result.returncode, report["code"], result.stderr)
        return report

    def refused(self, code, text):
        report = self.judge()
        self.assertEqual(report["code"], code, report)
        self.assertIn(text, report["reason"])
        self.assertFalse(report["credited"])
        receipt = json.loads((self.evidence / "receipt.json").read_text())
        self.assertEqual((receipt["executions"], receipt["executed"]), (0, []))

    def test_the_declaration_lists_every_runner_case(self):
        self.assertEqual(sorted(EXPECTED["tests"]), sorted(CASES))
        self.assertEqual(len(EXPECTED["tests"]), len(set(EXPECTED["tests"])))

    def test_the_lockfile_pins_every_dependency_and_quint_to_the_declared_archive(self):
        manifest = json.loads((ROOT / "verification/quint/package.json").read_text())
        lock = json.loads((ROOT / "verification/quint/package-lock.json").read_text())
        self.assertEqual(manifest["dependencies"], {"@informalsystems/quint": "file:quint.tgz"})
        self.assertEqual(lock["packages"][""]["dependencies"], manifest["dependencies"])
        quint = lock["packages"]["node_modules/@informalsystems/quint"]
        self.assertEqual((quint["version"], quint["resolved"]), (EXPECTED["quint"]["version"], "file:quint.tgz"))
        for name, entry in lock["packages"].items():
            if name:
                with self.subTest(package=name):
                    self.assertTrue(entry.get("integrity", "").startswith("sha512-"), entry)
                    self.assertTrue(entry.get("resolved", "").startswith(("https://registry.npmjs.org/", "file:quint.tgz")), entry)

    def test_complete_evidence_credits_every_case_with_its_bounds(self):
        report = self.judge()
        self.assertTrue(report["credited"], report)
        self.assertEqual(sorted(report["cases"]), sorted(CASES))
        self.assertEqual(report["cases"]["broken-progress"]["lasso"], [3, 4])
        self.assertEqual(report["cases"]["simulation"]["traces"], int(CHECK.SAMPLES))
        receipt = json.loads((self.evidence / "receipt.json").read_text())
        self.assertEqual((receipt["job"], receipt["module"], receipt["completion"]), ("quint", None, "completed"))
        self.assertEqual(receipt["executed"], sorted(set(CASES) - set(EXPECTED.get("blocked", {}))))
        premises = [line for line in receipt["assumptions"] if line.startswith("preserve ")]
        self.assertEqual(len(premises), 3, receipt["assumptions"])
        for name in ("END-self", "END-foreign", "NEW-EXCLUSION", "DURABLE", "EXPIRY-CLOCK", "RESTORE",
                     "U4", "NoPreemptOfForeignKey", "lineage registrant set"):
            self.assertIn(name, " ".join(premises))
        suffix = [line for line in receipt["assumptions"] if line.startswith("suffix ")]
        self.assertEqual(len(suffix), 1, receipt["assumptions"])
        for name in ("END", "DURABLE", "NEW-EXCLUSION"):
            self.assertIn(name, suffix[0])
        saturation = [line for line in receipt["assumptions"] if line.startswith("saturation ")]
        self.assertEqual(len(saturation), 1, receipt["assumptions"])
        for name in ("typed state", "LSNs 0 to 5", "region of two blocks", "END", "no refinement"):
            self.assertIn(name, saturation[0])
        join = [line for line in receipt["assumptions"] if line.startswith("join ")]
        self.assertEqual(len(join), 1, receipt["assumptions"])
        for name in ("imported as instances", "one action of each", "declared prefix root", "up to the case's BOUND",
                     "stated reductions", "no inductive or refinement proof"):
            self.assertIn(name, join[0])
        self.assertEqual(receipt["inputs"]["report.json"], hashlib.sha256((self.evidence / "report.json").read_bytes()).hexdigest())

    def test_a_missing_or_repeated_case_is_a_tool_failure(self):
        del self.results["safety"]
        self.refused(judge_quint.TOOL_FAILURE, "miss ['safety']")
        self.setUp()
        self.write()
        repeated = list(self.results.values()) + [self.results["progress"]]
        (self.evidence / "results.json").write_text(json.dumps({"quint": self.version, "runtime": self.runtime, "results": repeated,
                                                                "complete": True, "failure": None, "dirty": [], "revision": "0" * 40}))
        result = subprocess.run([sys.executable, str(SCRIPT), "judge", "--evidence", str(self.evidence), "--revision", "0" * 40],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, judge_quint.TOOL_FAILURE)
        self.assertIn("repeat a case", json.loads((self.evidence / "report.json").read_text())["reason"])

    def test_each_tool_other_than_the_declared_one_is_drift(self):
        for tool, field, value, text in [
            ("java", "version", 'openjdk version "17.0.1"', "java reports"),
            ("java", "install", {"sha256": "0" * 64}, "JDK install tree"),
            ("node", "version", "v18.0.0", "node reports"),
            ("node", "install", {"sha256": "0" * 64}, "Node.js install tree"),
            ("apalache", "install", {"sha256": "0" * 64}, "Apalache install tree"),
            ("quint", "version", "0.32.0", "quint '0.32.0'"),
            ("quint", "install", {"sha256": "0" * 64}, "node_modules tree differs"),
            ("quint", "apalache", "0.61.0", "launches Apalache '0.61.0'"),
        ]:
            with self.subTest(tool=tool, field=field):
                self.setUp()
                self.identity[tool][field] = value
                self.refused(judge_quint.TOOL_FAILURE, text)

    def test_the_identity_binds_the_whole_apalache_distribution(self):
        root = Path(self.temp.name) / "tools"
        dist = root / f"home/apalache-dist-{EXPECTED['apalache']['version']}"
        programs = {"jdk/bin/java": f'echo \'openjdk version "{EXPECTED["java"]["version"]}"\' >&2',
                    "node/bin/node": f"echo {EXPECTED['node']['version']}",
                    "npm/node_modules/.bin/quint": f"echo {EXPECTED['quint']['version']}",
                    f"{dist.relative_to(root)}/apalache/bin/apalache-mc": "exec java -jar apalache.jar \"$@\""}
        for name, body in programs.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(f"#!/bin/sh\n{body}\n")
            (root / name).chmod(0o755)
        (dist / "apalache/lib").mkdir()
        (dist / "apalache/lib/apalache.jar").write_bytes(b"jar")
        tag = root / "npm/node_modules/@informalsystems/quint/dist/src/apalache.js"
        tag.parent.mkdir(parents=True)
        tag.write_text(f"exports.DEFAULT_APALACHE_VERSION_TAG = '{EXPECTED['apalache']['version']}';\n")

        def apalache():
            subprocess.run([sys.executable, str(SCRIPT), "identity", "--java", str(root / "jdk/bin/java"),
                            "--node", str(root / "node/bin/node"), "--apalache", str(dist),
                            "--quint", str(root / "npm/node_modules/.bin/quint"), "--evidence", str(self.evidence)],
                           capture_output=True, text=True, check=True)
            return json.loads((self.evidence / "identity.json").read_text())["apalache"]

        before = apalache()
        self.assertEqual((before["path"], before["install"]["files"]), (str(dist), 2))
        (dist / "apalache/bin/apalache-mc").write_text("#!/bin/sh\nexec java -jar /tmp/other.jar \"$@\"\n")
        self.assertNotEqual(apalache()["install"]["sha256"], before["install"]["sha256"])

    def test_a_model_changed_since_the_identity_is_drift(self):
        self.assertIn("quint/session.qnt", self.identity["models"])
        self.identity["models"]["quint/session.qnt"] = "0" * 64
        self.refused(judge_quint.TOOL_FAILURE, "changed since the identity")

    def test_another_command_is_a_tool_failure(self):
        for change in (lambda argv: argv.__setitem__(0, "/usr/bin/python2"), lambda argv: argv.__setitem__(3, "/opt/other/quint"),
                       lambda argv: argv.__setitem__(5, "1"), lambda argv: argv.__setitem__(7, "/tmp/elsewhere"),
                       lambda argv: argv.append("--case")):
            with self.subTest(change=change):
                self.setUp()
                change(self.argv)
                self.refused(judge_quint.TOOL_FAILURE, "runner command differs")

    def test_an_interrupted_run_is_incomplete(self):
        for code in judge_quint.INTERRUPTED:
            with self.subTest(code=code):
                self.setUp()
                self.exit = code
                self.refused(judge_quint.INCOMPLETE, "interrupted")
                receipt = json.loads((self.evidence / "receipt.json").read_text())
                self.assertEqual(receipt["completion"], "timeout")

    def test_an_incomplete_failed_or_edited_runner_record_is_a_mismatch(self):
        self.complete = False
        self.refused(judge_quint.MISMATCH, "is incomplete")
        self.setUp()
        self.failure = {"case": "safety", "reason": "x"}
        self.refused(judge_quint.MISMATCH, "names a failure")
        self.setUp()
        self.dirty = [" M crates/kestrike/src/net/session.rs"]
        self.refused(judge_quint.MISMATCH, "modified tracked files")

    def test_a_runner_failure_is_a_mismatch(self):
        self.exit = 1
        self.complete = False
        self.failure = {"case": "safety", "reason": "safety: expected a completed check without violation (exit 1)"}
        self.refused(judge_quint.MISMATCH, "refused safety by its outcome")

    def test_a_runner_exit_without_a_recorded_case_failure_is_a_tool_failure(self):
        for code, results in ((2, False), (1, False), (1, True)):
            with self.subTest(code=code, results=results):
                self.setUp()
                self.exit = code
                self.complete = False
                self.write()
                if not results:
                    (self.evidence / "results.json").unlink()
                result = subprocess.run([sys.executable, str(SCRIPT), "judge", "--evidence", str(self.evidence),
                                         "--revision", "0" * 40], capture_output=True, text=True, check=False)
                report = json.loads((self.evidence / "report.json").read_text())
                self.assertEqual((result.returncode, report["code"]), (judge_quint.TOOL_FAILURE, judge_quint.TOOL_FAILURE))
                self.assertIn(f"exited {code} before recording a case outcome", report["reason"])
                receipt = json.loads((self.evidence / "receipt.json").read_text())
                self.assertEqual((receipt["completion"], receipt["executions"]), ("tool failure", 0))

    def test_a_runner_under_another_jdk_or_quint_is_drift(self):
        self.runtime = 'openjdk version "17.0.1"\n'
        self.refused(judge_quint.TOOL_FAILURE, "ran under")
        self.setUp()
        self.version = "0.32.0"
        self.refused(judge_quint.TOOL_FAILURE, "ran quint")

    def test_a_result_with_another_outcome_command_or_exit_is_a_mismatch(self):
        self.results["safety"]["expected"] = "violation"
        self.refused(judge_quint.MISMATCH, "safety ran")
        self.setUp()
        self.results["safety"]["command"][-1] = "agreement"
        self.refused(judge_quint.MISMATCH, "safety ran")
        self.setUp()
        self.results["progress"]["returncode"] = 1
        self.refused(judge_quint.MISMATCH, "progress exited 1")
        self.setUp()
        self.results["mutant-reuse-epoch"]["returncode"] = 0
        self.refused(judge_quint.MISMATCH, "mutant-reuse-epoch exited 0")

    def test_a_tlc_case_without_its_own_apalache_port_is_a_mismatch(self):
        for name, port in (("safety", None), ("safety", "40000"), ("safety", True), ("safety", 0), ("safety", 65536),
                           ("typecheck", 40000), ("simulation", 40000)):
            with self.subTest(name=name, port=port):
                self.setUp()
                self.results[name]["port"] = port
                self.refused(judge_quint.MISMATCH, f"{name} names port {port!r}")
        self.setUp()
        self.results["safety"]["port"] += 1
        self.refused(judge_quint.MISMATCH, "safety ran")

    def test_a_model_or_instance_other_than_the_runners_is_drift(self):
        self.results["mutant-hello-drops-active"]["inputs"]["session.qnt"] = digest((ROOT / "quint/session.qnt").read_text())
        self.refused(judge_quint.TOOL_FAILURE, "mutant-hello-drops-active checked a model")
        self.setUp()
        self.results["safety"]["inputs"]["case.qnt"] = digest(CHECK.instance(CASES["progress"]))
        self.refused(judge_quint.TOOL_FAILURE, "safety checked a model or an instance")
        self.setUp()
        self.results["connect-replay"]["inputs"]["replay.qnt"] = digest(CHECK.instance(CASES["safety"]))
        self.refused(judge_quint.TOOL_FAILURE, "connect-replay checked a model or an instance")

    def test_a_check_without_states_or_counterexample_is_a_mismatch(self):
        self.results["safety"]["states"] = [0, 0, 0]
        self.refused(judge_quint.MISMATCH, "summary differs from raw evidence")
        self.setUp()
        del self.results["reach-witnessRestart"]["trace"]
        self.refused(judge_quint.MISMATCH, "summary differs from raw evidence")

    def test_the_broken_variant_needs_its_loop_and_only_it_has_one(self):
        del self.results["broken-progress"]["lasso"]
        self.refused(judge_quint.MISMATCH, "summary differs from raw evidence")
        self.setUp()
        self.results["mutant-reuse-epoch"]["lasso"] = [1, 2]
        self.refused(judge_quint.MISMATCH, "mutant-reuse-epoch adds the broken variant's loop")

    def test_a_simulation_short_of_its_traces_or_witnesses_is_a_mismatch(self):
        self.results["simulation"]["traces"] = 3
        self.refused(judge_quint.MISMATCH, "summary differs from raw evidence")
        self.setUp()
        del self.results["simulation"]["witnessed"]["witnessRestart"]
        self.refused(judge_quint.MISMATCH, "summary differs from raw evidence")

    def test_a_connect_replay_short_of_its_traces_is_a_mismatch(self):
        self.results["connect-replay"]["traces"] = CHECK.REPLAY_TRACES - 1
        self.refused(judge_quint.MISMATCH, "summary differs from raw evidence")
        self.setUp()
        self.results["connect-replay"]["actions"] = CHECK.REPLAY_TRACES
        self.refused(judge_quint.MISMATCH, "summary differs from raw evidence")
        self.setUp()
        self.results["connect-replay"]["per_action"]["rekey"] = 0
        self.refused(judge_quint.MISMATCH, "summary differs from raw evidence")

    def test_malformed_results_are_a_tool_failure_with_a_report(self):
        self.results["safety"]["states"] = [10]
        report = self.judge()
        self.assertEqual(report["code"], judge_quint.MISMATCH)
        self.assertIn("summary differs from raw evidence", report["reason"])

    def test_an_extra_result_is_a_tool_failure(self):
        self.results["extra"] = {**self.results["safety"], "case": "extra"}
        self.refused(judge_quint.TOOL_FAILURE, "add ['extra']")

    def test_missing_evidence_files_are_tool_failures(self):
        for name in ("quint.argv", "quint.exit", "results.json", "identity.json"):
            with self.subTest(name=name):
                self.setUp()
                self.write()
                (self.evidence / name).unlink()
                result = subprocess.run([sys.executable, str(SCRIPT), "judge", "--evidence", str(self.evidence),
                                         "--revision", "0" * 40], capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, judge_quint.TOOL_FAILURE, name)

    def test_a_declaration_other_than_the_runners_cases_is_a_tool_failure(self):
        self.write()
        expected = {**EXPECTED, "tests": [*EXPECTED["tests"], "extra"]}
        with self.assertRaises(judge_quint.Refusal) as refusal:
            judge_quint.judge(self.evidence, expected, self.identity)
        self.assertEqual(refusal.exception.code, judge_quint.TOOL_FAILURE)
        self.assertIn("['extra'] the runner lacks", str(refusal.exception))

    def pinned(self, edit):
        """Judge the complete evidence under a copy of the registry whose `cases` map `edit` changes, and return the
        refusal."""
        self.write()
        expected = copy.deepcopy(EXPECTED)
        edit(expected["cases"])
        with self.assertRaises(judge_quint.Refusal) as refusal:
            judge_quint.judge(self.evidence, expected, self.identity, "0" * 40)
        return refusal.exception

    def test_the_judge_applies_the_registry_checks_to_a_run(self):
        refusal = self.pinned(lambda cases: cases.pop("safety"))
        self.assertEqual(refusal.code, judge_quint.TOOL_FAILURE)
        self.assertIn("the registry's cases omit ['safety'] and add []", str(refusal))

    def test_a_fixture_without_a_usable_registry_count_reaches_the_named_drift(self):
        planted = copy.deepcopy(EXPECTED)
        del planted["cases"]["safety"]["distinct"]
        with mock.patch.dict(globals(), {"EXPECTED": planted}):
            self.setUp()
        self.write()
        with self.assertRaisesRegex(judge_quint.Refusal, "safety: the registry pins no count on a passing TLC check"):
            judge_quint.judge(self.evidence, planted, self.identity, "0" * 40)

    def test_a_violation_log_without_an_explored_state_is_a_mismatch(self):
        name = "mutant-reuse-epoch"
        log = self.evidence / "quint" / name / "quint.log"
        original = log.read_text()
        for planted in (original.replace(" 7 distinct states", " 0 distinct states"),
                        "".join(line + "\n" for line in original.splitlines() if "distinct states found" not in line)):
            with self.subTest(log=planted):
                log.write_text(planted)
                self.results[name]["states"] = [17, 0, 0] if " 0 distinct" in planted else None
                self.refused(judge_quint.MISMATCH, f"{name}: TLC reports no explored state")

    def test_a_retained_input_with_other_bytes_than_the_runners_is_a_tool_failure(self):
        instance = self.evidence / "quint/safety/case.qnt"
        instance.write_bytes(instance.read_bytes().replace(b"\n", b"\r\n"))
        self.refused(judge_quint.TOOL_FAILURE, "safety: executed input differs from the declared instance")
        (self.evidence / "report.json").unlink()
        (self.evidence / "receipt.json").unlink()
        code, stdout, stderr = self.print_pins()
        self.assertEqual((code, stdout), (judge_quint.TOOL_FAILURE, ""))
        self.assertIn("safety: executed input differs", stderr)

    def test_a_missing_retained_input_is_a_tool_failure(self):
        (self.evidence / "quint/safety/case.qnt").unlink()
        self.refused(judge_quint.TOOL_FAILURE, "safety retains no case.qnt")

    def test_a_recorded_time_other_than_a_finite_count_of_seconds_is_a_tool_failure(self):
        """An integer past the largest finite float is refused with the report and receipt written, as infinity is."""
        for seconds in (float("inf"), float("nan"), -1.0, "1.0", None, True, 10 ** 400):
            with self.subTest(seconds=seconds):
                self.results["safety"]["seconds"] = seconds
                self.refused(judge_quint.TOOL_FAILURE, "malformed evidence: safety records")

    def test_a_simulation_whose_average_trace_length_is_not_finite_is_a_tool_failure(self):
        """A log average of 310 digits reads as infinity. A summary that records the same infinity agrees with the log,
        and the judge refuses it, so no receipt holds a token outside RFC 8259 JSON."""
        log = self.evidence / "quint/simulation/quint.log"
        log.write_text(log.read_text().replace("average=41.0", "average=1" + "0" * 309))
        self.results["simulation"]["lengths"]["average"] = float("inf")
        self.refused(judge_quint.TOOL_FAILURE, "malformed evidence: simulation records an average trace length of inf")
        self.assertNotIn("Infinity", (self.evidence / "receipt.json").read_text())

    def test_a_repeated_name_in_an_evidence_file_is_a_tool_failure(self):
        self.write()
        results = self.evidence / "results.json"
        text = results.read_text()
        self.assertTrue(text.startswith('{"quint": '))
        results.write_text('{"quint": "0.0.0", ' + text[1:])
        report, receipt = judge_quint.derive(self.evidence, "0" * 40)
        self.assertEqual((report["code"], receipt["executions"]), (judge_quint.TOOL_FAILURE, 0))
        self.assertIn("the object repeats ['quint']", report["reason"])

    def test_an_unresolvable_path_is_a_tool_failure(self):
        self.write()
        looped = self.evidence / "quint"
        shutil.rmtree(looped)
        looped.symlink_to(looped)
        report, receipt = judge_quint.derive(self.evidence, "0" * 40)
        self.assertEqual((report["code"], receipt["executions"]), (judge_quint.TOOL_FAILURE, 0))
        self.assertIn(f"{looped} cannot be resolved", report["reason"])
        code, stdout, stderr = self.print_pins()
        self.assertEqual((code, stdout), (judge_quint.TOOL_FAILURE, ""))
        self.assertIn("cannot be resolved", stderr)

    def test_a_runner_that_fails_to_load_is_a_tool_failure(self):
        self.write()
        broken = Path(self.temp.name) / "broken.py"
        for error in ("ImportError('no family module')", "NameError('undefined')", "SyntaxError('invalid syntax')"):
            with self.subTest(error=error):
                broken.write_text(f"raise {error}\n")
                with mock.patch.object(judge_quint, "runner", lambda: judge_quint.load("broken_runner", broken)):
                    report, receipt = judge_quint.derive(self.evidence, "0" * 40)
                    code, stdout, stderr = self.print_pins()
                self.assertEqual((report["code"], receipt["executions"]), (judge_quint.TOOL_FAILURE, 0))
                self.assertIn(f"{broken} fails to load: {error.split('(')[0]}", report["reason"])
                self.assertEqual((code, stdout), (judge_quint.TOOL_FAILURE, ""))
                self.assertIn("fails to load", stderr)
        broken.write_text("raise ImportError('no family module')\n")
        calls = []

        def second_load_fails():
            calls.append(None)
            return CHECK if len(calls) <= 2 else judge_quint.load("broken_runner", broken)

        with mock.patch.object(judge_quint, "runner", second_load_fails):
            report, receipt = judge_quint.derive(self.evidence, "0" * 40)
        self.assertEqual(len(calls), 3)
        self.assertEqual((report["code"], receipt["executions"]), (judge_quint.TOOL_FAILURE, 0))
        self.assertIn("fails to load: ImportError", report["reason"])

    def test_a_fixture_nested_past_the_recursion_limit_is_a_tool_failure(self):
        self.write()
        with mock.patch.object(judge_quint, "runner", lambda: CHECK), \
                mock.patch.object(CHECK, "verify_fixtures", side_effect=RecursionError("maximum recursion depth exceeded")):
            report, receipt = judge_quint.derive(self.evidence, "0" * 40)
            code, stdout, _ = self.print_pins()
        self.assertEqual((report["code"], receipt["executions"]), (judge_quint.TOOL_FAILURE, 0))
        self.assertIn("malformed evidence: RecursionError", report["reason"])
        self.assertEqual((code, stdout), (judge_quint.TOOL_FAILURE, ""))

    def test_the_unpinned_mode_is_selected_by_name_alone(self):
        for call in (lambda: judge_quint.derive(self.evidence, "0" * 40, None),
                     lambda: judge_quint.judge(self.evidence, EXPECTED, self.identity, "0" * 40, False),
                     lambda: judge_quint.declared_cases(EXPECTED, False)):
            with self.subTest(call=call), self.assertRaises(TypeError):
                call()

    def test_a_count_off_its_pin_with_the_evidence_unchanged_is_a_mismatch(self):
        pin = EXPECTED["cases"]["safety"]["distinct"]
        refusal = self.pinned(lambda cases: cases["safety"].update(distinct=pin + 1))
        self.assertEqual(refusal.code, judge_quint.MISMATCH)
        self.assertIn(f"safety's quint.log records {pin} distinct states, the registry pins {pin + 1}", str(refusal))

    def pins(self, write=True):
        if write:
            self.write()
        return subprocess.run([sys.executable, str(SCRIPT), "pins", "--evidence", str(self.evidence), "--revision", "0" * 40],
                              capture_output=True, text=True, check=False)

    def print_pins(self):
        """Run `pins` in process on the written evidence and return its exit code, stdout and stderr."""
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = judge_quint.print_pins(self.evidence, "0" * 40)
        return code, stdout.getvalue(), stderr.getvalue()

    def assert_no_judge_output(self):
        for name in ("report.json", "receipt.json"):
            self.assertFalse((self.evidence / name).exists(), name)

    def test_pins_prints_every_entry_with_the_count_its_log_records(self):
        result = self.pins()
        self.assertEqual(result.returncode, judge_quint.CREDITED, result.stderr)
        self.assert_no_judge_output()
        lines = (ROOT / "verification/quint/expected.json").read_text().splitlines()
        start = lines.index('  "cases": {')
        self.assertEqual(result.stdout, "\n".join(lines[start + 1:start + 1 + len(CASES)]) + "\n")
        pin = EXPECTED["cases"]["safety"]["distinct"]
        log = self.evidence / "quint/safety/quint.log"
        log.write_text(log.read_text().replace(f" {pin} distinct states", f" {pin + 5} distinct states"))
        self.results["safety"]["states"][1] = float(pin + 5)
        self.refused(judge_quint.MISMATCH, f"safety's quint.log records {pin + 5} distinct states")
        written = {name: (self.evidence / name).read_bytes() for name in ("report.json", "receipt.json")}
        result = self.pins(write=False)
        self.assertEqual(result.returncode, judge_quint.CREDITED, result.stderr)
        self.assertIn(f'    "safety": {{"outcome": "ok safety", "distinct": {pin + 5}}}',
                      [line.rstrip(",") for line in result.stdout.splitlines()])
        self.assertEqual({name: (self.evidence / name).read_bytes() for name in written}, written)

    def test_pins_leaves_out_the_registry_comparisons_alone(self):
        self.write()
        read_json = judge_quint.read_json
        stale = {**EXPECTED, "cases": {}}
        with mock.patch.object(judge_quint, "read_json",
                               lambda path: stale if path == judge_quint.EXPECTED else read_json(path)):
            self.assertEqual(json.loads("{" + judge_quint.pins(self.evidence, "0" * 40) + "}"), EXPECTED["cases"])
        for edit, code, text in ((lambda: setattr(self, "exit", 143), judge_quint.INCOMPLETE, "interrupted"),
                                 (lambda: setattr(self, "complete", False), judge_quint.MISMATCH, "incomplete"),
                                 (lambda: self.results["mutant-reuse-epoch"].update(returncode=0), judge_quint.MISMATCH,
                                  "mutant-reuse-epoch exited 0"),
                                 (lambda: setattr(self, "results", {**self.results, "safety": "safety"}), judge_quint.TOOL_FAILURE,
                                  "malformed evidence"),
                                 (lambda: self.identity["node"].update(version="v18.0.0"), judge_quint.TOOL_FAILURE,
                                  "node reports")):
            with self.subTest(text=text):
                self.setUp()
                edit()
                result = self.pins()
                self.assertEqual((result.returncode, result.stdout), (code, ""))
                self.assertIn(text, result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assert_no_judge_output()

    def test_pins_refuses_what_the_judge_refuses_apart_from_the_cases_map(self):
        self.write()
        (self.evidence / "pins.txt").write_bytes(b"\xff\xfe")
        self.assertEqual(subprocess.run([sys.executable, str(SCRIPT), "judge", "--evidence", str(self.evidence),
                                         "--revision", "0" * 40], capture_output=True, text=True,
                                        check=False).returncode, judge_quint.TOOL_FAILURE)
        (self.evidence / "report.json").unlink()
        (self.evidence / "receipt.json").unlink()
        result = self.pins(write=False)
        self.assertEqual((result.returncode, result.stdout), (judge_quint.TOOL_FAILURE, ""))
        self.assertIn("unreadable receipt input", result.stderr)
        self.assert_no_judge_output()
        self.write()
        missing = ROOT / "crates/kestrike/src/net/absent.rs"
        with mock.patch.object(judge_quint, "model_files", lambda original=judge_quint.model_files: [*original(), missing]):
            code, stdout, stderr = self.print_pins()
        self.assertEqual((code, stdout), (judge_quint.TOOL_FAILURE, ""))
        self.assertIn("unreadable input", stderr)
        self.assertIn("absent.rs", stderr)
        read_json = judge_quint.read_json
        for registry, text in (({**EXPECTED, "tests": [*EXPECTED["tests"], "extra"]}, "['extra'] the runner lacks"),
                               ({**EXPECTED, "blocked": {**EXPECTED["blocked"], "safety": ""}},
                                "undeclared case or empty gate")):
            with self.subTest(text=text), mock.patch.object(
                    judge_quint, "read_json", lambda path, registry=registry: registry if path == judge_quint.EXPECTED
                    else read_json(path)):
                code, stdout, stderr = self.print_pins()
            self.assertEqual((code, stdout), (judge_quint.TOOL_FAILURE, ""))
            self.assertIn(text, stderr)

    def test_staged_trees_other_than_the_declared_ones_are_refused(self):
        tree = Path(self.temp.name) / "tree"
        tree.mkdir()
        (tree / "file").write_text("x")
        result = subprocess.run([sys.executable, str(SCRIPT), "trees", "--node", str(tree), "--modules", str(tree)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, judge_quint.TOOL_FAILURE)
        self.assertIn("staged node tree digests", result.stderr)

    def test_a_registry_without_an_object_install_declaration_is_refused_by_trees(self):
        tree = Path(self.temp.name) / "tree"
        tree.mkdir()
        read_json = judge_quint.read_json
        for tool, value in (("node", None), ("node", ["install"]), ("quint", "install")):
            with self.subTest(tool=tool, value=value), mock.patch.object(
                    judge_quint, "read_json", lambda path, tool=tool, value=value: {**read_json(path), tool: value}), \
                    self.assertRaisesRegex(judge_quint.Refusal, "declares no node or quint install digest"):
                judge_quint.trees(argparse.Namespace(node=str(tree), modules=str(tree)))

    def test_a_report_the_judge_cannot_write_exits_2_without_a_receipt(self):
        self.write()
        report = self.evidence / "report.json"
        report.mkdir()
        result = subprocess.run([sys.executable, str(SCRIPT), "judge", "--evidence", str(self.evidence), "--revision", "0" * 40],
                                capture_output=True, text=True, check=False)
        report.rmdir()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertTrue(result.stderr.startswith("judge-quint: "), result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse((self.evidence / "receipt.json").exists())


class Registry(unittest.TestCase):
    """The committed registry restates the runner's cases, and the judge's registry and JSON readers refuse by name."""

    def test_the_registry_restates_every_runner_case_with_its_outcome_and_count(self):
        self.assertEqual(EXPECTED["cases"], {name: judge_quint.entry(case, EXPECTED["cases"][name].get("distinct"))
                                             for name, case in CASES.items()})
        counted = sorted(name for name, case in CASES.items() if judge_quint.counted(case))
        self.assertEqual(sorted(name for name, pin in EXPECTED["cases"].items() if "distinct" in pin), counted)
        self.assertLessEqual(set(EXPECTED["blocked"]), set(EXPECTED["cases"]))
        for name in ("typecheck", "connect-replay", "binder-replay", "simulation"):
            self.assertEqual(judge_quint.entry(CASES[name]), {"outcome": "ok"}, name)
        self.assertEqual(judge_quint.entry(CASES["mutant-reuse-epoch"]), {"outcome": "violation distinctEpochs"})
        self.assertEqual(judge_quint.entry(CASES["safety"], 5), {"outcome": "ok safety", "distinct": 5})

    def test_each_registry_entry_takes_one_line(self):
        lines = (ROOT / "verification/quint/expected.json").read_text().splitlines()
        start = lines.index('  "cases": {')
        entries = lines[start + 1:start + 1 + len(CASES)]
        self.assertEqual(lines[start + 1 + len(CASES)], "  }")
        self.assertEqual(entries, [f"    {json.dumps(name)}: {json.dumps(EXPECTED['cases'][name])}" + ("," if at < len(CASES) - 1 else "")
                                   for at, name in enumerate(sorted(CASES))])

    def drift(self, edit):
        """Check a copy of the registry whose `cases` map `edit` changes against the runner's cases, and return the
        refusal."""
        expected = copy.deepcopy(EXPECTED)
        edit(expected["cases"])
        with self.assertRaises(judge_quint.Refusal) as refusal:
            judge_quint.declared_cases(expected)
        self.assertEqual(refusal.exception.code, judge_quint.TOOL_FAILURE)
        return str(refusal.exception)

    def test_a_registry_without_an_entry_or_with_a_stray_entry_is_drift(self):
        self.assertIn("the registry's cases omit ['safety'] and add []", self.drift(lambda cases: cases.pop("safety")))
        self.assertIn("the registry's cases omit [] and add ['extra']",
                      self.drift(lambda cases: cases.update(extra={"outcome": "ok"})))
        for registry in ({name: value for name, value in EXPECTED.items() if name != "cases"}, {**EXPECTED, "cases": []}):
            with self.subTest(cases=registry.get("cases", "absent")), \
                    self.assertRaisesRegex(judge_quint.Refusal, "the registry declares no cases map"):
                judge_quint.declared_cases(registry)

    def test_an_outcome_other_than_the_runners_is_drift(self):
        for name, planted, runner in (("mutant-reuse-epoch", "violation agreement", "violation distinctEpochs"),
                                      ("mutant-reuse-epoch", "ok distinctEpochs", "violation distinctEpochs"),
                                      ("typecheck", "violation", "ok")):
            with self.subTest(name=name, outcome=planted):
                self.assertIn(f"{name}: the registry declares outcome {planted!r}, the runner {runner!r}",
                              self.drift(lambda cases, name=name, planted=planted: cases[name].update(outcome=planted)))
        self.assertIn("mutant-reuse-epoch: the registry entry 'violation distinctEpochs' is not a mapping",
                      self.drift(lambda cases: cases.update({"mutant-reuse-epoch": "violation distinctEpochs"})))

    def test_a_missing_count_or_a_count_beside_another_outcome_is_drift(self):
        self.assertIn("safety: the registry pins no count on a passing TLC check",
                      self.drift(lambda cases: cases["safety"].pop("distinct")))
        for name in ("mutant-reuse-epoch", "typecheck", "simulation"):
            with self.subTest(name=name):
                self.assertIn(f"{name}: the registry pins a count on a case other than a passing TLC check",
                              self.drift(lambda cases, name=name: cases[name].update(distinct=7)))

    def test_a_count_other_than_a_positive_integer_or_another_field_is_drift(self):
        for value in (0, True, "7"):
            with self.subTest(value=value):
                self.assertIn(f"safety: the registry count {value!r} is not a positive integer",
                              self.drift(lambda cases, value=value: cases["safety"].update(distinct=value)))
        for name, field in (("safety", "states"), ("typecheck", "note")):
            with self.subTest(name=name, field=field):
                refusal = self.drift(lambda cases, name=name, field=field: cases[name].update({field: 7}))
                self.assertIn(f"{name}: the registry entry", refusal)
                self.assertIn("holds fields other than its outcome and count", refusal)
                self.assertNotIn("positive integer", refusal)

    def test_a_name_the_declaration_repeats_is_drift(self):
        expected = {**EXPECTED, "tests": [*EXPECTED["tests"], "safety"]}
        with self.assertRaises(judge_quint.Refusal) as refusal:
            judge_quint.declared_cases(expected)
        self.assertEqual(refusal.exception.code, judge_quint.TOOL_FAILURE)
        self.assertIn("the declaration names ['safety'] more than once", str(refusal.exception))

    def test_a_registry_whose_root_is_not_an_object_is_a_tool_failure(self):
        with tempfile.TemporaryDirectory(prefix="kestrike-quint-") as temp:
            evidence = Path(temp) / "evidence"
            evidence.mkdir()
            registry = Path(temp) / "expected.json"
            read_json = judge_quint.read_json
            for root in ("[]", "null"):
                with self.subTest(root=root):
                    registry.write_text(root)
                    with self.assertRaises(judge_quint.Refusal) as refusal:
                        read_json(registry)
                    self.assertEqual(refusal.exception.code, judge_quint.TOOL_FAILURE)
                    self.assertIn("the JSON root is not an object", str(refusal.exception))
                    with mock.patch.object(judge_quint, "read_json",
                                           lambda path: read_json(registry if path == judge_quint.EXPECTED else path)):
                        report, receipt = judge_quint.derive(evidence, "0" * 40)
                    self.assertEqual((report["code"], receipt["executions"]), (judge_quint.TOOL_FAILURE, 0))
                    self.assertIn(f"unreadable {registry}: the JSON root is not an object", report["reason"])

    def test_a_repeated_name_in_one_json_object_is_a_tool_failure(self):
        with tempfile.TemporaryDirectory(prefix="kestrike-quint-") as temp:
            path = Path(temp) / "repeated.json"
            for text, names in (('{"cases": {"safety": {"outcome": "ok safety"}, "safety": {"outcome": "ok safety"}}}',
                                 "['safety']"),
                                ('{"b": 1, "a": 1, "b": 2, "a": 2, "b": 3}', "['a', 'b']")):
                with self.subTest(names=names):
                    path.write_text(text)
                    with self.assertRaises(judge_quint.Refusal) as refusal:
                        judge_quint.read_json(path)
                    self.assertEqual(refusal.exception.code, judge_quint.TOOL_FAILURE)
                    self.assertIn(f"the object repeats {names}", str(refusal.exception))

    def test_a_name_the_runner_declares_twice_is_drift(self):
        declared = [*CHECK.cases(), dataclasses.replace(CASES["safety"])]
        with mock.patch.object(judge_quint, "runner", lambda: types.SimpleNamespace(cases=lambda: iter(declared))), \
                self.assertRaises(judge_quint.Refusal) as refusal:
            judge_quint.declared_cases(EXPECTED)
        self.assertEqual(refusal.exception.code, judge_quint.TOOL_FAILURE)
        self.assertIn("the runner declares ['safety'] more than once", str(refusal.exception))

    def test_each_cited_control_entry_is_its_control_text(self):
        cited = {control["test"] for record in OBLIGATIONS["records"] if record["job"] == "quint" for control in record["controls"]}
        self.assertTrue(cited)
        self.assertEqual(cited_controls_unequal_to_their_text(EXPECTED), [])
        planted = copy.deepcopy(EXPECTED)
        planted["cases"]["mutant-reuse-epoch"]["outcome"] = "violation distinctEpochs "
        self.assertIn("mutant-reuse-epoch", cited)
        self.assertEqual(cited_controls_unequal_to_their_text(planted), ["mutant-reuse-epoch"])


class Runner(unittest.TestCase):
    """The runner refuses a log that lacks its case's declared outcome."""

    LOOP = ('State 1: <Initial predicate>\n/\\ q1case_session_last = [ act |-> "deliverToOwner", peer |-> "c1",\n'
            '  pendingDisplaced |-> TRUE ]\n'
            'State 2: <retry>\n/\\ q1case_session_last = [ act |-> "retry", peer |-> "c1", verdict |-> "confirm" ]\n'
            'State 3: <deliverToOwner>\n/\\ q1case_session_last = [ act |-> "deliverToOwner", peer |-> "c1",\n'
            '  frame |-> [ Some |-> [ kind |-> "confirm" ] ], verdict |-> "mismatch",\n'
            '  pendingForeign |-> TRUE ]\nBack to state 2: <retry>\n')
    TAIL = ("Error: Temporal property q_temporalProps was violated.\n"
            "10 states generated, 7 distinct states found, 0 states left on queue.\n[violation] Found an issue\n")

    def test_the_broken_variant_needs_a_loop_with_a_mismatch_under_a_foreign_pending_handshake(self):
        case = CASES["broken-progress"]
        self.assertEqual(CHECK.judge(case, self.LOOP + self.TAIL, 1)["lasso"], [2, 3])
        for broken in (self.LOOP.replace("pendingForeign |-> TRUE", "pendingForeign |-> FALSE"),
                       self.LOOP.replace('verdict |-> "confirm"', 'verdict |-> "hello"'),
                       self.LOOP.replace("pendingDisplaced |-> TRUE", "pendingDisplaced |-> FALSE"),
                       self.LOOP.replace('kind |-> "confirm"', 'kind |-> "data"'),
                       self.LOOP.replace('act |-> "retry", peer |-> "c1"', 'act |-> "retry", peer |-> "c2"'),
                       self.LOOP.replace("Back to state 2: <retry>\n", "")):
            with self.subTest(log=broken), self.assertRaises(RuntimeError):
                CHECK.judge(case, broken + self.TAIL, 1)

    def test_a_passing_case_needs_a_completed_check(self):
        log = "10 states generated, 7 distinct states found, 0 states left on queue.\n[ok] No violation found\n"
        with self.assertRaises(RuntimeError):
            CHECK.judge(CASES["safety"], log, 0)
        self.assertEqual(CHECK.judge(CASES["safety"], log + "Model checking completed. No error has been found.\n", 0)["states"],
                         [10, 7, 0])

    def test_a_violation_needs_its_own_property_and_a_nonzero_exit(self):
        log = ("State 1: <Initial predicate>\nState 2: <step>\nError: Invariant q_inv is violated.\n"
               "10 states generated, 7 distinct states found, 3 states left on queue.\n[violation] Found an issue\n")
        self.assertEqual(CHECK.judge(CASES["mutant-reuse-epoch"], log, 1)["states"], [10, 7, 3])
        with self.assertRaises(RuntimeError):
            CHECK.judge(CASES["mutant-reuse-epoch"], log, 0)
        with self.assertRaises(RuntimeError):
            CHECK.judge(CASES["broken-progress"], log, 1)
        with self.assertRaises(RuntimeError):
            CHECK.judge(CASES["mutant-reuse-epoch"], log.replace("State 2: <step>\n", ""), 1)

    def test_a_tlc_case_needs_its_declared_outcome_as_the_one_terminal_line(self):
        """A log that reports a second terminal line beside the declared one is refused: a failure TLC prints after
        a violation while it exits with the violation's status, a completion beside a violation, a repeated
        violation, and a failure or a second completion beside a completion. TLC's two trace headings are no
        outcome, so a violation followed by either one passes."""
        violation = ("Error: Invariant q_inv is violated.\n{}State 1: <Initial predicate>\nState 2: <step>\n"
                     "10 states generated, 7 distinct states found, 3 states left on queue.\n[violation] Found an issue\n")
        completed = ("Model checking completed. No error has been found.\n{}"
                     "10 states generated, 7 distinct states found, 0 states left on queue.\n[ok] No violation found\n")
        failure = "Error: TLC threw an unexpected exception.\n"
        for heading in ("Error: The behavior up to this point is:\n",
                        "Error: The following behavior constitutes a counter-example:\n"):
            self.assertEqual(CHECK.judge(CASES["mutant-reuse-epoch"], violation.format(heading), 1)["trace"], 2)
        for name, log, status in (
                ("mutant-reuse-epoch", violation.format(failure), 1),
                ("mutant-reuse-epoch", violation.format("Error: Evaluating invariant q_inv failed.\n"), 1),
                ("mutant-reuse-epoch", violation.format("Model checking completed. No error has been found.\n"), 1),
                ("mutant-reuse-epoch", violation.format("Error: Invariant q_inv is violated.\n"), 1),
                ("broken-progress", self.LOOP + failure + self.TAIL, 1),
                ("safety", completed.format(failure), 0),
                ("safety", completed.format("Model checking completed. No error has been found.\n"), 0)):
            with self.subTest(case=name, log=log), self.assertRaises(RuntimeError):
                CHECK.judge(CASES[name], log, status)

    def test_a_connect_replay_needs_its_report_line_and_a_passing_test(self):
        kinds = ",".join(f"{action}:3" for action in CHECK.REPLAY_ACTIONS)
        line = f"q1 connect replay: traces={CHECK.REPLAY_TRACES} actions=2050 longest=41 per_action={kinds} agreement=all\n"
        log = line + "test result: ok. 1 passed; 0 failed; 0 ignored\n"
        self.assertEqual(CHECK.judge(CASES["connect-replay"], log, 0)["actions"], 2050)
        for broken, code in ((log, 101), (log.replace(line, ""), 0), (log.replace("1 passed", "0 passed"), 0),
                             (log.replace(f"traces={CHECK.REPLAY_TRACES}", "traces=3"), 0),
                             (log.replace("rekey:3", "rekey:0"), 0)):
            with self.subTest(log=broken, code=code), self.assertRaises(RuntimeError):
                CHECK.judge(CASES["connect-replay"], broken, code)

    def test_the_replay_instance_binds_the_runner_constants(self):
        source = ROOT / "quint"
        self.assertEqual(sorted(CHECK.inputs(CASES["connect-replay"], source)), ["replay.qnt", "session.qnt"])
        self.assertEqual(CHECK.inputs(CASES["connect-replay"], source)["replay.qnt"], (source / "replay.qnt").read_text())
        with tempfile.TemporaryDirectory(prefix="kestrike-quint-") as temp:
            copy = Path(temp)
            for name in ("session.qnt", "replay.qnt"):
                (copy / name).write_text((source / name).read_text())
            text = (copy / "replay.qnt").read_text()
            self.assertEqual(text.count("FAULTS = 2"), 1)
            (copy / "replay.qnt").write_text(text.replace("FAULTS = 2", "FAULTS = 3"))
            with self.assertRaisesRegex(ValueError, "FAULTS"):
                CHECK.inputs(CASES["connect-replay"], copy)

    def test_the_replay_actions_are_the_models_init_and_step_actions(self):
        text = (ROOT / "quint/session.qnt").read_text()
        self.assertEqual(CHECK.REPLAY_ACTIONS, CHECK.model_actions(text))
        self.assertEqual(CHECK.REPLAY_ACTIONS[0], "init")
        self.assertEqual(len(CHECK.REPLAY_ACTIONS), len(set(CHECK.REPLAY_ACTIONS)))
        for name in CHECK.REPLAY_ACTIONS:
            with self.subTest(action=name):
                self.assertRegex(text, rf"(?m)^  action {name}\b")
        extended = text.replace("    stabilize,\n  }", "    stabilize,\n    extra,\n  }")
        self.assertNotEqual(extended, text)
        self.assertEqual(CHECK.model_actions(extended), (*CHECK.REPLAY_ACTIONS, "extra"))

    def test_a_simulation_needs_every_witness_line_and_its_lengths(self):
        lines = "".join(f"{name} was witnessed in 1 trace(s) out of {CHECK.SAMPLES} explored (0.25%)\n" for name in CHECK.WITNESSES)
        log = "[ok] No violation found\nTrace length statistics: max=41, min=41, average=41.00\n" + lines
        self.assertEqual(CHECK.judge(CASES["simulation"], log, 0)["traces"], int(CHECK.SAMPLES))
        with self.assertRaises(RuntimeError):
            CHECK.judge(CASES["simulation"], log.replace(lines.splitlines()[0] + "\n", ""), 0)

    def test_each_mutation_names_one_unique_text_of_the_model(self):
        text = (ROOT / "quint/session.qnt").read_text()
        for case in CASES.values():
            if case.mutations and case.family == "session":
                with self.subTest(case=case.name):
                    self.assertEqual(text.count(case.mutations[0][0]), 1)
                    self.assertNotEqual(CHECK.model(case, ROOT / "quint"), text)

    def test_each_tlc_case_runs_quint_against_its_own_apalache_endpoint(self):
        directory = Path("/tmp/case")
        for case in CASES.values():
            with self.subTest(case=case.name):
                argv = CHECK.command(case, QUINT, directory, 41234 if case.command == "tlc" else None)
                if case.command == "tlc":
                    at = argv.index("--server-endpoint")
                    self.assertEqual(argv[at + 1], "127.0.0.1:41234")
                else:
                    self.assertNotIn("--server-endpoint", argv)

    def test_cancellation_reaches_the_per_case_timeout_children(self):
        self.a_signal_to_the_runner_stops_the_case_session(signal.SIGTERM, 143)

    def test_a_terminal_interrupt_stops_the_case_session(self):
        self.a_signal_to_the_runner_stops_the_case_session(signal.SIGINT, 130)

    def a_signal_to_the_runner_stops_the_case_session(self, signum, status):
        with tempfile.TemporaryDirectory(prefix="quint-cancel-") as temp:
            directory = Path(temp)
            stub, pids = recording_stub(directory)
            runner = subprocess.Popen([sys.executable, "-c", f"import sys; from pathlib import Path; sys.path.insert(0, {str(ROOT / 'quint')!r}); import check; check.run_case(check.Case('cancel', command='typecheck', family='tenure'), Path({str(ROOT / 'quint')!r}), Path({str(directory)!r}), {str(stub)!r}, 1)"], start_new_session=True, preexec_fn=default_sigint, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                limit = time.monotonic() + 10
                while not pids.exists() and time.monotonic() < limit: time.sleep(0.05)
                self.assertTrue(pids.exists(), "case command started")
                time.sleep(0.1)
                os.killpg(runner.pid, signum)
                self.assertEqual(runner.wait(timeout=CHECK.KILL_GRACE_SECONDS + 10), status)
                children = pids.read_text().splitlines()
                self.assertEqual(len(children), 2)
                for pid in children:
                    self.assertTrue(stopped(pid), f"child {pid} stopped")
            finally:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(runner.pid, signal.SIGKILL)
                runner.wait()

    def test_a_sigterm_while_the_case_command_starts_still_stops_its_session(self):
        with tempfile.TemporaryDirectory(prefix="quint-start-") as temp:
            directory = Path(temp)
            stub, pids = recording_stub(directory)
            driver = (f"import os, signal, sys, time; from pathlib import Path; sys.path.insert(0, {str(ROOT / 'quint')!r}); import check\n"
                      "real = check.subprocess.Popen\n"
                      "def popen(*args, **kwargs):\n"
                      "    process = real(*args, **kwargs)\n"
                      f"    while len(Path({str(pids)!r}).read_text().splitlines() if Path({str(pids)!r}).exists() else []) < 2: time.sleep(0.05)\n"
                      "    os.kill(os.getpid(), signal.SIGTERM)\n"
                      "    return process\n"
                      "check.subprocess.Popen = popen\n"
                      f"check.run_case(check.Case('start', command='typecheck', family='tenure'), Path({str(ROOT / 'quint')!r}), Path({str(directory)!r}), {str(stub)!r}, 1)\n")
            runner = subprocess.Popen([sys.executable, "-c", driver], start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                self.assertEqual(runner.wait(timeout=30), 143)
                children = pids.read_text().splitlines()
                self.assertEqual(len(children), 2)
                for pid in children:
                    self.assertTrue(stopped(pid), f"child {pid} stopped with the runner")
            finally:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(runner.pid, signal.SIGKILL)
                runner.wait()
                for pid in pids.read_text().splitlines() if pids.exists() else []:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(int(pid), signal.SIGKILL)

    def test_the_case_deadline_stops_every_process_the_case_started(self):
        self.deadline_stops_the_recorded_processes("sleep 60")

    def test_the_case_deadline_kills_a_descendant_that_ignores_sigterm(self):
        self.deadline_stops_the_recorded_processes("sh -c 'trap \"\" TERM; sleep 60'")

    def deadline_stops_the_recorded_processes(self, child):
        with tempfile.TemporaryDirectory(prefix="quint-deadline-") as temp:
            directory = Path(temp)
            stub, pids = recording_stub(directory, child)
            driver = (f"import sys; from pathlib import Path; sys.path.insert(0, {str(ROOT / 'quint')!r}); import check\n"
                      "check.CASE_SECONDS, check.KILL_GRACE_SECONDS = 1, 1\n"
                      f"try: check.run_case(check.Case('deadline', command='typecheck', family='tenure'), Path({str(ROOT / 'quint')!r}), Path({str(directory)!r}), {str(stub)!r}, 1)\n"
                      "except check.Incomplete as error: print(error)\n")
            runner = subprocess.Popen([sys.executable, "-c", driver], start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            try:
                output, _ = runner.communicate(timeout=30)
                self.assertIn("deadline: incomplete command exit 124", output)
                children = pids.read_text().splitlines()
                self.assertEqual(len(children), 2)
                for pid in children:
                    self.assertTrue(stopped(pid), f"child {pid} stopped at the deadline")
            finally:
                try: os.killpg(runner.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                runner.wait()
                for pid in pids.read_text().splitlines() if pids.exists() else []:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(int(pid), signal.SIGKILL)
                    with contextlib.suppress(ProcessLookupError):
                        os.kill(int(pid), signal.SIGKILL)

    def test_a_declared_deadline_stops_its_case_and_only_session_safety_declares_one(self):
        """A case is stopped at the deadline it declares while the common one is far off, and the session
        `safety` case, at three faults under its invariant, is the one case that declares a deadline."""
        declared = {case.name: (case.deadline, case.settings, case.invariant, case.family)
                    for case in CHECK.cases() if case.deadline is not None}
        self.assertEqual(declared, {"safety": (CHECK.SAFETY_SECONDS, {"FAULTS": "3"}, "safety", "session")})
        self.assertGreater(CHECK.SAFETY_SECONDS, CHECK.CASE_SECONDS)
        with tempfile.TemporaryDirectory(prefix="quint-declared-") as temp:
            directory = Path(temp)
            stub, pids = recording_stub(directory)
            driver = (f"import sys; from pathlib import Path; sys.path.insert(0, {str(ROOT / 'quint')!r}); import check\n"
                      "check.KILL_GRACE_SECONDS = 1\n"
                      f"try: check.run_case(check.Case('declared', command='typecheck', family='tenure', deadline=1), Path({str(ROOT / 'quint')!r}), Path({str(directory)!r}), {str(stub)!r}, 1)\n"
                      "except check.Incomplete as error: print(error, check.CASE_SECONDS)\n")
            runner = subprocess.Popen([sys.executable, "-c", driver], start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            try:
                output, _ = runner.communicate(timeout=30)
                self.assertIn("declared: incomplete command exit 124 1100", output)
                children = pids.read_text().splitlines()
                self.assertEqual(len(children), 2)
                for pid in children:
                    self.assertTrue(stopped(pid), f"child {pid} stopped at the declared deadline")
            finally:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(runner.pid, signal.SIGKILL)
                runner.wait()
                for pid in pids.read_text().splitlines() if pids.exists() else []:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(int(pid), signal.SIGKILL)

    def test_a_stopped_run_records_the_case_it_was_running(self):
        """A SIGTERM to the runner, which is how the lane's run deadline stops it, exits 143 and leaves a record
        that names the case then running, so the evidence of a stopped run shows where the suite stood."""
        with tempfile.TemporaryDirectory(prefix="quint-stopped-") as temp:
            directory = Path(temp)
            stub, pids = recording_stub(directory)
            # The runner records `quint --version` and `java -version` before its first case.
            stub.write_text(stub.read_text().replace("#!/bin/sh\n", '#!/bin/sh\n[ "$1" != --version ] || exec echo 0.33.0\n'))
            (directory / "bin").mkdir()
            (directory / "bin/java").write_text("#!/bin/sh\necho stub\n")
            (directory / "bin/java").chmod(0o755)
            environment = {**os.environ, "PATH": f"{directory / 'bin'}{os.pathsep}{os.environ['PATH']}"}
            runner = subprocess.Popen([sys.executable, str(ROOT / "quint/check.py"), "--quint", str(stub), "--workers", "1",
                                       "--case", "typecheck", "--output", str(directory / "out")], env=environment,
                                      start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                limit = time.monotonic() + 10
                while len(pids.read_text().splitlines() if pids.exists() else []) < 2 and time.monotonic() < limit: time.sleep(0.05)
                os.kill(runner.pid, signal.SIGTERM)
                self.assertEqual(runner.wait(timeout=CHECK.KILL_GRACE_SECONDS + 10), 143)
                record = json.loads((directory / "out/results.json").read_text())
                self.assertEqual((record["complete"], record["results"]), (False, []))
                self.assertEqual(record["failure"], {"case": "typecheck", "reason": "typecheck: the runner stopped on a signal (exit 143)"})
            finally:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(runner.pid, signal.SIGKILL)
                runner.wait()
                for pid in pids.read_text().splitlines() if pids.exists() else []:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(int(pid), signal.SIGKILL)

    def test_a_free_port_is_one_no_socket_holds(self):
        port = CHECK.free_port()
        self.assertTrue(0 < port < 65536)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", port))
            listener.listen()
            self.assertNotEqual(CHECK.free_port(), port)

    def test_a_claimed_port_goes_to_no_other_runner_until_its_claim_closes(self):
        """Quint's server binds a case's port only after the runner drew it, so a second runner on the host can
        draw the same free port in between. The first runner's claim makes the second draw again, and a closed
        claim frees the number."""
        port, claim = CHECK.claim_port()
        self.addCleanup(claim.close)
        draw, drawn = CHECK.free_port, iter([port])
        with mock.patch.object(CHECK, "free_port", side_effect=lambda: next(drawn, None) or draw()):
            other, second = CHECK.claim_port()
        second.close()
        self.assertNotEqual(other, port)
        claim.close()
        with mock.patch.object(CHECK, "free_port", return_value=port):
            again, third = CHECK.claim_port()
        third.close()
        self.assertEqual(again, port)


def shard_artifact(producer, artifact, index, names, ci, revision):
    """Write the raw evidence shard `index` uploads after it ran the cases `names`, in the runner's order, at
    `producer` under the run identity `ci`, then move it to `artifact`, the directory the join downloads."""
    results = [JudgeQuint.result(types.SimpleNamespace(evidence=producer), CASES[name]) for name in names]
    identity = {
        "java": {"version": f'openjdk version "{EXPECTED["java"]["version"]}"', "install": {"sha256": EXPECTED["java"]["install"]}},
        "node": {"version": EXPECTED["node"]["version"], "install": {"sha256": EXPECTED["node"]["install"]}},
        "apalache": {"install": {"sha256": EXPECTED["apalache"]["install"]}},
        "quint": {"path": QUINT, "version": EXPECTED["quint"]["version"], "apalache": EXPECTED["apalache"]["version"],
                  "install": {"sha256": EXPECTED["quint"]["install"]}},
        "models": MODEL_DIGESTS,
        "shard": {"index": index, "ci": ci, "output": str(producer / "quint"), "executable": QUINT},
    }
    record = {"revision": revision, "ci": ci, "quint": EXPECTED["quint"]["version"], "runtime": identity["java"]["version"],
              "dirty": [], "complete": True, "failure": None, "results": results}
    for name, value in (("identity.json", identity), ("results.json", record)):
        (producer / name).write_text(json.dumps(value) + "\n")
    (producer / "quint.txt").write_text("".join(f"PASS {name}\n" for name in names))
    (producer / "quint.exit").write_text("0\n")
    (producer / "quint.argv").write_text("\n".join(
        ["python3", "quint/check.py", "--quint", QUINT, "--workers", str(EXPECTED["workers"]),
         "--output", str(producer / "quint"), *(arg for name in names for arg in ("--case", name))]) + "\n")
    producer.rename(artifact)


class QuintShards(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="kestrike-quint-join-")
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name)
        self.evidence = self.path / "download"
        (self.evidence / "shards").mkdir(parents=True)
        self.ci = {"GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "3"}
        self.revision = "f" * 40
        self.chosen = {index: next(name for name, case in judge_quint.shard_cases(CASES, index).items()
                                   if case.command == "tlc" and case.expected == "ok")
                       for index in judge_quint.SHARDS}
        case_map = {name: CASES[name] for name in self.chosen.values()}
        expected = {**EXPECTED, "tests": list(case_map), "cases": {name: EXPECTED["cases"][name] for name in case_map},
                    "blocked": {self.chosen[0]: "external gate"}}
        read_json = judge_quint.read_json
        patches = (mock.patch.dict(os.environ, self.ci),
                   mock.patch.object(judge_quint, "read_json",
                                     side_effect=lambda path: expected if path == judge_quint.EXPECTED else read_json(path)),
                   mock.patch.object(judge_quint, "runner_cases", return_value=case_map))
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.shards = {}
        for index, name in self.chosen.items():
            self.shards[index] = self.evidence / "shards" / f"quint-shard-{index}-42-3"
            shard_artifact(self.path / str(index), self.shards[index], index, [name], self.ci, self.revision)

    def write(self, path, value):
        path.write_text(json.dumps(value) + "\n")

    def judge(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = judge_quint.main(["judge", "--evidence", str(self.evidence), "--revision", self.revision])
        report = json.loads((self.evidence / "report.json").read_text())
        receipt = json.loads((self.evidence / "receipt.json").read_text())
        self.assertEqual(code, report["code"])
        return report, receipt

    def assert_refused(self, reason):
        report, receipt = self.judge()
        self.assertFalse(report["credited"])
        self.assertIn(reason, report["reason"])
        self.assertEqual((receipt["executions"], receipt["executed"]), (0, []))

    def test_join_checks_relocated_raw_files_and_does_not_credit_the_blocked_case(self):
        report, receipt = self.judge()
        self.assertTrue(report["credited"], report["reason"])
        self.assertEqual(set(report["cases"]), set(self.chosen.values()))
        self.assertEqual(receipt["executed"], [self.chosen[1]])
        self.assertEqual(receipt["module"], None)
        index = self.evidence / "quint-shards.json"
        self.assertEqual(receipt["inputs"][index.name], judge_quint.sha256(index))
        self.assertEqual(json.loads(index.read_text()), report["shards"])
        self.assertEqual(judge_quint.derive(self.evidence, self.revision), (report, receipt))

    def test_the_partition_covers_the_committed_declaration_including_blocked_cases(self):
        left, right = (set(judge_quint.shard_cases(CASES, index)) for index in judge_quint.SHARDS)
        self.assertTrue(left and right)
        self.assertFalse(left & right)
        self.assertEqual(left | right, set(EXPECTED["tests"]))
        self.assertLessEqual(set(EXPECTED["blocked"]), left | right)

    def test_missing_shard_cannot_credit_a_completed_subset(self):
        shutil.rmtree(self.shards[1])
        self.assert_refused("precisely this attempt's shard artifacts")

    def test_one_surviving_artifact_extracted_flat_is_incomplete(self):
        """The download step extracts a lone matching artifact into `shards/` itself, without its named directory."""
        shutil.rmtree(self.shards[1])
        for entry in list(self.shards[0].iterdir()):
            entry.rename(self.evidence / "shards" / entry.name)
        self.shards[0].rmdir()
        self.assert_refused("precisely this attempt's shard artifacts")

    def test_a_shard_that_ran_past_its_deadline_or_refused_a_case_is_the_lane_refusal(self):
        """The join judges a failed shard's uploaded evidence, so the receipt states the timeout or the refused case."""
        (self.shards[1] / "quint.exit").write_text("124\n")
        report, receipt = self.judge()
        self.assertEqual((report["code"], receipt["completion"], receipt["executions"]), (judge_quint.INCOMPLETE, "timeout", 0))
        (self.shards[1] / "quint.exit").write_text("1\n")
        path = self.shards[1] / "results.json"
        self.write(path, {**json.loads(path.read_text()), "complete": False, "results": [],
                          "failure": {"case": self.chosen[1], "reason": "the invariant is violated"}})
        report, receipt = self.judge()
        self.assertEqual((report["code"], receipt["completion"], receipt["executions"]), (judge_quint.MISMATCH, "completed", 0))
        self.assertIn(f"it refused {self.chosen[1]} by its outcome: the invariant is violated", report["reason"])

    def test_a_refused_join_binds_the_shards_it_judged(self):
        """A refused case leaves the run completed, and credit requires a completed receipt to bind the lane's
        evidence files. The join's receipt binds the sharded files whatever the verdict, with the manifest and
        the pins of the shards judged before the refusal."""
        (self.shards[1] / "quint" / self.chosen[1] / "quint.log").write_text("no outcome\n")
        report, receipt = self.judge()
        self.assertEqual((report["code"], receipt["completion"]), (judge_quint.MISMATCH, "completed"))
        self.assertEqual(list(report["shards"]), [self.shards[0].name])
        self.assertEqual(len(receipt["tool"]["provenance"]), 1)
        for name in ("report.json", "pins.txt", "quint-shards.json"):
            self.assertEqual(receipt["inputs"].get(name), judge_quint.sha256(self.evidence / name), name)
        self.assertEqual(judge_quint.derive(self.evidence, self.revision), (report, receipt))
        shutil.rmtree(self.shards[0])
        report, receipt = self.judge()
        self.assertEqual((report["shards"], receipt["tool"]["provenance"]), ({}, []))
        self.assertEqual(receipt["inputs"]["quint-shards.json"], judge_quint.sha256(self.evidence / "quint-shards.json"))

    def test_artifact_named_for_this_attempt_cannot_supply_an_older_result(self):
        path = self.shards[1] / "results.json"
        result = json.loads(path.read_text())
        result["ci"]["GITHUB_RUN_ATTEMPT"] = "2"
        self.write(path, result)
        self.assert_refused("results record another run or attempt")

    def test_duplicate_outcome_does_not_satisfy_the_declared_shard(self):
        path = self.shards[1] / "results.json"
        result = json.loads(path.read_text())
        result["results"] += result["results"]
        self.write(path, result)
        self.assert_refused("repeat a case")

    def test_mislabeled_shard_cannot_be_judged_as_the_missing_one(self):
        staging = self.path / "swap"
        self.shards[0].rename(staging)
        self.shards[1].rename(self.shards[0])
        staging.rename(self.shards[1])
        self.assert_refused("records another shard, run or attempt")

    def test_false_argv_and_bad_raw_coverage_both_refuse(self):
        path = self.shards[1] / "quint.argv"
        original = path.read_text()
        path.write_text(original.replace(self.chosen[1], self.chosen[0]))
        self.assert_refused("runner command differs")
        path.write_text(original)
        (self.shards[1] / "quint" / self.chosen[1] / "quint.log").write_text("no outcome\n")
        self.assert_refused("raw evidence refused")

    def test_a_shard_artifact_off_its_layout_or_with_unusable_producer_paths_is_refused(self):
        """The join reads a shard's files only where the downloaded artifact holds them and compares the shard's
        argv with the paths its identity records. A symbolic link in place of a judged entry, a missing or
        misplaced entry, and a producer path that is not a normalized absolute path under the recorded launcher's
        tree each let the join read or compare something other than what the shard ran, so each refuses the lane."""
        def link(path):
            """Replace `path` with a symbolic link to its own content, kept outside the evidence."""
            kept = self.path / "linked"
            path.rename(kept)
            path.symlink_to(kept, target_is_directory=kept.is_dir())

        def as_file(path):
            shutil.rmtree(path)
            path.write_text("")

        def marker(**change):
            path = self.shards[1] / "identity.json"
            self.write(path, {**(record := json.loads(path.read_text())), "shard": {**record["shard"], **change}})

        model = next(iter(CHECK.inputs(CASES[self.chosen[1]], ROOT / "quint")))
        linked, misplaced = "contains a symbolic link", "is not an artifact directory"
        # Each change takes shard 1's artifact, its case directory and the `quint` path its producer recorded.
        rows = [
            *((lambda raw, case, produced, name=name: link(raw / name), f"Quint shard 1 {linked}")
              for name in judge_quint.SHARD_INPUTS),
            (lambda raw, case, produced: link(raw.parent), "precisely this attempt's shard artifacts"),
            (lambda raw, case, produced: link(raw), f"Quint shard 1 {misplaced}"),
            (lambda raw, case, produced: as_file(raw), f"Quint shard 1 {misplaced}"),
            (lambda raw, case, produced: link(raw / "quint"), "Quint shard 1 has no raw case directory"),
            (lambda raw, case, produced: shutil.rmtree(raw / "quint"), "Quint shard 1 has no raw case directory"),
            (lambda raw, case, produced: link(case), f"a case artifact {linked}"),
            (lambda raw, case, produced: link(case / model), f"a case artifact {linked}"),
            (lambda raw, case, produced: link(case / "quint.log"), f"a case artifact {linked}"),
            (lambda raw, case, produced: marker(output=None), "producer path is invalid"),
            (lambda raw, case, produced: marker(output=f"{produced}\n"), "producer path is invalid"),
            (lambda raw, case, produced: marker(output="1/quint"), "producer path is not normalized"),
            (lambda raw, case, produced: marker(output=f"{produced.parent}/x/../quint"), "producer path is not normalized"),
            (lambda raw, case, produced: marker(output=f"{produced.parent}//quint"), "producer path is not normalized"),
            (lambda raw, case, produced: marker(output=f"{produced}/"), "producer path is not normalized"),
            (lambda raw, case, produced: marker(output=str(produced.with_name("other"))), "foreign output or Quint executable"),
            (lambda raw, case, produced: marker(executable="/usr/bin/quint"), "foreign output or Quint executable"),
        ]
        for row, (change, reason) in enumerate(rows):
            with self.subTest(row=row, reason=reason):
                self.doCleanups()
                self.setUp()
                change(self.shards[1], self.shards[1] / "quint" / self.chosen[1], self.path / "1" / "quint")
                self.assert_refused(reason)


if __name__ == "__main__":
    unittest.main()
