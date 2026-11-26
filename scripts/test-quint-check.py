#!/usr/bin/env python3
"""Check that quint/check.py refuses runs short of a case's declared outcome and cases it cannot dispatch.

The simulation tests feed the outcome parser a log in the form Quint prints and
check that it accepts the declared outcome and refuses a run that explored fewer
traces or shorter ones than the case requests. The violation tests check that a
violation whose trace holds another number of states than the case declares is
refused, that a recipe mutant that declares no length must violate at its
recipe's last action while an unmutated recipe case may violate earlier, that a
trace with a state header in non-ASCII digits or another malformed label is
refused, that each early
length a recipe mutant declares names a state inside its recipe, that every
standbys recipe case and initial-state reach case declares its trace length,
and that a non-ASCII duplicate state header is refused. A case that
declares both an invariant and a temporal property, a TLC case without one
property named by an identifier and a session case with a recipe refuse, and
a family command that drops a case's recipe is refused. The standbys run tests check that a run's turn
check enters its case and a turn outside the recipe refuses, and that a run's reached case refuses a trace one
state short of the whole recipe. The standbys instance tests check that a search, run or recipe case's instance
holds what its case names and what that reaches, that the typecheck keeps the whole model, and that a repeated item, a
module-level line that opens no item or a trailing doc comment refuses by case. The dispatch tests check that every dispatcher refuses an undeclared
family, and that a mutation target that is absent, repeated or removed by an
earlier replacement refuses. The projection tests check that a join case's
exhaustive check short of its bound is refused, that a join violation inside
its prefix, past `BOUND + 1` states or with state labels other than 1 to N in
order is refused, and that every declared projection's command steps under its
scheduler, whose generated action pins each prefix action to its turn and
starts the scheduler at the prefix's end; a family command that drops the step
is refused. A projection declaration whose bound leaves no step after its
prefix, whose mutant names an undeclared witness or whose two mutants share a
property and a mutation list refuses, and so does a case that sets a depth on
a violation or a trace length on a passing check. No join mutant carries the
mutation list of a registered mutant of any family, every reduction and
mutation target occurs once in its file, and the floor rule of the
prefix-saturation projection is the prefix model's shrink condition. The
binder's release-scope mutant keeps the devices a release's raw record decodes
to and hands the release both devices, so its violation is a restore write
outside the record. Each binder invariant that a passing case defines in its
instance module has a mutant case that must violate it. The generator test
checks that the grace, lookup, reclaim and register trace generators, given a
relative `--output`, write one trace per committed fixture under it.
"""

import dataclasses
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("quint_check", ROOT / "quint/check.py")
assert spec is not None and spec.loader is not None
check = importlib.util.module_from_spec(spec)
# `dataclass` resolves the module's annotations through `sys.modules`.
sys.modules[spec.name] = check
spec.loader.exec_module(check)
CASES = {case.name: case for case in check.cases()}


def simulation(traces=int(check.SAMPLES), shortest=int(check.STEPS) + 1, longest=int(check.STEPS) + 1):
    """A simulation log with `traces` traces whose state counts run from `shortest` to `longest`."""
    witnessed = "".join(f"{name} was witnessed in {traces} trace(s) out of {traces} explored (100.00%)\n"
                        for name in check.WITNESSES)
    return (f"[ok] No violation found (10ms at 28 traces/second).\n"
            f"Trace length statistics: max={longest}, min={shortest}, average={(longest + shortest) / 2:.2f}\n"
            f"Witnesses:\n{witnessed}")


class Simulation(unittest.TestCase):
    def test_the_declared_traces_at_full_length_pass(self):
        facts = check.judge(CASES["simulation"], simulation(), 0)
        self.assertEqual(facts["traces"], int(check.SAMPLES))
        self.assertEqual(facts["lengths"]["min"], int(check.STEPS) + 1)

    def test_fewer_traces_than_declared_are_refused(self):
        with self.assertRaisesRegex(RuntimeError, "traces"):
            check.judge(CASES["simulation"], simulation(traces=3), 0)

    def test_a_trace_that_ends_early_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, "steps"):
            check.judge(CASES["simulation"], simulation(shortest=12), 0)

    def test_traces_without_a_step_are_refused(self):
        with self.assertRaisesRegex(RuntimeError, "steps"):
            check.judge(CASES["simulation"], simulation(shortest=0, longest=0), 0)


def labelled(labels):
    """A TLC log of an invariant violation whose trace states carry `labels` in order."""
    return ("10 states generated, 7 distinct states found, 0 states left on queue\n"
            "Error: Invariant q_inv is violated.\n[violation] Found an issue\n"
            + "".join(f"State {label}: fixture\n" for label in labels))


def violation(states):
    """A TLC log of an invariant violation whose trace holds `states` states."""
    return labelled(range(1, states + 1))


class Violation(unittest.TestCase):
    def test_a_violation_at_another_step_than_declared_is_refused(self):
        case = CASES["preserve-mutant-partition-overlap"]
        self.assertEqual(check.judge(case, violation(case.trace), 1)["trace"], case.trace)
        for states in (case.trace - 1, case.trace + 1):
            with self.subTest(states=states), self.assertRaisesRegex(
                    RuntimeError, rf"^{re.escape(case.name)}: the violation's trace holds {states} states, not states 1 "
                                  rf"to {case.trace} in order$"):
                check.judge(case, violation(states), 1)

    def test_a_recipe_mutant_short_of_its_recipes_last_action_is_refused_until_it_declares_that_length(self):
        case = CASES["capture-mutant-LoadGuardNeverFires"]
        self.assertGreaterEqual(len(case.recipe), 2)
        self.assertEqual((case.trace, bool(case.mutations)), (None, True))
        last = len(case.recipe) + 1
        self.assertEqual(check.judge(case, violation(last), 1)["trace"], last)
        for states in (last - 1, last + 1):
            with self.subTest(states=states), self.assertRaisesRegex(
                    RuntimeError, rf"^{re.escape(case.name)}: the violation's trace holds {states} states, not states 1 "
                                  rf"to {last} in order, which end at its recipe's last action$"):
                check.judge(case, violation(states), 1)
        declared = dataclasses.replace(case, trace=last - 1)
        self.assertEqual(check.judge(declared, violation(last - 1), 1)["trace"], last - 1)

    def test_a_recipe_mutant_trace_with_an_extra_malformed_state_header_is_refused(self):
        case = CASES["capture-mutant-LoadGuardNeverFires"]
        last = len(case.recipe) + 1
        self.assertEqual(check.judge(case, violation(last), 1)["trace"], last)
        for header in ("State \u0662: fixture\n", f"State +{last + 1}: fixture\n"):
            with self.subTest(header=header), self.assertRaisesRegex(
                    RuntimeError, rf"^{re.escape(case.name)}: .*not states 1 to N in order$"):
                check.judge(case, violation(last) + header, 1)

    def test_a_recipe_case_without_a_mutation_may_violate_before_its_recipes_last_action(self):
        case = CASES["capture-overflow-reachable"]
        self.assertEqual((case.trace, case.mutations), (None, []))
        self.assertEqual(check.judge(case, violation(len(case.recipe)), 1)["trace"], len(case.recipe))

    def test_each_recipe_mutant_that_declares_an_earlier_trace_declares_a_state_inside_its_recipe(self):
        early = {case.name: case.trace for case in CASES.values()
                 if case.mutations and case.recipe and case.trace is not None and case.trace != len(case.recipe) + 1}
        self.assertTrue(all(2 <= trace <= len(CASES[name].recipe) for name, trace in early.items()), early)
        self.assertLessEqual({"prefix-mutant-shrink-frees-slot", "capture-mutant-CaptureConsistent",
                              "capture-mutant-UnitsExclusive", "capture-mutant-LedgerConserved",
                              "capture-mutant-CaptureConsistent-cursor", "watchdog-mutant-DeadlineFromOwnArm",
                              "watermark-run-restart-keeps-the-mark-from-empty-mark", "parked-mutant-OnlyOwedVisited"},
                             set(early))

    def test_a_trace_whose_states_are_not_numbered_one_to_n_in_order_is_refused(self):
        case = CASES["preserve-mutant-partition-overlap"]
        head = violation(0)
        for labels in ((1, 2, 4, 5), (2, 1, 3, 4), (1, 1, 2, 3, 4), (1, 2, 3, "04")):
            log = head + "".join(f"State {label}: fixture\n" for label in labels)
            with self.subTest(labels=labels), self.assertRaisesRegex(
                    RuntimeError, rf"^{re.escape(case.name)}: the violation's trace holds \d+ states labelled .*, "
                                  rf"not states 1 to N in order$"):
                check.judge(case, log, 1)

    def test_a_standbys_violation_outside_its_declared_length_is_refused(self):
        for name, (_, recipe, _, *_) in check.standbys_checks.MUTANTS.items():
            with self.subTest(name=name):
                self.assertEqual(CASES[f"standbys-mutant-{name}"].trace, len(recipe) + 1)
        for witness in check.standbys_checks.WITNESSES:
            with self.subTest(witness=witness):
                self.assertEqual(CASES[f"standbys-reach-{witness}"].after, 1)
        mutant, reach = CASES["standbys-mutant-admit-ignores-cap"], CASES["standbys-reach-witnessCensusCreated"]
        limit = int(check.standbys_checks.CONSTANTS["BOUND"]) + 1
        self.assertEqual(check.judge(reach, violation(limit), 1)["trace"], limit)
        for case, states in ((mutant, mutant.trace - 1), (mutant, mutant.trace + 1), (reach, limit + 1)):
            with self.subTest(case=case.name, states=states), self.assertRaisesRegex(RuntimeError, "trace holds"):
                check.judge(case, violation(states), 1)
        for name, (recipe, *_) in check.standbys_checks.RECIPES.items():
            with self.subTest(name=name):
                self.assertEqual(CASES[f"standbys-recipe-{name}"].trace, len(recipe) + 1)

    def test_a_non_ascii_duplicate_state_header_is_refused(self):
        for case, states in ((CASES["standbys-mutant-admit-ignores-cap"], 9),
                             (CASES["standbys-reach-witnessCensusCreated"], 8)):
            log = violation(states) + "State \u0663: fixture\n"
            with self.subTest(case=case.name), self.assertRaisesRegex(RuntimeError, "trace holds"):
                check.judge(case, log, 1)


class PreserveRuns(unittest.TestCase):
    def test_a_run_check_outside_its_recipe_refuses(self):
        runs = check.preserve_checks.RUNS
        recipe = ["fill(0)", "capture"]
        try:
            for at in (1, len(recipe)):
                runs["stray"] = (recipe, "true", {at: "true"})
                self.assertIn("preserve-run-stray", [case.name for case in check.preserve_checks.cases(check.Case)])
            for at in (0, -1, len(recipe) + 1):
                runs["stray"] = (recipe, "true", {at: "true"})
                with self.subTest(at=at), self.assertRaisesRegex(ValueError, "outside its recipe"):
                    list(check.preserve_checks.cases(check.Case))
        finally:
            runs.pop("stray", None)


class StandbysRuns(unittest.TestCase):
    def test_a_run_check_lands_in_its_case_and_a_check_outside_its_recipe_refuses(self):
        runs = check.standbys_checks.RUNS
        recipe = ['begin(0, "reserve", 1, 2)', "request(0)"]
        try:
            for at in (1, len(recipe)):
                runs["stray"] = (recipe, "true", {at: 'st.ev.res == "full"'})
                cases = {case.name: case for case in check.standbys_checks.cases(check.Case)}
                self.assertIn(f'(turn == {at} implies (st.ev.res == "full"))', cases["standbys-run-stray"].extra)
            for at in (0, -1, len(recipe) + 1):
                runs["stray"] = (recipe, "true", {at: "true"})
                with self.subTest(at=at), self.assertRaisesRegex(ValueError, "outside its recipe"):
                    list(check.standbys_checks.cases(check.Case))
        finally:
            runs.pop("stray", None)

    def test_a_row_with_a_second_instance_refuses(self):
        recipe = ['begin(0, "reserve", 1, 2)', "request(0)"]
        for table, row in ((check.standbys_checks.RUNS, (recipe, "true", {}, {}, {})),
                           (check.standbys_checks.MUTANTS, ("safety", recipe, [], {}, {}))):
            try:
                table["stray"] = row
                with self.assertRaisesRegex(ValueError, "more than one instance"):
                    list(check.standbys_checks.cases(check.Case))
            finally:
                table.pop("stray", None)

    def test_a_reached_run_trace_holds_the_whole_recipe(self):
        for name, (recipe, _, _, *_) in check.standbys_checks.RUNS.items():
            case = CASES[f"standbys-run-{name}-reached"]
            with self.subTest(run=name):
                self.assertEqual(check.judge(case, violation(len(recipe) + 1), 1)["trace"], len(recipe) + 1)
                with self.assertRaisesRegex(RuntimeError, "trace holds"):
                    check.judge(case, violation(len(recipe)), 1)

    def test_a_standbys_instance_holds_what_its_case_names_and_what_that_reaches(self):
        text = (ROOT / "quint/standbys.qnt").read_text()
        prune = check.standbys_checks.prune
        kept = prune(text, {"safety"}, "stray")
        self.assertIn("\n  val safety = ", kept)
        for dropped in ("  action init = ", "  action step = ", "  action takeover(", "  val witnessCensusCreated = "):
            with self.subTest(dropped=dropped):
                self.assertIn(dropped, text)
                self.assertNotIn(dropped, kept)
        for stays in ("  pure val EMAX = 3", "  var st: State", "  type State = ", "  const BOUND: int"):
            with self.subTest(stays=stays):
                self.assertIn(stays, kept)
        reached = prune(text, {"step"}, "stray")
        for name in ("step", "tenureStep", "takeover", "bump", "flip", "endStep"):
            with self.subTest(reached=name):
                self.assertRegex(reached, rf"\n  action {name}\b")
        head, found, tail = check.standbys_checks.items(text, "stray")
        self.assertEqual("\n".join(head + [line for _, _, block in found for line in block] + tail), text)
        every = {name for kind, name, _ in found if kind in check.standbys_checks.PRUNABLE}
        self.assertEqual(prune(text, every, "stray"), text)

    def test_a_standbys_case_enters_by_its_instance_text_recipe_invariant_and_step(self):
        entries = check.standbys_checks.entries
        recipe = check.Case("stray", command="tlc", invariant="runSafety", family="standbys",
                            recipe=["takeover(1)"], extra="  val runSafety = safety and turn < 3\n")
        self.assertLessEqual({"takeover", "safety", "turn", "runSafety", "init"}, entries(recipe))
        self.assertNotIn("step", entries(recipe))
        search = check.Case("stray", command="tlc", invariant="safety", family="standbys")
        self.assertLessEqual({"safety", "init", "step"}, entries(search))
        rooted = CASES["standbys-designated-safety"]
        self.assertEqual(rooted.step, "component")
        self.assertLessEqual({"component", "safety", "init", "step"}, entries(rooted))
        texts = check.inputs(CASES["standbys-run-capRefusesSecond"], ROOT / "quint")
        self.assertNotIn("  action step = ", texts["standbys.qnt"])
        typecheck = check.inputs(CASES["standbys-typecheck"], ROOT / "quint")
        self.assertEqual(typecheck["standbys.qnt"], (ROOT / "quint/standbys.qnt").read_text())

    def test_a_standbys_model_with_a_repeated_item_or_an_unknown_module_level_line_refuses_by_case(self):
        text = (ROOT / "quint/standbys.qnt").read_text()
        close = text.rindex("\n}")
        repeated = text[:close] + "\n  val safety = true" + text[close:]
        stray = text[:close] + "\n  nondet h = HOSTS.oneOf()" + text[close:]
        dangling = text[:close] + "\n  /// A comment that no item follows." + text[close:]
        for name, model, message in (("repeated", repeated, r"defines \['safety'\] more than once"),
                                     ("stray", stray, "module-level line that opens no item"),
                                     ("dangling", dangling, "doc comment that no item follows")):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, f"stray: .*{message}"):
                check.standbys_checks.prune(model, {"step"}, "stray")


class LossCases(unittest.TestCase):
    """The loss family declares a mutant for each statement of each invariant `safety` conjoins, witnesses that reach
    the states each statement constrains, a reach case for each witness the model defines, and rooted cases that pin
    each prefix action to its turn before the free steps."""

    @classmethod
    def setUpClass(cls):
        cls.MODEL = (ROOT / "quint/loss.qnt").read_text()

    def test_safety_conjoins_the_invariants_and_each_invariant_its_statements(self):
        loss = check.loss_checks
        found = re.search(r"(?ms)^  val safety = (.*?)\n\n", self.MODEL)
        self.assertIsNotNone(found)
        conjunction = " ".join(found[1].split()) if found else ""
        self.assertEqual(conjunction, " and ".join(loss.INVARIANTS))
        for invariant, clauses in loss.CLAUSES.items():
            with self.subTest(invariant=invariant):
                if clauses:
                    self.assertIn(f"\n  val {invariant} = {' and '.join(clauses)}\n", self.MODEL)
                for clause in clauses:
                    self.assertEqual(len(re.findall(rf"(?m)^  val {clause} =", self.MODEL)), 1)
        self.assertEqual(len(set(loss.STATEMENTS)), len(loss.STATEMENTS))

    def test_every_statement_has_a_mutant_that_must_violate_it_and_a_witness_the_runner_reaches(self):
        loss = check.loss_checks
        named = [statement for statement, _, _ in loss.MUTANTS.values()]
        named += [statement for statement, _, _ in loss.RUN_MUTANTS.values()]
        self.assertEqual(set(named), set(loss.STATEMENTS))
        self.assertEqual(set(loss.MUTANTS) & set(loss.RUN_MUTANTS), set())
        self.assertEqual(list(loss.REACHED_BY), list(loss.STATEMENTS))
        for statement in loss.STATEMENTS:
            with self.subTest(statement=statement):
                self.assertTrue(any(case.family == "loss" and case.expected == "violation" and case.mutations
                                    and case.invariant == statement for case in CASES.values()))
                self.assertTrue(loss.REACHED_BY[statement])
                for witness in loss.REACHED_BY[statement]:
                    self.assertIn(f"loss-reach-{witness}", CASES)

    def test_the_model_defines_exactly_the_declared_witnesses(self):
        defined = re.findall(r"(?m)^  val (witness\w+) =", self.MODEL)
        self.assertEqual(sorted(defined), sorted(check.loss_checks.WITNESSES))

    def test_every_mutation_target_occurs_once_in_the_model(self):
        loss = check.loss_checks
        for name, (_, _, mutations) in {**loss.MUTANTS, **loss.RUN_MUTANTS}.items():
            for old, _ in mutations:
                with self.subTest(mutant=name, target=old):
                    self.assertEqual(self.MODEL.count(old), 1)

    def test_every_rooted_case_pins_its_root_prefix_and_steps_under_the_rooted_scheduler(self):
        loss = check.loss_checks
        expected = {f"loss-safety-{root}": (root, "safety", "rootSafety") for root in loss.ROOTS}
        expected |= {f"loss-reach-{witness}": (root, "reach", "unreached") for witness, root in loss.WITNESSES.items()}
        expected |= {f"loss-mutant-{name}": (root, "mutant", statement)
                     for name, (statement, root, _) in loss.MUTANTS.items()}
        for name, (root, kind, invariant) in expected.items():
            with self.subTest(case=name):
                case = CASES[name]
                prefix, free = loss.ROOTS[root]
                rendered = check.inputs(case, ROOT / "quint")
                instance = rendered["case.qnt"]
                self.assertIn(f"import loss(BOUND = {len(prefix) + free}).*", instance)
                pinned = re.findall(r"all \{ turn == (\d+), (.*?) \},", instance)
                stand = loss.STANDS.get(root)
                gated = kind == "mutant" and stand is not None
                fixed = pinned[:-1] if gated else pinned
                self.assertEqual(fixed, [(str(at), action) for at, action in enumerate(prefix)])
                if gated:
                    self.assertEqual(pinned[-1], (str(len(prefix)), f"{stand}, step"))
                    self.assertIn(f"all {{ turn > {len(prefix)}, step }}", instance)
                else:
                    self.assertIn(f"all {{ turn >= {len(prefix)}, step }}", instance)
                argv = check.command(case, "quint", Path("/evidence"), 1)
                self.assertEqual(argv[argv.index("--step") + 1], "rooted")
                self.assertEqual(argv[argv.index("--invariant") + 1], invariant)
                if kind == "safety":
                    self.assertEqual((case.depth, case.after, case.expected), (len(prefix) + free + 1, None, "ok"))
                    conjunct = f" and (turn == {len(prefix)} implies ({stand}))" if prefix else ""
                    self.assertIn(f"\n  val rootSafety = safety{conjunct}\n", instance)
                else:
                    self.assertEqual((case.depth, case.after, case.expected), (None, len(prefix) + 1, "violation"))
                if kind == "mutant":
                    model = self.MODEL
                    for old, new in loss.MUTANTS[name.removeprefix("loss-mutant-")][2]:
                        model = model.replace(old, new)
                    self.assertEqual(rendered["loss.qnt"], model)
                    self.assertNotEqual(rendered["loss.qnt"], self.MODEL)
                else:
                    self.assertEqual(rendered["loss.qnt"], self.MODEL)

    def test_a_root_with_no_free_action_after_its_prefix_is_refused(self):
        loss = check.loss_checks
        saved = loss.ROOTS["opened"]
        try:
            for free in (0, -1):
                loss.ROOTS["opened"] = (saved[0], free)
                with self.subTest(free=free), self.assertRaises(ValueError):
                    list(loss.cases(check.Case))
        finally:
            loss.ROOTS["opened"] = saved

    def test_a_checkpoint_outside_its_run_or_its_recipe_is_refused(self):
        loss = check.loss_checks
        saved = dict(loss.CHECKPOINTS)
        name = "loss-run-host-loss"
        length = len(loss.RUNS[name][0])
        try:
            for points in ({"loss-run-nowhere": [(1, "true")]}, {name: [(0, "true")]}, {name: [(-1, "true")]},
                           {name: [(length + 1, "true")]}):
                loss.CHECKPOINTS.clear()
                loss.CHECKPOINTS.update(points)
                with self.subTest(points=points), self.assertRaises(ValueError):
                    list(loss.cases(check.Case))
            loss.CHECKPOINTS.clear()
            loss.CHECKPOINTS.update({name: [(1, "true"), (length, "true")]})
            list(loss.cases(check.Case))
        finally:
            loss.CHECKPOINTS.clear()
            loss.CHECKPOINTS.update(saved)

    def test_each_directed_run_pins_its_recipe_and_checks_its_checkpoints_and_final_state(self):
        loss = check.loss_checks
        for name, (recipe, outcome) in loss.RUNS.items():
            checks = "".join(f" and (turn == {at} implies ({state}))" for at, state in loss.CHECKPOINTS.get(name, []))
            definitions = {
                name: ("runSafety", f"\n  val runSafety = safety{checks} and (turn == {len(recipe)} implies ({outcome}))\n"),
                f"{name}-reached": ("runWitness", f"\n  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n"),
            }
            for case_name, (invariant, definition) in definitions.items():
                with self.subTest(case=case_name):
                    case = CASES[case_name]
                    instance = check.inputs(case, ROOT / "quint")["case.qnt"]
                    self.assertIn(f"import loss(BOUND = {len(recipe)}).*", instance)
                    pinned = re.findall(r"all \{ turn == (\d+), (.*?) \},", instance)
                    self.assertEqual(pinned, [(str(at), action) for at, action in enumerate(recipe)])
                    self.assertIn(definition, instance)
                    argv = check.command(case, "quint", Path("/evidence"), 1)
                    self.assertEqual(argv[argv.index("--step") + 1], "recipe")
                    self.assertEqual(argv[argv.index("--invariant") + 1], invariant)

    def test_each_recipe_mutant_pins_its_recipe_and_must_violate_its_statement_at_the_last_action(self):
        loss = check.loss_checks
        for name, (statement, recipe, mutations) in loss.RUN_MUTANTS.items():
            with self.subTest(mutant=name):
                case = CASES[f"loss-mutant-{name}"]
                rendered = check.inputs(case, ROOT / "quint")
                self.assertIn(f"import loss(BOUND = {len(recipe)}).*", rendered["case.qnt"])
                pinned = re.findall(r"all \{ turn == (\d+), (.*?) \},", rendered["case.qnt"])
                self.assertEqual(pinned, [(str(at), action) for at, action in enumerate(recipe)])
                model = self.MODEL
                for old, new in mutations:
                    model = model.replace(old, new)
                self.assertEqual(rendered["loss.qnt"], model)
                self.assertNotEqual(rendered["loss.qnt"], self.MODEL)
                argv = check.command(case, "quint", Path("/evidence"), 1)
                self.assertEqual(argv[argv.index("--step") + 1], "recipe")
                self.assertEqual(argv[argv.index("--invariant") + 1], statement)
                self.assertEqual((case.expected, case.trace, case.after, case.recipe), ("violation", None, None, recipe))
                log = "".join(f"State {n}: x\n" for n in range(1, len(recipe) + 1))
                log += "[violation] Found an issue\nError: Invariant q_inv is violated.\n"
                log += "5 states generated, 5 distinct states found, 0 states left on queue.\n"
                with self.assertRaisesRegex(RuntimeError, "which end at its recipe's last action"):
                    check.judge(case, log, 1)


class Dispatch(unittest.TestCase):
    def test_every_dispatcher_refuses_an_undeclared_family(self):
        source = ROOT / "quint"
        for command in ("typecheck", "replay", "simulate", "tlc"):
            case = check.Case("stray", command=command, invariant="safety", family="nope")
            for name, call, args in [("inputs", check.inputs, (case, source)),
                                     ("command", check.command, (case, "quint", ROOT, 41234)),
                                     ("constants", check.constants, (case,)),
                                     ("judge", check.judge, (case, "", 0))]:
                with self.subTest(command=command, dispatcher=name), \
                        self.assertRaisesRegex(ValueError, "unknown family nope"):
                    call(*args)

    def test_only_the_session_family_takes_a_session_replay_or_simulation_verdict(self):
        per_action = ",".join(f"{name}:1" for name in check.REPLAY_ACTIONS)
        replay = (f"q1 connect replay: traces={check.REPLAY_TRACES} actions={check.REPLAY_TRACES + 1} longest=3 "
                  f"per_action={per_action} agreement=all\ntest result: ok. 1 passed;")
        session = check.Case("connect-replay", command="replay")
        self.assertEqual(check.judge(session, replay, 0)["traces"], check.REPLAY_TRACES)
        self.assertEqual(check.judge(CASES["simulation"], simulation(), 0)["traces"], int(check.SAMPLES))
        for command, log in (("replay", replay), ("simulate", simulation())):
            case = check.Case("stray", command=command, invariant="safety", family="tenure")
            with self.subTest(command=command), self.assertRaisesRegex(ValueError, "has no"):
                check.judge(case, log, 0)

    def test_a_mutation_target_absent_or_repeated_refuses(self):
        for text in ("", "a a"):
            case = check.Case("stray", command="tlc", invariant="safety", mutations=(("a", "b"),))
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "mutation target count"):
                check.apply_mutations(case, text)

    def test_a_tenure_mutation_chain_refuses_a_target_the_first_replacement_removed(self):
        first = ("val admitted = h == rec.owner", "val admitted = true")
        alone = check.Case("stray", command="tlc", invariant="safety", family="tenure", mutations=(first,))
        self.assertIn("val admitted = true", check.inputs(alone, ROOT / "quint")["tenure.qnt"])
        case = check.Case("stray", command="tlc", invariant="safety", family="tenure",
                          mutations=(first, ("val admitted = h == rec.owner", "val admitted = false")))
        with self.assertRaisesRegex(ValueError, "mutation target is not unique"):
            check.inputs(case, ROOT / "quint")

    def test_a_tenure_instance_keeps_the_schedules_its_recipe_names_and_drops_the_others(self):
        case = check.Case("stray", command="tlc", invariant="safety", family="tenure", recipe=["takeoverStep"])
        texts = check.inputs(case, ROOT / "quint")
        self.assertIn("recipe = any {\n    all { Set(0).contains(turn), takeoverStep },", texts["case.qnt"])
        self.assertIn("  action takeoverStep = any {\n", texts["tenure.qnt"])
        for dropped in ("step", "restartStep", "reclaimStep", "handoffStep"):
            with self.subTest(dropped=dropped):
                self.assertNotIn(f"  action {dropped} = any {{\n", texts["tenure.qnt"])

    def test_a_tenure_instance_holds_what_its_case_names_and_what_that_reaches(self):
        text = (ROOT / "quint/tenure.qnt").read_text()
        prune = check.tenure_checks.prune
        self.assertEqual(prune(text, {"reclaimStep", "safety", "reclaimInit"}, "stray").count("\n  action reclaimStep ="), 1)
        kept = prune(text, {"OwnBumpBeforeFB"}, "stray")
        self.assertIn("\n  val OwnBumpBeforeFB = ", kept)
        for dropped in ("  val safety = ", "  action init = ", "  action restartReport2(", "  val witnessFlip = "):
            with self.subTest(dropped=dropped):
                self.assertIn(dropped, text)
                self.assertNotIn(dropped, kept)
        for stays in ("  pure val EMAX = 3", "  var rec: Shard", "  type Proc = ", "  const BOUND: int"):
            with self.subTest(stays=stays):
                self.assertIn(stays, kept)
        reached = prune(text, {"restartReport2"}, "stray")
        for name in ("restartReport2", "restartDevice", "deviceStep", "advance", "unchangedRecords", "liveKey"):
            with self.subTest(reached=name):
                self.assertRegex(reached, rf"\n  (action|def) {name}\b")
        head, found, tail = check.tenure_checks.items(text, "stray")
        self.assertEqual("\n".join(head + [line for _, _, block in found for line in block] + tail), text)
        every = {name for kind, name, _ in found if kind in check.tenure_checks.PRUNABLE}
        self.assertEqual(prune(text, every, "stray"), text)

    def test_a_tenure_case_enters_by_its_instance_text_recipe_invariant_and_step(self):
        entries = check.tenure_checks.entries
        recipe = check.Case("stray", command="tlc", invariant="runSafety", family="tenure", recipe=['start("h1")'],
                            extra="  val runSafety = safety and turn < 3\n")
        self.assertLessEqual({"start", "safety", "turn", "runSafety", "init"}, entries(recipe))
        self.assertNotIn("step", entries(recipe))
        search = check.Case("stray", command="tlc", invariant="NoEpochReuse", family="tenure")
        self.assertLessEqual({"NoEpochReuse", "init", "step"}, entries(search))
        rooted = check.Case("stray", command="tlc", invariant="safety", family="tenure", step="prefixed",
                            extra="  action caseInit = reclaimInit\n  action prefixed = reclaimStep\n")
        self.assertLessEqual({"safety", "reclaimInit", "reclaimStep"}, entries(rooted))
        self.assertFalse({"init", "step"} & entries(rooted))

    def test_a_tenure_model_with_a_repeated_item_or_an_unknown_module_level_line_refuses_by_case(self):
        text = (ROOT / "quint/tenure.qnt").read_text()
        close = text.rindex("\n}")
        repeated = text[:close] + "\n  val safety = true" + text[close:]
        stray = text[:close] + "\n  nondet h = HOSTS.oneOf()" + text[close:]
        dangling = text[:close] + "\n  /// A comment that no item follows." + text[close:]
        for name, model, message in (("repeated", repeated, r"defines \['safety'\] more than once"),
                                     ("stray", stray, "module-level line that opens no item"),
                                     ("dangling", dangling, "doc comment that no item follows")):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, f"stray: .*{message}"):
                check.tenure_checks.prune(model, {"step"}, "stray")

    def test_a_preserve_mutation_target_absent_repeated_or_removed_refuses(self):
        first = ("pure val END = true", "pure val END = false")
        alone = check.Case("stray", command="tlc", invariant="safety", family="preserve", mutations=(first,))
        self.assertIn("pure val END = false", check.inputs(alone, ROOT / "quint")["preserve.qnt"])
        for mutations in ((("no such text", "x"),), (("st.srv", "x"),), (first, first)):
            case = check.Case("stray", command="tlc", invariant="safety", family="preserve", mutations=mutations)
            with self.subTest(mutations=mutations), self.assertRaisesRegex(ValueError, "mutation target is not unique"):
                check.inputs(case, ROOT / "quint")

    def test_a_setting_that_names_no_constant_of_its_family_refuses(self):
        for family in ("session", "detect", "route", "tenure", "prefix", "coverage", "capture", "preserve", "suffix", "saturation", "keyops", "binder", "creation"):
            case = check.Case("stray", command="tlc", invariant="safety", family=family, settings={"BOUNDS": "9"})
            with self.subTest(family=family), self.assertRaisesRegex(ValueError, f"name no {family} constant"):
                check.inputs(case, ROOT / "quint")

    def test_the_binder_release_scope_mutant_widens_the_restored_devices_and_keeps_the_decoded_names(self):
        model = check.inputs(CASES["binder-mutant-release-ignores-record"], ROOT / "quint")["binder.qnt"]
        self.assertIn("releasedNames: st.releasedNames.replaceAt(a, rawNames(st.rawRecords.nth(a)))", model)
        self.assertNotIn("requests: st.requests.replaceAt(a, st.records.nth(a))", model)

    def test_each_binder_invariant_stated_beside_the_model_has_a_mutant_that_must_violate_it(self):
        """A passing case shows that the model satisfies an invariant its instance module defines. A mutant case
        that changes the model's copy and checks the same definitions shows that the invariant can fail."""
        binder = [case for case in CASES.values() if case.family == "binder" and case.extra and not case.recipe]
        held = {case.invariant: case.extra for case in binder if case.expected == "ok"}
        broken = {case.invariant for case in binder
                  if case.expected == "violation" and case.mutations and case.extra == held.get(case.invariant)}
        self.assertLessEqual({"RollbackOnlyMoved", "UnlinkOnlyAfterRestores"}, set(held))
        self.assertEqual(set(held) - broken, set())

    def test_a_setting_on_a_typecheck_or_replay_refuses(self):
        for command, family in (("typecheck", "coverage"), ("replay", "session")):
            case = check.Case("stray", command=command, family=family, settings={"BOUND": "9"} if family == "coverage"
                              else {next(iter(check.CONSTANTS)): "1"})
            with self.subTest(command=command), self.assertRaisesRegex(ValueError, "applies no settings"):
                check.inputs(case, ROOT / "quint")


def passing(depth):
    """A TLC log of a completed check without violation whose search reached `depth`."""
    return ("[ok] No violation found\nModel checking completed. No error has been found.\n"
            "10 states generated, 7 distinct states found, 0 states left on queue\n"
            f"The depth of the complete state graph search is {depth}.\n")


# A synthetic projection of two prefix actions at BOUND 3, whose declared values the tests state as literals.
SYNTHETIC = {"prefix": ["fill(0)", "capture"], "step": "step", "settings": {"BOUND": "3"},
             "witnesses": ["witnessWarm"], "mutants": {}}
JOIN = check.join_checks.PROJECTIONS


def projection_case_names(name, projection):
    base = f"join-{name}"
    return [f"{base}-safety"] + [f"{base}-reach-{w}" for w in projection["witnesses"]] + \
        [f"{base}-mutant-{m}" for m in projection["mutants"]]


class Projections(unittest.TestCase):
    def test_a_join_check_short_of_its_bound_is_refused(self):
        case = CASES["join-capture-suffix-safety"]
        self.assertEqual(check.judge(case, passing(case.depth), 0)["depth"], case.depth)
        for depth in (case.depth - 1, case.depth + 1):
            with self.subTest(depth=depth), self.assertRaisesRegex(RuntimeError, "reached depth"):
                check.judge(case, passing(depth), 0)

    def test_a_handoff_root_short_of_its_bound_or_a_witness_inside_its_prefix_is_refused(self):
        roots = [case for name, case in CASES.items() if name.startswith("tenure-handoff-") and case.expected == "ok"]
        reaches = [case for name, case in CASES.items() if name.startswith("tenure-handoff-reach-")]
        self.assertTrue(roots and reaches)
        prefixes = {f"tenure-handoff-reach-{witness}": len(check.tenure_checks.HANDOFF_ROOTS[root][0])
                    for root, witness in check.tenure_checks.HANDOFF_REACHES}
        self.assertEqual(sorted(prefixes), sorted(case.name for case in reaches))
        for case in roots:
            with self.subTest(case=case.name):
                self.assertEqual(case.depth, int(case.settings["BOUND"]) + 1)
                self.assertEqual(check.judge(case, passing(case.depth), 0)["depth"], case.depth)
                with self.assertRaisesRegex(RuntimeError, "reached depth"):
                    check.judge(case, passing(case.depth - 1), 0)
        for case in reaches:
            with self.subTest(case=case.name):
                self.assertEqual(case.after, prefixes[case.name] + 1)
                self.assertEqual(check.judge(case, violation(case.after + 1), 1)["trace"], case.after + 1)
                with self.assertRaisesRegex(RuntimeError, "states 1 to N in order"):
                    check.judge(case, violation(case.after), 1)

    def test_the_arm_root_short_of_its_bound_or_a_violation_inside_its_prefix_is_refused(self):
        rooted = {name: case for name, case in CASES.items()
                  if name.startswith("tenure-takeover-afterArmReport1") or name == "tenure-takeover-ArmFbConfirmed"}
        searches = [case for case in rooted.values() if case.expected == "ok"]
        violations = [case for case in rooted.values() if case.expected == "violation"]
        self.assertEqual(len(searches), 2)
        self.assertEqual(len(violations), 6)
        prefix = len(check.tenure_checks.ARM_ROOT)
        for case in searches:
            with self.subTest(case=case.name):
                self.assertEqual(case.depth, int(case.settings["BOUND"]) + 1)
                self.assertEqual(check.judge(case, passing(case.depth), 0)["depth"], case.depth)
                with self.assertRaisesRegex(RuntimeError, "reached depth"):
                    check.judge(case, passing(case.depth - 1), 0)
        for case in violations:
            with self.subTest(case=case.name):
                self.assertEqual(case.after, prefix + 1)
                self.assertEqual(check.judge(case, violation(case.after + 1), 1)["trace"], case.after + 1)
                with self.assertRaisesRegex(RuntimeError, "states 1 to N in order"):
                    check.judge(case, violation(case.after), 1)

    def test_a_join_violation_inside_its_prefix_or_past_its_bound_is_refused(self):
        case = CASES["join-coverage-preserve-mutant-recover-before-page-fence"]
        limit = int(case.settings["BOUND"]) + 1
        for states in (case.after + 1, limit):
            with self.subTest(states=states):
                self.assertEqual(check.judge(case, violation(states), 1)["trace"], states)
        for states in (case.after, limit + 1):
            with self.subTest(states=states), self.assertRaisesRegex(RuntimeError, "states 1 to N in order"):
                check.judge(case, violation(states), 1)

    def test_a_join_violation_with_malformed_state_labels_is_refused(self):
        case = CASES["join-capture-suffix-mutant-release-ignores-hold"]
        good = [str(n) for n in range(1, 11)]
        self.assertEqual(check.judge(case, labelled(good), 1)["trace"], 10)
        for name, labels in (("missing state 1", good[1:]), ("reordered", good[:2] + [good[3], good[2]] + good[4:]),
                             ("duplicated", good[:3] + ["3"] + good[3:]), ("zero-padded", good[:1] + ["02"] + good[2:]),
                             ("stray", good + ["12"])):
            with self.subTest(name), self.assertRaisesRegex(RuntimeError, "states 1 to N in order"):
                check.judge(case, labelled(labels), 1)

    def test_a_synthetic_projection_pins_its_prefix_scheduler_depth_and_threshold(self):
        safety, reach = check.projection_cases("join", "stray", SYNTHETIC)
        self.assertEqual((safety.depth, safety.after, reach.after, reach.depth), (4, None, 3, None))
        for case in (safety, reach):
            self.assertEqual(case.step, "component")
            self.assertIn("  action component = any {\n    all { turn == 0, fill(0) },\n    all { turn == 1, capture },\n"
                          "    all { turn >= 2, step },\n  }\n", case.extra)

    def test_every_declared_projection_runs_its_scheduler_after_its_prefix(self):
        for name, projection in JOIN.items():
            prefix, bound = projection.get("prefix", []), int(projection["settings"]["BOUND"])
            step = "component" if prefix else projection["step"]
            for case_name in projection_case_names(name, projection):
                case = CASES[case_name]
                with self.subTest(case=case_name):
                    argv = check.command(case, "quint", Path("/evidence"), 1)
                    self.assertEqual(argv[argv.index("--step") + 1], step)
                    text = check.inputs(case, ROOT / "quint")["case.qnt"]
                    self.assertTrue(text.startswith("module joinCase {\n"), text[:80])
                    self.assertIn(f"  pure val BOUND = {bound}\n", text)
                    if prefix:
                        for at, action in enumerate(prefix):
                            self.assertIn(f"    all {{ turn == {at}, {action} }},\n", case.extra)
                        self.assertIn(f"    all {{ turn >= {len(prefix)}, {projection['step']} }},\n", case.extra)
                    else:
                        self.assertNotIn("action component", case.extra)
                    if case_name.endswith("-safety"):
                        self.assertEqual((case.depth, case.after), (bound + 1, None))
                    else:
                        self.assertEqual((case.depth, case.after), (None, len(prefix) + 1))

    def test_a_command_that_drops_a_cases_step_is_refused(self):
        case = CASES["join-capture-suffix-safety"]

        def dropped(case, quint, directory, port):
            return ["quint", "verify", "case.qnt", "--invariant", case.invariant]

        def other(case, quint, directory, port):
            return ["quint", "verify", "case.qnt", "--invariant", case.invariant, "--step", "step"]

        original = check.join_checks.command
        try:
            for stub in (dropped, other):
                check.join_checks.command = stub
                with self.subTest(stub=stub.__name__), self.assertRaisesRegex(ValueError, "drops the case's step"):
                    check.command(case, "quint", Path("/evidence"), 1)
        finally:
            check.join_checks.command = original

    def test_a_command_that_drops_a_cases_recipe_is_refused(self):
        case = CASES["capture-mutant-LoadGuardNeverFires"]
        self.assertEqual(check.command(case, "quint", Path("/evidence"), 1)[-2:], ["--step", "recipe"])
        original = check.capture_checks.command

        def dropped(case, quint, directory, port):
            return original(case, quint, directory, port)[:-2]

        def other(case, quint, directory, port):
            return [*original(case, quint, directory, port)[:-1], "step"]

        try:
            for stub in (dropped, other):
                check.capture_checks.command = stub
                with self.subTest(stub=stub.__name__), self.assertRaisesRegex(
                        ValueError, rf"^{re.escape(case.name)}: the capture command drops the case's recipe$"):
                    check.command(case, "quint", Path("/evidence"), 1)
        finally:
            check.capture_checks.command = original

    def test_a_step_beside_a_recipe_or_on_a_session_case_refuses(self):
        for fields in ({"family": "suffix", "recipe": ["seal"], "step": "step"}, {"step": "step"}):
            with self.subTest(fields=fields), self.assertRaisesRegex(ValueError, "step applies only"):
                check.Case("stray", **fields)

    def test_a_case_that_declares_an_invariant_and_a_temporal_property_refuses(self):
        with self.assertRaisesRegex(ValueError, "^stray: a case checks one property"):
            check.Case("stray", invariant="safety", temporal="progress")

    def test_a_tlc_case_without_one_named_property_refuses(self):
        for fields in ({}, {"invariant": "safety,agreement"}, {"temporal": "progress, liveness"}, {"invariant": "true"}):
            with self.subTest(fields=fields), self.assertRaisesRegex(ValueError, "^stray: a tlc case names one property"):
                check.Case("stray", **fields)
        for fields in ({"command": "typecheck"}, {"command": "replay"}, {"command": "simulate", "invariant": "safety"},
                       {"invariant": "runSafety"}, {"temporal": "progress"}):
            with self.subTest(fields=fields):
                check.Case("stray", **fields)

    def test_a_recipe_on_a_session_case_refuses(self):
        with self.assertRaisesRegex(ValueError, "^stray: a recipe applies only to a family case"):
            check.Case("stray", invariant="safety", expected="violation", recipe=["init"])

    def test_a_passing_check_with_states_left_on_its_queue_is_refused(self):
        case = CASES["join-prefix-saturation-safety"]
        with self.assertRaisesRegex(RuntimeError, "left on its queue"):
            check.judge(case, passing(case.depth).replace("0 states left", "3 states left"), 0)

    def test_a_violation_without_a_declared_length_needs_ordered_labels(self):
        case = CASES["suffix-run-damagedTombReused-reached"]
        self.assertEqual((case.after, case.trace), (None, None))
        self.assertEqual(check.judge(case, violation(5), 1)["trace"], 5)
        for labels in (["1", "2", "2", "3"], ["1", "02", "3"], ["1", "3"], ["1", "\u0662"]):
            with self.subTest(labels=labels), self.assertRaisesRegex(RuntimeError, "states 1 to N in order"):
                check.judge(case, labelled(labels), 1)

    def test_an_after_threshold_without_a_bound_is_a_lower_limit_alone(self):
        case = check.Case("stray", invariant="unreached", expected="violation", after=3)
        self.assertEqual(check.judge(case, violation(9), 1)["trace"], 9)
        with self.assertRaisesRegex(RuntimeError, "states 1 to N in order"):
            check.judge(case, violation(3), 1)

    def test_a_projection_declaration_out_of_its_bounds_or_with_a_repeated_identity_refuses(self):
        self.assertEqual(len(list(check.projection_cases("join", "stray", SYNTHETIC))), 2)
        repeated = {"a": ("Retained", "witnessWarm", [("x", "y")]), "b": ("Retained", "witnessWarm", [("x", "y")])}
        for projection, message in (({**SYNTHETIC, "settings": {"BOUND": "2"}}, "leaves no step"),
                                    ({**SYNTHETIC, "mutants": {"m": ("Retained", "witnessChain", [])}}, "is not a witness"),
                                    ({**SYNTHETIC, "mutants": repeated}, "one property under one mutation list")):
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                list(check.projection_cases("join", "stray", projection))

    def test_a_depth_on_a_violation_or_a_trace_length_on_a_passing_check_refuses(self):
        for fields, message in (({"depth": 4, "expected": "violation"}, "depth applies"),
                                ({"after": 3}, "trace length applies"), ({"trace": 5}, "trace length applies")):
            with self.subTest(fields=fields), self.assertRaisesRegex(ValueError, message):
                check.Case("stray", **fields)

    def test_no_join_mutant_repeats_a_registered_mutant(self):
        registered = [list(case.mutations) for case in CASES.values() if case.family != "join" and case.mutations]
        for name, projection in JOIN.items():
            for mutant, (_, _, mutations) in projection["mutants"].items():
                with self.subTest(projection=name, mutant=mutant):
                    self.assertNotIn(list(mutations), registered)

    def test_every_reduction_and_mutation_target_occurs_once_in_its_file(self):
        joins = (ROOT / "quint/joins.qnt").read_text()
        for name, projection in JOIN.items():
            module = check.join_checks.module_text(joins, projection["module"])
            for source, old, _ in projection["reductions"]:
                with self.subTest(projection=name, reduction=old):
                    self.assertEqual((ROOT / "quint" / source).read_text().count(old), 1)
            for mutant, (_, _, mutations) in projection["mutants"].items():
                for old, _ in mutations:
                    with self.subTest(projection=name, mutant=mutant, target=old):
                        self.assertEqual(module.count(old), 1)

    def test_the_floor_rule_is_the_prefix_models_shrink_condition(self):
        prefix = (ROOT / "quint/prefix.qnt").read_text()
        joins = (ROOT / "quint/joins.qnt").read_text()
        self.assertIn("val newest = p.at + 1 >= known\n", prefix)
        self.assertIn("val shrink = newest and submitted.forall(q => q == p.id or succeeded.contains(q) or q < p.id)\n",
                      prefix)
        self.assertIn("    p.at + 1 >= P::known and P::submitted.forall(q => q == p.id or P::succeeded.contains(q) "
                      "or q < p.id)\n", joins)


# The stand-in for `quint run` resolves a relative `--out-itf` path against its working directory.
QUINT_RUN = """#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in
    --out-itf) out=$2; shift ;;
    --max-steps) steps=$2; shift ;;
  esac
  shift
done
states='{}'
while [ "$steps" -gt 0 ]; do states="$states,{}"; steps=$((steps - 1)); done
printf '{"#meta":{"format":"ITF"},"states":[%s]}\\n' "$states" > "$out"
"""


class Generators(unittest.TestCase):
    def test_a_trace_generator_writes_its_traces_under_a_relative_output_directory(self):
        storage = ROOT / "crates/kestrike/src/storage"
        for script, fixtures in (("grace_fixtures.py", "grace_replay_fixtures"),
                                 ("lookup_fixtures.py", "lookup_replay_fixtures"),
                                 ("reclaim_fixtures.py", "reclaim_replay_fixtures"),
                                 ("register_fixtures.py", "register_replay_fixtures")):
            with self.subTest(script=script), tempfile.TemporaryDirectory() as temporary:
                quint = Path(temporary) / "quint"
                quint.write_text(QUINT_RUN)
                quint.chmod(0o755)
                run = subprocess.run([sys.executable, str(ROOT / "quint" / script), "--quint", str(quint),
                                      "--output", "traces"], cwd=temporary, capture_output=True, text=True, check=False)
                self.assertEqual(run.returncode, 0, run.stderr)
                written = {path.name for path in (Path(temporary) / "traces").glob("*.itf.json")}
                self.assertEqual(written, {path.name for path in (storage / fixtures).glob("*.itf.json")})


# A stub `quint run` whose trace holds `--max-steps` + 1 states, each naming the trace's working directory.
QUINT_NAMED = QUINT_RUN.replace("states='{}'", 'name=$(basename "$PWD"); one="{\\"n\\":\\"$name\\"}"; states=$one').replace(
    'states="$states,{}"', 'states="$states,$one"')


def standbys_fixtures():
    spec = importlib.util.spec_from_file_location("standbys_fixtures", ROOT / "quint/standbys_fixtures.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StandbysGenerator(unittest.TestCase):
    def stub(self, directory, text):
        quint = Path(directory) / "bin" / "quint"
        quint.parent.mkdir()
        quint.write_text(text)
        quint.chmod(0o755)
        return quint

    def generate(self, directory, text, *args):
        self.stub(directory, text)
        return subprocess.run([sys.executable, str(ROOT / "quint/standbys_fixtures.py"), "--quint", "bin/quint",
                               "--output", "traces", *args], cwd=directory, capture_output=True, text=True,
                              check=False)

    def test_a_relative_quint_path_runs_from_the_callers_directory_and_writes_every_declared_trace(self):
        module = standbys_fixtures()
        with tempfile.TemporaryDirectory() as temporary:
            run = self.generate(temporary, QUINT_NAMED)
            self.assertEqual(run.returncode, 0, run.stderr)
            traces = Path(temporary) / "traces"
            written = {path.name.removesuffix(".itf.json"): path for path in traces.glob("*.itf.json")}
            declared = module.fixtures()
            self.assertEqual(set(written), set(declared))
            self.assertEqual({path.name for path in (ROOT / module.FIXTURES).glob("*.itf.json")},
                             {f"{name}.itf.json" for name in declared})
            for name, path in written.items():
                try:
                    recorded = json.loads(path.read_text())["#meta"]["standbys"]
                except (OSError, ValueError, KeyError) as error:
                    self.fail(f"{name}: the written trace is unreadable: {error}")
                self.assertEqual(recorded, {"model_sha256": recorded["model_sha256"], **declared[name][1]})

    def test_a_run_that_writes_no_trace_is_refused_and_leaves_an_older_fixture(self):
        module = standbys_fixtures()
        declared = module.fixtures()
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(module, "fixtures", lambda: {"run_enrollOne": declared["run_enrollOne"]}):
            traces = Path(temporary) / "traces"
            traces.mkdir()
            older = traces / "run_enrollOne.itf.json"
            try:
                trace = json.loads((ROOT / module.FIXTURES / older.name).read_text())
            except (OSError, ValueError) as error:
                self.fail(f"{older.name}: the committed trace is unreadable: {error}")
            trace["#meta"]["older"] = True
            older.write_text(json.dumps(trace))
            kept = older.read_bytes()
            quint = self.stub(temporary, "#!/bin/sh\nexit 0\n")
            with self.assertRaisesRegex(ValueError, "run_enrollOne: Quint wrote no readable trace"):
                module.generate(str(quint), traces)
            self.assertEqual(older.read_bytes(), kept)

    def test_a_trace_whose_states_are_no_list_of_objects_is_refused(self):
        for states in ('{"rows":[%s]}', '[[%s]]'):
            text = QUINT_RUN.replace('"states":[%s]', f'"states":{states}')
            self.assertNotEqual(text, QUINT_RUN)
            with self.subTest(states=states), tempfile.TemporaryDirectory() as temporary:
                run = self.generate(temporary, text, "--jobs", "1")
                self.assertNotEqual(run.returncode, 0)
                self.assertIn("the states are not a list of objects", run.stderr)

    def test_traces_with_equal_states_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = self.generate(temporary, QUINT_RUN)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn("its states equal those of", run.stderr)

    def test_a_model_copy_that_differs_from_the_recorded_digest_is_refused(self):
        module = standbys_fixtures()
        inputs = module.standbys_check.inputs

        def edited(case, source):
            texts = inputs(case, source)
            return {**texts, "standbys.qnt": texts["standbys.qnt"] + "\n"}

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(module.standbys_check, "inputs", edited):
            quint = self.stub(temporary, QUINT_NAMED)
            with self.assertRaisesRegex(ValueError, "the model copy differs"):
                module.generate(str(quint), Path(temporary) / "traces")

    def test_a_row_that_names_a_second_instance_is_refused_by_the_generator_and_the_checker(self):
        module = standbys_fixtures()
        for table, row in (("RUNS", ([], "true", {}, {}, {})), ("RECIPES", ([], "true", {}, {}))):
            with self.subTest(table=table), mock.patch.dict(getattr(module.standbys_check, table), {"twice": row}):
                with self.assertRaisesRegex(ValueError, "name more than one instance"):
                    module.directed()
                with self.assertRaisesRegex(ValueError, "name more than one instance"):
                    list(module.standbys_check.cases(check.Case))

    def test_a_zero_timeout_leaves_the_bound_to_the_caller(self):
        module = standbys_fixtures()
        bounds = []

        def quint(argv, timeout, **_):
            bounds.append(timeout)
            out = Path(argv[argv.index("--out-itf") + 1])
            states = [{"n": out.parent.name}] * (int(argv[argv.index("--max-steps") + 1]) + 1)
            out.write_text(json.dumps({"#meta": {"format": "ITF"}, "states": states}))

        for timeout, bound in ((None, None), (module.TIMEOUT, module.TIMEOUT)):
            bounds.clear()
            with self.subTest(timeout=timeout), tempfile.TemporaryDirectory() as temporary, \
                    mock.patch.object(module.subprocess, "run", quint):
                module.generate(sys.executable, Path(temporary) / "traces", 4, timeout)
                self.assertEqual(set(bounds), {bound})

    def test_a_directed_trace_steps_its_recipe_and_a_seeded_trace_the_models_step(self):
        module = standbys_fixtures()
        declared = module.fixtures()
        two = {name: declared[name] for name in ("run_enrollOne", "step_5b00")}
        steps = {}

        def quint(argv, cwd, **_):
            steps[Path(cwd).name] = argv[argv.index("--step") + 1] if "--step" in argv else None
            out = Path(argv[argv.index("--out-itf") + 1])
            states = [{"n": out.parent.name}] * (int(argv[argv.index("--max-steps") + 1]) + 1)
            out.write_text(json.dumps({"#meta": {"format": "ITF"}, "states": states}))

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(module, "fixtures", lambda: two), \
                mock.patch.object(module.subprocess, "run", quint):
            module.generate(sys.executable, Path(temporary) / "traces")
        self.assertEqual(steps, {"run_enrollOne": "recipe", "step_5b00": None})

    def test_a_trace_that_stops_before_its_final_action_or_names_no_format_is_refused(self):
        short = QUINT_NAMED.replace('states=$one', 'states=$one; steps=$((steps - 1))')
        formatless = QUINT_NAMED.replace('"format":"ITF"', '"format":1')
        for text, refusal in ((short, "the trace stopped before its final action"),
                              (formatless, "the ITF format is not a string")):
            with self.subTest(refusal=refusal), tempfile.TemporaryDirectory() as temporary:
                run = self.generate(temporary, text, "--jobs", "1")
                self.assertNotEqual(run.returncode, 0)
                self.assertIn(refusal, run.stderr)

    def test_a_quint_path_resolves_from_the_callers_directory_and_an_unknown_name_is_refused(self):
        module = standbys_fixtures()
        declared = module.fixtures()
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(module, "fixtures", lambda: {"run_enrollOne": declared["run_enrollOne"]}):
            quint = self.stub(temporary, QUINT_NAMED)
            cwd = os.getcwd()
            os.chdir(temporary)
            try:
                self.assertEqual(module.executable("bin/quint"), str(quint.resolve()))
                with self.assertRaisesRegex(ValueError, "no-such-quint: no executable of that name on PATH"):
                    module.generate("no-such-quint", Path(temporary) / "traces")
            finally:
                os.chdir(cwd)


def loss_fixtures():
    spec = importlib.util.spec_from_file_location("loss_fixtures", ROOT / "quint/loss_fixtures.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def loss_state(ev, procs=None, shards=None, vrecs=None):
    """A loss model state as `loss_fixtures.plain` returns it, holding the fields `left_out` reads."""
    idle = {"op": "idle", "pc": "", "vol": 0, "shard": 0, "rc": {"vol": 0}}
    held = {p: {**idle, **(procs or {}).get(p, {})} for p in (0, 1, 2)}
    rows = {1: {"ver": 1, "spare": 0}, 2: {"ver": 1, "spare": 0}, **(shards or {})}
    volumes = {1: {"state": 2}, 2: {"state": 2}, 3: {"state": 1}, **(vrecs or {})}
    event = {"proc": 0, "act": "", "op": "", "pc": "", "res": "", "shard": 1, **ev}
    return {"lossCase::loss::st": {"ev": event, "procs": held, "shards": rows, "vrecs": volumes}}


class LossGenerator(unittest.TestCase):
    def stub(self, directory, text):
        quint = Path(directory) / "bin" / "quint"
        quint.parent.mkdir()
        quint.write_text(text)
        quint.chmod(0o755)
        return quint

    def test_the_committed_traces_are_the_declared_ones_and_hold_no_left_out_interleaving(self):
        module = loss_fixtures()
        directory = ROOT / module.FIXTURES
        self.assertEqual({path.name for path in directory.glob("*.itf.json")},
                         {f"{name}.itf.json" for name in module.fixtures()})
        for path in sorted(directory.glob("*.itf.json")):
            with self.subTest(trace=path.name):
                states = [module.plain(state) for state in json.loads(path.read_text())["states"]]
                self.assertIsNone(module.left_out(states))

    def test_each_left_out_interleaving_is_named_and_its_neighbour_is_kept(self):
        module = loss_fixtures()
        start = loss_state({})
        abandoning = {2: {"op": "abandon", "vol": 3, "shard": 1, "pc": "retire"}}
        flip_begins = {"proc": 1, "act": "begin", "op": "flip", "pc": "shard"}
        flipping = {1: {"op": "flip", "vol": 3, "shard": 1, "pc": "shard"}}
        recorded = loss_state({"proc": 1, "act": "write", "op": "create", "pc": "record", "res": "record"})
        recording = loss_state({}, procs={1: {"op": "create", "vol": 3, "shard": 1, "pc": "record"}})
        provision_read = {"proc": 2, "act": "read", "op": "create", "pc": "provRead"}
        provisioning = {2: {"op": "create", "vol": 3, "shard": 1, "pc": "provRead"}}
        named = loss_state({"proc": 1, "act": "read", "op": "abandon", "pc": "named"},
                           procs={1: {"op": "abandon", "vol": 3, "shard": 1, "pc": "retire"}})
        naming = loss_state({}, procs={1: {"op": "abandon", "vol": 3, "shard": 1, "pc": "named"}})
        retired = {"proc": 1, "act": "write", "op": "abandon", "pc": "retire", "res": "ok"}
        retiring = {1: {"op": "abandon", "vol": 3, "shard": 1, "pc": "retire"}}
        volume_read = {"proc": 1, "act": "read", "op": "abandon", "pc": "volume"}
        reading = {1: {"op": "abandon", "vol": 3, "shard": 1, "pc": "volume"}}
        spare = {"proc": 2, "act": "write", "op": "flip", "pc": "spare", "res": "ok"}
        retires = loss_state({"proc": 2, "act": "write", "op": "abandon", "pc": "retire", "res": "ok"},
                             procs={2: {**abandoning[2], "pc": "raise"}})
        crashes = loss_state({"proc": 2, "act": "crash", "op": "abandon", "pc": "retire", "res": "crash"})
        refuses = loss_state({"proc": 2, "act": "write", "op": "abandon", "pc": "retire", "res": "condition"})
        lost_reply = {"proc": 2, "act": "unknown", "op": "abandon", "pc": "retire", "res": "unknown"}
        lost = loss_state(lost_reply, vrecs={3: {"state": 3}})
        stale = loss_state(lost_reply)
        named_abandon = {2: {**abandoning[2], "pc": "named"}}
        creating = {1: {"op": "create", "vol": 0, "shard": 1, "pc": "shard", "rc": {"vol": 3}}}
        found = {"proc": 1, "act": "read", "op": "create", "pc": "shard", "res": "created"}
        rereading = {1: {"op": "create", "vol": 3, "shard": 1, "pc": "reread"}}
        reread = {"proc": 1, "act": "read", "op": "create", "pc": "reread", "res": "created"}
        rows = (
            ("precedes the retirement write of process 2",
             [loss_state({}, procs=abandoning), loss_state(flip_begins, procs={**abandoning, **flipping}), retires],
             [loss_state({}, procs=abandoning), loss_state(flip_begins, procs={**abandoning, **flipping}), crashes]),
            ("precedes the retirement write of process 2",
             [loss_state({}, procs=abandoning), loss_state(flip_begins, procs={**abandoning, **flipping}), lost],
             [loss_state({}, procs=abandoning), loss_state(flip_begins, procs={**abandoning, **flipping}), refuses]),
            ("precedes the retirement write of process 2",
             [loss_state({}, procs=abandoning), loss_state(flip_begins, procs={**abandoning, **flipping}), lost],
             [loss_state({}, procs=abandoning), loss_state(flip_begins, procs={**abandoning, **flipping}), stale]),
            ("precedes the retirement write of process 2",
             [loss_state({}, procs=abandoning), loss_state(flip_begins, procs={**abandoning, **flipping}), retires],
             [loss_state({}, procs={2: {**abandoning[2], "pc": "current"}}),
              loss_state(flip_begins, procs={2: {**abandoning[2], "pc": "current"}, **flipping})]),
            ("precedes the retirement write of process 2",
             [loss_state({}, procs={**creating, **named_abandon}), loss_state(found, procs=named_abandon), retires],
             [loss_state({}, procs={**creating, **named_abandon}), loss_state(found, procs=named_abandon), crashes]),
            ("precedes the retirement write of process 2",
             [loss_state({}, procs={**rereading, **abandoning}), loss_state(reread, procs=abandoning), retires],
             [loss_state({}, procs={**rereading, **abandoning}), loss_state(reread, procs=abandoning), crashes]),
            ("a provision read of volume 3",
             [recording, recorded, loss_state({}, procs=provisioning), loss_state(provision_read)],
             [recording, recorded, loss_state({}, procs=provisioning, vrecs={3: {"state": 3}}),
              loss_state(provision_read, vrecs={3: {"state": 3}})]),
            ("a shard write precedes the settling write of process 1",
             [naming, named, loss_state({}, procs=retiring, shards={1: {"ver": 2, "spare": 0}}), loss_state(retired)],
             [naming, named, loss_state({}, procs=retiring), loss_state(retired)]),
            ("clears the spare it retired",
             [loss_state({}, procs=reading, shards={1: {"ver": 2, "spare": 3}}, vrecs={3: {"state": 3}}),
              loss_state(volume_read, vrecs={3: {"state": 3}})],
             [loss_state({}, procs=reading, vrecs={3: {"state": 3}}), loss_state(volume_read, vrecs={3: {"state": 3}})]),
            ("precedes a shard write of process 2",
             [naming, named, loss_state({}, procs={**retiring, 2: {"op": "flip", "vol": 3, "shard": 1, "pc": "spare"}}),
              loss_state(retired, procs={2: {"op": "flip", "vol": 3, "shard": 1, "pc": "spare"}}),
              loss_state(spare, procs={2: {"op": "flip", "vol": 3, "shard": 1, "pc": "reread"}})],
             [naming, named, loss_state({}, procs={**retiring, 2: {"op": "flip", "vol": 3, "shard": 1, "pc": "reread"}}),
              loss_state(retired, procs={2: {"op": "flip", "vol": 3, "shard": 1, "pc": "reread"}}),
              loss_state({"proc": 2, "act": "read", "op": "flip", "pc": "reread"},
                         procs={2: {"op": "flip", "vol": 3, "shard": 1, "pc": "unused"}})]),
        )
        other = {2: {"op": "abandon", "vol": 3, "shard": 1, "pc": "volume"}}
        other_read = {"proc": 2, "act": "read", "op": "abandon", "pc": "volume"}
        rows += (
            ("a shard write precedes the settling write of process 1",
             [naming, named, loss_state({}, procs={**retiring, **other}, vrecs={3: {"state": 3}}),
              loss_state(other_read, procs=retiring, vrecs={3: {"state": 3}}), loss_state(retired)],
             [naming, named, loss_state({}, procs={**retiring, **other}, vrecs={3: {"state": 3}}),
              loss_state({"proc": 2, "act": "crash", "op": "abandon", "pc": "volume"}, procs=retiring,
                         vrecs={3: {"state": 3}}), loss_state(retired)]),
            ("precedes a shard write of process 2",
             [naming, named, loss_state({}, procs={**retiring, 2: {"op": "flip", "vol": 3, "shard": 1, "pc": "volume"}}),
              loss_state(retired, procs={2: {"op": "flip", "vol": 3, "shard": 1, "pc": "volume"}}),
              loss_state({"proc": 2, "act": "write", "op": "flip", "pc": "flip", "res": "flip"})],
             [naming, named, loss_state({}, procs={**retiring, 2: {"op": "flip", "vol": 3, "shard": 1, "pc": "volume"}}),
              loss_state(retired, procs={2: {"op": "flip", "vol": 3, "shard": 1, "pc": "volume"}}),
              loss_state({"proc": 2, "act": "read", "op": "flip", "pc": "reread"},
                         procs={2: {"op": "flip", "vol": 3, "shard": 1, "pc": "unused"}}),
              loss_state({"proc": 2, "act": "write", "op": "flip", "pc": "flip", "res": "flip"})]),
        )
        for reason, refused, kept in rows:
            with self.subTest(reason=reason):
                self.assertIn(reason, module.left_out([start, *refused]) or "")
                self.assertIsNone(module.left_out([start, *kept]))

    def test_a_relative_quint_path_runs_from_the_callers_directory_and_writes_every_declared_trace(self):
        module = loss_fixtures()
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(module, "left_out", lambda states: None):
            quint = self.stub(temporary, QUINT_NAMED)
            traces = Path(temporary) / "traces"
            cwd = os.getcwd()
            os.chdir(temporary)
            try:
                module.generate("bin/quint", traces, 4)
            finally:
                os.chdir(cwd)
            written = {path.name.removesuffix(".itf.json"): path for path in traces.glob("*.itf.json")}
            declared = module.fixtures()
            self.assertEqual(set(written), set(declared))
            for name, path in written.items():
                recorded = json.loads(path.read_text())["#meta"]["loss"]
                self.assertEqual(recorded, {"model_sha256": recorded["model_sha256"], **declared[name][1]})
            self.assertTrue(quint.exists())

    def test_a_trace_the_replay_leaves_out_is_refused(self):
        module = loss_fixtures()
        declared = module.fixtures()
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(module, "fixtures", lambda: {"run_retirement": declared["run_retirement"]}), \
                mock.patch.object(module, "left_out", lambda states: "state 1: a reason"):
            quint = self.stub(temporary, QUINT_NAMED)
            with self.assertRaisesRegex(ValueError, "run_retirement: the replay leaves this trace out: state 1"):
                module.generate(str(quint), Path(temporary) / "traces")

    def test_a_trace_that_holds_no_loss_state_is_refused(self):
        module = loss_fixtures()
        declared = module.fixtures()
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(module, "fixtures", lambda: {"run_retirement": declared["run_retirement"]}):
            quint = self.stub(temporary, QUINT_NAMED)
            with self.assertRaisesRegex(ValueError, "run_retirement: the trace holds no loss state"):
                module.generate(str(quint), Path(temporary) / "traces")

    def test_traces_with_equal_states_are_refused_and_none_is_written(self):
        module = loss_fixtures()
        declared = module.fixtures()
        equal = {name: declared[name] for name in ("step_init_7900", "step_init_7901")}
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(module, "left_out", lambda states: None), \
                mock.patch.object(module, "fixtures", lambda: equal):
            quint = self.stub(temporary, QUINT_RUN)
            traces = Path(temporary) / "traces"
            with self.assertRaisesRegex(ValueError, "its states equal those of"):
                module.generate(str(quint), traces, 4)
            self.assertEqual(list(traces.glob("*.itf.json")), [])

    def written_by(self, directory, states):
        """A Quint stub that writes `states(steps)`, the JSON text of the states of a run of `steps` steps."""
        return self.stub(directory, f"""#!{sys.executable}
import json, sys
steps = int(sys.argv[sys.argv.index("--max-steps") + 1])
with open(sys.argv[sys.argv.index("--out-itf") + 1], "w") as out:
    out.write('{{"#meta": {{"format": "ITF"}}, "states": ' + ({states}) + '}}')
""")

    def assert_refused(self, quint_text, message):
        module = loss_fixtures()
        declared = module.fixtures()
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(module, "fixtures", lambda: {"run_retirement": declared["run_retirement"]}):
            quint = self.written_by(temporary, quint_text) if quint_text.startswith("json") else \
                self.stub(temporary, quint_text)
            traces = Path(temporary) / "traces"
            with self.assertRaisesRegex(ValueError, f"run_retirement: .*{message}"):
                module.generate(str(quint), traces)
            self.assertEqual(list(traces.glob("*.itf.json")), [])

    def test_a_run_that_writes_no_readable_trace_is_refused(self):
        self.assert_refused("#!/bin/sh\nexit 0\n", "Quint wrote no readable trace")
        self.assert_refused('json.dumps("x" * (steps + 1))', "the states are not a list of objects")
        self.assert_refused('json.dumps([{}] * steps + ["x"])', "the states are not a list of objects")
        self.assert_refused("json.dumps([{}] * steps)", "the trace stopped before its final action")
        self.assert_refused(QUINT_NAMED.replace('"format":"ITF"', '"format":1'), "the ITF format is not a string")

    def test_a_quint_path_resolves_from_the_callers_directory_and_an_unknown_name_is_refused(self):
        module = loss_fixtures()
        with tempfile.TemporaryDirectory() as temporary:
            quint = self.stub(temporary, QUINT_NAMED)
            cwd = os.getcwd()
            os.chdir(temporary)
            try:
                self.assertEqual(module.executable("bin/quint"), str(quint.resolve()))
                with self.assertRaisesRegex(ValueError, "no-such-quint: no executable of that name on PATH"):
                    module.generate("no-such-quint", Path(temporary) / "traces")
            finally:
                os.chdir(cwd)

    def test_a_malformed_integer_or_map_row_is_refused_as_no_loss_state(self):
        for state in ({"x": {"#bigint": "x"}}, {"x": {"#map": [[{"#bigint": "1"}]]}}):
            with self.subTest(state=state):
                self.assert_refused(f"json.dumps([{state!r}] * (steps + 1))", "the trace holds no loss state")

    def test_an_output_directory_that_holds_an_entry_is_refused_before_any_run(self):
        module = loss_fixtures()
        with tempfile.TemporaryDirectory() as temporary:
            ran = Path(temporary) / "ran"
            quint = self.stub(temporary, f"#!/bin/sh\ntouch {ran}\n")
            traces = Path(temporary) / "traces"
            traces.mkdir()
            sentinel = traces / "run_retirement.itf.json"
            sentinel.write_bytes(b"sentinel")
            with self.assertRaisesRegex(ValueError, "the output directory holds entries"):
                module.generate(str(quint), traces)
            self.assertEqual(sentinel.read_bytes(), b"sentinel")
            self.assertEqual([path.name for path in traces.iterdir()], [sentinel.name])
            self.assertFalse(ran.exists())

    def test_a_bare_quint_name_found_through_a_relative_path_entry_runs_in_each_trace_directory(self):
        module = loss_fixtures()
        declared = module.fixtures()
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(module, "left_out", lambda states: None), \
                mock.patch.object(module, "fixtures", lambda: {"run_retirement": declared["run_retirement"]}), \
                mock.patch.dict(os.environ, {"PATH": "bin" + os.pathsep + os.environ.get("PATH", "")}):
            self.stub(temporary, QUINT_NAMED)
            cwd = os.getcwd()
            os.chdir(temporary)
            try:
                module.generate("quint", Path("traces"))
            finally:
                os.chdir(cwd)
            self.assertTrue((Path(temporary) / "traces" / "run_retirement.itf.json").exists())

    def test_the_command_line_passes_a_zero_timeout_as_no_bound_and_writes_a_relative_output(self):
        module = loss_fixtures()
        declared = module.fixtures()
        two = {name: declared[name] for name in ("run_retirement", "step_racing_7900")}
        bounds = []

        def quint(argv, timeout, cwd, **_):
            bounds.append(timeout)
            out = Path(argv[argv.index("--out-itf") + 1])
            states = [{"n": out.parent.name}] * (int(argv[argv.index("--max-steps") + 1]) + 1)
            out.write_text(json.dumps({"#meta": {"format": "ITF"}, "states": states}))

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(module.subprocess, "run", quint), \
                mock.patch.object(module, "left_out", lambda states: None), \
                mock.patch.object(module, "fixtures", lambda: two):
            cwd = os.getcwd()
            os.chdir(temporary)
            try:
                module.main(["--quint", sys.executable, "--output", "traces", "--timeout", "0", "--jobs", "2"])
            finally:
                os.chdir(cwd)
            self.assertEqual(bounds, [None, None])
            self.assertEqual({path.name for path in (Path(temporary) / "traces").glob("*.itf.json")},
                             {f"{name}.itf.json" for name in two})

    def test_a_model_copy_that_differs_from_the_recorded_digest_is_refused(self):
        module = loss_fixtures()
        inputs = module.loss_check.inputs

        def edited(case, source):
            texts = inputs(case, source)
            return {**texts, "loss.qnt": texts["loss.qnt"] + "\n"}

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(module.loss_check, "inputs", edited):
            quint = self.stub(temporary, QUINT_NAMED)
            with self.assertRaisesRegex(ValueError, "the model copy differs"):
                module.generate(str(quint), Path(temporary) / "traces")

    def test_a_seeded_trace_steps_its_root_and_a_zero_timeout_leaves_the_bound_to_the_caller(self):
        module = loss_fixtures()
        calls = []

        def quint(argv, timeout, cwd, **_):
            calls.append((timeout, argv[argv.index("--step") + 1] if "--step" in argv else None,
                          (Path(cwd) / "case.qnt").read_text()))
            out = Path(argv[argv.index("--out-itf") + 1])
            states = [{"n": out.parent.name}] * (int(argv[argv.index("--max-steps") + 1]) + 1)
            out.write_text(json.dumps({"#meta": {"format": "ITF"}, "states": states}))

        for timeout in (None, module.TIMEOUT):
            calls.clear()
            with self.subTest(timeout=timeout), tempfile.TemporaryDirectory() as temporary, \
                    mock.patch.object(module.subprocess, "run", quint), \
                    mock.patch.object(module, "left_out", lambda states: None):
                module.generate(sys.executable, Path(temporary) / "traces", 4, timeout)
                self.assertEqual({bound for bound, _, _ in calls}, {timeout})
                self.assertEqual({step for _, step, _ in calls}, {"recipe", "rooted"})
                self.assertTrue(all("action rooted" in text for _, step, text in calls if step == "rooted"))


if __name__ == "__main__":
    unittest.main()
