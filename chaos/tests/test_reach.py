#!/usr/bin/env python3
"""Judge the recorded reach run and the cases built from it, and check the scope sentence and the required-event table.

    python3 chaos/tests/test_reach.py

The run under chaos/tests/runs/fixture-reach-live is a real held run of the scenario ks-reach-required-events,
recorded as chaos/tests/README.md states. Cases holds the seven verdict cases: the run as recorded,
and copies of it in a temporary directory with the records edited the way one verdict of the reach
judge describes: an unreached required event, a profile under no_pass, a profile under the
covered-pass floor, a recorded sweep exit 4 of a changed archive, an alarm, and a control whose
table requires an event cluster-pressure never reaches. Falsifiers edits the same run at the
judges' other branches and boundaries. Each edit keeps the per-profile counts the judges read
(runs, pass, caught, covered, reached) and the profile's member of the status's derived `reach`
map as a sweep could print them, apart from the one the case is about; the root totals and the
histories aggregates keep their recorded values. Each case checks the exit code and the outcome and detail of the receipt
each judge writes. Scope fails when the judges' scope sentence differs from the line of
chaos/project.yaml, when a committed reach receipt lacks it, or when the judges' copy of the
required-event table, its floor or the coverage counters differ from the Rust sources. The test
starts no sweep and needs only python3; chaos/tests/test_judges.py runs it.
"""
from __future__ import annotations

import ast
import importlib.util
import inspect
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
CHAOS = TESTS.parent
ROOT = CHAOS.parent
RECORDED = TESTS / "runs" / "fixture-reach-live"
REACH, VALIDITY = "chaos/judges/reach/reach.py", "chaos/judges/reach/validity.py"
SCENARIO, INVARIANT = "ks-reach-required-events", "ks-required-events-reached"
# Each run id names its receipt directory under chaos/receipts/.
WITNESS, PLANTED = "reach-live-1125b", "reach-control-1125b"
SUPERVISOR = ROOT / "crates" / "campaign-supervisor" / "src"
TABLE, SUMMARY = SUPERVISOR / "campaign" / "seeds" / "required.rs", SUPERVISOR / "protocol" / "summary.rs"
LABEL = "requires-invalidated-of-cluster-pressure"
HELD, BROKEN, INVALID, INCOMPLETE = 0, 1, 2, 3
OUTCOME = {HELD: "held", BROKEN: "broken", INVALID: "invalid", INCOMPLETE: "incomplete"}


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


sys.dont_write_bytecode = True
# shared.py imports the core judges' common.py as "common".
common = load_module("common", CHAOS / "judges" / "core" / "common.py")
shared = load_module("reach_shared", CHAOS / "judges" / "reach" / "shared.py")
validator = load_module("chaos_validator", CHAOS / "tools" / "validate_contract.py")
# The harness keeps a judge's receipt only if its receipt_accepted returns True for the receipt bytes,
# the expected binding and the judge's exit code.
harness = load_module("chaos_harness", CHAOS / "harness" / "run_scenario.py")
LEDGER = json.loads((CHAOS / "ledger.json").read_text(encoding="utf-8"))
ROW = next(row for row in LEDGER["invariants"] if row["id"] == INVARIANT)
PROPERTY = ROW["property"]["text"]
# What a control's broken detail reads: the pair that the row's control.defect label plants.
CONTROL = "unreached cluster-pressure: invalidated"
NONE_REACHED = "excused pairs reached: none"


def recorded_run() -> Path:
    """The one recorded run's directory."""
    assert RECORDED.is_dir(), f"{RECORDED.relative_to(ROOT).as_posix()} holds no recorded run"
    return RECORDED


def edit_json(path: Path, change) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    change(value)
    path.write_text(json.dumps(value, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def sweep_exit(code: int):
    return lambda run: run.update(sweep_exit=code)


def derive(status: dict, profile: str) -> None:
    """Set the profile's member of the status's `reach` map from its counts, as the supervisor derives it:
    its covered passes, and under `zero` each counter no covered pass reached while the profile has one."""
    entry, reach = status["profiles"][profile], status.get("reach", {}).get(profile)
    if isinstance(reach, dict):
        reach["covered"] = entry["covered"]
        reach.pop("zero", None)
        if entry["covered"]:
            reach["zero"] = [event for event in shared.COVERAGE if entry["reached"].get(event, {"runs": 0})["runs"] == 0]


def zero(*pairs: tuple[str, str]):
    """A status edit that leaves each (profile, event) with no reaching pass, as a sweep prints one."""
    def change(status: dict) -> None:
        for profile, event in pairs:
            status["profiles"][profile]["reached"][event] = {"runs": 0, "total": 0}
            derive(status, profile)
    return change


def cover(status: dict, profile: str, covered: int) -> None:
    """Give `profile` `covered` covered passes, each counter's reaching passes cut to that number."""
    entry = status["profiles"][profile]
    entry["covered"] = covered
    for event in entry["reached"].values():
        event["runs"] = min(event["runs"], covered)
        event["total"] = min(event["total"], event["runs"] * common.U32_MAX)
    derive(status, profile)


def unpassed(status: dict, profile: str) -> None:
    """Make `profile` one with runs and none counted under pass or caught, as no_pass lists it."""
    status["profiles"][profile].update({"pass": 0, "caught": 0, "covered": 0, "reached": {}, "caught_rules": {}})
    derive(status, profile)


def edits(*changes):
    """One edit that applies each of `changes` in turn; None is no change."""
    def change(value: dict) -> None:
        for each in filter(None, changes):
            each(value)
    return change


def listed_unreached(profile: str, *events: str):
    """A status edit that zeroes each event of `profile` and lists them under unreached, as the gate prints them."""
    return edits(zero(*((profile, event) for event in events)),
                 lambda status: status.update(unreached={profile: list(events)}))


def listed_no_pass(profile: str):
    """A status edit that leaves `profile` with no pass and no catch and lists it under no_pass."""
    return edits(lambda status: unpassed(status, profile), lambda status: status.update(no_pass=[profile]))


TABLE_ROW = r'\(\s*"([^"]+)",\s*[0-9_]+,\s*&\[(.*?)\],\s*&\[(.*?)\],\s*\),'


def table_rows(source: str | None = None) -> dict[str, tuple[list[str], list[str]]]:
    """Each row of the committed required-event table, `source` in place of required.rs when given: its required
    events and its excused events. The REQUIRED initializer must hold rows alone, each profile once."""
    source = TABLE.read_text(encoding="utf-8") if source is None else source
    declared = re.search(r"(?ms)^pub\(super\) const REQUIRED: &\[MeasuredRow\] = &\[\n(.*?)^\];", source)
    assert declared is not None, "required.rs declares no REQUIRED table the test can read"
    rows = re.findall(TABLE_ROW, declared[1], re.DOTALL)
    left = re.sub(TABLE_ROW, "", declared[1], flags=re.DOTALL).strip()
    assert rows and not left, f"the required-event table holds text the test cannot read as a row: {left[:80]!r}"
    profiles = [name for name, _, _ in rows]
    assert len(profiles) == len(set(profiles)), f"the required-event table repeats a profile: {profiles}"
    table = {}
    for name, required, excused in rows:
        events = ast.literal_eval("[" + required + "]")
        reasons = ast.literal_eval("[" + excused + "]") if excused.strip() else []
        table[name] = ([event for event, _ in events], [event for event, _ in reasons])
    return table


def copy_tree(top: Path, ledger: dict | None = None) -> Path:
    """A repository tree at `top` with copies of the judges and of the ledger, or of `ledger` in its place."""
    (top / "chaos").mkdir(parents=True)
    shutil.copytree(CHAOS / "judges", top / "chaos" / "judges")
    (top / "chaos" / "receipts").mkdir()
    (top / "chaos" / "ledger.json").write_text(json.dumps(ledger or LEDGER, indent=2) + "\n", encoding="utf-8")
    return top


def binding(tree: Path, script: str, row_id: str, evidence: Path) -> dict:
    """What the harness requires of the receipt of `row_id` for the run at `evidence`, as its judge_all builds it:
    the run's identity, the digest of each evidence file, of each file of the judge's directory and the core's and
    of the judged rows of the tree's ledger, and, for an invariant, its control.expect as the text a broken detail holds."""
    run = json.loads((evidence / "run.json").read_text(encoding="utf-8"))
    ledger = json.loads((tree / "chaos" / "ledger.json").read_text(encoding="utf-8"))
    rows = {row["id"]: row for part in ("invariants", "scenarios") for row in ledger[part]}
    scenario = rows[run["scenario"]]
    control = rows[row_id].get("control") if row_id != scenario["id"] else None
    folders = sorted({(tree / script).parent, tree / "chaos" / "judges" / "core"})
    return {**{key: run.get(key) for key in ("scenario", "mode", "defect", "system_build", "harness", "run_id", "started")},
            "evidence": harness.evidence_digests(evidence), "row": row_id, "command": [script, row_id],
            "rows": {row_id: harness.row_digest(rows[row_id]), scenario["id"]: harness.row_digest(scenario)},
            "judge": {path.relative_to(tree).as_posix(): harness.sha256(path) for folder in folders
                      for path in sorted(folder.iterdir())},
            "rule": control.get("expect") if isinstance(control, dict) else None}


def ledger_with(floor: object = None, delivery: object = None, reaching: object = None,
                profiles: str | None = None, defect: str | None = None, rule: object = None) -> tuple[dict, str]:
    """A copy of the ledger with the reach rows' numbers, the control's defect label, the property text or the
    scenario's profile set changed, and the scenario's digest."""
    ledger = json.loads(json.dumps(LEDGER))
    row = next(row for row in ledger["invariants"] if row["id"] == INVARIANT)
    scenario = next(row for row in ledger["scenarios"] if row["id"] == SCENARIO)
    if floor is not None:
        row["threshold"]["min_covered_passes"] = floor
    if reaching is not None:
        row["threshold"]["min_reaching_passes"] = reaching
    if delivery is not None:
        scenario["load_delivery"]["min_covered_per_profile"] = delivery
    if defect is not None:
        row["control"]["defect"] = defect
    if rule is not None:
        row["property"]["text"] = rule
    if profiles is not None:
        scenario["load"]["reference"] = profiles + scenario["load"]["reference"][len("cluster-swarm,cluster-broad,cluster-pressure"):]
    return ledger, common.row_digest(scenario)


class Judged(unittest.TestCase):
    """A scratch directory of cases, each a copy of the recorded run, and the judges run on them."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.scratch = Path(tempfile.mkdtemp(prefix="chaos-reach-"))
        cls.judged = copy_tree(cls.scratch / "judged")

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.scratch, ignore_errors=True)

    def case(self, run=None, status=None) -> Path:
        """A copy of the recorded run with run.json and sweep-status.json edited by `run` and `status`."""
        source = recorded_run()
        target = Path(tempfile.mkdtemp(dir=self.scratch)) / source.name
        shutil.copytree(source, target)
        if run:
            edit_json(target / "run.json", run)
        if status:
            edit_json(target / "sweep-status.json", status)
        return target

    def tree(self, ledger: dict | None = None) -> Path:
        return copy_tree(Path(tempfile.mkdtemp(dir=self.scratch)), ledger)

    def receipt(self, script: str, row: str, evidence: Path, tree: Path | None = None) -> tuple[int, dict | None, str]:
        """The judge's exit, the key of the receipt it wrote (None when it wrote none) and its output.

        The judge runs from `tree`, by default a copy of the repository's judges and ledger, and
        writes its receipt under that tree's chaos/receipts/, the one place the core accepts. For
        a run that has a run record, receipt_accepted of chaos/harness/run_scenario.py must return
        True for the receipt and the binding the harness builds for that judgement.
        """
        tree = tree or self.judged
        path = Path(tempfile.mkdtemp(dir=tree / "chaos" / "receipts")) / f"{row}.json"
        done = subprocess.run([sys.executable, "-I", "-B", str(tree / script), row, "--evidence", str(evidence),
                               "--receipt", str(path)], capture_output=True, text=True, check=False, timeout=120)
        data = path.read_bytes() if path.is_file() else None
        path.unlink(missing_ok=True)
        if data is None:
            return done.returncode, None, done.stdout + done.stderr
        if (evidence / "run.json").is_file():
            self.assertTrue(harness.receipt_accepted(data, binding(tree, script, row, evidence), done.returncode),
                            f"the harness would drop this receipt and report that the judge decided nothing: {done.stdout}")
        return done.returncode, json.loads(data)["key"], done.stdout + done.stderr

    def verdict(self, script: str, row: str, evidence: Path, code: int, *texts: str, tree: Path | None = None) -> dict:
        """Assert the judge's exit, its receipt's outcome, and that the detail holds `texts` and ends with the scope sentence."""
        exit_code, key, output = self.receipt(script, row, evidence, tree)
        self.assertEqual(exit_code, code, output)
        if key is None:
            self.fail(f"the judge wrote no receipt: {output}")
        self.assertEqual(output, f"{row}: {key['outcome']}: {key['detail']}\n".encode("ascii", "backslashreplace").decode())
        self.assertEqual(key["outcome"], OUTCOME[code], key["detail"])
        for text in texts:
            self.assertIn(text, key["detail"])
        self.assertTrue(key["detail"].endswith(f"; {shared.SCOPE}"), key["detail"])
        return key

    def verdicts(self, evidence: Path, reach: int, validity: int, *texts: str, valid: tuple[str, ...] = (),
                 tree: Path | None = None) -> dict:
        """Both judges' verdicts; `texts` are expected in the reach receipt's detail and `valid` in the validity one's."""
        self.verdict(VALIDITY, SCENARIO, evidence, validity, *valid, tree=tree)
        return self.verdict(REACH, INVARIANT, evidence, reach, *texts, tree=tree)


def changed_archive(run: dict) -> None:
    """The run record the harness writes for a sweep that found its archive changed: exit 4, sweep-status refused."""
    run.update(sweep_exit=4, status_exit=2, status_refusal="campaign sweep-status: the root is marked for a changed archive",
               archive_build_after="0" * 64, restored={"left_a_process": 0, "archive_verified": False})


def control(run: dict) -> None:
    run.update(sweep_exit=1, mode="control", defect=LABEL)


def reach_event(profile: str, event: str, runs: int, total: int):
    """A status edit that gives `profile` `runs` covered passes that reached `event` `total` times."""
    def change(status: dict) -> None:
        status["profiles"][profile]["reached"][event] = {"runs": runs, "total": total}
        derive(status, profile)
    return change


def also_swept(evidence: Path, profile: str, kind: str, cluster: bool) -> None:
    """Add `profile`, an entry of the recorded status, to the profiles the run record says it swept: the sweep
    command, the worker's listing with class `kind`, the profile's run range and its line of history.jsonl."""
    status = json.loads((evidence / "sweep-status.json").read_text(encoding="utf-8"))
    span = {"first": 0, "next": status["profiles"][profile]["next"]}

    def run(record: dict) -> None:
        record["profiles"] = [*record["profiles"], profile]
        sweep = record["commands"]["sweep"]
        sweep[sweep.index("--profiles") + 1] = ",".join(record["profiles"])
        record["listing"][profile] = {"class": kind, "cluster": cluster, "fails": None}
        record["runs"][profile] = span
    edit_json(evidence / "run.json", run)
    line = json.loads((evidence / "history.jsonl").read_text(encoding="utf-8").splitlines()[0])
    line.update(profile=profile, runs=span)
    with (evidence / "history.jsonl").open("a", encoding="utf-8") as history:
        history.write(json.dumps(line) + "\n")


def suspect_lines(evidence: Path, *lines: tuple[str, str, str, int]) -> None:
    """Write suspects.jsonl with one line per (profile, key, class, run), under the run's campaign, build and counts."""
    run = json.loads((evidence / "run.json").read_text(encoding="utf-8"))
    (evidence / "suspects.jsonl").write_text("".join(json.dumps(
        {"key": key, "profile": profile, "run": number, "seed": number, "class": cls, "campaign": run["campaign"],
         "build": run["system_build"], "counts": run["counts"]}) + "\n" for profile, key, cls, number in lines),
        encoding="utf-8")


def suspect_keys(profile: str, **keys: int):
    """A status edit that counts `keys` under the profile's suspect_keys and sets the profile's `suspects` to their
    sum, as a sweep counts each suspect once in both; a key's `__` stands for `: `."""
    def change(status: dict) -> None:
        entry = status["profiles"][profile]
        entry["suspect_keys"].update({key.replace("__", ": "): value for key, value in keys.items()})
        entry["suspects"] = sum(entry["suspect_keys"].values())
    return change


VIOLATION = "violation: " + "0" * 88


class Cases(Judged):
    """The seven verdicts of the reach judges, each read from the receipts both judges write."""

    def test_held(self) -> None:
        entries = json.loads((recorded_run() / "sweep-status.json").read_text(encoding="utf-8"))["profiles"]
        swept = tuple(f"{profile} {entries[profile]['runs']} runs, {entries[profile]['replays']} replays"
                      for profile in ("cluster-swarm", "cluster-broad", "cluster-pressure"))
        self.verdicts(self.case(), HELD, HELD, "required events reached", "reached faults", NONE_REACHED,
                      *(f"{profile} {entries[profile]['covered']} covered passes" for profile in shared.ROWS),
                      valid=("valid: campaign sweep exited 0", *swept))

    def test_broken_by_unreached(self) -> None:
        change = listed_unreached("cluster-swarm", "faults", "hits")
        self.verdicts(self.case(sweep_exit(1), change), BROKEN, HELD, "unreached cluster-swarm: faults, hits", PROPERTY,
                      NONE_REACHED, valid=("valid: campaign sweep exited 1", "unreached is the reach invariant's"))

    def test_broken_by_no_pass(self) -> None:
        # The listed profile has no covered pass, so it is under the floor too: the break decides first.
        self.verdicts(self.case(sweep_exit(1), listed_no_pass("cluster-broad")), BROKEN, HELD, "no_pass cluster-broad",
                      PROPERTY, NONE_REACHED, valid=("valid: campaign sweep exited 1", "no_pass is the reach invariant's"))

    def test_incomplete_under_the_floor(self) -> None:
        # A required event at zero on the short profile is no contradiction: the gate is not armed for it.
        change = edits(lambda status: cover(status, "cluster-swarm", 63), zero(("cluster-swarm", "faults")))
        self.verdicts(self.case(status=change), INCOMPLETE, HELD, "covered passes under the row's floor of 64",
                      "cluster-swarm 63", NONE_REACHED)

    def test_incomplete_on_a_recorded_exit_4_of_a_changed_archive(self) -> None:
        evidence = self.case(changed_archive)
        (evidence / "sweep-status.json").unlink()
        self.verdicts(evidence, INCOMPLETE, INCOMPLETE, "campaign sweep exited 4")

    def test_invalid_on_alarm(self) -> None:
        change = edits(listed_unreached("cluster-swarm", "faults"),
                       lambda status: status.update(alarm="1 control runs were missed"))
        self.verdicts(self.case(sweep_exit(1), change), INVALID, INVALID, "alarm")

    def test_the_control(self) -> None:
        evidence = self.case(control, lambda status: status.update(unreached={"cluster-pressure": ["invalidated"]}))
        key = self.verdicts(evidence, BROKEN, HELD, CONTROL, PROPERTY, NONE_REACHED)
        self.assertEqual((key["mode"], key["defect"], key["outcome"]), ("control", LABEL, "broken"))


class Falsifiers(Judged):
    """The judges' other branches and boundaries, each on an edited copy of the recorded run."""

    def test_a_run_that_shows_no_restoration_is_invalid(self) -> None:
        """The row's restoration names both facts of `restored`; each judge refuses a run that lacks either.

        The exit 1 case stands beside the reach flag `unreached`, where the validity judge reads the
        recorded exit as the sweep's verdict, so the refusal there comes from `restored` alone.
        """
        def unreached(status: dict) -> None:
            status.update(unreached={"cluster-pressure": ["invalidated"]})

        self.verdicts(self.case(control, unreached), BROKEN, HELD, CONTROL)
        facts = {"a process left": {"left_a_process": 1, "archive_verified": True},
                 "the archive unverified": {"left_a_process": 0, "archive_verified": False}}
        for name, restored in facts.items():
            def live(run: dict, restored=restored) -> None:
                run.update(restored=dict(restored, cause=None))

            def planted(run: dict, restored=restored) -> None:
                control(run)
                run.update(restored=dict(restored, cause=None))
            for exit_code, run, status in ((0, live, None), (1, planted, unreached)):
                with self.subTest(fact=name, sweep_exit=exit_code):
                    self.verdicts(self.case(run, status), INVALID, INVALID, "restoration not shown",
                                  valid=("restoration not shown",))

    def test_the_floor_is_met_at_its_value(self) -> None:
        self.verdicts(self.case(status=lambda status: cover(status, "cluster-swarm", 64)), HELD, HELD,
                      "cluster-swarm 64 covered passes")

    def test_the_floor_comes_from_the_row(self) -> None:
        ledger, digest = ledger_with(floor=10 ** 9, delivery=10 ** 9)
        evidence = self.case(lambda run: run.update(scenario_row=digest))
        self.verdicts(evidence, INCOMPLETE, HELD, f"floor of {10 ** 9}", tree=self.tree(ledger))

    def test_rows_that_state_another_floor_or_reach_are_invalid(self) -> None:
        numbered: tuple[tuple[dict[str, object], str], ...] = (
            ({"floor": 65}, "the row's covered-pass floor is 65"),
            ({"delivery": 65}, "min_covered_per_profile is 65"),
            ({"delivery": 64.0}, "min_covered_per_profile is 64.0: a minimum is an integer"),
            ({"reaching": 2}, "min_reaching_passes is 2"),
            ({"reaching": True}, "min_reaching_passes is True: a minimum is an integer"),
            ({"reaching": 1.0}, "min_reaching_passes is 1.0: a minimum is an integer"))
        for numbers, text in numbered:
            with self.subTest(numbers=numbers):
                ledger, digest = ledger_with(floor=numbers.get("floor"), delivery=numbers.get("delivery"),
                                             reaching=numbers.get("reaching"))
                evidence = self.case(lambda run, digest=digest: run.update(scenario_row=digest))
                self.verdict(REACH, INVARIANT, evidence, INVALID, text, tree=self.tree(ledger))

    def test_a_row_without_its_property_text_is_invalid(self) -> None:
        for rule in ("", ["text"]):
            with self.subTest(rule=rule):
                ledger, _ = ledger_with(rule=rule)
                self.verdict(REACH, INVARIANT, self.case(), INVALID, "the row holds no property text", tree=self.tree(ledger))

    def test_a_row_whose_control_plants_no_excused_pair_is_invalid(self) -> None:
        def planted(status: dict) -> None:
            status.update(unreached={"cluster-pressure": ["invalidated"]})
        unnamed, unexcused = "control.defect names no pair as requires-<event>-of-<profile>", "excuses no such pair"
        for label, text in (("another-label", unnamed), (f"x{LABEL}", unnamed), ("requires-invalidated-cluster-pressure", unnamed),
                            ("requires-faults-of-cluster-swarm", f"plants cluster-swarm: faults, and the committed table {unexcused}"),
                            ("requires-invalidated-of-cluster-broad", unexcused), (f"{LABEL}-x", unexcused),
                            ("requires-refused-of-cluster-pressure", unexcused)):
            with self.subTest(label=label):
                ledger, digest = ledger_with(defect=label)
                record = edits(control, lambda run, digest=digest, label=label: run.update(scenario_row=digest, defect=label))
                self.verdict(REACH, INVARIANT, self.case(record, planted), INVALID, text, tree=self.tree(ledger))

    def test_the_planted_pair_is_the_one_the_rows_label_names(self) -> None:
        label = "requires-cancelled-of-cluster-pressure"
        ledger, digest = ledger_with(defect=label)
        record = edits(control, lambda run: run.update(scenario_row=digest, defect=label))
        for events, reach, text in ((["cancelled"], BROKEN, "unreached cluster-pressure: cancelled"),
                                    (["invalidated"], INVALID, "the committed table excuses it")):
            with self.subTest(events=events):
                evidence = self.case(record, lambda status, events=events: status.update(unreached={"cluster-pressure": events}))
                self.verdicts(evidence, reach, HELD, text, tree=self.tree(ledger))

    def test_a_scenario_profile_without_a_table_row_is_invalid(self) -> None:
        ledger, digest = ledger_with(profiles="cluster-swarm,cluster-broad,cluster-pressure,h1-get")
        evidence = self.case(lambda run: run.update(scenario_row=digest))
        also_swept(evidence, "h1-get", "history", False)
        self.verdicts(evidence, INVALID, HELD, "has no row for the scenario's profile h1-get", tree=self.tree(ledger))

    def test_a_recorded_exit_3_is_incomplete_whatever_the_status_holds(self) -> None:
        evidence = self.case(sweep_exit(3), lambda status: status.update(campaign="another-sweep", unreached=[]))
        self.verdicts(evidence, INCOMPLETE, INCOMPLETE, "campaign sweep exited 3")

    def test_a_control_beside_a_recorded_exit_3_or_4_is_incomplete_whatever_its_label(self) -> None:
        for label in (LABEL, "another-label"):
            for code in (3, 4):
                with self.subTest(label=label, code=code):
                    exit_record = changed_archive if code == 4 else sweep_exit(3)
                    evidence = self.case(edits(control, lambda run, label=label: run.update(defect=label), exit_record))
                    if code == 4:
                        (evidence / "sweep-status.json").unlink()
                    self.verdicts(evidence, INCOMPLETE, INCOMPLETE, f"campaign sweep exited {code}",
                                  valid=(f"campaign sweep exited {code}",))

    def test_a_stopped_or_incomplete_run_is_incomplete_and_its_receipt_states_the_scope(self) -> None:
        for change, text in (({"deadline_fired": True}, "the run was stopped"),
                             ({"signal": 15}, "the run was stopped"),
                             ({"sweep_exit": -15}, "campaign sweep was ended by signal 15"),
                             ({"complete": False}, "does not mark the run complete")):
            with self.subTest(change=change):
                self.verdicts(self.case(lambda run, change=change: run.update(change)), INCOMPLETE, INCOMPLETE, text)

    def test_a_run_without_its_record_is_incomplete_and_its_receipt_states_the_scope(self) -> None:
        evidence = self.case()
        (evidence / "run.json").unlink()
        for path in (evidence, evidence.parent / "never-started"):
            with self.subTest(path=path.name):
                self.verdicts(path, INCOMPLETE, INCOMPLETE, "the run wrote no run.json")

    def test_an_exit_1_without_a_verdict_key_is_invalid(self) -> None:
        self.verdicts(self.case(sweep_exit(1)), INVALID, INVALID, "carry none of")

    def test_an_alarm_of_any_value_or_a_missed_run_without_one_is_invalid(self) -> None:
        def missed(profile: str):
            return lambda status: status["profiles"][profile].update(missed=1)

        def group(name: str, value: object):
            return lambda status: status[name].update(missed=value)
        cases = ((None, lambda status: status.update(alarm=""), "carry alarm \"\""),
                 (None, lambda status: status.update(alarm=None), "carry alarm null"),
                 (sweep_exit(1), edits(listed_unreached("cluster-swarm", "faults"), lambda status: status.update(alarm="")),
                  "carry alarm"),
                 (None, missed("cluster-swarm-leak"), "missed runs without alarm: \"cluster-swarm-leak\" 1"),
                 (None, group("controls", 2), "controls 2"),
                 (None, group("histories", 1), "histories 1"),
                 (None, lambda status: status.pop("histories"), "the status's histories records missed as None"),
                 (None, lambda status: status.pop("controls"), "the status's controls records missed as None"),
                 (None, lambda status: status["profiles"].update({"h2-get": [1]}), "the status's entry for \"h2-get\" is no object"),
                 (None, suspect_keys("cluster-swarm-leak", **{"control passed__0123": 1}), "\"control passed: 0123\""),
                 (None, suspect_keys("h1-get", **{"control met no check__0123": 1}), "\"control met no check: 0123\""))
        for run, change, text in cases:
            with self.subTest(text=text):
                self.verdicts(self.case(run, change), INVALID, INVALID, text)

    def test_a_missed_class_line_on_any_profile_is_invalid(self) -> None:
        for profile, cls in (("cluster-swarm-leak", "control passed"), ("h1-get", "control met no check")):
            with self.subTest(profile=profile):
                evidence = self.case(status=suspect_keys(profile, other=1))
                suspect_lines(evidence, (profile, "other", cls, 5))
                self.verdicts(evidence, INVALID, INVALID, f"missed runs without alarm: \"{profile}\" \"{cls}\"")

    def test_a_suspect_of_another_class_is_invalid_on_each_profile(self) -> None:
        for profile in sorted(shared.ROWS):
            with self.subTest(profile=profile):
                self.verdicts(self.case(status=suspect_keys(profile, **{"panic__src/lib.rs:1:1": 1})), INVALID, INVALID,
                              f"{profile} has a suspect of another class than violation: \"panic: src/lib.rs:1:1\"")

    def test_a_replay_that_differs_on_any_profile_is_invalid(self) -> None:
        self.verdicts(self.case(status=suspect_keys("cluster-swarm-leak", **{"replay differs__0123": 1})), INVALID,
                      INVALID, "replayed with another ending")
        for profile, cls, text in (("h1-get", "replay differs", "replayed with another ending"),
                                   ("cluster-broad", "panic", "cluster-broad has a suspect of another class than violation")):
            with self.subTest(profile=profile, cls=cls):
                evidence = self.case(status=suspect_keys(profile, other=1))
                suspect_lines(evidence, (profile, "other", cls, 5))
                self.verdicts(evidence, INVALID, INVALID, text)

    def test_records_the_core_refuses_are_invalid_beside_a_reach_key(self) -> None:
        def above(status: dict) -> None:
            status["profiles"]["h1-get"]["covered"] = status["profiles"]["h1-get"]["pass"] + 1
        for base in (listed_unreached("cluster-swarm", "faults"), listed_no_pass("cluster-broad")):
            for change, text in ((suspect_keys("cluster-swarm-leak", **{"replay differs__0123": 1}), "replayed with another ending"),
                                 (above, "h1-get records counts no sweep writes")):
                with self.subTest(text=text):
                    self.verdicts(self.case(sweep_exit(1), edits(base, change)), INVALID, INVALID, text)

    def test_a_control_that_names_a_swept_profile_stands_on_the_cores_terms(self) -> None:
        def named(run: dict) -> None:
            run.update(mode="control", defect="cluster-swarm-leak")

        def replayed(status: dict) -> None:
            status["profiles"]["cluster-swarm-leak"]["replays"] = 1
        unreplayed, unnamed = "the control cluster-swarm-leak has", "the control run's defect \"cluster-swarm-leak\""
        broken = edits(replayed, listed_unreached("cluster-swarm", "faults"))
        for run, change, validity, text, valid in (
                (None, None, INVALID, unreplayed, (unreplayed, "0 replays")),
                (None, replayed, HELD, unnamed, ("valid: campaign sweep exited 0",)),
                (sweep_exit(1), broken, HELD, unnamed, ("valid: campaign sweep exited 1", "unreached is the reach invariant's"))):
            with self.subTest(validity=validity, valid=valid[-1]):
                evidence = self.case(edits(named, run), change)
                also_swept(evidence, "cluster-swarm-leak", "control", True)
                self.verdicts(evidence, INVALID, validity, text, valid=valid)

    def test_listed_suspects_the_scenario_allows_change_no_verdict(self) -> None:
        change = edits(suspect_keys("cluster-broad", **{VIOLATION.replace(": ", "__"): 1}),
                       suspect_keys("h1-get", **{"panic__src/lib.rs:1:1": 1}))
        evidence = self.case(status=change)
        suspect_lines(evidence, ("cluster-broad", VIOLATION, "violation", 5), ("h1-get", "panic: src/lib.rs:1:1", "panic", 7))
        self.verdicts(evidence, HELD, HELD, "required events reached")

    def test_an_other_bucket_larger_than_its_lines_is_invalid(self) -> None:
        lines = [("h1-get", "other", "panic", number) for number in range(8)]
        for counted, reach, validity in ((8, HELD, HELD), (9, INVALID, INVALID)):
            with self.subTest(counted=counted):
                evidence = self.case(status=suspect_keys("h1-get", other=counted))
                suspect_lines(evidence, *lines)
                self.verdicts(evidence, reach, validity, *(() if reach == HELD else ("counts 9 suspects under other",)))
        evidence = self.case(status=suspect_keys("cluster-swarm-leak", other=1))
        self.verdicts(evidence, INVALID, INVALID, "counts 1 suspects under other and lists 0")

    def test_a_suspect_listed_under_other_and_not_counted_there_is_invalid(self) -> None:
        """The supervisor counts a suspect under the key its line names, so a line under `other` has a count there."""
        for profile, cls in (("cluster-swarm", "panic"), ("h1-get", "violation")):
            with self.subTest(profile=profile, cls=cls):
                evidence = self.case()
                suspect_lines(evidence, (profile, "other", cls, 5))
                self.verdicts(evidence, INVALID, INVALID,
                              f"suspects.jsonl lists 1 suspects of {profile} under 'other', and the status counts 0")
        evidence = self.case(status=suspect_keys("h1-get", other=1))
        suspect_lines(evidence, ("h1-get", "other", "panic", 5), ("h1-get", "other", "panic", 6))
        self.verdicts(evidence, INVALID, INVALID,
                      "suspects.jsonl lists 2 suspects of h1-get under 'other', and the status counts 1")

    def test_an_other_bucket_of_a_scenario_profile_stands_by_the_class_of_each_of_its_lines(self) -> None:
        """`other` names the bucket past the profile's key bound and no class; each line under it states its own."""
        for classes, code, text in ((("violation", "violation"), HELD, "required events reached"),
                                    (("violation", "panic"), INVALID,
                                     "cluster-broad has a suspect of another class than violation: \"panic\"")):
            with self.subTest(classes=classes):
                evidence = self.case(status=suspect_keys("cluster-broad", other=len(classes)))
                suspect_lines(evidence, *(("cluster-broad", "other", cls, number) for number, cls in enumerate(classes)))
                self.verdicts(evidence, code, code, text)

    def test_an_unreadable_status_or_a_missing_entry_is_invalid(self) -> None:
        def cut(evidence: Path) -> None:
            text = (evidence / "sweep-status.json").read_text(encoding="utf-8")
            (evidence / "sweep-status.json").write_text(text[: len(text) // 2], encoding="utf-8")

        def empty(evidence: Path) -> None:
            (evidence / "sweep-status.json").write_text("{}\n", encoding="utf-8")

        def absent(evidence: Path) -> None:
            (evidence / "sweep-status.json").unlink()

        def entry(evidence: Path) -> None:
            edit_json(evidence / "sweep-status.json", lambda status: status["profiles"].pop("cluster-broad"))

        def keys(evidence: Path) -> None:
            edit_json(evidence / "sweep-status.json", lambda status: status["profiles"]["cluster-broad"].pop("suspect_keys"))

        def unhistoried(evidence: Path) -> None:
            (evidence / "history.jsonl").unlink()

        def unfound(evidence: Path) -> None:
            (evidence / "findings.json").write_text("[", encoding="utf-8")

        def unlisted(evidence: Path) -> None:
            (evidence / "suspects.jsonl").write_text("{", encoding="utf-8")
        for change, text in ((cut, "sweep-status.json is unreadable"), (empty, "names no campaign and no profiles"),
                             (absent, "the run has no sweep-status.json"), (entry, "cluster-broad"),
                             (keys, "the status's entry for cluster-broad has no control marker"),
                             (unhistoried, "history.jsonl"), (unfound, "findings.json"), (unlisted, "suspects.jsonl")):
            with self.subTest(text=text):
                evidence = self.case()
                change(evidence)
                self.verdicts(evidence, INVALID, INVALID, text)

    def test_a_reached_map_of_another_form_is_invalid(self) -> None:
        def entry(value: object):
            return lambda status: status["profiles"]["cluster-swarm"].update(reached=value)
        for change, validity, text in ((entry(None), INVALID, "records reached as None"),
                                       (lambda status: status["profiles"]["cluster-swarm"].pop("reached"), HELD,
                                        "records no reached map of coverage counters: null"),
                                       (reach_event("cluster-swarm", "hits", 1, 1), HELD, "required events reached"),
                                       (lambda status: status["profiles"]["cluster-swarm"]["reached"].update(hits=[1, 1]),
                                        INVALID, "records runs as None"),
                                       (lambda status: status["profiles"]["cluster-swarm"]["reached"]["hits"].update(runs="1"),
                                        INVALID, "records runs as '1'")):
            with self.subTest(text=text):
                reach = HELD if text == "required events reached" else INVALID
                self.verdicts(self.case(status=change), reach, validity, text)

    def test_a_profile_without_a_replay_is_invalid_on_each_profile(self) -> None:
        for profile in sorted(shared.ROWS):
            with self.subTest(profile=profile):
                def unreplayed(status: dict, profile=profile) -> None:
                    status["profiles"][profile]["replays"] = 0
                self.verdicts(self.case(status=unreplayed), INVALID, INVALID, f"{profile} has", "0 replays")

    def test_counts_no_sweep_prints_are_invalid_on_any_profile(self) -> None:
        def entry(profile: str, key: str, above: str):
            def change(status: dict) -> None:
                status["profiles"][profile][key] = status["profiles"][profile][above] + 1
            return change
        cases = ((entry("cluster-swarm", "covered", "pass"), "records counts no sweep writes"),
                 (entry("cluster-swarm", "pass", "runs"), "records counts no sweep writes"),
                 (entry("h1-get", "covered", "pass"), "h1-get records counts no sweep writes"),
                 (entry("cluster-swarm-leak", "pass", "runs"), "cluster-swarm-leak records counts no sweep writes"),
                 (reach_event("cluster-swarm", "hits", 10 ** 9, 10 ** 9), "more than its covered passes"),
                 (reach_event("cluster-swarm", "hits", 0, 1), "which no sweep writes"),
                 (reach_event("cluster-swarm", "hits", 5, 4), "which no sweep writes"),
                 (reach_event("cluster-swarm", "hits", 1, 2 ** 32), "which no sweep writes"),
                 (reach_event("h1-get", "hits", 1, 1), "h1-get records 1 covered passes that reached hits"))
        for change, text in cases:
            with self.subTest(text=text):
                self.verdicts(self.case(status=change), INVALID, INVALID, text)
        self.verdicts(self.case(status=reach_event("cluster-swarm", "hits", 1, common.U32_MAX)), HELD, HELD)

    def test_counts_above_64_bits_are_invalid(self) -> None:
        top = common.U64_MAX
        self.verdicts(self.case(status=lambda status: status["profiles"]["cluster-swarm"].update(replays=top)), HELD, HELD)
        for change, text in ((lambda status: status["profiles"]["cluster-swarm"].update(replays=top + 1),
                              f"the status.profiles.cluster-swarm.replays records {top + 1}, above 2^64 - 1"),
                             (reach_event("cluster-swarm", "hits", 2 ** 32 + 2, top + 1),
                              "the status.profiles.cluster-swarm.reached.hits.total records"),
                             (lambda status: status["histories"].update(missed=top + 1), "the status.histories.missed"),
                             (lambda status: status["profiles"]["cluster-swarm"].update(windows_unplanned=[0, top + 1]),
                              f"the status.profiles.cluster-swarm.windows_unplanned records {top + 1}")):
            with self.subTest(text=text[:40]):
                self.verdicts(self.case(status=change), INVALID, INVALID, text)

    def test_a_reach_key_beside_exit_0_is_invalid(self) -> None:
        self.verdicts(self.case(status=listed_no_pass("cluster-swarm")), INVALID, INVALID, "exit disagrees with the totals")

    def test_a_no_pass_entry_its_counts_contradict_is_invalid(self) -> None:
        status = json.loads((recorded_run() / "sweep-status.json").read_text(encoding="utf-8"))
        caught = status["profiles"]["h1-put-wrong"]["caught"]
        self.assertGreater(caught, 0)
        for name, text in (("cluster-broad", "passes and 0 caught runs"), ("h1-put-wrong", f"0 passes and {caught} caught"),
                           ("cluster-swarm-leak", "outside the controls"), ("absent-profile", "no profile of the root"),
                           ("h2-get", "\"h2-get\" under no_pass, and it counts 0 runs")):
            with self.subTest(name=name):
                evidence = self.case(sweep_exit(1), lambda status, name=name: status.update(no_pass=[name]))
                self.verdicts(evidence, INVALID, INVALID, text)
                second = edits(listed_no_pass("cluster-swarm"),
                               lambda status, name=name: status.update(no_pass=["cluster-swarm", name]))
                self.verdicts(self.case(sweep_exit(1), second), INVALID, INVALID, text)

    def test_no_pass_lists_each_profile_at_the_supervisors_floor_of_runs_and_no_other(self) -> None:
        """`unpassed` of seeds.rs lists a profile outside the controls with NO_PASS_RUNS runs or more and no pass or catch."""
        floor = shared.NO_PASS_RUNS

        def runs(number: int):
            return lambda status: status["profiles"]["cluster-broad"].update(runs=number)
        self.verdicts(self.case(sweep_exit(1), edits(listed_no_pass("cluster-broad"), runs(floor))), BROKEN, HELD,
                      "no_pass cluster-broad", PROPERTY)
        self.verdicts(self.case(sweep_exit(1), edits(listed_no_pass("cluster-broad"), runs(floor - 1))), INVALID, INVALID,
                      f"\"cluster-broad\" under no_pass, and it counts {floor - 1} runs, 0 passes and 0 caught runs")
        silent = edits(lambda status: unpassed(status, "cluster-broad"), runs(floor))
        self.verdicts(self.case(status=silent), INVALID, INVALID,
                      f"\"cluster-broad\" has {floor} runs and none counted under pass or caught, and the status lists no "
                      "no_pass entry for it")
        under = edits(lambda status: unpassed(status, "cluster-broad"), runs(floor - 1))
        self.verdicts(self.case(status=under), INCOMPLETE, HELD, "cluster-broad 0")

    def test_a_key_naming_only_a_history_is_invalid_and_a_no_pass_one_leaves_the_sweep_valid(self) -> None:
        self.verdicts(self.case(sweep_exit(1), listed_no_pass("h1-put-wrong")), INVALID, HELD,
                      "name no profile of the scenario")
        short = edits(listed_no_pass("h1-put-wrong"), lambda status: cover(status, "cluster-swarm", 63))
        self.verdicts(self.case(sweep_exit(1), short), INVALID, HELD, "name no profile of the scenario")
        evidence = self.case(sweep_exit(1), lambda status: status.update(unreached={"h1-put-wrong": ["hits"]}))
        self.verdicts(evidence, INVALID, INVALID, "the committed required-event table has no row for it")
        for second, text in (({"h1-put-wrong": ["hits"]}, "the committed required-event table has no row for it"),
                             ({"cluster-swarm": ["bogus"]}, "they are no coverage counters")):
            with self.subTest(second=second):
                change = edits(zero(("cluster-broad", "cross")),
                               lambda status, second=second: status.update(unreached={"cluster-broad": ["cross"], **second}))
                self.verdicts(self.case(sweep_exit(1), change), INVALID, INVALID, text)

    def test_a_verdict_key_of_another_shape_is_invalid(self) -> None:
        for keys in ({"unreached": {}}, {"no_pass": []}, {"unreached": {"cluster-swarm": "faults"}},
                     {"no_pass": "cluster-swarm"}, {"no_pass": ["cluster-swarm", "cluster-swarm"]},
                     {"unreached": {"cluster-swarm": ["faults", "faults"]}}):
            with self.subTest(keys=keys):
                self.verdicts(self.case(sweep_exit(1), lambda status, keys=keys: status.update(keys)), INVALID, INVALID, "is no")
        for key, text in (("unreached", "the status's unreached is no map from a profile to distinct events: null"),
                          ("no_pass", "the status's no_pass is no list of distinct profiles: null")):
            with self.subTest(key=key):
                self.verdicts(self.case(sweep_exit(1), lambda status, key=key: status.update({key: None})), INVALID, INVALID, text)

    def test_an_unreached_or_no_pass_entry_on_a_control_or_a_missing_entry_is_invalid(self) -> None:
        def controlled(status: dict) -> None:
            status["profiles"]["cluster-swarm"]["control"] = True
        gone = edits(lambda status: status["profiles"].pop("cluster-pressure"),
                     lambda status: status.update(unreached={"cluster-pressure": ["refused"]}))
        for change, text in ((edits(listed_unreached("cluster-swarm", "faults"), controlled),
                              "\"cluster-swarm\" under unreached, and it is no profile of the root outside the controls"),
                             (edits(listed_no_pass("cluster-swarm"), controlled),
                              "\"cluster-swarm\" under no_pass, and it is no profile of the root outside the controls"),
                             (gone, "\"cluster-pressure\" under unreached, and it is no profile of the root")):
            with self.subTest(text=text[:30]):
                self.verdicts(self.case(sweep_exit(1), change), INVALID, INVALID, text)

    def test_a_scenario_profile_marked_as_a_control_is_invalid(self) -> None:
        def controlled(status: dict) -> None:
            entry = status["profiles"]["cluster-swarm"]
            entry["control"] = True
            status["controls"]["profiles"] += 1
            status["controls"]["runs"] += entry["runs"]
            status["controls"]["caught"] += entry["caught"]
            status["controls"]["other"] += sum(entry["uncredited"].values())
            status["reach"].pop("cluster-swarm")
        self.verdicts(self.case(status=controlled), INVALID, INVALID,
                      "no entry outside the controls for the scenario's profile cluster-swarm")

    def test_an_unreached_entry_outside_the_counters_or_repeated_is_invalid_in_one_bounded_line(self) -> None:
        long = "x\n" * 150
        for events, text in ((["bogus"], "they are no coverage counters"),
                             (["faults", long], "they are no coverage counters"),
                             (["faults"] * 100_000, "no map from a profile to distinct events")):
            with self.subTest(events=events[-1][:8], count=len(events)):
                evidence = self.case(sweep_exit(1), edits(zero(("cluster-swarm", "faults")),
                                                          lambda status, events=events: status.update(
                                                              unreached={"cluster-swarm": events})))
                key = self.verdicts(evidence, INVALID, INVALID, text)
                self.assertNotIn("\n", key["detail"])
                self.assertLess(len(key["detail"]), 400 + len(shared.SCOPE))
                code, _, output = self.receipt(REACH, INVARIANT, evidence)
                self.assertEqual((code, output.count("\n")), (INVALID, 1), output)

    def test_a_status_profile_name_stays_on_one_bounded_line(self) -> None:
        name = "n\n" * 300
        for change in (lambda status: status.update(no_pass=[name]),
                       lambda status: status["profiles"].update({name: dict(status["profiles"]["h2-get"], missed="x")})):
            with self.subTest():
                evidence = self.case(sweep_exit(1), change)
                key = self.verdicts(evidence, INVALID, INVALID)
                self.assertNotIn("\n", key["detail"])
                self.assertLess(len(key["detail"]), 400 + len(shared.SCOPE))

    def test_an_unreached_entry_its_counts_or_the_table_contradict_is_invalid(self) -> None:
        short = edits(lambda status: cover(status, "cluster-swarm", 10), zero(("cluster-swarm", "faults")))
        once = reach_event("cluster-swarm", "cross", 1, 1)
        cases = (({"unreached": {"cluster-swarm": ["faults"]}}, None, "covered passes reached it"),
                 ({"unreached": {"cluster-swarm": ["cross"]}}, once, "1 covered passes reached it"),
                 ({"unreached": {"cluster-pressure": ["invalidated"]}}, None, "the committed table excuses it"),
                 ({"unreached": {"cluster-swarm": ["faults"]}}, short, "under the row's covered-pass floor"))
        for keys, edit, text in cases:
            with self.subTest(keys=keys, text=text):
                change = edits(edit, lambda status, keys=keys: status.update(keys))
                self.verdicts(self.case(sweep_exit(1), change), INVALID, HELD, "under unreached, and", text)

    def test_an_unreached_entry_breaks_at_the_floor_and_is_invalid_under_it(self) -> None:
        for floor, covered, reach, text in ((64, 64, BROKEN, "unreached cluster-swarm: cross"),
                                            (64, 63, INVALID, "under the row's covered-pass floor"),
                                            (100, 100, BROKEN, "unreached cluster-swarm: cross"),
                                            (100, 99, INVALID, "under the row's covered-pass floor")):
            with self.subTest(floor=floor, covered=covered):
                ledger, digest = ledger_with(floor=floor, delivery=floor)
                evidence = self.case(edits(sweep_exit(1), lambda run, digest=digest: run.update(scenario_row=digest)),
                                     edits(lambda status, covered=covered: cover(status, "cluster-swarm", covered),
                                           listed_unreached("cluster-swarm", "cross")))
                self.verdicts(evidence, reach, HELD, text, tree=self.tree(ledger))
        beside = edits(lambda status: cover(status, "cluster-swarm", 63), listed_unreached("cluster-broad", "cross"))
        self.verdicts(self.case(sweep_exit(1), beside), BROKEN, HELD, "unreached cluster-broad: cross", PROPERTY)

    def test_a_silent_zero_is_invalid_at_the_floor_and_incomplete_under_it(self) -> None:
        silent = "no covered pass of cluster-swarm reached cross"
        for floor, covered, reach, text in ((64, 64, INVALID, silent), (64, 63, INCOMPLETE, "cluster-swarm 63"),
                                            (100, 100, INVALID, silent), (100, 99, INCOMPLETE, "cluster-swarm 99")):
            with self.subTest(floor=floor, covered=covered):
                ledger, digest = ledger_with(floor=floor, delivery=floor)
                evidence = self.case(lambda run, digest=digest: run.update(scenario_row=digest),
                                     edits(lambda status, covered=covered: cover(status, "cluster-swarm", covered),
                                           zero(("cluster-swarm", "cross"))))
                self.verdicts(evidence, reach, HELD, text, tree=self.tree(ledger))
        self.verdicts(self.case(status=reach_event("cluster-swarm", "cross", 1, 1)), HELD, HELD, "required events reached")

    def test_every_break_of_a_sweep_is_named(self) -> None:
        change = edits(zero(("cluster-swarm", "faults"), ("cluster-swarm", "hits"), ("cluster-broad", "cross")),
                       lambda status: status.update(unreached={"cluster-broad": ["cross"], "cluster-swarm": ["faults", "hits"]}),
                       listed_no_pass("cluster-pressure"))
        self.verdicts(self.case(sweep_exit(1), change), BROKEN, HELD,
                      "unreached cluster-swarm: faults, hits; unreached cluster-broad: cross; no_pass cluster-pressure; the row's",
                      PROPERTY, valid=("the sweep's reach verdict no_pass, unreached is the reach invariant's",))

    def test_a_required_event_of_cluster_pressure_unreached_breaks(self) -> None:
        self.verdicts(self.case(sweep_exit(1), listed_unreached("cluster-pressure", "refused")), BROKEN, HELD,
                      "unreached cluster-pressure: refused", PROPERTY)

    def test_counts_that_contradict_a_silent_or_partial_status_are_invalid(self) -> None:
        def dropped(status: dict) -> None:
            del status["profiles"]["cluster-swarm"]["reached"]["hits"]
            derive(status, "cluster-swarm")
        cases = ((None, zero(("cluster-swarm", "published")), "cluster-swarm reached published"),
                 (None, zero(("cluster-swarm", "invalidated")), "cluster-swarm reached invalidated"),
                 (None, dropped, "cluster-swarm reached hits"),
                 (None, zero(("cluster-broad", "faults")), "cluster-broad reached faults"),
                 (None, zero(("cluster-pressure", "refused")), "cluster-pressure reached refused"),
                 (None, edits(lambda status: cover(status, "cluster-swarm", 63), zero(("cluster-broad", "faults"))),
                  "cluster-broad reached faults"),
                 (sweep_exit(1), edits(zero(("cluster-broad", "faults"), ("cluster-broad", "hits")),
                                       lambda status: status.update(unreached={"cluster-broad": ["faults"]})),
                  "cluster-broad reached hits"))
        for run, change, text in cases:
            with self.subTest(text=text):
                self.verdicts(self.case(run, change), INVALID, HELD, f"no covered pass of {text}",
                              "which the committed table requires, and the status lists no unreached entry for it")

    def test_a_reached_map_no_sweep_prints_is_invalid_on_any_profile(self) -> None:
        for profile in ("cluster-swarm", "cluster-broad", "cluster-pressure"):
            for run, base in ((None, None), (sweep_exit(1), listed_no_pass("cluster-swarm"))):
                if base and profile == "cluster-swarm":
                    continue
                with self.subTest(profile=profile, broken_base=bool(base)):
                    def extra(status: dict, profile=profile) -> None:
                        status["profiles"][profile]["reached"]["reads"] = {"runs": 1, "total": 1}
                    self.verdicts(self.case(run, edits(base, extra)), INVALID, HELD, "no reached map of coverage counters")

    def test_a_run_without_the_binary_digest_is_invalid(self) -> None:
        for change in (lambda run: run.pop("campaign_binary"), lambda run: run["campaign_binary"].update(sha256="a" * 65)):
            with self.subTest():
                self.verdicts(self.case(change), INVALID, INVALID, "the campaign binary hashed otherwise")

    def test_a_reached_excused_pair_is_listed_and_changes_no_verdict(self) -> None:
        self.verdicts(self.case(status=reach_event("cluster-pressure", "cancelled", 1, 1)), HELD, HELD,
                      "excused pairs reached: cluster-pressure: cancelled by 1 ")
        both = edits(reach_event("cluster-pressure", "invalidated", 3, 7), reach_event("cluster-pressure", "cancelled", 2, 5))
        listed = ("excused pairs reached: cluster-pressure: invalidated by 3 covered passes, "
                  "cluster-pressure: cancelled by 2 covered passes; ")
        self.verdicts(self.case(status=both), HELD, HELD, listed)
        self.verdicts(self.case(sweep_exit(1), edits(both, listed_unreached("cluster-swarm", "faults"))), BROKEN, HELD, listed)
        short = edits(both, lambda status: cover(status, "cluster-swarm", 63))
        self.verdicts(self.case(status=short), INCOMPLETE, HELD, listed)

    def test_a_control_that_shows_no_effect_of_its_plant_is_invalid(self) -> None:
        def planted(status: dict) -> None:
            status.update(unreached={"cluster-pressure": ["invalidated"]})

        def short(status: dict) -> None:
            cover(status, "cluster-pressure", 63)
        unshown = "lists no unreached entry for its planted pair cluster-pressure: invalidated"
        cases = ((lambda run: run.update(defect="another-label"), planted, "the control run's defect"),
                 (lambda run: run.update(defect=LABEL[:-1]), planted, "the control run's defect"),
                 (lambda run: run.update(defect=f"{LABEL}-2"), planted, "the control run's defect"),
                 (sweep_exit(0), reach_event("cluster-pressure", "invalidated", 5, 5),
                  "the control's sweep lists no unreached entry, so its planted pair"),
                 (sweep_exit(0), None, unshown),
                 (None, lambda status: status.update(unreached={"cluster-pressure": ["cancelled"]}),
                  "the committed table excuses it"),
                 (None, lambda status: status.update(unreached={"cluster-pressure": ["invalidated", "cancelled"]}),
                  "the committed table excuses it"),
                 (None, listed_unreached("cluster-swarm", "faults"), unshown),
                 (None, listed_no_pass("cluster-broad"), unshown),
                 (None, edits(planted, zero(("cluster-swarm", "cross"))),
                  "no covered pass of cluster-swarm reached cross, which the committed table requires"),
                 (None, lambda status: status.update(unreached={"cluster-pressure": ["invalidated"], "cluster-swarm": ["faults"]}),
                  "the status lists cluster-swarm: faults under unreached, and"),
                 (None, edits(short, listed_unreached("cluster-swarm", "faults")),
                  "and not its planted pair cluster-pressure: invalidated"))
        for run, change, text in cases:
            with self.subTest(text=text):
                self.verdicts(self.case(edits(control, run), change), INVALID, HELD, text)
        self.verdicts(self.case(edits(control, sweep_exit(0)), short), INCOMPLETE, HELD, "cluster-pressure 63")

    def test_a_control_detail_holds_its_expect_whatever_the_sweep_lists_first(self) -> None:
        change = edits(zero(("cluster-pressure", "refused")),
                       lambda status: status.update(unreached={"cluster-pressure": ["refused", "invalidated"]}))
        key = self.verdicts(self.case(control, change), BROKEN, HELD, CONTROL, "invalidated, refused", PROPERTY)
        self.assertEqual(key["outcome"], "broken")

    def test_an_empty_or_blank_scope_sentence_exits_2(self) -> None:
        for sentence in ('""', '" \\t "'):
            tree = self.tree()
            module = tree / "chaos" / "judges" / "reach" / "shared.py"
            text, replaced = re.subn(r"^SCOPE = \(.*?\)$", f"SCOPE = {sentence}", module.read_text(encoding="utf-8"),
                                     count=1, flags=re.MULTILINE | re.DOTALL)
            self.assertEqual(replaced, 1)
            module.write_text(text, encoding="utf-8")
            for script, row in ((REACH, INVARIANT), (VALIDITY, SCENARIO)):
                with self.subTest(script=script, sentence=sentence):
                    code, key, output = self.receipt(script, row, self.case(), tree)
                    self.assertEqual((code, key), (INVALID, None), output)
                    self.assertIn("hold no scope sentence", output)


class Scope(unittest.TestCase):
    """The scope sentence, the receipt writer and the required-event table agree with the files they stand for."""

    def test_the_scope_sentence_is_the_line_of_the_project_file(self) -> None:
        project = (CHAOS / "project.yaml").read_text(encoding="utf-8")
        self.assertIn(shared.SCOPE, validator.yaml_list(project, "differs_from_production"))

    def test_the_readiness_claim_prints_the_scope_sentence(self) -> None:
        claim = (CHAOS / "READINESS.md").read_text(encoding="utf-8").splitlines()
        self.assertIn(f"- The copy differs from production: {shared.SCOPE}", claim)

    def test_loading_the_shared_module_again_keeps_one_scope_sentence(self) -> None:
        path = CHAOS / "judges" / "reach" / "shared.py"
        spec = importlib.util.spec_from_file_location("reach_shared", path)
        assert spec is not None and spec.loader is not None
        spec.loader.exec_module(shared)
        load_module("reach_shared_again", path)
        for _ in range(2):
            detail = common.receipt_for("row", "script", {}, None, None, None, HELD, "held")["key"]["detail"]
            self.assertEqual(detail, f"held; {shared.SCOPE}")
        self.assertIs(inspect.unwrap(common.report), shared.unscoped_report)

    def test_every_committed_reach_receipt_ends_with_the_scope_sentence(self) -> None:
        receipts = [path for path in (CHAOS / "receipts").glob("*/*.json") if path.stem in (SCENARIO, INVARIANT)]
        outcomes = {(json.loads(path.read_text(encoding="utf-8"))["key"]["mode"], path.stem) for path in receipts}
        self.assertLessEqual({("control", SCENARIO), ("control", INVARIANT), ("live", SCENARIO), ("live", INVARIANT)}, outcomes)
        for path in receipts:
            with self.subTest(receipt=path.relative_to(ROOT).as_posix()):
                detail = json.loads(path.read_text(encoding="utf-8"))["key"]["detail"]
                self.assertTrue(detail.endswith(f"; {shared.SCOPE}"), detail)

    def witness_and_control(self, receipts: Path) -> None:
        """Read the witness and the control under `receipts` by run id; receipts of other runs change nothing here."""
        for run, mode, row, outcome, start in (
                (WITNESS, "live", SCENARIO, "held", "valid: campaign sweep exited 0; "),
                (WITNESS, "live", INVARIANT, "held", f"{ROW['witness']['expect']}: "),
                (PLANTED, "control", SCENARIO, "held", "valid: campaign sweep exited 1; "),
                (PLANTED, "control", INVARIANT, "broken", f"{CONTROL}; the row's property: \"{PROPERTY}\"; ")):
            with self.subTest(run=run, row=row):
                receipt = json.loads((receipts / run / f"{row}.json").read_text(encoding="utf-8"))
                key = receipt["key"]
                self.assertEqual((receipt["run"]["run_id"], key["mode"], key["outcome"], key["defect"]),
                                 (run, mode, outcome, LABEL if mode == "control" else ""))
                self.assertTrue(key["detail"].startswith(start), key["detail"])

    def test_the_committed_witness_is_held_and_the_committed_control_broken_on_its_planted_pair(self) -> None:
        self.witness_and_control(CHAOS / "receipts")

    def test_a_second_run_of_the_scenario_leaves_the_witness_and_the_control_as_they_are_read(self) -> None:
        """The scenario row asks for two live runs, so the receipts of a later run stand beside the witness's."""
        with tempfile.TemporaryDirectory(prefix="chaos-reach-") as top:
            receipts = Path(top) / "receipts"
            shutil.copytree(CHAOS / "receipts", receipts)
            shutil.copytree(receipts / WITNESS, receipts / "reach-live-second")
            self.witness_and_control(receipts)

    def test_the_rows_name_the_reach_judges(self) -> None:
        scenario = next(row for row in LEDGER["scenarios"] if row["id"] == SCENARIO)
        self.assertEqual((ROW["judge"], scenario["judge"], scenario["invariants"], ROW["control"]["scenario"], ROW["kind"]),
                         (f"{REACH} {INVARIANT}", f"{VALIDITY} {SCENARIO}", [INVARIANT], SCENARIO, "threshold"))
        self.assertEqual(ROW["control"]["defect"], LABEL)
        self.assertEqual(common.scenario_profiles(scenario), ["cluster-swarm", "cluster-broad", "cluster-pressure"])

    def test_the_coverage_counters_are_those_of_the_summary(self) -> None:
        declared = re.search(r"pub const COVERAGE: \[&str; (\d+)\] = \[(.*?)\];", SUMMARY.read_text(encoding="utf-8"), re.DOTALL)
        assert declared is not None, "summary.rs declares no COVERAGE array the test can read"
        self.assertEqual((int(declared[1]), ast.literal_eval("[" + declared[2] + "]")),
                         (len(shared.COVERAGE), list(shared.COVERAGE)))

    def test_the_excused_pairs_are_those_of_the_required_event_table(self) -> None:
        table = table_rows()
        self.assertEqual({profile: set(events) for profile, events in shared.EXCUSED.items()},
                         {profile: set(excused) for profile, (_, excused) in table.items()})
        self.assertEqual(shared.ROWS, frozenset(table))
        for profile, (required, excused) in table.items():
            with self.subTest(profile=profile):
                self.assertEqual(sorted(required + excused), sorted(shared.COVERAGE))

    def test_the_table_reader_refuses_a_table_it_cannot_read_whole(self) -> None:
        source = TABLE.read_text(encoding="utf-8")
        row = re.search(TABLE_ROW, source, re.DOTALL)
        assert row is not None
        self.assertIn("cluster-swarm", table_rows(source.replace(row[0], row[0].replace("10673", "10_673"), 1)))
        for edited, text in ((source.replace(row[0], "// " + row[0].replace("\n", "\n// "), 1), "cannot read as a row"),
                             (source.replace(row[0], row[0] + "\n" + row[0], 1), "repeats a profile"),
                             (source.replace("pub(super) const REQUIRED: ", "pub(super) const OTHER: ", 1), "declares no REQUIRED")):
            with self.subTest(text=text), self.assertRaisesRegex(AssertionError, text):
                table_rows(edited)

    def test_the_row_floor_is_the_tables(self) -> None:
        declared = re.findall(r"(?m)^pub\(super\) const REQUIRED_PASSES: u64 = (\d+);$", TABLE.read_text(encoding="utf-8"))
        self.assertEqual(len(declared), 1, "required.rs declares no single REQUIRED_PASSES the test can read")
        self.assertEqual(int(declared[0]), ROW["threshold"]["min_covered_passes"])

    def test_the_gate_is_armed_and_reads_zero_as_the_supervisor_does(self) -> None:
        """The judge reads a profile as armed at the floor and a counter absent from `reached` as one no pass reached."""
        gate = re.search(r"pub\(super\) fn unreached\(.*?\n\}", TABLE.read_text(encoding="utf-8"), re.DOTALL)
        assert gate is not None, "required.rs declares no unreached the test can read"
        self.assertIn("    if totals.control || totals.covered < REQUIRED_PASSES {\n        return Vec::new();\n    }\n", gate[0])
        self.assertIn(".filter(|name| totals.never_reached(name))", gate[0])
        source = (SUPERVISOR / "campaign" / "seeds.rs").read_text(encoding="utf-8")
        absent = re.search(r"fn never_reached\(&self, name: &str\) -> bool \{(.*?)\n    \}", source, re.DOTALL)
        assert absent is not None, "seeds.rs declares no never_reached the test can read"
        self.assertEqual(absent[1].strip(), "self.reached.get(name).is_none_or(|event| event.runs == 0)")

    def test_the_no_pass_floor_and_rule_are_the_supervisors(self) -> None:
        """The claim prints NO_PASS_RUNS, and the judge accepts a no_pass entry on the terms `unpassed` lists one."""
        source = (SUPERVISOR / "campaign" / "seeds.rs").read_text(encoding="utf-8")
        declared = re.findall(r"(?m)^const NO_PASS_RUNS: u64 = (\d+);$", source)
        self.assertEqual(len(declared), 1, "seeds.rs declares no single NO_PASS_RUNS the test can read")
        self.assertEqual(int(declared[0]), shared.NO_PASS_RUNS)
        project = (CHAOS / "project.yaml").read_text(encoding="utf-8")
        printed = [line for line in validator.yaml_list(project, "trusted_base") if "the no_pass floor of " in line]
        self.assertEqual(len(printed), 1, "chaos/project.yaml prints no single no_pass floor")
        self.assertIn("ruled as it reads by the workstream's lead on the owner's delegation of 25 November 2026: "
                      f"the no_pass floor of {declared[0]} runs of a profile", printed[0])
        listed = re.search(r"fn unpassed\(totals: &Totals\) -> bool \{(.*?)\n\}", source, re.DOTALL)
        assert listed is not None, "seeds.rs declares no unpassed the test can read"
        self.assertEqual(listed[1].strip(),
                         "!totals.control && totals.runs >= NO_PASS_RUNS && totals.pass == 0 && totals.caught == 0")

    def test_the_count_relations_are_the_supervisors(self) -> None:
        source = (SUPERVISOR / "campaign" / "seeds.rs").read_text(encoding="utf-8")
        body = re.search(r"fn counts_agree\(&self\) -> bool \{(.*?)\n    \}", source, re.DOTALL)
        assert body is not None, "seeds.rs declares no counts_agree the test can read"
        for text in ("self.covered <= self.pass", "self.pass <= self.runs", "event.runs <= self.covered",
                     "event.runs <= event.total", "event.total <= event.runs.saturating_mul(u64::from(u32::MAX))"):
            self.assertIn(text, body[1])
        self.assertEqual((common.U32_MAX, common.U64_MAX), ((1 << 32) - 1, (1 << 64) - 1))
        missed = re.search(r'const MISSED: \[&str; 2\] = \[(.*?)\];', source)
        assert missed is not None, "seeds.rs declares no MISSED the test can read"
        self.assertEqual(ast.literal_eval("[" + missed[1] + "]"), list(shared.MISSED))


if __name__ == "__main__":
    unittest.main()
