#!/usr/bin/env python3
"""Exercise scripts/host-stop-controller.py over a fake control plane, in process: `FakePlane` replaces the one call
function and `Clock` the wall clock, the monotonic clock and the sleep, so no test starts the AWS CLI against any
endpoint. The plane holds the declared instances' states and status checks, the guardrail alarms' rows and the caller,
answers the five calls in the reply shapes the controller's header names, cuts a call whose scripted delay reaches its
timeout as the CLI does, and runs scripted refusals, lost replies, delays and faults per call; its log keeps the marks
that stood at each call. The cases cover a clean run and its calls, each refusal of step 1 and of the caller, the
snapshot and the declared set, the reach condition and the alarms before the stop, the checks before the stop leaves,
a stop that is never shown, the abort path before and after the stop is shown on each of its causes, the clocks, the
restoration, the marks' writes, the files the controller wrote judged by scripts/gameday-judge.py on a copy of its held
fixture, the call sites of the script, and `aws_cli` over a fake `aws` program on a temporary path. The fixtures under
scripts/host-stop-fixtures/ are synthetic: the operator file's approver says so, and no store wrote the snapshot. The
controller reads a copy of the game-day catalog in which each GD-2 prerequisite reads as met (`MET`)."""

from __future__ import annotations

import ast
import contextlib
import copy
import errno
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
import time
import unittest
from collections.abc import Callable
from pathlib import Path

# Each of the self-test's runs builds the controller's argument parser, whose messages gettext would look up in the
# locale directories each time; the C locale needs no lookup.
os.environ["LANGUAGE"] = "C"
ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/host-stop-controller.py"
FIXTURES = ROOT / "scripts/host-stop-fixtures"
HELD = ROOT / "scripts/gameday-fixtures/held"
SNAPSHOT = {path.name: path.read_bytes() for path in sorted((FIXTURES / "snapshot").iterdir())}
PACKAGE = (HELD / "package.json").read_bytes()
# The name under which the evidence directory holds the operator's copy of the package.
COPY = "package.json"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    previous, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


hsc = load("host_stop_controller", SCRIPT)
gj = hsc.judge
CATALOG = gj.decode(gj.CATALOG.read_text(encoding="utf-8"), "catalog")
FIS = gj.decode(gj.PROFILES.read_text(encoding="utf-8"), "profiles")
GD2 = next(e for e in CATALOG["entries"] if e["id"] == "GD-2")
OPERATOR = gj.decode((FIXTURES / "operator.json").read_text(encoding="utf-8"), "operator")
TARGET = "i-h1"
START = 104.0
FIVE = {("sts", "get-caller-identity"), ("ec2", "describe-instance-status"), ("ec2", "describe-instances"),
        ("ec2", "stop-instances"), ("cloudwatch", "describe-alarms")}
CHANGES = {"ec2 stop-instances", "ec2 start-instances", "ec2 reboot-instances", "ec2 terminate-instances"}
STATUS, RECORD, ALARMS, STOP = ("ec2 describe-instance-status", "ec2 describe-instances", "cloudwatch describe-alarms",
                                "ec2 stop-instances")
TEXTS = GD2["guardrail"]
# The end of every abort mark's detail: the SHA-256 of the restoration steps text the aborting run prints.
STEPS_TAIL = "; restoration steps sha256 " + hashlib.sha256(GD2["restoration"]["steps"].encode("utf-8")).hexdigest()
BLOCKS = "TBD - BLOCKS EXECUTION"
# The controller refuses to run GD-2 when a prerequisite contains BLOCKS, so every case runs under MET.
MET = copy.deepcopy(CATALOG)
for entry in MET["entries"]:
    if entry["id"] == "GD-2":
        entry["prerequisites"] = [text.replace(f": {BLOCKS}", "") for text in entry["prerequisites"]]


def setUpModule():
    """Points the judge's catalog path, which the controller reads at each run, at a file that holds MET."""
    scratch = Path(tempfile.mkdtemp(prefix="host-stop-catalog.", dir=SCRATCH))
    unittest.addModuleCleanup(shutil.rmtree, scratch)
    (scratch / "gamedays.json").write_text(json.dumps(MET), encoding="utf-8")
    unittest.addModuleCleanup(setattr, gj, "CATALOG", gj.CATALOG)
    gj.CATALOG = scratch / "gamedays.json"


class Clock:
    """`t` is the true time, which the monotonic clock (`elapsed`) and the control plane read; the controller's wall
    clock reads `t + step`. Only the controller's sleeps, the plane's calls and `advance` move `t`."""

    def __init__(self, t=START):
        self.t, self.step, self.sleeps = t, 0.0, 0

    def __call__(self):
        return self.t + self.step

    def elapsed(self):
        # Another origin than the wall clock's, so a bound that mixes the two clocks fails the cases.
        return self.t + 1e6

    def advance(self, seconds):
        self.t += seconds

    def sleep(self, seconds):
        assert seconds >= 0, seconds
        self.sleeps += 1
        assert self.sleeps < 10000, "the controller sleeps without end"
        self.t += seconds


class Kill(BaseException):
    """A process kill: nothing in the controller handles it, so it ends the run where it is raised."""


class FakePlane:
    """A control plane over `instances` {id: {state, checks, system, transition, reason, launched}} and `alarms`
    {name: row fields}; `launched` is the instance's last launch on the plane's clock, which its record names as
    LaunchTime. An alarm row holds StateValue, TreatMissingData `missing` and a StateTransitionedTimestamp; `flip(name,
    state)` sets its state and moves its timestamp. Each call takes `call_seconds`; a scripted delay that reaches the
    call's timeout advances the clock by the timeout and fails the call, as `aws_cli` does. The log keeps each call's
    timeout, the seconds the monotonic `deadline` left at its start when it is set, and the marks that stood in
    `evidence/injection` at its start; `envs` keeps each call's environment apart from the log, whose entries a failed
    assertion prints. `script[operation]` lists one action per call: None answers, "refuse" fails with no effect,
    "lose" applies the call and fails, "stall" applies it and runs to the call's cut, a number delays the answer by
    that many seconds, a callable runs first and returns one of those, and a one-argument callable `shape(reply)` (in
    `shapes`) rewrites the reply. `fault(operation)`, when set, is asked at each call; its first
    action other than None replaces the scripted one, marks the call in the log and clears it. A status read of a target
    with a stop requested reads `stopping` until `stop_after` reads, then `stopped`; with `stop_after` None it never
    stops. `stop_reply` is the state the stop request's reply names, and `transition_offset` moves the record's
    transition time from the request's."""

    def __init__(self, clock, evidence=None):
        self.clock, self.call_seconds, self.evidence = clock, 0.2, evidence
        self.arn = OPERATOR["identity"]
        self.instances = {i: {"state": "running", "checks": "ok", "system": "ok", "transition": "", "reason": None,
                              "launched": 0.0} for i in OPERATOR["instances"]}
        self.alarms: dict[str, dict[str, object]] = {n: {"StateValue": "OK", "TreatMissingData": "missing",
                           "StateTransitionedTimestamp": "2026-11-24T00:00:00.000Z"}
                       for n in OPERATOR["alarms"].values()}
        self.flips = 0
        self.script, self.shapes, self.log, self.envs = {}, {}, [], []
        self.deadline: float | None = None
        self.transition_offset = 0
        self.stop_after: int | None = 2
        self.stop_reads, self.stop_reply, self.stop_code = 0, "stopping", "Client.UserInitiatedShutdown"
        self.stopping: str | None = None
        self.fault: Callable[[str], object] | None = None

    def flip(self, name, state):
        self.flips += 1
        self.alarms[name].update(StateValue=state, StateTransitionedTimestamp=f"2026-11-24T00:00:{self.flips:02}.000Z")

    def standing(self):
        root = None if self.evidence is None else self.evidence / "injection"
        return sorted(p.stem for p in root.iterdir()) if root is not None and root.is_dir() else []

    def __call__(self, argv, retry, timeout, env):
        assert argv[-2:] == ("--region", OPERATOR["region"]), argv
        assert 0 < timeout <= hsc.CALL_SECONDS, timeout
        op, args = f"{argv[0]} {argv[1]}", list(argv[2:-2])
        begin = self.clock.t
        self.envs.append(env)
        self.log.append({"op": op, "args": args, "retry": retry, "start": begin, "timeout": timeout,
                         "left": None if self.deadline is None else self.deadline - begin, "marks": self.standing()})
        if op == STOP and self.evidence is not None and (self.evidence / "injection/stop.json").exists():
            self.log[-1]["stop.json"] = parse(self.evidence / "injection/stop.json")
        actions = self.script.get(op)
        action = actions.pop(0) if actions else None
        if self.fault is not None:
            planted = self.fault(op)
            if planted is not None:
                action, self.fault = planted, None
                self.log[-1]["fault"] = True
        if callable(action):
            action = action()
        if action == "stall":
            getattr(self, op.split()[1].replace("-", "_"))(args)
            action = hsc.CALL_SECONDS
        spent = self.clock.t - begin + self.call_seconds + (action if isinstance(action, (int, float)) else 0)
        if action == "late":
            # A reply the process delivers just past its cut, as a scheduler's delay can.
            self.clock.t = begin + timeout + 0.5
            self.log[-1]["time"] = self.clock.t
            return getattr(self, op.split()[1].replace("-", "_"))(args)
        if spent >= timeout:
            self.clock.t = begin + timeout
            self.log[-1].update(time=self.clock.t, cut=True)
            raise hsc.CallFailed(f"{op} gave no answer: timed out after {timeout} seconds")
        self.clock.t = begin + spent
        self.log[-1]["time"] = self.clock.t
        if action == "refuse":
            raise hsc.CallFailed(f"{op} refused")
        reply = getattr(self, op.split()[1].replace("-", "_"))(args)
        shapes = self.shapes.get(op)
        if shapes:
            reply = shapes.pop(0)(reply)
        if action == "lose":
            raise hsc.CallFailed(f"{op}: the reply was lost")
        return reply

    def ids(self, args):
        ids = args[args.index("--instance-ids") + 1:]
        for i in ids:
            if i not in self.instances:
                raise hsc.CallFailed(f"InvalidInstanceID.NotFound {i}")
        return ids

    def get_caller_identity(self, args):
        return {"UserId": "AROAEXAMPLE:gd2-run", "Account": "account", "Arn": self.arn}

    def describe_instance_status(self, args):
        assert args[0] == "--include-all-instances", args
        rows = []
        for i in self.ids(args):
            s = self.instances[i]
            if self.stopping == i and s["state"] == "stopping":
                self.stop_reads += 1
                if self.stop_after is not None and self.stop_reads >= self.stop_after:
                    s["state"] = "stopped"
            running = s["state"] == "running"
            rows.append({"InstanceId": i, "AvailabilityZone": "us-west-2a",
                         "InstanceState": {"Code": 16, "Name": s["state"]},
                         "InstanceStatus": {"Status": s["checks"] if running else "not-applicable", "Details": []},
                         "SystemStatus": {"Status": s["system"] if running else "not-applicable", "Details": []}})
        return {"InstanceStatuses": rows}

    def describe_instances(self, args):
        (i,) = self.ids(args)
        s = self.instances[i]
        row = {"InstanceId": i, "State": {"Code": 80, "Name": s["state"]}, "StateTransitionReason": s["transition"],
               "LaunchTime": launch_text(s["launched"])}
        if s["reason"] is not None:
            row["StateReason"] = {"Code": s["reason"], "Message": s["reason"]}
        return {"Reservations": [{"ReservationId": "r-1", "Instances": [row]}]}

    def stop_instances(self, args):
        (i,) = self.ids(args)
        s = self.instances[i]
        if s["state"] == "running":
            s.update(state="stopping", reason=self.stop_code,
                     transition=time.strftime("User initiated (%Y-%m-%d %H:%M:%S GMT)",
                                              time.gmtime(int(self.clock.t) + self.transition_offset)))
            self.stopping, self.stop_reads = i, 0
        return {"StoppingInstances": [{"InstanceId": i, "CurrentState": {"Code": 64, "Name": self.stop_reply},
                                       "PreviousState": {"Code": 16, "Name": "running"}}]}

    def describe_alarms(self, args):
        assert args[:3] == ["--alarm-types", "MetricAlarm", "--alarm-names"], args
        return {"MetricAlarms": [{"AlarmName": n, "MetricName": "Errors", "Namespace": "Kestrike/GameDay",
                                  **{k: v for k, v in self.alarms[n].items() if v is not None}}
                                 for n in args[3:] if n in self.alarms]}

    def ops(self, start=0):
        return [entry["op"] for entry in self.log[start:]]


def launch_text(seconds, zone="+00:00"):
    """`seconds` as a describe-instances LaunchTime: whole seconds as the CLI's reference shows them, and a fraction
    of three digits when `seconds` holds one."""
    whole = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(int(seconds // 1)))
    return whole + (f".{round(seconds % 1 * 1000):03}" if seconds % 1 else "") + zone


def memory_scratch():
    """The POSIX shared-memory file system's directory when this host has one the test may write, else None for the
    default temporary directory. The cases' directories stand there: each mark's write still syncs the file and its
    directory, which costs a disk flush on a disk-backed file system. `tempfile.mkdtemp` makes each case's directory
    private (mode 0700) under it, and each case removes its directory at its end."""
    shared = Path(os.sep, "dev", "shm")
    try:
        return str(shared) if shared.is_dir() and os.access(shared, os.W_OK | os.X_OK) else None
    except OSError:
        return None


SCRATCH = memory_scratch()


def parse(path):
    """The JSON value of the file at `path`; a file that is no JSON fails the test that reads it, naming the path."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise AssertionError(f"{path} cannot be read as JSON: {error}") from error


def listing(root):
    return sorted(p.relative_to(root).as_posix() for p in Path(root).rglob("*"))


def repeated(text, key, value):
    """The JSON object `text` with one more member `key`, which it already holds."""
    assert text.rstrip().endswith("}") and f'"{key}"' in text, text
    return text.rstrip()[:-1] + f", {json.dumps(key)}: {json.dumps(value)}}}\n"


def standing_marks(root):
    """The relative paths of the marks under `root/injection` but the seal."""
    return [f"injection/{p.name}" for p in (root / "injection").iterdir() if p.name != "collected.json"]


@contextlib.contextmanager
def patched(owner, name, value):
    """`owner.name` reads `value` inside the block and its own value again after it."""
    previous = getattr(owner, name)
    setattr(owner, name, value)
    try:
        yield
    finally:
        setattr(owner, name, previous)


def is_roles(path, data):
    """Whether a call of `publish` writes the roles mark."""
    return path.name == "roles.json"


def failing_once(owner, name, when, error):
    """`owner.name` inside the block: its first call for which `when(*args)` holds raises `error`."""
    step, failed = getattr(owner, name), []

    def planted(*args, **kwargs):
        if not failed and when(*args):
            failed.append(args)
            raise error
        return step(*args, **kwargs)
    return patched(owner, name, planted)


class Timeout(BaseException):
    """A bound passed: a BaseException, so the controller's handlers of Exception leave it to the test."""


@contextlib.contextmanager
def bounded(seconds):
    """Fails the block with Timeout when it runs longer than `seconds`, so a wait that should not happen fails the
    test rather than holding the suite."""
    def expired(signum, frame):
        raise Timeout(f"the block ran past {seconds} s")
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


class Case(unittest.TestCase):
    """One temporary directory per test with the operator file, the snapshot, the package and an evidence
    directory that holds the operator's copy of the package; `run_controller` and `restore` call the controller's
    `main` over the plane and the clock."""

    def setUp(self):
        for signum in hsc.SIGNALS:
            self.addCleanup(signal.signal, signum, signal.signal(signum, signal.SIG_DFL))
        self.tmp = Path(tempfile.mkdtemp(prefix="host-stop-test.", dir=SCRATCH))
        self.addCleanup(shutil.rmtree, self.tmp)
        (self.tmp / "snapshot").mkdir()
        for name, data in SNAPSHOT.items():
            (self.tmp / "snapshot" / name).write_bytes(data)
        self.operator, self.operator_text = copy.deepcopy(OPERATOR), None
        self.package = self.tmp / "package.json"
        self.evidence = self.tmp / "evidence"
        self.evidence.mkdir()
        self.fill(PACKAGE)
        self.clock = Clock()
        self.plane = FakePlane(self.clock, self.evidence)
        self.output = ""

    def fill(self, data):
        """Writes `data` as the package and as the operator's copy of it in the evidence directory."""
        self.package.write_bytes(data)
        (self.evidence / COPY).write_bytes(data)

    def write_operator(self):
        path = self.tmp / "operator.json"
        if self.operator_text is not None:
            path.write_text(self.operator_text, encoding="utf-8")
        else:
            path.write_text(json.dumps(self.operator, indent=1) + "\n", encoding="utf-8")
        return path

    def main(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = hsc.main(argv, call=self.plane, clock=self.clock, sleep=self.clock.sleep, elapsed=self.clock.elapsed)
        self.output += out.getvalue()
        return code

    def run_controller(self):
        deadline = self.operator.get("deadline_seconds") if isinstance(self.operator, dict) else None
        self.plane.deadline = self.clock.t + deadline if isinstance(deadline, (int, float)) else None
        return self.main(["run", "--operator", str(self.write_operator()), "--package", str(self.package),
                          "--evidence", str(self.evidence)])

    def restore(self, reviewed=None):
        """Runs `restore`; a restoration it writes is dated from the latest mark to the read that showed the target
        ready."""
        self.plane.deadline = None
        argv = ["restore", "--operator", str(self.write_operator()), "--evidence", str(self.evidence)]
        code = self.main(argv + (["--reviewed", str(reviewed)] if reviewed else []))
        if code == 0:
            marks = self.marks()
            ready = next(e["time"] for e in reversed(self.plane.log) if e["op"] == STATUS) + self.clock.step
            self.assertLessEqual(self.floor(), marks["restoration"]["time"], marks)
            self.assertLessEqual(marks["restoration"]["time"], ready, marks)
        return code

    def floor(self):
        """The latest time among the stop, stopped and abort marks that stand."""
        marks = self.marks()
        return max(marks[name]["time"] for name in ("stop", "stopped", "abort") if name in marks)

    def snapshot(self, name, change):
        """Rewrites one snapshot file with `change` applied to its list of rows."""
        path = self.tmp / "snapshot" / name
        rows = [gj.decode(line, name) for line in path.read_text(encoding="utf-8").splitlines()]
        change(rows)
        path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")

    def repackage(self, change):
        """Rewrites the package with `change` applied and approves its new digest."""
        package = parse(self.package)
        change(package)
        self.fill(json.dumps(package).encode("utf-8"))
        self.operator["approval"]["package_sha256"] = hashlib.sha256(self.package.read_bytes()).hexdigest()

    def patch(self, owner, name, value):
        """`owner.name` reads `value` until the test ends."""
        self.addCleanup(setattr, owner, name, getattr(owner, name))
        setattr(owner, name, value)

    def marks(self):
        """{mark: value} of DIR/injection; DIR holds nothing else but the package's copy once it holds `injection`."""
        root = self.evidence / "injection"
        if not root.exists():
            return {}
        self.assertEqual(sorted(p.name for p in self.evidence.iterdir()), ["injection", COPY])
        return {p.stem: parse(p) for p in root.iterdir()}

    def stops(self):
        return [e for e in self.plane.log if e["op"] == STOP]

    def shown(self):
        """Whether the record read that shows the stop has been made."""
        return any(e["op"] == RECORD for e in self.plane.log)

    def faulted(self, action, while_stopping=False):
        """Plants `action` on the first alarm read after the stop is shown, or, with `while_stopping`, after the stop
        request and before the record read."""
        def when(op):
            if op != ALARMS or not self.stops():
                return None
            return action if self.shown() != while_stopping else None
        self.plane.fault = when

    def fault_index(self):
        return next(i for i, e in enumerate(self.plane.log) if e.get("fault"))

    def after_fault(self):
        """Each call after the one the plane marked as the fault's."""
        return self.plane.ops(self.fault_index() + 1)

    def start_target(self, initializing=2):
        """The operator's start, now: the target runs with its checks initializing for `initializing` status reads."""
        reads = iter(range(initializing))
        target = self.plane.instances[TARGET]
        target.update(state="running", transition="", reason=None, checks="initializing", launched=self.clock.t)
        self.plane.stopping = None

        def ready():
            if next(reads, None) is None:
                target["checks"] = "ok"
        self.plane.script[STATUS] = [ready] * (initializing + 2)

    def review(self):
        """The operator's review, dated now, of the abort mark that stands."""
        abort = hashlib.sha256((self.evidence / "injection" / "abort.json").read_bytes()).hexdigest()
        return {"abort_sha256": abort, "steps": GD2["restoration"]["steps"], "reviewer": "the operator",
                "time": self.clock()}

    def assert_refused(self, calls=(), reason="refused: "):
        """The run ends in a refusal naming `reason`, after exactly `calls`, with the evidence directory holding the
        package's copy alone."""
        code = self.run_controller()
        self.assertEqual(code, 2, self.output)
        self.assertIn("refused: ", self.output)
        self.assertIn(reason, self.output)
        self.assertEqual(self.plane.ops(), list(calls), self.output)
        self.assertEqual(listing(self.evidence), [COPY], self.output)

    def assert_aborted(self, cause, marks, guardrail=None, detail=None):
        code = self.run_controller()
        self.assertEqual(code, 1, self.output)
        found = self.marks()
        self.assertEqual(sorted(found), sorted(marks), self.output)
        self.assertEqual((found["abort"]["cause"], found["abort"]["guardrail"]), (cause, guardrail), found["abort"])
        if detail is not None:
            self.assertIn(detail, found["abort"]["detail"])
        self.assertTrue(found["abort"]["detail"].endswith(STEPS_TAIL), found["abort"]["detail"][-120:])
        self.assertIn(GD2["restoration"]["steps"], self.output)
        self.assertFalse(CHANGES - {STOP} & set(self.plane.ops()), self.plane.ops())
        self.assertLessEqual(len(self.stops()), 1)
        # The abort path's status read, when a stop may have left, follows abort.json.
        if self.stops():
            self.assertEqual(self.plane.log[-1]["op"], STATUS)
            self.assertIn("abort", self.plane.log[-1]["marks"])
        return found


class Run(Case):
    def test_a_clean_run_sends_the_five_calls_in_order_writes_three_marks_and_exits_0(self):
        self.assertEqual(self.run_controller(), 0, self.output)
        self.assertIn(f"A start before {gj.decode(PACKAGE.decode(), COPY)['run']['end'] + 2 * hsc.SKEW_SECONDS + 1} "
                      "may end the judge's observation", self.output)
        ops = self.plane.ops()
        first = [op for i, op in enumerate(ops) if op not in ops[:i]]
        self.assertEqual(first, ["sts get-caller-identity", STATUS, ALARMS, STOP, RECORD])
        self.assertEqual([(e["args"], e["retry"]) for e in self.stops()], [(["--instance-ids", TARGET], False)])
        self.assertTrue(all(e["retry"] for e in self.plane.log if e["op"] != STOP))
        marks = self.marks()
        self.assertEqual(sorted(marks), ["roles", "stop", "stopped"])
        self.assertEqual((self.evidence / COPY).read_bytes(), PACKAGE, "the run leaves the package's copy as it was")
        stop, stopped = marks["stop"], marks["stopped"]
        self.assertEqual((stop["instance"], stop["identity"]), (TARGET, OPERATOR["identity"]))
        self.assertLess(marks["roles"]["time"], stop["time"])
        self.assertEqual(marks["roles"]["time"], 100, "roles.json carries the snapshot's cut")
        self.assertEqual((stopped["instance"], stopped["state"], stopped["request"]), (TARGET, "stopped", stop))
        # roles.json stands at the first alarm read and stop.json, read from disk, at the stop request.
        self.assertIn("roles", next(e for e in self.plane.log if e["op"] == ALARMS)["marks"])
        self.assertEqual(self.stops()[0]["marks"], ["roles", "stop"])
        # The stopped observation comes from a status read after the stop request, apart from its reply.
        stop_at = self.stops()[0]["time"]
        reads = [e for e in self.plane.log if e["op"] == STATUS and e["time"] > stop_at]
        self.assertEqual([e["time"] for e in reads[-1:]], [stopped["time"]], self.plane.log)
        asked = [e["args"][2:] for e in self.plane.log if e["op"] == STATUS]
        self.assertEqual(asked, [OPERATOR["instances"]] + [[TARGET]] * len(reads), "each poll names the target alone")
        self.assertEqual(sorted(marks["roles"]["standbys"]), ["h2", "h3"])
        self.assertIn("restoration is pending", self.output)
        # The observation polls the alarms until observe_seconds after the stopped read, and stopped.json stands
        # only after it.
        last = self.plane.log[-1]
        self.assertEqual(last["op"], ALARMS)
        self.assertGreaterEqual(last["start"], stopped["time"] + OPERATOR["observe_seconds"])
        # stop.json stood whole, as the final mark reads, when the stop request left.
        self.assertEqual(self.stops()[0]["stop.json"], stop)
        self.assertNotIn("stopped", last["marks"])

    def test_each_refusal_of_step_1_sends_no_call_and_writes_nothing(self):
        digest = OPERATOR["approval"]["package_sha256"]

        def without(key):
            return lambda o: o.pop(key)

        def set_(path, value):
            def change(o):
                node = o
                for k in path[:-1]:
                    node = node[k]
                node[path[-1]] = value
            return change

        cases = {
            "an operator file that is no JSON": ("not json", "not strict JSON"),
            "a repeated key": (repeated(json.dumps(OPERATOR), "region", "us-east-1"), "repeats a key"),
            "a missing key": (without("observe_seconds"), "refused: "),
            "an extra key": (set_(("extra",), 1), "refused: "),
            "no approval": (set_(("approval",), None), "holds no approval"),
            "an approval of another instance": (set_(("approval", "instance"), "i-h2"), "names instance i-h2"),
            "an approval of another package": (set_(("approval", "package_sha256"), "0" * 64), "another package"),
            "an approval past not_after": (set_(("approval", "not_after"), "1970-01-01T00:01:44Z"), "lapses"),
            "a target outside the declared set": (set_(("instances",), ["i-h2", "i-h3", "i-h4"]), "outside the "
                                                  "declared set"),
            "alarms missing a guardrail": (lambda o: o["alarms"].pop(TEXTS[3]), "refused: "),
            "alarms keyed by another text": (lambda o: o["alarms"].update({TEXTS[0] + " ": o["alarms"].pop(TEXTS[0])}),
                                             "refused: "),
            "one alarm for two guardrails": (set_(("alarms", TEXTS[1]), "gd2-guardrail-1"), "one alarm for two"),
            "an alarm name read as an option": (set_(("alarms", TEXTS[1]), "--debug"), "is no alarm name"),
            "a deadline shorter than the wait and the observation": (set_(("deadline_seconds",), 100), "holds less"),
            "a bound past its limit": (set_(("deadline_seconds",), hsc.LIMIT_SECONDS + 1), "past its limit"),
            "a bound that is no number": (set_(("observe_seconds",), "60"), "no positive"),
            "an instance ID read as an option": (set_(("instances",), ["i-h1", "--dry-run"]), "no instance ID"),
            "an instance ID with an option after it": (set_(("instances",), ["i-h1", "i-h2 --force"]),
                                                       "no instance ID"),
            "a region that is no region name": (set_(("region",), "us-west-2 --debug"), "no AWS region name"),
            "a repeated instance": (set_(("instances",), ["i-h1", "i-h2", "i-h2"]), "repeats an instance"),
            "more instances than one status read names": (set_(("instances",), [f"i-{n:x}" for n in range(101)]),
                                                          "not 1 to 100"),
            "an alarm name past 255 characters": (set_(("alarms", TEXTS[2]), "a" * 256), "is no alarm name"),
            "a snapshot path with a NUL": (set_(("snapshot",), "snap\u0000shot"), "control character"),
            "an alarm name with a lone surrogate": (set_(("alarms", TEXTS[2]), "gd2-\ud800"), "is no name of the layout"),
            "an approval that lapses before the deadline": (set_(("approval", "not_after"), "1970-01-01T00:06:33Z"),
                                                            "after the run's deadline"),
            "an approval that lapses within the skew after the deadline": (
                set_(("approval", "not_after"), "1970-01-01T00:06:36Z"), "after the run's deadline"),
            "a not_after without zero padding": (set_(("approval", "not_after"), "1970-1-1T01:00:00Z"), "is no time"),
            "a not_after on a day no calendar holds": (set_(("approval", "not_after"), "1970-02-30T00:00:00Z"),
                                                       "is no calendar time"),
            "an empty declared set": (set_(("instances",), []), "not 1 to 100"),
            "a not_after at second 61, which would read 01:00:01": (
                set_(("approval", "not_after"), "1970-01-01T00:59:61Z"), "is no time"),
            "a deadline past the run window": (set_(("deadline_seconds",), 297), "outside the package's run window"),
        }
        for name, (change, reason) in cases.items():
            with self.subTest(name):
                self.setUp()
                if isinstance(change, str):
                    self.operator_text = change
                else:
                    change(self.operator)
                self.assertEqual(OPERATOR["approval"]["package_sha256"], digest)
                self.assert_refused(reason=reason)
        with self.subTest("a run that starts inside the baseline window"):
            self.setUp()
            self.repackage(lambda p: p["baseline"].update(end=105))
            self.assert_refused(reason="inside the package's baseline window")
        with self.subTest("a run that starts before the run window"):
            # The judge ties the baseline's end to the run window, so a start before the run window lies inside the
            # baseline, which step 1 refuses.
            self.setUp()
            self.repackage(lambda p: (p["run"].update(start=130), p["baseline"].update(end=130)))
            self.assert_refused(reason="baseline window")
        for name, (change, reason) in {
                "another injection action": (lambda gd2: gd2["injection"].update(action="stop two hosts"),
                                             "GD-2's injection action differs"),
                "another restoration class": (lambda gd2: gd2["restoration"].update({"class": "automatic"}),
                                              "GD-2's restoration is not of class"),
                "restoration steps with no UTF-8 form": (lambda gd2: gd2["restoration"].update(steps="start \ud800"),
                                                         "GD-2's restoration is not of class"),
                "one prerequisite that is not met": (
                    lambda gd2: gd2["prerequisites"].append(f"a change freeze over the target zone: {BLOCKS}"),
                    "a change freeze over the target zone: TBD - BLOCKS EXECUTION']"),
                "no list of prerequisites": (lambda gd2: gd2.pop("prerequisites"), "execution: None"),
                "a prerequisite that is no text": (lambda gd2: gd2["prerequisites"].append(None), ", None]")}.items():
            with self.subTest(name):
                self.setUp()
                catalog = copy.deepcopy(MET)
                change(next(e for e in catalog["entries"] if e["id"] == "GD-2"))
                path = self.tmp / "gamedays.json"
                path.write_text(json.dumps(catalog), encoding="utf-8")
                committed, gj.CATALOG = gj.CATALOG, path
                try:
                    self.assert_refused(reason=reason)
                finally:
                    gj.CATALOG = committed
                if "prerequisite" in name:
                    self.assertIn("GD-2's prerequisites are not all met, so the catalog blocks its", self.output)
        for name, write in {"a malformed package": "{", "a package off the judge's layout": '{"id": "GD-2"}',
                            "a package that is no object": "[]"}.items():
            with self.subTest(name):
                self.setUp()
                self.fill(write.encode("utf-8"))
                self.assert_refused()
        with self.subTest("a simulation package"):
            self.setUp()
            self.repackage(lambda p: p.update(kind="simulation"))
            self.assert_refused(reason="only a staging run stops an instance")
        with self.subTest("a package past the judge's file size"):
            self.setUp()
            limit = max(gj.CATALOG.stat().st_size, len(json.dumps(self.operator, indent=1))) + 1
            self.fill(self.package.read_bytes() + b" " * limit)
            with patched(gj, "FILE_LIMIT", limit):
                self.assert_refused(reason=f"the package holds more than {limit} bytes")
        with self.subTest("an existing injection directory"):
            self.setUp()
            (self.evidence / "injection").mkdir()
            self.assertEqual(self.run_controller(), 2)
            self.assertEqual((self.plane.ops(), listing(self.evidence)), ([], ["injection", COPY]))
        with self.subTest("a missing evidence directory"):
            self.setUp()
            shutil.rmtree(self.evidence)
            self.assertEqual(self.run_controller(), 2)
            self.assertEqual(self.plane.ops(), [])
            self.assertFalse(self.evidence.exists())
        with self.subTest("a linked evidence directory"):
            self.setUp()
            (self.tmp / "linked").symlink_to(self.evidence)
            self.evidence = self.tmp / "linked"
            self.assert_refused(reason="is no directory")
        with self.subTest("an evidence directory named by an empty path, which reads as the working directory"):
            self.setUp()
            self.addCleanup(os.chdir, os.getcwd())
            os.chdir(self.evidence)
            code = self.main(["run", "--operator", str(self.write_operator()), "--package", str(self.package),
                              "--evidence", ""])
            self.assertEqual((code, self.plane.ops(), listing(self.evidence)), (2, [], [COPY]), self.output)
            self.assertIn("refused: '' is no directory", self.output)

    def test_an_evidence_directory_that_does_not_hold_the_packages_bytes_is_refused_with_no_call(self):
        copied = self.evidence / COPY

        def linked():
            copied.unlink()
            copied.symlink_to(self.package)

        def piped():
            copied.unlink()
            os.mkfifo(copied)

        def a_directory():
            copied.unlink()
            copied.mkdir()
        cases = {"no copy": (lambda: copied.unlink(), f"{COPY} cannot be read: No such file or directory"),
                 "a copy of other bytes": (lambda: copied.write_bytes(PACKAGE + b"\n"), "holds other bytes than"),
                 "a copy cut short": (lambda: copied.write_bytes(PACKAGE[:-1]), "holds other bytes than"),
                 "a link to the package": (linked, f"{COPY} cannot be read"),
                 "a named pipe": (piped, f"{COPY} is no regular file"),
                 "a directory": (a_directory, f"{COPY} is no regular file")}
        for name, (change, reason) in cases.items():
            with self.subTest(name):
                self.setUp()
                copied = self.evidence / COPY
                change()
                before = listing(self.evidence), copied.read_bytes() if copied.is_file() else None
                with bounded(5):
                    self.assertEqual(self.run_controller(), 2, self.output)
                self.assertIn("refused: ", self.output)
                self.assertIn(reason, self.output)
                self.assertEqual(self.plane.ops(), [], "no call is made beside a package the judge would refuse")
                self.assertEqual((listing(self.evidence), copied.read_bytes() if copied.is_file() else None), before)
        with self.subTest("the copy itself named as the package"):
            self.setUp()
            self.package = self.evidence / COPY
            self.assertEqual(self.run_controller(), 0, self.output)
            self.assertEqual((sorted(self.marks()), self.package.read_bytes()), (["roles", "stop", "stopped"], PACKAGE))

    def test_a_record_that_names_no_launch_time_still_shows_the_stop(self):
        def unnamed(reply):
            del reply["Reservations"][0]["Instances"][0]["LaunchTime"]
            return reply
        self.plane.shapes[RECORD] = [unnamed]
        self.assertEqual(self.run_controller(), 0, self.output)
        self.assertEqual(self.plane.ops().count(RECORD), 1)

    def test_the_committed_fixtures_say_they_are_synthetic(self):
        self.assertIn("synthetic fixture", OPERATOR["approval"]["approver"])

    def test_an_approval_that_lapses_the_skew_after_the_deadline_admits_the_run(self):
        self.operator["approval"]["not_after"] = "1970-01-01T00:06:39Z"
        self.assertEqual(self.run_controller(), 0, self.output)

    def test_values_exactly_at_their_bounds_are_admitted(self):
        self.operator["instances"] = [f"i-{n:x}" for n in range(hsc.MAX_INSTANCES)]
        self.operator["alarms"][TEXTS[2]] = "gd2 guardrail " + "a" * (hsc.ALARM_NAME_MAX - 14)
        operator = hsc.read_operator(self.write_operator(), GD2)
        self.assertEqual((len(operator["instances"]), len(operator["alarms"][TEXTS[2]])),
                         (hsc.MAX_INSTANCES, hsc.ALARM_NAME_MAX))
        raw = self.package.read_bytes()
        window = parse(self.package)["run"]
        admitted = {**OPERATOR, "deadline_seconds": window["end"] - window["start"],
                    "snapshot": str(self.tmp / "snapshot")}
        package, names, _, instance = hsc.check_run(raw, admitted, window["start"])
        self.assertEqual(instance, TARGET, "a start at the baseline's end with the deadline at the run window's end")
        for now in (100, 100 + OPERATOR["snapshot_max_age_seconds"]):
            self.assertEqual(hsc.read_snapshot(admitted, package, names, now)[2:], (100, 100), "read at its age bounds")
        opening = {**package, "baseline": {"start": 100, "end": 100}}
        self.assertEqual(hsc.read_snapshot(admitted, opening, names, 100)[2], 100, "a cut at the baseline's start")
        self.snapshot("shards.jsonl", lambda rows: (rows[3].update(generation=1, attempts=0), rows[4].update(
            generation=(1 << 32) - 1, attempts=gj.ATTEMPTS_MAX)))
        records = hsc.read_snapshot(admitted, package, names, 100)[0]
        self.assertEqual([(records[s]["generation"], records[s]["attempts"]) for s in ("s4", "s5")],
                         [(1, 0), ((1 << 32) - 1, (1 << 31) - 2)], "the counters at the ends of their ranges")
        with patched(gj, "FILE_LIMIT", len(raw)):
            self.assertEqual(hsc.read_bytes(self.package, "the package"), raw)
        mark = {"instance": TARGET, "time": START, "identity": OPERATOR["identity"]}
        data = hsc.encoded(mark, "a mark")
        with patched(hsc, "MARK_LIMIT", len(data)):
            self.assertEqual(hsc.encoded(mark, "a mark"), data)

    def test_a_step_taken_out_of_its_order_is_a_failure_the_controller_names(self):
        made = hsc.Controller(OPERATOR, GD2, self.plane, self.clock, self.clock.sleep, self.clock.elapsed)
        request = {"instance": TARGET, "time": START, "identity": OPERATOR["identity"]}
        for name, step in {"a stop checked before the preflight": made.ready,
                           "a pause with no deadline": lambda: made.pause(self.clock.elapsed() + 1),
                           "a mark with no injection directory": lambda: made.mark("stop", request),
                           "a stop awaited before the preflight": lambda: made.await_stop(request, 0)}.items():
            with self.subTest(name), self.assertRaises(RuntimeError):
                step()
        self.assertEqual((self.plane.ops(), self.clock.sleeps, listing(self.evidence)), ([], 0, [COPY]))

    def test_an_injection_directory_that_cannot_be_made_is_a_refusal(self):
        mkdir = os.mkdir

        def full(path, *args, **kwargs):
            if Path(path) == self.evidence / "injection":
                raise OSError(28, "No space left on device")
            return mkdir(path, *args, **kwargs)
        self.patch(hsc.os, "mkdir", full)
        self.assert_refused(["sts get-caller-identity", STATUS], "injection cannot be made: No space left on device")

    def window_plants(self):
        """{name: (plant, the refusal's text)}: each failure between the making of `injection/` and the roles mark,
        planted once by the context manager `plant()` returns."""
        def nth_fsync(n):
            calls, fsync = [], os.fsync

            def failing(fd):
                calls.append(fd)
                if len(calls) == n:
                    raise OSError(5, "Input/output error")
                fsync(fd)
            return patched(hsc.os, "fsync", failing)

        @contextlib.contextmanager
        def another_holder():
            mkdir, holders = os.mkdir, []

            def held(path, *args, **kwargs):
                mkdir(path, *args, **kwargs)
                if Path(path) == self.evidence / "injection" and not holders:
                    holders.append(hsc.lock(path))
            with patched(hsc.os, "mkdir", held):
                try:
                    yield
                finally:
                    hsc.unlock(holders[0])
        return {
            "a lock another descriptor holds": (another_holder, "is held by a run, restore or seal that has not ended"),
            "the evidence directory's sync": (lambda: failing_once(
                hsc.fis, "sync_directory", lambda d: Path(d) == self.evidence, OSError(5, "Input/output error")),
                "OSError: [Errno 5] Input/output error"),
            "the roles mark's write": (lambda: failing_once(
                hsc, "publish", is_roles, OSError(28, "No space left on device")), "No space left on device"),
            "a roles mark that stands under another's hand": (lambda: failing_once(
                hsc, "publish", is_roles, FileExistsError(17, "File exists")), "FileExistsError"),
            # The evidence directory's sync is the first fsync and the roles mark's sync once linked the third.
            "a roles mark removed after its sync failed": (lambda: nth_fsync(3), "so the mark is removed"),
        }

    def test_a_failure_before_the_roles_mark_stands_is_a_refusal_that_removes_injection(self):
        for name, (plant, reason) in self.window_plants().items():
            with self.subTest(name):
                self.setUp()
                with plant():
                    self.assert_refused(["sts get-caller-identity", STATUS], reason)
                    self.assertIn("before roles.json stood", self.output)
                    self.assertIn("is removed; nothing written", self.output)
                    self.assertNotIn("aborted on", self.output)
                    # The plant fails once, so the same directory takes the next run.
                    self.assertEqual(self.run_controller(), 0, self.output)
                    self.assertEqual(sorted(self.marks()), ["roles", "stop", "stopped"])

    def test_a_signal_beside_a_failure_before_the_roles_mark_stands_is_the_same_refusal(self):
        with self.subTest("a signal held since injection was made, then a failed sync of the evidence directory"):
            def signalled_sync(directory):
                os.kill(os.getpid(), signal.SIGTERM)
                return True
            with failing_once(hsc.fis, "sync_directory", signalled_sync, OSError(5, "Input/output error")):
                self.assert_refused(["sts get-caller-identity", STATUS], "Input/output error before roles.json stood")
        with self.subTest("a signal raised once a failed write of the roles mark ends its hold"):
            self.setUp()
            mark = hsc.Controller.mark

            def signalled(controller, name, value):
                try:
                    mark(controller, name, value)
                except OSError:
                    os.kill(os.getpid(), signal.SIGTERM)
                    raise
            with failing_once(hsc, "publish", is_roles, OSError(28, "No space left on device")), \
                    patched(hsc.Controller, "mark", signalled):
                self.assert_refused(["sts get-caller-identity", STATUS], "signal SIGTERM before roles.json stood")

    def test_an_injection_directory_that_cannot_be_removed_or_whose_removal_is_unsynced_is_named(self):
        rmdir, sync = os.rmdir, hsc.fis.sync_directory

        def kept(path, *args, **kwargs):
            if Path(path) == self.evidence / "injection":
                raise OSError(13, "Permission denied")
            return rmdir(path, *args, **kwargs)

        def unsynced(directory):
            # The sync before the roles mark passes; the one after the removal finds `injection` gone and fails.
            if Path(directory) == self.evidence and not (self.evidence / "injection").exists():
                raise OSError(5, "Input/output error")
            sync(directory)
        cases = {"a removal that fails": ((hsc.os, "rmdir", kept), ["injection", COPY]),
                 "a removal left unsynced": ((hsc.fis, "sync_directory", unsynced), [COPY])}
        for name, (plant, left) in cases.items():
            with self.subTest(name):
                self.setUp()
                with failing_once(hsc, "publish", is_roles, OSError(28, "No space left on device")), patched(*plant):
                    self.assertEqual(self.run_controller(), 2, self.output)
                self.assertIn("refused: OSError: [Errno 28] No space left on device before roles.json stood",
                              self.output)
                self.assertIn(f"{self.evidence / 'injection'} may stand", self.output)
                self.assertNotIn("nothing written", self.output)
                self.assertEqual((self.plane.ops(), listing(self.evidence)),
                                 (["sts get-caller-identity", STATUS], left))

    def test_a_roles_mark_that_stands_with_its_durability_unknown_takes_the_abort_path(self):
        calls, fsync, unlink = [], os.fsync, os.unlink

        def failing(fd):
            calls.append(fd)
            if len(calls) == 3:
                raise OSError(5, "Input/output error")
            fsync(fd)

        def kept(path, *args, **kwargs):
            if path == "roles.json":
                raise OSError(13, "Permission denied")
            return unlink(path, *args, **kwargs)
        with patched(hsc.os, "fsync", failing), patched(hsc.os, "unlink", kept):
            found = self.assert_aborted("exception", ["roles", "abort"],
                                        detail="roles.json stands, but it cannot be synced")
        self.assertEqual(self.stops(), [])
        self.assertIn("no stop request was sent", found["abort"]["detail"])

    def test_a_failure_the_controller_did_not_foresee_exits_2_and_names_what_stands(self):
        def fail(*args):
            raise RuntimeError("a planted fault in the snapshot's read")
        self.patch(hsc, "read_snapshot", fail)
        self.assertEqual(self.run_controller(), 2, self.output)
        self.assertIn("RuntimeError: a planted fault in the snapshot's read; nothing written", self.output)
        self.assertEqual((self.plane.ops(), listing(self.evidence)), (["sts get-caller-identity"], [COPY]))

    def test_a_wrong_or_unknown_caller_sends_no_stop_and_writes_nothing(self):
        identity = OPERATOR["identity"]
        for name, (change, reason) in {
                "another role": (lambda p: setattr(p, "arn", "arn:aws:sts::account:assumed-role/another-role/gd2-run"),
                                 "the caller is arn:aws:sts::account:assumed-role/another"),
                "a session whose name the identity begins": (lambda p: setattr(p, "arn", identity + "-2"),
                                                             f"the caller is {identity}-2, not {identity}"),
                "a lost reply": (lambda p: p.script.update({"sts get-caller-identity": ["lose"]}),
                                 "the caller is unknown"),
                "a reply whose Arn is no text": (lambda p: p.shapes.update(
                    {"sts get-caller-identity": [lambda r: {**r, "Arn": None}]}),
                    "the caller is unknown: Arn is no str"),
        }.items():
            with self.subTest(name):
                self.setUp()
                change(self.plane)
                self.assert_refused(["sts get-caller-identity"], reason)

    def test_a_stale_malformed_or_inconsistent_snapshot_is_refused_after_the_caller(self):
        changes = {
            "a stale shard record": ("shards.jsonl", lambda rows: [r.update(time=START - 61) for r in rows],
                                     "stale or ahead"),
            "a host report ahead of the clock": ("hosts.jsonl", lambda rows: rows[1]["report"].update(time=START + 1),
                                                 "stale or ahead"),
            "shard lines read at two times": ("shards.jsonl", lambda rows: rows[4].update(time=101), "not one cut"),
            "a missing shard": ("shards.jsonl", lambda rows: rows.pop(), "misses shards"),
            "a repeated shard": ("shards.jsonl", lambda rows: rows.append(dict(rows[0])), "repeats shard"),
            "an owner outside the package": ("shards.jsonl", lambda rows: rows[3].update(owner="h9"), "h9"),
            "an extra key": ("shards.jsonl", lambda rows: rows[0].update(note="x"), "refused: "),
            "a generation of 0": ("shards.jsonl", lambda rows: rows[4].update(generation=0),
                                  "generation is no generation of the layout: 0"),
            "a generation of 2^32": ("shards.jsonl", lambda rows: rows[4].update(generation=1 << 32),
                                     "generation is no generation of the layout"),
            "attempts below 0": ("shards.jsonl", lambda rows: rows[4].update(attempts=-1),
                                 "attempts is no attempts of the layout: -1"),
            "attempts past the judge's ATTEMPTS_MAX": (
                "shards.jsonl", lambda rows: rows[4].update(attempts=gj.ATTEMPTS_MAX + 1),
                "attempts is no attempts of the layout"),
            "an extra key in a host line": ("hosts.jsonl", lambda rows: rows[1].update(note="x"), "holds other keys"),
            "a health that is no boolean": ("hosts.jsonl", lambda rows: rows[1]["report"].update(healthy="yes"),
                                            "neither null nor"),
            "another target instance": ("hosts.jsonl", lambda rows: rows[0].update(instance="i-h9"),
                                        "target instance"),
            "one instance for two hosts": ("hosts.jsonl", lambda rows: rows[2].update(instance="i-h2"),
                                           "one instance twice"),
            "a host outside the package": ("hosts.jsonl", lambda rows: rows[2].update(host="h9"), "no host of the"),
            "a repeated host line": ("hosts.jsonl", lambda rows: rows.append(dict(rows[2], instance="i-h4")),
                                     "repeats one"),
            "a host that is no text": ("hosts.jsonl", lambda rows: rows[2].update(host=["h3"]), "no host of the"),
            "an owned shard with no witness key": ("shards.jsonl", lambda rows: rows[3].update(owner="h1",
                                                                                                standby="h2"),
                                                   "no witness key"),
            "a witness key of a shard the target does not own": (
                "shards.jsonl", lambda rows: rows[2].update(owner="h4"), "the target does not own"),
        }
        for name, (file, change, reason) in changes.items():
            with self.subTest(name):
                self.setUp()
                self.snapshot(file, change)
                self.assert_refused(["sts get-caller-identity"], reason)
        with self.subTest("a fresh cut before the baseline window starts, which the judge reads as no stop shown"):
            self.setUp()
            self.repackage(lambda p: p["baseline"].update(start=99))
            self.snapshot("shards.jsonl", lambda rows: [r.update(time=98) for r in rows])
            self.assert_refused(["sts get-caller-identity"], "cut 98 lies before the baseline window")

    def test_an_input_that_is_a_named_pipe_or_a_link_is_refused_without_waiting(self):
        (self.tmp / "snapshot" / "hosts.jsonl").unlink()
        os.mkfifo(self.tmp / "snapshot" / "hosts.jsonl")
        with bounded(5):
            self.assert_refused(["sts get-caller-identity"], "hosts.jsonl is no regular file")
        self.setUp()
        elsewhere = self.tmp / "shards-elsewhere.jsonl"
        (self.tmp / "snapshot" / "shards.jsonl").rename(elsewhere)
        (self.tmp / "snapshot" / "shards.jsonl").symlink_to(elsewhere)
        self.assert_refused(["sts get-caller-identity"], "shards.jsonl cannot be read")

    def test_a_snapshot_exactly_at_its_age_bound_is_read_and_is_too_old_when_the_stop_would_leave(self):
        # The caller's read ends one second after the run's start, which puts `oldest` exactly at the age bound.
        self.plane.script["sts get-caller-identity"] = [0.8]
        oldest = START + 1 - OPERATOR["snapshot_max_age_seconds"]
        self.snapshot("shards.jsonl", lambda rows: [r.update(time=oldest) for r in rows])
        found = self.assert_aborted("reach", ["roles", "abort"], detail="passed its age bound")
        self.assertEqual((found["roles"]["time"], self.stops()), (oldest, []))

    def test_a_roles_mark_off_the_judges_layout_is_refused_when_it_is_built(self):
        package = parse(self.package)
        names = gj.check_package(package)
        lines = (FIXTURES / "snapshot" / "shards.jsonl").read_text(encoding="utf-8").splitlines()
        records = {r["shard"]: {k: r[k] for k in gj.VERSION} for r in (gj.decode(line, "shards") for line in lines)}
        digest = OPERATOR["approval"]["package_sha256"]
        self.assertEqual(hsc.build_roles(package, names, digest, records, {}, {}, 100)["standbys"], {})
        records["s1"]["generation"] = -1
        with self.assertRaises(hsc.Refusal):
            hsc.build_roles(package, names, digest, records, {}, {}, 100)

    def test_a_declared_instance_not_running_or_an_unread_set_is_a_run_left_open(self):
        def reshape(change):
            return lambda p: p.shapes.update({STATUS: [lambda r: {"InstanceStatuses": change(r["InstanceStatuses"])}]})

        open_, unread = "are not running: a run is left open", "the declared instances' status is unknown"
        for name, (change, reason) in {
                "a stopped standby": (lambda p: p.instances["i-h2"].update(state="stopped"), open_),
                "a standby that is stopping": (lambda p: p.instances["i-h3"].update(state="stopping"), open_),
                "a stopped instance with no role": (lambda p: p.instances["i-h4"].update(state="stopped"), open_),
                "a lost status reply": (lambda p: p.script.update({STATUS: ["lose"]}), unread),
                "a status reply missing an instance": (reshape(lambda rows: rows[:-1]), unread),
                "a status reply naming an instance twice": (reshape(lambda rows: rows + rows[-1:]), unread),
                "a status reply naming an instance outside the declared set": (
                    reshape(lambda rows: rows + [{**rows[-1], "InstanceId": "i-h9"}]), unread),
                "a status reply whose state is no text": (
                    reshape(lambda rows: [{**rows[0], "InstanceState": {"Code": 16, "Name": 16}}] + rows[1:]), unread),
                "a partial status listing": (lambda p: p.shapes.update(
                    {STATUS: [lambda r: {**r, "NextToken": "t"}]}), unread)}.items():
            with self.subTest(name):
                self.setUp()
                change(self.plane)
                self.assert_refused(["sts get-caller-identity", STATUS], reason)

    def test_a_deadline_passed_before_injection_is_a_refusal(self):
        # Each call before injection/ is cut to the time the deadline leaves, and a cut at it is a refusal.
        self.operator.update(effect_timeout_seconds=10, observe_seconds=10, deadline_seconds=30)
        self.plane.script["sts get-caller-identity"] = [40]
        self.assert_refused(["sts get-caller-identity"], "the deadline of 30 s passed before injection/ was made")
        self.assertEqual(self.plane.log[0]["timeout"], 30)
        self.setUp()
        self.operator.update(effect_timeout_seconds=10, observe_seconds=10, deadline_seconds=30)
        self.plane.script["sts get-caller-identity"] = [25]
        self.plane.script[STATUS] = [10]
        self.assert_refused(["sts get-caller-identity", STATUS], "the deadline of 30 s passed")
        self.assertAlmostEqual(self.plane.log[1]["timeout"], 30 - 25.2)
        self.setUp()
        self.operator.update(effect_timeout_seconds=10, observe_seconds=10, deadline_seconds=30)
        build = hsc.build_roles

        def slow(*args):
            self.clock.advance(31)
            return build(*args)
        with patched(hsc, "build_roles", slow):
            self.assert_refused(["sts get-caller-identity", STATUS], "the deadline of 30 s passed before injection/")

    def test_too_few_roles_or_an_unhealthy_or_unread_standby_aborts_on_reach_with_no_stop(self):
        changes = {
            "no shard stood by for": ("shards.jsonl", lambda rows: rows[3].update(standby="h3"), "stands by for 0"),
            "an owned shard with no standby": ("shards.jsonl", lambda rows: rows[0].update(standby=None),
                                               "names no standby"),
            "an unhealthy standby": ("hosts.jsonl", lambda rows: rows[1]["report"].update(healthy=False),
                                     "reads running and unhealthy"),
            "a standby with no report": ("hosts.jsonl", lambda rows: rows[2].update(report=None),
                                         "reads running and no report"),
            "a standby with no snapshot line": ("hosts.jsonl", lambda rows: rows.pop(2), "has no instance state"),
        }
        for name, (file, change, detail) in changes.items():
            with self.subTest(name):
                self.setUp()
                self.snapshot(file, change)
                self.assert_aborted("reach", ["roles", "abort"], detail=detail)
                self.assertEqual(self.plane.ops(), ["sts get-caller-identity", STATUS])
        with self.subTest("one shard owned"):
            self.setUp()
            self.repackage(lambda p: p.update(witness=p["witness"][:1]))
            self.snapshot("shards.jsonl", lambda rows: [rows[i].update(owner="h4") for i in (1, 2)])
            self.assert_aborted("reach", ["roles", "abort"], detail="owns 1 shards")
            self.assertEqual(self.stops(), [])
        with self.subTest("a standby instance outside the declared set"):
            self.setUp()
            self.operator["instances"].remove("i-h3")
            self.plane.instances.pop("i-h3")
            marks = self.assert_aborted("reach", ["roles", "abort"], detail="standby host h3")
            self.assertNotIn("h3", marks["roles"]["standbys"])
            self.assertEqual(self.stops(), [])
        with self.subTest("an owned shard whose standby is the target itself"):
            self.setUp()
            self.snapshot("shards.jsonl", lambda rows: rows[0].update(standby="h1"))
            marks = self.assert_aborted("reach", ["roles", "abort"], detail="names no standby other than the target")
            self.assertEqual((sorted(marks["roles"]["standbys"]), self.stops()), (["h2", "h3"], []))

    def test_an_alarm_not_quiet_or_unread_before_the_stop_aborts_with_no_stop(self):
        def row(name, **fields):
            return lambda p: p.alarms[name].update(fields)

        def reshape(change):
            return lambda p: p.shapes.update({ALARMS: [change]})

        cases = {"in ALARM": (lambda p: p.flip("gd2-guardrail-4", "ALARM"), TEXTS[3], "reads ALARM"),
                 "without data": (lambda p: p.flip("gd2-guardrail-6", "INSUFFICIENT_DATA"), TEXTS[5],
                                  "reads INSUFFICIENT_DATA"),
                 "unanswered": (lambda p: p.alarms.pop("gd2-guardrail-8"), TEXTS[7], "reads no answer"),
                 "a lost reply": (lambda p: p.script.update({ALARMS: ["lose"]}), TEXTS[0], "the alarms are unread"),
                 "a refused read": (lambda p: p.script.update({ALARMS: ["refuse"]}), TEXTS[0], "the alarms are unread"),
                 "missing data read as not breaching": (row("gd2-guardrail-3", TreatMissingData="notBreaching"),
                                                        TEXTS[2], "treats missing data as notBreaching"),
                 "missing data ignored": (row("gd2-guardrail-7", TreatMissingData="ignore"), TEXTS[6],
                                          "treats missing data as ignore"),
                 "missing data left to its default": (row("gd2-guardrail-2", TreatMissingData=None), TEXTS[1],
                                                      "treats missing data as None"),
                 "missing data stated as null": (reshape(lambda r: {"MetricAlarms": [
                     {**a, "TreatMissingData": None} if a["AlarmName"] == "gd2-guardrail-5" else a
                     for a in r["MetricAlarms"]]}), TEXTS[4], "treats missing data as None"),
                 "an evaluation that is partial": (row("gd2-guardrail-1", EvaluationState="PARTIAL_DATA"), TEXTS[0],
                                                   "evaluation state PARTIAL_DATA"),
                 "an evaluation state of a kind not yet named": (row("gd2-guardrail-2", EvaluationState="LATER"),
                                                                 TEXTS[1], "evaluation state LATER"),
                 "an evaluation state that is no text": (row("gd2-guardrail-2", EvaluationState=3), TEXTS[0],
                                                         "EvaluationState is no str"),
                 "a PromQL alarm": (row("gd2-guardrail-6", EvaluationCriteria={"PromQLCriteria": {"Query": "up"}}),
                                    TEXTS[5], "a PromQL alarm"),
                 "a Metrics Insights alarm": (row("gd2-guardrail-8", Metrics=[
                     {"Id": "q", "Expression": " select AVG(Errors) FROM SCHEMA(\"Kestrike/GameDay\", Host)"}]),
                     TEXTS[7], "a metric query expression"),
                 "a metric math sum": (row("gd2-guardrail-3", Metrics=[{"Id": "e", "Expression": "m1 + m2"}]),
                                       TEXTS[2], "a metric query expression"),
                 "a FILL expression": (row("gd2-guardrail-3", Metrics=[{"Id": "e", "Expression": "FILL(m1, 0)"}]),
                                       TEXTS[2], "a metric query expression"),
                 "a percentile that ignores a low sample count": (
                     row("gd2-guardrail-5", EvaluateLowSampleCountPercentile="ignore"), TEXTS[4], "low sample count"),
                 "an evaluation state stated as null": (reshape(lambda r: {"MetricAlarms": [
                     {**a, "EvaluationState": None} for a in r["MetricAlarms"]]}), TEXTS[0], "EvaluationState is no"),
                 "an expression stated as null": (reshape(lambda r: {"MetricAlarms": [
                     {**a, "Metrics": [{"Id": "e", "Expression": None}]} for a in r["MetricAlarms"]]}), TEXTS[0],
                     "Expression is no"),
                 "a composite list stated as null": (reshape(lambda r: {**r, "CompositeAlarms": None}), TEXTS[0],
                                                     "CompositeAlarms is no"),
                 "a row with no transition timestamp": (row("gd2-guardrail-4", StateTransitionedTimestamp=None),
                                                        TEXTS[0], "StateTransitionedTimestamp is no str"),
                 "a composite alarm": (reshape(lambda r: {**r, "CompositeAlarms": [
                     {"AlarmName": "gd2-guardrail-1", "StateValue": "OK"}]}), TEXTS[0], "composite alarm"),
                 "an alarm named twice": (reshape(lambda r: {"MetricAlarms": [
                     {**r["MetricAlarms"][0], "StateValue": "ALARM"}] + r["MetricAlarms"]}), TEXTS[0], "twice"),
                 "an alarm not asked for": (reshape(lambda r: {"MetricAlarms": r["MetricAlarms"] + [
                     {"AlarmName": "other", "StateValue": "OK"}]}), TEXTS[0], "unasked"),
                 "a partial alarm listing": (reshape(lambda r: {**r, "NextToken": "t"}), TEXTS[0], "NextToken")}
        for name, (change, text, detail) in cases.items():
            with self.subTest(name):
                self.setUp()
                change(self.plane)
                self.assert_aborted("guardrail", ["roles", "abort"], text, detail)
                self.assertEqual(self.stops(), [])
                self.assertIn("no stop request was sent", self.marks()["abort"]["detail"])

    def test_alarms_that_state_missing_data_as_missing_or_breaching_on_one_metric_allow_the_stop(self):
        self.plane.alarms["gd2-guardrail-2"]["TreatMissingData"] = "breaching"
        self.plane.alarms["gd2-guardrail-3"]["Metrics"] = [{"Id": "m1", "MetricStat": {"Stat": "Sum"}}]
        self.assertEqual(self.run_controller(), 0, self.output)

    def test_a_stop_that_may_not_leave_aborts_before_the_request(self):
        with self.subTest("a snapshot past its age bound at the stop"):
            self.plane.script[ALARMS] = [57]
            self.assert_aborted("reach", ["roles", "abort"], detail="passed its age bound")
            self.assertEqual(self.stops(), [])
        with self.subTest("a snapshot past its age bound during the stop mark's write"):
            self.setUp()
            write = hsc.publish

            def aging(path, data):
                if path.name == "stop.json":
                    self.clock.advance(60)
                write(path, data)
            with patched(hsc, "publish", aging):
                found = self.assert_aborted("reach", ["roles", "stop", "abort"], detail="no stop request was sent")
            self.assertEqual(self.stops(), [])
            self.assertIn("passed its age bound", found["abort"]["detail"])
        with self.subTest("too little time left for the observation"):
            self.setUp()
            self.operator.update(deadline_seconds=110, snapshot_max_age_seconds=hsc.LIMIT_SECONDS)
            self.plane.script["sts get-caller-identity"] = [30]
            self.plane.script[ALARMS] = [40]
            self.assert_aborted("deadline", ["roles", "abort"], detail="cannot hold the observation of 45 s")
            self.assertEqual(self.stops(), [])
        with self.subTest("a wall clock that moves past the snapshot's age, as a suspend does"):
            self.setUp()
            self.plane.script[ALARMS] = [lambda: setattr(self.clock, "step", 3600.0)]
            self.assert_aborted("reach", ["roles", "abort"], detail="passed its age bound")
            self.assertEqual(self.stops(), [])
        with self.subTest("a wall clock that moves apart from the monotonic clock by more than the skew"):
            self.setUp()
            self.plane.script[ALARMS] = [lambda: setattr(self.clock, "step", hsc.SKEW_SECONDS + 5.0)]
            self.assert_aborted("deadline", ["roles", "abort"], detail="apart from the monotonic clock")
            self.assertEqual(self.stops(), [])
        with self.subTest("a wall clock that steps back by more than the skew and stays after the snapshot's cut"):
            self.setUp()
            self.plane.script[ALARMS] = [lambda: (setattr(self.clock, "step", -hsc.SKEW_SECONDS - 3.0), 10)[1]]
            self.assert_aborted("deadline", ["roles", "abort"], detail="apart from the monotonic clock")
            self.assertEqual(self.stops(), [])
        with self.subTest("a snapshot past its age bound on the monotonic clock while the wall clock steps back"):
            self.setUp()
            self.plane.script[ALARMS] = [lambda: (setattr(self.clock, "step", -3.0), 57)[1]]
            self.assert_aborted("reach", ["roles", "abort"], detail="passed its age bound")
            self.assertEqual(self.stops(), [])
        with self.subTest("an alarm that fires during the stop mark's write"):
            self.setUp()
            write = hsc.publish

            def firing(path, data):
                if path.name == "stop.json":
                    self.plane.flip("gd2-guardrail-2", "ALARM")
                write(path, data)
            with patched(hsc, "publish", firing):
                self.assert_aborted("guardrail", ["roles", "stop", "abort"], TEXTS[1], "no stop request was sent")
            self.assertEqual(self.stops(), [])
        with self.subTest("exactly the observation and one poll left"):
            self.setUp()
            self.operator.update(deadline_seconds=110, snapshot_max_age_seconds=hsc.LIMIT_SECONDS)
            # The alarms' first read ends with 50 s left before the deadline.
            self.plane.script[ALARMS] = [START + 110 - 50 - self.clock.t - 0.4 - 0.2]
            self.assert_aborted("deadline", ["roles", "abort"], detail="cannot hold the observation")
            self.assertEqual(self.stops(), [])

    def test_a_stop_accepted_and_never_shown_stopped_aborts_with_no_stopped_mark(self):
        def never(p):
            p.stop_after, p.stop_reply = None, "stopped"

        def wrong_record(p):
            p.stop_code = "Server.InternalError"

        def refused(p):
            p.script[STOP] = ["refuse"]

        def record_not_stopped(p):
            p.shapes[RECORD] = [lambda r: {"Reservations": [{"Instances": [
                {**r["Reservations"][0]["Instances"][0], "State": {"Code": 64, "Name": "stopping"}}]}]}] * 100

        def malformed_transition(p):
            p.shapes[RECORD] = [lambda r: {"Reservations": [{"Instances": [
                {**r["Reservations"][0]["Instances"][0], "StateTransitionReason": "User initiated"}]}]}] * 100

        def trailing_transition(p):
            p.shapes[RECORD] = [lambda r: {"Reservations": [{"Instances": [{
                **r["Reservations"][0]["Instances"][0], "StateTransitionReason":
                r["Reservations"][0]["Instances"][0]["StateTransitionReason"] + " and more"}]}]}] * 100

        def another_instance(p):
            p.shapes[RECORD] = [lambda r: {"Reservations": [{"Instances": [
                {**r["Reservations"][0]["Instances"][0], "InstanceId": "i-h2"}]}]}] * 100

        def slow_and_never(p):
            p.stop_after, p.script[STOP] = None, [10]

        sent = {"a refused request": "a stop request may have left and its outcome is unknown: ec2 stop-instances "
                                     "refused"}
        for name, change in {"a reply that reads stopped": never, "a record of another cause": wrong_record,
                             "a refused request": refused, "a record that reads another state": record_not_stopped,
                             "a record with no transition time": malformed_transition,
                             "a record with text after its transition time": trailing_transition,
                             "a record of another instance": another_instance,
                             "a request answered after 10 s": slow_and_never,
                             "a record at second 60": lambda p: p.shapes.update({RECORD: [lambda r: {"Reservations": [
                                 {"Instances": [{**r["Reservations"][0]["Instances"][0], "StateTransitionReason":
                                                 "User initiated (1970-01-01 00:01:60 GMT)"}]}]}] * 100})}.items():
            with self.subTest(name):
                self.setUp()
                change(self.plane)
                found = self.assert_aborted("stop-not-shown", ["roles", "stop", "abort"])
                self.assertEqual(len(self.stops()), 1)
                self.assertGreaterEqual(found["abort"]["time"],
                                        found["stop"]["time"] + OPERATOR["effect_timeout_seconds"] - 1e-6)
                self.assertLessEqual(found["abort"]["time"],
                                     found["stop"]["time"] + OPERATOR["effect_timeout_seconds"] + 1,
                                     "the effect timeout runs from the request")
                detail = found["abort"]["detail"]
                self.assertIn(sent.get(name, "the stop request was sent and answered"), detail)
                self.assertEqual(detail.count("ec2 stop-instances refused"), 1 if name in sent else 0)
                # The last poll reads the alarms and the status; the abort path then reads the status once more.
                ops = self.plane.ops()
                last = len(ops) - 1 - ops[::-1].index(ALARMS)
                # A last poll whose alarm read ends past the window makes no status read of its own.
                self.assertIn(ops[last + 1:], ([STATUS], [STATUS, STATUS], [STATUS, RECORD, STATUS]))

    def test_a_record_outside_the_request_and_the_stop_calls_end_or_of_two_instances_shows_no_stop(self):
        for name, change in {
                "a transition earlier than the request by more than the skew":
                    lambda p: setattr(p, "transition_offset", -hsc.SKEW_SECONDS - 1),
                "a transition later than the stop call's end by more than the skew":
                    lambda p: setattr(p, "transition_offset", hsc.SKEW_SECONDS + 1),
                "a transition whose second ends past the stop call's end and the skew":
                    lambda p: setattr(p, "transition_offset", hsc.SKEW_SECONDS),
                "a record naming two instances": lambda p: p.shapes.update({RECORD: [lambda r: {
                    "Reservations": r["Reservations"] * 2}] * 100})}.items():
            with self.subTest(name):
                self.setUp()
                change(self.plane)
                self.assert_aborted("stop-not-shown", ["roles", "stop", "abort"])
        for name, offset in {"within the skew before the request": -hsc.SKEW_SECONDS + 1,
                             "within the skew after the stop call's end": hsc.SKEW_SECONDS - 1}.items():
            with self.subTest(name):
                self.setUp()
                self.plane.transition_offset = offset
                self.assertEqual(self.run_controller(), 0, self.output)

    def test_a_stop_shown_by_reads_that_end_past_the_effect_timeout_is_not_shown(self):
        for name, script in {"a status read that ends past it": {STATUS: [None, None, 59]},
                             "a record read that ends past it": {RECORD: [59]}}.items():
            with self.subTest(name):
                self.setUp()
                self.plane.script.update(script)
                found = self.assert_aborted("stop-not-shown", ["roles", "stop", "abort"], detail="timed out")
                cut = next(e for e in self.plane.log if e.get("cut"))
                self.assertAlmostEqual(cut["time"], found["stop"]["time"] + OPERATOR["effect_timeout_seconds"],
                                       delta=0.5)
        with self.subTest("a record read that answers past it"):
            self.setUp()
            self.plane.script[RECORD] = ["late"]
            self.assert_aborted("stop-not-shown", ["roles", "stop", "abort"], detail="answered past the effect timeout")
        effect = OPERATOR["effect_timeout_seconds"]
        with self.subTest("an alarm read still unanswered at it"):
            self.setUp()
            self.faulted("stall", while_stopping=True)
            found = self.assert_aborted("stop-not-shown", ["roles", "stop", "abort"],
                                        detail="cloudwatch describe-alarms gave no answer")
            cut = self.plane.log[self.fault_index()]
            self.assertEqual((cut["op"], cut.get("cut"), self.after_fault()), (ALARMS, True, [STATUS]))
            self.assertLessEqual(cut["time"], found["stop"]["time"] + effect + 1e-6, "the read is cut at the timeout")
            self.assertLessEqual(found["abort"]["time"], found["stop"]["time"] + effect + 1e-6)
        with self.subTest("an alarm read lost before it"):
            self.setUp()
            self.faulted("lose", while_stopping=True)
            self.assert_aborted("guardrail", ["roles", "stop", "abort"], TEXTS[0], "the alarms are unread")
        with self.subTest("an alarm read that answers ALARM past it"):
            self.setUp()
            self.faulted(lambda: (self.plane.flip("gd2-guardrail-3", "ALARM"), "late")[1], while_stopping=True)
            self.assert_aborted("guardrail", ["roles", "stop", "abort"], TEXTS[2], "reads ALARM")

    def test_a_stopped_read_at_the_run_windows_end_shows_no_stop(self):
        # Calls of a quarter second keep every time exact in binary, so the wall clock reads the window's end exactly.
        self.plane.call_seconds = 0.25
        end = parse(self.package)["run"]["end"]
        self.plane.script[STATUS] = [None, None, lambda: setattr(self.clock, "step", end - (self.clock.t + 0.25))]
        self.assert_aborted("stop-not-shown", ["roles", "stop", "abort"], detail="outside [the stop request")
        read = [e for e in self.plane.log if e["op"] == STATUS][2]
        self.assertEqual(read["time"] + self.clock.step, end, "the read that showed stopped is dated at the end")

    def test_the_observation_ends_with_an_alarm_read_that_starts_at_or_after_its_end(self):
        def record():
            return next((e for e in self.plane.log if e["op"] == RECORD and "time" in e), {})

        def spanning(op):
            shown = record()
            if op != ALARMS or not shown:
                return None
            left = shown["time"] + OPERATOR["observe_seconds"] - self.clock.t
            return 4.0 if 0 < left < 4.0 else None
        self.plane.fault = spanning
        self.assertEqual(self.run_controller(), 0, self.output)
        end = record()["time"] + OPERATOR["observe_seconds"]
        spanned = self.plane.log[self.fault_index()]
        self.assertTrue(spanned["start"] < end < spanned["time"], spanned)
        self.assertGreaterEqual(self.plane.log[-1]["start"], end)

    def test_an_environment_changed_after_the_caller_check_does_not_reach_the_stop(self):
        kept = dict(os.environ)
        self.addCleanup(os.environ.update, kept)
        self.addCleanup(os.environ.clear)
        os.environ["AWS_SECRET_ACCESS_KEY"] = "a-planted-secret"
        before = dict(os.environ)

        def switch():
            os.environ.update(AWS_PROFILE="another-profile", AWS_ACCESS_KEY_ID="another-key")
        self.plane.script["cloudwatch describe-alarms"] = [switch]
        self.assertEqual(self.run_controller(), 0, self.output)
        self.assertFalse("a-planted-secret" in repr(self.plane.log), "the plane's log holds an environment value")
        caller = self.plane.envs[0]
        self.assertEqual((self.plane.log[0]["op"], len(self.plane.envs)),
                         ("sts get-caller-identity", len(self.plane.log)))
        self.assertTrue(caller == before, "the caller check runs under the environment read at the run's start")
        self.assertTrue(all(env is caller for env in self.plane.envs), "every call carries the one snapshot")
        self.assertFalse("another-profile" in caller.values(), "the changed profile reached a call")

    def test_a_lost_stop_reply_or_status_read_is_never_resent_and_the_polls_show_the_stop(self):
        self.plane.script[STOP] = ["lose"]
        self.plane.script[STATUS] = [None, "lose", "refuse"]
        self.assertEqual(self.run_controller(), 0, self.output)
        self.assertEqual(len(self.stops()), 1)
        self.assertEqual(sorted(self.marks()), ["roles", "stop", "stopped"])

    def test_a_stop_call_that_runs_to_its_cut_leaves_the_polls_half_the_effect_timeout(self):
        self.plane.script[STOP] = ["stall"]
        self.assertEqual(self.run_controller(), 0, self.output)
        (stop,) = self.stops()
        # The window opens at the request's time, before the alarms' second read.
        self.assertAlmostEqual(stop["timeout"], OPERATOR["effect_timeout_seconds"] / 2 - self.plane.call_seconds)
        self.assertTrue(stop.get("cut"))
        following = self.plane.log[self.plane.log.index(stop) + 1]
        self.assertEqual((following["op"], following["start"]), (ALARMS, stop["time"]), "the first poll runs at once")
        self.assertEqual(self.plane.log[self.plane.log.index(stop) + 2]["op"], STATUS)
        self.assertEqual(sorted(self.marks()), ["roles", "stop", "stopped"])

    def test_a_stop_shown_late_within_the_effect_timeout_writes_stopped(self):
        self.plane.stop_after = 8
        self.assertEqual(self.run_controller(), 0, self.output)
        marks = self.marks()
        self.assertLessEqual(marks["stopped"]["time"], marks["stop"]["time"] + OPERATOR["effect_timeout_seconds"])

    def test_a_roles_mark_past_the_judges_file_size_is_refused_before_injection(self):
        self.patch(hsc, "MARK_LIMIT", 4000)
        path = self.tmp / "snapshot" / "shards.jsonl"
        rows = [gj.decode(line, "shards") for line in path.read_text(encoding="utf-8").splitlines()]
        rows[4]["volume"] = "\u00e9" * 600
        path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
        self.assertLess((self.tmp / "snapshot" / "shards.jsonl").stat().st_size, 4000)
        self.assert_refused(["sts get-caller-identity", STATUS], "more than the judge reads")

    def test_the_window_runs_from_the_stop_calls_launch_to_its_return(self):
        with self.subTest("a slow stop call: its own transition shows the stop"):
            self.plane.script[STOP] = [10]
            self.assertEqual(self.run_controller(), 0, self.output)
        with self.subTest("a shutdown recorded before a late launch, and a refused request"):
            self.setUp()
            write = hsc.publish

            def foreign(path, data):
                write(path, data)
                if path.name == "stop.json":
                    self.plane.stop_instances(["--instance-ids", TARGET])
                    self.clock.advance(8)
            self.plane.script[STOP] = ["refuse"]
            with patched(hsc, "publish", foreign):
                self.assert_aborted("stop-not-shown", ["roles", "stop", "abort"])
            self.assertEqual(len(self.stops()), 1)

    def test_a_stop_request_that_never_left_aborts_with_no_poll(self):
        self.operator["snapshot_max_age_seconds"] = hsc.LIMIT_SECONDS
        write = hsc.publish

        def slow(path, data):
            write(path, data)
            if path.name == "stop.json":
                self.clock.advance(OPERATOR["effect_timeout_seconds"] / 2 + 1)
        self.patch(hsc, "publish", slow)
        found = self.assert_aborted("stop-not-shown", ["roles", "stop", "abort"], detail="never left")
        self.assertEqual(self.stops(), [])
        self.assertIn("no stop request was sent", found["abort"]["detail"])
        self.assertEqual(self.plane.ops()[-1], ALARMS)

    def test_the_check_before_the_stop_holds_the_approvals_lapse_and_the_run_windows_end(self):
        # Direct calls to `ready` isolate its approval-skew and run-window checks from the earlier admission checks.
        def controller(lapse, end=400.0, cut=100.0):
            operator = copy.deepcopy(OPERATOR)
            operator["approval"]["not_after"] = lapse
            made = hsc.Controller(operator, GD2, self.plane, self.clock, self.clock.sleep, self.clock.elapsed)
            made.package = {**parse(self.package), "baseline": {"start": 0, "end": START},
                            "run": {"start": START, "end": end}}
            made.cut, made.oldest, made.origin = cut, 100, (self.clock(), self.clock.elapsed())
            made.deadline, made.fresh_until = self.clock.elapsed() + 290, self.clock.elapsed() + 56
            return made
        self.assertEqual(controller("1970-01-01T00:01:49Z").ready(), START)
        for name, made in {"less than the skew before the approval's lapse": controller("1970-01-01T00:01:48Z"),
                           "at the snapshot's cut": controller("1970-01-01T01:00:00Z", cut=START),
                           "at the run window's end": controller("1970-01-01T01:00:00Z", end=START)}.items():
            with self.subTest(name):
                with self.assertRaises(hsc.Aborted) as caught:
                    made.ready()
                self.assertEqual(caught.exception.cause, "deadline")

    def test_a_run_exactly_at_its_bounds_stops_the_target(self):
        # Binary floating point represents 0.25 seconds exactly. At stop start, the snapshot age equals
        # `snapshot_max_age_seconds`, and the transition timestamp equals the earliest accepted second.
        self.plane.call_seconds, self.plane.transition_offset = 0.25, -hsc.SKEW_SECONDS
        self.plane.script[ALARMS] = [55]
        self.assertEqual(self.run_controller(), 0, self.output)
        (stop,) = self.stops()
        self.assertEqual(stop["start"], 100 + OPERATOR["snapshot_max_age_seconds"])
        self.assertEqual(self.plane.instances[TARGET]["transition"], "User initiated (1970-01-01 00:02:35 GMT)")

    def test_a_wall_clock_exactly_the_skew_ahead_admits_the_stop(self):
        self.plane.call_seconds, self.plane.transition_offset = 0.25, hsc.SKEW_SECONDS
        self.plane.script[ALARMS] = [lambda: setattr(self.clock, "step", float(hsc.SKEW_SECONDS))]
        self.assertEqual(self.run_controller(), 0, self.output)
        self.assertEqual(self.marks()["stop"]["time"], self.stops()[0]["start"] - 0.25 + hsc.SKEW_SECONDS)

    def test_a_request_dated_at_or_before_the_snapshots_cut_or_inside_the_baseline_is_not_sent(self):
        with self.subTest("at or before the snapshot's cut, after the baseline's end"):
            self.snapshot("shards.jsonl", lambda rows: [r.update(time=103) for r in rows])
            self.plane.script[ALARMS] = [lambda: setattr(self.clock, "step", -2.0)]
            self.assert_aborted("deadline", ["roles", "abort"], detail="at or before the snapshot's cut")
            self.assertEqual(self.stops(), [])
        with self.subTest("inside the baseline window, after the snapshot's cut and the run window's start"):
            self.setUp()
            self.repackage(lambda p: p["run"].update(start=70))
            self.snapshot("shards.jsonl", lambda rows: [r.update(time=90) for r in rows])
            self.plane.script[ALARMS] = [lambda: setattr(self.clock, "step", -4.9)]
            self.assert_aborted("deadline", ["roles", "abort"], detail="at or before the snapshot's cut")
            self.assertEqual(self.stops(), [])

    def test_a_pending_signal_ends_the_run_before_any_call(self):
        controller = hsc.Controller(hsc.read_operator(self.write_operator(), GD2), GD2, self.plane, self.clock,
                                    self.clock.sleep, self.clock.elapsed)
        controller.pending = signal.SIGTERM
        with self.assertRaises(hsc.Interrupted):
            controller.run(self.package, self.evidence)
        self.assertEqual((self.plane.ops(), listing(self.evidence)), ([], [COPY]))

    def test_a_raised_signal_disarms_the_controller(self):
        controller = hsc.Controller(OPERATOR, GD2, self.plane, self.clock, self.clock.sleep, self.clock.elapsed)
        controller.armed = True
        with self.assertRaises(hsc.Interrupted):
            controller.on_signal(signal.SIGTERM, None)
        self.assertFalse(controller.armed)
        controller.armed, controller.pending = True, signal.SIGINT
        with self.assertRaises(hsc.Interrupted):
            controller.release()
        self.assertFalse(controller.armed)

    def test_an_evidence_directory_with_no_unnamed_file_or_no_link_to_one_is_refused(self):
        opened, exists = hsc.os.open, hsc.os.path.exists
        root = str(self.evidence)

        def no_unnamed(path, flags, *args, **kwargs):
            if str(path) == root and flags & os.O_TMPFILE == os.O_TMPFILE:
                raise OSError(95, "Operation not supported")
            return opened(path, flags, *args, **kwargs)
        with patched(hsc.os, "open", no_unnamed):
            self.assert_refused(reason="takes no unnamed file")
        self.setUp()
        with patched(hsc.os.path, "exists", lambda p: False if str(p).startswith("/proc/self/fd/") else exists(p)):
            self.assert_refused(reason="does not resolve")

    def test_a_failed_stop_mark_sends_no_stop(self):
        write = hsc.publish
        for error, detail in ((OSError(28, "No space left on device"), "No space left on device"),
                              (hsc.Refusal("a planted refusal"), "Refusal: a planted refusal")):
            with self.subTest(detail):
                self.setUp()

                def failing(path, data, error=error):
                    if path.name == "stop.json":
                        raise error
                    write(path, data)
                with patched(hsc, "publish", failing):
                    self.assert_aborted("exception", ["roles", "abort"], detail=detail)
                self.assertEqual(self.stops(), [])


class AbortAfterStop(Case):
    """Each cause of the abort path after the stop is shown leaves the same marks and makes no call that changes an
    instance: after the faulted call the abort path's one status read alone follows."""

    def check(self, cause, guardrail=None, marks=("roles", "stop", "stopped", "abort")):
        found = self.assert_aborted(cause, list(marks), guardrail)
        self.assertEqual(self.after_fault(), [STATUS], self.plane.ops())
        self.assertEqual(len(self.stops()), 1)
        self.assertGreaterEqual(found["abort"]["time"], found["stop"]["time"])
        if "stopped" in marks:
            self.assertGreaterEqual(found["abort"]["time"], found["stopped"]["time"])
        return found

    def near_deadline(self):
        """A fault on an alarm read that starts less than 30 s before the deadline: a delay of 40 s, which the call's
        cut at the deadline ends."""
        def when(op):
            deadline = self.plane.deadline
            return 40 if op == ALARMS and self.stops() and deadline is not None and deadline - self.clock.t < 30 \
                else None
        self.plane.fault = when

    def test_a_guardrail_alarm(self):
        self.faulted(lambda: self.plane.flip("gd2-guardrail-5", "ALARM"))
        self.check("guardrail", TEXTS[4])

    def test_an_alarm_without_data(self):
        self.faulted(lambda: self.plane.flip("gd2-guardrail-2", "INSUFFICIENT_DATA"))
        self.check("guardrail", TEXTS[1])

    def test_an_alarm_that_fired_and_recovered_between_two_reads(self):
        def flicker():
            self.plane.flip("gd2-guardrail-7", "ALARM")
            self.plane.flip("gd2-guardrail-7", "OK")
        self.faulted(flicker)
        found = self.check("guardrail", TEXTS[6])
        self.assertIn("changed state", found["abort"]["detail"])

    def test_an_alarm_read_that_answers_past_the_deadline_aborts_the_run(self):
        # The observation's final alarm read, the last call of a run, answers quiet but past the deadline: the run
        # aborts with cause deadline rather than ending with exit 0.
        self.operator.update(effect_timeout_seconds=40, observe_seconds=240)

        def final(op):
            shown = [e for e in self.plane.log if e["op"] == STATUS and e.get("time") is not None
                     and self.plane.instances[TARGET]["state"] == "stopped"]
            return "late" if op == ALARMS and shown and self.clock.t >= shown[0]["time"] + 240 - 1e-6 else None
        self.plane.fault = final
        found = self.check("deadline")
        self.assertIn("the deadline of", found["abort"]["detail"])
        index = self.fault_index()
        self.assertEqual(self.plane.ops(index + 1), [STATUS], "no call starts after the late answer but the abort's")

    def test_the_deadline(self):
        # An observation that outlasts the deadline: the stop shows late, so a poll starts within 30 s of it, and
        # that call's cut at the deadline aborts the run with cause deadline.
        self.operator.update(effect_timeout_seconds=40, observe_seconds=240)
        self.plane.stop_after = 7
        self.near_deadline()
        found = self.check("deadline")
        self.assertTrue(self.plane.log[self.fault_index()].get("cut"))
        self.assertIn("the deadline of", found["abort"]["detail"])

    def test_a_call_near_the_deadline_is_cut_to_what_is_left(self):
        # An observation that ends 6 s before the deadline, so the polls run into its last 20 s.
        self.operator.update(effect_timeout_seconds=20, observe_seconds=OPERATOR["deadline_seconds"] - 25)
        # A delay that ends the alarm read 20 s before the deadline, planted where it is shorter than one call's cut.
        end = START + OPERATOR["deadline_seconds"] - 20
        self.plane.fault = lambda op: (end - self.clock.t) \
            if op == ALARMS and self.shown() and 0 < end - self.clock.t < hsc.CALL_SECONDS - 1 else None
        self.assertEqual(self.run_controller(), 0, self.output)
        after = self.plane.log[self.fault_index() + 1]
        self.assertLess(after["timeout"], 20)
        self.assertAlmostEqual(after["timeout"], after["left"], delta=1e-6)
        self.assertTrue(all(e["timeout"] <= min(hsc.CALL_SECONDS, e["left"]) + 1e-9 for e in self.plane.log))

    def test_an_exception(self):
        def fail():
            raise RuntimeError("a planted fault in the alarm read " + "x" * hsc.DETAIL_MAX)
        self.faulted(fail)
        detail = self.check("exception")["abort"]["detail"]
        self.assertTrue(detail.startswith("the stop request was sent and answered; RuntimeError: a planted fault"),
                        detail[:100])
        self.assertEqual(len(detail), hsc.DETAIL_MAX)
        self.assertTrue(detail.endswith("x" + STEPS_TAIL), "the cut keeps the steps' digest whole at the detail's end")

    def test_the_observations_last_alarm_read_answering_past_the_deadline_aborts_the_run(self):
        # The record read's time anchors the observation; the fault delays the alarm read that starts at or after the
        # observation's end until past the deadline.
        self.operator.update(effect_timeout_seconds=20, observe_seconds=OPERATOR["deadline_seconds"] - 25)

        def late(op):
            shown = next((e for e in self.plane.log if e["op"] == RECORD and "time" in e), None)
            at_end = shown is not None and self.clock.t > shown["time"] + self.operator["observe_seconds"] - 0.1
            return "late" if op == ALARMS and at_end else None
        self.plane.fault = late
        found = self.check("deadline")
        self.assertIn("the deadline of", found["abort"]["detail"])
        self.assertGreater(self.plane.log[self.fault_index()]["time"], self.plane.deadline)

    def test_the_run_holds_the_lock_of_injection_to_its_end(self):
        refusals = []

        def contend():
            with self.assertRaises(hsc.Refusal) as caught:
                hsc.lock(self.evidence / "injection")
            refusals.append(str(caught.exception))
        self.faulted(contend)
        self.assertEqual(self.run_controller(), 0, self.output)
        self.assertEqual(len(refusals), 1)
        self.assertIn("is held by", refusals[0])
        hsc.unlock(hsc.lock(self.evidence / "injection"))
        with self.assertRaises(hsc.Refusal) as missing:
            hsc.lock(self.evidence / "no-such-directory")
        self.assertIn("cannot be opened", str(missing.exception))

    def test_a_signal_while_injection_is_made_aborts_after_the_roles_mark(self):
        mkdir = os.mkdir

        def interrupted(path, *args, **kwargs):
            if Path(path) == self.evidence / "injection":
                os.kill(os.getpid(), signal.SIGHUP)
            return mkdir(path, *args, **kwargs)
        self.patch(hsc.os, "mkdir", interrupted)
        self.assert_aborted("signal", ["roles", "abort"], detail="signal SIGHUP")
        self.assertEqual(self.stops(), [])

    def test_a_process_signal(self):
        self.faulted(lambda: os.kill(os.getpid(), signal.SIGTERM))
        found = self.check("signal")
        self.assertIn("SIGTERM", found["abort"]["detail"])
        self.assertEqual(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)

    def test_each_cause_between_the_stop_request_and_the_stop_shown(self):
        self.plane.stop_after = None
        stopping = ("roles", "stop", "abort")
        with self.subTest("a guardrail alarm"):
            self.faulted(lambda: self.plane.flip("gd2-guardrail-3", "ALARM"), while_stopping=True)
            self.check("guardrail", TEXTS[2], stopping)
        with self.subTest("a signal"):
            self.setUp()
            self.plane.stop_after = None
            self.faulted(lambda: os.kill(os.getpid(), signal.SIGINT), while_stopping=True)
            self.assertIn("SIGINT", self.check("signal", None, stopping)["abort"]["detail"])
        with self.subTest("the deadline"):
            # A late start leaves the deadline inside the effect timeout.
            self.setUp()
            self.plane.stop_after = None
            self.operator.update(deadline_seconds=105)
            self.plane.script["sts get-caller-identity"] = [50]
            self.near_deadline()
            self.check("deadline", None, stopping)

    def test_a_signal_during_a_mark_waits_for_its_write(self):
        write = hsc.publish

        def interrupted_write(path, data):
            if path.name == "stop.json":
                os.kill(os.getpid(), signal.SIGTERM)
            write(path, data)
        self.patch(hsc, "publish", interrupted_write)
        found = self.assert_aborted("signal", ["roles", "stop", "abort"])
        self.assertEqual(self.stops(), [], "the signal raised at the write's end, before the stop request")
        self.assertEqual(listing(self.evidence / "injection"), sorted(f"{m}.json" for m in found))

    def test_a_signal_with_a_failed_write_still_ends_in_the_abort_path(self):
        write = hsc.publish

        def failed_write(path, data):
            if path.name == "stop.json":
                os.kill(os.getpid(), signal.SIGTERM)
                raise OSError(28, "No space left on device")
            write(path, data)
        self.patch(hsc, "publish", failed_write)
        found = self.assert_aborted("exception", ["roles", "abort"])
        self.assertIn("No space left on device", found["abort"]["detail"])

    def test_a_signal_during_the_abort_path_is_ignored(self):
        abort = hsc.Controller.abort

        def interrupted_abort(controller, *cause):
            os.kill(os.getpid(), signal.SIGTERM)
            return abort(controller, *cause)
        self.patch(hsc.Controller, "abort", interrupted_abort)
        self.plane.flip("gd2-guardrail-4", "ALARM")
        self.assert_aborted("guardrail", ["roles", "abort"], TEXTS[3])

    def test_a_signal_during_the_evidence_directory_sync_aborts_after_the_roles_mark(self):
        sync = hsc.fis.sync_directory

        def interrupted(directory):
            if Path(directory) == self.evidence:
                os.kill(os.getpid(), signal.SIGTERM)
            sync(directory)
        self.patch(hsc.fis, "sync_directory", interrupted)
        self.assert_aborted("signal", ["roles", "abort"])
        self.assertEqual(self.stops(), [])

    def test_a_signal_during_the_final_stopped_mark_keeps_exit_0(self):
        write = hsc.publish

        def interrupted_write(path, data):
            if path.name == "stopped.json":
                os.kill(os.getpid(), signal.SIGTERM)
            write(path, data)
        self.patch(hsc, "publish", interrupted_write)
        self.assertEqual(self.run_controller(), 0, self.output)
        self.assertEqual(sorted(self.marks()), ["roles", "stop", "stopped"])

    def test_a_run_killed_during_the_observation_leaves_no_stopped_mark(self):
        def kill():
            raise Kill()
        self.faulted(kill)
        with self.assertRaises(Kill):
            self.run_controller()
        self.assertEqual(sorted(self.marks()), ["roles", "stop"])
        self.assertEqual(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)

    def test_a_failed_abort_mark_leaves_no_stopped_mark(self):
        write = hsc.publish

        def failing(path, data):
            if path.name == "abort.json":
                raise OSError(28, "No space left on device")
            write(path, data)
        self.patch(hsc, "publish", failing)
        self.faulted(lambda: self.plane.flip("gd2-guardrail-1", "ALARM"))
        self.assertEqual(self.run_controller(), 1, self.output)
        self.assertEqual(sorted(self.marks()), ["roles", "stop"])
        self.assertIn("abort.json is unwritten", self.output)
        self.assertEqual(self.after_fault(), [STATUS])

    def test_a_restore_during_the_observation_is_refused(self):
        refusals = []

        def restore():
            controller = hsc.Controller(hsc.read_operator(self.write_operator(), GD2), GD2, self.plane, self.clock,
                                        self.clock.sleep, self.clock.elapsed)
            with self.assertRaises(hsc.Refusal) as caught:
                controller.restore(self.evidence, None)
            refusals.append(str(caught.exception))
        self.plane.fault = lambda op: restore if op == ALARMS and self.shown() else None
        self.assertEqual(self.run_controller(), 0, self.output)
        self.assertEqual(len(refusals), 1)
        self.assertIn("is held by a run, restore or seal that has not ended", refusals[0])

    def test_a_failed_output_stream_changes_no_outcome(self):
        class Broken(io.TextIOBase):
            def __init__(self, error):
                self.error = error

            def write(self, text):
                raise self.error

        errors = {"EIO": OSError(5, "Input/output error"),
                  "an unencodable text": UnicodeEncodeError("ascii", "\u00e9", 0, 1, "ordinal not in range")}
        for name, error in errors.items():
            for aborted in (False, True):
                with self.subTest(name, aborted=aborted):
                    self.setUp()
                    if aborted:
                        self.faulted(lambda: self.plane.flip("gd2-guardrail-1", "ALARM"))
                    self.plane.deadline = None
                    argv = ["run", "--operator", str(self.write_operator()), "--package", str(self.package),
                            "--evidence", str(self.evidence)]
                    with contextlib.redirect_stdout(Broken(error)), contextlib.redirect_stderr(Broken(error)):
                        code = hsc.main(argv, call=self.plane, clock=self.clock, sleep=self.clock.sleep,
                                        elapsed=self.clock.elapsed)
                    self.assertEqual(code, 1 if aborted else 0)
                    self.assertEqual("abort" in self.marks(), aborted)
                    if aborted:
                        self.assertEqual(self.after_fault(), [STATUS])

    def test_an_ignored_hangup_stays_ignored(self):
        previous = signal.signal(signal.SIGHUP, signal.SIG_IGN)
        self.addCleanup(signal.signal, signal.SIGHUP, previous)
        self.faulted(lambda: os.kill(os.getpid(), signal.SIGHUP))
        self.assertEqual(self.run_controller(), 0, self.output)
        self.assertNotIn("abort", self.marks())
        self.assertEqual(signal.getsignal(signal.SIGHUP), signal.SIG_IGN)

    def test_a_signal_before_injection_ends_the_run_with_nothing_written(self):
        self.plane.script["sts get-caller-identity"] = [lambda: os.kill(os.getpid(), signal.SIGINT)]
        self.assertEqual(self.run_controller(), 2, self.output)
        self.assertIn("signal SIGINT before any mark; nothing written", self.output)
        self.assertEqual((self.plane.ops(), listing(self.evidence)), (["sts get-caller-identity"], [COPY]))

    def signalled(self, name, signum):
        """Patches `hsc.name` until the test ends so that its first call sends `signum` to this process first."""
        step = getattr(hsc, name)

        def interrupted(*args):
            os.kill(os.getpid(), signum)
            return step(*args)
        return patched(hsc, name, interrupted)

    def test_a_signal_while_the_arguments_the_catalog_or_the_operator_file_are_read_ends_the_run_the_same_way(self):
        # A handler that stood before `main` hears each signal the controller leaves to it.
        left = []

        def hear(number, frame):
            left.append(number)
        for name in ("parser", "gd2_of", "read_operator"):
            for signum in hsc.SIGNALS:
                with self.subTest(name, signal=signum.name):
                    self.setUp()
                    left.clear()
                    for s in hsc.SIGNALS:
                        signal.signal(s, hear)
                    with self.signalled(name, signum):
                        self.assertEqual(self.run_controller(), 2, self.output)
                    self.assertIn(f"signal {signum.name} before any mark; nothing written", self.output)
                    self.assertEqual((left, self.plane.ops(), listing(self.evidence)), ([], [], [COPY]))
                    self.assertEqual([signal.getsignal(s) for s in hsc.SIGNALS], [hear] * len(hsc.SIGNALS))
        with self.subTest("a signal ignored at the start stays ignored while the operator file is read"):
            self.setUp()
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
            with self.signalled("read_operator", signal.SIGHUP):
                self.assertEqual(self.run_controller(), 0, self.output)
            self.assertEqual(signal.getsignal(signal.SIGHUP), signal.SIG_IGN)
        with self.subTest("a second signal while the first ends the run changes nothing"):
            self.setUp()
            left.clear()
            for s in hsc.SIGNALS:
                signal.signal(s, hear)
            say = hsc.say

            def again(text, err=False):
                os.kill(os.getpid(), signal.SIGTERM)
                say(text, err)
            with self.signalled("read_operator", signal.SIGINT), patched(hsc, "say", again):
                self.assertEqual(self.run_controller(), 2, self.output)
            self.assertIn("signal SIGINT before any mark; nothing written", self.output)
            self.assertEqual((left, self.plane.ops(), listing(self.evidence)), ([], [], [COPY]))
        with self.subTest("a signal while a refusal of the operator file is reported changes nothing"):
            self.setUp()
            left.clear()
            for s in hsc.SIGNALS:
                signal.signal(s, hear)
            self.operator["region"] = "nowhere"
            with patched(hsc, "say", again):
                self.assertEqual(self.run_controller(), 2, self.output)
            self.assertIn("refused: region 'nowhere' is no AWS region name; nothing written", self.output)
            self.assertEqual((left, self.plane.ops(), listing(self.evidence)), ([], [], [COPY]))

    def test_a_step_of_the_wall_clock_moves_no_bound(self):
        with self.subTest("forward, during the observation"):
            self.faulted(lambda: setattr(self.clock, "step", 1000.0))
            self.assertEqual(self.run_controller(), 0, self.output)
            shown = max(e["time"] for e in self.plane.log if e["op"] == STATUS)
            self.assertGreaterEqual(self.plane.log[-1]["time"], shown + OPERATOR["observe_seconds"])
        with self.subTest("backward, before the target reads stopped"):
            self.setUp()
            self.faulted(lambda: setattr(self.clock, "step", -1000.0), while_stopping=True)
            self.assertEqual(self.run_controller(), 1, self.output)
            self.assertEqual(sorted(self.marks()), ["abort", "roles", "stop"])
            self.assertEqual(self.marks()["abort"]["cause"], "stop-not-shown")
            sent = self.stops()[0]["start"]
            last = max(e["time"] for e in self.plane.log[:-1])
            self.assertLessEqual(last, sent + OPERATOR["effect_timeout_seconds"] + 1)

    def test_a_mark_is_synced_again_once_linked_and_a_failed_sync_removes_it(self):
        controller = hsc.Controller(OPERATOR, GD2, self.plane, self.clock, self.clock.sleep, self.clock.elapsed)
        controller.injection = self.evidence
        stop = {"instance": TARGET, "time": START, "identity": OPERATOR["identity"]}
        steps, fsync, link, sync = [], os.fsync, os.link, hsc.sync
        with patched(hsc.os, "fsync", lambda fd: (steps.append(("fsync", fd)), fsync(fd))[1]), \
                patched(hsc.os, "link", lambda *a, **k: (steps.append(("link",)), link(*a, **k))[1]), \
                patched(hsc, "sync", lambda fd: (steps.append(("sync", fd)), sync(fd))[1]):
            controller.mark("stop", stop)
        # `sync` of the directory runs os.fsync itself, so the last fsync is the directory's.
        self.assertEqual([step[0] for step in steps[-5:]], ["fsync", "link", "fsync", "sync", "fsync"])
        self.assertEqual(steps[-5][1], steps[-3][1], "the same file is synced before and after its link")
        (self.evidence / "stop.json").unlink()
        calls = []

        def failing(fd):
            calls.append(fd)
            if len(calls) == 2:
                raise OSError(5, "Input/output error")
            fsync(fd)
        with patched(hsc.os, "fsync", failing), self.assertRaises(hsc.Unwritten) as caught:
            controller.mark("stop", stop)
        self.assertFalse(caught.exception.stands)
        self.assertEqual(listing(self.evidence), [COPY])
        self.assertEqual(controller.written, ["stop"])
        calls.clear()

        def kept(*args, **kwargs):
            raise OSError(13, "Permission denied")
        with patched(hsc.os, "fsync", failing), patched(hsc.os, "unlink", kept), \
                self.assertRaises(hsc.Unwritten) as caught:
            controller.mark("stop", stop)
        self.assertTrue(caught.exception.stands, "a mark that cannot be removed stands and counts as written")
        self.assertEqual((listing(self.evidence), controller.written), ([COPY, "stop.json"], ["stop", "stop"]))

    def test_an_abort_mark_removed_after_a_failed_sync_leaves_no_stopped_mark(self):
        sync, failed = hsc.sync, []

        def failing(fd):
            if self.plane.log and self.plane.log[-1].get("fault") and len(failed) < 2:
                failed.append(fd)
                raise OSError(5, "Input/output error")
            sync(fd)
        self.patch(hsc, "sync", failing)
        self.faulted(lambda: self.plane.flip("gd2-guardrail-1", "ALARM"))
        self.assertEqual(self.run_controller(), 1, self.output)
        self.assertEqual(sorted(self.marks()), ["roles", "stop"])
        self.assertIn("the removal is unsynced", self.output)

    def test_a_deadline_reached_between_two_calls_aborts_before_the_next(self):
        # A late start leaves the observation's end past the deadline, so a pause ends at the deadline and the next
        # call's own check aborts the run.
        self.operator.update(effect_timeout_seconds=60, observe_seconds=200,
                             snapshot_max_age_seconds=hsc.LIMIT_SECONDS)
        self.plane.script["sts get-caller-identity"] = [50]
        self.plane.script[STATUS] = [30]
        self.plane.stop_after = 3
        found = self.assert_aborted("deadline", ["roles", "stop", "stopped", "abort"], detail="the deadline of")
        self.assertLess(max(e["start"] for e in self.plane.log[:-1]), self.plane.deadline)
        # A call asked for at the deadline aborts before it leaves.
        controller = hsc.Controller(OPERATOR, GD2, self.plane, self.clock, self.clock.sleep, self.clock.elapsed)
        controller.deadline, calls = self.clock.elapsed(), len(self.plane.log)
        with self.assertRaises(hsc.Aborted) as caught:
            controller.alarms()
        self.assertEqual((caught.exception.cause, len(self.plane.log)), ("deadline", calls))
        self.assertIn("the stop request was sent and answered", found["abort"]["detail"])

    def test_a_stop_call_cut_at_the_deadline_keeps_its_failure(self):
        self.operator.update(effect_timeout_seconds=60, observe_seconds=10, deadline_seconds=70)
        self.plane.script["sts get-caller-identity"] = [45]
        self.plane.script[STOP] = ["stall"]
        found = self.assert_aborted("deadline", ["roles", "stop", "abort"], detail="timed out")
        self.assertIn("a stop request may have left and its outcome is unknown", found["abort"]["detail"])
        self.assertTrue(self.stops()[0].get("cut"))

    def test_a_mark_is_written_once_and_leaves_no_other_file(self):
        controller = hsc.Controller(OPERATOR, GD2, self.plane, self.clock, self.clock.sleep, self.clock.elapsed)
        controller.injection = self.evidence
        with self.assertRaises(hsc.Refusal):
            controller.mark("stop", {"instance": TARGET, "time": START})
        self.assertEqual((listing(self.evidence), controller.written), ([COPY], []))
        stop, write = {"instance": TARGET, "time": START, "identity": OPERATOR["identity"]}, os.write
        with patched(hsc.os, "write", lambda fd, data: write(fd, bytes(data[:7]))):
            controller.mark("stop", stop)
        self.assertEqual(parse(self.evidence / "stop.json"), stop, "short writes leave the mark whole")
        with patched(hsc.os, "write", lambda fd, data: 0), bounded(5), self.assertRaises(OSError) as stuck:
            controller.mark("abort", {"cause": "exception", "guardrail": None, "time": START, "detail": "x"})
        self.assertIn("made no progress", str(stuck.exception))
        self.assertEqual((listing(self.evidence), controller.written), ([COPY, "stop.json"], ["stop"]))
        first = (self.evidence / "stop.json").read_bytes()
        with self.assertRaises(FileExistsError):
            controller.mark("stop", {"instance": TARGET, "time": START + 1, "identity": OPERATOR["identity"]})
        self.assertEqual((self.evidence / "stop.json").read_bytes(), first)
        self.assertEqual(listing(self.evidence), [COPY, "stop.json"])
        self.assertEqual(controller.written, ["stop"])


class Restore(Case):
    def aborted_run(self):
        """A run whose stop is never shown, the target started again, and the review of its abort: (path, review)."""
        self.plane.stop_after = None
        self.assertEqual(self.run_controller(), 1, self.output)
        self.start_target(initializing=0)
        return self.tmp / "reviewed.json", self.review()

    def assert_restore_refused(self, reviewed=None, reason="refused: "):
        start, before, seen = len(self.plane.log), listing(self.evidence), len(self.output)
        self.assertEqual(self.restore(reviewed), 2, self.output)
        self.assertIn(reason, self.output[seen:])
        self.assertEqual(self.plane.ops(start), [])
        self.assertEqual(listing(self.evidence), before)

    def test_restore_writes_restoration_once_the_target_runs_with_both_checks_ok(self):
        self.assertEqual(self.run_controller(), 0, self.output)
        # The target reads ready on the last status read that starts within the deadline.
        period = hsc.POLL_SECONDS + self.plane.call_seconds
        last = int(OPERATOR["deadline_seconds"] // period)
        self.start_target(initializing=last)
        launched, start = self.clock.t, len(self.plane.log)
        self.assertEqual(self.restore(), 0, self.output)
        marks = self.marks()
        self.assertEqual({k: v for k, v in marks["restoration"].items() if k != "time"},
                         {"instance": TARGET, "state": "running", "reviewed_sha256": None})
        # The record is read once, after the status read that shows the target ready.
        self.assertEqual(self.plane.ops(start), ["sts get-caller-identity"] + [STATUS] * (last + 1) + [RECORD])
        self.assertGreater(self.plane.log[-2]["start"] + period, self.plane.log[start + 1]["start"]
                           + OPERATOR["deadline_seconds"], "a read one period later starts past the deadline")
        self.assertAlmostEqual(marks["restoration"]["time"], launched - hsc.SKEW_SECONDS, places=6,
                               msg="the record's launch time less the skew")
        self.assertGreater(marks["restoration"]["time"], marks["stopped"]["time"])
        self.assertLess(marks["restoration"]["time"], self.plane.log[start]["start"], "before restore's start")
        self.assert_restore_refused(reason="restoration.json exists")

    def test_a_start_at_the_bound_a_run_prints_ends_no_observation_under_a_clock_error(self):
        # The plane's clock reads the skew behind the controller's, and its record names the launch's whole second.
        self.repackage(lambda p: p.update(clock_error_seconds=2))
        package = parse(self.package)
        self.assertEqual(self.run_controller(), 0, self.output)
        bounds = re.findall(r"A start before (\S+) may end the judge's observation", self.output)
        self.assertEqual(len(bounds), 1, self.output)
        late = float(bounds[0])
        self.clock.advance(late - self.clock.t)
        self.start_target(initializing=0)
        self.plane.instances[TARGET]["launched"] = (self.clock.t - hsc.SKEW_SECONDS) // 1
        self.assertEqual(self.restore(), 0, self.output)
        restoration = self.marks()["restoration"]
        self.assertEqual(restoration["time"], late - 2 * hsc.SKEW_SECONDS)
        self.assertFalse(gj.ends_observation(package, restoration), restoration)
        # The bound is the least the judge's rule admits: a restoration dated one second before the earliest time a
        # start at the bound is dated ends observation.
        self.assertEqual(late, package["run"]["end"] + 2 * hsc.SKEW_SECONDS + 1 + package["clock_error_seconds"])
        earliest = late - 2 * hsc.SKEW_SECONDS - 1
        self.assertFalse(gj.ends_observation(package, {"time": earliest}))
        self.assertTrue(gj.ends_observation(package, {"time": earliest - 1}))

    def test_the_restoration_is_dated_by_the_targets_launch_between_the_marks_and_the_ready_read(self):
        skew, step = hsc.SKEW_SECONDS, 0.25
        # (the launch the record names from the stopped report's time and the first ready read's, the restoration's
        # time or None for none written, the record reads made)
        cases = {
            "a launch after the marks": (lambda stopped, ready: stopped + 20, lambda s, r: s + 20 - skew, 1),
            "a launch the skew before the stopped report": (lambda s, r: s - skew, lambda s, r: s, 1),
            "a launch more than the skew before the stopped report": (lambda s, r: s - skew - step, None, None),
            "a launch the skew after the ready read": (lambda s, r: r + skew, lambda s, r: r, 1),
            "a launch more than the skew after the ready read": (lambda s, r: r + skew + step,
                                                               lambda s, r: r + step, 2)}
        for name, (launched, dated, records) in cases.items():
            with self.subTest(name):
                self.setUp()
                # Every call takes a binary fraction of a second, so each time below is exact.
                self.plane.call_seconds = step
                self.assertEqual(self.run_controller(), 0, self.output)
                self.start_target(initializing=0)
                stopped, ready = self.marks()["stopped"]["time"], self.clock.t + 2 * step
                self.assertEqual(self.floor(), stopped)
                self.plane.instances[TARGET]["launched"] = launched(stopped, ready)
                start = len(self.plane.log)
                # Bounds short enough that a restoration never shown ends within a few reads.
                self.operator.update(effect_timeout_seconds=hsc.POLL_SECONDS, observe_seconds=hsc.POLL_SECONDS,
                                     deadline_seconds=3 * hsc.POLL_SECONDS)
                if dated is None:
                    self.assertEqual(self.restore(), 1, self.output)
                    self.assertNotIn("restoration", self.marks())
                    self.assertIn("before the stopped report", self.output)
                    self.assertIn("the evidence is not to be judged as it stands", self.output)
                    self.assertEqual(self.plane.ops(start)[-1], RECORD)
                else:
                    self.assertEqual(self.restore(), 0, self.output)
                    self.assertEqual(self.marks()["restoration"]["time"], dated(stopped, ready))
                    self.assertEqual(self.plane.ops(start), ["sts get-caller-identity"] + [STATUS, RECORD] * records)
                self.assertFalse(CHANGES & set(self.plane.ops(start)))

    def test_a_record_that_shows_no_usable_launch_leaves_the_restoration_unshown(self):
        def launch(value):
            def shape(reply):
                row = reply["Reservations"][0]["Instances"][0]
                if value is None:
                    del row["LaunchTime"]
                else:
                    row["LaunchTime"] = value
                return reply
            return shape

        def pending(reply):
            reply["Reservations"][0]["Instances"][0]["State"] = {"Code": 0, "Name": "pending"}
            return reply
        self.assertEqual(self.run_controller(), 0, self.output)
        # Bounds short enough that each poll ends unshown within a few reads.
        self.operator.update(effect_timeout_seconds=hsc.POLL_SECONDS, observe_seconds=hsc.POLL_SECONDS,
                             deadline_seconds=3 * hsc.POLL_SECONDS)
        # A time the record could name for this start, so each case fails on its form alone.
        now, form = launch_text(int(self.clock.t), zone=""), "is no UTC time"
        self.assertEqual(hsc.launch_time(now + "Z"), int(self.clock.t))
        for name, (shape, reason) in {
                "no launch time": (launch(None), form), "a launch time that is no text": (launch(104), "is no str"),
                "another offset": (launch(now + "+01:00"), form), "no zone": (launch(now), form),
                "a zone in small letters": (launch(now + "z"), form), "a space for the T": (launch(
                    now.replace("T", " ") + "Z"), form), "seconds of 60": (launch(now[:-2] + "60Z"), form),
                "a fraction of ten digits": (launch(now + ".0000000000Z"), form),
                "text after the zone": (launch(now + "Z "), form), "a date alone": (launch(now[:10]), form),
                "a day no month holds": (launch("1970-02-30T00:00:00Z"), "is no calendar time"),
                "a record of a target not yet running": (pending, "record reads pending"),
                "a partial listing": (lambda reply: {**reply, "NextToken": "more"}, "NextToken")}.items():
            with self.subTest(name):
                self.start_target(initializing=0)
                self.plane.shapes[RECORD] = [shape] * 200
                seen, start = len(self.output), len(self.plane.log)
                self.assertEqual(self.restore(), 1, self.output[seen:])
                self.assertIn(reason, self.output[seen:])
                self.assertIn("the evidence is not to be judged as it stands", self.output[seen:])
                self.assertNotIn("restoration", self.marks())
                self.assertGreater(self.plane.ops(start).count(RECORD), 1, "the poll goes on to its deadline")
        with self.subTest("a record read that fails"):
            self.plane.shapes[RECORD] = []
            self.start_target(initializing=0)
            self.plane.script[RECORD] = ["lose"] * 200
            self.assertEqual(self.restore(), 1, self.output)
            self.assertNotIn("restoration", self.marks())
        self.plane.script[RECORD] = []
        self.start_target(initializing=0)
        self.assertEqual(self.restore(), 0, self.output)
        self.assertIn("restoration", self.marks())

    def test_a_launch_time_reads_in_both_utc_forms_with_or_without_a_fraction(self):
        for text, seconds in {"2026-11-24T00:00:10+00:00": 10, "2026-11-24T00:00:10Z": 10,
                              "2026-11-24T00:00:10.250+00:00": 10.25, "2026-11-24T00:00:10.250Z": 10.25}.items():
            with self.subTest(text):
                self.assertEqual(hsc.launch_time(text) - hsc.launch_time("2026-11-24T00:00:00Z"), seconds)
        self.assertEqual(hsc.launch_time("1970-01-01T00:01:44Z"), START)

    def test_a_record_read_that_runs_to_the_deadline_is_cut_there_and_writes_no_restoration(self):
        self.assertEqual(self.run_controller(), 0, self.output)
        period = hsc.POLL_SECONDS + self.plane.call_seconds
        self.start_target(initializing=int(OPERATOR["deadline_seconds"] // period))
        self.plane.script[RECORD] = [hsc.CALL_SECONDS]
        start = len(self.plane.log)
        self.assertEqual(self.restore(), 1, self.output)
        self.assertEqual(self.plane.ops(start)[-2:], [STATUS, RECORD])
        record = self.plane.log[-1]
        self.assertTrue(record.get("cut"), record)
        self.assertAlmostEqual(record["time"], self.plane.log[start + 1]["start"] + OPERATOR["deadline_seconds"])
        self.assertNotIn("restoration", self.marks())

    def test_restore_is_refused_without_a_stop_mark(self):
        self.assert_restore_refused(reason="no stop to restore from")
        self.assertEqual(listing(self.evidence), [COPY])
        self.snapshot("shards.jsonl", lambda rows: rows[3].update(standby="h3"))
        self.assertEqual(self.run_controller(), 1)
        self.assert_restore_refused(reason="injection/stop.json cannot be read")

    def test_after_an_abort_restore_needs_the_reviewed_record_of_that_abort(self):
        path, review = self.aborted_run()
        self.assert_restore_refused(reason="an abort stands: restore needs --reviewed")
        for name, (change, reason) in {
                "another abort": ({"abort_sha256": "0" * 64}, "names another abort"),
                "other steps": ({"steps": "restart it"}, "steps other than"),
                "an extra key": ({"note": "x"}, "refused: "),
                "a review dated before the abort": ({"time": self.marks()["abort"]["time"] - 1}, "before the abort"),
                "a review dated after restore's start": ({"time": self.clock() + 1}, "after restore's start")}.items():
            with self.subTest(name):
                path.write_text(json.dumps({**review, **change}), encoding="utf-8")
                self.assert_restore_refused(path, reason)
        with self.subTest("a repeated key"):
            path.write_text(repeated(json.dumps(review), "reviewer", "another"), encoding="utf-8")
            self.assert_restore_refused(path, "repeats a key")
        with self.subTest("a review kept inside DIR"):
            inside = self.evidence / "reviewed.json"
            inside.write_text(json.dumps(review), encoding="utf-8")
            self.assert_restore_refused(inside, "inside the evidence directory")
            inside.unlink()
        with self.subTest("a named pipe"):
            pipe = self.tmp / "pipe.json"
            os.mkfifo(pipe)
            with bounded(5):
                self.assert_restore_refused(pipe, "no regular file")
        with self.subTest("a review dated at the time of an abort dated at the stop's time is admitted"):
            injection = self.evidence / "injection"
            at = self.marks()["abort"]["time"]
            path.write_text(json.dumps({**review, "time": at}), encoding="utf-8")
            found = hsc.check_reviewed(path, injection / "abort.json", self.evidence, self.clock(),
                                       {**parse(injection / "stop.json"), "time": at})
            self.assertEqual(found, (hashlib.sha256(path.read_bytes()).hexdigest(), at))
        path.write_text(json.dumps(review), encoding="utf-8")
        self.assertEqual(self.restore(path), 0, self.output)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertIn(digest, self.output)
        self.assertEqual((self.marks()["restoration"]["instance"], self.marks()["restoration"]["reviewed_sha256"]),
                         (TARGET, digest))

    def test_after_an_abort_with_no_stop_shown_an_older_launch_dates_the_restoration_at_the_abort(self):
        path, review = self.aborted_run()
        path.write_text(json.dumps(review), encoding="utf-8")
        target = self.plane.instances[TARGET]
        target["launched"] = 0.0

        def unnamed(reply):
            del reply["Reservations"][0]["Instances"][0]["LaunchTime"]
            return reply
        self.plane.shapes[RECORD] = [unnamed] * 200
        self.assertEqual(self.restore(path), 1, self.output)
        self.assertNotIn("restoration", self.marks())
        self.plane.shapes[RECORD] = []
        self.assertEqual(self.restore(path), 0, self.output)
        marks = self.marks()
        self.assertNotIn("stopped", marks)
        self.assertEqual((marks["restoration"]["time"], marks["restoration"]["reviewed_sha256"]),
                         (marks["abort"]["time"], hashlib.sha256(path.read_bytes()).hexdigest()))

    def test_restore_refuses_an_abort_mark_the_judge_refuses(self):
        path, review = self.aborted_run()
        abort_path = self.evidence / "injection" / "abort.json"
        abort = parse(abort_path)
        self.assertEqual((abort["cause"], abort["guardrail"]), ("stop-not-shown", None))
        for name, change in {"cause guardrail with no guardrail": {"cause": "guardrail"},
                             "a guardrail with another cause": {"guardrail": TEXTS[0]}}.items():
            with self.subTest(name):
                abort_path.unlink()
                abort_path.write_text(json.dumps({**abort, **change}), encoding="utf-8")
                path.write_text(json.dumps({**review, "abort_sha256": hashlib.sha256(
                    abort_path.read_bytes()).hexdigest()}), encoding="utf-8")
                self.assert_restore_refused(path, "names a guardrail without cause guardrail")

    def test_a_review_names_the_steps_the_aborted_run_printed_whatever_the_catalog_holds_at_restore(self):
        path, review = self.aborted_run()
        later = copy.deepcopy(MET)
        next(e for e in later["entries"] if e["id"] == "GD-2")["restoration"]["steps"] = "start the instance"
        changed = self.tmp / "gamedays.json"
        changed.write_text(json.dumps(later), encoding="utf-8")
        self.patch(gj, "CATALOG", changed)
        path.write_text(json.dumps({**review, "steps": "start the instance"}), encoding="utf-8")
        self.assert_restore_refused(path, "steps other than those the aborted run printed")
        path.write_text(json.dumps(review), encoding="utf-8")
        self.assertEqual(self.restore(path), 0, self.output)
        self.assertEqual(self.marks()["restoration"]["reviewed_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_restore_refuses_an_abort_mark_whose_detail_does_not_end_with_its_runs_steps_digest(self):
        path, review = self.aborted_run()
        abort_path = self.evidence / "injection" / "abort.json"
        abort = parse(abort_path)
        self.assertTrue(abort["detail"].endswith(STEPS_TAIL), abort["detail"])
        other = "; restoration steps sha256 " + hashlib.sha256(b"start the instance").hexdigest()
        unpinned = "does not end with the digest of the restoration steps"
        others = "steps other than those the aborted run printed"
        for name, (detail, reason) in {
                "no detail": (None, unpinned),
                "a detail without the digest": (abort["detail"][:-len(STEPS_TAIL)], unpinned),
                "the digest before the detail's end": (abort["detail"] + " and more", unpinned),
                "a digest cut short": (abort["detail"][:-1], unpinned),
                "a digest in capitals": (abort["detail"][:-64] + abort["detail"][-64:].upper(), unpinned),
                "the digest of other steps": (abort["detail"][:-len(STEPS_TAIL)] + other, others),
                "the digest of other steps after the run's": (abort["detail"] + other, others)}.items():
            with self.subTest(name):
                abort_path.unlink()
                abort_path.write_text(json.dumps({**abort, "detail": detail}), encoding="utf-8")
                path.write_text(json.dumps({**review, "abort_sha256": hashlib.sha256(
                    abort_path.read_bytes()).hexdigest()}), encoding="utf-8")
                self.assert_restore_refused(path, reason)

    def test_restore_waits_for_the_system_check_as_well_as_the_instance_check(self):
        self.assertEqual(self.run_controller(), 0)
        self.plane.instances[TARGET].update(state="running", checks="ok", system="impaired")
        self.plane.stopping = None
        self.assertEqual(self.restore(), 1, self.output)
        self.assertNotIn("restoration", self.marks())

    def test_restore_refuses_an_unrecorded_end_and_an_undeclared_instance(self):
        (self.evidence / "injection").mkdir()
        stop = {"instance": TARGET, "time": START + 1, "identity": OPERATOR["identity"]}
        (self.evidence / "injection" / "stop.json").write_text(json.dumps({**stop, "note": "x"}), encoding="utf-8")
        self.assert_restore_refused(reason="injection/stop.json holds the keys")
        (self.evidence / "injection" / "stop.json").write_text(json.dumps(stop), encoding="utf-8")
        self.assert_restore_refused(reason="neither stopped.json nor abort.json")
        (self.evidence / "injection" / "stopped.json").write_text("{}", encoding="utf-8")
        self.operator["instances"].remove(TARGET)
        self.assert_restore_refused(reason="outside the declared set")

    def test_restore_refuses_a_stopped_mark_that_does_not_show_the_stop(self):
        self.assertEqual(self.run_controller(), 0, self.output)
        self.start_target(initializing=0)
        path = self.evidence / "injection" / "stopped.json"
        stopped = parse(path)
        at_the_request = self.tmp / "stopped.json"
        at_the_request.write_text(json.dumps({**stopped, "time": stopped["request"]["time"]}), encoding="utf-8")
        self.assertEqual(hsc.check_stopped(at_the_request, stopped["request"], stopped["request"]["time"]),
                         stopped["request"]["time"], "a read at the request's time, which is restore's start")
        no_stop = "shows no stop of injection/stop.json's request"
        for name, (change, reason) in {
                "a malformed mark": (None, "refused: "),
                "a report of another request": ({"request": {**stopped["request"], "time": START}}, no_stop),
                "a report of another state": ({"state": "stopping"}, no_stop),
                "a report of another instance": ({"instance": "i-h2"}, no_stop),
                "a report read before the request": ({"time": stopped["request"]["time"] - 1}, no_stop),
                "a report read after restore's start": ({"time": self.clock() + 1}, "after restore's start")}.items():
            with self.subTest(name):
                path.unlink()
                path.write_text(json.dumps({} if change is None else {**stopped, **change}), encoding="utf-8")
                self.assert_restore_refused(reason=reason)

    def test_restore_refuses_an_abort_before_the_stop_and_a_package_or_caller_other_than_the_approvals(self):
        path, review = self.aborted_run()
        injection = self.evidence / "injection"
        with self.subTest("an abort dated before the stop"):
            abort = parse(injection / "abort.json")
            (injection / "abort.json").unlink()
            (injection / "abort.json").write_text(json.dumps({**abort, "time": START}), encoding="utf-8")
            path.write_text(json.dumps({**review, "abort_sha256": hashlib.sha256(
                (injection / "abort.json").read_bytes()).hexdigest()}), encoding="utf-8")
            self.assert_restore_refused(path, "dated before the stop it would close")
        with self.subTest("roles of another package"):
            self.operator["approval"]["package_sha256"] = "0" * 64
            self.assert_restore_refused(path, "another package than the approval's")
        with self.subTest("another caller"):
            self.setUp()
            self.assertEqual(self.run_controller(), 0, self.output)
            self.start_target(initializing=0)
            self.plane.arn = "arn:aws:sts::account:assumed-role/another-role/gd2-run"
            self.assertEqual(self.restore(), 2, self.output)
            self.assertEqual(self.plane.ops()[-1], "sts get-caller-identity")
            self.assertNotIn("restoration", self.marks())

    def test_restore_after_an_abort_checks_a_stopped_mark_that_stands(self):
        self.faulted(lambda: self.plane.flip("gd2-guardrail-1", "ALARM"))
        self.assertEqual(self.run_controller(), 1, self.output)
        self.start_target(initializing=0)
        injection = self.evidence / "injection"
        self.assert_restore_refused(reason="an abort stands: restore needs --reviewed")
        (injection / "stopped.json").unlink()
        (injection / "stopped.json").write_text("{}", encoding="utf-8")
        path = self.tmp / "reviewed.json"
        path.write_text(json.dumps(self.review()), encoding="utf-8")
        self.assert_restore_refused(path)

    def test_a_restoration_reaches_a_stopped_report_dated_after_the_abort_mark(self):
        # Every call takes a binary fraction of a second, so each time below is exact.
        self.plane.call_seconds = 0.25
        self.faulted(lambda: self.plane.flip("gd2-guardrail-1", "ALARM"))
        self.assertEqual(self.run_controller(), 1, self.output)
        injection, marks = self.evidence / "injection", self.marks()
        self.assertLess(marks["stop"]["time"], marks["stopped"]["time"])
        # An abort mark dated at the stop request, before the stopped report, and a launch dated the skew before
        # that report, the earliest one a start after the stop admits.
        (injection / "abort.json").unlink()
        (injection / "abort.json").write_text(json.dumps({**marks["abort"], "time": marks["stop"]["time"]}),
                                              encoding="utf-8")
        self.start_target(initializing=0)
        self.plane.instances[TARGET]["launched"] = marks["stopped"]["time"] - hsc.SKEW_SECONDS
        path = self.tmp / "reviewed.json"
        path.write_text(json.dumps(self.review()), encoding="utf-8")
        self.assertEqual(self.restore(path), 0, self.output)
        self.assertEqual(self.marks()["restoration"]["time"], marks["stopped"]["time"])

    def test_restore_refuses_a_stop_mark_of_another_instance_or_identity_than_the_approvals(self):
        for key, other in (("instance", "i-h2"), ("identity", OPERATOR["identity"] + "-2")):
            with self.subTest(key):
                self.setUp()
                self.assertEqual(self.run_controller(), 0, self.output)
                injection = self.evidence / "injection"
                stop = {**parse(injection / "stop.json"), key: other}
                stopped = {**parse(injection / "stopped.json"), "instance": stop["instance"], "request": stop}
                for name, value in (("stop", stop), ("stopped", stopped)):
                    (injection / f"{name}.json").unlink()
                    (injection / f"{name}.json").write_text(json.dumps(value), encoding="utf-8")
                self.assert_restore_refused(reason="another instance or identity than the approval's")

    def test_restore_refuses_a_linked_evidence_root_or_injection_directory(self):
        self.assertEqual(self.run_controller(), 0, self.output)
        self.start_target(initializing=0)
        real = self.tmp / "real"
        try:
            self.evidence.rename(real)
        except OSError as error:
            self.fail(f"the evidence directory cannot be moved aside: {error}")
        before = listing(real)
        for name in ("root", "injection"):
            with self.subTest(name):
                if self.evidence.is_symlink():
                    self.evidence.unlink()
                if name == "root":
                    self.evidence.symlink_to(real)
                else:
                    self.evidence.mkdir()
                    (self.evidence / "injection").symlink_to(real / "injection")
                start, seen = len(self.plane.log), len(self.output)
                self.assertEqual(self.restore(), 2, self.output)
                self.assertIn("is no directory", self.output[seen:])
                self.assertEqual((self.plane.ops(start), listing(real)), ([], before))

    def test_a_signal_during_the_restoration_write_keeps_its_exit_0(self):
        self.assertEqual(self.run_controller(), 0)
        self.start_target(initializing=0)
        write = hsc.publish

        def interrupted_write(path, data):
            if path.name == "restoration.json":
                os.kill(os.getpid(), signal.SIGTERM)
            write(path, data)
        self.patch(hsc, "publish", interrupted_write)
        self.assertEqual(self.restore(), 0, self.output)
        self.assertIn("restoration", self.marks())

    def test_a_signal_before_or_during_the_poll_ends_restore_with_exit_1_and_no_mark(self):
        for name, (op, signum) in {"during the caller's read": ("sts get-caller-identity", signal.SIGTERM),
                                   "during a status read": (STATUS, signal.SIGHUP),
                                   "during the record read": (RECORD, signal.SIGINT)}.items():
            with self.subTest(name):
                self.setUp()
                self.assertEqual(self.run_controller(), 0)
                self.start_target(initializing=3)
                self.plane.fault = lambda o, op=op, signum=signum: (
                    lambda: os.kill(os.getpid(), signum)) if o == op else None
                self.assertEqual(self.restore(), 1, self.output)
                self.assertIn(f"signal {signal.Signals(signum).name}: the restoration is unwritten", self.output)
                self.assertEqual(self.after_fault(), [])
                self.assertNotIn("restoration", self.marks())

    def test_a_signal_during_restores_checks_ends_it_before_any_call(self):
        # `main` reads the arguments, the catalog and the operator file under the controller's handler, so a handler
        # that stood before `main` hears no signal of those reads either.
        left = []
        for name in ("parser", "gd2_of", "read_operator", "check_stopped"):
            with self.subTest(name):
                self.setUp()
                self.assertEqual(self.run_controller(), 0)
                self.start_target(initializing=0)
                signal.signal(signal.SIGTERM, lambda number, frame: left.append(number))
                step = getattr(hsc, name)

                def interrupted(*args, step=step):
                    os.kill(os.getpid(), signal.SIGTERM)
                    return step(*args)
                start = len(self.plane.log)
                with patched(hsc, name, interrupted):
                    self.assertEqual(self.restore(), 1, self.output)
                self.assertIn("signal SIGTERM: the restoration is unwritten", self.output)
                self.assertEqual((left, self.plane.ops(start)), ([], []))
                self.assertNotIn("restoration", self.marks())

    def test_a_restoration_whose_directory_sync_fails_is_removed_and_can_run_again(self):
        self.assertEqual(self.run_controller(), 0)
        self.start_target(initializing=0)
        sync, failed = hsc.sync, []

        def failing(directory):
            if not failed:
                failed.append(directory)
                raise OSError(5, "Input/output error")
            sync(directory)
        self.patch(hsc, "sync", failing)
        self.assertEqual(self.restore(), 1, self.output)
        self.assertIn("so the mark is removed", self.output)
        self.assertNotIn("restoration", self.marks())
        self.start_target(initializing=0)
        self.assertEqual(self.restore(), 0, self.output)
        self.assertIn("restoration", self.marks())

    def test_a_restoration_that_fails_before_its_link_is_unwritten_with_exit_1_and_can_run_again(self):
        self.assertEqual(self.run_controller(), 0)

        def unnamed(*args):
            return args[0] == "." and args[1] & os.O_TMPFILE == os.O_TMPFILE
        full, lost = OSError(errno.ENOSPC, "No space left on device"), OSError(errno.EIO, "Input/output error")
        for name, (step, when, error) in {"its unnamed file cannot be made": ("open", unnamed, full),
                                          "its write fails": ("write", lambda *args: True, full),
                                          "its sync before the link fails": ("fsync", lambda *args: True, lost)
                                          }.items():
            with self.subTest(name):
                self.start_target(initializing=0)
                seen = len(self.output)
                with failing_once(hsc.os, step, when, error):
                    self.assertEqual(self.restore(), 1, self.output)
                self.assertIn(f"restoration.json is unwritten: {error}", self.output[seen:])
                self.assertNotIn("restoration", self.marks())
        self.start_target(initializing=0)
        self.assertEqual(self.restore(), 0, self.output)
        self.assertIn("restoration", self.marks())

    def test_a_review_with_no_abort_is_refused(self):
        self.assertEqual(self.run_controller(), 0)
        path = self.tmp / "reviewed.json"
        path.write_text("{}", encoding="utf-8")
        self.assert_restore_refused(path, "no abort stands")

    def test_a_target_never_shown_ready_ends_restore_with_exit_1_and_no_mark(self):
        self.assertEqual(self.run_controller(), 0)
        self.plane.instances[TARGET].update(state="running", checks="impaired")
        self.plane.stopping = None

        def stopping(reply):
            return {"InstanceStatuses": [{**row, "InstanceState": {"Code": 64, "Name": "stopping"},
                                          "InstanceStatus": {"Status": "ok"}, "SystemStatus": {"Status": "ok"}}
                                         for row in reply["InstanceStatuses"]]}
        # Restoration requires a single status read that shows the target running with both checks ok.
        self.plane.script[STATUS] = ["lose"]
        self.plane.shapes[STATUS] = [stopping if n % 2 else (lambda reply: reply) for n in range(200)]
        begin = self.clock.t
        self.assertEqual(self.restore(), 1, self.output)
        self.assertNotIn("restoration", self.marks())
        self.assertLessEqual(self.clock.t, begin + OPERATOR["deadline_seconds"] + 1)
        self.assertIn("the target reads {'state': 'stopping', 'instance': 'ok', 'system': 'ok'}", self.output)

    def test_a_ready_read_dated_before_restores_start_writes_no_restoration(self):
        # Restore writes restoration.json only when the ready read is dated at or after restore's start.
        self.assertEqual(self.run_controller(), 0, self.output)
        self.start_target(initializing=0)
        # Bounds short enough that the poll ends unready within two reads.
        self.operator.update(effect_timeout_seconds=hsc.POLL_SECONDS, observe_seconds=hsc.POLL_SECONDS,
                             deadline_seconds=2 * hsc.POLL_SECONDS)

        def step_back():
            self.clock.step -= 3600
        self.plane.fault = lambda op: step_back if op == "sts get-caller-identity" else None
        start = len(self.plane.log)
        self.assertEqual(self.restore(), 1, self.output)
        self.assertEqual(self.plane.ops(start), ["sts get-caller-identity"] + [STATUS] * 2)
        self.assertNotIn("restoration", self.marks())
        self.assertIn("before restore's start", self.output)
        self.clock.step = 0
        self.start_target(initializing=0)
        self.assertEqual(self.restore(), 0, self.output)
        marks = self.marks()
        self.assertGreaterEqual(marks["restoration"]["time"], marks["stopped"]["time"])

    def test_restore_refuses_a_mark_whose_lookup_fails(self):
        # Restore refuses on a mark's lookup error: a failed abort.json lookup can hide an abort that requires the
        # operator's reviewed record.
        self.faulted(lambda: self.plane.flip("gd2-guardrail-1", "ALARM"))
        self.assertEqual(self.run_controller(), 1, self.output)
        self.start_target(initializing=0)
        self.assertEqual(sorted(self.marks()), ["abort", "roles", "stop", "stopped"])
        lstat = os.lstat
        for name in ("restoration", "stopped", "abort"):
            with self.subTest(name):
                def failing(path, *args, name=name, **kwargs):
                    if os.fspath(path).endswith(f"{name}.json"):
                        raise OSError(errno.EIO, "Input/output error")
                    return lstat(path, *args, **kwargs)
                with patched(os, "lstat", failing):
                    self.assert_restore_refused(reason=f"injection/{name}.json cannot be looked up")


class Judged(Case):
    """The marks the controller wrote stand in place of the held fixture's `injection/` in a copy of it, `seal` seals
    the copy, and the judge of scripts/gameday-judge.py reads the copy as the verdict table states. A seal refusal
    writes no mark and makes no call."""

    @classmethod
    def setUpClass(cls):
        cls.readiness = hsc.readiness

    def judge(self, records=None, versions=None):
        """The (run_status, verdict) of the copy, sealed by the controller once the run window has ended; `records`
        {shard: change} applies the store's history the snapshot was read from to the copy's first version of each
        named shard, and `versions` {shard: [version]} adds versions to its history in commit order."""
        root = self.copy(records, versions)
        self.clock.advance(max(0.0, parse(self.package)["run"]["end"] + 30 - self.clock.t))
        self.assertEqual(self.seal(root), 0, self.output)
        record = self.tmp / "record.json"
        with contextlib.redirect_stdout(io.StringIO()):
            gj.run(str(root), str(record), CATALOG, FIS, self.readiness)
        found = parse(record)
        return found["run_status"], found["verdict"]

    def seal(self, root):
        return self.main(["seal", "--operator", str(self.write_operator()), "--evidence", str(root)])

    def copy(self, records=None, versions=None):
        """The held fixture's collections with the controller's marks, unsealed, as `judge` states."""
        root = self.tmp / "judged"
        shutil.copytree(HELD, root, ignore=shutil.ignore_patterns("injection"))
        shutil.copytree(self.evidence / "injection", root / "injection")
        for shard in {*(records or {}), *(versions or {})}:
            path = root / "records" / f"{shard}.jsonl"
            rows = [gj.decode(line, shard) for line in path.read_text(encoding="utf-8").splitlines()]
            rows[0].update((records or {}).get(shard, {}))
            rows = sorted(rows + (versions or {}).get(shard, []), key=lambda r: r["time"])
            path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
            # The collector's coverage of the file counts its lines, so a version added to it is counted there.
            coverage = parse(root / "coverage.json")
            coverage[f"records/{shard}.jsonl"]["lines"] = len(rows)
            (root / "coverage.json").write_text(json.dumps(coverage, indent=1) + "\n", encoding="utf-8")
        return root

    def restore_after_the_run_window(self, initializing=0):
        """The operator's start and the restore once the run window has ended, as the held fixture's restoration
        stands, so the judge observes the whole window."""
        self.clock.advance(max(0.0, parse(self.package)["run"]["end"] + 20 - self.clock.t))
        self.start_target(initializing)
        self.assertEqual(self.restore(), 0, self.output)
        self.assertGreater(self.marks()["restoration"]["time"], parse(self.package)["run"]["end"])

    def test_a_clean_run_and_its_restoration_keep_the_fixture_held(self):
        self.assertEqual(self.run_controller(), 0, self.output)
        self.restore_after_the_run_window(initializing=1)
        self.assertEqual(self.judge(), ("COMPLETED", "HELD"))

    def test_a_target_started_inside_the_run_window_and_restored_after_it_leaves_the_run_inconclusive(self):
        # The restoration is dated by the target's launch, whenever `restore` runs and reads it ready.
        end = parse(self.package)["run"]["end"]
        self.assertEqual(self.run_controller(), 0, self.output)
        self.start_target(initializing=1)
        started = self.clock.t
        self.assertLess(started, end)
        self.clock.advance(end + 20 - self.clock.t)
        self.assertEqual(self.restore(), 0, self.output)
        self.assertAlmostEqual(self.marks()["restoration"]["time"], started - hsc.SKEW_SECONDS, places=6)
        self.assertEqual(self.judge(), ("COMPLETED", "INCONCLUSIVE"))

    def test_a_launch_the_skew_admits_inside_the_run_window_ends_observation_there(self):
        # The control plane's clock may read the skew ahead of the controller's, so a launch it dates less than the
        # skew after the run window's end may lie inside the window.
        end = parse(self.package)["run"]["end"]
        for launched, verdict in ((end + hsc.SKEW_SECONDS - 1, "INCONCLUSIVE"), (end + hsc.SKEW_SECONDS, "HELD")):
            with self.subTest(launched=launched):
                self.setUp()
                self.assertEqual(self.run_controller(), 0, self.output)
                self.clock.advance(end + 20 - self.clock.t)
                self.start_target(initializing=0)
                self.plane.instances[TARGET]["launched"] = launched
                self.assertEqual(self.restore(), 0, self.output)
                self.assertEqual(self.marks()["restoration"]["time"], launched - hsc.SKEW_SECONDS)
                self.assertEqual(self.judge(), ("COMPLETED", verdict))

    def test_a_restoration_inside_the_run_window_leaves_the_run_inconclusive(self):
        # The judge ends observation at a restoration inside the run window, so the rules read over the whole window
        # stand unobserved.
        self.assertEqual(self.run_controller(), 0, self.output)
        self.start_target(initializing=1)
        self.assertEqual(self.restore(), 0, self.output)
        self.assertLess(self.marks()["restoration"]["time"], parse(self.package)["run"]["end"])
        self.assertEqual(self.judge(), ("COMPLETED", "INCONCLUSIVE"))

    def test_a_version_committed_after_the_snapshots_cut_keeps_the_run_judged(self):
        # An attempts-only commit of s5 after the cut and before the controller assembled roles.json: roles.json
        # carries the cut, so the judge still grades the run.
        self.assertEqual(self.run_controller(), 0, self.output)
        self.restore_after_the_run_window()
        self.assertEqual(self.marks()["roles"]["time"], 100)
        later = {"time": 102, "owner": "h3", "standby": "h4", "generation": 5, "volume": "vol-s5", "attempts": 2}
        self.assertEqual(self.judge(versions={"s5": [later]}), ("COMPLETED", "HELD"))

    def test_too_few_roles_fail_to_inject(self):
        self.snapshot("shards.jsonl", lambda rows: rows[3].update(standby="h3"))
        self.assertEqual(self.run_controller(), 1, self.output)
        self.assertEqual(self.judge({"s4": {"standby": "h3"}}), ("FAILED_TO_INJECT", "INCONCLUSIVE"))

    def test_a_stop_never_shown_fails_to_inject(self):
        self.plane.stop_after = None
        self.assertEqual(self.run_controller(), 1, self.output)
        self.assertEqual(self.judge(), ("FAILED_TO_INJECT", "INCONCLUSIVE"))

    def test_an_abort_before_the_stop_is_shown_fails_to_inject(self):
        self.plane.stop_after = None
        self.faulted(lambda: self.plane.flip("gd2-guardrail-1", "ALARM"), while_stopping=True)
        self.assertEqual(self.run_controller(), 1, self.output)
        self.assertEqual(self.judge(), ("FAILED_TO_INJECT", "INCONCLUSIVE"))

    def test_an_abort_after_the_stop_and_its_reviewed_restoration_read_halted(self):
        self.faulted(lambda: self.plane.flip("gd2-guardrail-1", "ALARM"))
        self.assertEqual(self.run_controller(), 1, self.output)
        self.assertEqual(sorted(self.marks()), ["abort", "roles", "stop", "stopped"])
        self.start_target(initializing=0)
        path = self.tmp / "reviewed.json"
        path.write_text(json.dumps(self.review()), encoding="utf-8")
        self.assertEqual(self.restore(path), 0, self.output)
        self.assertEqual(self.marks()["restoration"]["reviewed_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(self.judge(), ("HALTED", "INCONCLUSIVE"))

    def test_a_run_killed_during_the_observation_is_not_held(self):
        def kill():
            raise Kill()
        self.faulted(kill)
        with self.assertRaises(Kill):
            self.run_controller()
        self.assertEqual(self.judge(), ("FAILED_TO_INJECT", "INCONCLUSIVE"))
        self.assertEqual(self.restore(), 2, "restore refuses a run that ended unrecorded")

    def test_a_signal_during_the_evidence_directory_sync_fails_to_inject(self):
        sync = hsc.fis.sync_directory

        def interrupted(directory):
            if Path(directory) == self.evidence:
                os.kill(os.getpid(), signal.SIGTERM)
            sync(directory)
        self.patch(hsc.fis, "sync_directory", interrupted)
        self.assertEqual(self.run_controller(), 1, self.output)
        self.assertEqual(self.judge(), ("FAILED_TO_INJECT", "INCONCLUSIVE"))


    def restored_copy(self):
        """A copy of a clean run restored after the run window, unsealed, for the cases of `seal`."""
        self.assertEqual(self.run_controller(), 0, self.output)
        self.restore_after_the_run_window()
        return self.copy()

    def assert_seal_refused(self, root, reason):
        calls, before, seen = len(self.plane.log), sorted(p.name for p in (root / "injection").iterdir()), len(self.output)
        self.assertEqual(self.seal(root), 2, self.output)
        self.assertIn(reason, self.output[seen:])
        self.assertEqual((len(self.plane.log), sorted(p.name for p in (root / "injection").iterdir())),
                         (calls, before))

    def test_the_seal_names_each_collected_file_and_a_row_removed_after_it_is_refused(self):
        root = self.restored_copy()
        calls, seen = len(self.plane.log), len(self.output)
        self.assertEqual(self.seal(root), 0, self.output)
        self.assertEqual(len(self.plane.log), calls, "the seal makes no call")
        mark = parse(root / "injection" / "collected.json")
        # The printed digest and the judge's record both name the SHA-256 of the mark's bytes on disk.
        digest = hashlib.sha256((root / "injection" / "collected.json").read_bytes()).hexdigest()
        self.assertIn(f"injection/collected.json sha256 {digest}\n", self.output[seen:])
        sealed_record = self.tmp / "sealed-record.json"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(gj.run(str(root), str(sealed_record), CATALOG, FIS, self.readiness), 0)
        self.assertEqual(parse(sealed_record)["seal"], {"sha256": digest, "time": mark["time"]})
        coverage = parse(root / "coverage.json")
        self.assertEqual(mark["time"], self.clock())
        self.assertEqual(sorted(mark["files"]), sorted([*coverage, "coverage.json", *standing_marks(root)]))
        for rel, digest in mark["files"].items():
            self.assertEqual(digest, hashlib.sha256((root / rel).read_bytes()).hexdigest(), rel)
        self.assert_seal_refused(root, "injection/collected.json exists")
        # The collector drops the CreateVolume row and lowers the count to match: the judge names the file.
        path = root / "provider.jsonl"
        rows = path.read_text(encoding="utf-8").splitlines(keepends=True)
        path.write_text("".join(rows[:-1]), encoding="utf-8")
        coverage["provider.jsonl"]["lines"] -= 1
        (root / "coverage.json").write_text(json.dumps(coverage, indent=1) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(gj.Refusal, "provider.jsonl differs from the bytes injection/collected.json "
                                    "seals"):
            gj.run(str(root), str(self.tmp / "record.json"), CATALOG, FIS, self.readiness)

    def test_a_seal_before_the_window_ends_or_off_its_collections_is_refused(self):
        root = self.restored_copy()
        end = parse(self.package)["run"]["end"]
        self.clock.advance(end - 1 - self.clock.t)
        self.assert_seal_refused(root, "its collections may still grow")
        self.clock.advance(31)

        def rewrite(rel, change):
            path = root / rel
            original = path.read_bytes()
            value = parse(path)
            change(value)
            path.write_text(json.dumps(value, indent=1) + "\n", encoding="utf-8")
            return lambda: path.write_bytes(original)

        for rel, change, reason in (
                ("coverage.json", lambda c: c["provider.jsonl"].update(lines=2), "coverage.json spans provider.jsonl "
                 "backwards or counts 2 lines, not its 3"),
                ("coverage.json", lambda c: c["origin.jsonl"].update(to=end + 60), f"coverage.json spans origin.jsonl "
                 f"to {end + 60}, after the seal's time"),
                ("coverage.json", lambda c: c.pop("witness.jsonl"), "not exactly the observeds"),
                ("injection/roles.json", lambda r: r.update(package_sha256="0" * 64), "names another package")):
            with self.subTest(reason=reason):
                undo = rewrite(rel, change)
                read, real = [], hsc.synced

                def recorded(name, at, fd, read=read, real=real):
                    read.append(at)
                    return real(name, at, fd)
                with patched(hsc, "synced", recorded):
                    self.assert_seal_refused(root, reason)
                if rel == "injection/roles.json":
                    # A roles.json of another package is refused before any collection is read.
                    self.assertEqual(read, ["package.json", "injection/roles.json"])
                undo()
        (root / "blockers.jsonl").unlink()
        self.assert_seal_refused(root, "blockers.jsonl is missing")
        (root / "package.json").write_bytes(PACKAGE + b" ")
        self.assert_seal_refused(root, "package.json holds other bytes than the approval's package")

    def test_a_seal_at_the_run_windows_end_is_written_and_a_second_racing_seal_is_refused(self):
        root = self.restored_copy()
        end = parse(self.package)["run"]["end"]
        self.clock.t = end
        self.assertEqual(self.clock(), end)
        self.assertEqual(self.seal(root), 0, self.output)
        self.assertEqual(parse(root / "injection" / "collected.json")["time"], end)
        first = (root / "injection" / "collected.json").read_bytes()
        # A seal that passes the existence check while another seal links its mark is refused by its listing.
        real = hsc.stands
        self.patch(hsc, "stands", lambda path, what: False if path.name == "collected.json" else real(path, what))
        self.assert_seal_refused(root, "injection/collected.json exists: the seal is written once")
        self.assertEqual((root / "injection" / "collected.json").read_bytes(), first)
        # A seal whose mark another seal links after its listing ends as the same refusal, at the link.
        (root / "injection" / "collected.json").unlink()
        publish = hsc.publish

        def raced(path, data):
            path.write_bytes(first)
            publish(path, data)
        with patched(hsc, "publish", raced):
            self.assertEqual(self.seal(root), 2, self.output)
        self.assertIn("injection/collected.json exists: the seal is written once", self.output)
        self.assertEqual((root / "injection" / "collected.json").read_bytes(), first)

    def test_a_linked_root_records_or_injection_or_a_simulation_package_writes_no_seal(self):
        root = self.restored_copy()
        twin = self.tmp / "twin"
        shutil.copytree(root, twin, symlinks=True)
        shutil.rmtree(root / "records")
        (root / "records").symlink_to(twin / "records")
        self.assert_seal_refused(root, "records is no directory")
        linked = self.tmp / "linked"
        linked.symlink_to(twin)
        self.assert_seal_refused(linked, f"{linked} is no directory;")
        self.assertFalse((twin / "injection" / "collected.json").exists())
        shutil.rmtree(twin / "injection")
        (twin / "injection").symlink_to(root / "injection")
        self.assertEqual(self.seal(twin), 2, self.output)
        self.assertIn("is no directory: no run to seal", self.output)
        # A simulation package, approved and named by roles.json, is the export's to seal.
        sim = self.tmp / "sim"
        shutil.copytree(root, sim, ignore=shutil.ignore_patterns("records"))
        shutil.copytree(twin / "records", sim / "records")
        package = parse(sim / "package.json")
        package.update(kind="simulation", clock_error_seconds=0)
        data = (json.dumps(package, indent=1) + "\n").encode()
        (sim / "package.json").write_bytes(data)
        self.operator["approval"]["package_sha256"] = hashlib.sha256(data).hexdigest()
        roles = parse(sim / "injection" / "roles.json")
        roles["package_sha256"] = self.operator["approval"]["package_sha256"]
        (sim / "injection" / "roles.json").write_text(json.dumps(roles), encoding="utf-8")
        self.assert_seal_refused(sim, "package.json is of kind simulation")

    def test_a_backwards_span_or_an_off_schema_row_is_refused_before_the_seal(self):
        root = self.restored_copy()
        coverage, original = parse(root / "coverage.json"), (root / "coverage.json").read_bytes()
        coverage["blockers.jsonl"]["from"] = 401
        (root / "coverage.json").write_text(json.dumps(coverage, indent=1) + "\n", encoding="utf-8")
        self.assert_seal_refused(root, "coverage.json spans blockers.jsonl backwards")
        (root / "coverage.json").write_bytes(original)
        path = root / "blockers.jsonl"
        rows = path.read_bytes()
        path.write_bytes(rows.replace(b'"name"', b'"label"', 1))
        self.assert_seal_refused(root, "blockers.jsonl line 1 holds the keys")
        path.write_bytes(rows)
        self.assertEqual(self.seal(root), 0, self.output)

    def test_a_signal_during_the_collection_reads_ends_the_seal_with_nothing_written(self):
        root = self.restored_copy()
        real = hsc.synced

        def signalled(name, rel, dir_fd):
            if rel == "witness.jsonl":
                os.kill(os.getpid(), signal.SIGTERM)
            return real(name, rel, dir_fd)
        self.patch(hsc, "synced", signalled)
        self.assertEqual(self.seal(root), 2, self.output)
        self.assertIn("signal SIGTERM", self.output)
        self.assertFalse((root / "injection" / "collected.json").exists())
        hsc.unlock(hsc.lock(root / "injection"))

    def test_a_signal_during_the_marks_write_waits_for_it(self):
        root = self.restored_copy()
        publish = hsc.publish

        def signalled(path, data):
            os.kill(os.getpid(), signal.SIGTERM)
            publish(path, data)
        self.patch(hsc, "publish", signalled)
        self.assertEqual(self.seal(root), 0, self.output)
        self.assertTrue((root / "injection" / "collected.json").exists())

    def test_a_signal_just_before_the_marks_write_is_held_ends_the_seal_with_nothing_written(self):
        root = self.restored_copy()
        real, sent = hsc.Controller.hold, []

        def signalled(controller):
            # The first hold of a seal is its mark's: the signal lands after every read and before the write is held.
            if not sent:
                sent.append(True)
                os.kill(os.getpid(), signal.SIGTERM)
            return real(controller)
        self.patch(hsc.Controller, "hold", signalled)
        self.assertEqual(self.seal(root), 2, self.output)
        self.assertIn("signal SIGTERM", self.output)
        self.assertFalse((root / "injection" / "collected.json").exists())
        hsc.unlock(hsc.lock(root / "injection"))

    def test_an_entry_outside_the_layout_in_the_root_or_records_writes_no_seal(self):
        root = self.restored_copy()
        for rel, reason in (("records/unlisted.jsonl", "records/unlisted.jsonl is no file of the layout"),
                            ("notes.txt", "notes.txt is no file of the layout")):
            with self.subTest(rel=rel):
                (root / rel).write_bytes(b"")
                # The judge refuses the directory as it stands, so a seal of it would name evidence the judge refuses.
                with self.assertRaisesRegex(gj.Refusal, reason):
                    gj.read_evidence(str(root))
                self.assert_seal_refused(root, reason)
                (root / rel).unlink()
        (root / "spare").mkdir()
        self.assert_seal_refused(root, "spare is no directory of the layout")
        (root / "spare").rmdir()
        (root / "records" / "linked.jsonl").symlink_to(root / "records" / "receipts.jsonl")
        self.assert_seal_refused(root, "records/linked.jsonl is a link or a special file")
        (root / "records" / "linked.jsonl").unlink()
        self.assertEqual(self.seal(root), 0, self.output)

    def test_a_signal_while_a_seals_refusal_is_printed_leaves_the_refusal(self):
        root = self.restored_copy()
        (root / "blockers.jsonl").unlink()
        say = hsc.say

        def signalled(text, err=False):
            if "refused" in text:
                os.kill(os.getpid(), signal.SIGTERM)
            say(text, err=err)
        self.patch(hsc, "say", signalled)
        self.assert_seal_refused(root, "blockers.jsonl is missing; nothing written")

    def test_a_failed_sync_of_a_collection_or_its_directory_writes_no_seal(self):
        root = self.restored_copy()
        real = os.fsync
        for rel, reason in (("witness.jsonl", "witness.jsonl cannot be read and synced"),
                            ("records/receipts.jsonl", "records/receipts.jsonl cannot be read and synced"),
                            ("records", "records cannot be synced"), ("", f"{root} cannot be synced")):
            with self.subTest(rel=rel):
                failed = os.stat(root / rel)

                def failing(fd, failed=failed):
                    if os.path.samestat(os.fstat(fd), failed):
                        raise OSError(errno.EIO, "I/O error")
                    return real(fd)
                with patched(hsc.os, "fsync", failing):
                    self.assert_seal_refused(root, reason)
        self.assertEqual(self.seal(root), 0, self.output)

    def test_a_seal_held_by_a_restore_is_refused_and_one_unwritten_or_left_standing_ends_with_exit_1(self):
        root = self.restored_copy()
        self.clock.advance(parse(self.package)["run"]["end"] + 30 - self.clock.t)
        held = hsc.lock(root / "injection")
        self.assert_seal_refused(root, "is held by a run, restore or seal that has not ended")
        hsc.unlock(held)
        mark = root / "injection" / "collected.json"

        def failing(*args, **kwargs):
            raise OSError(errno.EIO, "I/O error")
        # A write that fails before the link prints no digest.
        seen = len(self.output)
        with patched(hsc, "publish", failing):
            self.assertEqual(self.seal(root), 1, self.output)
        self.assertIn("collected.json is unwritten", self.output[seen:])
        self.assertNotIn("sha256", self.output[seen:])
        self.assertFalse(mark.exists())
        # A sync that fails after the link, with the mark removed again: the seal prints the digest of the mark it
        # linked, which may stand again after a crash.
        publish, linked = hsc.publish, []

        def recorded(path, data):
            linked.append(hashlib.sha256(data).hexdigest())
            publish(path, data)
        seen = len(self.output)
        with patched(hsc, "publish", recorded), patched(hsc, "sync", failing):
            self.assertEqual(self.seal(root), 1, self.output)
        self.assertIn("the removal is unsynced", self.output[seen:])
        self.assertIn(f"injection/collected.json sha256 {linked[-1]}\n", self.output[seen:])
        self.assertFalse(mark.exists())
        # The sync after the link and the removal both fail: the seal stands, and a second seal is refused.
        seen = len(self.output)
        with patched(hsc, "sync", failing), patched(hsc.os, "unlink", failing):
            self.assertEqual(self.seal(root), 1, self.output)
        self.assertIn("collected.json stands, but it cannot be synced", self.output[seen:])
        self.assertIn(f"injection/collected.json sha256 {hashlib.sha256(mark.read_bytes()).hexdigest()}\n",
                      self.output[seen:])
        self.assertEqual(sorted(parse(mark)["files"]), sorted([*parse(root / "coverage.json"), "coverage.json",
                                                              *standing_marks(root)]))
        self.assert_seal_refused(root, "injection/collected.json exists: the seal is written once")
        self.assertEqual(gj.read_evidence(str(root))["seal_sha256"], hashlib.sha256(mark.read_bytes()).hexdigest())

    def test_an_entry_of_injection_outside_the_layout_is_refused_before_it_is_read(self):
        root = self.restored_copy()
        real, read = hsc.synced, []

        def recorded(name, rel, dir_fd):
            read.append(rel)
            return real(name, rel, dir_fd)
        self.patch(hsc, "synced", recorded)
        for make, rel, reason in ((lambda p: p.write_bytes(b"{}"), "injection/notes.json", "is no file of the layout"),
                                  (lambda p: p.write_bytes(b"{}"), "notes.json", "is no file of the layout"),
                                  (lambda p: p.write_bytes(b""), "records/s9.jsonl", "is no file of the layout"),
                                  (lambda p: p.unlink(), "blockers.jsonl", "is missing"),
                                  (lambda p: p.mkdir(), "injection/spare", "is no directory of the layout"),
                                  (lambda p: p.symlink_to(root / "injection" / "roles.json"), "injection/linked.json",
                                   "is a link or a special file")):
            with self.subTest(rel=rel):
                read.clear()
                make(root / rel)
                self.assert_seal_refused(root, f"{rel} {reason}")
                self.assertEqual(read, ["package.json"])
                if rel == "blockers.jsonl":
                    shutil.copy(HELD / rel, root / rel)
                elif (root / rel).is_dir() and not (root / rel).is_symlink():
                    (root / rel).rmdir()
                else:
                    (root / rel).unlink()
        # When package.json is a directory, seal names package.json in the error and closes the directory descriptor.
        package = (root / "package.json").read_bytes()
        (root / "package.json").unlink()
        (root / "package.json").mkdir()
        opened = len(os.listdir("/proc/self/fd"))
        self.assert_seal_refused(root, "package.json is no regular file")
        self.assertEqual(len(os.listdir("/proc/self/fd")), opened)
        (root / "package.json").rmdir()
        (root / "package.json").write_bytes(package)
        self.assertEqual(self.seal(root), 0, self.output)

    def test_an_empty_evidence_path_seals_and_restores_nothing_in_the_working_directory(self):
        self.addCleanup(os.chdir, os.getcwd())
        root = self.restored_copy()
        self.clock.advance(parse(self.package)["run"]["end"] + 30 - self.clock.t)
        os.chdir(root)
        calls, seen = len(self.plane.log), len(self.output)
        self.assertEqual(self.main(["seal", "--operator", str(self.write_operator()), "--evidence", ""]), 2)
        self.assertIn("no evidence directory is named", self.output[seen:])
        self.assertFalse((root / "injection" / "collected.json").exists())
        (root / "injection" / "restoration.json").unlink()
        seen = len(self.output)
        self.assertEqual(self.main(["restore", "--operator", str(self.write_operator()), "--evidence", ""]), 2)
        self.assertIn("no evidence directory is named", self.output[seen:])
        self.assertEqual((len(self.plane.log), (root / "injection" / "restoration.json").exists()), (calls, False))
        # An explicit `.` names the working directory.
        self.assertEqual(self.main(["restore", "--operator", str(self.write_operator()), "--evidence", "."]), 0,
                         self.output)
        self.assertEqual(self.main(["seal", "--operator", str(self.write_operator()), "--evidence", "."]), 0,
                         self.output)

    def test_the_seal_names_each_mark_and_the_judge_refuses_one_removed_after_it(self):
        self.faulted(lambda: self.plane.flip("gd2-guardrail-1", "ALARM"))
        self.assertEqual(self.run_controller(), 1, self.output)
        self.start_target(initializing=0)
        path = self.tmp / "reviewed.json"
        path.write_text(json.dumps(self.review()), encoding="utf-8")
        self.assertEqual(self.restore(path), 0, self.output)
        root = self.copy()
        self.clock.advance(parse(self.package)["run"]["end"] + 30 - self.clock.t)
        self.assertEqual(self.seal(root), 0, self.output)
        mark = parse(root / "injection" / "collected.json")
        self.assertEqual(sorted(rel for rel in mark["files"] if rel.startswith("injection/")),
                         [f"injection/{name}.json" for name in ("abort", "restoration", "roles", "stop", "stopped")])
        # Without the abort, and with the restoration rewritten to name no review, the run would read COMPLETED.
        (root / "injection" / "abort.json").unlink()
        restoration = parse(root / "injection" / "restoration.json")
        restoration["reviewed_sha256"] = None
        (root / "injection" / "restoration.json").write_text(json.dumps(restoration, indent=1) + "\n")
        with self.assertRaisesRegex(gj.Refusal, "injection/collected.json seals injection/abort.json, which is missing"):
            gj.run(str(root), str(self.tmp / "record.json"), CATALOG, FIS, self.readiness)

    def test_a_restore_after_the_seal_writes_its_restoration_and_exits_1_when_it_may_end_observation(self):
        end = parse(self.package)["run"]["end"]
        # (launch, exit): inside the run window; after the window's end and before the seal's time; after the seal.
        for launched, code in ((end - 10, 1), (end + hsc.SKEW_SECONDS + 5, 0), (end + 40 + hsc.SKEW_SECONDS, 0)):
            with self.subTest(launched=launched):
                self.setUp()
                self.assertEqual(self.run_controller(), 0, self.output)
                root = self.copy()
                self.clock.advance(end + 30 - self.clock.t)
                self.assertEqual(self.seal(root), 0, self.output)
                self.clock.advance(max(0.0, launched + hsc.SKEW_SECONDS + 1 - self.clock.t))
                self.start_target(initializing=0)
                self.plane.instances[TARGET]["launched"] = launched
                seen = len(self.output)
                self.plane.deadline = None
                self.assertEqual(self.main(["restore", "--operator", str(self.write_operator()), "--evidence",
                                            str(root)]), code, self.output)
                restoration = parse(root / "injection" / "restoration.json")
                self.assertEqual(restoration["time"], launched - hsc.SKEW_SECONDS)
                record = self.tmp / "restored-record.json"
                if code:
                    self.assertIn("the judge refuses this evidence while the mark stands", self.output[seen:])
                    with self.assertRaisesRegex(gj.Refusal, "injection/restoration.json stands unsealed"):
                        gj.run(str(root), str(record), CATALOG, FIS, self.readiness)
                    continue
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(gj.run(str(root), str(record), CATALOG, FIS, self.readiness), 0)
                self.assertEqual((parse(record)["run_status"], parse(record)["verdict"]), ("COMPLETED", "HELD"))

    def test_a_restore_after_the_seal_refuses_a_sealed_mark_missing_or_changed_before_any_call(self):
        def changed_roles(root):
            roles = parse(root / "injection" / "roles.json")
            roles["time"] += 1
            (root / "injection" / "roles.json").write_text(json.dumps(roles, indent=1) + "\n")

        def unsealed(root):
            seal = parse(root / "injection" / "collected.json")
            seal.pop("files")
            (root / "injection" / "collected.json").write_text(json.dumps(seal))

        def unnamed(rel):
            def change(root):
                seal = parse(root / "injection" / "collected.json")
                del seal["files"][rel]
                (root / "injection" / "collected.json").write_text(json.dumps(seal))
            return change
        end = parse(self.package)["run"]["end"]
        for name, change, reason in (
                ("a seal that names no stop", unnamed("injection/stop.json"), "injection/stop.json stands unsealed"),
                ("a seal that names no stopped report", unnamed("injection/stopped.json"),
                 "injection/stopped.json stands unsealed"),
                ("a seal that names no coverage", unnamed("coverage.json"),
                 "injection/collected.json seals no coverage.json"),
                ("a seal that names no witness collection", unnamed("witness.jsonl"),
                 "injection/collected.json seals no witness.jsonl"),
                ("restoration", lambda root: (root / "injection" / "restoration.json").unlink(),
                 "injection/collected.json seals injection/restoration.json, which is missing"),
                ("abort", lambda root: (root / "injection" / "abort.json").unlink(),
                 "injection/collected.json seals injection/abort.json, which is missing"),
                ("roles", changed_roles, "injection/roles.json differs from the bytes injection/collected.json seals"),
                ("files", unsealed, "injection/collected.json holds the keys ['time'], not ['files', 'time']"),
                ("coverage changed after the seal", lambda root: (root / "coverage.json").write_bytes(
                    (root / "coverage.json").read_bytes() + b"\n"),
                 "coverage.json differs from the bytes injection/collected.json seals"),
                ("a collection removed after the seal", lambda root: (root / "witness.jsonl").unlink(),
                 "witness.jsonl is missing"),
                ("a file outside the layout", lambda root: (root / "notes.txt").write_text("a note"),
                 "notes.txt is no file of the layout"),
                ("package", lambda root: (root / "package.json").write_bytes(PACKAGE + b" "),
                 "package.json holds other bytes than the approval's package")):
            with self.subTest(name=name):
                self.setUp()
                if name == "abort":
                    self.faulted(lambda: self.plane.flip("gd2-guardrail-1", "ALARM"))
                self.assertEqual(self.run_controller(), 1 if name == "abort" else 0, self.output)
                if name == "restoration":
                    self.restore_after_the_run_window()
                root = self.copy()
                self.clock.advance(max(0.0, end + 30 - self.clock.t))
                self.assertEqual(self.seal(root), 0, self.output)
                change(root)
                self.start_target(initializing=0)
                calls, seen = len(self.plane.log), len(self.output)
                before = sorted(p.name for p in (root / "injection").iterdir())
                self.assertEqual(self.main(["restore", "--operator", str(self.write_operator()), "--evidence",
                                            str(root)]), 2, self.output)
                self.assertIn(reason, self.output[seen:])
                self.assertEqual((len(self.plane.log), sorted(p.name for p in (root / "injection").iterdir())),
                                 (calls, before))

class Script(unittest.TestCase):
    """The script's source: its calls go through `Controller.aws` as the five calls alone, `Controller.aws` reaches
    the seam once, `aws_cli` is named only as `main`'s default and holds the one process launch, and no module or name
    that could start a process or open a connection is imported another way."""

    TREE = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    NODES = tuple(ast.walk(TREE))
    LAUNCHES = {"system", "popen", "fork", "forkpty", "posix_spawn", "posix_spawnp", "startfile"}

    def nodes(self):
        """Every node of TREE: the script's own, walked once, and those of each statement a test appended to it."""
        own = len(type(self).TREE.body)
        return [*self.NODES, *(n for statement in self.TREE.body[own:] for n in ast.walk(statement))]

    def calls(self, attr):
        return [n for n in self.nodes() if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == attr]

    def test_the_call_sites_are_the_five_calls(self):
        found, retries = [], {}
        for site in self.calls("aws"):
            func = site.func
            assert isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name), ast.dump(site)
            self.assertEqual(func.value.id, "self", ast.dump(site))
            self.assertEqual(len(site.args), 1, "retry and the rest pass by keyword")
            self.assertTrue(all(k.arg is not None for k in site.keywords), "no ** at a call site")
            first = site.args[0]
            assert isinstance(first, ast.Tuple), ast.dump(site)
            words = [e.value for e in first.elts[:2] if isinstance(e, ast.Constant)]
            self.assertEqual(len(words), 2, ast.dump(site))
            found.append(tuple(words))
            retries[words[1]] = [ast.literal_eval(k.value) for k in site.keywords if k.arg in ("retry", "mutating")]
        self.assertEqual(sorted(found), sorted(FIVE))
        # The stop request alone turns the CLI's retries off and marks itself mutating; every other call keeps the
        # defaults.
        self.assertEqual({op: kw for op, kw in retries.items() if kw}, {"stop-instances": [False, True]})
        self.assertEqual(len(self.calls("call")), 1)
        # Every use of `aws` or `call` is a call, so no alias reaches the seam another way.
        called = {id(n.func) for n in self.nodes() if isinstance(n, ast.Call)}
        self.assertFalse([ast.dump(n) for n in self.nodes() if isinstance(n, ast.Attribute)
                          and n.attr in ("aws", "call") and id(n) not in called
                          and not isinstance(n.ctx, ast.Store)])

    def test_aws_cli_is_named_once_as_mains_default(self):
        names = [n for n in self.nodes() if isinstance(n, ast.Name) and n.id == "aws_cli"]
        self.assertEqual(len(names), 1)
        main = next(n for n in self.TREE.body if isinstance(n, ast.FunctionDef) and n.name == "main")
        self.assertIn(names[0], main.args.defaults)

    def test_one_process_launch_and_no_other_way_out(self):
        nodes = self.nodes()
        imports = [n for n in nodes if isinstance(n, (ast.Import, ast.ImportFrom))]
        for node in imports:
            if isinstance(node, ast.ImportFrom):
                self.assertNotIn((node.module or "").split(".")[0], {"os", "subprocess", "signal"}, ast.dump(node))
            else:
                self.assertTrue(all(a.asname is None for a in node.names), ast.dump(node))
        modules = {a.name.split(".")[0] for n in imports
                   for a in (n.names if isinstance(n, ast.Import) else [ast.alias(n.module or "")])}
        self.assertFalse(modules & {"socket", "urllib", "http", "boto3", "botocore", "ctypes", "multiprocessing",
                                    "asyncio", "pty", "concurrent", "threading", "shutil"})
        process = [n for n in nodes if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
                   and n.value.id == "subprocess"]
        self.assertEqual(sorted({n.attr for n in process}), ["DEVNULL", "TimeoutExpired", "run"])
        self.assertEqual(len([n for n in process if n.attr == "run"]), 1)
        system = [n.attr for n in nodes if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
                  and n.value.id == "os" and (n.attr in self.LAUNCHES or n.attr.startswith(("exec", "spawn")))]
        self.assertEqual(system, [])
        self.assertFalse([n for n in nodes if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                          and n.func.id in ("getattr", "__import__", "eval", "exec")])
        launcher = next(n for n in self.TREE.body if isinstance(n, ast.FunctionDef) and n.name == "aws_cli")
        self.assertIn(next(n for n in process if n.attr == "run"), list(ast.walk(launcher)))

    def test_the_scan_sees_a_launch_written_another_way(self):
        for source in ("from subprocess import Popen\n", "import subprocess as sp\n", "subprocess.Popen(['aws'])\n",
                       "os.posix_spawnp('aws', [], {})\n", "aws_cli(['sts'], True, 1)\n"):
            with self.subTest(source):
                tree = self.TREE
                self.TREE = ast.Module(body=tree.body + ast.parse(source).body, type_ignores=[])
                try:
                    with self.assertRaises(AssertionError):
                        self.test_one_process_launch_and_no_other_way_out()
                        self.test_aws_cli_is_named_once_as_mains_default()
                finally:
                    self.TREE = tree


class CommandLine(unittest.TestCase):
    """`aws_cli` over a fake `aws` program on a temporary path, whose mode an environment variable picks."""

    PROGRAM = """#!/bin/sh
case "$FAKE_AWS_MODE" in
  echo) format='{"argv": "%s", "attempts": "%s", "mode": "%s", "pager": "%s", "prompt": "%s", "endpoints": "%s"'
        printf "$format"', "stdin": "%s"}' "$*" "$AWS_MAX_ATTEMPTS" "$AWS_RETRY_MODE" "${AWS_PAGER-unset}" \\
          "$AWS_CLI_AUTO_PROMPT" "$AWS_IGNORE_CONFIGURED_ENDPOINT_URLS" "$(readlink /proc/self/fd/0)" ;;
  fail) echo "An error occurred (UnauthorizedOperation)" >&2; echo '{"Arn": "a"}'; exit 254 ;;
  list) echo '[]' ;;
  twice) echo '{"Arn": "a", "Arn": "b"}' ;;
  sleep) sleep 5; echo '{"Arn": "a"}' ;;
esac
"""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="host-stop-aws."))
        self.addCleanup(shutil.rmtree, self.tmp)
        program = self.tmp / "aws"
        program.write_text(self.PROGRAM, encoding="utf-8")
        program.chmod(stat.S_IRWXU)
        aws, environ = hsc.AWS, dict(os.environ)
        vars(hsc)["AWS"] = str(program)
        self.addCleanup(setattr, hsc, "AWS", aws)
        self.addCleanup(os.environ.update, environ)
        self.addCleanup(os.environ.clear)
        # The caller's own settings, each of which the CLI's call must override.
        os.environ.update(AWS_PAGER="less", AWS_CLI_AUTO_PROMPT="on", AWS_RETRY_MODE="legacy",
                          AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="false",
                          AWS_ENDPOINT_URL_CLOUDWATCH="https://cloudwatch.example.invalid")

    def call(self, mode, argv=("sts", "get-caller-identity"), retry=True, timeout=5.0):
        os.environ["FAKE_AWS_MODE"] = mode
        os.environ.pop("AWS_MAX_ATTEMPTS", None)
        return hsc.aws_cli(list(argv), retry, timeout, dict(os.environ))

    def test_the_cli_runs_under_the_environment_it_is_given(self):
        given = dict(os.environ, FAKE_AWS_MODE="echo")
        os.environ["FAKE_AWS_MODE"] = "fail"
        self.assertEqual(hsc.aws_cli(["sts", "get-caller-identity"], True, 5.0, given)["argv"].split()[:2],
                         ["sts", "get-caller-identity"])

    def test_a_reply_is_the_json_object_the_cli_prints(self):
        reply = self.call("echo", ("ec2", "stop-instances", "--instance-ids", "i-h1"), retry=False, timeout=7.5)
        self.assertEqual(reply["argv"], "ec2 stop-instances --instance-ids i-h1 --no-paginate --output json "
                                        "--cli-read-timeout 8 --cli-connect-timeout 8")
        self.assertEqual((reply["attempts"], reply["mode"], reply["pager"], reply["prompt"], reply["endpoints"],
                          reply["stdin"]), ("1", "standard", "", "off", "true", "/dev/null"))
        read = self.call("echo", ("cloudwatch", "describe-alarms"))
        self.assertEqual((read["attempts"], read["mode"], read["endpoints"]), ("", "legacy", "true"),
                         "a read call keeps the CLI's own retries and ignores the configured endpoints")
        self.assertIn("--no-paginate", read["argv"])

    def test_every_other_outcome_is_a_failed_call(self):
        for mode in ("fail", "list", "twice"):
            with self.subTest(mode), self.assertRaises(hsc.CallFailed) as caught:
                self.call(mode)
            if mode == "fail":
                self.assertIn("exited 254", str(caught.exception))
        with self.assertRaises(hsc.CallFailed) as caught:
            self.call("sleep", timeout=0.02)
        self.assertIsInstance(caught.exception.__cause__, subprocess.TimeoutExpired)
        vars(hsc)["AWS"] = str(self.tmp / "missing")
        with self.assertRaises(hsc.CallFailed):
            self.call("echo")


class Bytecode(unittest.TestCase):
    """`load` writes no bytecode for the module it loads or for the modules that module loads in turn, and leaves the
    interpreter's setting as it found it. The check runs in process over two modules in a temporary directory, which
    the self-test's bound of 1 s admits where a fresh interpreter compiling the controller's import chain would not."""

    def test_a_loaded_module_and_the_modules_it_loads_write_no_bytecode(self):
        tmp = Path(tempfile.mkdtemp(prefix="host-stop-bytecode."))
        self.addCleanup(shutil.rmtree, tmp)
        (tmp / "inner-module.py").write_text("VALUE = 1\n", encoding="utf-8")
        (tmp / "outer-module.py").write_text(
            "import importlib.util\nfrom pathlib import Path\n"
            "spec = importlib.util.spec_from_file_location('inner', Path(__file__).with_name('inner-module.py'))\n"
            "inner = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(inner)\n", encoding="utf-8")
        self.addCleanup(setattr, sys, "dont_write_bytecode", sys.dont_write_bytecode)
        for setting in (False, True):
            with self.subTest(setting=setting):
                sys.dont_write_bytecode = setting
                self.assertEqual(hsc.load("outer_module", tmp / "outer-module.py").inner.VALUE, 1)
                self.assertIs(sys.dont_write_bytecode, setting)
                self.assertEqual(listing(tmp), ["inner-module.py", "outer-module.py"])
        # Without the suppression the same load writes the cache, so the check above observes it.
        sys.dont_write_bytecode = False
        spec = importlib.util.spec_from_file_location("plain", tmp / "inner-module.py")
        assert spec is not None and spec.loader is not None
        spec.loader.exec_module(importlib.util.module_from_spec(spec))
        self.assertIn("__pycache__", listing(tmp))


if __name__ == "__main__":
    unittest.main()
