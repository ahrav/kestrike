#!/usr/bin/env python3
"""Exercise guest-binder.py with a fake QEMU that plays each guest outcome."""

import contextlib
import ctypes
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock

# With the subreaper flag set, a descendant the harness leaves behind
# reparents to this process, so the cleanup checks see it.
PR_SET_CHILD_SUBREAPER = 36
if ctypes.CDLL(None, use_errno=True).prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "prctl(PR_SET_CHILD_SUBREAPER) failed")

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/guest-binder.py"
REGISTRY = ROOT / "scripts/test-registry.json"
_SPEC = importlib.util.spec_from_file_location("guest_binder", SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(HARNESS)
TEST = HARNESS.TEST

QEMU = textwrap.dedent('''\
    #!/usr/bin/env python3
    import json, os, subprocess, sys, time
    from pathlib import Path
    if sys.argv[1:] == ["--version"]:
        print("QEMU emulator version 9.2.0 (fake)")
        print("Copyright (c) 2003-2026 the fake QEMU's developers")
        sys.exit(0)
    state = Path(os.environ["FAKE_STATE"])
    mode = os.environ["FAKE_GUEST"]
    args = sys.argv[1:]
    (state / "argv.txt").write_text("\\n".join(args))
    drive = next(a for a in args if a.startswith("file="))
    backing = drive.split(",")[0][len("file="):]
    (state / "backing.txt").write_text(backing)
    (state / "backing-bytes.txt").write_text(str(os.path.getsize(backing)))
    def say(line):
        print(line, flush=True)
    if mode == "stubborn":
        import signal
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        child = subprocess.Popen([sys.executable, "-c",
            "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(600)"])
        (state / "grandchild.pid").write_text(str(child.pid))
        say("guest-binder: ready kernel=6.1.0 modules=nvme,vfio-pci iommu=intel")
        time.sleep(600)
    if mode == "silent":
        time.sleep(600)
    if mode == "closed":
        sys.exit(0)
    say("Linux version 6.1.0 (fake)")
    say("guest-binder: ready kernel=6.1.0 modules=nvme,vfio-pci iommu=intel")
    if mode == "flood":
        say("x" * int(os.environ["FAKE_FLOOD"]))
    if mode == "stall":
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
        (state / "grandchild.pid").write_text(str(child.pid))
        time.sleep(600)
    if mode == "crash":
        sys.exit(1)
    say("running 1 test")
    # Under --nocapture libtest names the case before it runs, so the case's first report shares that line
    # and the outcome follows alone, as a real guest's console shows.
    started = "test " + os.environ.get("FAKE_TEST", "") + " ... "
    if mode != "unrefused":
        say(started + "guest-binder: default refused")
        started = ""
    say(started + "guest-binder: controller 0000:00:04.0 model \\"QEMU NVMe Ctrl\\" pci 1b36:0010 namespace nvme0n1 group 5")
    if mode == "unbound":
        say("FAILED")
        say("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2470 filtered out; finished in 0.10s")
        say("guest-binder: exit 101")
        sys.exit(0)
    for refused in ("substituted file refused", "other block node refused", "holder refused", "claimed"):
        if not (mode == "unclaimed" and refused == "claimed"):
            say("guest-binder: " + refused)
    say("guest-binder: bound")
    if mode != "unreleased":
        say("guest-binder: released")
    inventory = json.loads(Path("__INVENTORY__").read_text())["qemu"]["namespace_cases"]
    if mode != "namespace-tools":
        say("guest-binder: namespace tools ready")
    for index, case in enumerate(inventory):
        if index == 0 and mode == "namespace-missing":
            continue
        id = case["id"] if mode != "namespace-substituted" or index else "bind::network_tests::substituted"
        result = "failed" if mode == "namespace-failed" and index == 0 else "passed"
        if mode == "namespace-timeout" and index == 0:
            result = "timed-out"
        say("guest-binder: namespace " + id + " " + result)
        if mode == "namespace-duplicate" and index == 0:
            say("guest-binder: namespace " + id + " " + result)
    if mode in ("namespace-overflow-duplicate", "namespace-overflow-unexpected"):
        for index in range(256):
            say("guest-binder: padding " + str(index))
        id = inventory[0]["id"] if mode.endswith("duplicate") else "bind::network_tests::unexpected"
        say("guest-binder: namespace " + id + " passed")
    if mode == "zero":
        say("test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 2470 filtered out; finished in 0.00s")
    else:
        say("ok")
        say("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2470 filtered out; finished in 1.20s")
    if mode == "malformed-exit":
        say("guest-binder: exit " + os.environ["FAKE_EXIT"])
        sys.exit(0)
    if mode == "double-exit":
        say("guest-binder: exit 1")
    say("guest-binder: exit 3" if mode == "guest-exit" else "guest-binder: exit 0")
    if mode == "late-flood":
        say("x" * int(os.environ["FAKE_FLOOD"]))
        say("guest-binder: namespace " + inventory[0]["id"] + " passed")
    if mode == "linger":
        import signal
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        sys.stdout.close()
        os.close(1)
        os.close(2)
        time.sleep(600)
    sys.exit(1 if mode == "qemu-exit" else 0)
''').replace('__INVENTORY__', str(ROOT / 'scripts/test-inventory.json'))


def alive(pid):
    """Whether `pid` names a process that has not yet been reaped."""
    return Path(f"/proc/{pid}").exists()


class GuestBinder(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.qemu = self.dir / "qemu-system-x86_64"
        self.qemu.write_text(QEMU)
        self.qemu.chmod(0o755)
        for name in ("bzImage", "initrd.img"):
            (self.dir / name).write_bytes(name.encode())
        self.state = self.dir / "state"
        self.state.mkdir()
        self.artifacts = self.dir / "artifacts"

    def tearDown(self):
        self.tmp.cleanup()

    def argv(self, *extra, overrides=None):
        flags = {
            "--qemu": str(self.qemu), "--kernel": str(self.dir / "bzImage"),
            "--initrd": str(self.dir / "initrd.img"), "--artifacts": str(self.artifacts),
            "--accel": "tcg", "--handshake-seconds": "5", "--deadline-seconds": "10",
        }
        flags.update(overrides or {})
        return [sys.executable, str(SCRIPT), *(part for flag in flags.items() for part in flag), *extra]

    def run_guest(self, mode, overrides=None, extra=None):
        env = dict(os.environ, FAKE_STATE=str(self.state), FAKE_GUEST=mode, FAKE_TEST=TEST, **(extra or {}))
        done = subprocess.run(self.argv(overrides=overrides), env=env, capture_output=True, text=True, timeout=60)
        return done, self.record()

    def record(self):
        records = list(self.artifacts.glob("*/guest.json"))
        self.assertEqual(len(records), 1, "one record per run")
        return json.loads(records[0].read_text())

    def assert_cleaned(self, record):
        self.assertFalse(alive(record["qemu_pid"]), "QEMU is reaped")
        self.assertTrue(record["cleanup"]["qemu_reaped"])
        self.assertTrue(record["cleanup"]["backing_removed"])
        backing = (self.state / "backing.txt").read_text()
        self.assertFalse(Path(backing).parent.exists(), "the backing's private directory is gone")
        grandchild = self.state / "grandchild.pid"
        if grandchild.exists():
            pid = int(grandchild.read_text())
            deadline = time.monotonic() + 5
            while alive(pid) and time.monotonic() < deadline:
                with_reaped(pid)
            self.assertFalse(alive(pid), "the guest's descendants die with its group")

    def test_a_guest_that_runs_the_case_to_a_pass_qualifies_and_is_recorded(self):
        done, record = self.run_guest("pass")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(record["outcome"], "qualified pass")
        self.assertEqual(record["ready"], "kernel=6.1.0 modules=nvme,vfio-pci iommu=intel")
        self.assertEqual(record["reports"][0], "default refused")
        self.assertEqual(record["reports"][-8:], HARNESS.NAMESPACE_REPORTS)
        self.assertEqual((record["guest_exit"], record["qemu_exit"]), (0, 0))
        self.assertEqual(record["identity"]["pci"], "1b36:0010")
        self.assertEqual(record["qemu_version"], "QEMU emulator version 9.2.0 (fake)")
        self.assertEqual(set(record["inputs"]), {"qemu", "kernel", "initrd"})
        self.assertEqual(int((self.state / "backing-bytes.txt").read_text()), 64 << 20)
        argv = (self.state / "argv.txt").read_text().splitlines()
        self.assertIn("intel-iommu,intremap=on,caching-mode=on", argv)
        self.assertEqual(argv[argv.index("-cpu") + 1], "max")
        self.assertIn("nvme,serial=vol0123456789abcdef0,drive=volume", argv)
        self.assertIn("type=2,asset=i-0123456789abcdef0", argv)
        self.assertIn("-no-user-config", argv)
        append = argv[argv.index("-append") + 1]
        self.assertIn("loglevel=5", append.split())
        self.assertIn(f"KESTRIKE_GUEST_TEST_ID={TEST}", append)
        self.assertIn('KESTRIKE_GUEST_MODEL="QEMU NVMe Ctrl"', append)
        console = list(self.artifacts.glob("*/console.log"))[0].read_text()
        self.assertTrue(console.startswith("Linux version"))
        self.assertEqual((record["reports_overflow"], HARNESS.overflowed(console.splitlines())), (False, False))
        self.assert_cleaned(record)

    def test_a_failed_case_or_a_missing_report_fails(self):
        for mode in ("unbound", "unreleased", "unrefused", "unclaimed", "zero", "guest-exit", "qemu-exit"):
            with self.subTest(mode=mode):
                shutil.rmtree(self.artifacts, ignore_errors=True)
                done, record = self.run_guest(mode)
                self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
                self.assertEqual(record["outcome"], "case failed")
                self.assert_cleaned(record)

    def test_a_guest_that_never_reports_ready_misses_the_handshake_and_is_killed(self):
        done, record = self.run_guest("silent", overrides={"--handshake-seconds": "1"})
        self.assertEqual(done.returncode, 3, done.stdout + done.stderr)
        self.assertIsNone(record["ready"])
        self.assert_cleaned(record)

    def test_a_stalled_guest_is_witnessed_ready_then_killed_with_its_group_at_the_deadline(self):
        done, record = self.run_guest("stall", overrides={"--deadline-seconds": "2", "--handshake-seconds": "2"})
        self.assertEqual(done.returncode, 6, done.stdout + done.stderr)
        self.assertEqual(record["ready"], "kernel=6.1.0 modules=nvme,vfio-pci iommu=intel")
        self.assertTrue((self.state / "grandchild.pid").exists())
        self.assert_cleaned(record)

    def test_a_console_that_closes_before_ready_misses_the_handshake(self):
        done, record = self.run_guest("closed")
        self.assertEqual(done.returncode, 3, done.stdout + done.stderr)
        self.assertEqual(record["qemu_exit"], 0)
        self.assert_cleaned(record)

    def test_a_guest_that_ignores_sigterm_is_killed_with_its_group(self):
        done, record = self.run_guest("stubborn", overrides={"--deadline-seconds": "1", "--handshake-seconds": "1"})
        self.assertEqual(done.returncode, 6, done.stdout + done.stderr)
        self.assertEqual(record["qemu_exit"], -signal.SIGKILL)
        self.assert_cleaned(record)

    def test_a_malformed_exit_report_ends_without_a_result(self):
        for code in ("", "--1", "9" * 5000):
            with self.subTest(code=code[:8]):
                shutil.rmtree(self.artifacts, ignore_errors=True)
                done, record = self.run_guest("malformed-exit", extra={"FAKE_EXIT": code})
                self.assertEqual(done.returncode, 4, done.stdout + done.stderr)
                self.assertIsNone(record["guest_exit"])
                self.assert_cleaned(record)

    def test_a_qemu_that_outlives_the_grace_period_is_stopped_and_ends_the_run_at_the_deadline(self):
        args = HARNESS.parser().parse_args(self.argv()[2:])
        run = HARNESS.Run(args)
        run.dir = self.dir / "record"
        run.dir.mkdir()
        backing = self.dir / "volume.raw"
        backing.write_bytes(b"")
        env = {"FAKE_STATE": str(self.state), "FAKE_GUEST": "linger", "FAKE_TEST": TEST}
        with mock.patch.dict(os.environ, env), mock.patch.object(HARNESS, "GRACE", 1):
            with self.assertRaises(HARNESS.Stop) as stop:
                run.supervise(HARNESS.guest_argv(args, backing))
        self.assertEqual(stop.exception.code, HARNESS.DEADLINE)
        self.assertEqual(run.record["qemu_exit"], 0, "QEMU exited zero only because the harness stopped it")
        self.assertEqual(run.record["guest_exit"], 0, "the transcript itself passed")
        self.assertTrue(run.record["cleanup"]["qemu_reaped"])
        self.assertFalse(alive(run.record["qemu_pid"]), "QEMU is reaped")

    def test_a_second_exit_report_ends_without_a_result(self):
        done, record = self.run_guest("double-exit")
        self.assertEqual(done.returncode, 4, done.stdout + done.stderr)
        self.assertEqual((record["guest_exit"], record["exit_reports"]), (None, 2))
        self.assertEqual(record["reports"][-8:], HARNESS.NAMESPACE_REPORTS, "the case's own reports are kept")
        self.assert_cleaned(record)

    def test_a_guest_that_dies_before_its_result_ends_without_a_result(self):
        done, record = self.run_guest("crash")
        self.assertEqual(done.returncode, 4, done.stdout + done.stderr)
        self.assertIsNone(record["guest_exit"])
        self.assert_cleaned(record)

    def test_an_interrupted_run_stops_the_guest_and_removes_its_backing(self):
        env = dict(os.environ, FAKE_STATE=str(self.state), FAKE_GUEST="stall", FAKE_TEST=TEST)
        harness = subprocess.Popen(self.argv(overrides={"--deadline-seconds": "60", "--handshake-seconds": "30"}),
                                   env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 20
        while not (self.state / "grandchild.pid").exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        harness.send_signal(signal.SIGTERM)
        out, err = harness.communicate(timeout=60)
        self.assertEqual(harness.returncode, 5, out + err)
        record = self.record()
        self.assertEqual(record["outcome"], "interrupted")
        self.assert_cleaned(record)

    def test_missing_prerequisites_and_out_of_range_bounds_refuse_before_any_guest(self):
        broken = self.dir / "broken-qemu"
        broken.write_text("#!/bin/sh\nexit 1\n")
        broken.chmod(0o755)
        cases = [
            {"--kernel": str(self.dir / "missing")},
            {"--initrd": str(self.dir / "missing")},
            {"--qemu": str(broken)},
            {"--qemu": str(self.dir / "bzImage")},
            {"--deadline-seconds": "0"},
            {"--handshake-seconds": "20"},
        ]
        for overrides in cases:
            with self.subTest(overrides=overrides):
                env = dict(os.environ, FAKE_STATE=str(self.state), FAKE_GUEST="pass")
                done = subprocess.run(self.argv(overrides=overrides), env=env, capture_output=True, text=True,
                                      timeout=60)
                self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
                self.assertTrue(done.stdout.startswith("rejected input: "), done.stdout)
                self.assertFalse((self.state / "argv.txt").exists(), "no guest started")
                self.assertFalse(self.artifacts.exists(), "no record directory")

    def test_a_console_reader_the_host_refuses_stops_the_guest_and_rejects_the_run(self):
        args = HARNESS.parser().parse_args(self.argv()[2:])
        run = HARNESS.Run(args)
        run.dir = self.dir / "record"
        run.dir.mkdir()
        backing = self.dir / "volume.raw"
        backing.write_bytes(b"")

        def stop_leaked():
            pid = run.record["qemu_pid"]
            if pid is not None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(pid, signal.SIGKILL)
                with contextlib.suppress(ChildProcessError):
                    os.waitpid(pid, 0)

        self.addCleanup(stop_leaked)
        env = {"FAKE_STATE": str(self.state), "FAKE_GUEST": "stall", "FAKE_TEST": TEST}
        refused = RuntimeError("can't start new thread")
        with mock.patch.dict(os.environ, env), \
                mock.patch.object(HARNESS.threading.Thread, "start", side_effect=refused):
            with self.assertRaises(HARNESS.Stop) as stop:
                run.supervise(HARNESS.guest_argv(args, backing))
        self.assertEqual(stop.exception.code, HARNESS.REJECTED)
        self.assertIn("can't start new thread", str(stop.exception))
        self.assertTrue(run.record["cleanup"]["qemu_reaped"])
        self.assertIsNotNone(run.record["qemu_exit"])
        self.assertFalse(alive(run.record["qemu_pid"]), "QEMU is reaped")

    def test_an_overlong_console_line_is_cut_at_the_log_bound_and_the_run_is_judged_from_the_log(self):
        args = HARNESS.parser().parse_args(self.argv()[2:])
        run = HARNESS.Run(args)
        run.dir = self.dir / "record"
        run.dir.mkdir()
        backing = self.dir / "volume.raw"
        backing.write_bytes(b"")
        env = {"FAKE_STATE": str(self.state), "FAKE_GUEST": "flood", "FAKE_TEST": TEST, "FAKE_FLOOD": "200000"}
        with mock.patch.dict(os.environ, env), mock.patch.object(HARNESS, "CONSOLE_BYTES", 1024):
            code = run.supervise(HARNESS.guest_argv(args, backing))
        log = (run.dir / "console.log").read_text()
        self.assertEqual(len(log), 1024, "the log holds exactly its bound")
        self.assertTrue(log.startswith("Linux version"))
        self.assertTrue(run.record["console_truncated"])
        self.assertEqual(run.record["ready"], "kernel=6.1.0 modules=nvme,vfio-pci iommu=intel", "lines within the bound are judged")
        self.assertEqual(code, HARNESS.CRASHED, "the reports after the bound are dropped, so no exit report arrives")
        self.assertEqual((run.record["reports"], run.record["guest_exit"]), ([], None))
        self.assertFalse(alive(run.record["qemu_pid"]), "QEMU is reaped")

    def test_a_console_cut_at_the_log_bound_after_a_passing_transcript_is_a_failed_case(self):
        """The guest reports every witness, its passing summary and exit 0 inside the log bound, then writes past
        the bound a second witness of one namespace member. The run is judged from the log, which holds none of
        the text past the bound, so a cut log is a failed case."""
        args = HARNESS.parser().parse_args(self.argv()[2:])
        run = HARNESS.Run(args)
        run.dir = self.dir / "record"
        run.dir.mkdir()
        backing = self.dir / "volume.raw"
        backing.write_bytes(b"")
        env = {"FAKE_STATE": str(self.state), "FAKE_GUEST": "late-flood", "FAKE_TEST": TEST, "FAKE_FLOOD": "200000"}
        with mock.patch.dict(os.environ, env), mock.patch.object(HARNESS, "CONSOLE_BYTES", 1 << 14):
            code = run.supervise(HARNESS.guest_argv(args, backing))
        record = run.record
        self.assertTrue(record["console_truncated"])
        self.assertEqual(len((run.dir / "console.log").read_text()), 1 << 14, "the log holds exactly its bound")
        logged = (record["guest_exit"], record["qemu_exit"], record["reports_overflow"], HARNESS.namespace_gaps(record["reports"]))
        self.assertEqual(logged, (0, 0, False, []), "the logged transcript alone holds a passing run")
        self.assertEqual(code, HARNESS.FAILED)

    def test_an_interruption_during_the_grace_wait_after_the_console_closes_is_honored(self):
        for mode, grace in (("pass", HARNESS.GRACE), ("linger", 1)):
            with self.subTest(mode=mode):
                args = HARNESS.parser().parse_args(self.argv()[2:])
                run = HARNESS.Run(args)
                run.dir = self.dir / f"record-{mode}"
                run.dir.mkdir()
                backing = self.dir / "volume.raw"
                backing.write_bytes(b"")
                real_wait = subprocess.Popen.wait

                def wait_under_interruption(process, timeout=None):
                    if timeout == grace:
                        run.interrupt(signal.SIGTERM, None)
                    return real_wait(process, timeout=timeout)

                env = {"FAKE_STATE": str(self.state), "FAKE_GUEST": mode, "FAKE_TEST": TEST}
                with mock.patch.dict(os.environ, env), mock.patch.object(HARNESS, "GRACE", grace), \
                        mock.patch.object(HARNESS.subprocess.Popen, "wait", wait_under_interruption):
                    try:
                        code = run.supervise(HARNESS.guest_argv(args, backing))
                    except HARNESS.Stop as stop:
                        code = stop.code
                self.assertEqual(code, HARNESS.INTERRUPTED, "an interruption wins over the grace outcome")
                self.assertEqual((run.record["guest_exit"], run.record["qemu_exit"]), (0, 0), "the guest had finished")
                self.assertTrue(run.record["cleanup"]["qemu_reaped"])

    def test_a_backing_the_host_keeps_rejects_the_run(self):
        args = HARNESS.parser().parse_args(self.argv()[2:])
        run = HARNESS.Run(args)
        kept = []
        self.addCleanup(lambda: [shutil.rmtree(path, ignore_errors=True) for path in kept])
        env = {"FAKE_STATE": str(self.state), "FAKE_GUEST": "pass", "FAKE_TEST": TEST}
        with mock.patch.dict(os.environ, env), \
                mock.patch.object(HARNESS.shutil, "rmtree", lambda path, ignore_errors=False: kept.append(path)):
            with self.assertRaises(HARNESS.Stop) as stop:
                run.guest()
        self.assertEqual(stop.exception.code, HARNESS.REJECTED)
        self.assertEqual(kept, [str(Path(run.record["backing"]["path"]).parent)])
        self.assertIn(kept[0], str(stop.exception))
        self.assertFalse(run.record["cleanup"]["backing_removed"])
        self.assertTrue(run.record["cleanup"]["qemu_reaped"])
        self.assertEqual((run.record["guest_exit"], run.record["qemu_exit"]), (0, 0), "the case itself passed")

    def test_namespace_campaign_requires_each_exact_success_and_its_tools(self):
        for mode in ("missing", "substituted", "duplicate", "failed", "timeout", "tools"):
            with self.subTest(mode=mode):
                done, record = self.run_guest("namespace-" + mode)
                self.assertEqual(done.returncode, HARNESS.FAILED, done.stdout + done.stderr)
                self.assertTrue(HARNESS.namespace_gaps(record["reports"]))
                self.assert_cleaned(record)
                shutil.rmtree(self.artifacts)

    def test_report_overflow_rejects_namespace_witnesses_past_the_cap(self):
        for mode in ("duplicate", "unexpected"):
            with self.subTest(mode=mode):
                done, record = self.run_guest("namespace-overflow-" + mode)
                self.assertEqual(done.returncode, HARNESS.FAILED, done.stdout + done.stderr)
                self.assertTrue(record["reports_overflow"])
                self.assertEqual(len(record["reports"]), HARNESS.REPORT_BOUND)
                self.assertEqual(HARNESS.namespace_gaps(record["reports"]), [])
                self.assertEqual((record["guest_exit"], record["qemu_exit"]), (0, 0))
                console = next(self.artifacts.glob("*/console.log")).read_text()
                self.assertTrue(HARNESS.overflowed(console.splitlines()), "the console shows the overflow the record states")
                id = HARNESS.NAMESPACE_CASES[0]["id"] if mode == "duplicate" else "bind::network_tests::unexpected"
                self.assertIn(f"guest-binder: padding 255\nguest-binder: namespace {id} passed", console)
                self.assert_cleaned(record)
                shutil.rmtree(self.artifacts)

    def test_a_console_overflows_past_the_report_bound_as_the_record_counts_it(self):
        """The console count is the record's: the first `ready` is the handshake and each `exit` an exit report,
        every other report counts, a later `ready` included, and a console holding exactly the bound stays
        within it."""
        frame = ["Linux version 6.1.0", "guest-binder: ready kernel=6.1.0", "running 1 test"]
        reports = [f"guest-binder: padding {index}" for index in range(HARNESS.REPORT_BOUND)]
        self.assertEqual(HARNESS.REPORT_BOUND, 256)
        self.assertFalse(HARNESS.overflowed([*frame, *reports, "guest-binder: exit 0"]))
        self.assertFalse(HARNESS.overflowed([*frame, *reports, "guest-binder: exit 0", "guest-binder: exit 1"]))
        self.assertTrue(HARNESS.overflowed([*frame, *reports, "guest-binder: ready again", "guest-binder: exit 0"]))
        self.assertTrue(HARNESS.overflowed([*frame, *reports, "test x ... guest-binder: one more", "guest-binder: exit 0"]))
        self.assertTrue(HARNESS.overflowed([*reports, "guest-binder: one more"]), "a console without a handshake counts every report")

    def test_the_registry_assigns_the_harness_case_to_the_guest_class(self):
        rows = json.loads(REGISTRY.read_text())["rows"]
        guest = {(row["cfg"], row["target"], row["id"]) for row in rows if row["class"] == "guest-privileged"}
        namespace = {case["id"] for case in HARNESS.NAMESPACE_CASES}
        self.assertEqual(len(namespace), 8)
        self.assertEqual(guest, {(cfg, "kestrike", id) for cfg in ("ordinary", "miri") for id in (TEST, *namespace)})
        source = (ROOT / "crates/kestrike/src/bind/network_tests.rs").read_text()
        for case in HARNESS.NAMESPACE_CASES:
            id = case["id"]
            cause = "needs the disposable QEMU guest namespace campaign with ip, unshare, mount and umount"
            self.assertIn(f'#[test]\n#[ignore = "{cause}"]\nfn {id.split("::")[-1]}()', source)
            self.assertGreater(case["deadline_seconds"], 0)
            for row in rows:
                if row["id"] == id:
                    self.assertEqual(row["cause"], cause)
        hardware = {row["id"] for row in rows if row["class"] == "hardware-privileged"}
        self.assertNotIn(TEST, hardware, "hardware-lane.py schedules every hardware-privileged row")

def with_reaped(pid):
    """Collect `pid`'s status if it has exited and reparented to this subreaper."""
    with contextlib.suppress(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)
    time.sleep(0.05)


if __name__ == "__main__":
    unittest.main()
