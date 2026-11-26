#!/usr/bin/env python3
"""Check receipt scheduling, result accounting, and process-group cancellation."""

import contextlib
import importlib.util
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock

RUNNER = Path(__file__).with_name("run-receipt-selftests.py")
spec = importlib.util.spec_from_file_location("receipt_runner", RUNNER)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ReceiptRunner(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="kestrike-runner-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.script = self.directory / "cases.py"

    def write(self, source):
        self.script.write_text(textwrap.dedent(source))

    def run_script(self, *args):
        return subprocess.run([sys.executable, str(RUNNER), str(self.script), *args],
                              capture_output=True, text=True, timeout=15, check=False)

    def test_discovery_runs_every_nested_case_once_with_bounded_dynamic_dispatch(self):
        self.write('''
            import json, os, time, unittest
            from pathlib import Path
            root = Path(__file__).parent
            class Cases(unittest.TestCase):
                def event(self, kind):
                    line = json.dumps([kind, self._testMethodName, os.getpid()]) + "\\n"
                    with (root / "events").open("a") as out:
                        out.write(line)
                def setUp(self):
                    self.event("start")
                def tearDown(self):
                    self.event("end")
                def test_a_slow(self):
                    deadline = time.monotonic() + 5
                    while not (root / "third-finished").exists():
                        self.assertLess(time.monotonic(), deadline, "a free worker must pick up the third case")
                        time.sleep(0.01)
                def test_b_fast(self):
                    time.sleep(0.1)
                def test_c_third(self):
                    (root / "third-finished").touch()
                def test_d_new_case(self):
                    print("retained stdout")
                def test_e_new_case(self):
                    pass
                def test_f_new_case(self):
                    pass
            def load_tests(loader, tests, pattern):
                return unittest.TestSuite([unittest.TestSuite([tests])])
            if __name__ == "__main__":
                unittest.main()
        ''')
        output = io.StringIO()
        with mock.patch.object(runner, "default_workers", return_value=2), contextlib.redirect_stdout(output):
            code = runner.main([str(self.script), "--workers", "2"])
        text = output.getvalue()
        self.assertEqual(code, 0, text)
        events = [json.loads(line) for line in (self.directory / "events").read_text().splitlines()]
        started = [name for kind, name, _pid in events if kind == "start"]
        expected = ["test_a_slow", "test_b_fast", "test_c_third", "test_d_new_case", "test_e_new_case", "test_f_new_case"]
        self.assertCountEqual(started, expected)
        self.assertEqual(len({pid for kind, _name, pid in events if kind == "start"}), len(expected))
        active, maximum = 0, 0
        for kind, _name, _pid in events:
            active += 1 if kind == "start" else -1
            maximum = max(maximum, active)
            self.assertLessEqual(active, 2)
        self.assertEqual((active, maximum), (0, 2))
        positions = [text.index(f"=== cases.py: Cases.{name} ===") for name in expected]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("retained stdout", text)
        self.assertIn("6 selected; 6 completed; 0 failed", text)

    def test_failures_errors_and_skip_output_are_preserved(self):
        self.write('''
            import sys, unittest
            class Cases(unittest.TestCase):
                def test_failure(self):
                    self.fail("assertion evidence")
                def test_error(self):
                    raise RuntimeError("error evidence")
                def test_pass(self):
                    print("stdout evidence")
                    print("stderr evidence", file=sys.stderr)
                @unittest.skip("skip evidence")
                def test_skip(self):
                    self.fail("must not run")
            if __name__ == "__main__":
                unittest.main()
        ''')
        result = self.run_script("--workers", "4")
        self.assertNotEqual(result.returncode, 0)
        for evidence in ("assertion evidence", "error evidence", "stdout evidence", "stderr evidence",
                         "skipped 'skip evidence'", "OK (skipped=1)", "FAILED (failures=1)", "FAILED (errors=1)"):
            self.assertIn(evidence, result.stdout)
        self.assertIn("4 selected; 4 completed; 2 failed", result.stdout)

    def test_child_exit_without_running_a_case_never_passes(self):
        for code in (0, 7):
            with self.subTest(code=code):
                self.write(f'''
                    import os, unittest
                    class Cases(unittest.TestCase):
                        def test_exit(self):
                            print("exit evidence", flush=True)
                            os._exit({code})
                    if __name__ == "__main__":
                        unittest.main()
                ''')
                result = self.run_script()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("exit evidence", result.stdout)
                self.assertIn(f"Unsuccessful test process: exit {code}", result.stdout)
                self.assertIn("1 selected; 1 completed; 1 failed", result.stdout)

    def test_empty_duplicate_and_broken_discovery_fail_closed(self):
        sources = (
            "import unittest\n",
            '''
                import unittest
                class Cases(unittest.TestCase):
                    def test_one(self):
                        pass
                def load_tests(loader, tests, pattern):
                    return unittest.TestSuite([Cases("test_one"), Cases("test_one")])
            ''',
            '''
                import unittest
                def load_tests(loader, tests, pattern):
                    raise RuntimeError("broken discovery")
            ''',
            "raise RuntimeError('broken import')\n",
        )
        for source in sources:
            with self.subTest(source=source):
                self.write(source)
                result = self.run_script()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("discovery failed", result.stderr)
                self.assertNotIn("0 failed", result.stdout)

    def test_missing_script_fails_closed(self):
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("discovery failed", result.stderr)

    def test_import_time_output_does_not_corrupt_discovery(self):
        self.write('''
            import sys, unittest
            print("stdout noise")
            print("stderr noise", file=sys.stderr)
            class Cases(unittest.TestCase):
                def test_pass(self):
                    pass
            if __name__ == "__main__":
                unittest.main()
        ''')
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("1 selected; 1 completed; 0 failed", result.stdout)

    def test_worker_count_is_positive_and_capped_at_four(self):
        for workers in ("0", "-1", "5", "many"):
            with self.subTest(workers=workers):
                result = self.run_script("--workers", workers)
                self.assertEqual(result.returncode, 2)
                self.assertIn("workers must be an integer from 1 to 4", result.stderr)
        for available, expected in ((1, 1), (2, 2), (64, 4)):
            with mock.patch.object(runner.os, "sched_getaffinity", return_value=set(range(available))):
                self.assertEqual(runner.default_workers(), expected)

    def test_explicit_workers_are_also_bounded_by_cpu_affinity(self):
        self.write('''
            import unittest
            class Cases(unittest.TestCase):
                def test_pass(self):
                    pass
            if __name__ == "__main__":
                unittest.main()
        ''')
        cpu = min(os.sched_getaffinity(0))
        result = subprocess.run([sys.executable, str(RUNNER), str(self.script), "--workers", "4"],
                                capture_output=True, text=True, timeout=15, check=False,
                                preexec_fn=lambda: os.sched_setaffinity(0, {cpu}))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Running 1 self-tests with 1 workers", result.stdout)

    def test_finished_process_groups_are_removed_before_later_cases_start(self):
        commands = [[sys.executable, "-c", "pass"] for _ in range(3)]
        with runner.Supervisor() as supervisor:
            popen = runner.subprocess.Popen
            def start(*args, **kwargs):
                self.assertEqual(supervisor.processes, [])
                return popen(*args, **kwargs)
            with mock.patch.object(runner.subprocess, "Popen", side_effect=start):
                results = supervisor.run(commands, 1, self.directory)
            self.assertEqual(len(results), 3)
            self.assertEqual(supervisor.processes, [])

    def assert_cancelled_group_is_dead(self, signum, discovery=False):
        self.write('''
            import os, subprocess, sys, time, unittest
            from pathlib import Path
            root = Path(__file__).parent
            class Cases(unittest.TestCase):
                def test_hang(self):
                    (root / "leader").write_text(str(os.getpid()))
                    subprocess.Popen([sys.executable, "-c",
                        "import os, signal, sys, time; from pathlib import Path; "
                        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                        "Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(60)",
                        str(root / "grandchild")])
                    time.sleep(60)
            if __name__ == "__main__":
                unittest.main()
        ''')
        if discovery:
            with self.script.open("a") as out:
                out.write('\nelse:\n    Cases("test_hang").test_hang()\n')
        process = subprocess.Popen([sys.executable, str(RUNNER), str(self.script), "--workers", "1"],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        pids = []
        try:
            deadline = time.monotonic() + 5
            names = ("leader", "grandchild")
            while not all((self.directory / name).exists() and (self.directory / name).read_text() for name in names):
                self.assertIsNone(process.poll(), "runner exited before the grandchild wrote its pid")
                self.assertLess(time.monotonic(), deadline, "the grandchild did not write its pid")
                time.sleep(0.01)
            pids = [int((self.directory / name).read_text()) for name in names]
            process.send_signal(signum)
            out, err = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 128 + signum, out + err)
            self.assertIn("Interrupted by " + signal.Signals(signum).name, err)
            deadline = time.monotonic() + 2
            for pid in pids:
                while self.alive(pid) and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertFalse(self.alive(pid), f"process {pid} survived cancellation")
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate()
            for pid in pids:
                if self.alive(pid):
                    os.kill(pid, signal.SIGKILL)

    @staticmethod
    def alive(pid):
        try:
            stat = Path(f"/proc/{pid}/stat").read_text()
            return stat.rsplit(")", 1)[1].split()[0] != "Z"
        except FileNotFoundError:
            return False

    def test_sigterm_kills_a_grandchild_after_its_group_leader_exits(self):
        self.assert_cancelled_group_is_dead(signal.SIGTERM)

    def test_sigint_kills_a_grandchild_after_its_group_leader_exits(self):
        self.assert_cancelled_group_is_dead(signal.SIGINT)

    def test_cancelling_discovery_also_kills_its_process_group(self):
        self.assert_cancelled_group_is_dead(signal.SIGTERM, discovery=True)


if __name__ == "__main__":
    unittest.main()
