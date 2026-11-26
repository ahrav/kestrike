#!/usr/bin/env python3
"""Exercise reproduce-test.py with a fake cargo and fake test executables."""

import ctypes
import importlib.util
import hashlib
import json
import os
import re
import resource
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import types
import unittest
from pathlib import Path

# With the subreaper flag set, orphaned descendants reparent to this process
# and an exited one is a zombie until this process reaps it, so the cleanup
# assertions see the same state a container whose PID 1 does not reap shows.
PR_SET_CHILD_SUBREAPER = 36
if ctypes.CDLL(None, use_errno=True).prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "prctl(PR_SET_CHILD_SUBREAPER) failed")

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/reproduce-test.py"
_STABLE = re.search(r'^\s*STABLE: "([^"]+)"', (ROOT / ".github/workflows/agent-checks.yml").read_text(), re.M)
if _STABLE is None:
    raise SystemExit("agent-checks.yml names no STABLE toolchain")
STABLE = _STABLE.group(1)
TEST = "storage::record::vector_tests::the_boundary_record_ends_on_the_second_window"
LISTED = f"{TEST}: test"
PASSED = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1418 filtered out; finished in 0.00s"
FAILED = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1418 filtered out; finished in 0.00s"
ZERO = "test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 1418 filtered out; finished in 0.00s"

EXECUTABLE = textwrap.dedent('''\
    #!/usr/bin/env python3
    import json, os, signal, sys, time
    from pathlib import Path
    state = Path(os.environ["FAKE_STATE"])
    plan = json.loads((state / "plan.json").read_text())
    args = sys.argv[1:]
    name = Path(sys.argv[0]).name
    if "--list" in args:
        with (state / "lists.txt").open("a") as out:
            out.write("cwd=" + os.getcwd() + "\\n")
        if plan.get("list_hang"):
            import subprocess
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
            (state / "grandchild.pid").write_text(str(child.pid))
            time.sleep(600)
        key = "ignored" if "--ignored" in args else "listed"
        lines = plan.get(key, [])
        print("\\n".join(lines))
        print(f"\\n{len(lines)} tests, 0 benchmarks")
        sys.exit(0)
    runs = state / "runs.txt"
    with runs.open("a") as out:
        out.write(name + " " + " ".join(args) + " cwd=" + os.getcwd() + "\\n")
    attempt = len(runs.read_text().splitlines())
    outcome = plan["outcomes"][min(attempt, len(plan["outcomes"])) - 1]
    test = args[args.index("--exact") + 1]
    print("running 1 test", flush=True)
    print("attempt stderr", file=sys.stderr, flush=True)
    if ("--ignored" in args) != bool(plan.get("ignored")):
        outcome = "zero"
    if outcome == "pass":
        print(f"test {test} ... ok\\n\\n" + plan["passed"])
    elif outcome == "stray":
        import subprocess
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
        (state / "grandchild.pid").write_text(str(child.pid))
        print(f"test {test} ... ok\\n\\n" + plan["passed"])
    elif outcome in ("unrelated", "missing", "duplicate", "beside-ignored", "beside-ok", "beside-failed"):
        lines = {"unrelated": ["test other::test ... ok"], "missing": [],
                 "duplicate": [f"test {test} ... ok"] * 2,
                 "beside-ignored": [f"test {test} ... ok", "test other::test ... ignored"],
                 "beside-ok": [f"test {test} ... ok", "test other::test ... ok"],
                 "beside-failed": [f"test {test} ... ok", "test other::test ... FAILED"]}[outcome]
        print("\\n".join(lines) + "\\n\\n" + plan["passed"])
    elif outcome == "fail":
        print(f"test {test} ... FAILED\\n\\n" + plan["failed"])
        sys.exit(101)
    elif outcome == "zero":
        print(plan["zero"])
    elif outcome == "crash":
        os.kill(os.getpid(), signal.SIGSEGV)
    elif outcome == "stubborn":
        import subprocess
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        child = subprocess.Popen([sys.executable, "-c",
            "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(600)"])
        (state / "grandchild.pid").write_text(str(child.pid))
        time.sleep(600)
    elif outcome == "hang":
        import subprocess
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
        (state / "grandchild.pid").write_text(str(child.pid))
        time.sleep(600)
    elif outcome == "kill-reproducer":
        os.kill(os.getppid(), signal.SIGKILL)
    elif outcome == "block-artifact":
        record = Path(os.readlink("/proc/self/fd/1")).with_name("artifact.json")
        record.unlink()
        record.mkdir()
        print(f"test {test} ... ok\\n\\n" + plan["passed"])
''')

RUSTC = "#!/bin/sh\necho 'rustc 1.99.0 (00000000 2026-01-01)'\n"

CARGO = textwrap.dedent('''\
    #!/usr/bin/env python3
    import json, os, sys
    from pathlib import Path
    state = Path(os.environ["FAKE_STATE"])
    plan = json.loads((state / "plan.json").read_text())
    if sys.argv[1:] == ["-V"]:
        print("cargo 1.99.0 (5f94df478 2026-08-27)")
        sys.exit(0)
    if sys.argv[1:2] == ["metadata"]:
        if plan.get("metadata_hang"):
            import subprocess, time
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
            (state / "grandchild.pid").write_text(str(child.pid))
            time.sleep(600)
        print(json.dumps({"packages": [
            {"name": "loom", "version": "0.7.2", "manifest_path": "/registry/loom-0.7.2/Cargo.toml",
             "source": "registry+https://github.com/rust-lang/crates.io-index"},
            {"name": plan.get("package", "kestrike"), "version": "0.1.0", "manifest_path": str(state / "pkg" / "Cargo.toml")},
        ]}))
        sys.exit(plan.get("metadata_exit", 0))
    (state / "build-env.json").write_text(json.dumps({
        name: os.environ[name] for name in ("RUSTUP_TOOLCHAIN", "CARGO_PROFILE_DEV_OPT_LEVEL",
                                           "CARGO_PROFILE_DEV_DEBUG", "RUST_BACKTRACE")
        if name in os.environ
    }))
    with (state / "builds.txt").open("a") as out:
        out.write(" ".join(sys.argv[1:]) + "\\n")
    if plan.get("build_hang"):
        import subprocess, time
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
        (state / "grandchild.pid").write_text(str(child.pid))
        time.sleep(600)
    if plan.get("build_exit"):
        print("error: could not compile", file=sys.stderr)
        sys.exit(plan["build_exit"])
    for name, kind in plan["artifacts"]:
        print(json.dumps({
            "reason": "compiler-artifact",
            "target": {"name": name, "kind": [kind]},
            "profile": {"test": True},
            "executable": str(state / name) if name in plan.get("present", [name]) else str(state / "absent"),
        }))
    print(json.dumps({"reason": "build-finished", "success": True}))
''')


class Reproducer(unittest.TestCase):
    def test_supervise_sweeps_the_group_while_the_child_is_still_registered(self):
        spec = importlib.util.spec_from_file_location("reproduce_test", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        run, registered = module.Run(types.SimpleNamespace(
            test="t", package="p", target="lib", attempts=1, watchdog=30.0, release=False,
        )), []
        sweep = module.stop_group

        def recording_sweep(process):
            registered.append(run.child is process)
            sweep(process)

        module.__dict__["stop_group"] = recording_sweep
        with tempfile.TemporaryDirectory() as directory:
            out, err = Path(directory) / "out", Path(directory) / "err"
            status = module.supervise(run, [sys.executable, "-c", "pass"], out, err)
        self.assertEqual((status, registered, run.child), (0, [True], None))

    def test_an_interruption_during_the_spawn_still_stops_the_command(self):
        module = self.module()
        args = types.SimpleNamespace(test="t", package="p", target="lib", attempts=1, watchdog=30.0, release=False)
        run = module.Run(args)
        spawn, spawned = module.subprocess.Popen, []

        def interrupted_spawn(*argv, **options):
            process = spawn(*argv, **options)
            spawned.append(process.pid)
            run.interrupt(signal.SIGTERM, None)
            return process

        module.subprocess.Popen = interrupted_spawn
        self.addCleanup(setattr, module.subprocess, "Popen", spawn)
        with tempfile.TemporaryDirectory() as directory:
            out, err = Path(directory) / "out", Path(directory) / "err"
            with self.assertRaises(module.Stop) as stopped:
                module.supervise(run, ["sleep", "600"], out, err)
        self.assertEqual(stopped.exception.code, module.INTERRUPTED)
        self.assertIsNone(run.child)
        [pid] = spawned
        for _ in range(50):
            try:
                state = Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()[0]
            except OSError:
                return
            if state == "Z":
                return
            time.sleep(0.1)
        self.fail(f"the command spawned during the interruption, pid {pid}, survived")

    def module(self):
        spec = importlib.util.spec_from_file_location("reproduce_test", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kestrike-reproduce-")
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        for name in ("kestrike", "store_history", "other_suite"):
            path = self.state / name
            path.write_text(EXECUTABLE)
            path.chmod(0o755)
        self.cargo = self.state / "cargo"
        self.cargo.write_text(CARGO)
        self.cargo.chmod(0o755)
        self.artifacts = self.state / "artifacts"
        (self.state / "pkg").mkdir()

    def plan(self, outcomes=("pass",), listed=(LISTED,), ignored=(), **extra):
        plan = {
            "outcomes": list(outcomes), "listed": list(listed), "ignored": list(ignored),
            "passed": PASSED, "failed": FAILED, "zero": ZERO,
            "artifacts": [["kestrike", "lib"], ["store_history", "test"], ["other_suite", "test"]],
        }
        plan.update(extra)
        (self.state / "plan.json").write_text(json.dumps(plan))

    def repository(self):
        tree = self.state / "tree"
        tree.mkdir()
        git = ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-C", str(tree)]
        (tree / "tracked.txt").write_text("one\n")
        subprocess.run([*git, "init", "-q"], check=True)
        subprocess.run([*git, "add", "tracked.txt"], check=True)
        subprocess.run([*git, "commit", "-q", "-m", "init"], check=True)
        return tree

    def command(self, attempts=3, test=TEST, target="lib", watchdog="30", run_id="ci-7", cargo=None, extra=()):
        return [
            sys.executable, str(SCRIPT), "--package", "kestrike", "--target", target, "--test", test,
            "--attempts", str(attempts), "--watchdog", watchdog, "--artifacts", str(self.artifacts),
            "--run-id", run_id, "--lane", "nightly", "--cargo", cargo or str(self.cargo), *extra,
        ]

    def environment(self, **extra):
        env = {"PATH": os.environ["PATH"], "FAKE_STATE": str(self.state), **extra}
        return env

    def reproduce(self, *args, env=None, cwd=None, **kwargs):
        env = env or self.environment()
        return subprocess.run(
            self.command(*args, **kwargs), capture_output=True, text=True, env=env, cwd=cwd, check=False,
        )

    def lines(self, name):
        path = self.state / name
        return path.read_text().splitlines() if path.exists() else []

    def artifact(self, directory="ci-7-1-nightly"):
        try:
            return json.loads((self.artifacts / directory / "artifact.json").read_text())
        except (OSError, ValueError) as error:
            self.fail(f"no artifact in {directory}: {error}")

    def assert_group_stopped(self):
        pid = int((self.state / "grandchild.pid").read_text())
        for _ in range(50):
            try:
                state = Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()[0]
            except OSError:
                return
            if state == "Z":
                return
            time.sleep(0.1)
        self.fail(f"the attempt's child {pid} outlived the attempt")

    def test_builds_once_and_stops_exactly_at_n_clean_attempts(self):
        self.plan()
        result = self.reproduce(attempts=3, env=self.environment(RUST_BACKTRACE="1", CARGO_PROFILE_DEV_OPT_LEVEL="1", UNLISTED="x",
                                                                 CARGO_UNSTABLE_BUILD_STD="std", ASAN_OPTIONS="detect_leaks=0",
                                                                 KESTRIKE_MAPPINGS="/run/kestrike/mappings"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "not reproduced in 3 attempts")
        self.assertEqual(len(self.lines("builds.txt")), 1)
        self.assertEqual(len(self.lines("runs.txt")), 3)
        record = self.artifact()
        self.assertEqual(len(record["attempts"]), 3)
        for field in ("test_id", "isolation", "executable", "revision", "toolchain", "environment", "host", "ci_run"):
            self.assertIn(field, record)
        self.assertEqual(record["dependencies"],
                         ["kestrike 0.1.0", "loom 0.7.2 registry+https://github.com/rust-lang/crates.io-index"],
                         "a dependency is named with the source its version resolved from; a path package by the tree")
        self.assertEqual(record["environment"], {"RUST_BACKTRACE": "1", "CARGO_PROFILE_DEV_OPT_LEVEL": "1",
                                                 "CARGO_UNSTABLE_BUILD_STD": "std", "ASAN_OPTIONS": "detect_leaks=0",
                                                 "KESTRIKE_MAPPINGS": "/run/kestrike/mappings"})
        self.assertTrue((self.artifacts / "ci-7-1-nightly" / "build.stderr").exists())
        self.assertIn("attempt stderr", (self.artifacts / "ci-7-1-nightly" / "attempt-1.stderr").read_text())
        self.assertEqual(len(record["executable"]["sha256"]), 64)
        self.assertEqual(record["attempts"][0]["summary"], [PASSED])

    def test_rejects_bad_selections_and_bounds_before_any_attempt(self):
        for listed, ignored in (((), ()), ((LISTED, LISTED), ()), ((LISTED,), (LISTED, LISTED))):
            self.plan(listed=listed, ignored=ignored)
            result = self.reproduce(run_id=f"select-{len(listed)}-{len(ignored)}")
            self.assertEqual(result.returncode, 2, result.stdout)
        self.plan(present=["store_history"])
        self.assertEqual(self.reproduce(run_id="missing").returncode, 2)
        self.assertEqual(self.lines("runs.txt"), [])
        (self.state / "builds.txt").unlink()
        self.plan(listed=("crates/kestrike/src/storage/os.rs - storage::os::Platform (line 146): test",))
        doc = "crates/kestrike/src/storage/os.rs - storage::os::Platform (line 146)"
        self.assertEqual(self.reproduce(test=doc, run_id="doc").returncode, 2)
        self.assertEqual(self.reproduce(attempts=0, run_id="bound").returncode, 2)
        self.assertEqual(self.reproduce(watchdog="0", run_id="watchdog").returncode, 2)
        self.assertEqual(self.reproduce(watchdog="nan", run_id="nan").returncode, 2)
        self.assertEqual(self.reproduce(watchdog="inf", run_id="inf").returncode, 2)
        self.assertEqual(self.lines("builds.txt"), [], "rejected before the build")
        self.assertEqual(self.reproduce(run_id="tool", cargo="/nonexistent/cargo").returncode, 2)
        self.assertEqual(self.lines("runs.txt"), [])

    def test_the_first_failure_stops_the_run_and_a_later_pass_keeps_its_evidence(self):
        self.plan(outcomes=("pass", "fail", "pass"))
        result = self.reproduce(attempts=5)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertEqual(len(self.lines("runs.txt")), 2)
        failed = self.artifacts / "ci-7-1-nightly"
        self.assertIn(FAILED, (failed / "attempt-2.stdout").read_text())
        self.assertEqual(self.artifact()["attempts"][1]["exit"], 101)
        (self.state / "runs.txt").unlink()
        self.plan(outcomes=("pass",))
        self.assertEqual(self.reproduce(attempts=2).returncode, 0)
        self.assertEqual(self.artifact()["exit"], 1, "the failing run's artifact stays")
        self.assertEqual(self.artifact("ci-7-1-nightly.2")["exit"], 0)

    def test_an_attempt_passes_only_on_the_requested_id_s_own_ok_outcome(self):
        self.plan(outcomes=("pass",))
        result = self.reproduce(attempts=1, run_id="genuine")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.artifact("genuine-1-nightly")["attempts"][0]["outcomes"],
                         {"ok": [TEST], "FAILED": [], "ignored_names": []})
        for outcome, reason in (
            ("unrelated", "passed ['other::test'], failed [] and ignored []"),
            ("missing", "passed [], failed [] and ignored []"),
            ("duplicate", f"passed {[TEST, TEST]}, failed [] and ignored []"),
            ("beside-ignored", f"passed {[TEST]}, failed [] and ignored ['other::test']"),
            ("beside-ok", f"passed {[TEST, 'other::test']}, failed [] and ignored []"),
            ("beside-failed", f"passed {[TEST]}, failed ['other::test'] and ignored []"),
        ):
            with self.subTest(outcome):
                self.plan(outcomes=(outcome,))
                result = self.reproduce(attempts=1, run_id=outcome)
                self.assertEqual(result.returncode, 4, result.stdout)
                self.assertIn(f"attempt 1 {reason}, not exactly {TEST!r} once", result.stdout)

    def test_build_failure_crash_and_watchdog_have_distinct_codes(self):
        self.plan(build_exit=101)
        self.assertEqual(self.reproduce(run_id="build").returncode, 3)
        self.plan(metadata_exit=3)
        self.assertEqual(self.reproduce(run_id="metadata").returncode, 2)
        self.assertEqual(len(self.lines("builds.txt")), 1, "rejected before a second build")
        self.plan(outcomes=("crash",))
        self.assertEqual(self.reproduce(run_id="crash").returncode, 4)
        self.plan(outcomes=("hang",))
        started = time.time()
        result = self.reproduce(watchdog="1", run_id="hang")
        self.assertEqual(result.returncode, 6, result.stdout)
        self.assertLess(time.time() - started, 30)
        self.assertEqual(self.artifact("hang-1-nightly")["attempts"][0]["status"], "watchdog")
        self.assert_group_stopped()
        self.plan(outcomes=("stubborn",))
        result = self.reproduce(watchdog="1", run_id="stubborn")
        self.assertEqual(result.returncode, 6, result.stdout)
        self.assert_group_stopped()

    def test_an_interruption_stops_the_attempt_and_keeps_its_artifact(self):
        self.plan(outcomes=("hang",))
        env = self.environment()
        process = subprocess.Popen(self.command(run_id="cancel"), stdout=subprocess.PIPE, text=True, env=env)
        for _ in range(100):
            if (self.state / "grandchild.pid").exists():
                break
            time.sleep(0.1)
        process.send_signal(signal.SIGTERM)
        output, _ = process.communicate(timeout=30)
        self.assertEqual(process.returncode, 5, output)
        record = self.artifact("cancel-1-nightly")
        self.assertEqual((record["exit"], record["attempts"][0]["status"]), (5, "interrupted"))
        self.assertIn("running 1 test", (self.artifacts / "cancel-1-nightly" / "attempt-1.stdout").read_text())
        self.assert_group_stopped()

    def test_an_interruption_during_the_build_stops_the_build_group(self):
        self.plan(build_hang=True)
        self.interrupt_during("build-cancel")

    def test_an_interruption_during_the_listing_stops_the_listing_group(self):
        self.plan(list_hang=True)
        self.interrupt_during("list-cancel")

    def test_an_interruption_during_cargo_metadata_stops_its_group(self):
        self.plan(metadata_hang=True)
        self.interrupt_during("metadata-cancel")

    def interrupt_during(self, run_id, **env):
        process = subprocess.Popen(
            self.command(run_id=run_id), stdout=subprocess.PIPE, text=True, env=self.environment(**env),
        )
        for _ in range(100):
            if (self.state / "grandchild.pid").exists():
                break
            time.sleep(0.1)
        process.send_signal(signal.SIGTERM)
        output, _ = process.communicate(timeout=30)
        self.assertEqual(process.returncode, 5, output)
        self.assertEqual(self.artifact(f"{run_id}-1-nightly")["exit"], 5)
        self.assertEqual(self.lines("runs.txt"), [])
        self.assert_group_stopped()

    def test_the_listing_and_attempts_run_from_the_package_root(self):
        self.plan()
        package = self.state / "pkg"
        self.assertEqual(self.reproduce(attempts=2, run_id="root").returncode, 0)
        self.assertEqual(self.lines("lists.txt"), [f"cwd={package}"] * 2)
        self.assertEqual([line.rsplit(" ", 1)[1] for line in self.lines("runs.txt")], [f"cwd={package}"] * 2)
        self.assertEqual(self.artifact("root-1-nightly")["package_root"], str(package))

    def test_the_artifact_records_untracked_files_beside_the_dirty_flag(self):
        self.plan()
        tree = self.repository()
        (tree / ".cargo").mkdir()
        (tree / ".cargo" / "config.toml").write_text('[build]\nrustflags = ["-C", "target-cpu=native"]\n')
        self.assertEqual(self.reproduce(attempts=1, run_id="clean", cwd=tree).returncode, 0)
        record = self.artifact("clean-1-nightly")
        head = subprocess.run(["git", "-C", str(tree), "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
        self.assertEqual(record["revision"], head.stdout.strip())
        self.assertEqual((record["dirty"], record["untracked"]), (False, [".cargo/config.toml"]),
                         "the record names each untracked file, so a consumer can tell the files a run writes from others")
        (tree / "tracked.txt").write_text("two\n")
        self.assertEqual(self.reproduce(attempts=1, run_id="dirty", cwd=tree).returncode, 0)
        record = self.artifact("dirty-1-nightly")
        self.assertEqual((record["dirty"], record["untracked"]), (True, [".cargo/config.toml"]))

    def test_a_selected_ignored_test_runs_and_a_zero_test_attempt_never_passes(self):
        self.plan(ignored=(LISTED,))
        self.assertEqual(self.reproduce(attempts=1, run_id="ignored").returncode, 0)
        self.assertIn("--ignored", self.lines("runs.txt")[0])
        self.plan()
        self.assertEqual(self.reproduce(attempts=1, run_id="plain").returncode, 0)
        self.assertNotIn("--ignored", self.lines("runs.txt")[1])
        self.plan(outcomes=("zero",))
        result = self.reproduce(attempts=1, run_id="zero")
        self.assertEqual(result.returncode, 4, result.stdout)

    def test_release_builds_the_release_profile_like_the_loom_lane(self):
        self.plan()
        self.assertEqual(self.reproduce(attempts=1, run_id="debug").returncode, 0)
        self.assertNotIn("--release", self.lines("builds.txt")[0].split())
        self.assertFalse(self.artifact("debug-1-nightly")["release"])
        result = self.reproduce(attempts=1, run_id="release", extra=("--release",))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("--release", self.lines("builds.txt")[1].split())
        record = self.artifact("release-1-nightly")
        self.assertTrue(record["release"])
        self.assertIn("--release", record["build"]["command"])

    def test_one_target_is_resolved_even_when_lib_and_integration_both_build(self):
        self.plan()
        self.assertEqual(self.reproduce(attempts=1, run_id="lib").returncode, 0)
        self.assertEqual([line.split()[0] for line in self.lines("runs.txt")], ["kestrike"])
        self.assertIn("--lib", self.lines("builds.txt")[0])
        result = self.reproduce(attempts=1, run_id="integration", target="store_history")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.lines("runs.txt")[1].split()[0], "store_history")
        self.assertIn("--test store_history", self.lines("builds.txt")[1])

    def test_an_unwritable_artifact_is_a_tool_failure_not_a_reproduction(self):
        self.plan()

        def limit_file_size():
            resource.setrlimit(resource.RLIMIT_FSIZE, (64, 64))

        result = subprocess.run(
            self.command(attempts=1, run_id="full"), capture_output=True, text=True,
            env=self.environment(), preexec_fn=limit_file_size, check=False,
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("artifact.json could not be written", result.stdout)
        self.assertNotIn("Traceback", result.stderr)

    def test_the_artifact_key_carries_the_ci_run_attempt(self):
        self.plan()
        env = self.environment(GITHUB_RUN_ATTEMPT="2")
        self.assertEqual(self.reproduce(attempts=1, env=env).returncode, 0)
        self.assertEqual(self.artifact("ci-7-2-nightly")["run_attempt"], "2")

    def test_an_interruption_during_a_toolchain_probe_stops_its_group(self):
        self.plan()
        rustc = self.state / "rustc"
        rustc.write_text(
            "#!/bin/sh\n"
            f"{sys.executable} -c 'import time; time.sleep(600)' &\n"
            f"echo $! > {self.state / 'grandchild.pid'}\n"
            "sleep 600\n"
        )
        rustc.chmod(0o755)
        self.interrupt_during("probe-cancel", RUSTC=str(rustc))

    def test_a_passing_attempt_leaves_no_group_members_behind(self):
        self.plan(outcomes=("stray", "pass"))
        result = self.reproduce(attempts=2, run_id="stray")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assert_group_stopped()

    def test_the_toolchain_records_the_compiler_cargo_selects(self):
        self.plan()
        rustc = self.state / "rustc"
        rustc.write_text("#!/bin/sh\necho 'rustc 1.83.0-fake (0000000 2024-11-28)'\n")
        rustc.chmod(0o755)
        env = self.environment(RUSTC=str(rustc), RUSTC_WRAPPER="sccache")
        self.assertEqual(self.reproduce(attempts=1, run_id="rustc", env=env).returncode, 0)
        record = self.artifact("rustc-1-nightly")
        self.assertTrue(record["toolchain"]["rustc"].startswith("rustc 1.83.0-fake"), record["toolchain"])
        self.assertEqual(record["environment"], {"RUSTC": str(rustc), "RUSTC_WRAPPER": "sccache"})


class QuarantineLane(unittest.TestCase):
    """Run `rust-lane.sh quarantine` over a copied registry with a fake cargo and rustc."""

    CHURN = "storage::churn_tests::churn_replay"
    HISTORY = "campaign_histories_satisfy_the_store_contract"
    # A recipe under the lane's pinned build profile.
    PINNED = (f"RUSTUP_TOOLCHAIN={STABLE} CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_DEV_DEBUG=line-tables-only "
              f"python3 scripts/reproduce-test.py --package kestrike --target store_history --test {HISTORY} "
              "--attempts 20")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kestrike-quarantine-")
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / "state"
        self.work = Path(self.temp.name) / "work"
        self.bin = Path(self.temp.name) / "bin"
        for directory in (self.state / "pkg", self.work / "scripts", self.work / "verification", self.bin):
            directory.mkdir(parents=True)
        for name in ("scripts/select-tests.py", "scripts/reproduce-test.py", "scripts/test-inventory.json", "verification/obligations.json"):
            try:
                shutil.copy(ROOT / name, self.work / name)
            except OSError as error:
                self.fail(f"cannot stage {name}: {error}")
        for path, text in ((self.bin / "cargo", CARGO), (self.bin / "rustc", RUSTC)):
            path.write_text(text)
            path.chmod(0o755)
        for name in ("kestrike", "store_history"):
            path = self.state / name
            path.write_text(EXECUTABLE)
            path.chmod(0o755)

    def plan(self, test, outcomes, package="kestrike"):
        (self.state / "plan.json").write_text(json.dumps({
            "package": package, "outcomes": list(outcomes),
            "listed": [f"{test}: test"], "ignored": [f"{test}: test"],
            "passed": PASSED, "failed": FAILED, "zero": ZERO,
            "artifacts": [["kestrike", "lib"], ["store_history", "test"]],
        }))

    def lane(self, recipes=None, **extra_env):
        """Quarantine each named test in every cfg that ignores it, as the census requires of a miri twin row."""
        try:
            registry = json.loads((ROOT / "scripts/test-registry.json").read_text())
        except (OSError, ValueError) as error:
            self.fail(f"the committed registry is unreadable: {error}")
        for row in registry["rows"] if recipes is not None else []:
            if row["id"] in recipes:
                row.update({"class": "flaky-quarantine", "cause": "flaky: fixture", "recipe": recipes[row["id"]]})
            elif row["class"] == "flaky-quarantine":
                row["class"] = "diagnostic-replay"
        (self.work / "scripts/test-registry.json").write_text(json.dumps(registry))
        env = {k: v for k, v in os.environ.items() if not k.startswith("GITHUB_")}
        env.update(FAKE_STATE=str(self.state), PATH=f"{self.bin}:{env['PATH']}", STABLE=STABLE,
                   EVIDENCE=str(self.work / "evidence"), **extra_env)
        result = subprocess.run(["bash", str(ROOT / "scripts/rust-lane.sh"), "quarantine"], cwd=self.work,
                                env=env, capture_output=True, text=True, timeout=120, check=False)
        summary = self.work / "evidence/summary.md"
        return result.returncode, summary.read_text() if summary.exists() else "", result.stdout + result.stderr

    def recipe(self, package, target, test):
        return f"python3 scripts/reproduce-test.py --package {package} --target {target} --test {test} --attempts 2"

    def test_a_pinned_recipe_runs_twenty_attempts_with_its_pinned_environment(self):
        self.plan(self.HISTORY, ("pass",))
        code, summary, output = self.lane(
            {self.HISTORY: self.PINNED},
            RUSTUP_TOOLCHAIN="ambient-toolchain", CARGO_PROFILE_DEV_OPT_LEVEL="3",
            CARGO_PROFILE_DEV_DEBUG="full", RUST_BACKTRACE="1",
        )
        self.assertEqual(code, 0, summary + output)
        self.assertIn(f"- `{self.HISTORY}`: not reproduced in 20 attempts (exit 0)", summary)
        self.assertIn(f"- policy gap: {self.HISTORY} lacks text for ticket, date, expiry, first_failure", summary)
        self.assertIn("not evidence of a fix", summary)
        records = list((self.work / "evidence/reproduce").glob("*/artifact.json"))
        self.assertEqual(len(records), 1)
        record = json.loads(records[0].read_text())
        self.assertEqual(record["attempts_requested"], 20)
        self.assertEqual(len(record["attempts"]), 20)
        self.assertEqual(record["watchdog_seconds"], 1500.0)
        self.assertEqual((record["package"], record["target"], record["test_id"]),
                         ("kestrike", "store_history", self.HISTORY))
        expected = {
            "RUSTUP_TOOLCHAIN": STABLE, "CARGO_PROFILE_DEV_OPT_LEVEL": "1",
            "CARGO_PROFILE_DEV_DEBUG": "line-tables-only", "RUST_BACKTRACE": "1",
        }
        build_env = json.loads((self.state / "build-env.json").read_text())
        for name, value in expected.items():
            self.assertEqual(record["environment"][name], value)
            self.assertEqual(build_env[name], value)
        self.assertEqual(len((self.state / "builds.txt").read_text().splitlines()), 1)
        runs = (self.state / "runs.txt").read_text().splitlines()
        self.assertEqual(len(runs), 20)
        for run in runs:
            self.assertEqual(run.split(), ["store_history", "--exact", self.HISTORY,
                                         "--test-threads=1", "--ignored", f"cwd={self.state / 'pkg'}"])

    def test_a_pinned_recipe_keeps_its_pins_when_pasted_in_a_shell(self):
        self.plan(self.HISTORY, ("pass",))
        env = dict(os.environ, FAKE_STATE=str(self.state), PATH=f"{self.bin}:{os.environ['PATH']}",
                   RUSTUP_TOOLCHAIN="ambient-toolchain", CARGO_PROFILE_DEV_OPT_LEVEL="3",
                   CARGO_PROFILE_DEV_DEBUG="full")
        artifacts = self.work / "manual"
        command = self.PINNED + " " + shlex.join(["--artifacts", str(artifacts)])
        result = subprocess.run(["bash", "--noprofile", "--norc", "-c", command], cwd=self.work,
                                env=env, capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), "not reproduced in 20 attempts")
        record, = artifacts.glob("*/artifact.json")
        environment = json.loads(record.read_text())["environment"]
        build_env = json.loads((self.state / "build-env.json").read_text())
        for name, value in {"RUSTUP_TOOLCHAIN": STABLE, "CARGO_PROFILE_DEV_OPT_LEVEL": "1",
                            "CARGO_PROFILE_DEV_DEBUG": "line-tables-only"}.items():
            self.assertEqual(environment[name], value)
            self.assertEqual(build_env[name], value)

    def test_a_library_row_runs_by_its_lib_target(self):
        self.plan(self.CHURN, ("pass",))
        code, summary, output = self.lane(
            {self.CHURN: self.recipe("kestrike", "lib", self.CHURN)},
            CARGO_PROFILE_DEV_OPT_LEVEL="3", CARGO_PROFILE_DEV_DEBUG="full",
        )
        self.assertEqual(code, 0, summary + output)
        build_env = json.loads((self.state / "build-env.json").read_text())
        self.assertEqual(build_env["RUSTUP_TOOLCHAIN"], STABLE)
        self.assertEqual(build_env["CARGO_PROFILE_DEV_OPT_LEVEL"], "3")
        self.assertEqual(build_env["CARGO_PROFILE_DEV_DEBUG"], "full")
        self.assertIn(f"- `{self.CHURN}`: not reproduced in 2 attempts (exit 0)", summary)
        digest = hashlib.sha256((self.state / "kestrike").read_bytes()).hexdigest()[:16]
        self.assertIn(f"- `{self.CHURN}`: executable `kestrike` sha256 `{digest}`, 2 of 2 attempts, "
                      "last `test result: ok. 1 passed; 0 failed; 0 ignored;", summary)
        self.assertIn(f"- `{self.CHURN}` (miri): reproduced through its ordinary row", summary)
        self.assertIn("### Quarantine: 1 flaky-quarantine row(s) by exact ID", summary)
        runs = (self.state / "runs.txt").read_text().splitlines()
        self.assertEqual([run.split()[0] for run in runs], ["kestrike", "kestrike"])

    def test_a_reproduction_is_reported_and_an_unreported_exit_is_red(self):
        recipes = {self.HISTORY: self.recipe("kestrike", "store_history", self.HISTORY)}
        self.plan(self.HISTORY, ("fail",))
        code, summary, output = self.lane(recipes)
        self.assertEqual(code, 0, summary + output)
        self.assertIn(f"- `{self.HISTORY}`: reproduced: reproduced on attempt 1 (exit 1)", summary)
        self.assertRegex(summary, rf"- `{re.escape(self.HISTORY)}`: executable `store_history` sha256 "
                                  r"`[0-9a-f]{16}`, 1 of 2 attempts, last `test result: FAILED\.")
        for outcome in ("kill-reproducer", "block-artifact"):
            self.plan(self.HISTORY, (outcome,))
            code, summary, output = self.lane(recipes)
            self.assertEqual(code, 1, f"{outcome}: {summary}{output}")
            self.assertIn(f"::error::{self.HISTORY}: ", output)
            self.assertNotIn("Traceback", output)
            if outcome == "block-artifact":
                self.assertNotIn("executable `", summary.rsplit("### Quarantine", 1)[1])

    def test_other_environment_prefixes_are_unusable_without_running_a_build(self):
        self.plan(self.HISTORY, ("pass",))
        command = self.recipe("kestrike", "store_history", self.HISTORY)
        toolchain = f"RUSTUP_TOOLCHAIN={STABLE}"
        prefix = f"{toolchain} CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_DEV_DEBUG=line-tables-only"
        marker = self.work / "injected"
        prefixes = (
            toolchain,
            prefix.replace(toolchain, "RUSTUP_TOOLCHAIN=0.0.0"),
            prefix.replace("OPT_LEVEL=1", "OPT_LEVEL=3"),
            prefix.replace("DEBUG=line-tables-only", "DEBUG=0"),
            "RUSTC_WRAPPER=unexpected " + prefix,
            prefix + " RUSTC_WRAPPER=unexpected",
            prefix + " CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false",
            prefix + " " + toolchain,
            prefix + f"; touch {marker};",
            prefix + f"$(touch {marker})",
            "env " + prefix,
            " ".join(reversed(prefix.split())),
        )
        for bad_prefix in prefixes:
            with self.subTest(prefix=bad_prefix):
                code, summary, output = self.lane({self.HISTORY: f"{bad_prefix} {command}"})
                self.assertEqual(code, 1, summary + output)
                self.assertIn(f"::error::{self.HISTORY}: unusable recipe", output)
                self.assertNotIn("Traceback", output)
                self.assertFalse((self.state / "builds.txt").exists())
                self.assertFalse((self.state / "runs.txt").exists())
                self.assertFalse(marker.exists())

    def test_a_malformed_recipe_is_unusable_and_later_rows_still_run(self):
        self.plan(self.HISTORY, ("pass",))
        code, summary, output = self.lane({
            self.CHURN: "python3 scripts/reproduce-test.py --test 'unterminated",
            self.HISTORY: self.recipe("kestrike", "store_history", self.HISTORY),
        })
        self.assertEqual(code, 1, summary + output)
        self.assertNotIn("Traceback", output)
        self.assertIn(f"::error::{self.CHURN}: unusable recipe", output)
        self.assertIn(f"- `{self.CHURN}`: not run; the recipe needs", summary)
        self.assertIn(f"- `{self.HISTORY}`: not reproduced in 2 attempts (exit 0)", summary)
        digest = hashlib.sha256((self.state / "store_history").read_bytes()).hexdigest()[:16]
        self.assertIn(f"- `{self.HISTORY}`: executable `store_history` sha256 `{digest}`, 2 of 2 attempts, "
                      "last `test result: ok. 1 passed; 0 failed; 0 ignored;", summary)


if __name__ == "__main__":
    unittest.main()
