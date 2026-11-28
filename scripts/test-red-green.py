#!/usr/bin/env python3
"""Exercise red-green.py through the real runner with a fake cargo and a fake test executable.

The fake executable lists the test only when the carried `table_tests.rs` is
in its working directory. By default an attempt passes when `fix.marker` is
there and fails with the expected text otherwise; a plan.json entry for the
leg, named by the worktree directory, sets another outcome.
"""

import contextlib
import ctypes
import fcntl
import hashlib
import importlib.util
import io
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

# With the subreaper flag set, orphaned descendants reparent to this process
# and an exited one is a zombie until this process reaps it, so a leg process
# that outlives the command stays visible to the survival checks.
PR_SET_CHILD_SUBREAPER = 36
if ctypes.CDLL(None, use_errno=True).prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "prctl(PR_SET_CHILD_SUBREAPER) failed")

# The fixtures get the same modes under any caller's mask: a directory or file the tests create is writable by its
# owner alone unless a test changes its mode.
os.umask(0o022)
ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/red-green.py"
# Fixtures use the checkout's ignored `target/` because `red-green.py` rejects a temporary directory with an
# ancestor that other users can write.
FIXTURES = ROOT / "target"
TEST = "storage::device::table_tests::a_poll_reports_each_completion_once"
EXPECT = "a poll counts that completion as delivered"
PASSED = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s"
FAILED = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s"
TWO_LINES = "first payload line\nsecond payload line"
NO_EVIDENCE = "left no readable artifact.json or attempt output of its own in the receipt"
# The arguments that lead each Git step that builds a leg tree.
HOOKLESS = "-c core.hooksPath=/dev/null "

EXECUTABLE = textwrap.dedent('''\
    #!/usr/bin/env python3
    import json, os, signal, subprocess, sys, time
    from pathlib import Path
    state = Path(os.environ["FAKE_STATE"])
    tree = Path.cwd()
    leg = json.loads((state / "plan.json").read_text()).get(tree.name, {})
    test = sys.argv[sys.argv.index("--exact") + 1]
    (state / f"{tree.name}.pid").write_text(str(os.getppid()))
    if "--list" in sys.argv:
        files = {}
        for directory, _, names in os.walk(tree):
            for name in names:
                if name != ".git":
                    path = Path(directory, name)
                    files[str(path.relative_to(tree))] = path.read_text(errors="surrogateescape")
        (state / f"{tree.name}-tree.json").write_text(json.dumps(files))
        listed = (tree / "table_tests.rs").exists() and "--ignored" not in sys.argv
        print(f"{test}: test" if listed else "")
        sys.exit(0)
    outcome = leg.get("attempt") or ("pass" if (tree / "fix.marker").exists() else "fail")
    print("running 1 test", flush=True)
    if outcome in ("hang", "stubborn"):
        if outcome == "stubborn":
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        (state / "supervised.pid").write_text(str(os.getpid()))
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
        (state / "grandchild.pid.new").write_text(str(child.pid))
        (state / "grandchild.pid.new").rename(state / "grandchild.pid")
        time.sleep(600)
    if outcome == "crash":
        os.kill(os.getpid(), signal.SIGSEGV)
    if outcome.endswith("-receipt"):
        receipt = Path(os.readlink("/proc/self/fd/1")).parents[1] / "receipt.json"
        if outcome == "block-receipt":
            receipt.mkdir()
        elif outcome == "file-receipt":
            receipt.write_text("planted\\n")
        else:
            receipt.symlink_to(state / "planted.txt")
        outcome = "pass"
    if outcome == "pass":
        print(f"test {test} ... ok\\n\\nPASSED_LINE")
        sys.exit(0)
    if outcome == "stderr-text":
        print(f"thread '{test}' (4242) panicked at stderr_fixture.rs:1:1:\\nEXPECT_PLAIN", file=sys.stderr)
    text = {"other-text": "assertion failed: the counters moved",
            "stderr-text": "assertion failed: the counters moved",
            "should-panic": "note: panic did not contain expected string\\n      panic message: \\"the counters moved\\"\\n"
                            " expected substring: \\"zzz\\"",
            "non-string": "Box<dyn Any>\\nnote: expected panic with string value,\\n found non-string value: "
                          "`TypeId(0x1)`\\n     expected substring: \\"zzz\\"",
            "test-message": "test fixture lost a completion",
            "adjacent": "first payload line\\nsecond payload line",
            "split": "first payload line\\nnote: run with the payload split\\nsecond payload line",
            "no-panic": "note: test did not panic as expected at table_tests.rs:9:5"}.get(outcome, EXPECT_TEXT)
    kind = " - should panic" if outcome in ("should-panic", "non-string", "no-panic") else ""
    print(f"test {test}{kind} ... FAILED\\n\\nfailures:\\n\\n---- {test} stdout ----\\n\\n"
          f"thread '{test}' (4242) panicked at table_tests.rs:9:5:\\n{text}\\n"
          "note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace\\n"
          "note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.\\n"
          "stack backtrace:\\n   0: table_tests::frame\\n             at ./table_tests.rs:9:5\\n\\n"
          f"\\nfailures:\\n    {test}\\n\\nFAILED_LINE")
    sys.exit(101)
''').replace("PASSED_LINE", PASSED).replace("FAILED_LINE", FAILED).replace("EXPECT_TEXT", repr(EXPECT)).replace(
    "EXPECT_PLAIN", EXPECT)

CARGO = textwrap.dedent('''\
    #!/usr/bin/env python3
    import fcntl, json, os, subprocess, sys, time
    from pathlib import Path
    state = Path(os.environ["FAKE_STATE"])
    tree = Path.cwd()
    leg = json.loads((state / "plan.json").read_text()).get(tree.name, {})
    if sys.argv[1:] == ["-V"]:
        print("cargo 1.99.0 (5f94df478 2026-08-27)")
        sys.exit(0)
    if sys.argv[1:2] == ["metadata"]:
        print(json.dumps({"packages": [
            {"name": name, "version": "0.1.0", "manifest_path": str(tree / "Cargo.toml")}
            for name in ("kestrike", "fixture-pkg")
        ]}))
        sys.exit(leg.get("metadata_exit", 0))
    (state / f"{tree.name}.pid").write_text(str(os.getppid()))
    with open(Path(os.environ["CARGO_TARGET_DIR"]) / "red-green.lock", "a") as probe:
        try:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            held = False
        except BlockingIOError:
            held = True
    with (state / "builds.txt").open("a") as out:
        out.write(json.dumps({"leg": tree.name, "argv": sys.argv[1:], "lock_held": held, "stdin": sys.stdin.read(),
                              "target_dir": os.environ.get("CARGO_TARGET_DIR"),
                              "build_dir": os.environ.get("CARGO_BUILD_BUILD_DIR")}) + "\\n")
    if leg.get("replace"):
        Path(leg["replace"]).write_text("import sys\\nprint('Traceback (most recent call last): replaced')\\nsys.exit(1)\\n")
    if leg.get("build_hang"):
        (state / "supervised.pid").write_text(str(os.getpid()))
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
        (state / "grandchild.pid.new").write_text(str(child.pid))
        (state / "grandchild.pid.new").rename(state / "grandchild.pid")
        time.sleep(600)
    if leg.get("build_exit"):
        print("error: could not compile", file=sys.stderr)
        sys.exit(leg["build_exit"])
    target = ({"name": sys.argv[sys.argv.index("--test") + 1], "kind": ["test"]} if "--test" in sys.argv
              else {"name": "kestrike", "kind": ["lib"]})
    print(json.dumps({"reason": "compiler-artifact", "target": target,
                      "profile": {"test": True}, "executable": str(state / "kestrike")}))
''')

STUB_RUNNER = textwrap.dedent('''\
    import importlib.util, json, os, subprocess, sys
    from pathlib import Path
    spec = importlib.util.spec_from_file_location("real_runner", REAL)
    real = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(real)
    globals().update({name: value for name, value in vars(real).items() if not name.startswith("__")})
    if __name__ == "__main__":
        plan = json.loads((Path(os.environ["FAKE_STATE"]) / "plan.json").read_text())
        mode = plan.get(Path.cwd().name, {}).get("stub", "stop")
        if mode == "stop":
            print("Traceback (most recent call last): the runner stopped")
            sys.exit(1)
        done = subprocess.run([sys.executable, REAL, *sys.argv[1:]], capture_output=True, text=True)
        out, err = done.stdout, done.stderr
        own = Path([line for line in err.splitlines() if line.startswith("artifact: ")][-1].split(": ", 1)[1])
        if mode == "no-verdict":
            out = ""
        if mode == "no-artifact":
            err = "".join(line for line in err.splitlines(True) if not line.startswith("artifact: "))
        if mode == "no-stderr":
            own.with_name("attempt-1.stderr").unlink()
        if mode == "other-leg":
            [base] = own.parent.parent.glob("*-base")
            err += f"artifact: {base / 'artifact.json'}\\n"
        sys.stdout.write(out)
        sys.stderr.write(err)
        sys.exit(done.returncode)
''')


class RedGreen(unittest.TestCase):
    def setUp(self):
        FIXTURES.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="kestrike-red-green-test-", dir=FIXTURES)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.state, self.repo, self.tmp = self.root / "state", self.root / "repo", self.root / "tmp"
        for directory in (self.state, self.repo, self.tmp):
            directory.mkdir(mode=0o700)
        for name, text in (("kestrike", EXECUTABLE), ("cargo", CARGO),
                           ("rustc", "#!/bin/sh\necho 'rustc 1.99.0 (00000000 2026-01-01)'\n")):
            (self.state / name).write_text(text)
            (self.state / name).chmod(0o755)
        self.plan()
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "GITHUB_", "CARGO_"))}
        # The ceiling keeps Git's repository search from reaching the enclosing checkout when a command runs below
        # the fixture root.
        self.env.update(
            GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=str(self.root / "global"),
            GIT_CEILING_DIRECTORIES=str(self.root),
            GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com",
            GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com",
            FAKE_STATE=str(self.state), RUSTC=str(self.state / "rustc"), TMPDIR=str(self.tmp),
        )
        self.git("init", "-q", "-b", "main")
        self.base = self.commit({".gitignore": "/target\n", "Cargo.toml": "[package]\n", "table.rs": "unfixed\n"})
        (self.repo / "sub").mkdir()
        self.head = self.commit({"table.rs": "fixed\n", "fix.marker": "", "table_tests.rs": "#[test]\n",
                                 "notes.txt": "a head file\n", "sub/x.rs": "x\n", "t[a-z].rs": "", "tb.rs": "",
                                 "\udcff.rs": "", "cr\r.rs": ""})
        self.git("update-ref", "refs/remotes/origin/main", self.base)
        self.status = self.git("status", "--porcelain")

    def plan(self, **legs):
        (self.state / "plan.json").write_text(json.dumps(legs))

    def git(self, *args, input=None):
        return subprocess.run(("git", *args), cwd=self.repo, env=self.env, text=True, input=input,
                              capture_output=True, check=True).stdout.strip()

    def commit(self, files):
        for name, content in files.items():
            (self.repo / name).write_text(content)
            self.git("add", "--", name)
        self.git("commit", "-q", "-m", "change")
        return self.git("rev-parse", "HEAD")

    def command(self, *extra, carry=("table_tests.rs",), expect=EXPECT, script=SCRIPT, base=None, head=None,
                package="kestrike", target="lib", cargo=None, watchdog="30"):
        """Return the command line; base, head or cargo None names the fixture's own, and False omits the flag."""
        base = self.base if base is None else base
        head = self.head if head is None else head
        cargo = str(self.state / "cargo") if cargo is None else cargo
        return [sys.executable, str(script), "--package", package, "--target", target, "--test", TEST,
                "--expect", expect, *(["--carry", *carry] if carry else []), *(["--base", base] if base else []),
                *(["--head", head] if head else []), *([f"--cargo={cargo}"] if cargo else []),
                "--watchdog", watchdog, *extra]

    def red_green(self, *extra, env=None, cwd=None, input=None, **options):
        return subprocess.run(self.command(*extra, **options), cwd=cwd or self.repo, env=env or self.env, text=True,
                              capture_output=True, input=input)

    def module(self):
        spec = importlib.util.spec_from_file_location("red_green", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for handled in module.SIGNALS:
            self.addCleanup(signal.signal, handled, signal.getsignal(handled))
        return module

    def main_in_process(self, module, argv, *patches):
        """Run module.main(argv) in the fixture checkout, with the fixture's temporary directory, under patches and
        return (exit, stdout, stderr)."""
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.repo)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.dict(os.environ, self.env, clear=True))
            stack.enter_context(mock.patch.object(tempfile, "gettempdir", return_value=str(self.tmp)))
            for patch in patches:
                stack.enter_context(patch)
            stack.enter_context(contextlib.redirect_stdout(out))
            stack.enter_context(contextlib.redirect_stderr(err))
            code = module.main(argv)
        return code, out.getvalue(), err.getvalue()

    def fake_receipt(self, module, directory=None):
        args = types.SimpleNamespace(package="p", target="lib", test=TEST, expect=EXPECT, carry=["t.rs"],
                                     watchdog=30.0, release=False, cargo="cargo", artifacts=None)
        module.runner = module._load_runner(self.tmp)
        return module.Receipt(args, self.base, self.head, [], directory or self.root / "r", self.root, self.tmp)

    def first_stderr_line(self, process):
        """Return the process's first stderr line, or None when none arrives within 30 seconds."""
        lines = []
        reader = threading.Thread(target=lambda: lines.append(process.stderr.readline()), daemon=True)
        reader.start()
        reader.join(30)
        return lines[0] if lines else None

    def spawn(self, env=None):
        process = subprocess.Popen(self.command(), cwd=self.repo, env=env or self.env, text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(lambda: process.poll() is None and (process.kill(), process.communicate()))
        return process

    def git_wrapper(self, body):
        """Return an environment whose `git` runs body, a shell script in which GIT names the real git."""
        binaries = self.root / "bin"
        binaries.mkdir(exist_ok=True)
        wrapper = binaries / "git"
        wrapper.write_text("#!/bin/sh\n" + body.replace("GIT", f'"{shutil.which("git")}"'))
        wrapper.chmod(0o755)
        return dict(self.env, PATH=f"{binaries}{os.pathsep}{self.env['PATH']}")

    def builds(self):
        path = self.state / "builds.txt"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def receipt(self, result):
        lines = [line for line in result.stderr.splitlines() if line.startswith("receipt: ")]
        self.assertEqual(len(lines), 1, result.stderr)
        path = Path(lines[0].split(": ", 1)[1])
        return path, json.loads(path.read_text())

    def attempt_output(self, receipt, stream="stdout"):
        return (Path(receipt["legs"]["base"]["artifact"]).parent / f"attempt-1.{stream}").read_text()

    def assert_checkout_unchanged(self):
        self.assertEqual(self.git("worktree", "list", "--porcelain").count("worktree "), 1)
        self.assertEqual(self.git("status", "--porcelain"), self.status)
        self.assertEqual(list(self.tmp.iterdir()), [])

    def assert_gone(self, pid):
        for _ in range(100):
            try:
                state = Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()[0]
            except OSError:
                return
            if state == "Z":
                return
            time.sleep(0.1)
        self.fail(f"process {pid} outlived the command")

    def test_a_red_base_and_a_green_head_are_proven_and_the_receipt_binds_both_legs(self):
        result = self.red_green(cargo=False, env=dict(self.env, PATH=f"{self.state}{os.pathsep}{self.env['PATH']}"),
                                input="the command's standard input\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout,
                         f'red-green: {TEST} failed on {self.base[:12]} with "{EXPECT}" and passed on {self.head[:12]}\n')
        path, receipt = self.receipt(result)
        self.assertEqual(path.parent.parent, self.repo / "target/red-green")
        self.assertEqual((receipt["base"], receipt["head"], receipt["result"]), (self.base, self.head, "proven"))
        self.assertEqual(receipt["carried"],
                         [{"path": "table_tests.rs", "blob": self.git("rev-parse", f"{self.head}:table_tests.rs")}])
        self.assertEqual(receipt["scripts"], {name: hashlib.sha256((ROOT / "scripts" / name).read_bytes()).hexdigest()
                                              for name in ("red-green.py", "reproduce-test.py", "select-tests.py")})
        for leg, commit, code, verdict, dirty in (("base", self.base, 1, "reproduced: reproduced on attempt 1", True),
                                                  ("head", self.head, 0, "not reproduced in 1 attempts", False)):
            entry = receipt["legs"][leg]
            artifact = Path(entry["artifact"])
            self.assertEqual(artifact.parent.parent, path.parent)
            self.assertEqual(entry["sha256"], hashlib.sha256(artifact.read_bytes()).hexdigest())
            self.assertEqual((entry["exit"], entry["verdict"]), (code, verdict))
            self.assertGreater(entry["seconds"], 0)
            for stream in ("stdout", "stderr"):
                self.assertEqual(entry["attempt_sha256"][stream],
                                 hashlib.sha256(artifact.with_name(f"attempt-1.{stream}").read_bytes()).hexdigest())
            record = json.loads(artifact.read_text())
            self.assertEqual((record["revision"], record["test_id"], record["attempts_requested"],
                              record["watchdog_seconds"], record["release"], record["package"], record["target"],
                              record["dirty"], record["untracked"]),
                             (commit, TEST, 1, 30.0, False, "kestrike", "lib", dirty, []))
        self.assertIn(EXPECT, self.attempt_output(receipt))
        self.assertEqual(receipt["legs"]["base"]["expect_streams"], ["stdout"])
        self.assertEqual(shlex.split(receipt["command"]), [
            "python3", "scripts/red-green.py", "--package=kestrike", "--target=lib", f"--test={TEST}",
            f"--expect={EXPECT}", "--carry=table_tests.rs", f"--base={self.base}", f"--head={self.head}",
            "--watchdog=30.0"])
        base_tree = json.loads((self.state / "base-tree.json").read_text())
        self.assertEqual(base_tree, {".gitignore": "/target\n", "Cargo.toml": "[package]\n", "table.rs": "unfixed\n",
                                     "table_tests.rs": "#[test]\n"})
        builds = self.builds()
        self.assertEqual([build["leg"] for build in builds], ["base", "head"])
        build_dir = str(self.repo / "target/red-green/build")
        self.assertEqual({(build["target_dir"], build["build_dir"], build["lock_held"]) for build in builds},
                         {(build_dir, build_dir, True)})
        # Each build's standard input is the empty lock file, where the command's own holds a line.
        self.assertEqual([build["stdin"] for build in builds], ["", ""])
        self.assertEqual(builds[0]["argv"], builds[1]["argv"])
        self.assertEqual(builds[0]["argv"][:4], ["test", "-p", "kestrike", "--lib"])
        self.assert_checkout_unchanged()

    def test_the_repeat_command_parses_back_to_the_run_arguments(self):
        module = self.module()
        args = types.SimpleNamespace(package="kestrike", target="lib", test=TEST, expect="-x", release=True,
                                     carry=["-a.rs", "b c.rs"], watchdog=30.0, cargo="/c/cargo", artifacts="r")
        receipt = module.Receipt(args, self.base, self.head, [], self.root / "r" / "local-1-1", self.root, self.tmp)
        parsed = module.parse(shlex.split(receipt.record["command"])[2:])
        self.assertEqual((parsed.expect, parsed.carry, parsed.base, parsed.head, parsed.release, parsed.cargo,
                          parsed.artifacts, parsed.watchdog),
                         ("-x", ["-a.rs", "b c.rs"], self.base, self.head, True, "/c/cargo", str(self.root / "r"), 30.0))

    def test_a_checkout_hook_never_runs_in_a_leg_worktree(self):
        # The base holds the fix marker, so its test passes; the hook removes the marker from a base worktree.
        head = self.commit({"notes.txt": "a later head file\n"})
        log = self.state / "hook.log"
        hook = self.repo / ".git/hooks/post-checkout"
        hook.parent.mkdir(exist_ok=True)
        hook.write_text(f'#!/bin/sh\necho "$PWD" >> "{log}"\ncase "$PWD" in */base) rm -f fix.marker;; esac\n')
        hook.chmod(0o755)
        result = self.red_green(base=self.head, head=head)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertTrue(result.stdout.startswith("red-green refused: the test passes on the base: "), result.stdout)
        self.assertFalse(log.exists(), "a post-checkout hook ran in a leg worktree")
        self.assertIn("fix.marker", json.loads((self.state / "base-tree.json").read_text()))
        self.assert_checkout_unchanged()

    def test_a_leg_whose_tree_differs_from_its_commit_is_refused(self):
        # A smudge filter runs in the worktree Git is filling. Each mode changes one leg's tree in one way.
        mode, script = self.state / "filter-mode", self.state / "filter.sh"
        script.write_text(textwrap.dedent(f"""\
            #!/bin/sh
            case "$(cat "{mode}"):$PWD" in
                rewrite:*/base) sed s/unfixed/rewritten/;;
                ignored:*/base) cat; mkdir -p target; echo planted > target/planted;;
                untracked:*/base) cat; echo planted > extra.rs;;
                directory:*/base) cat; mkdir -p sub/empty;;
                sealed:*/base) cat; mkdir -p sealed; chmod 000 sealed;;
                missing:*/base) cat; rm -f Cargo.toml;;
                head:*/head) sed s/fixed/rewritten/;;
                *) cat;;
            esac
        """))
        script.chmod(0o755)
        self.git("config", "filter.mark.smudge", str(script))
        (self.repo / ".git/info/attributes").write_text("table.rs filter=mark\n")
        for name, leg, path in (("rewrite", "base", "table.rs"), ("ignored", "base", "target/planted"),
                                ("untracked", "base", "extra.rs"), ("directory", "base", "sub/empty"),
                                ("sealed", "base", "sealed"),
                                ("missing", "base", "Cargo.toml"),
                                ("head", "head", "table.rs"), ("none", None, None)):
            with self.subTest(name=name):
                mode.write_text(name)
                (self.state / "builds.txt").unlink(missing_ok=True)
                result = self.red_green()
                if leg is None:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    continue
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                [line] = result.stdout.splitlines()
                self.assertTrue(line.startswith(f"red-green refused: the {leg} leg's tree differs from its commit at "
                                                f"{path!r}"), line)
                _, receipt = self.receipt(result)
                legs = ["base"] if leg == "head" else []
                self.assertEqual((sorted(receipt["legs"]), [build["leg"] for build in self.builds()]), (legs, legs))
                self.assert_checkout_unchanged()

    def test_a_carried_path_that_replaces_a_base_directory_or_file_is_overlaid_as_git_does(self):
        (self.repo / "conf").mkdir()
        base = self.commit({"conf/inner.rs": "a directory on the base\n", "flat": "a file on the base\n"})
        self.git("rm", "-q", "-r", "conf", "flat")
        (self.repo / "flat").mkdir()
        head = self.commit({"conf": "a file on the head\n", "flat/inner.rs": "a directory on the head\n",
                            "notes.txt": "a later head file\n"})
        self.plan(base={"attempt": "fail"})
        result = self.red_green(base=base, head=head, carry=("conf", "flat/inner.rs"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        tree = json.loads((self.state / "base-tree.json").read_text())
        self.assertEqual({path: tree.get(path) for path in ("conf", "flat/inner.rs", "conf/inner.rs", "flat")},
                         {"conf": "a file on the head\n", "flat/inner.rs": "a directory on the head\n",
                          "conf/inner.rs": None, "flat": None})
        self.assert_checkout_unchanged()

    def test_carried_paths_match_literally_and_cleanup_keeps_unrelated_worktrees(self):
        other = self.root / "other"
        self.git("worktree", "add", "--quiet", "--detach", str(other), self.base)
        shutil.rmtree(other)
        self.git("replace", self.base, self.git("commit-tree", f"{self.head}^{{tree}}", "-m", "replacement"))
        result = self.red_green(carry=("table_tests.rs", "t[a-z].rs", "\udcff.rs", "cr\r.rs"),
                                env=dict(self.env, GIT_GLOB_PATHSPECS="1"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        base_tree = json.loads((self.state / "base-tree.json").read_text())
        self.assertEqual(sorted(base_tree), sorted([".gitignore", "Cargo.toml", "t[a-z].rs", "table.rs",
                                                    "table_tests.rs", "\udcff.rs", "cr\r.rs"]))
        self.assertEqual(base_tree["table.rs"], "unfixed\n")
        self.assertTrue((self.repo / ".git/worktrees/other").is_dir(), "cleanup removed an unrelated worktree")

    def test_each_wrong_red_is_refused_by_its_own_reason(self):
        reasons = []
        for name, plan, options, reason in (
            ("passes", {"base": {"attempt": "pass"}}, {}, "the test passes on the base: not reproduced"),
            ("build", {"base": {"build_exit": 101}}, {},
             "the base is red for the wrong reason, a build failure: build failure"),
            ("absent", {}, {"carry": ("notes.txt",)}, "the test is absent on the base: rejected input:"),
            ("crash", {"base": {"attempt": "crash"}}, {}, "the test crashed on the base: crash"),
            ("text", {"base": {"attempt": "other-text"}}, {},
             "the test failed on the base without the expected text: reproduced"),
            ("hang", {"base": {"attempt": "hang"}}, {"watchdog": "1"}, "the test hung on the base: watchdog expiry"),
            ("head", {"head": {"attempt": "fail"}}, {}, "the test fails on the head: reproduced"),
            ("head-build", {"head": {"build_exit": 101}}, {},
             "the head leg did not pass: exit 3, verdict 'build failure"),
            ("head-crash", {"head": {"attempt": "crash"}}, {}, "the head leg did not pass: exit 4, verdict 'crash"),
        ):
            with self.subTest(name=name):
                self.plan(**plan)
                (self.state / "builds.txt").unlink(missing_ok=True)
                result = self.red_green(**options)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                [line] = result.stdout.splitlines()
                self.assertTrue(line.startswith(f"red-green refused: {reason}"), line)
                if name == "absent":
                    self.assertIn("matched 0 listed", line)
                if name == "hang":
                    self.assert_gone(int((self.state / "grandchild.pid").read_text()))
                _, receipt = self.receipt(result)
                self.assertEqual(receipt["result"], line.replace("red-green refused: ", "refused: ", 1))
                legs = ["base", "head"] if name.startswith("head") else ["base"]
                if name in ("build", "absent", "head-build"):
                    # A leg that ran no attempt records its own artifact.json and no attempt output.
                    entry = receipt["legs"][legs[-1]]
                    self.assertEqual(entry["sha256"], hashlib.sha256(Path(entry["artifact"]).read_bytes()).hexdigest())
                    self.assertEqual((entry["attempt_sha256"], "evidence_error" in entry), ({}, False))
                self.assertEqual(sorted(receipt["legs"]), legs)
                self.assertEqual([build["leg"] for build in self.builds()], legs)
                reasons.append(line)
                self.assert_checkout_unchanged()
        self.assertEqual(len(set(reasons)), len(reasons), reasons)

    def test_framing_lines_never_hold_the_expected_text(self):
        module = self.module()
        for outcome, texts in (
            ("fail", ("running 1", "... FAILED", "failures:", f"---- {TEST[:7]}", "    " + TEST[:7], "panicked at",
                      "display a backtrace", "table_tests.rs:9:5", "table_tests::frame", "1 failed")),
            ("should-panic", ("zzz", "should panic", "... FAILED", "panic did not contain", "panic message",
                              "Some details")),
            ("non-string", ("expected panic with string value", "found non-string value")),
        ):
            with self.subTest(outcome=outcome):
                self.plan(base={"attempt": outcome})
                result = self.red_green(expect=texts[0])
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertTrue(result.stdout.startswith(
                    "red-green refused: the test failed on the base without the expected text: reproduced"),
                    result.stdout)
                _, receipt = self.receipt(result)
                output = self.attempt_output(receipt)
                kept = module.unframed(output, TEST)
                for text in texts:
                    self.assertIn(text, output)
                    self.assertNotIn(text, kept)
        for separator in ("\v", "\u2028", "\x1c"):
            self.assertNotIn(TWO_LINES, module.unframed(TWO_LINES.replace("\n", separator), TEST))
        self.assertEqual(module.unframed(f"running 1 test\r\n{EXPECT}\r\n", TEST), f"\0\n{EXPECT}\r\n")
        # An uncaptured test writes after libtest's `test ID ... ` prefix, so the result word stands on its own line.
        uncaptured = (f"\nrunning 1 test\ntest {TEST} ... a line the test prints\nFAILED\n\nfailures:\n\n"
                      f"failures:\n    {TEST}\n\n{FAILED}\n")
        self.assertNotIn("FAILED", module.unframed(uncaptured, TEST))

    def test_the_expected_text_is_read_from_the_lines_framing_leaves(self):
        for outcome, text, proven in (
            ("no-panic", "did not panic as expected", True),
            ("test-message", "lost a completion", True),
            ("stderr-text", EXPECT, True),
            ("stderr-text", "stderr_fixture.rs:1:1", False),
            ("adjacent", TWO_LINES, True),
            ("split", TWO_LINES, False),
        ):
            with self.subTest(outcome=outcome, text=text):
                self.plan(base={"attempt": outcome})
                result = self.red_green(expect=text)
                self.assertEqual(result.returncode, 0 if proven else 1, result.stdout + result.stderr)
                if not proven:
                    self.assertTrue(result.stdout.startswith(
                        "red-green refused: the test failed on the base without the expected text"), result.stdout)
                if outcome == "stderr-text":
                    _, receipt = self.receipt(result)
                    self.assertNotIn(text, self.attempt_output(receipt, "stdout"))
                    self.assertIn(text, self.attempt_output(receipt, "stderr"))
                    self.assertEqual(receipt["legs"]["base"]["expect_streams"], ["stderr"] if proven else [])
                if outcome == "adjacent":
                    self.assertEqual(result.stdout, f'red-green: {TEST} failed on {self.base[:12]} with "first payload '
                                                    f'line\\nsecond payload line" and passed on {self.head[:12]}\n')

    def test_a_runner_that_does_not_complete_or_document_a_leg_is_refused(self):
        self.plan(base={"metadata_exit": 1})
        result = self.red_green()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, "red-green refused: the runner did not complete the base leg: exit 2, "
                                        "verdict 'rejected input: cargo metadata exited 1'\n")
        scripts = self.root / "scripts"
        scripts.mkdir()
        shutil.copy(SCRIPT, scripts / "red-green.py")
        shutil.copy(ROOT / "scripts/select-tests.py", scripts / "select-tests.py")
        (scripts / "reproduce-test.py").write_text(
            STUB_RUNNER.replace("REAL", repr(str(ROOT / "scripts/reproduce-test.py"))))
        for plan, reason, legs in (
            ({}, "the runner did not complete the base leg: exit 1, "
                 "verdict 'Traceback (most recent call last): the runner stopped'", ["base"]),
            ({"base": {"stub": "no-artifact"}}, f"the base leg failed but {NO_EVIDENCE}: reproduced", ["base"]),
            ({"base": {"stub": "no-stderr"}}, f"the base leg failed but {NO_EVIDENCE}: reproduced", ["base"]),
            ({"base": {"stub": "real"}, "head": {"stub": "other-leg"}},
             f"the head leg passed but {NO_EVIDENCE}: not reproduced", ["base", "head"]),
            ({"base": {"stub": "real"}, "head": {"stub": "no-stderr"}},
             f"the head leg passed but {NO_EVIDENCE}: not reproduced", ["base", "head"]),
            ({"base": {"stub": "real"}, "head": {"stub": "no-verdict"}},
             "the head leg did not pass: exit 0, verdict ''", ["base", "head"]),
        ):
            with self.subTest(plan=plan):
                self.plan(**plan)
                stub = self.red_green(script=scripts / "red-green.py")
                self.assertEqual(stub.returncode, 1, stub.stderr)
                [line] = stub.stdout.splitlines()
                self.assertTrue(line.startswith(f"red-green refused: {reason}"), line)
                _, receipt = self.receipt(stub)
                self.assertEqual(sorted(receipt["legs"]), legs)
                self.assert_checkout_unchanged()

    def test_a_leg_counts_only_its_own_readable_artifact_and_a_reported_verdict(self):
        module = self.module()
        directory = self.root / "receipts/local-1-1"
        receipt = self.fake_receipt(module, directory)
        for name in ("local-1-1-1-base", "local-1-1-1-head.2", "local-1-1-1-base.3", "local-1-1-1-base.4"):
            (directory / name).mkdir(parents=True)
            (directory / name / "attempt-1.stdout").write_text(EXPECT)
        for name in ("local-1-1-1-base", "local-1-1-1-head.2"):
            (directory / name / "artifact.json").write_text("{}\n")
        (directory / "local-1-1-1-base.3/artifact.json").mkdir()
        shutil.copytree(directory / "local-1-1-1-base", self.root / "outside/local-1-1-1-base")
        for leg, announced, accepted in (
            ("base", directory / "local-1-1-1-base/artifact.json", True),
            ("head", directory / "local-1-1-1-head.2/artifact.json", True),
            ("head", directory / "local-1-1-1-base/artifact.json", False),
            ("base", directory / "local-1-1-1-base/attempt-1.stdout", False),
            ("base", self.root / "outside/local-1-1-1-base/artifact.json", False),
            ("base", directory / "local-1-1-1-base.3/artifact.json", False),
            ("base", directory / "local-1-1-1-base.4/artifact.json", False),
        ):
            with self.subTest(announced=announced), mock.patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": "1"}):
                entry = {}
                artifact, outputs = receipt.evidence(leg, str(announced), entry)
                self.assertEqual(artifact is not None, accepted)
                self.assertEqual(outputs, {"stdout": EXPECT.encode()} if accepted else {})
                self.assertEqual("sha256" in entry, accepted)
                self.assertEqual("evidence_error" in entry, announced.parent.name in ("local-1-1-1-base.3",
                                                                                      "local-1-1-1-base.4"))
        artifact = directory / "local-1-1-1-base/artifact.json"
        for code in (0, 6):
            self.assertEqual(receipt.base_reason(code, "", artifact, {}),
                             f"the runner did not complete the base leg: exit {code}, verdict ''")
        self.assertEqual(receipt.head_reason(1, "", artifact, {}), "the head leg did not pass: exit 1, verdict ''")
        # A reported failure or pass counts only with both attempt output streams.
        red, green = "reproduced: reproduced on attempt 1", "not reproduced in 1 attempts"
        receipt.record["legs"]["base"] = {}
        for outputs in ({"stdout": EXPECT.encode()}, {"stderr": b""}, {"stdout": EXPECT.encode(), "stderr": b""}):
            with self.subTest(streams=sorted(outputs)):
                complete = len(outputs) == 2
                self.assertEqual(receipt.base_reason(1, red, artifact, outputs),
                                 None if complete else f"the base leg failed but {NO_EVIDENCE}: {red}")
                self.assertEqual(receipt.head_reason(0, green, artifact, outputs),
                                 None if complete else f"the head leg passed but {NO_EVIDENCE}: {green}")

    def test_both_legs_run_the_runner_read_at_startup(self):
        scripts = self.root / "scripts"
        scripts.mkdir()
        for name in ("red-green.py", "reproduce-test.py", "select-tests.py"):
            shutil.copy(ROOT / "scripts" / name, scripts / name)
        original = hashlib.sha256((scripts / "reproduce-test.py").read_bytes()).hexdigest()
        # The base build replaces the runner beside the command, then the copy the legs run, which sits beside the
        # leg worktrees.
        for replaced in (str(scripts / "reproduce-test.py"), "../scripts/reproduce-test.py"):
            with self.subTest(replaced=replaced):
                shutil.copy(ROOT / "scripts/reproduce-test.py", scripts / "reproduce-test.py")
                self.plan(base={"replace": replaced})
                result = self.red_green(script=scripts / "red-green.py")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual("): replaced" in (scripts / "reproduce-test.py").read_text(), replaced[0] == "/")
                _, receipt = self.receipt(result)
                self.assertEqual(receipt["scripts"]["reproduce-test.py"], original)
                self.assert_checkout_unchanged()

    def test_rejected_input_starts_no_worktree_and_no_build(self):
        os.symlink("table_tests.rs", self.repo / "link.rs")
        self.git("add", "link.rs")
        self.git("commit", "-q", "-m", "link")
        linked = self.git("rev-parse", "HEAD")
        carried_only = self.commit({"table_tests.rs": "#[test] again\n"})
        self.git("commit", "-q", "--allow-empty", "-m", "empty")
        empty = self.git("rev-parse", "HEAD")
        # Two heads whose only change swaps a directory and a file at a carried path, one in each direction.
        (self.repo / "conf").mkdir()
        swap_base = self.commit({"conf/inner.rs": "a directory on the base\n", "flat": "a file on the base\n"})
        self.git("rm", "-q", "-r", "conf")
        file_for_directory = self.commit({"conf": "a file on the head\n"})
        self.git("rm", "-q", "flat")
        (self.repo / "flat").mkdir()
        directory_for_file = self.commit({"flat/inner.rs": "a directory on the head\n"})
        self.status = self.git("status", "--porcelain")
        loop = self.root / "loop"
        os.symlink(loop, loop)
        outside = self.root / "outside"
        outside.mkdir()
        shared, grouped = self.root / "shared", self.root / "grouped"
        for directory in (shared, shared / "mine", grouped):
            directory.mkdir(mode=0o700)
        shared.chmod(0o1707)
        grouped.chmod(0o770)
        erasing = self.root / "e\x1b[2Kx"
        erasing.mkdir(mode=0o700)
        erasing.chmod(0o770)
        built = self.root / "private/red-green"
        built.mkdir(parents=True)
        built.chmod(0o775)
        cases = [
            ("revision", {"base": "no-such-revision"}, "names no commit"),
            ("carry", {"carry": ("table_tests.rs", "missing.rs")}, "holds no regular file 'missing.rs'"),
            ("directory", {"carry": (".",)}, "holds no regular file '.'"),
            ("subdirectory", {"carry": ("sub",)}, "holds no regular file 'sub'"),
            ("symlink", {"head": linked, "carry": ("table_tests.rs", "link.rs")}, "holds no regular file 'link.rs'"),
            ("carried-only", {"base": linked, "head": carried_only}, "changes only carried paths"),
            ("empty-head", {"base": carried_only, "head": empty}, "changes only carried paths"),
            ("file-for-directory", {"base": swap_base, "head": file_for_directory, "carry": ("conf",)},
             "changes only carried paths"),
            ("directory-for-file", {"base": file_for_directory, "head": directory_for_file,
                                    "carry": ("flat/inner.rs",)}, "changes only carried paths"),
            ("empty", {"expect": ""}, "--expect is empty"),
            ("blank", {"expect": " \t "}, "--expect is empty"),
            ("test-id", {"expect": "table_tests::a_poll"}, "is part of the test ID"),
            ("watchdog-zero", {"watchdog": "0"}, "--watchdog must be a positive number"),
            ("watchdog-huge", {"watchdog": "1e10"}, "--watchdog must be a positive number"),
            ("same", {"base": self.head}, "is not an ancestor"),
            ("swapped", {"base": self.head, "head": self.base, "carry": ("table.rs",)}, "is not an ancestor"),
            ("artifacts", {"extra": ("--artifacts", str(loop / "receipts"))}, "cannot be resolved"),
            ("outside", {"cwd": outside}, "not in a Git checkout"),
        ]
        cases += [(name, {"env": dict(self.env, **{name: value})}, f"{name} would point the leg worktrees")
                  for name, value in (("GIT_DIR", str(self.repo / ".git")), ("GIT_WORK_TREE", str(self.repo)),
                                      ("GIT_INDEX_FILE", str(self.repo / ".git/index")),
                                      ("GIT_COMMON_DIR", str(self.repo / ".git")),
                                      ("GIT_OBJECT_DIRECTORY", str(self.repo / ".git/objects")))]
        cases += [
            ("target-loop", {"env": dict(self.env, CARGO_TARGET_DIR=str(loop))}, "cannot be resolved"),
            ("artifacts-byte", {"extra": ("--artifacts", str(self.root / "\udcffreceipts"))}, "cannot appear"),
            ("artifacts-newline", {"extra": ("--artifacts", str(self.root / "a\nb"))}, "cannot appear"),
            ("carry-only-dashes", {"carry": (), "extra": ("--carry=--",)}, ("names no path", "holds no regular")),
            ("carry-then-dashes", {"extra": ("--carry=--",)}, ("names no path", "holds no regular")),
            ("expect-dashes", {"extra": ("--expect=--",)}, ("has no value", "is part of the test ID")),
            ("temp-below-all-writable", {"env": dict(self.env, TMPDIR=str(shared / "mine"))},
             f"can write {shared}, and so can configure"),
            ("temp-group-writable", {"env": dict(self.env, TMPDIR=str(grouped))},
             f"can write {grouped}, and so can configure"),
            ("temp-control-characters", {"env": dict(self.env, TMPDIR=str(erasing))}, "e\\x1b[2Kx, and so can"),
            ("package-empty", {"package": ""}, "an option has no value"),
            ("cargo-empty", {"extra": ("--cargo=",)}, "an option has no value"),
            ("artifacts-empty", {"extra": ("--artifacts=",)}, "an option has no value"),
            ("build-below-all-writable", {"env": dict(self.env, CARGO_TARGET_DIR=str(shared / "mine"))},
             f"can write {shared}, and so can replace"),
            ("build-group-writable", {"env": dict(self.env, CARGO_TARGET_DIR=str(grouped))},
             f"can write {grouped}, and so can replace"),
            ("build-directory-writable", {"env": dict(self.env, CARGO_TARGET_DIR=str(built.parent))},
             f"can write {built}, and so can replace"),
        ]
        cases.append(("no-merge-base", {"base": False}, "has no merge base with origin/main"))
        for name, options, reason in cases:
            with self.subTest(name=name):
                if name == "no-merge-base":
                    orphan = self.git("commit-tree", self.git("mktree", input=""), "-m", "orphan")
                    self.git("update-ref", "refs/remotes/origin/main", orphan)
                extra = options.pop("extra", ())
                result = self.red_green(*extra, **options)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("red-green rejected: ", result.stderr)
                self.assertTrue(any(text in result.stderr for text in (reason if isinstance(reason, tuple)
                                                                        else (reason,))), result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertNotIn("\x1b", result.stderr)
                self.assertEqual(self.builds(), [])
                self.assertFalse((self.repo / "target").exists())
                self.assert_checkout_unchanged()

    def test_the_build_directory_is_created_for_the_invoking_user_alone(self):
        module = self.module()
        self.assertEqual(module.shared_directories(self.repo / "target/red-green/build"), [])
        for _ in range(2):
            # With an open umask each directory the command creates on the way to the build directory still has
            # no group or world write permission, so the next run accepts it.
            result = subprocess.run(self.command(), cwd=self.repo, env=self.env, text=True, capture_output=True,
                                    umask=0)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for directory in ("target", "target/red-green", "target/red-green/build"):
                mode = (self.repo / directory).stat().st_mode
                self.assertEqual(mode & 0o022, 0, f"{directory} has mode {oct(mode)}")
        (self.repo / "target/red-green").chmod(0o777)
        self.assertEqual(module.shared_directories(self.repo / "target/red-green/build/absent"),
                         [str(self.repo / "target/red-green")])

    def test_an_uncreatable_receipt_directory_is_refused_by_name(self):
        blocker = self.root / "file"
        blocker.write_text("")
        locked = self.root / "locked"
        locked.mkdir(mode=0o500)
        for name, options, path in (
            ("receipt", {"extra": ("--artifacts", str(blocker))}, f"{blocker}/local-"),
            ("build", {"env": dict(self.env, CARGO_TARGET_DIR=str(locked))}, f"{locked}/red-green "),
        ):
            # Root creates a directory inside one that grants its owner no write permission.
            if name == "build" and os.getuid() == 0:
                continue
            with self.subTest(name=name):
                result = self.red_green(*options.pop("extra", ()), **options)
                self.assertEqual(result.returncode, 1, result.stderr)
                [line] = result.stdout.splitlines()
                self.assertTrue(line.startswith(f"red-green refused: the {name} directory {path}"), line)
                self.assertIn("could not be created", line)
                self.assertNotIn("receipt: ", result.stderr)
                self.assertEqual(self.builds(), [])
                self.assert_checkout_unchanged()

    def test_a_receipt_directory_that_exists_is_refused_and_left_unchanged(self):
        module = self.module()
        existing = self.repo / "target/red-green/local-1700000000-4242"
        existing.mkdir(parents=True)
        (existing / "receipt.json").write_text("an earlier receipt\n")
        code, out, err = self.main_in_process(module, self.command()[2:],
                                              mock.patch.object(module.time, "time", return_value=1700000000.5),
                                              mock.patch.object(module.os, "getpid", return_value=4242))
        self.assertEqual(code, 1, out + err)
        self.assertTrue(out.startswith(f"red-green refused: the receipt directory {existing} could not be created"),
                        out)
        self.assertNotIn("receipt: ", err)
        self.assertEqual((existing / "receipt.json").read_text(), "an earlier receipt\n")
        self.assertEqual(self.builds(), [])

    def test_toolchain_configuration_another_user_owns_or_can_add_above_the_temporary_directory_is_rejected(self):
        module = self.module()
        (self.root / ".cargo").mkdir()
        self.assertEqual(module.foreign_toolchain_paths(self.tmp), [])
        another_user = mock.patch.object(module.os, "getuid", return_value=os.getuid() + 1)
        with another_user:
            found = module.foreign_toolchain_paths(self.tmp)
        self.assertIn(str(self.root / ".cargo"), found)
        # The mock changes `getuid()` but preserves fixture ownership, so the check reports the fixture directory
        # unless root owns it. The check trusts root-owned directories such as `/`.
        self.assertEqual(str(self.tmp) in found, os.getuid() != 0)
        self.assertNotIn("/", found)
        code, out, err = self.main_in_process(module, self.command()[2:], another_user)
        self.assertEqual((code, out), (2, ""), err)
        # The runner's private copy is written and loaded only below a temporary directory that passed the check.
        self.assertFalse(hasattr(module, "runner"))
        self.assertIn(str(self.root / ".cargo"), err)
        self.assertIn("can configure Cargo or rustup in the leg worktrees", err)
        self.assertEqual(self.builds(), [])

    def test_toolchain_configuration_another_user_can_write_above_the_temporary_directory_is_rejected(self):
        module = self.module()
        entry, shared = self.root / ".cargo", self.root / "shared"
        entry.mkdir()
        shared.mkdir()
        self.assertEqual(module.foreign_toolchain_paths(self.tmp), [])
        for mode in (0o775, 0o757):
            with self.subTest(mode=oct(mode)):
                entry.chmod(mode)
                self.assertEqual(module.foreign_toolchain_paths(self.tmp), [str(entry)])
        entry.chmod(0o755)
        for name in ("config.toml", "config"):
            config, target = entry / name, shared / name
            with self.subTest(name=name):
                config.write_text("")
                config.chmod(0o644)
                self.assertEqual(module.foreign_toolchain_paths(self.tmp), [])
                for mode in (0o664, 0o646):
                    config.chmod(mode)
                    self.assertEqual(module.foreign_toolchain_paths(self.tmp), [str(config)], oct(mode))
                config.unlink()
                # A link whose target is absent is reported, since the target cannot be examined.
                config.symlink_to(target)
                self.assertEqual(module.foreign_toolchain_paths(self.tmp), [str(config)])
                target.write_text("")
                target.chmod(0o644)
                self.assertEqual(module.foreign_toolchain_paths(self.tmp), [])
                target.chmod(0o666)
                self.assertEqual(module.foreign_toolchain_paths(self.tmp), [str(config)])
                config.unlink()
                target.unlink()
        entry.rmdir()
        entry.symlink_to(shared)
        self.assertEqual(module.foreign_toolchain_paths(self.tmp), [])
        # A link is reported when another user can replace what it resolves to, through a directory above it.
        inner = self.root / "open/inner"
        inner.mkdir(parents=True)
        entry.unlink()
        entry.symlink_to(inner)
        self.assertEqual(module.foreign_toolchain_paths(self.tmp), [])
        inner.parent.chmod(0o777)
        self.assertEqual(module.foreign_toolchain_paths(self.tmp), [str(entry)])
        # The same holds for a link met on the way: a link in a directory another user can write.
        inner.parent.chmod(0o755)
        hop = self.root / "hop"
        hop.mkdir()
        (hop / "middle").symlink_to(inner)
        entry.unlink()
        entry.symlink_to(hop / "middle")
        self.assertEqual(module.foreign_toolchain_paths(self.tmp), [])
        hop.chmod(0o777)
        self.assertEqual(module.foreign_toolchain_paths(self.tmp), [str(entry)])
        entry.unlink()
        entry.symlink_to(shared)
        shared.chmod(0o777)
        self.assertEqual(module.foreign_toolchain_paths(self.tmp), [str(entry)])
        code, out, err = self.main_in_process(module, self.command()[2:])
        self.assertEqual((code, out), (2, ""), err)
        self.assertIn(str(entry), err)
        self.assertEqual(self.builds(), [])

    def test_the_runner_copy_and_the_worktrees_are_created_in_the_checked_temporary_directory(self):
        module = self.module()
        link = self.root / "tmp-link"
        link.symlink_to(self.tmp)
        mkdtemp, used = tempfile.mkdtemp, []

        def recording(suffix=None, prefix=None, dir=None):
            used.append(dir)
            return mkdtemp(suffix, prefix, dir)

        code, out, err = self.main_in_process(module, self.command()[2:],
                                              mock.patch.object(tempfile, "gettempdir", return_value=str(link)),
                                              mock.patch.object(module.tempfile, "mkdtemp", recording))
        self.assertEqual(code, 0, out + err)
        # The check examined the directory the link resolves to, so every directory is created there by that name.
        self.assertEqual((len(used), set(map(str, used))), (2, {str(self.tmp)}))

    def test_a_cargo_home_another_user_can_write_is_used_as_the_environment_provides_it(self):
        home = self.root / "cargo-home"
        home.mkdir()
        home.chmod(0o777)
        result = self.red_green(env=dict(self.env, CARGO_HOME=str(home)))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_path_with_control_characters_is_printed_escaped(self):
        erasing = self.root / "e\x1b[2Kx"
        result = self.red_green("--artifacts", str(erasing))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("\x1b", result.stderr)
        self.assertIn("receipt: ", result.stderr)
        self.assertEqual(len(list(erasing.glob("*/receipt.json"))), 1)

    def test_a_result_line_escapes_control_characters(self):
        module, out = self.module(), io.StringIO()
        with contextlib.redirect_stdout(out):
            module.say("a\x1b[100Db\x08c\x7fd\x9be\tf\u2028g")
        self.assertEqual(out.getvalue(), "a\\x1b[100Db\\x08c\\x7fd\\x9be\\tf\\u2028g\n")

    def test_a_looping_directory_is_rejected_when_resolve_returns_it(self):
        module = self.module()
        loop = self.root / "loop"
        os.symlink(loop, loop)
        with mock.patch.object(module.Path, "resolve", lambda path, strict=False: path), \
                self.assertRaises(module.Rejected):
            module.resolved(loop / "receipts")

    def test_a_temporary_directory_step_is_shielded_and_its_failure_is_refused(self):
        module = self.module()
        mkdtemp = tempfile.mkdtemp

        def failing(*args, **options):
            # The worktree step names its prefix by keyword; the runner copy's directory is created as usual.
            if options.get("prefix") != "kestrike-red-green-":
                return mkdtemp(*args, **options)
            raise OSError("no temporary directory")

        code, out, err = self.main_in_process(module, self.command()[2:],
                                              mock.patch.object(module.tempfile, "mkdtemp", failing))
        self.assertEqual(code, 1, out + err)
        self.assertEqual(out, "red-green refused: a leg could not run: no temporary directory\n")
        self.assertTrue((self.repo / "target/red-green/build/red-green.lock").exists())
        self.assertEqual(json.loads(Path(err.split("receipt: ", 1)[1].strip()).read_text())["legs"], {})
        receipt, made = self.fake_receipt(module), []

        def interrupted(*_args, **options):
            made.append(mkdtemp(dir=options["dir"], prefix=options["prefix"]))
            receipt.interrupt(signal.SIGTERM, None)
            return made[0]

        with mock.patch.object(module.tempfile, "mkdtemp", interrupted), self.assertRaises(SystemExit) as raised:
            receipt.worktree("base", self.base)
        self.assertEqual((raised.exception.code, receipt.temp), (128 + signal.SIGTERM, made[0]))
        self.assertEqual(Path(made[0]).parent, self.tmp)
        receipt.cleanup()
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_a_named_head_package_target_release_and_build_directory_reach_both_legs(self):
        self.git("checkout", "-q", "-b", "side", self.base)
        self.git("update-ref", "refs/remotes/origin/main", self.commit({"table_tests.rs": "#[test] later\n"}))
        (self.repo / "table_tests.rs").write_text("staged\n")
        self.git("add", "table_tests.rs")
        (self.repo / "table_tests.rs").write_text("working\n")
        (self.repo / "scratch.txt").write_text("untracked\n")
        self.status = self.git("status", "--porcelain")
        staged = self.git("rev-parse", ":table_tests.rs")
        binaries = self.root / "bin"
        binaries.mkdir()
        (binaries / "-cargo").symlink_to(self.state / "cargo")
        env = dict(self.env, CARGO_TARGET_DIR="../shared", CARGO_BUILD_BUILD_DIR=str(self.root / "elsewhere"),
                   PATH=f"{binaries}{os.pathsep}{self.env['PATH']}")
        result = subprocess.run(self.command("--release", package="fixture-pkg", target="table_it", base=False,
                                             cargo="-cargo"), cwd=self.repo, text=True, capture_output=True, env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        _, receipt = self.receipt(result)
        target = self.root / "shared/red-green"
        self.assertEqual((receipt["base"], receipt["head"], receipt["release"], receipt["cargo_target_dir"]),
                         (self.base, self.head, True, str(target)))
        self.assertEqual(receipt["carried"],
                         [{"path": "table_tests.rs", "blob": self.git("rev-parse", f"{self.head}:table_tests.rs")}])
        for leg, commit in (("base", self.base), ("head", self.head)):
            record = json.loads(Path(receipt["legs"][leg]["artifact"]).read_text())
            self.assertEqual((record["revision"], record["release"], record["package"], record["target"]),
                             (commit, True, "fixture-pkg", "table_it"))
        self.assertEqual(json.loads((self.state / "base-tree.json").read_text())["table_tests.rs"], "#[test]\n")
        self.assertEqual([build["argv"][:5] for build in self.builds()],
                         [["test", "-p", "fixture-pkg", "--test", "table_it"]] * 2)
        self.assertTrue(all("--release" in build["argv"] and build["target_dir"] == build["build_dir"] == str(target)
                            for build in self.builds()))
        self.assertTrue({"--release", "--cargo=-cargo"} <= set(shlex.split(receipt["command"])))
        self.assertEqual((self.git("rev-parse", ":table_tests.rs"), (self.repo / "table_tests.rs").read_text()),
                         (staged, "working\n"))
        self.assert_checkout_unchanged()

    def test_a_receipt_that_cannot_be_written_is_refused(self):
        planted = self.state / "planted.txt"
        planted.write_text("planted\n")
        for outcome in ("block-receipt", "file-receipt", "link-receipt"):
            with self.subTest(outcome=outcome):
                self.plan(head={"attempt": outcome})
                result = self.red_green()
                self.assertEqual(result.returncode, 1, result.stderr)
                [line] = result.stdout.splitlines()
                self.assertRegex(line, r"^red-green refused: the receipt .*/receipt\.json could not be written: .*; "
                                       r"proven$")
                self.assertNotIn("receipt: ", result.stderr)
                self.assertEqual(planted.read_text(), "planted\n")
                self.assert_checkout_unchanged()

    def test_a_run_waits_for_the_build_lock_before_any_worktree_and_holds_it_through_both_legs(self):
        target = self.repo / "target/red-green/build"
        target.mkdir(parents=True)
        with open(target / "red-green.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            process = self.spawn()
            self.assertEqual(self.first_stderr_line(process), f"red-green: waiting for another run that builds in {target}\n")
            self.assertEqual((self.builds(), list(self.tmp.iterdir())), ([], []))
            self.assertEqual(self.git("worktree", "list", "--porcelain").count("worktree "), 1)
        stdout, stderr = process.communicate(timeout=60)
        self.assertEqual(process.returncode, 0, stdout + stderr)
        self.assertEqual([build["lock_held"] for build in self.builds()], [True, True])

    def test_a_lock_file_with_content_reaches_each_leg_as_empty_standard_input(self):
        target = self.repo / "target/red-green/build"
        target.mkdir(parents=True)
        (target / "red-green.lock").write_text("left by an earlier run\n")
        result = self.red_green()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual([build["stdin"] for build in self.builds()], ["", ""])

    def test_a_build_lock_another_user_can_write_is_refused(self):
        target = self.repo / "target/red-green/build"
        target.mkdir(parents=True)
        lock = target / "red-green.lock"
        lock.write_text("")
        lock.chmod(0o666)
        result = self.red_green()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertTrue(result.stdout.startswith(f"red-green refused: the build lock {lock} cannot be opened: another "
                                                 "user owns or can write it"), result.stdout)
        self.assertEqual(self.builds(), [])
        self.assert_checkout_unchanged()

    def test_a_build_directory_that_another_run_creates_first_is_used(self):
        module = self.module()
        build = self.root / "made/first"
        build.mkdir(parents=True)
        # Both runs saw the path absent; the other one created it before this one's `mkdir`.
        with mock.patch.object(Path, "exists", return_value=False):
            module.make_private(build)
        # A directory that appeared with group or world write permission is refused.
        build.chmod(0o777)
        with mock.patch.object(Path, "exists", return_value=False), self.assertRaises(PermissionError):
            module.make_private(build)
        (self.root / "made/file").write_text("")
        with mock.patch.object(Path, "exists", return_value=False), self.assertRaises(FileExistsError):
            module.make_private(self.root / "made/file")

    def test_a_signal_waits_once_the_runner_has_exited(self):
        module = self.module()
        receipt = self.fake_receipt(module)
        receipt.child = types.SimpleNamespace(returncode=0)
        receipt.interrupt(signal.SIGTERM, None)
        self.assertEqual(receipt.pending, signal.SIGTERM)
        receipt.child, receipt.pending = types.SimpleNamespace(returncode=None), None
        with self.assertRaises(SystemExit) as raised:
            receipt.interrupt(signal.SIGTERM, None)
        self.assertEqual(raised.exception.code, 128 + signal.SIGTERM)

    def test_a_build_lock_that_is_not_a_regular_file_is_refused(self):
        target = self.repo / "target/red-green/build"
        target.mkdir(parents=True)
        lock = target / "red-green.lock"
        for kind in ("fifo", "symlink"):
            with self.subTest(kind=kind):
                lock.unlink(missing_ok=True)
                os.mkfifo(lock) if kind == "fifo" else lock.symlink_to(self.root / "lock-target")
                result = subprocess.run(self.command(), cwd=self.repo, env=self.env, text=True, capture_output=True,
                                        timeout=30)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertTrue(result.stdout.startswith(f"red-green refused: the build lock {lock} cannot be opened"),
                                result.stdout)
                self.assertEqual("it is not a regular file" in result.stdout, kind == "fifo", result.stdout)
                self.assertEqual(self.builds(), [])
                self.assertFalse((self.root / "lock-target").exists())
                self.assert_checkout_unchanged()

    def test_a_runner_left_by_a_killed_command_keeps_the_build_lock(self):
        self.plan(base={"build_hang": True})
        first = self.spawn()
        for _ in range(300):
            if (self.state / "grandchild.pid").exists():
                break
            time.sleep(0.1)
        first.kill()
        first.communicate()
        runner = int((self.state / "base.pid").read_text())
        self.plan()
        second = self.spawn()
        target = self.repo / "target/red-green/build"
        self.assertEqual(self.first_stderr_line(second), f"red-green: waiting for another run that builds in {target}\n")
        self.assertEqual([build["leg"] for build in self.builds()], ["base"])
        os.kill(runner, signal.SIGTERM)
        stdout, stderr = second.communicate(timeout=60)
        self.assertEqual(second.returncode, 0, stdout + stderr)
        self.assert_gone(int((self.state / "grandchild.pid").read_text()))

    def test_a_build_left_by_a_killed_runner_keeps_the_build_lock(self):
        self.plan(base={"build_hang": True})
        first = self.spawn()
        for _ in range(300):
            if (self.state / "grandchild.pid").exists():
                break
            time.sleep(0.1)
        orphan = int((self.state / "supervised.pid").read_text())

        def stop_orphan():
            with contextlib.suppress(ProcessLookupError):
                os.killpg(orphan, signal.SIGKILL)

        self.addCleanup(stop_orphan)
        os.kill(int((self.state / "base.pid").read_text()), signal.SIGKILL)
        stdout, stderr = first.communicate(timeout=60)
        self.assertEqual(first.returncode, 1, stdout + stderr)
        self.assertIn("the runner did not complete the base leg: exit -9", stdout)
        # The build outlives its runner and the command, asleep in its own process group.
        self.assertEqual(Path(f"/proc/{orphan}/stat").read_text().rpartition(")")[2].split()[0], "S")
        self.plan()
        second = self.spawn()
        target = self.repo / "target/red-green/build"
        self.assertEqual(self.first_stderr_line(second), f"red-green: waiting for another run that builds in {target}\n")
        self.assertEqual([build["leg"] for build in self.builds()], ["base"])
        stop_orphan()
        stdout, stderr = second.communicate(timeout=60)
        self.assertEqual(second.returncode, 0, stdout + stderr)

    def test_a_git_step_that_fails_after_validation_is_refused_by_name(self):
        for pattern, legs, carry, prefix in (
            (f'"{HOOKLESS}worktree add --quiet --detach "*/base" "*', [], ("table_tests.rs",),
             "git worktree add --quiet --detach "),
            (f'"{HOOKLESS}worktree add --quiet --detach "*/head" "*', ["base"], ("table_tests.rs",),
             "git worktree add --quiet --detach "),
            (f'"{HOOKLESS}--literal-pathspecs checkout "*', [], ("table_tests.rs", "\udcff.rs"),
             "git --literal-pathspecs checkout "),
        ):
            with self.subTest(pattern=pattern):
                (self.state / "builds.txt").unlink(missing_ok=True)
                env = self.git_wrapper(f'case "$*" in {pattern}) echo "fatal: refused" >&2; exit 128;;\n'
                                       'esac\nexec GIT "$@"\n')
                result = self.red_green(carry=carry, env=dict(env, PYTHONIOENCODING="utf-8:strict"))
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                [line] = result.stdout.splitlines()
                self.assertTrue(line.startswith(f"red-green refused: {prefix}"), line)
                if len(carry) == 2:
                    self.assertIn("\\udcff.rs", line)
                _, receipt = self.receipt(result)
                self.assertEqual(sorted(receipt["legs"]), legs)
                self.assertEqual([build["leg"] for build in self.builds()], legs)
                self.assert_checkout_unchanged()

    def test_a_signal_during_the_final_cleanup_lets_the_run_finish(self):
        delivered = self.state / "delivered"
        env = self.git_wrapper(
            f'case "$*" in "worktree remove "*) [ -e "{delivered}" ] || {{ touch "{delivered}"; kill -TERM "$PPID"; '
            'echo "fatal: refused" >&2; exit 1; };;\n'
            'esac\nexec GIT "$@"\n')
        result = self.red_green(env=env)
        self.assertTrue(delivered.exists())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(result.stdout.startswith("red-green: "), result.stdout)
        _, receipt = self.receipt(result)
        self.assertEqual(receipt["result"], "proven")
        # The removal that failed is repeated once the temporary directory is gone, and it drops the registration.
        self.assertNotIn("could not remove worktree", result.stderr)
        self.assert_checkout_unchanged()
        always = self.git_wrapper('case "$*" in "worktree remove "*/base) echo "fatal: refused" >&2; exit 1;;\n'
                                  'esac\nexec GIT "$@"\n')
        result = self.red_green(env=always)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertRegex(result.stderr, r"red-green: could not remove worktree \S+/base: fatal: refused")
        self.assertEqual(self.git("worktree", "list", "--porcelain").count("worktree "), 2)
        self.assertEqual(list(self.tmp.iterdir()), [])

    def interrupt(self, ready, plan=None, env=None, signum=signal.SIGTERM, again=False):
        self.plan(**(plan or {}))
        process = subprocess.Popen(self.command(), cwd=self.repo, env=env or self.env, text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for _ in range(300):
            if ready.exists():
                break
            time.sleep(0.1)
        self.assertTrue(ready.exists(), "the leg never reached the interruption point")
        process.send_signal(signum)
        if again:
            time.sleep(0.5)
            process.send_signal(signum)
        stdout, stderr = process.communicate(timeout=60)
        self.assertEqual(process.returncode, 128 + signum, stdout + stderr)
        if (self.state / "base.pid").exists():
            with self.assertRaises(ChildProcessError):
                os.waitpid(int((self.state / "base.pid").read_text()), os.WNOHANG)
        self.assertEqual(stdout, "")
        self.assertEqual(list((self.repo / "target/red-green").glob("*/receipt.json")), [])
        self.assert_checkout_unchanged()

    def test_a_signal_after_the_head_runner_exits_lets_the_run_finish(self):
        module = self.module()
        evidence = module.Receipt.evidence

        # The signal lands once the last leg's runner has exited, while the command reads that leg's evidence: the
        # head leg of a proven run, and the base leg of a run refused for a passing base.
        for last, plan, code, line in (("head", {}, 0, "red-green: "),
                                       ("base", {"base": {"attempt": "pass"}}, 1,
                                        "red-green refused: the test passes on the base")):
            with self.subTest(last=last):
                self.plan(**plan)

                def signalled(receipt, name, announced, entry, last=last):
                    if name == last:
                        os.kill(os.getpid(), signal.SIGTERM)
                    return evidence(receipt, name, announced, entry)

                # Each run in this process gets its own receipt parent and build directory: the run directory is
                # named by the second and the process, and the process keeps a run's build lock until it exits.
                argv = self.command("--artifacts", str(self.root / f"receipts-{last}"))[2:]
                build = mock.patch.dict(os.environ, {"CARGO_TARGET_DIR": str(self.root / f"build-{last}")})
                result, out, err = self.main_in_process(module, argv, build,
                                                        mock.patch.object(module.Receipt, "evidence", signalled))
                self.assertEqual(result, code, out + err)
                self.assertTrue(out.startswith(line), out)
                written = json.loads(Path(err.split("receipt: ", 1)[1].strip()).read_text())
                self.assertEqual(written["result"] == "proven", code == 0)

    def test_a_sigterm_during_a_build_stops_the_leg_and_removes_the_worktrees(self):
        self.interrupt(self.state / "grandchild.pid", {"base": {"build_hang": True}})
        self.assert_gone(int((self.state / "grandchild.pid").read_text()))
        self.assert_gone(int((self.state / "supervised.pid").read_text()))

    def test_a_sigterm_during_an_attempt_stops_the_leg_and_removes_the_worktrees(self):
        # The attempt ignores SIGTERM, so the runner exits only after its group stop escalates to SIGKILL; a
        # second SIGTERM lands while the command waits for it.
        observed, alive = self.state / "remove-observed", self.state / "runner-alive"
        env = self.git_wrapper(
            'case "$*" in "worktree remove "*)\n'
            f'  pid=$(cat "{self.state / "base.pid"}")\n'
            f'  if [ -e "/proc/$pid" ] && [ "$(sed "s/.*) //" "/proc/$pid/stat" | cut -d" " -f1)" != Z ]; then '
            f'touch "{alive}"; fi\n'
            f'  touch "{observed}";;\n'
            'esac\nexec GIT "$@"\n')
        self.interrupt(self.state / "grandchild.pid", {"base": {"attempt": "stubborn"}}, env=env, again=True)
        self.assertTrue(observed.exists())
        self.assertFalse(alive.exists())
        self.assert_gone(int((self.state / "grandchild.pid").read_text()))
        self.assert_gone(int((self.state / "supervised.pid").read_text()))

    def test_a_sighup_or_sigint_during_an_attempt_stops_the_leg_and_removes_the_worktrees(self):
        for signum in (signal.SIGHUP, signal.SIGINT):
            with self.subTest(signum=signum):
                (self.state / "grandchild.pid").unlink(missing_ok=True)
                self.interrupt(self.state / "grandchild.pid", {"base": {"attempt": "hang"}}, signum=signum)
                self.assert_gone(int((self.state / "grandchild.pid").read_text()))

    def test_the_default_base_is_the_merge_base_and_relative_paths_are_anchored_at_the_invoking_directory(self):
        side = self.git("commit-tree", f"{self.base}^{{tree}}", "-p", self.base, "-m", "side")
        self.git("update-ref", "refs/remotes/origin/main", side)
        later = self.commit({"notes.txt": "a later head\n"})
        result = self.red_green("--artifacts", "../receipts", base=False, head=False, cargo="../state/cargo")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        path, receipt = self.receipt(result)
        self.assertEqual(path.parent.parent, self.root / "receipts")
        self.assertEqual((receipt["base"], receipt["head"]), (self.base, later))
        for leg in ("base", "head"):
            self.assertTrue(Path(receipt["legs"][leg]["artifact"]).is_file())
        self.assertEqual([build["leg"] for build in self.builds()], ["base", "head"])
        command = shlex.split(receipt["command"])
        self.assertIn(f"--artifacts={self.root / 'receipts'}", command)
        self.assertIn(f"--cargo={self.state / 'cargo'}", command)
        self.assert_checkout_unchanged()

    def test_a_signal_during_a_spawn_takes_effect_once_the_runner_is_registered(self):
        module = self.module()
        receipt = self.fake_receipt(module)
        popen = subprocess.Popen
        self.addCleanup(setattr, subprocess, "Popen", popen)
        started = []

        def interrupted_spawn(*_args, **_options):
            child = popen([sys.executable, "-c", "import time; time.sleep(600)"])
            self.addCleanup(lambda: child.poll() is None and (child.kill(), child.wait()))
            started.append(child)
            receipt.interrupt(signal.SIGINT, None)
            receipt.interrupt(signal.SIGTERM, None)
            return child

        def failing_spawn(*_args, **_options):
            receipt.interrupt(signal.SIGTERM, None)
            raise OSError("spawn failed")

        subprocess.Popen = interrupted_spawn
        with self.assertRaises(SystemExit) as raised:
            receipt.leg("base", str(self.repo))
        self.assertEqual((raised.exception.code, receipt.child), (128 + signal.SIGINT, started[0]))
        receipt.stop_child()
        self.assertIsNotNone(started[0].poll())
        receipt.child, receipt.pending = None, None
        subprocess.Popen = failing_spawn
        with self.assertRaises(SystemExit) as raised:
            receipt.leg("base", str(self.repo))
        self.assertEqual((raised.exception.code, receipt.child), (128 + signal.SIGTERM, None))

    def test_a_sigterm_during_the_overlay_waits_for_it_and_starts_no_leg(self):
        marker, done = self.state / "overlay.txt", self.state / "overlay-finished"
        env = self.git_wrapper(
            'GIT "$@"\n'
            "status=$?\n"
            f'case "$*" in "{HOOKLESS}--literal-pathspecs checkout "*)\n'
            f'  touch "{marker}"; kill -TERM "$PPID"; sleep 1; touch "{done}" ;;\n'
            "esac\n"
            'exit "$status"\n')
        self.interrupt(marker, env=env)
        self.assertTrue(done.exists())
        self.assertEqual(self.builds(), [])

    def test_a_sigterm_between_legs_starts_no_head_leg_and_removes_the_worktrees(self):
        marker, done = self.state / "between.txt", self.state / "add-finished"
        env = self.git_wrapper(
            'GIT "$@"\n'
            "status=$?\n"
            f'case "$*" in "{HOOKLESS}worktree add --quiet --detach "*/head" "*)\n'
            f'  GIT worktree lock "$7"; touch "{marker}"; kill -TERM "$PPID"; sleep 1; touch "{done}" ;;\n'
            "esac\n"
            'exit "$status"\n')
        self.interrupt(marker, env=env)
        self.assertTrue(done.exists())
        self.assertEqual([build["leg"] for build in self.builds()], ["base"])


if __name__ == "__main__":
    unittest.main()
