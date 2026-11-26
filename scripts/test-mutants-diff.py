#!/usr/bin/env python3
"""Exercise mutants-diff.py with a fake cargo over disposable Git repositories.

The fixtures live under the checkout's own `target/`, because the runner refuses an artifacts directory below a
directory another user can write, such as a shared temporary directory.
"""

import contextlib
import ctypes
import fcntl
import hashlib
import importlib.util
import io
import json
import os
import re
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

# With the subreaper flag set, orphaned descendants reparent to this process
# and an exited one is a zombie until this process reaps it, so the cleanup
# assertions see a stopped process as gone or a zombie.
PR_SET_CHILD_SUBREAPER = 36
if ctypes.CDLL(None, use_errno=True).prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "prctl(PR_SET_CHILD_SUBREAPER) failed")

# The runner refuses a directory another user can write, so the fixtures are created without group or other write
# access whatever umask the test starts with.
os.umask(0o022)

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/mutants-diff.py"
FIXTURES = ROOT / "target"
SOURCE = "crates/kestrike/src"
DEFAULT_TESTS = ["--lib", "--", "--skip", "bind::", "--skip", "native::", "--skip", "soak"]
DIFF = ["diff", "--full-index"]
CONFIG = textwrap.dedent('''\
    # Tool pin: cargo-mutants 27.1.0
    exclude_globs = [
        # A comment between entries.
        "crates/kestrike/src/bind/**",
    ]
    exclude_re = ["tests::"]
    additional_cargo_args = ["--config", "profile.dev.debug-assertions=false"]
''')
WORKFLOW = 'env:\n  STABLE: "1.99.0"\n  NIGHTLY: "nightly-2026-07-27"\n'

# The fake follows the shapes cargo-mutants 27.1.0 wrote on the aarch64 host:
# `--list --json` prints an array of mutants with `name` and `file`, or
# nothing when the diff yields no mutant, and a run
# writes `<output>/mutants.out/outcomes.json`, an `outcomes` array whose
# baseline record has `"scenario": "Baseline"` and whose mutant records hold
# `{"Mutant": {...}}`, a `summary` and `phase_results`, beside running totals.
# A plan's `exit` repeats the statuses the tool returned there: 4 on a failed
# baseline, else 3 with a timeout, else 2 with a missed mutant.
CARGO = textwrap.dedent('''\
    #!/usr/bin/env python3
    import hashlib, json, math, os, signal, subprocess, sys, time
    from pathlib import Path
    state = Path(os.environ["FAKE_STATE"])
    plan = json.loads((state / "plan.json").read_text())
    args = sys.argv[1:]
    def value(flag):
        return args[args.index(flag) + 1] if flag in args else None
    def digest(path):
        return hashlib.sha256(Path(path).read_bytes()).hexdigest() if Path(path).is_file() else None
    def publish(name, text):
        (state / (name + ".tmp")).write_text(text)
        os.replace(state / (name + ".tmp"), state / name)
    def hang():
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"], start_new_session=True)
        def terminate(signum, frame):
            if plan.get("hold"):
                publish("terminating", str(signum))
                for _ in range(50):
                    if (state / "release").exists():
                        break
                    time.sleep(0.1)
            child.terminate()
            child.wait()
            publish("terminated", str(signum))
            sys.exit(1)
        signal.signal(signal.SIGTERM, terminate)
        source = Path("crates/kestrike/src/lib.rs")
        if source.is_file():
            with source.open("a") as out:
                out.write("// mutated in place\\n")
        publish("grandchild.pid", str(child.pid))
        publish("ready", str(os.getpid()))
        time.sleep(600)
    names = ("CARGO_TARGET_DIR", "CARGO_BUILD_BUILD_DIR", "RUSTUP_TOOLCHAIN", "CARGO_PROFILE_DEV_OPT_LEVEL",
             "CARGO_PROFILE_DEV_DEBUG", "RUSTFLAGS", "CARGO_HOME", "RUSTUP_HOME")
    call = {"argv": args, "cwd": os.getcwd(), **{name: os.environ.get(name) for name in names}}
    if args == ["-vV"]:
        print("cargo 1.99.0 (5f94df478 2026-08-27)\\nrelease: 1.99.0\\nhost: " + plan.get("host", "aarch64-unknown-linux-gnu"))
        sys.exit(0)
    if args == ["mutants", "--version"]:
        if plan.get("absent"):
            print("error: no such command: `mutants`", file=sys.stderr)
            sys.exit(101)
        print("cargo-mutants " + plan.get("version", "27.1.0"))
        sys.exit(0)
    listed = [{"name": name, "file": file, "package": "kestrike", "genre": "FnValue", "diff": "--- " + name}
              for file, name in plan.get("listed", [])]
    shard = value("--shard")
    if shard:
        k, n = map(int, shard.split("/"))
        size = math.ceil(len(listed) / n)
        listed = listed[k * size:(k + 1) * size]
    lock = Path("Cargo.lock")
    call.update(diff_sha256=digest(value("--in-diff")), config_sha256=digest(".cargo/mutants.toml"),
                lock=lock.read_text() if lock.is_file() else None,
                tests=args[args.index("--") + 1:] if "--" in args else None)
    with (state / "calls.jsonl").open("a") as out:
        out.write(json.dumps(call) + "\\n")
    if "--list" in args:
        if plan.get("list_exit"):
            sys.exit(plan["list_exit"])
        if plan.get("list_hang"):
            hang()
        if "raw_listing" in plan:
            print(plan["raw_listing"])
        elif listed:
            print(json.dumps(listed))
        sys.exit(0)
    if plan.get("drop_git"):
        Path(".git").unlink()
    if plan.get("stray"):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
        (state / "grandchild.pid").write_text(str(child.pid))
    directory = Path(value("--output")) / "mutants.out"
    directory.mkdir(parents=True)
    if "raw_outcomes" in plan:
        (directory / "outcomes.json").write_text(plan["raw_outcomes"])
        sys.exit(plan.get("exit", 0))
    phases = [{"phase": "Build", "duration": 1.25, "process_status": "Success", "argv": []},
              {"phase": "Test", "duration": 0.5, "process_status": "Success", "argv": []}]
    records = [{"scenario": "Baseline", "summary": plan.get("baseline", "Success"), "phase_results": phases}]
    def write():
        if plan.get("no_outcomes"):
            return
        totals = {"total_mutants": len(records) - 1, "missed": 0, "caught": 0, "timeout": 0, "unviable": 0}
        totals.update(plan.get("totals", {}))
        (directory / "outcomes.json").write_text(json.dumps({"outcomes": records, **totals}))
    write()
    for mutant in listed:
        summary = plan.get("outcomes", {}).get(mutant["name"])
        if summary is None:
            continue
        records.append({"scenario": {"Mutant": mutant}, "summary": summary, "phase_results": phases})
        write()
        if plan.get("hang"):
            hang()
    sys.exit(plan.get("exit", 0))
''')
GIT = textwrap.dedent('''\
    #!/usr/bin/env python3
    import os, subprocess, sys, time
    from pathlib import Path
    real, state, args = {real!r}, Path(os.environ["FAKE_STATE"]), sys.argv[1:]
    mode = os.environ.get("FAKE_GIT_MODE", "")
    if "worktree" in args and "add" in args and mode == "fail-add":
        sys.exit(3)
    if "worktree" in args and "remove" in args and mode == "fail-remove":
        print("fatal: refused", file=sys.stderr)
        sys.exit(1)
    if "worktree" in args and "add" in args and mode == "hang-add":
        at = args.index("add") + 1
        subprocess.run([real, *args[:at], "--lock", *args[at:]], check=True)
        (state / "ready.tmp").write_text(str(os.getpid()))
        os.replace(state / "ready.tmp", state / "ready")
        time.sleep(600)
    os.execv(real, [real, *args])
''')


def glob_pattern(glob):
    """A regular expression for one `exclude_globs` entry over a repository-relative path."""
    pattern = ""
    for part in re.split(r"(\*\*/|/\*\*$|\*|\?)", glob):
        pattern += {"**/": "(?:.*/)?", "/**": "/.*", "*": "[^/]*", "?": "[^/]"}.get(part, re.escape(part))
    return re.compile(pattern + "$")


def unmatched_globs(config, tracked):
    """The `exclude_globs` entries of `config` that match none of the `tracked` paths.

    The array holds comments and quoted strings of either kind; anything else in it fails the check.
    """
    body = re.search(r"^exclude_globs\s*=\s*\[(.*?)^\]", config, re.M | re.S)
    if body is None:
        raise AssertionError("the configuration has no exclude_globs array")
    text = re.sub(r"#[^\n]*", "", body.group(1))
    rest = re.sub(r'"[^"]*"|\'[^\']*\'|[\s,]', "", text)
    if rest:
        raise AssertionError(f"exclude_globs holds {rest!r} outside its strings")
    globs = [double or single for double, single in re.findall(r'"([^"]*)"|\'([^\']*)\'', text)]
    patterns = [(glob, glob_pattern(glob)) for glob in globs]
    return [glob for glob, pattern in patterns if not any(pattern.match(path) for path in tracked if path)]


def outcomes(*records):
    return json.dumps({"outcomes": list(records)})


def baseline(summary="Success", duration=0.5):
    return {"scenario": "Baseline", "summary": summary, "phase_results": [{"phase": "Test", "duration": duration}]}


def mutant(name, summary, duration=0.5):
    return {"scenario": {"Mutant": {"name": name, "file": f"{SOURCE}/lib.rs"}}, "summary": summary,
            "phase_results": [{"phase": "Test", "duration": duration}]}


def default_signals():
    for handled in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(handled, signal.SIG_DFL)


def ignored_hangup():
    default_signals()
    signal.signal(signal.SIGHUP, signal.SIG_IGN)


class MutantsDiff(unittest.TestCase):
    def setUp(self):
        FIXTURES.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="kestrike-mutants-test-", dir=FIXTURES)
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        self.cargo = self.state / "cargo"
        self.cargo.write_text(CARGO)
        self.cargo.chmod(0o755)
        self.artifacts = self.state / "artifacts"
        self.repo = self.state / "repo"
        self.repo.mkdir()
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(("GIT_", "CARGO_MUTANTS_", "CARGO_PROFILE_")) and not k.endswith("RUSTFLAGS")}
        self.env.update(FAKE_STATE=str(self.state), GIT_CONFIG_NOSYSTEM="1",
                        GIT_CONFIG_GLOBAL=str(self.state / "gitconfig"), GIT_AUTHOR_NAME="t",
                        GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
        self.git("init", "-q")
        self.write(".gitignore", "/target\nCargo.lock\n")
        self.write("Cargo.toml", "[workspace]\n")
        self.write(".cargo/mutants.toml", CONFIG)
        self.write(".github/workflows/agent-checks.yml", WORKFLOW)
        self.write(f"{SOURCE}/lib.rs", "pub fn one() -> u32 { 1 }\n")
        self.write("README.md", "readme\n")
        self.base = self.commit("base")
        self.write(f"{SOURCE}/lib.rs", "pub fn one() -> u32 { 1 }\npub fn two() -> u32 { 2 }\n")
        self.head = self.commit("head")
        (self.repo / "Cargo.lock").write_text("# lock\n")

    def git(self, *args, cwd=None):
        return subprocess.run(["git", *args], cwd=cwd or self.repo, env=self.env, capture_output=True, text=True,
                              check=True).stdout

    def write(self, name, text):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def commit(self, message, cwd=None):
        self.git("add", "-A", cwd=cwd)
        self.git("commit", "-q", "-m", message, cwd=cwd)
        return self.git("rev-parse", "HEAD", cwd=cwd).strip()

    def plan(self, listed=(), outcomes=None, **extra):
        plan = {"listed": [list(entry) for entry in listed], "outcomes": outcomes or {}}
        plan.update(extra)
        (self.state / "plan.json").write_text(json.dumps(plan))

    def command(self, *extra, base=None, head=None, artifacts=None):
        return [sys.executable, str(SCRIPT), "--base", base or self.base, "--head", head or self.head,
                "--artifacts", str(artifacts or self.artifacts), "--cargo", str(self.cargo), *extra]

    def run_mutants(self, *extra, env=None, cwd=None, **kwargs):
        return subprocess.run(self.command(*extra, **kwargs), cwd=cwd or self.repo, env=env or self.env,
                              capture_output=True, text=True, timeout=120, preexec_fn=default_signals)

    def git_wrapper(self, mode):
        """An environment whose `git` is the wrapper in `mode`."""
        bin_dir = self.state / "bin"
        if not bin_dir.exists():
            bin_dir.mkdir()
            (bin_dir / "git").write_text(GIT.format(real=shutil.which("git")))
            (bin_dir / "git").chmod(0o755)
        return {**self.env, "PATH": f"{bin_dir}:{self.env['PATH']}", "FAKE_GIT_MODE": mode}

    def snapshot(self):
        """The worktree list, the bytes of every file outside `.git` and `target`, and the index bytes."""
        files = {}
        for path in sorted(self.repo.rglob("*")):
            relative = path.relative_to(self.repo)
            if relative.parts[0] in (".git", "target") or not path.is_file():
                continue
            files[str(relative)] = path.read_bytes()
        return self.git("worktree", "list", "--porcelain"), files, (self.repo / ".git/index").read_bytes()

    def calls(self):
        path = self.state / "calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def builds(self):
        return [call for call in self.calls() if "--list" not in call["argv"]]

    def listings(self):
        return [call for call in self.calls() if "--list" in call["argv"]]

    def reports(self, artifacts=None):
        return sorted((artifacts or self.artifacts).glob("*/report.json"))

    def clear(self):
        for path in (*self.reports(), self.state / "ready", self.state / "terminated", self.state / "terminating",
                     self.state / "release", self.state / "calls.jsonl"):
            if path.exists():
                path.unlink()

    def report(self, result=None, artifacts=None):
        reports = self.reports(artifacts)
        if len(reports) != 1:
            self.fail(f"expected one report, found {reports}: {result.stdout if result else ''}"
                      f"{result.stderr if result else ''}")
        return json.loads(reports[0].read_text(), parse_constant=lambda constant: self.fail(f"report holds {constant}"))

    def assert_gone(self, name="grandchild.pid"):
        pid = int((self.state / name).read_text())
        self.assertGreater(pid, 0)
        self.assertTrue(Path("/proc/self/stat").is_file(), "the process check needs procfs")
        for _ in range(50):
            try:
                status = Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()[0]
            except (FileNotFoundError, ProcessLookupError):
                return
            if status == "Z":
                return
            time.sleep(0.1)
        self.fail(f"the fake's process {pid} outlived the run")

    def kill_leftovers(self, runner):
        """Stop a runner and a sleeper that a failing case left behind."""
        if runner.poll() is None:
            runner.kill()
            runner.communicate(timeout=30)
        path = self.state / "grandchild.pid"
        if path.exists():
            # A sleeper the fake reaped has freed its PID, so signal only a process that still runs the sleeper.
            with contextlib.suppress(OSError, ValueError):
                pid = int(path.read_text())
                if pid > 0 and b"time.sleep(600)" in Path(f"/proc/{pid}/cmdline").read_bytes():
                    os.kill(pid, signal.SIGKILL)

    def start_until_ready(self, env=None, preexec_fn=default_signals, marker="ready"):
        """Start the runner and return it once the fake has published `marker`."""
        runner = subprocess.Popen(self.command(), cwd=self.repo, env=env or self.env, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, preexec_fn=preexec_fn)
        self.addCleanup(self.kill_leftovers, runner)
        self.wait_for(marker, runner)
        return runner

    def wait_for(self, marker, runner):
        for _ in range(300):
            if (self.state / marker).exists() or runner.poll() is not None:
                break
            time.sleep(0.1)
        if not (self.state / marker).exists():
            runner.kill()
            self.fail(f"the fake never published {marker}: {runner.communicate(timeout=30)}")

    def test_a_complete_run_with_missed_mutants_exits_0_and_prints_each_missed(self):
        listed = [(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:2:1: replace two -> u32 with {n}") for n in (0, 1)]
        listed.append((f"{SOURCE}/other.rs", f"{SOURCE}/other.rs:1:1: replace three -> u32 with 0"))
        self.plan(listed, {listed[0][1]: "MissedMutant", listed[1][1]: "MissedMutant",
                           listed[2][1]: "CaughtMutant"}, exit=2, stray=True)
        before = self.snapshot()
        result = self.run_mutants()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        line = (f"mutants: {self.head[:12]} against {self.base[:12]} on aarch64: 3 listed, 1 caught, 2 missed, "
                "0 timeout, 0 unviable; complete")
        self.assertEqual(result.stdout.splitlines(), [line, f"missed: {listed[0][1]}", f"missed: {listed[1][1]}"])
        report = self.report(result)
        self.assertTrue(report["complete"])
        self.assertEqual(report["flagged"], [f"{SOURCE}/lib.rs"], "the file with a caught mutant is not flagged")
        self.assertEqual(report["tool_exit"], 2)
        self.assertEqual(report["mutants"][0]["phase_seconds"], {"build": 1.25, "test": 0.5})
        [listing] = self.artifacts.glob("*/list.json")
        self.assertEqual([(m["name"], m["diff"]) for m in json.loads(listing.read_text())],
                         [(name, f"--- {name}") for _, name in listed], "list.json keeps each mutant's diff")
        self.assertEqual(self.snapshot(), before)
        self.assert_gone()

    def test_a_listed_mutant_without_an_outcome_makes_the_run_incomplete(self):
        listed = [(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:2:1: replace two -> u32 with {n}") for n in (0, 1)]
        self.plan(listed, {listed[0][1]: "CaughtMutant"})
        result = self.run_mutants()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertTrue(result.stdout.splitlines()[0].endswith("1 caught, 0 missed, 0 timeout, 0 unviable; incomplete"))
        report = self.report(result)
        self.assertFalse(report["complete"])
        self.assertEqual(report["reason"], "1 listed mutants have no outcome and 0 judged mutants were not listed")
        self.assertEqual([m["outcome"] for m in report["mutants"]], ["caught", "not-run"])
        self.assertEqual(report["counts"]["not-run"], 1)

    def test_a_failed_baseline_credits_no_kill(self):
        listed = [(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:2:1: replace two -> u32 with 0")]
        self.plan(listed, {listed[0][1]: "CaughtMutant"}, baseline="Failure", exit=4)
        result = self.run_mutants()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        report = self.report(result)
        self.assertEqual((report["baseline"], report["complete"], report["reason"]),
                         ("failed", False, "the baseline failed"))
        self.assertEqual(report["counts"], {"listed": 1, "caught": 0, "missed": 0, "timeout": 0, "unviable": 0,
                                            "not-run": 1})
        self.assertIn("reason: the baseline failed", result.stdout)

    def test_a_malformed_listing_or_outcome_file_makes_the_run_incomplete(self):
        names = [f"{SOURCE}/lib.rs:2:1: replace two -> u32 with {n}" for n in (0, 1)]
        listed = [(f"{SOURCE}/lib.rs", name) for name in names]
        a, b = names
        unreadable = "the tool wrote no readable outcome file"
        failed = "the baseline failed"
        absent = "the outcome file holds no baseline"
        caught = (mutant(a, "CaughtMutant"), mutant(b, "CaughtMutant"))
        cases = (
            ({"raw_listing": "{}"}, "the listing does not parse: expected an array of mutants"),
            ({"raw_listing": json.dumps([{"name": ["x"], "file": "f"}])},
             "the listing does not parse: expected an array of mutants"),
            ({"raw_listing": json.dumps([{"name": a, "file": "f"}, {"name": a, "file": "f"}])},
             "the listing does not parse: a mutant name repeats"),
            ({"raw_outcomes": "[" * 200000}, unreadable),
            ({"raw_outcomes": outcomes(baseline(), mutant(a, "CaughtMutant"), mutant(a, "MissedMutant"),
                                       mutant(b, "CaughtMutant"))}, unreadable),
            ({"raw_outcomes": outcomes(baseline(), mutant(a, "Failure"), *caught)}, unreadable),
            ({"raw_outcomes": outcomes(baseline(), *caught, mutant(a, "Failure"))}, unreadable),
            ({"raw_outcomes": outcomes(baseline("Failure"), baseline(), *caught)}, unreadable),
            ({"raw_outcomes": outcomes(baseline(), baseline("Failure"), *caught)}, unreadable),
            ({"raw_outcomes": outcomes(baseline(), mutant(a, "CaughtMutant", float("nan")),
                                       mutant(b, "CaughtMutant"))}, unreadable),
            ({"raw_outcomes": outcomes(baseline(), mutant(a, "CaughtMutant", -1), mutant(b, "CaughtMutant"))},
             unreadable),
            ({"raw_outcomes": outcomes(baseline(), mutant(a, "CaughtMutant", 10 ** 400), mutant(b, "CaughtMutant"))},
             unreadable),
            ({"raw_outcomes": outcomes(baseline(duration=float("nan")), *caught)}, unreadable),
            ({"raw_outcomes": outcomes(baseline(), {**mutant(a, "CaughtMutant"), "phase_results": {}},
                                       mutant(b, "CaughtMutant"))}, unreadable),
            ({"raw_outcomes": outcomes(*caught)}, absent),
            ({"raw_outcomes": outcomes(baseline(), *caught, mutant("unlisted", "CaughtMutant"))},
             "0 listed mutants have no outcome and 1 judged mutants were not listed"),
            ({"raw_outcomes": outcomes(baseline(), mutant(a, "CaughtMutant"), mutant("unlisted", "CaughtMutant"))},
             "1 listed mutants have no outcome and 1 judged mutants were not listed"),
            ({"raw_outcomes": outcomes(baseline(), mutant(a, "CaughtMutant"), mutant(b, "Failure"))},
             "1 listed mutants have no outcome and 0 judged mutants were not listed"),
            ({"raw_outcomes": outcomes(baseline("Failure"), *caught)}, failed),
            ({"raw_outcomes": outcomes(baseline(), *caught), "exit": 4}, failed),
            ({"raw_outcomes": outcomes(baseline(), mutant(a, "CaughtMutant")), "exit": 4}, failed),
        )
        for extra, reason in cases:
            with self.subTest(reason=reason, extra=str(extra)[:80]):
                self.clear()
                self.plan(listed, **extra)
                result = self.run_mutants()
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                report = self.report(result)
                self.assertFalse(report["complete"])
                self.assertTrue(report["reason"].startswith(reason), report["reason"])
                if reason in (unreadable, failed, absent):
                    self.assertEqual(report["counts"]["caught"], 0)
                if "raw_listing" in extra:
                    self.assertEqual((self.builds(), report["counts"]["listed"]), ([], 0))
                if reason in (failed, absent):
                    self.assertEqual({m["outcome"] for m in report["mutants"]}, {"not-run"})

    def test_timeout_and_unviable_are_counted_apart_and_the_tool_totals_are_recomputed(self):
        names = [f"{SOURCE}/lib.rs:{n}:1: replace two -> u32 with {n}" for n in range(4)]
        self.plan([(f"{SOURCE}/lib.rs", name) for name in names],
                  {names[0]: "Timeout", names[1]: "Unviable", names[2]: "CaughtMutant", names[3]: "MissedMutant"},
                  totals={"total_mutants": 9, "caught": 4, "missed": 0, "timeout": 0, "unviable": 0}, exit=3)
        result = self.run_mutants()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(": 4 listed, 1 caught, 1 missed, 1 timeout, 1 unviable; complete", result.stdout)
        report = self.report(result)
        self.assertEqual(report["counts"], {"listed": 4, "caught": 1, "missed": 1, "timeout": 1, "unviable": 1,
                                            "not-run": 0})
        self.assertEqual(report["flagged"], [], "a file whose viable mutants include a timeout is not flagged")

    def test_a_file_whose_viable_mutants_were_all_missed_is_flagged(self):
        missed, unviable = f"{SOURCE}/gated.rs", f"{SOURCE}/unviable.rs"
        caught, timeout = f"{SOURCE}/caught.rs", f"{SOURCE}/timeout.rs"
        plan = {f"{missed}:1:1: a": "MissedMutant", f"{missed}:2:1: b": "Unviable",
                f"{unviable}:1:1: c": "Unviable",
                f"{caught}:1:1: d": "CaughtMutant", f"{caught}:2:1: e": "MissedMutant",
                f"{timeout}:1:1: f": "Timeout", f"{timeout}:2:1: g": "MissedMutant"}
        self.plan([(name.split(":")[0], name) for name in plan], plan, exit=3)
        result = self.run_mutants()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.report(result)["flagged"], [missed],
                         "a caught or timed-out mutant beside a missed one keeps its file unflagged")

    def test_an_empty_diff_and_an_excluded_only_diff_list_nothing_and_build_nothing(self):
        self.write("README.md", "changed\n")
        docs = self.commit("docs")
        self.write(f"{SOURCE}/bind/host.rs", "pub fn host() {}\n")
        excluded = self.commit("excluded")
        self.plan()
        for base, head, listings in ((self.head, docs, 0), (docs, excluded, 1)):
            for stale in self.reports():
                stale.unlink()
            result = self.run_mutants(base=base, head=head)
            self.assertEqual((result.returncode, result.stdout), (0, "mutants: 0 listed\n"), result.stderr)
            report = self.report(result)
            self.assertEqual((report["complete"], report["mutants"], report["counts"]["listed"]), (True, [], 0))
            self.assertEqual(len(self.listings()), listings)
        self.assertEqual(self.builds(), [])

    def test_more_mutants_than_the_limit_are_refused_before_any_build(self):
        self.plan([(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:{n}:1: m") for n in range(3)])
        before = self.snapshot()
        result = self.run_mutants("--max-mutants", "2")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("mutants: 3 listed, above --max-mutants 2", result.stdout)
        self.assertEqual(self.builds(), [])
        self.assertEqual(self.reports(), [])
        self.assertEqual(self.snapshot(), before)

    def test_a_limit_refusal_whose_worktree_remains_exits_2_and_names_the_worktree(self):
        self.plan([(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:{n}:1: m") for n in range(3)])
        self.addCleanup(self.git, "worktree", "prune")
        result = self.run_mutants("--max-mutants", "2", env=self.git_wrapper("fail-remove"))
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("mutants: 3 listed, above --max-mutants 2", result.stdout)
        self.assertIn("mutants rejected: raise --max-mutants", result.stderr)
        self.assertRegex(result.stderr, r"mutants: the worktree .* remains: fatal: refused")
        self.assertEqual(self.builds(), [])
        self.assertEqual(self.reports(), [])
        self.assertEqual(self.git("worktree", "list", "--porcelain").count("worktree "), 2)

    def test_an_unknown_revision_an_absent_tool_and_another_version_are_refused_before_any_build(self):
        self.plan([(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:1:1: m")])
        for revision in ({"head": "no-such-revision"}, {"base": "no-such-base"}):
            result = self.run_mutants(**revision)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn(f"unknown revision {next(iter(revision.values()))!r}", result.stderr)
        self.plan([(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:1:1: m")], absent=True)
        result = self.run_mutants()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("cargo mutants --version exited 101 (error: no such command: `mutants`); install the "
                      "pinned tool: cargo install --locked --version 27.1.0 cargo-mutants", result.stderr)
        self.plan([(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:1:1: m")], version="26.2.0")
        result = self.run_mutants()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("cargo mutants is 26.2.0, the configuration pins 27.1.0; install it: "
                      "cargo install --locked --version 27.1.0 cargo-mutants", result.stderr)
        self.assertEqual(self.calls(), [])
        self.assertFalse(self.artifacts.exists(), "each refusal comes before the run directory")

    def test_each_rejected_input_exits_2_without_a_report_or_a_build(self):
        listed = [(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:2:1: m")]
        config, workflow = self.repo / ".cargo/mutants.toml", self.repo / ".github/workflows/agent-checks.yml"
        originals = {config: config.read_bytes(), workflow: workflow.read_bytes()}
        self.artifacts.mkdir()
        held = os.open(self.artifacts / "build.lock", os.O_WRONLY | os.O_CREAT, 0o600)
        self.addCleanup(os.close, held)
        fifo, link, shared, loop = (self.state / name for name in ("fifo", "link", "shared", "loop"))
        fifo.mkdir(mode=0o700)
        os.mkfifo(fifo / "build.lock")
        link.mkdir(mode=0o700)
        (link / "build.lock").symlink_to(self.state / "absent-lock")
        shared.mkdir()
        shared.chmod(0o777)
        (self.state / "into-shared").symlink_to(shared)
        loop.symlink_to(loop)
        # Cargo searches the worktree's ancestors for `.cargo/config.toml`. Another user can edit a world-writable
        # config file or create one in a world-writable `.cargo` directory.
        open_file, open_entry = self.state / "open-file", self.state / "open-entry"
        for private in (open_file, open_entry):
            (private / ".cargo").mkdir(parents=True)
        (open_file / ".cargo/config.toml").write_text('[build]\nrustc-wrapper = "/nonexistent"\n')
        (open_file / ".cargo/config.toml").chmod(0o666)
        (open_entry / ".cargo").chmod(0o777)
        pinless = CONFIG.replace("# Tool pin: cargo-mutants 27.1.0\n", "")
        cases = (
            ("two pin lines", (), {}, lambda: config.write_text(CONFIG + "# Tool pin: cargo-mutants 27.1.0\n"),
             "must hold one tool pin line"),
            ("no pin line", (), {}, lambda: config.write_text(pinless), "must hold one tool pin line"),
            ("no STABLE pin", (), {}, lambda: workflow.write_text("env: {}\n"), "one STABLE pin"),
            ("two STABLE pins", (), {}, lambda: workflow.write_text(WORKFLOW + '  STABLE: "1.98.0"\n'),
             "one STABLE pin"),
            ("an unreadable configuration", (), {}, lambda: config.write_bytes(b"\xff" + originals[config]),
             "UnicodeDecodeError"),
            ("a cargo that cannot run", ("--cargo", str(self.state / "absent")), {}, None, "cannot run"),
            ("no host", (), {"host": ""}, None, "-vV names no host"),
            ("a test-profile assertion variable", (), {"env": {"CARGO_PROFILE_TEST_DEBUG_ASSERTIONS": "true"}},
             None, "unset CARGO_PROFILE_TEST_DEBUG_ASSERTIONS"),
            ("an overflow-check variable", (), {"env": {"CARGO_PROFILE_DEV_OVERFLOW_CHECKS": "false"}}, None,
             "unset CARGO_PROFILE_DEV_OVERFLOW_CHECKS"),
            ("a tool variable", (), {"env": {"CARGO_MUTANTS_JOBS": "4"}}, None, "unset CARGO_MUTANTS_JOBS"),
            ("assertions in RUSTFLAGS", (), {"env": {"RUSTFLAGS": "-C debug-assertions=on"}}, None,
             "unset RUSTFLAGS"),
            ("assertions in encoded flags", (), {"env": {"CARGO_ENCODED_RUSTFLAGS": "-Cdebug-assertions=on"}}, None,
             "unset CARGO_ENCODED_RUSTFLAGS"),
            ("an abbreviated option", ("--test", "sim_worker"), {}, None, "unrecognized arguments"),
            ("shard index N", ("--shard", "2/2"), {}, None, "K/N with 0 <= K < N"),
            ("a zero limit", ("--max-mutants", "0"), {}, None, "a positive integer"),
            ("an empty base", ("--base", ""), {}, None, "argument --base: a value"),
            ("an empty artifacts directory", ("--artifacts", ""), {}, None, "argument --artifacts: a value"),
            ("a held artifacts directory", (), {}, lambda: fcntl.flock(held, fcntl.LOCK_EX), "another run holds"),
            ("a FIFO lock", ("--artifacts", str(fifo)), {}, None, "cannot be opened as a lock file"),
            ("a linked lock", ("--artifacts", str(link)), {}, None, "cannot be opened as a lock file"),
            ("a shared ancestor", ("--artifacts", str(shared / "artifacts")), {}, None,
             f"another user owns or can write {shared}"),
            ("a link into a shared ancestor", ("--artifacts", str(self.state / "into-shared/artifacts")), {}, None,
             f"another user owns or can write {shared}"),
            ("a Cargo configuration file another user can write", ("--artifacts", str(open_file / "artifacts")), {},
             None, f"another user owns or can write {open_file / '.cargo/config.toml'}"),
            ("a Cargo configuration directory another user can write", ("--artifacts", str(open_entry / "artifacts")),
             {}, None, f"another user owns or can write {open_entry / '.cargo'}"),
            ("a looping artifacts path", ("--artifacts", str(loop / "artifacts")), {}, None, "mutants rejected:"),
        )
        for label, extra, options, setup, message in cases:
            with self.subTest(label):
                self.clear()
                self.plan(listed, {listed[0][1]: "CaughtMutant"},
                          host=str(options.get("host", "aarch64-unknown-linux-gnu")))
                if setup:
                    setup()
                inherited = options.get("env", {})
                assert isinstance(inherited, dict)
                try:
                    result = self.run_mutants(*extra, env={**self.env, **inherited})
                finally:
                    for path, data in originals.items():
                        path.write_bytes(data)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn(message, result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertEqual(self.calls(), [])
                self.assertEqual([*self.reports(), *shared.rglob("*"), *open_file.glob("artifacts"),
                                  *open_entry.glob("artifacts"),
                                  *(entry for entry in (*fifo.iterdir(), *link.iterdir()) if entry.is_dir())], [])
        self.assertFalse(os.path.lexists(self.state / "absent-lock"), "the lock open does not follow a link")
        result = self.run_mutants(artifacts=self.state / "other-artifacts", env={**self.env, "RUSTFLAGS": "-C opt"})
        self.assertEqual(result.returncode, 0, "another artifacts directory runs beside the held one, and flags "
                                               f"that set no assertion pass: {result.stdout}{result.stderr}")
        self.assertEqual(self.calls()[0]["RUSTFLAGS"], "-C opt")

    def test_an_inherited_repository_override_is_refused_and_leaves_the_index_unchanged(self):
        self.write(f"{SOURCE}/lib.rs", "pub fn staged() {}\n")
        self.git("add", f"{SOURCE}/lib.rs")
        self.write(f"{SOURCE}/lib.rs", "pub fn unstaged() {}\n")
        self.plan([(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:2:1: m")])
        before = self.snapshot()
        dot_git = self.repo / ".git"
        for name, value in (("GIT_DIR", dot_git), ("GIT_WORK_TREE", self.repo), ("GIT_INDEX_FILE", dot_git / "index"),
                            ("GIT_COMMON_DIR", dot_git), ("GIT_OBJECT_DIRECTORY", dot_git / "objects")):
            with self.subTest(name):
                result = self.run_mutants(env={**self.env, name: str(value)})
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn(f"unset {name}", result.stderr)
                self.assertEqual(self.snapshot(), before)
                self.assertEqual(self.calls(), [])
                self.assertFalse(self.artifacts.exists())

    def test_a_tool_failure_is_incomplete_and_leaves_the_checkout_as_it_was(self):
        listed = [(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:2:1: replace two -> u32 with 0")]
        before = self.snapshot()
        cases = (
            ({"no_outcomes": True, "stray": True}, None, 0, "the tool wrote no readable outcome file"),
            ({"list_exit": 1}, None, 0, "the listing exited 1"),
            ({"outcomes": {listed[0][1]: "CaughtMutant"}, "exit": 70, "stray": True}, None, 1, "the tool exited 70"),
            ({}, self.git_wrapper("fail-add"), 0, "git worktree add exited 3"),
        )
        for extra, env, caught, reason in cases:
            with self.subTest(reason=reason):
                self.clear()
                self.plan(listed, **extra)
                result = self.run_mutants(env=env)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                report = self.report(result)
                self.assertEqual((report["complete"], report["reason"], report["counts"]["caught"]),
                                 (False, reason, caught))
                self.assertEqual(self.snapshot(), before)
                if extra.get("stray"):
                    self.assert_gone()
                if env is not None:
                    self.assertEqual(self.calls(), [])

    def test_a_worktree_that_remains_after_removal_makes_the_run_incomplete(self):
        listed = [(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:2:1: m")]
        self.plan(listed, {listed[0][1]: "CaughtMutant"})
        self.addCleanup(self.git, "worktree", "prune")
        result = self.run_mutants(env=self.git_wrapper("fail-remove"))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        report = self.report(result)
        self.assertFalse(report["complete"])
        self.assertTrue(report["reason"].startswith("the worktree "), report["reason"])
        self.assertIn("fatal: refused", report["reason"])
        self.assertEqual(self.git("worktree", "list", "--porcelain").count("worktree "), 2)

    def test_a_worktree_that_remains_under_a_path_with_a_line_break_makes_the_run_incomplete(self):
        listed = [(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:2:1: m")]
        self.plan(listed, {listed[0][1]: "CaughtMutant"})
        for registered, name in enumerate(("arti\nfacts", "arti\rfacts"), start=2):
            with self.subTest(name=name):
                self.addCleanup(self.git, "worktree", "prune")
                artifacts = self.state / name
                result = self.run_mutants(artifacts=artifacts, env=self.git_wrapper("fail-remove"))
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                report = self.report(result, artifacts)
                self.assertFalse(report["complete"])
                self.assertTrue(report["reason"].startswith("the worktree "), report["reason"])
                self.assertEqual(self.git("worktree", "list", "--porcelain").count("worktree "), registered)

    def test_a_worktree_without_its_git_file_is_removed_once_its_directory_is_gone(self):
        listed = [(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:2:1: m")]
        self.plan(listed, {listed[0][1]: "CaughtMutant"}, drop_git=True)
        self.addCleanup(self.git, "worktree", "prune")
        before = self.snapshot()
        result = self.run_mutants()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.report(result)["complete"])
        self.assertEqual(self.snapshot(), before)

    def test_each_printed_line_is_one_line_the_stream_can_encode(self):
        names = [f"{SOURCE}/lib.rs:2:1: lone \ud800 surrogate", f"{SOURCE}/lib.rs:3:1: first\nmissed: forged\rline"]
        listed = [(f"{SOURCE}/lib.rs", name) for name in names]
        self.plan(listed, dict.fromkeys(names, "MissedMutant"), exit=2)
        result = self.run_mutants()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual([entry["name"] for entry in self.report(result)["mutants"]], names)
        self.assertEqual(result.stdout.splitlines()[1:],
                         [f"missed: {SOURCE}/lib.rs:2:1: lone \\ud800 surrogate",
                          f"missed: {SOURCE}/lib.rs:3:1: first\\nmissed: forged\\rline"])

    def test_a_checkout_path_that_is_not_utf_8_is_kept(self):
        odd = Path(os.fsdecode(os.fsencode(self.state / "repo") + b"\xff"))
        self.git("clone", "-q", str(self.repo), str(odd))
        listed = [(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:2:1: m")]
        self.plan(listed, {listed[0][1]: "CaughtMutant"})
        clean = self.run_mutants(cwd=odd)
        self.assertEqual(clean.returncode, 0, clean.stdout + clean.stderr)
        self.clear()
        self.addCleanup(self.git, "worktree", "prune", cwd=odd)
        left = self.run_mutants(cwd=odd, artifacts=odd / "target/mutants", env=self.git_wrapper("fail-remove"))
        self.assertEqual(left.returncode, 1, left.stdout + left.stderr)
        self.assertNotIn("Traceback", left.stderr)
        self.assertIn("reason: the worktree ", left.stdout)
        self.assertIn("repo\\udcff", left.stdout)

    def test_a_head_without_a_root_manifest_starts_no_listing(self):
        (self.repo / "Cargo.toml").unlink()
        self.write(f"{SOURCE}/lib.rs", "pub fn one() -> u32 { 1 }\npub fn three() -> u32 { 3 }\n")
        head = self.commit("no root manifest")
        self.git("checkout", "-q", "--detach", self.head)
        self.plan([(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:2:1: m")])
        before = self.snapshot()
        result = self.run_mutants(base=self.head, head=head)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.report(result)["reason"],
                         "the head has no root Cargo.toml, so Cargo would take an enclosing workspace")
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.snapshot(), before)

    def test_malformed_test_arguments_are_refused_and_a_refused_report_directory_is_reported(self):
        self.plan([(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:1:1: m")], {f"{SOURCE}/lib.rs:1:1: m": "CaughtMutant"})
        for tests in ("--test 'unclosed", ""):
            result = self.run_mutants("--tests", tests)
            self.assertEqual(result.returncode, 2, f"{tests!r}: {result.stdout}{result.stderr}")
        self.assertEqual(self.calls(), [])
        (self.state / "blocked").write_text("a file where the artifacts directory would be\n")
        result = self.run_mutants(artifacts=self.state / "blocked/artifacts")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("mutants: the report could not be written:", result.stderr)
        self.assertEqual(self.git("worktree", "list", "--porcelain").count("worktree "), 1)

    def runner(self):
        spec = importlib.util.spec_from_file_location("mutants_diff", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_the_debug_assertion_entry_is_read_from_the_array_and_not_from_a_comment(self):
        read = self.runner().debug_assertions
        self.assertEqual(read(CONFIG), "false")
        for text, value in (
            ('additional_cargo_args = [\n    "--config",\n    "profile.dev.debug-assertions=true", # why\n]\n', "true"),
            ("additional_cargo_args = ['--config', 'profile.dev.debug-assertions=true']\n", "true"),
            ('  additional_cargo_args = ["--config", "profile.dev.debug-assertions=true"]\n', "true"),
            ('additional_cargo_args = ["--config=profile.dev.debug-assertions=true"]\n', "true"),
            ('additional_cargo_args = ["--config", "profile.dev.debug-assertions = true"]\n', "true"),
            ('additional_cargo_args = ["--config", "profile.dev.debug-assertions=false", "--config",\n'
             '    "profile.dev.debug-assertions=true"]\n', "true"),
            ('additional_cargo_args = ["a]b", "--config", "profile.dev.debug-assertions=true"]\n', "true"),
            ('"additional_cargo_args" = ["--config", "profile.dev.debug-assertions=true"]\n', "true"),
            ("'additional_cargo_args' = ['--config', 'profile.dev.debug-assertions=true']\n", "true"),
            ('additional_cargo_args = []  # "profile.dev.debug-assertions=true"\n', None),
            ('exclude_re = ["profile.dev.debug-assertions=true"]\n', None),
        ):
            with self.subTest(text=text):
                self.assertEqual(read(text), value)
        for text in ('additional_cargo_args = ["--config", "profile.test.debug-assertions=true"]\n',
                     "additional_cargo_args = [profile]\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                read(text)

    def test_a_configuration_the_runner_cannot_read_makes_the_run_incomplete(self):
        self.write(".cargo/mutants.toml", CONFIG.replace("profile.dev.debug-assertions", "profile.test.debug-assertions"))
        self.write(f"{SOURCE}/lib.rs", "pub fn one() -> u32 { 1 }\npub fn three() -> u32 { 3 }\n")
        head = self.commit("an unread entry")
        self.plan([(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:2:1: m")])
        result = self.run_mutants(base=self.head, head=head)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertTrue(self.report(result)["reason"].startswith("the worktree configuration does not parse"))
        self.assertEqual(self.calls(), [])

    def test_a_signal_during_a_spawn_stops_the_new_process(self):
        module = self.runner()
        spawn = module.subprocess.Popen
        self.addCleanup(setattr, module.subprocess, "Popen", spawn)
        self.addCleanup(signal.pthread_sigmask, signal.SIG_UNBLOCK, module.SIGNALS)
        for before_fork in (True, False):
            with self.subTest(before_fork=before_fork):
                run, spawned = module.Run(None), []

                def interrupted_spawn(*argv, run=run, spawned=spawned, before_fork=before_fork, **options):
                    if before_fork:
                        run.interrupt(signal.SIGTERM, None)
                    process = spawn(*argv, **options)
                    spawned.append(process)
                    if not before_fork:
                        run.interrupt(signal.SIGTERM, None)
                    return process

                module.subprocess.Popen = interrupted_spawn
                with self.assertRaises(module.Stop) as stopped:
                    module.supervise(run, ["sleep", "600"], self.state / "out", self.state / "err")
                self.assertEqual((stopped.exception.code, str(stopped.exception), run.child),
                                 (module.INCOMPLETE, f"interrupted by signal {int(signal.SIGTERM)}", None))
                self.assertEqual(spawned[0].returncode, -signal.SIGTERM,
                                 "the new process starts with the runner's signal mask and ends on SIGTERM")
                self.assertTrue(set(module.SIGNALS) <= signal.pthread_sigmask(signal.SIG_BLOCK, []),
                                "the first signal blocks the handled signals")
                signal.pthread_sigmask(signal.SIG_UNBLOCK, module.SIGNALS)

    def test_a_first_signal_at_the_hand_off_to_cleanup_still_removes_the_worktree_and_writes_the_report(self):
        module = self.runner()
        listed = [(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:2:1: m")]
        self.plan(listed, {listed[0][1]: "CaughtMutant"})
        before = self.git("worktree", "list", "--porcelain")
        ignore, calls = module.ignore_signals, []

        def interrupted_ignore():
            if not calls:
                calls.append(signal.SIGTERM)
                signal.raise_signal(signal.SIGTERM)
            ignore()

        patched = mock.patch.object(module, "ignore_signals", interrupted_ignore)
        patched.start()
        self.addCleanup(patched.stop)
        for handled, disposition in [(s, signal.getsignal(s)) for s in module.SIGNALS]:
            self.addCleanup(signal.signal, handled, disposition)
        default_signals()
        self.addCleanup(signal.pthread_sigmask, signal.SIG_UNBLOCK, module.SIGNALS)
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.repo)
        with mock.patch.dict(os.environ, self.env, clear=True), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = module.main(self.command()[2:])
        self.assertEqual((code, calls), (1, [signal.SIGTERM]))
        report = self.report()
        self.assertEqual((report["complete"], report["reason"]),
                         (False, f"interrupted by signal {int(signal.SIGTERM)}"))
        self.assertEqual(self.git("worktree", "list", "--porcelain"), before)

    def test_a_signal_while_a_mutant_runs_stops_the_tool_and_removes_the_worktree(self):
        listed = [(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:2:1: replace two -> u32 with {n}") for n in (0, 1)]
        before = self.snapshot()
        for handled in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            self.clear()
            self.plan(listed, {name: "CaughtMutant" for _, name in listed}, hang=True)
            runner = self.start_until_ready()
            runner.send_signal(handled)
            stdout, stderr = runner.communicate(timeout=60)
            self.assertEqual(runner.returncode, 1, f"{handled!r}: {stdout}{stderr}")
            report = self.report()
            self.assertEqual((report["complete"], report["reason"]),
                             (False, f"interrupted by signal {int(handled)}"))
            self.assertEqual([m["outcome"] for m in report["mutants"]], ["caught", "not-run"])
            self.assertTrue(stdout.splitlines()[0].endswith("; incomplete"), stdout)
            self.assertEqual(self.snapshot(), before, f"{handled!r}: the dirty worktree is removed")
            self.assertTrue((self.state / "terminated").exists(), f"{handled!r}: the tool received SIGTERM first")
            self.assert_gone()
            self.assert_gone("ready")

    def test_a_second_signal_during_cleanup_is_discarded(self):
        listed = [(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:2:1: m")]
        self.plan(listed, list_hang=True, hold=True)
        before = self.snapshot()
        runner = self.start_until_ready()
        runner.send_signal(signal.SIGTERM)
        self.wait_for("terminating", runner)
        runner.send_signal(signal.SIGINT)
        (self.state / "release").write_text("")
        stdout, stderr = runner.communicate(timeout=60)
        self.assertEqual(runner.returncode, 1, stdout + stderr)
        report = self.report()
        self.assertEqual((report["complete"], report["reason"]),
                         (False, f"interrupted by signal {int(signal.SIGTERM)}"))
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.builds(), [])
        self.assert_gone()
        self.assert_gone("ready")

    def test_a_signal_while_the_worktree_is_added_or_the_listing_runs_stops_it_and_removes_the_worktree(self):
        listed = [(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:2:1: m")]
        before = self.snapshot()
        for phase, env, extra in (("worktree add", self.git_wrapper("hang-add"), {}),
                                  ("listing", self.env, {"list_hang": True})):
            with self.subTest(phase=phase):
                self.clear()
                self.plan(listed, **extra)
                runner = self.start_until_ready(env=env)
                runner.send_signal(signal.SIGTERM)
                stdout, stderr = runner.communicate(timeout=60)
                self.assertEqual(runner.returncode, 1, stdout + stderr)
                report = self.report()
                self.assertEqual((report["complete"], report["reason"]),
                                 (False, f"interrupted by signal {int(signal.SIGTERM)}"))
                self.assertEqual(self.snapshot(), before)
                self.assertEqual(self.builds(), [])
                self.assert_gone("ready")

    def test_a_signal_ignored_at_start_stays_ignored(self):
        listed = [(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:2:1: replace two -> u32 with {n}") for n in (0, 1)]
        self.plan(listed, {name: "CaughtMutant" for _, name in listed}, hang=True)
        runner = self.start_until_ready(preexec_fn=ignored_hangup)
        runner.send_signal(signal.SIGHUP)
        time.sleep(1)
        self.assertIsNone(runner.poll(), "a run started under nohup outlives its terminal")
        runner.send_signal(signal.SIGTERM)
        stdout, stderr = runner.communicate(timeout=60)
        self.assertEqual(runner.returncode, 1, stdout + stderr)
        self.assertEqual(self.report()["reason"], f"interrupted by signal {int(signal.SIGTERM)}")

    def test_a_killed_runner_stops_the_tool(self):
        listed = [(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:2:1: replace two -> u32 with {n}") for n in (0, 1)]
        self.plan(listed, {name: "CaughtMutant" for _, name in listed}, hang=True)
        self.addCleanup(self.git, "worktree", "prune")
        runner = self.start_until_ready()
        runner.kill()
        runner.communicate(timeout=60)
        self.assert_gone("ready")
        self.assert_gone()
        self.assertTrue((self.state / "terminated").exists(), "the tool received SIGTERM when the runner died")

    def test_a_live_run_holds_its_artifacts_directory(self):
        listed = [(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:2:1: replace two -> u32 with {n}") for n in (0, 1)]
        self.plan(listed, {name: "CaughtMutant" for _, name in listed}, hang=True)
        first = self.start_until_ready()
        self.plan(listed, {name: "CaughtMutant" for _, name in listed})
        builds = len(self.builds())
        result = self.run_mutants()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("another run holds", result.stderr)
        self.assertEqual((len(self.builds()), len(self.reports())), (builds, 0))
        other = self.state / "other-artifacts"
        self.assertEqual(self.run_mutants(artifacts=other).returncode, 0, "another directory runs beside it")
        first.send_signal(signal.SIGTERM)
        first.communicate(timeout=60)
        for stale in self.reports():
            stale.unlink()
        result = self.run_mutants()
        self.assertEqual(result.returncode, 0, "the lock ends with the first run: " + result.stdout + result.stderr)

    def test_the_report_binds_the_diff_the_configuration_and_the_test_arguments(self):
        self.write(".cargo/mutants.toml", CONFIG.replace('"--config", "profile.dev.debug-assertions=false"', ""))
        self.write(f"{SOURCE}/lib.rs", "pub fn one() -> u32 { 1 }\npub fn three() -> u32 { 3 }\n")
        head = self.commit("head with another configuration")
        self.git("branch", "topic", head)
        self.git("checkout", "-q", "--detach", self.base)
        self.write(f"{SOURCE}/lib.rs", "pub fn one() -> u32 { 1 }\npub fn main_side() -> u32 { 4 }\n")
        self.write(".cargo/mutants.toml", CONFIG + "# a later edit\n")
        self.write(".github/workflows/agent-checks.yml", WORKFLOW.replace("1.99.0", "1.99.1"))
        main = self.commit("main side")
        self.git("update-ref", "refs/remotes/origin/main", main)
        listed = [(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:2:1: replace three -> u32 with 0")]
        self.plan(listed, {listed[0][1]: "Timeout"}, exit=3)
        inherited = {"CARGO_TARGET_DIR": "/inherited/target", "CARGO_BUILD_BUILD_DIR": "/inherited/build",
                     "CARGO_PROFILE_DEV_OPT_LEVEL": "3", "CARGO_PROFILE_DEV_DEBUG": "full"}
        result = subprocess.run([sys.executable, str(SCRIPT), "--head", "topic", "--artifacts", "relative/artifacts",
                                 "--cargo", str(self.cargo), "--tests=--test sim_worker -- --exact 'a b'"],
                                cwd=self.repo, env={**self.env, **inherited}, capture_output=True, text=True,
                                timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        artifacts = self.repo / "relative/artifacts"
        [path] = artifacts.glob("*/report.json")
        report = json.loads(path.read_text())
        [diff] = artifacts.glob("*/diff.patch")
        self.assertEqual(diff.read_text(), self.git(*DIFF, self.base, head, "--", SOURCE),
                         "the default base is the merge base of the head with origin/main")
        self.assertEqual((report["base"], report["head"], report["tool_version"]), (self.base, head, "27.1.0"))
        self.assertEqual(report["diff_sha256"], hashlib.sha256(diff.read_bytes()).hexdigest())
        head_config = self.git("show", f"{head}:.cargo/mutants.toml").encode()
        self.assertEqual(report["config_sha256"], hashlib.sha256(head_config).hexdigest())
        listing, run = self.calls()
        tests = ["--test", "sim_worker", "--", "--exact", "a b"]
        self.assertEqual((report["tests"], run["tests"]), (tests, tests))
        self.assertIsNone(report["debug_assertions"], "the head's configuration sets no debug-assertion entry")
        build = str(artifacts.resolve() / "build")
        for call in (listing, run):
            self.assertEqual((call["diff_sha256"], call["config_sha256"]),
                             (report["diff_sha256"], report["config_sha256"]))
            self.assertIn("-p kestrike", " ".join(call["argv"]))
            self.assertEqual((call["CARGO_TARGET_DIR"], call["CARGO_BUILD_BUILD_DIR"]), (build, build))
            self.assertEqual((call["CARGO_PROFILE_DEV_OPT_LEVEL"], call["CARGO_PROFILE_DEV_DEBUG"]),
                             ("1", "line-tables-only"))
            self.assertEqual(call["RUSTUP_TOOLCHAIN"], "1.99.1", "the pin comes from the invoking checkout")
            self.assertEqual(call["lock"], "# lock\n", "the worktree holds the checkout's Cargo.lock")
            self.assertTrue(Path(call["argv"][call["argv"].index("--in-diff") + 1]).is_absolute())
            self.assertEqual(Path(call["cwd"]).resolve().parent, path.parent.resolve(),
                             "the worktree sits in the run directory")
        self.assertEqual(listing["argv"][1:3], ["--list", "--json"])
        self.assertIn("--in-place", run["argv"])
        output = run["argv"][run["argv"].index("--output") + 1]
        self.assertTrue(Path(output).is_absolute())
        self.assertEqual(Path(output).resolve(), path.parent.resolve() / "tool")
        (self.state / "calls.jsonl").unlink()
        result = self.run_mutants()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = self.report(result)
        self.assertEqual((report["tests"], self.calls()[1]["tests"]), (DEFAULT_TESTS, DEFAULT_TESTS))
        self.assertEqual(report["debug_assertions"], "false")

    def test_the_default_head_and_artifacts_come_from_the_invoking_checkout(self):
        listed = [(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:2:1: m")]
        self.plan(listed, {listed[0][1]: "CaughtMutant"})
        before = self.snapshot()
        result = subprocess.run([sys.executable, str(SCRIPT), "--base", self.base, "--cargo", str(self.cargo)],
                                cwd=self.repo / SOURCE, env=self.env, capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        artifacts = self.repo / "target/mutants"
        self.assertEqual(self.report(result, artifacts)["head"], self.head)
        build = str(artifacts.resolve() / "build")
        for call in self.calls():
            self.assertEqual((call["CARGO_TARGET_DIR"], call["CARGO_BUILD_BUILD_DIR"]), (build, build))
        self.assertEqual(self.snapshot(), before)

    def test_a_checkout_name_with_a_trailing_space_is_kept(self):
        spaced = self.state / "repo "
        self.git("clone", "-q", str(self.repo), str(spaced))
        (spaced / "src-note").write_text("only in the spaced clone\n")
        head = self.commit("spaced head", cwd=spaced)
        self.plan()
        result = self.run_mutants(head=head, cwd=spaced)
        self.assertEqual((result.returncode, result.stdout), (0, "mutants: 0 listed\n"), result.stderr)
        self.assertEqual(self.report(result)["head"], head)

    def test_a_relative_cargo_path_names_the_same_program_in_the_worktree(self):
        (self.repo / "tools").mkdir()
        shutil.copy(self.cargo, self.repo / "tools/cargo")
        listed = [(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:2:1: m")]
        self.plan(listed, {listed[0][1]: "CaughtMutant"})
        result = self.run_mutants("--cargo", "tools/cargo")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(self.calls()), 2, "the listing and the run reach the invoking checkout's program")

    def test_a_relative_path_entry_names_the_same_program_in_the_worktree(self):
        # `link/../tools` is `real/tools`, since the kernel follows the link before it applies `..`.
        (self.repo / "real/sub").mkdir(parents=True)
        (self.repo / "real/tools").mkdir()
        (self.repo / "link").symlink_to("real/sub")
        shutil.copy(self.cargo, self.repo / "real/tools/cargo")
        listed = [(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:2:1: m")]
        self.plan(listed, {listed[0][1]: "CaughtMutant"})
        for entry, program in (("real/tools", "cargo"), ("link/../tools", "cargo"), ("", "link/../tools/cargo")):
            with self.subTest(entry=entry, program=program):
                self.clear()
                result = self.run_mutants("--cargo", program,
                                          env={**self.env, "PATH": f"{entry}{os.pathsep}{self.env['PATH']}"})
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual([call["cwd"] != str(self.repo) for call in self.calls()], [True, True],
                                 "the listing and the run reach the invoking checkout's program from the worktree")
        self.clear()
        result = self.run_mutants(env={**self.env, "CARGO_HOME": "home", "RUSTUP_HOME": "link/../rustup"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual([(call["CARGO_HOME"], call["RUSTUP_HOME"]) for call in self.calls()],
                         [(str(self.repo / "home"), str(self.repo / "link/../rustup"))] * 2)

    def test_the_lock_copy_keeps_a_lock_file_or_link_the_head_tracks(self):
        lock = self.repo / "Cargo.lock"
        heads = {}
        for name, target in (("linked", self.state / "sentinel"), ("dangling", self.state / "absent")):
            lock.unlink()
            lock.symlink_to(target)
            self.git("add", "-f", "Cargo.lock")
            heads[name] = self.commit(f"track a {name} lock")
            self.git("rm", "-q", "--cached", "Cargo.lock")
            lock.unlink()
            lock.write_text("# lock\n")
            self.commit(f"untrack the {name} lock")
        (self.state / "sentinel").write_text("sentinel\n")
        lock.write_text("# tracked\n")
        self.git("add", "-f", "Cargo.lock")
        self.write(f"{SOURCE}/lib.rs", "pub fn one() -> u32 { 1 }\npub fn three() -> u32 { 3 }\n")
        tracked = self.commit("track a lock")
        self.git("rm", "-q", "--cached", "Cargo.lock")
        lock.write_text("# lock\n")
        self.commit("untrack the lock")
        self.plan()
        for name in heads:
            with self.subTest(name):
                for stale in self.reports():
                    stale.unlink()
                result = self.run_mutants(base=self.head, head=heads[name])
                self.assertEqual((result.returncode, result.stdout), (0, "mutants: 0 listed\n"), result.stderr)
        self.assertEqual((self.state / "sentinel").read_text(), "sentinel\n",
                         "the copy does not write through a tracked link")
        self.assertFalse(os.path.lexists(self.state / "absent"), "the copy does not create a dangling link's target")
        listed = [(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:2:1: m")]
        self.plan(listed, {listed[0][1]: "CaughtMutant"})
        result = self.run_mutants(base=self.head, head=tracked)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.calls()[0]["lock"], "# tracked\n", "the head's own Cargo.lock stays")
        self.assertEqual(lock.read_text(), "# lock\n")

    def test_replace_refs_leave_the_compared_commits_as_they_are(self):
        tree = self.git("rev-parse", f"{self.head}^{{tree}}").strip()
        self.git("replace", self.base, self.git("commit-tree", tree, "-m", "replacement").strip())
        listed = [(f"{SOURCE}/lib.rs", f"{SOURCE}/lib.rs:2:1: m")]
        self.plan(listed, {listed[0][1]: "CaughtMutant"})
        result = self.run_mutants()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        [diff] = self.artifacts.glob("*/diff.patch")
        expected = self.git("--no-replace-objects", *DIFF, self.base, self.head, "--", SOURCE)
        self.assertTrue(expected)
        self.assertEqual(diff.read_text(), expected)

    def test_the_user_diff_settings_and_hooks_leave_the_patch_and_the_worktree_unchanged(self):
        lines = [f"line {n}" if n % 7 else "" for n in range(1, 31)]
        moved = [f"moved {n}" for n in range(1, 21)]
        self.write(f"{SOURCE}/long.rs", "\n".join(lines) + "\n")
        self.write(f"{SOURCE}/old.rs", "\n".join(moved) + "\n")
        base = self.commit("long file")
        lines[9], lines[21], moved[4] = "changed 10", "changed 22", "edited 5"
        self.write(f"{SOURCE}/long.rs", "\n".join(lines) + "\n")
        (self.repo / SOURCE / "old.rs").unlink()
        self.write(f"{SOURCE}/zz.rs", "\n".join(moved) + "\n")
        head = self.commit("two hunks and a rename")
        expected = subprocess.run(["git", *DIFF, base, head, "--", SOURCE], cwd=self.repo, env=self.env,
                                  capture_output=True, check=True).stdout
        self.assertEqual(expected.count(b"\n@@ "), 3, "the clean patch holds three hunks")
        self.assertIn(b"rename to crates/kestrike/src/zz.rs", expected)
        self.assertLess(expected.index(b"long.rs"), expected.index(b"zz.rs"))
        for name, body in (("convert", 'tr a-z A-Z < "$1"'), ("external", "echo EXTERNAL")):
            script = self.state / name
            script.write_text(f"#!/bin/sh\n{body}\n")
            script.chmod(0o755)
        (self.state / "order").write_text(f"{SOURCE}/zz.rs\n")
        (self.state / "gitconfig").write_text(textwrap.dedent(f'''\
            [color]
                ui = always
                diff = always
            [diff]
                noprefix = true
                mnemonicPrefix = true
                external = {self.state / "external"}
                algorithm = patience
                context = 10
                interHunkContext = 20
                suppressBlankEmpty = true
                renames = false
                orderFile = {self.state / "order"}
            [diff "conv"]
                textconv = {self.state / "convert"}
            [core]
                bigFileThreshold = 1
                abbrev = 7
        '''))
        (self.repo / ".git/info/attributes").write_text("*.rs diff=conv\n")
        hook = self.repo / ".git/hooks/post-checkout"
        hook.write_text(f"#!/bin/sh\ntouch {self.state / 'hooked'}\n")
        hook.chmod(0o755)
        name = f"{SOURCE}/long.rs:10:1: m"
        self.plan([(f"{SOURCE}/long.rs", name)], {name: "CaughtMutant"})
        result = self.run_mutants(base=base, head=head, env={**self.env, "GIT_DIFF_OPTS": "--unified=0"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        [diff] = self.artifacts.glob("*/diff.patch")
        self.assertEqual(diff.read_bytes(), expected)
        self.assertFalse((self.state / "hooked").exists(), "the worktree add runs no hook")

    def test_a_shard_applies_the_limit_to_its_slice_and_records_k_and_n(self):
        names = [f"{SOURCE}/lib.rs:{n}:1: m" for n in range(5)]
        self.plan([(f"{SOURCE}/lib.rs", name) for name in names], dict.fromkeys(names, "CaughtMutant"),
                  host="x86_64-unknown-linux-gnu")
        self.assertEqual(self.run_mutants("--max-mutants", "2").returncode, 2)
        self.assertEqual(self.run_mutants("--max-mutants", "2", "--shard", "0/2").returncode, 2,
                         "a three-mutant slice is above the limit")
        self.assertEqual(self.builds(), [])
        result = self.run_mutants("--max-mutants", "2", "--shard", "1/2")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.splitlines()[0],
                         f"mutants: {self.head[:12]} against {self.base[:12]} on x86_64, shard 1/2: 2 listed, "
                         "2 caught, 0 missed, 0 timeout, 0 unviable; complete")
        report = self.report(result)
        self.assertEqual((report["shard"], report["machine"]), ({"k": 1, "n": 2}, "x86_64"))
        self.assertEqual([m["name"] for m in report["mutants"]], names[3:])
        for call in self.calls()[-2:]:
            self.assertEqual(call["argv"][call["argv"].index("--shard") + 1], "1/2")

    def test_every_exclusion_of_the_committed_configuration_matches_a_tracked_file(self):
        module = self.runner()
        config = (ROOT / ".cargo/mutants.toml").read_text()
        self.assertEqual(len(module.PIN.findall(config)), 1, "the runner reads one pin line")
        self.assertEqual(module.debug_assertions(config), "false", "the runner reads the committed setting")
        workflow = (ROOT / ".github/workflows/agent-checks.yml").read_text()
        self.assertEqual(len(module.STABLE.findall(workflow)), 1, "the runner reads one STABLE pin")
        tracked = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, env=self.env, capture_output=True, text=True,
                                 check=True).stdout.split("\0")
        self.assertEqual(unmatched_globs(config, tracked), [])
        start = re.search(r"^exclude_globs\s*=\s*\[\n", config, re.M)
        assert start is not None
        for entry, dead in (('"crates/kestrike/src/absent/**"', "crates/kestrike/src/absent/**"),
                            ("'crates/kestrike/src/absent/**'", "crates/kestrike/src/absent/**"),
                            ('""', "")):
            planted = config[:start.end()] + f"    {entry}, # a reason\n" + config[start.end():]
            self.assertEqual(unmatched_globs(planted, tracked), [dead])
        with self.assertRaises(AssertionError):
            unmatched_globs(config[:start.end()] + "    bare,\n" + config[start.end():], tracked)


if __name__ == "__main__":
    unittest.main()
