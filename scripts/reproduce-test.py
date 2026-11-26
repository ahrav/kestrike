#!/usr/bin/env python3
"""Run one Rust test by exact ID, serially, until it fails or N attempts pass.

Usage:
  reproduce-test.py --package NAME --target lib|INTEGRATION --test ID --attempts N
      [--watchdog SECONDS] [--artifacts DIR] [--run-id ID] [--lane NAME]
      [--cargo PATH] [--release]

It builds once with `cargo test --no-run --message-format=json`, adding
`--release` when given so a loom lane failure rebuilds the lane's release
executable. The build runs in its own process group, so an interruption stops
the compiler and build-script processes with it. It resolves the target's
test executable from the compiler artifact and requires exactly one
`--list --exact` line; a matching `--list --ignored --exact` line marks the
ID ignored. Each listing and each attempt runs the executable directly from
the package root, as `cargo test` does, in its own process group; attempts
add `--exact`, `--ignored` for an ignored ID, and run under the watchdog.
An attempt passes only when it exits 0, its output holds exactly one
`test ID ... ok` outcome for the requested ID and no other executed or
ignored test, as `select-tests.py` parses outcome lines, and its one summary
reads `1 passed; 0 failed; 0 ignored`. The first other outcome stops the run.

`artifact.json` records the listed build and run environment variables and
every `KESTRIKE_*` input a hardware test reads. Every run past its
argument checks writes a new directory under
`--artifacts`, keyed by run ID, CI run attempt and lane, holding
`artifact.json` and each attempt's output. Attempt output files are written
as each attempt runs; `artifact.json` records the attempts when the run ends.
After N passing attempts it prints `not reproduced in N attempts`.

Exit 0 is not reproduced, 1 reproduced (a test failure), 2 rejected input,
an unusable tool or an `artifact.json` that cannot be written, 3 build
failure, 4 crash (a signal, a nonzero exit without a failed-test summary, an
attempt without a passing summary, or a passing summary without exactly one
`ok` outcome for the requested ID and no other executed or ignored test), 5
interruption and 6 watchdog expiry.
"""

import argparse
import contextlib
import hashlib
import importlib.util
import json
import math
import os
import platform
import re
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path


def _load_selector():
    spec = importlib.util.spec_from_file_location("select_tests", Path(__file__).with_name("select-tests.py"))
    if spec is None or spec.loader is None:
        raise SystemExit("select-tests.py cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


selector = _load_selector()
NOT_REPRODUCED, REPRODUCED, REJECTED, BUILD_FAILURE, CRASH, INTERRUPTED, WATCHDOG = range(7)
RESULTS = {
    NOT_REPRODUCED: "not reproduced",
    REPRODUCED: "reproduced",
    REJECTED: "rejected input",
    BUILD_FAILURE: "build failure",
    CRASH: "crash",
    INTERRUPTED: "interruption",
    WATCHDOG: "watchdog expiry",
}
ENVIRONMENT = (
    "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUST_BACKTRACE", "RUST_MIN_STACK",
    "CARGO_BUILD_TARGET", "CARGO_UNSTABLE_BUILD_STD", "CARGO_PROFILE_DEV_OPT_LEVEL", "CARGO_PROFILE_DEV_DEBUG", "SPDK_PKG_CONFIG_PATH",
    "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTUP_TOOLCHAIN", "ASAN_OPTIONS",
    "LOOM_MAX_PREEMPTIONS", "LOOM_MAX_BRANCHES", "LOOM_CHECKPOINT_FILE",
    "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB",
)
DOC_TEST = re.compile(r" - .*\(line \d+\)")
PASSED = re.compile(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; \d+ measured; \d+ filtered out;")
FAILED = re.compile(r"^test result: FAILED\. \d+ passed; [1-9]\d* failed;")


class Stop(Exception):
    def __init__(self, code, reason):
        super().__init__(reason)
        self.code = code


def probe(run, name, argv):
    """Run a short supervised probe and return its stdout, or its stderr, stripped."""
    stdout, stderr = run.dir / f"{name}.stdout", run.dir / f"{name}.stderr"
    try:
        supervise(run, argv, stdout, stderr)
    except OSError as error:
        return f"unavailable: {error}"
    return (stdout.read_text(errors="replace") or stderr.read_text(errors="replace")).strip()


class Run:
    def __init__(self, args):
        self.args = args
        self.record = {
            "test_id": args.test,
            "package": args.package,
            "target": args.target,
            "isolation": "one test by exact ID in one executable, attempts run serially in fresh processes",
            "attempts_requested": args.attempts,
            "watchdog_seconds": args.watchdog,
            "release": args.release,
            "attempts": [],
            "result": None,
            "exit": None,
        }
        self.dir = None
        self.child = None
        self.spawning = False
        self.pending = None
        self.package_root = None

    def interrupt(self, signum, _frame):
        """Handle SIGTERM or SIGINT: stop the supervised group and raise Stop.

        While `supervise` is between creating a process and registering it as
        `child`, the signal is recorded in `pending` and honored by `supervise`
        once the process is registered, so the new process is stopped too.
        """
        if self.spawning:
            self.pending = signum
            return
        if self.child is not None:
            stop_group(self.child)
        raise Stop(INTERRUPTED, f"interrupted by signal {signum}")

    def open(self):
        """Create the run directory and record the run's identity and tree: the revision, whether a tracked file
        is modified, and every untracked file. `resolve` records the toolchain and dependencies."""
        run_id = self.args.run_id or os.environ.get("GITHUB_RUN_ID") or f"local-{int(time.time())}-{os.getpid()}"
        attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
        base = Path(self.args.artifacts) / f"{run_id}-{attempt}-{self.args.lane}"
        candidate, suffix = base, 1
        while True:
            try:
                candidate.mkdir(parents=True)
                break
            except FileExistsError:
                suffix += 1
                candidate = base.with_name(f"{base.name}.{suffix}")
        self.dir = candidate
        status = probe(self, "git-status", ["git", "status", "--porcelain", "--untracked-files=all"]).splitlines()
        server, repository = os.environ.get("GITHUB_SERVER_URL"), os.environ.get("GITHUB_REPOSITORY")
        self.record.update(
            run_id=run_id,
            run_attempt=attempt,
            lane=self.args.lane,
            ci_run=f"{server}/{repository}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
            if server and repository and os.environ.get("GITHUB_RUN_ID") else None,
            revision=probe(self, "git-revision", ["git", "rev-parse", "HEAD"]),
            dirty=any(not line.startswith("??") for line in status),
            untracked=[line[3:] for line in status if line.startswith("??")],
            environment={name: value for name, value in os.environ.items()
                         if name in ENVIRONMENT or name.startswith("KESTRIKE_")},
            host={"uname": " ".join(platform.uname()), "cpu": cpu_model()},
        )
        self.save()

    def resolve(self):
        """Record the toolchain and the dependency versions `cargo metadata` resolves, and locate the package root
        the build, listing and attempts run from."""
        packages = metadata(self)
        manifests = [package["manifest_path"] for package in packages if package["name"] == self.args.package]
        if len(manifests) != 1:
            raise Stop(REJECTED, f"cargo metadata names {len(manifests)} packages called {self.args.package!r}")
        self.package_root = os.path.dirname(manifests[0])
        self.record.update(
            toolchain={
                "rustc": probe(self, "rustc", [os.environ.get("RUSTC", "rustc"), "-vV"]),
                "cargo": probe(self, "cargo", [self.args.cargo, "-V"]),
            },
            # A registry or git source names where a version's code came from; a path package is the tree itself.
            dependencies=sorted(" ".join(filter(None, (package["name"], package["version"], package.get("source"))))
                                for package in packages),
            package_root=self.package_root,
        )
        self.save()

    def save(self):
        if self.dir is not None:
            (self.dir / "artifact.json").write_text(json.dumps(self.record, indent=2, sort_keys=True) + "\n")

    def finish(self, code, message):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        self.record.update(result=message, exit=code)
        try:
            self.save()
        except OSError as error:
            code, message = REJECTED, f"{RESULTS[REJECTED]}: artifact.json could not be written ({error}); {message}"
        else:
            if self.dir is not None:
                print(f"artifact: {self.dir / 'artifact.json'}", file=sys.stderr)
        print(message)
        return code


def metadata(run):
    """Return the workspace's `cargo metadata` packages, each with a manifest path.

    The probe runs supervised, so an interruption stops its process group.
    """
    argv = [run.args.cargo, "metadata", "--format-version", "1"]
    status = supervise(run, argv, run.dir / "metadata.stdout", run.dir / "metadata.stderr")
    if status != 0:
        raise Stop(REJECTED, f"cargo metadata exited {status}")
    try:
        packages = json.loads((run.dir / "metadata.stdout").read_text(errors="replace"))["packages"]
        if not all(isinstance(package[key], str) for package in packages for key in ("name", "version", "manifest_path")):
            raise TypeError("a package lacks a name, version or manifest_path")
    except (ValueError, KeyError, TypeError) as error:
        raise Stop(REJECTED, f"cargo metadata exited {status}: {error}") from error
    return packages


# /proc/cpuinfo identifies a CPU family through the raw MIDR implementer and part on aarch64 and through the
# vendor, family and model on x86_64.
IDENTITY_LINES = {"aarch64": ("CPU implementer", "CPU part"), "x86_64": ("vendor_id", "cpu family", "model")}


def cpu_records(cpuinfo):
    """The processor records of `cpuinfo`, the blank-line-separated blocks with a `processor` line, each a map of
    its lines to their stripped values; none when a block repeats a line or carries a feature or identity line
    without a `processor` line."""
    cpu_lines = {"flags", "Features", *(name for names in IDENTITY_LINES.values() for name in names)}
    records = []
    for block in re.split(r"\n\s*\n", cpuinfo):
        fields = {}
        for line in block.splitlines():
            key, separator, value = line.partition(":")
            key = key.strip()
            if not separator:
                continue
            if key in fields:
                return []
            fields[key] = value.strip()
        if "processor" in fields:
            records.append(fields)
        elif cpu_lines & set(fields):
            return []
    return records


def cpu_features(cpuinfo):
    """The sorted CPU features every processor record of `cpuinfo` reports on its `flags` or `Features` line, or
    none when it holds no record or a record lacks that line."""
    lines = [record.get("flags", record.get("Features")) for record in cpu_records(cpuinfo)]
    if not lines or None in lines:
        return []
    return sorted(set.intersection(*(set(line.split()) for line in lines)))


def cpu_identity(cpuinfo, machine):
    """The CPU family identity lines `machine` reports in `cpuinfo`, each with its value, or None when the machine
    has no identity lines, `cpuinfo` holds no processor record, a record repeats a line or lacks one or leaves it
    blank, or two records report different values."""
    names = IDENTITY_LINES.get(machine)
    if names is None:
        return None
    identities = {tuple(record.get(name) for name in names) for record in cpu_records(cpuinfo)}
    if len(identities) != 1:
        return None
    values = identities.pop()
    if not all(values):
        return None
    return {name: values[index] for index, name in enumerate(names)}


def cpu_model(cpuinfo=None):
    """The CPU model `cpuinfo` names, read from /proc/cpuinfo when None: the first nonblank `model name` of its
    processor records, else its CPU family identity lines, else `platform.processor()`, else `unknown`."""
    if cpuinfo is None:
        try:
            cpuinfo = Path("/proc/cpuinfo").read_text()
        except OSError:
            cpuinfo = ""
    if model := next((record["model name"] for record in cpu_records(cpuinfo) if record.get("model name")), None):
        return model
    identity = cpu_identity(cpuinfo, platform.machine())
    if identity is not None:
        return ", ".join(f"{name} {value}" for name, value in identity.items())
    return platform.processor() or "unknown"


def supervise(run, argv, stdout, stderr, seconds=None, cwd=None):
    """Run argv in its own process group as `run.child` and return its exit status.

    The interruption handler stops the group through `run.child`. A signal
    that arrives while the process is being created is deferred by the handler
    and raised here once the process is registered. When `seconds` is set, the
    watchdog stops the group and raises TimeoutExpired. After the leader
    exits, any group member it left behind is stopped before the child is
    deregistered, so an interruption in that window still finds the group
    through `run.child`, and the next command starts with no process from
    this one alive.
    """
    with contextlib.ExitStack() as files:
        try:
            out = files.enter_context(open(stdout, "w"))
            err = files.enter_context(open(stderr, "w"))
        except OSError as error:
            raise Stop(REJECTED, f"the artifact directory refused {error.filename}: {error}") from error
        run.spawning = True
        try:
            process = subprocess.Popen(argv, stdout=out, stderr=err, start_new_session=True, cwd=cwd)
            run.child = process
        finally:
            run.spawning = False
        try:
            if run.pending is not None:
                raise Stop(INTERRUPTED, f"interrupted by signal {run.pending}")
            return wait_for_exit(process, seconds)
        finally:
            stop_group(process)
            run.child = None


def build(run):
    args = run.args
    selector = ["--lib"] if args.target == "lib" else ["--test", args.target]
    profile = ["--release"] if args.release else []
    argv = [args.cargo, "test", "-p", args.package, *selector, *profile, "--no-run", "--message-format=json"]
    status = supervise(run, argv, run.dir / "build.stdout", run.dir / "build.stderr")
    run.record["build"] = {"command": argv, "exit": status}
    if status != 0:
        raise Stop(BUILD_FAILURE, f"the build exited {status}")
    executables = []
    for line in (run.dir / "build.stdout").read_text(errors="replace").splitlines():
        try:
            message = json.loads(line)
        except ValueError:
            continue
        target = message.get("target", {})
        if message.get("reason") != "compiler-artifact" or not message.get("executable"):
            continue
        if not message.get("profile", {}).get("test"):
            continue
        wanted = "lib" in target.get("kind", []) if args.target == "lib" else (
            target.get("name") == args.target and "test" in target.get("kind", []))
        if wanted:
            executables.append(message["executable"])
    if len(executables) != 1 or not Path(executables[0]).is_file():
        raise Stop(REJECTED, f"the build named {len(executables)} executables for {args.target}: {executables}")
    executable = Path(executables[0])
    digest = hashlib.sha256()
    with executable.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    run.record["executable"] = {"path": str(executable), "sha256": digest.hexdigest()}
    run.save()
    return executable


def select(run, executable):
    test = run.args.test
    found = {}
    for flag in ([], ["--ignored"]):
        argv = [str(executable), "--list", "--exact", *flag, test]
        name = "list-ignored" if flag else "list"
        status = supervise(run, argv, run.dir / f"{name}.stdout", run.dir / f"{name}.stderr", cwd=run.package_root)
        if status != 0:
            raise Stop(REJECTED, f"{' '.join(argv)} exited {status}")
        found["ignored" if flag else "listed"] = [
            line for line in (run.dir / f"{name}.stdout").read_text(errors="replace").splitlines()
            if line == f"{test}: test"
        ]
    listed, ignored = found["listed"], found["ignored"]
    if len(listed) != 1 or len(ignored) > 1:
        raise Stop(REJECTED, f"{test!r} matched {len(listed)} listed and {len(ignored)} ignored tests")
    run.record["ignored"] = bool(ignored)
    run.save()
    return bool(ignored)


def attempt(run, executable, number, ignored):
    argv = [str(executable), "--exact", run.args.test, "--test-threads=1", *(["--ignored"] if ignored else [])]
    stdout = run.dir / f"attempt-{number}.stdout"
    stderr = run.dir / f"attempt-{number}.stderr"
    started = time.time()
    entry = {"attempt": number, "command": argv, "started": started}
    run.record["attempts"].append(entry)
    try:
        status = supervise(run, argv, stdout, stderr, seconds=run.args.watchdog, cwd=run.package_root)
    except subprocess.TimeoutExpired as expired:
        entry.update(seconds=round(time.time() - started, 3), status="watchdog")
        raise Stop(WATCHDOG, f"attempt {number} exceeded the {run.args.watchdog} s watchdog") from expired
    except Stop:
        entry.update(seconds=round(time.time() - started, 3), status="interrupted")
        raise
    entry.update(seconds=round(time.time() - started, 3), exit=status)
    lines = stdout.read_text(errors="replace").splitlines()
    summary = [line for line in lines if line.startswith("test result:")]
    entry["summary"] = summary
    if status < 0:
        raise Stop(CRASH, f"attempt {number} died from signal {-status}")
    if len(summary) == 1 and FAILED.match(summary[0]) and status != 0:
        raise Stop(REPRODUCED, f"reproduced on attempt {number}")
    if status != 0:
        raise Stop(CRASH, f"attempt {number} exited {status} without a failed-test summary")
    if len(summary) != 1 or not PASSED.match(summary[0]):
        raise Stop(CRASH, f"attempt {number} ended without exactly one passing test: {summary}")
    # The summary counts tests, not names: the attempt credits only the requested ID's own `ok` outcome.
    try:
        parsed = selector.parse_summaries("\n".join(lines))
    except selector.Refusal as refusal:
        raise Stop(CRASH, f"attempt {number} output does not parse: {refusal}") from None
    outcomes = {kind: [name for counts in parsed.values() for name in counts[kind]]
                for kind in ("ok", "FAILED", "ignored_names")}
    entry["outcomes"] = outcomes
    if outcomes != {"ok": [run.args.test], "FAILED": [], "ignored_names": []}:
        raise Stop(CRASH, f"attempt {number} passed {outcomes['ok']}, failed {outcomes['FAILED']} and ignored "
                          f"{outcomes['ignored_names']}, not exactly {run.args.test!r} once")


def wait_for_exit(process, seconds):
    """Return the exit status when the process exits, or raise TimeoutExpired.

    `seconds` None waits without a limit. A reaper thread blocks in waitpid, so
    the status arrives as soon as the process exits, and the interruption
    handler's `stop_group` sees that status while the main thread is suspended
    in the handler. The reaper starts with SIGINT and SIGTERM blocked, so the
    main thread receives them and runs the interruption handler.
    """
    reaper = threading.Thread(target=process.wait, daemon=True)
    interrupts = {signal.SIGINT, signal.SIGTERM}
    signal.pthread_sigmask(signal.SIG_BLOCK, interrupts)
    try:
        reaper.start()
    finally:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, interrupts)
    reaper.join(seconds)
    if reaper.is_alive():
        raise subprocess.TimeoutExpired(process.args, seconds)
    return process.returncode


def stop_group(process):
    """Stop every member of the process's group: SIGTERM, then SIGKILL.

    The waits bound how long the leader may take to exit; a leader that has
    already exited makes them immediate, and the group's other members
    receive both signals back to back.
    """
    for sig, wait in ((signal.SIGTERM, 10), (signal.SIGKILL, 10)):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=wait)
            break
        except subprocess.TimeoutExpired:
            continue
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)


def parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--package", required=True)
    parser.add_argument("--target", required=True, help="lib or an integration test target name")
    parser.add_argument("--test", required=True, help="the full test ID as the harness lists it")
    parser.add_argument("--attempts", required=True, type=int)
    parser.add_argument("--watchdog", type=float, default=1500.0, help="seconds per attempt (default 1500)")
    parser.add_argument("--artifacts", default="target/reproduce", help="default target/reproduce")
    parser.add_argument("--run-id")
    parser.add_argument("--lane", default="local")
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument(
        "--release", action="store_true", help="build the release profile, as the loom lane does",
    )
    return parser


def registry_key(args):
    """Return the test registry's (target, id) for the test that parsed arguments select.

    The registry names a library test by its crate's lib target, the package
    name with `-` replaced by `_`, where this tool's grammar says `lib`.
    """
    target = args.package.replace("-", "_") if args.target == "lib" else args.target
    return target, args.test


def reported(code, verdict):
    """Tell whether a finished run is a reported result rather than a failure of the run.

    Only not reproduced, reproduced and watchdog expiry are reported, and only
    when the printed verdict names the same result. A signal death exits
    outside this set, and an uncaught Python exception exits 1 without
    printing a verdict.
    """
    return code in (NOT_REPRODUCED, REPRODUCED, WATCHDOG) and verdict.startswith(RESULTS[code])


def main(argv=None):
    args = parser().parse_args(argv)
    run = Run(args)
    signal.signal(signal.SIGTERM, run.interrupt)
    signal.signal(signal.SIGINT, run.interrupt)
    try:
        if args.attempts < 1 or not (math.isfinite(args.watchdog) and args.watchdog > 0):
            raise Stop(REJECTED, "--attempts must be positive and --watchdog a positive finite number of seconds")
        if DOC_TEST.search(args.test):
            raise Stop(REJECTED, f"{args.test!r} is a doc-test ID; doc tests have no executable to repeat")
        run.open()
        run.resolve()
        executable = build(run)
        ignored = select(run, executable)
        for number in range(1, args.attempts + 1):
            attempt(run, executable, number, ignored)
    except Stop as stop:
        return run.finish(stop.code, f"{RESULTS[stop.code]}: {stop}")
    except Exception as error:
        return run.finish(REJECTED, f"{RESULTS[REJECTED]}: {type(error).__name__}: {error}")
    return run.finish(NOT_REPRODUCED, f"not reproduced in {args.attempts} attempts")


if __name__ == "__main__":
    sys.exit(main())
