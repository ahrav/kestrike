#!/usr/bin/env python3
"""Record that a regression test fails on a base commit and passes on a head commit.

Usage:
  red-green.py --package NAME --target lib|INTEGRATION --test ID --expect TEXT
      --carry PATH [PATH...] [--base REV] [--head REV] [--watchdog SECONDS]
      [--release] [--artifacts DIR] [--cargo PATH]

The base defaults to the merge base of the head with `origin/main` and the
head to `HEAD`. Each `--carry` path names a regular file from the repository
root that the head holds; together they are the test files laid over the base.

The command creates a detached worktree of the base under the resolved path of
the temporary directory and overlays the carried paths with
`git checkout HEAD_ID -- PATHS`, where HEAD_ID is the head's full commit ID, so
the base leg's tree is the base commit plus exactly those files at the head's
blobs. It runs the base leg, then, on a red base, the head leg in a detached
worktree of the head. A leg is one run of `scripts/reproduce-test.py` in that
leg's worktree with `--attempts 1`, an absolute `--artifacts` path and the same
package, target, test ID, profile, watchdog and cargo, each value joined to its
flag. The legs run a copy, in the temporary directory, of the runner and its
selector as read beside this script at startup, written afresh before each
leg, and the parent judges the legs with the same bytes. A `--cargo` path that holds a directory part is made
absolute against the invoking directory. Git runs with replace objects disabled
and with inherited pathspec modes removed, and the worktree and overlay steps
run with Git hooks disabled. Before each leg runs, the command compares the
leg's worktree with the files its commit and the carried paths name: every
file, symlink and empty directory the worktree holds, ignored and untracked
ones included, and each one's kind, executable bit and bytes. A leg whose tree differs is refused
by the first differing path, so a leg starts on the tree the receipt names.
A checkout that a filter or a line-ending conversion rewrites is refused this
way. The runner's own Git probes in a leg tree, such as `git status`, run
after this comparison under the invoking Git configuration.

Both legs build in one directory that only this command writes, set as both
`CARGO_TARGET_DIR` and `CARGO_BUILD_BUILD_DIR`: `target/red-green/build` in
the invoking checkout, or `red-green` under `CARGO_TARGET_DIR` when that is
set, made absolute. The command creates the directory and each missing
ancestor with mode 0700. The builds and tests of both legs write there, so a
file a test leaves under it reaches the head leg and later runs, as a file it
leaves in the temporary directory or the home directory does; a receipt is
evidence for a test whose result depends only on the tree it runs in. The
command holds an exclusive lock on the regular file
`red-green.lock` in that directory from before the base worktree is created
until the legs end, and empties the file once it holds the lock. A lock file
that another user owns or that its group or all users can write is refused. Each runner
gets the lock file as its standard input, and
the builds, listings and tests it starts inherit that and read end-of-file from
it, so two runs build into the directory one at a time while the command, a
runner or a leg process that kept that standard input is alive. A leg's
result is the runner's last stdout line, its verdict, and its stderr line
`artifact: PATH` names the `artifact.json` of the leg's own directory under
the receipt.

The base is red only when the runner's `reported` accepts exit 1 and that
leg's `attempt-1.stdout` or `attempt-1.stderr` holds the `--expect` text within
one run of adjacent LF-separated lines that `FRAMING` and backtraces leave. `FRAMING` covers
the lines libtest and the panic hook print around a failure, the test ID's own
lines and should_panic's echo of its expected text among them. libtest's note
that a should_panic test did not panic stays searchable as that failure's own
diagnostic. Every other line counts, the test's own prints and other threads'
panic messages included, so the text identifies the failing assertion only as
narrowly as the author chooses it. The head is green only on a reported exit 0.
Every other leg outcome is a refusal whose reason names the leg and the
outcome:

- base: a reported exit 1 without the text, a reported exit 0, exit 3 (a build
  failure, an absent integration target among them), exit 2 whose verdict holds
  `matched 0 listed` (the test is absent), exit 4 (a crash) and a reported
  exit 6 (a hang) each have their own reason; any other exit or verdict is
  quoted in the reason;
- head: a reported exit 1 has its own reason; any other exit or verdict is
  quoted in the reason;
- either leg: a red base or a green head whose own `artifact.json` or attempt
  output is missing from the receipt or unreadable has its own reason.

The receipt is the directory `target/red-green/RUN/` in the invoking checkout,
or `DIR/RUN/` under `--artifacts`, which this run creates. It holds each leg's
runner artifact directory, unchanged, and `receipt.json`, which names both
commits, each carried path with its blob ID at the head, the SHA-256 of this
script, the runner and its selector as read at startup, each leg's
`artifact.json` path and the SHA-256 of it and of each attempt output file
taken after the leg ends, the leg's exit, verdict and wall time, the base
streams that held the text, the result, and the command that repeats the run
from the repository root with both revisions as full commit IDs.
The base verdict reads the same attempt bytes that the receipt hashes. A
refused run writes its receipt with the legs that ran; the head leg runs only
on a red base. The stderr line `receipt: PATH` names the file. The file is
created exclusively, so an existing entry at that path makes the write fail.

Exit 0 is proven, printed as `red-green: ID failed on BASE with "TEXT" and
passed on HEAD` after `receipt.json` is written. Exit 1 is refused, printed as
`red-green refused: REASON`; a receipt directory that cannot be created and a
receipt that cannot be written are refusals. Result lines and the stderr
lines that name a path escape control characters and characters the stream
cannot encode. Exit 2 is rejected input, printed on
stderr as `red-green rejected: REASON` and found before any worktree or build:
an option with no value or an empty one, or a `--carry` that names no path; a set `GIT_DIR`,
`GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_COMMON_DIR` or `GIT_OBJECT_DIRECTORY`,
which would point the leg worktrees at another repository or index; a
`.cargo`, `.cargo/config.toml`, `.cargo/config`, `rust-toolchain` or
`rust-toolchain.toml` in the temporary directory or its ancestors, which Cargo
or rustup in a leg worktree would read, that another user owns or can write,
judged by the owner of the entry, by the owner and the group and world write
bits of the file or directory it resolves to, and by the directories that
resolving it passes through, every link on the way followed, or one of those
directories that a user other than the invoking user and root owns or that its
group or all users can write, where such an entry could appear while the legs
run; a build directory, or an ancestor of it, that such a user owns or that
its group or all users can write, where the files the legs build and run could
be replaced; an invoking directory outside a
Git checkout; an unknown revision; a default base with no merge base, which
`--base` resolves; a base that is the head or not its ancestor, since a receipt
compares a commit with the history that fixed it; a carried path the head does
not hold as a regular file; a head whose changes from the base all lie in
carried paths or in base paths the overlay of those replaces, since both legs
would then run the same tree; an empty or
whitespace-only `--expect`, which every output holds, or one that is part of
the test ID, which framing lines print; a watchdog that is not a positive
number of seconds the platform can wait for; a receipt or build directory whose
symlinks loop; and a receipt directory the runner's one-line UTF-8 `artifact:`
announcement cannot name. Argument syntax errors exit 2 with the usage message.

The checks on the temporary directory and the build directory cover the
directories in which this command places the code the legs run. The legs run
the toolchain the invoking environment provides, through `PATH`, `--cargo`,
the Cargo home and the rustup home, and the command examines those locations
only where they are entries of the temporary directory's ancestors.

The invoking checkout keeps its index and working tree. The worktrees are
removed on exit by their own paths. On SIGTERM, SIGHUP or SIGINT before the
legs end, the command ignores further signals, sends a running runner SIGTERM,
which stops the runner's supervised process group, waits for the runner to
exit, removes the worktrees and exits 128 plus the signal number with no result
line and no `receipt.json`. A signal that lands while the temporary directory,
a worktree or the overlay is being created, or while the runner is being
started, takes effect once that step returns. A signal that lands after a
runner exits waits until the command has judged that leg: it takes effect
before a head leg starts, and a run whose last leg has ended finishes. Once
the legs end the command ignores these signals and finishes.
"""

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types
from pathlib import Path

RUNNER = Path(__file__).absolute().with_name("reproduce-test.py")
SELECTOR = RUNNER.with_name("select-tests.py")
SOURCES = {path.name: path.read_bytes() for path in (Path(__file__).absolute(), RUNNER, SELECTOR)}
SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)
OVERRIDES = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY")
PATHSPEC_MODES = ("GIT_GLOB_PATHSPECS", "GIT_NOGLOB_PATHSPECS", "GIT_ICASE_PATHSPECS", "GIT_LITERAL_PATHSPECS")
TOOLCHAIN_FILES = (".cargo", ".cargo/config.toml", ".cargo/config", "rust-toolchain", "rust-toolchain.toml")
LINE_BREAKS = "\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029"
# The attempt output files the runner creates for each attempt it runs.
STREAMS = ("stdout", "stderr")
SHARED = stat.S_IWGRP | stat.S_IWOTH
NO_EVIDENCE = "left no readable artifact.json or attempt output of its own in the receipt"
# Line shapes libtest and the panic hook print around a failing test, with TEST standing for the test ID, and
# the should_panic lines that echo the expected text. `FAILED` stands alone on a line when an uncaptured test
# wrote after libtest's `test TEST ... ` prefix. libtest's `note: test did not panic as expected` stays
# searchable as that failure's own diagnostic. A backtrace runs from its header through the indented frame lines
# below it.
FRAMING = (
    r"running \d+ tests?", r"test TEST( - should panic)? \.\.\. .*", r"FAILED", r"test result: .*", r"failures:",
    r"successes:", r"---- TEST std(out|err) ----", r"\s*TEST", r"thread '.*' (\(\d+\) )?panicked at .*:\d+:\d+:",
    r"note: (run with .*|Some details .*|panic did not contain expected string|expected panic with string value,)",
    r"\s*panic message: .*", r"\s*expected substring: .*", r"\s*found non-string value: .*",
)


def _load_runner(temp_root):
    """Load the runner from a private copy, under temp_root, of the runner and selector bytes read at startup."""
    with tempfile.TemporaryDirectory(prefix="kestrike-red-green-runner-", dir=temp_root) as private:
        for path in (RUNNER, SELECTOR):
            Path(private, path.name).write_bytes(SOURCES[path.name])
        spec = importlib.util.spec_from_file_location("reproduce_test", Path(private, RUNNER.name))
        if spec is None or spec.loader is None:
            raise SystemExit("reproduce-test.py cannot be loaded")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


# The runner module. `Receipt.run` binds it, after `main` has checked the temporary directory that holds the
# private copy.
runner: types.ModuleType


class Rejected(Exception):
    pass


class Refused(Exception):
    pass


def text(argv, cwd=None):
    """Run argv and return the completed process, with output decoded byte for byte as file names decode."""
    done = subprocess.run(argv, cwd=cwd, capture_output=True)
    return subprocess.CompletedProcess(done.args, done.returncode, os.fsdecode(done.stdout), os.fsdecode(done.stderr))


def git(*args, cwd=None):
    """Run a Git step that builds a leg tree. Hooks are disabled for it, so the tree holds what Git checks out."""
    result = text(("git", "-c", f"core.hooksPath={os.devnull}", *args), cwd=cwd)
    if result.returncode != 0:
        raise Refused(f"git {' '.join(args)}: {result.stderr.strip()}")
    return result.stdout.strip()


def resolve(rev):
    found = text(("git", "rev-parse", "--verify", "--quiet", "--end-of-options", f"{rev}^{{commit}}"))
    if found.returncode != 0:
        raise Rejected(f"{rev!r} names no commit")
    return found.stdout.strip()


def carried_blobs(head, paths):
    """Return each carried path with its blob ID at the head, or reject a path the head does not hold as a
    regular file. The overlay copies a symlink as the link itself, so a carried path must be a regular file."""
    blobs = []
    for path in paths:
        found = text(("git", "--literal-pathspecs", "ls-tree", "-z", "--full-tree", head, "--", path))
        meta, _, name = found.stdout.partition("\t")
        fields = meta.split()
        if found.returncode != 0:
            raise Rejected(f"git ls-tree {head[:12]} {path!r}: {found.stderr.strip()}")
        if len(fields) != 3 or fields[0] not in ("100644", "100755") or name != f"{path}\0":
            raise Rejected(f"the head {head[:12]} holds no regular file {path!r}")
        blobs.append({"path": path, "blob": fields[2]})
    return blobs


def named_files(commit):
    """Return each path the commit names with its (mode, object ID), as the repository root names them."""
    found = text(("git", "ls-tree", "-r", "-z", "--full-tree", commit))
    if found.returncode != 0:
        raise Refused(f"git ls-tree {commit[:12]}: {found.stderr.strip()}")
    entries = (entry.partition("\t") for entry in filter(None, found.stdout.split("\0")))
    return {path: (meta.split()[0], meta.split()[2]) for meta, _, path in entries}


def tree_difference(tree, named):
    """Return the first path, in sorted order, at which the worktree at tree differs from named, or None.

    named gives each path's (mode, object ID). A path differs when the worktree holds a file, a symlink, an empty
    directory or a directory that cannot be listed that named lacks, when a named file or symlink is absent, or
    when its kind, executable bit or bytes differ from the named object: a file's content and a symlink's target
    each hash as a Git blob. The worktree's own `.git` entry and a submodule's path are outside the comparison.
    """
    present, unlisted = set(), []
    for directory, names, files in os.walk(tree, onerror=unlisted.append):
        links = [name for name in names if os.path.islink(os.path.join(directory, name))]
        present.update(os.path.relpath(os.path.join(directory, name), tree) for name in (*files, *links))
        if not names and not files and directory != tree:
            present.add(os.path.relpath(directory, tree))
    present.update(os.path.relpath(error.filename, tree) for error in unlisted)
    present = {path for path in present if path != ".git" and named.get(path, ("",))[0] != "160000"}
    for path in sorted(present | {path for path, (mode, _) in named.items() if mode != "160000"}):
        mode, blob = named.get(path, (None, None))
        if path not in present or mode not in ("100644", "100755", "120000"):
            return path
        full = os.path.join(tree, path)
        status = os.lstat(full)
        if mode == "120000":
            if not stat.S_ISLNK(status.st_mode):
                return path
            data = os.fsencode(os.readlink(full))
        elif not stat.S_ISREG(status.st_mode) or bool(status.st_mode & stat.S_IXUSR) != (mode == "100755"):
            return path
        else:
            data = Path(full).read_bytes()
        hashed = hashlib.new("sha1" if len(blob) == 40 else "sha256", b"blob %d\0" % len(data) + data)
        if hashed.hexdigest() != blob:
            return path
    return None


def overlaid(path, carry):
    """Tell whether the overlay of the carried paths decides path on the base: path is carried, lies below a
    carried path, or is a file that a carried path needs as a directory."""
    return any(path == other or path.startswith(f"{other}/") or other.startswith(f"{path}/") for other in carry)


def changed_paths(base, head):
    """Return the paths whose content or mode differs between base and head, as the repository root names them."""
    found = text(("git", "diff", "--name-only", "-z", "--no-renames", "--no-relative", base, head, "--"))
    if found.returncode != 0:
        raise Rejected(f"git diff {base[:12]} {head[:12]}: {found.stderr.strip()}")
    return set(filter(None, found.stdout.split("\0")))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def resolved(path):
    """Return path made absolute with its symlinks resolved, or reject a path whose symlinks loop. A path that does
    not exist yet resolves as far as it exists."""
    try:
        path = Path(path).resolve()
        os.stat(path)
    except FileNotFoundError:
        pass
    except (OSError, RuntimeError) as error:
        raise Rejected(f"a receipt or build directory cannot be resolved: {error}") from None
    return path


def shared_directories(path):
    """Return path and its ancestors, as far as they exist, in which another user can add or replace an entry: a
    directory that a user other than this one and root owns, or that its group or all users can write."""
    found = []
    for directory in (path, *path.parents):
        try:
            status = os.stat(directory)
        except (FileNotFoundError, NotADirectoryError):
            continue
        if status.st_uid not in (os.getuid(), 0) or status.st_mode & SHARED:
            found.append(str(directory))
    return found


def traversed(path):
    """Return each directory in which resolving path looks a name up, with every link on the way followed."""
    pending, current, passed, links = list(Path(path).parts[1:]), os.sep, [], 0
    while pending:
        part = pending.pop(0)
        if part == "..":
            current = os.path.dirname(current)
            continue
        passed.append(current)
        step = os.path.join(current, part)
        if os.path.islink(step) and links < 40:
            links += 1
            target = os.readlink(step)
            current = os.sep if os.path.isabs(target) else current
            pending[:0] = [name for name in target.split(os.sep) if name not in ("", ".")]
        else:
            current = step
    return passed


def make_private(path):
    """Create path and each missing ancestor as a directory that only the invoking user can write, and fail when
    path or an ancestor is then one `shared_directories` reports."""
    for directory in reversed([step for step in (path, *path.parents) if not step.exists()]):
        try:
            os.mkdir(directory, 0o700)
        except FileExistsError:
            # Another run of this command created the directory first.
            if not directory.is_dir():
                raise
    shared = shared_directories(path)
    if shared:
        raise PermissionError(f"another user owns or can write {', '.join(shared)}")


def foreign_toolchain_paths(root):
    """Return the paths through which another user can configure Cargo or rustup in a leg worktree under root.

    Cargo and rustup read `TOOLCHAIN_FILES` in every ancestor of a worktree on each run. The result holds each
    such entry in root or its ancestors that another user owns or can write: the entry or the file or directory
    it resolves to has another owner, that target is writable by its group or by all users, the target cannot be
    examined, or resolving the entry passes through a directory, by any link on the way, that another user owns
    or can write. It also holds each of those directories where an entry can appear while the legs run, as
    `shared_directories` gives them.
    """
    found = shared_directories(root)
    for directory in (root, *root.parents):
        for name in TOOLCHAIN_FILES:
            entry = directory / name
            try:
                owners = {os.lstat(entry).st_uid}
            except OSError:
                continue
            try:
                target = os.stat(entry)
            except OSError:
                found.append(str(entry))
                continue
            if (owners | {target.st_uid} != {os.getuid()} or target.st_mode & SHARED
                    or any(shared_directories(Path(passed))[:1] == [passed] for passed in traversed(entry))):
                found.append(str(entry))
    return found


def say(line, stream=None):
    """Print line on stream, stdout unless one is given, as one line, with control characters, line breaks among
    them, and characters the stream cannot encode escaped."""
    stream = stream or sys.stdout
    line = re.sub("[\x00-\x1f\x7f-\x9f\u2028\u2029]", lambda match: repr(match.group())[1:-1], line)
    encoding = getattr(stream, "encoding", None) or "utf-8"
    print(line.encode(encoding, "backslashreplace").decode(encoding), file=stream)


class Receipt:
    """One run: its worktrees, the running runner, and the evidence `receipt.json` records."""

    def __init__(self, args, base, head, blobs, directory, target_dir, temp_root):
        self.args, self.base, self.head, self.directory = args, base, head, directory
        self.target_dir, self.temp_root = target_dir, temp_root
        self.temp = None
        self.runner = RUNNER
        self.worktrees = []
        self.child = None
        self.lock = None
        self.shielded = False
        self.pending = None
        self.record = {
            "package": args.package, "target": args.target, "test": args.test, "expect": args.expect,
            "release": args.release, "watchdog_seconds": args.watchdog,
            "base": base, "head": head, "carried": blobs, "cargo_target_dir": str(target_dir),
            "scripts": {name: digest(data) for name, data in SOURCES.items()}, "legs": {}, "result": None,
            "command": self.repeat(),
        }

    def repeat(self):
        """Return the shell command that repeats this run. Each value is joined to its flag with `=`, so a value
        that starts with `-` parses as that value."""
        args = self.args
        argv = ["python3", "scripts/red-green.py", f"--package={args.package}", f"--target={args.target}",
                f"--test={args.test}", f"--expect={args.expect}", *(f"--carry={path}" for path in args.carry),
                f"--base={self.base}", f"--head={self.head}", f"--watchdog={args.watchdog!r}",
                *(["--release"] if args.release else []),
                *([f"--artifacts={self.directory.parent}"] if args.artifacts else []),
                *([f"--cargo={args.cargo}"] if args.cargo != "cargo" else [])]
        return shlex.join(argv)

    def interrupt(self, signum, _frame):
        """Exit on a signal; one that lands during a shielded step, or once the runner has exited, waits until
        `resume` honors it."""
        exited = self.child is not None and self.child.returncode is not None
        if self.shielded or self.pending is not None or exited:
            if self.pending is None:
                self.pending = signum
            return
        stop(signum, _frame)

    def shield(self, step):
        """Run step to completion with signals deferred, then honor a deferred signal.

        A step that creates a directory, a worktree or the runner records what it created before it returns, so
        cleanup finds it when the deferred signal exits right after.
        """
        self.shielded = True
        try:
            return step()
        finally:
            self.resume()

    def resume(self):
        """Honor a signal deferred since `shielded` was set."""
        self.shielded = False
        if self.pending is not None:
            stop(self.pending, None)

    def take_lock(self):
        """Hold the build directory's lock, waiting for a run that holds it.

        Each runner gets the lock's open file description as its standard input, and the processes the runner
        starts inherit it, so the lock stays held while this process or a leg process that kept that standard input
        is alive. The file is open for reading and writing and is emptied once the lock is held: a leg process
        reads end-of-file from it, and an exclusive lock on a network file system needs write access.
        """
        path = self.target_dir / "red-green.lock"
        try:
            self.lock = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o644)
        except OSError as error:
            raise Refused(f"the build lock {path} cannot be opened: {error}") from None
        status = os.fstat(self.lock)
        problem = ("it is not a regular file" if not stat.S_ISREG(status.st_mode) else
                   "another user owns or can write it" if status.st_uid != os.getuid() or status.st_mode & SHARED
                   else None)
        if problem:
            os.close(self.lock)
            self.lock = None
            raise Refused(f"the build lock {path} cannot be opened: {problem}")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            say(f"red-green: waiting for another run that builds in {self.target_dir}", sys.stderr)
            fcntl.flock(self.lock, fcntl.LOCK_EX)
        os.ftruncate(self.lock, 0)

    def worktree(self, name, commit):
        def create_temp():
            self.temp = tempfile.mkdtemp(prefix="kestrike-red-green-", dir=str(self.temp_root))
            return self.temp

        temp = self.temp or self.shield(create_temp)
        tree = os.path.join(temp, name)
        self.worktrees.append(tree)
        self.shield(lambda: git("worktree", "add", "--quiet", "--detach", tree, commit))
        return tree

    def copy_runner(self, temp):
        """Write the runner and selector bytes read at startup into this run's temporary directory. Each leg gets a
        fresh copy, so both legs run the code whose digests the receipt records."""
        scripts = Path(temp) / "scripts"
        scripts.mkdir(exist_ok=True)
        for path in (RUNNER, SELECTOR):
            (scripts / path.name).write_bytes(SOURCES[path.name])
        self.runner = scripts / RUNNER.name

    def leg(self, name, tree):
        """Run the runner in tree and return (exit, verdict, artifact path, attempt output bytes by stream)."""
        args = self.args
        argv = [sys.executable, str(self.runner), f"--package={args.package}", f"--target={args.target}",
                f"--test={args.test}", "--attempts=1", f"--watchdog={args.watchdog!r}",
                f"--artifacts={self.directory}", f"--run-id={self.directory.name}", f"--lane={name}",
                f"--cargo={args.cargo}", *(["--release"] if args.release else [])]
        env = dict(os.environ, CARGO_TARGET_DIR=str(self.target_dir), CARGO_BUILD_BUILD_DIR=str(self.target_dir))
        started = time.monotonic()

        def spawn():
            # On SIGTERM, SIGHUP or SIGINT this command sends SIGTERM to the runner in its own session,
            # and the runner then stops its supervised process group. The build lock is the runner's standard
            # input, which each process the runner starts inherits.
            self.child = subprocess.Popen(argv, cwd=tree, env=env, stdin=self.lock, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, text=True, errors="replace",
                                          start_new_session=True)
            return self.child

        child = self.shield(spawn)
        stdout, stderr = child.communicate()
        # The runner has exited. A signal waits from here until `run` knows whether another leg follows, so a run
        # whose last leg this is finishes and writes its receipt.
        self.shielded = True
        code, self.child = child.returncode, None
        lines = stdout.strip().splitlines()
        verdict = lines[-1] if lines else ""
        found = [line.split(": ", 1)[1] for line in stderr.splitlines() if line.startswith("artifact: ")]
        entry = {"exit": code, "verdict": verdict, "seconds": round(time.monotonic() - started, 3),
                 "artifact": None, "sha256": None, "attempt_sha256": {}}
        self.record["legs"][name] = entry
        return (code, verdict, *self.evidence(name, found[-1] if found else None, entry))

    def evidence(self, name, announced, entry):
        """Return the leg's artifact path and the bytes of each attempt output file present, by stream, recording
        their digests in entry. A leg that ran no attempt has no attempt output.

        The result is (None, {}) unless the runner announced the `artifact.json` of this leg's own directory in
        the receipt and each of those files reads.
        """
        if announced is None:
            return None, {}
        artifact = Path(os.path.realpath(announced))
        own = re.escape(f"{self.directory.name}-{os.environ.get('GITHUB_RUN_ATTEMPT', '1')}-{name}") + r"(\.\d+)?"
        if (artifact.name != "artifact.json" or artifact.parent.parent != self.directory
                or not re.fullmatch(own, artifact.parent.name)):
            return None, {}
        try:
            data = artifact.read_bytes()
            outputs = {stream: path.read_bytes() for stream in STREAMS
                       for path in [artifact.with_name(f"attempt-1.{stream}")] if path.is_file()}
        except OSError as error:
            entry["evidence_error"] = str(error)
            return None, {}
        entry.update(artifact=str(artifact), sha256=digest(data),
                     attempt_sha256={stream: digest(output) for stream, output in outputs.items()})
        return artifact, outputs

    def stop_child(self):
        """Send a running runner SIGTERM and wait for it, so its builds and tests end before the worktrees go."""
        if self.child is not None and self.child.poll() is None:
            self.child.send_signal(signal.SIGTERM)
            self.child.communicate()

    def cleanup(self):
        # The second `--force` lets Git remove a locked worktree. Git also drops the registration when its
        # directory is gone, so cleanup removes this run's registrations by their paths, and repeats a removal
        # that failed once the temporary directory is gone.
        remove = ("git", "worktree", "remove", "--force", "--force")
        failed = [tree for tree in self.worktrees if text((*remove, tree)).returncode != 0]
        if self.temp is not None:
            shutil.rmtree(self.temp, ignore_errors=True)
        for tree in failed:
            removed = text((*remove, tree))
            registered = f"worktree {tree}\n" in text(("git", "worktree", "list", "--porcelain")).stdout
            if removed.returncode != 0 and (registered or os.path.exists(tree)):
                say(f"red-green: could not remove worktree {tree}: {removed.stderr.strip()}", sys.stderr)

    def base_reason(self, code, verdict, artifact, outputs):
        """Return None for a red base, or the refusal reason for any other base leg outcome. A failure counts only
        with the leg's artifact and both attempt output streams."""
        if code == runner.REPRODUCED and runner.reported(code, verdict):
            if artifact is None or set(outputs) != set(STREAMS):
                return f"the base leg failed but {NO_EVIDENCE}: {verdict}"
            matched = [stream for stream, data in outputs.items()
                       if self.args.expect in unframed(os.fsdecode(data), self.args.test)]
            self.record["legs"]["base"]["expect_streams"] = matched
            if matched:
                return None
            return (f"the test failed on the base without the expected text: {verdict}; the search skips framing and "
                    "backtrace lines")
        if code == runner.NOT_REPRODUCED and runner.reported(code, verdict):
            return f"the test passes on the base: {verdict}"
        if code == runner.BUILD_FAILURE:
            return f"the base is red for the wrong reason, a build failure: {verdict}"
        if code == runner.REJECTED and "matched 0 listed" in verdict:
            return f"the test is absent on the base: {verdict}"
        if code == runner.CRASH:
            return f"the test crashed on the base: {verdict}"
        if code == runner.WATCHDOG and runner.reported(code, verdict):
            return f"the test hung on the base: {verdict}"
        return f"the runner did not complete the base leg: exit {code}, verdict {verdict!r}"

    def head_reason(self, code, verdict, artifact, outputs):
        """Return None for a green head, or the refusal reason for any other head leg outcome. A pass counts only
        with the leg's artifact and both attempt output streams."""
        if code == runner.REPRODUCED and runner.reported(code, verdict):
            return f"the test fails on the head: {verdict}"
        if not (code == runner.NOT_REPRODUCED and runner.reported(code, verdict)):
            return f"the head leg did not pass: exit {code}, verdict {verdict!r}"
        if artifact is None or set(outputs) != set(STREAMS):
            return f"the head leg passed but {NO_EVIDENCE}: {verdict}"
        return None

    def verify(self, name, tree, named):
        """Refuse a leg whose worktree differs from the files its commit and the carried paths name."""
        path = tree_difference(tree, named)
        if path is not None:
            raise Refused(f"the {name} leg's tree differs from its commit at {path!r}; Git configuration such as a "
                          "filter or a line-ending conversion changes what a checkout writes")

    def run(self):
        global runner
        runner = _load_runner(self.temp_root)
        self.take_lock()
        head_files = named_files(self.head)
        base_tree = self.worktree("base", self.base)
        self.copy_runner(os.path.dirname(base_tree))
        self.shield(lambda: git("--literal-pathspecs", "checkout", self.head, "--", *self.args.carry, cwd=base_tree))
        carried = {path: head_files[path] for path in self.args.carry}
        kept = {path: entry for path, entry in named_files(self.base).items() if not overlaid(path, carried)}
        self.verify("base", base_tree, {**kept, **carried})
        reason = self.base_reason(*self.leg("base", base_tree))
        if reason is None:
            self.resume()
            head_tree = self.worktree("head", self.head)
            self.copy_runner(os.path.dirname(head_tree))
            self.verify("head", head_tree, head_files)
            reason = self.head_reason(*self.leg("head", head_tree))
        return reason


def unframed(output, test):
    """Return the output with each framing or backtrace line replaced by a NUL line.

    Command-line arguments hold no NUL, so an `--expect` match lies within one run of adjacent kept lines.
    """
    framing = re.compile("|".join(f"(?:{shape.replace('TEST', re.escape(test))})" for shape in FRAMING))
    kept, backtrace = [], False
    for line in output.split("\n"):
        body = line[:-1] if line.endswith("\r") else line
        backtrace = body.startswith("stack backtrace:") or (backtrace and body.startswith(" "))
        kept.append("\0" if backtrace or framing.fullmatch(body) else line)
    return "\n".join(kept)


def stop(signum, _frame):
    """Ignore further signals and exit 128 plus the signal number, so one cleanup runs with no second
    interruption."""
    ignore_signals()
    sys.exit(128 + signum)


def ignore_signals():
    for handled in SIGNALS:
        signal.signal(handled, signal.SIG_IGN)


def parse(argv):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--package", required=True)
    parser.add_argument("--target", required=True, help="lib or an integration test target name")
    parser.add_argument("--test", required=True, help="the full test ID as the harness lists it")
    parser.add_argument("--expect", required=True,
                        help="a substring of the base leg's failing attempt output outside libtest framing and "
                             "backtraces; choose text specific to the intended failure, such as its assertion message")
    parser.add_argument("--carry", required=True, nargs="+", action="append", help="test files from the head")
    parser.add_argument("--base", help="default: the merge base of the head with origin/main")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--watchdog", type=float, default=1500.0, help="seconds per attempt (default 1500)")
    parser.add_argument("--artifacts", default=None, help="receipt parent directory (default target/red-green)")
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--release", action="store_true", help="build the release profile")
    args = parser.parse_args(argv)
    args.carry = [path for group in args.carry for path in group] if all(args.carry) else []
    return args


def main(argv=None):
    args = parse(argv)
    if isinstance(args.cargo, str) and os.sep in args.cargo:
        args.cargo = os.path.abspath(args.cargo)
    os.environ["GIT_NO_REPLACE_OBJECTS"] = "1"
    for name in PATHSPEC_MODES:
        os.environ.pop(name, None)
    receipt = None
    try:
        for handled in SIGNALS:
            signal.signal(handled, stop)
        try:
            values = (args.package, args.target, args.test, args.head, args.cargo, *args.carry,
                      *(value for value in (args.base, args.artifacts) if value is not None))
            # Python 3.12 and later read `--option=--` as the value `--`; earlier versions read no value. An empty
            # `--expect` has its own reason below.
            given = all(isinstance(value, str) and value != "--" for value in (*values, args.expect)) and all(values)
            if not args.carry or not given or not isinstance(args.watchdog, float):
                raise Rejected("an option has no value, or --carry names no path")
            overrides = [name for name in OVERRIDES if name in os.environ]
            if overrides:
                raise Rejected(f"{', '.join(overrides)} would point the leg worktrees at another repository or "
                               "index; unset them")
            temp_root = resolved(tempfile.gettempdir())
            foreign = foreign_toolchain_paths(temp_root)
            if foreign:
                raise Rejected(f"another user owns or can write {', '.join(foreign)}, and so can configure Cargo or "
                               "rustup in the leg worktrees; set TMPDIR to a directory only you control")
            top = text(("git", "rev-parse", "--show-toplevel"))
            if top.returncode != 0:
                raise Rejected("the invoking directory is not in a Git checkout")
            if not args.expect.strip():
                raise Rejected("--expect is empty")
            if args.expect in args.test:
                raise Rejected(f"--expect {args.expect!r} is part of the test ID")
            if not 0 < args.watchdog <= threading.TIMEOUT_MAX:
                raise Rejected(f"--watchdog must be a positive number of seconds up to {threading.TIMEOUT_MAX}")
            head = resolve(args.head)
            if args.base is None:
                found = text(("git", "merge-base", "origin/main", head))
                if found.returncode != 0:
                    raise Rejected(f"the head {head[:12]} has no merge base with origin/main; name --base")
                args.base = found.stdout.strip()
            base = resolve(args.base)
            ancestor = text(("git", "merge-base", "--is-ancestor", base, head))
            if base == head or ancestor.returncode != 0:
                raise Rejected(f"the base {base[:12]} is not an ancestor of the head {head[:12]} other than the head")
            blobs = carried_blobs(head, args.carry)
            if all(overlaid(path, args.carry) for path in changed_paths(base, head)):
                raise Rejected(f"the head {head[:12]} changes only carried paths, so both legs would run the same "
                               "tree")
            checkout = Path(top.stdout[:-1] if top.stdout.endswith("\n") else top.stdout)
            inherited = os.environ.get("CARGO_TARGET_DIR")
            parent = resolved(args.artifacts or checkout / "target/red-green")
            target_dir = resolved(Path(inherited) / "red-green" if inherited else checkout / "target/red-green/build")
            shared = shared_directories(target_dir)
            if shared:
                raise Rejected(f"another user owns or can write {', '.join(shared)}, and so can replace what the legs "
                               "build and run; set CARGO_TARGET_DIR to a directory only you control")
            shown = str(parent)
            if any(mark in shown for mark in LINE_BREAKS) or shown != shown.encode("utf-8", "replace").decode():
                raise Rejected(f"the receipt directory {shown!r} cannot appear on the runner's one-line UTF-8 "
                               "artifact announcement")
        except Rejected as rejected:
            ignore_signals()
            say(f"red-green rejected: {rejected}", sys.stderr)
            return 2
        directory = parent / f"local-{int(time.time())}-{os.getpid()}"
        receipt = Receipt(args, base, head, blobs, directory, target_dir, temp_root)
        for handled in SIGNALS:
            signal.signal(handled, receipt.interrupt)
        # The build directory comes first: by default the receipt directory's parent is one of its ancestors.
        for name, path, create in (("build", target_dir, make_private),
                                   ("receipt", directory, lambda path: path.mkdir(parents=True))):
            try:
                create(path)
            except OSError as error:
                ignore_signals()
                say(f"red-green refused: the {name} directory {path} could not be created: {error}")
                return 1
        try:
            reason = receipt.run()
        except Refused as refused:
            reason = str(refused)
        except OSError as error:
            reason = f"a leg could not run: {error}"
        # ignore_signals() keeps stop() from interrupting stop_child() and cleanup() in the finally block.
        ignore_signals()
    finally:
        ignore_signals()
        if receipt is not None:
            receipt.stop_child()
            receipt.cleanup()
    assert receipt is not None, "every path that leaves the try without a receipt returns"
    receipt.record["result"] = "proven" if reason is None else f"refused: {reason}"
    path = directory / "receipt.json"
    try:
        with open(path, "x") as out:
            out.write(json.dumps(receipt.record, indent=2, sort_keys=True) + "\n")
    except OSError as error:
        reason = f"the receipt {path} could not be written: {error}; {receipt.record['result']}"
    else:
        say(f"receipt: {path}", sys.stderr)
    if reason is not None:
        say(f"red-green refused: {reason}")
        return 1
    say(f'red-green: {args.test} failed on {base[:12]} with "{args.expect}" and passed on {head[:12]}')
    return 0


if __name__ == "__main__":
    sys.exit(main())
