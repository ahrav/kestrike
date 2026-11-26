#!/usr/bin/env python3
"""List and test the generated mutants of one commit range's kestrike lines.

Usage:
  mutants-diff.py [--base REV] [--head REV] [--max-mutants N] [--shard K/N]
      [--tests=ARGS] [--artifacts DIR] [--cargo PATH]

The base defaults to the merge base of the head with `origin/main`, the head
to `HEAD`, `--max-mutants` to 40 and `--artifacts` to `target/mutants` under
the invoking checkout's top level. `--cargo PATH` replaces `cargo`; a path
with a `/` is resolved against the invoking directory. Write `--tests=ARGS`
with `=`, so a value that starts with `-` stays a value. Options are matched
by their full names only.

The run judges the head commit, in this order:

1. It requires `cargo mutants --version` to report the version of the line
   `# Tool pin: cargo-mutants VERSION` in the invoking checkout's
   `.cargo/mutants.toml`. It installs nothing.
2. It takes the lock `<artifacts>/build.lock`, so one run at a time uses an
   artifacts directory, and writes `git diff BASE HEAD --
   crates/kestrike/src` as `diff.patch` into a new run directory
   `<artifacts>/<run id>/`. The lock ends with the runner; after a runner
   stopped by SIGKILL, start the next run on that directory once the old
   tool has exited.
3. It adds a detached worktree of the head, with Git hooks disabled, in a new
   directory under the run directory. The invoking repository's checkout
   filters, line-ending conversion and sparse-checkout settings apply to it.
   When the invoking checkout has a `Cargo.lock` and the worktree holds no
   entry at that path, it copies that file into the worktree. For a nonempty
   diff it requires a root `Cargo.toml` in the worktree and lists the mutants
   with `-p kestrike --in-diff DIFF --list --json` into `list.json`, each
   mutant with its name, file and `diff`.
4. It runs `cargo mutants --in-place -p kestrike --in-diff DIFF` in the
   worktree, in its own process group, with `--lib -- --skip bind:: --skip
   native:: --skip soak` after the tool's first `--`, or the shell-split
   words of `--tests=ARGS` in their place. It sets
   `CARGO_PROFILE_DEV_OPT_LEVEL=1`, `CARGO_PROFILE_DEV_DEBUG=line-tables-only`,
   `RUSTUP_TOOLCHAIN` to the `STABLE` pin of
   `.github/workflows/agent-checks.yml`, `CARGO_TARGET_DIR` and
   `CARGO_BUILD_BUILD_DIR` to `<artifacts>/build`, and `PATH`'s entries,
   `CARGO_HOME` and `RUSTUP_HOME` to their values resolved against the
   invoking directory. It refuses an inherited
   `CARGO_MUTANTS_*` variable, a `CARGO_PROFILE_*` variable other than the two
   it sets, and a `*RUSTFLAGS` value that sets debug assertions; the rest of
   the environment passes through. The tool writes into the run directory's
   `tool/`, runs one mutant at a time, and on SIGTERM stops the process groups
   of its cargo commands before it exits.
5. It reads the tool's `outcomes.json`, writes `report.json` and prints the
   result line and one `missed:` line per missed mutant.

Cargo reads configuration from the worktree's ancestors, which are the
artifacts directory and its ancestors, so the runner refuses an artifacts
directory, the default included, that another user owns or can write, or one
with such an ancestor. It also refuses a `.cargo`, `.cargo/config.toml`,
`.cargo/config`, `rust-toolchain` or `rust-toolchain.toml` entry of one of
those directories that another user owns or can write.
`foreign_toolchain_paths` in `scripts/red-green.py` makes both checks and
states how it judges an entry. Git runs with replace objects disabled and
without `GIT_DIFF_OPTS`. The diff is written as text with full object ids,
fixed prefixes, rename detection, the Myers algorithm, three lines of context
and no color, external diff, text conversion or path order, so those diff
settings of the user's configuration leave the patch unchanged; diff
attributes that select a hunk-header pattern still apply.

`--shard K/N` passes `K/N` unchanged to the listing and to the run; the tool
numbers shards 0 to N-1. The listed set is then the shard's slice, and
`--max-mutants` applies to that slice.

Every verdict comes from the per-mutant outcomes of `outcomes.json`. A
mutant is caught only when the run's baseline passed and the tool recorded it
caught; on a failed baseline, or a tool exit of 4, every listed mutant is
not-run. The counts are recomputed from those outcomes, and listed equals
caught plus missed plus timeout plus unviable plus not-run. A run with listed
mutants is complete only when the tool exited 0, 2 or 3, the baseline passed
and the set of judged mutants equals the listed set. A listing or outcome
file that repeats a mutant, an outcome file with a phase time that is not a
finite nonnegative number, a worktree configuration whose
`additional_cargo_args` the runner cannot read, and a worktree that remains
after the removal make the run incomplete.

`report.json` holds `base` and `head` (full commit ids), `diff_sha256` (the
file the tool read), `tool_version`, `config_sha256` (the worktree's
`.cargo/mutants.toml`, or null when it has none), `tests` (the arguments the
runner passes after the tool's first `--`; the worktree configuration's own
test settings, which `config_sha256` identifies, also apply), `machine` (the
architecture part of the `host:` triple that `cargo -vV` prints),
`debug_assertions` (the value of the last `profile.dev.debug-assertions=`
entry of the worktree configuration's `additional_cargo_args`, or null), `shard`
(`{"k": K, "n": N}` or null), `baseline` (`passed`, `failed` or null),
`tool_exit`, `mutants` (each listed mutant's `name`, `file`, `outcome` and
`phase_seconds`), `counts`, `flagged` (each file with one or more viable
mutants, judged and not unviable, all of them missed), `complete` and
`reason` (why the run is incomplete, or null).

`debug_assertions` records the configuration's entry. The setting the build
uses also depends on inputs outside that entry: rustflags in a Cargo
configuration file, a profile override in a manifest or a configuration file,
and a compiler wrapper can each turn debug assertions on for the build while
the field reads `false`.

The result line reads `mutants: HEAD against BASE on MACHINE: N listed, C
caught, M missed, T timeout, U unviable; complete`, where HEAD and BASE are
the first 12 characters of the commit ids, with `, shard K/N` after the
machine for a sharded run. An incomplete run ends it with `incomplete` and
prints the reason on the next line. An empty diff or an empty listing prints
`mutants: 0 listed`, writes a complete report with no mutant and starts no
build.

Each printed line stays one line: a control character, a line break included,
and a character the stream cannot encode are printed escaped. `report.json`
holds each mutant's name as the tool gave it.

The runner handles SIGINT, SIGTERM and SIGHUP from before it creates the run
directory until it has read the tool's outcomes; from then on it ignores
them, so the worktree removal and the report complete. A signal that is
ignored when the runner starts stays ignored, so a run under `nohup` outlives
its terminal. The first handled signal blocks the three signals, once a
process being started has started, so later ones are discarded. The runner
then stops the supervised process group (the worktree add, the listing or the
tool) with SIGTERM, then SIGKILL, removes the worktree, writes an incomplete
report and exits 1. Each supervised process receives SIGTERM when the runner
dies, so a runner stopped by SIGKILL also stops the tool; its worktree then
stays in the run directory and registered until `git worktree remove --force
--force` runs on that `worktree-*` path. Every other exit removes the
worktree with `git worktree remove --force --force`. The runner writes only
under the artifacts directory and in that worktree's entry in the
repository's Git directory, which the removal deletes, so with the default
artifacts directory, or one outside the checkout or ignored by it, the
invoking checkout's working tree and index stay as they were.

Exit 0 is a written report that reads `complete`, whatever it lists. Exit 1
is an incomplete run with a written report: a failed baseline, a failed
`git diff`, `git worktree add` or listing, a head without a root
`Cargo.toml`, a tool that exits outside 0, 2 and 3 or without a readable
outcome file, a judged set that differs from the listed set, a worktree that
remains, an unexpected runner error such as a run directory that refuses an
output file, or an interruption. When the artifacts directory refuses the
report, the runner prints that error in its place and exits 1. Exit 2 is
rejected input and writes no report: malformed arguments; a set `GIT_DIR`,
`GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_COMMON_DIR` or
`GIT_OBJECT_DIRECTORY`; an inherited variable that step 4 refuses; a
directory outside a Git checkout; an unknown revision or no merge base with
`origin/main`; a configuration without one pin line or a workflow without one
`STABLE` pin, or one of them unreadable; an absent tool or a `cargo -vV`
without a host; a tool version other than the pin; an artifacts directory
that cannot be resolved, that another user owns or can write, that has such a
Cargo or rustup entry in it or in an ancestor, or whose `build.lock` is not a
regular file the invoking user owns or is held by another run; or more listed
mutants than `--max-mutants`. Only the last of these reaches the worktree, and
none starts a build. The limit refusal takes precedence over a worktree that
remains: it exits 2, writes no report and names that worktree on standard
error.
"""

import argparse
import contextlib
import ctypes
import fcntl
import hashlib
import importlib.util
import json
import math
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
from collections import Counter
from pathlib import Path

COMPLETE, INCOMPLETE, REJECTED = 0, 1, 2
PACKAGE = "kestrike"
SOURCE = "crates/kestrike/src"
CONFIG = ".cargo/mutants.toml"
WORKFLOW = ".github/workflows/agent-checks.yml"
DEFAULT_TESTS = ("--lib", "--", "--skip", "bind::", "--skip", "native::", "--skip", "soak")
PIN = re.compile(r"^# Tool pin: cargo-mutants (\S+)$", re.M)
STABLE = re.compile(r'^\s*STABLE: "([^"]+)"', re.M)
OVERRIDES = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY")
ASSERTIONS = re.compile(r"debug[-_]assertions")
OWNED = ("CARGO_PROFILE_DEV_OPT_LEVEL", "CARGO_PROFILE_DEV_DEBUG")
DIFF = ("-c", "diff.suppressBlankEmpty=false", "diff", "--text", "--full-index", "--no-color", "--no-ext-diff",
        "--no-textconv", "--src-prefix=a/", "--dst-prefix=b/", "--find-renames", "--diff-algorithm=myers",
        "--unified=3", "--inter-hunk-context=0", "--indent-heuristic", "--no-relative", f"-O{os.devnull}")
# The tool's per-mutant summaries; a summary outside this map judges nothing.
VERDICTS = {"CaughtMutant": "caught", "MissedMutant": "missed", "Timeout": "timeout", "Unviable": "unviable"}
OUTCOMES = ("caught", "missed", "timeout", "unviable", "not-run")
# The tool exits 4 on a failed baseline, else 3 when a mutant timed out, else
# 2 when one is missed, else 0.
TOOL_RESULTS = (0, 2, 3)
BASELINE_FAILED = 4
SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
PR_SET_PDEATHSIG = 1
LIBC = ctypes.CDLL(None, use_errno=True)


def _load_receipt_command():
    """Load `red-green.py`, whose `foreign_toolchain_paths` and `make_private` judge where another user can
    configure Cargo for a worktree, so this runner and that command refuse the same directories."""
    spec = importlib.util.spec_from_file_location("red_green", Path(__file__).with_name("red-green.py"))
    if spec is None or spec.loader is None:
        raise SystemExit("red-green.py cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


red_green = _load_receipt_command()
# Each printed line goes through `say`, so a mutant name, a path or a Git message with a line break or a character
# the stream cannot encode stays one printed line.
say = red_green.say


class Stop(Exception):
    def __init__(self, code, reason):
        super().__init__(reason)
        self.code = code


class Run:
    """One invocation's lock, run directory, worktree, supervised child and report fields."""

    def __init__(self, args):
        self.args = args
        self.lock = None
        self.dir = None
        self.tree = None
        self.child = None
        self.spawning = False
        self.pending = None
        self.listed = []
        self.fields = {}

    def interrupt(self, signum, _frame):
        """Handle SIGINT, SIGTERM or SIGHUP: block the three, stop the supervised group and raise Stop.

        During a spawn the handler only records the signal, so the new process starts with the runner's signal
        mask; `supervise` blocks the three and raises once the process exists.
        """
        if self.spawning:
            self.pending = signum
            return
        signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
        if self.child is not None:
            stop_group(self.child)
        raise Stop(INCOMPLETE, f"interrupted by signal {signum}")

    def open(self, artifacts):
        """Take the artifacts directory's lock, create a new run directory under it named by its UTC start time,
        and return the run directory.

        The lock is opened without following a link or waiting on a FIFO, and must be a regular file the invoking
        user owns.
        """
        red_green.make_private(artifacts)
        if self.lock is None:
            path = artifacts / "build.lock"
            try:
                lock = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            except OSError as error:
                raise Stop(REJECTED, f"{path} cannot be opened as a lock file: {error}") from None
            status = os.fstat(lock)
            try:
                if not stat.S_ISREG(status.st_mode) or status.st_uid != os.getuid():
                    raise Stop(REJECTED, f"{path} is not a regular file the invoking user owns")
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(lock)
                raise Stop(REJECTED, f"another run holds {path}") from None
            except Stop:
                os.close(lock)
                raise
            self.lock = lock
        self.dir = Path(tempfile.mkdtemp(prefix=time.strftime("%Y%m%dT%H%M%SZ-", time.gmtime()), dir=artifacts))
        return self.dir


def git(top, *args):
    """Return the stdout of `git args` in `top`, or raise Stop(REJECTED) naming the failure."""
    result = subprocess.run(["git", "-C", str(top), *args], capture_output=True)
    if result.returncode != 0:
        raise Stop(REJECTED, f"git {' '.join(args)}: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout


def commit(top, revision):
    try:
        return git(top, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{revision}^{{commit}}").decode().strip()
    except Stop:
        raise Stop(REJECTED, f"unknown revision {revision!r}") from None


def debug_assertions(text):
    """The value of the last `profile.dev.debug-assertions=VALUE` entry of `additional_cargo_args` in `text`, or
    None when the array names none.

    Comments are removed first; the configuration's strings hold no `#`. The array's strings take either TOML
    quote, and an entry is read wherever it stands in the array, bare or attached as `--config=ENTRY`. Raises
    ValueError when the array is not a list of strings or names debug assertions in an entry the reader cannot
    read.
    """
    text = re.sub(r"#[^\n]*", "", text)
    start = re.search(r"""^\s*(["']?)additional_cargo_args\1\s*=\s*\[""", text, re.M)
    if start is None:
        return None
    words, at = [], start.end()
    while True:
        token = re.compile(r"""\s*(?:"([^"]*)"|'([^']*)'|(,)|(\]))""").match(text, at)
        if token is None:
            raise ValueError("additional_cargo_args is not an array of strings")
        at = token.end()
        if token.group(4):
            break
        if not token.group(3):
            words.append(token.group(1) if token.group(1) is not None else token.group(2))
    values = []
    for word in words:
        entry = re.fullmatch(r"(?:--config=)?\s*profile\.dev\.debug-assertions\s*=\s*(\w+)\s*", word)
        if entry:
            values.append(entry.group(1))
        elif ASSERTIONS.search(word):
            raise ValueError(f"additional_cargo_args entry {word!r} sets debug assertions in a form the runner "
                             "does not read")
    return values[-1] if values else None


def build_overrides(environ):
    """The variables in `environ` that change the tool or the build profile the run sets: each `CARGO_MUTANTS_*`
    variable, each `CARGO_PROFILE_*` variable other than the two the runner sets, and each `*RUSTFLAGS` value that
    sets debug assertions."""
    return sorted(name for name, value in environ.items()
                  if name.startswith("CARGO_MUTANTS_")
                  or (name.startswith("CARGO_PROFILE_") and name not in OWNED)
                  or (name.endswith("RUSTFLAGS") and ASSERTIONS.search(value)))


def tool_version(cargo, env, pin):
    install = f"cargo install --locked --version {pin} cargo-mutants"
    try:
        result = subprocess.run([cargo, "mutants", "--version"], capture_output=True, text=True, errors="replace",
                                env=env)
    except OSError as error:
        raise Stop(REJECTED, f"{cargo} cannot run ({error}); install the pinned tool: {install}") from None
    words = result.stdout.split()
    if result.returncode != 0:
        detail = result.stderr.strip().splitlines()[-1:] or [""]
        raise Stop(REJECTED, f"cargo mutants --version exited {result.returncode} ({detail[0]}); "
                             f"install the pinned tool: {install}")
    if len(words) != 2 or words[0] != "cargo-mutants":
        raise Stop(REJECTED, f"cargo mutants --version printed {result.stdout.strip()!r}; "
                             f"install the pinned tool: {install}")
    if words[1] != pin:
        raise Stop(REJECTED, f"cargo mutants is {words[1]}, the configuration pins {pin}; install it: {install}")
    return words[1]


def host_machine(cargo, env):
    result = subprocess.run([cargo, "-vV"], capture_output=True, text=True, errors="replace", env=env)
    hosts = [line[len("host: "):].strip() for line in result.stdout.splitlines() if line.startswith("host: ")]
    machine = hosts[0].split("-")[0] if len(hosts) == 1 else ""
    if result.returncode != 0 or not machine:
        raise Stop(REJECTED, f"{cargo} -vV names no host")
    return machine


def parent_death_signal(parent):
    """A hook that runs in a new child before exec and has SIGTERM delivered to it when `parent` dies."""
    def hook():
        LIBC.prctl(PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0)
        if os.getppid() != parent:
            os._exit(1)
    return hook


def supervise(run, argv, stdout, stderr, cwd=None, env=None):
    """Run argv in its own process group as `run.child` and return its exit status.

    The interruption handler stops the group through `run.child`. A signal
    that arrives while the process is being created is deferred by the handler
    and raised here once the process is registered. After the leader exits,
    any member of its group it left behind is stopped before the child is
    deregistered.
    """
    with open(stdout, "w") as out, open(stderr, "w") as err:
        run.spawning = True
        try:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                       start_new_session=True, cwd=cwd, env=env,
                                       preexec_fn=parent_death_signal(os.getpid()))
            run.child = process
        finally:
            run.spawning = False
        try:
            if run.pending is not None:
                signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
                raise Stop(INCOMPLETE, f"interrupted by signal {run.pending}")
            return wait_for_exit(process)
        finally:
            stop_group(process)
            run.child = None


def wait_for_exit(process):
    """Return the exit status once the process exits.

    A reaper thread blocks in waitpid, so the interruption handler's
    `stop_group` sees the status while the main thread is suspended in the
    handler. The reaper starts with the handled signals blocked, so the main
    thread receives them.
    """
    reaper = threading.Thread(target=process.wait, daemon=True)
    signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
    try:
        reaper.start()
    finally:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, SIGNALS)
    reaper.join()
    return process.returncode


def stop_group(process):
    """Stop every member of the process's group: SIGTERM, then SIGKILL."""
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


def remove_worktree(top, tree):
    """Remove the worktree and return why its directory or registration remains, or None.

    A `worktree add` stopped before it registered the tree leaves only the directory, which the removal deletes.
    """
    # A stopped `worktree add` leaves its `initializing` lock; the second `--force` removes a locked worktree. Git
    # refuses a directory without a valid `.git` file and drops the registration once the directory is gone, so a
    # removal that failed is repeated after the directory's removal.
    remove = ["git", "-C", str(top), "worktree", "remove", "--force", "--force", str(tree)]
    removed = subprocess.run(remove, capture_output=True)
    shutil.rmtree(tree, ignore_errors=True)
    if removed.returncode != 0:
        removed = subprocess.run(remove, capture_output=True)
    listed = subprocess.run(["git", "-C", str(top), "worktree", "list", "--porcelain"], capture_output=True)
    # The listing prints a path's bytes as they are, so the whole record is matched in the listing's bytes.
    registered = listed.returncode != 0 or b"\nworktree " + os.fsencode(tree.resolve()) + b"\n" in b"\n" + listed.stdout
    if registered or os.path.lexists(tree):
        return f"the worktree {tree} remains: {os.fsdecode(removed.stderr.strip() or listed.stderr.strip())}"
    return None


def read_listing(text):
    """The listing's mutants, each as its name and file; blank output is an empty listing.

    Raises ValueError unless the listing is an array of objects with a string name and file, no name repeated.
    """
    rows = json.loads(text) if text.strip() else []
    if not isinstance(rows, list) or not all(
            isinstance(row, dict) and isinstance(row.get("name"), str) and isinstance(row.get("file"), str)
            for row in rows):
        raise ValueError("expected an array of mutants, each with a string name and file")
    if len({row["name"] for row in rows}) != len(rows):
        raise ValueError("a mutant name repeats")
    return [{"name": row["name"], "file": row["file"]} for row in rows]


def seconds(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError(f"phase time {value!r}")
    return round(value, 3)


def read_outcomes(path):
    """The baseline verdict and each judged mutant's verdict and phase seconds in the tool's outcome file.

    Returns None when the file is absent, does not parse as the tool writes it, repeats the baseline or a
    mutant, or holds a phase time that is not a finite nonnegative number.
    """
    try:
        records = json.loads(path.read_text())["outcomes"]
        baseline, judged, seen = None, {}, set()
        for record in records:
            scenario, summary = record["scenario"], record["summary"]
            if not isinstance(record["phase_results"], list):
                return None
            phases = {phase["phase"].lower(): seconds(phase["duration"]) for phase in record["phase_results"]}
            if scenario == "Baseline":
                if baseline is not None:
                    return None
                baseline = "passed" if summary == "Success" else "failed"
                continue
            name = scenario["Mutant"]["name"]
            if name in seen:
                return None
            seen.add(name)
            if summary in VERDICTS:
                judged[name] = (VERDICTS[summary], phases)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, ArithmeticError):
        return None
    return baseline, judged


def tool_outcomes(run):
    """`read_outcomes` of the run's outcome file; a tool exit of 4 reads as a failed baseline whatever it holds."""
    outcomes = read_outcomes(run.dir / "tool/mutants.out/outcomes.json")
    if outcomes is not None and run.fields.get("tool_exit") == BASELINE_FAILED:
        outcomes = ("failed", outcomes[1])
    return outcomes


def judge(listed, outcomes, reason):
    """Return the per-mutant entries, counts, flagged files, baseline, completeness and reason.

    `listed` holds the listing's mutants, `outcomes` what `read_outcomes` returned, and `reason` a failure that
    already makes the run incomplete, or None. The first reason that applies stands: the given one, an unreadable
    outcome file, a baseline that failed or is absent, then a judged set other than the listed set. Only a
    passed baseline gives a listed mutant an outcome other than not-run.
    """
    baseline, judged = outcomes if outcomes is not None else (None, {})
    names = {mutant["name"] for mutant in listed}
    if reason is None and listed:
        if outcomes is None:
            reason = "the tool wrote no readable outcome file"
        elif baseline == "failed":
            reason = "the baseline failed"
        elif baseline is None:
            reason = "the outcome file holds no baseline"
        elif set(judged) != names:
            reason = (f"{len(names - set(judged))} listed mutants have no outcome and "
                      f"{len(set(judged) - names)} judged mutants were not listed")
    credited = judged if baseline == "passed" else {}
    entries = []
    for mutant in listed:
        outcome, phases = credited.get(mutant["name"], ("not-run", {}))
        entries.append({"name": mutant["name"], "file": mutant["file"], "outcome": outcome,
                        "phase_seconds": phases})
    tally = Counter(entry["outcome"] for entry in entries)
    viable = {}
    for entry in entries:
        if entry["outcome"] in ("caught", "missed", "timeout"):
            viable.setdefault(entry["file"], set()).add(entry["outcome"])
    return {"mutants": entries, "counts": {"listed": len(entries), **{kind: tally[kind] for kind in OUTCOMES}},
            "flagged": sorted(file for file, kinds in viable.items() if kinds == {"missed"}),
            "baseline": baseline, "complete": reason is None, "reason": reason}


def result_line(fields):
    counts, shard = fields["counts"], fields["shard"]
    where = f"{fields['head'][:12]} against {fields['base'][:12]} on {fields['machine']}"
    if shard is not None:
        where += f", shard {shard['k']}/{shard['n']}"
    state = "complete" if fields["complete"] else "incomplete"
    return (f"mutants: {where}: {counts['listed']} listed, {counts['caught']} caught, {counts['missed']} missed, "
            f"{counts['timeout']} timeout, {counts['unviable']} unviable; {state}")


def copy_lock(top, tree):
    """Copy the invoking checkout's Cargo.lock into the worktree when the worktree holds no file or link there.

    Exclusive creation fails on any existing entry, a dangling link included, so the copy never writes through one.
    """
    if (top / "Cargo.lock").is_file():
        with contextlib.suppress(FileExistsError), open(tree / "Cargo.lock", "xb") as lock:
            lock.write((top / "Cargo.lock").read_bytes())


def execute(run, top, artifacts, env):
    """Steps 2 to 4 and the outcome reading of step 5, recorded in `run.fields`, or raise Stop.

    `finish` writes the report and prints its lines.
    """
    args, fields = run.args, run.fields
    run.open(artifacts)
    diff = run.dir / "diff.patch"
    try:
        diff.write_bytes(git(top, *DIFF, fields["base"], fields["head"], "--", SOURCE))
    except Stop as stop:
        raise Stop(INCOMPLETE, str(stop)) from None
    fields["diff_sha256"] = hashlib.sha256(diff.read_bytes()).hexdigest()
    run.tree = Path(tempfile.mkdtemp(prefix="worktree-", dir=run.dir))
    added = supervise(run, ["git", "-C", str(top), "-c", f"core.hooksPath={os.devnull}", "worktree", "add",
                            "--quiet", "--detach", str(run.tree), fields["head"]],
                      run.dir / "worktree.stdout", run.dir / "worktree.stderr")
    if added != 0:
        raise Stop(INCOMPLETE, f"git worktree add exited {added}")
    copy_lock(top, run.tree)
    config = run.tree / CONFIG
    if config.is_file():
        data = config.read_bytes()
        fields["config_sha256"] = hashlib.sha256(data).hexdigest()
        try:
            fields["debug_assertions"] = debug_assertions(data.decode(errors="replace"))
        except ValueError as error:
            raise Stop(INCOMPLETE, f"the worktree configuration does not parse: {error}") from None
    shard = ["--shard", args.shard] if args.shard else []
    if diff.stat().st_size:
        if not (run.tree / "Cargo.toml").is_file():
            raise Stop(INCOMPLETE, "the head has no root Cargo.toml, so Cargo would take an enclosing workspace")
        listing = ["--list", "--json", "-p", PACKAGE, "--in-diff", str(diff), *shard]
        status = supervise(run, [args.cargo, "mutants", *listing], run.dir / "list.json", run.dir / "list.stderr",
                           cwd=run.tree, env=env)
        if status != 0:
            raise Stop(INCOMPLETE, f"the listing exited {status}")
        # A diff that yields no mutant ends the listing with exit 0 and no output.
        try:
            run.listed = read_listing((run.dir / "list.json").read_text())
        except (ValueError, RecursionError) as error:
            raise Stop(INCOMPLETE, f"the listing does not parse: {error}") from None
    if len(run.listed) > args.max_mutants:
        say(f"mutants: {len(run.listed)} listed, above --max-mutants {args.max_mutants}")
        raise Stop(REJECTED, "raise --max-mutants or pass --shard K/N")
    if not run.listed:
        fields.update(judge([], (None, {}), None))
        return
    say(f"mutants: testing {len(run.listed)} mutants; tool output in {run.dir / 'tool'}", sys.stderr)
    command = [args.cargo, "mutants", "--in-place", "-p", PACKAGE, "--in-diff", str(diff),
               "--output", str(run.dir / "tool"), *shard, "--", *fields["tests"]]
    fields["tool_exit"] = supervise(run, command, run.dir / "tool.stdout", run.dir / "tool.stderr", cwd=run.tree,
                                    env=env)
    reason = None
    if fields["tool_exit"] not in (*TOOL_RESULTS, BASELINE_FAILED):
        reason = f"the tool exited {fields['tool_exit']}"
    fields.update(judge(run.listed, tool_outcomes(run), reason))


def ignore_signals():
    """Ignore the handled signals; a signal that arrives meanwhile stays blocked, then is discarded."""
    signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
    for handled in SIGNALS:
        signal.signal(handled, signal.SIG_IGN)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, SIGNALS)


def finish(run, top, artifacts, stop):
    """Remove the worktree and, unless `stop` rejected the input, write the report and print its lines.

    `stop` is the Stop that ended `execute`, or None when it returned. A stop with exit 1, or a worktree that
    remains after the removal, makes the report incomplete even when every listed mutant was judged; a run that is
    already incomplete keeps its own reason.
    """
    ignore_signals()
    leftover = remove_worktree(top, run.tree) if run.tree is not None else None
    if stop is not None and stop.code == REJECTED:
        say(f"mutants rejected: {stop}", sys.stderr)
        if leftover:
            say(f"mutants: {leftover}", sys.stderr)
        return REJECTED
    fields = run.fields
    reason = str(stop) if stop is not None else None
    if leftover:
        say(f"mutants: {leftover}", sys.stderr)
        reason = reason or fields.get("reason") or leftover
    if reason is not None:
        fields.update(judge(run.listed, tool_outcomes(run) if run.dir else None, reason))
    try:
        report = (run.dir or run.open(artifacts)) / "report.json"
        report.write_text(json.dumps(fields, indent=2, sort_keys=True, allow_nan=False) + "\n")
    except (OSError, Stop) as error:
        say(f"mutants: the report could not be written: {error}", sys.stderr)
        return INCOMPLETE
    say(f"report: {report}", sys.stderr)
    if not fields["mutants"] and fields["complete"]:
        say("mutants: 0 listed")
        return COMPLETE
    say(result_line(fields))
    if not fields["complete"]:
        say(f"reason: {fields['reason']}")
    for entry in fields["mutants"]:
        if entry["outcome"] == "missed":
            say(f"missed: {entry['name']}")
    return COMPLETE if fields["complete"] else INCOMPLETE


def shard_value(value):
    found = re.fullmatch(r"([0-9]+)/([0-9]+)", value)
    if found is None or not int(found.group(1)) < int(found.group(2)):
        raise argparse.ArgumentTypeError("K/N with 0 <= K < N")
    return value


def test_arguments(value):
    try:
        words = shlex.split(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from None
    if not words:
        raise argparse.ArgumentTypeError("one or more test arguments")
    return words


def given(value):
    if not value:
        raise argparse.ArgumentTypeError("a value")
    return value


def positive(value):
    if not value.isdigit() or int(value) < 1:
        raise argparse.ArgumentTypeError("a positive integer")
    return int(value)


def parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
                                     allow_abbrev=False)
    parser.add_argument("--base", type=given, help="default: the merge base of the head with origin/main")
    parser.add_argument("--head", type=given, default="HEAD")
    parser.add_argument("--max-mutants", type=positive, default=40)
    parser.add_argument("--shard", type=shard_value, help="K/N, passed to the tool unchanged")
    parser.add_argument("--tests", type=test_arguments, help="test arguments after the tool's first --, split as a shell splits them")
    parser.add_argument("--artifacts", type=given, help="default: target/mutants under the checkout's top level")
    parser.add_argument("--cargo", type=given, default="cargo")
    return parser


def preflight(args):
    """Step 1 and the input checks before it: return the top level, the fields they fix, the artifacts directory
    and the tool environment, or raise Stop(REJECTED).

    A set Git repository or index variable is refused before the first Git call, which would read it. The
    artifacts directory, the default included, is resolved and refused when another user can add an entry to it
    or to an ancestor, or can write a Cargo or rustup configuration entry that one of them holds.
    """
    overrides = [name for name in OVERRIDES if name in os.environ]
    if overrides:
        raise Stop(REJECTED, f"unset {', '.join(overrides)}; the runner uses the invoking checkout's repository")
    inherited = build_overrides(os.environ)
    if inherited:
        raise Stop(REJECTED, f"unset {', '.join(inherited)}; the runner sets the tool's options and the build "
                             "profile")
    os.environ["GIT_NO_REPLACE_OBJECTS"] = "1"
    os.environ.pop("GIT_DIFF_OPTS", None)
    if os.sep in args.cargo:
        args.cargo = os.path.join(os.getcwd(), args.cargo)
    output = git(Path.cwd(), "rev-parse", "--show-toplevel")
    top = Path(os.fsdecode(output[:-1] if output.endswith(b"\n") else output))
    head = commit(top, args.head)
    base = commit(top, args.base) if args.base else git(top, "merge-base", head, "origin/main").decode().strip()
    pins = PIN.findall((top / CONFIG).read_text()) if (top / CONFIG).is_file() else []
    stable = STABLE.findall((top / WORKFLOW).read_text()) if (top / WORKFLOW).is_file() else []
    if len(pins) != 1 or len(stable) != 1:
        raise Stop(REJECTED, f"{CONFIG} must hold one tool pin line and {WORKFLOW} one STABLE pin")
    artifacts = (Path(args.artifacts) if args.artifacts else top / "target/mutants").resolve()
    foreign = red_green.foreign_toolchain_paths(artifacts)
    if foreign:
        raise Stop(REJECTED, f"another user owns or can write {', '.join(foreign)}, where Cargo would read "
                             "configuration; pass --artifacts under a directory only you control")
    build = str(artifacts / "build")
    # The probes run in the invoking directory and the tool in the worktree, so each PATH entry and the Cargo and
    # rustup homes are joined to the invoking directory, with a `..` after a link kept, and both find the same
    # `cargo`, `cargo-mutants` and toolchain.
    here = os.getcwd()
    path = os.pathsep.join(os.path.join(here, entry) for entry in os.environ.get("PATH", os.defpath).split(os.pathsep))
    homes = {name: os.path.join(here, os.environ[name]) for name in ("CARGO_HOME", "RUSTUP_HOME") if os.environ.get(name)}
    env = {**os.environ, **homes, "CARGO_PROFILE_DEV_OPT_LEVEL": "1", "CARGO_PROFILE_DEV_DEBUG": "line-tables-only",
           "RUSTUP_TOOLCHAIN": stable[0], "CARGO_TARGET_DIR": build, "CARGO_BUILD_BUILD_DIR": build, "PATH": path}
    version = tool_version(args.cargo, env, pins[0])
    machine = host_machine(args.cargo, env)
    shard = None
    if args.shard:
        k, n = args.shard.split("/")
        shard = {"k": int(k), "n": int(n)}
    fields = {"base": base, "head": head, "tool_version": version, "machine": machine, "shard": shard,
              "tests": args.tests if args.tests is not None else list(DEFAULT_TESTS),
              "diff_sha256": None, "config_sha256": None, "debug_assertions": None, "tool_exit": None}
    return top, fields, artifacts, env


def run_to_finish(run, top, artifacts, env):
    """Install the handlers, run `execute`, then ignore the signals; return the Stop that ended it, or None.

    An unexpected error becomes an exit-1 Stop that names it. The handler blocks the handled signals before it
    raises, so the outer clause takes the one Stop that a first signal raises while the handlers are installed,
    in an `except` body or in the hand-off.
    """
    try:
        for handled in SIGNALS:
            if signal.getsignal(handled) != signal.SIG_IGN:
                signal.signal(handled, run.interrupt)
        try:
            execute(run, top, artifacts, env)
            return None
        except Stop as stop:
            return stop
        except Exception as error:
            return Stop(INCOMPLETE, f"the runner failed: {type(error).__name__}: {error}")
        finally:
            ignore_signals()
    except Stop as stop:
        return stop


def main(argv=None):
    args = parser().parse_args(argv)
    run = Run(args)
    try:
        top, fields, artifacts, env = preflight(args)
    except Stop as stop:
        say(f"mutants rejected: {stop}", sys.stderr)
        return stop.code
    except (OSError, ValueError, RuntimeError) as error:
        say(f"mutants rejected: {type(error).__name__}: {error}", sys.stderr)
        return REJECTED
    run.fields.update(fields)
    return finish(run, top, artifacts, run_to_finish(run, top, artifacts, env))


if __name__ == "__main__":
    sys.exit(main())
