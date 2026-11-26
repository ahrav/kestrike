#!/usr/bin/env python3
"""Run each stored plant through a sweep and write the share that sweeps catch.

Usage:
  plant-runner.py [--work DIR] [--campaign PATH] [--workers N] [--runs N]
      [--for SECONDS] [--rounds N] [--plant ID]...

A plant is a directory `verification/plants/<id>/` that holds `plant.patch`,
a diff against the head that restores a fixed defect, and `plant.json`:
`id` (the directory's name), `row` (the defect's row in the table of fixed
defects the store draws on), `fix` (`pull_request` and `commit`), `files`
(the planted paths), `restores` (one sentence),
`proof` (the fix's regression test, which passes at the head and fails on the
plant), `expected` (the profiles the run sweeps for the plant, which the
guide's rule selects) and `miss_cause` (null, or `cause`, one of
`environment`, `workload`, `ordering` and `property`, with `evidence`, one
sentence). `docs/agents/simulation.md` ("Score the planted defects") gives the
rule for `expected` and the meaning of each cause. Plants stay patch files:
the runner applies them only in its scratch worktrees.

The run judges the invoking checkout's `HEAD`, and the plant store must match
it: a plant file that differs from `HEAD` is rejected. In that checkout the
run writes `verification/plants/score.json` and leaves the index, the refs,
the stash, the configuration and every other file as they were. Its Git
commands read no replacement object (`refs/replace`). Its work lies
in `--work`, by default a new directory under `$TMPDIR`, which it keeps as
the run's evidence. The work directory lies outside the checkout, on a mount
`campaign` accepts (xfs, or ext4 with a journal), under ancestors only the
invoking user or root can write. A run without `--work` needs a `$TMPDIR` of
that kind: under a shared one, such as `/tmp`, it is rejected. The run takes
the plants in two phases. Steps 1 and 2 run for every plant before step 3
runs for any, and between them the run removes the proof's worktree and
target directory, so no archive build shares the disk with them. For each
plant, in a detached worktree of the
head under `<work>/plants/<id>/` with Git hooks disabled, it:

1. checks with `git apply --check --index` that the patch applies; one that
   Git refuses (exit 1) is `does not apply` and no miss, and a check that
   fails otherwise leaves no verdict;
2. reruns the plant's `proof` with `scripts/reproduce-test.py --package
   kestrike --target lib --test PROOF --attempts 1` of the head, once on
   the head and once on the plant, in one more worktree of the head under
   `<work>/proof/` with the run's `Cargo.lock` and a Cargo target directory
   of its own, which Cargo resolves from (`CARGO_RESOLVER_LOCKFILE_PATH`).
   Both reruns run the head's `reproduce-test.py` and `select-tests.py` from
   copies under `<work>/proof/scripts/`, outside the tree a patch changes,
   and the run judges each verdict line with that copy's own `reported`. The
   run first reruns on the head the proof of each plant whose patch applies,
   then applies each such plant there in turn, reruns its proof and resets
   the tree. A rerun counts when the tree still holds a regular `Cargo.lock`
   of the run's bytes after it and its exit of 0 or 1 stands beside the
   verdict line the helper prints last for that exit, `not reproduced` or
   `reproduced`. A plant whose proof's reruns both count, and do not exit 0
   on the head and 1 on the plant, is `not live`: `n` does not count it. Any
   other ending leaves the plant with no verdict: a build failure (3), a
   crash (4), a watchdog expiry (6), a rejected test ID (2), an exit of 0 or
   1 without its verdict line, a changed or missing `Cargo.lock`, or a helper
   that cannot start or prints no UTF-8 text. A build failure on the head
   gives every proof not yet rerun there that reason. A setup of the proof's
   worktree or of the helper's check that fails, an apply or a reset there
   that fails, or a rerun that changes the `Cargo.lock`, leaves that plant
   and every later one with no verdict. When the proof's worktree or target
   directory remains after the phase, every plant that waits for its archive
   has no verdict;
3. applies the patch to the index, commits it on the detached head with the
   head's date and a fixed identity, so the planted commit depends on the head
   and the patch alone, writes the checkout's `Cargo.lock`, read once at the
   start, into the tree, so every archive of the run resolves the same
   dependencies, and builds the archive with `campaign sim archive`, under
   `CARGO_PROFILE_DEV_OPT_LEVEL=3` and `CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=true`,
   with a Cargo target and build directory of its own that it removes after
   the build;
4. sweeps the `expected` profiles into a new root at default counts, under
   the campaign name `plant-<id>`, with `--workers` workers and `--for`
   seconds a sweep, again until each profile's `next` in `sweep-status` is
   at least `--runs`, for at most `--rounds` sweeps. `campaign sweep` bounds
   a sweep by time, so `--runs` is a floor, at least 300. A sweep that exits 1
   ends the loop;
5. runs `campaign confirm` when an expected profile's suspect of class
   `violation` or `panic` stands in the root's `suspects.jsonl`, and reads
   the findings `confirm` prints once its dispatch reports `queue_empty`, or
   holds at its `backlog` limit alone;
6. runs the seed of each such suspect that `confirm` turned into a finding of
   the suspect's class with `campaign sim run` on the archive of the
   unpatched head, which the run builds once, at the first such seed, under
   `<work>/base/`. The check runs the sweep's manifest of the suspect's
   profile with the seed as its root and the base archive's pins, and only
   when that manifest, before the pins change, hashes to the confirmed job's
   `manifest_sha256`.

A plant's result, in this order:

- `not live`: both proof reruns count, as step 2 defines, and the proof exits
  1 on the head or 0 on the plant; the reason names both. The plant gets no
  archive and no sweep;
- `caught`: a suspect of class `violation` or `panic` in an expected profile
  that `confirm` turned into a finding of that class, whose seed passes
  (`sim run` exits 0 with the class `counts`) on the unpatched head's
  archive, and whose profile, run and seed have no `replay differs` line in
  the root's `suspects.jsonl`. A catch outranks every cause of no verdict
  below, the root's other suspects included, and its record lists each
  confirmed suspect whose seed does not pass on the head. A suspect whose
  replay differs gives no catch, since its seed does not determine its run;
  another suspect's seed can still catch. The sweep lists the first eight
  suspects of a key and counts the rest, so a profile whose status counts
  more suspects than the list holds under a `replay differs` key or under
  `other`, gives no count by key, or gives one that does not sum to its
  suspects or counts fewer under a key than the list holds, may hide a
  differing replay of any of its runs: no suspect of that profile gives a
  catch;
- `no verdict`: a cause of step 2 or a failed apply check; the sweep's
  replay of a confirmed suspect's run differs; the planted tree or the unpatched head does not build
  (`sim archive` exits 3) or `sim archive` exits another nonzero code; a
  `campaign` command exits with another code than 0 (or 1 for a sweep), or
  `confirm` leaves jobs queued; the suspect's seed ran on the unpatched head
  and did not pass (`sim run` exits 1 or 4 with a worker result), or its seed
  check did not run: its manifest differs from the confirmed job's, or `sim
  run` exits another code or prints no result; the root holds `alarm`,
  `no_pass`, `unreached` or `no_window` (the record names
  the key); `confirm` makes no finding of a suspect; the root holds any other
  suspect, in any profile, or `suspects.jsonl` lists one; a profile stays
  below the floor or has no run counted; the last sweep's exit disagrees with
  the root's verdict keys; the status names another campaign or counts than
  the default; a campaign output is malformed; or a step fails for another
  cause, which the reason names;
- `missed`: each expected profile reached the floor and the root holds no
  suspect. A plant with no expected profile is `missed` once its archive
  builds, with no sweep.

The score names the head commit and the sentence `k of n plants at commit
C`, where `n` counts the caught and the missed plants, a tally of the
results, `not_live`, the plants that are not live, and `settings`: the workers, the floor, the seconds and rounds of a
sweep, the base archive's build digest, the SHA-256 of the `campaign` binary
that judged the run, and the plants `--plant` selected (null for the whole
store). A run with `--plant` writes a score over the selected plants alone.
For each plant it holds `id`, `row`, `fix`, `files` and `proof` from its
record, the result and its reason, the proof's exits on the head and on the
plant, the planted commit and tree, the archive's
build digest, the campaign, the profiles, the counts, each profile's runs,
`next`, run range, passes and suspects, the root's control and history
totals, the verdict keys, the confirmed suspects whose seeds fail on the
head, the suspect behind a catch with its finding and its seed's ending on
the head, and for a miss its `miss_cause`. A swept miss is one sample: a
rerun at the same commit builds another archive and sweeps other seeds. The
base archive's digest is null when no seed check built it or its build failed.
The `campaign` digest is of the file read at the start; replacing the binary
during a run is unsupported. A reason names the work directory as `<work>`.

Exit 0: every plant is caught or missed and every miss has its cause. Exit 1:
a miss has no `miss_cause`. Exit 3: no miss lacks its cause, and a plant has
no verdict, is not live or has a patch that does not apply, so the score
counts fewer plants than the run selected. Exit 4: the run could not write its score, left a
worktree it could not remove or could not list, could not load `scripts/red-green.py`, whose Git and
shared-directory refusals it applies, or failed outside a plant. Exit 2:
rejected input, found before any worktree: a plant whose record or patch is
missing, no regular file or malformed, whose record or patch passes 1 MiB or
differs from the regular file `HEAD` holds, whose id is `score.json`, passes 245 bytes or is one `campaign` cannot take
in `plant-<id>`, whose `proof` holds a NUL or is no UTF-8 text, that names a
profile `campaign` cannot take, or whose
patch changes other paths than its `files` or renames, copies, deletes or changes a mode; a plant store that is
a link, differs from `HEAD` (ignored files included) or cannot be read;
an unknown `--plant`; a `--runs` below 300; a Git variable that points Git at
another repository or index; a checkout whose `Cargo.lock` is missing, a link or no regular file; a `--campaign`
that names no executable; a work directory inside the checkout, under an
ancestor another user can write, or one that cannot be created; or an
invoking directory outside a Git checkout. Exits 0, 1 and 3 write the score
and print its sentence and one `ID: RESULT (REASON)` line a plant. On
SIGINT, SIGTERM or SIGHUP the run ignores further signals, sends the running
`campaign` command or proof rerun SIGTERM, waits for it, removes its
worktrees, names on standard error each one it could not remove or could not
list, and exits 128 plus the signal number without a score. A signal that
lands once the run has begun to write its score ends nothing: the run
finishes with its score and its own exit. A signal the run inherited as
ignored stays ignored. The proof's worktree and its target directory go after
the last proof rerun, or with the other worktrees when the run ends before
that; the run prints each one that remains.
"""

import argparse
import collections
import contextlib
import hashlib
import importlib.util
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path

CAUSES = ("environment", "workload", "ordering", "property")
# The keys `carries_verdict` reads in crates/campaign-supervisor/src/campaign/seeds.rs: a root that holds one makes
# its sweep exit 1.
VERDICT_KEYS = ("alarm", "no_pass", "unreached", "no_window")
CATCH_CLASSES = ("violation", "panic")
IDENTITY = {"GIT_AUTHOR_NAME": "plant-runner", "GIT_AUTHOR_EMAIL": "plant-runner@invalid",
            "GIT_COMMITTER_NAME": "plant-runner", "GIT_COMMITTER_EMAIL": "plant-runner@invalid"}
FIELDS = ("id", "row", "fix", "files", "restores", "proof", "expected", "miss_cause")
PINS = ("build", "executable", "platform", "toolchain")
COUNTERS = ("next", "runs", "pass", "suspects")
HANDLED = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
FLOOR = 300
STORE = Path("verification") / "plants"
SCORE = "score.json"
BACKLOG = "backlog holds "
# `is_backlog_hold` and `OMITTED_REFUSALS` in crates/sim-host/src/runner.rs judge the same report the same way.
BACKLOG_END = "; dispose findings or raise backlog"
OMITTED = "omitted refusals:"
RECORD_BOUND = 1 << 20
PROOF = ("--package", "kestrike", "--target", "lib", "--attempts", "1")
HELPER = ("reproduce-test.py", "select-tests.py")
REPLAY_DIFFERS = "replay differs"
# The longest plant id whose proof logs, `plant-<id>.out` and `plant-<id>.err`, fit a file name of 255 bytes.
ID_BOUND = 255 - len("plant-") - len(".out")
# `list` in crates/campaign-supervisor/src/campaign/seeds.rs counts a suspect under `CLASS: IDENTITY`, or under
# `OTHER` once its profile holds the most keys, and lists the first eight suspects of each key.
OTHER = "other"


def _load_red_green():
    """Load `red-green.py`, whose `OVERRIDES` and `foreign_toolchain_paths` judge the Git environment and the
    directories where another user can configure Cargo, so this runner refuses what that command refuses."""
    spec = importlib.util.spec_from_file_location("red_green", Path(__file__).with_name("red-green.py"))
    try:
        if spec is None or spec.loader is None:
            raise ImportError("no loader")
        module = importlib.util.module_from_spec(spec)
        # The load writes no bytecode cache into the checkout the run judges.
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
        return module.OVERRIDES, module.foreign_toolchain_paths, module.make_private
    except Exception as error:
        print(f"plant-runner: scripts/red-green.py cannot be loaded: {error}", file=sys.stderr)
        raise SystemExit(4) from error


OVERRIDES, foreign_toolchain_paths, make_private = _load_red_green()


def _load(path, name):
    """Load the script at `path` as the module `name`."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"{path.name} has no loader")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Rejected(Exception):
    """Input the run refuses before it starts any work."""


class NoVerdict(Exception):
    """A step that leaves its plant with no verdict; the text is the reason."""


class Unbuilt(NoVerdict):
    """A proof rerun whose library tests did not build (exit 3), an ending no test ID changes."""


class Relocked(NoVerdict):
    """A proof rerun that left the proof's worktree without the run's Cargo.lock, so the tree is unfit for every
    later rerun."""


class GitFailed(Exception):
    """A checked Git step that exited nonzero: its subcommand, its exit code and its error output."""

    def __init__(self, step, code, stderr):
        super().__init__(f"`git {step}` exited {code}")
        self.step, self.code, self.stderr = step, code, stderr


class Signals:
    """The first handled signal and whether the run defers it.

    The handler records the first signal and ignores every later one. Outside
    a deferred region it raises `SystemExit(128 + signal)` at once; inside one
    it returns, and the region raises on leaving. The dispositions stay this
    handler's, so every child starts with the default ones.
    """

    pending = None
    deferring = False


def stop(number, _frame):
    if Signals.pending is not None:
        return
    Signals.pending = number
    if not Signals.deferring:
        raise SystemExit(128 + number)


@contextlib.contextmanager
def deferred():
    """A region that a handled signal does not interrupt; a signal that lands inside it ends the run on leaving."""
    outer, Signals.deferring = Signals.deferring, True
    try:
        yield
    finally:
        Signals.deferring = outer
        if not outer and Signals.pending is not None:
            raise SystemExit(128 + Signals.pending)


def install():
    """Installs `stop` for each handled signal the run did not inherit as ignored."""
    for number in HANDLED:
        if signal.getsignal(number) != signal.SIG_IGN:
            signal.signal(number, stop)


def git(top, *args, check=True, env=None, data=None):
    """Runs `git ARGS` in `top` with hooks and optional locks disabled, so a read such as `status` leaves the
    index as it was, with the commit encoding UTF-8, so a commit carries no `encoding` header whatever
    the configuration names, and with `git apply` taking a patch's whitespace as it stands, in its added lines
    and in its context; a checked failure raises `GitFailed`. With `data`, Git reads those bytes on its
    standard input and its output stays bytes."""
    done = subprocess.run(
        ["git", "--no-optional-locks", "-c", "core.hooksPath=/dev/null", "-c", "i18n.commitEncoding=UTF-8",
         "-c", "apply.whitespace=nowarn", "-c", "apply.ignoreWhitespace=no", "-C", str(top), *args],
        capture_output=True, text=data is None, input=data, check=False, env=env,
    )
    if check and done.returncode != 0:
        stderr = done.stderr if data is None else done.stderr.decode(errors="replace")
        raise GitFailed(args[0] if args else "", done.returncode, stderr)
    return done


def staged_checker(path):
    """The verdict check of the staged helper at `path`: its `reported` and its verdict text of exits 0 and 1.

    A helper that does not load, or lacks either, leaves every plant with no
    verdict. A signal during the load ends the run after it.
    """
    with deferred():
        try:
            module = _load(path, "staged_reproduce_test")
            if not callable(module.reported):
                raise TypeError("its `reported` is not callable")
            return module.reported, {code: str(module.RESULTS[code]) for code in (0, 1)}
        except (Exception, SystemExit) as error:
            raise NoVerdict(f"the head's scripts/{path.name} gives no verdict check: {type(error).__name__}: "
                            f"{error}") from error


def cargo_env(target, lockfile=None, **settings):
    """The run's environment with `target` as Cargo's target and build directory and `settings` added.

    With `lockfile`, Cargo resolves from that file whatever path a Cargo
    configuration names; without it, the caller's lockfile path is dropped,
    for a command that pins its own.
    """
    env = dict(os.environ, CARGO_TARGET_DIR=target, CARGO_BUILD_BUILD_DIR=target, **settings)
    env.pop("CARGO_RESOLVER_LOCKFILE_PATH", None)
    if lockfile is not None:
        env["CARGO_RESOLVER_LOCKFILE_PATH"] = str(lockfile)
    return env


def unique(pairs):
    """A JSON object's members; a repeated member is malformed."""
    members = {}
    for name, value in pairs:
        if name in members:
            raise ValueError(f"repeated member {name}")
        members[name] = value
    return members


def loads(data):
    """A JSON document whose objects repeat no member."""
    return json.loads(data, object_pairs_hook=unique)


def natural(value, least=0):
    """Whether `value` is a JSON integer of at least `least`; a boolean is none."""
    return isinstance(value, int) and not isinstance(value, bool) and value >= least


def count(value):
    """Whether `value` is a positive JSON integer."""
    return natural(value, 1)


def profile_name(value):
    """Whether `campaign` can take `value` as a profile name: printable ASCII without a comma or a slash, at
    most 242 bytes, and neither `.` nor `..`."""
    return (text(value) and len(value) <= 242 and all(" " <= c <= "~" for c in value)
            and "," not in value and "/" not in value and value not in (".", ".."))


def load_plant(top, head, directory):
    """The record of the plant in `directory`, checked field by field, with its patch's paths checked by Git.

    Each file is read once, at most `RECORD_BOUND` bytes, and must equal the
    regular file `head` holds at its path, so the plant scored is the plant
    the commit holds whatever the index's flags say.
    """
    name = directory.name
    record_path, patch = directory / "plant.json", directory / "plant.patch"
    try:
        if not all(path.is_file() and not path.is_symlink() for path in (record_path, patch)):
            raise Rejected(f"{name}: plant.json and plant.patch are both required, as regular files")
        data, patch_bytes = bounded(record_path), bounded(patch)
        if data is None or patch_bytes is None:
            raise Rejected(f"{name}: plant.json or plant.patch holds more than {RECORD_BOUND} bytes")
        record = loads(data)
    except (OSError, ValueError, RecursionError) as error:
        raise Rejected(f"{name}: plant.json is unreadable: {error}") from error
    if not isinstance(record, dict) or sorted(record) != sorted(FIELDS):
        raise Rejected(f"{name}: plant.json holds exactly the fields {', '.join(FIELDS)}")
    fix = record["fix"]
    checks = (
        (name != SCORE, f"id is another name than {SCORE}, the path of the run's score"),
        (len(name) <= ID_BOUND, f"id holds at most {ID_BOUND} bytes, so the proof's logs plant-<id>.out and "
                                "plant-<id>.err are file names"),
        (record["id"] == name and all(" " <= c <= "~" for c in name) and name == name.strip(),
         "id names the plant's directory in printable ASCII without edge spaces, so campaign takes plant-<id>"),
        (count(record["row"]), "row is a positive integer"),
        (isinstance(fix, dict) and sorted(fix) == ["commit", "pull_request"] and count(fix["pull_request"])
         and text(fix["commit"]), "fix holds a positive pull_request and a commit"),
        (strings(record["files"]) and record["files"], "files is a nonempty list of paths"),
        (text(record["restores"]) and text(record["proof"]), "restores and proof are nonempty text"),
        (argument(record["proof"]), "proof holds no NUL and is UTF-8 text a process takes as an argument"),
        (strings(record["expected"]) and all(profile_name(item) for item in record["expected"]),
         "expected is a list of profile names campaign can take"),
        (record["miss_cause"] is None or cause(record["miss_cause"]), "miss_cause is null or a cause with evidence"),
    )
    for holds, rule in checks:
        if not holds:
            raise Rejected(f"{name}: {rule}")
    # `--numstat` parses the patch without applying it, so a corrupt or empty patch is refused here and a
    # well-formed one whose context moved still reaches the worktree's check.
    stats = git(top, "apply", "--numstat", check=False, data=patch_bytes)
    out, err = stats.stdout.decode(errors="replace"), stats.stderr.decode(errors="replace")
    paths = [line.split("\t", 2)[-1] for line in out.splitlines() if line.count("\t") >= 2]
    if stats.returncode != 0 or not paths:
        lines = err.strip().splitlines()
        raise Rejected(f"{name}: plant.patch is no patch: {lines[0] if lines else 'it changes no path'}")
    if sorted(paths) != sorted(record["files"]):
        raise Rejected(f"{name}: plant.patch changes {', '.join(sorted(paths))}, and files names "
                       f"{', '.join(sorted(record['files']))}")
    # `--numstat` names a rename's new path alone and says nothing of modes, so `--summary` refuses both.
    summary = git(top, "apply", "--summary", check=False, data=patch_bytes).stdout.decode(errors="replace")
    summary = summary.splitlines()
    odd = [line.strip() for line in summary
           if line.strip().startswith(("rename ", "copy ", "mode change ", "delete mode "))
           or (line.strip().startswith("create mode ") and not line.strip().startswith("create mode 100644 "))]
    if odd:
        raise Rejected(f"{name}: plant.patch does more than change file contents: {odd[0]}")
    for path, held in ((record_path, data), (patch, patch_bytes)):
        committed(top, head, path, held)
    record["patch"] = patch_bytes
    return record


def bounded(path):
    """The bytes of `path`, read up to one byte past `RECORD_BOUND`; None when the file holds more."""
    try:
        with open(path, "rb") as source:
            data = source.read(RECORD_BOUND + 1)
    except OSError as error:
        raise Rejected(f"{path.parent.name}: {path.name} is unreadable: {error.strerror or error}") from error
    return data if len(data) <= RECORD_BOUND else None


def committed(top, head, path, data):
    """Refuses `data`, read at `path`, unless `head` holds those bytes there as a regular file."""
    relative = path.relative_to(top).as_posix()
    listed = git(top, "ls-tree", "-z", head, "--", relative, check=False).stdout.rstrip("\0").split("\0")
    fields = listed[0].split(None, 3) if len(listed) == 1 and listed[0] else []
    blob = None
    if len(fields) == 4 and fields[0] == "100644" and fields[1] == "blob":
        blob = git(top, "cat-file", "blob", fields[2], check=False, data=b"").stdout
    if blob != data:
        raise Rejected(f"the plant store differs from HEAD at {relative}; commit the plants first")


def argument(value):
    """Whether `value` is text a process takes as one argument: free of NUL, and UTF-8 text, so it also encodes
    as a file name and prints."""
    if not isinstance(value, str) or "\x00" in value:
        return False
    try:
        value.encode("utf-8")
        os.fsencode(value)
    except UnicodeError:
        return False
    return True


def text(value):
    return isinstance(value, str) and value.strip() != ""


def strings(value):
    return isinstance(value, list) and all(text(item) for item in value) and len(set(value)) == len(value)


def cause(value):
    return (
        isinstance(value, dict)
        and sorted(value) == ["cause", "evidence"]
        and value["cause"] in CAUSES
        and text(value["evidence"])
    )


def load_plants(top, head, chosen):
    """The plants of the store, checked, and those `chosen` names, or all of them. The store holds a directory
    for each plant directory `head` holds."""
    directory = top / STORE
    # The score is written into the store, so the store and its parent are real directories of the checkout.
    linked = [path for path in (top / STORE.parent, directory) if path.is_symlink()]
    if linked:
        raise Rejected(f"{linked[0]} is a link; the plant store must be a directory of the checkout")
    try:
        if not directory.is_dir():
            raise Rejected(f"{directory} is no directory")
        entries = sorted(directory.iterdir())
        places = [path for path in entries if path.is_dir()]
    except OSError as error:
        raise Rejected(f"the plant store cannot be read: {error}") from error
    plants = [load_plant(top, head, path) for path in places]
    if not plants:
        raise Rejected(f"{directory} holds no plant")
    names = {plant["id"] for plant in plants}
    unknown = [name for name in chosen if name not in names]
    if unknown:
        raise Rejected(f"no plant named {', '.join(unknown)}")
    changed = [
        line[3:] for line in git(top, "status", "--porcelain", "--untracked-files=all", "--ignored", "--",
                                 str(STORE)).stdout
        .splitlines() if not Path(line[3:]).name.lstrip(".").startswith(SCORE)
    ]
    if changed:
        raise Rejected(f"the plant store differs from HEAD at {', '.join(changed)}; commit the plants first")
    held = git(top, "ls-tree", "-z", "-d", "--name-only", head, "--", f"{STORE.as_posix()}/", check=False)
    if held.returncode != 0:
        raise Rejected(f"the plant store of HEAD cannot be listed: `git ls-tree` exited {held.returncode}")
    present = {(STORE / path.name).as_posix() for path in places}
    absent = sorted(name for name in held.stdout.split("\0") if name and name not in present)
    if absent:
        raise Rejected(f"the plant store differs from HEAD at {', '.join(absent)}; commit the plants first")
    return [plant for plant in plants if not chosen or plant["id"] in chosen]


def json_line(out, index, what):
    """The JSON object on line `index` of a command's output `out`."""
    try:
        printed = loads(out.split("\n")[index])
    except (IndexError, ValueError, RecursionError) as error:
        raise NoVerdict(f"`campaign {what}` printed no JSON object: {error}") from error
    if not isinstance(printed, dict):
        raise NoVerdict(f"`campaign {what}` printed no JSON object")
    return printed


class Run:
    """One run's settings, its work directory, its worktrees, its lockfile, the proof reruns and the base archive."""

    def __init__(self, args, top, head, lock):
        self.args, self.top, self.head, self.lock = args, top, head, lock
        self.checker = None
        self.on_head = {}
        self.proof_place = args.work / "proof"
        self.proof_tree = None
        self.proof_failure = None
        self.trees = []
        self.base = None
        self.base_failure = None
        self.date = git(top, "show", "--no-patch", "--no-show-signature", "--format=%cI", head).stdout.strip()

    def tree(self, place):
        """A detached worktree of the head at `place/tree`."""
        tree = place / "tree"
        make_private(place)
        self.trees.append(tree)
        # A signal during the add would leave a half-made, locked worktree; the add finishes first.
        with deferred():
            git(self.top, "worktree", "add", "--detach", str(tree), self.head)
        return tree

    def remove_trees(self):
        """Removes this run's worktrees, locked ones included, and returns each one that remains, paired with
        None, and each one a failed `git worktree list` leaves unknown, paired with that listing's exit code."""
        remained = []
        for tree in self.trees:
            git(self.top, "worktree", "remove", "--force", "--force", str(tree), check=False)
            listing = git(self.top, "worktree", "list", "--porcelain", check=False)
            if tree.exists() or f"worktree {tree}" in listing.stdout.splitlines():
                remained.append((tree, None))
            elif listing.returncode != 0:
                remained.append((tree, listing.returncode))
        return remained

    def write_lock(self, tree, what):
        """Writes the run's one lockfile into `tree`, `what`, which must hold none, so every build of the run
        resolves the same dependencies."""
        try:
            with open(tree / "Cargo.lock", "xb") as lock:
                lock.write(self.lock)
        except FileExistsError as error:
            raise NoVerdict(f"{what} already holds a Cargo.lock") from error
        except OSError as error:
            raise NoVerdict(f"the run's Cargo.lock cannot be written into {what}: {error.strerror or error}") from error

    def command(self, log, *args, cwd=None, env=None):
        """Runs `campaign ARGS` with its output in `log`.out and `log`.err, which it creates.

        A signal waits until the child is spawned and its handle held. An
        exception that lands while the command runs, such as the signal
        handler's, sends it SIGTERM and waits for it, so a sweep or a confirm
        in its own systemd scope stops its run before the runner goes on.
        """
        return self.process(log, [self.args.campaign, *args], f"campaign {args[0]}", cwd=cwd, env=env)

    def process(self, log, argv, what, cwd=None, env=None, session=False):
        """Runs `argv` as `command` runs a `campaign` command, and returns its exit and its output.

        With `session`, the child starts a session of its own, so a signal sent
        to the runner's process group reaches it only through the runner. A
        child that cannot start, or whose output is no UTF-8 text, leaves no
        verdict.
        """
        try:
            with open(f"{log}.out", "x+", encoding="utf-8") as out, open(f"{log}.err", "x", encoding="utf-8") as err:
                child = None
                try:
                    with deferred():
                        child = subprocess.Popen(argv, cwd=cwd, env=env, stdout=out, stderr=err,
                                                 start_new_session=session)
                    code = child.wait()
                except BaseException:
                    if child is not None:
                        child.terminate()
                        child.wait()
                    raise
                out.seek(0)
                try:
                    return code, out.read()
                except ValueError as error:
                    raise NoVerdict(f"`{what}` exited {code} and printed no UTF-8 text ({error}); its output is in "
                                    f"{Path(log).relative_to(self.args.work)}.out") from error
        except OSError as error:
            raise NoVerdict(f"`{what}` did not run: {error.strerror or error}") from error
        except ValueError as error:
            raise NoVerdict(f"`{what}` did not run: {error}") from error

    def holds_lock(self, tree):
        """Whether `tree` holds a regular Cargo.lock of exactly the run's bytes, read through one descriptor that
        follows no link and waits for no writer, and at most one byte past the run's lockfile."""
        try:
            descriptor = os.open(tree / "Cargo.lock", os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        except OSError:
            return False
        with os.fdopen(descriptor, "rb") as lock:
            return stat.S_ISREG(os.fstat(lock.fileno()).st_mode) and lock.read(len(self.lock) + 1) == self.lock

    def proof(self, tree, proof, label):
        """The exit of the head's `reproduce-test.py` for `proof` in the proof's worktree `tree` as it stands,
        logged as `label`: 0 or 1 beside the verdict line the staged helper's own check accepts for that exit,
        with the run's Cargo.lock still in the tree, or a `NoVerdict` that names any other ending."""
        place = self.proof_place
        argv = [sys.executable, str(place / "scripts" / HELPER[0]), *PROOF, "--test", proof,
                "--artifacts", str(place / "artifacts" / label)]
        env = cargo_env(str(place / "target"), lockfile=tree / "Cargo.lock")
        code, out = self.process(place / label, argv, "reproduce-test.py", cwd=tree, env=env, session=True)
        log = (place / label).relative_to(self.args.work)
        kept = (place / "artifacts" / label).relative_to(self.args.work)
        if not self.holds_lock(tree):
            raise Relocked(f"the rerun of the proof {proof} left the proof's worktree without the run's "
                           f"Cargo.lock; its output is in {log}.out")
        if code == 3:
            raise Unbuilt(f"the rerun of the proof {proof} exited 3; its verdict is in {log}.out and its build "
                          f"output under {kept}")
        if code not in (0, 1):
            raise NoVerdict(f"the rerun of the proof {proof} exited {code}; its verdict is in {log}.out, its error "
                            f"output in {log}.err and its run's output under {kept}")
        if self.checker is None:
            raise NoVerdict("the run holds no verdict check of the head's helper")
        lines = out.strip().splitlines()
        reported, results = self.checker
        try:
            counted = bool(reported(code, lines[-1] if lines else ""))
        except Exception as error:
            raise NoVerdict(f"the head's verdict check failed on the rerun of the proof {proof}: "
                            f"{type(error).__name__}: {error}") from error
        if not counted:
            raise NoVerdict(f"the rerun of the proof {proof} exited {code} without the verdict "
                            f"`{results[code]}`; its output is in {log}.out")
        return code

    def prove_head(self, proofs):
        """Makes the proof's worktree with the run's Cargo.lock, copies the head's helper scripts out of it, so a
        plant's patch changes neither leg's judge, loads the verdict check from that copy, and reruns each of
        `proofs` on the head, so the head builds once.

        A failure of that setup is kept in `proof_failure`, so every plant
        reports the first cause. A head rerun that fails is kept for its
        proof, so every plant of that proof reports the same reason. A head
        whose library tests do not build (exit 3) fails every proof not yet
        rerun with that reason, since no test ID changes the build. A rerun
        that leaves the tree without the run's Cargo.lock ends the head's
        reruns and is kept in `proof_failure`, since the tree no longer holds
        the run's resolution.
        """
        place = self.proof_place
        try:
            tree = self.tree(place)
            self.write_lock(tree, "the proof's worktree")
            (place / "scripts").mkdir()
            for name in HELPER:
                try:
                    shutil.copyfile(tree / "scripts" / name, place / "scripts" / name)
                except OSError as error:
                    raise NoVerdict(f"the head's scripts/{name} cannot be copied: {error.strerror}") from error
            self.checker = staged_checker(place / "scripts" / HELPER[0])
        except NoVerdict as error:
            self.proof_failure = error
            return
        except GitFailed as error:
            log = keep_git_error(place, error).relative_to(self.args.work)
            self.proof_failure = NoVerdict(f"the proof's worktree: {error}; its error is in {log}")
            return
        except (OSError, ValueError) as error:
            self.proof_failure = NoVerdict(f"the proof's worktree cannot be prepared: {error}")
            return
        self.proof_tree = tree
        for number, proof in enumerate(proofs):
            try:
                self.on_head[proof] = self.proof(tree, proof, f"head-{number}")
            except Relocked as error:
                self.proof_failure = error
                return
            except Unbuilt as error:
                shared = NoVerdict(f"the head's library tests do not build, so no proof reruns on the head: {error}")
                self.on_head.update(dict.fromkeys(proofs[number:], shared))
                return
            except NoVerdict as error:
                self.on_head[proof] = error

    def live(self, plant):
        """The proof's exits on the head, from `prove_head`, and on the plant.

        The plant's patch, the head's bytes, is applied to the proof's
        worktree, its proof rerun, and the tree reset, so each plant rebuilds
        what its patch and the previous plant's reset changed. A failure of
        the apply or the reset, or a rerun that changes the run's Cargo.lock,
        leaves the tree with an unknown share of that plant, so every later
        plant reports that failure. A rerun that fails after a reset that
        succeeded stays this plant's.
        """
        if self.proof_failure is not None:
            raise self.proof_failure
        head = self.on_head[plant["proof"]]
        if isinstance(head, NoVerdict):
            raise head
        tree = self.proof_tree
        try:
            git(tree, "apply", "--index", str(self.args.work / "plants" / plant["id"] / "plant.patch"))
            try:
                planted = self.proof(tree, plant["proof"], f"plant-{plant['id']}")
            finally:
                git(tree, "reset", "--hard", "--quiet")
        except Relocked as error:
            self.proof_failure = error
            raise
        except NoVerdict:
            raise
        except Exception as error:
            self.proof_failure = NoVerdict(f"the proof's worktree is no longer the head's tree: {error} at the "
                                           f"plant {plant['id']}")
            raise
        return head, planted

    def release_proof(self):
        """Removes the proof's worktree and target directory once the last proof has rerun, keeping its logs, and
        returns each of the two that remains."""
        tree, target = self.proof_place / "tree", self.proof_place / "target"
        if tree in self.trees:
            with deferred():
                git(self.top, "worktree", "remove", "--force", "--force", str(tree), check=False)
        shutil.rmtree(target, ignore_errors=True)
        listed = git(self.top, "worktree", "list", "--porcelain", check=False).stdout.splitlines()
        return [path for path in (tree, target) if path.exists() or path.is_symlink() or f"worktree {path}" in listed]

    def archive(self, place, tree, what):
        """Builds the archive of `tree` at `place/archive` and returns it with its pins."""
        target = str(place / "target")
        env = cargo_env(target, CARGO_PROFILE_DEV_OPT_LEVEL="3", CARGO_PROFILE_DEV_DEBUG_ASSERTIONS="true")
        output = place / "archive"
        # The run's one lockfile keeps every archive on one resolution of the dependencies.
        self.write_lock(tree, what)
        try:
            code, out = self.command(place / "archive", "sim", "archive", "--output", str(output), cwd=tree, env=env)
        finally:
            # The removal runs whole: a signal that lands in it ends the run after it.
            with deferred():
                shutil.rmtree(target, ignore_errors=True)
        if code == 3:
            raise NoVerdict(f"{what} does not build: `campaign sim archive` exited 3")
        if code != 0:
            raise NoVerdict(f"`campaign sim archive` of {what} exited {code}; its error is in "
                            f"{place.relative_to(self.args.work) / 'archive.err'}")
        pins = json_line(out.strip(), -1, "sim archive")
        if not all(isinstance(pins.get(key), str) for key in PINS):
            raise NoVerdict("`campaign sim archive` printed no pins")
        kept = output / "Cargo.lock"
        if kept.is_symlink() or not kept.is_file() or kept.read_bytes() != self.lock:
            raise NoVerdict(f"the archive of {what} keeps no regular Cargo.lock equal to the run's")
        return output, pins

    def base_archive(self):
        """The unpatched head's archive and pins, built at the first call; a failed build fails every call."""
        if self.base is None and self.base_failure is None:
            place = self.args.work / "base"
            try:
                self.base = self.archive(place, self.tree(place), "the unpatched head")
            except NoVerdict as error:
                self.base_failure = error
            except GitFailed as error:
                self.base_failure = NoVerdict(f"the unpatched head's worktree: {error}; its error is in "
                                              f"{keep_git_error(place, error).relative_to(self.args.work)}")
        if self.base_failure is not None:
            raise self.base_failure
        assert self.base is not None, "a base build sets the archive or the failure"
        return self.base

    def sweep(self, plant, archive, place):
        """Sweeps the plant's profiles until each reaches the floor; returns the last status."""
        root, floor = place / "root", self.args.runs
        code, status = 0, {}
        for number in range(1, self.args.rounds + 1):
            code, _ = self.command(
                place / f"sweep-{number}", "sweep", "--root", str(root), "--archive", str(archive),
                "--campaign", f"plant-{plant['id']}", "--profiles", ",".join(plant["expected"]),
                "--workers", str(self.args.workers), "--for", str(self.args.seconds),
            )
            if code not in (0, 1):
                raise NoVerdict(f"`campaign sweep` exited {code}")
            status = self.json(place / f"status-{number}", "sweep-status", "--root", str(root))
            if code == 1 or all(profile_runs(status, p)["next"] >= floor for p in plant["expected"]):
                break
        return code, status

    def json(self, log, *args):
        """The JSON object the first line of `campaign ARGS` prints; a scoped command adds a line after it."""
        code, out = self.command(log, *args)
        if code != 0:
            raise NoVerdict(f"`campaign {args[0]}` exited {code}")
        return json_line(out, 0, args[0])

    def confirm(self, place, archive):
        """The findings `confirm` prints for the root, and the backlog hold that stopped it, if one did.

        `confirm` exits 4 with its report when a refusal holds its dispatch.
        A hold whose every refusal is the `backlog` limit still settled and
        printed the findings it made, so those stand; any other hold or exit
        leaves the plant with no verdict.
        """
        code, out = self.command(place / "confirm", "confirm", "--root", str(place / "root"), "--archive", str(archive))
        if code not in (0, 4):
            raise NoVerdict(f"`campaign confirm` exited {code}")
        printed = json_line(out, 0, "confirm")
        refusals = printed.get("refusals")
        hold = None
        if code == 4:
            errors = (place / "confirm.err").read_text(errors="replace")
            if not (isinstance(refusals, list) and refusals and printed.get("dispatch") == "held"
                    and printed.get("rejections") == [] and OMITTED not in errors
                    and all(isinstance(line, str) and line.startswith(BACKLOG) and line.endswith(BACKLOG_END)
                            for line in refusals)):
                raise NoVerdict(f"`campaign confirm` exited 4 at dispatch {printed.get('dispatch')!r}")
            hold = f"`campaign confirm` held its queue: {refusals[0]}"
        elif printed.get("dispatch") != "queue_empty":
            raise NoVerdict(f"`campaign confirm` left its queue at dispatch {printed.get('dispatch')!r}")
        listing = printed.get("findings")
        findings = listing.get("findings") if isinstance(listing, dict) else None
        if not isinstance(findings, list) or not all(isinstance(finding, dict) for finding in findings):
            raise NoVerdict("`campaign confirm` printed no list of findings")
        return findings, hold

    def seed_on_base(self, root, suspect, place, confirmed):
        """The exit and the ending of the suspect's seed on the unpatched head's archive.

        The seed check runs the sweep's manifest of the suspect's profile with
        the suspect's seed as its root and the base archive's pins. Before the
        pins change, that manifest must hash to `confirmed`, the digest of the
        job `confirm` ran, so the check runs the confirmed experiment; when it
        does not, the exit is None and nothing runs.
        """
        manifest = (root / "manifests" / f"{suspect['profile']}.manifest").read_text().split("\n")
        if manifest and manifest[-1] == "":
            manifest.pop()
        seeded = "".join(rewrite(line, {"root": str(suspect["seed"])}) + "\n" for line in manifest)
        if hashlib.sha256(seeded.encode()).hexdigest() != confirmed:
            return None, "its manifest differs from the job `confirm` ran"
        archive, pins = self.base_archive()
        values = {key: pins[key] for key in PINS}
        values["root"] = str(suspect["seed"])
        check = place / "seeds" / suspect["profile"] / f"{suspect['run']}-{suspect['seed']}"
        make_private(check.parent)
        check.mkdir(mode=0o700)
        (check / "manifest").write_text("".join(rewrite(line, values) + "\n" for line in manifest))
        code, out = self.command(
            check / "run", "sim", "run", "--archive", str(archive), "--manifest", str(check / "manifest"),
            "--artifacts", str(check / "artifacts"),
        )
        try:
            printed = json_line(out.strip(), -1, "sim run")
            kind, reason = str(printed["class"]), printed.get("reason")
            ending = (reason if str(reason).startswith(f"{kind}: ") else f"{kind}: {reason}") if reason else kind
        except (KeyError, NoVerdict):
            # A seed check that printed no worker result ran nothing on the head.
            return None, f"exit {code} with no result"
        if code == 0 and kind != "counts":
            return None, f"exit 0 with the class {kind}"
        return code, ending


def rewrite(line, values):
    key = line.split(" = ", 1)[0]
    return f"{key} = {values[key]}" if key in values else line


def profile_runs(status, profile):
    """A profile's counters in a `sweep-status` document, each a nonnegative integer, and its run range."""
    profiles = status.get("profiles")
    totals = profiles.get(profile) if isinstance(profiles, dict) else None
    if not isinstance(totals, dict):
        raise NoVerdict(f"`campaign sweep-status` names no profile {profile}")
    values = {name: totals.get(name) for name in COUNTERS}
    if not all(natural(value) for value in values.values()):
        raise NoVerdict(f"`campaign sweep-status` gives {profile} no count of {', '.join(COUNTERS)}")
    passed, ran, following = (int(values[name] or 0) for name in ("pass", "runs", "next"))
    if not passed <= ran <= following:
        raise NoVerdict(f"`campaign sweep-status` gives {profile} counts out of order: pass {passed}, "
                        f"runs {ran}, next {following}")
    values["range"] = [0, values["next"] - 1] if values["next"] else None
    # Evidence fields alone: the replays a sweep ran and the rules its uncredited runs ended under.
    values["replays"], values["uncredited"] = totals.get("replays"), totals.get("uncredited")
    return values


def suspects(root, profiles):
    """The suspects of `profiles` and of a catch class in `suspects.jsonl`, once each, in file order, the count
    of complete records of any profile and class, the `(profile, run, seed)` of each `replay differs` record,
    and the count of complete records of each `(profile, key)`.

    A record is one line ended by a newline byte, as the sweep writes it; a
    record at the end without its newline is a write a kill cut short and is
    not read. A missing list holds no suspect. A list that is no regular
    file, or a complete line that is no suspect, leaves no verdict.
    """
    path, listed, seen, complete, replayed = root / "suspects.jsonl", [], set(), 0, set()
    shown = collections.Counter()
    if not path.exists() and not path.is_symlink():
        return listed, complete, replayed, shown
    if not path.is_file():
        raise NoVerdict("the root's suspects.jsonl is no regular file")
    with open(path, "rb") as lines:
        for number, line in enumerate(lines, 1):
            if not line.endswith(b"\n"):
                break
            complete += 1
            try:
                suspect = loads(line)
                fields = {name: suspect[name] for name in ("profile", "run", "seed", "class", "key")}
            except (KeyError, TypeError, ValueError, RecursionError) as error:
                raise NoVerdict(f"suspects.jsonl line {number} is no suspect") from error
            numbers = (fields["run"], fields["seed"])
            if not all(isinstance(fields[name], str) for name in ("profile", "class", "key")) or not all(
                    natural(value) for value in numbers):
                raise NoVerdict(f"suspects.jsonl line {number} is no suspect")
            shown[(fields["profile"], fields["key"])] += 1
            key = (fields["profile"], fields["run"], fields["seed"])
            if fields["class"] == REPLAY_DIFFERS:
                replayed.add(key)
            if fields["profile"] in profiles and fields["class"] in CATCH_CLASSES and key not in seen:
                seen.add(key)
                listed.append(fields)
    return listed, complete, replayed, shown


def unlisted_replay(status, profile, shown):
    """Why a differing replay of a run of `profile` may be absent from `suspects.jsonl`, or None.

    `status` is the `sweep-status` document and `shown` the lines the list
    holds of each `(profile, key)`. A key of class `replay differs`, or
    `OTHER`, which takes any class, whose count passes its lines holds a
    suspect the list does not name. A profile without a count of its
    suspects by key, each a nonnegative integer, is read the same way, and
    so is a count by key that does not sum to the profile's suspects or
    that counts fewer suspects under a key than the list holds: the sweep
    counts each suspect once under its key, so such a count leaves suspects
    out.
    """
    totals = (status.get("profiles") or {}).get(profile)
    if not isinstance(totals, dict):
        return f"`campaign sweep-status` names no profile {profile}"
    keys, total = totals.get("suspect_keys"), totals.get("suspects")
    if not isinstance(keys, dict) or not all(natural(number) for number in keys.values()):
        return f"`campaign sweep-status` gives {profile} no count of its suspects by key"
    if sum(keys.values()) != total:
        return f"`campaign sweep-status` counts {total!r} suspects of {profile} and {sum(keys.values())} by key"
    for (name, key), lines in sorted(shown.items()):
        if name == profile and lines > keys.get(key, 0):
            return (f"`suspects.jsonl` lists {lines} suspects of {profile} under `{key}` and `campaign "
                    f"sweep-status` counts {keys.get(key, 0)}")
    for key, number in sorted(keys.items()):
        if (key == OTHER or key.startswith(f"{REPLAY_DIFFERS}: ")) and number > shown[(profile, key)]:
            return (f"`campaign sweep-status` counts {number} suspects of {profile} under `{key}` and "
                    f"`suspects.jsonl` lists {shown[(profile, key)]}")
    return None


def member(value, name):
    """The member `name` of a JSON object, or None when `value` is no object."""
    return value.get(name) if isinstance(value, dict) else None


def finding_of(findings, suspect):
    """The id of the finding of the suspect's class whose admitted job is the suspect's run, and that job's
    manifest digest, or None. A finding of another shape confirms nothing."""
    for finding in findings:
        verified = member(finding, "verified")
        job = member(member(verified, "admission"), "job")
        experiment = member(job, "experiment")
        ran = (member(experiment, "profile"), member(experiment, "run"), member(job, "seed"), member(verified, "kind"))
        typed = text(member(finding, "id")) and natural(ran[1]) and natural(ran[2])
        if typed and ran == (suspect["profile"], suspect["run"], suspect["seed"], suspect["class"]):
            return finding["id"], member(job, "manifest_sha256")
    return None


def held_suspects(status):
    """Each profile's suspect count in a `sweep-status` document, controls and histories included."""
    profiles = status.get("profiles")
    if not isinstance(profiles, dict):
        raise NoVerdict("`campaign sweep-status` names no profiles")
    held = {name: totals.get("suspects") if isinstance(totals, dict) else None for name, totals in profiles.items()}
    unread = sorted(name for name, number in held.items() if not natural(number))
    if unread:
        raise NoVerdict(f"`campaign sweep-status` gives {', '.join(unread)} no suspect count")
    return held


def run_store(run, plants):
    """The score records of `plants`, in their order, in two phases.

    The first phase checks that each patch applies in the plant's worktree,
    then reruns the proofs of the plants whose patch applies, all on the
    proof's one target directory, and removes that directory and the proof's
    worktree. The second builds, sweeps and confirms each live plant, so no
    archive build shares the disk with the proof's target: when either
    remains, each plant that waits for its archive has no verdict. Each
    plant prints a line to stderr as the first phase settles it and when the
    second ends.
    """
    entries = []
    for plant in plants:
        record = {key: plant[key] for key in ("id", "row", "fix", "files", "proof")}
        record.update(campaign=f"plant-{plant['id']}", profiles=plant["expected"], proof_exits=None, commit=None,
                      tree=None, archive=None)
        record.update(counts=None, runs={}, controls=None, histories=None, keys={}, head_failures=[])
        entries.append((plant, record, settle(run, plant, record, applies)))
        if "result" in record:
            print(f"{plant['id']}: {record['result']}", file=sys.stderr, flush=True)
    applying = [(plant, record) for plant, record, _ in entries if "result" not in record]
    if applying:
        run.prove_head(list(dict.fromkeys(plant["proof"] for plant, _ in applying)))
    for plant, record in applying:
        settle(run, plant, record, prove)
        print(f"{plant['id']}: proof {record.get('result') or record['proof_exits']}", file=sys.stderr, flush=True)
    remained = run.release_proof()
    held = ", ".join(str(path.relative_to(run.args.work)) for path in remained)
    for plant, record, tree in entries:
        if "result" not in record and remained:
            record.update(result="no verdict", reason=f"the proof's {held} remained after the last proof rerun, so "
                                                      "no archive builds beside it")
        elif "result" not in record:
            settle(run, plant, record, judge, tree)
        if record["result"] == "missed":
            record["miss_cause"] = plant["miss_cause"]
        # The score is a tracked file, so its reasons name the work directory by a placeholder.
        record["reason"] = record["reason"].replace(str(run.args.work), "<work>")
        print(f"{plant['id']}: {record['result']}", file=sys.stderr, flush=True)
    return [record for _, record, _ in entries]


def settle(run, plant, record, step, *extra):
    """The value of `step(run, plant, record, *extra)`; a step that fails sets the plant's no verdict and its reason
    in `record`."""
    place = run.args.work / "plants" / plant["id"]
    try:
        return step(run, plant, record, *extra)
    except NoVerdict as error:
        record.update(result="no verdict", reason=str(error))
    except GitFailed as error:
        log = keep_git_error(place, error)
        reason = f"{error}; its error is in {log.relative_to(run.args.work)}"
        record.update(result="no verdict", reason=reason)
    except OSError as error:
        named = Path(error.filename) if error.filename else None
        if named is not None and run.args.work in named.parents:
            named = named.relative_to(run.args.work)
        record.update(result="no verdict", reason=f"the run failed: {type(error).__name__}: {error.strerror}"
                                                  + (f" ({named})" if named is not None else ""))
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError) as error:
        record.update(result="no verdict", reason=f"the run failed: {type(error).__name__}: {error}")
    return None


def applies(run, plant, record):
    """The plant's worktree, once the patch bytes read at the start apply there; otherwise `does not apply` when
    Git refuses them (exit 1), or no verdict when the check itself fails (another exit)."""
    place = run.args.work / "plants" / plant["id"]
    tree = run.tree(place)
    # The patch bytes read with the record at the start are the bytes every step applies.
    patch = place / "plant.patch"
    with open(patch, "xb") as staged:
        staged.write(plant["patch"])
    checked = git(tree, "apply", "--check", "--index", str(patch), check=False)
    if checked.returncode == 1:
        lines = checked.stderr.strip().splitlines()
        record.update(result="does not apply", reason=lines[0] if lines else "git apply --check failed")
        return None
    if checked.returncode != 0:
        raise GitFailed("apply", checked.returncode, checked.stderr)
    return tree


def prove(run, plant, record):
    """Records the proof's exits on the head and on the plant; a pair other than 0 and 1 is `not live`."""
    head, planted = run.live(plant)
    record["proof_exits"] = {"head": head, "plant": planted}
    if (head, planted) != (0, 1):
        record.update(result="not live", reason=f"its proof exits {head} on the head and {planted} on the plant, "
                                                 "where a live plant's proof exits 0 and 1")


def keep_git_error(place, error):
    """Appends a failed Git step's error output to `place/git.err` and returns that path."""
    log = place / "git.err"
    with contextlib.suppress(OSError), open(log, "a") as err:
        err.write(f"git {error.step} exited {error.code}:\n{error.stderr}")
    return log


def judge(run, plant, record, tree):
    """Builds, sweeps and confirms the live plant in its worktree `tree`, setting its result in `record`.

    The checks after the sweep run in the order the header lists the
    results: a catch first, then each cause of no verdict, then the miss.
    Every confirmed suspect's seed is checked on the unpatched head, so the
    record lists each one that fails there, beside a catch too.
    """
    place = run.args.work / "plants" / plant["id"]
    git(tree, "apply", "--index", str(place / "plant.patch"))
    # The head's date and a fixed identity make the planted commit a function of the head and the patch; the
    # environment outranks every configuration scope for both.
    env = dict(os.environ, GIT_AUTHOR_DATE=run.date, GIT_COMMITTER_DATE=run.date, **IDENTITY)
    git(tree, "commit", "--quiet", "--no-verify", "--no-gpg-sign", "--message", f"plant {plant['id']}", env=env)
    record["commit"] = git(tree, "rev-parse", "HEAD").stdout.strip()
    record["tree"] = git(tree, "rev-parse", "HEAD^{tree}").stdout.strip()
    archive, pins = run.archive(place, tree, "the planted tree")
    record["archive"] = pins["build"]
    if not plant["expected"]:
        record.update(result="missed", reason="no expected profile; no sweep ran")
        return
    code, status = run.sweep(plant, archive, place)
    record["counts"] = status.get("counts")
    record["runs"] = {profile: profile_runs(status, profile) for profile in plant["expected"]}
    record["controls"], record["histories"] = status.get("controls"), status.get("histories")
    record["keys"] = {key: status[key] for key in VERDICT_KEYS if key in status}
    listed, complete, replayed, shown = suspects(place / "root", plant["expected"])
    findings, hold = run.confirm(place, archive) if listed else ([], None)
    hidden = {profile: unlisted_replay(status, profile, shown) for profile in {s["profile"] for s in listed}}
    unconfirmed, unchecked, differing, caught = [], [], [], None
    for suspect in listed:
        named = f"{suspect['key']} in run {suspect['run']} of {suspect['profile']}"
        found = finding_of(findings, suspect)
        if found is None:
            unconfirmed.append(suspect)
            continue
        finding, confirmed = found
        # A seed whose replay differs does not determine its run, so it shows nothing about the plant.
        if (suspect["profile"], suspect["run"], suspect["seed"]) in replayed:
            differing.append(f"the sweep's replay of {named} differs, so its seed does not determine the run")
            continue
        # The list may lack a differing replay of this run, so the run shows nothing about the plant either.
        if hidden[suspect["profile"]]:
            differing.append(f"{hidden[suspect['profile']]}, so a differing replay of {named} may be unlisted")
            continue
        # Each seed check fails alone, so a later suspect can still catch and an earlier catch stands.
        try:
            checked, ending = run.seed_on_base(place / "root", suspect, place, confirmed)
        except (NoVerdict, OSError, ValueError) as error:
            unchecked.append(f"the seed check of {named} did not run: {error}")
            continue
        if checked == 0 and caught is None:
            caught = {key: suspect[key] for key in ("profile", "run", "seed", "key")}
            caught.update(finding=finding, head=ending)
        elif checked in (1, 4):
            failed = {key: suspect[key] for key in ("profile", "run", "seed", "key")}
            failed.update(finding=finding, head=ending, reason=f"the seed of {named} does not pass on the "
                                                               f"unpatched head: {ending}")
            record["head_failures"].append(failed)
        elif checked is None:
            unchecked.append(f"the seed check of {named} did not run: {ending}")
        elif checked != 0:
            unchecked.append(f"the seed check of {named} on the unpatched head exited {checked} ({ending})")
    if caught is not None:
        record.update(result="caught", reason=f"{caught['key']} in run {caught['run']} of {caught['profile']}",
                      suspect=caught)
        return
    held = {name: number for name, number in held_suspects(status).items() if number}
    short = [p for p in plant["expected"] if record["runs"][p]["next"] < run.args.runs]
    total = status.get("suspects")
    keyed = bool(record["keys"])
    settings = (status.get("campaign"), status.get("counts"))
    causes = (
        differing,
        [failed["reason"] for failed in record["head_failures"]],
        unchecked,
        [f"the root holds {', '.join(record['keys'])}"] if record["keys"] else [],
        [hold] if hold else [],
        [f"`campaign confirm` made no finding of {s['key']} in run {s['run']} of {s['profile']}" for s in unconfirmed],
        [f"the root holds suspects in {', '.join(f'{p} ({n})' for p, n in sorted(held.items()))}"] if held else [],
        [f"`campaign sweep-status` counts {total!r} suspects at the root"] if not natural(total) or total else [],
        [f"`suspects.jsonl` lists {complete} suspects"] if complete else [],
        [f"the last sweep exited {code} and the root holds no verdict key"] if code == 1 and not keyed else [],
        [f"`campaign sweep-status` names campaign {settings[0]!r} and counts {settings[1]!r}"]
        if settings != (record["campaign"], {}) else [],
        [f"{', '.join(short)} stayed below {run.args.runs} runs after {run.args.rounds} sweeps"] if short else [],
        [f"{p} has no run counted" for p in plant["expected"] if record["runs"][p]["runs"] == 0],
    )
    for reasons in causes:
        if reasons:
            raise NoVerdict(reasons[0])
    reason = f"each expected profile reached {run.args.runs} runs and the root holds no suspect"
    record.update(result="missed", reason=reason)


def score(head, records, settings):
    results = collections.Counter(record["result"] for record in records)
    counted = results["caught"] + results["missed"]
    return {
        "commit": head,
        "sentence": f"{results['caught']} of {counted} plants at commit {head}",
        "results": dict(results),
        "not_live": [record["id"] for record in records if record["result"] == "not live"],
        "settings": settings,
        "plants": records,
    }


def exit_code(records):
    if any(record["result"] == "missed" and record.get("miss_cause") is None for record in records):
        return 1
    if any(record["result"] in ("no verdict", "does not apply", "not live") for record in records):
        return 3
    return 0


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError(f"{value} is not a positive integer")
    return number


def floor(value):
    number = int(value)
    if number < FLOOR:
        raise argparse.ArgumentTypeError(f"{value} is below the floor of {FLOOR} runs a profile")
    return number


def parser():
    options = argparse.ArgumentParser(
        prog="plant-runner.py", description="Run each stored plant through a sweep.", allow_abbrev=False
    )
    options.add_argument("--work", type=Path, help="a new work directory outside the checkout, on xfs or journaled "
                                                   "ext4, under ancestors only you or root can write "
                                                   "(default: one under $TMPDIR, which must then be such a "
                                                   "directory)")
    options.add_argument("--campaign", default="campaign", help="the campaign binary, on PATH or a path")
    options.add_argument("--workers", type=positive, default=28)
    options.add_argument("--runs", type=floor, default=FLOOR, help=f"the floor of runs a profile, at least {FLOOR}")
    options.add_argument("--for", dest="seconds", type=positive, default=60, help="seconds a sweep")
    options.add_argument("--rounds", type=positive, default=10, help="sweeps a plant at most")
    options.add_argument("--plant", action="append", default=[],
                         help="run this plant only, and write a score over the selected plants; repeatable")
    return options


def work_directory(args, top):
    """Creates the run's work directory, outside the checkout and under ancestors only this user or root can
    write, so no other user can configure the Cargo builds of its worktrees."""
    chosen = Path(os.path.abspath(args.work)) if args.work is not None else None
    try:
        parent = (chosen.parent if chosen is not None else Path(tempfile.gettempdir())).resolve()
    except (OSError, RuntimeError) as error:
        raise Rejected(f"the work directory's parent cannot be resolved: {error}") from error
    place = parent / chosen.name if chosen is not None else parent
    if place == top or top in place.parents:
        raise Rejected(f"the work directory {place} lies inside the checkout")
    existing = next((path for path in (parent, *parent.parents) if path.exists()), parent)
    foreign = foreign_toolchain_paths(existing)
    if foreign:
        way = ("pass --work DIR or set TMPDIR, naming a directory only you control on xfs or journaled ext4"
               if chosen is None else "choose a work directory under a directory only you control")
        raise Rejected(f"another user owns or can write {', '.join(foreign)}, and so can configure Cargo in the "
                       f"run's worktrees; {way}")
    try:
        if chosen is None:
            return Path(tempfile.mkdtemp(prefix="plant-runner-", dir=parent))
        # Each missing ancestor is made 0700 whatever the umask, and the work directory itself must be new.
        make_private(parent)
        place.mkdir(mode=0o700)
        return place
    except OSError as error:
        raise Rejected(f"the work directory: {error}") from error


def digest_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as binary:
        for block in iter(lambda: binary.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def prepare(args):
    """The checkout's top, its head, the plants, the lockfile and the score path; creates the work directory last."""
    overrides = [name for name in OVERRIDES if name in os.environ]
    if overrides:
        raise Rejected(f"{', '.join(overrides)} would point the run's Git commands at another repository or index; "
                       "unset them")
    found = git(Path.cwd(), "rev-parse", "--show-toplevel", check=False)
    if found.returncode != 0:
        raise Rejected("the invoking directory is outside a Git checkout")
    top = Path(found.stdout.strip()).resolve()
    head = git(top, "rev-parse", "--verify", "HEAD^{commit}", check=False)
    if head.returncode != 0:
        raise Rejected("the checkout names no HEAD commit")
    plants = load_plants(top, head.stdout.strip(), args.plant)
    try:
        if (top / "Cargo.lock").is_symlink() or not (top / "Cargo.lock").is_file():
            raise OSError(0, "no regular file")
        lock = (top / "Cargo.lock").read_bytes()
    except OSError as error:
        raise Rejected(f"the checkout holds no readable Cargo.lock ({error.strerror}); build it once to resolve "
                       "the dependencies every archive of the run shares") from error
    # The archive build runs in a worktree, so the binary is resolved here, against `PATH` or the invoking
    # directory. Its digest is of the file read now; replacing the binary during a run is unsupported.
    found = shutil.which(args.campaign)
    if found is None:
        raise Rejected(f"no campaign binary at {args.campaign}")
    args.campaign = str(Path(found).resolve())
    try:
        args.campaign_sha256 = digest_of(args.campaign)
    except OSError as error:
        raise Rejected(f"the campaign binary cannot be read: {error}") from error
    args.work = work_directory(args, top)
    return top, head.stdout.strip(), plants, lock, top / STORE / SCORE


def publish(target, written):
    """Replaces `target` with `written` through a staging file this call creates under a fresh name beside it."""
    descriptor, staged = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        umask = os.umask(0)
        os.umask(umask)
        os.fchmod(descriptor, 0o666 & ~umask)
        with os.fdopen(descriptor, "w") as staging:
            staging.write(json.dumps(written, indent=2) + "\n")
        os.replace(staged, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(staged)
        raise


def main(argv=None):
    args = parser().parse_args(argv)
    # Every Git command of the run, and of the commands it starts, reads the objects their names hash to, so
    # the tree the run builds is the tree of the commit the score names whatever `refs/replace` holds.
    os.environ["GIT_NO_REPLACE_OBJECTS"] = "1"
    try:
        top, head, plants, lock, target = prepare(args)
    except Rejected as error:
        print(f"plant-runner rejected: {error}", file=sys.stderr)
        return 2
    print(f"work: {args.work}", file=sys.stderr)
    run = Run(args, top, head, lock)
    records = []
    install()
    remained = []
    try:
        records = run_store(run, plants)
    finally:
        # `deferred()` holds a signal's exit until the cleanup has named every worktree it left or could not list.
        with deferred():
            remained = run.remove_trees()
            for tree, unlisted in remained:
                if unlisted is None:
                    print(f"plant-runner left the worktree {tree}; remove it with `git worktree remove --force "
                          "--force`", file=sys.stderr)
                else:
                    print(f"plant-runner cannot tell whether the worktree {tree} remains: `git worktree list` exited "
                          f"{unlisted}; remove it with `git worktree remove --force --force` if it does",
                          file=sys.stderr)
            target_dir = args.work / "proof" / "target"
            shutil.rmtree(target_dir, ignore_errors=True)
            if target_dir.exists():
                print(f"plant-runner left the proof's target directory {target_dir}", file=sys.stderr)
    if remained:
        return 4
    settings = {
        "workers": args.workers, "runs": args.runs, "seconds": args.seconds, "rounds": args.rounds,
        "base_archive": run.base[1]["build"] if run.base else None, "campaign_sha256": args.campaign_sha256,
        "plants": args.plant or None,
    }
    written = score(head, records, settings)
    # Signal deferral lasts through run completion. The handler records signals received after the
    # pending-signal check and preserves the run's exit status.
    Signals.deferring = True
    if Signals.pending is not None:
        raise SystemExit(128 + Signals.pending)
    try:
        publish(target, written)
    except OSError as error:
        print(f"plant-runner wrote no score: {error}", file=sys.stderr)
        for record in records:
            print(f"{record['id']}: {record['result']} ({record['reason']})", file=sys.stderr)
        return 4
    print(written["sentence"])
    for record in records:
        print(f"{record['id']}: {record['result']} ({record['reason']})")
    return exit_code(records)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # noqa: BLE001
        # A failure outside a plant exits 4, apart from exit 1, which names a miss without its cause.
        traceback.print_exc()
        sys.exit(4)
