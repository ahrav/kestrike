#!/usr/bin/env python3
"""Run one chaos scenario as one campaign sweep, keep its evidence and judge it.

    python3 chaos/harness/run_scenario.py <scenario-id> <run-id> [--control DEFECT] \
        --archive DIR --campaign PATH --roots DIR [--cgroup-root DIR]
    python3 chaos/harness/run_scenario.py <scenario-id> <run-id> [--control DEFECT] --dry-run

The scenario row of chaos/ledger.json gives the profile set (its load.reference up to the first
`;`, a comma-separated list passed whole to --profiles), the workers, the batch, --for and the
deadline. Each parameter of the row's load object named count_<key> is passed as
--set <key>=<value>, in the row's order, and recorded as the run's counts; a row with none sweeps
at the default counts, and a load parameter that is neither a count nor one of reference,
multiple, workers, batch_s and for_s is refused. The harness only drives `campaign`: it copies the
binary into its own directory and runs every command from that copy, reads the worker's listing,
sweeps one new root, <roots>/<run-id>, under the run id as campaign name, then runs sweep-status,
confirm and findings on it. Each command runs in the harness's own new directory
<roots>/<run-id>.harness, which keeps the copy of the binary, the worker's listing artifacts and
each command's and each judge's standard output and error. A control run (--control) adds its
defect to the swept profiles when the worker lists the defect as a profile; otherwise the defect is
the run's label alone, as for a control that is the same sweep under another campaign binary.

The run record chaos/runs/<run-id>/run.json is on file with "complete": false before campaign
starts. It records the archive's build digest, the campaign binary's SHA-256 before the first
command, and after the last command the digests of the copy that ran and of the binary at its
path, the campaign name, the swept profiles with their listing lines, the counts, each profile's
run range, each command's exit, the dispatch state confirm reported, whether the deadline fired or
a signal stopped the run, and the restoration facts. "complete" turns true only when campaign
sweep returned by itself and the evidence its exit calls for was written; a refusal of
sweep-status after a sweep exit 2, 3 or 4 stands in the record. After a sweep exit 0 or 1 the
evidence is the copies of sweep-status.json, suspects.jsonl (empty when the root lists none) and
findings.json, the harness's history.jsonl and run.json; a run that stopped before sweep-status, or
whose sweep exited 3 or 4, holds run.json alone, and a run whose sweep exited with another code,
such as the 2 of a refusal, holds run.json and sweep-refusal.txt, the end of the sweep's standard
error. The copies and history.jsonl hold no wall-clock field. Then the harness runs the judge of
the scenario row and of each invariant it lists. Each writes its receipt into
chaos/receipts/.<run-id>.staging/, and the harness moves a receipt it accepts to
chaos/receipts/<run-id>/<row>.json without replacing any entry there.

A run id whose directory exists under chaos/runs/ or chaos/receipts/ is refused, in the dry-run
form too, so no run writes over an earlier one. --dry-run checks the ledger, the scenario and the
run id and stops: nothing is created and nothing runs. A full run also refuses an existing entry at
<roots>/<run-id> or <roots>/<run-id>.harness, a dangling link included, which the dry-run form does
not check. The deadline_s of the row bounds the campaign commands together: a command that passes
it, and one running when SIGTERM, SIGINT or SIGHUP reaches the harness, gets SIGTERM, and
STOP_WAIT_S later SIGKILL, as does its process group; the run then ends incomplete and is judged.
A signal the harness's caller set to be ignored stays ignored.

The cgroup root (--cgroup-root, or CAMPAIGN_CGROUP_ROOT) is the run's own: the harness and its
caller run outside it, and no other command uses it while the run lasts. It is resolved once, and
refused when the name given is a link, when it is no directory of the cgroup v2 file system, when it
holds a child group other than sweep and controller, the two campaign makes, and when a group under
it other than a worker group an earlier sweep left lists a process. After a sweep that accepted the
root (any exit but 2 and 3), under the lock campaign sweep holds on <cgroup root>/sweep while it
runs, the harness counts the processes left in the worker groups this run's sweep made there, then
writes cgroup.kill in each, deepest first. It writes no cgroup.kill of sweep itself, of its
controller or of a nested sweep, and it opens each group relative to the one above it. After
campaign confirm, whatever its end, the harness counts the processes in the groups confirm made
directly under the cgroup root, one for each attempt, adds them to that count and writes cgroup.kill
in each, deepest first. After the last command it adds the processes in every other group under the
cgroup root, the two controller groups, a nested sweep and an earlier sweep's worker groups
included, and writes no cgroup.kill there. So left_a_process counts every cgroup under the root, and
the harness kills only in the groups this run made. Each campaign command runs with the variables
ENVIRONMENT names and CAMPAIGN_CGROUP_ROOT, and each judge within JUDGE_WAIT_S. Diagnostics are
written after the run record and the receipts, so a caller that leaves the harness's output unread
holds up no cleanup, record or receipt.

Exit status: 2 for a refused argument, run id or ledger, a request for --help, and a run record
the harness could not finish or judge; 0 for a dry run the harness accepted. A run's exit is its
result: 3 incomplete when any judge left no receipt the harness accepts; otherwise 1 broken when
any invariant judge reports broken, and else the largest judge code (3 incomplete, 2 invalid,
0 held).
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import math
import os
import platform
import re
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import IO, Any, NoReturn

CHAOS = Path(__file__).resolve().parents[1]
ROOT = CHAOS.parent
ID = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")
JUDGE_SCRIPT = re.compile(r"chaos/judges/[a-z0-9_]+/[a-z0-9_]+\.py")
COUNT_KEY = re.compile(r"[a-z0-9_]+")
STOP_WAIT_S = 120
COUNT_PREFIX = "count_"
LOAD_KEYS = frozenset({"reference", "multiple", "workers", "batch_s", "for_s"})
POLL_S = 0.5
JUDGE_WAIT_S = 600
STOP_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
# The harness passes these variables of its own environment, and CAMPAIGN_CGROUP_ROOT, to each campaign command.
ENVIRONMENT = ("HOME", "LANG", "LC_ALL", "LOGNAME", "PATH", "TMPDIR", "USER", "XDG_RUNTIME_DIR")
OUTCOMES = {0: "held", 1: "broken", 2: "invalid", 3: "incomplete"}
WALL_CLOCK_KEYS = frozenset({"elapsed_s", "runs_per_s", "operations_per_s", "busy_us"})
TAIL_BYTES = 8000
# Each bound caps the bytes the harness reads of one record: the ledger, a receipt, sweep.json
# (campaign's checkpoint bound), one suspects.jsonl line with its line feed (campaign's line bound)
# and one command's JSON output.
LEDGER_BYTES = 1 << 24
RECEIPT_BYTES = 1 << 24
CHECKPOINT_BYTES = 1 << 24
LINE_BYTES = 1 << 24
OUTPUT_BYTES = 1 << 28
RESERVED_GROUPS = ("controller", "sweep")


def say(message: str, stream: int = 2) -> None:
    """One line on standard error (or `stream`), written by one system call; a closed stream loses the line and nothing else."""
    with contextlib.suppress(OSError):
        os.write(stream, f"{message}\n".encode("utf-8", "backslashreplace"))


def refuse(message: str) -> NoReturn:
    say(f"run_scenario: {message}")
    raise SystemExit(2)


def row_digest(row: dict) -> str:
    """Digest of a ledger row without its status, as the judges and the validator compute it."""
    kept = {key: value for key, value in row.items() if key != "status"}
    return hashlib.sha256(json.dumps(kept, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class RunError(Exception):
    """A record the run needs is unreadable; the run ends incomplete and is judged."""


def open_regular(path: str | Path, dir_fd: int | None = None) -> IO[bytes] | None:
    """The file at `path` opened for reading, or None when nothing is there.

    The open follows no link at the name and does not block; a link or any other file than a
    regular one raises RunError.
    """
    try:
        handle = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise RunError(f"cannot read {path}: {error}") from None
    file = os.fdopen(handle, "rb")
    if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
        file.close()
        raise RunError(f"{path} is no regular file")
    return file


def read_bounded(path: Path, bound: int) -> bytes:
    """The bytes of a regular file of at most `bound` bytes; an absent, linked, special, larger or unreadable file raises RunError."""
    file = open_regular(path)
    if file is None:
        raise RunError(f"cannot read {path}: it does not exist")
    try:
        with file:
            data = file.read(bound + 1)
    except OSError as error:
        raise RunError(f"cannot read {path}: {error}") from None
    if len(data) > bound:
        raise RunError(f"{path} holds more than {bound} bytes")
    return data


def unique(pairs: list[tuple[str, Any]]) -> dict:
    """A JSON object's members as a dict; a name that stands twice in one object raises ValueError."""
    value: dict = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"the member {key[:80]!r} stands twice in one object")
        value[key] = item
    return value


def parse(data: bytes) -> object:
    """One JSON document from UTF-8 bytes, each object's member names once; other bytes raise ValueError."""
    return json.loads(data.decode("utf-8"), object_pairs_hook=unique)


def read_json(path: Path, bound: int) -> object:
    """A JSON document a campaign command printed or the root holds, read under `bound`; an unreadable one raises RunError."""
    try:
        return parse(read_bounded(path, bound))
    except (ValueError, RecursionError) as error:
        raise RunError(f"cannot read {path}: {error.__class__.__name__}: {str(error)[:200]}") from None


def sha256(path: Path) -> str:
    """The SHA-256 of a regular file's bytes; an absent, linked, special or unreadable file raises RunError."""
    digest = hashlib.sha256()
    try:
        file = open_regular(path)
        if file is None:
            raise RunError(f"cannot read {path}: it does not exist")
        with file:
            for block in iter(lambda: file.read(1 << 20), b""):
                digest.update(block)
    except OSError as error:
        raise RunError(f"cannot read {path}: {error}") from None
    return digest.hexdigest()


def profiles_of(row: dict) -> list[str]:
    """The scenario's ordered sweep list: load.reference up to its first `;`, a comma-separated list of profile names."""
    reference = row["load"]["reference"]
    names = [name.strip() for name in reference.split(";", 1)[0].split(",")]
    if not all(ID.fullmatch(name) for name in names):
        raise ValueError(f"load.reference names no profile set before its first `;`: {reference[:80]!r}")
    return names


def counts_of(row: dict) -> dict[str, int]:
    """The counts a scenario row sets: each parameter of its load object named count_<key>, in the row's order.

    The sweep takes each as --set <key>=<value>, and a row with none sweeps at the default counts. A
    load parameter that is neither one of LOAD_KEYS nor a count, a near miss such as
    counts_restarts included, is one no sweep reads, so it raises ValueError.
    """
    counts = {}
    for name, value in row["load"].items():
        if name in LOAD_KEYS:
            continue
        key = name[len(COUNT_PREFIX):] if name.startswith(COUNT_PREFIX) else ""
        if not COUNT_KEY.fullmatch(key) or type(value) is not int or value < 0:
            raise ValueError(f"load.{name} is {value!r}: a load parameter is one of {', '.join(sorted(LOAD_KEYS))} or "
                             "count_<key> with a whole number of at least 0, under a key of lowercase letters, digits "
                             "and underscores")
        counts[key] = value
    return counts


def swept(profiles: list[str], defect: str, listing: dict[str, dict]) -> list[str]:
    """The profiles passed to --profiles: the row's set, and a control's defect when the worker lists it as a profile."""
    if defect and defect in listing and defect not in profiles:
        return [*profiles, defect]
    return list(profiles)


def parse_listing(text: str) -> dict[str, dict]:
    """Each profile line of the worker's capability listing: its class, whether it has a cluster declaration, its fails line.

    A line `fails: <profile> <declaration>` gives the profile's fails text, the words after the name.
    """
    listing: dict[str, dict] = {}
    for line in text.splitlines():
        word, _, rest = line.partition(": ")
        fields = rest.split()
        if word == "profile" and fields:
            classes = [field[len("class="):] for field in fields if field.startswith("class=")]
            listing[fields[0]] = {"class": classes[0] if classes else "", "cluster": False, "fails": None}
    for line in text.splitlines():
        word, _, rest = line.partition(": ")
        name, _, tail = rest.partition(" ")
        if name in listing and word == "cluster":
            listing[name]["cluster"] = True
        elif name in listing and word == "fails":
            listing[name]["fails"] = tail
    return listing


def without_wall_clock(value: object) -> object:
    """The value with every key of WALL_CLOCK_KEYS removed at any depth."""
    if isinstance(value, dict):
        return {key: without_wall_clock(item) for key, item in value.items() if key not in WALL_CLOCK_KEYS}
    if isinstance(value, list):
        return [without_wall_clock(item) for item in value]
    return value


def create_new(path: str | Path, permissions: int, dir_fd: int | None = None) -> int:
    """A descriptor open for writing on a new file; an existing entry at the path, a link or a FIFO included, raises OSError."""
    return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, permissions, dir_fd=dir_fd)


def write_new(path: Path, text: str) -> None:
    """Write an evidence file as a new regular file; an existing entry at the path, a link included, raises OSError."""
    with os.fdopen(create_new(path, 0o644), "w", encoding="utf-8") as file:
        file.write(text)


def replace_file(path: Path, text: str) -> None:
    """Write run.json, which the run writes more than once: each version goes whole to a new file beside it and is renamed over it.

    A stop during a write leaves the previous version.
    """
    beside = path.with_name(f".{path.name}.new")
    with contextlib.suppress(FileNotFoundError):
        beside.unlink()
    write_new(beside, text)
    os.replace(beside, path)


def create_log(path: Path) -> IO[bytes]:
    """A new file for a command's output; an existing entry at the path, a link or a FIFO included, raises OSError."""
    return os.fdopen(create_new(path, 0o600), "wb")


def text_of(path: Path) -> str:
    """The last 2000 characters of a capture file, read from its last TAIL_BYTES bytes through a checked open."""
    try:
        file = open_regular(path)
        if file is None:
            return "unreadable: no capture file"
        with file:
            file.seek(max(os.fstat(file.fileno()).st_size - TAIL_BYTES, 0))
            return file.read(TAIL_BYTES).decode("utf-8", errors="replace")[-2000:]
    except (OSError, RunError) as error:
        return f"unreadable: {error}"


class Stopper:
    """The one way a run stops early: the deadline, SIGTERM, SIGINT or SIGHUP.

    Each sends SIGTERM to the campaign command running. A command still running STOP_WAIT_S after
    that gets SIGKILL, as does its process group. The deadline and a stop are checked before each
    command's logs are made and again just before it starts, and the deadline when its end is
    seen, so a command that ends past it ends the run late. The stop's cause is reported by the
    caller once the run is recorded.
    """

    def __init__(self, deadline_s: float) -> None:
        self.deadline_s = deadline_s
        self.deadline: float | None = None
        self.kill_at: float | None = None
        self.child: subprocess.Popen | None = None
        self.signal: int | None = None
        self.deadline_fired = False

    def on_signal(self, number: int, frame: object) -> None:
        self.signal = number
        self.terminate()

    def terminate(self) -> None:
        """Send SIGTERM to the running command, once, and set when SIGKILL follows."""
        if self.kill_at is None:
            self.kill_at = time.monotonic() + STOP_WAIT_S
        if self.child is not None and self.child.poll() is None:
            self.child.send_signal(signal.SIGTERM)

    @staticmethod
    def kill(child: subprocess.Popen) -> None:
        """End the command and its process group."""
        with contextlib.suppress(OSError):
            os.killpg(child.pid, signal.SIGKILL)
        with contextlib.suppress(OSError):
            child.kill()

    @property
    def stopped(self) -> bool:
        return self.signal is not None or self.deadline_fired

    def late(self) -> bool:
        """Whether the deadline has passed; the first sight of it fires the deadline."""
        if not self.stopped and self.deadline is not None and time.monotonic() >= self.deadline:
            self.deadline_fired = True
        return self.deadline_fired

    def reason(self) -> str | None:
        """Why the run stopped, or None."""
        if self.signal is not None:
            return f"run_scenario: stopped by signal {self.signal}"
        if self.deadline_fired:
            return f"run_scenario: the run passed its deadline of {self.deadline_s} s"
        return None

    def run(self, argv: list[str], env: dict[str, str], cwd: Path, out: Path, err: Path) -> int | None:
        """Run one campaign command to its end, or stop it. Returns its exit, negative for a signal, or None when the run had stopped.

        Whatever ends this wait, an exception included, the command does not outlive it.
        """
        self.late()
        if self.stopped:
            return None
        if self.deadline is None:
            self.deadline = time.monotonic() + self.deadline_s
        try:
            with create_log(out) as stdout, create_log(err) as stderr:
                self.late()
                if self.stopped:
                    return None
                child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, env=env, cwd=cwd,
                                         start_new_session=True)
        except OSError as error:
            raise RunError(f"cannot start {argv[1]}: {error}") from None
        self.child = child
        try:
            if self.signal is not None:
                self.terminate()
            while child.poll() is None:
                now = time.monotonic()
                if self.kill_at is None and self.late():
                    self.terminate()
                elif self.kill_at is not None and now >= self.kill_at:
                    self.kill(child)
                until = self.kill_at if self.kill_at is not None else self.deadline
                with contextlib.suppress(subprocess.TimeoutExpired):
                    child.wait(timeout=min(POLL_S, max(until - now, 0.01)))
        except BaseException:
            self.kill(child)
            child.wait()
            raise
        finally:
            self.child = None
        self.late()
        return child.returncode


def on_cgroup2(handle: int) -> bool:
    """Whether an open directory is on a cgroup v2 mount: its device is the device of a cgroup2 line of mountinfo."""
    device = os.fstat(handle).st_dev
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as mounts:
            lines = mounts.read().splitlines()
    except OSError:
        return False
    for line in lines:
        fields, _, tail = line.partition(" - ")
        words = fields.split()
        if len(words) > 2 and tail.split(" ", 1)[0] == "cgroup2" and words[2] == f"{os.major(device)}:{os.minor(device)}":
            return True
    return False


def open_cgroup_root(named: str) -> tuple[int, Path]:
    """The delegated cgroup root, opened once, and its resolved path; refused unless it is a directory of cgroup v2 of its own.

    The name given is no link, the directory is on a cgroup v2 mount and holds cgroup.procs, its
    only child groups are the ones campaign makes, sweep and controller, and no group under it lists
    a process, except a worker group an earlier sweep left, which this run's sweep kills and removes.
    """
    if not named or os.path.islink(named.rstrip("/") or "/"):
        refuse("--cgroup-root or CAMPAIGN_CGROUP_ROOT names the delegated cgroup root, and no link to it")
    path = Path(os.path.realpath(named))
    try:
        handle = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as error:
        refuse(f"cannot open the cgroup root {path}: {error}")
    try:
        if not on_cgroup2(handle):
            refuse(f"{path} is no directory of the cgroup v2 file system: --cgroup-root names a delegated cgroup")
        procs = open_regular("cgroup.procs", dir_fd=handle)
        if procs is None:
            refuse(f"{path} holds no cgroup.procs: --cgroup-root names a delegated cgroup")
        procs.close()
        others = sorted(entry.name for entry in os.scandir(handle)
                        if entry.is_dir(follow_symlinks=False) and entry.name not in RESERVED_GROUPS)
    except (OSError, RunError) as error:
        refuse(f"cannot read the cgroup root {path}: {error}")
    if others:
        refuse(f"the cgroup root {path} holds the group {others[0]!r}, which no sweep of this harness made; a confirm "
               "of a later run refuses a group it has no record of")
    try:
        held = elsewhere(handle, set(pens_of(handle).values()))
    except (OSError, RunError) as error:
        refuse(f"cannot read the groups under the cgroup root {path}: {error}")
    if held:
        refuse(f"a group under the cgroup root {path} holds a process before the run: {held} listed in the "
               "cgroup.procs files under it, outside the worker groups of an earlier sweep; a run takes a root of its own")
    return handle, path


def pens_of(handle: int) -> dict[str, int]:
    """The worker groups under <cgroup root>/sweep by name, with their inode: every child but controller and a nested sweep."""
    try:
        base = os.open("sweep", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=handle)
    except FileNotFoundError:
        return {}
    try:
        return {entry.name: entry.inode() for entry in os.scandir(base)
                if entry.is_dir(follow_symlinks=False) and entry.name not in RESERVED_GROUPS}
    finally:
        os.close(base)


def groups_under(parent: int, name: str, device: int, found: list[tuple[int, str, int]], errors: list[str]) -> None:
    """Open the group `name` relative to `parent` and every group under it, deepest first into `found`, each with
    its name and its parent's descriptor.

    Each is opened without following a link and must stay on the cgroup mount. A group that went
    away is passed over; any other failure is noted in `errors` and the walk goes on.
    """
    try:
        handle = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    except FileNotFoundError:
        return
    except OSError as error:
        errors.append(f"cannot open the group {name}: {error}")
        return
    if os.fstat(handle).st_dev != device:
        os.close(handle)
        errors.append(f"the group {name} lies on another mount than the cgroup root")
        return
    try:
        children = [entry.name for entry in os.scandir(handle) if entry.is_dir(follow_symlinks=False)]
    except OSError as error:
        errors.append(f"cannot list the group {name}: {error}")
        children = []
    for child in children:
        groups_under(handle, child, device, found, errors)
    found.append((handle, name, parent))


def processes_in(group: int, name: str, parent: int) -> int:
    """How many processes a cgroup lists. A group without cgroup.procs that still stands under its parent raises RunError."""
    try:
        file = open_regular("cgroup.procs", dir_fd=group)
    except RunError as error:
        raise RunError(f"cannot read the cgroup.procs of {name}: {error}") from None
    if file is None:
        try:
            standing = os.stat(name, dir_fd=parent, follow_symlinks=False).st_ino == os.fstat(group).st_ino
        except FileNotFoundError:
            standing = False
        except OSError as error:
            raise RunError(f"cannot look up the group {name}: {error}") from None
        if standing:
            raise RunError(f"the group {name} stands and holds no cgroup.procs")
        return 0
    try:
        with file:
            return len(file.read(1 << 24).split())
    except OSError as error:
        raise RunError(f"cannot read the cgroup.procs of {name}: {error}") from None


def kill_group(group: int) -> None:
    """Write 1 to the group's cgroup.kill: an existing regular file, opened relative to the group without following a link
    or blocking. A group without one is passed over."""
    with contextlib.suppress(OSError):
        handle = os.open("cgroup.kill", os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=group)
        try:
            if stat.S_ISREG(os.fstat(handle).st_mode):
                os.write(handle, b"1")
        finally:
            os.close(handle)


def restore(root: int, before: dict[str, int], counted: set[int]) -> tuple[int | None, str | None]:
    """Count the processes the worker groups this run's sweep made under <cgroup root>/sweep hold, then kill them.

    The groups are the children of sweep other than controller and a nested sweep that were not
    there, with the same inode, before the sweep started, and the groups under them. The count and
    the kill run only while the harness holds the lock campaign sweep and fuzz runs take on sweep
    for their lifetime; another holder gives (None, its cause). Every group found is killed, its
    inode joins `counted`, and a count that cannot be made raises RunError after the kill.
    """
    try:
        base = os.open("sweep", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
    except FileNotFoundError:
        return 0, None
    except OSError as error:
        raise RunError(f"cannot open the sweep group: {error}") from None
    groups: list[tuple[int, str, int]] = []
    try:
        try:
            fcntl.flock(base, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return None, "another command holds the lock on the sweep group, so the harness left its groups alone"
        errors: list[str] = []
        device = os.fstat(base).st_dev
        try:
            owned = [entry.name for entry in os.scandir(base) if entry.is_dir(follow_symlinks=False)
                     and entry.name not in RESERVED_GROUPS and before.get(entry.name) != entry.inode()]
        except OSError as error:
            raise RunError(f"cannot list the sweep group: {error}") from None
        for name in sorted(owned):
            groups_under(base, name, device, groups, errors)
        counted.update(os.fstat(handle).st_ino for handle, _, _ in groups)
        left = 0
        try:
            for handle, name, parent in groups:
                left += processes_in(handle, name, parent)
        finally:
            for handle, _, _ in groups:
                kill_group(handle)
        if errors:
            raise RunError(errors[0])
        return left, None
    finally:
        for handle, _, _ in groups:
            os.close(handle)
        os.close(base)


def attempts_left(root: int, counted: set[int]) -> int:
    """Count the processes in the groups a campaign command of this run made directly under the cgroup root, then kill them.

    `open_cgroup_root` admits a root whose only child groups are sweep and controller, so every
    other child group found after a command is one that command made, as campaign confirm makes one
    for each attempt it runs. Each such group and the groups under it are opened relative to the
    group above, counted, and then given cgroup.kill, deepest first; sweep and controller are left
    as they are. The inode of each group joins `counted`. A count that cannot be made raises
    RunError after the kill.
    """
    groups: list[tuple[int, str, int]] = []
    errors: list[str] = []
    try:
        try:
            made = sorted(entry.name for entry in os.scandir(root)
                          if entry.is_dir(follow_symlinks=False) and entry.name not in RESERVED_GROUPS)
        except OSError as error:
            raise RunError(f"cannot list the cgroup root: {error}") from None
        device = os.fstat(root).st_dev
        for name in made:
            groups_under(root, name, device, groups, errors)
        counted.update(os.fstat(handle).st_ino for handle, _, _ in groups)
        left = 0
        try:
            for handle, name, parent in groups:
                left += processes_in(handle, name, parent)
        finally:
            for handle, _, _ in groups:
                kill_group(handle)
        if errors:
            raise RunError(errors[0])
        return left
    finally:
        for handle, _, _ in groups:
            os.close(handle)


def elsewhere(root: int, counted: set[int]) -> int:
    """Count the processes in every group under the cgroup root whose inode `counted` lacks, and kill none.

    `counted` names the groups this run made, which `restore` and `attempts_left` counted before
    their kill, so the two counts together cover every cgroup under the root once: the remainder is
    controller, sweep/controller, a nested sweep, a worker group an earlier sweep left, and the
    groups under them. The root itself must still hold cgroup.procs. A root that is gone and a
    count that cannot be made raise RunError.
    """
    present = open_regular("cgroup.procs", dir_fd=root)
    if present is None:
        raise RunError("the cgroup root holds no cgroup.procs at the run's end")
    present.close()
    groups: list[tuple[int, str, int]] = []
    errors: list[str] = []
    try:
        try:
            names = sorted(entry.name for entry in os.scandir(root) if entry.is_dir(follow_symlinks=False))
        except OSError as error:
            raise RunError(f"cannot list the cgroup root: {error}") from None
        device = os.fstat(root).st_dev
        for name in names:
            groups_under(root, name, device, groups, errors)
        if errors:
            raise RunError(errors[0])
        return sum(processes_in(handle, name, parent) for handle, name, parent in groups
                   if os.fstat(handle).st_ino not in counted)
    finally:
        for handle, _, _ in groups:
            os.close(handle)


def directory_digests(folders: list[Path]) -> dict[str, str]:
    """The SHA-256 of every file of each directory, by its path from the repository root; a link or a subdirectory raises RunError."""
    digests = {}
    for folder in folders:
        for path in sorted(folder.iterdir()):
            if path.is_symlink() or not path.is_file():
                raise RunError(f"{path} is no regular file; the harness and the judges run beside regular files only")
            digests[path.relative_to(ROOT).as_posix()] = sha256(path)
    return digests


def evidence_digests(folder: Path) -> dict[str, str | None]:
    """The evidence map a receipt of the run names: each regular file's SHA-256 and each link's None, as the validator lists them."""
    found: dict[str, str | None] = {}
    for entry in sorted(os.scandir(folder), key=lambda entry: entry.name):
        if entry.is_symlink():
            found[entry.name] = None
        elif entry.is_file(follow_symlinks=False):
            found[entry.name] = sha256(folder / entry.name)
    return found


def judge_script(name: str, command: object) -> Path:
    """The judge file of a ledger row's judge command, which is `<chaos/judges/<family>/<file>.py> <row id>`; any other raises ValueError."""
    words = command.split() if isinstance(command, str) else []
    if len(words) != 2 or words[1] != name or not JUDGE_SCRIPT.fullmatch(words[0]):
        raise ValueError(f"the judge of {name} is {command!r}; a judge is chaos/judges/<family>/<file>.py and its row id")
    script = ROOT / words[0]
    for path in (CHAOS / "judges", script.parent, script):
        if path.is_symlink() or not (path.is_dir() if path != script else path.is_file()):
            raise ValueError(f"{path.relative_to(ROOT).as_posix()} is no regular file or directory of the judges")
    return script


def judge(name: str, script: Path, evidence: Path, staged: Path, final: Path, capture: Path,
          expected: dict) -> tuple[int | None, list[tuple[int, str]]]:
    """Run one judge in isolated mode with no bytecode, so no path or startup file from the environment reaches it.

    The judge writes its receipt to `staged`, and its standard output and error go to capture files
    beside `capture`. Returns the judge's exit, or None when the judge decided nothing, with the lines
    to relay. A judge decided nothing when it ended outside the four contract codes (by a signal or
    past JUDGE_WAIT_S, for example), left no receipt, or left one that the binding `expected` does
    not describe (`receipt_accepted`), and when its receipt could not be placed at `final` as a new
    file. The staged receipt is removed whatever the outcome, and an entry already at `final` stays as
    it is. A core judge that could not read the evidence writes a receipt without the run's identity,
    which decides nothing either.
    """
    argv = [sys.executable, "-I", "-B", script.relative_to(ROOT).as_posix(), name, "--evidence", str(evidence),
            "--receipt", str(staged)]
    notes: list[tuple[int, str]] = []
    code: int | None = None
    outputs = (capture.with_name(f"{capture.name}.err"), capture.with_name(f"{capture.name}.out"))
    try:
        with create_log(outputs[0]) as stderr, create_log(outputs[1]) as stdout:
            code = subprocess.run(argv, cwd=ROOT, check=False, timeout=JUDGE_WAIT_S, stdout=stdout, stderr=stderr,
                                  stdin=subprocess.DEVNULL).returncode
    except subprocess.TimeoutExpired:
        notes.append((2, f"run_scenario: the judge of {name} ran past JUDGE_WAIT_S, {JUDGE_WAIT_S} s, and decided nothing"))
    except (OSError, subprocess.SubprocessError) as error:
        notes.append((2, f"run_scenario: cannot run the judge of {name}: {error}"))
    relayed = [(2, text_of(outputs[0]).rstrip("\n")), (1, text_of(outputs[1]).rstrip("\n"))]
    notes = [(stream, text) for stream, text in relayed if text and text != "unreadable: no capture file"] + notes
    try:
        data = read_bounded(staged, RECEIPT_BYTES) if code is not None and code in OUTCOMES else None
        if code is not None and data is not None and receipt_accepted(data, expected, code):
            with os.fdopen(create_new(final, 0o644), "wb") as file:
                file.write(data)
        else:
            code = None
    except (RunError, OSError) as error:
        notes.append((2, f"run_scenario: the receipt of {name} was not kept: {error}"))
        code = None
    finally:
        with contextlib.suppress(OSError):
            staged.unlink()
    return code, notes


def receipt_accepted(data: bytes, expected: dict, code: int) -> bool:
    """Whether a receipt describes this judgement: the row, the outcome of exit `code`, exactly the judge's files, the
    command, the rows' digests, the run's identity and harness, the digest of each evidence file, and a judgement time
    no earlier than the run's start. A broken receipt is one of a row that carries a rule text, with that text in its
    detail; a scenario row carries none, so its judge's exit 1 decides nothing."""
    try:
        receipt = parse(data)
        if not isinstance(receipt, dict) or not isinstance(receipt.get("key"), dict) or not isinstance(receipt.get("run"), dict):
            return False
        key, run = receipt["key"], receipt["run"]
        fields = {name: expected[name] for name in ("row", "scenario", "mode", "defect", "command", "evidence",
                                                     "system_build", "harness", "judge", "rows")}
        if any(key.get(name) != value for name, value in fields.items()) or key.get("outcome") != OUTCOMES[code]:
            return False
        if run.get("run_id") != expected["run_id"] or run.get("started") != expected["started"] \
                or not isinstance(run.get("judged"), str) or not re.fullmatch(r"[0-9-]{10}T[0-9:]{8}Z", run["judged"]) \
                or run["judged"] < expected["started"] or not isinstance(key.get("detail"), str):
            return False
        return code != 1 or (expected["rule"] is not None and expected["rule"] in key["detail"])
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError, MemoryError):
        return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one chaos scenario as one campaign sweep and judge it.",
                                     allow_abbrev=False)
    parser.add_argument("scenario")
    parser.add_argument("run_id", metavar="run-id")
    parser.add_argument("--control", default="", metavar="DEFECT", help="run as a control of this defect")
    parser.add_argument("--archive", help="the simulation archive that campaign sim archive wrote")
    parser.add_argument("--campaign", help="the campaign binary")
    parser.add_argument("--roots", help="the directory the new sweep root <roots>/<run-id> and the harness's "
                                        "directory <roots>/<run-id>.harness are made in; neither may exist")
    parser.add_argument("--cgroup-root", help="the delegated cgroup root; default: $CAMPAIGN_CGROUP_ROOT")
    parser.add_argument("--dry-run", action="store_true", help="check the ledger, the scenario and the run id, then stop")
    return parser.parse_args()


def main() -> int:
    """Run the harness; an error it did not foresee, and --help, leave exit 2, never the 0 of held or the 1 of a broken invariant.

    A standard stream the caller closed is opened on /dev/null first, so no file the harness opens
    takes its number and receives its lines; a stream that cannot be opened again exits 2.
    """
    try:
        for number in (0, 1, 2):
            try:
                os.fstat(number)
            except OSError:
                if os.open(os.devnull, os.O_RDWR) != number:
                    raise OSError(f"standard stream {number} could not be opened again on /dev/null") from None
        return harness()
    except SystemExit:
        return 2
    except Exception as error:
        say(f"run_scenario: the harness failed: {error.__class__.__name__}: {error}")
        return 2


def settings_of(args: argparse.Namespace, ledger: dict) -> dict:
    """The checked settings of the run of one scenario row: its row, profiles, counts, load, deadline and judge scripts.

    Every value is checked once here, before the dry run's answer, and the run reads it from here alone.
    """
    rows = {row["id"]: row for row in ledger["scenarios"]}
    invariants = {row["id"]: row for row in ledger["invariants"]}
    if not ID.fullmatch(args.scenario) or args.scenario not in rows:
        refuse(f"no scenario {args.scenario!r} in chaos/ledger.json")
    row = rows[args.scenario]
    try:
        load = row["load"]
        settings = {"row": row, "profiles": profiles_of(row), "counts": counts_of(row), "workers": load["workers"],
                    "batch_s": load["batch_s"], "for_s": load["for_s"], "deadline_s": row["deadline_s"]}
        listed = row["invariants"]
        if not isinstance(listed, list) or len(set(listed)) != len(listed) or not all(
                isinstance(name, str) and ID.fullmatch(name) and name != args.scenario for name in listed):
            raise ValueError("invariants lists row ids, each once, other than the scenario's own")
        settings["rows"] = {args.scenario: row, **{name: invariants[name] for name in listed}}
        settings["scripts"] = {name: judge_script(name, entry["judge"]) for name, entry in settings["rows"].items()}
    except (KeyError, TypeError, AttributeError, ValueError) as error:
        refuse(f"chaos/ledger.json lacks what a run of {args.scenario} needs: {error.__class__.__name__}: {error}")
    if not all(type(settings[key]) is int and settings[key] > 0 for key in ("workers", "batch_s", "for_s", "deadline_s")):
        refuse(f"the workers, batch_s, for_s and deadline_s of {args.scenario} are positive integers")
    return settings


def harness() -> int:
    args = parse_args()
    try:
        ledger = parse(read_bounded(CHAOS / "ledger.json", LEDGER_BYTES))
        if not isinstance(ledger, dict):
            raise TypeError("the ledger is no JSON object")
        ids = [row["id"] for name in ("fences", "invariants", "scenarios") for row in ledger.get(name, [])]
    except (RunError, ValueError, KeyError, TypeError, AttributeError, RecursionError) as error:
        refuse(f"cannot read chaos/ledger.json: {error.__class__.__name__}: {error}")
    shared = sorted({str(name) for name in ids if ids.count(name) > 1})
    if shared:
        refuse(f"chaos/ledger.json gives the id {shared[0]!r} to more than one row")
    settings = settings_of(args, ledger)
    if not ID.fullmatch(args.run_id):
        refuse(f"run id {args.run_id!r} is no id: lowercase letters and digits joined by single hyphens")
    if args.control and not ID.fullmatch(args.control):
        refuse(f"defect {args.control!r} is no profile name or label: lowercase letters and digits joined by single hyphens")
    out, receipts = CHAOS / "runs" / args.run_id, CHAOS / "receipts" / args.run_id
    for folder in (CHAOS / "runs", CHAOS / "receipts"):
        if folder.is_symlink():
            refuse(f"chaos/{folder.name} is a symbolic link: evidence and receipts are written inside the repository")
    staging = CHAOS / "receipts" / f".{args.run_id}.staging"
    taken = next((path for path in (receipts, out, staging) if path.exists() or path.is_symlink()), None)
    if taken is not None:
        refuse(f"run id {args.run_id} names an earlier run: {taken.relative_to(ROOT).as_posix()} exists")
    if args.dry_run:
        say(f"{args.scenario}: would sweep {','.join(settings['profiles'])} into chaos/runs/{args.run_id}", 1)
        return 0
    return run(args, settings, out, receipts, staging)


def result(scenario: str, codes: dict[str, int | None]) -> int:
    """The run's exit from its judges' exits: incomplete when a judge decided nothing, then broken, then the largest code."""
    if any(code is None for code in codes.values()):
        return 3
    if any(code == 1 for name, code in codes.items() if name != scenario):
        return 1
    return max(code for code in codes.values() if code is not None)


def run(args: argparse.Namespace, settings: dict, out: Path, receipts: Path, staging: Path) -> int:
    """Sweep the scenario into a new root, keep the evidence, judge it and return the run's result.

    After the sweep the harness hashes the copy of the binary that ran and the binary at its path;
    either digest unlike the first makes the run incomplete. The stop signals stay blocked while the
    final record is taken and written, so a stop the Stopper saw is in that record, and a later one
    acts as the caller set it once the record is on file.
    """
    if not args.archive or not args.campaign or not args.roots:
        refuse("a run needs --archive, --campaign and --roots")
    archive, campaign, roots = Path(args.archive).resolve(), Path(args.campaign).resolve(), Path(args.roots).resolve()
    if not (archive / "build").is_file():
        refuse(f"{archive} holds no build record: --archive names what campaign sim archive wrote")
    if not campaign.is_file() or not os.access(campaign, os.X_OK):
        refuse(f"{campaign} is no executable file")
    if not roots.is_dir():
        refuse("--roots names a directory")
    cgroup, cgroup_root = open_cgroup_root(args.cgroup_root or os.environ.get("CAMPAIGN_CGROUP_ROOT", ""))
    root, scratch = roots / args.run_id, roots / f"{args.run_id}.harness"
    if root.exists() or root.is_symlink() or scratch.exists() or scratch.is_symlink():
        refuse(f"the sweep root {root} or the harness's directory {scratch} exists: a run sweeps a new root")
    try:
        build, binary = sha256(archive / "build"), sha256(campaign)
        harness_files = directory_digests([Path(__file__).resolve().parent])
    except RunError as error:
        refuse(f"cannot read the archive, the campaign binary or the harness: {error}")
    # Blocking STOP_SIGNALS holds a stop until the Stopper exists and the first run.json is on file.
    signal.pthread_sigmask(signal.SIG_BLOCK, STOP_SIGNALS)
    try:
        receipts.mkdir(parents=True, exist_ok=False)
        out.mkdir(parents=True, exist_ok=False)
        scratch.mkdir(mode=0o700)
    except OSError as error:
        refuse(f"run id {args.run_id} names an earlier run or its directories cannot be made: {error}")
    row = settings["row"]
    record: dict = {
        "schema": 1, "run_id": args.run_id, "scenario": args.scenario, "scenario_row": row_digest(row),
        "mode": "control" if args.control else "live", "defect": args.control, "campaign": args.run_id,
        "root": str(root), "profiles": settings["profiles"], "listing": {}, "counts": settings["counts"],
        "workers": settings["workers"], "batch_s": settings["batch_s"], "for_s": settings["for_s"],
        "deadline_s": settings["deadline_s"], "archive": str(archive), "system_build": build, "root_build": None,
        "archive_build_after": None,
        "campaign_binary": {"path": str(campaign), "sha256": binary, "staged": str(scratch / "campaign"),
                            "sha256_after": None, "source_sha256_after": None},
        "harness": harness_files, "cgroup_root": str(cgroup_root),
        "constants": {"stop_wait_s": STOP_WAIT_S, "poll_s": POLL_S, "judge_wait_s": JUDGE_WAIT_S,
                      "receipt_bytes": RECEIPT_BYTES, "checkpoint_bytes": CHECKPOINT_BYTES, "line_bytes": LINE_BYTES,
                      "output_bytes": OUTPUT_BYTES, "ledger_bytes": LEDGER_BYTES},
        "interpreter": platform.python_version(), "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "commands": {}, "listing_exit": None, "sweep_exit": None, "status_exit": None, "status_refusal": None,
        "confirm_exit": None, "confirm_dispatch": None, "findings_exit": None, "runs": {}, "deadline_fired": False,
        "signal": None, "restored": {"left_a_process": None, "archive_verified": False, "cause": None}, "error": None,
        "seconds": None, "complete": False,
    }
    clock = time.monotonic()
    stopper = Stopper(settings["deadline_s"])
    env = {key: os.environ[key] for key in ENVIRONMENT if key in os.environ}
    env["CAMPAIGN_CGROUP_ROOT"] = str(cgroup_root)
    record["environment"] = sorted(env)
    try:
        replace_file(out / "run.json", json.dumps(record, indent=2, sort_keys=True) + "\n")
    except OSError as error:
        refuse(f"cannot write chaos/runs/{args.run_id}/run.json: {error}")
    inherited = {number: signal.getsignal(number) for number in STOP_SIGNALS}
    for number in STOP_SIGNALS:
        if inherited[number] != signal.SIG_IGN:
            signal.signal(number, stopper.on_signal)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, STOP_SIGNALS)
    notes: list[tuple[int, str]] = []
    try:
        counted: set[int] = set()
        complete = sweep(record, stopper, env, archive, scratch, out, cgroup, counted, notes)
        after = record["campaign_binary"]
        after.update(sha256_after=sha256(Path(after["staged"])), source_sha256_after=sha256(campaign))
        complete = complete and after["sha256_after"] == binary and after["source_sha256_after"] == binary
        restored = record["restored"]
        if restored["left_a_process"] is not None:
            made, restored["left_a_process"] = restored["left_a_process"], None
            restored["left_a_process"] = made + elsewhere(cgroup, counted)
    except Exception as error:  # every early end is judged with the record it has
        complete = False
        record["error"] = f"{error.__class__.__name__}: {error}"[:2000]
        notes.append((2, f"run_scenario: the run stopped early: {record['error']}"))
    signal.pthread_sigmask(signal.SIG_BLOCK, STOP_SIGNALS)
    record.update(deadline_fired=stopper.deadline_fired, signal=stopper.signal,
                  seconds=round(time.monotonic() - clock, 3), complete=complete and not stopper.stopped)
    for number in STOP_SIGNALS:
        signal.signal(number, inherited[number] if inherited[number] is not None else signal.SIG_DFL)
    replace_file(out / "run.json", json.dumps(record, indent=2, sort_keys=True) + "\n")
    signal.pthread_sigmask(signal.SIG_UNBLOCK, STOP_SIGNALS)
    codes, said = judge_all(record, settings, out, receipts, staging, scratch)
    reason = stopper.reason()
    for stream, text in ([(2, reason)] if reason else []) + notes + said:
        say(text, stream)
    for name, code in codes.items():
        say(f"{name}: {OUTCOMES[code] if code is not None else 'no receipt: the judge decided nothing'}", 1)
    return result(args.scenario, codes)


def judge_all(record: dict, settings: dict, out: Path, receipts: Path, staging: Path,
              scratch: Path) -> tuple[dict[str, int | None], list[tuple[int, str]]]:
    """Run each judge of the run against the binding its receipt must name, and return the exits and the lines to relay."""
    scenario = settings["row"]
    binding = {key: record[key] for key in ("scenario", "mode", "defect", "system_build", "harness", "run_id", "started")}
    binding["evidence"] = evidence_digests(out)
    staging.mkdir(mode=0o700)
    codes: dict[str, int | None] = {}
    said: list[tuple[int, str]] = []
    try:
        for name, script in settings["scripts"].items():
            row = settings["rows"][name]
            control = row.get("control") if name != record["scenario"] else None
            try:
                expected = {**binding, "row": name, "command": [script.relative_to(ROOT).as_posix(), name],
                            "rows": {name: row_digest(row), scenario["id"]: row_digest(scenario)},
                            "judge": directory_digests(sorted({script.parent, CHAOS / "judges" / "core"})),
                            "rule": control.get("expect") if isinstance(control, dict) else None}
            except RunError as error:
                codes[name] = None
                said.append((2, f"run_scenario: cannot read the judge of {name}: {error}"))
                continue
            codes[name], lines = judge(name, script, out, staging / f"{name}.json", receipts / f"{name}.json",
                                       scratch / f"judge-{name}", expected)
            said += lines
    finally:
        with contextlib.suppress(OSError):
            staging.rmdir()
    return codes, said


def stage(source: Path, target: Path, digest: str) -> Path:
    """Copy the campaign binary to a new executable file `target`, hashing the bytes it copies; another digest than the
    one recorded before the first command raises RunError."""
    file = open_regular(source)
    if file is None:
        raise RunError(f"cannot read {source}: it does not exist")
    copied = hashlib.sha256()
    with file, os.fdopen(create_new(target, 0o700), "wb") as copy:
        for block in iter(lambda: file.read(1 << 20), b""):
            copied.update(block)
            copy.write(block)
    if copied.hexdigest() != digest:
        raise RunError(f"{source} changed between its first hash and its copy")
    return target


def sweep(record: dict, stopper: Stopper, env: dict[str, str], archive: Path, scratch: Path, out: Path, cgroup: int,
          counted: set[int], notes: list[tuple[int, str]]) -> bool:
    """Run the campaign commands of one run and write the evidence. True when every copy the sweep's exit calls for is written.

    The rule, in the order the commands run: the listing exits 0; the sweep returns by itself; after
    exit 2, 3 or 4, which leave the root as no sweep it was asked for, the record of that exit and of
    sweep-status's answer is the evidence, which the judges turn into invalid or incomplete, and after
    an exit the judges call invalid the end of the sweep's standard error is kept beside the record
    as sweep-refusal.txt, the record file an invalid receipt names; after
    exit 0 or 1 the restoration count was taken, sweep-status exits 0 and its copies are written, the
    status's final elapsed time is at least --for, confirm exits 0 on an emptied dispatch queue and
    findings exits 0. The caller adds that no stop came and the binary stayed the same.
    """
    root, defect = Path(record["root"]), record["defect"]
    (scratch / "listing").mkdir(mode=0o700)
    staged = stage(Path(record["campaign_binary"]["path"]), Path(record["campaign_binary"]["staged"]),
                   record["campaign_binary"]["sha256"])

    def command(name: str, words: list[str]) -> int | None:
        record["commands"][name] = [str(staged), *words]
        return stopper.run(record["commands"][name], env, scratch, scratch / f"{name}.out", scratch / f"{name}.err")

    record["listing_exit"] = command("listing", ["sim", "capabilities", "--archive", str(archive),
                                                 "--artifacts", str(scratch / "listing")])
    if record["listing_exit"] != 0:
        return False
    printed = read_json(scratch / "listing.out", OUTPUT_BYTES)
    if not isinstance(printed, dict) or not isinstance(printed.get("capabilities"), str):
        raise RunError("campaign sim capabilities printed no capability listing")
    listing = parse_listing(printed["capabilities"])
    profiles = swept(record["profiles"], defect, listing)
    record["profiles"] = profiles
    record["listing"] = {profile: listing.get(profile) for profile in profiles}
    code = swept_root(record, command, archive, root, cgroup, counted, notes)
    if code is None or code < 0 or stopper.stopped:
        return False
    if code in (0, 1):
        record["archive_build_after"] = sha256(archive / "build")
        record["restored"]["archive_verified"] = record["archive_build_after"] == record["system_build"]
        checkpoint = root / "sweep.json"
        probe = open_regular(checkpoint)
        if probe is not None:
            probe.close()
            bound = read_json(checkpoint, CHECKPOINT_BYTES)
            record["root_build"] = bound.get("build") if isinstance(bound, dict) else None
    record["status_exit"] = command("sweep-status", ["sweep-status", "--root", str(root)])
    if record["status_exit"] != 0:
        record["status_refusal"] = text_of(scratch / "sweep-status.err")
    if code not in (0, 1):
        if code not in (3, 4):
            write_new(out / "sweep-refusal.txt", text_of(scratch / "sweep.err"))
        return record["status_exit"] is not None
    if record["status_exit"] != 0 or record["restored"]["left_a_process"] is None:
        return False
    elapsed = copied(record, scratch, root, out)
    if not (type(elapsed) is int or (type(elapsed) is float and math.isfinite(elapsed))) or elapsed < record["for_s"]:
        return False
    record["confirm_exit"] = confirmed(record, command, archive, root, cgroup, counted)
    if record["confirm_exit"] != 0:
        return False
    report = read_json(scratch / "confirm.out", OUTPUT_BYTES)
    record["confirm_dispatch"] = report.get("dispatch") if isinstance(report, dict) else None
    if record["confirm_dispatch"] != "queue_empty":
        return False
    record["findings_exit"] = command("findings", ["findings", "--state", str(root / "confirm" / "state")])
    if record["findings_exit"] != 0:
        return False
    findings = without_wall_clock(read_json(scratch / "findings.out", OUTPUT_BYTES))
    write_new(out / "findings.json", json.dumps(findings, indent=1, sort_keys=True) + "\n")
    return True


def swept_root(record: dict, command: Any, archive: Path, root: Path, cgroup: int, counted: set[int],
               notes: list[tuple[int, str]]) -> int | None:
    """Run campaign sweep and record its exit, then count and kill what this run's sweep left in its worker groups.

    The sweep's exit is recorded before the count, which can raise. A sweep that exited 2 refused an
    argument and one that exited 3 found the root held; neither accepted the root, so the harness
    writes no cgroup.kill after it. After any other end, a stop included, the count and the kill run
    before anything else is read, and a lock another command holds leaves the count unset with its
    cause in the record.
    """
    before = pens_of(cgroup)
    code: int | None = None
    try:
        code = command("sweep", ["sweep", "--root", str(root), "--archive", str(archive),
                                 "--campaign", record["campaign"], "--profiles", ",".join(record["profiles"]),
                                 "--workers", str(record["workers"]), "--batch", str(record["batch_s"]),
                                 "--for", str(record["for_s"]),
                                 *(word for key, value in record["counts"].items() for word in ("--set", f"{key}={value}"))])
        record["sweep_exit"] = code
    finally:
        if code in (2, 3):
            record["restored"]["cause"] = f"campaign sweep exited {code} and accepted no root, so no group was counted or killed"
        else:
            left, cause = restore(cgroup, before, counted)
            record["restored"].update(left_a_process=left, cause=cause)
            if cause is not None:
                notes.append((2, f"run_scenario: {cause}"))
    return code


def confirmed(record: dict, command: Any, archive: Path, root: Path, cgroup: int, counted: set[int]) -> int | None:
    """Run campaign confirm and record its exit, then add to the restoration count what it left in the groups it made.

    Confirm runs each attempt in a group of its own directly under the cgroup root. After any end of
    the command, a stop included, the harness counts the processes in those groups and kills them
    (`attempts_left`), so `left_a_process` covers the sweep's worker groups and confirm's attempt
    groups; `run` adds every other group under the root after the last command. The count stays
    unset in the record when it cannot be made, and the RunError ends the run.
    """
    code: int | None = None
    try:
        code = command("confirm", ["confirm", "--root", str(root), "--archive", str(archive)])
        record["confirm_exit"] = code
    finally:
        swept, record["restored"]["left_a_process"] = record["restored"]["left_a_process"], None
        record["restored"]["left_a_process"] = swept + attempts_left(cgroup, counted)
    return code


def copied(record: dict, scratch: Path, root: Path, out: Path) -> object:
    """Write the copies of a sweep that exited 0 or 1: the status, the suspects and history.jsonl. Returns the status's final
    elapsed time as printed."""
    printed = read_json(scratch / "sweep-status.out", OUTPUT_BYTES)
    elapsed = printed.get("elapsed_s") if isinstance(printed, dict) else None
    record["sweep_elapsed_s"] = elapsed
    status = without_wall_clock(printed)
    write_new(out / "sweep-status.json", json.dumps(status, indent=1, sort_keys=True) + "\n")
    copy_suspects(root / "suspects.jsonl", out / "suspects.jsonl")
    entries = status.get("profiles", {}) if isinstance(status, dict) else {}
    distinct = list(dict.fromkeys(record["profiles"]))
    for profile in distinct:
        entry = entries.get(profile)
        record["runs"][profile] = {"first": 0, "next": entry.get("next") if isinstance(entry, dict) else None}
    write_new(out / "history.jsonl", "".join(
        json.dumps({"profile": profile, "campaign": record["campaign"], "counts": record["counts"],
                    "build": record["system_build"], "runs": record["runs"][profile]}, sort_keys=True) + "\n"
        for profile in distinct))
    return elapsed


def copy_suspects(source: Path, target: Path) -> None:
    """Copy each complete line of the root's suspects.jsonl, one at a time, without its wall-clock keys.

    An absent log is copied as an empty file and an unterminated last line is left out; a link, any
    other file than a regular one and a line of more than LINE_BYTES bytes with its line feed raise
    RunError.
    """
    file = open_regular(source)
    with os.fdopen(create_new(target, 0o644), "wb") as copy:
        if file is None:
            return
        with file:
            for raw in iter(lambda: file.readline(LINE_BYTES + 1), b""):
                if len(raw) > LINE_BYTES:
                    raise RunError(f"{source} holds a line of more than {LINE_BYTES} bytes")
                if raw.endswith(b"\n"):
                    copy.write(copy_line(raw[:-1]))


def copy_line(line: bytes) -> bytes:
    """One complete line of the root's suspects.jsonl without its wall-clock keys.

    A line is read as the judges read it: UTF-8 bytes of one JSON document whose objects name each
    member once. Any other line is kept byte for byte, so the copy holds what the root holds and
    the judges refuse it.
    """
    try:
        return (json.dumps(without_wall_clock(parse(line)), sort_keys=True) + "\n").encode("utf-8")
    except (ValueError, RecursionError):
        return line + b"\n"


if __name__ == "__main__":
    sys.exit(main())
