#!/usr/bin/env python3
"""Run the repository checks a push needs, against the commits being pushed.

Usage:
  pre-push-checks.py [REMOTE] < pre-push-refs

Git's pre-push hook feeds one line per ref:
`<local ref> <local sha> <remote ref> <remote sha>`. For each pushed ref tip
this script lists the files the push changes against the remote commit, or
against the tip's merge base with `origin/main` for a new branch or a remote
commit this clone lacks, and runs the checks those files require in a temporary
worktree of the tip:

- the test inventory and registry, the selection and receipt scripts and their
  judges, the obligation catalog and its list of control-less records, a
  checker's `expected.json`, a file under `verification/intake/`, the atomic
  census and its classifier, the TLC and Quint runners, the Verus inventory,
  the agent-checks workflow, or a Rust change to an `#[ignore]` or
  `cfg_attr(.., ignore)` attribute or to the name of the fn it marks:
  `scripts/test-select-tests.py` and `scripts/verify-receipts.py admit`;
- `verification/verus/` or a source its inventory names:
  `scripts/judge-verus.py reconcile`;
- at a tip that holds `verification/models/links.json`: the registry, a model
  it enrolls, a file one of its rows cites, the TLC runner, the Verus or RC11
  judge, or the links check or its self-test: `scripts/model-links.py check`,
  and for a change to one of those scripts also `scripts/test-model-links.py`.
  A push that removes the registry from a tip that keeps the links check runs
  the check, which refuses the tree;
- `chaos` itself or a path under `chaos/`: the chaos contract check,
  `chaos/tools/validate_contract.py` with `--check-claim chaos/READINESS.md`,
  then, at a tip that holds it, `scripts/chaos-receipt-replay.py`, which runs
  each run receipt's judge again on its evidence and compares the receipt it
  writes with the stored one (a change to that script runs it too, and a push
  that removes it fails on the missing file),
  and for a change at or under `chaos/harness`, `chaos/judges`, `chaos/tests`,
  `chaos/tools` or `chaos/receipts`, or to the ledger, `chaos/project.yaml`
  or `chaos/approval-policy.md` itself, also the judges' test,
  `chaos/tests/test_judges.py`, which reads each of them;
- `crates/campaign-supervisor/src/campaign/calibration/controls.rs`,
  `crates/campaign-supervisor/src/campaign/seeds/required.rs`,
  `crates/campaign-supervisor/src/campaign/seeds.rs` or
  `crates/campaign-supervisor/src/protocol/summary.rs`, at a tip that holds
  `chaos/tests/test_judges.py`: the judges' test. That run checks each of
  these files only where a test it runs reads it; where none does, it passes
  whatever the change;
- `scripts/gameday-judge.py`, `scripts/test-gameday-judge.py`, a path under
  `scripts/gameday-fixtures/`, `scripts/readiness.py`, a script of its
  `OWNING` tuple (which it loads or hashes at import),
  `scripts/fis-profiles.json`, `verification/readiness/gamedays.json`, a file
  that declares one of the judge's `FLEET_BOUNDS`
  (`crates/kestrike/src/failover/zone_loop/directory.rs`,
  `crates/kestrike/src/failover/standbys.rs`) or
  `verification/readiness/failover.json`, at a tip that holds the judge's
  self-test: `scripts/test-gameday-judge.py`. A change to the judge or its
  self-test runs it at any tip, so a push that removes the self-test fails on
  the missing file;
- `scripts/host-stop-controller.py`, `scripts/test-host-stop-controller.py`, a
  path under `scripts/host-stop-fixtures/` or `scripts/gameday-fixtures/`, or
  a file the controller or its self-test loads or reads:
  `scripts/fis-controller.py`, `scripts/gameday-judge.py` or a file the judge
  reads (`scripts/readiness.py`, a script of its `OWNING` tuple,
  `scripts/fis-profiles.json`, `verification/readiness/gamedays.json` or a
  file that declares one of its `FLEET_BOUNDS`), at a
  tip that holds the controller's self-test:
  `scripts/test-host-stop-controller.py`. A change to the controller or its
  self-test runs it at any tip, so a push that removes the self-test fails on
  the missing file.

The contract check, the receipt replay, the judges' test and the game-day
judge's and the host stop controller's self-tests each start as
`python3 -I`: their imports come from the interpreter's installation, so a
file beside the program at the pushed tip and the `PYTHON*` variables have no
effect on them. `.githooks/pre-push` starts this script the same way.

Before the worktree checks, the hook guards the chaos records: the receipts
(`chaos/receipts/**/*.json` and `chaos/tests/receipts/**/*.json`) and the run
records (`chaos/runs/*/run.json` and `chaos/tests/runs/*/run.json`), which
carry the harness's own paths, commands
and output. At a tip with a change under `chaos/` or with no comparison base,
it refuses the tip when an entry at or under `chaos/` is a link or a
submodule, when `chaos`, `chaos/tests` or a record directory is not a
directory, when a record path is not a regular file, and when a record holds
what may be an AWS account number. For every ref it also reads each record
that a pushed commit adds or changes, merges' side branches included. A pushed
commit is one the tip reaches and the destination is not known to hold. The
destination holds the remote commit of the ref line and each commit that a
remote-tracking ref of REMOTE reaches, as of this clone's last fetch or push.
REMOTE is the hook's first argument, the name of the remote the push goes to;
a URL or a missing name selects no remote-tracking ref, and the remote commit
alone bounds the history. The refs of another remote whose name starts with
`REMOTE/` are left out, and a REMOTE whose own name starts with another
remote's name and `/` selects no remote-tracking ref either. A refused record in a commit the destination holds
therefore refuses no later push. The hook refuses the push when a pushed
commit's record holds such a number, or when a pushed commit makes a record
path a link or a submodule, naming that commit. The hook decodes a
record as JSON and
matches each key, string and integer in it; a record that is not JSON, or
that Git cannot read, refuses the push. A match is 12 digits with no letter or digit beside them, so
a digit run inside a SHA-256 digest is no match, or three groups of 4 joined
by `-` with no letter, digit or `-` beside them. Every Git command of the hook
reads the original objects and ignores `refs/replace/`, since a push sends the
originals, and reads pathspecs with their magic whatever pathspec mode
(`GIT_LITERAL_PATHSPECS` and its kin) the push set.

Any other Rust change runs no worktree check here, although the census and
witness checks read production source and the intake checks of `admit` read
the regression files, their crates' `Cargo.toml` and the module files on their
paths, `narrate/rules.rs`, the history sources, the `site.path` file of each
escape whose fix is not delivered, and, for a model reference, the `tla/` and
`quint/` models, the TLC configurations and the Quint case modules. After
moving or renaming such a file, run `scripts/verify-receipts.py admit`
yourself; CI runs the selection and reconciliation checks on every PR.

Before those checks, each ref line with a comparison base runs
`scripts/scan-weakened-tests.py --base BASE --head TIP`, the copy beside this
script, since the scan reads Git objects and needs no worktree. Every nonzero
scan exit is a failed check, and the worktree checks still run after it. A ref
line with no comparison base prints that its scan was skipped.

The worktree checks run the pushed tip's own scripts, including a fetched
commit pushed under a new name. A deleted ref needs no check. A ref line with
no comparison base runs every worktree check, the links checks only at a tip
that holds the registry or the links check, the contract check only at a tip
that holds `chaos/ledger.json`, the judges' test only at a tip that holds
`chaos/tests/test_judges.py`, and the game-day judge's and the host stop
controller's self-tests each only at a tip that holds that self-test, and
guards that tip's chaos records. A malformed
line fails the push.

Exit 0 passes, 1 is a failed check, 2 a malformed input or Git failure.
"""

import json
import os
import re
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

ZERO = "0" * 40
SCANNER = Path(__file__).with_name("scan-weakened-tests.py")
SELECTION_INPUTS = (
    "scripts/test-inventory.json", "scripts/test-registry.json",
    "scripts/select-tests.py", "scripts/test-select-tests.py",
    "verification/obligations.json", "verification/control-less.json",
    ".github/workflows/agent-checks.yml",
    "scripts/verify-receipts.py", "scripts/test-verify-receipts.py",
    "scripts/run-receipt-selftests.py", "scripts/scan-tag-compare.py",
    "scripts/classify-atomics.py", "verification/atomics/census.json",
    "tla/check.py", "quint/check.py", "verification/verus/inventory.json",
)
SELECTION_PATTERN = re.compile(r"^(scripts/judge-[\w-]+\.py|verification/[\w-]+/expected\.json)$")
INTAKE_PREFIX = "verification/intake/"
SELECTION = (
    ("python3", "scripts/test-select-tests.py"),
    ("python3", "scripts/verify-receipts.py", "admit"),
)
RECONCILE = (("python3", "scripts/judge-verus.py", "reconcile"),)
LINKS = "verification/models/links.json"
LINKS_SCRIPTS = (
    "scripts/model-links.py", "scripts/test-model-links.py", "tla/check.py",
    "scripts/judge-verus.py", "scripts/judge-rc11.py",
)
LINKS_CHECK = (("python3", "scripts/model-links.py", "check"),)
LINKS_SELFTEST = (("python3", "scripts/test-model-links.py"),)
CONTRACT = "chaos/ledger.json"
CONTRACT_CHECK = (("python3", "-I", "chaos/tools/validate_contract.py", CONTRACT, "--root", ".",
                   "--project", "chaos/project.yaml", "--receipts", "chaos/receipts",
                   "--check-claim", "chaos/READINESS.md"),)
REPLAY = "scripts/chaos-receipt-replay.py"
REPLAY_CHECK = (("python3", "-I", REPLAY),)
JUDGES = "chaos/tests/test_judges.py"
JUDGES_DIRS = ("chaos/harness/", "chaos/judges/", "chaos/tests/", "chaos/tools/", "chaos/receipts/")
JUDGES_FILES = (CONTRACT, "chaos/project.yaml", "chaos/approval-policy.md")
JUDGES_SOURCES = (
    "crates/campaign-supervisor/src/campaign/calibration/controls.rs",
    "crates/campaign-supervisor/src/campaign/seeds/required.rs",
    "crates/campaign-supervisor/src/campaign/seeds.rs",
    "crates/campaign-supervisor/src/protocol/summary.rs",
)
JUDGES_TEST = (("python3", "-I", JUDGES),)
GAMEDAY = "scripts/test-gameday-judge.py"
GAMEDAY_OWN = ("scripts/gameday-judge.py", GAMEDAY)
# A self-test that imports `readiness.py` depends on every script in `OWNING` because the module loads or hashes each
# script at import.
JUDGE_READS = ("scripts/gameday-judge.py", "scripts/readiness.py", "scripts/fis-profiles.json",
               "verification/readiness/gamedays.json", "crates/kestrike/src/failover/zone_loop/directory.rs",
               "crates/kestrike/src/failover/standbys.rs",
               *(f"scripts/{name}" for name in ("acceptance.py", "verify-receipts.py", "hit-gate.py",
                                                "hardware-lane.py", "recovery-packages.py", "measurement-frame.py",
                                                "sizing-worksheet.py", "reproduce-test.py", "select-tests.py")))
GAMEDAY_INPUTS = (GAMEDAY, *JUDGE_READS, "verification/readiness/failover.json")
GAMEDAY_FIXTURES = "scripts/gameday-fixtures/"
GAMEDAY_TEST = (("python3", "-I", GAMEDAY),)
HOST_STOP = "scripts/test-host-stop-controller.py"
HOST_STOP_OWN = ("scripts/host-stop-controller.py", HOST_STOP)
HOST_STOP_INPUTS = (*HOST_STOP_OWN, "scripts/fis-controller.py", *JUDGE_READS)
HOST_STOP_FIXTURES = ("scripts/host-stop-fixtures/", GAMEDAY_FIXTURES)
HOST_STOP_TEST = (("python3", "-I", HOST_STOP),)
ORDER = (SELECTION + RECONCILE + LINKS_CHECK + LINKS_SELFTEST + CONTRACT_CHECK + REPLAY_CHECK + JUDGES_TEST
         + GAMEDAY_TEST + HOST_STOP_TEST)
RECORD_DIRS = ("chaos/receipts", "chaos/runs", "chaos/tests/receipts", "chaos/tests/runs")
CHAOS_TREES = ("chaos", "chaos/tests", *RECORD_DIRS)
PATHSPEC_MODES = ("GIT_LITERAL_PATHSPECS", "GIT_GLOB_PATHSPECS", "GIT_NOGLOB_PATHSPECS", "GIT_ICASE_PATHSPECS")
CHAOS_RECORD = re.compile(r"chaos/(?:tests/)?receipts/.+\.json|chaos/(?:tests/)?runs/[^/]+/run\.json", re.DOTALL)
REGULAR = ("100644", "100755")
LINKS_OR_SUBMODULES = ("120000", "160000")
GLOB = re.compile(r"[*?\[\\]")
ACCOUNT_NUMBER = re.compile(r"(?<![0-9A-Za-z])[0-9]{12}(?![0-9A-Za-z])"
                            r"|(?<![0-9A-Za-z-])[0-9]{4}-[0-9]{4}-[0-9]{4}(?![0-9A-Za-z-])")
IGNORE = re.compile(r"#\[ignore\b[^\]]*\]|#\[cfg_attr\([^\]]*\bignore\b[^\]]*\]")
FUNCTION = re.compile(r"(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(?:r#)?\w+")


class GitError(Exception):
    pass


def git(*args):
    """Return the stdout of `git args` decoded as strict UTF-8, with no line-end translation."""
    result = subprocess.run(("git", *args), capture_output=True)
    if result.returncode != 0:
        raise GitError(f"git {' '.join(args)}: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout.decode()


def merge_base(one, other):
    """Return the merge base of two commits, or None when they share no history.

    Any other failure to compute it raises `GitError`.
    """
    found = subprocess.run(("git", "merge-base", one, other), capture_output=True)
    if found.returncode == 1 and not found.stdout:
        return None
    if found.returncode != 0:
        raise GitError(f"git merge-base {one} {other}: {found.stderr.decode(errors='replace').strip()}")
    return found.stdout.decode().strip()


def comparison_base(local, remote):
    """Return the commit to diff against, or None when every worktree check must run.

    None means the clone lacks `origin/main` or shares no history with it. Any
    other failure to compute the merge base raises `GitError`.
    """
    if remote != ZERO and subprocess.run(
        ("git", "cat-file", "-e", f"{remote}^{{commit}}"), capture_output=True,
    ).returncode == 0:
        return remote
    if not git("for-each-ref", "--format=%(refname)", "refs/remotes/origin/main"):
        return None
    return merge_base("origin/main", local)


def destination_refs(name, remotes):
    """Return the `git rev-list` arguments that name the remote-tracking refs of the remote called name.

    The last argument is a glob over `refs/remotes/`, so a name that is empty
    or holds a glob character returns nothing: such a name could select the
    refs of a remote the push does not go to. The glob `name/*` also matches
    the refs of each of `remotes` whose name starts with `name/`, so an
    exclusion for each of those remotes comes first. A name that starts with
    another remote's name and `/` returns nothing: that remote's branches
    under the rest of the name have the ref names of this remote's branches.
    """
    if not name or GLOB.search(name) or any(name.startswith(f"{other}/") for other in remotes):
        return ()
    return (*(f"--exclude={other}/*" for other in remotes if other.startswith(f"{name}/")), f"--remotes={name}")


def host_stop_input(path):
    """Return whether path is one the host stop controller's self-test loads or reads."""
    return path in HOST_STOP_INPUTS or path.startswith(HOST_STOP_FIXTURES)


def holds(commit, path):
    """Return whether the tree of commit holds path."""
    return subprocess.run(("git", "cat-file", "-e", f"{commit}:{path}"), capture_output=True).returncode == 0


def verus_sources(commit):
    """Return the source paths the Verus inventory at commit names.

    An absent inventory names none. An unreadable one, or one that is not
    UTF-8, returns None, and the caller runs reconciliation, which reports the
    defect.
    """
    found = subprocess.run(
        ("git", "show", f"{commit}:verification/verus/inventory.json"), capture_output=True,
    )
    if found.returncode != 0:
        return set()
    try:
        return set(json.loads(found.stdout.decode()).get("sources", {}))
    except (ValueError, AttributeError, TypeError):
        return None


def link_inputs(commit):
    """Return the paths whose change needs the model links check at commit.

    They are the registry, each model it enrolls, each file a row cites and
    the scripts the check loads. A commit that holds the check without the
    registry returns the registry path alone: the check refuses that tree, so
    a push that removes the registry runs it. A commit with neither has none.
    An unreadable registry returns None, and the caller runs the check, which
    reports the defect.
    """
    found = subprocess.run(("git", "show", f"{commit}:{LINKS}"), capture_output=True)
    if found.returncode != 0:
        return {LINKS} if holds(commit, LINKS_CHECK[0][1]) else set()
    try:
        data = json.loads(found.stdout.decode())
        return {
            LINKS, *LINKS_SCRIPTS, *(model["path"] for model in data["models"]),
            *(anchor["path"] for row in data["rows"] for anchor in row.get("anchors", ())),
        }
    except (ValueError, AttributeError, TypeError, KeyError):
        return None


def blob_texts(specs, errors="replace", absent: "str | None" = ""):
    """Return the UTF-8 text of each `<commit>:<path>` blob in order, or `absent` for an absent one.

    `errors` is the decoding error handler; under "strict", bytes that are not
    UTF-8 raise `GitError` naming the blob. An object that is not a blob also
    reads as `absent`.
    """
    result = subprocess.run(("git", "cat-file", "--batch"), capture_output=True,
                            input="".join(f"{spec}\n" for spec in specs).encode())
    if result.returncode != 0:
        raise GitError(f"git cat-file --batch: {result.stderr.decode(errors='replace').strip()}")
    data, texts, at = result.stdout, [], 0
    for spec in specs:
        end = data.index(b"\n", at)
        header, at = data[at:end].split(), end + 1
        # A found object's header is `<oid> <type> <size>`; an absent one ends in `missing`.
        if len(header) != 3 or not header[2].isdigit():
            texts.append(absent)
            continue
        size = int(header[2])
        try:
            texts.append(data[at:at + size].decode(errors=errors) if header[1] == b"blob" else absent)
        except UnicodeDecodeError as error:
            raise GitError(f"{spec}: {error}") from error
        at += size + 1
    return texts


def ignored_tests(text):
    """Return each ignore attribute's text through the name of the fn it precedes.

    The search skips the attributes between the two, as the registry census
    does, so a string inside `should_panic` cannot stand in for the fn name.
    A match that starts at or after an attribute's end is the next search's
    result too, and once no fn follows an attribute, none follows a later one.
    """
    spans, function, searched = [], None, False
    for found in IGNORE.finditer(text):
        if not searched or function is not None and function.start() < found.end():
            function, searched = FUNCTION.search(text, found.end()), True
        spans.append(text[found.start():function.end() if function else len(text)])
    return spans


def changes_ignore(base, local, paths):
    """Return whether the push changes an ignore attribute or the fn it precedes in Rust source.

    The registry census pairs each ignore cause with its test's fn name, so a
    renamed ignored test changes its input as an edited attribute does. Edits
    elsewhere in a file leave each span equal and select nothing. A path that
    holds a newline, which batch input cannot name, selects the checks.
    """
    rust = [p for p in paths if p.endswith(".rs")]
    if any("\n" in p for p in rust):
        return True
    texts = blob_texts([f"{commit}:{path}" for path in rust for commit in (base, local)]) if rust else []
    return any(ignored_tests(old) != ignored_tests(new) for old, new in zip(texts[::2], texts[1::2]))


def gameday_input(path):
    return path in GAMEDAY_INPUTS or path.startswith(GAMEDAY_FIXTURES)


def checks_for(paths, sources, links, ignore_changed=False, *, judges_held=True, replay_held=False,
               gameday_held=True, host_stop_held=True):
    """Return the commands the changed paths require, in run order.

    `judges_held` says whether the tip holds the judges' test; a change to a
    path of `JUDGES_SOURCES` runs that test only then. `replay_held` says
    whether it holds `REPLAY`, which a chaos change runs only then. A change
    to `REPLAY` itself runs it at any tip, so a push that removes the script
    fails on the missing file. `gameday_held` says whether it holds `GAMEDAY`,
    which a change to a game-day judge input runs only then; a change to the
    judge or its self-test runs it at any tip. `host_stop_held` says the same
    of `HOST_STOP` and the host stop controller's inputs.
    """
    commands = []
    if ignore_changed or any(p in SELECTION_INPUTS or SELECTION_PATTERN.match(p) or p.startswith(INTAKE_PREFIX)
                             for p in paths):
        commands += SELECTION
    if paths and sources is None or any(
        p.startswith("verification/verus/") or p in (sources or ()) for p in paths
    ):
        commands += RECONCILE
    if paths and links is None or any(p in (links or ()) for p in paths):
        commands += LINKS_CHECK
        if any(p in LINKS_SCRIPTS for p in paths):
            commands += LINKS_SELFTEST
    if chaos_change(paths):
        commands += CONTRACT_CHECK
    if replay_held and chaos_change(paths) or REPLAY in paths:
        commands += REPLAY_CHECK
    if any(p.startswith(JUDGES_DIRS) or p in JUDGES_FILES or f"{p}/" in JUDGES_DIRS for p in paths) or (
        judges_held and any(p in JUDGES_SOURCES for p in paths)
    ):
        commands += JUDGES_TEST
    if any(p in GAMEDAY_OWN for p in paths) or gameday_held and any(gameday_input(p) for p in paths):
        commands += GAMEDAY_TEST
    if any(p in HOST_STOP_OWN for p in paths) or host_stop_held and any(host_stop_input(p) for p in paths):
        commands += HOST_STOP_TEST
    return commands


def chaos_change(paths):
    """Return whether any of paths is `chaos` or lies under `chaos/`."""
    return any(p == "chaos" or p.startswith("chaos/") for p in paths)


def run_in_worktree(commit, commands):
    """Run each command in a detached worktree of commit; return the failures."""
    failures = []
    with tempfile.TemporaryDirectory(prefix="kestrike-pre-push-") as tree:
        try:
            git("worktree", "add", "--quiet", "--detach", tree, commit)
            for command in commands:
                print(f"pre-push: {commit[:12]}: {' '.join(command)}", file=sys.stderr)
                if subprocess.run(command, cwd=tree).returncode != 0:
                    failures.append(" ".join(command))
        finally:
            # A killed `worktree add` leaves its `initializing` lock; the second
            # `--force` removes a locked worktree.
            removed = subprocess.run(("git", "worktree", "remove", "--force", "--force", tree),
                                     capture_output=True, text=True)
            if removed.returncode != 0:
                print(f"pre-push: could not remove worktree {tree}: {removed.stderr.strip()}",
                      file=sys.stderr)
    return failures


def scan(base, commit):
    """Run the weakened-test scanner over base..commit; return the failure, if any."""
    command = ("python3", str(SCANNER), "--base", base, "--head", commit)
    print(f"pre-push: {commit[:12]}: scan-weakened-tests.py --base {base[:12]}", file=sys.stderr)
    sys.stderr.flush()
    if subprocess.run(command, stdout=sys.stderr).returncode != 0:
        return [f"scripts/scan-weakened-tests.py --base {base} --head {commit}"]
    return []


def shown(path):
    """Return path as a failure line names it, quoted when it holds a control character."""
    return path if path.isprintable() else repr(path)


def record_values(text):
    """Return each key, string and integer of a JSON record as text, or None when it is not JSON.

    Decoding first lets a JSON escape before a number end the match as the
    decoded character does. A float is no account number, so it is skipped.
    """
    try:
        pending = [json.loads(text, object_pairs_hook=lambda pairs: [part for pair in pairs for part in pair])]
    except (ValueError, RecursionError):
        return None
    found = []
    while pending:
        value = pending.pop()
        if isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, str):
            found.append(value)
        elif isinstance(value, int) and not isinstance(value, bool):
            found.append(str(value))
    return found


def tip_records(commit):
    """Return the failures of the chaos tree at commit and its records as (commit, path, oid).

    A link, a submodule, a record directory that is not a directory and a
    record path that is not a regular file each fail, so the records read are
    the ones the tree itself holds.
    """
    failures, records = [], []
    for entry in git("ls-tree", "-r", "-t", "-z", "--full-tree", commit, "--", "chaos").split("\0"):
        if not entry:
            continue
        # Each entry is `<mode> <type> <oid>`, a tab, then the path, which may hold a tab.
        meta, path = entry.split("\t", 1)
        mode, kind, oid = meta.split()
        where = f"{shown(path)} at {commit[:12]}"
        if mode in LINKS_OR_SUBMODULES:
            failures.append(f"{where} is a link or a submodule")
        elif path in CHAOS_TREES and kind != "tree":
            failures.append(f"{where} is not a directory")
        elif CHAOS_RECORD.fullmatch(path):
            if mode in REGULAR:
                records.append((commit, path, oid))
            else:
                failures.append(f"{where} is a chaos record that is not a regular file")
    return failures, records


def pushed_records(commits):
    """Return the failures of the chaos records that commits add or change, and those records as (commit, path, oid).

    A commit that makes a record path a link or a submodule fails: Git sends
    that entry with the commit, and it is no JSON record to read.
    """
    failures, records = [], []
    for commit in commits:
        fields = git("diff-tree", "-r", "-z", "-m", "--root", "--no-renames", "--no-commit-id", commit,
                     "--", *(f":(top){d}" for d in RECORD_DIRS)).split("\0")
        # Each change is `:<old mode> <new mode> <old oid> <new oid> <status>`, then its path.
        for at in range(0, len(fields) - 1, 2):
            _, mode, _, oid, status = fields[at].split()
            path = fields[at + 1]
            if status == "D" or not CHAOS_RECORD.fullmatch(path):
                continue
            if mode in REGULAR:
                records.append((commit, path, oid))
            else:
                failures.append(f"{shown(path)} at {commit[:12]} is a chaos record that is not a regular file")
    return failures, records


def account_numbers(records):
    """Return a failure for each (commit, path, oid) record that holds what may be an AWS account number.

    A record Git cannot read and a record that is not JSON each fail, so every
    record counts only once it was read and decoded. Each blob is read once
    and named by the first record that holds it.
    """
    first = {}
    for record in records:
        first.setdefault(record[2], record)
    unique = list(first.values())
    texts = blob_texts([oid for _, _, oid in unique], absent=None) if unique else []
    failures = []
    for at, (commit, path, _) in enumerate(unique):
        where = f"{shown(path)} at {commit[:12]}"
        values = None if texts[at] is None else record_values(texts[at])
        if texts[at] is None:
            failures.append(f"{where} is a chaos record Git could not read")
        elif values is None:
            failures.append(f"{where} is a chaos record that is not JSON")
        elif any(ACCOUNT_NUMBER.search(value) for value in values):
            failures.append(f"{where} holds what may be an AWS account number")
    return failures


def exit_on_signal(signum, _frame):
    """Turn SIGTERM and SIGHUP into SystemExit so the worktree cleanup runs.

    The handler raises inside the wait on any child, `git worktree add`
    included, and `subprocess.run` kills that child before the exception
    reaches the `finally` that removes the worktree.
    """
    sys.exit(128 + signum)


def main(lines, destination=""):
    # Every Git child reads the original objects, the ones the push sends, and
    # reads each pathspec with its magic, whatever pathspec mode the push set.
    os.environ["GIT_NO_REPLACE_OBJECTS"] = "1"
    for mode in PATHSPEC_MODES:
        os.environ.pop(mode, None)
    planned, scans, guarded, pushed = {}, [], [], []
    tracked = destination_refs(destination, git("remote").split() if destination else ())
    for line in lines:
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 4:
            print(f"pre-push: malformed ref line: {line!r}", file=sys.stderr)
            return 2
        _, local, _, remote = fields
        if local == ZERO:
            continue
        base = comparison_base(local, remote)
        links = link_inputs(local)
        if base is None:
            print(f"pre-push: {local[:12]}: no comparison base; weakened-test scan skipped",
                  file=sys.stderr)
            commands: "list[tuple[str, ...]]" = list(SELECTION + RECONCILE)
            if links != set():
                commands += LINKS_CHECK + LINKS_SELFTEST
            if holds(local, CONTRACT):
                commands += CONTRACT_CHECK
            if holds(local, CONTRACT) and holds(local, REPLAY):
                commands += REPLAY_CHECK
            if holds(local, JUDGES):
                commands += JUDGES_TEST
            if holds(local, GAMEDAY):
                commands += GAMEDAY_TEST
            if holds(local, HOST_STOP):
                commands += HOST_STOP_TEST
            guard = True
        else:
            if (base, local) not in scans:
                scans.append((base, local))
            paths = [p for p in git("diff", "--no-renames", "--no-relative", "--ignore-submodules=none",
                                    "--name-only", "-z", base, local).split("\0") if p]
            commands = checks_for(paths, verus_sources(local), links,
                                  ignore_changed=changes_ignore(base, local, paths),
                                  judges_held=any(p in JUDGES_SOURCES for p in paths) and holds(local, JUDGES),
                                  replay_held=holds(local, REPLAY),
                                  gameday_held=not any(p in GAMEDAY_OWN for p in paths)
                                  and any(gameday_input(p) for p in paths) and holds(local, GAMEDAY),
                                  host_stop_held=not any(p in HOST_STOP_OWN for p in paths)
                                  and any(host_stop_input(p) for p in paths) and holds(local, HOST_STOP))
            guard = chaos_change(paths)
        if guard and local not in guarded:
            guarded.append(local)
        # The scan treats ancestors of the destination's remote-tracking refs as
        # known to the destination, though those refs can be stale. When
        # `base == remote`, it also treats the advertised commit and its
        # ancestors as known. Any other commit reachable from `local` may be
        # new to the destination.
        known = ((remote,) if base == remote else ()) + tracked
        listed = git("rev-list", "--full-history", local, *(("--not", *known) if known else ()), "--",
                     *(f":(top){d}" for d in RECORD_DIRS)).split()
        pushed += [c for c in listed if c not in pushed]
        merged = planned.setdefault(local, [])
        merged += [c for c in commands if c not in merged]
    failures = []
    for base, commit in scans:
        failures += scan(base, commit)
    records = []
    for commit in guarded:
        found, held = tip_records(commit)
        failures += found
        records += held
    found, held = pushed_records(pushed)
    failures += found + account_numbers(records + held)
    for commit, commands in planned.items():
        if commands:
            failures += run_in_worktree(commit, sorted(commands, key=ORDER.index))
    for failure in failures:
        print(f"pre-push: failed: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    for handled in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(handled, exit_on_signal)
    try:
        sys.exit(main(sys.stdin.read().splitlines(), *sys.argv[1:2]))
    except (GitError, ValueError) as error:
        print(f"pre-push: {error}", file=sys.stderr)
        sys.exit(2)
