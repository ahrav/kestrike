#!/usr/bin/env python3
"""Self-test of plant-runner.py over a small Git fixture and a stand-in `campaign`.

The fixture is a repository whose one file `mode` reads `base`. Each plant's
patch rewrites `mode`, and the stand-in `campaign` reads the mode of the tree
it archives to act out one outcome: a catch, a pass, a tree that does not
build, an alarm, a suspect `confirm` makes no finding of, a suspect whose seed
also fails on the unpatched head, and more. The stand-in adds 200 runs to each
profile a sweep, and 100 to the profile `slow`, so a floor of 300 takes two
sweeps, or three with `slow`. A seed check passes only on the archive of
mode `base` and only for a seed other than 665 (a complete run that fails),
666 (fails), 777 (refused) and 555 (exits 0 with another class than `counts`).

Every Git command of the fixture and of the runner it starts runs with the
caller's Git variables removed and the global and system configuration
replaced by files of the fixture.

Run: python3 scripts/test-plant-runner.py
"""

import hashlib
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

RUNNER = Path(__file__).resolve().with_name("plant-runner.py")
# Fixtures live under the checkout's ignored target/, as the sibling self-tests' do, so the runner's refusal of a
# work directory under a shared ancestor, such as /tmp, does not refuse them; the pinned umask keeps their
# modes the same on every host.
SCRATCH = RUNNER.parents[1] / "target" / "test-plant-runner"
os.umask(0o022)


def discard(path):
    """Removes the directory `path` and everything under it, when it exists."""
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        return


def scratch_directory():
    SCRATCH.mkdir(mode=0o700, parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix="case-", dir=SCRATCH)).resolve()

STAND_IN = textwrap.dedent(
    r'''
    #!/usr/bin/env python3
    import hashlib, json, os, signal, subprocess, sys, time
    from pathlib import Path

    args = sys.argv[1:]
    LOG = Path(os.environ["STANDIN_LOG"])
    with open(LOG, "a") as log:
        log.write(json.dumps(args) + "\n")
    # With `STANDIN_BLOCK_SCORE`, each call makes that path a directory.
    if os.environ.get("STANDIN_BLOCK_SCORE"):
        Path(os.environ["STANDIN_BLOCK_SCORE"]).mkdir(exist_ok=True)

    def option(name):
        return args[args.index(name) + 1]

    def digest(mode):
        return hashlib.sha256(mode.encode()).hexdigest()

    def mode_of(archive):
        return (Path(archive) / "mode").read_text().strip()

    def hold_until_released(number, frame):
        """Marks that SIGTERM arrived, then waits, at most 30 s, for the test's release before it exits."""
        (LOG.parent / "handling").write_text(str(number))
        for _ in range(600):
            if (LOG.parent / "release").exists():
                break
            time.sleep(0.05)
        (LOG.parent / "terminated").write_text(str(number))
        sys.exit(4)

    # Each mode's suspect lines: (profile, run, seed, class); None names the last swept profile.
    ONE = [(None, 7, 42, "violation")]
    # Eight differing replays of other runs than 7: the most lines the sweep writes under one key.
    EIGHT = [(None, run, 42, "replay differs") for run in range(20, 28)]
    # Suspects the sweep counted under a key past the lines it wrote: mode -> (profile, key, count); None
    # names the last swept profile.
    UNLISTED = {"replayunlisted": (None, "replay differs: a rule", 1), "otherunlisted": (None, "other", 1),
                "manyviolations": (None, "violation: a rule", 12), "replayelsewhere": ("a", "replay differs: x", 1)}
    SUSPECTS = {
        "panic": [(None, 7, 42, "panic")],
        "second": [(None, 7, 666, "violation"), (None, 8, 42, "violation")],
        "passthenfail": [(None, 7, 42, "violation"), (None, 8, 666, "violation")],
        "dup": [(None, 7, 666, "violation"), (None, 7, 666, "violation")],
        "headfail": [(None, 7, 666, "violation")],
        "lonehead": [(None, 7, 665, "violation")],
        "rejectseed": [(None, 7, 777, "violation")],
        "oddthen": [(None, 7, 777, "violation"), (None, 8, 42, "violation")],
        "violatehead": [(None, 7, 665, "violation"), (None, 8, 42, "violation")],
        "laterfinding": [(None, 7, 42, "violation"), (None, 8, 42, "violation")],
        "other": [(None, 7, 42, "wall limit")],
        "gapfirst": [("gap", 7, 42, "violation"), ("a", 8, 42, "violation")],
        "gaplast": [("a", 7, 42, "violation"), ("gap", 8, 42, "violation")],
        "replaydiffers": [(None, 7, 42, "violation"), (None, 7, 42, "replay differs"), (None, 8, 42, "violation")],
        "replayonly": [(None, 7, 42, "violation"), (None, 7, 42, "replay differs")],
        "replayunlisted": [(None, 7, 42, "violation"), *EIGHT],
        "replaylisted": [(None, 7, 42, "violation"), *EIGHT],
        "otherunlisted": ONE,
        "replayelsewhere": [("a", 7, 42, "violation"), ("b", 8, 42, "violation")],
        "manyviolations": ONE,
        "nokeys": ONE,
        "oddkeys": ONE,
        "emptykeys": ONE,
        "shortkeys": ONE,
        "lowkey": [(None, 7, 42, "violation"), (None, 8, 42, "violation")],
        "history": [("h-history", 3, 42, "violation")],
        "catchbroken": [("a", 7, 42, "violation"), ("ghost", 8, 42, "violation")],
        "noresult": [(None, 7, 888, "violation")],
        "oddfinding": [(None, 7, 42, "violation"), (None, 8, 42, "violation")],
        "oddpass": [(None, 7, 555, "violation")],
        "twopass": [(None, 7, 42, "violation"), (None, 8, 43, "violation")],
        "longest": [(None, 7, 2 ** 64 - 1, "violation")],
    }
    HELD = ("held", "heldnone", "heldother", "heldrejected", "heldomitted", "heldmixed", "heldpaused")
    for mode in ("catch", "catchalarm", "refuse", "mismatch", "watchdog", "otherprofile", "otherseed", "queued",
                 "nomanifest", "wide", "deepconfirm", "othermanifest", "noid", "badrun", "boolrun", "confirmfail",
                 *HELD):
        SUSPECTS[mode] = ONE

    if args[:2] == ["sim", "archive"]:
        mode = Path("mode").read_text().strip()
        target = Path(os.environ["CARGO_TARGET_DIR"])
        target.mkdir(parents=True, exist_ok=True)
        (target / "built").write_text(mode)
        if mode == "nobuild" or (mode == "base" and os.environ.get("STANDIN_BASE_FAIL")):
            sys.exit(3)
        if mode == "refusedarchive":
            sys.exit(2)
        if mode == "lock":
            subprocess.run(["git", "worktree", "lock", "--reason", "a test", os.getcwd()], check=True)
        if mode == "hangbuild":
            signal.signal(signal.SIGTERM, hold_until_released)
            (LOG.parent / "ready").write_text("")
            time.sleep(60)
            sys.exit(0)
        out = Path(option("--output"))
        out.mkdir()
        (out / "mode").write_text(mode)
        if mode == "otherlock":
            (out / "Cargo.lock").write_text("another resolution\n")
        elif mode not in ("nolock", "nolockarchive"):
            (out / "Cargo.lock").write_bytes(Path("Cargo.lock").read_bytes())
        names = ("CARGO_PROFILE_DEV_OPT_LEVEL", "CARGO_PROFILE_DEV_DEBUG_ASSERTIONS", "CARGO_TARGET_DIR",
                 "CARGO_BUILD_BUILD_DIR")
        seen = {name: os.environ.get(name) for name in names}
        seen["lockfile"] = Path("Cargo.lock").read_text()
        if "CARGO_RESOLVER_LOCKFILE_PATH" in os.environ:
            (LOG.parent / "archive-lockfile-path").write_text(os.environ["CARGO_RESOLVER_LOCKFILE_PATH"])
        watched = Path(os.environ["STANDIN_WATCH"])
        seen["proof"] = {name: (watched / name).exists() for name in ("target", "tree")}
        (out / "env").write_text(json.dumps(seen))
        print(json.dumps({"build": digest(mode), "executable": "x-" + mode, "platform": "p-" + mode,
                          "toolchain": "t-" + mode}))
    elif args[0] == "sweep":
        root, mode = Path(option("--root")), mode_of(option("--archive"))
        if mode == "hang":
            signal.signal(signal.SIGTERM, hold_until_released)
            (LOG.parent / "ready").write_text("")
            time.sleep(60)
            sys.exit(0)
        profiles = option("--profiles").split(",")
        root.mkdir(mode=0o700, exist_ok=True)
        (root / "manifests").mkdir(exist_ok=True)
        path = root / "state.json"
        state = json.loads(path.read_text()) if path.exists() else {"profiles": {}}
        for profile in profiles:
            if mode == "nomanifest":
                continue
            if mode == "catchbroken" and profile == "ghost":
                state["profiles"].setdefault(profile, {"next": 400, "runs": 300, "pass": 300, "suspects": 0})
                continue
            totals = state["profiles"].setdefault(profile, {"next": 0, "runs": 0, "pass": 0, "suspects": 0, "replays": 1,
                                                                 "uncredited": {}})
            added = 0 if mode == "short" else 100 if profile == "slow" else 200
            totals["next"] += added
            totals["runs"] += added - 50 if added else 0
            totals["pass"] += added - 50 if added else 0
            if mode == "norun":
                totals["runs"] = totals["pass"] = 0
            if mode == "overrun":
                totals["runs"] = totals["next"] + 1
            if mode == "nocount":
                del totals["suspects"]
            if profile == "gap":
                continue
            (root / "manifests" / f"{profile}.manifest").write_text(
                f"version = 2\nprofile = {profile}\nroot = 1\nexecutable = x-{mode}\n"
                f"toolchain = t-{mode}\nbuild = {digest(mode)}\nplatform = p-{mode}\nturns = 9\n"
            )
        if mode in SUSPECTS and not (root / "suspects.jsonl").exists():
            lines = []
            for profile, run, seed, kind in SUSPECTS[mode]:
                profile = profile or profiles[-1]
                summary = {"rule": "a rule\u2028across a line separator"} if mode == "wide" else None
                lines.append(json.dumps({"profile": profile, "run": run, "seed": seed, "class": kind,
                                         "key": f"{kind}: a rule", "build": digest(mode), "summary": summary},
                                        ensure_ascii=False))
                entry = state["profiles"].setdefault(profile, {"next": 1, "runs": 1, "pass": 0, "suspects": 0})
                entry["suspects"] += 1
                keys = entry.setdefault("suspect_keys", {})
                keys[f"{kind}: a rule"] = keys.get(f"{kind}: a rule", 0) + 1
            if mode in UNLISTED:
                profile, key, more = UNLISTED[mode]
                entry = state["profiles"][profile or profiles[-1]]
                entry["suspects"] += more
                entry["suspect_keys"][key] = entry["suspect_keys"].get(key, 0) + more
            if mode == "nokeys":
                del state["profiles"][profiles[-1]]["suspect_keys"]
            if mode == "oddkeys":
                state["profiles"][profiles[-1]]["suspect_keys"]["violation: a rule"] = True
            if mode == "emptykeys":
                state["profiles"][profiles[-1]]["suspect_keys"] = {}
            if mode == "shortkeys":
                state["profiles"][profiles[-1]]["suspects"] += 1
            if mode == "lowkey":
                state["profiles"][profiles[-1]]["suspect_keys"] = {"violation: a rule": 1, "violation: b": 1}
            (root / "suspects.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
        if mode == "loneline" and not (root / "suspects.jsonl").exists():
            (root / "suspects.jsonl").write_text(json.dumps({"profile": "a", "run": 3, "seed": 5, "class": "wall limit",
                                                             "key": "wall limit"}) + "\n")
        if mode == "cutline" and not (root / "suspects.jsonl").exists():
            (root / "suspects.jsonl").write_text('{"profile": "a", "run": 3')
        if mode == "disorder":
            state["profiles"]["a"]["pass"] = state["profiles"]["a"]["runs"] + 1
        if mode == "historynocount":
            state["profiles"]["h-history"] = {"next": 5, "runs": 5, "pass": 5}
        if mode == "badline" and not (root / "suspects.jsonl").exists():
            (root / "suspects.jsonl").write_text('{"profile": "a", "run": "seven"}\n')
        if mode == "dirlog":
            (root / "suspects.jsonl").mkdir(exist_ok=True)
        if mode in ("alarm", "catchalarm"):
            state["alarm"] = 1
        if mode == "nopass":
            state["no_pass"] = profiles[:1]
        if mode == "unreached":
            state["unreached"] = {profiles[0]: ["a required event"]}
        if mode == "nowindow":
            state["no_window"] = {profiles[0]: ["a planned window"]}
        state["campaign"] = "another" if mode == "othercampaign" else option("--campaign")
        path.write_text(json.dumps(state))
        failing = ("alarm", "catchalarm", "nopass", "unreached", "nowindow", "exitone")
        sys.exit(4 if mode == "damaged" else 1 if mode in failing else 0)
    elif args[0] == "sweep-status":
        root = Path(option("--root"))
        state = json.loads((root / "state.json").read_text())
        total = sum(totals.get("suspects", 0) for totals in state["profiles"].values())
        if mode_of(Path(option("--root")).parent / "archive") == "rootsuspect":
            total += 1
        if mode_of(Path(option("--root")).parent / "archive") == "statusfail":
            sys.exit(2)
        if mode_of(root.parent / "archive") == "badbytes":
            sys.stdout.buffer.write(b"\xff\xfe\n")
            sys.exit(0)
        total = {"booltotal": False, "floattotal": 0.0}.get(mode_of(root.parent / "archive"), total)
        controls, histories = {"caught": 3, "missed": 0}, {"caught": 2, "missed": 0}
        counts = {"nodes": 5} if mode_of(root.parent / "archive") == "othercounts" else {}
        print(json.dumps({"counts": counts, "suspects": total, "controls": controls, "histories": histories, **state}))
    elif args[0] == "confirm":
        root, mode = Path(option("--root")), mode_of(option("--archive"))
        if mode == "deepconfirm":
            print("[" * 100000)
            sys.exit(0)
        if mode == "confirmfail":
            sys.exit(2)
        findings = []
        for number, line in enumerate((root / "suspects.jsonl").read_text(encoding="utf-8").split("\n")[:-1]):
            suspect = json.loads(line)
            if mode == "laterfinding" and number == 0:
                continue
            run = suspect["run"] + (1 if mode == "mismatch" else 0)
            profile = "other" if mode == "otherprofile" else suspect["profile"]
            seed = suspect["seed"] + (1 if mode == "otherseed" else 0)
            template = root / "manifests" / f"{suspect['profile']}.manifest"
            lines = template.read_text().splitlines() if template.exists() else []
            seeded = "".join((f"root = {seed}" if line.startswith("root = ") else line) + "\n" for line in lines)
            manifest = hashlib.sha256(seeded.encode()).hexdigest() if mode != "othermanifest" else "0" * 64
            job = {"experiment": {"profile": profile, "run": run}, "seed": seed, "manifest_sha256": manifest}
            kind = "watchdog" if mode == "watchdog" else suspect["class"]
            if mode == "badrun":
                job["experiment"]["run"] = str(run)
            if mode == "boolrun":
                job["experiment"]["run"] = True
            identity = None if mode == "noid" else f"finding-{number}"
            findings.append({"id": identity, "verified": {"admission": {"job": job}, "kind": kind}})
            if mode == "oddfinding" and number == 1:
                findings[-1]["verified"] = ["no object"]
        if mode in ("refuse", "heldnone"):
            findings = []
        dispatch = "paused" if mode in ("queued", "heldpaused") else "held" if mode in HELD else "queue_empty"
        backlog = ("backlog holds 64 failure pins without a resolved disposition at limit 64; dispose findings "
                   "or raise backlog")
        refusals = [backlog] if mode in HELD else []
        if mode == "heldother":
            refusals = ["state moved during findings"]
        if mode == "heldmixed":
            refusals.append("state moved during findings")
        if mode == "heldomitted":
            print("omitted refusals: 3", file=sys.stderr)
        rejections = ["a job the archive refused"] if mode == "heldrejected" else []
        print(json.dumps({"dispatch": dispatch, "refusals": refusals, "rejections": rejections,
                          "findings": {"findings": findings, "release_blockers": []}}))
        print(json.dumps({"exit": 4 if refusals else 0}))
        sys.exit(4 if refusals else 0)
    elif args[:2] == ["sim", "run"]:
        mode = mode_of(option("--archive"))
        manifest = dict(line.split(" = ", 1) for line in Path(option("--manifest")).read_text().splitlines())
        if manifest["build"] != digest(mode) or manifest["executable"] != "x-" + mode or manifest["root"] == "777":
            print(json.dumps({"class": "rejected", "reason": "the manifest names another build"}))
            sys.exit(2)
        if manifest["root"] == "665":
            print(json.dumps({"class": "complete", "reason": "complete: a rule failed"}))
            sys.exit(1)
        if mode == "base" and manifest["root"] == "888":
            print("no result")
            sys.exit(4)
        if mode == "base" and manifest["root"] == "555":
            print(json.dumps({"class": "complete", "reason": "complete: unsuccessful"}))
            sys.exit(0)
        failing = manifest["root"] == "666" or mode != "base"
        reason = "the run panicked" if failing else "counts: complete pass"
        print(json.dumps({"class": "incomplete" if failing else "counts", "reason": reason,
                          "artifact": option("--artifacts")}))
        sys.exit(4 if failing else 0)
    else:
        sys.exit(2)
    '''
).lstrip()

# `REPRODUCE` is the fixture's `scripts/reproduce-test.py`. It imports without side effects and gives the helper's
# `RESULTS` and `reported`, so the runner loads its verdict check from the staged copy. Run, it reads the tree's
# `mode` and exits:
# - `base`: the code `STANDIN_HEAD_PROOFS` gives the test ID, or 0, with the line `STANDIN_HEAD_LINES` gives it,
#   or bytes that are no UTF-8 text and 0 for a test ID in `STANDIN_BINARY_PROOFS`;
# - `notlive`, `silentpass`: 0; `swappass`: 0 beside the line of exit 1;
# - `brokenproof`: 3, a library-test build failure; `rejectproof`: 2; `crashproof`: 4; `watchproof`: 6;
# - `hangproof`: 4, once the test releases the SIGTERM it holds;
# - any other mode: 1, a failing test; `swapfail` prints the line of exit 0 and `trailfail` a line after its
#   verdict. In `nobuild`, library tests build and the archive build fails.
# It prints the verdict line of its exit; `silentpass`, `silentfail` and a `base` test ID in `STANDIN_SILENT_PROOFS`
# print none, to stand for a helper that ended before it ran a test. It writes an artifact pointer to stderr, as the
# helper does. Each call logs the mode, the working directory, `CARGO_TARGET_DIR`, `CARGO_BUILD_BUILD_DIR`, the
# tree's Cargo.lock, whether the rerun is a session leader, and the arguments. Each call creates the target
# directory and writes a `CARGO_RESOLVER_LOCKFILE_PATH` it sees to `lockfile-path` beside the log. `relock`, and
# `base` under `STANDIN_RELOCK_HEAD`, rewrite the tree's Cargo.lock and `unlock` removes it; `pintarget` leaves a
# directory in the target that its owner cannot empty; under `STANDIN_REWRITE`, a JSON pair of a path and a text,
# the mode `STANDIN_REWRITE_IN` (by default `pass`) writes that text there.
REPRODUCE = textwrap.dedent(
    r'''
    #!/usr/bin/env python3
    import json, os, signal, sys, time
    from pathlib import Path

    RESULTS = {0: "not reproduced", 1: "reproduced", 2: "rejected input", 3: "build failure", 4: "crash",
               6: "watchdog expiry"}
    DETAILS = {0: " in 1 attempts", 1: ": reproduced on attempt 1", 2: ": no test named it", 3: ": the build exited 101",
               4: ": the test died of signal 11", 6: ": attempt 1 ran past 1500 s"}


    def reported(code, verdict):
        """The fixture's verdict check, as the helper's: exits 0, 1 and 6 beside a line that names the same result."""
        return code in (0, 1, 6) and verdict.startswith(RESULTS[code])


    def main():
        log_path = Path(os.environ["STANDIN_PROOF_LOG"])

        def end(code, silent=False, line=None):
            """Prints the verdict line of `code`, or `line`, unless `silent`, and exits `code`."""
            if not silent:
                print(line if line is not None else RESULTS[code] + DETAILS[code])
            sys.exit(code)

        def hold_until_released(number, frame):
            """Marks that SIGTERM arrived, then waits, at most 30 s, for the test's release before it exits."""
            (log_path.parent / "handling").write_text(str(number))
            for _ in range(600):
                if (log_path.parent / "release").exists():
                    break
                time.sleep(0.05)
            (log_path.parent / "terminated").write_text(str(number))
            sys.exit(4)

        mode = Path("mode").read_text().strip()
        target, build = os.environ.get("CARGO_TARGET_DIR"), os.environ.get("CARGO_BUILD_BUILD_DIR")
        lock = Path("Cargo.lock").read_text() if Path("Cargo.lock").exists() else None
        leader = os.getsid(0) == os.getpid()
        with open(log_path, "a") as log:
            log.write(json.dumps([mode, os.getcwd(), target, build, lock, leader, *sys.argv[1:]]) + "\n")
        if target:
            Path(target).mkdir(parents=True, exist_ok=True)
        print(f"artifact: {sys.argv[sys.argv.index('--artifacts') + 1]}", file=sys.stderr)
        if "CARGO_RESOLVER_LOCKFILE_PATH" in os.environ:
            (log_path.parent / "lockfile-path").write_text(os.environ["CARGO_RESOLVER_LOCKFILE_PATH"])
        if mode == "relock" or (mode == "base" and os.environ.get("STANDIN_RELOCK_HEAD")):
            Path("Cargo.lock").write_text("# another resolution\n")
        if mode == "unlock":
            Path("Cargo.lock").unlink()
        if mode == "pintarget" and target:
            pinned = Path(target) / "pinned"
            pinned.mkdir()
            (pinned / "file").write_text("held")
            pinned.chmod(0o500)
        rewrite = os.environ.get("STANDIN_REWRITE")
        if rewrite and mode == os.environ.get("STANDIN_REWRITE_IN", "pass"):
            place, written = json.loads(rewrite)
            Path(place).write_text(written)
        test = sys.argv[sys.argv.index("--test") + 1]
        if mode == "base" and test in json.loads(os.environ.get("STANDIN_BINARY_PROOFS", "[]")):
            sys.stdout.buffer.write(b"\xff\xfe not text\n")
            sys.exit(0)
        if mode == "base":
            codes = json.loads(os.environ.get("STANDIN_HEAD_PROOFS", "{}"))
            lines = json.loads(os.environ.get("STANDIN_HEAD_LINES", "{}"))
            end(int(codes.get(test, 0)), test in json.loads(os.environ.get("STANDIN_SILENT_PROOFS", "[]")),
                lines.get(test))
        if mode == "hangproof":
            signal.signal(signal.SIGTERM, hold_until_released)
            (log_path.parent / "ready").write_text("")
            time.sleep(60)
            sys.exit(0)
        lines = {"swappass": RESULTS[1] + DETAILS[1], "swapfail": RESULTS[0] + DETAILS[0],
                 "trailfail": RESULTS[1] + DETAILS[1] + "\nthe run's last words"}
        codes = {"notlive": 0, "silentpass": 0, "brokenproof": 3, "swappass": 0, "watchproof": 6, "rejectproof": 2,
                 "crashproof": 4}
        end(codes.get(mode, 1), mode in ("silentpass", "silentfail"), lines.get(mode))


    if __name__ == "__main__":
        main()
    '''
).lstrip()

CAUSE = {"cause": "workload", "evidence": "No run reaches the planted state."}

# Each plant of the default run: the mode its patch writes, its expected profiles, its miss_cause and the line
# its patch replaces.
PLANTS = {
    "p-catch": ("catch", ["a", "b"], None, "base"),
    "p-miss": ("pass", ["a"], CAUSE, "base"),
    "p-nocause": ("pass", ["a"], None, "base"),
    "p-noprofile": ("pass", [], {"cause": "environment", "evidence": "No profile runs the file."}, "base"),
    "p-stale": ("pass", ["a"], CAUSE, "other"),
    "p-nobuild": ("nobuild", ["a"], CAUSE, "base"),
    "p-alarm": ("alarm", ["a"], CAUSE, "base"),
    "p-headfail": ("headfail", ["a"], CAUSE, "base"),
    "p-refuse": ("refuse", ["a"], CAUSE, "base"),
    "p-other": ("other", ["a"], CAUSE, "base"),
    "p-short": ("short", ["a"], CAUSE, "base"),
}

# Plants for the cases of one test each, kept out of the default run: each is `p-<mode>`, sweeps `a`, has a cause
# and replaces the line `base`. A case's store holds one from the first run that names it (`Fixture.stock`).
MODES = (
    "panic", "catchalarm", "second", "passthenfail", "dup", "mismatch", "watchdog", "rejectseed", "history",
    "hang", "hangbuild", "oddthen", "violatehead", "lonehead", "otherprofile", "otherseed", "laterfinding",
    "nomanifest", "damaged", "queued", "held", "heldnone", "heldother", "nopass", "unreached", "nocount", "wide",
    "badline", "dirlog", "deepconfirm", "refusedarchive", "lock", "othermanifest", "noid", "boolrun", "confirmfail",
    "noresult", "otherlock", "nolock", "loneline", "cutline", "disorder", "othercampaign", "exitone", "rootsuspect",
    "statusfail", "booltotal", "floattotal", "oddfinding", "notlive", "brokenproof", "hangproof", "silentpass",
    "silentfail", "relock", "unlock", "pintarget", "watchproof", "rejectproof", "crashproof", "swappass", "swapfail",
    "trailfail", "replaydiffers", "replayonly", "badrun", "replayunlisted", "replaylisted", "otherunlisted",
    "manyviolations", "nokeys", "oddkeys", "emptykeys", "shortkeys", "lowkey",
    "oddpass", "twopass", "heldrejected", "heldomitted", "heldmixed", "heldpaused", "norun", "overrun", "badbytes",
    "othercounts", "historynocount", "nowindow",
)
EXTRA = {f"p-{mode}": (mode, ["a"], CAUSE, "base") for mode in MODES}
EXTRA["p-gapfirst"] = ("gapfirst", ["a", "gap"], CAUSE, "base")
EXTRA["p-gaplast"] = ("gaplast", ["a", "gap"], CAUSE, "base")
EXTRA["p-nolockarchive"] = ("nolockarchive", [], CAUSE, "base")
EXTRA["p-slow"] = ("pass", ["a", "slow"], CAUSE, "base")
EXTRA["p-catchbroken"] = ("catchbroken", ["a", "ghost"], CAUSE, "base")
EXTRA["p-replayelsewhere"] = ("replayelsewhere", ["a", "b"], CAUSE, "base")
EXTRA["base"] = ("catch", ["a"], CAUSE, "base")
# Plants that need a signal or a broken root, or that leave the proof's worktree or target unfit for every later
# plant, and so stay out of the run of every plant.
APART = ("p-hang", "p-hangbuild", "p-hangproof", "p-relock", "p-unlock", "p-pintarget")


def digest(mode):
    return hashlib.sha256(mode.encode()).hexdigest()


def handled_signals():
    """Gives the runner's child the default dispositions of the signals the runner handles, so a suite started
    with one of them ignored still tests a handled signal."""
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, signal.SIG_DFL)


def clean_environment(scratch):
    """The caller's environment without its Git variables, with the fixture's own Git configuration files."""
    environment = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    (scratch / "gitconfig").touch()
    environment.update(
        GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=str(scratch / "gitconfig"), GIT_CEILING_DIRECTORIES=str(scratch),
        GIT_AUTHOR_NAME="fixture", GIT_AUTHOR_EMAIL="fixture@invalid", GIT_COMMITTER_NAME="fixture",
        GIT_COMMITTER_EMAIL="fixture@invalid",
    )
    return environment


def patch_of(mode, before):
    return f"--- a/mode\n+++ b/mode\n@@ -1 +1 @@\n-{before}\n+{mode}\n"


def write_plant(store, name, mode, expected, cause, before, fields=None, patch=None):
    place = store / name
    place.mkdir(parents=True)
    record = {
        "id": name, "row": 1, "fix": {"pull_request": 1, "commit": "0" * 40}, "files": ["mode"],
        "restores": "A defect.", "proof": "a::test", "expected": expected, "miss_cause": cause,
    }
    record.update(fields or {})
    (place / "plant.json").write_text(json.dumps(record))
    (place / "plant.patch").write_text(patch or patch_of(mode, before))
    return place


class Fixture(unittest.TestCase):
    """One repository, plant store and stand-in `campaign` a test. The store starts with the plants of `PLANTS`,
    and `stock` adds each plant of `EXTRA` that a run names, so a run checks the plants its case uses."""

    def setUp(self):
        self.scratch = scratch_directory()
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.env = clean_environment(self.scratch)
        self.repo = self.scratch / "repo"
        self.repo.mkdir()
        self.git("init", "--quiet")
        (self.repo / "mode").write_text("base\n")
        (self.repo / ".gitignore").write_text("Cargo.lock\n")
        (self.repo / "Cargo.lock").write_text("# the checkout's resolution\n")
        self.hooked = self.scratch / "hooked"
        hook = self.repo / ".git" / "hooks" / "post-checkout"
        hook.write_text(f"#!/bin/sh\necho \"$PWD\" >> {self.hooked}\n")
        hook.chmod(0o755)
        (self.repo / "scripts").mkdir()
        (self.repo / "scripts" / "reproduce-test.py").write_text(REPRODUCE)
        (self.repo / "scripts" / "select-tests.py").touch()
        self.proofs = self.scratch / "proofs.jsonl"
        self.proofs.touch()
        self.store = self.repo / "verification" / "plants"
        for name, plant in PLANTS.items():
            write_plant(self.store, name, *plant)
        self.commit("fixture")
        self.head = self.git("rev-parse", "HEAD").strip()
        self.stand_in = self.scratch / "campaign"
        self.stand_in.write_text(STAND_IN)
        self.stand_in.chmod(0o755)
        self.log = self.scratch / "calls.jsonl"
        self.log.touch()
        self.score = self.store / "score.json"
        self.work = self.scratch / "work"

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), *args], capture_output=True, text=True, check=True,
                              env=self.env).stdout

    def commit(self, message):
        self.git("add", "--all")
        self.git("commit", "--quiet", "--no-gpg-sign", "--message", message)

    def stock(self, *names):
        """Writes each named plant of `EXTRA` that the store lacks and commits those plants alone, which moves
        `HEAD`; a case that compares the checkout across a run calls this before its first snapshot."""
        missing = [name for name in names if name in EXTRA and not (self.store / name).exists()]
        if not missing:
            return
        for name in missing:
            write_plant(self.store, name, *EXTRA[name])
        paths = [str(self.store / name) for name in missing]
        self.git("add", "--", *paths)
        self.git("commit", "--quiet", "--no-gpg-sign", "--message", "more plants", "--", *paths)
        self.head = self.git("rev-parse", "HEAD").strip()

    def argv(self, *names, extra=(), work=None):
        self.stock(*names)
        argv = [sys.executable, str(RUNNER), "--campaign", str(self.stand_in), "--work", str(work or self.work),
                "--workers", "2", "--for", "1", "--rounds", "3", *extra]
        for name in names:
            argv += ["--plant", name]
        return argv

    def environment(self, env=()):
        return dict(self.env, STANDIN_LOG=str(self.log), STANDIN_PROOF_LOG=str(self.proofs),
                    STANDIN_WATCH=str(self.work / "proof"), **dict(env))

    def run_plants(self, *names, extra=(), env=(), work=None):
        return subprocess.run(self.argv(*names, extra=extra, work=work), cwd=self.repo, env=self.environment(env),
                              capture_output=True, text=True, check=False)

    def results(self):
        try:
            written = json.loads(self.score.read_text())
        except (OSError, ValueError) as error:
            self.fail(f"the runner wrote no readable score: {error}")
        return written, {plant["id"]: plant for plant in written["plants"]}

    def calls(self, *prefix):
        try:
            calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        except (OSError, ValueError) as error:
            self.fail(f"the stand-in's call log is unreadable: {error}")
        return [call for call in calls if call[: len(prefix)] == list(prefix)]

    def proof_log(self):
        try:
            return [json.loads(line) for line in self.proofs.read_text().splitlines()]
        except (OSError, ValueError) as error:
            self.fail(f"the stand-in's proof log is unreadable: {error}")

    def rejected(self, done, text):
        self.assertEqual(done.returncode, 2, done.stderr)
        self.assertIn(text, done.stderr)
        self.assertEqual(self.calls(), [])
        self.assertFalse(self.work.exists())
        self.assertFalse(self.score.exists())

    def verdict(self, name, result, reason):
        _, plants = self.results()
        self.assertEqual(plants[name]["result"], result, plants[name].get("reason"))
        self.assertIn(reason, plants[name]["reason"])
        return plants[name]

    def state(self):
        return (
            self.git("rev-parse", "HEAD"),
            self.git("status", "--porcelain", "--ignored", "--untracked-files=all"),
            self.git("worktree", "list", "--porcelain"),
            self.git("for-each-ref"),
            self.git("stash", "list"),
            self.git("config", "--list", "--local"),
            (self.repo / "mode").read_text(),
            (self.repo / ".git" / "index").read_bytes(),
        )

    def git_shim(self, word, action):
        """The `PATH` entry of a `git` that runs the shell text `action` in place of each Git command one of
        whose arguments is `word`, and the real Git, named `$real` in `action`, for every other command."""
        shim = self.scratch / "bin"
        shim.mkdir()
        real = shutil.which("git", path=self.env.get("PATH"))
        (shim / "git").write_text(
            f"#!/bin/sh\nreal={real}\nfor word in \"$@\"; do\n  if [ \"$word\" = {word} ]; then\n"
            f"    {action}\n  fi\ndone\nexec \"$real\" \"$@\"\n")
        (shim / "git").chmod(0o755)
        return {"PATH": f"{shim}:{self.env.get('PATH', '')}"}


class Results(Fixture):
    def test_each_result_stands_in_the_score_with_its_reason(self):
        names = [name for name in PLANTS if name != "p-nocause"]
        done = self.run_plants(*names)
        self.assertEqual(done.returncode, 3, done.stderr)
        written, plants = self.results()
        self.assertEqual(written["commit"], self.head)
        self.assertEqual(written["sentence"], f"1 of 3 plants at commit {self.head}")
        self.assertEqual(written["results"], {"caught": 1, "missed": 2, "no verdict": 6, "does not apply": 1})
        self.assertIn(written["sentence"], done.stdout)
        for line in ("p-catch: caught (violation: a rule in run 7 of b)", "p-alarm: no verdict (the root holds alarm)",
                     "p-miss: missed (each expected profile reached 300 runs and the root holds no suspect)"):
            self.assertIn(line, done.stdout.splitlines())
        self.assertEqual(plants["p-stale"]["result"], "does not apply")
        reasons = {
            "p-nobuild": "the planted tree does not build",
            "p-alarm": "the root holds alarm",
            "p-headfail": "does not pass on the unpatched head: incomplete",
            "p-refuse": "made no finding of violation: a rule in run 7 of a",
            "p-other": "the root holds suspects in a (1)",
            "p-short": "a stayed below 300 runs after 3 sweeps",
        }
        for name, reason in reasons.items():
            self.verdict(name, "no verdict", reason)
        self.assertEqual(plants["p-alarm"]["keys"], {"alarm": 1})
        self.assertEqual(written["settings"]["base_archive"], digest("base"))
        self.assertEqual(written["settings"]["plants"], names)
        self.assertEqual(written["settings"]["campaign_sha256"],
                         hashlib.sha256(self.stand_in.read_bytes()).hexdigest())

    def test_a_plant_whose_proof_passes_on_the_plant_is_not_live_and_leaves_n(self):
        done = self.run_plants("p-miss", "p-notlive")
        self.assertEqual(done.returncode, 3, done.stderr)
        written, plants = self.results()
        self.assertEqual(written["sentence"], f"0 of 1 plants at commit {self.head}")
        self.assertEqual(written["results"], {"missed": 1, "not live": 1})
        self.assertEqual(written["not_live"], ["p-notlive"])
        record = self.verdict("p-notlive", "not live", "its proof exits 0 on the head and 0 on the plant")
        self.assertEqual(record["proof_exits"], {"head": 0, "plant": 0})
        self.assertIsNone(record["archive"])
        self.assertEqual(plants["p-miss"]["proof_exits"], {"head": 0, "plant": 1})
        self.assertEqual(len(self.calls("sim", "archive")), 1)
        proofs = self.proof_log()
        self.assertEqual([proof[0] for proof in proofs], ["base", "pass", "notlive"])
        place = self.work / "proof"
        for proof in proofs:
            self.assertEqual(proof[1:4], [str(place / "tree"), str(place / "target"), str(place / "target")])
            self.assertEqual(proof[4:6], ["# the checkout's resolution\n", True])
            self.assertEqual(proof[6:14], ["--package", "kestrike", "--target", "lib", "--attempts", "1",
                                           "--test", "a::test"])
        self.assertFalse((place / "target").exists())

    def test_each_plant_is_judged_by_its_own_proof_on_the_head(self):
        write_plant(self.store, "p-otherproof", "otherproof", ["a"], CAUSE, "base", fields={"proof": "b::test"})
        self.commit("another proof")
        done = self.run_plants("p-miss", "p-otherproof", "p-catch",
                               env={"STANDIN_HEAD_PROOFS": json.dumps({"b::test": 1})})
        self.assertEqual(done.returncode, 3, done.stderr)
        self.verdict("p-otherproof", "not live", "its proof exits 1 on the head and 1 on the plant")
        self.verdict("p-miss", "missed", "each expected profile reached 300 runs")
        proofs = self.proof_log()
        heads = [proof[proof.index("--test") + 1] for proof in proofs if proof[0] == "base"]
        self.assertEqual(sorted(heads), ["a::test", "b::test"])
        planted = [(proof[0], proof[proof.index("--test") + 1]) for proof in proofs if proof[0] != "base"]
        self.assertEqual(sorted(planted), [("catch", "a::test"), ("otherproof", "b::test"), ("pass", "a::test")])

    def test_a_plant_whose_proof_fails_on_the_head_is_not_live(self):
        done = self.run_plants("p-miss", env={"STANDIN_HEAD_PROOFS": json.dumps({"a::test": 1})})
        self.assertEqual(done.returncode, 3, done.stderr)
        self.verdict("p-miss", "not live", "its proof exits 1 on the head and 1 on the plant")
        self.assertEqual(self.calls("sim", "archive"), [])

    def test_a_head_whose_library_tests_do_not_build_fails_every_proof_from_one_rerun(self):
        write_plant(self.store, "p-otherproof", "otherproof", ["a"], CAUSE, "base", fields={"proof": "b::test"})
        self.commit("another proof")
        done = self.run_plants("p-miss", "p-otherproof", "p-catch",
                               env={"STANDIN_HEAD_PROOFS": json.dumps({"a::test": 3})})
        self.assertEqual(done.returncode, 3, done.stderr)
        for name in ("p-miss", "p-otherproof", "p-catch"):
            self.verdict(name, "no verdict", "the head's library tests do not build, so no proof reruns on the head: "
                                             "the rerun of the proof a::test exited 3; its verdict is in "
                                             "proof/head-0.out and its build output under proof/artifacts/head-0")
        self.assertEqual([proof[0] for proof in self.proof_log()], ["base"])
        self.assertFalse((self.work / "proof" / "head-1.out").exists())
        self.assertEqual(self.calls("sim", "archive"), [])

    def test_a_head_build_failure_at_a_later_proof_leaves_the_earlier_proof_s_plant_judged(self):
        write_plant(self.store, "p-otherproof", "otherproof", ["a"], CAUSE, "base", fields={"proof": "b::test"})
        self.commit("another proof")
        done = self.run_plants("p-miss", "p-otherproof", env={"STANDIN_HEAD_PROOFS": json.dumps({"b::test": 3})})
        self.assertEqual(done.returncode, 3, done.stderr)
        record = self.verdict("p-miss", "missed", "each expected profile reached 300 runs")
        self.assertEqual(record["proof_exits"], {"head": 0, "plant": 1})
        self.verdict("p-otherproof", "no verdict", "the rerun of the proof b::test exited 3; its verdict is in "
                                                   "proof/head-1.out")

    def test_a_proof_rerun_that_fails_to_run_on_a_plant_leaves_that_plant_no_verdict_and_resets_the_tree(self):
        done = self.run_plants("p-brokenproof", "p-miss")
        self.assertEqual(done.returncode, 3, done.stderr)
        broken = self.verdict("p-brokenproof", "no verdict",
                              "the rerun of the proof a::test exited 3; its verdict is in proof/plant-p-brokenproof.out "
                              "and its build output under proof/artifacts/plant-p-brokenproof")
        self.assertIsNone(broken["archive"])
        record = self.verdict("p-miss", "missed", "each expected profile reached 300 runs")
        self.assertEqual(record["proof_exits"], {"head": 0, "plant": 1})
        self.assertEqual(len(self.calls("sim", "archive")), 1)
        self.assertEqual([proof[0] for proof in self.proof_log()], ["base", "brokenproof", "pass"])

    def test_a_plant_whose_proof_fails_on_the_head_and_passes_on_the_plant_is_not_live(self):
        done = self.run_plants("p-notlive", env={"STANDIN_HEAD_PROOFS": json.dumps({"a::test": 1})})
        self.assertEqual(done.returncode, 3, done.stderr)
        record = self.verdict("p-notlive", "not live", "its proof exits 1 on the head and 0 on the plant")
        self.assertEqual(record["proof_exits"], {"head": 1, "plant": 0})
        written, _ = self.results()
        self.assertEqual(written["sentence"], f"0 of 0 plants at commit {self.head}")
        self.assertEqual(self.calls("sim", "archive"), [])

    def test_a_plant_rerun_that_exits_0_or_1_without_that_exit_s_verdict_line_leaves_no_verdict(self):
        done = self.run_plants("p-miss", "p-silentfail", "p-silentpass")
        self.assertEqual(done.returncode, 3, done.stderr)
        self.verdict("p-silentfail", "no verdict", "the rerun of the proof a::test exited 1 without the verdict "
                                                   "`reproduced`; its output is in proof/plant-p-silentfail.out")
        self.verdict("p-silentpass", "no verdict", "the rerun of the proof a::test exited 0 without the verdict "
                                                   "`not reproduced`; its output is in proof/plant-p-silentpass.out")
        self.verdict("p-miss", "missed", "each expected profile reached 300 runs")
        written, _ = self.results()
        self.assertEqual(written["not_live"], [])
        self.assertEqual(len(self.calls("sim", "archive")), 1)

    def test_a_head_rerun_that_exits_0_or_1_without_that_exit_s_verdict_line_leaves_no_verdict(self):
        write_plant(self.store, "p-otherproof", "otherproof", ["a"], CAUSE, "base", fields={"proof": "b::test"})
        self.commit("another proof")
        env = {"STANDIN_HEAD_PROOFS": json.dumps({"a::test": 1}), "STANDIN_SILENT_PROOFS": '["a::test", "b::test"]'}
        done = self.run_plants("p-miss", "p-otherproof", env=env)
        self.assertEqual(done.returncode, 3, done.stderr)
        self.verdict("p-miss", "no verdict", "the rerun of the proof a::test exited 1 without the verdict "
                                             "`reproduced`; its output is in proof/head-0.out")
        self.verdict("p-otherproof", "no verdict", "the rerun of the proof b::test exited 0 without the verdict "
                                                   "`not reproduced`; its output is in proof/head-1.out")
        written, _ = self.results()
        self.assertEqual(written["not_live"], [])
        self.assertEqual(self.calls("sim", "archive"), [])

    def test_a_plant_that_patches_the_proof_helper_is_judged_by_the_head_s_helper(self):
        forced = ("--- a/scripts/reproduce-test.py\n+++ b/scripts/reproduce-test.py\n@@ -1,2 +1,5 @@\n"
                  " #!/usr/bin/env python3\n+import sys\n+print(\"reproduced: reproduced on attempt 1\")\n"
                  "+sys.exit(1)\n import json, os, signal, sys, time\n")
        write_plant(self.store, "p-judge", "base", ["a"], CAUSE, "base",
                    fields={"files": ["scripts/reproduce-test.py"]}, patch=forced)
        self.commit("a plant that patches the helper")
        done = self.run_plants("p-judge")
        self.assertEqual(done.returncode, 3, done.stderr)
        self.verdict("p-judge", "not live", "its proof exits 0 on the head and 0 on the plant")
        self.assertEqual([proof[0] for proof in self.proof_log()], ["base", "base"])
        self.assertEqual(self.calls("sim", "archive"), [])

    def test_a_head_without_the_proof_helper_leaves_no_verdict(self):
        self.git("rm", "--quiet", "scripts/select-tests.py")
        self.commit("a head without the selector")
        done = self.run_plants("p-miss")
        self.assertEqual(done.returncode, 3, done.stderr)
        self.verdict("p-miss", "no verdict", "the head's scripts/select-tests.py cannot be copied: No such file")
        self.assertEqual(self.proof_log(), [])

    def test_a_proof_worktree_that_keeps_a_plant_after_a_failed_reset_judges_no_later_plant(self):
        side = "--- /dev/null\n+++ b/side\n@@ -0,0 +1 @@\n+planted\n"
        write_plant(self.store, "p-side", "base", ["a"], CAUSE, "base", fields={"files": ["side"]}, patch=side)
        self.commit("a plant on another file")
        marker = self.scratch / "fail-reset"
        marker.touch()
        once = f"if [ -e {marker} ]; then rm {marker}; echo \"the index is locked\" >&2; exit 128; fi"
        done = self.run_plants("p-miss", "p-side", env=self.git_shim("reset", once))
        self.assertEqual(done.returncode, 3, done.stderr)
        self.assertFalse(marker.exists())
        self.verdict("p-miss", "no verdict", "`git reset` exited 128; its error is in plants/p-miss/git.err")
        self.verdict("p-side", "no verdict", "the proof's worktree is no longer the head's tree: `git reset` exited "
                                             "128 at the plant p-miss")
        self.assertEqual([proof[0] for proof in self.proof_log()], ["base", "pass"])
        self.assertEqual(self.calls("sim", "archive"), [])

    def test_a_proof_or_profile_that_no_process_takes_as_an_argument_is_rejected_before_any_worktree(self):
        cases = (
            ({"proof": "a::\u0000test"}, "proof holds no NUL and is UTF-8 text"),
            ({"proof": "a::\udcfftest"}, "proof holds no NUL and is UTF-8 text"),
            ({"expected": ["a\u0000b"]}, "expected is a list of profile names campaign can take"),
            ({"expected": ["a\udcff"]}, "expected is a list of profile names campaign can take"),
        )
        for fields, rule in cases:
            with self.subTest(rule, fields=list(fields.values())):
                write_plant(self.store, "p-bad", "pass", ["a"], CAUSE, "base", fields=fields)
                self.commit("a record no process takes")
                before = self.state()
                done = self.run_plants("p-miss")
                self.assertEqual(done.returncode, 2, done.stderr)
                self.assertIn(f"p-bad: {rule}", done.stderr)
                self.assertFalse(self.work.exists())
                self.assertEqual(self.proof_log(), [])
                self.assertEqual(self.state(), before)
                self.git("reset", "--hard", "--quiet", self.head)

    def test_a_head_rerun_that_prints_no_text_leaves_only_its_own_proof_with_no_verdict(self):
        write_plant(self.store, "p-bproof", "otherproof", ["a"], CAUSE, "base", fields={"proof": "b::test"})
        write_plant(self.store, "p-third", "pass", ["a"], CAUSE, "base", fields={"proof": "c::test"})
        self.commit("three proofs")
        done = self.run_plants("p-miss", "p-bproof", "p-third", env={"STANDIN_BINARY_PROOFS": '["b::test"]'})
        self.assertEqual(done.returncode, 3, done.stderr)
        self.verdict("p-bproof", "no verdict", "`reproduce-test.py` exited 0 and printed no UTF-8 text")
        self.verdict("p-bproof", "no verdict", "its output is in proof/head-0.out")
        for name in ("p-miss", "p-third"):
            record = self.verdict(name, "missed", "each expected profile reached 300 runs")
            self.assertEqual(record["proof_exits"], {"head": 0, "plant": 1})
        heads = [proof[proof.index("--test") + 1] for proof in self.proof_log() if proof[0] == "base"]
        self.assertEqual(heads, ["b::test", "a::test", "c::test"])

    def test_a_rerun_that_rewrites_the_run_s_lockfile_leaves_that_plant_and_each_later_one_no_verdict(self):
        done = self.run_plants("p-miss", "p-relock", "p-slow")
        self.assertEqual(done.returncode, 3, done.stderr)
        self.verdict("p-miss", "missed", "each expected profile reached 300 runs")
        for name in ("p-relock", "p-slow"):
            self.verdict(name, "no verdict", "the rerun of the proof a::test left the proof's worktree without the "
                                             "run's Cargo.lock; its output is in proof/plant-p-relock.out")
        self.assertEqual([proof[0] for proof in self.proof_log()], ["base", "pass", "relock"])
        written, _ = self.results()
        self.assertEqual(written["not_live"], [])
        self.assertEqual(len(self.calls("sim", "archive")), 1)

    def test_a_head_rerun_that_rewrites_the_run_s_lockfile_ends_the_head_s_reruns(self):
        write_plant(self.store, "p-otherproof", "otherproof", ["a"], CAUSE, "base", fields={"proof": "b::test"})
        self.commit("another proof")
        done = self.run_plants("p-miss", "p-otherproof", env={"STANDIN_RELOCK_HEAD": "1"})
        self.assertEqual(done.returncode, 3, done.stderr)
        for name in ("p-miss", "p-otherproof"):
            self.verdict(name, "no verdict", "the rerun of the proof a::test left the proof's worktree without the "
                                             "run's Cargo.lock; its output is in proof/head-0.out")
        self.assertEqual([proof[0] for proof in self.proof_log()], ["base"])

    def test_a_rerun_that_removes_the_run_s_lockfile_leaves_no_verdict(self):
        done = self.run_plants("p-unlock")
        self.assertEqual(done.returncode, 3, done.stderr)
        self.verdict("p-unlock", "no verdict", "left the proof's worktree without the run's Cargo.lock; its output is "
                                               "in proof/plant-p-unlock.out")
        self.assertEqual(self.calls("sim", "archive"), [])

    def test_the_proof_reruns_pin_the_tree_s_lockfile_over_the_caller_s_path(self):
        done = self.run_plants("p-miss", env={"CARGO_RESOLVER_LOCKFILE_PATH": str(self.scratch / "elsewhere.lock")})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.verdict("p-miss", "missed", "each expected profile reached 300 runs")
        self.assertEqual(len(self.proof_log()), 2)
        self.assertEqual((self.scratch / "lockfile-path").read_text(), str(self.work / "proof" / "tree" / "Cargo.lock"))

    def test_the_proof_and_the_archive_apply_the_head_s_copy_of_the_patch(self):
        checkout = self.store / "p-miss" / "plant.patch"
        done = self.run_plants("p-miss", env={"STANDIN_REWRITE": json.dumps([str(checkout), patch_of("catch", "base")])})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(checkout.read_text(), patch_of("catch", "base"))
        record = self.verdict("p-miss", "missed", "each expected profile reached 300 runs")
        self.assertEqual(self.git("show", f"{record['commit']}:mode"), "pass\n")
        self.assertEqual((self.work / "plants" / "p-miss" / "archive" / "mode").read_text(), "pass")
        self.assertEqual([proof[0] for proof in self.proof_log()], ["base", "pass"])

    def test_the_head_reruns_only_the_proofs_of_plants_whose_patch_applies(self):
        write_plant(self.store, "p-stale-own", "pass", ["a"], CAUSE, "other", fields={"proof": "z::test"})
        self.commit("a stale plant with a proof of its own")
        done = self.run_plants("p-stale-own", "p-miss")
        self.assertEqual(done.returncode, 3, done.stderr)
        self.verdict("p-stale-own", "does not apply", "patch failed")
        self.verdict("p-miss", "missed", "each expected profile reached 300 runs")
        self.assertEqual([proof[proof.index("--test") + 1] for proof in self.proof_log()], ["a::test", "a::test"])
        self.assertFalse((self.work / "proof" / "head-1.out").exists())

    def test_a_run_where_no_patch_applies_reruns_no_proof(self):
        done = self.run_plants("p-stale")
        self.assertEqual(done.returncode, 3, done.stderr)
        self.verdict("p-stale", "does not apply", "patch failed")
        self.assertEqual(self.proof_log(), [])
        self.assertFalse((self.work / "proof").exists())

    def test_a_failed_proof_setup_is_kept_and_every_plant_reports_its_first_cause(self):
        (self.repo / ".gitignore").write_text("")
        self.git("add", "--force", "Cargo.lock")
        self.commit("a head that tracks its Cargo.lock")
        added = self.scratch / "added"
        done = self.run_plants("p-miss", "p-catch", env=self.git_shim("add", f"echo \"$*\" >> {added}"))
        self.assertEqual(done.returncode, 3, done.stderr)
        for name in ("p-miss", "p-catch"):
            self.verdict(name, "no verdict", "the proof's worktree already holds a Cargo.lock")
        proof_tree = str(self.work / "proof" / "tree")
        self.assertEqual(sum(proof_tree in line.split() for line in added.read_text().splitlines()), 1)
        self.assertEqual(self.proof_log(), [])
        self.assertFalse((self.work / "proof" / "tree").exists())

    def test_a_reset_that_fails_with_undecodable_output_judges_no_later_plant(self):
        side = "--- /dev/null\n+++ b/side\n@@ -0,0 +1 @@\n+planted\n"
        write_plant(self.store, "p-side", "base", ["a"], CAUSE, "base", fields={"files": ["side"]}, patch=side)
        self.commit("a plant on another file")
        marker = self.scratch / "fail-reset"
        marker.touch()
        once = f"if [ -e {marker} ]; then rm {marker}; printf '\\377\\376\\n' >&2; exit 1; fi"
        done = self.run_plants("p-miss", "p-side", env=self.git_shim("reset", once))
        self.assertEqual(done.returncode, 3, done.stderr)
        self.verdict("p-miss", "no verdict", "UnicodeDecodeError")
        self.verdict("p-side", "no verdict", "the proof's worktree is no longer the head's tree")
        self.assertEqual([proof[0] for proof in self.proof_log()], ["base", "pass"])
        self.assertEqual(self.calls("sim", "archive"), [])

    def test_an_apply_check_that_fails_itself_leaves_no_verdict_and_a_refused_patch_does_not_apply(self):
        done = self.run_plants("p-miss", "p-stale",
                               env=self.git_shim("--check", "echo 'fatal: a broken check' >&2; exit 128"))
        self.assertEqual(done.returncode, 3, done.stderr)
        for name in ("p-miss", "p-stale"):
            self.verdict(name, "no verdict", "`git apply` exited 128")
        self.assertEqual(self.proof_log(), [])
        done = self.run_plants("p-stale", work=self.scratch / "work-2")
        self.assertEqual(done.returncode, 3, done.stderr)
        self.verdict("p-stale", "does not apply", "patch failed")

    def test_an_ignored_file_in_the_store_is_rejected(self):
        (self.repo / ".git" / "info").mkdir(exist_ok=True)
        (self.repo / ".git" / "info" / "exclude").write_text("extra.txt\n")
        (self.store / "p-miss" / "extra.txt").write_text("ignored\n")
        self.rejected(self.run_plants("p-miss"), "differs from HEAD at verification/plants/p-miss/extra.txt")

    def test_the_verdict_check_comes_from_the_head_s_staged_helper(self):
        helper = self.repo / "scripts" / "reproduce-test.py"
        helper.write_text(helper.read_text().replace('0: "not reproduced", 1: "reproduced"', '0: "held", 1: "failed"'))
        self.commit("a head whose helper words its verdicts its own way")
        done = self.run_plants("p-miss")
        self.assertEqual(done.returncode, 0, done.stderr)
        record = self.verdict("p-miss", "missed", "each expected profile reached 300 runs")
        self.assertEqual(record["proof_exits"], {"head": 0, "plant": 1})
        helper.write_text(helper.read_text().replace("def reported(", "def unreported("))
        self.commit("a head whose helper has no verdict check")
        self.proofs.write_text("")
        done = self.run_plants("p-miss", "p-catch", work=self.scratch / "work-2")
        self.assertEqual(done.returncode, 3, done.stderr)
        for name in ("p-miss", "p-catch"):
            self.verdict(name, "no verdict", "the head's scripts/reproduce-test.py gives no verdict check: "
                                             "AttributeError")
        self.assertEqual(self.proof_log(), [])

    def test_a_proof_target_that_cannot_be_removed_holds_every_archive(self):
        if os.geteuid() == 0:
            self.skipTest("root removes a directory its owner cannot empty")
        self.addCleanup(lambda: (self.work / "proof" / "target" / "pinned").exists()
                        and (self.work / "proof" / "target" / "pinned").chmod(0o700))
        done = self.run_plants("p-miss", "p-pintarget")
        self.assertEqual(done.returncode, 3, done.stderr)
        for name in ("p-miss", "p-pintarget"):
            self.verdict(name, "no verdict", "the proof's proof/target remained after the last proof rerun")
        self.assertEqual(self.calls("sim", "archive"), [])
        self.assertIn("plant-runner left the proof's target directory", done.stderr)

    def test_a_seed_check_that_fails_leaves_another_suspect_s_catch_in_either_order(self):
        done = self.run_plants("p-gapfirst", "p-gaplast")
        self.assertEqual(done.returncode, 0, done.stderr)
        for name in ("p-gapfirst", "p-gaplast"):
            caught = self.verdict(name, "caught", "violation: a rule in run")
            self.assertEqual(caught["suspect"]["profile"], "a", name)

    def test_a_suspect_whose_replay_differs_gives_no_catch_and_leaves_another_seed_to_catch(self):
        done = self.run_plants("p-replaydiffers", "p-replayonly")
        self.assertEqual(done.returncode, 3, done.stderr)
        caught = self.verdict("p-replaydiffers", "caught", "violation: a rule in run 8 of a")
        self.assertEqual(caught["suspect"]["run"], 8)
        self.verdict("p-replayonly", "no verdict", "the sweep's replay of violation: a rule in run 7 of a differs")
        self.assertEqual(len(self.calls("sim", "run")), 1)

    def test_a_differing_replay_the_sweep_counted_and_did_not_list_gives_no_catch(self):
        done = self.run_plants("p-replayunlisted", "p-otherunlisted", "p-replaylisted", "p-manyviolations")
        self.assertEqual(done.returncode, 3, done.stderr)
        self.verdict("p-replayunlisted", "no verdict", "`campaign sweep-status` counts 9 suspects of a under "
                                                       "`replay differs: a rule` and `suspects.jsonl` lists 8")
        self.verdict("p-otherunlisted", "no verdict", "`campaign sweep-status` counts 1 suspects of a under `other` "
                                                      "and `suspects.jsonl` lists 0")
        # Every differing replay listed, or uncounted lines of a catch class alone, leaves the catch.
        for name in ("p-replaylisted", "p-manyviolations"):
            caught = self.verdict(name, "caught", "violation: a rule in run 7 of a")
            self.assertEqual(caught["suspect"]["run"], 7, name)
        self.assertEqual(len(self.calls("sim", "run")), 2)

    def test_a_profile_that_may_hide_a_differing_replay_leaves_another_profile_s_suspect_to_catch(self):
        done = self.run_plants("p-replayelsewhere")
        self.assertEqual(done.returncode, 0, done.stderr)
        caught = self.verdict("p-replayelsewhere", "caught", "violation: a rule in run 8 of b")
        self.assertEqual((caught["suspect"]["profile"], caught["suspect"]["run"]), ("b", 8))
        self.assertEqual(len(self.calls("sim", "run")), 1)

    def test_a_status_without_a_profile_s_suspect_keys_gives_no_catch(self):
        done = self.run_plants("p-nokeys", "p-oddkeys")
        self.assertEqual(done.returncode, 3, done.stderr)
        for name in ("p-nokeys", "p-oddkeys"):
            self.verdict(name, "no verdict", "`campaign sweep-status` gives a no count of its suspects by key")
        self.assertEqual(self.calls("sim", "run"), [])

    def test_a_count_by_key_that_does_not_account_for_a_profile_s_suspects_gives_no_catch(self):
        done = self.run_plants("p-emptykeys", "p-shortkeys", "p-lowkey")
        self.assertEqual(done.returncode, 3, done.stderr)
        self.verdict("p-emptykeys", "no verdict", "`campaign sweep-status` counts 1 suspects of a and 0 by key")
        self.verdict("p-shortkeys", "no verdict", "`campaign sweep-status` counts 2 suspects of a and 1 by key")
        self.verdict("p-lowkey", "no verdict", "`suspects.jsonl` lists 2 suspects of a under `violation: a rule` "
                                               "and `campaign sweep-status` counts 1")
        self.assertEqual(self.calls("sim", "run"), [])

    def test_a_finding_without_an_id_or_an_integer_run_confirms_nothing(self):
        done = self.run_plants("p-noid", "p-badrun")
        self.assertEqual(done.returncode, 3, done.stderr)
        for name in ("p-noid", "p-badrun"):
            self.verdict(name, "no verdict", "`campaign confirm` made no finding of violation: a rule in run 7 of a")
        self.assertEqual(self.calls("sim", "run"), [])

    def test_an_archive_without_the_run_s_lockfile_leaves_no_verdict(self):
        done = self.run_plants("p-nolockarchive")
        self.assertEqual(done.returncode, 3, done.stderr)
        self.verdict("p-nolockarchive", "no verdict", "keeps no regular Cargo.lock equal to the run's")

    def test_a_rerun_that_exits_2_4_or_6_leaves_its_plant_alone_with_no_verdict(self):
        done = self.run_plants("p-crashproof", "p-rejectproof", "p-slow", "p-watchproof")
        self.assertEqual(done.returncode, 3, done.stderr)
        for name, code in (("p-crashproof", 4), ("p-rejectproof", 2), ("p-watchproof", 6)):
            record = self.verdict(name, "no verdict", f"the rerun of the proof a::test exited {code}; its verdict is "
                                                      f"in proof/plant-{name}.out")
            self.assertIsNone(record["archive"])
        record = self.verdict("p-slow", "missed", "each expected profile reached 300 runs")
        self.assertEqual(record["proof_exits"], {"head": 0, "plant": 1})
        written, _ = self.results()
        self.assertEqual(written["not_live"], [])
        self.assertEqual(len(self.calls("sim", "archive")), 1)

    def test_a_head_rerun_that_exits_6_stays_its_own_proof_s(self):
        write_plant(self.store, "p-otherproof", "otherproof", ["a"], CAUSE, "base", fields={"proof": "b::test"})
        self.commit("another proof")
        done = self.run_plants("p-miss", "p-otherproof", env={"STANDIN_HEAD_PROOFS": json.dumps({"a::test": 6})})
        self.assertEqual(done.returncode, 3, done.stderr)
        self.verdict("p-miss", "no verdict", "the rerun of the proof a::test exited 6; its verdict is in "
                                             "proof/head-0.out")
        _, plants = self.results()
        self.assertEqual(plants["p-otherproof"]["proof_exits"], {"head": 0, "plant": 1})
        self.assertEqual([proof[proof.index("--test") + 1] for proof in self.proof_log() if proof[0] == "base"],
                         ["a::test", "b::test"])

    def test_a_rerun_whose_last_line_is_not_its_exit_s_verdict_leaves_no_verdict(self):
        done = self.run_plants("p-swapfail", "p-swappass", "p-trailfail")
        self.assertEqual(done.returncode, 3, done.stderr)
        for name, code, wanted in (("p-swapfail", 1, "reproduced"), ("p-swappass", 0, "not reproduced"),
                                   ("p-trailfail", 1, "reproduced")):
            self.verdict(name, "no verdict", f"the rerun of the proof a::test exited {code} without the verdict "
                                             f"`{wanted}`; its output is in proof/plant-{name}.out")
        self.assertEqual(self.calls("sim", "archive"), [])
        lines = {"a::test": "reproduced: reproduced on attempt 1"}
        done = self.run_plants("p-miss", env={"STANDIN_HEAD_LINES": json.dumps(lines)}, work=self.scratch / "work-2")
        self.assertEqual(done.returncode, 3, done.stderr)
        self.verdict("p-miss", "no verdict", "exited 0 without the verdict `not reproduced`; its output is in "
                                             "proof/head-0.out")

    def test_the_proof_applies_the_head_s_patch_when_the_checkout_s_copy_changes_before_it(self):
        checkout = self.store / "p-miss" / "plant.patch"
        env = {"STANDIN_REWRITE": json.dumps([str(checkout), patch_of("catch", "base")]), "STANDIN_REWRITE_IN": "base"}
        done = self.run_plants("p-miss", env=env)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual([proof[0] for proof in self.proof_log()], ["base", "pass"])
        self.verdict("p-miss", "missed", "each expected profile reached 300 runs")

    def test_work_directory_ancestors_the_run_makes_are_private_under_any_umask(self):
        private = self.scratch / "private"
        private.mkdir(mode=0o700)
        work = private / "a" / "b" / "work"
        argv = self.argv("p-miss", work=work)
        done = subprocess.run(argv, cwd=self.repo, env=self.environment(), capture_output=True, text=True,
                              check=False, preexec_fn=lambda: os.umask(0o002))
        self.assertEqual(done.returncode, 0, done.stderr)
        for made in (private / "a", private / "a" / "b", work):
            self.assertEqual(made.stat().st_mode & 0o022, 0, made)
        again = subprocess.run(self.argv("p-miss", work=private / "a" / "b" / "work-2"), cwd=self.repo,
                               env=self.environment(), capture_output=True, text=True, check=False,
                               preexec_fn=lambda: os.umask(0o002))
        self.assertEqual(again.returncode, 0, again.stderr)

    def test_proof_output_is_read_as_utf_8_under_a_single_byte_locale(self):
        names = subprocess.run(["locale", "-a"], capture_output=True, text=True, check=False).stdout.split()
        latin = next((name for name in names if name.lower() in ("en_us.iso88591", "de_de.iso88591")), None)
        if latin is None:
            self.skipTest("no ISO-8859-1 locale is installed")
        write_plant(self.store, "p-bproof", "otherproof", ["a"], CAUSE, "base", fields={"proof": "b::test"})
        self.commit("a second proof")
        env = {"LC_ALL": latin, "PYTHONUTF8": "0", "STANDIN_BINARY_PROOFS": '["b::test"]'}
        done = self.run_plants("p-bproof", "p-miss", env=env)
        self.assertEqual(done.returncode, 3, done.stderr)
        self.verdict("p-bproof", "no verdict", "`reproduce-test.py` exited 0 and printed no UTF-8 text")
        self.verdict("p-miss", "missed", "each expected profile reached 300 runs")

    def test_the_archive_build_sees_no_lockfile_path_of_the_caller_s(self):
        done = self.run_plants("p-miss", env={"CARGO_RESOLVER_LOCKFILE_PATH": str(self.scratch / "elsewhere.lock")})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(len(self.calls("sim", "archive")), 1)
        self.assertFalse((self.scratch / "archive-lockfile-path").exists())

    def test_a_failed_apply_in_the_proof_s_worktree_judges_no_later_plant(self):
        side = "--- /dev/null\n+++ b/side\n@@ -0,0 +1 @@\n+planted\n"
        write_plant(self.store, "p-side", "base", ["a"], CAUSE, "base", fields={"files": ["side"]}, patch=side)
        self.commit("a plant on another file")
        counter = self.scratch / "applies"
        third = (f"echo x >> {counter}; if [ \"$(wc -l < {counter})\" -eq 3 ]; then echo 'error: disk full' >&2; "
                 "exit 1; fi")
        done = self.run_plants("p-miss", "p-side", env=self.git_shim("--index", third))
        self.assertEqual(done.returncode, 3, done.stderr)
        self.verdict("p-miss", "no verdict", "`git apply` exited 1; its error is in plants/p-miss/git.err")
        self.verdict("p-side", "no verdict", "the proof's worktree is no longer the head's tree: `git apply` exited 1 "
                                             "at the plant p-miss")
        self.assertEqual([proof[0] for proof in self.proof_log()], ["base"])

    def test_a_proof_worktree_that_cannot_be_added_gives_every_plant_its_first_cause(self):
        refuse = "case \"$*\" in *proof/tree*) echo 'fatal: no room' >&2; exit 128;; esac"
        done = self.run_plants("p-miss", "p-catch", env=self.git_shim("add", refuse))
        self.assertEqual(done.returncode, 3, done.stderr)
        for name in ("p-miss", "p-catch"):
            self.verdict(name, "no verdict", "the proof's worktree: `git worktree` exited 128; its error is in "
                                             "proof/git.err")
        self.assertEqual(self.proof_log(), [])
        self.assertIn("fatal: no room", (self.work / "proof" / "git.err").read_text())

    def test_a_catch_rests_on_a_confirmed_suspect_whose_seed_passes_on_the_head(self):
        shared = self.scratch / "shared-target"
        env = {"CARGO_TARGET_DIR": str(shared), "CARGO_BUILD_BUILD_DIR": str(shared)}
        done = self.run_plants("p-catch", env=env)
        self.assertEqual(done.returncode, 0, done.stderr)
        caught = self.verdict("p-catch", "caught", "violation: a rule in run 7 of b")
        self.assertEqual(caught["suspect"], {"profile": "b", "run": 7, "seed": 42, "key": "violation: a rule",
                                             "finding": "finding-0", "head": "counts: complete pass"})
        self.assertEqual(caught["head_failures"], [])
        self.assertEqual(caught["archive"], digest("catch"))
        self.assertEqual(caught["campaign"], "plant-p-catch")
        self.assertEqual(caught["profiles"], ["a", "b"])
        self.assertEqual(caught["counts"], {})
        self.assertEqual(caught["controls"], {"caught": 3, "missed": 0})
        self.assertEqual(caught["histories"], {"caught": 2, "missed": 0})
        written, _ = self.results()
        self.assertEqual(written["commit"], self.head)
        totals = {"runs": 300, "next": 400, "range": [0, 399], "pass": 300, "suspects": 0, "replays": 1,
                  "uncredited": {}}
        self.assertEqual(caught["runs"]["a"], totals)
        self.assertNotIn("miss_cause", caught)
        self.assertEqual(self.git("rev-parse", f"{caught['commit']}^").strip(), self.head)
        self.assertEqual(self.git("show", f"{caught['commit']}:mode"), "catch\n")
        self.assertEqual(self.git("rev-parse", f"{caught['commit']}^{{tree}}").strip(), caught["tree"])
        runs = self.calls("sim", "run")
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0][runs[0].index("--archive") + 1], str(self.work / "base" / "archive"))
        places = {"base": self.work / "base", "p-catch": self.work / "plants" / "p-catch"}
        for name, place in places.items():
            try:
                seen = json.loads((place / "archive" / "env").read_text())
            except (OSError, ValueError) as error:
                self.fail(f"the stand-in's archive environment is unreadable: {error}")
            self.assertEqual(seen, {
                "CARGO_PROFILE_DEV_OPT_LEVEL": "3", "CARGO_PROFILE_DEV_DEBUG_ASSERTIONS": "true",
                "CARGO_TARGET_DIR": str(place / "target"), "CARGO_BUILD_BUILD_DIR": str(place / "target"),
                "lockfile": "# the checkout's resolution\n", "proof": {"target": False, "tree": False}}, name)
            self.assertFalse((place / "target").exists(), name)
        self.assertFalse(shared.exists())
        check = self.work / "plants" / "p-catch" / "seeds" / "b" / "7-42" / "manifest"
        self.assertEqual(check.read_text().split("\n"), [
            "version = 2", "profile = b", "root = 42", "executable = x-base", "toolchain = t-base",
            f"build = {digest('base')}", "platform = p-base", "turns = 9", ""])
        self.assertFalse(self.hooked.exists())

    def test_a_plant_named_base_is_caught_with_its_seed_on_the_unpatched_head(self):
        self.run_plants("base")
        self.verdict("base", "caught", "violation: a rule in run 7 of a")
        runs = self.calls("sim", "run")
        self.assertEqual(runs[0][runs[0].index("--archive") + 1], str(self.work / "base" / "archive"))

    def test_the_planted_commit_depends_on_the_head_and_the_patch_alone(self):
        self.run_plants("p-miss")
        _, first = self.results()
        time.sleep(1.1)
        (self.scratch / "gitconfig").write_text("[author]\n\tname = someone\n[committer]\n\tname = someone\n")
        identity = {"GIT_AUTHOR_NAME": "another", "GIT_COMMITTER_EMAIL": "another@invalid"}
        self.git("config", "i18n.commitEncoding", "ISO-8859-1")
        self.run_plants("p-miss", work=self.scratch / "again", env=identity)
        _, second = self.results()
        self.assertIsNotNone(first["p-miss"]["commit"])
        self.assertEqual(first["p-miss"]["commit"], second["p-miss"]["commit"])
        self.assertEqual(first["p-miss"]["tree"], second["p-miss"]["tree"])

    def test_the_planted_commit_takes_the_head_s_date_beside_a_shown_signature(self):
        """The head carries a `gpgsig` header and `log.showSignature` is set, so `git show` prints the signature
        program's lines before its format; the planted commit is the one a run without that setting makes."""
        text = self.git("cat-file", "commit", "HEAD")
        header, message = text.split("\n\n", 1)
        signed = (f"{header}\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n fixture\n -----END PGP SIGNATURE-----\n\n"
                  f"{message}")
        written = subprocess.run(["git", "-C", str(self.repo), "hash-object", "-t", "commit", "-w", "--stdin"],
                                 input=signed, capture_output=True, text=True, check=True, env=self.env)
        self.git("reset", "--quiet", "--hard", written.stdout.strip())
        verifier = self.scratch / "verifier"
        verifier.write_text("#!/bin/sh\necho 'gpg: Signature made a day' >&2\nexit 1\n")
        verifier.chmod(0o755)
        self.git("config", "gpg.program", str(verifier))
        done = self.run_plants("p-miss")
        self.assertEqual(done.returncode, 0, done.stderr)
        _, first = self.results()
        self.git("config", "log.showSignature", "true")
        self.assertIn("gpg: Signature made a day", self.git("show", "--no-patch", "--format=%cI", "HEAD"))
        done = self.run_plants("p-miss", work=self.scratch / "again")
        self.assertEqual(done.returncode, 0, done.stderr)
        _, second = self.results()
        self.assertIsNotNone(first["p-miss"]["commit"])
        self.assertEqual(first["p-miss"]["commit"], second["p-miss"]["commit"])

    def test_the_planted_tree_holds_the_patch_s_bytes_under_a_configured_whitespace_fix(self):
        """The plant's patch adds a line that ends in a space; `apply.whitespace = fix` in the caller's
        configuration would strip it."""
        place = write_plant(self.store, "p-space", "pass", ["a"], CAUSE, "base")
        (place / "plant.patch").write_text(patch_of("pass ", "base"))
        self.commit("a patch with a trailing space")
        done = self.run_plants("p-space")
        self.assertEqual(done.returncode, 0, done.stderr)
        _, first = self.results()
        self.git("config", "apply.whitespace", "fix")
        done = self.run_plants("p-space", work=self.scratch / "again")
        self.assertEqual(done.returncode, 0, done.stderr)
        _, second = self.results()
        self.assertIsNotNone(first["p-space"]["tree"])
        self.assertEqual(first["p-space"]["tree"], second["p-space"]["tree"])
        self.assertEqual(first["p-space"]["commit"], second["p-space"]["commit"])

    def test_a_replacement_of_the_head_commit_is_not_read(self):
        """The run builds the tree of the commit its score names, whatever `refs/replace` holds for that commit."""
        (self.repo / "mode").write_text("other\n")
        self.git("add", "mode")
        tree = self.git("write-tree").strip()
        self.git("reset", "--quiet", "--hard", "HEAD")
        self.git("replace", self.head, self.git("commit-tree", tree, "-m", "a replacement").strip())
        done = self.run_plants("p-miss")
        self.assertEqual(done.returncode, 0, done.stderr)
        written, _ = self.results()
        self.assertEqual(written["commit"], self.head)
        self.verdict("p-miss", "missed", "each expected profile reached 300 runs")

    def test_a_suspect_of_a_profile_with_the_longest_name_is_checked_and_caught(self):
        """A profile name of 242 bytes, the longest `campaign` takes, and a seed of 20 digits leave the seed check
        a directory to make."""
        longest = "p" * 242
        write_plant(self.store, "p-longest", "longest", [longest], None, "base")
        self.commit("the longest profile name")
        done = self.run_plants("p-longest")
        self.assertEqual(done.returncode, 0, done.stderr)
        record = self.verdict("p-longest", "caught", f"violation: a rule in run 7 of {longest}")
        self.assertEqual(record["suspect"]["seed"], 2 ** 64 - 1)

    def test_a_catch_stands_when_a_later_seed_check_fails(self):
        self.run_plants("p-catchbroken")
        caught = self.verdict("p-catchbroken", "caught", "violation: a rule in run 7 of a")
        self.assertEqual(caught["suspect"]["seed"], 42)

    def test_a_finding_of_another_shape_after_a_catch_leaves_the_catch_standing(self):
        self.run_plants("p-oddfinding")
        caught = self.verdict("p-oddfinding", "caught", "violation: a rule in run 7 of a")
        self.assertEqual(caught["suspect"]["finding"], "finding-0")

    def test_a_finding_without_an_id_or_with_a_boolean_run_confirms_nothing(self):
        self.run_plants("p-noid", "p-boolrun")
        for name in ("p-noid", "p-boolrun"):
            self.verdict(name, "no verdict", "made no finding of violation: a rule in run 7 of a")
        self.assertEqual(self.calls("sim", "run"), [])

    def test_a_seed_check_that_prints_no_result_ran_nothing_on_the_head(self):
        done = self.run_plants("p-noresult")
        self.assertEqual(done.returncode, 3, done.stderr)
        failed = self.verdict("p-noresult", "no verdict", "the seed check of violation: a rule in run 7 of a did not "
                                                          "run: exit 4 with no result")
        self.assertEqual(failed["head_failures"], [])

    def test_a_seed_check_that_exits_0_with_another_class_than_counts_is_no_pass_on_the_head(self):
        done = self.run_plants("p-oddpass")
        self.assertEqual(done.returncode, 3, done.stderr)
        failed = self.verdict("p-oddpass", "no verdict", "the seed check of violation: a rule in run 7 of a did not "
                                                         "run: exit 0 with the class complete")
        self.assertEqual(failed["head_failures"], [])

    def test_the_first_suspect_whose_seed_passes_on_the_head_is_the_catch(self):
        self.run_plants("p-twopass")
        caught = self.verdict("p-twopass", "caught", "violation: a rule in run 7 of a")
        self.assertEqual((caught["suspect"]["seed"], caught["suspect"]["finding"]), (42, "finding-0"))
        self.assertEqual(len(self.calls("sim", "run")), 2)

    def test_each_malformed_or_contradictory_record_leaves_no_verdict(self):
        cases = {
            "p-otherlock": "keeps no regular Cargo.lock equal to the run's",
            "p-nolock": "keeps no regular Cargo.lock equal to the run's",
            "p-loneline": "`suspects.jsonl` lists 1 suspects",
            "p-disorder": "gives a counts out of order",
            "p-othercampaign": "names campaign 'another' and counts {}",
            "p-exitone": "the last sweep exited 1 and the root holds no verdict key",
            "p-rootsuspect": "counts 1 suspects at the root",
            "p-statusfail": "`campaign sweep-status` exited 2",
            "p-booltotal": "counts False suspects at the root",
            "p-floattotal": "counts 0.0 suspects at the root",
            "p-confirmfail": "`campaign confirm` exited 2",
            "p-norun": "a has no run counted",
            "p-overrun": "gives a counts out of order: pass 150, runs 201, next 200",
            "p-othercounts": "names campaign 'plant-p-othercounts' and counts {'nodes': 5}",
            "p-badbytes": "`campaign sweep-status` exited 0 and printed no UTF-8 text",
            "p-historynocount": "gives h-history no suspect count",
        }
        done = self.run_plants(*cases)
        self.assertEqual(done.returncode, 3, done.stderr)
        for name, reason in cases.items():
            with self.subTest(name):
                self.verdict(name, "no verdict", reason)
        self.assertEqual(len([call for call in self.calls("sweep") if "plant-p-exitone" in call]), 1)

    def test_a_suspect_record_a_kill_cut_short_is_not_read(self):
        self.run_plants("p-cutline")
        self.verdict("p-cutline", "missed", "each expected profile reached 300 runs")

    def test_a_panic_is_a_catch(self):
        self.run_plants("p-panic")
        self.verdict("p-panic", "caught", "panic: a rule in run 7 of a")

    def test_a_suspect_line_with_a_line_separator_is_one_record(self):
        self.run_plants("p-wide")
        self.verdict("p-wide", "caught", "violation: a rule in run 7 of a")

    def test_a_confirmed_catch_outranks_a_verdict_key(self):
        self.run_plants("p-catchalarm")
        self.verdict("p-catchalarm", "caught", "violation: a rule in run 7 of a")
        self.assertEqual(len(self.calls("sweep")), 1)

    def test_a_catch_lists_each_confirmed_seed_that_fails_on_the_head_in_either_order(self):
        self.run_plants("p-second", "p-passthenfail")
        for name, failing in (("p-second", 7), ("p-passthenfail", 8)):
            caught = self.verdict(name, "caught", "violation: a rule in run")
            self.assertEqual(caught["suspect"]["seed"], 42)
            self.assertEqual([(failed["run"], failed["seed"], failed["head"]) for failed in caught["head_failures"]],
                             [(failing, 666, "incomplete: the run panicked")], name)
        self.assertEqual(len(self.calls("sim", "run")), 4)

    def test_a_suspect_listed_twice_is_checked_once(self):
        done = self.run_plants("p-dup")
        self.assertEqual(done.returncode, 3, done.stderr)
        plant = self.verdict("p-dup", "no verdict", "does not pass on the unpatched head: incomplete")
        self.assertEqual(len(plant["head_failures"]), 1)
        self.assertEqual(len(self.calls("sim", "run")), 1)

    def test_a_seed_that_completes_with_a_failure_on_the_head_leaves_no_verdict(self):
        self.run_plants("p-lonehead")
        self.verdict("p-lonehead", "no verdict", "does not pass on the unpatched head: complete: a rule failed")

    def test_a_finding_of_another_run_or_class_confirms_nothing(self):
        self.run_plants("p-mismatch", "p-watchdog")
        self.verdict("p-mismatch", "no verdict", "made no finding of violation: a rule in run 7 of a")
        self.verdict("p-watchdog", "no verdict", "made no finding of violation: a rule in run 7 of a")
        self.assertEqual(self.calls("sim", "run"), [])

    def test_a_finding_of_another_profile_or_seed_confirms_nothing(self):
        self.run_plants("p-otherprofile", "p-otherseed")
        self.verdict("p-otherprofile", "no verdict", "made no finding of violation: a rule in run 7 of a")
        self.verdict("p-otherseed", "no verdict", "made no finding of violation: a rule in run 7 of a")
        self.assertEqual(self.calls("sim", "run"), [])

    def test_a_later_confirmed_suspect_is_caught_after_an_unconfirmed_one(self):
        self.run_plants("p-laterfinding")
        caught = self.verdict("p-laterfinding", "caught", "run 8 of a")
        self.assertEqual(caught["suspect"]["finding"], "finding-1")

    def test_a_seed_that_ends_in_a_violation_on_the_head_leaves_the_next_suspect_to_catch(self):
        self.run_plants("p-violatehead")
        caught = self.verdict("p-violatehead", "caught", "run 8 of a")
        self.assertEqual(caught["head_failures"][0]["head"], "complete: a rule failed")
        self.assertEqual(len(self.calls("sim", "run")), 2)

    def test_a_refused_seed_check_leaves_the_next_suspect_to_catch(self):
        self.run_plants("p-oddthen")
        self.verdict("p-oddthen", "caught", "run 8 of a")

    def test_a_failed_step_leaves_no_verdict_with_its_cause(self):
        done = self.run_plants("p-nomanifest", "p-damaged")
        self.assertEqual(done.returncode, 3, done.stderr)
        failed = self.verdict("p-nomanifest", "no verdict", "the seed check of violation: a rule in run 7 of a did "
                                                            "not run: [Errno 2] No such file or directory: "
                                                            "'<work>/plants/p-nomanifest/root/manifests/a.manifest'")
        self.assertNotIn(str(self.scratch), failed["reason"])
        self.verdict("p-damaged", "no verdict", "`campaign sweep` exited 4")

    def test_a_confirm_that_leaves_jobs_queued_leaves_no_verdict(self):
        self.run_plants("p-queued")
        self.verdict("p-queued", "no verdict", "left its queue at dispatch 'paused'")

    def test_a_confirm_held_at_its_backlog_keeps_the_findings_it_made(self):
        done = self.run_plants("p-held", "p-heldnone", "p-heldother")
        self.assertEqual(done.returncode, 3, done.stderr)
        self.verdict("p-held", "caught", "violation: a rule in run 7 of a")
        self.verdict("p-heldnone", "no verdict", "`campaign confirm` held its queue: backlog holds 64")
        self.verdict("p-heldother", "no verdict", "`campaign confirm` exited 4 at dispatch 'held'")
        self.assertEqual(len(self.calls("sim", "run")), 1)

    def test_a_confirm_held_for_more_than_its_backlog_keeps_no_finding(self):
        names = ("p-heldrejected", "p-heldomitted", "p-heldmixed", "p-heldpaused")
        done = self.run_plants(*names)
        self.assertEqual(done.returncode, 3, done.stderr)
        for name in names:
            with self.subTest(name):
                dispatch = "paused" if name == "p-heldpaused" else "held"
                self.verdict(name, "no verdict", f"`campaign confirm` exited 4 at dispatch '{dispatch}'")
        self.assertEqual(self.calls("sim", "run"), [])

    def test_a_refused_seed_check_is_no_failure_of_the_head(self):
        self.run_plants("p-rejectseed")
        plant = self.verdict("p-rejectseed", "no verdict", "seed check of violation: a rule in run 7 of a on the "
                                                           "unpatched head exited 2 (rejected: the manifest names another build)")
        self.assertEqual(plant["head_failures"], [])

    def test_a_seed_check_runs_only_the_job_confirm_ran(self):
        self.run_plants("p-othermanifest")
        self.verdict("p-othermanifest", "no verdict", "did not run: its manifest differs from the job `confirm` ran")
        self.assertEqual(self.calls("sim", "run"), [])

    def test_a_suspect_outside_the_expected_profiles_leaves_no_verdict(self):
        self.run_plants("p-history")
        self.verdict("p-history", "no verdict", "the root holds suspects in h-history (1)")
        self.assertEqual(self.calls("confirm"), [])

    def test_each_verdict_key_leaves_no_verdict_and_names_itself(self):
        done = self.run_plants("p-nopass", "p-unreached", "p-nowindow")
        self.assertEqual(done.returncode, 3, done.stderr)
        nopass = self.verdict("p-nopass", "no verdict", "the root holds no_pass")
        self.assertEqual(nopass["keys"], {"no_pass": ["a"]})
        unreached = self.verdict("p-unreached", "no verdict", "the root holds unreached")
        self.assertEqual(unreached["keys"], {"unreached": {"a": ["a required event"]}})
        window = self.verdict("p-nowindow", "no verdict", "the root holds no_window")
        self.assertEqual(window["keys"], {"no_window": {"a": ["a planned window"]}})

    def test_a_status_without_a_profile_s_suspect_count_leaves_no_verdict(self):
        self.run_plants("p-nocount")
        self.verdict("p-nocount", "no verdict", "gives a no count of next, runs, pass, suspects")

    def test_a_malformed_suspect_list_leaves_no_verdict(self):
        self.run_plants("p-badline", "p-dirlog")
        self.verdict("p-badline", "no verdict", "suspects.jsonl line 1 is no suspect")
        self.verdict("p-dirlog", "no verdict", "suspects.jsonl is no regular file")
        self.assertEqual(self.calls("confirm"), [])

    def test_an_output_nested_past_the_parser_leaves_no_verdict_and_the_run_goes_on(self):
        done = self.run_plants("p-deepconfirm", "p-miss")
        self.assertEqual(done.returncode, 3, done.stderr)
        self.verdict("p-deepconfirm", "no verdict", "`campaign confirm` printed no JSON object")
        self.verdict("p-miss", "missed", "each expected profile reached 300 runs")

    def test_an_archive_refused_for_another_cause_than_its_build_names_the_exit(self):
        self.run_plants("p-refusedarchive")
        plant = self.verdict("p-refusedarchive", "no verdict", "`campaign sim archive` of the planted tree exited 2")
        self.assertNotIn("does not build", plant["reason"])

    def test_an_unpatched_head_that_does_not_build_leaves_no_verdict(self):
        done = self.run_plants("p-catch", "p-headfail", env={"STANDIN_BASE_FAIL": "1"})
        self.assertEqual(done.returncode, 3, done.stderr)
        self.verdict("p-catch", "no verdict", "the unpatched head does not build")
        self.verdict("p-headfail", "no verdict", "the unpatched head does not build")
        self.assertEqual(len(self.calls("sim", "archive")), 3)

    def test_the_sweep_repeats_until_every_profile_reaches_the_floor(self):
        self.run_plants("p-miss", "p-slow")
        sweeps = self.calls("sweep")
        names = [call[call.index("--campaign") + 1] for call in sweeps]
        self.assertEqual(names, ["plant-p-miss"] * 2 + ["plant-p-slow"] * 3)
        for call in sweeps:
            self.assertEqual(call[call.index("--workers") + 1], "2")
        place = self.work / "plants" / "p-miss"
        self.assertEqual(sweeps[0], ["sweep", "--root", str(place / "root"), "--archive", str(place / "archive"),
                                     "--campaign", "plant-p-miss", "--profiles", "a", "--workers", "2", "--for", "1"])
        _, plants = self.results()
        self.assertEqual(plants["p-miss"]["miss_cause"], CAUSE)
        self.assertEqual(plants["p-slow"]["runs"]["slow"]["next"], 300)
        self.verdict("p-slow", "missed", "each expected profile reached 300 runs and the root holds no suspect")
        self.assertEqual(self.calls("confirm"), [])
        for name in ("p-miss", "p-slow"):
            seen = json.loads((self.work / "plants" / name / "archive" / "env").read_text())
            self.assertEqual(seen["proof"], {"target": False, "tree": False}, name)
        self.assertEqual([proof[0] for proof in self.proof_log()], ["base", "pass", "pass"])

    def test_a_floor_reached_exactly_ends_the_sweeps(self):
        self.run_plants("p-miss", extra=("--runs", "400"))
        self.verdict("p-miss", "missed", "each expected profile reached 400 runs")
        self.assertEqual(len(self.calls("sweep")), 2)
        written, _ = self.results()
        settings = {name: written["settings"][name] for name in ("workers", "runs", "seconds", "rounds")}
        self.assertEqual(settings, {"workers": 2, "runs": 400, "seconds": 1, "rounds": 3})

    def test_a_profile_one_run_below_the_floor_is_swept_again(self):
        self.run_plants("p-miss", extra=("--runs", "401"))
        self.verdict("p-miss", "missed", "each expected profile reached 401 runs")
        self.assertEqual(len(self.calls("sweep")), 3)

    def test_a_floor_out_of_reach_in_the_rounds_leaves_no_verdict(self):
        self.run_plants("p-miss", extra=("--runs", "601"))
        self.verdict("p-miss", "no verdict", "a stayed below 601 runs after 3 sweeps")
        self.assertEqual(len(self.calls("sweep")), 3)

    def test_a_plant_with_no_expected_profile_is_missed_without_a_sweep(self):
        done = self.run_plants("p-noprofile")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual([call[:2] for call in self.calls()], [["sim", "archive"]])
        written, plants = self.results()
        self.assertEqual(plants["p-noprofile"]["result"], "missed")
        self.assertEqual(plants["p-noprofile"]["archive"], digest("pass"))
        self.assertEqual(written["sentence"], f"0 of 1 plants at commit {self.head}")

    def test_a_failed_git_step_names_its_command_and_keeps_its_message_in_the_work_directory(self):
        path = self.git_shim("commit", f"echo \"a signer refused at {self.scratch}\" >&2; exit 7")
        self.run_plants("p-miss", env=path)
        plant = self.verdict("p-miss", "no verdict", "`git commit` exited 7; its error is in plants/p-miss/git.err")
        self.assertNotIn(str(self.scratch), plant["reason"])
        self.assertIn("a signer refused", (self.work / "plants" / "p-miss" / "git.err").read_text())

    def test_a_patch_check_that_fails_for_another_cause_than_the_patch_is_no_plant_that_does_not_apply(self):
        done = self.run_plants("p-miss", env=self.git_shim("--check", "echo 'fatal: a damaged index' >&2; exit 128"))
        self.assertEqual(done.returncode, 3, done.stderr)
        self.verdict("p-miss", "no verdict", "`git apply` exited 128; its error is in plants/p-miss/git.err")
        self.assertIn("a damaged index", (self.work / "plants" / "p-miss" / "git.err").read_text())

    def test_a_patch_that_adds_a_lockfile_leaves_no_verdict(self):
        place = write_plant(self.store, "p-ownlock", "pass", ["a"], CAUSE, "base", {"files": ["Cargo.lock"]})
        (place / "plant.patch").write_text("--- /dev/null\n+++ b/Cargo.lock\n@@ -0,0 +1 @@\n+another resolution\n")
        self.commit("a plant that adds a lockfile")
        self.run_plants("p-ownlock")
        self.verdict("p-ownlock", "no verdict", "`git apply` exited 1; its error is in plants/p-ownlock/git.err")
        self.assertIn("Cargo.lock: already exists", (self.work / "plants" / "p-ownlock" / "git.err").read_text())
        self.assertEqual(self.calls(), [])

    def test_commit_signing_in_the_caller_s_configuration_signs_no_scratch_commit(self):
        signer = self.scratch / "signer"
        signer.write_text(f"#!/bin/sh\ntouch {self.scratch / 'signed'}\nexit 1\n")
        signer.chmod(0o755)
        (self.scratch / "gitconfig").write_text(f"[commit]\n\tgpgsign = true\n[gpg]\n\tprogram = {signer}\n")
        done = self.run_plants("p-miss")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.verdict("p-miss", "missed", "each expected profile reached 300 runs")
        self.assertFalse((self.scratch / "signed").exists())


class Exits(Fixture):
    def test_a_miss_without_its_cause_exits_1(self):
        done = self.run_plants("p-nocause", "p-catch", "p-nobuild")
        self.assertEqual(done.returncode, 1, done.stderr)
        _, plants = self.results()
        self.assertEqual(plants["p-nocause"]["result"], "missed")
        self.assertIsNone(plants["p-nocause"]["miss_cause"])

    def test_a_miss_without_a_sweep_and_without_its_cause_exits_1(self):
        write_plant(self.store, "p-unswept", "pass", [], None, "base")
        self.commit("a plant with no expected profile and no cause")
        done = self.run_plants("p-unswept")
        self.assertEqual(done.returncode, 1, done.stderr)
        _, plants = self.results()
        self.assertEqual(plants["p-unswept"]["result"], "missed")
        self.assertIsNone(plants["p-unswept"]["miss_cause"])

    def test_each_of_the_four_cause_words_stands_in_the_score_of_its_miss(self):
        causes = {word: {"cause": word, "evidence": f"A sentence on {word}."}
                  for word in ("environment", "workload", "ordering", "property")}
        for word, cause in causes.items():
            write_plant(self.store, f"p-{word}", "pass", [], cause, "base")
        self.commit("a plant for each cause word")
        done = self.run_plants(*(f"p-{word}" for word in causes))
        self.assertEqual(done.returncode, 0, done.stderr)
        written, plants = self.results()
        self.assertEqual(written["commit"], self.git("rev-parse", "HEAD").strip())
        self.assertEqual(written["sentence"], f"0 of 4 plants at commit {written['commit']}")
        for word, cause in causes.items():
            self.assertEqual((plants[f"p-{word}"]["result"], plants[f"p-{word}"]["miss_cause"]), ("missed", cause))

    def test_every_plant_with_a_verdict_and_every_miss_with_a_cause_exits_0(self):
        done = self.run_plants("p-catch", "p-miss")
        self.assertEqual(done.returncode, 0, done.stderr)
        written, _ = self.results()
        self.assertEqual(written["sentence"], f"1 of 2 plants at commit {self.head}")

    def test_a_patch_that_does_not_apply_exits_3_and_stays_out_of_the_count(self):
        done = self.run_plants("p-catch", "p-miss", "p-stale")
        self.assertEqual(done.returncode, 3, done.stderr)
        written, plants = self.results()
        self.assertEqual(written["sentence"], f"1 of 2 plants at commit {self.head}")
        self.assertEqual(plants["p-stale"]["result"], "does not apply")
        discard(self.work)
        done = self.run_plants("p-stale")
        self.assertEqual(done.returncode, 3, done.stderr)
        written, _ = self.results()
        self.assertEqual(written["sentence"], f"0 of 0 plants at commit {self.head}")

    def test_a_malformed_record_is_rejected_before_any_work(self):
        cases = {
            "p-broken": ({"miss_cause": {"cause": "luck", "evidence": "none"}}, "miss_cause"),
            "p-noevidence": ({"miss_cause": {"cause": "workload", "evidence": " "}}, "miss_cause"),
            "p-bareword": ({"miss_cause": "workload"}, "miss_cause"),
            "p-boolrow": ({"row": True}, "row is a positive integer"),
            "p-nofiles": ({"files": []}, "files is a nonempty list"),
            "p-twoprofiles": ({"expected": ["a,b"]}, "expected is a list of profile names"),
            "p-badfix": ({"fix": {"pull_request": 0, "commit": "c"}}, "fix holds a positive pull_request"),
        }
        for name, (fields, rule) in cases.items():
            with self.subTest(name):
                place = write_plant(self.store, name, "pass", ["a"], CAUSE, "base", fields)
                self.rejected(self.run_plants(), f"{name}: {rule}")
                discard(place)

    def test_a_record_with_a_repeated_member_or_deep_nesting_is_rejected(self):
        place = write_plant(self.store, "p-twice", "pass", ["a"], CAUSE, "base")
        record = (place / "plant.json").read_text()
        for broken, text in ((record[:-1] + ', "expected": []}', "plant.json is unreadable: repeated member expected"),
                             ("[" * 100000, "plant.json is unreadable")):
            with self.subTest(text):
                (place / "plant.json").write_text(broken)
                self.rejected(self.run_plants(), f"p-twice: {text}")

    def test_a_missing_empty_or_corrupt_patch_is_rejected(self):
        place = write_plant(self.store, "p-patch", "pass", ["a"], CAUSE, "base")
        for patch, text in (("", "plant.patch is no patch"), ("--- a/mode\n+++ b/mode\n@@ -1 +1 @@\n-base\n",
                                                               "plant.patch is no patch")):
            with self.subTest(repr(patch)):
                (place / "plant.patch").write_text(patch)
                self.rejected(self.run_plants(), f"p-patch: {text}")
        (place / "plant.patch").unlink()
        self.rejected(self.run_plants(), "p-patch: plant.json and plant.patch are both required")

    def test_a_patch_that_renames_or_changes_a_mode_is_rejected(self):
        place = write_plant(self.store, "p-rename", "pass", ["mode"], CAUSE, "base")
        for patch, text in (
                ("diff --git a/mode b/mode\nold mode 100644\nnew mode 100755\n", "mode change"),
                ("diff --git a/mode b/mode\nsimilarity index 100%\nrename from mode\nrename to mode\n", "rename")):
            with self.subTest(text):
                (place / "plant.patch").write_text(patch)
                done = self.run_plants()
                self.assertEqual(done.returncode, 2, done.stderr)
                self.assertIn("p-rename: plant.patch", done.stderr)
                self.assertEqual(self.calls(), [])

    def test_a_patch_past_the_bound_is_rejected(self):
        place = write_plant(self.store, "p-big", "pass", ["mode"], CAUSE, "base")
        (place / "plant.patch").write_text(patch_of("pass", "base") + "#" * (1 << 20))
        self.rejected(self.run_plants(), "p-big: plant.json or plant.patch holds more than 1048576 bytes")

    def test_a_plant_file_edited_under_an_assume_unchanged_flag_is_rejected(self):
        record, patch = self.store / "p-miss" / "plant.json", self.store / "p-miss" / "plant.patch"
        for path, edit in ((record, record.read_text().replace("A defect.", "Another defect.")),
                           (patch, patch_of("catch", "base"))):
            with self.subTest(path.name):
                before = path.read_text()
                self.git("update-index", "--assume-unchanged", f"verification/plants/p-miss/{path.name}")
                path.write_text(edit)
                self.assertEqual(self.git("status", "--porcelain", "--", "verification/plants/p-miss"), "")
                self.rejected(self.run_plants("p-miss"), f"differs from HEAD at verification/plants/p-miss/{path.name}")
                path.write_text(before)

    def test_a_plant_directory_removed_under_an_assume_unchanged_flag_is_rejected(self):
        """`git status` reports no deletion of a path whose index entry is assume-unchanged, so the store's
        directories are compared with the ones `HEAD` holds."""
        for name in ("plant.json", "plant.patch"):
            self.git("update-index", "--assume-unchanged", f"verification/plants/p-miss/{name}")
        discard(self.store / "p-miss")
        self.assertEqual(self.git("status", "--porcelain", "--", "verification/plants"), "")
        self.rejected(self.run_plants(), "differs from HEAD at verification/plants/p-miss")

    def test_a_listing_of_the_head_s_plant_directories_that_fails_is_rejected(self):
        done = self.run_plants("p-miss", env=self.git_shim("-d", "echo 'a refused listing' >&2; exit 1"))
        self.rejected(done, "the plant store of HEAD cannot be listed: `git ls-tree` exited 1")

    def test_a_linked_plant_store_is_rejected(self):
        moved = self.scratch / "elsewhere"
        try:
            shutil.move(str(self.store), str(moved))
            self.store.symlink_to(moved)
        except OSError as error:
            self.fail(f"the store cannot be moved behind a link: {error}")
        self.rejected(self.run_plants("p-miss"), "is a link; the plant store must be a directory of the checkout")
        self.assertFalse((moved / "score.json").exists())

    def test_a_linked_verification_directory_is_rejected(self):
        moved = self.scratch / "elsewhere"
        try:
            shutil.move(str(self.store.parent), str(moved))
            self.store.parent.symlink_to(moved)
        except OSError as error:
            self.fail(f"the directory cannot be moved behind a link: {error}")
        self.rejected(self.run_plants("p-miss"), "is a link; the plant store must be a directory of the checkout")
        self.assertFalse((moved / "plants" / "score.json").exists())

    def test_a_store_with_no_plant_is_rejected(self):
        for place in self.store.iterdir():
            discard(place)
        (self.store / "keep").write_text("")
        self.commit("a store with no plant")
        self.rejected(self.run_plants(), "holds no plant")

    def test_a_floor_of_exactly_300_is_accepted(self):
        done = self.run_plants("p-noprofile", extra=("--runs", "300"))
        self.assertEqual(done.returncode, 0, done.stderr)
        written, _ = self.results()
        self.assertEqual(written["settings"]["runs"], 300)

    def test_a_record_naming_a_profile_campaign_cannot_take_or_other_fields_is_rejected(self):
        cases = {
            "p-slash": ({"expected": ["a/b"]}, "expected is a list of profile names campaign can take"),
            "p-dot": ({"expected": [".."]}, "expected is a list of profile names campaign can take"),
            "p-noproof": ({"proof": " "}, "restores and proof are nonempty text"),
            "p-otherid": ({"id": "p-elsewhere"}, "id names the plant's directory"),
            "p-edge ": ({}, "id names the plant's directory in printable ASCII without edge spaces"),
            "p-extra": ({"note": "x"}, "plant.json holds exactly the fields"),
        }
        for name, (fields, rule) in cases.items():
            with self.subTest(name):
                place = write_plant(self.store, name, "pass", ["a"], CAUSE, "base", fields)
                self.rejected(self.run_plants(), f"{name}: {rule}")
                discard(place)

    def test_a_checkout_without_a_lockfile_is_rejected(self):
        (self.repo / "Cargo.lock").unlink()
        self.rejected(self.run_plants("p-miss"), "the checkout holds no readable Cargo.lock")

    def test_a_checkout_whose_lockfile_is_a_link_is_rejected(self):
        outside = self.scratch / "outside.lock"
        (self.repo / "Cargo.lock").rename(outside)
        (self.repo / "Cargo.lock").symlink_to(outside)
        self.rejected(self.run_plants("p-miss"), "the checkout holds no readable Cargo.lock (no regular file)")

    def test_a_campaign_path_relative_to_the_invoking_directory_runs_from_there(self):
        done = subprocess.run(self.argv("p-noprofile")[:2] + ["--campaign", os.path.relpath(self.stand_in, self.repo)]
                              + self.argv("p-noprofile")[4:], cwd=self.repo, env=self.environment(),
                              capture_output=True, text=True, check=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual([call[:2] for call in self.calls()], [["sim", "archive"]])

    def test_a_patch_that_changes_paths_beyond_its_files_is_rejected(self):
        place = write_plant(self.store, "p-wider", "pass", ["a"], CAUSE, "base")
        (place / "plant.patch").write_text(patch_of("pass", "base") + "--- /dev/null\n+++ b/extra\n@@ -0,0 +1 @@\n+x\n")
        self.rejected(self.run_plants(), "p-wider: plant.patch changes extra, mode, and files names mode")
        discard(place)
        write_plant(self.store, "p-fewer", "pass", ["a"], CAUSE, "base", {"files": ["mode", "other"]})
        self.rejected(self.run_plants(), "p-fewer: plant.patch changes mode, and files names mode, other")

    def test_a_plant_store_that_differs_from_head_is_rejected(self):
        record = self.store / "p-miss" / "plant.json"
        patch = self.store / "p-miss" / "plant.patch"
        for path, edit in ((record, record.read_text().replace("A defect.", "Another defect.")),
                           (patch, patch_of("catch", "base"))):
            with self.subTest(path.name):
                before = path.read_text()
                path.write_text(edit)
                self.rejected(self.run_plants("p-miss"), f"differs from HEAD at verification/plants/p-miss/{path.name}")
                path.write_text(before)
        place = write_plant(self.store, "p-new", "pass", ["a"], CAUSE, "base")
        self.rejected(self.run_plants("p-miss"), "differs from HEAD at verification/plants/p-new/plant.json")
        discard(place)
        note = self.store / "p-miss" / "note"
        note.write_text("a file the commit does not hold\n")
        self.rejected(self.run_plants("p-miss"), "differs from HEAD at verification/plants/p-miss/note")
        note.unlink()
        # A plant the commit holds and the working tree lost would leave the score's population short.
        discard(self.store / "p-short")
        self.rejected(self.run_plants("p-miss"), "differs from HEAD at verification/plants/p-short/plant.json")

    def test_git_variables_that_point_at_another_repository_or_index_are_rejected(self):
        (self.repo / "mode").write_text("staged\n")
        self.git("add", "mode")
        (self.repo / "mode").write_text("base\n")
        before = self.state()
        for name, value in (("GIT_DIR", self.repo / ".git"), ("GIT_INDEX_FILE", self.repo / ".git" / "index")):
            with self.subTest(name):
                self.rejected(self.run_plants("p-miss", env={name: str(value)}), f"{name} would point")
                self.assertEqual(self.state(), before)

    def test_a_floor_below_300_is_rejected(self):
        done = self.run_plants("p-miss", extra=("--runs", "299"))
        self.assertEqual(done.returncode, 2)
        self.assertIn("below the floor of 300", done.stderr)
        self.assertEqual(self.calls(), [])

    def test_a_work_directory_inside_the_checkout_or_under_a_shared_directory_is_rejected(self):
        before = self.state()
        done = self.run_plants("p-miss", work=self.repo / "work")
        self.assertEqual(done.returncode, 2, done.stderr)
        self.assertIn("lies inside the checkout", done.stderr)
        self.assertFalse((self.repo / "work").exists())
        self.assertEqual(self.state(), before)
        shared = self.scratch / "shared"
        shared.mkdir()
        shared.chmod(0o777)
        self.rejected(self.run_plants("p-miss", work=shared / "inner" / "work"), "another user owns or can write")
        self.assertFalse((shared / "inner").exists())

    def test_a_default_work_directory_under_a_shared_temporary_directory_is_rejected_with_both_ways_out(self):
        before = self.state()
        shared = self.scratch / "shared-temporary"
        shared.mkdir()
        shared.chmod(0o777)
        argv = self.argv("p-miss")
        option = argv.index("--work")
        environment = {name: value for name, value in self.environment().items() if name not in ("TEMP", "TMP")}
        environment["TMPDIR"] = str(shared)
        done = subprocess.run(argv[:option] + argv[option + 2:], cwd=self.repo, env=environment,
                              capture_output=True, text=True, check=False)
        self.rejected(done, f"another user owns or can write {shared}")
        for way in ("--work", "TMPDIR"):
            self.assertIn(way, done.stderr)
        self.assertEqual(list(shared.iterdir()), [])
        self.assertEqual(self.state(), before)

    def test_an_existing_work_directory_and_a_directory_outside_a_checkout_are_rejected(self):
        self.work.mkdir()
        done = self.run_plants("p-miss")
        self.assertEqual(done.returncode, 2)
        self.assertIn("the work directory", done.stderr)
        self.work.rmdir()
        # A directory below the ceiling, so Git stops there and finds no checkout above the scratch directory.
        below = self.scratch / "outside"
        below.mkdir()
        outside = subprocess.run(self.argv("p-miss"), cwd=below, env=self.environment(),
                                 capture_output=True, text=True, check=False)
        self.rejected(outside, "outside a Git checkout")

    def test_a_campaign_binary_that_is_absent_is_rejected(self):
        self.rejected(self.run_plants("p-miss", extra=("--campaign", str(self.scratch / "absent"))),
                      "no campaign binary at")

    def test_an_unknown_plant_is_rejected(self):
        self.rejected(self.run_plants("p-none"), "no plant named p-none")

    def test_a_plant_at_the_score_s_path_is_rejected_before_any_work(self):
        write_plant(self.store, "score.json", "pass", ["a"], CAUSE, "base")
        self.commit("a plant at the score's path")
        done = self.run_plants()
        self.assertEqual(done.returncode, 2, done.stderr)
        self.assertIn("score.json: id is another name than score.json", done.stderr)
        self.assertEqual(self.calls(), [])
        self.assertFalse(self.work.exists())
        self.assertTrue(self.score.is_dir())

    def test_a_plant_whose_id_passes_245_bytes_is_rejected_and_one_of_245_keeps_its_proof_logs(self):
        longest, longer = "p-" + "x" * 243, "p-" + "x" * 244
        write_plant(self.store, longest, "pass", ["a"], CAUSE, "base")
        self.commit("a plant whose proof logs' names take 255 bytes")
        done = self.run_plants(longest)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.verdict(longest, "missed", "each expected profile reached 300 runs")
        for end in (".out", ".err"):
            self.assertTrue((self.work / "proof" / f"plant-{longest}{end}").is_file(), end)
        write_plant(self.store, longer, "pass", ["a"], CAUSE, "base")
        self.commit("a plant whose proof logs' names would pass 255 bytes")
        before = self.calls()
        done = self.run_plants(longer, work=self.scratch / "work-2")
        self.assertEqual(done.returncode, 2, done.stderr)
        self.assertIn("id holds at most 245 bytes", done.stderr)
        self.assertEqual(self.calls(), before)
        self.assertFalse((self.scratch / "work-2").exists())

    def test_a_score_that_cannot_be_written_exits_4_with_the_results(self):
        """The stand-in makes the score's path a directory during the run, which no user's staging file replaces."""
        done = self.run_plants("p-miss", env={"STANDIN_BLOCK_SCORE": str(self.score)})
        self.assertEqual(done.returncode, 4, done.stderr)
        self.assertIn("plant-runner wrote no score", done.stderr)
        self.assertIn("p-miss: missed (each expected profile reached 300 runs", done.stderr)
        self.assertNotIn("plants at commit", done.stdout)
        self.assertTrue(self.score.is_dir())
        self.assertEqual([path.name for path in self.store.iterdir() if path.name.startswith(".score.json.")], [])


class Checkout(Fixture):
    def test_the_starting_checkout_stays_unchanged_but_for_the_score(self):
        names = [*PLANTS, *(name for name in EXTRA if name not in APART)]
        self.stock(*names)
        before = self.state()
        done = self.run_plants(*names)
        self.assertEqual(done.returncode, 1, done.stderr)
        self.verdict("p-lock", "missed", "each expected profile reached 300 runs")
        self.score.unlink()
        self.assertEqual(self.state(), before)

    def test_a_run_of_the_whole_store_selects_no_plant_in_its_settings(self):
        self.run_plants()
        written, _ = self.results()
        self.assertIsNone(written["settings"]["plants"])

    def test_a_staging_file_or_link_beside_the_score_stays_as_it_was(self):
        sentinel, target = self.store / "score.json.tmp", self.scratch / "target"
        sentinel.write_text("a sentinel\n")
        target.write_text("a target\n")
        link = self.store / ".score.json.link"
        link.symlink_to(target)
        done = self.run_plants("p-miss")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(sentinel.read_text(), "a sentinel\n")
        self.assertTrue(link.is_symlink())
        self.assertEqual(target.read_text(), "a target\n")
        self.assertFalse(self.score.is_symlink())
        self.assertEqual(oct(self.score.stat().st_mode & 0o777), oct(0o666 & ~current_umask()))

    def test_a_score_that_is_a_link_is_replaced_and_its_target_stays(self):
        target = self.scratch / "elsewhere.json"
        target.write_text("another file\n")
        self.score.symlink_to(target)
        done = self.run_plants("p-noprofile")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertFalse(self.score.is_symlink())
        self.assertEqual(target.read_text(), "another file\n")
        written, _ = self.results()
        self.assertEqual(written["commit"], self.head)

    def test_a_run_leaves_an_index_whose_plant_entry_is_stale_as_it_was(self):
        index, record = self.repo / ".git" / "index", self.store / "p-noprofile" / "plant.json"
        before = index.read_bytes()
        later = record.stat().st_mtime + 5
        os.utime(record, (later, later))
        done = self.run_plants("p-noprofile")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(index.read_bytes(), before)

    def test_a_worktree_the_run_cannot_remove_exits_4_and_names_it(self):
        done = self.run_plants("p-miss", env=self.git_shim("remove", "echo 'a refused removal' >&2; exit 1"))
        self.assertEqual(done.returncode, 4, done.stderr)
        self.assertIn(f"plant-runner left the worktree {self.work / 'plants' / 'p-miss' / 'tree'}", done.stderr)
        self.assertFalse(self.score.exists())

    def test_a_worktree_listing_that_fails_exits_4_and_names_the_worktree(self):
        done = self.run_plants("p-miss", env=self.git_shim("list", "echo 'a refused listing' >&2; exit 1"))
        self.assertEqual(done.returncode, 4, done.stderr)
        tree = self.work / "plants" / "p-miss" / "tree"
        self.assertIn(f"plant-runner cannot tell whether the worktree {tree} remains", done.stderr)
        self.assertFalse(self.score.exists())

    def test_a_worktree_the_run_cannot_remove_after_a_signal_is_named_before_the_signal_s_exit(self):
        # The signal lands during the add, so the cleanup that follows it runs with the signal pending.
        action = ("case \" $* \" in *\" add \"*) kill -TERM $PPID; sleep 0.5;; "
                  "*\" remove \"*) echo 'a refused removal' >&2; exit 1;; esac")
        done = self.run_plants("p-miss", env=self.git_shim("worktree", action))
        self.assertEqual(done.returncode, 128 + signal.SIGTERM, done.stderr)
        self.assertIn(f"plant-runner left the worktree {self.work / 'plants' / 'p-miss' / 'tree'}", done.stderr)
        self.assertEqual(self.calls(), [])
        self.assertFalse(self.score.exists())

    def test_a_signal_during_the_worktree_add_lets_the_add_finish_and_removes_the_worktree(self):
        before = self.state()
        started, finished = self.scratch / "started", self.scratch / "finished"
        add = (f"touch {started}; kill -TERM $PPID; sleep 0.5; \"$real\" \"$@\"; code=$?; touch {finished}; "
               "exit $code")
        done = self.run_plants("p-miss", env=self.git_shim("add", add))
        self.assertEqual(done.returncode, 128 + signal.SIGTERM, done.stderr)
        self.assertTrue(started.exists() and finished.exists(), "the signal ended the worktree add")
        self.assertEqual(self.calls(), [])
        self.assertFalse(self.score.exists())
        self.assertEqual(self.state(), before)

    def signal_run(self, name, first, second, group=False):
        """Starts the runner on the plant `name`, sends `first` once the stand-in is ready and `second` while the
        stand-in handles the first, and returns the runner's exit and error output. With `group`, the runner leads
        its own session and each signal goes to its whole process group."""
        self.stock(name)
        before = self.state()
        runner = subprocess.Popen(self.argv(name), cwd=self.repo, env=self.environment(), stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, start_new_session=group, preexec_fn=handled_signals)
        self.addCleanup(lambda: runner.poll() is None and runner.kill())

        def send(number):
            if group:
                os.killpg(runner.pid, number)
            else:
                runner.send_signal(number)

        self.wait_for(self.scratch / "ready", runner)
        send(first)
        self.wait_for(self.scratch / "handling", runner)
        if second is not None:
            send(second)
            time.sleep(0.2)
            self.assertIsNone(runner.poll(), "the runner exited before the stand-in finished")
        (self.scratch / "release").write_text("")
        _, err = runner.communicate(timeout=60)
        self.assertEqual((self.scratch / "terminated").read_text(), str(int(signal.SIGTERM)))
        self.assertFalse(self.score.exists())
        self.assertEqual(self.state(), before)
        return runner.returncode, err.decode()

    def wait_for(self, path, runner):
        for _ in range(600):
            if path.exists():
                return
            if runner.poll() is not None:
                self.fail(f"the runner exited {runner.returncode} before {path.name}")
            time.sleep(0.05)
        self.fail(f"no {path.name} within 30 s")

    def test_a_signal_stops_the_sweep_and_removes_the_worktrees(self):
        for first, second in ((signal.SIGTERM, signal.SIGHUP), (signal.SIGINT, signal.SIGTERM),
                              (signal.SIGTERM, signal.SIGINT)):
            with self.subTest(f"{first.name} then {second.name}"):
                for marker in ("ready", "handling", "release", "terminated"):
                    (self.scratch / marker).unlink(missing_ok=True)
                discard(self.work)
                code, err = self.signal_run("p-hang", first, second)
                self.assertEqual(code, 128 + first, err)

    def test_a_signal_that_lands_once_the_score_is_written_leaves_the_run_its_own_exit(self):
        """The child replaces `publish` with one that writes the score and then sends the run SIGTERM."""
        program = textwrap.dedent("""\
            import importlib.util, os, signal, sys
            spec = importlib.util.spec_from_file_location("plant_runner", sys.argv[1])
            runner = importlib.util.module_from_spec(spec)
            sys.dont_write_bytecode = True
            spec.loader.exec_module(runner)
            written = runner.publish
            def publish(target, score):
                written(target, score)
                os.kill(os.getpid(), signal.SIGTERM)
            runner.publish = publish
            sys.exit(runner.main(sys.argv[2:]))
            """)
        argv = self.argv("p-miss")
        done = subprocess.run([argv[0], "-c", program, *argv[1:]], cwd=self.repo, env=self.environment(),
                              capture_output=True, text=True, check=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        written, _ = self.results()
        self.assertIn(written["sentence"], done.stdout)
        self.verdict("p-miss", "missed", "each expected profile reached 300 runs")

    def test_a_signal_during_the_build_removes_its_target_and_worktree(self):
        code, err = self.signal_run("p-hangbuild", signal.SIGTERM, signal.SIGHUP)
        self.assertEqual(code, 128 + signal.SIGTERM, err)
        self.assertFalse((self.work / "plants" / "p-hangbuild" / "target").exists())

    def test_a_signal_to_the_group_during_a_proof_rerun_reaches_the_proof_only_through_the_runner(self):
        code, err = self.signal_run("p-hangproof", signal.SIGHUP, None, group=True)
        self.assertEqual(code, 128 + signal.SIGHUP, err)
        self.assertFalse((self.work / "proof" / "target").exists())
        self.assertFalse((self.work / "proof" / "tree").exists())

    def test_a_sighup_inherited_as_ignored_stays_ignored(self):
        self.stock("p-hang")
        before = self.state()
        ignoring = ["sh", "-c", 'trap "" HUP; exec "$@"', "sh", *self.argv("p-hang")]
        runner = subprocess.Popen(ignoring, cwd=self.repo, env=self.environment(), stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
        self.addCleanup(lambda: runner.poll() is None and runner.kill())
        self.wait_for(self.scratch / "ready", runner)
        runner.send_signal(signal.SIGHUP)
        time.sleep(0.3)
        self.assertIsNone(runner.poll(), "an ignored SIGHUP stopped the run")
        self.assertFalse((self.scratch / "handling").exists())
        runner.send_signal(signal.SIGTERM)
        self.wait_for(self.scratch / "handling", runner)
        (self.scratch / "release").write_text("")
        _, err = runner.communicate(timeout=60)
        self.assertEqual(runner.returncode, 128 + signal.SIGTERM, err.decode())
        self.assertEqual(self.state(), before)


def current_umask():
    umask = os.umask(0)
    os.umask(umask)
    return umask


def load_runner():
    spec = importlib.util.spec_from_file_location("plant_runner", RUNNER)
    if spec is None or spec.loader is None:
        raise unittest.SkipTest("plant-runner.py cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    spec.loader.exec_module(module)
    return module


class Defaults(unittest.TestCase):
    """The default working values: 28 workers, a floor of 300 runs, 60 s a sweep, 10 sweeps;
    and the exit of a signal that lands after the cleanup, which no run of the fixture can place."""

    def test_a_run_without_options_takes_the_working_values(self):
        runner = load_runner()
        args = runner.parser().parse_args([])
        self.assertEqual((args.workers, args.runs, args.seconds, args.rounds), (28, 300, 60, 10))
        self.assertEqual(runner.FLOOR, 300)

    def test_the_handler_exits_128_plus_the_signal_outside_a_deferred_region(self):
        runner = load_runner()
        with self.assertRaises(SystemExit) as stopped:
            runner.stop(signal.SIGHUP, None)
        self.assertEqual(stopped.exception.code, 128 + signal.SIGHUP)
        self.assertEqual(runner.Signals.pending, signal.SIGHUP)


class SpawnWindow(unittest.TestCase):
    """A signal that lands after the child exists and before the runner holds its handle."""

    def test_a_signal_in_the_spawn_window_terminates_and_reaps_the_child(self):
        runner = load_runner()
        scratch = scratch_directory()
        self.addCleanup(shutil.rmtree, scratch, True)
        child = scratch / "child"
        child.write_text(textwrap.dedent(f"""\
            #!/usr/bin/env python3
            import signal, sys, time
            def ended(number, frame):
                time.sleep(0.5)
                open("{scratch / 'terminated'}", "w").write(str(number))
                sys.exit(4)
            signal.signal(signal.SIGTERM, ended)
            open("{scratch / 'ready'}", "w").write("")
            time.sleep(60)
            """))
        child.chmod(0o755)
        real = subprocess.Popen

        def spawned(*args, **kwargs):
            process = real(*args, **kwargs)
            for _ in range(1500):
                if (scratch / "ready").exists() or process.poll() is not None:
                    break
                time.sleep(0.02)
            if not (scratch / "ready").exists():
                process.kill()
                process.wait()
                raise AssertionError("the child wrote no ready marker within 30 s")
            os.kill(os.getpid(), signal.SIGTERM)
            return process

        saved = {number: signal.getsignal(number) for number in runner.HANDLED}
        self.addCleanup(lambda: [signal.signal(number, handler) for number, handler in saved.items()])
        runner.install()
        runner.subprocess.Popen = spawned
        self.addCleanup(setattr, runner.subprocess, "Popen", real)
        args = type("Args", (), {"campaign": str(child)})()
        run = runner.Run.__new__(runner.Run)
        run.args = args
        with self.assertRaises(SystemExit) as stopped:
            run.command(scratch / "sweep", "sweep")
        self.assertEqual(stopped.exception.code, 128 + signal.SIGTERM)
        self.assertEqual((scratch / "terminated").read_text(), str(int(signal.SIGTERM)))


if __name__ == "__main__":
    unittest.main()
