#!/usr/bin/env python3
"""Judge whether a run is a valid run of an ordering-figure scenario row.

    python3 -I -B chaos/judges/ordering/validity.py <scenario-id> --evidence chaos/runs/<run-id> [--receipt FILE]

The scenario sweeps planted ordering controls only, and a control passes no run, so validity rests
on each control's own counts. Exit 0 means valid: the sweep's records stand as `trusted` in
chaos/judges/core/common.py decides them (campaign sweep returned by itself with exit 0 and no
alarm, no_pass or unreached, on a root that holds the archive's build, with no process left, the
archive verified, the status naming the run's campaign and counts, history.jsonl agreeing with
both and no suspect of class `replay differs` anywhere in the root), and each profile of the
scenario is a control the worker lists, with at least the row's minimum of runs, a replay, no
suspect and positive faults_delivered, the link faults the row's injection oracle names.

A control run of this family is the same sweep on another archive: its defect is a change to the
worker's build, and run.json names it as a label that no swept profile carries. The checks
`trusted` makes of a control run need the defect among the swept profiles, so this judge hands
`trusted` the run record as a live one with no defect.

Beside `trusted`, the run stands when the totals carry no `no_window` key either, the swept
profiles are the scenario's controls, each a control in the status too, no other profile but a
rotating history ran, run.json's run range of each agrees with the status and history.jsonl, the
status's control totals equal the sums over its control entries, and no profile of the status
counts a missed run. The judge holds records.py, like common.py, to the bytes it executed.
Exit 2 means the run shows nothing about the scenario, exit 3 that it stopped before its evidence
was complete. This judge decides validity alone, so it never exits 1.
"""
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import os
import stat
import sys
from pathlib import Path
from typing import Any, NoReturn


def refuse(text: str) -> NoReturn:
    """Exit 2 with one line on standard error, which may be closed; no text of the line can stop the exit."""
    with contextlib.suppress(OSError):
        os.write(2, f"{text}\n".encode("utf-8", "backslashreplace"))
    os._exit(2)


# A standard stream the caller closed is opened on /dev/null, so no file the judge opens takes its number.
for number in (0, 1, 2):
    try:
        os.fstat(number)
    except OSError:
        try:
            opened = os.open(os.devnull, os.O_RDWR)
        except OSError:
            refuse("cannot open /dev/null in place of a closed standard stream")
        if opened != number:
            refuse("a closed standard stream could not be opened again on /dev/null")
if not sys.flags.isolated or not sys.flags.dont_write_bytecode:
    refuse(f"start the judge as python3 -I -B {sys.argv[0]} ...")
here = Path(__file__).resolve().parent
core = here.parent / "core"
try:
    # The judge executes the common.py and records.py bytes it read once and hashes each for its
    # LOADED_SHA256, through a loader that returns those bytes alone, so no bytecode cache takes part.
    # The bound is common.SOURCE_BYTES.
    for folder in {here, core}:
        for entry in os.scandir(folder):
            if not entry.is_file(follow_symlinks=False):
                raise OSError(f"{entry.name} beside the judge is no regular file")

    def load(name: str, folder: Path) -> Any:
        """The module `name` of `folder`, executed from the bytes read here, which keeps the search path of isolated mode."""
        path = str(folder / f"{name}.py")
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as file:
            if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
                raise OSError(f"{name}.py is no regular file")
            source = file.read((1 << 22) + 1)
        if len(source) > 1 << 22:
            raise OSError(f"{name}.py holds more than its bound of bytes")

        class Checked(importlib.machinery.SourceFileLoader):
            def get_data(self, path: str) -> bytes:
                if path != self.path:
                    raise OSError(f"the judge reads {name}.py's source alone")
                return source

        spec = importlib.util.spec_from_file_location(name, path, loader=Checked(name, path))
        if spec is None or spec.loader is None:
            raise ImportError(f"{name}.py has no loader")
        module = importlib.util.module_from_spec(spec)
        module.__dict__["LOADED_SHA256"] = hashlib.sha256(source).hexdigest()
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module

    common: Any = load("common", core)
    records: Any = load("records", here)
    HELD, INVALID, Verdict, count, main = common.HELD, common.INVALID, common.Verdict, common.count, common.main
except Exception as error:  # an import that fails is no verdict
    refuse(f"cannot load the judge: {error.__class__.__name__}: {error}")


def standing(scenario: dict, evidence: Any) -> dict:
    """The status document of a run whose records stand, read with a control run's defect as its label."""
    run = evidence.run
    evidence.run = dict(run, mode="live", defect="")
    try:
        return common.trusted(scenario, evidence)
    finally:
        evidence.run = run


def decide(row: dict, scenario: dict, evidence: Any) -> tuple[int, str]:
    status = standing(scenario, evidence)
    flags = records.flags(status)
    if flags:
        raise Verdict(INVALID, f"the totals carry the flags {flags}, and the sweep of a valid run exits 0 with none")
    need = common.minimum(scenario, "load_delivery", "min_runs_per_profile")
    controls = records.controls(scenario, evidence, status)
    records.ranges(evidence, status)
    records.totals(status)
    parts = []
    for profile in controls:
        entry = status["profiles"][profile]
        runs, replays, suspects, faults, missed = (count(entry, key, f"control {profile}") for key in
                                                   ("runs", "replays", "suspects", "faults_delivered", "missed"))
        if runs < need:
            raise Verdict(INVALID, f"minimum unmet: {profile} has {runs} runs, and the row requires {need}")
        if replays == 0:
            raise Verdict(INVALID, f"{profile} has no replay, so no run of it was shown to replay in a fresh process")
        keys = entry.get("suspect_keys")
        if suspects or keys:
            raise Verdict(INVALID, f"{profile} lists {suspects} suspects: {sorted(keys or {})[:1]!r}"[:300])
        if missed:
            raise Verdict(INVALID, f"{profile} missed {missed} runs, so a check let its planted defect through")
        if faults == 0:
            raise Verdict(INVALID, f"{profile} delivered no link fault, so the row's injection oracle saw no fault")
        parts.append(f"{profile} {runs} runs of {need} required, {replays} replays, {faults} link faults")
    records.alarmed(status)
    label = f"; control {evidence.run['defect']} on build {evidence.run['system_build']}" \
        if evidence.run["mode"] == "control" else ""
    return HELD, "valid: " + "; ".join(parts) + label


if __name__ == "__main__":
    common.sources = records.bound_sources(common.sources)
    sys.exit(main("scenarios", decide))
