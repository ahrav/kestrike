#!/usr/bin/env python3
"""Judge the required-event invariant on a run of a scenario that lists it.

    python3 -I -B chaos/judges/reach/reach.py <invariant-id> --evidence chaos/runs/<run-id> [--receipt FILE]

The row is a `threshold` invariant: threshold.min_covered_passes is the covered-pass floor at
which campaign sweep's required-event gate is armed, and the scenario's
load_delivery.min_covered_per_profile states the same floor; threshold.min_reaching_passes, 1,
states that one covered pass makes an event reached, so the judge compares reaching passes by
predicate (> 0, == 0) and refuses a row that states another number. Each of the three is read
through common.minimum. The judge decides only on a sweep that `sound` in shared.py accepts; its
docstring lists what that takes. The decision itself reads the row's threshold, property text,
witness.expect and control, the run record's mode and defect, and, for the profiles of the
scenario, the status's `unreached`, `no_pass` and `profiles.<profile>`'s `covered` and `reached`:

    broken      the recorded sweep exit is 1 and the status lists a profile of the scenario under
                `unreached` or `no_pass`, each listed event a coverage counter no covered pass
                reached on a profile at the floor and one the committed table requires, or in a
                control the pair its row's control.defect plants; the detail names the profile and
                its events, a control's planted event first, and holds the row's full property text
    held        the recorded exit is 0, the status carries none of the three keys, each scenario
                profile has at least min_covered_passes covered passes and, for each coverage
                counter outside the committed table's excused pairs, a covered pass that reached
                it, and each cluster profile meets the scenario row's reach minimums
    incomplete  a profile has fewer covered passes and the status carries no verdict key, so the
                gate was not armed; a recorded exit 3 or 4, a stopped run or an incomplete run record
    invalid     whatever `sound` refuses; rows whose floors or reaching passes disagree; a scenario
                profile the committed table has no row for; `unreached` or `no_pass` naming only
                profiles outside the scenario (a scripted history the sweep adds); an `unreached`
                entry or a silent counter that the profile's counts or the table contradict; a
                control run whose defect is not the row's, whose control.defect plants no excused
                pair, or whose sweep does not list the pair it plants

The row's control.defect is the label `requires-<event>-of-<profile>`, which names the excused
pair that the control's table requires. The row's control.expect is its property text, which every
broken detail holds: the harness keeps a broken receipt only when its detail holds control.expect.

The broken, held and under-floor incomplete details list the excused pairs of the required-event
table that the run reached. Every receipt ends with the scope sentence (shared.py).
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.machinery
import importlib.util
import os
import re
import sys
from pathlib import Path
from typing import NoReturn


def refuse(text: str) -> NoReturn:
    """Exit 2 with one line on standard error, which may be closed."""
    with contextlib.suppress(OSError):
        os.write(2, f"{text}\n".encode())
    os._exit(2)


# A standard stream the caller closed is opened on /dev/null, so no file the judge opens takes its number.
for number in (0, 1, 2):
    try:
        os.fstat(number)
    except OSError:
        os.open(os.devnull, os.O_RDWR)
if not sys.flags.isolated or not sys.flags.dont_write_bytecode:
    refuse(f"start the judge as python3 -I -B {sys.argv[0]} ...")
here = Path(__file__).resolve().parent
core = here.parent / "core"
try:
    # The judge executes the same common.py and shared.py bytes it reads, and hashes common.py's for LOADED_SHA256.
    for folder in {here, core}:
        for entry in os.scandir(folder):
            if not entry.is_file(follow_symlinks=False):
                raise OSError(f"{entry.name} beside the judge is no regular file")
    for name, path in (("common", str(core / "common.py")), ("shared", str(here / "shared.py"))):
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as file:
            source = file.read()

        class Checked(importlib.machinery.SourceFileLoader):
            def get_data(self, path: str, source: bytes = source) -> bytes:
                if path != self.path:
                    raise OSError(f"the judge reads {Path(self.path).name}'s source alone")
                return source

        spec = importlib.util.spec_from_file_location(name, path, loader=Checked(name, path))
        if spec is None or spec.loader is None:
            raise ImportError(f"{Path(path).name} has no loader")
        module = importlib.util.module_from_spec(spec)
        if name == "common":
            module.__dict__["LOADED_SHA256"] = hashlib.sha256(source).hexdigest()
        sys.modules[name] = module
        spec.loader.exec_module(module)
    from common import (  # pyright: ignore[reportMissingImports]
        BROKEN,
        HELD,
        INCOMPLETE,
        INVALID,
        Evidence,
        Verdict,
        count,
        distinct,
        main,
        minimum,
        reached,
        scenario_profiles,
    )
    from shared import COVERAGE, EXCUSED, ROWS, excused_reached, quoted, reach_counts, sound  # pyright: ignore[reportMissingImports]
except Exception as error:  # an import that fails is no verdict
    refuse(f"cannot load the judge: {error.__class__.__name__}: {error}")

PLANT = re.compile(r"requires-([a-z]+)-of-([a-z0-9]+(?:-[a-z0-9]+)*)")


def planted(row: dict, evidence: Evidence) -> dict[str, list[str]]:
    """The pair a control run's table plants, read from the row's control.defect label; {} for a live run."""
    if evidence.run["mode"] == "live":
        return {}
    control: dict = row["control"] if isinstance(row.get("control"), dict) else {}
    if evidence.run["defect"] != control.get("defect"):
        raise Verdict(INVALID, f"the control run's defect {quoted(evidence.run['defect'])} is not the row's control "
                               f"{quoted(control.get('defect'))}")
    match = PLANT.fullmatch(str(control.get("defect", "")))
    if match is None:
        raise Verdict(INVALID, f"{row.get('id')}: control.defect names no pair as requires-<event>-of-<profile>")
    event, profile = match[1], match[2]
    if event not in EXCUSED.get(profile, ()):
        raise Verdict(INVALID, f"{row.get('id')}: control.defect plants {profile}: {event}, and the committed table "
                               "excuses no such pair")
    return {profile: [event]}


def disagreement(reached: int, armed: bool, required: bool) -> str | None:
    """Why the status's own counts or the committed table contradict an `unreached` entry, or None."""
    if not armed:
        return "the profile is under the row's covered-pass floor, where the gate is not armed"
    if reached != 0:
        return f"{reached} covered passes reached it"
    if not required:
        return "the committed table excuses it, and the run's table requires it only in the control that plants it"
    return None


def listed(profile: str, events: list[str], plant: dict[str, list[str]]) -> str:
    """One break clause: the profile's planted event first, so a control's detail reads `unreached <profile>: <event>`."""
    first = plant.get(profile, [])
    return f"unreached {profile}: {', '.join(first + [event for event in events if event not in first])}"


def decide(row: dict, scenario: dict, evidence: Evidence) -> tuple[int, str]:
    sweep = sound(scenario, evidence)
    floor = minimum(row, "threshold", "min_covered_passes")
    if minimum(row, "threshold", "min_reaching_passes") != 1:
        raise Verdict(INVALID, f"{row.get('id')}: threshold.min_reaching_passes is "
                               f"{row['threshold']['min_reaching_passes']}, and the gate reads one covered pass as "
                               "reaching an event")
    stated = minimum(scenario, "load_delivery", "min_covered_per_profile")
    if stated != floor:
        raise Verdict(INVALID, f"{scenario.get('id')}: load_delivery.min_covered_per_profile is {stated}, and the "
                               f"row's covered-pass floor is {floor}")
    rule = row["property"].get("text") if isinstance(row.get("property"), dict) else None
    if not isinstance(rule, str) or not rule:
        raise Verdict(INVALID, f"{row.get('id')}: the row holds no property text")
    plant = planted(row, evidence)
    status, profiles = sweep.status, distinct(scenario_profiles(scenario))
    unlisted = [profile for profile in profiles if profile not in ROWS]
    if unlisted:
        raise Verdict(INVALID, f"the committed required-event table has no row for the scenario's profile {unlisted[0]}")
    counts = reach_counts(status, profiles)
    excused = excused_reached(counts)
    covered = {profile: count(status["profiles"][profile], "covered", f"profile {profile}") for profile in profiles}
    armed = {profile: covered[profile] >= floor for profile in profiles}
    for profile in profiles:
        events = sweep.unreached.get(profile, [])
        required = [event for event in COVERAGE if event not in EXCUSED[profile] or event in plant.get(profile, ())]
        for event in events:
            contradiction = disagreement(counts[profile][event], armed[profile], event in required)
            if contradiction:
                raise Verdict(INVALID, f"the status lists {profile}: {event} under unreached, and {contradiction}")
        omitted = [event for event in required if counts[profile][event] == 0 and event not in events]
        unshown = [event for event in omitted if event in plant.get(profile, ())]
        if armed[profile] and unshown:
            raise Verdict(INVALID, f"the control's sweep lists no unreached entry for its planted pair {profile}: "
                                   f"{', '.join(unshown)}, which no covered pass reached, so the plant shows no effect")
        if armed[profile] and omitted:
            raise Verdict(INVALID, f"no covered pass of {profile} reached {', '.join(omitted)}, which the committed "
                                   "table requires, and the status lists no unreached entry for it")
    breaks = [listed(profile, sweep.unreached[profile], plant) for profile in profiles if profile in sweep.unreached]
    breaks += [f"no_pass {profile}" for profile in profiles if profile in sweep.no_pass]
    missing = [f"{profile}: {event}" for profile, events in plant.items() for event in events
               if event not in sweep.unreached.get(profile, [])]
    if breaks and missing:
        raise Verdict(INVALID, f"the control's sweep lists {'; '.join(breaks)} and not its planted pair "
                               f"{', '.join(missing)}, so the break is no effect of the plant")
    if breaks:
        return BROKEN, f"{'; '.join(breaks)}; the row's property: \"{rule}\"; {excused}"
    if sweep.unreached or sweep.no_pass:
        raise Verdict(INVALID, f"campaign sweep exited {sweep.code} on unreached {quoted(sorted(sweep.unreached))} "
                               f"and no_pass {quoted(sweep.no_pass)}, which name no profile of the scenario")
    short = [f"{profile} {covered[profile]}" for profile in profiles if not armed[profile]]
    if short:
        raise Verdict(INCOMPLETE, f"covered passes under the row's floor of {floor}: {', '.join(short)}, so the "
                                  f"required-event gate was not armed for each profile; {excused}")
    if plant:
        raise Verdict(INVALID, f"the control's sweep lists no unreached entry, so its planted pair "
                               f"{', '.join(missing)} shows no effect")
    parts = [f"{profile} {covered[profile]} covered passes" for profile in profiles] + reached(scenario, evidence, status)
    witness = row["witness"].get("expect", "") if isinstance(row.get("witness"), dict) else ""
    return HELD, (f"{witness}: no unreached, no_pass or alarm; each profile has at least {floor} covered passes and, "
                  f"for each coverage counter outside the excused pairs, a covered pass that reached it: "
                  f"{'; '.join(parts)}; {excused}")


if __name__ == "__main__":
    sys.exit(main("invariants", decide))
