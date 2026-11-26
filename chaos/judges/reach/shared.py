"""What both reach judges share: the scope sentence, the required-event table and the check of a sound sweep.

reach.py and validity.py load chaos/judges/core/common.py by its path as the module `common`, and
then this file. Loading this file wraps common.receipt_for and common.report, so every receipt
either judge writes and every verdict line it prints, a refusal that common.main gives before the
judge decides included, ends its detail with SCOPE: the line of chaos/project.yaml that limits a
reach result to the simulated environment. The verdict line and the receipt's detail stay equal.
chaos/tests/test_reach.py fails when the two differ. A judge loaded with an empty SCOPE exits 2.

`campaign sweep` exits 1 when its totals carry `alarm` (a missed control or history run),
`no_pass` (a profile outside the controls with a run and none counted under pass or caught, past
the supervisor's own floor of runs) or `unreached` (a required event with no reaching pass on a
profile at the table's covered-pass floor). The last two are the sweep's verdict on reach, which
the invariant ks-required-events-reached judges, so `sound` checks the rest of the run with those
two keys set aside. Of the two keys it checks their form and the entries they name; whether an
`unreached` entry agrees with the profile's counts and the table is the reach judge's to decide.
"""
from __future__ import annotations

import functools
import inspect
import json
import sys
from typing import NamedTuple

import common  # pyright: ignore[reportMissingImports]

SCOPE = ("A reach count is evidence about the simulated environment only: it shows that a passing run of the named "
         "profile reached the event on this build at these counts, and it shows neither that a check judged the "
         "event nor that production reaches it.")
# EXCUSED must name the profiles of REQUIRED in crates/campaign-supervisor/src/campaign/seeds/required.rs,
# each with the events that row excuses; the row requires every other coverage counter.
EXCUSED = {"cluster-swarm": (), "cluster-broad": (), "cluster-pressure": ("invalidated", "cancelled")}
ROWS = frozenset(EXCUSED)
# COVERAGE must match the counters of COVERAGE in crates/campaign-supervisor/src/protocol/summary.rs.
COVERAGE = ("published", "hits", "misses", "refused", "invalidated", "cancelled", "cross", "reused", "healthy", "faults")
REACH_KEYS = ("no_pass", "unreached")
# The suspect classes of a control or history run that let its planted defect or declared failure
# through, which the supervisor counts under `missed`: MISSED of crates/campaign-supervisor/src/campaign/seeds.rs.
MISSED = ("control passed", "control met no check")
# NO_PASS_RUNS must match crates/campaign-supervisor/src/campaign/seeds.rs: `no_pass` lists a profile from this many runs.
NO_PASS_RUNS = 64
INVALID, Verdict, count = common.INVALID, common.Verdict, common.count

if not SCOPE.strip():
    sys.stderr.write("the reach judges hold no scope sentence, so no reach receipt could state its scope\n")
    sys.exit(INVALID)

# Each load wraps the original common.receipt_for, so each receipt includes SCOPE exactly once even
# after repeated loads in the same process.
unscoped_receipt = inspect.unwrap(common.receipt_for)


@functools.wraps(unscoped_receipt)
def scoped_receipt(*args: object) -> dict:
    """The receipt common.main writes, with SCOPE appended to its detail."""
    receipt = unscoped_receipt(*args)
    receipt["key"]["detail"] = f"{receipt['key']['detail']}; {SCOPE}"
    return receipt


unscoped_report = inspect.unwrap(common.report)


@functools.wraps(unscoped_report)
def scoped_report(text: str) -> None:
    """The verdict line common.main prints, with SCOPE appended to its detail as the receipt holds it."""
    line = text.removesuffix("\n")
    unscoped_report(f"{line}; {SCOPE}\n")


common.receipt_for = scoped_receipt
common.report = scoped_report


def quoted(value: object) -> str:
    """A status value as JSON, cut at 200 characters, for a detail: one line, whatever the value holds."""
    return json.dumps(value)[:200]


class Unjudged(common.Evidence):
    """The run's evidence with the sweep's reach verdict set aside, for common.trusted's check of its records.

    Its status is the document `sound` read, without `no_pass` and `unreached`, and a recorded sweep
    exit 1 that one of them explains reads as 0; `sound` has already required that exit 1 for them.
    A control whose defect is the run's label and no swept profile is the scenario's own sweep under
    another campaign binary, so its records stand on a live run's terms.
    """

    def __init__(self, evidence: common.Evidence, status: dict) -> None:
        self.__dict__.update(vars(evidence))
        self.run = dict(evidence.run)
        self.unjudged = {key: value for key, value in status.items() if key not in REACH_KEYS}
        if any(key in status for key in REACH_KEYS):
            self.run["sweep_exit"] = 0
        if self.run["mode"] == "control" and self.run["defect"] not in self.run["profiles"]:
            self.run.update(mode="live", defect="")

    def status(self) -> dict:
        return self.unjudged


def names(value: object) -> bool:
    """True for a non-empty list of distinct strings, as the sweep prints each name of a reach key once."""
    return (isinstance(value, list) and bool(value) and all(isinstance(item, str) for item in value)
            and len(set(value)) == len(value))


class Sweep(NamedTuple):
    """A sound sweep's records: its whole status document, recorded sweep exit and the two reach keys."""

    status: dict
    code: int
    unreached: dict[str, list[str]]
    no_pass: list[str]


def bounded(value: object, where: str = "the status") -> None:
    """Raise INVALID for an integer of the status above 2^64 - 1, the width of every count the sweep prints."""
    if type(value) is int and value > common.U64_MAX:
        raise Verdict(INVALID, f"{where[:200]} records {value}, above 2^64 - 1, the width of the sweep's counts")
    if isinstance(value, dict):
        for key, item in value.items():
            bounded(item, f"{where}.{key}")
    elif isinstance(value, list):
        for item in value:
            bounded(item, where)


def missed_runs(status: dict, entries: dict, lines: list[dict]) -> None:
    """Raise INVALID when a record of the status or suspects.jsonl shows a missed run beside a status with no alarm.

    The supervisor counts a missed run under its profile's `missed` and under the `missed` of the
    controls or histories totals, both of which every status prints, and records it as a suspect of
    a MISSED class; any one of those without `alarm` is a status no sweep prints.
    """
    missed = [f"{quoted(profile)} {entry['missed']}" for profile, entry in entries.items()
              if count(entry, "missed", f"profile {quoted(profile)}") > 0]
    missed += [f"{group} {status[group]['missed']}" for group in ("controls", "histories")
               if count(status.get(group), "missed", f"the status's {group}") > 0]
    missed += [f"{quoted(profile)} {quoted(key)}" for profile, entry in entries.items()
               if isinstance(entry.get("suspect_keys"), dict)
               for key in entry["suspect_keys"] if common.identity(key)[0] in MISSED]
    missed += [f"{quoted(line['profile'])} {quoted(line['class'])}" for line in lines if line["class"] in MISSED]
    if missed:
        raise Verdict(INVALID, f"missed runs without alarm: {', '.join(missed)[:300]}, so the totals disagree with "
                               "their records")


def reach_entries(status: dict, entries: dict, code: int) -> tuple[dict[str, list[str]], list[str]]:
    """The status's `unreached` and `no_pass`, or raise INVALID for keys of a form or on entries no sweep prints.

    `no_pass` lists distinct profiles, and they are the profiles outside the controls with
    NO_PASS_RUNS runs or more and none counted under pass or caught: an entry under that floor or
    with a pass or a catch is refused, and so is such a profile the key leaves out. `unreached` maps
    distinct profiles of the committed table outside the controls to distinct coverage counters;
    either key comes with a recorded exit 1.
    """
    unreached, no_pass = status.get("unreached", {}), status.get("no_pass", [])
    if "unreached" in status and (not isinstance(unreached, dict) or not unreached
                                  or not all(names(events) for events in unreached.values())):
        raise Verdict(INVALID, f"the status's unreached is no map from a profile to distinct events: {quoted(unreached)}")
    if "no_pass" in status and not names(no_pass):
        raise Verdict(INVALID, f"the status's no_pass is no list of distinct profiles: {quoted(no_pass)}")
    present = [key for key in REACH_KEYS if key in status]
    if present and code != 1:
        raise Verdict(INVALID, f"the status carries {', '.join(present)} and campaign sweep exited {code}, so the exit "
                               "disagrees with the totals")
    for key, listed in (("no_pass", no_pass), ("unreached", list(unreached))):
        for profile in listed:
            entry = entries.get(profile)
            if not isinstance(entry, dict) or entry.get("control") is not False:
                raise Verdict(INVALID, f"the status lists {quoted(profile)} under {key}, and it is no profile of the root "
                                       "outside the controls")
    named = set(no_pass)
    for profile, entry in entries.items():
        if entry.get("control") is not False:
            continue
        what = f"profile {quoted(profile)}"
        runs, passes, caught = (count(entry, name, what) for name in ("runs", "pass", "caught"))
        unpassed = runs >= NO_PASS_RUNS and not passes and not caught
        if profile in named and not unpassed:
            raise Verdict(INVALID, f"the status lists {quoted(profile)} under no_pass, and it counts {runs} runs, "
                                   f"{passes} passes and {caught} caught runs")
        if unpassed and profile not in named:
            raise Verdict(INVALID, f"{quoted(profile)} has {runs} runs and none counted under pass or caught, and the "
                                   "status lists no no_pass entry for it")
    for profile, events in unreached.items():
        if profile not in ROWS:
            raise Verdict(INVALID, f"the status lists {quoted(profile)} under unreached, and the committed required-event "
                                   "table has no row for it")
        outside = [event for event in events if event not in COVERAGE]
        if outside:
            raise Verdict(INVALID, f"the status lists {quoted(profile)}: {quoted(outside)} under unreached, and they are "
                                   "no coverage counters")
    return unreached, no_pass


def sound(scenario: dict, evidence: common.Evidence) -> Sweep:
    """The records of a sound sweep, or raise the Verdict that makes the run invalid or incomplete.

    A sweep is sound whatever its reach verdict when, in this order: the recorded exit is 0, or 1
    with `no_pass` or `unreached` (a recorded 3 or 4 or a kill is incomplete, before any status is
    read); no integer of the status exceeds 2^64 - 1; the status carries no `alarm` key, every
    profile entry is an object, and no record shows a missed run (`missed_runs`); the two reach keys
    have the form and name the entries `reach_entries` states; common.trusted accepts the records
    with the two reach keys set aside, which checks every profile entry's counts, the suspects of
    every profile and its `other` bucket, and the campaign binary's digest; no profile lists more
    lines of suspects.jsonl under `other` than its status counts there; each profile of the
    scenario has an entry outside the controls with runs and replays above zero, suspect keys of
    class violation alone, and listed suspects of class violation alone. `other` is the bucket a
    profile's suspects fall into past its bound of keys, and it names no class: common.trusted
    refuses a count under `other` above its distinct lines, so with the line count bounded by the
    status too, every suspect under `other` has a line, and the class each line states decides.
    """
    code = common.recorded_exit(evidence)
    status = evidence.status()
    bounded(status)
    if "alarm" in status:
        raise Verdict(INVALID, f"the totals carry alarm {quoted(status['alarm'])}, the sweep's mark of a missed control "
                               "or history run")
    entries = status["profiles"]
    odd = next((profile for profile, entry in entries.items() if not isinstance(entry, dict)), None)
    if odd is not None:
        raise Verdict(INVALID, f"the status's entry for {quoted(odd)} is no object")
    lines = evidence.suspects()
    missed_runs(status, entries, lines)
    unreached, no_pass = reach_entries(status, entries, code)
    common.trusted(scenario, Unjudged(evidence, status))
    listed: dict[str, list[dict]] = {}
    for line in lines:
        listed.setdefault(line["profile"], []).append(line)
    for profile, found in listed.items():
        overflow = sum(line["key"] == "other" for line in found)
        counted = entries[profile]["suspect_keys"].get("other", 0)
        if overflow > counted:
            raise Verdict(INVALID, f"suspects.jsonl lists {overflow} suspects of {quoted(profile)} under other, and the "
                                   f"status counts {counted}")
    profiles = common.distinct(common.scenario_profiles(scenario))
    for profile in profiles:
        entry = entries.get(profile)
        if not isinstance(entry, dict) or profile not in evidence.run["profiles"] or entry.get("control") is not False:
            raise Verdict(INVALID, f"the status holds no entry outside the controls for the scenario's profile {profile}")
        runs, replays = count(entry, "runs", f"profile {profile}"), count(entry, "replays", f"profile {profile}")
        if runs == 0 or replays == 0:
            raise Verdict(INVALID, f"{profile} has {runs} runs and {replays} replays; a sound sweep ran each profile "
                                   "and replayed a run of it in a fresh process")
        other = sorted(key for key in entry["suspect_keys"] if key != "other" and common.identity(key)[0] != "violation")
        other += sorted({line["class"] for line in listed.get(profile, ()) if line["class"] != "violation"})
        if other:
            raise Verdict(INVALID, f"{profile} has a suspect of another class than violation: {quoted(other[0])}")
    return Sweep(status, code, unreached, no_pass)


def reach_counts(status: dict, profiles: list[str]) -> dict[str, dict[str, int]]:
    """Each profile's reaching covered passes by coverage counter, or raise INVALID for a map of other counters.

    A profile's `reached` maps a coverage counter to `runs`, its covered passes that reached it, and
    `total`, how often they reached it; `sound` has had common.trusted check both against the
    profile's covered passes as the supervisor's own check of its counts does. A counter the map
    leaves out has 0 reaching passes.
    """
    counts = {}
    for profile in profiles:
        events = status["profiles"][profile].get("reached")
        if not isinstance(events, dict) or not set(events) <= set(COVERAGE):
            raise Verdict(INVALID, f"profile {profile} records no reached map of coverage counters: {quoted(events)}")
        counts[profile] = dict.fromkeys(COVERAGE, 0)
        for event, value in events.items():
            counts[profile][event] = count(value, "runs", f"{profile}'s reached.{event}")
    return counts


def excused_reached(counts: dict[str, dict[str, int]]) -> str:
    """The excused pairs of the table that a covered pass reached, whose excuse the run shows stale.

    Every profile of `counts` has a row of the table: the reach judge refuses another before it calls this.
    """
    found = [f"{profile}: {event} by {reached[event]} covered passes"
             for profile, reached in counts.items() for event in EXCUSED[profile] if reached[event] > 0]
    return f"excused pairs reached: {', '.join(found) if found else 'none'}"
