"""The record checks that both ordering judges make of one run's evidence, beside `recorded` of common.py.

The judge loads chaos/judges/core/common.py as the module `common` before it loads this file.
Each check raises the Verdict that makes the run invalid or incomplete, and returns when the
record stands.
"""
from __future__ import annotations

import sys
from typing import Any

common: Any = sys.modules["common"]
INVALID, Verdict, count = common.INVALID, common.Verdict, common.count
# The suspect classes of a missed control run, the MISSED classes of crates/campaign-supervisor/src/campaign/seeds.rs.
MISSED = ("control passed", "control met no check")
# `uncredited` uses this key when the control's plant takes no effect.
NO_EFFECT = "unsuccessful: the control's plant took no effect"
FLAGS = (*common.SWEEP_FLAGS, "no_window")


def flags(status: dict) -> list[str]:
    """The verdict flags the status's totals carry, whatever their values.

    FLAGS holds the totals keys of `carries_verdict` in crates/campaign-supervisor/src/campaign/seeds.rs,
    each of which gives `campaign sweep` exit 1.
    """
    return sorted(flag for flag in FLAGS if flag in status)


def controls(scenario: dict, evidence: Any, status: dict) -> list[str]:
    """The scenario's controls: the profiles run.json records, each a control in the worker's listing and in the
    status, when the only other profiles that ran are the histories the status's totals count.

    A swept control's `history` and `failing_history` markers agree with its listing line, as `kinds`
    of common.py reads them. Every sweep also runs the scripted histories in rotation. Any other
    profile with a run or a run range is outside the scope unless the status marks it `history: true`
    and no control, and the status's `histories` totals equal the number of profiles so marked, the
    number of them with runs and the sum of their runs. run.json's listing holds the swept profiles
    alone, so the history marker of an unswept profile is the status's own word, held to those totals.
    """
    names = common.scenario_profiles(scenario)
    run = evidence.run
    if sorted(run["profiles"]) != sorted(names):
        raise Verdict(INVALID, f"run.json records the swept profiles {run['profiles']}, and the scenario sweeps "
                               f"{names}"[:600])
    listing = run.get("listing")
    for name in names:
        entry = status["profiles"].get(name)
        line = listing.get(name) if isinstance(listing, dict) else None
        if not isinstance(entry, dict):
            raise Verdict(INVALID, f"the status holds no entry for the scenario's control {name}")
        if not isinstance(line, dict) or line.get("class") != "control":
            raise Verdict(INVALID, f"run.json's listing does not list {name} as a control: {line!r}"[:300])
        if entry.get("control") is not True:
            raise Verdict(INVALID, f"the status does not count {name} as a control: control {entry.get('control')!r}"[:300])
        common.kinds(evidence, status, name)
    runs = {profile: count(entry, "runs", f"profile {profile}") for profile, entry in status["profiles"].items()
            if isinstance(entry, dict)}
    histories = {profile for profile in runs if status["profiles"][profile].get("history") is True
                 and status["profiles"][profile].get("control") is False}
    ran = {profile for profile in runs if profile not in histories
           and (runs[profile] > 0 or count(status["profiles"][profile], "next", f"profile {profile}") > 0)}
    if not ran <= set(names):
        raise Verdict(INVALID, f"scope: the status shows the profiles {sorted(ran | set(names))} ran, and "
                               f"run.json records {sorted(run['profiles'])}"[:600])
    reported = tuple(count(status.get("histories"), key, "the status's histories") for key in ("profiles", "ran", "runs"))
    summed = (len(histories), sum(1 for profile in histories if runs[profile] > 0),
              min(sum(runs[profile] for profile in histories), common.U64_MAX))
    if reported != summed:
        raise Verdict(INVALID, f"scope: the status's histories count {reported[0]} profiles, {reported[1]} with runs and "
                               f"{reported[2]} runs, and its entries marked as histories hold {summed[0]}, {summed[1]} "
                               f"and {summed[2]}")
    return names


def span(value: object, what: str) -> dict:
    """A run range: `first` and `next`, each a run number. Any other value is no range."""
    if not isinstance(value, dict) or sorted(value) != ["first", "next"]:
        raise Verdict(INVALID, f"scope: {what} is {value!r}, which is no pair of run numbers first and next"[:600])
    return {key: count(value, key, f"scope: {what}") for key in ("first", "next")}


def ranges(evidence: Any, status: dict) -> None:
    """What replays the run stands in run.json, and the status and history.jsonl show the same.

    The root holds the run's build, each swept profile's run range starts at 0 and ends at the
    status's next run number, the profile's runs are that range's length, and each history.jsonl
    line names the run's build, campaign, counts and that range.
    """
    run = evidence.run
    history, spans = evidence.history(), run.get("runs")
    fields = [("root build", run.get("root_build"), run["system_build"])]
    for profile in run["profiles"]:
        line, entry = history[profile], status["profiles"].get(profile)
        seen = {"first": 0, "next": count(entry, "next", f"profile {profile}")}
        recorded = span(spans.get(profile) if isinstance(spans, dict) else None, f"run.json's run range of {profile}")
        listed = span(line.get("runs"), f"history line's run range of {profile}")
        runs = count(entry, "runs", f"profile {profile}")
        if runs != seen["next"]:
            raise Verdict(INVALID, f"scope: the status counts {runs} runs of {profile}, and its run range holds {seen['next']}")
        fields += [(f"run range of {profile}", seen, recorded), (f"history line's run range of {profile}", listed, seen)]
        fields += [(f"history line's {key} of {profile}", line.get(key), run[name])
                   for key, name in (("build", "system_build"), ("campaign", "campaign"), ("counts", "counts"))]
    differs = next(((field, shown, recorded) for field, shown, recorded in fields if shown != recorded), None)
    if differs is not None:
        field, shown, recorded = differs
        raise Verdict(INVALID, f"scope: the evidence shows {field} {shown!r} and run.json records {recorded!r}"[:600])


def totals(status: dict) -> None:
    """The status's totals of missed, no-effect and other-ending control runs equal the sums over its entries marked
    as controls, as the supervisor writes them.

    `recorded` of common.py holds the totals of profiles, runs and caught runs the same way and
    requires each entry's boolean control marker, so the judge calls it first.
    """
    summed = {"missed": 0, "no_effect": 0, "other": 0}
    for profile, entry in status["profiles"].items():
        if entry["control"]:
            endings = entry.get("uncredited")
            if not isinstance(endings, dict):
                raise Verdict(INVALID, f"{profile} records no uncredited map")
            summed["missed"] += count(entry, "missed", f"control {profile}")
            for key in endings:
                summed["no_effect" if key == NO_EFFECT else "other"] += count(endings, key, f"control {profile}")
    held = {key: min(value, common.U64_MAX) for key, value in summed.items()}
    reported = {key: count(status.get("controls"), key, "the status's controls") for key in summed}
    if reported != held:
        raise Verdict(INVALID, f"the status's controls count {reported['missed']} missed, {reported['no_effect']} with no "
                               f"effect and {reported['other']} under other endings, and its entries marked as controls "
                               f"hold {held['missed']} missed, {held['no_effect']} with no effect and {held['other']} "
                               "under other endings")


def alarm(status: dict) -> str | None:
    """The alarm the supervisor writes for the status's missed runs, or None when no profile missed a run.

    The supervisor's alarm names the missed runs of every profile of the status, controls and
    histories alike.
    """
    missed = sum(count(entry, "missed", f"profile {profile}") for profile, entry in status["profiles"].items())
    return f"{min(missed, common.U64_MAX)} control runs were missed" if missed else None


def alarmed(status: dict) -> None:
    """The status carries the alarm its profiles' missed runs call for, and none when no profile missed a run."""
    expected = alarm(status)
    if status.get("alarm") != expected:
        raise Verdict(INVALID, f"the status's profiles call for the alarm {expected!r}, and its totals carry the alarm "
                               f"{status.get('alarm')!r}"[:400])


def missed_shown(status: dict, control: str) -> None:
    """A control that missed runs counts a suspect of a missed class, as the supervisor records each missed run."""
    keys = status["profiles"][control].get("suspect_keys")
    if not isinstance(keys, dict) or not any(common.identity(key)[0] in MISSED and type(value) is int and value > 0
                                             for key, value in keys.items()):
        raise Verdict(INVALID, f"{control} counts missed runs, and its suspect_keys count no suspect of the classes "
                               f"{', '.join(MISSED)}: {sorted(keys or {})[:2]!r}"[:400])


def bound_sources(sources: Any) -> Any:
    """`common.sources`, which also requires records.py on disk to be the bytes this judge executed.

    common.main reads the judge's files before it judges and again before it writes the receipt,
    and holds common.py to its LOADED_SHA256; this wrapper holds records.py the same way.
    """
    def checked(judge: Any) -> dict[str, str]:
        digests = sources(judge)
        if digests.get("chaos/judges/ordering/records.py") != globals().get("LOADED_SHA256"):
            raise ValueError("records.py was not loaded from the bytes its digest names")
        return digests
    return checked
