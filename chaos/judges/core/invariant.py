#!/usr/bin/env python3
"""Judge one history or state invariant on a run of a scenario that lists it.

    python3 -I -B chaos/judges/core/invariant.py <invariant-id> --evidence chaos/runs/<run-id> [--receipt FILE]

The row carries its rule text as control.expect and its obligation code as witness.obligation.
A judge reports broken only through that rule, with the full text and the obligation in the detail:

- in mode control, when the named defect's caught_rules counts a caught run under the text, and the
  defect, when the worker's listing declares a failure of it, declares exactly the row's
  violation `violation <code> <rule>`;
- in mode live, by (a) a suspect key of class violation, in a profile of the scenario, that
  carries the row's obligation code and the SHA-256 of its rule text, with a finding of
  campaign confirm whose confirmed job is one of the key's listed runs, of the same campaign,
  profile, run number, build, seed and count overrides, and ended under the same key; or by (b) a
  history of the scenario whose listing declares exactly the row's violation and counts a caught
  run under the text in its caught_rules.

A control the sweep ran unnamed never gives broken. A break is reported only on records a verdict
can rest on, as `trusted` in common.py decides them: a recorded sweep exit 3 or 4 is incomplete,
and a totals flag, another build, counts no sweep writes or a control without a replay, with a
miss or with a run a kill ended is invalid. Held needs a valid run, as `held` decides it from the
same status, and no such suspect key; a valid run lists suspects of class violation only, so a
suspect counted under `other` leaves it invalid. A violation key whose rule the judge cannot read,
a suspect under the rule that confirm did not reproduce, and a history that declares the row's
violation with caught runs none of which counts under the row's text each leave the row invalid
when neither path shows a break. A control caught under another rule is invalid, and so is a
status marker of a swept profile that contradicts the listing's class or declaration.
"""
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import os
import stat
import sys
from pathlib import Path
from typing import NoReturn


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
    # The judge executes the common.py bytes it read once and hashes for LOADED_SHA256, through a
    # loader that returns those bytes alone, so no bytecode cache takes part. The bound is
    # common.SOURCE_BYTES.
    for folder in {here, core}:
        for entry in os.scandir(folder):
            if not entry.is_file(follow_symlinks=False):
                raise OSError(f"{entry.name} beside the judge is no regular file")
    path = str(core / "common.py")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as file:
        if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
            raise OSError("common.py is no regular file")
        source = file.read((1 << 22) + 1)
    if len(source) > 1 << 22:
        raise OSError("common.py holds more than its bound of bytes")

    class Checked(importlib.machinery.SourceFileLoader):
        def get_data(self, path: str) -> bytes:
            if path != self.path:
                raise OSError("the judge reads common.py's source alone")
            return source

    spec = importlib.util.spec_from_file_location("common", path, loader=Checked("common", path))
    if spec is None or spec.loader is None:
        raise ImportError("common.py has no loader")
    module = importlib.util.module_from_spec(spec)
    module.__dict__["LOADED_SHA256"] = hashlib.sha256(source).hexdigest()
    sys.modules["common"] = module
    spec.loader.exec_module(module)
    from common import (
        BROKEN,
        HELD,
        INVALID,
        Evidence,
        Verdict,
        count,
        declaration,
        distinct,
        held,
        identity,
        kinds,
        main,
        rule_digest,
        scenario_profiles,
        trusted,
    )
except Exception as error:  # an import that fails is no verdict
    refuse(f"cannot load the judge: {error.__class__.__name__}: {error}")


def rule_of(row: dict) -> tuple[str, int]:
    """The row's rule text and obligation code."""
    control, witness = row.get("control"), row.get("witness")
    rule = control.get("expect") if isinstance(control, dict) else None
    code = witness.get("obligation") if isinstance(witness, dict) else None
    if not isinstance(rule, str) or not rule or type(code) is not int or not 0 < code < 256:
        raise Verdict(INVALID, f"{row.get('id')}: the row needs its rule text as control.expect and its obligation "
                               "code, 1 to 255, as witness.obligation")
    return rule, code


def caught_under(entry: dict, rule: str, what: str) -> tuple[int, dict]:
    """How many caught runs a profile's caught_rules counts under `rule`, and the whole map.

    Each caught run counts under one rule, so the counts of the map sum to at most the profile's
    caught runs, which are at most its runs.
    """
    rules = entry.get("caught_rules")
    if not isinstance(rules, dict):
        raise Verdict(INVALID, f"{what} records no caught_rules")
    counted = {name: count(rules, name, what) for name in rules}
    caught, runs = count(entry, "caught", what), count(entry, "runs", what)
    if sum(counted.values()) > caught or caught > runs:
        raise Verdict(INVALID, f"{what} counts {sum(counted.values())} caught runs under its rules, {caught} caught runs "
                               f"and {runs} runs")
    return counted.get(rule, 0), rules


def reproduced(evidence: Evidence, lines: list[dict], findings: list[dict]) -> list[str]:
    """The ids of verified findings of kind violation that confirmed one of the listed suspects `lines`.

    A finding confirms a listed suspect when its job's experiment names the run's campaign, the
    suspect's profile and run number, the suspect's build as its pinned build and each count the
    run overrides at the run's value, its job's seed is the suspect's seed, and its confirmed run
    ended under the suspect's key. This shows the records of the sweep and of confirm agree on the
    job; it does not derive the seed itself.
    """
    by_run: dict[tuple[str, int], list[dict]] = {}
    for line in lines:
        by_run.setdefault((line["profile"], line["run"]), []).append(line)
    found = []
    for finding in findings:
        verified = finding.get("verified")
        if not isinstance(verified, dict) or verified.get("kind") != "violation":
            continue
        admission, artifact = verified.get("admission"), verified.get("artifact")
        job = admission.get("job") if isinstance(admission, dict) else None
        summary = artifact.get("summary") if isinstance(artifact, dict) else None
        observed = summary.get("identity") if isinstance(summary, dict) else None
        experiment = job.get("experiment") if isinstance(job, dict) else None
        if not isinstance(job, dict) or not isinstance(experiment, dict) or not isinstance(observed, str):
            continue
        pins, counts, profile, number = (experiment.get(key) for key in ("pins", "counts", "profile", "run"))
        seed = job.get("seed")
        if experiment.get("campaign") != evidence.run["campaign"] or not isinstance(profile, str) \
                or type(number) is not int or type(seed) is not int or not isinstance(pins, dict) \
                or not isinstance(counts, dict):
            continue
        if not all(type(counts.get(key)) is int and counts[key] == value for key, value in evidence.run["counts"].items()):
            continue
        if any(pins.get("build") == line["build"] and seed == line["seed"] and line["key"] == f"violation: {observed}"
               for line in by_run.get((profile, number), [])):
            found.append(finding["id"])
    return found


def known_issues(status: dict, matched: set[tuple[str, str]]) -> list[str]:
    """The issues of the known-findings rows that explain a matched key, as the status lists them; a row whose issue is
    no positive integer explains nothing."""
    issues = []
    rows = status.get("known")
    for row in rows if isinstance(rows, list) else []:
        keys = row.get("keys") if isinstance(row, dict) else None
        if isinstance(keys, dict) and type(row.get("issue")) is int and row["issue"] > 0 and any(
                isinstance(keys.get(profile), list) and key in keys[profile] for profile, key in matched):
            issues.append(f"#{row['issue']}")
    return issues


def decide(row: dict, scenario: dict, evidence: Evidence) -> tuple[int, str]:
    rule, code = rule_of(row)
    status = trusted(scenario, evidence)
    entries = status["profiles"]
    run = evidence.run
    for profile in distinct(run["profiles"]):
        kinds(evidence, status, profile)
    quoted = f"\"{rule}\" (obligation {code})"
    expected = ("violation", code, rule)
    if run["mode"] == "control":
        defect = run["defect"]
        declared = declaration(evidence, defect)
        if declared is not None and declared != expected:
            raise Verdict(INVALID, f"the control {defect} declares {run['listing'][defect]['fails'][:300]!r}, and the row "
                                   f"checks the violation {quoted}")
        caught, rules = caught_under(entries[defect], rule, f"the control {defect}")
        if caught > 0:
            return BROKEN, f"the control {defect} was caught {caught} times under the row's rule {quoted}"
        raise Verdict(INVALID, f"the control {defect} has no caught run under the row's rule {quoted}; it was caught "
                               f"under {sorted(rules)!r}"[:600])
    profiles = distinct(scenario_profiles(scenario))
    digest = rule_digest(rule)
    matched: set[tuple[str, str]] = set()
    unreadable: list[str] = []
    for profile in profiles:
        for key in entries[profile]["suspect_keys"]:
            cls, obligation, rule_hash = identity(key)
            if cls == "violation" and obligation is None:
                unreadable.append(f"{profile} counts a violation whose rule the judge cannot read: {key[:200]!r}")
            elif cls == "violation" and obligation == code and rule_hash == digest:
                matched.add((profile, key))
    # Each reason here refuses held, and either path below that shows a break comes first.
    pending = [*unreadable]
    if matched:
        lines = [line for line in evidence.suspects() if (line["profile"], line["key"]) in matched]
        found = reproduced(evidence, lines, evidence.findings())
        suspects = sum(entries[profile]["suspect_keys"][key] for profile, key in matched)
        names = ", ".join(sorted({profile for profile, _ in matched}))
        if found:
            issues = known_issues(status, matched)
            cited = f"; the known-findings rows of {', '.join(issues)} explain them" if issues else ""
            return BROKEN, (f"{suspects} suspects of {names} ended in the violation of the row's rule {quoted}; "
                            f"campaign confirm reproduced {len(found)} as findings {', '.join(found)[:300]}{cited}")
        pending.insert(0, f"{suspects} suspects of {names} carry the row's rule {quoted}, and campaign confirm "
                          f"reproduced none of their {len(lines)} listed runs as a finding")
    for profile in profiles:
        if declaration(evidence, profile) == expected:
            caught, _ = caught_under(entries[profile], rule, f"history {profile}")
            if caught > 0:
                return BROKEN, (f"the history {profile} of the scenario declares the row's violation and was caught "
                                f"{caught} times under the row's rule {quoted}")
            total = count(entries[profile], "caught", f"history {profile}")
            if total > 0:
                pending.append(f"the history {profile} declares the row's violation {quoted} and has {total} caught "
                               "runs, none of which caught_rules counts under the row's text")
    if pending:
        raise Verdict(INVALID, pending[0])
    detail = held(scenario, evidence, status)
    return HELD, f"no violation under the row's rule: no violation suspect of {', '.join(profiles)} carries the rule {quoted}; {detail}"


if __name__ == "__main__":
    sys.exit(main("invariants", decide))
