#!/usr/bin/env python3
"""Judge the ordering figure: how reliably one sweep catches each planted ordering control.

    python3 -I -B chaos/judges/ordering/figure.py <invariant-id> --evidence chaos/runs/<run-id> [--receipt FILE]

The scenario's profiles are planted ordering controls, one at each depth, which run
cluster-broad's scenario. The row gives the rule text a caught run counts under as
control.expect, and in its threshold the runs each control needs (min_runs_per_control), the
one-sided confidence of the lower bound (confidence, from 0.5 to MOST_CONFIDENCE), and each
control's depth, n and k as `<control>.depth`, `<control>.n` and `<control>.k`, equal to the
supervisor's control table.

For each control the judge reads runs, caught, missed and the no-effect count (the runs counted
under `unsuccessful: the control's plant took no effect`) from the status document. A control's
eligible runs are those that ended caught, missed or with no effect; runs that ended at a limit
or under another uncredited ending count toward the rate and not toward the floor, as
docs/agents/simulation.md counts finished runs. The judge gives:

    broken      a control's missed is positive, or a control has zero caught in at least
                min_runs_per_control eligible runs, with a replay and delivered link faults
    incomplete  a control has fewer than min_runs_per_control eligible runs
    invalid     a control is absent from the status, a caught run counts under another rule,
                the scope the evidence shows differs from run.json, or the records do not stand
    held        otherwise

A held detail begins with the judge's own phrase for what it measured, WITNESSED, whatever text
the row's witness.expect holds.

The first of these that applies decides the run, in the order invalid, a miss, zero caught,
incomplete, held. A control run names in its label the control its build leaves uncaught: the
label begins with that control's name and `-`. On such a run a label that names no one control,
or a catch of the named control, is invalid before a miss is read; zero caught is broken only for
the named control, and the named control with too few eligible runs is incomplete.

Every verdict rests on records that agree, as `recorded` in chaos/judges/core/common.py decides
them: the run record, the status, history.jsonl, the suspect and finding copies, the sweep's
command line, the restoration and the control totals. Beside them the judge requires what
`trusted` would, with two differences. A miss raises the supervisor's alarm and exit 1, which
`trusted` turns into invalid, so here exit 1 with the alarm that names the status's missed runs
and no other totals flag key is the record of a missed control, which counts a suspect of a
missed class; exit 0 with no totals flag key, no miss and no suspect of a control is the other
record a verdict rests on, and it needs that no profile of the status, a history included, counts
a missed run. And a control run's defect is a label that no swept profile carries, as validity.py
reads it. The totals flag keys are those of records.py, `no_window` among them.
The family's own checks add that the swept profiles are the scenario's controls, each a control
in the listing and the status, no other profile but a rotating history ran, each control's runs
are the length of its run range, and the status's totals of missed, no-effect and other-ending
control runs equal the sums over its control entries. A replay and delivered link faults of each
control are validity.py's for held, and the two receipts together show the witness.

A rate divides a control's caught runs by its runs, every run the sweep finished. A control whose
runs include some with no ending, a suspect other than a miss, gets no rate or bound. The bound's
arithmetic agrees with its closed forms and an exact calculation to a relative 1e-7 up to
MOST_RUNS runs of a control and a confidence of MOST_CONFIDENCE, so the written bound is the
computed one less that share, and a control with more runs or a row with a higher confidence is
invalid. The receipt carries three fields beside the core ones on a run
the judge measured. `scope` holds the archive build digest, the campaign, the counts, the
profiles, the runs of each control and the scope sentence, each read from the status document and
history.jsonl and checked against run.json. `figure` holds, for each control, its depth, n, k,
runs, caught, no effect, missed, eligible and other runs by ending, which together with the
control's suspects account for its runs; the rate; the one-sided Clopper-Pearson lower bound of
the row's confidence, found by bisection on the binomial tail; and the yardstick 1/(n*k^(d-1)) of
Burckhardt et al. (ASPLOS 2010), which no verdict uses. `figure_rounding` states how the rate, the
lower bound, the confidence and the yardstick are written: at most nine fraction digits,
so no value serializes with twelve digits in a row. A printed confidence
is the written one, so no confidence below 1 prints as 100%.

The judge holds records.py, like common.py, to the bytes it executed.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.machinery
import importlib.util
import math
import os
import stat
import sys
from decimal import ROUND_FLOOR, ROUND_HALF_EVEN, Decimal
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
# A start of the judge as a program is checked here; the judges' tests import its arithmetic as a module.
if __name__ == "__main__" and (not sys.flags.isolated or not sys.flags.dont_write_bytecode):
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
    BROKEN, HELD, INCOMPLETE, INVALID = common.BROKEN, common.HELD, common.INCOMPLETE, common.INVALID
    Verdict, count, core_receipt_for, main = common.Verdict, common.count, common.receipt_for, common.main
except Exception as error:  # an import that fails is no verdict
    refuse(f"cannot load the judge: {error.__class__.__name__}: {error}")

NO_EFFECT = records.NO_EFFECT
WITNESSED = "each planted ordering control caught"
MOST_RUNS = 10_000_000
MOST_CONFIDENCE = 0.9999999
# The bisection agrees with the exact bound to a relative 1e-7 up to MOST_RUNS; the written bound sits that much lower.
SLACK = 1e-7
DEEPEST = 3
ROUNDING = ("rate, lower_bound, confidence and yardstick are written to nine fraction digits when at least 0.0001 "
            "and to nine significant digits below it; lower_bound and confidence are cut down and the others "
            "rounded to nearest")
SCOPE = ("Per-run rate at which `campaign sweep` of archive build {build}, campaign {campaign}, counts {counts}, "
         "catches each planted ordering control of depth 1 to 3 beside `cluster-broad`, over {runs} runs each, "
         "with a {percent} lower bound: one thread, turn granularity, this profile, these counts and this build, "
         "and orders the turn controller can select. Each rate counts every run the sweep finished, those that "
         "ended at a limit among them, the row's floor of runs counts those that ended caught, missed or with no "
         "effect, and each bound holds for its own control and takes its run count as fixed, while --for sets "
         "that count by the wall clock. A caught run is a run that ended in the row's rule, which the sweep does "
         "not tie to the read the plant changed. Each control measures how often a drawn run reaches a rare "
         "interleaving of link deliveries with the upload: the chooser picks each GET's issue and orders the "
         "events ready at one instant, and link draws and the turn controller's clock rule decide when the others "
         "become ready. A read of version 0 that completes before the upload's session reports it published is an "
         "order of the real code that no run of this controller reaches: in the probes of blotter pull request 2117 the order formed "
         "in 0 of 300 `cluster-broad` roots and in 0 of 60,000 control runs, and the reason offered is that the "
         "turn controller holds the clock still while an event is runnable.")
YARDSTICK = ("not applicable: the bound 1/(n*k^(d-1)) holds for a scheduler that draws priorities and d-1 change "
             "points, so that it picks the d orders; this chooser draws uniformly at each turn, and link draws and "
             "the clock rule decide when the events of each premise become ready, so it picks no d orders; n, k "
             "and d are given for information")


def confidence_of(row: dict) -> float:
    """The row's one-sided confidence, from 0.5, so the bound lies at or below the rate, to MOST_CONFIDENCE.

    A bound of few catches is proportional to 1 - confidence, which binary floating point holds to
    2^-54. At MOST_CONFIDENCE that error is below a hundredth of SLACK; near 1 it exceeds SLACK.
    """
    held = row.get("threshold")
    value = held.get("confidence") if isinstance(held, dict) else None
    if type(value) is not float or not 0.5 <= value <= MOST_CONFIDENCE:
        raise Verdict(INVALID, f"{row.get('id')}: threshold.confidence is {value!r}, which is no share from 0.5 to "
                               f"{MOST_CONFIDENCE}")
    return value


def tail(caught: int, runs: int, rate: float) -> float:
    """P(X >= caught) for X binomial over `runs` trials at `rate`, for 0 < caught <= runs, 0 < rate <= caught / runs and rate < 1.

    The first term comes from log-gamma; each later term is the one before times a ratio below 1,
    since every index from `caught` on lies at or above the mean, so the sum stops once a term no
    longer moves it.
    """
    term = math.exp(math.lgamma(runs + 1) - math.lgamma(caught + 1) - math.lgamma(runs - caught + 1)
                    + caught * math.log(rate) + (runs - caught) * math.log1p(-rate))
    total, odds = 0.0, rate / (1 - rate)
    for index in range(caught, runs + 1):
        total += term
        term *= (runs - index) / (index + 1) * odds
        if term <= total * 1e-17:
            break
    return total


def lower_bound(caught: int, runs: int, confidence: float) -> float:
    """The one-sided Clopper-Pearson lower bound: the rate at which P(X >= caught) equals 1 - confidence.

    For a confidence of at least 0.5 that rate lies at or below caught / runs, where bisection starts.
    """
    alpha = 1 - confidence
    if caught == 0:
        return 0.0
    if caught == runs:
        return alpha ** (1 / runs)
    low, high = 0.0, caught / runs
    for _ in range(100):
        middle = (low + high) / 2
        if middle in (low, high):
            break
        if tail(caught, runs, middle) < alpha:
            low = middle
        else:
            high = middle
    return low


def scope(evidence: Any, status: dict, controls: list[str], confidence: float) -> dict:
    """The scope the status document and history.jsonl show, each field checked against run.json."""
    run = evidence.run
    records.ranges(evidence, status)
    runs = {control: count(status["profiles"][control], "runs", f"control {control}") for control in controls}
    counts = ", ".join(f"{key}={value}" for key, value in sorted(run["counts"].items())) or "default"
    listed = [str(runs[control]) for control in controls]
    each = (", ".join(listed[:-1]) + f" and {listed[-1]}") if len(listed) > 1 else listed[0]
    sentence = SCOPE.format(build=run["system_build"], campaign=run["campaign"], counts=counts, runs=each,
                            percent=percent(confidence))
    return {"build": run["system_build"], "campaign": run["campaign"], "counts": run["counts"],
            "profiles": list(run["profiles"]), "runs": runs, "sentence": sentence}


def percent(confidence: float) -> str:
    """A confidence as a percentage of the confidence the receipt holds, cut down to nine fraction digits, so no
    confidence below 1 prints as 100%."""
    return format((Decimal(repr(written(confidence, down=True))) * 100).normalize(), "f") + "%"


def written(value: float, down: bool = False) -> float:
    """A proportion as the receipt holds it: nine fraction digits from 0.0001 up, nine significant digits below."""
    if value <= 0:
        return 0.0
    exact = Decimal(repr(value))
    quantum = Decimal("1e-9") if exact.adjusted() >= -4 else Decimal(1).scaleb(exact.adjusted() - 8)
    return float(exact.quantize(quantum, rounding=ROUND_FLOOR if down else ROUND_HALF_EVEN))


def floored(bound: float) -> str:
    """A lower bound cut down to four significant digits, so the printed bound lies at or below the computed one."""
    if bound <= 0:
        return "0"
    exact = Decimal(bound)
    cut = exact.quantize(Decimal(1).scaleb(exact.adjusted() - 3), rounding=ROUND_FLOOR)
    return format(cut, "f" if exact.adjusted() >= -4 else "e")


def measured(row: dict, control: str, entry: dict, rule: str, confidence: float) -> dict:
    """One control's line of the figure, from its status entry and the row's numbers."""
    what = f"control {control}"
    runs, caught, missed = (count(entry, key, what) for key in ("runs", "caught", "missed"))
    if runs > MOST_RUNS:
        raise Verdict(INVALID, f"{control} has {runs} runs, and the lower bound's arithmetic is checked up to {MOST_RUNS}")
    uncredited = entry.get("uncredited")
    if not isinstance(uncredited, dict):
        raise Verdict(INVALID, f"{control} records no uncredited map")
    endings = {key: count(uncredited, key, what) for key in sorted(uncredited)}
    no_effect = endings.pop(NO_EFFECT, 0)
    rules = entry.get("caught_rules")
    if not isinstance(rules, dict):
        raise Verdict(INVALID, f"{control} records no caught_rules")
    counted = {key: value for key, value in ((key, count(rules, key, what)) for key in rules) if value}
    if counted != ({rule: caught} if caught else {}):
        raise Verdict(INVALID, f"{control} counts {caught} caught runs and caught_rules {rules!r}; every caught run "
                               f"of the figure counts under the row's rule \"{rule}\""[:600])
    # A finished run is caught, uncredited under its ending, or a suspect; a missed run is a suspect.
    other, suspects = sum(endings.values()), count(entry, "suspects", what)
    unaccounted = runs - caught - missed - no_effect - other
    if not 0 <= unaccounted <= suspects - missed:
        raise Verdict(INVALID, f"{control} counts {caught} caught, {missed} missed, {no_effect} with no effect, "
                               f"{other} under other endings and {suspects} suspects, which do not account for "
                               f"its {runs} runs")
    depth, n, k = (common.minimum(row, "threshold", f"{control}.{key}") for key in ("depth", "n", "k"))
    if depth > DEEPEST:
        raise Verdict(INVALID, f"{row.get('id')}: threshold.{control}.depth is {depth}, and the figure covers depth 1 to {DEEPEST}")
    # With zero caught the rate lies below -ln(1 - confidence)/runs, 3/runs at 95%, rounded up to one decimal.
    ceiling = math.ceil(-math.log(1 - confidence) * 10) / 10
    # A line whose runs include some with no ending has no sample of finished runs, so it carries counts alone.
    sampled = runs > 0 and unaccounted == 0
    not_found = (f"not found in {runs} runs; rate below {ceiling:g}/{runs} at {percent(confidence)}"
                 if sampled and not caught else None)
    return {"control": control, "depth": depth, "n": n, "k": k, "runs": runs, "caught": caught,
            "no_effect": no_effect, "missed": missed, "other": other, "other_endings": endings,
            "suspects": suspects, "unaccounted": unaccounted, "eligible": caught + missed + no_effect,
            "rate": written(caught / runs) if sampled else None,
            "lower_bound": written(lower_bound(caught, runs, confidence) * (1 - SLACK), down=True) if sampled else None,
            "confidence": written(confidence, down=True),
            "yardstick": written(1 / (n * k ** (depth - 1))), "yardstick_comparison": YARDSTICK, "not_found": not_found}


def shown(line: dict, confidence: float) -> str:
    """One control's figure as a clause of the detail, for a control with runs."""
    head = f"{line['control']} (depth {line['depth']}, n {line['n']}, k {line['k']})"
    counts = (f"runs {line['runs']}, caught {line['caught']}, no effect {line['no_effect']}, "
              f"missed {line['missed']}, other {line['other']}")
    if line["unaccounted"]:
        counts += f", suspects under no ending {line['unaccounted']}"
    if line["rate"] is None:
        return f"{head}: {counts}; no rate, since {line['unaccounted']} of its runs have no ending"
    if line["not_found"]:
        return f"{head}: {line['not_found']}; {counts}"
    return (f"{head}: {counts}; rate {line['rate']:.4g}, {percent(confidence)} lower bound "
            f"{floored(line['lower_bound'])}; yardstick {line['yardstick']:.4g}, a comparison not applicable")


def decide(row: dict, scenario: dict, evidence: Any) -> tuple[int, str]:
    control = row.get("control")
    rule = control.get("expect") if isinstance(control, dict) else None
    if not isinstance(rule, str) or not rule:
        raise Verdict(INVALID, f"{row.get('id')}: the row needs the rule text a caught run counts under as control.expect")
    need, confidence = common.minimum(row, "threshold", "min_runs_per_control"), confidence_of(row)
    code = common.recorded_exit(evidence)
    status = evidence.status()
    controls = records.controls(scenario, evidence, status)
    found = scope(evidence, status, controls, confidence)
    common.recorded(scenario, evidence)
    lines = [measured(row, name, status["profiles"][name], rule, confidence) for name in controls]
    records.totals(status)
    flags = records.flags(status)
    missed = [line for line in lines if line["missed"]]
    if missed and ((code, flags) != (1, ["alarm"]) or status["alarm"] != records.alarm(status)):
        raise Verdict(INVALID, f"{missed[0]['control']} missed {missed[0]['missed']} runs, and campaign sweep exited "
                               f"{code} with the totals flags {flags} and the alarm {status.get('alarm')!r}; a miss stands "
                               "on exit 1 with the alarm alone, which names the status's missed runs"[:600])
    if not missed and (code, flags) != (0, []):
        raise Verdict(INVALID, f"campaign sweep exited {code} with the totals flags {flags}, and no control of the "
                               "scenario missed a run; a figure without a miss stands on exit 0 with no flag")
    records.alarmed(status)
    for line in missed:
        records.missed_shown(status, line["control"])
    suspect = [line for line in lines if line["suspects"]]
    if not missed and suspect:
        raise Verdict(INVALID, f"{suspect[0]['control']} lists {suspect[0]['suspects']} suspects and no control of the "
                               "scenario missed a run; a figure without a miss stands on runs that each ended")
    unfound = [line for line in lines if line["caught"] == 0 and line["eligible"] >= need]
    if evidence.run["mode"] == "control":
        label = evidence.run["defect"]
        named = [line for line in lines if label.startswith(line["control"] + "-")]
        if len(named) != 1:
            raise Verdict(INVALID, f"the control run's label {label!r} begins with the name of no one control of the "
                                   "scenario, so it names no control its build leaves uncaught"[:300])
        if named[0]["caught"]:
            raise Verdict(INVALID, f"{named[0]['control']} was caught in {named[0]['caught']} of its {named[0]['runs']} "
                                   f"runs, and the control run {label!r} names it as the control its build leaves "
                                   "uncaught"[:400])
        unfound = [line for line in unfound if line is named[0]]
    if not missed:
        for line in unfound:
            entry = status["profiles"][line["control"]]
            if count(entry, "replays", line["control"]) == 0 or count(entry, "faults_delivered", line["control"]) == 0:
                raise Verdict(INVALID, f"{line['control']} was caught in none of its runs, and it has no replay or "
                                       "delivered no link fault, so its runs show no working control")
    evidence.figure = {"scope": found, "figure": lines, "figure_rounding": ROUNDING}
    quoted = f"the row's rule \"{rule}\""
    if missed:
        return BROKEN, "; ".join(f"{line['control']} missed {line['missed']} runs whose plant took effect and "
                                 f"met no check under {quoted}: {shown(line, confidence)}" for line in missed)
    if unfound:
        return BROKEN, "; ".join(f"{shown(line, confidence)}; no run was caught under {quoted}, and the row requires a catch "
                                 f"in {need} runs that ended caught, missed or with no effect" for line in unfound)
    short = [line for line in lines if line["eligible"] < need]
    if short:
        raise Verdict(INCOMPLETE, "; ".join(f"{line['control']} has {line['eligible']} runs that ended caught, missed or "
                                            f"with no effect, of its {line['runs']} runs, and the row requires {need}"
                                            for line in short))
    return HELD, f"{WITNESSED} under {quoted}: " + "; ".join(shown(line, confidence) for line in lines) + f". {found['sentence']}"


def receipt_for(row_id, script, judge, row, scenario, evidence, code, detail) -> dict:
    """The core receipt, with the scope and the figure of a run the judge measured and did not find invalid."""
    receipt = core_receipt_for(row_id, script, judge, row, scenario, evidence, code, detail)
    # main turns a verdict invalid when a judge file changed during the run; that receipt carries no figure either.
    if code != INVALID:
        receipt["key"].update(getattr(evidence, "figure", {}))
    return receipt


if __name__ == "__main__":
    # common.main writes the receipt through the module's receipt_for, so this family's fields join it there, and
    # reads the judge's files through the module's sources, which also holds records.py to the bytes executed.
    common.receipt_for = receipt_for
    common.sources = records.bound_sources(common.sources)
    sys.exit(main("invariants", decide))
