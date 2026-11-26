#!/usr/bin/env python3
"""Run each chaos run receipt's judge again and refuse a receipt that differs from the one the judge writes.

Run from the repository root. For each receipt `chaos/receipts/<run id>/<row>.json` outside
`fences/`, start the judge the row of `chaos/ledger.json` names as the harness does, on
`chaos/runs/<run id>`, and compare the receipt it writes with the stored one. Every field counts,
the verdict and any field a judge family adds included, except the time and the interpreter of
each judging. As the harness requires of a receipt it accepts, the judge's exit must be the one
of the outcome it writes, and a broken receipt's detail must hold the rule text its row expects
of a control. The judges run in a scratch copy of `chaos/` without its receipts, so the tree
itself stays as it is. Also refuse a receipt or a `chaos/runs/*/run.json` whose `system_build` is
not 64 lowercase hexadecimal digits, and a `chaos/project.yaml` with no `out_of_scope` item.
Exit 1 prints one line for each refusal.
"""

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

OUTCOMES = {0: "held", 1: "broken", 2: "invalid", 3: "incomplete"}
# The seconds the harness waits for a judge, `JUDGE_WAIT_S` of chaos/harness/run_scenario.py.
JUDGE_WAIT_S = 600
BUILD = re.compile(r"[0-9a-f]{64}")
# A judge takes these two fields of a receipt from its own clock and interpreter.
VOLATILE = (("run", "judged"), ("run", "interpreter"))
ABSENT = object()


def build_refusals(where, record):
    build = record.get("system_build")
    return [] if isinstance(build, str) and BUILD.fullmatch(build) else [
        f"{where} has system_build {build!r}, not 64 lowercase hexadecimal digits"]


def differences(stored, written):
    """The names of the fields in which two receipts differ, a field only one of them holds included."""
    names = []
    for part in sorted(set(stored) | set(written)):
        one, other = stored.get(part, ABSENT), written.get(part, ABSENT)
        if isinstance(one, dict) and isinstance(other, dict):
            names += [f"{part}.{name}" for name in sorted(set(one) | set(other))
                      if (part, name) not in VOLATILE and one.get(name, ABSENT) != other.get(name, ABSENT)]
        elif one != other:
            names.append(part)
    return names


def replay(receipt, data, judges, scratch, rules):
    """The refusals of run receipt `data`: its build, its differences from the receipt its row's judge writes, and
    what the harness refuses in that receipt, an outcome other than the exit's and a broken verdict whose detail
    lacks the rule text `rules` gives for the row."""
    key, evidence = data["key"], Path("chaos/runs") / data["run"]["run_id"]
    script, row = judges[key["row"]].split()
    (scratch / receipt.parent).mkdir(parents=True, exist_ok=True)
    done = subprocess.run([sys.executable, "-I", "-B", script, row, "--evidence", str(evidence), "--receipt", str(receipt)],
                          cwd=scratch, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=JUDGE_WAIT_S)
    try:
        written = json.loads((scratch / receipt).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return build_refusals(receipt, key) + [
            f"{receipt} has no receipt of its judge to compare with on {evidence}: {error.__class__.__name__}; the "
            f"judge exits {done.returncode} with {done.stderr.strip()[-300:]!r}"]
    names, outcome, rule = differences(data, written), written["key"]["outcome"], rules.get(key["row"])
    return build_refusals(receipt, key) + ([
        f"{receipt} differs in {', '.join(names)} from the receipt its judge writes on {evidence}; the judge exits "
        f"{done.returncode} with {done.stdout.strip()!r}"] if names else []) + ([
        f"{receipt}: its judge exits {done.returncode} and writes the outcome {outcome!r} on {evidence}, which is "
        "not the outcome of that exit"] if OUTCOMES.get(done.returncode) != outcome else []) + ([
        f"{receipt} is broken and its detail holds no rule text the row expects of a control: {rule!r}"]
        if outcome == "broken" and not (isinstance(rule, str) and rule in written["key"]["detail"]) else [])


def main():
    refusals = []
    with tempfile.TemporaryDirectory(prefix="chaos-replay-") as top:
        scratch = Path(top)
        try:
            project = Path("chaos/project.yaml").read_text(encoding="utf-8")
            listed = re.search(r"^out_of_scope:[ \t]*\n((?:[ \t]*(?:#.*)?\n)*[ \t]+-[ \t]+\S)", project, re.MULTILINE)
            refusals += [] if listed else ["chaos/project.yaml has no out_of_scope list or an empty one"]
            ledger = json.loads(Path("chaos/ledger.json").read_text(encoding="utf-8"))
            rows = [row for part in ("invariants", "scenarios") for row in ledger.get(part, [])]
            judges = {row["id"]: row["judge"] for row in rows}
            rules = {row["id"]: (row.get("control") or {}).get("expect") for row in rows}
            shutil.copytree("chaos", scratch / "chaos", symlinks=True,
                            ignore=lambda folder, names: ["receipts"] if folder == "chaos" else [])
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            refusals, judges, rules = [f"cannot read chaos/project.yaml, chaos/ledger.json or chaos/: {error!r}"], None, {}
        for receipt in sorted(Path("chaos/receipts").glob("*/*.json")) if judges is not None else ():
            if receipt.parent.name != "fences":
                try:
                    refusals += replay(receipt, json.loads(receipt.read_text(encoding="utf-8")), judges, scratch, rules)
                except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as error:
                    refusals.append(f"{receipt} cannot be replayed: {error!r}")
    for run in sorted(Path("chaos/runs").glob("*/run.json")):
        try:
            refusals += build_refusals(run, json.loads(run.read_text(encoding="utf-8")))
        except (OSError, ValueError, AttributeError) as error:
            refusals.append(f"{run} cannot be read: {error!r}")
    for refusal in refusals:
        print(f"chaos-receipt-replay: {refusal}")
    return 1 if refusals else 0


if __name__ == "__main__":
    sys.exit(main())
