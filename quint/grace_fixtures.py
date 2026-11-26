#!/usr/bin/env python3
"""Write the committed traces of the grace model that `storage::grace_replay_tests` replays.

Usage: grace_fixtures.py --quint QUINT --output DIR

One trace per directed recipe and one per pinned seed of the model's own `step`, written with
`quint run --mbt`. Each trace names the sha256 of `grace.qnt`, and the replay refuses a trace of another
model text.
"""
import argparse
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

SOURCE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("grace_checks", SOURCE / "grace_check.py")
grace_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(grace_checks)

FIXTURES = "crates/kestrike/src/storage/grace_replay_fixtures"
RECIPES = {
    **{name.removeprefix("grace-run-"): recipe for name, (recipe, _) in grace_checks.RUNS.items()},
    "refusals": ["pin(0)", "pin(0)", "observe(0)", "unpin(0)", "unpin(1)", "remove", "pin(1)", "observe(1)", "begin"],
    "keptCertificate": ["begin", "visit", "visit", "complete", "begin", "pin(0)", "visit", "visit", "complete", "unpin(0)"],
    "closingRetirement": ["elsewhere", "pin(1)", "remove", "retire", "begin", "visit", "visit", "complete", "release",
                          "elsewhere", "pin(0)"],
}
# Seeds of the committed traces of the model's own `step`.
SEEDS = {"step_a": "0x6a01", "step_b": "0x6a02", "step_c": "0x6a03", "step_d": "0x6a04", "step_e": "0x6a05",
         "step_f": "0x6a06"}
STEPS = 16


def generate(quint, output):
    digest = hashlib.sha256((SOURCE / "grace.qnt").read_bytes()).hexdigest()
    plans = [(name, recipe, "0x6a00") for name, recipe in RECIPES.items()] + [(name, [], seed) for name, seed in SEEDS.items()]
    for name, recipe, seed in plans:
        steps = len(recipe) or STEPS
        case = SimpleNamespace(name=name, mutations=[], extra="", recipe=recipe, settings={"BOUND": str(steps)})
        directory = output / name
        directory.mkdir(parents=True)
        for filename, text in grace_checks.inputs(case, SOURCE).items():
            (directory / filename).write_text(text)
        trace = output / (name + ".itf.json")
        subprocess.run([quint, "run", "case.qnt", "--main", "graceCase", "--step", "recipe" if recipe else "step",
                        "--backend", "typescript", "--mbt", "--invariant", "safety", "--seed", seed, "--max-samples", "1",
                        "--max-steps", str(steps), "--n-traces", "1", "--out-itf", str(trace)],
                       cwd=directory, check=True, timeout=60)
        data = json.loads(trace.read_text())
        if len(data["states"]) != steps + 1:
            raise ValueError(f"{name}: the trace stopped before its final action")
        data["#meta"] = {"grace": {"recipe": recipe, "seed": seed, "steps": steps, "model_sha256": digest}}
        trace.write_text(json.dumps(data, separators=(",", ":")) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quint", required=True, help="the pinned quint executable")
    parser.add_argument("--output", type=Path, required=True, help="a new directory for the traces")
    args = parser.parse_args()
    generate(args.quint, args.output.resolve())


if __name__ == "__main__":
    main()
