#!/usr/bin/env python3
"""Write the traces of the reclaim model that `storage::reclaim_replay_tests` replays into `--output`, one `<name>.itf.json` per trace beside its working directory.

Usage: reclaim_fixtures.py --quint QUINT --output DIR

One trace per directed recipe and one per pinned seed of the model's own `step`, written with
`quint run --mbt`. Each trace names the sha256 of `reclaim.qnt`, and the replay refuses a trace of another
model text.
The committed copies live under `crates/kestrike/src/storage/reclaim_replay_fixtures/`.
"""
import argparse
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

SOURCE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("reclaim_checks", SOURCE / "reclaim_check.py")
reclaim_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(reclaim_checks)

RECIPES = {
    **{name.removeprefix("reclaim-run-"): recipe for name, (recipe, _) in reclaim_checks.RUNS.items()},
    "leases": ["lease", "unlease", "service", "certify", "certify", "certify", "retire", "enter(1)", "certify", "certify",
               "service", "service", "unlease", "service", "exit(1)"],
}
# Seeds of the committed traces of the model's own `step`.
SEEDS = {"step_a": "0x7c01", "step_b": "0x7c02", "step_c": "0x7c03", "step_d": "0x7c04", "step_e": "0x7c05",
         "step_f": "0x7c06"}
STEPS = 18


def generate(quint, output):
    digest = hashlib.sha256((SOURCE / "reclaim.qnt").read_bytes()).hexdigest()
    plans = [(name, recipe, "0x7c00") for name, recipe in RECIPES.items()] + [(name, [], seed) for name, seed in SEEDS.items()]
    for name, recipe, seed in plans:
        steps = len(recipe) or STEPS
        case = SimpleNamespace(name=name, mutations=[], extra="", recipe=recipe, settings={"BOUND": str(steps)})
        directory = output / name
        directory.mkdir(parents=True)
        for filename, text in reclaim_checks.inputs(case, SOURCE).items():
            (directory / filename).write_text(text)
        trace = output / (name + ".itf.json")
        subprocess.run([quint, "run", "case.qnt", "--main", "reclaimCase", "--step", "recipe" if recipe else "step",
                        "--backend", "typescript", "--mbt", "--invariant", "safety", "--seed", seed, "--max-samples", "1",
                        "--max-steps", str(steps), "--n-traces", "1", "--out-itf", str(trace)],
                       cwd=directory, check=True, timeout=60)
        data = json.loads(trace.read_text())
        if len(data["states"]) != steps + 1:
            raise ValueError(f"{name}: the trace stopped before its final action")
        data["#meta"] = {"reclaim": {"recipe": recipe, "seed": seed, "steps": steps, "model_sha256": digest}}
        trace.write_text(json.dumps(data, separators=(",", ":")) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quint", required=True, help="the pinned quint executable")
    parser.add_argument("--output", type=Path, required=True, help="a new directory for the traces")
    args = parser.parse_args()
    generate(args.quint, args.output.resolve())


if __name__ == "__main__":
    main()
