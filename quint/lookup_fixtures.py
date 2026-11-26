#!/usr/bin/env python3
"""Write the traces of the lookup model that `storage::lookup_replay_tests` replays into `--output`, one `<name>.itf.json` per trace beside its working directory.

Usage: lookup_fixtures.py --quint QUINT --output DIR

One trace per directed recipe and one per pinned seed of the model's own `step`, written with
`quint run --mbt`. Each trace names the sha256 of `lookup.qnt`, and the replay refuses a trace of another
model text.
The committed copies live under `crates/kestrike/src/storage/lookup_replay_fixtures/`.
"""
import argparse
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

SOURCE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("lookup_checks", SOURCE / "lookup_check.py")
lookup_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lookup_checks)

RECIPES = {
    **{name.removeprefix("lookup-run-"): recipe for name, (recipe, _) in lookup_checks.RUNS.items()},
    "twoKeys": ["service", "certify", "certify", "publish(0)", "publish(1)", "lookup(1)", "remove(0)", "remove(1)",
                "certify", "service", "drop(2)", "service", "lookup(0)"],
}
# Seeds of the committed traces of the model's own `step`.
SEEDS = {"step_a": "0x5e01", "step_b": "0x5e02", "step_c": "0x5e03", "step_d": "0x5e04", "step_e": "0x5e05",
         "step_f": "0x5e06"}
STEPS = 16


def generate(quint, output):
    digest = hashlib.sha256((SOURCE / "lookup.qnt").read_bytes()).hexdigest()
    plans = [(name, recipe, "0x5e00") for name, recipe in RECIPES.items()] + [(name, [], seed) for name, seed in SEEDS.items()]
    for name, recipe, seed in plans:
        steps = len(recipe) or STEPS
        case = SimpleNamespace(name=name, mutations=[], extra="", recipe=recipe, settings={"BOUND": str(steps)})
        directory = output / name
        directory.mkdir(parents=True)
        for filename, text in lookup_checks.inputs(case, SOURCE).items():
            (directory / filename).write_text(text)
        trace = output / (name + ".itf.json")
        subprocess.run([quint, "run", "case.qnt", "--main", "lookupCase", "--step", "recipe" if recipe else "step",
                        "--backend", "typescript", "--mbt", "--invariant", "safety", "--seed", seed, "--max-samples", "1",
                        "--max-steps", str(steps), "--n-traces", "1", "--out-itf", str(trace)],
                       cwd=directory, check=True, timeout=60)
        data = json.loads(trace.read_text())
        if len(data["states"]) != steps + 1:
            raise ValueError(f"{name}: the trace stopped before its final action")
        data["#meta"] = {"lookup": {"recipe": recipe, "seed": seed, "steps": steps, "model_sha256": digest}}
        trace.write_text(json.dumps(data, separators=(",", ":")) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quint", required=True, help="the pinned quint executable")
    parser.add_argument("--output", type=Path, required=True, help="a new directory for the traces")
    args = parser.parse_args()
    generate(args.quint, args.output.resolve())


if __name__ == "__main__":
    main()
