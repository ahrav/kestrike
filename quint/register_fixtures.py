#!/usr/bin/env python3
"""Write the traces of the register model that `storage::register_replay_tests` replays into `--output`, one `<name>.itf.json` per trace beside its working directory.

Usage: register_fixtures.py --quint QUINT --output DIR

One trace per directed recipe and one per pinned seed of the model's own `step`, written with
`quint run --mbt`. Each trace names the sha256 of `register.qnt`, and the replay refuses a trace of another
model text.
The committed copies live under `crates/kestrike/src/storage/register_replay_fixtures/`.
"""
import argparse
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

SOURCE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("register_checks", SOURCE / "register_check.py")
register_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(register_checks)

RECIPES = {
    **{name.removeprefix("register-run-"): recipe for name, (recipe, _) in register_checks.RUNS.items()},
    "forgottenHandles": ["register", "register", "forget(1)", "register", "leak(0)", "forget(0)", "close", "register"],
    "leakedAcrossTheClose": ["register", "leak(0)", "close", "interval(0)", "drop(0)"],
}
# Seeds of the committed traces of the model's own `step`.
SEEDS = {"step_a": "0x3b01", "step_b": "0x3b02", "step_c": "0x3b03", "step_d": "0x3b04", "step_e": "0x3b05",
         "step_f": "0x3b06"}
STEPS = 14


def generate(quint, output):
    digest = hashlib.sha256((SOURCE / "register.qnt").read_bytes()).hexdigest()
    plans = [(name, recipe, "0x3b00") for name, recipe in RECIPES.items()] + [(name, [], seed) for name, seed in SEEDS.items()]
    for name, recipe, seed in plans:
        steps = len(recipe) or STEPS
        case = SimpleNamespace(name=name, mutations=[], extra="", recipe=recipe, settings={"BOUND": str(steps)})
        directory = output / name
        directory.mkdir(parents=True)
        for filename, text in register_checks.inputs(case, SOURCE).items():
            (directory / filename).write_text(text)
        trace = output / (name + ".itf.json")
        subprocess.run([quint, "run", "case.qnt", "--main", "registerCase", "--step", "recipe" if recipe else "step",
                        "--backend", "typescript", "--mbt", "--invariant", "safety", "--seed", seed, "--max-samples", "1",
                        "--max-steps", str(steps), "--n-traces", "1", "--out-itf", str(trace)],
                       cwd=directory, check=True, timeout=60)
        data = json.loads(trace.read_text())
        if len(data["states"]) != steps + 1:
            raise ValueError(f"{name}: the trace stopped before its final action")
        data["#meta"] = {"register": {"recipe": recipe, "seed": seed, "steps": steps, "model_sha256": digest}}
        trace.write_text(json.dumps(data, separators=(",", ":")) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quint", required=True, help="the pinned quint executable")
    parser.add_argument("--output", type=Path, required=True, help="a new directory for the traces")
    args = parser.parse_args()
    generate(args.quint, args.output.resolve())


if __name__ == "__main__":
    main()
