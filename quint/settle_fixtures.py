"""Settle model traces for the replay against `Namespace`: the directed recipes and seeded runs of `step`.

Each trace is one `quint run --mbt` of `settle.qnt` at the model's constants. A directed trace follows one recipe;
a seeded trace takes `STEPS` steps of the model's own `step` under the seed its name carries. `fixtures()` declares
every trace, and each trace records under `#meta.settle` the model's digest and its declared recipe, seed and step
count. The Rust replay refuses a trace whose digest differs from the model's or whose states differ in number from
its recorded steps, and `scripts/test-judge-quint.py` refuses committed traces that differ from the declaration.

    python3 quint/settle_fixtures.py --quint QUINT --output DIRECTORY
"""

import argparse
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

SOURCE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("settle_check", SOURCE / "settle_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load settle_check.py")
settle_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(settle_check)

FIXTURES = "crates/kestrike/src/net/settle_replay_fixtures"
STEPS = 24
SEEDS = (0x5E771E, 0xA11CE, 0x0DDBA11, 0x7E57)
RECIPES = {
    "refused_order": settle_check.RUNS["settle-run-refused-order"][0],
    "free_slot": settle_check.RUNS["settle-run-free-slot"][0],
    "pressure": settle_check.RUNS["settle-run-pressure"][0],
    "replaced": settle_check.RUNS["settle-run-replaced"][0],
}


def fixtures():
    """Each committed trace: its model and the recipe, seed and step count it records under `#meta.settle`."""
    plans = [(name, recipe, 0x5E77) for name, recipe in RECIPES.items()] + [(f"step_{seed:x}", [], seed) for seed in SEEDS]
    return {name: ("settle.qnt", {"recipe": recipe, "seed": hex(seed), "steps": len(recipe) or STEPS})
            for name, recipe, seed in plans}


def generate(quint, output):
    """Write each declared trace as ITF with the model's digest and its declaration under `#meta.settle`."""
    digest = hashlib.sha256((SOURCE / "settle.qnt").read_bytes()).hexdigest()
    for name, (_, declared) in fixtures().items():
        recipe, seed, steps = declared["recipe"], declared["seed"], declared["steps"]
        case = SimpleNamespace(name=name, mutations=[], extra="", recipe=recipe, settings={"BOUND": str(steps)})
        directory = output / name
        directory.mkdir(parents=True)
        for filename, text in settle_check.inputs(case, SOURCE).items():
            (directory / filename).write_text(text)
        trace = output / (name + ".itf.json")
        # A recipe restricts the scheduler to its schedule.
        step = ["--step", "recipe"] if recipe else []
        subprocess.run([quint, "run", "case.qnt", "--main", "settleCase", *step, "--backend", "typescript", "--mbt",
                        "--invariant", "safety", "--seed", seed, "--max-samples", "1", "--max-steps", str(steps),
                        "--n-traces", "1", "--out-itf", str(trace)], cwd=directory, check=True, timeout=120,
                       stdout=subprocess.DEVNULL)
        try:
            data = json.loads(trace.read_text())
        except ValueError as error:
            raise ValueError(f"{name}: the trace quint wrote is not JSON: {error}") from error
        if len(data["states"]) != steps + 1:
            raise ValueError(f"{name}: the trace stopped before its final action")
        # The run's timestamps differ between runs and carry no state.
        data["#meta"] = {"format": data["#meta"]["format"], "settle": {**declared, "model_sha256": digest}}
        trace.write_text(json.dumps(data, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quint", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    generate(args.quint, args.output.resolve())
