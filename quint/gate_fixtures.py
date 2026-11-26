"""Attach-gate model traces for the replay against `Volume`: the directed recipes and seeded runs of `step`.

Each trace is one `quint run --mbt` of `gate.qnt`. A directed trace follows one recipe; a seeded trace takes
`STEPS` steps of the model's own `step` under the seed its name carries. Every trace records under `#meta.gate`
the model's digest and its recipe or seed, and the Rust replay refuses a trace whose digest differs from the model's.

    python3 quint/gate_fixtures.py --quint QUINT --output DIRECTORY
"""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import gate_check

STEPS = 12
SEEDS = (0x1221, 0x1222, 0x1223, 0x1224, 0x1225, 0x1226, 0x1227, 0x1228)
RECIPES = {name.removeprefix("gate-run-").replace("-", "_"): recipe for name, (recipe, _) in gate_check.RUNS.items()}
SUBMIT, REPORTED = gate_check.SUBMIT, gate_check.REPORTED
RECIPES.update({
    "register_conflict": [SUBMIT, "register(false)", SUBMIT],
    "submit_refused": [SUBMIT, "register(true)", 'tick("busy")', 'tick("invalid")', SUBMIT],
    "device_gone": [SUBMIT, "register(true)", SUBMIT, "acquire(true)", 'tick("gone")', SUBMIT],
    "foreign_holder": REPORTED + ['report("holder")', SUBMIT],
    "other_type": REPORTED + ['report("type")', SUBMIT],
    "duplicate_own_record": REPORTED + ['report("duplicate")', SUBMIT],
    "own_pair_not_holding": REPORTED + ['report("notholder")', SUBMIT],
    "withheld_bytes": REPORTED + ['report("withheld")', SUBMIT],
    "failed_report": REPORTED + ['report("failed")', SUBMIT],
    "deposing_report": REPORTED + ['report("deposing")', SUBMIT],
    "expiry_under_the_register": [SUBMIT, "expire", SUBMIT],
    "withdrawal_under_the_acquire": [SUBMIT, "register(true)", SUBMIT, "withdraw", SUBMIT],
    "close_under_the_report": REPORTED + ["close", SUBMIT],
    "close_before_the_register": ["close", SUBMIT],
})


def run(quint, directory, trace, steps, seed, recipe):
    """Write one trace of `steps` steps; a recipe restricts the scheduler to its schedule."""
    case = SimpleNamespace(name=trace.name, mutations=[], extra="", recipe=recipe, settings={"BOUND": str(steps)})
    directory.mkdir(parents=True)
    for filename, text in gate_check.inputs(case, Path(__file__).resolve().parent).items():
        (directory / filename).write_text(text)
    step = ["--step", "recipe"] if recipe else []
    subprocess.run([quint, "run", "case.qnt", "--main", "gateCase", *step, "--backend", "typescript", "--mbt",
                    "--invariant", "safety", "--seed", hex(seed), "--max-samples", "1", "--max-steps", str(steps),
                    "--n-traces", "1", "--out-itf", str(trace)], cwd=directory, check=True, timeout=120,
                   stdout=subprocess.DEVNULL)
    return json.loads(trace.read_text())


def generate(quint, output):
    source = Path(__file__).resolve().parent
    digest = hashlib.sha256((source / "gate.qnt").read_bytes()).hexdigest()
    traces = {name: (recipe, 0x1220) for name, recipe in RECIPES.items()}
    traces.update({f"step_{seed:x}": (None, seed) for seed in SEEDS})
    for name, (recipe, seed) in traces.items():
        trace = output / (name + ".itf.json")
        steps = len(recipe) if recipe else STEPS
        data = run(quint, output / name, trace, steps, seed, recipe)
        if len(data["states"]) != steps + 1:
            raise ValueError(f"{name}: the trace stopped before its final action")
        meta = {"model_sha256": digest, "seed": hex(seed), "steps": steps}
        if recipe:
            meta["recipe"] = recipe
        # The run's timestamps differ between runs and carry no state.
        data["#meta"] = {"format": data["#meta"]["format"], "gate": meta}
        trace.write_text(json.dumps(data, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--quint", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    generate(args.quint, args.output.resolve())
