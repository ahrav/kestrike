"""Builder-escrow model traces for the replay against `Storage`: the directed recipes and seeded runs of `step`.

Each trace is one `quint run --mbt` of `escrow.qnt`. A directed trace follows one recipe; a seeded trace takes
`STEPS` steps of the model's own `step` under the seed its name carries. Every trace records under `#meta.escrow`
the model's digest and its recipe or seed, and the Rust replay refuses a trace whose digest differs from the model's.

    python3 quint/escrow_fixtures.py --quint QUINT --output DIRECTORY
"""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import escrow_check

STEPS = 12
SEEDS = ((0xe50, "316"), (0xe51, "316"), (0xe52, "316"), (0xe53, "316"), (0xe54, "316"), (0xe55, "316"),
         (0xe56, "315"), (0xe57, "315"))
RECIPES = {name.removeprefix("escrow-run-").replace("-", "_"): (recipe, volume)
           for name, (recipe, _, volume) in escrow_check.RUNS.items()}
RECIPES.update({
    # Each exit of each placement cut: an unplaced cancel and drop, a partial cancel, a complete cancel and drop, and
    # service returning a parked sequence one extent per call, then idle.
    "every_exit_at_every_cut": (["promise(1, 2)", "cancel(1)", "promise(2, 3)", "release(2)", "service",
                                "promise(1, 3)", "place(1)", "cancel(1)", "promise(2, 2)", "place(2)", "place(2)",
                                "release(2)", "service", "service", "service"], "316"),
    # A claim refused beside two promises, a cancel of an unplaced builder beside a complete one, a promise refused
    # beside two claims, the complete builder's cancel and an exact promise, then both claims return.
    "refusals_beside_promises_and_claims": (["promise(1, 3)", "promise(2, 2)", "claim", "place(1)", "place(1)",
                                            "place(1)", "cancel(2)", "claim", "claim", "promise(2, 2)", "cancel(1)",
                                            "promise(2, 3)", "unclaim", "unclaim"], "316"),
})


def run(quint, directory, trace, steps, seed, recipe, volume):
    """Write one trace of `steps` steps; a recipe restricts the scheduler to its schedule."""
    case = SimpleNamespace(name=trace.name, mutations=[], extra="", recipe=recipe,
                           settings={"BOUND": str(steps), "VOLUME": volume})
    directory.mkdir(parents=True)
    for filename, text in escrow_check.inputs(case, Path(__file__).resolve().parent).items():
        (directory / filename).write_text(text)
    step = ["--step", "recipe"] if recipe else []
    subprocess.run([quint, "run", "case.qnt", "--main", "escrowCase", *step, "--backend", "typescript", "--mbt",
                    "--invariant", "safety", "--seed", hex(seed), "--max-samples", "1", "--max-steps", str(steps),
                    "--n-traces", "1", "--out-itf", str(trace)], cwd=directory, check=True, timeout=120,
                   stdout=subprocess.DEVNULL)
    return json.loads(trace.read_text())


def generate(quint, output):
    source = Path(__file__).resolve().parent
    digest = hashlib.sha256((source / "escrow.qnt").read_bytes()).hexdigest()
    traces = {name: (recipe, 0xe4f, volume) for name, (recipe, volume) in RECIPES.items()}
    traces.update({f"step_{seed:x}": (None, seed, volume) for seed, volume in SEEDS})
    for name, (recipe, seed, volume) in traces.items():
        trace = output / (name + ".itf.json")
        steps = len(recipe) if recipe else STEPS
        data = run(quint, output / name, trace, steps, seed, recipe, volume)
        if len(data["states"]) != steps + 1:
            raise ValueError(f"{name}: the trace stopped before its final action")
        meta = {"model_sha256": digest, "seed": hex(seed), "steps": steps, "volume": int(volume)}
        if recipe:
            meta["recipe"] = recipe
        # The run's timestamps differ between runs and carry no state.
        data["#meta"] = {"format": data["#meta"]["format"], "escrow": meta}
        trace.write_text(json.dumps(data, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--quint", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    generate(args.quint, args.output.resolve())
