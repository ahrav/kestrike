"""Reconciler-creation model traces for the replay against `Reconciler`: the directed recipes and seeded runs of `step`.

Each trace is one `quint run --mbt` of `creation.qnt`. A directed trace follows one recipe; a seeded trace takes
`STEPS` steps of the model's own `step` under the seed its name carries. Every trace records under `#meta.creation`
the model's digest and its recipe or seed, and the Rust replay refuses a trace whose digest differs from the model's.

    python3 quint/creation_fixtures.py --quint QUINT --output DIRECTORY
"""

import argparse
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

SOURCE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("creation_check", SOURCE / "creation_check.py")
creation_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(creation_check)

FIXTURES = "crates/kestrike/src/failover/creation_replay_fixtures"
STEPS = 24
SEEDS = tuple(range(0x2185, 0x2195))
op = creation_check.op
RECIPES = {name.removeprefix("creation-run-").replace("-", "_"): recipe for name, (recipe, _) in creation_check.RUNS.items()}
RECIPES.update({
    # Two creations of one record race: the loser's page creates refuse on empty pages, its shard create refuses,
    # and it finds its own creation.
    "racing_creations_of_one_record": creation_check.RACED,
    # A creation read the shard record absent; another creation finishes and the owner fences page 0; the first
    # creation's page create meets the fenced page and it finds its own creation in the shard record.
    "fenced_page_under_a_retry": creation_check.MET_FENCE + ["request(1)"],
    # Unknown outcomes: a page create that committed, a shard create that was lost, a held shard create that lands,
    # and the retries.
    "unknown_outcomes_and_retries": op(0, "createShard", 1, 1) + ['unknown(0, "commit")'] + op(0, "createShard", 1, 4)
    + ['unknown(0, "lost")'] + op(0, "createShard", 1, 5) + ['unknown(0, "hold")', "release"] + op(1, "createShard", 1, 1),
    # A held shard create refuses after another creation won; the retry conflicts.
    "held_create_after_the_winner": op(0, "createShard", 2, 3) + ['unknown(0, "hold")'] + op(1, "createShard", 1, 6)
    + ["release"] + op(0, "createShard", 2, 1) + ["fence(1)"],
    # An attach before the volume record exists, then provisioning and the attach record under unknown outcomes and
    # a racing attach of another host.
    "volume_unknown_outcomes": op(0, "attach", 1, 1) + op(0, "provision", 0, 0) + ['unknown(0, "commit")']
    + op(0, "provision", 0, 2) + op(0, "attach", 1, 1) + op(1, "attach", 2, 1) + ['unknown(0, "lost")', "request(1)"]
    + op(0, "attach", 1, 1) + op(1, "provision", 0, 2),
    # Two attaches read the provisioning record; one writes, the other's write refuses on its condition.
    "racing_attaches": op(0, "provision", 0, 1) + op(0, "attach", 1, 1) + op(1, "attach", 2, 1)
    + ["request(1)", "request(0)"] + op(0, "attach", 1, 1),
    # A held attach write lands after the reply was unknown; the retry replays it.
    "held_attach_lands": op(0, "provision", 0, 1) + op(0, "attach", 1, 1) + ['unknown(0, "hold")', "release"]
    + op(0, "attach", 1, 1),
})


def run(quint, directory, trace, steps, seed, recipe):
    """Write one trace of `steps` steps; a recipe restricts the scheduler to its schedule."""
    case = SimpleNamespace(name=trace.name, mutations=[], extra="", recipe=recipe, settings={"BOUND": str(steps)})
    directory.mkdir(parents=True)
    for filename, text in creation_check.inputs(case, SOURCE).items():
        (directory / filename).write_text(text)
    step = ["--step", "recipe"] if recipe else []
    subprocess.run([quint, "run", "case.qnt", "--main", "creationCase", *step, "--backend", "typescript", "--mbt",
                    "--invariant", "safety", "--seed", hex(seed), "--max-samples", "1", "--max-steps", str(steps),
                    "--n-traces", "1", "--out-itf", str(trace)], cwd=directory, check=True, timeout=120,
                   stdout=subprocess.DEVNULL)
    return json.loads(trace.read_text())


def fixtures():
    """Each committed trace: its model and the seed, step count and, for a directed trace, the recipe it records
    under `#meta.creation`."""
    declared = {name: {"seed": hex(0x2184), "steps": len(recipe), "recipe": recipe} for name, recipe in RECIPES.items()}
    declared.update({f"step_{seed:x}": {"seed": hex(seed), "steps": STEPS} for seed in SEEDS})
    return {name: ("creation.qnt", metadata) for name, metadata in declared.items()}


def generate(quint, output):
    for name, (model, metadata) in fixtures().items():
        trace = output / (name + ".itf.json")
        steps = metadata["steps"]
        data = run(quint, output / name, trace, steps, int(metadata["seed"], 16), metadata.get("recipe"))
        if len(data["states"]) != steps + 1:
            raise ValueError(f"{name}: the trace stopped before its final action")
        digest = hashlib.sha256((SOURCE / model).read_bytes()).hexdigest()
        # The run's timestamps differ between runs and carry no state.
        data["#meta"] = {"format": data["#meta"]["format"], "creation": {"model_sha256": digest, **metadata}}
        trace.write_text(json.dumps(data, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--quint", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    generate(args.quint, args.output.resolve())
