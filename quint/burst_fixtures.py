"""Burst custody model traces for the replay against `Burst` over the mock port: directed recipes and seeded runs of `step`.

Each trace is one `quint run --mbt` of `burst.qnt`. A directed trace follows one recipe, with `BOUND` set to the
recipe's length; a seeded trace takes `STEPS` steps of the model's own `step` under its seed. Every trace records
under `#meta.burst` the model's digest, its recipe, its seed and its step count. The Rust replay refuses a trace
whose digest differs from the model's and a directed trace whose state records another action or argument than its
recipe entry, and `scripts/test-judge-quint.py` refuses committed traces that differ from
`fixtures()` in name, recipe, seed or step count.

    python3 quint/burst_fixtures.py --quint QUINT --output DIRECTORY
"""

import argparse
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

SOURCE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("burst_checks", SOURCE / "burst_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load burst_check.py")
burst_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(burst_checks)
RUNS, inputs = burst_checks.RUNS, burst_checks.inputs

FIXTURES = "crates/kestrike/src/native/burst_tests/replay_fixtures"
FIXTURE_RECIPES = {
    "uncertain_settles": RUNS["burst-run-uncertain-settles"][0],
    "unproven_holds": RUNS["burst-run-unproven-holds"][0],
    "down": ['send(2, 2, "no")', 'reclaim(true, true, "fail", true)', 'send(1, 1, "no")', 'reclaim(true, true, "ok", true)',
             "complete", "close(true)", "complete"],
    "lost_after_restart": ['send(1, 1, "no")', 'reclaim(true, true, "stale", false)', 'send(2, 2, "no")', "close(false)"],
    "freed": ['send(2, 0, "freed")', 'send(1, 1, "no")', 'reclaim(false, true, "ok", true)', 'send(2, 0, "no")', "close(false)"],
    "kept_unsettled": ['send(2, 1, "kept")', "complete", "close(false)", 'send(1, 1, "no")', "close(true)"],
    "lost_then_settled": ['send(2, 2, "no")', 'send(2, 1, "untaken")', 'reclaim(false, false, "ok", true)', "complete",
                          "close(true)", 'reclaim(true, true, "ok", true)'],
    "unsettled_kept": ['send(2, 1, "kept")', "close(false)", "complete"],
    "unsettled_untaken": ['send(1, 0, "untaken")', "close(false)", 'reclaim(true, true, "ok", true)'],
    "cleanup": ['send(2, 2, "no")', 'reclaim(false, true, "ok", true)', "complete", 'reclaim(true, true, "ok", true)',
                'send(2, 1, "kept")', 'reclaim(false, true, "fail", false)'],
}
# Seeds of the committed traces of the model's own `step`, ten steps each.
FIXTURE_SEEDS = {"step_a": "0xb60f", "step_b": "0xb623", "step_c": "0xb628", "step_d": "0xb64d"}
STEPS = 10


def fixtures():
    """Each committed trace: its model and the recipe, seed and step count it records under `#meta.burst`."""
    plans = [(name, recipe, "0xb570") for name, recipe in FIXTURE_RECIPES.items()] + [
        (name, [], seed) for name, seed in FIXTURE_SEEDS.items()]
    return {name: ("burst.qnt", {"recipe": recipe, "seed": seed, "steps": len(recipe) or STEPS}) for name, recipe, seed in plans}


def generate(quint, output):
    """Write the committed traces: one per directed recipe and one per seed of `step`, each naming the model's digest."""
    digest = hashlib.sha256((SOURCE / "burst.qnt").read_bytes()).hexdigest()
    for name, (_, declared) in fixtures().items():
        recipe, seed, steps = declared["recipe"], declared["seed"], declared["steps"]
        case = SimpleNamespace(name=name, mutations=[], extra="", recipe=recipe, settings={"BOUND": str(steps)})
        directory = output / name
        directory.mkdir(parents=True)
        for filename, text in inputs(case, SOURCE).items():
            (directory / filename).write_text(text)
        trace = output / (name + ".itf.json")
        subprocess.run([quint, "run", "case.qnt", "--main", "burstCase", "--step", "recipe" if recipe else "step",
                        "--backend", "typescript", "--mbt", "--invariant", "safety", "--seed", seed, "--max-samples", "1",
                        "--max-steps", str(steps), "--n-traces", "1", "--out-itf", str(trace)],
                       cwd=directory, check=True, timeout=60)
        data = json.loads(trace.read_text())
        if len(data["states"]) != steps + 1:
            raise ValueError(f"{name}: the trace stopped before its final action")
        data["#meta"] = {"burst": {**declared, "model_sha256": digest}}
        trace.write_text(json.dumps(data, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=generate.__doc__)
    parser.add_argument("--quint", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    generate(args.quint, args.output.resolve())
