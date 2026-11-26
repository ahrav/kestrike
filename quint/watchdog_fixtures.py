"""Write the committed traces the watchdog replay test reads: one per directed recipe and one per seed of the model's `step`."""

import argparse
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

SOURCE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("watchdog_checks", SOURCE / "watchdog_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load watchdog_check.py")
watchdog_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(watchdog_checks)

FIXTURES = "crates/kestrike/src/native/watchdog_tests/replay_fixtures"
RECIPES = {
    "idle_then_full_deadline": watchdog_checks.RUNS["watchdog-run-idle-then-full-deadline"][0],
    "disarm_then_rearm": watchdog_checks.RUNS["watchdog-run-disarm-then-rearm"][0],
    "partial_then_expiry": ["rearm", "wake(0)", "wake(1)", "pass(1)", "wake(0)", "wake(2)", "disarm", "rearm", "disarm"],
    "three_episodes": ["rearm", "wake(1)", "disarm", "pass(3)", "rearm", "wake(1)", "disarm", "wake(3)", "rearm", "wake(3)"],
}
# Seeds of the committed traces of the model's own `step`, ten steps each.
SEEDS = {"step_a": "0x7a01", "step_b": "0x7a02", "step_c": "0x7a03", "step_d": "0x7a04", "step_e": "0x7a05", "step_f": "0x7a06"}
STEPS = 10


def fixtures():
    """Each committed trace: its model and the recipe, seed and step count it records under `#meta.watchdog`."""
    plans = [(name, recipe, "0x7a00") for name, recipe in RECIPES.items()] + [(name, [], seed) for name, seed in SEEDS.items()]
    return {name: ("watchdog.qnt", {"recipe": recipe, "seed": seed, "steps": len(recipe) or STEPS}) for name, recipe, seed in plans}


def generate(quint, output):
    """Write each trace as ITF with the model's digest, its recipe or seed and its step count under `#meta`."""
    digest = hashlib.sha256((SOURCE / "watchdog.qnt").read_bytes()).hexdigest()
    for name, (_, declared) in fixtures().items():
        recipe, seed, steps = declared["recipe"], declared["seed"], declared["steps"]
        case = SimpleNamespace(name=name, mutations=[], extra="", recipe=recipe, settings={"BOUND": str(steps)})
        directory = output / name
        directory.mkdir(parents=True)
        for filename, text in watchdog_checks.inputs(case, SOURCE).items():
            (directory / filename).write_text(text)
        trace = output / (name + ".itf.json")
        subprocess.run([quint, "run", "case.qnt", "--main", "watchdogCase", "--step", "recipe" if recipe else "step",
                        "--backend", "typescript", "--mbt", "--invariant", "safety", "--seed", seed, "--max-samples", "1",
                        "--max-steps", str(steps), "--n-traces", "1", "--out-itf", str(trace)],
                       cwd=directory, check=True, timeout=60)
        data = json.loads(trace.read_text())
        if len(data["states"]) != steps + 1:
            raise ValueError(f"{name}: the trace stopped before its final action")
        data["#meta"] = {"watchdog": {**declared, "model_sha256": digest}}
        trace.write_text(json.dumps(data, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=generate.__doc__)
    parser.add_argument("--quint", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    generate(args.quint, args.output.resolve())
