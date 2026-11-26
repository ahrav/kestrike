"""Watermark-log model traces for the replay against the file log: the directed recipes and seeded runs of `step`.

Each trace is one `quint run --mbt` of `marklog.qnt` at the model's constants, with `BOUND` set to the trace's
length. A directed trace follows one recipe; a seeded trace takes `STEPS` steps of the model's own `step` under the
seed its name carries. Every state after the first records under `call` the action taken and its arguments: a
batch and the keys a crash landed as lists of pages, and a write's page. Every trace records under `#meta.marklog`
the model's digest, its seed, its number of steps and a directed trace's recipe. The Rust replay refuses a trace
whose digest differs from the model's or whose states number other than its steps plus one.

    python3 quint/marklog_fixtures.py --quint QUINT --output DIRECTORY
"""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from types import SimpleNamespace

import marklog_check

STEPS = 14
SEEDS = (0x6B01, 0x6B02, 0x6B03, 0x6B05, 0x6B08, 0x6B0D)
RECIPES = {
    "partly_landed": marklog_check.RUNS["marklog-run-partly-landed"][0],
    "whole_replacement": marklog_check.RUNS["marklog-run-whole-replacement"][0],
    "out_of_key_order": marklog_check.RUNS["marklog-run-out-of-key-order"][0],
    # The process that replaced the file whole raises a held mark in place, and then a new one.
    "raise_after_whole": ["read(Set(1, 2))", "write(1)", "read(Set(1))", "write(2)", "read(Set(2, 3))", "restart",
                          "read(Set(1, 2, 3))"],
    # A crash that lands nothing, one that lands every slot, and one that loses the one new mark of its raise.
    "crashes": ["read(Set(2))", "write(2)", "crash(Set(2), Set())", "crash(Set(2), Set(2))", "write(2)",
                "crash(Set(1, 2), Set(2))", "read(Set(1, 2))", "read(Set(1, 2, 3))"],
    # A whole replacement that a crash completes, read again by the next process, and three marks raised in place.
    "whole_then_in_place": ["crash(Set(1, 2, 3), Set(1, 2, 3))", "read(Set(1, 2, 3))", "write(1)", "write(2)",
                            "write(3)", "read(Set(3, 2, 1))", "restart", "read(Set(1))"],
}


def run(quint, directory, trace, steps, seed, recipe):
    """Write one trace of `steps` steps; a recipe restricts the scheduler to its schedule."""
    case = SimpleNamespace(name=trace.name, mutations=[], extra="", recipe=recipe, settings={"BOUND": str(steps)})
    directory.mkdir(parents=True)
    for filename, text in marklog_check.inputs(case, Path(__file__).resolve().parent).items():
        (directory / filename).write_text(text)
    step = ["--step", "recipe"] if recipe else []
    subprocess.run([quint, "run", "case.qnt", "--main", "marklogCase", *step, "--backend", "typescript", "--mbt",
                    "--invariant", "safety", "--seed", hex(seed), "--max-samples", "1", "--max-steps", str(steps),
                    "--n-traces", "1", "--out-itf", str(trace)], cwd=directory, check=True, timeout=120,
                   stdout=subprocess.DEVNULL)
    return json.loads(trace.read_text())


def pages(value):
    """A picked set of pages as a sorted list."""
    return sorted(int(page["#bigint"]) for page in value["#set"])


def call(state, text):
    """The action of `state` and its arguments, from the recipe's text or from the recorded picks."""
    act = state["marklogCase::marklog::ev"]["act"]
    if text is not None:
        sets = [sorted(int(page) for page in re.findall(r"\d+", inner)) for inner in re.findall(r"Set\(([^)]*)\)", text)]
        return [act, *sets] if sets else [act, *(int(page) for page in re.findall(r"\d+", text))]
    picks = state["mbt::nondetPicks"]
    names = {"read": ("batch",), "crash": ("batch", "landed"), "write": ("k",), "restart": ()}[act]
    return [act, *(int(picks[name]["value"]["#bigint"]) if name == "k" else pages(picks[name]["value"])
                   for name in names)]


def generate(quint, output):
    source = Path(__file__).resolve().parent
    digest = hashlib.sha256((source / "marklog.qnt").read_bytes()).hexdigest()
    traces = {name: (recipe, 0x6B00) for name, recipe in RECIPES.items()}
    traces.update({f"step_{seed:x}": (None, seed) for seed in SEEDS})
    for name, (recipe, seed) in traces.items():
        trace = output / (name + ".itf.json")
        steps = len(recipe) if recipe else STEPS
        data = run(quint, output / name, trace, steps, seed, recipe)
        if len(data["states"]) != steps + 1:
            raise ValueError(f"{name}: the trace stopped before its final action")
        for at, state in enumerate(data["states"][1:]):
            state["call"] = call(state, recipe[at] if recipe else None)
        meta = {"model_sha256": digest, "seed": hex(seed), "steps": steps}
        if recipe:
            meta["recipe"] = recipe
        # The run's timestamps differ between runs and carry no state.
        data["#meta"] = {"format": data["#meta"]["format"], "marklog": meta}
        trace.write_text(json.dumps(data, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quint", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    generate(args.quint, args.output.resolve())
