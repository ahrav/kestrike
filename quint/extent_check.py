"""Check the finite extent-allocator model: safety, a reachability witness per outcome, directed runs and mutations of each invariant."""
import re
from pathlib import Path

CONSTANTS = {"BOUND": "15"}
WITNESSES = tuple(re.findall(r"(?m)^  val (witness\w+) =", (Path(__file__).resolve().parent / "extent.qnt").read_text()))
SINGLES = ["reserve(1)"] * 6
DROPPED = SINGLES + ["release(0, 1)", "release(1, 1)", "release(3, 1)", "release(4, 1)"]
RUNS = {
    "extent-run-bestFit": (
        ["reserve(3)", "reserve(2)", "reserve(1)", "release(0, 3)", "reserve(1)"],
        'st.ev == {act: "reserve", res: "Indexed", start: 6, len: 1} and '
        'st.index == Set({len: 3, start: 0}, {len: 1, start: 7})'),
    "extent-run-fullIndexDrop": (
        DROPPED,
        'st.drops == 2 and st.index == Set({len: 2, start: 6}, {len: 2, start: 3}) and '
        'runs(st.free) == Set({len: 2, start: 0}, {len: 2, start: 3}, {len: 2, start: 6})'),
    "extent-run-fallback": (
        DROPPED + ["reserve(1)"] * 4 + ["reserve(2)"],
        'st.ev == {act: "reserve", res: "Fallback", start: 0, len: 2} and st.index == Set() and st.free == Set()'),
    "extent-run-notHeld": (
        ["reserve(2)", "release(1, 2)", "release(0, 2)", "release(0, 2)"],
        'st.ev.res == "NotHeld" and st.free == UNITS and st.index == Set({len: 8, start: 0}) and st.held == Set()'),
}
# Each mutation names the invariant that rejects it, the recipe that reaches the violation and the one changed text.
MUTANTS = {
    "extent-mutant-join-keeps-neighbour-key": (
        "IndexNamesMaximalRuns", ["reserve(1)", "reserve(1)", "release(0, 1)", "release(1, 1)"],
        ("val apart = {...freed, index: freed.index.exclude(Set({len: start - low, start: low}, {len: high - end, start: end}))}",
         "val apart = freed")),
    "extent-mutant-split-forgets-remainder": (
        "NoDropsMeansWholeFreeSet", ["reserve(1)"],
        (".union(if (rest.len > 0) Set(rest) else Set())}", "}")),
    "extent-mutant-full-offer-drops-nothing": (
        "IndexWithinCapacity", ["reserve(1)"] * 4 + ["release(0, 1)", "release(2, 1)"],
        ("index: s.index.exclude(Set(least(s.index))).union(Set(r))}", "index: s.index.union(Set(r))}")),
    "extent-mutant-indexed-fit-by-start": (
        "PlacementFollowsFit", RUNS["extent-run-bestFit"][0],
        ("val best = least(indexed)", "val best = lowest(indexed)")),
    "extent-mutant-reservation-leaves-units-free": (
        "HeldDisjoint", ["reserve(1)"],
        ("val taken = {...s, free: s.free.exclude(units({len: n, start: from.start})),", "val taken = {...s, free: s.free,")),
}


def cases(Case):
    yield Case("extent-typecheck", command="typecheck", family="extent")
    yield Case("extent-safety", invariant="safety", family="extent")
    for witness in WITNESSES:
        yield Case(f"extent-reach-{witness}", invariant="unreached", expected="violation", family="extent",
                   extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="extent", recipe=recipe, settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="extent", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (invariant, recipe, mutation) in MUTANTS.items():
        yield Case(name, invariant=invariant, expected="violation", family="extent", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=[mutation])


def inputs(case, source):
    text = (source / "extent.qnt").read_text()
    for old, new in case.mutations:
        if text.count(old) != 1:
            raise ValueError(f"{case.name}: mutation target is not unique")
        text = text.replace(old, new)
    extra = case.extra
    if case.recipe:
        picks = {}
        for at, action in enumerate(case.recipe):
            picks.setdefault(action, []).append(str(at))
        extra += "  action recipe = any {\n" + "".join(
            f'    all {{ Set({", ".join(turns)}).contains(turn), {action} }},\n' for action, turns in picks.items()) + "  }\n"
    bound = case.settings.get("BOUND", CONSTANTS["BOUND"])
    return {"extent.qnt": text, "case.qnt": f'module extentCase {{\n  import extent(BOUND = {bound}).* from "./extent"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "extent.qnt"]
    return [quint, "verify", "case.qnt", "--main", "extentCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])


FIXTURES = "crates/kestrike/src/storage/extent/replay_fixtures"
FIXTURE_RECIPES = {name.removeprefix("extent-run-"): recipe for name, (recipe, _) in RUNS.items()}
# Seeds of the committed traces of the model's own `step`, twenty-four steps each.
FIXTURE_SEEDS = {"step_a": "0xe701", "step_b": "0xe702", "step_c": "0xe703", "step_d": "0xe704", "step_e": "0xe705",
                 "step_f": "0xe706"}
STEPS = 24


def generate(quint, output):
    """Write the committed traces: one per directed recipe and one per seed of `step`, each naming the model's digest."""
    import hashlib
    import json
    import subprocess
    from types import SimpleNamespace
    source = Path(__file__).resolve().parent
    digest = hashlib.sha256((source / "extent.qnt").read_bytes()).hexdigest()
    plans = [(name, recipe, "0xe700") for name, recipe in FIXTURE_RECIPES.items()] + [
        (name, [], seed) for name, seed in FIXTURE_SEEDS.items()]
    for name, recipe, seed in plans:
        steps = len(recipe) or STEPS
        case = SimpleNamespace(name=name, mutations=[], extra="", recipe=recipe, settings={"BOUND": str(steps)})
        directory = output / name
        directory.mkdir(parents=True)
        for filename, text in inputs(case, source).items():
            (directory / filename).write_text(text)
        trace = output / (name + ".itf.json")
        subprocess.run([quint, "run", "case.qnt", "--main", "extentCase", "--step", "recipe" if recipe else "step",
                        "--backend", "typescript", "--mbt", "--invariant", "safety", "--seed", seed, "--max-samples", "1",
                        "--max-steps", str(steps), "--n-traces", "1", "--out-itf", str(trace)],
                       cwd=directory, check=True, timeout=60)
        data = json.loads(trace.read_text())
        if len(data["states"]) != steps + 1:
            raise ValueError(f"{name}: the trace stopped before its final action")
        data["#meta"] = {"extent": {"recipe": recipe, "seed": seed, "steps": steps, "model_sha256": digest}}
        trace.write_text(json.dumps(data, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=generate.__doc__)
    parser.add_argument("--quint", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    generate(args.quint, args.output.resolve())
