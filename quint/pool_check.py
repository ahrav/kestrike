"""Check the finite buffer-pool model: safety, a reachability witness per outcome, directed runs and mutations of each invariant."""
import re
from pathlib import Path

CONSTANTS = {"BOUND": "11"}
WITNESSES = tuple(re.findall(r"(?m)^  val (witness\w+) =", (Path(__file__).resolve().parent / "pool.qnt").read_text()))
RUNS = {
    "pool-run-heldThroughDrop": (
        ["acquire", "give(0)", "give(0)", "drop(0)", "acquire", "ret(0, 0)", "ret(0, 0)", "acquire"],
        'st.ev.res == "" and st.ev.buf == 0 and st.ev.inc == 1 and st.ended == 1 and st.mismatched == 0'),
    "pool-run-olderIncarnation": (
        ["acquire", "give(0)", "drop(0)", "ret(0, 0)", "acquire", "give(0)", "ret(0, 0)", "view(0)"],
        'st.ev.res == "Refused" and st.mismatched == 1 and st.bufs.get(0) == {set: "App", nic: 1, inc: 1}'),
    "pool-run-retire": (
        ["acquire", "drop(0)", "acquire", "drop(0)", "acquire", "drop(0)", "acquire", "drop(0)", "acquire"],
        'st.bufs.get(0) == {set: "Retired", nic: 0, inc: 3} and st.retired == 1 and st.ev.buf == 1 and st.stack == []'),
    "pool-run-quarantine": (
        ["acquire", "store(0)", "detach(0)", "discard(0)", "acquire"],
        'st.ev.buf == 0 and st.ev.inc == 1 and st.bufs.get(0).set == "App"'),
    "pool-run-posting": (
        ["post", "complete(0)", "lend(0)", "drop(0)", "unlend(0)", "post", "unpost(0)"],
        'st.stack == [1, 0] and st.bufs.get(0) == {set: "Free", nic: 0, inc: 2} and st.ended == 1'),
}
# Each mutation names the invariant that rejects it, the recipe that reaches the violation and the one changed text.
MUTANTS = {
    "pool-mutant-drop-frees-held": (
        "HeldStaysOffStack", ["acquire", "give(0)", "drop(0)"],
        ('if (s.bufs.get(b).nic > 0) moved(s, b, "Nic") else freed(s, b)', "freed(s, b)")),
    "pool-mutant-return-ignores-incarnation": (
        "ReferencesCounted", RUNS["pool-run-olderIncarnation"][0][:7],
        ("val hit = if (BUFS.contains(b)) s.bufs.get(b).inc == inc and s.bufs.get(b).nic > 0 else false",
         "val hit = if (BUFS.contains(b)) s.bufs.get(b).nic > 0 else false")),
    "pool-mutant-view-ignores-references": (
        "NoMutableViewWhileHeld", ["acquire", "lend(0)", "view(0)"],
        ('if (st.bufs.get(b).nic > 0) "Refused" else "Viewed"', '"Viewed"')),
    "pool-mutant-free-loses-buffer": (
        "Partition", ["acquire", "drop(0)"],
        ("stack: s.stack.append(b)}", "stack: s.stack}")),
    "pool-mutant-free-keeps-incarnation": (
        "IncarnationIssuedOnce", ["acquire", "drop(0)", "acquire"],
        ('{set: "Free", nic: 0, inc: r.inc + 1}', '{set: "Free", nic: 0, inc: r.inc}')),
}


def cases(Case):
    yield Case("pool-typecheck", command="typecheck", family="pool")
    yield Case("pool-safety", invariant="safety", family="pool")
    for witness in WITNESSES:
        yield Case(f"pool-reach-{witness}", invariant="unreached", expected="violation", family="pool",
                   extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="pool", recipe=recipe, settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="pool", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (invariant, recipe, mutation) in MUTANTS.items():
        yield Case(name, invariant=invariant, expected="violation", family="pool", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=[mutation])


def inputs(case, source):
    text = (source / "pool.qnt").read_text()
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
    return {"pool.qnt": text, "case.qnt": f'module poolCase {{\n  import pool(BOUND = {bound}).* from "./pool"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "pool.qnt"]
    return [quint, "verify", "case.qnt", "--main", "poolCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])


FIXTURES = "crates/kestrike/src/storage/device/pool_replay_fixtures"
FIXTURE_RECIPES = {
    **{name.removeprefix("pool-run-"): recipe for name, (recipe, _) in RUNS.items()},
    "exhausted": ["acquire", "post", "acquire", "post", "handoff(0)", "ret(2, 0)", "ret(0, 1)", "ret(0, 0)", "ret(0, 0)",
                  "complete(1)", "store(1)", "restore(1)", "view(1)", "drop(1)"],
}
# Seeds of the committed traces of the model's own `step`, sixteen steps each.
FIXTURE_SEEDS = {"step_a": "0x9b01", "step_b": "0x9b02", "step_c": "0x9b03", "step_d": "0x9b04", "step_e": "0x9b05",
                 "step_f": "0x9b06"}
STEPS = 16


def generate(quint, output):
    """Write the committed traces: one per directed recipe and one per seed of `step`, each naming the model's digest."""
    import hashlib
    import json
    import subprocess
    from types import SimpleNamespace
    source = Path(__file__).resolve().parent
    digest = hashlib.sha256((source / "pool.qnt").read_bytes()).hexdigest()
    plans = [(name, recipe, "0x9b00") for name, recipe in FIXTURE_RECIPES.items()] + [
        (name, [], seed) for name, seed in FIXTURE_SEEDS.items()]
    for name, recipe, seed in plans:
        steps = len(recipe) or STEPS
        case = SimpleNamespace(name=name, mutations=[], extra="", recipe=recipe, settings={"BOUND": str(steps)})
        directory = output / name
        directory.mkdir(parents=True)
        for filename, text in inputs(case, source).items():
            (directory / filename).write_text(text)
        trace = output / (name + ".itf.json")
        subprocess.run([quint, "run", "case.qnt", "--main", "poolCase", "--step", "recipe" if recipe else "step",
                        "--backend", "typescript", "--mbt", "--invariant", "safety", "--seed", seed, "--max-samples", "1",
                        "--max-steps", str(steps), "--n-traces", "1", "--out-itf", str(trace)],
                       cwd=directory, check=True, timeout=60)
        data = json.loads(trace.read_text())
        if len(data["states"]) != steps + 1:
            raise ValueError(f"{name}: the trace stopped before its final action")
        data["#meta"] = {"pool": {"recipe": recipe, "seed": seed, "steps": steps, "model_sha256": digest}}
        trace.write_text(json.dumps(data, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=generate.__doc__)
    parser.add_argument("--quint", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    generate(args.quint, args.output.resolve())
