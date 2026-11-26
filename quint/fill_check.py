"""Check the finite fill-authority model: safety, a reachability witness per outcome, directed runs and one mutation per invariant."""

CONSTANTS = {"BOUND": "8"}
WITNESSES = ("witnessGranted", "witnessInProgress", "witnessInProgressDeparted", "witnessFull", "witnessExhausted",
             "witnessRevoked", "witnessNoneRevoked", "witnessDeparted", "witnessDepartedRevoked", "witnessReleased",
             "witnessIdle", "witnessReplacement")
RUNS = {
    "fill-run-replacement": (["begin(0)", "revoke(0)", "begin(0)", "depart(1)", "service", "depart(2)", "service"],
                             "st.recs.get(0) == FREE and st.recs.get(1) == FREE and st.next == 3"),
    "fill-run-exhausted": (["begin(0)", "begin(1)", "depart(1)", "service", "begin(0)", "begin(0)", "depart(2)", "depart(3)", "service"],
                           "witnessReleased and st.next == 4 and st.live == Set()"),
}
MUTANTS = {
    "OneCurrentPerKey": (["begin(0)", "begin(0)"], ('else if (current.size() > 0) {...st, ev: event("begin", "InProgress", key, 0, 0)}\n        else if (free', 'else if (free')),
    "SerialIssuedOnce": (["begin(0)", "begin(1)"], ("next: st.next + 1, live", "next: st.next, live")),
    "SerialWithinMaximum": (["begin(0)", "begin(1)", "depart(1)", "depart(2)", "service", "begin(0)", "depart(3)", "service", "begin(0)"],
                            ("if (st.next > MAX) {", "if (st.next > MAX + 1) {")),
    "LiveOwnerKeepsRecord": (["begin(0)", "service"], ("val releasable = RECORDS.filter(r => st.recs.get(r).departed)",
                                                       "val releasable = RECORDS.filter(r => occupied(st.recs.get(r)))")),
    "DepartsAfterOwnerEnded": (["begin(0)", "revoke(0)"], ("{...found, revoked: true}", "{...found, departed: true}")),
    "WellFormed": (["begin(0)", "depart(1)", "service"], ("if (releasable.contains(r)) FREE else", "if (releasable.contains(r)) {...FREE, departed: true} else")),
}


def cases(Case):
    yield Case("fill-typecheck", command="typecheck", family="fill")
    yield Case("fill-safety", invariant="safety", family="fill")
    for witness in WITNESSES:
        yield Case(f"fill-reach-{witness}", invariant="unreached", expected="violation", family="fill",
                   extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="fill", recipe=recipe, settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="fill", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (recipe, mutation) in MUTANTS.items():
        yield Case(f"fill-mutant-{name}", invariant=name, expected="violation", family="fill", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=[mutation])


def inputs(case, source):
    text = (source / "fill.qnt").read_text()
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
    return {"fill.qnt": text, "case.qnt": f'module fillCase {{\n  import fill(BOUND = {bound}).* from "./fill"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "fill.qnt"]
    return [quint, "verify", "case.qnt", "--main", "fillCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])


FIXTURES = "crates/kestrike/src/storage/fill_replay_fixtures"
FIXTURE_RECIPES = {
    "replacement": RUNS["fill-run-replacement"][0],
    "exhausted": RUNS["fill-run-exhausted"][0],
    "full": ["begin(0)", "revoke(0)", "begin(1)", "begin(0)", "revoke(0)", "depart(2)", "service", "begin(0)", "depart(1)", "depart(3)", "service"],
    "in_progress": ["service", "revoke(1)", "begin(1)", "begin(1)", "depart(1)", "begin(1)", "revoke(1)", "begin(1)", "service", "begin(0)", "begin(0)"],
    "second_record": ["begin(0)", "begin(1)", "begin(1)", "revoke(1)", "begin(1)"],
}
# Seeds of the committed traces of the model's own `step`, eight steps each.
FIXTURE_SEEDS = {"step_a": "0x1f11", "step_b": "0x1f12", "step_c": "0x1f13", "step_d": "0x1f14"}
STEPS = 8


def fixtures():
    """Each committed trace: its model and the recipe, seed and step count it records under `#meta.fill`."""
    plans = [(name, recipe, "0x1f10") for name, recipe in FIXTURE_RECIPES.items()] + [
        (name, [], seed) for name, seed in FIXTURE_SEEDS.items()]
    return {name: ("fill.qnt", {"recipe": recipe, "seed": seed, "steps": len(recipe) or STEPS}) for name, recipe, seed in plans}


def generate(quint, output):
    """Write the committed traces: one per directed recipe and one per seed of `step`, each naming the model's digest."""
    import hashlib
    import json
    import subprocess
    from pathlib import Path
    from types import SimpleNamespace
    source = Path(__file__).resolve().parent
    digest = hashlib.sha256((source / "fill.qnt").read_bytes()).hexdigest()
    for name, (_, declared) in fixtures().items():
        recipe, seed, steps = declared["recipe"], declared["seed"], declared["steps"]
        case = SimpleNamespace(name=name, mutations=[], extra="", recipe=recipe, settings={"BOUND": str(steps)})
        directory = output / name
        directory.mkdir(parents=True)
        for filename, text in inputs(case, source).items():
            (directory / filename).write_text(text)
        trace = output / (name + ".itf.json")
        subprocess.run([quint, "run", "case.qnt", "--main", "fillCase", "--step", "recipe" if recipe else "step",
                        "--backend", "typescript", "--mbt", "--invariant", "safety", "--seed", seed, "--max-samples", "1",
                        "--max-steps", str(steps), "--n-traces", "1", "--out-itf", str(trace)],
                       cwd=directory, check=True, timeout=60)
        data = json.loads(trace.read_text())
        if len(data["states"]) != steps + 1:
            raise ValueError(f"{name}: the trace stopped before its final action")
        data["#meta"] = {"fill": {**declared, "model_sha256": digest}}
        trace.write_text(json.dumps(data, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser(description=generate.__doc__)
    parser.add_argument("--quint", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    generate(args.quint, args.output.resolve())
