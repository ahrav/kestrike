"""Check the finite visit model: safety, a reachability witness per outcome, directed runs and one mutation per invariant."""

CONSTANTS = {"BOUND": "8"}
WITNESSES = ("witnessPublished", "witnessLeased", "witnessRetired", "witnessRetiredLeased", "witnessCertified",
             "witnessCertifyIdle", "witnessDropped", "witnessRead", "witnessHeldByAnchor", "witnessHeldByRight",
             "witnessNothingRetired", "witnessPartialOfThree", "witnessSecondPartial", "witnessReturned",
             "witnessReturnedDirect")
RUNS = {
    "visit-run-three-extents": (["publish(0, 3, false)", "invalidate(0)", "visit", "certify", "visit", "visit", "visit", "visit"],
                                "st.ev.res == \"Idle\" and st.ret.ver == 0 and st.charge == 0"),
    "visit-run-right-held": (["publish(0, 2, true)", "invalidate(0)", "certify", "visit", "read", "release", "visit", "visit"],
                             "st.ev.res == \"Returned\" and st.charge == 0"),
}
MUTANTS = {
    "OneExtentPerVisit": (["publish(0, 3, false)", "invalidate(0)", "certify", "visit"],
                          ("{...st, ret: {...st.ret, held: st.ret.held - 1}, charge: st.charge - 1,\n          ev: event(\"visit\", \"Partial\", 0, st.ret.n, st.ret.held - 1)}",
                           "{...st, ret: {...st.ret, held: st.ret.held - 2}, charge: st.charge - 2,\n          ev: event(\"visit\", \"Partial\", 0, st.ret.n, st.ret.held - 2)}"), {}),
    "BlockersHold": (["publish(0, 2, true)", "invalidate(0)", "certify", "visit"],
                     ("if (st.ret.ver == 0 or blocked(st.ret))", "if (st.ret.ver == 0 or st.ret.anchor)"), {}),
    "SlotUntilLastExtent": (["publish(0, 1, false)", "invalidate(0)", "certify", "visit"],
                            ("else {...st, ret: GONE, charge: st.charge - 1,", "else {...st, ret: {...st.ret, held: 0}, charge: st.charge - 1,"), {}),
    "ChargeFollowsExtents": (["publish(0, 2, false)", "invalidate(0)", "certify", "visit"],
                             ("held: st.ret.held - 1}, charge: st.charge - 1,", "held: st.ret.held - 1}, charge: st.charge,"), {}),
}


def cases(Case):
    yield Case("visit-typecheck", command="typecheck", family="visit")
    yield Case("visit-safety", invariant="safety", family="visit")
    for witness in WITNESSES:
        yield Case(f"visit-reach-{witness}", invariant="unreached", expected="violation", family="visit",
                   extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="visit", recipe=recipe, settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="visit", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (recipe, mutation, settings) in MUTANTS.items():
        yield Case(f"visit-mutant-{name}", invariant=name, expected="violation", family="visit", recipe=recipe,
                   settings={"BOUND": str(len(recipe)), **settings}, mutations=[mutation])


def inputs(case, source):
    text = (source / "visit.qnt").read_text()
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
    bindings = ", ".join(f"{name} = {value}" for name, value in {**CONSTANTS, **case.settings}.items())
    return {"visit.qnt": text, "case.qnt": f'module visitCase {{\n  import visit({bindings}).* from "./visit"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "visit.qnt"]
    return [quint, "verify", "case.qnt", "--main", "visitCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])


FIXTURES = "crates/kestrike/src/storage/visit_replay_fixtures"
FIXTURE_RECIPES = {
    "three_extents": RUNS["visit-run-three-extents"][0],
    "right_held": RUNS["visit-run-right-held"][0],
    "beside": ["publish(0, 3, true)", "publish(1, 2, false)", "invalidate(0)", "certify", "visit", "read", "publish(0, 1, false)",
               "release", "visit", "visit", "visit", "invalidate(1)", "visit", "certify", "visit", "visit", "visit"],
    "direct": ["visit", "certify", "publish(1, 1, false)", "invalidate(1)", "certify", "visit", "visit", "publish(1, 1, true)",
               "invalidate(1)", "release", "visit", "certify", "visit"],
}
# Seeds of the committed traces of the model's own `step`, sixteen steps each.
FIXTURE_SEEDS = {"step_a": "0x23fd", "step_b": "0x23f5", "step_c": "0x23c5", "step_d": "0x23bd"}
STEPS = 16


def generate(quint, output):
    """Write the committed traces: one per directed recipe and one per seed of `step`, each naming the model's digest."""
    import hashlib
    import json
    import subprocess
    from pathlib import Path
    from types import SimpleNamespace
    source = Path(__file__).resolve().parent
    digest = hashlib.sha256((source / "visit.qnt").read_bytes()).hexdigest()
    plans = [(name, recipe, "0x7100") for name, recipe in FIXTURE_RECIPES.items()] + [
        (name, [], seed) for name, seed in FIXTURE_SEEDS.items()]
    for name, recipe, seed in plans:
        steps = len(recipe) or STEPS
        case = SimpleNamespace(name=name, mutations=[], extra="", recipe=recipe, settings={"BOUND": str(steps)})
        directory = output / name
        directory.mkdir(parents=True)
        for filename, text in inputs(case, source).items():
            (directory / filename).write_text(text)
        trace = output / (name + ".itf.json")
        subprocess.run([quint, "run", "case.qnt", "--main", "visitCase", "--step", "recipe" if recipe else "step",
                        "--backend", "typescript", "--mbt", "--invariant", "safety", "--seed", seed, "--max-samples", "1",
                        "--max-steps", str(steps), "--n-traces", "1", "--out-itf", str(trace)],
                       cwd=directory, check=True, timeout=120)
        data = json.loads(trace.read_text())
        if len(data["states"]) != steps + 1:
            raise ValueError(f"{name}: the trace stopped before its final action")
        data["#meta"] = {"visit": {"recipe": recipe, "seed": seed, "steps": steps, "model_sha256": digest}}
        trace.write_text(json.dumps(data, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser(description=generate.__doc__)
    parser.add_argument("--quint", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    generate(args.quint, args.output.resolve())
