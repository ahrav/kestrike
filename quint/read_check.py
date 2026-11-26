"""Check the finite volume read model: safety, a reachability witness per outcome, directed runs and one mutation per invariant clause."""

CONSTANTS = {"BOUND": "10"}
WITNESSES = ("witnessComplete", "witnessAheadFirst", "witnessKeptIssued", "witnessMerged", "witnessExhausted", "witnessStaleGrant",
             "witnessStaleCancel", "witnessCancelledTwoOut", "witnessDrainedAfterCancel", "witnessCurrentFailed",
             "witnessAheadFailed", "witnessFailedAheadWaits")
TWO = ["admit", "grant"]
RUNS = {
    "read-run-complete": (TWO + ["terminal(1, true)", "grant", "terminal(2, true)", "terminal(3, true)"],
                          "witnessComplete and drained and st.chunks == 3"),
    "read-run-ahead-first": (TWO + ["grant", "terminal(2, true)", "terminal(1, true)", "terminal(3, true)"],
                             "witnessComplete and drained"),
    "read-run-cancel-two-out": (TWO + ["cancel", "terminal(1, true)", "terminal(2, true)"],
                                "witnessDrainedAfterCancel and st.chunks == 0"),
    "read-run-failed-ahead": (TWO + ["terminal(2, false)", "terminal(1, true)"],
                              'witnessAheadFailed and st.ev.handed == List(1) and drained'),
}
MUTANTS = {
    "OneDone-second-done": ("OneDone", TWO + ["cancel", "cancel"],
        ('st\' = if (st.phase == "done") {...st, ev: event("cancel", 0, true, "Stale")}\n      else {...st, phase: "done", dones',
         'st\' = {...st, phase: "done", dones')),
    "OneDone-chunk-after-done": ("OneDone", TWO + ["cancel", "terminal(1, true)"],
        ('    if (s.phase != "reading") s\n    else if (s.done.contains(s.chunks + 1))', '    if (s.done.contains(s.chunks + 1))')),
    "ChunksVerified-ahead-before-current": ("ChunksVerified", TWO + ["terminal(2, true)"],
        ("else if (s.done.contains(s.chunks + 1))", "else if (s.done.contains(s.chunks + 1) or s.done.contains(s.chunks + 2))")),
    "ChunksVerified-failed-command": ("ChunksVerified", ["admit", "terminal(1, false)"],
        ("done: if (ok) st.done.union(Set(k)) else st.done,\n      failed: if (ok) st.failed else st.failed.union(Set(k)),",
         "done: if (ok) st.done.union(Set(k)) else st.done,\n      failed: st.failed, chunks: if (ok) st.chunks else st.chunks + 1,")),
}


def cases(Case):
    yield Case("read-typecheck", command="typecheck", family="read")
    yield Case("read-safety", invariant="safety", family="read")
    for witness in WITNESSES:
        yield Case(f"read-reach-{witness}", invariant="unreached", expected="violation", family="read",
                   extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="read", recipe=recipe, settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="read", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (invariant, recipe, mutation) in MUTANTS.items():
        yield Case(f"read-mutant-{name}", invariant=invariant, expected="violation", family="read", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=[mutation])


def inputs(case, source):
    text = (source / "read.qnt").read_text()
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
    return {"read.qnt": text, "case.qnt": f'module readCase {{\n  import read(BOUND = {bound}).* from "./read"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "read.qnt"]
    return [quint, "verify", "case.qnt", "--main", "readCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])


FIXTURES = "crates/kestrike/src/storage/volume/read_replay_fixtures"
FIXTURE_RECIPES = {
    "complete": RUNS["read-run-complete"][0],
    "ahead_first": TWO + ["grant", "terminal(2, true)", "terminal(1, true)", "grant", "terminal(3, true)"],
    "kept_merged": TWO + ["grant", "grant", "terminal(1, true)", "terminal(2, true)", "grant", "terminal(3, true)", "grant", "cancel"],
    "cancel_two_out": TWO + ["cancel", "terminal(1, true)", "terminal(2, true)", "grant"],
    "cancel_after_chunk": TWO + ["terminal(1, true)", "cancel", "terminal(2, true)"],
    "failed_ahead": RUNS["read-run-failed-ahead"][0],
    "failed_ahead_kept": TWO + ["grant", "terminal(2, false)", "terminal(1, true)"],
    "failed_current": TWO + ["grant", "terminal(1, false)", "terminal(2, true)"],
    "failed_last": TWO + ["terminal(1, true)", "terminal(2, true)", "grant", "terminal(3, false)"],
    "failed_ahead_last": TWO + ["terminal(1, true)", "grant", "terminal(3, false)", "terminal(2, true)"],
    "newest_first_tail": TWO + ["terminal(1, true)", "grant", "terminal(3, true)", "terminal(2, true)"],
    "one_at_a_time": ["admit", "terminal(1, true)", "grant", "terminal(2, true)", "grant", "terminal(3, true)"],
    "failed_first": ["admit", "terminal(1, false)", "grant", "cancel"],
}
# Seeds of the committed traces of the model's own `step`, ten steps each.
FIXTURE_SEEDS = {"step_a": "0x3b01", "step_b": "0x3b08", "step_c": "0x3b09"}
STEPS = 10


def generate(quint, output):
    """Write the committed traces: one per directed recipe and one per seed of `step`, each naming the model's digest."""
    import hashlib
    import json
    import subprocess
    from pathlib import Path
    from types import SimpleNamespace
    source = Path(__file__).resolve().parent
    digest = hashlib.sha256((source / "read.qnt").read_bytes()).hexdigest()
    plans = [(name, recipe, "0x3b00") for name, recipe in FIXTURE_RECIPES.items()] + [
        (name, [], seed) for name, seed in FIXTURE_SEEDS.items()]
    for name, recipe, seed in plans:
        steps = len(recipe) or STEPS
        case = SimpleNamespace(name=name, mutations=[], extra="", recipe=recipe, settings={"BOUND": str(steps)})
        directory = output / name
        directory.mkdir(parents=True)
        for filename, text in inputs(case, source).items():
            (directory / filename).write_text(text)
        trace = output / (name + ".itf.json")
        subprocess.run([quint, "run", "case.qnt", "--main", "readCase", "--step", "recipe" if recipe else "step",
                        "--backend", "typescript", "--mbt", "--invariant", "safety", "--seed", seed, "--max-samples", "1",
                        "--max-steps", str(steps), "--n-traces", "1", "--out-itf", str(trace)],
                       cwd=directory, check=True, timeout=60)
        data = json.loads(trace.read_text())
        if len(data["states"]) != steps + 1:
            raise ValueError(f"{name}: the trace stopped before its final action")
        data["#meta"] = {"read": {"recipe": recipe, "seed": seed, "steps": steps, "model_sha256": digest}}
        trace.write_text(json.dumps(data, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser(description=generate.__doc__)
    parser.add_argument("--quint", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    generate(args.quint, args.output.resolve())
