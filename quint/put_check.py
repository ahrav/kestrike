"""Check the finite PUT owner model: safety, a reachability witness per outcome, a directed run beside each path witness, directed runs and one mutation per invariant clause."""

CONSTANTS = {"BOUND": "10"}
WITNESSES = ("witnessPublished", "witnessOutOfOrder", "witnessDuplicate", "witnessConflictEnded", "witnessConflictDraining",
             "witnessCancelAtAuthority", "witnessCancelDraining", "witnessDrained", "witnessDeviceErrorDraining",
             "witnessDeviceErrorEnded", "witnessRevokedAtData", "witnessRevokedAtCompletion", "witnessSuccessorBesideOldWrite",
             "witnessLateTerminalAfterSuccessor", "witnessSuccessorFailed")
WITNESSES += ("witnessRevokedBehindBase",)
READY = ["begin", "prepare", "data(0)", "data(1)"]
RUNS = {
    "put-run-published": (READY + ["terminal(1, true)", "terminal(0, true)"], 'witnessPublished and st.stage == "ended"'),
    "put-run-late-write-beside-successor": (
        READY + ["invalidate", "sbegin", "sterminal(true)", "terminal(1, true)", "terminal(0, true)"],
        'witnessLateTerminalAfterSuccessor and st.ev.reply == "Contended" and st.stage == "ended"'),
    "put-run-failed-header": (READY + ["terminal(1, true)", "terminal(0, false)"],
                              "witnessDeviceErrorEnded and st.published == 0"),
}
# BESIDE maps each witness that names a path to a recipe along the path its event alone does not tell from the
# witness's, which keeps the witness false, and the state that run ends in.
BESIDE = {
    "witnessDuplicate": (READY, 'st.ev.act == "data" and st.ev.arg == 1 and st.ev.base == 2 and not(st.repeated) and '
                                'RANGES.forall(w => st.ws.get(w) == "submitted")'),
    "witnessCancelAtAuthority": (["begin", "prepare", "cancel"],
                                 'st.ev.reply == "Cancelled" and st.cancelled == "ready" and st.stage == "ended"'),
}
MUTANTS = {
    "PublishedComplete-missing-range": ("PublishedComplete", READY + ["terminal(0, true)"],
        ('val complete = RANGES.forall(x => ws.get(x) == "written")', 'val complete = ws.get(0) == "written"')),
    "PublishedComplete-revoked-authority": ("PublishedComplete", READY + ["invalidate", "terminal(1, true)", "terminal(0, true)"],
        ('else if (st.revoked) {...st, ws: ws, stage: "ended", ev: event("terminal", w, ok, "Contended", 0)}\n        else {',
         'else {')),
    "PublishedComplete-credits-duplicate": ("PublishedComplete", READY + ["data(0)", "terminal(1, true)", "terminal(0, true)"],
        ('if (st.credit.get(i) > 0) {...st, ev:', 'if (st.credit.get(i) > 0) {...st, credit: st.credit.set(i, 2), ev:')),
    "PublishedClientBytes": ("PublishedClientBytes", READY + ["differ(0)", "terminal(1, true)", "terminal(0, true)"],
        ('st\' = {...st, conflict: true, stage: ending(st.ws), ev: event("differ", i, true, "ConflictingData", 0)}',
         'st\' = {...st, data: st.data.set(i, 2), ev: event("differ", i, true, "ACK", 0)}')),
    "HeaderLast": ("HeaderLast", READY, ("order: List(1, 0), ev", "order: List(0, 1), ev")),
    "WriteCustody": ("WriteCustody", READY + ["cancel"],
        ('st\' = {...st, stage: ending(st.ws), cancelled: st.stage, ev: event("cancel", 0, true, "Cancelled", 0)}',
         'st\' = {...st, stage: "ended", cancelled: st.stage, ev: event("cancel", 0, true, "Cancelled", 0)}')),
    "SuccessorIsolated": ("SuccessorIsolated", READY + ["invalidate", "sbegin"],
        ('st\' = {...st, succ: "writing", ev: event("sbegin", 0, true, "ACK", 1)}',
         'st\' = {...st, succ: "published", published: 2, ev: event("sbegin", 0, true, "ACK", 1)}')),
}


def cases(Case):
    yield Case("put-typecheck", command="typecheck", family="put")
    yield Case("put-safety", invariant="safety", family="put")
    for witness in WITNESSES:
        yield Case(f"put-reach-{witness}", invariant="unreached", expected="violation", family="put",
                   extra=f"  val unreached = not({witness})\n")
    for witness, (recipe, ending) in BESIDE.items():
        yield Case(f"put-beside-{witness}", invariant="beside", family="put", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, depth=len(recipe) + 1,
                   extra=f"  val beside = not({witness}) and (turn == {len(recipe)} implies ({ending}))\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="put", recipe=recipe, settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="put", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (invariant, recipe, mutation) in MUTANTS.items():
        yield Case(f"put-mutant-{name}", invariant=invariant, expected="violation", family="put", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=[mutation])


def inputs(case, source):
    text = (source / "put.qnt").read_text()
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
    return {"put.qnt": text, "case.qnt": f'module putCase {{\n  import put(BOUND = {bound}).* from "./put"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "put.qnt"]
    return [quint, "verify", "case.qnt", "--main", "putCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])


FIXTURES = "crates/kestrike/src/net/put_replay_fixtures"
FIXTURE_RECIPES = {
    "published": READY + ["data(1)", "terminal(1, true)", "terminal(0, true)"],
    "out_of_order": ["begin", "prepare", "data(1)", "data(0)", "terminal(0, true)", "terminal(1, true)"],
    "successor": RUNS["put-run-late-write-beside-successor"][0],
    "failed_header": RUNS["put-run-failed-header"][0],
    "failed_payload": READY + ["terminal(1, false)", "terminal(0, true)"],
    "cancel_draining": READY + ["cancel", "terminal(1, true)", "terminal(0, true)"],
    "cancel_authority": ["begin", "cancel"],
    "conflict_ended": ["begin", "prepare", "data(0)", "differ(0)"],
    "conflict_draining": READY + ["differ(1)", "terminal(0, true)", "terminal(1, false)"],
    "revoked_at_data": ["begin", "prepare", "data(0)", "invalidate", "data(0)", "data(1)", "sbegin", "sterminal(false)"],
    "revoked_failed": READY + ["invalidate", "terminal(1, false)", "terminal(0, true)", "sbegin", "sterminal(true)"],
    "revoked_at_completion": READY + ["terminal(1, true)", "invalidate", "terminal(0, true)"],
    "revoked_behind_base": ["begin", "prepare", "invalidate", "data(1)", "sbegin", "data(1)", "sterminal(true)", "data(0)"],
    "revoked_behind_base_failed": ["begin", "prepare", "data(1)", "invalidate", "sbegin", "sterminal(false)", "data(0)"],
}
# The committed traces of the model's own `step`, each with its seed and the steps its run takes: at most `STEPS`,
# fewer when the upload and its successor end sooner and no action stays enabled.
FIXTURE_SEEDS = {"step_a": ("0x2a08", 5), "step_b": ("0x2a0d", 7), "step_c": ("0x2a11", 4)}
STEPS = 10


def fixtures():
    """Each committed trace: its model and the recipe, seed and step count it records under `#meta.put`."""
    plans = [(name, recipe, "0x2a00", len(recipe)) for name, recipe in FIXTURE_RECIPES.items()] + [
        (name, [], seed, steps) for name, (seed, steps) in FIXTURE_SEEDS.items()]
    return {name: ("put.qnt", {"recipe": recipe, "seed": seed, "steps": steps}) for name, recipe, seed, steps in plans}


def generate(quint, output):
    """Write each declared trace as ITF with the model's digest and its declaration under `#meta.put`."""
    import hashlib
    import json
    import subprocess
    from pathlib import Path
    from types import SimpleNamespace
    source = Path(__file__).resolve().parent
    digest = hashlib.sha256((source / "put.qnt").read_bytes()).hexdigest()
    for name, (_, declared) in fixtures().items():
        recipe, seed = declared["recipe"], declared["seed"]
        steps = len(recipe) or STEPS
        case = SimpleNamespace(name=name, mutations=[], extra="", recipe=recipe, settings={"BOUND": str(steps)})
        directory = output / name
        directory.mkdir(parents=True)
        for filename, text in inputs(case, source).items():
            (directory / filename).write_text(text)
        trace = output / (name + ".itf.json")
        subprocess.run([quint, "run", "case.qnt", "--main", "putCase", "--step", "recipe" if recipe else "step",
                        "--backend", "typescript", "--mbt", "--invariant", "safety", "--seed", seed, "--max-samples", "1",
                        "--max-steps", str(steps), "--n-traces", "1", "--out-itf", str(trace)],
                       cwd=directory, check=True, timeout=60)
        try:
            data = json.loads(trace.read_text())
        except ValueError as error:
            raise ValueError(f"{name}: the trace quint wrote is not JSON: {error}") from error
        if len(data["states"]) != declared["steps"] + 1:
            raise ValueError(f"{name}: the trace holds {len(data['states']) - 1} steps, not the {declared['steps']} declared")
        data["#meta"] = {"put": {**declared, "model_sha256": digest}}
        trace.write_text(json.dumps(data, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser(description=generate.__doc__)
    parser.add_argument("--quint", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    generate(args.quint, args.output.resolve())
