"""Check the finite request-identity model: safety, a reachability witness per action outcome, directed runs and one mutation per invariant."""

CONSTANTS = {"BOUND": "6"}
WITNESSES = ("witnessAdmitted", "witnessBusy", "witnessStale", "witnessExhausted", "witnessPeerPressure",
             "witnessTablePressure", "witnessEnded", "witnessEndedReplaced", "witnessUnbound", "witnessReleasedBound",
             "witnessReleasedBesideSuccessor", "witnessStaleRelease", "witnessReplaced",
             "witnessDrainingAfterReplacement", "witnessSuccessorBesideUnbound", "witnessReadmittedAfterReplacement",
             "witnessOlder", "witnessFresh", "witnessSame", "witnessWrongOperation", "witnessWrongOperationRow")
RUNS = {
    # An ended identity is refused as stale on its free slot and as busy under its successor, before and after its release.
    "identity-run-successor": (['admit(1, 1, 1, "PUT", 1)', "end(1, 1)", "unbind(1, 1)", "refuse(1, 1, 1)",
                                'admit(1, 1, 2, "GET", 2)', "release(1, 1, 1, 1)", "refuse(1, 1, 1)"],
                               'st.ev.res == "Busy" and st.admits.get((1, 1, 1, 1)) == 1 and '
                               "st.wire.get((1, 1)).active == 2 and st.tgen.get(1) == 2"),
    # A replaced session's request drains under its binding, and the new session admits the same generation once.
    "identity-run-replacement": (['admit(1, 1, 1, "GET", 1)', "replace(1)", "refuse(1, 1, 1)", "end(1, 1)",
                                  "release(1, 1, 1, 1)", 'admit(1, 1, 1, "GET", 1)', "end(1, 1)", "release(1, 1, 1, 1)"],
                                 'st.ev.res == "StaleRelease" and st.admits.get((1, 1, 1, 1)) == 1 and '
                                 "st.admits.get((2, 1, 1, 1)) == 1 and st.wire.get((1, 1)).active == 1"),
}
# Each invariant, a schedule that reaches its violation in the mutated copy, and the one replacement of the model's text.
MUTANTS = {
    "OneAdmission": (['admit(1, 1, 1, "GET", 1)', "end(1, 1)", "release(1, 1, 1, 1)", 'admit(1, 1, 1, "GET", 1)'],
                     ('else if (g <= w.mark) "Stale"\n', "")),
    "OneBindingPerHandle": (['admit(1, 1, 1, "GET", 1)', 'admit(1, 1, 2, "GET", 2)'],
                            ('if (w.active != 0) "Busy"\n    else if (g <= w.mark)', "if (g <= w.mark)")),
    "ExactBinding": (['admit(1, 1, 1, "GET", 1)', "end(1, 1)", "release(1, 2, 1, 1)"],
                     ("tick, w.active == h or (rec.unbound and rec.peer == p), rec.ended,", "tick, rec.ended,")),
    "Capacity": (['admit(1, 1, 1, "GET", 1)', "end(1, 1)", "unbind(1, 1)", 'admit(1, 1, 2, "GET", 2)',
                  'admit(1, 2, 1, "GET", 3)'],
                 ('else if (held(p).size() >= SHARE) "PeerPressure"\n', "")),
    "ExactRelease": (['admit(1, 1, 1, "GET", 1)', "end(1, 1)", "release(1, 1, 1, 1)", 'admit(1, 1, 2, "GET", 1)',
                      "end(1, 1)", "release(1, 1, 1, 1)"],
                     ("val exact = tg == st.tgen.get(h)", "val exact = true")),
}


def cases(Case):
    yield Case("identity-typecheck", command="typecheck", family="identity")
    yield Case("identity-safety", invariant="safety", family="identity")
    for witness in WITNESSES:
        # A stale release names a handle's earlier table generation, which takes six calls to exist.
        yield Case(f"identity-reach-{witness}", invariant="unreached", expected="violation", family="identity",
                   settings={"BOUND": "6" if witness == "witnessStaleRelease" else "5"},
                   extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="identity", recipe=recipe, settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="identity", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (recipe, mutation) in MUTANTS.items():
        yield Case(f"identity-mutant-{name}", invariant=name, expected="violation", family="identity", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=[mutation])


def inputs(case, source):
    text = (source / "identity.qnt").read_text()
    for old, new in case.mutations:
        if text.count(old) != 1:
            raise ValueError(f"{case.name}: mutation target is not unique")
        text = text.replace(old, new)
    extra = case.extra
    if case.recipe:
        extra += "  action recipe = any {\n" + "".join(
            f"    all {{ turn == {at}, {action} }},\n" for at, action in enumerate(case.recipe)) + "  }\n"
    bound = case.settings.get("BOUND", CONSTANTS["BOUND"])
    return {"identity.qnt": text,
            "case.qnt": f'module identityCase {{\n  import identity(BOUND = {bound}).* from "./identity"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "identity.qnt"]
    return [quint, "verify", "case.qnt", "--main", "identityCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])
