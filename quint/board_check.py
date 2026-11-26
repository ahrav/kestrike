"""Check the finite release-board model: safety, a reachability witness per action outcome, directed runs and the two lease mutations."""

CONSTANTS = {"BOUND": "12"}
WITNESSES = ("witnessAdmitted", "witnessGenerations", "witnessHanded", "witnessCredited", "witnessFreed",
             "witnessFreedEarlierCore", "witnessFreedBesideOpen", "witnessClosed", "witnessClosedHolding",
             "witnessAttached", "witnessAttachedClosing", "witnessOrphans")
RUNS = {
    # A lease outlives its request and its handle's next request: its return frees the orphan and credits nothing.
    "board-run-later-generation": (["admit(1)", "hand(1)", "close(1)", "admit(1)", "hand(1)", "giveBackStale(1)",
                                    "giveBack(1)", "close(1)"],
                                   'st.orphans == 0 and st.ev.res == "Closed" and st.leases.get(1).live == 3'),
    # A lease outlives its core: the successor's request on the same handle and generation is not credited.
    "board-run-later-core": (["admit(1)", "hand(1)", "hand(1)", "attach", "admit(1)", "giveBackStale(1)", "hand(1)",
                              "giveBackStale(1)", "close(1)", "giveBackStale(1)"],
                             'st.orphans == 0 and st.ev.res == "Freed" and st.core == 2 and st.next == 3'),
}
# Each mutation, a schedule that reaches its violation in the mutated copy, and the one replacement of the model's text.
CREDITS = "val credits = l.open and l.score == st.core and l.sgen == l.gen"
MUTANTS = {
    "lease-without-core": (["admit(1)", "hand(1)", "attach", "admit(1)", "giveBackStale(1)"],
                           (CREDITS, "val credits = l.open and l.sgen == l.gen")),
    "lease-without-generation": (["admit(1)", "hand(1)", "close(1)", "admit(1)", "giveBackStale(1)"],
                                 (CREDITS, "val credits = l.open and l.score == st.core")),
}


def cases(Case):
    yield Case("board-typecheck", command="typecheck", family="board")
    yield Case("board-safety", invariant="safety", family="board")
    for witness in WITNESSES:
        yield Case(f"board-reach-{witness}", invariant="unreached", expected="violation", family="board",
                   extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="board", recipe=recipe, settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="board", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (recipe, mutation) in MUTANTS.items():
        yield Case(f"board-mutant-{name}", invariant="OrphanConservation", expected="violation", family="board",
                   recipe=recipe, settings={"BOUND": str(len(recipe))}, mutations=[mutation])


def inputs(case, source):
    text = (source / "board.qnt").read_text()
    for old, new in case.mutations:
        if text.count(old) != 1:
            raise ValueError(f"{case.name}: mutation target is not unique")
        text = text.replace(old, new)
    extra = case.extra
    if case.recipe:
        extra += "  action recipe = any {\n" + "".join(
            f"    all {{ turn == {at}, {action} }},\n" for at, action in enumerate(case.recipe)) + "  }\n"
    bound = case.settings.get("BOUND", CONSTANTS["BOUND"])
    return {"board.qnt": text,
            "case.qnt": f'module boardCase {{\n  import board(BOUND = {bound}).* from "./board"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "board.qnt"]
    return [quint, "verify", "case.qnt", "--main", "boardCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])
