"""Check the finite settle-rule model: safety, a reachability witness per action outcome, directed runs and one mutation per invariant."""

CONSTANTS = {"BOUND": "8"}
WITNESSES = ("witnessAdmitted", "witnessBusy", "witnessStale", "witnessStaleAfterRefusal", "witnessExhausted",
             "witnessPressure", "witnessSettled", "witnessSettledKept", "witnessRefused", "witnessIgnored",
             "witnessIgnoredBelowRefusal", "witnessEnded", "witnessEndedReplaced", "witnessUnbound",
             "witnessUnboundRaised", "witnessReleased", "witnessReleasedRaised", "witnessReplaced",
             "witnessReplacedRefusal", "witnessOlder", "witnessFresh", "witnessSame")
RUNS = {
    # Generations refused in either order while a request holds the binding are stale once it unbinds.
    "settle-run-refused-order": (["admit(1, 1)", "settle(3, false)", "settle(2, false)", "refuse(3)", "end", "unbind",
                                  "refuse(3)", "refuse(2)"],
                                 'st.ev.res == "Stale" and st.mark == 3 and st.refused == 0 and not(st.row)'),
    # A generation settled on a free slot keeps its row and refuses its own admission; the next generation admits.
    "settle-run-free-slot": (["settle(2, true)", "refuse(2)", "refuse(1)", "route(2)", "admit(3, 1)", "settle(2, true)",
                              "end", "release(1)"],
                             'st.ev.res == "Released" and st.mark == 3 and st.row and st.answered.size() == 2'),
    "settle-run-rowless-settle": (["settle(2, false)", "refuse(2)"],
                                  'st.ev.res == "Stale" and st.mark == 2 and not(st.row) and not(witnessStaleAfterRefusal)'),
    # The recipes of the committed replay traces `pressure` and `replaced` (settle_fixtures.py), each as a checked run.
    # Two draining records fill the table, the limit refuses and settles nothing, and both release unbound.
    "settle-run-pressure": (["admit(1, 1)", "end", "unbind", "admit(2, 2)", "end", "unbind", "refuse(3)", "refuse(4)",
                             "settle(4, false)", "route(1)", "release(1)", "release(2)"],
                            'st.ev.res == "Released" and st.mark == 2 and st.active == 0 and st.answered.size() == 2 and '
                            "st.table.get(1) == FREE and st.table.get(2) == FREE"),
    # A refusal recorded before a replacement is forgotten with the session; one recorded after it is raised by the
    # old request's release, and the next request's unbind raises its own.
    "settle-run-replaced": (["admit(2, 1)", "settle(3, true)", "replace", "settle(1, false)", "end", "release(1)",
                             "refuse(1)", "admit(2, 1)", "settle(3, true)", "end", "unbind", "route(3)"],
                            'st.ev.res == "Same" and st.epoch == 2 and st.mark == 3 and st.refused == 0 and '
                            "st.active == 0 and not(st.row) and st.answered.size() == 5"),
}
# Each invariant, a schedule that reaches its violation in the mutated copy, and the one replacement of the model's text.
MUTANTS = {
    "AnsweredOnce": (["settle(2, false)", "admit(2, 1)"], ('    else if (g <= st.mark) "Stale"\n', "")),
    "WatermarkCoversAnswered": (["admit(1, 1)", "settle(3, false)", "settle(2, false)"],
                                ("val known = g <= st.mark or (st.active != 0 and g <= st.refused) or g == LIMIT",
                                 "val known = g <= st.mark or g == LIMIT")),
    "RefusedOnlyWhileBound": (["admit(1, 1)", "settle(3, false)", "end", "release(1)"],
                              ("{...s, active: 0, mark: s.refused, row: false, refused: 0, raised: true}",
                               "{...s, active: 0, mark: s.refused, row: false, raised: true}")),
}


def cases(Case):
    yield Case("settle-typecheck", command="typecheck", family="settle")
    yield Case("settle-safety", invariant="safety", family="settle")
    for witness in WITNESSES:
        yield Case(f"settle-reach-{witness}", invariant="unreached", expected="violation", family="settle",
                   extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="settle", recipe=recipe, settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="settle", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (recipe, mutation) in MUTANTS.items():
        yield Case(f"settle-mutant-{name}", invariant=name, expected="violation", family="settle", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=[mutation])


def inputs(case, source):
    text = (source / "settle.qnt").read_text()
    for old, new in case.mutations:
        if text.count(old) != 1:
            raise ValueError(f"{case.name}: mutation target is not unique")
        text = text.replace(old, new)
    extra = case.extra
    if case.recipe:
        extra += "  action recipe = any {\n" + "".join(
            f"    all {{ turn == {at}, {action} }},\n" for at, action in enumerate(case.recipe)) + "  }\n"
    bound = case.settings.get("BOUND", CONSTANTS["BOUND"])
    return {"settle.qnt": text,
            "case.qnt": f'module settleCase {{\n  import settle(BOUND = {bound}).* from "./settle"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "settle.qnt"]
    return [quint, "verify", "case.qnt", "--main", "settleCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])
