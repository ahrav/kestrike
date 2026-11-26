"""Check the finite parked-table model: safety, a reachability witness per outcome, directed runs and one mutation per invariant."""

CONSTANTS = {"BOUND": "12"}
WITNESSES = ("witnessPlaced", "witnessFollowed", "witnessUntracked", "witnessTaken", "witnessPlaceFreed", "witnessOwed",
             "witnessOweEmpty", "witnessOweAll", "witnessDepartedFollowers", "witnessDepartedAll", "witnessDepartedNone",
             "witnessOweFillFollowers", "witnessOweFillAll", "witnessPending", "witnessElapsed", "witnessCheckStarts",
             "witnessCheckOwesAll", "witnessAdmissionChanged", "witnessHalfShare", "witnessChecked", "witnessCheckContinues",
             "witnessVisited", "witnessVisitWraps", "witnessAllowanceSpent", "witnessIdlePass", "witnessPassEnds")
# One whole pass with no check: its checks phase, then its visits.
PASS = ["beginPass(true)", "beginVisits"]
RUNS = {
    # Four joins are owed four visits; a pass makes three and the next pass the fourth, and each visited entry leaves.
    "parked-run-allowance": (["park(0, 0)", "park(1, 1)", "park(2, 2)", "park(3, 3)"] + PASS + ["visit", "take(0)", "visit",
                              "take(1)", "visit", "take(2)", "visit", "endPass"] + PASS + ["visit", "take(3)", "endPass"],
                             "parkedSlots(t) == Set() and t.due == Set() and t.cursor == 4 and t.visits == 1"),
    # With every fill tracked, a departure owes a visit to its own followers alone.
    "parked-run-departure": (["park(0, 0)", "park(2, 1)", "park(3, 1)"] + PASS + ["visit", "visit", "visit", "endPass",
                              "departed(1)"],
                             't.ev.res == "followers" and t.due == Set(2, 3)'),
    # A due check observes the watched fills within its share of the allowance, before the owed visits.
    "parked-run-check": (["park(1, 1)", "park(3, 3)", "park(2, 2)", "beginPass(true)", "check", "notePending(1)", "check",
                          "oweFillOf(3)", "beginVisits", "visit", "visit", "endPass", "beginPass(true)", "check",
                          "beginVisits", "visit", "visit", "endPass"],
                         't.due == Set() and t.checking == Set() and not(t.elapsed) and t.ev.act == "endPass"'),
    # The fifth distinct fill finds no tracking place: its entry is untracked, and a due check owes every entry.
    "parked-run-untracked": (["park(0, 0)", "park(1, 1)", "park(2, 2)", "park(3, 3)", "park(4, 4)"] + PASS +
                             ["visit", "visit", "visit", "endPass"] + PASS + ["visit", "visit", "endPass", "elapse",
                                                                             "beginPass(true)"],
                             "t.due == parkedSlots(t) and t.checking == Set() and untracked(t) == Set(4)"),
    # A changed read admission owes every entry a visit, and the cursor wraps to reach them.
    "parked-run-admission": (["park(0, 0)", "park(2, 2)"] + PASS + ["visit", "visit", "endPass", "beginPass(false)",
                                                                    "beginVisits", "visit", "visit", "endPass"],
                             "t.due == Set() and t.cursor == 3 and not(t.admits)"),
    # A pass stops at the one entry owed at its start: an entry owed again waits with the allowance of three unspent.
    "parked-run-owedAtStart": (["park(0, 0)"] + PASS + ["visit", "owe(0)", "visit"],
                               't.ev.res == "none" and t.due == Set(0) and t.visits == 1 and not(witnessAllowanceSpent)'),
}
MUTANTS = {
    "WithinWake": (["park(0, 0)", "park(2, 2)", "park(4, 4)", "park(1, 0)"] + PASS + ["visit", "visit", "visit", "visit"],
                   ("pass: if (WAKE < limit) WAKE else limit,", "pass: limit,")),
    "OncePerPass": (["park(0, 0)", "park(2, 2)"] + PASS + ["visit", "owe(0)", "visit", "visit"],
                    ("val limit = t.visits + t.due.size()", "val limit = WAKE")),
    "OwedIsParked": (["park(0, 0)", "park(2, 2)"] + PASS + ["visit", "owe(0)", "take(0)"],
                     ("places: t.places.set(slot, -1), due: t.due.exclude(Set(slot)),", "places: t.places.set(slot, -1),")),
    "DepartureOwesFollowers": (["park(0, 0)", "park(1, 1)", "park(2, 2)", "park(3, 3)", "park(4, 4)"] + PASS +
                               ["visit", "visit", "visit", "endPass"] + PASS + ["visit", "visit", "endPass", "departed(0)"],
                               ('      t\' = if (untracked(t) != Set()) {...owedAll(t), ev: event("departed", "all", fill)}\n'
                                "        else if (k != Set())", "      t' = if (k != Set())")),
    "OnlyOwedVisited": (["park(0, 0)", "park(2, 2)"] + PASS + ["visit", "visit", "endPass", "owe(2)"] + PASS + ["visit"],
                        ("val slot = if (ahead != Set()) lowest(ahead) else lowest(t.due)", "val slot = lowest(parkedSlots(t))")),
}


# The trace length of each mutant whose mutated rule breaks its property before the recipe's last action: the initial
# state and one state per action through the action that breaks it.
KILLS = {
    # A visit that takes the lowest parked slot takes slot 0 again at the first pass's second visit, after the first
    # visit took slot 0 off the owed set, so the first pass visits an entry no one owes before it reaches slot 2, ahead
    # of the recipe's `endPass`, `owe(2)` and second pass.
    "OnlyOwedVisited": MUTANTS["OnlyOwedVisited"][0].index("visit", MUTANTS["OnlyOwedVisited"][0].index("visit") + 1) + 2,
}


def cases(Case):
    yield Case("parked-typecheck", command="typecheck", family="parked")
    yield Case("parked-safety", invariant="safety", family="parked")
    for witness in WITNESSES:
        yield Case(f"parked-reach-{witness}", invariant="unreached", expected="violation", family="parked",
                   settings={"BOUND": "12"}, extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="parked", recipe=recipe, settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="parked", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (recipe, mutation) in MUTANTS.items():
        yield Case(f"parked-mutant-{name}", invariant=name, expected="violation", family="parked", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=[mutation], trace=KILLS.get(name))


def inputs(case, source):
    text = (source / "parked.qnt").read_text()
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
    return {"parked.qnt": text, "case.qnt": f'module parkedCase {{\n  import parked(BOUND = {bound}).* from "./parked"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "parked.qnt"]
    return [quint, "verify", "case.qnt", "--main", "parkedCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])
