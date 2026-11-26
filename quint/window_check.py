"""Check the finite receive-window model: safety, a reachability witness per outcome, directed runs and one mutation per invariant."""

CONSTANTS = {"BOUND": "14"}
WITNESSES = ("witnessGet", "witnessAck", "witnessCancelFrame", "witnessRefused", "witnessNothingDue", "witnessGrantAck",
             "witnessBound", "witnessBoundDropsHeld", "witnessBoundExposesHeld", "witnessStartRepeat", "witnessStartOther",
             "witnessTooLarge", "witnessHeld", "witnessHeldBeforeStart", "witnessGap", "witnessDuplicate",
             "witnessBelowBase", "witnessAtGrant", "witnessOtherManifest", "witnessHeldBack", "witnessComplete",
             "witnessEarlyComplete", "witnessMissing", "witnessPressure", "witnessFailed", "witnessIncomplete",
             "witnessErrorIgnored", "witnessCancelled", "witnessCancelledExposed", "witnessTaken", "witnessTakeNone",
             "witnessTakenAfterComplete", "witnessRelease", "witnessReleaseAfterClose", "witnessClosed",
             "witnessCloseWaitsForCancel", "witnessRetryGet", "witnessRetryAck", "witnessDeadline",
             "witnessDeadlineExposed", "witnessSessionEnd", "witnessSessionEndKeeps")
# The GET goes out and START binds manifest A.
BOUND_A = ["poll(true)", 'start("A")']
RUNS = {
    # Two fragments fill the window, a release raises the grant, the third arrives and COMPLETE ends the request.
    "window-run-complete": (BOUND_A + ['data(0, "A")', 'data(1, "A")', "take", "release(0)", "poll(true)", 'data(2, "A")',
                                       "take", "take", 'complete("A")', "release(1)", "release(2)", "close"],
                            'r.closed and r.outcome == "Complete" and r.handed == 3 and r.granted == 3'),
    # Fragments held before START: the one naming another manifest is dropped, and nothing is handed out early.
    "window-run-heldBeforeStart": (["poll(true)", 'data(1, "A")', 'data(0, "B")', "take", 'start("A")', 'data(0, "A")',
                                    "take", "take"],
                                   "r.handed == 2 and r.base == 2 and not(r.foreign) and r.seenTo == 2"),
    # An ERROR after a fragment was handed out ends the request Incomplete.
    "window-run-incomplete": (BOUND_A + ['data(0, "A")', "take", 'error("Missing")', "close"],
                              'r.closed and r.outcome == "Incomplete" and r.handed == 1'),
    # A cancel returns the fragment not handed out, and close waits for the CANCEL.
    "window-run-cancel": (BOUND_A + ['data(0, "A")', "cancel", "take", "close", "poll(true)", "close"],
                          'r.closed and r.outcome == "Failed" and r.handed == 0'),
    # Frames naming another manifest change nothing once START bound one.
    "window-run-otherManifest": (BOUND_A + ['data(0, "B")', 'start("B")', 'data(0, "A")', 'complete("B")', 'data(1, "A")',
                                            "take", "take", "release(0)", "release(1)", "poll(true)", 'data(2, "A")',
                                            'complete("A")'],
                                 'r.outcome == "Complete" and r.granted == 4 and r.base == 3'),
    # A gap, a retried ACK, and the deadline with its CANCEL.
    "window-run-deadline": (BOUND_A + ['data(1, "A")', "retry", "poll(true)", "deadline", "poll(true)", "close"],
                            'r.closed and r.outcome == "Failed" and r.ev.res == "true"'),
    # A START with no fragment held binds its manifest and drops nothing.
    "window-run-startHoldingNothing": (['start("A")'],
                                       'r.ev.res == "bound" and r.manifest == "A" and not(witnessBoundDropsHeld)'),
}
MUTANTS = {
    "InWindow": (BOUND_A + ['data(2, "A")'],
                 ("val fits = undecided(r) and i >= r.base and i < r.granted and",
                  "val fits = undecided(r) and i >= r.base and i <= r.granted and")),
    "BoundManifest": (['data(0, "B")', 'start("A")'],
                      ("val kept = r.held.keys().filter(i => r.held.get(i) == m)", "val kept = r.held.keys()")),
    "InOrder": (['data(0, "A")', "take"],
                ("if (live(r) and r.handed < r.base and has(r, r.handed))", "if (live(r) and r.handed <= r.base and has(r, r.handed))")),
    "CompleteNeedsAll": (BOUND_A + ['complete("A")'],
                         ("if (live(r) and undecided(r) and r.manifest == m and r.base == N)",
                          "if (live(r) and undecided(r) and r.manifest == m)")),
    "ExposedIsIncomplete": (BOUND_A + ['data(0, "A")', "take", 'error("Failed")'],
                            ('outcome: if (s.handed > 0) "Incomplete" else outcome, cancelDue: cancel,',
                             "outcome: outcome, cancelDue: cancel,")),
}


def cases(Case):
    yield Case("window-typecheck", command="typecheck", family="window")
    yield Case("window-safety", invariant="safety", family="window")
    for witness in WITNESSES:
        yield Case(f"window-reach-{witness}", invariant="unreached", expected="violation", family="window",
                   settings={"BOUND": "14"}, extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="window", recipe=recipe, settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="window", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (recipe, mutation) in MUTANTS.items():
        yield Case(f"window-mutant-{name}", invariant=name, expected="violation", family="window", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=[mutation])


def inputs(case, source):
    text = (source / "window.qnt").read_text()
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
    return {"window.qnt": text, "case.qnt": f'module windowCase {{\n  import window(BOUND = {bound}).* from "./window"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "window.qnt"]
    return [quint, "verify", "case.qnt", "--main", "windowCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])
