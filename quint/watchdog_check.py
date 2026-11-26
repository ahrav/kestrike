"""Check the finite rearmable-watchdog model: safety, a reachability witness per outcome, directed runs and one mutation per invariant."""

CONSTANTS = {"BOUND": "8"}
WITNESSES = ("witnessArmed", "witnessRefused", "witnessRunning", "witnessExpiredDisarm", "witnessPassed", "witnessIdle",
             "witnessWaiting", "witnessPartial", "witnessContained", "witnessEnded", "witnessSecondEpisode",
             "witnessDisarmWinsRace", "witnessIdlePastDeadline")
RUNS = {
    "watchdog-run-idle-then-full-deadline": (["wake(3)", "rearm", "wake(1)", "wake(1)", "disarm", "rearm"],
                                             "st.expired and st.contained == 1 and witnessRefused and st.waits == 4"),
    "watchdog-run-disarm-then-rearm": (["rearm", "disarm", "wake(3)", "rearm", "pass(3)", "disarm", "wake(0)"],
                                       "not(st.expired) and st.contained == 0 and witnessIdle and st.arms == 2"),
}
MUTANTS = {
    "ContainsAtMostOnce": (["rearm", "wake(2)", "wake(0)"], ("{...s, expired: true, ended: true, contained", "{...s, expired: true, ended: false, contained")),
    "IdleNeverContains": (["wake(3)"], ("else if (s.armed == IDLE) {...s, waits", "else if (s.armed == IDLE and s.now < DEADLINE) {...s, waits")),
    "DeadlineFromOwnArm": (["pass(2)", "rearm", "wake(0)"], ("armed: st.now, armedAt: st.now", "armed: 0, armedAt: st.now")),
    "ExpiredRefusesRearm": (["rearm", "wake(2)", "rearm"], ('st\' = if (st.expired) {...st, ev: event("rearm", "Refused", 0)}', 'st\' = if (false) {...st, ev: event("rearm", "Refused", 0)}')),
    "WorkerOutlivesDisarm": (["rearm", "disarm"], ('armed: IDLE, ev: event("disarm"', 'armed: IDLE, ended: true, ev: event("disarm"')),
}


# The trace length of each mutant whose mutated rule breaks its property before the recipe's last action: the initial
# state and one state per action through the action that breaks it.
KILLS = {
    # A rearm that records the arm at time 0 after the clock passed two ticks runs the worker at once, as every accepted
    # rearm does, and the worker finds that deadline passed and contains in the rearm's own state, before the wake.
    "DeadlineFromOwnArm": MUTANTS["DeadlineFromOwnArm"][0].index("rearm") + 2,
}


def cases(Case):
    yield Case("watchdog-typecheck", command="typecheck", family="watchdog")
    yield Case("watchdog-safety", invariant="safety", family="watchdog")
    for witness in WITNESSES:
        yield Case(f"watchdog-reach-{witness}", invariant="unreached", expected="violation", family="watchdog",
                   extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="watchdog", recipe=recipe, settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="watchdog", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (recipe, mutation) in MUTANTS.items():
        yield Case(f"watchdog-mutant-{name}", invariant=name, expected="violation", family="watchdog", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=[mutation], trace=KILLS.get(name))


def inputs(case, source):
    text = (source / "watchdog.qnt").read_text()
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
    return {"watchdog.qnt": text, "case.qnt": f'module watchdogCase {{\n  import watchdog(BOUND = {bound}).* from "./watchdog"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "watchdog.qnt"]
    return [quint, "verify", "case.qnt", "--main", "watchdogCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])
