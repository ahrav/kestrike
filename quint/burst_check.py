"""Check the finite burst custody model: safety, a reachability witness per outcome, directed runs and one mutation per invariant."""

CONSTANTS = {"BOUND": "6"}
WITNESSES = ("witnessSent", "witnessRingFull", "witnessUncertainKept", "witnessUncertainUntaken", "witnessUncertainFreed",
             "witnessPoisoned", "witnessSendClosed", "witnessReturned", "witnessReturnedQuarantine", "witnessIdle",
             "witnessReclaimClosed", "witnessCleanup", "witnessLost", "witnessLostHolding", "witnessRecovered",
             "witnessRecoveredReleased", "witnessRecoveredReturned", "witnessDown", "witnessLostAfterRestart", "witnessHanded",
             "witnessSettled", "witnessSettledLost", "witnessUnsettled", "witnessGone")
RUNS = {
    "burst-run-uncertain-settles": (['send(2, 1, "untaken")', 'send(1, 1, "no")', 'reclaim(false, true, "ok", true)',
                                     'send(1, 1, "no")', "complete"],
                                    'st.link == "Up" and st.held == 0 and st.dev == 0 and st.quar == "none" and '
                                    "st.released == 1 and st.returned == 0 and st.recoveries == 1 and st.sent == 2"),
    "burst-run-unproven-holds": (['send(2, 2, "no")', 'send(2, 1, "kept")', 'reclaim(true, false, "ok", true)',
                                  'reclaim(true, true, "ok", true)', "complete", "close(true)"],
                                 'st.link == "Lost" and st.held == 0 and st.dev == 0 and st.gone and st.returned == 1 and '
                                 "st.released == 0 and st.resets == 1 and st.recoveries == 0"),
}
MUTANTS = {
    "HeldUntilProvenStop": (['send(2, 1, "kept")'],
                            ('val charged = if (uncertain and unc != "freed") 1 else 0', "val charged = 0")),
    "UncertainPoisons": (['send(2, 1, "untaken")', 'send(1, 1, "no")'],
                         ('      else if (st.quar != "none") {...st, ev: event("send", "Poisoned", 0)}\n', "")),
    "UnprovenStopKeepsHeld": (['send(2, 1, "untaken")', 'reclaim(false, false, "ok", true)'],
                              ('else if (not(proven)) {...st, resets: st.resets + 1, link: "Lost",',
                               'else if (not(proven)) {...settled, link: "Lost",')),
}


def cases(Case):
    yield Case("burst-typecheck", command="typecheck", family="burst")
    yield Case("burst-safety", invariant="safety", family="burst")
    for witness in WITNESSES:
        yield Case(f"burst-reach-{witness}", invariant="unreached", expected="violation", family="burst",
                   extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="burst", recipe=recipe, settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="burst", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (recipe, mutation) in MUTANTS.items():
        yield Case(f"burst-mutant-{name}", invariant=name, expected="violation", family="burst", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=[mutation])


def inputs(case, source):
    text = (source / "burst.qnt").read_text()
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
    return {"burst.qnt": text, "case.qnt": f'module burstCase {{\n  import burst(BOUND = {bound}).* from "./burst"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "burst.qnt"]
    return [quint, "verify", "case.qnt", "--main", "burstCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])
