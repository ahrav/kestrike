"""Check the finite transmit-custody model: safety, a reachability witness per outcome, directed runs and the mutations of each invariant."""

CONSTANTS = {"BOUND": "5"}
WITNESSES = ("witnessSent", "witnessRingFull", "witnessExhausted", "witnessUncertainKept", "witnessUncertainUnkept",
             "witnessUncertainFreed", "witnessPoisoned", "witnessClosed", "witnessReturned", "witnessReturnedQuarantined",
             "witnessIdle", "witnessQuiet", "witnessUnproven", "witnessRecovered", "witnessRecoveredReleased",
             "witnessRecoveredReturned", "witnessDown", "witnessLostAfterRestart", "witnessKept", "witnessCloseUnproven",
             "witnessSettled", "witnessSettledAfterLost", "witnessRested")
RECOVER = "reclaim(false, true, true, true, true)"
UNPROVEN = "reclaim(true, false, true, true, true)"
RUNS = {
    "custody-run-kept-returns-at-the-stop": (
        ['send(3, 1, "kept")', 'send(1, 1, "none")', RECOVER, 'send(1, 1, "none")'],
        'st.ev.res == "Sent" and st.returned == 1 and st.released == 0 and st.dev == Set(3) and st.pool == Set(3)'),
    "custody-run-unkept-releases-locally": (
        ['send(2, 0, "unkept")', RECOVER, "close(true)"],
        'st.ev.res == "Kept" and st.released == 1 and st.local == Set(0) and st.pool == Set() and st.stops == 1'),
    "custody-run-unproven-stop-holds": (
        ['send(2, 2, "none")', UNPROVEN, 'send(1, 1, "none")', "close(true)", "devReturn"],
        'st.link == "Lost" and st.dev == Set(1) and st.pool == Set(1) and st.stops == 1'),
    "custody-run-lost-quarantine-settles-at-close": (
        ['send(2, 1, "kept")', UNPROVEN, "close(true)", "rest"],
        'st.link == "Lost" and st.dev == Set() and st.pool == Set() and st.returned == 1 and st.stops == 2'),
    "custody-run-failed-restart": (
        ['send(1, 1, "none")', "reclaim(true, true, true, false, true)", "reclaim(true, true, true, true, true)"],
        'st.ev.res == "Idle" and st.link == "Down" and st.pool == Set() and st.stops == 2 and st.restarts == 1'),
}
MUTANTS = {
    "DeviceHeldStaysCharged": (['send(2, 1, "kept")'],
                               ('val heldU = if (uncertain and fault != "freed")', 'val heldU = if (uncertain and fault == "unkept")')),
    "ExitsOnlyByPortReturn": (['send(1, 0, "kept")', RECOVER],
                              ("val unkept = s.q != NONE and pool.contains(s.q)", "val unkept = s.q != NONE")),
    "FailedRestartReturnsEvery": (['send(2, 2, "none")', "reclaim(true, true, true, false, true)"],
                                  ("    {...s, dev: Set(), pool: if (unkept)", "    {...s, pool: if (unkept)")),
    "UnprovenStopKeepsHeld": (['send(1, 1, "none")', UNPROVEN],
                              ('{...episode, link: "Lost", stops: st.stops + 1,',
                               '{...episode, link: "Lost", dev: Set(), pool: st.pool.exclude(st.dev), stops: st.stops + 1,')),
}


def cases(Case):
    yield Case("custody-typecheck", command="typecheck", family="custody")
    yield Case("custody-safety", invariant="safety", family="custody")
    for witness in WITNESSES:
        yield Case(f"custody-reach-{witness}", invariant="unreached", expected="violation", family="custody",
                   extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="custody", recipe=recipe, settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="custody", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (recipe, mutation) in MUTANTS.items():
        yield Case(f"custody-mutant-{name}", invariant=name, expected="violation", family="custody", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=[mutation])
    # The second clause of `FailedRestartReturnsEvery`: a proven stop that empties the device and leaves its chains
    # off the free stack.
    recipe = MUTANTS["FailedRestartReturnsEvery"][0]
    yield Case("custody-mutant-FailedRestartReturnsEvery-charged", invariant="FailedRestartReturnsEvery",
               expected="violation", family="custody", recipe=recipe, settings={"BOUND": str(len(recipe))},
               mutations=[("    val pool = s.pool.exclude(s.dev)\n", "    val pool = s.pool\n")])


def inputs(case, source):
    text = (source / "custody.qnt").read_text()
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
    return {"custody.qnt": text, "case.qnt": f'module custodyCase {{\n  import custody(BOUND = {bound}).* from "./custody"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "custody.qnt"]
    return [quint, "verify", "case.qnt", "--main", "custodyCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])
