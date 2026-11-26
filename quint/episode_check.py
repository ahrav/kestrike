"""Check the finite recovery-episode model: safety, a reachability witness per outcome, directed runs and one mutation per invariant."""

CONSTANTS = {"BOUND": "5", "ARMABLE": "true"}
WITNESSES = ("witnessSent", "witnessUncertainKept", "witnessUncertainUntaken", "witnessPoisoned", "witnessSendClosed",
             "witnessReturned", "witnessIdle", "witnessReclaimClosed", "witnessCleanup", "witnessLost", "witnessRecovered",
             "witnessSecondEpisode", "witnessDown", "witnessDownStale", "witnessLostAfterRestart", "witnessExpiredStop",
             "witnessExpiredStopProvenQuarantine", "witnessExpiredRecheck", "witnessExpiredReset",
             "witnessExpiredReinitialize", "witnessExpiredRestart", "witnessExpiredSecondStop",
             "witnessExpiredLaterEpisode", "witnessHanded", "witnessHandedContained", "witnessSettled", "witnessUnsettled",
             "witnessGone")
# Witnesses only a watchdog that cannot arm reaches.
UNARMED_WITNESSES = ("witnessRefused", "witnessSettledRefused")
RUNS = {
    "episode-run-stalled-reset": (['send("untaken")', 'reclaim(false, "Reset", true, "ok", true)', 'send("no")',
                                   "close(true)"],
                                  'st.link == "Lost" and st.contained and st.requests == 1 and st.released == 1 and '
                                  'st.ep.expiredAt == "Reset" and st.held == 0 and st.gone and st.resets == 1 and '
                                  "st.recoveries == 0"),
    "episode-run-stalled-stop-keeps-quarantine": (['send("no")', 'send("kept")', 'reclaim(true, "Stop", true, "ok", true)',
                                                   "close(true)"],
                                                  'st.link == "Lost" and st.contained and st.quar == "returned" and '
                                                  "st.returned == 0 and st.released == 0 and st.dev == 0 and st.held == 0 "
                                                  "and st.gone"),
    "episode-run-rearms": (['reclaim(true, "none", true, "ok", true)', 'reclaim(true, "Stop2", true, "ok", true)',
                            'reclaim(true, "Stop2", true, "fail", true)'],
                           'st.link == "Lost" and st.resets == 3 and st.recoveries == 2 and st.requests == 1 and '
                           'st.ep.n == 3 and st.ep.expiredAt == "Stop" and st.log.length() == 6'),
}
UNARMED_RUNS = {
    "episode-run-refused": (['send("untaken")', 'reclaim(false, "Stop", true, "ok", true)', 'reclaim(true, "none", true, "ok", true)',
                             "close(true)"],
                            'st.link == "Lost" and st.ep.refused and st.resets == 1 and st.requests == 0 and '
                            "st.released == 1 and st.held == 0 and st.gone"),
}
MUTANTS = {
    "RefusedBeforeAnyStage": (False, ['reclaim(true, "none", true, "ok", true)'],
                              ('link: "Lost", ep: {...IDLE, n: base.resets, refused: true},\n        log: List(),',
                               'link: "Lost", ep: {...IDLE, n: base.resets, refused: true},\n        log: FULL.slice(0, 1),')),
    "NoStageAfterExpiry": (True, ['reclaim(true, "Reset", true, "ok", true)'],
                           ('else if (stall == "Reset") expired(settled, "Reset", FULL.slice(0, 3))',
                            'else if (stall == "Reset") expired(settled, "Reset", FULL.slice(0, 4))')),
    "ExpiryLosesLinkAndContainsOnce": (True, ['reclaim(true, "Restart", true, "ok", true)'],
                                       ('else if (stall == "Restart") expired(settled, "Restart", FULL)',
                                        'else if (stall == "Restart") {...expired(settled, "Restart", FULL), link: "Up"}')),
    "ExpiryKeepsQuarantine-stop": (True, ['send("untaken")', 'reclaim(false, "Stop", true, "ok", true)'],
                                   ('expired(if (proven) returnedOnly(base) else base, "Stop", FULL.slice(0, 1))',
                                    'expired(if (proven) settled else base, "Stop", FULL.slice(0, 1))')),
    "ExpiryKeepsQuarantine-close": (True, ['send("untaken")', 'reclaim(false, "Stop", false, "ok", true)', "close(true)"],
                                    ('else if (st.quar == "none" or st.contained) {...st, gone: true, ev: event("close", "Handed")}',
                                     'else if (st.quar == "none") {...st, gone: true, ev: event("close", "Handed")}')),
    "FaultFreeDisarms": (True, ['reclaim(true, "none", true, "ok", true)'],
                         ('else {...ended(settled, "Up", "Restart", FULL, "Recovered"), recoveries: st.recoveries + 1}',
                          'else {...ended(settled, "Up", "Restart", FULL, "Recovered"), requests: st.requests + 1}')),
}


def cases(Case):
    yield Case("episode-typecheck", command="typecheck", family="episode")
    yield Case("episode-safety", invariant="safety", family="episode")
    yield Case("episode-safety-unarmed", invariant="safety", family="episode", settings={"ARMABLE": "false"})
    for witness in WITNESSES:
        yield Case(f"episode-reach-{witness}", invariant="unreached", expected="violation", family="episode",
                   extra=f"  val unreached = not({witness})\n")
    for witness in UNARMED_WITNESSES:
        yield Case(f"episode-reach-{witness}", invariant="unreached", expected="violation", family="episode",
                   settings={"ARMABLE": "false"}, extra=f"  val unreached = not({witness})\n")
    for armable, runs in (("true", RUNS), ("false", UNARMED_RUNS)):
        for name, (recipe, outcome) in runs.items():
            settings = {"BOUND": str(len(recipe)), "ARMABLE": armable}
            yield Case(name, invariant="runSafety", family="episode", recipe=recipe, settings=settings,
                       extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
            yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="episode", recipe=recipe,
                       settings=settings, extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (armable, recipe, mutation) in MUTANTS.items():
        yield Case(f"episode-mutant-{name}", invariant=name.split("-")[0], expected="violation", family="episode",
                   recipe=recipe, settings={"BOUND": str(len(recipe)), "ARMABLE": "true" if armable else "false"},
                   mutations=[mutation])


def inputs(case, source):
    text = (source / "episode.qnt").read_text()
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
    constants = {**CONSTANTS, **case.settings}
    bindings = ", ".join(f"{name} = {value}" for name, value in constants.items())
    return {"episode.qnt": text, "case.qnt": f'module episodeCase {{\n  import episode({bindings}).* from "./episode"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "episode.qnt"]
    return [quint, "verify", "case.qnt", "--main", "episodeCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])
