"""Check the finite watermark-client model: safety, each invariant, a reachability witness per step choice and outcome, directed runs and one mutation per invariant."""

CONSTANTS = {"BOUND": "9"}
INVARIANTS = ("NoAdoptionBelowMark", "RefusalWithdraws", "WithdrawnIsSilent", "MarkIsDurable")
WITNESSES = ("witnessRead", "witnessStaleAdmitted", "witnessStaleRegression", "witnessUnavailable", "witnessBumped",
             "witnessRefused", "witnessLostAcknowledged", "witnessLostRegression", "witnessLostThenRead",
             "witnessDoubleWinRegression", "witnessDoubleWinCommitted", "witnessUnknownCommitted",
             "witnessUnknownUncommitted", "witnessOther", "witnessOtherKeeps", "witnessOtherFlips",
             "witnessReusedVersion", "witnessLowerVersion", "witnessLowerValue", "witnessLog",
             "witnessWithdrawn", "witnessRestartKeepsMark", "witnessRestartAboveStore", "witnessLogBreak",
             "witnessLogMend")
RUNS = {
    # A restarted process enforces the mark its predecessor recorded: a read that misses the last commit regresses.
    "watermark-run-restart-keeps-the-mark": (["readPass", "bumpPass", "restart", "readStale", "readPass"],
                                             'ev.res == "Withdrawn" and withdrawn and mark == {ver: 2, e: 1}'),
    # A lost write leaves the mark above the store: the next read regresses, and so does the read of the next
    # process, which starts from the log.
    "watermark-run-lost-write": (["readPass", "bumpLost", "readPass", "restart", "readPass"],
                                 'ev.res == "Regression" and withdrawn and hist.length() == 1 and logMark.ver == 2'),
    # A doubly won write commits over another writer's value at a version the client did not expect.
    "watermark-run-double-win": (["readPass", "other", "bumpDoubleWin", "bumpPass"],
                                 'ev.res == "Withdrawn" and hist.length() == 3 and late == 0'),
    # After a lost write another writer's flip commits at the version the client was acknowledged, with a higher
    # value: the read regresses on the reused version alone.
    "watermark-run-reused-version": (["readPass", "bumpLost", "otherFlips", "readPass"],
                                     'ev.res == "Regression" and hist.length() == 2 and mark == {ver: 2, e: 1}'),
    # A read that misses a commit which kept the value regresses on the version alone.
    "watermark-run-lower-version": (["otherKeeps", "readPass", "readStale", "readPass"],
                                    'ev.res == "Withdrawn" and mark == {ver: 2, e: 0} and late == 0'),
    # A failed record of the raised mark withdraws the client with the write committed and the log unchanged.
    "watermark-run-log-failure": (["readPass", "logBreak", "bumpPass", "readPass", "logMend", "restart", "readPass"],
                                  'ev.res == "Ok" and mark == {ver: 2, e: 1} and logMark == mark'),
    # A bump whose reply is lost behind another writer's commit appends nothing: the record is above the held version
    # by that writer's value alone, and the trace does not meet the committed-timeout witness.
    "watermark-run-timeout-after-other": (["readPass", "other", "bumpTimeoutCommit"],
                                          'ev.res == "Unknown" and hist.length() == 2 and held.ver == 1 and late == 0 '
                                          'and not(witnessUnknownCommitted)'),
}
# Each mutation, the invariant it breaks, and the one replacement of the model's text.
MUTANTS = {
    "observe-accepts-any-result": ("NoAdoptionBelowMark", ("val regresses = below(r, mark)", "val regresses = false")),
    "observe-ignores-version": ("NoAdoptionBelowMark", ("r.ver < m.ver or r.e < m.e or reused", "r.e < m.e or reused")),
    "observe-ignores-value": ("NoAdoptionBelowMark", ("r.ver < m.ver or r.e < m.e or reused", "r.ver < m.ver or reused")),
    "observe-ignores-reuse": ("NoAdoptionBelowMark", ("val reused = r.ver == m.ver and r.e != m.e", "val reused = false")),
    "refusal-keeps-serving": ("RefusalWithdraws", ("val withdraws = refused", "val withdraws = false")),
    "withdrawn-issues-request": ("WithdrawnIsSilent",
                                 ('if (withdrawn) refuseWithdrawn("readPass") else all { take("readPass", current), unchangedStore }',
                                  'all { take("readPass", current), unchangedStore }')),
    "raise-without-record": ("MarkIsDurable", ("logMark' = if (raised and logged) r else logMark,", "logMark' = logMark,")),
    "restart-from-empty-mark": ("MarkIsDurable", ("mark' = logMark, withdrawn' = false, held' = NONE,",
                                                  "mark' = NONE, withdrawn' = false, held' = NONE,")),
}


def cases(Case):
    yield Case("watermark-typecheck", command="typecheck", family="watermark")
    yield Case("watermark-safety", invariant="safety", family="watermark")
    for name in INVARIANTS:
        yield Case(f"watermark-{name}", invariant=name, family="watermark")
    for witness in WITNESSES:
        yield Case(f"watermark-reach-{witness}", invariant="unreached", expected="violation", family="watermark",
                   extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="watermark", recipe=recipe,
                   settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="watermark", recipe=recipe,
                   settings={"BOUND": str(len(recipe))},
                   extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (invariant, mutation) in MUTANTS.items():
        yield Case(f"watermark-mutant-{name}", invariant=invariant, expected="violation", family="watermark",
                   mutations=[mutation])
    # The conjunction `safety` and a directed run's `runSafety` each reject a mutation themselves.
    yield Case("watermark-mutant-safety-observe-accepts-any-result", invariant="safety", expected="violation",
               family="watermark", mutations=[MUTANTS["observe-accepts-any-result"][1]])
    # The committed-timeout witness holds only where the bump commits: with a timeout that never commits, no state
    # meets it.
    yield Case("watermark-uncommitted-timeout-is-unwitnessed", invariant="unreached", family="watermark",
               mutations=[('bump("bumpTimeoutCommit", hist.length() == held.ver, false)',
                           'bump("bumpTimeoutCommit", false, false)')],
               extra="  val unreached = not(witnessUnknownCommitted)\n")
    recipe = RUNS["watermark-run-restart-keeps-the-mark"][0]
    # A restart that starts from the empty mark leaves `mark` unequal to the logged mark, so `MarkIsDurable`, a conjunct of
    # `safety`, fails in the restart's own state, before the reads after it.
    yield Case("watermark-run-restart-keeps-the-mark-from-empty-mark", invariant="runSafety", expected="violation",
               family="watermark", recipe=recipe, settings={"BOUND": str(len(recipe))},
               mutations=[MUTANTS["restart-from-empty-mark"][1]], trace=recipe.index("restart") + 2,
               extra=f"  val runSafety = safety and (turn == {len(recipe)} implies true)\n")


def inputs(case, source):
    text = (source / "watermark.qnt").read_text()
    for old, new in case.mutations:
        if text.count(old) != 1:
            raise ValueError(f"{case.name}: mutation target is not unique")
        text = text.replace(old, new)
    extra = case.extra
    if case.recipe:
        extra += "  action recipe = any {\n" + "".join(
            f"    all {{ turn == {at}, {action} }},\n" for at, action in enumerate(case.recipe)) + "  }\n"
    bound = case.settings.get("BOUND", CONSTANTS["BOUND"])
    return {"watermark.qnt": text,
            "case.qnt": f'module watermarkCase {{\n  import watermark(BOUND = {bound}).* from "./watermark"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "watermark.qnt"]
    return [quint, "verify", "case.qnt", "--main", "watermarkCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])
