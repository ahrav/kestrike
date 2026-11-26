"""Check the finite attach-gate model: safety, a reachability witness per outcome, directed runs and one mutation per invariant."""

CONSTANTS = {"BOUND": "8"}
WITNESSES = ("witnessSubmitted", "witnessBusy", "witnessLost", "witnessIdle", "witnessIdleAfterThePass",
             "witnessSubmitRefused", "witnessRegistered", "witnessRegisterConflict", "witnessAcquired",
             "witnessAcquireConflict", "witnessFenced", "witnessForeignRegistrant", "witnessForeignHolder",
             "witnessOtherType", "witnessDuplicate", "witnessNotHolder", "witnessWithheld", "witnessReportFailed",
             "witnessReportDeposed", "witnessExpired", "witnessExpiredUnderACommand", "witnessWithdrawn", "witnessClosed",
             "witnessTimedOut")
SUBMIT = 'tick("none")'
REPORTED = [SUBMIT, "register(true)", SUBMIT, "acquire(true)", SUBMIT]
RUNS = {
    "gate-run-passes": (REPORTED + ['report("sole")', SUBMIT],
                        'st.outcome == "fenced" and st.admissions == 1 and st.medium and st.sent == 3 and witnessIdleAfterThePass'),
    "gate-run-busy-then-foreign-registrant": (
        ['tick("busy")'] + REPORTED + ['report("registrant")', SUBMIT],
        'st.outcome == "registrant" and st.flip and st.admissions == 0 and not(st.medium) and st.sent == 3'),
    "gate-run-acquire-conflict": ([SUBMIT, "register(true)", SUBMIT, "acquire(false)", SUBMIT],
                                  'st.outcome == "command" and st.failed == 1 and st.machine == "withdrawn" and not(st.flip) and st.sent == 2'),
    "gate-run-report-times-out": (REPORTED + ["timeout", SUBMIT],
                                  'st.outcome == "authority" and st.machine == "pre" and st.admissions == 0 and st.sent == 3'),
}
MUTANTS = {
    "NoMediumBeforeTheGate": (REPORTED, ('{...st, pending: true, sent: st.sent + 1, ev: event("tick", "submitted")}',
                                         '{...st, pending: true, sent: st.sent + 1, medium: st.step == REPORT, ev: event("tick", "submitted")}')),
    "PassNeedsTheSoleReport": ([SUBMIT, "register(true)", SUBMIT, "acquire(true)"],
                               ('{...st, step: REPORT, pending: false, ev: event("acquire", "ok")}',
                                '{...st, step: REPORT, pending: false, outcome: "fenced", admissions: 1, ready: "loading", '
                                'ev: event("acquire", "ok")}')),
    "AdmitsExactlyOnce": (REPORTED + ['report("duplicate")'],
                          ('else if (view == "duplicate") refused(st, "duplicate", "report")',
                           'else if (view == "duplicate") {...refused(st, "duplicate", "report"), admissions: 1}')),
    "RefusalEndsWithNoMedium": (REPORTED + ['report("registrant")'],
                                ('else {...refused(st, view, "report"), machine: "withdrawn", flip: true}',
                                 'else {...refused(st, view, "report"), machine: "withdrawn", flip: true, medium: true}')),
    "LoadingOnlyAfterTheGate": ([SUBMIT], ('{...st, pending: true, sent: st.sent + 1, ev: event("tick", "submitted")}',
                                           '{...st, pending: true, sent: st.sent + 1, ready: "loading", ev: event("tick", "submitted")}')),
}


def cases(Case):
    yield Case("gate-typecheck", command="typecheck", family="gate")
    yield Case("gate-safety", invariant="safety", family="gate")
    for witness in WITNESSES:
        yield Case(f"gate-reach-{witness}", invariant="unreached", expected="violation", family="gate",
                   extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="gate", recipe=recipe, settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="gate", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (recipe, mutation) in MUTANTS.items():
        yield Case(f"gate-mutant-{name}", invariant=name, expected="violation", family="gate", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=[mutation])


def inputs(case, source):
    text = (source / "gate.qnt").read_text()
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
    return {"gate.qnt": text, "case.qnt": f'module gateCase {{\n  import gate(BOUND = {bound}).* from "./gate"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "gate.qnt"]
    return [quint, "verify", "case.qnt", "--main", "gateCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])
