"""Check the finite fill-claims model: safety, a reachability witness per outcome, directed runs and one mutation per invariant."""

CONSTANTS = {"BOUND": "8", "LIMIT": "2", "LEASES": "3"}
WITNESSES = ("witnessReserved", "witnessInProgress", "witnessInProgressDeparted", "witnessIndexFull", "witnessReplacementFull",
             "witnessLeaseLimit", "witnessActivated", "witnessReplaced", "witnessExpired", "witnessExpiredBesideIncumbent",
             "witnessAborted", "witnessRefunded", "witnessUnblocked", "witnessIdle", "witnessRemoved", "witnessRevoked",
             "witnessRevokedDeparted", "witnessRemovedRevoked", "witnessNone", "witnessSuperseded", "witnessLeaseDropped")
IDLE = "st.p == 0 and st.c == 0 and st.v == 0"
RUNS = {
    "claims-run-refunds": (["reserve(0)", "abort(0)", "service", "reserve(0)", "publishFill(0, true)", "service"],
                           f"{IDLE} and st.ev.res == \"Idle\""),
    "claims-run-revoked": (["reserve(0)", "publishFill(0, false)", "reserve(0)", "invalidate(0)", "endRevoked(0)", "release(0)"],
                           f"{IDLE} and st.ev.res == \"LeaseDropped\""),
}
MUTANTS = {
    "UploadHoldsClaims": (["reserve(0)"], ('p: st.p + 1, c: st.c + 2,\n        ev: event("reserve", "Reserved", key, 0)}',
                                         'p: st.p + 1, c: st.c + 1,\n        ev: event("reserve", "Reserved", key, 0)}'), {}),
    "ReadyNeverRefusesFull": (["reserve(0)", "reserve(1)", "publishFill(0, false)", "publishFill(1, false)"],
                              ('{state: "reserved", place: true}), p: st.p + 1, c: st.c + 2,', '{state: "reserved", place: false}), c: st.c + 2,'),
                              {"LIMIT": "1", "LEASES": "5"}),
    "ClaimsReturnOnce": (["reserve(0)", "abort(0)"], ('c: st.c - 2,\n      ev: event("abort", "Aborted", key, 0)}',
                                                     'c: st.c - 2, p: st.p - 1,\n      ev: event("abort", "Aborted", key, 0)}'), {}),
    "RefusalKeepsIncumbent": (["reserve(0)", "publishFill(0, false)", "reserve(0)", "publishFill(0, true)"],
                              ('refusal(st, {...st, rec: st.rec.set(key, NONE), p: st.p - spent, c: st.c - 2,\n            ev: event("publishFill", "Expired", key, 1)})',
                               'refusal(st, {...st, rec: st.rec.set(key, NONE), p: st.p - spent, c: st.c - 2, vis: st.vis.set(key, 0), v: st.v - 1,\n            ev: event("publishFill", "Expired", key, 1)})'), {}),
}


def cases(Case):
    yield Case("claims-typecheck", command="typecheck", family="claims")
    yield Case("claims-safety", invariant="safety", family="claims")
    for witness in WITNESSES:
        yield Case(f"claims-reach-{witness}", invariant="unreached", expected="violation", family="claims",
                   extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="claims", recipe=recipe, settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="claims", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (recipe, mutation, settings) in MUTANTS.items():
        yield Case(f"claims-mutant-{name}", invariant=name, expected="violation", family="claims", recipe=recipe,
                   settings={"BOUND": str(len(recipe)), **settings}, mutations=[mutation])


def inputs(case, source):
    text = (source / "claims.qnt").read_text()
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
    bindings = ", ".join(f"{name} = {value}" for name, value in {**CONSTANTS, **case.settings}.items())
    return {"claims.qnt": text, "case.qnt": f'module claimsCase {{\n  import claims({bindings}).* from "./claims"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "claims.qnt"]
    return [quint, "verify", "case.qnt", "--main", "claimsCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])
