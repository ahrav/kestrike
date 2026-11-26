"""Check the finite retired-allowance model: safety, a reachability witness per outcome, directed runs and one mutation per invariant."""

CONSTANTS = {"BOUND": "8", "T": "2"}
WITNESSES = ("witnessPublished", "witnessLeased", "witnessPublishPressure", "witnessReplaced", "witnessReplacePressure",
             "witnessRetired", "witnessPastAllowance", "witnessCertified", "witnessDropped", "witnessReturned",
             "witnessReturnRestoresClaims", "witnessHeldAfterCertify", "witnessIdle")
RUNS = {
    "allowance-run-mass-invalidation": (["publish(0, false)", "publish(1, false)", "publish(2, false)", "invalidate(0)", "invalidate(1)",
                                         "invalidate(2)", "publish(3, false)", "certify", "visit", "publish(3, false)"],
                                        "st.ev.res == \"Published\" and st.charge == 0"),
    "allowance-run-reader-held": (["publish(0, true)", "publish(1, false)", "invalidate(0)", "certify", "visit", "replace(1)",
                                   "publish(2, false)", "release", "certify", "visit"],
                                  "st.ev.res == \"Returned\" and st.charge == 0"),
}
MUTANTS = {
    "PressureGatesClaims": (["publish(0, false)", "publish(1, false)", "publish(2, false)", "invalidate(0)", "invalidate(1)", "replace(2)"],
                            ("if (st.charge >= T) {...st, ev: event(\"replace\", \"RetiredPressure\", key, 0)}",
                             "if (st.charge >= T + 1) {...st, ev: event(\"replace\", \"RetiredPressure\", key, 0)}"), {}),
    "RefusalChangesNothing": (["publish(0, false)", "publish(1, false)", "publish(2, false)", "invalidate(0)", "invalidate(1)", "replace(2)"],
                              ("if (st.charge >= T) {...st, ev: event(\"replace\", \"RetiredPressure\", key, 0)}",
                               "if (st.charge >= T) {...st, vis: st.vis.set(key, ABSENT), ev: event(\"replace\", \"RetiredPressure\", key, 0)}"), {}),
    "ChargeCountsRetired": (["publish(0, false)", "invalidate(0)", "certify", "visit"],
                            ("charge: st.charge - gone.size(),", "charge: st.charge,"), {}),
}


def cases(Case):
    yield Case("allowance-typecheck", command="typecheck", family="allowance")
    yield Case("allowance-safety", invariant="safety", family="allowance")
    for witness in WITNESSES:
        yield Case(f"allowance-reach-{witness}", invariant="unreached", expected="violation", family="allowance",
                   extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="allowance", recipe=recipe, settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="allowance", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (recipe, mutation, settings) in MUTANTS.items():
        yield Case(f"allowance-mutant-{name}", invariant=name, expected="violation", family="allowance", recipe=recipe,
                   settings={"BOUND": str(len(recipe)), **settings}, mutations=[mutation])


def inputs(case, source):
    text = (source / "allowance.qnt").read_text()
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
    return {"allowance.qnt": text, "case.qnt": f'module allowanceCase {{\n  import allowance({bindings}).* from "./allowance"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "allowance.qnt"]
    return [quint, "verify", "case.qnt", "--main", "allowanceCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])
