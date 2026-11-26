"""Check the finite builder-escrow model: safety, a reachability witness per outcome, directed runs and one mutation per invariant."""

CONSTANTS = {"BOUND": "12", "VOLUME": "316"}
WITNESSES = ("witnessPromiseTwo", "witnessPromiseThree", "witnessPromiseExact", "witnessPromiseShort",
             "witnessPromiseRefusedBeside", "witnessPlacePartial", "witnessPlaceComplete", "witnessCancelUnplaced",
             "witnessCancelPartial", "witnessCancelComplete", "witnessDropUnplaced", "witnessDropPartial",
             "witnessDropComplete", "witnessServiceIdle", "witnessServicePartial", "witnessServiceLast",
             "witnessServiceEmpty", "witnessClaim", "witnessClaimBesidePromise", "witnessClaimRefused",
             "witnessUnclaim", "witnessTwoBuilders")
RUNS = {
    "escrow-run-an-exact-promise-succeeds-and-a-short-one-refuses": (
        ["claim", "claim", "promise(1, 3)", "promise(2, 2)", "place(1)"],
        "st.u == 2 * 63 and st.free == 316 - 3 * 63 and pre.u == 3 * 63 and st.b.get(2).phase == \"none\"", "316"),
    "escrow-run-a-claim-beside-a-promise-spares-the-promised-units": (
        ["promise(1, 3)", "claim", "claim", "place(1)", "unclaim", "release(1)", "service"],
        "st.u == 0 and st.direct == 1 and st.free == 316 - 63 and not(st.parked) and ev.res == \"serviced\"", "316"),
    "escrow-run-two-builders-interleave-and-each-exit-refunds-once": (
        ["promise(1, 2)", "promise(2, 2)", "place(2)", "place(1)", "cancel(1)", "place(2)", "release(2)",
         "service", "service", "service"],
        "st.u == 0 and st.free == 316 and not(st.parked) and ev.res == \"idle\"", "316"),
    "escrow-run-the-reserve-refuses-a-promise-of-exactly-the-allocatable-units": (
        ["claim", "claim", "promise(1, 3)", "unclaim", "promise(1, 3)"],
        "st.u == 3 * 63 and pre.u == 0 and st.free == 315 - 63 and st.direct == 1", "315"),
}
MUTANTS = {
    "PromiseNeedsAllocatable": (["promise(1, 3)", "claim", "promise(2, 2)"],
                                ("if (st.free - st.u >= charge + R) all {", "if (st.free - st.u >= charge - E + R) all {")),
    "RefusalChangesNothing": (["claim", "claim", "promise(1, 2)", "promise(2, 2)"],
                              ("        st' = st,\n        ev' = event(\"promise\", k, \"clean_reserve\", st, 0, charge)",
                               "        st' = {...st, u: st.u + charge},\n"
                               "        ev' = event(\"promise\", k, \"clean_reserve\", st, 0, charge)")),
    "EscrowIsRemaining": (["promise(1, 2)", "place(1)"],
                          ("free: st.free - E, u: st.u - E, b:", "free: st.free - E, u: st.u, b:")),
    "EscrowWithinFree": (["promise(1, 3)", "promise(2, 3)"],
                         ("if (st.free - st.u >= charge + R) all {", "if (st.free >= charge + R) all {")),
    "Conservation": (["claim", "unclaim"],
                     ("st' = {...st, free: st.free + E, direct: st.direct - 1},",
                      "st' = {...st, free: st.free + E + E, direct: st.direct - 1},")),
    "ClaimSparesPromised": (["promise(1, 2)", "promise(2, 2)", "claim", "claim"],
                            ("    if (st.free - st.u >= E + R) all {", "    if (st.free >= E + R) all {")),
    "RefundOnce": (["promise(1, 2)", "place(1)", "cancel(1)"],
                   ("u: st.u - x.rem, b: st.b.set(k, IDLE)},\n      ev' = event(\"cancel\"",
                    "u: st.u - x.rem - x.rem, b: st.b.set(k, IDLE)},\n      ev' = event(\"cancel\"")),
    "CompleteAtLast": (["promise(1, 3)", "place(1)", "place(1)"],
                       ("if (placed == x.extents) \"complete\"", "if (placed + 1 >= x.extents) \"complete\"")),
}
RESERVE_MUTANT = (["claim", "claim", "promise(1, 3)"],
                  ("if (st.free - st.u >= charge + R) all {", "if (st.free - st.u >= charge) all {"))


def cases(Case):
    yield Case("escrow-typecheck", command="typecheck", family="escrow")
    yield Case("escrow-safety", invariant="safety", family="escrow")
    yield Case("escrow-safety-volume-315", invariant="safety", family="escrow", settings={"VOLUME": "315"})
    yield Case("escrow-reach-witnessPromiseShortByReserve-volume-315", invariant="unreached", expected="violation",
               family="escrow", settings={"VOLUME": "315"}, extra="  val unreached = not(witnessPromiseShortByReserve)\n")
    for witness in WITNESSES:
        yield Case(f"escrow-reach-{witness}", invariant="unreached", expected="violation", family="escrow",
                   extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome, volume) in RUNS.items():
        settings = {"BOUND": str(len(recipe)), "VOLUME": volume}
        yield Case(name, invariant="runSafety", family="escrow", recipe=recipe, settings=settings,
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="escrow", recipe=recipe,
                   settings=settings, extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (recipe, mutation) in MUTANTS.items():
        yield Case(f"escrow-mutant-{name}", invariant=name, expected="violation", family="escrow", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=[mutation])
    # At VOLUME 315 the allocatable units can equal a charge exactly, so only the clean reserve refuses the promise.
    yield Case("escrow-mutant-PromiseNeedsAllocatable-reserve-volume-315", invariant="PromiseNeedsAllocatable",
               expected="violation", family="escrow", recipe=RESERVE_MUTANT[0],
               settings={"BOUND": str(len(RESERVE_MUTANT[0])), "VOLUME": "315"}, mutations=[RESERVE_MUTANT[1]])


def inputs(case, source):
    text = (source / "escrow.qnt").read_text()
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
    volume = case.settings.get("VOLUME", CONSTANTS["VOLUME"])
    return {"escrow.qnt": text,
            "case.qnt": f'module escrowCase {{\n  import escrow(BOUND = {bound}, VOLUME = {volume}).* from "./escrow"\n'
                        f'{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "escrow.qnt"]
    return [quint, "verify", "case.qnt", "--main", "escrowCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])
