"""Check the finite mempool transmit-custody model: safety, a reachability witness per outcome, directed runs and one mutation per invariant."""

CONSTANTS = {"BOUND": "8"}
WITNESSES = ("witnessAcquired", "witnessReacquired", "witnessSent", "witnessFreed", "witnessHeld", "witnessTaken",
             "witnessRefused", "witnessAttached", "witnessHeaderReturned", "witnessDescReturned",
             "witnessDescReturnedFreed", "witnessDescUnarmed")
SOURCE_FREED = 'st.bufs.get("s0") == {owned: false, refs: 0, inc: 1, free: true} and st.stack == [0, 1]'
RUNS = {
    "mempool-run-drop-then-return": (['acquire("s0")', "take", "attach(1)", 'drop("s0")', "giveDesc(1)"], SOURCE_FREED),
    "mempool-run-return-then-drop": (['acquire("s0")', "take", "attach(1)", "giveDesc(1)", 'drop("s0")'], SOURCE_FREED),
    "mempool-run-header-reuse": (['acquire("h0")', 'send("h0")', 'giveHeader("h0")', 'acquire("h0")', 'send("h0")'],
                                 'st.htok.get("h0") == {armed: true, inc: 1} and st.returned == 1'),
    "mempool-run-two-segments": (['acquire("s0")', "take", "take", "take", "attach(1)", "attach(0)", 'drop("s0")',
                                  "giveDesc(0)", "giveDesc(1)"],
                                 SOURCE_FREED.replace("[0, 1]", "[0, 1] and st.refused == 1 and st.returned == 2")),
}
MUTANTS = {
    "OutOnceBackOnce": (["take", "giveDesc(1)"],
                        ("out: st.out.set(d, false), stack: st.stack.append(d)", "out: st.out.set(d, true), stack: st.stack.append(d)")),
    "NoStrayNoMismatch": (['acquire("s0")', "take", "attach(1)", "giveDesc(1)"],
                          ("dtok: st.dtok.set(d, {armed: true, inc: s.inc})", "dtok: st.dtok.set(d, {armed: true, inc: s.inc + 1})")),
    "TokenNamesLiveIncarnation": (['acquire("h0")', 'send("h0")'],
                                  ("{...b, owned: false, refs: b.refs + 1}", "{...b, owned: false, refs: b.refs}")),
    "FreesOnlyWhenBothReleased": (['acquire("s0")', "take", "attach(1)", 'drop("s0")'],
                                  ('{...found, owned: false}), ev: event("drop", "Held"', '{...found, owned: false, free: true}), ev: event("drop", "Held"')),
}


def cases(Case):
    yield Case("mempool-typecheck", command="typecheck", family="mempool")
    yield Case("mempool-safety", invariant="safety", family="mempool")
    for witness in WITNESSES:
        yield Case(f"mempool-reach-{witness}", invariant="unreached", expected="violation", family="mempool",
                   extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="mempool", recipe=recipe, settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="mempool", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (recipe, mutation) in MUTANTS.items():
        yield Case(f"mempool-mutant-{name}", invariant=name, expected="violation", family="mempool", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=[mutation])


def inputs(case, source):
    text = (source / "mempool.qnt").read_text()
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
    return {"mempool.qnt": text,
            "case.qnt": f'module mempoolCase {{\n  import mempool(BOUND = {bound}).* from "./mempool"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "mempool.qnt"]
    return [quint, "verify", "case.qnt", "--main", "mempoolCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])
