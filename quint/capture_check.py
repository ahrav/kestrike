"""Check finite capture safety, completed recipes and missing-mechanism controls."""

CONSTANTS = {"BOUND": "10"}
REUSE = ["bind(0,0)", "publish(0)", "start", "remove(0)", "release(0)", "bind(1,0)", "publish(1)",
         "scan", "scan", "scan", "complete", "crash", "load"]
VISITED = ["bind(0,0)", "publish(0)", "start", "scan", "remove(0)", "release(0)", "scan", "scan", "complete", "crash", "load"]
RUNS = {
    "cxT1": (REUSE, "witnessLoaded"),
    "capture-bind-start-publish-scan": (["bind(0,0)", "start", "publish(0)", "scan", "scan", "scan", "complete", "crash", "load"], "witnessBoundExcluded"),
    "capture-overflow": (["bind(0,0)", "publish(0)", "bind(1,1)", "publish(1)", "bind(2,2)", "publish(2)", "start", "remove(0)", "remove(1)", "remove(2)"], "witnessAbandoned"),
}
MUTANTS = {
    "CaptureConsistent": (REUSE, ("val save = st.phase == \"capture\" and not(st.abandoned) and e.insert <= st.t0 and e.slot >= st.cursor", "val save = false")),
    "UnitsExclusive": (REUSE, ("e.slot == st.cursor and e.insert <= st.t0", "e.slot == st.cursor")),
    "LedgerConserved": (REUSE, ("free:st.free.union(Set(e.unit)),ledgerFree:st.ledgerFree+1,ledgerOwned:st.ledgerOwned-1", "free:st.free,ledgerFree:st.ledgerFree,ledgerOwned:st.ledgerOwned")),
    "LoadGuardNeverFires": (REUSE, ("e.slot == st.cursor and e.insert <= st.t0", "e.slot == st.cursor")),
    "CaptureConsistent-cursor": (VISITED, ("e.slot >= st.cursor", "true")),
    "LedgerConserved-release-before-hook": (["bind(0,0)", "publish(0)", "start", "release(0)"], ("nondet e = st.retiring.filter(e => e.slot == slot).oneOf()", "nondet e = st.live.union(st.retiring).filter(e => e.slot == slot).oneOf()")),
    # A load that admits nothing raises no alarm and keeps the ledger consistent.
    "LoadRetains-cold-load": (REUSE, ("val admitted = if (valid) st.checkpoint else Set()", "val admitted: Set[Entry] = Set()")),
    # A load that installs each entry under another incarnation keeps the units, the ledger and the alarm.
    "LoadRetains-other-id": (REUSE, ("alarm:alarm,bound:admitted,", "alarm:alarm,bound:admitted.map(e => {...e, id: e.id + 1}),")),
}


# The trace length of each mutant whose mutated rule breaks its property before the recipe's last action: the initial
# state and one state per action through the action that breaks it. TLC stops at that state, so the trace ends
# there.
KILLS = {
    # A removal that saves nothing leaves the removed snapshot member out of the side set, so the checkpoint
    # `complete` writes differs from the snapshot.
    "CaptureConsistent": MUTANTS["CaptureConsistent"][0].index("complete") + 2,
    # A scan that ignores the insertion step collects at slot 1 the entry published after the snapshot, which reuses the
    # unit of the removed entry the side set holds; the second scan reaches slot 1.
    "UnitsExclusive": MUTANTS["UnitsExclusive"][0].index("scan", MUTANTS["UnitsExclusive"][0].index("scan") + 1) + 2,
    # A release that returns no unit to the free set and leaves the ledger as it was counts the released unit as owned
    # in the release's own state.
    "LedgerConserved": MUTANTS["LedgerConserved"][0].index("release(0)") + 2,
    # A removal that saves its entry whatever the cursor saves the entry the first scan already put in the output.
    "CaptureConsistent-cursor": MUTANTS["CaptureConsistent-cursor"][0].index("remove(0)") + 2,
}


def cases(Case):
    yield Case("capture-typecheck", command="typecheck", family="capture")
    yield Case("capture-safety", invariant="safety", family="capture")
    for witness in ("witnessLoaded", "witnessAbandoned"):
        yield Case(f"capture-reach-{witness}", invariant="unreached", expected="violation", family="capture",
                   extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="capture", recipe=recipe,
                   settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reachable", invariant="runWitness", expected="violation", family="capture", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, extra=f"  val runWitness = not({outcome})\n")
    for name, (recipe, mutation) in MUTANTS.items():
        yield Case(f"capture-mutant-{name}", invariant=name.partition("-")[0], expected="violation", family="capture",
                   recipe=recipe, settings={"BOUND": str(len(recipe))}, mutations=[mutation], trace=KILLS.get(name))

def inputs(case, source):
    text = (source / "capture.qnt").read_text()
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
    return {"capture.qnt": text, "case.qnt": f'module captureCase {{\n  import capture(BOUND = {bound}).* from "./capture"\n{extra}}}\n'}

def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "capture.qnt"]
    return [quint, "verify", "case.qnt", "--main", "captureCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])
