"""Check the finite watermark-log model: safety, each invariant, a reachability witness per step choice and outcome, directed runs and at least one mutation per invariant."""

CONSTANTS = {"BOUND": "6"}
INVARIANTS = ("MarksFillPrefix", "OneSlotPerKey", "LoadsBeforeOrAfter", "ReturnedMarksAreDurable")
WITNESSES = ("witnessFirstMark", "witnessRaisedInPlace", "witnessTwoRaisedInPlace", "witnessWhole",
             "witnessNothingRaised", "witnessOutOfKeyOrder", "witnessCrashNothingLanded", "witnessCrashPartlyLanded",
             "witnessCrashAllLanded", "witnessCrashNewMarkLost", "witnessCrashWholeOld", "witnessCrashWholeNew",
             "witnessWrite", "witnessRestart")
RUNS = {
    # Two pages rise in one in-place raise and a crash lands one slot: the next process loads one new mark and one
    # previous mark.
    "marklog-run-partly-landed": (["read(Set(1))", "read(Set(2))", "write(1)", "write(2)",
                                   "crash(Set(1, 2), Set(2))", "read(Set(1, 2))"],
                                  'ev.how == "inPlace" and mark == Map(1 -> 2, 2 -> 2, 3 -> 0) and acked == mark'),
    # A batch that brings two new marks replaces the file whole; a crash in it leaves the previous file.
    "marklog-run-whole-replacement": (["read(Set(3))", "crash(Set(1, 2), Set())", "read(Set(1, 2))"],
                                      'ev.how == "whole" and file[0] == {key: 1, ver: 1} and file[2] == {key: 3, ver: 1}'),
    # A new mark takes the next free slot, so the slots leave key order, and a restart loads them.
    "marklog-run-out-of-key-order": (["read(Set(2))", "read(Set(1))", "restart", "write(2)", "read(Set(2))"],
                                     'file[0] == {key: 2, ver: 2} and file[1] == {key: 1, ver: 1} and mark == acked'),
}
# Each mutation, the invariant it breaks, and the one replacement of the model's text.
MUTANTS = {
    "two-new-marks-in-place": ("MarksFillPrefix", ("raised(batch).filter(k => mark.get(k) == 0).size() <= 1",
                                                   "raised(batch).filter(k => mark.get(k) == 0).size() <= 3")),
    "new-mark-skips-a-slot": ("MarksFillPrefix", ("else free + earlier", "else free + earlier + 1")),
    "held-key-takes-a-new-slot": ("OneSlotPerKey", ("if (at.size() > 0) at.fold(0, (a, i) => i) else free + earlier",
                                                    "free + earlier")),
    "whole-replacement-tears": ("LoadsBeforeOrAfter", ("else if (landed == raised(batch)) whole(risen(batch)) else file",
                                                       "else if (landed == raised(batch)) whole(risen(batch)) else whole(NONE)")),
    "restart-forgets-the-file": ("ReturnedMarksAreDurable", ("mark' = marksOf(file), file' = file, acked' = acked, store' = store,",
                                                             "mark' = NONE, file' = file, acked' = acked, store' = store,")),
}


def cases(Case):
    yield Case("marklog-typecheck", command="typecheck", family="marklog")
    yield Case("marklog-safety", invariant="safety", family="marklog")
    for name in INVARIANTS:
        yield Case(f"marklog-{name}", invariant=name, family="marklog")
    for witness in WITNESSES:
        yield Case(f"marklog-reach-{witness}", invariant="unreached", expected="violation", family="marklog",
                   extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="marklog", recipe=recipe,
                   settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="marklog", recipe=recipe,
                   settings={"BOUND": str(len(recipe))},
                   extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (invariant, mutation) in MUTANTS.items():
        yield Case(f"marklog-mutant-{name}", invariant=invariant, expected="violation", family="marklog",
                   mutations=[mutation])
    # The conjunction `safety` and a directed run's `runSafety` each reject a mutation themselves.
    yield Case("marklog-mutant-safety-two-new-marks-in-place", invariant="safety", expected="violation",
               family="marklog", mutations=[MUTANTS["two-new-marks-in-place"][1]])
    recipe = ["read(Set(3))", "crash(Set(1, 2), Set())"]
    yield Case("marklog-run-whole-replacement-tears", invariant="runSafety", expected="violation", family="marklog",
               recipe=recipe, settings={"BOUND": str(len(recipe))},
               mutations=[MUTANTS["whole-replacement-tears"][1]],
               extra=f"  val runSafety = safety and (turn == {len(recipe)} implies true)\n")


def inputs(case, source):
    text = (source / "marklog.qnt").read_text()
    for old, new in case.mutations:
        if text.count(old) != 1:
            raise ValueError(f"{case.name}: mutation target is not unique")
        text = text.replace(old, new)
    extra = case.extra
    if case.recipe:
        extra += "  action recipe = any {\n" + "".join(
            f"    all {{ turn == {at}, {action} }},\n" for at, action in enumerate(case.recipe)) + "  }\n"
    bound = case.settings.get("BOUND", CONSTANTS["BOUND"])
    return {"marklog.qnt": text,
            "case.qnt": f'module marklogCase {{\n  import marklog(BOUND = {bound}).* from "./marklog"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "marklog.qnt"]
    return [quint, "verify", "case.qnt", "--main", "marklogCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])
