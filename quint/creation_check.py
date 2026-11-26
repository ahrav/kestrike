"""Check the finite reconciler-creation model: safety, a reachability witness per outcome, a directed run beside each path witness, directed runs, one mutation per invariant and the Rust replay of its regenerated traces."""

CONSTANTS = {"BOUND": "14"}
# The ignored test that regenerates the traces `creation_fixtures.py` declares, requires them to equal the committed
# ones and replays them against the reconciler.
REPLAY_TEST = "failover::reconcile_tests::creation_replay::generated_creation_traces_replay"


def op(proc, name, arg, requests=0):
    """The steps of one operation: its start and `requests` requests."""
    return [f'begin({proc}, "{name}", {arg})'] + [f"request({proc})"] * requests


def ends(act, operation, key, res):
    return f'st.ev.act == "{act}" and st.ev.op == "{operation}" and st.ev.key == "{key}" and st.ev.res == "{res}"'


# A whole shard creation: the shard read, both page creates, the shard create.
CREATE = op(0, "createShard", 1, 4)
ATTACHED = op(0, "provision", 0, 1) + op(0, "attach", 1, 2)
# After both creations read the shard record absent: process 0 creates both pages and the shard record, and
# process 1's page creates refuse on the empty pages, its shard create refuses, and it reads the shard record.
RACE = ["request(0)", "request(1)", "request(1)", "request(0)", "request(1)", "request(0)", "request(1)", "request(1)",
        "request(1)"]
PROC = "st.procs.get(st.ev.proc)"
# Each witness names a state the model must reach: an outcome of a request, or a race the creation rules decide.
WITNESSES = {
    "ShardCreated": ends("write", "createShard", "shard", "created"),
    "ShardFoundAtTheFirstRead": ends("read", "createShard", "shard", "found") + f" and {PROC}.pc == 0",
    "ShardConflictAtTheFirstRead": ends("read", "createShard", "shard", "conflict") + f" and {PROC}.pc == 0",
    "PageCreateRefusedOnAnEmptyPage": ends("read", "createShard", "page0", "") + f" and {PROC}.pc == 3",
    "RaceLostToTheSameCreation": ends("read", "createShard", "shard", "found") + f" and {PROC}.pc == 6",
    "Provisioned": ends("write", "provision", "volume", "provisioned"),
    "ProvisionFound": ends("read", "provision", "volume", "found"),
    "ProvisionConflict": ends("read", "provision", "volume", "conflict"),
    "Attached": ends("write", "attach", "volume", "recorded"),
    "AttachReplayed": ends("read", "attach", "volume", "recorded"),
    "AttachConflict": ends("read", "attach", "volume", "conflict"),
    "AttachAbsent": ends("read", "attach", "volume", "absent"),
    "AttachWriteRefused": ends("write", "attach", "volume", "condition"),
    "UnknownCommitted": 'st.ev.act == "commit"',
    "UnknownLost": 'st.ev.act == "lost"',
    "Held": 'st.ev.act == "hold"',
    "ReleaseCommitted": 'st.ev.act == "release" and st.ev.res == "committed"',
    "ReleaseRefused": 'st.ev.act == "release" and st.ev.res == "refused"',
    "Fenced": 'st.ev.act == "fence"',
    "FencedPageUnderARetry": ends("read", "createShard", "page0", "")
    + f" and {PROC}.pc == 6 and st.pages.get(0).fenced and st.shard.id == st.ev.arg",
    # A held shard create refuses after another creation committed.
    "HeldCreateAfterTheWinner": 'st.ev.act == "release" and st.ev.key == "shard" and st.ev.res == "refused"',
}
RUNS = {
    "creation-run-create-then-replay": (
        CREATE + op(1, "createShard", 1, 1) + op(1, "createShard", 2, 1),
        'st.ev.res == "conflict" and st.shard.id == 1 and st.returned == Set(1) and st.pages.get(1).exists'),
    "creation-run-racing-creations": (
        op(0, "createShard", 1, 1) + op(1, "createShard", 2, 1) + RACE,
        'st.ev.res == "conflict" and st.shard.id == 1 and st.returned == Set(1)'),
    "creation-run-attach-once": (
        ATTACHED + op(1, "attach", 2, 1) + op(1, "attach", 1, 1) + op(1, "provision", 0, 2),
        'st.ev.res == "conflict" and st.vol.host == 1 and st.witnesses == Set(1) and st.hosts == Set(1)'),
}
RACED = op(0, "createShard", 1, 1) + op(1, "createShard", 1, 1) + RACE
MET_FENCE = op(1, "createShard", 1, 1) + CREATE + ["fence(0)"] + ["request(1)"] * 2
# BESIDE maps each witness to a recipe that keeps the witness false and a required final-state predicate.
BESIDE = {
    "ShardFoundAtTheFirstRead": (RACED, WITNESSES["RaceLostToTheSameCreation"]),
    "ShardConflictAtTheFirstRead": (
        RUNS["creation-run-racing-creations"][0],
        ends("read", "createShard", "shard", "conflict") + f" and {PROC}.pc == 6"),
    "PageCreateRefusedOnAnEmptyPage": (MET_FENCE, WITNESSES["FencedPageUnderARetry"]),
    "RaceLostToTheSameCreation": (CREATE + op(1, "createShard", 1, 1), WITNESSES["ShardFoundAtTheFirstRead"]),
    "FencedPageUnderARetry": (
        CREATE + ["fence(0)"] + op(1, "createShard", 1, 1),
        WITNESSES["ShardFoundAtTheFirstRead"] + " and st.pages.get(0).fenced"),
}
MUTANTS = {
    "WitnessMeansRecorded": (op(0, "provision", 0, 1) + op(0, "attach", 1, 1) + ['unknown(0, "lost")'],
                             ('st\' = {...stored, procs: st.procs.set(p, ended(proc, "unknown")), ev:',
                              'st\' = {...stored, procs: st.procs.set(p, ended(proc, "unknown")), witnesses: '
                              'if (proc.op == "attach") st.witnesses.union(Set(proc.arg)) else st.witnesses, ev:')),
    "OneAttachForLife": (ATTACHED + op(1, "attach", 2, 2),
                         ('    else ended(p, "conflict")\n  pure def event', '    else {...p, pc: 1, vver: s.vol.ver}\n  pure def event')),
    "CreationReturnsItsOwnRecord": (CREATE + op(1, "createShard", 2, 1),
                                    ('ended(p, if (s.shard.id == p.arg) "found" else "conflict")', 'ended(p, "found")')),
    "PagesBeforeTheShard": (op(0, "createShard", 1, 2),
                            ('(if (s.shard.exists) replayed(s, p) else {...p, pc: 1})', '(if (s.shard.exists) replayed(s, p) else {...p, pc: 5})')),
}


def cases(Case):
    yield Case("creation-typecheck", command="typecheck", family="creation")
    yield Case("creation-safety", invariant="safety", family="creation")
    yield Case("creation-replay", command="replay", family="creation")
    for witness, reached in WITNESSES.items():
        yield Case(f"creation-reach-{witness}", invariant="unreached", expected="violation", family="creation",
                   extra=f"  val unreached = not({reached})\n")
    for witness, (recipe, ending) in BESIDE.items():
        yield Case(f"creation-beside-{witness}", invariant="beside", family="creation", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, depth=len(recipe) + 1,
                   extra=f"  val beside = not({WITNESSES[witness]}) and (turn == {len(recipe)} implies ({ending}))\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="creation", recipe=recipe, settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="creation", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (recipe, mutation) in MUTANTS.items():
        yield Case(f"creation-mutant-{name}", invariant=name, expected="violation", family="creation", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=[mutation])


def inputs(case, source):
    text = (source / "creation.qnt").read_text()
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
    return {"creation.qnt": text,
            "case.qnt": f'module creationCase {{\n  import creation(BOUND = {bound}).* from "./creation"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "replay":
        return ["cargo", "test", "-p", "kestrike", "--lib", "--", "--ignored", "--exact", REPLAY_TEST, "--nocapture"]
    if case.command == "typecheck":
        return [quint, "typecheck", "creation.qnt"]
    return [quint, "verify", "case.qnt", "--main", "creationCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])
