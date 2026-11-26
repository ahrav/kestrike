"""Preservation model cases: typecheck, free-scheduler safety, reachability witnesses, the directed runs and the planted
mutations.

A run is a recipe of model actions that restricts the scheduler to one schedule; it passes only when TLC checks
`safety` over the whole recipe, its last state holds the run's outcome, and each state its checks name holds that
check. A `-no-end` run sets `END = false` and checks the properties `NO_END_RUNS` names, `RecoveredInstalled`, the
outcome and the same intermediate checks. A recipe mutant replaces model text and must violate its named property
first at the last step of its recipe; the runner requires the violation's trace to hold that step's states plus the
initial one. Write ids come from one counter: a fill or a tombstone takes one id, and a capture takes rows r and
r + 1 and Publish id r + 2; a refusal takes none.
"""

CONSTANTS = {"BOUND": "9"}
# The bound of the free-scheduler cases that schedule `damageStep`.
DAMAGE_BOUND = "8"
WITNESSES = ("witnessWarm", "witnessStaleLanding", "witnessBarrierFreed", "witnessRefusedSlot", "witnessRefusedFull",
             "witnessRefusedLog", "witnessRefusedReplace", "witnessExcluded", "witnessTombLanded", "witnessChain", "witnessReopen",
             "witnessDeposedWrite", "witnessFencedCrash")
# Witnesses reached under `damageStep` at `DAMAGE_BOUND`.
DAMAGE_WITNESSES = ("witnessDamagedLoss",)
# The fills take ids 1 and 2; the capture takes row ids 3 and 4 and Publish id 5.
PUBLISHED = ["fill(0)", "fill(1)", "capture", "applyId(5)", "ackId(5)"]
TAKEOVER = ["lose", "takeover", "fence", "recover"]
WARM = PUBLISHED + TAKEOVER
EVICTED = PUBLISHED + ['drop(0, "evict")']
CYCLE = ["capture", "applyId({0})", "ackId({0})"]
# The fill takes id 1; the captures take row ids 2 and 3, 5 and 6, 8 and 9, 11 and 12, and 14 and 15.
BOTH_HIT = (["fill(0)"] + [s.format(i) for i in (4, 7, 10) for s in CYCLE] + ["capture", "barrier"]
            + [s.format(13) for s in CYCLE] + ["landId(2)"] + [s.format(16) for s in CYCLE] + ["landId(5)"] + TAKEOVER)
# The tombstones take ids 6 and 11, the fill takes id 7, and the capture takes row ids 8 and 9 and Publish id 10.
LOG_FULL = (EVICTED + ["tombDone(6)", "fill(0)", "capture", "applyId(10)", 'drop(1, "evict")', 'drop(0, "evict")'])
PREEMPT = (["fill(0)", 'drop(0, "invalidate")', "fill(1)", "capture", "applyId(5)", "ackId(5)", "lose", "takeover"]
           + TAKEOVER[1:] + ["fill(0)", "capture", "applyId(9)", "landId(1)"])
ROLLBACK = (["fill(0)", "capture", "applyId(4)", "ackId(4)"] + TAKEOVER + ["capture", "applyId(7)", "ackId(7)"] + TAKEOVER
            + ["lose", "rollback", "reopen", "takeover", "fence", "recover"])
# The fills take ids 1, 5, 6 and 7; the captures take row ids 2 and 3 with Publish id 4, and 8 and 9 with 10.
INVISIBLE = (["fill(0)", "capture", "applyId(4)", "ackId(4)", 'drop(0, "invalidate")', "fill(1)", "fill(0)",
              'drop(0, "expire")', "fill(0)", "barrier", "fill(0)", "landId(1)", "capture", "applyId(10)", "ackId(10)"]
             + TAKEOVER)
# The tombstone takes id 6, the fills take ids 7, 8 and 9, and the capture takes row ids 10 and 11 and Publish id 12.
CHAIN_EVICT = (WARM + ['drop(1, "evict")', "tombDone(6)", "fill(1)"] + TAKEOVER
               + ["fill(1)", 'drop(1, "invalidate")', "fill(1)", "capture", "applyId(12)", "landId(7)"])
# The post-takeover fill takes id 6; capture takes row ids 7 and 8 and Publish id 9.
DEPOSED = (PUBLISHED + ["lose", "takeover", 'drop(1, "invalidate")', "fill(1)", "capture", "applyId(9)", "fence",
                        "recover", "landId(6)"])
# The fills take ids 1, 2, 3 and 9, the tombstones take ids 7, 8 and 13, and the captures take row ids 4 and 5 with
# Publish id 6, and 10 and 11 with 12.
ANCESTOR = (["fill(0)", "fill(1)", 'drop(0, "invalidate")', "fill(0)", "capture", "applyId(6)", "ackId(6)",
             'drop(0, "evict")', "tombDone(7)"] + TAKEOVER
            + ['drop(1, "evict")', "fill(0)", "capture", 'drop(0, "evict")', "tombDone(13)"] + TAKEOVER)
# The tombstones take ids 6, 11 and 12, the fill takes id 7, and the capture takes row ids 8 and 9 and Publish id 10;
# the acknowledgment releases block 9, the barrier frees it, and tombstone 12 reuses it.
JOURNAL_WRAP = (EVICTED + ["tombDone(6)", "fill(0)", "capture", "applyId(10)", "ackId(10)", "barrier",
                           'drop(1, "evict")', 'drop(0, "evict")', "tombDone(12)"] + TAKEOVER)
# The tombstone takes id 6 and the fills take ids 7 and 8: the expiry and the completed tombstone release units 1 and 0,
# the barrier frees them, and the fills reuse them.
RELEASE_REUSE = (PUBLISHED + ['drop(1, "expire")', 'drop(0, "evict")', "tombDone(6)", "barrier", "fill(0)", "fill(1)"]
                 + TAKEOVER)
# The tombstones take ids 5, 10 and 15, the fills take ids 1, 6 and 11, and the captures take row ids 2 and 3, 7 and
# 8, and 12 and 13 with Publish ids 4, 9 and 14; tombstone 15 reuses block 9 and tombstone 5 lands over it.
JOURNAL_REUSE = (["fill(0)", "capture", "applyId(4)", "ackId(4)", 'drop(0, "evict")', "tombDone(5)", "fill(0)",
                  "capture", "applyId(9)", "ackId(9)", "barrier", 'drop(0, "evict")', "tombDone(10)", "fill(0)",
                  "capture", "applyId(14)", "ackId(14)", 'drop(0, "evict")', "tombDone(15)", "landId(5)"] + TAKEOVER)
# The fill takes id 1, the tombstone takes id 5, the capture takes row ids 6 and 7 and Publish id 8, and the refill
# takes id 9: tombstone 5 never lands, so recovery at tenure 3 frees payload 1's unit, the refill reuses it, and the
# rollback names slot 0 again, whose eligible entry is payload 1.
ROLLBACK_REUSE = (["fill(0)", "capture", "applyId(4)", "ackId(4)"] + TAKEOVER
                  + ['drop(0, "evict")', "capture", "applyId(8)", "ackId(8)"] + TAKEOVER + ["fill(0)", "lose", "rollback"])
RUNS = {
    "warmTakeover": (WARM, "st.recovered == Set(1, 2)", {}),
    "invisibleAttempt": (INVISIBLE, "st.recovered == Set(5, 7)", {9: 'ev == "refusedFull"', 12: 'ev == "landEnded"'}),
    "bothCopiesHit": (BOTH_HIT, "st.recovered == Set(1) and st.named == 1",
                      {11: 'ev == "refusedSlot"', 16: 'ev == "landEnded"', 20: 'ev == "landEnded"'}),
    "tombCompleted": (EVICTED + ["tombDone(6)"] + TAKEOVER, "st.recovered == Set(2)", {}),
    "tombLanded": (EVICTED + ["landId(6)"] + TAKEOVER, "st.recovered == Set(2) and st.tombs == Set(6)", {}),
    "tombLost": (EVICTED + TAKEOVER, "st.recovered == Set(1, 2) and st.tombs == Set()", {}),
    "chainABC": (PUBLISHED + ["lose", "takeover", "takeover", "fence", "recover"],
                 "st.recovered == Set(1, 2) and st.ten == 3", {}),
    "chainABCevict": (CHAIN_EVICT, 'ev == "landEnded" and st.recovered == Set(1) and st.ten == 3 and st.named == 1', {}),
    "deposedWrites": (DEPOSED, 'ev == "landEnded" and st.recovered == Set(1) and st.named == 0', {}),
    "slotsExhausted": (["fill(0)", "capture", "capture", "capture", "capture"], 'ev == "refusedSlot"', {}),
    "logFull": (LOG_FULL, 'ev == "refusedLog" and st.live.get(0) == 7', {}),
    "payloadFull": (LOG_FULL + ["fill(1)"], 'ev == "refusedFull"', {}),
    # Recovery returns the entry whose eviction tombstone remains incomplete.
    "exhaustedTakeover": (LOG_FULL + ["fill(1)"] + TAKEOVER, "st.recovered == Set(2, 7) and st.named == 1", {}),
    "storeRollback": (ROLLBACK, "st.recovered == Set(1) and st.ten == 4", {}),
    "faultLocal": (PUBLISHED + ["corrupt(1)"] + TAKEOVER, "st.recovered == Set(1) and st.lost == Set(2)", {}),
    "faultLocalRow": (PUBLISHED + ["corrupt(4)"] + TAKEOVER, "st.recovered == Set(1) and st.lost == Set(2)", {}),
    # B crashes before its fence; C's fence ends A's attempt before the recipe offers it.
    "takeoverBeforePreempt": (PREEMPT, 'ev == "landEnded" and st.named == 1', {}),
    # The refill waits for its predecessor's tombstone; the completed tombstone then excludes the predecessor.
    "replaceRefused": (EVICTED + ["fill(0)", "tombDone(6)", "fill(0)"] + TAKEOVER,
                       "st.recovered == Set(2) and st.live.get(0) == 0", {7: 'ev == "refusedReplace"', 9: "st.live.get(0) == 7"}),
    "journalWrap": (JOURNAL_WRAP, "st.recovered == Set(2) and st.tombs == Set(6, 12) and st.own.get(9) == 12",
                    {14: 'ev == "tomb" and st.own.get(9) == 12'}),
    "releaseReuse": (RELEASE_REUSE, "st.recovered == Set()", {10: "st.own.get(0) == 7", 11: "st.own.get(1) == 8"}),
    # The successor crashes after its fence; the next successor recovers the named cut at tenure 3.
    "fencedCrash": (PUBLISHED + ["lose", "takeover", "fence", "lose", "takeover", "fence", "recover"],
                    "st.recovered == Set(1, 2) and st.named == 0 and st.ten == 3", {}),
    "faultRepaired": (PUBLISHED + ["corrupt(1)", "landId(2)"] + TAKEOVER,
                      "st.recovered == Set(1, 2) and st.lost == Set()", {7: "st.corrupted == Set() and st.img.get(1) == 2"}),
    "faultLocalTwo": (PUBLISHED + ["corrupt(1)", "corrupt(4)"] + TAKEOVER,
                      "st.recovered == Set(1) and st.lost == Set(2) and st.corrupted == Set(1, 4)", {}),
    "damageRepairedByFill": (PUBLISHED + ["corrupt(1)"] + TAKEOVER + ["fill(1)"],
                             "st.corrupted == Set() and st.live.get(1) == 6 and st.own.get(1) == 6", {}),
    "rollbackPastReuse": (ROLLBACK_REUSE + ["reopen"] + TAKEOVER[1:], "st.named == 1 and st.recovered == Set() and st.ten == 4",
                          {19: "st.restored and st.named == 0 and st.img.get(0) == 9"}),
    "damageRepairedByCapture": (PUBLISHED + ["corrupt(4)"] + TAKEOVER + ["capture", "applyId(8)", "ackId(8)", "barrier",
                                                                       "capture"],
                                "st.corrupted == Set() and st.img.get(4) == 10", {}),
}
# Runs checked with END = false: each holds the named properties and its outcome without the provider premise.
NO_END_RUNS = {"warmTakeover": "Retained and LossIsFaultLocal and NoResurrection",
               "chainABC": "Retained and LossIsFaultLocal and NoResurrection",
               "fencedCrash": "Retained and LossIsFaultLocal and NoResurrection",
               "faultLocal": "LossIsFaultLocal", "faultLocalRow": "LossIsFaultLocal", "faultLocalTwo": "LossIsFaultLocal",
               "faultRepaired": "LossIsFaultLocal"}
KEPT = "val kept = cut.ws.filter(r => loadable(r, cut.lsn)).map(r => m(r).ref)"
ALL_OR_NOTHING = [(KEPT, "val kept = if (cut.ws.forall(r => m(r).ref == 0 or loadable(r, cut.lsn))) "
                         "cut.ws.filter(r => loadable(r, cut.lsn)).map(r => m(r).ref) else Set()")]
NO_END = [("pure val END = true", "pure val END = false")]
REPLAY_SKIP = [(" or tombVisible(w, l)", "")]
INVALIDATED = ["fill(0)", 'drop(0, "invalidate")', "barrier"]
# Without END the first two captures' row attempts have landed on the reused row units of slots 0 and 1 by this step.
BOTH_HIT_STEP = 20
MUTANTS = {
    "total-eviction": ("LossIsFaultLocal", WARM, [(KEPT, "val kept: Set[int] = Set()")]),
    "all-or-nothing-load": ("LossIsFaultLocal", RUNS["faultLocal"][0], ALL_OR_NOTHING),
    "all-or-nothing-load-row": ("LossIsFaultLocal", RUNS["faultLocalRow"][0], ALL_OR_NOTHING),
    "skipped-tombstone": ("Retained", PUBLISHED + ['drop(0, "evict")', "barrier", "fill(0)"],
                          [('val needsTomb = how == "evict" and inPoss(w)', "val needsTomb = false")]),
    "replay-skips-tombstone": ("NoResurrection", RUNS["tombCompleted"][0], REPLAY_SKIP),
    "replay-skips-landed-tombstone": ("NoResurrection", RUNS["tombLanded"][0], REPLAY_SKIP),
    "reuse-after-grace": ("Retained", ["fill(0)", "capture", "applyId(4)", "ackId(4)", 'drop(0, "invalidate")',
                                       "graceRelease", "fill(1)", "capture", "applyId(8)", "ackId(8)", "landId(1)"],
                          [("pure val GRACE = false", "pure val GRACE = true")]),
    "premise-no-end": ("Retained", PREEMPT, NO_END),
    "barrier-no-end": ("Retained", INVALIDATED + ["fill(0)", "capture", "landId(1)"], NO_END),
    "retained-reads-restored-named": ("Retained", ROLLBACK_REUSE,
                                      [("if (st.named >= 0 and not(st.restored))", "if (st.named >= 0)")]),
    "recover-installs-nothing": ("RecoveredInstalled", WARM,
                                 [("live: KEYS.mapBy(k => kept.fold(0, (a, w) => if (m(w).key == k) w else a))",
                                   "live: KEYS.mapBy(k => 0)")]),
    "preempt-last-owner-only": ("Retained", PREEMPT, [("a.t >= st.ten", "a.t != st.ten - 1")]),
    "fence-keeps-previous": ("Retained", CHAIN_EVICT, [("a.t >= st.ten", "a.t >= st.ten - 1")]),
    "fixed-generation-gap": ("TenureUnique", ROLLBACK[:19],
                             [("ten: st.issued.fold(0, (a, x) => if (x > a) x else a)", "ten: st.snap.ten + 1")]),
    "ancestor-truncation": ("NoResurrection", ANCESTOR, [(".union(required.map(b => (b, st.img.get(b))))", "")]),
    "larger-slots": ("Retained", ["fill(0)"] + [s.format(i) for i in (4, 7) for s in CYCLE]
                     + ["capture", "applyId(10)", "landId(2)"],
                     [("pure val SLOTS = 3", "pure val SLOTS = 4"),
                      ("quar: st.quar.union(out),",
                       "quar: st.quar.union(out.exclude(rows)), free: st.free.union(out.intersect(rows)),")]),
    "partition-overlap": ("Partition", INVALIDATED,
                          [("st.att, free: st.free.union(st.quar), quar: Set()",
                            "st.att, free: st.free.union(st.quar), quar: st.quar")]),
    "refusal-writes": ("RefusalChangesNothing", LOG_FULL,
                       [('tick("refusedLog"), st\' = st }', 'tick("refusedLog"), st\' = { ...st, lsn: st.lsn + 1 } }')]),
    "full-refusal-writes": ("RefusalChangesNothing", RUNS["payloadFull"][0],
                            [('tick("refusedFull"), st\' = st }',
                              'tick("refusedFull"), st\' = { ...st, nextW: st.nextW + 1 } }')]),
    "slot-refusal-writes": ("RefusalChangesNothing", RUNS["slotsExhausted"][0],
                            [('tick("refusedSlot"), st\' = st }',
                              'tick("refusedSlot"), st\' = { ...st, nextW: st.nextW + 1 } }')]),
    "replace-refusal-writes": ("RefusalChangesNothing", EVICTED + ["fill(0)"],
                               [('tick("refusedReplace"), st\' = st }',
                                 'tick("refusedReplace"), st\' = { ...st, nextW: st.nextW + 1 } }')]),
    "replace-before-tombstone": ("NoResurrection", EVICTED + ["fill(0)"] + TAKEOVER,
                                 [("def replacing(k: int): bool = st.pendTomb.exists(t => m(t).key == k)",
                                   "def replacing(k: int): bool = false")]),
    "all-or-nothing-load-two": ("LossIsFaultLocal", RUNS["faultLocalTwo"][0], ALL_OR_NOTHING),
    "journal-no-end": ("NoResurrection", JOURNAL_REUSE, NO_END),
    "barrier-exposes-free": ("FreeUnexposed", INVALIDATED, NO_END),
    "barrier-breaks-agreement": ("AttemptsAgree", INVALIDATED, NO_END),
    "fill-skips-image": ("OwnedIntact", ["fill(0)"], [("img: st.img.set(u, w), own: st.own.set(u, w)", "own: st.own.set(u, w)")]),
    "release-named-rows": ("CutsOwned", PUBLISHED, [("val rows = st.poss.exclude(Set(p.slot))", "val rows = st.poss")]),
    "shrink-drops-named": ("NamedIsPossible", PUBLISHED,
                           [("poss: if (shrink) Set(p.slot) else st.poss", "poss: if (shrink) Set() else st.poss")]),
    "tomb-keeps-head": ("Support", EVICTED, [("nextW: t + 1, lsn: st.lsn + 1,", "nextW: t + 1, lsn: st.lsn,")]),
}
# The landing guard of the free scheduler; the stale-landing witness offers every landing.
LAND_GUARD = [("all { st.img.get(a.unit) != a.id, land(a) }", "land(a)")]
# The issued-id guard of `landId`; without it a Publish id reports an ended attempt.
LAND_ID_GUARD = [("all { i > 0, st.meta.keys().contains(i),", "all { true,")]


def cases(Case):
    yield Case("preserve-typecheck", command="typecheck", family="preserve")
    yield Case("preserve-safety", invariant="safety", family="preserve")
    yield Case("preserve-safety-damage", invariant="safety", family="preserve", settings={"BOUND": DAMAGE_BOUND},
               step="damageStep")
    for witness in WITNESSES:
        yield Case(f"preserve-reach-{witness}", invariant="unreached", expected="violation", family="preserve",
                   mutations=LAND_GUARD if witness == "witnessStaleLanding" else [],
                   extra=f"  val unreached = not({witness})\n")
    for witness in DAMAGE_WITNESSES:
        yield Case(f"preserve-reach-{witness}", invariant="unreached", expected="violation", family="preserve",
                   settings={"BOUND": DAMAGE_BOUND}, step="damageStep", extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome, checks) in RUNS.items():
        if any(not 0 < at <= len(recipe) for at in checks):
            raise ValueError(f"preserve-run-{name}: a check names a turn outside its recipe")
        clauses = "".join(f" and (turn == {at} implies ({check}))" for at, check in sorted(checks.items()))
        yield Case(f"preserve-run-{name}", invariant="runSafety", family="preserve", recipe=recipe,
                   settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome})){clauses}\n")
    for name, props in NO_END_RUNS.items():
        recipe, outcome, checks = RUNS[name]
        clauses = "".join(f" and (turn == {at} implies ({check}))" for at, check in sorted(checks.items()))
        yield Case(f"preserve-run-{name}-no-end", invariant="runNoEnd", family="preserve", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=NO_END,
                   extra=f"  val runNoEnd = {props} and RecoveredInstalled and (turn == {len(recipe)} implies ({outcome})){clauses}\n")
    yield Case("preserve-mutant-both-copies-no-end", invariant="notBothHit", expected="violation", family="preserve",
               recipe=BOTH_HIT[:BOTH_HIT_STEP], settings={"BOUND": str(BOTH_HIT_STEP)}, mutations=NO_END,
               trace=BOTH_HIT_STEP + 1,
               extra=f"  val notBothHit = not(turn == {BOTH_HIT_STEP} and st.img.get(rowUnit(0, 0)) == 2"
                     " and st.img.get(rowUnit(1, 0)) == 5)\n")
    yield Case("preserve-mutant-land-unissued-id", invariant="noEndedLanding", expected="violation", family="preserve",
               recipe=PUBLISHED + ["landId(5)"], settings={"BOUND": str(len(PUBLISHED) + 1)}, mutations=LAND_ID_GUARD,
               trace=len(PUBLISHED) + 2, extra='  val noEndedLanding = ev != "landEnded"\n')
    for name, (prop, recipe, mutations) in MUTANTS.items():
        yield Case(f"preserve-mutant-{name}", invariant=prop, expected="violation", family="preserve", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=mutations, trace=len(recipe) + 1)


def inputs(case, source):
    text = (source / "preserve.qnt").read_text()
    for old, new in case.mutations:
        if text.count(old) != 1:
            raise ValueError(f"{case.name}: mutation target is not unique")
        text = text.replace(old, new)
    bound = case.settings.get("BOUND", CONSTANTS["BOUND"])
    extra = case.extra
    if case.recipe:
        picks = {}
        for at, action in enumerate(case.recipe):
            picks.setdefault(action, []).append(str(at))
        extra += "  action recipe = any {\n" + "".join(
            f'    all {{ Set({", ".join(turns)}).contains(turn), {action} }},\n' for action, turns in picks.items()) + "  }\n"
    return {"preserve.qnt": text,
            "case.qnt": f'module preserveCase {{\n  import preserve(BOUND = {bound}).* from "./preserve"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "preserve.qnt"]
    step = "recipe" if case.recipe else case.step
    return [quint, "verify", "case.qnt", "--main", "preserveCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", step] if step else [])
