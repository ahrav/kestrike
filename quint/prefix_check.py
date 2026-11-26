"""Prefix model cases: typecheck, each safety invariant, reachability witnesses, the directed runs and the planted
mutations.

A run is a recipe of model actions that restricts the scheduler to one schedule; it passes only when TLC checks
`safety` over the whole recipe, one state per action after `init`, and its last state holds the run's outcome.
"""

CONSTANTS = {"BOUND": "8"}
INVARIANTS = ("NamedSlotHoldsItsCapture", "EntriesBounded", "RefusalSubmitsNothing", "NamedIsPossible")
WITNESSES = ("witnessSlotRefused", "witnessEntriesRefused", "witnessShrunk", "witnessCaptured")
SLOT_REFUSAL = 'else if (open.size() == 0) all { tick("refusedSlot"), unchangedHost }'
ENTRIES_REFUSAL = 'if (not(bounded)) all { tick("refusedEntries"), unchangedHost }'
# REFUSAL_FRAME preserves host state while refusal mutations assign `written'` and `submits'`.
REFUSAL_FRAME = ("knownNamed' = knownNamed, knownId' = knownId, possible' = possible, quar' = quar, pending' = pending, "
                 "inflight' = inflight, succeeded' = succeeded, nextId' = nextId, content' = content")
# Each mutation, the invariant it must break, and its replacements of the model's text.
MUTANTS = {
    "placement-ignores-named": ("NamedSlotHoldsItsCapture",
                                ("val open = free(possible.union(quar))", "val open = free(Set())")),
    # Placement against the slot the store names alone overwrites the slot of a Publish still in flight.
    "placement-against-named-only": ("NamedSlotHoldsItsCapture",
                                     ("val open = free(possible.union(quar))", "val open = free(Set(named))")),
    "entries-unchecked": ("EntriesBounded", ("val bounded = entries <= NMAX", "val bounded = true")),
    "refusal-writes": ("RefusalSubmitsNothing",
                       (SLOT_REFUSAL,
                        f'else if (open.size() == 0) all {{ tick("refusedSlot"), {REFUSAL_FRAME}, '
                        "written' = written.union(Set((0, entries, 0))), submits' = submits + 1 }")),
    "entries-refusal-writes": ("RefusalSubmitsNothing",
                               (ENTRIES_REFUSAL,
                                f'if (not(bounded)) all {{ tick("refusedEntries"), {REFUSAL_FRAME}, '
                                "written' = written.union(Set((0, 0, 0))), submits' = submits + 1 }")),
    # A refusal that resubmits a unit already written leaves the set of tuples unchanged and moves the count.
    "refusal-resubmits": ("RefusalSubmitsNothing",
                          (SLOT_REFUSAL,
                           f'else if (open.size() == 0) all {{ tick("refusedSlot"), {REFUSAL_FRAME}, '
                           "written' = written, submits' = submits + 1 }")),
    # A success that shrinks the set while a later own write is unresolved lets that write name a slot outside it.
    "shrink-ignores-later": ("NamedIsPossible",
                               ("val shrink = newest and submitted.forall(q => q == p.id or succeeded.contains(q) or q < p.id)",
                                "val shrink = newest")),
    # A late success of an older write shrinks the set away from the slot a newer write named.
    "shrink-on-stale-success": ("NamedIsPossible", ("val newest = p.at + 1 >= known", "val newest = true")),
    # A Publish whose outcome the host never learns keeps its slot possibly named; dropping it lets the store name a
    # slot outside the set.
    "timeout-frees-slot": ("NamedIsPossible",
                           ("pending' = pending.exclude(Set(p)),\n    known' = known, knownNamed' = knownNamed, knownId' = knownId, possible' = possible,",
                            "pending' = pending.exclude(Set(p)),\n    known' = known, knownNamed' = knownNamed, knownId' = knownId, "
                            "possible' = possible.exclude(Set(p.slot)),")),
}

# Each run, its recipe and the outcome its last state holds.
CXA2F = ["capture(1)", "unresolvedId(1)", "read", "confirm", "applyId(2)", "succeedId(2)", "capture(1)",
         "applyId(1)"]
# A Confirm of slot 1 is delayed while a Publish into slot 0, which the first shrink freed, commits and succeeds, the
# shrink quarantines slot 1 so the next capture takes slot 2, and then the store applies the stale Confirm; only a
# field-scoped condition lets it commit.
CONFIRM_FIELD = ["capture(1)", "applyId(1)", "succeedId(1)", "read", "confirm", "capture(1)", "applyId(3)",
                 "succeedId(3)", "capture(1)", "applyId(2)"]
RUNS = {
    # Two captures fill the slots outside the named one, and the third finds every slot possibly named: it is
    # refused with no unit submitted.
    "slotsExhausted": (["capture(1)", "capture(1)", "capture(1)"], 'ev == "refusedSlot" and written.size() == 2'),
    # A capture within the cap proceeds, and the next, of more entries than the cap, is refused with no unit
    # submitted.
    "entriesAboveCap": (["capture(2)", "capture(3)"], 'ev == "refusedEntries" and written.size() == 1'),
    # A Publish whose reply timed out is still in flight when the host reads the record and its Confirm commits and
    # succeeds; the set shrinks to the named slot, and the delayed Publish then fails on the record version.
    "cxA2": (["capture(1)", "unresolvedId(1)", "read", "confirm", "applyId(2)", "succeedId(2)", "applyId(1)"],
             'ev == "apply" and named == 0 and not(committed.contains(1)) and possible == Set(0)'),
    # As cxA2, and a capture follows the Confirm's success before the store applies the delayed Publish: the shrink
    # quarantined the delayed Publish's slot, so the capture takes the third slot. The model's `unresolved` stands
    # for a timeout and a failure reply alike, so cxA2 and cxA2f cover both.
    "cxA2f": (CXA2F, 'ev == "apply" and named == 0 and content.get(2) == 3 and content.get(1) == 1 '
                     'and quar == Set(1) and not(committed.contains(1))'),
}
# Three captures publish and succeed: the first shrink frees slot 0, which no capture wrote, and the next two shrinks
# quarantine slots 1 and 0, so a fourth capture finds every slot possibly named or quarantined: it is refused, no
# stale attempt can land, and recovery starts warm.
PUBLISHED = ["capture(1)", "applyId({0})", "succeedId({0})"]
QUARANTINED = [step.format(i) for i in (1, 2, 3) for step in PUBLISHED] + ["capture(1)", "recover"]
# The same schedule under a shrink that frees its slots: the third capture reuses slot 1, and an attempt of the first
# capture lands on it after the reusing Publish succeeded.
REUSED = [step.format(i) for i in (1, 2, 3) for step in PUBLISHED] + ["staleOf(1, 1)", "recover"]
STALE_SAFETY = "safety and NoStaleLoad"
QUARANTINE = "quar' = if (shrink) quar.union(possible.exclude(Set(p.slot)).filter(s => written.exists(w => w._1 == s))) else quar,"
COLD = 'recovered\' = if (content.get(named) == namedId) "warm" else "cold",'
# A published capture with no stale attempt recovers warm.
WARM = [step.format(1) for step in PUBLISHED] + ["recover"]

def cases(Case):
    yield Case("prefix-typecheck", command="typecheck", family="prefix")
    yield Case("prefix-safety", invariant="safety", family="prefix")
    for name in INVARIANTS:
        yield Case(f"prefix-{name}", invariant=name, family="prefix")
    for witness in WITNESSES:
        yield Case(f"prefix-reach-{witness}", invariant="unreached", expected="violation", family="prefix",
                   extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(f"prefix-run-{name}", invariant="runSafety", family="prefix", recipe=recipe,
                   settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
    yield Case("prefix-run-cxA2field", invariant="safety", expected="violation", family="prefix", recipe=CXA2F,
               settings={"BOUND": str(len(CXA2F))}, mutations=[("pure val FIELD = false", "pure val FIELD = true")])
    yield Case("prefix-run-confirmExact", invariant="runSafety", family="prefix", recipe=CONFIRM_FIELD,
               settings={"BOUND": str(len(CONFIRM_FIELD))},
               extra=f"  val runSafety = safety and (turn == {len(CONFIRM_FIELD)} implies "
                     "(named == 0 and not(committed.contains(2))))\n")
    yield Case("prefix-run-confirmField", invariant="safety", expected="violation", family="prefix",
               recipe=CONFIRM_FIELD, settings={"BOUND": str(len(CONFIRM_FIELD))},
               mutations=[("pure val FIELD = false", "pure val FIELD = true")])
    yield Case("prefix-run-ceWarm", invariant="runSafety", family="prefix", recipe=WARM,
               settings={"BOUND": str(len(WARM))},
               extra=f'  val runSafety = {STALE_SAFETY} and (turn == {len(WARM)} implies recovered == "warm")\n')
    yield Case("prefix-run-ceE4", invariant="runSafety", family="prefix", recipe=QUARANTINED,
               settings={"BOUND": str(len(QUARANTINED))},
               extra=f"  val runSafety = {STALE_SAFETY} and (turn == {len(QUARANTINED)} implies "
                     '(recovered == "warm" and written.size() == 3 and quar == Set(0, 1)))\n')
    # A shrink that quarantines nothing lets the third capture reuse slot 1, which the first capture wrote, so the
    # first capture's stale unit attempt overwrites the named slot at `staleOf(1, 1)`, before the recovery that
    # `prefix-mutant-shrink-frees-slot-warm` checks.
    yield Case("prefix-mutant-shrink-frees-slot", invariant="NamedSlotHoldsItsCapture", expected="violation",
               family="prefix", recipe=REUSED, settings={"BOUND": str(len(REUSED))},
               mutations=[(QUARANTINE, "quar' = quar,")], trace=REUSED.index("staleOf(1, 1)") + 2)
    yield Case("prefix-mutant-shrink-frees-slot-warm", invariant="NoStaleLoad", expected="violation", family="prefix",
               recipe=REUSED, settings={"BOUND": str(len(REUSED))},
               mutations=[(QUARANTINE, "quar' = quar,"), (COLD, 'recovered\' = "warm",')])
    for name, (prop, *mutations) in MUTANTS.items():
        yield Case(f"prefix-mutant-{name}", invariant=prop, expected="violation", family="prefix", mutations=mutations)


def inputs(case, source):
    text = (source / "prefix.qnt").read_text()
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
    return {"prefix.qnt": text,
            "case.qnt": f'module prefixCase {{\n  import prefix(BOUND = {bound}).* from "./prefix"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "prefix.qnt"]
    return [quint, "verify", "case.qnt", "--main", "prefixCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])
