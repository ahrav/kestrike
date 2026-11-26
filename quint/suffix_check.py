"""Suffix model cases: typecheck, free-scheduler safety, each property, reachability witnesses, the directed runs and
the planted mutations, and the planned exit's drain search from its root with its witnesses, runs and mutants.

The free-scheduler safety check at BOUND 12 reaches tombstone loss, split records, damage below the certified end
and a successor's replay; the NO-SKIP and cross-level supersession hazards need 13 and 14 transitions, so their
coverage comes from the directed runs and mutants below, each checked with `safety` over its whole recipe.

A run is a recipe of model actions that restricts the scheduler to one schedule; it passes only when TLC checks
`safety` over the whole recipe and its last state holds the run's outcome, and the run's reach case shows the recipe
ends in a state holding that outcome. A recipe mutant replaces model text and must violate its named property first
at the last step of its recipe; the runner requires the violation's trace to hold that step's states plus the
initial one.
"""

import importlib.util
from pathlib import Path

# The drain root's instance text comes from the tenure cases' `prefixed`, which the tenure and suffix roots share.
_spec = importlib.util.spec_from_file_location("tenure_checks", Path(__file__).resolve().parent / "tenure_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load tenure_check.py")
tenure_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tenure_checks)
prefixed = tenure_checks.prefixed

CONSTANTS = {"BOUND": "12", "UNCERTIFIED": "4"}
INVARIANTS = ("OneOwner", "ReplayReflectsCut", "NoResurrection", "RecoveredIntact", "Retained", "NoConflict",
              "HistoryNotReused", "InTenureCapacity", "RefusalChangesNothing", "UncertifiedBounded")
# Cases whose cap binds: the default `UNCERTIFIED` of `J` never refuses inside one tenure.
TIGHT = {"UNCERTIFIED": "2"}
WITNESSES = ("witnessRecovered", "witnessDamage", "witnessRefused", "witnessWrapped")
FILL_X = "fill(1, 1, false)"
FILL_Y = "fill(2, 2, false)"
COMPLETE = "nondet b = pending.oneOf() complete(b)"
EVICT_X = "nondet r = live.filter(x => x.key == 1).oneOf() evict(r)"
PUBLISHED_X = [FILL_X, "seal", COMPLETE, "publish"]
# X inserted, replaced on unit 2 by a record split across LSNs 1 and 2, both blocks durable and certified, and a fill
# of key 2 on X's released unit left in the open block after an extension admits it.
SPLIT_TOMB = [FILL_X, "seal", COMPLETE, "nondet r = live.oneOf() replace(r, 2, true)", "seal", COMPLETE, COMPLETE,
              "certify", "extend", "fill(2, 1, false)"]
SPLIT_TOMB_OUTCOME = "damage and recovered.exists(r => r.id == 1 and payload.get(r.unit) != r.id)"
# Each run, its recipe and the outcome its last state holds.
RUNS = {
    # The lost removal record: the tombstone's block never reaches the medium, so its entry stays eligible.
    "tombLost": (PUBLISHED_X + [EVICT_X, "seal", "lose", "recover"],
                 "recovered.size() == 1 and recovered.forall(r => r.key == 1) and not(damage)"),
    # A replacement on another unit whose second block never landed: the old entry stays, the new one is lost, and
    # the key never has two identities.
    "replaceOther": (PUBLISHED_X + ["nondet r = live.oneOf() replace(r, 2, true)", "seal",
                                    "nondet b = pending.filter(b => b.recs.length() == 1).oneOf() land(b)", "lose", "recover"],
                     "recovered.size() == 1 and recovered.forall(r => r.key == 1 and r.unit == 1) and not(damage)"),
    # The same replacement with both blocks durable installs the successor and excludes the predecessor.
    "replaceWhole": (PUBLISHED_X + ["nondet r = live.oneOf() replace(r, 2, true)", "seal",
                                    "nondet b = pending.filter(b => b.lsn == 1).oneOf() complete(b)", COMPLETE, "lose", "recover"],
                     'recovered.size() == 1 and recovered.forall(r => r.key == 1 and r.unit == 2 and r.kind == "rep")'),
    # REMOVE X/1 durable and certified, INSERT Y/1 after it, then the REMOVE's block damaged: Y is behind the hole
    # and does not apply, X resurrects, the damage is accounted and the unit has one owner.
    "removeLostInsertRetained": (PUBLISHED_X + [EVICT_X, "seal", COMPLETE, "certify", "fill(2, 1, false)", "seal", COMPLETE,
                                                "corrupt(1)", "lose", "recover"],
                                 "damage and recovered.size() == 1 and recovered.forall(r => r.key == 1) and not(conflict)"),
    # A record split across two blocks whose second block never landed applies nothing.
    "splitCut": (["fill(1, 1, true)", "seal", "nondet b = pending.filter(b => b.lsn == 0).oneOf() land(b)", "lose", "recover"],
                 "recovered.size() == 0 and not(damage)"),
    # A cut inside the region: the records below it are not replayed, the tombstone above it excludes.
    "midRegion": ([FILL_X, "seal", COMPLETE, FILL_Y, "seal", COMPLETE, "publish",
                   "nondet r = live.filter(x => x.key == 2).oneOf() evict(r)", "seal", COMPLETE, "lose", "recover"],
                  "cut == 2 and recovered.size() == 1 and recovered.forall(r => r.key == 1) and supersededIds.size() == 0"),
    # The head reaches the reserved end: a fill is refused with nothing changed, and an extension admits it.
    "logFull": ([FILL_X, "seal", COMPLETE, FILL_Y, "seal", COMPLETE, EVICT_X, "seal", COMPLETE, FILL_X, "extend", FILL_X],
                'ev == "fill" and lsnHead == 3 and open.length() == 1 and reserved == 4 and live.size() == 2'),
    # B is lost before its block lands; C replays A's suffix and B's, each from its own start.
    "chainABC": ([FILL_X, "seal", COMPLETE, "lose", "recover", FILL_Y, "seal", "lose", "recover"],
                 "recovered.size() == 1 and recovered.forall(r => r.key == 1) and session == 6 and chain.length() == 2"),
    # A successor's block takes the unit of a block below the cut, which no replay needs.
    "ringReuse": (PUBLISHED_X + ["lose", "recover", EVICT_X, "seal", COMPLETE, "fill(1, 2, false)", "seal", COMPLETE, "lose",
                                 "recover"],
                  "replaced == 0 and lsnHead == 5 and recovered.size() == 1 and recovered.forall(r => r.unit == 2)"),
    # The head reaches the floor's capacity: the tenure refuses rather than wrap over required history.
    "wrapRefused": ([FILL_X, "seal", COMPLETE, "lose", "recover", FILL_Y, "seal", COMPLETE, EVICT_X],
                    'ev == "refusedRange" and lsnHead == 4 and reserved == 4 and capacity == 4 and live.size() == 2'),
    # X inserted and evicted in one suffix, Y on X's unit after the certified REMOVE, then the REMOVE's block damaged:
    # Y is dropped behind the hole and named, and X resurrects with its own tombstone's damage accounted.
    "sameLevelDamage": ([FILL_X, "seal", COMPLETE, EVICT_X, "seal", COMPLETE, "certify", "fill(2, 1, false)", "seal",
                         COMPLETE, "corrupt(1)", "lose", "recover"],
                        "damage and recovered.size() == 1 and recovered.forall(r => r.key == 1) and droppedIds.size() == 1"),
    # A whole tombstone behind a hole of its suffix still excludes its entry.
    "frontierBehindHole": (PUBLISHED_X + [FILL_Y, "seal", EVICT_X, "seal",
                                          "nondet b = pending.filter(b => b.lsn == 2).oneOf() land(b)", "lose", "recover"],
                           "recovered.size() == 0 and excludedIds == Set(1)"),
    # A predecessor's certified REMOVE of X is damaged after the successor reused X's unit for Y: Y's later level
    # supersedes the resurrected X, and the damage is accounted.
    "crossLevelDamage": (PUBLISHED_X + [EVICT_X, "seal", COMPLETE, "certify", "lose", "recover", "fill(2, 1, false)", "seal",
                                        COMPLETE, "corrupt(1)", "lose", "recover"],
                         "recovered.size() == 1 and recovered.forall(r => r.key == 2) and supersededIds.size() == 1 "
                         "and not(conflict)"),
    # A predecessor that used every block leaves the successor no capacity: its fill is refused with nothing
    # changed, and its first publish raises the capacity so the next fill is admitted.
    "exhaustedSuccessor": ([FILL_X, "seal", COMPLETE, "extend", FILL_Y, "seal", COMPLETE, EVICT_X, "seal", COMPLETE,
                            "nondet r = live.oneOf() evict(r)", "seal", COMPLETE, "lose", "recover", FILL_X, "publish",
                            "extend", FILL_X],
                           'ev == "fill" and lsnHead == 4 and capacity == 8 and open.length() == 1'),
    # A unit of the predecessor's range holds no block of its LSN: the hole ends that suffix's tail, and the
    # successor's suffix replays from its own start.
    "staleUnit": (PUBLISHED_X + [FILL_Y, "seal", "lose", "recover", FILL_Y, "seal", COMPLETE, "lose", "recover"],
                  "recovered.size() == 2 and recovered.forall(r => r.unit != 2 or r.id == 3)"),
    # A pass whose snapshot member X leaves through a recorded REMOVE above its cut publishes, Y takes X's unit after
    # the REMOVE is durable, and the replay from the pass's cut excludes X and installs Y: one owner, no resurrection.
    "publishAfterRecordedRemoval": ([FILL_X, "seal", COMPLETE, "startPass", EVICT_X, "seal", COMPLETE,
                                     "fill(2, 1, false)", "seal", COMPLETE, "publishPass", "lose", "recover"],
                                    "cut == 1 and base.exists(r => r.key == 1) and recovered.size() == 1 "
                                    "and recovered.forall(r => r.key == 2 and r.unit == 1) and excludedIds == Set(1)"),
    # The head reaches the certified end plus the cap: an eviction is refused with nothing changed, and a certify of
    # the durable prefix admits it.
    "uncertifiedCap": ([FILL_X, "seal", COMPLETE, FILL_Y, "seal", COMPLETE, EVICT_X, "certify", EVICT_X],
                       'ev == "evict" and certified == 2 and lsnHead == 2 and open.length() == 1'),
    # X's certified REMOVE is damaged after a fill took X's unit, and X resurrects over that payload and enters the
    # successor's published cut; a later tenure's landing then replaces the damaged block below the cut, and the next
    # recovery still loads X from the cut with its tombstone's damage on record.
    "damagedTombReused": ([FILL_X, "seal", "publish", EVICT_X, "seal", COMPLETE, COMPLETE, "certify", "fill(2, 1, false)",
                           "corrupt(1)", "lose", "recover", "publish", "lose", "recover", FILL_Y, "seal",
                           "nondet b = pending.oneOf() land(b)", "lose", "recover"],
                          "replaced == 1 and not(damage) and recovered.exists(r => r.key == 1 and payload.get(r.unit) != r.id)"),
    # A split REPLACE of X completes and is certified, a fill takes X's released unit, and the REPLACE's first block
    # is damaged: X resurrects over the fill's payload, excused by its tombstone's first block.
    "splitTombFirstDamaged": (SPLIT_TOMB + ["corrupt(1)", "lose", "recover"], SPLIT_TOMB_OUTCOME),
    # The same with the REPLACE's second block damaged: the exception rests on the tombstone's last block.
    "splitTombLastDamaged": (SPLIT_TOMB + ["corrupt(2)", "lose", "recover"], SPLIT_TOMB_OUTCOME),
    # X's certified REMOVE is damaged after a fill of X's unit stays in the open block, and the successor resurrects
    # X over that payload; the successor removes X again and loses its host before that REMOVE lands, and the next
    # recovery resurrects X once more, with the damaged first tombstone still on record beside the second.
    "removedAgain": ([FILL_X, "seal", COMPLETE, EVICT_X, "seal", COMPLETE, "certify", "fill(2, 1, false)", "lose",
                      "corrupt(1)", "recover", EVICT_X, "seal", "lose", "recover"],
                     "damage and tombAt.get(1).size() == 2 and recovered.exists(r => r.id == 1 and payload.get(r.unit) != r.id)"),
}
# Runs whose recipe needs the binding cap.
RUN_SETTINGS = {"uncertifiedCap": TIGHT}
SKIP_HOLES = ("lsns(ks._2).filter(l => l < firstHole(ks._2))).filter(r => r.kind != \"rem\")",
              "lsns(ks._2)).filter(r => r.kind != \"rem\")")
NO_WITHHOLD = ("val loaded = candidates.filter(p => candidates.forall(q => q == p or q._2.unit != p._2.unit or q._1 < p._1))",
               "val loaded = candidates")
EXCLUDED = "acc.union(recordsOf(ks._2, lsns(ks._2)).filter(r => r.kind != \"ins\").map(r => r.old)))"
# Each mutant: the run whose recipe it follows, the property it must break, and its replacements of the model's text.
MUTANTS = {
    # Inserts behind a hole apply: the resurrected X and the insert behind the hole share a unit at one level.
    "skip-holes": ("sameLevelDamage", "NoConflict", [SKIP_HOLES]),
    # Blind hole skipping with no ownership check loads two owners of one unit.
    "blind-skip": ("sameLevelDamage", "OneOwner", [SKIP_HOLES, NO_WITHHOLD]),
    # A REPLACE cut by a hole excludes its old identity from its first block alone: the entry is lost with no
    # tombstone whole on the medium.
    "partial-record": ("replaceOther", "Retained",
                       [("ls.filter(l => whole(sfx, l))", "ls.filter(l => valid(sfx, l))")]),
    # No record excludes: an entry whose tombstone is whole on the medium recovers.
    "no-exclusion": ("midRegion", "NoResurrection", [(EXCLUDED, "acc)")]),
    # Exclusions apply only before their suffix's first hole: a whole tombstone behind a hole resurrects its entry.
    "frontier-before-hole": ("frontierBehindHole", "NoResurrection",
                             [(EXCLUDED, EXCLUDED.replace("lsns(ks._2))", "lsns(ks._2).filter(l => l < firstHole(ks._2)))"))]),
    # Every shared unit withholds all its owners: the successor's intact entry is lost to a predecessor's damage.
    "withhold-across-levels": ("crossLevelDamage", "Retained", [("q._2.unit != p._2.unit or q._1 < p._1))",
                                                                "q._2.unit != p._2.unit))")]),
    # A successor's capacity ignores the required history below its start: a landing replaces a block the replay
    # needs.
    "wrap-before-floor": ("wrapRefused", "HistoryNotReused",
                          [("val capacityNext = (if (floor < reserved) floor else reserved) + J",
                            "val capacityNext = reserved + J")]),
    # A publish raises the capacity past the tenure's start plus `J`, so the tenure would reuse its own units.
    "rebase-past-start": ("tombLost", "InTenureCapacity",
                          [("val raised = (if (lsnHead < start) lsnHead else start) + J", "val raised = lsnHead + J")]),
    # A recovery installs nothing: a checkpoint entry with no tombstone and no later owner is lost.
    "recover-installs-nothing": ("tombLost", "ReplayReflectsCut",
                                 [("val loaded = candidates.filter(p => candidates.forall(q => q == p or q._2.unit != p._2.unit or q._1 < p._1))",
                                   "val loaded = candidates.filter(p => false)")]),
    # A dropped intact insert is excused by naming it: the hole is placed at the insert itself.
    "drop-intact": ("staleUnit", "Retained",
                    [("recordsOf(ks._2, lsns(ks._2).filter(l => l < firstHole(ks._2))).filter(r => r.kind != \"rem\")",
                      "recordsOf(ks._2, lsns(ks._2).filter(l => l < firstHole(ks._2) and l < 3)).filter(r => r.kind != \"rem\")")]),
    # A refusal empties the live set.
    "refusal-writes": ("wrapRefused", "RefusalChangesNothing",
                       [("sameRecord, sameLive, phase' = phase }",
                         "sameRecord, live' = Set(), ever' = ever, nextId' = nextId, held' = held, payload' = payload, "
                         "sameGhost, phase' = phase }")]),
    # An eviction releases its unit at the append: a fill reuses it while the tombstone is unflushed, and the lost
    # tombstone resurrects an entry whose unit holds the fill's payload.
    "release-before-durable": ("tombLost", "RecoveredIntact",
                               [("        held' = held.union(Set(r.unit)), removedIds' = removedIds.union(Set(r.id)),",
                                 "        held' = held, removedIds' = removedIds.union(Set(r.id)),")]),
}
# The replay of a published pass starts at the head when it publishes, not at the cut its start sealed: the
# snapshot's X, whose REMOVE lies below that head, resurrects on the unit Y's payload took.
MUTANTS["cut-at-publish"] = ("publishAfterRecordedRemoval", "RecoveredIntact",
                             [("cut' = passCut, base' = passBase,", "cut' = lsnHead, base' = passBase,")])
# Appends ignore the certified end: the head runs past the cap.
MUTANTS["cap-skipped"] = ("uncertifiedCap", "UncertifiedBounded",
                          [("last < reserved and last < certified + UNCERTIFIED", "last < reserved")])
# The same early release beside damage to the block before the lost one-block REMOVE: damage to another record's
# block grants X's tombstone no exception.
MUTANTS["release-beside-damage"] = ("tombLost", "RecoveredIntact", MUTANTS["release-before-durable"][2])
# The exception reads one block of a tombstone: damage to the other block of a split tombstone grants none.
TOMB_BLOCKS = "damagedLsns.contains(t._1) or damagedLsns.contains(t._2)"
MUTANTS["tomb-first-block-unread"] = ("splitTombFirstDamaged", "RecoveredIntact",
                                      [(TOMB_BLOCKS, "damagedLsns.contains(t._2)")])
MUTANTS["tomb-last-block-unread"] = ("splitTombLastDamaged", "RecoveredIntact",
                                     [(TOMB_BLOCKS, "damagedLsns.contains(t._1)")])
# The ghost keeps only an id's latest tombstone: the second REMOVE hides the damaged first one, and RecoveredIntact
# refuses the recovery its statement admits.
MUTANTS["forgets-damaged-tombstone"] = ("removedAgain", "RecoveredIntact", [(
    "tombAt.setBy(open[0].old, ts => ts.union(Set((lsnHead, lsnHead + blocks - 1))))",
    "tombAt.put(open[0].old, Set((lsnHead, lsnHead + blocks - 1)))")])
# The recipes the mutants follow where they differ from their run's.
MUTANT_RECIPES = {
    "wrap-before-floor": RUNS["wrapRefused"][0] + ["seal", COMPLETE],
    "rebase-past-start": PUBLISHED_X,
    "cap-skipped": RUNS["uncertifiedCap"][0][:7] + ["seal"],
    "release-before-durable": RUNS["tombLost"][0][:6] + ["fill(2, 1, false)", "seal",
                                                          "nondet b = pending.filter(b => b.lsn == 2).oneOf() land(b)", "lose",
                                                          "recover"],
    "release-beside-damage": [FILL_X, "seal", COMPLETE, "certify", "publish", EVICT_X, "seal", "fill(1, 1, false)",
                              "corrupt(0)", "lose", "recover"],
}


# A planned exit's drain on the free scheduler's records: X and Y inserted with X's block durable, fills stop, the
# drain's publish at the head, X's REMOVE sealed and every block durable and certified, and all mutations stop.
DRAINED = [FILL_X, "seal", COMPLETE, FILL_Y, "seal", "stopFills", "publish", EVICT_X, "seal", COMPLETE, COMPLETE,
           "certify", "stopMutations"]
# The same drain with X's REMOVE sealed and left pending, and its earlier blocks certified.
PENDING_REMOVE = [FILL_X, "seal", COMPLETE, "certify", "stopFills", "publish", EVICT_X, "seal", "stopMutations"]
# Each handoff run: its recipe and the outcome its last state holds.
HANDOFF_RUNS = {
    # The transfer follows the drain's publish and a certify through the head: the recovery after it loads exactly
    # the membership at the withdrawal, Y alone.
    "handoffCutExact": (DRAINED + ["transfer", "recover"],
                        'ev == "handoffRecover" and recovered == prior._1 and recovered.size() == 1 '
                        'and recovered.forall(r => r.key == 2) and not(damage) and excludedIds == Set(1)'),
    # A block of the sealed suffix below the certified end is damaged after the transfer: the replay reports the
    # damage, and X's damaged REMOVE resurrects it.
    "handoffCutDamageReported": (DRAINED + ["transfer", "corrupt(2)", "recover"],
                                 'ev == "handoffRecover" and damage and recovered != prior._1'),
    # The host is lost during the drain, after its publish: the successor recovers as after any host loss.
    "handoffLostDuringDrain": ([FILL_X, "seal", COMPLETE, "stopFills", "publish", EVICT_X, "seal", "lose", "recover"],
                               'ev == "recover" and recovered.size() == 1 and recovered.forall(r => r.key == 1)'),
    # A planned exit resumes before the transfer, and the tenure admits a fill again.
    "handoffResumeAdmitsFill": (["stopFills", "resumeDrain", FILL_X],
                                'ev == "fill" and phase == "serving" and open.length() == 1'),
}
# The drain through all mutations stopped with X's REMOVE in the open block, and the mutation that admits it.
UNSEALED = [FILL_X, "seal", COMPLETE, "certify", "stopFills", "publish", EVICT_X, "stopMutations"]
SEALS_OPEN = ("    val sealed = open.length() == 0\n", "    val sealed = true\n")
# The mutation that stops all mutations without the drain's publish.
SKIPS_PUBLISH = ('phase == "published", sealed, tick("stopMutations"),',
                 'Set("fillsStopped", "published").contains(phase), sealed, tick("stopMutations"),')
# Each handoff mutant: the property it breaks, its recipe and its replacements of the model's text.
HANDOFF_MUTANTS = {
    # The transfer ignores the certified end: X's REMOVE is pending at the withdrawal, the fence ends it, and X
    # resurrects in the recovery after the transfer.
    "transfer-before-certify": ("HandoffCutIsExact", PENDING_REMOVE + ["transfer", "recover"],
                                [("val certifiedThroughHead = certified == lsnHead", "val certifiedThroughHead = true")]),
    # The transfer requires only the durable end at the head: X's REMOVE is durable and uncertified at the transfer.
    "transfer-at-durable-head": ("TransferAtCertifiedHead", PENDING_REMOVE + [COMPLETE, "transfer"],
                                 [("val certifiedThroughHead = certified == lsnHead",
                                   "val certifiedThroughHead = durable == lsnHead")]),
    # The transfer requires the certified end at the durable end, which a pending block keeps below the head.
    "transfer-below-head": ("HandoffCutIsExact", PENDING_REMOVE + ["transfer", "recover"],
                            [("val certifiedThroughHead = certified == lsnHead",
                              "val certifiedThroughHead = certified == durable")]),
    # Mutations stop with X's REMOVE still in the open block: the block never takes an LSN, and X resurrects.
    "transfer-unsealed": ("HandoffCutIsExact", UNSEALED + ["transfer", "recover"], [SEALS_OPEN]),
    # The same transfer breaks the sealed clause at the transfer, with X's REMOVE in the open block.
    "transfer-with-open-block": ("TransferAtCertifiedHead", UNSEALED + ["transfer"], [SEALS_OPEN]),
    # All mutations stop before the drain's publish: X's INSERT lies above the cut at the transfer.
    "transfer-before-publish": ("TransferFollowsPublish", [FILL_X, "seal", COMPLETE, "certify", "stopFills",
                                                           "stopMutations", "transfer"], [SKIPS_PUBLISH]),
    # The same skipped publish under a checkpoint published before fills stopped: X's REMOVE is the one record above
    # that cut, so no INSERT shows the skip, and the exit transfers from a checkpoint its drain never published.
    "transfer-on-earlier-publish": ("TransferFollowsPublish", [FILL_X, "seal", COMPLETE, "certify", "publish",
                                                               "stopFills", EVICT_X, "seal", COMPLETE, "certify",
                                                               "stopMutations", "transfer"], [SKIPS_PUBLISH]),
    # A fill is admitted after the drain's publish: its INSERT lies above the cut at the transfer.
    "fill-after-stop": ("TransferFollowsPublish", ["stopFills", "publish", FILL_X, "seal", COMPLETE, "certify",
                                                   "stopMutations", "transfer"],
                        [('phase == "serving", open.length() == 0, not(owned.contains(u)), live.forall(x => x.key != k),',
                          'appending, open.length() == 0, not(owned.contains(u)), live.forall(x => x.key != k),')]),
    # The transfer ignores the certified end and the recovery reports damage where no fault damaged a block: X
    # resurrects under a damage report that names no fault.
    "transfer-before-certify-reports-damage": ("HandoffCutIsExact", PENDING_REMOVE + ["transfer", "recover"],
                                               [("val certifiedThroughHead = certified == lsnHead",
                                                 "val certifiedThroughHead = true"),
                                                ("recovered' = loaded.map(p => p._2), damage' = damaged,",
                                                 "recovered' = loaded.map(p => p._2), damage' = true,")]),
    # The recovery reports no damage after a fault damaged X's REMOVE below the certified end, and X resurrects.
    "handoff-damage-unreported": ("HandoffCutIsExact", DRAINED + ["transfer", "corrupt(2)", "recover"],
                                  [("recovered' = loaded.map(p => p._2), damage' = damaged,",
                                    "recovered' = loaded.map(p => p._2), damage' = false,")]),
}
# The planned exit's search root: X durable and certified, then the drain scheduler for its turns.
DRAIN_ROOT = [FILL_X, "seal", COMPLETE, "certify"]
DRAIN_TURNS = 10


def run_cases(Case, name, recipe, outcome, settings, trace=None):
    """Run `name`'s two cases: `safety` and the outcome over the whole recipe, and the reach case that shows the
    recipe ends in a state holding the outcome, whose trace holds `trace` states when set."""
    yield Case(f"suffix-run-{name}", invariant="runSafety", family="suffix", recipe=recipe, settings=settings,
               extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
    yield Case(f"suffix-run-{name}-reached", invariant="unreached", expected="violation", family="suffix",
               recipe=recipe, settings=settings, trace=trace,
               extra=f"  val unreached = not(turn == {len(recipe)} and ({outcome}))\n")


def handoff_cases(Case):
    """The planned exit's cases: the drain root, which must reach its last turn, its witnesses, which must hold
    after the root's prefix, the runs, whose reach cases hold the whole recipe, and the mutants."""
    bound = len(DRAIN_ROOT) + DRAIN_TURNS
    settings = {"BOUND": str(bound)}
    extra = prefixed(DRAIN_ROOT, "drainStep")
    yield Case("suffix-handoff-safety", invariant="safety", family="suffix", step="prefixed", settings=settings,
               extra=extra, depth=bound + 1)
    for witness in ("witnessHandoffRecovered", "witnessHandoffDamage", "witnessHandoffSuffixReplayed"):
        yield Case(f"suffix-handoff-reach-{witness}", invariant="unreached", expected="violation", family="suffix",
                   step="prefixed", settings=settings, after=len(DRAIN_ROOT) + 1,
                   extra=extra + f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in HANDOFF_RUNS.items():
        yield from run_cases(Case, name, recipe, outcome, {"BOUND": str(len(recipe))}, trace=len(recipe) + 1)
    for name, (prop, recipe, mutations) in HANDOFF_MUTANTS.items():
        yield Case(f"suffix-mutant-{name}", invariant=prop, expected="violation", family="suffix", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=mutations, trace=len(recipe) + 1)


def cases(Case):
    yield Case("suffix-typecheck", command="typecheck", family="suffix")
    yield Case("suffix-safety", invariant="safety", family="suffix")
    for name in INVARIANTS:
        tight = TIGHT if name == "UncertifiedBounded" else {}
        yield Case(f"suffix-{name}", invariant=name, family="suffix", settings={"BOUND": "9", **tight})
    for witness in WITNESSES:
        yield Case(f"suffix-reach-{witness}", invariant="unreached", expected="violation", family="suffix",
                   settings={"BOUND": "9"}, extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield from run_cases(Case, name, recipe, outcome, {"BOUND": str(len(recipe)), **RUN_SETTINGS.get(name, {})})
    for name, (run, prop, mutations) in MUTANTS.items():
        recipe = MUTANT_RECIPES.get(name, RUNS[run][0])
        yield Case(f"suffix-mutant-{name}", invariant=prop, expected="violation", family="suffix", recipe=recipe,
                   settings={"BOUND": str(len(recipe)), **RUN_SETTINGS.get(run, {})}, mutations=mutations,
                   trace=len(recipe) + 1)
    yield from handoff_cases(Case)


def inputs(case, source):
    text = (source / "suffix.qnt").read_text()
    for old, new in case.mutations:
        if text.count(old) != 1:
            raise ValueError(f"{case.name}: mutation target is not unique")
        text = text.replace(old, new)
    bound = case.settings.get("BOUND", CONSTANTS["BOUND"])
    cap = case.settings.get("UNCERTIFIED", CONSTANTS["UNCERTIFIED"])
    extra = case.extra
    if case.recipe:
        picks = {}
        for at, action in enumerate(case.recipe):
            picks.setdefault(action, []).append(str(at))
        extra += "  action recipe = any {\n" + "".join(
            f'    all {{ Set({", ".join(turns)}).contains(turn), {action} }},\n' for action, turns in picks.items()) + "  }\n"
    return {"suffix.qnt": text,
            "case.qnt": f'module suffixCase {{\n  import suffix(BOUND = {bound}, UNCERTIFIED = {cap}).* from "./suffix"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "suffix.qnt"]
    return [quint, "verify", "case.qnt", "--main", "suffixCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else ["--step", case.step] if case.step else [])
