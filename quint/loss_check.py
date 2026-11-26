"""Check the finite volume-loss model: safety from each root, a reachability witness per path, directed runs, at least one mutation per statement of each invariant and the Rust replay of its regenerated traces."""

# The ignored test that regenerates the traces `loss_fixtures.py` declares, requires them to equal the committed ones
# and replays them against the reconciler.
REPLAY_TEST = "failover::reconcile_tests::loss_replay::generated_loss_traces_replay"
CONSTANTS = {"BOUND": "9"}


def op(proc, name, shard, requests):
    """The actions of one step of process `proc`: its start and `requests` store requests."""
    return [f'begin({proc}, "{name}", {shard})'] + [f"request({proc})"] * requests


# Shard 1 has an open receipt.
OPENED = ["lose(1)"] + op(1, "replacement", 1, 3)
# Reconciler 1 stands at the provider call of the issued attempt 1.
ISSUED = OPENED + op(1, "create", 1, 3)
# Reconciler 1's provider call creates volume 3.
CREATED = ISSUED + ['call(1, "make", true)', "request(1)", "request(1)"]
# Reconciler 1's flip step named volume 3 the spare of shard 1.
SPARED = CREATED + op(1, "flip", 1, 4)
# Shard 1 has a held receipt.
HELD = ["lose(1)", "impair(2)"] + op(1, "replacement", 1, 3)
# The operator released the hold of shard 1's receipt while volume 2 stays impaired.
RELEASED = HELD + op(0, "release", 1, 2)
# Reconciler 2 latched the hold while reconciler 1 stands at its provider call.
LATCHED = ISSUED + ["impair(2)"] + op(2, "create", 1, 2)
# Reconciler 2 latched the hold over the receipt that records volume 3.
COVERED = CREATED + ["impair(2)"] + op(2, "create", 1, 2)
# Reconciler 1's abandon step stands at the retirement write of volume 3.
FAILED = CREATED + ["lose(3)"] + op(1, "abandon", 1, 3)
# Reconciler 2's flip step stands at its spare write while reconciler 1 stands at the retirement write.
RACING = FAILED + op(2, "flip", 1, 3)
FLIP = op(1, "flip", 1, 9)
# Reconciler 1's flip stands at its receipt recheck after its fence raised the version of volume 3's record, which the
# control plane reported lost.
FENCED = CREATED + ["lose(3)"] + op(1, "flip", 1, 7)
# Reconciler 1's flip activated volume 3 after the control plane reported it lost.
FLIPPED = CREATED + ["lose(3)"] + FLIP
# Reconciler 2 stands at its provider call under attempt 1's token after reconciler 1 recorded volume 3, the control
# plane reported it lost, and reconciler 1 retired it and opened attempt 2.
STALE = (ISSUED + op(2, "create", 1, 2) + ['call(1, "make", true)', "request(1)", "request(1)", "lose(3)"]
         + op(1, "abandon", 1, 7))
# Both reconcilers' flips of volume 3 stand at their flip writes.
DUELING = CREATED + op(1, "flip", 1, 8) + op(2, "flip", 1, 6)
# Each root pairs a fixed action prefix with the number of free actions its search takes after that prefix.
ROOTS = {
    "init": ([], 13),
    "opened": (OPENED, 9),
    "issued": (ISSUED, 9),
    "created": (CREATED, 9),
    "spared": (SPARED, 9),
    "held": (HELD, 9),
    "released": (RELEASED, 9),
    "latched": (LATCHED, 9),
    "covered": (COVERED, 9),
    "failed": (FAILED, 9),
    "racing": (RACING, 9),
    "fenced": (FENCED, 9),
    "flipped": (FLIPPED, 9),
    "dueling": (DUELING, 9),
    "stale": (STALE, 9),
}
ALL_IDLE = "PROCS.forall(p => st.procs.get(p) == IDLE)"
# The state each nonempty root's prefix leaves, checked at the prefix's last turn of its safety search.
STANDS = {
    "opened": "st.rcpts.get(1) == {exists: true, attempt: 1, phase: \"open\", vol: 0, held: false, released: false, "
              f"ver: 1}} and {ALL_IDLE}",
    "issued": 'st.rcpts.get(1).phase == "issued" and st.procs.get(1).pc == "call" and st.procs.get(1).rc.attempt == 1',
    "created": 'st.rcpts.get(1).phase == "created" and st.rcpts.get(1).vol == 3 '
               f"and st.vrecs.get(3).state == PROVISIONED and {ALL_IDLE}",
    "spared": 'st.shards.get(1).spare == 3 and st.procs.get(1).op == "flip" and st.procs.get(1).pc == "reread"',
    "held": f'st.rcpts.get(1).held and st.rcpts.get(1).phase == "open" and {ALL_IDLE}',
    "released": "st.rcpts.get(1).released and not(st.rcpts.get(1).held) and st.vols.get(2).health == IMPAIRED "
                f"and {ALL_IDLE}",
    "latched": 'st.rcpts.get(1).held and st.rcpts.get(1).phase == "issued" and st.procs.get(1).pc == "call" '
               "and st.procs.get(2) == IDLE",
    "covered": 'st.rcpts.get(1).held and st.rcpts.get(1).phase == "created" and st.rcpts.get(1).vol == 3 '
               f"and {ALL_IDLE}",
    "failed": 'st.procs.get(1).op == "abandon" and st.procs.get(1).pc == "retire" and st.procs.get(1).vol == 3',
    "racing": 'st.procs.get(1).pc == "retire" and st.procs.get(1).vol == 3 and st.procs.get(2).op == "flip" '
              'and st.procs.get(2).pc == "spare" and st.procs.get(2).vol == 3',
    "fenced": 'st.procs.get(1).op == "flip" and st.procs.get(1).pc == "recheck" and st.shards.get(1).spare == 3 '
              "and st.vrecs.get(3) == {state: PROVISIONED, ver: 2} and st.vols.get(3).health == LOST",
    "flipped": "st.shards.get(1).g == 2 and st.shards.get(1).active == 3 and st.vols.get(3).health == LOST "
               f"and {ALL_IDLE}",
    "dueling": 'PROCS.exclude(Set(OPERATOR)).forall(p => st.procs.get(p).op == "flip" and st.procs.get(p).pc == "flip" '
               "and st.procs.get(p).vol == 3) and st.shards.get(1).g == 1 and st.shards.get(1).spare == 3",
    "stale": 'st.procs.get(2).pc == "call" and st.procs.get(2).rc.attempt == 1 and st.procs.get(1) == IDLE '
             'and st.rcpts.get(1).attempt == 2 and st.rcpts.get(1).phase == "open" '
             "and st.vrecs.get(3).state == RETIRED",
}
# Each root's search must reach every witness mapped to that root.
WITNESSES = {
    "witnessHostLossRetains": "init",
    "witnessImpairedRetains": "init",
    "witnessIsolatedStart": "init",
    "witnessCorrelatedStart": "init",
    "witnessLatchDue": "opened",
    "witnessReplacementLatch": "opened",
    "witnessCreateLatch": "opened",
    "witnessHeldRefused": "held",
    "witnessHoldOutlivesRecovery": "held",
    "witnessRelease": "held",
    "witnessCreateAfterRelease": "latched",
    "witnessOpensOverReleased": "released",
    "witnessCallOverLatchedHold": "latched",
    "witnessIssued": "opened",
    "witnessMade": "issued",
    "witnessProviderFailed": "issued",
    "witnessMadeUnknown": "issued",
    "witnessKeptVolume": "issued",
    "witnessKeptFailed": "issued",
    "witnessStaleToken": "stale",
    "witnessRecorded": "issued",
    "witnessRecordRefused": "latched",
    "witnessFailedRaise": "issued",
    "witnessCrash": "opened",
    "witnessUnknownWrite": "opened",
    "witnessRetired": "failed",
    "witnessAbandoned": "failed",
    "witnessAbandonOpensHeld": "failed",
    "witnessNextTokenMakes": "failed",
    "witnessAbandonReplayed": "failed",
    "witnessAbandonHeld": "failed",
    "witnessProvisionFound": "issued",
    "witnessProvisionRetired": "stale",
    "witnessSpareNamed": "created",
    "witnessFlipOverNamedSpare": "spared",
    "witnessFlipped": "spared",
    "witnessFlipRefused": "dueling",
    "witnessFenceRefusesRetire": "racing",
    "witnessFlipRefusesHeld": "covered",
    "witnessBothHeld": "held",
    "witnessAbandonNamedActive": "flipped",
    "witnessAbandonNamedSpare": "fenced",
    "witnessReleaseAbsent": "init",
    "witnessReleaseUnheld": "opened",
}
# Each directed run and the state its last action must reach.
RUNS = {
    "loss-run-host-loss": (
        ["hostLoss(1)"] + op(1, "replacement", 1, 1) + op(2, "create", 1, 1) + op(1, "abandon", 1, 1),
        "not(st.rcpts.get(1).exists) and st.calls == Set() and st.shards.get(1).g == 1"),
    "loss-run-isolated-replacement": (
        ISSUED + ['call(1, "make", false)'] + op(2, "create", 1, 2) + ['call(2, "make", true)', "request(2)",
                                                                       "request(2)"] + FLIP,
        "st.shards.get(1) == {g: 2, active: 3, spare: 0, ver: 3} and st.made.size() == 1 "
        "and st.rcpts.get(1).attempt == 1"),
    "loss-run-correlated-release": (
        HELD + op(1, "create", 1, 1) + ["recover(2)"] + op(1, "create", 1, 1) + op(0, "release", 1, 2)
        + op(1, "create", 1, 3) + ['call(1, "make", true)', "request(1)", "request(1)"] + FLIP,
        "st.shards.get(1).active == 3 and st.rcpts.get(1).released and not(st.rcpts.get(1).held)"),
    "loss-run-latch-after-issue": (
        LATCHED + ['call(1, "make", true)', "request(1)", "request(1)"] + op(2, "create", 1, 1)
        + op(0, "release", 1, 2) + op(2, "create", 1, 2) + ['call(2, "make", true)', "request(2)", "request(2)",
                                                            "request(2)"],
        'st.rcpts.get(1).phase == "created" and st.rcpts.get(1).vol == 3 and st.rcpts.get(1).released '
        "and st.made.size() == 1"),
    "loss-run-stale-token": (
        STALE + ['call(2, "make", true)', "request(2)", "request(2)", "request(2)"],
        'st.ev.pc == "reread" and st.ev.res == "stale" and st.rcpts.get(1).attempt == 2 and st.made.size() == 1'),
    "loss-run-crash-at-call": (
        ISSUED + ["crash(1)"] + op(2, "create", 1, 2) + ['call(2, "make", true)', "request(2)", "request(2)"],
        'st.rcpts.get(1).attempt == 1 and st.rcpts.get(1).phase == "created" and st.rcpts.get(1).vol == 3 '
        "and st.made == Set({shard: 1, attempt: 1, vol: 3})"),
    "loss-run-retirement": (
        CREATED + ["lose(3)"] + op(1, "abandon", 1, 7) + op(1, "create", 1, 3) + ['call(1, "fail", true)', "request(1)"]
        + op(1, "create", 1, 3) + ['call(1, "make", true)', "request(1)", "request(1)"] + FLIP,
        "st.shards.get(1).active == 4 and st.rcpts.get(1).attempt == 3 and st.vrecs.get(3).state == RETIRED"),
}
# Each directed run's intermediate checks: the turn after an action and the state it must reach.
CHECKPOINTS = {
    "loss-run-isolated-replacement": [
        (len(ISSUED) + 1, 'st.ev.act == "call" and st.ev.res == "unknown" and not(st.ev.kept) '
                          'and st.made == Set({shard: 1, attempt: 1, vol: 3}) and st.rcpts.get(1).phase == "issued"'),
        (len(ISSUED) + 5, 'st.ev.act == "call" and st.ev.proc == 2 and st.ev.kept and st.ev.res == "volume" '
                          "and st.made.size() == 1 and st.procs.get(2).vol == 3"),
    ],
    "loss-run-crash-at-call": [
        (len(ISSUED) + 1, 'st.ev.act == "crash" and st.ev.proc == 1 and st.procs.get(1) == IDLE '
                          'and st.rcpts.get(1).phase == "issued" and st.calls == Set() and st.made == Set()'),
    ],
}
# Each invariant `safety` conjoins and the statements it conjoins in turn; an invariant with none is one statement.
CLAUSES = {
    "HostLossCreatesNothing": ("receiptNeedsLoss", "callNeedsLoss", "flipNeedsLoss"),
    "CorrelatedHold": ("opensHeld", "latchFollows", "latchKeeps", "callNeedsIsolation", "holdNeedsImpairment"),
    "HeldReadCreatesNothing": (),
    "OnlyOperatorReleases": ("clearIsRelease", "markIsRelease"),
    "ReleaseIsFinal": ("releasedUnheld", "releaseStays"),
    "CreateAfterIssue": ("callCarriesIssued", "callFollowsIssue"),
    "OneVolumePerToken": (),
    "AttemptAdvancesOnlyOnTerminal": ("advanceIsTerminal", "retiredIsLost"),
    "EveryVolumeRecorded": ("madeIsRecorded", "createdIsMade", "recordedHasRecord"),
    "ActivatesOnlyUnheld": ("spareReadUnheld", "flipReadUnheld", "activeNotRetired", "activatesOnce"),
}
INVARIANTS = tuple(CLAUSES)
STATEMENTS = tuple(statement for invariant, clauses in CLAUSES.items() for statement in clauses or (invariant,))
# The witnesses that reach the states each statement constrains: the left side of its implication, or a member of the
# set it ranges over.
REACHED_BY = {
    "receiptNeedsLoss": ("witnessIsolatedStart", "witnessHostLossRetains", "witnessImpairedRetains"),
    "callNeedsLoss": ("witnessMade",),
    "flipNeedsLoss": ("witnessFlipped",),
    "opensHeld": ("witnessCorrelatedStart", "witnessAbandonOpensHeld"),
    "latchFollows": ("witnessLatchDue",),
    "latchKeeps": ("witnessReplacementLatch", "witnessCreateLatch"),
    "callNeedsIsolation": ("witnessCreateAfterRelease",),
    "holdNeedsImpairment": ("witnessCorrelatedStart", "witnessReplacementLatch", "witnessCreateLatch",
                            "witnessAbandonOpensHeld"),
    "HeldReadCreatesNothing": ("witnessMade", "witnessCallOverLatchedHold"),
    "clearIsRelease": ("witnessRelease",),
    "markIsRelease": ("witnessRelease",),
    "releasedUnheld": ("witnessRelease", "witnessOpensOverReleased"),
    "releaseStays": ("witnessOpensOverReleased",),
    "callCarriesIssued": ("witnessMade",),
    "callFollowsIssue": ("witnessMade", "witnessKeptVolume"),
    "OneVolumePerToken": ("witnessKeptVolume", "witnessMadeUnknown"),
    "advanceIsTerminal": ("witnessFailedRaise", "witnessAbandoned", "witnessProvisionRetired"),
    "retiredIsLost": ("witnessRetired",),
    "madeIsRecorded": ("witnessNextTokenMakes", "witnessStaleToken"),
    "createdIsMade": ("witnessRecorded",),
    "recordedHasRecord": ("witnessRecorded",),
    "spareReadUnheld": ("witnessSpareNamed",),
    "flipReadUnheld": ("witnessFlipped",),
    "activeNotRetired": ("witnessFlipped", "witnessAbandonNamedActive"),
    "activatesOnce": ("witnessFlipped", "witnessFlipRefused"),
}
EVIDENCE = "= p.lost.contains(rec.active)"
LATCH = 'else if (p.others > 0 and not(r.released) and not(r.held)) go({...p, rc: r}, "latch")'
HOLD = 'else if (p.others > 0 and not(r.released)) go({...p, rc: r}, "hold")'
START_WRITE = "held: p.others > 0, released: false, ver: 1}"
LATCH_WRITE = 'else if (p.pc == "latch") {...p.rc, held: true'
HOLD_WRITE = 'else if (p.pc == "hold") {...p.rc, held: true'
RECORD_WRITE = '{...p.rc, phase: "created", vol: p.vol, ver: p.rc.ver + 1}'
RELEASE_WRITE = "{...p.rc, held: false, released: true, ver: p.rc.ver + 1}"
NEXT_HOLD = "held: others > 0 and not(r.released)"
KNOWN = "val known = st.prov.keys().contains(t)"
NAMED = "if (rec.active == p.vol or rec.spare == p.vol)"
LOST_REPLY = "val after = if (not(reply)) IDLE"
FENCE_ACK = 'else if (p.pc == "fence") go({...p, vver: 0, rc: NONE}, "recheck")'
FENCE_SKIPS_RECHECK = (FENCE_ACK, 'else if (p.pc == "fence") go({...p, vver: 0, rc: NONE}, "flip")')
HOST_LOSS_EVIDENCE = [(EVIDENCE, "= p.lost.contains(rec.active) or s.hostLost.contains(p.shard)")]
# Each mutation names the statement it breaks, the root whose search must find the violation, and its replacements.
MUTANTS = {
    "decide-reads-host-loss": ("receiptNeedsLoss", "init", HOST_LOSS_EVIDENCE),
    "decide-reads-impairment": ("receiptNeedsLoss", "init", [(
        EVIDENCE, "= p.lost.contains(rec.active) or s.vols.get(rec.active).health == IMPAIRED")]),
    "create-ignores-absent": ("callNeedsLoss", "init", [(
        'if (not(r.exists)) done("absent")\n      else if (r.held) done("held")', 'if (r.held) done("held")')]),
    "start-opens-unheld": ("opensHeld", "init", [(START_WRITE, "held: false, released: false, ver: 1}")]),
    "next-attempt-opens-unheld": ("opensHeld", "failed", [(NEXT_HOLD, "held: false")]),
    "create-ignores-others": ("latchFollows", "issued", [(HOLD, "")]),
    "replacement-skips-latch": ("latchFollows", "opened", [(LATCH + "\n      ", "")]),
    "hold-drops-volume": ("latchKeeps", "created", [(
        HOLD_WRITE + ", ver: p.rc.ver + 1}", HOLD_WRITE + ', phase: "issued", vol: 0, ver: p.rc.ver + 1}')]),
    "latch-drops-volume": ("latchKeeps", "created", [(
        LATCH_WRITE + ", ver: p.rc.ver + 1}", LATCH_WRITE + ', phase: "issued", vol: 0, ver: p.rc.ver + 1}')]),
    "latch-writes-unheld": ("latchKeeps", "opened", [(LATCH_WRITE, 'else if (p.pc == "latch") {...p.rc, held: p.rc.held')]),
    "hold-writes-unheld": ("latchKeeps", "opened", [(HOLD_WRITE, 'else if (p.pc == "hold") {...p.rc, held: p.rc.held')]),
    "hold-continues-to-call": ("callNeedsIsolation", "issued", [(
        'else if (p.pc == "latch" or p.pc == "hold") done("held")',
        'else if (p.pc == "latch") done("held")\n    else if (p.pc == "hold") go(p, "shard")')]),
    "others-forced-to-zero": ("callNeedsIsolation", "opened", [("others: seen, seen: seen", "others: 0, seen: seen")]),
    "start-holds-isolated": ("holdNeedsImpairment", "init", [(START_WRITE, "held: true, released: false, ver: 1}")]),
    "replacement-latches-isolated": ("holdNeedsImpairment", "opened", [(
        LATCH, 'else if (not(r.released) and not(r.held)) go({...p, rc: r}, "latch")')]),
    "create-holds-isolated": ("holdNeedsImpairment", "opened", [(
        HOLD, 'else if (not(r.released)) go({...p, rc: r}, "hold")')]),
    "next-attempt-holds-isolated": ("holdNeedsImpairment", "issued", [(NEXT_HOLD, "held: not(r.released)")]),
    "create-ignores-held": ("HeldReadCreatesNothing", "held", [('else if (r.held) done("held")\n', "")]),
    "isolated-observation-clears-hold": ("clearIsRelease", "held", [
        (LATCH, 'else if (not(r.released) and (p.others > 0) != r.held) go({...p, rc: r}, "latch")'),
        (LATCH_WRITE, 'else if (p.pc == "latch") {...p.rc, held: p.others > 0')]),
    "release-leaves-unmarked": ("clearIsRelease", "held", [(
        RELEASE_WRITE, "{...p.rc, held: false, released: false, ver: p.rc.ver + 1}")]),
    "release-drops-volume": ("clearIsRelease", "covered", [(
        RELEASE_WRITE, '{...p.rc, held: false, released: true, phase: "issued", vol: 0, ver: p.rc.ver + 1}')]),
    "release-unheld": ("markIsRelease", "opened", [(
        'else if (r.held) go({...p, rc: r}, "release") else done("unheld")', 'else go({...p, rc: r}, "release")')]),
    "release-keeps-hold": ("markIsRelease", "held", [(
        RELEASE_WRITE, "{...p.rc, held: true, released: true, ver: p.rc.ver + 1}")]),
    "reconciler-releases": ("markIsRelease", "held", [('(p == OPERATOR) == (op == "release"), ', "")]),
    "next-attempt-ignores-release": ("releasedUnheld", "released", [(NEXT_HOLD, "held: others > 0")]),
    "latch-ignores-release": ("releasedUnheld", "released", [(
        LATCH, 'else if (p.others > 0 and not(r.held)) go({...p, rc: r}, "latch")')]),
    "hold-ignores-release": ("releasedUnheld", "released", [(HOLD, 'else if (p.others > 0) go({...p, rc: r}, "hold")')]),
    "next-attempt-drops-release": ("releaseStays", "released", [(
        NEXT_HOLD + ", ver", NEXT_HOLD + ", released: false, ver")]),
    "create-calls-over-created": ("callCarriesIssued", "created", [(
        'if (p.rc.phase == "created") done(if (rec.g == 1) "created" else "stale")\n      else if (p.rc.phase == "open")',
        'if (p.rc.phase == "open")')]),
    "create-skips-issue": ("callFollowsIssue", "opened", [(
        '(if (rec.g == 1) go(p, "issue") else done("stale"))', '(if (rec.g == 1) go(p, "call") else done("stale"))')]),
    "provider-forgets-tokens": ("OneVolumePerToken", "issued", [(KNOWN, "val known = false")]),
    "abandon-skips-retire": ("advanceIsTerminal", "created", [(
        'if (vrec.state == RETIRED) go(p, "current") else go({...p, vver: vrec.ver}, "named")', 'go(p, "current")')]),
    "dropped-create-raises-attempt": ("advanceIsTerminal", "issued", [(
        LOST_REPLY, 'val after = if (not(reply)) {...proc, pc: "raise"}')]),
    "provision-overwrites-record": ("advanceIsTerminal", "stale", [(
        "s.vrecs.get(p.vol).state == ABSENT\n", "true\n")]),
    "abandon-ignores-loss": ("retiredIsLost", "created", [(' and p.lost.contains(r.vol)', "")]),
    "unknown-raises-attempt": ("madeIsRecorded", "issued", [(
        LOST_REPLY, 'val after = if (not(reply)) {...proc, pc: "raise"}')]),
    "provider-forgets-refusals": ("madeIsRecorded", "issued", [(
        KNOWN, KNOWN + ' and not(st.prov.get(t).kind == "failed" '
        "and proc.rc.attempt < st.rcpts.get(proc.shard).attempt)")]),
    "record-writes-another-volume": ("createdIsMade", "issued", [(
        RECORD_WRITE, '{...p.rc, phase: "created", vol: p.shard, ver: p.rc.ver + 1}')]),
    "record-skips-provision": ("recordedHasRecord", "issued", [(
        'else if (out.kind == "volume") {...proc, pc: "provision", vol: out.vol}',
        'else if (out.kind == "volume") {...proc, pc: "record", vol: out.vol}')]),
    "spare-skips-receipt-read": ("spareReadUnheld", "created", [('else go(p, "receipt")', 'else go(p, "spare")')]),
    "held-check-ignores-hold": ("spareReadUnheld", "covered", [(
        '= r.held and r.phase == "created" and r.vol == vol', "= false")]),
    "spare-ignores-hold": ("spareReadUnheld", "covered", [(
        'if (heldAt(r, p.vol)) done("held") else go({...p, rc: r}, "spare")', 'go({...p, rc: r}, "spare")')]),
    "flip-ignores-hold": ("flipReadUnheld", "spared", [(
        'if (heldAt(r, p.vol)) done("held") else go({...p, rc: r}, "flip")', 'go({...p, rc: r}, "flip")')]),
    "flip-skips-recheck": ("flipReadUnheld", "spared", [FENCE_SKIPS_RECHECK]),
    "flip-rechecks-before-fence": ("flipReadUnheld", "spared", [
        ('if (vrec.state == PROVISIONED) go({...p, vver: vrec.ver}, "fence") else done("conflict")',
         'if (heldAt(r, p.vol)) done("held")\n      else if (vrec.state == PROVISIONED) go({...p, vver: vrec.ver, rc: r}, "fence") '
         'else done("conflict")'),
        FENCE_SKIPS_RECHECK]),
    "flip-skips-fence": ("activeNotRetired", "racing", [(
        'go({...p, vver: vrec.ver}, "fence")', 'go({...p, vver: vrec.ver}, "recheck")')]),
    "abandon-retires-active": ("activeNotRetired", "flipped", [(NAMED, "if (rec.spare == p.vol)")]),
    "abandon-retires-spare": ("activeNotRetired", "fenced", [(NAMED, "if (rec.active == p.vol)")]),
    "flip-write-ignores-version": ("activatesOnce", "dueling", [(
        "else s.shards.get(p.shard).ver == p.sver\n", 'else p.pc == "flip" or s.shards.get(p.shard).ver == p.sver\n')]),
}
# Each recipe mutation names the statement it breaks at its recipe's last action, the recipe and its replacements.
RUN_MUTANTS = {
    "host-loss-flips": ("flipNeedsLoss", ["hostLoss(1)"] + CREATED[1:] + FLIP, HOST_LOSS_EVIDENCE),
    "token-omits-shard": (
        "createdIsMade",
        CREATED + ["lose(2)"] + op(2, "replacement", 2, 3) + op(0, "release", 2, 2) + op(2, "create", 2, 3)
        + ['call(2, "make", true)'] + ["request(2)"] * 3,
        [("(int, int) = (shard, attempt)", "(int, int) = (1, attempt)")]),
}


def rooted(prefix, stand=None):
    """The action that takes the prefix's actions in order and then free actions of the model's `step`. With `stand`,
    the first free action is enabled only in a state that meets it, so a prefix that ends elsewhere disables the
    search."""
    free = (f"    all {{ turn == {len(prefix)}, {stand}, step }},\n    all {{ turn > {len(prefix)}, step }},\n"
            if stand else f"    all {{ turn >= {len(prefix)}, step }},\n")
    return "  action rooted = any {\n" + "".join(
        f"    all {{ turn == {at}, {action} }},\n" for at, action in enumerate(prefix)) + free + "  }\n"


def bound(root):
    """The root's `BOUND`: its prefix and at least one free action after it."""
    prefix, free = ROOTS[root]
    if free < 1:
        raise ValueError(f"root {root}: the search must take at least one free action after its prefix")
    return len(prefix) + free


def cases(Case):
    yield Case("loss-typecheck", command="typecheck", family="loss")
    yield Case("loss-replay", command="replay", family="loss")
    for root, (prefix, _) in ROOTS.items():
        stand = f" and (turn == {len(prefix)} implies ({STANDS[root]}))" if prefix else ""
        yield Case(f"loss-safety-{root}", invariant="rootSafety", family="loss", settings={"BOUND": str(bound(root))},
                   step="rooted", extra=rooted(prefix) + f"  val rootSafety = safety{stand}\n", depth=bound(root) + 1)
    for witness, root in WITNESSES.items():
        prefix = ROOTS[root][0]
        yield Case(f"loss-reach-{witness}", invariant="unreached", expected="violation", family="loss",
                   settings={"BOUND": str(bound(root))}, step="rooted", after=len(prefix) + 1,
                   extra=rooted(prefix) + f"  val unreached = not({witness})\n")
    for name, points in CHECKPOINTS.items():
        if name not in RUNS:
            raise ValueError(f"checkpoints name {name}, which is no directed run")
        for at, _ in points:
            if not 0 < at <= len(RUNS[name][0]):
                raise ValueError(f"{name}: checkpoint turn {at} lies outside its recipe")
    for name, (recipe, outcome) in RUNS.items():
        checks = "".join(f" and (turn == {at} implies ({state}))" for at, state in CHECKPOINTS.get(name, []))
        yield Case(name, invariant="runSafety", family="loss", recipe=recipe, settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety{checks} and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="loss", recipe=recipe,
                   settings={"BOUND": str(len(recipe))},
                   extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (statement, root, mutations) in MUTANTS.items():
        prefix = ROOTS[root][0]
        yield Case(f"loss-mutant-{name}", invariant=statement, expected="violation", family="loss",
                   settings={"BOUND": str(bound(root))}, step="rooted", after=len(prefix) + 1,
                   extra=rooted(prefix, STANDS.get(root)), mutations=mutations)
    for name, (statement, recipe, mutations) in RUN_MUTANTS.items():
        yield Case(f"loss-mutant-{name}", invariant=statement, expected="violation", family="loss", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=mutations)


def inputs(case, source):
    text = (source / "loss.qnt").read_text()
    for old, new in case.mutations:
        if text.count(old) != 1:
            raise ValueError(f"{case.name}: mutation target is not unique")
        text = text.replace(old, new)
    extra = case.extra
    if case.recipe:
        extra += "  action recipe = any {\n" + "".join(
            f"    all {{ turn == {at}, {action} }},\n" for at, action in enumerate(case.recipe)) + "  }\n"
    limit = case.settings.get("BOUND", CONSTANTS["BOUND"])
    return {"loss.qnt": text,
            "case.qnt": f'module lossCase {{\n  import loss(BOUND = {limit}).* from "./loss"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "replay":
        return ["cargo", "test", "-p", "kestrike", "--lib", "--", "--ignored", "--exact", REPLAY_TEST, "--nocapture"]
    if case.command == "typecheck":
        return [quint, "typecheck", "loss.qnt"]
    step = ["--step", "recipe"] if case.recipe else ["--step", case.step] if case.step else []
    return [quint, "verify", "case.qnt", "--main", "lossCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + step
