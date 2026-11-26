"""Check the reconciler's standby census, attach and enrollment model: safety from the initial state and from prefix
roots, reachability witnesses of the outcomes these instances reach, directed runs and mutants of its guards, request
orders and premises, and the Rust replay of its regenerated traces. The closed-volume refusal of `record` has no
witness here.

`CONSTANTS` is instance S2; S2H, S3, S2E and S4 override its constants, and a root, run or mutant names the instance
it runs in, as does a recipe.

`cases` yields the cases that start at the initial state: the typecheck, `standbys-safety`, the reach cases of the
witnesses that state reaches, the runs and the mutants. A run holds safety at every step, its stated results at named
turns and its final state at the last turn, and its `-reached` case violates the negated final state with a trace of
the whole recipe; a mutant violates a safety property on a recipe that reaches the violation. `PROJECTIONS` declares
the prefix roots, which `check.projection_cases` expands into a `safety` case, one reach case per witness and one
case per root mutant each. A root's prefix is a legal history of the free scheduler, so a witness reached after it is
reached by the model, and a root mutant shows that the root's search finds the race its guard closes.

`inputs` gives each search, reach, run, mutant and recipe case an instance that holds only the actions, definitions
and values its case reaches, beside the constants, types and variables, since Apalache's server refuses a request past
20,000,000 characters; the typecheck case keeps the whole model.
"""
import re

# The ignored test that regenerates the traces `standbys_fixtures.py` declares, requires them to equal the committed
# ones and replays them against the reconciler.
REPLAY_TEST = "failover::reconcile_tests::standbys_replay::generated_standbys_traces_replay"
# S2: two shards and three hosts under `CAP = 1`; every host starts attached and enrolled on shard 1's volume, and
# hosts 2 and 3 on shard 2's. The attachment and role limits are slack.
CONSTANTS = {"BOUND": "7", "SHARDS": "Set(1, 2)", "HOSTS": "Set(1, 2, 3)", "CAP": "1",
             "OWNER": "Map(1 -> 1, 2 -> 2)", "STANDBY": "Map(1 -> 0, 2 -> 0)",
             "PAIRED": "Map(1 -> Set(1, 2, 3), 2 -> Set(2, 3))", "LOST": "Set()", "ATTACH": "9",
             "USED": "Map(1 -> 0, 2 -> 0, 3 -> 0)", "ROLES": "9", "LOSSES": "1",
             "SUSPECTS": "1", "OCCUPY": "0", "GMAX": "2"}
# S2H: host 1 owns shard 1 and stands by shard 2, host 2 owns shard 2 and stands by shard 1, and host 3, the one
# candidate left after host 1's loss, has one free attachment slot; `CAP = 2` and two roles per host.
S2H = {"CAP": "2", "STANDBY": "Map(1 -> 2, 2 -> 1)", "PAIRED": "Map(1 -> Set(1, 2), 2 -> Set(2, 1))", "ATTACH": "3",
       "USED": "Map(1 -> 0, 2 -> 0, 3 -> 2)", "ROLES": "2", "LOSSES": "1", "SUSPECTS": "0", "OCCUPY": "1",
       "GMAX": "1"}
# S4: S2 with a fourth host, which holds no attach of either volume while shard 1's volume holds `VOLMAX` live attaches.
S4 = {"HOSTS": "Set(1, 2, 3, 4)", "USED": "Map(1 -> 0, 2 -> 0, 3 -> 0, 4 -> 0)"}
# S3: host 1, lost at the start, owned shards 1 and 2 and stood by shard 3; host 2 stands by shard 1, host 3 owns
# shard 3, and host 4 is attached to no volume; `CAP = 2` and two roles per host.
S3 = {"SHARDS": "Set(1, 2, 3)", "HOSTS": "Set(1, 2, 3, 4)", "CAP": "2", "OWNER": "Map(1 -> 1, 2 -> 1, 3 -> 3)",
      "STANDBY": "Map(1 -> 2, 2 -> 0, 3 -> 1)", "PAIRED": "Map(1 -> Set(1, 2), 2 -> Set(1), 3 -> Set(3, 1))",
      "LOST": "Set(1)", "ATTACH": "3",
      "USED": "Map(1 -> 0, 2 -> 0, 3 -> 0, 4 -> 1)", "ROLES": "2", "LOSSES": "0", "SUSPECTS": "0", "OCCUPY": "0",
      "GMAX": "1"}
# S2E: two shards each attached to its owner alone, no standby, `CAP = 2`.
S2E = {**S2H, "STANDBY": "Map(1 -> 0, 2 -> 0)", "PAIRED": "Map(1 -> Set(1), 2 -> Set(2))",
       "USED": "Map(1 -> 0, 2 -> 0, 3 -> 0)", "LOSSES": "0", "OCCUPY": "0"}


def op(r, name, s, h, requests):
    """Reconciler `r` starts operation `name` on shard `s` and host `h`, then makes `requests` more requests."""
    return [f'begin({r}, "{name}", {s}, {h})'] + [f"request({r})"] * requests


def reserve(r, s, h):
    """A reservation that ends in its census write."""
    return op(r, "reserve", s, h, 3)


def designate(r, s, h):
    """A designation of the slot reconciler `r` holds that ends in its shard write."""
    return op(r, "designate", s, h, 3)


def release(r, s):
    """A release of shard `s` that ends in its census write; a release takes no host and names host 1."""
    return op(r, "release", s, 1, 3)


def attach(r, s, h):
    """The attach record, the completed attach and the enrollment of host `h` on shard `s`'s volume."""
    return op(r, "record", s, h, 3) + [f"attachEnds({s}, {h}, true)"] + op(r, "enroll", s, h, 3)


def root(prefix, witnesses, mutants=None, settings=None, steps=6):
    """A prefix root of instance `settings` (S2 by default) searched `steps` steps past its prefix."""
    return {"prefix": prefix, "step": "step", "settings": {**(settings or {}), "BOUND": str(len(prefix) + steps)},
            "witnesses": witnesses, "mutants": mutants or {}}


FULL_LINE = '    else if (not(p.had.on) and p.count >= capOf(r)) ended(p, "full")\n'
CURRENT_LINE = '    else if (sameTarget(p.rec, p.had)) ended(p, "keptCurrent")\n'
STANDBY_LINE = '    else if (p.rec.standby != 0) ended(p, "keptStandby")\n'
TAKEN_LINE = ('    else if (incumbent != 0 and incumbent != p.h and not(lost.contains(incumbent))) '
              'ended(p, "taken")\n')
CENSUS_VERSION = 'if (w.key == "census") s.census.get(w.z).ver == w.expect'
IGNORES_CENSUS_VERSION = [(CENSUS_VERSION, 'if (w.key == "census") true')]
LIVE_LINE = ('    else if (p.had.host != p.rec.owner and p.live and not(lost.contains(p.had.host))) '
             'ended(p, "keptLive")\n')
STALE_CHECK = 'not(sameTarget(q.rec, q.slot))) ended(q, "stale")'
SKIPS_STALE = [('    if (q.op == "designate" and k == "shard" and not(sameTarget(q.rec, q.slot))) ended(q, "stale")\n'
                '    else if', "    if")]
DESIGNATE_ORDER = '["volume", "shard", "census", "write"]'
RESERVE_ORDER = 'if (op == "reserve") ["census", "shard", "volume", "write"]'
RELEASE_ORDER = 'else if (op == "release") ["census", "shard", "volume", "write"]'
CENSUS_FIRST = [(DESIGNATE_ORDER, '["volume", "census", "shard", "write"]')]
SKIPS_CENSUS = [(DESIGNATE_ORDER, '["volume", "shard", "write"]')]
UNENROLLED_LINE = '    else if (not(p.enrolled)) ended(p, "unenrolled")\n'
UNATTACHED_LINE = '    else if (not(p.live)) ended(p, "unattached")\n'
STALE_REPORT = [("pure def reported(s: State, h: int): int = used(s, h)",
                 "pure def reported(s: State, h: int): int = USED.get(h) + attachments(s, h)")]
PENDING_UNCOUNTED = [("val room = reported(s, p.h) + pend < ATTACH", "val room = reported(s, p.h) < ATTACH")]
OCCUPY_IGNORES_OWED = [("    used(st, h) + owed(st, h) < ATTACH,\n", "    used(st, h) < ATTACH,\n")]
OCCUPY_HELD = ('    not(st.held.on and st.held.key == "census" and st.held.entry.host == h),\n', "")
OCCUPY_DURING_RESERVATION = [
    ('    RECS.forall(r => not(procs.get(r).op == "reserve" and procs.get(r).h == h and keyOf(procs.get(r)) == '
     '"write")),\n', ""),
    OCCUPY_HELD]
# The loop's stuck bound: a release keeps an entry while an attach record of its shard and host is in flight or held,
# and no attach record starts while a decided drop of its slot is unsent or held (`DROP_GUARD`).
IGNORES_RECORDING = [('RECS.exists(x => ps.get(x).op == "record" and ps.get(x).s == shard and ps.get(x).h == h)',
                      "false")]
IGNORES_HELD_RECORD = [('(s.held.on and s.held.op == "record" and s.held.s == shard and s.held.host == h)', "false")]
DROP_GUARD = '      op == "record" implies not(dropping(st, procs, s, p.slot)),\n'
HELD_DROP = ' or (s.held.on and s.held.op == "release" and s.held.s == shard and s.held.host == x.host)'
STUCK_BOUND = [('    else if (recording) ended(p, "keptRecording")\n', ""), (DROP_GUARD, "")]
ENROLL_BEFORE_ATTACH = [("(st.attached.contains((s, h)) and not(st.volumes.get(s).enrolled.contains(h)))",
                         "not(st.volumes.get(s).enrolled.contains(h))")]
RECORD_GUARD = '      op == "record" implies (p.ss == s and p.slot.host == h and e == p.slot),\n'
IGNORES_LISTING = [(RECORD_GUARD, '      op == "record" implies (p.ss == s and p.slot.host == h),\n')]
FAILED_ATTACH_COMPLETES = [(" not(st.attached.contains((s, h))), not(st.failed.contains((s, h))),\n",
                            " not(st.attached.contains((s, h))),\n")]
ATTACH_BEFORE_RECORD = [("    st.volumes.get(s).live.contains(h), not(st.attached.contains((s, h))),",
                         "    not(st.attached.contains((s, h))),")]
ENDED_ATTACH_COMPLETES = [("    st.volumes.get(s).live.contains(h), not(st.attached.contains((s, h))),",
                           "    (st.volumes.get(s).live.contains(h) or en.ended.contains((s, h))), "
                           "not(st.attached.contains((s, h))),")]
CAPS_DISAGREE = [("pure def capOf(r: int): int = CAP", "pure def capOf(r: int): int = if (r == 1) CAP + 1 else CAP")]
ROLES_UNFILTERED = [("val excluded = op == \"reserve\" and gains and roles(st, h) >= ROLES", "val excluded = false")]
RETRY_WITHOUT_REPLAN = [('else if (ok) acknowledged(p) else ended(p, "condition")',
                         'else if (ok) acknowledged(p) else if (p.op == "reserve") {...p, pc: 0} else ended(p, "condition")')]
RELEASE_FIRST = [(RELEASE_ORDER, 'else if (op == "release") ["shard", "census", "volume", "write"]')]

# Witnesses the free scheduler reaches from the initial state within `standbys-safety`'s bound.
WITNESSES = ["witnessCensusCreated", "witnessIneligible", "witnessUnknownCommitted", "witnessUnknownLost",
             "witnessHeld", "witnessHeldDelivered", "witnessReleaseAbsent"]
RESERVED = reserve(0, 1, 2)
DESIGNATED = RESERVED + designate(0, 1, 2)
# Reconciler 0's designation of host 2 has read the volume record, the shard record and the census, and writes next.
DESIGNATING = RESERVED + op(0, "designate", 1, 2, 2)
# Reconciler 1 moves shard 1's slot from host 2 to host 3 on its false suspicion of host 2.
MOVE = ["suspect(1, 2)"] + reserve(1, 1, 3)
# Reconciler 0 holds shard 1's slot for host 2, and its designation of host 2 has read the volume and shard records
# and reads the census next; then reconciler 1 moves the slot to host 3.
RACING = RESERVED + op(0, "designate", 1, 2, 1) + MOVE
# Reconciler 1's release makes its first request at shard 1's first tenure; then the owner bumps and reconciler 0
# reserves and designates host 2 at the new tenure.
RENEWED = op(1, "release", 1, 1, 0) + ["bump(1)"] + reserve(0, 1, 2) + designate(0, 1, 2)
# Reconciler 0's reservation of host 2 has read the absent census and shard 1's record at its first tenure; the owner
# bumps, and reconciler 1's reservation of host 2 has read the absent census and the record at the new tenure and
# writes next.
BUMPED = op(0, "reserve", 1, 2, 1) + ["bump(1)"] + op(1, "reserve", 1, 2, 2)
# S2H after host 1's loss, known to both reconcilers.
LOST_1 = ["lose(1)", "learn(0, 1)", "learn(1, 1)"]
# Then host 2 takes shard 1 over and reconciler 0 reserves host 3 for it.
CLAIMED = LOST_1 + ["takeover(1)"] + reserve(0, 1, 3)
# S2H with host 3 standing by shard 1 and one free attachment slot before the prefix.
CROSS_BOTH = {**S2H, "STANDBY": "Map(1 -> 3, 2 -> 1)", "PAIRED": "Map(1 -> Set(1, 3), 2 -> Set(2, 1))",
              "USED": "Map(1 -> 0, 2 -> 0, 3 -> 1)", "OCCUPY": "0"}
# S2H with both hosts of shard 1 lost and known to reconciler 0.
DOUBLE = {**S2H, "LOSSES": "2", "OCCUPY": "0"}
DOUBLE_LOSS = ["lose(1)", "lose(2)", "learn(0, 1)", "learn(0, 2)"]
# S2H with host 3 attached and enrolled on shard 1's volume, where it holds no role, which takes its last free slot.
CROSS_END = {**S2H, "PAIRED": "Map(1 -> Set(1, 2, 3), 2 -> Set(2, 1))", "OCCUPY": "0"}
# The end decision's role check of the shard record's standby.
END_STANDBY = ("      r.standby != h, r.e > 0, en.ending == Set(),", "      r.e > 0, en.ending == Set(),")
# Host 2's end is decided and host 2 takes shard 1 over; host 3 is designated, the end lands on owner 2, which keeps
# its attachment with no live attach in the volume record, and host 3 takes over.
DEPOSED = (["endRead(1, 2)"] + DESIGNATED + ["takeover(1)"] + reserve(0, 1, 3) + designate(0, 1, 3)
           + ["endWrite(1, 2)", "takeover(1)"])
# S3 with host 1's loss known to both reconcilers.
STORM = ["learn(0, 1)", "learn(1, 1)"]
# Host 2 takes shard 1 over as its named standby.
STORM_TAKEOVER = STORM + ["takeover(1)"]
# The release drops shard 1's entry, which named host 2.
STORM_FREED = STORM_TAKEOVER + release(0, 1)
# Shard 1 retains its census slot when reconciler 0 re-reserves it for host 3.
STORM_CLAIMED = STORM_TAKEOVER + reserve(0, 1, 3)
# Both reconcilers read the census STORM_FREED leaves and decide to reserve host 2, one role short of the limit, for
# shards 2 and 3; both census writes are next.
STORM_RACING = (STORM_FREED + ['begin(0, "reserve", 2, 2)', 'begin(1, "reserve", 3, 2)']
                + ["request(0)", "request(1)"] * 2)
PROJECTIONS = {
    # Reconciler 0 holds shard 1's slot for host 2.
    "reserved": root(RESERVED, ["witnessTaken", "witnessFull", "witnessDesignated", "witnessStale",
                                "witnessKeptCurrent", "witnessKeptLive", "witnessReleased", "witnessMovedOnSuspicion",
                                "witnessMovedOnLoss", "witnessListed", "witnessReleaseUnlisted",
                                "witnessTransferred"], {
        # A reservation takes the slot from host 2, which its reconciler's evidence does not show lost.
        "reserve-moves-live-incumbent": ("SlotMovesOnlyOnEvidence", "witnessTaken", [(TAKEN_LINE, "")]),
        # After the owner's bump, a release drops the entry of host 2, which holds a live attach.
        "release-ignores-live": ("SlotMovesOnlyOnEvidence", "witnessKeptLive", [(LIVE_LINE, "")]),
    }),
    # Shard 1 names host 2 its standby, and reconciler 0 still holds the slot.
    "designated": root(DESIGNATED, ["witnessAsIs", "witnessKeptStandby", "witnessMovedFromOwner", "witnessStale",
                                    "witnessTransferred"], {
        # After host 2's takeover, the mutant designates host 2 over the shard record that names it owner.
        "designate-skips-stale": ("FeasibleSlot", "witnessStale", SKIPS_STALE),
    }),
    # Shard 1's owner transferred it to host 2, its named standby, and the record names no standby: the census entry
    # that names host 2 moves off the new owner.
    "transferred": root(DESIGNATED + ["transfer(1)"], ["witnessMovedFromOwner"], steps=5),
    # After the transfer reconciler 0 moved the entry to host 3, and a designation names a standby of the transferred
    # shard again; the prefix holds the transfer, so every designation past it follows the transfer.
    "redesignating": root(DESIGNATED + ["transfer(1)"] + reserve(0, 1, 3), ["witnessRedesignatedOverNewOwner"],
                          steps=5),
    # A designation has read the census and its write is next while a release can run.
    "designating": root(DESIGNATING, ["witnessDesignated", "witnessKeptCurrent", "witnessDesignationConditionLost",
                                      "witnessTransferred"], {
        "release-at-current-target": ("StandbyCovered", "witnessKeptCurrent", [(CURRENT_LINE, "")]),
    }),
    # Reconciler 1 moved the slot to host 3 on its false suspicion while reconciler 0's designation of host 2 has read
    # the volume and shard records and reads the census next.
    "racing": root(RACING, ["witnessDesignated", "witnessConflict", "witnessTransferred"], {
        "designate-reads-census-first": ("NewerDesignationStands", "witnessConflict", CENSUS_FIRST),
    }),
    # Reconciler 1 moved the slot to host 3 and its designation has read the volume and shard records, while
    # reconciler 0 still holds the slot for host 2.
    "replacing": root(RESERVED + MOVE + op(1, "designate", 1, 3, 1),
                      ["witnessDesignated", "witnessConflict", "witnessTransferred"], {
        "designate-skips-census": ("NewerDesignationStands", "witnessDesignated", SKIPS_CENSUS),
    }),
    # Reconciler 1's release has read the census at shard 1's first tenure; then the owner bumped and reconciler 0
    # reserved and designated host 2 at the new tenure.
    "releasing": root(RESERVED + RENEWED,
                      ["witnessKeptStandby"], {
        "release-reads-shard-first": ("StandbyCovered", "witnessKeptStandby", RELEASE_FIRST),
    }),
    # Shard 1 names host 2, and reconciler 1 moved the slot to host 3 on its false suspicion of host 2.
    "moved": root(DESIGNATED + MOVE, ["witnessReplaced", "witnessConflict", "witnessTransferred"], {
        # The census no longer names host 2, and the end decision ignores that the record still names it standby.
        "end-ignores-standby": ("DesignatedIsEnrolled", "witnessReplaced", [END_STANDBY]),
    }),
    # Reconciler 0 holds shard 2's slot for host 1, which holds no attach of that volume.
    "unenrolled": root(reserve(0, 2, 1), ["witnessUnenrolled"], {
        "designate-unenrolled": ("DesignatedIsEnrolled", "witnessUnenrolled", [(UNENROLLED_LINE, "")]),
    }),
    # Reconciler 0 stopped holding shard 1's slot, and reconciler 1's reservation found the slot listed.
    "crashed": root(RESERVED + ["crash(0)"] + op(1, "reserve", 1, 2, 2),
                    ["witnessCrashConverges", "witnessTransferred"]),
    # Both reconcilers began reservations of different shards over the absent census.
    "begun": root(['begin(0, "reserve", 1, 2)', 'begin(1, "reserve", 2, 3)'], ["witnessConditionLost"]),
    # A reservation that read shard 1's record at its first tenure is in flight while one decided at the next tenure
    # writes next.
    "bumped": root(BUMPED, ["witnessEarlierTenurePending"], {
        # The earlier reservation's census write lands over the entry at the later tenure.
        "census-write-ignores-version": ("EntryTargetAdvances", "witnessEarlierTenurePending",
                                         IGNORES_CENSUS_VERSION),
    }),
    # S2H after host 1's loss: both shards need a standby and host 3 is the one candidate.
    "cross": root(LOST_1, ["witnessOneHostForBoth", "witnessHeadroom", "witnessOccupied", "witnessTransferred"], {
        # The reservation counts the outside attachments published at the start; its completed attaches and standby
        # roles stay current.
        "stale-report": ("HostAttachmentsWithinLimit", "witnessHeadroom", STALE_REPORT),
        # An actor outside the census takes a slot a census entry still owes.
        "occupy-ignores-owed": ("HostAttachmentsWithinLimit", "witnessOccupied", OCCUPY_IGNORES_OWED),
        # An actor outside the census takes a slot after a reservation decided on the report and before its census
        # write commits.
        "occupy-during-reservation": ("HostAttachmentsWithinLimit", "witnessOccupied", OCCUPY_DURING_RESERVATION),
    }, settings=S2H, steps=12),
    # Host 2 took shard 1 over, reconciler 0 reserved host 3 for it, and the owner bumped, so a release may drop the
    # entry while host 3's attach is not yet recorded.
    "cross-bumped": root(CLAIMED + ["bump(1)"], ["witnessKeptRecording", "witnessTransferred"], {
        "release-before-stuck-bound": ("HostAttachmentsWithinLimit", "witnessKeptRecording", STUCK_BOUND),
    }, settings=S2H, steps=11),
    # Shard 1's owner and standby are lost, and host 3 is reserved, attached and enrolled for it.
    "cross-fresh": root(DOUBLE_LOSS + reserve(0, 1, 3) + attach(0, 1, 3), ["witnessFreshDesignated"],
                        settings=DOUBLE),
    # Host 3 starts as shard 1's standby with one more free slot; after host 1's loss its designation for shard 2
    # writes next.
    "cross-both": root(LOST_1 + reserve(1, 2, 3) + attach(1, 2, 3) + op(1, "designate", 2, 3, 2),
                       ["witnessStandsByBoth", "witnessTransferred"], settings=CROSS_BOTH),
    # S3 after host 1's loss, known to both reconcilers.
    "storm": root(STORM, ["witnessFullNoAttach", "witnessTransferred"], {
        "attach-before-reservation": ("AttachFollowsReservation", "witnessFullNoAttach", [(RECORD_GUARD, "")]),
        "caps-disagree": ("CensusUnderCap", "witnessFullNoAttach", CAPS_DISAGREE),
    }, settings=S3, steps=11),
    # Host 2 took shard 1 over and the release dropped shard 1's entry, which named host 2.
    "storm-taken": root(STORM_FREED, ["witnessSlotTakenAfterTakeover", "witnessReservationFullAfterTakeover",
                                      "witnessTransferred"], settings=S3, steps=7),
    "storm-racing": root(STORM_RACING, ["witnessExcluded", "witnessConditionLost", "witnessTransferred"], {
        "census-write-ignores-version": ("CensusUnderCap", "witnessConditionLost", IGNORES_CENSUS_VERSION),
        "census-write-ignores-version-roles": ("StandbyRolesWithinHostLimit", "witnessConditionLost",
                                               IGNORES_CENSUS_VERSION),
        "retry-without-replan": ("StandbyRolesWithinHostLimit", "witnessConditionLost", RETRY_WITHOUT_REPLAN),
    }, settings=S3),
    # Host 2 owns shard 1 and holds shard 2's slot, at the role limit.
    "storm-shared": root(STORM_FREED + reserve(0, 2, 2),
                         ["witnessExcluded", "witnessListedAtLimit", "witnessTransferred"], {
        # The loop reserves a host with no candidate filter.
        "roles-unfiltered": ("StandbyRolesWithinHostLimit", "witnessExcluded", ROLES_UNFILTERED),
    }, settings=S3),
    # Host 2 took shard 1 over, and host 3's attach of shard 1's volume is recorded under its new slot.
    "storm-recorded": root(STORM_CLAIMED + op(0, "record", 1, 3, 3),
                           ["witnessAttachFailed", "witnessClosed", "witnessReenrolled", "witnessTransferred"],
                           settings=S3),
    # Host 2 took shard 1 over, and host 3 is reserved, attached and enrolled for shard 1.
    "storm-designating": root(STORM_CLAIMED + attach(0, 1, 3), ["witnessDesignated", "witnessTransferred"],
                              settings=S3, steps=8),
    # Host 2's recorded attach of shard 1's volume failed for good, so host 2 is live with no pair, and reconciler 0
    # still holds the slot.
    "failed": root(reserve(0, 1, 2) + op(0, "record", 1, 2, 3) + ["attachEnds(1, 2, false)"],
                   ["witnessMovedOnFailedAttach", "witnessUnenrolled"], {
        "designate-unenrolled": ("DesignatedIsEnrolled", "witnessUnenrolled", [(UNENROLLED_LINE, "")]),
    }, settings=S2E),
    # Host 2's end is decided, then reconciler 0 reserves host 2's slot, so the end can land beside a release, a
    # designation or a move of the slot.
    "ending": root(["endRead(1, 2)"] + RESERVED,
                   ["witnessReleasedAfterEnd", "witnessNamedEnded", "witnessTransferred"]),
    # Host 2's end is decided while reconciler 0's designation of host 2 writes next.
    "endingDesignation": root(["endRead(1, 2)"] + DESIGNATING, ["witnessNamedEnded", "witnessTransferred"], steps=6),
    # Host 3 holds an attach of shard 1's volume with no role and no free attachment slot; after host 1's loss it is
    # the one candidate for shard 2, and the end of its attach is decided. A reservation of shard 2 for host 3 refuses
    # Headroom until the end lands and moves the slot off the lost host after it.
    "endingCross": root(LOST_1 + ["endRead(1, 3)"], ["witnessHeadroom", "witnessMovedOnLoss", "witnessTransferred"],
                        settings=CROSS_END, steps=12),
}
# A later `begin` of a reconciler needs that reconciler idle, so a run's recipe ends each earlier operation of it.
RUNS = {
    "capRefusesSecond": (
        DESIGNATED + op(1, "reserve", 2, 3, 2),
        'ev.res == "full" and procs.get(1).ss == 0 and st.census.get(1).ver == 1 and listed(st.census.get(1)) == 1 '
        'and st.shards.get(1).standby == 2 and st.shards.get(2).standby == 0', {}),
    "racingReservations": (
        ['begin(0, "reserve", 1, 2)', 'begin(1, "reserve", 2, 3)'] + ["request(0)", "request(1)"] * 3
        + op(1, "reserve", 2, 3, 2),
        'ev.res == "full" and procs.get(1).ss == 0 and st.census.get(1).ver == 1 and st.census.get(1).slots.get(1).on '
        "and not(st.census.get(1).slots.get(2).on)",
        {7: 'ev.res == "reserved" and ev.note == "created"',
         8: 'ev.act == "write" and ev.key == "census" and ev.res == "condition" and procs.get(1).ss == 0'}),
    # Reconciler 0's reservation reads shard 1's record before the owner's bump and decides after reconciler 1's
    # reservation at the new tenure created the census: its write, an entry at the first tenure, loses its condition.
    "earlierTenureLosesCondition": (
        BUMPED + ["request(1)", "request(0)", "request(0)"],
        'ev.act == "write" and ev.key == "census" and ev.res == "condition" and ev.proc == 0 '
        "and procs.get(0).ss == 0 and st.census.get(1).ver == 1 "
        "and st.census.get(1).slots.get(1) == {on: true, g: 1, owner: 1, e: 2, host: 2}",
        {7: 'ev.res == "reserved" and ev.note == "created" and st.census.get(1).slots.get(1).e == 2',
         8: "witnessEarlierTenurePending and procs.get(0).put == {on: true, g: 1, owner: 1, e: 1, host: 2}"}),
    "staleReconcilerRefused": (
        RESERVED + op(1, "reserve", 1, 3, 2) + ["lose(2)", "learn(1, 2)"] + reserve(1, 1, 3) + designate(1, 1, 3)
        + op(0, "designate", 1, 2, 2) + op(0, "reserve", 1, 2, 2),
        'ev.res == "taken" and procs.get(0).ss == 0 and st.shards.get(1).standby == 3 '
        "and st.shards.get(1).ver == 2 and st.census.get(1).ver == 2 and st.census.get(1).slots.get(1).host == 3",
        {7: 'ev.res == "taken" and procs.get(1).ss == 0 and st.census.get(1).ver == 1',
         13: 'ev.note == "movedOnLoss"', 17: 'ev.res == "designated"', 20: 'ev.res == "conflict"'}),
    "designateReadsCensusAfterShard": (
        RACING + designate(1, 1, 3) + ["request(0)"],
        'ev.res == "conflict" and st.shards.get(1).standby == 3 and st.shards.get(1).ver == 2 '
        "and st.census.get(1).slots.get(1).host == 3",
        {11: 'ev.note == "movedOnSuspicion"', 15: 'ev.res == "designated"'}),
    "releaseReadsShardAfterCensus": (
        RESERVED + op(1, "release", 1, 1, 0) + ["bump(1)"] + reserve(0, 1, 2) + ["suspect(1, 2)"]
        + ["request(1)"] * 3,
        'ev.res == "condition" and st.census.get(1).ver == 2 '
        "and st.census.get(1).slots.get(1) == {on: true, g: 1, owner: 1, e: 2, host: 2}",
        {10: 'ev.res == "reserved" and st.census.get(1).slots.get(1).e == 2',
         12: 'procs.get(1).had.e == 1 and procs.get(1).rec.e == 2'}),
    "restartConverges": (
        op(0, "reserve", 1, 2, 2) + ['unknown(0, "commit")'] + op(0, "reserve", 1, 2, 2) + ["crash(0)"]
        + op(1, "reserve", 1, 2, 2) + designate(1, 1, 2),
        'ev.res == "designated" and st.census.get(1).ver == 1 and listed(st.census.get(1)) == 1 '
        "and st.census.get(1).slots.get(1).host == 2 and st.shards.get(1).standby == 2 and st.shards.get(1).ver == 2 "
        "and procs.get(0) == IDLE and st.orphan == {s: 1, r: 0}",
        {4: 'ev.act == "commit" and ev.note == "created" and ev.res == "unknown" and procs.get(0).ss == 0',
         7: 'ev.res == "listed" and procs.get(0).ss == 1', 11: 'ev.res == "listed"'}),
    "flipReleasesEntry": (
        RESERVED + ["flip(1, 3)"] + release(0, 1),
        'ev.res == "released" and not(st.census.get(1).slots.get(1).on) and st.shards.get(1).g == 2', {}),
    # One shard's standby from reservation to designation, with no Register step.
    "enrollOne": (
        reserve(0, 1, 3) + attach(0, 1, 3) + designate(0, 1, 3),
        'ev.res == "designated" and listed(st.census.get(1)) == 1 and st.volumes.get(1).live == Set(1, 3) '
        "and st.volumes.get(1).enrolled == Set(1, 3) and st.shards.get(1).standby == 3",
        {8: 'ev.res == "recorded"', 13: 'ev.res == "enrolled"'}, S2E),
    # Host 1 owned shard 1 and stood by shard 2; after its loss host 2 owns both, and host 3's one free slot takes
    # one reservation and refuses the other.
    "hostInTwoRolesLost": (
        CLAIMED + op(1, "reserve", 2, 3, 2),
        'ev.res == "headroom" and procs.get(1).ss == 0 and st.census.get(1).ver == 2 '
        "and st.census.get(1).slots.get(1).host == 3 and st.census.get(1).slots.get(2).host == 1",
        {4: "roles(st, 2) == 2 and st.census.get(1).slots.get(1).host == 2 and st.shards.get(1).owner == 2",
         8: 'ev.res == "reserved"'}, S2H),
    "ownerAtRoleLimit": (op(0, "reserve", 2, 2, 2) + op(0, "reserve", 2, 2, 0) + ["takeover(2)"] + ["request(0)"] * 3,
                         'ev.note == "movedFromOwner" and roles(st, 2) == 2', {3: 'ev.res == "ineligible"'}, S2H),
    # After host 2's takeover of shard 1, host 3 is reserved, recorded, enrolled and designated under the new owner.
    "reEnrollAfterTakeover": (
        CLAIMED + attach(0, 1, 3) + designate(0, 1, 3),
        'ev.res == "designated" and st.shards.get(1) == {g: 1, owner: 2, e: 2, standby: 3, ver: 3} '
        "and st.volumes.get(1).live == Set(1, 2, 3) and st.volumes.get(1).enrolled == Set(1, 2, 3)",
        {8: 'ev.res == "reserved"', 12: 'ev.res == "recorded"', 17: 'ev.res == "enrolled"'}, S2H),
    # Host 3 takes shard 1 over between a reservation's census read and its volume read: the current report lists
    # shard 1 as owned, so its still-listed entry counts as pending and the reservation refuses Headroom.
    "headroomAfterTakeoverBetweenReads": (
        LOST_1 + ['begin(1, "reserve", 2, 3)', "takeover(1)", "request(1)", "request(1)"],
        'ev.res == "headroom" and procs.get(1) == IDLE and st.shards.get(1).owner == 3 '
        "and st.census.get(1).ver == 1 and st.census.get(1).slots.get(2).host == 1", {}, CROSS_BOTH),
    # Host 3 enrolls on shard 1 between a reservation's census read and its volume read: the current report lists
    # shard 1 in the standby role, so the reservation of shard 2 commits.
    "reservedAfterEnrollBetweenReads": (
        reserve(0, 1, 3) + op(0, "record", 1, 3, 3) + ["attachEnds(1, 3, true)", 'begin(1, "reserve", 2, 3)']
        + op(0, "enroll", 1, 3, 3) + ["request(1)"] * 3,
        'ev.res == "reserved" and st.census.get(1).slots.get(2).host == 3 and st.volumes.get(1).enrolled == Set(1, 3)',
        {14: 'ev.res == "enrolled"'}, {**S2E, "USED": "Map(1 -> 0, 2 -> 0, 3 -> 1)"}),
    # Reconciler 1 renews host 3's entry at the next attempt while reconciler 0 records host 3's attach under the
    # earlier slot; after another bump the release keeps the renewed entry, and the attach stays charged.
    "renewedEntryKeptWhileRecording": (
        reserve(0, 1, 3) + op(0, "record", 1, 3, 1) + ["bump(1)"] + reserve(1, 1, 3) + ["bump(1)"]
        + op(1, "release", 1, 1, 2) + ["request(0)", "request(0)"],
        'ev.res == "recorded" and st.census.get(1).slots.get(1) == {on: true, g: 1, owner: 1, e: 2, host: 3} '
        "and st.volumes.get(1).live == Set(1, 3)",
        {11: 'ev.res == "reserved" and st.census.get(1).slots.get(1).e == 2', 15: 'ev.res == "keptRecording"'},
        {**S2E, "USED": "Map(1 -> 0, 2 -> 0, 3 -> 2)"}),
    # Shard 1's owner and standby are lost; host 3 is reserved, recorded, enrolled and designated.
    "freshHostAfterDoubleLoss": (
        DOUBLE_LOSS + reserve(0, 1, 3) + attach(0, 1, 3) + designate(0, 1, 3),
        'ev.res == "designated" and st.shards.get(1).standby == 3 and st.shards.get(1).g == 1 '
        "and st.volumes.get(1) == {live: Set(1, 2, 3), enrolled: Set(1, 2, 3), ver: 3}",
        {8: 'ev.res == "reserved"', 12: 'ev.res == "recorded"', 17: 'ev.res == "enrolled"'}, DOUBLE),
    # Shard 1's owner transfers it to host 2, its named standby, which clears the standby; reconciler 0 moves the
    # census entry off the new owner to host 3 and designates host 3.
    "transferThenRedesignate": (
        DESIGNATED + ["transfer(1)"] + reserve(0, 1, 3) + designate(0, 1, 3),
        'ev.res == "designated" and st.shards.get(1).owner == 2 and st.shards.get(1).e == 2 '
        "and st.shards.get(1).standby == 3 and st.census.get(1).slots.get(1).host == 3 "
        "and listed(st.census.get(1)) == 1",
        {9: 'ev.act == "transfer" and st.shards.get(1).standby == 0', 13: 'ev.note == "movedFromOwner"'}),
    # Host 2's recorded attach of shard 1's volume fails for good; the slot moves to host 3 on that evidence.
    "attachFailedMovesSlot": (
        reserve(0, 1, 2) + op(0, "record", 1, 2, 3) + ["attachEnds(1, 2, false)"] + reserve(1, 1, 3)
        + attach(1, 1, 3) + designate(1, 1, 3),
        'ev.res == "designated" and st.shards.get(1).standby == 3 and st.census.get(1).slots.get(1).host == 3 '
        "and st.volumes.get(1).live == Set(1, 2, 3) and st.volumes.get(1).enrolled == Set(1, 3)",
        {9: 'ev.res == "failed" and st.volumes.get(1).live == Set(1, 2) and st.volumes.get(1).enrolled == Set(1) '
            "and st.failed.contains((1, 2)) and not(st.attached.contains((1, 2)))",
         13: 'ev.note == "movedOnFailedAttach"'}, S2E),
    # The host that owned two shards and stood by the third is lost. Reconciler 0 re-reserves shard 1 for host 3,
    # which attaches, enrolls and is designated; then the cap refuses shard 2's reservation for host 4 while shards 1
    # and 3 name standbys.
    "stormOwnerOfTwo": (
        STORM_CLAIMED + attach(0, 1, 3) + designate(0, 1, 3) + op(1, "reserve", 2, 4, 2),
        'ev.res == "full" and procs.get(1).ss == 0 and st.census.get(1).ver == 2 and listed(st.census.get(1)) == 2 '
        "and st.shards.get(1).standby == 3 and st.shards.get(3).standby == 1 and st.shards.get(2).standby == 0",
        {7: 'ev.note == "movedFromOwner"', 20: 'ev.res == "designated"'}, S3),
    # The housekeeping release runs before the re-reservation: shard 2 takes the slot shard 1's takeover freed, and
    # the cap refuses shard 1.
    "slotTakenAfterTakeover": (
        STORM_FREED + reserve(1, 2, 4) + op(0, "reserve", 1, 3, 2),
        'ev.res == "full" and procs.get(0).ss == 0 and st.census.get(1).ver == 3 '
        "and st.census.get(1).slots.get(2).on and not(st.census.get(1).slots.get(1).on)",
        {7: 'ev.res == "released"', 11: 'ev.note == "newEntry"'}, S3),
    # The loop's order for a standby contender: the re-reservation runs first, shard 1 keeps its slot, and the cap
    # refuses shard 2.
    "slotKeptUnderLoopOrder": (
        STORM_CLAIMED + op(0, "release", 1, 1, 2) + op(1, "reserve", 2, 4, 2),
        'ev.res == "full" and procs.get(1).ss == 0 and st.census.get(1).ver == 2 '
        "and st.census.get(1).slots.get(1).host == 3 and not(st.census.get(1).slots.get(2).on)",
        {7: 'ev.note == "movedFromOwner"', 10: 'ev.res == "keptCurrent"'}, S3),
    # The loop's order for a fresh contender: shard 2's owner is lost with no standby, so its fresh need withholds
    # shard 1's re-reservation; the release drops the entry shard 1's takeover left, shard 2 takes the slot and names
    # host 4, and the cap refuses shard 1's re-reservation.
    "freshTakesStaleEntry": (
        STORM_FREED + reserve(0, 2, 4) + attach(0, 2, 4) + designate(0, 2, 4) + op(1, "reserve", 1, 3, 2),
        'ev.res == "full" and procs.get(1).ss == 0 and listed(st.census.get(1)) == 2 '
        "and st.census.get(1).slots.get(2).host == 4 and not(st.census.get(1).slots.get(1).on) "
        "and st.shards.get(2).standby == 4 and st.shards.get(1).standby == 0",
        {7: 'ev.res == "released"', 11: 'ev.note == "newEntry"', 15: 'ev.res == "recorded"',
         20: 'ev.res == "enrolled"', 24: 'ev.res == "designated"'}, S3),
    # Reconciler 0's reservation of shard 2 for host 2 commits with no reply, leaving host 2 at the role limit and
    # neither reconciler holding the slot; reconciler 1's reservation of the same shard and host finds it listed.
    "listedAfterUnknownAtLimit": (
        STORM_FREED + op(0, "reserve", 2, 2, 2) + ['unknown(0, "commit")'] + op(1, "reserve", 2, 2, 2),
        'ev.res == "listed" and procs.get(1).ss == 2 and procs.get(1).slot == st.census.get(1).slots.get(2) '
        "and procs.get(0).ss == 0 and st.census.get(1).ver == 3 and roles(st, 2) == ROLES",
        {11: 'ev.act == "commit" and ev.note == "newEntry" and procs.get(0).ss == 0 and procs.get(1).ss == 0'}, S3),
    # Host 3, at the role limit with shard 1's entry, has its attach recorded; after the owner's bump reconciler 1
    # renews host 3's entry at the new attempt.
    "renewedAtLimitAfterBump": (
        STORM_CLAIMED + op(0, "record", 1, 3, 3) + ["bump(1)"] + reserve(1, 1, 3),
        'ev.act == "write" and ev.note == "entry" and st.census.get(1).ver == 3 and roles(st, 3) == ROLES '
        "and st.census.get(1).slots.get(1) == {on: true, g: 1, owner: 2, e: 3, host: 3} "
        "and st.volumes.get(1).live.contains(3)", {11: 'ev.res == "recorded"'}, S3),
    # Host 2's end is decided; reconciler 0's designation of host 3 writes next, reconciler 1 moves the slot to host 2
    # on its false suspicion of host 3, and its designation of host 2 reads the volume record before the end lands.
    # Host 3's designation commits, and host 2's then reads the new shard record and replaces it: the record names
    # host 2, whose attach ended after the designation's volume read.
    "designationBehindRivalRacesEnd": (
        ["endRead(1, 2)"] + reserve(0, 1, 3) + op(0, "designate", 1, 3, 2) + ["suspect(1, 3)"] + reserve(1, 1, 2)
        + ['begin(1, "designate", 1, 2)', "endWrite(1, 2)", "request(0)"] + ["request(1)"] * 3,
        'ev.note == "replaced" and st.shards.get(1).standby == 2 and not(st.volumes.get(1).live.contains(2)) '
        "and en.raced == Set((1, 2))",
        {16: 'ev.note == "named" and st.shards.get(1).standby == 3 and en.raced == Set()'}),
}
# A release whose census write drops the entry, then reconciler 0's pending designation write.
OVERTAKEN = ["suspect(1, 2)"] + release(1, 1) + ["request(0)"]
# A release whose census write drops the entry, then reconciler 0's designation write over a shard read that
# predates it.
UNCOVERED = DESIGNATING + OVERTAKEN


def both_reserve(s):
    """Reconciler 0 reserves shard 1 for host 2 and reconciler 1 shard `s` for host 3, both over the empty census."""
    return ['begin(0, "reserve", 1, 2)', f'begin(1, "reserve", {s}, 3)'] + ["request(0)", "request(1)"] * 3


# Each mutant: the property it violates, the recipe that reaches the violation, and its text replacements.
# A recipe follows its mutant's request order.
MUTANTS = {
    "admit-ignores-cap": ("CensusUnderCap", RESERVED + reserve(1, 2, 3), [(FULL_LINE, "")]),
    "census-write-ignores-version": ("CensusUnderCap", both_reserve(2), IGNORES_CENSUS_VERSION),
    # Both reservations of shard 1 read the empty census, and the second write takes host 2's new slot.
    "census-write-ignores-version-one-shard": ("SlotMovesOnlyOnEvidence", both_reserve(1), IGNORES_CENSUS_VERSION),
    # Reconciler 1's release prepares to drop host 2's entry on its learned loss; reconciler 0 then moves the slot to
    # host 3, and the release's write drops host 3's entry.
    "census-write-ignores-version-stale-release": (
        "SlotMovesOnlyOnEvidence",
        RESERVED + ["bump(1)", "lose(2)", "learn(1, 2)", "learn(0, 2)"] + op(1, "release", 1, 1, 2) + reserve(0, 1, 3)
        + ["request(1)"],
        IGNORES_CENSUS_VERSION),
    "release-at-current-target": ("StandbyCovered", UNCOVERED, [(CURRENT_LINE, "")]),
    "release-at-current-target-two-shards": ("StandbysUnderCap", UNCOVERED + reserve(1, 2, 3) + designate(1, 2, 3),
                                             [(CURRENT_LINE, "")]),
    "release-ignores-standby": ("StandbyCovered", DESIGNATED + ["bump(1)", "suspect(1, 2)"] + release(1, 1),
                                [(STANDBY_LINE, "")]),
    # The release's shard read precedes a bump, a reservation and a designation at the new tenure.
    "release-reads-shard-first": ("StandbyCovered", RENEWED + ["suspect(1, 2)"] + ["request(1)"] * 3, RELEASE_FIRST),
    # After the owner's bump, the release drops host 2's entry while host 2 holds a live attach.
    "release-ignores-live": ("SlotMovesOnlyOnEvidence", RESERVED + ["bump(1)"] + release(1, 1), [(LIVE_LINE, "")]),
    # Under the shortened order a designation makes two requests after its start.
    "designate-skips-census": (
        "NewerDesignationStands",
        RESERVED + MOVE + op(1, "designate", 1, 3, 2) + op(0, "designate", 1, 2, 2),
        SKIPS_CENSUS),
    "designate-reads-census-first": (
        "NewerDesignationStands", RACING + designate(1, 1, 3) + ["request(0)", "request(0)"], CENSUS_FIRST),
    "designate-skips-stale": ("FeasibleSlot", DESIGNATED + ["takeover(1)"] + designate(0, 1, 2), SKIPS_STALE),
    # Reconciler 0's designation of host 2 at the first attempt passes its shard read after the owner's bump, and its
    # write names host 2 after a release dropped the entry.
    "stale-ignores-attempt": (
        "StandbyCovered",
        RESERVED + ["bump(1)"] + op(0, "designate", 1, 2, 2) + OVERTAKEN,
        [(STALE_CHECK, 'not(q.rec.g == q.slot.g and q.rec.owner == q.slot.owner)) ended(q, "stale")')]),
    # Reconciler 0's designation reads the volume record before host 2's takeover, a flip back to host 1 and its
    # fresh acquisition, then passes its shard read at the second generation; a release drops the entry before its
    # write.
    "stale-ignores-generation": (
        "StandbyCovered",
        DESIGNATED + ['begin(0, "designate", 1, 2)', "takeover(1)", "flip(1, 1)", "fresh(1)", "request(0)",
                      "request(0)"] + release(1, 1) + ["request(0)"],
        [(STALE_CHECK, 'not(q.rec.owner == q.slot.owner and q.rec.e == q.slot.e)) ended(q, "stale")')]),
    # Reconciler 0's pending designation of host 2 lands after reconciler 1 moved the slot and designated host 3.
    "designate-write-ignores-version": (
        "NewerDesignationStands", DESIGNATING + MOVE + designate(1, 1, 3) + ["request(0)"],
        [('else if (w.key == "shard") s.shards.get(w.s).ver == w.expect', 'else if (w.key == "shard") true')]),
    "reserve-moves-live-incumbent": ("SlotMovesOnlyOnEvidence", RESERVED + reserve(1, 1, 3), [(TAKEN_LINE, "")]),
    # Under the reversed order the reservation's start reads the shard record.
    "reserve-reads-shard-first": (
        "EntryTargetAdvances",
        op(0, "reserve", 1, 2, 0) + ["bump(1)"] + reserve(1, 1, 2) + ["request(0)"] * 3,
        [(RESERVE_ORDER, 'if (op == "reserve") ["shard", "census", "volume", "write"]')]),
    "owner-as-candidate": ("FeasibleSlot", reserve(0, 1, 1),
                           [('if (p.rec.e == 0 or p.h == p.rec.owner) ended(p, "ineligible")',
                             'if (p.rec.e == 0) ended(p, "ineligible")')]),
    # A release drops host 3's entry while reconciler 0 records host 3's attach under that slot, and the slot the
    # entry held goes to an attachment outside the census.
    "release-ignores-recording": (
        "HostAttachmentsWithinLimit",
        CLAIMED + op(0, "record", 1, 3, 1) + ["bump(1)"] + release(1, 1)
        + ["request(0)", "request(0)", "occupy(3)", "attachEnds(1, 3, true)"],
        IGNORES_RECORDING, S2H),
    # Reconciler 0's attach record write is held when a release drops host 3's entry; the write lands later, and its
    # live event lets a new reservation of host 3 skip Headroom after an outside attachment fills the host.
    "release-ignores-held-record": (
        "HostAttachmentsWithinLimit",
        CLAIMED + op(0, "record", 1, 3, 1) + ['unknown(0, "hold")', "bump(1)"] + release(1, 1)
        + ["deliver", "occupy(3)"] + reserve(0, 1, 3),
        IGNORES_HELD_RECORD, S2H),
    # Reconciler 0, idle and holding host 3's slot, begins the attach record after a release decided to drop the
    # entry and before that drop commits.
    "record-after-drop-decision": (
        "HostAttachmentsWithinLimit",
        CLAIMED + ["bump(1)"] + op(1, "release", 1, 1, 2) + ['begin(0, "record", 1, 3)', "request(1)"]
        + ["request(0)"] * 3 + ["occupy(3)", "attachEnds(1, 3, true)"],
        [(DROP_GUARD, "")], S2H),
    # Reconciler 1's release decides to drop host 3's entry and its census write is held; reconciler 0, idle and
    # holding host 3's slot, begins the attach record, and the held drop lands before the record's volume write.
    "record-after-held-drop": (
        "HostAttachmentsWithinLimit",
        CLAIMED + ["bump(1)"] + op(1, "release", 1, 1, 2) + ['unknown(1, "hold")', 'begin(0, "record", 1, 3)', "deliver"]
        + ["request(0)"] * 3 + ["occupy(3)", "attachEnds(1, 3, true)"],
        [(HELD_DROP, "")], S2H),
    # Reconciler 0, holding host 3's slot, begins the attach record after a release dropped the entry; an attachment
    # outside the census takes the slot the entry held, and the attach completes.
    "record-ignores-listing": (
        "HostAttachmentsWithinLimit",
        CLAIMED + ["bump(1)"] + release(1, 1) + op(0, "record", 1, 3, 3) + ["occupy(3)", "attachEnds(1, 3, true)"],
        IGNORES_LISTING, S2H),
    "pending-uncounted": ("HostAttachmentsWithinLimit", CLAIMED + reserve(1, 2, 3), PENDING_UNCOUNTED, S2H),
    # Reconciler 0 holds the census write of shard 1's reservation for host 3; an attachment outside the census takes
    # a slot on host 3 before the held census write lands.
    "occupy-during-held-reservation": (
        "HostAttachmentsWithinLimit",
        LOST_1 + ["takeover(1)"] + op(0, "reserve", 1, 3, 2) + ['unknown(0, "hold")', "occupy(3)", "deliver"],
        [OCCUPY_HELD], S2H),
    # Host 3 enrolls before its attach completes, so shard 1's entry stops counting as pending while the attach is
    # not yet counted as used, and the second reservation commits past the limit.
    "enroll-before-attach": (
        "HostAttachmentsWithinLimit",
        CLAIMED + op(0, "record", 1, 3, 3) + op(0, "enroll", 1, 3, 3) + reserve(1, 2, 3),
        ENROLL_BEFORE_ATTACH, S2H),
    # A reconciler that holds no slot records host 2's attach of shard 1's volume.
    "attach-before-reservation": ("AttachFollowsReservation", op(0, "record", 1, 2, 2), [(RECORD_GUARD, "")], S2E),
    # Host 1's enrollment on shard 2 reads the volume record before a flip, and its write lands on the new volume's
    # record; after the fresh acquisition host 1 is reserved and designated there with no live attach.
    "volume-write-ignores-version": (
        "DesignatedIsEnrolled",
        reserve(0, 2, 1) + op(0, "record", 2, 1, 3) + ["attachEnds(2, 1, true)"]
        + ['begin(0, "enroll", 2, 1)', "request(0)", "flip(2, 3)", "request(0)", "request(0)", "fresh(2)"]
        + reserve(1, 2, 1) + designate(1, 2, 1),
        [("    else s.volumes.get(w.s).ver == w.expect\n", "    else true\n")]),
    # The premise control of true loss evidence: reconciler 0 falsely suspects host 2 and takes shard 1's slot for
    # host 3, and reconciler 1 falsely suspects host 3 and moves the slot off it while host 3's recorded attach is in
    # flight, so that attach is counted nowhere until it completes.
    "false-suspicion-headroom": (
        "HostAttachmentsWithinLimit",
        ["suspect(0, 2)"] + reserve(0, 1, 3) + op(0, "record", 1, 3, 3) + ["suspect(1, 3)"] + reserve(1, 1, 2)
        + ["lose(1)", "learn(0, 1)"] + reserve(0, 2, 3) + ["attachEnds(1, 3, true)"],
        [], {**S2H, "SUSPECTS": "2", "OCCUPY": "0"}),
    # The transfer keeps the standby it named owner, so the record names one host owner and standby.
    "transfer-keeps-standby": ("FeasibleSlot", DESIGNATED + ["transfer(1)"],
                               [("{...r, e: r.e + 1, owner: r.standby, standby: 0, ver: r.ver + 1}",
                                 "{...r, e: r.e + 1, owner: r.standby, standby: r.standby, ver: r.ver + 1}")]),
    # The transfer makes a named standby owner though its attach ended in a race with its designation.
    "transfer-ignores-target-attach": ("OwnerHoldsItsAttach",
                                       ["endRead(1, 2)"] + DESIGNATING + ["endWrite(1, 2)", "request(0)", "transfer(1)"],
                                       [("r.e + 1 < EMAX, targetReady,", "r.e + 1 < EMAX,")]),
    # After the owner's bump, the transfer takes the last attempt, which the new owner needs for its own bump.
    "transfer-spends-last-attempt": ("TransferLeavesBump", DESIGNATED + ["bump(1)", "transfer(1)"],
                                     [("r.e + 1 < EMAX, targetReady,", "r.e < EMAX, targetReady,")]),
    # The takeover makes a named standby owner though its attach ended in a race with its designation.
    "takeover-ignores-end": ("OwnerHoldsItsAttach", ["endRead(1, 2)"] + DESIGNATING + ["endWrite(1, 2)", "request(0)",
                                                                                     "takeover(1)"],
                             [("r.e < EMAX, ready,", "r.e < EMAX,")]),
    # The end lands while a designation of host 2 writes next, and that write is lost. A second designation, begun
    # after the end with no enrollment check, names host 2: its volume read showed no live attach, so the record
    # names a standby whose attach ended in no race with that designation.
    "designate-unenrolled-after-race": (
        "DesignatedIsEnrolled",
        ["endRead(1, 2)"] + DESIGNATING + ["endWrite(1, 2)", 'unknown(0, "lost")'] + designate(0, 1, 2),
        [(UNENROLLED_LINE, "")]),
    # A landed end clears the failure of an attach that failed for good: host 3's entry stopped owing a slot when its
    # attach failed, an attachment outside the census took that slot, and after the end the entry owes an attach again.
    "end-clears-failed": (
        "HostAttachmentsWithinLimit",
        LOST_1 + reserve(0, 2, 3) + op(0, "record", 2, 3, 2)
        + ["attachEnds(2, 3, false)", "occupy(3)", "endRead(2, 3)", "endWrite(2, 3)"],
        [("attached: if (owner) st.attached else st.attached.exclude(Set((s, h)))},",
          "attached: if (owner) st.attached else st.attached.exclude(Set((s, h))), "
          "failed: st.failed.exclude(Set((s, h)))},")], S2H),
    # A landed end keeps the ended attach's enrolled pair: a later designation of the host passes its enrollment
    # check and names a standby with no live attach.
    "end-keeps-enrolled": ("DesignatedIsEnrolled",
                           ["endRead(1, 2)"] + RESERVED + ["endWrite(1, 2)"] + designate(0, 1, 2),
                           [("enrolled: v.enrolled.exclude(Set(h)),", "enrolled: v.enrolled,")]),
    # The enrollment of a host with a completed attach and no live attach writes its pair: deposed owner 2, whose
    # end left it its attachment, enrolls with no attach record and is reserved and designated.
    "enroll-unattached": ("DesignatedIsEnrolled",
                          DEPOSED + op(0, "enroll", 1, 2, 3) + reserve(0, 1, 2) + designate(0, 1, 2),
                          [(UNATTACHED_LINE, "")]),
    # The premise control of the attach call following its record: the control plane completes host 3's attach of
    # both volumes before any attach record or census entry names host 3.
    "attach-before-record": ("HostAttachmentsWithinLimit", ["attachEnds(1, 3, true)", "attachEnds(2, 3, true)"],
                             ATTACH_BEFORE_RECORD, S2H),
    # The premise control of a final failure: host 3's recorded attach fails for good, so its entry stops owing a
    # slot; an attachment outside the census takes that slot, and the attach then completes.
    "failed-attach-completes": (
        "HostAttachmentsWithinLimit",
        CLAIMED + op(0, "record", 1, 3, 3) + ["attachEnds(1, 3, false)", "occupy(3)", "attachEnds(1, 3, true)"],
        FAILED_ATTACH_COMPLETES, S2H),
    # The premise control of no answer after an end: host 3's recorded attach ends before the control plane answers
    # it, a release drops its entry on the ended record, an attachment outside the census takes the slot the entry
    # owed, and the attach then completes.
    "ended-attach-completes": (
        "HostAttachmentsWithinLimit",
        CLAIMED + op(0, "record", 1, 3, 3) + ["endRead(1, 3)", "endWrite(1, 3)", "bump(1)"] + release(1, 1)
        + ["occupy(3)", "attachEnds(1, 3, true)"],
        ENDED_ATTACH_COMPLETES, S2H),
    # The premise control of no flip where the attachment limit binds: two flips make host 3, with one free
    # attachment slot, the owner of both shards on volumes it attaches.
    "flip-at-attach-limit": ("HostAttachmentsWithinLimit", ["flip(1, 3)", "flip(2, 3)"], [], {**S2H, "GMAX": "2"}),
    # After a census write loses its condition, the reservation retries with the host it planned, past the role limit.
    "retry-without-replan": (
        "StandbyRolesWithinHostLimit",
        STORM_RACING + ["request(0)", "request(1)"] + ["request(1)"] * 4,
        RETRY_WITHOUT_REPLAN, S3),
    # A fresh contender takes a live named standby's entry: after shard 1 names host 3 and the owner bumps, the
    # release drops the entry with neither the standby nor the live-attach guard, and shard 2's fresh host is
    # designated, so three shards name standbys under a cap of two.
    "fresh-takes-live-standby-entry": (
        "StandbysUnderCap",
        STORM_CLAIMED + attach(0, 1, 3) + designate(0, 1, 3) + ["bump(1)"] + release(1, 1) + reserve(1, 2, 4)
        + attach(1, 2, 4) + designate(1, 2, 4),
        [(STANDBY_LINE, ""), (LIVE_LINE, "")], S3),
    # Reconciler 1 maps shard 2 to another zone, whose census it reserves and designates under.
    "zones-disagree": (
        "StandbysUnderCap", STORM + reserve(1, 2, 4) + attach(1, 2, 4) + designate(1, 2, 4),
        [("pure def zoneOf(r: int, s: int): int = ZONE",
          "pure def zoneOf(r: int, s: int): int = if (r == 1 and s == 2) 2 else ZONE")], S3),
    # With a one-role limit, reconciler 0 falsely suspects host 2 and moves shard 1's slot to host 4; host 2, shard
    # 1's named standby, then takes shard 1 over while reconciler 1's entry for shard 3 names it, two roles.
    "false-suspicion-roles": (
        "StandbyRolesWithinHostLimit",
        STORM + ["suspect(0, 2)"] + reserve(0, 1, 4) + reserve(1, 3, 2) + ["takeover(1)"],
        [], {**S3, "SUSPECTS": "1", "ROLES": "1"}),
    # The premise control of no flip where the role limit binds: two flips make host 3, the owner of shard 3, the
    # owner of all three shards.
    "flip-at-role-limit": ("StandbyRolesWithinHostLimit", ["flip(1, 3)", "flip(2, 3)"], [], {**S3, "GMAX": "2"}),
    "ineligible-ignores-unacquired": ("FeasibleSlot", ["flip(1, 3)"] + reserve(0, 1, 2),
                                      [('if (p.rec.e == 0 or p.h == p.rec.owner) ended(p, "ineligible")',
                                        'if (p.h == p.rec.owner) ended(p, "ineligible")')]),
}


# Each recipe reach case: a recipe of the unmutated model and the state its last action reaches.
RECIPES = {
    # Reconciler 0's census read after the move refuses Conflict before any designation of host 3.
    "conflictBeforeDesignation": (
        RACING + ["request(0)"],
        'ev.res == "conflict" and ev.proc == 0 and st.shards.get(1) == {g: 1, owner: 1, e: 1, standby: 0, ver: 1} '
        "and st.census.get(1).slots.get(1) == {on: true, g: 1, owner: 1, e: 1, host: 3}"),
    # Reconciler 0's pending designation of host 2 loses its version condition to host 3's designation at the same
    # tenure.
    "designationOvertaken": (
        DESIGNATING + MOVE + designate(1, 1, 3) + ["request(0)"],
        'ev.act == "write" and ev.key == "shard" and ev.res == "condition" and ev.proc == 0 '
        "and st.shards.get(1) == {g: 1, owner: 1, e: 1, standby: 3, ver: 2}"),
    # A held shard write is refused at delivery after the owner's bump.
    "heldDeliveryRefused": (
        DESIGNATING + ['unknown(0, "hold")', "bump(1)", "deliver"],
        'ev.act == "deliver" and ev.res == "refused" '
        "and st.shards.get(1) == {g: 1, owner: 1, e: 2, standby: 0, ver: 2}"),
    # A move admitted on the false suspicion keeps that grounds when the held write lands after host 2's loss.
    "suspicionHeldAcrossLoss": (
        RESERVED + ["suspect(1, 2)"] + op(1, "reserve", 1, 3, 2) + ['unknown(1, "hold")', "lose(2)", "deliver"],
        'ev.act == "deliver" and ev.res == "committed" and ev.note == "movedOnSuspicion" '
        "and st.census.get(1).slots.get(1).host == 3"),
    # A release drops host 2's entry on the loss its reconciler learned.
    "releaseDropsOnLoss": (
        RESERVED + ["bump(1)", "lose(2)", "learn(1, 2)"] + release(1, 1),
        'ev.res == "released" and not(st.census.get(1).slots.get(1).on) and SlotMovesOnlyOnEvidence'),
    # Host 2's end is decided before its reservation; reconciler 0's designation of host 2 has read the volume record
    # when the end lands, and the designation then commits naming host 2.
    "designationRacesEnd": (
        ["endRead(1, 2)"] + DESIGNATING + ["endWrite(1, 2)", "request(0)"],
        "witnessNamedEnded and st.shards.get(1).standby == 2 and not(st.volumes.get(1).live.contains(2))"),
    # Host 2's attach of shard 1's volume is decided to end before host 2 holds the slot and ends after; after the
    # owner's bump a release drops the entry, whose host the volume record no longer shows live.
    "releasedAfterEnd": (
        ["endRead(1, 2)"] + RESERVED + ["endWrite(1, 2)", "bump(1)"] + release(1, 1),
        "witnessReleasedAfterEnd and not(st.volumes.get(1).live.contains(2))"),
    # Host 4's reservation on shard 1 refuses Closed at `VOLMAX` live attaches; host 3's attach ends, and host 4's
    # reservation and attach record then complete in the slot that end freed.
    "reopenedAfterEnd": (
        op(0, "reserve", 1, 4, 2) + ["endRead(1, 3)", "endWrite(1, 3)"] + reserve(0, 1, 4) + op(0, "record", 1, 4, 3),
        "witnessReopenedAfterEnd and st.volumes.get(1).live == Set(1, 2, 4)", S4),
    # Host 2's end is decided while the record names no standby; reconciler 0 reserves and designates host 2, and the
    # end then lands with no designation in flight.
    "designationBeforeEndLands": (
        ["endRead(1, 2)"] + RESERVED + designate(0, 1, 2) + ["endWrite(1, 2)"],
        "en.raced.contains((1, 2)) and st.shards.get(1).standby == 2 and not(st.volumes.get(1).live.contains(2)) "
        "and procs.get(0).op == \"idle\""),
    # Host 2's end is decided; host 2 is designated and takes the shard over, and the end lands on the owner, which
    # keeps its attach.
    "endLandsOnOwner": (
        ["endRead(1, 2)"] + DESIGNATED + ["takeover(1)", "endWrite(1, 2)"],
        "st.shards.get(1).owner == 2 and st.attached.contains((1, 2)) and not(st.volumes.get(1).live.contains(2)) "
        "and en.endedOwners.contains((1, 2))"),
    # Host 3's end of shard 2's volume is decided, host 1's attach record then writes that volume record, and the end
    # refuses on the moved version with no write.
    "endRefusedOnMovedVolume": (
        ["endRead(2, 3)"] + reserve(0, 2, 1) + op(0, "record", 2, 1, 3) + ["endWrite(2, 3)"],
        'ev.act == "endRefused" and st.volumes.get(2).live.contains(3) and en.ending == Set()'),
    # Host 2 takes shard 1 over with its end decided, host 3 is designated, the end lands on owner 2, which keeps its
    # attachment, and host 3 takes over: host 2's enrollment refuses, since the volume record shows it no live attach.
    "enrollRefusedUnattached": (
        DEPOSED + ['begin(0, "enroll", 1, 2)', "request(0)"],
        'ev.res == "unattached" and st.shards.get(1).owner == 3 and st.attached.contains((1, 2)) '
        "and not(st.volumes.get(1).live.contains(2)) and not(st.volumes.get(1).enrolled.contains(2))"),
    # Host 1's live attach of shard 2's volume has no pair; after the owner's bump the release keeps its entry.
    "unenrolledKeepsLive": (
        reserve(0, 2, 1) + op(0, "record", 2, 1, 3) + ["bump(2)"] + op(1, "release", 2, 1, 2),
        'ev.res == "keptLive" and st.census.get(1).ver == 1 '
        "and st.census.get(1).slots.get(2) == {on: true, g: 1, owner: 2, e: 1, host: 1} "
        "and st.volumes.get(2).live.contains(1) and not(st.volumes.get(2).enrolled.contains(1))"),
    # An attach record that read the volume record before a flip refuses at its shard read with no write.
    "recordRefusedAtFlip": (
        reserve(0, 2, 1) + ['begin(0, "record", 2, 1)', "flip(2, 3)", "fresh(2)", "request(0)"],
        'ev.res == "notServing" and st.shards.get(2).e == 1 '
        "and st.volumes.get(2) == {live: Set(3), enrolled: Set(3), ver: 2}"),
    # An attach record whose volume write committed refuses at its last shard read after a flip and a fresh
    # acquisition, which name a new volume.
    "recordRefusedAfterFlip": (
        reserve(0, 2, 1) + op(0, "record", 2, 1, 2) + ["flip(2, 3)", "fresh(2)", "request(0)"],
        'ev.res == "notServing" and st.volumes.get(2).ver == 3 and st.recorded.contains((2, 1)) '
        "and st.shards.get(2).g == 2 and st.shards.get(2).e == 1"),
    # An enrollment that read the volume record before a flip refuses Tenure at its shard read with no write.
    "enrollRefusedAtFlip": (
        reserve(0, 2, 1) + op(0, "record", 2, 1, 3) + ["attachEnds(2, 1, true)", 'begin(0, "enroll", 2, 1)',
                                                       "flip(2, 3)", "fresh(2)", "request(0)"],
        'ev.res == "tenure" and st.shards.get(2).e == 1 '
        "and st.volumes.get(2) == {live: Set(3), enrolled: Set(3), ver: 3}"),
    # An enrollment whose volume write committed refuses Tenure at its last shard read after a flip and a fresh
    # acquisition.
    "enrollRefusedAfterFlip": (
        reserve(0, 2, 1) + op(0, "record", 2, 1, 3) + ["attachEnds(2, 1, true)"] + op(0, "enroll", 2, 1, 2)
        + ["flip(2, 3)", "fresh(2)", "request(0)"],
        'ev.res == "tenure" and st.volumes.get(2).ver == 4 and st.shards.get(2).g == 2 and st.shards.get(2).e == 1'),
    # Both reconcilers hold host 1's slot of shard 2 and record its attach over one volume version; the second volume
    # write loses its condition and leaves the record as the first wrote it.
    "volumeConditionLost": (
        reserve(0, 2, 1) + op(1, "reserve", 2, 1, 2) + ['begin(0, "record", 2, 1)', 'begin(1, "record", 2, 1)',
                                                        "request(0)", "request(1)", "request(0)", "request(1)"],
        'ev.act == "write" and ev.key == "volume" and ev.res == "condition" and ev.proc == 1 '
        "and st.volumes.get(2) == {live: Set(2, 3, 1), enrolled: Set(2, 3), ver: 2}"),
    # A release of shard 2, which the census does not list, leaves the census as it is.
    "unlistedKeepsCensus": (
        RESERVED + op(1, "release", 2, 1, 2),
        'ev.res == "unlisted" and st.census.get(1).ver == 1 '
        "and st.census.get(1).slots.get(1) == {on: true, g: 1, owner: 1, e: 1, host: 2} "
        "and not(st.census.get(1).slots.get(2).on)"),
}

def single_instances():
    """Refuse a run, mutant or recipe row that names more than one instance."""
    if bad := [name for table in (RUNS, MUTANTS) for name, row in table.items() if len(row) > 4] + [
            name for name, row in RECIPES.items() if len(row) > 3]:
        raise ValueError(f"standbys: rows {bad} name more than one instance")


def cases(Case):
    single_instances()
    yield Case("standbys-typecheck", command="typecheck", family="standbys")
    yield Case("standbys-safety", invariant="safety", family="standbys", depth=int(CONSTANTS["BOUND"]) + 1)
    yield Case("standbys-replay", command="replay", family="standbys")
    for witness in WITNESSES:
        yield Case(f"standbys-reach-{witness}", invariant="unreached", expected="violation", family="standbys",
                   extra=f"  val unreached = not({witness})\n", after=1)
    for name, (recipe, outcome, checks, *instance) in RUNS.items():
        if any(not 0 < at <= len(recipe) for at in checks):
            raise ValueError(f"standbys-run-{name}: a check names a turn outside its recipe")
        clauses = "".join(f" and (turn == {at} implies ({check}))" for at, check in sorted(checks.items()))
        settings = {**(instance[0] if instance else {}), "BOUND": str(len(recipe))}
        yield Case(f"standbys-run-{name}", invariant="runSafety", family="standbys", recipe=recipe, settings=settings,
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome})){clauses}\n")
        yield Case(f"standbys-run-{name}-reached", invariant="runWitness", expected="violation", family="standbys",
                   recipe=recipe, settings=settings, trace=len(recipe) + 1,
                   extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (prop, recipe, mutations, *instance) in MUTANTS.items():
        yield Case(f"standbys-mutant-{name}", invariant=prop, expected="violation", family="standbys", recipe=recipe,
                   settings={**(instance[0] if instance else {}), "BOUND": str(len(recipe))}, mutations=mutations,
                   trace=len(recipe) + 1)
    for name, (recipe, outcome, *instance) in RECIPES.items():
        yield Case(f"standbys-recipe-{name}", invariant="unreached", expected="violation", family="standbys",
                   recipe=recipe, settings={**(instance[0] if instance else {}), "BOUND": str(len(recipe))},
                   trace=len(recipe) + 1,
                   extra=f"  val unreached = not({outcome})\n")


# A module-level line of the model opens an item with one of these keywords, after two spaces of indentation.
ITEM = re.compile(r"  (pure val|pure def|action|def|val|type|var|const) (\w+)")
# The items a case's instance drops when nothing the case checks names them. Constants, types and variables stay.
PRUNABLE = ("action", "def", "val", "pure def")
WORD = re.compile(r"[A-Za-z_]\w*")


def entries(case):
    """The names case `case` enters the model by: the words of its instance text and its recipe, its invariant and
    its step, `init`, and the free scheduler `step` for a search that names no step."""
    names = set(WORD.findall("\n".join([case.extra, *case.recipe, case.invariant or "", case.step or ""])))
    names.add("init")
    if not case.recipe and not case.step:
        names.add("step")
    return names


def items(text, case_name):
    """The model's text as its lines before the module's first item, its module-level items in order, each a
    `(kind, name, lines)` triple that starts at its first doc-comment line and ends before the next item, and the
    line that closes the module. A module-level line that is neither a doc comment, an item's opening line nor a
    line that closes an item's block raises ValueError, as does a doc comment that no item follows."""
    lines = text.split("\n")
    last = max(at for at, line in enumerate(lines) if line == "}")
    first = next(at for at, line in enumerate(lines) if line.startswith("module ")) + 1
    found, block, opened = [], [], None
    for line in lines[first:last]:
        level = line.startswith("  ") and not line.startswith("   ")
        doc = level and line.startswith("  ///")
        opening = ITEM.match(line) if level and not doc else None
        if level and not doc and not opening and not line.startswith("  }"):
            raise ValueError(f"{case_name}: the model holds a module-level line that opens no item: {line!r}")
        if (doc or opening) and opened and (opening or not block[-1].startswith("  ///")):
            found.append((*opened, block))
            block, opened = [], None
        block.append(line)
        if opening:
            opened = (opening[1], opening[2])
    if not opened or block[-1].startswith("  ///"):
        raise ValueError(f"{case_name}: the model ends in a doc comment that no item follows")
    found.append((*opened, block))
    return lines[:first], found, lines[last:]


def prune(text, keep, case_name):
    """The model text without the actions, definitions and values that nothing in `keep` reaches: an item is reached
    when `keep` names it or a reached item's code, or a constant's, type's or variable's, names it. Every action and
    definition a kept item names is part of the instance Apalache translates for TLC, whose size its server bounds,
    so an instance holds only what its case checks. A prunable name defined twice raises ValueError."""
    head, found, tail = items(text, case_name)
    prunable = [name for kind, name, _ in found if kind in PRUNABLE]
    repeated = sorted({name for name in prunable if prunable.count(name) > 1})
    if repeated:
        raise ValueError(f"{case_name}: the model defines {repeated} more than once")
    words = {name: set(WORD.findall("\n".join(line for line in block if not line.startswith("  ///"))))
             for _, name, block in found}
    reached = set()
    frontier = set(keep) | {word for kind, name, _ in found if kind not in PRUNABLE for word in words[name]}
    while frontier:
        name = frontier.pop()
        if name in prunable and name not in reached:
            reached.add(name)
            frontier |= words[name]
    kept = [line for kind, name, block in found if kind not in PRUNABLE or name in reached for line in block]
    return "\n".join(head + kept + tail)


def inputs(case, source):
    text = (source / "standbys.qnt").read_text()
    for old, new in case.mutations:
        if text.count(old) != 1:
            raise ValueError(f"{case.name}: mutation target is not unique")
        text = text.replace(old, new)
    if case.command not in ("typecheck", "replay"):
        text = prune(text, entries(case), case.name)
    extra = case.extra
    if case.recipe:
        picks = {}
        for at, action in enumerate(case.recipe):
            picks.setdefault(action, []).append(str(at))
        extra += "  action recipe = any {\n" + "".join(
            f'    all {{ Set({", ".join(turns)}).contains(turn), {action} }},\n' for action, turns in picks.items()) + "  }\n"
    bindings = ", ".join(f"{name} = {value}" for name, value in {**CONSTANTS, **case.settings}.items())
    return {"standbys.qnt": text,
            "case.qnt": f'module standbysCase {{\n  import standbys({bindings}).* from "./standbys"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "replay":
        return ["cargo", "test", "-p", "kestrike", "--lib", "--", "--ignored", "--exact", REPLAY_TEST, "--nocapture"]
    if case.command == "typecheck":
        return [quint, "typecheck", "standbys.qnt"]
    step = ["--step", "recipe"] if case.recipe else ["--step", case.step] if case.step else []
    return [quint, "verify", "case.qnt", "--main", "standbysCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + step
