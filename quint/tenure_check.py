"""Tenure model cases: typecheck, each safety invariant, reachability witnesses, the directed runs, the negative
recipes, the mutated runs that must pass, the prefixed takeover search with its reach companion and the planted
mutations, with the restart and takeover schedules for the invariants that check there, and the reclaim and handoff
schedules' prefix roots, runs and mutants.

A run is a recipe of model actions that restricts the scheduler to one schedule; it passes only when TLC checks
`safety` over the whole recipe, one state per action after `init`, and its last state holds the end its `RUNS` entry
names: `v2` retired, the restart's FB, or the takeover state the entry states.

The takeover search at `BOUND = 12` ends at the lineage arm's bump, before its acknowledgment, so the arm's Register,
reread, preempt and Report #2 are searched from `ARM_ROOT`, a restart's Report #1 that took the arm, under the takeover
schedules (`arm_root_cases`); `ArmFbConfirmed` checks there, where an arm FB is reachable.

The reclaim cases (`reclaim_cases`) start at `reclaimInit` and step under `reclaimStep`: an attach recorded,
requested, enrolled, ended, its key preempted, its pair dropped, detached and marked gone. Four prefix roots search
`reclaimSafety` exhaustively at three and four hosts; each run holds `reclaimSafety` and its stated end, with a
`-reached` companion; each mutant violates its named property at its recipe's last action.
"""

import re

CONSTANTS = {"BOUND": "9"}
INVARIANTS = ("OneActiveVolumePerShard", "NoEpochReuse", "NoBumpAfterFlip", "OneFlipPerGeneration",
              "ReplacedSpareNeverActive", "AttachOutsideDesiredStateRetires", "RecordedAttachRetiresNothing", "FreshIsEmpty",
              "NoPreemptOfForeignKey",
              "DetectedLossWithdraws", "RecordsBeforeDevice", "BumpAtOwnGeneration", "NoPredecessorEffectAfterFB",
              "NoWriteBeforeFB", "OwnBumpBeforeFB")
TAKEOVER_INVARIANTS = ("NoEpochReuse", "OwnBumpBeforeFB", "RecordsBeforeDevice", "NoPreemptOfForeignKey",
                       "InterruptedTakeoverRetainsVolume", "StalePreemptRetainsVolume", "NamedStandbyTakesOver",
                       "TakeoverCasBeforeDevice", "RestartRetiresOnlyOnObservation", "DeviceFailureRetainsVolume",
                       "OwnBumpBeforePreempt", "ArmFbConfirmed")
WITNESSES = ("witnessFlip", "witnessActivated", "witnessSecondGeneration", "witnessCommittedTimeout",
             "witnessStaleBumpRefused", "witnessFlipRaceLost", "witnessSpareReplaced", "witnessPollRetired",
             "witnessKeptBesideStandby", "witnessKeptBeforeStandbyListed", "witnessPollRetiresUnbound",
             "witnessSpareRetired", "witnessFreshRefused", "witnessFreshAfterRefusal", "witnessPreempt",
             "witnessDeposedObserved", "witnessCommandThenLoss", "witnessRestartDevice", "witnessFreshFb",
             "witnessFreshWrite", "witnessTakeoverFb", "witnessTakeoverChain", "witnessSupersededPreempt",
             "witnessLandAfterTakeoverFb", "witnessStatusRetires", "witnessUnnamedRefused",
             "witnessStaleStandbyRefused", "witnessUnknownThenRestart",
             "witnessRerunAfterForeignRefusal", "witnessRerunAfterUnheldRefusal", "witnessRerunAfterDeviceRefusal")
FLIP_CONDITION = ("s.spare == r.spare and s.spareHost == r.spareHost and s.g == r.g and s.active == r.active "
                  "and s.owner == r.owner and s.e == r.e")
# The restart retirement admitting a device-failure refusal beside the unrecorded holder's, at the step-1 target or,
# after a failure past the bump, at the bumped target the Rust hold names.
DEVICE_FAILURE_RETIRES = ('q.phase == "refusedForeign", rec.owner == q.host',
                          'Set("refusedForeign", "refusedDevice").contains(q.phase), rec.owner == q.host')
DEVICE_FAILURE_TARGET = ('rec.g == q.g, rec.e == q.n, advance("restartRetire", p)',
                         'rec.g == q.g, (rec.e == q.n or (q.phase == "refusedDevice" and rec.e == q.n + 1)), '
                         'advance("restartRetire", p)')
# The restart's Report #1 relabels the lineage arm's recorded holder as the unrecorded holder's refusal.
RECORDED_HOLDER_RETIRES = ('else if (lineageHolder) "reportedHolder"', 'else if (lineageHolder) "refusedForeign"')
CONFIRMED = ("val confirmed = holding and holder == q.key\n"
             '      and ((not(q.takeover) and q.prkey == "") or (rec.owner == q.host and rec.e == q.n + 1))\n'
             "      and liveKey(q.key)")
TAKEOVER_HOLDER = "val recordedHolder = holding and holder != q.key and paired(holder) and keyHost(holder) != q.host"
NAMED = "val named = rec.standby == h and live(h) and paired(attachKey(h))"
TENURE_CHECK = "val current = rec.g == q.g and rec.owner == q.host and rec.e == q.n + 1 and liveKey(q.key)"
# The caller's binding without its read of the recorded attach event: it binds a host whose event the volume record
# lacks.
BIND_WITHOUT_EVENT = ("not(retired.contains(rec.active)), events.get(rec.active).contains(h),\n"
                      "    not(bound.contains((rec.active, h)))",
                      "not(retired.contains(rec.active)),\n    not(bound.contains((rec.active, h)))")
# Each mutation, the invariant it must break, and its replacements of the model's text.
MUTANTS = {
    "flip-without-condition": ("OneActiveVolumePerShard", (FLIP_CONDITION, "true")),
    "bump-on-counter-alone": ("NoBumpAfterFlip",
                              ("r.g == s.g and r.active == s.active and r.owner == s.owner and r.e == s.e", "r.e == s.e")),
    "reread-after-timeout": ("NoEpochReuse", ("val reread = false", "val reread = true")),
    "idempotent-flip-commits": ("OneFlipPerGeneration",
                                ("if (r.kind == \"flip\") flipHolds(r, s)", "if (r.kind == \"flip\") (flipHolds(r, s) or applied(r, s) == s)")),
    "flip-ignores-spare": ("ReplacedSpareNeverActive",
                           ("s.spare == r.spare and s.spareHost == r.spareHost and s.g == r.g", "s.g == r.g")),
    "fresh-reads-events": ("FreshIsEmpty", ("val fresh = rec.e > 0 or listed.get(rec.active) == Set(h)",
                                            "val fresh = rec.e > 0 or events.get(rec.active) == Set(h)")),
    "poll-ignores-listing": ("AttachOutsideDesiredStateRetires",
                             ("val inside = listing.contains(rec.owner) and listing.subseteq(admittedSet(rec.active))",
                              "val inside = true")),
    "poll-never-retires": ("AttachOutsideDesiredStateRetires",
                           ("retired' = if (inside) retired else retired.union(Set(rec.active)),", "retired' = retired,")),
    # The poll retires on every listing, so a poll that keeps serving on its admitted set retires the volume too.
    "poll-retires-kept": ("AttachOutsideDesiredStateRetires",
                          ("retired' = if (inside) retired else retired.union(Set(rec.active)),",
                           "retired' = retired.union(Set(rec.active)),")),
    # The poll filters its listing to recorded attach events, so the volume keeps serving beside an unrecorded
    # attachment.
    "poll-filters-listing": ("AttachOutsideDesiredStateRetires",
                             ("  action poll = {\n    val listing = listed.get(rec.active)",
                              "  action poll = {\n    val listing = listed.get(rec.active).intersect(events.get(rec.active))")),
    # The poll admits every host whose attach event the volume record holds, bound by its caller or not.
    "poll-admits-unbound-attach": ("AttachOutsideDesiredStateRetires",
                                   ("listing.subseteq(admittedSet(rec.active))",
                                    "listing.subseteq(Set(rec.owner).union(events.get(rec.active)))")),
    # The admitted set drops the caller's binding, so the poll and its own definition agree on a wider set.
    "admitted-set-ignores-binding": ("AttachOutsideDesiredStateRetires",
                                     ("Set(rec.owner).union(events.get(v).filter(h => bound.contains((v, h))))",
                                      "Set(rec.owner).union(events.get(v))")),
    # The caller binds a host whose attach event the volume record lacks, and the admitted set drops the recorded
    # event, so the poll keeps serving beside a bound attachment whose event the record does not hold.
    "admitted-set-ignores-events": ("AttachOutsideDesiredStateRetires", BIND_WITHOUT_EVENT,
                                    ("Set(rec.owner).union(events.get(v).filter(h => bound.contains((v, h))))",
                                     "Set(rec.owner).union(boundHosts(v))")),
    # That binding alone: the attach request follows it with no attach event recorded, and the admitted set, which
    # needs the recorded event, retires the volume.
    "bind-without-attach-event": ("RecordedAttachRetiresNothing", BIND_WITHOUT_EVENT),
    # The poll requires the listing to equal the admitted set, so a bound standby not yet listed retires the volume.
    "poll-requires-every-standby": ("RecordedAttachRetiresNothing",
                                    ("listing.subseteq(admittedSet(rec.active))", "listing == admittedSet(rec.active)")),
    # The poll also requires the caller to bind every recorded attach event other than the owner's, the model's form
    # of one clause of the Rust OWNER-EVENTS rule, so a poll between the record write and the binding retires.
    "poll-judges-recorded-events": ("RecordedAttachRetiresNothing",
                                    ("listing.subseteq(admittedSet(rec.active))",
                                     "listing.subseteq(admittedSet(rec.active)) and events.get(rec.active).forall("
                                     "h => h == rec.owner or bound.contains((rec.active, h)))")),
    # The reconciler's attach request precedes the record write of the host's attach event.
    "attach-request-before-record": ("RecordedAttachRetiresNothing",
                                     ("val ordered = bound.contains((rec.active, h))", "val ordered = true")),
    # The attach request follows the record write and precedes the caller's read of the recorded event.
    "attach-before-caller-binding": ("RecordedAttachRetiresNothing",
                              ("val ordered = bound.contains((rec.active, h))",
                               "val ordered = events.get(rec.active).contains(h)")),
    # The premise control: a foreign attachment that detaches before the fresh check leaves no listed record.
    "foreign-detach": ("FreshIsEmpty", ("pure val FOREIGN_DETACH = false", "pure val FOREIGN_DETACH = true")),
    "cross-host-preempt": ("NoPreemptOfForeignKey", ("val admitted = h == rec.owner", "val admitted = true"),
                           ("val ownKey = k == attachKey(h)", "val ownKey = k == attachKey(rec.owner)")),
    "foreign-key-preempt": ("NoPreemptOfForeignKey", ("val ownKey = k == attachKey(h)", "val ownKey = true")),
    "withdraw-fixed-list": ("DetectedLossWithdraws", ("val withdraws = LOSSES.contains(c)",
                                                      'val withdraws = Set("flipped", "newerFence").contains(c)')),
    "command-after-withdraw": ("DetectedLossWithdraws",
                               ('q.phase == "active", tick("command", p)',
                                '(q.phase == "active" or q.phase == "withdrawn"), tick("command", p)')),
    "poll-keeps-attempt": ("DetectedLossWithdraws",
                           ("procs' = if (inside) procs else procs.keys().mapBy(", "procs' = if (true) procs else procs.keys().mapBy(")),
    # A device step of the restart admits the ended process, which read no records in this incarnation.
    "restart-skips-records": ("RecordsBeforeDevice",
                              ("val admitted = q.phase == from", 'val admitted = q.phase == from or q.phase == "ended"')),
    "restart-ignores-fresh": ("RecordsBeforeDevice",
                              ("nextId <= REQUESTS, rec.owner == h, rec.e > 0, rec.e < EMAX",
                               "nextId <= REQUESTS, rec.owner == h, rec.e < EMAX")),
    "restart-bump-rereads": ("BumpAtOwnGeneration",
                             ('val request = { id: p, kind: "bump", g: q.g, active: q.vol, owner: q.host, e: q.n,',
                              'val request = { id: p, kind: "bump", g: rec.g, active: rec.active, owner: rec.owner, e: rec.e,')),
    # The restart serves after the preempt without Report #2.
    "restart-drops-report-2": ("NoPredecessorEffectAfterFB", (CONFIRMED, "val confirmed = true")),
    # The ready wait returns while a write of the ended incarnation is card-held.
    "restart-ready-ignores-held": ("NoPredecessorEffectAfterFB", ("held == 0 or (skipsDrainAfterHold", "true or (skipsDrainAfterHold")),
    "restart-reread-after-timeout": ("NoEpochReuse", ("val reread = false", "val reread = q.restart")),
    # Allowing the fresh path to report in the "sent" phase violates OwnBumpBeforeFB.
    "fresh-report-before-bump": ("OwnBumpBeforeFB",
                                  ('deviceStep(p, "active", "active", "", true),',
                                   'deviceStep(p, "sent", "active", "", true),')),
    # The fresh path writes the medium while its bump is outstanding, before the `E` bump's acknowledgment.
    "fresh-writes-before-bump": ("NoWriteBeforeFB",
                                 ('val fenced = q.phase == "active" and fb.keys().contains(p)',
                                  'val fenced = q.phase == "sent" or (q.phase == "active" and fb.keys().contains(p))')),
    # A successor that re-reads the record after its timed-out CAS and adopts the consumed attempt.
    "takeover-reread-after-timeout": ("NoEpochReuse", ("val reread = false", "val reread = q.takeover")),
    # The preempt admitted while the CAS reply is outstanding, so Report #2 mints FB without the activation.
    "takeover-report-before-cas": ("OwnBumpBeforeFB",
                                   ('deviceStep(p, "reported", if (registered)', 'deviceStep(p, "sent", if (registered)')),
    # Report #1 issued while the CAS reply is outstanding: a device command before the acknowledged CAS.
    "takeover-device-before-cas": ("TakeoverCasBeforeDevice",
                                   ('q.phase == "bumped", advance("takeoverReport1", p)',
                                    '(q.phase == "bumped" or q.phase == "sent"), advance("takeoverReport1", p)')),
    # A host the record does not name as standby submits the CAS, and the CAS ignores the standby.
    "takeover-unnamed-standby": ("NamedStandbyTakesOver", (NAMED, "val named = true"),
                                 ("bumpHolds(r, s) and s.standby == r.to", "bumpHolds(r, s)")),
    # Report #1 admits a holder outside the recorded hosts, so the preempt names a key no takeover succeeded.
    "takeover-preempts-unrecorded-holder": ("NoPreemptOfForeignKey",
                                            (TAKEOVER_HOLDER, "val recordedHolder = holding and holder != q.key")),
    # The takeover admission admits a host the record does not name: it submits the CAS, which ignores the standby,
    # and reaches Report #1 on a record read that failed its checks.
    "takeover-unnamed-reaches-device": ("RecordsBeforeDevice",
                                        ("pending' = if (named) pending.union(Set(request)) else pending",
                                         "pending' = pending.union(Set(request))"),
                                        ('phase: if (named) "sent" else "refused"', 'phase: "sent"'),
                                        ("bumpHolds(r, s) and s.standby == r.to", "bumpHolds(r, s)")),
    # A takeover CAS that moves the shard to a new generation and volume, as the flip does.
    "takeover-flips": ("InterruptedTakeoverRetainsVolume",
                       ('else if (r.kind == "takeover") { ...s, owner: r.to, e: r.e + 1, standby: "" }',
                        'else if (r.kind == "takeover") { g: r.g + 1, active: "v3", owner: r.to, e: 0, spare: "", spareHost: "", standby: "" }')),
    # A successor's start that retires the volume when an earlier successor stopped after its CAS.
    "interrupted-takeover-retires": ("InterruptedTakeoverRetainsVolume",
                                     ("val interruptedRetires = false", "val interruptedRetires = true")),
    # An issuance rule that admits the owner's preempt of any key.
    "takeover-preempt-any-key": ("NoPreemptOfForeignKey",
                                 ("admitted and (ownKey or succeeded(h, k) or endedForm(h, k) or bumpedForm(h, k)) and rec.e > 0",
                                  "admitted and rec.e > 0")),
    # A restart whose Report #1 shows a recorded pair of another host holding requests the flip in place of the
    # lineage arm.
    "restart-retires-recorded-holder": ("InterruptedTakeoverRetainsVolume", RECORDED_HOLDER_RETIRES),
    # The same relabel judged by what Report #1 showed: the retirement follows a recorded holder.
    "restart-retires-recorded-holder-observation": ("RestartRetiresOnlyOnObservation", RECORDED_HOLDER_RETIRES),
    # A restart whose Report #1 shows nobody holding requests the flip, as an unrecorded holder's does: a takeover
    # before the owner's fresh Report commits, an abstract schedule since Rust enrolls a standby only after that
    # Report fenced page 0, and its successor's restart retires the retained volume.
    "restart-retires-unheld": ("InterruptedTakeoverRetainsVolume",
        ('else if (not(holding)) "refusedUnheld"', 'else if (not(holding)) "refusedForeign"')),
    # The same relabel judged by what Report #1 showed: the retirement follows a Report with nobody holding.
    "restart-retires-unheld-observation": ("RestartRetiresOnlyOnObservation",
        ('else if (not(holding)) "refusedUnheld"', 'else if (not(holding)) "refusedForeign"')),
    # A restart refusal on a failed device step requests the flip, as an unrecorded holder's Report does: the
    # restart retires the volume after host-local faults, so each retention invariant breaks under the takeover
    # schedules.
    "restart-retires-device-failure": ("InterruptedTakeoverRetainsVolume", DEVICE_FAILURE_RETIRES,
                                       DEVICE_FAILURE_TARGET),
    "restart-retires-device-failure-observation": ("RestartRetiresOnlyOnObservation", DEVICE_FAILURE_RETIRES,
                                                   DEVICE_FAILURE_TARGET),
    "restart-retires-device-failure-retains": ("DeviceFailureRetainsVolume", DEVICE_FAILURE_RETIRES,
                                               DEVICE_FAILURE_TARGET),
    # A failed device step proceeds to FB, so a restart that never bumped serves.
    "restart-device-failure-serves": ("OwnBumpBeforeFB", ("val deviceFailureServes = false", "val deviceFailureServes = true")),
    # A rerun after a post-bump hold resumes at the held attempt's E without its own bump.
    "restart-rerun-reuses-bump": ("NoEpochReuse", ("val adoptsHeldBump = false", "val adoptsHeldBump = true")),
    # The lineage arm registers and preempts on the record read and Report #1 alone, before its own bump.
    "target-activates-on-read": ("OwnBumpBeforePreempt", ('val bumped = q.phase == "bumped"',
                                                          'val bumped = Set("bumped", "reportedHolder").contains(q.phase)')),
}


RESTART_ONLY = ("RecordsBeforeDevice", "BumpAtOwnGeneration", "NoPredecessorEffectAfterFB", "NoWriteBeforeFB", "OwnBumpBeforeFB")
RESTART_ALSO = ("NoEpochReuse",)
RESTART_STEP = {"step": "restartStep", "settings": {"BOUND": "15"}}
RESTART_CASES = ("witnessRestartDevice", "witnessFreshWrite", "witnessRerunAfterDeviceRefusal", "fresh-writes-before-bump",
                 "fresh-report-before-bump") + tuple(name for name in MUTANTS if name.startswith("restart-"))
TAKEOVER_STEP = {"step": "takeoverStep", "settings": {"BOUND": "12"}}
TAKEOVER_CASES = ("witnessTakeoverFb", "witnessTakeoverChain", "witnessSupersededPreempt", "witnessLandAfterTakeoverFb", "witnessStatusRetires",
                  "witnessUnnamedRefused", "witnessStaleStandbyRefused", "witnessUnknownThenRestart",
                  "witnessRerunAfterForeignRefusal",
                  "witnessRerunAfterUnheldRefusal", "interrupted-takeover-retires", "restart-retires-recorded-holder",
                  "restart-retires-unheld", "restart-retires-recorded-holder-observation",
                  "restart-retires-unheld-observation", "restart-retires-device-failure",
                  "restart-retires-device-failure-observation", "restart-retires-device-failure-retains",
                  "target-activates-on-read") + tuple(
    name for name in MUTANTS if name.startswith("takeover-"))


def schedule(name):
    """The scheduler a case runs under: the takeover schedules, the restart schedules or the free scheduler."""
    if name in TAKEOVER_CASES:
        return TAKEOVER_STEP
    if name in RESTART_CASES:
        return RESTART_STEP
    return {}


def fresh_foreign_attach(stale):
    """The flip to the spare, a foreign attach and write of it, the fresh path's refusal, and a flip to a new spare
    that the next owner activates."""
    return ["requestFlip", "decideAny", f'foreignAttach("v2", {str(stale).lower()})', 'foreignWrite("v2")',
            'freshRefuse("h2")', 'spare("v3", "h3")', "requestFlip", "decideAny", 'start("h3")', "decideAny",
            "reply(3)"]


def mid_tenure(event, unregisters=False):
    """The owner activates, a mid-tenure controller event ends its incarnation with one write card-held, and a
    reset also with one outstanding, and the restart sequence reruns from the record read: the held write lands
    before ready, the self Preempt-and-Abort aborts the outstanding write, and Report #2 reaches the next FB. With
    `unregisters` the self Preempt-and-Abort unregisters its caller and the outstanding write lands after Report #2
    refused."""
    tail = ["restartPreempt(2, true)", "restartReport2(2)", "landQueued"] if unregisters else [
        "restartPreempt(2, false)", "restartReport2(2)"]
    return ['start("h1")', "decideAny", "reply(1)", "freshReport(1)", f'midTenure(1, "{event}", true)', 'restartRecords("h1")', "land",
            "restartReady(2)", "restartReport1(2)", "restartBump(2)", "decideAny", "reply(2)"] + tail


RESTART_FB = "fb.keys().contains(2)"
# The owner activates and a mid-tenure Abort ends its incarnation with one write card-held; the restart's ready wait
# fails while the write is held, the write lands, and the rerun reaches FB through its own bump at E = 1.
DEVICE_FAIL_RERUN = ['start("h1")', "decideAny", "reply(1)", "freshReport(1)", 'midTenure(1, "abort", true)',
                     'restartRecords("h1")', "restartDeviceFail(2)", "land", 'restartRecords("h1")', "restartReady(3)",
                     "restartReport1(3)", "restartBump(3)", "decideAny", "reply(3)", "restartPreempt(3, false)",
                     "restartReport2(3)"]
RETIRED_V2 = 'retired.contains("v2")'
FRESH_H1 = ['start("h1")', "decideAny", "reply(1)", "freshReport(1)"]
# A activates, B's takeover CAS commits, and C, designated over B's tenure, commits its CAS and takes Report #1.
CHAIN = ['nameStandby("h3")', 'takeoverStart("h3")', "decideAny", "reply(3)", "takeoverReport1(3)"]
INTERRUPTED = FRESH_H1 + ['takeoverStart("h2")', "decideAny", "reply(2)", "takeoverCrash(2)"] + CHAIN
# Three hops under EMAX 4: B's and C's CASes commit and each stops before its preempt while A holds; h2, designated
# again over C's tenure, commits and preempts A, the owner B's committed takeover deposed two takeovers back.
THREE_HOP = INTERRUPTED[:-1] + ["takeoverCrash(3)", 'nameStandby("h2")', 'takeoverStart("h2")', "decideAny", "reply(4)",
                               "takeoverReport1(4)"]
# B stays alive in place of the crash: C preempts A and reaches FB, then B takes its Report #1 and its preempt step.
PAUSED_SUCCESSOR = FRESH_H1 + ['takeoverStart("h2")', "decideAny", "reply(2)"] + CHAIN + [
    "takeoverPreempt(3)", "restartReport2(3)", "takeoverReport1(2)"]
# B's CAS commits and B captures A's key, then pauses; A, named standby over B's tenure, takes the record back,
# refuses at Report #1 because its own pair holds, and serves again through its restart under the same key; B's stale
# preempt then deposes A's later tenure.
REUSED_KEY = FRESH_H1 + ['takeoverStart("h2")', "decideAny", "reply(2)", "takeoverReport1(2)",
                         'nameStandby("h1")', 'takeoverStart("h1")', "decideAny", "reply(3)", "takeoverReport1(3)",
                         'observe(1, "laterTenure")', 'restartRecords("h1")', "restartReady(4)", "restartReport1(4)",
                         "restartBump(4)", "decideAny", "reply(4)", "restartPreempt(4, false)", "restartReport2(4)",
                         "takeoverPreempt(2)", "restartReport2(2)", "statusDeposition(false)", "reportPoll"]
# The reused-key schedule's two hold controls: the Report retires on a recorded foreign holder, at its last step,
# and the deposing status requests the retirement itself, at the step before it.
EMAX_FOUR = ("pure val EMAX = 3", "pure val EMAX = 4")
# The model text each run replaces before its check.
RUN_MUTATIONS = {"reusedAttachmentKey": [EMAX_FOUR], "threeHopFreshHostRecovers": [EMAX_FOUR],
                 "recordedRefusalRerun": [EMAX_FOUR], "armRerunReachesFb": [EMAX_FOUR], "armRereadRefusesMovedRecord": [EMAX_FOUR],
                 "armRegisterFailRerunReachesFb": [EMAX_FOUR],
                 "reusedAttachmentKeyRestartReachesFb": [("pure val EMAX = 3", "pure val EMAX = 5"),
                                                         ("pure val REQUESTS = 4", "pure val REQUESTS = 5")],
                 "armPausedPreemptRefusesAtReport2": [("pure val EMAX = 3", "pure val EMAX = 5"),
                                                      ("pure val REQUESTS = 4", "pure val REQUESTS = 5")]}
REUSED_KEY_CONTROLS = {
    "reusedAttachmentKey-poll-retires": (("retired' = if (keeps) retired else retired.union(Set(rec.active)),",
                                          "retired' = if (own and keeps) retired else retired.union(Set(rec.active)),"),
                                         len(REUSED_KEY) + 1),
    "reusedAttachmentKey-status-retires": (("val statusRetires = false", "val statusRetires = true"), len(REUSED_KEY)),
}


def arm(p):
    """Restart `p`'s lineage arm after its Report #1: the bump and its acknowledged reply, Register, the reread, the
    preempt, and Report #2."""
    return [f"restartBump({p})", "decideAny", f"reply({p})", f"restartRegister({p})", f"restartReread({p})",
            f"restartLineagePreempt({p})", f"restartReport2({p})"]


# h2's CAS commits with its reply lost, and h2's restart takes Report #1 with A holding.
UNKNOWN_RESTART = FRESH_H1 + ['takeoverStart("h2")', "decideAny", "timeout(2)", 'restartRecords("h2")', "restartReady(3)",
                              "restartReport1(3)"]
# B's CAS commits and B stops before its preempt; B's restart takes Report #1 with A holding.
CRASHED_RESTART = FRESH_H1 + ['takeoverStart("h2")', "decideAny", "reply(2)", "takeoverCrash(2)", 'restartRecords("h2")',
                              "restartReady(3)", "restartReport1(3)"]
# The arm's bump commits with its reply lost, and h2 restarts again through Report #1.
ARM_BUMP_UNKNOWN_RERUN = UNKNOWN_RESTART + ["restartBump(3)", "decideAny", "timeout(3)", 'restartRecords("h2")',
                                            "restartReady(4)", "restartReport1(4)"]
# The arm bumps and registers; h3, named over h2's bumped tenure, commits its takeover; the arm's reread follows.
ARM_MOVED = UNKNOWN_RESTART + ["restartBump(3)", "decideAny", "reply(3)", "restartRegister(3)", 'nameStandby("h3")',
                               'takeoverStart("h3")', "decideAny", "restartReread(3)"]
# The arm's reread names its bumped tenure; h3, named over that tenure, then commits its takeover and captures A's key
# at Report #1 while the arm's preempt is in flight. The arm's preempt lands, h3's preempt of A's key finds the arm's
# key holding, both Report #2s refuse, and h3's restart takes the arm over the paused restart's key to FB.
ARM_PAUSED = UNKNOWN_RESTART + ["restartBump(3)", "decideAny", "reply(3)", "restartRegister(3)", "restartReread(3)",
                                'nameStandby("h3")', 'takeoverStart("h3")', "decideAny", "reply(4)", "takeoverReport1(4)",
                                "restartLineagePreempt(3)", "takeoverPreempt(4)", "restartReport2(3)"]
# A's attempt is deposed by `UNRECORDED`'s preempt and withdraws; h2's takeover commits and its restart takes
# Report #1 with `UNRECORDED` holding, then the arm's bump, Register and preempt.
UNRECORDED_ARM = FRESH_H1 + ["statusDeposition(true)", 'takeoverStart("h2")', "decideAny", "timeout(2)",
                             'restartRecords("h2")', "restartReady(3)", "restartReport1(3)", "restartBump(3)", "decideAny",
                             "reply(3)", "restartRegister(3)", "restartReread(3)", "restartLineagePreempt(3)"]
# The lineage arm's search root: h2's takeover CAS commits with its reply lost and h2's restart takes Report #1 with h1
# holding. The takeover schedules then run `ARM_TURNS` turns at EMAX 5 and five requests, so the arm's bump, Register,
# reread, preempt and Report #2 meet a takeover over the bumped tenure, the arm's rerun, device failures, the serving
# Report, status depositions and the restart's retirement.
ARM_ROOT = UNKNOWN_RESTART
ARM_TURNS = 12
ARM_CONSTANTS = [("pure val EMAX = 3", "pure val EMAX = 5"), ("pure val REQUESTS = 4", "pure val REQUESTS = 5")]
# The witnesses the arm root's search reaches past its prefix.
ARM_WITNESSES = ("witnessArmFb", "witnessArmRereadRefused", "witnessArmReport2Refused",
                 "witnessRerunAfterRecordedRefusal")
# The reread admits a moved record.
SKIPS_REREAD = ("val passes = named", "val passes = true")
# The arm's Report #2 without its tenure check.
ARM_REPORT2_SKIPS_TENURE = (CONFIRMED, CONFIRMED.replace('(not(q.takeover) and q.prkey == "")', "not(q.takeover)"))
# Each mutant the arm root's search must reject past its prefix, with the property it breaks.
ARM_ROOT_MUTANTS = {
    "skips-reread": ("NoPreemptOfForeignKey", SKIPS_REREAD),
    "report2-skips-tenure-check": ("ArmFbConfirmed", ARM_REPORT2_SKIPS_TENURE),
}
RESTART_WON = ('fb.keys().contains(2) and not(fb.keys().contains(3)) and procs.get(3).phase == "refused" '
               'and rec.g == 1 and rec.active == "v1" and rec.owner == "h1" and rec.e == 2')
RACE_LOST = ('fb.keys().contains(3) and not(fb.keys().contains(2)) and procs.get(2).phase == "refused" '
             'and rec.g == 1 and rec.active == "v1" and rec.owner == "h2" and rec.e == 2')

# Each run, its recipe and the state its last turn must reach: v2 retired by the check the run names, the restart's
# FB, or the takeover state the entry states.
RUNS = {
    "midTenureReset": (mid_tenure("reset"), RESTART_FB),
    "midTenureAbort": (mid_tenure("abort"), RESTART_FB),
    "midTenureQueueDelete": (mid_tenure("queueDelete"), RESTART_FB),
    "freshForeignAttach": (fresh_foreign_attach(False), RETIRED_V2),
    "freshForeignAttachStale": (fresh_foreign_attach(True), RETIRED_V2),
    # A foreign attach and write of the idle spare, the standby's check retiring it, and a new spare that the
    # next owner activates after the flip.
    "SparePoll": (['foreignAttach("v2", false)', 'foreignWrite("v2")', "sparePoll", 'spare("v3", "h2")',
                   "requestFlip", "decideAny", 'start("h2")', "decideAny", "reply(2)"], RETIRED_V2),
    # A activates; B's takeover CAS commits and B stops before its preempt while A holds; C, designated over B's
    # tenure, commits its CAS, and its Report #1 admits A, whose tenure B's committed takeover deposed, so C preempts
    # A's key and reaches FB on v1 at its generation.
    "interruptedTakeoverFreshHostRecovers": (INTERRUPTED + ["takeoverPreempt(3)", "restartReport2(3)"],
                                             'fb.keys().contains(3) and holder == "h3" and preempts == Set(("h3", "h1", true)) '
                                             'and rec.owner == "h3" and rec.standby == "" and rec.g == 1 '
                                             'and rec.active == "v1" and not(retired.contains("v1"))'),
    # The third successor preempts A, three takeovers back, and reaches FB on v1.
    "threeHopFreshHostRecovers": (THREE_HOP + ["takeoverPreempt(4)", "restartReport2(4)"],
                                  'fb.keys().contains(4) and holder == "h2" and preempts == Set(("h2", "h1", true)) '
                                  'and rec.owner == "h2" and rec.e == 4 and rec.active == "v1" '
                                  'and not(retired.contains("v1"))'),
    # The same chain with B alive and paused after its CAS: once C holds, B's Report #1 shows C while the record names
    # C's tenure, so B refuses with no preempt and C keeps the reservation.
    "pausedSuccessorRefusesLaterHolder": (PAUSED_SUCCESSOR,
                                          'procs.get(2).phase == "refused" and holder == "h3" '
                                          'and preempts == Set(("h3", "h1", true)) and fb.keys().contains(3)'),
    # The standby designation moves to h3 between h2's record read and its CAS; the CAS fails its condition and h2
    # issues no device command.
    "staleStandbyDesignation": (FRESH_H1 + ['takeoverStart("h2")', 'nameStandby("h3")', "decideAny", "reply(2)"],
                                'procs.get(2).phase == "refused" and not(deviceActs.contains(2)) and rec.owner == "h1" '
                                'and rec.standby == "h3"'),
    # h3, attached and unnamed, refuses with no request; the named standby h2 takes over to FB.
    "twoAttachedOneNamed": (FRESH_H1 + ['takeoverStart("h3")', 'takeoverStart("h2")', "decideAny", "reply(3)",
                                        "takeoverReport1(3)", "takeoverPreempt(3)", "restartReport2(3)"],
                            'procs.get(2).phase == "refused" and not(deviceActs.contains(2)) and fb.keys().contains(3) '
                            'and rec.owner == "h2" and rec.standby == ""'),
    # h2's CAS commits with its reply lost; h2 issues no device command and proceeds only through its same-host
    # restart, whose Report #1 shows A, a recorded pair of another host, so it takes the lineage arm with A's key
    # captured and v1 retained.
    "takeoverUnknownThenRestart": (UNKNOWN_RESTART,
                                   'decided.get(2) and procs.get(2).phase == "refused" and not(deviceActs.contains(2)) '
                                   'and procs.get(3).phase == "reportedHolder" and procs.get(3).prkey == "h1" '
                                   'and not(retired.contains("v1"))'),
    # The same restart carries the arm to FB: its own bump, Register, the reread that still names its tenure, the
    # preempt of A's key and Report #2, on v1 at its generation (D20).
    "takeoverUnknownRestartReachesFb": (UNKNOWN_RESTART + arm(3),
                                        'fb.keys().contains(3) and holder == "h2" and preempts == Set(("h2", "h1", true)) '
                                        'and activations.contains((1, 2, 3)) and rec.owner == "h2" and rec.e == 3 '
                                        'and rec.g == 1 and rec.active == "v1" and not(retired.contains("v1"))'),
    # The arm's bump commits with its reply lost: the restart refuses with no Register and no preempt, and h2 restarts
    # again; the rerun reads the bumped record and its Report #1 takes the arm again with v1 retained.
    "recordedRefusalRerun": (ARM_BUMP_UNKNOWN_RERUN,
                             'procs.get(3).phase == "refused" and not(fencing.contains(3)) '
                             'and procs.get(4).phase == "reportedHolder" and deviceActs.contains(4) '
                             'and preempts == Set() and not(retired.contains("v1"))'),
    # The rerun carries the arm to FB at the next E under its own bump's session, never the refused one's.
    "armRerunReachesFb": (ARM_BUMP_UNKNOWN_RERUN + arm(4),
                          'fb.keys().contains(4) and not(fb.keys().contains(3)) and activations.contains((1, 3, 4)) '
                          'and not(activations.exists(a => a._3 == 3)) and holder == "h2" and rec.e == 4 '
                          'and not(retired.contains("v1"))'),
    # The record moves between the arm's bump and its preempt: h3, named over h2's bumped tenure, commits its
    # takeover, and the arm's reread refuses with no preempt, so A keeps the reservation.
    "armRereadRefusesMovedRecord": (ARM_MOVED,
                                    'procs.get(3).phase == "refused" and not(preempts.exists(x => x._1 == "h2")) '
                                    'and holder == "h1" and rec.owner == "h3" and not(retired.contains("v1"))'),
    # The arm's Register fails: a hold with no flip, and the rerun reaches FB through its own bump.
    "armRegisterFailRerunReachesFb": (UNKNOWN_RESTART + ["restartBump(3)", "decideAny", "reply(3)", "restartDeviceFail(3)",
                                                         'restartRecords("h2")', "restartReady(4)", "restartReport1(4)"]
                                      + arm(4),
                                      'procs.get(3).phase == "refusedDevice" and fencing.contains(3) '
                                      'and fb.keys().contains(4) and activations.contains((1, 3, 4)) and holder == "h2" '
                                      'and not(retired.contains("v1"))'),
    # The record moves after the arm's reread passed: the paused preempt lands under h3's tenure and takes the
    # reservation, and the arm's Report #2 refuses on the tenure check with no FB; h3, whose own preempt found the
    # arm's key holding, recovers through its restart's arm on v1 at E = 5.
    "armPausedPreemptRefusesAtReport2": (ARM_PAUSED + ["restartReport2(4)", 'restartRecords("h3")', "restartReady(5)",
                                                       "restartReport1(5)"] + arm(5),
                                         'procs.get(3).phase == "refused" and not(fb.keys().contains(3)) '
                                         'and preempts.contains(("h2", "h1", true)) and fb.keys().contains(5) '
                                         'and holder == "h3" and rec.owner == "h3" and rec.e == 5 '
                                         'and not(retired.contains("v1"))'),
    # B pauses after its CAS and Report #1 while A regains the record and serves again under the same attachment key.
    # B's stale preempt deposes A and B's Report #2 refuses; A's command completes with a deposing status, which
    # withdraws A, and A's Report then holds the retained volume with no retirement (RECORDED-HOLDER-HOLD).
    "reusedAttachmentKey": (REUSED_KEY,
                            'rec.owner == "h1" and holder == "h2" and procs.get(2).phase == "refused" and not(fb.keys().contains(2)) '
                            'and ev.act == "reportHold" and not(retired.contains("v1")) and procs.get(4).phase == "withdrawn"'),
    # A's mid-tenure event leaves a write of A's ended incarnation card-held; B takes over to FB and A's write lands
    # after B's FB, which drains no predecessor.
    "takeoverPredecessorLanding": (FRESH_H1 + ['midTenure(1, "abort", true)', 'takeoverStart("h2")', "decideAny",
                                               "reply(2)", "takeoverReport1(2)", "takeoverPreempt(2)",
                                               "restartReport2(2)", "land"],
                                   'procs.get(1).phase == "ended" and procs.get(2).phase == "active" '
                                   'and fb.keys().contains(2) and landed == Set(turn) and turn > fb.get(2) '
                                   'and rec.owner == "h2"'),
    # A's fresh tenure, B's takeover to FB, and a mid-tenure event of B's tenure whose card-held write lands: A's
    # process, still active, holds no tenure the record names once it names B, so the drain property excludes it.
    "takeoverSuccessorLanding": (['start("h1")', "decideAny", "reply(1)", "freshReport(1)", 'takeoverStart("h2")',
                                  "decideAny", "reply(2)", "takeoverReport1(2)", "takeoverPreempt(2)", "restartReport2(2)",
                                  'midTenure(2, "abort", true)', "land"],
                                 'fb.keys().contains(1) and fb.keys().contains(2) and procs.get(2).phase == "ended" '
                                 'and landed.size() == 1 and rec.owner == "h2"'),
    # B takes over between A's bump and A's fresh Report, so nobody holds: B's Report #1 refuses with no preempt, and
    # B's restart refuses `refusedUnheld` with v1 retained (NO-HOLDER-HOLD). The schedule is an abstract witness: Rust
    # enrolls a standby only after the owner's fresh Report fenced page 0.
    "unheldTakeoverRestartHolds": (['start("h1")', "decideAny", "reply(1)", 'takeoverStart("h2")', "decideAny",
                                    "reply(2)", "takeoverReport1(2)", 'restartRecords("h2")', "restartReady(3)",
                                    "restartReport1(3)"],
                                   'procs.get(2).phase == "refused" and procs.get(3).phase == "refusedUnheld" '
                                   'and preempts == Set() and rec.owner == "h2" and not(holding) '
                                   'and not(retired.contains("v1"))'),
    # B's takeover CAS commits and B stops before its preempt; B's restart reads the record naming B, and its
    # Report #1 shows A, a recorded pair of another host, so it takes the lineage arm with v1 retained.
    "takeoverThenOwnRestart": (CRASHED_RESTART,
                              'procs.get(3).phase == "reportedHolder" and not(retired.contains("v1"))'),
    # The same restart carries the arm to FB: a successor that dies after its takeover write and before its preempt
    # recovers the shard through its own restart.
    "takeoverCrashRestartReachesFb": (CRASHED_RESTART + arm(3),
                                      'fb.keys().contains(3) and holder == "h2" and preempts == Set(("h2", "h1", true)) '
                                      'and rec.owner == "h2" and rec.e == 3 and not(retired.contains("v1"))'),
    # The deposed tenure of reusedAttachmentKey, withdrawn by its Report's hold while the record names it
    # owner, reaches its FB again through its own restart: the arm bumps, preempts B's key and takes Report #2.
    "reusedAttachmentKeyRestartReachesFb": (REUSED_KEY + ['restartRecords("h1")', "restartReady(5)", "restartReport1(5)"]
                                            + arm(5),
                                            'fb.keys().contains(5) and holder == "h1" and rec.owner == "h1" and rec.e == 5 '
                                            'and preempts.contains(("h1", "h2", true)) and procs.get(4).phase == "withdrawn" '
                                            'and not(retired.contains("v1"))'),
    # DEVICE-FAILURE-HOLD: h2's takeover CAS commits with its reply lost and h2's same-host restart fails its ready
    # wait: the restart refuses `refusedDevice` with v1 retained and A still holding.
    "unknownTakeoverRestartDeviceFailHolds": (FRESH_H1 + ['takeoverStart("h2")', "decideAny", "timeout(2)",
                                                          'restartRecords("h2")', "restartDeviceFail(3)"],
                                              'decided.get(2) and procs.get(3).phase == "refusedDevice" '
                                              'and deviceActs.contains(3) and holder == "h1" '
                                              'and not(retired.contains("v1"))'),
    # B's CAS commits and B stops before its preempt; B's restart reads the record naming B and its Report #1
    # fails: the restart refuses `refusedDevice` with no preempt and v1 retained.
    "interruptedTakeoverReport1FailHolds": (FRESH_H1 + ['takeoverStart("h2")', "decideAny", "reply(2)",
                                                        "takeoverCrash(2)", 'restartRecords("h2")', "restartReady(3)",
                                                        "restartDeviceFail(3)"],
                                            'procs.get(3).phase == "refusedDevice" and preempts == Set() '
                                            'and rec.owner == "h2" and not(retired.contains("v1"))'),
    # The unheld takeover schedule, then B's rerun fails its ready wait: the hold stays a hold with v1 retained.
    "unheldThenDeviceFailHolds": (['start("h1")', "decideAny", "reply(1)", 'takeoverStart("h2")', "decideAny",
                                   "reply(2)", "takeoverReport1(2)", 'restartRecords("h2")', "restartReady(3)",
                                   "restartReport1(3)", 'restartRecords("h2")', "restartDeviceFail(4)"],
                                  'procs.get(3).phase == "refusedUnheld" and procs.get(4).phase == "refusedDevice" '
                                  'and preempts == Set() and not(retired.contains("v1"))'),
    # A failed ready wait before the bump consumes no E: the rerun reaches FB at E = 1 with the volume retained.
    "deviceFailThenRerunReachesFb": (DEVICE_FAIL_RERUN,
                                     'procs.get(2).phase == "refusedDevice" and fb.keys().contains(3) '
                                     'and activations.contains((1, 1, 3)) and rec.e == 2 and not(retired.contains("v1"))'),
    # A self preempt that fails after the bump holds with E = 2 consumed; the rerun bumps to E = 3 and reaches FB
    # under its own session, never the held attempt's.
    "postBumpFailThenRerunReachesFb": (['start("h1")', "decideAny", "reply(1)", "freshReport(1)",
                                        'midTenure(1, "abort", true)', 'restartRecords("h1")', "land",
                                        "restartReady(2)", "restartReport1(2)", "restartBump(2)", "decideAny",
                                        "reply(2)", "restartDeviceFail(2)", 'restartRecords("h1")', "restartReady(3)",
                                        "restartReport1(3)", "restartBump(3)", "decideAny", "reply(3)",
                                        "restartPreempt(3, false)", "restartReport2(3)"],
                                       'procs.get(2).phase == "refusedDevice" and not(fb.keys().contains(2)) '
                                       'and fb.keys().contains(3) and activations.contains((1, 1, 2)) '
                                       'and activations.contains((1, 2, 3)) and rec.e == 3 and not(retired.contains("v1"))'),
    # The owner's restart fails its ready wait and the named standby's takeover then reaches FB on the retained
    # volume at its generation: the takeover ends the hold.
    "deviceRefusalThenTakeover": (FRESH_H1 + ['midTenure(1, "abort", true)', 'restartRecords("h1")',
                                              "restartDeviceFail(2)", 'takeoverStart("h2")', "decideAny", "reply(3)",
                                              "takeoverReport1(3)", "takeoverPreempt(3)", "restartReport2(3)"],
                                  'procs.get(2).phase == "refusedDevice" and fb.keys().contains(3) '
                                  'and rec.owner == "h2" and rec.g == 1 and rec.active == "v1" '
                                  'and not(retired.contains("v1"))'),
    # A's restart and B's takeover condition on one record: the takeover commits first, the restart's bump fails its
    # condition and refuses, and B reaches FB.
    "restartTakeoverRace": (['start("h1")', "decideAny", "reply(1)", "freshReport(1)", 'midTenure(1, "abort", true)',
                             'restartRecords("h1")', "land", "restartReady(2)", "restartReport1(2)",
                             'takeoverStart("h2")', "restartBump(2)", "decideOf(3)", "decideOf(2)", "reply(2)",
                             "reply(3)", "takeoverReport1(3)", "takeoverPreempt(3)", "restartReport2(3)"], RACE_LOST),
    # The same race with the restart's bump committing first: B's takeover CAS fails its condition on E and refuses,
    # and A's restart reaches FB.
    "takeoverLosesToRestart": (['start("h1")', "decideAny", "reply(1)", "freshReport(1)", 'midTenure(1, "abort", true)',
                                'restartRecords("h1")', "land", "restartReady(2)", "restartReport1(2)",
                                'takeoverStart("h2")', "restartBump(2)", "decideOf(2)", "decideOf(3)", "reply(2)",
                                "reply(3)", "restartPreempt(2, false)", "restartReport2(2)"], RESTART_WON),
}
# A takeover CAS conditioned on (g, active, owner) and the standby without E, which commits over the restart's bump.
TAKEOVER_IGNORES_E = ("bumpHolds(r, s) and s.standby == r.to",
                      "r.g == s.g and r.active == s.active and r.owner == s.owner and s.standby == r.to")


# The reclaim schedule runs from `reclaimInit`, whose `v1` listing shows the three attaches of `RC0`; its cases
# raise the host set, attempts, requests and retained entries by replacing the model's constants.
HOSTS_LINE = 'pure val HOSTS = Set("h1", "h2", "h3")'


def hosts(n):
    """The host set of `n` hosts."""
    return (HOSTS_LINE, "pure val HOSTS = Set(" + ", ".join(f'"h{i}"' for i in range(1, n + 1)) + ")")


def constant(name, old, new):
    return (f"pure val {name} = {old}", f"pure val {name} = {new}")


RECLAIM_INIT = "  action caseInit = reclaimInit\n"
# `safety` holds every tenure invariant, the device-order ones included; the reclaim properties join it.
RECLAIM_INVARIANTS = ("safety", "EndedAttachNeverRetires", "EndedGrantsNothing", "EndedPreemptSparesLiveAttach",
                      "EndOrder", "EndedHoldsNoRole", "HistoryBound", "AttachAfterGone", "EndedOwnerServesNothing")


def r_takeover(h, p):
    """Host `h`'s takeover as process `p`: its start, the CAS and its reply, Register with Report #1, the preempt
    and Report #2."""
    return [f'takeoverStart("{h}")', "decideAny", f"reply({p})", f"takeoverReport1({p})", f"takeoverPreempt({p})",
            f"restartReport2({p})"]


def r_cas(h, p):
    """Host `h`'s takeover CAS as process `p`, acknowledged."""
    return [f'takeoverStart("{h}")', "decideAny", f"reply({p})"]


def r_end(i):
    """The end decision and the end write of entry `i`."""
    return [f"endRead({i})", f"endWrite({i})"]


def r_attach(h, i):
    """Host `h`'s attach as entry `i`: the entry, the request that lands, and the enrollment."""
    return [f'recordAttach("{h}")', f"attachRequest({i}, true)", f"enroll({i})"]


def r_reclaim(i):
    """The owner's Report showing entry `i`'s key absent, the pair drop, the detach and the gone mark."""
    return ["reportPoll", f"dropPair({i})", f"detachRequest({i})", f"detachDone({i})", f"markGone({i})"]


FOUR = [hosts(4)]
# h2's CAS commits, h3 is named over h2's tenure and takes over to FB.
RECLAIM_ROOTS_PAUSED = r_cas("h2", 2) + ['nameStandby("h3")'] + r_takeover("h3", 3)
# A paused successor h2 commits its CAS; h3, designated over h2's tenure, takes over to FB, and h2's entry ends.
PAUSED_ENDED = r_cas("h2", 2) + ['nameStandby("h3")'] + r_takeover("h3", 3) + r_end(2)
# The lateRegisterAfterDrop schedule through its second Report, the one that judges the late registrant.
LATE_REGISTER = PAUSED_ENDED + ["reportPoll", "dropPair(2)", "takeoverReport1(2)", "reportPoll"]
# h2 registers at its Report #1 and pauses; h3 takes over to FB and h2's entry ends with its pair recorded.
REGISTERED_ENDED = r_cas("h2", 2) + ["takeoverReport1(2)", 'nameStandby("h3")'] + r_takeover("h3", 3) + r_end(2)
# The paused owner h3 decides a second ended-key preempt of h2's first attach, h2's entry is reclaimed, and h2
# attaches again under a new entry and key, is named and takes over to FB.
REATTACHED = (PAUSED_ENDED + ["takeoverReport1(2)", "reportPoll", 'endedPreempt("h2")', "endedPreemptLands(true)",
                              'endedPreempt("h2")'] + r_reclaim(2) + r_attach("h2", 4) + ['nameStandby("h2")']
              + r_takeover("h2", 4))
# h2's CAS commits and h2 stops before its preempt while h1 holds; h1's entry ends with its pair recorded.
ENDED_PREDECESSOR = r_cas("h2", 2) + ["takeoverCrash(2)"] + r_end(1)
# h3's end is decided, h3 is named standby, and the end is written: the record names an ended host.
RACED = ["endRead(3)", 'nameStandby("h3")', "endWrite(3)"]
# h2's takeover CAS is pending while its entry ends and is reclaimed and h2 attaches again under k4; then the CAS
# commits and h2's first attach takes Report #1.
STALE_CAS = (['nameStandby("h3")', "endRead(2)", 'nameStandby("h2")', 'takeoverStart("h2")', "endWrite(2)"]
             + r_reclaim(2) + ['recordAttach("h2")', "attachRequest(4, true)", "decideAny", "reply(2)",
                               "takeoverReport1(2)"])
FAILED_LATE = (r_end(3) + ['recordAttach("h4")', "attachRequest(4, false)"] + r_end(4)
               + ["lateLand(4)", "readListing", "pollEntries", "enroll(4)"])
STALE_CAS_RECOVERY = STALE_CAS + ['nameStandby("h3")'] + r_takeover("h3", 3)
REATTACHED_UNENROLLED = RACED + ["reportPoll"] + r_reclaim(3)[1:] + ['recordAttach("h3")', "attachRequest(4, true)",
                                                                      'takeoverStart("h3")']
UNREGISTERED_PREEMPT = (r_cas("h2", 2) + ["takeoverReport1(2)", 'nameStandby("h3")'] + r_takeover("h3", 3) + r_end(2)
                        + ["reportPoll", 'endedPreempt("h2")', "endedPreemptLands(true)", "takeoverPreempt(2)"])
# h2's end is decided while h3 is named; h2, named again, commits its takeover with the reply lost and its restart
# takes the arm through its Register; the end is then written, and the arm's reread follows.
ENDED_ARM = ['nameStandby("h3")', "endRead(2)", 'nameStandby("h2")', 'takeoverStart("h2")', "decideAny", "timeout(2)",
             'restartRecords("h2")', "restartReady(3)", "restartReport1(3)", "restartBump(3)", "decideAny", "reply(3)",
             "restartRegister(3)", "endWrite(2)", "restartReread(3)"]
# h2 takes over to FB; h3, named over h2's tenure, commits its takeover, captures h2's key at Report #1 and pauses; h1
# takes the record back and preempts h2's key; h2, named again, commits a takeover with its reply lost, and its restart
# takes the arm over h1's pair through its reread; h3's paused preempt then removes h2's registration, and the arm's
# preempt follows.
UNREGISTERED_ARM = (r_takeover("h2", 2) + ['nameStandby("h3")'] + r_cas("h3", 3)
                    + ["takeoverReport1(3)", 'nameStandby("h1")'] + r_cas("h1", 4)
                    + ["takeoverReport1(4)", "takeoverPreempt(4)", 'nameStandby("h2")', 'takeoverStart("h2")',
                       "decideAny", "timeout(5)", 'observe(2, "laterTenure")', 'restartRecords("h2")',
                       "restartReady(6)", "restartReport1(6)", "restartBump(6)", "decideAny", "reply(6)",
                       "restartRegister(6)", "restartReread(6)", "takeoverPreempt(3)", "restartLineagePreempt(6)"])
# h2's arm reads h1 as holder at Report #1 and at its reread. Its preempt of h1's key lands after h3's takeover
# and after h1's pair was dropped.
PAIR_DROPPED_ARM = (['takeoverStart("h2")', "decideAny", "timeout(2)", 'restartRecords("h2")', "restartReady(3)",
                     "restartReport1(3)", "restartBump(3)", "decideAny", "reply(3)", "restartRegister(3)",
                     "restartReread(3)", 'nameStandby("h3")'] + r_takeover("h3", 4) + r_end(1)
                    + ["reportPoll", "dropPair(1)", "restartLineagePreempt(3)", "restartReport2(3)"])
UNREGISTERED_ARM_END = ('procs.get(6).phase == "refused" and fencing.contains(6) and holder == "h1" '
                        'and not(rc.regs.contains("h2")) and preempts.contains(("h3", "h2", true)) '
                        'and not(retired.contains("v1"))')
UNREGISTERED_END = ('procs.get(2).phase == "refused" and not(preempts.exists(x => x._1 == "h2")) and holder == "h3" '
                    'and not(retired.contains("v1"))')
MISSING_OWNER = (['nameStandby("h3")', "endRead(2)", 'nameStandby("h2")', 'takeoverStart("h2")', "endWrite(2)"]
                 + r_reclaim(2)[:4] + ["decideAny", "reply(2)", "readListing", "pollEntries"])
# h3's end is decided before its designation; h3 takes over through its preempt, and the end lands before Report #2.
ENDED_BEFORE_REPORT_2 = (["endRead(3)", 'nameStandby("h3")'] + r_cas("h3", 2)
                         + ["takeoverReport1(2)", "takeoverPreempt(2)", "endWrite(3)", "restartReport2(2)"])
# h3's end is decided before its designation and written after its takeover reached FB; the owner's poll then reads
# h3's own entry ended.
OWNER_ENDED = ["endRead(3)", 'nameStandby("h3")'] + r_takeover("h3", 2) + ["endWrite(3)", "readListing", "pollEntries"]
# A foreign attach of the active volume, then the owner's poll: the listing read and the record read.
FOREIGN_POLL = ['foreignAttach("v1", false)', "readListing", "pollEntries"]
# The reused-key schedule from `reclaimInit` through h2's refused Report #2: h1 serves past the FB of its restart
# while h2's stale preempt left h2's pair holding.
DEPOSED_SERVING = REUSED_KEY[len(FRESH_H1):REUSED_KEY.index("restartReport2(2)") + 1]
# h1 reads the listing, h2 takes over and h1 takes the record back at a higher E; the last step offers both arms of
# the poll's record read, the verdict and the superseded end, and only the second is enabled.
SUPERSEDED_POLL = (["readListing"] + r_cas("h2", 2) + ['nameStandby("h1")'] + r_cas("h1", 3)
                   + ["any { pollEntries, pollSuperseded }"])
# h3's entry ends, its pair drops, it is detached and marked gone.
RECLAIMED_3 = r_end(3) + r_reclaim(3)
# The listing-first poll's race: h3's entry ends, the owner reads the listing, and h4's entry is recorded and its attach
# lands before the poll's record read.
RACING_POLL = r_end(3) + ["readListing", 'recordAttach("h4")', "attachRequest(4, true)", "pollEntries"]


def processes(n):
    """The constants a schedule of `n` processes needs: `EMAX` and `REQUESTS` at `n`."""
    return [constant("EMAX", 3, n), constant("REQUESTS", 4, n)]


# After owner h1 drops the pair of h2's ended entry, process 4 registers h2's key again. That registration lets
# process 2 preempt h1's key under its earlier Report #1, so h2's ended key holds the reservation.
DROPPED_KEY_HOLDER = (r_cas("h2", 2) + ["takeoverReport1(2)", 'nameStandby("h3")'] + r_takeover("h3", 3)
                      + ['nameStandby("h2")'] + r_cas("h2", 4) + ['nameStandby("h1")'] + r_takeover("h1", 5) + r_end(2)
                      + ['endedPreempt("h2")', "endedPreemptLands(true)", "reportPoll", "dropPair(2)",
                         "takeoverReport1(4)", "takeoverPreempt(2)"])
# The Report withdraws process 5 and process 1 observes the later tenure, so every earlier process of h1 has ended
# when h1 reads the records on restart.
DROPPED_KEY_RESTART = DROPPED_KEY_HOLDER + ["reportPoll", 'observe(1, "laterTenure")', 'restartRecords("h1")',
                                            "restartReady(6)", "restartReport1(6)"]
# Owner h1 decides to preempt h2's ended key. Process 2 preempts h1's key, removes h1's registration, and leaves
# h2's key as the holder. Process 3, a superseded h1 takeover, registers h1's key again before the device applies
# h1's earlier preempt to h2's key.
ENDED_PREEMPT_MOVES = (r_cas("h2", 2) + ["takeoverReport1(2)", 'nameStandby("h1")'] + r_cas("h1", 3)
                       + ['nameStandby("h3")'] + r_takeover("h3", 4) + ['nameStandby("h1")'] + r_takeover("h1", 5)
                       + r_end(2) + ['endedPreempt("h2")', "takeoverPreempt(2)", "takeoverReport1(3)",
                                     "endedPreemptLands(true)"])


def chain(depth):
    """A takeover chain over ended predecessors: h1 serves past its FB, each of `depth - 1` successors commits its
    CAS and stops before its preempt, each deposed host's entry ends with its pair recorded, and a new host's entry is
    recorded, enrolled and named for each next successor; the last successor's Register and Report #1 admit h1's
    key, which it preempts before Report #2."""
    recipe = r_cas("h2", 2) + ["takeoverCrash(2)"] + r_end(1)
    for k in range(3, depth + 1):
        recipe += r_attach(f"h{k}", k) if k > 3 else []  # h3's entry 3 is in `RC0`
        recipe += [f'nameStandby("h{k}")'] + r_cas(f"h{k}", k) + [f"takeoverCrash({k})"] + r_end(k - 1)
    last = depth + 1
    recipe += r_attach(f"h{last}", last) + [f'nameStandby("h{last}")'] + r_takeover(f"h{last}", last)
    return recipe


def chain_settings(depth):
    """The constants a chain of `depth` hops needs: one host per hop beyond h1, one attempt and request per hop
    beyond the fresh one, and every entry retained."""
    return [hosts(depth + 1), constant("EMAX", 3, depth + 2), constant("REQUESTS", 4, depth + 2),
            constant("MAX_EVENTS", 4, depth + 1)]


# h1 serves; h2 is replaced as standby by h3 and reclaimed; h4 attaches and replaces h3, which is reclaimed; h2
# attaches again under a new key and replaces h4, which is reclaimed; then h2's new attach takes over to FB.
REPLACED = (['nameStandby("h3")'] + r_end(2) + r_reclaim(2) + r_attach("h4", 4) + ['nameStandby("h4")']
            + r_end(3) + r_reclaim(3) + r_attach("h2", 5) + ['nameStandby("h2")'] + r_end(4) + r_reclaim(4)
            + r_takeover("h2", 2))
# Each reclaim run: its recipe, the state its last turn reaches, and its model replacements.
RECLAIM_RUNS = {
    "fourthAttachTakesOver": (r_takeover("h2", 2) + r_end(1) + r_attach("h4", 4) + ['nameStandby("h4")']
                              + r_takeover("h4", 3),
                              'witnessFourthAttach and HistoryBound and rec.owner == "h4" and holder == "k4" '
                              'and preempts.contains(("h4", "h2", true)) and not(retired.contains("v1"))', FOUR),
    "endedPredecessorFreshHostRecovers": (ENDED_PREDECESSOR + ['nameStandby("h3")'] + r_takeover("h3", 3),
                                          'fb.keys().contains(3) and holder == "h3" and preempts == Set(("h3", "h1", true)) '
                                          'and rc.attaches.get(1).state == "ended" and not(retired.contains("v1"))', []),
    "lateRegisterAfterDrop": (LATE_REGISTER + ['endedPreempt("h2")', "endedPreemptLands(true)", "reportPoll"],
                              'rc.regs == Set("h3") and preempts.contains(("h3", "h2", true)) and not(rc.attaches.get(2).pair) '
                              'and procs.get(2).phase == "refused" and ev.act == "reportPoll" and not(retired.contains("v1"))', []),
    "failedAttachLandsLate": (FAILED_LATE,
                              'ev.act == "enrollRefused" and listed.get("v1").contains("h4") and not(rc.attaches.get(4).pair) '
                              'and kept.size() == 1 and not(retired.contains("v1"))', FOUR),
    "pausedOwnerEndedPreemptAfterReattach": (REATTACHED + ["endedPreemptLands(true)"],
                                             'holder == "k4" and rc.regs.contains("k4") and fb.keys().contains(4) '
                                             'and rc.spared == Set(("h2", false, false)) and rec.owner == "h2"', [EMAX_FOUR]),
    "designationRacesEnd": (RACED + ['takeoverStart("h3")', 'nameStandby("h2")'] + r_takeover("h2", 3),
                            'procs.get(2).phase == "refused" and not(deviceActs.contains(2)) and pending.forall(r => r.id != 2) '
                            'and fb.keys().contains(3) and rec.owner == "h2" and not(retired.contains("v1"))', []),
    "designationRacesEndAfterCas": (["endRead(3)", 'nameStandby("h3")'] + r_cas("h3", 2)
                                    + ["endWrite(3)", "takeoverReport1(2)", 'nameStandby("h2")'] + r_takeover("h2", 3),
                                    'procs.get(2).phase == "refused" and not(preempts.exists(x => x._1 == "h3")) '
                                    'and fb.keys().contains(3) and rec.owner == "h2" and not(retired.contains("v1"))', []),
    "endedPreemptNoEffectKeepsPair": (REGISTERED_ENDED + ["reportPoll", 'endedPreempt("h2")', "endedPreemptLands(false)",
                                                          "reportPoll"],
                                      'rc.regs.contains("h2") and rc.attaches.get(2).pair and rc.detaches == Set() '
                                      'and not(rc.absent.contains(2)) and ev.act == "reportPoll"', []),
    "standbyReplacedThreeTimes": (REPLACED,
                                  'fb.keys().contains(2) and holder == "k5" and rec.owner == "h2" and rec.g == 1 '
                                  'and HistoryBound and rc.attaches.get(2).state == "gone" and not(retired.contains("v1"))',
                                  FOUR),
    "ownerLostTwiceThenStandbyLost": (chain(4),
                                      'fb.keys().contains(5) and preempts == Set(("h5", "h1", true)) and rec.g == 1 '
                                      'and liveCount <= MAX_ATTACHED and not(retired.contains("v1"))', chain_settings(4)),
    # h2's CAS is pending while its entry ends, is reclaimed and h2 attaches again under k4; the stale CAS then
    # commits, and Report #1 rereads the entry under h2's first key and refuses.
    "staleCasAfterReattach": (STALE_CAS,
                              'procs.get(2).phase == "refused" and not(fb.keys().contains(2)) and holder == "h1" '
                              'and rec.owner == "h2" and not(retired.contains("v1"))', []),
    # The stale CAS made h2 owner under its first key; h3, named over that tenure, takes over and preempts h1's key,
    # whose tenure the stale CAS's takeover deposed under h2's first key.
    "staleCasThenFreshHostRecovers": (STALE_CAS_RECOVERY,
                                      'fb.keys().contains(3) and preempts.contains(("h3", "h1", true)) and holder == "h3" '
                                      'and not(retired.contains("v1"))', []),
    # h3's end is decided before its designation and lands after; h3 is reclaimed and attaches again under k4 with no
    # enrollment, and its takeover under the surviving designation refuses with no request.
    "reattachedUnenrolledRefuses": (REATTACHED_UNENROLLED,
                                    'procs.get(2).phase == "refused" and pending == Set() and not(deviceActs.contains(2)) '
                                    'and rec.standby == "h3" and rec.owner == "h1"', []),
    # h2 registers at its Report #1 and pauses; h3 takes over to FB, ends h2's entry and removes h2's key by an
    # ended-key preempt, and h2's resumed preempt refuses with no effect.
    "preemptAfterOwnKeyRemovedRefuses": (UNREGISTERED_PREEMPT, UNREGISTERED_END, []),
    # h2 stops after its CAS over h1's tenure while h2's own entry is ended and detached, so the listing of h2's poll
    # lacks h2 and holds no outside instance, and the record shows h2's entry ended: the poll withdraws with no
    # retirement.
    "missingOwnerPollWithdraws": (MISSING_OWNER,
                                  'ev.act == "pollWithdrawn" and kept == Set() and not(retired.contains("v1")) '
                                  'and rec.owner == "h2" and rc.endedPolls == Set(("h2", 1, 2))', []),
    # h1 reads the listing, h2 takes over and h1 takes the record back at a higher E; the open poll ends with no
    # verdict.
    "pollSupersededAtLaterE": (SUPERSEDED_POLL,
                               'ev.act == "pollSuperseded" and kept == Set() and not(retired.contains("v1")) '
                               'and rec.owner == "h1" and rec.e == 3 and rc.poller == ""', []),
    # A successor stops after its CAS, the ended predecessor still holds under its recorded pair, and the successor's
    # restart takes the lineage arm at Report #1 with the ended holder's key captured and the volume retained.
    "endedHolderRestartHolds": (ENDED_PREDECESSOR + ['restartRecords("h2")', "restartReady(3)", "restartReport1(3)"],
                                'procs.get(3).phase == "reportedHolder" and procs.get(3).prkey == "h1" '
                                'and not(retired.contains("v1"))', []),
    # The same restart carries the arm to FB over the ended holder, whose recorded pair the arm admits.
    "endedHolderRestartReachesFb": (ENDED_PREDECESSOR + ['restartRecords("h2")', "restartReady(3)", "restartReport1(3)"]
                                    + arm(3),
                                    'fb.keys().contains(3) and holder == "h2" and preempts == Set(("h2", "h1", true)) '
                                    'and rc.attaches.get(1).state == "ended" and not(retired.contains("v1"))', []),
    # h1, deposed by h2's stale preempt, still serves; h2's entry ends with its pair recorded and holding, and h1's
    # Report holds the volume under that recorded pair with no retirement and withdraws h1's attempt.
    "endedHolderReportHolds": (DEPOSED_SERVING + r_end(2) + ["reportPoll"],
                               'ev.act == "reportHold" and holder == "h2" and rc.attaches.get(2).state == "ended" '
                               'and procs.get(4).phase == "withdrawn" and not(retired.contains("v1"))', [EMAX_FOUR]),
    # A foreign attachment of the active volume: the owner's poll retires the volume in its step, finds only that
    # attachment outside the retained entries, and withdraws the owner's attempt.
    "foreignAttachPollRetires": (FOREIGN_POLL,
                                 'ev.act == "pollRetired" and rc.retiredOn == Set(UNRECORDED) and retired.contains("v1") '
                                 'and procs.get(1).phase == "withdrawn" and kept == Set()', []),
    # An unrecorded holder takes the reservation and the owner's command completes with a deposing status: the Report
    # that judges the withdrawn attempt retires the volume on that holder alone.
    "unrecordedHolderReportRetires": (["statusDeposition(true)", "reportPoll"],
                                      'ev.act == "reportRetired" and rc.retiredOn == Set(UNRECORDED) '
                                      'and retired.contains("v1") and holder == UNRECORDED', []),
    # h3's end lands between its takeover preempt and its Report #2: Report #2 rereads the entry under h3's key and
    # grants no FB, and h3's recorded pair holds the retained volume.
    "endLandsBeforeReport2Refuses": (ENDED_BEFORE_REPORT_2,
                                     'procs.get(2).phase == "refused" and not(fb.keys().contains(2)) and holder == "h3" '
                                     'and rc.attaches.get(3).state == "ended" and preempts == Set(("h3", "h1", true)) '
                                     'and not(retired.contains("v1"))', []),
    # The arm's own attach ends between its Register and its reread: the reread refuses with no preempt, and h1
    # keeps the reservation.
    "armRereadRefusesEndedAttach": (ENDED_ARM,
                                    'procs.get(3).phase == "refused" and rc.rereads == Set((3, false)) '
                                    'and preempts == Set() and holder == "h1" and rc.attaches.get(2).state == "ended" '
                                    'and rec.owner == "h2" and not(retired.contains("v1"))', []),
    # h3's paused takeover preempt removes the registration of h2's key after h2's arm registered and reread: the
    # arm's preempt refuses with no effect, and h1 keeps the reservation.
    "armPreemptAfterOwnKeyRemovedRefuses": (UNREGISTERED_ARM, UNREGISTERED_ARM_END,
                                            [constant("EMAX", 3, 6), constant("REQUESTS", 4, 6)]),
    # Between the arm's reread and its preempt, h1 loses its pair. The preempt's recorded evidence stays admitted,
    # because Report #1 showed h1's key as a recorded pair. h3 holds the reservation, so the preempt leaves h3 as
    # holder. The arm refuses at Report #2.
    "armPreemptAfterHolderPairDropped": (PAIR_DROPPED_ARM,
                                         'procs.get(3).phase == "refused" and not(fb.keys().contains(3)) '
                                         'and preempts == Set(("h3", "h1", true), ("h2", "h1", true)) '
                                         'and not(paired("h1")) and rc.attaches.get(1).state == "ended" '
                                         'and holder == "h3" and fb.keys().contains(4) and not(retired.contains("v1"))',
                                         [constant("EMAX", 3, 4)]),
    "takeoverChainDepthFive": (chain(5),
                               'fb.keys().contains(6) and preempts == Set(("h6", "h1", true)) and rec.g == 1 '
                               'and liveCount <= MAX_ATTACHED and not(retired.contains("v1"))', chain_settings(5)),
    # After h2's key ends and the record drops h2's pair, the serving Report still treats h2 as a recorded
    # attachment, holds the volume, and withdraws h1's attempt.
    "droppedKeyHolderReportHolds": (DROPPED_KEY_HOLDER + ["reportPoll"],
                                    'ev.act == "reportHold" and holder == "h2" and endedKey("h2") and not(paired("h2")) '
                                    'and procs.get(5).phase == "withdrawn" and not(retired.contains("v1"))',
                                    processes(5)),
    # After the record drops h2's pair, the Report of h1's restart still counts h2 as a recorded attachment.
    "droppedKeyHolderRestartHolds": (DROPPED_KEY_RESTART,
                                     'procs.get(6).phase == "refusedRecorded" and holder == "h2" and not(paired("h2")) '
                                     'and not(retired.contains("v1"))', processes(6)),
}
ISSUABLE = "val issuable = endedKey(k) and servingPastFb(rec.owner) and not(holding and holder == k)"
ENDABLE = "val endable = rec.e > 0 and a.host != rec.owner and a.host != rec.standby"
NAME_GUARD = "HOSTS.contains(h), h != rec.owner, rec.standby != h, live(h), paired(attachKey(h)),"
# Each reclaim mutant: the invariant it breaks, its recipe, the replacements of the model's text and the constants.
RECLAIM_MUTANTS = {
    "reclaim-end-drops-pair": ("EndOrder", ENDED_PREDECESSOR,
                               [('    val written = { ...a, state: "ended" }\n',
                                 '    val written = { ...a, state: "ended", pair: false }\n')]),
    "reclaim-judges-ignore-ended-key": ("EndedAttachNeverRetires", LATE_REGISTER,
                                        [("and not(paired(k)) and not(endedKey(k)))", "and not(paired(k)))")]),
    "reclaim-remove-while-listed": ("EndedAttachNeverRetires", r_end(3) + ["markGone(3)", "readListing",
                                                                                  "pollEntries"],
                                    [('val clean = a.req == "detached" and not(listed.get(rec.active).contains(a.host)) '
                                      "and not(rc.pollRead.contains(a.host))", "val clean = true")]),
    # The serving Report admits only a live attach's recorded pair as holder, so an ended holder retires the volume.
    "reclaim-report-retires-ended-holder": ("EndedAttachNeverRetires", DEPOSED_SERVING + r_end(2) + ["reportPoll"],
                                            [EMAX_FOUR,
                                             ("val recordedHolder = holding and holder != ownKey and recordedKey(holder)\n",
                                              "val recordedHolder = holding and holder != ownKey and recordedKey(holder) "
                                              "and liveKey(holder)\n")]),
    # Using `paired(holder)` makes the serving Report retire the volume on h2's ended key after the record drops
    # h2's pair.
    "reclaim-report-retires-dropped-key-holder": ("EndedAttachNeverRetires", DROPPED_KEY_HOLDER + ["reportPoll"],
                                                  processes(5)
                                                  + [("val recordedHolder = holding and holder != ownKey and recordedKey(holder)\n",
                                                      "val recordedHolder = holding and holder != ownKey and paired(holder)\n")]),
    # After the record drops h2's pair, `paired(holder)` is false, so `restartRetire(6)` retires the volume on h2's
    # ended key.
    "reclaim-restart-retires-dropped-key-holder": ("EndedAttachNeverRetires", DROPPED_KEY_RESTART + ["restartRetire(6)"],
                                                   processes(6)
                                                   + [('else if (recordedKey(holder)) "refusedRecorded"',
                                                       'else if (paired(holder)) "refusedRecorded"')]),
    # The Report reads a registrant with a recorded pair as foreign: h2, paused after its CAS, registers under its
    # live, enrolled attach while h3 serves, and h3's Report retires the volume.
    "reclaim-report-ignores-recorded-pair": ("EndedAttachNeverRetires",
                                             RECLAIM_ROOTS_PAUSED + ["takeoverReport1(2)", "reportPoll"],
                                             [("and not(paired(k)) and not(endedKey(k)))", "and not(endedKey(k)))")]),
    # The premise that a failed or detached request lands no more, dropped: h3's instance is listed again after its
    # gone mark, outside the retained entries.
    "reclaim-late-land-after-detach": ("EndedAttachNeverRetires",
                                       RECLAIMED_3 + ["lateLand(3)", "readListing", "pollEntries"],
                                       [('rc.attaches.keys().contains(i), a.req == "failed", advance("lateLand", i)',
                                         'rc.attaches.keys().contains(i), Set("failed", "detached").contains(a.req), '
                                         'advance("lateLand", i)')]),
    "reclaim-poll-ignores-listing": ("AttachOutsideDesiredStateRetires", FOREIGN_POLL,
                                     [("    val outside = not(listing.subseteq(admitted))\n", "    val outside = false\n"),
                                      ("val admits = listing.contains(rec.owner) and listing.subseteq(admitted)",
                                       "val admits = true")]),
    "reclaim-poll-never-retires": ("AttachOutsideDesiredStateRetires", FOREIGN_POLL,
                                   [("retired' = if (not(outside)) retired else retired.union(Set(rec.active)),",
                                     "retired' = retired,")]),
    # The poll retires on every listing, so a poll that keeps serving on the retained entries retires the volume.
    "reclaim-poll-retires-kept": ("AttachOutsideDesiredStateRetires", ["readListing", "pollEntries"],
                                  [("retired' = if (not(outside)) retired else retired.union(Set(rec.active)),",
                                    "retired' = retired.union(Set(rec.active)),")]),
    # The poll reads no instance as outside: a listing with a foreign attachment ends with no verdict and no
    # retirement.
    "reclaim-poll-outside-unobserved": ("EndedAttachNeverRetires", FOREIGN_POLL,
                                        [("    val outside = not(listing.subseteq(admitted))\n",
                                          "    val outside = false\n")]),
    # The serving Report retires whatever it finds: the own pair holds and no registrant is foreign.
    "reclaim-report-retires-kept": ("EndedAttachNeverRetires", ["reportPoll"],
                                    [("retired' = if (keeps) retired else retired.union(Set(rec.active)),",
                                      "retired' = retired.union(Set(rec.active)),")]),
    # The retiring poll withdraws no attempt, and the owner's attempt takes a command after the trigger it observed.
    "reclaim-poll-keeps-attempt": ("DetectedLossWithdraws", FOREIGN_POLL + ["command(1)"],
                                   [("procs' = if (not(withdraws)) procs else procs.keys().mapBy(",
                                     "procs' = if (true) procs else procs.keys().mapBy(")]),
    # The poll keeps serving on a record that shows the owner's own entry ended: h3, whose end was decided before its
    # takeover and written after its FB, keeps serving past the poll that read it.
    "reclaim-poll-serves-ended-owner": ("EndedOwnerServesNothing", OWNER_ENDED,
                                        [("    val withdraws = outside or ownEnded\n", "    val withdraws = outside\n")]),
    "reclaim-ended-preempt-live-key": ("NoPreemptOfForeignKey", ['endedPreempt("h2")'],
                                       [("val issuable = endedKey(k) and", "val issuable = true and")]),
    "reclaim-ended-preempt-holder-key": ("NoPreemptOfForeignKey",
                                         DEPOSED_SERVING + r_end(2) + ['endedPreempt("h2")'],
                                         [EMAX_FOUR, (ISSUABLE, "val issuable = endedKey(k) and servingPastFb(rec.owner)")]),
    "reclaim-ended-preempt-before-fb": ("NoPreemptOfForeignKey",
                                        r_cas("h2", 2) + r_end(3) + ['endedPreempt("h3")'],
                                        [(ISSUABLE, "val issuable = endedKey(k) and not(holding and holder == k)")]),
    # The paused owner's preempt lands after h2's reattach registered and before h2's takeover preempt deposes h3.
    "reclaim-key-reused-across-attaches": ("EndedPreemptSparesLiveAttach",
                                           REATTACHED[:REATTACHED.index("takeoverPreempt(4)")] + ["endedPreemptLands(true)"],
                                           [EMAX_FOUR, ("    val key = KEYS.get(rc.next)\n",
                                                        "    val key = if (newest(h) == 0) KEYS.get(rc.next) "
                                                        "else rc.attaches.get(newest(h)).key\n")]),
    # A restart of a record-named owner whose own attach ended: its ready wait is a device command after a records
    # read that failed its own-attach check.
    "reclaim-restart-reads-ended-own-attach": ("RecordsBeforeDevice",
                                               STALE_CAS[:STALE_CAS.index("endWrite(2)") + 1]
                                               + ["decideAny", "reply(2)", "takeoverCrash(2)", 'restartRecords("h2")',
                                                  "restartReady(3)"],
                                               [("rec.e < EMAX, ownAttach, not(", "rec.e < EMAX, not(")]),
    # The owner names the holder's key and the device takes the preempt from an unregistered issuer: h1, deposed by
    # h2's stale preempt and still serving, preempts h2's ended key, and the reservation moves. Either replacement
    # alone moves nothing in this schedule, where no registered issuer serves beside an ended holder.
    "reclaim-ended-preempt-moves-holder": ("EndedPreemptSparesLiveAttach",
                                           DEPOSED_SERVING + r_end(2)
                                           + ['endedPreempt("h2")', "endedPreemptLands(true)"],
                                           [EMAX_FOUR,
                                            (ISSUABLE, "val issuable = endedKey(k) and servingPastFb(rec.owner)"),
                                            ("    val takes = effect and rc.regs.contains(rc.dueBy)\n",
                                             "    val takes = effect\n")]),
    # The arm's reread admits a restart whose own attach ended after its Register, and its preempt of h1's key follows
    # a reread that did not name the tenure with the attach live.
    "reclaim-arm-reread-ignores-ended-attach": ("NoPreemptOfForeignKey", ENDED_ARM + ["restartLineagePreempt(3)"],
                                                [("val passes = named",
                                                  "val passes = rec.g == q.g and rec.owner == q.host and rec.e == q.n + 1")]),
    "reclaim-ended-attach-takes-over": ("EndedGrantsNothing", RACED + ['takeoverStart("h3")'],
                                        [(NAMED, "val named = rec.standby == h and paired(attachKey(h))")]),
    "reclaim-detach-before-drop": ("EndOrder", REGISTERED_ENDED + ["detachRequest(2)"],
                                   [("    val unpaired = not(a.pair)\n", "    val unpaired = true\n")]),
    # A live entry with no pair, recorded and not yet enrolled, is detached before any end mark.
    "reclaim-detach-before-end": ("EndOrder", r_end(3) + ['recordAttach("h4")', "detachRequest(4)"],
                                  [('rc.attaches.keys().contains(i), a.state == "ended", unpaired,',
                                    "rc.attaches.keys().contains(i), unpaired,"), hosts(4)]),
    "reclaim-drop-without-report": ("EndOrder", REGISTERED_ENDED + ["dropPair(2)"],
                                    [("    val reported = rc.absent.contains(i)\n", "    val reported = true\n")]),
    # The serving Report records an ended entry absent though it lists the entry's key.
    "reclaim-report-absent-lists-key": ("EndOrder", REGISTERED_ENDED + ["reportPoll"],
                                        [("and rc.attaches.get(i).pair\n"
                                          "      and not(rc.regs.contains(rc.attaches.get(i).key)))",
                                          "and rc.attaches.get(i).pair)")]),
    # A Report on which another host's recorded pair holds records an absence: h1 serves past its FB under h2's hold.
    "reclaim-hold-report-records-absence": ("EndOrder", DEPOSED_SERVING + r_end(3) + ["reportPoll"],
                                            [EMAX_FOUR, ("val recorded = if (own and owning.size() > 0)",
                                                         "val recorded = if (owning.size() > 0)")]),
    # The pair drops after h2's takeover CAS deposed the owner whose Report showed the key absent, with no owner
    # serving past its FB.
    "reclaim-drop-not-serving": ("EndOrder", r_end(3) + ["reportPoll"] + r_cas("h2", 2) + ["dropPair(3)"],
                                 [('a.state == "ended", a.pair, servingPastFb(rec.owner), reported,',
                                   'a.state == "ended", a.pair, reported,')]),
    "reclaim-reattach-resumes-epoch": ("NoEpochReuse", REATTACHED[:REATTACHED.index("reply(4)") + 1],
                                       [EMAX_FOUR, ('phase: if (named) "sent" else "refused", g: rec.g, n: rec.e,',
                                                    'phase: if (named) "sent" else "refused", g: rec.g, '
                                                    'n: if (entriesOf(h).size() > 1) rec.e - 1 else rec.e,')]),
    # The poll reads the volume record before the listing: an attach recorded and landed between the two reads is
    # listed outside the admitted set the poll read.
    "attach-before-binding": ("RecordedAttachRetiresNothing", RACING_POLL,
                              [("pollRead: listed.get(rec.active), poller", "pollRead: reclaimAdmitted, poller"),
                               ("    val listing = rc.pollRead\n", "    val listing = listed.get(rec.active)\n"),
                               ("    val admitted = reclaimAdmitted\n", "    val admitted = rc.pollRead\n"), hosts(4)]),
    # Report #1 and Report #2 judge the host's newest attach in place of the process's own, so the stale CAS of
    # staleCasAfterReattach reaches an FB under a gone attach's key.
    "reclaim-reread-judges-newest-attach": ("EndedGrantsNothing",
                                            STALE_CAS + ["takeoverPreempt(2)", "restartReport2(2)"],
                                            [(TENURE_CHECK, TENURE_CHECK.replace("liveKey(q.key)", "live(q.host)")),
                                             (CONFIRMED, CONFIRMED.replace("liveKey(q.key)", "live(q.host)"))]),
    # The gone mark ignores an owner poll whose listing read showed the instance: that poll's record read then finds
    # the instance outside the retained entries.
    "reclaim-gone-ignores-open-poll": ("EndedAttachNeverRetires",
                                       r_end(3) + ["reportPoll", "dropPair(3)", "detachRequest(3)", "readListing",
                                                   "detachDone(3)", "markGone(3)", "pollEntries"],
                                       [(" and not(rc.pollRead.contains(a.host))", "")]),
    # A gone entry's key stops being an ended key: a Register that lands after the gone mark is unknown to the Report.
    "reclaim-gone-key-not-ended": ("EndedAttachNeverRetires",
                                   RECLAIM_ROOTS_PAUSED + r_end(2) + r_reclaim(2) + ["takeoverReport1(2)", "reportPoll"],
                                   [('Set("ended", "gone").contains(rc.attaches.get(i).state)',
                                     'rc.attaches.get(i).state == "ended"')]),
    # A host attaches again while its earlier entry is ended, before its gone mark.
    "reclaim-reattach-before-gone": ("AttachAfterGone", r_end(3) + r_reclaim(3)[:4] + ['recordAttach("h3")'],
                                     [("rec.e > 0, not(retired.contains(rec.active)), afterGone(h),",
                                       "rec.e > 0, not(retired.contains(rec.active)), not(live(h)),")]),
    # The enrollment admits an ended entry.
    "reclaim-enroll-admits-ended": ("EndedGrantsNothing", FAILED_LATE,
                                    [('    val admitted = a.state == "live"\n', "    val admitted = true\n"), hosts(4)]),
    # The takeover start ignores the enrolled pair, so a reattached, unenrolled standby submits its CAS.
    "reclaim-takeover-ignores-enrollment": ("EndedGrantsNothing", REATTACHED_UNENROLLED,
                                            [(NAMED, "val named = rec.standby == h and live(h)")]),
    # Lineage records the predecessor's newest attach key, so the deposed tenure won under h2's first key is lost.
    "reclaim-lineage-newest-key": ("NoPreemptOfForeignKey", STALE_CAS_RECOVERY[:-1],
                                   [("procs.get(r.id).key, tenureKey(r.owner))))", "procs.get(r.id).key, attachKey(r.owner))))")]),
    # The enrollment does not wait for the attach request: a recorded entry enrolls before its request.
    "reclaim-enroll-before-landed": ("EndedGrantsNothing", r_end(3) + ['recordAttach("h4")', "enroll(4)"],
                                     [('rc.attaches.keys().contains(i), a.req == "landed", not(a.pair), a.host != rec.owner,',
                                       "rc.attaches.keys().contains(i), not(a.pair), a.host != rec.owner,"), hosts(4)]),
    # The designation names a host whose attach ended, and one whose new attach has no enrolled pair.
    "reclaim-designation-names-ended": ("EndedGrantsNothing", ['nameStandby("h3")'] + r_end(2) + ['nameStandby("h2")'],
                                        [(NAME_GUARD, NAME_GUARD.replace(" live(h),", ""))]),
    "reclaim-designation-names-unenrolled": ("EndedGrantsNothing",
                                             RECLAIMED_3 + ['recordAttach("h3")', "attachRequest(4, true)",
                                                            'nameStandby("h3")'],
                                             [(NAME_GUARD, NAME_GUARD.replace(" paired(attachKey(h)),", ""))]),
    # The end is decided for the owner's attach, and for the named standby's.
    "reclaim-end-ignores-owner": ("EndedHoldsNoRole", ["endRead(1)"],
                                  [(ENDABLE, "val endable = rec.e > 0 and a.host != rec.standby")]),
    "reclaim-end-ignores-standby": ("EndedHoldsNoRole", ["endRead(2)"],
                                    [(ENDABLE, "val endable = rec.e > 0 and a.host != rec.owner")]),
    # Report #2 grants the FB without rereading the entry, which ended after the takeover's preempt.
    "reclaim-report2-skips-reread": ("EndedGrantsNothing", ENDED_BEFORE_REPORT_2,
                                     [(CONFIRMED, CONFIRMED.replace("\n      and liveKey(q.key)", ""))]),
    # The volume admits an attach at `MAX_EVENTS` retained entries with a live slot free.
    "reclaim-attach-past-events-bound": ("HistoryBound",
                                         r_end(3) + ['recordAttach("h4")', "attachRequest(4, true)"] + r_end(4)
                                         + ['recordAttach("h5")'],
                                         [("    val open = liveCount < MAX_ATTACHED and retainedCount < MAX_EVENTS\n",
                                           "    val open = liveCount < MAX_ATTACHED\n"), hosts(5)]),
    # The volume admits an attach at any count.
    "reclaim-attach-past-bound": ("HistoryBound", ['recordAttach("h4")'], [("    val open = liveCount < MAX_ATTACHED and retainedCount < MAX_EVENTS\n",
                                                                            "    val open = true\n"), hosts(4)]),
}
NO_END = (ENDABLE, "val endable = false")
REFUSES_ENDED_HOLDER = (TAKEOVER_HOLDER, TAKEOVER_HOLDER + " and not(endedKey(holder))")
# Each reclaim root: its prefix, the turns its search runs past it, and its constants.
RECLAIM_ROOTS = {
    "serving": ([], 10),
    "takenOver": (r_takeover("h2", 2), 10),
    "ended": (r_takeover("h2", 2) + r_end(1), 10),
    "paused": (RECLAIM_ROOTS_PAUSED, 10),
}


def prefixed(prefix, step="reclaimStep"):
    """The instance text of a search that takes `prefix` one action per turn and then `step`."""
    if not prefix:
        return f"  action prefixed = {step}\n"
    picks = "".join(f"    all {{ turn == {at}, {action} }},\n" for at, action in enumerate(prefix))
    return ("  action prefix = any {\n" + picks + "  }\n"
            f"  action prefixed = any {{ prefix, all {{ turn >= {len(prefix)}, {step} }} }}\n")


def arm_root_cases(Case):
    """The lineage arm's rooted search under the takeover schedules: `safety`, and `ArmFbConfirmed` alone, over every
    continuation of `ARM_ROOT` for `ARM_TURNS` turns, each of which must reach its last turn; the witnesses, which
    must hold past the prefix; and the mutants, which the search must reject past the prefix."""
    bound = len(ARM_ROOT) + ARM_TURNS
    settings = {"BOUND": str(bound)}
    extra = prefixed(ARM_ROOT, "takeoverStep")
    for name, prop in (("afterArmReport1", "safety"), ("ArmFbConfirmed", "ArmFbConfirmed")):
        yield Case(f"tenure-takeover-{name}", invariant=prop, family="tenure", step="prefixed", settings=settings,
                   mutations=ARM_CONSTANTS, extra=extra, depth=bound + 1)
    for witness in ARM_WITNESSES:
        yield Case(f"tenure-takeover-afterArmReport1-reach-{witness}", invariant="unreached", expected="violation",
                   family="tenure", step="prefixed", settings=settings, mutations=ARM_CONSTANTS,
                   after=len(ARM_ROOT) + 1, extra=extra + f"  val unreached = not({witness})\n")
    for name, (prop, mutation) in ARM_ROOT_MUTANTS.items():
        yield Case(f"tenure-takeover-afterArmReport1-mutant-{name}", invariant=prop, expected="violation",
                   family="tenure", step="prefixed", settings=settings, mutations=[*ARM_CONSTANTS, mutation],
                   after=len(ARM_ROOT) + 1, extra=extra)


def reclaim_cases(Case):
    """The reclaim schedule's cases."""
    safety = "  val reclaimSafety = " + " and ".join(RECLAIM_INVARIANTS) + "\n"
    for root, (prefix, turns) in RECLAIM_ROOTS.items():
        for n in (3, 4):
            yield Case(f"tenure-reclaim-{root}-h{n}", invariant="reclaimSafety", family="tenure", step="prefixed",
                       settings={"BOUND": str(len(prefix) + turns)}, mutations=[hosts(n)], depth=len(prefix) + turns + 1,
                       extra=RECLAIM_INIT + prefixed(prefix) + safety)
    for name, (recipe, end, mutations) in RECLAIM_RUNS.items():
        yield Case(f"tenure-run-{name}", invariant="runSafety", family="tenure", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=mutations,
                   extra=RECLAIM_INIT + safety + f"  val runSafety = reclaimSafety and (turn == {len(recipe)} implies ({end}))\n")
        yield Case(f"tenure-run-{name}-reached", invariant="runWitness", expected="violation", family="tenure",
                   recipe=recipe, settings={"BOUND": str(len(recipe))}, mutations=mutations, trace=len(recipe) + 1,
                   extra=RECLAIM_INIT + f"  val runWitness = not(turn == {len(recipe)} and ({end}))\n")
    for name, (prop, recipe, mutations) in RECLAIM_MUTANTS.items():
        yield Case(f"tenure-mutant-{name}", invariant=prop, expected="violation", family="tenure", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=mutations,
                   trace=len(recipe) + 1, extra=RECLAIM_INIT)
    # The issuer check of the takeover preempt dropped: h2's preempt takes effect though its key lost its
    # registration, so the run's end is unreached.
    recipe = RECLAIM_RUNS["preemptAfterOwnKeyRemovedRefuses"][0]
    yield Case("tenure-run-preemptAfterOwnKeyRemovedRefuses-ignores-issuer", invariant="refusedEnd",
               expected="violation", family="tenure", recipe=recipe, settings={"BOUND": str(len(recipe))},
               mutations=[("    val registered = rc.regs.contains(q.key)\n", "    val registered = true\n")],
               trace=len(recipe) + 1,
               extra=RECLAIM_INIT + f"  val refusedEnd = turn == {len(recipe)} implies ({UNREGISTERED_END})\n")
    # The refused takeover preempt names the key of a later tenure, which no takeover of its issuer succeeded: h2's
    # command names h3's key once h2's registration is gone, so the key it named lacks the takeover's evidence.
    yield Case("tenure-run-preemptAfterOwnKeyRemovedRefuses-names-later-key", invariant="NoPreemptOfForeignKey",
               expected="violation", family="tenure", recipe=recipe, settings={"BOUND": str(len(recipe))},
               mutations=[('deviceStep(p, "reported", if (registered) "preempted" else "refused", q.prkey, true),',
                           'deviceStep(p, "reported", if (registered) "preempted" else "refused", '
                           'if (registered) q.prkey else "h3", true),')],
               trace=len(recipe) + 1, extra=RECLAIM_INIT)
    # The issuer check of the arm's preempt dropped: h2's preempt takes the reservation though its key lost its
    # registration, so the run's end is unreached.
    recipe, end, mutations = RECLAIM_RUNS["armPreemptAfterOwnKeyRemovedRefuses"]
    yield Case("tenure-run-armPreemptAfterOwnKeyRemovedRefuses-ignores-issuer", invariant="refusedEnd",
               expected="violation", family="tenure", recipe=recipe, settings={"BOUND": str(len(recipe))},
               mutations=[*mutations, ("val issuerRegistered = rc.regs.contains(q.key)", "val issuerRegistered = true")],
               trace=len(recipe) + 1,
               extra=RECLAIM_INIT + f"  val refusedEnd = turn == {len(recipe)} implies ({end})\n")
    # The refused arm preempt names a key Report #1 did not show: h2's command names h3's key once h2's registration
    # is gone, so the key the command named lacks the bumped form's evidence.
    yield Case("tenure-run-armPreemptAfterOwnKeyRemovedRefuses-names-unshown-key", invariant="NoPreemptOfForeignKey",
               expected="violation", family="tenure", recipe=recipe, settings={"BOUND": str(len(recipe))},
               mutations=[*mutations,
                          ('deviceStep(p, "reread", if (issuerRegistered) "preempted" else "refused", q.prkey, true),',
                           'deviceStep(p, "reread", if (issuerRegistered) "preempted" else "refused", '
                           'if (issuerRegistered) q.prkey else "h3", true),')],
               trace=len(recipe) + 1, extra=RECLAIM_INIT)
    # The poll's record read judges under a later tenure than the one that read the listing: the run's end, the poll
    # superseded with no verdict, is unreached on the branch that judges.
    recipe, end, _ = RECLAIM_RUNS["pollSupersededAtLaterE"]
    yield Case("tenure-run-pollSupersededAtLaterE-judges", invariant="supersededEnd", expected="violation",
               family="tenure", recipe=recipe, settings={"BOUND": str(len(recipe))},
               mutations=[('rc.poller != "", pollCurrent, not(retired.contains(rec.active)),',
                           'rc.poller != "", not(retired.contains(rec.active)),')], trace=len(recipe) + 1,
               extra=RECLAIM_INIT + f"  val supersededEnd = turn == {len(recipe)} implies ({end})\n")
    # In the mutant, Report #1 admits h3, whose entry ended after h3's CAS. The run ends with h3 in phase `reported`,
    # but h3 must finish in phase `refused`.
    recipe, end, _ = RECLAIM_RUNS["designationRacesEndAfterCas"]
    yield Case("tenure-run-designationRacesEndAfterCas-skips-reread", invariant="rereadEnd", expected="violation",
               family="tenure", recipe=recipe, settings={"BOUND": str(len(recipe))},
               mutations=[(TENURE_CHECK, TENURE_CHECK.replace(" and liveKey(q.key)", ""))], trace=len(recipe) + 1,
               extra=RECLAIM_INIT + f"  val rereadEnd = turn == {len(recipe)} implies ({end})\n")
    # The closure controls: cut to the direct predecessor, to one earlier takeover, and to one round fewer than the
    # chain's depth, the last successor's preempt of h1 carries no evidence, so each chain needs its full depth.
    for run, depth, controls in (("takeoverChainDepthFive", 5, (("one-level", 0), ("one-round", 1), ("three-rounds", 3))),
                                 ("ownerLostTwiceThenStandbyLost", 4, (("two-rounds", 2),))):
        recipe = RECLAIM_RUNS[run][0][:-1]
        for control, rounds in controls:
            yield Case(f"tenure-run-{run}-{control}", invariant="NoPreemptOfForeignKey", family="tenure",
                       recipe=recipe, expected="violation", settings={"BOUND": str(len(recipe))},
                       mutations=chain_settings(depth) + [("1.to(REQUESTS).fold(", f"1.to({rounds}).fold(")],
                       trace=len(recipe) + 1, extra=RECLAIM_INIT)
    # The reach control: a successor's Report #1 that refuses an ended holder stops the fresh-host recovery at that
    # Report, with no preempt, so its FB, which follows the preempt and Report #2, is unreachable.
    recipe = RECLAIM_RUNS["endedPredecessorFreshHostRecovers"][0]
    recipe = recipe[:recipe.index("takeoverReport1(3)") + 1]
    yield Case("tenure-mutant-reclaim-takeover-refuses-ended-holder", invariant="stopsShort", family="tenure",
               recipe=recipe, settings={"BOUND": str(len(recipe))}, mutations=[REFUSES_ENDED_HOLDER],
               extra=RECLAIM_INIT + f'  val stopsShort = turn == {len(recipe)} implies (procs.get(3).phase == "refused" '
                                    'and preempts == Set() and not(fb.keys().contains(3)))\n')
    yield Case("tenure-mutant-reclaim-takeover-refuses-ended-holder-reached", invariant="refused", expected="violation",
               family="tenure", recipe=recipe, settings={"BOUND": str(len(recipe))}, mutations=[REFUSES_ENDED_HOLDER],
               trace=len(recipe) + 1,
               extra=RECLAIM_INIT + f'  val refused = not(turn == {len(recipe)} and procs.get(3).phase == "refused")\n')
    # The bound control: from h2's FB, the takenOver root's search records a fourth entry, and with no end the same
    # search, run to the root's full depth, records none.
    prefix, turns = RECLAIM_ROOTS["takenOver"]
    extra = RECLAIM_INIT + prefixed(prefix) + "  val unreached = not(witnessFourthEntry)\n"
    settings = {"BOUND": str(len(prefix) + turns)}
    yield Case("tenure-reach-witnessFourthEntry", invariant="unreached", expected="violation", family="tenure",
               step="prefixed", settings=settings, mutations=FOUR, extra=extra)
    yield Case("tenure-mutant-reclaim-no-end", invariant="unreached", family="tenure", step="prefixed",
               settings=settings, mutations=FOUR + [NO_END], depth=len(prefix) + turns + 1, extra=extra)
    # witnessFourthAttach from the ended root: the fourth attach is recorded, enrolled, named and takes over to FB
    # within the root's search.
    prefix, turns = RECLAIM_ROOTS["ended"]
    yield Case("tenure-reach-witnessFourthAttach", invariant="unreached", expected="violation", family="tenure",
               step="prefixed", settings={"BOUND": str(len(prefix) + turns)}, mutations=FOUR,
               extra=RECLAIM_INIT + prefixed(prefix) + "  val unreached = not(witnessFourthAttach)\n")
    # The reclaim witnesses, each reached on a recipe of the unmutated model.
    for witness, recipe, mutations in (
            ("witnessClosedAtLive", ['recordAttach("h4")'], FOUR),
            ("witnessClosedAtEvents", r_end(3) + ['recordAttach("h4")', "attachRequest(4, true)"] + r_end(4)
             + ['recordAttach("h5")'], [hosts(5)]),
            ("witnessEndedRegistrantKept", LATE_REGISTER, []),
            ("witnessEndedPreemptRemoves", LATE_REGISTER + ['endedPreempt("h2")', "endedPreemptLands(true)"], []),
            ("witnessReattach", REPLACED[:REPLACED.index('recordAttach("h2")') + 1], FOUR),
            ("witnessKeptBesideEnded", r_end(3) + ["readListing", "pollEntries"], []),
            ("witnessOwnerEntryEnded", OWNER_ENDED, []),
            ("witnessReclaimPollRetires", FOREIGN_POLL, []),
            ("witnessEndedPreemptMovesHolder", ENDED_PREEMPT_MOVES, processes(5))):
        yield Case(f"tenure-reach-{witness}", invariant="unreached", expected="violation", family="tenure",
                   recipe=recipe, settings={"BOUND": str(len(recipe))}, mutations=mutations, trace=len(recipe) + 1,
                   extra=RECLAIM_INIT + f"  val unreached = not({witness})\n")


# The handoff schedule runs from `reclaimInit`: h1 serves past its FB at E = 1 with h2 named standby, and drains,
# withdraws and transfers to h2, which activates through its restart's lineage arm.
HANDOFF_INIT = RECLAIM_INIT
ISSUED = ["planDrain(1)", "transferStart(1)"]
TRANSFERRED = ISSUED + ["decideAny", "transferReply(1)"]


def target(p):
    """h2's restart as process `p` through Report #1, then its lineage arm to FB."""
    return ['restartRecords("h2")', f"restartReady({p})", f"restartReport1({p})"] + arm(p)


def own_restart(p):
    """The owner's same-host restart as process `p` on the own path: Report #1, the bump, the self preempt and
    Report #2."""
    return ['restartRecords("h1")', f"restartReady({p})", f"restartReport1({p})", f"restartBump({p})", "decideAny",
            f"reply({p})", f"restartPreempt({p}, false)", f"restartReport2({p})"]


HANDOFF_FB = TRANSFERRED + target(2)
# The transfer's reply is lost while its request is still undecided; h1's restart bumps first, and the transfer then
# fails its condition on E.
UNKNOWN_UNCOMMITTED = ISSUED + ["transferTimeout(1)", 'restartRecords("h1")', "restartReady(2)", "restartReport1(2)",
                                "restartBump(2)", "decideOf(2)", "decideOf(1)", "reply(2)", "restartPreempt(2, false)",
                                "restartReport2(2)"]
# The designation moves to h3 after the transfer's issue, so the transfer fails its condition on the standby.
REFUSED = ISSUED + ['nameStandby("h3")', "decideAny", "transferReply(1)"] + own_restart(2)
# h2's takeover CAS and the transfer both condition on h1's tenure and h2 named.
RACE = ISSUED + ['takeoverStart("h2")']
# h2 pauses after its CAS and Report #1 with h1's key captured, and h1 regains the record through its own takeover and
# serves again past its restart's FB.
STALE_TAKEOVER = (['takeoverStart("h2")', "decideAny", "reply(2)", "takeoverReport1(2)", 'nameStandby("h1")',
                   'takeoverStart("h1")', "decideAny", "reply(3)", "takeoverReport1(3)", 'observe(1, "laterTenure")']
                  + own_restart(4))
# The deploy restart to FB at E = 2, the attempt before `EMAX`, and the next planned exit's drain.
LAST_ATTEMPT = ["planDrain(1)", "planRestart(1)"] + own_restart(2) + ["planDrain(2)"]
# `TAKEOVER_BUMPS` lets a takeover process issue the restart's bump from `reported`, a second request under its id
# beside its CAS, which `TakeoverIssuesNoBump` refuses in the model.
TAKEOVER_BUMPS = ('procs.keys().contains(p), q.restart, Set("reported", "reportedHolder")',
                  'procs.keys().contains(p), Set("reported", "reportedHolder")')
# Under `TAKEOVER_BUMPS`, h2's takeover process issues a bump from `reported`, a second request under process 2's id.
# When h2 drains, h3 is the named standby and the store still holds process 2's second request undecided.
PENDING_REQUEST = ['takeoverStart("h2")', "decideAny", "reply(2)", "takeoverReport1(2)", "restartBump(2)", "reply(2)",
                   "takeoverReport1(2)", "takeoverPreempt(2)", "restartReport2(2)", 'nameStandby("h3")', "planDrain(2)"]
# The reconciler decides the end of h2's entry while h3 is the named standby, the designation returns to h2, and the
# end write lands between the transfer's issue and its commit: the committed transfer names h2, whose attach ended.
TARGET_ENDED = (['nameStandby("h3")', "endRead(2)", 'nameStandby("h2")'] + ISSUED
                + ["endWrite(2)", "decideAny", "transferReply(1)"])
# Each handoff run: its recipe, the state its last turn reaches, and its model replacements.
HANDOFF_RUNS = {
    # The owner drains, withdraws and transfers; the acknowledged commit ends it, and h2's restart takes the lineage
    # arm over h1's pair to FB on v1 at its generation: the transfer and h2's bump each consume one E.
    "handoffTargetReachesFb": (HANDOFF_FB,
                               'witnessHandoffFb and procs.get(1).phase == "transferred" and rec.owner == "h2" '
                               'and rec.standby == "" and rec.e == 3 and rec.g == 1 and rec.active == "v1" '
                               'and holder == "h2" and activations == Set((1, 0, 1), (1, 2, 2)) '
                               'and not(retired.contains("v1"))', []),
    # The transfer commits with its reply lost, the outgoing attempt's exit (`transferUnknown`); restartRecords'
    # owner guard is h1's record read, which names h2, so h1's host starts no restart, and h2 reaches FB.
    "handoffUnknownCommittedExits": (ISSUED + ["decideAny", "transferTimeout(1)"] + target(2),
                                     'witnessTransferUnknownCommitted and rec.owner == "h2" and rec.e == 3', []),
    # The transfer's reply is lost and it never commits: h1's same-host restart bumps and reaches FB, and the record
    # still names h1 owner and h2 standby.
    "handoffUnknownUncommittedRestarts": (UNKNOWN_UNCOMMITTED,
                                          'witnessTransferUnknownThenRestart and not(decided.get(1)) and rec.owner == "h1" '
                                          'and rec.standby == "h2" and rec.e == 2 and fb.keys().contains(2)', []),
    # The designation moves before the commit: the transfer is refused, and h1's same-host restart reaches FB.
    "handoffRefusedRestarts": (REFUSED,
                               'witnessTransferRefusedThenRestart and handoffs == Set() and rec.owner == "h1" '
                               'and rec.standby == "h3" and rec.e == 2', []),
    # The transfer wins the race with h2's takeover CAS, whose condition then fails; h2 activates through its restart.
    "handoffRacesTakeoverTransferWins": (RACE + ["decideOf(1)", "decideOf(2)", "transferReply(1)", "reply(2)"] + target(3),
                                         'witnessHandoffFb and procs.get(2).phase == "refused" and not(deviceActs.contains(2)) '
                                         'and fb.keys().contains(3) and rec.e == 3', []),
    # h2's takeover CAS wins the race; the transfer fails its condition, the refusal ends h1's attempt, restartRecords'
    # owner guard starts no h1 restart while the record names h2, and h2's takeover reaches FB.
    "handoffRacesTakeoverTakeoverWins": (RACE + ["decideOf(2)", "decideOf(1)", "reply(2)", "transferReply(1)",
                                                 "takeoverReport1(2)", "takeoverPreempt(2)", "restartReport2(2)"],
                                         'procs.get(1).phase == "transferRefused" and handoffs == Set() '
                                         'and fb.keys().contains(2) and rec.owner == "h2" and holder == "h2" '
                                         'and procs.keys().forall(r => procs.get(r).host != "h1" or r == 1)', []),
    # h2's arm bump commits with its reply lost; the rerun reaches FB at the next E under its own session.
    "handoffTargetBumpUnknownRerun": (TRANSFERRED + ['restartRecords("h2")', "restartReady(2)", "restartReport1(2)",
                                                     "restartBump(2)", "decideAny", "timeout(2)"] + target(3),
                                      'witnessHandoffFb and not(activations.exists(a => a._3 == 2)) '
                                      'and activations.contains((1, 3, 3)) and rec.e == 4', [EMAX_FOUR]),
    # h2's arm Register fails: a hold with no flip, and h2's rerun reaches FB.
    "handoffTargetRegisterFailRerun": (TRANSFERRED + ['restartRecords("h2")', "restartReady(2)", "restartReport1(2)",
                                                      "restartBump(2)", "decideAny", "reply(2)", "restartDeviceFail(2)"]
                                       + target(3),
                                       'procs.get(2).phase == "refusedDevice" and fencing.contains(2) '
                                       'and fb.keys().contains(3) and holder == "h2" and rec.e == 4 '
                                       'and not(retired.contains("v1"))', [EMAX_FOUR]),
    # h2 is lost after the committed transfer and before its device steps: h3, named over h2's transfer tenure,
    # takes over and preempts h1's key, whose tenure h2's transfer succeeded, and reaches FB.
    "handoffTargetLostFreshHostRecovers": (TRANSFERRED + ['nameStandby("h3")'] + r_takeover("h3", 2),
                                           'fb.keys().contains(2) and holder == "h3" and preempts == Set(("h3", "h1", true)) '
                                           'and rec.owner == "h3" and rec.g == 1 and rec.active == "v1" '
                                           'and not(retired.contains("v1"))', []),
    # The deploy restart: the drained owner withdraws with no transfer and its same-host restart reaches FB at
    # E = 2 with the record's owner and standby unchanged.
    "handoffPlannedRestart": (["planDrain(1)", "planRestart(1)"] + own_restart(2),
                              'fb.keys().contains(2) and rec.owner == "h1" and rec.standby == "h2" and rec.e == 2 '
                              'and transfers == Set()', []),
    # A planned exit resumes before the withdrawal: the same tenure commands again with no E consumed.
    "handoffResumeBeforeWithdraw": (["planDrain(1)", "planResume(1)", "command(1)"],
                                    'commands.size() == 1 and rec.e == 1 and procs.get(1).phase == "active"', []),
    # The committed transfer's lineage row admits no preempt by its target: h2 may preempt h1's key only after its
    # own bump, through the bumped form.
    "handoffTransferAdmitsNoTargetPreempt": (TRANSFERRED,
                                             'not(preemptAdmitted("h2", "h1")) and rec.owner == "h2" and rec.e == 2', []),
    # After attempt 3 commits the handoff to h2, h1's deposed attempt 1 can still issue a command under its original
    # tenure.
    "handoffOlderAttemptCommandsAfterTransfer": (r_takeover("h2", 2) + ['nameStandby("h1")'] + r_takeover("h1", 3)
                                                 + ['nameStandby("h2")', "planDrain(3)", "transferStart(3)", "decideAny",
                                                    "command(1)"],
                                                 'commands.exists(c => c._1 == 1) and procs.get(3).phase == "transferring" '
                                                 'and handoffs.exists(h => h.by == 3) and rec.owner == "h2" and rec.e == 4',
                                                 [constant("EMAX", 3, 5)]),
    # h2 pauses after its CAS and Report #1, h1 regains the record through its restart and transfers it to h3, and
    # h2's stale preempt of h1's key then takes the reservation while the record names h3's transfer tenure.
    "handoffStalePreemptAfterTransfer": (STALE_TAKEOVER + ["planDrain(4)", 'nameStandby("h3")', "transferStart(4)",
                                                           "decideAny", "takeoverPreempt(2)"],
                                         'holder == "h2" and rec.owner == "h3" and rec.e == 5 and handoffs.size() == 1',
                                         [constant("EMAX", 3, 6)]),
    # The same stale preempt lands after the target's own bump: h2 takes the reservation while the record names
    # h3's bumped tenure.
    "handoffStalePreemptAfterTargetBump": (STALE_TAKEOVER + ["planDrain(4)", 'nameStandby("h3")', "transferStart(4)",
                                                             "decideAny", 'restartRecords("h3")', "restartReady(5)",
                                                             "restartReport1(5)", "restartBump(5)", "decideAny",
                                                             "reply(5)", "takeoverPreempt(2)"],
                                           'holder == "h2" and rec.owner == "h3" and rec.e == 6 and handoffs.size() == 1 '
                                           'and procs.get(5).phase == "bumped" and activations.contains((1, 5, 5))',
                                           [constant("EMAX", 3, 6), constant("REQUESTS", 4, 5)]),
    # At the attempt before the last the drained owner has no transfer: of the two withdrawals the recipe's last
    # step offers, the planned restart alone is enabled, and the record keeps its owner and standby.
    "handoffLastAttemptRestarts": (LAST_ATTEMPT + ["any { transferStart(2), planRestart(2) }"],
                                   'ev.act == "planRestart" and transfers == Set() and rec.owner == "h1" '
                                   'and rec.standby == "h2" and rec.e == 2 and procs.get(2).phase == "withdrawn"', []),
    # After h1 transfers the record to h2, h2's paused takeover preempts h1's key. At preemption, the record still
    # names h2's transfer tenure; h2's restart has yet to bump `E`.
    "handoffStalePreemptByTarget": (STALE_TAKEOVER + ["planDrain(4)", 'nameStandby("h2")', "transferStart(4)",
                                                      "decideAny", "takeoverPreempt(2)"],
                                    'holder == "h2" and rec.owner == "h2" and rec.e == 5 and handoffs.size() == 1 '
                                    'and not(activations.exists(a => a._2 == 4))', [constant("EMAX", 3, 6)]),
    # The target's attach ends between the outgoing owner's issue of the transfer and its commit: the record names
    # h2 owner at the transfer's tenure with h2's entry ended. Of the two steps the recipe's last step offers, h2's
    # restart and the designation of h3, the designation alone is enabled, so h2 starts no process: it issues no
    # device command and reaches no FB, h1's pair keeps the reservation and the volume stays unretired.
    "handoffTargetAttachEndsBeforeCommit": (TARGET_ENDED + ['any { restartRecords("h2"), nameStandby("h3") }'],
                                            'ev.act == "nameStandby" and rec.owner == "h2" and rec.e == 2 '
                                            'and rec.standby == "h3" and handoffs.size() == 1 '
                                            'and procs.get(1).phase == "transferred" and procs.keys() == Set(1) '
                                            'and rc.attaches.get(2).state == "ended" and rc.attaches.get(2).pair '
                                            'and fb.keys() == Set(1) and fencing == Set(1) and preempts == Set() '
                                            'and holding and holder == "h1" and not(retired.contains("v1"))', []),
    # After that transfer h3, named over h2's transfer tenure, takes over, preempts h1's key through the transfer's
    # lineage row and reaches FB: the shard serves again through another standby's takeover, with no process of h2.
    "handoffEndedTargetFreshHostRecovers": (TARGET_ENDED + ['nameStandby("h3")'] + r_takeover("h3", 2),
                                            'fb.keys() == Set(1, 2) and procs.keys() == Set(1, 2) '
                                            'and procs.get(2).host == "h3" and holder == "h3" '
                                            'and preempts == Set(("h3", "h1", true)) and rec.owner == "h3" '
                                            'and rec.e == 3 and rec.g == 1 and rec.active == "v1" '
                                            'and rc.attaches.get(2).state == "ended" and not(retired.contains("v1"))', []),
}
# `ON_READ` lets h2's restart pass `restartReread` under the transfer tenure, preempt, and take Report #2 before
# advancing `E`.
ON_READ = ("val named = rec.g == q.g and rec.owner == q.host and rec.e == q.n + 1 and liveKey(q.key)",
           "val named = rec.g == q.g and rec.owner == q.host and rec.e == q.n and liveKey(q.key)")
TARGET_ON_READ = TRANSFERRED + ['restartRecords("h2")', "restartReady(2)", "restartReport1(2)", "restartRegister(2)",
                                "restartReread(2)", "restartLineagePreempt(2)", "restartReport2(2)"]
TRANSFER_APPLIED = 'else if (r.kind == "transfer") { ...s, owner: r.to, e: r.e + 1, standby: "" }'
# Each handoff mutant: the invariant it breaks, its recipe and the replacements of the model's text.
HANDOFF_MUTANTS = {
    # The transfer keeps E, so the target's tenure shares the outgoing owner's attempt counter.
    "transfer-keeps-e": ("TransferNamesStandby", ISSUED + ["decideAny"],
                         [('else if (r.kind == "transfer") { ...s, owner: r.to, e: r.e + 1, standby: "" }',
                           'else if (r.kind == "transfer") { ...s, owner: r.to, e: r.e, standby: "" }')]),
    # The transfer's condition omits the standby, so a transfer issued before the designation moved names a host
    # the record no longer names.
    "transfer-ignores-standby": ("TransferNamesStandby", ISSUED + ['nameStandby("h3")', "decideAny"],
                                 [("pure def transferHolds(r: Req, s: Shard): bool = s.standby == r.to and bumpHolds(r, s)",
                                   "pure def transferHolds(r: Req, s: Shard): bool = bumpHolds(r, s)")]),
    # The acknowledged transfer activates the outgoing attempt at the next E, a session no bump of its own made.
    "transfer-mints-session": ("TransferNamesStandby", TRANSFERRED,
                               [('"transferred" else "transferRefused" }),\n      activations\' = activations,',
                                 '"transferred" else "transferRefused" }),\n'
                                 "      activations' = if (decided.get(p)) activations.union(Set((q.g, q.n + 1, p))) else activations,")]),
    # The withdrawn owner commands while its transfer is in flight.
    "emit-after-transfer": ("NoEmissionAfterTransfer", ISSUED + ["command(1)"],
                            [('fb.keys().contains(p), q.phase == "active", tick("command", p),',
                              'fb.keys().contains(p), Set("active", "transferring").contains(q.phase), tick("command", p),')]),
    # A lost transfer reply resumes the withdrawn owner in place, and it commands under the transferred tenure.
    "unknown-transfer-resumes": ("NoEmissionAfterTransfer", ISSUED + ["transferTimeout(1)", "planResume(1)", "command(1)"],
                                 [('val resumable = q.phase == "draining"',
                                   'val resumable = Set("draining", "transferUnknown").contains(q.phase)')]),
    # The outgoing owner releases its registration at its withdrawal, so nobody holds once the transfer commits.
    "release-by-predecessor": ("TransferRetainsVolume", ISSUED + ["decideAny"],
                               [("      handoffs' = handoffs, unchangedRestart, listed' = listed,",
                                 "      handoffs' = handoffs, holding' = false, holder' = \"\", preempts' = preempts, held' = held,\n"
                                 "      queued' = queued, landed' = landed, fb' = fb, recordsRead' = recordsRead, deviceActs' = deviceActs,\n"
                                 "      fencing' = fencing, writes' = writes, listed' = listed,")]),
    # The transfer's condition omits E, so a transfer issued before the outgoing owner's restart bumped commits over
    # that bump and leaves E where the bump put it.
    "transfer-ignores-e": ("TransferNamesStandby", UNKNOWN_UNCOMMITTED[:UNKNOWN_UNCOMMITTED.index("decideOf(1)") + 1],
                           [("pure def transferHolds(r: Req, s: Shard): bool = s.standby == r.to and bumpHolds(r, s)",
                             "pure def transferHolds(r: Req, s: Shard): bool = s.standby == r.to and r.g == s.g "
                             "and r.active == s.active and r.owner == s.owner")]),
    # The transfer issues with no standby named: h2, serving past its arm's FB after the first transfer cleared the
    # standby, transfers the record to nobody.
    "transfer-to-no-standby": ("TransferNamesStandby", HANDOFF_FB + ["planDrain(2)", "transferStart(2)", "decideAny"],
                               [constant("EMAX", 3, 5), ('q.n + 1 == rec.e, rec.e + 1 < EMAX, rec.standby != "", not(',
                                                         'q.n + 1 == rec.e, rec.e + 1 < EMAX, not(')]),
    # The transfer names the target owner and h3 standby in the same write.
    "transfer-names-new-standby": ("TransferNamesStandby", ISSUED + ["decideAny"],
                                   [('else if (r.kind == "transfer") { ...s, owner: r.to, e: r.e + 1, standby: "" }',
                                     'else if (r.kind == "transfer") { ...s, owner: r.to, e: r.e + 1, standby: "h3" }')]),
    # The target's Report #1 turns the outgoing owner's recorded pair into the retirement request on the planned path.
    "handoff-target-retires-recorded-holder": ("TransferRetainsVolume",
                                               TRANSFERRED + ['restartRecords("h2")', "restartReady(2)",
                                                              "restartReport1(2)", "restartRetire(2)"],
                                               [RECORDED_HOLDER_RETIRES]),
    # The transfer raises E and clears the standby while the record keeps the outgoing owner.
    "transfer-keeps-owner": ("TransferNamesStandby", ISSUED + ["decideAny"],
                             [(TRANSFER_APPLIED, 'else if (r.kind == "transfer") { ...s, e: r.e + 1, standby: "" }')]),
    # A committed transfer joins no lineage, so h3's takeover over the target's transfer tenure preempts the
    # outgoing owner's key with no tenure of that key succeeded.
    "transfer-leaves-no-lineage": ("NoPreemptOfForeignKey", TRANSFERRED + ['nameStandby("h3")'] + r_takeover("h3", 2)[:-1],
                                   [('else if (ok and r.kind == "transfer") lineage.union(Set((r.to, r.owner, rec.standby, '
                                     'r.id, r.e, attachKey(r.to), procs.get(r.id).key)))',
                                     'else if (ok and r.kind == "transfer") lineage')]),
    # A draining attempt whose tenure h2's takeover deposed issues the transfer on the record it reads then, h2's
    # tenure with h3 named, and the store commits it.
    "transfer-by-deposed-owner": ("TransferByOwnTenure",
                                  ["planDrain(1)", 'takeoverStart("h2")', "decideAny", 'nameStandby("h3")',
                                   "transferStart(1)", "decideAny"],
                                  [EMAX_FOUR, ("fb.keys().contains(p), q.host == rec.owner, q.g == rec.g,\n"
                                               "      q.n + 1 == rec.e, rec.e + 1 < EMAX,",
                                               "fb.keys().contains(p), rec.e + 1 < EMAX,")]),
    # The transfer issues with one attempt left, so its commit leaves the target no bump.
    "transfer-spends-last-attempt": ("TransferLeavesBump", LAST_ATTEMPT + ["transferStart(2)", "decideAny"],
                                     [('q.n + 1 == rec.e, rec.e + 1 < EMAX, rec.standby != ""',
                                       'q.n + 1 == rec.e, rec.e < EMAX, rec.standby != ""')]),
    # The reply arrives while the store still holds the transfer undecided and reads the attempt's earlier decision,
    # its bump's commit, as the transfer's.
    "transfer-reply-before-decision": ("TransferAckMatchesCommit", ISSUED + ["transferReply(1)"],
                                       [('q.phase == "transferring", not(pending.exists(r => r.id == p)),\n'
                                         '      decided.keys().contains(p), tick("transferReply", p),',
                                         'q.phase == "transferring",\n'
                                         '      decided.keys().contains(p), tick("transferReply", p),')]),
    # The target's lineage preempt releases the reservation in place of taking it, so nobody the property names
    # holds at the target's bumped tenure.
    "handoff-target-preempt-releases": ("TransferRetainsVolume", HANDOFF_FB[:-1],
                                        [("holder' = if (issuerRegistered and holder == q.prkey) q.key else holder,\n"
                                          "      preempts' = if (issuerRegistered) preempts.union(Set((q.host, q.prkey, rc.rereads",
                                          "holder' = if (issuerRegistered and holder == q.prkey) \"\" else holder,\n"
                                          "      preempts' = if (issuerRegistered) preempts.union(Set((q.host, q.prkey, rc.rereads")]),
    # The transfer moves the shard to a new generation and volume, as the flip does.
    "transfer-flips": ("TransferRetainsVolume", ISSUED + ["decideAny"],
                       [('else if (r.kind == "transfer") { ...s, owner: r.to, e: r.e + 1, standby: "" }',
                         'else if (r.kind == "transfer") { g: r.g + 1, active: "v3", owner: r.to, e: 0, spare: "", '
                         'spareHost: "", standby: "" }')]),
    # A takeover process bumps beside its CAS, and the transfer issues while the store holds that bump: the store
    # commits the transfer and then refuses the bump, and the reply reads the refusal as the transfer's decision.
    "transfer-over-pending-request": ("TransferAckMatchesCommit",
                                      PENDING_REQUEST + ["transferStart(2)", "decideOf(2)", "decideOf(2)",
                                                         "transferReply(2)"],
                                      [EMAX_FOUR, TAKEOVER_BUMPS,
                                       ('not(pending.exists(r => r.id == p)), tick("transferStart", p),',
                                        'tick("transferStart", p),')]),
    # The target registers and preempts on its role read and Report #1, so its key holds while the record still
    # names the transfer's tenure.
    "handoff-target-preempts-on-read": ("TransferRetainsVolume", TARGET_ON_READ[:-1],
                                        [MUTANTS["target-activates-on-read"][1], ON_READ]),
}
# Each handoff root: its prefix, the turns its search runs past it, and its model replacements. The roots after the
# commit run at EMAX 4, so a takeover can commit over the target's transfer tenure and over its bumped tenure.
HANDOFF_ROOTS = {
    "serving": ([], 9, []),
    "draining": (["planDrain(1)"], 9, []),
    "issued": (ISSUED, 11, []),
    "transferred": (TRANSFERRED, 12, [EMAX_FOUR]),
    "targetBumped": (TRANSFERRED + ['restartRecords("h2")', "restartReady(2)", "restartReport1(2)", "restartBump(2)",
                                    "decideAny", "reply(2)"], 11, [EMAX_FOUR]),
}
# Each handoff reach case: its root and the witness its search reaches past the root's prefix.
HANDOFF_REACHES = (("issued", "witnessHandoffFb"), ("targetBumped", "witnessTakeoverOverTargetBump"),
                   ("issued", "witnessTransferUnknownThenRestart"), ("issued", "witnessTransferRefusedThenRestart"),
                   ("issued", "witnessLaterAttemptCommands"), ("transferred", "witnessTargetCommands"),
                   ("transferred", "witnessArmRereadRefused"), ("targetBumped", "witnessArmReport2Refused"))


def handoff_cases(Case):
    """The handoff schedule's cases. Each root's search must reach its last turn, and each reach case's witness
    must hold after the root's prefix."""
    for root, (prefix, turns, mutations) in HANDOFF_ROOTS.items():
        yield Case(f"tenure-handoff-{root}", invariant="safety", family="tenure", step="prefixed",
                   settings={"BOUND": str(len(prefix) + turns)}, mutations=mutations, depth=len(prefix) + turns + 1,
                   extra=HANDOFF_INIT + prefixed(prefix, "handoffStep"))
    for root, witness in HANDOFF_REACHES:
        prefix, turns, mutations = HANDOFF_ROOTS[root]
        yield Case(f"tenure-handoff-reach-{witness}", invariant="unreached", expected="violation", family="tenure",
                   step="prefixed", settings={"BOUND": str(len(prefix) + turns)}, mutations=mutations,
                   after=len(prefix) + 1,
                   extra=HANDOFF_INIT + prefixed(prefix, "handoffStep") + f"  val unreached = not({witness})\n")
    for name, (recipe, end, mutations) in HANDOFF_RUNS.items():
        yield Case(f"tenure-run-{name}", invariant="runSafety", family="tenure", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=mutations,
                   extra=HANDOFF_INIT + f"  val runSafety = safety and (turn == {len(recipe)} implies ({end}))\n")
        yield Case(f"tenure-run-{name}-reached", invariant="runWitness", expected="violation", family="tenure",
                   recipe=recipe, settings={"BOUND": str(len(recipe))}, mutations=mutations, trace=len(recipe) + 1,
                   extra=HANDOFF_INIT + f"  val runWitness = not(turn == {len(recipe)} and ({end}))\n")
    # With `restartRecords` admitting a host whose own attach ended, the replacement of
    # `reclaim-restart-reads-ended-own-attach`, the same run's last step also starts h2's restart, and the run's end
    # state, which holds no process of h2, fails on that branch.
    recipe, end, _ = HANDOFF_RUNS["handoffTargetAttachEndsBeforeCommit"]
    yield Case("tenure-run-handoffTargetAttachEndsBeforeCommit-skips-own-attach", invariant="targetEnd",
               expected="violation", family="tenure", recipe=recipe, settings={"BOUND": str(len(recipe))},
               mutations=RECLAIM_MUTANTS["reclaim-restart-reads-ended-own-attach"][2], trace=len(recipe) + 1,
               extra=HANDOFF_INIT + f"  val targetEnd = turn == {len(recipe)} implies ({end})\n")
    for name, (prop, recipe, mutations) in HANDOFF_MUTANTS.items():
        yield Case(f"tenure-mutant-{name}", invariant=prop, expected="violation", family="tenure", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=mutations, trace=len(recipe) + 1, extra=HANDOFF_INIT)
    yield Case("tenure-mutant-handoff-target-serves-on-read", invariant="OwnBumpBeforeFB", expected="violation",
               family="tenure", recipe=TARGET_ON_READ, settings={"BOUND": str(len(TARGET_ON_READ))},
               mutations=[MUTANTS["target-activates-on-read"][1], ON_READ,
                          (CONFIRMED, CONFIRMED.replace("rec.e == q.n + 1))\n", "rec.e == q.n))\n"))],
               trace=len(TARGET_ON_READ) + 1,
               extra=HANDOFF_INIT)


def cases(Case):
    yield Case("tenure-typecheck", command="typecheck", family="tenure")
    yield Case("tenure-safety", invariant="safety", family="tenure")
    for name in INVARIANTS:
        yield Case(f"tenure-{name}", invariant=name, family="tenure", **(RESTART_STEP if name in RESTART_ONLY else {}))
    for name in TAKEOVER_INVARIANTS:
        # `ArmFbConfirmed` checks at the arm root: the search at `BOUND = 12` reaches no arm FB.
        if name != "ArmFbConfirmed":
            yield Case(f"tenure-takeover-{name}", invariant=name, family="tenure", **TAKEOVER_STEP)
    for witness in WITNESSES:
        yield Case(f"tenure-reach-{witness}", invariant="unreached", expected="violation", family="tenure",
                   extra=f"  val unreached = not({witness})\n", **schedule(witness))
    for name, (recipe, end) in RUNS.items():
        yield Case(f"tenure-run-{name}", invariant="runSafety", family="tenure", recipe=recipe,
                   settings={"BOUND": str(len(recipe))},
                   mutations=RUN_MUTATIONS.get(name, []),
                   extra=f'  val runSafety = safety and (turn == {len(recipe)} implies {end})\n')
    # The reset schedule with a self Preempt-and-Abort that unregisters its caller and the aborted write landing
    # after Report #2: with Report #2 dropped, the restart serves and the landing follows its FB.
    recipe = mid_tenure("reset", unregisters=True)
    yield Case("tenure-run-midTenureReset-drop-report-2", invariant="NoPredecessorEffectAfterFB", family="tenure",
               recipe=recipe, expected="violation", settings={"BOUND": str(len(recipe))},
               mutations=[MUTANTS["restart-drops-report-2"][1]], trace=len(recipe) + 1)
    # The restart-first race with a takeover CAS that ignores E: both requests commit at one E and both replies
    # activate the same (g, n).
    recipe = RUNS["takeoverLosesToRestart"][0]
    yield Case("tenure-run-takeoverLosesToRestart-ignores-e", invariant="NoEpochReuse", family="tenure",
               recipe=recipe, expected="violation", settings={"BOUND": str(len(recipe))},
               mutations=[TAKEOVER_IGNORES_E], trace=recipe.index("reply(3)") + 2)
    # The device-failure rerun with the write landing after the rerun's FB: with the rerun's ready wait skipping the
    # drain after a hold, the ended incarnation's write lands after FB.
    recipe = [action for action in DEVICE_FAIL_RERUN if action != "land"] + ["land"]
    yield Case("tenure-run-deviceFailThenRerunReachesFb-skips-drain", invariant="NoPredecessorEffectAfterFB",
               family="tenure", recipe=recipe, expected="violation", settings={"BOUND": str(len(recipe))},
               mutations=[("val skipsDrainAfterHold = false", "val skipsDrainAfterHold = true")],
               trace=len(recipe) + 1)
    # The post-bump hold of postBumpFailThenRerunReachesFb, then a retirement at the bumped target: with restartRetire
    # admitting a device-failure refusal, the failed self preempt retires the volume.
    recipe = RUNS["postBumpFailThenRerunReachesFb"][0]
    recipe = recipe[:recipe.index("restartDeviceFail(2)") + 1] + ["restartRetire(2)"]
    for prop in ("DeviceFailureRetainsVolume", "RestartRetiresOnlyOnObservation"):
        yield Case(f"tenure-run-postBumpFailRetires-{prop}", invariant=prop, family="tenure", recipe=recipe,
                   expected="violation", settings={"BOUND": str(len(recipe))},
                   mutations=[DEVICE_FAILURE_RETIRES, DEVICE_FAILURE_TARGET], trace=len(recipe) + 1)
    # The paused-successor chain with Report #1 skipping the tenure check: B captures the key of C, whose later tenure
    # no takeover of B succeeded, and B's preempt names it.
    recipe = PAUSED_SUCCESSOR + ["takeoverPreempt(2)"]
    yield Case("tenure-run-pausedSuccessorRefusesLaterHolder-skips-tenure-check", invariant="NoPreemptOfForeignKey",
               family="tenure", recipe=recipe, expected="violation", settings={"BOUND": str(len(recipe))},
               mutations=[(TENURE_CHECK, "val current = true")],
               trace=len(recipe) + 1)
    # The paused-successor chain revisiting A, with Report #1 skipping the tenure check: B captures C's key, A takes
    # the record back over C's tenure at a higher `E`, and B's preempt of C's key carries no evidence only because
    # deposedBy follows a host's takeovers at a lower `E` than the one that reached it.
    recipe = PAUSED_SUCCESSOR + ['nameStandby("h1")', 'takeoverStart("h1")', "decideAny", "takeoverPreempt(2)"]
    yield Case("tenure-run-revisitLaterHolder-skips-tenure-check", invariant="NoPreemptOfForeignKey", family="tenure",
               recipe=recipe, expected="violation", settings={"BOUND": str(len(recipe))},
               mutations=[EMAX_FOUR, (TENURE_CHECK, "val current = true")],
               trace=len(recipe) + 1)
    # The same run with the `E` ordering clause removed from deposedBy passes, so the control above fails only through
    # that clause.
    yield Case("tenure-run-revisitLaterHolder-skips-tenure-check-without-e-order", invariant="NoPreemptOfForeignKey",
               family="tenure", recipe=recipe, settings={"BOUND": str(len(recipe))},
               mutations=[EMAX_FOUR, ("b._6 == r._1 and b._5 < r._2", "b._6 == r._1"), (TENURE_CHECK, "val current = true")])
    # The three-hop chain with the closure cut to one level: the third successor's preempt of A carries no evidence.
    recipe = RUNS["threeHopFreshHostRecovers"][0][:-1]
    yield Case("tenure-run-threeHopFreshHostRecovers-one-level", invariant="NoPreemptOfForeignKey", family="tenure",
               recipe=recipe, expected="violation", settings={"BOUND": str(len(recipe))},
               mutations=[EMAX_FOUR, ("1.to(REQUESTS).fold(", "1.to(0).fold(")], trace=len(recipe) + 1)
    # The closure cut to one round reaches two hops: the three-hop preempt carries no evidence, while the two-hop run
    # still holds, so the three-hop run needs the closure beyond the definition with one earlier takeover.
    yield Case("tenure-run-threeHopFreshHostRecovers-one-round", invariant="NoPreemptOfForeignKey", family="tenure",
               recipe=recipe, expected="violation", settings={"BOUND": str(len(recipe))},
               mutations=[EMAX_FOUR, ("1.to(REQUESTS).fold(", "1.to(1).fold(")], trace=len(recipe) + 1)
    recipe = RUNS["interruptedTakeoverFreshHostRecovers"][0]
    yield Case("tenure-run-interruptedTakeoverFreshHostRecovers-one-round", invariant="runSafety", family="tenure",
               recipe=recipe, settings={"BOUND": str(len(recipe))},
               mutations=[("1.to(REQUESTS).fold(", "1.to(1).fold(")],
               extra=f'  val runSafety = safety and (turn == {len(recipe)} implies '
                     f'{RUNS["interruptedTakeoverFreshHostRecovers"][1]})\n')
    # After the two-hop superseded-tenure preempt, with the middle successor live and EMAX 4, the free takeover
    # schedule, restarts included, runs five turns under every takeover invariant.
    prefix = FRESH_H1 + ['takeoverStart("h2")', "decideAny", "reply(2)"] + CHAIN + ["takeoverPreempt(3)"]
    picks = "".join(f"    all {{ turn == {at}, {action} }},\n" for at, action in enumerate(prefix))
    extra = ("  action prefix = any {\n" + picks + "  }\n"
             f"  action prefixed = any {{ prefix, all {{ turn >= {len(prefix)}, takeoverStep }} }}\n"
             "  val takeoverSafety = " + " and ".join(TAKEOVER_INVARIANTS) + "\n")
    yield Case("tenure-takeover-afterSupersededPreempt", invariant="takeoverSafety", family="tenure", step="prefixed",
               settings={"BOUND": str(len(prefix) + 5)}, mutations=[EMAX_FOUR], extra=extra)
    # The same prefixed search reaches its last turn with the superseded preempt issued, so a prefix action the model
    # stops admitting ends the search early and fails this case.
    yield Case("tenure-takeover-afterSupersededPreempt-reached", invariant="unreached", expected="violation",
               family="tenure", step="prefixed", settings={"BOUND": str(len(prefix) + 5)}, mutations=[EMAX_FOUR],
               extra=extra + f'  val unreached = not(turn == {len(prefix) + 5} and preempts.contains(("h3", "h1", true)))\n',
               trace=len(prefix) + 6)
    for name, (mutation, trace) in REUSED_KEY_CONTROLS.items():
        yield Case(f"tenure-run-{name}", invariant="StalePreemptRetainsVolume", family="tenure", recipe=REUSED_KEY,
                   expected="violation", settings={"BOUND": str(len(REUSED_KEY))},
                   mutations=[*RUN_MUTATIONS["reusedAttachmentKey"], mutation],
                   trace=trace)
    # The lineage arm's controls, each violating its property at its recipe's last step. A reread that admits a
    # moved record lets the arm preempt A's key after h3's takeover deposed h2's bumped tenure, a Report #1 that
    # admits an unrecorded holder lets the arm preempt `UNRECORDED`, a Report #1 that captures h3's recorded pair in
    # place of the holder it shows lets the arm preempt h3, and a Register and reread on Report #1 alone let the arm
    # preempt before its own bump; none of those keys carries the bumped form's evidence. A failed reread-phase
    # preempt or Report #2 that serves reaches the arm's FB with no preempt or no confirming Report #2.
    named = "val named = rec.g == q.g and rec.owner == q.host and rec.e == q.n + 1 and liveKey(q.key)"
    bumped = UNKNOWN_RESTART + ["restartBump(3)", "decideAny", "reply(3)", "restartRegister(3)", "restartReread(3)"]
    serves = ("val deviceFailureServes = false", "val deviceFailureServes = true")
    # The mutation records the lineage preempt under the issuer's own key (`q.key`). Its control tests whether
    # `ArmFbConfirmed` refuses an arm FB whose recorded preempt names a key other than the captured one.
    own_key = ("Set((q.host, q.prkey, rc.rereads.contains((p, true))", "Set((q.host, q.key, rc.rereads.contains((p, true))")
    for name, prop, recipe, mutations in (
            ("armRereadRefusesMovedRecord-skips-reread", "NoPreemptOfForeignKey", ARM_MOVED + ["restartLineagePreempt(3)"],
             [SKIPS_REREAD]),
            ("armAdmitsUnrecordedHolder", "NoPreemptOfForeignKey", UNRECORDED_ARM,
             [("val lineageHolder = holding and holder != q.key and paired(holder) and keyHost(holder) != q.host",
               "val lineageHolder = holding and holder != q.key and keyHost(holder) != q.host")]),
            ("armPreemptsUnshownKey", "NoPreemptOfForeignKey", bumped + ["restartLineagePreempt(3)"],
             [('deviceStep(p, "ready", dest, if (lineageHolder) holder else "", false)',
               'deviceStep(p, "ready", dest, if (lineageHolder) "h3" else "", false)')]),
            ("armPreemptsBeforeBump", "NoPreemptOfForeignKey",
             UNKNOWN_RESTART + ["restartRegister(3)", "restartReread(3)", "restartLineagePreempt(3)"],
             [MUTANTS["target-activates-on-read"][1], (named, named.replace("rec.e == q.n + 1", "rec.e == q.n"))]),
            ("armFailedPreemptNamesUnshownKey", "NoPreemptOfForeignKey", bumped + ["restartDeviceFail(3)"],
             [('deviceStep(p, q.phase, if (deviceFailureServes) "active" else "refusedDevice", q.prkey,',
               'deviceStep(p, q.phase, if (deviceFailureServes) "active" else "refusedDevice", '
               'if (q.phase == "reread") "h3" else q.prkey,')]),
            ("armServesWithoutPreempt", "ArmFbConfirmed", bumped + ["restartDeviceFail(3)"], [serves]),
            ("armServesWithoutReport2", "ArmFbConfirmed", bumped + ["restartLineagePreempt(3)", "restartDeviceFail(3)"],
             [serves]),
            ("armServesWithoutCapturedKeyPreempt", "ArmFbConfirmed", UNKNOWN_RESTART + arm(3), [own_key])):
        yield Case(f"tenure-run-{name}", invariant=prop, family="tenure", recipe=recipe,
                   expected="violation", settings={"BOUND": str(len(recipe))}, mutations=[EMAX_FOUR, *mutations],
                   trace=len(recipe) + 1)
    # A takeover whose Report #1 left it `reported` takes the restart's bump: a second store write beside its CAS.
    recipe = FRESH_H1 + r_cas("h2", 2) + ["takeoverReport1(2)", "restartBump(2)"]
    yield Case("tenure-run-takeoverBumpsAfterReport1", invariant="TakeoverIssuesNoBump", family="tenure", recipe=recipe,
               expected="violation", settings={"BOUND": str(len(recipe))},
               mutations=[('procs.keys().contains(p), q.restart, Set("reported", "reportedHolder")',
                           'procs.keys().contains(p), Set("reported", "reportedHolder")')],
               trace=len(recipe) + 1)
    # Report #2 without the arm's tenure check: the paused preempt of armPausedPreemptRefusesAtReport2 reaches FB while
    # the record names h3's tenure, an arm FB whose Report #2 read another tenure than the one its bump activated.
    yield Case("tenure-run-armPausedPreemptRefusesAtReport2-skips-tenure-check", invariant="ArmFbConfirmed",
               family="tenure", recipe=ARM_PAUSED, expected="violation", settings={"BOUND": str(len(ARM_PAUSED))},
               mutations=[*RUN_MUTATIONS["armPausedPreemptRefusesAtReport2"], ARM_REPORT2_SKIPS_TENURE],
               trace=len(ARM_PAUSED) + 1)
    yield from arm_root_cases(Case)
    # The rerun after the arm's refused bump, as a recipe: the free takeover search at its bound ends before it.
    recipe = RUNS["recordedRefusalRerun"][0]
    yield Case("tenure-reach-witnessRerunAfterRecordedRefusal", invariant="unreached", expected="violation",
               family="tenure", recipe=recipe, settings={"BOUND": str(len(recipe))}, mutations=[EMAX_FOUR],
               extra="  val unreached = not(witnessRerunAfterRecordedRefusal)\n",
               trace=recipe.index('restartRecords("h2")', recipe.index("timeout(3)")) + 2)
    for name in RESTART_ALSO:
        yield Case(f"tenure-restart-{name}", invariant=name, family="tenure", **RESTART_STEP)
    for name, (prop, *mutations) in MUTANTS.items():
        yield Case(f"tenure-mutant-{name}", invariant=prop, expected="violation", family="tenure", mutations=mutations,
                   **schedule(name))
    yield from reclaim_cases(Case)
    yield from handoff_cases(Case)


# A module-level line of the model opens an item with one of these keywords, after two spaces of indentation.
ITEM = re.compile(r"  (pure val|pure def|action|def|val|type|var|const) (\w+)")
# The items a case's instance drops when nothing the case checks names them. Constants, types and variables stay.
PRUNABLE = ("action", "def", "val", "pure def")
WORD = re.compile(r"[A-Za-z_]\w*")


def entries(case):
    """The names case `case` enters the model by: the words of its instance text and its recipe, its invariant and
    its step, `init` unless its instance text defines `caseInit`, and the free scheduler `step` for a search that
    names no step."""
    names = set(WORD.findall("\n".join([case.extra, *case.recipe, case.invariant or "", case.step or ""])))
    if "action caseInit" not in case.extra:
        names.add("init")
    if not case.recipe and not case.step:
        names.add("step")
    return names


def items(text, case_name):
    """The model's text as its lines before the module's first item, its module-level items in order, each a
    `(kind, name, lines)` triple that starts at its first doc-comment line and ends before the next item, and the
    line that closes the module. A module-level line that is neither a doc comment, an item's opening line nor a
    closing brace raises ValueError, as does a doc comment that no item follows."""
    lines = text.split("\n")
    last = max(at for at, line in enumerate(lines) if line == "}")
    first = next(at for at, line in enumerate(lines) if line.startswith("module ")) + 1
    found, block, opened = [], [], None
    for line in lines[first:last]:
        level = line.startswith("  ") and not line.startswith("   ")
        doc = level and line.startswith("  ///")
        opening = ITEM.match(line) if level and not doc else None
        if level and not doc and not opening and line != "  }":
            raise ValueError(f"{case_name}: the model holds a module-level line that opens no item: {line!r}")
        if (doc or opening) and opened and (opening or not block[-1].startswith("  ///")):
            found.append((*opened, block))
            block, opened = [], None
        block.append(line)
        if opening:
            opened = (opening[1], opening[2])
    if not opened:
        raise ValueError(f"{case_name}: the model ends in a doc comment that no item follows")
    found.append((*opened, block))
    return lines[:first], found, lines[last:]


def prune(text, keep, case_name):
    """The model text without the actions, definitions and values that nothing in `keep` reaches: an item is reached
    when `keep` names it or a reached item's code, or a constant's, type's or variable's, names it. Every action a
    kept item names is part of the instance Apalache translates for TLC, whose size its server bounds, so an instance
    holds only what its case checks. A prunable name defined twice raises ValueError."""
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
    text = (source / "tenure.qnt").read_text()
    for old, new in case.mutations:
        if text.count(old) != 1:
            raise ValueError(f"{case.name}: mutation target is not unique")
        text = text.replace(old, new)
    if case.command != "typecheck":
        text = prune(text, entries(case), case.name)
    bound = case.settings.get("BOUND", CONSTANTS["BOUND"])
    extra = case.extra
    if case.recipe:
        picks = {}
        for at, action in enumerate(case.recipe):
            picks.setdefault(action, []).append(str(at))
        extra += "  action recipe = any {\n" + "".join(
            f'    all {{ Set({", ".join(turns)}).contains(turn), {action} }},\n' for action, turns in picks.items()) + "  }\n"
    return {"tenure.qnt": text,
            "case.qnt": f'module coreCase {{\n  import tenure(BOUND = {bound}).* from "./tenure"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "tenure.qnt"]
    if case.recipe:
        step = ["--step", "recipe"]
    elif case.step:
        step = ["--step", case.step]
    else:
        step = []
    init = ["--init", "caseInit"] if "action caseInit" in case.extra else []
    return [quint, "verify", "case.qnt", "--main", "coreCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + init + step
