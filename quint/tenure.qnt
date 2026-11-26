/// One shard record in an asynchronous store: owner attempts bump the attempt counter `E`, reconcilers flip the
/// shard to its spare, and the store applies each conditional request later, once, or reports it unknown.
/// An attempt activates only on the acknowledged success of its own bump. The control plane lists every attachment
/// of each volume; a foreign attachment, stale or unrecorded, may attach any volume and write it. The owner's poll
/// retires a volume whose listing names an attachment outside its admitted set, the standby's spare check one whose
/// listing names another attachment, and the fresh path of an
/// attempt at `E = 0` proceeds only on a listing of exactly its own attachment. Every check reads the listing at
/// one instant and retires in the step that reads it; the reconciler's admission of a retirement request is
/// outside the model. The owner's poll keeps serving on a listing of its admitted set that holds its own attachment:
/// the owner and each standby whose attach event the volume record holds and the poll's caller binds. The reconciler
/// attaches a standby in three steps (`standbyRecord`, `standbyBind`, `standbyAttach`): it records the attach event,
/// the caller binds the host by reading that event, and the attach request follows; `RecordedAttachRetiresNothing`
/// checks that no poll retires a volume over such an attach. This is the order of the parent specification's
/// amendment A3, under which the recorded entry is what a caller binds; the poll judges the listing alone, and the
/// volume record's attach-event check is outside the model. A poll that also requires the caller to bind every
/// recorded attach event retires between the record and the binding, which the `poll-judges-recorded-events` control
/// shows. A caller binds by reading the event and no action removes one, so every bound host has its recorded event
/// in every reached state; the `admitted-set-ignores-events` control binds a host without it.
/// The model takes two premises of the fresh check as given: a foreign attachment stays listed, which the
/// access-control statement provides only for the detaches it binds, and every listed record is visible to the
/// check. `FreshIsEmpty` holds at the instant of the fresh check; a foreign attach and write between the
/// check and the attempt's activation is outside it. `FOREIGN_DETACH` is the premise control: with it set, a
/// foreign attachment may detach, and `FreshIsEmpty` fails.
/// A reservation key belongs to one attach of a host to the volume (D16): the record's attach entries (`rc.attaches`)
/// each carry their own key, and the first three are the attaches of `HOSTS`, whose keys are the host names.
/// `preemptAdmitted` is the abstract issuance rule of a Preempt: the owner the shard record names, once `E > 0`,
/// naming its own attach's key or the key of an attach whose tenure its committed takeover succeeded, directly or
/// through committed takeover writes: the predecessor that takeover deposed, or, at any depth, an attach that an
/// earlier committed takeover by an attach in that chain deposed, the chain successors that stopped before their
/// preempt leave; past its FB, an ended key that does not hold, which a Preempt with no abort removes (the ended
/// form); or, after its own acknowledged bump at the record's tenure, the key of a recorded pair of another host (the
/// bumped form, amendment A1). The chain is the transitive closure of `lineage` over attach keys, ordered by the `E`
/// each takeover consumed, so its depth is bounded only by the committed takeovers `EMAX` admits, not by the rule.
/// `NoPreemptOfForeignKey` checks that rule's definition in every reachable state, and checks the issued preempts: a
/// self preempt names its issuer's own key, a takeover preempt names a host whose tenure the issuer's own
/// acknowledged takeover succeeded, and a lineage preempt names the recorded pair of another host that the issuer's
/// Report #1 showed holding, after the issuer's own acknowledged bump and a reread that named the tenure that bump
/// activated, whether the device took the takeover or lineage preempt, refused it for a lost registration or failed
/// it.
/// An active attempt that observes a loss, a shard record with another `(g, owner, E)`, a page fence above its
/// session, a failed write showing a later tenure, a result below its watermark, a retirement trigger or a planned
/// change, withdraws in the step that observes it, and a withdrawn attempt takes no command action;
/// `DetectedLossWithdraws` checks that no attempt that observed a loss takes a later command action.
/// A same-host restart (`restart: true` processes) reaches its fencing boundary (FB) only through the sequence: read
/// the records (`restartRecords`, which starts only while the host's newest attach is live with its pair recorded,
/// the enrolled own pair of Rust's step 2), wait for controller ready (`restartReady`, blocked while a write of the ended
/// incarnation is card-held), Report #1 (`restartReport1`, refusing unless the own pair holds or a recorded pair of
/// another host holds), the `E` bump conditioned on the records read (`restartBump`, then `decide` and `reply`), the
/// self Preempt-and-Abort (`restartPreempt`, which aborts the ended incarnation's outstanding writes, or returns
/// success while unregistering its caller), and Report #2 (`restartReport2`, refusing unless the own pair still
/// holds). When Report #1 shows a recorded pair of another host holding, the restart takes the lineage arm (D20) in
/// place of the self preempt: after its acknowledged bump it registers (`restartRegister`), rereads the shard record,
/// which must still name the bumped tenure (`restartReread`), preempts the holder's key (`restartLineagePreempt`),
/// which may land after the record moved, and takes Report #2, which also requires the record to name the bumped
/// tenure. A handoff target, a successor whose takeover committed with an unknown reply or that stopped before its
/// preempt, and a tenure withdrawn under a recorded holder while the record names it owner take this arm.
/// `OwnBumpBeforePreempt`: every Register and preempt, issued with success or failure, follows the issuing attempt's
/// own acknowledged write. `ArmFbConfirmed`: every FB of the arm follows the host's admitted preempt of the key
/// Report #1 captured and the attempt's own confirming Report #2. A
/// mid-tenure controller event (`midTenure`: a reset, an Abort or a queue delete) ends the incarnation with one write
/// card-held, and a reset also with one outstanding. `RecordsBeforeDevice`: every restart or takeover that issued a
/// device command read records that passed its step-1 checks, checked under the restart and the takeover schedules. `BumpAtOwnGeneration`: every committed bump, a restart's
/// included, commits at the generation its attempt read. `NoPredecessorEffectAfterFB`: no write of an ended
/// incarnation lands after the FB of the restart or fresh attempt that holds the record's current tenure; a stale attempt that lands after FB,
/// which the read check turns into a miss, is outside the model. A takeover's FB drains no predecessor: a write of
/// the deposed owner may land after it, and the recovery order and the preservation mechanism carry that residual.
/// The model's card-held and outstanding writes carry no host, so `restartReady` waits on every host's writes and the
/// lineage arm's FB over another host's holder is judged through a drain of that host's writes that Rust's
/// restart, which waits on its own controller, does not perform.
/// The fresh path of an attempt at `E = 0` reaches its FB at `freshReport`, which stands for the host ID, Register,
/// type-2 Acquire and fresh Report after its acknowledged bump, and writes the medium at `freshWrite`, the activation
/// record first. `NoWriteBeforeFB`: every medium write of an attempt follows its FB. `OwnBumpBeforeFB`: every attempt
/// that reached FB activated through its own committed bump. `RecordsBeforeDevice` covers the
/// fresh path's device commands through the record and listing checks of its `start`.
/// A same-volume takeover (`takeover: true` processes) is the recorded standby's acquisition of the retained active
/// volume at its generation. The shard record names at most one standby (`rec.standby`), which `nameStandby`, the
/// enrollment write of a function outside the cache hosts, sets. `takeoverStart` reads the records; a host the record
/// does not name refuses with no request, and the standby submits the takeover CAS, the model's field-conditioned
/// form of the exact-version CAS, conditioned on `(g, active, owner, E)` and the standby and writing the successor as
/// owner with `E + 1` and no standby; the model has no record versions, so a designation changed away and back and a
/// checkpoint-only write are Rust test boundaries. `decide`
/// and `reply` activate `(g, 2n + 2)` only on the acknowledged commit. Every device step follows that reply:
/// `takeoverReport1` admits as holder only a recorded host other than the issuer while the record names the issuer's
/// tenure, the model's single step for Report #1 and the tenure check before the preempt, and captures its key;
/// `takeoverPreempt` names that key whichever owner the record names by then, and `restartReport2` is its Report #2
/// and FB. A successor that stops after its CAS leaves the record naming it with no standby, and the next designated
/// host's takeover preempts the holder that successor left, the fresh-host recovery.
/// `NamedStandbyTakesOver`: every committed takeover's and planned transfer's successor is the standby the record
/// named at the commit.
/// `TakeoverCasBeforeDevice`: every takeover process that issued a device command activated through its own
/// acknowledged CAS. `TakeoverIssuesNoBump`: a takeover's one store write is its CAS, and every bump of `E` is a fresh
/// attempt's or a restart's. `InterruptedTakeoverRetainsVolume`: every committed takeover keeps the generation and the active
/// volume of the record it conditioned on, and that volume is retired only while `UNRECORDED`, a holder outside the
/// recorded set, holds the reservation.
/// DEVICE-FAILURE-HOLD: a restart device step that ends without success (`restartDeviceFail`: the ready wait, the host
/// ID or Report #1 after `records` or `ready`, the self preempt or the arm's Register after `bumped`, the arm's lineage
/// preempt after `reread`, or Report #2 after `preempted`) refuses into `refusedDevice` and retires nothing; a hold
/// from `bumped`, `reread` or `preempted` follows the activation of its acknowledged bump, reaches no FB, and no rerun reuses that activation. A bump without an acknowledged success ends
/// `refused` through `reply` or `timeout`, which retires nothing either. `RestartRetiresOnlyOnObservation`: every
/// restart retirement follows a Report #1 of that restart that showed `UNRECORDED`, as the `shown` ghost records it.
/// `DeviceFailureRetainsVolume`: a restart held
/// on a device failure leaves its volume unretired unless `UNRECORDED` holds. The hold ends by a rerun of the
/// sequence, which reaches FB through its own bump, or by the standby's takeover.
/// The reclaim schedule (`reclaimStep` from `reclaimInit`) carries an attach through its recorded steps (D14): the
/// reconciler records an entry, whose key belongs to that attach alone and which binds the host's instance, and
/// requests the attach, which lands, fails or lands late; the standby enrolls its pair; a designation names any live,
/// enrolled attach (D16); the reconciler ends an entry whose host the shard record names neither owner nor standby;
/// the owner past its FB removes an ended key that does not hold by a Preempt with no abort, whose next Report is its
/// only receipt (D17), and drops the pair after a Report showed the key absent; the reconciler detaches an entry with
/// no pair and marks it gone after clean listings. A standby registers at its takeover (D18). The owner's poll reads
/// the listing, then the record, and admits the instances of the retained entries; an owner whose own entry the record
/// shows ended or gone withdraws at that poll. `EndedAttachNeverRetires`, `EndedGrantsNothing`,
/// `EndedOwnerServesNothing`, `EndedPreemptSparesLiveAttach`, `EndOrder` and `HistoryBound` check the ended attach
/// there.
/// The handoff schedule (`handoffStep` from `reclaimInit`) carries a planned transfer (A2, D19 to D21): the serving
/// owner drains (`planDrain`), stops admission and, before its withdrawal, may resume in place (`planResume`); it then
/// withdraws and either exits for a same-host restart (`planRestart`) or issues, in the same step, the transfer write
/// (`transferStart`), the model's field-conditioned form of the exact-version write, conditioned on its own tenure and
/// the record's standby, that names the standby owner at `E + 1` and no standby; the model has no record versions, so
/// a designation changed away and back before the commit is a Rust test boundary. The write's reply ends the owner
/// (`transferReply`) or is lost (`transferTimeout`); the withdrawn owner never resumes, and its host restarts only
/// while the record still names it owner. The target activates through its own restart's lineage arm. A committed
/// transfer joins `lineage` as an owner-change write, so a takeover over the target's transfer tenure preempts the
/// outgoing owner's key; the transfer's row admits no preempt by its target, which preempts through the bumped form
/// or, when its own earlier committed takeover succeeded a tenure of that key, through that takeover's admission.
/// `TransferNamesStandby`, `NoEmissionAfterTransfer` and `TransferRetainsVolume` check the transfer,
/// `TransferByOwnTenure` its issuer, `TransferLeavesBump` the attempt it leaves the target and
/// `TransferAckMatchesCommit` its reply; the drain's publish and certify are actions of the suffix model.
module tenure {
  const BOUND: int
  pure val HOSTS = Set("h1", "h2", "h3")
  pure val REQUESTS = 4
  pure val EMAX = 3
  type Shard = { g: int, active: str, owner: str, e: int, spare: str, spareHost: str, standby: str }
  type Req = { id: int, kind: str, g: int, active: str, owner: str, e: int, spare: str, spareHost: str, to: str }
  /// A process: its host, phase, the generation and `E` it read, its volume, its kind, the key it captured for its
  /// preempt (`prkey`) and the reservation key of its host's attach (`key`).
  type Proc = { host: str, phase: str, g: int, n: int, vol: str, restart: bool, takeover: bool, prkey: str, key: str }
  /// A committed planned transfer: the attempt that issued it and its attach key, the owner the record named at the
  /// commit, the target and its attach key, the standby the record named at the commit, the generation and active
  /// volume the transfer conditioned on, the record's `E` when it committed, and the record after it.
  type Handoff = { by: int, fromKey: str, owner: str, to: str, toKey: str, named: str, g: int, vol: str, e: int,
    after: Shard }
  /// An attach entry of the active volume's record: its host, the reservation key that belongs to that attach alone,
  /// its state (`live`, `ended`, then `gone`), whether the record holds its enrolled pair, and its attach request
  /// (`recorded` before the request, then `landed` or `failed`, `detaching` once its detach is requested, and
  /// `detached`).
  type Attach = { host: str, key: str, state: str, pair: bool, req: str }
  /// The reclaim state: the attach entries by sequence number and the next number, the keys registered at the device,
  /// the listing an owner poll read before its record read (empty while none is open) and the owner and `E` of the
  /// tenure that read it, the entry whose end a reconciler decided and has not written (0 for none), and the ended
  /// key a decided ended-key preempt names and the key of its issuer ("" for none); and history the properties read: what each retirement found outside its admitted set or its recorded
  /// pairs (`retiredOn`), every grant with whether the attach was ended at the read the grant relied on (`grants`),
  /// every pair drop with whether the record-named owner served past its FB and a Report after the end had recorded
  /// the key absent, an end write that changes its entry's pair counting as a drop with neither (`drops`), every
  /// detach request with whether the entry was live or the record still held its pair
  /// (`detaches`), the entries whose key such a Report showed absent (`absent`, which the pair drop also reads), the
  /// entries a Report recorded absent while it listed their key or was not a serving owner's Report on which the own
  /// pair holds (`unshown`), the entries whose end was decided while the shard record named their host owner or
  /// standby or held `E = 0` (`roleEnds`), every ended-key preempt's landing with whether it removed a live
  /// entry's registration or changed the holder (`spared`), the host, generation and `E` of every tenure whose
  /// poll's record read found the entry under that tenure's key ended or gone (`endedPolls`), and every lineage-arm
  /// shard read, the reread before the preempt and Report #2's, with whether it named the tenure its restart's bump
  /// activated with the restart's attach live (`rereads`).
  type Reclaim = {
    attaches: int -> Attach, next: int, regs: Set[str], pollRead: Set[str], poller: str, pollE: int, ending: int,
    due: str, dueBy: str,
    retiredOn: Set[str], grants: Set[(str, int, bool)], drops: Set[(int, bool)], detaches: Set[(int, bool)],
    absent: Set[int], unshown: Set[int], roleEnds: Set[int], spared: Set[(str, bool, bool)],
    endedPolls: Set[(str, int, int)], rereads: Set[(int, bool)]
  }
  pure val EVENTS = Set("reset", "abort", "queueDelete")
  pure val VOLUMES = Set("v1", "v2", "v3", "v4")
  /// A stale attacher is a fleet host whose attach event the volume record holds; an unrecorded one is software
  /// outside the protocol, absent from the events.
  pure val STALE = "hs"
  pure val UNRECORDED = "x"
  pure val FOREIGN_MAX = 1
  /// The most live attach entries a volume record holds (`MAX_ATTACHED`), the most entries it retains before a gone
  /// entry leaves, and the key of each entry by its sequence number: the first three are the attaches of `HOSTS`.
  pure val MAX_ATTACHED = 3
  pure val MAX_EVENTS = 4
  pure val KEYS = Map(1 -> "h1", 2 -> "h2", 3 -> "h3", 4 -> "k4", 5 -> "k5", 6 -> "k6", 7 -> "k7")
  pure val FOREIGN_DETACH = false
  /// The losses an attempt observes: the four deposition observations, a retirement trigger and a planned change.
  pure val LOSSES = Set("flipped", "newerFence", "laterTenure", "regression", "trigger", "planned")
  var rec: Shard
  var pending: Set[Req]
  var decided: int -> bool
  var procs: int -> Proc
  var activations: Set[(int, int, int)]
  var history: Set[(int, str)]
  /// The source generation and request of every committed flip.
  var flipWins: Set[(int, int)]
  /// Every spare the reconciler replaced or the standby's check retired before a flip activated it.
  var replaced: Set[str]
  var bumps: Set[(int, int)]
  /// The control plane's attachment records of each volume, in every state; a foreign detach under the premise
  /// control and, under the reclaim schedule, a completed detach drop one, and an attach request adds one. A set holds no duplicate record, and every active volume and named spare lists its
  /// holder, so an empty listing, which the Rust checks read as no observation, is unreachable for a check.
  var listed: str -> Set[str]
  /// The attach events each volume record holds.
  var events: str -> Set[str]
  /// Every volume a foreign attachment wrote.
  var foreignWritten: Set[str]
  var foreign: int
  var retired: Set[str]
  /// Every poll that kept its volume serving: the volume, its owner, the listing the poll read, and the hosts whose
  /// attach event the volume record held and the hosts the caller bound at that poll.
  var kept: Set[{ vol: str, owner: str, listing: Set[str], events: Set[str], bound: Set[str] }]
  /// The standbys the owner poll's caller binds, by volume: each host whose recorded attach event the caller read.
  var bound: Set[(str, str)]
  /// Every standby attach the reconciler requested, by volume.
  var attaching: Set[(str, str)]
  /// Every fresh check that passed: the volume and whether no foreign attachment had written it.
  var freshChecks: Set[(str, bool)]
  /// Every retirement a restart refusal requested: the restart and the phase it refused in.
  var restartRetired: Set[(int, str)]
  /// What each restart's Report #1 showed: the restart, the holder, or "" when nobody held, and whether the holder's
  /// key was then the key of a recorded pair of another host.
  var shown: Set[(int, str, bool)]
  /// The generation of every fresh refusal.
  var refusedAt: Set[int]
  /// Every loss an active attempt observed: the attempt, the cause and the turn of the observation.
  var observations: Set[(int, str, int)]
  /// Every command action an attempt took: the attempt and the turn of the action.
  var commands: Set[(int, int)]
  /// Whether the owner's pair holds the reservation of the active volume.
  var holding: bool
  /// The holder identity and issued preempts: issuer, PRKEY and whether recorded evidence admits that key; a self
  /// preempt records its issuer's own key, and a takeover preempt the holder's key it captured at `takeoverReport1`.
  /// A takeover or lineage preempt is recorded when the device takes it, an ended-key preempt at its decision.
  var holder: str
  var preempts: Set[(str, str, bool)]
  /// Writes of an ended incarnation: `held` at the card, which the ready wait completes, and `queued` outstanding,
  /// which the self Preempt-and-Abort aborts.
  var held: int
  var queued: int
  /// The turn of every landing of an ended incarnation's write.
  var landed: Set[int]
  /// The FB turn of every fresh, restart or takeover attempt that reached it.
  var fb: int -> int
  /// Every committed takeover: the generation and active volume the CAS conditioned on, and the record's generation
  /// and active volume after it.
  var takeovers: Set[(int, str, int, str)]
  /// Every committed takeover's and planned transfer's successor, predecessor owner, the standby the record named at
  /// the commit, the request, whose write committed, the `E` that write consumed, and the keys of the successor's and
  /// the predecessor's attaches: a takeover's request is the successor's attempt, and a transfer's the outgoing
  /// owner's, so a chain follows a transfer as a committed owner-change write (A2).
  var lineage: Set[(str, str, str, int, int, str, str)]
  /// Every committed planned transfer, and every transfer an owner issued: its process and the turn of the issue.
  var handoffs: Set[Handoff]
  var transfers: Set[(int, int)]
  /// Every fresh, restart or takeover attempt that read the records, with whether that read passed its checks: the
  /// owner, epoch and retired-volume checks, and for a takeover the named standby, `E > 0` and an unretired volume;
  /// and every attempt that issued a device command.
  var recordsRead: Set[(int, bool)]
  var deviceActs: Set[int]
  /// Every attempt that issued a fencing command: a Register or a Preempt-and-Abort of the fresh path, a restart or a
  /// takeover.
  var fencing: Set[int]
  /// Every medium write of an attempt's tenure: the attempt and the turn of the write.
  var writes: Set[(int, int)]
  var free: Set[str]
  var rc: Reclaim
  var nextId: int
  var turn: int
  var ev: { act: str, id: int }

  pure def bumpHolds(r: Req, s: Shard): bool = r.g == s.g and r.active == s.active and r.owner == s.owner and r.e == s.e
  pure def flipHolds(r: Req, s: Shard): bool =
    s.spare == r.spare and s.spareHost == r.spareHost and s.g == r.g and s.active == r.active and s.owner == r.owner and s.e == r.e
  pure def holds(r: Req, s: Shard): bool =
    if (r.kind == "flip") flipHolds(r, s) else if (r.kind == "takeover") bumpHolds(r, s) and s.standby == r.to
    else if (r.kind == "transfer") transferHolds(r, s) else bumpHolds(r, s)
  /// The planned transfer's condition: the withdrawn owner's tenure `(g, active, owner, E)` and the standby it names.
  pure def transferHolds(r: Req, s: Shard): bool = s.standby == r.to and bumpHolds(r, s)
  pure def applied(r: Req, s: Shard): Shard =
    if (r.kind == "bump") { ...s, e: r.e + 1 }
    else if (r.kind == "takeover") { ...s, owner: r.to, e: r.e + 1, standby: "" }
    else if (r.kind == "transfer") { ...s, owner: r.to, e: r.e + 1, standby: "" }
    else { g: r.g + 1, active: r.spare, owner: r.spareHost, e: 0, spare: "", spareHost: "", standby: "" }

  /// The first three attach entries: one live, enrolled attach of each host of `HOSTS`, under its own key.
  pure val RC0: Reclaim = {
    attaches: Map(1 -> { host: "h1", key: "h1", state: "live", pair: true, req: "landed" },
      2 -> { host: "h2", key: "h2", state: "live", pair: true, req: "landed" },
      3 -> { host: "h3", key: "h3", state: "live", pair: true, req: "landed" }),
    next: 4, regs: Set(), pollRead: Set(), poller: "", pollE: 0, ending: 0, due: "", dueBy: "", retiredOn: Set(), grants: Set(), drops: Set(),
    detaches: Set(), absent: Set(), unshown: Set(), roleEnds: Set(), spared: Set(), endedPolls: Set(),
    rereads: Set()
  }
  action init = all {
    rec' = { g: 1, active: "v1", owner: "h1", e: 0, spare: "v2", spareHost: "h2", standby: "h2" },
    pending' = Set(), decided' = Map(), procs' = Map(), activations' = Set(), history' = Set((1, "v1")), bumps' = Set(),
    free' = Set("v3", "v4"), nextId' = 1, turn' = 0, ev' = { act: "init", id: 0 }, flipWins' = Set(), replaced' = Set(),
    listed' = Map("v1" -> Set("h1"), "v2" -> Set("h2"), "v3" -> Set(), "v4" -> Set()),
    events' = Map("v1" -> Set("h1"), "v2" -> Set("h2"), "v3" -> Set(), "v4" -> Set()),
    foreignWritten' = Set(), foreign' = 0, retired' = Set(), kept' = Set(), bound' = Set(), attaching' = Set(),
    freshChecks' = Set(), refusedAt' = Set(),
    restartRetired' = Set(), shown' = Set(),
    observations' = Set(), commands' = Set(),
    holding' = false, holder' = "", preempts' = Set(), held' = 0, queued' = 0, landed' = Set(), fb' = Map(), recordsRead' = Set(), deviceActs' = Set(), fencing' = Set(),
    writes' = Set(), takeovers' = Set(), lineage' = Set(), handoffs' = Set(), transfers' = Set(), rc' = RC0,
  }
  /// The reclaim schedule's initial state: `h1` serves past the FB of its fresh activation at `E = 1`, process 1, the
  /// record names `h2` standby and no spare, and the listing of `v1` shows the three attaches of `RC0`, the two
  /// standbys' attached by the reconciler after that FB.
  action reclaimInit = all {
    rec' = { g: 1, active: "v1", owner: "h1", e: 1, spare: "", spareHost: "", standby: "h2" },
    pending' = Set(), decided' = Map(1 -> true),
    procs' = Map(1 -> { host: "h1", phase: "active", g: 1, n: 0, vol: "v1", restart: false, takeover: false, prkey: "", key: "h1" }),
    activations' = Set((1, 0, 1)), history' = Set((1, "v1")), bumps' = Set((1, 1)),
    free' = Set("v3", "v4"), nextId' = 2, turn' = 0, ev' = { act: "init", id: 0 }, flipWins' = Set(), replaced' = Set(),
    listed' = Map("v1" -> Set("h1", "h2", "h3"), "v2" -> Set(), "v3" -> Set(), "v4" -> Set()),
    events' = Map("v1" -> Set("h1", "h2", "h3"), "v2" -> Set(), "v3" -> Set(), "v4" -> Set()),
    foreignWritten' = Set(), foreign' = 0, retired' = Set(), kept' = Set(), bound' = Set(),
    attaching' = Set(("v1", "h2"), ("v1", "h3")), freshChecks' = Set(("v1", true)), refusedAt' = Set(),
    restartRetired' = Set(), shown' = Set(),
    observations' = Set(), commands' = Set(),
    holding' = true, holder' = "h1", preempts' = Set(), held' = 0, queued' = 0, landed' = Set(), fb' = Map(1 -> 0),
    recordsRead' = Set((1, true)), deviceActs' = Set(1), fencing' = Set(1),
    writes' = Set(), takeovers' = Set(), lineage' = Set(), handoffs' = Set(), transfers' = Set(),
    rc' = { ...RC0, regs: Set("h1") },
  }
  action unchangedRestart = all {
    holding' = holding, holder' = holder, preempts' = preempts, held' = held, queued' = queued, landed' = landed, fb' = fb, recordsRead' = recordsRead,
    deviceActs' = deviceActs, fencing' = fencing, writes' = writes,
  }
  action unchangedShard = all { procs' = procs, unchangedRecords }
  action unchangedRecords = all {
    rec' = rec, pending' = pending, decided' = decided, activations' = activations, history' = history,
    bumps' = bumps, free' = free, nextId' = nextId, flipWins' = flipWins, replaced' = replaced,
    unchangedTakeovers,
  }
  action unchangedTakeovers = all { takeovers' = takeovers, lineage' = lineage, unchangedHandoffs }
  action unchangedHandoffs = all { handoffs' = handoffs, transfers' = transfers }
  action unchangedLoss = all { observations' = observations, commands' = commands }
  action unchangedChecks = all { kept' = kept, freshChecks' = freshChecks, refusedAt' = refusedAt, unchangedLoss, unchangedRetirements }
  action unchangedRetirements = all { restartRetired' = restartRetired, shown' = shown }
  action unchangedAttachments = all {
    listed' = listed, events' = events, foreignWritten' = foreignWritten, foreign' = foreign, retired' = retired,
    unchangedStandbyAttach, unchangedChecks,
  }
  action unchangedStandbyAttach = all { bound' = bound, attaching' = attaching }
  action tick(act: str, id: int): bool = all { advance(act, id), rc' = rc }
  /// The turn of an action that writes the reclaim state itself.
  action advance(act: str, id: int): bool = all { turn < BOUND, turn' = turn + 1, ev' = { act: act, id: id } }

  /// A new process of the owner reads the record and submits `E: n -> n + 1` conditioned on `(g, active, owner, n)`.
  /// An earlier process of the same host may still be paused with its own request outstanding. No process starts on
  /// a retired active volume, and at `E = 0`, the fresh path, a process starts only on a listing of exactly its own
  /// attachment.
  action start(h: str): bool = {
    val fresh = rec.e > 0 or listed.get(rec.active) == Set(h)
    all {
      nextId <= REQUESTS, rec.owner == h, rec.e < EMAX, not(retired.contains(rec.active)), fresh, tick("start", nextId),
      holding' = holding, holder' = holder, preempts' = preempts, held' = held, queued' = queued, landed' = landed, fb' = fb, deviceActs' = deviceActs, fencing' = fencing, writes' = writes,
      recordsRead' = if (rec.e == 0) recordsRead.union(Set((nextId, rec.owner == h and not(retired.contains(rec.active))
        and listed.get(rec.active) == Set(h)))) else recordsRead,
      pending' = pending.union(Set({ id: nextId, kind: "bump", g: rec.g, active: rec.active, owner: rec.owner, e: rec.e, spare: "", spareHost: "", to: "" })),
      procs' = procs.put(nextId, { host: h, phase: "sent", g: rec.g, n: rec.e, vol: rec.active, restart: false, takeover: false, prkey: "", key: attachKey(h) }),
      nextId' = nextId + 1,
      rec' = rec, decided' = decided, activations' = activations, history' = history, bumps' = bumps, free' = free,
      flipWins' = flipWins, replaced' = replaced, unchangedTakeovers,
      freshChecks' = if (rec.e == 0) freshChecks.union(Set((rec.active, not(foreignWritten.contains(rec.active))))) else freshChecks,
      listed' = listed, events' = events, unchangedStandbyAttach, foreignWritten' = foreignWritten, foreign' = foreign, retired' = retired,
      kept' = kept, refusedAt' = refusedAt, unchangedRetirements, unchangedLoss,
    }
  }
  /// A reconciler reads the record and submits the flip to its spare, after its listing shows only the standby.
  action requestFlip = all {
    nextId <= REQUESTS, rec.spare != "", listed.get(rec.spare) == Set(rec.spareHost), tick("requestFlip", nextId), unchangedRestart,
    pending' = pending.union(Set({ id: nextId, kind: "flip", g: rec.g, active: rec.active, owner: rec.owner, e: rec.e, spare: rec.spare, spareHost: rec.spareHost, to: "" })),
    nextId' = nextId + 1,
    rec' = rec, decided' = decided, procs' = procs, activations' = activations, history' = history, bumps' = bumps, free' = free,
    flipWins' = flipWins, replaced' = replaced, unchangedTakeovers, unchangedAttachments,
  }
  /// The reconciler provisions a spare for a shard without one, or replaces the spare with a fresh volume.
  /// It records the attach event and the attach in one step.
  action spare(v: str, h: str): bool = all {
    free.contains(v), h != rec.owner, tick("spare", 0), unchangedRestart,
    rec' = { ...rec, spare: v, spareHost: h }, free' = free.exclude(Set(v)),
    replaced' = if (rec.spare != "") replaced.union(Set(rec.spare)) else replaced,
    pending' = pending, decided' = decided, procs' = procs, activations' = activations, history' = history, bumps' = bumps, nextId' = nextId,
    flipWins' = flipWins, unchangedTakeovers,
    listed' = listed.set(v, listed.get(v).union(Set(h))), events' = events.set(v, events.get(v).union(Set(h))), unchangedStandbyAttach,
    foreignWritten' = foreignWritten, foreign' = foreign, retired' = retired, unchangedChecks,
  }
  /// A foreign attachment of `v`; a stale one also lands in the volume record's events.
  action foreignAttach(v: str, stale: bool): bool = {
    val a = if (stale) STALE else UNRECORDED
    all {
      foreign < FOREIGN_MAX, VOLUMES.contains(v), tick("foreignAttach", 0), unchangedRestart,
      listed' = listed.set(v, listed.get(v).union(Set(a))),
      events' = if (stale) events.set(v, events.get(v).union(Set(a))) else events, unchangedStandbyAttach,
      foreign' = foreign + 1,
      foreignWritten' = foreignWritten, retired' = retired, unchangedChecks, unchangedShard,
    }
  }
  /// Under the premise control, the foreign attachment of `v` detaches and leaves the listing.
  action foreignDetach(v: str): bool = all {
    FOREIGN_DETACH, VOLUMES.contains(v), listed.get(v).exists(a => a == STALE or a == UNRECORDED),
    tick("foreignDetach", 0), unchangedRestart,
    listed' = listed.set(v, listed.get(v).exclude(Set(STALE, UNRECORDED))),
    events' = events, unchangedStandbyAttach, foreignWritten' = foreignWritten, foreign' = foreign, retired' = retired, unchangedChecks,
    unchangedShard,
  }
  /// The reconciler records host `h`'s attach event in the active volume's record, for a host other than the owner
  /// once an attempt of the owner at the record's generation reached its FB, the fence a standby attach waits for:
  /// the first step of a standby attach.
  action standbyRecord(h: str): bool = all {
    HOSTS.contains(h), h != rec.owner, not(retired.contains(rec.active)),
    fb.keys().exists(p => procs.get(p).host == rec.owner and procs.get(p).g == rec.g),
    not(events.get(rec.active).contains(h)), tick("standbyRecord", 0), unchangedRestart,
    events' = events.set(rec.active, events.get(rec.active).union(Set(h))), unchangedStandbyAttach,
    listed' = listed, foreignWritten' = foreignWritten, foreign' = foreign, retired' = retired, unchangedChecks,
    unchangedShard,
  }
  /// The owner poll's caller binds host `h` by reading its attach event in the active volume's record.
  action standbyBind(h: str): bool = all {
    HOSTS.contains(h), h != rec.owner, not(retired.contains(rec.active)), events.get(rec.active).contains(h),
    not(bound.contains((rec.active, h))), tick("standbyBind", 0), unchangedRestart,
    bound' = bound.union(Set((rec.active, h))), attaching' = attaching,
    listed' = listed, events' = events, foreignWritten' = foreignWritten, foreign' = foreign, retired' = retired,
    unchangedChecks, unchangedShard,
  }
  /// The reconciler requests host `h`'s attach of the active volume once the caller bound the host, and the listing
  /// shows the attachment.
  action standbyAttach(h: str): bool = {
    val ordered = bound.contains((rec.active, h))
    all {
      ordered, HOSTS.contains(h), h != rec.owner, not(retired.contains(rec.active)),
      not(listed.get(rec.active).contains(h)), tick("standbyAttach", 0),
      unchangedRestart,
      listed' = listed.set(rec.active, listed.get(rec.active).union(Set(h))),
      attaching' = attaching.union(Set((rec.active, h))), bound' = bound,
      events' = events, foreignWritten' = foreignWritten, foreign' = foreign, retired' = retired, unchangedChecks,
      unchangedShard,
    }
  }
  /// The reclaim state after attach entry `i` takes `a`.
  def withEntry(i: int, a: Attach): Reclaim = { ...rc, attaches: rc.attaches.put(i, a) }
  /// Whether every entry of host `h` is gone, so a new attach of `h` may be recorded.
  def afterGone(h: str): bool = entriesOf(h).forall(i => rc.attaches.get(i).state == "gone")
  /// The live and the retained (live or ended) attach entries.
  def liveCount: int = rc.attaches.keys().filter(i => rc.attaches.get(i).state == "live").size()
  def retainedCount: int = rc.attaches.keys().filter(i => rc.attaches.get(i).state != "gone").size()
  /// The reconciler records a new attach entry of host `h` under a key of that attach alone, for a host other than
  /// the owner whose every earlier entry is gone and with no listed attachment, while the owner's tenure holds `E > 0`:
  /// the entry binds the host's instance (A3, D15), so a host holds at most one retained entry (`AttachAfterGone`). At `MAX_ATTACHED` live entries or `MAX_EVENTS` retained ones the volume admits no attach,
  /// and the step refuses with no write (`attachClosed`).
  action recordAttach(h: str): bool = {
    val open = liveCount < MAX_ATTACHED and retainedCount < MAX_EVENTS
    val key = KEYS.get(rc.next)
    all {
      HOSTS.contains(h), h != rec.owner, rec.e > 0, not(retired.contains(rec.active)), afterGone(h),
      not(listed.get(rec.active).contains(h)), KEYS.keys().contains(rc.next),
      advance(if (open) "recordAttach" else "attachClosed", rc.next), unchangedRestart, unchangedShard,
      rc' = if (open) { ...withEntry(rc.next, { host: h, key: key, state: "live", pair: false, req: "recorded" }),
        next: rc.next + 1 } else rc,
      unchangedAttachments,
    }
  }
  /// The reconciler requests the attach of entry `i`, which lands and is listed, or fails. A failed request may still
  /// land later (`lateLand`) until a detach is requested.
  action attachRequest(i: int, lands: bool): bool = {
    val a = rc.attaches.get(i)
    all {
      rc.attaches.keys().contains(i), a.req == "recorded", advance(if (lands) "attachLanded" else "attachFailed", i),
      unchangedRestart, unchangedShard,
      rc' = withEntry(i, { ...a, req: if (lands) "landed" else "failed" }),
      listed' = if (lands) listed.set(rec.active, listed.get(rec.active).union(Set(a.host))) else listed,
      attaching' = attaching.union(Set((rec.active, a.host))), bound' = bound,
      events' = events, foreignWritten' = foreignWritten, foreign' = foreign, retired' = retired, unchangedChecks,
    }
  }
  /// A failed attach request of entry `i` lands late, live or ended, and the listing shows its instance.
  action lateLand(i: int): bool = {
    val a = rc.attaches.get(i)
    all {
      rc.attaches.keys().contains(i), a.req == "failed", advance("lateLand", i), unchangedRestart, unchangedShard,
      rc' = withEntry(i, { ...a, req: "landed" }),
      listed' = listed.set(rec.active, listed.get(rec.active).union(Set(a.host))),
      events' = events, foreignWritten' = foreignWritten, foreign' = foreign, retired' = retired,
      unchangedStandbyAttach, unchangedChecks,
    }
  }
  /// The standby's enrollment of entry `i` once its attach landed: the record holds its pair. The enrollment reads
  /// the entry and refuses with no write (`enrollRefused`) when it is ended.
  action enroll(i: int): bool = {
    val a = rc.attaches.get(i)
    val admitted = a.state == "live"
    all {
      rc.attaches.keys().contains(i), a.req == "landed", not(a.pair), a.host != rec.owner, rec.e > 0,
      a.state != "gone", advance(if (admitted) "enroll" else "enrollRefused", i), unchangedRestart, unchangedShard,
      rc' = if (admitted) { ...withEntry(i, { ...a, pair: true }),
        grants: rc.grants.union(Set(("enroll", i, a.state == "ended" or a.req != "landed"))) } else rc,
      unchangedAttachments,
    }
  }
  /// The reconciler decides to end live entry `i`: its shard read names the entry's host neither owner nor standby at
  /// `E > 0`. The end write follows at a later step.
  action endRead(i: int): bool = {
    val a = rc.attaches.get(i)
    val endable = rec.e > 0 and a.host != rec.owner and a.host != rec.standby
    all {
      rc.attaches.keys().contains(i), a.state == "live", rc.ending == 0, endable, advance("endRead", i),
      unchangedRestart, unchangedShard, unchangedAttachments,
      rc' = { ...rc, ending: i, roleEnds: if (rec.e > 0 and Set(rec.owner, rec.standby).forall(h => h != a.host))
        rc.roleEnds else rc.roleEnds.union(Set(i)) },
    }
  }
  /// The end write of the decided entry, conditioned on the entry the decision read: the entry is ended, first in the
  /// reclamation order (D14), whatever the shard record names by then. The write keeps the entry's pair; `rc.drops`
  /// records a write that changes it as a pair drop with no recorded absence.
  action endWrite(i: int): bool = {
    val a = rc.attaches.get(i)
    val written = { ...a, state: "ended" }
    all {
      rc.ending == i, a.state == "live", advance("endWrite", i), unchangedRestart, unchangedShard,
      rc' = { ...withEntry(i, written), ending: 0,
        drops: if (written.pair == a.pair) rc.drops else rc.drops.union(Set((i, false))) }, unchangedAttachments,
    }
  }
  /// The record-named owner, serving past its FB, decides a Preempt with no abort naming ended key `k` that does not
  /// hold; the issued preempt and its key evidence are recorded at the decision. The preempt lands at a later step.
  action endedPreempt(k: str): bool = {
    val issuable = endedKey(k) and servingPastFb(rec.owner) and not(holding and holder == k)
    all {
      issuable, rc.due == "", advance("endedPreempt", 0), unchangedShard, unchangedAttachments,
      rc' = { ...rc, due: k, dueBy: attachKey(rec.owner) },
      preempts' = preempts.union(Set((rec.owner, k, endedForm(rec.owner, k)))),
      holding' = holding, holder' = holder, held' = held, queued' = queued, landed' = landed, fb' = fb,
      recordsRead' = recordsRead, deviceActs' = deviceActs, fencing' = fencing, writes' = writes,
    }
  }
  /// The decided ended-key preempt lands, however late: it removes every registration under its key, or, with
  /// `effect` false, reports success and changes nothing; the next Report is its only receipt (D17). The device takes
  /// it only while its issuer's key is registered. A Preempt with no abort that names the holder's key also moves the
  /// reservation to the issuer.
  action endedPreemptLands(effect: bool): bool = {
    val k = rc.due
    val takes = effect and rc.regs.contains(rc.dueBy)
    val removes = takes and rc.regs.contains(k)
    val moves = takes and holding and holder == k
    all {
      k != "", advance("endedPreemptLands", 0), unchangedShard, unchangedAttachments,
      rc' = { ...rc, due: "", dueBy: "", regs: if (removes) rc.regs.exclude(Set(k)) else rc.regs,
        spared: rc.spared.union(Set((k, removes and keyEntries(k).exists(i => rc.attaches.get(i).state == "live"), moves))) },
      holding' = holding, holder' = if (moves) rc.dueBy else holder, preempts' = preempts, held' = held,
      queued' = queued, landed' = landed, fb' = fb, recordsRead' = recordsRead, deviceActs' = deviceActs, fencing' = fencing, writes' = writes,
    }
  }
  /// The record-named owner, serving past its FB, drops the pair of ended entry `i` after one of its Reports showed
  /// the entry's key absent.
  action dropPair(i: int): bool = {
    val a = rc.attaches.get(i)
    val reported = rc.absent.contains(i)
    all {
      rc.attaches.keys().contains(i), a.state == "ended", a.pair, servingPastFb(rec.owner), reported,
      advance("dropPair", i), unchangedRestart, unchangedShard,
      rc' = { ...withEntry(i, { ...a, pair: false }), drops: rc.drops.union(Set((i, rc.absent.contains(i) and a.state == "ended"
        and servingPastFb(rec.owner)))) },
      unchangedAttachments,
    }
  }
  /// The reconciler requests the detach of ended entry `i` once the record holds no pair for it.
  action detachRequest(i: int): bool = {
    val a = rc.attaches.get(i)
    val unpaired = not(a.pair)
    all {
      rc.attaches.keys().contains(i), a.state == "ended", unpaired, Set("recorded", "landed", "failed").contains(a.req),
      advance("detachRequest", i), unchangedRestart, unchangedShard,
      rc' = { ...withEntry(i, { ...a, req: "detaching" }), detaches: rc.detaches.union(Set((i, a.pair or a.state != "ended"))) },
      unchangedAttachments,
    }
  }
  /// The detach of entry `i` completes, and the listing no longer shows the host's instance.
  action detachDone(i: int): bool = {
    val a = rc.attaches.get(i)
    all {
      rc.attaches.keys().contains(i), a.req == "detaching", advance("detachDone", i), unchangedRestart, unchangedShard,
      rc' = withEntry(i, { ...a, req: "detached" }),
      listed' = listed.set(rec.active, listed.get(rec.active).exclude(Set(a.host))),
      events' = events, foreignWritten' = foreignWritten, foreign' = foreign, retired' = retired,
      unchangedStandbyAttach, unchangedChecks,
    }
  }
  /// The reconciler marks ended entry `i` gone once its detach completed and its clean listings no longer show its
  /// host's instance. The model's listing is consistent, and its second clean listing follows the record read of
  /// every owner poll whose listing read showed the instance: the premise that an owner poll's two reads take less
  /// time than the interval between the reconciler's two clean listings.
  action markGone(i: int): bool = {
    val a = rc.attaches.get(i)
    val clean = a.req == "detached" and not(listed.get(rec.active).contains(a.host)) and not(rc.pollRead.contains(a.host))
    all {
      rc.attaches.keys().contains(i), a.state == "ended", clean, advance("markGone", i), unchangedRestart,
      unchangedShard, rc' = withEntry(i, { ...a, state: "gone" }), unchangedAttachments,
    }
  }
  /// The owner's poll under the reclaim schedule reads the listing first.
  action readListing = all {
    rc.poller == "", not(retired.contains(rec.active)), advance("readListing", 0), unchangedRestart,
    unchangedShard, rc' = { ...rc, pollRead: listed.get(rec.active), poller: rec.owner, pollE: rec.e },
    unchangedAttachments,
  }
  /// Whether the open poll's tenure is the record's: the owner and `E` its listing read saw.
  def pollCurrent: bool = rc.poller == rec.owner and rc.pollE == rec.e
  /// The poll's record read finds another tenure than the one that read the listing, another owner or the same host at
  /// another `E`: the poll ends with no verdict, and that tenure's attempts observe the later tenure through `observe`.
  action pollSuperseded = all {
    rc.poller != "", not(pollCurrent), advance("pollSuperseded", 0), unchangedRestart, unchangedShard,
    rc' = { ...rc, pollRead: Set(), poller: "", pollE: 0 }, unchangedAttachments,
  }
  /// The admitted set of the reclaim poll: the owner and the instances of the retained entries.
  def reclaimAdmitted: Set[str] = Set(rec.owner).union(retainedHosts)
  /// The poll's record read after its listing read: the entries bind the instances, and the poll gives the first
  /// verdict of this order that applies. A listing with an instance outside the owner and the retained entries, live
  /// or ended, retires the volume as `poll` does. A record that shows the entry under the key of the owner's tenure
  /// ended or gone withdraws every active or sent attempt of the owner at the record's generation with no retirement
  /// (`pollWithdrawn`, ENDED-GRANTS-NOTHING), whether or not the listing holds the owner's attachment: the verdict
  /// volume record format 3 gives an owner whose own attach ended. A listing that holds the owner's attachment keeps
  /// the owner serving. A listing that lacks it ends the poll with no verdict (`pollUnobserved`), as Rust's missing
  /// attachment refuses without retiring. The listing drops a host only at the detach of its ended entry, so under
  /// the reclaim schedule a poll whose listing lacks the owner withdraws. The step records a tenure whose own entry
  /// it read ended or gone in `endedPolls` from that read alone.
  action pollEntries = {
    val listing = rc.pollRead
    val admitted = reclaimAdmitted
    val outside = not(listing.subseteq(admitted))
    val admits = listing.contains(rec.owner) and listing.subseteq(admitted)
    val ownEnded = not(liveKey(tenureKey(rec.owner)))
    val withdraws = outside or ownEnded
    val entryHosts = rc.attaches.keys().filter(i => Set("live", "ended").contains(rc.attaches.get(i).state))
      .map(i => rc.attaches.get(i).host)
    val owning = procs.keys().filter(p => Set("active", "sent").contains(procs.get(p).phase)
      and procs.get(p).host == rec.owner and procs.get(p).g == rec.g)
    all {
      rc.poller != "", pollCurrent, not(retired.contains(rec.active)),
      advance(if (outside) "pollRetired" else if (withdraws) "pollWithdrawn" else if (admits) "poll" else "pollUnobserved", 0),
      unchangedRestart,
      rc' = { ...rc, pollRead: Set(), poller: "", pollE: 0,
        retiredOn: if (admits) rc.retiredOn else rc.retiredOn.union(listing.exclude(admitted)),
        endedPolls: if (liveKey(tenureKey(rec.owner))) rc.endedPolls else rc.endedPolls.union(Set((rec.owner, rec.g, rec.e))) },
      kept' = if (admits and not(withdraws)) kept.union(Set({ vol: rec.active, owner: rec.owner, listing: listing, events: entryHosts,
        bound: entryHosts })) else kept,
      retired' = if (not(outside)) retired else retired.union(Set(rec.active)),
      procs' = if (not(withdraws)) procs else procs.keys().mapBy(p => if (owning.contains(p)) { ...procs.get(p), phase: "withdrawn" } else procs.get(p)),
      observations' = if (not(withdraws)) observations else observations.union(owning.map(p => (p, "trigger", turn + 1))),
      commands' = commands,
      listed' = listed, events' = events, unchangedStandbyAttach, foreignWritten' = foreignWritten, foreign' = foreign,
      freshChecks' = freshChecks, refusedAt' = refusedAt, unchangedRetirements, unchangedRecords,
    }
  }
  /// A foreign attachment writes the volume it attached.
  action foreignWrite(v: str): bool = all {
    VOLUMES.contains(v), listed.get(v).exists(a => a == STALE or a == UNRECORDED), tick("foreignWrite", 0), unchangedRestart,
    foreignWritten' = foreignWritten.union(Set(v)),
    listed' = listed, events' = events, unchangedStandbyAttach, foreign' = foreign, retired' = retired, unchangedChecks, unchangedShard,
  }
  /// The admitted set of volume `v`: the owner the shard record names and each host whose attach event the volume
  /// record holds and the poll's caller binds. `standbyBind` reads the event and no action removes one, so the filter
  /// over `events` keeps every bound host in every reached state.
  def admittedSet(v: str): Set[str] = Set(rec.owner).union(events.get(v).filter(h => bound.contains((v, h))))
  /// The hosts the poll's caller binds on volume `v`, and the standbys the reconciler requested an attach for there.
  def boundHosts(v: str): Set[str] = bound.filter(b => b._1 == v).map(b => b._2)
  def requestedHosts(v: str): Set[str] = attaching.filter(a => a._1 == v).map(a => a._2)
  /// The owner's poll of its active volume: it keeps serving on a listing inside its admitted set that holds its own
  /// attachment, so a listing that lacks a recorded standby retires nothing, and otherwise retires the volume, and
  /// each active or sent attempt of the owner at the record's generation observes the retirement trigger and
  /// withdraws in the same step, so a later bump reply activates none of them.
  action poll = {
    val listing = listed.get(rec.active)
    val inside = listing.contains(rec.owner) and listing.subseteq(admittedSet(rec.active))
    val owning = procs.keys().filter(p => Set("active", "sent").contains(procs.get(p).phase)
      and procs.get(p).host == rec.owner and procs.get(p).g == rec.g)
    all {
      not(retired.contains(rec.active)), tick(if (inside) "poll" else "pollRetired", 0), unchangedRestart,
      kept' = if (inside) kept.union(Set({ vol: rec.active, owner: rec.owner, listing: listed.get(rec.active),
        events: events.get(rec.active), bound: boundHosts(rec.active) })) else kept,
      retired' = if (inside) retired else retired.union(Set(rec.active)),
      procs' = if (inside) procs else procs.keys().mapBy(p => if (owning.contains(p)) { ...procs.get(p), phase: "withdrawn" } else procs.get(p)),
      observations' = if (inside) observations else observations.union(owning.map(p => (p, "trigger", turn + 1))),
      commands' = commands,
      listed' = listed, events' = events, unchangedStandbyAttach, foreignWritten' = foreignWritten, foreign' = foreign, freshChecks' = freshChecks,
      refusedAt' = refusedAt, unchangedRetirements,
      rec' = rec, pending' = pending, decided' = decided, activations' = activations, history' = history,
      bumps' = bumps, free' = free, nextId' = nextId, flipWins' = flipWins, replaced' = replaced, unchangedTakeovers,
    }
  }
  /// The serving owner's Report at its poll under the takeover and reclaim schedules: the own pair holding keeps it
  /// serving; a holder that is a recorded attachment of another host, under a recorded pair of a live or an ended
  /// attach or under an ended key whose pair the record dropped (RECORDED-HOLDER-HOLD),
  /// withdraws every serving attempt of the record's current tenure, active past its FB at the record's generation
  /// and `E`, with no retirement; an unrecorded holder, or a registrant under no recorded pair and no ended key,
  /// retires the volume with the alarm. A registrant under an ended key is no observation. `UNRECORDED`, the holder
  /// of `statusDeposition(true)`, is the only key no entry names. A serving Report on which the own pair holds
  /// records each ended entry whose key it shows absent while the record holds the pair.
  /// STATUS-REJUDGE: an attempt a deposing status withdrew takes this Report once more, which judges the holder.
  action reportPoll = {
    val owning = procs.keys().filter(p => procs.get(p).phase == "active" and fb.keys().contains(p)
      and procs.get(p).host == rec.owner and procs.get(p).g == rec.g and procs.get(p).n + 1 == rec.e)
    val deposed = procs.keys().filter(p => procs.get(p).phase == "withdrawn" and procs.get(p).host == rec.owner
      and procs.get(p).g == rec.g and procs.get(p).n + 1 == rec.e and observations.exists(o => o._1 == p and o._2 == "status")
      and not(observations.exists(o => o._1 == p and o._2 == "judged")))
    val ownKey = attachKey(rec.owner)
    val own = holding and holder == ownKey
    val recordedHolder = holding and holder != ownKey and recordedKey(holder)
    val foreignRegs = rc.regs.filter(k => k != holder and k != ownKey and not(paired(k)) and not(endedKey(k)))
    val keeps = (own or recordedHolder) and foreignRegs == Set()
    val shownAbsent = rc.attaches.keys().filter(i => rc.attaches.get(i).state == "ended" and rc.attaches.get(i).pair
      and not(rc.regs.contains(rc.attaches.get(i).key)))
    val recorded = if (own and owning.size() > 0) rc.absent.union(shownAbsent) else rc.absent
    val servingOwn = holding and holder == attachKey(rec.owner) and servingPastFb(rec.owner)
    all {
      not(retired.contains(rec.active)), owning.size() + deposed.size() > 0, holding,
      advance(if (not(keeps)) "reportRetired" else if (own) "reportPoll" else "reportHold", 0), unchangedRestart,
      rc' = { ...rc, absent: recorded,
        unshown: rc.unshown.union(recorded.exclude(rc.absent).filter(i => not(servingOwn)
          or rc.regs.contains(rc.attaches.get(i).key) or rc.attaches.get(i).state != "ended")),
        retiredOn: if (keeps) rc.retiredOn else rc.retiredOn.union(foreignRegs).union(if (own or recordedHolder) Set() else Set(holder)) },
      kept' = kept,
      retired' = if (keeps) retired else retired.union(Set(rec.active)),
      procs' = if (own and keeps) procs else procs.keys().mapBy(p => if (owning.contains(p)) { ...procs.get(p), phase: "withdrawn" } else procs.get(p)),
      observations' = observations.union(deposed.map(p => (p, "judged", turn + 1)))
        .union(if (own and keeps) Set() else owning.map(p => (p, "trigger", turn + 1))),
      commands' = commands,
      listed' = listed, events' = events, unchangedStandbyAttach, foreignWritten' = foreignWritten, foreign' = foreign, freshChecks' = freshChecks,
      refusedAt' = refusedAt, unchangedRetirements,
      rec' = rec, pending' = pending, decided' = decided, activations' = activations, history' = history,
      bumps' = bumps, free' = free, nextId' = nextId, flipWins' = flipWins, replaced' = replaced, unchangedTakeovers,
    }
  }
  /// A deposed owner's outstanding command completes with a deposing status (`0x1B` after a preempt, `0x83` after
  /// the reservation passed), while serving or after a Report's withdrawal, since Withdrawn keeps command custody:
  /// STATUS-IS-DEPOSITION, every serving attempt of the record's current tenure, at least one, withdraws with no
  /// retirement, and STATUS-REJUDGE, a later
  /// `reportPoll` judges the holder. With `unrecorded`, the status follows a preempt of the owner holding by
  /// `UNRECORDED`, a pair outside the recorded set. `statusRetires` is the retirement the status itself requests.
  action statusDeposition(unrecorded: bool): bool = {
    val statusRetires = false
    val owning = procs.keys().filter(p => procs.get(p).phase == "active" and fb.keys().contains(p)
      and procs.get(p).host == rec.owner and procs.get(p).g == rec.g and procs.get(p).n + 1 == rec.e)
    all {
      not(retired.contains(rec.active)), holding, (holder == attachKey(rec.owner)) == unrecorded, HOSTS.contains(rec.owner),
      owning.size() > 0,
      advance("statusDeposition", 0),
      rc' = if (unrecorded) { ...rc, regs: rc.regs.exclude(Set(holder)).union(Set(UNRECORDED)) } else rc,
      holding' = holding, holder' = if (unrecorded) UNRECORDED else holder, preempts' = preempts, held' = held,
      queued' = queued, landed' = landed, fb' = fb, recordsRead' = recordsRead, deviceActs' = deviceActs, fencing' = fencing, writes' = writes,
      kept' = kept,
      retired' = if (statusRetires) retired.union(Set(rec.active)) else retired,
      procs' = procs.keys().mapBy(p => if (owning.contains(p)) { ...procs.get(p), phase: "withdrawn" } else procs.get(p)),
      observations' = observations.union(owning.map(p => (p, "status", turn + 1))),
      commands' = commands,
      listed' = listed, events' = events, unchangedStandbyAttach, foreignWritten' = foreignWritten, foreign' = foreign, freshChecks' = freshChecks,
      refusedAt' = refusedAt, unchangedRetirements,
      rec' = rec, pending' = pending, decided' = decided, activations' = activations, history' = history,
      bumps' = bumps, free' = free, nextId' = nextId, flipWins' = flipWins, replaced' = replaced, unchangedTakeovers,
    }
  }
  /// The standby's check of the idle spare: a listing that names another attachment retires the spare, and the
  /// shard record names no spare until the reconciler provisions one.
  action sparePoll = {
    val sole = listed.get(rec.spare) == Set(rec.spareHost)
    all {
      rec.spare != "", tick(if (sole) "sparePoll" else "spareRetired", 0), unchangedRestart,
      rec' = if (sole) rec else { ...rec, spare: "", spareHost: "" },
      retired' = if (sole) retired else retired.union(Set(rec.spare)),
      replaced' = if (sole) replaced else replaced.union(Set(rec.spare)),
      listed' = listed, events' = events, unchangedStandbyAttach, foreignWritten' = foreignWritten, foreign' = foreign, unchangedChecks,
      pending' = pending, decided' = decided, procs' = procs, activations' = activations, history' = history,
      bumps' = bumps, free' = free, nextId' = nextId, flipWins' = flipWins, unchangedTakeovers,
    }
  }
  /// Whether host `h` may issue a Preempt naming key `k`: the owner the shard record names, once a bump of `E` has
  /// committed, naming its own attach's key, the key of a host whose tenure its committed takeover succeeded, past
  /// its FB an ended key that does not hold (`endedForm`), or, after its own acknowledged bump at the record's
  /// tenure, the key of the recorded pair of another host that the bumping restart's Report #1 showed holding
  /// (`bumpedForm`, amendment A1). The issuing process's Report #2 lies outside the rule.
  def preemptAdmitted(h: str, k: str): bool = {
    val admitted = h == rec.owner
    val ownKey = k == attachKey(h)
    admitted and (ownKey or succeeded(h, k) or endedForm(h, k) or bumpedForm(h, k)) and rec.e > 0
  }
  /// The bumped form of a preempt: `h` is the record-named owner with a restart whose own bump activated the record's
  /// current tenure, and `k` is the key its Report #1 captured (`armKey`).
  def bumpedForm(h: str, k: str): bool = h == rec.owner and procs.keys().exists(p => procs.get(p).restart
    and procs.get(p).host == h and procs.get(p).g == rec.g and procs.get(p).n + 1 == rec.e and armKey(p, k))
  /// The key evidence of restart `p`'s lineage preempt of key `k`: `p`'s own bump activated its tenure, and its
  /// Report #1 showed `k` holding as the key of a recorded pair, live or ended, of another host. `shown` fixes the
  /// pair at that Report, so a pair dropped before the preempt lands leaves the evidence admitted.
  def armKey(p: int, k: str): bool = activations.contains((procs.get(p).g, procs.get(p).n, p)) and shown.contains((p, k, true))
  /// The ended form of a preempt: `h` is the record-named owner with an attempt serving past its FB at the record's
  /// tenure, and `k` is the key of an ended entry and does not hold the reservation.
  def endedForm(h: str, k: str): bool = h == rec.owner and servingPastFb(h) and endedKey(k) and not(holding and holder == k)
  /// Whether an attempt of `h` at the record's current tenure is active past its FB.
  def servingPastFb(h: str): bool = procs.keys().exists(p => procs.get(p).phase == "active" and fb.keys().contains(p)
    and procs.get(p).host == h and procs.get(p).g == rec.g and procs.get(p).n + 1 == rec.e)
  /// The keys an attach entry can carry.
  pure val KEY_VALUES = KEYS.keys().map(i => KEYS.get(i))
  /// The entries of host `h`, and its newest one (0 for none).
  def entriesOf(h: str): Set[int] = rc.attaches.keys().filter(i => rc.attaches.get(i).host == h)
  def newest(h: str): int = entriesOf(h).fold(0, (m, i) => if (i > m) i else m)
  /// The key of host `h`'s newest attach, or `h` for a host with no entry.
  def attachKey(h: str): str = if (newest(h) == 0) h else rc.attaches.get(newest(h)).key
  /// Whether host `h`'s newest attach entry is live, and whether the entry under key `k` is: a process judges the
  /// attach whose key it holds, which a later attach of its host leaves ended or gone.
  def live(h: str): bool = newest(h) > 0 and rc.attaches.get(newest(h)).state == "live"
  def liveKey(k: str): bool = keyEntries(k).exists(i => rc.attaches.get(i).state == "live")
  /// The entries under key `k`.
  def keyEntries(k: str): Set[int] = rc.attaches.keys().filter(i => rc.attaches.get(i).key == k)
  /// Whether the record holds a pair under key `k`, of a live or an ended attach.
  def paired(k: str): bool = keyEntries(k).exists(i => rc.attaches.get(i).state != "gone" and rc.attaches.get(i).pair)
  /// Whether `k` is an ended key: the key of an ended entry, or of a gone one, whose gone event the record keeps.
  def endedKey(k: str): bool = keyEntries(k).exists(i => Set("ended", "gone").contains(rc.attaches.get(i).state))
  /// Whether a holder under key `k` is a recorded attachment: the record holds a pair under `k`, or `k` is an ended
  /// key, which the record names after the pair drops.
  def recordedKey(k: str): bool = paired(k) or endedKey(k)
  /// The host whose attach key `k` is, or `k` for a key no entry names.
  def keyHost(k: str): str = if (keyEntries(k) == Set()) k
    else rc.attaches.get(keyEntries(k).fold(0, (m, i) => if (i > m) i else m)).host
  /// The hosts of the retained entries, live or ended: the instances their attach entries bind.
  def retainedHosts: Set[str] = rc.attaches.keys().filter(i => rc.attaches.get(i).state != "gone")
    .map(i => rc.attaches.get(i).host)
  /// The hosts whose tenure the committed takeover `l` succeeded through committed takeover writes, each with the
  /// `E` at which its tenure was deposed: the owner `l` deposed, and, from each reached host, the owner every committed
  /// takeover by that host at a lower `E` deposed. Every takeover of the schedule commits at the record's one
  /// generation and consumes one `E`, so `E` orders the commits, and a chain holds at most one takeover per request,
  /// which `REQUESTS` rounds reach. The `E` ordering clause follows, from each reached host, only takeovers of that
  /// host's tenure at a lower `E` than the one that reached it, so a deposed owner that takes the record back at a
  /// higher `E` adds nothing to the tenures an earlier takeover succeeded.
  def deposedBy(l: (str, str, str, int, int, str, str)): Set[(str, int)] =
    1.to(REQUESTS).fold(Set((l._7, l._5)), (reached, _) => reached.union(
      lineage.filter(b => reached.exists(r => b._6 == r._1 and b._5 < r._2)).map(b => (b._7, b._5))))
  /// Whether the committed takeover `l` succeeded a tenure held under key `k`, directly or through committed
  /// takeover writes.
  def supersedes(l: (str, str, str, int, int, str, str), k: str): bool = deposedBy(l).exists(r => r._1 == k)
  /// The key under which owner `h` won its current tenure: the successor key of `h`'s latest committed takeover, or
  /// the key of `h`'s attach when no committed takeover made it owner.
  def tenureKey(h: str): str = {
    val won = lineage.filter(l => l._1 == h)
    if (won == Set()) attachKey(h) else won.fold(("", -1), (best, l) => if (l._5 > best._2) (l._6, l._5) else best)._1
  }
  /// Whether a committed takeover by `h` succeeded a tenure held under key `k`.
  /// The chain's head is `h`'s own committed request, so a transfer's row, whose request is the outgoing owner's,
  /// admits no preempt by its target, and a takeover's chain passes through it. A target whose own earlier committed
  /// takeover succeeded a tenure held under `k` keeps that takeover's admission once a transfer names it owner again.
  def succeeded(h: str, k: str): bool = lineage.exists(l => l._1 == h and procs.get(l._4).host == h and supersedes(l, k))
  /// The fresh path of the named owner at `E = 0` refuses before any device command on a listing that names another
  /// attachment, and the volume retires; each active or sent attempt of the owner at the record's generation
  /// observes the retirement trigger and withdraws in the same step.
  action freshRefuse(h: str): bool = {
    val refusing = procs.keys().filter(p => Set("active", "sent").contains(procs.get(p).phase)
      and procs.get(p).host == h and procs.get(p).g == rec.g)
    all {
      rec.owner == h, rec.e == 0, not(retired.contains(rec.active)), listed.get(rec.active) != Set(h),
      tick("freshRefuse", 0), unchangedRestart,
      retired' = retired.union(Set(rec.active)), refusedAt' = refusedAt.union(Set(rec.g)), unchangedRetirements,
      procs' = procs.keys().mapBy(p => if (refusing.contains(p)) { ...procs.get(p), phase: "withdrawn" } else procs.get(p)),
      observations' = observations.union(refusing.map(p => (p, "trigger", turn + 1))),
      commands' = commands,
      listed' = listed, events' = events, unchangedStandbyAttach, foreignWritten' = foreignWritten, foreign' = foreign, kept' = kept,
      freshChecks' = freshChecks,
      rec' = rec, pending' = pending, decided' = decided, activations' = activations, history' = history,
      bumps' = bumps, free' = free, nextId' = nextId, flipWins' = flipWins, replaced' = replaced, unchangedTakeovers,
    }
  }
  /// The store decides one outstanding request: it commits when its condition holds on the current record. A flip
  /// refused because another flip of its read generation committed first is a lost flip race.
  action decide(r: Req): bool = {
    val ok = holds(r, rec)
    val after = applied(r, rec)
    val raceLost = r.kind == "flip" and not(ok) and rec.g == r.g + 1
    all {
      pending.contains(r), tick(if (raceLost) "flipRaceLost" else "decide", r.id), unchangedRestart,
      pending' = pending.exclude(Set(r)), decided' = decided.put(r.id, ok),
      rec' = if (ok) after else rec,
      history' = if (ok) history.union(Set((after.g, after.active))) else history,
      bumps' = if (ok and r.kind != "flip") bumps.union(Set((procs.get(r.id).g, rec.g))) else bumps,
      flipWins' = if (ok and r.kind == "flip") flipWins.union(Set((r.g, r.id))) else flipWins,
      takeovers' = if (ok and r.kind == "takeover") takeovers.union(Set((rec.g, rec.active, after.g, after.active))) else takeovers,
      lineage' = if (ok and r.kind == "takeover") lineage.union(Set((r.to, r.owner, rec.standby, r.id, r.e, procs.get(r.id).key, tenureKey(r.owner))))
        else if (ok and r.kind == "transfer") lineage.union(Set((r.to, r.owner, rec.standby, r.id, r.e, attachKey(r.to), procs.get(r.id).key)))
        else lineage,
      handoffs' = if (ok and r.kind == "transfer") handoffs.union(Set({ by: r.id, fromKey: procs.get(r.id).key,
        owner: rec.owner, to: r.to, toKey: attachKey(r.to), named: rec.standby, g: r.g, vol: r.active, e: rec.e,
        after: after })) else handoffs,
      transfers' = transfers,
      procs' = procs, activations' = activations, free' = free, nextId' = nextId, replaced' = replaced,
      unchangedAttachments,
    }
  }
  /// Decides the one outstanding request.
  action decideAny = all { pending.size() == 1, nondet r = pending.oneOf() decide(r) }
  /// Decides the outstanding request of process `p`.
  action decideOf(p: int): bool = all { pending.exists(r => r.id == p), nondet r = pending.filter(r => r.id == p).oneOf() decide(r) }
  /// The process receives its request's reply: an acknowledged commit activates `(g, 2n + 2)`, a refusal ends it.
  action reply(p: int): bool = {
    val q = procs.get(p)
    all {
      procs.keys().contains(p), q.phase == "sent", decided.keys().contains(p), tick("reply", p), unchangedRestart,
      procs' = procs.set(p, { ...q, phase: if (not(decided.get(p))) "refused" else if (q.restart or q.takeover) "bumped" else "active" }),
      activations' = if (decided.get(p)) activations.union(Set((q.g, q.n, p))) else activations,
      rec' = rec, pending' = pending, decided' = decided, history' = history, bumps' = bumps, free' = free, nextId' = nextId,
      flipWins' = flipWins, replaced' = replaced, unchangedTakeovers, unchangedAttachments,
    }
  }
  /// The reply is lost or times out, whether or not the store decided the request: the attempt refuses.
  action timeout(p: int): bool = {
    val q = procs.get(p)
    val reread = false
    val adopt = reread and rec.e > 0 and rec.owner == q.host and rec.g == q.g
    all {
      procs.keys().contains(p), q.phase == "sent", tick("timeout", p), unchangedRestart,
      procs' = procs.set(p, { ...q, phase: if (adopt) "active" else "refused" }),
      activations' = if (adopt) activations.union(Set((rec.g, rec.e - 1, p))) else activations,
      rec' = rec, pending' = pending, decided' = decided, history' = history, bumps' = bumps, free' = free, nextId' = nextId,
      flipWins' = flipWins, replaced' = replaced, unchangedTakeovers, unchangedAttachments,
    }
  }
  /// Active attempt `p` observes loss `c` and withdraws in that step. A flip is observable once the record shows
  /// another `(g, owner, E)` than the attempt's.
  action observe(p: int, c: str): bool = {
    val q = procs.get(p)
    val withdraws = LOSSES.contains(c)
    all {
      procs.keys().contains(p), q.phase == "active", LOSSES.contains(c),
      c != "flipped" or rec.g != q.g or rec.owner != q.host or rec.e != q.n + 1,
      tick("observe", p), unchangedRestart,
      observations' = observations.union(Set((p, c, turn + 1))),
      procs' = procs.set(p, { ...q, phase: if (withdraws) "withdrawn" else q.phase }),
      commands' = commands,
      rec' = rec, pending' = pending, decided' = decided, activations' = activations, history' = history,
      bumps' = bumps, free' = free, nextId' = nextId, flipWins' = flipWins, replaced' = replaced, unchangedTakeovers,
      listed' = listed, events' = events, unchangedStandbyAttach, foreignWritten' = foreignWritten, foreign' = foreign,
      retired' = retired, kept' = kept, freshChecks' = freshChecks, refusedAt' = refusedAt, unchangedRetirements,
    }
  }
  /// Active attempt `p` takes a command action under its tenure: a medium write, a confirm or a reservation
  /// command.
  action command(p: int): bool = {
    val q = procs.get(p)
    all {
      procs.keys().contains(p), fb.keys().contains(p), q.phase == "active", tick("command", p),
      holding' = holding, holder' = holder, preempts' = preempts, held' = held, queued' = queued, landed' = landed, fb' = fb, recordsRead' = recordsRead,
      deviceActs' = deviceActs, fencing' = fencing, writes' = writes.union(Set((p, turn + 1))),
      commands' = commands.union(Set((p, turn + 1))),
      observations' = observations,
      unchangedShard, listed' = listed, events' = events, unchangedStandbyAttach, foreignWritten' = foreignWritten, foreign' = foreign,
      retired' = retired, kept' = kept, freshChecks' = freshChecks, refusedAt' = refusedAt, unchangedRetirements,
    }
  }
  /// A serving attempt of the record's current tenure, active past its FB at the record's generation and `E`.
  def serving(p: int): bool = procs.keys().contains(p) and procs.get(p).phase == "active" and fb.keys().contains(p)
    and procs.get(p).host == rec.owner and procs.get(p).g == rec.g and procs.get(p).n + 1 == rec.e
  /// The planned exit of serving attempt `p` starts: the owner stops mutation admission and publishes and certifies
  /// its recoverable cut; hits continue. `command` admits an active attempt alone, so
  /// the drain's own medium writes, the publish and the certify, are the suffix model's, and the tenure invariants
  /// judge the withdrawal and the transfer, whichever phase they follow.
  action planDrain(p: int): bool = all {
    serving(p), tick("planDrain", p), procs' = procs.set(p, { ...procs.get(p), phase: "draining" }), unchangedRecords,
    unchangedRestart, unchangedAttachments,
  }
  /// A planned exit that fails before the withdrawal resumes in place (D21): the same tenure serves again and no `E`
  /// is consumed.
  action planResume(p: int): bool = {
    val q = procs.get(p)
    val resumable = q.phase == "draining"
    all {
      procs.keys().contains(p), resumable, tick("planResume", p), procs' = procs.set(p, { ...q, phase: "active" }),
      unchangedRecords, unchangedRestart, unchangedAttachments,
    }
  }
  /// The planned restart of a draining owner, the deploy restart and the roll: it withdraws for the planned change,
  /// issues no transfer and exits, and its host's next incarnation runs the same-host restart.
  action planRestart(p: int): bool = {
    val q = procs.get(p)
    all {
      procs.keys().contains(p), q.phase == "draining", tick("planRestart", p),
      procs' = procs.set(p, { ...q, phase: "withdrawn" }),
      observations' = observations.union(Set((p, "planned", turn + 1))), commands' = commands,
      unchangedRecords, unchangedRestart, listed' = listed, events' = events, unchangedStandbyAttach,
      foreignWritten' = foreignWritten, foreign' = foreign, retired' = retired, kept' = kept, freshChecks' = freshChecks,
      refusedAt' = refusedAt, unchangedRetirements,
    }
  }
  /// The draining owner withdraws for the planned change and, in the same step, issues the transfer write (A2, D19):
  /// its view of the records names its own tenure `(g, active, owner, E)` and a standby, with two attempts left at or
  /// below `EMAX`, the bound of every write the model searches: the transfer consumes one and the target's own bump
  /// the other, so a handoff that commits leaves its target an attempt to activate with. The write, the model's
  /// field-conditioned form of the exact-version write, conditioned on that tenure and that standby names the standby
  /// owner at `E + 1` and no standby. The request reuses the attempt's id, whose bump decision it replaces, so it
  /// issues only once the store holds no other request under that id: the next decision the store records there is
  /// the transfer's. The withdrawn attempt takes no command action and mints no session.
  action transferStart(p: int): bool = {
    val q = procs.get(p)
    val request = { id: p, kind: "transfer", g: rec.g, active: rec.active, owner: rec.owner, e: rec.e, spare: "",
      spareHost: "", to: rec.standby }
    all {
      procs.keys().contains(p), q.phase == "draining", fb.keys().contains(p), q.host == rec.owner, q.g == rec.g,
      q.n + 1 == rec.e, rec.e + 1 < EMAX, rec.standby != "", not(retired.contains(rec.active)),
      not(pending.exists(r => r.id == p)), tick("transferStart", p),
      procs' = procs.set(p, { ...q, phase: "transferring" }),
      pending' = pending.union(Set(request)), transfers' = transfers.union(Set((p, turn + 1))),
      observations' = observations.union(Set((p, "planned", turn + 1))), commands' = commands,
      rec' = rec, decided' = decided, activations' = activations, history' = history, bumps' = bumps, free' = free,
      nextId' = nextId, flipWins' = flipWins, replaced' = replaced, takeovers' = takeovers, lineage' = lineage,
      handoffs' = handoffs, unchangedRestart, listed' = listed, events' = events, unchangedStandbyAttach,
      foreignWritten' = foreignWritten, foreign' = foreign, retired' = retired, kept' = kept, freshChecks' = freshChecks,
      refusedAt' = refusedAt, unchangedRetirements,
    }
  }
  /// The transfer's reply after the store decided it: an acknowledged commit ends the outgoing owner, which exits
  /// (`transferred`), and a refusal leaves it `transferRefused`. Neither mints a session. The reply reads the
  /// transfer's own decision: from its issue the transfer is the one request the store holds under the attempt's id,
  /// so the reply waits until the store decided it.
  action transferReply(p: int): bool = {
    val q = procs.get(p)
    all {
      procs.keys().contains(p), q.phase == "transferring", not(pending.exists(r => r.id == p)),
      decided.keys().contains(p), tick("transferReply", p),
      procs' = procs.set(p, { ...q, phase: if (decided.get(p)) "transferred" else "transferRefused" }),
      activations' = activations,
      rec' = rec, pending' = pending, decided' = decided, history' = history, bumps' = bumps, free' = free, nextId' = nextId,
      flipWins' = flipWins, replaced' = replaced, unchangedTakeovers, unchangedRestart, unchangedAttachments,
    }
  }
  /// The transfer's reply is lost or times out, whether or not the store decided it (`transferUnknown`), the outgoing
  /// attempt's exit. After a refusal or an unknown outcome the withdrawn attempt never resumes, and its host's record
  /// read is the owner guard of `restartRecords`: the same-host restart runs only while the record still names the
  /// host owner, so after a committed transfer the host starts no later attempt.
  action transferTimeout(p: int): bool = {
    val q = procs.get(p)
    all {
      procs.keys().contains(p), q.phase == "transferring", tick("transferTimeout", p),
      procs' = procs.set(p, { ...q, phase: "transferUnknown" }),
      unchangedRecords, unchangedRestart, unchangedAttachments,
    }
  }
  /// A mid-tenure controller event ends the incarnation of active process `p` of the record's current tenure with one
  /// write of it
  /// card-held. A reset also leaves one write outstanding, which the self Preempt-and-Abort aborts, and keeps the
  /// registration only when `keep`; an Abort or a queue delete ends the outstanding write at the card with its
  /// status and keeps the registration. The ended incarnation's record read and device commands no longer count for
  /// `RecordsBeforeDevice`, so a later command of `p` needs a new record read.
  action midTenure(p: int, c: str, keep: bool): bool = {
    val q = procs.get(p)
    all {
      procs.keys().contains(p), fb.keys().contains(p), q.phase == "active", EVENTS.contains(c), q.host == rec.owner,
      q.g == rec.g, q.n + 1 == rec.e, held == 0, queued == 0,
      advance("midTenure", p),
      rc' = if (c == "reset" and not(keep)) { ...rc, regs: rc.regs.exclude(Set(q.key)) } else rc,
      procs' = procs.set(p, { ...q, phase: "ended" }),
      held' = 1, queued' = if (c == "reset") 1 else 0, holding' = if (c == "reset") keep else holding, holder' = if (c == "reset" and not(keep)) "" else holder, preempts' = preempts,
      landed' = landed, fb' = fb, recordsRead' = recordsRead.filter(r => r._1 != p),
      deviceActs' = deviceActs.exclude(Set(p)), fencing' = fencing, writes' = writes.union(Set((p, turn + 1))),
      unchangedRecords, unchangedAttachments,
    }
  }
  /// A card-held write of the ended incarnation completes at the card.
  action land = all {
    held > 0, tick("land", 0),
    held' = held - 1, landed' = landed.union(Set(turn + 1)),
    holding' = holding, holder' = holder, preempts' = preempts, queued' = queued, fb' = fb, recordsRead' = recordsRead, deviceActs' = deviceActs, fencing' = fencing, writes' = writes,
    unchangedShard, unchangedAttachments,
  }
  /// An outstanding write of the ended incarnation lands.
  action landQueued = all {
    queued > 0, tick("landQueued", 0),
    queued' = queued - 1, landed' = landed.union(Set(turn + 1)),
    holding' = holding, holder' = holder, preempts' = preempts, held' = held, fb' = fb, recordsRead' = recordsRead, deviceActs' = deviceActs, fencing' = fencing, writes' = writes,
    unchangedShard, unchangedAttachments,
  }
  /// Step 1 of the restart of host `h`, once every earlier process of `h` ended: the shard and volume records,
  /// which name `h` the owner of the active volume, and the volume record's entry for `h`'s newest attach, which must
  /// be live with its pair recorded (`ownAttach`, the enrolled own pair of Rust's step 2): a host whose own attach
  /// ended starts no restart, so it issues no device command, bump or Register. `recordsRead` records whether the
  /// read passed.
  action restartRecords(h: str): bool = {
    val adopts = adoptsHeldBump and procs.keys().exists(p => procs.get(p).restart and procs.get(p).host == h
      and procs.get(p).phase == "refusedDevice" and procs.get(p).g == rec.g and procs.get(p).n + 1 == rec.e)
    val ended = procs.keys().forall(p => procs.get(p).host != h or Set("ended", "refused", "refusedRecorded", "refusedUnheld", "refusedForeign", "refusedDevice", "withdrawn", "transferred", "transferRefused", "transferUnknown").contains(procs.get(p).phase))
    val ownAttach = live(h) and paired(attachKey(h))
    all {
      nextId <= REQUESTS, rec.owner == h, rec.e > 0, rec.e < EMAX, ownAttach, not(retired.contains(rec.active)), ended,
      tick("restartRecords", nextId),
      procs' = procs.put(nextId, if (adopts) { host: h, phase: "bumped", g: rec.g, n: rec.e - 1, vol: rec.active, restart: true, takeover: false, prkey: "", key: attachKey(h) }
        else { host: h, phase: "records", g: rec.g, n: rec.e, vol: rec.active, restart: true, takeover: false, prkey: "", key: attachKey(h) }),
      nextId' = nextId + 1,
      recordsRead' = recordsRead.union(Set((nextId, rec.owner == h and rec.e > 0 and not(retired.contains(rec.active))
        and live(h) and paired(attachKey(h))))),
      holding' = holding, holder' = holder, preempts' = preempts, held' = held, queued' = queued, landed' = landed, fb' = fb, deviceActs' = deviceActs, fencing' = fencing, writes' = writes,
      activations' = if (adopts) activations.union(Set((rec.g, rec.e - 1, nextId))) else activations,
        rec' = rec, pending' = pending, decided' = decided, history' = history,
      bumps' = bumps, free' = free, flipWins' = flipWins, replaced' = replaced, unchangedTakeovers, unchangedAttachments,
    }
  }
  /// Restart `p` moves to device phase `dest` from `from`, issuing a device command.
  action restartDevice(p: int, from: str, dest: str): bool = deviceStep(p, from, dest, procs.get(p).prkey, false)
  /// Process `p` moves to device phase `dest` from `from`, issuing a device command, with `k` as the key it captured
  /// for its preempt; `fences` records a Register or a preempt among the command.
  action deviceStep(p: int, from: str, dest: str, k: str, fences: bool): bool = {
    val q = procs.get(p)
    val admitted = q.phase == from
    all {
      procs.keys().contains(p), admitted,
      procs' = procs.set(p, { ...q, phase: dest, prkey: k }),
      deviceActs' = deviceActs.union(Set(p)), fencing' = if (fences) fencing.union(Set(p)) else fencing, writes' = writes,
    }
  }
  /// Step 3: the controller reports ready once no write of the ended incarnation is card-held.
  action restartReady(p: int): bool = all {
    held == 0 or (skipsDrainAfterHold and procs.keys().exists(r => r < p and procs.get(r).restart
      and procs.get(r).host == procs.get(p).host and procs.get(r).phase == "refusedDevice")),
    tick("restartReady", p), restartDevice(p, "records", "ready"),
    holding' = holding, holder' = holder, preempts' = preempts, held' = held, queued' = queued, landed' = landed, fb' = fb, recordsRead' = recordsRead,
    unchangedRecords, unchangedAttachments,
  }
  /// Step 5: Report #1 shows the own pair holding, or a recorded pair of another host holding, which takes the
  /// lineage arm (D20): the restart captures the holder's key for its preempt (`reportedHolder`) and goes on to its own
  /// bump. Otherwise the restart refuses: `refusedRecorded` on a recorded pair of another attach of its own host or
  /// on a holder under an ended key whose pair the record dropped, and `refusedUnheld` when nobody holds
  /// (NO-HOLDER-HOLD), both with no retirement, and `refusedForeign` on an unrecorded holder. The arm admits a
  /// recorded pair of a live or an ended attach. `UNRECORDED`, the one registrant no entry names, holds, so a Report
  /// with nobody holding shows only recorded registrants and the branch tests `holding` alone. The model has no registrant rows, host-ID aliases or inconclusive counts; Rust's
  /// registrant-membership, own-host-ID and count checks of NO-HOLDER-HOLD are Rust test boundaries
  /// (no-holder-hold-retains-volume). `shown` records the holder and whether its key is the key of a recorded pair of
  /// another host at this Report, the fact a lineage preempt's key evidence reads.
  action restartReport1(p: int): bool = {
    val q = procs.get(p)
    val lineageHolder = holding and holder != q.key and paired(holder) and keyHost(holder) != q.host
    val dest = if (holding and holder == q.key) "reported" else if (not(holding)) "refusedUnheld"
      else if (lineageHolder) "reportedHolder" else if (recordedKey(holder)) "refusedRecorded" else "refusedForeign"
    all {
      tick("restartReport1", p), deviceStep(p, "ready", dest, if (lineageHolder) holder else "", false),
      holding' = holding, holder' = holder, preempts' = preempts, held' = held, queued' = queued, landed' = landed, fb' = fb, recordsRead' = recordsRead,
      unchangedRecords,
      listed' = listed, events' = events, unchangedStandbyAttach, foreignWritten' = foreignWritten, foreign' = foreign, retired' = retired,
      kept' = kept, freshChecks' = freshChecks, refusedAt' = refusedAt, unchangedLoss,
      restartRetired' = restartRetired,
      shown' = shown.union(Set((p, if (holding) holder else "", holding and paired(holder) and keyHost(holder) != q.host))),
    }
  }
  /// A restart refusal requesting a flip retires the volume at the exact target its records held.
  /// A recorded pair of another host takes the lineage arm, and nobody holding and a device failure refuse without a
  /// flip, so interrupted takeovers and host-local faults preserve the volume.
  action restartRetire(p: int): bool = {
    val q = procs.get(p)
    all {
      procs.keys().contains(p), q.restart, q.phase == "refusedForeign", rec.owner == q.host,
      rec.g == q.g, rec.e == q.n, advance("restartRetire", p), unchangedRestart,
      rc' = { ...rc, retiredOn: rc.retiredOn.union(Set(holder)) },
      retired' = retired.union(Set(q.vol)), restartRetired' = restartRetired.union(Set((p, q.phase))), shown' = shown,
      listed' = listed, events' = events, unchangedStandbyAttach, foreignWritten' = foreignWritten, foreign' = foreign,
      kept' = kept, freshChecks' = freshChecks, refusedAt' = refusedAt, unchangedLoss,
      unchangedShard,
    }
  }
  /// DEVICE-FAILURE-HOLD: a device step of restart `p` ends without success, whatever its status: from `records` the
  /// ready wait, from `ready` the host ID or Report #1, from `bumped` the self preempt or the arm's Register, from
  /// `reread` the arm's lineage preempt and from `preempted` Report #2; the arm's failed step is the one
  /// RECORDED-HOLDER-HOLD left to a restart. A failed Register or preempt is an issued fencing command (`fencing`).
  /// The restart refuses into `refusedDevice` with the command issued and no retirement; a hold from `bumped`,
  /// `reread` or `preempted` keeps the activation of its bump, reaches no FB, and the bump stays consumed, so a rerun
  /// takes the next `E`. `deviceFailureServes` is the control whose failed
  /// step proceeds to FB.
  action restartDeviceFail(p: int): bool = {
    val q = procs.get(p)
    all {
      procs.keys().contains(p), q.restart, Set("records", "ready", "bumped", "reread", "preempted").contains(q.phase),
      tick("restartDeviceFail", p),
      deviceStep(p, q.phase, if (deviceFailureServes) "active" else "refusedDevice", q.prkey,
        Set("bumped", "reread").contains(q.phase)),
      fb' = if (deviceFailureServes) fb.put(p, turn + 1) else fb,
      holding' = holding, holder' = holder, preempts' = preempts, held' = held, queued' = queued, landed' = landed, recordsRead' = recordsRead,
      unchangedRecords, unchangedAttachments,
    }
  }
  /// `deviceFailureServes` lets a failed device step reach FB; `adoptsHeldBump` lets a rerun after a post-bump hold
  /// resume at the held attempt's `E` without its own bump; `skipsDrainAfterHold` lets a rerun after a hold report
  /// ready with a write card-held. Each is a control that a safety invariant must refuse.
  val deviceFailureServes = false
  val adoptsHeldBump = false
  val skipsDrainAfterHold = false
  /// Step 6: the bump `E: n -> n + 1` conditioned on the records step 1 read, on the own path and on the arm. A
  /// takeover, whose Report #1 also leaves it `reported`, issues no bump.
  action restartBump(p: int): bool = {
    val q = procs.get(p)
    val request = { id: p, kind: "bump", g: q.g, active: q.vol, owner: q.host, e: q.n, spare: "", spareHost: "", to: "" }
    all {
      procs.keys().contains(p), q.restart, Set("reported", "reportedHolder").contains(q.phase), tick("restartBump", p),
      pending' = pending.union(Set(request)),
      procs' = procs.set(p, { ...q, phase: "sent" }),
      holding' = holding, holder' = holder, preempts' = preempts, held' = held, queued' = queued, landed' = landed, fb' = fb, recordsRead' = recordsRead,
      deviceActs' = deviceActs, fencing' = fencing, writes' = writes,
      rec' = rec, decided' = decided, activations' = activations, history' = history, bumps' = bumps, free' = free,
      nextId' = nextId, flipWins' = flipWins, replaced' = replaced, unchangedTakeovers, unchangedAttachments,
    }
  }
  /// Step 7: the self Preempt-and-Abort after the acknowledged bump. It aborts the ended incarnation's outstanding
  /// writes, or returns success while unregistering its caller when `unregisters`.
  action restartPreempt(p: int, unregisters: bool): bool = all {
    holding, procs.keys().contains(p), not(procs.get(p).takeover), procs.get(p).prkey == "", advance("restartPreempt", p),
    rc' = if (unregisters) { ...rc, regs: rc.regs.exclude(Set(procs.get(p).key)) } else rc,
    deviceStep(p, "bumped", "preempted", "", true),
    holding' = not(unregisters), holder' = if (unregisters) "" else holder, preempts' = preempts.union(Set((procs.get(p).host, procs.get(p).key, true))), queued' = if (unregisters) queued else 0,
    held' = held, landed' = landed, fb' = fb, recordsRead' = recordsRead,
    unchangedRecords, unchangedAttachments,
  }
  /// The lineage arm's Register (D20), after the acknowledged bump of a restart whose Report #1 showed a recorded
  /// pair of another host holding: it adds the restart's own key.
  action restartRegister(p: int): bool = {
    val q = procs.get(p)
    val bumped = q.phase == "bumped"
    all {
      procs.keys().contains(p), q.restart, q.prkey != "", bumped, advance("restartRegister", p),
      rc' = { ...rc, regs: rc.regs.union(Set(q.key)) },
      deviceStep(p, q.phase, "registered", q.prkey, true),
      holding' = holding, holder' = holder, preempts' = preempts, held' = held, queued' = queued, landed' = landed,
      fb' = fb, recordsRead' = recordsRead, unchangedRecords, unchangedAttachments,
    }
  }
  /// The lineage arm's shard reread after its Register: the record must still name the tenure the restart's bump
  /// activated, `(g, owner, E)`, with the restart's attach live, and the restart goes on to its preempt (`reread`);
  /// a reread that shows another tenure refuses with no preempt. `rc.rereads` records what the reread showed.
  action restartReread(p: int): bool = {
    val q = procs.get(p)
    val named = rec.g == q.g and rec.owner == q.host and rec.e == q.n + 1 and liveKey(q.key)
    val passes = named
    all {
      procs.keys().contains(p), q.restart, q.phase == "registered", advance("restartReread", p),
      rc' = { ...rc, rereads: rc.rereads.union(Set((p, named))) },
      procs' = procs.set(p, { ...q, phase: if (passes) "reread" else "refused" }),
      unchangedRestart, unchangedRecords, unchangedAttachments,
    }
  }
  /// The lineage arm's Preempt-and-Abort after a reread that named its tenure, issued and landing in a later step,
  /// whichever owner the record names by then: it names the key Report #1 captured, which passes the reservation to
  /// the issuer when it is the holder's. The issued key's evidence is the bumped form of the issuance rule, fixed at
  /// Report #1 and at the reread: the reread named the tenure this attempt's own acknowledged bump activated
  /// (`rc.rereads`), and Report #1 showed the key holding as the recorded pair of another host (`armKey`). A pair
  /// dropped between the reread and the landing leaves that evidence admitted. As for a takeover
  /// preempt, the device takes the command only from a registered issuer: an issuer whose key no longer holds a
  /// registration refuses with no effect. `preempts` records the command the device took, and
  /// `NoPreemptOfForeignKey` judges the key of a taken and of a refused command in the state this action leaves.
  action restartLineagePreempt(p: int): bool = {
    val q = procs.get(p)
    val issuerRegistered = rc.regs.contains(q.key)
    all {
      procs.keys().contains(p), q.restart, holding, advance("restartLineagePreempt", p),
      rc' = if (issuerRegistered) { ...rc, regs: rc.regs.exclude(Set(q.prkey)) } else rc,
      deviceStep(p, "reread", if (issuerRegistered) "preempted" else "refused", q.prkey, true),
      holding' = holding, holder' = if (issuerRegistered and holder == q.prkey) q.key else holder,
      preempts' = if (issuerRegistered) preempts.union(Set((q.host, q.prkey, rc.rereads.contains((p, true))
        and armKey(p, q.prkey)))) else preempts,
      held' = held, queued' = queued, landed' = landed, fb' = fb, recordsRead' = recordsRead,
      unchangedRecords, unchangedAttachments,
    }
  }
  /// `interruptedRetires` is a retirement at a successor's start while an earlier successor stopped after its CAS.
  val interruptedRetires = false
  /// Host `h` reads the records, which name another host owner of the retained active volume at `E > 0`. The
  /// standby the record names submits the takeover CAS: owner `:= h`, `E: n -> n + 1`, no standby, conditioned on
  /// `(g, active, owner, n)` and the standby; any other host refuses with no request. The process keeps the owner it
  /// read, its predecessor, as `prkey`. The start does not require a holder: a takeover between the owner's bump and
  /// its fresh Report finds nobody holding, its Report #1 refuses with no preempt, and its successor's restart refuses
  /// `refusedUnheld`. That takeover is an abstract witness: Rust enrolls a standby only after the owner's fresh
  /// Report fenced page 0 (OWNER-FENCED-BEFORE-STANDBY), so no Rust takeover commits before that Report. A serving
  /// Report with nobody holding is a Rust test boundary (no-holder-hold-retains-volume). The takeover schedules keep a registration once it holds: their mid-tenure event is an Abort
  /// that keeps it and their self preempt keeps its caller, and they end no attach, so every holder is a host's
  /// live attach; the reclaim schedule ends attaches. A standby whose newest attach entry is ended refuses with no
  /// request (`EndedGrantsNothing`).
  action takeoverStart(h: str): bool = {
    val named = rec.standby == h and live(h) and paired(attachKey(h))
    val request = { id: nextId, kind: "takeover", g: rec.g, active: rec.active, owner: rec.owner, e: rec.e, spare: "", spareHost: "", to: h }
    all {
      nextId <= REQUESTS, rec.owner != h, rec.e > 0, rec.e < EMAX, not(retired.contains(rec.active)),
      advance("takeoverStart", nextId),
      rc' = if (named) { ...rc, grants: rc.grants.union(Set(("cas", nextId, not(live(h) and paired(attachKey(h)))))) } else rc,
      pending' = if (named) pending.union(Set(request)) else pending,
      procs' = procs.put(nextId, { host: h, phase: if (named) "sent" else "refused", g: rec.g, n: rec.e, vol: rec.active, restart: false, takeover: true, prkey: rec.owner, key: attachKey(h) }),
      nextId' = nextId + 1,
      recordsRead' = recordsRead.union(Set((nextId, named and rec.e > 0 and not(retired.contains(rec.active))))),
      retired' = if (interruptedRetires and procs.keys().exists(p => procs.get(p).takeover and procs.get(p).phase == "bumped")) retired.union(Set(rec.active)) else retired,
      holding' = holding, holder' = holder, preempts' = preempts, held' = held, queued' = queued, landed' = landed, fb' = fb, deviceActs' = deviceActs, fencing' = fencing, writes' = writes,
      rec' = rec, decided' = decided, activations' = activations, history' = history, bumps' = bumps, free' = free,
      flipWins' = flipWins, replaced' = replaced, unchangedTakeovers,
      listed' = listed, events' = events, unchangedStandbyAttach, foreignWritten' = foreignWritten, foreign' = foreign, unchangedChecks,
    }
  }
  /// The enrollment function names `h`, a host other than the owner whose newest attach is live and enrolled, as the
  /// record's standby.
  action nameStandby(h: str): bool = all {
    HOSTS.contains(h), h != rec.owner, rec.standby != h, live(h), paired(attachKey(h)), advance("nameStandby", 0),
    unchangedRestart,
    rc' = if (newest(h) > 0 and rc.attaches.get(newest(h)).state == "live" and rc.attaches.get(newest(h)).pair) rc
      else { ...rc, grants: rc.grants.union(Set(("name", newest(h), true))) },
    rec' = { ...rec, standby: h },
    pending' = pending, decided' = decided, procs' = procs, activations' = activations, history' = history,
    bumps' = bumps, free' = free, nextId' = nextId, flipWins' = flipWins, replaced' = replaced, unchangedTakeovers,
    unchangedAttachments,
  }
  /// Register, then Report #1 of a takeover process whose CAS reply acknowledged the commit, with the tenure check that
  /// precedes the preempt, as one step. Register relies on the takeover's record read and adds the process's key;
  /// only Reports read the registrations, and they judge each key by its own entry, so a Report that runs between
  /// Register and Report #1 judges the registration as it does after them. The tenure check rereads the entry under
  /// the process's key and refuses when it is no longer live. Report #1 admits the holder only when it is a recorded
  /// pair of another host and the record still
  /// names the issuer's tenure, and captures its key; an unrecorded holder, the own host, nobody holding and a
  /// superseded issuer refuse with no preempt. One step stands for Rust's Report #1 and its later shard read: the
  /// issuer's acknowledged CAS precedes Report #1 and `E` only rises, so a record that names the issuer's tenure at
  /// the later read named it at Report #1 too, and `takeoverPreempt` rechecks nothing, which admits more schedules
  /// than Rust's `Superseded` refusal at that read.
  action takeoverReport1(p: int): bool = {
    val q = procs.get(p)
    val current = rec.g == q.g and rec.owner == q.host and rec.e == q.n + 1 and liveKey(q.key)
    val recordedHolder = holding and holder != q.key and paired(holder) and keyHost(holder) != q.host
    val admitted = recordedHolder and current
    all {
      procs.keys().contains(p), q.takeover, q.phase == "bumped", advance("takeoverReport1", p),
      rc' = { ...rc, regs: rc.regs.union(Set(q.key)) },
      procs' = procs.set(p, { ...q, phase: if (admitted) "reported" else "refused", prkey: holder }),
      deviceActs' = deviceActs.union(Set(p)), fencing' = fencing.union(Set(p)), writes' = writes,
      holding' = holding, holder' = holder, preempts' = preempts, held' = held, queued' = queued, landed' = landed, fb' = fb, recordsRead' = recordsRead,
      unchangedRecords, unchangedAttachments,
    }
  }
  /// The successor's Preempt-and-Abort of the captured holder's key, whichever owner the record names by then. The
  /// device takes it only from a registrant: once the issuer's own key lost its registration, the preempt refuses
  /// with no effect and the process refuses.
  /// The reservation passes to the issuer only when that key is the holder's, and the issued key's evidence, this
  /// attempt's own committed and acknowledged takeover succeeding a tenure of that key's host, is recorded either way.
  action takeoverPreempt(p: int): bool = {
    val q = procs.get(p)
    val registered = rc.regs.contains(q.key)
    all {
      procs.keys().contains(p), q.takeover, holding, advance("takeoverPreempt", p),
      rc' = if (registered) { ...rc, regs: rc.regs.exclude(Set(q.prkey)) } else rc,
      deviceStep(p, "reported", if (registered) "preempted" else "refused", q.prkey, true),
      holding' = holding, holder' = if (registered and holder == q.prkey) q.key else holder,
      preempts' = if (registered) preempts.union(Set((q.host, q.prkey,
        lineage.exists(l => l._4 == p and l._1 == q.host and supersedes(l, q.prkey)) and activations.exists(a => a._3 == p))))
        else preempts,
      held' = held, queued' = queued, landed' = landed, fb' = fb, recordsRead' = recordsRead,
      unchangedRecords, unchangedAttachments,
    }
  }
  /// A successor stops after its own acknowledged CAS and before preempting; its next process starts from records.
  action takeoverCrash(p: int): bool = all {
    procs.keys().contains(p), procs.get(p).takeover, Set("bumped", "reported").contains(procs.get(p).phase),
    tick("takeoverCrash", p),
    procs' = procs.set(p, { ...procs.get(p), phase: "ended" }),
    unchangedRecords, unchangedAttachments, unchangedRestart,
  }
  /// Step 8: Report #2 confirms the own pair still holds, and the restart reaches FB; otherwise it refuses. A takeover
  /// and the lineage arm, whose preempt named another host's key, also require the record to name the tenure their
  /// own write activated, so a preempt that lands after the record moved reaches no FB. `rc.rereads` records what
  /// the arm's Report #2 read of the shard record showed.
  action restartReport2(p: int): bool = {
    val q = procs.get(p)
    val confirmed = holding and holder == q.key
      and ((not(q.takeover) and q.prkey == "") or (rec.owner == q.host and rec.e == q.n + 1))
      and liveKey(q.key)
    val arm = q.restart and q.prkey != ""
    val shows = rec.owner == q.host and rec.g == q.g and rec.e == q.n + 1 and liveKey(q.key)
    all {
      advance("restartReport2", p), restartDevice(p, "preempted", if (confirmed) "active" else "refused"),
      rc' = { ...rc, grants: if (confirmed) rc.grants.union(Set(("fb", p, not(liveKey(q.key))))) else rc.grants,
        rereads: if (arm) rc.rereads.union(Set((p, shows))) else rc.rereads },
      fb' = if (confirmed) fb.put(p, turn + 1) else fb,
      holding' = holding, holder' = holder, preempts' = preempts, held' = held, queued' = queued, landed' = landed, recordsRead' = recordsRead,
      unchangedRecords, unchangedAttachments,
    }
  }
  /// The fresh path of attempt `p` at `E = 0` after its acknowledged bump: the host ID, Register, type-2 Acquire and
  /// the fresh Report, which shows the own pair holding and reaches FB.
  action freshReport(p: int): bool = {
    val q = procs.get(p)
    all {
      procs.keys().contains(p), not(q.restart), q.n == 0, not(fb.keys().contains(p)), advance("freshReport", p),
      rc' = { ...rc, regs: rc.regs.union(Set(q.key)) },
      deviceStep(p, "active", "active", "", true),
      fb' = fb.put(p, turn + 1), holding' = true, holder' = q.key, preempts' = preempts, held' = held, queued' = queued, landed' = landed,
      recordsRead' = recordsRead, unchangedRecords, unchangedAttachments,
    }
  }
  /// Fresh attempt `p` writes the medium, the activation record first, once its fresh Report reached FB.
  action freshWrite(p: int): bool = {
    val q = procs.get(p)
    val fenced = q.phase == "active" and fb.keys().contains(p)
    all {
      procs.keys().contains(p), not(q.restart), fenced, tick("freshWrite", p),
      writes' = writes.union(Set((p, turn + 1))), deviceActs' = deviceActs.union(Set(p)), fencing' = fencing,
      holding' = holding, holder' = holder, preempts' = preempts, held' = held, queued' = queued, landed' = landed, fb' = fb, recordsRead' = recordsRead,
      unchangedShard, unchangedAttachments,
    }
  }
  action step = any {
    nondet h = HOSTS.oneOf()
    start(h),
    requestFlip,
    nondet v = Set("v3", "v4").oneOf()
    nondet h = HOSTS.oneOf()
    spare(v, h),
    nondet r = pending.union(Set({ id: 0, kind: "none", g: 0, active: "", owner: "", e: 0, spare: "", spareHost: "", to: "" })).oneOf()
    decide(r),
    nondet p = 1.to(REQUESTS).oneOf()
    any { reply(p), timeout(p) },
    nondet v = VOLUMES.oneOf()
    nondet stale = Set(true, false).oneOf()
    any { foreignAttach(v, stale), foreignWrite(v), foreignDetach(v) },
    nondet h = HOSTS.oneOf()
    any { standbyRecord(h), standbyBind(h), standbyAttach(h) },
    poll,
    sparePoll,
    nondet h = HOSTS.oneOf()
    freshRefuse(h),
    nondet p = 1.to(REQUESTS).oneOf()
    nondet c = LOSSES.oneOf()
    any { observe(p, c), command(p), freshReport(p) },
  }

  /// The restart schedules, which the restart invariants check under: the owner's fresh activation at `E = 0`, a
  /// reconciler's flip, mid-tenure events, landings and the restart sequence of the owner, with the store deciding
  /// its requests in any order. `step` holds the cross-host schedules, whose attempts never restart.
  action restartStep = any {
    all { rec.e == 0, start("h1") },
    requestFlip,
    nondet r = pending.union(Set({ id: 0, kind: "none", g: 0, active: "", owner: "", e: 0, spare: "", spareHost: "", to: "" })).oneOf()
    decide(r),
    nondet p = 1.to(REQUESTS).oneOf()
    any { reply(p), timeout(p) },
    nondet p = 1.to(REQUESTS).oneOf()
    nondet c = EVENTS.oneOf()
    nondet keep = Set(true, false).oneOf()
    midTenure(p, c, keep),
    land,
    landQueued,
    restartRecords("h1"),
    nondet p = 1.to(REQUESTS).oneOf()
    nondet unregisters = Set(true, false).oneOf()
    any { restartReady(p), restartReport1(p), restartBump(p), restartPreempt(p, unregisters), restartReport2(p),
      restartDeviceFail(p), freshReport(p), freshWrite(p) },
  }

  /// The takeover schedules: the owner's fresh activation at `E = 0`, a mid-tenure Abort that keeps the registration
  /// and the owner's restart sequence, whose self preempt keeps its caller, racing the standby's takeover on one record, standby designations, takeovers by named and unnamed
  /// hosts with their Reports and preempts, with the store deciding requests in any order.
  action takeoverStep = any {
    all { rec.e == 0, start("h1") },
    nondet r = pending.union(Set({ id: 0, kind: "none", g: 0, active: "", owner: "", e: 0, spare: "", spareHost: "", to: "" })).oneOf()
    decide(r),
    nondet p = 1.to(REQUESTS).oneOf()
    any { reply(p), timeout(p) },
    nondet p = 1.to(REQUESTS).oneOf()
    midTenure(p, "abort", true),
    land,
    nondet h = HOSTS.oneOf()
    restartRecords(h),
    nondet h = HOSTS.oneOf()
    any { takeoverStart(h), nameStandby(h) },
    nondet p = 1.to(REQUESTS).oneOf()
    any { restartReady(p), restartReport1(p), restartBump(p), restartPreempt(p, false), restartRegister(p),
      restartReread(p), restartLineagePreempt(p), restartReport2(p), restartDeviceFail(p), freshReport(p),
      takeoverReport1(p),
      takeoverPreempt(p), takeoverCrash(p), restartRetire(p) },
    reportPoll,
    nondet unrecorded = Set(false, true).oneOf()
    statusDeposition(unrecorded),
  }

  /// The reclaim schedule over `reclaimInit`, whose owner serves past its FB: attach entries recorded,
  /// requested, landing, failing or landing late, enrolled, ended, dropped, detached and marked gone, standby
  /// designations and takeovers with their Register, Reports and preempts, a record-named owner's restart with its
  /// lineage arm, ended-key preempts landing late or with no effect, and the owner's listing-first poll and its
  /// Report, with the store deciding requests in any order.
  action reclaimStep = any {
    nondet r = pending.union(Set({ id: 0, kind: "none", g: 0, active: "", owner: "", e: 0, spare: "", spareHost: "", to: "" })).oneOf()
    decide(r),
    nondet p = 1.to(REQUESTS).oneOf()
    any { reply(p), timeout(p), takeoverReport1(p), takeoverPreempt(p), takeoverCrash(p), restartReport2(p),
      restartReady(p), restartReport1(p), restartBump(p), restartPreempt(p, false), restartRegister(p),
      restartReread(p), restartLineagePreempt(p), restartDeviceFail(p) },
    nondet h = HOSTS.oneOf()
    any { recordAttach(h), takeoverStart(h), nameStandby(h), restartRecords(h) },
    nondet i = rc.attaches.keys().oneOf()
    any { attachRequest(i, true), attachRequest(i, false), lateLand(i), enroll(i), endRead(i), endWrite(i), dropPair(i), detachRequest(i),
      detachDone(i), markGone(i) },
    nondet k = KEY_VALUES.oneOf()
    endedPreempt(k),
    nondet effect = Set(true, false).oneOf()
    endedPreemptLands(effect),
    readListing,
    pollEntries,
    pollSuperseded,
    reportPoll,
  }

  /// The handoff schedule over `reclaimInit`, whose owner serves past its FB with a named standby: the owner's
  /// planned exit, which drains, resumes, restarts or withdraws and transfers, the transfer's outcomes, the
  /// record-named owner's restart with its lineage arm, standby designations and takeovers racing the transfer,
  /// command actions and the serving owner's Report, with the store deciding requests in any order.
  action handoffStep = any {
    nondet r = pending.union(Set({ id: 0, kind: "none", g: 0, active: "", owner: "", e: 0, spare: "", spareHost: "", to: "" })).oneOf()
    decide(r),
    nondet p = 1.to(REQUESTS).oneOf()
    any { reply(p), timeout(p), planDrain(p), planResume(p), planRestart(p), transferStart(p), transferReply(p),
      transferTimeout(p), command(p), restartReady(p), restartReport1(p), restartBump(p), restartPreempt(p, false),
      restartRegister(p), restartReread(p), restartLineagePreempt(p), restartReport2(p), restartDeviceFail(p),
      takeoverReport1(p),
      takeoverPreempt(p), takeoverCrash(p) },
    nondet h = HOSTS.oneOf()
    any { restartRecords(h), takeoverStart(h), nameStandby(h) },
    reportPoll,
  }

  /// Each generation names one active volume, and a volume active in one generation is active in no other.
  val OneActiveVolumePerShard = history.forall(a => history.forall(b => (a._1 == b._1) iff (a._2 == b._2)))
  /// No two attempts activate one `(g, n)`, so no two tenures share the session `g * 2^32 + 2n + 2`.
  val NoEpochReuse = activations.forall(a => activations.forall(b => (a._1 == b._1 and a._2 == b._2) implies a._3 == b._3))
  /// Every committed bump commits at the generation its attempt read, so no `E` bump lands after a flip.
  val NoBumpAfterFlip = bumps.forall(b => b._1 == b._2)
  /// At most one flip of each source generation commits.
  val OneFlipPerGeneration = flipWins.forall(a => flipWins.forall(b => a._1 == b._1 implies a._2 == b._2))
  /// A spare the reconciler replaced or the standby's check retired before a flip activated it is active in no
  /// generation.
  val ReplacedSpareNeverActive = history.forall(h => not(replaced.contains(h._2)))
  /// Every poll that kept its volume serving read a listing that holds the owner's attachment and otherwise only hosts
  /// whose attach event the volume record held and the caller bound at that poll, and left the volume unretired, as
  /// did a reclaim poll that ended with no verdict; and every retiring step retired the active volume: `poll` and the
  /// fresh check on any other listing, the reclaim poll on a listing with an instance outside the owner and the
  /// retained entries. A reclaim poll that withdraws on an ended own entry retires nothing, which
  /// `EndedAttachNeverRetires` checks. The free scheduler removes no owner attachment, so the owner clause holds in
  /// every state it reaches.
  val AttachOutsideDesiredStateRetires = kept.forall(k => k.listing.contains(k.owner)
      and k.listing.forall(a => a == k.owner or (k.events.contains(a) and k.bound.contains(a))))
    and ((ev.act == "pollRetired" or ev.act == "freshRefuse") implies retired.contains(rec.active))
    and ((ev.act == "poll" or ev.act == "pollUnobserved") implies not(retired.contains(rec.active)))
  /// No poll retires a volume whose listing holds the owner's attachment and otherwise only standbys whose attach the
  /// reconciler requested; the record, bind, request order keeps it under a poll that judges the listing alone.
  val RecordedAttachRetiresNothing = {
    val listing = listed.get(rec.active)
    ev.act == "pollRetired" implies not(listing.contains(rec.owner) and listing.subseteq(Set(rec.owner).union(requestedHosts(rec.active))))
  }
  /// Every fresh check that passed found its volume unwritten by any foreign attachment, and every fresh attempt that
  /// reached FB activated a volume whose fresh check found it unwritten.
  val FreshIsEmpty = freshChecks.forall(c => c._2)
    and fb.keys().forall(p => procs.get(p).restart or procs.get(p).takeover or freshChecks.contains((procs.get(p).vol, true)))
  /// Every preempt the abstract issuance rule admits names the issuing host's own attach key, the key of an attach
  /// whose tenure its committed takeover succeeded, from the record-named owner past its FB an ended key that does not
  /// hold (the ended form), or a key in the bumped form, a clause that checks the rule's definition alone, since no
  /// action reads `preemptAdmitted`; and every issued preempt carries admitted key evidence: a self preempt names its
  /// issuer's own key, a takeover preempt names a host whose tenure the issuer's own acknowledged takeover succeeded,
  /// directly or through earlier committed takeover writes at any depth (`deposedBy` and `supersedes`), an ended-key
  /// preempt names an ended key that does not hold from the owner past its FB, and a lineage preempt names the key
  /// `armKey` admits after a reread that named its tenure. `preempts` holds a takeover or lineage preempt once the
  /// device takes it, so the last three clauses judge the lineage preempt and the takeover preempt in the state their
  /// action leaves, whether the device took or refused the command: the key the command named, which `deviceStep`
  /// stores in the attempt's `prkey`, carries the bumped form's evidence or the takeover's. The third judges the same
  /// key after a failed device step of an attempt whose reread named its tenure: the arm's failed lineage preempt,
  /// and its failed Report #2, which names the same key.
  val NoPreemptOfForeignKey = HOSTS.forall(h => KEY_VALUES.union(Set(UNRECORDED)).forall(k =>
      preemptAdmitted(h, k) implies (k == attachKey(h) or succeeded(h, k) or endedForm(h, k) or bumpedForm(h, k))))
    and preempts.forall(p => p._3)
    and (ev.act == "restartLineagePreempt" implies (rc.rereads.contains((ev.id, true))
      and armKey(ev.id, procs.get(ev.id).prkey)))
    and (ev.act == "takeoverPreempt" implies (lineage.exists(l => l._4 == ev.id and l._1 == procs.get(ev.id).host
      and supersedes(l, procs.get(ev.id).prkey)) and activations.exists(a => a._3 == ev.id)))
    and ((ev.act == "restartDeviceFail" and rc.rereads.contains((ev.id, true)))
      implies armKey(ev.id, procs.get(ev.id).prkey))
  /// Every committed takeover's and planned transfer's successor is the standby the record named when its write
  /// committed.
  val NamedStandbyTakesOver = lineage.forall(l => l._1 == l._3)
  /// Every takeover process that issued a device command activated through its own acknowledged CAS.
  val TakeoverCasBeforeDevice = deviceActs.forall(p => not(procs.get(p).takeover) or activations.exists(a => a._3 == p))
  /// Every outstanding bump of `E` is a fresh attempt's or a restart's: a takeover's one store write is its CAS.
  val TakeoverIssuesNoBump = pending.forall(r => r.kind != "bump" or not(procs.get(r.id).takeover))
  /// Every committed takeover keeps the generation and the active volume of the record it conditioned on, and no
  /// takeover's volume is retired unless `UNRECORDED` holds the reservation: a successor that stops after its CAS
  /// leaves the volume for the fresh-host attach, and an unrecorded holder retires it.
  val InterruptedTakeoverRetainsVolume = takeovers.forall(t => t._1 == t._3 and t._2 == t._4
    and (not(retired.contains(t._2)) or holder == UNRECORDED))
  /// Every retirement a restart refusal requested followed a Report #1 of that restart that showed `UNRECORDED`, a
  /// holder outside the recorded set, as the `shown` ghost records it: a device failure, a recorded holder and nobody
  /// holding request none (DEVICE-FAILURE-HOLD).
  val RestartRetiresOnlyOnObservation = restartRetired.forall(r => shown.exists(s => s._1 == r._1 and s._2 == UNRECORDED))
  /// A restart held on a device failure leaves its volume unretired unless `UNRECORDED` holds the reservation.
  val DeviceFailureRetainsVolume = procs.keys().forall(p => (procs.get(p).restart and procs.get(p).phase == "refusedDevice")
    implies (not(retired.contains(procs.get(p).vol)) or holder == UNRECORDED))
  /// After any issued preempt whose key evidence is admitted, an own-key self preempt, a takeover preempt of the
  /// key of a host whose tenure it succeeded, an ended-key preempt or a lineage preempt, the record's active volume is
  /// unretired unless `UNRECORDED` holds the reservation:
  /// the deposed owner's Report hold and its status depositions request no retirement, and an unrecorded holder
  /// retires the volume.
  val StalePreemptRetainsVolume = preempts.forall(p => p._3 implies (not(retired.contains(rec.active)) or holder == UNRECORDED))
  /// Every committed planned transfer names a host, the standby the record named at its commit, owner, raises the
  /// record's `E` by one from its value at the commit and leaves no standby, and no transfer mints a session: every
  /// activation of an attempt that issued a transfer is the one its own bump made before it.
  val TransferNamesStandby = handoffs.forall(h => HOSTS.contains(h.to) and h.to == h.named and h.after.owner == h.to
      and h.after.e == h.e + 1 and h.after.standby == "")
    and transfers.forall(t => activations.forall(a => a._3 != t._1 or a._2 == procs.get(t._1).n))
  /// Every committed planned transfer was issued by an attempt that serves the tenure it transfers: the attempt
  /// reached its FB, its host is the owner the record named at the commit, and its generation and `E` are the
  /// record's at the commit.
  val TransferByOwnTenure = handoffs.forall(h => fb.keys().contains(h.by) and procs.get(h.by).host == h.owner
    and procs.get(h.by).g == h.g and procs.get(h.by).n + 1 == h.e)
  /// Every committed planned transfer leaves the record's `E` below `EMAX`, so the target's own bump has an attempt.
  val TransferLeavesBump = handoffs.forall(h => h.after.e < EMAX)
  /// An attempt whose transfer was acknowledged as committed (`transferred`) has a committed transfer, and one whose
  /// transfer was acknowledged as refused (`transferRefused`) has none: the reply reads the transfer's own decision.
  val TransferAckMatchesCommit = procs.keys().forall(p =>
    (procs.get(p).phase != "transferred" or handoffs.exists(h => h.by == p))
    and (procs.get(p).phase != "transferRefused" or not(handoffs.exists(h => h.by == p))))
  /// No attempt takes a command action under the tenure it transferred: from the turn an attempt issued its
  /// transfer, it takes none, and every later attempt of its host that takes a command action holds an activation of
  /// its own, a same-host restart's bump or a takeover's CAS. An earlier attempt of the host, deposed before the
  /// transfer, is judged by `DetectedLossWithdraws`.
  val NoEmissionAfterTransfer = transfers.forall(t => commands.forall(c => c._2 < t._2
    or procs.get(c._1).host != procs.get(t._1).host or c._1 < t._1
    or (c._1 > t._1 and activations.exists(a => a._3 == c._1))))
  /// No planned transfer flips the shard or changes its generation or volume, the volume stays unretired unless
  /// `UNRECORDED` holds, and the reservation stays held: while the record names the transfer's tenure the outgoing
  /// attempt's pair holds, and while the record names a later tenure of the target with no owner-change write
  /// committed after the transfer, the tenures the target's own bumps name, the outgoing pair or the target's holds,
  /// except where a preempt of the outgoing key moved it to the preempting host (`movedOff`), a paused takeover's
  /// stale preempt included. At the transfer's tenure that host is another host than the target, or the target when
  /// its own committed takeover succeeded a tenure of the outgoing key, whose paused preempt lands after the
  /// transfer: a target with no such takeover holds only after its own bump. A release by the outgoing attempt
  /// leaves no holder and breaks it. The handoff schedule holds no unrecorded holder and no restart retirement, so
  /// its searches reach no retired volume.
  val TransferRetainsVolume = handoffs.forall(h => h.after.g == h.g and h.after.active == h.vol
    and (not(retired.contains(h.vol)) or holder == UNRECORDED)
    and ((rec.g == h.g and rec.owner == h.to and rec.e == h.e + 1) implies (holding and (holder == h.fromKey
      or (movedOff(h.fromKey) and (keyHost(holder) != h.to or succeeded(h.to, h.fromKey))))))
    and ((rec.g == h.g and rec.owner == h.to and rec.e >= h.e + 2 and not(lineage.exists(l => l._5 > h.e)))
      implies (holding and (holder == h.fromKey or holder == h.toKey or movedOff(h.fromKey)))))
  /// Whether the holder's host issued a preempt of key `k` and is another host than `k`'s.
  def movedOff(k: str): bool = keyHost(holder) != keyHost(k) and preempts.exists(x => x._1 == keyHost(holder) and x._2 == k)
  /// No attempt that observed a loss takes a command action at a later turn.
  val DetectedLossWithdraws = observations.forall(o => commands.forall(c => c._1 != o._1 or c._2 < o._3))
  /// Every fresh, restart or takeover attempt that issued a device command in its incarnation read records in it that
  /// passed its checks; a passing takeover read names the host standby at `E > 0` on an unretired volume.
  val RecordsBeforeDevice = deviceActs.forall(p => recordsRead.contains((p, true)))
  /// Every medium write of an attempt follows the FB of that attempt.
  val NoWriteBeforeFB = writes.forall(w => fb.keys().contains(w._1) and fb.get(w._1) < w._2)
  /// Every attempt that reached FB activated through its own committed bump.
  val OwnBumpBeforeFB = fb.keys().forall(p => activations.exists(a => a._3 == p))
  /// Every attempt that issued a fencing command, a Register or a Preempt-and-Abort, with success or failure,
  /// activated through its own acknowledged bump or takeover CAS first: the lineage arm's Register and preempt follow
  /// the restart's own bump.
  val OwnBumpBeforePreempt = fencing.forall(p => activations.exists(a => a._3 == p))
  /// Every FB a restart reached through the lineage arm follows its host's preempt, with admitted key evidence, of the
  /// key its Report #1 captured, and the attempt's own confirming Report #2, whose `fb` grant records the own pair
  /// holding under its live key, and each shard read of the attempt, the reread before its preempt and Report #2's,
  /// named the tenure its bump activated with its attach live (`rc.rereads`). The preempt is matched by host and key,
  /// so it may be an earlier attempt's of that host.
  val ArmFbConfirmed = fb.keys().forall(p => not(procs.get(p).restart) or procs.get(p).prkey == ""
    or (preempts.contains((procs.get(p).host, procs.get(p).prkey, true)) and rc.grants.contains(("fb", p, false))
      and not(rc.rereads.contains((p, false)))))
  /// Every committed bump, a restart's included, commits at the generation its attempt read at its start or its
  /// step 1: `NoBumpAfterFlip` under the restart schedules.
  val BumpAtOwnGeneration = NoBumpAfterFlip
  /// No write of an ended incarnation lands after the FB of a restart or fresh attempt that holds the record's
  /// current tenure: its host, generation and `E` are the record's. A takeover's FB drains no predecessor, so the
  /// property excludes it, and it excludes an attempt whose tenure the record no longer holds, which may serve until
  /// it observes its deposition. `held` and `queued` count every ended incarnation's writes, so a restart's ready wait
  /// drains them all, including a deposed predecessor's; the Rust ready wait drains the restarting host's own.
  val NoPredecessorEffectAfterFB = fb.keys().forall(p => procs.get(p).takeover or procs.get(p).phase != "active"
    or procs.get(p).host != rec.owner or procs.get(p).g != rec.g or procs.get(p).n + 1 != rec.e
    or landed.forall(t => t <= fb.get(p)))
  /// No retirement follows from a listed attachment of a retained entry, a registrant with a recorded pair or a
  /// registrant under an ended key, holding or not: every attachment a retiring poll found outside its admitted set,
  /// and every holder
  /// or registrant a retiring Report found outside its recorded pairs and ended keys, is `UNRECORDED`, the one
  /// attachment outside the protocol; and the active volume is retired exactly when such a check found one, so a
  /// check that finds one retires in its step and none retires with nothing found. The second clause holds under the
  /// reclaim schedule, whose retirements are the poll's record read, the serving Report and the restart's.
  val EndedAttachNeverRetires = rc.retiredOn.forall(a => a == UNRECORDED)
    and (retired.contains(rec.active) iff rc.retiredOn != Set())
  /// No enrollment, takeover CAS or FB belongs to an attach whose entry was ended at the record read it relied on, no
  /// enrollment to an attach whose request had not landed, no takeover CAS to an attach without its enrolled pair, and
  /// no designation names a host whose newest attach was ended or unenrolled when it was written; a takeover's
  /// Register relies on its CAS's read. A designation and an end commit in either order, so the record can name an
  /// ended host afterwards.
  val EndedGrantsNothing = rc.grants.forall(g => not(g._3))
  /// No attempt serves a tenure after a poll of that tenure read its own entry ended or gone: an owner whose attach
  /// ended withdraws at that poll (ENDED-GRANTS-NOTHING), however the end raced its takeover.
  val EndedOwnerServesNothing = rc.endedPolls.forall(t => procs.keys().forall(p => not(procs.get(p).phase == "active"
    and procs.get(p).host == t._1 and procs.get(p).g == t._2 and procs.get(p).n + 1 == t._3)))
  /// No ended-key preempt, however late it lands, removes the registration of a live entry or moves the reservation.
  /// The reclaim roots, which start at most three takeover processes and commit at most two takeovers, reach no
  /// landing that moves the reservation; `witnessEndedPreemptMovesHolder` reaches one with four takeover processes,
  /// each of which commits its takeover.
  val EndedPreemptSparesLiveAttach = rc.spared.forall(s => not(s._2) and not(s._3))
  /// Every pair drop is the record-named owner's while it serves past its FB and follows the end mark and a recorded
  /// absence, so the end write itself drops no pair; every recorded absence is of an ended entry whose key a serving
  /// owner's Report, on which its own pair
  /// held, did not list; and every detach request names an ended entry whose pair the record no longer holds.
  val EndOrder = rc.drops.forall(d => d._2) and rc.detaches.forall(d => not(d._2)) and rc.unshown == Set()
  /// Every end was decided on a shard read that named the entry's host neither owner nor standby at `E > 0`: only an
  /// attach that holds no role is ended. The end write lands whatever the record names by then.
  val EndedHoldsNoRole = rc.roleEnds == Set()
  /// No host holds two retained attach entries: a new attach of a host follows the gone mark of its earlier one.
  val AttachAfterGone = HOSTS.forall(h => entriesOf(h).filter(i => rc.attaches.get(i).state != "gone").size() <= 1)
  /// At most `MAX_ATTACHED` live and `MAX_EVENTS` retained attach entries exist.
  val HistoryBound = liveCount <= MAX_ATTACHED and retainedCount <= MAX_EVENTS
  val safety = OneActiveVolumePerShard and NoEpochReuse and NoBumpAfterFlip and OneFlipPerGeneration
    and ReplacedSpareNeverActive and AttachOutsideDesiredStateRetires and RecordedAttachRetiresNothing and FreshIsEmpty
    and NoPreemptOfForeignKey
    and DetectedLossWithdraws and RecordsBeforeDevice and BumpAtOwnGeneration and NoPredecessorEffectAfterFB
    and NoWriteBeforeFB and OwnBumpBeforeFB and OwnBumpBeforePreempt and ArmFbConfirmed and InterruptedTakeoverRetainsVolume and StalePreemptRetainsVolume
    and NamedStandbyTakesOver and TakeoverCasBeforeDevice and TakeoverIssuesNoBump and RestartRetiresOnlyOnObservation
    and DeviceFailureRetainsVolume and TransferNamesStandby and NoEmissionAfterTransfer and TransferRetainsVolume
    and TransferByOwnTenure and TransferLeavesBump and TransferAckMatchesCommit

  /// A fourth attach of the volume, recorded after an earlier entry ended, is named and takes over to its FB at the
  /// volume's one generation, and its preempt names the key of the attach whose tenure it succeeded.
  val witnessFourthAttach = fb.keys().exists(p => procs.get(p).takeover and procs.get(p).key == KEYS.get(4)
    and procs.get(p).g == 1 and procs.get(p).vol == "v1" and preempts.exists(x => x._1 == procs.get(p).host and x._3
    and x._2 != KEYS.get(4)))
  /// The reclaim poll retires the volume on an attachment outside the protocol.
  val witnessReclaimPollRetires = ev.act == "pollRetired" and rc.retiredOn == Set(UNRECORDED) and retired.contains(rec.active)
  /// The record-named owner's own entry is ended, by an end decided before the host became owner and written after,
  /// and the owner's poll that read it withdrew the owner's attempts with no retirement.
  val witnessOwnerEntryEnded = ev.act == "pollWithdrawn" and not(retired.contains(rec.active))
    and not(servingPastFb(rec.owner)) and procs.keys().exists(p => procs.get(p).host == rec.owner
    and procs.get(p).phase == "withdrawn")
    and rc.attaches.keys().exists(i => rc.attaches.get(i).host == rec.owner and rc.attaches.get(i).state == "ended")
  /// A fourth attach entry is recorded on the volume.
  val witnessFourthEntry = rc.attaches.keys().contains(4)
  /// A record attempt refuses at `MAX_ATTACHED` live entries, and at `MAX_EVENTS` retained ones with a slot free.
  val witnessClosedAtLive = ev.act == "attachClosed" and liveCount == MAX_ATTACHED
  val witnessClosedAtEvents = ev.act == "attachClosed" and liveCount < MAX_ATTACHED and retainedCount == MAX_EVENTS
  /// A serving Report keeps the owner serving beside a registrant under an ended key whose pair the record dropped.
  val witnessEndedRegistrantKept = ev.act == "reportPoll" and rc.regs.exists(k => endedKey(k) and not(paired(k)))
  /// An ended-key preempt lands and removes its key's registration.
  val witnessEndedPreemptRemoves = ev.act == "endedPreemptLands" and rc.spared.size() > 0
    and not(rc.regs.exists(k => rc.spared.exists(s => s._1 == k)))
  /// An ended-key preempt lands on the holder's key and moves the reservation to its issuer: the ended key took the
  /// reservation after the preempt's decision, and a Register restored the issuer's key before the landing.
  /// `EndedPreemptSparesLiveAttach` is false in that state.
  val witnessEndedPreemptMovesHolder = ev.act == "endedPreemptLands" and rc.spared.exists(s => s._3)
  /// An entry is marked gone, and a later entry of the same host is recorded.
  val witnessReattach = HOSTS.exists(h => entriesOf(h).exists(i => rc.attaches.get(i).state == "gone")
    and live(h))
  /// The poll keeps serving on a listing with the instance of an ended entry.
  val witnessKeptBesideEnded = ev.act == "poll" and kept.exists(k => k.listing.exists(a =>
    entriesOf(a).exists(i => rc.attaches.get(i).state == "ended") and not(live(a))))
  /// The target of a committed planned transfer reaches its FB through its own restart: its bump activated a tenure
  /// after the transfer's, and its lineage preempt named the outgoing owner's key.
  val witnessHandoffFb = handoffs.exists(h => fb.keys().exists(p => procs.get(p).restart and procs.get(p).host == h.to
    and activations.exists(a => a._1 == h.g and a._2 > h.e and a._3 == p)) and preempts.contains((h.to, h.fromKey, true)))
  /// The outgoing owner's transfer reply is lost and the transfer did not commit, and the owner's same-host restart
  /// reaches its FB.
  val witnessTransferUnknownThenRestart = handoffs == Set() and transfers.exists(t => procs.get(t._1).phase == "transferUnknown"
    and fb.keys().exists(r => r > t._1 and procs.get(r).restart and procs.get(r).host == procs.get(t._1).host))
  /// The outgoing owner's transfer reply is lost after the transfer committed: the owner's host starts no later
  /// attempt, and the target reaches its FB.
  val witnessTransferUnknownCommitted = witnessHandoffFb and transfers.exists(t => procs.get(t._1).phase == "transferUnknown"
    and procs.keys().forall(r => r <= t._1 or procs.get(r).host != procs.get(t._1).host))
  /// A transfer refused because the designation moved before its commit, and the owner's same-host restart reaches
  /// its FB.
  val witnessTransferRefusedThenRestart = transfers.exists(t => procs.get(t._1).phase == "transferRefused"
    and fb.keys().exists(r => r > t._1 and procs.get(r).restart and procs.get(r).host == procs.get(t._1).host))
  /// A later attempt of a transferring attempt's host takes a command action after the transfer's issue.
  val witnessLaterAttemptCommands = transfers.exists(t => commands.exists(c => c._2 >= t._2 and c._1 > t._1
    and procs.get(c._1).host == procs.get(t._1).host))
  /// The target of a committed transfer takes a command action under a tenure its own restart's bump activated.
  val witnessTargetCommands = handoffs.exists(h => commands.exists(c => procs.get(c._1).restart
    and procs.get(c._1).host == h.to and activations.exists(a => a._1 == h.g and a._2 > h.e and a._3 == c._1)))
  /// Another host's takeover commits over the tenure the target's own bump activated after a committed transfer.
  val witnessTakeoverOverTargetBump = handoffs.exists(h => lineage.exists(l => l._1 != h.to and l._5 == h.e + 2))
  val witnessFlip = history.size() >= 2
  val witnessActivated = activations.size() >= 1
  val witnessSecondGeneration = activations.exists(a => a._1 == 2)
  val witnessCommittedTimeout = procs.keys().exists(p => procs.get(p).phase == "refused" and decided.keys().contains(p) and decided.get(p))
  val witnessStaleBumpRefused = bumps.size() == 0 and history.size() >= 2 and decided.keys().exists(p => procs.keys().contains(p) and not(decided.get(p)))
  val witnessFlipRaceLost = ev.act == "flipRaceLost"
  val witnessSpareReplaced = replaced.size() >= 1 and history.size() >= 2
  val witnessPollRetired = ev.act == "pollRetired"
  /// A poll keeps serving on a listing that holds a standby whose attach the reconciler requested.
  val witnessKeptBesideStandby = kept.exists(k => k.listing.exists(a => a != k.owner and requestedHosts(k.vol).contains(a)))
  /// A poll keeps serving on a listing of the owner alone while the volume record holds the attach event of a standby
  /// the caller bound.
  val witnessKeptBeforeStandbyListed = ev.act == "poll" and listed.get(rec.active) == Set(rec.owner)
    and events.get(rec.active).exists(h => h != rec.owner and HOSTS.contains(h) and bound.contains((rec.active, h)))
  /// A poll retires the volume on a listed attachment whose attach event the volume record holds and the caller does
  /// not bind: the stale foreign attach, whose host the caller never binds.
  val witnessPollRetiresUnbound = ev.act == "pollRetired" and listed.get(rec.active).exists(a => a != rec.owner
    and events.get(rec.active).contains(a) and not(bound.contains((rec.active, a))))
  val witnessSpareRetired = ev.act == "spareRetired" and replaced.exists(v => retired.contains(v))
  val witnessFreshRefused = ev.act == "freshRefuse" and retired.contains(rec.active)
  val witnessPreempt = HOSTS.exists(h => preemptAdmitted(h, attachKey(h)))
  val witnessFreshAfterRefusal = refusedAt.exists(g => activations.exists(a => a._1 > g))
  val witnessDeposedObserved = observations.exists(o => o._2 == "flipped" and procs.get(o._1).phase == "withdrawn")
  val witnessCommandThenLoss = commands.exists(c => observations.exists(o => o._1 == c._1 and c._2 < o._3))
  val witnessRestartDevice = deviceActs.exists(p => procs.keys().contains(p) and procs.get(p).restart)
  val witnessFreshWrite = ev.act == "freshWrite"
  val witnessFreshFb = fb.keys().exists(p => not(procs.get(p).restart) and not(procs.get(p).takeover))
  val witnessTakeoverFb = fb.keys().exists(p => procs.get(p).takeover)
  val witnessTakeoverChain = lineage.exists(a => lineage.exists(b => a._2 == b._1))
  /// A takeover preempt names a host its issuer's committed takeover did not depose directly.
  val witnessSupersededPreempt = preempts.exists(p => p._1 != keyHost(p._2) and p._3
    and not(lineage.exists(l => l._1 == p._1 and l._7 == p._2)))
  /// A host the record does not name as standby refuses its takeover with no request.
  val witnessUnnamedRefused = procs.keys().exists(p => procs.get(p).takeover and procs.get(p).phase == "refused"
    and not(decided.keys().contains(p)) and not(pending.exists(r => r.id == p)))
  /// A takeover CAS fails its condition after the standby designation moved.
  val witnessStaleStandbyRefused = procs.keys().exists(p => procs.get(p).takeover and decided.keys().contains(p)
    and not(decided.get(p)) and rec.standby != procs.get(p).host and rec.standby != ""
    and rec.g == procs.get(p).g and rec.e == procs.get(p).n and rec.owner == procs.get(p).prkey)
  /// A takeover CAS commits with its reply lost, so the attempt issues no device command, and the successor's
  /// same-host restart issues one.
  val witnessUnknownThenRestart = procs.keys().exists(p => procs.get(p).takeover and procs.get(p).phase == "refused"
    and decided.keys().contains(p) and decided.get(p) and not(deviceActs.contains(p))
    and deviceActs.exists(r => procs.get(r).restart and procs.get(r).host == procs.get(p).host))
  /// A restart of some host refused at Report #1 into `phase`, and that host started a later restart.
  def rerunAfter(phase: str): bool = procs.keys().exists(p => procs.get(p).restart and procs.get(p).phase == phase
    and procs.keys().exists(r => r > p and procs.get(r).restart and procs.get(r).host == procs.get(p).host))
  /// A host restarts again after its restart's lineage arm, taken at a Report #1 that showed a recorded pair of
  /// another host, refused or held.
  val witnessRerunAfterRecordedRefusal = procs.keys().exists(p => procs.get(p).restart and procs.get(p).prkey != ""
    and Set("refused", "refusedDevice").contains(procs.get(p).phase)
    and procs.keys().exists(r => r > p and procs.get(r).restart and procs.get(r).host == procs.get(p).host))
  /// A restart reaches its FB through the lineage arm.
  val witnessArmFb = fb.keys().exists(p => procs.get(p).restart and procs.get(p).prkey != "")
  /// The lineage arm's reread shows another tenure than the one its bump activated, or its own attach ended, and the
  /// restart refuses with no preempt.
  val witnessArmRereadRefused = ev.act == "restartReread" and procs.get(ev.id).phase == "refused"
  /// The lineage arm's preempt landed with admitted evidence and its Report #2 refuses, the record naming another
  /// tenure or another key holding by then.
  val witnessArmReport2Refused = ev.act == "restartReport2" and procs.get(ev.id).restart and procs.get(ev.id).prkey != ""
    and procs.get(ev.id).phase == "refused" and preempts.contains((procs.get(ev.id).host, procs.get(ev.id).prkey, true))
  /// A host restarts again after its restart's Report #1 showed an unrecorded holder.
  val witnessRerunAfterForeignRefusal = rerunAfter("refusedForeign")
  /// A host restarts again after its restart's Report #1 showed nobody holding.
  val witnessRerunAfterUnheldRefusal = rerunAfter("refusedUnheld")
  /// A host restarts again after a device step of its restart failed.
  val witnessRerunAfterDeviceRefusal = rerunAfter("refusedDevice")
  /// A write of an ended incarnation lands after a takeover's FB, which drains no predecessor.
  val witnessLandAfterTakeoverFb = fb.keys().exists(p => procs.get(p).takeover and landed.exists(t => t > fb.get(p)))
  /// STATUS-REJUDGE: the Report that judges an attempt a deposing status withdrew retires the volume under the
  /// unrecorded holder.
  val witnessStatusRetires = ev.act == "reportRetired" and holder == UNRECORDED and retired.contains(rec.active)
    and observations.exists(o => o._2 == "judged" and o._3 == turn)
}
