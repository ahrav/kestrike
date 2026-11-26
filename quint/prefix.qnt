/// The checkpoint slots of one tenure's metadata prefix against the store record that names one of them. A capture
/// places its units in a slot outside the tenure's possibly-named set and its quarantine, and is refused before any
/// unit is submitted when every slot is possibly named or quarantined or its entries exceed `NMAX`. A Publish is an exact-version compare-and-swap on
/// the version the host knows; submitting one adds its slot to the set. The store applies a Publish later, once, or
/// never, and the host learns success, failure or nothing. The set shrinks to the slot a Publish committed over only
/// on that Publish's acknowledged success when the version it committed is at least the newest the host knows and
/// every other own Publish that has not succeeded was submitted before it, and every slot the shrink drops that a
/// capture wrote enters the quarantine, which no later capture of the tenure places into. A Confirm is the other own exact-version
/// writer: the host reads the record, adopting its version, named slot and named capture, and compare-and-swaps the
/// value it read, which keeps the named slot and capture; its success shrinks the set as a Publish's does. Under `FIELD` the store applies a write whose version is stale, the field-scoped condition a host
/// write must not use. A stale unit attempt of an earlier capture may land on its slot whenever a later capture wrote
/// that slot, and recovery reads the named slot and starts warm only when the slot holds the named capture's units.
/// One `capture` step runs from placement to the Publish's submission, so the invariants hold for an implementation that processes no other placement and no success between a capture's placement and its Publish's submission.
module prefix {
  const BOUND: int
  pure val SLOTS = 3
  pure val NMAX = 2
  pure val CAPTURES = 4
  /// Whether the store applies a write whatever the record's version.
  pure val FIELD = false
  /// An own write naming `slot` and `capture` at the version `at` the host knew: a Publish of a new capture, or a
  /// Confirm of the slot and capture the host read as named.
  type Pub = { id: int, slot: int, capture: int, at: int }
  /// The slot the store names, the capture the named Publish published, and the store record's version.
  var named: int
  var namedId: int
  var ver: int
  /// The version the host last adopted and the slot and capture that version names.
  var known: int
  var knownNamed: int
  var knownId: int
  /// What the last recovery read: "none" before any, then "warm" or "cold".
  var recovered: str
  /// The slots the store may name as the tenure knows them.
  var possible: Set[int]
  /// The slots a capture wrote that a shrink dropped from the set: an earlier capture's unit attempt may still land on
  /// them.
  var quar: Set[int]
  /// Publishes the host awaits a reply to, Publishes the store has yet to apply or refuse, the Publishes the store
  /// committed, and the Publishes the host learned succeeded.
  var pending: Set[Pub]
  var inflight: Set[Pub]
  var committed: Set[int]
  var succeeded: Set[int]
  var nextId: int
  /// The capture whose units each slot holds.
  var content: int -> int
  /// Every capture unit submitted: the slot, the capture's entries and the capture.
  var written: Set[(int, int, int)]
  /// The units submitted before the step.
  var prior: Set[(int, int, int)]
  /// Every unit submission counted, a repeat of an earlier tuple included, and the count before the step.
  var submits: int
  var priorSubmits: int
  var turn: int
  var ev: str

  /// The ids of every Publish submitted so far.
  val submitted = 1.to(nextId - 1)

  pure def free(possible: Set[int]): Set[int] = 0.to(SLOTS - 1).filter(s => not(possible.contains(s)))
  pure def lowest(slots: Set[int]): int = slots.fold(SLOTS, (low, s) => if (s < low) s else low)

  action init = all {
    named' = 0, namedId' = 0, ver' = 0, known' = 0, knownNamed' = 0, knownId' = 0, recovered' = "none", possible' = Set(0),
    quar' = Set(),
    pending' = Set(), inflight' = Set(),
    committed' = Set(), succeeded' = Set(), nextId' = 1,
    content' = 0.to(SLOTS - 1).mapBy(s => 0), written' = Set(), prior' = Set(), submits' = 0, priorSubmits' = 0,
    turn' = 0, ev' = "init",
  }
  action tick(act: str): bool = all {
    turn < BOUND, turn' = turn + 1, ev' = act, prior' = written, priorSubmits' = submits, recovered' = recovered,
  }
  action unchangedStore = all { named' = named, namedId' = namedId, ver' = ver, committed' = committed }
  action unchangedHost = all {
    knownNamed' = knownNamed, knownId' = knownId, possible' = possible, quar' = quar, pending' = pending, inflight' = inflight,
    succeeded' = succeeded, nextId' = nextId, content' = content, written' = written, submits' = submits,
  }

  /// A capture of `entries` entries: placement, then every unit into the slot and a Publish of it.
  action capture(entries: int): bool = {
    val open = free(possible.union(quar))
    val bounded = entries <= NMAX
    all {
      nextId <= CAPTURES, unchangedStore, known' = known,
      if (not(bounded)) all { tick("refusedEntries"), unchangedHost }
      else if (open.size() == 0) all { tick("refusedSlot"), unchangedHost }
      else {
        val slot = lowest(open)
        val p = { id: nextId, slot: slot, capture: nextId, at: known }
        all {
          tick("capture"), knownNamed' = knownNamed, knownId' = knownId,
          written' = written.union(Set((slot, entries, nextId))), submits' = submits + 1,
          content' = content.set(slot, nextId),
          possible' = possible.union(Set(slot)), quar' = quar,
          pending' = pending.union(Set(p)), inflight' = inflight.union(Set(p)),
          succeeded' = succeeded, nextId' = nextId + 1,
        }
      },
    }
  }
  /// The store applies an inflight write: it commits exactly when its version is the record's, or always under
  /// `FIELD`, and the record then names the write's slot and capture.
  action apply(p: Pub): bool = {
    val commits = p.at == ver or FIELD
    all {
    inflight.contains(p), tick("apply"),
    inflight' = inflight.exclude(Set(p)),
    named' = if (commits) p.slot else named,
    namedId' = if (commits) p.capture else namedId,
    ver' = if (commits) ver + 1 else ver,
    committed' = if (commits) committed.union(Set(p.id)) else committed,
    known' = known, knownNamed' = knownNamed, knownId' = knownId, possible' = possible, quar' = quar, pending' = pending,
    succeeded' = succeeded,
    nextId' = nextId, content' = content, written' = written, submits' = submits,
    }
  }
  /// The host learns the acknowledged success of a committed write, and the set shrinks to its slot when the write's
  /// version is at least the newest the host knows and every other own write that has not succeeded was submitted
  /// before it; the slots the shrink drops that a capture wrote enter the quarantine, and the slot named at the start,
  /// which no capture of the tenure wrote, goes free.
  action succeed(p: Pub): bool = {
    val newest = p.at + 1 >= known
    val shrink = newest and submitted.forall(q => q == p.id or succeeded.contains(q) or q < p.id)
    all {
      pending.contains(p), committed.contains(p.id), tick("succeed"), unchangedStore,
      possible' = if (shrink) Set(p.slot) else possible,
      quar' = if (shrink) quar.union(possible.exclude(Set(p.slot)).filter(s => written.exists(w => w._1 == s))) else quar,
      known' = if (newest) p.at + 1 else known, knownNamed' = if (newest) p.slot else knownNamed,
      knownId' = if (newest) p.capture else knownId,
      pending' = pending.exclude(Set(p)), succeeded' = succeeded.union(Set(p.id)),
      inflight' = inflight, nextId' = nextId, content' = content, written' = written, submits' = submits,
    }
  }
  /// The host learns a refusal, or the reply is lost or times out: the slot stays possibly named.
  action unresolved(p: Pub): bool = all {
    pending.contains(p), tick("unresolved"), unchangedStore,
    pending' = pending.exclude(Set(p)),
    known' = known, knownNamed' = knownNamed, knownId' = knownId, possible' = possible, quar' = quar, inflight' = inflight,
    succeeded' = succeeded,
    nextId' = nextId, content' = content, written' = written, submits' = submits,
  }
  /// The host reads the record and adopts its version and named slot.
  action read: bool = all {
    tick("read"), unchangedStore, known' = ver, knownNamed' = named, knownId' = namedId, possible' = possible, quar' = quar,
    pending' = pending,
    inflight' = inflight, succeeded' = succeeded, nextId' = nextId, content' = content, written' = written,
    submits' = submits,
  }
  /// The host submits a Confirm of the value it last read.
  action confirm: bool = {
    val p = { id: nextId, slot: knownNamed, capture: knownId, at: known }
    all {
      nextId <= CAPTURES, tick("confirm"), unchangedStore, known' = known, knownNamed' = knownNamed, knownId' = knownId,
      possible' = possible.union(Set(knownNamed)), quar' = quar, pending' = pending.union(Set(p)),
      inflight' = inflight.union(Set(p)),
      succeeded' = succeeded, nextId' = nextId + 1, content' = content, written' = written, submits' = submits,
    }
  }
  /// A unit attempt of an earlier capture lands on its slot after a later capture wrote the slot.
  action stale(w: (int, int, int)): bool = all {
    written.contains(w), content.get(w._1) != w._3, tick("stale"), unchangedStore, known' = known,
    knownNamed' = knownNamed, knownId' = knownId, possible' = possible, quar' = quar, pending' = pending, inflight' = inflight,
    succeeded' = succeeded,
    nextId' = nextId, content' = content.set(w._1, w._3), written' = written, submits' = submits,
  }
  /// Recovery reads the named slot: warm when it holds the named capture's units, cold otherwise.
  action recover: bool = all {
    turn < BOUND, turn' = turn + 1, ev' = "recover", prior' = written, priorSubmits' = submits,
    recovered' = if (content.get(named) == namedId) "warm" else "cold",
    unchangedStore, unchangedHost, known' = known,
  }
  action applyId(i: int): bool = all {
    inflight.exists(p => p.id == i),
    nondet p = inflight.filter(p => p.id == i).oneOf()
    apply(p),
  }
  action succeedId(i: int): bool = all {
    pending.exists(p => p.id == i),
    nondet p = pending.filter(p => p.id == i).oneOf()
    succeed(p),
  }
  action unresolvedId(i: int): bool = all {
    pending.exists(p => p.id == i),
    nondet p = pending.filter(p => p.id == i).oneOf()
    unresolved(p),
  }
  action staleOf(slot: int, id: int): bool = all {
    written.exists(w => w._1 == slot and w._3 == id),
    nondet w = written.filter(w => w._1 == slot and w._3 == id).oneOf()
    stale(w),
  }
  action step = any {
    nondet entries = 0.to(NMAX + 1).oneOf()
    capture(entries),
    nondet p = inflight.union(Set({ id: 0, slot: 0, capture: 0, at: 0 })).oneOf()
    apply(p),
    nondet q = pending.union(Set({ id: 0, slot: 0, capture: 0, at: 0 })).oneOf()
    any { succeed(q), unresolved(q) },
    read,
    confirm,
    nondet w = written.union(Set((0, 0, 0))).oneOf()
    stale(w),
  }

  /// The slot the store names holds the units of the capture its Publish published.
  val NamedSlotHoldsItsCapture = content.get(named) == namedId
  /// No capture of more than `NMAX` entries submits a unit.
  val EntriesBounded = written.forall(w => w._2 <= NMAX)
  /// A refused capture submits no unit.
  val RefusalSubmitsNothing = (ev == "refusedSlot" or ev == "refusedEntries") implies (written == prior and submits == priorSubmits)
  /// The store names a slot in the tenure's possibly-named set.
  val NamedIsPossible = possible.contains(named)
  /// A warm recovery loads the named capture's own units.
  val NoStaleLoad = (ev == "recover" and recovered == "warm") implies content.get(named) == namedId
  val safety = NamedSlotHoldsItsCapture and EntriesBounded and RefusalSubmitsNothing and NamedIsPossible

  val witnessSlotRefused = ev == "refusedSlot"
  val witnessEntriesRefused = ev == "refusedEntries"
  val witnessShrunk = ev == "succeed" and possible.size() == 1 and named != 0
  val witnessCaptured = written.size() >= 1
}
