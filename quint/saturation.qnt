/// Finite-resource accounting of one shard's recovery history (P7): the delta region's LSNs and the checkpoint
/// slots. The log part tracks the settled floor, the tenure's first LSN, the head, the durable prefix, the reserved
/// end, the capacity and the recorded suffix chain; the slot part tracks each slot's place in the possibly named
/// set, the slot the store names, the slots a unit write of the tenure reached, and the sent Publishes the store
/// may still apply. Every action is a log step that
/// reads and writes the log part alone, a slot step that reads and writes the slot part alone, or the takeover,
/// whose log half and slot half each read their own part. `logInv` and `slotInv` are checked as inductive: from
/// every typed state that satisfies one, every step keeps it, and each implies its P7 properties.
module saturation {
  const BOUND: int
  /// The delta region's blocks, the suffix chain's cap, the write queue's blocks and the highest LSN of the typed
  /// domain.
  pure val J = 2
  pure val CHAIN = 2
  pure val QUEUE = 1
  pure val LMAX = 5
  pure val LSNS = 0.to(LMAX)
  pure val SLOTS = Set(0, 1, 2)
  pure val STATUS = Set("free", "named", "submitted", "pending", "reserved", "quarantined")

  /// `own`: the store records the tenure's suffix. `chain`: the recorded suffixes, the tenure's included.
  type Log = { floor: int, start: int, head: int, durable: int, reserved: int, capacity: int, chain: int, own: bool }
  /// `status`: `submitted` is a Publish recorded in the set and not yet sent, `pending` a sent Publish whose outcome
  /// no success settled. `named`: the slot the store names, -1 for none. `exposed`: the slots a unit write of this
  /// tenure reached. `wrote`: the slot of the last unit write, -1 for none. `inflight`: the store's side, the slots of
  /// sent Publishes that expect the store's current version, so the store may still apply them whatever the set
  /// holds.
  type Slots = { status: int -> str, named: int, exposed: Set[int], wrote: int, inflight: Set[int] }

  var log: Log
  var slots: Slots
  var prior: (Log, Slots)
  var turn: int
  var ev: str

  pure def minOf(a: int, b: int): int = if (a < b) a else b
  pure def maxOf(a: int, b: int): int = if (a < b) b else a
  pure def count(s: Slots, status: str): int = SLOTS.filter(k => s.status.get(k) == status).size()

  /// The log part's inductive invariant: the tenure's LSNs run start, durable, head, reserved end, capacity in
  /// order, the capacity lies within `J` of the lower of the floor and the start, the blocks awaiting durability
  /// are at most the queue, the chain is within its cap, and a tenure with no recorded suffix has appended nothing.
  pure def logInv(l: Log): bool = and {
    0 <= l.floor, 0 <= l.start, l.floor <= l.head,
    l.start <= l.durable, l.durable <= l.head, l.head <= l.reserved, l.reserved <= l.capacity,
    l.capacity <= minOf(l.floor, l.start) + J,
    l.head - l.durable <= QUEUE,
    0 <= l.chain, l.chain <= CHAIN, l.own implies l.chain >= 1,
    not(l.own) implies (l.head == l.start and l.reserved == l.start),
  }
  /// The typed domain of the log part, the set the inductive case starts from: the floor and start within the LSNs,
  /// the head, durable prefix, reserved end and capacity within `J` past them, and the chain within its cap.
  pure def typedLog(l: Log): bool = and {
    LSNS.contains(l.floor), LSNS.contains(l.start),
    0.to(LMAX + J).contains(l.head), 0.to(LMAX + J).contains(l.durable),
    0.to(LMAX + J).contains(l.reserved), 0.to(LMAX + J).contains(l.capacity), 0.to(CHAIN).contains(l.chain),
  }
  /// P7 for the region: LSN `L` lies on unit `L % J`, so a required history of at most `J` blocks, and a tenure of
  /// at most `J` blocks, never puts two of their blocks on one unit.
  pure def historyOwnsUnits(l: Log): bool = l.head - l.floor <= J and l.head - l.start <= J

  /// The slot part's inductive invariant: at most one named and one reserved slot, the store's slot named or
  /// pending in the set, no slot a unit write reached free, and every Publish the store may still apply pending in
  /// the set.
  pure def slotInv(s: Slots): bool = and {
    s.status.keys() == SLOTS,
    count(s, "named") <= 1, count(s, "reserved") <= 1,
    if (s.named == -1) true else s.status.get(s.named) == "named" or s.status.get(s.named) == "pending",
    s.exposed.subseteq(SLOTS), s.exposed.forall(k => s.status.get(k) != "free"),
    s.inflight.subseteq(SLOTS), s.inflight.forall(k => s.status.get(k) == "pending"),
  }
  /// P7 for the slots: the slot the store names is never the reserved slot, the only slot a unit write targets.
  pure def namedNotReserved(s: Slots): bool = if (s.named == -1) true else s.status.get(s.named) != "reserved"

  /// Where a slot leaving the set goes: quarantine once a unit write of the tenure reached it, free otherwise. The Rust
  /// set also quarantines an unexposed slot that leaves, except the slot named at the tenure's start; the model's
  /// rule frees more slots, so its slot invariant covers the Rust rule.
  pure def left(s: Slots, k: int): str = if (s.exposed.contains(k)) "quarantined" else "free"

  pure val L0: Log = { floor: 0, start: 0, head: 0, durable: 0, reserved: 0, capacity: J, chain: 0, own: false }
  pure val S0: Slots = { status: SLOTS.mapBy(k => "free"), named: -1, exposed: Set(), wrote: -1, inflight: Set() }

  action advance(name: str): bool = all { turn < BOUND, turn' = turn + 1, ev' = name, prior' = (log, slots) }
  action logStep(name: str, after: Log): bool = all { log' = after, slots' = slots, advance(name) }
  action slotStep(name: str, after: Slots): bool = all { slots' = after, log' = log, advance(name) }
  action refused(name: str): bool = all { log' = log, slots' = slots, advance(name) }

  action init = all { log' = L0, slots' = S0, prior' = (L0, S0), turn' = 0, ev' = "init" }
  /// Every typed log state that satisfies `logInv`, beside the initial slots.
  action initLog = {
    nondet f = LSNS.oneOf()
    nondet s = LSNS.oneOf()
    nondet h = 0.to(LMAX + J).oneOf()
    nondet d = 0.to(LMAX + J).oneOf()
    nondet r = 0.to(LMAX + J).oneOf()
    nondet c = 0.to(LMAX + J).oneOf()
    nondet n = 0.to(CHAIN).oneOf()
    nondet o = Set(true, false).oneOf()
    val l = { floor: f, start: s, head: h, durable: d, reserved: r, capacity: c, chain: n, own: o }
    all { logInv(l), log' = l, slots' = S0, prior' = (l, S0), turn' = 0, ev' = "init" }
  }
  /// Every typed slot state that satisfies `slotInv`, beside the initial log.
  action initSlots = {
    nondet m = SLOTS.setOfMaps(STATUS).oneOf()
    nondet n = Set(-1, 0, 1, 2).oneOf()
    nondet e = SLOTS.powerset().oneOf()
    nondet w = Set(-1, 0, 1, 2).oneOf()
    nondet f = SLOTS.powerset().oneOf()
    val s = { status: m, named: n, exposed: e, wrote: w, inflight: f }
    all { slotInv(s), slots' = s, log' = L0, prior' = (L0, s), turn' = 0, ev' = "init" }
  }

  /// The tenure records its suffix with a reserved end `r` blocks past its start, within the capacity; a chain at
  /// its cap refuses before any write.
  action recordSuffix(r: int): bool = any {
    all { not(log.own), log.chain < CHAIN,
          logStep("recordSuffix", { ...log, own: true, chain: log.chain + 1,
                                    reserved: minOf(log.start + r, log.capacity) }) },
    all { not(log.own), log.chain >= CHAIN, refused("refusedChain") },
  }
  /// The store records a higher reserved end; an extension whose outcome is unknown changes nothing.
  action extend(end: int): bool = all {
    log.own, log.reserved < end, end <= log.capacity, logStep("extend", { ...log, reserved: end }),
  }
  /// An append seals one block at the head, or refuses before any change: no recorded suffix, the head at the
  /// reserved end, or the queue at its bound.
  action appendBlock = any {
    all { log.own, log.head < log.reserved, log.head - log.durable < QUEUE,
          logStep("append", { ...log, head: log.head + 1 }) },
    all { not(log.own), refused("refusedClosed") },
    all { log.own, log.head >= log.reserved, refused("refusedReserved") },
    all { log.own, log.head < log.reserved, log.head - log.durable >= QUEUE, refused("refusedQueue") },
  }
  action written = all { log.durable < log.head, logStep("written", { ...log, durable: log.durable + 1 }) }
  /// A settled Publish of cut `c` raises the floor and the capacity, and a cut at or past the tenure's start drops
  /// every predecessor suffix. The typed domain bounds the capacity. The log part takes the settlement as given: the
  /// coupling of a floor rise to the slot part's settling success is the Rust rule `settled_floor`, which this model
  /// does not check.
  action publish(c: int): bool = all {
    log.floor <= c, c <= log.head, minOf(c, log.start) + J <= LMAX + J,
    logStep("publish", { ...log, floor: c, capacity: maxOf(log.capacity, minOf(c, log.start) + J),
                         chain: if (c >= log.start) (if (log.own) 1 else 0) else log.chain }),
  }

  action reserve(k: int): bool = any {
    all { count(slots, "reserved") == 0, slots.status.get(k) == "free",
          slotStep("reserve", { ...slots, status: slots.status.set(k, "reserved") }) },
    all { count(slots, "reserved") == 0, count(slots, "free") == 0, refused("refusedSlot") },
  }
  action writeUnit(k: int): bool = all {
    slots.status.get(k) == "reserved",
    slotStep("writeUnit", { ...slots, exposed: slots.exposed.union(Set(k)), wrote: k }),
  }
  action abandonStage(k: int): bool = all {
    slots.status.get(k) == "reserved",
    slotStep("abandon", { ...slots, status: slots.status.set(k, left(slots, k)) }),
  }
  /// The stage's Publish is recorded in the set before it is sent, ending its reservation.
  action submit(k: int): bool = all {
    slots.status.get(k) == "reserved", slotStep("submit", { ...slots, status: slots.status.set(k, "submitted") }),
  }
  /// The recorded Publish is sent; the store may apply it, and its outcome is unknown until a success settles the
  /// set.
  action send(k: int): bool = all {
    slots.status.get(k) == "submitted",
    slotStep("send", { ...slots, status: slots.status.set(k, "pending"), inflight: slots.inflight.union(Set(k)) }),
  }
  /// A recorded Publish the client refused before sending leaves the set: its slot goes where `left` sends it. A
  /// sent Publish stays pending, since the store may still apply it.
  action abandonPending(k: int): bool = all {
    slots.status.get(k) == "submitted",
    slotStep("abandonPending", { ...slots, status: slots.status.set(k, left(slots, k)) }),
  }
  /// The store applies a sent Publish. Under the exact-version CAS every other sent Publish expected the version it
  /// replaced, so none of them can apply afterwards.
  action commit(k: int): bool = all {
    slots.inflight.contains(k), slotStep("commit", { ...slots, named: k, inflight: Set() }),
  }
  /// The acknowledged success of the write the store's slot came from, with no Publish sent after it still in
  /// flight: the set becomes that slot alone.
  action settle = all {
    if (slots.named == -1) false else slots.status.get(slots.named) == "pending",
    slots.inflight == Set(),
    slotStep("settle", { ...slots, status: SLOTS.mapBy(k =>
      if (k == slots.named) "named"
      else if (Set("named", "submitted", "pending").contains(slots.status.get(k))) left(slots, k)
      else slots.status.get(k)) }),
  }
  /// The slot half of the acknowledged success of a later own write that names no new checkpoint, a suffix record,
  /// extension or certification, whose log half is `recordSuffix` or `extend`: with no Publish recorded and unsent,
  /// the write followed every Publish still in the set, so the set becomes the store's slot alone, every other slot
  /// leaves through `left`, and the version it committed ends every Publish in flight.
  action settleByWrite = all {
    count(slots, "submitted") == 0,
    slotStep("settleByWrite", { ...slots, inflight: Set(), status: SLOTS.mapBy(k =>
      if (k == slots.named) "named"
      else if (Set("named", "pending").contains(slots.status.get(k))) left(slots, k)
      else slots.status.get(k)) }),
  }
  /// Timing-only release of a quarantined slot: outside `step`, the control the grace mutant adds.
  action graceRelease(k: int): bool = all {
    slots.status.get(k) == "quarantined", slotStep("grace", { ...slots, status: slots.status.set(k, "free") }),
  }
  /// Host loss and the successor's takeover: its suffix starts at the predecessor's reserved end with nothing
  /// recorded, the chain is kept, and its fence, under END, ends every earlier attempt, so the set is the store's
  /// slot alone and no slot is exposed.
  action takeover = all {
    log.reserved <= LMAX,
    log' = { ...log, start: log.reserved, head: log.reserved, durable: log.reserved, own: false,
             capacity: minOf(log.floor, log.reserved) + J },
    slots' = { status: SLOTS.mapBy(k => if (k == slots.named) "named" else "free"), named: slots.named,
               exposed: Set(), wrote: -1, inflight: Set() },
    advance("takeover"),
  }

  action step = any {
    nondet r = 1.to(J).oneOf() recordSuffix(r),
    nondet end = 0.to(LMAX + J).oneOf() extend(end),
    appendBlock,
    written,
    nondet c = LSNS.oneOf() publish(c),
    nondet k = SLOTS.oneOf() reserve(k),
    nondet k = SLOTS.oneOf() writeUnit(k),
    nondet k = SLOTS.oneOf() abandonStage(k),
    nondet k = SLOTS.oneOf() submit(k),
    nondet k = SLOTS.oneOf() send(k),
    nondet k = SLOTS.oneOf() commit(k),
    settle,
    settleByWrite,
    nondet k = SLOTS.oneOf() abandonPending(k),
    takeover,
  }

  val LogInductive = logInv(log) and historyOwnsUnits(log) and typedLog(log)
  val SlotInductive = slotInv(slots) and namedNotReserved(slots)
  /// A unit write lands on a slot other than the one the store names.
  val WriteMissesNamed = ev == "writeUnit" implies slots.wrote != slots.named
  val RefusalChangesNothing =
    Set("refusedChain", "refusedClosed", "refusedReserved", "refusedQueue", "refusedSlot").contains(ev)
      implies (log, slots) == prior
  val safety = LogInductive and SlotInductive and WriteMissesNamed and RefusalChangesNothing

  val witnessRefusedChain = ev == "refusedChain"
  val witnessRefusedQueue = ev == "refusedQueue"
  val witnessRefusedReserved = ev == "refusedReserved"
  val witnessRefusedSlot = ev == "refusedSlot"
  val witnessChainCleared = ev == "publish" and prior._1.chain == CHAIN and log.chain < CHAIN
  val witnessWrapped = ev == "append" and log.head > J
  val witnessQuarantined = SLOTS.exists(k => slots.status.get(k) == "quarantined")
  val witnessSettled = ev == "settle"
  val witnessTakeoverNamed = ev == "takeover" and slots.named != -1
  val witnessWriteBesideNamed = ev == "writeUnit" and slots.named != -1
  val witnessAbandonedPending = ev == "abandonPending"
  val witnessSettledByWrite = ev == "settleByWrite" and prior._2.inflight != Set()
}
