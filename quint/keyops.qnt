/// One key of a live storage: its fill attempts, its resident mapping, the rights that name its extents and the unit
/// ledger, over `UNITS` one-unit slots and a fill table of two records. `begin` grants an attempt, `reserve` claims a
/// slot for it, `receive` submits the record's one write and `writeDone` delivers that write's terminal. `publish`
/// makes the slot resident under a deadline, returns the object's first lease and retires an incumbent; every refused
/// publication consumes its fill. `lookup` answers Hit with a lease, Missing, or Expired at or past the deadline.
/// `invalidate` ends the mapping and revokes the key's current attempt, `expire` and `evict` remove an unleased
/// resident, `certify` and `service` release a retired slot's anchor and return it once no right names it,
/// `serviceFills` frees departed records, `close` shuts admission and `closeService` is the bounded cleanup after it.
/// `st.pubs`, `st.ended` and `st.voided` are history sets no action reads.
module keyops {
  const BOUND: int
  /// The volume's slots, each holding one unit.
  const UNITS: int
  pure val SLOTS = 0.to(UNITS - 1)
  pure val FILLS = 2
  pure val SERIALS = 4
  pure val RIGHTS = 2
  pure val MAXT = 2
  /// `write` is "none" before the submit, "out" while the command is outstanding, then "ok" or "failed".
  type Slot = { state: str, inc: int, label: int, deadline: int, anchor: bool, cert: bool, write: str }
  /// A fill record: its attempt's serial, the slot the attempt reserved or -1, and the record's two flags.
  type Fill = { serial: int, slot: int, revoked: bool, departed: bool }
  /// A lease or a write set's right on one incarnation of a slot.
  type Right = { slot: int, inc: int, kind: str, id: int }
  type Ledger = { free: int, reserved: int, resident: int, retired: int }
  type State = {
    slots: int -> Slot, fills: Set[Fill], rights: Set[Right], ledger: Ledger, clock: int, closed: bool, issued: int,
    pubs: Set[{ label: int, deadline: int }], ended: Set[int], voided: Set[int]
  }
  /// The last action, its arguments and result, and what it read before it changed the state.
  type Ev = {
    act: str, res: str, n: int, s: int, d: int, ok: bool, label: int, deadline: int, write: str,
    refs: int, held: bool, kept: bool, changed: bool, shut: bool, current: bool
  }
  var st: State
  var ev: Ev
  var turn: int

  pure val vacant: Slot = { state: "Free", inc: 0, label: 0, deadline: 0, anchor: false, cert: false, write: "none" }
  pure val nofill: Fill = { serial: 0, slot: -1, revoked: false, departed: true }
  pure val quiet: Ev = {
    act: "init", res: "", n: 0, s: -1, d: 0, ok: false, label: 0, deadline: 0, write: "none",
    refs: 0, held: false, kept: true, changed: false, shut: false, current: false
  }
  pure def lowest(xs: Set[int]): int = xs.fold(99, (low, x) => if (x < low) x else low)
  pure def named(s: State, slot: int): Set[Right] = s.rights.filter(r => r.slot == slot and r.inc == s.slots.get(slot).inc)
  pure def leases(s: State, slot: int): Set[Right] = named(s, slot).filter(r => r.kind == "lease")
  /// The slot's count: every right that names its incarnation, plus its anchor.
  pure def refs(s: State, slot: int): int = named(s, slot).size() + (if (s.slots.get(slot).anchor) 1 else 0)
  pure def resident(s: State): Set[int] = SLOTS.filter(x => s.slots.get(x).state == "Resident")
  pure def fillOf(s: State, n: int): Fill = s.fills.fold(nofill, (found, f) => if (f.serial == n) f else found)
  pure def setFill(s: State, f: Fill): State = { ...s, fills: s.fills.filter(g => g.serial != f.serial).union(Set(f)) }
  pure def term(state: str): str = if (state == "Filling") "reserved" else if (state == "Resident") "resident" else "retired"
  pure def move(l: Ledger, src: str, dst: str): Ledger = {
    val taken = if (src == "free") { ...l, free: l.free - 1 } else if (src == "reserved") { ...l, reserved: l.reserved - 1 }
                else if (src == "resident") { ...l, resident: l.resident - 1 } else { ...l, retired: l.retired - 1 }
    if (dst == "free") { ...taken, free: taken.free + 1 } else if (dst == "reserved") { ...taken, reserved: taken.reserved + 1 }
    else if (dst == "resident") { ...taken, resident: taken.resident + 1 } else { ...taken, retired: taken.retired + 1 }
  }
  /// The slot's extent goes back to the allocator; its incarnation stays consumed.
  pure def returned(s: State, slot: int): State = {
    val old = s.slots.get(slot)
    { ...s, slots: s.slots.set(slot, { ...vacant, inc: old.inc }), ledger: move(s.ledger, term(old.state), "free") }
  }
  /// The slot is abandoned or its mapping ended: it stays held, with its anchor and rights, until service returns it.
  pure def retire(s: State, slot: int): State = {
    val old = s.slots.get(slot)
    { ...s, slots: s.slots.set(slot, { ...old, state: "Retired" }), ledger: move(s.ledger, term(old.state), "retired") }
  }
  /// The resident's mapping ends.
  pure def unmap(s: State, slot: int): State = { ...retire(s, slot), ended: s.ended.union(Set(s.slots.get(slot).label)) }
  /// One service visit: a certified anchor is released, and the slot returns once its count is zero.
  pure def serviced(s: State, slot: int): State = {
    val old = s.slots.get(slot)
    val anchored = old.anchor and not(old.cert)
    val unanchored = { ...s, slots: s.slots.set(slot, { ...old, anchor: anchored }) }
    if (old.state != "Retired") s
    else if (refs(unanchored, slot) == 0) returned(unanchored, slot) else unanchored
  }
  pure def certified(s: State): State = { ...s, slots: SLOTS.mapBy(x => {
    val old = s.slots.get(x)
    if (old.state == "Retired" and old.anchor) { ...old, cert: true } else old
  }) }
  /// Whether a visit that returned `slot` left a right naming it or an anchor still awaiting grace.
  pure def heldReturn(before: State, after: State, slot: int): bool = {
    val old = before.slots.get(slot)
    old.state == "Retired" and after.slots.get(slot).state == "Free"
      and (named(before, slot).size() > 0 or (old.anchor and not(old.cert)))
  }
  pure def visit(before: State, after: State): str =
    if (SLOTS.exists(x => before.slots.get(x).state == "Retired" and after.slots.get(x).state == "Free")) "Returned"
    else if (SLOTS.exists(x => after.slots.get(x).state == "Retired")) "Held" else "None"

  action init = all {
    st' = { slots: SLOTS.mapBy(_ => vacant), fills: Set(), rights: Set(), ledger: { free: UNITS, reserved: 0, resident: 0, retired: 0 },
      clock: 0, closed: false, issued: 1, pubs: Set(), ended: Set(), voided: Set() },
    ev' = quiet, turn' = 0,
  }
  action apply(e: Ev, after: State): bool = all {
    turn < BOUND, turn' = turn + 1, st' = after,
    ev' = { ...e, shut: st.closed, current: st.fills.exists(f => not(f.revoked) and not(f.departed)),
      kept: resident(after) == resident(st) and resident(st).forall(x => after.slots.get(x) == st.slots.get(x)) and after.pubs == st.pubs,
      changed: after.slots != st.slots or after.ledger != st.ledger or after.rights != st.rights },
  }
  action begin = {
    val res = if (st.closed) "Closed" else if (st.fills.exists(f => not(f.revoked))) "InProgress"
              else if (st.fills.size() >= FILLS) "FillSlotsFull" else "Granted"
    val granted = { ...st, fills: st.fills.union(Set({ serial: st.issued, slot: -1, revoked: false, departed: false })), issued: st.issued + 1 }
    all { st.issued <= SERIALS, apply({ ...quiet, act: "begin", res: res, n: st.issued }, if (res == "Granted") granted else st) }
  }
  action reserve(n: int): bool = {
    val f = fillOf(st, n)
    val free = SLOTS.filter(x => st.slots.get(x).state == "Free")
    val res = if (st.closed) "Closed" else if (free.size() == 0) "CleanReserve" else if (f.revoked) "Superseded" else "Reserved"
    val s = lowest(free)
    val claimed = { ...setFill(st, { ...f, slot: s }),
      slots: st.slots.set(s, { ...vacant, state: "Filling", inc: st.slots.get(s).inc + 1, label: n }),
      ledger: move(st.ledger, "free", "reserved") }
    all { not(f.departed), f.slot < 0,
      apply({ ...quiet, act: "reserve", res: res, n: n, s: if (res == "Reserved") s else -1 },
        if (res == "Reserved") claimed else setFill(st, { ...f, departed: true })) }
  }
  action receive(n: int): bool = {
    val f = fillOf(st, n)
    val res = if (st.closed) "Closed" else if (f.revoked) "Revoked" else "Submitted"
    all { not(f.departed), f.slot >= 0, st.slots.get(f.slot).write == "none",
      apply({ ...quiet, act: "receive", res: res, n: n, s: f.slot },
        if (res == "Submitted") { ...st, slots: st.slots.set(f.slot, { ...st.slots.get(f.slot), write: "out" }),
          rights: st.rights.union(Set({ slot: f.slot, inc: st.slots.get(f.slot).inc, kind: "write", id: 0 })) }
        else st) }
  }
  action writeDone(s: int, ok: bool): bool = {
    val right = { slot: s, inc: st.slots.get(s).inc, kind: "write", id: 0 }
    all { SLOTS.contains(s), st.rights.contains(right),
      apply({ ...quiet, act: "writeDone", res: if (ok) "Written" else "Failed", s: s, ok: ok },
        { ...st, rights: st.rights.exclude(Set(right)),
          slots: st.slots.set(s, { ...st.slots.get(s), write: if (ok) "ok" else "failed" }) }) }
  }
  action publish(n: int, d: int): bool = {
    val f = fillOf(st, n)
    val slot = st.slots.get(f.slot)
    val incumbents = resident(st)
    val res = if (slot.write != "ok") "Incomplete" else if (st.closed) "Closed" else if (f.revoked) "Superseded"
              else if (st.clock >= d) "Expired" else if (incumbents.size() > 0) "Replaced" else "Published"
    val gone = setFill(st, { ...f, departed: true })
    val displaced = incumbents.fold(gone, (acc, i) => unmap(acc, i))
    val disposed = if (slot.write == "none") returned(gone, f.slot) else retire(gone, f.slot)
    val committed = { ...setFill(displaced, { ...f, departed: true, revoked: true }),
      slots: displaced.slots.set(f.slot, { ...slot, state: "Resident", deadline: d, anchor: true }),
      ledger: move(displaced.ledger, "reserved", "resident"),
      rights: displaced.rights.union(Set({ slot: f.slot, inc: slot.inc, kind: "lease", id: 1 })),
      pubs: displaced.pubs.union(Set({ label: n, deadline: d })) }
    all { not(f.departed), f.slot >= 0,
      apply({ ...quiet, act: "publish", res: res, n: n, s: f.slot, d: d, label: n, deadline: d, write: slot.write },
        if (res == "Published" or res == "Replaced") committed
        else if (res == "Expired") setFill(disposed, { ...f, departed: true, revoked: true })
        else disposed) }
  }
  action abort(n: int): bool = {
    val f = fillOf(st, n)
    val gone = setFill(st, { ...f, departed: true })
    all { not(f.departed),
      apply({ ...quiet, act: "abort", res: "Aborted", n: n, s: f.slot },
        if (f.slot < 0) gone else if (st.slots.get(f.slot).write == "none") returned(gone, f.slot) else retire(gone, f.slot)) }
  }
  action lookup = {
    val found = resident(st)
    val v = lowest(found)
    val res = if (st.closed) "Closed" else if (found.size() == 0) "Missing" else if (st.clock >= st.slots.get(v).deadline) "Expired"
              else if (leases(st, v).size() >= RIGHTS) "RetainLimit" else "Hit"
    val id = if (leases(st, v).exists(r => r.id == 1)) 2 else 1
    apply({ ...quiet, act: "lookup", res: res, s: if (found.size() == 0) -1 else v,
        label: if (found.size() == 0) 0 else st.slots.get(v).label, deadline: if (found.size() == 0) 0 else st.slots.get(v).deadline },
      if (res == "Hit") { ...st, rights: st.rights.union(Set({ slot: v, inc: st.slots.get(v).inc, kind: "lease", id: id })) } else st)
  }
  action release(s: int): bool = {
    val held = leases(st, s)
    val id = if (held.exists(r => r.id == 2)) 2 else 1
    all { SLOTS.contains(s), held.size() > 0,
      apply({ ...quiet, act: "release", res: "Released", s: s },
        { ...st, rights: st.rights.exclude(Set({ slot: s, inc: st.slots.get(s).inc, kind: "lease", id: id })) }) }
  }
  action invalidate = {
    val found = resident(st)
    val current = st.fills.filter(f => not(f.revoked))
    val unmapped = found.fold(st, (acc, i) => unmap(acc, i))
    val ended = { ...unmapped, fills: unmapped.fills.map(f => { ...f, revoked: true }),
      voided: unmapped.voided.union(current.map(f => f.serial)) }
    apply({ ...quiet, act: "invalidate", res: if (st.closed) "Closed" else "Invalidated",
        n: if (st.closed or current.size() == 0) 0 else lowest(current.map(f => f.serial)),
        s: if (st.closed or found.size() == 0) -1 else lowest(found),
        label: if (st.closed or found.size() == 0) 0 else st.slots.get(lowest(found)).label },
      if (st.closed) st else ended)
  }
  action expire = {
    val due = resident(st).filter(x => refs(st, x) == 1 and st.clock >= st.slots.get(x).deadline)
    val v = lowest(due)
    apply({ ...quiet, act: "expire", res: if (due.size() > 0) "Removed" else "None", s: if (due.size() > 0) v else -1,
        label: if (due.size() > 0) st.slots.get(v).label else 0, deadline: if (due.size() > 0) st.slots.get(v).deadline else 0,
        refs: if (due.size() > 0) refs(st, v) else 0 },
      due.fold(st, (acc, i) => unmap(acc, i)))
  }
  action evict = {
    val idle = resident(st).filter(x => refs(st, x) == 1)
    val v = lowest(idle)
    val replacing = st.fills.exists(f => not(f.revoked) and not(f.departed))
    val res = if (idle.size() == 0) "None" else if (replacing) "Replacing" else "Removed"
    apply({ ...quiet, act: "evict", res: res, s: if (idle.size() > 0) v else -1,
        label: if (idle.size() > 0) st.slots.get(v).label else 0, refs: if (idle.size() > 0) refs(st, v) else 0 },
      if (res == "Removed") unmap(st, v) else st)
  }
  action certify = apply({ ...quiet, act: "certify", res: "Certified" }, certified(st))
  action serviceOne(s: int): bool = {
    val visited = serviced(st, s)
    all { SLOTS.contains(s), st.slots.get(s).state == "Retired",
      apply({ ...quiet, act: "serviceOne", res: if (visited.slots.get(s).state == "Free") "Returned" else "Held", s: s,
        held: heldReturn(st, visited, s) }, visited) }
  }
  action service = {
    val visited = SLOTS.fold(st, (acc, x) => serviced(acc, x))
    apply({ ...quiet, act: "service", res: visit(st, visited), held: SLOTS.exists(x => heldReturn(st, visited, x)) }, visited)
  }
  action serviceFills = apply({ ...quiet, act: "serviceFills", res: if (st.fills.exists(f => f.departed)) "Freed" else "None" },
    { ...st, fills: st.fills.filter(f => not(f.departed)) })
  action close = all { not(st.closed), apply({ ...quiet, act: "close", res: "Done" }, { ...st, closed: true }) }
  /// One funded close-service call: the index sweep, fill service, slot service and one certification, in that order.
  action closeService = {
    val swept = resident(st).fold(st, (acc, i) => unmap(acc, i))
    val freed = { ...swept, fills: swept.fills.filter(f => not(f.departed)) }
    val visited = SLOTS.fold(freed, (acc, x) => serviced(acc, x))
    all { st.closed,
      apply({ ...quiet, act: "closeService", res: visit(freed, visited), held: SLOTS.exists(x => heldReturn(freed, visited, x)) },
        certified(visited)) }
  }
  action tick = all { st.clock < MAXT, apply({ ...quiet, act: "tick", res: "Tick" }, { ...st, clock: st.clock + 1 }) }

  val served = Set("Hit", "Published", "Replaced")
  /// A hit returns a label a publication published whose visibility no invalidation, replacement, expiry, eviction or
  /// close sweep ended.
  val HitIsLive = (ev.act == "lookup" and ev.res == "Hit") implies
    (st.pubs.exists(p => p.label == ev.label) and not(st.ended.contains(ev.label)))
  /// No lookup and no publication hands out a lease at or after the object's deadline.
  val NoServeAtDeadline = served.contains(ev.res) implies st.clock < ev.deadline
  /// A lookup answers Expired only for a resident at or past its deadline.
  val ExpiredIsLapsed = (ev.act == "lookup" and ev.res == "Expired") implies
    resident(st).exists(x => st.slots.get(x).label == ev.label and st.clock >= st.slots.get(x).deadline)
  /// PUBLISH-COMPLETE: a fill publishes only after its write's successful terminal released the write right.
  val PublishComplete = ((ev.res == "Published" or ev.res == "Replaced") implies ev.write == "ok")
    and resident(st).forall(x => st.slots.get(x).write == "ok" and not(named(st, x).exists(r => r.kind == "write")))
  /// REVOKE: no attempt an invalidation revoked publishes.
  val RevokedNeverPublishes = st.pubs.forall(p => not(st.voided.contains(p.label)))
  /// REUSE: a slot returns only at a count of zero, its anchor released after a certification.
  val ReuseAtZero = not(ev.held)
  /// EVICT-NO-REUSE: every lease and write right names a held slot at the incarnation it was taken on.
  val EvictNoReuse = st.rights.forall(r => st.slots.get(r.slot).inc == r.inc and st.slots.get(r.slot).state != "Free")
  val refusals = Set("Closed", "InProgress", "FillSlotsFull", "CleanReserve", "Superseded", "Revoked", "Missing", "Expired", "RetainLimit")
  /// REJECT-OWNS-NOTHING: a refused grant, reservation, receive, lookup or invalidation leaves every slot, the ledger
  /// and every right as they were.
  val RejectOwnsNothing = (Set("begin", "reserve", "receive", "lookup", "invalidate").contains(ev.act) and refusals.contains(ev.res))
    implies not(ev.changed)
  /// A refused publication leaves the incumbent's mapping and record as they were.
  val RefusalKeepsIncumbent = (ev.act == "publish" and not(served.contains(ev.res))) implies ev.kept
  /// The key has at most one resident mapping.
  val OneMapping = resident(st).size() <= 1
  /// The key has at most one current attempt, and the table holds at most `FILLS` records.
  val OneAttempt = st.fills.filter(f => not(f.revoked)).size() <= 1 and st.fills.size() <= FILLS
  pure def census(s: State, state: str): int = SLOTS.filter(x => s.slots.get(x).state == state).size()
  /// The four ledger terms equal the slot census and sum to the unit count.
  val UnitsConserved = st.ledger.free + st.ledger.reserved + st.ledger.resident + st.ledger.retired == SLOTS.size()
    and st.ledger.free == census(st, "Free") and st.ledger.reserved == census(st, "Filling")
    and st.ledger.resident == census(st, "Resident") and st.ledger.retired == census(st, "Retired")
  /// An expiry removes only an unleased resident at or past its deadline, and an eviction only an unleased resident
  /// while no undeparted attempt is current.
  val RemovalLegal = ((ev.act == "expire" and ev.res == "Removed") implies (ev.refs == 1 and st.clock >= ev.deadline))
    and ((ev.act == "evict" and ev.res == "Removed") implies (ev.refs == 1 and not(ev.current)))
  /// After close no grant, reservation, receive, publication, hit or invalidation is acknowledged.
  val ClosedAdmitsNothing = ev.shut implies
    not(Set("Granted", "Reserved", "Submitted", "Published", "Replaced", "Hit", "Invalidated").contains(ev.res))
  val safety = HitIsLive and NoServeAtDeadline and ExpiredIsLapsed and PublishComplete and RevokedNeverPublishes and ReuseAtZero and EvictNoReuse
    and RejectOwnsNothing and RefusalKeepsIncumbent and OneMapping and OneAttempt and UnitsConserved and RemovalLegal
    and ClosedAdmitsNothing

  val witnessHit = ev.res == "Hit"
  val witnessExpired = ev.act == "lookup" and ev.res == "Expired"
  val witnessReplaced = ev.res == "Replaced" and SLOTS.exists(x => st.slots.get(x).state == "Retired" and leases(st, x).size() > 0)
  val witnessRevoked = ev.act == "invalidate" and ev.n > 0 and ev.s >= 0
  val witnessSuperseded = ev.act == "publish" and ev.res == "Superseded"
  val witnessIncomplete = ev.act == "publish" and ev.res == "Incomplete"
  val witnessLatePublish = ev.act == "publish" and ev.res == "Expired"
  val witnessSwept = ev.act == "expire" and ev.res == "Removed"
  val witnessEvicted = ev.act == "evict" and ev.res == "Removed"
  val witnessReplacing = ev.res == "Replacing"
  val witnessHeld = (ev.act == "service" or ev.act == "serviceOne") and ev.res == "Held"
    and SLOTS.exists(x => st.slots.get(x).state == "Retired" and not(st.slots.get(x).anchor) and leases(st, x).size() > 0)
  val witnessReused = SLOTS.exists(x => st.slots.get(x).inc >= 2 and st.slots.get(x).state == "Resident")
  val witnessLateTerminal = ev.act == "writeDone" and st.slots.get(ev.s).state == "Retired"
  val witnessInProgress = ev.res == "InProgress"
  val witnessFillSlotsFull = ev.res == "FillSlotsFull"
  val witnessCleanReserve = ev.res == "CleanReserve"
  val witnessRetainLimit = ev.res == "RetainLimit"
  val witnessClosedRefusal = ev.res == "Closed"
  val witnessDrained = st.closed and ev.act == "closeService" and st.ledger.free == SLOTS.size() and st.fills.size() == 0
    and st.pubs.size() > 0

  action step = any {
    begin, lookup, invalidate, expire, evict, certify, service, serviceFills, close, closeService, tick,
    nondet n = 1.to(SERIALS).oneOf()
    any { reserve(n), receive(n), abort(n) },
    nondet n = 1.to(SERIALS).oneOf()
    nondet d = 1.to(MAXT).oneOf()
    publish(n, d),
    nondet s = SLOTS.oneOf()
    any { release(s), serviceOne(s) },
    nondet s = SLOTS.oneOf()
    nondet ok = Set(true, false).oneOf()
    writeDone(s, ok),
  }
}
