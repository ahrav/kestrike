/// The owner's request namespace of tla/Identity.tla: two peers of two wire slots each, wire generations 1 to 3 with 3
/// the generation limit, two session epochs per peer, a table of three handles and a per-peer share of two.
/// Each step is one namespace call. Zero stands for no watermark, no bound handle and no peer.
module identity {
  const BOUND: int
  type Row = {op: str, epoch: int}
  type Wire = {mark: int, active: int, row: Row}
  type Record = {peer: int, op: str, slot: int, gen: int, ended: bool, unbound: bool, tg: int}
  type Event = {act: str, res: str, peer: int, slot: int, gen: int, op: str, handle: int, tg: int}
  type State = {
    epoch: int -> int, wire: (int, int) -> Wire, table: int -> Record, tgen: int -> int,
    admits: (int, int, int, int) -> int, wrong: int, freed: int, ev: Event
  }
  var st: State
  var turn: int
  pure val PEERS = Set(1, 2)
  pure val SLOTS = Set(1, 2)
  pure val LIMIT = 3
  pure val GENS = 1.to(LIMIT)
  pure val EPOCHS = Set(1, 2)
  pure val HANDLES = Set(1, 2, 3)
  pure val SHARE = 2
  pure val OPS = Set("GET", "PUT")
  pure val NOROW: Row = {op: "none", epoch: 0}
  pure val FREE: Record = {peer: 0, op: "none", slot: 0, gen: 0, ended: false, unbound: false, tg: 0}
  pure def event(act: str, res: str, peer: int, slot: int, gen: int, op: str, handle: int, tg: int): Event =
    {act: act, res: res, peer: peer, slot: slot, gen: gen, op: op, handle: handle, tg: tg}
  def live = HANDLES.filter(h => st.table.get(h) != FREE)
  def held(p: int): Set[int] = live.filter(h => st.table.get(h).peer == p)
  action init = all {
    st' = {epoch: PEERS.mapBy(_ => 1), wire: tuples(PEERS, SLOTS).mapBy(_ => {mark: 0, active: 0, row: NOROW}),
      table: HANDLES.mapBy(_ => FREE), tgen: HANDLES.mapBy(_ => 1),
      admits: tuples(EPOCHS, PEERS, SLOTS, GENS).mapBy(_ => 0), wrong: 0, freed: 0,
      ev: event("init", "", 0, 0, 0, "none", 0, 0)},
    turn' = 0
  }
  action tick = all {turn < BOUND, turn' = turn + 1}
  /// The refusal an admission of wire identity (p, s, g) meets, in the order the namespace checks, or "" for none.
  def refusal(p: int, s: int, g: int): str = {
    val w = st.wire.get((p, s))
    if (w.active != 0) "Busy"
    else if (g <= w.mark) "Stale"
    else if (g == LIMIT) "Exhausted"
    else if (held(p).size() >= SHARE) "PeerPressure"
    else if (live.size() >= HANDLES.size()) "TablePressure"
    else ""
  }
  /// A fresh wire identity takes free handle h: the watermark rises, the handle binds and the row clears.
  action admit(p: int, s: int, g: int, op: str, h: int): bool = all {
    tick, refusal(p, s, g) == "", st.table.get(h) == FREE,
    st' = {...st,
      table: st.table.set(h, {peer: p, op: op, slot: s, gen: g, ended: false, unbound: false, tg: st.tgen.get(h)}),
      wire: st.wire.set((p, s), {mark: g, active: h, row: NOROW}),
      admits: st.admits.setBy((st.epoch.get(p), p, s, g), n => n + 1),
      ev: event("admit", "Admitted", p, s, g, op, h, st.tgen.get(h))}
  }
  /// A refused admission names its refusal and changes nothing else.
  action refuse(p: int, s: int, g: int): bool = all {
    tick, refusal(p, s, g) != "",
    st' = {...st, ev: event("refuse", refusal(p, s, g), p, s, g, "none", 0, 0)}
  }
  /// A request ends: under its session the slot retains a row of the request's operation and epoch; a request
  /// whose session was replaced ends without one.
  action end(p: int, s: int): bool = {
    val w = st.wire.get((p, s))
    val h = w.active
    all {
      tick, h != 0, w.row == NOROW, not(st.table.get(h).ended),
      st' = {...st,
        table: st.table.setBy(h, r => {...r, ended: true}),
        wire: if (w.mark == 0) st.wire
          else st.wire.set((p, s), {...w, row: {op: st.table.get(h).op, epoch: st.epoch.get(p)}}),
        ev: event("end", if (w.mark == 0) "EndedReplaced" else "Ended", p, s, st.table.get(h).gen, st.table.get(h).op,
          h, st.table.get(h).tg)}
    }
  }
  /// An ended request whose row is retained frees its wire slot while its record drains, marked unbound.
  action unbind(p: int, s: int): bool = {
    val w = st.wire.get((p, s))
    val h = w.active
    all {
      tick, h != 0, w.row != NOROW, st.table.get(h).ended,
      st' = {...st,
        wire: st.wire.set((p, s), {...w, active: 0}),
        table: st.table.setBy(h, r => {...r, unbound: true}),
        ev: event("unbind", "Unbound", p, s, st.table.get(h).gen, st.table.get(h).op, h, st.table.get(h).tg)}
    }
  }
  /// A release names a handle and a table generation. Naming the handle's current generation frees the record,
  /// clears the binding when the slot still binds the handle and advances the generation; an earlier one frees nothing.
  action release(p: int, s: int, h: int, tg: int): bool = {
    val w = st.wire.get((p, s))
    val rec = st.table.get(h)
    val exact = tg == st.tgen.get(h)
    all {
      tick, w.active == h or (rec.unbound and rec.peer == p), rec.ended, 1 <= tg, tg <= st.tgen.get(h),
      st' = if (exact) {...st,
          table: st.table.set(h, FREE), tgen: st.tgen.setBy(h, n => n + 1),
          wire: st.wire.set((p, s), {...w, active: if (w.active == h) 0 else w.active}),
          freed: st.freed + (if (rec.tg == tg) 0 else 1),
          ev: event("release", "Released", p, s, rec.gen, rec.op, h, tg)}
        else {...st, ev: event("release", "StaleRelease", p, s, 0, "none", h, tg)}
    }
  }
  /// Session replacement retires the peer: watermarks and rows clear, live bindings stay.
  action replace(p: int): bool = all {
    tick, st.epoch.get(p) < EPOCHS.size(),
    st' = {...st,
      epoch: st.epoch.setBy(p, e => e + 1),
      wire: st.wire.keys().mapBy(k => if (k._1 == p) {mark: 0, active: st.wire.get(k).active, row: NOROW} else st.wire.get(k)),
      ev: event("replace", "Replaced", p, 0, 0, "none", 0, 0)}
  }
  /// A frame of operation op naming wire identity (p, s, g) routes by generation; at the watermark, a bound
  /// request or a retained row of the other operation counts WrongOperation and changes nothing else.
  action route(p: int, s: int, g: int, op: str): bool = {
    val w = st.wire.get((p, s))
    val other = (w.active != 0 and st.table.get(w.active).op != op) or (w.row != NOROW and w.row.op != op)
    val res = if (g < w.mark) "Older" else if (g > w.mark) "Fresh" else if (other) "WrongOperation" else "Same"
    all {
      tick,
      st' = {...st, wrong: st.wrong + (if (res == "WrongOperation") 1 else 0), ev: event("route", res, p, s, g, op, 0, 0)}
    }
  }
  def bound(h: int): bool = tuples(PEERS, SLOTS).exists(k => st.wire.get(k).active == h)
  val ExactBinding = tuples(PEERS, SLOTS).forall(k => {
    val w = st.wire.get(k)
    w.active != 0 implies {
      val r = st.table.get(w.active)
      r.peer == k._1 and r.slot == k._2 and (w.mark == 0 or r.gen == w.mark)
    }
  })
  val OneBindingPerHandle = and {
    tuples(PEERS, SLOTS).forall(j => tuples(PEERS, SLOTS).forall(k =>
      (st.wire.get(j).active != 0 and st.wire.get(j).active == st.wire.get(k).active) implies j == k)),
    live.forall(h => (bound(h) iff not(st.table.get(h).unbound)) and (st.table.get(h).unbound implies st.table.get(h).ended))
  }
  val OneAdmission = st.admits.keys().forall(k => st.admits.get(k) <= 1)
  val Capacity = live.size() <= HANDLES.size() and PEERS.forall(p => held(p).size() <= SHARE)
  val ExactRelease = st.freed == 0
  val safety = ExactBinding and OneBindingPerHandle and OneAdmission and Capacity and ExactRelease
  val witnessAdmitted = st.ev.res == "Admitted"
  val witnessBusy = st.ev.res == "Busy"
  val witnessStale = st.ev.res == "Stale"
  val witnessExhausted = st.ev.res == "Exhausted"
  val witnessPeerPressure = st.ev.res == "PeerPressure"
  val witnessTablePressure = st.ev.res == "TablePressure"
  val witnessEnded = st.ev.res == "Ended"
  val witnessEndedReplaced = st.ev.res == "EndedReplaced"
  val witnessUnbound = st.ev.res == "Unbound"
  val witnessReleasedBound = st.ev.res == "Released" and not(live.contains(st.ev.handle)) and st.ev.gen != 0 and
    st.wire.get((st.ev.peer, st.ev.slot)).active == 0 and st.wire.get((st.ev.peer, st.ev.slot)).mark == st.ev.gen
  val witnessReleasedBesideSuccessor = st.ev.res == "Released" and st.wire.get((st.ev.peer, st.ev.slot)).active != 0
  val witnessStaleRelease = st.ev.res == "StaleRelease"
  val witnessReplaced = st.ev.res == "Replaced"
  val witnessDrainingAfterReplacement = st.ev.res == "Replaced" and
    SLOTS.exists(s => st.wire.get((st.ev.peer, s)).active != 0)
  val witnessSuccessorBesideUnbound = st.ev.res == "Admitted" and
    held(st.ev.peer).exists(h => st.table.get(h).unbound and st.table.get(h).slot == st.ev.slot)
  val witnessReadmittedAfterReplacement = st.ev.res == "Admitted" and st.epoch.get(st.ev.peer) == 2 and
    st.admits.get((1, st.ev.peer, st.ev.slot, st.ev.gen)) == 1
  val witnessOlder = st.ev.res == "Older"
  val witnessFresh = st.ev.res == "Fresh"
  val witnessSame = st.ev.res == "Same"
  val witnessWrongOperation = st.ev.res == "WrongOperation"
  val witnessWrongOperationRow = st.ev.res == "WrongOperation" and st.wire.get((st.ev.peer, st.ev.slot)).active == 0
  action step = any {
    {
      nondet p = PEERS.oneOf()
      nondet s = SLOTS.oneOf()
      nondet g = GENS.oneOf()
      nondet op = OPS.oneOf()
      nondet h = HANDLES.oneOf()
      admit(p, s, g, op, h)
    },
    {
      nondet p = PEERS.oneOf()
      nondet s = SLOTS.oneOf()
      nondet g = GENS.oneOf()
      refuse(p, s, g)
    },
    {
      nondet p = PEERS.oneOf()
      nondet s = SLOTS.oneOf()
      end(p, s)
    },
    {
      nondet p = PEERS.oneOf()
      nondet s = SLOTS.oneOf()
      unbind(p, s)
    },
    {
      nondet p = PEERS.oneOf()
      nondet s = SLOTS.oneOf()
      nondet h = HANDLES.oneOf()
      nondet earlier = Set(0, 1).oneOf()
      release(p, s, h, st.tgen.get(h) - earlier)
    },
    {
      nondet p = PEERS.oneOf()
      replace(p)
    },
    {
      nondet p = PEERS.oneOf()
      nondet s = SLOTS.oneOf()
      nondet g = GENS.oneOf()
      nondet op = OPS.oneOf()
      route(p, s, g, op)
    },
  }
}
