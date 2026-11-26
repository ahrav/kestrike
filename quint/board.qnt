/// The client's release board of tla/Identity.tla: two table handles, two board cores, wire generations 1 to 5 below
/// the generation limit of 6, and at most two leases handed per request. Each step is one board or namespace call.
module board {
  const BOUND: int
  type Lease = {core: int, gen: int, live: int, handed: int, open: bool, stale: int, score: int, sgen: int}
  type Event = {act: str, res: str, handle: int}
  type State = {core: int, next: int, orphans: int, leases: int -> Lease, ev: Event}
  var st: State
  var turn: int
  pure val HANDLES = Set(1, 2)
  pure val CORES = 2
  pure val LIMIT = 6
  pure val LEASES = 2
  pure val CLOSED: Lease = {core: 0, gen: 1, live: 1, handed: 0, open: false, stale: 0, score: 0, sgen: 0}
  def open = HANDLES.filter(h => st.leases.get(h).open)
  action init = all {
    st' = {core: 1, next: 1, orphans: 0, leases: HANDLES.mapBy(_ => CLOSED), ev: {act: "init", res: "", handle: 0}},
    turn' = 0
  }
  action tick = all {turn < BOUND, turn' = turn + 1}
  /// A request admitted under the current core takes the next wire generation and the handle's live generation.
  action admit(h: int): bool = {
    val l = st.leases.get(h)
    all {
      tick, not(l.open), st.next < LIMIT,
      st' = {...st, next: st.next + 1,
        leases: st.leases.set(h, {...l, core: st.core, gen: l.live, handed: 0, open: true}),
        ev: {act: "admit", res: "Admitted", handle: h}}
    }
  }
  /// A board past its last wire generation refuses the admission and changes nothing else.
  action exhausted(h: int): bool = all {
    tick, not(st.leases.get(h).open), st.next >= LIMIT,
    st' = {...st, ev: {act: "exhausted", res: "Generations", handle: h}}
  }
  /// The open request hands the application one more lease.
  action hand(h: int): bool = {
    val l = st.leases.get(h)
    all {
      tick, l.open, l.handed < LEASES,
      st' = {...st, leases: st.leases.set(h, {...l, handed: l.handed + 1}), ev: {act: "hand", res: "Handed", handle: h}}
    }
  }
  /// The application returns a lease of the open request, which is credited.
  action giveBack(h: int): bool = {
    val l = st.leases.get(h)
    all {
      tick, l.handed > 0,
      st' = {...st, leases: st.leases.set(h, {...l, handed: l.handed - 1}), ev: {act: "giveBack", res: "Credited", handle: h}}
    }
  }
  /// The application returns a lease of a closed request. It credits the handle's open request only under the
  /// lease's core and generation, and otherwise frees one orphan.
  action giveBackStale(h: int): bool = {
    val l = st.leases.get(h)
    val credits = l.open and l.score == st.core and l.sgen == l.gen
    all {
      tick, l.stale > 0,
      st' = {...st, orphans: if (credits) st.orphans else st.orphans - 1,
        leases: st.leases.set(h, {...l, stale: l.stale - 1}),
        ev: {act: "giveBackStale", res: if (credits) "CreditedStale" else if (l.score < st.core) "FreedEarlierCore" else "Freed",
          handle: h}}
    }
  }
  /// A close turns the request's held leases into orphans and advances the handle's generation.
  action close(h: int): bool = {
    val l = st.leases.get(h)
    all {
      tick, l.open, l.stale == 0,
      st' = {...st, orphans: st.orphans + l.handed,
        leases: st.leases.set(h, {...l, open: false, live: l.live + 1, stale: l.handed, handed: 0, score: l.core, sgen: l.gen}),
        ev: {act: "close", res: if (l.handed > 0) "ClosedHolding" else "Closed", handle: h}}
    }
  }
  /// Destroying the namespace closes every open request; its successor attaches under the next core and its
  /// handle generations restart.
  action attach: bool = all {
    tick, st.core < CORES, open.forall(h => st.leases.get(h).stale == 0),
    st' = {...st, core: st.core + 1, orphans: st.orphans + open.fold(0, (sum, h) => sum + st.leases.get(h).handed),
      leases: st.leases.keys().mapBy(h => {
        val l = st.leases.get(h)
        if (l.open) {...l, open: false, live: 1, stale: l.handed, handed: 0, score: l.core, sgen: l.gen}
        else {...l, live: 1}
      }),
      ev: {act: "attach", res: if (open.size() > 0) "AttachedClosing" else "Attached", handle: 0}}
  }
  val OrphanConservation = st.orphans == HANDLES.fold(0, (sum, h) => sum + st.leases.get(h).stale)
  val safety = OrphanConservation
  val witnessAdmitted = st.ev.res == "Admitted"
  val witnessGenerations = st.ev.res == "Generations"
  val witnessHanded = st.ev.res == "Handed"
  val witnessCredited = st.ev.res == "Credited"
  val witnessFreed = st.ev.res == "Freed"
  val witnessFreedEarlierCore = st.ev.res == "FreedEarlierCore"
  val witnessFreedBesideOpen = (st.ev.res == "Freed" or st.ev.res == "FreedEarlierCore") and st.leases.get(st.ev.handle).open
  val witnessClosed = st.ev.res == "Closed"
  val witnessClosedHolding = st.ev.res == "ClosedHolding"
  val witnessAttached = st.ev.res == "Attached"
  val witnessAttachedClosing = st.ev.res == "AttachedClosing"
  val witnessOrphans = st.orphans == 4
  action step = any {
    {
      nondet h = HANDLES.oneOf()
      any {admit(h), exhausted(h), hand(h), giveBack(h), giveBackStale(h), close(h)}
    },
    attach,
  }
}
