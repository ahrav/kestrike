/// How a transmit chain leaves custody, for one burst logic over one device: four header buffers, sends of one to
/// three header-only datagrams, the device's returns, a turn's reclaim with its recovery, and the hand-back of the
/// port. A chain is named by the order it was built in. `dev` holds the chains the device holds and `pool` the
/// chains whose buffers are off the header pool's free stack.
module custody {
  const BOUND: int
  type Event = {act: str, res: str}
  type State = {
    link: str, dev: Set[int], pool: Set[int], q: int, next: int, closed: bool,
    took: Set[int], local: Set[int], prevDev: Set[int], prevPool: Set[int],
    returned: int, released: int, stops: int, restarts: int, ev: Event
  }
  var st: State
  var turn: int
  pure val HEADERS = 4
  pure val NONE = -1
  pure val QUIET: Event = {act: "init", res: ""}
  pure def least(a: int, b: int): int = if (a < b) a else b
  pure def mark(s: State): State = {...s, prevDev: s.dev, prevPool: s.pool}
  action init = all {
    st' = {
      link: "Up", dev: Set(), pool: Set(), q: NONE, next: 0, closed: false,
      took: Set(), local: Set(), prevDev: Set(), prevPool: Set(),
      returned: 0, released: 0, stops: 0, restarts: 0, ev: QUIET
    },
    turn' = 0
  }
  action tick = all {turn < BOUND, turn' = turn + 1}
  action send(n: int, accept: int, fault: str): bool = {
    val built = least(n, HEADERS - st.pool.size())
    val a = least(accept, built)
    val uncertain = fault != "none" and a < built
    val accepted = st.next.to(st.next + a - 1)
    val u = st.next + a
    val keptDev = if (uncertain and fault == "kept") Set(u) else Set()
    val heldU = if (uncertain and fault != "freed") Set(u) else Set()
    val tookU = if (uncertain and fault != "unkept") Set(u) else Set()
    val ev = {...QUIET, act: "send"}
    all {tick, not(st.closed),
      st' = if (st.link != "Up") {...mark(st), ev: {...ev, res: "Closed"}}
        else if (st.q != NONE) {...mark(st), ev: {...ev, res: "Poisoned"}}
        else {...mark(st), dev: st.dev.union(accepted).union(keptDev), pool: st.pool.union(accepted).union(heldU),
          took: st.took.union(accepted).union(tookU), q: if (uncertain) u else NONE, next: st.next + built,
          ev: {...ev, res: if (uncertain) "Uncertain" else if (built < n) "Exhausted" else if (a < built) "RingFull" else "Sent"}}
    }
  }
  action devReturn = {
    val oldest = st.dev.filter(c => st.dev.forall(d => c <= d))
    all {tick, st.dev.size() > 0,
      st' = {...mark(st), dev: st.dev.exclude(oldest), pool: st.pool.exclude(oldest),
        ev: {...QUIET, act: "devReturn", res: if (oldest.contains(st.q)) "ReturnedQuarantined" else "Returned"}}
    }
  }
  /// The state after a proven stop: the device returned every chain it held, and the quarantine settled.
  pure def stopped(s: State): State = {
    val pool = s.pool.exclude(s.dev)
    val unkept = s.q != NONE and pool.contains(s.q)
    {...s, dev: Set(), pool: if (unkept) pool.exclude(Set(s.q)) else pool, q: NONE,
      local: if (unkept) s.local.union(Set(s.q)) else s.local,
      returned: s.returned + (if (s.q != NONE and not(unkept)) 1 else 0),
      released: s.released + (if (unkept) 1 else 0), stops: s.stops + 1}
  }
  action reclaim(reset: bool, stop: bool, recheck: bool, start: bool, again: bool): bool = {
    val ev = {...QUIET, act: "reclaim"}
    val episode = mark(st)
    val proven = stopped(episode)
    val tried = {...proven, restarts: proven.restarts + (if (recheck) 1 else 0), stops: proven.stops + 1}
    all {tick, not(st.closed),
      st' = if (st.link != "Up") {...mark(st), ev: {...ev, res: "Idle"}}
        else if (not(reset) and st.q == NONE) {...mark(st), ev: {...ev, res: "Quiet"}}
        else if (not(stop)) {...episode, link: "Lost", stops: st.stops + 1, ev: {...ev, res: "Unproven"}}
        else if (recheck and start) {...proven, restarts: proven.restarts + 1,
          ev: {...ev, res: "Recovered"}}
        else if (again) {...tried, link: "Down", ev: {...ev, res: "Down"}}
        else {...tried, link: "Lost", ev: {...ev, res: "LostAfterRestart"}}
    }
  }
  action close(stop: bool): bool = {
    val ev = {...QUIET, act: "close"}
    all {tick, not(st.closed),
      st' = if (st.q == NONE) {...mark(st), closed: true, ev: {...ev, res: "Kept"}}
        else if (not(stop)) {...mark(st), closed: true, stops: st.stops + 1, ev: {...ev, res: "CloseUnproven"}}
        else {...stopped(mark(st)), closed: true, ev: {...ev, res: "Settled"}}
    }
  }
  action rest = all {tick, st.closed, st' = {...mark(st), ev: {...QUIET, act: "rest", res: "Rested"}}}
  val DeviceHeldStaysCharged = st.dev.subseteq(st.pool)
  val ExitsOnlyByPortReturn = st.local.intersect(st.took) == Set()
  val FailedRestartReturnsEvery = st.ev.res == "Down" implies
    (st.dev == Set() and st.pool.intersect(st.prevDev) == Set())
  val UnprovenStopKeepsHeld = and {
    st.ev.res == "Unproven" implies st.link == "Lost",
    Set("Unproven", "CloseUnproven").contains(st.ev.res) implies (st.dev == st.prevDev and st.pool == st.prevPool),
  }
  val safety = DeviceHeldStaysCharged and ExitsOnlyByPortReturn and FailedRestartReturnsEvery and UnprovenStopKeepsHeld
  val witnessSent = st.ev.res == "Sent"
  val witnessRingFull = st.ev.res == "RingFull"
  val witnessExhausted = st.ev.res == "Exhausted"
  val witnessUncertainKept = st.ev.res == "Uncertain" and st.dev.contains(st.q)
  val witnessUncertainUnkept = st.ev.res == "Uncertain" and st.pool.contains(st.q) and not(st.dev.contains(st.q))
  val witnessUncertainFreed = st.ev.res == "Uncertain" and not(st.pool.contains(st.q))
  val witnessPoisoned = st.ev.res == "Poisoned"
  val witnessClosed = st.ev.res == "Closed"
  val witnessReturned = st.ev.res == "Returned"
  val witnessReturnedQuarantined = st.ev.res == "ReturnedQuarantined"
  val witnessIdle = st.ev.res == "Idle"
  val witnessQuiet = st.ev.res == "Quiet"
  val witnessUnproven = st.ev.res == "Unproven" and st.dev.size() > 0
  val witnessRecovered = st.ev.res == "Recovered"
  val witnessRecoveredReleased = st.ev.res == "Recovered" and st.released > 0
  val witnessRecoveredReturned = st.ev.res == "Recovered" and st.returned > 0
  val witnessDown = st.ev.res == "Down"
  val witnessLostAfterRestart = st.ev.res == "LostAfterRestart"
  val witnessKept = st.ev.res == "Kept" and st.dev.size() > 0
  val witnessCloseUnproven = st.ev.res == "CloseUnproven"
  val witnessSettled = st.ev.res == "Settled"
  val witnessSettledAfterLost = st.ev.res == "Settled" and st.link == "Lost"
  val witnessRested = st.ev.res == "Rested"
  /// The choices that keep the burst logic: a send, a device return or a turn's reclaim.
  action busy = any {
    nondet n = Set(1, 2, 3).oneOf()
    nondet accept = Set(0, 1, 2, 3).oneOf()
    nondet fault = Set("none", "kept", "unkept", "freed").oneOf()
    send(n, accept, fault),
    devReturn,
    nondet reset = Set(false, true).oneOf()
    nondet stop = Set(false, true).oneOf()
    nondet recheck = Set(false, true).oneOf()
    nondet start = Set(false, true).oneOf()
    nondet again = Set(false, true).oneOf()
    reclaim(reset, stop, recheck, start, again),
  }
  action step = any {
    busy,
    nondet stop = Set(false, true).oneOf()
    close(stop),
    rest,
  }
}
