/// The escrow of a storage's multi-extent objects, as the pool gate's holders drive it: a builder promises an
/// object's whole charge, places its extents one per call, and ends by a cancel under the gate or by a drop that
/// parks its slot for service, beside direct one-extent claims. Units are the storage's own: every extent, a
/// builder's and a direct claim's alike, is `E` units, and the clean reserve is `R` units. Each step is one call
/// that completes before the next starts.
module escrow {
  const BOUND: int
  const VOLUME: int
  type Builder = {phase: str, extents: int, placed: int, rem: int}
  type Core = {free: int, u: int, direct: int, b: int -> Builder, parked: bool, parkedExt: int}
  type Event = {act: str, who: int, res: str, free0: int, u0: int, rem0: int, charge: int}
  var st: Core
  var pre: Core
  var ev: Event
  var turn: int
  /// The units of one extent of the instance's objects, whose bodies are whole extent payloads.
  pure val E = 63
  /// The clean reserve the pool keeps free beside the escrow.
  pure val R = 1
  /// Direct claims held at once.
  pure val DIRECT = 2
  pure val BUILDERS = Set(1, 2)
  pure val SIZES = Set(2, 3)
  pure val IDLE: Builder = {phase: "none", extents: 0, placed: 0, rem: 0}
  pure def event(act: str, who: int, res: str, s: Core, rem0: int, charge: int): Event =
    {act: act, who: who, res: res, free0: s.free, u0: s.u, rem0: rem0, charge: charge}
  action init = all {
    st' = {free: VOLUME, u: 0, direct: 0, b: BUILDERS.mapBy(_ => IDLE), parked: false, parkedExt: 0},
    pre' = {free: VOLUME, u: 0, direct: 0, b: BUILDERS.mapBy(_ => IDLE), parked: false, parkedExt: 0},
    ev' = {act: "init", who: 0, res: "", free0: VOLUME, u0: 0, rem0: 0, charge: 0},
    turn' = 0
  }
  /// One call: it advances the turn and records the state before it.
  action count = all {turn < BOUND, turn' = turn + 1, pre' = st}
  /// A promise of an object of `n` extents by a handle holding no builder: it succeeds when the free units less
  /// the escrow cover the charge plus the clean reserve, adding the charge to the escrow, and otherwise refuses
  /// with nothing changed.
  action promise(k: int, n: int): bool = {
    val charge = n * E
    all {count, st.b.get(k).phase == "none",
      if (st.free - st.u >= charge + R) all {
        st' = {...st, u: st.u + charge, b: st.b.set(k, {phase: "building", extents: n, placed: 0, rem: charge})},
        ev' = event("promise", k, "ok", st, 0, charge)
      } else all {
        st' = st,
        ev' = event("promise", k, "clean_reserve", st, 0, charge)
      }
    }
  }
  /// A placement of the next extent of an incomplete builder: its units leave the free units, the escrow and the
  /// builder's remaining charge together, and the builder is complete at its last extent.
  action place(k: int): bool = {
    val x = st.b.get(k)
    val placed = x.placed + 1
    all {count, x.phase == "building", x.placed < x.extents,
      st' = {...st, free: st.free - E, u: st.u - E, b: st.b.set(k, {...x, placed: placed, rem: x.rem - E})},
      ev' = event("place", k, if (placed == x.extents) "complete" else "partial", st, x.rem, x.extents * E)
    }
  }
  /// A cancel under a free gate: it subtracts the remaining charge from the escrow and returns the placed
  /// extents, the block and the slot in the same hold.
  action cancel(k: int): bool = {
    val x = st.b.get(k)
    all {count, x.phase == "building",
      st' = {...st, free: st.free + x.placed * E, u: st.u - x.rem, b: st.b.set(k, IDLE)},
      ev' = event("cancel", k, "ok", st, x.rem, x.extents * E)
    }
  }
  /// A drop: it refunds the remaining charge and parks the slot with its placed extents for service.
  action release(k: int): bool = {
    val x = st.b.get(k)
    all {count, x.phase == "building", not(st.parked),
      st' = {...st, u: st.u - x.rem, b: st.b.set(k, IDLE), parked: true, parkedExt: x.placed},
      ev' = event("drop", k, "ok", st, x.rem, x.extents * E)
    }
  }
  /// A service call funded at the minimum: one visit of the parked slot returns its last held extent, and the
  /// visit that leaves none returns the block and the slot too. With nothing parked the call returns nothing.
  action service: bool = all {count,
    if (not(st.parked)) all {st' = st, ev' = event("service", 0, "idle", st, 0, 0)}
    else if (st.parkedExt >= 2) all {
      st' = {...st, free: st.free + E, parkedExt: st.parkedExt - 1},
      ev' = event("service", 0, "partial", st, 0, 0)
    } else all {
      st' = {...st, free: st.free + st.parkedExt * E, parked: false, parkedExt: 0},
      ev' = event("service", 0, "serviced", st, 0, 0)
    }
  }
  /// A direct claim of one extent: it succeeds when the free units less the escrow cover the extent plus the
  /// clean reserve, and otherwise refuses with nothing changed.
  action claim: bool = all {count, st.direct < DIRECT,
    if (st.free - st.u >= E + R) all {
      st' = {...st, free: st.free - E, direct: st.direct + 1},
      ev' = event("claim", 0, "ok", st, 0, E)
    } else all {
      st' = st,
      ev' = event("claim", 0, "clean_reserve", st, 0, E)
    }
  }
  /// The cancel of the latest direct claim returns its extent.
  action unclaim: bool = all {count, st.direct > 0,
    st' = {...st, free: st.free + E, direct: st.direct - 1},
    ev' = event("unclaim", 0, "ok", st, 0, E)
  }
  pure def building(s: Core): Set[int] = BUILDERS.filter(k => s.b.get(k).phase == "building")
  pure def remaining(s: Core): int = building(s).fold(0, (sum, k) => sum + s.b.get(k).rem)
  pure def held(s: Core): int =
    building(s).fold(0, (sum, k) => sum + s.b.get(k).placed * E) + (if (s.parked) s.parkedExt * E else 0)
  val PromiseNeedsAllocatable = ev.act == "promise" implies (ev.res == "ok" iff ev.free0 - ev.u0 >= ev.charge + R)
  val RefusalChangesNothing = ev.res == "clean_reserve" implies st == pre
  val EscrowIsRemaining = st.u == remaining(st)
  val EscrowWithinFree = st.u <= st.free
  val Conservation = st.free + held(st) + st.direct * E == VOLUME
  val ClaimSparesPromised = ev.act == "claim" and ev.res == "ok" implies st.free >= st.u + R
  val RefundOnce = (ev.act == "cancel" or ev.act == "drop") implies ev.u0 - st.u == ev.rem0
  val CompleteAtLast = BUILDERS.forall(k => st.b.get(k).phase == "building" implies
      (st.b.get(k).rem == 0 iff st.b.get(k).placed == st.b.get(k).extents))
    and (ev.act == "place" implies (ev.res == "complete" iff st.b.get(ev.who).placed == st.b.get(ev.who).extents))
  val safety = PromiseNeedsAllocatable and RefusalChangesNothing and EscrowIsRemaining and EscrowWithinFree
    and Conservation and ClaimSparesPromised and RefundOnce and CompleteAtLast
  val witnessPromiseTwo = ev.act == "promise" and ev.res == "ok" and ev.charge == 2 * E
  val witnessPromiseThree = ev.act == "promise" and ev.res == "ok" and ev.charge == 3 * E
  val witnessPromiseExact = ev.act == "promise" and ev.res == "ok" and ev.free0 - ev.u0 == ev.charge + R
  val witnessPromiseShort = ev.act == "promise" and ev.res == "clean_reserve" and ev.free0 - ev.u0 == ev.charge + R - E
  val witnessPromiseShortByReserve = ev.act == "promise" and ev.res == "clean_reserve" and ev.free0 - ev.u0 == ev.charge
  val witnessPromiseRefusedBeside = ev.act == "promise" and ev.res == "clean_reserve" and ev.u0 > 0
  val witnessPlacePartial = ev.act == "place" and ev.res == "partial"
  val witnessPlaceComplete = ev.act == "place" and ev.res == "complete"
  val witnessCancelUnplaced = ev.act == "cancel" and ev.rem0 == ev.charge
  val witnessCancelPartial = ev.act == "cancel" and ev.rem0 > 0 and ev.rem0 < ev.charge
  val witnessCancelComplete = ev.act == "cancel" and ev.rem0 == 0
  val witnessDropUnplaced = ev.act == "drop" and ev.rem0 == ev.charge
  val witnessDropPartial = ev.act == "drop" and ev.rem0 > 0 and ev.rem0 < ev.charge
  val witnessDropComplete = ev.act == "drop" and ev.rem0 == 0
  val witnessServiceIdle = ev.act == "service" and ev.res == "idle"
  val witnessServicePartial = ev.act == "service" and ev.res == "partial"
  val witnessServiceLast = ev.act == "service" and ev.res == "serviced" and st.free > ev.free0
  val witnessServiceEmpty = ev.act == "service" and ev.res == "serviced" and st.free == ev.free0
  val witnessClaim = ev.act == "claim" and ev.res == "ok"
  val witnessClaimBesidePromise = ev.act == "claim" and ev.res == "ok" and ev.u0 > 0
  val witnessClaimRefused = ev.act == "claim" and ev.res == "clean_reserve"
  val witnessUnclaim = ev.act == "unclaim"
  val witnessTwoBuilders = building(st).size() == 2
  action step = {
    nondet k = BUILDERS.oneOf()
    nondet n = SIZES.oneOf()
    any {promise(k, n), place(k), cancel(k), release(k), service, claim, unclaim}
  }
}
