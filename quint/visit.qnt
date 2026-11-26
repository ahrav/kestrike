/// The return of one retired object of a volume, an extent a visit: two keys, objects of one to three extents,
/// and at most one retired object, held by its anchor until a certification and by its lease's right.
/// Each step is one call: a publication, an invalidation, a certification, a lease's drop or read, or a visit.
module visit {
  const BOUND: int
  type Object = {ver: int, n: int, right: bool}
  type Retired = {ver: int, n: int, held: int, anchor: bool, right: bool}
  /// `extent` is, for a visit, the extents the retired object holds after it, and for a certification 1 when it
  /// released an anchor.
  type Event = {act: str, res: str, key: int, n: int, extent: int}
  type State = {
    vis: int -> Object, ret: Retired, charge: int, next: int, single: bool, heldBack: bool, ev: Event
  }
  var st: State
  var turn: int
  pure val KEYS = Set(0, 1)
  pure val SIZES = Set(1, 2, 3)
  pure val ABSENT: Object = {ver: 0, n: 0, right: false}
  pure val GONE: Retired = {ver: 0, n: 0, held: 0, anchor: false, right: false}
  pure def event(act: str, res: str, key: int, n: int, extent: int): Event =
    {act: act, res: res, key: key, n: n, extent: extent}
  pure def blocked(r: Retired): bool = r.anchor or r.right
  /// `after`, a visit's state, with `single` recording that it returned at most one extent, the last one held,
  /// and `heldBack` that it returned none from an object its anchor or a right holds.
  pure def visited(before: State, after: State): State = {...after,
    single: Set(0, 1).contains(before.ret.held - after.ret.held) and after.ev.extent == after.ret.held,
    heldBack: not(blocked(before.ret)) or after.ret == before.ret}
  action init = all {
    st' = {
      vis: KEYS.mapBy(_ => ABSENT), ret: GONE, charge: 0, next: 1, single: true, heldBack: true,
      ev: event("init", "", 0, 0, 0)
    },
    turn' = 0
  }
  action tick = all {turn < BOUND, turn' = turn + 1}
  action publish(key: int, n: int, keep: bool): bool = all {tick, st.vis.get(key).ver == 0,
    st' = {...st, vis: st.vis.set(key, {ver: st.next, n: n, right: keep}), next: st.next + 1,
      ev: event("publish", if (keep) "Leased" else "Published", key, n, 0)}
  }
  action invalidate(key: int): bool = {
    val own = st.vis.get(key)
    all {tick, own.ver != 0, st.ret.ver == 0,
      st' = {...st, vis: st.vis.set(key, ABSENT),
        ret: {ver: own.ver, n: own.n, held: own.n, anchor: true, right: own.right}, charge: own.n,
        ev: event("invalidate", "Retired", key, own.n, 0)}
    }
  }
  action certify = all {tick,
    st' = {...st, ret: {...st.ret, anchor: false},
      ev: event("certify", "Certified", 0, st.ret.n, if (st.ret.anchor) 1 else 0)}
  }
  action release = all {tick, st.ret.right,
    st' = {...st, ret: {...st.ret, right: false}, ev: event("release", "Dropped", 0, st.ret.n, 0)}
  }
  action read = all {tick, st.ret.right,
    st' = {...st, ev: event("read", "Read", 0, st.ret.n, 0)}
  }
  action visit = all {tick,
    st' = visited(st,
      if (st.ret.ver == 0 or blocked(st.ret)) {...st, ev: event("visit", "Idle", 0, st.ret.n, st.ret.held)}
      else if (st.ret.held >= 2)
        {...st, ret: {...st.ret, held: st.ret.held - 1}, charge: st.charge - 1,
          ev: event("visit", "Partial", 0, st.ret.n, st.ret.held - 1)}
      else {...st, ret: GONE, charge: st.charge - 1, ev: event("visit", "Returned", 0, st.ret.n, 0)})
  }
  val OneExtentPerVisit = st.single
  val BlockersHold = st.heldBack
  val SlotUntilLastExtent = (st.ret.ver != 0) == (st.ret.held > 0)
  val ChargeFollowsExtents = st.charge == st.ret.held
  val safety = OneExtentPerVisit and BlockersHold and SlotUntilLastExtent and ChargeFollowsExtents
  val witnessPublished = st.ev.res == "Published"
  val witnessLeased = st.ev.res == "Leased"
  val witnessRetired = st.ev.res == "Retired" and not(st.ret.right)
  val witnessRetiredLeased = st.ev.res == "Retired" and st.ret.right
  val witnessCertified = st.ev.res == "Certified" and st.ev.extent == 1
  val witnessCertifyIdle = st.ev.res == "Certified" and st.ev.extent == 0
  val witnessDropped = st.ev.res == "Dropped"
  val witnessRead = st.ev.res == "Read" and st.ret.held == st.ret.n
  val witnessHeldByAnchor = st.ev.act == "visit" and st.ev.res == "Idle" and st.ret.anchor and not(st.ret.right)
  val witnessHeldByRight = st.ev.act == "visit" and st.ev.res == "Idle" and st.ret.right and not(st.ret.anchor)
  val witnessNothingRetired = st.ev.act == "visit" and st.ev.res == "Idle" and st.ret.ver == 0
  val witnessPartialOfThree = st.ev.res == "Partial" and st.ev.n == 3 and st.ev.extent == 2
  val witnessSecondPartial = st.ev.res == "Partial" and st.ev.n == 3 and st.ev.extent == 1
  val witnessReturned = st.ev.res == "Returned" and st.ev.n == 3
  val witnessReturnedDirect = st.ev.res == "Returned" and st.ev.n == 1
  action step = {
    nondet key = KEYS.oneOf()
    nondet n = SIZES.oneOf()
    nondet keep = Set(false, true).oneOf()
    any {publish(key, n, keep), invalidate(key), certify, release, read, visit}
  }
}
