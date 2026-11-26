/// The retired allowance of one volume: five keys of one-unit objects, the retired objects with their anchors and
/// one lease's right, and the retired charge that gates every claim at the allowance.
/// Each step is one call: a claim that publishes or replaces, an invalidation, a certification, a lease's drop
/// or a funded return.
module allowance {
  const BOUND: int
  const T: int
  type Object = {ver: int, right: bool}
  type Retired = {anchor: bool, right: bool}
  type Event = {act: str, res: str, key: int, count: int}
  type State = {
    vis: int -> Object, retired: int -> Retired, charge: int, next: int, gated: bool, kept: bool, ev: Event
  }
  var st: State
  var turn: int
  pure val KEYS = Set(0, 1, 2, 3, 4)
  pure val ABSENT: Object = {ver: 0, right: false}
  pure def event(act: str, res: str, key: int, count: int): Event = {act: act, res: res, key: key, count: count}
  pure def leased(s: State): bool =
    KEYS.exists(k => s.vis.get(k).right) or s.retired.keys().exists(v => s.retired.get(v).right)
  /// `after`, a claim's state, with `gated` recording that it refused exactly at or above the allowance and
  /// `kept` that a refusal changed nothing.
  pure def claimed(before: State, after: State): State = {...after,
    gated: (after.ev.res == "RetiredPressure") == (before.charge >= T),
    kept: after.ev.res != "RetiredPressure" or
      (after.vis == before.vis and after.retired == before.retired and after.charge == before.charge)}
  action init = all {
    st' = {
      vis: KEYS.mapBy(_ => ABSENT), retired: Map(), charge: 0, next: 1, gated: true, kept: true,
      ev: event("init", "", 0, 0)
    },
    turn' = 0
  }
  action tick = all {turn < BOUND, turn' = turn + 1}
  action publish(key: int, keep: bool): bool = all {tick, st.vis.get(key).ver == 0, not(keep and leased(st)),
    st' = claimed(st,
      if (st.charge >= T) {...st, ev: event("publish", "RetiredPressure", key, 0)}
      else {...st, vis: st.vis.set(key, {ver: st.next, right: keep}), next: st.next + 1,
        ev: event("publish", if (keep) "Leased" else "Published", key, 0)})
  }
  action replace(key: int): bool = {
    val own = st.vis.get(key)
    all {tick, own.ver != 0,
      st' = claimed(st,
        if (st.charge >= T) {...st, ev: event("replace", "RetiredPressure", key, 0)}
        else {...st, vis: st.vis.set(key, {ver: st.next, right: false}), next: st.next + 1,
          retired: st.retired.put(own.ver, {anchor: true, right: own.right}), charge: st.charge + 1,
          ev: event("replace", "Replaced", key, 0)})
    }
  }
  action invalidate(key: int): bool = {
    val own = st.vis.get(key)
    all {tick, own.ver != 0,
      st' = {...st, vis: st.vis.set(key, ABSENT), retired: st.retired.put(own.ver, {anchor: true, right: own.right}),
        charge: st.charge + 1, ev: event("invalidate", "Retired", key, 0)}
    }
  }
  action certify = all {tick,
    st' = {...st, retired: st.retired.keys().mapBy(v => {...st.retired.get(v), anchor: false}),
      ev: event("certify", "Certified", 0, st.retired.keys().filter(v => st.retired.get(v).anchor).size())}
  }
  action release = all {tick, leased(st),
    st' = {...st, vis: st.vis.keys().mapBy(k => {...st.vis.get(k), right: false}),
      retired: st.retired.keys().mapBy(v => {...st.retired.get(v), right: false}),
      ev: event("release", "Dropped", 0, 0)}
  }
  action visit = {
    val gone = st.retired.keys().filter(v => not(st.retired.get(v).anchor) and not(st.retired.get(v).right))
    all {tick,
      st' = {...st, retired: st.retired.keys().exclude(gone).mapBy(v => st.retired.get(v)),
        charge: st.charge - gone.size(),
        ev: event("visit", if (gone.size() == 0) "Idle" else "Returned", 0, gone.size())}
    }
  }
  val PressureGatesClaims = st.gated
  val RefusalChangesNothing = st.kept
  val ChargeCountsRetired = st.charge == st.retired.keys().size()
  val safety = PressureGatesClaims and RefusalChangesNothing and ChargeCountsRetired
  val witnessPublished = st.ev.res == "Published"
  val witnessLeased = st.ev.res == "Leased"
  val witnessPublishPressure = st.ev.act == "publish" and st.ev.res == "RetiredPressure"
  val witnessReplaced = st.ev.res == "Replaced"
  val witnessReplacePressure = st.ev.act == "replace" and st.ev.res == "RetiredPressure"
  val witnessRetired = st.ev.res == "Retired" and st.charge < T
  val witnessPastAllowance = st.ev.res == "Retired" and st.charge > T
  val witnessCertified = st.ev.res == "Certified" and st.ev.count > 0
  val witnessDropped = st.ev.res == "Dropped"
  val witnessReturned = st.ev.res == "Returned"
  val witnessReturnRestoresClaims = st.ev.res == "Returned" and st.charge < T and st.charge + st.ev.count >= T
  val witnessHeldAfterCertify = st.ev.act == "visit" and st.charge > 0 and
    st.retired.keys().forall(v => st.retired.get(v).right and not(st.retired.get(v).anchor))
  val witnessIdle = st.ev.act == "visit" and st.ev.res == "Idle" and st.charge == 0
  action step = {
    nondet key = KEYS.oneOf()
    nondet keep = Set(false, true).oneOf()
    any {publish(key, keep), replace(key), invalidate(key), certify, release, visit}
  }
}
