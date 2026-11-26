/// The claims of the fills of one index shard: two keys, a visible limit, a lease limit, and for each key its
/// visible object, its current fill's record, its revoked fills and its leases.
/// Each step is one call of a fill's owner, of an invalidation, of the service pass or of a lease's holder.
module claims {
  const BOUND: int
  const LIMIT: int
  const LEASES: int
  type Record = {state: str, place: bool}
  /// `count` is 1 for a publication past its deadline and, for a pass, the records it released.
  type Event = {act: str, res: str, key: int, count: int}
  type State = {
    vis: int -> int, rec: int -> Record, revoked: int -> int, leases: int -> int,
    v: int, p: int, c: int, next: int, kept: bool, ev: Event
  }
  var st: State
  var turn: int
  pure val KEYS = Set(0, 1)
  pure val NONE: Record = {state: "none", place: false}
  pure def event(act: str, res: str, key: int, count: int): Event = {act: act, res: res, key: key, count: count}
  pure def places(s: State): int = KEYS.filter(k => s.rec.get(k).place).size()
  pure def credits(s: State): int =
    KEYS.fold(0, (sum, k) => sum + s.leases.get(k) + 2 * s.revoked.get(k) + (if (s.rec.get(k).state == "reserved") 2 else 0))
  /// `after`, a refusal's state, with `kept` recording whether it left every key's visible object as `before` had it.
  pure def refusal(before: State, after: State): State = {...after, kept: after.vis == before.vis}
  action init = all {
    st' = {
      vis: KEYS.mapBy(_ => 0), rec: KEYS.mapBy(_ => NONE), revoked: KEYS.mapBy(_ => 0), leases: KEYS.mapBy(_ => 0),
      v: 0, p: 0, c: 0, next: 1, kept: true, ev: event("init", "", 0, 0)
    },
    turn' = 0
  }
  action tick = all {turn < BOUND, turn' = turn + 1}
  action reserve(key: int): bool = all {tick,
    st' = if (st.rec.get(key).state != "none") {...st, kept: true, ev: event("reserve", "InProgress", key, 0)}
      else if (st.v + st.p >= LIMIT)
        refusal(st, {...st, rec: st.rec.set(key, {state: "departed", place: false}), ev: event("reserve", "IndexFull", key, 0)})
      else if (st.c + 2 > LEASES)
        refusal(st, {...st, rec: st.rec.set(key, {state: "departed", place: false}), ev: event("reserve", "LeaseLimit", key, 0)})
      else {...st, kept: true, rec: st.rec.set(key, {state: "reserved", place: true}), p: st.p + 1, c: st.c + 2,
        ev: event("reserve", "Reserved", key, 0)}
  }
  action publishFill(key: int, late: bool): bool = {
    val held = st.rec.get(key)
    val spent = if (held.place) 1 else 0
    all {tick, held.state == "reserved",
      st' = if (late)
          refusal(st, {...st, rec: st.rec.set(key, NONE), p: st.p - spent, c: st.c - 2,
            ev: event("publishFill", "Expired", key, 1)})
        else if (not(held.place) and st.v + st.p >= LIMIT)
          refusal(st, {...st, rec: st.rec.set(key, NONE), c: st.c - 2, ev: event("publishFill", "IndexFull", key, 0)})
        else {...st, kept: true, rec: st.rec.set(key, NONE), p: st.p - spent, c: st.c - 1,
          vis: st.vis.set(key, st.next), next: st.next + 1, leases: st.leases.setBy(key, n => n + 1),
          v: if (st.vis.get(key) == 0) st.v + 1 else st.v,
          ev: event("publishFill", if (st.vis.get(key) == 0) "Activated" else "Replaced", key, 0)}
    }
  }
  action abort(key: int): bool = all {tick, st.rec.get(key).state == "reserved",
    st' = {...st, kept: true, rec: st.rec.setBy(key, r => {...r, state: "departed"}), c: st.c - 2,
      ev: event("abort", "Aborted", key, 0)}
  }
  action service = {
    val departed = KEYS.filter(k => st.rec.get(k).state == "departed")
    val refunded = departed.filter(k => st.rec.get(k).place).size()
    all {tick,
      st' = {...st, kept: true, rec: st.rec.keys().mapBy(k => if (departed.contains(k)) NONE else st.rec.get(k)),
        p: st.p - refunded, ev: event("service", if (refunded == 0) "Idle" else "Refunded", 0, departed.size())}
    }
  }
  action invalidate(key: int): bool = {
    val held = st.rec.get(key)
    val removed = st.vis.get(key) != 0
    val revoked = held.state != "none"
    all {tick,
      st' = {...st, kept: true, vis: st.vis.set(key, 0), v: if (removed) st.v - 1 else st.v,
        rec: st.rec.set(key, NONE), p: if (held.place) st.p - 1 else st.p,
        revoked: if (held.state == "reserved") st.revoked.setBy(key, n => n + 1) else st.revoked,
        ev: event("invalidate", if (removed and revoked) "RemovedRevoked" else if (removed) "Removed"
          else if (revoked) "Revoked" else "None", key, 0)}
    }
  }
  action endRevoked(key: int): bool = all {tick, st.revoked.get(key) > 0,
    st' = {...st, kept: true, revoked: st.revoked.setBy(key, n => n - 1), c: st.c - 2,
      ev: event("endRevoked", "Superseded", key, 0)}
  }
  action release(key: int): bool = all {tick, st.leases.get(key) > 0,
    st' = {...st, kept: true, leases: st.leases.setBy(key, n => n - 1), c: st.c - 1,
      ev: event("release", "LeaseDropped", key, 0)}
  }
  val UploadHoldsClaims = KEYS.forall(k => st.rec.get(k).state != "reserved" or st.rec.get(k).place) and
    st.c >= 2 * KEYS.filter(k => st.rec.get(k).state == "reserved").size()
  val ReadyNeverRefusesFull = not(st.ev.act == "publishFill" and Set("IndexFull", "LeaseLimit").contains(st.ev.res))
  val ClaimsReturnOnce = st.p == places(st) and st.c == credits(st)
  val RefusalKeepsIncumbent = st.kept
  val safety = UploadHoldsClaims and ReadyNeverRefusesFull and ClaimsReturnOnce and RefusalKeepsIncumbent
  val witnessReserved = st.ev.res == "Reserved"
  val witnessInProgress = st.ev.res == "InProgress" and st.rec.get(st.ev.key).state == "reserved"
  val witnessInProgressDeparted = st.ev.res == "InProgress" and st.rec.get(st.ev.key).state == "departed"
  val witnessIndexFull = st.ev.act == "reserve" and st.ev.res == "IndexFull"
  val witnessReplacementFull = st.ev.act == "reserve" and st.ev.res == "IndexFull" and st.vis.get(st.ev.key) != 0
  val witnessLeaseLimit = st.ev.res == "LeaseLimit"
  val witnessActivated = st.ev.res == "Activated"
  val witnessReplaced = st.ev.res == "Replaced"
  val witnessExpired = st.ev.res == "Expired"
  val witnessExpiredBesideIncumbent = st.ev.res == "Expired" and st.vis.get(st.ev.key) != 0
  val witnessAborted = st.ev.res == "Aborted"
  val witnessRefunded = st.ev.res == "Refunded"
  val witnessUnblocked = st.ev.res == "Idle" and st.ev.count > 0
  val witnessIdle = st.ev.res == "Idle" and st.ev.count == 0
  val witnessRemoved = st.ev.res == "Removed"
  val witnessRevoked = st.ev.res == "Revoked" and st.revoked.get(st.ev.key) > 0
  val witnessRevokedDeparted = st.ev.res == "Revoked" and st.revoked.get(st.ev.key) == 0
  val witnessRemovedRevoked = st.ev.res == "RemovedRevoked"
  val witnessNone = st.ev.act == "invalidate" and st.ev.res == "None"
  val witnessSuperseded = st.ev.res == "Superseded"
  val witnessLeaseDropped = st.ev.res == "LeaseDropped"
  action step = {
    nondet key = KEYS.oneOf()
    nondet late = Set(false, true).oneOf()
    any {reserve(key), publishFill(key, late), abort(key), service, invalidate(key), endRevoked(key), release(key)}
  }
}
