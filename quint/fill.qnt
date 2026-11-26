/// The fill authority of one index shard: two keys, a table of two records and a serial maximum of 3.
/// Each step is one gate hold or the owner's one departure. A record is Free (serial 0, no flag) or
/// occupied by the serial of the attempt that holds it, with a departed and a revoked flag.
module fill {
  const BOUND: int
  type Record = {serial: int, departed: bool, revoked: bool, key: int}
  type Event = {act: str, res: str, key: int, rec: int, serial: int}
  type State = {
    recs: int -> Record, next: int, live: Set[int], issued: Set[int], reissued: bool, ev: Event
  }
  var st: State
  var turn: int
  pure val KEYS = Set(0, 1)
  pure val RECORDS = Set(0, 1)
  pure val MAX = 3
  pure val FREE: Record = {serial: 0, departed: false, revoked: false, key: 0}
  pure def occupied(r: Record): bool = r.serial != 0
  pure def associated(r: Record): bool = occupied(r) and not(r.revoked)
  pure def event(act: str, res: str, key: int, rec: int, serial: int): Event =
    {act: act, res: res, key: key, rec: rec, serial: serial}
  action init = all {
    st' = {recs: RECORDS.mapBy(_ => FREE), next: 1, live: Set(), issued: Set(), reissued: false,
      ev: event("init", "", 0, 0, 0)},
    turn' = 0
  }
  action tick = all {turn < BOUND, turn' = turn + 1}
  action begin(key: int): bool = {
    val current = RECORDS.filter(r => associated(st.recs.get(r)) and st.recs.get(r).key == key)
    val free = RECORDS.filter(r => not(occupied(st.recs.get(r))))
    val rec = if (free.contains(0)) 0 else 1
    val granted = {serial: st.next, departed: false, revoked: false, key: key}
    all {tick,
      st' = if (st.next > MAX) {...st, ev: event("begin", "AttemptExhausted", key, 0, 0)}
        else if (current.size() > 0) {...st, ev: event("begin", "InProgress", key, 0, 0)}
        else if (free.size() == 0) {...st, ev: event("begin", "FillSlotsFull", key, 0, 0)}
        else {...st, recs: st.recs.set(rec, granted), next: st.next + 1, live: st.live.union(Set(st.next)),
          issued: st.issued.union(Set(st.next)), reissued: st.reissued or st.issued.contains(st.next),
          ev: event("begin", "Granted", key, rec, st.next)}
    }
  }
  action revoke(key: int): bool = {
    val current = RECORDS.filter(r => associated(st.recs.get(r)) and st.recs.get(r).key == key)
    val rec = if (current.contains(0)) 0 else 1
    val found = st.recs.get(rec)
    all {tick,
      st' = if (current.size() == 0) {...st, ev: event("revoke", "None", key, 0, 0)}
        else {...st, recs: st.recs.set(rec, {...found, revoked: true}),
          ev: event("revoke", "Revoked", key, rec, found.serial)}
    }
  }
  action depart(serial: int): bool = {
    val held = RECORDS.filter(r => st.recs.get(r).serial == serial and not(st.recs.get(r).departed))
    val rec = if (held.contains(0)) 0 else 1
    val found = st.recs.get(rec)
    all {tick, st.live.contains(serial),
      st' = if (held.size() == 0) {...st, live: st.live.exclude(Set(serial)), ev: event("depart", "Ended", 0, 0, serial)}
        else {...st, live: st.live.exclude(Set(serial)), recs: st.recs.set(rec, {...found, departed: true}),
          ev: event("depart", "Departed", found.key, rec, serial)}
    }
  }
  action service = {
    val releasable = RECORDS.filter(r => st.recs.get(r).departed)
    all {tick,
      st' = {...st, recs: st.recs.keys().mapBy(r => if (releasable.contains(r)) FREE else st.recs.get(r)),
        ev: event("service", if (releasable.size() == 0) "Idle" else "Released", 0, 0, releasable.size())}
    }
  }
  val OneCurrentPerKey = RECORDS.forall(a => RECORDS.forall(b =>
    a == b or not(associated(st.recs.get(a)) and associated(st.recs.get(b)) and st.recs.get(a).key == st.recs.get(b).key)))
  val SerialIssuedOnce = not(st.reissued)
  val SerialWithinMaximum = st.issued.forall(s => 1 <= s and s <= MAX)
  val LiveOwnerKeepsRecord = st.live.forall(s => RECORDS.exists(r => st.recs.get(r).serial == s and not(st.recs.get(r).departed)))
  val DepartsAfterOwnerEnded = RECORDS.forall(r => st.recs.get(r).departed implies not(st.live.contains(st.recs.get(r).serial)))
  val WellFormed = RECORDS.forall(r => if (occupied(st.recs.get(r))) 1 <= st.recs.get(r).serial and st.recs.get(r).serial < st.next
    else st.recs.get(r) == FREE)
  val safety = OneCurrentPerKey and SerialIssuedOnce and SerialWithinMaximum and LiveOwnerKeepsRecord and
    DepartsAfterOwnerEnded and WellFormed
  val witnessGranted = st.ev.res == "Granted"
  val witnessInProgress = st.ev.res == "InProgress"
  val witnessInProgressDeparted = st.ev.res == "InProgress" and st.live == Set()
  val witnessFull = st.ev.res == "FillSlotsFull"
  val witnessExhausted = st.ev.res == "AttemptExhausted"
  val witnessRevoked = st.ev.res == "Revoked"
  val witnessNoneRevoked = st.ev.act == "revoke" and st.ev.res == "None"
  val witnessDeparted = st.ev.res == "Departed"
  val witnessDepartedRevoked = st.ev.res == "Departed" and st.recs.get(st.ev.rec).revoked
  val witnessReleased = st.ev.res == "Released"
  val witnessIdle = st.ev.res == "Idle"
  val witnessReplacement = st.ev.res == "Granted" and
    RECORDS.exists(r => st.recs.get(r).revoked and st.recs.get(r).key == st.ev.key and st.live.contains(st.recs.get(r).serial))
  action step = {
    nondet key = KEYS.oneOf()
    nondet serial = Set(1, 2, 3).oneOf()
    any {begin(key), revoke(key), depart(serial), service}
  }
}
