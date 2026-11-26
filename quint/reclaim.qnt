/// The reclamation of one slot on a live storage: two registered readers, lease rights, one maintainer.
/// Each step is one call: a reader's entry into a protected interval or its exit, a duplicated lease or a dropped one,
/// the object's retirement, one certification call funded for one record, one service call, and the publication of the
/// next object into the returned slot. A pin holds the era its entry read; zero is an inactive record.
module reclaim {
  const BOUND: int
  type Pass = {on: bool, start: int, low: int, next: int}
  type Event = {act: str, res: str, reader: int, value: int, released: bool, returned: bool}
  type State = {
    era: int, certified: int, pins: int -> int, watch: int -> int, inc: int, phase: str, rights: int,
    anchored: bool, stamp: int, pass: Pass, returns: int, published: int, ev: Event
  }
  var st: State
  var turn: int
  pure val READERS = Set(0, 1)
  pure val RECORDS = 2
  pure val FIRST = 1
  pure val INACTIVE = 0
  pure val NOPIN = 1000
  pure val RIGHTS = 2
  pure def least(a: int, b: int): int = if (a < b) a else b
  pure def note(s: State, act: str, reader: int): State =
    {...s, ev: {act: act, res: "", reader: reader, value: 0, released: false, returned: false}}
  pure def result(s: State, res: str, value: int): State = {...s, ev: {...s.ev, res: res, value: value}}
  /// An entry pins the era. The reader watches the object when the object is resident at that moment.
  pure def entered(s: State, r: int): State =
    result({...s, pins: s.pins.set(r, s.era), watch: s.watch.set(r, if (s.phase == "Resident") s.inc else 0)}, "Ok", s.era)
  /// The retirement stamps the object with the era it found and advances the era; the anchor stays counted.
  pure def retired(s: State): State = result({...s, stamp: s.era, era: s.era + 1, phase: "Retired"}, "Ok", s.era)
  /// One visit: the pass keeps the smallest active pin it has seen.
  pure def visited(s: State): State = {
    val pin = s.pins.get(s.pass.next)
    {...s, pass: {...s.pass, low: if (pin != INACTIVE) least(s.pass.low, pin) else s.pass.low, next: s.pass.next + 1}}
  }
  /// The completion: the certified era rises to the smaller of the start era and the smallest pin seen, when that is higher.
  pure def completed(s: State): State = {
    val bound = least(s.pass.start, s.pass.low)
    val certified = if (bound <= s.certified) s.certified else bound
    result({...s, certified: certified, pass: {on: false, start: 0, low: NOPIN, next: 0}}, "Certified", certified)
  }
  /// One certification call funded for one record. With no pass in progress it begins one only when the era exceeds
  /// the certified era, and otherwise reports the certified era. It visits one record and completes the pass when
  /// that was the last one.
  pure def certifying(s: State): State = {
    val begun = if (s.pass.on) s else {...s, pass: {on: true, start: s.era, low: NOPIN, next: 0}}
    val seen = visited(begun)
    if (not(s.pass.on) and s.era <= s.certified) result(s, "Idle", s.certified)
    else if (seen.pass.next == RECORDS) completed(seen)
    else result(seen, "Advanced", 0)
  }
  /// One service call. On a retired slot it releases the anchor when the stamp lies strictly below the certified
  /// era, then returns the slot when no anchor and no right is counted, and otherwise holds it.
  pure def serviced(s: State): State = {
    val releases = s.anchored and s.stamp < s.certified
    val anchored = s.anchored and not(releases)
    val returns = not(anchored) and s.rights == 0
    if (s.phase != "Retired") result(s, "Nothing", 0)
    else {...s, anchored: anchored, phase: if (returns) "Free" else s.phase,
      returns: if (returns) s.returns + 1 else s.returns,
      ev: {...s.ev, res: if (returns) "Returned" else "Held", released: releases, returned: returns}}
  }
  /// The next object takes the returned slot under the next incarnation, with its anchor and one lease.
  pure def republished(s: State): State =
    result({...s, inc: s.inc + 1, phase: "Resident", rights: 1, anchored: true, stamp: 0, returns: 0,
      published: s.published + 1}, "Ok", s.inc + 1)
  action init = all {
    st' = {era: FIRST, certified: 0, pins: READERS.mapBy(_ => INACTIVE), watch: READERS.mapBy(_ => 0), inc: 1,
      phase: "Resident", rights: 1, anchored: true, stamp: 0, pass: {on: false, start: 0, low: NOPIN, next: 0},
      returns: 0, published: 1, ev: {act: "init", res: "", reader: 0, value: 0, released: false, returned: false}},
    turn' = 0
  }
  action tick = all {turn < BOUND, turn' = turn + 1}
  action enter(r: int): bool = all {tick, st.pins.get(r) == INACTIVE, st' = entered(note(st, "enter", r), r)}
  action exit(r: int): bool = all {tick, st.pins.get(r) != INACTIVE,
    st' = result({...note(st, "exit", r), pins: st.pins.set(r, INACTIVE), watch: st.watch.set(r, 0)}, "Ok", 0)}
  action lease = all {tick, st.rights >= 1, st.rights < RIGHTS,
    st' = result({...note(st, "lease", 0), rights: st.rights + 1}, "Ok", st.rights + 1)}
  action unlease = all {tick, st.rights >= 1,
    st' = result({...note(st, "unlease", 0), rights: st.rights - 1}, "Ok", st.rights - 1)}
  action retire = all {tick, st.phase == "Resident", st' = retired(note(st, "retire", 0))}
  action certify = all {tick, st' = certifying(note(st, "certify", 0))}
  action service = all {tick, st' = serviced(note(st, "service", 0))}
  action republish = all {tick, st.phase == "Free", st' = republished(note(st, "republish", 0))}
  val ReadersPrecedeReuse = and {
    st.rights > 0 implies st.phase != "Free",
    READERS.forall(r => st.watch.get(r) != 0 implies (st.watch.get(r) == st.inc and st.phase != "Free")),
  }
  val ReturnsOnce = st.returns <= 1
  val ReusedAsNext = st.inc == st.published
  val safety = ReadersPrecedeReuse and ReturnsOnce and ReusedAsNext
  val witnessEntered = st.ev.act == "enter"
  val witnessEnteredAfterRetirement = st.ev.act == "enter" and st.watch.get(st.ev.reader) == 0
  val witnessExited = st.ev.act == "exit"
  val witnessLeased = st.ev.act == "lease"
  val witnessUnleased = st.ev.act == "unlease"
  val witnessRetired = st.ev.act == "retire"
  val witnessRetiredAgain = st.ev.act == "retire" and st.inc == 2
  val witnessCertifyIdle = st.ev.act == "certify" and st.ev.res == "Idle"
  val witnessCertifyAdvanced = st.ev.act == "certify" and st.ev.res == "Advanced"
  val witnessCertified = st.ev.act == "certify" and st.ev.res == "Certified"
  val witnessCertifiedBelowEra = st.ev.act == "certify" and st.ev.res == "Certified" and st.ev.value < st.era
  val witnessServiceNothing = st.ev.act == "service" and st.ev.res == "Nothing"
  val witnessHeldByAnchor = st.ev.act == "service" and st.ev.res == "Held" and st.anchored
  val witnessHeldByRight = st.ev.act == "service" and st.ev.res == "Held" and not(st.anchored) and not(st.ev.released)
  val witnessReleasedUnderRight = st.ev.act == "service" and st.ev.res == "Held" and st.ev.released
  val witnessReturnedAnchorLast = st.ev.act == "service" and st.ev.returned and st.ev.released
  val witnessReturnedRightLast = st.ev.act == "service" and st.ev.returned and not(st.ev.released)
  val witnessRepublished = st.ev.act == "republish"
  action someEnter = {
    nondet r = READERS.oneOf()
    enter(r)
  }
  action someExit = {
    nondet r = READERS.oneOf()
    exit(r)
  }
  action step = any {someEnter, someExit, lease, unlease, retire, certify, service, republish}
}
