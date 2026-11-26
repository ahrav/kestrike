/// Reader registration on a live storage: two registration records, the handles that claim them, and the close of
/// admission. Each step is one call: a registration, a registration that the close lands inside, a whole protected
/// interval, an interval whose guard is leaked, an entry that the close lands inside, the drop of a registration (its
/// event's value is 1 when the drop cleared a leaked pin), a
/// forgotten registration, and the close. A pin holds the era its entry read; zero is an inactive record. Record
/// NONE stands for no record: `vacant` returns it when both records are claimed, and every action that names a
/// record draws from records 0 and 1.
module register {
  const BOUND: int
  type Record = {claimed: bool, held: bool, pin: int, leaked: bool, intervals: int}
  type Event = {act: str, res: str, record: int, value: int}
  type State = {closed: bool, recs: int -> Record, late: bool, kept: bool, ev: Event}
  var st: State
  var turn: int
  pure val RECORDS = Set(0, 1)
  pure val ERA = 1
  pure val INACTIVE = 0
  pure val NONE = -1
  pure def note(s: State, act: str, record: int): State = {...s, ev: {act: act, res: "", record: record, value: 0}}
  pure def result(s: State, res: str, value: int): State = {...s, ev: {...s.ev, res: res, value: value}}
  /// The record a registration claims: the lowest one no handle has claimed, or NONE.
  pure def vacant(s: State): int =
    if (not(s.recs.get(0).claimed)) 0 else if (not(s.recs.get(1).claimed)) 1 else NONE
  /// `register`: closed admission refuses first, then a full table; otherwise the lowest vacant record is claimed.
  /// `closing` lands the close between the claim and the cutoff read that follows it, which gives the record back.
  pure def registered(s: State, closing: bool): State = {
    val r = vacant(s)
    val admitted = {...s, recs: s.recs.set(r, {...s.recs.get(r), claimed: true, held: true})}
    if (s.closed) result(s, "Closed", NONE)
    else if (r == NONE) result(s, "ReaderLimit", NONE)
    else if (closing) result({...s, closed: true}, "Closed", NONE)
    else result({...admitted, late: s.late or s.closed or closing}, "Ok", r)
  }
  /// `enter`: a record that still holds a leaked pin refuses `Leaked` and keeps that pin; otherwise the era is pinned
  /// and the cutoff is read, and closed admission clears the new pin and refuses `Closed`. `closing` lands the close
  /// between the pin and that read. An admitted entry counts one interval; `leaks` forgets its guard, which leaves the
  /// pin in place, and otherwise the exit clears it.
  pure def entered(s: State, r: int, closing: bool, leaks: bool): State = {
    val rec = s.recs.get(r)
    val closed = s.closed or closing
    val admitted = {...rec, pin: if (leaks) ERA else INACTIVE, leaked: leaks, intervals: rec.intervals + 1}
    if (rec.leaked) result(s, "Leaked", 0)
    else if (closed) result({...s, closed: closed, recs: s.recs.set(r, {...rec, pin: INACTIVE})}, "Closed", 0)
    else result({...s, recs: s.recs.set(r, admitted), late: s.late or s.closed or closing}, "Ok", ERA)
  }
  /// What a refused entry left behind: a `Closed` refusal an inactive record, a `Leaked` refusal the pin it found.
  pure def judged(before: State, after: State, r: int): State =
    {...after, kept: before.kept or
      (after.ev.res == "Closed" and after.recs.get(r).pin != INACTIVE) or
      (after.ev.res == "Leaked" and after.recs.get(r).pin != before.recs.get(r).pin)}
  action init = all {
    st' = {closed: false, recs: RECORDS.union(Set(NONE)).mapBy(r =>
        {claimed: r == NONE, held: false, pin: INACTIVE, leaked: false, intervals: 0}),
      late: false, kept: false, ev: {act: "init", res: "", record: 0, value: 0}},
    turn' = 0
  }
  action tick = all {turn < BOUND, turn' = turn + 1}
  action register = all {tick, st' = registered(note(st, "register", 0), false)}
  action registerRacingClose = all {tick, not(st.closed), vacant(st) != NONE,
    st' = registered(note(st, "registerRacingClose", 0), true)}
  action interval(r: int): bool = all {tick, st.recs.get(r).held,
    st' = judged(st, entered(note(st, "interval", r), r, false, false), r)}
  action leak(r: int): bool = all {tick, st.recs.get(r).held, not(st.recs.get(r).leaked), not(st.closed),
    st' = judged(st, entered(note(st, "leak", r), r, false, true), r)}
  action intervalRacingClose(r: int): bool = all {tick, st.recs.get(r).held, not(st.recs.get(r).leaked), not(st.closed),
    st' = judged(st, entered(note(st, "intervalRacingClose", r), r, true, false), r)}
  action drop(r: int): bool = all {tick, st.recs.get(r).held,
    st' = result({...note(st, "drop", r), recs: st.recs.set(r, {...st.recs.get(r), claimed: false, held: false,
      pin: INACTIVE, leaked: false})}, "Ok", if (st.recs.get(r).leaked) 1 else 0)}
  action forget(r: int): bool = all {tick, st.recs.get(r).held,
    st' = result({...note(st, "forget", r), recs: st.recs.set(r, {...st.recs.get(r), held: false})}, "Ok", 0)}
  action close = all {tick, not(st.closed), st' = result({...note(st, "close", 0), closed: true}, "Ok", 0)}
  val AdmittedOnlyWhileOpen = not(st.late)
  val RefusedEntryKeepsNoNewPin = not(st.kept)
  val LeakedPinStays = RECORDS.forall(r => st.recs.get(r).leaked implies st.recs.get(r).pin != INACTIVE)
  val safety = AdmittedOnlyWhileOpen and RefusedEntryKeepsNoNewPin and LeakedPinStays
  val witnessRegistered = st.ev.act == "register" and st.ev.res == "Ok"
  val witnessRegisteredSecond = st.ev.act == "register" and st.ev.res == "Ok" and st.ev.value == 1
  val witnessRegisteredAgain = st.ev.act == "register" and st.ev.res == "Ok" and st.recs.get(st.ev.value).intervals > 0
  val witnessReaderLimit = st.ev.act == "register" and st.ev.res == "ReaderLimit"
  val witnessRegisterClosed = st.ev.act == "register" and st.ev.res == "Closed"
  val witnessRegisterRacedClose = st.ev.act == "registerRacingClose" and st.ev.res == "Closed"
  val witnessInterval = st.ev.act == "interval" and st.ev.res == "Ok"
  val witnessIntervalClosed = st.ev.act == "interval" and st.ev.res == "Closed"
  val witnessIntervalLeaked = st.ev.act == "interval" and st.ev.res == "Leaked"
  val witnessIntervalLeakedAfterClose = st.ev.act == "interval" and st.ev.res == "Leaked" and st.closed
  val witnessLeak = st.ev.act == "leak" and st.ev.res == "Ok"
  val witnessIntervalRacedClose = st.ev.act == "intervalRacingClose" and st.ev.res == "Closed"
  val witnessDropped = st.ev.act == "drop"
  val witnessDroppedLeaked = st.ev.act == "drop" and st.ev.value == 1
  val witnessForgotten = st.ev.act == "forget"
  val witnessClose = st.ev.act == "close"
  action someInterval = {
    nondet r = RECORDS.oneOf()
    interval(r)
  }
  action someLeak = {
    nondet r = RECORDS.oneOf()
    leak(r)
  }
  action someIntervalRacingClose = {
    nondet r = RECORDS.oneOf()
    intervalRacingClose(r)
  }
  action someDrop = {
    nondet r = RECORDS.oneOf()
    drop(r)
  }
  action someForget = {
    nondet r = RECORDS.oneOf()
    forget(r)
  }
  action step = any {register, registerRacingClose, someInterval, someLeak, someIntervalRacingClose, someDrop, someForget,
    close}
}
