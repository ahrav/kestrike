/// The grace protocol of one slot: two readers, one writer and one maintainer.
/// Each step is one call of the `grace` module or one act of its callers: a pin, a reader's observation of the entry,
/// an unpin, the entry's removal, the retirement's bump with its stamp and mark, a bump for a retirement elsewhere,
/// the start of a certification pass, one visit, the pass's completion, an attempt to release the anchor, the reuse.
/// A pin holds the era it read; zero is an inactive record. Eras at or above TERMINAL refuse every new pin.
module grace {
  const BOUND: int
  type Pass = {on: bool, start: int, low: int, next: int}
  type Event = {act: str, res: str, reader: int, value: int, closes: bool}
  type State = {
    era: int, certified: int, pins: int -> int, copies: int -> bool, visible: bool,
    stamp: int, anchored: bool, released: bool, reused: bool, pass: Pass, ev: Event
  }
  var st: State
  var turn: int
  pure val READERS = Set(0, 1)
  pure val RECORDS = 2
  pure val FIRST = 1
  pure val TERMINAL = 3
  pure val INACTIVE = 0
  pure val NOPIN = 1000
  pure def least(a: int, b: int): int = if (a < b) a else b
  pure def note(s: State, act: str, reader: int): State =
    {...s, ev: {act: act, res: "", reader: reader, value: 0, closes: false}}
  pure def result(s: State, res: str, value: int): State = {...s, ev: {...s.ev, res: res, value: value}}
  /// `pin`: the terminal era refuses first, then a record that still holds a pin; otherwise the record takes the era.
  pure def pinned(s: State, r: int): State =
    if (s.era >= TERMINAL) result(s, "Terminal", 0)
    else if (s.pins.get(r) != INACTIVE) result(s, "Active", 0)
    else result({...s, pins: s.pins.set(r, s.era)}, "Ok", s.era)
  /// A pinned reader's observation: it holds a copy of the entry exactly when the entry is still visible.
  pure def observed(s: State, r: int): State =
    result({...s, copies: s.copies.set(r, s.visible)}, if (s.visible) "Visible" else "Gone", 0)
  /// `unpin`: the interval ends and the reader holds no copy.
  pure def unpinned(s: State, r: int): State =
    result({...s, pins: s.pins.set(r, INACTIVE), copies: s.copies.set(r, false)}, "Ok", 0)
  /// `bump`: the era advances and the call returns the era it found, and closes when that era is `TERMINAL - 1` or more.
  pure def bumped(s: State): State =
    {...s, era: s.era + 1, ev: {...s.ev, res: "Ok", value: s.era, closes: s.era >= TERMINAL - 1}}
  /// The retirement of the removed entry: the bump, its stamp and the anchored mark.
  pure def retired(s: State): State = {...bumped(s), stamp: s.era, anchored: true}
  /// `PassCursor::visit`: the pass keeps the smallest active pin it has seen.
  pure def visited(s: State): State = {
    val pin = s.pins.get(s.pass.next)
    result({...s, pass: {...s.pass, low: if (pin != INACTIVE) least(s.pass.low, pin) else s.pass.low,
      next: s.pass.next + 1}}, "Ok", pin)
  }
  /// `PassCursor::complete`: the certified era rises to the pass's bound, the smaller of the start era and the
  /// smallest pin seen, when that is higher. The result is `Start` or `Pin` for the value that set it, or `Kept`
  /// when the certified era stays.
  pure def completed(s: State): State = {
    val bound = least(s.pass.start, s.pass.low)
    val certified = if (bound <= s.certified) s.certified else bound
    result({...s, certified: certified, pass: {on: false, start: 0, low: NOPIN, next: 0}},
      if (bound <= s.certified) "Kept" else if (bound < s.pass.start) "Pin" else "Start", certified)
  }
  /// `releasable`: the anchor leaves only when its stamp lies strictly below the certified era.
  pure def tried(s: State): State =
    if (s.stamp < s.certified) result({...s, released: true}, "Released", 0) else result(s, "Held", 0)
  action init = all {
    st' = {era: FIRST, certified: 0, pins: READERS.mapBy(_ => INACTIVE), copies: READERS.mapBy(_ => false), visible: true,
      stamp: 0, anchored: false, released: false, reused: false, pass: {on: false, start: 0, low: NOPIN, next: 0},
      ev: {act: "init", res: "", reader: 0, value: 0, closes: false}},
    turn' = 0
  }
  action tick = all {turn < BOUND, turn' = turn + 1}
  action pin(r: int): bool = all {tick, st' = pinned(note(st, "pin", r), r)}
  action observe(r: int): bool = all {tick, st.pins.get(r) != INACTIVE, st' = observed(note(st, "observe", r), r)}
  action unpin(r: int): bool = all {tick, st' = unpinned(note(st, "unpin", r), r)}
  action remove = all {tick, st.visible, st' = result({...note(st, "remove", 0), visible: false}, "Ok", 0)}
  action retire = all {tick, st.stamp == 0, not(st.visible), st' = retired(note(st, "retire", 0))}
  action elsewhere = all {tick, st' = bumped(note(st, "elsewhere", 0))}
  action begin = all {tick, not(st.pass.on),
    st' = result({...note(st, "begin", 0), pass: {on: true, start: st.era, low: NOPIN, next: 0}}, "Ok", st.era)}
  action visit = all {tick, st.pass.on, st.pass.next < RECORDS, st' = visited(note(st, "visit", 0))}
  action complete = all {tick, st.pass.on, st.pass.next == RECORDS, st' = completed(note(st, "complete", 0))}
  action release = all {tick, st.anchored, not(st.released), st' = tried(note(st, "release", 0))}
  action reuse = all {tick, st.released, not(st.reused), st' = result({...note(st, "reuse", 0), reused: true}, "Ok", 0)}
  val Protected = READERS.forall(r => st.copies.get(r) implies not(st.released or st.reused))
  val safety = Protected
  val witnessPinned = st.ev.act == "pin" and st.ev.res == "Ok"
  val witnessPinActive = st.ev.act == "pin" and st.ev.res == "Active"
  val witnessPinTerminal = st.ev.act == "pin" and st.ev.res == "Terminal"
  val witnessPinnedAfterBump = st.ev.act == "pin" and st.ev.res == "Ok" and st.ev.value > FIRST
  val witnessObservedVisible = st.ev.act == "observe" and st.ev.res == "Visible"
  val witnessObservedGone = st.ev.act == "observe" and st.ev.res == "Gone"
  val witnessUnpinned = st.ev.act == "unpin"
  val witnessRemoved = st.ev.act == "remove"
  val witnessRetired = st.ev.act == "retire" and not(st.ev.closes)
  val witnessRetiredClosing = st.ev.act == "retire" and st.ev.closes
  val witnessElsewhere = st.ev.act == "elsewhere" and not(st.ev.closes)
  val witnessElsewhereClosing = st.ev.act == "elsewhere" and st.ev.closes
  val witnessBegun = st.ev.act == "begin"
  val witnessVisitedPin = st.ev.act == "visit" and st.ev.value != INACTIVE
  val witnessVisitedInactive = st.ev.act == "visit" and st.ev.value == INACTIVE
  val witnessRaisedToStart = st.ev.act == "complete" and st.ev.res == "Start"
  val witnessRaisedToPin = st.ev.act == "complete" and st.ev.res == "Pin"
  val witnessKept = st.ev.act == "complete" and st.ev.res == "Kept"
  val witnessReleased = st.ev.act == "release" and st.ev.res == "Released"
  val witnessHeld = st.ev.act == "release" and st.ev.res == "Held"
  val witnessHeldUnderCopy = st.ev.act == "release" and st.ev.res == "Held" and READERS.exists(r => st.copies.get(r))
  val witnessReused = st.ev.act == "reuse"
  action somePin = {
    nondet r = READERS.oneOf()
    pin(r)
  }
  action someObserve = {
    nondet r = READERS.oneOf()
    observe(r)
  }
  action someUnpin = {
    nondet r = READERS.oneOf()
    unpin(r)
  }
  action step = any {somePin, someObserve, someUnpin, remove, retire, elsewhere, begin, visit, complete, release, reuse}
}
