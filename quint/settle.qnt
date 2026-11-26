/// The settle rules of the owner's request namespace on one wire slot of one peer: wire generations 1 to 4 with 4
/// the generation limit, two session epochs and a table of two handles. Each step is one namespace call.
/// Zero stands for no watermark, no bound handle and no refused generation.
module settle {
  const BOUND: int
  type Record = {gen: int, ended: bool, unbound: bool}
  type Event = {act: str, res: str, gen: int, handle: int, keep: bool}
  type State = {
    epoch: int, mark: int, active: int, row: bool, refused: int, table: int -> Record,
    answered: Set[(int, int)], readmitted: bool, raised: bool, ev: Event
  }
  var st: State
  var turn: int
  pure val LIMIT = 4
  pure val GENS = 1.to(LIMIT)
  pure val EPOCHS = 2
  pure val HANDLES = Set(1, 2)
  pure val FREE: Record = {gen: 0, ended: false, unbound: false}
  pure def event(act: str, res: str, gen: int, handle: int, keep: bool): Event =
    {act: act, res: res, gen: gen, handle: handle, keep: keep}
  def live = HANDLES.filter(h => st.table.get(h) != FREE)
  action init = all {
    st' = {epoch: 1, mark: 0, active: 0, row: false, refused: 0, table: HANDLES.mapBy(_ => FREE),
      answered: Set(), readmitted: false, raised: false, ev: event("init", "", 0, 0, false)},
    turn' = 0
  }
  action tick = all {turn < BOUND, turn' = turn + 1}
  /// The refusal an admission of generation g meets, in the order the namespace checks, or "" for none.
  def refusal(g: int): str =
    if (st.active != 0) "Busy"
    else if (g <= st.mark) "Stale"
    else if (g == LIMIT) "Exhausted"
    else if (live.size() >= HANDLES.size()) "Pressure"
    else ""
  /// A fresh generation takes free handle h: the watermark rises, the handle binds and the row clears.
  action admit(g: int, h: int): bool = all {
    tick, refusal(g) == "", st.table.get(h) == FREE,
    st' = {...st, mark: g, active: h, row: false, raised: false, table: st.table.set(h, {gen: g, ended: false, unbound: false}),
      answered: st.answered.union(Set((st.epoch, g))), readmitted: st.readmitted or st.answered.contains((st.epoch, g)),
      ev: event("admit", "Admitted", g, h, false)}
  }
  /// A refused admission names its refusal and changes nothing else.
  action refuse(g: int): bool = all {
    tick, refusal(g) != "",
    st' = {...st, ev: event("refuse", refusal(g), g, 0, false)}
  }
  /// An operation answers generation g without admitting it. A generation the slot already settled or refused,
  /// or the limit, changes nothing. On a free binding g becomes the watermark and the answer the row, kept or
  /// none; while a request holds the binding g is recorded as refused.
  action settle(g: int, keep: bool): bool = {
    val known = g <= st.mark or (st.active != 0 and g <= st.refused) or g == LIMIT
    all {
      tick,
      st' = if (known) {...st, ev: event("settle", "Ignored", g, 0, keep)}
        else if (st.active != 0) {...st, refused: g, answered: st.answered.union(Set((st.epoch, g))),
          ev: event("settle", "Refused", g, 0, keep)}
        else {...st, mark: g, row: keep, raised: false, answered: st.answered.union(Set((st.epoch, g))),
          ev: event("settle", "Settled", g, 0, keep)}
    }
  }
  /// The bound request ends: under its session the slot retains its row; after a replacement it retains none.
  action end: bool = all {
    tick, st.active != 0, not(st.table.get(st.active).ended),
    st' = {...st, table: st.table.setBy(st.active, r => {...r, ended: true}), row: st.row or st.mark != 0,
      ev: event("end", if (st.mark == 0) "EndedReplaced" else "Ended", st.table.get(st.active).gen, st.active, false)}
  }
  /// The binding frees: a generation refused while it was held becomes the watermark and the row drops.
  /// `raised` is true while the watermark is a refused generation that a freed binding raised.
  pure def freed(s: State): State =
    if (s.refused != 0) {...s, active: 0, mark: s.refused, row: false, refused: 0, raised: true} else {...s, active: 0}
  /// An ended request whose row is retained frees its binding while its record drains, marked unbound.
  action unbind: bool = all {
    tick, st.active != 0, st.row, st.table.get(st.active).ended,
    st' = {...freed(st), table: st.table.setBy(st.active, r => {...r, unbound: true}),
      ev: event("unbind", if (st.refused != 0) "UnboundRaised" else "Unbound", st.table.get(st.active).gen, st.active, false)}
  }
  /// A release frees an ended record the slot binds or the mark names; a bound one frees its binding.
  action release(h: int): bool = {
    val rec = st.table.get(h)
    val bound = st.active == h
    val after = if (bound) freed(st) else st
    all {
      tick, bound or rec.unbound, rec.ended,
      st' = {...after, table: st.table.set(h, FREE),
        ev: event("release", if (bound and st.refused != 0) "ReleasedRaised" else "Released", rec.gen, h, false)}
    }
  }
  /// Session replacement clears the watermark, the row and the refused generation and keeps the binding. Its
  /// event records the refused generation it forgot.
  action replace: bool = all {
    tick, st.epoch < EPOCHS,
    st' = {...st, epoch: st.epoch + 1, mark: 0, row: false, refused: 0, raised: false, ev: event("replace", "Replaced", st.refused, 0, false)}
  }
  /// A frame of generation g routes below, at or above the watermark.
  action route(g: int): bool = all {
    tick,
    st' = {...st, ev: event("route", if (g < st.mark) "Older" else if (g > st.mark) "Fresh" else "Same", g, 0, false)}
  }
  val AnsweredOnce = not(st.readmitted)
  val RefusedOnlyWhileBound = st.refused != 0 implies (st.active != 0 and st.refused > st.mark)
  val WatermarkCoversAnswered = st.answered.forall(a =>
    a._1 != st.epoch or a._2 <= st.mark or a._2 <= st.refused)
  val safety = AnsweredOnce and RefusedOnlyWhileBound and WatermarkCoversAnswered
  val witnessAdmitted = st.ev.res == "Admitted"
  val witnessBusy = st.ev.res == "Busy"
  val witnessStale = st.ev.res == "Stale"
  val witnessStaleAfterRefusal = st.ev.res == "Stale" and st.raised and st.ev.gen == st.mark
  val witnessExhausted = st.ev.res == "Exhausted"
  val witnessPressure = st.ev.res == "Pressure"
  val witnessSettled = st.ev.res == "Settled"
  val witnessSettledKept = st.ev.res == "Settled" and st.row
  val witnessRefused = st.ev.res == "Refused"
  val witnessIgnored = st.ev.res == "Ignored"
  val witnessIgnoredBelowRefusal = st.ev.res == "Ignored" and st.ev.gen > st.mark and st.ev.gen < st.refused
  val witnessEnded = st.ev.res == "Ended"
  val witnessEndedReplaced = st.ev.res == "EndedReplaced"
  val witnessUnbound = st.ev.res == "Unbound"
  val witnessUnboundRaised = st.ev.res == "UnboundRaised"
  val witnessReleased = st.ev.res == "Released"
  val witnessReleasedRaised = st.ev.res == "ReleasedRaised"
  val witnessReplaced = st.ev.res == "Replaced"
  val witnessReplacedRefusal = st.ev.res == "Replaced" and st.ev.gen != 0
  val witnessOlder = st.ev.res == "Older"
  val witnessFresh = st.ev.res == "Fresh"
  val witnessSame = st.ev.res == "Same"
  action step = any {
    {
      nondet g = GENS.oneOf()
      nondet h = HANDLES.oneOf()
      admit(g, h)
    },
    {
      nondet g = GENS.oneOf()
      refuse(g)
    },
    {
      nondet g = GENS.oneOf()
      nondet keep = Set(false, true).oneOf()
      settle(g, keep)
    },
    end,
    unbind,
    {
      nondet h = HANDLES.oneOf()
      release(h)
    },
    replace,
    {
      nondet g = GENS.oneOf()
      route(g)
    },
  }
}
