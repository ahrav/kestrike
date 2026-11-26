/// The owner and device half of one remote PUT of two fragments, in the steps the owner shows at its
/// frames and its device terminals: BEGIN, PREPARE, DATA and CANCEL frames, an invalidation, the
/// terminal of each write, and one successor upload of the same key after a revocation. The owner
/// answers, submits, fails and publishes inside the step that enables it. Range 0 is the write that
/// carries the record's header and range 1 the other payload write.
module put {
  const BOUND: int
  type Event = {act: str, arg: int, ok: bool, reply: str, base: int}
  type State = {
    stage: str, credit: int -> int, data: int -> int, conflict: bool, revoked: bool,
    ws: int -> str, order: List[int], published: int, bytes: int -> int,
    succ: str, sterm: bool, repeated: bool, cancelled: str, ev: Event
  }
  var st: State
  var turn: int
  pure val FRAGS = Set(0, 1)
  pure val RANGES = Set(0, 1)
  pure def event(act: str, arg: int, ok: bool, reply: str, base: int): Event =
    {act: act, arg: arg, ok: ok, reply: reply, base: base}
  pure def base(credit: int -> int): int = if (credit.get(0) == 0) 0 else if (credit.get(1) == 0) 1 else 2
  pure def outstanding(ws: int -> str): bool = RANGES.exists(w => ws.get(w) == "submitted")
  pure def ending(ws: int -> str): str = if (outstanding(ws)) "draining" else "ended"
  action init = all {
    st' = {stage: "idle", credit: FRAGS.mapBy(_ => 0), data: FRAGS.mapBy(_ => 0), conflict: false, revoked: false,
      ws: RANGES.mapBy(_ => "none"), order: List(), published: 0, bytes: FRAGS.mapBy(_ => 0),
      succ: "none", sterm: false, repeated: false, cancelled: "", ev: event("init", 0, true, "", 0)},
    turn' = 0
  }
  action tick = all {turn < BOUND, turn' = turn + 1}
  action begin = all {
    tick, st.stage == "idle",
    st' = {...st, stage: "authority", ev: event("begin", 0, true, "AUTHORITY", 0)}
  }
  action prepare = all {
    tick, st.stage == "authority",
    st' = {...st, stage: "ready", ev: event("prepare", 0, true, "READY", 0)}
  }
  /// `repeated` records whether the latest DATA named a fragment the upload had already credited.
  action data(i: int): bool = {
    val credit = st.credit.set(i, 1)
    val whole = FRAGS.forall(f => credit.get(f) == 1)
    all {tick, st.stage == "ready",
      st' = {...(if (st.credit.get(i) > 0) {...st, ev: event("data", i, true, "ACK", base(st.credit))}
        else if (st.revoked and base(credit) == base(st.credit)) {...st, credit: credit, data: st.data.set(i, 1),
          ev: event("data", i, true, "ACK", base(credit))}
        else if (st.revoked) {...st, stage: "ended", ev: event("data", i, true, "Contended", 0)}
        else if (whole) {...st, credit: credit, data: st.data.set(i, 1),
          ws: RANGES.mapBy(_ => "submitted"), order: List(1, 0), ev: event("data", i, true, "ACK", base(credit))}
        else {...st, credit: credit, data: st.data.set(i, 1), ev: event("data", i, true, "ACK", base(credit))}),
        repeated: st.credit.get(i) > 0}
    }
  }
  action differ(i: int): bool = all {
    tick, st.stage == "ready", st.credit.get(i) > 0,
    st' = {...st, conflict: true, stage: ending(st.ws), ev: event("differ", i, true, "ConflictingData", 0)}
  }
  /// `cancelled` records the stage the cancel found the upload in.
  action cancel = all {
    tick, Set("authority", "ready").contains(st.stage),
    st' = {...st, stage: ending(st.ws), cancelled: st.stage, ev: event("cancel", 0, true, "Cancelled", 0)}
  }
  action invalidate = all {
    tick, st.stage == "ready", not(st.revoked),
    st' = {...st, revoked: true, ev: event("invalidate", 0, true, "", 0)}
  }
  action terminal(w: int, ok: bool): bool = {
    val ws = st.ws.set(w, if (ok) "written" else "failed")
    val complete = RANGES.forall(x => ws.get(x) == "written")
    all {tick, st.ws.get(w) == "submitted",
      st' = if (st.stage == "draining") {...st, ws: ws, stage: ending(ws), ev: event("terminal", w, ok, "", 0)}
        else if (not(ok)) {...st, ws: ws, stage: ending(ws), ev: event("terminal", w, ok, "DeviceError", 0)}
        else if (not(complete)) {...st, ws: ws, ev: event("terminal", w, ok, "", 0)}
        else if (st.revoked) {...st, ws: ws, stage: "ended", ev: event("terminal", w, ok, "Contended", 0)}
        else {...st, ws: ws, stage: "ended", published: 1, bytes: st.data, ev: event("terminal", w, ok, "RESULT", 0)}
    }
  }
  action sbegin = all {
    tick, st.revoked, st.succ == "none",
    st' = {...st, succ: "writing", ev: event("sbegin", 0, true, "ACK", 1)}
  }
  action sterminal(ok: bool): bool = all {
    tick, st.succ == "writing",
    st' = if (ok) {...st, succ: "published", sterm: true, published: 2, bytes: FRAGS.mapBy(_ => 2),
        ev: event("sterminal", 0, ok, "RESULT", 0)}
      else {...st, succ: "failed", sterm: true, ev: event("sterminal", 0, ok, "DeviceError", 0)}
  }
  val live = (if (Set("authority", "ready", "draining").contains(st.stage)) 1 else 0) + (if (st.succ == "writing") 1 else 0)
  val PublishedComplete = st.published == 1 implies (FRAGS.forall(i => st.credit.get(i) == 1) and
    RANGES.forall(w => st.ws.get(w) == "written") and not(st.conflict) and not(st.revoked))
  val PublishedClientBytes = st.published == 1 implies FRAGS.forall(i => st.bytes.get(i) == 1)
  val HeaderLast = st.ws.get(0) != "none" implies (st.ws.get(1) != "none" and st.order == List(1, 0))
  val WriteCustody = st.stage == "ended" implies not(outstanding(st.ws))
  val SuccessorIsolated = st.succ == "published" implies st.sterm
  val safety = PublishedComplete and PublishedClientBytes and HeaderLast and WriteCustody and SuccessorIsolated
  val witnessPublished = st.ev.reply == "RESULT" and st.published == 1
  val witnessOutOfOrder = st.ev.act == "data" and st.ev.arg == 1 and st.ev.base == 0 and st.ev.reply == "ACK"
  val witnessDuplicate = st.ev.act == "data" and st.repeated and st.credit.get(st.ev.arg) == 1 and outstanding(st.ws)
  val witnessConflictEnded = st.ev.reply == "ConflictingData" and st.stage == "ended"
  val witnessConflictDraining = st.ev.reply == "ConflictingData" and st.stage == "draining"
  val witnessCancelAtAuthority = st.ev.reply == "Cancelled" and st.cancelled == "authority" and st.credit.get(0) == 0 and st.stage == "ended"
  val witnessCancelDraining = st.ev.reply == "Cancelled" and st.stage == "draining"
  val witnessDrained = st.ev.act == "terminal" and st.ev.reply == "" and st.stage == "ended"
  val witnessDeviceErrorDraining = st.ev.reply == "DeviceError" and st.stage == "draining"
  val witnessDeviceErrorEnded = st.ev.act == "terminal" and st.ev.reply == "DeviceError" and st.stage == "ended"
  val witnessRevokedAtData = st.ev.act == "data" and st.ev.reply == "Contended"
  val witnessRevokedBehindBase = st.ev.act == "data" and st.ev.reply == "ACK" and st.revoked and st.ev.base == 0 and st.credit.get(1) == 1
  val witnessRevokedAtCompletion = st.ev.act == "terminal" and st.ev.reply == "Contended"
  val witnessSuccessorBesideOldWrite = st.succ == "published" and outstanding(st.ws)
  val witnessLateTerminalAfterSuccessor = st.ev.act == "terminal" and st.succ == "published" and st.published == 2
  val witnessSuccessorFailed = st.succ == "failed"
  action step = {
    nondet i = FRAGS.oneOf()
    nondet w = RANGES.oneOf()
    nondet ok = Set(true, false).oneOf()
    any {begin, prepare, data(i), differ(i), cancel, invalidate, terminal(w, ok), sbegin, sterminal(ok)}
  }
}
