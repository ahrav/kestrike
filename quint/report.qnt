/// Reservation commands on the command table of one device: three slots, a reservation share of two retained buffers, two data buffers.
/// Each step is one public call of the table or one act of the device: a Report submit with the driver's answer, a data submit,
/// a posted completion, a poll, a Report timeout, a cancel, a read of a Report snapshot, a close or a quiesce.
/// A token is a slot and the generation the slot issued. A reserve entry is idle with its buffer, or lent to an outstanding command.
module report {
  const BOUND: int
  type Record = {gen: int, phase: str, kind: str, timed: bool}
  type Tok = {slot: int, gen: int}
  type Entry = {idle: bool, snap: Tok}
  type Post = {slot: int, gen: int, ok: bool, valid: bool}
  type Term = {slot: int, gen: int, kind: str, status: str, refused: bool}
  type Event = {act: str, res: str, slot: int, gen: int, ordinal: int, room: int, out: List[Term]}
  type State = {
    adm: str, recs: int -> Record, free: List[int], entries: int -> Entry, pending: int, tick: int, abandoned: int,
    drain: int, spare: int, dev: Set[int], posted: List[Post], timedOut: Set[Tok], healthy: Set[Tok], requoted: bool,
    ev: Event
  }
  var st: State
  var turn: int
  pure val DEPTH = 3
  pure val SLOTS = Set(0, 1, 2)
  pure val SHARE = 2
  pure val ENTRIES = Set(0, 1)
  pure val POSTED = 3
  pure val NOTOK: Tok = {slot: -1, gen: 0}
  pure val EMPTY: Record = {gen: 0, phase: "Free", kind: "None", timed: false}
  pure def note(s: State, act: str, slot: int, gen: int, ordinal: int, room: int): State =
    {...s, ev: {act: act, res: "", slot: slot, gen: gen, ordinal: ordinal, room: room, out: []}}
  pure def result(s: State, res: str): State = {...s, ev: {...s.ev, res: res}}
  pure def outstanding(s: State): int = DEPTH - s.free.length()
  pure def refusal(s: State): str = if (s.adm == "Lost") "DeviceLost" else s.adm
  pure def top(s: State): int = s.free[s.free.length() - 1]
  pure def popped(s: State): List[int] = s.free.slice(0, s.free.length() - 1)
  /// The lowest reserve entry that is idle, or that is lent.
  pure def first(s: State, idle: bool): int = if (s.entries.get(0).idle == idle) 0 else 1
  pure def targets(s: State, slot: int, gen: int): bool =
    s.recs.get(slot).gen == gen and (s.recs.get(slot).phase == "Accepted" or s.recs.get(slot).phase == "Detached")
  /// A Report submit: the admission, not-before, quota and reserve refusals issue no token and make no driver call.
  pure def reported(s: State, ordinal: int, notBefore: int, outcome: str): State = {
    val at = first(s, true)
    val slot = top(s)
    val gen = s.recs.get(slot).gen + 1
    val taken = {...s, entries: s.entries.set(at, {idle: false, snap: NOTOK}), ev: {...s.ev, slot: slot, gen: gen}}
    val held = {...taken, free: popped(taken), pending: taken.pending + 1}
    if (s.adm != "Open") result(s, refusal(s))
    else if (ordinal < notBefore) result(s, "NotBefore")
    else if (s.tick >= ordinal) result(s, "TickQuota")
    else if (not(ENTRIES.exists(e => s.entries.get(e).idle))) result(s, "TableFull")
    else if (outcome == "Accept")
      result({...held, recs: held.recs.set(slot, {gen: gen, phase: "Accepted", kind: "Report", timed: false}),
        tick: ordinal, requoted: held.requoted or ordinal <= s.tick, dev: held.dev.union(Set(slot))}, "Accepted")
    else if (outcome == "Unwind")
      result({...held, recs: held.recs.set(slot, {gen: gen, phase: "Reserved", kind: "Report", timed: false}), adm: "Lost"},
        "Unwound")
    else result({...taken, recs: taken.recs.set(slot, {...EMPTY, gen: gen}),
      entries: taken.entries.set(at, {idle: true, snap: NOTOK})}, "Refused")
  }
  /// A data submit: refused while the free slots would not leave one for each idle reserve buffer.
  pure def submitted(s: State): State = {
    val slot = top(s)
    val gen = s.recs.get(slot).gen + 1
    if (s.adm != "Open") result(s, refusal(s))
    else if (s.free.length() + s.pending <= SHARE) result(s, "TableFull")
    else result({...s, recs: s.recs.set(slot, {gen: gen, phase: "Accepted", kind: "Data", timed: false}), free: popped(s),
      spare: s.spare - 1, dev: s.dev.union(Set(slot)), ev: {...s.ev, slot: slot, gen: gen}}, "Accepted")
  }
  /// The terminal of the slot's command: the slot frees, a Report's buffer returns to the lowest lent reserve entry with the snapshot it earned.
  pure def ended(s: State, slot: int, status: str, snap: Tok, refused: bool): State = {
    val r = s.recs.get(slot)
    val base = {...s, recs: s.recs.set(slot, {...EMPTY, gen: r.gen}), free: s.free.append(slot),
      abandoned: if (r.phase == "Detached") s.abandoned - 1 else s.abandoned}
    val term = {slot: slot, gen: r.gen, status: status, refused: refused,
      kind: if (r.kind == "Report") "Reservation" else if (r.phase == "Detached") "Abandoned"
        else if (status == "None") "Quiesced" else "Returned"}
    val after = if (r.kind == "Report")
      {...base, pending: base.pending - 1, entries: base.entries.set(first(base, false), {idle: true, snap: snap})}
      else {...base, spare: base.spare + 1}
    {...after, ev: {...after.ev, out: after.ev.out.append(term)}}
  }
  /// One picked completion: a Report publishes its snapshot only when it is still attached, healthy and passes the identity check.
  pure def complete(s: State, p: Post): State = {
    val r = s.recs.get(p.slot)
    val earned = r.kind == "Report" and r.phase == "Accepted" and p.ok
    ended(s, p.slot, if (p.ok) "Ok" else "Failed", if (earned and p.valid) {slot: p.slot, gen: p.gen} else NOTOK,
      earned and not(p.valid))
  }
  pure def pick(s: State, room: int): State = {
    val limit = if (room < DEPTH) room else DEPTH
    val count = if (s.posted.length() < limit) s.posted.length() else limit
    s.posted.slice(0, count).foldl({...s, posted: s.posted.slice(count, s.posted.length())}, (a, p) => complete(a, p))
  }
  /// The stopped drain ends the first `room` outstanding records at or after the drain cursor, in slot order. A free
  /// slot spends no room, and the cursor moves past the last record ended.
  pure def drained(s: State, room: int): State = {
    val owed = [0, 1, 2].select(slot => s.drain <= slot and s.recs.get(slot).phase != "Free")
    val count = if (room < owed.length()) room else owed.length()
    val ending = owed.slice(0, count)
    ending.foldl({...s, drain: if (count > 0) ending[count - 1] + 1 else s.drain},
      (a, slot) => ended(a, slot, "None", NOTOK, false))
  }
  pure def delivering(s: State): State = result(s, if (outstanding(s) == 0) "DeviceStopped" else "Delivering")
  pure def quiesced(s: State, answer: str, room: int): State = {
    val closed = {...s, adm: if (s.adm == "Open") "Closed" else s.adm}
    val swept = pick(closed, room)
    val stopped = {...swept, adm: "Stopped", dev: Set(), posted: []}
    if (closed.adm == "Stopped") delivering(drained(closed, room))
    else if (outstanding(swept) == 0) result(swept, "AllReturned")
    else if (answer == "Pending") result(swept, "Draining")
    else delivering(drained(stopped, room - swept.ev.out.length()))
  }
  action init = all {
    st' = {adm: "Open", recs: SLOTS.mapBy(_ => EMPTY), free: [2, 1, 0], entries: ENTRIES.mapBy(_ => {idle: true, snap: NOTOK}),
      pending: 0, tick: -1, abandoned: 0, drain: 0, spare: 2, dev: Set(), posted: [], timedOut: Set(), healthy: Set(),
      requoted: false, ev: {act: "init", res: "", slot: 0, gen: 0, ordinal: 0, room: 0, out: []}},
    turn' = 0
  }
  action tick = all {turn < BOUND, turn' = turn + 1}
  action submitReport(ordinal: int, notBefore: int, outcome: str): bool = all {tick,
    st' = reported(note(st, "submitReport", 0, 0, ordinal, notBefore), ordinal, notBefore, outcome)}
  action submitData = all {tick, st.spare > 0, st' = submitted(note(st, "submitData", 0, 0, 0, 0))}
  /// The device finishes an accepted command: healthy or failed, and for a Report with bytes that pass the identity check or not.
  action post(slot: int, ok: bool, valid: bool): bool = all {tick, st.dev.contains(slot), st.posted.length() < POSTED,
    st' = {...note(st, "post", slot, st.recs.get(slot).gen, if (ok) 1 else 0, if (valid) 1 else 0),
      dev: st.dev.exclude(Set(slot)), posted: st.posted.append({slot: slot, gen: st.recs.get(slot).gen, ok: ok, valid: valid}),
      healthy: if (ok and valid and st.recs.get(slot).kind == "Report")
        st.healthy.union(Set({slot: slot, gen: st.recs.get(slot).gen})) else st.healthy}}
  action poll(room: int): bool = all {tick,
    st' = if (st.adm == "Stopped") drained(note(st, "poll", 0, 0, 0, room), room) else pick(note(st, "poll", 0, 0, 0, room), room)}
  /// A Report passes its deadline: an attached one detaches, and its token never earns a snapshot.
  action timeout(slot: int, gen: int): bool = {
    val r = st.recs.get(slot)
    val hit = targets(st, slot, gen) and r.kind == "Report" and not(r.timed)
    val noted = note(st, "timeout", slot, gen, 0, 0)
    all {tick,
      st' = if (hit) result({...noted, recs: noted.recs.set(slot, {...r, timed: true, phase: "Detached"}),
          abandoned: if (r.phase == "Accepted") noted.abandoned + 1 else noted.abandoned,
          timedOut: noted.timedOut.union(Set({slot: slot, gen: gen}))}, "True")
        else result(noted, "False")}
  }
  action cancel(slot: int, gen: int): bool = {
    val r = st.recs.get(slot)
    val hit = targets(st, slot, gen) and r.phase == "Accepted" and st.adm != "Closed" and st.adm != "Stopped"
    val noted = note(st, "cancel", slot, gen, 0, 0)
    all {tick,
      st' = if (hit) result({...noted, recs: noted.recs.set(slot, {...r, phase: "Detached"}), abandoned: noted.abandoned + 1},
          "Ok")
        else result(noted, "Stale")}
  }
  /// A read of the snapshot a token earned: present while its reserve entry still holds it.
  action read(slot: int, gen: int): bool = all {tick,
    st' = result(note(st, "read", slot, gen, 0, 0),
      if (ENTRIES.exists(e => st.entries.get(e).idle and st.entries.get(e).snap == {slot: slot, gen: gen})) "Some" else "None")}
  action close = all {tick, st' = {...note(st, "close", 0, 0, 0, 0), adm: if (st.adm == "Open") "Closed" else st.adm}}
  action quiesce(answer: str, room: int): bool = all {tick, st' = quiesced(note(st, "quiesce", 0, 0, 0, room), answer, room)}
  val TimedOutEstablishesNothing = st.timedOut.forall(t => ENTRIES.forall(e => st.entries.get(e).snap != t))
  val SnapshotOnlyAfterHealthySuccess = ENTRIES.forall(e =>
    st.entries.get(e).snap == NOTOK or (st.entries.get(e).idle and st.healthy.contains(st.entries.get(e).snap)))
  val ReserveRetained = and {
    ENTRIES.filter(e => st.entries.get(e).idle).size() + st.pending == SHARE,
    st.pending == SLOTS.filter(s => st.recs.get(s).kind == "Report" and st.recs.get(s).phase != "Free").size(),
    st.abandoned == SLOTS.filter(s => st.recs.get(s).phase == "Detached").size(),
  }
  val DataLeavesShare = st.free.length() >= SHARE - st.pending
  val TickAdvances = not(st.requoted)
  val safety = TimedOutEstablishesNothing and SnapshotOnlyAfterHealthySuccess and ReserveRetained and DataLeavesShare and
    TickAdvances
  val witnessAccepted = st.ev.act == "submitReport" and st.ev.res == "Accepted"
  val witnessRefused = st.ev.res == "Refused"
  val witnessUnwound = st.ev.res == "Unwound"
  val witnessNotBefore = st.ev.res == "NotBefore"
  val witnessTickQuota = st.ev.res == "TickQuota"
  val witnessReserveFull = st.ev.act == "submitReport" and st.ev.res == "TableFull"
  val witnessReportRefusedClosed = st.ev.act == "submitReport" and st.ev.res == "Closed"
  val witnessReportRefusedLost = st.ev.act == "submitReport" and st.ev.res == "DeviceLost"
  val witnessDataAccepted = st.ev.act == "submitData" and st.ev.res == "Accepted"
  val witnessDataLeavesShare = st.ev.act == "submitData" and st.ev.res == "TableFull" and st.free.length() > 0
  val witnessPosted = st.ev.act == "post"
  val witnessSnapshot = st.ev.act == "poll" and ENTRIES.exists(e => st.entries.get(e).snap != NOTOK)
  val witnessIdentityRefused = st.ev.act == "poll" and st.ev.out.select(t => t.refused).length() > 0
  val witnessFailedReport = st.ev.act == "poll" and st.ev.out.select(t => t.kind == "Reservation" and t.status == "Failed").length() > 0
  val witnessLateTerminal = st.ev.act == "poll" and
    st.ev.out.select(t => t.kind == "Reservation" and st.timedOut.contains({slot: t.slot, gen: t.gen})).length() > 0
  val witnessDataReturned = st.ev.out.select(t => t.kind == "Returned").length() > 0
  val witnessDataAbandoned = st.ev.out.select(t => t.kind == "Abandoned").length() > 0
  val witnessTimedOut = st.ev.act == "timeout" and st.ev.res == "True"
  val witnessTimeoutRefused = st.ev.act == "timeout" and st.ev.res == "False"
  val witnessCancelled = st.ev.act == "cancel" and st.ev.res == "Ok"
  val witnessCancelStale = st.ev.act == "cancel" and st.ev.res == "Stale"
  val witnessReadSome = st.ev.act == "read" and st.ev.res == "Some"
  val witnessReadNone = st.ev.act == "read" and st.ev.res == "None"
  val witnessClosed = st.ev.act == "close" and st.adm == "Closed"
  val witnessAllReturned = st.ev.res == "AllReturned"
  val witnessDraining = st.ev.res == "Draining"
  val witnessDelivering = st.ev.res == "Delivering"
  val witnessDeviceStopped = st.ev.res == "DeviceStopped"
  val witnessStoppedReservation = st.adm == "Stopped" and
    st.ev.out.select(t => t.kind == "Reservation" and t.status == "None").length() > 0
  action someReport = {
    nondet ordinal = Set(0, 1, 2, 3).oneOf()
    nondet notBefore = Set(0, 2).oneOf()
    nondet outcome = Set("Accept", "Refuse", "Unwind").oneOf()
    submitReport(ordinal, notBefore, outcome)
  }
  action somePost = {
    nondet slot = SLOTS.oneOf()
    nondet ok = Set(true, false).oneOf()
    nondet valid = Set(true, false).oneOf()
    post(slot, ok, valid)
  }
  action somePoll = {
    nondet room = Set(1, 3).oneOf()
    poll(room)
  }
  action someToken = {
    nondet slot = SLOTS.oneOf()
    nondet gen = Set(1, 2, 3).oneOf()
    any {timeout(slot, gen), cancel(slot, gen), read(slot, gen)}
  }
  action someQuiesce = {
    nondet answer = Set("Pending", "Stopped").oneOf()
    nondet room = Set(1, 3).oneOf()
    quiesce(answer, room)
  }
  action step = any {someReport, submitData, somePost, somePoll, someToken, close, someQuiesce}
}
