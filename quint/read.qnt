/// One read of a record of three read commands on a volume that reads one command ahead, in the
/// steps the volume shows: the admission, which issues command 1; a grant; the device terminal of
/// a command; and a cancel. The volume issues, hands off and ends inside the step that enables it.
/// Command k carries the k-th run of chunks, and the read holds the current command, the lowest not
/// handed off, and at most one command ahead of it.
module read {
  const BOUND: int
  type Event = {act: str, arg: int, ok: bool, res: str, handed: List[int], done: str, issued: int}
  type State = {
    phase: str, issued: int, cmds: Set[int], done: Set[int], failed: Set[int], chunks: int,
    kept: bool, dones: int, at_done: int, ev: Event
  }
  var st: State
  var turn: int
  pure val COMMANDS = 3
  pure def event(act: str, arg: int, ok: bool, res: str): Event =
    {act: act, arg: arg, ok: ok, res: res, handed: List(), done: "", issued: 0}
  /// Hands off the current command when its terminal arrived as read, or ends the read once at a
  /// failed current command or after the last chunk.
  pure def hand(s: State): State =
    if (s.phase != "reading") s
    else if (s.done.contains(s.chunks + 1))
      {...s, chunks: s.chunks + 1, ev: {...s.ev, handed: s.ev.handed.append(s.chunks + 1)}}
    else if (s.failed.contains(s.chunks + 1))
      {...s, phase: "done", dones: s.dones + 1, at_done: s.chunks, ev: {...s.ev, done: "DeviceError"}}
    else if (s.chunks == COMMANDS)
      {...s, phase: "done", dones: s.dones + 1, at_done: s.chunks, ev: {...s.ev, done: "Complete"}}
    else s
  /// Issues the next command for a kept grant once the current command and one ahead leave room.
  pure def issue(s: State): State =
    if (s.phase == "reading" and s.kept and s.issued < COMMANDS and s.issued - s.chunks < 2)
      {...s, kept: false, issued: s.issued + 1, cmds: s.cmds.union(Set(s.issued + 1)), ev: {...s.ev, issued: s.ev.issued + 1}}
    else s
  pure def settle(s: State): State = issue(hand(hand(hand(hand(s)))))
  action init = all {
    st' = {phase: "idle", issued: 0, cmds: Set(), done: Set(), failed: Set(), chunks: 0, kept: false,
      dones: 0, at_done: 0, ev: event("init", 0, true, "")},
    turn' = 0
  }
  action tick = all {turn < BOUND, turn' = turn + 1}
  action admit = all {
    tick, st.phase == "idle",
    st' = {...st, phase: "reading", issued: 1, cmds: Set(1), ev: {...event("admit", 0, true, ""), issued: 1}}
  }
  action grant = all {
    tick, st.phase != "idle",
    st' = if (st.phase == "done") {...st, ev: event("grant", 0, true, "Stale")}
      else if (st.issued == COMMANDS) {...st, ev: event("grant", 0, true, "Exhausted")}
      else if (st.issued - st.chunks < 2) {...st, issued: st.issued + 1, cmds: st.cmds.union(Set(st.issued + 1)),
        ev: {...event("grant", 0, true, "Added"), issued: 1}}
      else if (st.kept) {...st, ev: event("grant", 0, true, "Merged")}
      else {...st, kept: true, ev: event("grant", 0, true, "Added")}
  }
  action terminal(k: int, ok: bool): bool = all {
    tick, st.cmds.contains(k),
    st' = settle({...st, cmds: st.cmds.exclude(Set(k)),
      done: if (ok) st.done.union(Set(k)) else st.done,
      failed: if (ok) st.failed else st.failed.union(Set(k)),
      ev: event("terminal", k, ok, "")})
  }
  action cancel = all {
    tick, st.phase != "idle",
    st' = if (st.phase == "done") {...st, ev: event("cancel", 0, true, "Stale")}
      else {...st, phase: "done", dones: st.dones + 1, at_done: st.chunks,
        ev: {...event("cancel", 0, true, ""), done: "Cancelled"}}
  }
  val OneDone = st.dones <= 1 and (st.phase == "done" implies (st.dones == 1 and st.chunks == st.at_done))
  val ChunksVerified = 1.to(st.chunks).forall(x => st.done.contains(x))
  val safety = OneDone and ChunksVerified
  val drained = st.phase == "done" and st.cmds == Set()
  val witnessComplete = st.ev.done == "Complete"
  val witnessAheadFirst = st.ev.handed == List(1, 2)
  val witnessKeptIssued = st.ev.act == "terminal" and st.ev.issued == 1
  val witnessMerged = st.ev.res == "Merged"
  val witnessExhausted = st.ev.res == "Exhausted"
  val witnessStaleGrant = st.ev.act == "grant" and st.ev.res == "Stale"
  val witnessStaleCancel = st.ev.act == "cancel" and st.ev.res == "Stale"
  val witnessCancelledTwoOut = st.ev.done == "Cancelled" and st.cmds.size() == 2
  val witnessDrainedAfterCancel = st.ev.act == "terminal" and st.at_done < COMMANDS and st.dones == 1 and drained and st.failed == Set()
  val witnessCurrentFailed = st.ev.act == "terminal" and not(st.ev.ok) and st.ev.done == "DeviceError"
  val witnessAheadFailed = st.ev.act == "terminal" and st.ev.ok and st.ev.done == "DeviceError"
  val witnessFailedAheadWaits = st.ev.act == "terminal" and not(st.ev.ok) and st.phase == "reading"
  action step = {
    nondet k = 1.to(COMMANDS).oneOf()
    nondet ok = Set(true, false).oneOf()
    any {admit, grant, terminal(k, ok), cancel}
  }
}
