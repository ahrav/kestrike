/// The client's receive window for one GET: three fragments through a window of two, the manifest
/// START binds, the fragments held, handed out and released, and the request's one outcome. Each
/// step is one call on the fetch core or one frame of the owner, with the result the call shows.
module window {
  const BOUND: int
  type Event = {act: str, res: str, idx: int, tag: str}
  type Request = {
    manifest: str, base: int, handed: int, granted: int, advertised: int, ackedBase: int, seenTo: int,
    burst: int, held: int -> str, leases: Set[int], released: int, outcome: str, getDue: bool,
    ackDue: bool, cancelDue: str, closed: bool, foreign: bool, completed: bool,
    ev: Event
  }
  var r: Request
  var turn: int
  /// The fragments of either manifest and the window's width.
  pure val N = 3
  pure val W = 2
  pure val FRAGS = Set(0, 1, 2)
  pure def event(act: str, res: str, idx: int, tag: str): Event = {act: act, res: res, idx: idx, tag: tag}
  pure def undecided(s: Request): bool = s.outcome == "none"
  pure def live(s: Request): bool = not(s.closed)
  pure def bound(s: Request): bool = s.manifest != ""
  pure def owed(s: Request): bool = bound(s) and s.base < N
  /// Every granted fragment arrived and awaits the application's release.
  pure def heldBack(s: Request): bool = owed(s) and s.base == s.granted
  /// The advertised grant admits at most one burst beyond the highest fragment received.
  pure def creditLow(s: Request): bool = {
    val room = if (s.advertised > s.seenTo) s.advertised - s.seenTo else 0
    room <= s.burst
  }
  pure def has(s: Request, i: int): bool = s.held.keys().contains(i)
  /// The receipt base after it moves over the contiguous fragments held below the grant.
  pure def reach(s: Request): int = {
    val end = if (N < s.granted) N else s.granted
    val one = if (s.base < end and has(s, s.base)) s.base + 1 else s.base
    val two = if (one > s.base and one < end and has(s, one)) one + 1 else one
    if (two > one and two < end and has(s, two)) two + 1 else two
  }
  pure def advanced(s: Request): Request =
    if (bound(s) and reach(s) > s.base) {...s, base: reach(s), ackDue: true} else s
  /// One past the highest fragment held at or above the base, or the base.
  pure def highest(s: Request): int = {
    val above = s.held.keys().filter(i => i >= s.base)
    if (above.contains(2)) 3 else if (above.contains(1)) 2 else if (above.contains(0)) 1 else s.base
  }
  /// The end of an undecided request: the status's outcome before any fragment was handed out and
  /// `Incomplete` after, with the fragments not handed out returned.
  pure def finished(s: Request, outcome: str, cancel: str): Request =
    if (not(live(s)) or not(undecided(s))) s
    else {...s, outcome: if (s.handed > 0) "Incomplete" else outcome, cancelDue: cancel, getDue: false,
      ackDue: false, held: Map()}
  /// The grant the next poll folds in: the initial window and one per released lease.
  pure def folded(s: Request): Request = {
    val grant = W + s.released
    val raised = if (live(s) and undecided(s) and grant > s.granted) {...s, granted: grant} else s
    if (live(s) and undecided(s))
      {...raised, ackDue: raised.ackDue or (owed(raised) and creditLow(raised) and raised.granted > raised.advertised)}
    else raised
  }
  /// The frame the next poll sends: a CANCEL, a GET before START, or an ACK.
  pure def frame(s: Request): str =
    if (not(live(s))) "none" else if (s.cancelDue != "") "cancel" else if (not(undecided(s))) "none"
    else if (s.getDue) "get" else if (bound(s) and s.ackDue) "ack" else "none"

  action init = all {
    r' = {manifest: "", base: 0, handed: 0, granted: W, advertised: W, ackedBase: 0, seenTo: 0, burst: 0,
      held: Map(), leases: Set(), released: 0, outcome: "none", getDue: true, ackDue: false, cancelDue: "",
      closed: false, foreign: false, completed: false, ev: event("init", "", 0, "")},
    turn' = 0
  }
  action tick = all {turn < BOUND, turn' = turn + 1}
  /// A poll with room for one frame: it folds the released grant in and sends the due frame, which the
  /// transport takes or refuses.
  action poll(taken: bool): bool = {
    val s = folded(r)
    val kind = frame(s)
    all {tick,
      r' = if (kind == "none") {...s, ev: event("poll", "none", 0, "")}
        else if (not(taken)) {...s, ev: event("poll", "refused", s.base, kind)}
        else if (kind == "cancel") {...s, cancelDue: "", ev: event("poll", "cancel", 0, s.cancelDue)}
        else if (kind == "get") {...s, getDue: false, advertised: W, ev: event("poll", "get", 0, "")}
        else {...s, ackDue: false, advertised: s.granted, ackedBase: s.base, ev: event("poll", "ack", s.base, "")}
    }
  }
  /// A START naming manifest `m`; `Big` names one above the GET's caps.
  action start(m: str): bool = {
    val kept = r.held.keys().filter(i => r.held.get(i) == m)
    val pruned = {...r, held: kept.mapBy(i => r.held.get(i))}
    val bind = {...pruned, manifest: m, getDue: false, ackDue: true,
      seenTo: if (kept == r.held.keys()) r.seenTo else highest(pruned)}
    all {tick,
      r' = if (not(live(r)) or not(undecided(r)) or (bound(r) and r.manifest != m)) {...r, ev: event("start", "ignored", 0, m)}
        else if (bound(r)) {...r, ackDue: true, ev: event("start", "repeat", 0, m)}
        else if (m == "Big") {...finished(r, "Failed", "Cancelled"), ev: event("start", "TooLarge", 0, m)}
        else {...advanced(bind), ev: event("start", "bound", 0, m)}
    }
  }
  /// A DATA frame of fragment `i` naming manifest `m`.
  action data(i: int, m: str): bool = {
    val fits = undecided(r) and i >= r.base and i < r.granted and (not(bound(r)) or r.manifest == m)
    val seen = if (i + 1 > r.seenTo) i + 1 else r.seenTo
    val reach = if (seen - r.ackedBase > r.burst) seen - r.ackedBase else r.burst
    val placed = {...r, held: r.held.put(i, m), seenTo: seen, burst: reach}
    val credited = {...placed, ackDue: placed.ackDue or (placed.granted > placed.advertised and owed(placed) and creditLow(placed))}
    all {tick,
      r' = if (not(live(r))) {...r, ev: event("data", "dropped", i, m)}
        else if (fits and not(has(r, i))) {...advanced(credited), ev: event("data", "held", i, m)}
        else {...r, ackDue: r.ackDue or (i < r.base and undecided(r)), ev: event("data", "dropped", i, m)}
    }
  }
  action complete(m: str): bool = all {tick,
    r' = if (live(r) and undecided(r) and r.manifest == m and r.base == N)
        {...r, outcome: "Complete", ackDue: false, completed: true, ev: event("complete", "Complete", 0, m)}
      else {...r, ev: event("complete", "ignored", 0, m)}
  }
  /// An ERROR whose status is a miss, a pressure refusal or a failure.
  action error(kind: str): bool = {
    val s = finished(r, kind, "")
    all {tick, r' = {...s, ev: event("error", if (s == r) "ignored" else s.outcome, 0, kind)}}
  }
  action cancel = {
    val s = finished(r, "Failed", "Cancelled")
    all {tick, r' = {...s, ev: event("cancel", if (s == r) "ignored" else s.outcome, 0, "")}}
  }
  /// The application takes the next fragment in order, if received.
  action take = all {tick,
    r' = if (live(r) and r.handed < r.base and has(r, r.handed))
        {...r, handed: r.handed + 1, held: r.held.keys().exclude(Set(r.handed)).mapBy(i => r.held.get(i)),
          leases: r.leases.union(Set(r.handed)), foreign: r.foreign or r.held.get(r.handed) != r.manifest,
          ev: event("take", "taken", r.handed, r.held.get(r.handed))}
      else {...r, ev: event("take", "none", 0, "")}
  }
  /// The application drops its lease of fragment `i`; a live request gains one receive slot.
  action release(i: int): bool = all {tick, r.leases.contains(i),
    r' = {...r, leases: r.leases.exclude(Set(i)), released: if (live(r)) r.released + 1 else r.released,
      ev: event("release", "", i, "")}
  }
  action close = all {tick,
    r' = if (live(r) and not(undecided(r)) and r.cancelDue == "") {...r, closed: true, held: Map(), ev: event("close", "true", 0, "")}
      else {...r, ev: event("close", "false", 0, "")}
  }
  /// The retry timer fires: the GET is due again before START and the ACK after it.
  action retry = all {tick, live(r), undecided(r), not(heldBack(r)),
    r' = if (bound(r)) {...r, ackDue: true, ev: event("retry", "ack", 0, "")}
      else {...r, getDue: true, ev: event("retry", "get", 0, "")}
  }
  action deadline = {
    val s = finished(r, "Failed", "TimedOut")
    all {tick, live(r), undecided(r), r' = {...s, ev: event("deadline", s.outcome, 0, "")}}
  }
  /// The session ends: an undecided request ends without a CANCEL.
  action endSession = {
    val s = finished(r, "Failed", "")
    all {tick, live(r), r' = {...s, ev: event("endSession", if (s == r) "kept" else s.outcome, 0, "")}}
  }

  /// A held fragment lies at or above the fragments handed out and below the grant.
  val InWindow = r.held.keys().forall(i => i >= r.handed and i < r.granted)
  /// Nothing is handed out or acknowledged before START, and once START bound a manifest every held
  /// fragment and every fragment handed out names it.
  val BoundManifest = (not(bound(r)) implies (r.handed == 0 and r.base == 0)) and
    (bound(r) implies r.held.keys().forall(i => r.held.get(i) == r.manifest)) and not(r.foreign)
  /// Fragments are handed out below the receipt base, in order.
  val InOrder = r.handed <= r.base and r.leases.forall(i => i < r.handed)
  /// Success follows START, every fragment and COMPLETE.
  val CompleteNeedsAll = r.outcome == "Complete" implies (bound(r) and r.base == N and r.completed)
  /// A request that ended otherwise after a fragment was handed out ended `Incomplete`.
  val ExposedIsIncomplete = (Set("Missing", "Pressure", "Failed").contains(r.outcome) implies r.handed == 0) and
    (r.outcome == "Incomplete" implies r.handed > 0)
  val safety = InWindow and BoundManifest and InOrder and CompleteNeedsAll and ExposedIsIncomplete

  val witnessGet = r.ev.act == "poll" and r.ev.res == "get"
  val witnessAck = r.ev.act == "poll" and r.ev.res == "ack"
  val witnessCancelFrame = r.ev.act == "poll" and r.ev.res == "cancel"
  val witnessRefused = r.ev.act == "poll" and r.ev.res == "refused"
  val witnessNothingDue = r.ev.act == "poll" and r.ev.res == "none" and undecided(r)
  val witnessGrantAck = r.ev.act == "poll" and r.ev.res == "ack" and r.granted > W
  val witnessBound = r.ev.res == "bound"
  /// `burst` is positive at the START only when a fragment was held before it, and none stays at or above the base.
  val witnessBoundDropsHeld = r.ev.res == "bound" and r.seenTo == r.base and r.base == 0 and r.burst > 0
  val witnessBoundExposesHeld = r.ev.res == "bound" and r.base > 0
  val witnessStartRepeat = r.ev.res == "repeat"
  val witnessStartOther = r.ev.act == "start" and r.ev.res == "ignored" and bound(r) and undecided(r)
  val witnessTooLarge = r.ev.res == "TooLarge"
  val witnessHeld = r.ev.act == "data" and r.ev.res == "held"
  val witnessHeldBeforeStart = r.ev.act == "data" and r.ev.res == "held" and not(bound(r))
  val witnessGap = r.ev.act == "data" and r.ev.res == "held" and bound(r) and r.seenTo > r.base + 1
  val witnessDuplicate = r.ev.act == "data" and r.ev.res == "dropped" and has(r, r.ev.idx)
  val witnessBelowBase = r.ev.act == "data" and r.ev.res == "dropped" and r.ev.idx < r.base and r.ackDue
  val witnessAtGrant = r.ev.act == "data" and r.ev.res == "dropped" and r.ev.idx >= r.granted and undecided(r)
  val witnessOtherManifest = r.ev.act == "data" and r.ev.res == "dropped" and bound(r) and r.ev.tag != r.manifest and
    r.ev.idx >= r.base and r.ev.idx < r.granted and undecided(r)
  val witnessHeldBack = heldBack(r) and r.ev.act == "data"
  val witnessComplete = r.ev.res == "Complete"
  val witnessEarlyComplete = r.ev.act == "complete" and r.ev.res == "ignored" and bound(r) and undecided(r)
  val witnessMissing = r.ev.act == "error" and r.outcome == "Missing"
  val witnessPressure = r.ev.act == "error" and r.outcome == "Pressure"
  val witnessFailed = r.ev.act == "error" and r.outcome == "Failed"
  val witnessIncomplete = r.ev.act == "error" and r.outcome == "Incomplete"
  val witnessErrorIgnored = r.ev.act == "error" and r.ev.res == "ignored"
  val witnessCancelled = r.ev.act == "cancel" and r.ev.res == "Failed"
  val witnessCancelledExposed = r.ev.act == "cancel" and r.ev.res == "Incomplete"
  val witnessTaken = r.ev.res == "taken"
  val witnessTakeNone = r.ev.act == "take" and r.ev.res == "none" and r.held.keys() != Set()
  val witnessTakenAfterComplete = r.ev.res == "taken" and r.outcome == "Complete"
  val witnessRelease = r.ev.act == "release" and live(r)
  val witnessReleaseAfterClose = r.ev.act == "release" and r.closed
  val witnessClosed = r.ev.act == "close" and r.ev.res == "true"
  val witnessCloseWaitsForCancel = r.ev.act == "close" and r.ev.res == "false" and r.cancelDue != ""
  val witnessRetryGet = r.ev.act == "retry" and r.ev.res == "get"
  val witnessRetryAck = r.ev.act == "retry" and r.ev.res == "ack"
  val witnessDeadline = r.ev.act == "deadline" and r.outcome == "Failed"
  val witnessDeadlineExposed = r.ev.act == "deadline" and r.outcome == "Incomplete"
  val witnessSessionEnd = r.ev.act == "endSession" and r.ev.res == "Failed"
  val witnessSessionEndKeeps = r.ev.act == "endSession" and r.ev.res == "kept" and r.outcome == "Complete"

  pure def manifestOf(b: int): str = if (b == 0) "A" else "B"
  pure def startOf(a: int): str = if (a == 0) "A" else if (a == 1) "B" else "Big"
  pure def errorOf(a: int): str = if (a == 0) "Missing" else if (a == 1) "Pressure" else "Failed"
  /// Two picks parameterize every action, so a step has six picks for each of its twelve choices.
  action step = {
    nondet a = FRAGS.oneOf()
    nondet b = Set(0, 1).oneOf()
    any {poll(b == 0), start(startOf(a)), data(a, manifestOf(b)), complete(manifestOf(b)), error(errorOf(a)), cancel,
      take, release(a), close, retry, deadline, endSession}
  }
}
