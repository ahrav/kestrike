/// The detector's suspicion and the arbiter's flip nomination. Placement is caller-validated evidence; liveness runs
/// under `fixedStep` and `declareStep` and assumes ready evidence and per-obligation fairness. A heartbeat carries the
/// sender's health bit: three observed windows that admitted a heartbeat, with every heartbeat admitted since the last
/// healthy one reporting the sender unhealthy, read as a declared failure, which nominates on one observer class,
/// while an observed stall reads gray and needs two. A window with no heartbeat keeps the declared count.
/// A silent suspicion ends after two windows with a healthy heartbeat; a window whose every heartbeat reports the
/// sender unhealthy keeps that count, and a window with no heartbeat restarts it.
module detect {
  const BOUND: int
  type Peer = { generation: int, trackedSince: int, seq: int, progress: int, seen: bool, progressed: bool, affirmed: bool, empty: int, stalled: int, declared: int, exit: int, since: int, kind: str }
  type Evidence = { observation: int, grayVotes: bool, declaredVotes: bool, dwellValid: bool, boundsValid: bool, suspicionFresh: bool, roundsValid: bool, healthy: bool, age: int, dead: int, alive: bool, unknown: bool, answers: int, distinct: bool, second: bool,
    clock: bool, clockAge: int }
  pure val ready: Evidence = { observation: 1, grayVotes: false, declaredVotes: false, dwellValid: true, boundsValid: true, suspicionFresh: true, roundsValid: true, healthy: true, age: 10, dead: 2, alive: false, unknown: false, answers: 2, distinct: true, second: true,
    clock: true, clockAge: 3 }
  pure val fresh: Peer = { generation: 1, trackedSince: 0, seq: -1, progress: -1, seen: false, progressed: false, affirmed: false, empty: 0, stalled: 0, declared: 0, exit: 0, since: 0, kind: "Alive" }
  pure def cap(v: int, bound: int): int = if (v > bound) bound else v
  var reported: str
  var prior: Peer
  var peer: Peer
  var now: int
  var votes: Set[str]
  var nominated: bool
  var turn: int
  var ev: { act: str, res: str, seq: int, progress: int, healthy: bool, observed: bool, exhausted: bool, evidence: Evidence, who: str }
  pure def verdict(e: Evidence, p: Peer): str = {
    if (not(e.dwellValid)) "Dwell"
    else if (not(e.boundsValid)) "Bounds"
    else if (not(e.healthy)) "ObserverUnhealthy"
    else if (not(e.suspicionFresh) or p.generation != e.observation) "StaleSuspicion"
    else if (p.kind == "Alive" or p.kind == "Unknown") "NotSuspect"
    else if (e.age < 0) "Time"
    else if (e.age <= 2) "HolderGrace"
    else if (not(e.roundsValid)) "ProbeBound"
    else if (e.answers == 0) "SelfSuspect"
    else if (e.alive) "Alive"
    else if (e.unknown) "Unknown"
    else if (e.dead < 2 or not(e.distinct)) "Quorum"
    else if ((p.kind == "Gray" or e.grayVotes) and not(e.second)) "GrayNeedsSecondClass"
    else if (not(e.clock) or e.clockAge > 3 or e.clockAge < 0) "ClockUntrusted"
    else "Nominate"
  }
  pure def heartbeat(p: Peer, seq: int, progress: int, healthy: bool): Peer =
    if (seq <= p.seq) p else { ...p, seq: seq, seen: true, affirmed: p.affirmed or healthy, empty: 0,
      progress: if (progress > p.progress) progress else p.progress,
      progressed: p.progressed or progress > p.progress,
      stalled: if (progress > p.progress) 0 else p.stalled }
  /// The window admitted a heartbeat and every admitted one reported the sender unhealthy.
  pure def declaring(p: Peer): bool = p.seen and not(p.affirmed)
  pure def window(p: Peer, t: int, observed: bool): Peer = {
    // A healthy heartbeat, in an observed window or a gap, ends the declared count and turns a declared suspicion
    // into an observed stall.
    val held = if (p.kind == "Declared" and p.affirmed) "Gray" else p.kind
    val kept = if (p.affirmed) 0 else p.declared
    val empty = if (p.seen) 0 else cap(p.empty + 1, 3)
    val stalled = if (p.progressed) 0 else cap(p.stalled + 1, 3)
    // A window with no heartbeat keeps the count.
    val declared = if (declaring(p)) cap(kept + 1, 3) else kept
    val declares = declaring(p) and declared >= 3
    val nonempty = if (held == "Gray") p.progressed else if (held == "Declared") false else p.seen and p.affirmed
    // A window whose every heartbeat reports the sender unhealthy keeps a silent suspicion's exit count, and a
    // suspicion ends only in a window that counts toward its exit.
    val keptExit = if (held == "Silent" and declaring(p)) p.exit else 0
    val exit = if (held == "Alive" or declares) 0 else if (nonempty) cap(p.exit + 1, 2) else keptExit
    val clear = held != "Alive" and not(declares) and nonempty and exit >= 2 and t - p.since >= 2
    val suspect = t - p.trackedSince >= 2 and (declares or empty >= 3 or stalled >= 3)
    if (not(observed)) { ...p, seen: false, progressed: false, affirmed: false, exit: 0, declared: kept, kind: held }
    else { ...p, seen: false, progressed: false, affirmed: false, empty: empty, stalled: stalled, declared: declared,
      exit: if (clear) 0 else exit,
      // A declaration at the onset count relabels any held suspicion before its exit is judged.
      kind: if (held != "Alive") (if (declares) "Declared" else if (clear) (if (held == "Silent" and stalled >= 3) "Gray" else "Alive") else held)
            else if (suspect) (if (declares) "Declared" else if (empty >= 3) "Silent" else "Gray") else "Alive",
      since: if (held == "Alive" and suspect) t else p.since }
  }
  action commit(p: Peer, reading: str, t: int, v: Set[str], done: bool): bool = all {
    turn < BOUND, peer' = p, prior' = peer, now' = t, reported' = reading, votes' = v, nominated' = done,
    turn' = cap(turn + 1, 50),
  }
  action init = all {
    peer' = fresh, prior' = fresh, reported' = "Alive", now' = 0, votes' = Set(), nominated' = false, turn' = 0,
    ev' = { act: "init", res: "Alive", seq: 0, progress: 0, healthy: true, observed: false, exhausted: false, evidence: ready, who: "" },
  }
  action beat(seq: int, progress: int, healthy: bool): bool = {
    val merged = heartbeat(peer, seq, progress, healthy)
    all { commit(merged, reported, now, votes, nominated),
    ev' = { ...ev, act: "beat", res: if (seq <= peer.seq) "Duplicate" else "Heartbeat", seq: seq, progress: progress, healthy: healthy },
  }}
  /// One heartbeat per window from a sender reporting itself unhealthy with flat counters, numbered above every
  /// admitted one. The stored sequence stays, so the schedule's state space stays finite.
  action declare: bool = {
    val merged = heartbeat(peer, peer.seq + 1, 0, false)
    all { not(peer.seen), commit({ ...merged, seq: peer.seq }, reported, now, votes, nominated),
    ev' = { ...ev, act: "beat", res: "Heartbeat", seq: peer.seq + 1, progress: 0, healthy: false },
  }}
  action closeWindow(observed: bool, exhausted: bool): bool = {
    val t = cap(now + 1, 10)
    val merged = window(peer, t, observed)
    val reading = if (exhausted) "Unknown" else if (merged.empty >= 3 and merged.kind != "Alive") "Silent"
      else if (merged.kind == "Declared" and not(declaring(peer))) "Gray" else merged.kind
    all { commit(merged, reading, t, votes, nominated),
    ev' = { ...ev, act: "window", res: reading, observed: observed, exhausted: exhausted },
  }}
  action probe(who: str): bool = all {
    not(Set("Alive", "Unknown").contains(reported)), not(votes.contains(who)),
    commit(peer, reported, now, votes.union(Set(who)), nominated),
    ev' = { ...ev, act: "probe", res: "Dead", who: who },
  }
  action nominate(who: str, e: Evidence): bool = {
    val res = verdict(e, { ...peer, kind: reported })
    all { commit(peer, reported, now, votes, nominated or res == "Nominate"),
    ev' = { ...ev, act: "nominate", res: res, evidence: e, who: who },
  }}
  action retrack = all { peer.generation == 1,
    commit({ ...fresh, generation: 2, trackedSince: now, seq: peer.seq, progress: peer.progress }, "Alive", now, Set(), nominated),
    ev' = { ...ev, act: "retrack", res: "Retracked" },
  }
  action step = any {
    closeWindow(true, false), closeWindow(false, false), closeWindow(true, true),
    nondet seq = Set(0, 1, 2, 3, 4).oneOf()
    nondet progress = Set(0, 1, 2).oneOf()
    nondet healthy = Set(true, false).oneOf()
    beat(seq, progress, healthy), probe("a"), probe("b"),
    // The local kind, the counted vote kinds and a second observer class vary independently.
    nondet grayVotes = Set(true, false).oneOf()
    nondet declaredVotes = Set(true, false).oneOf()
    nondet second = Set(true, false).oneOf()
    nominate("a", { ...ready, dead: votes.size(), answers: votes.size(), grayVotes: grayVotes, declaredVotes: declaredVotes, second: second }),
    retrack,
  }
  action fixedStep = any {
    closeWindow(true, false), probe("a"), probe("b"),
    nominate("a", { ...ready, dead: votes.size(), answers: votes.size() }),
  }
  val GrayPreserved = ev.act == "beat" and ev.progress <= prior.progress and prior.kind == "Gray" implies peer.kind == "Gray"
  val DuplicateChangesNothing = ev.act == "beat" and ev.seq <= prior.seq implies peer == prior
  /// A gap keeps the empty, stalled and declared counts and the suspicion's kind, except that a healthy heartbeat it
  /// admitted ends the declared count and turns a declared suspicion gray.
  val GapUnobserved = ev.act == "window" and not(ev.observed) implies peer.empty == prior.empty and peer.stalled == prior.stalled
    and peer.declared == (if (prior.affirmed) 0 else prior.declared)
    and peer.kind == (if (prior.kind == "Declared" and prior.affirmed) "Gray" else prior.kind)
  /// A gray suspicion stays suspected through a window without progress: gray, or declared at the onset count.
  val GrayExitNeedsProgress = ev.act == "window" and prior.kind == "Gray" and not(prior.progressed)
    implies peer.kind == "Gray" or (peer.kind == "Declared" and peer.declared >= 3 and declaring(prior))
  /// An observed window that admitted a healthy heartbeat neither starts nor keeps a declared suspicion, nor reads one.
  val HealthyWindowNeverDeclares = ev.act == "window" and ev.observed and prior.affirmed implies peer.kind != "Declared" and reported != "Declared"
  /// A declared suspicion starts only in a declaring window at three windows that admitted a heartbeat with no
  /// healthy one since the last healthy heartbeat.
  val DeclaredNeedsOnsetCount = ev.act == "window" and peer.kind == "Declared" and prior.kind != "Declared"
    implies peer.declared >= 3 and declaring(prior)
  /// A declared reading comes only from a window that admitted a heartbeat and no healthy one.
  val DeclaredReadingIsFresh = ev.act == "window" and reported == "Declared" implies declaring(prior)
  /// An observed window whose every heartbeat reports the sender unhealthy keeps a silent suspicion and its exit
  /// count, or relabels the suspicion declared at the onset count.
  val UnhealthyWindowKeepsSilentExit = ev.act == "window" and ev.observed and prior.kind == "Silent" and declaring(prior)
    implies (peer.kind == "Silent" and peer.exit == prior.exit) or (peer.kind == "Declared" and peer.declared >= 3)
  /// A nomination under a gray local kind or a counted gray vote has votes of a second observer class.
  val GrayNominationHasSecondClass = ev.act == "nominate" and ev.res == "Nominate" and (reported == "Gray" or ev.evidence.grayVotes) implies ev.evidence.second
  val safety = GrayExitNeedsProgress and GrayPreserved and DuplicateChangesNothing and GapUnobserved and HealthyWindowNeverDeclares
    and DeclaredNeedsOnsetCount and DeclaredReadingIsFresh and GrayNominationHasSecondClass and UnhealthyWindowKeepsSilentExit
  /// Under `fixedStep`, which schedules only observed windows, both probes and nomination, a peer that sends no
  /// heartbeat is eventually nominated given weak fairness of each of those actions.
  temporal progress = and {
    weakFair(closeWindow(true, false), (peer, prior, now, votes, nominated, turn, ev, reported)),
    weakFair(probe("a"), (peer, prior, now, votes, nominated, turn, ev, reported)), weakFair(probe("b"), (peer, prior, now, votes, nominated, turn, ev, reported)),
    weakFair(nominate("a", { ...ready, dead: votes.size(), answers: votes.size() }), (peer, prior, now, votes, nominated, turn, ev, reported)),
  } implies eventually(nominated)
  /// The evidence of DEAD votes of one observer class, each reading a declared hold.
  val oneClass: Evidence = { ...ready, dead: votes.size(), answers: votes.size(), declaredVotes: true, second: false }
  action declaredWindow = all { peer.seen, closeWindow(true, false) }
  /// Under `declareStep` the sender reports itself unhealthy in the one heartbeat of every window.
  action declareStep = any { declare, declaredWindow, probe("a"), probe("b"), nominate("a", oneClass) }
  /// Under `declareStep`, a peer that declares itself held in every window is eventually nominated on DEAD votes of
  /// one observer class, given weak fairness of each of its actions.
  temporal declaredProgress = and {
    weakFair(declare, (peer, prior, now, votes, nominated, turn, ev, reported)),
    weakFair(declaredWindow, (peer, prior, now, votes, nominated, turn, ev, reported)),
    weakFair(probe("a"), (peer, prior, now, votes, nominated, turn, ev, reported)),
    weakFair(probe("b"), (peer, prior, now, votes, nominated, turn, ev, reported)),
    weakFair(nominate("a", oneClass), (peer, prior, now, votes, nominated, turn, ev, reported)),
  } implies eventually(nominated)
  val witnessRetracked = ev.act == "retrack"
  val witnessHeartbeat = ev.res == "Heartbeat"
  val witnessDuplicate = ev.res == "Duplicate"
  val witnessSilent = ev.act == "window" and ev.res == "Silent"
  val witnessGray = ev.act == "window" and ev.res == "Gray"
  val witnessUnknownWindow = ev.act == "window" and ev.res == "Unknown"
  val witnessAliveWindow = ev.act == "window" and ev.res == "Alive"
  val witnessGap = ev.act == "window" and not(ev.observed)
  val witnessProbe = ev.act == "probe"
  val witnessNominate = ev.res == "Nominate"
  val witnessDeclared = ev.act == "window" and ev.res == "Declared"
  val witnessDeclaredAged = ev.act == "window" and ev.res == "Gray" and peer.kind == "Declared"
  val witnessDeclaredDemoted = ev.act == "window" and prior.kind == "Declared" and peer.kind == "Gray"
  val witnessGrayPromoted = ev.act == "window" and prior.kind == "Gray" and peer.kind == "Declared"
  val witnessSilentExitAcrossUnhealthy = ev.act == "window" and prior.kind == "Silent" and peer.kind == "Alive" and prior.declared > 0
  val witnessDeclaredNominate = ev.res == "Nominate" and reported == "Declared" and not(ev.evidence.second)
  val witnessGrayKindDeclaredVotes = ev.res == "GrayNeedsSecondClass" and reported == "Gray" and ev.evidence.declaredVotes and not(ev.evidence.grayVotes)
  val witnessDeclaredKindGrayVotes = ev.res == "GrayNeedsSecondClass" and reported == "Declared" and ev.evidence.grayVotes and ev.evidence.declaredVotes
}
