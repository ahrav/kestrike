/// One burst transport's quiesced recovery under its watchdog: at most one quarantined chain, the stages of one
/// episode in order, and a stall that expires the watchdog inside one stage. Each step is one call of the
/// transport or the device's return of the chains it holds.
module episode {
  const BOUND: int
  const ARMABLE: bool
  type Event = {act: str, res: str}
  type Episode = {n: int, reached: str, expiredAt: str, requested: bool, refused: bool}
  type State = {
    link: str, held: int, dev: int, quar: str, gone: bool, armable: bool, contained: bool,
    returned: int, released: int, resets: int, recoveries: int, requests: int, ep: Episode, log: List[str],
    expiredSettled: bool, containedStopped: bool, ev: Event
  }
  var st: State
  var turn: int
  pure val CAP = 8
  pure val UNCERTAIN = Set("no", "kept", "untaken")
  pure val STALLS = Set("none", "Stop", "Recheck", "Reset", "Reinitialize", "Restart", "Stop2")
  pure val RESTARTS = Set("ok", "stale", "fail")
  pure val IDLE: Episode = {n: 0, reached: "", expiredAt: "", requested: false, refused: false}
  pure val FULL = List("Stop", "Recheck", "Reset", "Reinitialize", "Restart")
  pure def event(act: str, res: str): Event = {act: act, res: res}
  pure def untaken(s: State): int = if (s.quar == "untaken") 1 else 0
  /// The state a proven stop leaves once the quarantine settled: the device returned every chain it held.
  pure def stopped(s: State): State = {...s, held: s.held - s.dev - untaken(s), dev: 0, quar: "none",
    returned: s.returned + (if (s.quar == "kept" or s.quar == "returned") 1 else 0),
    released: s.released + untaken(s)}
  /// The state a proven stop leaves before anything settles: the device returned every chain it held.
  pure def returnedOnly(s: State): State =
    {...s, held: s.held - s.dev, dev: 0, quar: if (s.quar == "kept") "returned" else s.quar}
  /// An episode whose watchdog expired inside stage `at`, the last of `log`.
  pure def expired(s: State, at: str, log: List[str]): State = {...s, link: "Lost", contained: true,
    requests: s.requests + 1, ep: {n: s.resets, reached: at, expiredAt: at, requested: true, refused: false},
    log: log, ev: event("reclaim", "Expired")}
  /// An episode that disarmed its watchdog after `reached`, the last of `log`.
  pure def ended(s: State, link: str, reached: str, log: List[str], res: str): State = {...s, link: link,
    ep: {n: s.resets, reached: reached, expiredAt: "", requested: false, refused: false},
    log: log, ev: event("reclaim", res)}
  /// The second stop, after a failed restart whose stages were `log`.
  pure def second(s: State, log: List[str], stall: str, again: bool): State =
    if (stall == "Stop2") expired(s, "Stop", log.append("Stop"))
    else if (again) ended(s, "Down", "Stop", log.append("Stop"), "Down")
    else ended(s, "Lost", "Stop", log.append("Stop"), "LostAfterRestart")
  action init = all {
    st' = {link: "Up", held: 0, dev: 0, quar: "none", gone: false, armable: ARMABLE, contained: false,
      returned: 0, released: 0, resets: 0, recoveries: 0, requests: 0, ep: IDLE, log: List(),
      expiredSettled: false, containedStopped: false, ev: event("init", "")},
    turn' = 0
  }
  action tick = all {turn < BOUND, turn' = turn + 1}
  action send(unc: str): bool = {
    val after = if (st.gone) {...st, ev: event("send", "Gone")}
      else if (st.link != "Up") {...st, ev: event("send", "Closed")}
      else if (st.quar != "none") {...st, ev: event("send", "Poisoned")}
      else if (unc == "no") {...st, held: st.held + 1, dev: st.dev + 1, ev: event("send", "Sent")}
      else {...st, held: st.held + 2, dev: st.dev + (if (unc == "kept") 2 else 1), quar: unc,
        ev: event("send", "Uncertain")}
    all {tick, st.held + 2 <= CAP, st' = {...after, log: List()}}
  }
  action complete = all {tick,
    st' = if (st.gone) {...st, log: List(), ev: event("complete", "Gone")}
      else if (st.dev == 0) {...st, log: List(), ev: event("complete", "Idle")}
      else {...returnedOnly(st), log: List(), ev: event("complete", "Returned")}
  }
  action reclaim(reset: bool, stall: str, proven: bool, restart: str, again: bool): bool = {
    val recovers = not(st.gone) and st.link == "Up" and (reset or st.quar != "none")
    val base = {...st, resets: st.resets + 1}
    val settled = stopped(base)
    val after = if (st.gone) {...st, log: List(), ev: event("reclaim", "Gone")}
      else if (st.link != "Up") {...st, log: List(), ev: event("reclaim", "Closed")}
      else if (not(recovers)) {...st, log: List(), ev: event("reclaim", "Cleanup")}
      else if (not(st.armable)) {...base, link: "Lost", ep: {...IDLE, n: base.resets, refused: true},
        log: List(), ev: event("reclaim", "Refused")}
      else if (stall == "Stop") expired(if (proven) returnedOnly(base) else base, "Stop", FULL.slice(0, 1))
      else if (not(proven)) ended(base, "Lost", "Stop", FULL.slice(0, 1), "Lost")
      else if (stall == "Recheck") expired(settled, "Recheck", FULL.slice(0, 2))
      else if (restart == "stale") second(settled, FULL.slice(0, 2), stall, again)
      else if (stall == "Reset") expired(settled, "Reset", FULL.slice(0, 3))
      else if (stall == "Reinitialize") expired(settled, "Reinitialize", FULL.slice(0, 4))
      else if (stall == "Restart") expired(settled, "Restart", FULL)
      else if (restart == "fail") second(settled, FULL, stall, again)
      else {...ended(settled, "Up", "Restart", FULL, "Recovered"), recoveries: st.recoveries + 1}
    all {tick,
      st' = {...after,
        expiredSettled: st.expiredSettled or (recovers and st.armable and stall == "Stop" and
          (after.returned != st.returned or after.released != st.released or (after.quar == "none") != (st.quar == "none")))}
    }
  }
  action close(proven: bool): bool = {
    val after = if (st.gone) {...st, ev: event("close", "Gone")}
      else if (st.quar == "none" or st.contained) {...st, gone: true, ev: event("close", "Handed")}
      else if (proven) {...stopped(st), gone: true, ev: event("close", "Settled")}
      else {...st, gone: true, ev: event("close", "Unsettled")}
    all {tick,
      st' = {...after, log: List(),
        containedStopped: st.containedStopped or (not(st.gone) and st.contained and
          (after.held != st.held or after.dev != st.dev or after.quar != st.quar))}
    }
  }
  val ran = st.ev.act == "reclaim"
  val RefusedBeforeAnyStage = (ran and st.ev.res == "Refused") implies
    (st.log == List() and st.ep.refused and st.link == "Lost" and st.requests == 0)
  val NoStageAfterExpiry = (ran and st.ev.res == "Expired") implies
    (st.log.length() > 0 and st.log[st.log.length() - 1] == st.ep.expiredAt and st.ep.reached == st.ep.expiredAt)
  val ExpiryLosesLinkAndContainsOnce = st.requests <= 1 and ((ran and st.ev.res == "Expired") implies
    (st.link == "Lost" and st.ep.requested and st.requests == 1 and st.contained))
  val ExpiryKeepsQuarantine = not(st.expiredSettled) and not(st.containedStopped)
  val FaultFreeDisarms = (ran and st.ev.res == "Recovered") implies
    (st.link == "Up" and st.ep.expiredAt == "" and not(st.ep.requested) and st.ep.reached == "Restart" and
      st.log == FULL and st.requests == 0)
  val safety = RefusedBeforeAnyStage and NoStageAfterExpiry and ExpiryLosesLinkAndContainsOnce and
    ExpiryKeepsQuarantine and FaultFreeDisarms
  val witnessSent = st.ev.res == "Sent"
  val witnessUncertainKept = st.ev.res == "Uncertain" and st.quar == "kept"
  val witnessUncertainUntaken = st.ev.res == "Uncertain" and st.quar == "untaken"
  val witnessPoisoned = st.ev.res == "Poisoned"
  val witnessSendClosed = st.ev.act == "send" and st.ev.res == "Closed"
  val witnessReturned = st.ev.res == "Returned"
  val witnessIdle = st.ev.res == "Idle"
  val witnessReclaimClosed = ran and st.ev.res == "Closed"
  val witnessCleanup = st.ev.res == "Cleanup"
  val witnessRefused = st.ev.res == "Refused"
  val witnessLost = st.ev.res == "Lost"
  val witnessRecovered = st.ev.res == "Recovered"
  val witnessSecondEpisode = st.ev.res == "Recovered" and st.ep.n == 2
  val witnessDown = st.ev.res == "Down"
  val witnessDownStale = st.ev.res == "Down" and st.log.length() == 3
  val witnessLostAfterRestart = st.ev.res == "LostAfterRestart"
  val witnessExpiredStop = st.ev.res == "Expired" and st.log == FULL.slice(0, 1)
  val witnessExpiredStopProvenQuarantine = st.ev.res == "Expired" and st.log == FULL.slice(0, 1) and st.dev == 0 and
    st.quar != "none"
  val witnessExpiredRecheck = st.ev.res == "Expired" and st.ep.expiredAt == "Recheck"
  val witnessExpiredReset = st.ev.res == "Expired" and st.ep.expiredAt == "Reset"
  val witnessExpiredReinitialize = st.ev.res == "Expired" and st.ep.expiredAt == "Reinitialize"
  val witnessExpiredRestart = st.ev.res == "Expired" and st.ep.expiredAt == "Restart"
  val witnessExpiredSecondStop = st.ev.res == "Expired" and st.ep.expiredAt == "Stop" and st.log.length() > 1
  val witnessExpiredLaterEpisode = st.ev.res == "Expired" and st.ep.n == 2
  val witnessHanded = st.ev.res == "Handed"
  val witnessHandedContained = st.ev.res == "Handed" and st.contained and st.quar != "none"
  val witnessSettled = st.ev.res == "Settled"
  val witnessSettledRefused = st.ev.res == "Settled" and st.ep.refused
  val witnessUnsettled = st.ev.res == "Unsettled"
  val witnessGone = st.ev.res == "Gone"
  action step = {
    nondet unc = UNCERTAIN.oneOf()
    nondet reset = Set(false, true).oneOf()
    nondet stall = STALLS.oneOf()
    nondet proven = Set(false, true).oneOf()
    nondet restart = RESTARTS.oneOf()
    nondet again = Set(false, true).oneOf()
    any {send(unc), complete, reclaim(reset, stall, proven, restart, again), close(proven)}
  }
}
