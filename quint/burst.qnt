/// The transmit custody of one burst transport over one device queue pair: a header pool of eight buffers,
/// one chain per datagram, at most two datagrams per send. Each step is one call of the transport or the
/// device's return of the chains it holds.
module burst {
  const BOUND: int
  type Event = {act: str, res: str, n: int}
  type Args = {n: int, k: int, unc: str, reset: bool, proven: bool, restart: str, again: bool}
  type State = {
    link: str, held: int, dev: int, quar: str, gone: bool,
    sent: int, quarantined: int, returned: int, released: int, resets: int, recoveries: int,
    admittedPoisoned: bool, unprovenReleased: bool, ev: Event, arg: Args
  }
  var st: State
  var turn: int
  pure val CAP = 8
  pure val BATCHES = Set(1, 2)
  pure val ACCEPTS = Set(0, 1, 2)
  pure val UNCERTAIN = Set("no", "kept", "untaken", "freed")
  pure val RESTARTS = Set("ok", "stale", "fail")
  pure val NONE: Args = {n: 0, k: 0, unc: "", reset: false, proven: false, restart: "", again: false}
  pure def event(act: str, res: str, n: int): Event = {act: act, res: res, n: n}
  pure def untaken(s: State): int = if (s.quar == "untaken") 1 else 0
  /// The state a proven stop leaves: the device returned every chain it held and the quarantine settled once.
  pure def stopped(s: State): State = {...s, held: s.held - s.dev - untaken(s), dev: 0, quar: "none",
    returned: s.returned + (if (s.quar == "kept" or s.quar == "returned") 1 else 0),
    released: s.released + untaken(s)}
  /// Whether `after` differs from `before` in what an unproven stop must keep.
  pure def moved(before: State, after: State): bool =
    after.held != before.held or after.dev != before.dev or after.quar != before.quar
  action init = all {
    st' = {link: "Up", held: 0, dev: 0, quar: "none", gone: false,
      sent: 0, quarantined: 0, returned: 0, released: 0, resets: 0, recoveries: 0,
      admittedPoisoned: false, unprovenReleased: false, ev: event("init", "", 0), arg: NONE},
    turn' = 0
  }
  action tick = all {turn < BOUND, turn' = turn + 1}
  action send(n: int, k: int, unc: str): bool = {
    val accepted = if (k < n) k else n
    val uncertain = unc != "no" and accepted < n
    val charged = if (uncertain and unc != "freed") 1 else 0
    val kept = if (uncertain and unc == "kept") 1 else 0
    val after = if (st.gone) {...st, ev: event("send", "Gone", 0)}
      else if (st.link != "Up") {...st, ev: event("send", "Closed", 0)}
      else if (st.quar != "none") {...st, ev: event("send", "Poisoned", 0)}
      else {...st, held: st.held + accepted + charged, dev: st.dev + accepted + kept,
        quar: if (not(uncertain)) st.quar else if (unc == "freed") "returned" else unc,
        sent: st.sent + accepted, quarantined: st.quarantined + (if (uncertain) 1 else 0),
        admittedPoisoned: st.admittedPoisoned or st.quar != "none",
        ev: event("send", if (uncertain) "Uncertain" else "Sent", accepted)}
    all {tick, st.held + n <= CAP, st' = {...after, arg: {...NONE, n: n, k: k, unc: unc}}}
  }
  action complete = all {tick,
    st' = if (st.gone) {...st, ev: event("complete", "Gone", 0), arg: NONE}
      else if (st.dev == 0) {...st, ev: event("complete", "Idle", 0), arg: NONE}
      else {...st, held: st.held - st.dev, dev: 0, quar: if (st.quar == "kept") "returned" else st.quar,
        ev: event("complete", "Returned", st.dev), arg: NONE}
  }
  action reclaim(reset: bool, proven: bool, restart: str, again: bool): bool = {
    val settled = {...stopped(st), resets: st.resets + 1}
    val recovers = not(st.gone) and st.link == "Up" and (reset or st.quar != "none")
    val after = if (st.gone) {...st, ev: event("reclaim", "Gone", 0)}
      else if (st.link != "Up") {...st, ev: event("reclaim", "Closed", 0)}
      else if (not(recovers)) {...st, ev: event("reclaim", "Cleanup", 0)}
      else if (not(proven)) {...st, resets: st.resets + 1, link: "Lost", ev: event("reclaim", "Lost", 0)}
      else if (restart == "ok") {...settled, recoveries: st.recoveries + 1, ev: event("reclaim", "Recovered", 0)}
      else if (again) {...settled, link: "Down", ev: event("reclaim", "Down", 0)}
      else {...settled, link: "Lost", ev: event("reclaim", "LostAfterRestart", 0)}
    all {tick,
      st' = {...after, arg: {...NONE, reset: reset, proven: proven, restart: restart, again: again},
        unprovenReleased: st.unprovenReleased or
          (recovers and not(proven) and (moved(st, after) or after.link != "Lost"))}
    }
  }
  action close(proven: bool): bool = {
    val after = if (st.gone) {...st, ev: event("close", "Gone", 0)}
      else if (st.quar == "none") {...st, gone: true, ev: event("close", "Handed", 0)}
      else if (proven) {...stopped(st), gone: true, ev: event("close", "Settled", 0)}
      else {...st, gone: true, ev: event("close", "Unsettled", 0)}
    all {tick,
      st' = {...after, arg: {...NONE, proven: proven},
        unprovenReleased: st.unprovenReleased or
          (not(st.gone) and st.quar != "none" and not(proven) and moved(st, after))}
    }
  }
  val HeldUntilProvenStop = st.dev >= 0 and st.held >= st.dev + untaken(st)
  val UncertainPoisons = not(st.admittedPoisoned)
  val UnprovenStopKeepsHeld = not(st.unprovenReleased)
  val safety = HeldUntilProvenStop and UncertainPoisons and UnprovenStopKeepsHeld
  val witnessSent = st.ev.res == "Sent" and st.ev.n > 0
  val witnessRingFull = st.ev.res == "Sent" and st.ev.n == 0
  val witnessUncertainKept = st.ev.res == "Uncertain" and st.quar == "kept"
  val witnessUncertainUntaken = st.ev.res == "Uncertain" and st.quar == "untaken"
  val witnessUncertainFreed = st.ev.res == "Uncertain" and st.quar == "returned"
  val witnessPoisoned = st.ev.res == "Poisoned"
  val witnessSendClosed = st.ev.act == "send" and st.ev.res == "Closed"
  val witnessReturned = st.ev.res == "Returned"
  val witnessReturnedQuarantine = st.ev.res == "Returned" and st.quar == "returned"
  val witnessIdle = st.ev.res == "Idle"
  val witnessReclaimClosed = st.ev.act == "reclaim" and st.ev.res == "Closed"
  val witnessCleanup = st.ev.res == "Cleanup"
  val witnessLost = st.ev.res == "Lost"
  val witnessLostHolding = st.ev.res == "Lost" and st.dev > 0 and st.quar == "untaken"
  val witnessRecovered = st.ev.res == "Recovered"
  val witnessRecoveredReleased = st.ev.res == "Recovered" and st.released == 1
  val witnessRecoveredReturned = st.ev.res == "Recovered" and st.returned == 1
  val witnessDown = st.ev.res == "Down"
  val witnessLostAfterRestart = st.ev.res == "LostAfterRestart"
  val witnessHanded = st.ev.res == "Handed"
  val witnessSettled = st.ev.res == "Settled"
  val witnessSettledLost = st.ev.res == "Settled" and st.link == "Lost"
  val witnessUnsettled = st.ev.res == "Unsettled"
  val witnessGone = st.ev.res == "Gone"
  action step = {
    nondet n = BATCHES.oneOf()
    nondet k = ACCEPTS.oneOf()
    nondet unc = UNCERTAIN.oneOf()
    nondet reset = Set(false, true).oneOf()
    nondet proven = Set(false, true).oneOf()
    nondet restart = RESTARTS.oneOf()
    nondet again = Set(false, true).oneOf()
    any {send(n, k, unc), complete, reclaim(reset, proven, restart, again), close(proven)}
  }
}
