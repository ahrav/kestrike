/// The rearmable watchdog worker of one recovery watch: one worker, a deadline of two ticks and a clock the
/// environment advances. Each step is one owner call (`rearm`, `disarm`), one silent clock advance (`pass`) or
/// one clock advance that wakes the worker (`wake`). The worker reads the clock only when woken, and a wake
/// runs it to its next wait or to its one containment request.
module watchdog {
  const BOUND: int
  type Event = {act: str, res: str, dt: int}
  type State = {
    now: int, armed: int, expired: bool, contained: int, ended: bool, waits: int, wait: int,
    armedAt: int, arms: int, idleContained: bool, early: bool, rearmedExpired: bool, ev: Event
  }
  var st: State
  var turn: int
  pure val DEADLINE = 2
  pure val IDLE = -1
  pure val UNBOUNDED = -1
  pure def event(act: str, res: str, dt: int): Event = {act: act, res: res, dt: dt}
  /// The worker's pass after a wake: an ended worker does nothing, an idle one waits without bound, a running
  /// deadline that passed on the clock expires and asks to contain, and any other waits for the remainder.
  pure def woken(s: State): State =
    if (s.ended) s
    else if (s.armed == IDLE) {...s, waits: s.waits + 1, wait: UNBOUNDED}
    else if (s.now - s.armed >= DEADLINE)
      {...s, expired: true, ended: true, contained: s.contained + 1,
        idleContained: s.idleContained or s.armed == IDLE, early: s.early or s.now - s.armedAt < DEADLINE}
    else {...s, waits: s.waits + 1, wait: DEADLINE - (s.now - s.armed)}
  action init = all {
    st' = {now: 0, armed: IDLE, expired: false, contained: 0, ended: false, waits: 1, wait: UNBOUNDED,
      armedAt: IDLE, arms: 0, idleContained: false, early: false, rearmedExpired: false, ev: event("init", "", 0)},
    turn' = 0
  }
  action tick = all {turn < BOUND, turn' = turn + 1}
  action rearm = all {tick, st.expired or st.armed == IDLE,
    st' = if (st.expired) {...st, ev: event("rearm", "Refused", 0)}
      else woken({...st, armed: st.now, armedAt: st.now, arms: st.arms + 1,
        rearmedExpired: st.rearmedExpired or st.expired, ev: event("rearm", "Armed", 0)})
  }
  action disarm = all {tick,
    st' = {...st, armed: IDLE, ev: event("disarm", if (st.expired) "Expired" else "Running", 0)}
  }
  action pass(dt: int): bool = all {tick, dt > 0,
    st' = {...st, now: st.now + dt, ev: event("pass", "Passed", dt)}
  }
  action wake(dt: int): bool = {
    val after = woken({...st, now: st.now + dt})
    val res = if (st.ended) "Ended" else if (after.ended) "Contained" else if (after.wait == UNBOUNDED) "Idle" else "Waiting"
    all {tick, st' = {...after, ev: event("wake", res, dt)}}
  }
  val ContainsAtMostOnce = st.contained <= 1
  val IdleNeverContains = not(st.idleContained)
  val DeadlineFromOwnArm = not(st.early)
  val ExpiredRefusesRearm = not(st.rearmedExpired)
  val WorkerOutlivesDisarm = st.ended implies st.expired
  val safety = ContainsAtMostOnce and IdleNeverContains and DeadlineFromOwnArm and ExpiredRefusesRearm and
    WorkerOutlivesDisarm
  val witnessArmed = st.ev.res == "Armed"
  val witnessRefused = st.ev.res == "Refused"
  val witnessRunning = st.ev.res == "Running"
  val witnessExpiredDisarm = st.ev.res == "Expired"
  val witnessPassed = st.ev.res == "Passed"
  val witnessIdle = st.ev.res == "Idle"
  val witnessWaiting = st.ev.res == "Waiting"
  val witnessPartial = st.ev.res == "Waiting" and st.wait < DEADLINE
  val witnessContained = st.ev.res == "Contained"
  val witnessEnded = st.ev.res == "Ended"
  val witnessSecondEpisode = st.ev.res == "Armed" and st.arms == 2
  val witnessDisarmWinsRace = st.ev.res == "Running" and st.armedAt != IDLE and st.now - st.armedAt >= DEADLINE
  val witnessIdlePastDeadline = st.ev.res == "Idle" and st.now >= DEADLINE
  action step = {
    nondet dt = Set(0, 1, 2, 3).oneOf()
    any {rearm, disarm, pass(dt), wake(dt)}
  }
}
