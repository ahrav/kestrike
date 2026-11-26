/// The attach gate of one volume under a serving machine that holds the tenure's token before the fencing
/// boundary: Register, Acquire and Report, one reservation command at a time. Each step is one poll of the
/// volume, one gate command's completion, one serving-machine event or the Report's deadline. The gate passes
/// only on a Report that shows the own pair as the one holder and the one registrant of a type-2 reservation.
module gate {
  const BOUND: int
  type Event = {act: str, res: str}
  type State = {
    step: int, pending: bool, outcome: str, failed: int, lost: bool, machine: str, flip: bool, sent: int,
    admissions: int, medium: bool, ready: str, sole: bool, ev: Event
  }
  var st: State
  var turn: int
  pure val REGISTER = 0
  pure val ACQUIRE = 1
  pure val REPORT = 2
  /// The Report views: the own pair alone and holding; a foreign registrant; a foreign holder; a reservation of
  /// another type; a second record of the own host ID; the own pair registered and not holding; bytes the driver
  /// withholds; a failed status; a deposing status.
  pure val VIEWS = Set("sole", "registrant", "holder", "type", "duplicate", "notholder", "withheld", "failed", "deposing")
  /// The submit refusals: none, a full queue, a refusal that fails the command, and the device's loss, which
  /// keeps the attach bootstrapping and withdraws fill admission.
  pure val REFUSALS = Set("none", "busy", "invalid", "gone")
  pure def event(act: str, res: str): Event = {act: act, res: res}
  /// The gate runs: no outcome, the device present and the machine before the boundary.
  pure def running(s: State): bool = s.outcome == "" and not(s.lost)
  /// A refusal ends the attach: the outcome, with fill admission withdrawn.
  pure def refused(s: State, outcome: str, act: str): State =
    {...s, pending: false, outcome: outcome, ready: "withheld", ev: event(act, outcome)}
  action init = all {
    st' = {step: REGISTER, pending: false, outcome: "", failed: -1, lost: false, machine: "pre", flip: false, sent: 0,
      admissions: 0, medium: false, ready: "detached", sole: false, ev: event("init", "")},
    turn' = 0
  }
  action count = all {turn < BOUND, turn' = turn + 1}
  /// One poll: the volume submits the gate's next command, and the driver accepts it or returns `refusal`.
  action tick(refusal: str): bool = all {count,
    st' = if (not(running(st)) or st.pending) {...st, ev: event("tick", "idle")}
      else if (refusal == "none") {...st, pending: true, sent: st.sent + 1, ev: event("tick", "submitted")}
      else if (refusal == "busy") {...st, ev: event("tick", "busy")}
      else if (refusal == "gone") {...st, lost: true, ready: "withheld", ev: event("tick", "lost")}
      else {...refused(st, "command", "tick"), failed: st.step}
  }
  /// The Register completes: a conflict is a deposing status, which also withdraws the machine with no flip request.
  action register(ok: bool): bool = all {count, running(st), st.pending, st.step == REGISTER,
    st' = if (ok) {...st, step: ACQUIRE, pending: false, ev: event("register", "ok")}
      else {...refused(st, "command", "register"), failed: REGISTER, machine: "withdrawn"}
  }
  /// The Acquire completes: a conflict is a deposing status, which also withdraws the machine with no flip request.
  action acquire(ok: bool): bool = all {count, running(st), st.pending, st.step == ACQUIRE,
    st' = if (ok) {...st, step: REPORT, pending: false, ev: event("acquire", "ok")}
      else {...refused(st, "command", "acquire"), failed: ACQUIRE, machine: "withdrawn"}
  }
  /// The Report completes with `view`. The sole view passes the gate: the driver admits medium commands once, the
  /// machine crosses the boundary, the readiness word loads and the bootstrap submits its first medium command.
  /// Retirement evidence withdraws the machine with the flip request; a deposing status withdraws it with none.
  action report(view: str): bool = all {count, running(st), st.pending, st.step == REPORT,
    st' = if (view == "sole") {...st, pending: false, outcome: "fenced", machine: "recovering", admissions: st.admissions + 1,
        medium: true, ready: "loading", sole: true, ev: event("report", "fenced")}
      else if (view == "failed") {...refused(st, "command", "report"), failed: REPORT}
      else if (view == "deposing") {...refused(st, "authority", "report"), machine: "withdrawn"}
      else if (view == "withheld") refused(st, "unreadable", "report")
      else if (view == "duplicate") refused(st, "duplicate", "report")
      else {...refused(st, view, "report"), machine: "withdrawn", flip: true}
  }
  /// The serving window expires while the gate runs.
  action expire = all {count, running(st),
    st' = refused(st, "authority", "expire")
  }
  /// The serving machine withdraws for a retirement trigger, with the flip request, while the gate runs.
  action withdraw = all {count, running(st),
    st' = {...refused(st, "authority", "withdraw"), machine: "withdrawn", flip: true}
  }
  /// The serving machine closes while the gate runs.
  action close = all {count, running(st),
    st' = {...refused(st, "authority", "close"), machine: "closed"}
  }
  /// The gate's Report passes its deadline.
  action timeout = all {count, running(st), st.pending, st.step == REPORT,
    st' = refused(st, "authority", "timeout")
  }
  val NoMediumBeforeTheGate = st.medium implies st.outcome == "fenced"
  val PassNeedsTheSoleReport = st.outcome == "fenced" implies (st.sole and st.sent == 3)
  val AdmitsExactlyOnce = st.admissions == (if (st.outcome == "fenced") 1 else 0)
  val RefusalEndsWithNoMedium = (st.outcome != "" and st.outcome != "fenced") implies
    (not(st.medium) and st.admissions == 0 and st.ready == "withheld")
  val LoadingOnlyAfterTheGate = st.ready == "loading" implies st.outcome == "fenced"
  val safety = NoMediumBeforeTheGate and PassNeedsTheSoleReport and AdmitsExactlyOnce and RefusalEndsWithNoMedium and
    LoadingOnlyAfterTheGate
  val witnessSubmitted = st.ev.res == "submitted"
  val witnessBusy = st.ev.res == "busy"
  val witnessLost = st.ev.res == "lost"
  val witnessIdle = st.ev.res == "idle"
  val witnessIdleAfterThePass = st.ev.res == "idle" and st.outcome == "fenced"
  val witnessSubmitRefused = st.ev.act == "tick" and st.ev.res == "command"
  val witnessRegistered = st.ev.act == "register" and st.ev.res == "ok"
  val witnessRegisterConflict = st.ev.act == "register" and st.ev.res == "command"
  val witnessAcquired = st.ev.act == "acquire" and st.ev.res == "ok"
  val witnessAcquireConflict = st.ev.act == "acquire" and st.ev.res == "command"
  val witnessFenced = st.ev.res == "fenced"
  val witnessForeignRegistrant = st.ev.res == "registrant"
  val witnessForeignHolder = st.ev.res == "holder"
  val witnessOtherType = st.ev.res == "type"
  val witnessDuplicate = st.ev.res == "duplicate"
  val witnessNotHolder = st.ev.res == "notholder"
  val witnessWithheld = st.ev.res == "unreadable"
  val witnessReportFailed = st.ev.act == "report" and st.ev.res == "command"
  val witnessReportDeposed = st.ev.act == "report" and st.ev.res == "authority"
  val witnessExpired = st.ev.act == "expire"
  val witnessExpiredUnderACommand = st.ev.act == "expire" and st.sent > 0 and st.step < REPORT
  val witnessWithdrawn = st.ev.act == "withdraw"
  val witnessClosed = st.ev.act == "close"
  val witnessTimedOut = st.ev.act == "timeout"
  action step = {
    nondet refusal = REFUSALS.oneOf()
    nondet ok = Set(true, false).oneOf()
    nondet view = VIEWS.oneOf()
    any {tick(refusal), register(ok), acquire(ok), report(view), expire, withdraw, close, timeout}
  }
}
