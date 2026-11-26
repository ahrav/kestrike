/// The store client's watermark over one shard record: one client process at a time, restarted from its durable
/// log, one other writer, and a store whose replies follow its contract or one of the kill arms. A record value `e`
/// stands for the record's `(g, E)` in its order: the attempt counter at the first generation, and ten plus the
/// attempt counter after the one flip. Version `v` of the record is the `v`-th committed value, up to four
/// versions. Each step is one client call, one store event or one host event.
module watermark {
  const BOUND: int
  type Mark = {ver: int, e: int}
  type Event = {act: str, res: str}
  /// The committed values, oldest first: version `v` holds `hist[v - 1]`.
  var hist: List[int]
  /// The watermark the client process checks results against; version 0 stands for no mark.
  var mark: Mark
  /// The watermark the host's log holds.
  var logMark: Mark
  var logFails: bool
  var withdrawn: bool
  /// The value the client's last acknowledged read or bump returned; version 0 stands for none.
  var held: Mark
  /// Every value a call returned, with the mark the client held before the call.
  var adopted: Set[(Mark, Mark)]
  /// The calls that reached the store while the client was withdrawn.
  var late: int
  var ev: Event
  var turn: int
  pure val VERSIONS = 4
  pure val NONE: Mark = {ver: 0, e: 0}
  /// The value of the record a flip writes.
  pure val FLIPPED = 10
  def current: Mark = {ver: hist.length(), e: hist[hist.length() - 1]}
  /// Whether a result regresses below `m`: a lower version, a lower value, or the same version with another value.
  def below(r: Mark, m: Mark): bool = {
    val reused = r.ver == m.ver and r.e != m.e
    m.ver > 0 and (r.ver < m.ver or r.e < m.e or reused)
  }
  action init = all {
    hist' = [0], mark' = NONE, logMark' = NONE, logFails' = false, withdrawn' = false, held' = NONE,
    adopted' = Set(), late' = 0, ev' = {act: "init", res: ""}, turn' = 0
  }
  action tick = all {turn < BOUND, turn' = turn + 1}
  action unchangedStore = hist' = hist
  action unchangedHost = logFails' = logFails
  /// `late` after a call that reaches the store: the call counts when the client is withdrawn.
  def reached: int = if (withdrawn) late + 1 else late
  /// A call of a withdrawn client returns at the client and reaches no store.
  action refuseWithdrawn(act: str): bool = all {
    mark' = mark, logMark' = logMark, withdrawn' = withdrawn, held' = held, adopted' = adopted, late' = late,
    ev' = {act: act, res: "Withdrawn"}, unchangedStore, unchangedHost
  }
  /// The client takes the result `r` of a read or of its own acknowledged write: a regression withdraws it, and a
  /// raised mark is recorded in the log before the value returns; a failed record withdraws it.
  action take(act: str, r: Mark): bool = {
    val regresses = below(r, mark)
    val raised = not(regresses) and r != mark
    val logged = not(raised) or not(logFails)
    val refused = regresses or not(logged)
    val withdraws = refused
    all {
      mark' = if (regresses) mark else r,
      logMark' = if (raised and logged) r else logMark,
      withdrawn' = withdraws,
      held' = if (refused) held else r,
      adopted' = if (refused) adopted else adopted.union(Set((r, mark))),
      late' = reached, unchangedHost,
      ev' = {act: act, res: if (regresses) "Regression" else if (not(logged)) "Log" else "Ok"}
    }
  }
  /// A read that returns the record's current value.
  action readPass = all {
    tick,
    if (withdrawn) refuseWithdrawn("readPass") else all { take("readPass", current), unchangedStore }
  }
  /// A read that misses the last commit and returns the previous version.
  action readStale = all {
    tick, hist.length() >= 2,
    if (withdrawn) refuseWithdrawn("readStale")
    else all { take("readStale", {ver: hist.length() - 1, e: hist[hist.length() - 2]}), unchangedStore }
  }
  /// A read that returns no value.
  action readUnavailable = all {
    tick,
    if (withdrawn) refuseWithdrawn("readUnavailable") else all {
      mark' = mark, logMark' = logMark, withdrawn' = withdrawn, held' = held, adopted' = adopted, late' = reached,
      ev' = {act: "readUnavailable", res: "Unavailable"}, unchangedStore, unchangedHost
    }
  }
  /// The client's bump of the value it holds, an exact-version write expecting that value's version. `applies` is
  /// whether the store commits it and `acks` whether the store acknowledges a commit at the version after its
  /// current one. An acknowledged version at or below the mark, or other than the one after the expected version,
  /// is a regression.
  action bump(act: str, applies: bool, acks: bool): bool = {
    val acked = hist.length() + 1
    val result = {ver: acked, e: held.e + 1}
    val misreported = acked <= mark.ver or acked != held.ver + 1
    all {
      tick, held.ver > 0, hist.length() < VERSIONS,
      if (withdrawn) refuseWithdrawn(act) else all {
        hist' = if (applies) hist.append(held.e + 1) else hist,
        if (not(acks)) all {
          mark' = mark, logMark' = logMark, withdrawn' = withdrawn, held' = held, adopted' = adopted, late' = reached,
          unchangedHost, ev' = {act: act, res: "Unknown"}
        } else if (misreported) all {
          mark' = mark, logMark' = logMark, withdrawn' = true, held' = held, adopted' = adopted, late' = reached,
          unchangedHost, ev' = {act: act, res: "Regression"}
        } else take(act, result)
      }
    }
  }
  /// The store follows its contract: the write commits when the record is at the expected version.
  action bumpPass = if (withdrawn or hist.length() == held.ver) bump("bumpPass", true, true) else all {
    tick, held.ver > 0, hist.length() < VERSIONS,
    mark' = mark, logMark' = logMark, withdrawn' = withdrawn, held' = held, adopted' = adopted, late' = reached,
    ev' = {act: "bumpPass", res: "Refused"}, unchangedStore, unchangedHost
  }
  /// Kill arm: the store acknowledges the write and never applies it.
  action bumpLost = bump("bumpLost", false, true)
  /// Kill arm: the store applies the write whether or not the record is at the expected version.
  action bumpDoubleWin = bump("bumpDoubleWin", true, true)
  /// The reply is lost after the write commits under its condition.
  action bumpTimeoutCommit = bump("bumpTimeoutCommit", hist.length() == held.ver, false)
  /// The reply is lost and the write does not commit.
  action bumpTimeoutNoCommit = bump("bumpTimeoutNoCommit", false, false)
  /// Another writer commits the next attempt.
  action other = all {
    tick, hist.length() < VERSIONS,
    hist' = hist.append(hist[hist.length() - 1] + 1),
    mark' = mark, logMark' = logMark, withdrawn' = withdrawn, held' = held, adopted' = adopted, late' = late,
    ev' = {act: "other", res: ""}, unchangedHost
  }
  /// Another writer replaces the record and keeps its attempt counter.
  action otherKeeps = all {
    tick, hist.length() < VERSIONS,
    hist' = hist.append(hist[hist.length() - 1]),
    mark' = mark, logMark' = logMark, withdrawn' = withdrawn, held' = held, adopted' = adopted, late' = late,
    ev' = {act: "otherKeeps", res: ""}, unchangedHost
  }
  /// Another writer flips the record to its next generation, whose attempt counter starts at zero.
  action otherFlips = all {
    tick, hist.length() < VERSIONS, hist[hist.length() - 1] < FLIPPED,
    hist' = hist.append(FLIPPED),
    mark' = mark, logMark' = logMark, withdrawn' = withdrawn, held' = held, adopted' = adopted, late' = late,
    ev' = {act: "otherFlips", res: ""}, unchangedHost
  }
  /// The client process ends and the host starts its next one from the log.
  action restart = all {
    tick, not(logFails),
    mark' = logMark, withdrawn' = false, held' = NONE,
    logMark' = logMark, adopted' = adopted, late' = late, ev' = {act: "restart", res: ""}, unchangedStore,
    unchangedHost
  }
  /// The host's log starts failing its records.
  action logBreak = all {
    tick, not(logFails), logFails' = true,
    mark' = mark, logMark' = logMark, withdrawn' = withdrawn, held' = held, adopted' = adopted, late' = late,
    ev' = {act: "logBreak", res: ""}, unchangedStore
  }
  /// The host's log records again.
  action logMend = all {
    tick, logFails, logFails' = false,
    mark' = mark, logMark' = logMark, withdrawn' = withdrawn, held' = held, adopted' = adopted, late' = late,
    ev' = {act: "logMend", res: ""}, unchangedStore
  }
  action step = any {
    readPass, readStale, readUnavailable,
    bumpPass, bumpLost, bumpDoubleWin, bumpTimeoutCommit, bumpTimeoutNoCommit,
    other, otherKeeps, otherFlips, restart, logBreak, logMend,
  }
  /// No call returns a value below the mark the client held: a lower version, a lower value, or the mark's version
  /// with another value.
  val NoAdoptionBelowMark = adopted.forall(a => a._2.ver == 0
    or (a._1.ver >= a._2.ver and a._1.e >= a._2.e and (a._1.ver > a._2.ver or a._1.e == a._2.e)))
  /// A regression and a failed record of the raised mark each withdraw the client.
  val RefusalWithdraws = (ev.res == "Regression" or ev.res == "Log") implies withdrawn
  /// No call reaches the store while the client is withdrawn.
  val WithdrawnIsSilent = late == 0
  /// While the client is not withdrawn, the mark it checks results against is the one its log holds.
  val MarkIsDurable = withdrawn or mark == logMark
  val safety = NoAdoptionBelowMark and RefusalWithdraws and WithdrawnIsSilent and MarkIsDurable
  val witnessRead = ev.act == "readPass" and ev.res == "Ok"
  val witnessStaleAdmitted = ev.act == "readStale" and ev.res == "Ok"
  val witnessStaleRegression = ev.act == "readStale" and ev.res == "Regression"
  val witnessUnavailable = ev.res == "Unavailable"
  val witnessBumped = ev.act == "bumpPass" and ev.res == "Ok"
  val witnessRefused = ev.res == "Refused"
  val witnessLostAcknowledged = ev.act == "bumpLost" and ev.res == "Ok"
  val witnessLostRegression = ev.act == "bumpLost" and ev.res == "Regression"
  val witnessLostThenRead = ev.act == "readPass" and ev.res == "Regression"
  val witnessDoubleWinRegression = ev.act == "bumpDoubleWin" and ev.res == "Regression"
  val witnessDoubleWinCommitted = ev.act == "bumpDoubleWin" and ev.res == "Ok"
  /// The reply of a write that committed is lost. From `init` only `readPass` gives the client a value to bump, so a
  /// bump at the second step finds the record at the held version, and the second version is the bump's own append.
  val witnessUnknownCommitted = ev.act == "bumpTimeoutCommit" and ev.res == "Unknown" and turn == 2
    and hist.length() == 2
  val witnessUnknownUncommitted = ev.act == "bumpTimeoutNoCommit" and ev.res == "Unknown"
  val witnessOther = ev.act == "other"
  val witnessLog = ev.res == "Log"
  val witnessWithdrawn = ev.res == "Withdrawn"
  val witnessRestartKeepsMark = ev.act == "restart" and mark.ver > 0
  val witnessRestartAboveStore = ev.act == "restart" and hist.length() < mark.ver
  val witnessOtherKeeps = ev.act == "otherKeeps"
  val witnessOtherFlips = ev.act == "otherFlips"
  val witnessReusedVersion = ev.act == "readPass" and ev.res == "Regression" and hist.length() == mark.ver
    and hist[hist.length() - 1] > mark.e
  val witnessLowerVersion = ev.act == "readStale" and ev.res == "Regression"
    and hist[hist.length() - 2] == mark.e
  val witnessLowerValue = ev.act == "readPass" and ev.res == "Regression" and hist.length() > mark.ver
  val witnessLogBreak = ev.act == "logBreak"
  val witnessLogMend = ev.act == "logMend"
}
