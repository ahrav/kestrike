/// Per-shard tenure high-water ordered by generation, then activated epoch. Authenticated frames retain conflicts
/// until a higher tenure. A retirement of the held or a later generation darkens that generation at any epoch
/// until a later one, and epoch 0 sorts below every activated epoch of its generation.
///
/// Withdrawals carry send order. The owner stamps the frames it sends with one increasing number, `ready(s, k)` is the
/// READY that opens session `s` with stamp `k`, and `withdraw(s, k)` is a not-serving frame of session `s` naming the
/// held tenure. Frames arrive in any order. `binder` is the session of the READY that arrived last at the held tenure,
/// whether or not it moved the route, and `high` holds each session's highest admitted stamp. A withdrawal leaves the
/// binding for a Candidate of that tenure only when its session is the binder and admits it above `high`.
/// `WithdrawalOrdered`: while the READYs arrived in the order the owner sent them, the owner sent every withdrawal
/// that takes effect after every READY the route admitted. A frame of `receive` names no modelled session, so a
/// binding it makes has no binder.
module route {
  const BOUND: int
  type Frame = { g: int, a: int, x: int, bound: bool, dark: bool }
  type HW = { g: int, a: int, x: int, kind: str }
  var hw: HW
  var prior: HW
  var ev: { act: str, frame: Frame, res: str, sent: bool, accepted: bool, s: int, k: int, floor: int, inOrder: bool }
  var turn: int
  var binder: int
  var high: int -> int
  /// The highest stamp of an admitted READY, and whether every READY arrived above the ones before it.
  var maxReady: int
  var readiesInOrder: bool
  pure val SESSIONS = Set(1, 2)
  pure val initial = { g: 0, a: 0, x: 0, kind: "None" }
  pure val emptyFrame = { g: 0, a: 0, x: 0, bound: false, dark: false }
  pure def below(f: { g: int, a: int }, h: { g: int, a: int }): bool = f.g < h.g or (f.g == h.g and f.a < h.a)
  pure def same(f: { g: int, a: int }, h: { g: int, a: int }): bool = f.g == h.g and f.a == h.a
  pure def merge(old: HW, f: Frame): HW = {
    val tie = same({ g: f.g, a: f.a }, { g: old.g, a: old.a })
    if (old.kind == "Dark" and f.g <= old.g) old
    else if (f.dark and f.g == old.g) { g: f.g, a: if (f.a > old.a) f.a else old.a, x: 0, kind: "Dark" }
    else if (below({ g: f.g, a: f.a }, { g: old.g, a: old.a })) old
    else if (tie and (old.kind == "Conflict" or old.x != f.x)) { ...old, x: 0, kind: "Conflict" }
    else {
      val kind = if (f.dark) "Dark" else if (f.bound) "Bound"
                 else if (tie and old.kind == "Bound") "Bound" else "Candidate"
      { g: f.g, a: f.a, x: if (f.dark) 0 else f.x, kind: kind }
    }
  }
  pure def accepts(h: HW, f: Frame): bool = h.kind == "Bound" and f.g == h.g and f.a == h.a and f.x == h.x
  action init = all {
    hw' = initial, prior' = initial, turn' = 0, binder' = 0, high' = SESSIONS.mapBy(_ => 0), maxReady' = 0, readiesInOrder' = true,
    ev' = { act: "init", frame: emptyFrame, res: "None", sent: false, accepted: false, s: 0, k: 0, floor: 0, inOrder: true },
  }
  pure def binds(old: HW, new: HW): bool = new.kind == "Bound" and new != old
  action receive(f: Frame): bool = {
    val merged = merge(hw, f)
    all { turn < BOUND,
    hw' = merged, prior' = hw, turn' = turn + 1, binder' = if (binds(hw, merged)) 0 else binder,
    high' = high, maxReady' = maxReady, readiesInOrder' = readiesInOrder,
    ev' = { act: "receive", frame: f, res: merged.kind, sent: false, accepted: false, s: 0, k: 0, floor: maxReady, inOrder: readiesInOrder },
  }}
  action ready(s: int, k: int): bool = {
    val merged = merge(hw, { g: hw.g, a: hw.a, x: hw.x, bound: true, dark: false })
    all { turn < BOUND, Set("Candidate", "Bound").contains(hw.kind), high.get(s) == 0,
    hw' = merged, prior' = hw, turn' = turn + 1, binder' = s,
    high' = high.set(s, k), maxReady' = if (k > maxReady) k else maxReady, readiesInOrder' = (readiesInOrder and k > maxReady),
    ev' = { act: "ready", frame: emptyFrame, res: merged.kind, sent: false, accepted: false, s: s, k: k, floor: maxReady, inOrder: readiesInOrder },
  }}
  action withdraw(s: int, k: int): bool = {
    val newest = k > high.get(s)
    val ordered = newest and s == binder
    val merged = if (hw.kind == "Bound" and ordered) { ...hw, kind: "Candidate" } else hw
    all { turn < BOUND, Set("Candidate", "Bound").contains(hw.kind), high.get(s) > 0,
    hw' = merged, prior' = hw, turn' = turn + 1, binder' = binder,
    high' = if (newest) high.set(s, k) else high, maxReady' = maxReady, readiesInOrder' = readiesInOrder,
    ev' = { act: "withdraw", frame: emptyFrame, res: merged.kind, sent: false, accepted: false, s: s, k: k, floor: maxReady, inOrder: readiesInOrder },
  }}
  action request = all {
    turn < BOUND, hw' = hw, prior' = hw, turn' = turn + 1, binder' = binder, high' = high, maxReady' = maxReady, readiesInOrder' = readiesInOrder,
    ev' = { ...ev, act: "request", sent: Set("Candidate", "Bound").contains(hw.kind), accepted: false },
  }
  action response(f: Frame): bool = all {
    turn < BOUND, hw' = hw, prior' = hw, turn' = turn + 1, binder' = binder, high' = high, maxReady' = maxReady, readiesInOrder' = readiesInOrder,
    ev' = { ...ev, act: "response", frame: f, sent: false, accepted: accepts(hw, f) },
  }
  action step = any {
    nondet g = 1.to(2).oneOf()
    nondet a = 1.to(3).oneOf()
    nondet x = Set(1, 2).oneOf()
    nondet bound = Set(false, true).oneOf()
    nondet dark = Set(false, true).oneOf()
    receive({ g: g, a: a, x: x, bound: bound, dark: dark }),
    request,
    nondet g = 1.to(2).oneOf()
    nondet a = 1.to(3).oneOf()
    nondet x = Set(1, 2).oneOf()
    response({ g: g, a: a, x: x, bound: true, dark: false }),
    nondet s = SESSIONS.oneOf()
    nondet k = 1.to(4).oneOf()
    ready(s, k),
    nondet s = SESSIONS.oneOf()
    nondet k = 1.to(4).oneOf()
    withdraw(s, k),
  }
  val RouteMonotonic = (hw.g > prior.g or (hw.g == prior.g and hw.a >= prior.a))
    and (prior.kind == "Conflict" and same({ g: hw.g, a: hw.a }, { g: prior.g, a: prior.a }) implies Set("Conflict", "Dark").contains(hw.kind))
    and (prior.kind == "Dark" and hw.g == prior.g implies hw == prior)
    and (ev.act == "receive" and ev.frame.dark and ev.frame.g >= prior.g implies hw.kind == "Dark" and hw.g == ev.frame.g)
    and (ev.act == "receive" and not(ev.frame.dark and ev.frame.g == prior.g) and (ev.frame.g < prior.g or (ev.frame.g == prior.g and ev.frame.a < prior.a)) implies hw == prior)
    and (ev.act == "receive" and prior.kind != "Dark" and not(ev.frame.dark) and same({ g: ev.frame.g, a: ev.frame.a }, { g: prior.g, a: prior.a }) and ev.frame.x != prior.x implies hw.kind == "Conflict")
    and (ev.act == "receive" and not(ev.frame.bound) and hw.kind == "Bound" implies hw == prior)
    and (ev.accepted implies ev.frame.g == hw.g and ev.frame.a == hw.a and ev.frame.x == hw.x and hw.kind == "Bound")
    and (Set("Conflict", "Dark").contains(hw.kind) implies not(ev.sent) and not(ev.accepted))
  /// A Bound route leaves its binding for a Candidate of the same tenure and host only by a withdrawal, and while the
  /// READYs arrived in send order the owner sent that withdrawal after every READY the route admitted.
  val WithdrawalOrdered = (prior.kind == "Bound" and hw.kind == "Candidate" and same({ g: hw.g, a: hw.a }, { g: prior.g, a: prior.a }))
    implies (ev.act == "withdraw" and hw.x == prior.x and (ev.inOrder implies ev.k > ev.floor))
  val safety = RouteMonotonic and WithdrawalOrdered
  val witnessCandidate = ev.act == "receive" and hw.kind == "Candidate"
  val witnessBound = ev.act == "receive" and hw.kind == "Bound"
  val witnessConflictAB = hw.kind == "Conflict" and prior.x == 1
  val witnessConflictBA = hw.kind == "Conflict" and prior.x == 2
  val witnessDark = ev.act == "receive" and hw.kind == "Dark"
  val witnessDarkBelow = ev.act == "receive" and ev.frame.dark and ev.frame.a < prior.a and hw.kind == "Dark"
  val witnessDarkKept = ev.act == "receive" and prior.kind == "Dark" and hw == prior and ev.frame.bound and not(ev.frame.dark)
  val witnessStale = ev.act == "receive" and below({ g: ev.frame.g, a: ev.frame.a }, { g: hw.g, a: hw.a })
  val witnessFlip = ev.act == "receive" and hw.g > prior.g and hw.a < prior.a and hw.kind == "Bound"
  val witnessDuplicate = ev.act == "receive" and hw == prior and hw.kind == "Bound"
  val witnessRequest = ev.act == "request" and ev.sent
  val witnessRequestWithheld = ev.act == "request" and not(ev.sent)
  val witnessAccepted = ev.act == "response" and ev.accepted
  val witnessRejected = ev.act == "response" and not(ev.accepted)
  val witnessConflictExit = prior.kind == "Conflict" and hw.kind == "Bound"
  val witnessWithdrawn = ev.act == "withdraw" and prior.kind == "Bound" and hw.kind == "Candidate"
  val witnessWithdrawalOvertaken = ev.act == "withdraw" and ev.s == binder and ev.k < high.get(ev.s) and hw.kind == "Bound"
  val witnessWithdrawalAfterOtherReady = ev.act == "withdraw" and ev.s != binder and ev.k > ev.floor and hw.kind == "Bound"
  val witnessReadyOnBound = ev.act == "ready" and prior.kind == "Bound" and hw == prior and binder == 2
  val witnessReopenedWithdraws = ev.act == "withdraw" and ev.s == 2 and prior.kind == "Bound" and hw.kind == "Candidate"
  val witnessRebound = ev.act == "ready" and prior.kind == "Candidate" and hw.kind == "Bound" and binder == 2
}
