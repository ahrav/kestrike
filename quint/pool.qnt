/// One buffer pool of the arena: two buffers, incarnations 0 to 3, at most two device references per buffer.
/// Each step is one call on the pool: an acquire or a posting, the end of a handle, a device reference taken or returned,
/// a request for a mutable view, or a custody move of the command table.
/// A buffer's obligation set is Free, App behind a live handle, Storage, Quarantined, Posted, Nic or Retired.
module pool {
  const BOUND: int
  type Buf = {set: str, nic: int, inc: int}
  type Event = {act: str, res: str, buf: int, inc: int}
  type State = {
    bufs: int -> Buf, stack: List[int], mismatched: int, ended: int, retired: int,
    lent: int -> int, raw: int -> int, issued: Set[(int, int)], reissued: bool, ev: Event
  }
  var st: State
  var turn: int
  pure val BUFS = Set(0, 1)
  pure val MAX = 3
  pure val CAP = 2
  pure val NONE = -1
  pure def note(s: State, act: str, res: str, buf: int, inc: int): State =
    {...s, ev: {act: act, res: res, buf: buf, inc: inc}}
  pure def moved(s: State, b: int, class: str): State = {...s, bufs: s.bufs.set(b, {...s.bufs.get(b), set: class})}
  /// Every obligation of the buffer ended: it starts its next incarnation on the free stack, or retires at the last one.
  pure def freed(s: State, b: int): State = {
    val r = s.bufs.get(b)
    if (r.inc == MAX) {...s, bufs: s.bufs.set(b, {set: "Retired", nic: 0, inc: r.inc}), retired: s.retired + 1}
    else {...s, bufs: s.bufs.set(b, {set: "Free", nic: 0, inc: r.inc + 1}), stack: s.stack.append(b)}
  }
  /// The top of the free stack leaves it under set `class`, as a handle or a posting.
  pure def popped(s: State, act: str, class: str): State = {
    val b = s.stack[s.stack.length() - 1]
    val inc = s.bufs.get(b).inc
    if (s.stack.length() == 0) note(s, act, "Exhausted", NONE, 0)
    else note({...moved(s, b, class), stack: s.stack.slice(0, s.stack.length() - 1),
      issued: s.issued.union(Set((b, inc))), reissued: s.reissued or s.issued.contains((b, inc))}, act, "", b, inc)
  }
  /// The end of a handle: free, or Nic while device references remain.
  pure def dropped(s: State, b: int): State =
    if (s.bufs.get(b).nic > 0) moved(s, b, "Nic") else freed(s, b)
  /// One device reference ends; the last one frees a Nic buffer and leaves a handle's buffer App.
  pure def returned(s: State, b: int): State = {
    val r = s.bufs.get(b)
    val rest = {...s, bufs: s.bufs.set(b, {...r, nic: r.nic - 1})}
    if (r.nic > 1) rest
    else if (r.set == "Nic") freed({...rest, ended: rest.ended + 1}, b)
    else {...rest, ended: rest.ended + 1}
  }
  pure def held(s: State, b: int): State = {...s, bufs: s.bufs.set(b, {...s.bufs.get(b), nic: s.bufs.get(b).nic + 1})}
  /// A raw return naming buffer `b` at incarnation `inc`: it ends a reference of the current incarnation and otherwise only counts.
  /// `owed` is the device's side: it gives up a reference it took over for the current incarnation.
  pure def rawReturn(s: State, b: int, inc: int): State = {
    val hit = if (BUFS.contains(b)) s.bufs.get(b).inc == inc and s.bufs.get(b).nic > 0 else false
    val owed = if (BUFS.contains(b)) s.bufs.get(b).inc == inc and s.raw.get(b) > 0 else false
    val taken = if (owed) {...s, raw: s.raw.set(b, s.raw.get(b) - 1)} else s
    if (hit) note(returned(taken, b), "ret", "Matched", b, inc)
    else note({...taken, mismatched: taken.mismatched + 1}, "ret", "Mismatched", b, inc)
  }
  pure def has(s: State, b: int, class: str): bool = s.bufs.get(b).set == class
  pure def now(s: State, b: int): int = s.bufs.get(b).inc
  action init = all {
    st' = {bufs: BUFS.mapBy(_ => {set: "Free", nic: 0, inc: 0}), stack: [1, 0], mismatched: 0, ended: 0, retired: 0,
      lent: BUFS.mapBy(_ => 0), raw: BUFS.mapBy(_ => 0), issued: Set(), reissued: false,
      ev: {act: "init", res: "", buf: NONE, inc: 0}},
    turn' = 0
  }
  action tick = all {turn < BOUND, turn' = turn + 1}
  action acquire = all {tick, st' = popped(st, "acquire", "App")}
  action post = all {tick, st' = popped(st, "post", "Posted")}
  action drop(b: int): bool = all {tick, has(st, b, "App"), st' = note(dropped(st, b), "drop", "", b, now(st, b))}
  action lend(b: int): bool = all {tick, has(st, b, "App"), st.bufs.get(b).nic < CAP,
    st' = note(held({...st, lent: st.lent.set(b, st.lent.get(b) + 1)}, b), "lend", "", b, now(st, b))}
  action unlend(b: int): bool = all {tick, st.lent.get(b) > 0,
    st' = note(returned({...st, lent: st.lent.set(b, st.lent.get(b) - 1)}, b), "unlend", "", b, now(st, b))}
  action give(b: int): bool = all {tick, has(st, b, "App"), st.bufs.get(b).nic < CAP,
    st' = note(held({...st, raw: st.raw.set(b, st.raw.get(b) + 1)}, b), "give", "", b, now(st, b))}
  action handoff(b: int): bool = all {tick, has(st, b, "App"), st.bufs.get(b).nic < CAP,
    st' = note(moved(held({...st, raw: st.raw.set(b, st.raw.get(b) + 1)}, b), b, "Nic"), "handoff", "", b, now(st, b))}
  /// The device returns a reference it took over, or a return names no reference of the buffer's current incarnation.
  action ret(b: int, inc: int): bool = all {tick,
    if (BUFS.contains(b)) st.bufs.get(b).inc != inc or st.bufs.get(b).nic == 0 or st.raw.get(b) > 0 else true,
    st' = rawReturn(st, b, inc)}
  action view(b: int): bool = all {tick, has(st, b, "App"),
    st' = note(st, "view", if (st.bufs.get(b).nic > 0) "Refused" else "Viewed", b, now(st, b))}
  action store(b: int): bool = all {tick, has(st, b, "App"), st.bufs.get(b).nic == 0,
    st' = note(moved(st, b, "Storage"), "store", "", b, now(st, b))}
  action restore(b: int): bool = all {tick, has(st, b, "Storage"), st' = note(moved(st, b, "App"), "restore", "", b, now(st, b))}
  action detach(b: int): bool = all {tick, has(st, b, "Storage"),
    st' = note(moved(st, b, "Quarantined"), "detach", "", b, now(st, b))}
  action discard(b: int): bool = all {tick, has(st, b, "Quarantined"), st' = note(freed(st, b), "discard", "", b, now(st, b))}
  action complete(b: int): bool = all {tick, has(st, b, "Posted"), st' = note(moved(st, b, "App"), "complete", "", b, now(st, b))}
  action unpost(b: int): bool = all {tick, has(st, b, "Posted"), st' = note(freed(st, b), "unpost", "", b, now(st, b))}
  val HeldStaysOffStack = BUFS.forall(b => st.lent.get(b) + st.raw.get(b) > 0 implies
    (st.stack.select(x => x == b).length() == 0 and (has(st, b, "App") or has(st, b, "Nic"))))
  val ReferencesCounted = BUFS.forall(b => st.bufs.get(b).nic == st.lent.get(b) + st.raw.get(b))
  val NoMutableViewWhileHeld = st.ev.res == "Viewed" implies st.lent.get(st.ev.buf) + st.raw.get(st.ev.buf) == 0
  val Partition = and {
    BUFS.forall(b => st.stack.select(x => x == b).length() == (if (has(st, b, "Free")) 1 else 0)),
    st.retired == BUFS.filter(b => has(st, b, "Retired")).size(),
    BUFS.forall(b => has(st, b, "Nic") implies st.bufs.get(b).nic > 0),
    BUFS.forall(b => st.bufs.get(b).nic > 0 implies (has(st, b, "App") or has(st, b, "Nic"))),
  }
  val IncarnationIssuedOnce = not(st.reissued)
  val safety = HeldStaysOffStack and ReferencesCounted and NoMutableViewWhileHeld and Partition and IncarnationIssuedOnce
  val witnessAcquired = st.ev.act == "acquire" and st.ev.res == ""
  val witnessExhausted = st.ev.act == "acquire" and st.ev.res == "Exhausted"
  val witnessPosted = st.ev.act == "post" and st.ev.res == ""
  val witnessPostExhausted = st.ev.act == "post" and st.ev.res == "Exhausted"
  val witnessDropFreed = st.ev.act == "drop" and has(st, st.ev.buf, "Free")
  val witnessDropHeld = st.ev.act == "drop" and has(st, st.ev.buf, "Nic")
  val witnessDropRetired = st.ev.act == "drop" and has(st, st.ev.buf, "Retired")
  val witnessLent = st.ev.act == "lend"
  val witnessUnlentToApp = st.ev.act == "unlend" and has(st, st.ev.buf, "App")
  val witnessUnlentFreed = st.ev.act == "unlend" and has(st, st.ev.buf, "Free")
  val witnessGiven = st.ev.act == "give"
  val witnessHandoff = st.ev.act == "handoff"
  val witnessMatched = st.ev.res == "Matched"
  val witnessLastReturnFreed = st.ev.res == "Matched" and has(st, st.ev.buf, "Free")
  val witnessReturnKeepsCount = st.ev.res == "Matched" and st.bufs.get(st.ev.buf).nic > 0
  val witnessMismatched = st.ev.res == "Mismatched"
  val witnessOlderIncarnation = st.ev.res == "Mismatched" and st.ev.buf != 2 and st.ev.inc < now(st, st.ev.buf) and
    st.bufs.get(st.ev.buf).nic > 0
  val witnessViewed = st.ev.res == "Viewed"
  val witnessViewRefused = st.ev.res == "Refused"
  val witnessStored = st.ev.act == "store"
  val witnessRestored = st.ev.act == "restore"
  val witnessDetached = st.ev.act == "detach"
  val witnessDiscarded = st.ev.act == "discard"
  val witnessCompleted = st.ev.act == "complete"
  val witnessUnposted = st.ev.act == "unpost"
  action someRet = {
    nondet b = Set(0, 1, 2).oneOf()
    nondet inc = Set(0, 1, 2, 3).oneOf()
    ret(b, inc)
  }
  action some = {
    nondet b = BUFS.oneOf()
    any {drop(b), lend(b), unlend(b), give(b), handoff(b), view(b), store(b), restore(b), detach(b), discard(b), complete(b),
      unpost(b)}
  }
  action step = any {acquire, post, some, someRet}
}
