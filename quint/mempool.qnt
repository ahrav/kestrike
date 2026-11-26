/// The transmit custody of the packet mempool ops: a header pool of two buffers, a payload pool of two
/// descriptors and one read-response source buffer. Each step is one call the burst logic or a device makes:
/// an acquire, a header handed to the device with its token, a descriptor take, a descriptor attached to the
/// source with its token, a handle's drop, or one give-back of an object through its pool's ops.
module mempool {
  const BOUND: int
  /// A buffer's owner handle, its device references, its incarnation and whether it is on the free stack.
  type Buf = {owned: bool, refs: int, inc: int, free: bool}
  /// The armed device-reference token in a transmit mbuf's private area and the incarnation it names.
  type Tok = {armed: bool, inc: int}
  type Event = {act: str, res: str, buf: str, desc: int}
  type State = {
    bufs: str -> Buf, htok: str -> Tok, dtok: int -> Tok, out: int -> bool, stack: List[int],
    returned: int, stray: int, mismatched: int, refused: int, ev: Event
  }
  var st: State
  var turn: int
  pure val HEADERS = Set("h0", "h1")
  pure val SOURCE = "s0"
  pure val BUFS = HEADERS.union(Set(SOURCE))
  pure val DESCS = Set(0, 1)
  pure val FREE: Buf = {owned: false, refs: 0, inc: 0, free: true}
  pure val DISARMED: Tok = {armed: false, inc: 0}
  pure def event(act: str, res: str, buf: str, desc: int): Event = {act: act, res: res, buf: buf, desc: desc}
  pure def stacked(s: List[int], d: int): bool = s.foldl(false, (found, x) => found or x == d)
  /// One device reference of `inc` returned to `b`: the last one frees a buffer whose handle ended, and a
  /// return naming another incarnation or no live reference changes nothing.
  pure def giveRef(b: Buf, inc: int): Buf =
    if (inc != b.inc or b.refs == 0) b
    else if (b.refs == 1 and not(b.owned)) {owned: false, refs: 0, inc: b.inc + 1, free: true}
    else {...b, refs: b.refs - 1}
  pure def matches(b: Buf, inc: int): bool = inc == b.inc and b.refs > 0
  action init = all {
    st' = {bufs: BUFS.mapBy(_ => FREE), htok: HEADERS.mapBy(_ => DISARMED), dtok: DESCS.mapBy(_ => DISARMED),
      out: DESCS.mapBy(_ => false), stack: [0, 1], returned: 0, stray: 0, mismatched: 0, refused: 0,
      ev: event("init", "", "", 0)},
    turn' = 0
  }
  action tick = all {turn < BOUND, turn' = turn + 1}
  /// The owner acquires the free buffer `b`.
  action acquire(b: str): bool = all {tick, st.bufs.get(b).free,
    st' = {...st, bufs: st.bufs.set(b, {...st.bufs.get(b), owned: true, free: false}), ev: event("acquire", "Acquired", b, 0)}
  }
  /// The owner hands header `h` to the device in one record write: the handle ends, one device reference
  /// starts, and the header mbuf's token names the buffer's incarnation.
  action send(h: str): bool = {
    val b = st.bufs.get(h)
    all {tick, b.owned, not(st.htok.get(h).armed),
      st' = {...st, bufs: st.bufs.set(h, {...b, owned: false, refs: b.refs + 1}), htok: st.htok.set(h, {armed: true, inc: b.inc}),
        ev: event("send", "Sent", h, 0)}
    }
  }
  /// The owner drops its handle of `b`; a buffer with no device reference returns to the free stack.
  action drop(b: str): bool = {
    val found = st.bufs.get(b)
    all {tick, found.owned,
      st' = if (found.refs == 0) {...st, bufs: st.bufs.set(b, {owned: false, refs: 0, inc: found.inc + 1, free: true}), ev: event("drop", "Freed", b, 0)}
        else {...st, bufs: st.bufs.set(b, {...found, owned: false}), ev: event("drop", "Held", b, 0)}
    }
  }
  /// One descriptor take: the stack's top goes out, or an empty stack refuses.
  action take = all {tick,
    st' = if (st.stack.length() == 0) {...st, refused: st.refused + 1, ev: event("take", "Refused", "", 0)}
      else {
        val d = st.stack[st.stack.length() - 1]
        {...st, stack: st.stack.slice(0, st.stack.length() - 1), out: st.out.set(d, true), ev: event("take", "Taken", "", d)}
      }
  }
  /// An out descriptor takes one device reference to the owned source; its token names the source's incarnation.
  action attach(d: int): bool = {
    val s = st.bufs.get(SOURCE)
    all {tick, st.out.get(d), not(st.dtok.get(d).armed), s.owned,
      st' = {...st, bufs: st.bufs.set(SOURCE, {...s, refs: s.refs + 1}), dtok: st.dtok.set(d, {armed: true, inc: s.inc}),
        ev: event("attach", "Attached", SOURCE, d)}
    }
  }
  /// The header pool's enqueue of header `h`'s mbuf, whose token is armed: it disarms the token and returns
  /// the reference it names.
  action giveHeader(h: str): bool = {
    val t = st.htok.get(h)
    val b = st.bufs.get(h)
    all {tick, t.armed,
      st' = {...st, htok: st.htok.set(h, DISARMED), bufs: st.bufs.set(h, giveRef(b, t.inc)),
        returned: st.returned + (if (matches(b, t.inc)) 1 else 0), stray: st.stray + (if (matches(b, t.inc)) 0 else 1),
        mismatched: st.mismatched + (if (matches(b, t.inc)) 0 else 1),
        ev: event("giveHeader", if (giveRef(b, t.inc).free) "ReturnedFreed" else "Returned", h, 0)}
    }
  }
  /// The payload pool's enqueue of out descriptor `d`: it goes back on the stack, and an armed token is
  /// disarmed and its reference returned.
  action giveDesc(d: int): bool = {
    val t = st.dtok.get(d)
    val s = st.bufs.get(SOURCE)
    val after = if (t.armed) giveRef(s, t.inc) else s
    all {tick, st.out.get(d),
      st' = {...st, out: st.out.set(d, false), stack: st.stack.append(d), dtok: st.dtok.set(d, DISARMED),
        bufs: st.bufs.set(SOURCE, after), returned: st.returned + 1,
        mismatched: st.mismatched + (if (t.armed and not(matches(s, t.inc))) 1 else 0),
        ev: event("giveDesc", if (not(t.armed)) "Unarmed" else if (after.free) "ReturnedFreed" else "Returned", SOURCE, d)}
    }
  }
  /// Every descriptor is on the stack or out, never both, and the stack holds each once.
  val OutOnceBackOnce = st.stack.length() + DESCS.filter(d => st.out.get(d)).size() == DESCS.size() and
    DESCS.forall(d => st.out.get(d) iff not(stacked(st.stack, d)))
  /// Returns through the ops name a live reference of their own buffer: none counts stray or mismatched.
  val NoStrayNoMismatch = st.stray == 0 and st.mismatched == 0
  /// Every armed token names its own buffer's live incarnation, and each buffer's device references are
  /// exactly the armed tokens naming it.
  val TokenNamesLiveIncarnation =
    HEADERS.forall(h => st.bufs.get(h).refs == (if (st.htok.get(h).armed) 1 else 0) and
      (st.htok.get(h).armed implies st.htok.get(h).inc == st.bufs.get(h).inc)) and
    DESCS.forall(d => st.dtok.get(d).armed implies (st.out.get(d) and st.dtok.get(d).inc == st.bufs.get(SOURCE).inc)) and
    st.bufs.get(SOURCE).refs == DESCS.filter(d => st.dtok.get(d).armed).size()
  /// A buffer is on the free stack exactly when its handle ended and no device reference remains.
  val FreesOnlyWhenBothReleased = BUFS.forall(b => st.bufs.get(b).free iff (not(st.bufs.get(b).owned) and st.bufs.get(b).refs == 0))
  val safety = OutOnceBackOnce and NoStrayNoMismatch and TokenNamesLiveIncarnation and FreesOnlyWhenBothReleased
  val witnessAcquired = st.ev.res == "Acquired"
  val witnessReacquired = st.ev.res == "Acquired" and st.bufs.get(st.ev.buf).inc > 0
  val witnessSent = st.ev.res == "Sent"
  val witnessFreed = st.ev.res == "Freed"
  val witnessHeld = st.ev.res == "Held"
  val witnessTaken = st.ev.res == "Taken"
  val witnessRefused = st.ev.res == "Refused"
  val witnessAttached = st.ev.res == "Attached"
  val witnessHeaderReturned = st.ev.act == "giveHeader" and st.ev.res == "ReturnedFreed"
  val witnessDescReturned = st.ev.act == "giveDesc" and st.ev.res == "Returned"
  val witnessDescReturnedFreed = st.ev.act == "giveDesc" and st.ev.res == "ReturnedFreed"
  val witnessDescUnarmed = st.ev.res == "Unarmed"
  action step = {
    nondet b = BUFS.oneOf()
    nondet h = HEADERS.oneOf()
    nondet d = DESCS.oneOf()
    any {acquire(b), send(h), drop(b), take, attach(d), giveHeader(h), giveDesc(d)}
  }
}
