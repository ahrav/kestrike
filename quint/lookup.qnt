/// Lookups of two keys on a live indexed storage, beside the operations that change what a key names.
/// Each step is one storage operation: a publication, a replacement, a removal, a lookup, a dropped lease, the clock
/// passing the deadline, the close of admission, one funded certification and one funded service call.
/// Objects are numbered from 1 in the order they are published, and number 0 stands for no object; every object has
/// the same deadline.
module lookup {
  const BOUND: int
  type Object = {key: int, phase: str, anchored: bool, rights: int, stamp: int}
  type Event = {act: str, res: str, key: int, value: int, visited: int, held: int, released: int, serviced: int}
  type State = {
    era: int, certified: int, objs: int -> Object, names: int -> int, born: int, late: bool, closed: bool,
    bad: bool, ev: Event
  }
  var st: State
  var turn: int
  pure val KEYS = Set(0, 1)
  pure val IDS = Set(1, 2, 3, 4)
  pure val OBJECTS = 4
  pure val RIGHTS = 2
  pure val NONE = 0
  pure val FIRST = 1
  pure def note(s: State, act: str, key: int): State =
    {...s, ev: {act: act, res: "", key: key, value: 0, visited: 0, held: 0, released: 0, serviced: 0}}
  pure def result(s: State, res: str, value: int): State = {...s, ev: {...s.ev, res: res, value: value}}
  /// The next object becomes visible under the key, with its anchor counted.
  pure def published(s: State, k: int): State = {
    val fresh = s.born + 1
    {...s, born: fresh, names: s.names.set(k, fresh),
      objs: s.objs.set(fresh, {key: k, phase: "Visible", anchored: true, rights: 0, stamp: 0})}
  }
  /// The object the key names leaves the index: the retirement stamps it with the era it found and advances the era.
  pure def ended(s: State, k: int): State = {
    val old = s.names.get(k)
    {...s, era: s.era + 1, names: s.names.set(k, NONE),
      objs: s.objs.set(old, {...s.objs.get(old), phase: "Retired", stamp: s.era})}
  }
  /// One lookup. Closed admission refuses first; a key that names no object is missing; a named object at or past
  /// its deadline is expired; otherwise the lookup returns a lease on the named object, one more right on it.
  pure def looked(s: State, k: int): State = {
    val id = s.names.get(k)
    val seen =
      if (s.closed) result(s, "Closed", NONE)
      else if (id == NONE) result(s, "Missing", NONE)
      else if (s.late) result(s, "Expired", NONE)
      else result({...s, objs: s.objs.set(id, {...s.objs.get(id), rights: s.objs.get(id).rights + 1})}, "Hit", id)
    val leased = seen.ev.value
    {...seen, bad: s.bad or (seen.ev.res == "Hit" and (s.closed or s.late or s.names.get(k) != leased or
      s.objs.get(leased).key != k or s.objs.get(leased).phase != "Visible"))}
  }
  /// One funded certification: with no pin in place the pass certifies the current era, when that is higher.
  pure def certifying(s: State): State =
    if (s.era <= s.certified) result(s, "Idle", s.certified) else result({...s, certified: s.era}, "Certified", s.era)
  /// What one service visit makes of an object: a retired object's anchor is released when its stamp lies strictly
  /// below the certified era, and the object returns when neither its anchor nor a right is counted.
  pure def visit(o: Object, certified: int): Object = {
    val anchored = o.anchored and not(o.stamp < certified)
    if (o.phase != "Retired") o
    else {...o, anchored: anchored, phase: if (not(anchored) and o.rights == 0) "Returned" else o.phase}
  }
  /// One funded service call visits every retired object.
  pure def serviced(s: State): State = {
    val after = IDS.union(Set(NONE)).mapBy(id => visit(s.objs.get(id), s.certified))
    val retired = IDS.filter(id => s.objs.get(id).phase == "Retired")
    {...s, objs: after, ev: {...s.ev, res: "Ok", visited: retired.size(),
      held: retired.filter(id => after.get(id).phase == "Retired").size(),
      released: retired.filter(id => s.objs.get(id).anchored and not(after.get(id).anchored)).size(),
      serviced: retired.filter(id => after.get(id).phase == "Returned").size()}}
  }
  action init = all {
    st' = {era: FIRST, certified: 0, objs: IDS.union(Set(NONE)).mapBy(_ => {key: 0, phase: "Unborn", anchored: false, rights: 0, stamp: 0}),
      names: KEYS.mapBy(_ => NONE), born: 0, late: false, closed: false, bad: false,
      ev: {act: "init", res: "", key: 0, value: 0, visited: 0, held: 0, released: 0, serviced: 0}},
    turn' = 0
  }
  action tick = all {turn < BOUND, turn' = turn + 1}
  action publish(k: int): bool = all {tick, not(st.closed), st.names.get(k) == NONE, st.born < OBJECTS,
    st' = result(published(note(st, "publish", k), k), "Ok", st.born + 1)}
  action replace(k: int): bool = all {tick, not(st.closed), st.names.get(k) != NONE, st.born < OBJECTS,
    st' = result(published(ended(note(st, "replace", k), k), k), "Ok", st.born + 1)}
  action remove(k: int): bool = all {tick, st.names.get(k) != NONE,
    st' = result(ended(note(st, "remove", k), k), "Ok", st.names.get(k))}
  action lookup(k: int): bool = all {tick,
    st.names.get(k) == NONE or st.objs.get(st.names.get(k)).rights < RIGHTS,
    st' = looked(note(st, "lookup", k), k)}
  action drop(id: int): bool = all {tick, st.objs.get(id).rights > 0,
    st' = result({...note(st, "drop", 0), objs: st.objs.set(id, {...st.objs.get(id), rights: st.objs.get(id).rights - 1})},
      "Ok", id)}
  action expire = all {tick, not(st.late), st' = result({...note(st, "expire", 0), late: true}, "Ok", 0)}
  action close = all {tick, not(st.closed), st' = result({...note(st, "close", 0), closed: true}, "Ok", 0)}
  action certify = all {tick, st' = certifying(note(st, "certify", 0))}
  action service = all {tick, st' = serviced(note(st, "service", 0))}
  val HitOnVisible = not(st.bad)
  val HitRetained = IDS.forall(id => st.objs.get(id).rights > 0 implies st.objs.get(id).phase != "Returned")
  val safety = HitOnVisible and HitRetained
  val witnessPublished = st.ev.act == "publish"
  val witnessReplaced = st.ev.act == "replace"
  val witnessRemoved = st.ev.act == "remove"
  val witnessRemovedAfterClose = st.ev.act == "remove" and st.closed
  val witnessHit = st.ev.act == "lookup" and st.ev.res == "Hit"
  val witnessHitOnSuccessor = st.ev.act == "lookup" and st.ev.res == "Hit" and
    IDS.exists(id => id < st.ev.value and st.objs.get(id).phase != "Unborn" and st.objs.get(id).key == st.ev.key)
  val witnessMissing = st.ev.act == "lookup" and st.ev.res == "Missing"
  val witnessMissingAfterRemoval = st.ev.act == "lookup" and st.ev.res == "Missing" and
    IDS.exists(id => st.objs.get(id).phase != "Unborn" and st.objs.get(id).key == st.ev.key)
  val witnessExpired = st.ev.act == "lookup" and st.ev.res == "Expired"
  val witnessClosed = st.ev.act == "lookup" and st.ev.res == "Closed"
  val witnessDropped = st.ev.act == "drop"
  val witnessDroppedRetired = st.ev.act == "drop" and st.objs.get(st.ev.value).phase == "Retired"
  val witnessLate = st.ev.act == "expire"
  val witnessClose = st.ev.act == "close"
  val witnessCertified = st.ev.act == "certify" and st.ev.res == "Certified"
  val witnessCertifyIdle = st.ev.act == "certify" and st.ev.res == "Idle"
  val witnessServiceNothing = st.ev.act == "service" and st.ev.visited == 0
  val witnessServiceHolds = st.ev.act == "service" and st.ev.held > 0
  val witnessServiceReleases = st.ev.act == "service" and st.ev.released > 0
  val witnessServiceReturns = st.ev.act == "service" and st.ev.serviced > 0
  val witnessServiceTwo = st.ev.act == "service" and st.ev.visited == 2
  action somePublish = {
    nondet k = KEYS.oneOf()
    publish(k)
  }
  action someReplace = {
    nondet k = KEYS.oneOf()
    replace(k)
  }
  action someRemove = {
    nondet k = KEYS.oneOf()
    remove(k)
  }
  action someLookup = {
    nondet k = KEYS.oneOf()
    lookup(k)
  }
  action someDrop = {
    nondet id = IDS.oneOf()
    drop(id)
  }
  action step = any {somePublish, someReplace, someRemove, someLookup, someDrop, expire, close, certify, service}
}
