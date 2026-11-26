/// The owner's table of parked GETs: five request slots, five fills and four tracking places, with a
/// wake allowance of three visits a pass. Each step is one call on the table, in the order the owner's
/// turn makes them, with the result the call returns.
module parked {
  const BOUND: int
  type Event = {act: str, res: str, idx: int}
  /// A tracking place: the fill it tracks (-1 when free), whether the owner sees that fill depart,
  /// and whether the current pass found it pending.
  type Place = {fill: int, reported: bool, pending: bool}
  type Table = {
    fills: int -> int, places: int -> int, tracked: int -> Place, due: Set[int], checking: Set[int],
    elapsed: bool, odd: bool, admits: bool, cursor: int, pass: int, visits: int, phase: str, checked: Set[int],
    passed: Set[int], repeated: bool, unowed: bool, wrapped: bool, ev: Event
  }
  var t: Table
  var turn: int
  pure val SLOTS = Set(0, 1, 2, 3, 4)
  pure val PLACES = Set(0, 1, 2, 3)
  pure val WAKE = 3
  pure val FREE: Place = {fill: -1, reported: false, pending: false}
  pure def event(act: str, res: str, idx: int): Event = {act: act, res: res, idx: idx}
  /// The owner sees an even fill depart; an odd fill is watched by checks.
  pure def reported(fill: int): bool = fill % 2 == 0
  pure def parks(s: Table, slot: int): bool = s.fills.get(slot) >= 0
  pure def parkedSlots(s: Table): Set[int] = SLOTS.filter(slot => parks(s, slot))
  /// The slots that follow tracking place `k`.
  pure def members(s: Table, k: int): Set[int] = SLOTS.filter(slot => parks(s, slot) and s.places.get(slot) == k)
  pure def untracked(s: Table): Set[int] = SLOTS.filter(slot => parks(s, slot) and s.places.get(slot) < 0)
  /// The tracked fills checks observe, and the untracked entries.
  pure def watched(s: Table): int =
    PLACES.filter(k => s.tracked.get(k).fill >= 0 and not(s.tracked.get(k).reported)).size() + untracked(s).size()
  pure def placeOf(s: Table, fill: int): Set[int] = PLACES.filter(k => s.tracked.get(k).fill == fill)
  pure def lowest(among: Set[int]): int =
    if (among.contains(0)) 0 else if (among.contains(1)) 1 else if (among.contains(2)) 2 else if (among.contains(3)) 3 else 4
  pure def checkDue(s: Table): bool = watched(s) > 0 and s.elapsed
  /// Every parked entry is owed a visit, and any check under way ends.
  pure def owedAll(s: Table): Table = {...s, due: parkedSlots(s), checking: Set()}
  pure def owedFollowers(s: Table, k: int): Table = {...s, due: s.due.union(members(s, k))}

  action init = all {
    t' = {fills: SLOTS.mapBy(_ => -1), places: SLOTS.mapBy(_ => -1), tracked: PLACES.mapBy(_ => FREE), due: Set(),
      checking: Set(), elapsed: true, odd: false, admits: true, cursor: 0, pass: 0, visits: 0, phase: "rest",
      checked: Set(), passed: Set(), repeated: false, unowed: false, wrapped: false, ev: event("init", "", 0)},
    turn' = 0
  }
  action tick = all {turn < BOUND, turn' = turn + 1}
  /// A GET parks in `slot` behind `fill` and is owed a visit: it follows the fill's place, takes a free
  /// place for it, or stays untracked.
  action park(slot: int, fill: int): bool = {
    val known = placeOf(t, fill)
    val free = PLACES.filter(k => t.tracked.get(k).fill < 0)
    val k = if (known != Set()) lowest(known) else if (free != Set()) lowest(free) else -1
    val place = if (k < 0 or known != Set()) t.tracked else t.tracked.set(k, {fill: fill, reported: reported(fill), pending: false})
    all {tick, t.phase == "rest", not(parks(t, slot)),
      t' = {...t, fills: t.fills.set(slot, fill), places: t.places.set(slot, k), tracked: place, due: t.due.union(Set(slot)),
        ev: event("park", if (known != Set()) "followed" else if (k >= 0) "placed" else "untracked", slot)}
    }
  }
  /// The owner removes the entry a visit of this pass returned; a fill's last follower frees its place.
  action take(slot: int): bool = {
    val k = t.places.get(slot)
    val last = k >= 0 and members(t, k) == Set(slot)
    all {tick, t.phase == "visits", parks(t, slot), t.passed.contains(slot),
      t' = {...t, fills: t.fills.set(slot, -1), places: t.places.set(slot, -1), due: t.due.exclude(Set(slot)),
        tracked: if (last) t.tracked.set(k, FREE) else t.tracked, checking: if (last) t.checking.exclude(Set(k)) else t.checking,
        ev: event("take", if (last) "freed" else "", slot)}
    }
  }
  /// The entry in `slot`, if any, is owed a visit: between passes because its request ended, or in a
  /// pass because its visit could not finish.
  action owe(slot: int): bool = all {tick, t.phase == "rest" or (t.phase == "visits" and t.passed.contains(slot)),
    parks(t, slot) or slot == 0,
    t' = {...t, due: if (parks(t, slot)) t.due.union(Set(slot)) else t.due, ev: event("owe", "", slot)}
  }
  action oweAll = all {tick, t.phase == "rest", t' = {...owedAll(t), ev: event("oweAll", "", 0)}}
  /// `fill` departed as the owner sees it: its followers are owed a visit, and every entry while some
  /// entry is untracked.
  action departed(fill: int): bool = {
    val k = placeOf(t, fill)
    all {tick, t.phase == "rest", fill == 0 or SLOTS.exists(slot => t.fills.get(slot) == fill),
      t' = if (untracked(t) != Set()) {...owedAll(t), ev: event("departed", "all", fill)}
        else if (k != Set()) {...owedFollowers(t, lowest(k)), ev: event("departed", "followers", fill)}
        else {...t, ev: event("departed", "none", fill)}
    }
  }
  /// This pass's check found the fill of the entry in `slot` no longer pending.
  action oweFillOf(slot: int): bool = all {tick, t.phase == "checks", t.checked.contains(slot), parks(t, slot),
    t' = if (t.places.get(slot) >= 0 and untracked(t) == Set())
        {...owedFollowers(t, t.places.get(slot)), ev: event("oweFillOf", "followers", slot)}
      else {...owedAll(t), ev: event("oweFillOf", "all", slot)}
  }
  /// A check or visit of this pass found the fill of the entry in `slot` pending.
  action notePending(slot: int): bool = {
    val k = t.places.get(slot)
    all {tick, parks(t, slot), (t.phase == "checks" and t.checked.contains(slot)) or (t.phase == "visits" and t.passed.contains(slot)),
      t' = {...t, tracked: if (k >= 0) t.tracked.set(k, {...t.tracked.get(k), pending: true}) else t.tracked,
        ev: event("notePending", "", slot)}
    }
  }
  /// A check period passes.
  action elapse = all {tick, t.phase == "rest", not(t.elapsed), t' = {...t, elapsed: true, ev: event("elapse", "", 0)}}
  /// A turn's pass starts under the owner's read admission: a changed admission owes every entry, a due
  /// check marks the watched fills, and the pass's check share is set.
  action beginPass(admits: bool): bool = {
    val a = if (admits != t.admits) {...owedAll(t), admits: admits} else t
    val starts = a.checking == Set() and checkDue(a)
    val b = if (not(starts)) a
      else if (untracked(a) == Set())
        {...a, elapsed: false, checking: PLACES.filter(k => a.tracked.get(k).fill >= 0 and not(a.tracked.get(k).reported))}
      else {...owedAll(a), elapsed: false}
    val c = if (b.checking != Set()) {...b, elapsed: false} else b
    val odd = if (c.due == Set()) c.odd else not(c.odd)
    val share = if (c.due == Set()) WAKE else WAKE / 2 + (if (WAKE % 2 == 1 and odd) 1 else 0)
    all {tick,
      t' = {...c, odd: odd, pass: if (share < c.checking.size()) share else c.checking.size(), visits: 0, phase: "checks",
        checked: Set(), passed: Set(), tracked: c.tracked.keys().mapBy(k => {...c.tracked.get(k), pending: false}),
        ev: event("beginPass", if (admits) "admits" else "refuses", 0)}
    }
  }
  /// The check under way observes its next fill through one of that fill's followers.
  action check = {
    val k = lowest(t.checking)
    val slot = lowest(members(t, k))
    all {tick, t.phase == "checks",
      t' = if (t.checking != Set() and t.visits < t.pass)
          {...t, checking: t.checking.exclude(Set(k)), visits: t.visits + 1, checked: t.checked.union(Set(slot)),
            ev: event("check", "slot", slot)}
        else {...t, ev: event("check", "none", 0)}
    }
  }
  /// The pass turns from its checks to the visits it owes now.
  action beginVisits = {
    val limit = t.visits + t.due.size()
    all {tick, t.phase == "checks", t' = {...t, pass: if (WAKE < limit) WAKE else limit, phase: "visits", ev: event("beginVisits", "", 0)}}
  }
  /// The pass visits the next owed entry from the cursor, wrapping.
  action visit = {
    val ahead = t.due.filter(slot => slot >= t.cursor)
    val slot = if (ahead != Set()) lowest(ahead) else lowest(t.due)
    all {tick, t.phase == "visits",
      t' = if (t.visits < t.pass and t.due != Set())
          {...t, due: t.due.exclude(Set(slot)), cursor: slot + 1, visits: t.visits + 1, passed: t.passed.union(Set(slot)),
            repeated: t.repeated or t.passed.contains(slot), unowed: t.unowed or not(t.due.contains(slot)),
            wrapped: slot < t.cursor,
            ev: event("visit", "slot", slot)}
        else {...t, ev: event("visit", "none", 0)}
    }
  }

  /// A pass's checks and visits together stay within the wake allowance.
  val WithinWake = t.visits <= WAKE
  /// A pass visits each entry at most once.
  val OncePerPass = not(t.repeated)
  /// Only parked entries are owed a visit, and a check under way names only watched fills.
  val OwedIsParked = t.due.subseteq(parkedSlots(t)) and
    t.checking.forall(k => t.tracked.get(k).fill >= 0 and not(t.tracked.get(k).reported))
  /// A fill's departure leaves every follower of that fill owed a visit, and every entry while some entry is
  /// untracked.
  val DepartureOwesFollowers = t.ev.act == "departed" implies SLOTS.forall(slot =>
    (parks(t, slot) and (t.fills.get(slot) == t.ev.idx or untracked(t) != Set())) implies t.due.contains(slot))
  /// A pass visits only entries owed a visit.
  val OnlyOwedVisited = not(t.unowed)
  val safety = WithinWake and OncePerPass and OwedIsParked and DepartureOwesFollowers and OnlyOwedVisited

  val witnessPlaced = t.ev.res == "placed"
  val witnessFollowed = t.ev.res == "followed"
  val witnessUntracked = t.ev.res == "untracked"
  val witnessTaken = t.ev.act == "take"
  val witnessPlaceFreed = t.ev.act == "take" and t.ev.res == "freed"
  val witnessOwed = t.ev.act == "owe" and t.due.contains(t.ev.idx)
  val witnessOweEmpty = t.ev.act == "owe" and not(parks(t, t.ev.idx))
  val witnessOweAll = t.ev.act == "oweAll" and t.due.size() >= 2
  val witnessDepartedFollowers = t.ev.act == "departed" and t.ev.res == "followers"
  val witnessDepartedAll = t.ev.act == "departed" and t.ev.res == "all"
  val witnessDepartedNone = t.ev.act == "departed" and t.ev.res == "none"
  val witnessOweFillFollowers = t.ev.act == "oweFillOf" and t.ev.res == "followers"
  val witnessOweFillAll = t.ev.act == "oweFillOf" and t.ev.res == "all"
  val witnessPending = t.ev.act == "notePending" and t.places.get(t.ev.idx) >= 0
  val witnessElapsed = t.ev.act == "elapse"
  val witnessCheckStarts = t.ev.act == "beginPass" and t.checking != Set()
  val witnessCheckOwesAll = t.ev.act == "beginPass" and untracked(t) != Set() and t.due == parkedSlots(t) and not(t.elapsed)
  val witnessAdmissionChanged = t.ev.act == "beginPass" and t.ev.res == "refuses" and t.due != Set()
  val witnessHalfShare = t.ev.act == "beginPass" and t.checking.size() >= 2 and t.pass == 1
  val witnessChecked = t.ev.act == "check" and t.ev.res == "slot"
  val witnessCheckContinues = t.ev.act == "check" and t.ev.res == "none" and t.checking != Set()
  val witnessVisited = t.ev.act == "visit" and t.ev.res == "slot"
  val witnessVisitWraps = t.ev.act == "visit" and t.ev.res == "slot" and t.wrapped
  val witnessAllowanceSpent = t.ev.act == "visit" and t.ev.res == "none" and t.due != Set() and t.visits == WAKE
  val witnessIdlePass = t.ev.act == "beginVisits" and t.pass == 0 and parkedSlots(t) != Set()
  val witnessPassEnds = t.ev.act == "endPass"

  /// The turn's pass is over.
  action endPass = all {tick, t.phase == "visits", t' = {...t, phase: "rest", ev: event("endPass", "", 0)}}

  /// Two picks parameterize every action, so a step has ten picks for each of its thirteen choices. A
  /// GET parks in the lowest free slot, behind that slot's own fill or behind fill 1.
  action step = {
    nondet a = SLOTS.oneOf()
    nondet b = Set(true, false).oneOf()
    any {all {a == lowest(SLOTS.exclude(parkedSlots(t))), park(a, if (b) a else 1)}, take(a), owe(a), oweAll, departed(a),
      oweFillOf(a), notePending(a), elapse, beginPass(b), check, beginVisits, visit, endPass}
  }
}
