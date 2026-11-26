/// The extent allocator of one volume: eight units, an index of at most two runs, reservations of one to three units.
/// Each step is one reservation or one return. A run is a length and a start, ordered by length and then start, as the index keys are.
module extent {
  const BOUND: int
  type Run = {len: int, start: int}
  type Event = {act: str, res: str, start: int, len: int}
  type State = {free: Set[int], index: Set[Run], drops: int, held: Set[Run], misplaced: bool, ev: Event}
  var st: State
  var turn: int
  pure val N = 8
  pure val UNITS = 0.to(N - 1)
  pure val CAP = 2
  pure def units(r: Run): Set[int] = UNITS.filter(u => r.start <= u and u < r.start + r.len)
  /// The free units from `u` upward and from `u - 1` downward, counted until the first taken unit or the volume's edge.
  pure def freeAfter(f: Set[int], u: int): int = 1.to(N).filter(k => 0.to(k - 1).forall(i => f.contains(u + i))).size()
  pure def freeBefore(f: Set[int], u: int): int = 1.to(N).filter(k => 1.to(k).forall(i => f.contains(u - i))).size()
  /// The maximal free runs of a free set.
  pure def runs(f: Set[int]): Set[Run] =
    f.filter(u => not(f.contains(u - 1))).map(u => {len: freeAfter(f, u), start: u})
  pure def below(a: Run, b: Run): bool = a.len < b.len or (a.len == b.len and a.start < b.start)
  pure def least(s: Set[Run]): Run = s.fold({len: N + 1, start: N}, (m, a) => if (below(a, m)) a else m)
  pure def lowest(s: Set[Run]): Run = s.fold({len: 0, start: N}, (m, a) => if (a.start < m.start) a else m)
  /// A free run is offered to the index: a full index counts a drop and keeps the larger of the run and its smallest entry.
  pure def offered(s: State, r: Run): State =
    if (r.len == 0) s
    else if (s.index.size() < CAP) {...s, index: s.index.union(Set(r))}
    else if (below(r, least(s.index))) {...s, drops: s.drops + 1}
    else {...s, drops: s.drops + 1, index: s.index.exclude(Set(least(s.index))).union(Set(r))}
  pure def note(s: State, act: str, res: str, start: int, len: int): State =
    {...s, ev: {act: act, res: res, start: start, len: len}}
  /// A reservation of `n` units: the smallest indexed run that holds it, else the lowest run that holds it, else no fit.
  pure def reserved(s: State, n: int): State = {
    val fitting = runs(s.free).filter(r => r.len >= n)
    val indexed = s.index.filter(r => r.len >= n)
    val best = least(indexed)
    val first = lowest(fitting)
    val from = if (indexed.size() > 0) best else first
    val rest = {len: from.len - n, start: from.start + n}
    val taken = {...s, free: s.free.exclude(units({len: n, start: from.start})),
      held: s.held.union(Set({len: n, start: from.start})),
      misplaced: s.misplaced or
        (if (indexed.size() > 0) indexed.exists(r => below(r, from)) else fitting.exists(r => r.start < from.start))}
    if (fitting.size() == 0) note(s, "reserve", "NoFit", 0, n)
    else if (indexed.size() > 0)
      note({...taken, index: taken.index.exclude(Set(from)).union(if (rest.len > 0) Set(rest) else Set())},
        "reserve", "Indexed", from.start, n)
    else note(offered(taken, rest), "reserve", "Fallback", from.start, n)
  }
  /// A return of the extent `start..start + len`: refused unless every unit is taken, else joined with its free neighbours.
  pure def released(s: State, start: int, len: int): State = {
    val extent = {len: len, start: start}
    val end = start + len
    val low = start - freeBefore(s.free, start)
    val high = end + freeAfter(s.free, end)
    val freed = {...s, free: s.free.union(units(extent)), held: s.held.exclude(Set(extent))}
    val apart = {...freed, index: freed.index.exclude(Set({len: start - low, start: low}, {len: high - end, start: end}))}
    if (end > N or units(extent).exists(u => s.free.contains(u))) note(s, "release", "NotHeld", start, len)
    else if (low == start and high == end) note(offered(freed, extent), "release", "Alone", start, len)
    else note(offered(apart, {len: high - low, start: low}), "release", "Joined", start, len)
  }
  action init = all {
    st' = {free: UNITS, index: Set({len: N, start: 0}), drops: 0, held: Set(), misplaced: false,
      ev: {act: "init", res: "", start: 0, len: 0}},
    turn' = 0
  }
  action tick = all {turn < BOUND, turn' = turn + 1}
  action reserve(n: int): bool = all {tick, st' = reserved(st, n)}
  /// The caller returns an extent it holds, or names one that covers a free unit or passes the volume's end.
  action release(start: int, len: int): bool = all {tick,
    st.held.contains({len: len, start: start}) or start + len > N or
      units({len: len, start: start}).exists(u => st.free.contains(u)),
    st' = released(st, start, len)}
  val IndexNamesMaximalRuns = st.index.subseteq(runs(st.free))
  val NoDropsMeansWholeFreeSet = st.drops == 0 implies st.index == runs(st.free)
  val IndexWithinCapacity = st.index.size() <= CAP
  val PlacementFollowsFit = not(st.misplaced)
  val HeldDisjoint = and {
    st.held.forall(a => a.start + a.len <= N and st.held.forall(b => a == b or units(a).intersect(units(b)) == Set())),
    st.free == UNITS.filter(u => st.held.forall(r => not(units(r).contains(u)))),
  }
  val safety = IndexNamesMaximalRuns and NoDropsMeansWholeFreeSet and IndexWithinCapacity and PlacementFollowsFit and
    HeldDisjoint
  val witnessIndexed = st.ev.res == "Indexed"
  val witnessIndexedExact = st.ev.res == "Indexed" and st.index.size() == 0 and st.free.size() > 0
  val witnessBestBeatsLowest = st.ev.res == "Indexed" and runs(st.free).exists(r => r.start < st.ev.start and r.len >= st.ev.len)
  val witnessFallback = st.ev.res == "Fallback"
  val witnessNoFit = st.ev.res == "NoFit"
  val witnessNoFitWithFree = st.ev.res == "NoFit" and st.free.size() >= st.ev.len
  val witnessAlone = st.ev.res == "Alone"
  val witnessJoined = st.ev.res == "Joined"
  val witnessJoinedBothSides = st.ev.res == "Joined" and st.free.contains(st.ev.start - 1) and st.free.contains(st.ev.start + st.ev.len)
  val witnessNotHeld = st.ev.res == "NotHeld"
  val witnessDropped = st.drops > 0
  val witnessDropKeepsOffered = st.drops > 0 and st.ev.act == "release" and
    st.index.exists(r => units(r).contains(st.ev.start))
  val witnessDropLeavesOut = st.drops > 0 and st.index != runs(st.free)
  val witnessWholeAgain = st.drops > 0 and st.index == runs(st.free) and st.free == UNITS
  action someReserve = {
    nondet n = Set(1, 2, 3).oneOf()
    reserve(n)
  }
  action someRelease = {
    nondet start = 0.to(N).oneOf()
    nondet len = Set(1, 2, 3).oneOf()
    release(start, len)
  }
  action step = any {someReserve, someRelease}
}
