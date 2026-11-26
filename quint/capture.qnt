/// A finite capture of three RAM slots and four payload units. Each entry owns one unit.
/// Publication gives a bound entry its insertion step. Removal saves an unvisited snapshot
/// member before a separate release returns its unit. Recovery reserves every admitted unit and records its turn in
/// `loadTurn`, so the load's own state is the one whose installed entries `LoadRetains` reads.
module capture {
  const BOUND: int
  type Entry = {slot: int, key: int, unit: int, insert: int, id: int}
  type State = {
    live: Set[Entry], bound: Set[Entry], retiring: Set[Entry], free: Set[int], clock: int,
    t0: int, cursor: int, snapshot: Set[Entry], side: Set[Entry], out: Set[Entry],
    checkpoint: Set[Entry], phase: str, abandoned: bool, loaded: bool, alarm: bool,
    ledgerFree: int, ledgerOwned: int, loadTurn: int
  }
  var st: State
  var turn: int
  pure val SLOTS = Set(0, 1, 2)
  pure val UNITS = Set(0, 1, 2, 3)
  pure val CAP = 2
  action init = all {
    st' = {live:Set(),bound:Set(),retiring:Set(),free:UNITS,clock:0,t0:0,cursor:0,snapshot:Set(),side:Set(),out:Set(),
      checkpoint:Set(),phase:"idle",abandoned:false,loaded:false,alarm:false,ledgerFree:4,ledgerOwned:0,loadTurn:-1},
    turn' = 0
  }
  action tick = all {turn < BOUND, turn' = turn + 1}
  action bind(slot:int, unit:int): bool = all {
    tick, SLOTS.contains(slot), st.free.contains(unit), st.free.size() > 1,
    st.phase != "recovering" or st.loaded,
    not(st.live.union(st.bound).union(st.retiring).exists(e => e.slot == slot)),
    st' = {...st, bound:st.bound.union(Set({slot:slot,key:slot,unit:unit,insert:0,id:turn+1})),
      free:st.free.exclude(Set(unit)),ledgerFree:st.ledgerFree-1,ledgerOwned:st.ledgerOwned+1}
  }
  action publish(slot:int): bool = {
    nondet e = st.bound.filter(e => e.slot == slot).oneOf()
    all {tick,
      st' = {...st,bound:st.bound.exclude(Set(e)),live:st.live.union(Set({...e,insert:st.clock+1})),clock:st.clock+1}
    }
  }
  action start = all {
    tick, st.phase == "idle",
    st' = {...st,t0:st.clock,snapshot:st.live,phase:"capture",cursor:0,side:Set(),out:Set(),checkpoint:Set(),abandoned:false,loaded:false,alarm:false}
  }
  action remove(slot:int): bool = {
    nondet e = st.live.filter(e => e.slot == slot).oneOf()
    val save = st.phase == "capture" and not(st.abandoned) and e.insert <= st.t0 and e.slot >= st.cursor
    val grown = if (save) st.side.union(Set(e)) else st.side
    all {tick,
      st' = {...st,live:st.live.exclude(Set(e)),retiring:st.retiring.union(Set(e)),
        side:if (grown.size() > CAP) st.side else grown,abandoned:st.abandoned or grown.size() > CAP}
    }
  }
  action release(slot:int): bool = {
    nondet e = st.retiring.filter(e => e.slot == slot).oneOf()
    all {tick,
      st' = {...st,retiring:st.retiring.exclude(Set(e)),
        free:st.free.union(Set(e.unit)),ledgerFree:st.ledgerFree+1,ledgerOwned:st.ledgerOwned-1}
    }
  }
  action scan = {
    val rows = st.live.filter(e => e.slot == st.cursor and e.insert <= st.t0)
    all {tick, st.phase == "capture", not(st.abandoned), st.cursor < 3,
      st' = {...st,cursor:st.cursor+1,out:st.out.union(rows)}
    }
  }
  action complete = all {
    tick, st.phase == "capture", not(st.abandoned), st.cursor == 3,
    st' = {...st,checkpoint:st.out.union(st.side),phase:"done"}
  }
  action crash = all {
    tick, st.phase == "done",
    st' = {...st,live:Set(),bound:Set(),retiring:Set(),free:UNITS,ledgerFree:4,ledgerOwned:0,phase:"recovering"}
  }
  pure def exclusive(es:Set[Entry]):bool = es.forall(a => es.forall(b => a == b or
    (a.slot != b.slot and a.key != b.key and a.unit != b.unit)))
  action load = {
    val valid = exclusive(st.checkpoint) and st.checkpoint.forall(e => UNITS.contains(e.unit)) and st.checkpoint.size() <= 3
    val alarm = not(valid)
    val admitted = if (valid) st.checkpoint else Set()
    val units = admitted.map(e => e.unit)
    all {tick, st.phase == "recovering", not(st.loaded),
      st' = {...st,loaded:true,alarm:alarm,bound:admitted,free:UNITS.exclude(units),ledgerFree:4-units.size(),ledgerOwned:units.size(),
        loadTurn:turn+1}
    }
  }
  val CaptureConsistent = st.out.intersect(st.side) == Set() and
    (Set("done", "recovering").contains(st.phase) implies st.checkpoint == st.snapshot)
  val UnitsExclusive = exclusive(st.live.union(st.bound).union(st.retiring)) and exclusive(st.out.union(st.side)) and exclusive(st.checkpoint)
  val ownedUnits = st.live.union(st.bound).union(st.retiring).map(e => e.unit)
  val LedgerConserved = st.ledgerFree + st.ledgerOwned == 4 and st.ledgerFree == st.free.size() and
    st.ledgerOwned == ownedUnits.size() and ownedUnits.union(st.free) == UNITS and ownedUnits.intersect(st.free) == Set()
  val LoadGuardNeverFires = not(st.alarm)
  val SideBounded = st.side.size() <= CAP
  /// In the state a load produces, the bound entries it installed are exactly the completed checkpoint; a load that
  /// installs any other set, an empty one or one with another incarnation included, fails even when it raises no
  /// alarm. Later binds, publishes and removals change `bound`, so the comparison holds in the load's state alone.
  val LoadRetains = st.loadTurn == turn implies st.bound == st.checkpoint
  val safety = CaptureConsistent and UnitsExclusive and LedgerConserved and LoadGuardNeverFires and SideBounded
    and LoadRetains
  val witnessLoaded = st.loaded and st.checkpoint.size() == 1 and st.bound == st.checkpoint
  val witnessAbandoned = st.abandoned
  val witnessBoundExcluded = st.loaded and st.snapshot.size() == 0 and st.clock > st.t0
  action step = {
    nondet slot = SLOTS.oneOf()
    nondet unit = UNITS.oneOf()
    any {bind(slot,unit),publish(slot),start,remove(slot),release(slot),scan,complete,crash,load}
  }
}
