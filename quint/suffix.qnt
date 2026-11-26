/// One tenure chain's mutation suffix over a delta region of `J` blocks against the preservation model's frontier: a
/// tenure appends INSERT, REMOVE and REPLACE records to the open block, seals blocks that take the next LSN and
/// reach the medium as attempts that land or stay pending, publishes a cut that the replay starts from, raises the
/// certified end to the durable prefix, runs a capture pass whose cut is sealed at its start and published after
/// recorded removals, keeps the head at most `UNCERTIFIED` blocks past the certified end, and loses the host; the successor's fence ends every pending attempt and
/// its recovery replays the checkpoint then every block from the cut. Replay checks each block before any record
/// applies: a block of another LSN on the unit, a damaged block or a missing one is a hole. Tombstones of whole
/// records exclude whatever the holes; inserts apply only up to their suffix's first hole; a record split across two
/// blocks is whole only when both are valid; two live owners of a unit are both withheld. A unit holds one block at a
/// time, so a tenure uses only LSNs below the floor of required history plus `J`, and refuses an append at the
/// reserved end. An evicted entry's payload unit stays held until its tombstone's block is durable, and a fill writes
/// its payload at issue. A planned exit (`drainStep`) stops fills, publishes the drain's checkpoint at the head,
/// keeps appending REMOVEs, stops all mutations with the open block sealed, and transfers once the certified end
/// reaches the head; the recovery after the transfer replays that checkpoint and suffix, and before the transfer the
/// exit may resume in place.
module suffix {
  const BOUND: int
  /// The most blocks the head runs past the certified end: an append whose last block reaches the certified end plus
  /// this is refused before its acknowledgment.
  const UNCERTIFIED: int
  pure val KEYS = Set(1, 2)
  pure val UNITS = Set(1, 2)
  pure val J = 4
  pure val RESERVE = 3

  /// An INSERT of `key` on `unit` with incarnation `id`, a REMOVE of incarnation `old` on `oldUnit`, or a REPLACE
  /// whose REMOVE half is `old` on `oldUnit` and INSERT half is `(key, unit, id)`. `split` marks a record whose last
  /// part lies in the next block.
  type Mutation = { kind: str, key: int, unit: int, id: int, old: int, oldUnit: int, split: bool }
  type Block = { lsn: int, session: int, recs: List[Mutation], damaged: bool }
  /// One tenure's suffix as the store records it: its session, first LSN, certified end and reserved end.
  type Suffix = { session: int, start: int, certified: int, end: int }

  var session: int
  var live: Set[Mutation]
  var ever: Set[Mutation]
  var nextId: int
  /// The open block's LSN and record, the reserved end, the capacity and the tenure's first LSN.
  var lsnHead: int
  var open: List[Mutation]
  var reserved: int
  var capacity: int
  var start: int
  /// The region by unit `lsn % J`, the sealed blocks whose attempts are pending, and the LSN of the block the last
  /// landing replaced.
  var region: int -> Block
  var pending: Set[Block]
  var replaced: int
  var durable: int
  var certified: int
  /// The suffixes of earlier tenures that end above the cut, oldest first.
  var chain: List[Suffix]
  var cut: int
  var base: Set[Mutation]
  /// An in-flight capture pass: the cut sealed at its start, -1 for none, and its snapshot, the live set then.
  var passCut: int
  var passBase: Set[Mutation]
  /// Payload units whose tombstone's block is not yet durable, and the incarnation whose payload each unit holds.
  var held: Set[int]
  var payload: int -> int
  /// The live set after each sealed block's record, by the LSN of the record's last block, and the live set at the
  /// last completed block.
  var liveAt: int -> Set[Mutation]
  var durableLive: Set[Mutation]
  /// The lost tenure's `durableLive` as the last recovery read it.
  var before: Set[Mutation]
  /// Ghost: the ids an acknowledged tombstone removed, the first and last block LSNs of every tombstone of each id, a
  /// resurrected entry's later REMOVE included, each insert's block, and the LSN of every block a fault damaged,
  /// which a later landing on that block's unit keeps.
  var removedIds: Set[int]
  var tombAt: int -> Set[(int, int)]
  var insAt: int -> int
  var damagedLsns: Set[int]
  /// Ghost: the planned exit published its checkpoint after fills stopped. A resume, a host loss and a recovery end
  /// the exit and clear it.
  var drainPublished: bool
  /// The state an action starts from, for `RefusalChangesNothing`.
  var prior: (Set[Mutation], Set[int], List[Mutation], int, int)
  var phase: str
  var recovered: Set[Mutation]
  var damage: bool
  var conflict: bool
  var excludedIds: Set[int]
  var supersededIds: Set[int]
  var droppedIds: Set[int]
  var turn: int
  var ev: str

  pure val none = { lsn: -1, session: 0, recs: [], damaged: false }
  pure val noRec = { kind: "", key: 0, unit: 0, id: 0, old: 0, oldUnit: 0, split: false }

  action init = all {
    session' = 2, live' = Set(), ever' = Set(), nextId' = 1, lsnHead' = 0, open' = [], reserved' = RESERVE, capacity' = J,
    start' = 0, region' = 0.to(J - 1).mapBy(u => none), pending' = Set(), replaced' = -1, durable' = 0, certified' = 0,
    chain' = [], cut' = 0, base' = Set(), passCut' = -1, passBase' = Set(), held' = Set(), payload' = UNITS.mapBy(u => 0), liveAt' = Map(), durableLive' = Set(), before' = Set(),
    phase' = "serving", recovered' = Set(),
    damage' = false, conflict' = false, excludedIds' = Set(), supersededIds' = Set(), droppedIds' = Set(),
    removedIds' = Set(), tombAt' = Map(), insAt' = Map(), damagedLsns' = Set(), drainPublished' = false,
    prior' = (Set(), Set(), [], 0, 0), turn' = 0,
    ev' = "init",
  }
  action tick(act: str): bool = all {
    turn < BOUND, turn' = turn + 1, ev' = act, prior' = (live, held, open, lsnHead, reserved),
  }
  action sameLog = all { lsnHead' = lsnHead, open' = open, reserved' = reserved, capacity' = capacity, start' = start }
  action sameMedia = all {
    region' = region, pending' = pending, replaced' = replaced, durable' = durable, certified' = certified,
    liveAt' = liveAt, durableLive' = durableLive, before' = before,
  }
  action sameStore = all {
    chain' = chain, cut' = cut, base' = base, passCut' = passCut, passBase' = passBase, recovered' = recovered, damage' = damage, conflict' = conflict, excludedIds' = excludedIds,
    supersededIds' = supersededIds, droppedIds' = droppedIds, session' = session,
  }
  /// The store's record and the planned exit's ghost, which a publish, a resume, a host loss and a recovery write.
  action sameRecord = all { sameStore, drainPublished' = drainPublished }
  action sameGhost = all { removedIds' = removedIds, tombAt' = tombAt, insAt' = insAt, damagedLsns' = damagedLsns }
  action sameLive = all { live' = live, ever' = ever, nextId' = nextId, held' = held, payload' = payload, sameGhost }
  action refuse(act: str): bool = all { tick(act), sameLog, sameMedia, sameRecord, sameLive, phase' = phase }

  val owned = live.map(r => r.unit).union(held)
  /// The units the completion of `b` releases: those of the tombstones whose record's last part lies in `b`, which
  /// for a split record is the record of the block before.
  def releases(b: Block): Set[int] = {
    val prior = region.get((b.lsn + J - 1) % J)
    val own = b.recs.foldl(Set(), (acc, r) => if (r.kind != "ins" and not(r.split)) acc.union(Set(r.oldUnit)) else acc)
    if (b.lsn > 0 and prior.lsn == b.lsn - 1)
      own.union(prior.recs.foldl(Set(), (acc, r) => if (r.kind != "ins" and r.split) acc.union(Set(r.oldUnit)) else acc))
    else own
  }
  /// The tenure appends while it serves and, during a planned exit, REMOVEs until all mutations stop; its blocks
  /// land, complete and certify, and its host may be lost, until the transfer.
  def appending: bool = Set("serving", "fillsStopped", "published").contains(phase)
  def tenureOpen: bool = Set("serving", "fillsStopped", "published", "sealed").contains(phase)
  def fits(r: Mutation): bool = {
    val last = if (r.split) lsnHead + 1 else lsnHead
    last < reserved and last < certified + UNCERTIFIED
  }

  /// Stages `r` as the open block's one record; the caller refuses a record that does not fit before calling.
  action stage(r: Mutation, act: str): bool = all {
    appending, open.length() == 0, tick(act), phase' = phase, sameMedia, sameRecord,
    open' = [r], lsnHead' = lsnHead, reserved' = reserved, capacity' = capacity, start' = start,
  }
  action fill(k: int, u: int, split: bool): bool = {
    val r = { kind: "ins", key: k, unit: u, id: nextId, old: 0, oldUnit: 0, split: split }
    all {
      phase == "serving", open.length() == 0, not(owned.contains(u)), live.forall(x => x.key != k),
      if (not(fits(r))) refuse("refusedRange")
      else all {
        stage(r, "fill"), live' = live.union(Set(r)), ever' = ever.union(Set(r)), nextId' = nextId + 1, held' = held,
        sameGhost,
        payload' = payload.set(u, r.id),
      },
    }
  }
  action evict(r: Mutation): bool = {
    val t = { kind: "rem", key: r.key, unit: r.unit, id: 0, old: r.id, oldUnit: r.unit, split: false }
    all {
      appending, open.length() == 0, live.contains(r),
      if (not(fits(t))) refuse("refusedRange")
      else all {
        stage(t, "evict"), live' = live.exclude(Set(r)), ever' = ever, nextId' = nextId, payload' = payload,
        held' = held.union(Set(r.unit)), removedIds' = removedIds.union(Set(r.id)), tombAt' = tombAt, insAt' = insAt,
        damagedLsns' = damagedLsns,
      },
    }
  }
  action replace(r: Mutation, u: int, split: bool): bool = {
    val n = { kind: "rep", key: r.key, unit: u, id: nextId, old: r.id, oldUnit: r.unit, split: split }
    all {
      phase == "serving", open.length() == 0, live.contains(r), not(owned.contains(u)),
      if (not(fits(n))) refuse("refusedRange")
      else all {
        stage(n, "replace"), live' = live.exclude(Set(r)).union(Set(n)), ever' = ever.union(Set(n)),
        nextId' = nextId + 1, held' = held.union(Set(r.unit)), payload' = payload.set(u, n.id),
        removedIds' = removedIds.union(Set(r.id)), tombAt' = tombAt, insAt' = insAt, damagedLsns' = damagedLsns,
      },
    }
  }
  /// The open block takes the head LSN and its attempt is pending; a split record's second block follows it.
  action seal: bool = {
    val blocks = if (open[0].split) 2 else 1
    all {
      appending, open.length() == 1, tick("seal"), phase' = phase, sameRecord,
      live' = live, ever' = ever, nextId' = nextId, held' = held, payload' = payload, removedIds' = removedIds,
      damagedLsns' = damagedLsns,
      tombAt' = if (open[0].kind == "ins") tombAt
        else if (tombAt.keys().contains(open[0].old))
          tombAt.setBy(open[0].old, ts => ts.union(Set((lsnHead, lsnHead + blocks - 1))))
        else tombAt.put(open[0].old, Set((lsnHead, lsnHead + blocks - 1))),
      insAt' = if (open[0].kind != "rem") insAt.put(open[0].id, lsnHead) else insAt,
      lsnHead' = lsnHead + blocks, open' = [], reserved' = reserved, capacity' = capacity, start' = start,
      region' = region, replaced' = replaced, durable' = durable, certified' = certified, durableLive' = durableLive,
      before' = before, liveAt' = liveAt.put(lsnHead + blocks - 1, live),
      pending' = pending.union(Set({ lsn: lsnHead, session: session, recs: open, damaged: false }))
        .union(if (blocks == 2) Set({ lsn: lsnHead + 1, session: session, recs: [], damaged: false }) else Set()),
    }
  }
  /// A pending attempt lands on its unit; `complete` is the landing of the lowest pending block that the tenure
  /// learns of, so the durable prefix passes it and its tombstones release their units.
  action land(b: Block): bool = all {
    pending.contains(b), tick("land"), phase' = phase, sameLog, sameRecord, sameLive,
    region' = region.set(b.lsn % J, b), replaced' = region.get(b.lsn % J).lsn, pending' = pending.exclude(Set(b)),
    durable' = durable, certified' = certified, liveAt' = liveAt, durableLive' = durableLive, before' = before,
  }
  action complete(b: Block): bool = all {
    tenureOpen, pending.contains(b), b.lsn == durable, tick("complete"), phase' = phase, sameLog, sameRecord,
    region' = region.set(b.lsn % J, b), replaced' = region.get(b.lsn % J).lsn, pending' = pending.exclude(Set(b)),
    durable' = durable + 1, certified' = certified, liveAt' = liveAt, before' = before,
    durableLive' = if (liveAt.keys().contains(b.lsn)) liveAt.get(b.lsn) else durableLive,
    live' = live, ever' = ever, nextId' = nextId, payload' = payload, sameGhost,
    held' = held.exclude(releases(b)),
  }
  action certify: bool = all {
    tenureOpen, certified < durable, tick("certify"), phase' = phase, sameLog, sameRecord, sameLive,
    region' = region, pending' = pending, replaced' = replaced, durable' = durable, certified' = durable,
    liveAt' = liveAt, durableLive' = durableLive, before' = before,
  }
  action extend: bool = all {
    appending, reserved < capacity, tick("extend"), phase' = phase, sameMedia, sameRecord, sameLive,
    lsnHead' = lsnHead, open' = open, reserved' = reserved + 1, capacity' = capacity, start' = start,
  }
  /// A capture publishes: the cut is the head with the open block sealed, and the checkpoint is the live set, which
  /// is then durable evidence of the membership at the cut. It runs only with no pass in flight, so no pass
  /// publishes a cut below one already published. A publish after a planned exit stopped fills is that drain's
  /// acknowledged checkpoint (`published`).
  action publish: bool = all {
    Set("serving", "fillsStopped").contains(phase), open.length() == 0, passCut < 0, tick("publish"),
    phase' = if (phase == "fillsStopped") "published" else phase, sameLive,
    lsnHead' = lsnHead, open' = open, reserved' = reserved, start' = start,
    capacity' = { val raised = (if (lsnHead < start) lsnHead else start) + J
      if (raised > capacity) raised else capacity },
    region' = region, pending' = pending, replaced' = replaced, durable' = durable, certified' = certified,
    liveAt' = liveAt.keys().filter(l => l >= lsnHead).mapBy(l => liveAt.get(l)), durableLive' = live, before' = before,
    cut' = lsnHead, base' = live, passCut' = passCut, passBase' = passBase, recovered' = recovered, damage' = damage,
    conflict' = conflict, excludedIds' = excludedIds, supersededIds' = supersededIds, droppedIds' = droppedIds,
    session' = session, chain' = chain.foldl([], (kept, sfx) => if (sfx.end <= lsnHead) kept else kept.append(sfx)),
    drainPublished' = phase == "fillsStopped",
  }
  /// A capture pass starts: the cut is the head with the open block sealed, and its snapshot is the live set. Every
  /// record after the start, the REMOVEs of snapshot members among them, lies at or above the cut.
  action startPass: bool = all {
    phase == "serving", open.length() == 0, passCut < 0, tick("startPass"), phase' = phase, sameLog, sameMedia,
    sameLive, chain' = chain, cut' = cut, base' = base, recovered' = recovered, damage' = damage, conflict' = conflict,
    excludedIds' = excludedIds, supersededIds' = supersededIds, droppedIds' = droppedIds, session' = session,
    passCut' = lsnHead, passBase' = live, drainPublished' = drainPublished,
  }
  /// The pass publishes its snapshot at its cut, after removals of snapshot members that the suffix recorded above
  /// it; the durable evidence is the snapshot until a block at or above the cut is durable.
  action publishPass: bool = all {
    phase == "serving", passCut >= 0, tick("publishPass"), phase' = phase, sameLive,
    lsnHead' = lsnHead, open' = open, reserved' = reserved, start' = start,
    capacity' = { val raised = (if (passCut < start) passCut else start) + J
      if (raised > capacity) raised else capacity },
    region' = region, pending' = pending, replaced' = replaced, durable' = durable, certified' = certified,
    liveAt' = liveAt.keys().filter(l => l >= passCut).mapBy(l => liveAt.get(l)),
    durableLive' = if (durable > passCut) durableLive else passBase, before' = before,
    cut' = passCut, base' = passBase, passCut' = -1, passBase' = Set(), recovered' = recovered, damage' = damage,
    conflict' = conflict, excludedIds' = excludedIds, supersededIds' = supersededIds, droppedIds' = droppedIds,
    session' = session, chain' = chain.foldl([], (kept, sfx) => if (sfx.end <= passCut) kept else kept.append(sfx)),
    drainPublished' = drainPublished,
  }
  /// A block on the medium below the certified end is damaged, and the ghost records its LSN.
  action corrupt(u: int): bool = all {
    region.get(u).lsn >= 0, region.get(u).lsn < certified, not(region.get(u).damaged), tick("corrupt"),
    phase' = phase, sameLog, sameRecord,
    live' = live, ever' = ever, nextId' = nextId, held' = held, payload' = payload, removedIds' = removedIds,
    tombAt' = tombAt, insAt' = insAt, damagedLsns' = damagedLsns.union(Set(region.get(u).lsn)),
    region' = region.set(u, { ...region.get(u), damaged: true }), pending' = pending, replaced' = replaced,
    durable' = durable, certified' = certified, liveAt' = liveAt, durableLive' = durableLive, before' = before,
  }
  action lose: bool = all {
    tenureOpen, tick("lose"), phase' = "lost", sameLog, sameMedia, sameStore, drainPublished' = false, sameLive,
  }
  /// A planned exit stops fills: fills and REPLACEs are refused, and REMOVEs continue until all mutations stop.
  action stopFills: bool = all {
    phase == "serving", passCut < 0, tick("stopFills"), phase' = "fillsStopped", sameLog, sameMedia, sameRecord, sameLive,
  }
  /// A planned exit that fails before the withdrawal resumes in place and serves its tenure again.
  action resumeDrain: bool = all {
    Set("fillsStopped", "published", "sealed").contains(phase), tick("resumeDrain"), phase' = "serving", sameLog,
    sameMedia, sameStore, drainPublished' = false, sameLive,
  }
  /// After the drain's publish, all mutations stop with the open block sealed.
  action stopMutations: bool = {
    val sealed = open.length() == 0
    all {
      phase == "published", sealed, tick("stopMutations"), phase' = "sealed", sameLog, sameMedia, sameRecord,
      sameLive,
    }
  }
  /// The withdrawal and the transfer write, once the certified end reached the head, the durable end of the sealed
  /// suffix: the target's recovery, or the outgoing owner's same-host restart after a refused or unknown transfer,
  /// replays the drain's checkpoint and that suffix.
  action transfer: bool = {
    val certifiedThroughHead = certified == lsnHead
    all {
      phase == "sealed", certifiedThroughHead, tick("transfer"), phase' = "transferred", sameLog, sameMedia,
      sameRecord, sameLive,
    }
  }
  /// The successor's fence ends every pending attempt; its recovery replays the checkpoint, then every suffix of
  /// the chain from the cut: tombstones of whole blocks exclude, inserts apply up to each suffix's first hole, each
  /// suffix's certified end rises to the blocks the recovery read whole, and its own suffix starts at the
  /// predecessor's reserved end with the floor's capacity.
  action recover: bool = {
    val own = { session: session, start: start, certified: certified, end: reserved }
    val suffixes = chain.append(own)
    def blockAt(l: int): Block = region.get(l % J)
    def valid(sfx: Suffix, l: int): bool =
      blockAt(l).lsn == l and blockAt(l).session == sfx.session and not(blockAt(l).damaged)
    def whole(sfx: Suffix, l: int): bool =
      valid(sfx, l) and blockAt(l).recs.foldl(true, (ok, r) => ok and (not(r.split) or valid(sfx, l + 1)))
    def lsns(sfx: Suffix): Set[int] = (if (sfx.start > cut) sfx.start else cut).to(sfx.end - 1)
    def firstHole(sfx: Suffix): int = lsns(sfx).fold(sfx.end, (h, l) => if (l < h and not(whole(sfx, l))) l else h)
    // The first block of the suffix that is not valid: the hole's physical place, which a split record's missing
    // second block puts one past the record's first.
    def firstInvalid(sfx: Suffix): int = lsns(sfx).fold(sfx.end, (h, l) => if (l < h and not(valid(sfx, l))) l else h)
    def recordsOf(sfx: Suffix, ls: Set[int]): Set[Mutation] =
      ls.filter(l => whole(sfx, l)).fold(Set(), (acc, l) => acc.union(blockAt(l).recs.foldl(Set(), (t, r) => t.union(Set(r)))))
    val levels = 1.to(suffixes.length()).map(k => (k, suffixes[k - 1]))
    val excluded = levels.fold(Set(), (acc, ks) =>
      acc.union(recordsOf(ks._2, lsns(ks._2)).filter(r => r.kind != "ins").map(r => r.old)))
    val inserted = levels.fold(Set(), (acc, ks) => acc.union(
      recordsOf(ks._2, lsns(ks._2).filter(l => l < firstHole(ks._2))).filter(r => r.kind != "rem").map(r => (ks._1, r))))
    val dropped = levels.fold(Set(), (acc, ks) => acc.union(
      recordsOf(ks._2, lsns(ks._2).filter(l => l >= firstHole(ks._2))).filter(r => r.kind != "rem").map(r => r.id)))
    val damaged = suffixes.foldl(false, (d, sfx) => d or firstInvalid(sfx) < sfx.certified)
    val eligible = base.map(r => (0, r)).union(inserted).filter(p => not(excluded.contains(p._2.id)))
    // Of one key, the latest incarnation alone stays a candidate.
    val candidates = eligible.filter(p => eligible.forall(q => q._2.key != p._2.key or q._2.id <= p._2.id))
    val loaded = candidates.filter(p => candidates.forall(q => q == p or q._2.unit != p._2.unit or q._1 < p._1))
    val superseded = eligible.filter(p => not(candidates.contains(p))
      or candidates.exists(q => q._2.unit == p._2.unit and q._1 > p._1))
    val floor = cut
    val capacityNext = (if (floor < reserved) floor else reserved) + J
    all {
      Set("lost", "transferred").contains(phase), tick(if (phase == "transferred") "handoffRecover" else "recover"),
      phase' = "serving",
      pending' = Set(), region' = region, replaced' = replaced, durable' = reserved, certified' = reserved,
      liveAt' = Map(), durableLive' = loaded.map(p => p._2), before' = durableLive,
      chain' = suffixes.foldl([], (acc, sfx) => acc.append({ ...sfx,
        certified: if (firstInvalid(sfx) > sfx.certified) firstInvalid(sfx) else sfx.certified })),
      cut' = cut, base' = base, passCut' = -1, passBase' = Set(), recovered' = loaded.map(p => p._2), damage' = damaged,
      conflict' = loaded.size() + superseded.size() != eligible.size(), excludedIds' = excluded,
      supersededIds' = superseded.map(p => p._2.id), droppedIds' = dropped, session' = session + 2,
      drainPublished' = false,
      live' = loaded.map(p => p._2), ever' = ever, nextId' = nextId, held' = Set(), payload' = payload, sameGhost,
      lsnHead' = reserved, open' = [], capacity' = capacityNext, start' = reserved,
      reserved' = if (reserved + RESERVE < capacityNext) reserved + RESERVE else capacityNext,
    }
  }
  action step = any {
    nondet k = KEYS.oneOf()
    nondet u = UNITS.oneOf()
    nondet split = Set(true, false).oneOf()
    fill(k, u, split),
    nondet r = live.union(Set(noRec)).oneOf()
    nondet u = UNITS.oneOf()
    nondet split = Set(true, false).oneOf()
    any { evict(r), replace(r, u, split) },
    seal,
    nondet b = pending.union(Set(none)).oneOf()
    any { land(b), complete(b) },
    certify,
    extend,
    publish,
    startPass,
    publishPass,
    nondet u = 0.to(J - 1).oneOf()
    corrupt(u),
    lose,
    recover,
  }

  /// The free scheduler with a planned exit: fills stop, the drain's publish, all mutations stop, the transfer, and
  /// a resume before it.
  action drainStep = any { step, stopFills, resumeDrain, stopMutations, transfer }

  /// The block holding LSN `l` is on the medium and undamaged.
  def intact(l: int): bool = region.get(l % J).lsn == l and not(region.get(l % J).damaged)
  /// A tombstone of `id` is whole on the medium: its block and, for a split record, the next one are intact.
  def tombstoned(id: int): bool = 0.to(J - 1).exists(u => {
    val b = region.get(u)
    b.lsn >= 0 and not(b.damaged) and b.recs.foldl(false, (found, r) =>
      found or (r.kind != "ins" and r.old == id and (not(r.split) or intact(b.lsn + 1))))
  })
  /// A block of one of `id`'s tombstones, its first or its last, was damaged at some time, whether or not a later
  /// landing has since replaced it. This is a record of damage to those blocks: it holds from the first such damage
  /// on, for a split tombstone that never became whole too, and does not show that the damage resurrected the entry.
  def tombDamaged(id: int): bool =
    tombAt.keys().contains(id) and tombAt.get(id).exists(t => damagedLsns.contains(t._1) or damagedLsns.contains(t._2))
  /// A recovery took the step: the successor's after a host loss, or the one after a planned transfer.
  val recovering = ev == "recover" or ev == "handoffRecover"
  /// P6: no two recovered entries own one unit or one key.
  val OneOwner = recovered.forall(a => recovered.forall(b => a == b or (a.unit != b.unit and a.key != b.key)))
  /// P5: a recovery loads only acknowledged entries, and every checkpoint entry it does not load is excluded by a
  /// whole tombstone or superseded by a later level's owner of its unit.
  val ReplayReflectsCut = recovering implies (recovered.forall(r => ever.contains(r))
    and base.forall(r => recovered.contains(r) or excludedIds.contains(r.id) or supersededIds.contains(r.id)))
  /// FRONTIER: no recovered entry has a whole tombstone on the medium.
  val NoResurrection = recovering implies recovered.forall(r => not(tombstoned(r.id)))
  /// A recovered entry's unit holds its own payload, unless a block of one of its own tombstones was damaged, the
  /// fault that resurrected it; its checked bytes then fail the hit's identity check. The exception holds per id: a
  /// payload that a later removal of the same resurrected id released before its tombstone was durable falls under
  /// it too, a release the hold in `evict` rules out.
  val RecoveredIntact = recovering implies recovered.forall(r => payload.get(r.unit) == r.id or tombDamaged(r.id))
  /// A block of `r`'s suffix, from the replay's start through the one before its insert, is not intact on the
  /// medium: the ghost's account of the hole that drops `r`.
  def behindHole(r: Mutation): bool = insAt.keys().contains(r.id) and {
    val at = insAt.get(r.id)
    val suffixes = chain.append({ session: 0, start: start, certified: 0, end: lsnHead })
    suffixes.foldl(false, (found, sfx) => found or (sfx.start <= at and at < sfx.end
      and (if (sfx.start > cut) sfx.start else cut).to(at - 1).exists(l => not(intact(l)))))
  }
  /// R2 with fault-local loss: every entry live at the last durable block recovers unless a whole tombstone on the
  /// medium excludes it, a later level superseded it after its removal, a block of its suffix before its insert is
  /// not intact, or a block of its own insert is not intact.
  val Retained = recovering implies before.forall(r => recovered.contains(r) or tombstoned(r.id)
    or behindHole(r) or (supersededIds.contains(r.id) and removedIds.contains(r.id))
    or (insAt.keys().contains(r.id) and not(intact(insAt.get(r.id)) and (not(r.split) or intact(insAt.get(r.id) + 1)))))
  /// P6 within one level: no two entries of one level claim a unit.
  val NoConflict = not(conflict)
  /// P7: a landing replaces only a block below the cut, which no replay needs.
  val HistoryNotReused = replaced < cut
  /// The head and the reserved end stay at or below the capacity, which stays at or below `start + J`;
  /// `HistoryNotReused` covers the floor.
  val InTenureCapacity = lsnHead <= capacity and reserved <= capacity and capacity <= start + J
  val RefusalChangesNothing = ev == "refusedRange" implies (live, held, open, lsnHead, reserved) == prior
  /// P7/R9: the head runs at most `UNCERTIFIED` blocks past the certified end, so the acknowledged records a replay
  /// could count as an unflushed tail stay bounded.
  val UncertifiedBounded = lsnHead <= certified + UNCERTIFIED
  /// The planned transfer follows a certify through the head, the durable end of the sealed suffix, with no record in
  /// the open block.
  val TransferAtCertifiedHead = ev == "transfer" implies (certified == lsnHead and open.length() == 0)
  /// The planned transfer follows the drain's publish: the exit published its checkpoint after fills stopped, and
  /// every block on the medium from the cut on holds REMOVE records alone, so that checkpoint holds every entry the
  /// recovery loads and the suffix past it only removes.
  val TransferFollowsPublish = ev == "transfer" implies (drainPublished and 0.to(J - 1).forall(u =>
    region.get(u).lsn < cut or region.get(u).recs.foldl(true, (rems, r) => rems and r.kind == "rem")))
  /// HANDOFF-CUT-IS-EXACT (END): the recovery after a planned transfer loads exactly the membership at the
  /// withdrawal, the drain's checkpoint and its sealed suffix certified through the head, unless a fault damaged a
  /// block from the cut to the head and the replay reports damage. `prior` holds the state the recovery started
  /// from, whose live set and head the transfer fixed.
  val HandoffCutIsExact = ev == "handoffRecover" implies (recovered == prior._1
    or (damage and damagedLsns.exists(l => l >= cut and l < prior._4)))
  val safety = OneOwner and ReplayReflectsCut and NoResurrection and RecoveredIntact and Retained and NoConflict
    and HistoryNotReused and InTenureCapacity and RefusalChangesNothing and UncertifiedBounded and HandoffCutIsExact
    and TransferAtCertifiedHead and TransferFollowsPublish

  val witnessRecovered = ev == "recover" and recovered.size() >= 1
  val witnessDamage = ev == "recover" and damage
  val witnessRefused = ev == "refusedRange"
  val witnessWrapped = ev == "land" and replaced >= 0
  /// A recovery after a planned transfer loads a nonempty membership, and one reports damage.
  val witnessHandoffRecovered = ev == "handoffRecover" and recovered.size() >= 1
  val witnessHandoffDamage = ev == "handoffRecover" and damage
  /// A recovery after a planned transfer reports no damage and excludes an entry by a REMOVE of the sealed suffix.
  val witnessHandoffSuffixReplayed = ev == "handoffRecover" and not(damage) and excludedIds.size() >= 1
    and recovered == prior._1
}
