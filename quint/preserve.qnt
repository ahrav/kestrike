/// One shard's volume across host losses under barrier-gated reuse. Every device write, a payload unit, a checkpoint
/// row or a journal tombstone, leaves an attempt that may land again at any later step, after its completion and
/// after host loss included. A released unit enters quarantine and becomes free only at a completed barrier. `END` is
/// the provider premise: a successful Preempt-and-Abort, with a Report showing the issuer as sole registrant, ends
/// every attempt the preempted registrations submitted before it. The in-tenure barrier preempts the issuing tenure's
/// own registration; the successor's fence preempts every registration of the lineage. A deposed predecessor keeps
/// issuing commands under its own tenure from the successor's takeover until the successor's fence, and the successor
/// writes nothing before its fence. Evicting an entry of a possibly named cut writes a tombstone and keeps the entry's
/// unit until the tombstone completes; an acknowledged invalidation or an expiry is evidence by itself. A fill of a key
/// whose evicted entry still has a pending tombstone is refused, so a same-key replacement follows a durable
/// exclusion of its predecessor. A capture is one step: it snapshots the live entries, places one row per key in a
/// slot outside the possibly named set and adds the slot to that set; a Publish is the prefix model's exact-version
/// compare-and-swap; a Publish that loses the version race stays pending until the acknowledgment of a later committed
/// Publish settles it or recovery clears it. Recovery loads each row
/// and payload that is intact and unexcluded, and holds the named slot, the loaded payloads and every journal block
/// whose tombstone is at or above the cut. A refused fill, capture or tombstone changes nothing. A store rollback,
/// enabled only after host loss, restores the record as it stood before the first takeover and closes takeover until
/// a reopen restores the latest record and a tenure floor at the highest issued tenure, so the next takeover issues a
/// tenure one above it; detection of the restore, no continued writes through the old store instance, the floor, the
/// latest record and complete coverage are the RESTORE premise. DURABLE is a storage premise: a completed or landed
/// write is on the volume, and host loss reverts none.
/// EXPIRY-CLOCK is a clock premise: the successor's clock bound at recovery reaches every deadline the predecessor
/// recorded as expired, so `expired` is one set that every tenure reads.
///
/// Write ids come from one counter, `nextW`: a fill or a tombstone takes one id, and a capture takes rows `r` and
/// `r + 1` and Publish id `r + 2`.
module preserve {
  const BOUND: int
  pure val KEYS = Set(0, 1)
  pure val PU = 3
  pure val SLOTS = 3
  pure val J = 2
  /// The provider premise: a completed Preempt-and-Abort ends every earlier attempt of the registrations it names.
  pure val END = true
  /// The timing-only release control: quarantined units become free with no barrier.
  pure val GRACE = false
  pure def rowUnit(s: int, k: int): int = PU + 2 * s + k
  pure def block(l: int): int = PU + 2 * SLOTS + l % J
  pure val UNITS = 0.to(PU + 2 * SLOTS + J - 1)
  pure val PAYLOAD = 0.to(PU - 1)
  pure val BLOCKS = 0.to(J - 1).map(i => PU + 2 * SLOTS + i)
  pure def lowest(xs: Set[int]): int = xs.fold(PU + 2 * SLOTS + J, (a, x) => if (x < a) x else a)
  pure def count(b: bool): int = if (b) 1 else 0
  /// A pending attempt of write `id` on `unit`, submitted by tenure `t`.
  type W = { id: int, unit: int, t: int }
  /// A write: a payload of `key`, a row naming payload `ref`, or a tombstone of payload `ref` at journal `lsn`.
  type M = { kind: str, key: int, unit: int, ref: int, lsn: int }
  type Cut = { lsn: int, ws: Set[int] }
  type Pub = { id: int, slot: int, at: int }
  /// A store record: the named slot, the record version and the tenure.
  type Snap = { named: int, ver: int, ten: int }
  /// `img` is the media, `own` the write each held unit must keep; every unit is free, quarantined or owned. `srv` is
  /// the tenure that issues commands, 0 from a fence to the next recovery. `lost` holds entries a recovery accounted
  /// to damaged units. `snap` is the record as it stood before the first takeover, the one rollback target; `latest`
  /// is the record a rollback discarded, and `restored` holds from a rollback to its reopen.
  type State = {
    img: int -> int, own: int -> int, free: Set[int], quar: Set[int], att: Set[W], meta: int -> M, nextW: int,
    live: int -> int, cuts: int -> Cut, poss: Set[int], pend: Set[Pub], inflight: Set[Pub], committed: Set[int],
    named: int, ver: int, known: int, ten: int, srv: int, phase: str, lsn: int, tombs: Set[int], pendTomb: Set[int],
    acked: Set[int], expired: Set[int], lost: Set[int], corrupted: Set[int], lossEligible: Set[(int, int)],
    recovered: Set[int], issued: Set[int], reissued: bool, restored: bool, snap: Snap, latest: Snap
  }
  var st: State
  var prior: State
  var ev: str
  var turn: int

  pure val BLANK: M = { kind: "blank", key: -1, unit: -1, ref: 0, lsn: -1 }
  pure val NOSNAP: Snap = { named: -1, ver: 0, ten: 0 }
  pure val INIT: State = {
    img: UNITS.mapBy(u => 0), own: UNITS.mapBy(u => 0), free: UNITS, quar: Set(), att: Set(),
    meta: Map(0 -> BLANK), nextW: 1, live: KEYS.mapBy(k => 0),
    // Key -1 is the cold cut: `recover` and `eligibleIn` index `cuts` by `named`, which is -1 before any Publish.
    cuts: Set(-1).union(0.to(SLOTS - 1)).mapBy(s => { lsn: 0, ws: Set() }), poss: Set(), pend: Set(), inflight: Set(),
    committed: Set(), named: -1, ver: 0, known: 0, ten: 1, srv: 1, phase: "serving", lsn: 0, tombs: Set(),
    pendTomb: Set(), acked: Set(), expired: Set(), lost: Set(), corrupted: Set(), lossEligible: Set(), recovered: Set(),
    issued: Set(1), reissued: false, restored: false, snap: NOSNAP, latest: NOSNAP,
  }
  action init = all { st' = INIT, prior' = INIT, ev' = "init", turn' = 0 }
  /// The refusal labels; `RefusalChangesNothing` compares each refused step with `prior`.
  pure val REFUSALS = Set("refusedFull", "refusedReplace", "refusedLog", "refusedSlot")
  /// Labels whose predicates read `prior`; every other step stores INIT there, so equal successors merge.
  pure val READS_PRIOR = REFUSALS.union(Set("barrier", "land", "lose"))
  action tick(a: str): bool = all { turn < BOUND, turn' = turn + 1, ev' = a,
    prior' = if (READS_PRIOR.contains(a)) st else INIT }

  def m(w: int): M = st.meta.get(w)
  /// The serving tenure, or a deposed one between its successor's takeover and fence, issues commands.
  def issuing: bool = st.phase == "serving" or (st.phase == "bumped" and st.srv > 0)
  def refs(s: int): Set[int] = st.cuts.get(s).ws.map(r => m(r).ref)
  def inPoss(w: int): bool = st.poss.exists(s => refs(s).contains(w))
  /// Journal block `b` holds a tombstone at or above LSN `l`.
  def tombOn(b: int, l: int): bool = m(st.img.get(b)).kind == "tomb" and m(st.img.get(b)).lsn >= l
  def tombVisible(w: int, l: int): bool = BLOCKS.exists(b => tombOn(b, l) and m(st.img.get(b)).ref == w)
  /// Recovery's media view of the exclusions: the coverage set, the expiry set and the tombstones on the journal.
  def excludedAt(w: int, l: int): bool = st.acked.contains(w) or st.expired.contains(w) or tombVisible(w, l)
  /// A tombstone is eviction evidence once it is on the media: completed, or pending with its attempt landed.
  def evidence(t: int): bool = st.tombs.contains(t) or (st.pendTomb.contains(t) and st.img.get(m(t).unit) == t)
  /// The ghost specification of slot `s`'s eligible entries, S for the named slot: no acknowledged invalidation,
  /// expiry, accounted damage or tombstone evidence at or above the cut. It reads ghost sets, and `excludedAt` is the
  /// media view recovery reads.
  def eligibleIn(s: int): Set[int] = refs(s).filter(w => w != 0
    and not(st.acked.contains(w)) and not(st.expired.contains(w)) and not(st.lost.contains(w))
    and not(st.tombs.union(st.pendTomb).exists(t => evidence(t) and m(t).ref == w and m(t).lsn >= st.cuts.get(s).lsn)))
  /// Key `k`'s evicted entry still has a pending tombstone, so a fill of `k` would replace it before its exclusion is
  /// durable.
  def replacing(k: int): bool = st.pendTomb.exists(t => m(t).key == k)
  /// A later payload of the same key exists: an acknowledged fill superseded `w`.
  def superseded(w: int): bool = st.meta.keys().exists(v => v > w and m(v).kind == "payload" and m(v).key == m(w).key)
  def intact(u: int, w: int): bool = st.img.get(u) == w or st.corrupted.contains(u)
  def loadable(r: int, l: int): bool =
    st.img.get(m(r).unit) == r and m(r).ref != 0 and not(excludedAt(m(r).ref, l)) and st.img.get(m(m(r).ref).unit) == m(r).ref

  action fill(k: int): bool = {
    val open = st.free.intersect(PAYLOAD)
    val u = lowest(open)
    val w = st.nextW
    all { issuing, st.live.get(k) == 0,
      if (open.size() == 0) all { tick("refusedFull"), st' = st }
      else if (replacing(k)) all { tick("refusedReplace"), st' = st }
      else all { tick("fill"), st' = { ...st, img: st.img.set(u, w), own: st.own.set(u, w), free: st.free.exclude(Set(u)),
        att: st.att.union(Set({ id: w, unit: u, t: st.srv })), nextW: w + 1, live: st.live.set(k, w),
        meta: st.meta.put(w, { kind: "payload", key: k, unit: u, ref: w, lsn: st.lsn }), corrupted: st.corrupted.exclude(Set(u)) } } }
  }
  /// Removes key `k`'s entry by eviction, acknowledged invalidation or expiry.
  action drop(k: int, how: str): bool = {
    val w = st.live.get(k)
    val b = block(st.lsn)
    val t = st.nextW
    val needsTomb = how == "evict" and inPoss(w)
    all { issuing, w != 0,
      if (needsTomb and not(st.free.contains(b))) all { tick("refusedLog"), st' = st }
      else if (needsTomb) all { tick("tomb"), st' = { ...st, own: st.own.set(b, t), free: st.free.exclude(Set(b)),
        att: st.att.union(Set({ id: t, unit: b, t: st.srv })), nextW: t + 1, lsn: st.lsn + 1, live: st.live.set(k, 0),
        meta: st.meta.put(t, { kind: "tomb", key: k, unit: b, ref: w, lsn: st.lsn }), pendTomb: st.pendTomb.union(Set(t)) } }
      else all { tick(how), st' = { ...st, own: st.own.set(m(w).unit, 0), quar: st.quar.union(Set(m(w).unit)),
        live: st.live.set(k, 0), acked: if (how == "invalidate") st.acked.union(Set(w)) else st.acked,
        expired: if (how == "expire") st.expired.union(Set(w)) else st.expired } } }
  }
  /// A tombstone completes: it is on the media, and the evicted entry's unit enters quarantine.
  action tombDone(t: int): bool = all { issuing, st.pendTomb.contains(t), tick("tombDone"),
    st' = { ...st, img: st.img.set(m(t).unit, t), own: st.own.set(m(m(t).ref).unit, 0),
      quar: st.quar.union(Set(m(m(t).ref).unit)), pendTomb: st.pendTomb.exclude(Set(t)), tombs: st.tombs.union(Set(t)) } }
  /// Rows `r` and `r + 1` into the lowest slot outside the possibly named set whose row units are free, and Publish
  /// `r + 2` at the last settled version.
  action capture: bool = {
    val open = 0.to(SLOTS - 1).filter(s => not(st.poss.contains(s)) and KEYS.forall(k => st.free.contains(rowUnit(s, k))))
    val s = lowest(open)
    val r = st.nextW
    val p = { id: r + 2, slot: s, at: st.known }
    val units = KEYS.map(k => rowUnit(s, k))
    all { issuing,
      if (open.size() == 0) all { tick("refusedSlot"), st' = st }
      else all { tick("capture"), st' = { ...st, img: st.img.set(rowUnit(s, 0), r).set(rowUnit(s, 1), r + 1),
        own: st.own.set(rowUnit(s, 0), r).set(rowUnit(s, 1), r + 1), free: st.free.exclude(units),
        att: st.att.union(KEYS.map(k => { id: r + k, unit: rowUnit(s, k), t: st.srv })), nextW: r + 3,
        meta: st.meta.put(r, { kind: "row", key: 0, unit: rowUnit(s, 0), ref: st.live.get(0), lsn: st.lsn })
          .put(r + 1, { kind: "row", key: 1, unit: rowUnit(s, 1), ref: st.live.get(1), lsn: st.lsn }),
        cuts: st.cuts.set(s, { lsn: st.lsn, ws: Set(r, r + 1) }), poss: st.poss.union(Set(s)),
        pend: st.pend.union(Set(p)), inflight: st.inflight.union(Set(p)), corrupted: st.corrupted.exclude(units) } } }
  }
  action applyPub(p: Pub): bool = {
    val commits = p.at == st.ver
    all { st.inflight.contains(p), not(st.restored), tick("apply"),
      st' = { ...st, inflight: st.inflight.exclude(Set(p)), named: if (commits) p.slot else st.named,
        ver: if (commits) st.ver + 1 else st.ver, committed: if (commits) st.committed.union(Set(p.id)) else st.committed } }
  }
  /// The Publish facts of the record that names slot `named` at version `ver`: the known version is at most `ver`, a
  /// Publish that can still commit names a possibly named slot, and a committed pending Publish is below `ver` and,
  /// when it meets the acknowledgment's shrink guard, names `named`.
  def recordFacts(named: int, ver: int): bool = st.known <= ver
    and st.inflight.forall(p => p.at < ver or st.poss.contains(p.slot))
    and st.pend.forall(p => st.committed.contains(p.id) implies (p.at < ver and (shrinks(p) implies named == p.slot)))
  /// The acknowledgment of `p` settles the possibly named set: `p` is at or above the last settled version and no later
  /// Publish is pending.
  def shrinks(p: Pub): bool = p.at + 1 >= st.known and st.pend.forall(q => q.id <= p.id)
  /// The acknowledged success of a committed Publish; the shrink releases the dropped slots' rows and the blocks of
  /// completed tombstones below the new cut.
  action ackPub(p: Pub): bool = {
    val shrink = shrinks(p)
    val rows = st.poss.exclude(Set(p.slot)).map(s => KEYS.map(k => rowUnit(s, k))).flatten()
    val blocks = BLOCKS.filter(b => st.tombs.contains(st.own.get(b)) and m(st.own.get(b)).lsn < st.cuts.get(p.slot).lsn)
    val out = if (shrink) rows.union(blocks) else Set()
    all { issuing, st.pend.contains(p), st.committed.contains(p.id), tick("ack"),
      st' = { ...st, own: UNITS.mapBy(u => if (out.contains(u)) 0 else st.own.get(u)), quar: st.quar.union(out),
        poss: if (shrink) Set(p.slot) else st.poss, known: if (p.at + 1 > st.known) p.at + 1 else st.known,
        pend: st.pend.filter(q => q.id > p.id) } }
  }
  /// A landing rewrites the whole unit, so it also ends the unit's damage.
  action land(a: W): bool = all { st.att.contains(a), tick(if (st.quar.contains(a.unit)) "landQuarantined" else "land"),
    st' = { ...st, img: st.img.set(a.unit, a.id), corrupted: st.corrupted.exclude(Set(a.unit)) } }
  /// The in-tenure barrier: a self Preempt-and-Abort and a Report showing the issuer as sole registrant, once no
  /// tombstone is outstanding. It is one step, so no command is admitted between the Preempt-and-Abort and the
  /// release; only units quarantined before it become free.
  action barrier: bool = all { issuing, st.pendTomb == Set(), tick("barrier"),
    st' = { ...st, att: if (END) st.att.filter(a => a.t != st.srv) else st.att, free: st.free.union(st.quar), quar: Set() } }
  action graceRelease: bool = all { GRACE, issuing, tick("grace"),
    st' = { ...st, free: st.free.union(st.quar), quar: Set() } }
  /// The host is lost while serving, or a successor crashes between its fence and its recovery.
  action lose: bool = all { Set("serving", "fenced").contains(st.phase), tick("lose"), st' = { ...st, phase: "lost" } }
  /// A successor's acknowledged exact-version CAS; from `bumped`, the previous successor crashed before its fence.
  action takeover: bool = all { Set("lost", "bumped").contains(st.phase), not(st.restored), tick("takeover"),
    st' = { ...st, ten: st.ten + 1, ver: st.ver + 1, phase: "bumped", issued: st.issued.union(Set(st.ten + 1)),
      reissued: st.reissued or st.issued.contains(st.ten + 1),
      snap: if (st.snap.ten == 0) { named: st.named, ver: st.ver, ten: st.ten } else st.snap } }
  /// Preempt-and-Abort naming every registrant of the lineage since the last completed barrier, then a Report.
  action fence: bool = all { st.phase == "bumped", tick("fence"),
    st' = { ...st, phase: "fenced", srv: 0, att: if (END) st.att.filter(a => a.t >= st.ten) else st.att } }
  action recover: bool = {
    val cut = st.cuts.get(st.named)
    val kept = cut.ws.filter(r => loadable(r, cut.lsn)).map(r => m(r).ref)
    val required = BLOCKS.filter(b => tombOn(b, cut.lsn))
    val elig = eligibleIn(st.named)
    // Row, payload and block units occupy disjoint ranges and a payload unit holds one write, so each unit appears in
    // at most one pair.
    val owners = cut.ws.map(r => (m(r).unit, r)).union(kept.map(w => (m(w).unit, w))).union(required.map(b => (b, st.img.get(b))))
    all { st.phase == "fenced", tick("recover"),
      st' = { ...st, own: UNITS.mapBy(u => owners.fold(0, (a, o) => if (o._1 == u) o._2 else a)),
        free: UNITS.exclude(owners.map(o => o._1)), quar: Set(), pendTomb: Set(), pend: Set(), known: st.ver, srv: st.ten,
        poss: if (st.named >= 0) Set(st.named) else Set(), live: KEYS.mapBy(k => kept.fold(0, (a, w) => if (m(w).key == k) w else a)),
        tombs: st.tombs.union(required.map(b => st.img.get(b))), lost: st.lost.union(elig.exclude(kept)), recovered: kept,
        lossEligible: cut.ws.filter(r => elig.contains(m(r).ref)).map(r => (m(r).ref, m(r).unit)), phase: "serving" } }
  }
  /// Damages payload or row unit `u`; at most two units are damaged at once.
  action corrupt(u: int): bool = all { st.corrupted.size() < 2, not(st.corrupted.contains(u)), u < PU + 2 * SLOTS,
    tick("corrupt"), st' = { ...st, img: st.img.set(u, -1), corrupted: st.corrupted.union(Set(u)) } }
  /// The store rolls back, after host loss only, to `snap`, the record as it stood before the first takeover; `latest`
  /// keeps the record the rollback discarded.
  action rollback: bool = all { st.phase == "lost", st.snap.ten > 0, not(st.restored), tick("rollback"),
    st' = { ...st, latest: { named: st.named, ver: st.ver, ten: st.ten }, named: st.snap.named, ver: st.snap.ver,
      ten: st.snap.ten, restored: true } }
  /// Reopens the restored store at its latest record's slot, one version above that record, and a tenure floor at the
  /// highest issued tenure; the next takeover issues one above it. The new version is RESTORE's instance change: a
  /// Publish issued to the rolled-back instance applies as a lost version race.
  action reopen: bool = all { st.restored, tick("reopen"),
    st' = { ...st, named: st.latest.named, ver: st.latest.ver + 1, ten: st.issued.fold(0, (a, x) => if (x > a) x else a),
      restored: false } }
  action landId(i: int): bool = {
    val hits = st.att.filter(a => a.id == i)
    all { i > 0, st.meta.keys().contains(i),
      if (hits.size() == 0) all { tick("landEnded"), st' = st } else all { nondet a = hits.oneOf() land(a) } }
  }
  action applyId(i: int): bool = all { st.inflight.exists(p => p.id == i), nondet p = st.inflight.filter(p => p.id == i).oneOf() applyPub(p) }
  action ackId(i: int): bool = all { st.pend.exists(p => p.id == i), nondet p = st.pend.filter(p => p.id == i).oneOf() ackPub(p) }
  action step = any {
    nondet k = KEYS.oneOf()
    any {
      fill(k),
      nondet how = Set("evict", "invalidate", "expire").oneOf()
      drop(k, how),
    },
    capture,
    nondet p = st.inflight.union(Set({ id: 0, slot: 0, at: -1 })).oneOf()
    applyPub(p),
    nondet q = st.pend.union(Set({ id: 0, slot: 0, at: -1 })).oneOf()
    ackPub(q),
    nondet t = st.pendTomb.union(Set(0)).oneOf()
    tombDone(t),
    // A landing on a unit that holds its bytes, and a barrier with nothing to end or free, change no state.
    nondet a = st.att.union(Set({ id: 0, unit: 0, t: 0 })).oneOf()
    all { st.img.get(a.unit) != a.id, land(a) },
    all { st.quar != Set() or (END and st.att.exists(a => a.t == st.srv)), barrier },
    lose, takeover, fence, recover, rollback, reopen,
  }
  /// The free scheduler with unit damage: `step`, or `corrupt` of any payload or row unit.
  action damageStep = any {
    step,
    nondet u = 0.to(PU + 2 * SLOTS - 1).oneOf()
    corrupt(u),
  }

  val Partition = UNITS.forall(u => count(st.free.contains(u)) + count(st.quar.contains(u)) + count(st.own.get(u) != 0) == 1)
  val FreeUnexposed = st.att.forall(a => not(st.free.contains(a.unit)))
  val AttemptsAgree = st.att.forall(a => st.quar.contains(a.unit) or st.own.get(a.unit) == a.id)
  /// Every held unit outside damage holds its owner's write, or its owner is a tombstone still in flight.
  val OwnedIntact = UNITS.forall(u => (st.own.get(u) != 0 and not(st.corrupted.contains(u)) and not(st.pendTomb.contains(st.own.get(u))))
    implies st.img.get(u) == st.own.get(u))
  val NamedIsPossible = st.named < 0 or st.restored or st.poss.contains(st.named)
  def cutHeld(s: int): bool = st.cuts.get(s).ws.forall(r => st.own.get(m(r).unit) == r)
    and eligibleIn(s).forall(w => st.own.get(m(w).unit) == w)
    and st.tombs.forall(t => m(t).lsn >= st.cuts.get(s).lsn implies st.own.get(m(t).unit) == t)
  val CutsOwned = st.poss.forall(s => cutHeld(s))
  /// The facts the per-action argument for the six clauses above relies on: write records agree with attempts, owners,
  /// live entries and rows; every pending attempt is of the tenure that issues commands, which is positive, and outside
  /// a store restoration none is of a tenure above the current one; the issuing tenure is 0 or an issued tenure, below
  /// the current one while a successor's takeover awaits its fence, and 0 with no attempt from a fence to the next
  /// recovery; a pending
  /// tombstone holds its block and its entry's unit; outside a store restoration the known version is at most the
  /// record version, a Publish that can still commit names a possibly named slot, and a committed pending Publish is
  /// below the record version and, when it meets the acknowledgment's shrink guard, names the named slot; during a
  /// store restoration the discarded record satisfies the same Publish facts and names a possibly named slot; a
  /// serving host issues under the current tenure; cut LSNs follow capture order and stay at or below the journal head;
  /// and every tombstone's LSN is below the head, and no live entry or later cut names an entry under a tombstone.
  val Support = and {
    st.att.forall(a => a.id < st.nextW and m(a.id).unit == a.unit and a.t > 0 and a.t == st.srv
      and (st.restored or a.t <= st.ten)),
    st.srv == 0 or st.issued.contains(st.srv),
    st.phase == "bumped" implies st.srv < st.ten,
    st.phase == "fenced" implies (st.srv == 0 and st.att == Set()),
    UNITS.forall(u => st.own.get(u) != 0 implies (st.own.get(u) < st.nextW and m(st.own.get(u)).unit == u)),
    KEYS.forall(k => st.live.get(k) != 0 implies
      (m(st.live.get(k)).key == k and m(st.live.get(k)).kind == "payload" and st.own.get(m(st.live.get(k)).unit) == st.live.get(k))),
    0.to(SLOTS - 1).forall(s => st.cuts.get(s).ws.forall(r => m(r).kind == "row" and m(r).unit == rowUnit(s, m(r).key)
      and (m(r).ref == 0 or m(m(r).ref).kind == "payload"))),
    st.pendTomb.forall(t => m(t).kind == "tomb" and st.own.get(m(t).unit) == t and st.own.get(m(m(t).ref).unit) == m(t).ref),
    if (st.restored) recordFacts(st.latest.named, st.latest.ver) and (st.latest.named < 0 or st.poss.contains(st.latest.named))
    else recordFacts(st.named, st.ver),
    st.phase == "serving" implies st.srv == st.ten,
    st.poss.forall(a => st.cuts.get(a).lsn <= st.lsn and st.poss.forall(b =>
      st.cuts.get(a).ws.forall(x => st.cuts.get(b).ws.forall(y => x < y)) implies st.cuts.get(a).lsn <= st.cuts.get(b).lsn)),
    st.tombs.union(st.pendTomb).forall(t => m(t).lsn < st.lsn and KEYS.forall(k => st.live.get(k) != m(t).ref)
      and st.poss.forall(s => st.cuts.get(s).lsn > m(t).lsn implies not(refs(s).contains(m(t).ref)))),
  }
  /// The bounded state invariant: TLC checks it in every reachable state within the bounds.
  val Preserved = Partition and FreeUnexposed and AttemptsAgree and OwnedIntact and NamedIsPossible and CutsOwned and Support
  /// Every possibly named cut's rows and eligible payloads, and outside a store restoration the named cut's, are on the
  /// media or on a damaged unit.
  val Retained = st.poss.union(if (st.named >= 0 and not(st.restored)) Set(st.named) else Set()).forall(s =>
    st.cuts.get(s).ws.forall(r => intact(m(r).unit, r)) and eligibleIn(s).forall(w => intact(m(w).unit, w)))
  /// Recovery loads every eligible entry of the cut that no damaged unit holds.
  val LossIsFaultLocal = ev == "recover" implies st.lossEligible.forall(e =>
    st.recovered.contains(e._1) or st.corrupted.contains(e._2) or st.corrupted.contains(m(e._1).unit))
  /// Recovery loads only entries eligible at the cut, and no entry a later fill of its key superseded.
  val NoResurrection = ev == "recover" implies
    (st.recovered.subseteq(st.lossEligible.map(e => e._1)) and st.recovered.forall(w => not(superseded(w))))
  /// Recovery installs exactly the entries it reports recovered.
  val RecoveredInstalled = ev == "recover" implies KEYS.map(k => st.live.get(k)).exclude(Set(0)) == st.recovered
  val RefusalChangesNothing = REFUSALS.contains(ev) implies st == prior
  val TenureUnique = not(st.reissued)
  val safety = Preserved and Retained and LossIsFaultLocal and NoResurrection and RecoveredInstalled and RefusalChangesNothing
    and TenureUnique

  val witnessWarm = ev == "recover" and st.recovered.size() >= 1
  /// Reachability only: under END a landing on a quarantined unit writes the bytes of that unit's last owner.
  val witnessStaleLanding = ev == "landQuarantined"
  val witnessBarrierFreed = ev == "barrier" and st.free.size() > prior.free.size()
  val witnessRefusedSlot = ev == "refusedSlot"
  val witnessRefusedFull = ev == "refusedFull"
  val witnessRefusedLog = ev == "refusedLog"
  val witnessRefusedReplace = ev == "refusedReplace"
  val witnessExcluded = ev == "recover" and st.lossEligible.size() < st.cuts.get(st.named).ws.filter(r => m(r).ref != 0).size()
  val witnessTombLanded = ev == "land" and st.pendTomb.exists(t => st.img.get(m(t).unit) == t and prior.img.get(m(t).unit) != t)
  val witnessChain = st.ten == 3
  val witnessReopen = ev == "reopen"
  val witnessDeposedWrite = st.phase == "bumped" and Set("fill", "capture", "tomb").contains(ev)
  val witnessFencedCrash = ev == "lose" and prior.phase == "fenced"
  val witnessDamagedLoss = ev == "recover" and st.lost != Set()
}
