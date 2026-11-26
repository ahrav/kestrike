/// Composed projections of the accepted recovery models. Each module imports two source models as instances and
/// steps them under one joint scheduler: every joint step is one source action with the other model's variables
/// unchanged, or one action of each source model taken together, and adds a ghost map from one model's state to the
/// other's. Each module's `safety` is both source models' `safety` and the joint invariants that state the interface
/// between them. `turn` counts joint steps up to `BOUND`; each source model counts its own actions against the same
/// `BOUND`, which therefore never binds before the joint count does.

/// Capture cut and durable suffix (P3, P5). One tenure of `suffix` runs one multi-step capture pass of `capture`:
/// - `bind` is the capture's allocation of a slot and unit; `publish` is the capture's publication together with the
///   suffix's INSERT append of that entry, and the ghost `idOf` maps the capture entry's id to the INSERT's id;
/// - `remove` is the capture's removal, which saves an unvisited snapshot member, together with the suffix's REMOVE
///   append; `release` is the capture's return of the unit to its allocator, enabled once the suffix no longer holds
///   the unit, that is once the REMOVE's block is durable;
/// - `start` is the capture's `t0` snapshot together with the suffix's pass start, which seals the cut, and
///   `complete` is the capture's checkpoint together with the suffix's publication of the pass at that cut;
/// - `scan` is the capture alone; block seal, landing, completion, certification, extension, host loss and the
///   successor's recovery are the suffix alone, and an append the suffix refuses leaves the capture unchanged.
/// Capture slot `s` is suffix key `s + 1`; suffix units 1 and 2 are capture units 1 and 2. The capture model's own
/// crash and load are unused: the suffix's recovery is the successor's. After the host loss the capture's state is
/// the lost host's memory, and no action of the capturing tenure runs.
module captureSuffix {
  const BOUND: int
  import capture(BOUND = BOUND) as C from "./capture"
  import suffix(BOUND = BOUND, UNCERTIFIED = 4) as S from "./suffix"
  var turn: int
  var act: str
  /// The suffix INSERT id of each published capture entry, and the head LSN at the pass's start.
  var idOf: int -> int
  var startCut: int

  action keepC = all { C::st' = C::st, C::turn' = C::turn }
  action keepS = all {
    S::session' = S::session, S::live' = S::live, S::ever' = S::ever, S::nextId' = S::nextId, S::lsnHead' = S::lsnHead,
    S::open' = S::open, S::reserved' = S::reserved, S::capacity' = S::capacity, S::start' = S::start,
    S::region' = S::region, S::pending' = S::pending, S::replaced' = S::replaced, S::durable' = S::durable,
    S::certified' = S::certified, S::chain' = S::chain, S::cut' = S::cut, S::base' = S::base,
    S::passCut' = S::passCut, S::passBase' = S::passBase, S::held' = S::held, S::payload' = S::payload,
    S::liveAt' = S::liveAt, S::durableLive' = S::durableLive, S::before' = S::before, S::removedIds' = S::removedIds,
    S::tombAt' = S::tombAt, S::insAt' = S::insAt, S::damagedLsns' = S::damagedLsns, S::prior' = S::prior,
    S::phase' = S::phase, S::recovered' = S::recovered, S::damage' = S::damage, S::conflict' = S::conflict,
    S::excludedIds' = S::excludedIds, S::supersededIds' = S::supersededIds, S::droppedIds' = S::droppedIds,
    S::turn' = S::turn, S::ev' = S::ev, S::drainPublished' = S::drainPublished,
  }
  action joint(a: str): bool = all { turn < BOUND, turn' = turn + 1, act' = a }
  action keepGhost = all { idOf' = idOf, startCut' = startCut }
  /// The capturing tenure, the suffix's first, serves.
  def first: bool = S::session == 2 and S::phase == "serving"

  action init = all { C::init, S::init, turn' = 0, act' = "init", idOf' = Map(), startCut' = -1 }
  action bind(s: int, u: int): bool = all { first, joint("bind"), C::bind(s, u), keepS, keepGhost }
  action publish(s: int): bool = {
    nondet e = C::st.bound.filter(e => e.slot == s).oneOf()
    val r = { kind: "ins", key: s + 1, unit: e.unit, id: S::nextId, old: 0, oldUnit: 0, split: false }
    all { first, any {
      all { S::fits(r), joint("publish"), C::publish(s), S::fill(s + 1, e.unit, false),
            idOf' = idOf.put(e.id, S::nextId), startCut' = startCut },
      all { not(S::fits(r)), joint("refusedPublish"), S::fill(s + 1, e.unit, false), keepC, keepGhost },
    } }
  }
  action remove(s: int): bool = {
    nondet r = S::live.filter(x => x.key == s + 1).oneOf()
    val t = { kind: "rem", key: r.key, unit: r.unit, id: 0, old: r.id, oldUnit: r.unit, split: false }
    all { first, any {
      all { S::fits(t), joint("remove"), C::remove(s), S::evict(r), keepGhost },
      all { not(S::fits(t)), joint("refusedRemove"), S::evict(r), keepC, keepGhost },
    } }
  }
  action release(s: int): bool = all {
    first, C::st.retiring.filter(e => e.slot == s).forall(e => not(S::held.contains(e.unit))),
    joint("release"), C::release(s), keepS, keepGhost,
  }
  action start = all { first, joint("start"), C::start, S::startPass, idOf' = idOf, startCut' = S::lsnHead }
  action scan = all { first, joint("scan"), C::scan, keepS, keepGhost }
  action complete = all { first, joint("complete"), C::complete, S::publishPass, keepGhost }
  action seal = all { first, joint("seal"), S::seal, keepC, keepGhost }
  /// A pending block lands, before or after the host loss and until the successor's fence ends the attempt.
  action land = { nondet b = S::pending.oneOf() all { S::session == 2, joint("land"), S::land(b), keepC, keepGhost } }
  action blockDone = { nondet b = S::pending.oneOf() all { first, joint("blockDone"), S::complete(b), keepC, keepGhost } }
  action certify = all { first, joint("certify"), S::certify, keepC, keepGhost }
  action extend = all { first, joint("extend"), S::extend, keepC, keepGhost }
  action lose = all { first, joint("lose"), S::lose, keepC, keepGhost }
  action recover = all { S::session == 2, joint("recover"), S::recover, keepC, keepGhost }
  action step = any {
    nondet s = Set(0, 1).oneOf()
    nondet u = Set(1, 2).oneOf()
    any { bind(s, u), publish(s), remove(s), release(s) },
    start, scan, complete, seal, land, blockDone, certify, extend, lose, recover,
  }

  def sid(e: C::Entry): int = idOf.get(e.id)
  /// The state map: while the capturing tenure serves, the capture's live entries are the suffix's, by id, key and
  /// unit.
  val LiveAgrees = first implies C::st.live.map(e => (sid(e), e.slot + 1, e.unit)) == S::live.map(r => (r.id, r.key, r.unit))
  /// P3: once the pass completed, the suffix's published cut is the head at the pass's start and its membership is
  /// the multi-step capture's checkpoint, every member removed after `t0` included.
  val CutIsCapture = C::st.phase == "done" implies
    (S::cut == startCut and S::base.map(r => r.id) == C::st.checkpoint.map(e => sid(e)))
  /// P7: while the capturing tenure serves, no unit the capture's allocator holds free is live in the suffix or held
  /// for a REMOVE whose block is not durable.
  val AllocatorHonorsHold = first implies C::st.free.intersect(S::owned) == Set()
  /// P5: a recovery after the pass completed loads every member of the capture's checkpoint unless a whole tombstone
  /// on the medium excludes it or a later incarnation of its key supersedes it.
  val CheckpointRecovered = (S::ev == "recover" and C::st.phase == "done") implies C::st.checkpoint.forall(e =>
    S::recovered.exists(r => r.id == sid(e)) or S::tombstoned(sid(e)) or S::supersededIds.contains(sid(e)))
  val safety = C::safety and S::safety and LiveAgrees and CutIsCapture and AllocatorHonorsHold and CheckpointRecovered

  /// A recovery after the pass loads a nonempty set beside every saved member, each excluded by its whole REMOVE.
  val witnessSavedExcluded = act == "recover" and C::st.phase == "done" and C::st.side != Set()
    and C::st.side.forall(e => S::excludedIds.contains(sid(e))) and S::recovered != Set()
  /// A recovery after the pass loads a saved member, whose REMOVE was recorded and not durable, with its own payload.
  val witnessSavedKept = act == "recover" and C::st.phase == "done"
    and C::st.side.exists(e => S::recovered.exists(r => r.id == sid(e) and S::payload.get(r.unit) == r.id))
  /// A recovery after the pass loads another entry on a saved member's unit: the unit was released after the
  /// member's REMOVE was durable and bound again.
  val witnessReuseAfterDurable = act == "recover" and C::st.phase == "done"
    and C::st.side.exists(e => S::recovered.exists(r => r.unit == e.unit and r.id != sid(e)))
  /// A recovery of a host lost during the pass loads a nonempty set.
  val witnessLostMidPass = act == "recover" and C::st.phase == "capture" and not(C::st.abandoned) and S::recovered != Set()
  /// A recovery after an abandoned pass loads a nonempty set.
  val witnessAbandonedRecovered = act == "recover" and C::st.abandoned and S::recovered != Set()
  /// The suffix refuses an append during the pass, and the capture is unchanged.
  val witnessRefusedInPass = S::ev == "refusedRange" and C::st.phase == "capture"
}

/// Coverage acknowledgment and recovered membership (P5). Tenure 1 of `coverage`, with both pages fenced, serves the
/// first tenure of `preserve`; tenure 2 is the successor:
/// - `invalidate` is the coverage INVALIDATE's page compare-and-swap submission for the key of a live preservation
///   entry; the store's `apply` and `timeout` are coverage alone;
/// - `reply` is coverage alone, except the reply of a committed coverage write, the acknowledgment, which happens
///   together with the preservation drop by invalidation that adds the entry to `acked`;
/// - `pageFence` and `reread` are coverage alone while the tenure's host runs;
/// - `fill` is a coverage FILL together with the preservation fill when coverage admits it, and coverage alone when
///   coverage refuses it;
/// - capture, Publish application and acknowledgment, host loss, takeover, the lineage fence and recovery are
///   preservation alone, and recovery runs once the successor fenced every coverage page.
/// Preservation key `k` is coverage key `k + 1` at version 1, on page `k`; a preservation tenure is the coverage tenure
/// of its number. Tenure 1's host runs while it issues commands, deposed between the successor's takeover and fence
/// included; the successor's runs from its takeover on. Only key 0 is invalidated; key 1 is the unaffected entry.
module coveragePreserve {
  const BOUND: int
  import coverage(BOUND = BOUND, TENURES = 2, FENCED_FIRST = true) as C from "./coverage"
  import preserve(BOUND = BOUND) as P from "./preserve"
  var turn: int
  var act: str

  action keepC = all {
    C::pages' = C::pages, C::inflight' = C::inflight, C::results' = C::results, C::pending' = C::pending,
    C::nextId' = C::nextId, C::fenced' = C::fenced, C::cov' = C::cov, C::known' = C::known, C::stale' = C::stale,
    C::oversized' = C::oversized, C::withdrawn' = C::withdrawn, C::resident' = C::resident, C::refused' = C::refused,
    C::acks' = C::acks, C::adoptions' = C::adoptions, C::succeeded' = C::succeeded, C::timedOut' = C::timedOut,
    C::prevCov' = C::prevCov, C::turn' = C::turn,
  }
  action keepP = all { P::st' = P::st, P::prior' = P::prior, P::ev' = P::ev, P::turn' = P::turn }
  action joint(a: str): bool = all { turn < BOUND, turn' = turn + 1, act' = a }
  /// Tenure `t`'s host runs: tenure 1 while it issues commands, the successor from its takeover on.
  def host(t: int): bool = if (t == 1) P::issuing and P::st.srv == 1 else P::st.ten == t and P::st.phase != "lost"

  action init = all { C::init, P::init, turn' = 0, act' = "init" }
  action fill(k: int): bool = {
    val t = P::st.srv
    all { host(t), P::st.live.get(k) == 0, C::fenced.get(t) == C::PAGES, any {
      all { C::covered(C::cov.get(t), k + 1, 1), joint("refusedFill"), C::fill(t, k + 1, 1), keepP },
      all { not(C::covered(C::cov.get(t), k + 1, 1)), P::st.free.intersect(P::PAYLOAD) != Set(), not(P::replacing(k)),
            joint("fill"), C::fill(t, k + 1, 1), P::fill(k) },
    } }
  }
  action invalidate(k: int): bool = all {
    host(P::st.srv), P::st.live.get(k) != 0, joint("invalidate"), C::invalidate(P::st.srv, k + 1, 1), keepP,
  }
  action apply(i: int): bool = all { joint("apply"), C::applyId(i), keepP }
  action timeout(i: int): bool = all { joint("timeout"), C::timeoutId(i), keepP }
  action reply(i: int): bool = {
    nondet r = C::pending.filter(r => r.id == i).oneOf()
    val acked = C::results.keys().contains(i) and C::results.get(i).ok and r.kind == "cover"
    any {
      all { host(r.t), not(acked), joint("reply"), C::replyId(i), keepP },
      all { host(r.t), acked, P::st.live.get(r.k - 1) != 0, joint("ack"), C::replyId(i), P::drop(r.k - 1, "invalidate") },
    }
  }
  action pageFence(p: int): bool = all { host(2), joint("pageFence"), C::fence(2, p), keepP }
  action reread(p: int): bool = { nondet t = C::tenures.oneOf() all { host(t), joint("reread"), C::reread(t, p), keepP } }
  action capture = all { joint("capture"), P::capture, keepC }
  action publish = { nondet p = P::st.inflight.oneOf() all { joint("publish"), P::applyPub(p), keepC } }
  action settle = { nondet p = P::st.pend.oneOf() all { joint("settle"), P::ackPub(p), keepC } }
  action lose = all { joint("lose"), P::lose, keepC }
  action takeover = all { P::st.ten < 2, joint("takeover"), P::takeover, keepC }
  action fence = all { joint("fence"), P::fence, keepC }
  action recover = all { C::fenced.get(P::st.ten) == C::PAGES, joint("recover"), P::recover, keepC }
  action step = any {
    nondet k = P::KEYS.oneOf()
    fill(k),
    invalidate(0),
    nondet i = 1.to(C::REQUESTS).oneOf()
    any { apply(i), timeout(i), reply(i) },
    nondet p = C::PAGES.oneOf()
    any { pageFence(p), reread(p) },
    capture, publish, settle, lose, takeover, fence, recover,
  }

  /// The state map: preservation's acknowledged invalidations are coverage's acknowledged INVALIDATEs.
  val AcksAgree = P::st.acked.map(w => (P::m(w).key + 1, 1)) == C::acks.map(a => (a.k, a.v))
  /// P5: no key of an acknowledged INVALIDATE has a live preservation entry again, through recovery or a later FILL.
  val InvalidationNotReinstated = C::acks.forall(a => P::st.live.get(a.k - 1) == 0)
  /// P5: every invalidation preservation's recovery excludes is covered by the recovering tenure's coverage, which it
  /// built by fencing every page.
  val ExclusionCovered = P::ev == "recover" implies
    P::st.acked.forall(w => C::covered(C::cov.get(P::st.ten), P::m(w).key + 1, 1))
  val safety = C::safety and P::safety and AcksAgree and InvalidationNotReinstated and ExclusionCovered

  /// A recovery loads a nonempty set and excludes an entry of its cut whose INVALIDATE was acknowledged.
  val witnessAckedExcludedRetained = act == "recover" and P::st.recovered != Set()
    and P::st.acked.exists(w => P::refs(P::st.named).contains(w))
  /// The recovered successor refuses the FILL of a key tenure 1's acknowledged INVALIDATE covers.
  val witnessSuccessorRefusesAcked = act == "refusedFill" and P::st.phase == "serving" and P::st.srv == 2
    and C::acks.exists(a => a.t == 1 and C::refused.contains((2, a.k, a.v)))
  /// A recovery loads the entry of a page whose coverage write failed its condition.
  val witnessFailedCasRetained = act == "recover" and C::results.keys().exists(i => C::results.get(i).kind == "cover"
    and not(C::results.get(i).ok) and P::st.recovered.exists(w => P::m(w).key == C::results.get(i).p))
  /// A recovery loads key 1's entry, which no INVALIDATE targets, beside the entry of a page whose coverage write
  /// committed while its reply timed out. The recovering tenure's fenced coverage covers that second entry, and
  /// recovery loads it because it takes its invalidation exclusions from `acked`, which holds acknowledged INVALIDATEs
  /// only; a recovery that left out covered entries would leave this witness unreached.
  val witnessLostReplyRetained = act == "recover" and C::timedOut.exists(i => C::results.keys().contains(i)
    and C::results.get(i).ok and C::results.get(i).kind == "cover"
    and P::st.recovered.exists(w => P::m(w).key == C::results.get(i).p
      and C::covered(C::cov.get(P::st.ten), P::m(w).key + 1, 1)))
    and P::st.recovered.exists(w => P::m(w).key == 1)
}

/// Possibly named slots, the settled floor and reuse (P6, P7). One tenure of `prefix` publishes captures through
/// exact-version Publishes and Confirms, and the log part of `saturation` holds the floor, the tenure's suffix and its
/// appends:
/// - `capture` is prefix's capture, and the ghost `cutOf` records the log head as its cut;
/// - `succeed` is prefix's learned success, together with the log's floor rise to the capture's cut exactly when the
///   success shrinks the possibly named set (`settles` is prefix's `newest` and `shrink`), which is the Rust rule
///   `settled_floor`;
/// - `apply`, `unresolved`, `read`, `confirm` and `stale` are prefix alone; the suffix record, extension, append and
///   durability are the log alone;
/// - `takeover` is the log's takeover together with prefix's recovery read of the named slot. The takeover ends every
///   Publish in flight, as the store record's version bump at a takeover does: prefix takes no step after it, and
///   `reachable` drops the writes in flight.
module prefixSaturation {
  const BOUND: int
  import prefix(BOUND = BOUND) as P from "./prefix"
  import saturation(BOUND = BOUND) as S from "./saturation"
  var turn: int
  var act: str
  /// The log head at each capture, the capture's cut; capture 0 is the record's initial capture.
  var cutOf: int -> int
  var took: bool

  action keepP = all {
    P::named' = P::named, P::namedId' = P::namedId, P::ver' = P::ver, P::known' = P::known,
    P::knownNamed' = P::knownNamed, P::knownId' = P::knownId, P::recovered' = P::recovered, P::possible' = P::possible,
    P::quar' = P::quar, P::pending' = P::pending, P::inflight' = P::inflight, P::committed' = P::committed,
    P::succeeded' = P::succeeded, P::nextId' = P::nextId, P::content' = P::content, P::written' = P::written,
    P::prior' = P::prior, P::submits' = P::submits, P::priorSubmits' = P::priorSubmits, P::turn' = P::turn, P::ev' = P::ev,
  }
  action keepS = all { S::log' = S::log, S::slots' = S::slots, S::prior' = S::prior, S::turn' = S::turn, S::ev' = S::ev }
  action joint(a: str): bool = all { turn < BOUND, turn' = turn + 1, act' = a }
  action keepGhost = all { cutOf' = cutOf, took' = took }
  /// Prefix's `succeed` of `p` shrinks the possibly named set to `p`'s slot: its `newest` and `shrink`.
  def settles(p: P::Pub): bool =
    p.at + 1 >= P::known and P::submitted.forall(q => q == p.id or P::succeeded.contains(q) or q < p.id)

  action init = all { P::init, S::init, turn' = 0, act' = "init", cutOf' = Map(0 -> 0), took' = false }
  action capture = all { not(took), joint("capture"), P::capture(1), keepS, took' = took,
    cutOf' = if (P::free(P::possible.union(P::quar)) != Set()) cutOf.put(P::nextId, S::log.head) else cutOf }
  action apply = { nondet p = P::inflight.oneOf() all { not(took), joint("apply"), P::apply(p), keepS, keepGhost } }
  action succeed = {
    nondet p = P::pending.oneOf()
    val c = cutOf.get(p.capture)
    all { not(took), joint(if (not(settles(p))) "succeed" else if (p.capture == p.id) "settle" else "settleConfirm"),
          P::succeed(p), keepGhost, if (settles(p) and S::log.floor <= c) S::publish(c) else keepS }
  }
  action unresolved = { nondet p = P::pending.oneOf() all { not(took), joint("unresolved"), P::unresolved(p), keepS, keepGhost } }
  action read = all { not(took), joint("read"), P::read, keepS, keepGhost }
  action confirm = all { not(took), joint("confirm"), P::confirm, keepS, keepGhost }
  action stale = { nondet w = P::written.oneOf() all { not(took), joint("stale"), P::stale(w), keepS, keepGhost } }
  action recordSuffix = { nondet r = 1.to(S::J).oneOf() all { joint("recordSuffix"), S::recordSuffix(r), keepP, keepGhost } }
  action extend = { nondet e = 0.to(S::LMAX + S::J).oneOf() all { joint("extend"), S::extend(e), keepP, keepGhost } }
  action appendBlock = all { joint("append"), S::appendBlock, keepP, keepGhost }
  action written = all { joint("written"), S::written, keepP, keepGhost }
  action takeover = all { not(took), joint("takeover"), S::takeover, P::recover, cutOf' = cutOf, took' = true }
  action step = any { capture, apply, succeed, unresolved, read, confirm, stale, recordSuffix, extend, appendBlock, written,
    takeover }

  /// The captures whose cut the store names or may still name: the named capture and, before the takeover, every
  /// write in flight at the record's version.
  val reachable = Set(P::namedId).union(if (took) Set() else P::inflight.filter(p => p.at == P::ver).map(p => p.capture))
  /// The `settled_floor` premise: the floor lies at or below every reachable cut.
  val FloorBelowReachable = reachable.forall(c => S::log.floor <= cutOf.get(c))
  /// P7: no block at or above a reachable cut is reused; the head stays within `J` blocks of every reachable cut.
  val ReachableHistoryIntact = reachable.forall(c => S::log.head <= cutOf.get(c) + S::J)
  /// Both models' safety, prefix's `NoStaleLoad`, a warm recovery that loads the named capture's own units, and the
  /// joint invariants.
  val safety = P::safety and P::NoStaleLoad and S::safety and FloorBelowReachable and ReachableHistoryIntact

  /// After a warm recovery, an append writes the unit of a block below the settled floor.
  val witnessReuseAfterSettle = took and P::recovered == "warm" and S::ev == "append"
    and S::log.head - 1 - S::J >= 0 and S::log.head - 1 - S::J < S::log.floor
  /// A Confirm's success settles the set and raises the floor above 0.
  val witnessConfirmSettles = act == "settleConfirm" and S::ev == "publish" and S::log.floor > 0
  /// A success that settles nothing, beside a later write still pending or in flight.
  val witnessPendingKeepsFloor = act == "succeed" and P::inflight.union(P::pending).exists(p => p.capture > P::namedId)
  /// A warm recovery of a named capture whose success the host never learned, with the floor below its cut.
  val witnessUnknownNamedRecovered = took and P::recovered == "warm" and P::committed.contains(P::namedId)
    and not(P::succeeded.contains(P::namedId)) and S::log.floor < cutOf.get(P::namedId)
}
