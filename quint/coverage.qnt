/// The coverage pages of one shard in an asynchronous store, and the tenures that fence them, acknowledge
/// INVALIDATEs through them and admit FILLs against the coverage they hold in memory. A tenure is an integer; a later
/// tenure is larger. Every store write is an exact-version compare-and-swap on a page value the host read, which the
/// store applies later, once, or never, and may reject as oversized; the host learns success, failure or nothing. A
/// tenure fences every page before it admits a FILL or acknowledges an INVALIDATE, and adopts a page's blocked set
/// only on the acknowledged success of its own compare-and-swap that set or confirmed its fence. After a coverage
/// write fails its condition or times out, the tenure may re-read the page and take the read as its next basis; after
/// a size rejection it re-reads and writes the page saturated. A saturated page holds no entries and blocks every
/// version of every key on it. A tenure keeps at most one request per page awaiting its reply. With `FENCED_FIRST`,
/// tenure 1 starts with both pages fenced by acknowledged requests 1 and 2.
module coverage {
  const BOUND: int
  const TENURES: int
  const FENCED_FIRST: bool
  pure val PAGES = Set(0, 1)
  pure val KEYS = Set(1, 2, 3)
  pure val VERSIONS = Set(1)
  pure val CPAGE = 1
  pure val REQUESTS = 6
  type Page = { fence: int, ver: int, entries: Set[(int, int)], sat: bool }
  /// A tenure's in-memory coverage: entries `(k, v)` and the pages it holds saturated.
  type Cov = { entries: Set[(int, int)], sat: Set[int] }
  type Req = { id: int, t: int, kind: str, page: int, at: int, value: Page, k: int, v: int }
  /// A decided request: its tenure, kind and page, whether it committed or was rejected as oversized, and the page
  /// value it proposed.
  type Result = { ok: bool, rejected: bool, t: int, kind: str, p: int, page: Page }
  type Ack = { t: int, k: int, v: int, id: int }
  /// The request a page adoption rests on; basis 0 names none.
  type Adoption = { t: int, p: int, basis: int }
  var pages: int -> Page
  var inflight: Set[Req]
  var results: int -> Result
  var pending: Set[Req]
  var nextId: int
  var fenced: int -> Set[int]
  var cov: int -> Cov
  /// The page value each tenure holds as its compare-and-swap basis.
  var known: int -> int -> Page
  /// Pages whose coverage write failed its condition or timed out, and rejected coverage writes awaiting their
  /// saturated rewrite.
  var stale: Set[(int, int)]
  var oversized: Set[Req]
  var withdrawn: Set[int]
  /// Admitted FILLs and refused FILLs, as `(tenure, k, v)`.
  var resident: Set[(int, int, int)]
  var refused: Set[(int, int, int)]
  var acks: Set[Ack]
  var adoptions: Set[Adoption]
  /// Requests whose success the host learned, and requests whose reply timed out.
  var succeeded: Set[int]
  var timedOut: Set[int]
  /// The coverage before the step.
  var prevCov: int -> Cov
  var turn: int

  pure val EMPTY = { fence: 0, ver: 0, entries: Set(), sat: false }
  pure val FIRST_PAGE = { fence: 1, ver: 1, entries: Set(), sat: false }
  pure val NONE = { entries: Set(), sat: Set() }
  pure val PAIRS = tuples(KEYS, VERSIONS)
  pure def pageOf(k: int): int = (k - 1) % 2
  pure def covered(c: Cov, k: int, v: int): bool = c.entries.contains((k, v)) or c.sat.contains(pageOf(k))
  /// The `(k, v)` pairs that page `p` blocks: its entries, or every pair on it when saturated.
  pure def blocked(p: int, pg: Page): Set[(int, int)] = if (pg.sat) PAIRS.filter(e => pageOf(e._1) == p) else pg.entries
  pure def coveredSet(c: Cov): Set[(int, int)] = PAIRS.filter(e => covered(c, e._1, e._2))
  pure def extend(c: Cov, p: int, pg: Page): Cov =
    { entries: c.entries.union(pg.entries), sat: if (pg.sat) c.sat.union(Set(p)) else c.sat }
  def tenures = 1.to(TENURES)
  def live(t: int): bool = tenures.contains(t) and not(withdrawn.contains(t))
  def awaiting(t: int, p: int): bool = pending.exists(r => r.t == t and r.page == p)

  action init = {
    val start = if (FENCED_FIRST) FIRST_PAGE else EMPTY
    val first = PAGES.mapBy(p => start)
    all {
      pages' = first, inflight' = Set(), pending' = Set(),
      results' = if (FENCED_FIRST) Set(1, 2).mapBy(i => { ok: true, rejected: false, t: 1, kind: "fence", p: i - 1,
        page: FIRST_PAGE }) else Map(),
      nextId' = if (FENCED_FIRST) 3 else 1,
      fenced' = tenures.mapBy(t => if (FENCED_FIRST and t == 1) PAGES else Set()),
      cov' = tenures.mapBy(t => NONE),
      known' = tenures.mapBy(t => if (FENCED_FIRST and t == 1) first else PAGES.mapBy(p => EMPTY)),
      stale' = Set(), oversized' = Set(), withdrawn' = Set(), resident' = Set(), refused' = Set(), acks' = Set(),
      adoptions' = if (FENCED_FIRST) PAGES.map(p => { t: 1, p: p, basis: p + 1 }) else Set(),
      succeeded' = if (FENCED_FIRST) Set(1, 2) else Set(), timedOut' = Set(),
      prevCov' = tenures.mapBy(t => NONE), turn' = 0,
    }
  }
  action tick = all { turn < BOUND, turn' = turn + 1, prevCov' = cov }
  action keepStore = all { pages' = pages, inflight' = inflight, results' = results }
  action keepFills = all { resident' = resident, refused' = refused }
  action keepGhosts = all { acks' = acks, adoptions' = adoptions, succeeded' = succeeded, timedOut' = timedOut }
  action keepCoverage = all { fenced' = fenced, cov' = cov, known' = known }
  action keepRetries = all { stale' = stale, oversized' = oversized }
  action submit(r: Req): bool = all {
    inflight' = inflight.union(Set(r)), pending' = pending.union(Set(r)), nextId' = nextId + 1,
    pages' = pages, results' = results,
  }
  action withdraw(t: int): bool = all {
    withdrawn' = withdrawn.union(Set(t)),
    keepStore, pending' = pending, nextId' = nextId, keepCoverage, keepFills, keepGhosts, keepRetries,
  }

  /// A tenure reads page `p`. A newer fence withdraws it; otherwise it submits a compare-and-swap on the read version
  /// that sets its fence, which confirms the fence when the read already shows it.
  action fence(t: int, p: int): bool = {
    val pg = pages.get(p)
    val newer = pg.fence > t
    val mine = pg.fence == t
    val readAdopts = false
    val ownReadAdopts = false
    val shown = results.keys().filter(i => results.get(i).ok and results.get(i).t == t and results.get(i).p == p
      and results.get(i).page == pg)
    all {
      live(t), not(fenced.get(t).contains(p)), not(awaiting(t, p)), tick,
      if (newer) withdraw(t)
      else if (readAdopts or (mine and ownReadAdopts)) all {
        fenced' = fenced.set(t, fenced.get(t).union(Set(p))), cov' = cov.set(t, extend(cov.get(t), p, pg)),
        known' = known.set(t, known.get(t).set(p, pg)),
        adoptions' = adoptions.union(Set({ t: t, p: p, basis: shown.fold(0, (m, i) => if (i > m) i else m) })),
        keepStore, pending' = pending, nextId' = nextId, keepFills, withdrawn' = withdrawn, keepRetries,
        acks' = acks, succeeded' = succeeded, timedOut' = timedOut,
      }
      else all {
        nextId <= REQUESTS,
        submit({ id: nextId, t: t, kind: if (mine) "confirm" else "fence", page: p, at: pg.ver,
                 value: { ...pg, fence: t, ver: pg.ver + 1 }, k: 0, v: 0 }),
        keepCoverage, keepFills, keepGhosts, withdrawn' = withdrawn, keepRetries,
      },
    }
  }
  /// INVALIDATE(k, v) by a tenure that fenced every page: the page value it will write enters the tenure's coverage
  /// before the compare-and-swap on the known version is submitted. An entry beyond `CPAGE` saturates the page.
  action invalidate(t: int, k: int, v: int): bool = {
    val p = pageOf(k)
    val pg = known.get(t).get(p)
    val grown = pg.entries.union(Set((k, v)))
    val value = if (pg.sat) { ...pg, ver: pg.ver + 1 }
      else if (grown.size() > CPAGE) { ...pg, entries: Set(), sat: true, ver: pg.ver + 1 }
      else { ...pg, entries: grown, ver: pg.ver + 1 }
    all {
      live(t), fenced.get(t) == PAGES, not(awaiting(t, p)), nextId <= REQUESTS, tick,
      submit({ id: nextId, t: t, kind: "cover", page: p, at: pg.ver, value: value, k: k, v: v }),
      cov' = cov.set(t, extend(cov.get(t), p, value)),
      acks' = acks, resident' = resident.exclude(Set((t, k, v))),
      fenced' = fenced, known' = known, withdrawn' = withdrawn, refused' = refused, keepRetries,
      adoptions' = adoptions, succeeded' = succeeded, timedOut' = timedOut,
    }
  }
  /// A tenure re-reads page `p` after its coverage write failed its condition or timed out: a newer fence withdraws
  /// it; otherwise the read becomes its basis and its blocked set enters the tenure's coverage.
  action reread(t: int, p: int): bool = {
    val pg = pages.get(p)
    all {
      live(t), stale.contains((t, p)), not(awaiting(t, p)), tick,
      if (pg.fence > t) withdraw(t)
      else all {
        cov' = cov.set(t, extend(cov.get(t), p, pg)), known' = known.set(t, known.get(t).set(p, pg)),
        stale' = stale.exclude(Set((t, p))), oversized' = oversized,
        fenced' = fenced, keepStore, pending' = pending, nextId' = nextId, keepFills, keepGhosts,
        withdrawn' = withdrawn,
      },
    }
  }
  /// After a size rejection the tenure re-reads the page and writes it saturated on the read version; the read and
  /// the saturation enter its coverage before the write is submitted. A newer fence withdraws it.
  action saturate(r: Req): bool = {
    val pg = pages.get(r.page)
    val value = { fence: r.t, ver: pg.ver + 1, entries: Set(), sat: true }
    all {
      live(r.t), not(awaiting(r.t, r.page)), nextId <= REQUESTS, tick,
      if (pg.fence > r.t) withdraw(r.t)
      else all {
        submit({ ...r, id: nextId, at: pg.ver, value: value }),
        cov' = cov.set(r.t, extend(extend(cov.get(r.t), r.page, pg), r.page, value)),
        known' = known.set(r.t, known.get(r.t).set(r.page, pg)),
        oversized' = oversized.exclude(Set(r)), stale' = stale,
        fenced' = fenced, keepFills, keepGhosts, withdrawn' = withdrawn,
      },
    }
  }
  /// FILL(k, v) by a tenure that fenced every page: admitted when its coverage leaves `(k, v)` uncovered.
  action fill(t: int, k: int, v: int): bool = {
    val ready = fenced.get(t) == PAGES
    all {
      live(t), ready, not(resident.contains((t, k, v))), not(refused.contains((t, k, v))), tick,
      if (covered(cov.get(t), k, v)) all { refused' = refused.union(Set((t, k, v))), resident' = resident }
      else all { resident' = resident.union(Set((t, k, v))), refused' = refused },
      keepStore, pending' = pending, nextId' = nextId, keepCoverage, keepGhosts, withdrawn' = withdrawn, keepRetries,
    }
  }
  /// The store applies a request: it commits exactly when its version is the page's.
  action apply(r: Req): bool = {
    val ok = pages.get(r.page).ver == r.at
    all {
      tick,
      inflight' = inflight.exclude(Set(r)),
      pages' = if (ok) pages.set(r.page, r.value) else pages,
      results' = results.put(r.id, { ok: ok, rejected: false, t: r.t, kind: r.kind, p: r.page, page: r.value }),
      pending' = pending, nextId' = nextId, keepCoverage, keepFills, keepGhosts, withdrawn' = withdrawn, keepRetries,
    }
  }
  /// The store refuses an unsaturated coverage write as oversized and leaves the page unchanged.
  action reject(r: Req): bool = all {
    r.kind == "cover", not(r.value.sat), tick,
    inflight' = inflight.exclude(Set(r)), pages' = pages,
    results' = results.put(r.id, { ok: false, rejected: true, t: r.t, kind: r.kind, p: r.page, page: r.value }),
    pending' = pending, nextId' = nextId, keepCoverage, keepFills, keepGhosts, withdrawn' = withdrawn, keepRetries,
  }
  /// The host learns a decided request's result. A fence or confirm success adopts the page; a coverage success
  /// acknowledges the INVALIDATE; a size rejection awaits the saturated rewrite; a coverage write that failed its
  /// condition leaves its page stale; a failed fence changes nothing.
  action reply(r: Req): bool = {
    val res = results.get(r.id)
    val absorbed = r.value
    all {
      live(r.t), tick, keepStore, nextId' = nextId, keepFills, timedOut' = timedOut,
      pending' = pending.exclude(Set(r)),
      if (res.ok) all {
        succeeded' = succeeded.union(Set(r.id)),
        cov' = cov.set(r.t, extend(cov.get(r.t), r.page, absorbed)),
        known' = known.set(r.t, known.get(r.t).set(r.page, r.value)),
        fenced' = if (r.kind == "cover") fenced else fenced.set(r.t, fenced.get(r.t).union(Set(r.page))),
        acks' = if (r.kind == "cover") acks.union(Set({ t: r.t, k: r.k, v: r.v, id: r.id })) else acks,
        adoptions' = if (r.kind == "cover") adoptions else adoptions.union(Set({ t: r.t, p: r.page, basis: r.id })),
        withdrawn' = withdrawn, keepRetries,
      }
      else all {
        oversized' = if (res.rejected) oversized.union(Set(r)) else oversized,
        stale' = if (r.kind == "cover" and not(res.rejected)) stale.union(Set((r.t, r.page))) else stale,
        withdrawn' = withdrawn, keepCoverage, acks' = acks, adoptions' = adoptions, succeeded' = succeeded,
      },
    }
  }
  /// The reply is lost or times out, whether or not the store applied the request; a coverage write's page is stale.
  action timeout(r: Req): bool = all {
    tick, pending' = pending.exclude(Set(r)), timedOut' = timedOut.union(Set(r.id)),
    stale' = if (r.kind == "cover") stale.union(Set((r.t, r.page))) else stale, oversized' = oversized,
    keepStore, nextId' = nextId, keepCoverage, keepFills, withdrawn' = withdrawn,
    acks' = acks, adoptions' = adoptions, succeeded' = succeeded,
  }
  action applyId(i: int): bool = all { inflight.exists(r => r.id == i), nondet r = inflight.filter(r => r.id == i).oneOf() apply(r) }
  action rejectId(i: int): bool = all { inflight.exists(r => r.id == i), nondet r = inflight.filter(r => r.id == i).oneOf() reject(r) }
  action replyId(i: int): bool = all {
    pending.exists(r => r.id == i), results.keys().contains(i), nondet r = pending.filter(r => r.id == i).oneOf() reply(r)
  }
  action timeoutId(i: int): bool = all { pending.exists(r => r.id == i), nondet r = pending.filter(r => r.id == i).oneOf() timeout(r) }
  action saturateId(i: int): bool = all {
    oversized.exists(r => r.id == i), nondet r = oversized.filter(r => r.id == i).oneOf() saturate(r)
  }
  action step = any {
    nondet t = tenures.oneOf()
    nondet p = PAGES.oneOf()
    any { fence(t, p), reread(t, p) },
    nondet t = tenures.oneOf()
    nondet k = KEYS.oneOf()
    nondet v = VERSIONS.oneOf()
    any { invalidate(t, k, v), fill(t, k, v) },
    nondet i = 1.to(REQUESTS).oneOf()
    any { applyId(i), rejectId(i), replyId(i), timeoutId(i), saturateId(i) },
  }

  /// Every acknowledged INVALIDATE rests on the tenure's own coverage write, whose success the host learned from its
  /// reply, that committed with the tenure's fence while every page of the tenure was fenced, and whose page value
  /// blocks the entry; and every coverage write in flight or awaiting its reply belongs to a tenure that fenced
  /// every page.
  val NoAckBeforeAuthoritative = acks.forall(a => succeeded.contains(a.id) and fenced.get(a.t) == PAGES
    and results.keys().contains(a.id) and {
      val res = results.get(a.id)
      res.ok and res.t == a.t and res.kind == "cover" and res.page.fence == a.t
        and blocked(res.p, res.page).contains((a.k, a.v))
    })
    and inflight.union(pending).forall(r => r.kind != "cover" or fenced.get(r.t) == PAGES)
  /// No page's fence or blocked set shrinks across its committed writes, ordered by version, and no tenure's covered
  /// set shrinks in a step.
  val CoverageNeverDecreases = results.keys().forall(i => results.keys().forall(j => {
      val a = results.get(i)
      val b = results.get(j)
      (a.ok and b.ok and a.p == b.p and a.page.ver < b.page.ver)
        implies (a.page.fence <= b.page.fence and blocked(a.p, a.page).subseteq(blocked(b.p, b.page)))
    }))
    and tenures.forall(t => coveredSet(prevCov.get(t)).subseteq(coveredSet(cov.get(t))))
  /// A tenure that fenced every page covers every INVALIDATE an earlier tenure acknowledged.
  val FencedCoverageComplete = tenures.forall(t => fenced.get(t) == PAGES
    implies acks.forall(a => a.t < t implies covered(cov.get(t), a.k, a.v)))
  /// No resident FILL of a tenure is an entry that it or an earlier tenure acknowledged as invalidated; an
  /// INVALIDATE evicts the tenure's resident entry of its `(k, v)` when it is submitted.
  val NoCoveredResidency = resident.forall(r => acks.forall(a => not(a.t <= r._1 and a.k == r._2 and a.v == r._3)))
  /// Every adoption rests on a fence or confirm of the tenure's own on that page that the store committed with the
  /// tenure's fence.
  val FenceOrder = adoptions.forall(a => results.keys().contains(a.basis) and {
    val res = results.get(a.basis)
    res.ok and res.t == a.t and res.p == a.p and res.kind != "cover" and res.page.fence == a.t
  })
  /// Every adoption rests on a request whose success the host learned from its reply; a commit whose reply timed out
  /// is unknown to the host.
  val NoAdoptionFromUnknown = adoptions.forall(a => succeeded.contains(a.basis))
  val safety = NoAckBeforeAuthoritative and CoverageNeverDecreases and FencedCoverageComplete and NoCoveredResidency
    and FenceOrder and NoAdoptionFromUnknown

  val witnessFencedAll = tenures.exists(t => t > 1 and fenced.get(t) == PAGES)
  val witnessCarryForward = tenures.exists(t => fenced.get(t) == PAGES and acks.exists(a => a.t < t))
  val witnessConfirmed = adoptions.exists(a => results.keys().contains(a.basis) and results.get(a.basis).kind == "confirm")
  val witnessWithdrawn = withdrawn.size() >= 1
  val witnessCommittedTimeout = timedOut.exists(i => results.keys().contains(i) and results.get(i).ok)
  val witnessFillRefused = refused.size() >= 1
  val witnessAck = acks.size() >= 1
  val witnessSaturated = PAGES.exists(p => pages.get(p).sat)
}
