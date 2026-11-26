/// The reconciler's creation steps over one shard record, its two coverage pages and one volume record, one
/// store request per step: two processes run create_shard, provision and record_attach with the request order of
/// `failover/reconcile.rs` and the store client's shard creation. A create commits only on an absent record and
/// an exact-version write only at its version; a write's reply may be lost with or without its commit, and one
/// write may be held and released later. The owner fences a page once the shard record exists.
module creation {
  const BOUND: int
  /// The shard record: whether it exists, the creation it records (1 or 2) and its version.
  type Shard = {exists: bool, id: int, ver: int}
  /// A coverage page: whether it exists, its version, and whether it holds a fence.
  type Page = {exists: bool, ver: int, fenced: bool}
  /// The volume record: 0 absent, 1 provisioning, 2 fresh with `host`'s one attach event; and its version.
  type Volume = {state: int, host: int, ver: int}
  /// A process: its operation, the creation or host it names, its next request, the volume version it read and
  /// its last result.
  type Proc = {op: str, arg: int, pc: int, vver: int, res: str}
  /// A held write: the record it names, whether it is a create, the version an exact write conditions on, and
  /// the creation or host it writes.
  type Held = {on: bool, key: str, create: bool, expect: int, arg: int}
  type Event = {act: str, proc: int, op: str, arg: int, key: str, res: str}
  type State = {
    shard: Shard, pages: int -> Page, vol: Volume, procs: int -> Proc, held: Held,
    witnesses: Set[int], hosts: Set[int], returned: Set[int], ev: Event
  }
  var st: State
  var turn: int
  pure val PAGES = Set(0, 1)
  pure val PROCS = Set(0, 1)
  pure val OPS = Set("createShard", "provision", "attach")
  pure val ARGS = Set(1, 2)
  pure val FAULTS = Set("commit", "lost", "hold")
  pure val ABSENT = 0
  pure val PROVISIONING = 1
  pure val FRESH = 2
  pure val IDLE: Proc = {op: "idle", arg: 0, pc: 0, vver: 0, res: ""}
  pure val NOTHING: Held = {on: false, key: "", create: false, expect: 0, arg: 0}
  pure def ended(p: Proc, res: str): Proc = {...p, op: "idle", res: res}
  /// The record the process's next request names. A shard creation reads the shard record (0), creates page 0
  /// (1), reads it after a refused create (2), does the same for page 1 (3, 4), creates the shard record (5) and
  /// reads it after a refusal (6). A provision creates the volume record (0) and reads it after a refusal (1).
  /// An attach reads the volume record (0) and writes it (1).
  pure def key(p: Proc): str =
    if (p.op != "createShard") "volume"
    else if (p.pc == 1 or p.pc == 2) "page0"
    else if (p.pc == 3 or p.pc == 4) "page1"
    else "shard"
  /// Whether the process's next request is a write.
  pure def writes(p: Proc): bool =
    if (p.op == "createShard") p.pc == 1 or p.pc == 3 or p.pc == 5
    else if (p.op == "provision") p.pc == 0
    else p.pc == 1
  /// The write the process issues at its program counter.
  pure def write(p: Proc): Held =
    {on: true, key: key(p), create: p.op != "attach", expect: p.vver, arg: p.arg}
  /// Whether the store admits the write: a create on an absent record, an exact write at its version.
  pure def lands(s: State, w: Held): bool =
    if (w.key == "shard") not(s.shard.exists)
    else if (w.key == "page0") not(s.pages.get(0).exists)
    else if (w.key == "page1") not(s.pages.get(1).exists)
    else if (w.create) s.vol.state == ABSENT
    else s.vol.ver == w.expect
  /// The store after the write commits.
  pure def committed(s: State, w: Held): State =
    if (w.key == "shard") {...s, shard: {exists: true, id: w.arg, ver: 1}}
    else if (w.key == "page0") {...s, pages: s.pages.set(0, {exists: true, ver: 1, fenced: false})}
    else if (w.key == "page1") {...s, pages: s.pages.set(1, {exists: true, ver: 1, fenced: false})}
    else if (w.create) {...s, vol: {state: PROVISIONING, host: 0, ver: 1}}
    else {...s, vol: {state: FRESH, host: w.arg, ver: w.expect + 1}, hosts: s.hosts.union(Set(w.arg))}
  /// The process after its acknowledged write.
  pure def acknowledged(p: Proc): Proc =
    if (p.op == "createShard") (if (p.pc == 5) ended(p, "created") else {...p, pc: p.pc + 2})
    else if (p.op == "provision") ended(p, "provisioned")
    else ended(p, "recorded")
  /// The process after its write refuses on its condition.
  pure def refused(p: Proc): Proc =
    if (p.op == "createShard") (if (p.pc == 5) {...p, pc: 6} else {...p, pc: p.pc + 1})
    else if (p.op == "provision") {...p, pc: 1}
    else ended(p, "condition")
  /// The shard record the store holds, judged as a replay of the process's creation.
  pure def replayed(s: State, p: Proc): Proc = ended(p, if (s.shard.id == p.arg) "found" else "conflict")
  /// The process after its next read returns the record the store holds.
  pure def reads(s: State, p: Proc): Proc =
    if (p.op == "createShard" and p.pc == 0) (if (s.shard.exists) replayed(s, p) else {...p, pc: 1})
    else if (p.op == "createShard" and p.pc == 6) (if (s.shard.exists) replayed(s, p) else ended(p, "conflict"))
    else if (p.op == "createShard") {
      val page = s.pages.get(if (p.pc == 2) 0 else 1)
      if (page.exists and page.ver == 1 and not(page.fenced)) {...p, pc: p.pc + 1} else {...p, pc: 6}
    }
    else if (p.op == "provision") ended(p, if (s.vol.state == PROVISIONING) "found" else "conflict")
    else if (s.vol.state == ABSENT) ended(p, "absent")
    else if (s.vol.state == PROVISIONING) {...p, pc: 1, vver: s.vol.ver}
    else if (s.vol.host == p.arg) ended(p, "recorded")
    else ended(p, "conflict")
  pure def event(act: str, proc: int, p: Proc, name: str, res: str): Event =
    {act: act, proc: proc, op: p.op, arg: p.arg, key: name, res: res}
  /// The history a returned result adds: an attach witness, or the creation a shard creation returned.
  pure def recorded(s: State, p: Proc, after: Proc): State =
    if (after.op != "idle") s
    else if (p.op == "attach" and after.res == "recorded") {...s, witnesses: s.witnesses.union(Set(p.arg))}
    else if (p.op == "createShard" and (after.res == "created" or after.res == "found"))
      {...s, returned: s.returned.union(Set(p.arg))}
    else s
  action init = all {
    st' = {shard: {exists: false, id: 0, ver: 0}, pages: PAGES.mapBy(_ => {exists: false, ver: 0, fenced: false}),
      vol: {state: ABSENT, host: 0, ver: 0}, procs: PROCS.mapBy(_ => IDLE), held: NOTHING,
      witnesses: Set(), hosts: Set(), returned: Set(), ev: event("init", 0, IDLE, "", "")},
    turn' = 0
  }
  action count = all {turn < BOUND, turn' = turn + 1}
  /// A caller starts an operation on an idle process: a shard creation of creation `arg`, a provision, or the
  /// attach record of host `arg`.
  action begin(p: int, op: str, arg: int): bool = {
    val started = {...IDLE, op: op, arg: if (op == "provision") 0 else arg}
    all {count, st.procs.get(p).op == "idle",
      st' = {...st, procs: st.procs.set(p, started), ev: event("begin", p, started, "", "")}
    }
  }
  /// The process's next request reaches the store and its reply returns.
  action request(p: int): bool = {
    val proc = st.procs.get(p)
    val w = write(proc)
    val after = if (not(writes(proc))) reads(st, proc)
      else if (lands(st, w)) acknowledged(proc)
      else refused(proc)
    val stored = if (writes(proc) and lands(st, w)) committed(st, w) else st
    all {count, proc.op != "idle",
      st' = {...recorded(stored, proc, after), procs: st.procs.set(p, after),
        ev: event(if (writes(proc)) "write" else "read", p, proc, key(proc), if (after.op == "idle") after.res else "")}
    }
  }
  /// The process's next write gets no reply: it commits, is lost, or is held; the operation ends unknown.
  action unknown(p: int, fault: str): bool = {
    val proc = st.procs.get(p)
    val w = write(proc)
    val stored = if (fault == "commit" and lands(st, w)) committed(st, w)
      else if (fault == "hold") {...st, held: w}
      else st
    all {count, proc.op != "idle", writes(proc), fault == "hold" implies not(st.held.on),
      st' = {...stored, procs: st.procs.set(p, ended(proc, "unknown")), ev: event(fault, p, proc, key(proc), "unknown")}
    }
  }
  /// The held write reaches the store.
  action release = all {count, st.held.on,
    st' = {...(if (lands(st, st.held)) committed(st, st.held) else st), held: NOTHING,
      ev: event("release", 0, IDLE, st.held.key, if (lands(st, st.held)) "committed" else "refused")}
  }
  /// The owner fences a page of the created shard.
  action fence(page: int): bool = all {count, st.shard.exists, st.pages.get(page).exists, not(st.pages.get(page).fenced),
    st' = {...st, pages: st.pages.set(page, {exists: true, ver: st.pages.get(page).ver + 1, fenced: true}),
      ev: event("fence", 0, IDLE, if (page == 0) "page0" else "page1", "")}
  }
  val WitnessMeansRecorded = st.witnesses.forall(h => st.vol.state == FRESH and st.vol.host == h)
  val OneAttachForLife = st.hosts.size() <= 1
  val CreationReturnsItsOwnRecord = st.returned.forall(id => st.shard.exists and st.shard.id == id)
  val PagesBeforeTheShard = st.shard.exists implies PAGES.forall(page => st.pages.get(page).exists)
  val safety = WitnessMeansRecorded and OneAttachForLife and CreationReturnsItsOwnRecord and PagesBeforeTheShard
  action step = {
    nondet p = PROCS.oneOf()
    nondet op = OPS.oneOf()
    nondet arg = ARGS.oneOf()
    nondet fault = FAULTS.oneOf()
    nondet page = PAGES.oneOf()
    any {begin(p, op, arg), request(p), unknown(p, fault), release, fence(page)}
  }
}
