/// The volume-loss replacement over two shards in one AZ: two reconcilers and an operator run the receipt steps of
/// `failover/reconcile.rs` (`replacement`, `create_replacement`, `release_hold`, `retire` with `abandon`, and
/// `add_spare` with `flip`) over the shard records, the replacement receipts and the volume records. A step is one
/// such operation, and each of its store requests and provider calls is a separate action. The control plane
/// reports each volume available, impaired or lost, and a host may be lost; a process observes every volume's health
/// when it starts a step and decides from that observation. A store write commits only at the version it read, or on
/// an absent record for a create, and its reply may be lost after it commits. A provider create may make a volume,
/// refuse for good or never arrive, and its reply may be lost; the provider keeps each token's outcome. Either
/// reconciler or the operator may crash before any pending request of its step, the first one included; a request
/// already sent stays committed.
module loss {
  const BOUND: int
  /// A shard's replacement receipt for the generation after the first: the attempt, its phase (`open`, `issued`,
  /// `created` with `vol`), the hold and the release, and the store version, 0 while absent.
  type Receipt = {exists: bool, attempt: int, phase: str, vol: int, held: bool, released: bool, ver: int}
  /// A shard record: its generation, active volume, spare (0 for none) and version.
  type ShardRec = {g: int, active: int, spare: int, ver: int}
  /// A volume record: `ABSENT`, `PROVISIONED`, `ACTIVE` or `RETIRED`, and its version.
  type VolRec = {state: int, ver: int}
  /// The control plane's view of a volume: the shard whose volume it is and its health.
  type Vol = {shard: int, health: str}
  /// The outcome a provider keeps for a token: `volume` with the volume it made, or `failed`.
  type Outcome = {kind: str, vol: int}
  /// One step in progress: its operation, shard and next request; the lost volumes of its shard it observed at its
  /// start, kept by `replacement` and `abandon` until the read that decides on them and empty otherwise; whether it
  /// observed an impaired or lost volume of the other shard (1) or none (0), kept by `replacement`, `create` and
  /// `abandon` and 0 for `release` and `flip`; `seen`, that same count as the control plane held it when the step
  /// started, which the invariants and witnesses read and no step does; the receipt it carries, which a flip clears
  /// at its shard reread and again when its fence is acknowledged, so the flip write counts only a receipt read after
  /// the fence; the receipt `abandon` observed; the shard and volume record versions its next write conditions on;
  /// the volume it works on; and the spare its shard read showed, kept until its volume read.
  type Proc = {op: str, shard: int, pc: str, lost: Set[int], others: int, seen: int, rc: Receipt, obs: Receipt,
    sver: int, vver: int, vol: int, spare: int}
  type Step = {p: Proc, res: str}
  type Made = {shard: int, attempt: int, vol: int}
  /// A provider call with the receipt the caller carried, from its read or from its acknowledged issue write (its
  /// attempt, phase, hold and release), and whether the other shard had an impaired or lost volume when the step
  /// started.
  type Call = {shard: int, attempt: int, phase: str, readHeld: bool, seen: int, released: bool}
  /// A committed spare write or flip of `vol`: the generation of the shard record it replaced, whether the step
  /// carries a receipt from a read before it, and whether that read showed a hold of `vol`. A flip starts only over
  /// an existing receipt, so a read of the receipt always carries one.
  type Flip = {shard: int, vol: int, g: int, read: bool, readHeld: bool}
  /// The last action: a receipt write it committed (`rw`), whether that write opened an attempt, the receipt before
  /// and after it, whether the other shard had an impaired or lost volume when the step started (0 for an
  /// environment action and for `release` and `flip`), the attempt of the receipt the process carries, and for a
  /// provider call whether the provider returned a kept outcome.
  type Event = {act: str, proc: int, op: str, shard: int, pc: str, res: str, rw: bool, opens: bool, before: Receipt,
    after: Receipt, seen: int, attempt: int, kept: bool}
  type State = {
    shards: int -> ShardRec, rcpts: int -> Receipt, vrecs: int -> VolRec, vols: int -> Vol, hostLost: Set[int],
    prov: (int, int) -> Outcome, next: int, procs: int -> Proc,
    issued: Set[(int, int)], made: Set[Made], recorded: Set[Made], calls: Set[Call], spares: Set[Flip],
    flips: Set[Flip], ev: Event
  }
  var st: State
  var turn: int
  pure val SHARDS = Set(1, 2)
  /// Host `h` owns shard `h`.
  pure val HOSTS = Set(1, 2)
  pure val OPERATOR = 0
  pure val PROCS = Set(0, 1, 2)
  pure val OPS = Set("replacement", "create", "release", "abandon", "flip")
  pure val RESULTS = Set("make", "fail", "drop")
  pure val AVAILABLE = "available"
  pure val IMPAIRED = "impaired"
  pure val LOST = "lost"
  pure val ABSENT = 0
  pure val PROVISIONED = 1
  pure val ACTIVE = 2
  pure val RETIRED = 3
  /// The receipt writes; the other writes are `provision`, `retire`, `fence`, `spare` and `flip`.
  pure val RWRITES = Set("start", "latch", "hold", "issue", "record", "release", "raise")
  pure val NONE: Receipt = {exists: false, attempt: 0, phase: "", vol: 0, held: false, released: false, ver: 0}
  pure val IDLE: Proc = {op: "idle", shard: 0, pc: "", lost: Set(), others: 0, seen: 0, rc: NONE, obs: NONE, sver: 0,
    vver: 0, vol: 0, spare: 0}
  /// The create token of a shard's attempt: the generation is the same for every receipt of the model.
  pure def token(shard: int, attempt: int): (int, int) = (shard, attempt)
  pure def go(p: Proc, pc: str): Step = {p: {...p, pc: pc}, res: ""}
  pure def done(res: str): Step = {p: IDLE, res: res}
  /// Whether `r` holds `vol` as the volume its create returned: the receipt check before a spare write or a flip.
  pure def heldAt(r: Receipt, vol: int): bool = r.held and r.phase == "created" and r.vol == vol
  /// The history record of a spare write or flip by `p` that commits over the shard record `rec`, judged on the
  /// receipt `p` carries; the hold test is written out so `ActivatesOnlyUnheld` stays independent of the step's
  /// guard.
  pure def activation(p: Proc, rec: ShardRec): Flip =
    {shard: p.shard, vol: p.vol, g: rec.g, read: p.rc.exists,
      readHeld: p.rc.held and p.rc.phase == "created" and p.rc.vol == p.vol}
  /// Two receipts that differ at most in their hold, release and version.
  pure def flagsOnly(a: Receipt, b: Receipt): bool =
    {...a, held: false, released: false, ver: 0} == {...b, held: false, released: false, ver: 0}
  /// Two receipts with the same value, whatever their versions.
  pure def same(a: Receipt, b: Receipt): bool = {...a, ver: 0} == {...b, ver: 0}
  /// The count of the other shard's impaired or lost volumes.
  pure def othersOf(s: State, shard: int): int =
    s.vols.keys().filter(v => s.vols.get(v).shard != shard and s.vols.get(v).health != AVAILABLE).size()
  /// Whether the observation shows the shard record's active volume lost: `decide`'s `Provision` or `Hold`. The
  /// decision reads the observation alone; `s` gives the `decide-reads-host-loss` mutation the lost hosts.
  pure def evidence(s: State, p: Proc, rec: ShardRec): bool = p.lost.contains(rec.active)
  /// The attempt after `r`'s, held beside another impaired or lost volume unless the operator released the hold.
  pure def nextAttempt(r: Receipt, others: int): Receipt =
    {...r, attempt: r.attempt + 1, phase: "open", vol: 0, held: others > 0 and not(r.released), ver: r.ver + 1}
  /// The receipt a receipt write stores.
  pure def receiptWrite(p: Proc): Receipt =
    if (p.pc == "start") {exists: true, attempt: 1, phase: "open", vol: 0, held: p.others > 0, released: false, ver: 1}
    else if (p.pc == "latch") {...p.rc, held: true, ver: p.rc.ver + 1}
    else if (p.pc == "hold") {...p.rc, held: true, ver: p.rc.ver + 1}
    else if (p.pc == "issue") {...p.rc, phase: "issued", ver: p.rc.ver + 1}
    else if (p.pc == "record") {...p.rc, phase: "created", vol: p.vol, ver: p.rc.ver + 1}
    else if (p.pc == "release") {...p.rc, held: false, released: true, ver: p.rc.ver + 1}
    else nextAttempt(p.rc, p.others)
  pure def writes(p: Proc): bool =
    RWRITES.contains(p.pc) or Set("provision", "retire", "fence", "spare", "flip").contains(p.pc)
  /// Whether the store commits the process's write: a create on an absent record, any other write at its version.
  pure def lands(s: State, p: Proc): bool =
    if (p.pc == "start") not(s.rcpts.get(p.shard).exists)
    else if (RWRITES.contains(p.pc)) s.rcpts.get(p.shard).ver == p.rc.ver
    else if (p.pc == "provision") s.vrecs.get(p.vol).state == ABSENT
    else if (p.pc == "retire" or p.pc == "fence") s.vrecs.get(p.vol).ver == p.vver
    else s.shards.get(p.shard).ver == p.sver
  /// The store after the process's write commits. A flip write stores generation 2, the one after the generation 1
  /// its step's shard reread admits, whatever the stored record holds when the write commits.
  pure def committed(s: State, p: Proc): State =
    if (RWRITES.contains(p.pc)) {
      val r = receiptWrite(p)
      {...s, rcpts: s.rcpts.set(p.shard, r),
        issued: if (p.pc == "issue") s.issued.union(Set(token(p.shard, r.attempt))) else s.issued,
        recorded: if (p.pc == "record") s.recorded.union(Set({shard: p.shard, attempt: r.attempt, vol: r.vol}))
          else s.recorded}
    }
    else if (p.pc == "provision") {...s, vrecs: s.vrecs.set(p.vol, {state: PROVISIONED, ver: 1})}
    else if (p.pc == "retire") {...s, vrecs: s.vrecs.set(p.vol, {state: RETIRED, ver: p.vver + 1})}
    else if (p.pc == "fence") {...s, vrecs: s.vrecs.set(p.vol, {...s.vrecs.get(p.vol), ver: p.vver + 1})}
    else if (p.pc == "spare") {...s, shards: s.shards.set(p.shard, {...s.shards.get(p.shard), spare: p.vol, ver: p.sver + 1}),
      spares: s.spares.union(Set(activation(p, s.shards.get(p.shard))))}
    else {...s, shards: s.shards.set(p.shard, {g: 2, active: p.vol, spare: 0, ver: p.sver + 1}),
      flips: s.flips.union(Set(activation(p, s.shards.get(p.shard))))}
  /// The process after its write is acknowledged.
  pure def acked(p: Proc): Step =
    if (p.pc == "issue") go({...p, rc: receiptWrite(p)}, "call")
    else if (p.pc == "provision") go(p, "record")
    else if (p.pc == "retire") go({...p, vver: 0}, "current")
    else if (p.pc == "spare") go(p, "reread")
    else if (p.pc == "fence") go({...p, vver: 0, rc: NONE}, "recheck")
    else if (p.pc == "latch" or p.pc == "hold") done("held")
    else done(p.pc)
  /// The process after its write is refused on its condition.
  pure def refused(p: Proc): Step = if (p.pc == "provision") go(p, "provRead") else done("condition")
  /// The process after its read returns what the store holds.
  pure def reads(s: State, p: Proc): Step = {
    val r = s.rcpts.get(p.shard)
    val rec = s.shards.get(p.shard)
    val vrec = s.vrecs.get(p.vol)
    if (p.op == "replacement" and p.pc == "shard")
      if (rec.g != 1) done("outside")
      else if (not(evidence(s, p, rec))) done("retain")
      else go({...p, lost: Set()}, "receipt")
    else if (p.op == "replacement")
      if (not(r.exists)) go(p, "start")
      else if (p.others > 0 and not(r.released) and not(r.held)) go({...p, rc: r}, "latch")
      else done("returned")
    else if (p.op == "create" and p.pc == "receipt")
      if (not(r.exists)) done("absent")
      else if (r.held) done("held")
      else if (p.others > 0 and not(r.released)) go({...p, rc: r}, "hold")
      else go({...p, rc: r}, "shard")
    else if (p.op == "create" and p.pc == "shard")
      if (p.rc.phase == "created") done(if (rec.g == 1) "created" else "stale")
      else if (p.rc.phase == "open") (if (rec.g == 1) go(p, "issue") else done("stale"))
      else go(p, "call")
    else if (p.op == "create" and p.pc == "provRead")
      if (vrec.state == PROVISIONED) go(p, "record") else go(p, "reread")
    else if (p.op == "create")
      done(if (r.phase == "created" and r.vol == p.vol and not(r.held)) "created"
        else if (r == p.rc) "conflict" else "stale")
    else if (p.op == "release")
      if (not(r.exists)) done("absent")
      else if (r.held) go({...p, rc: r}, "release") else done("unheld")
    else if (p.op == "abandon" and p.pc == "observe")
      if (r.exists and r.phase == "created" and not(r.held) and p.lost.contains(r.vol))
        go({...p, lost: Set(), obs: r, vol: r.vol}, "volume")
      else done("nothing")
    else if (p.op == "abandon" and p.pc == "volume")
      if (vrec.state == RETIRED) go(p, "current") else go({...p, vver: vrec.ver}, "named")
    else if (p.op == "abandon" and p.pc == "named")
      if (rec.active == p.vol or rec.spare == p.vol) done("named") else go(p, "retire")
    else if (p.op == "abandon" and p.pc == "current")
      if (r.attempt == p.obs.attempt + 1 and r.phase == "open") done("replayed")
      else if (r.attempt == p.obs.attempt and r.phase == "created" and r.vol == p.vol and r.held) done("held")
      else if (not(same(r, p.obs))) done("stale")
      else go({...p, rc: r}, "due")
    else if (p.op == "abandon")
      if (rec.g == 1) go(p, "raise") else done("stale")
    else if (p.op == "flip" and p.pc == "shard")
      if (rec.g != 1) done("past")
      else if (rec.active == p.vol or (rec.spare != 0 and rec.spare != p.vol)) done("conflict")
      else go({...p, sver: rec.ver, spare: rec.spare}, "volume")
    else if (p.op == "flip" and p.pc == "volume")
      if (vrec.state != PROVISIONED) done("conflict")
      else if (p.spare == p.vol) go(p, "reread")
      else go(p, "receipt")
    else if (p.op == "flip" and p.pc == "receipt")
      if (heldAt(r, p.vol)) done("held") else go({...p, rc: r}, "spare")
    else if (p.op == "flip" and p.pc == "reread")
      if (rec.g != 1) done("past") else if (rec.spare != p.vol) done("conflict")
      else go({...p, sver: rec.ver, rc: NONE, spare: 0}, "unused")
    else if (p.op == "flip" and p.pc == "unused")
      if (vrec.state == PROVISIONED) go({...p, vver: vrec.ver}, "fence") else done("conflict")
    else
      if (heldAt(r, p.vol)) done("held") else go({...p, rc: r}, "flip")
  }
  /// The event of a step from `before` to `after` by process `p`, which ran `proc`; `rw` marks a committed receipt
  /// write.
  pure def event(act: str, p: int, proc: Proc, res: str, before: State, after: State, rw: bool): Event = {
    val b = if (rw) before.rcpts.get(proc.shard) else NONE
    val a = if (rw) after.rcpts.get(proc.shard) else NONE
    {act: act, proc: p, op: proc.op, shard: proc.shard, pc: proc.pc, res: res, rw: rw,
      opens: rw and (not(b.exists) or a.attempt != b.attempt), before: b, after: a, seen: proc.seen,
      attempt: proc.rc.attempt, kept: false}
  }
  /// The event of an environment action on volume or host `id`.
  pure def envEvent(act: str, id: int): Event =
    {act: act, proc: 0, op: "", shard: id, pc: "", res: "", rw: false, opens: false, before: NONE, after: NONE,
      seen: 0, attempt: 0, kept: false}
  action init = all {
    st' = {
      shards: SHARDS.mapBy(s => {g: 1, active: s, spare: 0, ver: 1}),
      rcpts: SHARDS.mapBy(_ => NONE),
      vrecs: SHARDS.mapBy(_ => {state: ACTIVE, ver: 1}),
      vols: SHARDS.mapBy(s => {shard: s, health: AVAILABLE}),
      hostLost: Set(), prov: Map(), next: 3, procs: PROCS.mapBy(_ => IDLE),
      issued: Set(), made: Set(), recorded: Set(), calls: Set(), spares: Set(), flips: Set(), ev: envEvent("init", 0)
    },
    turn' = 0
  }
  action count = all {turn < BOUND, turn' = turn + 1}
  /// An idle process starts a step on `shard` and observes the control plane: the operator releases, and a
  /// reconciler runs any other step. The step keeps its shard's lost volumes for `replacement` and `abandon`, which
  /// read them once, and whether the other shard has an impaired or lost volume for the steps that decide on it:
  /// `seen` is the control plane's state and `others` the count the step is passed. A flip starts only for the
  /// volume the shard's current receipt records as created, which either reconciler reads.
  action begin(p: int, op: str, shard: int): bool = {
    val lost = if (op == "replacement" or op == "abandon")
      st.vols.keys().filter(v => st.vols.get(v).shard == shard and st.vols.get(v).health == LOST)
      else Set()
    val pc = if (op == "replacement" or op == "flip") "shard" else if (op == "abandon") "observe" else "receipt"
    val r = st.rcpts.get(shard)
    val seen = if (op == "release" or op == "flip" or othersOf(st, shard) == 0) 0 else 1
    val started = {...IDLE, op: op, shard: shard, pc: pc, lost: lost, others: seen, seen: seen,
      vol: if (op == "flip" and r.phase == "created") r.vol else 0}
    all {PROCS.contains(p), OPS.contains(op), SHARDS.contains(shard), count, st.procs.get(p).op == "idle",
      (p == OPERATOR) == (op == "release"), op == "flip" implies started.vol != 0,
      st' = {...st, procs: st.procs.set(p, started), ev: event("begin", p, started, "", st, st, false)}
    }
  }
  /// The process's next store request reaches the store and its reply returns.
  action request(p: int): bool = {
    val proc = st.procs.get(p)
    val write = writes(proc)
    val ok = write and lands(st, proc)
    val stored = if (ok) committed(st, proc) else st
    val after = if (not(write)) reads(st, proc) else if (ok) acked(proc) else refused(proc)
    all {PROCS.contains(p), count, proc.op != "idle", proc.pc != "call",
      st' = {...stored, procs: st.procs.set(p, after.p),
        ev: event(if (write) "write" else "read", p, proc, if (ok and after.res == "") "ok" else after.res, st, stored,
          ok and RWRITES.contains(proc.pc))}
    }
  }
  /// The process's next write commits when its condition holds and its reply is lost; the step ends unknown.
  action unknown(p: int): bool = {
    val proc = st.procs.get(p)
    val ok = lands(st, proc)
    val stored = if (ok) committed(st, proc) else st
    all {PROCS.contains(p), count, proc.op != "idle", writes(proc),
      st' = {...stored, procs: st.procs.set(p, IDLE),
        ev: event("unknown", p, proc, "unknown", st, stored, ok and RWRITES.contains(proc.pc))}
    }
  }
  /// The process crashes: its step ends before its pending request, and a write it had not sent never reaches the
  /// store.
  action crash(p: int): bool = {
    val proc = st.procs.get(p)
    all {PROCS.contains(p), count, proc.op != "idle",
      st' = {...st, procs: st.procs.set(p, IDLE), ev: event("crash", p, proc, "crash", st, st, false)}
    }
  }
  /// The process calls the provider under its receipt's token. A token the provider has seen returns its kept
  /// outcome; a new one makes a volume (`make`), refuses for good (`fail`) or never arrives (`drop`). The reply
  /// returns when `reply` holds and is lost otherwise.
  action call(p: int, result: str, reply: bool): bool = {
    val proc = st.procs.get(p)
    val t = token(proc.shard, proc.rc.attempt)
    val known = st.prov.keys().contains(t)
    val out = if (known) st.prov.get(t)
      else if (result == "make") {kind: "volume", vol: st.next}
      else if (result == "fail") {kind: "failed", vol: 0}
      else {kind: "none", vol: 0}
    val makes = not(known) and result == "make"
    val after = if (not(reply)) IDLE
      else if (out.kind == "volume") {...proc, pc: "provision", vol: out.vol}
      else {...proc, pc: "raise"}
    val stored = {...st,
      prov: if (known or result == "drop") st.prov else st.prov.put(t, out),
      vols: if (makes) st.vols.put(st.next, {shard: proc.shard, health: AVAILABLE}) else st.vols,
      vrecs: if (makes) st.vrecs.put(st.next, {state: ABSENT, ver: 0}) else st.vrecs,
      next: if (makes) st.next + 1 else st.next,
      made: if (makes) st.made.union(Set({shard: proc.shard, attempt: proc.rc.attempt, vol: st.next})) else st.made,
      calls: st.calls.union(Set({shard: proc.shard, attempt: proc.rc.attempt, phase: proc.rc.phase,
        readHeld: proc.rc.held, seen: proc.seen, released: proc.rc.released}))
    }
    all {PROCS.contains(p), RESULTS.contains(result), count, proc.op != "idle", proc.pc == "call",
      known implies result == "make",
      out.kind == "none" implies not(reply),
      st' = {...stored, procs: st.procs.set(p, after),
        ev: {...event("call", p, proc, if (not(reply)) "unknown" else out.kind, st, stored, false), kept: known}}
    }
  }
  /// The control plane reports volume `v` lost; a lost volume stays lost.
  action lose(v: int): bool = all {st.vols.keys().contains(v), count, st.vols.get(v).health != LOST,
    st' = {...st, vols: st.vols.set(v, {...st.vols.get(v), health: LOST}), ev: envEvent("lose", v)}
  }
  action impair(v: int): bool = all {st.vols.keys().contains(v), count, st.vols.get(v).health == AVAILABLE,
    st' = {...st, vols: st.vols.set(v, {...st.vols.get(v), health: IMPAIRED}), ev: envEvent("impair", v)}
  }
  action recover(v: int): bool = all {st.vols.keys().contains(v), count, st.vols.get(v).health == IMPAIRED,
    st' = {...st, vols: st.vols.set(v, {...st.vols.get(v), health: AVAILABLE}), ev: envEvent("recover", v)}
  }
  /// Host `h` is lost; its volume's health is unchanged.
  action hostLoss(h: int): bool = all {HOSTS.contains(h), count, not(st.hostLost.contains(h)),
    st' = {...st, hostLost: st.hostLost.union(Set(h)), ev: envEvent("hostLoss", h)}
  }

  pure def terminal(s: State, shard: int, attempt: int): bool = {
    val t = token(shard, attempt)
    s.prov.keys().contains(t) and (s.prov.get(t).kind == "failed"
      or (s.prov.get(t).kind == "volume" and s.vrecs.get(s.prov.get(t).vol).state == RETIRED))
  }
  /// The last action, which the event statements and the witnesses read.
  val ev = st.ev
  /// A shard has a receipt only when the control plane reported its first active volume lost: the replacement
  /// step's decision reads volume loss alone.
  val receiptNeedsLoss = SHARDS.forall(s => st.rcpts.get(s).exists implies st.vols.get(s).health == LOST)
  /// A provider call names only such a shard: the create step's receipt read refuses an absent receipt.
  val callNeedsLoss = SHARDS.forall(s => st.calls.exists(c => c.shard == s) implies st.vols.get(s).health == LOST)
  /// A generation changes only for such a shard: a flip starts only for a volume a receipt records.
  val flipNeedsLoss = SHARDS.forall(s => st.shards.get(s).g > 1 implies st.vols.get(s).health == LOST)
  /// No receipt, provider call or generation change for a shard whose first active volume the control plane never
  /// reported lost: a host loss alone creates nothing.
  val HostLossCreatesNothing = receiptNeedsLoss and callNeedsLoss and flipNeedsLoss
  /// The last action is a replacement or create step's read of an existing unheld, unreleased receipt in a step that
  /// started beside an impaired or lost volume of the other shard: a read after which a latch is due.
  val latchDue = {
    val r = st.rcpts.get(ev.shard)
    ev.act == "read" and ev.pc == "receipt" and Set("replacement", "create").contains(ev.op)
      and ev.seen > 0 and r.exists and not(r.held) and not(r.released)
  }
  /// A receipt write that opens an attempt in a step that started beside an impaired or lost volume of the other
  /// shard holds it unless the operator released the replacement.
  val opensHeld = ev.opens and ev.seen > 0 and not(ev.after.released) implies ev.after.held
  /// A step whose receipt read shows a latch due goes on to write it.
  val latchFollows = latchDue implies Set("latch", "hold").contains(st.procs.get(ev.proc).pc)
  /// A committed latch leaves the receipt held at the same attempt, phase and volume.
  val latchKeeps = ev.rw and Set("latch", "hold").contains(ev.pc)
    implies ev.after.held and flagsOnly(ev.before, ev.after)
  /// No provider call comes from a step that started beside an impaired or lost volume of the other shard, unless
  /// the receipt the step carries is released.
  val callNeedsIsolation = st.calls.forall(c => c.seen == 0 or c.released)
  /// A write holds a receipt only in a step that started beside an impaired or lost volume of the other shard: a
  /// loss observed alone is never held.
  val holdNeedsImpairment = ev.rw and not(ev.before.held) and ev.after.held implies ev.seen > 0
  /// A loss beside an impaired or lost volume of the other shard holds the replacement, and only such a loss does.
  val CorrelatedHold = opensHeld and latchFollows and latchKeeps and callNeedsIsolation and holdNeedsImpairment
  /// Every provider call follows a receipt read that showed no hold.
  val HeldReadCreatesNothing = st.calls.forall(c => not(c.readHeld))
  /// Only the operator's write clears a hold, and it marks the receipt released at the same attempt, phase and
  /// volume.
  val clearIsRelease = ev.rw and ev.before.held and not(ev.after.held)
    implies ev.proc == OPERATOR and ev.after.released and flagsOnly(ev.before, ev.after)
  /// A write first marks a receipt released only when it is the operator's and clears a hold.
  val markIsRelease = ev.rw and not(ev.before.released) and ev.after.released
    implies ev.proc == OPERATOR and ev.before.held and not(ev.after.held)
  val OnlyOperatorReleases = clearIsRelease and markIsRelease
  /// A released receipt is unheld.
  val releasedUnheld = SHARDS.forall(s => st.rcpts.get(s).released implies not(st.rcpts.get(s).held))
  /// A write over a released receipt leaves it released.
  val releaseStays = ev.rw and ev.before.released implies ev.after.released
  val ReleaseIsFinal = releasedUnheld and releaseStays
  /// The receipt a provider call's step carries, from its acknowledged issue write or its read of an issued
  /// receipt, shows the attempt issued.
  val callCarriesIssued = st.calls.forall(c => c.phase == "issued")
  /// Every provider call under a token follows the committed `issued` write of its attempt.
  val callFollowsIssue = st.calls.forall(c => st.issued.contains(token(c.shard, c.attempt)))
  val CreateAfterIssue = callCarriesIssued and callFollowsIssue
  /// One token makes at most one volume.
  val OneVolumePerToken = st.made.forall(m => st.made.forall(n =>
    (m.shard == n.shard and m.attempt == n.attempt) implies m.vol == n.vol))
  /// A receipt's attempt moves past an earlier one only when the provider kept a refusal for that attempt's token or
  /// the volume it made is retired.
  val advanceIsTerminal = SHARDS.forall(s =>
    1.to(st.rcpts.get(s).attempt - 1).forall(a => terminal(st, s, a)))
  /// Only a volume the control plane reported lost is retired.
  val retiredIsLost =
    st.vrecs.keys().forall(v => st.vrecs.get(v).state == RETIRED implies st.vols.get(v).health == LOST)
  val AttemptAdvancesOnlyOnTerminal = advanceIsTerminal and retiredIsLost
  /// A volume a token made is recorded before the receipt moves past that token's attempt.
  val madeIsRecorded =
    st.made.forall(m => st.rcpts.get(m.shard).attempt == m.attempt or st.recorded.contains(m))
  /// A created receipt records a volume its attempt's token made.
  val createdIsMade = SHARDS.forall(s => st.rcpts.get(s).phase == "created"
    implies st.made.contains({shard: s, attempt: st.rcpts.get(s).attempt, vol: st.rcpts.get(s).vol}))
  /// A created receipt records a volume whose volume record exists: the create step writes that record first.
  val recordedHasRecord = SHARDS.forall(s => st.rcpts.get(s).phase == "created"
    implies st.vrecs.keys().contains(st.rcpts.get(s).vol) and st.vrecs.get(st.rcpts.get(s).vol).state != ABSENT)
  val EveryVolumeRecorded = madeIsRecorded and createdIsMade and recordedHasRecord
  /// Every spare write of a volume follows a receipt read that showed no hold of that volume.
  val spareReadUnheld = st.spares.forall(f => f.read and not(f.readHeld))
  /// Every flip of a volume follows a receipt read, after its fence, that showed no hold of that volume.
  val flipReadUnheld = st.flips.forall(f => f.read and not(f.readHeld))
  /// No activated replacement is retired.
  val activeNotRetired =
    SHARDS.forall(s => st.shards.get(s).g > 1 implies st.vrecs.get(st.shards.get(s).active).state != RETIRED)
  /// Every committed flip replaced a shard record of the first generation, so a shard flips at most once: one flip
  /// activates one replacement.
  val activatesOnce = st.flips.forall(f => f.g == 1)
  val ActivatesOnlyUnheld = spareReadUnheld and flipReadUnheld and activeNotRetired and activatesOnce
  val safety = HostLossCreatesNothing and CorrelatedHold and HeldReadCreatesNothing and OnlyOperatorReleases
    and ReleaseIsFinal and CreateAfterIssue and OneVolumePerToken and AttemptAdvancesOnlyOnTerminal
    and EveryVolumeRecorded and ActivatesOnlyUnheld

  /// A replacement step retains the active volume of a shard whose host is lost.
  val witnessHostLossRetains = ev.op == "replacement" and ev.res == "retain" and st.hostLost.contains(ev.shard)
  /// A replacement step retains an impaired active volume.
  val witnessImpairedRetains = ev.op == "replacement" and ev.res == "retain"
    and st.vols.get(ev.shard).health == IMPAIRED
  val witnessIsolatedStart = ev.rw and ev.pc == "start" and not(ev.after.held)
  val witnessCorrelatedStart = ev.rw and ev.pc == "start" and ev.after.held
  val witnessLatchDue = latchDue
  val witnessReplacementLatch = ev.rw and ev.pc == "latch"
  val witnessCreateLatch = ev.rw and ev.pc == "hold"
  val witnessHeldRefused = ev.op == "create" and ev.act == "read" and ev.res == "held"
  /// A create step refuses a held receipt after the other shard's volumes recovered.
  val witnessHoldOutlivesRecovery = witnessHeldRefused and ev.seen == 0
  val witnessRelease = ev.rw and ev.pc == "release"
  /// A provider call after the release, by a create step that started while the other shard's volume was impaired or
  /// lost.
  val witnessCreateAfterRelease = ev.act == "call" and ev.seen > 0
  /// A step opens the next attempt unheld over a released receipt, beside an impaired or lost volume of the other
  /// shard.
  val witnessOpensOverReleased = ev.opens and ev.before.released and ev.seen > 0
  /// A provider call by a step whose issued read predates the hold the receipt now carries.
  val witnessCallOverLatchedHold = ev.act == "call" and st.rcpts.get(ev.shard).held
  val witnessIssued = ev.rw and ev.pc == "issue"
  val witnessMade = ev.act == "call" and ev.res == "volume" and not(ev.kept)
  val witnessProviderFailed = ev.act == "call" and ev.res == "failed" and not(ev.kept)
  /// The provider made a volume for a new token and the reply was lost.
  val witnessMadeUnknown = ev.act == "call" and ev.res == "unknown" and not(ev.kept)
    and st.made.exists(m => m.shard == ev.shard and m.attempt == ev.attempt)
  /// A repeat of a token returns the volume the token made.
  val witnessKeptVolume = ev.act == "call" and ev.kept and ev.res == "volume"
  val witnessKeptFailed = ev.act == "call" and ev.kept and ev.res == "failed"
  /// A call under the token of an attempt the receipt has moved past, a token that made a volume.
  val witnessStaleToken = ev.act == "call" and ev.attempt < st.rcpts.get(ev.shard).attempt
    and st.made.exists(m => m.shard == ev.shard and m.attempt == ev.attempt)
  val witnessRecorded = ev.rw and ev.pc == "record"
  /// A create step's write of its volume fails its condition, as after a hold latched over its issued read.
  val witnessRecordRefused = ev.act == "write" and ev.pc == "record" and ev.res == "condition"
  val witnessFailedRaise = ev.rw and ev.op == "create" and ev.pc == "raise"
  /// A reconciler crashes at its provider call, after the issue write of its attempt committed.
  val witnessCrash = ev.act == "crash" and ev.pc == "call"
  val witnessUnknownWrite = ev.act == "unknown" and ev.rw
  val witnessRetired = ev.act == "write" and ev.pc == "retire" and ev.res == "ok"
  val witnessAbandoned = ev.rw and ev.op == "abandon"
  /// An abandon step opens the next attempt held beside an impaired or lost volume of the other shard.
  val witnessAbandonOpensHeld = ev.rw and ev.op == "abandon" and ev.opens and ev.after.held
  /// The next attempt's token makes a volume after the first attempt's volume was recorded.
  val witnessNextTokenMakes = witnessMade and ev.attempt == 2
    and st.recorded.exists(m => m.shard == ev.shard and m.attempt == 1)
  /// An abandon step finds the next attempt an earlier abandon step opened.
  val witnessAbandonReplayed = ev.op == "abandon" and ev.res == "replayed"
  /// An abandon step refuses a hold latched over the volume it observed.
  val witnessAbandonHeld = ev.op == "abandon" and ev.res == "held"
  /// A create step's volume record create is refused and its read finds the record provisioned.
  val witnessProvisionFound = ev.pc == "provRead" and st.procs.get(ev.proc).pc == "record"
  val witnessSpareNamed = ev.act == "write" and ev.pc == "spare" and ev.res == "ok"
  /// A create step's volume record create is refused and its read finds the record retired.
  val witnessProvisionRetired = ev.pc == "provRead" and st.procs.get(ev.proc).pc == "reread"
    and st.vrecs.get(st.procs.get(ev.proc).vol).state == RETIRED
  /// A flip step finds its volume already named the spare and goes on to the flip with no spare write.
  val witnessFlipOverNamedSpare = ev.op == "flip" and ev.pc == "volume" and st.procs.get(ev.proc).pc == "reread"
  val witnessFlipped = ev.op == "flip" and ev.pc == "flip" and ev.res == "flip"
  /// A flip write fails its condition after the other reconciler's flip committed.
  val witnessFlipRefused = ev.op == "flip" and ev.pc == "flip" and ev.res == "condition"
    and st.shards.get(ev.shard).g > 1
  /// A retirement write fails its condition while a volume record the flip's fence raised stays provisioned.
  val witnessFenceRefusesRetire = ev.pc == "retire" and ev.res == "condition"
    and st.vrecs.keys().exists(v => st.vrecs.get(v).state == PROVISIONED and st.vrecs.get(v).ver > 1)
  val witnessFlipRefusesHeld = ev.op == "flip" and ev.res == "held"
  /// An abandon step refuses a lost volume the flip activated.
  val witnessAbandonNamedActive = ev.op == "abandon" and ev.res == "named" and st.shards.get(ev.shard).g > 1
  /// An abandon step refuses a lost volume a flip named spare before the flip commits.
  val witnessAbandonNamedSpare = ev.op == "abandon" and ev.res == "named" and st.shards.get(ev.shard).g == 1
    and st.shards.get(ev.shard).spare != 0
  /// A release finds no receipt.
  val witnessReleaseAbsent = ev.op == "release" and ev.res == "absent" and not(st.rcpts.get(ev.shard).exists)
  /// A release finds an existing receipt unheld and writes nothing.
  val witnessReleaseUnheld = ev.op == "release" and ev.res == "unheld" and st.rcpts.get(ev.shard).exists
    and not(st.rcpts.get(ev.shard).held)
  val witnessBothHeld = SHARDS.forall(s => st.rcpts.get(s).held)

  action starts = {
    nondet p = PROCS.oneOf()
    nondet op = OPS.oneOf()
    nondet shard = SHARDS.oneOf()
    begin(p, op, shard)
  }
  action requests = {
    nondet p = PROCS.oneOf()
    any {request(p), unknown(p), crash(p)}
  }
  action calls = {
    nondet p = PROCS.oneOf()
    nondet result = RESULTS.oneOf()
    nondet reply = Set(true, false).oneOf()
    call(p, result, reply)
  }
  action health = {
    nondet v = st.vols.keys().oneOf()
    any {lose(v), impair(v), recover(v)}
  }
  action hosts = {
    nondet h = HOSTS.oneOf()
    hostLoss(h)
  }
  action step = any {starts, requests, calls, health, hosts}
}
