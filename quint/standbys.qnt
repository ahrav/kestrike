/// The reconciler's standby census and the standby's attach and enrollment over a zone's shards:
/// `Reconciler::reserve`, `release`, `designate` and `record_standby` of `failover/reconcile.rs` with the admission
/// rule of `Population::admit` and `Census::released` in `failover/standbys.rs`, and the standby host's
/// `enroll_standby`, one store request per step, on two reconciler processes that share the census and the shard and
/// volume records. A census, shard or volume write commits only at the version its operation read; its reply may be
/// lost with or without its commit, and one write may be held and delivered later. Hosts are lost, a reconciler learns a loss or suspects a live host,
/// the control plane answers a recorded attach, an actor outside the census takes a host's attachment slot, and each
/// shard record moves by the owner's bump, a takeover, a planned transfer, a flip and a fresh acquisition.
module standbys {
  const BOUND: int
  const SHARDS: Set[int]
  const HOSTS: Set[int]
  const CAP: int
  /// The initial owner and standby of each shard (0 for none), the hosts whose completed attach of its volume has an
  /// enrolled pair, and the hosts lost at the start.
  const OWNER: int -> int
  const STANDBY: int -> int
  const PAIRED: int -> Set[int]
  const LOST: Set[int]
  /// A host's attachment limit, the attachments each host holds outside the modeled volumes, and the host role limit
  /// `host_roles_max` on the shards a host owns plus the census entries that name it on a shard it does not own; a
  /// takeover turns the new owner's entry for that shard into its owner role.
  const ATTACH: int
  const USED: int -> int
  const ROLES: int
  /// The environment's further host losses, false suspicions, attachments taken outside the census, and the largest
  /// generation.
  const LOSSES: int
  const SUSPECTS: int
  const OCCUPY: int
  const GMAX: int
  pure val RECS = Set(0, 1)
  /// The zones a census can belong to; every shard is in zone 1.
  pure val ZONES = Set(1, 2)
  pure val ZONE = 1
  pure val OPS = Set("reserve", "release", "designate", "record", "enroll")
  pure val FAULTS = Set("commit", "lost", "hold")
  /// The largest attempt counter and the most live attaches a volume record holds, `MAX_ATTACHED`.
  pure val EMAX = 3
  pure val VOLMAX = 3
  /// A census slot: whether the census lists it, the `(g, owner, E)` it was reserved at and the host it names.
  type Entry = {on: bool, g: int, owner: int, e: int, host: int}
  /// A zone's census record: its version, 0 while it is absent, and the slot of each shard.
  type Census = {ver: int, slots: int -> Entry}
  /// A shard record: its tenure `(g, owner, E)`, the standby it names (0 for none) and its version.
  type Record = {g: int, owner: int, e: int, standby: int, ver: int}
  /// The record of a shard's active volume: the hosts with a live attach, the hosts with an enrolled pair, and its
  /// version.
  type Volume = {live: Set[int], enrolled: Set[int], ver: int}
  /// A reconciler process: its operation, shard and host, its next request, what its reads returned (the census
  /// version, the shard's entry, the number of listed shards and, for a reservation, the other shards whose entries in
  /// that census name the host; the shard record; the volume version and, for an attach record or an enrollment, the
  /// generation of the volume it read, whether the volume record shows the judged host live and enrolled, and whether
  /// it admits a new attach), the entry its census write puts and the grounds its
  /// reads gave for the host whose entry that write replaces or drops (`why`), its last result, and the slot it holds:
  /// the entry a reservation returned and that entry's shard (0 for none). The judged host is the operation's host,
  /// the entry's host for `release`, and the slot's host for `designate`.
  type Proc = {op: str, s: int, h: int, pc: int, cver: int, had: Entry, count: int, named: Set[int], rec: Record,
    vver: int, vgen: int, live: bool, enrolled: bool, open: bool, put: Entry, why: str, res: str, slot: Entry, ss: int}
  /// A write in flight: the record it names and its zone, the version it conditions on, the census entry it puts
  /// (off for a release), the host (`host`) of the entry a census write's census read returned or the host a
  /// designation, an attach record or an enrollment names, and in `why` a census write's grounds for that host or,
  /// for a designation, `live` when its volume read showed the host's attach live with its pair enrolled.
  type Write = {on: bool, key: str, op: str, z: int, s: int, expect: int, entry: Entry, host: int, why: str}
  /// The key a designation of `host` is judged by: shard `s` and the shard record's `(g, owner, E)` at the
  /// designation.
  type Named = {s: int, g: int, owner: int, e: int, host: int}
  type Event = {act: str, key: str, proc: int, op: str, s: int, h: int, res: str, note: str}
  /// The store records (`census`, `shards`, `volumes`) and the write in flight (`held`); the environment's lost
  /// hosts, each reconciler's loss evidence, the false suspicions made (`suspicions`, by reconciler and host), the
  /// attaches the control plane completed (`attached`) and refused for good (`failed`), and the attachments taken
  /// outside the census; and history the
  /// properties read: each shard's tenure high-water `hw` and `regressed` for `EntryTargetAdvances`, `unevidenced`
  /// for `SlotMovesOnlyOnEvidence`, the hosts each shard's slot moved away from (`displaced`), the designations they
  /// may no longer commit (`barred`) and `overturned` for `NewerDesignationStands`, the slots ever listed
  /// (`reserved`) and the attaches ever recorded (`recorded`) for `AttachFollowsReservation`, and `orphan` for a
  /// witness. The attach ends, the reconcilers' processes and the last event are variables of their own.
  type State = {
    census: int -> Census, shards: int -> Record, volumes: int -> Volume, held: Write,
    gone: Set[int], seen: int -> Set[int], suspicions: Set[(int, int)], attached: Set[(int, int)],
    failed: Set[(int, int)],
    outside: int -> int, occupied: int,
    hw: int -> int, regressed: bool, unevidenced: bool, displaced: int -> Set[int], barred: Set[Named],
    overturned: bool, reserved: Set[(int, int)], recorded: Set[(int, int)], orphan: {s: int, r: int}
  }
  /// The attach ends, a variable of its own beside `st`: the end a reconciler decided and has not written (`ending`:
  /// shard, host, the volume version and the standby its reads saw), the attaches that ended (`ended`, by shard and
  /// host), the named standbys whose attach ended in a race with their designation (`raced`, by shard and host, for
  /// `DesignatedIsEnrolled`, until an enrollment of that host, a designation of another host or a flip), the ends that
  /// landed on the shard's owner (`endedOwners`, for `OwnerHoldsItsAttach`), and for witnesses the shards on which a
  /// reservation or an attach record refused because the volume record admitted no new attach (`closed`), the closed
  /// shards an end then reopened (`reopenable`), and whether a release dropped the entry of a host whose attach ended
  /// (`releasedEnded`).
  type Ends = {
    ending: Set[(int, int, int, int)], ended: Set[(int, int)], raced: Set[(int, int)], endedOwners: Set[(int, int)],
    closed: Set[int], reopenable: Set[int], releasedEnded: bool
  }
  var st: State
  var en: Ends
  var procs: int -> Proc
  var ev: Event
  var turn: int
  pure val OFF: Entry = {on: false, g: 0, owner: 0, e: 0, host: 0}
  pure val NOREC: Record = {g: 0, owner: 0, e: 0, standby: 0, ver: 0}
  pure val IDLE: Proc = {op: "idle", s: 0, h: 0, pc: 0, cver: 0, had: OFF, count: 0, named: Set(), rec: NOREC,
    vver: 0, vgen: 0, live: false, enrolled: false, open: false, put: OFF, why: "", res: "", slot: OFF, ss: 0}
  pure val NOWRITE: Write = {on: false, key: "", op: "", z: 0, s: 0, expect: 0, entry: OFF, host: 0, why: ""}
  /// The store requests of each operation in production order: `reserve` reads the census, the shard record and the
  /// active volume's record before its census write; `release` reads the census, the shard record and the volume
  /// record before its census write; `designate` reads the volume record, the shard record and the census before its
  /// shard write; and `record` and `enroll` read the volume record and the shard record, write the volume record and
  /// read the shard record again.
  pure def order(op: str): List[str] =
    if (op == "reserve") ["census", "shard", "volume", "write"]
    else if (op == "release") ["census", "shard", "volume", "write"]
    else if (op == "designate") ["volume", "shard", "census", "write"]
    else if (op == "record" or op == "enroll") ["volume", "shard", "write", "shard"]
    else []
  pure def keyOf(p: Proc): str = if (p.pc < order(p.op).length()) order(p.op)[p.pc] else ""
  /// Whether an attach record of host `h` on shard `shard` is outstanding: a reconciler records it, at whatever
  /// tenure its slot names, or that record's write is held.
  pure def outstandingRecord(s: State, ps: int -> Proc, shard: int, h: int): bool =
    RECS.exists(x => ps.get(x).op == "record" and ps.get(x).s == shard and ps.get(x).h == h)
    or (s.held.on and s.held.op == "record" and s.held.s == shard and s.held.host == h)
  /// Whether a release has decided to drop entry `x` of shard `shard` and that census write is unsent, matched by
  /// the entry its census read returned, or held, matched by shard and the entry's host at any tenure.
  pure def dropping(s: State, ps: int -> Proc, shard: int, x: Entry): bool =
    RECS.exists(y => ps.get(y).op == "release" and ps.get(y).s == shard and keyOf(ps.get(y)) == "write"
      and ps.get(y).had == x) or (s.held.on and s.held.op == "release" and s.held.s == shard and s.held.host == x.host)
  pure def ended(p: Proc, res: str): Proc = {...p, op: "idle", res: res}
  /// The state after a process step whose result is `Closed`, a reservation or an attach record that found the volume
  /// record admitting no new attach, records the shard.
  pure def refusedClosed(e: Ends, p: Proc): Ends =
    if (p.res == "closed" or p.res == "attachClosed") {...e, closed: e.closed.union(Set(p.s))} else e
  /// The process as the state keeps it: an idle process keeps only the slot it holds.
  pure def settled(p: Proc): Proc = if (p.op == "idle") {...IDLE, slot: p.slot, ss: p.ss} else p
  /// The zone each reconciler maps a shard to, and the cap each reconciler applies.
  pure def zoneOf(r: int, s: int): int = ZONE
  pure def capOf(r: int): int = CAP
  pure def listed(c: Census): int = SHARDS.filter(s => c.slots.get(s).on).size()
  pure def sameTarget(r: Record, x: Entry): bool = r.g == x.g and r.owner == x.owner and r.e == x.e
  /// A tenure's place in the order of a shard's tenures: the generation, then the attempt counter.
  pure def rank(x: Entry): int = x.g * (EMAX + 1) + x.e
  /// Whether entry `x` takes the slot `old` lists from another host.
  pure def moves(old: Entry, x: Entry): bool = old.on and x.on and old.host != x.host
  /// The true losses reconciler `r` learned: its loss evidence less its false suspicions.
  pure def learned(s: State, r: int): Set[int] = s.seen.get(r).filter(h => not(s.suspicions.contains((r, h))))
  /// A reconciler's grounds for taking shard `shard`'s slot from host `x`: `owner` when its shard read names `x`
  /// owner, `loss` when it learned `x` lost, `failed` when `x`'s attach of the shard's volume failed for good,
  /// `suspicion` when its false suspicion names `x`, and none (`""`) otherwise.
  pure def grounds(s: State, r: int, shard: int, owner: int, x: int): str =
    if (x == owner) "owner" else if (learned(s, r).contains(x)) "loss"
    else if (s.failed.contains((shard, x))) "failed" else if (s.seen.get(r).contains(x)) "suspicion" else ""
  /// The reconciler's evidence that a host can no longer serve as the shard's standby: a host it holds lost, and a
  /// host whose attach of the shard's volume failed for good.
  pure def lostTo(s: State, r: int, shard: int): Set[int] =
    s.seen.get(r).union(HOSTS.filter(h => s.failed.contains((shard, h))))
  /// Whether host `h`'s report lists shard `x` in the standby role: the volume record of `x`'s active volume enrolls
  /// the host's pair and the shard record names another owner.
  pure def standbyRole(s: State, h: int, x: int): bool =
    s.volumes.get(x).enrolled.contains(h) and s.shards.get(x).owner != h
  /// The shards whose active volume host `h` has attached.
  pure def attachments(s: State, h: int): int = SHARDS.filter(x => s.attached.contains((x, h))).size()
  /// The attachments host `h` holds: its completed attaches and its attachments outside the modeled volumes.
  pure def used(s: State, h: int): int = s.outside.get(h) + attachments(s, h)
  /// The attachments host `h`'s report shows used; a reservation reads a current report.
  pure def reported(s: State, h: int): int = used(s, h)
  /// The shards other than `shard` whose entries in census `c` name host `h`.
  pure def others(c: Census, h: int, shard: int): Set[int] = SHARDS.filter(x => {
    val e = c.slots.get(x)
    x != shard and e.on and e.host == h
  })
  /// The census entries of every zone that name host `h`, by zone and shard.
  pure def naming(s: State, h: int): Set[(int, int)] = tuples(ZONES, SHARDS).filter(((z, x)) => {
    val e = s.census.get(z).slots.get(x)
    e.on and e.host == h
  })
  /// The shards host `h` owns plus the census entries that name it on a shard it does not own.
  pure def roles(s: State, h: int): int = SHARDS.filter(x => s.shards.get(x).owner == h).size()
    + naming(s, h).filter(((z, x)) => s.shards.get(x).owner != h).size()
  /// The census entries that still owe host `h` an attach: entries naming it whose attach has not completed or
  /// failed.
  pure def owed(s: State, h: int): int =
    naming(s, h).filter(((z, x)) => not(s.attached.contains((x, h))) and not(s.failed.contains((x, h)))).size()
  /// `Population::admit` over the census, shard record and volume record the reservation read, the candidate's
  /// current report and the reconciler's loss evidence: `Ineligible`, a slot already listed for the host at the
  /// record's tenure, `Closed` and `Headroom` for a candidate with no live attach, `Taken` while the incumbent (the
  /// entry's host unless the record names it owner, or else the record's standby) is another host the evidence
  /// does not show lost, `Full` for a new slot in a census at the cap, or the census write. HEADROOM counts as pending
  /// the entries of the census the reservation read for other shards that name the host and whose shard the report
  /// does not list in the standby role; the model reads the gauge and the roles from one report at the decision, where
  /// the code's caller captures it before the call. A census write that moves the slot records its grounds for the
  /// host of the entry the census read; it commits only at the version it read, so that host is the one it replaces.
  pure def admit(s: State, r: int, p: Proc): Proc = {
    val lost = lostTo(s, r, p.s)
    val entry = {on: true, g: p.rec.g, owner: p.rec.owner, e: p.rec.e, host: p.h}
    val incumbent = if (p.had.on and p.had.host != p.rec.owner) p.had.host else p.rec.standby
    val pend = p.named.filter(x => not(standbyRole(s, p.h, x))).size()
    val room = reported(s, p.h) + pend < ATTACH
    if (p.rec.e == 0 or p.h == p.rec.owner) ended(p, "ineligible")
    else if (p.had == entry) {...ended(p, "listed"), slot: entry, ss: p.s}
    else if (not(p.live) and not(p.open)) ended(p, "closed")
    else if (not(p.live) and not(room)) ended(p, "headroom")
    else if (incumbent != 0 and incumbent != p.h and not(lost.contains(incumbent))) ended(p, "taken")
    else if (not(p.had.on) and p.count >= capOf(r)) ended(p, "full")
    else {...p, put: entry, why: if (moves(p.had, entry)) grounds(s, r, p.s, p.rec.owner, p.had.host) else ""}
  }
  /// `Census::released` over the census, shard record and volume record the release read: the entry stays while
  /// the record names a standby, holds the entry's tenure, or shows the entry's host, not the owner, live and not
  /// lost; otherwise the census write drops it, with its grounds for the entry's host: the owner, no live attach, or
  /// the loss evidence. The model adds the loop's stuck bound, which `Census::released` does not apply: an entry that
  /// would drop on any of those grounds stays while an attach record of its shard and host is outstanding
  /// (`recording`, `keptRecording`).
  pure def dropOrKeep(s: State, r: int, recording: bool, p: Proc): Proc = {
    val lost = lostTo(s, r, p.s)
    if (not(p.had.on)) ended(p, "unlisted")
    else if (p.rec.standby != 0) ended(p, "keptStandby")
    else if (sameTarget(p.rec, p.had)) ended(p, "keptCurrent")
    else if (p.had.host != p.rec.owner and p.live and not(lost.contains(p.had.host))) ended(p, "keptLive")
    else if (recording) ended(p, "keptRecording")
    else {...p, put: OFF,
      why: if (p.had.host != p.rec.owner and not(p.live)) "unattached" else grounds(s, r, p.s, p.rec.owner, p.had.host)}
  }
  /// The checks of `designate` after its last read: a record that already names the host returns as it is, and a
  /// host whose live attach the volume record enrolls no pair for refuses, which the code reports as `Conflict`.
  pure def designation(p: Proc): Proc =
    if (p.rec.standby == p.slot.host) ended(p, "asis")
    else if (not(p.enrolled)) ended(p, "unenrolled")
    else p
  /// STANDBY-TENURE over the shard record a standby step read: the generation of the volume the step read, so the
  /// record names that volume active, and another owner at `E > 0`.
  pure def tenured(p: Proc): bool = p.rec.g == p.vgen and p.rec.owner != p.h and p.rec.e > 0
  /// The checks of `record_standby` before its write: a shard record that fails STANDBY-TENURE and a volume record
  /// that admits no new attach refuse, both the code's `Conflict`. The attach record starts only for a host with no
  /// live attach, so the code's witness of an existing attach is outside the model.
  pure def recordChecks(p: Proc): Proc =
    if (not(tenured(p))) ended(p, "notServing")
    else if (not(p.open)) ended(p, "attachClosed")
    else p
  /// The checks of `enroll_standby` before its write: `Tenure`, then `Enrollment(Unattached)` for a host whose
  /// attach the volume record does not show live. An end that lands on the owner leaves such a host: the owner keeps
  /// its attachment, and a later takeover leaves it a host with a completed attach and no live attach. The
  /// enrollment starts only once the host's attach completed and while it has no pair, so the code's return of an
  /// enrolled pair is outside the model.
  pure def enrollChecks(p: Proc): Proc =
    if (not(tenured(p))) ended(p, "tenure")
    else if (not(p.live)) ended(p, "unattached")
    else p
  /// The shard read after an attach record's or an enrollment's write: STANDBY-TENURE refuses as before the write,
  /// and otherwise the operation returns.
  pure def confirmed(p: Proc): Proc =
    if (not(tenured(p))) ended(p, if (p.op == "record") "notServing" else "tenure")
    else ended(p, if (p.op == "record") "recorded" else "enrolled")
  /// The process after the read it has just made: `designate` refuses `Stale` at a shard record of another tenure
  /// than its slot's and `Conflict` at a census that lists another entry or none for the shard, `release` ends at an
  /// absent census, after its last read before its write each operation decides, and the shard read after an
  /// attach record's or an enrollment's write ends it.
  pure def checked(s: State, ps: int -> Proc, r: int, q: Proc, k: str): Proc =
    if (q.op == "designate" and k == "shard" and not(sameTarget(q.rec, q.slot))) ended(q, "stale")
    else if (q.op == "designate" and k == "census" and q.had != q.slot) ended(q, "conflict")
    else if (q.op == "release" and k == "census" and q.cver == 0) ended(q, "absent")
    else if (keyOf(q) == "") confirmed(q)
    else if (keyOf(q) != "write") q
    else if (q.op == "reserve") admit(s, r, q)
    else if (q.op == "release") dropOrKeep(s, r, outstandingRecord(s, ps, q.s, q.had.host), q)
    else if (q.op == "designate") designation(q)
    else if (q.op == "record") recordChecks(q)
    else enrollChecks(q)
  /// The process after its next read returns what the store holds.
  pure def readNext(s: State, ps: int -> Proc, r: int, p: Proc): Proc = {
    val k = keyOf(p)
    val vol = s.volumes.get(p.s)
    val judged = if (p.op == "release") p.had.host else if (p.op == "designate") p.slot.host else p.h
    val c = s.census.get(zoneOf(r, p.s))
    val q = if (k == "census") {...p, cver: c.ver, had: c.slots.get(p.s), count: listed(c),
        named: if (p.op == "reserve") others(c, p.h, p.s) else Set()}
      else if (k == "shard") {...p, rec: s.shards.get(p.s)}
      else {...p, vver: vol.ver, vgen: if (p.op == "record" or p.op == "enroll") s.shards.get(p.s).g else 0,
        live: vol.live.contains(judged), enrolled: vol.enrolled.contains(judged), open: vol.live.size() < VOLMAX}
    checked(s, ps, r, {...q, pc: q.pc + 1}, k)
  }
  /// The write the process issues at its next request, each at the version the operation read: the census write of
  /// `reserve` or `release`, where version 0 creates the absent census; the shard write of `designate`, which
  /// carries whether its volume read showed the host's attach live with its pair enrolled; and the volume write of
  /// `record` and `enroll`.
  pure def write(r: int, p: Proc): Write = {
    val w = {on: true, key: "census", op: p.op, z: zoneOf(r, p.s), s: p.s, expect: p.cver, entry: p.put,
      host: p.had.host, why: p.why}
    if (p.op == "designate") {...w, key: "shard", expect: p.rec.ver, host: p.slot.host,
      why: if (p.live and p.enrolled) "live" else ""}
    else if (p.op == "record" or p.op == "enroll") {...w, key: "volume", expect: p.vver, host: p.h, why: ""}
    else w
  }
  /// Whether a census write's grounds name the host of the entry `old` it replaces or drops.
  pure def credited(old: Entry, w: Write): bool = w.why != "" and w.host == old.host
  pure def lands(s: State, w: Write): bool =
    if (w.key == "census") s.census.get(w.z).ver == w.expect
    else if (w.key == "shard") s.shards.get(w.s).ver == w.expect
    else s.volumes.get(w.s).ver == w.expect
  /// The store after the write commits, with its history. A census write that takes the stored slot from another
  /// host, or drops a listed entry, records whether its writer had grounds for that host. A census write that places
  /// an entry raises the shard's tenure high-water, records a regression below it and records the slot as reserved;
  /// the hosts the slot moved away from, less the entry's host, stay displaced, and the entry's host is no longer
  /// barred. A designation of a barred host
  /// is overturned, and every designation bars the hosts its shard's slot moved away from at that tenure. An attach
  /// record adds the host's live attach and an enrollment its pair.
  pure def committed(s: State, w: Write): State =
    if (w.key == "census") {
      val c = s.census.get(w.z)
      val old = c.slots.get(w.s)
      val placed = w.entry.on
      val moved = moves(old, w.entry)
      val stored = {...s, census: s.census.set(w.z, {ver: c.ver + 1, slots: c.slots.set(w.s, w.entry)}),
        unevidenced: s.unevidenced or ((moved or (old.on and not(placed))) and not(credited(old, w)))}
      val away = if (moved) s.displaced.get(w.s).union(Set(old.host)) else s.displaced.get(w.s)
      if (not(placed)) stored
      else {...stored,
        hw: if (rank(w.entry) > s.hw.get(w.s)) s.hw.set(w.s, rank(w.entry)) else s.hw,
        regressed: s.regressed or rank(w.entry) < s.hw.get(w.s),
        displaced: s.displaced.set(w.s, away.exclude(Set(w.entry.host))),
        barred: s.barred.filter(b => b.s != w.s or b.host != w.entry.host),
        reserved: s.reserved.union(Set((w.s, w.entry.host)))}
    } else if (w.key == "shard") {
      val r = s.shards.get(w.s)
      val named = {s: w.s, g: r.g, owner: r.owner, e: r.e, host: w.host}
      {...s,
        shards: s.shards.set(w.s, {...r, standby: w.host, ver: r.ver + 1}),
        overturned: s.overturned or s.barred.contains(named),
        barred: s.barred.union(s.displaced.get(w.s).exclude(Set(w.host)).map(x => {...named, host: x}))}
    } else {
      val v = s.volumes.get(w.s)
      if (w.op == "record")
        {...s, volumes: s.volumes.set(w.s, {...v, live: v.live.union(Set(w.host)), ver: v.ver + 1}),
          recorded: s.recorded.union(Set((w.s, w.host)))}
      else {...s, volumes: s.volumes.set(w.s, {...v, enrolled: v.enrolled.union(Set(w.host)), ver: v.ver + 1})}
    }
  /// The attach ends after write `w` commits over state `s`: a release that drops the entry of a host whose attach
  /// ended, on the grounds that it shows no live attach, is recorded; a designation ends the race of the standby it
  /// replaces and is itself in a race with an end when its volume read showed the host's attach live and enrolled
  /// and the volume record no longer does, whichever process or held write carries it and whether or not a new
  /// attach of the host was recorded since; and an enrollment ends the race of its host.
  pure def endsAfter(s: State, e: Ends, w: Write): Ends = {
    val old = s.census.get(w.z).slots.get(w.s)
    if (w.key == "census") {...e, releasedEnded: e.releasedEnded or (old.on and not(w.entry.on)
      and w.why == "unattached" and e.ended.contains((w.s, old.host)))}
    else if (w.key == "shard") {
      val v = s.volumes.get(w.s)
      {...e, raced: e.raced.filter(a => a._1 != w.s).union(
        if (w.why == "live" and not(v.live.contains(w.host) and v.enrolled.contains(w.host))) Set((w.s, w.host))
        else Set())}
    }
    else if (w.op == "enroll") {...e, raced: e.raced.exclude(Set((w.s, w.host)))}
    else e
  }
  /// What a committed write did, for the witnesses; a slot move is named by its writer's grounds.
  pure def note(s: State, w: Write): str =
    if (w.key == "census") {
      val c = s.census.get(w.z)
      val old = c.slots.get(w.s)
      if (c.ver == 0) "created"
      else if (not(w.entry.on)) "dropped"
      else if (not(old.on)) "newEntry"
      else if (not(moves(old, w.entry))) "entry"
      else if (not(credited(old, w))) "movedUnevidenced"
      else if (w.why == "loss") "movedOnLoss"
      else if (w.why == "owner") "movedFromOwner"
      else if (w.why == "failed") "movedOnFailedAttach"
      else "movedOnSuspicion"
    }
    else if (w.key == "volume") w.op
    else if (s.shards.get(w.s).standby != 0) "replaced"
    else "named"
  /// The process after its acknowledged write: a reservation returns the slot it wrote, and an attach record and an
  /// enrollment go on to their last shard read.
  pure def acknowledged(p: Proc): Proc =
    if (p.op == "reserve") {...ended(p, "reserved"), slot: p.put, ss: p.s}
    else if (p.op == "release") ended(p, "released")
    else if (p.op == "designate") ended(p, "designated")
    else {...p, pc: p.pc + 1}
  pure def event(act: str, key: str, r: int, p: Proc, res: str, note: str): Event =
    {act: act, key: key, proc: r, op: p.op, s: p.s, h: p.h, res: res, note: note}
  pure def env(act: str, r: int, s: int, h: int): Event =
    {act: act, key: "", proc: r, op: "", s: s, h: h, res: "", note: ""}
  pure def first(s: int): Entry =
    if (STANDBY.get(s) == 0) OFF else {on: true, g: 1, owner: OWNER.get(s), e: 1, host: STANDBY.get(s)}
  /// Every shard starts at generation 1 and `E = 1` with its initial owner and standby, its volume record holding the
  /// paired hosts' live attaches and pairs, and zone 1's census listing each named standby's slot.
  action init = all {
    st' = {
      census: ZONES.mapBy(z => if (z == ZONE and SHARDS.exists(s => STANDBY.get(s) != 0))
        {ver: 1, slots: SHARDS.mapBy(s => first(s))} else {ver: 0, slots: SHARDS.mapBy(_ => OFF)}),
      shards: SHARDS.mapBy(s => {g: 1, owner: OWNER.get(s), e: 1, standby: STANDBY.get(s), ver: 1}),
      volumes: SHARDS.mapBy(s => {live: PAIRED.get(s), enrolled: PAIRED.get(s), ver: 1}),
      held: NOWRITE, gone: LOST, seen: RECS.mapBy(_ => Set()), suspicions: Set(),
      attached: SHARDS.map(s => PAIRED.get(s).map(h => (s, h))).flatten(),
      failed: Set(),
      outside: USED, occupied: 0,
      hw: SHARDS.mapBy(s => rank(first(s))), regressed: false, unevidenced: false,
      displaced: SHARDS.mapBy(_ => Set()), barred: Set(), overturned: false,
      reserved: SHARDS.filter(s => STANDBY.get(s) != 0).map(s => (s, STANDBY.get(s))), recorded: Set(),
      orphan: {s: 0, r: 0}},
    en' = {ending: Set(), ended: Set(), raced: Set(), endedOwners: Set(), closed: Set(), reopenable: Set(),
      releasedEnded: false},
    procs' = RECS.mapBy(_ => IDLE), ev' = env("init", 0, 0, 0), turn' = 0
  }
  action count = all {turn < BOUND, turn' = turn + 1}
  /// The host arguments an operation takes: a release takes no host, stores host 0 and is started with host 1 alone,
  /// so the scheduler starts one release per reconciler and shard.
  pure def hostArgs(op: str): Set[int] = if (op == "release") Set(1) else HOSTS
  /// A caller starts an operation on an idle reconciler and its first read reaches the store: a reservation of
  /// shard `s` for host `h` that the reconciler's evidence does not hold lost, a release of shard `s`, the designation
  /// of the slot the reconciler holds, the attach record of that slot for a host with no live attach while the census,
  /// read in this step, lists the slot and no release's decided drop of it is unsent or held, or host `h`'s enrollment
  /// on shard `s` once its attach completed and while it has no pair. The loop's candidate filter excludes a host that
  /// gains a role at the host role limit, with no request, over the census this step's read returns.
  action begin(r: int, op: str, s: int, h: int): bool = {
    val p = procs.get(r)
    val started = {...IDLE, op: op, s: s, h: if (op == "release") 0 else h,
      slot: if (op == "reserve") OFF else p.slot, ss: if (op == "reserve") 0 else p.ss}
    val e = st.census.get(zoneOf(r, s)).slots.get(s)
    val gains = st.shards.get(s).owner != h and not(e.on and e.host == h)
    val excluded = op == "reserve" and gains and roles(st, h) >= ROLES
    val after = if (excluded) ended(started, "excluded") else readNext(st, procs, r, started)
    all {count, OPS.contains(op), SHARDS.contains(s), hostArgs(op).contains(h), p.op == "idle",
      op == "reserve" implies not(lostTo(st, r, s).contains(h)),
      op == "designate" implies (p.ss == s and p.slot.host == h),
      op == "record" implies (p.ss == s and p.slot.host == h and e == p.slot),
      op == "record" implies not(dropping(st, procs, s, p.slot)),
      op == "record" implies not(st.volumes.get(s).live.contains(h)),
      op == "enroll" implies (st.attached.contains((s, h)) and not(st.volumes.get(s).enrolled.contains(h))),
      st' = st, en' = refusedClosed(en, after), procs' = procs.set(r, settled(after)),
      ev' = event(if (excluded) "plan" else "read", if (excluded) "" else keyOf(started), r, started, after.res, "")
    }
  }
  /// The reconciler's next request reaches the store and its reply returns.
  action request(r: int): bool = {
    val p = procs.get(r)
    val k = keyOf(p)
    val w = write(r, p)
    val ok = lands(st, w)
    val writes = k == "write"
    val commits = writes and ok
    val after = if (not(writes)) readNext(st, procs, r, p) else if (ok) acknowledged(p) else ended(p, "condition")
    all {count, p.op != "idle",
      st' = if (commits) committed(st, w) else st,
      en' = if (commits) endsAfter(st, en, w) else refusedClosed(en, after), procs' = procs.set(r, settled(after)),
      ev' = event(if (writes) "write" else "read", if (writes) w.key else k, r, p,
        after.res, if (commits) note(st, w) else "")
    }
  }
  /// The reconciler's next write gets no reply: it commits, is lost, or is held; the operation ends unknown.
  action unknown(r: int, fault: str): bool = {
    val p = procs.get(r)
    val w = write(r, p)
    val ok = fault == "commit" and lands(st, w)
    val stored = if (ok) committed(st, w) else if (fault == "hold") {...st, held: w} else st
    all {count, FAULTS.contains(fault), p.op != "idle", keyOf(p) == "write", fault == "hold" implies not(st.held.on),
      st' = stored, en' = if (ok) endsAfter(st, en, w) else en, procs' = procs.set(r, settled(ended(p, "unknown"))),
      ev' = event(fault, w.key, r, p, "unknown", if (ok) note(st, w) else "")
    }
  }
  /// The held write reaches the store.
  action deliver = {
    val ok = lands(st, st.held)
    all {count, st.held.on,
      st' = {...(if (ok) committed(st, st.held) else st), held: NOWRITE}, procs' = procs,
      en' = if (ok) endsAfter(st, en, st.held) else en,
      ev' = {...env("deliver", 0, st.held.s, st.held.host), key: st.held.key, res: if (ok) "committed" else "refused",
        note: if (ok) note(st, st.held) else ""}
    }
  }
  /// The reconciler stops and restarts with no process state; a write it left in flight stays in flight.
  action crash(r: int): bool = {
    val p = procs.get(r)
    all {count, p != IDLE,
      st' = {...st, orphan: if (p.ss != 0) {s: p.ss, r: r} else st.orphan}, procs' = procs.set(r, IDLE),
      en' = en, ev' = env("crash", r, p.ss, 0)
    }
  }
  action lose(h: int): bool = all {count, HOSTS.contains(h), not(st.gone.contains(h)),
    st.gone.size() < LOST.size() + LOSSES,
    st' = {...st, gone: st.gone.union(Set(h))}, procs' = procs, en' = en, ev' = env("lose", 0, 0, h)
  }
  /// A reconciler's evidence shows a lost host lost.
  action learn(r: int, h: int): bool = all {count, RECS.contains(r), st.gone.contains(h),
    not(st.seen.get(r).contains(h)),
    st' = {...st, seen: st.seen.set(r, st.seen.get(r).union(Set(h)))}, procs' = procs, en' = en, ev' = env("learn", r, 0, h)
  }
  /// A false suspicion: a reconciler's evidence shows a live host lost.
  action suspect(r: int, h: int): bool = all {count, RECS.contains(r), HOSTS.contains(h),
    st.suspicions.size() < SUSPECTS, not(st.gone.contains(h)),
    not(st.seen.get(r).contains(h)),
    st' = {...st, seen: st.seen.set(r, st.seen.get(r).union(Set(h))), suspicions: st.suspicions.union(Set((r, h)))},
    procs' = procs, en' = en, ev' = env("suspect", r, 0, h)
  }
  /// The control plane answers host `h`'s attach of shard `s`'s volume, which the volume record shows live: the
  /// attach completes, or fails for good and stays live in the record with no pair.
  action attachEnds(s: int, h: int, completes: bool): bool = all {count, SHARDS.contains(s), HOSTS.contains(h),
    st.volumes.get(s).live.contains(h), not(st.attached.contains((s, h))), not(st.failed.contains((s, h))),
    not(st.gone.contains(h)),
    st' = {...st, attached: if (completes) st.attached.union(Set((s, h))) else st.attached,
      failed: if (completes) st.failed else st.failed.union(Set((s, h)))},
    procs' = procs, en' = en, ev' = {...env("attachEnds", 0, s, h), res: if (completes) "attached" else "failed"}
  }
  /// The reconciler decides to end host `h`'s live attach of shard `s`'s volume: its shard read names the host
  /// neither owner nor standby at `E > 0`, and it keeps the volume record's version and the standby it read. The
  /// decision reads no census, as `Reconciler::end_attach` reads none, so a census entry may name the host. One end decision is open at a time; its write follows at a later
  /// step.
  action endRead(s: int, h: int): bool = {
    val r = st.shards.get(s)
    all {count, SHARDS.contains(s), HOSTS.contains(h), st.volumes.get(s).live.contains(h), r.owner != h,
      r.standby != h, r.e > 0, en.ending == Set(),
      st' = st, en' = {...en, ending: Set((s, h, st.volumes.get(s).ver, r.standby))}, procs' = procs,
      ev' = env("endRead", 0, s, h)
    }
  }
  /// The decided end's volume write, conditioned on the volume version its decision read, whatever the shard record
  /// and the census name by then. It refuses with no write when the volume record moved (`endRefused`), and the
  /// decision ends. Otherwise the volume record no longer shows the attach live or enrolled and its slot under
  /// `VOLMAX` is free; the host's attachment is released unless the shard record names the host owner, which keeps
  /// its attach and never detaches itself; an attach that failed for good stays failed for the shard. The end mark,
  /// the owner's pair drop, the detach and the gone mark are one step here; the tenure model's reclaim schedule
  /// checks their order. The end is in a race with a designation of the host when the shard record names the host
  /// standby though the decision read another standby; a designation that commits after the end is judged at its
  /// own write.
  action endWrite(s: int, h: int): bool = {
    val v = st.volumes.get(s)
    val d = en.ending.filter(x => x._1 == s and x._2 == h)
    val lands = d.exists(x => x._3 == v.ver)
    val owner = st.shards.get(s).owner == h
    val namedSince = st.shards.get(s).standby == h and d.exists(x => x._4 != h)
    all {count, d != Set(), v.live.contains(h),
      st' = if (not(lands)) st else {...st,
        volumes: st.volumes.set(s, {live: v.live.exclude(Set(h)), enrolled: v.enrolled.exclude(Set(h)),
        ver: v.ver + 1}), attached: if (owner) st.attached else st.attached.exclude(Set((s, h)))},
      en' = if (not(lands)) {...en, ending: Set()} else {...en,
        ended: en.ended.union(Set((s, h))), ending: Set(),
        endedOwners: if (owner) en.endedOwners.union(Set((s, h))) else en.endedOwners,
        raced: if (namedSince) en.raced.union(Set((s, h))) else en.raced,
        reopenable: if (en.closed.contains(s)) en.reopenable.union(Set(s)) else en.reopenable},
      procs' = procs, ev' = env(if (lands) "endWrite" else "endRefused", 0, s, h)
    }
  }
  /// An actor outside the census takes one of host `h`'s attachment slots while the host's attachments plus the
  /// entries that still owe it an attach stay under its limit. As an environment premise, no slot is taken while a
  /// reservation for `h` has decided and its census write is unsent or held.
  action occupy(h: int): bool = all {count, HOSTS.contains(h), st.occupied < OCCUPY, not(st.gone.contains(h)),
    used(st, h) + owed(st, h) < ATTACH,
    RECS.forall(r => not(procs.get(r).op == "reserve" and procs.get(r).h == h and keyOf(procs.get(r)) == "write")),
    not(st.held.on and st.held.key == "census" and st.held.entry.host == h),
    st' = {...st, outside: st.outside.set(h, st.outside.get(h) + 1), occupied: st.occupied + 1}, procs' = procs,
    en' = en, ev' = env("occupy", 0, 0, h)
  }
  /// The owner's attempt bump, which keeps the standby.
  action bump(s: int): bool = {
    val r = st.shards.get(s)
    all {count, SHARDS.contains(s), r.e >= 1, r.e < EMAX, not(st.gone.contains(r.owner)),
      st' = {...st, shards: st.shards.set(s, {...r, e: r.e + 1, ver: r.ver + 1})}, procs' = procs,
      en' = en, ev' = env("bump", 0, s, r.owner)
    }
  }
  /// The owner's fresh first acquisition after a flip.
  action fresh(s: int): bool = {
    val r = st.shards.get(s)
    all {count, SHARDS.contains(s), r.e == 0, not(st.gone.contains(r.owner)),
      st' = {...st, shards: st.shards.set(s, {...r, e: 1, ver: r.ver + 1})}, procs' = procs,
      en' = en, ev' = env("fresh", 0, s, r.owner)
    }
  }
  /// The named standby's takeover: it becomes the owner at the next attempt and the record names no standby. The
  /// step reads the standby's live, enrolled attach and writes the shard record at once, so no end lands between
  /// the two; the tenure model's reclaim schedule splits them (`missingOwnerPollWithdraws`).
  action takeover(s: int): bool = {
    val r = st.shards.get(s)
    val ready = st.volumes.get(s).live.contains(r.standby) and st.volumes.get(s).enrolled.contains(r.standby)
    all {count, SHARDS.contains(s), r.standby != 0, not(st.gone.contains(r.standby)), r.e < EMAX, ready,
      st' = {...st, shards: st.shards.set(s, {...r, owner: r.standby, e: r.e + 1, standby: 0, ver: r.ver + 1})},
      procs' = procs, en' = en, ev' = env("takeover", 0, s, r.standby)
    }
  }
  /// The outgoing owner's planned transfer: while the owner is live, the volume record shows the standby's live,
  /// enrolled attach and two attempts remain at or below `EMAX`, it names the record's standby owner at the next
  /// attempt and leaves no standby, and the reconcilers enroll a standby again. The transfer takes one of the two
  /// attempts and the new owner's own bump the other. The step reads the standby's attach and writes the shard
  /// record at once, so no end lands between the two. A writer that reads the volume record in one request and
  /// writes the shard record in another admits an end between them: that history is outside this model and
  /// `OwnerHoldsItsAttach`.
  action transfer(s: int): bool = {
    val r = st.shards.get(s)
    val targetReady = st.volumes.get(s).live.contains(r.standby) and st.volumes.get(s).enrolled.contains(r.standby)
    all {count, SHARDS.contains(s), r.standby != 0, not(st.gone.contains(r.owner)), r.e + 1 < EMAX, targetReady,
      st' = {...st, shards: st.shards.set(s, {...r, e: r.e + 1, owner: r.standby, standby: 0, ver: r.ver + 1})},
      procs' = procs, en' = en, ev' = env("transfer", 0, s, r.standby)
    }
  }
  /// The flip to the next generation on a new volume that host `h`, the spare's host, owns and alone attaches; the
  /// displaced volume's attaches and failures stay with it, and an end decided on it lands nowhere.
  action flip(s: int, h: int): bool = {
    val r = st.shards.get(s)
    all {count, SHARDS.contains(s), HOSTS.contains(h), r.g < GMAX, h != r.owner, not(st.gone.contains(h)),
      st' = {...st, shards: st.shards.set(s, {g: r.g + 1, owner: h, e: 0, standby: 0, ver: r.ver + 1}),
        volumes: st.volumes.set(s, {live: Set(h), enrolled: Set(h), ver: st.volumes.get(s).ver + 1}),
        attached: st.attached.filter(a => a._1 != s).union(Set((s, h))), failed: st.failed.filter(a => a._1 != s)},
      en' = {...en, ending: en.ending.filter(a => a._1 != s), raced: en.raced.filter(a => a._1 != s),
        endedOwners: en.endedOwners.filter(a => a._1 != s)},
      procs' = procs, ev' = env("flip", 0, s, h)
    }
  }
  pure def live(s: State): Set[int] = HOSTS.exclude(s.gone)
  val CensusUnderCap = ZONES.forall(z => listed(st.census.get(z)) <= CAP)
  val StandbyCovered = SHARDS.forall(s => st.shards.get(s).standby != 0 implies st.census.get(ZONE).slots.get(s).on)
  val StandbysUnderCap = SHARDS.filter(s => st.shards.get(s).standby != 0).size() <= CAP
  val SlotMovesOnlyOnEvidence = not(st.unevidenced)
  val NewerDesignationStands = not(st.overturned)
  val EntryTargetAdvances = not(st.regressed)
  val FeasibleSlot = SHARDS.forall(s => ZONES.forall(z => {
    val x = st.census.get(z).slots.get(s)
    x.on implies (x.host != x.owner and x.e > 0)
  }) and st.shards.get(s).standby != st.shards.get(s).owner)
  /// The named standby is live and enrolled, or its attach ended in a race with its designation (`raced`): the end
  /// was decided while the shard record named another standby and landed after a designation named the host, or
  /// landed between the volume read, which showed the attach live and enrolled, and the shard write of the
  /// designation that named the host. The end
  /// conditions on the volume record and the designation on the shard record, so the two commit in either order; the
  /// tenure model's `designationRacesEnd` shows such a standby refusing before any device command, and
  /// `designationRacesEndAfterCas` refusing at its reread with no preempt.
  val DesignatedIsEnrolled = SHARDS.forall(s => {
    val h = st.shards.get(s).standby
    h != 0 implies ((st.volumes.get(s).live.contains(h) and st.volumes.get(s).enrolled.contains(h))
      or en.raced.contains((s, h)))
  })
  /// Every owner at `E > 0` holds a live attach of its volume with an enrolled pair, or its attach ended after it
  /// became owner: a takeover makes owner only a standby with a live, enrolled attach.
  val OwnerHoldsItsAttach = SHARDS.forall(s => {
    val r = st.shards.get(s)
    r.e > 0 implies ((st.volumes.get(s).live.contains(r.owner) and st.volumes.get(s).enrolled.contains(r.owner))
      or en.endedOwners.contains((s, r.owner)))
  })
  /// A planned transfer writes an attempt below `EMAX`, so the owner it names holds an attempt for its own bump.
  val TransferLeavesBump = ev.act == "transfer" implies st.shards.get(ev.s).e < EMAX
  val AttachFollowsReservation = st.recorded.subseteq(st.reserved)
  val HostAttachmentsWithinLimit = live(st).forall(h => used(st, h) + owed(st, h) <= ATTACH)
  val StandbyRolesWithinHostLimit = live(st).forall(h => roles(st, h) <= ROLES)
  /// Witnesses: each names a state the unmutated model reaches, checked as the inverted invariant.
  val witnessCensusCreated = ev.note == "created"
  val witnessIneligible = ev.res == "ineligible"
  val witnessTaken = ev.res == "taken"
  val witnessFull = ev.res == "full"
  val witnessListed = ev.res == "listed"
  val witnessMovedOnLoss = ev.note == "movedOnLoss"
  val witnessMovedOnSuspicion = ev.note == "movedOnSuspicion"
  val witnessMovedFromOwner = ev.note == "movedFromOwner"
  val witnessDesignated = ev.note == "named"
  val witnessReplaced = ev.note == "replaced"
  val witnessStale = ev.res == "stale"
  val witnessConflict = ev.res == "conflict"
  val witnessAsIs = ev.res == "asis"
  val witnessUnenrolled = ev.res == "unenrolled"
  val witnessReleased = ev.res == "released"
  val witnessKeptCurrent = ev.res == "keptCurrent"
  val witnessKeptStandby = ev.res == "keptStandby"
  val witnessKeptLive = ev.res == "keptLive"
  val witnessReleaseAbsent = ev.res == "absent"
  val witnessReleaseUnlisted = ev.res == "unlisted"
  val witnessConditionLost = ev.act == "write" and ev.key == "census" and ev.res == "condition"
  /// A reservation whose census write is next puts an entry at an earlier tenure than one the census listed for its
  /// shard.
  val witnessEarlierTenurePending = RECS.exists(r => {
    val p = procs.get(r)
    p.op == "reserve" and keyOf(p) == "write" and rank(p.put) < st.hw.get(p.s)
  })
  val witnessDesignationConditionLost = ev.act == "write" and ev.key == "shard" and ev.res == "condition"
  val witnessUnknownCommitted = ev.act == "commit" and ev.note != ""
  val witnessUnknownLost = ev.act == "lost"
  val witnessHeld = ev.act == "hold"
  val witnessHeldDelivered = ev.act == "deliver" and ev.res == "committed"
  /// A reconciler stopped while it held a slot, and the other reconciler's designation of that shard returned.
  val witnessCrashConverges = st.orphan.s != 0 and ev.proc != st.orphan.r and ev.s == st.orphan.s
    and (ev.res == "designated" or ev.res == "asis")
  val witnessHeadroom = ev.res == "headroom"
  /// An actor outside the census takes the last free attachment slot of a host that owns no shard.
  val witnessOccupied = ev.act == "occupy" and used(st, ev.h) == ATTACH
    and SHARDS.forall(s => st.shards.get(s).owner != ev.h)
  val witnessKeptRecording = ev.res == "keptRecording"
  val witnessMovedOnFailedAttach = ev.note == "movedOnFailedAttach"
  /// A host designated on a shard whose owner is lost, after the standby it named was lost or with none named.
  val witnessFreshDesignated = (ev.note == "named" or ev.note == "replaced")
    and st.gone.contains(st.shards.get(ev.s).owner)
  val witnessStandsByBoth = HOSTS.exists(h => SHARDS.filter(s => st.shards.get(s).standby == h).size() >= 2)
  /// Every shard's owner is live and names no live standby, and one live host owns no shard.
  val witnessOneHostForBoth = SHARDS.forall(s => {
    val r = st.shards.get(s)
    not(st.gone.contains(r.owner)) and (r.standby == 0 or st.gone.contains(r.standby))
  }) and live(st).filter(h => SHARDS.forall(s => st.shards.get(s).owner != h)).size() == 1
  /// A release drops the entry of a host whose attach of the shard's volume ended, on the grounds that it shows no
  /// live attach.
  val witnessReleasedAfterEnd = ev.res == "released" and en.releasedEnded
  /// An attach record completes on a shard whose volume record refused a new attach before an end landed there.
  val witnessReopenedAfterEnd = ev.res == "recorded" and en.reopenable.contains(ev.s)
  /// A designation commits naming a host whose attach ended after the designation's volume read.
  val witnessNamedEnded = ev.note == "named" and en.raced.contains((ev.s, st.shards.get(ev.s).standby))
  /// A live candidate at the host role limit, not the shard's owner, excluded by the loop's filter from a reservation
  /// the census rules would admit: the shard's entry names a host the reconciler holds lost, or the shard is unlisted
  /// and the census is under `CAP`. The predicate leaves the `Closed` and `Headroom` checks out.
  val witnessExcluded = ev.res == "excluded" and not(st.gone.contains(ev.h)) and roles(st, ev.h) == ROLES
    and st.shards.get(ev.s).owner != ev.h and {
      val e = st.census.get(ZONE).slots.get(ev.s)
      if (e.on) lostTo(st, ev.proc, ev.s).contains(e.host) else listed(st.census.get(ZONE)) < CAP
    }
  /// A reservation finds the slot already listed for a live host at the role limit, which keeps its role.
  val witnessListedAtLimit = ev.res == "listed" and not(st.gone.contains(ev.h)) and roles(st, ev.h) == ROLES
  val witnessClosed = ev.res == "closed"
  val witnessAttachFailed = ev.act == "attachEnds" and ev.res == "failed"
  /// Shard `x` at generation 1 with an owner other than its initial one. A takeover and a planned transfer keep the
  /// generation and a flip raises it, so this state shows that the shard's standby became its owner by one of the
  /// two; a later move back to the initial owner leaves it false.
  pure def takenOver(s: State, x: int): bool = s.shards.get(x).g == 1 and s.shards.get(x).owner != OWNER.get(x)
  /// An enrollment written on a shard whose standby became its owner.
  val witnessReenrolled = ev.note == "enroll" and takenOver(st, ev.s)
  val witnessFullNoAttach = ev.res == "full" and not(st.volumes.get(ev.s).live.contains(ev.h))
  /// A census write lists a shard that held no slot while a shard whose standby became its owner holds none and
  /// needs one.
  val witnessSlotTakenAfterTakeover = ev.note == "newEntry" and SHARDS.exists(s => {
    s != ev.s and takenOver(st, s) and st.shards.get(s).standby == 0 and not(st.census.get(ZONE).slots.get(s).on)
  })
  /// The cap refuses the reservation of a shard whose standby became its owner.
  val witnessReservationFullAfterTakeover = ev.res == "full" and takenOver(st, ev.s)
  /// A planned transfer moves a shard record.
  val witnessTransferred = ev.act == "transfer"
  /// A designation names a standby of a shard whose record names an owner other than its initial one, as after a
  /// takeover or a planned transfer.
  val witnessRedesignatedOverNewOwner = ev.note == "named" and st.shards.get(ev.s).owner != OWNER.get(ev.s)
  val safety = CensusUnderCap and StandbyCovered and StandbysUnderCap and SlotMovesOnlyOnEvidence
    and NewerDesignationStands and EntryTargetAdvances and FeasibleSlot and DesignatedIsEnrolled
    and OwnerHoldsItsAttach and TransferLeavesBump and AttachFollowsReservation and HostAttachmentsWithinLimit
    and StandbyRolesWithinHostLimit
  action beginStep = {
    nondet r = RECS.oneOf()
    nondet op = OPS.oneOf()
    nondet s = SHARDS.oneOf()
    nondet h = hostArgs(op).oneOf()
    begin(r, op, s, h)
  }
  action procStep = {
    nondet r = RECS.oneOf()
    any {request(r), crash(r)}
  }
  action faultStep = {
    nondet r = RECS.oneOf()
    nondet fault = FAULTS.oneOf()
    unknown(r, fault)
  }
  action hostStep = {
    nondet h = HOSTS.oneOf()
    any {lose(h), occupy(h)}
  }
  action evidenceStep = {
    nondet r = RECS.oneOf()
    nondet h = HOSTS.oneOf()
    any {learn(r, h), suspect(r, h)}
  }
  action attachStep = {
    nondet s = SHARDS.oneOf()
    nondet h = HOSTS.oneOf()
    nondet completes = Set(true, false).oneOf()
    attachEnds(s, h, completes)
  }
  action endStep = {
    nondet s = SHARDS.oneOf()
    nondet h = HOSTS.oneOf()
    any {endRead(s, h), endWrite(s, h)}
  }
  action tenureStep = {
    nondet s = SHARDS.oneOf()
    any {bump(s), fresh(s), takeover(s), transfer(s)}
  }
  action flipStep = {
    nondet s = SHARDS.oneOf()
    nondet h = HOSTS.oneOf()
    flip(s, h)
  }
  action step = any {beginStep, procStep, faultStep, deliver, hostStep, evidenceStep, attachStep, endStep,
    tenureStep, flipStep}
}
