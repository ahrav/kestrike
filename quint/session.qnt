// -*- mode: Bluespec; -*-
// Q1: the session bootstrap of one owner and its client peers.
//
// Each client opens a session through HELLO, CHALLENGE, CONFIRM and READY,
// then exchanges data frames under it. The network loses, duplicates,
// reorders and delays frames, clients reboot with fresh boot nonces or
// reopen beside their active sessions, and the endpoints re-key, until the
// environment sets `stable`. After that no frame is lost, duplicated or
// delayed past a client's retry timer, and the copies already in flight
// still deliver.
//
// The handlers follow the session table and the client endpoint: the owner
// keeps a pending and an active handshake per peer, a bootstrap-sequence
// floor for the active session's client nonce and for the most recent other
// nonce, and the nonce the last activation displaced. A client keeps its
// boot nonce, its last bootstrap sequence, its pending and active
// handshakes, the CONFIRM repeats it sent for the pending one and whether an
// opening is under way.
// Its retry repeats the pending CONFIRM at most `REPEATS` times and then
// sends a fresh HELLO; a negative `REPEATS` repeats it without bound, which
// is the broken variant.
//
// Abstractions, each preserving every comparison the handlers make:
// - Bootstrap sequences and epochs are relabelled after every step by their
//   rank among the values in use: sequences per peer and client nonce,
//   epochs per peer. The handlers compare these values only for equality
//   and order and create new ones above every value in use, so the
//   relabelled system has the same behaviors and finitely many states.
// - The owner keeps one boot, so its nonce is fixed within a key epoch, and
//   a re-key drops every frame in flight, because the receiver's new keys
//   refuse frames sealed under the old ones. Data frames are checked for the
//   session they name; caps and the replay window are the implementation's
//   own tests.
// - Counters stay far below their 64-bit limits; the modeled exhaustion is
//   a pending handshake whose CONFIRM repeats are spent.
module session {
  const CLIENTS: Set[str]
  // Boot nonces per client; a reboot moves to the next one.
  const BOOTS: int
  // Re-keys before stability.
  const REKEYS: int
  // Losses, duplications, early retries, reboots, reopens and re-keys before
  // stability, together.
  const FAULTS: int
  // Distinct bootstrap frames in flight per peer toward the owner and toward the client.
  const CAP_TO_OWNER: int
  const CAP_TO_CLIENT: int
  // Copies of one frame in flight.
  const COPIES: int
  // CONFIRM repeats per pending handshake; negative repeats without bound.
  const REPEATS: int

  type Option[a] = Some(a) | None
  type Nonce = { boot: int, key: int }
  type Handshake = { epoch: int, client: Nonce }
  type Floor = { nonce: Nonce, highest: int }
  type OwnerPeer = {
    pending: Option[Handshake],
    active: Option[Handshake],
    issued: int,
    activeFloor: Option[Floor],
    otherFloor: Option[Floor],
    displaced: Option[Nonce],
  }
  type Client = {
    nonce: Nonce,
    sent: int,
    pending: Option[Handshake],
    active: Option[Handshake],
    repeats: int,
    // Whether an opening is under way: the client resends its bootstrap
    // frame until a READY activates the handshake it opened.
    opening: bool,
  }
  // `seq` is the sender's bootstrap sequence on HELLO and CONFIRM, the
  // echoed one on CHALLENGE and READY, and 0 on data frames.
  type Frame = { kind: str, peer: str, toOwner: bool, client: Nonce, epoch: int, seq: int }
  type State = {
    owner: str -> OwnerPeer,
    clients: str -> Client,
    net: Frame -> int,
    stable: bool,
    rekeys: int,
    faults: int,
    overflow: bool,
  }
  // The step that produced the state: its action, peer, the frame a
  // delivery handled, the handler's verdict and the facts the invariants
  // and witnesses read.
  type Event = {
    act: str,
    peer: str,
    frame: Option[Frame],
    verdict: str,
    changed: bool,
    namedActive: bool,
    binds: bool,
    replaced: str,
    pendingDisplaced: bool,
    restart: bool,
    pendingForeign: bool,
  }

  var s: State
  var last: Event

  pure val noEvent: Event = {
    act: "init", peer: "", frame: None, verdict: "", changed: false,
    namedActive: false, binds: false, replaced: "", pendingDisplaced: false, restart: false,
    pendingForeign: false,
  }

  pure def names(h: Option[Handshake], f: Frame): bool = match h {
    | Some(x) => x.epoch == f.epoch and x.client == f.client
    | None => false
  }

  pure def isSome(o: Option[a]): bool = match o { | Some(_) => true | None => false }

  // Floors and in-flight frames.

  pure def floorIs(o: Option[Floor], n: Nonce): bool = match o {
    | Some(x) => x.nonce == n
    | None => false
  }

  pure def floorHighest(o: Option[Floor]): int = match o { | Some(x) => x.highest | None => 0 }

  pure def channel(st: State, peer: str, toOwner: bool): Set[Frame] =
    st.net.keys().filter(f => f.peer == peer and f.toOwner == toOwner)

  // Before stability a channel holds at most its capacity of distinct
  // bootstrap frames and one distinct data frame.
  pure def room(st: State, peer: str, toOwner: bool, kind: str): bool =
    val held = inFlight(st, peer, toOwner, kind == "data")
    st.stable or held.size() < (if (kind == "data") 1 else if (toOwner) CAP_TO_OWNER else CAP_TO_CLIENT)

  // The frames of one class, bootstrap or data, in flight toward one end.
  pure def inFlight(st: State, peer: str, toOwner: bool, data: bool): Set[Frame] =
    channel(st, peer, toOwner).filter(f => (f.kind == "data") == data)

  // Adds one copy of `f`. Before stability a frame past its channel's room or
  // its copy bound is lost; after stability a copy past the bound is a
  // modeling error that `bounded` reports.
  pure def send(st: State, f: Frame): State =
    if (st.net.keys().contains(f))
      if (st.net.get(f) < COPIES) { ...st, net: st.net.set(f, st.net.get(f) + 1) }
      else { ...st, overflow: st.overflow or st.stable }
    else if (room(st, f.peer, f.toOwner, f.kind)) { ...st, net: st.net.put(f, 1) }
    else st

  pure def take(st: State, f: Frame): State =
    if (st.net.get(f) > 1) { ...st, net: st.net.set(f, st.net.get(f) - 1) }
    else { ...st, net: st.net.keys().exclude(Set(f)).mapBy(g => st.net.get(g)) }

  // Owner handlers.

  // The floor check for `n` at `seq`: the raised floors, or None when stale.
  pure def checkFloor(o: OwnerPeer, n: Nonce, seq: int): Option[OwnerPeer] =
    if (seq == 0 or o.displaced == Some(n)) None
    else if (floorIs(o.activeFloor, n))
      if (seq > floorHighest(o.activeFloor)) Some({ ...o, activeFloor: Some({ nonce: n, highest: seq }) })
      else None
    else
      // A nonce outside both floors starts the other floor at 0.
      val other = if (floorIs(o.otherFloor, n)) floorHighest(o.otherFloor) else 0
      if (seq > other) Some({ ...o, otherFloor: Some({ nonce: n, highest: seq }) })
      else None

  // Makes `h` active; a floor for its nonce becomes the active floor, and an
  // active floor for another nonce names the displaced nonce.
  pure def activate(o: OwnerPeer, h: Handshake): OwnerPeer =
    val displaced = match o.activeFloor {
      | Some(x) => if (x.nonce != h.client) Some(x.nonce) else o.displaced
      | None => o.displaced
    }
    val floors = if (floorIs(o.otherFloor, h.client)) { activeFloor: o.otherFloor, otherFloor: None }
                 else { activeFloor: o.activeFloor, otherFloor: o.otherFloor }
    { ...o, displaced: displaced, activeFloor: floors.activeFloor, otherFloor: floors.otherFloor,
      pending: None, active: Some(h) }

  pure def replacement(o: OwnerPeer, h: Handshake): str = match o.active {
    | Some(x) => if (x.client == h.client) "replacement" else "displacement"
    | None => ""
  }

  // The owner's answer to client frame `f`, removed from the network.
  pure def ownerReceive(st: State, f: Frame): (State, Event) =
    val o = st.owner.get(f.peer)
    val ev = { ...noEvent, act: "deliverToOwner", peer: f.peer, frame: Some(f) }
    val keep = (st, { ...ev, verdict: "stale" })
    if (f.kind == "hello")
      match checkFloor(o, f.client, f.seq) {
        | None => keep
        | Some(raised) =>
          val epoch = raised.issued + 1
          val h = { epoch: epoch, client: f.client }
          val after = { ...raised, issued: epoch, pending: Some(h) }
          val displacedPending = match o.pending { | Some(p) => p.client != f.client | None => false }
          val reply = { kind: "challenge", peer: f.peer, toOwner: false, client: f.client, epoch: epoch, seq: f.seq }
          (send({ ...st, owner: st.owner.set(f.peer, after) }, reply),
           { ...ev, verdict: "accepted", pendingDisplaced: displacedPending })
      }
    else if (f.kind == "confirm")
      if (names(o.active, f))
        match checkFloor(o, f.client, f.seq) {
          | None => keep
          | Some(raised) =>
            val reply = { kind: "ready", peer: f.peer, toOwner: false, client: f.client, epoch: f.epoch, seq: f.seq }
            (send({ ...st, owner: st.owner.set(f.peer, raised) }, reply), { ...ev, verdict: "repeat" })
        }
      else if (names(o.pending, f))
        match checkFloor(o, f.client, f.seq) {
          | None => keep
          | Some(raised) =>
            val h = { epoch: f.epoch, client: f.client }
            val reply = { kind: "ready", peer: f.peer, toOwner: false, client: f.client, epoch: f.epoch, seq: f.seq }
            (send({ ...st, owner: st.owner.set(f.peer, activate(raised, h)) }, reply),
             { ...ev, verdict: "activated", replaced: replacement(o, h) })
        }
      else (st, { ...ev, verdict: "mismatch" })
    else
      val admitted = names(o.active, f)
      (st, { ...ev, verdict: if (admitted) "accepted" else "mismatch" })

  // Client handlers.

  pure def clientReceive(st: State, f: Frame): (State, Event) =
    val c = st.clients.get(f.peer)
    val ev = { ...noEvent, act: "deliverToClient", peer: f.peer, frame: Some(f) }
    if (f.kind == "challenge")
      if (f.client != c.nonce) (st, { ...ev, verdict: "mismatch" })
      else if (c.sent == 0 or f.seq != c.sent) (st, { ...ev, verdict: "stale" })
      else
        val h = { epoch: f.epoch, client: c.nonce }
        val after = { ...c, sent: c.sent + 1, pending: Some(h), repeats: 0 }
        val confirm = { kind: "confirm", peer: f.peer, toOwner: true, client: c.nonce, epoch: f.epoch, seq: c.sent + 1 }
        (send({ ...st, clients: st.clients.set(f.peer, after) }, confirm), { ...ev, verdict: "accepted" })
    else if (f.kind == "ready")
      if (names(c.active, f)) (st, { ...ev, verdict: "repeat" })
      else if (not(names(c.pending, f))) (st, { ...ev, verdict: "mismatch" })
      else if (f.seq != c.sent) (st, { ...ev, verdict: "stale" })
      else
        val after = { ...c, active: c.pending, pending: None, opening: false }
        ({ ...st, clients: st.clients.set(f.peer, after) },
         { ...ev, verdict: "activated", binds: st.owner.get(f.peer).active == c.pending })
    else
      val admitted = names(c.active, f)
      (st, { ...ev, verdict: if (admitted) "accepted" else "mismatch" })

  // A client's bootstrap resend: the pending CONFIRM while its repeats last,
  // otherwise a fresh HELLO that drops the pending handshake.
  pure def resend(st: State, peer: str): (State, Event) =
    val c = st.clients.get(peer)
    val ev = { ...noEvent, act: "retry", peer: peer }
    match c.pending {
      | Some(h) =>
        if (REPEATS < 0 or c.repeats < REPEATS)
          val after = { ...c, sent: c.sent + 1, repeats: if (REPEATS < 0) 0 else c.repeats + 1 }
          val confirm = { kind: "confirm", peer: peer, toOwner: true, client: c.nonce, epoch: h.epoch, seq: c.sent + 1 }
          (send({ ...st, clients: st.clients.set(peer, after) }, confirm), { ...ev, verdict: "confirm" })
        else (sendHello(st, peer, c), { ...ev, verdict: "hello", restart: true })
      | None => (sendHello(st, peer, c), { ...ev, verdict: "hello" })
    }

  // Client `c`'s HELLO at its next bootstrap sequence. It drops the pending
  // handshake and keeps the active session, which stays until a READY
  // activates a new one.
  pure def sendHello(st: State, peer: str, c: Client): State =
    val hello = { kind: "hello", peer: peer, toOwner: true, client: c.nonce, epoch: 0, seq: c.sent + 1 }
    send({ ...st, clients: st.clients.set(peer, { ...c, sent: c.sent + 1, pending: None }) }, hello)

  // Relabelling of sequences and epochs by rank, 0 kept as 0.

  pure def rank(values: Set[int], v: int): int =
    if (v == 0) 0 else values.filter(u => u > 0 and u < v).size() + 1

  pure def floorSeqs(o: Option[Floor], n: Nonce): Set[int] = match o {
    | Some(x) => if (x.nonce == n) Set(x.highest) else Set()
    | None => Set()
  }

  pure def seqs(st: State, peer: str, n: Nonce): Set[int] =
    val c = st.clients.get(peer)
    val o = st.owner.get(peer)
    (if (c.nonce == n) Set(c.sent) else Set())
      .union(floorSeqs(o.activeFloor, n)).union(floorSeqs(o.otherFloor, n))
      .union(st.net.keys().filter(f => f.peer == peer and f.client == n).map(f => f.seq))

  pure def epochOf(h: Option[Handshake]): Set[int] = match h { | Some(x) => Set(x.epoch) | None => Set() }

  pure def epochs(st: State, peer: str): Set[int] =
    val c = st.clients.get(peer)
    val o = st.owner.get(peer)
    Set(o.issued).union(epochOf(o.pending)).union(epochOf(o.active))
      .union(epochOf(c.pending)).union(epochOf(c.active))
      .union(st.net.keys().filter(f => f.peer == peer).map(f => f.epoch))

  pure def relabel(h: Option[Handshake], e: Set[int]): Option[Handshake] = match h {
    | Some(x) => Some({ ...x, epoch: rank(e, x.epoch) })
    | None => None
  }

  pure def relabelFloor(st: State, peer: str, o: Option[Floor]): Option[Floor] = match o {
    | Some(x) => Some({ ...x, highest: rank(seqs(st, peer, x.nonce), x.highest) })
    | None => None
  }

  pure def normalize(st: State): State =
    val owner = CLIENTS.mapBy(p =>
      val o = st.owner.get(p)
      val e = epochs(st, p)
      { ...o, issued: rank(e, o.issued), pending: relabel(o.pending, e), active: relabel(o.active, e),
        activeFloor: relabelFloor(st, p, o.activeFloor), otherFloor: relabelFloor(st, p, o.otherFloor) })
    val clients = CLIENTS.mapBy(p =>
      val c = st.clients.get(p)
      val e = epochs(st, p)
      { ...c, sent: rank(seqs(st, p, c.nonce), c.sent), pending: relabel(c.pending, e), active: relabel(c.active, e) })
    val net = st.net.keys().map(f =>
      ({ ...f, epoch: rank(epochs(st, f.peer), f.epoch), seq: rank(seqs(st, f.peer, f.client), f.seq) },
       st.net.get(f))).setToMap()
    { ...st, owner: owner, clients: clients, net: net }

  // Actions.

  // Whether the owner's pending handshake for `peer` names a client nonce
  // other than the client's current one.
  pure def pendingForeign(st: State, peer: str): bool =
    CLIENTS.contains(peer) and match st.owner.get(peer).pending {
      | Some(h) => h.client != st.clients.get(peer).nonce
      | None => false
    }

  action commit(st: State, ev: Event): bool = all {
    s' = normalize(st),
    last' = { ...ev, pendingForeign: pendingForeign(st, ev.peer) },
  }

  action init = all {
    s' = {
      owner: CLIENTS.mapBy(_ => { pending: None, active: None, issued: 0, activeFloor: None,
                                  otherFloor: None, displaced: None }),
      clients: CLIENTS.mapBy(_ => { nonce: { boot: 0, key: 0 }, sent: 0, pending: None, active: None, repeats: 0,
                                    opening: true }),
      net: Map(),
      stable: false,
      rekeys: 0,
      faults: 0,
      overflow: false,
    },
    last' = noEvent,
  }

  // Whether `peer`'s current bootstrap exchange has a frame in flight.
  pure def awaiting(st: State, peer: str): bool =
    st.net.keys().exists(f => f.peer == peer and f.kind != "data" and f.client == st.clients.get(peer).nonce)

  // An opening client retries once its exchange is idle, since the retry
  // timer outlasts the round trip. Before stability a delay can hold a frame
  // past the timer, so a retry while a frame is in flight spends a fault.
  action retry(peer: str): bool = all {
    s.clients.get(peer).opening,
    val early = awaiting(s, peer)
    all {
      not(early) or (not(s.stable) and s.faults < FAULTS),
      room(s, peer, true, "hello"),
      val r = resend(s, peer)
      commit({ ...r._1, faults: r._1.faults + (if (early) 1 else 0) }, r._2),
    },
  }

  // An active client opens a fresh session beside its active one. Its HELLO
  // starts an opening, and the active session stays until the new
  // handshake's READY replaces it. A reopen happens only before stability
  // and spends a fault.
  action reopen(peer: str): bool = all {
    not(s.stable),
    s.faults < FAULTS,
    isActive(s, peer),
    room(s, peer, true, "hello"),
    val c = s.clients.get(peer)
    commit({ ...sendHello(s, peer, { ...c, opening: true }), faults: s.faults + 1 },
           { ...noEvent, act: "reopen", peer: peer }),
  }

  // Delivery takes one frame of a class, so fairness toward the bootstrap
  // class holds while data frames keep arriving.
  action deliverToOwner(peer: str, data: bool): bool = all {
    inFlight(s, peer, true, data).size() > 0,
    nondet f = inFlight(s, peer, true, data).oneOf()
    val r = ownerReceive(take(s, f), f)
    commit(r._1, { ...r._2, changed: r._1.owner != s.owner or r._1.clients != s.clients,
                   namedActive: s.owner.get(peer).active == Some({ epoch: f.epoch, client: f.client }),
                   binds: r._1.owner.get(peer).active == s.owner.get(peer).pending }),
  }

  action deliverToClient(peer: str, data: bool): bool = all {
    inFlight(s, peer, false, data).size() > 0,
    nondet f = inFlight(s, peer, false, data).oneOf()
    val r = clientReceive(take(s, f), f)
    commit(r._1, { ...r._2, changed: r._1.owner != s.owner or r._1.clients != s.clients,
                   namedActive: s.clients.get(peer).active == Some({ epoch: f.epoch, client: f.client }) }),
  }

  pure def handshake(o: Option[Handshake]): Handshake = match o {
    | Some(x) => x
    | None => { epoch: 0, client: { boot: 0, key: 0 } }
  }

  // A data frame under the sender's active session `h`, sent while no data
  // frame is in flight in that direction.
  action data(peer: str, toOwner: bool, h: Option[Handshake], act: str): bool = all {
    isSome(h),
    not(channel(s, peer, toOwner).exists(f => f.kind == "data")),
    val f = { kind: "data", peer: peer, toOwner: toOwner, client: handshake(h).client, epoch: handshake(h).epoch, seq: 0 }
    commit(send(s, f), { ...noEvent, act: act, peer: peer, frame: Some(f) }),
  }

  action clientData(peer: str): bool = data(peer, true, s.clients.get(peer).active, "clientData")
  action ownerData(peer: str): bool = data(peer, false, s.owner.get(peer).active, "ownerData")

  action lose: bool = all {
    not(s.stable),
    s.faults < FAULTS,
    s.net.keys().size() > 0,
    nondet f = s.net.keys().oneOf()
    commit({ ...take(s, f), faults: s.faults + 1 }, { ...noEvent, act: "lose", peer: f.peer, frame: Some(f) }),
  }

  action duplicate: bool = all {
    not(s.stable),
    s.faults < FAULTS,
    s.net.keys().exists(f => s.net.get(f) < COPIES),
    nondet f = s.net.keys().filter(f => s.net.get(f) < COPIES).oneOf()
    commit({ ...s, faults: s.faults + 1, net: s.net.set(f, s.net.get(f) + 1) }, { ...noEvent, act: "duplicate", peer: f.peer, frame: Some(f) }),
  }

  // A reboot starts the client over under its next boot nonce.
  action reboot(peer: str): bool = all {
    not(s.stable),
    s.faults < FAULTS,
    s.clients.get(peer).nonce.boot + 1 < BOOTS,
    val c = s.clients.get(peer)
    val after = { nonce: { ...c.nonce, boot: c.nonce.boot + 1 }, sent: 0, pending: None, active: None, repeats: 0,
                  opening: true }
    commit({ ...s, faults: s.faults + 1, clients: s.clients.set(peer, after) }, { ...noEvent, act: "reboot", peer: peer }),
  }

  // A re-key of every endpoint: sessions and pending handshakes end, each
  // client takes a new boot nonce and keeps its bootstrap sequence, the
  // owner keeps its floors and issued epochs, and the frames in flight fail
  // authentication under the new keys.
  action rekey: bool = all {
    not(s.stable),
    s.faults < FAULTS,
    s.rekeys < REKEYS,
    val key = s.rekeys + 1
    commit({ ...s,
      rekeys: key,
      faults: s.faults + 1,
      net: Map(),
      owner: CLIENTS.mapBy(p => { ...s.owner.get(p), pending: None, active: None }),
      clients: CLIENTS.mapBy(p =>
        val c = s.clients.get(p)
        { ...c, nonce: { ...c.nonce, key: key }, pending: None, active: None, repeats: 0, opening: true }),
    }, { ...noEvent, act: "rekey" }),
  }

  action stabilize: bool = all {
    not(s.stable),
    commit({ ...s, stable: true }, { ...noEvent, act: "stabilize" }),
  }

  action step = any {
    nondet peer = CLIENTS.oneOf()
    nondet data = Set(false, true).oneOf()
    any { retry(peer), deliverToOwner(peer, data), deliverToClient(peer, data), clientData(peer), ownerData(peer),
          reboot(peer), reopen(peer) },
    lose,
    duplicate,
    rekey,
    stabilize,
  }

  // Safety.

  pure def isActive(st: State, peer: str): bool = isSome(st.clients.get(peer).active)

  // A client's active session is the owner's active session for that peer:
  // the same epoch and client nonce. While the client reopens beside its
  // active session, the owner may instead hold a later handshake of the same
  // client nonce, which the owner activated before its READY reached the
  // client.
  val agreement = CLIENTS.forall(p =>
    val c = s.clients.get(p)
    val o = s.owner.get(p).active
    match c.active {
      | Some(h) => o == Some(h) or (c.opening and match o {
          | Some(x) => x.client == h.client and x.epoch > h.epoch
          | None => false
        })
      | None => true
    })

  // Every activation binds exactly the handshake it completes: on CONFIRM the
  // owner's new active session is its pending handshake before the step, and
  // on READY the client's new active session is the owner's active one.
  val activationBinds = last.verdict == "activated" implies last.binds

  // Epochs issued within one owner boot are distinct: the pending epoch is
  // the last issued one and differs from the active epoch, which is at most
  // the last issued one.
  val distinctEpochs = CLIENTS.forall(p =>
    val o = s.owner.get(p)
    val pending = match o.pending { | Some(h) => h.epoch == o.issued | None => true }
    val active = match o.active { | Some(h) => h.epoch <= o.issued | None => true }
    val apart = match o.pending { | Some(h) => o.active.epochOf().forall(e => e != h.epoch) | None => true }
    pending and active and apart)

  // A refused frame changes no session state, and a data frame is accepted
  // only under the receiver's active session.
  val staleChangesNothing = Set("stale", "mismatch").contains(last.verdict) implies not(last.changed)
  val dataNamesActive =
    (last.verdict == "accepted" and match last.frame { | Some(f) => f.kind == "data" | None => false })
      implies last.namedActive

  // After stability every frame fits the network's copy bound.
  val bounded = not(s.overflow)

  val safety = agreement and activationBinds and distinctEpochs and staleChangesNothing
    and dataNamesActive and bounded

  // Progress: under fair delivery and retries, every client ends active.
  temporal fairness = and {
    weakFair(stabilize, (s, last)),
    CLIENTS.forall(p => and {
      weakFair(retry(p), (s, last)),
      weakFair(deliverToOwner(p, false), (s, last)),
      weakFair(deliverToClient(p, false), (s, last)),
    }),
  }
  temporal progress = fairness implies CLIENTS.forall(p => eventually(always(isActive(s, p))))

  // Reachability witnesses: each is true in the state an action or outcome produced.
  pure def delivered(e: Event, kind: str, verdict: str): bool =
    e.verdict == verdict and match e.frame { | Some(f) => f.kind == kind and Set("deliverToOwner", "deliverToClient").contains(e.act) | None => false }

  val witnessHello = delivered(last, "hello", "accepted")
  val witnessStaleHello = delivered(last, "hello", "stale")
  val witnessChallenge = delivered(last, "challenge", "accepted")
  val witnessChallengeMismatch = delivered(last, "challenge", "mismatch")
  val witnessChallengeStale = delivered(last, "challenge", "stale")
  val witnessOwnerActivation = delivered(last, "confirm", "activated")
  val witnessConfirmMismatch = delivered(last, "confirm", "mismatch")
  val witnessConfirmRepeat = delivered(last, "confirm", "repeat")
  val witnessConfirmStale = delivered(last, "confirm", "stale")
  val witnessReadyRepeat = delivered(last, "ready", "repeat")
  val witnessReadyStale = delivered(last, "ready", "stale")
  val witnessClientActivation = delivered(last, "ready", "activated")
  val witnessReadyMismatch = delivered(last, "ready", "mismatch")
  val witnessOwnerData = last.act == "deliverToOwner" and delivered(last, "data", "accepted")
  val witnessClientData = last.act == "deliverToClient" and delivered(last, "data", "accepted")
  val witnessStaleData = last.act == "deliverToClient" and delivered(last, "data", "mismatch")
  val witnessOwnerStaleData = last.act == "deliverToOwner" and delivered(last, "data", "mismatch")
  val witnessReplacement = last.replaced == "replacement"
  val witnessDisplacement = last.replaced == "displacement"
  val witnessPendingDisplaced = last.pendingDisplaced
  val witnessRestart = last.restart
  // A client restarts its handshake while the owner's pending handshake for
  // it names another client nonce: a stale HELLO displaced it.
  val witnessDisplacedRestart = last.restart and last.pendingForeign
  val witnessLose = last.act == "lose"
  val witnessDuplicate = last.act == "duplicate"
  val witnessReboot = last.act == "reboot"
  val witnessRekey = last.act == "rekey"
  val witnessReopen = last.act == "reopen"
  // The owner activated a reopened client's new handshake before its READY
  // reached the client, which still holds the replaced session.
  val witnessReopenWindow = CLIENTS.exists(p =>
    isActive(s, p) and s.owner.get(p).active != s.clients.get(p).active)
  val witnessAllActive = s.stable and CLIENTS.forall(p => isActive(s, p))
}

