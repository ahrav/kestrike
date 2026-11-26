------------------------------- MODULE Identity -------------------------------
(* Request identity and PUT result replay over one owner namespace and one   *)
(* client board, at small finite bounds.                                     *)
(*                                                                           *)
(* Six identities bound every effect. The owner keeps one wire slot per peer *)
(* and slot number with its session's highest admitted generation, the live  *)
(* request's table handle and a retained outcome row; a request's operation  *)
(* (GET or PUT) is fixed at admission. The shared request table charges one  *)
(* per-peer share across operations and hands out table handles whose        *)
(* generation advances at release. The client board attaches a successive   *)
(* core number to each request namespace; a lease release credits the live  *)
(* request only under its board core and generation and otherwise frees one  *)
(* orphan. A frame reaches a request only under its peer, wire slot,         *)
(* generation, operation and session epoch; a refusal changes no identity;   *)
(* a retained row answers a matching retry until its expiry, and after       *)
(* expiry the owner answers UnknownOutcome. The fill and read inside each    *)
(* request, and the outcome it reports, are the Lifecycle model's; here a    *)
(* request ends in one step that retains its row and sends a RESULT; a      *)
(* request whose RESULT went out frees its wire slot while its record       *)
(* drains, marked unbound, and a release names it by that mark. The         *)
(* client's upload keeps an outcome that a later matching RESULT may        *)
(* resolve while it is Unknown.                                             *)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Upload,   \* the client holds one PUT
    Mismatch, \* the client may retry with another shape
    StaleData, \* the client may send DATA of an ended upload
    Peers,   \* peers; each holds its own wire slots and share
    Slots,   \* wire slot numbers per peer
    Gens,    \* wire generations 1..G a peer may name; G is the generation limit
    Epochs,  \* session epochs 1..E a peer may hold, in order
    Share,   \* live requests one peer may hold
    Table,   \* table handles, shared across peers
    PutCap,  \* live PUT records, active and ended, across all peers
    PeerPutCap, \* live PUT records one peer may hold
    Cores,   \* client board core numbers 1..C, one per namespace attachment
    Leases,  \* leases one GET hands the application
    Linger   \* clock ticks a retained row answers after its request ended

Ops == {"GET", "PUT"}
Limit == Cardinality(Gens)
Kinds == {"RETRY", "RETRY2", "DATA", "RESULT", "UNKNOWN"}
Frame == [peer : Peers, slot : Slots, gen : Gens, op : Ops, epoch : Epochs, kind : Kinds]
NoRow == [op |-> "none", epoch |-> 0, expires |-> 0]
Free == [peer |-> 0, op |-> "none", slot |-> 0, gen |-> 0, ended |-> FALSE, unbound |-> FALSE, tg |-> 0]

VARIABLES
    epoch,     \* each peer's current session epoch at the owner
    wire,      \* each peer's wire slots: mark (watermark, 0 for none), active handle (0 for none), row
    table,     \* each table handle's record: peer, operation, wire slot and generation, ended, unbound, or Free
    tgen,      \* each table handle's generation
    admits,    \* admissions per epoch, peer, wire slot and generation
    net,       \* frames sent; delivery is repeatable
    counts,    \* saturating counters: refusals, share-pressure refusals and refusals by the global or per-peer PUT cap,
               \* wrong operations, conflicts, UnknownOutcome
               \* answers and those from an expired row, dropped frames, replays and those from a stale or other-operation
               \* row, stale lease returns under an earlier core, releases naming a stale table generation, and
               \* releases that freed a record of another table generation
    clock,     \* the owner's clock, which expires rows
    upload,    \* the client's one PUT: its wire identity, epoch and outcome
    board,     \* the client board: core, next wire generation, orphans
    leases     \* client GET leases per client handle: board core and generation of the open request, the handle's
               \* live generation, handed leases, open, and the stale leases of one closed request with their core and generation

vars == <<epoch, wire, table, tgen, admits, net, counts, clock, upload, board, leases>>
ownerVars == <<epoch, wire, table, tgen, admits, counts, clock>>
clientVars == <<upload, board, leases>>

Live == {h \in 1..Table : table[h] # Free}
Held(p) == {h \in Live : table[h].peer = p}
LivePuts == {h \in Live : table[h].op = "PUT"}
HeldPuts(p) == {h \in Held(p) : table[h].op = "PUT"}
Send(m) == net' = net \cup {m}
Count(k) == counts' = [counts EXCEPT ![k] = @ + 1]

Init ==
    /\ epoch = [p \in Peers |-> 1]
    /\ wire = [p \in Peers |-> [s \in Slots |-> [mark |-> 0, active |-> 0, row |-> NoRow]]]
    /\ table = [h \in 1..Table |-> Free] /\ tgen = [h \in 1..Table |-> 1]
    /\ admits = [e \in Epochs |-> [p \in Peers |-> [s \in Slots |-> [g \in Gens |-> 0]]]]
    /\ net = {} /\ counts = [refused |-> 0, pressure |-> 0, capped |-> 0, peercapped |-> 0, wrong |-> 0, conflict |-> 0, unknown |-> 0, expired |-> 0,
                             dropped |-> 0, replays |-> 0, late |-> 0, crossed |-> 0, oldlease |-> 0, stalerel |-> 0, freed |-> 0]
    /\ clock = 0
    /\ upload = [peer |-> 0, slot |-> 0, gen |-> 0, epoch |-> 0, outcome |-> "none", abandoned |-> FALSE, by |-> 0, bye |-> 0, resolved |-> FALSE]
    /\ board = [core |-> 1, next |-> 1, orphans |-> 0]
    /\ leases = [h \in 1..Table |-> [core |-> 0, gen |-> 1, live |-> 1, handed |-> 0, open |-> FALSE,
                                      stale |-> 0, score |-> 0, sgen |-> 0]]

-----------------------------------------------------------------------------
\* Owner admission. A fresh wire identity above the slot's watermark and below
\* the generation limit, on a free binding with room in the peer's share and
\* the table, takes a table handle: the watermark rises and the row clears.
\* Every refusal preserves every identity and moves its refusal counters: the
\* pressure one for a fresh PUT that a held GET keeps out of a full share or
\* table, and a cap one for a fresh PUT with room that the global or the
\* per-peer PUT cap refuses; each counter saturates at a small bound so a
\* repeated refusal adds no state.
Fresh(p, s, g) == g > wire[p][s].mark /\ wire[p][s].active = 0 /\ g < Limit
Room(p) == Cardinality(Held(p)) < Share /\ Cardinality(Live) < Table
\* A PUT also needs room under the global and per-peer PUT caps. Its record
\* counts against both from admission until Release frees it, ended or not.
Admissible(p, op) == Room(p) /\ (op = "GET" \/ (Cardinality(LivePuts) < PutCap /\ Cardinality(HeldPuts(p)) < PeerPutCap))

Admit(p, s, g, op) ==
    /\ Fresh(p, s, g) /\ Admissible(p, op)
    /\ \E h \in 1..Table :
        /\ table[h] = Free
        /\ table' = [table EXCEPT ![h] = [peer |-> p, op |-> op, slot |-> s, gen |-> g, ended |-> FALSE, unbound |-> FALSE, tg |-> tgen[h]]]
        /\ wire' = [wire EXCEPT ![p][s] = [mark |-> g, active |-> h, row |-> NoRow]]
    /\ admits' = [admits EXCEPT ![epoch[p]][p][s][g] = @ + 1]
    /\ UNCHANGED <<epoch, tgen, net, counts, clock, clientVars>>

Refuse(p, s, g, op) ==
    /\ ~(Fresh(p, s, g) /\ Admissible(p, op)) /\ counts.refused < 1
    /\ counts' = [counts EXCEPT !.refused = @ + 1,
                  !.pressure = @ + (IF Fresh(p, s, g) /\ op = "PUT" /\ ~Room(p) /\ \E h \in Held(p) : table[h].op = "GET" THEN 1 ELSE 0),
                  !.capped = @ + (IF Fresh(p, s, g) /\ op = "PUT" /\ Room(p) /\ Cardinality(LivePuts) >= PutCap THEN 1 ELSE 0),
                  !.peercapped = @ + (IF Fresh(p, s, g) /\ op = "PUT" /\ Room(p) /\ Cardinality(LivePuts) < PutCap
                                         /\ Cardinality(HeldPuts(p)) >= PeerPutCap THEN 1 ELSE 0)]
    /\ UNCHANGED <<epoch, wire, table, tgen, admits, net, clock, clientVars>>

\* A request ends in one step: the row retains its operation under the
\* request's epoch until Linger ticks pass, and a RESULT goes out. The row
\* keeps what replay and routing read; the outcome a request reports is the
\* Lifecycle model's. A request whose session was replaced ends without a row
\* or a reply.
End(p, s) ==
    /\ wire[p][s].active # 0 /\ wire[p][s].row = NoRow /\ table[wire[p][s].active].ended = FALSE
    /\ LET h == wire[p][s].active IN
        IF wire[p][s].mark = 0
        THEN table' = [table EXCEPT ![h].ended = TRUE] /\ UNCHANGED <<wire, net>>
        ELSE /\ wire' = [wire EXCEPT ![p][s].row = [op |-> table[h].op, epoch |-> epoch[p], expires |-> clock + Linger]]
             /\ table' = [table EXCEPT ![h].ended = TRUE]
             /\ Send([peer |-> p, slot |-> s, gen |-> table[h].gen, op |-> table[h].op,
                      epoch |-> epoch[p], kind |-> "RESULT"])
    /\ UNCHANGED <<epoch, tgen, admits, counts, clock, clientVars>>

\* A GET or PUT whose RESULT went out under its session frees its wire slot
\* while its record drains: the binding clears, the record stays live and
\* marked unbound, and the watermark and row stay, so a fresh generation on
\* the slot admits on share and table room alone. A record ended without a
\* RESULT, its session replaced, keeps its binding until release.
Unbind(p, s) ==
    /\ wire[p][s].active # 0 /\ wire[p][s].row # NoRow
    /\ LET h == wire[p][s].active IN
        /\ table[h].ended
        /\ wire' = [wire EXCEPT ![p][s].active = 0]
        /\ table' = [table EXCEPT ![h].unbound = TRUE]
    /\ UNCHANGED <<epoch, tgen, admits, net, counts, clock, clientVars>>

\* Release drops the record once its custody drained. A release names the
\* handle it frees and a table generation: it acts only on the handle the
\* wire slot binds or on the peer's handle marked unbound, whose record the
\* handle alone names, so a delayed release of an earlier handle leaves a
\* successor's binding alone; naming the handle's current table generation
\* clears the exact binding, if any, and advances that generation while the
\* watermark and row stay; naming an earlier generation frees nothing.
Release(p, s, h, tg) ==
    /\ (wire[p][s].active = h \/ (table[h].unbound /\ table[h].peer = p)) /\ table[h].ended /\ tg <= tgen[h]
    /\ IF tg = tgen[h]
       THEN /\ table' = [table EXCEPT ![h] = Free] /\ tgen' = [tgen EXCEPT ![h] = @ + 1]
            /\ wire' = [wire EXCEPT ![p][s].active = IF @ = h THEN 0 ELSE @]
            /\ counts' = [counts EXCEPT !.freed = @ + (IF table[h].tg = tg THEN 0 ELSE 1)]
       ELSE /\ counts.stalerel < 1 /\ counts' = [counts EXCEPT !.stalerel = @ + 1]
            /\ UNCHANGED <<table, tgen, wire>>
    /\ UNCHANGED <<epoch, admits, net, clock, clientVars>>

\* Routing. A frame of the peer's current session epoch at the watermark that
\* meets another operation's live request or row counts WrongOperation and
\* changes nothing else; the session boundary keeps an earlier epoch's frame
\* from every owner action.
At(w, g) == w.mark = g
Other(w, op) ==
    \/ w.active # 0 /\ table[w.active].op # op
    \/ w.row # NoRow /\ w.row.op # op
Current(w, p) == w.row # NoRow /\ w.row.epoch = epoch[p] /\ w.row.expires > clock

WrongOp ==
    \E f \in net :
    /\ f.kind \in {"RETRY", "RETRY2", "DATA"} /\ f.epoch = epoch[f.peer]
    /\ At(wire[f.peer][f.slot], f.gen) /\ Other(wire[f.peer][f.slot], f.op) /\ counts.wrong < 1
    /\ Count("wrong")
    /\ UNCHANGED <<epoch, wire, table, tgen, admits, net, clock, clientVars>>

\* A PUT retry at the watermark with no live or draining request of its own
\* generation: a matching one replays the retained outcome under the row's
\* epoch before expiry, a changed shape conflicts, and an expired or absent
\* row, or an older or fresh generation, answers UnknownOutcome. A row behind
\* a draining binding answers too.
Answers(f, w) ==
    /\ f.kind \in {"RETRY", "RETRY2"} /\ f.op = "PUT" /\ f.epoch = epoch[f.peer]
    /\ ~(At(w, f.gen) /\ Other(w, f.op)) /\ ~(At(w, f.gen) /\ w.active # 0 /\ ~table[w.active].ended)

Replay ==
    \E f \in net : LET w == wire[f.peer][f.slot] IN
    /\ Answers(f, w) /\ f.kind = "RETRY" /\ At(w, f.gen) /\ Current(w, f.peer) /\ counts.replays < 1
    /\ Send([f EXCEPT !.kind = "RESULT"])
    /\ counts' = [counts EXCEPT !.replays = @ + 1,
                  !.late = @ + (IF w.row.epoch = epoch[f.peer] /\ w.row.expires > clock THEN 0 ELSE 1),
                  !.crossed = @ + (IF w.row.op = f.op THEN 0 ELSE 1)]
    /\ UNCHANGED <<epoch, wire, table, tgen, admits, clock, clientVars>>

Conflict ==
    \E f \in net : LET w == wire[f.peer][f.slot] IN
    /\ Answers(f, w) /\ f.kind = "RETRY2" /\ At(w, f.gen) /\ Current(w, f.peer) /\ counts.conflict < 1
    /\ Count("conflict")
    /\ UNCHANGED <<epoch, wire, table, tgen, admits, net, clock, clientVars>>

UnknownAnswer ==
    \E f \in net : LET w == wire[f.peer][f.slot] IN
    /\ Answers(f, w) /\ ~(At(w, f.gen) /\ Current(w, f.peer))
    /\ [f EXCEPT !.kind = "UNKNOWN"] \notin net
    /\ Send([f EXCEPT !.kind = "UNKNOWN"])
    /\ counts' = [counts EXCEPT !.unknown = @ + 1,
                  !.expired = @ + (IF At(w, f.gen) /\ w.row # NoRow /\ w.row.op = f.op /\ w.row.expires <= clock THEN 1 ELSE 0)]
    /\ UNCHANGED <<epoch, wire, table, tgen, admits, clock, clientVars>>

\* Stale DATA: a frame of an older generation reaches no request and counts
\* as dropped.
Stale ==
    \E f \in net :
    /\ f.kind = "DATA" /\ f.op = "PUT"
    /\ f.gen < wire[f.peer][f.slot].mark /\ f.epoch = epoch[f.peer] /\ counts.dropped < 1
    /\ Count("dropped")
    /\ UNCHANGED <<epoch, wire, table, tgen, admits, net, clock, clientVars>>

\* The clock runs to Linger + 1 and on while any retained row is current, so
\* every row reaches its expiry. Rows come only from admissions, at most
\* Limit - 1 per session, peer and wire slot, which bounds the clock.
ClockBound == Linger + 1 + Linger * Cardinality(Epochs) * Cardinality(Peers) * Cardinality(Slots) * (Limit - 1)

Tick ==
    /\ clock < Linger + 1 \/ \E p \in Peers, s \in Slots : wire[p][s].row.expires > clock
    /\ clock' = clock + 1
    /\ UNCHANGED <<epoch, wire, table, tgen, admits, net, counts, clientVars>>

\* Session replacement retires the peer: watermarks and rows clear, live
\* bindings and their charges stay until each request drains and releases.
Replace(p) ==
    /\ epoch[p] < Cardinality(Epochs)
    /\ epoch' = [epoch EXCEPT ![p] = @ + 1]
    /\ wire' = [wire EXCEPT ![p] = [s \in Slots |-> [mark |-> 0, active |-> wire[p][s].active, row |-> NoRow]]]
    /\ UNCHANGED <<table, tgen, admits, net, counts, clock, clientVars>>

-----------------------------------------------------------------------------
\* The client's PUT. It names the owner's admitted identity, sends retries
\* with its shape or another, and keeps an outcome a matching RESULT or
\* UNKNOWN decides; a RESULT resolves Unknown while the upload is held.
UBegin(p, s, g) ==
    /\ Upload /\ upload.peer = 0 /\ admits[epoch[p]][p][s][g] > 0
    /\ upload' = [upload EXCEPT !.peer = p, !.slot = s, !.gen = g, !.epoch = epoch[p]]
    /\ UNCHANGED <<ownerVars, net, board, leases>>

URetry(k) ==
    /\ upload.peer # 0 /\ upload.outcome \in {"none", "Unknown"} /\ ~upload.abandoned
    /\ LET f == [peer |-> upload.peer, slot |-> upload.slot, gen |-> upload.gen, op |-> "PUT",
                 epoch |-> upload.epoch, kind |-> k] IN
        f \notin net /\ Send(f)
    /\ UNCHANGED <<ownerVars, clientVars>>

\* A reply reaches the upload only under its peer, wire identity, operation
\* and epoch; a RESULT decides Published, an UNKNOWN decides Unknown, and only
\* an Unknown outcome is overwritten, abandoned or not: abandon ends the wait.
\* The upload keeps one identity for the whole run; retirement and a
\* successor on the same wire slot, which admits under a higher generation,
\* are the delayed-RESULT history's.
UReply ==
    \E f \in net :
    /\ f.kind \in {"RESULT", "UNKNOWN"} /\ f.op = "PUT"
    /\ f.peer = upload.peer /\ f.slot = upload.slot /\ f.gen = upload.gen /\ f.epoch = upload.epoch
    /\ upload.outcome \in {"none", "Unknown"}
    /\ LET o == IF f.kind = "RESULT" THEN "Published" ELSE "Unknown" IN
        /\ o # upload.outcome
        /\ upload' = [upload EXCEPT !.outcome = o, !.by = f.gen, !.bye = f.epoch,
                                    !.resolved = @ \/ upload.outcome = "Unknown"]
    /\ UNCHANGED <<ownerVars, net, board, leases>>

\* A delayed or other-peer frame: one stray PUT retry naming any wire identity
\* of the current epoch.
Stray(p, s, g) ==
    /\ Upload
    /\ ~\E f \in net : f.kind = "RETRY" /\ (f.peer # upload.peer \/ f.slot # upload.slot \/ f.gen # upload.gen)
    /\ (p # upload.peer \/ s # upload.slot \/ g # upload.gen)
    /\ Send([peer |-> p, slot |-> s, gen |-> g, op |-> "PUT", epoch |-> epoch[p], kind |-> "RETRY"])
    /\ UNCHANGED <<ownerVars, clientVars>>

UExpire ==
    /\ upload.peer # 0 /\ upload.outcome = "none"
    /\ upload' = [upload EXCEPT !.outcome = "Unknown"]
    /\ UNCHANGED <<ownerVars, net, board, leases>>

UAbandon ==
    /\ upload.outcome = "Unknown" /\ ~upload.abandoned
    /\ upload' = [upload EXCEPT !.abandoned = TRUE]
    /\ UNCHANGED <<ownerVars, net, board, leases>>

-----------------------------------------------------------------------------
\* Client board and GET leases. A request admitted under the current core
\* takes the next wire generation and records the handle's live generation,
\* which advances at close; a GET hands leases; a close turns held leases
\* into orphans and closes the slot; a lease return credits the live request
\* only under its core and generation and otherwise frees one orphan; a
\* successor namespace attaches under the next core after closing every live
\* request.
CAdmit(h) ==
    /\ ~leases[h].open /\ board.next < Limit
    /\ leases' = [leases EXCEPT ![h].core = board.core, ![h].gen = leases[h].live, ![h].handed = 0, ![h].open = TRUE]
    /\ board' = [board EXCEPT !.next = @ + 1]
    /\ UNCHANGED <<ownerVars, net, upload>>

CHand(h) ==
    /\ leases[h].open /\ leases[h].handed < Leases
    /\ leases' = [leases EXCEPT ![h].handed = @ + 1]
    /\ UNCHANGED <<ownerVars, net, upload, board>>


\* The application returns the live request's own lease: the request is
\* credited.
CReturn(h) ==
    /\ leases[h].handed > 0
    /\ leases' = [leases EXCEPT ![h].handed = @ - 1]
    /\ UNCHANGED <<ownerVars, net, upload, board>>

\* A stale lease names the core and generation it was handed under; it
\* credits a live request only when that request's core and generation equal
\* the lease's, and otherwise frees one orphan.
Credits(h) == leases[h].open /\ leases[h].score = board.core /\ leases[h].sgen = leases[h].gen

CReturnStale(h) ==
    /\ leases[h].stale > 0
    /\ leases' = [leases EXCEPT ![h].stale = @ - 1]
    /\ IF Credits(h) THEN UNCHANGED board ELSE board' = [board EXCEPT !.orphans = @ - 1]
    /\ counts' = [counts EXCEPT !.oldlease = @ + (IF leases[h].score < board.core /\ counts.oldlease < 1 THEN 1 ELSE 0)]
    /\ UNCHANGED <<epoch, wire, table, tgen, admits, clock, net, upload>>

CClose(h) ==
    /\ leases[h].open /\ leases[h].stale = 0
    /\ leases' = [leases EXCEPT ![h].open = FALSE, ![h].live = @ + 1, ![h].stale = leases[h].handed, ![h].handed = 0,
                                ![h].score = leases[h].core, ![h].sgen = leases[h].gen]
    /\ board' = [board EXCEPT !.orphans = @ + leases[h].handed]
    /\ UNCHANGED <<ownerVars, net, upload>>

RECURSIVE Sum(_)
Sum(S) == IF S = {} THEN 0 ELSE LET h == CHOOSE x \in S : TRUE IN leases[h].handed + Sum(S \ {h})
Open == {h \in 1..Table : leases[h].open}

\* Destroying the namespace closes every live request; the successor attaches
\* under the next core and its request generations restart.
CAttach ==
    /\ board.core < Cardinality(Cores) /\ \A h \in Open : leases[h].stale = 0
    /\ board' = [board EXCEPT !.core = @ + 1, !.orphans = @ + Sum(Open)]
    /\ leases' = [h \in 1..Table |-> [leases[h] EXCEPT !.open = FALSE, !.live = 1, !.handed = 0,
                                                       !.stale = IF leases[h].open THEN leases[h].handed ELSE @,
                                                       !.score = IF leases[h].open THEN leases[h].core ELSE @,
                                                       !.sgen = IF leases[h].open THEN leases[h].gen ELSE @]]
    /\ UNCHANGED <<ownerVars, net, upload>>

-----------------------------------------------------------------------------
\* The terminal stutter: every binding released, every lease returned, the
\* clock at or past Linger + 1 and every row's expiry, and the upload decided.
Done ==
    /\ Live = {} /\ \A p \in Peers, s \in Slots : wire[p][s].row.expires <= clock
    /\ \A h \in 1..Table : ~leases[h].open /\ leases[h].handed = 0 /\ leases[h].stale = 0
    /\ clock >= Linger + 1 /\ (upload.peer = 0 \/ upload.outcome # "none")
    /\ UNCHANGED vars

Next ==
    \/ \E p \in Peers, s \in Slots, g \in Gens, op \in Ops : Admit(p, s, g, op) \/ Refuse(p, s, g, op)
    \/ \E p \in Peers, s \in Slots : End(p, s) \/ Unbind(p, s)
    \* A handle's generation grows once per release, at most Limit + 1 times at the shipped bounds.
    \/ \E p \in Peers, s \in Slots, h \in 1..Table, tg \in 1..(Limit + 1) : Release(p, s, h, tg)
    \/ WrongOp \/ Replay \/ Conflict \/ UnknownAnswer \/ Stale \/ UReply
    \/ \E p \in Peers : Replace(p)
    \/ \E p \in Peers, s \in Slots, g \in Gens : UBegin(p, s, g)
    \/ URetry("RETRY") \/ (Mismatch /\ URetry("RETRY2")) \/ (StaleData /\ URetry("DATA"))
    \/ \E p \in Peers, s \in Slots, g \in Gens : Stray(p, s, g)
    \/ UExpire \/ UAbandon \/ Tick
    \/ \E h \in 1..Table : CAdmit(h) \/ CHand(h) \/ CReturn(h) \/ CReturnStale(h) \/ CClose(h)
    \/ CAttach
    \/ Done

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
TypeOK ==
    /\ epoch \in [Peers -> Epochs]
    /\ \A p \in Peers, s \in Slots : wire[p][s].mark \in {0} \cup Gens /\ wire[p][s].active \in {0} \cup (1..Table)
    /\ \A h \in 1..Table : table[h] = Free \/ (table[h].peer \in Peers /\ table[h].op \in Ops)
    /\ net \subseteq Frame /\ clock \in 0..ClockBound
    /\ upload.outcome \in {"none", "Published", "Unknown"}
    /\ board.core \in Cores /\ board.orphans \in Nat

\* A live binding's record names exactly its peer and wire slot, and the
\* watermark while the session that admitted it lasts; no two bindings share
\* a handle; every live record is bound once or marked unbound, never both,
\* and a marked record has ended.
ExactBinding ==
    \A p \in Peers, s \in Slots : wire[p][s].active # 0 =>
        LET r == table[wire[p][s].active] IN
            r.peer = p /\ r.slot = s /\ (wire[p][s].mark = 0 \/ r.gen = wire[p][s].mark)
Bound(h) == \E p \in Peers, s \in Slots : wire[p][s].active = h
OneBindingPerHandle ==
    /\ \A p, q \in Peers, s, t \in Slots :
        wire[p][s].active # 0 /\ wire[p][s].active = wire[q][t].active => p = q /\ s = t
    /\ \A h \in Live : (Bound(h) <=> ~table[h].unbound) /\ (table[h].unbound => table[h].ended)

\* Each wire identity admits at most once per session, so a replay never
\* admits a second request.
OneAdmission == \A e \in Epochs, p \in Peers, s \in Slots, g \in Gens : admits[e][p][s][g] <= 1

\* The shared capacity holds across operations, and PUT records, ended ones
\* included, stay within the global and per-peer PUT caps.
Capacity == Cardinality(Live) <= Table /\ \A p \in Peers : Cardinality(Held(p)) <= Share
PutCaps == Cardinality(LivePuts) <= PutCap /\ \A p \in Peers : Cardinality(HeldPuts(p)) <= PeerPutCap

\* GET headroom: PUT records leave at least one table handle and one slot of
\* every peer's share, so a fresh GET finds room whenever no other GET holds
\* it. It holds when PutCap < Table and PeerPutCap < Share, the reserves of
\* one the owner's start requires; a case checks it at those bounds.
Headroom == Cardinality(LivePuts) < Table /\ \A p \in Peers : Cardinality(HeldPuts(p)) < Share

\* A RESULT in flight names an identity the owner admitted under that epoch,
\* and the client's Published needs a RESULT under its exact identity and epoch.
ResultHasAdmission == \A f \in net : f.kind = "RESULT" => admits[f.epoch][f.peer][f.slot][f.gen] = 1
PublishedNeedsResult ==
    upload.outcome = "Published" =>
        /\ upload.by = upload.gen /\ upload.bye = upload.epoch
        /\ [peer |-> upload.peer, slot |-> upload.slot, gen |-> upload.gen, op |-> "PUT",
            epoch |-> upload.epoch, kind |-> "RESULT"] \in net

\* A replay answers only from a row of the frame's epoch and operation that
\* has not expired, and a release frees only the record admitted under the
\* handle's generation it names; with OneBindingPerHandle, only the handle
\* it names, bound or marked.
NoExpiredReplay == counts.late = 0
NoCrossedReplay == counts.crossed = 0
ExactRelease == counts.freed = 0

\* Orphans equal the leases of closed requests still handed out.
RECURSIVE StaleSum(_)
StaleSum(S) == IF S = {} THEN 0 ELSE LET h == CHOOSE x \in S : TRUE IN leases[h].stale + StaleSum(S \ {h})
OrphanConservation == board.orphans = StaleSum(1..Table)

Safety == ExactBinding /\ OneBindingPerHandle /\ OneAdmission /\ Capacity /\ PutCaps /\ ResultHasAdmission
          /\ NoExpiredReplay /\ NoCrossedReplay /\ ExactRelease /\ PublishedNeedsResult /\ OrphanConservation
=============================================================================
