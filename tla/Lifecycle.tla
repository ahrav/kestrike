------------------------------ MODULE Lifecycle ------------------------------
(* One remote PUT from a client through an owner's fill to publication, and  *)
(* one GET of the published record, at small finite bounds.                 *)
(*                                                                           *)
(* The client asks for authority, prepares, waits for READY, supplies and    *)
(* sends fragments within the owner's grant, and reports Published, Failed,  *)
(* NotStarted or Unknown. The owner credits each fragment once, submits      *)
(* each write range once with the header range last, publishes only when    *)
(* every range completed under current authority, and drains an ended fill  *)
(* until its writes end. Device terminals are keyed by serial and range.    *)
(* A GET holds its record until every command ends and delivers at most one *)
(* Done, after which no chunk follows. Source custody, byte geometry and    *)
(* session replay are lower-layer assumptions this model abstracts as the   *)
(* fragment, range and message sets below. Payload ranges                   *)
(* submit in any order once their fragments arrived and the grant ignores   *)
(* receive pressure: both over-approximate production, which consumes the   *)
(* contiguous prefix and grants base + window - held.                       *)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Frags,        \* fragment indices 1..N; {} is a header-only upload
    Ranges,       \* write ranges; range 0 is the header, the rest carry payload
    Cover,        \* the payload range each fragment's bytes land in
    Window,       \* fragments the owner grants beyond its cumulative base
    Chunks,       \* the published record's read commands, in payload order
    Conflicts,    \* the network may deliver a duplicate with different bytes
    Successor,    \* an invalidation may revoke the fill and admit a successor
    Loss,         \* the owner may lose its volume after an accepted submit
    Expiry,       \* the owner's retained terminal row and its reply may expire
    WriteFaults,  \* a device terminal may report a failed write
    Stops,        \* the device may stop with a proof
    Unproven,     \* the device may stop without proof and hold its commands
    Deadlines,    \* client and owner deadlines and client cancel can fire
    Get           \* a GET reads the published record

N == Cardinality(Frags)
Versions == IF Conflicts THEN {1, 2} ELSE {1}
Min(a, b) == IF a < b THEN a ELSE b
Grant(base) == Min(N, base + Window)
Base(credited) == CHOOSE b \in 0..N : /\ \A i \in 1..b : i \in credited
                                      /\ b = N \/ (b + 1) \notin credited
Msg == [t : {"BEGIN", "PREPARE", "CANCEL", "AUTHORITY", "RESULT"}]
       \cup [t : {"DATA"}, i : Frags, v : Versions] \cup [t : {"READY"}, g : 0..N]
       \cup [t : {"ACK"}, b : 0..N, g : 0..N]
       \cup [t : {"ERROR"}, st : {"Cancelled", "TimedOut", "Contended", "ConflictingData",
                                  "DeviceError", "OwnerUnavailable", "Unknown"}]

\* c: the client's upload; o: the owner's fill; ws: each serial's write ranges;
\* dev: the device's outstanding writes; r: the read.
VARIABLES c, net, o, ws, dev, stop, store, r
vars == <<c, net, o, ws, dev, stop, store, r>>

Send(m) == net' = net \cup {m}
Credited == {i \in Frags : o.credit[i] > 0}
Decided == c.outcome # "none"
Retained(u, i) == i > u.base /\ u.outcome = "none" /\ ~u.cancelled
Known == c.outcome \in {"Published", "Failed", "NotStarted"} \/ (c.outcome = "Unknown" /\ c.abandoned)
Writing(s) == {x \in dev : x.s = s}
Payload(w) == {i \in Frags : Cover[i] = w}

Init ==
    /\ c = [phase |-> "begin", handed |-> FALSE, cancelled |-> FALSE, outcome |-> "none",
            abandoned |-> FALSE, closed |-> FALSE, grant |-> 0, base |-> 0, supplied |-> {},
            src |-> [i \in Frags |-> "free"], nic |-> {}]
    /\ net = {}
    /\ o = [stage |-> "idle", credit |-> [i \in Frags |-> 0], data |-> [i \in Frags |-> 0],
            conflict |-> FALSE, revoked |-> FALSE, succ |-> "none", sterm |-> FALSE,
            replay |-> TRUE, lost |-> FALSE]
    /\ ws = [s \in {1, 2} |-> [w \in Ranges |-> "none"]]
    /\ dev = {} /\ stop = "running" /\ store = [s |-> 0, bytes |-> [i \in Frags |-> 0]]
    /\ r = [phase |-> "idle", ver |-> 0, issued |-> 0, done |-> {}, cmds |-> {}, chunks |-> 0,
            dones |-> 0, at_done |-> 0]

-----------------------------------------------------------------------------
\* Client. Retention ends at the cumulative base or a decision; a slot frees
\* once the NIC also returned it.
Release(u) == [u EXCEPT !.src = [i \in Frags |->
    IF u.src[i] = "held" /\ ~Retained(u, i) /\ i \notin u.nic THEN "free" ELSE u.src[i]]]
ClientStep == UNCHANGED <<o, ws, dev, stop, store, r>>

CBegin ==
    /\ c.phase = "begin" /\ ~c.handed /\ ~Decided
    /\ c' = [c EXCEPT !.handed = TRUE] /\ Send([t |-> "BEGIN"]) /\ ClientStep

CAuthority ==
    /\ c.phase = "begin" /\ [t |-> "AUTHORITY"] \in net
    /\ c' = [c EXCEPT !.phase = "authority"] /\ UNCHANGED net /\ ClientStep

CPrepare ==
    /\ c.phase = "authority" /\ ~Decided
    /\ c' = [c EXCEPT !.phase = "prepared"] /\ Send([t |-> "PREPARE"]) /\ ClientStep

CReady ==
    /\ c.phase = "prepared"
    /\ \E m \in net : m.t = "READY" /\ c' = [c EXCEPT !.phase = "ready", !.grant = m.g]
    /\ UNCHANGED net /\ ClientStep

\* Payload supply waits for READY and stays within the grant.
CSupply(i) ==
    /\ c.phase = "ready" /\ ~Decided /\ ~c.cancelled /\ i \notin c.supplied /\ i <= c.grant
    /\ c' = [c EXCEPT !.supplied = @ \cup {i}, !.src[i] = "held"] /\ UNCHANGED net /\ ClientStep

\* A send hands the slot's bytes to the NIC, which reads them until it returns them.
CSend(i) ==
    /\ c.src[i] = "held" /\ i \notin c.nic
    /\ c' = [c EXCEPT !.nic = @ \cup {i}] /\ Send([t |-> "DATA", i |-> i, v |-> 1]) /\ ClientStep

CNicReturn(i) ==
    /\ i \in c.nic
    /\ c' = Release([c EXCEPT !.nic = @ \ {i}]) /\ UNCHANGED net /\ ClientStep

CAck ==
    /\ c.phase \in {"ready", "received"} /\ ~Decided
    /\ \E m \in net :
        /\ m.t = "ACK" /\ (m.b > c.base \/ m.g > c.grant)
        /\ LET base == IF m.b > c.base THEN m.b ELSE c.base IN
           c' = Release([c EXCEPT !.base = base, !.grant = IF m.g > @ THEN m.g ELSE @,
                                  !.phase = IF base = N THEN "received" ELSE @])
    /\ UNCHANGED net /\ ClientStep

\* A reply reaches the upload until close releases it; a retained RESULT or
\* ERROR still decides an Unknown upload the client has not closed.
CResult ==
    /\ c.phase \in {"prepared", "ready", "received"} /\ c.outcome \in {"none", "Unknown"}
    /\ ~c.closed /\ [t |-> "RESULT"] \in net
    /\ c' = Release([c EXCEPT !.outcome = "Published"]) /\ UNCHANGED net /\ ClientStep

CError ==
    /\ c.outcome \in {"none", "Unknown"} /\ ~c.closed
    /\ \E m \in net :
        /\ m.t = "ERROR" /\ (m.st # "Unknown" \/ c.outcome = "none")
        /\ c' = Release([c EXCEPT !.outcome = IF m.st = "Unknown" THEN "Unknown" ELSE "Failed"])
    /\ UNCHANGED net /\ ClientStep

\* An unsent upload ends NotStarted at once; a sent one asks the owner and waits.
CCancel ==
    /\ Deadlines /\ ~Decided /\ ~c.cancelled
    /\ IF c.handed
       THEN c' = Release([c EXCEPT !.cancelled = TRUE]) /\ Send([t |-> "CANCEL"])
       ELSE c' = [c EXCEPT !.outcome = "NotStarted"] /\ UNCHANGED net
    /\ ClientStep

\* The deadline, exhausted resends, a refused send or a session replacement:
\* Unknown once anything reached a send, otherwise NotStarted.
CExpire ==
    /\ Deadlines /\ ~Decided
    /\ c' = Release([c EXCEPT !.outcome = IF c.handed THEN "Unknown" ELSE "NotStarted"])
    /\ UNCHANGED net /\ ClientStep

CAbandon ==
    /\ c.outcome = "Unknown" /\ ~c.abandoned
    /\ c' = [c EXCEPT !.abandoned = TRUE] /\ UNCHANGED net /\ ClientStep

CClose ==
    /\ Known /\ ~c.closed /\ c.nic = {} /\ \A i \in Frags : c.src[i] = "free"
    /\ c' = [c EXCEPT !.closed = TRUE] /\ UNCHANGED net /\ ClientStep

\* A copy whose bytes differ reaches the owner after it credited the client's
\* copy. An authenticated DATA frame comes only from the uploading session,
\* and source custody keeps a fragment's bytes fixed while they are retained,
\* so a differing copy that arrives first is indistinguishable at the owner
\* from the client's own and lies outside what the protocol can detect.
NConflict(i) ==
    /\ Conflicts /\ o.data[i] = 1
    /\ [t |-> "DATA", i |-> i, v |-> 2] \notin net
    /\ Send([t |-> "DATA", i |-> i, v |-> 2]) /\ UNCHANGED <<c, o, ws, dev, stop, store, r>>

-----------------------------------------------------------------------------
\* Owner.
OwnerStep == UNCHANGED <<c, ws, dev, stop, store, r>>

\* Ending sends the error, keeps the terminal row for replay, and drains the
\* fill until its own writes end.
Fail(st) ==
    /\ o' = [o EXCEPT !.stage = IF @ = "ready" THEN "draining" ELSE "ended"]
    /\ Send([t |-> "ERROR", st |-> st])

OBegin ==
    /\ o.stage = "idle" /\ [t |-> "BEGIN"] \in net
    /\ o' = [o EXCEPT !.stage = "authority"] /\ Send([t |-> "AUTHORITY"]) /\ OwnerStep

OPrepare ==
    /\ o.stage = "authority" /\ [t |-> "PREPARE"] \in net
    /\ o' = [o EXCEPT !.stage = "ready"] /\ Send([t |-> "READY", g |-> Grant(0)]) /\ OwnerStep

\* Each fragment credits once; a different duplicate fails the upload. The
\* implementation decides o.data[i] # m.v for a consumed fragment by tagging
\* the original frame's authenticated header, rebuilt with its stored send
\* sequence, over the duplicate's body and comparing that tag with the stored
\* one, so version equality corresponds to tag equality under the collision
\* resistance of HMAC-SHA256 truncated to 128 bits.
OData ==
    /\ o.stage = "ready"
    /\ \E m \in net :
        /\ m.t = "DATA" /\ m.i <= Grant(Base(Credited))
        /\ IF o.credit[m.i] = 0
           THEN /\ o' = [o EXCEPT !.credit[m.i] = 1, !.data[m.i] = m.v]
                /\ LET b == Base(Credited \cup {m.i}) IN Send([t |-> "ACK", b |-> b, g |-> Grant(b)])
           ELSE /\ o.data[m.i] # m.v /\ ~o.conflict /\ o' = [o EXCEPT !.conflict = TRUE]
                /\ UNCHANGED net
    /\ OwnerStep

\* A payload range submits once its fragments arrived; the header range submits last.
Submittable(w) ==
    IF w = 0 THEN Credited = Frags /\ \A x \in Ranges \ {0} : ws[1][x] # "none"
    ELSE Payload(w) # {} /\ Payload(w) \subseteq Credited

OSubmit(w) ==
    /\ o.stage = "ready" /\ ~o.conflict /\ ~o.revoked /\ ~o.lost /\ stop = "running"
    /\ ws[1][w] = "none" /\ Submittable(w)
    /\ ws' = [ws EXCEPT ![1][w] = "submitted"] /\ dev' = dev \cup {[s |-> 1, w |-> w]}
    /\ UNCHANGED <<c, net, o, stop, store, r>>

Complete == \A w \in Ranges : ws[1][w] = "written"

\* Publication needs every range written, current authority and no conflict.
OPublish ==
    /\ o.stage = "ready" /\ Complete /\ ~o.conflict /\ ~o.revoked /\ ~o.lost
    /\ store' = [s |-> 1, bytes |-> o.data] /\ o' = [o EXCEPT !.stage = "ended"]
    /\ Send([t |-> "RESULT"]) /\ UNCHANGED <<c, ws, dev, stop, r>>

OFail ==
    /\ o.stage \in {"authority", "ready"}
    /\ \/ [t |-> "CANCEL"] \in net /\ Fail("Cancelled")
       \/ o.conflict /\ Fail("ConflictingData")
       \/ \E w \in Ranges : ws[1][w] = "failed" /\ Fail("DeviceError")
       \/ o.revoked /\ Fail("Contended")
       \/ o.lost /\ Fail("OwnerUnavailable")
    /\ OwnerStep

\* The owner's clock reaches the upload's deadline.
OTimeout == Deadlines /\ o.stage \in {"authority", "ready"} /\ Fail("TimedOut") /\ OwnerStep

\* The fill aborts only after its own writes ended.
ODrain ==
    /\ o.stage = "draining" /\ Writing(1) = {}
    /\ o' = [o EXCEPT !.stage = "ended"] /\ UNCHANGED net /\ OwnerStep

\* The retained terminal row expires: a retransmission then finds no evidence
\* and the owner answers UnknownOutcome.
OExpire ==
    /\ Expiry /\ o.stage = "ended" /\ o.replay
    /\ o' = [o EXCEPT !.replay = FALSE]
    /\ net' = {m \in net : m.t \notin {"RESULT", "ERROR"}} \cup {[t |-> "ERROR", st |-> "Unknown"]}
    /\ OwnerStep

\* Invalidation revokes the live fill; a successor with a new serial then
\* takes the record and writes its own header.
OInvalidate ==
    /\ Successor /\ o.stage = "ready" /\ ~o.revoked
    /\ o' = [o EXCEPT !.revoked = TRUE] /\ UNCHANGED net /\ OwnerStep

SBegin ==
    /\ o.revoked /\ o.succ = "none" /\ stop = "running"
    /\ o' = [o EXCEPT !.succ = "writing"] /\ ws' = [ws EXCEPT ![2][0] = "submitted"]
    /\ dev' = dev \cup {[s |-> 2, w |-> 0]} /\ UNCHANGED <<c, net, stop, store, r>>

SFail ==
    /\ o.succ = "writing" /\ ws[2][0] = "failed"
    /\ o' = [o EXCEPT !.succ = "failed"] /\ UNCHANGED net /\ OwnerStep

SPublish ==
    /\ o.succ = "writing" /\ ws[2][0] = "written"
    /\ o' = [o EXCEPT !.succ = "published"] /\ store' = [s |-> 2, bytes |-> [i \in Frags |-> 0]]
    /\ UNCHANGED <<c, net, ws, dev, stop, r>>

OLose ==
    /\ Loss /\ ~o.lost /\ Writing(1) # {}
    /\ o' = [o EXCEPT !.lost = TRUE] /\ UNCHANGED net /\ OwnerStep

-----------------------------------------------------------------------------
\* Device. A terminal names the serial and range of its own command.
DTerminal ==
    /\ stop # "unproven"
    /\ \E x \in dev, res \in IF WriteFaults THEN {"written", "failed"} ELSE {"written"} :
        /\ dev' = dev \ {x} /\ ws' = [ws EXCEPT ![x.s][x.w] = res]
        /\ o' = [o EXCEPT !.sterm = @ \/ x.s = 2]
    /\ UNCHANGED <<c, net, stop, store, r>>

\* A proven stop ends every command; an unproven one keeps every command held.
DStop ==
    /\ Stops /\ stop = "running"
    /\ \/ /\ stop' = "proven" /\ dev' = {} /\ r' = [r EXCEPT !.cmds = {}]
          /\ ws' = [s \in {1, 2} |-> [w \in Ranges |->
                       IF [s |-> s, w |-> w] \in dev THEN "failed" ELSE ws[s][w]]]
       \/ Unproven /\ stop' = "unproven" /\ UNCHANGED <<dev, ws, r>>
    /\ UNCHANGED <<c, net, o, store>>

-----------------------------------------------------------------------------
\* GET. A read holds its record from admission until every command ended.
ReadStep == UNCHANGED <<c, net, o, ws, dev, stop, store>>

RAdmit ==
    /\ Get /\ r.phase = "idle" /\ store.s # 0 /\ stop = "running"
    /\ r' = [r EXCEPT !.phase = "reading", !.ver = store.s] /\ ReadStep

\* The current command and one read-ahead command are outstanding at most.
RIssue ==
    /\ r.phase = "reading" /\ r.issued < Chunks /\ Cardinality(r.cmds) < 2 /\ stop = "running"
    /\ r' = [r EXCEPT !.issued = @ + 1, !.cmds = @ \cup {r.issued + 1}] /\ ReadStep

RTerminal ==
    /\ stop # "unproven"
    /\ \E x \in r.cmds : r' = [r EXCEPT !.cmds = @ \ {x}, !.done = @ \cup {x}]
    /\ ReadStep

\* A chunk hands off verified and in payload order.
RChunk ==
    /\ r.phase = "reading" /\ (r.chunks + 1) \in r.done
    /\ r' = [r EXCEPT !.chunks = @ + 1] /\ ReadStep

\* Done ends the read once: after every chunk, or on cancel, deadline or stop
\* with its commands still held.
RDone ==
    /\ r.phase = "reading" /\ (r.chunks = Chunks \/ Deadlines \/ stop # "running")
    /\ r' = [r EXCEPT !.phase = "done", !.dones = @ + 1, !.at_done = r.chunks] /\ ReadStep

-----------------------------------------------------------------------------
\* Named terminal stutters: everything ended, or an unproven stop holds custody
\* (a stutter the owner's own deadline may still interleave with).
Finished ==
    /\ c.closed /\ o.stage \in {"idle", "ended"} /\ dev = {}
    /\ o.succ # "writing" /\ r.phase # "reading" /\ r.cmds = {}
Held == stop = "unproven" /\ (dev # {} \/ r.cmds # {})
Done == (Finished \/ Held) /\ UNCHANGED vars

\* Every action changes state, so a reachable state without one is a deadlock
\* unless a named terminal stutter covers it.
Next ==
    \/ CBegin \/ CAuthority \/ CPrepare \/ CReady \/ CAck \/ CResult \/ CError
    \/ CCancel \/ CExpire \/ CAbandon \/ CClose
    \/ \E i \in Frags : CSupply(i) \/ CSend(i) \/ CNicReturn(i) \/ NConflict(i)
    \/ OBegin \/ OPrepare \/ OData \/ OPublish \/ OFail \/ OTimeout \/ ODrain \/ OExpire
    \/ OInvalidate \/ SBegin \/ SFail \/ SPublish \/ OLose \/ (\E w \in Ranges : OSubmit(w))
    \/ DTerminal \/ DStop
    \/ RAdmit \/ RIssue \/ RTerminal \/ RChunk \/ RDone
    \/ Done

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
\* Safety.
TypeOK ==
    /\ c.phase \in {"begin", "authority", "prepared", "ready", "received"}
    /\ c.handed \in BOOLEAN /\ c.cancelled \in BOOLEAN /\ c.abandoned \in BOOLEAN /\ c.closed \in BOOLEAN
    /\ c.outcome \in {"none", "Published", "Failed", "NotStarted", "Unknown"}
    /\ c.grant \in 0..N /\ c.base \in 0..N /\ c.supplied \subseteq Frags
    /\ c.src \in [Frags -> {"free", "held"}] /\ c.nic \subseteq Frags /\ net \subseteq Msg
    /\ o.stage \in {"idle", "authority", "ready", "draining", "ended"}
    /\ o.credit \in [Frags -> 0..2] /\ o.data \in [Frags -> 0..2]
    /\ o.conflict \in BOOLEAN /\ o.revoked \in BOOLEAN /\ o.sterm \in BOOLEAN
    /\ o.replay \in BOOLEAN /\ o.lost \in BOOLEAN
    /\ o.succ \in {"none", "writing", "published", "failed"}
    /\ ws \in [{1, 2} -> [Ranges -> {"none", "submitted", "written", "failed"}]]
    /\ dev \subseteq [s : {1, 2}, w : Ranges] /\ stop \in {"running", "proven", "unproven"}
    /\ store.s \in 0..2 /\ store.bytes \in [Frags -> 0..2]
    /\ r.phase \in {"idle", "reading", "done"} /\ r.ver \in 0..2 /\ r.issued \in 0..Chunks
    /\ r.cmds \subseteq 1..Chunks /\ r.done \subseteq 1..Chunks /\ r.chunks \in 0..Chunks
    /\ r.dones \in Nat /\ r.at_done \in 0..Chunks

\* Publication by the PUT's serial: every fragment credited exactly once, every
\* range written, no conflicting bytes, and authority current.
PublishedComplete ==
    store.s = 1 => /\ \A i \in Frags : o.credit[i] = 1
                   /\ \A w \in Ranges : ws[1][w] = "written"
                   /\ ~o.conflict /\ ~o.revoked

\* A client Published needs the owner's publication; full receipt is not enough.
PublishedNeedsResult == c.outcome = "Published" => store.s = 1

\* The PUT's serial publishes the bytes the client sent, which are version 1.
PublishedClientBytes == store.s = 1 => \A i \in Frags : store.bytes[i] = 1

\* A known failure means the PUT's serial never published.
FailedMeansUnpublished == c.outcome \in {"Failed", "NotStarted"} => store.s # 1

\* Supply waits for READY.
SupplyAfterReady == c.supplied # {} => c.phase \in {"ready", "received"}

\* A source slot frees only once retention and NIC access both ended, and an
\* ended upload holds no slot it could send again.
SourceCustody == \A i \in c.supplied : c.src[i] = "free" => ~Retained(c, i) /\ i \notin c.nic
NoDataAfterEnd == \A i \in Frags : c.src[i] = "held" => Retained(c, i) \/ i \in c.nic

\* An ended fill holds no outstanding write.
WriteCustody == o.stage = "ended" => Writing(1) = {}

\* A successor publishes only after its own write's terminal.
SuccessorIsolated == o.succ = "published" => o.sterm

\* The header range submits only after every payload range submitted.
HeaderLast == ws[1][0] # "none" => \A w \in Ranges \ {0} : ws[1][w] # "none"

\* A read gets at most one Done and no chunk after it; chunks follow their
\* terminals.
OneDone == r.dones <= 1 /\ (r.phase = "done" => r.dones = 1 /\ r.chunks = r.at_done)
ChunksVerified == \A x \in 1..r.chunks : x \in r.done

Safety ==
    /\ PublishedComplete /\ PublishedNeedsResult /\ PublishedClientBytes
    /\ FailedMeansUnpublished /\ SupplyAfterReady
    /\ SourceCustody /\ NoDataAfterEnd /\ WriteCustody /\ SuccessorIsolated /\ HeaderLast
    /\ OneDone /\ ChunksVerified

\* Close releases the upload, so a closed client's outcome is final.
ClosedIsFinal == [][c.closed => c.outcome' = c.outcome]_vars

-----------------------------------------------------------------------------
\* Final liveness under named assumptions: funded fair client, owner, Tick and
\* Poll work with fair delivery of retained messages (Service); an advancing
\* owner clock (Clock); an eventually supplying client (Supplier); and
\* eventual device terminals (Device), which a configuration without write
\* faults reports as written.
Supplier == \A i \in Frags : WF_vars(CSupply(i))
Service ==
    /\ \A i \in Frags : WF_vars(CSend(i)) /\ WF_vars(CNicReturn(i))
    /\ WF_vars(CBegin) /\ WF_vars(CAuthority) /\ WF_vars(CPrepare) /\ WF_vars(CReady)
    /\ WF_vars(CAck) /\ WF_vars(CResult) /\ WF_vars(CError) /\ WF_vars(CClose)
    /\ WF_vars(OBegin) /\ WF_vars(OPrepare) /\ WF_vars(OData) /\ WF_vars(OPublish)
    /\ WF_vars(OFail) /\ WF_vars(ODrain) /\ WF_vars(SPublish)
    /\ \A w \in Ranges : WF_vars(OSubmit(w))
    /\ WF_vars(RAdmit) /\ WF_vars(RIssue) /\ WF_vars(RChunk) /\ WF_vars(RDone)
Device == WF_vars(DTerminal) /\ WF_vars(RTerminal)
Clock == WF_vars(OTimeout)

FairSpec == Spec /\ Supplier /\ Service /\ Clock /\ Device /\ WF_vars(CAbandon)
StalledSpec == Spec /\ Service /\ Clock /\ Device /\ WF_vars(CAbandon)
NoAbandonSpec == Spec /\ Supplier /\ Service /\ Clock /\ Device

\* The upload reaches an outcome, an ended fill and the read drain, and a
\* decided upload closes; without deadlines, it publishes and learns it.
Decides == <>Decided
Drains == [](o.stage \in {"authority", "ready", "draining"} => <>(o.stage \in {"idle", "ended"}))
ReadDrains == [](r.phase = "reading" => <>(r.phase = "done" /\ r.cmds = {}))
Releases == [](Decided => <>c.closed)
Publishes == <>(c.outcome = "Published")
=============================================================================
