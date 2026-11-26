------------------------------ MODULE Recovery ------------------------------
(* One key's records across a process death and its recovery, at small     *)
(* finite bounds.                                                          *)
(*                                                                         *)
(* Seven components stay separate. The volatile state is the incarnation's *)
(* bindings, its queued writes, its replay position and the extents it     *)
(* reused after recovery; the persistent state is the media, the published *)
(* roots and the issuer's last generation; the old process holds the dead  *)
(* incarnation's outstanding writes; observation holds each recovery-safe  *)
(* exclusion's acknowledgment; exclusion holds the protected exclusions;   *)
(* freshness is the invalidation feed and its floor, the highest observed  *)
(* acknowledged cursor; and protected extents are the units an exclusion   *)
(* keeps from reuse. A ghost map records each generation's label, issue    *)
(* count and invalidation cursor and decides nothing.                      *)
(*                                                                         *)
(* Crash resets the volatile state, moves its queued writes to the old     *)
(* process and keeps every other component and the ghost map unchanged;  *)
(* each old write then lands as one whole unit or not at all. Recovery     *)
(* binds a label only to a durable published root that no exclusion names  *)
(* and no replayed invalidation names, once replay reached the floor, and  *)
(* ends Recovered or Withheld; the recovered incarnation fills on, and     *)
(* issuing past the last generation ends Exhausted and halts the owner.    *)
(* `Replacement` is the hypothesis under which a label's successor root    *)
(* may publish once its predecessors are excluded; `Fence` enables a       *)
(* persistence fence that makes every queued write durable at once.        *)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Labels,       \* the labels one key's records carry, positive numbers
    Units,        \* media extents; each record occupies one
    Gens,         \* record generations the owner may issue, positive numbers
    Cursors,      \* invalidation feed positions, from 0; each invalidation takes the next
    Replacement,  \* hypothesis: a successor root may replace its label's excluded ones
    Fence         \* a persistence fence may make every queued write durable

Rec == [l : Labels, g : Gens]
Write == [r : Rec, u : Units]
Empty == [l |-> 0, g |-> 0]
Terminal == {"Recovered", "Withheld", "Exhausted"}
Acked == {"emitted", "observed", "unobserved"}

\* vol: volatile; per: persistent; old: old process; obs: observation;
\* excl: exclusion; fresh: invalidation feed and floor; prot: protected extents;
\* issued: ghost map of each generation's label, issue count and invalidation
\* cursor; done: the run's phase or terminal.
VARIABLES vol, per, old, obs, excl, fresh, prot, issued, done
vars == <<vol, per, old, obs, excl, fresh, prot, issued, done>>

VolInit == [index |-> [l \in Labels |-> 0], queue |-> {}, replayed |-> 0, reused |-> {}]
Live == done = "running"
\* The running incarnation, or the recovered one once recovery ended.
Filling == done \in {"running", "Recovered", "Withheld"}
Entry == [r : Rec, at : Cursors \ {0}]
Holds(u, r) == per.media[u] = r
Durable(r) == \E u \in Units : Holds(u, r)
Admissible == per.roots \ excl
Outstanding == vol.queue \cup old.q
Bound(l) == [l |-> l, g |-> vol.index[l]]
\* Fill and reuse need the admissible-root proof. The binding conjunct reads
\* the in-memory index, whose every binding names an admissible root, so the
\* root conjunct covers it within the model's bounds. A protected extent and a
\* unit an outstanding write targets stay ineligible; the recovered incarnation
\* reuses only once the old process's writes are proven stopped, and the
\* old-queue conjunct abstracts that proof.
Free(u) == /\ \A r \in Admissible : ~Holds(u, r)
           /\ \A l \in Labels : vol.index[l] # 0 => ~Holds(u, Bound(l))
           /\ u \notin prot
           /\ \A w \in Outstanding : w.u # u
Last == CHOOSE g \in Gens : \A h \in Gens : h <= g
\* Each place a record stands or will land: a unit holding it, or the unit
\* an outstanding write of it targets.
Places(r) == {u \in Units : Holds(u, r)} \cup {w.u : w \in {x \in Outstanding : x.r = r}}

TypeOK ==
    /\ vol \in [index : [Labels -> Gens \cup {0}], queue : SUBSET Write,
                replayed : Cursors, reused : SUBSET Units]
    /\ per \in [media : [Units -> Rec \cup {Empty}], roots : SUBSET Rec, next : Gens \cup {0}]
    /\ old \in [q : SUBSET Write, landed : BOOLEAN]
    /\ obs \in [Rec -> {"none", "requested"} \cup Acked]
    /\ excl \subseteq Rec
    /\ fresh \in [feed : SUBSET Entry, top : Cursors, floor : Cursors]
    /\ prot \subseteq Units
    /\ issued \in [Gens -> [l : Labels \cup {0}, n : 0..2, at : Cursors]]
    /\ done \in {"running", "crashed"} \cup Terminal

Init ==
    /\ vol = VolInit
    /\ per = [media |-> [u \in Units |-> Empty], roots |-> {}, next |-> 0]
    /\ old = [q |-> {}, landed |-> FALSE]
    /\ obs = [r \in Rec |-> "none"]
    /\ excl = {}
    /\ fresh = [feed |-> {}, top |-> 0, floor |-> 0]
    /\ prot = {}
    /\ issued = [g \in Gens |-> [l |-> 0, n |-> 0, at |-> 0]]
    /\ done = "running"

\* The issuer persists its last generation and issues the next to `l`,
\* whose record's write is queued to a free unit.
Fill(l, u) ==
    /\ Filling
    /\ per.next + 1 \in Gens
    /\ Free(u)
    /\ LET g == per.next + 1
       IN /\ per' = [per EXCEPT !.next = g]
          /\ issued' = [issued EXCEPT ![g] = [l |-> l, n |-> IF @.n = 0 THEN 1 ELSE 2, at |-> 0]]
          /\ vol' = [vol EXCEPT !.queue = @ \cup {[r |-> [l |-> l, g |-> g], u |-> u]}]
    /\ UNCHANGED <<old, obs, excl, fresh, prot, done>>

\* Every generation is issued: the owner ends with the typed outcome.
Exhaust ==
    /\ Filling
    /\ per.next = Last
    /\ done' = "Exhausted"
    /\ UNCHANGED <<vol, per, old, obs, excl, fresh, prot, issued>>

\* A queued write lands durably as one whole unit.
Land(w) ==
    /\ Filling
    /\ w \in vol.queue
    /\ per' = [per EXCEPT !.media[w.u] = w.r]
    /\ vol' = [vol EXCEPT !.queue = @ \ {w}]
    /\ UNCHANGED <<old, obs, excl, fresh, prot, issued, done>>

\* The persistence fence makes every queued write of the running
\* incarnation durable at once.
PersistFence ==
    /\ Fence
    /\ Live
    /\ vol.queue # {}
    /\ per' = [per EXCEPT !.media = [u \in Units |->
                 IF \E w \in vol.queue : w.u = u
                 THEN (CHOOSE w \in vol.queue : w.u = u).r ELSE @[u]]]
    /\ vol' = [vol EXCEPT !.queue = {}]
    /\ UNCHANGED <<old, obs, excl, fresh, prot, issued, done>>

\* A durable record whose extent no outstanding write targets publishes its
\* root and becomes visible. A label's first root publishes alone; under
\* the replacement hypothesis a successor publishes once every other root
\* of its label is excluded.
Publish(r) ==
    /\ Live
    /\ r \notin per.roots
    /\ Durable(r)
    /\ \A u \in Units : Holds(u, r) => \A w \in Outstanding : w.u # u
    /\ \A q \in per.roots : q.l = r.l => Replacement /\ q \in excl
    /\ per' = [per EXCEPT !.roots = @ \cup {r}]
    /\ vol' = [vol EXCEPT !.index[r.l] = r.g]
    /\ UNCHANGED <<old, obs, excl, fresh, prot, issued, done>>

\* A client asks for a recovery-safe exclusion of a published root.
RequestExclude(r) ==
    /\ Live
    /\ r \in per.roots
    /\ obs[r] = "none"
    /\ obs' = [obs EXCEPT ![r] = "requested"]
    /\ UNCHANGED <<vol, per, old, excl, fresh, prot, issued, done>>

\* The protected exclusion: the root leaves the admissible set, its extent
\* stays protected and its binding ends.
Exclude(r) ==
    /\ Live
    /\ obs[r] = "requested"
    /\ r \notin excl
    /\ excl' = excl \cup {r}
    /\ prot' = prot \cup {u \in Units : Holds(u, r)}
    /\ vol' = [vol EXCEPT !.index[r.l] = IF @ = r.g THEN 0 ELSE @]
    /\ UNCHANGED <<per, old, obs, fresh, issued, done>>

\* The owner emits the exclusion's acknowledgment once the exclusion holds.
Ack(r) ==
    /\ Live
    /\ obs[r] = "requested"
    /\ r \in excl
    /\ obs' = [obs EXCEPT ![r] = "emitted"]
    /\ UNCHANGED <<vol, per, old, excl, fresh, prot, issued, done>>

\* The living client consumes the acknowledgment.
Observe(r) ==
    /\ Live
    /\ obs[r] = "emitted"
    /\ obs' = [obs EXCEPT ![r] = "observed"]
    /\ UNCHANGED <<vol, per, old, excl, fresh, prot, issued, done>>

\* The acknowledgment is lost or its consumer died before consuming it.
Lose(r) ==
    /\ obs[r] = "emitted"
    /\ obs' = [obs EXCEPT ![r] = "unobserved"]
    /\ UNCHANGED <<vol, per, old, excl, fresh, prot, issued, done>>

\* An observed exclusion releases its extent's protection.
Unprotect(u) ==
    /\ Live
    /\ u \in prot
    /\ \A r \in excl : Holds(u, r) => obs[r] = "observed"
    /\ prot' = prot \ {u}
    /\ UNCHANGED <<vol, per, old, obs, excl, fresh, issued, done>>

\* A live invalidation ends the binding in memory and appends it to the
\* invalidation feed at the next cursor, which the ghost map records against
\* the record's generation; it records no exclusion.
LiveInvalidate(l) ==
    /\ Live
    /\ vol.index[l] # 0
    /\ fresh.top + 1 \in Cursors
    /\ vol' = [vol EXCEPT !.index[l] = 0]
    /\ fresh' = [fresh EXCEPT !.feed = @ \cup {[r |-> Bound(l), at |-> fresh.top + 1]},
                              !.top = @ + 1]
    /\ issued' = [issued EXCEPT ![vol.index[l]].at = fresh.top + 1]
    /\ UNCHANGED <<per, old, obs, excl, prot, done>>

\* The living client observes the acknowledgment of the invalidation at
\* cursor `c`, which raises the floor. A client observes only while the
\* incarnation that sent the acknowledgment lives: a response still in a
\* dead incarnation's link is emission only, so the floor stands fixed at
\* the crash.
FreshAck(c) ==
    /\ Live
    /\ fresh.floor < c /\ c <= fresh.top
    /\ fresh' = [fresh EXCEPT !.floor = c]
    /\ UNCHANGED <<vol, per, old, obs, excl, prot, issued, done>>

\* Process death: the volatile state resets and its queued writes move to
\* the old process.
Crash ==
    /\ Live
    /\ vol' = VolInit
    /\ old' = [old EXCEPT !.q = vol.queue]
    /\ done' = "crashed"
    /\ UNCHANGED <<per, obs, excl, fresh, prot, issued>>

\* An old-process write lands late as one whole unit of its own record.
OldLand(w) ==
    /\ w \in old.q
    /\ per' = [per EXCEPT !.media[w.u] = w.r]
    /\ old' = [q |-> old.q \ {w}, landed |-> TRUE]
    /\ UNCHANGED <<vol, obs, excl, fresh, prot, issued, done>>

\* An old-process write never lands.
OldDrop(w) ==
    /\ w \in old.q
    /\ old' = [old EXCEPT !.q = @ \ {w}]
    /\ UNCHANGED <<vol, per, obs, excl, fresh, prot, issued, done>>

\* Recovery replays the invalidation feed one cursor further.
Replay ==
    /\ done = "crashed"
    /\ vol.replayed + 1 \in Cursors
    /\ vol' = [vol EXCEPT !.replayed = @ + 1]
    /\ UNCHANGED <<per, old, obs, excl, fresh, prot, issued, done>>

\* Recovery binds each label to its one eligible root once replay reached
\* the floor, a root being eligible when it is published, unexcluded and
\* durable and no invalidation the replay covered names it, and ends
\* Recovered when it bound one, else Withheld.
Recover ==
    /\ done = "crashed"
    /\ LET Eligible(l) == {r \in Admissible : /\ r.l = l /\ Durable(r)
                                              /\ \A e \in fresh.feed : e.r = r => e.at > vol.replayed}
           Covered == vol.replayed >= fresh.floor
           index == [l \in Labels |-> IF Covered /\ Cardinality(Eligible(l)) = 1
                                      THEN (CHOOSE r \in Eligible(l) : TRUE).g ELSE 0]
       IN /\ vol' = [vol EXCEPT !.index = index]
          /\ done' = IF \E l \in Labels : index[l] # 0 THEN "Recovered" ELSE "Withheld"
    /\ UNCHANGED <<per, old, obs, excl, fresh, prot, issued>>

\* The recovered incarnation claims a free extent.
Reuse(u) ==
    /\ done \in {"Recovered", "Withheld"}
    /\ u \notin vol.reused
    /\ Free(u)
    /\ vol' = [vol EXCEPT !.reused = @ \cup {u}]
    /\ UNCHANGED <<per, old, obs, excl, fresh, prot, issued, done>>

\* A terminal run with no old work outstanding stutters.
Finished ==
    /\ done \in Terminal
    /\ old.q = {}
    /\ UNCHANGED vars

Next ==
    \/ \E l \in Labels, u \in Units : Fill(l, u)
    \/ Exhaust
    \/ \E w \in Write : Land(w) \/ OldLand(w) \/ OldDrop(w)
    \/ PersistFence
    \/ \E r \in Rec : Publish(r) \/ RequestExclude(r) \/ Exclude(r) \/ Ack(r)
                      \/ Observe(r) \/ Lose(r)
    \/ \E u \in Units : Unprotect(u) \/ Reuse(u)
    \/ \E l \in Labels : LiveInvalidate(l)
    \/ \E c \in Cursors : FreshAck(c)
    \/ Crash \/ Replay \/ Recover \/ Finished

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
\* A successor is visible only after every other root of its label is
\* excluded.
XBeforeV == \A l \in Labels : vol.index[l] # 0 =>
                \A q \in per.roots : (q.l = l /\ q.g # vol.index[l]) => q \in excl

\* An exclusion's acknowledgment is emitted only after the exclusion holds.
AckAfterX == \A r \in Rec : obs[r] \in Acked => r \in excl

\* A binding names a record durable on the media.
AdmissionNeedsEvidence == \A l \in Labels : vol.index[l] # 0 => Durable(Bound(l))

\* A recovered binding needs replay at or past the floor.
RecoveredNeedsReplay ==
    (done \in {"Recovered", "Withheld"} /\ \E l \in Labels : vol.index[l] # 0)
        => vol.replayed >= fresh.floor

\* A recovered binding names no record whose invalidation the replay
\* covered, acknowledged or not: the ghost cursor of every bound record is
\* above the replay position.
ReplayHonored == done \in {"Recovered", "Withheld"} =>
                     \A l \in Labels : vol.index[l] # 0 => issued[vol.index[l]].at \notin 1..vol.replayed

\* A binding names a published root.
AdmitAuthorized == \A l \in Labels : vol.index[l] # 0 => Bound(l) \in per.roots

\* After a crash no binding names a record whose invalidation's
\* acknowledgment was observed: the ghost cursor of every bound record is
\* above the floor, whatever the feed recovery replayed still holds.
ServeFresh == done \in {"crashed", "Recovered", "Withheld"} =>
                  \A l \in Labels : vol.index[l] # 0 => issued[vol.index[l]].at \notin 1..fresh.floor

\* An admissible root keeps its record, and a reused extent holds none.
ReuseTwoProofs ==
    /\ \A r \in Admissible : Durable(r)
    /\ \A u \in vol.reused : \A r \in Admissible : ~Holds(u, r)

\* Every queued, outstanding or published record carries a generation
\* issued to its own label and stands or lands in one place, and no
\* generation is issued twice.
GenerationNeverReissued ==
    /\ \A g \in Gens : issued[g].n <= 1
    /\ \A r \in {w.r : w \in vol.queue \cup old.q} \cup per.roots : issued[r.g].l = r.l
    /\ \A r \in Rec : Cardinality(Places(r)) <= 1

\* Every record on the media, late old-process work included, carries a
\* generation issued to its own label.
LateWorkKeepsIdentity ==
    \A u \in Units : per.media[u] # Empty => issued[per.media[u].g].l = per.media[u].l

\* A reused extent, or one the recovered incarnation's queued write targets,
\* is one no outstanding old write may still land on.
UnknownIneligible == \A u \in vol.reused \cup {w.u : w \in vol.queue} :
                         \A w \in old.q : w.u # u

\* A binding names no excluded record and no record whose exclusion was
\* acknowledged.
ExcludedStayOut == \A l \in Labels : vol.index[l] # 0 =>
                       Bound(l) \notin excl /\ obs[Bound(l)] \notin Acked

\* Every exclusion rests on a recovery-safe request; a live invalidation
\* adds none.
LiveAckIsNotExclusion == \A r \in excl : obs[r] # "none"

\* While the incarnation runs, no binding names an invalidated record: the
\* live invalidation ended the binding it addressed.
LiveBindingFresh == Live => \A l \in Labels : vol.index[l] # 0 => issued[vol.index[l]].at = 0

\* The run ends Exhausted only once every generation is issued.
ExhaustionIsTyped == done = "Exhausted" => \A g \in Gens : issued[g].n # 0

\* An excluded root keeps its record until its acknowledgment is observed:
\* protection holds the extent, and only the observation releases it.
ProtectedUntilObserved == \A r \in excl : obs[r] # "observed" => Durable(r)

Safety ==
    /\ XBeforeV /\ AckAfterX /\ AdmissionNeedsEvidence /\ RecoveredNeedsReplay
    /\ AdmitAuthorized /\ ServeFresh /\ ReuseTwoProofs /\ GenerationNeverReissued
    /\ LateWorkKeepsIdentity /\ UnknownIneligible /\ ExcludedStayOut
    /\ LiveAckIsNotExclusion /\ LiveBindingFresh /\ ExhaustionIsTyped /\ ProtectedUntilObserved
    /\ ReplayHonored
=============================================================================
