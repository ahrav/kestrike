----------------------------- MODULE IdentityMC -----------------------------
(* Configurations of the identity model and the inverted invariants whose   *)
(* violations witness its named scenarios.                                   *)
EXTENDS Identity

IdNoRefusal == counts.refused = 0
IdNoWrongOperation == counts.wrong = 0
IdNoConflict == counts.conflict = 0
IdNoUnknownAnswer == counts.unknown = 0
IdNoReplay == counts.replays = 0
IdNoExpiredRetry == counts.expired = 0
IdNoResolvedUnknown == ~upload.resolved
IdNoRetainedUnknown == ~(upload.outcome = "Unknown" /\ upload.abandoned)
IdNoOrphan == board.orphans = 0
IdNoOldLeaseReturn == counts.oldlease = 0
IdNoStaleRelease == counts.stalerel = 0
IdNoUnbound == \A h \in Live : ~(table[h].unbound /\ table[h].op = "GET")
IdNoUnboundPut == \A h \in Live : ~(table[h].unbound /\ table[h].op = "PUT")
IdNoReuseBesideUnbound == ~(\E p \in Peers, s \in Slots : wire[p][s].active # 0 /\ \E h \in Held(p) : table[h].unbound /\ table[h].slot = s)
IdNoSharedPressure == counts.pressure = 0
IdNoReplacementDrain == ~(\E p \in Peers : epoch[p] > 1 /\ \E s \in Slots : wire[p][s].active # 0 /\ wire[p][s].mark = 0)
IdNoStaleData == counts.dropped = 0
IdNoCappedPut == counts.capped = 0
IdNoPeerCappedPut == counts.peercapped = 0
IdNoReservedGet ==
    ~\E p \in Peers : /\ Cardinality(HeldPuts(p)) = PeerPutCap /\ Cardinality(Held(p)) = Share
                     /\ Cardinality(LivePuts) = PutCap /\ Cardinality(Live) = Table
=============================================================================
