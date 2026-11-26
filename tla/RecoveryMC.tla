----------------------------- MODULE RecoveryMC -----------------------------
(* The inverted invariants whose violations witness the recovery model's   *)
(* named states: each terminal, and the state each invariant constrains.   *)
EXTENDS Recovery

NoRecovered == done # "Recovered"
NoWithheld == done # "Withheld"
NoExhausted == done # "Exhausted"
NoVisibleSuccessor == ~\E l \in Labels : vol.index[l] # 0 /\
                        \E q \in excl : q.l = l /\ q.g # vol.index[l]
NoObservedExclusion == \A r \in Rec : obs[r] # "observed"
NoLostAcknowledgment == \A r \in Rec : obs[r] # "unobserved"
NoLiveBinding == \A l \in Labels : vol.index[l] = 0
NoRecoveryPastFloor == ~(done = "Recovered" /\ fresh.floor > 0)
NoWithheldBelowFloor == ~(done = "Withheld" /\ vol.replayed < fresh.floor /\ Admissible # {})
NoReuse == vol.reused = {}
NoFullIssue == \E g \in Gens : issued[g].n = 0
NoRecoveredFill == ~(done \in {"Recovered", "Withheld"} /\ vol.queue # {})
NoInvalidationWithheld == ~(done = "Withheld" /\ \E e \in fresh.feed : e.r \in Admissible /\ e.at <= vol.replayed)
NoLateLanding == ~old.landed
NoReuseBesideOldWork == ~(vol.reused # {} /\ old.q # {})
NoExclusionAcrossCrash == ~(done \in {"crashed", "Recovered", "Withheld"} /\ \E r \in excl : Durable(r))
NoLiveInvalidation == ~\E r \in per.roots : /\ r \notin excl /\ done = "running"
                                            /\ vol.index[r.l] = 0
NoReleasedProtection == ~\E u \in Units : u \notin prot /\ \E r \in excl : Holds(u, r) /\ obs[r] = "observed"
NoRecoveredExhaustion == ~(done = "Exhausted" /\ vol.reused # {} /\ vol.queue # {})
NoReplayAboveFloor == ~(done = "Recovered" /\ \E e \in fresh.feed : e.at > fresh.floor /\ e.at <= vol.replayed)
=============================================================================
