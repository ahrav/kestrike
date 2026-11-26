----------------------------- MODULE LifecycleMC -----------------------------
(* Configurations of the lifecycle model and the inverted invariants whose  *)
(* violations witness its named scenarios.                                   *)
EXTENDS Lifecycle

\* Both fragments land in one payload range, or each in its own.
OneRange == [i \in Frags |-> 1]
EachRange == [i \in Frags |-> i]

NoPublication == store.s # 1
NoUnknownPublication == ~(c.outcome = "Unknown" /\ store.s = 1)
NoPublishedAfterCancel == ~(c.outcome = "Published" /\ c.cancelled)
NoFailure == c.outcome # "Failed"
NoFullReceiptWithHeldWrite == ~(N > 0 /\ c.base = N /\ Writing(1) # {} /\ ~Decided)
NoConflict == ~o.conflict
NoLateOldWrite == ~(o.succ # "none" /\ Writing(1) # {})
NoSuccessorPublication == o.succ # "published"
NoCancelWithTwoReads == ~(r.phase = "done" /\ Cardinality(r.cmds) = 2)
NoCompleteRead == ~(r.phase = "done" /\ r.chunks = Chunks)
NoLossAfterSubmit == ~(o.lost /\ Writing(1) # {})
NoReadBesideUpload == ~(r.phase = "reading" /\ o.stage = "ready" /\ o.succ # "none")
NoHeldUnknown == ~(c.outcome = "Unknown" /\ ~c.abandoned /\ ~c.closed /\ o.stage = "ended")
NoHeldStop == ~Held
=============================================================================
