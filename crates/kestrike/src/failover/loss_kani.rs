//! Kani proof of the loss decision [`decide`](super::loss::decide) and of the replacement receipt's successor rule,
//! [`Receipt::succeeds`](super::loss::Receipt::succeeds), which the store client checks before every replacement of an
//! existing receipt ([`Client::replace`] and [`Client::replace_all`] return `Successor` before any request). A receipt
//! create has no predecessor; the client checks its admission, its namespace and its encoding.
//!
//! [`Client::replace`]: crate::storage::store::Client::replace
//! [`Client::replace_all`]: crate::storage::store::Client::replace_all
//!
//!
//! - HOST-LOSS-KEEPS-VOLUME and LOSS-NEEDS-EVIDENCE: `decide` provisions only for `Lost` evidence about the shard
//!   record's own active volume while no other volume of the AZ is impaired or lost, and every other evidence
//!   retains the volume.
//! - CORRELATED-HOLD: a loss beside one or more impaired or lost volumes holds, and a loss at a generation of
//!   `2^32 - 2` or above holds with no replacement, since no session activates the next one.
//! - Receipt progression: a receipt keeps its namespace and shard and never lowers its generation; within one
//!   generation it keeps its layout, never lowers its attempt and never clears its release mark; within one attempt
//!   it never moves its phase backward and keeps a recorded volume. A higher attempt of the same generation may open
//!   without the previous attempt's volume and later record another.
//! - Authorized hold release: within one generation the hold clears exactly in the write that first marks the
//!   receipt released.
//!
//! Bounds: both functions are loop-free, and the harness's only loops run a constant count: the volume name check
//! builds its 16-byte lane word in 16 iterations, and the shard record generator fills `MAX_CHAIN` suffixes. Each
//! proof covers one call at Kani's default unwinding. The shard record
//! is any value of every field (`super::symbolic_kani`), the evidence names the active volume or another with any
//! health, `others` is any `usize`, and each receipt's namespace, shard, generation, attempt, layout, phase and flags
//! take every value their types admit, receipts the decoder refuses included. Volume names enter both functions only
//! through equality and are drawn from three distinct names. Two premises stay outside the proof: `others` is the
//! caller's count of the other impaired or lost volumes of the AZ, and the release mark is written only by
//! `Reconciler::release_hold`, whose `OperatorRelease` argument only test builds construct.

#[cfg(kani)]
mod verification {
    use super::super::loss::{Decision, Health, Phase, Receipt, Request, decide};
    use super::super::records::{Layout, Record, SuccessorRule};
    use super::super::symbolic_kani::values::{generation, namespace, shard, shard_record, volume};
    use crate::net::ownership::ShardGeneration;

    fn health() -> Health {
        let health = match kani::any::<u8>() % 3 {
            0 => Health::Available,
            1 => Health::Impaired,
            _ => Health::Lost,
        };
        // A new variant fails to compile here; the selector above then needs an arm for it.
        match health {
            Health::Available | Health::Impaired | Health::Lost => health,
        }
    }

    /// Over one call with any shard record, any evidence and any count of other impaired or lost volumes: `decide`
    /// returns `Provision` of the next generation exactly for `Lost` evidence about the active volume with no other
    /// volume impaired or lost and a next generation below `2^32 - 1`, `Hold` with that replacement beside another
    /// impaired or lost volume, `Hold(None)` for a loss at the last generation, and `Retain` for every other
    /// evidence. Bounds: one loop-free call of `decide` at the default unwinding.
    #[kani::proof]
    fn a_replacement_follows_only_the_active_volume_s_own_loss_and_holds_beside_another() {
        let record = shard_record();
        let evidence = (if kani::any() { record.active } else { volume() }, health());
        let others: usize = kani::any();
        let decision = decide(&record, evidence, others);
        let own_loss = evidence.0 == record.active && evidence.1 == Health::Lost;
        let next = record.generation.get() + 1;
        let reference = if !own_loss {
            Decision::Retain
        } else if next >= u64::from(u32::MAX) {
            Decision::Hold(None)
        } else {
            let replacement = Request {
                namespace: record.namespace,
                shard: record.shard,
                generation: ShardGeneration::new(next).unwrap(),
            };
            if others == 0 {
                Decision::Provision(replacement)
            } else {
                Decision::Hold(Some(replacement))
            }
        };
        assert_eq!(decision, reference);
        kani::cover!(decision == Decision::Retain && evidence.1 == Health::Lost);
        kani::cover!(decision == Decision::Retain && evidence.0 == record.active);
        kani::cover!(matches!(decision, Decision::Provision(_)));
        kani::cover!(matches!(decision, Decision::Hold(Some(_))));
        kani::cover!(decision == Decision::Hold(None));
        if let Decision::Provision(request) = decision {
            // "only loss of the active volume, alone in its AZ, provisions a replacement"
            assert!(evidence == (record.active, Health::Lost) && others == 0);
            assert_eq!(request.generation.get(), record.generation.get() + 1);
            assert!(request.generation.get() < u64::from(u32::MAX));
        }
    }

    fn receipt() -> Receipt {
        let phase = match kani::any::<u8>() % 3 {
            0 => Phase::Open,
            1 => Phase::Issued,
            _ => Phase::Created(volume()),
        };
        Receipt {
            request: Request {
                namespace: namespace(),
                shard: shard(),
                generation: generation(),
            },
            layout: Layout {
                units: kani::any(),
                slots: kani::any(),
                slot_units: kani::any(),
                entries: kani::any(),
            },
            attempt: kani::any(),
            phase,
            held: kani::any(),
            released: kani::any(),
        }
    }

    /// The successor rule of a replacement receipt, restated: the refusal of `next` over `prior`, or `Ok`.
    fn reference_succeeds(next: &Receipt, prior: &Receipt) -> Result<(), SuccessorRule> {
        let (later, earlier) = (&next.request, &prior.request);
        if later.namespace != earlier.namespace || later.shard != earlier.shard {
            return Err(SuccessorRule::Identity);
        }
        if later.generation.get() < earlier.generation.get() {
            return Err(SuccessorRule::State);
        }
        if later.generation.get() > earlier.generation.get() {
            return Ok(());
        }
        if next.layout != prior.layout {
            return Err(SuccessorRule::Layout);
        }
        let phase_kept = match (prior.phase, next.phase) {
            (Phase::Created(made), phase) => phase == Phase::Created(made),
            (Phase::Issued, Phase::Open) => false,
            (Phase::Issued | Phase::Open, _) => true,
        };
        let attempt_kept =
            next.attempt > prior.attempt || (next.attempt == prior.attempt && phase_kept);
        let release_kept = next.released || !prior.released;
        let first_release = next.released && !prior.released;
        let unheld = prior.held && !next.held;
        if attempt_kept && release_kept && unheld == first_release {
            Ok(())
        } else {
            Err(SuccessorRule::State)
        }
    }

    /// Over any two receipts: `succeeds` answers as the reference rule, refusal variant included, and an admitted
    /// successor of the same generation keeps the release mark, clears a hold only in the write that marks the
    /// receipt released, and keeps a recorded volume of its attempt. Bounds: one loop-free call of `succeeds` at the
    /// default unwinding.
    #[kani::proof]
    fn a_receipt_moves_forward_and_drops_its_hold_only_in_its_release() {
        let prior = receipt();
        let next = receipt();
        let admitted = next.succeeds(&prior);
        assert_eq!(admitted, reference_succeeds(&next, &prior));
        let same = next.request == prior.request;
        // The guards of the same-generation rule other than the phase and the hold, held valid so that a refusal
        // cover names the one rule that refuses.
        let same_attempt = same && next.attempt == prior.attempt;
        let release_valid = next.released || !prior.released;
        let hold_valid = (prior.held && !next.held) == (next.released && !prior.released);
        kani::cover!(admitted.is_ok() && same && prior.held && !next.held);
        kani::cover!(admitted.is_ok() && same && prior.held && next.held);
        // A higher attempt opens without the previous attempt's volume, or records another one.
        let raised = admitted.is_ok() && same && next.attempt > prior.attempt;
        kani::cover!(
            raised && matches!(prior.phase, Phase::Created(_)) && next.phase == Phase::Open
        );
        kani::cover!(
            raised
                && matches!((prior.phase, next.phase), (Phase::Created(a), Phase::Created(b)) if a != b)
        );
        kani::cover!(
            admitted.is_ok()
                && same_attempt
                && prior.phase == Phase::Issued
                && matches!(next.phase, Phase::Created(_))
        );
        kani::cover!(admitted.is_ok() && next.request.generation > prior.request.generation);
        kani::cover!(admitted == Err(SuccessorRule::Identity));
        kani::cover!(admitted == Err(SuccessorRule::Layout));
        kani::cover!(
            admitted == Err(SuccessorRule::State)
                && same_attempt
                && next.layout == prior.layout
                && next.phase == prior.phase
                && prior.held
                && !next.held
                && !prior.released
                && !next.released
        );
        kani::cover!(
            admitted.is_ok()
                && same
                && matches!(prior.phase, Phase::Created(_))
                && next.attempt == prior.attempt
        );
        kani::cover!(
            admitted == Err(SuccessorRule::State)
                && same_attempt
                && next.layout == prior.layout
                && release_valid
                && hold_valid
                && next.held == prior.held
                && next.released == prior.released
                && matches!((prior.phase, next.phase), (Phase::Created(a), Phase::Created(b)) if a != b)
        );
        if admitted.is_ok() && same {
            // "a held replacement makes no provider call until an operator releases it": the hold clears only
            // together with the release mark, and the mark stays.
            if prior.held && !next.held {
                assert!(next.released && !prior.released);
            }
            assert!(next.released || !prior.released);
            assert!(next.attempt >= prior.attempt);
            if let Phase::Created(made) = prior.phase
                && next.attempt == prior.attempt
            {
                assert_eq!(next.phase, Phase::Created(made));
            }
        }
    }
}
