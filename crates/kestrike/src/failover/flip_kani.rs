//! Kani proof of the tenure writers' next-record functions in `flip`, the functions the store client calls:
//! [`flipped`](super::flip::flipped), [`bumped`](super::flip::bumped), [`taken_over`](super::flip::taken_over),
//! [`transferred`](super::flip::transferred) and [`designated`](super::flip::designated).
//!
//! - The step of `NoEpochReuse`: each writer's next record either keeps `(g, E)` and the owner and changes only the
//!   standby, which is the designation, or raises `(g, E)` in lexicographic order, which is every other writer. One
//!   write therefore never returns a shard record's `(g, owner, E)` to an earlier value.
//! - Each writer's record: the bump keeps `g`, the owner and the standby and raises `E` by one; the takeover keeps
//!   `g`, names the successor owner, raises `E` by one and clears the standby; the transfer keeps `g`, names its
//!   target owner, raises `E` by one and clears the standby; the designation names the standby;
//!   the flip raises `g` by one, names the spare and its host active and owner, sets `E = 0` and clears the spare,
//!   the checkpoint, the cut, the ancestry and the standby. Every field a writer does not name is the read record's.
//! - Each refusal arm on exactly its condition: the bump and the takeover refuse `AttemptsExhausted` at
//!   `E >= ATTEMPTS_MAX`, the takeover first refuses `Target` for another target, no standby or another standby than
//!   the successor, or `E = 0`, the transfer refuses `Target` for another shard or tenure, `E = 0`, a standby other
//!   than its target, its target as owner or no checkpoint, then `AttemptsExhausted` when `E + 2` passes
//!   `ATTEMPTS_MAX`, the
//!   designation refuses `Target` for another target, `E = 0` or the owner as standby, and the flip refuses
//!   `NoSpare` before `GenerationExhausted`.
//!
//! Bounds: the functions are loop-free, and every loop of the harness runs a constant count: the record generator
//! fills and the record comparison reads `MAX_CHAIN` suffixes, and the volume name check builds its 16-byte lane word
//! in 16 iterations. The proof covers one call of one writer at Kani's default unwinding. The read record is any value of every field
//! (`failover::symbolic_kani`), records the decoder refuses included, with volume names drawn from three; the target,
//! the successor and the standby are any values. A pass establishes the single write. Induction over the committed
//! writes, the store's rule that at most one exact-version write commits per version, and a session's adoption only
//! from an acknowledged write stay premises.

#[cfg(kani)]
mod verification {
    use super::super::flip::{
        FlipRefusal, TenureRefusal, bumped, designated, flipped, taken_over, transferred,
    };
    use super::super::records::{ATTEMPTS_MAX, Ancestry, Host, MAX_CHAIN, ShardRecord};
    use super::super::retire::Target;
    use super::super::symbolic_kani::values::{host, shard, shard_record, target};
    use crate::net::ownership::{Shard, ShardGeneration};

    /// A tenure writer of the shard record.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Writer {
        Flip,
        Bump,
        Takeover {
            target: Target,
            successor: Host,
        },
        Designation {
            target: Target,
            standby: Host,
        },
        Transfer {
            shard: Shard,
            own: Target,
            target: Host,
        },
    }

    /// Why a writer refused.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Refused {
        Flip(FlipRefusal),
        Tenure(TenureRefusal),
    }

    /// A writer, with its target either the read record's own `(g, owner, E)` or any other, and its host either the
    /// read record's standby or owner or any other.
    fn writer(read: &ShardRecord) -> Writer {
        let target = if kani::any() {
            Target::of(read)
        } else {
            target()
        };
        let named = match kani::any::<u8>() % 3 {
            0 => read.standby.unwrap_or_else(host),
            1 => read.owner,
            _ => host(),
        };
        match kani::any::<u8>() % 5 {
            0 => Writer::Flip,
            1 => Writer::Bump,
            2 => Writer::Takeover {
                target,
                successor: named,
            },
            3 => Writer::Designation {
                target,
                standby: named,
            },
            _ => Writer::Transfer {
                shard: if kani::any() { read.shard } else { shard() },
                own: target,
                target: named,
            },
        }
    }

    /// The record `writer` writes over `read`, through the production next-record function.
    fn written(writer: Writer, read: &ShardRecord) -> Result<ShardRecord, Refused> {
        match writer {
            Writer::Flip => flipped(read).map_err(Refused::Flip),
            Writer::Bump => bumped(read).map_err(Refused::Tenure),
            Writer::Takeover { target, successor } => {
                taken_over(read, target, successor).map_err(Refused::Tenure)
            }
            Writer::Designation { target, standby } => {
                designated(read, target, standby).map_err(Refused::Tenure)
            }
            Writer::Transfer { shard, own, target } => {
                transferred(read, (shard, own), target).map_err(Refused::Tenure)
            }
        }
    }

    /// The refusal the writer's rule names for `read`, or `None` when it writes.
    fn refusal(writer: Writer, read: &ShardRecord) -> Option<Refused> {
        let exhausted = read.attempts >= ATTEMPTS_MAX;
        match writer {
            Writer::Flip => {
                let spare = read.spare.is_some_and(|(spare, _)| spare != read.active);
                if !spare {
                    Some(Refused::Flip(FlipRefusal::NoSpare))
                } else if read.generation.get() + 1 >= u64::from(u32::MAX) {
                    Some(Refused::Flip(FlipRefusal::GenerationExhausted))
                } else {
                    None
                }
            }
            Writer::Bump => exhausted.then_some(Refused::Tenure(TenureRefusal::AttemptsExhausted)),
            Writer::Takeover { target, successor } => {
                let stale = (read.generation, read.owner, read.attempts)
                    != (target.generation, target.owner, target.attempts)
                    || read.standby != Some(successor)
                    || read.attempts == 0;
                if stale {
                    Some(Refused::Tenure(TenureRefusal::Target))
                } else {
                    exhausted.then_some(Refused::Tenure(TenureRefusal::AttemptsExhausted))
                }
            }
            Writer::Designation { target, standby } => {
                let stale = (read.generation, read.owner, read.attempts)
                    != (target.generation, target.owner, target.attempts)
                    || read.attempts == 0
                    || read.owner == standby;
                stale.then_some(Refused::Tenure(TenureRefusal::Target))
            }
            Writer::Transfer { shard, own, target } => {
                let stale = read.shard != shard
                    || (read.generation, read.owner, read.attempts)
                        != (own.generation, own.owner, own.attempts)
                    || read.attempts == 0
                    || read.standby != Some(target)
                    || read.owner == target
                    || read.checkpoint.is_none();
                if stale {
                    Some(Refused::Tenure(TenureRefusal::Target))
                } else {
                    (u64::from(read.attempts) + 2 > u64::from(ATTEMPTS_MAX))
                        .then_some(Refused::Tenure(TenureRefusal::AttemptsExhausted))
                }
            }
        }
    }

    /// The record `writer`'s rule names for `read` when it writes, stated field by field.
    fn expected(writer: Writer, read: &ShardRecord) -> ShardRecord {
        match writer {
            Writer::Flip => {
                let (active, owner) = read.spare.unwrap();
                ShardRecord {
                    generation: ShardGeneration::new(read.generation.get() + 1).unwrap(),
                    active,
                    owner,
                    attempts: 0,
                    spare: None,
                    checkpoint: None,
                    cut: 0,
                    ancestry: Ancestry::default(),
                    standby: None,
                    ..*read
                }
            }
            Writer::Bump => ShardRecord {
                attempts: read.attempts + 1,
                ..*read
            },
            Writer::Takeover { successor, .. } => ShardRecord {
                owner: successor,
                attempts: read.attempts + 1,
                standby: None,
                ..*read
            },
            Writer::Designation { standby, .. } => ShardRecord {
                standby: Some(standby),
                ..*read
            },
            Writer::Transfer { target, .. } => ShardRecord {
                owner: target,
                attempts: read.attempts + 1,
                standby: None,
                ..*read
            },
        }
    }

    /// Over one write of any tenure writer over any read record: the writer refuses exactly on its rule's condition
    /// with its rule's refusal, and a written record is the one its rule names; the designation keeps `(g, owner, E)`
    /// and changes only the standby, and every other writer raises `(g, E)` in lexicographic order. Nineteen covers
    /// witness reachable cases: each writer's write, the flip and the bump from a read with a full ancestry, a
    /// checkpoint, a nonzero cut and a standby, each refusal arm, a takeover by the named successor whose stale target
    /// and exhausted `E` overlap, a flip with no spare at the last generation, and for the transfer its stale refusal,
    /// its refusal at `E = ATTEMPTS_MAX - 1`, where a bump still writes, its stale refusal above
    /// `E = ATTEMPTS_MAX - 2`, which comes before its budget, and its stale refusal of an otherwise eligible record of
    /// another shard, of a record that names no checkpoint, and of a target that is the record's owner. Bounds: one
    /// call of one loop-free writer at the default unwinding.
    #[kani::proof]
    fn every_tenure_writer_keeps_the_tenure_and_names_a_standby_or_raises_g_and_e() {
        let read = shard_record();
        let writer = writer(&read);
        let next = written(writer, &read);
        assert_eq!(next.err(), refusal(writer, &read));
        if let Ok(next) = next {
            assert!(next == expected(writer, &read));
            let before = (read.generation.get(), read.attempts);
            let after = (next.generation.get(), next.attempts);
            match writer {
                Writer::Designation { .. } => {
                    // "a designation keeps the tenure and changes only the standby"
                    assert!(
                        ShardRecord {
                            standby: read.standby,
                            ..next
                        } == read
                    );
                }
                Writer::Flip | Writer::Bump | Writer::Takeover { .. } | Writer::Transfer { .. } => {
                    // "every other writer raises (g, E)"
                    assert!(after > before);
                }
            }
        }
        let takeover = matches!(writer, Writer::Takeover { .. });
        let designation = matches!(writer, Writer::Designation { .. });
        let transfer = matches!(writer, Writer::Transfer { .. });
        let exhausted = Err(Refused::Tenure(TenureRefusal::AttemptsExhausted));
        let stale = Err(Refused::Tenure(TenureRefusal::Target));
        let populated = read.ancestry.as_slice().len() == MAX_CHAIN
            && read.checkpoint.is_some()
            && read.cut != 0
            && read.standby.is_some();
        kani::cover!(next.is_ok() && writer == Writer::Flip && populated);
        kani::cover!(next.is_ok() && writer == Writer::Bump && populated);
        kani::cover!(next.is_ok() && takeover);
        kani::cover!(next.is_ok() && designation);
        kani::cover!(next == Err(Refused::Flip(FlipRefusal::NoSpare)));
        kani::cover!(next == Err(Refused::Flip(FlipRefusal::GenerationExhausted)));
        kani::cover!(next == exhausted && writer == Writer::Bump);
        kani::cover!(next == exhausted && takeover);
        kani::cover!(next == stale && takeover);
        kani::cover!(next == stale && designation);
        kani::cover!(next.is_ok() && transfer);
        kani::cover!(next == stale && transfer);
        kani::cover!(next == exhausted && transfer && read.attempts < ATTEMPTS_MAX);
        // The transfer's Target refusal comes before its budget, and its shard check refuses an otherwise eligible
        // transfer.
        kani::cover!(next == stale && transfer && read.attempts > ATTEMPTS_MAX - 2);
        let shard_alone = match writer {
            Writer::Transfer { shard, own, target } => {
                read.shard != shard
                    && Target::of(&read) == own
                    && read.attempts > 0
                    && read.attempts <= ATTEMPTS_MAX - 2
                    && read.standby == Some(target)
                    && read.owner != target
                    && read.checkpoint.is_some()
            }
            Writer::Flip | Writer::Bump | Writer::Takeover { .. } | Writer::Designation { .. } => {
                false
            }
        };
        kani::cover!(next == stale && shard_alone);
        // An otherwise eligible transfer that names no checkpoint, and one whose target is the record's owner, each
        // refuse on that check alone.
        let (checkpoint_alone, owner_alone) = match writer {
            Writer::Transfer { shard, own, target } => {
                let tenure = read.shard == shard
                    && Target::of(&read) == own
                    && read.attempts > 0
                    && read.attempts <= ATTEMPTS_MAX - 2;
                (
                    tenure
                        && read.standby == Some(target)
                        && read.owner != target
                        && read.checkpoint.is_none(),
                    tenure && read.owner == target && read.checkpoint.is_some(),
                )
            }
            Writer::Flip | Writer::Bump | Writer::Takeover { .. } | Writer::Designation { .. } => {
                (false, false)
            }
        };
        kani::cover!(next == stale && checkpoint_alone);
        kani::cover!(next == stale && owner_alone);
        let overlap = match writer {
            Writer::Takeover { target, successor } => {
                Target::of(&read) != target && read.standby == Some(successor)
            }
            Writer::Flip | Writer::Bump | Writer::Designation { .. } | Writer::Transfer { .. } => {
                false
            }
        };
        kani::cover!(next == stale && overlap && read.attempts >= ATTEMPTS_MAX);
        kani::cover!(
            next == Err(Refused::Flip(FlipRefusal::NoSpare))
                && read.spare.is_none()
                && read.generation.get() + 1 >= u64::from(u32::MAX)
        );
    }
}
