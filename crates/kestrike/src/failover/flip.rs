//! Computes the shard record each tenure writer writes, and the state a volume has under the shard record.
//!
//! [`flipped`] maps `(g, V_g, owner, E)` to `(g + 1, V_s, spare host, 0)`, clears the spare and the standby, and sets
//! `ck := none` with no cut and no ancestry, since the suffixes they name are of the displaced volume's journal.
//! The store client writes this computed record by an exact-version compare-and-swap on the read value, which
//! commits at most one flip of a generation (`OneActiveVolumePerShard`). The next generation starts its attempt counter at zero, so an activated
//! epoch value recurs across generations while every session `(g, a)` is distinct: no two attempts activate one
//! `(g, n)` (`NoEpochReuse` over store-derived sessions).
//!
//! [`bumped`] and [`taken_over`] keep `g` and raise `E` by one, the bump keeping the owner and the standby and the
//! takeover naming the standby owner and clearing the standby; [`designated`] names a standby and keeps every other
//! field. So every tenure writer either keeps `(g, E)` and changes only the standby, or raises `(g, E)` in
//! lexicographic order, and one write never returns a shard record's `(g, owner, E)` to an earlier value: the step
//! of `NoEpochReuse`. Each function refuses before the store client makes any request.
//!
//! [`transferred`] returns a record that keeps `g`, raises `E` by one, makes the standby the owner and clears the
//! standby, as the takeover does.
//!
//! [`volume_state`] treats the shard record as the authority on which volume is active. The reconciler writes a
//! volume record's retired state after the flip commits, so a volume record showing active while the shard record
//! names another volume refuses (`RetiredVolumeNeverReturns`, the flip half).

use super::records::{ATTEMPTS_MAX, Ancestry, Host, ShardRecord, VolumeRecord, VolumeState};
use super::retire::Target;
use crate::net::ownership::{Shard, ShardGeneration};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlipRefusal {
    /// The record names no spare distinct from its active volume.
    NoSpare,
    /// `g + 1` is `2^32 - 1` or above, a generation no session activates; the shard admits no further generation.
    GenerationExhausted,
}

/// The record a flip of `read` writes: the next generation, the spare as the active volume, the spare host as the
/// owner, `E = 0`, no spare, no named checkpoint, no cut, no ancestry and no standby. `B`, `C_page` and the namespace carry over
/// from `read`.
///
/// # Errors
///
/// [`FlipRefusal::NoSpare`] before [`FlipRefusal::GenerationExhausted`].
pub fn flipped(read: &ShardRecord) -> Result<ShardRecord, FlipRefusal> {
    let spare = read.spare.filter(|spare| spare.0 != read.active);
    let (active, owner) = spare.ok_or(FlipRefusal::NoSpare)?;
    let generation = ShardGeneration::new(read.generation.get() + 1)
        .filter(|next| next.get() < u64::from(u32::MAX))
        .ok_or(FlipRefusal::GenerationExhausted)?;
    Ok(ShardRecord {
        generation,
        active,
        owner,
        attempts: 0,
        spare: None,
        checkpoint: None,
        cut: 0,
        ancestry: Ancestry::default(),
        standby: None,
        ..*read
    })
}

/// On refusal, [`bumped`], [`taken_over`], [`transferred`] and [`designated`] return `TenureRefusal` before the store
/// client issues a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenureRefusal {
    /// `E` is at [`ATTEMPTS_MAX`] or above, so no attempt follows it at the record's generation; for a transfer, `E`
    /// leaves no room up to [`ATTEMPTS_MAX`] for both the transfer's attempt and the target's restart bump.
    AttemptsExhausted,
    /// The record holds another `(g, owner, E)` than the writer's target, names no standby or another standby than the
    /// takeover's successor or the transfer's target, holds `E = 0`, names the designated standby as owner, or, for a
    /// transfer, is of another shard than the transferring tenure's, names no checkpoint, or names its owner as the
    /// target.
    Target,
}

/// The record a bump of `read` writes: `E` raised by one, the owner and the standby kept, every other field
/// `read`'s.
///
/// # Errors
///
/// [`TenureRefusal::AttemptsExhausted`] when `read`'s `E` is at [`ATTEMPTS_MAX`] or above.
pub fn bumped(read: &ShardRecord) -> Result<ShardRecord, TenureRefusal> {
    consumed(read, read.owner, read.standby)
}

/// The record the takeover by `successor` of `read` at `target` writes: `successor` as owner, `E` raised by one and
/// no standby, every other field `read`'s, so the retained volume keeps `g`, its identity, `ck` and the recovery
/// manifest.
///
/// # Errors
///
/// [`TenureRefusal::Target`] when `read` holds another `(g, owner, E)` than `target`, names no standby or another
/// standby than `successor`, or holds `E = 0`, before [`TenureRefusal::AttemptsExhausted`] when `E` is at
/// [`ATTEMPTS_MAX`] or above.
pub fn taken_over(
    read: &ShardRecord,
    target: Target,
    successor: Host,
) -> Result<ShardRecord, TenureRefusal> {
    if Target::of(read) != target || read.standby != Some(successor) || read.attempts == 0 {
        return Err(TenureRefusal::Target);
    }
    consumed(read, successor, None)
}

/// The planned transfer makes `target` the owner, raises `E` by one, clears the standby and keeps every other field
/// of `read`, including its generation and checkpoint.
///
/// TRANSFER-NAMES-STANDBY: `read` holds the transferring tenure `own` of `shard` with `E > 0`, names `target` as
/// standby and some other host as owner, names a checkpoint, and leaves `E` room for two attempts: the transfer's
/// and the target's own restart bump.
///
/// # Errors
///
/// [`TenureRefusal::Target`] when a check of the tenure, the standby or the checkpoint fails; otherwise
/// [`TenureRefusal::AttemptsExhausted`] when `E + 2` exceeds [`ATTEMPTS_MAX`].
pub fn transferred(
    read: &ShardRecord,
    (shard, own): (Shard, Target),
    target: Host,
) -> Result<ShardRecord, TenureRefusal> {
    if read.shard != shard
        || Target::of(read) != own
        || read.attempts == 0
        || read.standby != Some(target)
        || read.owner == target
        || read.checkpoint.is_none()
    {
        return Err(TenureRefusal::Target);
    }
    if read.attempts > ATTEMPTS_MAX.saturating_sub(2) {
        return Err(TenureRefusal::AttemptsExhausted);
    }
    consumed(read, target, None)
}

/// The record the designation of `standby` over `read` at `target` writes: `standby` as the standby, every other
/// field `read`'s, so the tenure `(g, owner, E)`, `ck` and the recovery manifest stay.
///
/// # Errors
///
/// [`TenureRefusal::Target`] when `read` holds another `(g, owner, E)` than `target`, holds `E = 0` or names
/// `standby` as owner.
pub fn designated(
    read: &ShardRecord,
    target: Target,
    standby: Host,
) -> Result<ShardRecord, TenureRefusal> {
    if Target::of(read) != target || read.attempts == 0 || read.owner == standby {
        return Err(TenureRefusal::Target);
    }
    Ok(ShardRecord {
        standby: Some(standby),
        ..*read
    })
}

/// `read` with `E` raised by one, `owner` as owner and `standby` as standby: the shared record of [`bumped`],
/// [`taken_over`] and [`transferred`].
fn consumed(
    read: &ShardRecord,
    owner: Host,
    standby: Option<Host>,
) -> Result<ShardRecord, TenureRefusal> {
    if read.attempts >= ATTEMPTS_MAX {
        return Err(TenureRefusal::AttemptsExhausted);
    }
    Ok(ShardRecord {
        owner,
        attempts: read.attempts + 1,
        standby,
        ..*read
    })
}

/// A volume record that contradicts the shard record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeMismatch {
    /// The volume record shows active while the shard record names another active volume: the volume is retired.
    ActiveElsewhere,
    /// The shard record names the volume active while its record shows it retired or deleted.
    RetiredNamedActive,
}

/// The state of `volume` under `shard`: active when the shard record names it, otherwise the volume record's state.
///
/// # Errors
///
/// A [`VolumeMismatch`] when the two records contradict each other; a caller refuses every command to the volume.
pub fn volume_state(
    shard: &ShardRecord,
    volume: &VolumeRecord,
) -> Result<VolumeState, VolumeMismatch> {
    let named = shard.active == volume.volume;
    match volume.state {
        VolumeState::Active if !named => Err(VolumeMismatch::ActiveElsewhere),
        VolumeState::Retired | VolumeState::Deleted if named => {
            Err(VolumeMismatch::RetiredNamedActive)
        }
        _ if named => Ok(VolumeState::Active),
        state => Ok(state),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::store::sim::{MemLog, Shared};
    use crate::storage::store::{Client, Key, Refusal, StoreError};
    use crate::storage::store_tests::{client, record, seeded};

    /// Three reconcilers each read the shard record and then flip it, in every interleaving of the reads and flips:
    /// exactly one flip commits and every other refuses on its condition or finds no spare, so the shard has one
    /// active volume. A flip without a spare, with a spare equal to the active volume,
    /// or at `g = 2^32 - 2` or `2^32 - 1`, whose next generation no session activates, refuses before any write, and a
    /// flip at `g = 2^32 - 3` reaches `2^32 - 2`.
    #[test]
    fn concurrent_flips_one_winner() {
        let events = [0, 0, 1, 1, 2, 2];
        let mut orders = Vec::new();
        permutations(&events, &mut Vec::new(), &mut [false; 6], &mut orders);
        for order in &orders {
            let store = seeded();
            let mut clients: Vec<Client<Shared, MemLog>> = (0..3).map(|_| client(&store)).collect();
            let mut reads = [None, None, None];
            let mut wins = Vec::new();
            for &who in order {
                match reads[who].take() {
                    None => {
                        reads[who] = Some(
                            clients[who]
                                .read::<ShardRecord>(Key::Shard(record().shard))
                                .unwrap(),
                        )
                    }
                    Some(read) => match clients[who].flip(&read) {
                        Ok(_) => wins.push(read.value().generation),
                        Err(
                            StoreError::Refused(Refusal::Condition)
                            | StoreError::Flip(FlipRefusal::NoSpare),
                        ) => {}
                        Err(error) => panic!("{order:?}: {error:?}"),
                    },
                }
            }
            assert_eq!(
                wins.len(),
                1,
                "{order:?}: a flip leaves no spare to flip to again"
            );
        }
        assert_eq!(
            flipped(&ShardRecord {
                spare: None,
                ..record()
            }),
            Err(FlipRefusal::NoSpare)
        );
        let at = |g: u32| ShardRecord {
            generation: ShardGeneration::new(u64::from(g)).unwrap(),
            ..record()
        };
        assert_eq!(
            flipped(&at(u32::MAX - 2)).map(|next| next.generation.get()),
            Ok(u64::from(u32::MAX - 1))
        );
        for last in [at(u32::MAX - 1), at(u32::MAX)] {
            assert_eq!(flipped(&last), Err(FlipRefusal::GenerationExhausted));
        }
        let onto_itself = ShardRecord {
            spare: Some((record().active, record().owner)),
            ..record()
        };
        assert_eq!(flipped(&onto_itself), Err(FlipRefusal::NoSpare));
    }

    /// Each tenure writer refuses exactly on its rule: the bump and the takeover at `E = ATTEMPTS_MAX`, `ATTEMPTS_MAX + 1`
    /// and `u32::MAX`; the takeover for another `(g, owner, E)`, no standby, another standby than the successor or
    /// `E = 0`, each `Target` before `AttemptsExhausted`; the designation for another `(g, owner, E)`, `E = 0` or the
    /// owner as standby. The admitted bump and takeover return the whole record their rules name, and a designation at
    /// `E = ATTEMPTS_MAX` changes only the standby.
    #[test]
    fn each_tenure_writer_refuses_on_its_rule() {
        let (standby, another) = (Host::new(77).unwrap(), Host::new(78).unwrap());
        let read = ShardRecord {
            attempts: 2,
            standby: Some(standby),
            ..record()
        };
        let target = Target::of(&read);
        let other = Target {
            attempts: 3,
            ..target
        };
        let at = |attempts: u32| ShardRecord { attempts, ..read };
        for attempts in [ATTEMPTS_MAX, ATTEMPTS_MAX + 1, u32::MAX] {
            let exhausted = at(attempts);
            assert_eq!(
                bumped(&exhausted),
                Err(TenureRefusal::AttemptsExhausted),
                "{attempts}"
            );
            assert_eq!(
                taken_over(&exhausted, Target::of(&exhausted), standby),
                Err(TenureRefusal::AttemptsExhausted),
                "{attempts}"
            );
        }
        assert_eq!(
            bumped(&read),
            Ok(ShardRecord {
                attempts: 3,
                ..read
            })
        );
        let unnamed = ShardRecord {
            standby: None,
            ..read
        };
        let last = at(ATTEMPTS_MAX);
        let unnamed_last = ShardRecord {
            standby: None,
            ..last
        };
        for (moved, target, successor) in [
            (read, other, standby),
            (read, target, another),
            (unnamed, target, standby),
            (at(0), Target::of(&at(0)), standby),
            (last, other, standby),
            (last, Target::of(&last), another),
            (unnamed_last, Target::of(&unnamed_last), standby),
        ] {
            assert_eq!(
                taken_over(&moved, target, successor),
                Err(TenureRefusal::Target),
                "{moved:?} {target:?} {successor:?}"
            );
        }
        assert_eq!(
            taken_over(&read, target, standby),
            Ok(ShardRecord {
                owner: standby,
                attempts: 3,
                standby: None,
                ..read
            })
        );
        for (moved, target, named) in [
            (read, other, standby),
            (at(0), Target::of(&at(0)), standby),
            (read, target, read.owner),
        ] {
            assert_eq!(
                designated(&moved, target, named),
                Err(TenureRefusal::Target),
                "{moved:?} {target:?} {named:?}"
            );
        }
        for designating in [read, last] {
            assert_eq!(
                designated(&designating, Target::of(&designating), another),
                Ok(ShardRecord {
                    standby: Some(another),
                    ..designating
                })
            );
        }
    }

    /// Every distinct ordering of `events` in which each reconciler's first event, its read, precedes its second.
    fn permutations(
        events: &[usize],
        prefix: &mut Vec<usize>,
        used: &mut [bool; 6],
        out: &mut Vec<Vec<usize>>,
    ) {
        if prefix.len() == events.len() {
            out.push(prefix.clone());
            return;
        }
        let mut tried = Vec::new();
        for at in 0..events.len() {
            if used[at] || tried.contains(&events[at]) {
                continue;
            }
            tried.push(events[at]);
            used[at] = true;
            prefix.push(events[at]);
            permutations(events, prefix, used, out);
            prefix.pop();
            used[at] = false;
        }
    }
}
