//! A fill's early claims, all taken under the shard gate at reservation:
//! the index place, named in its fill record's place word, and two lease
//! credits held by the fill's owner, the publisher's and the terminal read
//! right's its followers rely on.
//!
//! The place is one pending pair on the key's chain: the chain's first free
//! pair, found by a walk over its buckets' control words, or the first pair
//! of an overflow bucket popped from the shard's free stack and linked to
//! the chain's tail inside one sequence bracket.
//! Taking it also claims one additional key against `V + P_index <= N`,
//! and each credit is one `Shared` lease credit. The fill record's place word
//! names the pair and the additional-key claim from the hold that takes
//! them until the hold that spends or refunds them, so both have a fixed
//! record that service and finalization see; the credits belong to the
//! fill's owner, which returns both at its end. A publication hands the
//! publisher's credit to its first lease and the terminal credit to the
//! fill's row when a follower joined, and returns the terminal credit
//! otherwise.
//!
//! Publication spends the claims under its own hold: it activates the
//! pending pair, or, when an incumbent carries the key's fingerprint,
//! replaces the incumbent's pair and refunds the pending one. A refund
//! frees the pending lane and returns the additional-key claim, each once,
//! and clears the place word: a publication refused under its hold on
//! intact tables refunds there, an invalidation that revokes the fill
//! refunds under its own, and the service pass that releases a departed
//! record refunds whatever place word remains. A refunded pair in an
//! overflow bucket can leave that bucket linked and empty; it stays one of
//! the chain's at most `D` links and stays available as a free pair for the
//! chain's later inserts.

use std::sync::atomic::Ordering;

use super::budget::WorkBudget;
use super::lease::{CreditError, reserve_shared_credits, return_shared};
use super::os::Platform;
use super::owner::Storage;
use super::publish::{PublishError, Tables, counted, place, walk_to_free};
use super::shards::{Hold, ShardControl};
use super::writable::FillReserveError;
use crate::index::{BucketView, Busy, CONTROL_MASK, Identity, KeyRoute, PAIRS, would_exhaust};
use crate::storage::AllocationId;

/// The place word's flag: the record holds claims.
const CLAIMED: u64 = 1 << 63;
/// Bits of the pair's position in its bucket.
const PAIR_BITS: u32 = 8;

/// One fill's claimed place: its bucket and pair in the shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Claimed {
    pub(crate) bucket: usize,
    pub(crate) pair: usize,
}

impl Claimed {
    /// The place word naming these claims.
    pub(crate) fn word(self) -> u64 {
        debug_assert!(self.pair < 1 << PAIR_BITS && (self.bucket as u64) < 1 << (63 - PAIR_BITS));
        CLAIMED | (self.bucket as u64) << PAIR_BITS | self.pair as u64
    }

    /// The claims `word` names, `None` for a record that holds none.
    pub(crate) fn of(word: u64) -> Option<Self> {
        (word & CLAIMED != 0).then_some(Self {
            bucket: ((word & !CLAIMED) >> PAIR_BITS) as usize,
            pair: (word & ((1 << PAIR_BITS) - 1)) as usize,
        })
    }
}

/// Claims `route`'s place for `id` and [`FILL_CREDITS`] `Shared` credits
/// against `lease_limit`, under the shard gate the caller holds, charging
/// the credit attempts and the walk to `budget`. The steps run in order:
/// the stable sequence, the additional-key room, the credits, the walk
/// over control and link words to the chain's first free pair or its tail,
/// then the pending pair and the additional-key claim.
///
/// # Errors
///
/// `IndexFull` when the shard is terminal or about to exhaust, `N` is
/// reached, the chain is full to its depth bound or the stack is empty, or
/// a popped bucket's link would spend the sequence's last bracket before
/// the publication's commit;
/// `Corrupt` on a malformed table or an odd sequence; `LeaseLimit`,
/// `Contended` or `BudgetExhausted` for the credit; `BudgetExhausted` for
/// the walk. A refusal of the second credit returns the first, a refusal
/// from the walk or the place returns both first, and every refusal except
/// `Corrupt` leaves the chain, the stack and `reserved` unchanged.
pub(crate) fn claim<P: Platform>(
    storage: &Storage<P>,
    tables: &mut Tables<'_>,
    route: &KeyRoute,
    id: AllocationId,
    lease_limit: usize,
    budget: &mut WorkBudget,
) -> Result<Claimed, FillReserveError> {
    let (shard, control) = (tables.shard, tables.control);
    let (stable, visible, reserved) = counted(shard, control).map_err(reserve_error)?;
    if visible + reserved >= shard.geometry.visible {
        return Err(FillReserveError::IndexFull);
    }
    // The credits first, so a refusal leaves the chain and the stack as
    // they were.
    reserve_fill_credits(storage, lease_limit, budget)?;
    let mut placed = || {
        let end = walk_to_free(shard, &tables.hold, route, budget)?;
        // A pop spends one bracket on the link and the publication's commit
        // spends its own.
        if end.free.is_none() && would_exhaust(stable + 2) {
            return Err(PublishError::IndexFull);
        }
        let (place, popped) = place(shard, &mut tables.hold, control, &end)?;
        if !tables.hold.buckets[place.bucket].reserve_pair(place.pair, route.tag(), id) {
            return Err(PublishError::Corrupt);
        }
        Ok((place, popped))
    };
    let (place, popped) = match placed() {
        Ok(placed) => placed,
        Err(error) => {
            return_fill_credits(storage);
            return Err(reserve_error(error));
        }
    };
    // A popped bucket becomes reachable through the tail's link, a chain
    // change readers see only across a bracket.
    if let Some(popped) = popped {
        let busy = Busy::begin(&control.sequence, stable);
        tables.hold.buckets[popped.tail].link(popped.link);
        busy.commit();
    }
    control.reserved.store(reserved + 1, Ordering::Relaxed);
    Ok(Claimed {
        bucket: place.bucket,
        pair: place.pair,
    })
}

/// The `Shared` credits a reserved fill holds: the publisher's, which its
/// first lease takes, and the terminal read right's, which its row retains
/// for followers once it publishes.
pub(crate) const FILL_CREDITS: usize = 2;

/// Reserves a fill's [`FILL_CREDITS`] `Shared` credits against
/// `lease_limit`, or none.
fn reserve_fill_credits<P: Platform>(
    storage: &Storage<P>,
    lease_limit: usize,
    budget: &mut WorkBudget,
) -> Result<(), FillReserveError> {
    reserve_shared_credits(storage, lease_limit, FILL_CREDITS, budget).map_err(
        |error| match error {
            CreditError::LeaseLimit => FillReserveError::LeaseLimit,
            CreditError::Contended => FillReserveError::Contended,
            CreditError::BudgetExhausted => FillReserveError::BudgetExhausted,
        },
    )
}

/// Returns every one of a fill's credits, at its end or before custody.
#[inline(always)]
pub(crate) fn return_fill_credits<P: Platform>(storage: &Storage<P>) {
    return_shared(storage, FILL_CREDITS);
}

/// Returns `count` of a fill's `Shared` credits.
#[inline(always)]
pub(crate) fn return_credits<P: Platform>(storage: &Storage<P>, count: usize) {
    if count != 0 {
        return_shared(storage, count);
    }
}

/// A claim's refusal from the shard's tables.
fn reserve_error(error: PublishError) -> FillReserveError {
    match error {
        PublishError::BudgetExhausted => FillReserveError::BudgetExhausted,
        PublishError::IndexFull => FillReserveError::IndexFull,
        PublishError::Corrupt => FillReserveError::Corrupt,
        PublishError::NoIndex
        | PublishError::Closed
        | PublishError::Contended
        | PublishError::Present
        | PublishError::AnchorPresent => {
            unreachable!(
                "the sequence, the walk and the place refuse only for budget, room or corruption"
            )
        }
    }
}

/// Whether the table agrees with `claimed`, under the shard gate the
/// caller holds: the pair's position is below the bucket's pair count, the
/// bucket is in the shard, its control word has no reserved bit set, the
/// pair is pending and a claim is counted. A publication, an invalidation
/// and the fill service pass check this before they refund, so the refund
/// cannot fail and a reserved control bit fails closed there as it does on
/// every chain walk.
/// The pending pair's word must name `owner`'s slot and incarnation.
pub(crate) fn check(
    hold: &Hold<'_>,
    control: &ShardControl,
    claimed: Claimed,
    owner: AllocationId,
) -> Option<Identity> {
    if claimed.pair >= PAIRS || control.reserved.load(Ordering::Relaxed) == 0 {
        return None;
    }
    let bucket = hold.buckets.get(claimed.bucket)?;
    if bucket.control() & !CONTROL_MASK != 0 {
        return None;
    }
    let pending = Identity::unpack(bucket.pending_word(claimed.pair)?);
    (pending == Identity::new(pending.tag, owner)).then_some(pending)
}

/// Refunds the place the place word `word` names, under the shard gate
/// the caller holds, and clears the word: the pending pair and the
/// additional-key claim, each once. A word that names no claims changes
/// nothing.
///
/// # Panics
///
/// If the pair is not pending or no claim is counted, which only a
/// malformed table or place word produces; the caller holds the gate, so
/// the panic poisons it.
pub(crate) fn refund(hold: &Hold<'_>, control: &ShardControl, word: &mut u64) {
    let Some(claimed) = Claimed::of(*word) else {
        return;
    };
    let Some(reserved) = control.reserved.load(Ordering::Relaxed).checked_sub(1) else {
        panic!("a fill's claim is not counted");
    };
    let freed = hold
        .buckets
        .get(claimed.bucket)
        .is_some_and(|bucket| bucket.cancel_pair(claimed.pair));
    assert!(freed, "a fill's claimed pair is not pending");
    control.reserved.store(reserved, Ordering::Relaxed);
    *word = 0;
}
