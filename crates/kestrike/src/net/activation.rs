//! One owner's activation envelope: the engine bytes the stack's storage,
//! arena, volume and owner charge at construction, by category, summed with
//! checked arithmetic and checked against the memory the host declares for
//! the owner ([`OwnerDemand::memory_bytes`]). The `native` module's `Wire`
//! and `PacketMempool` charge their retained state to the supplied budget.
//!
//! Activation takes each part's charge before that part is built: the
//! storage's from its validated configuration and index, the arena's from
//! its validated configuration, the volume's from the built storage and
//! arena before attach, and the owner's from the attached volume before
//! start. Each part's budget is its subtotal, so a part the subtotal does
//! not cover refuses with its budget unchanged: the storage, the arena and
//! the volume before they allocate, and the owner after releasing any
//! sub-part it built before the refusing charge.
//!
//! Invariants owned by this module:
//!
//! - Each category's bytes come from the charge function of the part that
//!   charges them, the same function its constructor charges by:
//!   [`StorageCharges::of`] for the storage's root image with its fill
//!   tables and follower rows, its control image (slots, policy, allocator,
//!   claims and the terminal overlap), its index and its startup peak;
//!   [`ValidatedBufferConfig::charge`] for the arena's DMA backing and pool
//!   metadata; [`Volume::attach_charge`](crate::storage::Volume::attach_charge)
//!   for the volume's read and write records, local verification, command
//!   shares and command table; and [`OwnerCharges`] for the owner's keys,
//!   request table, wake rows, timers and replies, sessions, wire slots,
//!   GET scheduler and PUT lanes. A stack built with each part's budget at
//!   its subtotal constructs, and the sum equals what the parts charge.
//! - The storage's startup scratch is a transient peak; the envelope counts
//!   it as resident, so the total bounds the peak of the four parts it sums.
//! - [`Envelope::check`] adds the categories in [`Category`] order and
//!   refuses at the first whose running sum passes the allowance, naming
//!   it; a running sum past `usize` refuses `Overflow` naming the category
//!   that overflowed. An allowance equal to the total admits it, and one
//!   byte less refuses at the last nonzero category.
//! - The owner's start checks keep their own typed refusals: the PUT caps
//!   against the GET reserves, the write commands against the device
//!   queue, and read records and response buffers against the request
//!   slots. The envelope counts the bytes those shapes charge, so the
//!   reserves, the command shares and the `F + 1` receive-write buffers are
//!   checked once, where they are configured, and charged once, here.

use crate::storage::{StorageCharges, ValidatedBufferConfig};

use super::envelope::OwnerDemand;
use super::owner::OwnerCharges;

/// One part of the envelope, in the order [`Envelope::check`] adds them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// The storage's root image: its fill tables and follower rows.
    StorageRoot,
    /// The storage's control image and pool record: slots, policy,
    /// allocator, claims and terminal overlap.
    StorageControl,
    /// The storage's index shards and their summaries.
    StorageIndex,
    /// The storage's startup scratch, charged at its initialization peak.
    StorageStartup,
    /// The buffer arena's DMA backing and pool metadata.
    Arena,
    /// The volume's records, verification arrays and command table.
    Volume,
    /// The owner's key ring and PUT grants.
    OwnerKeys,
    /// The owner's request table and turn scratch, its parked-GET rows
    /// among it.
    OwnerRequestTable,
    /// The owner's session table and replay windows.
    OwnerSessions,
    /// The owner's per-peer wire slots.
    OwnerWireSlots,
    /// The GET scheduler's timers, pacing, reply rings and window
    /// checksums.
    OwnerServe,
    /// The PUT core's lanes, receive rings and digests.
    OwnerPut,
}

impl Category {
    /// Every category, in check order.
    pub const ALL: [Self; 12] = [
        Self::StorageRoot,
        Self::StorageControl,
        Self::StorageIndex,
        Self::StorageStartup,
        Self::Arena,
        Self::Volume,
        Self::OwnerKeys,
        Self::OwnerRequestTable,
        Self::OwnerSessions,
        Self::OwnerWireSlots,
        Self::OwnerServe,
        Self::OwnerPut,
    ];
}

// `Envelope::bytes` indexes by discriminant, so `ALL` lists the variants in
// declaration order.
const _: () = {
    let mut at = 0;
    while at < Category::ALL.len() {
        assert!(Category::ALL[at] as usize == at);
        at += 1;
    }
};

/// Why an envelope does not fit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The running sum through `category` is `needed`, past `allowance`.
    Short {
        category: Category,
        needed: usize,
        allowance: usize,
    },
    /// The running sum overflows `usize` at `category`.
    Overflow { category: Category },
}

/// One owner stack's engine bytes, one entry per [`Category`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Envelope {
    bytes: [usize; Category::ALL.len()],
}

impl Envelope {
    /// The envelope of a stack whose parts charge `storage`, `arena`'s
    /// configuration, `volume` bytes and `owner`.
    pub fn new(
        storage: StorageCharges,
        arena: &ValidatedBufferConfig,
        volume: usize,
        owner: OwnerCharges,
    ) -> Self {
        Self {
            bytes: [
                storage.root,
                storage.control,
                storage.index,
                storage.startup,
                arena.charge(),
                volume,
                owner.keys,
                owner.request_table,
                owner.sessions,
                owner.wire_slots,
                owner.serve,
                owner.put,
            ],
        }
    }

    /// The bytes of `category`.
    pub fn bytes(&self, category: Category) -> usize {
        self.bytes[category as usize]
    }

    /// The sum of every category.
    ///
    /// # Errors
    ///
    /// `Overflow` naming the category whose addition overflowed.
    pub fn total(&self) -> Result<usize, EnvelopeError> {
        self.check(usize::MAX)
    }

    /// The total, when it fits the memory `demand` declares for the owner.
    ///
    /// # Errors
    ///
    /// As [`check`](Self::check) with that allowance.
    pub fn covered_by(&self, demand: &OwnerDemand) -> Result<usize, EnvelopeError> {
        self.check(usize::try_from(demand.memory_bytes).unwrap_or(usize::MAX))
    }

    /// An envelope of exactly these category bytes, in [`Category::ALL`]
    /// order, for tests that plant one.
    #[cfg(test)]
    pub(super) fn of_bytes(bytes: [usize; Category::ALL.len()]) -> Self {
        Self { bytes }
    }

    /// The total, when it fits `allowance`.
    ///
    /// # Errors
    ///
    /// `Short` naming the first category whose running sum passes
    /// `allowance`, or `Overflow` naming the one whose addition overflows.
    pub fn check(&self, allowance: usize) -> Result<usize, EnvelopeError> {
        let mut needed = 0usize;
        for (category, bytes) in Category::ALL.into_iter().zip(self.bytes) {
            needed = needed
                .checked_add(bytes)
                .ok_or(EnvelopeError::Overflow { category })?;
            if needed > allowance {
                return Err(EnvelopeError::Short {
                    category,
                    needed,
                    allowance,
                });
            }
        }
        Ok(needed)
    }
}

#[cfg(kani)]
mod verification {
    use super::{Category, Envelope, EnvelopeError};

    /// Over symbolic category bytes and a symbolic allowance: an allowance
    /// at the total admits it; any smaller allowance refuses `Short` at the
    /// first category whose running sum passes it, carrying that sum and
    /// the allowance; one byte less than the total refuses at the last
    /// nonzero category; and a sum past `usize` refuses `Overflow` at the
    /// category whose addition overflows, whatever the allowance, unless an
    /// earlier running sum already passed it.
    #[kani::proof]
    fn the_check_admits_exactly_the_total_and_names_the_short_category() {
        let envelope = Envelope { bytes: kani::any() };
        let allowance: usize = kani::any();
        let mut running = Some(0usize);
        let mut overflow = None;
        let mut first_past = None;
        for (category, bytes) in Category::ALL.into_iter().zip(envelope.bytes) {
            running = running.and_then(|sum| sum.checked_add(bytes));
            match running {
                None if overflow.is_none() && first_past.is_none() => overflow = Some(category),
                Some(sum) if sum > allowance && first_past.is_none() && overflow.is_none() => {
                    first_past = Some((category, sum));
                }
                _ => {}
            }
        }
        kani::cover!(running.is_none());
        kani::cover!(running.is_some_and(|total| total > 0 && total <= allowance));
        kani::cover!(running.is_some_and(|total| total > allowance));
        let checked = envelope.check(allowance);
        match (overflow, first_past) {
            (Some(category), _) => assert_eq!(checked, Err(EnvelopeError::Overflow { category })),
            (None, Some((category, needed))) => assert_eq!(
                checked,
                Err(EnvelopeError::Short {
                    category,
                    needed,
                    allowance
                })
            ),
            (None, None) => assert_eq!(
                checked,
                running.ok_or(EnvelopeError::Overflow {
                    category: Category::OwnerPut
                })
            ),
        }
        if let Some(total) = running {
            assert_eq!(envelope.check(total), Ok(total));
            if total > 0 {
                let last = Category::ALL
                    .into_iter()
                    .rev()
                    .find(|&category| envelope.bytes(category) > 0);
                match envelope.check(total - 1) {
                    Err(EnvelopeError::Short {
                        category, needed, ..
                    }) => {
                        assert_eq!(Some(category), last);
                        assert_eq!(needed, total);
                    }
                    _ => panic!("one byte short refuses"),
                }
            }
        }
    }
}
