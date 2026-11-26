//! Each slot's position word and the words service shares without the pool gate: the durable prefix it judges a retired slot's position against, the retirement-epoch word, the applied feed position and the volume's halt.
//!
//! A position word holds [`NO_RECORD`] for a retired slot that waits on no block, the position of the suffix block a retired resident waits for, or a parked retirement's epoch marker ([`PARKED_EPOCH`]) until the service hold that retires the slot or converts the park ends that registration; a retirement that loses the capture mutex leaves the marker for a later pass. Every marker lies above every position [`reusable`](super::reusable) admits while admission is open, so a slot whose word holds one stays held.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::super::coverage::release;
use super::durable::{LSN_LIMIT, NO_RECORD};

/// The position word a parking thread stores for a retirement registered under epoch 0 or 1 before its park's exchange, which service reads from a slot word carrying `ANCHORED` and `ABANDONED` without `RETIRED`.
pub(crate) const PARKED_EPOCH: [u64; 2] = [u64::MAX - 4, u64::MAX - 5];

// Every marker lies above every position, so `reusable` holds each as it holds a position past the durable prefix.
const _: () = assert!(PARKED_EPOCH[1] >> 32 > LSN_LIMIT);

/// The epoch a parked position word carries.
pub(crate) fn epoch_of(position: u64) -> Option<u64> {
    PARKED_EPOCH
        .iter()
        .position(|&mark| mark == position)
        .map(|epoch| epoch as u64)
}

/// The words readable without the gate; they start all zero.
#[derive(Debug, Default)]
pub(crate) struct JournalWords {
    /// The durable prefix, an exclusive LSN frontier that [`reusable`](super::reusable) judges a retired slot's position against: on an open volume the tenure's suffix blocks from its start up to `prefix` are persisted, and it certifies no predecessor LSN below that start. The volume's tick is its one writer and stores it with release; a service call that walks loads it with acquire once, which orders the call's returns after every write before a release store the load reads. The word starts at zero, and `reusable` admits a [`NO_RECORD`] position with no right left at any prefix.
    pub(crate) prefix: AtomicU64,
    /// The retirement-epoch word; see [`epochs`](super::super::coverage).
    pub(crate) epochs: AtomicU64,
    /// The highest feed position a caller advanced coverage to, `C_applied`: raised by `fetch_max` with release.
    pub(crate) applied: AtomicU64,
    /// Set once the open volume's metadata halts; service then counts no retired slot as awaiting.
    pub(crate) halted: AtomicBool,
}

/// A pool-gate holder's view of every slot's position word and the shared words.
pub(crate) struct JournalHold<'a> {
    pub(crate) positions: &'a [AtomicU64],
    pub(crate) words: &'a JournalWords,
}

impl JournalHold<'_> {
    /// Records the retirement of `slot` in the hold that retires it: its position word becomes `held`, the position of a suffix block the slot waits for, or [`NO_RECORD`], and a retirement `counted` under an epoch ends that registration in this hold. It ends a registration only through `counted` and overwrites the word unread, so a caller retiring a slot whose word holds a [`PARKED_EPOCH`] marker passes that marker's epoch.
    #[inline]
    pub(crate) fn retire(&mut self, slot: usize, held: Option<u64>, counted: Option<u64>) {
        if let Some(epoch) = counted {
            release(&self.words.epochs, epoch);
        }
        self.positions[slot].store(held.unwrap_or(NO_RECORD), Ordering::Relaxed);
    }

    /// Ends the coverage registration a parked retirement's position word carries, once, leaving [`NO_RECORD`].
    pub(crate) fn end_parked(&mut self, slot: usize) {
        let marked = self.position(slot);
        if let Some(epoch) = epoch_of(marked) {
            release(&self.words.epochs, epoch);
            self.positions[slot].store(NO_RECORD, Ordering::Relaxed);
        }
    }

    /// The position word of `slot`.
    pub(crate) fn position(&self, slot: usize) -> u64 {
        self.positions[slot].load(Ordering::Relaxed)
    }

    /// `release` clears `slot`'s position word to [`NO_RECORD`] as its extents return. Service ends a parked coverage registration through `end_parked` or `retire` before calling `release`.
    pub(crate) fn release(&mut self, slot: usize) {
        self.positions[slot].store(NO_RECORD, Ordering::Relaxed);
    }
}
