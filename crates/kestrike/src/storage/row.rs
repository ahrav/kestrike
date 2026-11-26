//! Safety invariant of a fill row's terminal word: a follower reports a
//! producer outcome only from a word its producer wrote before the
//! departure the follower observed, so a follower never reports an outcome
//! the producer did not reach.
//!
//! Each fill record has one row beside its state word. The row's terminal
//! word carries the producer's phase in its two lowest bits:
//!
//! - `GRANTED`: the grant's reset. The record is not joinable.
//! - `READY`: the reservation's hold wrote the row's allocation and lengths
//!   and granted the upload, so a follower may join.
//! - `PUBLISHED`: the publication's hold wrote the object's deadline seconds
//!   in the upper half and, when the publication attached the row's retained
//!   right, the `RETAINED` flag.
//! - `FAILED`: the producer recorded a typed [`FillFailure`] in bits 8 to 15
//!   before its departure.
//!
//! Only the record's owner writes the word between the grant and its
//! departure, and only through this module's operations: the grant's
//! [`reset`](FillRow::reset) under the shard gate, the reservation's
//! [`mark_ready`](FillRow::mark_ready) and the publication's
//! [`publish`](FillRow::publish) under the gate, and a failure's
//! [`record_failure`](FillRow::record_failure), with or without the gate,
//! as the owner's last write to the row, sequenced before its `Release`
//! departure. The
//! follower's `Acquire` observation of the departed state word therefore
//! carries every terminal write, the pair the `fill` module's departure and
//! observation already form. A departed record whose word still reads
//! `READY` ended without publishing or recording a failure: an ordinary
//! abort, a revocation, a supersession or an expiry, which a follower
//! reports as missing.

use std::sync::atomic::{AtomicU64, Ordering};

/// One fill record's row in the root mapping, laid out, initialized and
/// charged with its table. Every field is an atomic: the producer writes the
/// terminal outside the shard gate on failure, and a follower lowers the
/// observer count outside the gate; every read of the count, by a join, a
/// publication, a grant's reset or service, holds the gate. The count's
/// reads are `Acquire` and its detach is `Release`. Every
/// other access is `Relaxed`: the gate's holds order the gate-held ones,
/// and the record's departure and observation order the producer's terminal
/// before a follower's read, as the module documentation states.
#[derive(Debug)]
#[repr(C)]
pub(crate) struct FillRow {
    /// The producer's phase and outcome, as this module encodes it.
    terminal: AtomicU64,
    /// Followers joined to the record and not yet detached. Service frees a
    /// departed record only when this reads zero under the gate.
    observers: AtomicU64,
    /// The reserved allocation's record tag, written with `READY`.
    allocation: AtomicU64,
    /// The object's metadata length in the upper half and body length in
    /// the lower, written with `READY`.
    lengths: AtomicU64,
}

const _: () = assert!(size_of::<FillRow>() == 32);

impl FillRow {
    /// A Free record's row: granted, with no follower.
    pub(crate) const fn new() -> Self {
        Self {
            terminal: AtomicU64::new(GRANTED),
            observers: AtomicU64::new(0),
            allocation: AtomicU64::new(0),
            lengths: AtomicU64::new(0),
        }
    }

    /// The grant's reset of a Free record's row, under the shard gate.
    ///
    /// # Errors
    ///
    /// [`Malformed`] when a follower is still joined: service frees a
    /// record only after its last follower detached.
    pub(crate) fn reset(&self) -> Result<(), Malformed> {
        if self.observers() != 0 {
            return Err(Malformed);
        }
        self.terminal.store(GRANTED, Ordering::Relaxed);
        Ok(())
    }

    /// The reservation's upload grant, under the shard gate: the reserved
    /// allocation's record tag and the object's lengths, then `READY`.
    pub(crate) fn mark_ready(&self, allocation: u64, metadata_len: u32, body_len: u32) {
        self.allocation.store(allocation, Ordering::Relaxed);
        self.lengths.store(
            (metadata_len as u64) << 32 | body_len as u64,
            Ordering::Relaxed,
        );
        self.terminal.store(READY, Ordering::Relaxed);
    }

    /// The publication's terminal, under the shard gate before the
    /// owner's departure: the deadline seconds and whether the row retains
    /// a right.
    pub(crate) fn publish(&self, expires_at_s: u32, retained: bool) {
        self.terminal
            .store(published(expires_at_s, retained), Ordering::Relaxed);
    }

    /// A failed producer's terminal, its last write to the row, sequenced
    /// before its `Release` departure, with or without the gate.
    pub(crate) fn record_failure(&self, failure: FillFailure) {
        self.terminal.store(failed(failure), Ordering::Relaxed);
    }

    /// The terminal, which a reader trusts under the gate or after an
    /// `Acquire` observation of the departure.
    ///
    /// # Errors
    ///
    /// [`Malformed`] for a word no writer forms.
    pub(crate) fn terminal(&self) -> Result<Terminal, Malformed> {
        decode(self.terminal.load(Ordering::Relaxed))
    }

    /// The reserved allocation's record tag.
    pub(crate) fn allocation(&self) -> u64 {
        self.allocation.load(Ordering::Relaxed)
    }

    /// The object's metadata and body lengths.
    pub(crate) fn lengths(&self) -> (u32, u32) {
        let word = self.lengths.load(Ordering::Relaxed);
        ((word >> 32) as u32, word as u32)
    }

    /// Followers joined and not yet detached, read with `Acquire`: a read
    /// of a count a detach lowered carries every access that follower made
    /// before it.
    pub(crate) fn observers(&self) -> u64 {
        self.observers.load(Ordering::Acquire)
    }

    /// A follower's join, under the shard gate.
    pub(crate) fn join(&self) {
        self.observers.fetch_add(1, Ordering::Relaxed);
    }

    /// A follower's detach, with or without the gate, returning the count
    /// before it. The `Release` subtraction follows every read the follower
    /// made of the row, and service's `Acquire` read of the lowered count
    /// orders those reads before the record is freed.
    pub(crate) fn detach(&self) -> u64 {
        self.observers.fetch_sub(1, Ordering::Release)
    }

    /// Stores `word` as the terminal, for a test that plants a word no
    /// writer forms.
    #[cfg(test)]
    pub(crate) fn plant_terminal(&self, word: u64) {
        self.terminal.store(word, Ordering::Relaxed);
    }

    /// The record tag of the right a publication retained for its
    /// followers, read by service under the gate as it frees the record.
    ///
    /// # Errors
    ///
    /// [`Malformed`] for a word no writer forms.
    pub(crate) fn retained(&self) -> Result<Option<u64>, Malformed> {
        Ok(match self.terminal()? {
            Terminal::Published { retained: true, .. } => Some(self.allocation()),
            _ => None,
        })
    }
}

/// The phase bits.
const PHASE: u64 = 0b11;
/// The word of a granted, not yet upload-granted record: the grant's reset.
pub(crate) const GRANTED: u64 = 0;
/// The word of an upload-granted record.
pub(crate) const READY: u64 = 1;
const PUBLISHED: u64 = 2;
const FAILED: u64 = 3;
/// A published word whose publication attached the row's retained right.
const RETAINED: u64 = 1 << 2;
const CAUSE_SHIFT: u32 = 8;
const EXPIRY_SHIFT: u32 = 32;

/// Why a producer's fill ended without publishing, as its followers report
/// it. A producer whose fill ends through an ordinary abort, a revocation, a
/// supersession or an expiry records none, and its followers report the key
/// as missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FillFailure {
    /// A write failed or never completed, so the object was never whole.
    DeviceError = 1,
    /// The producer's own deadline ended the fill.
    TimedOut = 2,
    /// Admission closed before the fill published.
    Closed = 3,
    /// The storage or its volume could not serve the fill.
    OwnerUnavailable = 4,
    /// The publication had no clock sample.
    ClockUnavailable = 5,
    /// A gate, a bounded exchange or the budget refused the publication.
    Contended = 6,
    /// The volume's buffers, command table or write budget refused the
    /// upload's writes.
    StoragePressure = 7,
    /// The index had no place for the object.
    ObjectPressure = 8,
}

impl FillFailure {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 8] = [
        Self::DeviceError,
        Self::TimedOut,
        Self::Closed,
        Self::OwnerUnavailable,
        Self::ClockUnavailable,
        Self::Contended,
        Self::StoragePressure,
        Self::ObjectPressure,
    ];

    fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::DeviceError,
            2 => Self::TimedOut,
            3 => Self::Closed,
            4 => Self::OwnerUnavailable,
            5 => Self::ClockUnavailable,
            6 => Self::Contended,
            7 => Self::StoragePressure,
            8 => Self::ObjectPressure,
            _ => return None,
        })
    }
}

/// A decoded terminal word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Terminal {
    Granted,
    Ready,
    Published {
        /// The publication attached the row's retained right.
        retained: bool,
        expires_at_s: u32,
    },
    Failed(FillFailure),
}

/// A terminal word no writer forms: a failure without a known cause, or
/// stray bits beside the phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Malformed;

/// The word of a publication with deadline `expires_at_s`, which attached
/// the row's retained right when `retained`.
pub(crate) const fn published(expires_at_s: u32, retained: bool) -> u64 {
    let flag = if retained { RETAINED } else { 0 };
    (expires_at_s as u64) << EXPIRY_SHIFT | flag | PUBLISHED
}

/// The word of a fill that ended with `failure`.
pub(crate) const fn failed(failure: FillFailure) -> u64 {
    (failure as u64) << CAUSE_SHIFT | FAILED
}

/// Decodes `word`.
///
/// # Errors
///
/// [`Malformed`] for a word no writer forms.
pub(crate) fn decode(word: u64) -> Result<Terminal, Malformed> {
    match word & PHASE {
        GRANTED if word == GRANTED => Ok(Terminal::Granted),
        READY if word == READY => Ok(Terminal::Ready),
        PUBLISHED if word as u32 & !((PHASE | RETAINED) as u32) == 0 => Ok(Terminal::Published {
            retained: word & RETAINED != 0,
            expires_at_s: (word >> EXPIRY_SHIFT) as u32,
        }),
        FAILED if word & !(PHASE | 0xFF << CAUSE_SHIFT) == 0 => {
            FillFailure::from_code((word >> CAUSE_SHIFT) as u8)
                .map(Terminal::Failed)
                .ok_or(Malformed)
        }
        _ => Err(Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_written_word_round_trips_and_stray_bits_are_malformed() {
        assert_eq!(decode(GRANTED), Ok(Terminal::Granted));
        assert_eq!(decode(READY), Ok(Terminal::Ready));
        for (expires_at_s, retained) in [(0, false), (1, true), (u32::MAX, true), (7, false)] {
            assert_eq!(
                decode(published(expires_at_s, retained)),
                Ok(Terminal::Published {
                    retained,
                    expires_at_s,
                })
            );
        }
        for failure in FillFailure::ALL {
            assert_eq!(decode(failed(failure)), Ok(Terminal::Failed(failure)));
        }
        // A failure without a cause, an unknown cause, and stray bits beside
        // each phase.
        assert_eq!(decode(FAILED), Err(Malformed));
        assert_eq!(decode(9 << CAUSE_SHIFT | FAILED), Err(Malformed));
        assert_eq!(
            decode(failed(FillFailure::Closed) | 1 << 20),
            Err(Malformed)
        );
        assert_eq!(decode(failed(FillFailure::Closed) | 1 << 4), Err(Malformed));
        assert_eq!(decode(READY | 1 << 9), Err(Malformed));
        assert_eq!(decode(1 << 9), Err(Malformed));
        assert_eq!(decode(published(3, false) | 1 << 8), Err(Malformed));
    }
}
