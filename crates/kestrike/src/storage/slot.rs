//! One object slot's 32-byte record, two to a cache line.
//!
//! Layout, `repr(C)` at alignment 8, pinned by a `const` assertion and a
//! test: `ident`, the slot's lifetime word (see the `word` module), at 0;
//! `fingerprint` at 8; `locator` at 16; `expires_at_s` at 24; and `prev` at
//! 28. Every field is an atomic, so a reader without the gate and a
//! concurrent writer access the bytes without a data race; which value a
//! reader may rely on is the protocol each field states, and the record's
//! accessors own each field's ordering.
//!
//! - `ident`: incarnation, flags, state and count, as the `word` module
//!   states.
//! - `fingerprint`: the key's 64-bit hash word and the object's identity in
//!   RAM, stored by `bind` in the hold that makes the slot resident, before
//!   the slot is indexed. A lookup and every shard-gate holder's walk match
//!   a candidate by it; expiry and eviction route a resident's removal from
//!   it under the gate. Once the mapping has ended, `retire_anchored`
//!   overwrites it with the retirement era: a `Release` store on the thread
//!   that cleared the mapping, after that thread's release fence behind the
//!   odd or terminal sequence store, and before the release
//!   read-modify-write that sets `ANCHORED`; the anchor's release reads the
//!   era there. A lookup loads the word with `Acquire`, so one that reads an
//!   era synchronizes with that fence and its next sequence load sees the
//!   removal: whether the era equals the probed fingerprint or not, the
//!   lookup yields neither `Missing` nor a hit, since its closing bracket
//!   finds the sequence moved and every earlier exit returns another error. A shard-gate holder's walk reads only visible pairs, whose
//!   mappings have not ended, so it reads the fingerprint `bind` stored. A
//!   slot still `Resident` may carry the era: an invalidation or a
//!   replacement ends the mapping and stamps it before the retirement
//!   reaches the ledger, and a park leaves the state for service. Expiry or eviction that routes such a slot's removal from
//!   the era walks a chain without the pair and ends `Absent`, with no other
//!   effect.
//! - `locator`: the held extent's packed [`ExtentLocator`] from the claim to
//!   the return, or a sequence handle naming the arena block that lists the
//!   object's extents (the `held` module states both forms); it stays fixed
//!   while the object is anchored, so the return receives it without
//!   arithmetic on offsets. A `Free` slot's field holds
//!   the last locator it held, or zero before its first claim; the claim
//!   overwrites it with the reserved extent.
//! - `expires_at_s`: the deadline's whole seconds on the engine's nanosecond
//!   timeline, rounded down, and `u32::MAX` for a deadline past `u32::MAX`
//!   seconds. Lookup, publication and the expiry sweep compare the whole
//!   seconds of their sample against it ([`expired`]), so an object is
//!   never served at or after its deadline, and one whose deadline lies
//!   within `u32::MAX` seconds expires up to one second early.
//! - `prev`: the eviction policy's link one step toward its list's head, or
//!   [`POLICY_NONE`]; read and written only under the gate (see the `policy`
//!   module), and [`POLICY_NONE`] on every slot that is not a member.
//!
//! A record's lengths and chunk checksums live in its header on the device,
//! which a volume read verifies before any payload byte; the ledger takes a
//! held slot's payload length from its extents' units and the slot's tail,
//! the record tail of the object's last extent, every earlier extent of a
//! sequence carrying a full extent's payload (the `tables` module holds the
//! tail table).

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::extent::ExtentLocator;
use super::policy::{
    POLICY_NONE, PolicySlot, clear_policy_bits, move_policy_bits, policy_word, set_policy_bits,
};

/// Nanoseconds per second of the engine's timeline.
const NANOS: u64 = 1_000_000_000;

/// One object slot's record. See the module documentation.
#[repr(C)]
#[derive(Debug)]
pub(crate) struct Record {
    pub(crate) ident: AtomicU64,
    fingerprint: AtomicU64,
    locator: AtomicU64,
    expires_at_s: AtomicU32,
    prev: AtomicU32,
}

const _: () = assert!(
    size_of::<Record>() == 32
        && align_of::<Record>() == 8
        && std::mem::offset_of!(Record, prev) == 28
);

impl Record {
    /// A free slot's record before its first claim: incarnation zero and no
    /// policy link.
    pub(crate) fn free() -> Self {
        Self {
            ident: AtomicU64::new(0),
            fingerprint: AtomicU64::new(0),
            locator: AtomicU64::new(0),
            expires_at_s: AtomicU32::new(0),
            prev: AtomicU32::new(POLICY_NONE),
        }
    }

    /// The key's hash word `bind` stored, or the retirement era once the
    /// mapping has ended. `Acquire`, so a lookup that reads the era
    /// synchronizes with the release fence the stamping thread issued
    /// before clearing the mapping, and with the stamp's own `Release`, and
    /// is ordered after the removal's odd or terminal sequence store; a gate
    /// holder's read is ordered by the gate.
    #[inline(always)]
    pub(crate) fn fingerprint(&self) -> u64 {
        self.fingerprint.load(Ordering::Acquire)
    }

    /// Stores the key's hash word; `bind` calls it under the gate, and the
    /// publication's release install orders it before any reader names the
    /// slot.
    #[inline(always)]
    pub(crate) fn set_fingerprint(&self, fingerprint: u64) {
        self.fingerprint.store(fingerprint, Ordering::Relaxed);
    }

    /// Stores the retirement era over the fingerprint once the mapping has
    /// ended; the caller's next write of the word is the release
    /// read-modify-write that sets `ANCHORED` and publishes the stamp to
    /// service. The thread that cleared the mapping stores it, after the
    /// release fence behind its odd store or, in a terminal shard, the fence
    /// its hold issues before the bare stores, so a lookup whose `Acquire`
    /// load reads the era sees the odd or terminal sequence value or a later
    /// one. In a serving shard `Release` adds the even commit sequenced
    /// before this store to that edge.
    #[inline(always)]
    pub(crate) fn stamp_era(&self, era: u64) {
        self.fingerprint.store(era, Ordering::Release);
    }

    /// The retirement era [`stamp_era`](Self::stamp_era) stored. The caller
    /// loaded the word with acquire and saw `ANCHORED`, which orders the
    /// stamp before this load.
    #[inline(always)]
    pub(crate) fn retire_era(&self) -> u64 {
        self.fingerprint.load(Ordering::Relaxed)
    }

    /// The fingerprint word as a `Relaxed` load, for a caller that forms a
    /// prefetch address from it outside the gate. A stale word or a stamped
    /// era routes the hint to another line. `Relaxed` compiles to a plain
    /// `ldr` on AArch64, where an `Acquire` load's `ldar` waits for the
    /// caller's last gate release to drain.
    #[inline(always)]
    pub(crate) fn fingerprint_hint(&self) -> u64 {
        self.fingerprint.load(Ordering::Relaxed)
    }

    /// The held extent. Meaningful from the claim to the return.
    #[inline(always)]
    pub(crate) fn locator(&self) -> ExtentLocator {
        ExtentLocator::from_bits(self.locator.load(Ordering::Relaxed))
    }

    /// Stores the extent the claim reserved; the gate holder calls it for a
    /// slot no reader can name.
    #[inline(always)]
    pub(crate) fn set_locator(&self, locator: ExtentLocator) {
        self.locator.store(locator.bits(), Ordering::Relaxed);
    }

    #[inline(always)]
    pub(crate) fn expires_at_s(&self) -> u32 {
        self.expires_at_s.load(Ordering::Relaxed)
    }

    /// Stores the deadline `bind` makes resident, in whole seconds.
    #[inline(always)]
    pub(crate) fn set_expires_at_s(&self, seconds: u32) {
        self.expires_at_s.store(seconds, Ordering::Relaxed);
    }
}

/// The policy's gate-held accesses. The lifetime word's read and bit
/// writes run the `policy` module's bodies over the record's std word;
/// `prev` is a `Relaxed` load and store, ordered by the gate the caller
/// holds.
impl PolicySlot for Record {
    #[inline(always)]
    fn word(&self) -> u64 {
        policy_word(&self.ident)
    }

    #[inline(always)]
    fn set_bits(&self, bits: u64) {
        set_policy_bits(&self.ident, bits);
    }

    #[inline(always)]
    fn clear_bits(&self, bits: u64) {
        clear_policy_bits(&self.ident, bits);
    }

    #[inline(always)]
    fn move_bits(&self, from: u64, to: u64) {
        move_policy_bits(&self.ident, from, to);
    }

    #[inline(always)]
    fn prev(&self) -> u32 {
        self.prev.load(Ordering::Relaxed)
    }

    #[inline(always)]
    fn set_prev(&self, prev: u32) {
        self.prev.store(prev, Ordering::Relaxed);
    }
}

/// The whole seconds of a nanosecond `deadline`, rounded down and clamped to
/// `u32::MAX`.
#[inline(always)]
pub(crate) const fn deadline_seconds(deadline: u64) -> u32 {
    let seconds = deadline / NANOS;
    if seconds > u32::MAX as u64 {
        u32::MAX
    } else {
        seconds as u32
    }
}

/// Whether a nanosecond sample `now` has reached `expires_at_s`: its whole
/// seconds are at or past it. `expires_at_s` rounds the deadline down, so a
/// sample below the deadline may already expire, by less than one second,
/// and a sample at or past the deadline always does.
#[inline(always)]
pub(crate) const fn expired(now: u64, expires_at_s: u32) -> bool {
    now >= expires_at_s as u64 * NANOS
}

#[cfg(test)]
mod tests {
    use std::mem::{align_of, offset_of, size_of};

    use super::super::extent::{ExtentLocator, LOCATOR_LEN_LIMIT, LOCATOR_START_LIMIT};
    use super::super::policy::{POLICY_NONE, PolicySlot};
    use super::super::word::{ABANDONED, DETACHED, EVICTED, LINKED, REF, VISITED};
    use super::{Record, deadline_seconds, expired};

    /// Two records share a cache line; every field sits at its pinned
    /// offset, and a fresh record's `prev` is the policy's end marker.
    #[test]
    fn the_record_is_32_bytes_at_pinned_offsets() {
        assert_eq!(size_of::<Record>(), 32);
        assert_eq!(align_of::<Record>(), 8);
        assert_eq!(offset_of!(Record, ident), 0);
        assert_eq!(offset_of!(Record, fingerprint), 8);
        assert_eq!(offset_of!(Record, locator), 16);
        assert_eq!(offset_of!(Record, expires_at_s), 24);
        assert_eq!(offset_of!(Record, prev), 28);
        assert_eq!(Record::free().prev(), POLICY_NONE);
        assert_eq!(size_of::<[Record; 2]>(), 64);
    }

    /// The policy's bit writes on the production record change exactly
    /// their bits of a word that carries a count, the visited bit and a
    /// flag; a set and a clear are idempotent.
    #[test]
    fn policy_bit_writes_change_only_their_bits() {
        let record = Record::free();
        let base = 1 | REF | VISITED | ABANDONED;
        record
            .ident
            .store(base, std::sync::atomic::Ordering::Relaxed);
        for _ in 0..2 {
            record.set_bits(LINKED);
            assert_eq!(record.word(), base | LINKED);
        }
        record.move_bits(LINKED, DETACHED);
        assert_eq!(record.word(), base | DETACHED);
        for _ in 0..2 {
            record.clear_bits(DETACHED);
            assert_eq!(record.word(), base);
        }
        record.set_bits(LINKED);
        record.move_bits(LINKED, DETACHED | EVICTED);
        assert_eq!(record.word(), base | DETACHED | EVICTED);
        record.clear_bits(EVICTED);
        assert_eq!(record.word(), base | DETACHED);
    }

    /// The record round-trips a locator at the 37-bit start and 24-bit
    /// length limits.
    #[test]
    fn the_locator_field_round_trips_the_extent() {
        let record = Record::free();
        for (start, len) in [
            (0, 1),
            (LOCATOR_START_LIMIT - 1, LOCATOR_LEN_LIMIT - 1),
            (LOCATOR_START_LIMIT - 1, 1),
            (0, LOCATOR_LEN_LIMIT - 1),
        ] {
            let locator = ExtentLocator::new(start, len).unwrap();
            record.set_locator(locator);
            assert_eq!(record.locator(), locator);
            assert_eq!(
                (record.locator().start_unit(), record.locator().len_units()),
                (start, len)
            );
        }
    }

    /// A deadline keeps its whole seconds, rounded down, and one past
    /// `u32::MAX` seconds clamps; a sample expires the object at the second
    /// that holds the deadline, so never later than the deadline and, for a
    /// deadline within `u32::MAX` seconds, at most one second earlier.
    #[test]
    fn expiry_compares_whole_seconds_and_never_serves_past_the_deadline() {
        const S: u64 = 1_000_000_000;
        assert_eq!(deadline_seconds(0), 0);
        assert_eq!(deadline_seconds(S - 1), 0);
        assert_eq!(deadline_seconds(5 * S), 5);
        assert_eq!(deadline_seconds(5 * S + S - 1), 5);
        assert_eq!(deadline_seconds(u64::from(u32::MAX) * S + S - 1), u32::MAX);
        assert_eq!(deadline_seconds((u64::from(u32::MAX) + 1) * S), u32::MAX);
        assert_eq!(deadline_seconds(u64::MAX), u32::MAX);
        for deadline in [S, 5 * S, 5 * S + 1, 5 * S + S - 1, 7 * S - 1] {
            let seconds = deadline_seconds(deadline);
            for now in [
                deadline.saturating_sub(S),
                deadline.saturating_sub(S) + 1,
                deadline - 1,
                deadline,
                deadline + 1,
            ] {
                let is_expired = expired(now, seconds);
                if now >= deadline {
                    assert!(is_expired, "served at or after {deadline}: {now}");
                }
                if is_expired {
                    assert!(now + S > deadline, "more than a second early: {now}");
                }
            }
        }
        let clamped = deadline_seconds(u64::MAX);
        assert!(!expired(u64::from(u32::MAX) * S - 1, clamped));
        assert!(expired(u64::from(u32::MAX) * S, clamped));
    }
}
