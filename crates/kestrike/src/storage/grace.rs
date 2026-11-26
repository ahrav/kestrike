//! Epoch-based reclamation for retired-slot anchors: readers pin an era,
//! a maintenance pass certifies which eras no reader can still observe, and
//! the return service releases anchors below the certified era.
//!
//! The protocol is written over abstract 64-bit control words so the same
//! code runs on the mapped control words of a live storage and, under
//! `--cfg loom`, on model atomics. [`Strength`] names the orderings of the
//! three store-then-load points, an optional fence at each and the
//! publication of the certified era; production uses [`Sequential`], whose
//! accesses at the three points are `SeqCst`, whose publication is a
//! `Release` store and whose fences are empty. The model encodes the same three constraints as `Release` stores,
//! `SeqCst` fences and `Acquire` loads, because loom 0.7.2 does not model
//! the cross-location total order of `SeqCst` accesses (its
//! `rt::thread::Set::seq_cst` is a documented no-op) while it does model
//! `SeqCst` fences; the model's negative controls drop fences, and the
//! `grace_model` module records which drops are weakenings.
//!
//! # Era values
//!
//! Pins hold era values in `1..ERA_TERMINAL`; zero means no active pin.
//! Values with the top bit set are terminal: the bump that lands there
//! poisons admission and every later pin is refused. Every retirement whose
//! bump returns `ERA_TERMINAL - 1` or more closes admission with `SeqCst`
//! before it publishes its reclaimable mark, not only the one that crossed:
//! a crossing thread paused before its close still holds its unserviceable
//! anchor and slot, and the next terminal-band retirement closes before that
//! mark can become eligible, so no completed terminal-band retirement is
//! recycled into a newly admitted object. Once admission is closed every
//! further retirement comes from an object already admitted, so their number
//! is bounded by the summed slot count, which validation keeps at or below
//! `u64::MAX - ERA_TERMINAL`: every stamp stays below `u64::MAX`, so era
//! comparisons are plain unsigned comparisons. The terminal
//! threshold is a [`Strength`] constant so the model can run a tiny band;
//! production uses [`ERA_TERMINAL`].
//!
//! # Ordering argument
//!
//! Three store-then-load points need one total order: the reader's pin store
//! then its observation load, the writer's visibility removal then its era
//! bump, and the maintainer's `start_era` load then its record loads. All
//! three use `SeqCst`, as do the reader's era load and the pin loads of the
//! pass. The observation load and the removal store belong to the index,
//! which must perform them with `SeqCst` too: the reader's shard-sequence
//! loads, and the commit of the bracket that ends the mapping; this module
//! supplies the other four operations and the bump. With `Acquire`/`Release` alone a
//! store-buffering execution is allowed in which the maintainer reads an
//! inactive pin while the reader read the identity the writer had already
//! removed; any weakening needs a new proof and a matched model
//! counterexample.
//!
//! The `register` module adds a fourth point on the same pin store: after
//! [`pin`] the reader loads the admission cutoff with `SeqCst`, so a pin
//! whose cutoff read returned open precedes the close in the total order,
//! and a `SeqCst` pin load ordered after the close sees that pin while its
//! interval is active, or its clearing store once the interval's protected
//! work has ended. The cutoff is a root word; `Storage::close` states that
//! contract,
//! and its consumer is the terminal-band retirement that closes admission
//! before publishing a reclaimable mark.
//!
//! In the `SeqCst` total order `S`, write `L_e` for the reader's era load,
//! `S_p` for its pin store, `L_o` for its observation load, `W` for the
//! writer's removal, `B` for the bump that returned `retire_era`, `L_s` for
//! the maintainer's `start_era` load and `V` for its load of the reader's
//! record. A reader that observed the removed identity has `L_o` before `W`
//! in `S`, so `L_e < S_p < L_o < W < B`, and the value it pinned is at most
//! `retire_era` because the era only grows. If `V` follows `S_p` while the
//! pin is active, `V` reads that pin, so the certified value stays at or
//! below `retire_era` and the anchor is held. If `V` precedes `S_p`, then
//! `L_s < V < S_p < B`, so `retire_era` is at least `start_era`, which bounds
//! the certified value from above; the anchor is held again. `L_s` and `V`
//! may run in different calls and on different threads: the pass cursor is
//! read and written under the maintenance gate, whose acquire and release
//! order `L_s` before `V`, and `S` is consistent with that order. That is why
//! an interrupted pass may resume with the same `start_era`: every record it
//! visits is judged against a bound its own first load fixed. If `V` follows
//! the reader's clearing store, the reader's interval is over: every
//! protected access it made precedes that store, and any right it retained
//! is counted in the slot on its own, so releasing the anchor is legal. A
//! reader that loaded the era, paused and stored a stale value only lowers
//! its pin, which only delays release. The object's reference increment
//! happens inside the pin window and the incarnation check follows it. This
//! proves protection completion, not linearizability or aliasing; those are
//! separate written arguments.
//!
//! A pass visits only the records below the claimed bound, a word that only
//! grows. After claiming its record and before any pin the record takes, a
//! registration loads the bound with `SeqCst` and, when it does not cover the
//! record, raises it with a `SeqCst` read-modify-write; write `F` for the
//! last of those accesses, which reads or writes a value above the record's
//! index. Each call of a pass loads the bound with `SeqCst` as `H`, after
//! `L_s` in the total order since the maintenance gate orders the calls of
//! one pass. A record the pass did not visit lies at or above the value `H`
//! read, so that value precedes, in the word's modification order, the one
//! `F` read or wrote, and `H` is coherence-ordered before `F`: `H` precedes
//! `F` in `S`. Every pin the record takes is sequenced after `F`, so
//! `L_s < H < F < L_e < S_p`, and `H` plays
//! the role of `V` preceding `S_p` above: the reader's pin is at least
//! `start_era`, and so is any stamp of a retirement it observed. Skipping
//! the record changes neither the bound the pass certifies nor which
//! anchors it holds.
//!
//! The clearing store is not one of the three points: nothing the reader
//! loads after it needs ordering against it. It is a `Release` store, and
//! the pass's `SeqCst` load of the record acquires it, whether it reads the
//! store itself or a later pin, which the handle's holder stores after it
//! with `SeqCst`, on the same thread or after the handoff that moved the
//! handle, so the interval's protected accesses happen before the release
//! either way. In the total order the load still precedes the record's next
//! pin store whenever it reads the cleared value, which is what the `V`
//! before `S_p` case uses. Weakening it further to `Relaxed` would let the
//! reuse overtake the interval's last read.
//!
//! # Ordinary-memory argument
//!
//! The total order above settles which pins a pass must count. What the
//! released memory holds is a separate happens-before argument over the
//! `Release`/`Acquire` edges; where a step below leans on the total order it
//! says so.
//!
//! - A slot's record fields are written before the shard commits the
//!   mapping's sequence with a `Release`-capable store, and a reader's
//!   `Acquire`-capable observation of that sequence consumes the writes, as
//!   does a later commit ordered after it under the shard gate. A candidate
//!   copied under a stable sequence therefore reads initialized record
//!   fields.
//! - Every protected read a reader makes is sequenced before its clearing
//!   `Release` store. A pass that loads the cleared value with `Acquire`
//!   carries the completed reads to the certificate it publishes, and the
//!   anchor's release loads that certificate with `Acquire`. A pass that
//!   loads a later interval's pin instead still carries them: the handle's
//!   holder stores that pin after the clearing store, on the same thread or
//!   after the handoff that moved the handle, so the clearing store happens
//!   before the pin store, and the pass's load, which synchronizes with the
//!   pin store, is ordered after both. A
//!   pass that observed neither relies on the total-order exclusion above:
//!   it saw a pin at or below the stamp, or it saw the record before the
//!   pin, so its bound holds the anchor.
//! - Every external right's `Release` decrement and the anchor's `AcqRel`
//!   exchange, with the read-modify-writes between them, form one release
//!   sequence on the slot's word, since every write of the word is a
//!   read-modify-write; the return's acquire of the terminal zero, by the
//!   `Acquire` load that reads it or by the anchor's own exchange when that
//!   is what leaves it, consumes every lease's reads. A count that reads
//!   zero because it was never raised is not retirement evidence: the
//!   return also requires the retired flag, written under the pool gate, or
//!   the parked flag, whose gate-free `AcqRel` exchange orders the counter
//!   ahead of it and lands only on the incarnation it was issued for.
//! - A new incarnation is written only after the exact old return under the
//!   pool gate, so its initialization is ordered after every read of the old
//!   one by the edges above.
//!
//! The terminal band's own argument is a happens-before chain closed by the
//! pool gate. A retirement bumps and stamps first, then records its
//! obligation, moving the slot to retired under the gate or parking its
//! incarnation when the gate is busy, with the read-modify-write that
//! publishes its reclaimable mark; until then the slot is still resident,
//! and after it the anchor keeps the count positive, so neither form
//! returns the slot before the mark is published. Every band retirement
//! stores the cutoff `SeqCst` before that `AcqRel` read-modify-write.
//! Service releases
//! the anchor only after loading that mark with `Acquire`, removes it with
//! a successful `AcqRel` compare-exchange that clears `ANCHORED` and
//! decrements the count, and returns the slot after
//! loading zero with
//! `Acquire`, all under the pool gate; the allocation that could reclaim the
//! slot takes the same gate first and loads the cutoff before its claim
//! commits. The close therefore happens before that load, which by
//! coherence reads closed, and the gate keeps the free set unchanged
//! between the load and the claim. This is also what bounds the stamps: a
//! slot retires after the close at most once, because its next claim would
//! have to follow its own mark and so read closed, so the stamps consumed
//! after the close are at most the summed slot count, which validation
//! keeps within the reserve above the band.
//!
//! # Accepted tradeoff
//!
//! A reader that stays pinned stalls every later release in its domain for
//! as long as it stays pinned. Memory stays bounded because retired slots
//! keep their charge and admission refuses when capacity is gone; no slot is
//! reclaimed early, no reader is unregistered by force and no counter is
//! reset. The protocol neither waits, spins nor allocates.

use std::sync::atomic::Ordering;

use super::probe::{self, Primitive};

/// The first era a pin may hold. Zero is reserved for no active pin.
pub(crate) const ERA_FIRST: u64 = 1;

pub(crate) use super::config::ERA_TERMINAL;

/// An unpinned registration record.
pub(crate) const INACTIVE: u64 = 0;

/// A 64-bit control word the protocol reads and writes atomically.
pub(crate) trait EraWord {
    fn load(&self, order: Ordering) -> u64;
    fn store(&self, value: u64, order: Ordering);
    fn fetch_add(&self, value: u64, order: Ordering) -> u64;
}

/// Forwards every [`EraWord`] method to the inherent method of one atomic
/// type; both implementations are the same one-line forwards.
macro_rules! forward_era_word {
    ($atomic:ty) => {
        impl EraWord for $atomic {
            #[inline(always)]
            fn load(&self, order: Ordering) -> u64 {
                Self::load(self, order)
            }

            #[inline(always)]
            fn store(&self, value: u64, order: Ordering) {
                Self::store(self, value, order);
            }

            #[inline(always)]
            fn fetch_add(&self, value: u64, order: Ordering) -> u64 {
                Self::fetch_add(self, value, order)
            }
        }
    };
}

forward_era_word!(std::sync::atomic::AtomicU64);
#[cfg(all(test, loom))]
forward_era_word!(loom::sync::atomic::AtomicU64);

/// Memory orderings of the protocol's three store-then-load points, the
/// loads that feed them and the publication of the certified era.
/// Production uses [`Sequential`].
pub(crate) trait Strength {
    /// First terminal era; [`ERA_TERMINAL`] in production, tiny in a model.
    const TERMINAL: u64 = ERA_TERMINAL;
    /// The reader's era load.
    const ERA_LOAD: Ordering;
    /// The reader's pin store.
    const PIN_STORE: Ordering;
    /// The writer's era bump.
    const BUMP: Ordering;
    /// The maintainer's `start_era` load.
    const START: Ordering;
    /// The maintainer's pin loads.
    const VISIT: Ordering;
    /// The maintainer's publication of the certified era, which the release
    /// of every anchor reads with `Acquire`. A store: the pass runs under
    /// the maintenance gate, so it is the word's only writer.
    const PUBLISH: Ordering;

    /// Fence after the reader's pin store, before its observation load.
    /// Empty when the accesses themselves are `SeqCst`.
    #[inline(always)]
    fn fence_pin() {}

    /// Fence after the writer's visibility removal, before its era bump.
    #[inline(always)]
    fn fence_retire() {}

    /// Fence after the maintainer's `start_era` load, before its pin loads.
    #[inline(always)]
    fn fence_certify() {}
}

/// Production strength: `SeqCst` at the three points; publication is a
/// `Release` store.
pub(crate) struct Sequential;

impl Strength for Sequential {
    const ERA_LOAD: Ordering = Ordering::SeqCst;
    const PIN_STORE: Ordering = Ordering::SeqCst;
    const BUMP: Ordering = Ordering::SeqCst;
    const START: Ordering = Ordering::SeqCst;
    const VISIT: Ordering = Ordering::SeqCst;
    const PUBLISH: Ordering = Ordering::Release;
}

/// Why no pin was stored. The record is untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinRefused {
    /// The era counter is terminal: no new pin is admitted.
    Terminal,
    /// The record still holds a pin: an earlier interval was leaked without
    /// ending, and raising its pin would certify away the protection it may
    /// still rely on.
    Active,
}

/// Pins the current era into `record` and returns it. The record must be
/// inactive: one registration admits one interval at a time, and a record
/// still holding a pin is refused rather than overwritten, because a leaked
/// interval may still rely on it. The caller's handle is the record's only
/// writer, so a load decides that and the pin is a plain store, not a
/// read-modify-write.
///
/// # Errors
///
/// `Terminal` if the era is in the terminal band, `Active` if the record
/// already holds a pin; the record is untouched either way.
#[inline(always)]
pub(crate) fn pin<W: EraWord, S: Strength>(era: &W, record: &W) -> Result<u64, PinRefused> {
    probe::note(Primitive::Load);
    let now = era.load(S::ERA_LOAD);
    if now >= S::TERMINAL {
        return Err(PinRefused::Terminal);
    }
    probe::note(Primitive::Load);
    if record.load(Ordering::Relaxed) != INACTIVE {
        return Err(PinRefused::Active);
    }
    probe::note(Primitive::Store);
    record.store(now, S::PIN_STORE);
    S::fence_pin();
    Ok(now)
}

/// Clears `record` after the holder's last protected access. `Release`: the
/// module documentation states why the clearing store needs no place in the
/// total order.
#[inline(always)]
pub(crate) fn unpin<W: EraWord>(record: &W) {
    probe::note(Primitive::Store);
    record.store(INACTIVE, Ordering::Release);
}

/// One retirement's era bump, performed after its visibility removal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Bump {
    /// The era the retirement is stamped with.
    pub retire_era: u64,
    /// Whether the stamp is `TERMINAL - 1` or above: the bump moved the
    /// counter into the terminal band or found it there, and the caller
    /// closes admission before publishing the retirement's mark. Every
    /// terminal-band retirement reports `true`, not only the crossing one.
    pub closes_admission: bool,
}

/// Advances the era once for a retirement whose visibility is already gone.
/// The counter keeps counting inside the terminal band; the module
/// documentation states why it cannot wrap.
#[inline(always)]
pub(crate) fn bump<W: EraWord, S: Strength>(era: &W) -> Bump {
    S::fence_retire();
    let retire_era = era.fetch_add(1, S::BUMP);
    Bump {
        retire_era,
        closes_admission: retire_era >= S::TERMINAL - 1,
    }
}

/// Position of one certification pass over the registration records.
/// [`IDLE`](Self::IDLE) is the state between passes; a begun pass is never
/// mistaken for it because the era starts at [`ERA_FIRST`] and only grows,
/// so its `start_era` is never zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PassCursor {
    /// Era loaded before the first visit; the certified value never exceeds
    /// it.
    pub start_era: u64,
    /// Smallest active pin seen so far, held as the pin less one so that an
    /// inactive record, zero, keys as `u64::MAX` and one unsigned minimum
    /// per visit skips it without a branch; `u64::MAX` when none. Pins are
    /// at least [`ERA_FIRST`], so the key of a real pin never wraps.
    pub min_key: u64,
    /// Records visited so far in this pass.
    pub next: usize,
}

impl PassCursor {
    /// No pass in progress.
    pub(crate) const IDLE: Self = Self {
        start_era: 0,
        min_key: u64::MAX,
        next: 0,
    };

    /// Smallest active pin seen so far; `u64::MAX` when none.
    #[inline]
    pub(crate) fn min_pin(&self) -> u64 {
        self.min_key.saturating_add(1)
    }

    /// Whether a pass has started and not yet completed.
    #[inline]
    pub(crate) fn in_progress(&self) -> bool {
        *self != Self::IDLE
    }

    /// Begins a pass: loads `start_era` before any record is visited.
    #[inline]
    pub(crate) fn begin<W: EraWord, S: Strength>(era: &W) -> Self {
        let start_era = era.load(S::START);
        S::fence_certify();
        Self {
            start_era,
            min_key: u64::MAX,
            next: 0,
        }
    }

    /// Visits one record, loading its pin fresh, and advances the cursor.
    /// Returns the pin loaded, `INACTIVE` for an unpinned record.
    #[inline]
    pub(crate) fn visit<W: EraWord, S: Strength>(&mut self, record: &W) -> u64 {
        let pin = record.load(S::VISIT);
        self.min_key = self.min_key.min(pin.wrapping_sub(1));
        self.next += 1;
        pin
    }

    /// The bound this pass proves once every record has been visited:
    /// `min(start_era, min_active_pin)`.
    #[inline]
    pub(crate) fn bound(&self) -> u64 {
        self.start_era.min(self.min_pin())
    }

    /// Completes the pass over `records` records: raises `certified` to the
    /// pass's bound if that is higher and returns the value now certified.
    /// The caller has visited every record and holds the maintenance gate,
    /// so this is the word's only writer and a load then a store raise it
    /// without a read-modify-write; the gate's acquire take orders the
    /// previous pass's store before the load. An incomplete pass certifies
    /// nothing and must not call this.
    #[inline]
    pub(crate) fn complete<W: EraWord, S: Strength>(self, records: usize, certified: &W) -> u64 {
        debug_assert_eq!(self.next, records, "certifying from an incomplete pass");
        let bound = self.bound();
        let current = certified.load(Ordering::Relaxed);
        if bound <= current {
            return current;
        }
        certified.store(bound, S::PUBLISH);
        bound
    }
}

/// Whether a retirement stamped `retire_era` may release its anchor under a
/// certified value: strictly below, never equal.
#[inline(always)]
pub(crate) fn releasable(retire_era: u64, certified: u64) -> bool {
    retire_era < certified
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;

    use super::{
        Bump, ERA_FIRST, ERA_TERMINAL, INACTIVE, PassCursor, PinRefused, Sequential, bump, pin,
        releasable, unpin,
    };

    #[test]
    fn pins_hold_the_era_and_the_terminal_band_refuses() {
        let era = AtomicU64::new(ERA_FIRST);
        let record = AtomicU64::new(INACTIVE);
        assert_eq!(pin::<_, Sequential>(&era, &record), Ok(ERA_FIRST));
        assert_eq!(record.load(std::sync::atomic::Ordering::SeqCst), ERA_FIRST);
        // A record still pinned refuses a second pin and keeps the first.
        era.store(5, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(pin::<_, Sequential>(&era, &record), Err(PinRefused::Active));
        assert_eq!(record.load(std::sync::atomic::Ordering::SeqCst), ERA_FIRST);
        unpin(&record);
        assert_eq!(record.load(std::sync::atomic::Ordering::SeqCst), INACTIVE);

        era.store(ERA_TERMINAL - 1, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(pin::<_, Sequential>(&era, &record), Ok(ERA_TERMINAL - 1));
        unpin(&record);
        assert_eq!(
            bump::<_, Sequential>(&era),
            Bump {
                retire_era: ERA_TERMINAL - 1,
                closes_admission: true,
            }
        );
        assert_eq!(
            pin::<_, Sequential>(&era, &record),
            Err(PinRefused::Terminal)
        );
        assert_eq!(record.load(std::sync::atomic::Ordering::SeqCst), INACTIVE);
        // Later bumps stay in the band and close admission again; a bump
        // below the band does not.
        assert_eq!(
            bump::<_, Sequential>(&era),
            Bump {
                retire_era: ERA_TERMINAL,
                closes_admission: true,
            }
        );
        let below = AtomicU64::new(ERA_TERMINAL - 2);
        assert_eq!(
            bump::<_, Sequential>(&below),
            Bump {
                retire_era: ERA_TERMINAL - 2,
                closes_admission: false,
            }
        );
    }

    /// The bound is the minimum of the start era and every active pin seen,
    /// computed independently for every subset of active records.
    #[test]
    fn a_completed_pass_certifies_the_minimum_of_start_and_active_pins() {
        for active in 0u8..8 {
            let era = AtomicU64::new(10);
            let certified = AtomicU64::new(0);
            let records: [AtomicU64; 3] = std::array::from_fn(|index| {
                let pinned = active & (1 << index) != 0;
                AtomicU64::new(if pinned { 4 + index as u64 } else { INACTIVE })
            });
            let mut cursor = PassCursor::begin::<_, Sequential>(&era);
            assert_eq!(cursor.start_era, 10);
            // The era moves after the start load; the bound ignores it.
            era.store(20, std::sync::atomic::Ordering::SeqCst);
            let expected = (0..3)
                .filter(|index| active & (1 << index) != 0)
                .map(|index| 4 + index as u64)
                .min()
                .unwrap_or(10)
                .min(10);
            for (visited, record) in records.iter().enumerate() {
                assert!(cursor.in_progress() || visited == 0);
                cursor.visit::<_, Sequential>(record);
                assert_eq!(cursor.next, visited + 1);
            }
            assert_eq!(
                cursor.complete::<_, Sequential>(records.len(), &certified),
                expected
            );
            // Certified never decreases.
            certified.store(expected + 5, std::sync::atomic::Ordering::SeqCst);
            let again = PassCursor::begin::<_, Sequential>(&AtomicU64::new(expected));
            assert_eq!(again.complete::<_, Sequential>(0, &certified), expected + 5);
        }
        assert!(releasable(3, 4));
        assert!(!releasable(4, 4));
        assert!(!releasable(5, 4));
        assert!(!PassCursor::IDLE.in_progress());
    }

    /// The minimum is kept as the pin less one, so an inactive record keys
    /// last and the smallest and largest admissible pins map back exactly;
    /// a pass that saw no active pin reports `u64::MAX` and bounds at its
    /// start era.
    #[test]
    fn the_pass_minimum_keys_inactive_records_last_and_maps_back_exactly() {
        let era = AtomicU64::new(ERA_TERMINAL - 1);
        let mut cursor = PassCursor::begin::<_, Sequential>(&era);
        assert_eq!(cursor.min_pin(), u64::MAX);
        cursor.visit::<_, Sequential>(&AtomicU64::new(INACTIVE));
        assert_eq!((cursor.min_pin(), cursor.min_key), (u64::MAX, u64::MAX));
        assert_eq!(cursor.bound(), ERA_TERMINAL - 1);
        cursor.visit::<_, Sequential>(&AtomicU64::new(ERA_TERMINAL - 1));
        assert_eq!(cursor.min_pin(), ERA_TERMINAL - 1);
        cursor.visit::<_, Sequential>(&AtomicU64::new(INACTIVE));
        assert_eq!(cursor.min_pin(), ERA_TERMINAL - 1);
        cursor.visit::<_, Sequential>(&AtomicU64::new(ERA_FIRST));
        assert_eq!((cursor.min_pin(), cursor.min_key), (ERA_FIRST, 0));
        assert_eq!(cursor.next, 4);
        assert_eq!(cursor.bound(), ERA_FIRST);
        assert!(cursor.in_progress());
    }
}
