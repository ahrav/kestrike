//! Kani proof of the certification pass in `grace`: a pass that
//! [`PassCursor::begin`](super::grace::PassCursor::begin) starts, that visits
//! every record across two calls and that
//! [`PassCursor::complete`](super::grace::PassCursor::complete) ends raises
//! the certified era to `min(start_era, smallest active pin)` when that is
//! higher and otherwise leaves it, so no retirement stamped at or above an
//! active pin or the start era becomes
//! [`releasable`](super::grace::releasable) under the bound the pass proves.
//! The completing call passes the incomplete-pass assertion of
//! `PassCursor::complete`, which Kani checks as a property.
//!
//! Bounds: three registration records, each `INACTIVE` or a symbolic pin in
//! `ERA_FIRST..ERA_TERMINAL`; a symbolic start era in that range and a
//! symbolic later era stored between the two calls; a symbolic prior
//! certified value; a symbolic split point from 0 through 3; unwinding 4.
//! The words are `std` atomics under the production `Sequential` strength
//! on one thread, so the proof covers the pass's arithmetic, not its
//! orderings, which the loom model of `grace_model` checks.

#[cfg(kani)]
mod verification {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::super::grace::{
        ERA_FIRST, ERA_TERMINAL, INACTIVE, PassCursor, Sequential, releasable,
    };

    /// Registration records in the pass.
    const RECORDS: usize = 3;

    /// A symbolic record word: unpinned or holding an admitted pin.
    fn record() -> u64 {
        let pin: u64 = kani::any();
        kani::assume(pin == INACTIVE || (ERA_FIRST..ERA_TERMINAL).contains(&pin));
        pin
    }

    /// A pass over three records, split at a symbolic point into two calls with the era advanced between them,
    /// returns and publishes the larger of the prior certified value and `min(start_era, smallest active pin)`;
    /// its bound releases no retirement stamped at or above an active pin or the start era, and each visit
    /// returns the record's pin.
    #[kani::proof]
    #[kani::unwind(4)]
    fn a_split_pass_certifies_the_minimum_of_its_start_era_and_every_active_pin() {
        let start: u64 = kani::any();
        kani::assume((ERA_FIRST..ERA_TERMINAL).contains(&start));
        let era = AtomicU64::new(start);
        let pins = [record(), record(), record()];
        let records = pins.map(AtomicU64::new);
        let prior: u64 = kani::any();
        let certified = AtomicU64::new(prior);
        let split: usize = kani::any();
        kani::assume(split <= RECORDS);

        let mut cursor = PassCursor::begin::<_, Sequential>(&era);
        assert!(cursor.in_progress());
        for (record, &pin) in records[..split].iter().zip(&pins[..split]) {
            assert_eq!(cursor.visit::<_, Sequential>(record), pin);
        }
        let later: u64 = kani::any();
        kani::assume(later >= start);
        era.store(later, Ordering::SeqCst);
        let mut resumed = cursor;
        for (record, &pin) in records[split..].iter().zip(&pins[split..]) {
            assert_eq!(resumed.visit::<_, Sequential>(record), pin);
        }

        let smallest = pins
            .iter()
            .copied()
            .filter(|&pin| pin != INACTIVE)
            .min()
            .unwrap_or(u64::MAX);
        assert_eq!(resumed.min_pin(), smallest);
        let bound = start.min(smallest);
        assert_eq!(resumed.bound(), bound);
        let stamp: u64 = kani::any();
        if stamp >= start || pins.iter().any(|&pin| pin != INACTIVE && stamp >= pin) {
            assert!(!releasable(stamp, bound));
        }

        let published = resumed.complete::<_, Sequential>(RECORDS, &certified);
        assert_eq!(published, prior.max(bound));
        assert_eq!(certified.load(Ordering::Relaxed), published);

        kani::cover!(split == 1 && later > start);
        kani::cover!(pins.iter().all(|&pin| pin == INACTIVE) && published == start);
        kani::cover!(smallest < start && published == smallest);
        kani::cover!(
            pins[RECORDS - 1] != INACTIVE && pins[RECORDS - 1] == smallest && smallest < start
        );
        kani::cover!(prior > bound && published == prior);
        kani::cover!(stamp < bound && releasable(stamp, published));
    }
}
