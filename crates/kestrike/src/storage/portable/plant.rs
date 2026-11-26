//! Planted defects of the portable-expiry path for negative controls; each test plants one for the test thread and the matching check fails by name.

use std::cell::Cell;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Plant {
    /// The writer samples the monotonic clock before it reads the provider, or recovery reads the provider before it samples.
    SamplingOrder,
    /// The writer converts the remaining life with no rate margin.
    IgnoreRateBound,
    /// Recovery converts through the root contract's writer rate bound in place of the local one.
    WriterRateAtRecovery,
    /// Recovery takes its deadline as the latest bound plus the stored lifetime.
    RederiveTtl,
    /// Recovery converts the remaining life from its reading's earliest bound.
    EarliestAtRecovery,
    /// Recovery converts a reading whose latest bound lies below the written earliest bound.
    ExtendOnBackwardStep,
    /// The segment reader trusts a disrupted status.
    TrustDisrupted,
    /// The writer persists a lifetime at its `u32::MAX` cap as a deadline that never expires.
    ClampAsNever,
}

thread_local! {
    static PLANT: Cell<Option<Plant>> = const { Cell::new(None) };
}

/// Plants `plant` on this thread until the returned guard drops.
pub(crate) fn plant(plant: Plant) -> Planted {
    PLANT.with(|cell| cell.set(Some(plant)));
    Planted
}

pub(crate) fn planted(plant: Plant) -> bool {
    PLANT.with(Cell::get) == Some(plant)
}

/// Clears the thread's plant on drop.
pub(crate) struct Planted;

impl Drop for Planted {
    fn drop(&mut self) {
        PLANT.with(|cell| cell.set(None));
    }
}
