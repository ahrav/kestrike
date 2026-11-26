//! A publication's portable pair and the counters a volume reports about its physical clock.
//!
//! The pair is the device form of a portable deadline: `deadline_ns` nanoseconds since the Unix epoch on the contract's scale and `lifetime_ms`, with `deadline_ns - lifetime_ms * 1e6` the earliest bound of the reading it came from. Zero in both fields is the absent pair; every present pair has a nonzero deadline and a nonzero lifetime.

use super::clock::{Reading, Trust};
use super::contract::ClockContract;
use super::expiry::{Absent, CAUSES, NANOS_PER_MILLI, portable};

/// A slot's portable pair, or [`ABSENT`](Self::ABSENT).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PortableExpiry {
    pub deadline_ns: u64,
    pub lifetime_ms: u32,
}

impl PortableExpiry {
    /// The pair of a binding that persists no portable deadline and stays live-only.
    pub const ABSENT: Self = Self {
        deadline_ns: 0,
        lifetime_ms: 0,
    };

    /// The pair for `reading`, taken before the monotonic `sample`, of a binding whose whole-second live deadline is `live_s`, under `contract`.
    ///
    /// [`portable`]'s lifetime counts true time. A stepped scale's labels can lag true time by one leap second per month end, so the pair subtracts the scale's [leap allowance](super::ClockScale::leap_allowance_ns) from both `lifetime_ms` and `deadline_ns`.
    pub(crate) fn of(
        reading: &Reading,
        contract: &ClockContract,
        sample: Option<u64>,
        live_s: u32,
    ) -> Result<Self, Absent> {
        let (deadline_ns, lifetime_ms) = portable(
            reading.earliest,
            reading.latest,
            reading.trust == Trust::Trusted,
            contract.max_uncertainty_ns,
            contract.rate_error_ppb,
            sample,
            live_s,
        )?;
        let span = u128::from(lifetime_ms) * u128::from(NANOS_PER_MILLI);
        // A lifetime of at most `u32::MAX` ms holds at most two month ends, so the allowance is at most 2,000 ms.
        let allowance_ms =
            (contract.scale.leap_allowance_ns(span) / u128::from(NANOS_PER_MILLI)) as u32;
        let lifetime_ms = lifetime_ms.saturating_sub(allowance_ms);
        if lifetime_ms == 0 {
            return Err(Absent::LiveDeadlinePassed);
        }
        Ok(Self {
            deadline_ns: deadline_ns - u64::from(allowance_ms) * NANOS_PER_MILLI,
            lifetime_ms,
        })
    }
}

/// Publications that persisted no portable pair, one counter per cause in [`Absent`]'s order; each publication counts at most once.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AbsentCounts([u64; CAUSES]);

impl AbsentCounts {
    pub(crate) fn count(&mut self, cause: Absent) {
        self.0[cause as usize] += 1;
    }

    /// The publications counted under `cause`.
    pub fn of(&self, cause: Absent) -> u64 {
        self.0[cause as usize]
    }

    pub fn total(&self) -> u64 {
        self.0.iter().sum()
    }
}

/// The volume's view of its physical-clock provider.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClockReport {
    /// The provider's verdict on its latest reading; `None` before the first.
    pub trust: Option<Trust>,
    /// The monotonic sample taken after the last trusted reading; `None` before the first. A reader subtracts it from its own sample for the reading's age.
    pub last_trusted_at: Option<u64>,
    pub absent: AbsentCounts,
}
