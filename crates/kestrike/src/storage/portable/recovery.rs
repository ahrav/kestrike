//! Recovery converts the portable pair an extent-0 row carries into a whole-second deadline on the recovering host. The oracle checks whether each recovered deadline respects the pair's true-time deadline under the local rate-error bound.
//!
//! EXPIRY-SHORTENS, recovery half: the monotonic sample `m` is taken before the reading, the remaining life `R = deadline_ns - latest` starts from the latest bound, and `R` converts through the recovering host's lower rate bound, `floor(R * (1e9 - rho_local) / 1e9)`, so the local deadline's true instant lies at or before the pair's deadline. The postcondition holds from conversion until the host's first suspend.

#[cfg(test)]
use super::clock::PhysicalClock;
use super::clock::{Reading, Trust};
use super::contract::{CONTRACT_LEN, ClockContract};
use super::expiry::{NANOS_PER_MILLI, NANOS_PER_SECOND};

/// `planted!(Name)` reads whether a test planted `Plant::Name` on this thread; it is false outside tests.
macro_rules! planted {
    ($plant:ident) => {{
        #[cfg(test)]
        let planted = super::plant::planted(super::plant::Plant::$plant);
        #[cfg(not(test))]
        let planted = false;
        planted
    }};
}

/// Why recovery withholds a pair, in the order [`Recovery::deadline`] checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Withheld {
    /// A zero lifetime, or a deadline at or below the lifetime's span, which leaves no positive earliest bound.
    Malformed,
    /// The root's contract fails to decode, or names another scale than the local one.
    ContractMismatch,
    /// Recovery requires both a trusted provider reading and a host monotonic sample taken before that reading.
    Untrusted,
    /// The reading is wider than the recovering host's maximum uncertainty.
    WidthExceeded,
    /// The latest bound lies below the earliest bound the pair was written from.
    BackwardStep,
    /// The latest bound lies at or past the deadline, or the rounded local deadline lies at or before the monotonic sample.
    Expired,
    /// The local deadline reaches the `u32::MAX` whole-second clamp, or the monotonic sample's own whole second does, for a pair [`Recovery::retained`] keeps expired.
    Overflow,
}

/// The local whole-second deadline of `pair`, written under the root contract bytes `root`, recovered under `local` from `reading`, taken after the monotonic sample `before`: [`Recovery::deadline`] of one pair.
#[cfg(test)]
pub(crate) fn recovered_deadline(
    pair: (u64, u32),
    root: &[u8; CONTRACT_LEN],
    local: &ClockContract,
    reading: &Reading,
    before: Option<u64>,
) -> Result<u32, Withheld> {
    Recovery::new(root, local, reading, before).deadline(pair)
}

/// `Recovery` holds what every pair's conversion under one root contract, local contract, reading and sample shares: the checks that read no pair, decided once, and the bounds and rate the conversion reads.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Recovery {
    shared: Result<Shared, Withheld>,
}

#[derive(Debug, Clone, Copy)]
struct Shared {
    earliest: u64,
    latest: u64,
    /// `from` is the bound the remaining life starts at.
    from: u64,
    rho: u32,
    scale: super::clock::ClockScale,
    before: u64,
}

impl Recovery {
    /// The checks between a pair's `Malformed` check and its `BackwardStep` check, in their order, with the bounds and rate they pass.
    pub(crate) fn new(
        root: &[u8; CONTRACT_LEN],
        local: &ClockContract,
        reading: &Reading,
        before: Option<u64>,
    ) -> Self {
        Self {
            shared: shared(root, local, reading, before),
        }
    }

    /// The pair-independent checks of the clock contracts, the reading and the sample: `Err` withholds every pair.
    pub(crate) fn verdict(&self) -> Result<(), Withheld> {
        self.shared.map(|_| ())
    }

    /// The local whole-second deadline of `(deadline_ns, lifetime_ms)`, refusing by the first [`Withheld`] cause in its order.
    pub(crate) fn deadline(&self, (deadline_ns, lifetime_ms): (u64, u32)) -> Result<u32, Withheld> {
        let span = u128::from(lifetime_ms) * u128::from(NANOS_PER_MILLI);
        if lifetime_ms == 0 || u128::from(deadline_ns) <= span {
            return Err(Withheld::Malformed);
        }
        let shared = self.shared?;
        let earliest = deadline_ns - span as u64;
        if shared.latest < earliest && !planted!(ExtendOnBackwardStep) {
            return Err(Withheld::BackwardStep);
        }
        let end = if planted!(RederiveTtl) {
            shared.latest.saturating_add(span as u64)
        } else {
            deadline_ns
        };
        if shared.from >= end {
            return Err(Withheld::Expired);
        }
        let remaining = end - shared.from;
        // A stepped scale's label difference can exceed the true span by a removed leap second per month end.
        let allowance = shared.scale.leap_allowance_ns(u128::from(remaining));
        let remaining = remaining - allowance.min(u128::from(remaining)) as u64;
        let kept = NANOS_PER_SECOND - u64::from(shared.rho);
        // `remaining = q * 1e9 + r` with `r < 1e9`, so the floor splits into `q * kept`, at most `remaining`, and `floor(r * kept / 1e9)`, whose product stays below 1e18.
        let (whole, part) = (remaining / NANOS_PER_SECOND, remaining % NANOS_PER_SECOND);
        let local_span = whole * kept + part * kept / NANOS_PER_SECOND;
        // The rounded deadline lies at or before the sample when `before + local_span` falls in the sample's own whole second.
        if local_span < NANOS_PER_SECOND - shared.before % NANOS_PER_SECOND {
            return Err(Withheld::Expired);
        }
        // An instant past `u64::MAX` nanoseconds lies past `u32::MAX` seconds.
        let Some(instant) = shared
            .before
            .checked_add(local_span)
            .filter(|instant| instant / NANOS_PER_SECOND < u64::from(u32::MAX))
        else {
            return Err(Withheld::Overflow);
        };
        Ok((instant / NANOS_PER_SECOND) as u32)
    }

    /// The deadline a load that frees an expired entry's units gives `pair`: [`Recovery::deadline`], but for an `Expired` verdict that a later recovery can reverse.
    ///
    /// The true instant lies at or after the reading's earliest bound, and a later trusted reading's latest bound lies at or after the true instant, less one second on a stepped scale, whose labels repeat at an inserted leap second.
    /// So a deadline at or below the earliest bound, less that second, is `Expired` at every later recovery, and only that pair stays `Expired` here.
    /// A later recovery under a wider reading can keep such a pair expired where this one answers `Expired`; none judges it alive.
    ///
    /// Any other `Expired` verdict comes from this reading's width or from the whole-second rounding at this sample, and a recovery at a later instant, under another reading or sample, can judge the pair alive.
    /// Such a pair gets the sample's own whole second, which every later sample of this host has reached: its entry is expired here and its units stay held.
    /// A sample whose whole second reaches the `u32::MAX` clamp has no such deadline, and the pair is withheld `Overflow`.
    pub(crate) fn retained(&self, pair: (u64, u32)) -> Result<u32, Withheld> {
        let verdict = self.deadline(pair);
        let (Err(Withheld::Expired), Ok(shared)) = (verdict, self.shared) else {
            return verdict;
        };
        let repeat = shared.scale.leap_allowance_ns(0).min(u128::from(u64::MAX)) as u64;
        if pair.0 <= shared.earliest.saturating_sub(repeat) {
            return Err(Withheld::Expired);
        }
        u32::try_from(shared.before / NANOS_PER_SECOND)
            .ok()
            .filter(|second| *second < u32::MAX)
            .ok_or(Withheld::Overflow)
    }
}

/// The per-reading checks of [`Recovery::new`]: `ContractMismatch`, `Untrusted` and `WidthExceeded` in that order, then the bounds and rate a pair's conversion reads.
fn shared(
    root: &[u8; CONTRACT_LEN],
    local: &ClockContract,
    reading: &Reading,
    before: Option<u64>,
) -> Result<Shared, Withheld> {
    let written = ClockContract::decode(root).map_err(|_| Withheld::ContractMismatch)?;
    if written.scale != local.scale {
        return Err(Withheld::ContractMismatch);
    }
    let (Trust::Trusted, Some(before)) = (reading.trust, before) else {
        return Err(Withheld::Untrusted);
    };
    if reading.latest < reading.earliest
        || reading.latest - reading.earliest > local.max_uncertainty_ns
    {
        return Err(Withheld::WidthExceeded);
    }
    Ok(Shared {
        earliest: reading.earliest,
        latest: reading.latest,
        from: if planted!(EarliestAtRecovery) {
            reading.earliest
        } else {
            reading.latest
        },
        rho: if planted!(WriterRateAtRecovery) {
            written.rate_error_ppb
        } else {
            local.rate_error_ppb
        },
        scale: local.scale,
        before,
    })
}

/// Recovers `pair` the way a loader samples: the monotonic `sample` first, then one reading of `clock`, or the reverse under [`Plant::SamplingOrder`].
#[cfg(test)]
pub(crate) fn recover(
    pair: (u64, u32),
    root: &[u8; CONTRACT_LEN],
    local: &ClockContract,
    clock: &mut dyn PhysicalClock,
    sample: &mut dyn FnMut() -> u64,
) -> Result<u32, Withheld> {
    let (reading, before) = if planted!(SamplingOrder) {
        let reading = clock.read();
        (reading, sample())
    } else {
        let before = sample();
        (clock.read(), before)
    };
    recovered_deadline(pair, root, local, &reading, Some(before))
}

/// One recovery scenario in true time, nanoseconds: a writer stored a pair whose deadline is `deadline_ns`, from a reading whose earliest bound held true time, and the recovering host's reading holds true instant `recovered_true`, with its monotonic sample taken `gap` true nanoseconds earlier at local tick `before`.
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Scenario {
    pub(crate) deadline_ns: u64,
    pub(crate) recovered_true: u64,
    pub(crate) gap: u64,
    pub(crate) before: u64,
}

/// Whether the oracle accepts `seconds`, the local deadline recovered in `scenario` under a local rate-error bound `rho`: the true time the local span from `before` to `seconds` can take on a clock running up to `rho` parts per billion slow, `ceil(span * 1e9 / (1e9 - rho))`, starting at the sample's true instant, ends at or before the pair's deadline, which lies at or before the writer's true instant plus the lifetime.
#[cfg(test)]
pub(crate) fn oracle_accepts(scenario: &Scenario, rho: u32, seconds: u32) -> bool {
    let giga = u128::from(NANOS_PER_SECOND);
    let span = (u128::from(seconds) * giga).saturating_sub(u128::from(scenario.before));
    let slowest = span * giga;
    let true_span = slowest.div_ceil(giga - u128::from(rho));
    let sampled_true = u128::from(scenario.recovered_true) - u128::from(scenario.gap);
    sampled_true + true_span <= u128::from(scenario.deadline_ns)
}
