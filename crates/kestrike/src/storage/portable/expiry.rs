//! The portable pair of a publication: [`portable`] shortens the remaining monotonic life of the whole-second live deadline through the writer's upper clock-rate bound and adds the result to the earliest bound of a trusted physical-clock reading.
//!
//! The function reads plain values, and Verus checks it against its `ensures` contract.
//! EXPIRY-SHORTENS, writer half: when the reading precedes the monotonic sample `m` and the writer's clock runs within `rate_ppb` of true time, the monotonic duration `L - m` spans at least `(L - m) * 1e9 / (1e9 + rate_ppb)` true nanoseconds, so `earliest + lifetime` lies at or before the physical instant of the monotonic deadline `L`.
//! Every refusal names one cause, checked in the order [`Absent`] lists them.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const NANOS_PER_SECOND: u64 = 1_000_000_000;

#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const NANOS_PER_MILLI: u64 = 1_000_000;

/// Why [`portable`] yields no pair, in the order it checks.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Absent {
    /// The provider reported its reading untrusted.
    Untrusted,
    /// The reading's width, latest minus earliest, exceeds the contract's maximum uncertainty, or its latest bound lies below its earliest.
    WidthExceeded,
    /// The reading's earliest bound is zero.
    EarliestZero,
    /// The monotonic sample taken after the reading failed.
    MonotonicUnavailable,
    /// The sample lies at or past the live deadline, or less than one whole millisecond of true time remains before it.
    LiveDeadlinePassed,
    /// The earliest bound plus the lifetime passes `u64::MAX`.
    Overflow,
}

/// The number of [`Absent`] causes.
pub const CAUSES: usize = Absent::Overflow as usize + 1;

/// The pair `(deadline_ns, lifetime_ms)` for a reading `[earliest, latest]` that its provider reported `trusted`, under a contract admitting widths up to `max_width` nanoseconds and a writer rate error of `rate_ppb`, with `sample` the monotonic sample taken after the reading and `live_s` the slot's whole-second live deadline.
///
/// The lifetime is the remaining true life in whole milliseconds, capped at `u32::MAX`; the deadline is the earliest bound plus that lifetime.
#[cfg_attr(verus_keep_ghost, verus_spec(converted =>
    requires
        rate_ppb < NANOS_PER_SECOND,
    ensures
        !trusted ==> converted == Err::<(u64, u32), Absent>(Absent::Untrusted),
        converted matches Ok((deadline, lifetime)) ==> trusted
            && earliest <= latest
            && latest - earliest <= max_width
            && earliest > 0
            && sample is Some
            && lifetime > 0
            && deadline == earliest + lifetime * NANOS_PER_MILLI
            && (sample->0 as int) < (live_s as int) * NANOS_PER_SECOND
            && (lifetime as int) * NANOS_PER_MILLI * (NANOS_PER_SECOND + rate_ppb)
                <= ((live_s as int) * NANOS_PER_SECOND - (sample->0 as int)) * NANOS_PER_SECOND,
))]
pub fn portable(
    earliest: u64,
    latest: u64,
    trusted: bool,
    max_width: u64,
    rate_ppb: u32,
    sample: Option<u64>,
    live_s: u32,
) -> Result<(u64, u32), Absent> {
    if !trusted {
        return Err(Absent::Untrusted);
    }
    if latest < earliest || latest - earliest > max_width {
        return Err(Absent::WidthExceeded);
    }
    if earliest == 0 {
        return Err(Absent::EarliestZero);
    }
    let sample = match sample {
        Some(sample) => sample,
        None => return Err(Absent::MonotonicUnavailable),
    };
    let live = live_s as u64 * NANOS_PER_SECOND;
    if sample >= live {
        return Err(Absent::LiveDeadlinePassed);
    }
    let remaining = (live - sample) as u128;
    let scale = NANOS_PER_SECOND as u128 + rate_ppb as u128;
    #[cfg(verus_keep_ghost)]
    proof! {
        assert(remaining * 1_000_000_000u128 <= 0xFFFF_FFFF_FFFF_FFFFu128 * 1_000_000_000u128) by (nonlinear_arith)
            requires remaining <= 0xFFFF_FFFF_FFFF_FFFFu128;
    }
    let physical = remaining * NANOS_PER_SECOND as u128 / scale;
    let millis = physical / NANOS_PER_MILLI as u128;
    #[cfg(verus_keep_ghost)]
    proof! {
        let (r, s, p, m) = (remaining as int, scale as int, physical as int, millis as int);
        assert(p * s <= r * 1_000_000_000) by (nonlinear_arith)
            requires p == (r * 1_000_000_000) / s, s > 0, r >= 0;
        assert(m * 1_000_000 <= p) by (nonlinear_arith)
            requires m == p / 1_000_000, p >= 0;
    }
    let lifetime = if millis > u32::MAX as u128 {
        u32::MAX
    } else {
        millis as u32
    };
    if lifetime == 0 {
        return Err(Absent::LiveDeadlinePassed);
    }
    #[cfg(verus_keep_ghost)]
    proof! {
        let (r, s, p, m, l) = (remaining as int, scale as int, physical as int, millis as int, lifetime as int);
        assert(l * 1_000_000 * s <= r * 1_000_000_000) by (nonlinear_arith)
            requires
                0 <= l <= m,
                m * 1_000_000 <= p,
                p * s <= r * 1_000_000_000,
                s > 0;
    }
    let span = lifetime as u64 * NANOS_PER_MILLI;
    match earliest.checked_add(span) {
        Some(deadline) => Ok((deadline, lifetime)),
        None => Err(Absent::Overflow),
    }
}
