//! Token-bucket pacing for datagrams: over any interval of `t` seconds a pacer admits at most `burst + rate * t` datagrams; and byte shaping for one endpoint's whole egress, at a rate learned from the host's bandwidth allowance.
//!
//! Tokens are kept in millionths, so a refill over whole microseconds keeps sub-token credit up to the cap; the cap is the burst, which also bounds what a late wake can spend.
//! Every whole datagram sent, first send or retry, takes one token from its destination's pacer.

/// Datagram pacing for one destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pacer {
    /// Datagrams per second; at least 1.
    rate: u64,
    /// Tokens the bucket holds at most, in millionths.
    cap: u64,
    tokens: u64,
    last_us: u64,
}

const SCALE: u64 = 1_000_000;

impl Pacer {
    /// A full bucket of `burst` datagrams refilling at `rate_per_sec`, each taken as at least 1, as of `now_us`.
    pub fn new(rate_per_sec: u64, burst: u64, now_us: u64) -> Self {
        let cap = burst.max(1).saturating_mul(SCALE);
        Self {
            rate: rate_per_sec.max(1),
            cap,
            tokens: cap,
            last_us: now_us,
        }
    }

    #[inline]
    fn refill(&mut self, now_us: u64) {
        if now_us <= self.last_us {
            return;
        }
        let gained = (now_us - self.last_us).saturating_mul(self.rate);
        self.last_us = now_us;
        self.tokens = self.tokens.saturating_add(gained).min(self.cap);
    }

    /// Whether one datagram's token is available at `now_us`; a true answer lets the caller [`spend`](Self::spend) it after the send.
    #[inline]
    pub(super) fn ready(&mut self, now_us: u64) -> bool {
        self.refill(now_us);
        self.tokens >= SCALE
    }

    /// Spends the token [`ready`](Self::ready) reported available at the same instant.
    #[inline]
    pub(super) fn spend(&mut self) {
        debug_assert!(self.tokens >= SCALE, "spend follows a ready check");
        self.tokens -= SCALE;
    }

    /// Takes one datagram's token at `now_us`, or returns false and takes nothing.
    #[inline]
    pub fn take(&mut self, now_us: u64) -> bool {
        self.refill(now_us);
        if self.tokens < SCALE {
            return false;
        }
        self.tokens -= SCALE;
        true
    }

    /// Returns the token of a datagram that was spent and then went unsent, up to the cap.
    pub fn refund(&mut self) {
        self.tokens = self.tokens.saturating_add(SCALE).min(self.cap);
    }

    /// The earliest time at or after `now_us` when one token is available.
    ///
    /// The wait runs from the last forward sample, so a `now_us` before that
    /// sample gets a deadline measured from it. A due time past the clock
    /// saturates at `u64::MAX`, where the bucket can hold less than one token.
    #[inline]
    pub fn ready_at(&mut self, now_us: u64) -> u64 {
        self.refill(now_us);
        if self.tokens >= SCALE {
            return now_us;
        }
        let missing = SCALE - self.tokens;
        self.last_us.saturating_add(missing.div_ceil(self.rate))
    }
}

#[cfg(test)]
impl Pacer {
    /// The full state as `(rate, cap, tokens, last_us)`, with `cap` and
    /// `tokens` in millionths of a token.
    pub(super) fn parts(&self) -> (u64, u64, u64, u64) {
        (self.rate, self.cap, self.tokens, self.last_us)
    }
}

/// Egress shaping for one endpoint: a byte token bucket whose rate follows the share of the host's outbound bandwidth allowance the endpoint can use, learned from the allowance-exceeded count the device reports.
///
/// A new shaper admits everything. Each [`Shaper::CONTROL_US`] the endpoint reports the device's exceeded count: a count that rose shapes an unshaped shaper at seven eighths of its measured egress and otherwise lowers the rate by an eighth, and a count that held raises it by [`Shaper::STEP`], so the rate saws just below the share whose bursts the allowance queues, within [`Shaper::FLOOR`] and [`Shaper::CEILING`] bytes per second; the bucket holds [`Shaper::BURST`] bytes. The egress a shaped interval measures is the shaper's own output, so only the exceeded count moves the rate.
///
/// Two endpoints converge toward equal shares under five premises: (a) each endpoint's control steps see every shared rise of the count as exactly one cut; (b) both run equal effective control periods; (c) both are already shaped and backlogged; (d) both rates stay inside [`Shaper::FLOOR`] and [`Shaper::CEILING`] through each step, which needs the fair share inside that range, so the allowance lies between twice the floor and twice the ceiling; and (e) only their shaped egress drives the exceedance. Then each shared cut multiplies the difference of their rates by seven eighths, to within a byte per second per cut, about 5.2 cuts per halving, and each held step adds [`Shaper::STEP`] to both, so the difference holds while the sum grows and the shares move toward equal.
///
/// Outside that regime lie idle-then-return demand, whose idle endpoint climbs on held counts and returns above its share; a rise one endpoint's step sees and the other's does not; differing control periods, which the owner's control tick, firing at or after the due time, can produce; a missing count on one endpoint; a step that clamps either rate, the floor holding the lower rate on a cut or the ceiling the higher on a held step; a share below the floor; and exceedance that egress outside the shapers drives.
///
/// The count is per device, so two endpoints see a shared rise only through one device's counter; whether two devices under one instance allowance report a shared rise is outside this crate.
///
/// [`take`](Shaper::take) charges a datagram's bytes to the bucket and to the control interval's egress at staging, and [`refund`](Shaper::refund) returns both for a staged datagram that went unsent, so the interval's egress is exact once every staged datagram settled, which happens before the endpoint's control step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shaper {
    /// The shaped bytes per second, or [`Shaper::UNSHAPED`] until the allowance was first exceeded.
    rate: u64,
    /// Bytes in the bucket; meaningful once shaped.
    tokens: u64,
    /// When the bucket was last refilled; the control step that shapes the shaper sets it, so it is current from the first shaped refill on.
    last_us: u64,
    /// Bytes charged since the control interval began, and when it began.
    window_start_us: u64,
    window_bytes: u64,
    /// The exceeded count at the last control step, once a step recorded one.
    exceeded: Option<u64>,
}

impl Shaper {
    /// Bytes per second the shaper admits at least, whatever it learned.
    pub const FLOOR: u64 = 500_000_000;
    /// Bytes per second the rate rises to at most.
    pub const CEILING: u64 = 12_500_000_000;
    /// Bytes per second a held count adds to the rate each control step.
    pub const STEP: u64 = 10_000_000;
    /// Bytes the bucket holds: the most that leaves at line rate above the shaped rate.
    pub const BURST: u64 = 128 << 10;
    /// Microseconds between control steps.
    pub const CONTROL_US: u64 = 20_000;
    /// The rate until the allowance was first exceeded: everything leaves.
    pub const UNSHAPED: u64 = u64::MAX;

    /// An unshaped shaper whose first control interval starts at `now_us`.
    pub fn new(now_us: u64) -> Self {
        Self {
            rate: Self::UNSHAPED,
            tokens: Self::BURST,
            last_us: now_us,
            window_start_us: now_us,
            window_bytes: 0,
            exceeded: None,
        }
    }

    pub fn rate(&self) -> u64 {
        self.rate
    }

    /// When the next control step is due.
    pub fn control_due_us(&self) -> u64 {
        self.window_start_us.saturating_add(Self::CONTROL_US)
    }

    /// Refills a shaped bucket for the whole microseconds since its last refill. Whole microseconds at a rate of at least the floor refill at least 500 bytes each, so the truncation stays below a byte per refill; a product past `u64` saturates, which fills the bucket, as the exact product would.
    #[inline]
    fn refill(&mut self, now_us: u64) {
        if now_us <= self.last_us {
            return;
        }
        let gained = (now_us - self.last_us).saturating_mul(self.rate) / SCALE;
        self.last_us = now_us;
        self.tokens = self.tokens.saturating_add(gained).min(Self::BURST);
    }

    /// Whether a datagram of `bytes` may stage at `now_us`: always while unshaped, and otherwise once the refilled bucket holds its bytes; a datagram larger than the bucket leaves once the bucket is full.
    #[inline]
    pub fn ready(&mut self, now_us: u64, bytes: u64) -> bool {
        if self.rate == Self::UNSHAPED {
            return true;
        }
        self.refill(now_us);
        self.tokens >= bytes.min(Self::BURST)
    }

    /// Charges `bytes` of a datagram staged at `now_us` to the control interval's egress and, once shaped, to the bucket, or returns false and charges nothing while [`ready`](Self::ready) refuses it.
    #[inline]
    pub fn take(&mut self, now_us: u64, bytes: u64) -> bool {
        if !self.ready(now_us, bytes) {
            return false;
        }
        if self.rate != Self::UNSHAPED {
            self.tokens = self.tokens.saturating_sub(bytes);
        }
        self.window_bytes = self.window_bytes.saturating_add(bytes);
        true
    }

    /// Returns the bytes of a datagram that was taken and then went unsent: to the bucket, up to its size, and from the interval's egress.
    #[inline]
    pub fn refund(&mut self, bytes: u64) {
        if self.rate != Self::UNSHAPED {
            self.tokens = self.tokens.saturating_add(bytes).min(Self::BURST);
        }
        self.window_bytes = self.window_bytes.saturating_sub(bytes);
    }

    /// One control step at `now_us`. It compares the device's cumulative `exceeded` count with the last recorded count: an increase lowers the rate, from the interval's measured egress when the shaper was unshaped, and an unchanged count raises it. The first recorded count leaves the rate unshaped. `None`, a device that reported no count, keeps the rate and the comparison baseline. Every step starts the next control interval.
    pub fn control(&mut self, now_us: u64, exceeded: Option<u64>) {
        if let (Some(last), Some(count)) = (self.exceeded, exceeded) {
            if count > last {
                let from = if self.rate == Self::UNSHAPED {
                    let elapsed = now_us.saturating_sub(self.window_start_us).max(1);
                    self.tokens = Self::BURST;
                    self.last_us = now_us;
                    (u128::from(self.window_bytes) * u128::from(SCALE) / u128::from(elapsed)) as u64
                } else {
                    self.rate
                };
                self.rate = (from - from / 8).clamp(Self::FLOOR, Self::CEILING);
            } else if self.rate != Self::UNSHAPED {
                self.rate = self.rate.saturating_add(Self::STEP).min(Self::CEILING);
            }
        }
        self.exceeded = exceeded.or(self.exceeded);
        self.window_start_us = now_us;
        self.window_bytes = 0;
    }
}
