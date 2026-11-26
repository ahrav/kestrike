//! When a capture pass starts and how fast its checkpoint units are submitted.
//!
//! # Triggers
//!
//! A pass is due when none is in flight and either `byte_trigger` bytes have changed since the last start, `time_ceiling_ns` has elapsed since it, or a planned restart has stopped fills.
//!
//! # Pacing and the boost
//!
//! Side-list pressure switches submissions from the paced interval to the fast interval. A capacity covering `n_max` keeps the paced interval because the whole snapshot fits the side list.
//!
//! # Sizing
//!
//! A pass walks `slot_bound` slots, empty slots included, at `UNIT_ENTRIES` slot visits per submitted unit. `reserve` budgets removals at `max_removals_per_second` over the worst boosted remainder: one paced interval before the writer observes pressure, then every unit at the fast interval, each delayed by up to `decision_ns`. `CapturePolicy::new` requires `q_cap >= min(2 * reserve, n_max)`. When `q_cap < n_max`, the boost threshold `q_cap - reserve` leaves a whole reserve of headroom.
//!
//! The sizing assumes a writer that calls `unit_due` within `decision_ns` of each due time, visits `UNIT_ENTRIES` slots per submitted unit, and calls `submitted` for each unit it submits.

use super::super::geometry::EXTENT_LIMIT;
use super::super::ledger::EngineBudget;
use super::capture::{CaptureEntry, CaptureError};
use crate::failover::records::UNIT_ENTRIES;
/// `CapturePolicy::new` validates `CaptureConfig` before constructing a policy.
#[derive(Debug, Clone, Copy)]
pub struct CaptureConfig {
    /// Most members one pass may checkpoint.
    pub n_max: usize,
    /// `slot_bound` limits the pool's total slot count, including empty slots. A pass can admit at most `min(n_max, slot_bound)` members.
    pub slot_bound: usize,
    /// Changed bytes that make a pass due.
    pub byte_trigger: u64,
    /// Nanoseconds since the last start that make a pass due.
    pub time_ceiling_ns: u64,
    /// Interval between units before the boost.
    pub paced_unit_ns: u64,
    /// Interval between units after the boost.
    pub fast_unit_ns: u64,
    /// Maximum writer delay after a pacing deadline, included in removal reserve sizing.
    pub decision_ns: u64,
    /// Removal rate the side-list reserve is sized for.
    pub max_removals_per_second: u64,
    /// Side-list capacity in entries.
    pub q_cap: usize,
    /// Side-list capacity in extent words; at least `min(q_cap, n_max)`, one word per entry.
    pub extent_words: usize,
}
/// Trigger and pacing state for one storage's captures. Time arguments are nanoseconds on one monotonic clock.
#[derive(Debug)]
pub struct CapturePolicy {
    config: CaptureConfig,
    // Covers pressure-detection delay and the remaining fast submissions.
    reserve: usize,
    // changed bytes since the last start
    bytes: u64,
    last_start: u64,
    // earliest time the next unit may be submitted
    next_unit: u64,
    in_flight: bool,
    boosted: bool,
}
impl CapturePolicy {
    /// `CapturePolicy::new` validates `config`, derives `reserve`, charges the worst-case capture memory to `budget`, and starts the time ceiling at `now`.
    ///
    /// The charge covers `min(q_cap, n_max)` side-list entries plus the entry a visit returns and the entry an overflowing removal drops. It caps extent words at `EXTENT_LIMIT` per entry and `extent_words + 2 * EXTENT_LIMIT` in total; the side list is capped at `extent_words` words, so a pass holds no more words than the charge covers.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` rejects a zero bound or interval, `paced_unit_ns < fast_unit_ns`, `q_cap` below the sizing floor, `extent_words` below `min(q_cap, n_max)`, and arithmetic overflow. `Memory` rejects a charge past the budget's limit; the budget is unchanged.
    pub fn new(
        config: CaptureConfig,
        now: u64,
        budget: &mut EngineBudget,
    ) -> Result<Self, CaptureError> {
        let c = config;
        let zero = [c.n_max, c.slot_bound, c.q_cap, c.extent_words].contains(&0)
            || [
                c.byte_trigger,
                c.time_ceiling_ns,
                c.fast_unit_ns,
                c.decision_ns,
            ]
            .contains(&0);
        if zero || c.max_removals_per_second == 0 || c.paced_unit_ns < c.fast_unit_ns {
            return Err(CaptureError::InvalidConfig);
        }
        let units = 1 + c.slot_bound.div_ceil(UNIT_ENTRIES as usize);
        let duration = u128::from(c.paced_unit_ns)
            + u128::from(c.decision_ns)
            + (units as u128 + 1) * (u128::from(c.fast_unit_ns) + u128::from(c.decision_ns));
        if duration > u128::from(u64::MAX) {
            return Err(CaptureError::InvalidConfig);
        }
        let reserve = (duration * u128::from(c.max_removals_per_second)).div_ceil(1_000_000_000);
        let reserve = usize::try_from(reserve).map_err(|_| CaptureError::InvalidConfig)?;
        let minimum = reserve
            .checked_mul(2)
            .ok_or(CaptureError::InvalidConfig)?
            .min(c.n_max);
        if c.q_cap < minimum || (units as u128) * u128::from(c.paced_unit_ns) > u128::from(u64::MAX)
        {
            return Err(CaptureError::InvalidConfig);
        }
        if c.extent_words < c.q_cap.min(c.n_max) {
            return Err(CaptureError::InvalidConfig);
        }
        let entries = c
            .q_cap
            .min(c.n_max)
            .checked_add(2)
            .ok_or(CaptureError::InvalidConfig)?;
        let limit = EXTENT_LIMIT as usize;
        let words = entries
            .saturating_mul(limit)
            .min(c.extent_words.saturating_add(2 * limit));
        let bytes = entries
            .checked_mul(std::mem::size_of::<CaptureEntry>())
            .and_then(|b| {
                words
                    .checked_mul(std::mem::size_of::<u64>())
                    .and_then(|w| b.checked_add(w))
            })
            .ok_or(CaptureError::InvalidConfig)?;
        budget.charge(bytes).map_err(CaptureError::Memory)?;
        Ok(Self {
            config,
            reserve,
            bytes: 0,
            last_start: now,
            next_unit: now,
            in_flight: false,
            boosted: false,
        })
    }
    /// Adds `bytes` toward `byte_trigger`, saturating. Bytes changed during a pass count toward the next one.
    pub fn changed_bytes(&mut self, bytes: u64) {
        self.bytes = self.bytes.saturating_add(bytes);
    }
    /// Whether a pass should start at `now`: none in flight and a trigger holds (bytes, time ceiling, or `planned_restart && fill_stopped`).
    pub fn due(&self, now: u64, planned_restart: bool, fill_stopped: bool) -> bool {
        !self.in_flight
            && (self.bytes >= self.config.byte_trigger
                || now.saturating_sub(self.last_start) >= self.config.time_ceiling_ns
                || (planned_restart && fill_stopped))
    }
    /// Records a pass started at `now`: clears the byte count and the boost, restarts the time ceiling, and makes the first unit due immediately.
    ///
    /// # Errors
    ///
    /// `InFlight` if a pass is already recorded in flight.
    pub fn started(&mut self, now: u64) -> Result<(), CaptureError> {
        if self.in_flight {
            return Err(CaptureError::InFlight);
        }
        self.in_flight = true;
        self.boosted = false;
        self.bytes = 0;
        self.last_start = now;
        self.next_unit = now;
        Ok(())
    }
    /// During a pass whose `q_cap` is below `n_max`, the first call that sees `side_entries >= q_cap - reserve` latches the boost and makes a unit due at once; `started` clears the latch. With no pass in flight the result is false and the state is unchanged.
    pub fn unit_due(&mut self, now: u64, side_entries: usize) -> bool {
        if self.in_flight
            && !self.boosted
            && self.config.q_cap < self.config.n_max
            && side_entries >= self.config.q_cap.saturating_sub(self.reserve)
        {
            self.boosted = true;
            self.next_unit = self.next_unit.min(now);
        }
        self.in_flight && now >= self.next_unit
    }
    /// `submitted` schedules the next unit one interval after the actual submission time `now`, using the fast interval once boosted and the paced interval otherwise.
    ///
    /// # Errors
    ///
    /// - `Idle` if no pass is in flight.
    /// - `NotDue` if `now` precedes the scheduled time of the next unit.
    /// - `InvalidConfig` if the next due time overflows `u64`.
    pub fn submitted(&mut self, now: u64) -> Result<(), CaptureError> {
        if !self.in_flight {
            return Err(CaptureError::Idle);
        }
        if now < self.next_unit {
            return Err(CaptureError::NotDue);
        }
        let interval = if self.boosted {
            self.config.fast_unit_ns
        } else {
            self.config.paced_unit_ns
        };
        self.next_unit = now
            .checked_add(interval)
            .ok_or(CaptureError::InvalidConfig)?;
        Ok(())
    }
    /// Records the pass ended; the time ceiling keeps counting from the pass's start.
    pub fn finished(&mut self) {
        self.in_flight = false;
    }
    pub fn n_max(&self) -> usize {
        self.config.n_max
    }
    pub fn slot_bound(&self) -> usize {
        self.config.slot_bound
    }
    /// The side-list capacity handed to `Capture::start`: `q_cap` entries and `extent_words` words.
    pub fn side_cap(&self) -> super::SideCap {
        super::SideCap {
            entries: self.config.q_cap,
            words: self.config.extent_words,
        }
    }
}
