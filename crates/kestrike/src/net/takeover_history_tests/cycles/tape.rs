//! The open-loop arrival tape of a cycle run and the buckets its requests settle in.
//!
//! Every draw is an integer from one `SplitMix64` stream seeded by the run, so a report depends on no host
//! floating-point library. A phase's arrivals carry ticks that never decrease and may repeat; [`Phase::runnable`]
//! returns every arrival due at a tick, after which [`Phase::next_due`] is the next tick strictly after it, so
//! same-tick arrivals are all offered and a phase never waits on an arrival that is already due. Each offered request
//! settles in exactly one bucket of [`Buckets`], which [`Buckets::settled`] checks against `offered`.

use crate::storage::seeded::SplitMix64;

/// What an arrival asks of the shard. The operand is a raw draw the cycle reduces against the state when it offers
/// the arrival.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Get(u64),
    Fill,
    Invalidate(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Arrival {
    pub(super) tick: u64,
    pub(super) kind: Kind,
}

/// The percentages of a phase's arrivals that are FILLs and INVALIDATEs; the rest are GETs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Mix {
    pub(crate) fill: u64,
    pub(crate) invalidate: u64,
}

/// The run's one stream of integer draws.
pub(super) struct Tape(SplitMix64);

impl Tape {
    pub(super) fn new(seed: u64) -> Self {
        Self(SplitMix64::new(seed))
    }

    /// A draw below `bound`, which is positive.
    pub(super) fn below(&mut self, bound: u64) -> u64 {
        self.0.below(bound)
    }

    /// `count` arrivals from tick 0, each at most `gap` ticks after the one before it, with `mix`'s kinds.
    pub(super) fn phase(&mut self, count: u32, gap: u64, mix: Mix) -> Phase {
        let mut tick = 0;
        let arrivals = (0..count)
            .map(|_| {
                tick += self.below(gap + 1);
                let (kind, operand) = (self.below(100), self.0.next_u64());
                let kind = if kind < mix.fill {
                    Kind::Fill
                } else if kind < mix.fill + mix.invalidate {
                    Kind::Invalidate(operand)
                } else {
                    Kind::Get(operand)
                };
                Arrival { tick, kind }
            })
            .collect();
        Phase {
            arrivals,
            offered: 0,
        }
    }
}

/// One phase's arrivals in tick order and how many of them were offered.
pub(super) struct Phase {
    arrivals: Vec<Arrival>,
    offered: usize,
}

impl Phase {
    /// Every arrival due at or before `now` that was not yet offered, marked offered.
    pub(super) fn runnable(&mut self, now: u64) -> Vec<Arrival> {
        let due = self.arrivals[self.offered..].partition_point(|arrival| arrival.tick <= now);
        let from = self.offered;
        self.offered += due;
        self.arrivals[from..self.offered].to_vec()
    }

    /// The tick of the first arrival not yet offered; `None` when every arrival was offered. After `runnable(now)`
    /// it is strictly after `now`.
    pub(super) fn next_due(&self) -> Option<u64> {
        self.arrivals.get(self.offered).map(|arrival| arrival.tick)
    }

    /// Whether every arrival was offered.
    pub(super) fn exhausted(&self) -> bool {
        self.offered == self.arrivals.len()
    }
}

/// The terminal buckets of one phase's offered requests. A GET ends `retained` on an exact hit of an entry of the
/// retained set, `fresh` on an exact hit of an object the serving tenure published, `miss`, `refused` under
/// pressure, at admission or at its tick while no tenure serves, `timed_out`, `errored`, or `interrupted` by the
/// cut. A FILL or INVALIDATE ends `applied` when acknowledged and otherwise as a GET does. [`Buckets::dropped`]
/// counts the offered requests that settled in no bucket.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Buckets {
    pub(crate) offered: u64,
    pub(crate) retained: u64,
    pub(crate) fresh: u64,
    pub(crate) miss: u64,
    pub(crate) applied: u64,
    pub(crate) refused: u64,
    pub(crate) timed_out: u64,
    pub(crate) errored: u64,
    pub(crate) interrupted: u64,
}

impl Buckets {
    /// The requests settled in a terminal bucket.
    pub(crate) fn sum(&self) -> u64 {
        self.retained
            + self.fresh
            + self.miss
            + self.applied
            + self.refused
            + self.timed_out
            + self.errored
            + self.interrupted
    }

    /// The offered requests that settled in no bucket.
    pub(crate) fn dropped(&self) -> u64 {
        self.offered.saturating_sub(self.sum())
    }

    /// Whether every offered request settled in exactly one bucket: none dropped and none settled twice.
    pub(crate) fn settled(&self) -> bool {
        self.offered == self.sum()
    }
}

/// One phase's counts: its buckets, the misses that go to the origin, the device commands the tenure accepted, the
/// bytes its complete reads delivered, the ticks its requests waited from arrival to settlement, and the most
/// resident and reserved bytes the pool held at the phase's start, after each of its rounds and after each FILL and
/// INVALIDATE. A FILL's own rounds are sampled at its end, so a reservation the FILL releases is in the peak only
/// when a later sample still holds it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PhaseReport {
    pub(crate) buckets: Buckets,
    pub(crate) origin_demand: u64,
    pub(crate) operations: u64,
    pub(crate) bytes: u64,
    pub(crate) waited: u64,
    pub(crate) waited_max: u64,
    pub(crate) peak_charged: u64,
}

impl PhaseReport {
    /// Records that a request which arrived at `arrived` settled at `now`.
    pub(super) fn waited(&mut self, arrived: u64, now: u64) {
        let waited = now.saturating_sub(arrived);
        self.waited += waited;
        self.waited_max = self.waited_max.max(waited);
    }
}
