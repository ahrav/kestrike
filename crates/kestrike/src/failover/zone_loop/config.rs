//! One zone's reconciler configuration and the bounds it validates into. Every `_us` time is in microseconds on the
//! loop's own elapsed clock; the [`OwnerBounds`] times are in the owners' unit that `Bounds::new` takes. Each timer
//! and limit of [`ZoneConfig`] with a fixed default takes it from the constant of the same name in upper case; the
//! census cap defaults to the shard count passed to [`ZoneConfig::defaults`], and `report_period_us` is always
//! supplied.
//!
//! - ZONE-BOUNDS: a [`ZoneBounds`] exists only as the result of [`ZoneConfig::validate`]. Every timer, count and
//!   limit of its configuration is nonzero, and so is every owners' bound except the clock error. The replacement
//!   layout meets [`Layout::check_floor`], whose entry cap may be zero. The configuration meets every relation a
//!   [`ConfigRefusal`] names, and each derived window fits `u64`.
//! - A population cap below the zone's shard count passes validation; [`ZoneBounds::cap_below_shards`] reports it.

use std::path::PathBuf;

use crate::failover::bounds::{Bounds, BoundsError};
use crate::failover::identity::is_az;
use crate::failover::records::{Layout, LayoutRefusal, delta_blocks};
use crate::failover::standbys::{MAX_SLOTS, Zone};
use crate::failover::zone_loop::directory::Directory;

/// Default: the loop's tick period, 10 s.
pub const TICK_US: u64 = 10_000_000;
/// Default: the report periods within which a host's report sequence must have advanced for the host to read as
/// reporting, 3.
pub const FRESH_PERIODS: u32 = 3;
/// Default: the report periods of silence that, with instance evidence, let a host read as lost, 6.
pub const SILENT_PERIODS: u32 = 6;
/// Default: how long an instance reads stopped before its silence counts as loss, 300 s.
pub const STOPPED_DWELL_US: u64 = 300_000_000;
/// Default: how long an instance's status checks read impaired before its silence counts as loss, 180 s.
pub const IMPAIRED_DWELL_US: u64 = 180_000_000;
/// Default: the consecutive complete listings an instance is absent from before its silence counts as loss, 2.
pub const ABSENT_TICKS: u32 = 2;
/// Default: the consecutive complete observations of state `error` that make a volume lost, 2.
pub const LOSS_TICKS: u32 = 2;
/// Default: how long a recorded attach waits for its listing to show it before the loop acts on it again, 30 s.
pub const ATTACH_SETTLE_US: u64 = 30_000_000;
/// Default: how long an attach may stay unsettled before the loop treats it as stuck, 900 s.
pub const ATTACH_STUCK_US: u64 = 900_000_000;
/// Default: the settle time of a detach, 300 s: the least time between two detach requests for one entry, between
/// the return of an entry's last attach or detach request and the first listing kept for its release, and between
/// the two listings of a release. It is the `settle` of the `Settle` the loop passes to
/// `Reconciler::release_attach`, so it covers a listing call's duration, the control plane's consistency lag, the
/// landing delay of an earlier request and the time an owner's poll holds a listing.
pub const DETACH_SETTLE_US: u64 = 300_000_000;
/// The value `detach_settle_us` must exceed, 120 s. It equals the listing hold of the owner's poll
/// (`failover::reconcile::LISTING_HOLD_US`): the bound on the span from a listing's request to the volume record read
/// of the owner's poll that judges it, which every owner's periods (`host::duties::Periods`) must stay below.
/// [`ZoneConfig::validate`] checks the loop's side of that premise only. With a settle time at or below the hold, an
/// owner's poll could judge a listing taken before a detach against a record that already holds the entry gone, and
/// retire a healthy volume.
pub const DETACH_SETTLE_FLOOR_US: u64 = 120_000_000;
/// Default: how long an attached host may stay unenrolled before the loop treats its enrollment as stuck, 300 s.
pub const ENROLL_STUCK_US: u64 = 300_000_000;
/// Default: how long an issued create waits for its volume to list, 300 s.
pub const CREATE_SETTLE_US: u64 = 300_000_000;
/// Default: the time within which a shard without a live named standby should have one designated, 600 s. It is a
/// completion deadline and a monitor threshold.
pub const STANDBY_TARGET_US: u64 = 600_000_000;
/// Default: volume replacements in flight in the zone, 1.
pub const REPLACEMENTS_INFLIGHT_MAX: u32 = 1;
/// Default: create attempts of one replacement, 3.
pub const CREATE_ATTEMPTS_MAX: u32 = 3;
/// Default: the first wait after a failed create, 60 s, doubling per attempt.
pub const CREATE_BACKOFF_US: u64 = 60_000_000;
/// Default: the longest wait after a failed create, 600 s.
pub const CREATE_BACKOFF_MAX_US: u64 = 600_000_000;
/// Default: standby enrollments in flight in the zone, 4.
pub const ENROLL_INFLIGHT_MAX: u32 = 4;
/// Default: new attach starts admitted per [`ATTACH_WINDOW_US`], 16.
pub const ATTACH_STARTS_PER_WINDOW: u32 = 16;
/// Default: the window of the attach start rate, 600 s.
pub const ATTACH_WINDOW_US: u64 = 600_000_000;
/// Default: the zone host hold starts above this fraction of the zone's active hosts read lost or unknown, one
/// quarter.
pub const HOST_HOLD: Fraction = Fraction {
    numerator: 1,
    denominator: 4,
};
/// Default: census entries that may name one host, 6.
pub const STANDBYS_PER_HOST_MAX: u32 = 6;
/// The roles one host holds, owned shards and census entries together, 10: the value an operator writes into a
/// directory's `host_roles_max`.
pub const HOST_ROLES_MAX: u32 = 10;
/// Default: store writes one tick issues, 32.
pub const WRITES_PER_TICK: u32 = 32;
/// Default: mutating provider calls one tick issues, 8.
pub const CALLS_PER_TICK: u32 = 8;

/// `Fraction` is a share of a zone's hosts and keeps both terms as written. [`Fraction::exceeded_by`] tests a host
/// count against it. A [`ZoneBounds`] holds only a fraction with `0 < numerator < denominator`. Index geometry has
/// its own ratio with `usize` terms, `crate::index::Ratio`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fraction {
    pub numerator: u32,
    pub denominator: u32,
}

impl Fraction {
    /// Whether `count` exceeds this fraction of `of`: `count × denominator > of × numerator`, in `u128`. With a zero
    /// denominator it returns `false` for every `count`.
    pub fn exceeded_by(self, count: usize, of: usize) -> bool {
        let scaled = |value: usize, by: u32| (value as u128) * u128::from(by);
        scaled(count, self.denominator) > scaled(of, self.numerator)
    }
}

/// The inputs of the owners' serving bounds, [`Bounds::new`]'s arguments, which the loop's attach rule reads through
/// [`Bounds::pair_cap`]. The times are in the owners' serving-clock unit, which the soak binary's operator inputs
/// give in microseconds. Validation checks the values among themselves; the operator matches them to the running
/// owners' settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerBounds {
    pub registrant_max: u32,
    pub retry_max: u32,
    pub window: u64,
    pub report_deadline: u64,
    /// The device Report period, apart from the host report period.
    pub report_period: u64,
    pub clock_error: u64,
}

/// One zone's reconciler configuration, as an operator writes it. [`ZoneConfig::validate`] turns it into the
/// [`ZoneBounds`] the loop is built with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneConfig {
    pub zone: Zone,
    /// The control plane's availability-zone name: 1 to 63 bytes of ASCII lowercase letters, digits or `-`.
    pub name: String,
    pub owner: OwnerBounds,
    /// The layout for the zone's replacement volumes. The directory's `ShardEntry::layout` reports the layout of a
    /// shard's existing volumes.
    pub replacement: Layout,
    /// Where the zone's fleet directory is read from, an absolute path.
    pub directory: PathBuf,
    /// The host report producer's sealing period.
    pub report_period_us: u64,
    pub tick_us: u64,
    pub fresh_periods: u32,
    pub silent_periods: u32,
    pub stopped_dwell_us: u64,
    pub impaired_dwell_us: u64,
    pub absent_ticks: u32,
    pub loss_ticks: u32,
    pub attach_settle_us: u64,
    pub attach_stuck_us: u64,
    pub detach_settle_us: u64,
    pub enroll_stuck_us: u64,
    pub create_settle_us: u64,
    pub standby_target_us: u64,
    pub replacements_inflight_max: u32,
    pub create_attempts_max: u32,
    pub create_backoff_us: u64,
    pub create_backoff_max_us: u64,
    pub enroll_inflight_max: u32,
    pub attach_starts_per_window: u32,
    pub attach_window_us: u64,
    pub host_hold: Fraction,
    pub standbys_per_host_max: u32,
    /// The census admission limit (POPULATION-CAP in `failover::standbys`): the census adds a shard only while it
    /// lists fewer than this many. A census that already lists more keeps its entries.
    pub population_cap: usize,
    /// The store-writing steps one actuation makes (ONE-ATTEMPT in `zone_loop::actuate`). A step counts once
    /// whatever number of store writes its `Reconciler` call issues; a replacement's flip with the retirement of the
    /// displaced volume issues several. The retry of a displaced volume's retirement spends one unit each.
    /// A correlated hold's write spends a unit when one is left and proceeds at zero.
    pub writes_per_tick: u32,
    /// The attach requests, detach requests and replacement creates one actuation sends (ONE-ATTEMPT in
    /// `zone_loop::actuate`). Validation requires it above `enroll_inflight_max`: at most that many enrollments
    /// hold an attach entry, so their requests leave a call of every tick to the detaches and to a replacement.
    pub calls_per_tick: u32,
}

/// A configuration value [`ConfigRefusal`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    ReportPeriodUs,
    TickUs,
    FreshPeriods,
    SilentPeriods,
    StoppedDwellUs,
    ImpairedDwellUs,
    AbsentTicks,
    LossTicks,
    AttachSettleUs,
    AttachStuckUs,
    DetachSettleUs,
    EnrollStuckUs,
    CreateSettleUs,
    StandbyTargetUs,
    ReplacementsInflightMax,
    CreateAttemptsMax,
    CreateBackoffUs,
    CreateBackoffMaxUs,
    EnrollInflightMax,
    AttachStartsPerWindow,
    AttachWindowUs,
    HostHold,
    StandbysPerHostMax,
    PopulationCap,
    WritesPerTick,
    CallsPerTick,
}

/// The first check [`ZoneConfig::validate`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigRefusal {
    /// The zone name is empty, longer than 63 bytes or holds a byte other than an ASCII lowercase letter, a digit or
    /// `-`.
    Name,
    /// The directory path is not absolute.
    Directory,
    /// The value is zero; for [`Field::HostHold`], either term of the fraction.
    Zero(Field),
    /// The owners' bounds refuse.
    Bounds(BoundsError),
    /// Validation requires [`Bounds::pair_cap`] of 3 or more, so the replacement can pair while the owner and a lost
    /// named standby still hold two recorded pairs.
    PairCap,
    /// The replacement layout fails [`Layout::check_floor`]: too few slots, a slot size other than its entry cap
    /// requires, or a prefix below the slots' floor.
    Layout(LayoutRefusal),
    /// The checkpoint slots take the replacement layout's whole prefix, leaving zero delta blocks for a mutation
    /// suffix.
    DeltaRegion,
    /// `fresh_periods` is below 2, so one late report would read as not reporting.
    FreshPeriods,
    /// `silent_periods` is not above `fresh_periods`.
    SilentPeriods,
    /// `loss_ticks` is below 2, so one observation of state `error` would make a volume lost.
    LossTicks,
    /// `tick_us` is above `report_period_us`, so the loop would read a host's reports less often than the host
    /// seals them.
    Tick,
    /// A dwell is at or above `standby_target_us`. For [`Field::StoppedDwellUs`] and [`Field::ImpairedDwellUs`] the
    /// dwell is the field's value; for [`Field::AbsentTicks`] and [`Field::LossTicks`] it spans `ticks - 1`
    /// intervals of `tick_us`.
    Dwell(Field),
    /// `attach_stuck_us` is not above `attach_settle_us`.
    AttachStuck,
    /// `detach_settle_us` is not above [`DETACH_SETTLE_FLOOR_US`], so an owner's poll could hold a listing longer
    /// than the settle time.
    DetachSettle,
    /// `create_backoff_max_us` is below `create_backoff_us`.
    Backoff,
    /// `create_attempts_max` is `u32::MAX`; incrementing a `u32` attempt counter at that limit overflows.
    CreateAttempts,
    /// The host hold fraction is at or above one.
    HostHold,
    /// `population_cap` is above [`MAX_SLOTS`], which no census can hold.
    PopulationCap,
    /// `calls_per_tick` is not above `enroll_inflight_max`, so the attach requests of the enrollments in flight
    /// could take every call of every tick and leave none to a replacement's create or attach request.
    Calls,
    /// A window `periods × report_period_us` does not fit `u64`.
    Overflow,
    /// The silent window `silent_periods × report_period_us` is at or above `standby_target_us`. If a host's report
    /// stays unchanged from the start of its tracking, the standby target arrives at or before the end of the silent
    /// window.
    Silence,
}

/// The warning [`ZoneBounds::cap_below_shards`] returns: the census cap and the larger shard count of the zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapBelowShards {
    pub cap: usize,
    pub shards: usize,
}

/// A validated [`ZoneConfig`] and the owners' [`Bounds`] it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneBounds {
    config: ZoneConfig,
    bounds: Bounds,
    fresh_us: u64,
    silent_us: u64,
}

impl ZoneConfig {
    /// The configuration of `zone` named `name` serving `shards` shards, with the owners' bounds `owner`, the
    /// replacement layout `replacement`, the directory at `directory` and the host report period
    /// `report_period_us`. The census cap defaults to `shards`; timers and limits with fixed defaults use their
    /// matching constants.
    ///
    /// With the timer defaults, [`ZoneConfig::validate`] accepts only `shards` from 1 to [`MAX_SLOTS`] and a report
    /// period from [`TICK_US`] to below [`STANDBY_TARGET_US`] / [`SILENT_PERIODS`], 10 s to under 100 s. These are
    /// necessary conditions: the name, directory, owner bounds and layout must also pass.
    pub fn defaults(
        zone: Zone,
        name: String,
        shards: usize,
        owner: OwnerBounds,
        replacement: Layout,
        directory: PathBuf,
        report_period_us: u64,
    ) -> Self {
        Self {
            zone,
            name,
            owner,
            replacement,
            directory,
            report_period_us,
            tick_us: TICK_US,
            fresh_periods: FRESH_PERIODS,
            silent_periods: SILENT_PERIODS,
            stopped_dwell_us: STOPPED_DWELL_US,
            impaired_dwell_us: IMPAIRED_DWELL_US,
            absent_ticks: ABSENT_TICKS,
            loss_ticks: LOSS_TICKS,
            attach_settle_us: ATTACH_SETTLE_US,
            attach_stuck_us: ATTACH_STUCK_US,
            detach_settle_us: DETACH_SETTLE_US,
            enroll_stuck_us: ENROLL_STUCK_US,
            create_settle_us: CREATE_SETTLE_US,
            standby_target_us: STANDBY_TARGET_US,
            replacements_inflight_max: REPLACEMENTS_INFLIGHT_MAX,
            create_attempts_max: CREATE_ATTEMPTS_MAX,
            create_backoff_us: CREATE_BACKOFF_US,
            create_backoff_max_us: CREATE_BACKOFF_MAX_US,
            enroll_inflight_max: ENROLL_INFLIGHT_MAX,
            attach_starts_per_window: ATTACH_STARTS_PER_WINDOW,
            attach_window_us: ATTACH_WINDOW_US,
            host_hold: HOST_HOLD,
            standbys_per_host_max: STANDBYS_PER_HOST_MAX,
            population_cap: shards,
            writes_per_tick: WRITES_PER_TICK,
            calls_per_tick: CALLS_PER_TICK,
        }
    }

    /// `first_zero` returns the first [`Field`] in declaration order whose value is zero; [`Field::HostHold`]
    /// qualifies when either term is zero. The pattern names every `ZoneConfig` field, the unchecked ones as `_`, so
    /// a new `ZoneConfig` field requires a matching entry in the pattern.
    fn first_zero(&self) -> Option<Field> {
        let Self {
            zone: _,
            name: _,
            owner: _,
            replacement: _,
            directory: _,
            report_period_us,
            tick_us,
            fresh_periods,
            silent_periods,
            stopped_dwell_us,
            impaired_dwell_us,
            absent_ticks,
            loss_ticks,
            attach_settle_us,
            attach_stuck_us,
            detach_settle_us,
            enroll_stuck_us,
            create_settle_us,
            standby_target_us,
            replacements_inflight_max,
            create_attempts_max,
            create_backoff_us,
            create_backoff_max_us,
            enroll_inflight_max,
            attach_starts_per_window,
            attach_window_us,
            host_hold,
            standbys_per_host_max,
            population_cap,
            writes_per_tick,
            calls_per_tick,
        } = *self;
        [
            (report_period_us == 0, Field::ReportPeriodUs),
            (tick_us == 0, Field::TickUs),
            (fresh_periods == 0, Field::FreshPeriods),
            (silent_periods == 0, Field::SilentPeriods),
            (stopped_dwell_us == 0, Field::StoppedDwellUs),
            (impaired_dwell_us == 0, Field::ImpairedDwellUs),
            (absent_ticks == 0, Field::AbsentTicks),
            (loss_ticks == 0, Field::LossTicks),
            (attach_settle_us == 0, Field::AttachSettleUs),
            (attach_stuck_us == 0, Field::AttachStuckUs),
            (detach_settle_us == 0, Field::DetachSettleUs),
            (enroll_stuck_us == 0, Field::EnrollStuckUs),
            (create_settle_us == 0, Field::CreateSettleUs),
            (standby_target_us == 0, Field::StandbyTargetUs),
            (
                replacements_inflight_max == 0,
                Field::ReplacementsInflightMax,
            ),
            (create_attempts_max == 0, Field::CreateAttemptsMax),
            (create_backoff_us == 0, Field::CreateBackoffUs),
            (create_backoff_max_us == 0, Field::CreateBackoffMaxUs),
            (enroll_inflight_max == 0, Field::EnrollInflightMax),
            (attach_starts_per_window == 0, Field::AttachStartsPerWindow),
            (attach_window_us == 0, Field::AttachWindowUs),
            (
                host_hold.numerator == 0 || host_hold.denominator == 0,
                Field::HostHold,
            ),
            (standbys_per_host_max == 0, Field::StandbysPerHostMax),
            (population_cap == 0, Field::PopulationCap),
            (writes_per_tick == 0, Field::WritesPerTick),
            (calls_per_tick == 0, Field::CallsPerTick),
        ]
        .into_iter()
        .find_map(|(zero, field)| zero.then_some(field))
    }

    /// The bounds this configuration names.
    ///
    /// # Errors
    ///
    /// The first failed check, in order: [`ConfigRefusal::Name`], [`ConfigRefusal::Directory`], a zero value in
    /// [`Field`] order, the owners' [`ConfigRefusal::Bounds`], [`ConfigRefusal::PairCap`], the replacement
    /// [`ConfigRefusal::Layout`], [`ConfigRefusal::DeltaRegion`], then [`ConfigRefusal::FreshPeriods`],
    /// [`ConfigRefusal::SilentPeriods`], [`ConfigRefusal::LossTicks`], [`ConfigRefusal::Tick`],
    /// [`ConfigRefusal::Dwell`] when any dwell (checked in stopped, impaired, absence, loss order) is at or above
    /// `standby_target_us`, [`ConfigRefusal::AttachStuck`], [`ConfigRefusal::DetachSettle`],
    /// [`ConfigRefusal::Backoff`], [`ConfigRefusal::CreateAttempts`], [`ConfigRefusal::HostHold`],
    /// [`ConfigRefusal::PopulationCap`], [`ConfigRefusal::Calls`], [`ConfigRefusal::Overflow`] and
    /// [`ConfigRefusal::Silence`]. The relations with `standby_target_us` are necessary conditions on the timers at
    /// one listing per tick; the target also has to cover attach, enrollment and designation time, which `validate`
    /// leaves to the operator.
    pub fn validate(self) -> Result<ZoneBounds, ConfigRefusal> {
        if !is_az(&self.name) {
            return Err(ConfigRefusal::Name);
        }
        if !self.directory.is_absolute() {
            return Err(ConfigRefusal::Directory);
        }
        if let Some(field) = self.first_zero() {
            return Err(ConfigRefusal::Zero(field));
        }
        let o = self.owner;
        let bounds = Bounds::new(
            o.registrant_max,
            o.retry_max,
            o.window,
            o.report_deadline,
            o.report_period,
            o.clock_error,
        )
        .map_err(ConfigRefusal::Bounds)?;
        if bounds.pair_cap() < 3 {
            return Err(ConfigRefusal::PairCap);
        }
        let r = self.replacement;
        r.check_floor().map_err(ConfigRefusal::Layout)?;
        if delta_blocks(&r) == 0 {
            return Err(ConfigRefusal::DeltaRegion);
        }
        if self.fresh_periods < 2 {
            return Err(ConfigRefusal::FreshPeriods);
        }
        if self.silent_periods <= self.fresh_periods {
            return Err(ConfigRefusal::SilentPeriods);
        }
        if self.loss_ticks < 2 {
            return Err(ConfigRefusal::LossTicks);
        }
        if self.tick_us > self.report_period_us {
            return Err(ConfigRefusal::Tick);
        }
        let span = |ticks: u32| u64::from(ticks - 1).saturating_mul(self.tick_us);
        let dwells = [
            (self.stopped_dwell_us, Field::StoppedDwellUs),
            (self.impaired_dwell_us, Field::ImpairedDwellUs),
            (span(self.absent_ticks), Field::AbsentTicks),
            (span(self.loss_ticks), Field::LossTicks),
        ];
        if let Some((_, field)) = dwells
            .into_iter()
            .find(|(dwell, _)| *dwell >= self.standby_target_us)
        {
            return Err(ConfigRefusal::Dwell(field));
        }
        if self.attach_stuck_us <= self.attach_settle_us {
            return Err(ConfigRefusal::AttachStuck);
        }
        if self.detach_settle_us <= DETACH_SETTLE_FLOOR_US {
            return Err(ConfigRefusal::DetachSettle);
        }
        if self.create_backoff_max_us < self.create_backoff_us {
            return Err(ConfigRefusal::Backoff);
        }
        if self.create_attempts_max == u32::MAX {
            return Err(ConfigRefusal::CreateAttempts);
        }
        if self.host_hold.numerator >= self.host_hold.denominator {
            return Err(ConfigRefusal::HostHold);
        }
        if self.population_cap > MAX_SLOTS {
            return Err(ConfigRefusal::PopulationCap);
        }
        if self.calls_per_tick <= self.enroll_inflight_max {
            return Err(ConfigRefusal::Calls);
        }
        let window = |periods: u32| {
            self.report_period_us
                .checked_mul(periods.into())
                .ok_or(ConfigRefusal::Overflow)
        };
        let (fresh_us, silent_us) = (window(self.fresh_periods)?, window(self.silent_periods)?);
        if silent_us >= self.standby_target_us {
            return Err(ConfigRefusal::Silence);
        }
        Ok(ZoneBounds {
            config: self,
            bounds,
            fresh_us,
            silent_us,
        })
    }
}

impl ZoneBounds {
    pub fn config(&self) -> &ZoneConfig {
        &self.config
    }

    /// These bounds with `calls_per_tick` set to `calls`, any value above zero: the budget tests run a tick's calls
    /// at or below the enrollments in flight, which [`ZoneConfig::validate`] refuses.
    #[cfg(test)]
    pub(crate) fn with_calls(mut self, calls: u32) -> Self {
        assert!(calls > 0);
        self.config.calls_per_tick = calls;
        self
    }

    /// The owners' serving bounds.
    pub fn bounds(&self) -> &Bounds {
        &self.bounds
    }

    pub fn fresh_us(&self) -> u64 {
        self.fresh_us
    }

    pub fn silent_us(&self) -> u64 {
        self.silent_us
    }

    /// For a directory of the configuration's zone, `cap_below_shards` returns the census cap and the shard count
    /// when the cap is below the shard count. For a directory of another zone it returns `None`.
    pub fn cap_below_shards<P>(&self, directory: &Directory<P>) -> Option<CapBelowShards> {
        if directory.zone() != self.config.zone {
            return None;
        }
        let (cap, shards) = (self.config.population_cap, directory.shards().len());
        (cap < shards).then_some(CapBelowShards { cap, shards })
    }
}
