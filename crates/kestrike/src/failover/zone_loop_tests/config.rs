use std::path::PathBuf;

use crate::failover::bounds::{Bounds, BoundsError, Parameter};
use crate::failover::records::{Layout, LayoutRefusal};
use crate::failover::sim::layout;
use crate::failover::standbys::{MAX_SLOTS, Zone};
use crate::failover::zone_loop::config::*;
use crate::failover::zone_loop::directory::{Directory, ReconcilerProjection};

use super::directory::{directory, listing, report_keys};

pub(crate) const REPORT_PERIOD_US: u64 = TICK_US;

fn owner() -> OwnerBounds {
    OwnerBounds {
        registrant_max: 8,
        retry_max: 2,
        window: 36,
        report_deadline: 10,
        report_period: 20,
        clock_error: 5,
    }
}

fn config_with(shards: usize, report_period_us: u64) -> ZoneConfig {
    let directory = PathBuf::from("/etc/kestrike/zone-1.directory");
    let name = "us-east-1a".into();
    ZoneConfig::defaults(
        Zone(1),
        name,
        shards,
        owner(),
        layout(),
        directory,
        report_period_us,
    )
}

pub(crate) fn config_of(shards: usize) -> ZoneConfig {
    config_with(shards, REPORT_PERIOD_US)
}

pub(crate) fn bounds() -> ZoneBounds {
    config_of(8).validate().unwrap()
}

fn refusal(change: impl FnOnce(&mut ZoneConfig)) -> ConfigRefusal {
    let mut config = config_of(8);
    change(&mut config);
    config.validate().unwrap_err()
}

#[test]
fn the_default_configuration_validates() {
    let bounds = bounds();
    let c = bounds.config();
    assert_eq!(c.report_period_us, 10_000_000);
    assert_eq!(c.tick_us, 10_000_000);
    assert_eq!((c.fresh_periods, c.silent_periods), (3, 6));
    assert_eq!(
        (c.stopped_dwell_us, c.impaired_dwell_us),
        (300_000_000, 180_000_000)
    );
    assert_eq!((c.absent_ticks, c.loss_ticks), (2, 2));
    assert_eq!(
        (c.attach_settle_us, c.attach_stuck_us),
        (30_000_000, 900_000_000)
    );
    assert_eq!(c.detach_settle_us, 300_000_000);
    assert_eq!(
        (c.enroll_stuck_us, c.create_settle_us),
        (300_000_000, 300_000_000)
    );
    assert_eq!(c.standby_target_us, 600_000_000);
    assert_eq!((c.replacements_inflight_max, c.create_attempts_max), (1, 3));
    assert_eq!(
        (c.create_backoff_us, c.create_backoff_max_us),
        (60_000_000, 600_000_000)
    );
    assert_eq!(c.enroll_inflight_max, 4);
    assert_eq!(
        (c.attach_starts_per_window, c.attach_window_us),
        (16, 600_000_000)
    );
    assert_eq!(
        c.host_hold,
        Fraction {
            numerator: 1,
            denominator: 4
        }
    );
    assert_eq!((c.standbys_per_host_max, HOST_ROLES_MAX), (6, 10));
    assert_eq!(c.population_cap, 8);
    assert_eq!((c.writes_per_tick, c.calls_per_tick), (32, 8));
    assert_eq!(bounds.fresh_us(), 30_000_000);
    assert_eq!(bounds.silent_us(), 60_000_000);
    assert_eq!(bounds.cap_below_shards(&directory(4, 8)), None);
    assert_eq!(*bounds.bounds(), Bounds::new(8, 2, 36, 10, 20, 5).unwrap());
    assert_eq!(bounds.bounds().pair_cap(), 8);
}

#[test]
fn defaults_keep_the_report_period_and_take_the_census_cap_from_the_shard_count() {
    let mut config = config_with(5, 20_000_000);
    assert_eq!(
        (config.tick_us, config.report_period_us),
        (10_000_000, 20_000_000)
    );
    assert_eq!(config.population_cap, 5);
    config.fresh_periods = 4;
    config.silent_periods = 5;
    config.owner.registrant_max = 3;
    let bounds = config.validate().unwrap();
    assert_eq!(
        (bounds.fresh_us(), bounds.silent_us()),
        (80_000_000, 100_000_000)
    );
    let owner = bounds.bounds();
    assert_eq!(
        (owner.registrant_max(), owner.pair_cap(), owner.retry_max()),
        (3, 3, 2)
    );
    assert_eq!(
        (
            owner.window(),
            owner.report_deadline(),
            owner.report_period()
        ),
        (36, 10, 20)
    );
    assert!(config_of(1).validate().is_ok());
    assert!(config_of(MAX_SLOTS).validate().is_ok());
    assert_eq!(
        config_of(0).validate().unwrap_err(),
        ConfigRefusal::Zero(Field::PopulationCap)
    );
    assert_eq!(
        config_of(MAX_SLOTS + 1).validate().unwrap_err(),
        ConfigRefusal::PopulationCap
    );
}

fn zone_directory(zone: Zone, shards: u32) -> Directory<ReconcilerProjection> {
    let mut listing = listing(4, shards);
    listing.zone = zone;
    (listing.hosts.iter_mut()).for_each(|h| h.placement.zone = zone);
    (listing.shards.iter_mut()).for_each(|s| s.zone = zone);
    let keys = report_keys(&listing);
    Directory::new(listing, keys).unwrap()
}

#[test]
fn validation_keeps_the_values_the_caller_supplies() {
    let replacement = Layout {
        units: 11,
        ..layout()
    };
    let mut config = ZoneConfig::defaults(
        Zone(2),
        "eu-west-3c".into(),
        8,
        owner(),
        replacement,
        PathBuf::from("/srv/zone-2/directory"),
        REPORT_PERIOD_US,
    );
    config.loss_ticks = 3;
    config.population_cap = 5;
    let bounds = config.validate().unwrap();
    let c = bounds.config();
    assert_eq!((c.zone, c.name.as_str()), (Zone(2), "eu-west-3c"));
    assert_eq!(c.directory, PathBuf::from("/srv/zone-2/directory"));
    assert_eq!(
        (
            c.replacement.units,
            c.replacement.slots,
            c.replacement.entries
        ),
        (11, 3, 64)
    );
    assert_eq!((c.loss_ticks, c.population_cap), (3, 5));
    assert_eq!(
        bounds.cap_below_shards(&zone_directory(Zone(2), 8)),
        Some(CapBelowShards { cap: 5, shards: 8 })
    );
    assert_eq!(bounds.cap_below_shards(&directory(4, 8)), None);
}

#[test]
fn the_default_timers_admit_report_periods_from_the_tick_to_below_a_sixth_of_the_target() {
    let period = |report_period_us| config_with(8, report_period_us).validate().err();
    assert_eq!(period(TICK_US - 1), Some(ConfigRefusal::Tick));
    assert_eq!(period(TICK_US), None);
    assert_eq!(period(99_999_999), None);
    assert_eq!(period(100_000_000), Some(ConfigRefusal::Silence));
}

#[test]
fn a_zero_value_refuses_naming_its_field() {
    type Change = fn(&mut ZoneConfig);
    let cases: [(Change, Field); 26] = [
        (|c| c.report_period_us = 0, Field::ReportPeriodUs),
        (|c| c.tick_us = 0, Field::TickUs),
        (|c| c.fresh_periods = 0, Field::FreshPeriods),
        (|c| c.silent_periods = 0, Field::SilentPeriods),
        (|c| c.stopped_dwell_us = 0, Field::StoppedDwellUs),
        (|c| c.impaired_dwell_us = 0, Field::ImpairedDwellUs),
        (|c| c.absent_ticks = 0, Field::AbsentTicks),
        (|c| c.loss_ticks = 0, Field::LossTicks),
        (|c| c.attach_settle_us = 0, Field::AttachSettleUs),
        (|c| c.attach_stuck_us = 0, Field::AttachStuckUs),
        (|c| c.detach_settle_us = 0, Field::DetachSettleUs),
        (|c| c.enroll_stuck_us = 0, Field::EnrollStuckUs),
        (|c| c.create_settle_us = 0, Field::CreateSettleUs),
        (|c| c.standby_target_us = 0, Field::StandbyTargetUs),
        (
            |c| c.replacements_inflight_max = 0,
            Field::ReplacementsInflightMax,
        ),
        (|c| c.create_attempts_max = 0, Field::CreateAttemptsMax),
        (|c| c.create_backoff_us = 0, Field::CreateBackoffUs),
        (|c| c.create_backoff_max_us = 0, Field::CreateBackoffMaxUs),
        (|c| c.enroll_inflight_max = 0, Field::EnrollInflightMax),
        (
            |c| c.attach_starts_per_window = 0,
            Field::AttachStartsPerWindow,
        ),
        (|c| c.attach_window_us = 0, Field::AttachWindowUs),
        (|c| c.host_hold.denominator = 0, Field::HostHold),
        (|c| c.standbys_per_host_max = 0, Field::StandbysPerHostMax),
        (|c| c.population_cap = 0, Field::PopulationCap),
        (|c| c.writes_per_tick = 0, Field::WritesPerTick),
        (|c| c.calls_per_tick = 0, Field::CallsPerTick),
    ];
    for (change, field) in cases {
        assert_eq!(refusal(change), ConfigRefusal::Zero(field), "{field:?}");
    }
    for pair in cases.windows(2) {
        let [(first, field), (second, _)] = pair else {
            unreachable!("windows(2) yields pairs")
        };
        let both = refusal(|c| {
            first(c);
            second(c);
        });
        assert_eq!(both, ConfigRefusal::Zero(*field), "{field:?}");
    }
    assert_eq!(
        refusal(|c| c.host_hold.numerator = 0),
        ConfigRefusal::Zero(Field::HostHold)
    );
}

#[test]
fn each_invalid_relation_refuses_naming_it() {
    assert_eq!(
        refusal(|c| c.fresh_periods = 1),
        ConfigRefusal::FreshPeriods
    );
    assert_eq!(
        refusal(|c| c.silent_periods = c.fresh_periods),
        ConfigRefusal::SilentPeriods
    );
    assert_eq!(
        refusal(|c| c.silent_periods = c.fresh_periods - 1),
        ConfigRefusal::SilentPeriods
    );
    assert_eq!(refusal(|c| c.loss_ticks = 1), ConfigRefusal::LossTicks);
    assert_eq!(
        refusal(|c| c.owner.registrant_max = 1),
        ConfigRefusal::PairCap
    );
    assert_eq!(
        refusal(|c| c.owner.registrant_max = 2),
        ConfigRefusal::PairCap
    );
    assert_eq!(
        refusal(|c| c.replacement.units = 10),
        ConfigRefusal::DeltaRegion
    );
    assert_eq!(
        refusal(|c| {
            c.replacement.slots = 4;
            c.replacement.units = 13;
        }),
        ConfigRefusal::DeltaRegion
    );
    assert_eq!(
        refusal(|c| c.tick_us = c.report_period_us + 1),
        ConfigRefusal::Tick
    );
    assert_eq!(
        refusal(|c| c.stopped_dwell_us = c.standby_target_us),
        ConfigRefusal::Dwell(Field::StoppedDwellUs)
    );
    assert_eq!(
        refusal(|c| c.impaired_dwell_us = c.standby_target_us),
        ConfigRefusal::Dwell(Field::ImpairedDwellUs)
    );
    assert_eq!(
        refusal(|c| c.absent_ticks = 61),
        ConfigRefusal::Dwell(Field::AbsentTicks)
    );
    assert_eq!(
        refusal(|c| c.absent_ticks = u32::MAX),
        ConfigRefusal::Dwell(Field::AbsentTicks)
    );
    assert_eq!(
        refusal(|c| c.loss_ticks = 61),
        ConfigRefusal::Dwell(Field::LossTicks)
    );
    assert_eq!(
        refusal(|c| c.standby_target_us = c.stopped_dwell_us),
        ConfigRefusal::Dwell(Field::StoppedDwellUs)
    );
    assert_eq!(
        refusal(|c| c.attach_stuck_us = c.attach_settle_us),
        ConfigRefusal::AttachStuck
    );
    assert_eq!(
        refusal(|c| c.attach_stuck_us = c.attach_settle_us - 1),
        ConfigRefusal::AttachStuck
    );
    assert_eq!(
        refusal(|c| c.detach_settle_us = DETACH_SETTLE_FLOOR_US),
        ConfigRefusal::DetachSettle
    );
    assert_eq!(
        refusal(|c| c.detach_settle_us = 1),
        ConfigRefusal::DetachSettle
    );
    assert_eq!(
        refusal(|c| c.create_backoff_max_us = c.create_backoff_us - 1),
        ConfigRefusal::Backoff
    );
    assert_eq!(
        refusal(|c| c.create_attempts_max = u32::MAX),
        ConfigRefusal::CreateAttempts
    );
    for (numerator, denominator) in [(1, 1), (4, 4), (5, 4)] {
        assert_eq!(
            refusal(|c| c.host_hold = Fraction {
                numerator,
                denominator
            }),
            ConfigRefusal::HostHold,
            "{numerator}/{denominator}"
        );
    }
    assert_eq!(
        refusal(|c| c.population_cap = MAX_SLOTS + 1),
        ConfigRefusal::PopulationCap
    );
    for below in [0, 1, 3] {
        assert_eq!(
            refusal(|c| c.calls_per_tick = c.enroll_inflight_max - below),
            ConfigRefusal::Calls,
            "{below} below the enrollments in flight"
        );
    }
    assert_eq!(
        refusal(|c| c.enroll_inflight_max = c.calls_per_tick),
        ConfigRefusal::Calls
    );
    let mut admitted = config_of(8);
    admitted.calls_per_tick = admitted.enroll_inflight_max + 1;
    assert_eq!(admitted.validate().err(), None, "one call above");
    assert_eq!(
        refusal(|c| c.report_period_us = u64::MAX / 4),
        ConfigRefusal::Overflow
    );
    assert_eq!(
        refusal(|c| c.report_period_us = c.standby_target_us / 6),
        ConfigRefusal::Silence
    );
    assert_eq!(
        refusal(|c| c.report_period_us = c.standby_target_us / 6 + 1),
        ConfigRefusal::Silence
    );
    assert_eq!(
        refusal(|c| {
            c.standby_target_us = 60_000_000;
            c.stopped_dwell_us = 50_000_000;
            c.impaired_dwell_us = 50_000_000;
        }),
        ConfigRefusal::Silence
    );
}

#[test]
fn an_absence_span_past_u64_refuses_and_one_below_it_validates() {
    let span = |tick_us: u64| {
        let mut config = config_with(8, tick_us);
        config.tick_us = tick_us;
        config.absent_ticks = u32::MAX;
        config.standby_target_us = u64::MAX;
        config.validate().err()
    };
    assert_eq!(span(1 << 32), None);
    assert_eq!(
        span(1 << 33),
        Some(ConfigRefusal::Dwell(Field::AbsentTicks))
    );
}

#[test]
fn each_relation_validates_at_its_inside_edge() {
    let inside: [fn(&mut ZoneConfig); 23] = [
        |c| c.report_period_us = c.standby_target_us / 6 - 1,
        |c| c.fresh_periods = 2,
        |c| c.silent_periods = c.fresh_periods + 1,
        |c| c.tick_us = c.report_period_us,
        |c| c.stopped_dwell_us = c.standby_target_us - 1,
        |c| c.impaired_dwell_us = c.standby_target_us - 1,
        |c| c.absent_ticks = 60,
        |c| c.absent_ticks = 1,
        |c| c.loss_ticks = 60,
        |c| c.owner.registrant_max = 3,
        |c| c.replacement.units = 11,
        |c| {
            c.replacement.slots = 4;
            c.replacement.units = 14;
        },
        |c| {
            c.standby_target_us = 700_000_000;
            c.stopped_dwell_us = 650_000_000;
        },
        |c| c.attach_stuck_us = c.attach_settle_us + 1,
        |c| c.detach_settle_us = DETACH_SETTLE_FLOOR_US + 1,
        |c| c.create_backoff_max_us = c.create_backoff_us,
        |c| {
            c.host_hold = Fraction {
                numerator: 3,
                denominator: 4,
            }
        },
        |c| c.population_cap = MAX_SLOTS,
        |c| c.create_attempts_max = u32::MAX - 1,
        |c| c.name = "a".repeat(63),
        |c| c.name = "us-west-2-lax-1a".into(),
        |c| c.name = "0".into(),
        |c| c.silent_periods = 4,
    ];
    for (row, change) in inside.into_iter().enumerate() {
        let mut config = config_with(8, 2 * TICK_US);
        change(&mut config);
        assert_eq!(config.validate().err(), None, "row {row}");
    }
}

#[test]
fn the_first_failed_check_in_the_documented_order_names_the_refusal() {
    type Change = fn(&mut ZoneConfig);
    let cases: [(Change, ConfigRefusal); 26] = [
        (
            |c| {
                c.name.clear();
                c.directory = PathBuf::from("zone-1.directory");
            },
            ConfigRefusal::Name,
        ),
        (
            |c| {
                c.directory = PathBuf::from("zone-1.directory");
                c.tick_us = 0;
            },
            ConfigRefusal::Directory,
        ),
        (
            |c| {
                c.tick_us = 0;
                c.loss_ticks = 0;
            },
            ConfigRefusal::Zero(Field::TickUs),
        ),
        (
            |c| {
                c.calls_per_tick = 0;
                c.owner.retry_max = 0;
            },
            ConfigRefusal::Zero(Field::CallsPerTick),
        ),
        (
            |c| {
                c.owner.retry_max = 0;
                c.owner.registrant_max = 1;
            },
            ConfigRefusal::Bounds(BoundsError::Zero(Parameter::RetryMax)),
        ),
        (
            |c| {
                c.owner.registrant_max = 1;
                c.replacement.slots = 2;
            },
            ConfigRefusal::PairCap,
        ),
        (
            |c| {
                c.replacement.slots = 2;
                c.fresh_periods = 1;
            },
            ConfigRefusal::Layout(LayoutRefusal::TooFewSlots { slots: 2 }),
        ),
        (
            |c| c.replacement.units = 9,
            ConfigRefusal::Layout(LayoutRefusal::BelowFloor {
                units: 9,
                floor: 10,
            }),
        ),
        (
            |c| {
                c.replacement.units = 10;
                c.fresh_periods = 1;
            },
            ConfigRefusal::DeltaRegion,
        ),
        (
            |c| {
                c.fresh_periods = 1;
                c.silent_periods = 1;
            },
            ConfigRefusal::FreshPeriods,
        ),
        (
            |c| {
                c.fresh_periods = 1;
                c.loss_ticks = 1;
            },
            ConfigRefusal::FreshPeriods,
        ),
        (
            |c| {
                c.silent_periods = c.fresh_periods;
                c.loss_ticks = 1;
            },
            ConfigRefusal::SilentPeriods,
        ),
        (
            |c| {
                c.loss_ticks = 1;
                c.tick_us = c.report_period_us + 1;
            },
            ConfigRefusal::LossTicks,
        ),
        (
            |c| {
                c.tick_us = c.report_period_us + 1;
                c.stopped_dwell_us = c.standby_target_us;
            },
            ConfigRefusal::Tick,
        ),
        (
            |c| {
                c.stopped_dwell_us = c.standby_target_us;
                c.impaired_dwell_us = c.standby_target_us;
            },
            ConfigRefusal::Dwell(Field::StoppedDwellUs),
        ),
        (
            |c| {
                c.impaired_dwell_us = c.standby_target_us;
                c.absent_ticks = 61;
            },
            ConfigRefusal::Dwell(Field::ImpairedDwellUs),
        ),
        (
            |c| {
                c.absent_ticks = 61;
                c.loss_ticks = 61;
            },
            ConfigRefusal::Dwell(Field::AbsentTicks),
        ),
        (
            |c| {
                c.loss_ticks = 61;
                c.attach_stuck_us = c.attach_settle_us;
            },
            ConfigRefusal::Dwell(Field::LossTicks),
        ),
        (
            |c| {
                c.attach_stuck_us = c.attach_settle_us;
                c.detach_settle_us = DETACH_SETTLE_FLOOR_US;
            },
            ConfigRefusal::AttachStuck,
        ),
        (
            |c| {
                c.detach_settle_us = DETACH_SETTLE_FLOOR_US;
                c.create_backoff_max_us = c.create_backoff_us - 1;
            },
            ConfigRefusal::DetachSettle,
        ),
        (
            |c| {
                c.create_backoff_max_us = c.create_backoff_us - 1;
                c.create_attempts_max = u32::MAX;
            },
            ConfigRefusal::Backoff,
        ),
        (
            |c| {
                c.create_attempts_max = u32::MAX;
                c.host_hold.numerator = c.host_hold.denominator;
            },
            ConfigRefusal::CreateAttempts,
        ),
        (
            |c| {
                c.host_hold.numerator = c.host_hold.denominator;
                c.population_cap = MAX_SLOTS + 1;
            },
            ConfigRefusal::HostHold,
        ),
        (
            |c| {
                c.population_cap = MAX_SLOTS + 1;
                c.calls_per_tick = c.enroll_inflight_max;
            },
            ConfigRefusal::PopulationCap,
        ),
        (
            |c| {
                c.calls_per_tick = c.enroll_inflight_max;
                c.report_period_us = u64::MAX / 4;
            },
            ConfigRefusal::Calls,
        ),
        (
            |c| {
                c.report_period_us = u64::MAX / 4;
                c.standby_target_us = u64::MAX;
            },
            ConfigRefusal::Overflow,
        ),
    ];
    for (row, (change, expected)) in cases.into_iter().enumerate() {
        assert_eq!(refusal(change), expected, "row {row}");
    }
}

#[test]
fn the_name_path_owner_bounds_and_layout_refuse() {
    let names = [
        String::new(),
        "us east".into(),
        "a".repeat(64),
        "US-EAST-1A".into(),
        "us_east_1a".into(),
        "us-east-\u{e9}".into(),
        "us\u{7f}east".into(),
    ];
    for name in names {
        assert_eq!(
            refusal(|c| c.name = name.clone()),
            ConfigRefusal::Name,
            "{name:?}"
        );
    }
    assert_eq!(
        refusal(|c| c.directory = PathBuf::from("zone-1.directory")),
        ConfigRefusal::Directory
    );
    assert_eq!(
        refusal(|c| c.owner.retry_max = 0),
        ConfigRefusal::Bounds(BoundsError::Zero(Parameter::RetryMax))
    );
    assert_eq!(
        refusal(|c| c.owner.clock_error = 6),
        ConfigRefusal::Bounds(BoundsError::WindowTooShort {
            window: 36,
            needed_above: 36
        })
    );
    assert_eq!(
        refusal(|c| c.replacement.slots = 2),
        ConfigRefusal::Layout(LayoutRefusal::TooFewSlots { slots: 2 })
    );
}

#[test]
fn a_cap_below_the_shard_count_validates_and_is_reported() {
    let mut config = config_of(8);
    config.population_cap = 5;
    let bounds = config.validate().unwrap();
    assert_eq!(
        bounds.cap_below_shards(&directory(4, 8)),
        Some(CapBelowShards { cap: 5, shards: 8 })
    );
    assert_eq!(bounds.cap_below_shards(&directory(4, 5)), None);
    assert_eq!(bounds.cap_below_shards(&directory(4, 4)), None);
    let mut foreign = config_of(8);
    foreign.zone = Zone(2);
    foreign.population_cap = 5;
    let foreign = foreign.validate().unwrap();
    assert_eq!(foreign.cap_below_shards(&directory(4, 8)), None);
}

#[test]
fn the_host_hold_is_exceeded_only_above_its_fraction() {
    assert!(HOST_HOLD.exceeded_by(5, 16));
    assert!(!HOST_HOLD.exceeded_by(4, 16));
    assert!(!HOST_HOLD.exceeded_by(0, 0));
    assert!(HOST_HOLD.exceeded_by(1, 0));
    let mut config = config_of(8);
    config.host_hold = Fraction {
        numerator: 2,
        denominator: 3,
    };
    let hold = config.validate().unwrap().config().host_hold;
    assert!(!hold.exceeded_by(3, 5));
    assert!(hold.exceeded_by(4, 5));
    assert!(!hold.exceeded_by(6, 9));
    assert!(hold.exceeded_by(7, 9));
    let unchecked = Fraction {
        numerator: 1,
        denominator: 0,
    };
    assert!(!unchecked.exceeded_by(5, 16));
    let half = Fraction {
        numerator: 1,
        denominator: 2,
    };
    assert!(!half.exceeded_by(usize::MAX / 2, usize::MAX));
    assert!(half.exceeded_by(usize::MAX / 2 + 1, usize::MAX));
}
