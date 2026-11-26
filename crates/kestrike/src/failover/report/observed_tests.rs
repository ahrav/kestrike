//! Each conversion into the entry's labels and counts maps every source value to its own label or field.

use super::*;
use crate::failover::evidence::NotSole;
use crate::storage::store::Tally;

#[test]
fn every_alarm_hold_judgment_listing_and_damage_reads_its_own_label() {
    for (alarm, label) in [
        (Alarm::Clear, Watermark::Clear),
        (Alarm::Regression, Watermark::Regression),
        (Alarm::Checkpoint, Watermark::Checkpoint),
        (Alarm::Log, Watermark::Log),
        (Alarm::Namespace, Watermark::Namespace),
    ] {
        assert_eq!(Watermark::from(alarm), label);
    }
    for (hold, label) in [
        (HoldState::Clear, Hold::Clear),
        (HoldState::Held, Hold::Held),
        (HoldState::Pending, Hold::Pending),
        (HoldState::Superseded, Hold::Superseded),
    ] {
        assert_eq!(Hold::from(hold), label);
    }
    for (judgment, label) in [
        (RegistrantJudgment::Sole, Registrants::Sole),
        (RegistrantJudgment::Recorded, Registrants::Recorded),
        (RegistrantJudgment::Ended, Registrants::EndedRegistrant),
        (
            RegistrantJudgment::Refused(NotSole::ForeignRegistrant),
            Registrants::ForeignRegistrant,
        ),
        (
            RegistrantJudgment::Refused(NotSole::DuplicateOwnRecord),
            Registrants::DuplicateOwnRecord,
        ),
    ] {
        assert_eq!(Registrants::from(judgment), label);
    }
    for (checked, label) in [
        (Ok(()), Enumeration::Matches),
        (Err(Mismatch::Foreign("i-0f".into())), Enumeration::Foreign),
        (Err(Mismatch::Duplicate), Enumeration::Duplicate),
        (Err(Mismatch::Missing), Enumeration::Missing),
    ] {
        assert_eq!(Enumeration::from(&checked), label);
    }
    let header = crate::storage::HeaderMismatch::Magic { found: 0 };
    for (damage, label) in [
        (
            UnitDamage::Header {
                unit: 1,
                mismatch: header,
            },
            Damage::Header,
        ),
        (UnitDamage::Chunk { unit: 1 }, Damage::Chunk),
        (UnitDamage::Content { unit: 1 }, Damage::Content),
        (
            UnitDamage::Units {
                recorded: 1,
                named: 2,
            },
            Damage::Units,
        ),
        (UnitDamage::Unread { unit: 1 }, Damage::Unread),
    ] {
        assert_eq!(Damage::from(&damage), label);
    }
}

/// Each outcome sums over the record classes into its own count: a tally of two unknown creates over two classes,
/// five unavailable reads over five, three refused creates over two and one failed log write reads those totals, and
/// a fresh tally reads zero of each.
#[test]
fn the_store_counts_sum_each_outcome_over_its_classes() {
    assert_eq!(
        StoreOutcomes::from(crate::storage::store::tally_tests::distinct()),
        StoreOutcomes {
            unknown: Some(2),
            unavailable: Some(5),
            refused: Some(3),
            log: Some(1),
        }
    );
    let zero = Some(0);
    assert_eq!(
        StoreOutcomes::from(Tally::default()),
        StoreOutcomes {
            unknown: zero,
            unavailable: zero,
            refused: zero,
            log: zero,
        }
    );
}

/// The backlog reads its blocks of the queue bound and its age in whole microseconds, 0 when every block is durable
/// and unavailable when the clock sample failed.
#[test]
fn the_backlog_reads_blocks_of_the_bound_and_its_age_in_microseconds() {
    let backlog = |blocks, age_ns| {
        Backlog::from(SuffixBacklog {
            blocks,
            limit: 4,
            age_ns,
        })
    };
    assert_eq!(
        backlog(2, Some(5_500)),
        Backlog {
            blocks: Gauge::known(2, 4),
            flush_lag_us: Some(5),
        }
    );
    assert_eq!(backlog(0, Some(0)).flush_lag_us, Some(0));
    assert_eq!(
        backlog(1, None),
        Backlog {
            blocks: Gauge::known(1, 4),
            flush_lag_us: None,
        },
        "a failed clock sample loses only the lag"
    );
}

/// Each recovery time counts from the start of initialization to its own milestone: a report whose attach first
/// ticked at 1,000 reads each milestone's own distance, live at the transition into live among transitions before and
/// after it, a restored attach's retained readiness at its live time, a milestone not yet reached reads unavailable,
/// a milestone out of the recorder's order reads unavailable, and a report with no initialization start reads every
/// time unavailable.
#[test]
fn the_recovery_times_count_each_milestone_from_the_first_tick() {
    use crate::storage::Readiness;
    use crate::storage::Transition;
    let mut report = RecoveryReport::default();
    assert_eq!(RecoveryTimes::of(&report), RecoveryTimes::UNAVAILABLE);
    let phase = |report: &mut RecoveryReport, phase: RecoveryPhase, start, end| {
        let entry = &mut report.phases[phase as usize];
        (entry.start, entry.end) = (Some(start), end);
    };
    phase(
        &mut report,
        RecoveryPhase::Initialization,
        1_000,
        Some(1_300),
    );
    assert_eq!(
        RecoveryTimes::of(&report),
        RecoveryTimes {
            loaded_us: Some(300),
            ..RecoveryTimes::UNAVAILABLE
        },
        "only the load ended"
    );
    let transition = |from, to, at| Some(Transition { from, to, at });
    report.transitions[..3].copy_from_slice(&[
        transition(Readiness::Loaded, Readiness::Replaying, 1_400),
        transition(Readiness::Replaying, Readiness::Live, 1_700),
        transition(Readiness::Live, Readiness::Withheld, 2_600),
    ]);
    phase(&mut report, RecoveryPhase::Replay, 1_400, Some(1_700));
    phase(
        &mut report,
        RecoveryPhase::RetainedReadiness,
        1_700,
        Some(1_700),
    );
    phase(&mut report, RecoveryPhase::FirstSafeHit, 1_900, Some(1_950));
    phase(&mut report, RecoveryPhase::FillReadiness, 2_400, None);
    assert_eq!(
        RecoveryTimes::of(&report),
        RecoveryTimes {
            loaded_us: Some(300),
            live_us: Some(700),
            first_hit_us: Some(900),
            retained_us: Some(700),
            fill_us: Some(1_400),
        }
    );
    // A backward clock step put live and retained readiness before the load's end and the first hit before live:
    // each milestone out of order reads unavailable, and the rest keep their distances.
    let mut stepped = report;
    stepped.transitions[1] = transition(Readiness::Replaying, Readiness::Live, 1_200);
    phase(
        &mut stepped,
        RecoveryPhase::RetainedReadiness,
        1_200,
        Some(1_200),
    );
    assert_eq!(
        RecoveryTimes::of(&stepped),
        RecoveryTimes {
            loaded_us: Some(300),
            first_hit_us: Some(900),
            fill_us: Some(1_400),
            ..RecoveryTimes::UNAVAILABLE
        }
    );
    phase(
        &mut stepped,
        RecoveryPhase::FirstSafeHit,
        1_250,
        Some(1_250),
    );
    phase(&mut stepped, RecoveryPhase::FillReadiness, 1_280, None);
    assert_eq!(
        RecoveryTimes::of(&stepped),
        RecoveryTimes {
            loaded_us: Some(300),
            ..RecoveryTimes::UNAVAILABLE
        },
        "a first hit and a fill before the load's end, with live out of order"
    );
    phase(&mut report, RecoveryPhase::FirstSafeHit, 1_600, Some(1_600));
    assert_eq!(
        RecoveryTimes::of(&report).first_hit_us,
        None,
        "a first hit before live"
    );
}

/// The retention account copies each loss count of the warm report into its own field and the allocator's held
/// units beside them.
#[test]
fn the_retention_account_reads_each_loss_count_in_its_own_field() {
    let mut report = RecoveryReport {
        held_units: 7,
        ..RecoveryReport::default()
    };
    let warm = &mut report.warm;
    warm.failed_units = 1;
    warm.unread_units = 2;
    warm.first_damage = Some(UnitDamage::Chunk { unit: 3 });
    warm.suffix_damage = 4;
    warm.suffix_tails = 5;
    warm.suffix_dropped = 6;
    warm.suffix_unread = 8;
    warm.slot_superseded = 9;
    warm.slot_withheld = 10;
    warm.installed = 41;
    warm.omitted = 11;
    assert_eq!(
        Retention::of(&report),
        Retention {
            first_damage: Some(Damage::Chunk),
            installed: 41,
            omitted: 11,
            held_units: 7,
            failed_units: 1,
            unread_units: 2,
            suffix_damage: 4,
            suffix_tails: 5,
            suffix_dropped: 6,
            suffix_unread: 8,
            slot_superseded: 9,
            slot_withheld: 10,
        }
    );
}

/// A read defect is a header or chunk mismatch: with five header mismatches, two of them a first extent's key
/// mismatch, and three chunk mismatches, six reads count; the first extents' key mismatches alone count none.
#[test]
fn read_defects_count_header_and_chunk_mismatches_beside_the_first_extent_key_ones() {
    let reads = VolumeReport {
        header_mismatch: 5,
        lookup_false_positives: 2,
        chunk_mismatch: 3,
        ..VolumeReport::default()
    };
    assert_eq!(read_defects(&reads), 6);
    let collisions = VolumeReport {
        header_mismatch: 2,
        lookup_false_positives: 2,
        ..VolumeReport::default()
    };
    assert_eq!(read_defects(&collisions), 0);
}
