//! The owner builds `VolumeEntry` from driver-supplied `Observed` fields and owner state.

use super::observe_tests::flip;
use super::owner_tenure_tests::{observe, serve_at, shard_at, token, volume_record};
use super::owner_tests::key;
use super::put_tests::{Scene, fenced_coverage, scene, versions};
use crate::failover::attachments::Mismatch;
use crate::failover::records::{ShardRecord, VolumeId, VolumeRecord, VolumeState};
use crate::failover::report::{
    Backlog, Captures, Coverage, Enumeration, Gauge, Hold, Observed, Recovery, RecoveryKind,
    RecoveryStatus, Registrants, StoreOutcomes, VolumeEntry, Watermark, Withdrawal,
};
use crate::failover::serving::{Cause, Event};
use crate::storage::checkpoint::SuffixDue;
use crate::storage::store::sim::{Arm, MemLog, Shared};
use crate::storage::store::{Alarm, Client, Key};
use crate::storage::store_tests::{client, seeded};
use crate::storage::{WorkBudget, store_tests};

pub(super) fn viewed(scene: &mut Scene<'_, '_>, volume: VolumeRecord) -> u64 {
    viewed_at(scene, volume, 1)
}

/// [`viewed`] under the tenure of generation 3 at attempt count `attempts`.
fn viewed_at(scene: &mut Scene<'_, '_>, volume: VolumeRecord, attempts: u32) -> u64 {
    serve_at(scene, 3, attempts);
    let token = token(scene);
    let record = shard_at(token, 3, token.epoch.get() / 2);
    observe(scene, Some(record), Some(volume), token.exhid);
    scene.turn * 100
}

pub(super) fn active() -> VolumeRecord {
    volume_record("vol-0a", VolumeState::Active)
}

#[track_caller]
pub(super) fn entry(scene: &Scene<'_, '_>, now: u64, observed: &Observed) -> VolumeEntry {
    let entry = scene.owner.report_entry(now, observed).unwrap();
    assert_eq!(
        entry.encode().and_then(|bytes| VolumeEntry::decode(&bytes)),
        Ok(entry),
        "the entry encodes and decodes to itself"
    );
    entry
}

fn tallied() -> Client<Shared, MemLog> {
    let store = seeded();
    let mut reader = client(&store);
    store.schedule(Arm::Unavailable);
    assert!(
        reader
            .read::<ShardRecord>(Key::Shard(store_tests::shard()))
            .is_err()
    );
    reader
}

fn regressed() -> Client<Shared, MemLog> {
    let key = Key::Shard(store_tests::shard());
    let store = seeded();
    let mut owner = client(&store);
    let read = owner.read::<ShardRecord>(key).unwrap();
    owner.bump(&read).unwrap();
    owner.read::<ShardRecord>(key).unwrap();
    store.schedule(Arm::StaleCurrentRead);
    assert!(owner.read::<ShardRecord>(key).is_err());
    assert_eq!(owner.alarm(), Alarm::Regression);
    owner
}

/// The driver's part fills the enumeration, the watermark, the store counts, the recovery part, the capture counts,
/// the quarantine gauge, `publication_due` and the roll flags. With any one part missing, that field reads
/// unavailable and the others keep their values; an empty part reads every such field unavailable, never zero.
#[test]
fn the_driver_part_fills_its_fields_and_a_missing_part_reads_unavailable() {
    scene(&[], |mut scene| {
        let now = viewed(&mut scene, active());
        let reader = tallied();
        let mut status = RecoveryStatus::NO_ATTEMPT;
        status.start(RecoveryKind::Restart, now - 50);
        status.complete();
        let observed = Observed {
            enumeration: Enumeration::from(&Err(Mismatch::Foreign("i-0f".into()))),
            alarm: Some(reader.alarm()),
            store: Some(reader.outcomes()),
            recovery: Some(status),
            captures: Captures {
                refused: Some(2),
                abandoned: Some(1),
            },
            quarantine: Gauge::known(1, 3),
            suffix_due: Some(SuffixDue {
                handoff: false,
                publication: true,
            }),
            roll_due: Some(true),
            roll_active: Some(false),
        };
        let full = entry(&scene, now, &observed);
        let parts = |entry: &VolumeEntry| {
            (
                entry.enumeration,
                entry.watermark,
                entry.store,
                entry.recovery,
                entry.captures,
                entry.pressure.quarantine,
                entry.publication_due,
                entry.roll_due,
                entry.roll_active,
            )
        };
        assert_eq!(
            parts(&full),
            (
                Enumeration::Foreign,
                Watermark::Clear,
                StoreOutcomes {
                    unknown: Some(0),
                    unavailable: Some(1),
                    refused: Some(0),
                    log: Some(0),
                },
                status.recovery(now),
                observed.captures,
                Gauge::known(1, 3),
                Some(true),
                Some(true),
                Some(false),
            )
        );
        let empty = entry(&scene, now, &Observed::UNAVAILABLE);
        let unavailable = Captures {
            refused: None,
            abandoned: None,
        };
        assert_eq!(
            parts(&empty),
            (
                Enumeration::Unavailable,
                Watermark::Unavailable,
                StoreOutcomes::UNAVAILABLE,
                Recovery::UNAVAILABLE,
                unavailable,
                Gauge::Unavailable,
                None,
                None,
                None,
            )
        );
        // Each row removes one part and names the one field that then reads unavailable; the rest stay at `full`.
        let rows: [(&str, Observed, VolumeEntry); 9] = [
            (
                "enumeration",
                Observed {
                    enumeration: Enumeration::Unavailable,
                    ..observed
                },
                VolumeEntry {
                    enumeration: empty.enumeration,
                    ..full
                },
            ),
            (
                "alarm",
                Observed {
                    alarm: None,
                    ..observed
                },
                VolumeEntry {
                    watermark: empty.watermark,
                    ..full
                },
            ),
            (
                "store",
                Observed {
                    store: None,
                    ..observed
                },
                VolumeEntry {
                    store: empty.store,
                    ..full
                },
            ),
            (
                "recovery",
                Observed {
                    recovery: None,
                    ..observed
                },
                VolumeEntry {
                    recovery: empty.recovery,
                    ..full
                },
            ),
            (
                "captures",
                Observed {
                    captures: unavailable,
                    ..observed
                },
                VolumeEntry {
                    captures: empty.captures,
                    ..full
                },
            ),
            (
                "quarantine",
                Observed {
                    quarantine: Gauge::Unavailable,
                    ..observed
                },
                VolumeEntry {
                    pressure: crate::failover::report::Pressure {
                        quarantine: empty.pressure.quarantine,
                        ..full.pressure
                    },
                    ..full
                },
            ),
            (
                "suffix_due",
                Observed {
                    suffix_due: None,
                    ..observed
                },
                VolumeEntry {
                    publication_due: empty.publication_due,
                    ..full
                },
            ),
            (
                "roll_due",
                Observed {
                    roll_due: None,
                    ..observed
                },
                VolumeEntry {
                    roll_due: empty.roll_due,
                    ..full
                },
            ),
            (
                "roll_active",
                Observed {
                    roll_active: None,
                    ..observed
                },
                VolumeEntry {
                    roll_active: empty.roll_active,
                    ..full
                },
            ),
        ];
        for (part, reduced, expected) in rows {
            assert_eq!(entry(&scene, now, &reduced), expected, "{part} missing");
        }
        let authority = scene.owner.authority_report();
        assert_eq!(
            (full.registrants, full.hold),
            (
                authority.registrants.map(Registrants::from),
                Some(Hold::from(authority.hold))
            ),
            "the authority's judgment and hold"
        );
    });
}

/// The watermark reads the client's alarm and the withdrawal reads the serving machine, two separate sources: a
/// client's regression alarm on a serving tenure reads `watermark = regression` and no withdrawal, a regression
/// withdrawal the test delivers to the machine reads `withdrawal = regression` with no watermark, and both together
/// read both. A `namespace` alarm reads `watermark = namespace`. A clear alarm on a serving tenure reads `clear` and
/// no withdrawal.
#[test]
fn the_client_alarm_reads_the_watermark_beside_the_machine_withdrawal() {
    scene(&[], |mut scene| {
        let now = viewed(&mut scene, active());
        let with_alarm = |alarm| Observed {
            alarm: Some(alarm),
            ..Observed::UNAVAILABLE
        };
        let clear = entry(&scene, now, &with_alarm(Alarm::Clear));
        assert_eq!(
            (clear.watermark, clear.withdrawal),
            (Watermark::Clear, None)
        );
        let namespace = entry(&scene, now, &with_alarm(Alarm::Namespace));
        assert_eq!(
            (namespace.watermark, namespace.withdrawal),
            (Watermark::Namespace, None)
        );
        let owner = regressed();
        let alarmed = entry(&scene, now, &with_alarm(owner.alarm()));
        assert_eq!(
            (alarmed.watermark, alarmed.withdrawal),
            (Watermark::Regression, None),
            "the alarm alone withdraws nothing"
        );
        scene
            .owner
            .authority_event(Event::Withdraw(Cause::Regression), now);
        let withdrawn = entry(&scene, now, &Observed::UNAVAILABLE);
        assert_eq!(
            (withdrawn.watermark, withdrawn.withdrawal),
            (Watermark::Unavailable, Some(Withdrawal::Regression)),
            "the withdrawal alone raises no watermark"
        );
        let regression = entry(&scene, now, &with_alarm(owner.alarm()));
        assert_eq!(
            (regression.watermark, regression.withdrawal),
            (Watermark::Regression, Some(Withdrawal::Regression))
        );
    });
}

#[test]
fn the_flip_bit_reads_a_retirement_trigger_and_stays_clear_for_a_planned_exit() {
    for (cause, withdrawal, flip) in [
        (Cause::Attachment, Withdrawal::Attachment, true),
        (Cause::Regression, Withdrawal::Regression, false),
        (Cause::Planned, Withdrawal::Planned, false),
    ] {
        scene(&[], |mut scene| {
            let now = viewed(&mut scene, active());
            let serving = entry(&scene, now, &Observed::UNAVAILABLE);
            assert_eq!((serving.withdrawal, serving.flip), (None, false));
            scene.owner.authority_event(Event::Withdraw(cause), now);
            let withdrawn = entry(&scene, now, &Observed::UNAVAILABLE);
            assert_eq!(
                (withdrawn.serving, withdrawn.withdrawal, withdrawn.flip),
                (
                    Some(crate::failover::serving::State::Withdrawn),
                    Some(withdrawal),
                    flip
                ),
                "{cause:?}"
            );
        });
    }
}

/// `roll_due` and `roll_active` read the driver's flags and `publication_due` the suffix signal's publication bit.
/// `roll_due` with no suffix handoff signal (a tenure with no free checkpoint slot, or a stage refused for placement)
/// reads set, a handoff signal with `roll_due` clear reads clear, and with both flags clear the entry reads both
/// clear. The rows where the handoff signal and `roll_due` differ reject a builder that takes `roll_due` from the
/// signal, and the rows where the handoff and publication bits differ reject one that reads the handoff bit as
/// `publication_due`.
#[test]
fn the_roll_flags_come_from_the_driver_alone() {
    scene(&[], |mut scene| {
        let now = viewed(&mut scene, active());
        for (handoff, publication, due, active) in [
            (false, true, true, false),
            (true, false, false, false),
            (false, false, false, true),
            (false, false, false, false),
        ] {
            let observed = Observed {
                suffix_due: Some(SuffixDue {
                    handoff,
                    publication,
                }),
                roll_due: Some(due),
                roll_active: Some(active),
                ..Observed::UNAVAILABLE
            };
            let entry = entry(&scene, now, &observed);
            assert_eq!(
                (entry.roll_due, entry.roll_active, entry.publication_due),
                (Some(due), Some(active), Some(publication)),
                "handoff {handoff}"
            );
        }
    });
}

/// A driver's quarantine gauge whose count exceeds its limit reads unavailable and the entry still encodes, while a
/// gauge within its limit reads as given.
#[test]
fn an_over_limit_quarantine_gauge_reads_unavailable() {
    scene(&[], |mut scene| {
        let now = viewed(&mut scene, active());
        let with = |quarantine| Observed {
            quarantine,
            ..Observed::UNAVAILABLE
        };
        let over = Gauge::Known {
            used: 4,
            limit: std::num::NonZeroU64::new(3).unwrap(),
        };
        let base = entry(&scene, now, &Observed::UNAVAILABLE);
        assert_eq!(entry(&scene, now, &with(over)), base);
        let within = entry(&scene, now, &with(Gauge::known(1, 3)));
        assert_eq!(within.pressure.quarantine, Gauge::known(1, 3));
    });
}

/// `served` counts the attach's complete reads and `read_defects` its reads that failed their identity or checksum
/// check: a fresh attach reads zero of both, one complete read raises `served` by one and records the first-hit
/// time, and a read of the record after one payload byte flipped raises `read_defects` by one.
#[test]
fn the_attach_reads_give_served_and_read_defects() {
    scene(&[], |mut scene| {
        let now = viewed(&mut scene, active());
        let fresh = entry(&scene, now, &Observed::UNAVAILABLE);
        assert_eq!((fresh.served, fresh.read_defects), (Some(0), Some(0)));
        assert_eq!(fresh.times.first_hit_us, None, "no read completed yet");
        let name = 1;
        assert_eq!(
            scene.read(0, name, 0).0,
            Some(super::fetch::Outcome::Complete)
        );
        let served = entry(&scene, scene.turn * 100, &Observed::UNAVAILABLE);
        assert_eq!((served.served, served.read_defects), (Some(1), Some(0)));
        assert_eq!(
            served.times,
            crate::failover::report::RecoveryTimes::of(&scene.owner.recovery_report())
        );
        assert!(
            served.times.first_hit_us.is_some(),
            "the first complete read at Live records the first hit"
        );
        flip(&scene, 300);
        assert_ne!(
            scene.read(0, name, 0).0,
            Some(super::fetch::Outcome::Complete)
        );
        let defective = entry(&scene, scene.turn * 100, &Observed::UNAVAILABLE);
        assert_eq!(
            (
                defective.served,
                defective.read_defects,
                scene.owner.volume_report().chunk_mismatch
            ),
            (Some(1), Some(1), 1),
            "the flipped payload fails its checksum"
        );
        let defects = |entries: [&VolumeEntry; 2]| entries.map(|entry| entry.read_defects.unwrap());
        let read_defect = crate::failover::report::alarm_tests::controls::read_defect();
        assert_eq!(
            defects([&fresh, &defective]),
            read_defect.fault,
            "read-defect"
        );
        assert_eq!(defects([&fresh, &served]), read_defect.clean, "read-defect");
    });
    // A flipped allocation byte of the record header fails the first extent's header check, which counts; a first
    // extent's key mismatch, which the read answers `Missing`, would not.
    scene(&[], |mut scene| {
        let now = viewed(&mut scene, active());
        flip(&scene, 48);
        assert_ne!(scene.read(0, 1, 0).0, Some(super::fetch::Outcome::Complete));
        let report = scene.owner.volume_report();
        let entry = entry(&scene, now, &Observed::UNAVAILABLE);
        assert_eq!(
            (
                entry.read_defects,
                report.header_mismatch,
                report.lookup_false_positives
            ),
            (Some(1), 1, 0),
            "a header failure other than the key counts"
        );
    });
}

/// A volume record with `MAX_ATTACHED` live attaches reads a full attach gauge, and one with two live attaches reads
/// two of three.
#[test]
fn the_attach_gauge_reads_the_live_attaches_of_the_own_volume_record() {
    use crate::failover::takeover::tests::{b_host, b_pair, c_host, c_pair, lineage};
    for (successors, live) in [(2, 3), (1, 2)] {
        scene(&[], |mut scene| {
            let hosts = [(c_host(), c_pair()), (b_host(), b_pair())];
            let record = VolumeRecord {
                volume: VolumeId::new("vol-0a").unwrap(),
                ..lineage(&hosts[..successors])
            };
            let now = viewed(&mut scene, record);
            let entry = entry(&scene, now, &Observed::UNAVAILABLE);
            assert_eq!(
                entry.attaches,
                Gauge::known(live, 3),
                "{successors} successors"
            );
        });
    }
}

/// Held INVALIDATEs at the hold bound read a full invalidation gauge, and a saturated coverage page reads one
/// saturated page of the page count. With no hold and no saturated page both gauges read zero.
#[test]
fn held_invalidations_and_saturated_pages_fill_their_gauges() {
    let bound = super::owner::INVALIDATIONS;
    for loaded in [true, false] {
        scene(&[], |mut scene| {
            let now = viewed(&mut scene, active());
            assert_eq!(
                entry(&scene, now, &Observed::UNAVAILABLE).coverage,
                Coverage::UNAVAILABLE,
                "no coverage before the fencing"
            );
            let store = store_tests::seeded_under(scene.owner.tenure());
            if loaded {
                let page = Key::Page(store_tests::shard(), 1);
                let mut writer = client(&store);
                let read = writer
                    .read::<crate::failover::records::CoveragePage>(page)
                    .unwrap();
                let saturated = crate::failover::records::CoveragePage {
                    saturated: true,
                    ..read.value().clone()
                };
                writer.replace(&read, saturated).unwrap();
            }
            let (fencing, _) = fenced_coverage(&store, scene.owner.tenure());
            scene.owner.install_coverage(fencing).unwrap();
            let mut held = 0;
            if loaded {
                for name in 0..=u8::MAX {
                    let mut budget = WorkBudget::new(1 << 12);
                    let removal = (scene.owner).invalidate_interval(
                        &key(name),
                        versions(3, 5),
                        4,
                        &mut budget,
                    );
                    held += usize::from(matches!(removal, Ok(Some(_))));
                    if held == bound {
                        break;
                    }
                }
                assert_eq!(held, bound, "the hold fills");
            }
            let entry = entry(&scene, now, &Observed::UNAVAILABLE);
            assert_eq!(
                (entry.invalidations, entry.coverage.saturated),
                (
                    Gauge::known(held as u64, bound as u64),
                    Gauge::known(u64::from(loaded), 2)
                ),
                "loaded: {loaded}"
            );
            use crate::failover::report::alarm_tests::controls;
            let (backlog, saturated) = (
                controls::mutation_backlog_full(),
                controls::coverage_saturated(),
            );
            assert_eq!(
                (entry.invalidations, entry.coverage.saturated),
                (backlog.pick(loaded), saturated.pick(loaded)),
                "mutation-backlog-full and coverage-saturated"
            );
            let mut reader = client(&store);
            let largest = (0..2)
                .map(|page| {
                    let key = Key::Page(store_tests::shard(), page);
                    let read = reader.read::<crate::failover::records::CoveragePage>(key);
                    read.unwrap().value().encoded_len() as u64
                })
                .max()
                .unwrap();
            let capacity = store_tests::stored(&store).1.page_cap.get();
            assert_eq!(
                entry.coverage.largest,
                Gauge::known(largest, u64::from(capacity)),
                "the largest stored page of the shard record's page capacity"
            );
            assert_eq!(
                entry.suffix,
                Backlog::UNAVAILABLE,
                "a cold tenure opens no suffix"
            );
        });
    }
}

/// Entry counts restart with the tenure: an incarnation whose attach served one complete read and failed one checksum
/// reads `served = 1` and `read_defects = 1`, and the next incarnation over the same media, a new attach serving a
/// later attempt of the generation, reads zero of both under its own tenure before its first read.
#[test]
fn a_relaunched_tenure_starts_its_counts_at_zero() {
    use super::restart::{MANIFEST, Run, restart_scene};
    restart_scene(
        MANIFEST,
        |Run {
             mut scene,
             mut life,
             mut fresh,
             ..
         }| {
            viewed_at(&mut scene, active(), 1);
            assert_eq!(scene.read(0, 1, 0).0, Some(super::fetch::Outcome::Complete));
            flip(&scene, 300);
            assert_ne!(scene.read(0, 1, 0).0, Some(super::fetch::Outcome::Complete));
            let first = entry(&scene, scene.turn * 100, &Observed::UNAVAILABLE);
            assert_eq!((first.served, first.read_defects), (Some(1), Some(1)));
            super::restart_tests::kill(&mut life, scene);
            life.dead_mut(0)
                .dispose(crate::storage::device::sim::QuiesceMode::AllReturned)
                .unwrap();
            let mut scene = super::restart_tests::relaunch(&mut life, fresh.remove(0));
            let now = viewed_at(&mut scene, active(), 2);
            let next = entry(&scene, now, &Observed::UNAVAILABLE);
            assert_ne!(
                next.tenure, first.tenure,
                "the relaunch serves a new tenure"
            );
            assert_eq!((next.served, next.read_defects), (Some(0), Some(0)));
        },
    );
}
