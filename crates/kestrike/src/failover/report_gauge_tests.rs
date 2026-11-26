//! The frontier and full gauges of the owner's report entry need the own volume active.
//!
//! The frontier and full gauges of the owner's report entry read the recorded history, and an owner whose
//! shard record names another volume active reports them unavailable, since that record's history lies on the
//! active volume's region.
//!
//! Each test runs the owner of the net test scene, serving a tenure of volume `vol-0a`, through the same steps:
//! an observed shard view whose record names `vol-0a` active, with a cut and two ancestry suffixes, and whose
//! volume read gives the layout; then one later observed shard record. `Owner::report_entry` is read after each
//! observation, once in a share window that refused no charge and once in a window that
//! `Owner::refuse_recovery_io` made refuse.
//!
//! - `a_record_naming_another_volume_active_reports_frontier_and_full_unavailable`: the later record names
//!   `vol-0b` active. Both gauges then read `Gauge::Unavailable`, with and without a refused share window, and
//!   the ancestry gauge is still known.
//! - `a_record_naming_the_own_volume_active_keeps_frontier_and_full_known`: the later record changes the
//!   owner and keeps `vol-0a` active, and both gauges keep the readings of the first record.
//!
//! The expected readings are computed here from the scripted record and layout, not read from the entry. Each
//! test collects its readings inside the scene, lets the scene go, and asserts last.

use std::num::NonZeroU64;

use super::records::{Ancestry, NamedCheckpoint, ShardRecord, Suffix, VolumeId, VolumeState};
use super::report::{Gauge, Observed, Pressure, RecordedRole};
use super::sim::host;
use crate::net::owner_tenure_tests::{observe, serve_at, shard_at, token, volume_record};
use crate::net::put_tests::scene;
use crate::storage::store_tests::SPARE;

/// The generation of the scripted tenure.
const GENERATION: u64 = 3;
/// The record's cut and the bounds of its two suffixes: the first starts below the cut.
const CUT: u64 = 10;
const FIRST: (u64, u64) = (5, 20);
const LAST: (u64, u64) = (20, 30);
/// The delta blocks the record's replay requires: from the cut, which lies above the first suffix's start, to
/// the end of the last suffix.
const REQUIRED: u64 = LAST.1 - CUT;
/// The delta region of the layout `volume_record` gives: 64 units less the first and 3 slots of 2 units.
const REGION: u64 = 64 - (1 + 3 * 2);
/// The bound of the ancestry gauge, the longest chain a record keeps.
const CHAIN: u64 = 4;
/// The resources the full gauge counts: the ancestry, the delta history and the recovery I/O share.
const RESOURCES: u64 = 3;

fn known(used: u64, limit: u64) -> Gauge {
    Gauge::Known {
        used,
        limit: NonZeroU64::new(limit).unwrap(),
    }
}

/// The later record a run observes.
#[derive(Clone, Copy)]
enum Later {
    /// Names `vol-0b` active under another owner, with `vol-0a` as its spare.
    AnotherVolume,
    /// Names `vol-0a` active under another owner.
    OwnVolume,
}

/// What one run read from the owner's entries.
struct Run {
    /// The role after the first record, which shows the owner accepted it.
    first_role: Option<RecordedRole>,
    /// The pressure after the first record, in a clear share window and in a refused one.
    first: [Pressure; 2],
    /// Whether the later record names the own volume active, as the entry's role shows the owner accepted it.
    later_role: Option<RecordedRole>,
    /// The pressure after the later record, in a clear share window and in a refused one.
    later: [Pressure; 2],
}

/// Serves a tenure, observes the own-active record with the volume read, then `later`, and reads the entry's
/// pressure in a clear and in a refused share window after each.
fn run(later: Later) -> Run {
    let mut out = None;
    scene(&[], |mut scene| {
        serve_at(&mut scene, GENERATION, 1);
        let token = token(&scene);
        let suffix = |epoch: u64, (start, end): (u64, u64)| Suffix {
            session: (GENERATION << 32) | epoch,
            start,
            certified: end,
            end,
        };
        let record = ShardRecord {
            checkpoint: Some(NamedCheckpoint {
                slot: 1,
                session: (GENERATION << 32) | 2,
                capture: 4,
                units: 8,
            }),
            cut: CUT,
            ancestry: Ancestry::new(&[suffix(2, FIRST), suffix(4, LAST)]).unwrap(),
            ..shard_at(token, GENERATION, token.epoch.get() / 2)
        };
        let own = VolumeId::new("vol-0a").unwrap();
        let volume = volume_record("vol-0a", VolumeState::Active);
        // Reads the pressure at `at` in a window that refused nothing, then refuses a charge in the window
        // open one interval of the share's clock later and reads there.
        let mut window = 0;
        let mut read = |scene: &mut crate::net::put_tests::Scene<'_, '_>| {
            window += 1;
            let clear = scene.turn * 100 + window * 1_000_000;
            let refused = clear + 500_000;
            let before = scene
                .owner
                .report_entry(clear, &Observed::UNAVAILABLE)
                .unwrap();
            scene.owner.refuse_recovery_io(refused);
            let after = scene
                .owner
                .report_entry(refused, &Observed::UNAVAILABLE)
                .unwrap();
            (before.role, [before.pressure, after.pressure])
        };
        observe(&mut scene, Some(record), Some(volume), token.exhid);
        let (first_role, first) = read(&mut scene);
        let next = match later {
            Later::AnotherVolume => ShardRecord {
                owner: host(SPARE),
                active: VolumeId::new("vol-0b").unwrap(),
                spare: Some((own, record.owner)),
                ..record
            },
            Later::OwnVolume => ShardRecord {
                owner: host(SPARE),
                spare: None,
                ..record
            },
        };
        scene.turn += 1;
        observe(&mut scene, Some(next), None, token.exhid);
        let (later_role, later) = read(&mut scene);
        out = Some(Run {
            first_role,
            first,
            later_role,
            later,
        });
    });
    out.expect("the scene ran its body")
}

/// The pressure the property gives the own-active record: the required blocks of the region, two suffixes of
/// the chain, and of the three history resources only the share at its bound, when its window refused.
fn own_active(share_refused: bool) -> Pressure {
    Pressure {
        frontier: known(REQUIRED, REGION),
        ancestry: known(2, CHAIN),
        quarantine: Gauge::Unavailable,
        full: known(u64::from(share_refused), RESOURCES),
    }
}

/// Premises of both tests: the owner accepted the first record as its own, and its entry then carries the
/// gauges of that record in a clear and in a refused window.
fn first_record_is_reported(run: &Run) {
    assert_eq!(
        run.first_role,
        Some(RecordedRole::Owner),
        "premise first-record-accepted: the entry's role after the own-active record"
    );
    assert_eq!(
        run.first,
        [own_active(false), own_active(true)],
        "while the record names the own volume active, frontier is the required delta blocks of J \
         and full counts the resources at their bound, the refused share among them"
    );
}

#[test]
fn a_record_naming_another_volume_active_reports_frontier_and_full_unavailable() {
    let run = run(Later::AnotherVolume);
    first_record_is_reported(&run);
    assert_eq!(
        run.later_role,
        Some(RecordedRole::Replacement),
        "premise later-record-accepted: the entry's role after the record that names vol-0b active"
    );
    let unavailable = Pressure {
        frontier: Gauge::Unavailable,
        ancestry: known(2, CHAIN),
        quarantine: Gauge::Unavailable,
        full: Gauge::Unavailable,
    };
    assert_eq!(
        run.later,
        [unavailable, unavailable],
        "an owner whose shard record names another volume active reports frontier and full \
         unavailable, in a clear and in a refused share window, and its ancestry gauge stays known"
    );
}

#[test]
fn a_record_naming_the_own_volume_active_keeps_frontier_and_full_known() {
    let run = run(Later::OwnVolume);
    first_record_is_reported(&run);
    assert_ne!(
        run.later_role,
        Some(RecordedRole::Owner),
        "premise later-record-accepted: the entry's role after the record that names another owner"
    );
    assert_eq!(
        run.later,
        [own_active(false), own_active(true)],
        "a later record that still names the own volume active keeps frontier and full known"
    );
}
