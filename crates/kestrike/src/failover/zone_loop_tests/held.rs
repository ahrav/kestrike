//! A live owner whose report holds the diagnostic entry that `host::recover::held_status` builds gives its shard the
//! blocker `restart-held` at the record's tenure and one attempt above it, reads blocked, plans no step and writes
//! nothing.

use crate::failover::records::ShardRecord;
use crate::failover::report::status::{CLASSES, Class};
use crate::failover::report::{Phase, RecordedRole, VolumeEntry};
use crate::failover::sim::host;
use crate::failover::standbys::lists_standby;
use crate::failover::zone_loop::Tick;
use crate::failover::zone_loop::plan::device_hold;
use crate::failover::zone_loop::status::{Blocker, ShardState};
use crate::net::ownership::{ActivatedEpoch, ShardGeneration};
use crate::storage::store::sim::MemLog;
use crate::storage::store::{Client, Key};

use super::observe::{Fixture, S, START, id, owner_of, volume};
use super::survey::{designate_all, warm};

fn record(fixture: &Fixture) -> ShardRecord {
    let mut client = Client::open(fixture.store.clone(), MemLog::default()).unwrap();
    *client
        .read::<ShardRecord>(Key::Shard(id(1)))
        .unwrap()
        .value()
}

/// Commits `n` bumps of shard 1's record.
fn bump(fixture: &Fixture, n: u32) {
    let mut client = Client::open(fixture.store.clone(), MemLog::default()).unwrap();
    for _ in 0..n {
        let stored = client.read::<ShardRecord>(Key::Shard(id(1))).unwrap();
        client.bump(&stored).unwrap();
    }
}

/// The held restart's entry for a restart that read `read`.
fn held(read: &ShardRecord) -> VolumeEntry {
    let status = crate::host::agent::tests::held_final(read, 7);
    status.entry.expect("the held restart's entry")
}

fn class(tick: &Tick, class: Class) -> u32 {
    let at = CLASSES.iter().position(|listed| *listed == class);
    tick.part.classes[at.unwrap()]
}

struct Run {
    tick: Tick,
    wrote: bool,
}

/// Six hosts; shard 1 has owner H2 and named standby H3.
fn fixture() -> Fixture {
    let mut fixture = Fixture::new(6, 1);
    warm(&mut fixture, 12);
    designate_all(&fixture);
    let record = record(&fixture);
    assert_eq!(
        (record.owner, record.standby),
        (owner_of(1, 6), Some(host(3)))
    );
    fixture
}

/// After `bumps` bumps, `publisher` reports `entries` once and every other host reports none; then each tick for
/// 300 s every host outside `silent` reports again.
fn run(bumps: u32, publisher: u64, entries: &[VolumeEntry], silent: &[u64]) -> Run {
    let mut fixture = fixture();
    bump(&fixture, bumps);
    let before = fixture.commits();
    for number in 1..=fixture.hosts {
        let published = if number == publisher { entries } else { &[] };
        fixture.publish(number, published);
    }
    let mut last = None;
    for at in 0..=30 {
        for number in (1..=fixture.hosts).filter(|number| !silent.contains(number)) {
            let published = if number == publisher { entries } else { &[] };
            fixture.publish(number, published);
        }
        let now_us = START + (200 + 10 * at) * S;
        let directory = Ok(fixture.directory());
        last = Some(fixture.zone.tick(directory, &mut fixture.world, now_us));
    }
    Run {
        tick: last.unwrap(),
        wrote: fixture.commits() != before,
    }
}

fn row(run: &Run) -> (ShardState, Option<Blocker>) {
    let row = run.tick.survey.status.shards[0];
    (row.state, row.blocker)
}

/// The record stands at the `E` the restart read or, after a committed bump, at `E + 1`; both read `restart-held`,
/// the class blocked, no step and no write. Without the match, `E` reads `DeviceFailureHold` and `E + 1` no
/// blocker.
#[test]
fn a_live_owner_s_held_restart_reads_restart_held_at_either_bump_outcome() {
    let read = record(&fixture());
    for bumps in [0, 1] {
        let run = run(bumps, 2, &[held(&read)], &[]);
        assert_eq!(
            row(&run),
            (ShardState::Protected, Some(Blocker::RestartHeld)),
            "bumps {bumps}"
        );
        assert_eq!(class(&run.tick, Class::Blocked), 1, "bumps {bumps}");
        let at = Blocker::RestartHeld.position();
        assert_eq!(run.tick.part.blockers[at], 1, "bumps {bumps}");
        assert_eq!(run.tick.part.stale_serving, 0, "bumps {bumps}");
        let steps = &run.tick.survey.plan.steps;
        assert!(steps.is_empty(), "bumps {bumps}: {steps:?}");
        assert!(!run.wrote, "bumps {bumps}: the blocker writes no store key");
    }
}

/// Two attempts past the read, another host's report, another volume, another generation and a silent owner give
/// no `restart-held`.
#[test]
fn a_held_restart_entry_matches_only_its_owner_volume_generation_and_one_attempt() {
    let read = record(&fixture());
    let entry = held(&read);
    let other_volume = VolumeEntry {
        volume: volume(2),
        ..entry
    };
    let other_generation = VolumeEntry {
        tenure: Some((
            ShardGeneration::new(read.generation.get() + 1).unwrap(),
            ActivatedEpoch::new(2 * read.attempts).unwrap(),
        )),
        ..entry
    };
    let cases = [
        ("two attempts past the read", run(2, 2, &[entry], &[])),
        ("another host", run(0, 4, &[entry], &[])),
        ("another volume", run(0, 2, &[other_volume], &[])),
        ("another generation", run(0, 2, &[other_generation], &[])),
        ("a silent owner", run(0, 2, &[entry], &[2])),
    ];
    for (name, run) in cases {
        let (_, blocker) = row(&run);
        assert_ne!(blocker, Some(Blocker::RestartHeld), "{name}");
        assert_eq!(class(&run.tick, Class::Blocked), 0, "{name}");
    }
}

/// The readers of an entry's tenure, at `E` and `E + 1`: the join keeps the entry out of `ShardRecords::entries` and
/// in `ShardRecords::held`; the standby census credits nothing; `device_hold`, which `holds_device` reads, reads no
/// hold. The status builder is judged in `a_live_owner_s_held_restart_reads_restart_held_at_either_bump_outcome`,
/// the alarm evaluator in
/// `failover::report::alarm_tests::a_held_restart_entry_pages_unknown_recovery_write_alone_and_starts_no_counter_series`
/// and the heartbeat in
/// `host::agent::tests::a_held_restart_s_final_status_seals_its_entry_past_the_freshness_bound_with_no_heartbeat_entry`.
#[test]
fn every_reader_of_an_entry_s_tenure_reads_the_held_restart_entry_as_a_diagnostic_at_e_and_e_plus_one()
 {
    let read = record(&fixture());
    let entry = held(&read);
    assert_eq!(
        (entry.role, entry.phase),
        (Some(RecordedRole::Owner), Some(Phase::Held))
    );
    assert!(!device_hold(&entry), "no device hold");
    let device = VolumeEntry {
        recovery: crate::failover::report::Recovery {
            check: Some(crate::failover::report::RecoveryCheck::FirstReport),
            store: None,
            ..entry.recovery
        },
        ..entry
    };
    assert!(
        device_hold(&device),
        "a hold at Report #1 reads a device hold"
    );
    for bumps in [0, 1] {
        let mut fixture = fixture();
        bump(&fixture, bumps);
        for number in 1..=fixture.hosts {
            let published = if number == 2 { vec![entry] } else { vec![] };
            fixture.publish(number, &published);
        }
        let observation = fixture.observe(START + 200 * S);
        let view = observation.zone.as_ref().expect("a zone view");
        let records = match &view.shards[0].records {
            Ok(Some(records)) => records,
            other => panic!("bumps {bumps}: {other:?}"),
        };
        assert!(
            records.entries.is_empty(),
            "bumps {bumps}: {:?}",
            records.entries
        );
        assert_eq!(records.held, Some((host(2), entry)), "bumps {bumps}");
        let owner = (view.hosts.iter())
            .find(|view| view.entry.host == host(2))
            .unwrap();
        let report = owner.report.as_ref().unwrap();
        assert!(
            !lists_standby(report, 1, volume(1)),
            "bumps {bumps}: no standby credit"
        );
    }
}

/// The control: a match at the record's tenure alone misses the restart whose bump committed.
#[test]
fn the_control_that_matches_the_record_s_tenure_alone_misses_the_committed_bump() {
    use crate::failover::zone_loop::observe::HELD_AT_RECORD_ONLY;
    let read = record(&fixture());
    HELD_AT_RECORD_ONLY.set(true);
    let planted = run(1, 2, &[held(&read)], &[]);
    HELD_AT_RECORD_ONLY.set(false);
    assert_eq!(
        row(&planted),
        (ShardState::Protected, None),
        "the planted match at the record's tenure alone misses the committed bump"
    );
}
