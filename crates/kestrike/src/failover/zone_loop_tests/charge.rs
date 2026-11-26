//! The tests require the planner and `Reconciler::reserve` to credit the same standby entries within a tick. A census
//! entry charges its host one attachment until that host's report lists the entry's shard in the standby role on the
//! active volume of the shard record the survey read.

use crate::failover::reconcile::StandbyGate;
use crate::failover::records::{ShardRecord, VolumeId};
use crate::failover::report::tests::bare;
use crate::failover::report::{Gauge, RecordedRole, VolumeEntry};
use crate::failover::retire::Target;
use crate::failover::sim::host;
use crate::failover::standbys::{Entry, Refusal};
use crate::failover::zone_loop::actuate::{Outcome, Reason, Verdict};
use crate::failover::zone_loop::directory::Color;
use crate::failover::zone_loop::plan::{Step, Survey};
use crate::failover::zone_loop::status::{Blocker, ShardState};
use crate::net::ownership::ShardGeneration;
use crate::storage::store::{Key, Outcome as Written, Store, Write};

use super::actuate::{census_of, shard, stored};
use super::observe::{Fixture, S, START, ZONE, volume};
use super::survey::{designate_attached, roomy_fixture, state_of};

fn fixture() -> Fixture {
    let mut fixture = roomy_fixture(3, 2);
    fixture.headroom.attachments = Gauge::known(1, 2);
    let listing = fixture.listing.as_mut().unwrap();
    for entry in &mut listing.hosts {
        entry.placement.color = Color(u16::from(entry.host == host(1)));
    }
    fixture
}

fn standby(number: u32, volume: VolumeId) -> VolumeEntry {
    VolumeEntry {
        shard: shard(number),
        ..bare(volume.as_str(), RecordedRole::Standby)
    }
}

fn old() -> VolumeId {
    VolumeId::new("vol-0f").unwrap()
}

fn survey(fixture: &mut Fixture, now_us: u64, listed: &[VolumeEntry]) -> Survey {
    for number in 1..=fixture.hosts {
        let entries = if number == 1 { listed } else { &[] };
        fixture.publish(number, entries);
    }
    let directory = Ok(fixture.directory());
    (fixture.zone).survey(directory, &mut fixture.world, now_us)
}

fn warmed(fixture: &mut Fixture, listed: &[VolumeEntry]) -> Survey {
    for tick in 0..12 {
        survey(fixture, START + tick * 10 * S, listed);
    }
    let surveyed = survey(fixture, START + 120 * S, listed);
    assert!(!surveyed.plan.holds.warm_up);
    surveyed
}

fn reserves(survey: &Survey) -> Vec<u32> {
    let reserve = |step: &Step| match *step {
        Step::Reserve {
            shard, host: held, ..
        } if held == host(1) => Some(shard.get()),
        _ => None,
    };
    survey.plan.steps.iter().filter_map(reserve).collect()
}

fn actuated(fixture: &mut Fixture, survey: &Survey) -> Vec<(u32, Verdict)> {
    let gate = StandbyGate::qualified();
    let outcomes = (fixture.zone).actuate(&gate, survey, START + 120 * S, &mut fixture.world);
    let reserved = |outcome: &Outcome| match outcome.step {
        Step::Reserve { shard, .. } => Some((shard.get(), outcome.verdict)),
        _ => None,
    };
    outcomes.unwrap().iter().filter_map(reserved).collect()
}

fn commit(fixture: &Fixture, key: Key, value: Vec<u8>) {
    let mut store = fixture.store.clone();
    let held = store.0.borrow().current(&key).map(|item| item.version);
    let write = match held {
        Some(expect) => Write::Exact { expect, value },
        None => Write::Create(value),
    };
    assert!(matches!(store.write(&key, &write), Written::Committed(_)));
}

fn written_by_another(fixture: &Fixture, entry: Entry) {
    let census = crate::failover::standbys::tests::listing(ZONE, shard(1), entry);
    let value = crate::failover::records::Record::encode(&census);
    commit(fixture, Key::Standbys(ZONE), value);
}

fn entry_of(fixture: &Fixture, raised: u64) -> Entry {
    let record: ShardRecord = stored(&fixture.store, Key::Shard(shard(1)));
    let mut target = Target::of(&record);
    target.generation = ShardGeneration::new(target.generation.get() + raised).unwrap();
    Entry {
        target,
        host: host(1),
    }
}

fn headroom() -> Verdict {
    Verdict::Wait(Reason::Population(Refusal::Headroom))
}

#[test]
fn two_reservations_on_one_tick_credit_a_standby_entry_only_on_the_active_volume() {
    for (listed, expected) in [(volume(1), vec![1, 2]), (old(), vec![1])] {
        let case = format!("{listed:?}");
        let mut fixture = fixture();
        let survey = warmed(&mut fixture, &[standby(1, listed)]);
        assert_eq!(reserves(&survey), expected, "{case}");
        if expected.len() == 1 {
            let refused = (ShardState::NoCandidate, Some(Blocker::Headroom));
            assert_eq!(state_of(&survey.plan, 2), refused, "{case}");
        }
        let verdicts = actuated(&mut fixture, &survey);
        let advanced: Vec<_> = expected.iter().map(|&n| (n, Verdict::Advance)).collect();
        assert_eq!(verdicts, advanced, "{case}");
        let census = census_of(&fixture.store).unwrap();
        assert_eq!(census.len(), expected.len(), "{case}");
    }
}

#[test]
fn a_census_reread_after_another_reconciler_acted_credits_only_the_surveyed_active_volume() {
    let cases = [
        (volume(1), 0, true),
        (old(), 0, false),
        (volume(1), 1, false),
    ];
    for (listed, raised, admitted) in cases {
        let case = format!("{listed:?} raised {raised}");
        let mut fixture = fixture();
        designate_attached(&fixture, 1, host(1));
        let survey = warmed(&mut fixture, &[standby(1, listed)]);
        assert_eq!(reserves(&survey), [2], "{case}");
        let entry = entry_of(&fixture, raised);
        written_by_another(&fixture, entry);
        let verdicts = actuated(&mut fixture, &survey);
        let expected = if admitted {
            Verdict::Advance
        } else {
            headroom()
        };
        assert_eq!(verdicts, [(2, expected)], "{case}");
        let census = census_of(&fixture.store).unwrap();
        assert_eq!(census.slot(shard(1)), Some(entry), "{case}");
        assert_eq!(census.slot(shard(2)).is_some(), admitted, "{case}");
    }
}

#[test]
fn the_planner_and_reserve_credit_the_same_standby_entries_on_one_tick() {
    let cases = [
        (volume(1), false, true),
        (old(), false, false),
        (volume(1), true, false),
    ];
    for (listed, unread, admitted) in cases {
        let case = format!("{listed:?} unread {unread}");
        let mut fixture = fixture();
        designate_attached(&fixture, 1, host(1));
        written_by_another(&fixture, entry_of(&fixture, 0));
        let listed = [standby(1, listed)];
        for tick in 0..12 {
            survey(&mut fixture, START + tick * 10 * S, &listed);
        }
        if unread {
            commit(&fixture, Key::Shard(shard(1)), vec![0xff; 8]);
        }
        let survey = survey(&mut fixture, START + 120 * S, &listed);
        assert!(!survey.plan.holds.warm_up, "{case}");
        let view = survey.observation.zone.as_ref().unwrap();
        assert_eq!(view.shards[0].records.is_err(), unread, "{case}");
        let expected: Vec<u32> = if admitted { vec![2] } else { Vec::new() };
        assert_eq!(reserves(&survey), expected, "{case}");
        if !admitted {
            let refused = (ShardState::NoCandidate, Some(Blocker::Headroom));
            assert_eq!(state_of(&survey.plan, 2), refused, "{case}");
        }
        let verdicts = actuated(&mut fixture, &survey);
        let advanced: Vec<_> = expected.iter().map(|&n| (n, Verdict::Advance)).collect();
        assert_eq!(verdicts, advanced, "{case}");
    }
}
