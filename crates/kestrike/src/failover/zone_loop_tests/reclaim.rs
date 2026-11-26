use crate::failover::arbiter::Partition;
use crate::failover::attachments::InstanceId;
use crate::failover::evidence::Pair;
use crate::failover::reconcile::{Binding as RecordBinding, Listing, Reconciler, StandbyGate};
use crate::failover::records::{
    ERA, EventKind, Host, MAX_ATTACHED, RecordedPair, ShardRecord, VolumeId, VolumeRecord,
    attachment_key,
};
use crate::failover::retire::Target;
use crate::failover::sim::host;
use crate::failover::standbys::Need;
use crate::failover::zone_loop::actuate::{Outcome, Reason, Reclaim, Verdict};
use crate::failover::zone_loop::plan::{Step, Survey};
use crate::failover::zone_loop::status::{Blocker, ShardState};
use crate::storage::store::Key;
use crate::storage::store::sim::Arm;

use super::actuate::{
    After, Cell, Faults, Hook, census_of, hosts_of, keeps_volume, owner, plant_volume,
    reconciler_client, shard,
};
use super::config::config_of;
use super::directory::instance;
use super::observe::{S, START, ZONE, volume};
use super::world::{AttachFault, DetachFault, Event};

fn gone(cell: &Cell, number: u32, host: Host) -> bool {
    let held = cell.volume(number);
    held.latest(host)
        .is_some_and(|(_, event)| event.kind == EventKind::Gone)
}

fn host_of(step: &Step) -> Option<Host> {
    match *step {
        Step::End { host, .. } | Step::Detach { host, .. } | Step::ReleaseAttach { host, .. } => {
            Some(host)
        }
        _ => None,
    }
}

fn reclaims_of(seen: &[(u64, Outcome)], of: Host) -> Vec<(u64, Reclaim)> {
    let mine = seen
        .iter()
        .filter(|(_, outcome)| host_of(&outcome.step) == Some(of));
    mine.filter_map(|(at, outcome)| Some((*at, outcome.reclaim?)))
        .collect()
}

fn kinds(reclaims: &[(u64, Reclaim)]) -> Vec<Reclaim> {
    reclaims.iter().map(|(_, reclaim)| *reclaim).collect()
}

fn detaches(cell: &Cell) -> Vec<InstanceId> {
    let events = cell.fixture.world.events();
    let calls = events.iter().filter_map(|event| match *event {
        Event::Detach(_, instance) => Some(instance),
        _ => None,
    });
    calls.collect()
}

fn run(cell: &mut Cell, ticks: usize, done: impl Fn(&Cell) -> bool) -> Vec<(u64, Outcome)> {
    let mut seen = Vec::new();
    for _ in 0..ticks {
        let at = cell.now_us;
        let (_, outcomes) = cell.tick();
        for number in 1..=cell.fixture.shards {
            assert!(cell.volume(number).live_hosts().count() <= MAX_ATTACHED);
        }
        seen.extend(outcomes.into_iter().map(|outcome| (at, outcome)));
        if done(cell) {
            return seen;
        }
    }
    panic!("no fixpoint within {ticks} ticks: {seen:?}");
}

fn settled_releases(seen: &[(u64, Outcome)]) -> bool {
    let moved = Verdict::Wait(Reason::Moved);
    let releases = seen
        .iter()
        .filter(|(_, o)| matches!(o.step, Step::ReleaseAttach { .. }));
    releases
        .clone()
        .all(|(_, outcome)| outcome.verdict != moved)
}

fn record_third(cell: &Cell) -> Host {
    record_entry(cell, host(5))
}

/// Records an attach entry of `third` on shard 1's volume through another reconciler; no attachment follows.
fn record_entry(cell: &Cell, third: Host) -> Host {
    let gate = StandbyGate::qualified();
    let mut recorder = Reconciler::new(reconciler_client(cell.store()));
    let peers: Vec<crate::failover::attachments::Peer> = (1..=cell.fixture.hosts)
        .map(|n| crate::failover::attachments::Peer {
            host: host(n),
            instance: instance(n),
        })
        .collect();
    let binding = RecordBinding {
        instance: instance(third.get()),
        unbound: &peers,
        listing: None,
    };
    let bounds = *cell.bounds.bounds();
    let era = crate::failover::records::ERA;
    recorder
        .record_standby(&gate, shard(1), volume(1), third, era, &bounds, &binding)
        .unwrap();
    third
}

fn attach_third(cell: &mut Cell) -> Host {
    let third = record_third(cell);
    cell.fixture.world.attach(volume(1), instance(5));
    cell.tick();
    third
}

fn clean(cell: &Cell) {
    assert!(cell.breaks.is_empty(), "{:?}", cell.breaks);
    let world = &cell.fixture.world;
    assert!(world.breaks.is_empty(), "{:?}", world.breaks);
}

#[test]
fn a_replaced_lost_standby_is_ended_dropped_detached_and_released_after_two_settled_listings() {
    let mut cell = Cell::new(6, 1);
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    let before = cell.snapshot();
    let lost = cell.shard(1).standby.unwrap();
    cell.lose(lost.get());
    let seen = run(&mut cell, 200, |cell| gone(cell, 1, lost));
    let reclaims = reclaims_of(&seen, lost);
    let expected = [Reclaim::Ended, Reclaim::DetachRequested, Reclaim::Gone];
    assert_eq!(kinds(&reclaims), expected);
    assert!(settled_releases(&seen), "{seen:?}");
    let successor = cell.shard(1).standby.unwrap();
    assert_ne!(successor, lost);
    let designated = (seen.iter()).find(|(_, outcome)| {
        matches!(outcome.step, Step::Designate { host, .. } if host == successor)
            && outcome.verdict == Verdict::Advance
    });
    assert!(designated.unwrap().0 < reclaims[0].0);
    let config = cell.bounds.config();
    let (settle, tick) = (config.detach_settle_us, config.tick_us);
    let (detached, released) = (reclaims[1].0, reclaims[2].0);
    assert_eq!(released - detached, tick + 2 * settle, "{reclaims:?}");
    assert_eq!(detaches(&cell), [instance(lost.get())]);
    assert!(
        !cell
            .listed(1)
            .contains(&instance(lost.get()).as_str().to_owned())
    );
    assert!(keeps_volume(&cell, &before));
    clean(&cell);
}

#[test]
fn a_lost_named_standby_is_replaced_at_the_pair_cap_floor_of_three() {
    let mut config = config_of(8);
    config.owner.registrant_max = 3;
    let mut cell = Cell::with(6, 1, true, config.validate().unwrap());
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    let lost = cell.shard(1).standby.unwrap();
    cell.lose(lost.get());
    let seen = run(&mut cell, 200, |cell| gone(cell, 1, lost));
    let successor = cell.shard(1).standby.unwrap();
    assert_ne!(successor, lost);
    assert!(cell.volume(1).enrolled(successor).is_some());
    assert!(cell.volume(1).pairs.len() <= 3);
    let expected = [Reclaim::Ended, Reclaim::DetachRequested, Reclaim::Gone];
    assert_eq!(kinds(&reclaims_of(&seen, lost)), expected);
    clean(&cell);
}

#[test]
fn a_detach_before_the_owners_pair_drop_fails_the_order_check() {
    let mut cell = Cell::new(6, 1);
    cell.drops = false;
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    let lost = cell.shard(1).standby.unwrap();
    cell.lose(lost.get());
    cell.run_until(100, |cell| cell.volume(1).ended(lost));
    for _ in 0..40 {
        let (survey, _) = cell.tick();
        let unwinding = |step: &Step| matches!(step, Step::Detach { host, .. } | Step::ReleaseAttach { host, .. } if *host == lost);
        let planned = survey.plan.steps.iter().any(unwinding);
        assert!(!planned, "{:?}", survey.plan.steps);
    }
    let held = cell.volume(1);
    let (seq, _) = held.latest(lost).unwrap();
    assert!(held.pinned(lost, seq).is_some());
    assert!(detaches(&cell).is_empty());
    clean(&cell);
    cell.fixture.world.detached(volume(1), instance(lost.get()));
    let breaks = cell.fixture.world.breaks.len();
    assert_eq!(breaks, 1, "a detach while the entry's pair is recorded");
    cell.fixture.world.breaks.clear();
    cell.drops = true;
    run(&mut cell, 120, |cell| gone(cell, 1, lost));
    clean(&cell);
}

#[test]
fn an_attach_that_never_enrolled_is_ended_detached_without_a_drop_and_released() {
    let mut config = config_of(8);
    config.attach_stuck_us = 120 * S;
    let mut cell = Cell::with(6, 1, true, config.validate().unwrap());
    cell.run_until(40, |cell| hosts_of(&cell.volume(1)).len() == 2);
    let stuck = hosts_of(&cell.volume(1))[1];
    cell.unenrolled.push(stuck.get());
    let seen = run(&mut cell, 200, |cell| gone(cell, 1, stuck));
    let reclaims = reclaims_of(&seen, stuck);
    let expected = [Reclaim::Ended, Reclaim::DetachRequested, Reclaim::Gone];
    assert_eq!(kinds(&reclaims), expected);
    assert!(reclaims[1].0 - reclaims[0].0 <= 2 * 10 * S, "{reclaims:?}");
    assert_eq!(detaches(&cell), [instance(stuck.get())]);
    let standby = cell.shard(1).standby;
    assert!(standby.is_some_and(|named| named != stuck), "{standby:?}");
    clean(&cell);
}

#[test]
fn a_failed_attach_that_lands_late_is_detached_again_and_released_after_clean_listings() {
    let mut config = config_of(8);
    config.attach_stuck_us = 120 * S;
    let mut cell = Cell::with(6, 1, true, config.validate().unwrap());
    cell.fixture
        .world
        .faults
        .attach
        .extend([AttachFault::Refuse; 4]);
    cell.run_until(40, |cell| hosts_of(&cell.volume(1)).len() == 2);
    let late = hosts_of(&cell.volume(1))[1];
    let mut seen = run(&mut cell, 200, |cell| cell.volume(1).ended(late));
    for _ in 0..35 {
        let at = cell.now_us;
        let (_, outcomes) = cell.tick();
        seen.extend(outcomes.into_iter().map(|outcome| (at, outcome)));
    }
    assert!(!gone(&cell, 1, late));
    cell.fixture.world.attach(volume(1), instance(late.get()));
    let landed = cell.now_us;
    seen.extend(run(&mut cell, 200, |cell| gone(cell, 1, late)));
    let reclaims = reclaims_of(&seen, late);
    let expected = [Reclaim::Ended, Reclaim::DetachRequested, Reclaim::Gone];
    assert_eq!(kinds(&reclaims), expected);
    let settle = cell.bounds.config().detach_settle_us;
    assert!(settled_releases(&seen), "{seen:?}");
    assert!(reclaims[1].0 >= landed);
    assert!(reclaims[2].0 - reclaims[1].0 >= 2 * settle, "{reclaims:?}");
    assert_eq!(detaches(&cell), [instance(late.get())]);
    clean(&cell);
}

/// DETACH-RELISTED: an instance that lists again after its entry reads `Gone` takes a detach under a `Relisted`
/// witness, at most once per `detach_settle_us`, and its record keeps the gone entry. The gone entry stands at
/// sequence 1 in one case and at sequence 2, after an earlier candidate's entry, in the other.
#[test]
fn an_instance_that_lists_again_after_gone_is_detached() {
    for rounds in [1, 2] {
        relisted_after_gone(rounds);
    }
}

fn relisted_after_gone(rounds: usize) {
    let mut config = config_of(8);
    config.attach_stuck_us = 120 * S;
    let mut cell = Cell::with(6, 1, true, config.validate().unwrap());
    cell.fixture
        .world
        .faults
        .attach
        .extend(vec![AttachFault::Refuse; 4 * rounds]);
    cell.run_until(80, |cell| hosts_of(&cell.volume(1)).len() > rounds);
    let late = hosts_of(&cell.volume(1))[rounds];
    run(&mut cell, 400, |cell| gone(cell, 1, late));
    let seq = cell.volume(1).latest(late).map(|(seq, _)| seq);
    assert_eq!(seq, Some(rounds as u32));
    let before = detaches(&cell).len();
    let record = cell.volume(1);
    cell.fixture
        .world
        .faults
        .detach
        .push_back(DetachFault::Lingers);
    cell.fixture.world.attach(volume(1), instance(late.get()));
    let landed = cell.now_us;
    let seen = run(&mut cell, 200, |cell| {
        !cell
            .listed(1)
            .contains(&instance(late.get()).as_str().to_owned())
    });
    let requested: Vec<u64> = reclaims_of(&seen, late)
        .into_iter()
        .filter(|(_, reclaim)| *reclaim == Reclaim::DetachRequested)
        .map(|(at, _)| at)
        .collect();
    assert_eq!(requested.len(), 2, "{seen:?}");
    assert!(requested[0] >= landed);
    let settle = cell.bounds.config().detach_settle_us;
    assert!(requested[1] - requested[0] >= settle, "{requested:?}");
    assert_eq!(detaches(&cell).len(), before + 2);
    assert_eq!(cell.volume(1).latest(late), record.latest(late));
    assert!(gone(&cell, 1, late));
    clean(&cell);
}

fn recording(of: Host) -> impl Fn(&Step) -> bool {
    move |step| matches!(*step, Step::RecordAttach { host, .. } if host == of)
}

/// The verdicts of `of`'s `RecordAttach` steps in `seen`, each with its tick's time.
fn records_of(seen: &[(u64, Outcome)], of: Host) -> Vec<(u64, Verdict)> {
    let recording = recording(of);
    let records = seen.iter().filter(|(_, outcome)| recording(&outcome.step));
    records
        .map(|(at, outcome)| (*at, outcome.verdict))
        .collect()
}

/// Leaves the shard's owner and `only` as the zone's active hosts.
fn drain_others(cell: &mut Cell, only: Host) {
    let owner = cell.shard(1).owner;
    for number in 1..=cell.fixture.hosts {
        if ![only, owner].contains(&host(number)) {
            cell.drain(host(number));
        }
    }
}

/// A cell whose first candidate's entry was ended as stuck and reads gone, with that host.
fn gone_candidate() -> (Cell, Host) {
    let mut config = config_of(8);
    config.attach_stuck_us = 120 * S;
    let mut cell = Cell::with(6, 1, true, config.validate().unwrap());
    let refused = vec![AttachFault::Refuse; 4];
    cell.fixture.world.faults.attach.extend(refused);
    cell.run_until(80, |cell| hosts_of(&cell.volume(1)).len() > 1);
    let late = hosts_of(&cell.volume(1))[1];
    run(&mut cell, 400, |cell| gone(cell, 1, late));
    (cell, late)
}

/// RECORD-SETTLED for the loop's own detach request, for each reply: a gone entry's instance lists again and is
/// detached, with an unknown reply in one case and a second request after a first that lingers in another. The
/// host's next attach entry is recorded at the first survey `tick_us + detach_settle_us` after the last detach
/// request and waits `Settling` before it. A survey one microsecond before that time waits also when its actuation
/// falls after it.
#[test]
fn a_host_detached_again_after_gone_records_no_new_attach_before_that_detach_settles() {
    let faults = [
        None,
        Some(DetachFault::Unknown { detached: true }),
        Some(DetachFault::Lingers),
    ];
    for (fault, exact) in faults.into_iter().zip([false, true, false]) {
        let (mut cell, late) = gone_candidate();
        let shown = instance(late.get()).as_str().to_owned();
        cell.fixture.world.faults.detach.extend(fault);
        cell.fixture.world.attach(volume(1), instance(late.get()));
        let seen = run(&mut cell, 200, |cell| !cell.listed(1).contains(&shown));
        let detached = reclaims_of(&seen, late).last().unwrap().0;
        let config = cell.bounds.config();
        let settled = detached + config.tick_us + config.detach_settle_us;
        drain_others(&mut cell, late);
        if let Some(standby) = cell.shard(1).standby {
            cell.lose(standby.get());
        }
        let waits = |verdict: &Verdict| *verdict == Verdict::Wait(Reason::Settling);
        if exact {
            let reserved = |cell: &Cell| cell.now_us >= settled - 20 * S;
            let seen = run(&mut cell, 400, reserved);
            assert!(records_of(&seen, late).iter().any(|(_, held)| waits(held)));
            cell.now_us = settled - 1;
            let survey = cell.survey();
            cell.now_us = settled;
            let early = outcome_of(&cell.actuate(&survey), recording(late));
            assert_eq!(early.verdict, Verdict::Wait(Reason::Settling), "{fault:?}");
            assert!(cell.volume(1).live(late).is_none());
        }
        let seen = run(&mut cell, 400, |cell| cell.volume(1).live(late).is_some());
        let records = records_of(&seen, late);
        let (recorded, last) = records.last().unwrap();
        assert_eq!((*recorded, *last), (settled, Verdict::Advance), "{fault:?}");
        let earlier = &records[..records.len() - 1];
        assert!(earlier.iter().all(|(_, held)| waits(held)), "{records:?}");
        assert_eq!(earlier.is_empty(), exact, "{fault:?} {records:?}");
        clean(&cell);
    }
}

/// RECORD-SETTLED counts from the first survey after the detach request: the caller's next survey comes three ticks
/// after the call that sent the detach of a gone entry's instance, and the host's next attach entry is recorded
/// `detach_settle_us` after that survey.
#[test]
fn a_new_attach_entry_settles_from_the_first_survey_after_the_detach() {
    let (mut cell, late) = gone_candidate();
    let shown = instance(late.get()).as_str().to_owned();
    cell.fixture.world.attach(volume(1), instance(late.get()));
    let seen = run(&mut cell, 200, |cell| !cell.listed(1).contains(&shown));
    let detached = reclaims_of(&seen, late).last().unwrap().0;
    let (tick_us, settle_us) = {
        let config = cell.bounds.config();
        (config.tick_us, config.detach_settle_us)
    };
    drain_others(&mut cell, late);
    let returned = detached + 3 * tick_us;
    cell.now_us = returned;
    let seen = run(&mut cell, 400, |cell| cell.volume(1).live(late).is_some());
    let records = records_of(&seen, late);
    let recorded = (returned + settle_us, Verdict::Advance);
    assert_eq!(*records.last().unwrap(), recorded, "{records:?}");
    clean(&cell);
}

/// RECORD-SETTLED at the attach step: the detached host's new entry is recorded by another reconciler while the
/// loop's detach of its instance is settling, as a record write that returned unknown and committed later would
/// leave it. The loop sends the entry's attach request no earlier than `detach_settle_us` after the detach's
/// return, and waits `Settling` before it.
#[test]
fn an_entry_recorded_while_its_instances_detach_settles_takes_no_attach_request_before_it() {
    let (mut cell, late) = gone_candidate();
    let shown = instance(late.get()).as_str().to_owned();
    cell.fixture.world.attach(volume(1), instance(late.get()));
    let seen = run(&mut cell, 200, |cell| !cell.listed(1).contains(&shown));
    let detached = reclaims_of(&seen, late).last().unwrap().0;
    let (tick_us, settle_us) = {
        let config = cell.bounds.config();
        (config.tick_us, config.detach_settle_us)
    };
    drain_others(&mut cell, late);
    let waits = |outcome: &Outcome| {
        recording(late)(&outcome.step) && outcome.verdict == Verdict::Wait(Reason::Settling)
    };
    let seen = cell.run_until(40, |cell| cell.zone.requests.is_empty());
    assert!(seen.iter().any(waits), "{seen:?}");
    record_entry(&cell, late);
    let calls = cell.attach_calls().len();
    let mut seen = Vec::new();
    let mut requested = None;
    for _ in 0..80 {
        let at = cell.now_us;
        let (_, outcomes) = cell.tick();
        seen.extend(outcomes);
        if cell.attach_calls().len() > calls {
            requested = Some(at);
            break;
        }
    }
    let settled = detached + tick_us + settle_us;
    assert_eq!(requested, Some(settled), "{seen:?}");
    let settling = seen.iter().any(|outcome| {
        matches!(outcome.step, Step::Attach { host, .. } if host == late)
            && outcome.verdict == Verdict::Wait(Reason::Settling)
    });
    assert!(settling, "{seen:?}");
}

/// RECORD-SETTLED across a restart, and its control: a loop that starts inside the settle time of an earlier run's
/// detach of a gone entry's instance records the host's next entry `tick_us + detach_settle_us` after its own first
/// survey, and a loop older than that span records the next entry of a host whose gone entry it never detached
/// again with no `Settling` wait.
#[test]
fn a_new_loop_records_a_gone_hosts_next_entry_a_settle_time_after_its_first_survey() {
    for relisted in [false, true] {
        let (mut cell, late) = gone_candidate();
        let mut started = None;
        if relisted {
            let shown = instance(late.get()).as_str().to_owned();
            cell.fixture.world.attach(volume(1), instance(late.get()));
            run(&mut cell, 200, |cell| !cell.listed(1).contains(&shown));
            cell.restart();
            started = Some(cell.now_us);
        }
        drain_others(&mut cell, late);
        let seen = run(&mut cell, 400, |cell| cell.volume(1).live(late).is_some());
        let records = records_of(&seen, late);
        let waited = records
            .iter()
            .any(|(_, held)| *held == Verdict::Wait(Reason::Settling));
        assert_eq!(waited, relisted, "{records:?}");
        if let Some(started) = started {
            let config = cell.bounds.config();
            let settled = started + config.tick_us + config.detach_settle_us;
            assert_eq!(records.last().unwrap().0, settled, "{records:?}");
        }
        clean(&cell);
    }
}

/// RECORD-SETTLED keeps the detach time by volume and instance: a full record sheds the detached host's gone entry
/// for another host's attach entry, written by a second reconciler inside the settle time, and the detached host's
/// next entry still waits `Settling` until `tick_us + detach_settle_us` after the detach request, in a loop older
/// than that span.
#[test]
fn a_detached_host_whose_gone_entry_a_full_record_shed_still_waits_for_the_detach_to_settle() {
    use crate::failover::records::{ERA, MAX_EVENTS};
    let mut cell = Cell::new(6, 1);
    let hold = |cell: &mut Cell, on: bool| {
        let mut held = cell.fixture.listing.clone().unwrap();
        held.version += 1;
        held.zone_hold = on;
        cell.fixture.listing = Some(held);
    };
    let any = |step: &Step| matches!(step, Step::RecordAttach { .. });
    let first = cell.planned(any);
    let detached = first.plan.steps.iter().find_map(|step| match *step {
        Step::RecordAttach { host, .. } => Some(host),
        _ => None,
    });
    let detached = detached.unwrap();
    hold(&mut cell, true);
    let span = {
        let config = cell.bounds.config();
        config.tick_us + config.detach_settle_us
    };
    while cell.now_us <= first.status.started_us + span {
        cell.tick();
    }
    let fillers = 40..40 + MAX_EVENTS as u64 - 2;
    plant_volume(&cell, 1, |held| {
        for n in std::iter::once(detached.get()).chain(fillers.clone()) {
            let seq = held.push(EventKind::Attach, host(n), ERA).unwrap();
            let event = held.events.iter_mut().find(|event| event.seq == seq);
            let event = event.unwrap();
            (event.kind, event.instance) = (EventKind::Gone, Some(instance(n)));
        }
    });
    assert_eq!(cell.volume(1).events.len(), MAX_EVENTS);
    let shown = instance(detached.get()).as_str().to_owned();
    cell.fixture
        .world
        .attach(volume(1), instance(detached.get()));
    let seen = run(&mut cell, 20, |cell| !cell.listed(1).contains(&shown));
    let requested = *reclaims_of(&seen, detached).last().unwrap();
    assert_eq!(requested.1, Reclaim::DetachRequested);
    let settled = requested.0 + span;
    let gate = StandbyGate::qualified();
    let mut peer = Reconciler::new(reconciler_client(cell.store()));
    let peers: Vec<crate::failover::attachments::Peer> = (1..=cell.fixture.hosts)
        .map(|n| crate::failover::attachments::Peer {
            host: host(n),
            instance: instance(n),
        })
        .collect();
    let owner = cell.shard(1).owner;
    let other = (1..=6)
        .map(host)
        .find(|&other| ![owner, detached].contains(&other));
    let other = other.unwrap();
    let listed = cell.listed(1);
    let binding = RecordBinding {
        instance: instance(other.get()),
        unbound: &peers,
        listing: Some(&listed),
    };
    let bounds = *cell.bounds.bounds();
    peer.record_standby(&gate, shard(1), volume(1), other, ERA, &bounds, &binding)
        .unwrap();
    assert!(cell.volume(1).latest(detached).is_none());
    assert_eq!(cell.volume(1).events.len(), MAX_EVENTS);
    hold(&mut cell, false);
    let seen = run(&mut cell, 400, |cell| {
        cell.volume(1).live(detached).is_some()
    });
    let records = records_of(&seen, detached);
    let waits = |(_, held): &(u64, Verdict)| *held == Verdict::Wait(Reason::Settling);
    assert!(records.iter().any(waits), "{records:?}");
    assert_eq!(*records.last().unwrap(), (settled, Verdict::Advance));
    clean(&cell);
}

/// RECORD-SETTLED's first-survey reading: a new loop records no attach entry before `tick_us + detach_settle_us`
/// after its first survey on a compacted volume record, or for an instance that a retained gone entry of any host
/// binds, and records at once on an uncompacted record whose gone entries bind other instances.
#[test]
fn a_new_loop_waits_a_settle_time_where_the_record_cannot_exclude_an_earlier_detach() {
    use crate::failover::records::ERA;
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum History {
        Compacted,
        BindsCandidate,
        BindsOther,
    }
    for history in [
        History::Compacted,
        History::BindsCandidate,
        History::BindsOther,
    ] {
        let mut cell = Cell::new(6, 1);
        let any = |step: &Step| matches!(step, Step::RecordAttach { .. });
        let first = cell.planned(any);
        let candidate = first
            .plan
            .steps
            .iter()
            .find_map(|step| match *step {
                Step::RecordAttach { host, .. } => Some(host),
                _ => None,
            })
            .unwrap();
        let started = first.status.started_us;
        plant_volume(&cell, 1, |held| {
            for n in [40, 41] {
                let seq = held.push(EventKind::Attach, host(n), ERA).unwrap();
                let event = held.events.iter_mut().find(|event| event.seq == seq);
                let bound = match (history, n) {
                    (History::BindsCandidate, 40) => instance(candidate.get()),
                    _ => instance(n),
                };
                let event = event.unwrap();
                (event.kind, event.instance) = (EventKind::Gone, Some(bound));
            }
            if history == History::Compacted {
                held.events.remove(1);
            }
        });
        assert_eq!(cell.volume(1).uncompacted(), history != History::Compacted);
        let seen = run(&mut cell, 400, |cell| {
            cell.volume(1).live(candidate).is_some()
        });
        let records = records_of(&seen, candidate);
        let waited = records
            .iter()
            .any(|(_, held)| *held == Verdict::Wait(Reason::Settling));
        assert_eq!(waited, history != History::BindsOther, "{history:?}");
        let config = cell.bounds.config();
        let settled = started + config.tick_us + config.detach_settle_us;
        let recorded = records.last().unwrap().0;
        match history {
            History::BindsOther => assert!(recorded < settled, "{records:?}"),
            _ => assert_eq!(recorded, settled, "{history:?} {records:?}"),
        }
        clean(&cell);
    }
}

#[test]
fn a_release_needs_two_settled_clean_listings_and_a_new_loop_starts_the_clock_again() {
    let mut cell = Cell::new(6, 1);
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    let lost = cell.shard(1).standby.unwrap();
    cell.lose(lost.get());
    let seen = run(&mut cell, 200, |cell| !detaches(cell).is_empty());
    let settle = cell.bounds.config().detach_settle_us;
    let detached = reclaims_of(&seen, lost).last().unwrap().0;
    let mut seen = Vec::new();
    for _ in 0..15 {
        let at = cell.now_us;
        let (_, outcomes) = cell.tick();
        seen.extend(outcomes.into_iter().map(|outcome| (at, outcome)));
    }
    assert!(kinds(&reclaims_of(&seen, lost)).is_empty());
    let restarted = cell.now_us;
    assert!(restarted - detached < 2 * settle);
    cell.restart();
    let seen = run(&mut cell, 200, |cell| gone(cell, 1, lost));
    let released = reclaims_of(&seen, lost).last().unwrap().0;
    assert!(released - restarted >= 2 * settle, "{released} {restarted}");

    let gate = StandbyGate::qualified();
    let mut cell = Cell::new(6, 1);
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    let lost = cell.shard(1).standby.unwrap();
    cell.lose(lost.get());
    run(&mut cell, 200, |cell| !detaches(cell).is_empty());
    cell.run_until(10, |_| true);
    let before = cell.volume(1);
    let listed = cell.listed(1);
    let one = [Listing {
        at: cell.now_us,
        instances: &listed,
    }];
    let mut planted = Reconciler::new(reconciler_client(cell.store()));
    let witness = planted.detachable(volume(1), lost).unwrap();
    let timing = crate::failover::reconcile::Settle {
        requested: 0,
        settle,
    };
    let early = planted.release_attach(&gate, &witness, &one, timing);
    assert_eq!(
        early,
        Err(crate::failover::reconcile::ReconcileError::Conflict)
    );
    assert_eq!(cell.volume(1), before);
    let two = [
        one[0],
        Listing {
            at: cell.now_us + settle,
            instances: &listed,
        },
    ];
    planted
        .release_attach(&gate, &witness, &two, timing)
        .unwrap();
    assert!(gone(&cell, 1, lost));
}

#[test]
fn a_full_volume_ends_the_third_hosts_attach_before_it_records_the_candidate() {
    let mut cell = Cell::new(6, 1);
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    let (first, standby) = (cell.shard(1).owner, cell.shard(1).standby.unwrap());
    let third = attach_third(&mut cell);
    assert_eq!(first, host(2));
    assert!(cell.volume(1).enrolled(third).is_some());
    cell.lose(standby.get());
    let seen = run(&mut cell, 100, |cell| {
        cell.shard(1).standby.is_some_and(|named| named != standby)
    });
    let candidate = cell.shard(1).standby.unwrap();
    assert_ne!(candidate, third);
    let ended = reclaims_of(&seen, third);
    assert_eq!(kinds(&ended)[0], Reclaim::Ended);
    let recorded = (seen.iter()).find(|(_, outcome)| {
        matches!(outcome.step, Step::RecordAttach { host, .. } if host == candidate)
            && outcome.verdict == Verdict::Advance
    });
    assert!(ended[0].0 < recorded.unwrap().0);
    assert_eq!(
        hosts_of(&cell.volume(1)),
        [first, standby, third, candidate]
    );
    clean(&cell);
}

#[test]
fn the_owner_and_the_named_standby_keep_their_attaches_and_a_deposed_owner_ranks_first() {
    let mut cell = Cell::new(6, 1);
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    let (held, standby) = (cell.shard(1).owner, cell.shard(1).standby.unwrap());
    cell.lose(held.get());
    cell.lose(standby.get());
    for _ in 0..60 {
        let (_, outcomes) = cell.tick();
        let record = cell.shard(1);
        for outcome in &outcomes {
            if let Step::End { host, .. } = outcome.step {
                assert_ne!(host, record.owner);
            }
        }
    }
    clean(&cell);

    let mut cell = Cell::new(6, 1);
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    let (deposed, successor) = (cell.shard(1).owner, cell.shard(1).standby.unwrap());
    let mut client = owner(cell.store());
    let read = client.read::<ShardRecord>(Key::Shard(shard(1))).unwrap();
    client
        .take_over(&read, Target::of(read.value()), successor)
        .unwrap();
    let entries = hosts_of(&cell.volume(1));
    let calls = cell.fixture.world.events().len();
    let seen = run(&mut cell, 40, |cell| cell.shard(1).standby.is_some());
    assert_eq!(cell.shard(1).standby, Some(deposed));
    assert_eq!(hosts_of(&cell.volume(1)), entries);
    assert!(reclaims_of(&seen, deposed).is_empty());
    let attached = cell.fixture.world.events()[calls..]
        .iter()
        .any(|event| matches!(event, Event::Attach(..) | Event::Detach(..)));
    assert!(!attached);
    clean(&cell);
}

#[test]
fn a_designation_that_races_the_end_write_replans_and_enrolls_another_host() {
    let mut cell = Cell::new(6, 1);
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    let standby = cell.shard(1).standby.unwrap();
    let before = cell.snapshot();
    let third = attach_third(&mut cell);
    let mut draining = cell.fixture.listing.clone().unwrap();
    draining.version += 1;
    let at = draining.hosts.iter().position(|entry| entry.host == third);
    draining.hosts[at.unwrap()].state =
        crate::failover::zone_loop::directory::DirectoryState::Draining;
    cell.fixture.listing = Some(draining);
    let store = cell.store().clone();
    *cell.after.borrow_mut() = Some((
        Key::Volume(volume(1)),
        Box::new(move || {
            let mut client = owner(&store);
            let read = client.read::<ShardRecord>(Key::Shard(shard(1))).unwrap();
            client
                .designate(&read, Target::of(read.value()), third)
                .unwrap();
        }),
    ));
    let seen = run(&mut cell, 60, |cell| {
        cell.shard(1).standby.is_some_and(|named| named != third)
    });
    assert_eq!(cell.shard(1).standby, Some(standby));
    let named = (seen.iter()).find(|(_, outcome)| outcome.reclaim == Some(Reclaim::EndedNamed));
    assert_eq!(named.unwrap().1.verdict, Verdict::Wait(Reason::Moved));
    assert!(cell.volume(1).ended(third));
    assert!(keeps_volume(&cell, &before));
    clean(&cell);
}

fn replace(cell: &mut Cell) {
    let lost = cell.shard(1).standby.unwrap();
    cell.lose(lost.get());
    let replaced = |cell: &Cell| {
        cell.shard(1).standby.is_some_and(|named| named != lost) && cell.volume(1).ended(lost)
    };
    cell.run_until(200, replaced);
}

#[test]
fn a_volume_outlives_four_standby_replacements_and_a_takeover_at_its_generation() {
    let mut cell = Cell::new(16, 1);
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    let before = cell.snapshot();
    for _ in 0..4 {
        replace(&mut cell);
    }
    let live = cell.shard(1).standby.unwrap();
    let attaches = hosts_of(&cell.volume(1)).len();
    assert!(
        attaches >= 6,
        "{attaches} attach entries in the volume's life"
    );
    let deposed = cell.shard(1).owner;
    cell.lose(deposed.get());
    let mut client = owner(cell.store());
    let read = client.read::<ShardRecord>(Key::Shard(shard(1))).unwrap();
    client
        .take_over(&read, Target::of(read.value()), live)
        .unwrap();
    let entries = hosts_of(&cell.volume(1)).len();
    cell.run_until(100, |cell| {
        cell.shard(1).standby.is_some() && cell.volume(1).ended(deposed)
    });
    let after = cell.shard(1);
    assert_eq!(after.owner, live);
    let successor = after.standby.unwrap();
    assert_ne!(successor, deposed);
    let held = cell.volume(1);
    let (seq, _) = held.latest(successor).unwrap();
    let at = held.events.iter().position(|event| event.seq == seq);
    assert!(at.unwrap() >= entries, "{:?}", held.events);
    let was = before.shards[0].0;
    assert_eq!(
        (after.generation, after.active),
        (was.generation, was.active)
    );
    assert_eq!(
        cell.volume(1).state,
        crate::failover::records::VolumeState::Fresh
    );
    assert!(keeps_volume(&cell, &before));
    clean(&cell);

    let mut cell = Cell::new(16, 1);
    cell.ends = false;
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    let first = cell.shard(1).standby.unwrap();
    cell.lose(first.get());
    cell.run_until(60, |cell| {
        cell.shard(1).standby.is_some_and(|named| named != first)
    });
    let second = cell.shard(1).standby.unwrap();
    cell.lose(second.get());
    let mut closed = false;
    for _ in 0..60 {
        let (survey, _) = cell.tick();
        closed |= survey.plan.shards.iter().any(|plan| {
            (plan.state, plan.blocker) == (ShardState::Closed, Some(Blocker::AttachClosed))
        });
    }
    assert!(closed);
    assert_eq!(hosts_of(&cell.volume(1)).len(), 3);
}

fn settled(cell: &Cell, lost: Host) -> bool {
    gone(cell, 1, lost) && cell.shard(1).standby.is_some_and(|named| named != lost)
}

fn reclaim_converged(cell: &Cell, lost: Host, commits: usize) -> Result<(), String> {
    let held = cell.volume(1);
    let entries = held
        .events
        .iter()
        .filter(|event| event.host == lost)
        .count();
    if entries != 1 || !gone(cell, 1, lost) {
        return Err(format!("entries of {lost:?}: {:?}", held.events));
    }
    let named = cell.shard(1).standby.ok_or("no standby")?;
    let attached = cell.listed(1);
    let ours = attached
        .iter()
        .filter(|id| *id == instance(named.get()).as_str())
        .count();
    if ours != 1
        || attached
            .iter()
            .any(|id| id == instance(lost.get()).as_str())
    {
        return Err(format!("listing {attached:?}"));
    }
    let key = Key::Shard(shard(1));
    let shard_commits = cell.store().0.borrow().commit_count(&key);
    if shard_commits != commits + 1 {
        return Err(format!("{shard_commits} shard record commits"));
    }
    if !cell.breaks.is_empty() || !cell.fixture.world.breaks.is_empty() {
        return Err(format!("{:?} {:?}", cell.breaks, cell.fixture.world.breaks));
    }
    Ok(())
}

#[test]
fn a_crash_at_every_reclaim_effect_with_a_second_loop_releases_the_entry_once() {
    let mut config = config_of(8);
    config.detach_settle_us = 130 * S;
    let bounds = config.validate().unwrap();
    let prepared = |bounds: &crate::failover::zone_loop::config::ZoneBounds| {
        let mut cell = Cell::with(4, 1, true, bounds.clone());
        cell.run_until(40, |cell| cell.shard(1).standby.is_some());
        let lost = cell.shard(1).standby.unwrap();
        let commits = cell.store().0.borrow().commit_count(&Key::Shard(shard(1)));
        cell.lose(lost.get());
        cell.faults.borrow_mut().effects = 0;
        (cell, lost, commits)
    };
    let (mut baseline, lost, commits) = prepared(&bounds);
    baseline.run_until(200, |cell| settled(cell, lost));
    reclaim_converged(&baseline, lost, commits).unwrap();
    let effects = baseline.faults.borrow().effects;
    assert!(effects >= 6, "{effects} effects");
    let arms = [
        crate::storage::store::sim::Arm::Pass,
        crate::storage::store::sim::Arm::Timeout { commit: true },
        crate::storage::store::sim::Arm::Timeout { commit: false },
    ];
    let mut failures = Vec::new();
    for at in 0..effects {
        for arm in arms {
            let (mut cell, lost, commits) = prepared(&bounds);
            cell.faults.borrow_mut().at = Some((at, arm));
            let quiet = Faults::default();
            let (hook, after) = (Hook::default(), After::default());
            let mut second = Cell::open(&cell.fixture, &quiet, &hook, &after, &cell.bounds);
            let gate = StandbyGate::qualified();
            let mut ticks = 0;
            while ticks < 300 && !(cell.restarts > 0 && settled(&cell, lost)) {
                cell.tick();
                if cell.restarts == 0 {
                    ticks += 1;
                    continue;
                }
                let directory = Ok(cell.fixture.directory());
                let now_us = cell.now_us - 5 * S;
                let theirs = second.survey(directory, &mut cell.fixture.world, now_us);
                let world = &mut cell.fixture.world;
                second.actuate(&gate, &theirs, now_us, world).unwrap();
                ticks += 1;
            }
            for _ in 0..4 {
                cell.tick();
            }
            let mut result = reclaim_converged(&cell, lost, commits);
            if result.is_ok() && cell.restarts != 1 {
                result = Err(format!("{} restarts", cell.restarts));
            }
            if let Err(why) = result {
                failures.push(format!("effect {at} under {arm:?}: {why}"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_detach_that_lists_late_is_requested_again_after_the_settle_time_and_released_after_it() {
    let mut cell = Cell::new(6, 1);
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    let lost = cell.shard(1).standby.unwrap();
    cell.fixture.world.faults.detach.extend([
        DetachFault::Lingers,
        DetachFault::Unknown { detached: false },
        DetachFault::Unknown { detached: true },
    ]);
    cell.lose(lost.get());
    let seen = run(&mut cell, 300, |cell| gone(cell, 1, lost));
    let reclaims = reclaims_of(&seen, lost);
    let expected = [
        Reclaim::Ended,
        Reclaim::DetachRequested,
        Reclaim::DetachUnknown,
        Reclaim::DetachUnknown,
        Reclaim::Gone,
    ];
    assert_eq!(kinds(&reclaims), expected);
    let settle = cell.bounds.config().detach_settle_us;
    assert!(reclaims[2].0 - reclaims[1].0 >= settle, "{reclaims:?}");
    assert!(reclaims[3].0 - reclaims[2].0 >= settle, "{reclaims:?}");
    assert!(reclaims[4].0 - reclaims[3].0 >= 2 * settle, "{reclaims:?}");
    assert_eq!(detaches(&cell).len(), 3);
    clean(&cell);
}

#[test]
fn a_detach_planned_from_a_listing_that_cleared_before_the_step_makes_no_request() {
    let mut cell = Cell::new(6, 1);
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    let lost = cell.shard(1).standby.unwrap();
    cell.lose(lost.get());
    let mut planned = None;
    for _ in 0..200 {
        let survey = cell.survey();
        let detaching = (survey.plan.steps.iter())
            .any(|step| matches!(step, Step::Detach { host, .. } if *host == lost));
        if detaching {
            cell.fixture.world.detach(volume(1), instance(lost.get()));
            planned = Some(cell.actuate(&survey));
            break;
        }
        cell.actuate(&survey);
        cell.enroll_listed();
        cell.drop_ended_pairs();
        cell.now_us += 10 * S;
    }
    let outcomes = planned.unwrap();
    let detach = outcomes
        .iter()
        .find(|o| matches!(o.step, Step::Detach { .. }));
    assert_eq!(
        detach.map(|o| (o.verdict, o.reclaim)),
        Some((Verdict::Advance, None))
    );
    assert!(detaches(&cell).is_empty());
}

#[test]
fn an_attach_whose_requests_never_land_is_ended_after_the_stuck_bound_and_its_slot_moves() {
    for fault in [
        AttachFault::Unknown { attached: false },
        AttachFault::Unlanded,
    ] {
        let mut config = config_of(8);
        config.attach_stuck_us = 120 * S;
        let stuck_us = config.attach_stuck_us;
        let mut cell = Cell::with(6, 1, true, config.validate().unwrap());
        cell.fixture.world.faults.attach.extend([fault; 64]);
        let mut requests = Vec::new();
        let mut ended = None;
        for _ in 0..200 {
            let at = cell.now_us;
            let (_, outcomes) = cell.tick();
            for outcome in &outcomes {
                if outcome.reply.is_some() && ended.is_none() {
                    requests.push(at);
                }
                if outcome.reclaim == Some(Reclaim::Ended) {
                    ended.get_or_insert(at);
                }
            }
            if ended.is_some() {
                cell.fixture.world.faults.attach.clear();
                if cell.shard(1).standby.is_some() {
                    break;
                }
            }
        }
        let ended = ended.unwrap_or_else(|| panic!("{fault:?}: no end"));
        let (first, last) = (requests[0], *requests.last().unwrap());
        assert!(last - first < stuck_us, "{fault:?}: {requests:?}");
        assert_eq!(ended - last, stuck_us, "{fault:?}: {ended} {requests:?}");
        let candidate = hosts_of(&cell.volume(1))[1];
        assert!(cell.volume(1).ended(candidate));
        let standby = cell.shard(1).standby.unwrap();
        assert_ne!(standby, candidate);
        clean(&cell);
    }
}

#[test]
fn a_listed_unenrolled_attach_is_ended_after_the_stuck_bound_from_a_new_loops_first_survey() {
    let mut config = config_of(8);
    config.attach_stuck_us = 120 * S;
    let stuck_us = config.attach_stuck_us;
    let mut cell = Cell::with(6, 1, true, config.validate().unwrap());
    cell.run_until(40, |cell| hosts_of(&cell.volume(1)).len() == 2);
    let stuck = hosts_of(&cell.volume(1))[1];
    cell.unenrolled.push(stuck.get());
    let listed = instance(stuck.get()).as_str().to_owned();
    cell.run_until(10, |cell| cell.listed(1).contains(&listed));
    cell.restart();
    let (restarted, calls) = (cell.now_us, cell.attach_calls().len());
    let seen = run(&mut cell, 100, |cell| cell.volume(1).ended(stuck));
    let ended = reclaims_of(&seen, stuck);
    assert_eq!(kinds(&ended)[0], Reclaim::Ended);
    assert_eq!(ended[0].0 - restarted, stuck_us, "{ended:?}");
    let again = cell.attach_calls()[calls..].to_vec();
    assert!(!again.iter().any(|(_, id)| *id == instance(stuck.get())));
    cell.run_until(60, |cell| cell.shard(1).standby.is_some());
    assert_ne!(cell.shard(1).standby, Some(stuck));
    clean(&cell);
}

#[test]
fn an_attached_host_that_never_enrolls_is_ended_enroll_stuck_us_after_its_first_listing_and_its_slot_moves()
 {
    for blink in [false, true] {
        let mut config = config_of(8);
        config.attach_stuck_us = 3_600 * S;
        config.enroll_stuck_us = 120 * S;
        let enroll_us = config.enroll_stuck_us;
        let mut cell = Cell::with(6, 1, true, config.validate().unwrap());
        cell.run_until(40, |cell| hosts_of(&cell.volume(1)).len() == 2);
        let stuck = hosts_of(&cell.volume(1))[1];
        cell.unenrolled.push(stuck.get());
        let listed = instance(stuck.get()).as_str().to_owned();
        let active = cell.shard(1).active;
        let (mut first, mut shown, mut ended) = (None, None, None);
        for _ in 0..100 {
            let at = cell.now_us;
            if blink && first.is_some_and(|first| at == first + 60 * S) {
                cell.fixture.world.detach(active, instance(stuck.get()));
            }
            let (survey, outcomes) = cell.tick();
            let view = survey.observation.zone.as_ref().unwrap();
            let lists = view
                .listing(active)
                .is_some_and(|ids| ids.contains(&listed));
            match (lists, shown) {
                (true, None) => shown = Some(at),
                (false, _) => shown = None,
                (true, Some(_)) => {}
            }
            first = first.or(shown);
            let ends = outcomes.iter().any(|outcome| {
                matches!(outcome.step, Step::End { host, .. } if host == stuck)
                    && outcome.reclaim == Some(Reclaim::Ended)
            });
            if ends {
                ended = Some(at);
                break;
            }
            assert_eq!(cell.volume(1).enrolled(stuck), None);
            let slot = census_of(cell.store()).and_then(|census| census.slot(shard(1)));
            let held = slot.map(|slot| slot.host);
            assert_eq!(held, Some(stuck), "the slot stays before the bound");
        }
        let (first, shown, ended) = (first.unwrap(), shown.unwrap(), ended.unwrap());
        assert_eq!(ended - shown, enroll_us, "blink {blink}");
        assert_eq!(ended - first > enroll_us, blink, "blink {blink}");
        cell.run_until(60, |cell| cell.shard(1).standby.is_some());
        assert_ne!(cell.shard(1).standby, Some(stuck));
        clean(&cell);
    }
}

/// A slot host whose live, unenrolled entry has a key that a recorded pair holds takes no attach request: the plan
/// reads the shard closed, the survey starts the entry's stuck clock at its first sighting, and `attach_stuck_us`
/// later the plan ends the entry and the slot moves to another host.
#[test]
fn a_slot_host_whose_entry_key_a_recorded_pair_holds_takes_no_attach_and_is_ended_attach_stuck_us_after_its_first_sighting()
 {
    let mut config = config_of(8);
    config.attach_stuck_us = 120 * S;
    config.enroll_stuck_us = 3_600 * S;
    let stuck_us = config.attach_stuck_us;
    let mut cell = Cell::with(6, 1, true, config.validate().unwrap());
    cell.drops = false;
    cell.run_until(40, |cell| hosts_of(&cell.volume(1)).len() == 2);
    let stuck = hosts_of(&cell.volume(1))[1];
    assert_eq!(cell.volume(1).enrolled(stuck), None);
    assert!(
        !cell
            .listed(1)
            .contains(&instance(stuck.get()).as_str().to_owned())
    );
    plant_volume(&cell, 1, |held| {
        let taken = attachment_key(held.live(stuck).unwrap()).unwrap();
        let other = held.push(EventKind::Attach, host(9), ERA).unwrap();
        let entry = held.events.iter_mut().find(|event| event.seq == other);
        let entry = entry.unwrap();
        entry.kind = EventKind::Ended;
        entry.instance = Some(instance(9));
        let pair = Pair {
            key: taken,
            ..crate::failover::evidence_tests::pair(9, 1, 1)
        };
        held.pairs.push(RecordedPair {
            host: host(9),
            attach: other,
            pair,
        });
    });
    let calls = cell.attach_calls().len();
    let first = cell.now_us;
    let mut ended = None;
    for _ in 0..100 {
        let at = cell.now_us;
        let (survey, outcomes) = cell.tick();
        let ends = outcomes.iter().any(|outcome| {
            matches!(outcome.step, Step::End { host, .. } if host == stuck)
                && outcome.reclaim == Some(Reclaim::Ended)
        });
        if ends {
            ended = Some(at);
            break;
        }
        let plan = survey
            .plan
            .shards
            .iter()
            .find(|plan| plan.shard == shard(1));
        let plan = plan.map(|plan| (plan.state, plan.blocker));
        assert_eq!(
            plan,
            Some((ShardState::Closed, Some(Blocker::AttachClosed)))
        );
        let attaching = |step: &Step| matches!(step, Step::Attach { host, .. } if *host == stuck);
        assert!(
            !survey.plan.steps.iter().any(attaching),
            "{:?}",
            survey.plan.steps
        );
        let slot = census_of(cell.store()).and_then(|census| census.slot(shard(1)));
        assert_eq!(
            slot.map(|slot| slot.host),
            Some(stuck),
            "the slot stays before the bound"
        );
    }
    assert_eq!(ended.map(|ended| ended - first), Some(stuck_us));
    let requested = cell.attach_calls()[calls..].to_vec();
    assert!(
        !requested.iter().any(|(_, id)| *id == instance(stuck.get())),
        "{requested:?}"
    );
    cell.run_until(60, |cell| cell.shard(1).standby.is_some());
    assert_ne!(cell.shard(1).standby, Some(stuck));
    clean(&cell);
}

#[test]
fn a_settling_release_leaves_the_write_budget_to_another_shards_end() {
    let mut config = config_of(8);
    config.writes_per_tick = 1;
    let mut cell = Cell::with(8, 2, true, config.validate().unwrap());
    let mut placed = cell.fixture.listing.clone().unwrap();
    for entry in &mut placed.hosts {
        let owner = matches!(entry.host.get(), 2 | 3);
        entry.placement.partition = Partition(if owner { 7 } else { entry.host.get() as u32 });
    }
    cell.fixture.listing = Some(placed);
    cell.run_until(120, |cell| cell.designated());
    let (first, second) = (
        cell.shard(1).standby.unwrap(),
        cell.shard(2).standby.unwrap(),
    );
    assert_ne!(first, second);
    assert!(first != cell.shard(2).owner && second != cell.shard(1).owner);
    cell.lose(first.get());
    let settling = |seen: &[Outcome]| {
        seen.iter().any(|outcome| {
            matches!(outcome.step, Step::ReleaseAttach { host, .. } if host == first)
                && outcome.verdict == Verdict::Wait(Reason::Settling)
        })
    };
    let mut waited = false;
    for _ in 0..100 {
        let (_, outcomes) = cell.tick();
        if settling(&outcomes) {
            waited = true;
            break;
        }
    }
    assert!(waited);
    cell.lose(second.get());
    let seen = run(&mut cell, 200, |cell| cell.volume(2).ended(second));
    assert!(!gone(&cell, 1, first), "{seen:?}");
}

#[test]
fn a_sighting_in_a_survey_with_no_actuation_restarts_the_release_pair() {
    let mut cell = Cell::new(6, 1);
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    let lost = cell.shard(1).standby.unwrap();
    cell.lose(lost.get());
    cell.run_until(300, |cell| !cell.zone.clean.is_empty());
    let settle = cell.bounds.config().detach_settle_us;
    cell.fixture.world.attach(volume(1), instance(lost.get()));
    drop(cell.survey());
    assert!(cell.zone.clean.is_empty());
    cell.now_us += 10 * S;
    cell.fixture.world.detach(volume(1), instance(lost.get()));
    let cleared = cell.now_us;
    let seen = run(&mut cell, 200, |cell| gone(cell, 1, lost));
    let released = reclaims_of(&seen, lost).last().unwrap().0;
    assert!(released - cleared >= settle, "{released} {cleared}");
    clean(&cell);
}

/// A survey listing that omits the ended instance and holds an identifier that is no instance ID is kept for no
/// release: the plan holds no release step and the loop keeps no listing while the identifier is listed, and the
/// entry is released two settled listings after the identifier leaves.
#[test]
fn a_listing_with_an_unreadable_identifier_is_kept_for_no_release() {
    let mut cell = Cell::new(6, 1);
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    let lost = cell.shard(1).standby.unwrap();
    cell.lose(lost.get());
    run(&mut cell, 200, |cell| !detaches(cell).is_empty());
    let unreadable = |cell: &mut Cell, listed: bool| {
        let mut rows = cell.fixture.world.volumes.iter_mut();
        let row = rows.find(|row| row.volume == volume(1)).unwrap();
        row.attachments.retain(|id| id != "i-unreadable");
        if listed {
            row.attachments.push("i-unreadable".to_owned());
        }
    };
    unreadable(&mut cell, true);
    let (tick_us, settle_us) = {
        let config = cell.bounds.config();
        (config.tick_us, config.detach_settle_us)
    };
    let from = cell.now_us;
    while cell.now_us - from < 2 * (tick_us + 2 * settle_us) {
        let at = cell.now_us;
        let (survey, _) = cell.tick();
        assert!(!survey.plan.steps.iter().any(releasing), "{at}");
        assert!(cell.zone.clean.is_empty(), "{at}");
    }
    assert!(!gone(&cell, 1, lost));
    unreadable(&mut cell, false);
    let cleared = cell.now_us;
    let seen = run(&mut cell, 200, |cell| gone(cell, 1, lost));
    let released = reclaims_of(&seen, lost).last().unwrap().0;
    assert_eq!(released - cleared, settle_us);
    clean(&cell);
}

#[test]
fn a_fresh_listing_with_an_unreadable_identifier_and_no_instance_makes_no_detach() {
    let mut cell = Cell::new(6, 1);
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    let lost = cell.shard(1).standby.unwrap();
    cell.lose(lost.get());
    let mut planned = None;
    for _ in 0..200 {
        let survey = cell.survey();
        let detaching = (survey.plan.steps.iter())
            .any(|step| matches!(step, Step::Detach { host, .. } if *host == lost));
        if detaching {
            cell.fixture.world.detach(volume(1), instance(lost.get()));
            let mut rows = cell.fixture.world.volumes.iter_mut();
            let row = rows.find(|row| row.volume == volume(1)).unwrap();
            row.attachments.push(String::new());
            planned = Some(cell.actuate(&survey));
            break;
        }
        cell.actuate(&survey);
        cell.enroll_listed();
        cell.drop_ended_pairs();
        cell.now_us += 10 * S;
    }
    let outcomes = planned.unwrap();
    let detach = outcomes
        .iter()
        .find(|o| matches!(o.step, Step::Detach { .. }));
    let unlisted = (Verdict::Wait(Reason::Unlisted), None);
    assert_eq!(detach.map(|o| (o.verdict, o.reclaim)), Some(unlisted));
    assert!(detaches(&cell).is_empty());
}

#[test]
fn one_call_per_tick_spaces_two_shards_detaches_and_each_waits_for_the_budget() {
    let config = config_of(8);
    let mut cell = Cell::with(8, 2, true, config.validate().unwrap().with_calls(1));
    let mut placed = cell.fixture.listing.clone().unwrap();
    for entry in &mut placed.hosts {
        let owner = matches!(entry.host.get(), 2 | 3);
        entry.placement.partition = Partition(if owner { 7 } else { entry.host.get() as u32 });
    }
    cell.fixture.listing = Some(placed);
    cell.run_until(120, |cell| cell.designated());
    let (first, second) = (
        cell.shard(1).standby.unwrap(),
        cell.shard(2).standby.unwrap(),
    );
    assert_ne!(first, second);
    cell.drops = false;
    cell.lose(first.get());
    cell.lose(second.get());
    cell.run_until(100, |cell| {
        cell.volume(1).ended(first) && cell.volume(2).ended(second)
    });
    cell.drops = true;
    let mut budgeted = false;
    for _ in 0..300 {
        let calls = cell.fixture.world.events().len();
        let (_, outcomes) = cell.tick();
        let sent = cell.fixture.world.events()[calls..]
            .iter()
            .filter(|event| matches!(event, Event::Attach(..) | Event::Detach(..)))
            .count();
        assert!(sent <= 1, "{sent} requests in one tick");
        budgeted |= outcomes.iter().any(|outcome| {
            matches!(outcome.step, Step::Detach { .. })
                && outcome.verdict == Verdict::Wait(Reason::Budget)
        });
        if gone(&cell, 1, first) && gone(&cell, 2, second) {
            break;
        }
    }
    assert!(budgeted);
    assert!(gone(&cell, 1, first) && gone(&cell, 2, second));
    assert_eq!(detaches(&cell).len(), 2);
    clean(&cell);
}

/// One call per tick and an attach wait of one tick: a named standby whose new attach never lists is requested on
/// every tick, and another shard's detach, never requested before, takes the call of the first tick that plans it.
#[test]
fn a_detach_goes_out_while_a_named_standbys_attach_retries_every_tick() {
    let mut config = config_of(8);
    config.attach_settle_us = config.tick_us;
    let mut cell = Cell::with(8, 2, true, config.validate().unwrap().with_calls(1));
    let mut placed = cell.fixture.listing.clone().unwrap();
    for entry in &mut placed.hosts {
        let owner = matches!(entry.host.get(), 2 | 3);
        entry.placement.partition = Partition(if owner { 7 } else { entry.host.get() as u32 });
    }
    cell.fixture.listing = Some(placed);
    cell.run_until(120, |cell| cell.designated());
    let (retrying, lost) = (
        cell.shard(1).standby.unwrap(),
        cell.shard(2).standby.unwrap(),
    );
    assert_ne!(retrying, lost);
    cell.drops = false;
    cell.lose(lost.get());
    cell.run_until(100, |cell| cell.volume(2).ended(lost));
    assert!(detaches(&cell).is_empty());

    release_through_others(&mut cell, retrying);
    let unlanded = vec![AttachFault::Unlanded; 400];
    cell.fixture.world.faults.attach.extend(unlanded);
    let retries = |cell: &Cell| {
        let sent = cell.attach_calls();
        let mine = sent
            .iter()
            .filter(|(_, id)| *id == instance(retrying.get()));
        mine.count()
    };
    let before = retries(&cell);
    cell.run_until(60, |cell| retries(cell) >= before + 2);

    cell.drops = true;
    let mut planned = None;
    for _ in 0..60 {
        let sent = retries(&cell);
        let (survey, outcomes) = cell.tick();
        if survey.plan.steps.iter().any(detaching) {
            let attached = survey.plan.steps.iter().any(attaching_step);
            let detach = outcome_of(&outcomes, detaching);
            planned = Some((attached, detach.reclaim, retries(&cell) - sent));
            break;
        }
    }
    let requested = Some(Reclaim::DetachRequested);
    assert_eq!(planned, Some((true, requested, 0)));
    assert_eq!(detaches(&cell), [instance(lost.get())]);
    let sent = retries(&cell);
    cell.tick();
    assert_eq!(retries(&cell), sent + 1);
}

/// CALL-ROTATION for a fresh need that already sent a request: with one call per tick and an attach wait of one
/// tick, a fresh need's attach returns unknown on every tick, and another shard's detach, never requested before,
/// takes the call of the first tick that plans it; the fresh attach goes out again on the next tick.
#[test]
fn a_detach_goes_out_while_a_fresh_needs_attach_retries_every_tick() {
    let mut config = config_of(8);
    config.attach_settle_us = config.tick_us;
    let mut cell = Cell::with(9, 3, true, config.validate().unwrap().with_calls(1));
    cell.run_until(200, Cell::designated);
    let lost = cell.shard(1).standby.unwrap();
    cell.drops = false;
    cell.lose(lost.get());
    cell.run_until(100, |cell| cell.volume(1).ended(lost));
    cell.run_until(100, Cell::designated);
    assert!(detaches(&cell).is_empty());

    let fresh = cell.shard(3);
    cell.lose(fresh.owner.get());
    cell.lose(fresh.standby.unwrap().get());
    let unknown = vec![AttachFault::Unknown { attached: false }; 400];
    cell.fixture.world.faults.attach.extend(unknown);
    let retries = |cell: &Cell| {
        let sent = cell.attach_calls();
        sent.iter().filter(|(held, _)| *held == volume(3)).count()
    };
    let before = retries(&cell);
    cell.run_until(100, |cell| retries(cell) >= before + 2);

    cell.drops = true;
    let mut planned = None;
    for _ in 0..30 {
        let sent = retries(&cell);
        let (survey, outcomes) = cell.tick();
        if survey.plan.steps.iter().any(detaching) {
            let attached = survey.plan.steps.iter().any(attaching_step);
            let detach = outcome_of(&outcomes, detaching);
            planned = Some((attached, detach.reclaim, retries(&cell) - sent));
            break;
        }
    }
    let requested = Some(Reclaim::DetachRequested);
    assert_eq!(planned, Some((true, requested, 0)));
    assert_eq!(detaches(&cell), [instance(lost.get())]);
    let sent = retries(&cell);
    cell.tick();
    assert_eq!(retries(&cell), sent + 1);
}

/// A cell of two shards with one write a tick whose shard 2 plans a `RecordAttach`, that plan, and a lost host
/// that neither shard names.
fn contended() -> (Cell, Survey, Host) {
    let mut config = config_of(8);
    config.writes_per_tick = 1;
    let mut cell = Cell::with(8, 2, true, config.validate().unwrap());
    spread_partitions(&mut cell);
    cell.run_until(120, |cell| cell.designated());
    let named: Vec<Host> = (1..=2)
        .flat_map(|n| [Some(cell.shard(n).owner), cell.shard(n).standby])
        .flatten()
        .collect();
    let third = (1..=8).map(host).find(|held| !named.contains(held));
    let third = third.unwrap();
    cell.lose(cell.shard(2).standby.unwrap().get());
    cell.lose(third.get());
    let survey = cell.planned(recording_second);
    (cell, survey, third)
}

fn recording_second(step: &Step) -> bool {
    matches!(step, Step::RecordAttach { shard: at, .. } if *at == shard(2))
}

/// One write per tick: shard 2's record write returns unknown on every tick and commits nothing, and the end of a
/// lost third host's attach on shard 1 takes the next tick's write. The record write is retried on a later tick.
#[test]
fn an_end_takes_a_write_while_another_shards_record_write_returns_unknown_every_tick() {
    let (mut cell, survey, third) = contended();
    let unknown = |cell: &Cell| {
        let store = cell.store().clone();
        let fault = move || store.schedule(Arm::Timeout { commit: false });
        *cell.hook.borrow_mut() = Some((Key::Volume(volume(2)), Box::new(fault)));
    };
    unknown(&cell);
    let outcomes = cell.actuate(&survey);
    let first = outcome_of(&outcomes, recording_second);
    assert_eq!(first.verdict, Verdict::Wait(Reason::Unknown));
    cell.now_us += 10 * S;
    record_entry(&cell, third);
    unknown(&cell);
    let (_, outcomes) = cell.tick();
    assert_eq!(outcome_of(&outcomes, ending).verdict, Verdict::Advance);
    assert_eq!(
        outcome_of(&outcomes, recording_second).verdict,
        Verdict::Wait(Reason::Budget)
    );
    assert!(cell.volume(1).ended(third));
    let mut retried = 0;
    for _ in 0..6 {
        unknown(&cell);
        let (_, outcomes) = cell.tick();
        let unknown =
            |o: &&Outcome| recording_second(&o.step) && o.verdict == Verdict::Wait(Reason::Unknown);
        retried += outcomes.iter().filter(unknown).count();
    }
    assert!(retried >= 1, "{retried} retries");
}

/// One write per tick: both shards' writes return unknown on every tick, and the one write goes to each shard in
/// turn.
#[test]
fn two_shards_whose_writes_return_unknown_every_tick_take_the_one_write_in_turn() {
    let (mut cell, survey, third) = contended();
    cell.fault_next(Arm::Timeout { commit: false });
    let outcomes = cell.actuate(&survey);
    let first = outcome_of(&outcomes, recording_second);
    assert_eq!(first.verdict, Verdict::Wait(Reason::Unknown));
    cell.now_us += 10 * S;
    record_entry(&cell, third);
    let mut charged = Vec::new();
    for _ in 0..6 {
        cell.fault_next(Arm::Timeout { commit: false });
        let (_, outcomes) = cell.tick();
        let unknown: Vec<_> = outcomes
            .iter()
            .filter(|o| o.verdict == Verdict::Wait(Reason::Unknown))
            .map(|o| o.step.shard())
            .collect();
        assert_eq!(unknown.len(), 1, "{outcomes:?}");
        charged.push(unknown[0]);
    }
    let turns = [shard(1), shard(2)].repeat(3);
    assert_eq!(charged, turns);
    assert!(!cell.volume(1).ended(third));
}

/// One write per tick: a shard that nothing serves keeps its place ahead of a standby need's write on the tick
/// after its record write returned unknown.
#[test]
fn a_fresh_needs_record_write_that_returned_unknown_takes_the_next_ticks_one_write() {
    let mut config = config_of(8);
    config.writes_per_tick = 1;
    let mut cell = Cell::with(8, 2, true, config.validate().unwrap());
    spread_partitions(&mut cell);
    cell.run_until(120, |cell| cell.designated());
    let fresh = cell.shard(1);
    cell.lose(fresh.owner.get());
    cell.lose(fresh.standby.unwrap().get());
    cell.lose(cell.shard(2).standby.unwrap().get());
    let recording =
        |step: &Step| matches!(step, Step::RecordAttach { shard: at, .. } if *at == shard(1));
    let second = |step: &Step| step.shard() == shard(2) && !attaching_step(step);
    let survey = cell.planned(recording);
    let store = cell.store().clone();
    let fault = move || store.schedule(Arm::Timeout { commit: false });
    *cell.hook.borrow_mut() = Some((Key::Volume(volume(1)), Box::new(fault)));
    let outcomes = cell.actuate(&survey);
    let first = outcome_of(&outcomes, recording);
    assert_eq!(first.verdict, Verdict::Wait(Reason::Unknown));
    cell.now_us += 10 * S;
    let (survey, outcomes) = cell.tick();
    let first = survey
        .plan
        .shards
        .iter()
        .find(|plan| plan.shard == shard(1));
    let need = match first.map(|plan| plan.state) {
        Some(ShardState::Enrolling { need, .. }) => Some(need),
        _ => None,
    };
    assert_eq!(need, Some(Need::Fresh));
    assert_eq!(outcome_of(&outcomes, recording).verdict, Verdict::Advance);
    assert_eq!(
        outcome_of(&outcomes, second).verdict,
        Verdict::Wait(Reason::Budget)
    );
}

fn attaching_step(step: &Step) -> bool {
    matches!(step, Step::Attach { .. })
}

/// Ends `host`'s live entry of shard 1's volume, drops its pair, detaches its instance and marks the entry gone,
/// through an owner's client and a second reconciler.
fn release_through_others(cell: &mut Cell, host: Host) {
    let mut client = owner(cell.store());
    let read = client.read::<VolumeRecord>(Key::Volume(volume(1))).unwrap();
    let mut ended = read.value().clone();
    let seq = ended.live(host).unwrap();
    let entry = ended.events.iter_mut().find(|event| event.seq == seq);
    entry.unwrap().kind = EventKind::Ended;
    let read = client.replace(&read, ended).unwrap();
    let mut dropped = read.value().clone();
    dropped.pairs.retain(|pair| pair.host != host);
    client.replace(&read, dropped).unwrap();
    cell.fixture.world.detach(volume(1), instance(host.get()));
    let listed = cell.listed(1);
    let settle = cell.bounds.config().detach_settle_us;
    let clean = |at: u64| Listing {
        at,
        instances: &listed,
    };
    let two = [clean(cell.now_us), clean(cell.now_us + settle)];
    let gate = StandbyGate::qualified();
    let mut other = Reconciler::new(reconciler_client(cell.store()));
    let witness = other.detachable(volume(1), host).unwrap();
    let timing = crate::failover::reconcile::Settle {
        requested: 0,
        settle,
    };
    other.release_attach(&gate, &witness, &two, timing).unwrap();
    assert!(gone(cell, 1, host));
}

/// CALL-ROTATION within one shard: a named standby's attach returns unknown on every tick, which stops the shard's
/// later steps, and the shard's detach, never requested before, runs ahead of it and goes out.
#[test]
fn a_shards_detach_runs_ahead_of_its_named_standbys_attach_that_returns_unknown() {
    let mut config = config_of(8);
    config.attach_settle_us = config.tick_us;
    let mut cell = Cell::with(6, 1, true, config.validate().unwrap());
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    let standby = cell.shard(1).standby.unwrap();
    let third = record_third(&cell);
    assert_ne!(third, standby);
    let (seq, _) = cell.volume(1).latest(third).unwrap();
    let gate = StandbyGate::qualified();
    let mut other = Reconciler::new(reconciler_client(cell.store()));
    other
        .end_attach(&gate, shard(1), volume(1), third, seq)
        .unwrap();
    release_through_others(&mut cell, standby);
    let unknown = vec![AttachFault::Unknown { attached: false }; 400];
    cell.fixture.world.faults.attach.extend(unknown);
    let calls = cell.attach_calls().len();
    cell.run_until(40, |cell| cell.attach_calls().len() > calls);
    assert!(detaches(&cell).is_empty());
    cell.fixture.world.attach(volume(1), instance(third.get()));
    let mut planned = None;
    for _ in 0..80 {
        let (survey, outcomes) = cell.tick();
        let steps = &survey.plan.steps;
        if steps.iter().any(detaching) && steps.iter().any(attaching_step) {
            let attach = outcome_of(&outcomes, attaching_step);
            let detach = outcome_of(&outcomes, detaching);
            planned = Some((attach.verdict, detach.verdict, detach.reclaim));
            break;
        }
    }
    let unknown = Verdict::Wait(Reason::Unknown);
    let requested = Some(Reclaim::DetachRequested);
    assert_eq!(planned, Some((unknown, Verdict::Advance, requested)));
    assert_eq!(detaches(&cell), [instance(third.get())]);
}

#[test]
fn an_unrequested_slot_entry_under_the_operator_hold_keeps_its_slot_and_attaches_after_it() {
    for unread in [false, true] {
        let mut config = config_of(8);
        config.attach_stuck_us = 120 * S;
        let stuck_us = config.attach_stuck_us;
        let mut cell = Cell::with(6, 1, true, config.validate().unwrap());
        let mut recorded = false;
        for _ in 0..40 {
            let (_, outcomes) = cell.tick();
            recorded = outcomes.iter().any(|outcome| {
                matches!(outcome.step, Step::RecordAttach { .. })
                    && outcome.verdict == Verdict::Advance
            });
            if recorded {
                break;
            }
        }
        assert!(recorded);
        let candidate = hosts_of(&cell.volume(1))[1];
        assert!(cell.attach_calls().is_empty());
        let hold = |cell: &mut Cell, on: bool| {
            let mut held = cell.fixture.listing.clone().unwrap();
            held.version += 1;
            held.zone_hold = on;
            cell.fixture.listing = Some(held);
        };
        hold(&mut cell, true);
        let held_at = cell.now_us;
        if unread {
            cell.store().schedule(Arm::Unavailable);
            let survey = cell.survey();
            assert!(
                survey
                    .observation
                    .zone
                    .is_ok_and(|view| view.census.is_err())
            );
            assert!(cell.zone.sighted.is_empty());
        }
        let mut seen = Vec::new();
        while cell.now_us - held_at < 2 * stuck_us {
            let (_, outcomes) = cell.tick();
            seen.extend(outcomes);
        }
        assert!(
            !seen.iter().any(|o| o.reclaim == Some(Reclaim::Ended)),
            "{unread} {seen:?}"
        );
        assert!(cell.attach_calls().is_empty());
        assert!(cell.volume(1).live(candidate).is_some());
        hold(&mut cell, false);
        cell.run_until(10, |cell| !cell.attach_calls().is_empty());
        assert_eq!(cell.attach_calls()[0].1, instance(candidate.get()));
        assert!(cell.volume(1).live(candidate).is_some());
        clean(&cell);
    }
}

#[test]
fn a_fresh_listing_that_shows_an_ended_instance_restarts_its_release_pair() {
    for detach in [false, true] {
        let mut cell = Cell::new(8, 1);
        cell.run_until(40, |cell| cell.shard(1).standby.is_some());
        let first = cell.shard(1).standby.unwrap();
        cell.lose(first.get());
        cell.run_until(300, |cell| !cell.zone.clean.is_empty());
        let second = cell.shard(1).standby.unwrap();
        assert_ne!(second, first);
        cell.lose(second.get());
        let shown = instance(first.get());
        let (seq, _) = cell.volume(1).latest(first).unwrap();
        let mut cleared = None;
        for _ in 0..120 {
            let survey = cell.survey();
            let fresh = survey.plan.steps.iter().any(|step| match detach {
                true => matches!(step, Step::Detach { .. }),
                false => matches!(step, Step::Attach { .. }),
            });
            if fresh {
                assert!(cell.zone.clean.contains_key(&(volume(1), seq)), "{detach}");
                cell.fixture.world.attach(volume(1), shown);
            }
            cell.actuate(&survey);
            if fresh {
                cell.fixture.world.detach(volume(1), shown);
                assert!(!cell.zone.clean.contains_key(&(volume(1), seq)), "{detach}");
                cleared = Some(cell.now_us);
            }
            cell.enroll_listed();
            cell.drop_ended_pairs();
            cell.now_us += 10 * S;
            if cleared.is_some() {
                break;
            }
        }
        let cleared = cleared.unwrap();
        let settle = cell.bounds.config().detach_settle_us;
        let seen = run(&mut cell, 200, |cell| gone(cell, 1, first));
        let released = reclaims_of(&seen, first).last().unwrap().0;
        assert!(released - cleared >= settle, "{released} {cleared}");
    }
}

fn outcome_of(outcomes: &[Outcome], wanted: impl Fn(&Step) -> bool) -> Outcome {
    let found = outcomes.iter().find(|outcome| wanted(&outcome.step));
    *found.unwrap_or_else(|| panic!("{outcomes:?}"))
}

fn ending(step: &Step) -> bool {
    matches!(step, Step::End { .. })
}

fn detaching(step: &Step) -> bool {
    matches!(step, Step::Detach { .. })
}

fn releasing(step: &Step) -> bool {
    matches!(step, Step::ReleaseAttach { .. })
}

fn reserving(step: &Step) -> bool {
    matches!(step, Step::Reserve { .. })
}

fn slot_host(cell: &Cell) -> Host {
    let census = census_of(cell.store()).unwrap();
    census.slot(shard(1)).unwrap().host
}

#[test]
fn an_end_takes_the_ticks_one_write_and_the_next_ticks_reservation_moves_the_slot() {
    let mut config = config_of(8);
    config.writes_per_tick = 1;
    config.attach_stuck_us = 120 * S;
    let mut cell = Cell::with(6, 1, true, config.validate().unwrap());
    cell.run_until(60, |cell| hosts_of(&cell.volume(1)).len() == 2);
    let stuck = hosts_of(&cell.volume(1))[1];
    cell.unenrolled.push(stuck.get());
    let mut ended = None;
    for _ in 0..100 {
        let events = cell.fixture.world.events().len();
        let (_, outcomes) = cell.tick();
        assert!(cell.writes_since(events) <= 1, "{outcomes:?}");
        if outcomes.iter().any(|o| o.reclaim == Some(Reclaim::Ended)) {
            ended = Some(outcomes);
            break;
        }
    }
    let outcomes = ended.expect("the stuck attach ends");
    let reserve = outcome_of(&outcomes, reserving);
    assert_eq!(reserve.verdict, Verdict::Wait(Reason::Budget));
    assert_eq!(slot_host(&cell), stuck);
    assert!(cell.volume(1).ended(stuck));
    let (_, outcomes) = cell.tick();
    let reserve = outcome_of(&outcomes, reserving);
    assert_eq!(reserve.verdict, Verdict::Advance, "{outcomes:?}");
    assert_ne!(slot_host(&cell), stuck);
    clean(&cell);
}

#[test]
fn two_ready_releases_under_one_write_per_tick_are_recorded_in_two_ticks() {
    let mut config = config_of(8);
    config.writes_per_tick = 1;
    let mut cell = Cell::with(8, 2, true, config.validate().unwrap());
    let mut placed = cell.fixture.listing.clone().unwrap();
    for entry in &mut placed.hosts {
        let owner = matches!(entry.host.get(), 2 | 3);
        entry.placement.partition = Partition(if owner { 7 } else { entry.host.get() as u32 });
    }
    cell.fixture.listing = Some(placed);
    cell.run_until(200, |cell| cell.designated());
    let (first, second) = (
        cell.shard(1).standby.unwrap(),
        cell.shard(2).standby.unwrap(),
    );
    assert_ne!(first, second);
    cell.drops = false;
    cell.lose(first.get());
    cell.lose(second.get());
    cell.run_until(200, |cell| {
        cell.volume(1).ended(first) && cell.volume(2).ended(second)
    });
    assert!(detaches(&cell).is_empty());
    cell.drops = true;
    cell.drop_ended_pairs();
    let (_, outcomes) = cell.tick();
    let sent = outcomes
        .iter()
        .filter(|o| o.reclaim == Some(Reclaim::DetachRequested));
    assert_eq!(sent.count(), 2, "{outcomes:?}");
    let mut released = Vec::new();
    let mut budgeted = false;
    for _ in 0..200 {
        let (events, at) = (cell.fixture.world.events().len(), cell.now_us);
        let (_, outcomes) = cell.tick();
        assert!(cell.writes_since(events) <= 1, "{outcomes:?}");
        let gone = outcomes.iter().filter(|o| o.reclaim == Some(Reclaim::Gone));
        released.extend(gone.map(|_| at));
        budgeted |= outcomes
            .iter()
            .any(|o| releasing(&o.step) && o.verdict == Verdict::Wait(Reason::Budget));
        if released.len() == 2 {
            break;
        }
    }
    assert!(budgeted);
    assert_eq!(released.len(), 2);
    assert_eq!(released[1] - released[0], 10 * S);
    assert!(gone(&cell, 1, first) && gone(&cell, 2, second));
    clean(&cell);
}

#[test]
fn an_end_with_an_unknown_outcome_stops_the_shards_reservation_for_the_tick() {
    for commit in [false, true] {
        let mut config = config_of(8);
        config.attach_stuck_us = 120 * S;
        let mut cell = Cell::with(6, 1, true, config.validate().unwrap());
        cell.run_until(40, |cell| hosts_of(&cell.volume(1)).len() == 2);
        let lost = hosts_of(&cell.volume(1))[1];
        cell.unenrolled.push(lost.get());
        let survey = cell.planned(ending);
        assert!(survey.plan.steps.iter().any(reserving));
        let census = Key::Standbys(ZONE);
        let reserved = cell.store().0.borrow().commit_count(&census);
        cell.fault_next(Arm::Timeout { commit });
        let events = cell.fixture.world.events().len();
        let outcomes = cell.actuate(&survey);
        let end = outcome_of(&outcomes, ending);
        assert_eq!(
            (end.verdict, end.reclaim),
            (Verdict::Wait(Reason::Unknown), None)
        );
        let reserve = outcome_of(&outcomes, reserving);
        assert_eq!(reserve.verdict, Verdict::Wait(Reason::Moved));
        assert_eq!(cell.writes_since(events), 1);
        assert_eq!(cell.store().0.borrow().commit_count(&census), reserved);
        assert_eq!(slot_host(&cell), lost);
        assert_eq!(cell.volume(1).ended(lost), commit);
        cell.drop_ended_pairs();
        cell.now_us += 10 * S;
        let done = |cell: &Cell| {
            gone(cell, 1, lost) && cell.shard(1).standby.is_some_and(|named| named != lost)
        };
        run(&mut cell, 200, done);
        clean(&cell);
    }
}

#[test]
fn an_end_of_a_host_the_record_names_after_the_survey_is_refused_under_its_role() {
    for owning in [false, true] {
        let mut cell = Cell::new(6, 1);
        cell.run_until(40, |cell| cell.shard(1).standby.is_some());
        let third = attach_third(&mut cell);
        assert!(cell.volume(1).enrolled(third).is_some());
        cell.drain(third);
        let mut survey = cell.planned(ending);
        let end = Step::End {
            shard: shard(1),
            host: third,
        };
        assert_eq!(survey.plan.steps, [end]);
        survey.plan.steps.push(end);
        let mut client = owner(cell.store());
        let read = client.read::<ShardRecord>(Key::Shard(shard(1))).unwrap();
        client
            .designate(&read, Target::of(read.value()), third)
            .unwrap();
        if owning {
            let read = client.read::<ShardRecord>(Key::Shard(shard(1))).unwrap();
            client
                .take_over(&read, Target::of(read.value()), third)
                .unwrap();
        }
        let before = cell.volume(1);
        let events = cell.fixture.world.events().len();
        let outcomes = cell.actuate(&survey);
        let ends: Vec<(Verdict, Option<Reclaim>)> = (outcomes.iter())
            .map(|outcome| (outcome.verdict, outcome.reclaim))
            .collect();
        let label = match owning {
            true => Reclaim::RefusedOwner,
            false => Reclaim::RefusedStandby,
        };
        let moved = Verdict::Wait(Reason::Moved);
        assert_eq!(ends, [(moved, Some(label)), (moved, None)], "{owning}");
        assert_eq!(cell.writes_since(events), 0);
        assert_eq!(cell.volume(1), before);
        assert!(cell.volume(1).live(third).is_some());
    }
}

#[test]
fn a_failed_fresh_listing_holds_the_detach_request() {
    let mut cell = Cell::new(6, 1);
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    let lost = cell.shard(1).standby.unwrap();
    cell.lose(lost.get());
    let mut planned = None;
    for _ in 0..200 {
        let survey = cell.survey();
        if survey.plan.steps.iter().any(detaching) {
            planned = Some(survey);
            break;
        }
        cell.actuate(&survey);
        cell.enroll_listed();
        cell.drop_ended_pairs();
        cell.now_us += 10 * S;
    }
    let survey = planned.expect("a survey plans the detach");
    cell.fixture.world.faults.attachments = true;
    let outcomes = cell.actuate(&survey);
    let held = outcome_of(&outcomes, detaching);
    assert_eq!(
        (held.verdict, held.reclaim),
        (Verdict::Wait(Reason::Unlisted), None)
    );
    assert!(detaches(&cell).is_empty());
    cell.fixture.world.faults.attachments = false;
    cell.drop_ended_pairs();
    cell.now_us += 10 * S;
    let (_, outcomes) = cell.tick();
    let sent = outcome_of(&outcomes, detaching);
    assert_eq!(sent.reclaim, Some(Reclaim::DetachRequested));
    assert_eq!(detaches(&cell), [instance(lost.get())]);
    clean(&cell);
}

#[test]
fn a_repeat_detach_request_goes_out_at_the_settle_time_and_not_before() {
    let mut cell = Cell::new(6, 1);
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    let lost = cell.shard(1).standby.unwrap();
    cell.fixture
        .world
        .faults
        .detach
        .push_back(DetachFault::Lingers);
    cell.lose(lost.get());
    let seen = run(&mut cell, 200, |cell| !detaches(cell).is_empty());
    let detached = reclaims_of(&seen, lost).last().unwrap().0;
    let settle = cell.bounds.config().detach_settle_us;
    cell.now_us = detached + settle - 1;
    let survey = cell.survey();
    let early = outcome_of(&cell.actuate(&survey), detaching);
    assert_eq!(
        (early.verdict, early.reclaim),
        (Verdict::Wait(Reason::Settling), None)
    );
    assert_eq!(detaches(&cell).len(), 1);
    cell.now_us = detached + settle;
    let survey = cell.survey();
    let due = outcome_of(&cell.actuate(&survey), detaching);
    assert_eq!(
        (due.verdict, due.reclaim),
        (Verdict::Advance, Some(Reclaim::DetachRequested))
    );
    assert_eq!(detaches(&cell).len(), 2);
    clean(&cell);
}

#[test]
fn the_first_clean_listing_is_kept_at_the_settle_time_after_the_last_requests_tick_by_its_survey_time()
 {
    for (restarted, exact) in [(false, false), (false, true), (true, false), (true, true)] {
        let mut cell = Cell::new(6, 1);
        cell.run_until(40, |cell| cell.shard(1).standby.is_some());
        let lost = cell.shard(1).standby.unwrap();
        cell.lose(lost.get());
        let seen = run(&mut cell, 200, |cell| !detaches(cell).is_empty());
        let mut requested = reclaims_of(&seen, lost).last().unwrap().0;
        if restarted {
            cell.restart();
            requested = cell.now_us;
            let first = cell.survey();
            assert_eq!(first.status.started_us, requested);
        } else {
            cell.tick();
        }
        let config = cell.bounds.config();
        let returned = requested + config.tick_us;
        assert!(cell.zone.clean.is_empty());
        cell.now_us = returned + config.detach_settle_us - u64::from(!exact);
        let survey = cell.survey();
        if !exact {
            cell.now_us += 5 * S;
        }
        let waiting = outcome_of(&cell.actuate(&survey), releasing);
        assert_eq!(waiting.verdict, Verdict::Wait(Reason::Settling));
        let kept = usize::from(exact);
        assert_eq!(cell.zone.clean.len(), kept, "{restarted} {exact}");
    }
}

/// RELEASE-SETTLED counts from the first survey after the last request, which follows the request's return: the
/// caller's next survey comes three ticks after the call that sent the detach, and the first clean listing is kept
/// `detach_settle_us` after that survey and not one microsecond before.
#[test]
fn a_release_settles_from_the_first_survey_after_its_last_request() {
    for exact in [false, true] {
        let mut cell = Cell::new(6, 1);
        cell.run_until(40, |cell| cell.shard(1).standby.is_some());
        let lost = cell.shard(1).standby.unwrap();
        cell.lose(lost.get());
        let seen = run(&mut cell, 200, |cell| !detaches(cell).is_empty());
        let requested = reclaims_of(&seen, lost).last().unwrap().0;
        let (tick_us, settle_us) = {
            let config = cell.bounds.config();
            (config.tick_us, config.detach_settle_us)
        };
        let returned = requested + 3 * tick_us;
        cell.now_us = returned;
        let survey = cell.survey();
        let waiting = outcome_of(&cell.actuate(&survey), releasing);
        assert_eq!(waiting.verdict, Verdict::Wait(Reason::Settling));
        assert!(cell.zone.clean.is_empty());
        cell.now_us = returned + settle_us - u64::from(!exact);
        let survey = cell.survey();
        let waiting = outcome_of(&cell.actuate(&survey), releasing);
        assert_eq!(waiting.verdict, Verdict::Wait(Reason::Settling));
        assert_eq!(cell.zone.clean.len(), usize::from(exact), "{exact}");
    }
}

#[test]
fn a_shard_that_leaves_the_directory_keeps_its_request_times_one_tick_past_the_longer_bound() {
    for exact in [false, true] {
        let mut cell = Cell::new(6, 1);
        cell.run_until(40, |cell| cell.shard(1).standby.is_some());
        let lost = cell.shard(1).standby.unwrap();
        cell.lose(lost.get());
        let seen = run(&mut cell, 200, |cell| !detaches(cell).is_empty());
        let detached = reclaims_of(&seen, lost).last().unwrap().0;
        cell.tick();
        let config = cell.bounds.config();
        let longer = config.attach_stuck_us.max(config.detach_settle_us);
        cell.now_us = detached + longer + config.tick_us - u64::from(!exact);
        let mut delisted = cell.survey();
        delisted.plan.steps.clear();
        delisted.observation.zone.as_mut().unwrap().shards.clear();
        cell.actuate(&delisted);
        let (seq, _) = cell.volume(1).latest(lost).unwrap();
        let held = cell.zone.requests.contains_key(&(volume(1), seq));
        assert_eq!(held, !exact, "{exact}");
    }
}

#[test]
fn an_entry_requested_after_its_first_sighting_is_stuck_from_the_request() {
    let mut config = config_of(8);
    config.attach_stuck_us = 120 * S;
    let stuck_us = config.attach_stuck_us;
    let mut cell = Cell::with(6, 1, true, config.validate().unwrap());
    cell.run_until(40, |cell| hosts_of(&cell.volume(1)).len() == 2);
    let stuck = hosts_of(&cell.volume(1))[1];
    cell.unenrolled.push(stuck.get());
    let listed = instance(stuck.get()).as_str().to_owned();
    cell.run_until(10, |cell| cell.listed(1).contains(&listed));
    cell.restart();
    let restarted = cell.now_us;
    for _ in 0..6 {
        cell.tick();
    }
    cell.fixture.world.detach(volume(1), instance(stuck.get()));
    let calls = cell.attach_calls().len();
    let mut requested = None;
    for _ in 0..10 {
        let at = cell.now_us;
        cell.tick();
        if cell.attach_calls().len() > calls {
            requested = Some(at);
            break;
        }
    }
    let requested = requested.expect("the loop requests the unlisted entry's attach");
    assert!(requested - restarted >= 60 * S);
    let seen = run(&mut cell, 100, |cell| cell.volume(1).ended(stuck));
    let ended = reclaims_of(&seen, stuck);
    assert_eq!(kinds(&ended)[0], Reclaim::Ended);
    assert_eq!(ended[0].0 - requested, stuck_us, "{ended:?}");
    clean(&cell);
}

#[test]
fn an_unlisted_entry_of_a_host_without_the_slot_ends_at_the_stuck_bound_after_its_first_sighting() {
    let mut config = config_of(8);
    config.attach_stuck_us = 120 * S;
    let stuck_us = config.attach_stuck_us;
    let mut cell = Cell::with(6, 1, true, config.validate().unwrap());
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    let standby = cell.shard(1).standby.unwrap();
    let third = record_third(&cell);
    let sighted = cell.now_us;
    cell.tick();
    assert!(!cell.zone.sighted.is_empty());
    cell.store().schedule(Arm::Unavailable);
    let unread = cell.survey();
    assert!(
        unread
            .observation
            .zone
            .is_ok_and(|view| view.census.is_err())
    );
    assert!(!cell.zone.sighted.is_empty());
    let seen = run(&mut cell, 100, |cell| cell.volume(1).ended(third));
    let ended = reclaims_of(&seen, third);
    assert_eq!(kinds(&ended)[0], Reclaim::Ended);
    assert_eq!(ended[0].0 - sighted, stuck_us, "{ended:?}");
    assert!(!cell.zone.sighted.is_empty());
    cell.tick();
    assert!(cell.zone.sighted.is_empty());
    assert_eq!(cell.shard(1).standby, Some(standby));
    let requested = cell.attach_calls();
    assert!(!requested.iter().any(|(_, id)| *id == instance(third.get())));
    clean(&cell);
}

#[test]
fn a_draining_slot_host_keeps_its_slot_until_its_attach_is_ended() {
    let mut cell = Cell::new(6, 1);
    cell.run_until(40, |cell| hosts_of(&cell.volume(1)).len() == 2);
    let first = hosts_of(&cell.volume(1))[1];
    cell.unenrolled.push(first.get());
    cell.drain(first);
    let survey = cell.planned(ending);
    let end = Step::End {
        shard: shard(1),
        host: first,
    };
    assert_eq!(survey.plan.steps[0], end);
    assert!(survey.plan.steps.iter().any(reserving));
    cell.store().schedule(Arm::Unavailable);
    let outcomes = cell.actuate(&survey);
    let unread = outcome_of(&outcomes, ending);
    assert_eq!(
        (unread.verdict, unread.reclaim),
        (Verdict::Wait(Reason::Store), None)
    );
    let taken = crate::failover::standbys::Refusal::Taken;
    let reserve = outcome_of(&outcomes, reserving);
    assert_eq!(reserve.verdict, Verdict::Wait(Reason::Population(taken)));
    assert_eq!(slot_host(&cell), first);
    assert!(cell.volume(1).live(first).is_some());
    cell.now_us += 10 * S;
    let (_, outcomes) = cell.tick();
    assert_eq!(outcome_of(&outcomes, ending).reclaim, Some(Reclaim::Ended));
    assert_eq!(outcome_of(&outcomes, reserving).verdict, Verdict::Advance);
    assert_ne!(slot_host(&cell), first);
    clean(&cell);
}

fn spread_partitions(cell: &mut Cell) {
    let mut placed = cell.fixture.listing.clone().unwrap();
    for entry in &mut placed.hosts {
        let owner = matches!(entry.host.get(), 2 | 3);
        entry.placement.partition = Partition(if owner { 7 } else { entry.host.get() as u32 });
    }
    cell.fixture.listing = Some(placed);
}

#[test]
fn a_detach_goes_out_in_a_tick_whose_one_write_a_designation_took() {
    let mut config = config_of(8);
    config.writes_per_tick = 1;
    let mut cell = Cell::with(8, 2, true, config.validate().unwrap());
    spread_partitions(&mut cell);
    cell.run_until(200, |cell| cell.designated());
    let (first, second) = (
        cell.shard(1).standby.unwrap(),
        cell.shard(2).standby.unwrap(),
    );
    assert_ne!(first, second);
    cell.drops = false;
    cell.lose(first.get());
    cell.run_until(200, |cell| cell.volume(1).ended(first));
    cell.lose(second.get());
    let designating =
        |step: &Step| matches!(step, Step::Designate { shard: at, .. } if *at == shard(2));
    drop(cell.planned(designating));
    cell.drop_ended_pairs();
    let survey = cell.survey();
    let detach = Step::Detach {
        shard: shard(1),
        host: first,
    };
    let steps = &survey.plan.steps;
    assert!(steps.iter().any(designating), "{steps:?}");
    assert!(steps.contains(&detach), "{steps:?}");
    let events = cell.fixture.world.events().len();
    let outcomes = cell.actuate(&survey);
    assert_eq!(outcome_of(&outcomes, designating).verdict, Verdict::Advance);
    let sent = outcome_of(&outcomes, detaching);
    assert_eq!(sent.reclaim, Some(Reclaim::DetachRequested), "{outcomes:?}");
    assert_eq!(cell.writes_since(events), 1);
    assert_eq!(detaches(&cell), [instance(first.get())]);
    clean(&cell);
}

#[test]
fn an_unrequested_slot_entry_whose_instance_another_volume_lists_keeps_its_slot_under_the_hold() {
    let mut config = config_of(8);
    config.attach_stuck_us = 120 * S;
    let stuck_us = config.attach_stuck_us;
    let mut cell = Cell::with(6, 2, true, config.validate().unwrap());
    cell.drain(host(1));
    let mut candidate = None;
    for _ in 0..40 {
        let (_, outcomes) = cell.tick();
        candidate = outcomes.iter().find_map(|outcome| match outcome.step {
            Step::RecordAttach {
                shard: at, host, ..
            } if at == shard(1) && outcome.verdict == Verdict::Advance => Some(host),
            _ => None,
        });
        if candidate.is_some() {
            break;
        }
    }
    let candidate = candidate.expect("shard 1 records its candidate's attach");
    assert_eq!(candidate, cell.shard(2).owner);
    let listed = instance(candidate.get()).as_str().to_owned();
    assert!(cell.listed(2).contains(&listed));
    let requested = |cell: &Cell| {
        let calls = cell.attach_calls();
        calls.iter().any(|(at, _)| *at == volume(1))
    };
    assert!(!requested(&cell));
    let hold = |cell: &mut Cell, on: bool| {
        let mut held = cell.fixture.listing.clone().unwrap();
        held.version += 1;
        held.zone_hold = on;
        cell.fixture.listing = Some(held);
    };
    hold(&mut cell, true);
    let held_at = cell.now_us;
    while cell.now_us - held_at < 2 * stuck_us {
        let (_, outcomes) = cell.tick();
        let ended = outcomes.iter().any(|o| o.reclaim == Some(Reclaim::Ended));
        assert!(!ended, "{outcomes:?}");
    }
    assert!(!requested(&cell));
    assert!(cell.volume(1).live(candidate).is_some());
    hold(&mut cell, false);
    cell.run_until(10, requested);
    assert!(cell.volume(1).live(candidate).is_some());
    clean(&cell);
}

#[test]
fn an_ended_entry_of_a_host_attached_to_another_volume_is_released_on_its_own_volumes_listings() {
    let mut config = config_of(8);
    config.attach_stuck_us = 120 * S;
    let mut cell = Cell::with(6, 2, true, config.validate().unwrap());
    cell.run_until(200, |cell| cell.designated());
    let settle = cell.bounds.config().detach_settle_us;
    while cell.now_us < super::observe::START + 2 * settle {
        cell.tick();
    }
    let other = cell.shard(2).owner;
    let roles = cell.shard(1);
    assert!(other != roles.owner && Some(other) != roles.standby);
    record_entry(&cell, other);
    let unlanded = AttachFault::Unknown { attached: false };
    cell.fixture.world.faults.attach.extend([unlanded; 64]);
    cell.lose(cell.shard(2).standby.unwrap().get());
    let seen = run(&mut cell, 300, |cell| gone(cell, 1, other));
    let reclaims = reclaims_of(&seen, other);
    assert_eq!(kinds(&reclaims), [Reclaim::Ended, Reclaim::Gone]);
    let waited = reclaims[1].0 - reclaims[0].0;
    assert!(
        waited >= settle && waited <= settle + 2 * 10 * S,
        "{reclaims:?}"
    );
    let attached = instance(other.get());
    assert!(cell.listed(2).contains(&attached.as_str().to_owned()));
    assert!(!detaches(&cell).contains(&attached));
    let fresh = seen.iter().any(|(at, outcome)| {
        *at > reclaims[0].0
            && matches!(outcome.step, Step::Attach { shard: at, .. } if at == shard(2))
    });
    assert!(
        fresh,
        "an attach step reads volume 2's listing during the release wait"
    );
}

#[test]
fn a_fresh_listing_without_the_ended_instance_leaves_its_release_pair_in_place() {
    let mut config = config_of(8);
    config.attach_stuck_us = 120 * S;
    let mut cell = Cell::with(8, 1, true, config.validate().unwrap());
    cell.run_until(40, |cell| hosts_of(&cell.volume(1)).len() == 2);
    let stuck = hosts_of(&cell.volume(1))[1];
    cell.unenrolled.push(stuck.get());
    let mut seen = run(&mut cell, 100, |cell| !detaches(cell).is_empty());
    let unlanded = [AttachFault::Unlanded; 64];
    cell.fixture.world.faults.attach.extend(unlanded);
    seen.extend(run(&mut cell, 200, |cell| gone(cell, 1, stuck)));
    let reclaims = reclaims_of(&seen, stuck);
    let expected = [Reclaim::Ended, Reclaim::DetachRequested, Reclaim::Gone];
    assert_eq!(kinds(&reclaims), expected);
    let config = cell.bounds.config();
    let (settle, tick) = (config.detach_settle_us, config.tick_us);
    let (detached, released) = (reclaims[1].0, reclaims[2].0);
    assert_eq!(released - detached, tick + 2 * settle, "{reclaims:?}");
    let polls = seen.iter().filter(|(at, outcome)| {
        *at > detached + settle && matches!(outcome.step, Step::Attach { .. })
    });
    assert!(
        polls.count() > 0,
        "an attach step reads the listing afresh during the wait"
    );
}

#[test]
fn a_refused_end_whose_reread_withdraws_the_client_raises_its_alarm() {
    let mut cell = Cell::new(6, 1);
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    let third = attach_third(&mut cell);
    cell.drain(third);
    let survey = cell.planned(ending);
    let end = Step::End {
        shard: shard(1),
        host: third,
    };
    assert_eq!(survey.plan.steps, [end]);
    let mut client = owner(cell.store());
    let read = client.read::<ShardRecord>(Key::Shard(shard(1))).unwrap();
    client
        .designate(&read, Target::of(read.value()), third)
        .unwrap();
    cell.store().schedule(Arm::Pass);
    cell.store().schedule(Arm::Pass);
    cell.store().schedule(Arm::StaleCurrentRead);
    let outcomes = cell.actuate(&survey);
    let refused = outcome_of(&outcomes, ending);
    assert_eq!(
        (refused.verdict, refused.reclaim),
        (Verdict::Alarm(Reason::Withdrawn), None)
    );
    assert!(cell.volume(1).live(third).is_some());
}

#[test]
fn a_named_standby_whose_new_attach_does_not_land_takes_requests_past_the_stuck_bound() {
    let mut config = config_of(8);
    config.attach_stuck_us = 120 * S;
    let (settle_us, stuck_us) = (config.attach_settle_us, config.attach_stuck_us);
    let mut cell = Cell::with(6, 1, true, config.validate().unwrap());
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    let standby = cell.shard(1).standby.unwrap();
    let mut client = owner(cell.store());
    let read = client.read::<VolumeRecord>(Key::Volume(volume(1))).unwrap();
    let mut ended = read.value().clone();
    let seq = ended.live(standby).unwrap();
    let entry = ended.events.iter_mut().find(|event| event.seq == seq);
    entry.unwrap().kind = EventKind::Ended;
    let read = client.replace(&read, ended).unwrap();
    let mut dropped = read.value().clone();
    dropped.pairs.retain(|pair| pair.host != standby);
    client.replace(&read, dropped).unwrap();
    cell.fixture
        .world
        .detach(volume(1), instance(standby.get()));
    let listed = cell.listed(1);
    let settle = cell.bounds.config().detach_settle_us;
    let clean = |at: u64| Listing {
        at,
        instances: &listed,
    };
    let two = [clean(cell.now_us), clean(cell.now_us + settle)];
    let gate = StandbyGate::qualified();
    let mut other = Reconciler::new(reconciler_client(cell.store()));
    let witness = other.detachable(volume(1), standby).unwrap();
    let timing = crate::failover::reconcile::Settle {
        requested: 0,
        settle,
    };
    other.release_attach(&gate, &witness, &two, timing).unwrap();
    assert!(gone(&cell, 1, standby));

    let unlanded = [AttachFault::Unlanded; 6];
    cell.fixture.world.faults.attach.extend(unlanded);
    let calls = cell.attach_calls().len();
    let mut requests = Vec::new();
    let mut seen = Vec::new();
    for _ in 0..60 {
        let at = cell.now_us;
        let (_, outcomes) = cell.tick();
        let sent = outcomes.iter().filter(|outcome| outcome.reply.is_some());
        requests.extend(sent.map(|_| at));
        seen.extend(outcomes);
        if cell.volume(1).enrolled(standby).is_some() {
            break;
        }
    }
    assert!(cell.volume(1).enrolled(standby).is_some(), "{requests:?}");
    assert_eq!(requests.len(), 7, "{requests:?}");
    assert!(requests[6] - requests[0] >= stuck_us, "{requests:?}");
    let gaps = requests.windows(2).map(|pair| pair[1] - pair[0]);
    assert!(gaps.clone().all(|gap| gap == settle_us), "{requests:?}");
    let sent = cell.attach_calls()[calls..].to_vec();
    assert!(sent.iter().all(|(_, id)| *id == instance(standby.get())));
    assert!(
        !seen.iter().any(|outcome| outcome.reclaim.is_some()),
        "{seen:?}"
    );
    assert_eq!(cell.shard(1).standby, Some(standby));
    assert_eq!(slot_host(&cell), standby);
    let (survey, _) = cell.tick();
    assert_eq!(survey.plan.shards[0].state, ShardState::Protected);
    assert!(cell.breaks.is_empty(), "{:?}", cell.breaks);
    assert!(cell.fixture.world.breaks.is_empty());
}

#[test]
fn a_tick_that_fails_to_read_the_shard_keeps_its_volumes_first_clean_listing() {
    use crate::failover::zone_loop::observe::Source;
    use crate::storage::store::StoreError;
    let mut cell = Cell::new(6, 1);
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    let lost = cell.shard(1).standby.unwrap();
    cell.lose(lost.get());
    let mut seen = run(&mut cell, 300, |cell| !cell.zone.clean.is_empty());
    let mut survey = cell.survey();
    survey.plan.steps.clear();
    let view = survey.observation.zone.as_mut().unwrap();
    view.shards[0].records = Err(Source::Store(StoreError::Unavailable));
    cell.actuate(&survey);
    assert!(!cell.zone.clean.is_empty());
    cell.now_us += 10 * S;
    seen.extend(run(&mut cell, 200, |cell| gone(cell, 1, lost)));
    let reclaims = reclaims_of(&seen, lost);
    let config = cell.bounds.config();
    let (settle, tick) = (config.detach_settle_us, config.tick_us);
    let (detached, released) = (reclaims[1].0, reclaims[2].0);
    assert_eq!(released - detached, tick + 2 * settle, "{reclaims:?}");
}

/// A shard that a survey lists with a failed record read keeps its request times, also past the longer of
/// `attach_stuck_us` and `detach_settle_us` after its last request; a survey that omits the shard drops them.
#[test]
fn a_shard_listed_with_a_failed_record_read_keeps_its_request_times() {
    use crate::failover::zone_loop::observe::Source;
    use crate::storage::store::StoreError;
    let mut cell = Cell::new(6, 1);
    cell.run_until(40, |cell| !cell.zone.requests.is_empty());
    cell.survey();
    let requested: Vec<(VolumeId, u32)> = cell.zone.requests.keys().copied().collect();
    let config = cell.bounds.config();
    let last = (cell.zone.requests.values())
        .map(|requested| requested.last_us)
        .max();
    let delisted = config.attach_stuck_us.max(config.detach_settle_us);
    cell.now_us = last.unwrap() + delisted + 10 * S;
    let mut survey = cell.survey();
    survey.plan.steps.clear();
    let view = survey.observation.zone.as_mut().unwrap();
    view.shards[0].records = Err(Source::Store(StoreError::Unavailable));
    cell.actuate(&survey);
    let kept: Vec<(VolumeId, u32)> = cell.zone.requests.keys().copied().collect();
    assert_eq!(kept, requested);
    cell.now_us += 10 * S;
    let mut survey = cell.survey();
    survey.plan.steps.clear();
    survey.observation.zone.as_mut().unwrap().shards.clear();
    cell.actuate(&survey);
    assert!(cell.zone.requests.is_empty());
}

/// A lost standby's cell and host; with `relisted`, the host's entry is gone and its instance lists again.
fn lost_standby(relisted: bool) -> (Cell, Host) {
    let mut cell = Cell::new(6, 1);
    cell.run_until(40, |cell| cell.shard(1).standby.is_some());
    let lost = cell.shard(1).standby.unwrap();
    cell.lose(lost.get());
    if relisted {
        run(&mut cell, 300, |cell| gone(cell, 1, lost));
        cell.fixture.world.attach(volume(1), instance(lost.get()));
    }
    (cell, lost)
}

/// Marks `host`'s latest entry gone and appends a later entry of `host` that binds the same instance and reads
/// `kind`, so the host's latest entry moves to another sequence number.
fn plant_successor(cell: &Cell, host: Host, kind: EventKind) {
    plant_volume(cell, 1, |held| {
        let (seq, _) = held.latest(host).unwrap();
        let moved = held.events.iter_mut().find(|event| event.seq == seq);
        moved.unwrap().kind = EventKind::Gone;
        let next = held.push(EventKind::Attach, host, ERA).unwrap();
        let entry = held.events.iter_mut().find(|event| event.seq == next);
        let entry = entry.unwrap();
        entry.kind = kind;
        entry.instance = Some(instance(host.get()));
    });
}

/// The detach of an ended entry, the detach of a relisted gone entry and the release of an ended entry each act only
/// on the entry the survey judged: when the step's reread finds the host's latest entry at another sequence number,
/// with the same instance, the step waits with `Moved` and makes no request or write.
#[test]
fn a_reclaim_step_whose_reread_finds_a_later_entry_of_the_host_waits_moved() {
    let arms = [
        (false, Reclaim::DetachRequested, EventKind::Ended),
        (true, Reclaim::DetachRequested, EventKind::Gone),
        (false, Reclaim::Gone, EventKind::Ended),
    ];
    for (relisted, reclaim, kind) in arms {
        let (mut cell, lost) = lost_standby(relisted);
        let seen = run(&mut cell, 300, |cell| {
            gone(cell, 1, lost)
                && !cell
                    .listed(1)
                    .contains(&instance(lost.get()).as_str().to_owned())
        });
        let at = reclaims_of(&seen, lost)
            .into_iter()
            .find(|(_, seen)| *seen == reclaim);
        let at = at.unwrap().0;
        let (mut cell, lost) = lost_standby(relisted);
        while cell.now_us < at {
            cell.tick();
        }
        assert_eq!(cell.now_us, at);
        let survey = cell.survey();
        let planned = |step: &&Step| host_of(step) == Some(lost);
        let step = *survey.plan.steps.iter().find(planned).unwrap();
        let control = cell.actuate(&survey);
        let control = control.iter().find(|outcome| outcome.step == step);
        assert_eq!(
            control.and_then(|outcome| outcome.reclaim),
            Some(reclaim),
            "{relisted} {kind:?}"
        );
        let (mut cell, lost) = lost_standby(relisted);
        while cell.now_us < at {
            cell.tick();
        }
        let survey = cell.survey();
        let detaches_before = detaches(&cell).len();
        plant_successor(&cell, lost, kind);
        let planted = cell.volume(1);
        let outcomes = cell.actuate(&survey);
        let outcome = outcomes
            .iter()
            .find(|outcome| outcome.step == step)
            .unwrap();
        assert_eq!(
            outcome.verdict,
            Verdict::Wait(Reason::Moved),
            "{relisted} {kind:?}"
        );
        assert_eq!(outcome.reclaim, None);
        assert_eq!(detaches(&cell).len(), detaches_before);
        assert_eq!(cell.volume(1), planted);
    }
}

#[test]
fn an_end_on_one_shard_is_no_loss_evidence_for_another_shards_slot() {
    let mut cell = Cell::with(6, 2, true, config_of(8).validate().unwrap());
    cell.drain(host(2));
    let recording =
        |step: &Step| matches!(step, Step::RecordAttach { shard: at, .. } if *at == shard(2));
    let planned = cell.planned(recording);
    let held = planned.plan.steps.iter().find_map(|step| match *step {
        Step::RecordAttach {
            shard: at, host, ..
        } if at == shard(2) => Some(host),
        _ => None,
    });
    let held = held.unwrap();
    let roles = cell.shard(1);
    assert!(held != roles.owner && Some(held) != roles.standby);
    assert!(cell.volume(1).live(held).is_none());
    record_entry(&cell, held);
    let other = (1..=6)
        .map(host)
        .find(|&h| h != held && h != cell.shard(2).owner && h != host(2));
    let mut survey = cell.survey();
    let end = Step::End {
        shard: shard(1),
        host: held,
    };
    let reserve = Step::Reserve {
        shard: shard(2),
        host: other.unwrap(),
        target: Target::of(&cell.shard(2)),
    };
    survey.plan.steps = vec![end, reserve];
    let outcomes = cell.actuate(&survey);
    assert_eq!(outcome_of(&outcomes, ending).reclaim, Some(Reclaim::Ended));
    let taken = crate::failover::standbys::Refusal::Taken;
    let refused = outcome_of(&outcomes, reserving);
    assert_eq!(refused.verdict, Verdict::Wait(Reason::Population(taken)));
    let census = census_of(cell.store()).unwrap();
    assert_eq!(census.slot(shard(2)).unwrap().host, held);
}

#[test]
fn a_lost_slot_host_whose_pair_key_refuses_its_end_keeps_its_attach_and_is_replaced() {
    let mut cell = Cell::new(6, 1);
    cell.run_until(40, |cell| hosts_of(&cell.volume(1)).len() == 2);
    let lost = hosts_of(&cell.volume(1))[1];
    cell.unenrolled.push(lost.get());
    cell.lose(lost.get());
    let end = Step::End {
        shard: shard(1),
        host: lost,
    };
    let mut planned = false;
    for _ in 0..200 {
        let survey = cell.survey();
        planned = survey.plan.steps.contains(&end);
        if planned {
            break;
        }
        cell.actuate(&survey);
        cell.now_us += 10 * S;
    }
    assert!(planned, "the plan ends the lost host's attach");
    plant_volume(&cell, 1, |held| {
        let attach = held.live(lost).unwrap();
        let pair = Pair {
            key: attachment_key(attach + 4).unwrap(),
            ..crate::failover::evidence_tests::pair(lost.get() as u8, 1, 1)
        };
        held.pairs.push(RecordedPair {
            host: lost,
            attach,
            pair,
        });
    });
    cell.now_us += 10 * S;
    let mut seen = Vec::new();
    for _ in 0..60 {
        let (_, outcomes) = cell.tick();
        seen.extend(outcomes);
        if cell.shard(1).standby.is_some() {
            break;
        }
    }
    let standby = cell.shard(1).standby;
    assert!(standby.is_some_and(|named| named != lost), "{seen:?}");
    assert!(!seen.iter().any(|outcome| outcome.step == end), "{seen:?}");
    assert!(cell.volume(1).live(lost).is_some());
    clean(&cell);
}

#[test]
fn a_shard_that_leaves_the_directory_keeps_its_detach_time_for_the_settle_time() {
    for lingers in [false, true] {
        let mut config = config_of(8);
        config.attach_stuck_us = 120 * S;
        let (stuck, settle) = (config.attach_stuck_us, config.detach_settle_us);
        assert!(stuck < settle);
        let mut cell = Cell::with(6, 1, true, config.validate().unwrap());
        cell.run_until(40, |cell| cell.shard(1).standby.is_some());
        while cell.now_us < START + settle {
            cell.tick();
        }
        let lost = cell.shard(1).standby.unwrap();
        if lingers {
            let faults = &mut cell.fixture.world.faults.detach;
            faults.push_back(DetachFault::Lingers);
        }
        cell.lose(lost.get());
        let seen = run(&mut cell, 200, |cell| !detaches(cell).is_empty());
        let detached = reclaims_of(&seen, lost).last().unwrap().0;
        cell.now_us = detached + stuck;
        let mut delisted = cell.survey();
        delisted.plan.steps.clear();
        delisted.observation.zone.as_mut().unwrap().shards.clear();
        cell.actuate(&delisted);
        cell.now_us += 10 * S;
        assert!(cell.now_us < detached + settle);
        let survey = cell.survey();
        let outcomes = cell.actuate(&survey);
        let early = match lingers {
            true => outcome_of(&outcomes, detaching),
            false => outcome_of(&outcomes, releasing),
        };
        assert_eq!(
            (early.verdict, early.reclaim),
            (Verdict::Wait(Reason::Settling), None),
            "lingers {lingers}"
        );
        assert_eq!(detaches(&cell).len(), 1, "lingers {lingers}");
        assert!(cell.zone.clean.is_empty(), "lingers {lingers}");
    }
}

#[test]
fn a_kept_listing_is_dropped_when_its_shard_reads_another_volume_or_leaves_the_directory() {
    let kept = || {
        let mut cell = Cell::new(6, 1);
        cell.run_until(40, |cell| cell.shard(1).standby.is_some());
        let lost = cell.shard(1).standby.unwrap();
        cell.lose(lost.get());
        run(&mut cell, 300, |cell| !cell.zone.clean.is_empty());
        cell
    };
    let next = |cell: &mut Cell, change: &dyn Fn(&mut Survey)| {
        let mut survey = cell.survey();
        survey.plan.steps.clear();
        change(&mut survey);
        cell.actuate(&survey);
        cell.zone.clean.len()
    };
    let flipped = |survey: &mut Survey| {
        let view = survey.observation.zone.as_mut().unwrap();
        let records = view.shards[0].records.as_mut().unwrap().as_mut().unwrap();
        records.active.volume = VolumeId::new("vol-0f1").unwrap();
    };
    let delisted = |survey: &mut Survey| {
        survey.observation.zone.as_mut().unwrap().shards.clear();
    };
    assert_eq!(next(&mut kept(), &flipped), 0);
    assert_eq!(next(&mut kept(), &delisted), 0);
}

#[test]
fn the_stuck_clocks_of_a_shard_that_leaves_the_directory_are_dropped_and_outlast_a_failed_read() {
    use crate::failover::zone_loop::observe::Source;
    use crate::storage::store::StoreError;
    let mut cell = Cell::new(6, 1);
    cell.run_until(40, |cell| hosts_of(&cell.volume(1)).len() == 2);
    let waiting = hosts_of(&cell.volume(1))[1];
    cell.unenrolled.push(waiting.get());
    cell.run_until(20, |cell| !cell.zone.attached.is_empty());
    let clocks = |cell: &Cell| (cell.zone.sighted.len(), cell.zone.attached.len());
    assert_eq!(clocks(&cell), (1, 1));
    let mut survey = cell.survey();
    let view = survey.observation.zone.as_mut().unwrap();
    view.shards[0].records = Err(Source::Store(StoreError::Unavailable));
    cell.zone.stuck(&survey.observation, cell.now_us);
    assert_eq!(clocks(&cell), (1, 1));
    survey.observation.zone.as_mut().unwrap().shards.clear();
    cell.zone.stuck(&survey.observation, cell.now_us);
    assert_eq!(clocks(&cell), (0, 0));
}
