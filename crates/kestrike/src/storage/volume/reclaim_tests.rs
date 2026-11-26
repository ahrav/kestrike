//! A continuing owner poll submits the ended-key preempt, a Report follows it, and a later poll whose Report lacks
//! the key returns the pair to drop. EndOrder requires the owner to retain the pair while a Report lists its key,
//! whatever status the preempt returned.

use std::cell::Cell;
use std::rc::Rc;

use super::authority_tests::Clock;
use super::gate_fixture::{Control, Reserving, arena, attach_reserving, own, ticks};
use crate::failover::attachments::InstanceId;
use crate::failover::evidence::{Pair, Registrant};
use crate::failover::identity::{Exhid, Key};
use crate::failover::poll::{Reads, Verdict};
use crate::failover::poll_tests::{listed, owner, serving, volume};
use crate::failover::reconcile::StandbyGate;
use crate::failover::records::{
    AttachmentEvent, ERA, EventKind, Host, RecordedPair, VolumeRecord, VolumeState, attachment_key,
};
use crate::failover::retire::{Retirement, Role, Target, Trigger};
use crate::failover::serving::{Cause, Deposing, Event, Readiness, State};
use crate::storage::device::DeviceStatus;
use crate::storage::device::sim::SimControl;
use crate::storage::test_platform::TestPlatform;
use crate::storage::{ReservationCommand, Storage};

type Dev<'s, 'a> = super::Volume<'s, 'a, TestPlatform, Reserving>;

fn ended_pair(seq: u32) -> Pair {
    Pair {
        exhid: Exhid::new([0x30 + seq as u8; 16]).unwrap(),
        key: attachment_key(seq).unwrap(),
    }
}

fn with_ended(ended: &[u32]) -> VolumeRecord {
    let holder = owner();
    let mut record = volume(VolumeState::Active, holder.host);
    record.pairs = vec![RecordedPair {
        host: holder.host,
        pair: own(),
        attach: 0,
    }];
    for &seq in ended {
        let host = Host::new(holder.host.get() + 100 + u64::from(seq)).unwrap();
        record.events.push(AttachmentEvent {
            seq,
            kind: EventKind::Ended,
            host,
            era: ERA,
            instance: Some(InstanceId::new(&format!("i-0eeeeeeeeeeeeee{seq:x}0")).unwrap()),
        });
        record.pairs.push(RecordedPair {
            host,
            pair: ended_pair(seq),
            attach: seq,
        });
        record.next = seq + 1;
    }
    record
}

fn serving_owner<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    arena: &'a crate::storage::device::BufferArena<TestPlatform>,
    registered: &[Pair],
) -> (Dev<'s, 'a>, SimControl, Control, Rc<Cell<u64>>) {
    let mut authority = super::ServingAuthority::fixture();
    authority.recorded = Some(Box::new([own()]));
    let (mut dev, control, registry) = attach_reserving(storage, arena, authority);
    let time = Rc::new(Cell::new(0));
    dev.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
    ticks(&mut dev, &control, 64);
    let token = dev.serving_token().expect("the gate passed");
    dev.authority_event(Event::Readiness(Readiness::ReadReady { token }));
    for (at, pair) in registered.iter().enumerate() {
        registry.borrow_mut().entries.push(Registrant {
            cntlid: 20 + at as u16,
            holder: false,
            pair: *pair,
        });
    }
    time.set(1_000);
    ticks(&mut dev, &control, 8);
    assert_eq!(dev.authority_state(), State::Serving);
    (dev, control, registry, time)
}

fn poll_and_reclaim(dev: &mut Dev<'_, '_>, record: &VolumeRecord) -> (Verdict, Vec<Pair>) {
    let holder = owner();
    let shard = serving();
    let alone = listed(&[holder.instance.as_str()]);
    let reads = Reads {
        shard: Some(&shard),
        volume: Some(record),
        listed: Some(&alone),
        peers: &[],
    };
    let polled = dev.poll_report().expect("a parsed Report");
    let report = polled.report();
    let verdict = dev.owner_poll(
        &holder,
        Target::of(&shard),
        own(),
        Ok(&report),
        &reads,
        dev.serving_sample(),
    );
    let pairs = dev.owner_reclaim(
        &StandbyGate::qualified(),
        &holder,
        &verdict,
        Ok(&report),
        record,
    );
    (verdict, pairs)
}

fn commands_since(registry: &Control, from: usize) -> Vec<&'static str> {
    registry.borrow().log[from..]
        .iter()
        .map(|command| match command {
            ReservationCommand::Report { .. } => "report",
            ReservationCommand::PreemptEnded(_) => "ended",
            _ => "other",
        })
        .collect()
}

fn listed_keys(dev: &Dev<'_, '_>) -> Vec<Key> {
    let polled = dev.poll_report().expect("a parsed Report");
    polled
        .report()
        .entries
        .iter()
        .map(|entry| entry.pair.key)
        .collect()
}

#[test]
fn a_registered_ended_pair_is_preempted_then_dropped_after_a_report_without_its_key() {
    let (storage, arena) = (super::gate_fixture::storage(), arena());
    let record = with_ended(&[1]);
    let (mut dev, control, registry, time) = serving_owner(&storage, &arena, &[ended_pair(1)]);
    assert!(listed_keys(&dev).contains(&ended_pair(1).key));
    let before = registry.borrow().log.len();
    assert_eq!(
        poll_and_reclaim(&mut dev, &record),
        (Verdict::Continue, Vec::new()),
        "a pair whose key the Report lists stays"
    );
    assert_eq!(commands_since(&registry, before), ["ended"]);
    let Some(ReservationCommand::PreemptEnded(preempt)) = registry.borrow().log.last().copied()
    else {
        panic!("the step submitted the ended preempt");
    };
    assert_eq!(
        (preempt.pair(), preempt.ended()),
        (own(), ended_pair(1).key)
    );
    time.set(1_050);
    ticks(&mut dev, &control, 4);
    assert_eq!(
        commands_since(&registry, before),
        ["ended", "report"],
        "a Report follows the preempt's completion"
    );
    assert!(!listed_keys(&dev).contains(&ended_pair(1).key));
    let before = registry.borrow().log.len();
    assert_eq!(
        poll_and_reclaim(&mut dev, &record),
        (Verdict::Continue, vec![ended_pair(1)]),
        "a Report without the key drops the pair"
    );
    assert_eq!(commands_since(&registry, before), Vec::<&str>::new());
    assert_eq!(dev.authority_report().withdrawal, None);
}

#[test]
fn a_report_submitted_before_the_owner_saw_the_end_drops_nothing() {
    let (storage, arena) = (super::gate_fixture::storage(), arena());
    let record = with_ended(&[1]);
    let (mut dev, control, registry, time) = serving_owner(&storage, &arena, &[]);
    let before = registry.borrow().log.len();
    assert_eq!(
        poll_and_reclaim(&mut dev, &record),
        (Verdict::Continue, Vec::new()),
        "the first poll that shows the end judges a Report submitted before it"
    );
    assert_eq!(
        poll_and_reclaim(&mut dev, &record),
        (Verdict::Continue, Vec::new()),
        "the same Report again"
    );
    time.set(1_100);
    ticks(&mut dev, &control, 4);
    assert_eq!(
        poll_and_reclaim(&mut dev, &record),
        (Verdict::Continue, vec![ended_pair(1)]),
        "a Report submitted after the poll that saw the end"
    );
    assert_eq!(commands_since(&registry, before), ["report"]);
}

/// The no-effect history. `planted` sets the authority's planted defect before the history starts, under which a
/// preempt's success status counts as the receipt that its key left.
fn no_effect(planted: bool) {
    super::authority::reclaim_plant::arm(planted);
    let (storage, arena) = (super::gate_fixture::storage(), arena());
    let record = with_ended(&[1]);
    let (mut dev, control, registry, time) = serving_owner(&storage, &arena, &[ended_pair(1)]);
    registry.borrow_mut().mutation_status = Some(DeviceStatus::Nvme(0));
    let before = registry.borrow().log.len();
    assert_eq!(
        poll_and_reclaim(&mut dev, &record),
        (Verdict::Continue, Vec::new())
    );
    time.set(1_050);
    ticks(&mut dev, &control, 4);
    assert_eq!(commands_since(&registry, before), ["ended", "report"]);
    assert_eq!(
        registry.borrow().mutation_status,
        None,
        "the preempt completed with the success status"
    );
    assert!(
        listed_keys(&dev).contains(&ended_pair(1).key),
        "the success status left the registration"
    );
    let (verdict, pairs) = poll_and_reclaim(&mut dev, &record);
    assert_eq!(
        (verdict, pairs),
        (Verdict::Continue, Vec::new()),
        "the pair stays while a Report lists its key"
    );
    assert_eq!(
        commands_since(&registry, before),
        ["ended", "report", "ended"]
    );
}

#[test]
fn a_preempt_that_succeeds_with_no_effect_keeps_the_pair_and_is_issued_again() {
    no_effect(false);
}

#[test]
#[should_panic(expected = "the pair stays while a Report lists its key")]
fn negative_control_dropping_on_the_preempts_success_status_drops_a_listed_pair() {
    no_effect(true);
}

/// The second history must trigger the same listed-pair assertion even after the first history panics on the same
/// thread.
#[test]
fn a_planted_history_starts_with_no_receipt_of_an_earlier_one() {
    for _ in 0..2 {
        let planted = std::panic::catch_unwind(|| no_effect(true)).unwrap_err();
        let said = planted.downcast_ref::<String>().expect("an assertion");
        assert!(
            said.contains("the pair stays while a Report lists its key"),
            "{said}"
        );
    }
}

#[test]
fn a_conflict_for_a_key_no_registrant_carries_keeps_the_owner_serving() {
    let (storage, arena) = (super::gate_fixture::storage(), arena());
    let record = with_ended(&[1]);
    let (mut dev, control, registry, _) = serving_owner(&storage, &arena, &[ended_pair(1)]);
    let holder = owner();
    let shard = serving();
    let alone = listed(&[holder.instance.as_str()]);
    let reads = Reads {
        shard: Some(&shard),
        volume: Some(&record),
        listed: Some(&alone),
        peers: &[],
    };
    let polled = dev.poll_report().unwrap();
    let report = polled.report();
    let verdict = dev.owner_poll(
        &holder,
        Target::of(&shard),
        own(),
        Ok(&report),
        &reads,
        dev.serving_sample(),
    );
    {
        let mut registry = registry.borrow_mut();
        registry.entries.retain(|entry| entry.pair != ended_pair(1));
        let conflict = crate::failover::evidence::RESERVATION_CONFLICT << 1;
        registry.mutation_status = Some(DeviceStatus::Nvme(conflict));
    }
    let before = registry.borrow().log.len();
    let gate = StandbyGate::qualified();
    assert_eq!(
        dev.owner_reclaim(&gate, &holder, &verdict, Ok(&report), &record),
        Vec::new()
    );
    ticks(&mut dev, &control, 4);
    assert_eq!(commands_since(&registry, before), ["ended", "report"]);
    let authority = dev.authority_report();
    assert_eq!(authority.state, State::Serving);
    assert_eq!((authority.withdrawal, authority.flip), (None, None));
    assert_eq!(listed_keys(&dev), [own().key]);
    assert!(dev.poll_report().unwrap().report().entries[0].holder);
}

/// ENDED-PREEMPT: the device refuses the preempt of an owner whose registration a successor removed, with the
/// Reservation Conflict it also returns for a key no registrant carries. The status carries no verdict in either
/// case. The Report the completion makes due lists the successor holding and no own record, and that Report
/// withdraws the owner.
#[test]
fn the_owner_withdraws_when_the_report_after_a_refused_preempt_shows_a_successor_holding() {
    let (storage, arena) = (super::gate_fixture::storage(), arena());
    let record = with_ended(&[1]);
    let (mut dev, control, registry, _) = serving_owner(&storage, &arena, &[ended_pair(1)]);
    let holder = owner();
    let shard = serving();
    let alone = listed(&[holder.instance.as_str()]);
    let reads = Reads {
        shard: Some(&shard),
        volume: Some(&record),
        listed: Some(&alone),
        peers: &[],
    };
    let polled = dev.poll_report().unwrap();
    let report = polled.report();
    let verdict = dev.owner_poll(
        &holder,
        Target::of(&shard),
        own(),
        Ok(&report),
        &reads,
        dev.serving_sample(),
    );
    assert_eq!(verdict, Verdict::Continue);
    let successor = Pair {
        exhid: Exhid::new([0x66; 16]).unwrap(),
        key: attachment_key(2).unwrap(),
    };
    {
        let mut registry = registry.borrow_mut();
        registry.entries.retain(|entry| entry.pair != own());
        registry.entries.push(Registrant {
            cntlid: 30,
            holder: true,
            pair: successor,
        });
    }
    let before = registry.borrow().log.len();
    let gate = StandbyGate::qualified();
    assert_eq!(
        dev.owner_reclaim(&gate, &holder, &verdict, Ok(&report), &record),
        Vec::new()
    );
    ticks(&mut dev, &control, 4);
    assert_eq!(commands_since(&registry, before), ["ended", "report"]);
    assert!(
        (registry.borrow().entries.iter()).any(|entry| entry.pair == ended_pair(1)),
        "the refused preempt removed no registration"
    );
    let authority = dev.authority_report();
    assert_eq!(authority.state, State::Withdrawn);
    assert!(
        matches!(authority.withdrawal, Some(Cause::Report(_))),
        "the Report that lists the successor holding withdraws the owner: {:?}",
        authority.withdrawal
    );
}

#[test]
fn two_registered_ended_keys_take_one_preempt_per_poll() {
    let (storage, arena) = (super::gate_fixture::storage(), arena());
    let record = with_ended(&[1, 2]);
    let (mut dev, control, registry, time) =
        serving_owner(&storage, &arena, &[ended_pair(2), ended_pair(1)]);
    let before = registry.borrow().log.len();
    registry.borrow_mut().budget = Some(0);
    for _ in 0..2 {
        assert_eq!(
            poll_and_reclaim(&mut dev, &record),
            (Verdict::Continue, Vec::new())
        );
    }
    ticks(&mut dev, &control, 4);
    assert_eq!(
        commands_since(&registry, before),
        ["ended"],
        "no second preempt and no Report while one preempt is outstanding before the next periodic Report"
    );
    registry.borrow_mut().budget = None;
    time.set(1_050);
    ticks(&mut dev, &control, 4);
    assert_eq!(
        commands_since(&registry, before),
        ["ended", "report"],
        "the preempt's completion makes a Report due before the next periodic one at 1,100"
    );
    assert_eq!(listed_keys(&dev), [own().key, ended_pair(2).key]);
    assert_eq!(
        poll_and_reclaim(&mut dev, &record),
        (Verdict::Continue, vec![ended_pair(1)])
    );
    let log = registry.borrow().log.clone();
    let ended: Vec<_> = (log.iter())
        .filter_map(|command| match command {
            ReservationCommand::PreemptEnded(preempt) => Some(preempt.ended()),
            _ => None,
        })
        .collect();
    assert_eq!(ended, [ended_pair(1).key, ended_pair(2).key]);
}

#[test]
fn a_poll_that_does_not_continue_preempts_and_drops_nothing() {
    let (storage, arena) = (super::gate_fixture::storage(), arena());
    let record = with_ended(&[1, 2]);
    let (mut dev, control, registry, time) = serving_owner(&storage, &arena, &[ended_pair(1)]);
    registry.borrow_mut().mutation_status = Some(DeviceStatus::Nvme(0));
    let _ = poll_and_reclaim(&mut dev, &record);
    time.set(1_050);
    ticks(&mut dev, &control, 4);
    let holder = owner();
    let target = Target::of(&serving());
    let polled = dev.poll_report().unwrap();
    let report = polled.report();
    assert!(
        report.submitted_at > 1_000,
        "a Report after the poll that saw both ends"
    );
    assert!(
        report
            .entries
            .iter()
            .any(|entry| entry.pair == ended_pair(1))
    );
    let retire = Retirement::new(holder.volume, Role::Active, target, Trigger::Events).unwrap();
    let gate = StandbyGate::qualified();
    let before = registry.borrow().log.len();
    for verdict in [
        Verdict::Withdraw,
        Verdict::Unobserved,
        Verdict::Deposed,
        Verdict::Retire(retire),
    ] {
        assert_eq!(
            dev.owner_reclaim(&gate, &holder, &verdict, Ok(&report), &record),
            Vec::new(),
            "{verdict:?}"
        );
    }
    assert_eq!(commands_since(&registry, before), Vec::<&str>::new());
    assert_eq!(
        dev.owner_reclaim(&gate, &holder, &Verdict::Continue, Ok(&report), &record),
        vec![ended_pair(2)],
        "control: the same reads on a continuing poll drop the absent pair"
    );
    assert_eq!(
        commands_since(&registry, before),
        ["ended"],
        "control: and preempt the listed key"
    );
}

#[test]
fn a_continuing_poll_by_an_authority_that_may_not_serve_preempts_and_drops_nothing() {
    let (storage, arena) = (super::gate_fixture::storage(), arena());
    let record = with_ended(&[1, 2]);
    let (mut dev, control, registry, time) = serving_owner(&storage, &arena, &[ended_pair(1)]);
    registry.borrow_mut().refuse = Some(crate::storage::device::RefusalReason::QueueFull);
    let _ = poll_and_reclaim(&mut dev, &record);
    registry.borrow_mut().refuse = None;
    time.set(1_100);
    ticks(&mut dev, &control, 4);
    let holder = owner();
    let polled = dev.poll_report().unwrap();
    let report = polled.report();
    assert!(
        report.submitted_at > 1_000,
        "the Report follows the sighting of both ends, so a serving poll drops pair 2 (the queue-refusal sibling)"
    );
    assert!(
        report
            .entries
            .iter()
            .any(|entry| entry.pair == ended_pair(1))
    );
    let gate = StandbyGate::qualified();
    let before = registry.borrow().log.len();
    time.set(1_090);
    assert_eq!(
        dev.owner_reclaim(&gate, &holder, &Verdict::Continue, Ok(&report), &record),
        Vec::new(),
        "a clock reading below the last sample"
    );
    time.set(1_100);
    dev.armed = true;
    assert_eq!(
        dev.owner_reclaim(&gate, &holder, &Verdict::Continue, Ok(&report), &record),
        Vec::new(),
        "an unwound tick loses the device"
    );
    dev.armed = false;
    dev.authority_event(Event::Withdraw(Cause::Planned));
    assert_eq!(dev.authority_state(), State::Withdrawn);
    assert_eq!(
        dev.owner_reclaim(&gate, &holder, &Verdict::Continue, Ok(&report), &record),
        Vec::new(),
        "a withdrawn authority"
    );
    assert_eq!(commands_since(&registry, before), Vec::<&str>::new());
}

#[test]
fn a_first_sighting_at_a_backward_reading_is_not_recorded() {
    let (storage, arena) = (super::gate_fixture::storage(), arena());
    let record = with_ended(&[1]);
    let (mut dev, control, registry, time) = serving_owner(&storage, &arena, &[]);
    time.set(1_100);
    ticks(&mut dev, &control, 4);
    let holder = owner();
    let polled = dev.poll_report().unwrap();
    let report = polled.report();
    assert_eq!(report.submitted_at, 1_100);
    let gate = StandbyGate::qualified();
    let before = registry.borrow().log.len();
    time.set(1_090);
    assert_eq!(
        dev.owner_reclaim(&gate, &holder, &Verdict::Continue, Ok(&report), &record),
        Vec::new(),
        "the backward reading"
    );
    time.set(1_100);
    assert_eq!(
        dev.owner_reclaim(&gate, &holder, &Verdict::Continue, Ok(&report), &record),
        Vec::new(),
        "the first recorded sighting is at 1,100, the Report's own submission"
    );
    time.set(1_200);
    ticks(&mut dev, &control, 4);
    assert_eq!(
        poll_and_reclaim(&mut dev, &record),
        (Verdict::Continue, vec![ended_pair(1)]),
        "control: a later Report drops the pair"
    );
    assert_eq!(commands_since(&registry, before), ["report"]);
}

#[test]
fn each_pair_drops_only_on_a_report_after_its_own_sighting_and_sightings_are_pruned() {
    let (storage, arena) = (super::gate_fixture::storage(), arena());
    let one = with_ended(&[1]);
    let both = with_ended(&[1, 2]);
    let (mut dev, control, _registry, time) = serving_owner(&storage, &arena, &[]);
    let holder = owner();
    let gate = StandbyGate::qualified();
    let early = dev.poll_report().unwrap();
    assert!(early.report().submitted_at <= 1_000);
    let reclaim = |dev: &mut Dev<'_, '_>, polled: &crate::storage::PolledReport, record| {
        let report = polled.report();
        dev.owner_reclaim(&gate, &holder, &Verdict::Continue, Ok(&report), record)
    };
    assert_eq!(
        reclaim(&mut dev, &early, &one),
        Vec::new(),
        "pair 1 seen at 1,000"
    );
    time.set(1_100);
    ticks(&mut dev, &control, 4);
    let middle = dev.poll_report().unwrap();
    assert_eq!(middle.report().submitted_at, 1_100);
    time.set(1_110);
    assert_eq!(
        reclaim(&mut dev, &early, &both),
        Vec::new(),
        "pair 2 seen at 1,110 over the earlier Report"
    );
    assert_eq!(
        reclaim(&mut dev, &middle, &both),
        vec![ended_pair(1)],
        "the Report at 1,100 follows pair 1's sighting and precedes pair 2's"
    );
    time.set(1_200);
    ticks(&mut dev, &control, 4);
    let late = dev.poll_report().unwrap();
    assert_eq!(
        reclaim(&mut dev, &late, &both),
        vec![ended_pair(1), ended_pair(2)]
    );
    let mut dropped = both.clone();
    dropped
        .pairs
        .retain(|recorded| recorded.host == holder.host);
    let _ = reclaim(&mut dev, &late, &dropped);
    assert!(
        dev.authority.ended.is_empty(),
        "a dropped pair's sighting leaves"
    );
}

#[test]
fn a_pair_pinned_to_another_ended_entry_takes_a_new_sighting() {
    use crate::failover::records::AttachmentEvent;
    let (storage, arena) = (super::gate_fixture::storage(), arena());
    let first = with_ended(&[1]);
    let mut moved = with_ended(&[1]);
    let host = Host::new(owner().host.get() + 102).unwrap();
    moved.events.push(AttachmentEvent {
        seq: 2,
        kind: EventKind::Ended,
        host,
        era: ERA,
        instance: Some(InstanceId::new("i-0eeeeeeeeeeeeee20").unwrap()),
    });
    moved.next = 3;
    let pin = moved
        .pairs
        .iter_mut()
        .find(|recorded| recorded.pair == ended_pair(1))
        .unwrap();
    (pin.host, pin.attach) = (host, 2);
    let (mut dev, control, _registry, time) = serving_owner(&storage, &arena, &[]);
    let holder = owner();
    let gate = StandbyGate::qualified();
    let reclaim = |dev: &mut Dev<'_, '_>, record| {
        let polled = dev.poll_report().unwrap();
        let report = polled.report();
        dev.owner_reclaim(&gate, &holder, &Verdict::Continue, Ok(&report), record)
    };
    assert_eq!(reclaim(&mut dev, &first), Vec::new());
    time.set(1_100);
    ticks(&mut dev, &control, 4);
    time.set(1_110);
    assert_eq!(
        reclaim(&mut dev, &moved),
        Vec::new(),
        "the pair's new entry was first seen after the Report"
    );
    time.set(1_200);
    ticks(&mut dev, &control, 4);
    assert_eq!(reclaim(&mut dev, &moved), vec![ended_pair(1)]);
}

#[test]
fn a_preempt_the_queue_refuses_waits_for_the_next_poll() {
    use crate::storage::device::RefusalReason;
    let (storage, arena) = (super::gate_fixture::storage(), arena());
    let record = with_ended(&[1, 2]);
    let (mut dev, control, registry, time) = serving_owner(&storage, &arena, &[ended_pair(1)]);
    let before = registry.borrow().log.len();
    registry.borrow_mut().refuse = Some(RefusalReason::QueueFull);
    assert_eq!(
        poll_and_reclaim(&mut dev, &record),
        (Verdict::Continue, Vec::new())
    );
    assert_eq!(commands_since(&registry, before), Vec::<&str>::new());
    assert!(!dev.is_lost());
    registry.borrow_mut().refuse = None;
    time.set(1_100);
    ticks(&mut dev, &control, 4);
    let before = registry.borrow().log.len();
    assert_eq!(
        poll_and_reclaim(&mut dev, &record),
        (Verdict::Continue, vec![ended_pair(2)])
    );
    assert_eq!(
        commands_since(&registry, before),
        ["ended"],
        "the next poll submits the preempt once"
    );
}

#[test]
fn a_preempt_refused_for_the_devices_loss_loses_the_volume_and_drops_nothing() {
    use crate::storage::device::RefusalReason;
    let (storage, arena) = (super::gate_fixture::storage(), arena());
    let record = with_ended(&[1, 2]);
    let (mut dev, control, registry, time) = serving_owner(&storage, &arena, &[ended_pair(1)]);
    registry.borrow_mut().refuse = Some(RefusalReason::QueueFull);
    let _ = poll_and_reclaim(&mut dev, &record);
    registry.borrow_mut().refuse = None;
    time.set(1_100);
    ticks(&mut dev, &control, 4);
    let before = registry.borrow().log.len();
    registry.borrow_mut().refuse = Some(RefusalReason::DeviceGone);
    assert_eq!(
        poll_and_reclaim(&mut dev, &record),
        (Verdict::Continue, Vec::new()),
        "the absent pair does not drop after the loss"
    );
    assert_eq!(commands_since(&registry, before), Vec::<&str>::new());
    assert!(dev.is_lost());
}

#[test]
fn a_deposing_status_while_a_preempt_is_outstanding_withdraws_and_the_preempt_changes_nothing() {
    use super::bootstrap_tests::submitted;
    use crate::failover::evidence::{PREEMPT_ABORTED, RESERVATION_CONFLICT};
    use crate::storage::device::Operation;
    use crate::storage::device::sim::Fault;
    let (storage, arena) = (super::gate_fixture::storage(), arena());
    let record = with_ended(&[1]);
    let (mut dev, control, registry, _) = serving_owner(&storage, &arena, &[ended_pair(1)]);
    registry.borrow_mut().budget = Some(0);
    let _ = poll_and_reclaim(&mut dev, &record);
    assert!(matches!(
        registry.borrow().log.last(),
        Some(ReservationCommand::PreemptEnded(_))
    ));
    control.set_halted(true);
    let reads = submitted(&control, Operation::Read).len();
    let _ = super::gate_fixture::read_record(&mut dev);
    let read = submitted(&control, Operation::Read)[reads].0;
    control.fault(
        read,
        Fault::Status(DeviceStatus::Nvme(RESERVATION_CONFLICT << 1)),
    );
    control.set_halted(false);
    ticks(&mut dev, &control, 2);
    let withdrawn = dev.authority_report();
    assert_eq!(
        (withdrawn.state, withdrawn.withdrawal, withdrawn.flip),
        (
            State::Withdrawn,
            Some(Cause::Status(Deposing::Conflict)),
            None
        )
    );
    let reports = registry.borrow().reports();
    {
        let mut registry = registry.borrow_mut();
        registry.mutation_status = Some(DeviceStatus::Nvme(PREEMPT_ABORTED << 1));
        registry.budget = None;
    }
    ticks(&mut dev, &control, 4);
    assert_eq!(
        registry.borrow().mutation_status,
        None,
        "the preempt completed with Preempt Aborted"
    );
    let after = dev.authority_report();
    assert_eq!(
        (after.state, after.withdrawal, after.flip, after.refusal),
        (
            withdrawn.state,
            withdrawn.withdrawal,
            withdrawn.flip,
            withdrawn.refusal
        ),
        "the preempt's completion changes nothing"
    );
    assert!(registry.borrow().reports() > reports);
}

#[test]
fn a_late_register_under_a_dropped_ended_key_is_preempted_with_no_drop() {
    let (storage, arena) = (super::gate_fixture::storage(), arena());
    let mut record = with_ended(&[1]);
    record
        .pairs
        .retain(|recorded| recorded.pair != ended_pair(1));
    let late = Pair {
        exhid: Exhid::new([0x77; 16]).unwrap(),
        ..ended_pair(1)
    };
    let (mut dev, control, registry, _) = serving_owner(&storage, &arena, &[late]);
    let before = registry.borrow().log.len();
    assert_eq!(
        poll_and_reclaim(&mut dev, &record),
        (Verdict::Continue, Vec::new())
    );
    ticks(&mut dev, &control, 4);
    assert_eq!(commands_since(&registry, before), ["ended", "report"]);
    assert_eq!(listed_keys(&dev), [own().key]);
    let authority = dev.authority_report();
    assert_eq!(
        (authority.state, authority.withdrawal, authority.flip),
        (State::Serving, None, None)
    );
}

#[test]
fn a_record_of_another_volume_preempts_and_drops_nothing() {
    let (storage, arena) = (super::gate_fixture::storage(), arena());
    let record = with_ended(&[1, 2]);
    let (mut dev, control, registry, time) = serving_owner(&storage, &arena, &[ended_pair(1)]);
    let other = VolumeRecord {
        volume: crate::failover::records::VolumeId::new("vol-0c").unwrap(),
        ..record.clone()
    };
    let holder = owner();
    assert_ne!(other.volume, holder.volume);
    let gate = StandbyGate::qualified();
    let before = registry.borrow().log.len();
    for round in 0..2 {
        time.set(1_100 + 100 * round);
        ticks(&mut dev, &control, 4);
        let polled = dev.poll_report().unwrap();
        let report = polled.report();
        assert_eq!(
            dev.owner_reclaim(&gate, &holder, &Verdict::Continue, Ok(&report), &other),
            Vec::new(),
            "round {round}"
        );
    }
    assert!(
        commands_since(&registry, before)
            .iter()
            .all(|command| *command == "report"),
        "no preempt for another volume's ended key"
    );
    time.set(1_300);
    ticks(&mut dev, &control, 4);
    let polled = dev.poll_report().unwrap();
    let report = polled.report();
    assert_eq!(
        dev.owner_reclaim(&gate, &holder, &Verdict::Continue, Ok(&report), &record),
        Vec::new(),
        "the first sighting of the owner's own record follows the other volume's polls"
    );
    assert_eq!(
        commands_since(&registry, before).last(),
        Some(&"ended"),
        "the owner's own record names the registered ended key"
    );
}

#[test]
fn a_continuing_poll_before_the_fencing_boundary_preempts_and_drops_nothing() {
    let (storage, arena) = (super::gate_fixture::storage(), arena());
    let record = with_ended(&[1, 2]);
    let mut authority = super::ServingAuthority::fixture();
    authority.recorded = Some(Box::new([own()]));
    let (mut dev, _control, registry) = attach_reserving(&storage, &arena, authority);
    let time = Rc::new(Cell::new(0));
    dev.set_serving_clock(Box::new(Clock(Rc::clone(&time))));
    assert!(dev.serving_token().is_some() && dev.metadata.fenced.is_none());
    let entries = [
        Registrant {
            cntlid: 10,
            holder: true,
            pair: own(),
        },
        Registrant {
            cntlid: 20,
            holder: false,
            pair: ended_pair(1),
        },
    ];
    let holder = owner();
    let gate = StandbyGate::qualified();
    let before = registry.borrow().log.len();
    for submitted_at in [0, 2_000] {
        let report = crate::failover::evidence::Report {
            submitted_at,
            ..crate::failover::poll_tests::report_of(&entries)
        };
        time.set(1_000);
        assert_eq!(
            dev.owner_reclaim(&gate, &holder, &Verdict::Continue, Ok(&report), &record),
            Vec::new(),
            "a Report submitted at {submitted_at}"
        );
    }
    assert_eq!(commands_since(&registry, before), Vec::<&str>::new());
}

#[test]
fn a_continuing_poll_on_a_closed_volume_preempts_and_drops_nothing() {
    let (storage, arena) = (super::gate_fixture::storage(), arena());
    let record = with_ended(&[1, 2]);
    let (mut dev, control, registry, time) = serving_owner(&storage, &arena, &[ended_pair(1)]);
    registry.borrow_mut().refuse = Some(crate::storage::device::RefusalReason::QueueFull);
    let _ = poll_and_reclaim(&mut dev, &record);
    registry.borrow_mut().refuse = None;
    time.set(1_100);
    ticks(&mut dev, &control, 4);
    let polled = dev.poll_report().unwrap();
    let report = polled.report();
    assert!(
        report.submitted_at > 1_000
            && (report.entries.iter()).any(|entry| entry.pair == ended_pair(1)),
        "the Report follows the sighting of both ends and lists key 1, so an open volume preempts key 1 and drops pair 2"
    );
    let _ = dev.close();
    assert!(
        dev.serving_token().is_some() && !dev.is_lost() && dev.metadata.fenced.is_some(),
        "the closed volume keeps its token, its device and its fencing boundary"
    );
    assert!(
        dev.admit_authority(
            crate::failover::serving::Operation::Read,
            dev.serving_token()
        )
        .is_ok(),
        "the serving machine admits the read"
    );
    assert_eq!(dev.admission(), Err(super::ReadRefusal::Closed));
    let before = registry.borrow().log.len();
    assert_eq!(
        dev.owner_reclaim(
            &StandbyGate::qualified(),
            &owner(),
            &Verdict::Continue,
            Ok(&report),
            &record
        ),
        Vec::new(),
        "a closed volume"
    );
    assert_eq!(commands_since(&registry, before), Vec::<&str>::new());
}
