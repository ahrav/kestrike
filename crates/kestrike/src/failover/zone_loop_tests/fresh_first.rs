//! FRESH-FIRST: on a full census, a refused fresh-host need takes the slot of an entry that `Census::releases` drops
//! ahead of that shard's re-reservation, and never the entry of a live named standby.

use std::cell::RefCell;
use std::rc::Rc;

use crate::failover::reconcile::StandbyGate;
use crate::failover::records::{Host, ShardRecord};
use crate::failover::retire::Target;
use crate::failover::standbys::{Census, Need};
use crate::failover::zone_loop::actuate::{Outcome, Reason, Verdict};
use crate::failover::zone_loop::config::ZoneBounds;
use crate::failover::zone_loop::evidence::HostEvidence;
use crate::failover::zone_loop::plan::{Step, Survey};
use crate::failover::zone_loop::status::{Blocker, EnrollPhase, ShardState};
use crate::storage::store::Key;
use crate::storage::store::sim::Arm;

use super::actuate::{
    After, Cell, Faults, Hook, Loop, census_of, hosts_of, order_breaks, owner, shard,
};
use super::config::config_of;
use super::directory::instance;
use super::observe::{S, ZONE, owner_of, volume};
use super::survey::state_of;
use super::world::World;

const HOSTS: u64 = 12;
const SHARDS: u32 = 6;
const CAP: usize = 5;
/// The shard outside the census, whose owner is lost with no standby named.
const OUTSIDE: u32 = 6;
/// The shard whose owner is lost in the same failure and whose standby takes it over.
const TAKEN: u32 = 4;

fn capped() -> ZoneBounds {
    let mut config = config_of(SHARDS as usize);
    config.population_cap = CAP;
    config.validate().unwrap()
}

/// Every committed census version lists at most `CAP` shards.
fn census_versions_within_cap(cell: &Cell) -> Result<(), String> {
    let store = cell.store().0.borrow();
    for item in store.versions(&Key::Standbys(ZONE)) {
        let census = Census::decode_owned(item.value.clone()).unwrap();
        if census.len() > CAP {
            return Err(format!("a census version lists {} shards", census.len()));
        }
    }
    Ok(())
}

/// Shards 1 to 5 name standbys and fill the census; shard 6 names none.
fn designated_but_outside() -> Cell {
    designated_under(capped())
}

fn designated_under(bounds: ZoneBounds) -> Cell {
    let mut cell = Cell::with(HOSTS, SHARDS, true, bounds);
    cell.run_until(240, |cell| {
        (1..OUTSIDE).all(|n| cell.shard(n).standby.is_some())
    });
    for _ in 0..4 {
        cell.tick();
    }
    assert_eq!(cell.shard(OUTSIDE).standby, None);
    assert_eq!(census_of(cell.store()).unwrap().len(), CAP);
    cell
}

fn plan_of(survey: &Survey, number: u32) -> (ShardState, Option<Blocker>) {
    state_of(&survey.plan, number)
}

fn verdict_of(survey: &Survey, host: Host) -> HostEvidence {
    let view = survey.observation.zone.as_ref().unwrap();
    let found = view.hosts.iter().find(|held| held.entry.host == host);
    found.map_or(HostEvidence::Unknown, |held| held.verdict)
}

/// Loses `hosts` and runs `tick` until its survey reads each of them lost.
fn lose_under(cell: &mut Cell, hosts: &[Host], mut tick: impl FnMut(&mut Cell) -> Survey) {
    for host in hosts {
        cell.lose(host.get());
    }
    for _ in 0..60 {
        let survey = tick(cell);
        if hosts
            .iter()
            .all(|&host| verdict_of(&survey, host) == HostEvidence::Lost)
        {
            return;
        }
    }
    panic!("the loop never read {hosts:?} lost");
}

fn lose_and_wait(cell: &mut Cell, hosts: &[Host]) {
    lose_under(cell, hosts, |cell| cell.tick().0);
}

/// Shard 4's named standby takes it over, and the census entry names the new owner at the earlier target.
fn take_over(cell: &Cell) -> Host {
    let mut client = owner(cell.store());
    let read = client
        .read::<ShardRecord>(Key::Shard(shard(TAKEN)))
        .unwrap();
    let successor = read.value().standby.unwrap();
    client
        .take_over(&read, Target::of(read.value()), successor)
        .unwrap();
    let record = cell.shard(TAKEN);
    let entry = census_of(cell.store()).unwrap().slot(shard(TAKEN)).unwrap();
    assert_eq!((record.owner, record.standby), (successor, None));
    assert!(entry.host == successor && entry.target != Target::of(&record));
    successor
}

fn reserves(survey: &Survey, number: u32) -> bool {
    let reserve =
        |step: &Step| matches!(step, Step::Reserve { shard: at, .. } if *at == shard(number));
    survey.plan.steps.iter().any(reserve)
}

fn releases(survey: &Survey, number: u32) -> bool {
    let release =
        |step: &Step| matches!(step, Step::Release { shard: at, .. } if *at == shard(number));
    survey.plan.steps.iter().any(release)
}

/// The verdict of the first outcome whose step `wanted` selects.
fn verdict_where(outcomes: &[Outcome], wanted: impl Fn(&Step) -> bool) -> Verdict {
    outcomes
        .iter()
        .find(|outcome| wanted(&outcome.step))
        .unwrap()
        .verdict
}

/// Whether the plan withholds shard 4's re-reservation and releases its entry.
fn withheld(survey: &Survey) -> bool {
    let refused = matches!(
        plan_of(survey, TAKEN),
        (
            ShardState::Enrolling {
                need: Need::Standby,
                phase: EnrollPhase::Unreserved,
                ..
            },
            Some(Blocker::CensusFull)
        )
    );
    refused && releases(survey, TAKEN) && !reserves(survey, TAKEN)
}

fn census_full(survey: &Survey, number: u32) -> bool {
    plan_of(survey, number) == (ShardState::NoCandidate, Some(Blocker::CensusFull))
}

fn census_lists(cell: &Cell, number: u32) -> Option<Host> {
    let census = census_of(cell.store())?;
    census.slot(shard(number)).map(|slot| slot.host)
}

/// Shard 6 names a fresh host its entry lists, shard 4 serves under `successor` with no standby, no entry and
/// `CensusFull`, the census lists `CAP` shards, and no committed version lists more.
fn fresh_first_converged(cell: &Cell, survey: &Survey, successor: Host) -> Result<(), String> {
    let named = cell
        .shard(OUTSIDE)
        .standby
        .ok_or("shard 6 names no standby")?;
    if census_lists(cell, OUTSIDE) != Some(named) {
        return Err(format!(
            "shard 6 names {named:?}, its entry {:?}",
            census_lists(cell, OUTSIDE)
        ));
    }
    let taken = cell.shard(TAKEN);
    if (taken.owner, taken.standby) != (successor, None) || census_lists(cell, TAKEN).is_some() {
        return Err(format!(
            "shard 4 {taken:?}, entry {:?}",
            census_lists(cell, TAKEN)
        ));
    }
    if !census_full(survey, TAKEN) {
        return Err(format!("shard 4 plans {:?}", plan_of(survey, TAKEN)));
    }
    let len = census_of(cell.store()).map_or(0, |census| census.len());
    if len != CAP {
        return Err(format!("census of {len}"));
    }
    census_versions_within_cap(cell)
}

/// Shard 6's fresh host holds the one new attach entry of its volume and its listing's one new attachment, shard 6's
/// record took one write, shard 4's none, and no attach request of shard 6's volume repeats one before it.
fn designated_once(cell: &Cell, before: &Before) -> Result<(), String> {
    let named = cell
        .shard(OUTSIDE)
        .standby
        .ok_or("shard 6 names no standby")?;
    let hosts = hosts_of(&cell.volume(OUTSIDE));
    if hosts != [owner_of(OUTSIDE, HOSTS), named] {
        return Err(format!("shard 6 entries {hosts:?}"));
    }
    let listed = cell.listed(OUTSIDE);
    let ours = listed
        .iter()
        .filter(|id| *id == instance(named.get()).as_str())
        .count();
    if ours != 1 {
        return Err(format!("shard 6 listing {listed:?}"));
    }
    let commits = |number| (cell.store().0.borrow()).commit_count(&Key::Shard(shard(number)));
    if (commits(OUTSIDE), commits(TAKEN)) != (before.outside + 1, before.taken) {
        return Err(format!(
            "shard record commits {} and {}",
            commits(OUTSIDE),
            commits(TAKEN)
        ));
    }
    let calls = cell.attach_calls();
    let ours: Vec<_> = calls[before.calls..]
        .iter()
        .filter(|(at, _)| *at == volume(OUTSIDE))
        .collect();
    let distinct: std::collections::BTreeSet<_> = ours.iter().collect();
    if distinct.len() != ours.len() {
        return Err(format!("repeated attach requests {ours:?}"));
    }
    Ok(())
}

/// Shard record commit counts of shards 6 and 4 and the attach requests made, before a run.
struct Before {
    outside: usize,
    taken: usize,
    calls: usize,
}

fn before(cell: &Cell) -> Before {
    let commits = |number| (cell.store().0.borrow()).commit_count(&Key::Shard(shard(number)));
    Before {
        outside: commits(OUTSIDE),
        taken: commits(TAKEN),
        calls: cell.attach_calls().len(),
    }
}

/// On a full census a fresh-host need takes the slot of a taken-over shard's stale entry. Shard 6's owner is lost with
/// no standby, so its fresh need is refused `CensusFull`. Shard 4's owner is lost in the same failure and its standby
/// takes it over, which leaves shard 4's entry at the earlier target naming the new owner. The loop withholds shard
/// 4's re-reservation once, releases that entry, and admits, records, attaches and designates shard 6's fresh host,
/// with one attach entry, one listed attachment and one shard record write. Shard 4 then serves with `CensusFull`
/// for its standby need, with no flip, no provider create and no shard record write, so no designation commits under
/// the released entry. Control: with the re-reservation restored in place of the release, shard 4 keeps the slot and
/// shard 6 stays refused.
#[test]
fn a_refused_fresh_need_takes_the_slot_of_a_taken_over_shards_stale_entry() {
    let mut cell = designated_but_outside();
    lose_and_wait(
        &mut cell,
        &[owner_of(TAKEN, HOSTS), owner_of(OUTSIDE, HOSTS)],
    );
    let successor = take_over(&cell);
    let counted = before(&cell);
    let before = cell.snapshot();
    let commits = |cell: &Cell| (cell.store().0.borrow()).commit_count(&Key::Shard(shard(TAKEN)));
    let taken_commits = commits(&cell);
    let mut withholds = 0;
    let mut last = None;
    for _ in 0..120 {
        let (survey, _) = cell.tick();
        withholds += usize::from(withheld(&survey));
        last = Some(survey);
        if cell.shard(OUTSIDE).standby.is_some() {
            break;
        }
    }
    for _ in 0..20 {
        last = Some(cell.tick().0);
    }
    assert_eq!(withholds, 1);
    fresh_first_converged(&cell, &last.unwrap(), successor).unwrap();
    designated_once(&cell, &counted).unwrap();
    assert_eq!(commits(&cell), taken_commits);
    let held = cell.store().0.borrow();
    assert!(held.flips.is_empty());
    assert_eq!(held.commit_count(&Key::Replacement(shard(TAKEN))), 0);
    drop(held);
    let (was, _) = &before.shards[TAKEN as usize - 1];
    let now = cell.shard(TAKEN);
    assert_eq!((now.generation, now.active), (was.generation, was.active));
    cell.clean();

    let mut control = designated_but_outside();
    control.withholds = false;
    lose_and_wait(
        &mut control,
        &[owner_of(TAKEN, HOSTS), owner_of(OUTSIDE, HOSTS)],
    );
    take_over(&control);
    let mut withholds = 0;
    for _ in 0..140 {
        withholds += usize::from(withheld(&control.tick().0));
    }
    let survey = control.tick().0;
    assert!(withholds > 0);
    assert_eq!(
        control.shard(OUTSIDE).standby,
        None,
        "control: shard 6 takes a host"
    );
    assert!(
        census_full(&survey, OUTSIDE),
        "{:?}",
        plan_of(&survey, OUTSIDE)
    );
    assert!(control.shard(TAKEN).standby.is_some());
    census_versions_within_cap(&control).unwrap();
}

/// A host that is live, owns no shard and holds no role or entry of shards 1 and 6.
fn bystander(cell: &Cell) -> Host {
    let roles: Vec<Host> = [1, OUTSIDE]
        .iter()
        .flat_map(|&n| {
            let record = cell.shard(n);
            [Some(record.owner), record.standby, census_lists(cell, n)]
        })
        .flatten()
        .collect();
    let owners: Vec<Host> = (1..=SHARDS).map(|n| owner_of(n, HOSTS)).collect();
    let found = (1..=HOSTS).map(crate::failover::sim::host);
    let mut free = found.filter(|host| !roles.contains(host) && !owners.contains(host));
    free.next().unwrap()
}

/// No eviction: when every listed entry names a live standby, shard 6's fresh need stays refused `CensusFull`, no
/// release is planned and the census keeps every entry. Control: steps a planner would add to take a live named
/// standby's entry fail at the census, the release of shard 1's entry by `Census::released` (the record names a
/// standby), its move to another host by the one-host-per-slot check (`Taken`), and shard 6's reservation by the cap
/// check (`Full`), and the census stays as it was.
#[test]
fn a_fresh_need_takes_no_entry_of_a_live_named_standby() {
    use crate::failover::standbys::Refusal;

    let mut cell = designated_but_outside();
    let outside = owner_of(OUTSIDE, HOSTS);
    assert!((1..OUTSIDE).all(|n| cell.shard(n).standby != Some(outside)));
    let census = census_of(cell.store()).unwrap();
    lose_and_wait(&mut cell, &[outside]);
    for _ in 0..60 {
        let (survey, _) = cell.tick();
        assert!(
            census_full(&survey, OUTSIDE),
            "{:?}",
            plan_of(&survey, OUTSIDE)
        );
        let releasing = (survey.plan.steps.iter()).any(|step| matches!(step, Step::Release { .. }));
        assert!(!releasing, "{:?}", survey.plan.steps);
    }
    assert_eq!(census_of(cell.store()), Some(census.clone()));
    assert_eq!(cell.shard(OUTSIDE).standby, None);
    cell.clean();

    let other = bystander(&cell);
    let mut client = owner(cell.store());
    let read = client.read::<ShardRecord>(Key::Shard(shard(1))).unwrap();
    client.bump(&read).unwrap();
    let census = census_of(cell.store()).unwrap();
    let first = cell.shard(1);
    let entry = census.slot(shard(1)).unwrap();
    assert!(first.standby == Some(entry.host) && entry.target != Target::of(&first));
    let mut survey = cell.survey();
    survey.plan.steps.clear();
    let planted = [
        Step::Reserve {
            shard: shard(1),
            host: other,
            target: Target::of(&first),
        },
        Step::Release {
            shard: shard(1),
            host: entry.host,
            target: entry.target,
        },
        Step::Reserve {
            shard: shard(OUTSIDE),
            host: other,
            target: Target::of(&cell.shard(OUTSIDE)),
        },
    ];
    survey.plan.steps.extend(planted);
    let outcomes = cell.actuate(&survey);
    let verdict = |step: Step| {
        outcomes
            .iter()
            .find(|outcome| outcome.step == step)
            .unwrap()
            .verdict
    };
    assert_eq!(
        verdict(planted[0]),
        Verdict::Wait(Reason::Population(Refusal::Taken))
    );
    assert_eq!(verdict(planted[1]), Verdict::Wait(Reason::Moved));
    assert_eq!(
        verdict(planted[2]),
        Verdict::Wait(Reason::Population(Refusal::Full))
    );
    assert_eq!(census_of(cell.store()), Some(census));
    census_versions_within_cap(&cell).unwrap();
}

/// A fresh need no place frees for takes no in-flight unit from a standby replacement. With one in-flight unit, shard
/// 6's owner is lost with no standby and every census entry names a standby, so no entry is releasable; the named
/// standby of another shard is lost in the same failure. The loop replaces that standby on its shard's entry, with
/// shard 6 refused `CensusFull` on every tick, no release planned and no committed census above the cap.
#[test]
fn a_fresh_need_no_place_frees_for_leaves_a_lost_standbys_replacement_its_unit() {
    let mut config = config_of(SHARDS as usize);
    config.population_cap = CAP;
    config.enroll_inflight_max = 1;
    let mut cell = designated_under(config.validate().unwrap());
    let outside = owner_of(OUTSIDE, HOSTS);
    let owners: Vec<Host> = (1..=SHARDS).map(|n| owner_of(n, HOSTS)).collect();
    let named = |cell: &Cell, n: u32| cell.shard(n).standby.unwrap();
    let bare = (1..OUTSIDE).find(|&n| !owners.contains(&named(&cell, n)));
    let bare = bare.expect("a named standby that owns no shard");
    let lost = named(&cell, bare);
    lose_and_wait(&mut cell, &[outside, lost]);
    let mut replaced = false;
    for _ in 0..80 {
        let (survey, _) = cell.tick();
        assert!(
            census_full(&survey, OUTSIDE),
            "{:?}",
            plan_of(&survey, OUTSIDE)
        );
        let releasing = (survey.plan.steps.iter()).any(|step| matches!(step, Step::Release { .. }));
        assert!(!releasing, "{:?}", survey.plan.steps);
        replaced = cell.shard(bare).standby.is_some_and(|host| host != lost);
        if replaced {
            break;
        }
    }
    assert!(replaced, "shard {bare} keeps its lost standby {lost:?}");
    assert_eq!(census_lists(&cell, bare), cell.shard(bare).standby);
    assert_eq!(cell.shard(OUTSIDE).standby, None);
    census_versions_within_cap(&cell).unwrap();
    cell.clean();
}

/// A `Standby` contender gets no slot: shard 6, whose owner serves, wants a standby while shard 4's re-reservation
/// lands on its entry after a takeover, and shard 4 keeps the slot with no withhold. The loop's order for a standby
/// contender is the re-reservation first.
#[test]
fn a_standby_contender_leaves_a_taken_over_shard_its_slot() {
    let mut cell = designated_but_outside();
    lose_and_wait(&mut cell, &[owner_of(TAKEN, HOSTS)]);
    let successor = take_over(&cell);
    for _ in 0..80 {
        let (survey, _) = cell.tick();
        assert!(!withheld(&survey));
        assert!(
            census_full(&survey, OUTSIDE),
            "{:?}",
            plan_of(&survey, OUTSIDE)
        );
    }
    let named = cell.shard(TAKEN).standby.unwrap();
    assert_ne!(named, successor);
    assert_eq!(census_lists(&cell, TAKEN), Some(named));
    assert_eq!(cell.shard(OUTSIDE).standby, None);
    census_versions_within_cap(&cell).unwrap();
    cell.clean();
}

/// FRESH-FIRST's reach: a fresh need that appears after shard 4's re-reservation was admitted on an earlier tick
/// stays refused `CensusFull`, and shard 4's entry, written for its new standby, stays. The reservation a loop has
/// written is kept.
#[test]
fn a_fresh_need_after_an_admitted_re_reservation_stays_refused() {
    let mut cell = designated_but_outside();
    lose_and_wait(&mut cell, &[owner_of(TAKEN, HOSTS)]);
    take_over(&cell);
    let mut admitted = false;
    for _ in 0..60 {
        let (survey, _) = cell.tick();
        admitted |= reserves(&survey, TAKEN);
        if admitted {
            break;
        }
    }
    assert!(admitted);
    let entry = census_of(cell.store()).unwrap().slot(shard(TAKEN)).unwrap();
    assert_eq!(entry.target, Target::of(&cell.shard(TAKEN)));
    lose_and_wait(&mut cell, &[owner_of(OUTSIDE, HOSTS)]);
    for _ in 0..100 {
        let (survey, _) = cell.tick();
        assert!(!withheld(&survey));
        assert!(
            census_full(&survey, OUTSIDE),
            "{:?}",
            plan_of(&survey, OUTSIDE)
        );
    }
    assert_eq!(cell.shard(OUTSIDE).standby, None);
    let kept = census_of(cell.store()).unwrap().slot(shard(TAKEN)).unwrap();
    assert_eq!(kept, entry);
    assert_eq!(cell.shard(TAKEN).standby, Some(entry.host));
    census_versions_within_cap(&cell).unwrap();
    cell.clean();
}

/// A second loop over `cell`'s store and world, with no faults of its own.
fn second_loop(cell: &Cell) -> Rc<RefCell<Loop>> {
    let (quiet, hook, after) = (Faults::default(), Hook::default(), After::default());
    Rc::new(RefCell::new(Cell::open(
        &cell.fixture,
        &quiet,
        &hook,
        &after,
        &cell.bounds,
    )))
}

fn second_survey(cell: &mut Cell, second: &RefCell<Loop>, now_us: u64) -> Survey {
    let directory = Ok(cell.fixture.directory());
    (second.borrow_mut()).survey(directory, &mut cell.fixture.world, now_us)
}

fn second_actuate(
    cell: &mut Cell,
    second: &RefCell<Loop>,
    survey: &Survey,
    now_us: u64,
) -> Vec<Outcome> {
    let gate = StandbyGate::qualified();
    let before = cell.snapshot();
    let world = &mut cell.fixture.world;
    let done = (second.borrow_mut()).actuate(&gate, survey, now_us, world);
    cell.breaks.extend(order_breaks(&before, &cell.snapshot()));
    done.unwrap()
}

/// One tick of `cell`'s loop, then one of `second` five seconds later; returns `cell`'s survey.
fn both_tick(cell: &mut Cell, second: &RefCell<Loop>) -> Survey {
    let (survey, _) = cell.tick();
    let now_us = cell.now_us - 5 * S;
    let theirs = second_survey(cell, second, now_us);
    second_actuate(cell, second, &theirs, now_us);
    survey
}

fn lose_under_both(cell: &mut Cell, second: &RefCell<Loop>, hosts: &[Host]) {
    lose_under(cell, hosts, |cell| both_tick(cell, second));
}

/// Two loops, both through warm-up, over the designated zone.
fn two_loops() -> (Cell, Rc<RefCell<Loop>>) {
    let mut cell = designated_but_outside();
    let second = second_loop(&cell);
    for _ in 0..20 {
        both_tick(&mut cell, &second);
    }
    (cell, second)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Order {
    /// The lagging loop's re-reservation commits before the other loop's release.
    ReservationFirst,
    /// The release commits before the lagging loop's census read.
    ReleaseFirst,
    /// The release commits between the lagging loop's census read and its census write.
    ReleaseBetween,
}

/// The end state of an order in which shard 4 keeps its slot: shard 4 names a standby its entry lists at its
/// current target, and shard 6 names none and reads `CensusFull`.
fn slot_kept(cell: &Cell, survey: &Survey) -> Result<(), String> {
    let named = cell
        .shard(TAKEN)
        .standby
        .ok_or("shard 4 names no standby")?;
    let entry = census_of(cell.store()).and_then(|census| census.slot(shard(TAKEN)));
    if entry.map(|entry| (entry.host, entry.target))
        != Some((named, Target::of(&cell.shard(TAKEN))))
    {
        return Err(format!("shard 4 names {named:?}, its entry {entry:?}"));
    }
    if cell.shard(OUTSIDE).standby.is_some() || !census_full(survey, OUTSIDE) {
        return Err(format!(
            "shard 6 {:?} plans {:?}",
            cell.shard(OUTSIDE),
            plan_of(survey, OUTSIDE)
        ));
    }
    census_versions_within_cap(cell)
}

/// Two loops race at the census. Shard 6's owner is lost after shard 4's takeover. On the race tick the first loop
/// surveys before its silence bound passes, reads shard 6's owner not yet lost, sees no fresh need and plans shard
/// 4's re-reservation; the second loop surveys nine seconds later, reads the owner lost and plans the withhold and the
/// release. Neither loop actuates the surveys before that tick. The end state is the one the write order selects.
/// With the re-reservation first, the release waits `Moved`; with the release before the lagging census read, both
/// writes advance and the re-reservation finds a free place; in both, shard 4 keeps its slot and shard 6 stays
/// `CensusFull`. With the release between the lagging census read and its write, that write loses its condition and
/// shard 6 takes the slot. Each order converges, no committed census lists more than the cap, and the last 40 ticks
/// change no census or shard record.
#[test]
fn two_loops_racing_a_re_reservation_against_a_release_end_as_the_winning_write_selects() {
    for order in [
        Order::ReservationFirst,
        Order::ReleaseFirst,
        Order::ReleaseBetween,
    ] {
        let (mut cell, second) = two_loops();
        lose_under_both(&mut cell, &second, &[owner_of(TAKEN, HOSTS)]);
        let successor = take_over(&cell);
        let outside = owner_of(OUTSIDE, HOSTS);
        cell.lose(outside.get());
        let mut race = None;
        for _ in 0..60 {
            let lagging = cell.survey();
            assert_ne!(
                verdict_of(&lagging, outside),
                HostEvidence::Lost,
                "{order:?}"
            );
            let now_us = cell.now_us + 9 * S;
            let current = second_survey(&mut cell, &second, now_us);
            if verdict_of(&current, outside) == HostEvidence::Lost {
                race = Some((lagging, current, now_us));
                break;
            }
            cell.now_us += 10 * S;
        }
        let (lagging, current, now_us) = race.unwrap();
        let unread = (ShardState::OwnerUnknown, Some(Blocker::OwnerNotReady));
        assert!(
            reserves(&lagging, TAKEN) && plan_of(&lagging, OUTSIDE) == unread,
            "{order:?}"
        );
        assert!(withheld(&current), "{order:?}: {:?}", current.plan.steps);
        let released = |outcomes: &[Outcome]| {
            verdict_where(outcomes, |step| matches!(step, Step::Release { .. }))
        };
        let reserved = |outcomes: &[Outcome]| {
            verdict_where(outcomes, |step| matches!(step, Step::Reserve { .. }))
        };
        match order {
            Order::ReservationFirst => {
                assert_eq!(reserved(&cell.actuate(&lagging)), Verdict::Advance);
                let theirs = second_actuate(&mut cell, &second, &current, now_us);
                assert_eq!(released(&theirs), Verdict::Wait(Reason::Moved));
            }
            Order::ReleaseFirst => {
                let theirs = second_actuate(&mut cell, &second, &current, now_us);
                assert_eq!(released(&theirs), Verdict::Advance);
                assert_eq!(reserved(&cell.actuate(&lagging)), Verdict::Advance);
            }
            Order::ReleaseBetween => {
                let (other, theirs) = (second.clone(), current.clone());
                *cell.hook.borrow_mut() = Some((
                    Key::Standbys(ZONE),
                    Box::new(move || {
                        let gate = StandbyGate::qualified();
                        let mut idle = World::new(ZONE);
                        let done = (other.borrow_mut()).actuate(&gate, &theirs, now_us, &mut idle);
                        let release = done
                            .unwrap()
                            .into_iter()
                            .find(|o| matches!(o.step, Step::Release { .. }));
                        assert_eq!(release.unwrap().verdict, Verdict::Advance);
                    }),
                ));
                assert_eq!(
                    reserved(&cell.actuate(&lagging)),
                    Verdict::Wait(Reason::Moved)
                );
            }
        }
        cell.enroll_listed();
        cell.now_us += 10 * S;
        let mut last = None;
        for _ in 0..160 {
            last = Some(both_tick(&mut cell, &second));
        }
        let snapshot = |cell: &Cell| {
            (
                census_of(cell.store()),
                (1..=SHARDS).map(|n| cell.shard(n)).collect::<Vec<_>>(),
            )
        };
        let settled = snapshot(&cell);
        for _ in 0..40 {
            last = Some(both_tick(&mut cell, &second));
        }
        assert!(snapshot(&cell) == settled, "{order:?}: the run flaps");
        let last = last.unwrap();
        let ended = match order {
            Order::ReservationFirst | Order::ReleaseFirst => slot_kept(&cell, &last),
            Order::ReleaseBetween => fresh_first_converged(&cell, &last, successor),
        };
        ended.unwrap_or_else(|why| panic!("{order:?}: {why}"));
        cell.clean();
    }
}

/// Two warmed loops that read the loss on the same tick, the second five seconds after the first, and a crash of the
/// first loop at each of its effects and the host's enrollment writes over the release, the admission, the attach
/// record, the attach request and the designation, acknowledged, timed out and committed, or timed out and not
/// committed, then a new first loop: every run ends in the same state, shard 6 designated once to the host the
/// uncrashed run designates and shard 4 `CensusFull`, with one restart and no committed census above the cap. The
/// second loop's own effects take no crash.
#[test]
fn a_crash_at_every_fresh_first_effect_with_a_second_loop_ends_in_one_state() {
    let prepared = || {
        let (mut cell, second) = two_loops();
        lose_under_both(
            &mut cell,
            &second,
            &[owner_of(TAKEN, HOSTS), owner_of(OUTSIDE, HOSTS)],
        );
        let successor = take_over(&cell);
        cell.faults.borrow_mut().effects = 0;
        let counted = before(&cell);
        (cell, second, successor, counted)
    };
    let run = |cell: &mut Cell, second: &RefCell<Loop>, ticks: usize| {
        let mut last = None;
        for _ in 0..ticks {
            last = Some(both_tick(cell, second));
            if cell.restarts > 0 && cell.shard(OUTSIDE).standby.is_some() {
                break;
            }
        }
        for _ in 0..12 {
            last = Some(both_tick(cell, second));
        }
        last.unwrap()
    };
    let (mut baseline, second, successor, counted) = prepared();
    let last = run(&mut baseline, &second, 120);
    fresh_first_converged(&baseline, &last, successor).unwrap();
    designated_once(&baseline, &counted).unwrap();
    let designee = baseline.shard(OUTSIDE).standby.unwrap();
    let effects = baseline.faults.borrow().effects;
    assert!(effects >= 5, "{effects} effects");
    let mut failures = Vec::new();
    for at in 0..effects {
        for arm in [
            Arm::Pass,
            Arm::Timeout { commit: true },
            Arm::Timeout { commit: false },
        ] {
            let (mut cell, second, successor, counted) = prepared();
            cell.faults.borrow_mut().at = Some((at, arm));
            let last = run(&mut cell, &second, 300);
            let mut result = fresh_first_converged(&cell, &last, successor);
            if result.is_ok() {
                result = designated_once(&cell, &counted);
            }
            if result.is_ok() && cell.shard(OUTSIDE).standby != Some(designee) {
                result = Err(format!("shard 6 names {:?}", cell.shard(OUTSIDE).standby));
            }
            if result.is_ok() && cell.restarts != 1 {
                result = Err(format!("{} restarts", cell.restarts));
            }
            if result.is_ok() && (!cell.breaks.is_empty() || !cell.fixture.world.breaks.is_empty())
            {
                result = Err(format!("{:?} {:?}", cell.breaks, cell.fixture.world.breaks));
            }
            if let Err(why) = result {
                failures.push(format!("effect {at} under {arm:?}: {why}"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
