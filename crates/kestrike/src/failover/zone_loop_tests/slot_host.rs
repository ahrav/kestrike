use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use crate::failover::attachments::Unlisted;
use crate::failover::reconcile::{Reconciler, StandbyGate};
use crate::failover::records::{Host, ShardRecord, VolumeId};
use crate::failover::report::Gauge;
use crate::failover::report::alarm_tests::controls;
use crate::failover::retire::Target;
use crate::failover::sim::host;
use crate::failover::standbys::Need;
use crate::failover::standbys::{Population, Refusal, Zone};
use crate::failover::zone_loop::Tick;
use crate::failover::zone_loop::actuate::{Outcome, Reason, Reclaim, Verdict};
use crate::failover::zone_loop::evidence::{HostEvidence, Instance, InstanceState};
use crate::failover::zone_loop::plan::{Step, Survey};
use crate::failover::zone_loop::sources::{
    InstanceSource, ListedVolume, ReportSource, Unreachable, VolumeSource,
};
use crate::failover::zone_loop::status::{Blocker, EnrollPhase, ShardState};
use crate::net::ownership::Shard;
use crate::storage::store::sim::Arm;
use crate::storage::store::{Key, Refusal as StoreRefusal, StoreError};

use super::actuate::{
    After, Cell, Hook, Loop, census_of, order_breaks, owner, reconciler_client, shard,
};
use super::config::bounds;
use super::directory::instance;
use super::observe::{S, ZONE};
use super::world::World;

pub(super) fn restore_protected(survey: &mut Survey) {
    let Ok(view) = &survey.observation.zone else {
        return;
    };
    let Ok(census) = &view.census else {
        return;
    };
    let live = |named: Host| {
        (view.hosts.iter())
            .any(|held| held.entry.host == named && held.verdict == HostEvidence::Live)
    };
    let displaced: BTreeSet<Shard> = (view.shards.iter())
        .filter_map(|held| {
            let records = held.records.as_ref().ok()?.as_ref()?;
            let record = &records.record;
            let standby = record.standby?;
            let slot = census.slot(record.shard)?;
            let named = live(standby) && records.active.live(standby).is_some();
            let tenure = slot.target.generation == record.generation
                && slot.target.owner == record.owner
                && slot.target.attempts <= record.attempts;
            let other = slot.host != standby && slot.host != record.owner && tenure;
            (named && other).then_some(record.shard)
        })
        .collect();
    let plan = &mut survey.plan;
    let enrolls = |step: &Step| {
        matches!(
            step,
            Step::Reserve { .. }
                | Step::RecordAttach { .. }
                | Step::Attach { .. }
                | Step::Designate { .. }
        )
    };
    (plan.steps).retain(|step| !enrolls(step) || !displaced.contains(&step.shard()));
    for held in (plan.shards.iter_mut()).filter(|held| displaced.contains(&held.shard)) {
        (held.state, held.blocker, held.protected) = (ShardState::Protected, None, true);
    }
}

struct Blind<'a> {
    world: &'a mut World,
    host: Host,
    frozen: Option<Vec<u8>>,
}

impl ReportSource for Blind<'_> {
    fn latest(&mut self, named: Host) -> Result<Option<Vec<u8>>, Unreachable> {
        if named == self.host {
            return Ok(self.frozen.clone());
        }
        self.world.latest(named)
    }
}

impl InstanceSource for Blind<'_> {
    fn instances(&mut self, zone: Zone) -> Result<Vec<Instance>, Unlisted> {
        let mut listed = self.world.instances(zone)?;
        let hidden = instance(self.host.get());
        for row in listed.iter_mut().filter(|row| row.instance == hidden) {
            row.state = InstanceState::Terminated;
        }
        Ok(listed)
    }
}

impl VolumeSource for Blind<'_> {
    fn volumes(&mut self, zone: Zone) -> Result<Vec<ListedVolume>, Unlisted> {
        self.world.volumes(zone)
    }
}

struct Second {
    zone: Rc<RefCell<Loop>>,
    blind: Option<(Host, Option<Vec<u8>>)>,
    slot_host: bool,
}

impl Second {
    fn open(cell: &Cell) -> Self {
        let (hook, after) = (Hook::default(), After::default());
        let zone = Cell::open(&cell.fixture, &cell.faults, &hook, &after, &cell.bounds);
        Self {
            zone: Rc::new(RefCell::new(zone)),
            blind: None,
            slot_host: true,
        }
    }

    fn blind(&mut self, cell: &Cell, named: Host) {
        let frozen = cell.fixture.world.reports.get(&named).cloned();
        self.blind = Some((named, frozen));
    }

    fn survey(&self, cell: &mut Cell) -> Survey {
        let directory = Ok(cell.fixture.directory());
        let mut zone = self.zone.borrow_mut();
        let world = &mut cell.fixture.world;
        let mut survey = match &self.blind {
            Some((named, frozen)) => {
                let mut sources = Blind {
                    world,
                    host: *named,
                    frozen: frozen.clone(),
                };
                zone.survey(directory, &mut sources, cell.now_us)
            }
            None => zone.survey(directory, world, cell.now_us),
        };
        if !self.slot_host {
            restore_protected(&mut survey);
        }
        survey
    }

    fn actuate(&self, cell: &mut Cell, survey: &Survey) -> Vec<Outcome> {
        let gate = StandbyGate::qualified();
        let before = cell.snapshot();
        let mut zone = self.zone.borrow_mut();
        let outcomes = zone.actuate(&gate, survey, cell.now_us, &mut cell.fixture.world);
        let after = cell.snapshot();
        cell.breaks.extend(order_breaks(&before, &after));
        outcomes.unwrap()
    }
}

fn verdict_of(survey: &Survey, named: Host) -> Option<HostEvidence> {
    let view = survey.observation.zone.as_ref().ok()?;
    let found = view.hosts.iter().find(|held| held.entry.host == named);
    found.map(|held| held.verdict)
}

fn state(survey: &Survey) -> ShardState {
    let found = survey
        .plan
        .shards
        .iter()
        .find(|held| held.shard == shard(1));
    found.unwrap().state
}

fn short_of_protected(survey: &Survey, next: Host) -> bool {
    let view = survey.observation.zone.as_ref().unwrap();
    let held = view.shards.iter().find(|held| held.shard == shard(1));
    let records = held.and_then(|held| held.records.as_ref().ok()?.as_ref());
    let named = records.and_then(|records| records.record.standby);
    state(survey) != ShardState::Protected || named == Some(next)
}

fn steps(survey: &Survey) -> Vec<Step> {
    let planned = survey.plan.steps.iter().copied();
    planned.filter(|step| step.shard() == shard(1)).collect()
}

fn reserves(steps: &[Step]) -> Vec<Host> {
    let reserve = |step: &Step| match *step {
        Step::Reserve { host, .. } => Some(host),
        _ => None,
    };
    steps.iter().filter_map(reserve).collect()
}

fn census_commits(cell: &Cell) -> usize {
    cell.store().0.borrow().commit_count(&Key::Standbys(ZONE))
}

fn tenure(record: &ShardRecord) -> (u64, Host, VolumeId) {
    (record.generation.get(), record.owner, record.active)
}

fn slot_host(cell: &Cell) -> Host {
    census_of(cell.store())
        .unwrap()
        .slot(shard(1))
        .unwrap()
        .host
}

fn both(cell: &mut Cell, second: &Second) -> (Survey, Survey) {
    let mine = cell.survey();
    cell.actuate(&mine);
    let theirs = second.survey(cell);
    second.actuate(cell, &theirs);
    cell.enroll_listed();
    cell.drop_ended_pairs();
    cell.now_us += 10 * S;
    (mine, theirs)
}

fn moved_inside_the_designation(cell: &mut Cell) -> (Host, Host) {
    let designating = |step: &Step| matches!(step, Step::Designate { .. });
    let survey = cell.planned(designating);
    let Some(&Step::Designate { host: first, .. }) =
        survey.plan.steps.iter().find(|s| designating(s))
    else {
        unreachable!()
    };
    let store = cell.store().clone();
    let next = if first == host(1) { host(3) } else { host(1) };
    *cell.hook.borrow_mut() = Some((
        Key::Shard(shard(1)),
        Box::new(move || {
            let gate = StandbyGate::qualified();
            let mut other = Reconciler::new(reconciler_client(&store));
            let report = crate::failover::standbys::tests::roomy(next);
            let population = Population { cap: 8 };
            let zone = bounds();
            let lost = |h| h == first;
            let slot = other.reserve(
                &gate,
                &population,
                zone.bounds(),
                ZONE,
                shard(1),
                &report,
                lost,
            );
            assert_eq!(slot.unwrap().host(), next);
        }),
    ));
    let outcomes = cell.actuate(&survey);
    assert!(cell.hook.borrow().is_none(), "the shard write ran");
    let designated = outcomes.iter().find(|o| designating(&o.step)).unwrap();
    assert_eq!(designated.verdict, Verdict::Advance);
    let raced = cell.shard(1);
    assert_eq!(raced.standby, Some(first));
    let slot = census_of(cell.store()).unwrap().slot(shard(1)).unwrap();
    assert_eq!((slot.host, slot.target), (next, Target::of(&raced)));
    cell.enroll_listed();
    cell.now_us += 10 * S;
    (first, next)
}

#[test]
fn a_slot_moved_to_a_live_host_inside_a_designation_designates_that_host_over_the_named_standby() {
    for slot_host_rule in [true, false] {
        let mut cell = Cell::new(6, 1);
        cell.slot_host = slot_host_rule;
        let (first, next) = moved_inside_the_designation(&mut cell);
        let before = cell.shard(1);
        let writes = census_commits(&cell);
        for _ in 0..60 {
            if cell.shard(1).standby == Some(next) {
                break;
            }
            let (survey, _) = cell.tick();
            assert!(reserves(&steps(&survey)).is_empty(), "{:?}", steps(&survey));
            assert_eq!(census_of(cell.store()).unwrap().len(), 1);
            assert_eq!(tenure(&cell.shard(1)), tenure(&before));
            if slot_host_rule {
                assert!(short_of_protected(&survey, next));
            }
        }
        assert_eq!(census_commits(&cell), writes);
        assert_eq!(slot_host(&cell), next);
        if !slot_host_rule {
            assert_eq!(
                cell.shard(1).standby,
                Some(first),
                "the restored Protected reading keeps the named standby beside the slot's host"
            );
            continue;
        }
        assert_eq!(cell.shard(1).standby, Some(next));
        let volume = cell.volume(1);
        assert!(volume.enrolled(next).is_some());
        assert!(volume.live(first).is_some() && volume.enrolled(first).is_some());
        cell.clean();
    }
}

#[test]
fn a_second_loop_holding_the_standby_lost_moves_its_slot_inside_the_designation_and_both_converge()
{
    let mut cell = Cell::new(6, 1);
    let mut second = Second::open(&cell);
    let mut raced = None;
    for _ in 0..80 {
        let mine = cell.survey();
        if second.blind.is_none()
            && let Some(slot) = census_of(cell.store()).and_then(|held| held.slot(shard(1)))
        {
            second.blind(&cell, slot.host);
        }
        let theirs = second.survey(&mut cell);
        let designating = steps(&mine).iter().find_map(|step| match *step {
            Step::Designate { host, .. } => Some(host),
            _ => None,
        });
        match designating {
            Some(first) if verdict_of(&theirs, first) == Some(HostEvidence::Lost) => {
                let (zone, now_us) = (second.zone.clone(), cell.now_us);
                let outcomes = Rc::new(RefCell::new(Vec::new()));
                let seen = outcomes.clone();
                *cell.hook.borrow_mut() = Some((
                    Key::Shard(shard(1)),
                    Box::new(move || {
                        let gate = StandbyGate::qualified();
                        let mut idle = World::new(ZONE);
                        let done = zone.borrow_mut().actuate(&gate, &theirs, now_us, &mut idle);
                        *seen.borrow_mut() = done.unwrap();
                    }),
                ));
                let mine = cell.actuate(&mine);
                assert!(cell.hook.borrow().is_none(), "the shard write ran");
                let theirs = outcomes.borrow().clone();
                raced = Some((first, mine, theirs));
                cell.enroll_listed();
                cell.now_us += 10 * S;
                break;
            }
            Some(_) => {}
            None => {
                cell.actuate(&mine);
            }
        }
        cell.enroll_listed();
        cell.now_us += 10 * S;
    }
    let (first, mine, theirs) = raced.expect("B reads S lost while A designates it");
    let designated = mine
        .iter()
        .find(|o| matches!(o.step, Step::Designate { .. }));
    assert_eq!(designated.unwrap().verdict, Verdict::Advance);
    let moved: Vec<Step> = theirs.iter().map(|o| o.step).collect();
    let next = slot_host(&cell);
    assert_eq!(reserves(&moved), [next], "{theirs:?}");
    assert_ne!(next, first);
    assert_eq!(cell.shard(1).standby, Some(first));
    let before = cell.shard(1);
    let writes = census_commits(&cell);
    let roles = [before.owner, first, next];
    let bystander = (1..=6).map(host).find(|h| !roles.contains(h)).unwrap();
    let mut planted = cell.survey();
    planted.plan.steps = vec![Step::Reserve {
        shard: shard(1),
        host: bystander,
        target: Target::of(&before),
    }];
    let refused = cell.actuate(&planted);
    let taken = Verdict::Wait(Reason::Population(Refusal::Taken));
    assert_eq!(refused[0].verdict, taken, "control");
    assert_eq!((census_commits(&cell), slot_host(&cell)), (writes, next));
    cell.now_us += 10 * S;
    for _ in 0..60 {
        if cell.shard(1).standby == Some(next) {
            break;
        }
        let (mine, theirs) = both(&mut cell, &second);
        assert!(reserves(&steps(&mine)).is_empty() && reserves(&steps(&theirs)).is_empty());
        assert_eq!(tenure(&cell.shard(1)), tenure(&before));
    }
    assert_eq!(cell.shard(1).standby, Some(next));
    assert!(cell.volume(1).enrolled(next).is_some());
    assert_eq!((census_commits(&cell), slot_host(&cell)), (writes, next));
    cell.clean();
}

#[test]
fn a_second_loops_healed_loss_verdict_leaves_both_loops_converging_on_the_slots_host() {
    for slot_host_rule in [true, false] {
        let mut cell = Cell::new(6, 1);
        cell.slot_host = slot_host_rule;
        let mut second = Second::open(&cell);
        second.slot_host = slot_host_rule;
        for _ in 0..80 {
            let mine = cell.survey();
            cell.actuate(&mine);
            second.survey(&mut cell);
            cell.enroll_listed();
            cell.now_us += 10 * S;
            if cell.designated() {
                break;
            }
        }
        let first = cell.shard(1).standby.expect("A designates S");
        second.blind(&cell, first);
        let mut reserved = None;
        for _ in 0..20 {
            let mine = cell.survey();
            cell.actuate(&mine);
            let theirs = second.survey(&mut cell);
            if verdict_of(&theirs, first) == Some(HostEvidence::Lost) {
                reserved = Some(second.actuate(&mut cell, &theirs));
            }
            cell.enroll_listed();
            cell.now_us += 10 * S;
            if reserved.is_some() {
                break;
            }
        }
        let reserved = reserved.expect("B reads S lost");
        let moved = reserved
            .iter()
            .find(|o| matches!(o.step, Step::Reserve { .. }));
        assert_eq!(moved.unwrap().verdict, Verdict::Advance, "{reserved:?}");
        let next = slot_host(&cell);
        assert_ne!(next, first);
        assert_eq!(cell.shard(1).standby, Some(first));
        second.blind = None;
        let before = cell.shard(1);
        let writes = census_commits(&cell);
        let mut enrolling = (false, false);
        let enrolls = |survey: &Survey| {
            steps(survey).iter().any(|step| match *step {
                Step::RecordAttach { host, .. }
                | Step::Attach { host, .. }
                | Step::Designate { host, .. } => host == next,
                _ => false,
            })
        };
        for _ in 0..60 {
            if cell.shard(1).standby == Some(next) {
                break;
            }
            let (mine, theirs) = both(&mut cell, &second);
            assert!(reserves(&steps(&mine)).is_empty() && reserves(&steps(&theirs)).is_empty());
            assert_eq!(tenure(&cell.shard(1)), tenure(&before));
            enrolling = (
                enrolling.0 || enrolls(&mine),
                enrolling.1 || enrolls(&theirs),
            );
            if slot_host_rule {
                assert!(short_of_protected(&mine, next) && short_of_protected(&theirs, next));
            }
        }
        assert_eq!((census_commits(&cell), slot_host(&cell)), (writes, next));
        if !slot_host_rule {
            assert_eq!(cell.shard(1).standby, Some(first), "control");
            continue;
        }
        assert_eq!(enrolling, (true, true));
        assert_eq!(cell.shard(1).standby, Some(next));
        let volume = cell.volume(1);
        assert!(volume.enrolled(next).is_some());
        assert!(volume.live(first).is_some() && volume.enrolled(first).is_some());
        cell.clean();
    }
}

#[test]
fn a_failed_slot_host_yields_its_slot_to_the_named_standby_only_on_its_loss() {
    let mut cell = Cell::new(6, 1);
    let (first, next) = moved_inside_the_designation(&mut cell);
    let before = cell.shard(1);
    let writes = census_commits(&cell);
    let mut planted = cell.survey();
    planted.plan.steps = vec![Step::Reserve {
        shard: shard(1),
        host: first,
        target: Target::of(&before),
    }];
    let refused = cell.actuate(&planted);
    let taken = Verdict::Wait(Reason::Population(Refusal::Taken));
    assert_eq!(
        refused[0].verdict, taken,
        "a reservation of the named standby over the live slot host is refused Taken"
    );
    assert_eq!((census_commits(&cell), slot_host(&cell)), (writes, next));
    cell.now_us += 10 * S;
    cell.lose(next.get());
    let mut moved = None;
    for _ in 0..30 {
        let (survey, outcomes) = cell.tick();
        let lost = verdict_of(&survey, next) == Some(HostEvidence::Lost);
        let planned = reserves(&steps(&survey));
        assert!(planned.iter().all(|&host| host == first), "{planned:?}");
        assert!(lost || planned.is_empty(), "{:?}", steps(&survey));
        let designates = |step: &Step| matches!(step, Step::Designate { .. });
        assert!(!steps(&survey).iter().any(designates));
        if !planned.is_empty() {
            moved = Some(outcomes);
            break;
        }
    }
    let outcomes = moved.expect("the loop reserves S once X reads lost");
    let reserve = outcomes
        .iter()
        .find(|o| matches!(o.step, Step::Reserve { .. }));
    assert_eq!(reserve.unwrap().verdict, Verdict::Advance);
    assert_eq!(
        (census_commits(&cell), slot_host(&cell)),
        (writes + 1, first)
    );
    for _ in 0..5 {
        let (survey, _) = cell.tick();
        assert_eq!(state(&survey), ShardState::Protected);
    }
    assert_eq!(census_commits(&cell), writes + 1);
    let after = cell.shard(1);
    assert_eq!(
        (after.standby, tenure(&after)),
        (Some(first), tenure(&before))
    );
    assert_eq!(census_of(cell.store()).unwrap().len(), 1);
    cell.clean();
}

#[test]
fn an_owner_bump_inside_the_displacement_retargets_the_slots_host_and_converges() {
    for slot_host_rule in [true, false] {
        let mut cell = Cell::new(6, 1);
        cell.slot_host = slot_host_rule;
        let (first, next) = moved_inside_the_designation(&mut cell);
        let mut client = owner(cell.store());
        let read = client.read::<ShardRecord>(Key::Shard(shard(1))).unwrap();
        client.bump(&read).unwrap();
        let bumped = cell.shard(1);
        assert_eq!(
            (bumped.standby, bumped.attempts),
            (Some(first), read.value().attempts + 1)
        );
        let target = Target::of(&bumped);
        let entry = census_of(cell.store()).unwrap().slot(shard(1)).unwrap();
        assert!(entry.host == next && entry.target != target);
        let mut retargeted = false;
        for _ in 0..60 {
            if cell.shard(1).standby == Some(next) {
                break;
            }
            let (survey, _) = cell.tick();
            let reserve = Step::Reserve {
                shard: shard(1),
                host: next,
                target,
            };
            retargeted |= steps(&survey).contains(&reserve);
            assert!(reserves(&steps(&survey)).iter().all(|&host| host == next));
            assert_eq!(tenure(&cell.shard(1)), tenure(&bumped));
            if slot_host_rule {
                assert!(short_of_protected(&survey, next));
            }
        }
        if !slot_host_rule {
            assert_eq!(cell.shard(1).standby, Some(first), "control");
            continue;
        }
        assert!(retargeted);
        assert_eq!(cell.shard(1).standby, Some(next));
        let slot = census_of(cell.store()).unwrap().slot(shard(1)).unwrap();
        assert_eq!((slot.host, slot.target), (next, target));
        cell.clean();
    }
}

#[test]
fn a_takeover_by_the_displaced_standby_wins_or_loses_by_the_shards_exact_version_write() {
    for takeover_first in [true, false] {
        let mut cell = Cell::new(6, 1);
        let (first, next) = moved_inside_the_designation(&mut cell);
        let designating =
            |step: &Step| matches!(*step, Step::Designate { host, .. } if host == next);
        let survey = cell.planned(designating);
        let mut client = owner(cell.store());
        let read = client.read::<ShardRecord>(Key::Shard(shard(1))).unwrap();
        let old = Target::of(read.value());
        if !takeover_first {
            let outcomes = cell.actuate(&survey);
            let designated = outcomes.iter().find(|o| designating(&o.step)).unwrap();
            assert_eq!(designated.verdict, Verdict::Advance);
            let refused = client.take_over(&read, old, first);
            let condition = StoreError::Refused(StoreRefusal::Condition);
            assert_eq!(refused.map(|_| ()), Err(condition));
            let record = cell.shard(1);
            let named = (record.owner, record.standby);
            assert_eq!(named, (read.value().owner, Some(next)));
            cell.clean();
            continue;
        }
        let store = cell.store().clone();
        *cell.hook.borrow_mut() = Some((
            Key::Shard(shard(1)),
            Box::new(move || {
                let mut client = owner(&store);
                let read = client.read::<ShardRecord>(Key::Shard(shard(1))).unwrap();
                client.take_over(&read, old, first).unwrap();
            }),
        ));
        let commits = cell.store().0.borrow().commit_count(&Key::Shard(shard(1)));
        let outcomes = cell.actuate(&survey);
        assert!(cell.hook.borrow().is_none(), "the shard write ran");
        let after = cell.store().0.borrow().commit_count(&Key::Shard(shard(1)));
        assert_eq!(after, commits + 1);
        let taken = cell.shard(1);
        assert_eq!((taken.owner, taken.standby), (first, None));
        let designated = outcomes.iter().find(|o| designating(&o.step)).unwrap();
        assert_eq!(designated.verdict, Verdict::Wait(Reason::Moved));
        cell.enroll_listed();
        cell.now_us += 10 * S;
        let target = Target::of(&taken);
        let mut retargeted = false;
        for _ in 0..60 {
            if cell.shard(1).standby == Some(next) {
                break;
            }
            let (survey, _) = cell.tick();
            retargeted |= steps(&survey).contains(&Step::Reserve {
                shard: shard(1),
                host: next,
                target,
            });
            assert_eq!(tenure(&cell.shard(1)), tenure(&taken));
        }
        assert!(retargeted);
        assert_eq!(cell.shard(1).standby, Some(next));
        let slot = census_of(cell.store()).unwrap().slot(shard(1)).unwrap();
        assert_eq!((slot.host, slot.target), (next, target));
        cell.clean();
    }
}

#[test]
fn a_slot_host_whose_attach_never_enrolls_is_ended_and_yields_its_slot_to_the_named_standby() {
    let mut cell = Cell::new(6, 1);
    let (first, next) = moved_inside_the_designation(&mut cell);
    cell.unenrolled.push(next.get());
    let before = cell.shard(1);
    let writes = census_commits(&cell);
    let mut ended = false;
    let mut moved = None;
    for _ in 0..200 {
        let (survey, outcomes) = cell.tick();
        let planned = reserves(&steps(&survey));
        assert!(planned.iter().all(|&host| host == first), "{planned:?}");
        let end = Step::End {
            shard: shard(1),
            host: next,
        };
        let ending = ended || steps(&survey).contains(&end);
        assert!(ending || planned.is_empty(), "{:?}", steps(&survey));
        assert_eq!(tenure(&cell.shard(1)), tenure(&before));
        let advanced =
            |step: Step| (outcomes.iter()).any(|o| o.step == step && o.verdict == Verdict::Advance);
        ended |= advanced(end);
        if !planned.is_empty() && census_commits(&cell) > writes {
            moved = Some(outcomes);
            break;
        }
    }
    assert!(ended);
    let outcomes = moved.expect("the loop reserves S once X's attach is ended");
    let reserve = outcomes
        .iter()
        .find(|o| matches!(o.step, Step::Reserve { .. }));
    assert_eq!(reserve.unwrap().verdict, Verdict::Advance);
    assert_eq!(
        (census_commits(&cell), slot_host(&cell)),
        (writes + 1, first)
    );
    assert!(cell.volume(1).live(next).is_none());
    let (survey, _) = cell.tick();
    assert_eq!(state(&survey), ShardState::Protected);
    assert_eq!(cell.shard(1).standby, Some(first));
    cell.clean();
}

fn part_tick(cell: &mut Cell) -> Tick {
    for number in 1..=cell.fixture.hosts {
        if !cell.silent.contains(&number) {
            cell.fixture.publish(number, &[]);
        }
    }
    let directory = Ok(cell.fixture.directory());
    (cell.zone).tick(directory, &mut cell.fixture.world, cell.now_us)
}

/// The state, blocker, exposure and overdue reading of shard 1's status row.
fn row(tick: &Tick) -> ((ShardState, Option<Blocker>), (Option<u64>, bool)) {
    let mut rows = tick.survey.status.shards.iter();
    let row = rows.find(|row| row.shard == shard(1)).unwrap();
    ((row.state, row.blocker), (row.exposure_us, row.overdue))
}

/// EXPOSURE: a displaced shard's named standby is live and attached, so each tick that reads the shard short of
/// `Protected` keeps its exposure clock closed and publishes it `named`, strictly past the standby target included.
/// Once the named standby is lost, the clock opens at zero, and strictly past the target the shard publishes `past`.
#[test]
fn a_displaced_shard_runs_no_exposure_clock_while_its_named_standby_is_live() {
    let mut cell = Cell::new(6, 1);
    let (first, next) = moved_inside_the_designation(&mut cell);
    let target = cell.bounds.config().standby_target_us;
    let unconfirmed = (ShardState::NoCandidate, Some(Blocker::LossUnconfirmed));
    // The entry host stops reporting. Once it reads unknown, the shard has no candidate and plans no step.
    cell.silent.push(next.get());
    let mut held = false;
    for _ in 0..12 {
        let tick = part_tick(&mut cell);
        assert!(short_of_protected(&tick.survey, next));
        assert_eq!(row(&tick).1, (None, false), "{:?}", row(&tick).0);
        held = row(&tick).0 == unconfirmed;
        if held {
            break;
        }
        cell.now_us += 10 * S;
    }
    assert!(held, "the silent entry host reads unknown");
    cell.now_us += target + 10 * S;
    let named = part_tick(&mut cell);
    assert_eq!(row(&named), (unconfirmed, (None, false)));
    assert_eq!(named.part.standby, [1, 0, 0, 0, 0]);
    let alarm = controls::no_standby_past_target();
    assert_eq!(named.part.standby[3], alarm.clean);
    assert_eq!(cell.shard(1).standby, Some(first));
    assert_eq!(slot_host(&cell), next);
    cell.lose(first.get());
    let (mut opened, mut past) = (None, None);
    for _ in 0..=(target / (10 * S) + 30) {
        let tick = part_tick(&mut cell);
        opened = opened.or(row(&tick).1.0);
        if row(&tick).1.1 {
            past = Some(tick);
            break;
        }
        cell.now_us += 10 * S;
    }
    assert_eq!(
        opened,
        Some(0),
        "the clock opens on the first tick with the standby short of live"
    );
    let past = past.expect("the open clock passes the standby target");
    assert_eq!(verdict_of(&past.survey, first), Some(HostEvidence::Lost));
    assert_eq!(row(&past).0, unconfirmed);
    assert_eq!(past.part.standby, [0, 0, 0, 1, 0]);
    assert_eq!(past.part.standby[3], alarm.fault);
}

/// The displaced shard of `moved_inside_the_designation` once the loop has recorded the entry host's attach entry,
/// before any attach request for it.
fn recorded_unrequested(cell: &mut Cell) -> (Host, Host) {
    let (first, next) = moved_inside_the_designation(cell);
    let recording = |step: &Step| matches!(step, Step::RecordAttach { .. });
    let survey = cell.planned(recording);
    cell.actuate(&survey);
    cell.now_us += 10 * S;
    assert!(cell.volume(1).live(next).is_some());
    assert!(!requested(cell, next));
    (first, next)
}

fn requested(cell: &Cell, named: Host) -> bool {
    let calls = cell.attach_calls();
    calls.iter().any(|(_, id)| *id == instance(named.get()))
}

/// One tick in which `tight`, a host of `cell.silent`, reports its recovery gauge at its limit.
fn tight_tick(cell: &mut Cell, tight: Host) -> (Survey, Vec<Outcome>) {
    let roomy = cell.fixture.headroom;
    cell.fixture.headroom.recovery = Gauge::known(2, 2);
    cell.fixture.publish(tight.get(), &[]);
    cell.fixture.headroom = roomy;
    cell.tick()
}

fn ended(outcomes: &[Outcome], named: Host) -> bool {
    let end = Step::End {
        shard: shard(1),
        host: named,
    };
    let mut ends = outcomes.iter().filter(|o| o.step == end);
    ends.any(|o| o.verdict == Verdict::Advance && o.reclaim == Some(Reclaim::Ended))
}

fn hold(cell: &mut Cell, on: bool) {
    let mut held = cell.fixture.listing.clone().unwrap();
    held.version += 1;
    held.zone_hold = on;
    cell.fixture.listing = Some(held);
}

/// The named standby takes the entry back: one census write reserves it, and the shard reads `Protected` under it.
fn yields_to(cell: &mut Cell, first: Host, next: Host, writes: usize) {
    cell.run_until(20, |cell| slot_host(cell) == first);
    assert_eq!(census_commits(cell), writes + 1);
    assert!(cell.volume(1).live(next).is_none());
    assert!(!requested(cell, next));
    let (survey, _) = cell.tick();
    assert_eq!(state(&survey), ShardState::Protected);
    assert_eq!(cell.shard(1).standby, Some(first));
    cell.clean();
}

/// SLOT-HOST: a recorded entry of the slot host that `choose` refuses before its first attach request holds its
/// in-flight unit and takes no step; `attach_stuck_us` after the first survey that read it, the plan ends it and the
/// named standby takes the entry back. When the refusal clears before the bound, the loop requests the attach, plans
/// no end, and designates the slot host.
#[test]
fn a_recorded_slot_host_entry_that_choose_refuses_is_ended_at_the_stuck_bound_and_yields_to_the_named_standby()
 {
    for lasting in [true, false] {
        let mut cell = Cell::new(6, 1);
        let (first, next) = recorded_unrequested(&mut cell);
        let stuck_us = cell.bounds.config().attach_stuck_us;
        let (before, writes) = (cell.shard(1), census_commits(&cell));
        let refused = ShardState::Enrolling {
            need: Need::Standby,
            phase: EnrollPhase::Recorded,
            host: next,
        };
        cell.silent.push(next.get());
        let sighted_us = cell.now_us;
        let mut ended_us = None;
        while cell.now_us - sighted_us <= stuck_us
            && (lasting || cell.now_us - sighted_us < 300 * S)
        {
            let at = cell.now_us;
            let (survey, outcomes) = tight_tick(&mut cell, next);
            if ended(&outcomes, next) {
                ended_us = Some(at);
                break;
            }
            let held = survey
                .plan
                .shards
                .iter()
                .find(|held| held.shard == shard(1));
            let held = held.unwrap();
            assert_eq!(
                (held.state, held.blocker),
                (refused, Some(Blocker::Headroom))
            );
            assert_eq!(survey.plan.inflight, 1);
            assert!(steps(&survey).is_empty(), "{:?}", steps(&survey));
            assert_eq!(
                (slot_host(&cell), tenure(&cell.shard(1))),
                (next, tenure(&before))
            );
        }
        if lasting {
            assert_eq!(ended_us, Some(sighted_us + stuck_us));
            yields_to(&mut cell, first, next, writes);
            continue;
        }
        cell.silent.clear();
        let mut outcomes = Vec::new();
        for _ in 0..60 {
            if cell.shard(1).standby == Some(next) {
                break;
            }
            outcomes.extend(cell.tick().1);
        }
        assert_eq!(cell.shard(1).standby, Some(next), "control");
        assert!(requested(&cell, next) && !ended(&outcomes, next));
        assert_eq!((census_commits(&cell), slot_host(&cell)), (writes, next));
        cell.clean();
    }
}

/// SLOT-HOST under the operator hold: the hold withholds the recorded entry's attach, so the entry is ended
/// `attach_stuck_us` after the first survey that read it displaced, and the named standby, which needs no new attach,
/// takes the entry back under the hold.
#[test]
fn a_recorded_slot_host_entry_under_the_operator_hold_is_ended_at_the_stuck_bound_while_its_shard_is_displaced()
 {
    let mut cell = Cell::new(6, 1);
    let (first, next) = recorded_unrequested(&mut cell);
    let stuck_us = cell.bounds.config().attach_stuck_us;
    let writes = census_commits(&cell);
    hold(&mut cell, true);
    let sighted_us = cell.now_us;
    let mut ended_us = None;
    while cell.now_us - sighted_us <= stuck_us {
        let at = cell.now_us;
        let (survey, outcomes) = cell.tick();
        assert!(survey.plan.holds.operator);
        if ended(&outcomes, next) {
            ended_us = Some(at);
            break;
        }
    }
    assert_eq!(ended_us, Some(sighted_us + stuck_us));
    yields_to(&mut cell, first, next, writes);
}

/// The displaced clock lasts only while the shard reads displaced. When the named standby is lost under the operator
/// hold, the slot host's recorded entry is the shard's one enrollment in progress: it keeps its slot for twice the
/// stuck bound and takes the first attach request after the hold.
#[test]
fn a_recorded_slot_host_entry_whose_shard_leaves_the_displaced_state_keeps_its_slot_under_the_operator_hold()
 {
    let mut cell = Cell::new(6, 1);
    let (first, next) = recorded_unrequested(&mut cell);
    let stuck_us = cell.bounds.config().attach_stuck_us;
    hold(&mut cell, true);
    let held_us = cell.now_us;
    let mut seen = Vec::new();
    while cell.now_us - held_us < 2 * stuck_us {
        if cell.now_us - held_us == 50 * S {
            cell.lose(first.get());
        }
        seen.extend(cell.tick().1);
    }
    let survey = cell.survey();
    assert_eq!(verdict_of(&survey, first), Some(HostEvidence::Lost));
    assert!(
        !seen.iter().any(|o| o.reclaim == Some(Reclaim::Ended)),
        "{seen:?}"
    );
    assert!(cell.volume(1).live(next).is_some() && !requested(&cell, next));
    assert_eq!(slot_host(&cell), next);
    hold(&mut cell, false);
    cell.run_until(10, |cell| requested(cell, next));
    assert!(cell.volume(1).live(next).is_some());
    cell.clean();
}

/// The displaced clock is process memory: a loop that restarts while the refusal lasts ends the entry
/// `attach_stuck_us` after its own first survey that reads the named standby live.
#[test]
fn a_restarted_loop_ends_a_refused_recorded_slot_host_entry_at_the_stuck_bound_from_its_first_survey()
 {
    let mut cell = Cell::new(6, 1);
    let (first, next) = recorded_unrequested(&mut cell);
    let stuck_us = cell.bounds.config().attach_stuck_us;
    let writes = census_commits(&cell);
    cell.silent.push(next.get());
    for _ in 0..30 {
        let (_, outcomes) = tight_tick(&mut cell, next);
        assert!(!ended(&outcomes, next));
    }
    cell.restart();
    let restarted_us = cell.now_us;
    let (mut displaced_us, mut ended_us) = (None, None);
    while cell.now_us - restarted_us <= stuck_us + 60 * S {
        let at = cell.now_us;
        let (survey, outcomes) = tight_tick(&mut cell, next);
        if verdict_of(&survey, first) == Some(HostEvidence::Live) {
            displaced_us = displaced_us.or(Some(at));
        }
        if ended(&outcomes, next) {
            ended_us = Some(at);
            break;
        }
    }
    let displaced_us = displaced_us.expect("the new loop reads the named standby live");
    assert!(displaced_us - restarted_us <= 60 * S);
    assert_eq!(ended_us, Some(displaced_us + stuck_us));
    yields_to(&mut cell, first, next, writes);
}

/// A survey that cannot read the census reads no shard, so the displaced clock keeps its start through it: the entry
/// is ended `attach_stuck_us` after the first survey that read it displaced.
#[test]
fn a_survey_that_cannot_read_the_census_keeps_the_displaced_clock() {
    let mut cell = Cell::new(6, 1);
    let (first, next) = recorded_unrequested(&mut cell);
    let stuck_us = cell.bounds.config().attach_stuck_us;
    let writes = census_commits(&cell);
    cell.silent.push(next.get());
    let sighted_us = cell.now_us;
    let (mut unread, mut ended_us) = (0, None);
    while cell.now_us - sighted_us <= stuck_us {
        let at = cell.now_us;
        if (at - sighted_us) / (10 * S) % 30 == 15 {
            cell.store().schedule(Arm::Unavailable);
            let survey = cell.survey();
            let view = survey.observation.zone.as_ref().unwrap();
            assert!(view.census.is_err() && view.shards.iter().all(|held| held.records.is_err()));
            unread += 1;
            cell.now_us += 10 * S;
            continue;
        }
        let (_, outcomes) = tight_tick(&mut cell, next);
        if ended(&outcomes, next) {
            ended_us = Some(at);
            break;
        }
    }
    assert_eq!(unread, 3);
    assert_eq!(ended_us, Some(sighted_us + stuck_us));
    yields_to(&mut cell, first, next, writes);
}
