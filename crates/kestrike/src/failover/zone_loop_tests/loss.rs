//! CORRELATED-HOLD uses the observer's count of other impaired volumes. LOSS-NEEDS-EVIDENCE uses its run of
//! consecutive complete views for the shard and its confirmation of the loss.

use crate::failover::loss::{Health, Phase};
use crate::failover::reconcile::{Reconciler, StandbyGate};
use crate::failover::records::{ERA, ShardRecord, VolumeId, VolumeRecord, VolumeState};
use crate::failover::retire::Target;
use crate::failover::sim::{host, layout};
use crate::failover::standbys::Entry;
use crate::failover::zone_loop::ZoneLoop;
use crate::failover::zone_loop::evidence::{
    ListedVolumeState, VolumeCondition, VolumeJudgement, VolumeStatus,
};
use crate::failover::zone_loop::observe::Source;
use crate::failover::zone_loop::plan::Survey;
use crate::failover::zone_loop::sources::Unreachable;
use crate::failover::zone_loop::status::{Blocker, ShardState};
use crate::failover::zone_loop::tests::world::{Event, Provisioner, Recording, World};
use crate::net::ownership::Shard;
use crate::storage::store::StoreError;
use crate::storage::store::sim::{Arm, AsProvisioner, AsReconciler, MemLog, Shared};
use crate::storage::store::{Client, Key, Outcome, Store, Write};

use super::config::config_of;
use super::observe::{
    Fixture, S, START, ZONE, condition, error, id, in_use, owner, owner_of, reconciler, volume,
};
use super::survey::{reserves, roomy_fixture, state_of, surveyed};

fn impaired() -> VolumeCondition {
    condition(ListedVolumeState::InUse, VolumeStatus::Impaired)
}

fn creating() -> VolumeCondition {
    condition(ListedVolumeState::Creating, VolumeStatus::Ok)
}

fn unvalued() -> VolumeCondition {
    condition(ListedVolumeState::InUse, VolumeStatus::InsufficientData)
}

fn warmed(fixture: &mut Fixture) -> Survey {
    let mut last = None;
    for step in 0..10 {
        last = Some(surveyed(fixture, START + step * 10 * S));
    }
    let survey = last.unwrap();
    assert!(!survey.plan.holds.warm_up);
    survey
}

fn state(survey: &Survey, number: u32) -> (ShardState, Option<Blocker>) {
    state_of(&survey.plan, number)
}

fn judgement(survey: &Survey, number: u32) -> VolumeJudgement {
    let shards = &survey.observation.zone.as_ref().unwrap().shards;
    let view = shards.iter().find(|view| view.shard == id(number)).unwrap();
    view.records.as_ref().unwrap().as_ref().unwrap().judgement
}

fn held() -> (ShardState, Option<Blocker>) {
    (ShardState::ReplacementHeld, Some(Blocker::CorrelatedHold))
}

fn replacing() -> (ShardState, Option<Blocker>) {
    (ShardState::Replacing { phase: Phase::Open }, None)
}

fn unconfirmed() -> (ShardState, Option<Blocker>) {
    (ShardState::LossUnconfirmed, Some(Blocker::LossUnconfirmed))
}

fn orphan() -> VolumeId {
    VolumeId::new("vol-0e").unwrap()
}

fn provision(store: &Shared, volume: VolumeId) {
    reconciler(store).provision(volume, layout()).unwrap();
}

fn retire_record(store: &Shared, volume: VolumeId) {
    let mut client = owner(store);
    let read = client.read::<VolumeRecord>(Key::Volume(volume)).unwrap();
    let next = VolumeRecord {
        state: VolumeState::Retired,
        ..read.value().clone()
    };
    client.replace(&read, next).unwrap();
}

fn reads(world: &World) -> Vec<Key> {
    let events = world.events();
    let read = |seen: &Event| match seen {
        Event::Read(key) => Some(*key),
        _ => None,
    };
    events.iter().filter_map(read).collect()
}

/// The census and every read of both shards' records pass; the next read, the first lookup, fails.
fn fail_first_lookup(fixture: &Fixture) {
    for _ in 0..7 {
        fixture.store.schedule(Arm::Pass);
    }
    fixture.store.schedule(Arm::Unavailable);
}

/// The check flags planned provisioning beside another listed volume whose record state is below `Retired` and
/// that meets either condition: its status differs from `Ok`, or its listed state falls outside
/// `{Available, InUse}`.
fn provisions_beside_impairment(survey: &Survey, world: &World, store: &Shared) -> Option<Shard> {
    let mut client = owner(store);
    let mut impaired_cache_volumes = Vec::new();
    for listed in &world.volumes {
        let condition = listed.condition;
        let bad = condition.status != VolumeStatus::Ok
            || !matches!(
                condition.state,
                ListedVolumeState::Available | ListedVolumeState::InUse
            );
        let record = client.read::<VolumeRecord>(Key::Volume(listed.volume));
        let cache = record.is_ok_and(|read| read.value().state < VolumeState::Retired);
        if bad && cache {
            impaired_cache_volumes.push(listed.volume);
        }
    }
    let view = survey.observation.zone.as_ref().ok()?;
    survey.plan.shards.iter().find_map(|plan| {
        let provisions = plan.state == ShardState::Replacing { phase: Phase::Open };
        let active = view.shards.iter().find(|shard| shard.shard == plan.shard)?;
        let active = active.records.as_ref().ok()?.as_ref()?.record.active;
        let beside = impaired_cache_volumes
            .iter()
            .any(|&volume| volume != active);
        (provisions && beside).then_some(plan.shard)
    })
}

#[test]
fn a_loss_beside_an_unread_shard_s_impaired_volume_holds() {
    for (neighbor, expected) in [(impaired(), held()), (in_use(), unconfirmed())] {
        let mut fixture = roomy_fixture(6, 2);
        fixture.world.volume(volume(1), neighbor);
        fixture.world.volume(volume(2), error());
        warmed(&mut fixture);
        fixture.store.schedule(Arm::Pass);
        fixture.store.schedule(Arm::Unavailable);
        let survey = surveyed(&mut fixture, START + 100 * S);
        let shards = &survey.observation.zone.as_ref().unwrap().shards;
        assert!(shards[0].records.is_err(), "shard 1's records are unread");
        let unavailable = Source::Store(StoreError::Unavailable);
        let unobserved = (
            ShardState::Unobserved(unavailable),
            Some(Blocker::StoreUnavailable),
        );
        assert_eq!(state(&survey, 1), unobserved);
        assert_eq!(state(&survey, 2), expected, "{neighbor:?}");
        assert_eq!(judgement(&survey, 2).streak, 0);
        let breach = provisions_beside_impairment(&survey, &fixture.world, &fixture.store);
        assert_eq!(breach, None);
        if expected == held() {
            let mut planted = survey.clone();
            let shard = Shard::new(2).unwrap();
            let row = planted
                .plan
                .shards
                .iter_mut()
                .find(|plan| plan.shard == shard);
            row.unwrap().state = ShardState::Replacing { phase: Phase::Open };
            let caught = provisions_beside_impairment(&planted, &fixture.world, &fixture.store);
            assert_eq!(caught, Some(shard), "the planted control");
        } else {
            let survey = surveyed(&mut fixture, START + 110 * S);
            assert_eq!(state(&survey, 2), unconfirmed(), "one complete view");
            let survey = surveyed(&mut fixture, START + 120 * S);
            assert_eq!(state(&survey, 2), replacing(), "two complete views");
        }
    }
}

#[test]
fn an_unnamed_cache_volume_counts_beside_a_loss_until_its_record_retires() {
    let foreign = VolumeId::new("vol-0d").unwrap();
    let scene = |recorded: bool, retired: bool| {
        let mut fixture = roomy_fixture(6, 2);
        if recorded {
            provision(&fixture.store, orphan());
        }
        if retired {
            retire_record(&fixture.store, orphan());
        }
        let listed = if recorded { orphan() } else { foreign };
        fixture.world.volume(listed, creating());
        fixture.world.volume(volume(2), error());
        let survey = warmed(&mut fixture);
        let breach = provisions_beside_impairment(&survey, &fixture.world, &fixture.store);
        assert_eq!(breach, None, "recorded {recorded}, retired {retired}");
        state(&survey, 2)
    };
    assert_eq!(scene(true, false), held(), "an unnamed cache volume");
    assert_eq!(
        scene(false, false),
        replacing(),
        "a volume of another workload"
    );
    assert_eq!(scene(true, true), replacing(), "a retired cache volume");
}

/// An unnamed cache volume with no status value may be impaired, so an isolated loss beside it waits for its value.
#[test]
fn an_unvalued_unnamed_cache_volume_leaves_an_isolated_loss_unconfirmed() {
    let mut fixture = roomy_fixture(6, 2);
    provision(&fixture.store, orphan());
    fixture.world.volume(orphan(), unvalued());
    fixture.world.volume(volume(2), error());
    let survey = warmed(&mut fixture);
    assert_eq!(state(&survey, 2), unconfirmed());
    let judged = judgement(&survey, 2);
    assert_eq!(
        (judged.others, judged.complete, judged.streak),
        (0, false, 0)
    );
    let breach = provisions_beside_impairment(&survey, &fixture.world, &fixture.store);
    assert_eq!(breach, None);
    fixture.world.volume(orphan(), in_use());
    let survey = surveyed(&mut fixture, START + 100 * S);
    assert_eq!(state(&survey, 2), unconfirmed(), "one complete view");
    let survey = surveyed(&mut fixture, START + 110 * S);
    assert_eq!(state(&survey, 2), replacing(), "two complete views");
}

/// Every impaired or lost unnamed cache volume adds one to the count.
#[test]
fn every_unnamed_impaired_or_lost_cache_volume_counts() {
    let lost = VolumeId::new("vol-0d").unwrap();
    let mut fixture = roomy_fixture(6, 2);
    provision(&fixture.store, orphan());
    provision(&fixture.store, lost);
    fixture.world.volume(orphan(), creating());
    fixture.world.volume(lost, error());
    fixture.world.volume(volume(2), error());
    let survey = warmed(&mut fixture);
    let tick = fixture.zone.ticks;
    assert_eq!(fixture.zone.volumes.health(lost, tick), Some(Health::Lost));
    assert_eq!(state(&survey, 2), held());
    assert_eq!(judgement(&survey, 2).others, 2);
    assert_eq!(judgement(&survey, 1).others, 3);
    let unavailable: Vec<VolumeId> = fixture.zone.volumes.unavailable(tick).collect();
    assert_eq!(unavailable, [lost, orphan(), volume(2)]);
    assert_eq!(fixture.zone.volumes.unavailable(tick + 1).count(), 0);
    fixture.world.faults.volumes = true;
    surveyed(&mut fixture, START + 100 * S);
    let tick = fixture.zone.ticks;
    assert_eq!(fixture.zone.volumes.unavailable(tick).count(), 0);
}

#[test]
fn an_isolated_loss_provisions_after_a_run_of_complete_views() {
    let mut fixture = roomy_fixture(6, 2);
    fixture.world.volume(volume(2), error());
    let survey = warmed(&mut fixture);
    assert_eq!(state(&survey, 2), replacing());
    fixture.world.volume(volume(1), unvalued());
    let survey = surveyed(&mut fixture, START + 100 * S);
    assert_eq!(state(&survey, 2), unconfirmed(), "an incomplete view");
    fixture.world.volume(volume(1), in_use());
    let survey = surveyed(&mut fixture, START + 110 * S);
    assert_eq!(state(&survey, 2), unconfirmed(), "one complete view");
    let survey = surveyed(&mut fixture, START + 111 * S);
    assert_eq!(judgement(&survey, 2).streak, 1, "a repeat inside the tick");
    assert_eq!(state(&survey, 2), unconfirmed(), "a repeat inside the tick");
    let survey = surveyed(&mut fixture, START + 120 * S);
    assert_eq!(judgement(&survey, 2).streak, 2);
    assert_eq!(state(&survey, 2), replacing(), "two complete views");
    let refused = (fixture.zone).survey(Err(Unreachable), &mut fixture.world, START + 130 * S);
    assert!(refused.observation.zone.is_err());
    let survey = surveyed(&mut fixture, START + 140 * S);
    assert_eq!(
        judgement(&survey, 2).streak,
        1,
        "after a failed directory read"
    );
}

/// A call that could not judge a shard gives it no credit for the tick, so a complete retry inside the tick starts
/// no run.
#[test]
fn a_retry_inside_a_tick_after_a_failed_read_of_the_shard_earns_no_credit() {
    let mut fixture = roomy_fixture(6, 2);
    fixture.world.volume(volume(2), error());
    warmed(&mut fixture);
    for _ in 0..4 {
        fixture.store.schedule(Arm::Pass);
    }
    fixture.store.schedule(Arm::Unavailable);
    let survey = surveyed(&mut fixture, START + 100 * S);
    let shards = &survey.observation.zone.as_ref().unwrap().shards;
    assert!(shards[1].records.is_err(), "shard 2's records are unread");
    let survey = surveyed(&mut fixture, START + 101 * S);
    assert_eq!(judgement(&survey, 2).streak, 0, "a retry inside the tick");
    assert_eq!(state(&survey, 2), unconfirmed());
    let survey = surveyed(&mut fixture, START + 110 * S);
    assert_eq!(state(&survey, 2), unconfirmed(), "one complete view");
    let survey = surveyed(&mut fixture, START + 120 * S);
    assert_eq!(state(&survey, 2), replacing(), "two complete views");
}

/// A census slot whose shard record the store does not hold leaves the zone view incomplete.
#[test]
fn a_census_slot_without_its_shard_record_breaks_the_run() {
    let mut fixture = roomy_fixture(6, 2);
    let mut listing = super::directory::listing(6, 3);
    listing.hosts = fixture.listing.as_ref().unwrap().hosts.clone();
    fixture.listing = Some(listing);
    let third = ShardRecord {
        shard: id(3),
        active: volume(3),
        owner: owner_of(3, 6),
        spare: None,
        ..crate::storage::store_tests::record()
    };
    let slot = Entry {
        target: Target::of(&ShardRecord {
            attempts: 1,
            ..third
        }),
        host: host(1),
    };
    let census = crate::failover::standbys::tests::listing(ZONE, id(3), slot);
    let open = Client::open(AsReconciler(fixture.store.clone()), MemLog::default());
    open.unwrap().create(Key::Standbys(ZONE), census).unwrap();
    fixture.world.volume(volume(2), error());
    let survey = warmed(&mut fixture);
    assert!(matches!(
        survey.observation.zone.as_ref().unwrap().shards[2].records,
        Ok(None)
    ));
    assert_eq!(judgement(&survey, 2).streak, 0);
    assert_eq!(state(&survey, 2), unconfirmed());
    let mut provisioner = Reconciler::new(
        Client::open(AsProvisioner(fixture.store.clone()), MemLog::default()).unwrap(),
    );
    provisioner.create_shard(third).unwrap();
    provision(&fixture.store, volume(3));
    let attached = reconciler(&fixture.store).record_attach(volume(3), third.owner, ERA);
    attached.unwrap();
    fixture.world.volume(volume(3), in_use());
    let survey = surveyed(&mut fixture, START + 100 * S);
    assert_eq!(judgement(&survey, 2).streak, 1);
    assert_eq!(state(&survey, 2), unconfirmed(), "one complete view");
    let survey = surveyed(&mut fixture, START + 110 * S);
    assert_eq!(state(&survey, 2), replacing(), "two complete views");
}

/// The run belongs to the active volume it was measured for; a new active volume starts its own.
#[test]
fn a_change_of_active_volume_restarts_the_run() {
    let mut fixture = roomy_fixture(6, 2);
    let gate = StandbyGate::qualified();
    let evidence = (volume(1), Health::Lost);
    let opened = reconciler(&fixture.store).replacement(&gate, id(1), evidence, 0, layout());
    opened.unwrap();
    let spare = fixture.spare();
    fixture.world.volume(spare, error());
    let survey = warmed(&mut fixture);
    let judged = judgement(&survey, 2);
    assert_eq!(
        (judged.health, judged.streak),
        (Some(Health::Available), 10)
    );
    let read = owner(&fixture.store).read::<ShardRecord>(Key::Shard(id(2)));
    let target = Target::of(read.unwrap().value());
    reconciler(&fixture.store)
        .flip(&gate, id(2), target)
        .unwrap();
    let survey = surveyed(&mut fixture, START + 100 * S);
    let records = survey.observation.zone.as_ref().unwrap().shards[1]
        .records
        .as_ref();
    assert_eq!(records.unwrap().as_ref().unwrap().record.active, spare);
    let judged = judgement(&survey, 2);
    assert_eq!((judged.health, judged.others), (Some(Health::Lost), 0));
    assert_eq!(judged.streak, 1);
    assert_eq!(state(&survey, 2), unconfirmed(), "one complete view");
    let survey = surveyed(&mut fixture, START + 110 * S);
    assert_eq!(state(&survey, 2), replacing(), "two complete views");
}

/// Beside another impaired volume, the planner holds a replacement only after consecutive complete views confirm
/// the loss. The hold persists on a later incomplete view while the same active volume reads lost.
#[test]
fn a_correlated_loss_holds_only_once_confirmed() {
    let mut fixture = roomy_fixture(6, 2);
    provision(&fixture.store, orphan());
    fixture.world.volume(orphan(), creating());
    fixture.world.volume(volume(1), unvalued());
    fixture.world.volume(volume(2), error());
    let survey = warmed(&mut fixture);
    let judged = judgement(&survey, 2);
    assert_eq!((judged.others, judged.complete), (1, false));
    assert_eq!(state(&survey, 2), unconfirmed(), "never a complete view");
    fixture.world.volume(volume(1), in_use());
    let survey = surveyed(&mut fixture, START + 100 * S);
    assert_eq!(state(&survey, 2), unconfirmed(), "one complete view");
    let survey = surveyed(&mut fixture, START + 110 * S);
    assert_eq!(state(&survey, 2), held(), "two complete views");
    fixture.world.volume(volume(1), unvalued());
    let survey = surveyed(&mut fixture, START + 120 * S);
    assert!(!judgement(&survey, 2).complete);
    assert_eq!(
        state(&survey, 2),
        held(),
        "a confirmed loss on an incomplete view"
    );
}

/// A confirmed loss holds while the tick counts another impaired volume. On a tick whose only impaired neighbor
/// reads unvalued the count is zero and the view incomplete, so the isolated rule applies and the loss reads
/// unconfirmed. The confirmation carries through that tick: the hold returns on the next tick that counts the
/// neighbor impaired. Beside a neighbor that reads healthy, the loss provisions after a new run of complete views.
#[test]
fn a_confirmed_loss_whose_only_impaired_neighbor_reads_unvalued_takes_the_isolated_rule() {
    let mut fixture = roomy_fixture(6, 2);
    fixture.world.volume(volume(1), impaired());
    fixture.world.volume(volume(2), error());
    let survey = warmed(&mut fixture);
    assert_eq!(state(&survey, 2), held());
    fixture.world.volume(volume(1), unvalued());
    let survey = surveyed(&mut fixture, START + 100 * S);
    let judged = judgement(&survey, 2);
    assert_eq!((judged.others, judged.complete), (0, false));
    assert!(judged.confirmed);
    assert_eq!(state(&survey, 2), unconfirmed(), "an unvalued neighbor");
    fixture.world.volume(volume(1), impaired());
    let survey = surveyed(&mut fixture, START + 110 * S);
    assert_eq!(judgement(&survey, 2).streak, 1);
    assert_eq!(state(&survey, 2), held(), "the neighbor reads impaired");
    fixture.world.volume(volume(1), in_use());
    let survey = surveyed(&mut fixture, START + 120 * S);
    assert_eq!(judgement(&survey, 2).streak, 2);
    assert_eq!(state(&survey, 2), replacing(), "a healthy neighbor");
}

#[test]
fn a_loss_beside_an_impaired_replacement_in_creation_holds() {
    let mut fixture = roomy_fixture(6, 2);
    let mut reconciler = reconciler(&fixture.store);
    let gate = StandbyGate::qualified();
    let shard = Shard::new(1).unwrap();
    let evidence = (volume(1), Health::Lost);
    reconciler
        .replacement(&gate, shard, evidence, 0, layout())
        .unwrap();
    let mut provider = Provisioner::default();
    let created = reconciler.create_replacement(&gate, shard, 0, &mut provider);
    let replacement = created.unwrap().value().volume;
    fixture.world.volume(replacement, creating());
    fixture.world.volume(volume(2), error());
    let survey = warmed(&mut fixture);
    assert_eq!(state(&survey, 2), held());
    let phase = Phase::Created(replacement);
    assert_eq!(state(&survey, 1), (ShardState::Replacing { phase }, None));
    let available = condition(ListedVolumeState::Available, VolumeStatus::Ok);
    fixture.world.volume(replacement, available);
    let survey = surveyed(&mut fixture, START + 100 * S);
    assert_eq!(
        state(&survey, 2),
        replacing(),
        "beside an available replacement"
    );
    fixture
        .world
        .volumes
        .retain(|row| row.volume != replacement);
    let survey = surveyed(&mut fixture, START + 110 * S);
    assert!(
        !judgement(&survey, 2).complete,
        "a replacement its receipt names and the listing omits has no health value"
    );
    assert_eq!(state(&survey, 2), unconfirmed());
}

/// A create whose reply was lost leaves its receipt issued and may have made a volume with no record yet, so a
/// record-less impaired volume beside an issued receipt leaves another shard's isolated loss unconfirmed. The
/// issuer's own view stays complete, so its retry of the same token can settle the create, until a second shard's
/// receipt reads issued too.
#[test]
fn a_record_less_volume_beside_an_issued_receipt_leaves_an_isolated_loss_unconfirmed() {
    let mut fixture = roomy_fixture(6, 2);
    let mut reconciler = reconciler(&fixture.store);
    let gate = StandbyGate::qualified();
    let evidence = (volume(1), Health::Lost);
    reconciler
        .replacement(&gate, id(1), evidence, 0, layout())
        .unwrap();
    let mut provider = Provisioner {
        lose: 1,
        ..Provisioner::default()
    };
    let created = reconciler.create_replacement(&gate, id(1), 0, &mut provider);
    assert!(created.is_err());
    let made = provider.created[0].1;
    let absent = owner(&fixture.store).read::<VolumeRecord>(Key::Volume(made));
    assert!(absent.is_err(), "the create wrote no volume record");
    fixture.world.volume(made, creating());
    fixture.world.volume(volume(2), error());
    let survey = warmed(&mut fixture);
    let issued = ShardState::Replacing {
        phase: Phase::Issued,
    };
    assert_eq!(state(&survey, 1), (issued, None));
    assert!(!judgement(&survey, 2).complete);
    assert_eq!(state(&survey, 2), unconfirmed());
    assert!(
        judgement(&survey, 1).complete,
        "the issuer's own possible product leaves its own view complete"
    );
    let mut other = Provisioner {
        lose: 1,
        ..Provisioner::default()
    };
    fixture.world.volume(volume(2), in_use());
    let evidence = (volume(2), Health::Lost);
    reconciler
        .replacement(&gate, id(2), evidence, 0, layout())
        .unwrap();
    assert!(
        reconciler
            .create_replacement(&gate, id(2), 0, &mut other)
            .is_err()
    );
    let survey = surveyed(&mut fixture, START + 100 * S);
    assert!(
        !judgement(&survey, 1).complete && !judgement(&survey, 2).complete,
        "beside another shard's issued receipt the volume is unknown for both"
    );
}

/// A lookup that fails leaves every judgement incomplete and the tick's store source incomplete.
#[test]
fn a_failed_lookup_of_an_unnamed_volume_breaks_the_run() {
    let mut fixture = roomy_fixture(6, 2);
    provision(&fixture.store, orphan());
    fixture.world.volume(orphan(), impaired());
    fixture.world.volume(volume(2), error());
    assert_eq!(state(&warmed(&mut fixture), 2), held());
    fail_first_lookup(&fixture);
    fixture.world.log.borrow_mut().clear();
    let survey = surveyed(&mut fixture, START + 100 * S);
    let read = reads(&fixture.world);
    assert_eq!(read.len(), 8);
    assert_eq!(read.last(), Some(&Key::Volume(orphan())));
    assert!(!survey.observation.complete.store);
    let shards = &survey.observation.zone.as_ref().unwrap().shards;
    assert!(
        shards
            .iter()
            .all(|shard| matches!(shard.records, Ok(Some(_))))
    );
    let judged = judgement(&survey, 2);
    assert_eq!(
        (judged.others, judged.complete, judged.streak),
        (0, false, 0)
    );
    assert_eq!(state(&survey, 2), unconfirmed());
    retire_record(&fixture.store, orphan());
    let survey = surveyed(&mut fixture, START + 110 * S);
    assert_eq!(state(&survey, 2), unconfirmed(), "one complete view");
    let survey = surveyed(&mut fixture, START + 120 * S);
    assert_eq!(state(&survey, 2), replacing(), "two complete views");
}

/// Warm-up needs a tick whose store reads, the lookups included, all answered.
#[test]
fn warm_up_waits_for_a_tick_whose_lookups_read() {
    let mut fixture = roomy_fixture(6, 2);
    provision(&fixture.store, orphan());
    fixture.world.volume(orphan(), impaired());
    fixture.world.volume(volume(2), error());
    for step in 0..12 {
        fail_first_lookup(&fixture);
        let survey = surveyed(&mut fixture, START + step * 10 * S);
        assert!(!survey.observation.complete.store);
        assert!(survey.plan.holds.warm_up, "step {step}");
    }
    let survey = surveyed(&mut fixture, START + 120 * S);
    assert!(survey.observation.complete.store);
    assert!(!survey.plan.holds.warm_up);
}

/// Commits bytes under `key` that decode as no record, as the key's first version or its next.
fn garble(store: &Shared, key: Key) {
    let mut store = store.clone();
    let held = store.0.borrow().current(&key).map(|item| item.version);
    let value = vec![0xff; 8];
    let write = match held {
        Some(expect) => Write::Exact { expect, value },
        None => Write::Create(value),
    };
    assert!(matches!(store.write(&key, &write), Outcome::Committed(_)));
}

/// Warm-up waits for the reads the plan uses (`Observation::answered`) and not for the count of unnamed volumes.
/// A loop starts beside an unnamed listed volume in `error`. With a stored record that does not decode, the store
/// answered the count's read: the count reads zero and the store flag stays set. With a record whose read the
/// store leaves unanswered on every tick, the count reads unavailable and the status carries the store flag clear
/// beside it. On every tick of either loop `answered` is set, and the loop holds through the settle time and then
/// leaves warm-up.
#[test]
fn warm_up_ends_beside_an_unnamed_volume_whose_record_never_reads() {
    for unanswered in [false, true] {
        let mut fixture = roomy_fixture(6, 2);
        match unanswered {
            true => provision(&fixture.store, orphan()),
            false => garble(&fixture.store, Key::Volume(orphan())),
        }
        fixture.world.volume(orphan(), error());
        let mut last = None;
        for step in 0..10 {
            if unanswered {
                fail_first_lookup(&fixture);
            }
            let survey = surveyed(&mut fixture, START + step * 10 * S);
            let case = format!("unanswered {unanswered}, step {step}");
            let view = survey.observation.zone.as_ref().unwrap();
            let expected = match unanswered {
                true => (None, false),
                false => (Some(0), true),
            };
            assert_eq!(
                (view.unnamed, survey.status.complete.store),
                expected,
                "{case}"
            );
            assert_eq!(
                survey.observation.complete, survey.status.complete,
                "{case}"
            );
            assert!(survey.observation.answered, "{case}");
            if step == 0 {
                assert!(survey.plan.holds.warm_up, "{case}: before the settle time");
            }
            last = Some(survey);
        }
        let last = last.unwrap();
        let warming = (last.plan.holds.warm_up, last.status.holds.warm_up);
        assert_eq!(warming, (false, false), "unanswered {unanswered}");
    }
}

/// A loop that starts with a loss in view beside an unnamed listed volume whose stored record does not decode
/// leaves warm-up on the tick a loop beside a record-less volume does: the store answered the lookup. The volume's
/// membership stays unknown, so the loss stays undecided on every tick, while the loop beside the record-less
/// volume provisions.
#[test]
fn warm_up_ends_beside_a_loss_and_an_unnamed_volume_whose_record_does_not_decode() {
    let mut fixture = roomy_fixture(6, 2);
    let mut control = roomy_fixture(6, 2);
    garble(&fixture.store, Key::Volume(orphan()));
    for fixture in [&mut fixture, &mut control] {
        fixture.world.volume(orphan(), impaired());
        fixture.world.volume(volume(2), error());
    }
    let mut warm = 0;
    for step in 0..60 {
        let now_us = START + step * 10 * S;
        let survey = surveyed(&mut fixture, now_us);
        let expected = surveyed(&mut control, now_us);
        assert!(survey.observation.complete.store, "step {step}");
        let warming = survey.plan.holds.warm_up;
        assert_eq!(warming, expected.plan.holds.warm_up, "step {step}");
        warm += u64::from(warming);
        let judged = judgement(&survey, 2);
        assert!(!judged.complete && !judged.confirmed, "step {step}");
        assert_eq!((judged.others, judged.streak), (0, 0), "step {step}");
        if step > 0 {
            assert_eq!(judged.health, Some(Health::Lost), "step {step}");
            assert_eq!(state(&survey, 2), unconfirmed(), "step {step}");
        }
        if step > 1 {
            assert_eq!(state(&expected, 2), replacing(), "step {step}");
        }
    }
    assert!((1..10).contains(&warm), "{warm} ticks in warm-up");
    let mut client = owner(&fixture.store);
    let read = client.read::<VolumeRecord>(Key::Volume(orphan()));
    assert!(matches!(read, Err(StoreError::Codec(_))));
}

/// A loss confirmed beside shard 1's impaired volume keeps its hold on a tick whose lookup of an unnamed listed
/// volume returns bytes that do not decode: the view is incomplete, the confirmation carries, and the count still
/// holds shard 1's volume.
#[test]
fn a_confirmed_hold_stands_beside_an_unnamed_volume_whose_record_does_not_decode() {
    let mut fixture = roomy_fixture(6, 2);
    fixture.world.volume(volume(1), impaired());
    fixture.world.volume(volume(2), error());
    let survey = warmed(&mut fixture);
    assert_eq!(state(&survey, 2), held());
    garble(&fixture.store, Key::Volume(orphan()));
    fixture.world.volume(orphan(), impaired());
    for step in 10..13 {
        let survey = surveyed(&mut fixture, START + step * 10 * S);
        assert!(survey.observation.complete.store, "step {step}");
        let judged = judgement(&survey, 2);
        assert_eq!((judged.others, judged.complete), (1, false), "step {step}");
        assert_eq!(state(&survey, 2), held(), "step {step}");
    }
}

/// A loss confirmed beside one unnamed impaired cache volume reads held through that volume's lookup. Once the
/// volume's record stops decoding, the volume counts nothing although the listing still shows it impaired: the
/// count is zero on an incomplete view, and the loss reads unconfirmed.
#[test]
fn a_confirmed_hold_ends_when_its_only_counted_neighbor_s_record_stops_decoding() {
    let mut fixture = roomy_fixture(6, 2);
    provision(&fixture.store, orphan());
    fixture.world.volume(orphan(), impaired());
    fixture.world.volume(volume(2), error());
    let survey = warmed(&mut fixture);
    assert_eq!(judgement(&survey, 2).others, 1);
    assert_eq!(state(&survey, 2), held());
    garble(&fixture.store, Key::Volume(orphan()));
    let survey = surveyed(&mut fixture, START + 100 * S);
    assert!(survey.observation.complete.store);
    let judged = judgement(&survey, 2);
    assert_eq!((judged.others, judged.complete), (0, false));
    assert!(judged.confirmed);
    assert_eq!(state(&survey, 2), unconfirmed());
}

/// The directory omits shard 1 while its receipt reads `Open`, so each call with a loss in view rereads that
/// receipt. Once the store answers the reread with bytes that do not decode, the tick's store source stays
/// complete, shard 1 stays a remembered issuer, and shard 2's loss, which provisioned before, stays undecided.
#[test]
fn an_omitted_issuer_s_receipt_that_does_not_decode_leaves_a_loss_unconfirmed() {
    let mut fixture = roomy_fixture(6, 2);
    let gate = StandbyGate::qualified();
    let evidence = (volume(1), Health::Lost);
    reconciler(&fixture.store)
        .replacement(&gate, id(1), evidence, 0, layout())
        .unwrap();
    fixture.world.volume(volume(2), error());
    warmed(&mut fixture);
    let mut reduced = fixture.listing.clone().unwrap();
    reduced.shards.retain(|entry| entry.shard == id(2));
    reduced.version += 1;
    fixture.listing = Some(reduced);
    let survey = surveyed(&mut fixture, START + 100 * S);
    assert_eq!(state(&survey, 2), replacing(), "the receipt reads open");
    let receipt = Key::Replacement(id(1));
    garble(&fixture.store, receipt);
    for step in 11..14 {
        fixture.world.log.borrow_mut().clear();
        let survey = surveyed(&mut fixture, START + step * 10 * S);
        assert_eq!(reads(&fixture.world).last(), Some(&receipt), "step {step}");
        assert!(survey.observation.complete.store, "step {step}");
        assert!(!judgement(&survey, 2).complete, "step {step}");
        assert_eq!(state(&survey, 2), unconfirmed(), "step {step}");
    }
}

/// The records `ZoneLoop::shard_records` reads for a shard.
const SHARD_READS: [&str; 5] = ["shard", "active", "spare", "receipt", "replacement"];

/// Stores what the named read of shard 2 needs and returns the read's key: a spare for `spare`, and a created
/// replacement of a later generation for `replacement`.
fn shard_read(fixture: &mut Fixture, read: &str) -> Key {
    match read {
        "shard" => Key::Shard(id(2)),
        "active" => Key::Volume(volume(2)),
        "spare" => Key::Volume(fixture.spare()),
        "receipt" => Key::Replacement(id(2)),
        "replacement" => {
            let mut reconciler = reconciler(&fixture.store);
            let gate = StandbyGate::qualified();
            let evidence = (volume(2), Health::Lost);
            reconciler
                .replacement(&gate, id(2), evidence, 0, layout())
                .unwrap();
            let created =
                reconciler.create_replacement(&gate, id(2), 0, &mut Provisioner::default());
            Key::Volume(created.unwrap().value().volume)
        }
        other => unreachable!("{other}"),
    }
}

fn unobserved(survey: &Survey, number: u32) -> Option<StoreError> {
    match state(survey, number) {
        (ShardState::Unobserved(Source::Store(error)), Some(Blocker::StoreUnavailable)) => {
            Some(error)
        }
        _ => None,
    }
}

/// For each record a shard read makes, a loop that starts beside stored bytes that do not decode leaves warm-up on
/// the tick a loop whose reads all decode does. The store answered every read, the shard stays unread with the
/// store blocker, and the tick's store flag stays clear.
#[test]
fn warm_up_ends_beside_a_shard_whose_record_does_not_decode() {
    for read in SHARD_READS {
        let mut fixture = roomy_fixture(6, 2);
        let mut control = roomy_fixture(6, 2);
        let key = shard_read(&mut fixture, read);
        shard_read(&mut control, read);
        garble(&fixture.store, key);
        let mut warm = 0;
        for step in 0..30 {
            let now_us = START + step * 10 * S;
            let survey = surveyed(&mut fixture, now_us);
            let expected = surveyed(&mut control, now_us);
            let warming = survey.plan.holds.warm_up;
            assert_eq!(warming, expected.plan.holds.warm_up, "{read} step {step}");
            warm += u64::from(warming);
            let observation = &survey.observation;
            assert!(observation.answered, "{read} step {step}");
            assert!(!observation.complete.store, "{read} step {step}");
            let error = unobserved(&survey, 2);
            assert!(
                matches!(error, Some(StoreError::Codec(_))),
                "{read} {error:?}"
            );
        }
        assert!((1..10).contains(&warm), "{read}: {warm} ticks in warm-up");
    }
}

/// The control of the decode rule: while the store leaves the same read unanswered on every tick, warm-up holds,
/// and it ends on the first tick whose reads all answer.
#[test]
fn warm_up_waits_while_a_read_of_a_shard_s_records_goes_unanswered() {
    for read in SHARD_READS {
        let mut fixture = roomy_fixture(6, 2);
        let mut twin = roomy_fixture(6, 2);
        shard_read(&mut fixture, read);
        let key = shard_read(&mut twin, read);
        twin.world.log.borrow_mut().clear();
        surveyed(&mut twin, START);
        let reads = reads(&twin.world);
        let index = reads.iter().position(|seen| *seen == key).unwrap();
        for step in 0..30 {
            for _ in 0..index {
                fixture.store.schedule(Arm::Pass);
            }
            fixture.store.schedule(Arm::Unavailable);
            let survey = surveyed(&mut fixture, START + step * 10 * S);
            assert!(!survey.observation.answered, "{read} step {step}");
            assert!(survey.plan.holds.warm_up, "{read} step {step}");
            let error = unobserved(&survey, 2);
            assert_eq!(error, Some(StoreError::Unavailable), "{read} step {step}");
        }
        let survey = surveyed(&mut fixture, START + 300 * S);
        assert!(survey.observation.answered, "{read}");
        assert!(!survey.plan.holds.warm_up, "{read}");
    }
}

/// A census that does not decode leaves the zone unobserved, so warm-up holds on every tick.
#[test]
fn warm_up_waits_beside_a_census_that_does_not_decode() {
    let mut fixture = roomy_fixture(6, 2);
    garble(&fixture.store, Key::Standbys(ZONE));
    for step in 0..30 {
        let survey = surveyed(&mut fixture, START + step * 10 * S);
        let source = survey.observation.unobserved();
        let undecoded = matches!(source, Some(Source::Store(StoreError::Codec(_))));
        assert!(undecoded, "step {step}: {source:?}");
        assert!(!survey.observation.answered, "step {step}");
        assert!(survey.plan.holds.warm_up, "step {step}");
    }
}

/// Once warm-up has ended beside a shard whose record does not decode, the plan treats that shard as it treats any
/// unread shard. It decides no isolated loss: shard 2's lost volume, which provisions in a loop that reads shard
/// 1, stays unconfirmed. It charges the unread shard as a role of every host: with one role per host, shard 2
/// finds no standby candidate, and with room it reserves one.
#[test]
fn the_plan_beside_a_shard_whose_record_does_not_decode_decides_no_loss_and_charges_its_role() {
    let planned = |garbled: bool, lost: bool, roles_max: u32| {
        let mut fixture = roomy_fixture(6, 2);
        let mut listing = fixture.listing.clone().unwrap();
        listing.host_roles_max = roles_max;
        fixture.listing = Some(listing);
        if garbled {
            garble(&fixture.store, Key::Shard(id(1)));
        }
        if lost {
            fixture.world.volume(volume(2), error());
        }
        let survey = warmed(&mut fixture);
        let undecoded = matches!(unobserved(&survey, 1), Some(StoreError::Codec(_)));
        assert_eq!(undecoded, garbled);
        survey
    };
    let survey = planned(true, true, 10);
    assert_eq!(state(&survey, 2), unconfirmed());
    let judged = judgement(&survey, 2);
    assert_eq!(judged.health, Some(Health::Lost));
    assert!(!judged.complete && judged.streak == 0);
    assert_eq!(state(&planned(false, true, 10), 2), replacing());

    assert_eq!(reserves(&planned(true, false, 10).plan), [(2, 2)]);
    let full = planned(true, false, 1);
    assert!(reserves(&full.plan).is_empty());
    let capped = (ShardState::NoCandidate, Some(Blocker::PerHostCap));
    assert_eq!(state(&full, 2), capped);
    assert_eq!(reserves(&planned(false, false, 1).plan), [(1, 1), (2, 4)]);
}

#[test]
fn a_failed_census_reads_no_unnamed_volume() {
    let mut fixture = roomy_fixture(6, 2);
    provision(&fixture.store, orphan());
    fixture.world.volume(orphan(), impaired());
    fixture.store.schedule(Arm::Unavailable);
    fixture.world.log.borrow_mut().clear();
    let survey = surveyed(&mut fixture, START);
    assert!(survey.observation.unobserved().is_some());
    assert_eq!(reads(&fixture.world), [Key::Standbys(ZONE)]);
}

/// The lookups come last, ascending. A call whose judgements can reach a loss decision reads one per unnamed volume
/// whose health reads impaired, lost or unvalued. Any other call reads, for the count of unnamed volumes, one per
/// unnamed volume that reads impaired or lost, a volume it found with no record included on each call. A volume a
/// read record shows retired is read once, in its shard's reads.
#[test]
fn the_lookups_follow_the_shard_reads_in_ascending_order() {
    let named = ["vol-0e", "vol-0d", "vol-0c", "vol-0b"].map(|id| VolumeId::new(id).unwrap());
    let [late, early, absent, healthy] = named;
    for erring in [false, true] {
        let mut fixture = roomy_fixture(6, 2);
        for volume in [late, early, healthy] {
            provision(&fixture.store, volume);
        }
        let spare = fixture.spare();
        retire_record(&fixture.store, spare);
        fixture.world.volume(spare, impaired());
        fixture.world.volume(late, impaired());
        fixture.world.volume(early, unvalued());
        fixture.world.volume(absent, creating());
        fixture.world.volume(healthy, in_use());
        if erring {
            fixture.world.volume(volume(1), error());
        }
        fixture.world.log.borrow_mut().clear();
        surveyed(&mut fixture, START);
        let mut expected = vec![
            Key::Standbys(ZONE),
            Key::Shard(id(1)),
            Key::Volume(volume(1)),
            Key::Replacement(id(1)),
            Key::Shard(id(2)),
            Key::Volume(volume(2)),
            Key::Volume(spare),
            Key::Replacement(id(2)),
        ];
        let shard_reads = expected.clone();
        match erring {
            true => expected.extend([absent, early, late].map(Key::Volume)),
            false => expected.extend([absent, late].map(Key::Volume)),
        }
        assert_eq!(reads(&fixture.world), expected, "erring {erring}");
        if !erring {
            fixture.world.log.borrow_mut().clear();
            surveyed(&mut fixture, START + 10 * S);
            let mut again = shard_reads;
            again.extend([absent, late].map(Key::Volume));
            assert_eq!(reads(&fixture.world), again, "the second call");
        }
    }
}

/// A call that skips the lookups gives no shard credit, so a run starts with the first call whose count covered the
/// unnamed volumes.
#[test]
fn a_call_without_lookups_earns_no_credit() {
    let mut fixture = roomy_fixture(6, 2);
    provision(&fixture.store, orphan());
    fixture.world.volume(orphan(), unvalued());
    let survey = warmed(&mut fixture);
    assert_eq!(judgement(&survey, 2).streak, 0);
    fixture.world.volume(orphan(), in_use());
    fixture.world.volume(volume(2), error());
    let survey = surveyed(&mut fixture, START + 100 * S);
    assert_eq!(
        judgement(&survey, 2).streak,
        1,
        "the first call with lookups"
    );
}

/// A failed lookup leaves the later lookups in place, and their impaired volumes still count.
#[test]
fn a_failed_lookup_keeps_the_later_lookups() {
    let first = VolumeId::new("vol-0d").unwrap();
    let mut fixture = roomy_fixture(6, 2);
    provision(&fixture.store, first);
    provision(&fixture.store, orphan());
    fixture.world.volume(first, impaired());
    fixture.world.volume(orphan(), impaired());
    fixture.world.volume(volume(2), error());
    assert_eq!(state(&warmed(&mut fixture), 2), held());
    fail_first_lookup(&fixture);
    fixture.world.log.borrow_mut().clear();
    let survey = surveyed(&mut fixture, START + 100 * S);
    let read = reads(&fixture.world);
    assert_eq!(read[7..], [Key::Volume(first), Key::Volume(orphan())]);
    assert!(!survey.observation.complete.store);
    let judged = judgement(&survey, 2);
    assert_eq!((judged.others, judged.complete), (1, false));
    assert_eq!(
        state(&survey, 2),
        held(),
        "a confirmed loss beside the later volume"
    );
}

/// A directory shard the store holds no record of and the census holds no slot for leaves its peers' runs intact.
#[test]
fn a_directory_shard_with_no_record_and_no_slot_keeps_the_run() {
    let mut fixture = roomy_fixture(6, 2);
    let mut listing = super::directory::listing(6, 3);
    listing.hosts = fixture.listing.as_ref().unwrap().hosts.clone();
    fixture.listing = Some(listing);
    fixture.world.volume(volume(2), error());
    let survey = warmed(&mut fixture);
    let shards = &survey.observation.zone.as_ref().unwrap().shards;
    assert!(matches!(shards[2].records, Ok(None)));
    assert!(judgement(&survey, 2).streak >= 2);
    assert_eq!(state(&survey, 2), replacing());
}

/// A census read that fails gives every shard no credit for its tick, so a retry inside the tick starts no run.
#[test]
fn a_retry_inside_a_tick_after_a_failed_census_earns_no_credit() {
    let mut fixture = roomy_fixture(6, 2);
    fixture.world.volume(volume(2), error());
    warmed(&mut fixture);
    fixture.store.schedule(Arm::Unavailable);
    let survey = surveyed(&mut fixture, START + 100 * S);
    assert!(survey.observation.unobserved().is_some());
    let survey = surveyed(&mut fixture, START + 101 * S);
    assert_eq!(judgement(&survey, 2).streak, 0, "a retry inside the tick");
    assert_eq!(state(&survey, 2), unconfirmed());
    let survey = surveyed(&mut fixture, START + 110 * S);
    assert_eq!(state(&survey, 2), unconfirmed(), "one complete view");
    let survey = surveyed(&mut fixture, START + 120 * S);
    assert_eq!(state(&survey, 2), replacing(), "two complete views");
}

/// A shard that leaves the directory and returns inside one tick starts from that tick's unjudged run.
#[test]
fn a_shard_relisted_inside_a_tick_earns_no_credit_for_it() {
    let mut fixture = roomy_fixture(6, 2);
    fixture.world.volume(volume(2), error());
    warmed(&mut fixture);
    let full = fixture.listing.clone().unwrap();
    let mut reduced = full.clone();
    reduced.shards.retain(|entry| entry.shard == id(1));
    reduced.version = full.version + 1;
    fixture.listing = Some(reduced);
    let survey = surveyed(&mut fixture, START + 100 * S);
    assert_eq!(survey.observation.zone.as_ref().unwrap().shards.len(), 1);
    let mut relisted = full;
    relisted.version += 2;
    fixture.listing = Some(relisted);
    let survey = surveyed(&mut fixture, START + 101 * S);
    assert_eq!(judgement(&survey, 2).streak, 0, "relisted inside the tick");
    assert_eq!(state(&survey, 2), unconfirmed());
    let survey = surveyed(&mut fixture, START + 110 * S);
    assert_eq!(state(&survey, 2), unconfirmed(), "one complete view");
    let survey = surveyed(&mut fixture, START + 120 * S);
    assert_eq!(state(&survey, 2), replacing(), "two complete views");
}

/// With `loss_ticks` 3, a loss beside another impaired volume confirms on the third complete view, not the second.
#[test]
fn a_correlated_loss_confirms_on_the_configured_run() {
    let mut fixture = roomy_fixture(6, 2);
    let mut config = config_of(8);
    config.loss_ticks = 3;
    let bounds = config.validate().unwrap();
    let recording = Recording {
        inner: AsReconciler(fixture.store.clone()),
        log: fixture.world.log.clone(),
    };
    let client = Client::open(recording, MemLog::default()).unwrap();
    fixture.zone = ZoneLoop::new(Reconciler::new(client), bounds);
    provision(&fixture.store, orphan());
    fixture.world.volume(orphan(), creating());
    fixture.world.volume(volume(1), unvalued());
    fixture.world.volume(volume(2), error());
    let survey = warmed(&mut fixture);
    assert_eq!(judgement(&survey, 2).health, Some(Health::Lost));
    fixture.world.volume(volume(1), in_use());
    for (step, views) in [(10, 1), (11, 2)] {
        let survey = surveyed(&mut fixture, START + step * 10 * S);
        let judged = judgement(&survey, 2);
        assert_eq!((judged.streak, judged.confirmed), (views, false));
        assert_eq!(state(&survey, 2), unconfirmed(), "{views} complete views");
    }
    let survey = surveyed(&mut fixture, START + 120 * S);
    let judged = judgement(&survey, 2);
    assert_eq!((judged.streak, judged.confirmed), (3, true));
    assert_eq!(state(&survey, 2), held(), "three complete views");
}

/// An issued receipt at the shard's own generation, after a flip to another spare, still marks a record-less volume
/// as a possible product of its create.
#[test]
fn an_issued_receipt_at_the_shard_s_generation_keeps_a_record_less_volume_unknown() {
    let mut fixture = roomy_fixture(6, 2);
    let gate = StandbyGate::qualified();
    let mut reconciler = reconciler(&fixture.store);
    let evidence = (volume(2), Health::Lost);
    reconciler
        .replacement(&gate, id(2), evidence, 0, layout())
        .unwrap();
    let mut provider = Provisioner {
        lose: 1,
        ..Provisioner::default()
    };
    let created = reconciler.create_replacement(&gate, id(2), 0, &mut provider);
    assert!(created.is_err());
    let made = provider.created[0].1;
    let spare = fixture.spare();
    let read = owner(&fixture.store).read::<ShardRecord>(Key::Shard(id(2)));
    let target = Target::of(read.unwrap().value());
    reconciler.flip(&gate, id(2), target).unwrap();
    let shard = owner(&fixture.store).read::<ShardRecord>(Key::Shard(id(2)));
    let shard = *shard.unwrap().value();
    let receipt =
        owner(&fixture.store).read::<crate::failover::loss::Receipt>(Key::Replacement(id(2)));
    let receipt = receipt.unwrap().value().clone();
    assert_eq!((shard.active, receipt.phase), (spare, Phase::Issued));
    assert_eq!(receipt.request.generation, shard.generation);
    fixture.world.volume(spare, in_use());
    fixture.world.volume(made, creating());
    fixture.world.volume(volume(1), error());
    let survey = warmed(&mut fixture);
    assert!(!judgement(&survey, 1).complete);
    assert_eq!(state(&survey, 1), unconfirmed());
    assert!(
        !judgement(&survey, 2).complete,
        "the issuer's own view too: its receipt is of a generation its record already holds"
    );
    let available = condition(ListedVolumeState::Available, VolumeStatus::Ok);
    fixture.world.volume(made, available);
    surveyed(&mut fixture, START + 100 * S);
    let survey = surveyed(&mut fixture, START + 110 * S);
    assert_eq!(state(&survey, 1), replacing(), "beside an available volume");
}

/// Two calls at one instant share a tick at the smallest admitted period, so they count one error observation and
/// one complete view.
#[test]
fn calls_at_one_instant_share_a_tick_at_a_one_microsecond_period() {
    let mut fixture = roomy_fixture(6, 2);
    let mut config = config_of(8);
    config.tick_us = 1;
    let bounds = config.validate().unwrap();
    assert_eq!(bounds.config().loss_ticks, 2);
    let recording = Recording {
        inner: AsReconciler(fixture.store.clone()),
        log: fixture.world.log.clone(),
    };
    let client = Client::open(recording, MemLog::default()).unwrap();
    fixture.zone = ZoneLoop::new(Reconciler::new(client), bounds);
    fixture.world.volume(volume(2), error());
    for _ in 0..2 {
        let survey = surveyed(&mut fixture, START);
        let judged = judgement(&survey, 2);
        assert_eq!((judged.health, judged.streak), (Some(Health::Impaired), 1));
        assert_eq!(state(&survey, 2).0, ShardState::VolumeImpaired);
    }
    let survey = surveyed(&mut fixture, START + 1);
    let judged = judgement(&survey, 2);
    assert_eq!((judged.health, judged.streak), (Some(Health::Lost), 2));
    assert_eq!(state(&survey, 2), replacing());
}

/// Shard 1's unresolved create blocks shard 2's replacement after the directory drops shard 1. The create lost its
/// reply and made a volume with no record, and the zone listing shows that volume in state `error`. In the `Issued`
/// history the create runs before the loop's first call. In the `Open` history the create runs after two calls
/// with shard 1 delisted, so each earlier receipt read returned `Open`. After a receipt reread fails, the tick
/// clears its store flag and continues to the volume lookup. The survey plans shard 2's replacement
/// once the receipt leaves `Issued` and the volume's record reads retired. The control lists a record-less volume
/// from another workload. With shard 1's receipt absent, the survey plans shard 2's replacement.
#[test]
fn an_unresolved_create_counts_after_its_issuer_leaves_the_directory() {
    let history = |seen: Option<Phase>| {
        let mut fixture = roomy_fixture(6, 2);
        let mut reconciler = reconciler(&fixture.store);
        let gate = StandbyGate::qualified();
        let mut provider = Provisioner {
            lose: 1,
            ..Provisioner::default()
        };
        if seen.is_some() {
            let evidence = (volume(1), Health::Lost);
            reconciler
                .replacement(&gate, id(1), evidence, 0, layout())
                .unwrap();
        }
        let mut made = orphan();
        if seen == Some(Phase::Issued) {
            let created = reconciler.create_replacement(&gate, id(1), 0, &mut provider);
            assert!(created.is_err());
            made = provider.created[0].1;
        }
        if seen != Some(Phase::Open) {
            fixture.world.volume(made, error());
        }
        fixture.world.volume(volume(2), error());
        let survey = warmed(&mut fixture);
        let listed = state(&survey, 2);
        if seen == Some(Phase::Open) {
            let open = ShardState::Replacing { phase: Phase::Open };
            assert_eq!(
                state(&survey, 1),
                (open, None),
                "the loop's last shard read"
            );
        }
        let mut reduced = fixture.listing.clone().unwrap();
        reduced.shards.retain(|entry| entry.shard == id(2));
        reduced.version += 1;
        fixture.listing = Some(reduced);
        let mut omitted = Vec::new();
        for step in 10..16 {
            if seen == Some(Phase::Open) && step == 12 {
                let created = reconciler.create_replacement(&gate, id(1), 0, &mut provider);
                assert!(created.is_err());
                made = provider.created[0].1;
                fixture.world.volume(made, error());
            }
            let survey = surveyed(&mut fixture, START + step * 10 * S);
            assert_eq!(survey.observation.zone.as_ref().unwrap().shards.len(), 1);
            omitted.push(state(&survey, 2));
        }
        (fixture, reconciler, provider, made, listed, omitted)
    };

    let held = [unconfirmed(); 6];
    let mut late = held;
    late[..2].fill(replacing());
    for (phase, at_listing, after) in [
        (Phase::Issued, unconfirmed(), held),
        (Phase::Open, replacing(), late),
    ] {
        let (mut fixture, mut reconciler, mut provider, made, listed, omitted) =
            history(Some(phase));
        assert_eq!(listed, at_listing, "while listed, last read {phase:?}");
        assert_eq!(omitted, after, "once omitted, last read {phase:?}");
        let expected = [
            Key::Standbys(ZONE),
            Key::Shard(id(2)),
            Key::Volume(volume(2)),
            Key::Replacement(id(2)),
            Key::Replacement(id(1)),
            Key::Volume(made),
        ];
        for (step, answered) in [(16, false), (17, true)] {
            if !answered {
                for _ in 0..4 {
                    fixture.store.schedule(Arm::Pass);
                }
                fixture.store.schedule(Arm::Unavailable);
            }
            fixture.world.log.borrow_mut().clear();
            let survey = surveyed(&mut fixture, START + step * 10 * S);
            assert_eq!(reads(&fixture.world), expected, "one reread, {phase:?}");
            assert_eq!(survey.observation.complete.store, answered, "{phase:?}");
            assert!(!judgement(&survey, 2).complete, "{phase:?}");
            assert_eq!(state(&survey, 2), unconfirmed(), "{phase:?}");
        }
        let gate = StandbyGate::qualified();
        let settled = reconciler.create_replacement(&gate, id(1), 0, &mut provider);
        assert!(settled.is_ok(), "{settled:?}");
        assert_eq!(
            provider.created.len(),
            1,
            "the same token names the same volume"
        );
        reconciler.retire(id(1), made).unwrap();
        let states: Vec<_> = (18..22)
            .map(|step| state(&surveyed(&mut fixture, START + step * 10 * S), 2))
            .collect();
        assert_eq!(states.last(), Some(&replacing()), "{phase:?}: {states:?}");
    }

    let (_, _, _, _, listed, omitted) = history(None);
    assert_eq!(listed, replacing(), "a volume of another workload, listed");
    assert_eq!(omitted.last(), Some(&replacing()), "{omitted:?}");
}

/// The count of unnamed volumes: a listed volume that reads impaired or lost, holds a record short of retired and is
/// named by no read shard record counts one, on a call that looks volumes up for a loss and on a call that does
/// not. A named impaired volume, a volume whose record reads retired and a volume with no record count nothing. A
/// retired record is read once for its volume's stay in the listing and a volume with no record on every call. A
/// call whose shard read or count read
/// fails reads the count unavailable, in the view and in the status part. A count read the store leaves unanswered
/// clears the store flag and leaves `Observation::answered` set.
#[test]
fn the_unnamed_count_reads_impaired_cache_volumes_no_shard_names() {
    let mut fixture = roomy_fixture(6, 2);
    let unnamed = |survey: &Survey| {
        let (observed, reported) = (survey.observation.complete, survey.status.complete);
        assert_eq!(
            observed, reported,
            "the status carries the observation's flags"
        );
        survey.observation.zone.as_ref().unwrap().unnamed
    };
    let lookups = |fixture: &Fixture, from: usize, volume: VolumeId| {
        let read = &reads(&fixture.world)[from..];
        read.iter()
            .filter(|key| **key == Key::Volume(volume))
            .count()
    };
    let mut at = START + 90 * S;
    let next = |fixture: &mut Fixture, at: &mut u64| {
        *at += 10 * S;
        surveyed(fixture, *at)
    };
    assert_eq!(unnamed(&warmed(&mut fixture)), Some(0));
    fixture.world.volume(volume(2), impaired());
    assert_eq!(
        unnamed(&next(&mut fixture, &mut at)),
        Some(0),
        "a named volume"
    );
    fixture.world.volume(volume(2), in_use());

    provision(&fixture.store, orphan());
    fixture.world.volume(orphan(), in_use());
    assert_eq!(
        unnamed(&next(&mut fixture, &mut at)),
        Some(0),
        "an available volume"
    );
    fixture.world.volume(orphan(), impaired());
    assert_eq!(unnamed(&next(&mut fixture, &mut at)), Some(1), "impaired");
    fixture.world.volume(orphan(), error());
    assert_eq!(unnamed(&next(&mut fixture, &mut at)), Some(1), "in error");
    fixture.world.volume(volume(2), error());
    let beside = next(&mut fixture, &mut at);
    assert_eq!(judgement(&beside, 2).others, 1);
    assert_eq!(
        unnamed(&beside),
        Some(1),
        "on a call that looks up for a loss"
    );
    fixture.world.volume(volume(2), in_use());

    fixture.store.schedule(Arm::Pass);
    fixture.store.schedule(Arm::Unavailable);
    let unread = next(&mut fixture, &mut at);
    let shards = &unread.observation.zone.as_ref().unwrap().shards;
    assert!(shards.iter().any(|shard| shard.records.is_err()));
    assert_eq!(unnamed(&unread), None, "a failed shard read");
    fail_first_lookup(&fixture);
    let failed = next(&mut fixture, &mut at);
    assert_eq!(unnamed(&failed), None, "a failed count read");
    assert!(
        !failed.observation.complete.store,
        "the store flag is clear for the count that did not read"
    );
    assert!(
        failed.observation.answered,
        "the reads the plan uses were answered"
    );
    assert_eq!(failed.status.unnamed, None);
    at += 10 * S;
    fixture.store.schedule(Arm::Pass);
    fixture.store.schedule(Arm::Unavailable);
    let directory = Ok(fixture.directory());
    let part = fixture.zone.tick(directory, &mut fixture.world, at).part;
    assert_eq!(
        part.unnamed_volumes, None,
        "the part of a failed shard read"
    );
    at += 10 * S;
    fail_first_lookup(&fixture);
    let directory = Ok(fixture.directory());
    let part = fixture.zone.tick(directory, &mut fixture.world, at).part;
    assert_eq!(
        (part.unnamed_volumes, part.flags.store, part.flags.warm_up),
        (None, false, false),
        "the part of a failed count read"
    );
    at += 10 * S;
    let directory = Ok(fixture.directory());
    let part = fixture.zone.tick(directory, &mut fixture.world, at).part;
    assert_eq!((part.unnamed_volumes, part.flags.store), (Some(1), true));

    retire_record(&fixture.store, orphan());
    let before = reads(&fixture.world).len();
    for _ in 0..3 {
        assert_eq!(
            unnamed(&next(&mut fixture, &mut at)),
            Some(0),
            "a retired record"
        );
    }
    assert_eq!(
        lookups(&fixture, before, orphan()),
        1,
        "a retired record is read once"
    );
    let foreign = VolumeId::new("vol-0d").unwrap();
    fixture.world.volume(foreign, error());
    let before = reads(&fixture.world).len();
    for _ in 0..3 {
        assert_eq!(unnamed(&next(&mut fixture, &mut at)), Some(0), "no record");
    }
    assert_eq!(
        lookups(&fixture, before, foreign),
        3,
        "a volume with no record is read on each call"
    );
}

/// The count follows a volume's current record: a listed volume in `error` with no record counts nothing, and once
/// a record short of retired is written for it the next call counts it, on a call that skips the lookups and on
/// the call after one that ran them, for the three statuses the `volume-unnamed` row needs.
#[test]
fn a_recordless_volume_counts_once_its_record_is_written() {
    for loss_between in [false, true] {
        let mut fixture = roomy_fixture(6, 2);
        let unnamed = |survey: &Survey| survey.observation.zone.as_ref().unwrap().unnamed;
        let mut at = START + 90 * S;
        let next = |fixture: &mut Fixture, at: &mut u64| {
            *at += 10 * S;
            surveyed(fixture, *at)
        };
        assert_eq!(unnamed(&warmed(&mut fixture)), Some(0));
        fixture.world.volume(orphan(), error());
        assert_eq!(unnamed(&next(&mut fixture, &mut at)), Some(0), "no record");
        if loss_between {
            fixture.world.volume(volume(2), error());
            let beside = next(&mut fixture, &mut at);
            assert_eq!(
                (unnamed(&beside), judgement(&beside, 2).others),
                (Some(0), 0)
            );
            fixture.world.volume(volume(2), in_use());
        }
        provision(&fixture.store, orphan());
        for step in 0..3 {
            let counted = unnamed(&next(&mut fixture, &mut at));
            assert_eq!(counted, Some(1), "loss between {loss_between}, step {step}");
        }
    }
}

/// A confirmation counts lost readings alone. Shard 2's active volume reads impaired through a full run of complete
/// views beside an impaired peer, while shard 1's receipt keeps the lookups running. Its first lost reading then
/// lands on an incomplete view: the loss reads unconfirmed and no hold is planned. The control is the same history
/// with that view complete, which confirms the loss and plans the hold.
#[test]
fn an_impaired_run_confirms_no_loss_at_the_first_lost_reading() {
    let history = |incomplete: bool| {
        let mut fixture = roomy_fixture(6, 2);
        let gate = StandbyGate::qualified();
        let evidence = (volume(1), Health::Lost);
        reconciler(&fixture.store)
            .replacement(&gate, id(1), evidence, 0, layout())
            .unwrap();
        provision(&fixture.store, orphan());
        fixture.world.volume(orphan(), creating());
        fixture.world.volume(volume(2), impaired());
        let survey = warmed(&mut fixture);
        let before = judgement(&survey, 2);
        assert_eq!(before.health, Some(Health::Impaired));
        assert!(
            before.streak >= 2 && before.others > 0 && !before.confirmed,
            "{before:?}"
        );
        fixture.world.volume(volume(2), error());
        let survey = surveyed(&mut fixture, START + 100 * S);
        assert_eq!(
            judgement(&survey, 2).health,
            Some(Health::Impaired),
            "one error listing"
        );
        if incomplete {
            fixture.world.volume(volume(1), unvalued());
        }
        let survey = surveyed(&mut fixture, START + 110 * S);
        let first = judgement(&survey, 2);
        assert_eq!(first.health, Some(Health::Lost), "the first lost reading");
        assert!(
            first.others > 0 && first.complete != incomplete,
            "{first:?}"
        );
        let next = surveyed(&mut fixture, START + 120 * S);
        (first, state(&survey, 2), state(&next, 2))
    };
    let (first, at_first, _) = history(true);
    assert!(!first.confirmed, "{first:?}");
    assert_eq!(at_first, unconfirmed());
    let (first, at_first, at_second) = history(false);
    assert!(
        first.confirmed,
        "a complete view of a full run confirms: {first:?}"
    );
    assert_eq!((at_first, at_second), (held(), held()));
}
