use std::collections::BTreeSet;

use crate::failover::loss::{CreateError, Decision, Phase, Provider, Receipt};
use crate::failover::reconcile::{OperatorRelease, ReconcileError, Reconciler, StandbyGate};
use crate::failover::records::{
    EventKind, Record, ShardRecord, VolumeId, VolumeRecord, VolumeState,
};
use crate::failover::report::alarm_tests::controls::slot as at;
use crate::failover::report::status::{CREATES, Create, DECISIONS, Decided};
use crate::failover::zone_loop::actuate::{Outcome, Reason, Verdict};
use crate::failover::zone_loop::evidence::{ListedVolumeState, VolumeStatus};
use crate::failover::zone_loop::plan::{Step, Survey};
use crate::failover::zone_loop::replace::Replaced;
use crate::failover::zone_loop::status::{Blocker, ShardState};
use crate::storage::store::Key;
use crate::storage::store::sim::{Arm, AsReconciler, MemLog, Shared};

use super::actuate::{After, Cell, Faults, Hook, reconciler_client, shard, stored};
use super::observe::{S, condition, error, in_use, volume};
use super::world::{AttachFault, Provisioner};

fn warning() -> crate::failover::zone_loop::evidence::VolumeCondition {
    condition(ListedVolumeState::InUse, VolumeStatus::Warning)
}

fn receipt(cell: &Cell, number: u32) -> Option<Receipt> {
    let key = Key::Replacement(shard(number));
    let item = cell.store().0.borrow().current(&key).cloned();
    item.map(|item| Receipt::decode(&item.value).unwrap())
}

fn record_of(cell: &Cell, volume: VolumeId) -> VolumeRecord {
    stored(cell.store(), Key::Volume(volume))
}

fn effects(outcomes: &[Outcome]) -> Vec<Replaced> {
    let advanced = outcomes
        .iter()
        .filter(|outcome| outcome.verdict == Verdict::Advance);
    advanced.filter_map(|outcome| outcome.replaced).collect()
}

fn made(cell: &Cell) -> Vec<(String, VolumeId)> {
    cell.fixture.world.provider.created.clone()
}

/// Shard 1's record before its loss, with shard 2's record at the same time.
struct Lost {
    record: ShardRecord,
    other: ShardRecord,
}

impl core::ops::Deref for Lost {
    type Target = ShardRecord;

    fn deref(&self) -> &ShardRecord {
        &self.record
    }
}

/// A designated two-shard zone whose shard 1 then reads its active volume in `error`.
fn lost_zone() -> (Cell, Lost) {
    let mut cell = Cell::new(4, 2);
    cell.run_until(80, Cell::designated);
    let lost = Lost {
        record: cell.shard(1),
        other: cell.shard(2),
    };
    cell.fixture.world.volume(volume(1), error());
    (cell, lost)
}

fn flipped(cell: &Cell, lost: &ShardRecord) -> bool {
    cell.shard(1).generation > lost.generation
}

/// The provider calls of the loop's world.
fn calls(cell: &Cell) -> usize {
    cell.fixture.world.provider.calls
}

/// The CREATE-AFTER-ISSUE and FLIP-ENTRY oracle over the store: the provider made one volume, under the receipt's
/// token, the store committed one flip in the zone, from the lost generation, to the volume the receipt records as
/// created, shard 2 kept the generation and
/// active volume it held before the loss, and the flip found the displaced volume retired. With `cut`, the process
/// stopped after the flip committed and before the displaced volume's retired state, and that volume reads active
/// and named by no shard, since a restarted loop has no memory of the flip.
fn replaced_once(cell: &Cell, lost: &Lost, cut: bool) -> Result<(), String> {
    let now = cell.shard(1);
    if now.generation.get() != lost.generation.get() + 1 {
        return Err(format!(
            "generation {} from {}",
            now.generation.get(),
            lost.generation.get()
        ));
    }
    let made = made(cell);
    if made.len() != 1 {
        return Err(format!("made {made:?}"));
    }
    let flips = cell.store().0.borrow().flips.clone();
    if flips != [lost.generation.get()] {
        return Err(format!("committed flips from generations {flips:?}"));
    }
    let receipt = receipt(cell, 1).ok_or("no receipt")?;
    if receipt.phase != Phase::Created(now.active) || made[0].1 != now.active {
        return Err(format!("receipt {receipt:?}, active {:?}", now.active));
    }
    if receipt.token() != made[0].0 {
        return Err(format!("token {} made the volume", made[0].0));
    }
    let displaced = record_of(cell, lost.active).state;
    let other = cell.shard(2);
    let expected = match cut {
        true => VolumeState::Active,
        false => VolumeState::Retired,
    };
    if displaced != expected || other.active == lost.active {
        return Err(format!("displaced volume {displaced:?}"));
    }
    if (other.generation, other.active) != (lost.other.generation, lost.other.active) {
        return Err(format!("shard 2 moved to {other:?}"));
    }
    Ok(())
}

/// An isolated loss records its intent, creates one volume under the receipt's token, records and requests the
/// replacement's attach for the shard's owner, verifies the attachment, names the spare and flips once, then retires
/// the displaced volume in the records with its attachment left in place.
#[test]
fn an_isolated_loss_flips_once_to_one_verified_replacement() {
    let (mut cell, lost) = lost_zone();
    let outcomes = cell.run_until(60, |cell| flipped(cell, &lost));
    let steps = effects(&outcomes);
    let kinds: Vec<&str> = steps
        .iter()
        .map(|effect| match effect {
            Replaced::Decided(_) => "decide",
            Replaced::Created(_) => "create",
            Replaced::Recorded => "record",
            Replaced::Requested(_) => "attach",
            Replaced::Named => "name",
            Replaced::Flipped => "flip",
            Replaced::Latched | Replaced::Abandoned | Replaced::Rejected => "other",
        })
        .collect();
    assert_eq!(
        kinds,
        ["decide", "create", "record", "attach", "name", "flip"]
    );
    replaced_once(&cell, &lost, false).unwrap();
    let now = cell.shard(1);
    assert_eq!((now.owner, now.attempts), (lost.owner, 0));
    assert_eq!(record_of(&cell, lost.active).state, VolumeState::Retired);
    let listed = cell
        .fixture
        .world
        .volumes
        .iter()
        .find(|row| row.volume == lost.active);
    assert!(
        !listed.unwrap().attachments.is_empty(),
        "the displaced volume stays attached"
    );
    cell.clean();
    for _ in 0..10 {
        cell.tick();
    }
    replaced_once(&cell, &lost, false).unwrap();
    let events = &cell.zone.telemetry.events;
    assert_eq!(events.decisions[at(DECISIONS, Decided::Provision)], 1);
    assert_eq!(events.creates[at(CREATES, Create::Created)], 1);
}

/// IDEMPOTENT-PROVISIONING under a crash: the loop's store client or provider fails at each of the replacement's effects in turn,
/// as a lost reply that committed, one that did not and a plain pass. In one run the process restarts and a second
/// loop runs beside it; in the other the same loop survives the fault. Each run ends in one generation advance and
/// one volume of one token. The displaced volume ends retired in every run but the ones whose restart falls after
/// the flip committed and before the displaced volume's retired state, which leave it active; the test reads that
/// cut from the store on the tick of the restart, and at least one run reaches it.
#[test]
fn a_crash_at_every_replacement_effect_with_a_second_loop_flips_once() {
    let prepared = || {
        let (cell, lost) = lost_zone();
        cell.faults.borrow_mut().effects = 0;
        (cell, lost)
    };
    let (mut baseline, lost) = prepared();
    baseline.run_until(60, |cell| flipped(cell, &lost));
    replaced_once(&baseline, &lost, false).unwrap();
    let effects = baseline.faults.borrow().effects;
    assert!(effects >= 8, "{effects} effects");
    let arms = [
        Arm::Pass,
        Arm::Timeout { commit: true },
        Arm::Timeout { commit: false },
    ];
    let mut failures = Vec::new();
    let mut cuts = 0;
    for at in 0..effects {
        for (arm, survives) in arms.into_iter().flat_map(|arm| [(arm, false), (arm, true)]) {
            let (mut cell, lost) = prepared();
            {
                let mut faults = cell.faults.borrow_mut();
                faults.at = Some((at, arm));
                faults.survives = survives;
            }
            let quiet = Faults::default();
            let (hook, after) = (Hook::default(), After::default());
            let mut second = Cell::open(&cell.fixture, &quiet, &hook, &after, &cell.bounds);
            let gate = StandbyGate::qualified();
            let mut ticks = 0;
            let mut cut = false;
            let done = |cell: &Cell| (survives || cell.restarts > 0) && flipped(cell, &lost);
            while ticks < 120 && !done(&cell) {
                let restarts = cell.restarts;
                cell.tick();
                ticks += 1;
                if cell.restarts == 0 {
                    continue;
                }
                if restarts == 0 {
                    let retired = record_of(&cell, lost.active).state == VolumeState::Retired;
                    cut = flipped(&cell, &lost) && !retired;
                }
                let directory = Ok(cell.fixture.directory());
                let now_us = cell.now_us - 5 * S;
                let theirs = second.survey(directory, &mut cell.fixture.world, now_us);
                let world = &mut cell.fixture.world;
                second.actuate(&gate, &theirs, now_us, world).unwrap();
            }
            for _ in 0..4 {
                cell.tick();
            }
            let mut result = replaced_once(&cell, &lost, cut);
            let restarts = usize::from(!survives);
            if result.is_ok() && cell.restarts != restarts {
                result = Err(format!("{} restarts", cell.restarts));
            }
            if result.is_ok() && !(cell.breaks.is_empty() && cell.fixture.world.breaks.is_empty()) {
                result = Err(format!("{:?} {:?}", cell.breaks, cell.fixture.world.breaks));
            }
            if let Err(why) = result {
                failures.push(format!(
                    "effect {at} under {arm:?}, survives {survives}: {why}"
                ));
            }
            cuts += usize::from(cut);
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
    assert!(
        cuts > 0,
        "no run stopped between the flip and the retirement"
    );
}

/// CORRELATED-HOLD: shard 1's loss beside shard 2's impaired volume latches a held receipt, and nothing is created
/// while the hold stands, after the other volume recovers too. Only the operator's release lets the replacement run.
/// The same latch follows a transient warning on the shard's own named spare that its receipt did not create, and
/// the hold outlives the warning until the release.
#[test]
fn a_correlated_loss_holds_until_the_operator_releases_it() {
    for own_spare in [false, true] {
        let (mut cell, lost) = lost_zone();
        let beside = if own_spare {
            let spare = own_spare_of(&cell);
            cell.fixture.world.volume(spare, warning());
            spare
        } else {
            cell.fixture.world.volume(volume(2), warning());
            volume(2)
        };
        let lost = match own_spare {
            true => Lost {
                record: cell.shard(1),
                other: cell.shard(2),
            },
            false => lost,
        };
        for _ in 0..10 {
            cell.tick();
        }
        let held = receipt(&cell, 1).expect("the hold latches a receipt");
        assert!(held.held, "own spare {own_spare}: {held:?}");
        let store = cell.store().0.borrow();
        let versions = store.versions(&Key::Replacement(shard(1)));
        let unheld = (versions.iter())
            .map(|item| Receipt::decode(&item.value).unwrap())
            .find(|version| !version.held);
        assert_eq!(
            unheld, None,
            "the receipt starts held, in its first version"
        );
        drop(store);
        let decided = cell.zone.telemetry.events.decisions[at(DECISIONS, Decided::Hold)];
        assert!(decided > 0, "the hold's decision reaches the status events");
        assert_eq!(calls(&cell), 0);
        cell.fixture.world.volume(beside, in_use());
        let (survey, _) = cell.tick();
        let held_state = (ShardState::ReplacementHeld, Some(Blocker::CorrelatedHold));
        let plan = survey
            .plan
            .shards
            .iter()
            .find(|plan| plan.shard == shard(1))
            .unwrap();
        assert_eq!(
            (plan.state, plan.blocker),
            held_state,
            "own spare {own_spare}"
        );
        for _ in 0..10 {
            cell.tick();
        }
        assert!(receipt(&cell, 1).unwrap().held);
        assert_eq!(calls(&cell), 0, "nothing is created under the hold");
        assert_eq!(cell.shard(1).generation, lost.generation);
        let mut operator = Reconciler::new(reconciler_client(cell.store()));
        let released = operator.release_hold(&OperatorRelease::diagnosed(), held.request);
        assert!(released.unwrap().value().released);
        if own_spare {
            let mut refused = 0;
            for _ in 0..20 {
                let (_, outcomes) = cell.tick();
                refused += (outcomes.iter())
                    .filter(|outcome| outcome.verdict == Verdict::Alarm(Reason::Spare))
                    .count();
            }
            assert!(
                refused > 0,
                "a spare the receipt did not create blocks the flip"
            );
            assert_eq!(cell.shard(1).generation, lost.generation);
            assert_eq!(flip_breach(&cell, &lost), None);
            break;
        }
        cell.run_until(60, |cell| flipped(cell, &lost));
        replaced_once(&cell, &lost, false).unwrap();
    }
}

/// Names a provisioned volume shard 1's spare, attached by host 3, as a spare its receipt did not create.
fn own_spare_of(cell: &Cell) -> VolumeId {
    let spare = VolumeId::new("vol-0f").unwrap();
    let mut reconciler = Reconciler::new(reconciler_client(cell.store()));
    let layout = crate::failover::sim::layout();
    reconciler.provision(spare, layout).unwrap();
    let host = crate::failover::sim::host(3);
    let attached = reconciler.record_attach(spare, host, crate::failover::records::ERA);
    let target = crate::failover::retire::Target::of(&cell.shard(1));
    reconciler
        .add_spare(shard(1), target, &attached.unwrap())
        .unwrap();
    spare
}

/// HOST-LOSS-KEEPS-VOLUME: an owner host lost with its volume available writes no receipt, calls no provider and
/// flips nothing.
#[test]
fn a_lost_owner_host_starts_no_replacement() {
    let mut cell = Cell::new(4, 2);
    cell.run_until(80, Cell::designated);
    let before = cell.shard(1);
    cell.lose(before.owner.get());
    for _ in 0..30 {
        let (survey, _) = cell.tick();
        let replaces = |step: &Step| matches!(step, Step::Replace { .. });
        assert!(!survey.plan.steps.iter().any(replaces));
    }
    assert!(receipt(&cell, 1).is_none());
    assert_eq!(calls(&cell), 0);
    assert_eq!(cell.shard(1).active, before.active);
}

/// IDEMPOTENT-PROVISIONING with bounded attempts: an unknown create repeats the same token after the settle time, and
/// a failed create opens the next attempt, whose create waits its backoff; an attempt past `create_attempts_max`
/// calls no provider.
#[test]
fn creates_repeat_their_token_and_back_off_within_the_attempt_bound() {
    let tick_us = 10 * S;
    let (mut cell, lost) = lost_zone();
    cell.fixture.world.provider.lose = 1;
    let mut created = Vec::new();
    let mut verdicts = Vec::new();
    for _ in 0..80 {
        let (_, outcomes) = cell.tick();
        for outcome in outcomes {
            if let Some(Replaced::Created(result)) = outcome.replaced {
                created.push((cell.now_us, result));
                verdicts.push(outcome.verdict);
            }
        }
        if flipped(&cell, &lost) {
            break;
        }
    }
    let results: Vec<Result<(), CreateError>> = created.iter().map(|&(_, result)| result).collect();
    assert_eq!(results, [Err(CreateError::Unknown), Ok(())]);
    assert_eq!(
        verdicts,
        [Verdict::Wait(Reason::Unknown), Verdict::Advance],
        "an unknown create stops the shard's later steps of its tick"
    );
    let events = &cell.zone.telemetry.events;
    assert_eq!(events.creates[at(CREATES, Create::Unknown)], 1);
    assert_eq!(events.creates[at(CREATES, Create::Created)], 1);
    let settle_us = cell.bounds.config().create_settle_us;
    let gap = created[1].0 - created[0].0;
    assert!(
        (settle_us..settle_us + tick_us).contains(&gap),
        "the unknown create repeats its token on the first tick after {settle_us} us, not after {gap} us"
    );
    replaced_once(&cell, &lost, false).unwrap();

    let (mut cell, lost) = lost_zone();
    let max = cell.bounds.config().create_attempts_max;
    let mut sent = Vec::new();
    let mut exhausted = 0;
    for _ in 0..200 {
        let (_, outcomes) = cell.tick();
        for outcome in outcomes {
            if let Some(Replaced::Created(result)) = outcome.replaced {
                sent.push((cell.now_us, result));
            }
            exhausted += usize::from(outcome.verdict == Verdict::Alarm(Reason::Attempts));
        }
        if let Some(held) = receipt(&cell, 1) {
            let token = held.token();
            let failed = &mut cell.fixture.world.provider.failed;
            if !failed.contains(&token) {
                failed.push(token);
            }
        }
    }
    let attempts = receipt(&cell, 1).unwrap().attempt;
    assert_eq!(attempts, max + 1, "each failed create raised the attempt");
    assert_eq!(sent.len() as u32, max, "{sent:?}");
    assert_eq!(calls(&cell) as u32, max, "no provider call past the bound");
    assert!(exhausted > 0, "the attempt past the bound raises Attempts");
    assert!(
        sent.iter()
            .all(|(_, result)| *result == Err(CreateError::Failed))
    );
    let events = &cell.zone.telemetry.events;
    assert_eq!(events.creates[at(CREATES, Create::Failed)], max);
    let config = cell.bounds.config();
    for (pair, failures) in sent.windows(2).zip(0u32..) {
        let wait = crate::failover::zone_loop::actuate::backoff_us(
            config.create_backoff_us,
            config.create_backoff_max_us,
            failures,
        );
        let gap = pair[1].0 - pair[0].0;
        assert!((wait..wait + tick_us).contains(&gap), "{sent:?}");
    }
    assert!(made(&cell).is_empty());
    assert_eq!(cell.shard(1).generation, lost.generation);
    cell.clean();
}

/// Runs ticks until the receipt of shard 1 records a created volume, and returns that volume.
fn created(cell: &mut Cell) -> VolumeId {
    for _ in 0..40 {
        cell.tick();
        if let Some(volume) = receipt(cell, 1).and_then(|held| held.phase.volume()) {
            return volume;
        }
    }
    panic!("no create within 40 ticks");
}

/// FLIP-ENTRY oracle: the shard advanced its generation to a volume other than the one its receipt records as
/// created.
fn flip_breach(cell: &Cell, lost: &ShardRecord) -> Option<VolumeId> {
    flip_breach_of(&cell.shard(1), cell, lost)
}

/// ABANDON-ENTRY oracle: the receipt stands past its first attempt while a volume an earlier attempt made never read
/// lost in the zone listing (`seen_lost`).
fn abandon_breach(cell: &Cell, seen_lost: &BTreeSet<VolumeId>) -> Option<VolumeId> {
    let held = receipt(cell, 1)?;
    let made = made(cell);
    let earlier = made.iter().filter(|(token, _)| *token != held.token());
    earlier
        .map(|&(_, volume)| volume)
        .find(|volume| !seen_lost.contains(volume))
}

/// Runs ticks until shard 1's record names its receipt's created volume spare, and returns that volume.
fn named(cell: &mut Cell) -> VolumeId {
    for _ in 0..60 {
        cell.tick();
        let made = receipt(cell, 1).and_then(|held| held.phase.volume());
        if let Some((spare, _)) = cell.shard(1).spare
            && Some(spare) == made
        {
            return spare;
        }
    }
    panic!("no spare named within 60 ticks");
}

/// VERIFY-BEFORE-NAMING: a replacement whose attachment listing shows a foreign instance, before its naming as spare
/// and after it, is retired in the records and raises `Foreign`; it is never named or flipped, also after the foreign
/// attachment leaves. Skipping the listing check for a named spare fails the second case, which flips.
#[test]
fn a_wrongly_attached_replacement_is_never_promoted() {
    for after_naming in [false, true] {
        let (mut cell, lost) = lost_zone();
        let replacement = match after_naming {
            true => named(&mut cell),
            false => created(&mut cell),
        };
        let foreign = crate::failover::attachments::InstanceId::new("i-0000beef").unwrap();
        let shard_key = Key::Shard(shard(1));
        let versions = cell.store().0.borrow().versions(&shard_key).len();
        cell.fixture.world.attach(replacement, foreign);
        let mut alarms = 0;
        for _ in 0..20 {
            let (_, outcomes) = cell.tick();
            alarms += (outcomes.iter())
                .filter(|outcome| outcome.verdict == Verdict::Alarm(Reason::Foreign))
                .count();
        }
        assert!(alarms > 0, "after naming {after_naming}");
        if !after_naming {
            let store = cell.store().0.borrow();
            let later = &store.versions(&shard_key)[versions..];
            let named = later.iter().any(|item| {
                let record = ShardRecord::decode(&item.value).unwrap();
                record.spare.is_some_and(|(spare, _)| spare == replacement)
            });
            assert!(
                !named,
                "no committed shard version names the foreign-attached volume"
            );
        }
        assert_eq!(
            record_of(&cell, replacement).state,
            VolumeState::Retired,
            "after naming {after_naming}"
        );
        assert_eq!(cell.shard(1).spare, None);
        assert_eq!(cell.shard(1).generation, lost.generation);
        cell.fixture.world.detach(replacement, foreign);
        for _ in 0..40 {
            cell.tick();
        }
        assert_eq!(
            cell.shard(1).generation,
            lost.generation,
            "after naming {after_naming}"
        );
        assert_eq!(cell.shard(1).spare, None);
        assert_eq!(flip_breach(&cell, &lost), None);
        let held = receipt(&cell, 1).unwrap();
        assert_eq!((held.attempt, held.phase), (1, Phase::Created(replacement)));
    }
}

/// ABANDON-ENTRY: a replacement that reads impaired is left as it is, and one that reads lost is retired and its
/// receipt moves to the next attempt, whose token makes a second volume that the shard flips to. Under a held
/// receipt a lost replacement is neither retired nor abandoned. The planted control raises the attempt with no loss
/// observed and the oracle names the volume; a flip to a volume the receipt did not create is named by the flip
/// oracle.
#[test]
fn a_lost_replacement_is_abandoned_only_on_its_observed_loss_under_an_unheld_receipt() {
    let (mut cell, lost) = lost_zone();
    let first = created(&mut cell);
    let mut seen_lost = BTreeSet::new();
    cell.fixture.world.volume(first, warning());
    for _ in 0..10 {
        cell.tick();
    }
    assert_eq!(
        receipt(&cell, 1).unwrap().attempt,
        1,
        "an impaired replacement stays"
    );
    assert_eq!(record_of(&cell, first).state, VolumeState::Provisioning);
    cell.fixture.world.volume(first, error());
    let needed = cell.bounds.config().loss_ticks;
    let mut errors = 0;
    for _ in 0..80 {
        cell.tick();
        errors += 1;
        if errors >= needed {
            seen_lost.insert(first);
        }
        let retired = record_of(&cell, first).state == VolumeState::Retired;
        let advanced = receipt(&cell, 1).unwrap().attempt > 1;
        assert_eq!(
            early(errors, needed, retired || advanced),
            None,
            "the abandon waits for the loop to read the volume lost"
        );
        if flipped(&cell, &lost) {
            break;
        }
    }
    assert_eq!(early(1, needed, true), Some(1), "the planted control");
    assert_eq!(record_of(&cell, first).state, VolumeState::Retired);
    let held = receipt(&cell, 1).unwrap();
    assert_eq!(held.attempt, 2);
    assert_eq!(made(&cell).len(), 2);
    assert_eq!(held.phase, Phase::Created(cell.shard(1).active));
    assert_eq!(abandon_breach(&cell, &seen_lost), None);
    assert_eq!(flip_breach(&cell, &lost), None);
    assert_eq!(
        abandon_breach(&cell, &BTreeSet::new()),
        Some(first),
        "the planted control"
    );
    let mut planted = cell.shard(1);
    planted.active = first;
    assert_eq!(
        flip_breach_of(&planted, &cell, &lost),
        Some(first),
        "the planted control"
    );

    let (mut cell, lost) = lost_zone();
    let first = created(&mut cell);
    cell.fixture.world.volume(volume(2), warning());
    let holds = |cell: &Cell| cell.zone.telemetry.events.decisions[at(DECISIONS, Decided::Hold)];
    let before = holds(&cell);
    for _ in 0..4 {
        cell.tick();
    }
    assert!(receipt(&cell, 1).unwrap().held);
    assert_eq!(
        holds(&cell),
        before + 1,
        "the latch's decision reaches the status events once"
    );
    cell.fixture.world.volume(volume(2), in_use());
    cell.fixture.world.volume(first, error());
    for _ in 0..10 {
        cell.tick();
    }
    let held = receipt(&cell, 1).unwrap();
    assert_eq!((held.attempt, held.phase), (1, Phase::Created(first)));
    assert_ne!(
        record_of(&cell, first).state,
        VolumeState::Retired,
        "a held receipt keeps its volume"
    );
    assert_eq!(cell.shard(1).generation, lost.generation);
}

fn flip_breach_of(now: &ShardRecord, cell: &Cell, lost: &ShardRecord) -> Option<VolumeId> {
    let made = receipt(cell, 1).and_then(|held| held.phase.volume());
    (now.generation > lost.generation && Some(now.active) != made).then_some(now.active)
}

/// ABANDON-ENTRY oracle per tick: the number of error listings of the replacement when the loop retired it or
/// advanced its receipt before `needed` such listings let the loop read it lost.
fn early(errors: u32, needed: u32, abandoned: bool) -> Option<u32> {
    (abandoned && errors < needed).then_some(errors)
}

/// LOSS-NEEDS-EVIDENCE across the receipt: once the receipt opens, a tick whose evidence no longer reads the loss
/// takes no further effect, and the replacement resumes when the loss reads again on complete views.
#[test]
fn an_open_receipt_advances_only_while_the_loss_still_reads() {
    let (mut cell, lost) = lost_zone();
    for _ in 0..20 {
        cell.tick();
        if receipt(&cell, 1).is_some() {
            break;
        }
    }
    assert_eq!(receipt(&cell, 1).unwrap().phase, Phase::Open);
    cell.fixture.world.volume(volume(1), in_use());
    let mut unconfirmed = 0;
    for _ in 0..10 {
        let (_, outcomes) = cell.tick();
        unconfirmed += (outcomes.iter())
            .filter(|outcome| outcome.verdict == Verdict::Wait(Reason::Unconfirmed))
            .count();
    }
    assert!(unconfirmed > 0);
    assert_eq!(calls(&cell), 0, "no create without the loss");
    cell.fixture.world.volume(volume(1), error());
    cell.run_until(60, |cell| flipped(cell, &lost));
    replaced_once(&cell, &lost, false).unwrap();

    let (mut cell, lost) = lost_zone();
    let replacement = created(&mut cell);
    cell.fixture.world.volume(volume(1), in_use());
    for _ in 0..10 {
        cell.tick();
    }
    assert_eq!(
        record_of(&cell, replacement).state,
        VolumeState::Provisioning
    );
    assert_eq!(
        (cell.shard(1).spare, cell.shard(1).generation),
        (None, lost.generation)
    );
}

/// Two loops that survey and act on every tick from the loss on flip the shard once to one volume of one token.
#[test]
fn two_loops_replacing_one_shard_flip_it_once() {
    let (mut cell, lost) = lost_zone();
    let quiet = Faults::default();
    let (hook, after) = (Hook::default(), After::default());
    let mut second = Cell::open(&cell.fixture, &quiet, &hook, &after, &cell.bounds);
    let gate = StandbyGate::qualified();
    for _ in 0..60 {
        let directory = Ok(cell.fixture.directory());
        let theirs = second.survey(directory, &mut cell.fixture.world, cell.now_us);
        let world = &mut cell.fixture.world;
        second.actuate(&gate, &theirs, cell.now_us, world).unwrap();
        cell.tick();
        if flipped(&cell, &lost) {
            break;
        }
    }
    for _ in 0..4 {
        cell.tick();
    }
    replaced_once(&cell, &lost, false).unwrap();
    assert!(cell.breaks.is_empty() && cell.fixture.world.breaks.is_empty());
}

/// Every phase of the tick feeds the status's events, the enrollment and attach steps and the
/// replacement's decision and create, and the next tick's part carries the counts.
#[test]
fn each_phase_of_the_tick_feeds_the_status_events() {
    use crate::failover::report::status::{ATTACHES, AttachOutcome, RESERVATIONS, Reservation};
    let (mut cell, lost) = lost_zone();
    let events = cell.zone.telemetry.events;
    assert_eq!(
        events.reservations[at(RESERVATIONS, Reservation::Reserved)],
        2
    );
    assert_eq!(events.attaches[at(ATTACHES, AttachOutcome::Recorded)], 2);
    assert_eq!(events.attaches[at(ATTACHES, AttachOutcome::Requested)], 2);
    cell.run_until(60, |cell| flipped(cell, &lost));
    let directory = Ok(cell.fixture.directory());
    let part = cell
        .zone
        .tick(directory, &mut cell.fixture.world, cell.now_us)
        .part;
    assert_eq!(part.events.decisions[at(DECISIONS, Decided::Provision)], 1);
    assert_eq!(part.events.creates[at(CREATES, Create::Created)], 1);
    assert_eq!(
        part.events.attaches[at(ATTACHES, AttachOutcome::Requested)],
        3
    );
    assert_eq!(
        part.events.attaches[at(ATTACHES, AttachOutcome::Recorded)],
        3,
        "the replacement's attach record"
    );
    assert_eq!(part.events, cell.zone.telemetry.events);
}

/// A reconciler over the cell's store beside the loop's own, as a second loop or the operator.
fn peer(cell: &Cell) -> Reconciler<AsReconciler<Shared>, MemLog> {
    Reconciler::new(reconciler_client(cell.store()))
}

/// Ticks until shard 1's replacement record holds its attach event, and returns the replacement.
fn recorded(cell: &mut Cell) -> VolumeId {
    for _ in 0..40 {
        let (_, outcomes) = cell.tick();
        let recorded = |outcome: &Outcome| outcome.replaced == Some(Replaced::Recorded);
        if outcomes.iter().any(recorded) {
            return receipt(cell, 1)
                .and_then(|held| held.phase.volume())
                .unwrap();
        }
    }
    panic!("no attach record within 40 ticks");
}

fn attached(cell: &mut Cell) -> VolumeId {
    let replacement = recorded(cell);
    for _ in 0..40 {
        let own = cell
            .fixture
            .world
            .volumes
            .iter()
            .any(|listed| listed.volume == replacement && !listed.attachments.is_empty());
        if own {
            assert_eq!(cell.shard(1).spare, None);
            return replacement;
        }
        let survey = cell.survey();
        let advances = survey
            .plan
            .steps
            .iter()
            .any(|step| matches!(step, Step::Replace { .. }));
        assert!(advances, "the replacement's attach request is planned");
        cell.actuate(&survey);
        cell.now_us += 10 * S;
    }
    panic!("no attachment of the replacement within 40 surveys");
}

/// ABANDON-ENTRY with a hold that latches after the survey: the loop surveys an unheld receipt whose created volume
/// reads lost, another reconciler latches the hold, and the actuation of that survey keeps the volume unretired, the
/// receipt at its attempt and the generation unchanged.
#[test]
fn a_hold_latched_after_the_survey_keeps_the_lost_replacement() {
    let (mut cell, lost) = lost_zone();
    let first = created(&mut cell);
    cell.fixture.world.volume(first, error());
    for _ in 1..cell.bounds.config().loss_ticks {
        cell.tick();
    }
    let survey = cell.survey();
    let held = receipt(&cell, 1).unwrap();
    let latched = peer(&cell).latch(&StandbyGate::qualified(), held.request);
    assert!(latched.unwrap().value().held);
    let outcomes = cell.actuate(&survey);
    let verdict = (outcomes.iter())
        .find(|outcome| matches!(outcome.step, Step::Replace { .. }))
        .map(|outcome| outcome.verdict);
    assert_eq!(verdict, Some(Verdict::Wait(Reason::Held)));
    assert_ne!(record_of(&cell, first).state, VolumeState::Retired);
    let now = receipt(&cell, 1).unwrap();
    assert_eq!(
        (now.attempt, now.phase, now.held),
        (1, Phase::Created(first), true)
    );
    assert_eq!(cell.shard(1).generation, lost.generation);
}

/// CREATE-AFTER-ISSUE with a stale survey: the loop surveys its receipt's last admitted attempt, a second reconciler
/// fails that attempt, and the actuation of the survey, with this loop's create timers cleared, sends no create for
/// the attempt past `create_attempts_max`.
#[test]
fn a_create_on_a_stale_survey_sends_no_attempt_past_the_bound() {
    let (mut cell, _lost) = lost_zone();
    let max = cell.bounds.config().create_attempts_max;
    for _ in 0..200 {
        let held = receipt(&cell, 1);
        if held
            .as_ref()
            .is_some_and(|held| held.attempt == max && held.phase == Phase::Open)
        {
            break;
        }
        if let Some(held) = held {
            cell.fixture.world.provider.failed.push(held.token());
        }
        cell.tick();
    }
    let open = receipt(&cell, 1).unwrap();
    assert_eq!((open.attempt, open.phase), (max, Phase::Open));
    let survey = cell.survey();
    cell.zone.creates.clear();
    let mut failing = Provisioner::default();
    failing.failed.push(open.token());
    let failed =
        peer(&cell).create_replacement(&StandbyGate::qualified(), shard(1), 0, &mut failing);
    assert_eq!(
        failed.err(),
        Some(ReconcileError::Create(CreateError::Failed))
    );
    let before = calls(&cell);
    let outcomes = cell.actuate(&survey);
    let replaced = (outcomes.iter()).find(|outcome| matches!(outcome.step, Step::Replace { .. }));
    assert_eq!(
        replaced.map(|outcome| outcome.verdict),
        Some(Verdict::Wait(Reason::Moved))
    );
    assert_eq!(calls(&cell), before, "no create of attempt {}", max + 1);
    let now = receipt(&cell, 1).unwrap();
    assert_eq!((now.attempt, now.phase), (max + 1, Phase::Open));
}

/// CORRELATED-HOLD's latch with a stale survey: the loop surveys an open receipt beside an impaired volume, another
/// reconciler latches the hold and the operator releases it, and the actuation of that survey calls no provider and
/// leaves the released receipt open.
#[test]
fn a_latch_on_a_stale_survey_never_reaches_the_provider() {
    let (mut cell, _lost) = lost_zone();
    for _ in 0..20 {
        cell.tick();
        if receipt(&cell, 1).is_some() {
            break;
        }
    }
    let open = receipt(&cell, 1).unwrap();
    assert_eq!(open.phase, Phase::Open);
    cell.fixture.world.volume(volume(2), warning());
    let survey = cell.survey();
    let mut operator = peer(&cell);
    operator
        .latch(&StandbyGate::qualified(), open.request)
        .unwrap();
    let released = operator.release_hold(&OperatorRelease::diagnosed(), open.request);
    assert!(released.unwrap().value().released);
    let records = survey.observation.zone.as_ref().unwrap().shards[0]
        .records
        .as_ref()
        .unwrap()
        .as_ref()
        .unwrap();
    assert!(
        records.judgement.others > 0 && records.judgement.confirmed,
        "the survey reads the correlated loss that plans the latch"
    );
    let outcomes = cell.actuate(&survey);
    assert_eq!(
        replace_verdict(&outcomes),
        Some(Verdict::Wait(Reason::Moved))
    );
    assert!(effects(&outcomes).is_empty());
    assert_eq!(calls(&cell), 0);
    let now = receipt(&cell, 1).unwrap();
    assert_eq!(
        (now.phase, now.held, now.released),
        (Phase::Open, false, true)
    );
}

/// FLIP-ENTRY at the flip's own shard read: `Reconciler::flip_to` refuses a shard record that names another spare
/// than the one the caller verified, before any write, and flips to the verified one.
#[test]
fn the_flip_activates_only_the_verified_spare() {
    let (mut cell, lost) = lost_zone();
    let spare = named(&mut cell);
    let record = cell.shard(1);
    let (_, host) = record.spare.unwrap();
    let target = crate::failover::retire::Target::of(&record);
    let gate = StandbyGate::qualified();
    let other = VolumeId::new("vol-0f").unwrap();
    let refused = peer(&cell).flip_to(&gate, shard(1), target, (other, host));
    assert_eq!(refused.err(), Some(ReconcileError::Conflict));
    assert_eq!(cell.shard(1).generation, lost.generation);
    assert!(
        peer(&cell)
            .flip_to(&gate, shard(1), target, (spare, host))
            .is_ok()
    );
    assert_eq!(cell.shard(1).active, spare);
}

/// VERIFY-BEFORE-NAMING for the attaching host: once the host the replacement's attach event names reads lost, the
/// loop sends no attach request, names no spare and flips nothing, and raises `Attacher`; the replacement volume
/// stays as recorded.
#[test]
fn a_lost_attaching_host_stops_the_replacement() {
    let (mut cell, lost) = lost_zone();
    let replacement = recorded(&mut cell);
    let attacher = record_of(&cell, replacement).events[0].host;
    cell.lose(attacher.get());
    let before = cell.attach_calls().len();
    let mut alarms = 0;
    for _ in 0..30 {
        let (_, outcomes) = cell.tick();
        alarms += (outcomes.iter())
            .filter(|outcome| outcome.verdict == Verdict::Alarm(Reason::Attacher))
            .count();
    }
    assert!(alarms > 0);
    let sent = &cell.attach_calls()[before..];
    assert!(
        sent.iter().all(|(volume, _)| *volume != replacement),
        "{sent:?}"
    );
    assert_eq!(cell.shard(1).spare, None);
    assert_eq!(cell.shard(1).generation, lost.generation);
    assert_eq!(record_of(&cell, replacement).state, VolumeState::Fresh);
}

/// VERIFY-BEFORE-NAMING for the record: a fresh replacement record whose history holds more than its attaching
/// host's one attach event takes no attach request and raises a step conflict.
#[test]
fn a_replacement_record_of_another_shape_takes_no_attach() {
    let (mut cell, lost) = lost_zone();
    let replacement = recorded(&mut cell);
    let mut client = reconciler_client(cell.store());
    let read = client
        .read::<VolumeRecord>(Key::Volume(replacement))
        .unwrap();
    let mut changed = read.value().clone();
    let attacher = changed.events[0].host;
    let era = changed.events[0].era;
    changed.push(EventKind::Detach, attacher, era).unwrap();
    client.replace(&read, changed).unwrap();
    let before = cell.attach_calls().len();
    let mut alarms = 0;
    for _ in 0..10 {
        let (_, outcomes) = cell.tick();
        let conflict = Verdict::Alarm(Reason::Step(ReconcileError::Conflict));
        alarms += outcomes
            .iter()
            .filter(|outcome| outcome.verdict == conflict)
            .count();
    }
    assert!(alarms > 0);
    let sent = &cell.attach_calls()[before..];
    assert!(
        sent.iter().all(|(volume, _)| *volume != replacement),
        "{sent:?}"
    );
    assert_eq!(cell.shard(1).generation, lost.generation);
}

/// The replacement's host when the owner drains: the attach request and the flip go to the active host of fewest
/// roles, lowest first, at its directory instance. The test counts the roles from the shard records; shard 1's own
/// standby role moves to the new owner with the flip, so it counts no role.
#[test]
fn a_draining_owner_gives_the_replacement_to_the_host_of_fewest_roles() {
    let (mut cell, lost) = lost_zone();
    cell.drain(lost.owner);
    let roles = |host: crate::failover::records::Host| {
        (1..=cell.fixture.shards)
            .map(|number| cell.shard(number))
            .filter(|record| {
                record.owner == host || (record.shard != shard(1) && record.standby == Some(host))
            })
            .count()
    };
    let expected = (1..=cell.fixture.hosts)
        .map(crate::failover::sim::host)
        .filter(|&host| host != lost.owner)
        .min_by_key(|&host| (roles(host), host))
        .unwrap();
    cell.run_until(60, |cell| flipped(cell, &lost));
    replaced_once(&cell, &lost, false).unwrap();
    let now = cell.shard(1);
    assert_eq!(now.owner, expected);
    let instance = super::directory::instance(expected.get());
    let sent: Vec<_> = (cell.attach_calls().into_iter())
        .filter(|(volume, _)| *volume == now.active)
        .collect();
    assert_eq!(sent, [(now.active, instance)]);
}

/// LOSS-NEEDS-EVIDENCE per effect: with an open receipt and the active volume still in `error`, a tick whose view is
/// incomplete makes no create, and the first complete tick after it makes none either, since its run of complete
/// views starts again; the create follows once the run reaches its length.
#[test]
fn an_incomplete_view_restarts_the_run_an_open_receipt_needs() {
    let (mut cell, lost) = lost_zone();
    for _ in 0..20 {
        cell.tick();
        if receipt(&cell, 1).is_some() {
            break;
        }
    }
    assert_eq!(receipt(&cell, 1).unwrap().phase, Phase::Open);
    let unknown = condition(ListedVolumeState::InUse, VolumeStatus::InsufficientData);
    cell.fixture.world.volume(volume(2), unknown);
    let (_, outcomes) = cell.tick();
    let unconfirmed = |outcomes: &[Outcome]| {
        (outcomes.iter()).any(|outcome| outcome.verdict == Verdict::Wait(Reason::Unconfirmed))
    };
    assert!(unconfirmed(&outcomes));
    assert_eq!(calls(&cell), 0);
    cell.fixture.world.volume(volume(2), in_use());
    let (_, outcomes) = cell.tick();
    assert!(
        unconfirmed(&outcomes),
        "the first complete view after the gap"
    );
    assert_eq!(calls(&cell), 0);
    cell.run_until(60, |cell| flipped(cell, &lost));
    replaced_once(&cell, &lost, false).unwrap();
}

/// CORRELATED-HOLD's release: the operator releases the hold while the other volume still reads impaired, and the
/// replacement then runs; a released receipt is never latched again.
#[test]
fn a_released_hold_runs_beside_a_still_impaired_volume() {
    let (mut cell, lost) = lost_zone();
    cell.fixture.world.volume(volume(2), warning());
    for _ in 0..10 {
        cell.tick();
    }
    let held = receipt(&cell, 1).unwrap();
    assert!(held.held);
    let released = peer(&cell).release_hold(&OperatorRelease::diagnosed(), held.request);
    assert!(released.unwrap().value().released);
    cell.run_until(60, |cell| flipped(cell, &lost));
    let now = receipt(&cell, 1).unwrap();
    assert!(!now.held && now.released);
    assert_eq!(cell.shard(1).generation.get(), lost.generation.get() + 1);
}

/// CREATE-AFTER-ISSUE's timers start on a provider call alone. An issue write that fails without committing sends no
/// create and starts no settle wait, and the receipt stays open. An issue write that commits with its reply lost
/// sends no create either: the loop holds no acknowledged issue write. In both cases the next tick reads the receipt
/// first and sends the create.
#[test]
fn a_failed_issue_write_starts_no_create_wait() {
    for commit in [false, true] {
        let (mut cell, _lost) = lost_zone();
        for _ in 0..20 {
            cell.tick();
            if receipt(&cell, 1).is_some() {
                break;
            }
        }
        assert_eq!(receipt(&cell, 1).unwrap().phase, Phase::Open);
        cell.fault_next(Arm::Timeout { commit });
        cell.tick();
        assert_eq!(
            calls(&cell),
            0,
            "commit {commit}: no create follows the lost reply"
        );
        let phase = match commit {
            true => Phase::Issued,
            false => Phase::Open,
        };
        assert_eq!(receipt(&cell, 1).unwrap().phase, phase);
        cell.tick();
        assert_eq!(
            calls(&cell),
            1,
            "commit {commit}: the create follows on the next tick"
        );
        cell.clean();
    }
}

/// The replacement's attach request keeps its retry time across ticks: after a refused request the next one waits
/// the attach settle time, doubled after each refusal.
#[test]
fn a_refused_replacement_attach_waits_its_backoff() {
    let (mut cell, lost) = lost_zone();
    let replacement = recorded(&mut cell);
    let faults = &mut cell.fixture.world.faults.attach;
    faults.push_back(AttachFault::Refuse);
    faults.push_back(AttachFault::Refuse);
    let mut sent = Vec::new();
    for _ in 0..40 {
        let before = cell.attach_calls().len();
        let now_us = cell.now_us;
        cell.tick();
        let calls = &cell.attach_calls()[before..];
        if calls.iter().any(|(volume, _)| *volume == replacement) {
            sent.push(now_us);
        }
        if flipped(&cell, &lost) {
            break;
        }
    }
    assert!(sent.len() >= 3, "{sent:?}");
    let config = cell.bounds.config();
    for (refusals, pair) in (1u32..).zip(sent.windows(2).take(2)) {
        let wait = crate::failover::zone_loop::actuate::backoff_us(
            config.attach_settle_us,
            config.attach_stuck_us,
            refusals,
        );
        let gap = pair[1] - pair[0];
        assert!(
            (wait..wait + 10 * S).contains(&gap),
            "{sent:?} after {refusals}"
        );
    }
}

/// The provider double's CREATE-AFTER-ISSUE check: a create whose token no committed receipt version shows issued
/// records a break, and the loop's own creates record none.
#[test]
fn a_create_before_its_issue_write_breaks_the_world() {
    let (mut cell, lost) = lost_zone();
    cell.run_until(60, |cell| flipped(cell, &lost));
    replaced_once(&cell, &lost, false).unwrap();
    assert!(cell.fixture.world.breaks.is_empty());
    let mut unissued = receipt(&cell, 1).unwrap();
    unissued.attempt += 1;
    let layout = unissued.layout;
    let _ = Provider::create(&mut cell.fixture.world, &unissued.token(), layout);
    assert_eq!(cell.fixture.world.breaks.len(), 1, "the planted control");

    let (mut cell, _lost) = lost_zone();
    for _ in 0..20 {
        cell.tick();
        if receipt(&cell, 1).is_some() {
            break;
        }
    }
    let open = receipt(&cell, 1).unwrap();
    assert_eq!(open.phase, Phase::Open);
    let _ = Provider::create(&mut cell.fixture.world, &open.token(), open.layout);
    assert_eq!(
        cell.fixture.world.breaks.len(),
        1,
        "a create under the token of a receipt whose every version reads open"
    );
}

/// FLIP-ENTRY for a receipt further ahead: a receipt two generations past the shard record's, unheld and issued
/// under a confirmed isolated loss, takes no create, attach or naming and raises a step conflict.
#[test]
fn a_receipt_past_the_next_generation_takes_no_effect() {
    let (mut cell, lost) = lost_zone();
    let ahead = Receipt {
        request: crate::failover::loss::Request {
            namespace: lost.namespace,
            shard: shard(1),
            generation: crate::net::ownership::ShardGeneration::new(lost.generation.get() + 2)
                .unwrap(),
        },
        layout: cell.bounds.config().replacement,
        attempt: 1,
        phase: Phase::Issued,
        held: false,
        released: false,
    };
    let mut client = reconciler_client(cell.store());
    client
        .create(Key::Replacement(shard(1)), ahead.clone())
        .unwrap();
    let mut conflicts = 0;
    for _ in 0..10 {
        let (_, outcomes) = cell.tick();
        let conflict = Verdict::Alarm(Reason::Step(ReconcileError::Conflict));
        conflicts += outcomes
            .iter()
            .filter(|outcome| outcome.verdict == conflict)
            .count();
    }
    assert!(conflicts > 0);
    let errors = cell.zone.telemetry.events.errors;
    let counted = errors[at(
        crate::failover::report::status::STEP_ERRORS,
        crate::failover::report::status::StepError::Conflict,
    )];
    assert_eq!(counted as usize, conflicts, "each conflict counts once");
    assert_eq!(calls(&cell), 0);
    assert_eq!(cell.shard(1).spare, None);
    assert_eq!(receipt(&cell, 1), Some(ahead));
}

/// A superseded receipt that blocks a new one: an issued receipt at the shard record's generation, as an operator's
/// flip to another spare leaves it, makes the next loss raise a step conflict instead of waiting in silence.
#[test]
fn a_superseded_issued_receipt_alarms_on_the_next_loss() {
    let (mut cell, lost) = lost_zone();
    let superseded = Receipt {
        request: crate::failover::loss::Request {
            namespace: lost.namespace,
            shard: shard(1),
            generation: lost.generation,
        },
        layout: cell.bounds.config().replacement,
        attempt: 1,
        phase: Phase::Issued,
        held: false,
        released: false,
    };
    let mut client = reconciler_client(cell.store());
    client
        .create(Key::Replacement(shard(1)), superseded)
        .unwrap();
    let mut conflicts = 0;
    for _ in 0..10 {
        let (_, outcomes) = cell.tick();
        let conflict = Verdict::Alarm(Reason::Step(ReconcileError::Conflict));
        conflicts += outcomes
            .iter()
            .filter(|outcome| outcome.verdict == conflict)
            .count();
    }
    assert!(conflicts > 0);
    assert_eq!(calls(&cell), 0);
    assert_eq!(cell.shard(1).generation, lost.generation);
}

/// CREATE-AFTER-ISSUE's timers belong to one replacement request: after a first replacement flips, a loss of the new
/// active volume in the same loop creates its replacement on the first tick its receipt opens, with no settle wait
/// carried from the earlier token.
#[test]
fn a_second_replacement_of_one_shard_waits_no_earlier_settle_time() {
    let (mut cell, lost) = lost_zone();
    cell.run_until(60, |cell| flipped(cell, &lost));
    replaced_once(&cell, &lost, false).unwrap();
    let first = cell.shard(1);
    cell.fixture.world.volume(first.active, error());
    let mut opened = None;
    let mut sent = None;
    for _ in 0..40 {
        cell.tick();
        let held = receipt(&cell, 1).unwrap();
        if held.request.generation > first.generation {
            opened.get_or_insert(cell.now_us);
        }
        if calls(&cell) == 2 {
            sent = Some(cell.now_us);
            break;
        }
    }
    let (opened, sent) = (opened.unwrap(), sent.unwrap());
    assert!(
        sent - opened <= 10 * S,
        "opened at {opened}, created at {sent}"
    );
}

/// ABANDON-ENTRY on a run of complete views: a created volume that reads lost while another named volume's health is
/// unknown is neither retired nor abandoned, and the receipt keeps its attempt, also on the first complete view
/// after the gap; once the run of complete views reaches its length the lost volume is retired and the receipt
/// moves to its next attempt.
#[test]
fn a_lost_replacement_is_retired_only_on_a_complete_view() {
    let (mut cell, _lost) = lost_zone();
    let first = created(&mut cell);
    let unknown = condition(ListedVolumeState::InUse, VolumeStatus::InsufficientData);
    cell.fixture.world.volume(volume(2), unknown);
    cell.fixture.world.volume(first, error());
    for _ in 0..6 {
        cell.tick();
    }
    assert_ne!(record_of(&cell, first).state, VolumeState::Retired);
    let held = receipt(&cell, 1).unwrap();
    assert_eq!((held.attempt, held.phase), (1, Phase::Created(first)));
    cell.fixture.world.volume(volume(2), in_use());
    cell.tick();
    assert_ne!(
        record_of(&cell, first).state,
        VolumeState::Retired,
        "one complete view after the gap is short of the run"
    );
    assert_eq!(receipt(&cell, 1).unwrap().attempt, 1);
    for _ in 0..6 {
        cell.tick();
    }
    assert_eq!(record_of(&cell, first).state, VolumeState::Retired);
    assert!(receipt(&cell, 1).unwrap().attempt >= 2);
}

/// ABANDON-ENTRY after the naming: a replacement the shard record names spare that then reads lost is removed from
/// the spare slot and retired, the receipt moves to its next attempt, and the shard later flips to the second volume.
#[test]
fn a_named_spare_that_reads_lost_is_retired_and_replaced() {
    let (mut cell, lost) = lost_zone();
    let first = named(&mut cell);
    cell.fixture.world.volume(first, error());
    let mut abandoned = false;
    for _ in 0..80 {
        cell.tick();
        let held = receipt(&cell, 1).unwrap();
        if held.attempt == 2 && !abandoned {
            abandoned = true;
            assert_eq!(cell.shard(1).generation, lost.generation);
            assert_ne!(cell.shard(1).spare.map(|(spare, _)| spare), Some(first));
        }
        if flipped(&cell, &lost) {
            break;
        }
    }
    assert!(abandoned);
    assert_eq!(record_of(&cell, first).state, VolumeState::Retired);
    let now = cell.shard(1);
    assert_ne!(now.active, first);
    assert_eq!(receipt(&cell, 1).unwrap().phase, Phase::Created(now.active));
    assert_eq!(flip_breach(&cell, &lost), None);
    cell.clean();
}

/// CORRELATED-HOLD needs the subject's own loss: an open receipt whose active volume reads in use again takes no hold
/// from another volume's impairment, and calls no provider.
#[test]
fn a_peer_impairment_holds_no_receipt_over_a_recovered_volume() {
    let (mut cell, _lost) = lost_zone();
    for _ in 0..20 {
        cell.tick();
        if receipt(&cell, 1).is_some() {
            break;
        }
    }
    assert_eq!(receipt(&cell, 1).unwrap().phase, Phase::Open);
    cell.fixture.world.volume(volume(1), in_use());
    cell.fixture.world.volume(volume(2), warning());
    for _ in 0..6 {
        cell.tick();
    }
    let held = receipt(&cell, 1).unwrap();
    assert!(!held.held, "{held:?}");
    assert_eq!(calls(&cell), 0);
}

/// CREATE-AFTER-ISSUE binds the create to the request the step admitted: the loop surveys its open receipt, the
/// stored receipt then changes to an issued attempt 1 of another request, and the actuation of that survey sends no
/// provider call under the other request's token.
#[test]
fn a_create_on_a_stale_survey_sends_no_token_of_another_request() {
    let (mut cell, lost) = lost_zone();
    for _ in 0..20 {
        cell.tick();
        if receipt(&cell, 1).is_some() {
            break;
        }
    }
    let open = receipt(&cell, 1).unwrap();
    assert_eq!((open.attempt, open.phase), (1, Phase::Open));
    let survey = cell.survey();
    let mut other = open.clone();
    other.request.generation =
        crate::net::ownership::ShardGeneration::new(lost.generation.get() + 2).unwrap();
    other.phase = Phase::Issued;
    let mut client = reconciler_client(cell.store());
    let read = client.read::<Receipt>(Key::Replacement(shard(1))).unwrap();
    client.replace(&read, other.clone()).unwrap();
    let outcomes = cell.actuate(&survey);
    let replaced = (outcomes.iter()).find(|outcome| matches!(outcome.step, Step::Replace { .. }));
    assert_eq!(
        replaced.map(|outcome| outcome.verdict),
        Some(Verdict::Wait(Reason::Moved))
    );
    assert_eq!(calls(&cell), 0, "no create under the other request's token");
    assert_eq!(receipt(&cell, 1), Some(other));
}

/// The peer's flip makes the survey stale: the issued request now targets the generation the shard already holds.
#[test]
fn a_create_on_a_stale_survey_sends_no_token_of_a_generation_the_shard_holds() {
    let gate = StandbyGate::qualified();
    let (mut cell, lost) = lost_zone();
    cell.fixture.world.provider.lose = 1;
    for _ in 0..40 {
        cell.tick();
        if calls(&cell) == 1 {
            break;
        }
    }
    let issued = receipt(&cell, 1).unwrap();
    assert_eq!((calls(&cell), issued.phase), (1, Phase::Issued));
    cell.zone.creates.clear();
    let survey = cell.survey();
    own_spare_of(&cell);
    let target = crate::failover::retire::Target::of(&lost.record);
    assert!(peer(&cell).flip(&gate, shard(1), target).is_ok());
    assert_eq!(
        cell.shard(1).generation,
        issued.request.generation,
        "another reconciler's flip reached the receipt's generation"
    );
    let outcomes = cell.actuate(&survey);
    assert_eq!(
        replace_verdict(&outcomes),
        Some(Verdict::Wait(Reason::Moved))
    );
    assert_eq!(
        calls(&cell),
        1,
        "no create for a generation the shard holds"
    );
    assert_eq!(receipt(&cell, 1), Some(issued));
    let mut operator = peer(&cell);
    let settled = operator.create_replacement(&gate, shard(1), 0, &mut cell.fixture.world.provider);
    assert_eq!(
        settled.err(),
        Some(ReconcileError::Stale),
        "the operator's step settles the token"
    );
    let recorded = receipt(&cell, 1).unwrap().phase;
    assert_eq!(recorded, Phase::Created(made(&cell)[0].1));
}

/// ACKNOWLEDGED-ONLY for a flip that lands while the create is in flight: another reconciler flips the shard to a
/// spare the receipt did not create, and retires the displaced volume, after this step's issue write and before the
/// provider's reply. The step records the volume the provider made and reads `Moved`, since the shard record
/// already holds the request's generation. The receipt keeps that volume for the operator (SUPERSEDED-RECEIPT): a
/// later loss of the shard raises the step conflict on every tick and sends no create until `Reconciler::retire`
/// retires the volume.
#[test]
fn a_flip_during_the_create_reads_moved_and_keeps_the_volume_for_the_operator() {
    let (mut cell, lost) = lost_zone();
    for _ in 0..40 {
        cell.tick();
        if receipt(&cell, 1).is_some() {
            break;
        }
    }
    assert_eq!(receipt(&cell, 1).unwrap().phase, Phase::Open);
    let spare = own_spare_of(&cell);
    cell.fixture.world.volume(spare, in_use());
    let store = cell.store().clone();
    let target = crate::failover::retire::Target::of(&lost.record);
    let displaced = lost.active;
    let flip = move || {
        let mut peer = Reconciler::new(reconciler_client(&store));
        let flipped = peer.flip(&StandbyGate::qualified(), shard(1), target);
        assert!(flipped.is_ok(), "{flipped:?}");
        let retired = peer.retire(shard(1), displaced);
        assert!(retired.is_ok(), "{retired:?}");
    };
    *cell.after.borrow_mut() = Some((Key::Replacement(shard(1)), Box::new(flip)));
    let (_, outcomes) = cell.tick();
    assert_eq!(calls(&cell), 1, "the create was in flight at the flip");
    assert_eq!(
        replace_verdict(&outcomes),
        Some(Verdict::Wait(Reason::Moved))
    );
    let made = made(&cell)[0].1;
    let held = receipt(&cell, 1).unwrap();
    let now = cell.shard(1);
    assert_eq!(held.phase, Phase::Created(made));
    assert_eq!(
        (now.generation, now.active),
        (held.request.generation, spare)
    );
    assert_eq!(record_of(&cell, made).state, VolumeState::Provisioning);

    cell.fixture.world.volume(spare, error());
    let conflict = Verdict::Alarm(Reason::Step(ReconcileError::Conflict));
    let mut conflicts = 0;
    for _ in 0..20 {
        let (_, outcomes) = cell.tick();
        conflicts += usize::from(replace_verdict(&outcomes) == Some(conflict));
    }
    assert!(
        conflicts > 0,
        "the superseded receipt refuses the next start"
    );
    assert_eq!(calls(&cell), 1, "no create under the superseded receipt");
    let retired = peer(&cell).retire(shard(1), made);
    assert!(retired.is_ok(), "{retired:?}");
    cell.run_until(60, |cell| calls(cell) == 2);
    assert_eq!(calls(&cell), 2, "the next replacement creates");
    assert_eq!(
        receipt(&cell, 1).unwrap().request.generation.get(),
        held.request.generation.get() + 1
    );
}

/// The replacement's attach record and its attach request each follow a shard read of the same step at the step's
/// target: the loop surveys a replacement before its attach record, or one whose record holds its attach event and
/// whose listing lacks the instance, another reconciler names a spare the receipt did not create and flips the
/// shard to it, and the actuation of that survey reads `Moved`, writes no attach event and sends no attach request.
/// The receipt still records the replacement, so the receipt read alone does not show the flip.
#[test]
fn a_flip_after_the_survey_records_and_requests_no_replacement_attach() {
    for recorded_before in [false, true] {
        let (mut cell, lost) = lost_zone();
        let replacement = match recorded_before {
            true => recorded(&mut cell),
            false => created(&mut cell),
        };
        let requests = |cell: &Cell| {
            let events = cell.fixture.world.events();
            let sent = |event: &&super::world::Event| matches!(event, super::world::Event::Attach(volume, _) if *volume == replacement);
            events.iter().filter(sent).count()
        };
        let before = record_of(&cell, replacement);
        assert_eq!(before.events.len(), usize::from(recorded_before));
        assert_eq!(requests(&cell), 0);
        let survey = cell.survey();
        let held = receipt(&cell, 1).unwrap();
        own_spare_of(&cell);
        let target = crate::failover::retire::Target::of(&lost.record);
        let flipped = peer(&cell).flip(&StandbyGate::qualified(), shard(1), target);
        assert!(flipped.is_ok(), "{flipped:?}");
        assert_eq!(receipt(&cell, 1), Some(held), "the flip leaves the receipt");
        let outcomes = cell.actuate(&survey);
        let case = format!("recorded before {recorded_before}");
        assert_eq!(
            replace_verdict(&outcomes),
            Some(Verdict::Wait(Reason::Moved)),
            "{case}"
        );
        assert_eq!(record_of(&cell, replacement), before, "{case}");
        assert_eq!(requests(&cell), 0, "{case}");
    }
}

/// The verdict of the survey's `Replace` step among `outcomes`.
fn replace_verdict(outcomes: &[Outcome]) -> Option<Verdict> {
    (outcomes.iter())
        .find(|outcome| matches!(outcome.step, Step::Replace { .. }))
        .map(|outcome| outcome.verdict)
}

/// CORRELATED-HOLD with a hold that latches after the survey, for each effect on a created replacement: the attach
/// record, the attach request, the rejection of a foreign-attached spare and the flip. The actuation of the survey waits on
/// the hold and leaves the volume record, the attach requests and the spare slot as they stood.
#[test]
fn a_hold_latched_after_the_survey_stops_each_effect_on_the_created_volume() {
    let gate = StandbyGate::qualified();
    let foreign = crate::failover::attachments::InstanceId::new("i-0000beef").unwrap();
    for case in ["record", "attach", "reject", "flip"] {
        let (mut cell, lost) = lost_zone();
        let replacement = match case {
            "record" => created(&mut cell),
            "attach" => recorded(&mut cell),
            _ => named(&mut cell),
        };
        if case == "reject" {
            cell.fixture.world.attach(replacement, foreign);
        }
        let survey = cell.survey();
        let before = (record_of(&cell, replacement), cell.shard(1));
        let sent = cell.attach_calls().len();
        let held = receipt(&cell, 1).unwrap();
        assert!(peer(&cell).latch(&gate, held.request).unwrap().value().held);
        let outcomes = cell.actuate(&survey);
        assert_eq!(
            replace_verdict(&outcomes),
            Some(Verdict::Wait(Reason::Held)),
            "{case}"
        );
        assert_eq!(
            (record_of(&cell, replacement), cell.shard(1)),
            before,
            "{case}"
        );
        assert_eq!(cell.attach_calls().len(), sent, "{case}");
        let now = receipt(&cell, 1).unwrap();
        assert_eq!(
            (now.attempt, now.phase, now.held),
            (1, Phase::Created(replacement), true),
            "{case}"
        );
        assert_eq!(cell.shard(1).generation, lost.generation);
    }
}

/// VERIFY-BEFORE-NAMING keeps a rejection whose write failed: the listing of a named replacement shows a foreign
/// instance, the rejection's first write fails without committing, and the foreign instance leaves before the next
/// tick. The loop still retires the replacement on the later clean listing and never flips to it.
#[test]
fn a_failed_rejection_is_repeated_after_the_foreign_attachment_leaves() {
    let (mut cell, lost) = lost_zone();
    let replacement = named(&mut cell);
    let foreign = crate::failover::attachments::InstanceId::new("i-0000beef").unwrap();
    cell.fixture.world.attach(replacement, foreign);
    cell.fault_next(Arm::Timeout { commit: false });
    let (_, outcomes) = cell.tick();
    assert_eq!(
        replace_verdict(&outcomes),
        Some(Verdict::Wait(Reason::Unknown)),
        "the rejection's write fails"
    );
    assert_eq!(record_of(&cell, replacement).state, VolumeState::Fresh);
    cell.fixture.world.detach(replacement, foreign);
    for _ in 0..20 {
        cell.tick();
    }
    assert_eq!(record_of(&cell, replacement).state, VolumeState::Retired);
    assert_eq!(cell.shard(1).spare, None);
    assert_eq!(cell.shard(1).generation, lost.generation);
    assert_eq!(flip_breach(&cell, &lost), None);
}

/// The rejected volumes live in the loop's memory, so a rejection lasts beyond its process only through the
/// replacement's retired state. The listing of a replacement shows a foreign instance, before its naming as spare or
/// after it, and the foreign instance leaves before the next tick. The control is the loop that keeps running after
/// the rejection's first write fails without committing: it retires the replacement on the later clean listing and
/// never flips to it. A process that stops at that uncommitted write, or after the write that removes the named
/// spare and before the retired state, takes the rejection with it: the restarted loop reads the replacement's
/// record unused and its listing clean, and flips to it.
#[test]
fn a_rejection_short_of_the_retired_state_ends_with_its_process() {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Stop {
        Never,
        FirstWrite,
        SpareRemoved,
    }
    let foreign = crate::failover::attachments::InstanceId::new("i-0000beef").unwrap();
    let cases = [
        (false, Stop::Never),
        (false, Stop::FirstWrite),
        (true, Stop::Never),
        (true, Stop::FirstWrite),
        (true, Stop::SpareRemoved),
    ];
    for (after_naming, stop) in cases {
        let case = format!("after naming {after_naming}, stop {stop:?}");
        let (mut cell, lost) = lost_zone();
        let replacement = match after_naming {
            true => named(&mut cell),
            false => attached(&mut cell),
        };
        cell.fixture.world.attach(replacement, foreign);
        match stop {
            Stop::Never | Stop::FirstWrite => {
                cell.fault_next(Arm::Timeout { commit: false });
                cell.faults.borrow_mut().survives = stop == Stop::Never;
            }
            Stop::SpareRemoved => {
                let faults = cell.faults.clone();
                let dies = move || faults.borrow_mut().dead = true;
                *cell.after.borrow_mut() = Some((Key::Shard(shard(1)), Box::new(dies)));
            }
        }
        let (_, outcomes) = cell.tick();
        assert_eq!(
            replace_verdict(&outcomes),
            Some(Verdict::Wait(Reason::Unknown)),
            "{case}"
        );
        assert_eq!(cell.restarts, usize::from(stop != Stop::Never), "{case}");
        assert_eq!(
            record_of(&cell, replacement).state,
            VolumeState::Fresh,
            "{case}"
        );
        let removed = stop == Stop::SpareRemoved || !after_naming;
        assert_eq!(cell.shard(1).spare.is_none(), removed, "{case}");
        cell.fixture.world.detach(replacement, foreign);
        for _ in 0..40 {
            cell.tick();
        }
        let now = cell.shard(1);
        let retired = record_of(&cell, replacement).state == VolumeState::Retired;
        match stop {
            Stop::Never => {
                assert!(retired, "{case}");
                assert_eq!(
                    (now.generation, now.spare),
                    (lost.generation, None),
                    "{case}"
                );
            }
            Stop::FirstWrite | Stop::SpareRemoved => {
                assert!(!retired, "{case}");
                assert_eq!(now.generation.get(), lost.generation.get() + 1, "{case}");
                assert_eq!(now.active, replacement, "{case}");
            }
        }
        assert_eq!(flip_breach(&cell, &lost), None, "{case}");
    }
}

/// A rejection reads the spare slot in the retirement itself: the loop surveys an unnamed replacement whose listing
/// shows a foreign instance, another reconciler names the replacement spare, and the actuation of that survey
/// removes it from the spare slot and retires it.
#[test]
fn a_rejection_retires_a_replacement_named_after_the_survey() {
    let (mut cell, lost) = lost_zone();
    let replacement = attached(&mut cell);
    let foreign = crate::failover::attachments::InstanceId::new("i-0000beef").unwrap();
    cell.fixture.world.attach(replacement, foreign);
    let survey = cell.survey();
    let event = record_of(&cell, replacement).events[0];
    let target = crate::failover::retire::Target::of(&cell.shard(1));
    let mut second = peer(&cell);
    let attached = second
        .record_attach(replacement, event.host, event.era)
        .unwrap();
    second.add_spare(shard(1), target, &attached).unwrap();
    assert_eq!(cell.shard(1).spare, Some((replacement, event.host)));
    let outcomes = cell.actuate(&survey);
    assert_eq!(
        replace_verdict(&outcomes),
        Some(Verdict::Alarm(Reason::Foreign))
    );
    assert_eq!(record_of(&cell, replacement).state, VolumeState::Retired);
    assert_eq!(cell.shard(1).spare, None);
    assert_eq!(cell.shard(1).generation, lost.generation);
}

/// A foreign attachment in the survey's zone listing disqualifies the replacement even if the instance detaches
/// before actuation: a record that names another instance, and a record whose instance ID the listing could not
/// read, which lists as an empty entry and counts as foreign (LISTED-SPARE).
#[test]
fn a_foreign_attachment_in_the_survey_s_listing_rejects_the_replacement() {
    let foreign = crate::failover::attachments::InstanceId::new("i-0000beef").unwrap();
    for (after_naming, unreadable) in [(false, false), (true, false), (false, true), (true, true)] {
        let case = format!("after naming {after_naming}, unreadable {unreadable}");
        let (mut cell, lost) = lost_zone();
        let replacement = match after_naming {
            true => named(&mut cell),
            false => attached(&mut cell),
        };
        let record = match unreadable {
            true => String::new(),
            false => foreign.as_str().to_owned(),
        };
        let rows = |cell: &mut Cell, change: &dyn Fn(&mut Vec<String>)| {
            let listed = cell.fixture.world.volumes.iter_mut();
            listed
                .filter(|row| row.volume == replacement)
                .for_each(|row| change(&mut row.attachments));
        };
        rows(&mut cell, &|listed| listed.push(record.clone()));
        let survey = cell.survey();
        rows(&mut cell, &|listed| listed.retain(|id| *id != record));
        let outcomes = cell.actuate(&survey);
        assert_eq!(
            replace_verdict(&outcomes),
            Some(Verdict::Alarm(Reason::Foreign)),
            "{case}"
        );
        assert_eq!(
            record_of(&cell, replacement).state,
            VolumeState::Retired,
            "{case}"
        );
        assert_eq!(cell.shard(1).spare, None, "{case}");
        assert_eq!(cell.shard(1).generation, lost.generation, "{case}");
    }
}

/// FLIP-ENTRY reports a flip only when this step committed it: the loop surveys its named, verified spare, another
/// reconciler flips the shard to it, and the actuation of that survey reads the shard past its target, waits, and
/// leaves the displaced volume's retirement to the next tick, which retires it.
#[test]
fn a_flip_another_reconciler_committed_is_not_reported_as_this_step_s() {
    let (mut cell, lost) = lost_zone();
    let spare = named(&mut cell);
    let survey = cell.survey();
    assert!(
        survey
            .plan
            .steps
            .iter()
            .any(|step| matches!(step, Step::Replace { .. })),
        "the flip is planned"
    );
    let record = cell.shard(1);
    let (_, host) = record.spare.unwrap();
    let target = crate::failover::retire::Target::of(&record);
    let flipped_by_peer =
        peer(&cell).flip_to(&StandbyGate::qualified(), shard(1), target, (spare, host));
    assert!(flipped_by_peer.is_ok());
    let outcomes = cell.actuate(&survey);
    assert_eq!(
        replace_verdict(&outcomes),
        Some(Verdict::Wait(Reason::Moved))
    );
    assert!(effects(&outcomes).is_empty());
    assert_eq!(record_of(&cell, lost.active).state, VolumeState::Active);
    cell.now_us += 10 * S;
    cell.tick();
    assert_eq!(record_of(&cell, lost.active).state, VolumeState::Retired);
    replaced_once(&cell, &lost, false).unwrap();
}

/// Arms an uncommitted timeout for the loop's next store write to `key`; the loop keeps running after it. With
/// `after`, the timeout is armed only once the loop has written that key in the same tick.
fn fail_next_write_to(cell: &Cell, key: Key, after: Option<Key>) {
    let faults = cell.faults.clone();
    let arm = move || {
        let mut faults = faults.borrow_mut();
        faults.survives = true;
        faults.at = Some((faults.effects, Arm::Timeout { commit: false }));
    };
    let armed: Option<(Key, Box<dyn FnOnce()>)> = Some((key, Box::new(arm)));
    *cell.hook.borrow_mut() = None;
    *cell.after.borrow_mut() = None;
    match after {
        None => *cell.hook.borrow_mut() = armed,
        Some(first) => {
            let hook = cell.hook.clone();
            let install = move || *hook.borrow_mut() = armed;
            *cell.after.borrow_mut() = Some((first, Box::new(install)));
        }
    }
}

/// RETIRE-DISPLACED across two flips of one shard in a surviving loop: the first displaced volume's retirement
/// fails on every tick from the flip on, so its record stays active and named by no shard, and its `error` listing counts beside
/// the loss of the shard's second volume, which holds until the operator's release. After the second flip and the
/// end of the fault, the loop retires both displaced volumes and leaves both attached.
#[test]
fn a_second_flip_keeps_the_first_displaced_volume_s_retirement() {
    let (mut cell, lost) = lost_zone();
    let first = lost.active;
    for _ in 0..60 {
        fail_next_write_to(&cell, Key::Volume(first), Some(Key::Shard(shard(1))));
        cell.tick();
        if flipped(&cell, &lost) {
            break;
        }
    }
    let second = cell.shard(1);
    assert!(second.generation > lost.generation);
    assert_eq!(record_of(&cell, first).state, VolumeState::Active);
    cell.fixture.world.volume(second.active, error());
    let mut released = false;
    for _ in 0..120 {
        fail_next_write_to(&cell, Key::Volume(first), None);
        cell.tick();
        let held = receipt(&cell, 1).filter(|held| held.held);
        if let Some(held) = held {
            let release = peer(&cell).release_hold(&OperatorRelease::diagnosed(), held.request);
            released = release.unwrap().value().released;
        }
        if cell.shard(1).generation > second.generation {
            break;
        }
    }
    assert!(
        released,
        "the unretired first volume counts beside the second loss"
    );
    assert!(cell.shard(1).generation > second.generation);
    assert_eq!(record_of(&cell, first).state, VolumeState::Active);
    *cell.hook.borrow_mut() = None;
    cell.faults.borrow_mut().at = None;
    for _ in 0..4 {
        cell.tick();
    }
    for displaced in [first, second.active] {
        assert_eq!(record_of(&cell, displaced).state, VolumeState::Retired);
        let listed = (cell.fixture.world.volumes.iter()).find(|row| row.volume == displaced);
        assert!(!listed.unwrap().attachments.is_empty(), "{displaced:?}");
    }
}

/// Lists shard 1 in the directory the next survey reads, or omits it.
fn list_shard_1(cell: &mut Cell, listed: bool) {
    let mut listing = cell.fixture.listing.clone().unwrap();
    let hosts = listing.hosts.len() as u64;
    let shards = super::directory::listing(hosts, cell.fixture.shards).shards;
    listing.shards = shards;
    if !listed {
        listing.shards.retain(|entry| entry.shard != shard(1));
    }
    listing.version += 1;
    cell.fixture.listing = Some(listing);
}

/// RETIRE-DISPLACED for a shard the directory omits after the flip: the loop reads the shard record itself. With
/// the flip committed and its retirement failed, the displaced volume is retired while the shard stays omitted.
/// With the flip's write uncommitted, the shard record still names the volume active, so the loop writes nothing
/// to the volume's record and keeps the pair.
#[test]
fn a_displaced_volume_is_retired_after_the_directory_omits_its_shard() {
    for flips in [true, false] {
        let (mut cell, lost) = lost_zone();
        let first = lost.active;
        named(&mut cell);
        let failing = match flips {
            true => Key::Volume(first),
            false => Key::Shard(shard(1)),
        };
        fail_next_write_to(&cell, failing, flips.then_some(Key::Shard(shard(1))));
        cell.tick();
        assert_eq!(flipped(&cell, &lost), flips);
        assert_eq!(record_of(&cell, first).state, VolumeState::Active);
        assert!(cell.zone.displaced.contains(&(shard(1), first)));
        *cell.hook.borrow_mut() = None;
        *cell.after.borrow_mut() = None;
        cell.faults.borrow_mut().at = None;
        list_shard_1(&mut cell, false);
        let key = Key::Volume(first);
        let versions = cell.store().0.borrow().versions(&key).len();
        for _ in 0..4 {
            cell.tick();
        }
        let written = cell.store().0.borrow().versions(&key).len() - versions;
        let state = record_of(&cell, first).state;
        let kept = cell.zone.displaced.contains(&(shard(1), first));
        let expected = match flips {
            true => (VolumeState::Retired, false, 1),
            false => (VolumeState::Active, true, 0),
        };
        assert_eq!((state, kept, written), expected, "flips {flips}");
        assert_eq!(flipped(&cell, &lost), flips, "flips {flips}");
    }
}

/// A rejection whose write failed waits while the directory omits its shard: the plan holds no step for the shard,
/// so the loop neither names nor flips the replacement and writes nothing for it. Once the directory lists the
/// shard again, the loop retires the replacement from its memory, after the foreign instance has left.
#[test]
fn a_rejection_waits_while_the_directory_omits_its_shard() {
    let foreign = crate::failover::attachments::InstanceId::new("i-0000beef").unwrap();
    let (mut cell, lost) = lost_zone();
    let replacement = named(&mut cell);
    let spare = cell.shard(1).spare;
    cell.fixture.world.attach(replacement, foreign);
    cell.fault_next(Arm::Timeout { commit: false });
    let (_, outcomes) = cell.tick();
    assert_eq!(
        replace_verdict(&outcomes),
        Some(Verdict::Wait(Reason::Unknown))
    );
    cell.fixture.world.detach(replacement, foreign);
    list_shard_1(&mut cell, false);
    for _ in 0..10 {
        cell.tick();
    }
    assert_eq!(record_of(&cell, replacement).state, VolumeState::Fresh);
    assert_eq!(cell.shard(1).spare, spare);
    assert!(!flipped(&cell, &lost));
    assert!(cell.zone.rejected.contains_key(&replacement));
    list_shard_1(&mut cell, true);
    for _ in 0..6 {
        cell.tick();
    }
    assert_eq!(record_of(&cell, replacement).state, VolumeState::Retired);
    assert_eq!(cell.shard(1).spare, None);
    assert!(!flipped(&cell, &lost));
    assert!(cell.zone.rejected.is_empty());
}

/// The status part of a tick at the cell's current time.
fn part_of(cell: &mut Cell) -> crate::failover::report::status::ZonePart {
    let directory = Ok(cell.fixture.directory());
    let world = &mut cell.fixture.world;
    cell.zone.tick(directory, world, cell.now_us).part
}

/// The listed volumes in `error` whose record reads short of retired and that no shard record names active or
/// spare: a displaced volume whose retirement no process finished.
fn stranded(cell: &Cell) -> Vec<VolumeId> {
    let records: Vec<ShardRecord> = (1..=cell.fixture.shards)
        .map(|number| cell.shard(number))
        .collect();
    let named = |volume: VolumeId| {
        (records.iter()).any(|record| {
            record.active == volume || record.spare.is_some_and(|spare| spare.0 == volume)
        })
    };
    let rows = cell.fixture.world.volumes.iter();
    rows.filter(|row| row.condition == error())
        .map(|row| row.volume)
        .filter(|&volume| !named(volume))
        .filter(|&volume| {
            let key = Key::Volume(volume);
            let item = cell.store().0.borrow().current(&key).cloned();
            item.is_some_and(|item| {
                VolumeRecord::decode(&item.value).unwrap().state < VolumeState::Retired
            })
        })
        .collect()
}

/// What one run of the history of `a_crash_between_the_flip_and_the_retirement_strands_the_displaced_volume` read.
#[derive(Debug, PartialEq, Eq)]
struct Stranding {
    /// The stranded volumes after the flip and ten more ticks.
    stranded: Vec<VolumeId>,
    /// The part's blocker counts, held receipts and lost active volumes on a tick before the second loss.
    quiet: (u32, u32, u32),
    /// The part's count of unnamed volumes on that tick.
    unnamed: Option<u64>,
    /// The count of other impaired volumes shard 2's loss read, and whether its receipt latched held.
    beside: (usize, bool),
}

/// RETIRE-DISPLACED under a crash: the process stops right after the flip's shard write commits and before the
/// displaced volume's retirement, and a restarted loop runs on. No later tick retires the displaced volume: its
/// record stays active, no shard names it, and the status part shows no blocker, no held receipt and no lost active
/// volume for it. The part counts it as one unnamed volume, the `volume-unnamed` alarm's signal, from the first
/// complete tick after the crash. Its `error` listing counts beside the next loss in the zone, so shard 2's loss latches a held
/// receipt and reads `ReplacementHeld` with `CorrelatedHold`, the status counts one held receipt (the
/// `replacement-held` alarm's signal), and no provider call follows. The operator clears it with two acts: the
/// retirement of the displaced volume, after which shard 2's loss reads no other impaired volume, and the release
/// of the hold, after which shard 2 flips once. The run without the crash is the control: the displaced volume is
/// retired in the flip's step, nothing is stranded, and shard 2's loss provisions with no hold.
#[test]
fn a_crash_between_the_flip_and_the_retirement_strands_the_displaced_volume() {
    use crate::failover::report::alarm_tests::controls::{self, Twin};
    use crate::failover::report::status::{RECEIPTS, ReceiptCount};
    let held_at = at(RECEIPTS, ReceiptCount::Held);
    let lost_at =
        crate::failover::report::status::health_at(Some(crate::failover::loss::Health::Lost));
    let others_of = |cell: &mut Cell, number: u32| {
        let survey = cell.survey();
        let view = survey.observation.zone.as_ref().unwrap();
        let found = view.shards.iter().find(|held| held.shard == shard(number));
        let records = found.unwrap().records.as_ref().unwrap().as_ref().unwrap();
        records.judgement.others
    };
    let run = |crash: bool| {
        let (mut cell, lost) = lost_zone();
        named(&mut cell);
        if crash {
            let faults = cell.faults.clone();
            let stop = move || faults.borrow_mut().dead = true;
            *cell.after.borrow_mut() = Some((Key::Shard(shard(1)), Box::new(stop)));
        }
        cell.tick();
        assert_eq!(cell.restarts, usize::from(crash));
        assert_eq!(cell.shard(1).generation.get(), lost.generation.get() + 1);
        for _ in 0..10 {
            cell.tick();
        }
        replaced_once(&cell, &lost, crash).unwrap();
        let stranded_after = stranded(&cell);
        let part = part_of(&mut cell);
        let quiet = (
            part.blockers.iter().sum::<u32>(),
            part.receipts[held_at],
            part.volumes[lost_at],
        );
        let unnamed = part.unnamed_volumes;
        cell.fixture.world.volume(lost.other.active, error());
        for _ in 0..10 {
            cell.tick();
        }
        let beside = others_of(&mut cell, 2);
        let held = receipt(&cell, 2).is_some_and(|held| held.held);
        let seen = Stranding {
            stranded: stranded_after,
            quiet,
            unnamed,
            beside: (beside, held),
        };
        (cell, lost, seen)
    };

    let (mut control, lost, seen) = run(false);
    let clean = Stranding {
        stranded: Vec::new(),
        quiet: (0, 0, 0),
        unnamed: Some(0),
        beside: (0, false),
    };
    assert_eq!(seen, clean, "the run without the crash");
    assert_eq!(record_of(&control, lost.active).state, VolumeState::Retired);
    control.run_until(60, |cell| cell.shard(2).generation > lost.other.generation);
    assert!(control.shard(2).generation > lost.other.generation);
    let unheld = part_of(&mut control).receipts[held_at];

    let (mut cell, lost, seen) = run(true);
    let held = Stranding {
        stranded: vec![lost.active],
        quiet: (0, 0, 0),
        unnamed: Some(1),
        beside: (1, true),
    };
    assert_eq!(seen, held, "the run with the crash");
    let unnamed = Twin {
        fault: seen.unnamed,
        clean: clean.unnamed,
    };
    assert_eq!(unnamed, controls::volume_unnamed(), "volume-unnamed");
    assert_eq!(record_of(&cell, lost.active).state, VolumeState::Active);
    let (survey, _) = cell.tick();
    let plan = (survey.plan.shards.iter()).find(|plan| plan.shard == shard(2));
    let plan = plan.unwrap();
    assert_eq!(
        (plan.state, plan.blocker),
        (ShardState::ReplacementHeld, Some(Blocker::CorrelatedHold))
    );
    let part = part_of(&mut cell);
    assert_eq!(part.blockers[Blocker::CorrelatedHold.position()], 1);
    assert_eq!(part.volumes[lost_at], 1);
    assert_eq!(part.unnamed_volumes, Some(1));
    let alarm = Twin {
        fault: part.receipts[held_at],
        clean: unheld,
    };
    assert_eq!(alarm, controls::replacement_held(), "replacement-held");
    assert_eq!(calls(&cell), 1, "no create for shard 2 under the hold");

    let retired = peer(&cell).retire(shard(1), lost.active);
    assert!(retired.is_ok(), "{retired:?}");
    assert_eq!(record_of(&cell, lost.active).state, VolumeState::Retired);
    assert_eq!(stranded(&cell), []);
    for _ in 0..10 {
        cell.tick();
    }
    assert_eq!(others_of(&mut cell, 2), 0);
    let latched = receipt(&cell, 2).unwrap();
    assert!(
        latched.held && calls(&cell) == 1,
        "the retirement alone leaves the latched hold"
    );
    let released = peer(&cell).release_hold(&OperatorRelease::diagnosed(), latched.request);
    assert!(released.unwrap().value().released);
    cell.run_until(60, |cell| cell.shard(2).generation > lost.other.generation);
    assert_eq!(
        cell.shard(2).generation.get(),
        lost.other.generation.get() + 1
    );
    let part = part_of(&mut cell);
    assert_eq!((part.receipts[held_at], part.unnamed_volumes), (0, Some(0)));
    assert_eq!(calls(&cell), 2);
    cell.clean();
}

/// The step rechecks the loss evidence the plan decided on: a survey whose shard reads its loss confirmed from the
/// tick before on a view that is incomplete now plans no replacement, and a replace step planted into that survey
/// starts no receipt.
#[test]
fn a_planted_step_starts_no_receipt_on_an_incomplete_view() {
    let (mut cell, _lost) = lost_zone();
    let judged = |survey: &crate::failover::zone_loop::plan::Survey| {
        let view = survey.observation.zone.as_ref().unwrap();
        view.shards[0]
            .records
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
            .judgement
    };
    let mut confirmed = None;
    for _ in 0..10 {
        let survey = cell.survey();
        cell.now_us += 10 * S;
        if judged(&survey).confirmed {
            confirmed = Some(survey);
            break;
        }
    }
    assert!(confirmed.is_some() && receipt(&cell, 1).is_none());
    let unknown = condition(ListedVolumeState::InUse, VolumeStatus::InsufficientData);
    cell.fixture.world.volume(volume(2), unknown);
    let mut survey = cell.survey();
    let now = judged(&survey);
    assert!(now.confirmed && !now.complete && now.others == 0, "{now:?}");
    let replaces = |step: &Step| matches!(step, Step::Replace { .. });
    assert!(!survey.plan.steps.iter().any(replaces));
    survey.plan.steps.push(Step::Replace {
        shard: shard(1),
        target: crate::failover::retire::Target::of(&cell.shard(1)),
        host: None,
    });
    let outcomes = cell.actuate(&survey);
    assert_eq!(
        replace_verdict(&outcomes),
        Some(Verdict::Wait(Reason::Unconfirmed))
    );
    assert_eq!(receipt(&cell, 1), None);
    assert_eq!(calls(&cell), 0);
}

/// CORRELATED-HOLD needs the active volume's own loss in the abandon too: a created replacement reads lost while
/// the active volume reads in use again and another volume reads impaired. The loop retires the lost replacement
/// and the receipt's next attempt opens unheld, with no provider call while the active volume's loss does not read.
#[test]
fn an_abandon_over_a_recovered_volume_opens_the_next_attempt_unheld() {
    let (mut cell, lost) = lost_zone();
    let first = created(&mut cell);
    cell.fixture.world.volume(volume(1), in_use());
    cell.fixture.world.volume(volume(2), warning());
    cell.fixture.world.volume(first, error());
    for _ in 0..20 {
        cell.tick();
        if receipt(&cell, 1).unwrap().attempt > 1 {
            break;
        }
    }
    let next = receipt(&cell, 1).unwrap();
    assert_eq!(
        (next.attempt, next.phase, next.held),
        (2, Phase::Open, false),
        "a peer's impairment holds no receipt over a recovered volume"
    );
    assert_eq!(record_of(&cell, first).state, VolumeState::Retired);
    for _ in 0..6 {
        cell.tick();
    }
    assert!(!receipt(&cell, 1).unwrap().held);
    assert_eq!(calls(&cell), 1);
    assert_eq!(cell.shard(1).generation, lost.generation);
}

/// VERIFY-BEFORE-NAMING after the naming: a named replacement whose listing no longer shows its attaching host's
/// instance raises `Foreign`, gets no further attach request and is not flipped.
#[test]
fn a_named_spare_without_its_own_attachment_alarms_and_takes_no_attach() {
    let (mut cell, lost) = lost_zone();
    let replacement = named(&mut cell);
    let (_, host) = cell.shard(1).spare.unwrap();
    let own = super::directory::instance(host.get());
    cell.fixture.world.detach(replacement, own);
    let sent = cell.attach_calls().len();
    let mut alarms = 0;
    for _ in 0..10 {
        let (_, outcomes) = cell.tick();
        alarms += usize::from(replace_verdict(&outcomes) == Some(Verdict::Alarm(Reason::Foreign)));
    }
    assert_eq!(alarms, 10);
    assert_eq!(
        cell.attach_calls().len(),
        sent,
        "no attach request for a named spare"
    );
    assert_eq!(cell.shard(1).generation, lost.generation);
    assert_eq!(cell.shard(1).spare, Some((replacement, host)));
}

/// IDEMPOTENT-PROVISIONING when the lost reply's volume lists in `error`: the create's reply is lost after the
/// provider made the volume, which has no record and reads `error`. The loop repeats the same token after the settle
/// time, records that volume, reads it lost, retires it and flips to the volume of the next attempt's token.
#[test]
fn a_lost_reply_whose_volume_reads_error_is_settled_under_the_same_token() {
    let (mut cell, lost) = lost_zone();
    cell.fixture.world.provider.lose = 1;
    let mut first = None;
    for _ in 0..120 {
        cell.tick();
        if first.is_none()
            && let Some(&(_, volume)) = made(&cell).first()
        {
            assert_eq!(receipt(&cell, 1).unwrap().phase, Phase::Issued);
            cell.fixture.world.volume(volume, error());
            first = Some(volume);
        }
        if flipped(&cell, &lost) {
            break;
        }
    }
    let first = first.expect("the lost create made a volume");
    let calls = cell.fixture.world.provider.layouts.iter();
    let tokens: Vec<&str> = calls.map(|(token, _)| token.as_str()).collect();
    assert_eq!(tokens.len(), 3, "{tokens:?}");
    assert_eq!(tokens[0], tokens[1], "the unknown create repeats its token");
    assert_ne!(tokens[1], tokens[2], "the next attempt has its own token");
    assert_eq!(record_of(&cell, first).state, VolumeState::Retired);
    let made = made(&cell);
    assert_eq!(made.len(), 2, "one volume for each token");
    let now = cell.shard(1);
    assert_eq!(now.generation.get(), lost.generation.get() + 1);
    assert_eq!(now.active, made[1].1);
    assert_eq!(flip_breach(&cell, &lost), None);
    cell.clean();
}

/// ONE-ATTEMPT for the replacement's effects: two shards replace their volumes side by side, at `calls_per_tick = 1`
/// with the default write budget and at `writes_per_tick = 1` too. No tick sends more than one provider or attach
/// call, and a step past the budget waits with `Budget`. A one-write budget allows at most one budgeted
/// store-writing replacement effect per tick. The correlated hold starts and latches independently of that budget.
/// A displaced volume's failed retirement retries on a tick with write budget left after planned steps.
#[test]
fn replacement_steps_share_the_tick_s_write_and_call_budgets() {
    for one_write in [false, true] {
        let mut config = super::config::config_of(8);
        config.replacements_inflight_max = 2;
        if one_write {
            config.writes_per_tick = 1;
        }
        let mut cell = Cell::with(4, 2, true, config.validate().unwrap().with_calls(1));
        cell.run_until(400, Cell::designated);
        assert!(cell.designated());
        let before = [cell.shard(1), cell.shard(2)];
        for record in &before {
            cell.fixture.world.volume(record.active, error());
        }
        let moved = |cell: &Cell, number: u32| {
            cell.shard(number).generation > before[number as usize - 1].generation
        };
        let (mut waited, mut over_budget, mut retried_beside_a_write) = (0, 0, 0);
        for _ in 0..400 {
            let held: Vec<Receipt> = [1, 2]
                .into_iter()
                .filter_map(|number| receipt(&cell, number).filter(|held| held.held))
                .collect();
            if held.len() == 2 {
                for held in held {
                    let released =
                        peer(&cell).release_hold(&OperatorRelease::diagnosed(), held.request);
                    assert!(released.unwrap().value().released);
                }
            }
            if !moved(&cell, 1) {
                let first = Some(Key::Shard(shard(1)));
                fail_next_write_to(&cell, Key::Volume(before[0].active), first);
            } else {
                *cell.hook.borrow_mut() = None;
                *cell.after.borrow_mut() = None;
                cell.faults.borrow_mut().at = None;
            }
            let pending =
                moved(&cell, 1) && record_of(&cell, before[0].active).state != VolumeState::Retired;
            let calls_before = calls(&cell) + cell.attach_calls().len();
            let (_, outcomes) = cell.tick();
            let sent = calls(&cell) + cell.attach_calls().len() - calls_before;
            assert!(sent <= 1, "{sent} calls in one tick, one write {one_write}");
            let wrote = (outcomes.iter())
                .filter(|outcome| {
                    outcome.verdict != Verdict::Wait(Reason::Budget)
                        && matches!(
                            outcome.replaced,
                            Some(
                                Replaced::Decided(Decision::Provision(_))
                                    | Replaced::Created(_)
                                    | Replaced::Recorded
                                    | Replaced::Named
                                    | Replaced::Flipped
                                    | Replaced::Abandoned
                                    | Replaced::Rejected
                            )
                        )
                })
                .count();
            assert!(
                !one_write || wrote <= 1,
                "{wrote} budgeted replacement writes in one tick"
            );
            over_budget += (outcomes.iter())
                .filter(|outcome| outcome.verdict == Verdict::Wait(Reason::Budget))
                .count();
            let retired = record_of(&cell, before[0].active).state == VolumeState::Retired;
            if pending && wrote == 1 {
                waited += 1;
                retried_beside_a_write += usize::from(retired);
            }
            if moved(&cell, 1) && moved(&cell, 2) && retired {
                break;
            }
        }
        assert!(moved(&cell, 1) && moved(&cell, 2));
        assert!(over_budget > 0, "a step past the budget waits");
        if one_write {
            assert!(
                waited > 0,
                "a displaced retirement met a tick whose write was taken"
            );
            assert_eq!(retried_beside_a_write, 0);
        }
        for record in &before {
            assert_eq!(record_of(&cell, record.active).state, VolumeState::Retired);
        }
        assert_eq!(made(&cell).len(), 2);
        cell.clean();
    }
}

/// With `writes_per_tick = 1`, actuation writes every planned correlated hold, even when an earlier hold spends the
/// write budget or a create spends both the write and call budgets. In the last case one tick runs while shard 1's
/// receipt is held, so its step leaves the plan and the tried steps (WRITE-YIELD), and the later actuation runs
/// shard 1's create before shard 2's hold, in plan order.
#[test]
fn a_correlated_hold_is_written_on_a_tick_whose_budget_is_spent() {
    let zone = |calls_per_tick: u32| {
        let mut config = super::config::config_of(8);
        config.replacements_inflight_max = 2;
        config.writes_per_tick = 1;
        let mut cell = Cell::with(
            4,
            2,
            true,
            config.validate().unwrap().with_calls(calls_per_tick),
        );
        cell.run_until(400, Cell::designated);
        let active = [cell.shard(1).active, cell.shard(2).active];
        (cell, active)
    };
    let held = |cell: &Cell, number: u32| receipt(cell, number).is_some_and(|held| held.held);
    let ticked_until_receipt = |cell: &mut Cell, number: u32| {
        for _ in 0..40 {
            if let Some(held) = receipt(cell, number) {
                return held;
            }
            cell.tick();
        }
        panic!("no receipt of shard {number} within 40 ticks");
    };
    let correlated = |survey: &Survey, number: u32| {
        let shards = &survey.observation.zone.as_ref().unwrap().shards;
        let view = shards.iter().find(|view| view.shard == shard(number));
        let records = view.and_then(|view| view.records.as_ref().ok()?.as_ref());
        records.is_some_and(|records| records.judgement.others > 0 && records.judgement.confirmed)
    };
    let surveyed_until = |cell: &mut Cell, ready: &dyn Fn(&Survey) -> bool| {
        for _ in 0..20 {
            let survey = cell.survey();
            if ready(&survey) {
                return survey;
            }
            cell.now_us += 10 * S;
        }
        panic!("no survey within 20 reads the correlated loss");
    };

    let (mut cell, active) = zone(8);
    for volume in active {
        cell.fixture.world.volume(volume, error());
    }
    ticked_until_receipt(&mut cell, 1);
    assert!(
        held(&cell, 1) && held(&cell, 2),
        "two holds start on one tick"
    );
    cell.fixture.world.volume(active[0], in_use());
    for _ in 0..20 {
        cell.tick();
    }
    assert!(
        held(&cell, 2),
        "the hold outlives the other volume's recovery"
    );
    assert_eq!(calls(&cell), 0);

    let (mut cell, active) = zone(8);
    cell.fixture.world.volume(active[1], error());
    let open = ticked_until_receipt(&mut cell, 2);
    assert!(!open.held && !open.released, "{open:?}");
    cell.fixture.world.volume(active[0], error());
    let both = |survey: &Survey| correlated(survey, 1) && correlated(survey, 2);
    let survey = surveyed_until(&mut cell, &both);
    cell.actuate(&survey);
    assert!(
        held(&cell, 1) && held(&cell, 2),
        "a hold starts and a pending receipt latches on one tick"
    );

    let (mut cell, active) = zone(1);
    cell.fixture.world.volume(active[0], error());
    cell.fixture.world.volume(active[1], warning());
    let first = ticked_until_receipt(&mut cell, 1);
    assert!(first.held, "{first:?}");
    cell.tick();
    let released = peer(&cell).release_hold(&OperatorRelease::diagnosed(), first.request);
    assert!(released.unwrap().value().released);
    cell.fixture.world.volume(active[1], error());
    let second = |survey: &Survey| correlated(survey, 2);
    let survey = surveyed_until(&mut cell, &second);
    let outcomes = cell.actuate(&survey);
    let created = |outcome: &Outcome| outcome.replaced == Some(Replaced::Created(Ok(())));
    assert!(
        outcomes.iter().any(created),
        "shard 1's create spends the tick's write and call: {outcomes:?}"
    );
    assert!(held(&cell, 2), "a hold starts after a create on one tick");
    assert_eq!(calls(&cell), 1);
}

/// VERIFY-BEFORE-NAMING for a draining attaching host: a host that attaches the replacement without owning the shard
/// and then drains raises `Attacher`, takes no attach request and is neither named nor flipped to; the shard's owner
/// that drains after its attach record still takes the replacement, since the flip keeps it the owner.
#[test]
fn a_draining_attaching_host_is_admitted_only_as_the_shard_s_owner() {
    let (mut cell, lost) = lost_zone();
    cell.drain(lost.owner);
    let replacement = recorded(&mut cell);
    let attacher = record_of(&cell, replacement).events[0].host;
    assert_ne!(attacher, lost.owner);
    cell.drain(attacher);
    let sent = cell.attach_calls().len();
    let mut alarms = 0;
    for _ in 0..20 {
        let (_, outcomes) = cell.tick();
        alarms += usize::from(replace_verdict(&outcomes) == Some(Verdict::Alarm(Reason::Attacher)));
    }
    assert_eq!(alarms, 20);
    assert_eq!(cell.attach_calls().len(), sent);
    assert_eq!(cell.shard(1).spare, None);
    assert_eq!(cell.shard(1).generation, lost.generation);

    let (mut cell, lost) = lost_zone();
    let replacement = recorded(&mut cell);
    assert_eq!(record_of(&cell, replacement).events[0].host, lost.owner);
    cell.drain(lost.owner);
    cell.run_until(60, |cell| flipped(cell, &lost));
    replaced_once(&cell, &lost, false).unwrap();
    assert_eq!(cell.shard(1).owner, lost.owner);
}

/// The replacement's attach record needs its host's report at `MIN_ERA` or later: a survey whose report of the
/// planned host reads an earlier era records nothing and raises `Era`.
#[test]
fn a_replacement_host_below_the_era_floor_records_no_attach() {
    let (mut cell, _lost) = lost_zone();
    let replacement = created(&mut cell);
    let mut survey = cell.survey();
    let planned = survey.plan.steps.iter().find_map(|step| match *step {
        Step::Replace { host, .. } => host,
        _ => None,
    });
    let planned = planned.expect("the plan chose the replacement's host");
    let view = survey.observation.zone.as_mut().unwrap();
    let held = (view.hosts.iter_mut()).find(|held| held.entry.host == planned);
    let report = held.unwrap().report.as_mut().unwrap();
    std::sync::Arc::make_mut(report).host.build.era = crate::failover::records::MIN_ERA - 1;
    let outcomes = cell.actuate(&survey);
    assert_eq!(
        replace_verdict(&outcomes),
        Some(Verdict::Alarm(Reason::Era))
    );
    let record = record_of(&cell, replacement);
    assert_eq!(
        (record.state, record.events.len()),
        (VolumeState::Provisioning, 0)
    );
}

/// FLIP-ENTRY through the loop: the loop surveys its named, verified spare, the shard record's spare slot then
/// changes to another unused volume of the same host, and the actuation of that survey flips nothing: the shard
/// keeps its generation, its active volume and the other spare.
#[test]
fn the_loop_flips_only_to_the_spare_it_verified() {
    let (mut cell, lost) = lost_zone();
    let spare = named(&mut cell);
    let survey = cell.survey();
    let (_, host) = cell.shard(1).spare.unwrap();
    let era = record_of(&cell, spare).events[0].era;
    let other = VolumeId::new("vol-0f").unwrap();
    let mut second = peer(&cell);
    second
        .provision(other, cell.bounds.config().replacement)
        .unwrap();
    second.record_attach(other, host, era).unwrap();
    let mut client = reconciler_client(cell.store());
    let read = client.read::<ShardRecord>(Key::Shard(shard(1))).unwrap();
    let swapped = ShardRecord {
        spare: Some((other, host)),
        ..*read.value()
    };
    client.replace(&read, swapped).unwrap();
    let outcomes = cell.actuate(&survey);
    assert_eq!(
        replace_verdict(&outcomes),
        Some(Verdict::Wait(Reason::Moved))
    );
    let now = cell.shard(1);
    assert_eq!(
        (now.generation, now.active, now.spare),
        (lost.generation, lost.active, Some((other, host)))
    );
    assert_eq!(flip_breach(&cell, &lost), None);
}

/// LOSS-NEEDS-EVIDENCE per effect at each configured run: with `loss_ticks` 2 and 3, an open receipt over a volume
/// still in `error` makes no create on the incomplete tick or on the complete ticks after it until the run of
/// complete views reaches `loss_ticks`, and creates on the tick that completes the run.
#[test]
fn the_create_waits_for_the_configured_run_of_complete_views() {
    for loss_ticks in [2u32, 3] {
        let mut config = super::config::config_of(8);
        config.loss_ticks = loss_ticks;
        let mut cell = Cell::with(4, 2, true, config.validate().unwrap());
        cell.run_until(80, Cell::designated);
        cell.fixture.world.volume(volume(1), error());
        for _ in 0..20 {
            let survey = cell.survey();
            let open = (survey.plan.steps.iter()).any(|step| matches!(step, Step::Replace { .. }));
            if open {
                let outcomes = cell.actuate(&survey);
                assert_eq!(effects(&outcomes).len(), 1, "the receipt's start");
                cell.now_us += 10 * S;
                break;
            }
            cell.actuate(&survey);
            cell.now_us += 10 * S;
        }
        assert_eq!(receipt(&cell, 1).unwrap().phase, Phase::Open);
        let unknown = condition(ListedVolumeState::InUse, VolumeStatus::InsufficientData);
        cell.fixture.world.volume(volume(2), unknown);
        cell.tick();
        cell.fixture.world.volume(volume(2), in_use());
        for view in 1..loss_ticks {
            let (_, outcomes) = cell.tick();
            assert_eq!(
                replace_verdict(&outcomes),
                Some(Verdict::Wait(Reason::Unconfirmed)),
                "complete view {view} of {loss_ticks}"
            );
            assert_eq!(calls(&cell), 0);
        }
        cell.tick();
        assert_eq!(calls(&cell), 1, "the create on complete view {loss_ticks}");
    }
}

/// CORRELATED-HOLD with a hold that latches after the survey of an open receipt: the actuation of that survey sends
/// no create and leaves the receipt held and open.
#[test]
fn a_hold_latched_after_the_survey_stops_the_create() {
    let (mut cell, _lost) = lost_zone();
    for _ in 0..20 {
        cell.tick();
        if receipt(&cell, 1).is_some() {
            break;
        }
    }
    let open = receipt(&cell, 1).unwrap();
    assert_eq!(open.phase, Phase::Open);
    let survey = cell.survey();
    let latched = peer(&cell).latch(&StandbyGate::qualified(), open.request);
    assert!(latched.unwrap().value().held);
    let outcomes = cell.actuate(&survey);
    assert_eq!(
        replace_verdict(&outcomes),
        Some(Verdict::Wait(Reason::Held))
    );
    assert_eq!(calls(&cell), 0);
    let now = receipt(&cell, 1).unwrap();
    assert_eq!((now.attempt, now.phase, now.held), (1, Phase::Open, true));
}

/// The call budget leaves a call to a replacement: `ZoneConfig::validate` admits `calls_per_tick` only above
/// `enroll_inflight_max`. Two enrollments are in flight and each sends its attach request on every tick, since the
/// control plane answers unknown and `attach_settle_us` is one tick; shard 3's active volume then reads lost. At
/// the first admitted budget, three calls, the replacement's create is sent on a tick on which both enrollments
/// request. At two calls, the budget validation refuses, the create waits on the budget on every such tick.
#[test]
fn a_replacement_s_create_is_sent_on_a_tick_on_which_every_enrollment_requests() {
    for budget in [3, 2] {
        let mut config = super::config::config_of(8);
        config.enroll_inflight_max = 2;
        config.calls_per_tick = 3;
        config.attach_settle_us = config.tick_us;
        let mut cell = Cell::with(12, 3, true, config.validate().unwrap().with_calls(budget));
        let faults = &mut cell.fixture.world.faults.attach;
        faults.extend([AttachFault::Unknown { attached: false }; 256]);
        let ticked = |cell: &mut Cell| {
            let events = cell.fixture.world.events().len();
            let (_, outcomes) = cell.tick();
            let requests = (cell.fixture.world.events()[events..].iter())
                .filter(|event| matches!(event, super::world::Event::Attach(..)))
                .count();
            (requests, outcomes)
        };
        for _ in 0..20 {
            if ticked(&mut cell).0 == 2 {
                break;
            }
        }
        cell.fixture.world.volume(volume(3), error());
        let (mut created, mut waits) = (None, 0);
        for _ in 0..40 {
            let (requests, outcomes) = ticked(&mut cell);
            assert_eq!(
                requests, 2,
                "each enrollment in flight requests on every tick"
            );
            let replace = |outcome: &&Outcome| matches!(outcome.step, Step::Replace { .. });
            let step = outcomes.iter().find(replace);
            if step.is_some_and(|outcome| outcome.replaced == Some(Replaced::Created(Ok(())))) {
                created = Some(requests);
                break;
            }
            let budgeted = Some(Verdict::Wait(Reason::Budget));
            waits += usize::from(step.map(|outcome| outcome.verdict) == budgeted);
        }
        match budget {
            3 => assert_eq!((created, calls(&cell), waits), (Some(2), 1, 0)),
            _ => {
                assert_eq!((created, calls(&cell)), (None, 0));
                assert!(waits >= 30, "{waits} ticks waited on the budget");
            }
        }
    }
}
