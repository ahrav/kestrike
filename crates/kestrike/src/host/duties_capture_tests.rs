use std::cell::Cell;
use std::rc::Rc;
use std::sync::atomic::Ordering;

use super::capture::{ADMIT_ARENA, Pass, STALE_EPOCH, Unit};
use super::tests::{Filling, fill_bytes, fill_step, log_open, periods, records};
use super::view_tests::{Events, Listing};
use super::{CaptureRefusal, Duties, Open, Uncaptured};
use crate::failover::fresh::tests as fresh_tests;
pub(super) use crate::failover::fresh::tests::shard_now as shard_record;
use crate::failover::records::{Host, NamedCheckpoint, Suffix, VolumeRecord};
use crate::failover::report::Gauge;
use crate::host::duties::tests::TEST_VIEW_US as VIEW_US;
use crate::host::lane::tests::{Locked, bounds, locked_client};
use crate::host::lane::{Lane, Plane};
use crate::host::recover_tests::own_holds;
use crate::host::serve::loop_tests::{
    Stage, TestOwner, staged_fresh, staged_fresh_on, staged_over, staged_over_on,
};
use crate::host::serve::tests::warm_volume_certified;
use crate::host::serve::tests::{content, restart_short_of_live};
use crate::host::{Exit, HostGate, Rerun};
use crate::net::{Outcome as Fetched, RequestId, SessionState};
use crate::storage::PARK_RECOVERY;
use crate::storage::WorkBudget;
use crate::storage::checkpoint::{
    Checkpoint, PossiblyNamed, StagedCheckpoint, UNIT_LEN, WriteRefused,
};
use crate::storage::device::sim::Media;
use crate::storage::gate_fixture::Control;
use crate::storage::owner_fixture::held_units;
use crate::storage::owner_fixture::reserve_at;
use crate::storage::owner_fixture::{residents, units_free};
use crate::storage::page_coverage::Interval;
use crate::storage::portable::{Reading, Trust, Untrusted};
use crate::storage::store::sim::Arm;
use crate::storage::store::sim::{MemLog, Shared};
use crate::storage::store::{Client, Key, StoreError};
use crate::storage::store::{Item, Outcome, Refusal, Store, Unavailable, Write};
use crate::storage::store_tests::{SPARE, shard};
use crate::storage::test_platform::TestPlatform;
use crate::storage::warm_sim::layout;
use crate::storage::warm_sim::object_key;
use crate::storage::warm_sim::{
    REFUSE_ABSENT, REPLAY_PLANT, RETAIN_ABSENT, ReplayPlant, sequence_storage, storage,
    wide_storage,
};
use crate::storage::warm_sim::{
    block_unit, live_only_insert, region, shard_store_with, suffix_block, tenure_replacing,
};
use crate::storage::{
    CacheVersion, CaptureConfig, CapturePolicy, Decision, EXTENT_PAYLOAD, EngineBudget,
    FillPublishError, FillReserveError, IO_UNIT, LayoutError, LoadRefusal, MetadataOutcome,
    Readiness, SlotIndex, SlotState, Storage,
};

pub(super) type CaptureDuties<'w> = Duties<'w, Shared, MemLog, TestPlatform>;

fn policy() -> CapturePolicy {
    policy_every(1_000_000)
}

pub(super) fn policy_every(time_ceiling_ns: u64) -> CapturePolicy {
    policy_bounded(time_ceiling_ns, 1 << 12)
}

/// [`policy_every`] whose starts admit at most `slot_bound` storage slots.
pub(super) fn policy_bounded(time_ceiling_ns: u64, slot_bound: usize) -> CapturePolicy {
    let config = CaptureConfig {
        n_max: 1 << 12,
        slot_bound,
        byte_trigger: u64::MAX,
        time_ceiling_ns,
        paced_unit_ns: 100_000,
        fast_unit_ns: 100_000,
        decision_ns: 1,
        max_removals_per_second: 1,
        q_cap: 1 << 12,
        extent_words: 1 << 12,
    };
    CapturePolicy::new(config, 0, &mut EngineBudget::unlimited()).unwrap()
}

fn capture_duties<'w>(stage: &Stage<'w>) -> CaptureDuties<'w> {
    capture_duties_under(stage, policy())
}

pub(super) fn capture_duties_under<'w>(
    stage: &Stage<'w>,
    policy: CapturePolicy,
) -> CaptureDuties<'w> {
    capturing_over(stage, policy).unwrap()
}

/// Duties over an inline lane on `stage`'s store and storage, and their [`Duties::capturing`] of `policy`.
fn capturing_over<'w>(
    stage: &Stage<'w>,
    policy: CapturePolicy,
) -> Result<CaptureDuties<'w>, Box<Uncaptured<'w, Shared, MemLog, TestPlatform>>> {
    let client = Client::open(stage.store.clone(), MemLog::default()).unwrap();
    Duties::new(
        (
            &HostGate::qualified(),
            crate::failover::reconcile::StandbyGate::qualified(),
        ),
        Lane::inline(client, stage.storage),
        records(),
        None,
        bounds(),
        periods(),
    )
    .capturing(policy, EngineBudget::unlimited())
}

/// A fresh acquisition's store whose volume record's layout maps the attached volume's metadata prefix.
pub(super) fn fresh_store() -> Shared {
    let volume = VolumeRecord {
        layout: layout(),
        ..fresh_tests::volume_record()
    };
    fresh_tests::store(fresh_tests::shard_record(0), volume)
}

/// Replaces the shard record with `change` applied, as another writer of the record would.
fn replaced_record(
    store: &Shared,
    change: impl FnOnce(&mut crate::failover::records::ShardRecord),
) {
    let mut client = Client::open(store.clone(), MemLog::default()).unwrap();
    let read = client.read(Key::Shard(shard())).unwrap();
    let mut next = *read.value();
    change(&mut next);
    client.replace(&read, next).unwrap();
}

pub(super) fn published(duties: &CaptureDuties<'_>) -> u64 {
    duties
        .capture
        .as_ref()
        .map_or(0, |capture| capture.published)
}

/// The bytes the warm volume's suffix and the tenure's fills leave for object `n`: the predecessor's suffix replaced
/// object 2.
pub(crate) fn replaced(n: u8) -> Vec<u8> {
    let mut bytes = content(n, n);
    if n == 2 {
        bytes[4..].fill(0xee);
    }
    bytes
}

/// The outcome and the bytes of a GET of each of `keys` after a restart over `volume`.
fn served_after_restart(volume: (Shared, Media), keys: &[u8]) -> Vec<(u8, Fetched, Vec<u8>)> {
    served_after_restart_on(volume, own_holds(), || storage(1), keys)
}

/// [`served_after_restart`] over the reservation table `registry` and the storage `make` builds.
fn served_after_restart_on(
    volume: (Shared, Media),
    registry: Control,
    make: fn() -> Storage<TestPlatform>,
    keys: &[u8],
) -> Vec<(u8, Fetched, Vec<u8>)> {
    staged_over_on(volume, registry, make, |mut stage| {
        let mut gets: Vec<(u8, RequestId, Vec<u8>)> = Vec::new();
        let mut done = Vec::new();
        let served = stage.serve(
            |rounds, _, stop| {
                let active = rounds.client.borrow().state() == SessionState::Active;
                if active && gets.len() == done.len() && done.len() < keys.len() {
                    let n = keys[done.len()];
                    gets.push((n, rounds.get(n), Vec::new()));
                }
                if let Some((n, id, bytes)) = gets.get_mut(done.len())
                    && let Some(outcome) = rounds.fetched(*id, bytes)
                {
                    done.push((*n, outcome, std::mem::take(bytes)));
                }
                if done.len() == keys.len() {
                    stop.store(true, Ordering::Release);
                }
            },
            |_: &mut TestOwner<'_>, _| {},
        );
        assert_eq!(served.exit, Exit::Stopped);
        done
    })
}

/// The kind of `pass` and of its unit command, for the per-turn transition check.
fn step_of(pass: &Pass) -> (u8, Option<Unit>) {
    match pass {
        Pass::Idle => (0, None),
        Pass::Walking { .. } => (1, None),
        Pass::Walked { .. } => (2, None),
        Pass::Encoding { .. } => (3, None),
        Pass::Writing { unit, .. } => (4, Some(*unit)),
        Pass::Proving { .. } => (5, None),
        Pass::Publishing { .. } => (6, None),
        Pass::Finishing { .. } => (7, None),
    }
}

/// Whether a turn may move the pass from `from` to `to`: no move, or one edge of the pass or of its unit commands.
fn one_transition(from: (u8, Option<Unit>), to: (u8, Option<Unit>)) -> bool {
    let unit = |unit: Option<Unit>| match unit {
        Some(Unit::Write(at)) => (0, at),
        Some(Unit::Written(at)) => (1, at),
        Some(Unit::Read(at)) => (2, at),
        Some(Unit::Reading(at)) => (3, at),
        None => (0, 0),
    };
    match (from, to) {
        _ if from == to => true,
        ((4, a), (4, b)) => {
            let ((a, at), (b, bt)) = (unit(a), unit(b));
            (b == a + 1 && at == bt) || (a == 3 && b == 0 && bt == at + 1)
        }
        ((4, _), (5, _)) | ((5, _), (6, _)) | ((6, _), (7, _)) => true,
        ((7, _), (0, _)) | ((0, _), (1, _)) | ((1, _), (2, _)) | ((2, _), (3, _)) => true,
        ((3, _), (4, Some(Unit::Write(0)))) => true,
        _ => false,
    }
}

/// VerifiedBeforePublish: a `Live` tenure with fills publishes a checkpoint for its own session at a cut above the
/// record's, each turn moving the pass by at most one transition. The FILL of object 9 and the INVALIDATE of object
/// 4 land before the first Publish and the FILL of 10 and the INVALIDATE of 3 after it; the cut may precede all
/// four, so the suffix replays the changes above it. A restart then serves exactly what the tenure acknowledged:
/// objects 3 and 4 miss, and the others serve from the cut or the suffix.
#[test]
fn a_tenure_with_fills_publishes_a_checkpoint_and_a_restart_loads_the_cut_plus_the_suffix() {
    let (volume, named, session) = staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = capture_duties(&stage);
        let storage = stage.storage;
        let cut_before = shard_record(&stage.store).cut;
        let mut filling: Filling<'_> = None;
        let (mut before, mut after) = (None, None);
        let (mut removed_before, mut removed_after) = (None, None);
        let mut session = 0;
        let mut steps = vec![step_of(&Pass::Idle)];
        let ended = std::cell::Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                session = owner.tenure().get();
                let mut budget = WorkBudget::new(1 << 20);
                if duties.open == Open::Opened && before.is_none() {
                    assert!(log_open(storage));
                    before = fill_step(owner, storage, &mut filling, 9);
                }
                if before.is_some() && removed_before.is_none() {
                    assert_eq!(published(&duties), 0);
                    removed_before = Some(owner.invalidate(&object_key(4), 4, &mut budget).is_ok());
                }
                if published(&duties) == 1 && after.is_none() {
                    after = fill_step(owner, storage, &mut filling, 10);
                }
                if after.is_some() && removed_after.is_none() {
                    removed_after = Some(owner.invalidate(&object_key(3), 4, &mut budget).is_ok());
                }
                steps.push(step_of(&duties.capture.as_ref().unwrap().pass));
                let idle = storage.with_suffix(|log| log.idle()).unwrap_or(false);
                ended.set(removed_after.is_some() && idle);
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert_eq!((before, after), (Some(Ok(())), Some(Ok(()))));
        assert_eq!((removed_before, removed_after), (Some(true), Some(true)));
        for turn in steps.windows(2) {
            assert!(one_transition(turn[0], turn[1]), "{turn:?}");
        }
        let capture = duties.capture.as_ref().unwrap();
        assert_eq!((capture.refused, capture.abandoned), (0, 0));
        let record = shard_record(&stage.store);
        assert!(record.cut > cut_before, "the Publish wrote the pass's cut");
        let named = record.checkpoint.expect("the Publish named a checkpoint");
        ((stage.store.clone(), stage.media.clone()), named, session)
    });
    assert_eq!(named.session, session, "the checkpoint is this tenure's");
    let served = served_after_restart(volume, &[1, 2, 3, 4, 9, 10]);
    let expected: Vec<(u8, Fetched, Vec<u8>)> = [1, 2, 3, 4, 9, 10]
        .into_iter()
        .map(|n| match n {
            3 | 4 => (n, Fetched::Missing, Vec::new()),
            _ => (n, Fetched::Complete, replaced(n)),
        })
        .collect();
    assert_eq!(served, expected);
}

/// What [`fill_then_publish`] saw: the FILL's outcome, its slot and the units its entry holds, the publications the
/// volume made with no portable pair, the tenure's Publishes and those after the FILL, and the store, media and
/// reservation table the tenure left.
struct Filled {
    fill: Option<Result<(), FillPublishError>>,
    slot: Option<usize>,
    units: Option<(u64, u32)>,
    absent: u64,
    published: u64,
    published_after: u64,
    volume: (Shared, Media),
    registry: Control,
}

/// Where [`fill_then_publish`] leaves its FILL when the tenure stops.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Lands {
    /// In the cut: the FILL goes out once the open reached `Opened`, and the tenure runs until two passes published
    /// after it. The second pass started after the first's Publish, so its cut follows the FILL.
    Cut,
    /// In the certified suffix over the tenure's own checkpoint: the FILL goes out after the tenure's first
    /// Publish, and the tenure stops once the suffix is idle with no Publish after the FILL.
    Suffix,
    /// As `Suffix`, with an INVALIDATE of the FILL's key after it, so the suffix records the insert and its removal.
    SuffixThenRemoval,
    /// In the certified suffix over the checkpoint the tenure loaded: the FILL goes out once the open reached
    /// `Opened`, and the tenure stops once the suffix is idle, before any Publish.
    SuffixOverLoaded,
    /// Nowhere: the FILL goes out once the open reached `Opened`, its payload reaches the device, and the tenure
    /// stops before the FILL publishes, as a crash between the payload write and the publication stops it. The
    /// suffix records no insert of the FILL, and no Publish follows it.
    Unpublished,
}

/// A capturing `Live` tenure over `stage` under `policy` FILLs object `n` with `payload` where `lands` places it,
/// with the volume's clock provider reading untrusted from that FILL on when `untrusted`.
fn fill_then_publish(
    stage: &mut Stage<'_>,
    (n, payload, untrusted): (u8, &[u8], bool),
    policy: CapturePolicy,
    lands: Lands,
) -> Filled {
    let mut duties = capture_duties_under(stage, policy);
    let storage = stage.storage;
    let script = stage.clock.clone();
    let mut filling: Filling<'_> = None;
    let (mut fill, mut id, mut published_at, mut removed) = (None, None, 0, None);
    let mut written = false;
    let mut absent = 0;
    let ended = Cell::new(false);
    let (served, _) = stage.serve_until(
        |_, _, stop| {
            if ended.get() {
                stop.store(true, Ordering::Release);
            }
        },
        |owner, now| {
            let exit = duties.turn(owner, now);
            let opened = matches!(
                lands,
                Lands::Cut | Lands::SuffixOverLoaded | Lands::Unpublished
            );
            let due = opened || published(&duties) >= 1;
            if duties.open == Open::Opened && due && fill.is_none() && !written {
                if untrusted && filling.is_none() {
                    script.queue(&[Reading {
                        trust: Trust::Untrusted(Untrusted::Unknown),
                        ..TRUSTED
                    }]);
                }
                id = filling.as_ref().map(|(fill, _)| fill.id()).or(id);
                written = lands == Lands::Unpublished
                    && (filling.as_ref())
                        .is_some_and(|(fill, _)| owner.fill_progress(fill).is_ready());
                if !written {
                    fill = fill_bytes(owner, storage, &mut filling, n, payload);
                }
                published_at = published(&duties);
            }
            if lands == Lands::SuffixThenRemoval && fill.is_some() && removed.is_none() {
                let mut budget = WorkBudget::new(1 << 20);
                removed = Some(owner.invalidate(&object_key(n), 4, &mut budget).is_ok());
            }
            absent = owner.volume_report().clock.absent.total();
            let idle = storage.with_suffix(|log| log.idle()).unwrap_or(false);
            let pass_idle = matches!(duties.capture.as_ref().unwrap().pass, Pass::Idle);
            let after = published(&duties) - published_at;
            let done = match lands {
                Lands::Cut => after >= 2 && pass_idle,
                Lands::Suffix | Lands::SuffixOverLoaded => true,
                Lands::SuffixThenRemoval => removed.is_some(),
                Lands::Unpublished => written,
            };
            ended.set((fill.is_some() || written) && done && idle);
            exit
        },
    );
    assert_eq!(served.exit, Exit::Stopped);
    assert_ne!(
        removed,
        Some(false),
        "the INVALIDATE removed the FILL's object"
    );
    let capture = duties.capture.as_ref().unwrap();
    assert_eq!((capture.refused, capture.abandoned), (0, 0));
    let units = (removed.is_none() && (fill == Some(Ok(())) || written))
        .then(|| held_units(storage, id.expect("the FILL reserved")));
    Filled {
        fill,
        slot: id.map(|id| id.slot_index()),
        units,
        absent,
        published: published(&duties),
        published_after: published(&duties) - published_at,
        volume: (stage.store.clone(), stage.media.clone()),
        registry: stage.registry.clone(),
    }
}

/// The warm load's refusal of an entry the installer cannot restore.
const UNRESTORABLE: MetadataOutcome = MetadataOutcome::Unloadable(LoadRefusal::Unrestorable);

/// The reading [`ScriptedClock::trusted`](crate::storage::portable::scripted::ScriptedClock::trusted) gives.
const TRUSTED: Reading = Reading {
    earliest: crate::storage::portable::scripted::TEST_EARLIEST,
    latest: crate::storage::portable::scripted::TEST_EARLIEST + 2_000_000,
    trust: Trust::Trusted,
};

/// The objects a restart over the warm fixture serves after object 9's FILL with `payload`, and the outcome each
/// GET expects: objects 1 to 4 from the predecessor's cut and suffix, and object 9 when `nine` holds.
fn served_after_the_fill(nine: Option<&[u8]>) -> Vec<(u8, Fetched, Vec<u8>)> {
    (1..=4)
        .map(|n| (n, Fetched::Complete, replaced(n)))
        .chain([match nine {
            Some(bytes) => (9, Fetched::Complete, bytes.to_vec()),
            None => (9, Fetched::Missing, Vec::new()),
        }])
        .collect()
}

/// An entry with no portable pair in the tenure's own cut restarts as a miss. A FILL published while the volume's
/// clock provider reads untrusted binds `PortableExpiry::ABSENT` (`Volume::portable_expiry`), the pair of a
/// live-only binding; the capture walk copies it into the next cut. The restart, under a trusted reading, omits it
/// as it omits an expired entry (`warm::convert`), reaches `Live` and serves a miss for object 9 and its hits for
/// objects 1 to 4. Control: the same history under a trusted reading restarts and serves object 9.
#[test]
fn a_fill_with_no_portable_pair_in_the_cut_restarts_as_a_miss() {
    for untrusted in [false, true] {
        let filled = staged_over(warm_volume_certified(0), |mut stage| {
            fill_then_publish(
                &mut stage,
                (9, &content(9, 9), untrusted),
                policy(),
                Lands::Cut,
            )
        });
        assert_eq!(filled.fill, Some(Ok(())), "untrusted {untrusted}");
        assert_eq!(
            filled.absent,
            u64::from(untrusted),
            "the FILL's absent pairs"
        );
        let nine = content(9, 9);
        let served = served_after_restart(filled.volume, &[1, 2, 3, 4, 9]);
        assert_eq!(
            served,
            served_after_the_fill((!untrusted).then_some(&nine[..]))
        );
    }
}

/// An insert with no portable pair in the tenure's certified suffix restarts as a miss: the FILL goes out after the
/// tenure's first Publish and no Publish follows it, so only the suffix holds its insert. The restart replays the
/// suffix, omits the entry, reaches `Live` and serves a miss for object 9 and its hits for objects 1 to 4.
#[test]
fn an_insert_with_no_portable_pair_in_the_suffix_restarts_as_a_miss() {
    let filled = staged_over(warm_volume_certified(0), |mut stage| {
        let lands = Lands::Suffix;
        fill_then_publish(
            &mut stage,
            (9, &content(9, 9), true),
            policy_every(20_000_000),
            lands,
        )
    });
    assert_eq!((filled.fill, filled.absent), (Some(Ok(())), 1));
    assert_eq!(filled.published_after, 0, "no cut holds the FILL");
    let served = served_after_restart(filled.volume, &[1, 2, 3, 4, 9]);
    assert_eq!(served, served_after_the_fill(None));
}

/// A suffix that holds an insert with no portable pair and then the removal of its key replays: the restart reaches
/// `Live` and serves a miss for object 9 and its hits for objects 1 to 4.
#[test]
fn an_insert_with_no_portable_pair_and_its_removal_replay_from_the_suffix() {
    let filled = staged_over(warm_volume_certified(0), |mut stage| {
        let lands = Lands::SuffixThenRemoval;
        fill_then_publish(
            &mut stage,
            (9, &content(9, 9), true),
            policy_every(20_000_000),
            lands,
        )
    });
    assert_eq!((filled.fill, filled.absent), (Some(Ok(())), 1));
    assert_eq!(filled.published_after, 0, "no cut holds the FILL");
    let served = served_after_restart(filled.volume, &[1, 2, 3, 4, 9]);
    assert_eq!(served, served_after_the_fill(None));
}

/// Control (planted: the warm load refuses the absent pair as it refuses every other malformed pair): the cut that
/// holds a FILL published under an untrusted reading is one its own restart refuses `Unrestorable`, and the
/// restart holds short of `Live`.
#[test]
fn a_planted_refusal_of_the_absent_pair_holds_the_restart() {
    let filled = staged_over(warm_volume_certified(0), |mut stage| {
        fill_then_publish(&mut stage, (9, &content(9, 9), true), policy(), Lands::Cut)
    });
    assert_eq!((filled.fill, filled.absent), (Some(Ok(())), 1));
    let (store, media) = &filled.volume;
    REFUSE_ABSENT.with(|refuse| refuse.set(true));
    let (exit, outcome) = restart_short_of_live((store, &filled.registry, media), || storage(1));
    REFUSE_ABSENT.with(|refuse| refuse.set(false));
    assert!(matches!(exit, Exit::Held { .. }), "{exit:?}");
    assert_eq!(outcome, Some(UNRESTORABLE));
}

/// Tenure A FILLs object 9 under an untrusted reading and publishes it in its cut; its restart, tenure B, FILLs
/// object 10 where `lands` places it. Returns the units of A's entry and of B's, and what tenure B left.
fn reused_after_a_restart(lands: Lands) -> ((u64, u32), (u64, u32), Filled) {
    let first = staged_over(warm_volume_certified(0), |mut stage| {
        fill_then_publish(&mut stage, (9, &content(9, 9), true), policy(), Lands::Cut)
    });
    assert_eq!((first.fill, first.absent), (Some(Ok(())), 1));
    let second = staged_over_on(
        first.volume,
        first.registry,
        || storage(1),
        |mut stage| {
            fill_then_publish(
                &mut stage,
                (10, &content(10, 10), false),
                policy_every(20_000_000),
                lands,
            )
        },
    );
    assert_eq!((second.fill, second.absent), (Some(Ok(())), 0));
    match lands {
        Lands::Cut => assert!(second.published_after >= 2, "B's cut holds object 10"),
        _ => assert_eq!(second.published, 0, "the record still names A's checkpoint"),
    }
    (first.units.unwrap(), second.units.unwrap(), second)
}

/// What a restart over tenure B's volume serves of objects 1 to 4, 9 and 10 when B's FILL of object 10 took the
/// units of A's omitted entry of object 9: object 10's bytes, a miss for object 9 and the hits for objects 1 to 4.
fn reuse_served() -> Vec<(u8, Fetched, Vec<u8>)> {
    served_after_the_fill(None)
        .into_iter()
        .chain([(10, Fetched::Complete, content(10, 10))])
        .collect()
}

/// The units an omitted live-only entry leaves free carry a later FILL across a second restart. Tenure A FILLs object
/// 9 under an untrusted reading and publishes it in its cut; A's restart omits the entry and frees its units, and
/// tenure B's FILL of object 10 takes them, in another slot. B's restart then serves object 10's bytes, a miss for
/// object 9 and the hits for objects 1 to 4, both when it loads B's newer checkpoint and when it loads A's
/// checkpoint, which still holds object 9's entry, with B's certified suffix replayed over it.
///
/// Control (planted: every load retains an entry whose pair is absent as a member that never expires): A's restart
/// keeps object 9's entry and its units, so B's FILL takes other units and B's restart serves object 9, and the
/// case fails at each landing.
#[test]
fn units_an_omitted_live_only_entry_freed_carry_a_later_fill_across_a_second_restart() {
    for retain in [false, true] {
        RETAIN_ABSENT.with(|planted| planted.set(retain));
        for lands in [Lands::Cut, Lands::SuffixOverLoaded] {
            let (nine, ten, second) = reused_after_a_restart(lands);
            let keys = [1, 2, 3, 4, 9, 10];
            let served =
                served_after_restart_on(second.volume, second.registry, || storage(1), &keys);
            let reused = ten == nine && served == reuse_served();
            assert_eq!(
                reused, !retain,
                "retained {retain}: object 9 at {nine:?}, 10 at {ten:?}, {served:?}"
            );
        }
    }
    RETAIN_ABSENT.with(|planted| planted.set(false));
}

/// A later level's entry over the same units supersedes a checkpoint entry: with the retention planted only at B's
/// restart, which loads A's checkpoint with object 9's entry and B's suffix whose insert of object 10 holds the same
/// units in another slot, the suffix replay supersedes object 9's entry (ONE-OWNER in
/// `storage::recovery::delta_replay`: an entry sharing a payload unit with an entry of a later level is superseded),
/// and the restart serves what the unplanted load serves.
#[test]
fn a_suffix_insert_over_the_freed_units_supersedes_a_retained_entry_of_the_cut() {
    let (nine, ten, second) = reused_after_a_restart(Lands::SuffixOverLoaded);
    assert_eq!(ten, nine);
    RETAIN_ABSENT.with(|planted| planted.set(true));
    let keys = [1, 2, 3, 4, 9, 10];
    let served = served_after_restart_on(second.volume, second.registry, || storage(1), &keys);
    RETAIN_ABSENT.with(|planted| planted.set(false));
    assert_eq!(served, reuse_served());
}

/// A volume the record names this host's at `E = 4`, with a named checkpoint of objects `1..=4` whose entries hold
/// present pairs, and one certified suffix whose one block holds an INSERT of object 2 bound live-only: a later
/// publication of object 2, in its own slot and units, whose pair is `PortableExpiry::ABSENT`. No record of the
/// suffix removes the checkpoint's entry of object 2, so only the INSERT supersedes it.
fn live_only_over_the_cut() -> (Shared, Media) {
    let capturing = crate::storage::session_at(3, 0);
    let before = capturing.get();
    let replaced = Some((2, content(2, 0xee)));
    let (a, replace) = tenure_replacing(capturing, 4, |n| content(n, n), replaced);
    let insert = live_only_insert(&replace.expect("the replacement's record"));
    let lap = region();
    let recorded = [Suffix {
        session: before,
        start: lap,
        certified: lap + 1,
        end: lap + 1,
    }];
    let records = shard_store_with(a.named, false, 4, (lap, &recorded));
    let at = block_unit(lap) as usize * IO_UNIT;
    let block = suffix_block(before, lap, &[insert]);
    a.media.borrow_mut()[at..at + IO_UNIT].copy_from_slice(&block);
    (records, a.media)
}

/// A live-only later version of a key supersedes the checkpoint's version of it. The checkpoint holds object 2 with a
/// present pair and the certified suffix an INSERT of object 2 whose pair is `PortableExpiry::ABSENT`. The replay
/// supersedes the checkpoint's entry by its key (`delta_replay::keys`, `Patch::fate`), the conversion omits the
/// INSERT's entry as live-only, and the restart serves a miss for object 2, where serving the checkpoint's version
/// would restore an older binding the INSERT replaced, and its hits for objects 1, 3 and 4.
///
/// Control (planted: the replay drops every insert before it applies, `ReplayPlant::DropInserts`): the checkpoint's
/// entry of object 2 stays, the restart serves its bytes, and the case fails.
#[test]
fn a_live_only_insert_in_the_suffix_supersedes_the_cut_s_version_of_its_key() {
    let keys = [1, 2, 3, 4];
    let expected: Vec<_> = keys
        .iter()
        .map(|&n| match n {
            2 => (n, Fetched::Missing, Vec::new()),
            n => (n, Fetched::Complete, content(n, n)),
        })
        .collect();
    for dropped in [false, true] {
        REPLAY_PLANT.with(|plant| plant.set(dropped.then_some(ReplayPlant::DropInserts)));
        let served = served_after_restart(live_only_over_the_cut(), &keys);
        REPLAY_PLANT.with(|plant| plant.set(None));
        assert_eq!(
            served == expected,
            !dropped,
            "dropped {dropped}: {served:?}"
        );
        if dropped {
            assert_eq!(served[1], (2, Fetched::Complete, content(2, 2)));
        }
    }
}

/// What a restart over `volume` on `registry` holds once its session is active, read from the tables before any
/// FILL: whether slot `slot` is resident, whether the allocator holds `units` free, and the resident count.
fn held_after_restart(
    volume: (Shared, Media),
    registry: Control,
    slot: usize,
    units: (u64, u32),
) -> (bool, bool, usize) {
    staged_over_on(
        volume,
        registry,
        || storage(1),
        |mut stage| {
            let storage = stage.storage;
            let mut held = None;
            let served = stage.serve(
                |rounds, _, stop| {
                    if held.is_none() && rounds.client.borrow().state() == SessionState::Active {
                        let resident = storage.slot_state(SlotIndex(slot));
                        let resident =
                            resident.is_some_and(|(state, _)| state == SlotState::Resident);
                        held = Some((resident, units_free(storage, units), residents(storage)));
                        stop.store(true, Ordering::Release);
                    }
                },
                |_: &mut TestOwner<'_>, _| {},
            );
            assert_eq!(served.exit, Exit::Stopped);
            held.expect("the session became active")
        },
    )
}

/// Tenure A FILLs object 9 under an untrusted reading and publishes it in its cut; its restart, tenure B, omits the
/// entry, FILLs object 10 into the units it freed, and stops before that FILL publishes. Returns the slot and units
/// of A's entry and what tenure B left.
fn reused_before_a_crash() -> (usize, (u64, u32), Filled) {
    let first = staged_over(warm_volume_certified(0), |mut stage| {
        fill_then_publish(&mut stage, (9, &content(9, 9), true), policy(), Lands::Cut)
    });
    assert_eq!((first.fill, first.absent), (Some(Ok(())), 1));
    let second = staged_over_on(
        first.volume,
        first.registry,
        || storage(1),
        |mut stage| {
            fill_then_publish(
                &mut stage,
                (10, &content(10, 10), false),
                policy_every(20_000_000),
                Lands::Unpublished,
            )
        },
    );
    let (slot, units) = (first.slot.unwrap(), first.units.unwrap());
    assert_eq!(second.fill, None, "object 10's FILL never published");
    assert_eq!(second.published, 0, "the record still names A's checkpoint");
    assert_eq!(
        second.units,
        Some(units),
        "object 10's payload took object 9's units"
    );
    assert_ne!(
        second.slot,
        Some(slot),
        "object 10's FILL holds another slot"
    );
    (slot, units, second)
}

/// The units an omitted live-only entry freed stay free at a load of the older checkpoint after a crash lost the
/// later FILL that took them. Tenure A FILLs object 9 under an untrusted reading and publishes it in its cut; A's
/// restart, tenure B, omits the entry, and B's FILL of object 10 writes its payload over the units it freed; B
/// crashes before that FILL publishes, so no record of it is recoverable and no later entry supersedes object 9's.
/// B's restart loads A's checkpoint, which still holds object 9's entry: the tables show its slot not resident, its
/// units free and the four objects of the predecessor's cut resident. A GET of object 9 would miss either way, since a
/// retained entry over the rewritten units fails identity at residency, so the case reads the tables.
///
/// Control (planted: that load retains an entry whose pair is absent as a member that never expires): object 9's slot
/// is resident and the warm hold holds its units, which now carry object 10's bytes, and the case fails.
#[test]
fn units_an_omitted_live_only_entry_freed_stay_free_when_a_crash_loses_the_later_fill_s_insert() {
    for retain in [false, true] {
        let (slot, units, second) = reused_before_a_crash();
        RETAIN_ABSENT.with(|planted| planted.set(retain));
        let held = held_after_restart(second.volume, second.registry, slot, units);
        RETAIN_ABSENT.with(|planted| planted.set(false));
        assert_eq!(
            held == (false, true, 4),
            !retain,
            "retained {retain}: object 9's slot {slot} and units {units:?} read {held:?}"
        );
        if retain {
            assert_eq!(held, (true, false, 5));
        }
    }
}

/// A body one byte past one extent's payload, behind object 9's four metadata bytes.
fn past_one_extent() -> Vec<u8> {
    [
        &object_key(9)[..4],
        &vec![9; EXTENT_PAYLOAD as usize + 1][..],
    ]
    .concat()
}

/// Duties built with a capture policy refuse a storage that carries a sequence arena, before the tenure serves:
/// `capturing` returns the duties with no policy and the cause `SequenceArena`, and the tenure's owner was never
/// served.
#[test]
fn capturing_duties_refuse_a_storage_with_a_sequence_arena() {
    staged_fresh_on(fresh_store(), sequence_storage, |stage| {
        let Err(refused) = capturing_over(&stage, policy()) else {
            panic!("the duties admitted a storage with a sequence arena");
        };
        assert_eq!(refused.cause, CaptureRefusal::SequenceArena);
        assert!(
            refused.duties.capture.is_none(),
            "the duties keep no policy"
        );
        assert!(stage.owner.is_some(), "no serve took the owner");
    });
}

/// On a storage with no sequence arena, a FILL whose body passes `EXTENT_PAYLOAD` bytes refuses
/// `Layout(MultipleExtents)` even under a body cap past it, and the capturing tenure publishes its other FILLs and
/// restarts warm: the restart serves object 9.
#[test]
fn a_fill_past_one_extent_refuses_and_the_capturing_tenure_restarts_warm() {
    let filled = staged_fresh_on(fresh_store(), wide_storage, |mut stage| {
        let large = past_one_extent();
        let refused = reserve_at(
            stage.storage,
            &object_key(8),
            CacheVersion(0),
            4,
            large.len() - 4,
        );
        assert!(
            matches!(
                refused,
                Err(FillReserveError::Layout(LayoutError::MultipleExtents {
                    extents: 2
                }))
            ),
            "{:?}",
            refused.err()
        );
        fill_then_publish(&mut stage, (9, &content(9, 9), false), policy(), Lands::Cut)
    });
    assert_eq!(filled.fill, Some(Ok(())));
    let served = served_after_restart_on(filled.volume, filled.registry, wide_storage, &[9, 8]);
    assert_eq!(
        served,
        [
            (9, Fetched::Complete, content(9, 9)),
            (8, Fetched::Missing, Vec::new())
        ]
    );
}

/// Control (planted: `capturing` admits the sequence arena): a FILL whose body passes `EXTENT_PAYLOAD` bytes is
/// admitted as two extents (`FillAttempt::reserve_storage` through `reserve_sequence`, as a wire PUT's
/// `promise_storage`), publishes as a sequence member, and the capture walk copies both extents into the cut
/// (`capture_entry_into`). The tenure's restart refuses the warm load `Unrestorable`, since the warm installer
/// restores entries of one extent only (`warm::convert`), and holds short of `Live`. A FILL of one extent on the
/// same storage restarts and serves, so the refusal is the two extents'.
#[test]
fn a_planted_arena_publishes_a_cut_of_two_extents_its_own_restart_refuses() {
    let large = past_one_extent();
    let Decision::Admit(admitted) =
        sequence_storage().decide_admission(Some(4), Some(large.len() - 4))
    else {
        panic!("the storage admits a body one byte past one extent's payload");
    };
    assert_eq!(admitted.extents(), 2);
    ADMIT_ARENA.with(|admit| admit.set(true));
    for payload in [content(9, 9), large] {
        let two = payload.len() - 4 > EXTENT_PAYLOAD as usize;
        let filled = staged_fresh_on(fresh_store(), sequence_storage, |mut stage| {
            fill_then_publish(&mut stage, (9, &payload, false), policy(), Lands::Cut)
        });
        assert_eq!(filled.fill, Some(Ok(())), "two extents {two}");
        if !two {
            let served =
                served_after_restart_on(filled.volume, filled.registry, sequence_storage, &[9]);
            assert_eq!(served, [(9, Fetched::Complete, payload)]);
            continue;
        }
        let (store, media) = &filled.volume;
        let (exit, outcome) =
            restart_short_of_live((store, &filled.registry, media), sequence_storage);
        assert!(matches!(exit, Exit::Held { .. }), "{exit:?}");
        assert_eq!(outcome, Some(UNRESTORABLE));
    }
    ADMIT_ARENA.with(|admit| admit.set(false));
}

/// STORE-OFF-POLL: over a threaded lane and threaded recovery helpers, the pass's encode runs on a recovery helper
/// and every store request, the Publish's included, on the lane thread.
#[test]
fn the_encode_runs_on_a_helper_and_the_publish_on_the_lane_thread() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let store = Locked::of(&stage.store);
        let storage = stage.storage;
        let (encoded_on, threads) = std::thread::scope(|scope| {
            let lane = Lane::start(
                &HostGate::qualified(),
                scope,
                locked_client(&store),
                storage,
                crate::storage::CpuSet::current().unwrap(),
            )
            .unwrap();
            let mut duties = Duties::new(
                (
                    &HostGate::qualified(),
                    crate::failover::reconcile::StandbyGate::qualified(),
                ),
                lane,
                records(),
                None,
                bounds(),
                periods(),
            )
            .capturing(policy(), EngineBudget::unlimited())
            .unwrap();
            let done = Cell::new(false);
            let (served, _) = stage.serve_until(
                |_, _, stop| {
                    if done.get() {
                        stop.store(true, Ordering::Release);
                    }
                },
                |owner, now| {
                    let exit = duties.turn(owner, now);
                    let capture = duties.capture.as_ref().unwrap();
                    done.set(capture.published == 1 && matches!(capture.pass, Pass::Idle));
                    exit
                },
            );
            assert_eq!(served.exit, Exit::Stopped);
            let encoded_on = duties.capture.as_ref().unwrap().encoded_on.clone();
            drop(duties.end());
            (encoded_on, store.threads())
        });
        let helper = encoded_on.expect("an encode ran");
        assert!(helper.starts_with("recovery-"), "{helper}");
        assert!(!threads.is_empty());
        assert!(
            threads
                .iter()
                .all(|name| name.as_deref() == Some("store-lane")),
            "{threads:?}"
        );
    });
}

/// A store whose next shard-record write after `armed` is raised takes `arm`, whose shard-record reads fail while
/// `blind` is raised, and whose volume-record reads return `relaid`'s layout while it holds one, as a store that
/// breaks the volume record's successor rule would.
#[derive(Clone)]
pub(super) struct Unanswered {
    pub(super) inner: Shared,
    pub(super) armed: Rc<Cell<bool>>,
    pub(super) arm: Arm,
    blind: Rc<Cell<bool>>,
    relaid: Rc<Cell<Option<crate::failover::records::Layout>>>,
}

impl Unanswered {
    pub(super) fn over(inner: &Shared, arm: Arm) -> Self {
        Self {
            inner: inner.clone(),
            armed: Rc::default(),
            arm,
            blind: Rc::default(),
            relaid: Rc::default(),
        }
    }
}

impl Store for Unanswered {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        if matches!(key, Key::Shard(_)) && self.blind.get() {
            return Err(Unavailable);
        }
        let read = self.inner.read(key)?;
        match (key, read, self.relaid.get()) {
            (Key::Volume(_), Some(item), Some(layout)) => {
                use crate::failover::records::Record;
                let mut volume = VolumeRecord::decode(&item.value).unwrap();
                volume.layout = layout;
                Ok(Some(Item {
                    value: volume.encode(),
                    ..item
                }))
            }
            (_, read, _) => Ok(read),
        }
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        if matches!(key, Key::Shard(_)) && self.armed.replace(false) {
            self.inner.0.borrow_mut().schedule(self.arm);
        }
        self.inner.write(key, write)
    }

    fn namespace(&self) -> crate::failover::records::Namespace {
        self.inner.namespace()
    }
}

pub(super) fn pass_slot(duties: &Duties<'_, impl Store, MemLog, TestPlatform>) -> Option<u32> {
    match &duties.capture.as_ref()?.pass {
        Pass::Writing { staged, .. } | Pass::Proving { staged, .. } => Some(staged.slot()),
        _ => None,
    }
}

/// QuarantineUntilBarrier: a Publish whose reply never arrives leaves its slot possibly named until the settling
/// Confirm over the next view's read commits, which quarantines the unanswered slot; the next pass reserves another
/// slot and publishes. The parked write then cannot commit over the moved version.
#[test]
fn an_unanswered_publish_keeps_its_slot_possibly_named_until_the_next_settling_write() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let store = Unanswered::over(&stage.store, Arm::Hold);
        let armed = Rc::clone(&store.armed);
        let client = Client::open(store, MemLog::default()).unwrap();
        let mut duties = Duties::new(
            (
                &HostGate::qualified(),
                crate::failover::reconcile::StandbyGate::qualified(),
            ),
            Lane::inline(client, stage.storage),
            records(),
            None,
            bounds(),
            periods(),
        )
        .capturing(policy(), EngineBudget::unlimited())
        .unwrap();
        let mut slots = Vec::new();
        let mut unanswered = None;
        let mut unanswered_refusal = None;
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                let capture = duties.capture.as_ref().unwrap();
                if let Some(slot) = pass_slot(&duties)
                    && slots.last() != Some(&slot)
                {
                    slots.push(slot);
                    armed.set(slots.len() == 1);
                }
                if capture.abandoned == 1 && unanswered.is_none() {
                    unanswered_refusal = capture.refusal;
                    let possible = duties.here();
                    unanswered = Some((possible.slots(), duties.quarantine()));
                }
                ended.set(capture.published == 1 && matches!(capture.pass, Pass::Idle));
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        let refusal = duties.capture.as_ref().unwrap().refusal;
        assert!(
            refusal.is_none(),
            "the second Publish succeeded: {refusal:?}"
        );
        assert_eq!(
            unanswered_refusal,
            Some(WriteRefused::Store(
                crate::storage::store::StoreError::Unknown
            ))
        );
        let (first, second) = (slots[0], slots[1]);
        assert_ne!(first, second, "the next stage reserves another slot");
        let (held, gauge) = unanswered.expect("the first Publish's reply never arrived");
        assert!(
            held.contains(&first),
            "the unanswered slot stays possibly named"
        );
        assert_eq!(gauge, Gauge::known(1, 3));
        let possible = duties.here();
        assert_eq!(possible.slots(), [second]);
        assert!(possible.quarantined().contains(&first));
        let released = stage.store.0.borrow_mut().release();
        assert_eq!(
            released,
            [Outcome::NotCommitted(Refusal::Condition)],
            "the one parked write, the first Publish, cannot commit over the moved version"
        );
        let named = shard_record(&stage.store).checkpoint.unwrap();
        assert_eq!(named.slot, second);
    });
}

/// VerifiedBeforePublish control, planted: the Publish carries the owner thread's epoch minus one, as an epoch read
/// before a load commit would. It is refused `Replaced` before any request, and the stage's slot is quarantined.
#[test]
fn a_publish_under_a_stale_epoch_is_refused_replaced() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = capture_duties(&stage);
        let before = shard_record(&stage.store);
        let store = stage.store.clone();
        let mut commits = None;
        let mut slot = None;
        let ended = Cell::new(false);
        STALE_EPOCH.with(|stale| stale.set(true));
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                slot = slot.or(pass_slot(&duties));
                let capture = duties.capture.as_ref().unwrap();
                if matches!(capture.pass, Pass::Proving { .. }) {
                    commits = Some(store.0.borrow().commit_count(&Key::Shard(shard())));
                }
                ended.set(capture.abandoned == 1 && matches!(capture.pass, Pass::Idle));
                exit
            },
        );
        STALE_EPOCH.with(|stale| stale.set(false));
        assert_eq!(served.exit, Exit::Stopped);
        let capture = duties.capture.as_ref().unwrap();
        assert_eq!(capture.refusal, Some(WriteRefused::Replaced));
        let after = stage.store.0.borrow().commit_count(&Key::Shard(shard()));
        assert_eq!(
            commits,
            Some(after),
            "the refused Publish made no shard-record write"
        );
        assert_eq!(capture.published, 0);
        assert_eq!(shard_record(&stage.store).checkpoint, before.checkpoint);
        assert!(duties.here().quarantined().contains(&slot.unwrap()));
        let (unresolved, slots) = duties.here().unresolved();
        assert_eq!(
            duties.quarantine(),
            Gauge::known(unresolved, slots),
            "the stage's end refreshed the gauge"
        );
        assert_eq!(unresolved, 1);
    });
}

/// Control for PossNamedCoversStore, planted: a unit write of a stage over another set, staged while the Publish
/// holds the tenure's set on the lane, fails the single-holder check.
#[test]
fn a_unit_write_while_the_publish_holds_the_set_fails_the_single_holder_check() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = capture_duties(&stage);
        duties.lane.inline_mut().hold();
        let mut failure = None;
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                let exit = duties.turn(owner, now);
                let publishing = matches!(
                    duties.capture.as_ref().unwrap().pass,
                    Pass::Publishing { .. }
                );
                if !publishing {
                    duties.lane.inline_mut().release();
                    return exit;
                }
                let mut other = PossiblyNamed::new((shard(), 1), layout(), None);
                let staged = StagedCheckpoint::reserved_at(
                    &mut other,
                    Checkpoint {
                        shard: shard(),
                        session: 1,
                        capture: 1,
                    },
                    1,
                    vec![Box::new([0; UNIT_LEN])],
                );
                let planted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    duties.unit(owner, (1, staged), (Unit::Write(0), 0), now + VIEW_US);
                }));
                failure = planted
                    .err()
                    .and_then(|panic| panic.downcast::<&str>().ok());
                Some(Exit::Stopped)
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        let failure = failure.expect("the planted unit write fails");
        assert!(failure.starts_with("PossNamedCoversStore"), "{failure}");
    });
}

/// STORE-OFF-POLL: while the helpers hold the encode's terminal for longer than eight view periods, the view keeps
/// running on the lane and every GET completes; the pass resumes once the terminal lands.
#[test]
fn a_held_encode_terminal_leaves_views_running_and_gets_served() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = capture_duties(&stage);
        let views = Cell::new(0);
        let gets = Cell::new(0);
        let gets_held = Cell::new(None::<u64>);
        let held = Cell::new(None::<u64>);
        let done = Cell::new(false);
        let mut pending: Option<(RequestId, Vec<u8>)> = None;
        PARK_RECOVERY.with(|park| park.set(true));
        let (served, _) = stage.serve_until(
            |rounds, _, stop| {
                let active = rounds.client.borrow().state() == SessionState::Active;
                if held.get().is_some() && active && pending.is_none() {
                    pending = Some((rounds.get(1 + (gets.get() % 4) as u8), Vec::new()));
                }
                if let Some((id, bytes)) = pending.as_mut()
                    && let Some(outcome) = rounds.fetched(*id, bytes)
                {
                    assert_eq!(outcome, Fetched::Complete);
                    gets.set(gets.get() + 1);
                    pending = None;
                }
                if done.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let viewed = duties.view_at;
                let exit = duties.turn(owner, now);
                let encoding =
                    matches!(duties.capture.as_ref().unwrap().pass, Pass::Encoding { .. });
                match held.get() {
                    None if encoding => held.set(Some(now)),
                    Some(from) if encoding => {
                        views.set(views.get() + u64::from(duties.view_at != viewed));
                        if now >= from + 8 * VIEW_US {
                            gets_held.set(gets_held.get().or(Some(gets.get())));
                            owner.release_parked();
                        }
                    }
                    _ => {}
                }
                done.set(published(&duties) == 1);
                exit
            },
        );
        PARK_RECOVERY.with(|park| park.set(false));
        assert_eq!(served.exit, Exit::Stopped);
        assert!(
            views.get() >= 7,
            "views ran while the encode was held: {}",
            views.get()
        );
        let gets_held = gets_held.get().expect("the hold ended by its release");
        assert!(
            gets_held >= 4,
            "GETs completed while the encode was held: {gets_held}"
        );
    });
}

/// Stage and quarantine state at the end of the abandoned first pass. `commanded` records whether the stage issued
/// a unit command after the removal.
struct Released {
    slot: u32,
    commanded: bool,
    quarantined: Vec<u32>,
    gauge: Gauge,
}

/// Removing a snapshot member while the suffix is closed ends the fresh tenure's first pass. If `after_write` is
/// true, removal follows the first staged unit write; otherwise, removal occurs on the walk's first turn.
fn removal_with_the_suffix_closed(after_write: bool) -> Released {
    staged_fresh(fresh_store(), |mut stage| {
        let mut duties = capture_duties_under(&stage, policy_every(5_000_000));
        let storage = stage.storage;
        let mut filling: Filling<'_> = None;
        let (mut filled, mut removed, mut abandoned) = (None, None, None);
        let mut slot = None;
        let mut commanded = false;
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                if duties.open == Open::Opened && filled.is_none() {
                    assert!(
                        !log_open(storage),
                        "a record naming no checkpoint leaves the log closed"
                    );
                    filled = fill_step(owner, storage, &mut filling, 9);
                }
                let capture = duties.capture.as_ref().unwrap();
                let unit = match &capture.pass {
                    Pass::Writing { unit, .. } => Some(*unit),
                    _ => None,
                };
                commanded |= removed.is_some()
                    && capture.abandoned == 0
                    && unit.is_some_and(|unit| unit != Unit::Write(0));
                let at = match after_write {
                    true => unit == Some(Unit::Written(0)),
                    false => {
                        matches!(&capture.pass, Pass::Walking { cut, .. } if cut.is_empty())
                    }
                };
                if at && filled == Some(Ok(())) && removed.is_none() {
                    assert_eq!(capture.published, 0, "the removal falls in the first pass");
                    let mut budget = WorkBudget::new(1 << 20);
                    removed = Some(owner.invalidate(&object_key(9), 4, &mut budget).is_ok());
                }
                if removed.is_some() && slot.is_none() {
                    slot = pass_slot(&duties);
                }
                if capture.abandoned == 1 && abandoned.is_none() {
                    assert_eq!(
                        capture.refusal, None,
                        "the proof refused, before any Publish"
                    );
                    abandoned = Some((duties.here().quarantined().to_vec(), duties.quarantine()));
                }
                ended.set(
                    duties.open == Open::Opened && published(&duties) == 1 && log_open(storage),
                );
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert_eq!((filled, removed), (Some(Ok(())), Some(true)));
        let (quarantined, gauge) = abandoned.expect("the first pass was abandoned");
        let named = shard_record(&stage.store).checkpoint.unwrap();
        assert!(!quarantined.contains(&named.slot));
        Released {
            slot: slot.expect("the first pass staged"),
            commanded,
            quarantined,
            gauge,
        }
    })
}

/// With the suffix closed, removing a snapshot member during the walk releases the pass. The capture refuses a
/// released pass's unit submit, so the pass ends with its stage unexposed: the stage's slot is free again and the
/// quarantine stays empty.
#[test]
fn a_removal_during_the_walk_with_the_suffix_closed_ends_the_pass_before_a_unit_write() {
    let released = removal_with_the_suffix_closed(false);
    assert!(!released.commanded, "no unit command followed the removal");
    assert_eq!(released.quarantined, [0u32; 0], "no slot was spent");
    assert_eq!(
        released.gauge,
        Gauge::known(0, 3),
        "the abandon refreshed the gauge"
    );
}

/// QuarantineUntilBarrier: with the suffix closed, removing a snapshot member once the stage's first unit write is
/// staged ends the pass with that slot exposed, so the abandoned stage's slot is quarantined.
#[test]
fn a_removal_after_a_unit_write_with_the_suffix_closed_quarantines_the_slot() {
    let released = removal_with_the_suffix_closed(true);
    assert_eq!(
        released.quarantined,
        [released.slot],
        "the abandoned stage's slot is quarantined"
    );
    assert_eq!(
        released.gauge,
        Gauge::known(1, 3),
        "the abandon refreshed the gauge"
    );
}

/// A first Publish in a fresh tenure whose write commits but whose reply is lost: the open runs again from the next
/// view, its Confirm settles the set and the suffix opens over the published checkpoint, so a later FILL publishes.
#[test]
fn a_first_publish_that_commits_with_a_lost_reply_still_opens_the_suffix() {
    staged_fresh(fresh_store(), |mut stage| {
        let unanswered = Unanswered::over(&stage.store, Arm::Timeout { commit: true });
        let armed = Rc::clone(&unanswered.armed);
        let client = Client::open(unanswered, MemLog::default()).unwrap();
        let mut duties = Duties::new(
            (
                &HostGate::qualified(),
                crate::failover::reconcile::StandbyGate::qualified(),
            ),
            Lane::inline(client, stage.storage),
            records(),
            None,
            bounds(),
            periods(),
        )
        .capturing(policy(), EngineBudget::unlimited())
        .unwrap();
        let (storage, store) = (stage.storage, stage.store.clone());
        let mut filling: Filling<'_> = None;
        let (mut proved, mut refusal, mut filled) = (None, None, None);
        let mut opened_after = None;
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                let capture = duties.capture.as_ref().unwrap();
                if let Pass::Proving { staged, .. } = &capture.pass
                    && proved.is_none()
                {
                    proved = Some(staged.named());
                    armed.set(true);
                }
                refusal = refusal.or(capture.refusal);
                if refusal.is_some() && log_open(storage) && opened_after.is_none() {
                    opened_after = Some((capture.published, shard_record(&store).checkpoint));
                }
                if refusal.is_some() && log_open(storage) && filled.is_none() {
                    filled = fill_step(owner, storage, &mut filling, 9);
                }
                ended.set(filled.is_some());
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert!(
            matches!(
                refusal,
                Some(WriteRefused::Store(
                    crate::storage::store::StoreError::Unknown
                ))
            ),
            "{refusal:?}"
        );
        assert_eq!(
            opened_after,
            Some((0, proved)),
            "the suffix opened over the lost reply's checkpoint before any acknowledged Publish"
        );
        assert_eq!(
            filled,
            Some(Ok(())),
            "a FILL publishes once the suffix opened"
        );
    });
}

/// A volume record whose layout maps another metadata prefix than the attached volume's stops the open before the
/// set is built: no pass starts, no unit is written and the record names no checkpoint.
#[test]
fn a_recorded_layout_over_another_prefix_stops_the_open() {
    let store = fresh_tests::store(fresh_tests::shard_record(0), fresh_tests::volume_record());
    staged_fresh(store, |mut stage| {
        assert_ne!(fresh_tests::volume_record().layout.units, layout().units);
        let mut duties = capture_duties(&stage);
        let storage = stage.storage;
        let stopped = Cell::new(None::<u64>);
        let ended = Cell::new(false);
        let mut idle = true;
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                idle &= matches!(duties.capture.as_ref().unwrap().pass, Pass::Idle);
                if duties.open == Open::Stopped && stopped.get().is_none() {
                    stopped.set(Some(now));
                }
                ended.set(stopped.get().is_some_and(|at| now >= at + 2 * VIEW_US));
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert!(idle, "no pass started");
        assert!(matches!(duties.possible, super::Set::Unbuilt));
        assert!(!log_open(storage));
        assert_eq!(shard_record(&stage.store).checkpoint, None);
    });
}

/// After a Publish whose outcome is unknown, the next view's read of the tenure names a checkpoint the tenure did not
/// write: a later pointer at a slot outside the set. The open stops on that view, so no later pass starts, no unit
/// is written to the planted slot and the record is not written again.
#[test]
fn a_view_naming_a_checkpoint_the_tenure_did_not_write_stops_the_open() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let unanswered = Unanswered::over(&stage.store, Arm::Timeout { commit: false });
        let armed = Rc::clone(&unanswered.armed);
        let client = Client::open(unanswered, MemLog::default()).unwrap();
        let mut duties = Duties::new(
            (
                &HostGate::qualified(),
                crate::failover::reconcile::StandbyGate::qualified(),
            ),
            Lane::inline(client, stage.storage),
            records(),
            None,
            bounds(),
            periods(),
        )
        .capturing(policy(), EngineBudget::unlimited())
        .unwrap();
        let inherited = shard_record(&stage.store).checkpoint.unwrap().slot;
        let store = stage.store.clone();
        let (mut first, mut planted, mut stopped) = (None, None, None);
        let mut started_after = false;
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                let capture = duties.capture.as_ref().unwrap();
                if first.is_none()
                    && let Pass::Proving { staged, .. } = &capture.pass
                {
                    first = Some(staged.slot());
                    armed.set(true);
                }
                started_after |= planted.is_some() && !matches!(capture.pass, Pass::Idle);
                if planted.is_none()
                    && let Some(refusal) = capture.refusal
                {
                    assert_eq!(
                        refusal,
                        WriteRefused::Store(crate::storage::store::StoreError::Unknown)
                    );
                    let foreign = (0..3)
                        .find(|&slot| slot != inherited && Some(slot) != first)
                        .unwrap();
                    let session = owner.tenure().get();
                    replaced_record(&store, |record| {
                        record.checkpoint = Some(NamedCheckpoint {
                            slot: foreign,
                            session,
                            capture: u32::MAX,
                            units: 1,
                        });
                    });
                    let commits = store.0.borrow().commit_count(&Key::Shard(shard()));
                    planted = Some((foreign, commits));
                }
                if duties.open == Open::Stopped && stopped.is_none() {
                    stopped = Some(now);
                }
                ended.set(stopped.is_some_and(|at| now >= at + 4 * VIEW_US));
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        let (foreign, commits) = planted.expect("the first Publish's outcome was unknown");
        assert!(
            stopped.is_some(),
            "the view naming the planted pointer stopped the open"
        );
        assert!(!started_after, "no pass started after the plant");
        assert!(!duties.here().contains(foreign));
        assert_eq!(
            stage.store.0.borrow().commit_count(&Key::Shard(shard())),
            commits,
            "the tenure wrote no shard record after the plant"
        );
        assert_eq!(shard_record(&stage.store).checkpoint.unwrap().slot, foreign);
    });
}

/// In a fresh tenure whose first Publish committed with a lost reply, a view naming another pointer at the submitted
/// slot than the one the Publish submitted stops the open: no Confirm commits and the suffix stays closed.
#[test]
fn a_view_altering_an_unsettled_first_publish_stops_the_open() {
    staged_fresh(fresh_store(), |mut stage| {
        let unanswered = Unanswered::over(&stage.store, Arm::Timeout { commit: true });
        let armed = Rc::clone(&unanswered.armed);
        let client = Client::open(unanswered, MemLog::default()).unwrap();
        let mut duties = Duties::new(
            (
                &HostGate::qualified(),
                crate::failover::reconcile::StandbyGate::qualified(),
            ),
            Lane::inline(client, stage.storage),
            records(),
            None,
            bounds(),
            periods(),
        )
        .capturing(policy(), EngineBudget::unlimited())
        .unwrap();
        let (storage, store) = (stage.storage, stage.store.clone());
        let (mut submitted, mut planted, mut stopped) = (None, None, None);
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                let capture = duties.capture.as_ref().unwrap();
                if submitted.is_none()
                    && let Pass::Proving { staged, .. } = &capture.pass
                {
                    submitted = Some(staged.named());
                    armed.set(true);
                }
                if planted.is_none() && capture.refusal.is_some() {
                    let named = submitted.unwrap();
                    assert_eq!(shard_record(&store).checkpoint, Some(named));
                    replaced_record(&store, |record| {
                        record.checkpoint = Some(NamedCheckpoint {
                            capture: named.capture + 1,
                            ..named
                        });
                    });
                    planted = Some(store.0.borrow().commit_count(&Key::Shard(shard())));
                }
                if duties.open == Open::Stopped && stopped.is_none() {
                    stopped = Some(now);
                }
                ended.set(stopped.is_some_and(|at| now >= at + 2 * VIEW_US));
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        let commits = planted.expect("the first Publish's reply was lost");
        assert!(stopped.is_some());
        assert_eq!(
            store.0.borrow().commit_count(&Key::Shard(shard())),
            commits,
            "no Confirm committed over the altered pointer"
        );
        assert!(!log_open(storage), "the suffix stayed closed");
    });
}

/// Another writer's change of the shard record after the open, here a spare designation, reaches the duties through
/// a view; the pass's Publish conditions on that newer read and commits, keeping the designation. The helpers hold
/// the encode's terminal until a view after the designation landed.
#[test]
fn a_publish_conditions_on_a_newer_view_of_the_tenure() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = capture_duties(&stage);
        let store = stage.store.clone();
        let spare = (
            crate::failover::records::VolumeId::new("vol-5ba7e").unwrap(),
            Host::new(SPARE).unwrap(),
        );
        let mut designated = None;
        let ended = Cell::new(false);
        PARK_RECOVERY.with(|park| park.set(true));
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                let capture = duties.capture.as_ref().unwrap();
                if designated.is_none() && matches!(capture.pass, Pass::Walking { .. }) {
                    replaced_record(&store, |record| record.spare = Some(spare));
                    designated = Some(duties.view_at);
                }
                let viewed = designated.is_some_and(|at| duties.view_at > at + VIEW_US);
                if viewed && matches!(capture.pass, Pass::Encoding { .. }) {
                    owner.release_parked();
                }
                ended.set(capture.published == 1 && matches!(capture.pass, Pass::Idle));
                exit
            },
        );
        PARK_RECOVERY.with(|park| park.set(false));
        assert_eq!(served.exit, Exit::Stopped);
        let capture = duties.capture.as_ref().unwrap();
        assert_eq!((capture.refused, capture.abandoned), (0, 0));
        assert!(duties.here().quarantined().is_empty(), "no slot was spent");
        assert_eq!(shard_record(&stage.store).spare, Some(spare));
    });
}

/// A pass whose views fail to read the shard record waits in `Proving` with its stage and sends no Publish; once a
/// view reads the tenure again, the same pass publishes. The helpers hold the encode's terminal until a failed view
/// has landed, so the pass reaches `Proving` while the views fail.
#[test]
fn a_proved_pass_waits_while_views_fail_and_publishes_after() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let unanswered = Unanswered::over(&stage.store, Arm::Hold);
        let blind = Rc::clone(&unanswered.blind);
        let client = Client::open(unanswered, MemLog::default()).unwrap();
        let mut duties = Duties::new(
            (
                &HostGate::qualified(),
                crate::failover::reconcile::StandbyGate::qualified(),
            ),
            Lane::inline(client, stage.storage),
            records(),
            None,
            bounds(),
            periods(),
        )
        .capturing(policy(), EngineBudget::unlimited())
        .unwrap();
        let store = stage.store.clone();
        let mut waited = None::<(u64, usize)>;
        let mut published_blind = false;
        let ended = Cell::new(false);
        PARK_RECOVERY.with(|park| park.set(true));
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                let capture = duties.capture.as_ref().unwrap();
                let encoding = matches!(capture.pass, Pass::Encoding { .. });
                if waited.is_none() && encoding {
                    blind.set(true);
                    if !duties.viewed_tenure {
                        owner.release_parked();
                    }
                }
                let proving = matches!(capture.pass, Pass::Proving { .. });
                if waited.is_none() && proving {
                    assert!(!duties.viewed_tenure);
                    let commits = store.0.borrow().commit_count(&Key::Shard(shard()));
                    waited = Some((now, commits));
                }
                published_blind |= blind.get() && matches!(capture.pass, Pass::Publishing { .. });
                if let Some((since, commits)) = waited
                    && blind.get()
                    && now >= since + VIEW_US / 2
                {
                    assert!(proving, "the pass kept its stage");
                    assert_eq!(store.0.borrow().commit_count(&Key::Shard(shard())), commits);
                    blind.set(false);
                }
                ended.set(capture.published == 1 && matches!(capture.pass, Pass::Idle));
                exit
            },
        );
        PARK_RECOVERY.with(|park| park.set(false));
        assert_eq!(served.exit, Exit::Stopped);
        assert!(
            waited.is_some(),
            "the pass reached Proving while views failed"
        );
        assert!(!published_blind, "no Publish was sent while views failed");
        assert_eq!(duties.capture.as_ref().unwrap().abandoned, 0);
    });
}

/// A proved pass waits while the lane holds a page job: an INVALIDATE held on the turn the pass would publish sends
/// its page job first, and the Publish goes out on a later turn, so a page job stays the lane's one outstanding job.
#[test]
fn a_proved_pass_waits_for_the_adoption_of_a_page_job() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = capture_duties(&stage);
        let mut invalidated = None;
        let mut paged_while_proving = false;
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let proving = matches!(duties.capture.as_ref().unwrap().pass, Pass::Proving { .. });
                if invalidated.is_none() && proving && duties.lane.outstanding() == 0 {
                    let mut budget = WorkBudget::new(1 << 20);
                    let interval = Interval::new(CacheVersion(3), CacheVersion(5)).unwrap();
                    let held = owner.invalidate_interval(&object_key(4), interval, 2, &mut budget);
                    invalidated = Some(held.is_ok());
                }
                let exit = duties.turn(owner, now);
                assert!(
                    !duties.paging || duties.lane.outstanding() == 1,
                    "a page job beside another unadopted job"
                );
                paged_while_proving |=
                    duties.paging && invalidated.is_some() && published(&duties) == 0;
                let capture = duties.capture.as_ref().unwrap();
                ended.set(capture.published == 1 && matches!(capture.pass, Pass::Idle));
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert_eq!(invalidated, Some(true));
        assert!(
            paged_while_proving,
            "the page job went out before the Publish"
        );
        assert_eq!(duties.capture.as_ref().unwrap().abandoned, 0);
    });
}

#[test]
fn a_budget_below_the_copys_first_reservation_is_refused_before_the_tenure_serves() {
    use crate::storage::checkpoint::Cut;
    staged_over(warm_volume_certified(0), |stage| {
        let first = Cut::new().turn_reserve();
        let under = |budget: usize| {
            let client = Client::open(stage.store.clone(), MemLog::default()).unwrap();
            Duties::new(
                (
                    &HostGate::qualified(),
                    crate::failover::reconcile::StandbyGate::qualified(),
                ),
                Lane::inline(client, stage.storage),
                records(),
                None,
                bounds(),
                periods(),
            )
            .capturing(policy(), EngineBudget::new(budget))
        };
        let Err(refused) = under(first - 1) else {
            panic!("the duties admitted a budget one byte short of the first reservation");
        };
        assert_eq!(refused.cause, CaptureRefusal::Budget);
        assert!(
            refused.duties.capture.is_none(),
            "the duties keep no policy"
        );
        let admitted = under(first).expect("the budget holds the copy's first reservation");
        assert_eq!(admitted.capture.as_ref().unwrap().budget.limit(), first);
        assert!(stage.owner.is_some(), "no serve took the owner");
    });
}

/// A proved pass waits while the lane holds a listing: a listing submitted on the turn the pass would publish stays
/// the lane's one outstanding job until its completion is adopted, and the Publish goes out on a later turn to an
/// idle lane. So a view that falls due waits behind one lane job, the listing or the Publish, which is the delay
/// POLL-WITHIN-WINDOW admits periods against.
#[test]
fn a_proved_pass_waits_for_the_adoption_of_a_listing() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let client = Client::open(stage.store.clone(), MemLog::default()).unwrap();
        let plane = Plane(Box::new(Listing::new(&Events::default())));
        let mut duties = Duties::new(
            (
                &HostGate::qualified(),
                crate::failover::reconcile::StandbyGate::qualified(),
            ),
            Lane::inline(client, stage.storage),
            records(),
            Some(plane),
            bounds(),
            periods(),
        )
        .capturing(policy(), EngineBudget::unlimited())
        .unwrap();
        let store = stage.store.clone();
        let mut listing = None::<(u64, usize)>;
        let mut waited = false;
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let proving = matches!(duties.capture.as_ref().unwrap().pass, Pass::Proving { .. });
                let idle = duties.plane.is_some() && duties.lane.outstanding() == 0;
                if listing.is_none() && proving && idle {
                    duties.listing_at = now;
                    duties.lane.inline_mut().hold();
                    let commits = store.0.borrow().commit_count(&Key::Shard(shard()));
                    listing = Some((now, commits));
                }
                let exit = duties.turn(owner, now);
                let capture = duties.capture.as_ref().unwrap();
                assert!(
                    !matches!(capture.pass, Pass::Publishing { .. })
                        || duties.lane.outstanding() == 1,
                    "a Publish beside another unadopted job"
                );
                if let Some((at, commits)) = listing {
                    if now < at + VIEW_US / 2 {
                        assert!(duties.plane.is_none(), "the listing is unadopted");
                        assert!(
                            matches!(capture.pass, Pass::Proving { .. }),
                            "the pass kept its stage"
                        );
                        assert_eq!(store.0.borrow().commit_count(&Key::Shard(shard())), commits);
                        waited = true;
                    } else {
                        while duties.lane.inline_mut().release() {}
                    }
                }
                ended.set(capture.published == 1 && matches!(capture.pass, Pass::Idle));
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert!(waited, "the listing and the proved pass shared a turn");
        assert_eq!(published(&duties), 1);
        assert_eq!(duties.capture.as_ref().unwrap().abandoned, 0);
    });
}

/// A second `capturing` keeps the first policy, budget, pass and counts.
#[test]
fn a_second_capturing_call_keeps_the_first() {
    staged_over(warm_volume_certified(0), |stage| {
        let mut duties = capture_duties(&stage);
        let capture = duties.capture.as_mut().unwrap();
        (capture.refused, capture.abandoned, capture.start_at) = (2, 3, 7);
        let duties = duties
            .capturing(policy_every(1), EngineBudget::new(0))
            .unwrap();
        let capture = duties.capture.as_ref().unwrap();
        assert_eq!(
            (capture.refused, capture.abandoned, capture.start_at),
            (2, 3, 7)
        );
        assert_eq!(capture.budget.limit(), EngineBudget::unlimited().limit());
    });
}

/// Runs one pass of a warm tenure under `budget` and returns the cut's input bytes and the stage's unit count, or
/// the refused and abandoned counts once the pass ended unstaged.
fn pass_under(budget: EngineBudget) -> Result<(usize, usize), (u64, u64)> {
    staged_over(warm_volume_certified(0), |mut stage| {
        let client = Client::open(stage.store.clone(), MemLog::default()).unwrap();
        let mut duties = Duties::new(
            (
                &HostGate::qualified(),
                crate::failover::reconcile::StandbyGate::qualified(),
            ),
            Lane::inline(client, stage.storage),
            records(),
            None,
            bounds(),
            periods(),
        )
        .capturing(policy(), EngineBudget::unlimited())
        .unwrap();
        duties.capture.as_mut().unwrap().budget = budget;
        let mut input = None;
        let result = Cell::new(None);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if result.get().is_some() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                let capture = duties.capture.as_ref().unwrap();
                match &capture.pass {
                    Pass::Walked { input: bytes, .. } => input = Some(*bytes),
                    Pass::Writing { staged, .. } => {
                        result.set(Some(Ok((input.unwrap(), staged.units().len()))));
                    }
                    Pass::Idle if capture.refused + capture.abandoned > 0 => {
                        result.set(Some(Err((capture.refused, capture.abandoned))));
                    }
                    _ => {}
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        result.get().unwrap()
    })
}

/// The walk's copy of the cut and the encode's units count together against the capture budget: a budget one byte
/// short of the cut ends the pass abandoned in the walk, and one byte short of the cut and its units refuses the
/// stage, each before any unit write.
#[test]
fn a_cut_and_its_units_past_the_budget_end_the_pass_unstaged() {
    let (input, units) = pass_under(EngineBudget::unlimited()).expect("an unlimited pass stages");
    let per_unit = UNIT_LEN + size_of::<Box<[u8; UNIT_LEN]>>() + size_of::<bool>();
    let staged = input + units * per_unit;
    assert_eq!(
        pass_under(EngineBudget::new(staged)).map(|(_, units)| units),
        Ok(units)
    );
    assert_eq!(pass_under(EngineBudget::new(staged - 1)), Err((1, 0)));
    assert_eq!(pass_under(EngineBudget::new(input - 1)), Err((0, 1)));
}

/// A layout of the warm fixture's prefix length with another slot width.
fn relaid_layout() -> crate::failover::records::Layout {
    crate::failover::records::Layout {
        slot_units: 4,
        entries: 3 * crate::failover::records::UNIT_ENTRIES as u32,
        ..layout()
    }
}

/// Runs a warm tenure over `store` until `until` holds or the open stopped and four view periods passed, calling
/// `each` after every turn, and returns the duties' open, the shard-record commits and whether a pass left `Idle`.
fn run_over(
    stage: &mut Stage<'_>,
    store: Unanswered,
    records: super::Records<'static>,
    mut each: impl FnMut(&mut Duties<'_, Unanswered, MemLog, TestPlatform>, &mut TestOwner<'_>, u64),
) -> (Open, usize, bool) {
    let client = Client::open(store, MemLog::default()).unwrap();
    let mut duties = Duties::new(
        (
            &HostGate::qualified(),
            crate::failover::reconcile::StandbyGate::qualified(),
        ),
        Lane::inline(client, stage.storage),
        records,
        None,
        bounds(),
        periods(),
    )
    .capturing(policy(), EngineBudget::unlimited())
    .unwrap();
    let commits = stage.store.0.borrow().commit_count(&Key::Shard(shard()));
    let mut moved = false;
    let stopped = Cell::new(None::<u64>);
    let ended = Cell::new(false);
    let (served, _) = stage.serve_until(
        |_, _, stop| {
            if ended.get() {
                stop.store(true, Ordering::Release);
            }
        },
        |owner, now| {
            let exit = duties.turn(owner, now);
            each(&mut duties, owner, now);
            moved |= !matches!(duties.capture.as_ref().unwrap().pass, Pass::Idle);
            if duties.open == Open::Stopped && stopped.get().is_none() {
                stopped.set(Some(now));
            }
            ended.set(stopped.get().is_some_and(|at| now >= at + 4 * VIEW_US));
            exit
        },
    );
    assert_eq!(served.exit, Exit::Stopped);
    let after = stage.store.0.borrow().commit_count(&Key::Shard(shard()));
    (duties.open, after - commits, moved)
}

/// A warm tenure whose first view shows another slot width than the warm load read under, at the same prefix length,
/// stops the open before the set is built: no Confirm, no pass and no shard-record write.
#[test]
fn a_view_of_another_slot_layout_than_the_warm_load_stops_the_open() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let store = Unanswered::over(&stage.store, Arm::Hold);
        store.relaid.set(Some(relaid_layout()));
        let (open, commits, moved) = run_over(&mut stage, store, records(), |duties, _, _| {
            assert!(
                !matches!(duties.possible, super::Set::Here(_)) || duties.open != Open::Stopped
            );
        });
        assert_eq!((open, commits, moved), (Open::Stopped, 0, false));
    });
}

/// A view whose volume record's layout differs from the one the set was built under, read while a pass walks, stops
/// the open; the pass ends abandoned at its first unit command and publishes nothing.
#[test]
fn a_later_view_of_another_layout_stops_the_open_and_the_pass() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let store = Unanswered::over(&stage.store, Arm::Hold);
        let relaid = Rc::clone(&store.relaid);
        let shared = stage.store.clone();
        let mut abandoned = 0;
        let mut walked = None;
        PARK_RECOVERY.with(|park| park.set(true));
        let (open, commits, _) = run_over(&mut stage, store, records(), |duties, owner, _| {
            let capture = duties.capture.as_ref().unwrap();
            if walked.is_none() && matches!(capture.pass, Pass::Walking { .. }) {
                relaid.set(Some(relaid_layout()));
                walked = Some(shared.0.borrow().commit_count(&Key::Shard(shard())));
            }
            if duties.open == Open::Stopped {
                owner.release_parked();
            }
            assert!(!matches!(capture.pass, Pass::Publishing { .. }));
            abandoned = capture.abandoned;
        });
        PARK_RECOVERY.with(|park| park.set(false));
        assert_eq!(open, Open::Stopped);
        assert_eq!(abandoned, 1, "the pass ended abandoned");
        let before = walked.expect("a pass walked");
        assert_eq!(
            shared.0.borrow().commit_count(&Key::Shard(shard())),
            before,
            "no shard-record write after the walk's start"
        );
        assert!(commits >= 1);
    });
}

/// A withdrawal of the owner while a pass waits in `Proving` ends the pass abandoned with its slot quarantined and
/// no Publish, and starts no later pass.
#[test]
fn a_withdrawal_before_the_publish_ends_the_pass_unpublished() {
    use crate::failover::serving::{Cause, Event};
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = capture_duties(&stage);
        let store = stage.store.clone();
        let mut withdrawn = None;
        let mut slot = None;
        let (mut idle_again, mut started_after) = (false, false);
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                let capture = duties.capture.as_ref().unwrap();
                if withdrawn.is_none()
                    && let Pass::Proving { staged, .. } = &capture.pass
                {
                    slot = Some(staged.slot());
                    owner.authority_event(Event::Withdraw(Cause::Unheld), now);
                    let commits = store.0.borrow().commit_count(&Key::Shard(shard()));
                    withdrawn = Some((now, commits));
                }
                let finished = capture.abandoned == 1 && matches!(capture.pass, Pass::Idle);
                started_after |= idle_again && !matches!(capture.pass, Pass::Idle);
                idle_again |= finished;
                ended.set(idle_again && withdrawn.is_some_and(|(at, _)| now >= at + 2 * VIEW_US));
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        let (_, commits) = withdrawn.expect("the pass reached Proving");
        assert_eq!(store.0.borrow().commit_count(&Key::Shard(shard())), commits);
        let capture = duties.capture.as_ref().unwrap();
        assert_eq!((capture.published, capture.abandoned), (0, 1));
        assert!(
            !started_after,
            "no pass started after the withdrawn one ended"
        );
        assert!(duties.here().quarantined().contains(&slot.unwrap()));
        assert!(
            capture.kept.is_empty(),
            "the halted pass freed the stage's buffers"
        );
    });
}

/// The addresses of `units`, unit 0 first.
fn addresses(units: &[Box<[u8; UNIT_LEN]>]) -> Vec<*const u8> {
    units.iter().map(|unit| unit.as_ptr()).collect()
}

/// The tenure keeps the unit buffers of a published stage between passes, and the next pass's stage writes into
/// them: its units lie at the addresses of the last stage's. Once the owner's authority withdraws, the next turn
/// that adopts a view frees them, with no pass running.
#[test]
fn a_pass_writes_into_the_units_the_last_pass_kept_and_a_withdrawal_frees_them() {
    use crate::failover::serving::{Cause, Event};
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = capture_duties(&stage);
        let mut stages: Vec<Vec<*const u8>> = Vec::new();
        let mut kept_between = Vec::new();
        let mut withdrawn = None;
        let mut freed = None;
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                let capture = duties.capture.as_ref().unwrap();
                if let Pass::Writing { staged, .. } = &capture.pass
                    && stages.len() == capture.published as usize
                {
                    stages.push(addresses(staged.units()));
                }
                if matches!(capture.pass, Pass::Idle)
                    && capture.published as usize > kept_between.len()
                {
                    kept_between.push(addresses(&capture.kept));
                }
                if withdrawn.is_none()
                    && capture.published == 2
                    && matches!(capture.pass, Pass::Idle)
                {
                    owner.authority_event(Event::Withdraw(Cause::Unheld), now);
                    withdrawn = Some(now);
                }
                if let Some(at) = withdrawn
                    && freed.is_none()
                    && capture.kept.is_empty()
                {
                    freed = Some(now - at);
                }
                assert!(withdrawn.is_none() || capture.published == 2);
                ended.set(withdrawn.is_some_and(|at| now >= at + 2 * VIEW_US));
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert_eq!(stages.len(), 2);
        assert!(!stages[0].is_empty());
        assert_eq!(
            kept_between[0], stages[0],
            "the tenure keeps the first stage's buffers"
        );
        assert_eq!(stages[1], stages[0], "the second stage writes into them");
        let freed = freed.expect("the withdrawal freed the kept buffers");
        assert!(freed <= VIEW_US, "freed {freed} us after the withdrawal");
        assert!(matches!(duties.capture.as_ref().unwrap().pass, Pass::Idle));
    });
}

/// A walk turn checks the copy's chunks with the kept unit buffers' bytes against the capture budget: a budget that
/// holds the copy, one more chunk and those bytes walks with the buffers kept, a budget one byte short of the copy
/// and those bytes walks once the buffers yield them, and a budget short of the copy alone ends the walk abandoned.
/// A walk with the buffers charged refuses the chunk that a walk with them yielded reserves.
#[test]
fn a_walk_counts_the_kept_units_against_the_capture_budget() {
    use super::capture::{Walked, turn_budget, walk_turn};
    use crate::storage::checkpoint::{Cut, PER_UNIT};
    staged_over(warm_volume_certified(0), |stage| {
        let storage = stage.storage;
        // Walks the storage's membership from an empty copy under `budget` with `kept` bytes of unit buffers held,
        // as `Duties::walk` does, or with the kept bytes charged on every turn when `pinned`.
        let walk = |budget: usize, mut kept: usize, pinned: bool| {
            let mut policy = policy();
            let counter = storage
                .try_start_capture(&mut policy, 1_000_000_000, false, false, true)
                .unwrap()
                .unwrap()
                .counter;
            let (budget, mut cut, mut yielded) = (EngineBudget::new(budget), Cut::new(), false);
            let outcome = loop {
                let mut charged = budget;
                let held = match pinned {
                    true => charged.charge(kept).map(|()| charged).ok(),
                    false => turn_budget(budget, kept, &cut),
                };
                let held = held.unwrap_or_else(|| {
                    (yielded, kept) = (true, 0);
                    budget
                });
                match walk_turn(storage, held, counter, cut) {
                    Walked::More(more) => cut = more,
                    Walked::Done(done, input) => break Ok((done.len(), input)),
                    Walked::Abandoned(_) => break Err(()),
                }
            };
            storage.finish_capture(&mut policy, counter).unwrap();
            (outcome, yielded)
        };
        let (walked, yielded) = walk(usize::MAX, 0, false);
        let (members, input) = walked.unwrap();
        assert!(members > 0 && !yielded);
        let (kept, chunk) = (3 * PER_UNIT, 8192 * size_of::<u64>());
        assert_eq!(
            walk(input + chunk + kept, kept, false),
            (Ok((members, input)), false)
        );
        assert_eq!(
            walk(input + kept - 1, kept, false),
            (Ok((members, input)), true)
        );
        assert_eq!(walk(input + kept - 1, kept, true), (Err(()), false));
        assert_eq!(walk(input - 1, kept, false).0, Err(()));
        assert_eq!(walk(input - 1, 0, false), (Err(()), false));
    });
}

#[test]
fn a_walk_that_takes_the_kept_units_bytes_waits_for_their_discard_to_land() {
    use crate::storage::checkpoint::{Cut, PER_UNIT};
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = capture_duties(&stage);
        PARK_RECOVERY.with(|park| park.set(true));
        let (mut planted, mut waited, mut landed, mut reserved) = (false, 0u32, false, false);
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                let capture = duties.capture.as_mut().unwrap();
                if matches!(capture.pass, Pass::Encoding { .. }) {
                    owner.release_parked();
                }
                if !planted && capture.published == 1 && matches!(capture.pass, Pass::Idle) {
                    assert!(
                        !capture.kept.is_empty(),
                        "the tenure kept the stage's units"
                    );
                    let kept = capture.kept.len() * PER_UNIT;
                    capture.spare = Cut::new();
                    capture.budget = EngineBudget::new(Cut::new().turn_reserve() + kept - 1);
                    planted = true;
                } else if planted && !landed && capture.kept.is_empty() {
                    let Pass::Walking { cut, .. } = &capture.pass else {
                        panic!("the walk waits in place: {:?}", capture.pass);
                    };
                    assert_eq!(
                        cut.bytes(),
                        0,
                        "the copy reserves a chunk once the helpers freed the units"
                    );
                    waited += 1;
                    if waited == 64 {
                        owner.release_parked();
                        landed = true;
                    }
                } else if landed {
                    reserved |= match &capture.pass {
                        Pass::Walking { cut, .. } => cut.bytes() > 0,
                        pass => !matches!(pass, Pass::Idle | Pass::Finishing { .. }),
                    };
                    ended.set(reserved || matches!(capture.pass, Pass::Idle));
                }
                exit
            },
        );
        PARK_RECOVERY.with(|park| park.set(false));
        assert_eq!(served.exit, Exit::Stopped);
        assert_eq!(waited, 64);
        assert!(reserved, "the walk went on once the discard landed");
    });
}

fn capturing_on<'w, S: Store>(
    stage: &Stage<'w>,
    store: S,
    log: MemLog,
) -> Duties<'w, S, MemLog, TestPlatform> {
    let client = Client::open(store, log).unwrap();
    Duties::new(
        (
            &HostGate::qualified(),
            crate::failover::reconcile::StandbyGate::qualified(),
        ),
        Lane::inline(client, stage.storage),
        records(),
        None,
        bounds(),
        periods(),
    )
    .capturing(policy(), EngineBudget::unlimited())
    .unwrap()
}

/// The watermark log fails to record the Publish's raised watermark, which withdraws the store client.
#[test]
fn a_publish_that_withdraws_the_store_client_ends_the_tenure_on_its_adoption() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let log = MemLog::default();
        let fail = Rc::clone(&log.fail);
        let mut duties = capturing_on(&stage, stage.store.clone(), log);
        let mut adopted = None;
        let (served, _) = stage.serve_until(
            |_, _, _| {},
            |owner, now| {
                let exit = duties.turn(owner, now);
                let capture = duties.capture.as_ref().unwrap();
                if matches!(capture.pass, Pass::Proving { .. }) {
                    fail.set(true);
                }
                if adopted.is_none()
                    && let Some(refusal) = capture.refusal
                {
                    let ended = exit == Some(Exit::Rerun(Rerun::Withdrawn));
                    adopted = Some((refusal, ended, duties.open));
                }
                exit
            },
        );
        assert_eq!(served.exit, Exit::Rerun(Rerun::Withdrawn));
        assert_eq!(
            adopted,
            Some((WriteRefused::Store(StoreError::Log), true, Open::Stopped))
        );
    });
}

/// Two Publishes each end with an unknown outcome. The settling Confirm over the view after the first commits before
/// the second pass starts, so the first Publish's late write loses its condition, and the second Publish's checkpoint
/// becomes the base.
#[test]
fn a_settling_confirm_between_two_unanswered_publishes_makes_the_second_the_base() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let store = Unanswered::over(&stage.store, Arm::Hold);
        let armed = Rc::clone(&store.armed);
        let mut duties = capturing_on(&stage, store, MemLog::default());
        let shared = stage.store.clone();
        let mut submitted = Vec::new();
        let mut released = None;
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                let capture = duties.capture.as_ref().unwrap();
                if let Pass::Proving { staged, .. } = &capture.pass
                    && submitted.last() != Some(&staged.named())
                {
                    submitted.push(staged.named());
                    armed.set(true);
                }
                if capture.abandoned == 2 && released.is_none() {
                    released = Some((shared.0.borrow_mut().release(), now));
                }
                ended.set((released.as_ref()).is_some_and(|(_, at)| now >= *at + 3 * VIEW_US));
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        let (outcomes, _) = released.expect("two Publishes ended with an unknown outcome");
        assert!(
            matches!(
                outcomes[..],
                [
                    Outcome::NotCommitted(Refusal::Condition),
                    Outcome::Committed(_)
                ]
            ),
            "{outcomes:?}"
        );
        assert_ne!(submitted[0], submitted[1]);
        let second = Some(submitted[1]);
        assert_eq!(shard_record(&stage.store).checkpoint, second);
        assert_eq!(duties.open, Open::Opened);
        let base = duties.read.as_ref().map(|read| read.value().checkpoint);
        assert_eq!(base, Some(second));
    });
}

#[test]
fn a_withheld_readiness_ends_a_writing_pass() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = capture_duties(&stage);
        let storage = stage.storage;
        let mut withheld = None;
        let ended = Cell::new(false);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                let capture = duties.capture.as_ref().unwrap();
                let writing = matches!(
                    capture.pass,
                    Pass::Writing {
                        unit: Unit::Write(_),
                        ..
                    }
                );
                if withheld.is_none() && writing {
                    assert_eq!(storage.withdraw(), Readiness::Withheld);
                    withheld = Some(now);
                }
                ended.set(withheld.is_some_and(|at| now >= at + 2 * VIEW_US));
                exit
            },
        );
        assert_eq!(served.exit, Exit::Stopped);
        assert!(withheld.is_some(), "a pass reached its unit writes");
        let capture = duties.capture.as_ref().unwrap();
        assert_eq!(step_of(&capture.pass), step_of(&Pass::Idle));
        assert_eq!((capture.published, capture.abandoned), (0, 1));
    });
}

#[test]
fn a_newer_view_naming_a_foreign_checkpoint_stops_the_open_before_a_unit_write() {
    staged_over(warm_volume_certified(0), |mut stage| {
        let mut duties = capture_duties(&stage);
        let store = stage.store.clone();
        let mut planted = None;
        let mut exposed = false;
        let ended = Cell::new(false);
        PARK_RECOVERY.with(|park| park.set(true));
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if ended.get() {
                    stop.store(true, Ordering::Release);
                }
            },
            |owner, now| {
                let exit = duties.turn(owner, now);
                let capture = duties.capture.as_ref().unwrap();
                // A suffix step may hold the set on the lane while the pass walks.
                let walking = matches!(capture.pass, Pass::Walking { .. }) && duties.set_here();
                if planted.is_none() && walking {
                    let foreign = duties.here().free_slot().expect("a free slot");
                    let session = owner.tenure().get();
                    replaced_record(&store, |record| {
                        record.checkpoint = Some(NamedCheckpoint {
                            slot: foreign,
                            session,
                            capture: u32::MAX,
                            units: 1,
                        });
                    });
                    planted = Some(now);
                }
                if planted.is_some_and(|at| now >= at + 3 * VIEW_US) {
                    owner.release_parked();
                }
                exposed |= match &capture.pass {
                    Pass::Writing { unit, .. } => *unit != Unit::Write(0),
                    Pass::Proving { .. } | Pass::Publishing { .. } => true,
                    _ => false,
                };
                let idle = matches!(capture.pass, Pass::Idle);
                ended.set(idle && planted.is_some_and(|at| now >= at + 6 * VIEW_US));
                exit
            },
        );
        PARK_RECOVERY.with(|park| park.set(false));
        assert_eq!(served.exit, Exit::Stopped);
        assert!(planted.is_some(), "a pass walked");
        assert_eq!(duties.open, Open::Stopped);
        assert!(!exposed, "no unit write followed the foreign view");
        assert_eq!(published(&duties), 0);
    });
}
