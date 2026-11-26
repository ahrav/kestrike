//! `Reconciler::add_spare` names only an unused attached volume.
//!
//! Over a simulated store with a created shard and its attached active
//! volume, `add_spare` names an attached volume the spare of the tenure it
//! is given only while the volume's record shows it unused. A volume whose
//! record another writer made show use is refused `Conflict` with no shard
//! write, another tenure is refused `Stale`, the active volume and an
//! occupied slot are refused `Conflict`, and an unused volume is named
//! once.
//!
//! Each test reads what the calls did into a value and asserts afterwards.

use crate::failover::evidence::Pair;
use crate::failover::identity::{Epoch, Exhid, Incarnation, Key as ReservationKey};
use crate::failover::reconcile::{AttachRecorded, ReconcileError, Reconciler};
use crate::failover::records::{
    ERA, EventKind, Modification, RecordedPair, ShardRecord, VolumeId, VolumeRecord, VolumeState,
};
use crate::failover::retire::Target;
use crate::failover::sim::{host, layout};
use crate::storage::store::sim::{AsProvisioner, AsReconciler, MemLog, Shared};
use crate::storage::store::{Client, Key};
use crate::storage::store_tests::{OWNER, SPARE, client, record, shard as sid, stored};

fn vol(name: &str) -> VolumeId {
    VolumeId::new(name).unwrap()
}

/// The long-running reconciler, over the store as its principal reaches it.
fn reconciler(store: &Shared) -> Reconciler<AsReconciler<Shared>, MemLog> {
    Reconciler::new(Client::open(AsReconciler(store.clone()), MemLog::default()).unwrap())
}

/// The record the shard is created with: the fixture's record with no spare.
fn empty() -> ShardRecord {
    ShardRecord {
        spare: None,
        ..record()
    }
}

/// Provisions `id` and records its attachment to host `holder`, which returns the witness `add_spare` takes.
fn attach(
    reconciler: &mut Reconciler<AsReconciler<Shared>, MemLog>,
    id: VolumeId,
    holder: u64,
) -> AttachRecorded {
    reconciler.provision(id, layout()).unwrap();
    reconciler.record_attach(id, host(holder), ERA).unwrap()
}

/// A store holding the shard created from [`empty`] and its active volume, provisioned and attached to the
/// owner.
fn world() -> Shared {
    let store = Shared::new();
    Reconciler::new(Client::open(AsProvisioner(store.clone()), MemLog::default()).unwrap())
        .create_shard(empty())
        .unwrap();
    attach(&mut reconciler(&store), record().active, OWNER);
    store
}

/// Commits the store holds for the shard record.
fn shard_commits(store: &Shared) -> usize {
    store.0.borrow().commit_count(&Key::Shard(sid()))
}

/// Replaces the volume record of `id` with `edit` of it, as another writer.
fn edit_volume(store: &Shared, id: VolumeId, edit: fn(&VolumeRecord) -> VolumeRecord) {
    let mut other = client(store);
    let read = other.read::<VolumeRecord>(Key::Volume(id)).unwrap();
    let next = edit(read.value());
    other.replace(&read, next).unwrap();
}

fn modified(held: &VolumeRecord) -> VolumeRecord {
    VolumeRecord {
        modification: Some(Modification::InProgress),
        ..held.clone()
    }
}

/// `held` with a detach event of the spare host after its attach event.
fn detached(held: &VolumeRecord) -> VolumeRecord {
    let mut next = held.clone();
    next.push(EventKind::Detach, host(SPARE), ERA);
    next
}

/// `held` with a recorded pair of the spare host pinned to its first attach event.
fn registered(held: &VolumeRecord) -> VolumeRecord {
    VolumeRecord {
        pairs: vec![RecordedPair {
            host: host(SPARE),
            pair: Pair {
                exhid: Exhid::new([0xE1; 16]).unwrap(),
                key: ReservationKey::new(Epoch::new(2).unwrap(), Incarnation::new(1).unwrap()),
            },
            attach: held.events[0].seq,
        }],
        ..held.clone()
    }
}

/// `held` with its fence raised to the session `(1, 2)`.
fn fenced(held: &VolumeRecord) -> VolumeRecord {
    VolumeRecord {
        fence: crate::net::ownership::session_of(1, 2),
        ..held.clone()
    }
}

fn retired(held: &VolumeRecord) -> VolumeRecord {
    VolumeRecord {
        state: VolumeState::Retired,
        ..held.clone()
    }
}

/// What one `add_spare` call left: its result without the read, the shard commits it added and the spare the
/// stored shard record names afterwards.
type Left = (
    Result<(), ReconcileError>,
    usize,
    Option<(VolumeId, crate::failover::records::Host)>,
);

/// A change another writer makes to a volume record.
type Edit = fn(&VolumeRecord) -> VolumeRecord;

/// Calls `add_spare` for `attached` under `target` and reads what it left in `store`.
fn add_spare(
    store: &Shared,
    reconciler: &mut Reconciler<AsReconciler<Shared>, MemLog>,
    target: Target,
    attached: &AttachRecorded,
) -> Left {
    let before = shard_commits(store);
    let result = reconciler.add_spare(sid(), target, attached).map(drop);
    (result, shard_commits(store) - before, stored(store).1.spare)
}

/// A volume attached to the spare host whose record another writer then made show use is not unused:
/// `add_spare` with its attach witness refuses `Conflict`, writes no shard record and names no spare. One
/// store per case, so no case rests on what another left.
#[test]
fn a_volume_whose_record_shows_use_is_refused_conflict_with_no_shard_write() {
    let cases: [(&str, Edit); 5] = [
        ("a modification record", modified),
        ("a second attachment event", detached),
        ("a recorded pair", registered),
        ("a nonzero fence", fenced),
        ("the retired state", retired),
    ];
    let observed = cases.map(|(case, edit)| {
        let store = world();
        let mut reconciler = reconciler(&store);
        let used = attach(&mut reconciler, vol("vol-0c"), SPARE);
        edit_volume(&store, vol("vol-0c"), edit);
        let left = add_spare(&store, &mut reconciler, Target::of(&empty()), &used);
        (case, left)
    });
    let refused: Left = (Err(ReconcileError::Conflict), 0, None);
    assert_eq!(observed, cases.map(|(case, _)| (case, refused)));
}

/// The counterpart without the other writer's change: the same volume, unused, is named the spare with one shard
/// write, and a repeat of the call returns the shard record as it is and writes nothing.
#[test]
fn an_unused_volume_is_named_once_and_a_repeat_writes_nothing() {
    let store = world();
    let mut reconciler = reconciler(&store);
    let unused = attach(&mut reconciler, vol("vol-0c"), SPARE);
    let target = Target::of(&empty());
    let named = (vol("vol-0c"), host(SPARE));
    let first = add_spare(&store, &mut reconciler, target, &unused);
    let before = shard_commits(&store);
    let repeat = reconciler
        .add_spare(sid(), target, &unused)
        .map(|read| *read.value());
    let repeat_commits = shard_commits(&store) - before;
    let after = stored(&store).1;
    assert_eq!(first, (Ok(()), 1, Some(named)));
    assert_eq!(
        (repeat, repeat_commits),
        (
            Ok(ShardRecord {
                spare: Some(named),
                ..empty()
            }),
            0
        )
    );
    assert_eq!(after.spare, Some(named));
}

/// The refusals that do not read the volume record as used: a target of another tenure is `Stale`, the
/// active volume is a `Conflict`, and once a spare is named another unused volume is a `Conflict`. None
/// writes the shard record.
#[test]
fn another_tenure_is_stale_and_the_active_volume_or_an_occupied_slot_conflicts() {
    let store = world();
    let mut reconciler = reconciler(&store);
    let target = Target::of(&empty());
    let active = reconciler
        .record_attach(record().active, host(OWNER), ERA)
        .unwrap();
    let first = attach(&mut reconciler, vol("vol-0c"), SPARE);
    let second = attach(&mut reconciler, vol("vol-0d"), 14);

    let of_active = add_spare(&store, &mut reconciler, target, &active);
    // The owner bumps `E`, so the stored record holds another tenure than `target`.
    let mut owner = client(&store);
    let read = owner.read::<ShardRecord>(Key::Shard(sid())).unwrap();
    owner.bump(&read).unwrap();
    let current = Target::of(&stored(&store).1);
    let stale = add_spare(&store, &mut reconciler, target, &first);
    let named = add_spare(&store, &mut reconciler, current, &first);
    let occupied = add_spare(&store, &mut reconciler, current, &second);

    let spare = Some((vol("vol-0c"), host(SPARE)));
    assert_ne!(current, target, "premise: the bump changed the tenure");
    assert_eq!(of_active, (Err(ReconcileError::Conflict), 0, None));
    assert_eq!(stale, (Err(ReconcileError::Stale), 0, None));
    assert_eq!(named, (Ok(()), 1, spare));
    assert_eq!(occupied, (Err(ReconcileError::Conflict), 0, spare));
}
