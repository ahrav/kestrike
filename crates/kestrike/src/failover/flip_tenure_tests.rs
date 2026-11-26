//! `Reconciler::flip` against the tenure its target names.
//!
//! A stored shard record at generation g names an unused attached spare, and the owner bumps `E` once.
//! `Reconciler::flip(shard, target)` refuses `ReconcileError::Stale` for a `target` at g read before the bump,
//! whose `attempts` differ from the record's, and for one at g whose `owner` differs, and after each refusal the
//! shard record, the two volume records, every record's commit count and the store's list of flips are as they
//! were. After the same history a flip with the record's own `(g, owner, E)` returns `Flip::Flipped` at g + 1,
//! and a repeat with that same target returns `Flip::Past` and writes nothing.

use super::reconcile::{Flip, ReconcileError, Reconciler, StandbyGate};
use super::records::{ERA, Record, ShardRecord, VolumeId, VolumeRecord};
use super::retire::Target;
use super::sim::{host, layout};
use crate::storage::store::sim::{AsProvisioner, AsReconciler, MemLog, Shared};
use crate::storage::store::{Client, Key};
use crate::storage::store_tests::{OWNER, SPARE, client, record, shard, stored};

/// The spare: the volume the fixture record names, attached to the standby host.
fn spare_volume() -> VolumeId {
    VolumeId::new("vol-0b").unwrap()
}

/// The long-running reconciler, over the store as its principal reaches it.
fn reconciler(store: &Shared) -> Reconciler<AsReconciler<Shared>, MemLog> {
    Reconciler::new(Client::open(AsReconciler(store.clone()), MemLog::default()).unwrap())
}

/// A store whose shard record, at the fixture's generation g with `E = 1`, names an unused attached spare: the
/// shard is created with no spare, its active volume is provisioned and attached to the owner, `vol-0b` is
/// provisioned, attached to the standby and added as the spare, and the owner then bumps `E` once. Returns the
/// store with the shard record read before the bump and the one stored after it.
fn bumped_with_a_spare() -> (Shared, ShardRecord, ShardRecord) {
    let created = ShardRecord {
        spare: None,
        ..record()
    };
    let store = Shared::new();
    Reconciler::new(Client::open(AsProvisioner(store.clone()), MemLog::default()).unwrap())
        .create_shard(created)
        .unwrap();
    let mut reconciler = reconciler(&store);
    reconciler.provision(created.active, layout()).unwrap();
    reconciler
        .record_attach(created.active, host(OWNER), ERA)
        .unwrap();
    reconciler.provision(spare_volume(), layout()).unwrap();
    let attached = reconciler
        .record_attach(spare_volume(), host(SPARE), ERA)
        .unwrap();
    reconciler
        .add_spare(shard(), Target::of(&created), &attached)
        .unwrap();
    let before = stored(&store).1;
    let mut owner = client(&store);
    let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    owner.bump(&read).unwrap();
    let after = stored(&store).1;
    assert_eq!(
        (
            before.generation,
            before.owner,
            before.attempts,
            before.spare
        ),
        (
            record().generation,
            host(OWNER),
            0,
            Some((spare_volume(), host(SPARE)))
        ),
        "premise: the record at g names the owner, E = 0 and the attached spare"
    );
    assert_eq!(
        after,
        ShardRecord {
            attempts: 1,
            ..before
        },
        "premise: the owner's bump raised E alone"
    );
    (store, before, after)
}

/// The volume record `store` holds for `id`.
fn stored_volume(store: &Shared, id: VolumeId) -> VolumeRecord {
    let item = store.0.borrow().current(&Key::Volume(id)).cloned().unwrap();
    VolumeRecord::decode(&item.value).unwrap()
}

/// Everything a flip writes: the shard record, the active and the spare volume's records, each record's commit
/// count, and the generations the store flipped.
fn written(store: &Shared) -> (ShardRecord, [VolumeRecord; 2], [usize; 3], Vec<u64>) {
    let volumes = [record().active, spare_volume()];
    let commits = [
        Key::Shard(shard()),
        Key::Volume(volumes[0]),
        Key::Volume(volumes[1]),
    ]
    .map(|key| store.0.borrow().commit_count(&key));
    (
        stored(store).1,
        volumes.map(|id| stored_volume(store, id)),
        commits,
        store.0.borrow().flips.clone(),
    )
}

/// FLIP-ONCE-PER-TENURE: `Reconciler::flip` flips the shard from the `(g, owner, E)` its caller names. A target
/// at the record's generation that names another `E`, read before the owner's bump, or another owner is another
/// tenure: the flip refuses `Stale` and writes nothing.
#[test]
fn a_flip_naming_the_generation_with_another_e_or_owner_refuses_stale_and_writes_nothing() {
    let (store, before, after) = bumped_with_a_spare();
    let mut reconciler = reconciler(&store);
    let untouched = written(&store);
    assert!(
        untouched.3.is_empty(),
        "premise: the store has flipped nothing"
    );

    let earlier_e = Target::of(&before);
    assert_eq!(
        (earlier_e.generation, earlier_e.owner, earlier_e.attempts),
        (after.generation, after.owner, after.attempts - 1),
        "premise: the target differs from the record in E alone"
    );
    assert_eq!(
        reconciler.flip(&StandbyGate::qualified(), shard(), earlier_e),
        Err(ReconcileError::Stale),
        "a flip naming g with the E read before the owner's bump is refused Stale"
    );
    assert_eq!(
        written(&store),
        untouched,
        "the refused flip of another E wrote nothing"
    );

    let other_owner = Target {
        owner: host(99),
        ..Target::of(&after)
    };
    assert_ne!(other_owner.owner, after.owner, "premise: another owner");
    assert_eq!(
        reconciler.flip(&StandbyGate::qualified(), shard(), other_owner),
        Err(ReconcileError::Stale),
        "a flip naming g and E with another owner is refused Stale"
    );
    assert_eq!(
        written(&store),
        untouched,
        "the refused flip of another owner wrote nothing"
    );
}

/// After the same history, a flip that names the record's own `(g, owner, E)`
/// flips once, to g + 1 with the spare active under its host and `E = 0`, and a repeat with that same target
/// finds the shard past g: it returns `Past` and writes nothing.
#[test]
fn a_flip_naming_the_records_own_tenure_flips_once_and_its_repeat_is_past() {
    let (store, _, after) = bumped_with_a_spare();
    let mut reconciler = reconciler(&store);
    let g = record().generation.get();
    let own = Target::of(&after);

    let flipped = reconciler.flip(&StandbyGate::qualified(), shard(), own);
    let Ok(Flip::Flipped(flipped)) = flipped else {
        panic!("a flip naming the record's own (g, owner, E) flips: {flipped:?}");
    };
    assert_eq!(
        flipped.generation().get(),
        g + 1,
        "the flip moves the shard from g to g + 1"
    );
    let moved = written(&store);
    let record = moved.0;
    assert_eq!(
        (
            record.generation.get(),
            record.active,
            record.owner,
            record.attempts
        ),
        (g + 1, spare_volume(), host(SPARE), 0),
        "the stored record is at g + 1 with the spare active under its host"
    );
    assert_eq!(moved.3, vec![g], "the store flipped g once");

    assert_eq!(
        reconciler.flip(&StandbyGate::qualified(), shard(), own),
        Ok(Flip::Past),
        "a repeat of the same target finds the shard past g"
    );
    assert_eq!(written(&store), moved, "the repeat wrote nothing");
}
