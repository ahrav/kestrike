//! `Reconciler::create_shard` adopts a stored shard record only of the same creation.
//!
//! The creation is the shard, generation, active volume, owner, `B`, `C_page` and namespace. A stored record
//! of any other creation is refused `Conflict`; spare bookkeeping and the owner's `E` may differ.

use core::num::{NonZeroU16, NonZeroU32};

use crate::failover::reconcile::{ReconcileError, Reconciler};
use crate::failover::records::{Namespace, ShardRecord, VolumeId};
use crate::failover::sim::host;
use crate::net::ownership::ShardGeneration;
use crate::storage::store::sim::{Arm, AsProvisioner, MemLog, Shared};
use crate::storage::store::{Client, Key, StoreError};
use crate::storage::store_tests::{OWNER, SPARE, client, record, shard, stored};

/// The shard provisioner, over the store as its principal reaches it.
fn provisioner(store: &Shared) -> Reconciler<AsProvisioner<Shared>, MemLog> {
    Reconciler::new(Client::open(AsProvisioner(store.clone()), MemLog::default()).unwrap())
}

/// The record a shard is created with: [`record`] with no spare.
fn creation() -> ShardRecord {
    ShardRecord {
        spare: None,
        ..record()
    }
}

/// Watching one page past the creation's `B` lets the commit snapshot detect a write to a page that only a larger
/// `B` names.
const WATCHED: u16 = 3;

/// Commits of the shard record and of each watched coverage page, read without a store request.
fn commits(store: &Shared) -> Vec<usize> {
    let sim = store.0.borrow();
    let pages = (0..WATCHED).map(|page| Key::Page(shard(), page));
    std::iter::once(Key::Shard(shard()))
        .chain(pages)
        .map(|key| sim.commit_count(&key))
        .collect()
}

/// A store that holds the shard created from [`creation`].
fn created_store() -> Shared {
    let store = Shared::new();
    provisioner(&store).create_shard(creation()).unwrap();
    store
}

/// The six records that differ from [`creation`] in exactly one field a creation sets and that one key can hold.
fn others() -> [(&'static str, ShardRecord); 6] {
    assert_ne!(OWNER, 15, "the other owner differs from the creation's");
    [
        (
            "generation",
            ShardRecord {
                generation: ShardGeneration::new(4).unwrap(),
                ..creation()
            },
        ),
        (
            "active volume",
            ShardRecord {
                active: VolumeId::new("vol-0e").unwrap(),
                ..creation()
            },
        ),
        (
            "owner",
            ShardRecord {
                owner: host(15),
                ..creation()
            },
        ),
        (
            "pages (B)",
            ShardRecord {
                pages: NonZeroU16::new(3).unwrap(),
                ..creation()
            },
        ),
        (
            "page_cap (C_page)",
            ShardRecord {
                page_cap: NonZeroU32::new(8192).unwrap(),
                ..creation()
            },
        ),
        (
            "namespace",
            ShardRecord {
                namespace: Namespace::new([0x22; 16]).unwrap(),
                ..creation()
            },
        ),
    ]
}

/// What one `create_shard` over a store returned, with the store's commits and shard record after it.
#[derive(Debug, PartialEq)]
struct Call {
    returned: Result<ShardRecord, ReconcileError>,
    commits: Vec<usize>,
    stored: ShardRecord,
}

/// Calls `create_shard(record)` as a provisioner that made no earlier request.
fn call(store: &Shared, record: ShardRecord) -> Call {
    let returned = provisioner(store)
        .create_shard(record)
        .map(|read| *read.value());
    Call {
        returned,
        commits: commits(store),
        stored: stored(store).1,
    }
}

/// Each record that differs from the stored creation in one creation field refuses `Conflict` and writes
/// neither the shard record nor a page.
#[test]
fn a_record_of_another_creation_refuses_conflict_with_no_write() {
    let store = created_store();
    let before = commits(&store);
    let calls: Vec<(&str, ShardRecord, Call)> = others()
        .into_iter()
        .map(|(field, other)| (field, other, call(&store, other)))
        .collect();
    drop(store);

    assert_eq!(
        before,
        [1, 1, 1, 0],
        "one create of the record and of each of its B pages, and none of the page past them"
    );
    for (field, other, call) in calls {
        assert!(
            other.pages.get() <= WATCHED,
            "premise: the snapshot watches every page the record of another {field} names"
        );
        let differing = [
            other.generation != creation().generation,
            other.active != creation().active,
            other.owner != creation().owner,
            other.pages != creation().pages,
            other.page_cap != creation().page_cap,
            other.namespace != creation().namespace,
        ];
        assert_eq!(
            differing.iter().filter(|&&differs| differs).count(),
            1,
            "premise: the record differs in {field} alone"
        );
        assert_eq!(
            call,
            Call {
                returned: Err(ReconcileError::Conflict),
                commits: before.clone(),
                stored: creation(),
            },
            "a record of another {field} is another creation: {other:?}"
        );
    }
}

/// The same steps with the creation's own record: the call adopts the stored record and writes nothing.
#[test]
fn the_same_creation_is_adopted_with_no_write() {
    let store = created_store();
    let before = commits(&store);
    let call = call(&store, creation());
    drop(store);

    assert_eq!(
        call,
        Call {
            returned: Ok(creation()),
            commits: before,
            stored: creation(),
        }
    );
}

/// After another writer bumped `E` and named a spare, a replay of the creation record returns the stored record
/// as it is, with one read and no shard or page write, while a record of another owner still refuses.
#[test]
fn a_replay_after_a_bump_and_a_spare_returns_the_stored_record() {
    let store = created_store();
    let mut writer = client(&store);
    let read = writer.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    let bumped = writer.bump(&read).map(drop);
    let read = writer.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    let spare = Some((VolumeId::new("vol-0b").unwrap(), host(SPARE)));
    let named = writer
        .replace(
            &read,
            ShardRecord {
                spare,
                ..*read.value()
            },
        )
        .map(drop);
    let (version, held) = stored(&store);
    let before = commits(&store);

    // The replay's read takes the passing arm, so the next request finds the failing arm only if the replay made no other request.
    store.schedule(Arm::Pass);
    store.schedule(Arm::Unavailable);
    let replay = provisioner(&store)
        .create_shard(creation())
        .map(|read| (read.version(), *read.value()));
    let next = client(&store)
        .read::<ShardRecord>(Key::Shard(shard()))
        .map(drop);
    let after = (commits(&store), stored(&store));
    let other_owner = call(
        &store,
        ShardRecord {
            owner: host(15),
            ..creation()
        },
    );
    drop(writer);
    drop(store);

    assert_eq!(bumped, Ok(()), "premise: the owner's bump commits");
    assert_eq!(named, Ok(()), "premise: the spare's naming commits");
    assert_eq!(
        (held.attempts, held.spare),
        (1, spare),
        "premise: the stored record moved past its creation"
    );
    assert_eq!(before, [3, 1, 1, 0], "premise: two writes after the create");
    assert_eq!(
        replay,
        Ok((version, held)),
        "the replay returns the stored record"
    );
    assert_eq!(
        next,
        Err(StoreError::Unavailable),
        "the replay made one request, its read"
    );
    assert_eq!(
        after,
        (before.clone(), (version, held)),
        "the replay wrote nothing"
    );
    assert_eq!(
        other_owner,
        Call {
            returned: Err(ReconcileError::Conflict),
            commits: before,
            stored: held,
        },
        "a moved record still refuses another owner's creation"
    );
}
