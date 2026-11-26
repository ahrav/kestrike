use core::num::{NonZeroU16, NonZeroU32};

use crate::failover::attachments::Mismatch;
use crate::failover::evidence::Pair;
use crate::failover::identity::{Epoch, Exhid, Incarnation, Key as ReservationKey};
use crate::failover::loss::{
    CreateError, Decision, Health, Phase, Provider, Receipt, Request, decide,
};
use crate::failover::reconcile::{
    AttachRecorded, Detachable, Flip, Listing, OperatorRelease, ReconcileError, Reconciler,
    Retired, Settle, StandbyGate,
};
use crate::failover::records::Host;
use crate::failover::records::{
    Ancestry, AttachmentEvent, CoveragePage, CreationSource, ERA, EventKind, Layout, LayoutRefusal,
    Lineage, Modification, NamedCheckpoint, Record, RecordedPair, ShardRecord, Suffix, VolumeId,
    VolumeRecord, VolumeState,
};
use crate::failover::retire::{Retirement, Role, Target, Trigger};
use crate::failover::sim::{host, layout};
use crate::failover::standbys::tests::roomy;
use crate::failover::standbys::{
    Attach, Census, Entry, Population, Refusal as PopulationRefusal, Slot, Zone,
};
use crate::net::ownership::ShardGeneration;
use crate::storage::store::dynamo;
use crate::storage::store::sim::{Arm, AsProvisioner, AsReconciler, MemLog, Point, Shared, hooked};
use crate::storage::store::{Client, Key, Outcome, Read, Refusal, StoreError};
use crate::storage::store_tests::{
    OWNER, SPARE, UNKNOWN, client, committed, record, shard as sid, stored,
};

#[path = "creation_replay_tests.rs"]
pub(in crate::failover) mod creation_replay;
#[path = "loss_replay_tests.rs"]
mod loss_replay;
#[path = "replay_driver_tests.rs"]
pub(in crate::failover) mod replay_driver;
#[path = "standbys_replay_tests.rs"]
mod standbys_replay;

fn vol(name: &str) -> VolumeId {
    VolumeId::new(name).unwrap()
}

/// The long-running reconciler, over the store as its principal reaches it.
fn reconciler(store: &Shared) -> Reconciler<AsReconciler<Shared>, MemLog> {
    Reconciler::new(Client::open(AsReconciler(store.clone()), MemLog::default()).unwrap())
}

/// The shard provisioner, over the store as its principal reaches it.
fn provisioner(store: &Shared) -> Reconciler<AsProvisioner<Shared>, MemLog> {
    Reconciler::new(Client::open(AsProvisioner(store.clone()), MemLog::default()).unwrap())
}

/// [`record`] with no spare: the record a shard is created with.
fn empty() -> ShardRecord {
    ShardRecord {
        spare: None,
        ..record()
    }
}

/// The volume record `store` holds now, read without consuming a scheduled arm.
fn stored_volume(store: &Shared, id: VolumeId) -> VolumeRecord {
    let item = store.0.borrow().current(&Key::Volume(id)).cloned().unwrap();
    VolumeRecord::decode(&item.value).unwrap()
}

fn commits(store: &Shared, key: Key) -> usize {
    store.0.borrow().commit_count(&key)
}

/// Replaces the volume record of `id` with `edit` of it, as another writer.
fn edit_volume(store: &Shared, id: VolumeId, edit: impl FnOnce(&VolumeRecord) -> VolumeRecord) {
    let mut other = client(store);
    let read = other.read::<VolumeRecord>(Key::Volume(id)).unwrap();
    let next = edit(read.value());
    other.replace(&read, next).unwrap();
}

/// `held` with host `h`'s live entry ended in place, as the reconciler's end write leaves it.
fn ended(held: &VolumeRecord, h: u64) -> VolumeRecord {
    let mut next = held.clone();
    let at = next.live(host(h)).unwrap();
    next.events
        .iter_mut()
        .find(|event| event.seq == at)
        .unwrap()
        .kind = EventKind::Ended;
    next
}

/// `held` with host `h`'s latest entry marked gone, as the reconciler's gone write leaves an ended entry.
fn gone(held: &VolumeRecord, h: u64) -> VolumeRecord {
    let mut next = held.clone();
    next.events
        .iter_mut()
        .rfind(|event| event.host == host(h))
        .unwrap()
        .kind = EventKind::Gone;
    next
}

/// The format version of the volume record `store` holds now, read from its stored bytes without consuming a
/// scheduled arm.
fn stored_format(store: &Shared, id: VolumeId) -> u16 {
    let item = store.0.borrow().current(&Key::Volume(id)).cloned().unwrap();
    u16::from_be_bytes([item.value[4], item.value[5]])
}

/// A client over `store` that counts every request it submits, failed ones included.
fn counting(
    store: &Shared,
) -> (
    Client<crate::storage::store::sim::Counting<Shared>, MemLog>,
    crate::storage::store::sim::Requests,
) {
    let requests = crate::storage::store::sim::Requests::default();
    let client = Client::open(
        crate::storage::store::sim::Counting {
            store: store.clone(),
            requests: requests.clone(),
        },
        MemLog::default(),
    )
    .unwrap();
    (client, requests)
}

/// Bumps `E` as the owner.
fn bump(store: &Shared) {
    let mut owner = client(store);
    let read = owner.read::<ShardRecord>(Key::Shard(sid())).unwrap();
    owner.bump(&read).unwrap();
}

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
    provisioner(&store).create_shard(empty()).unwrap();
    attach(&mut reconciler(&store), record().active, OWNER);
    store
}

/// [`world`] with `vol-0b`, attached to the standby, named the spare.
fn spared() -> (Shared, AttachRecorded) {
    let store = world();
    let mut reconciler = reconciler(&store);
    let spare = attach(&mut reconciler, vol("vol-0b"), SPARE);
    reconciler
        .add_spare(sid(), Target::of(&empty()), &spare)
        .unwrap();
    (store, spare)
}

fn drop_request(id: VolumeId, target: Target) -> Retirement {
    Retirement::new(
        id,
        Role::Spare,
        target,
        Trigger::Attachment(Mismatch::Duplicate),
    )
    .unwrap()
}

/// The requests each step makes, in order; a count names how many pass before the faulted one.
/// `create_shard` on an empty store: shard read, one create per page, then the shard create.
const FIRST_PAGE_CREATE: usize = 1;
fn shard_create() -> usize {
    1 + usize::from(empty().pages.get())
}
/// `record_attach`: volume read, then its write.
const ATTACH_WRITE: usize = 1;
/// `add_spare`: shard read, volume read, receipt read, then the naming write.
const NAMING_WRITE: usize = 3;
/// `flip`: shard read, spare read, spare rewrite, active read, active mark, receipt read, then the flip.
const SPARE_REWRITE: usize = 2;
const ACTIVE_MARK: usize = 4;
const FLIP_WRITE: usize = 6;
/// `retire` reads the volume and shard, writes the retired state, then conditions the settling write on the shard
/// version read.
const RETIRE_WRITE: usize = 2;
const RETIRE_SETTLE: usize = 3;

/// `retire_spare` of a named spare that no receipt records: volume read, shard read, receipt read, the removal, the
/// retired-state write, then the settling write.
const REMOVAL: usize = 3;
const SPARE_RETIRE_WRITE: usize = 4;
const SPARE_SETTLE: usize = 5;
/// `retire` of a volume already retired: volume read, shard read, then the settling write.
const RETIRED_SETTLE: usize = 2;
const STANDBY_WRITE: usize = 3;

/// Schedules `requests` passing requests and then `arm`, asserts that the step returns no witness, and returns
/// the retry's result.
fn unknown_then_retry<T: std::fmt::Debug>(
    store: &Shared,
    requests: usize,
    arm: Arm,
    mut step: impl FnMut() -> Result<T, ReconcileError>,
) -> Result<T, ReconcileError> {
    park(store, requests, arm);
    let first = step();
    assert!(
        matches!(first, Err(ReconcileError::Store(StoreError::Unknown))),
        "{arm:?}: {first:?}"
    );
    step()
}

/// Schedules `requests` passing requests and then `arm`.
fn park(store: &Shared, requests: usize, arm: Arm) {
    for _ in 0..requests {
        store.schedule(Arm::Pass);
    }
    store.schedule(arm);
}

/// A flip retried after an unknown outcome repeats the flip of its tenure when the first did not commit, and finds
/// the shard past that generation when it did, even after another reconciler named a new spare at the next
/// generation; a retry after the owner's `E` bump refuses as stale. The shard flips once from that tenure, the
/// flip clears the checkpoint a host named, and the displaced volume's record shows it active.
#[test]
fn flip_retry_idempotent_on_generation() {
    let g = record().generation.get();
    for arm in UNKNOWN {
        let commit = committed(arm);
        let (store, _) = spared();
        let mut owner = client(&store);
        let read = owner.read::<ShardRecord>(Key::Shard(sid())).unwrap();
        let published = ShardRecord {
            checkpoint: Some(NamedCheckpoint {
                slot: 1,
                session: (3 << 32) | 2,
                capture: 1,
                units: 4,
            }),
            ..*read.value()
        };
        owner.replace(&read, published).unwrap();
        let target = Target::of(&published);
        let mut reconciler = reconciler(&store);
        park(&store, FLIP_WRITE, arm);
        assert_eq!(
            reconciler.flip(&StandbyGate::qualified(), sid(), target),
            Err(ReconcileError::Store(StoreError::Unknown))
        );
        if commit {
            let mut other = self::reconciler(&store);
            let next = attach(&mut other, vol("vol-0d"), 14);
            other
                .add_spare(sid(), Target::of(&stored(&store).1), &next)
                .unwrap();
        }
        let retried = reconciler
            .flip(&StandbyGate::qualified(), sid(), target)
            .unwrap();
        match (commit, retried) {
            (true, Flip::Past) => {
                assert_eq!(stored(&store).1.spare, Some((vol("vol-0d"), host(14))));
            }
            (false, Flip::Flipped(flipped)) => assert_eq!(flipped.generation().get(), g + 1),
            (commit, other) => panic!("commit {commit}: {other:?}"),
        }
        assert_eq!(
            reconciler.flip(&StandbyGate::qualified(), sid(), target),
            Ok(Flip::Past),
            "{arm:?}"
        );
        assert_eq!(store.0.borrow().flips, vec![g], "{arm:?}: one flip of g");
        let after = stored(&store).1;
        assert_eq!(
            (
                after.generation.get(),
                after.active,
                after.owner,
                after.attempts,
                after.checkpoint
            ),
            (g + 1, vol("vol-0b"), host(SPARE), 0, None)
        );
        assert_eq!(
            stored_volume(&store, record().active).state,
            VolumeState::Active
        );
    }

    let (store, _) = spared();
    let target = Target::of(&stored(&store).1);
    let mut reconciler = reconciler(&store);
    park(&store, FLIP_WRITE, Arm::Timeout { commit: false });
    assert_eq!(
        reconciler.flip(&StandbyGate::qualified(), sid(), target),
        Err(ReconcileError::Store(StoreError::Unknown))
    );
    bump(&store);
    assert_eq!(
        reconciler.flip(&StandbyGate::qualified(), sid(), target),
        Err(ReconcileError::Stale),
        "a restarted tenure is not flipped"
    );
    let later = Target {
        generation: ShardGeneration::new(g + 1).unwrap(),
        ..target
    };
    assert_eq!(
        reconciler.flip(&StandbyGate::qualified(), sid(), later),
        Err(ReconcileError::Stale)
    );
    assert!(store.0.borrow().flips.is_empty());
}

/// Every reconciler write whose outcome is unknown, committed or not, returns no witness; its retry reads the
/// record and either finds the committed value or makes the write, so each record holds one commit of the step,
/// except the settling shard write and the flip's spare rewrite, which every attempt makes again.
#[test]
fn unknown_outcome_adopts_nothing() {
    let active = record().active;
    for arm in UNKNOWN {
        let commit = committed(arm);
        let store = Shared::new();
        unknown_then_retry(&store, shard_create(), arm, || {
            provisioner(&store).create_shard(empty())
        })
        .unwrap();
        assert_eq!(commits(&store, Key::Shard(sid())), 1, "{arm:?}");
        let paged = Shared::new();
        let mut paging = provisioner(&paged);
        unknown_then_retry(&paged, FIRST_PAGE_CREATE, arm, || {
            paging.create_shard(empty())
        })
        .unwrap();
        for page in 0..empty().pages.get() {
            assert_eq!(
                commits(&paged, Key::Page(sid(), page)),
                1,
                "{arm:?}: page {page}"
            );
        }
        assert_eq!(commits(&paged, Key::Shard(sid())), 1, "{arm:?}");

        let mut reconciler = reconciler(&store);
        unknown_then_retry(&store, 0, arm, || reconciler.provision(active, layout())).unwrap();
        unknown_then_retry(&store, ATTACH_WRITE, arm, || {
            reconciler.record_attach(active, host(OWNER), ERA)
        })
        .unwrap();
        assert_eq!(commits(&store, Key::Volume(active)), 2, "{arm:?}");
        let spare = attach(&mut reconciler, vol("vol-0b"), SPARE);
        let target = Target::of(&empty());
        unknown_then_retry(&store, NAMING_WRITE, arm, || {
            reconciler.add_spare(sid(), target, &spare)
        })
        .unwrap();
        assert_eq!(commits(&store, Key::Shard(sid())), 2, "{arm:?}");

        unknown_then_retry(&store, FLIP_WRITE, arm, || {
            reconciler.flip(&StandbyGate::qualified(), sid(), target)
        })
        .unwrap();
        assert_eq!(
            commits(&store, Key::Volume(active)),
            3,
            "{arm:?}: create, attach, active"
        );
        assert_eq!(commits(&store, Key::Shard(sid())), 3, "{arm:?}: one flip");

        unknown_then_retry(&store, RETIRE_WRITE, arm, || {
            reconciler.retire(sid(), active)
        })
        .unwrap();
        assert_eq!(
            commits(&store, Key::Volume(active)),
            4,
            "{arm:?}: create, attach, active, retire"
        );
        assert_eq!(stored_volume(&store, active).state, VolumeState::Retired);
        let shard = commits(&store, Key::Shard(sid()));
        unknown_then_retry(&store, RETIRED_SETTLE, arm, || {
            reconciler.retire(sid(), active)
        })
        .unwrap();
        assert_eq!(
            commits(&store, Key::Shard(sid())),
            shard + 1 + usize::from(commit),
            "{arm:?}: one settling write per attempt that commits it"
        );

        let next = Target::of(&stored(&store).1);
        for (id, requests) in [
            ("vol-0d", REMOVAL),
            ("vol-0e", SPARE_RETIRE_WRITE),
            ("vol-0f", SPARE_SETTLE),
        ] {
            let spare = attach(&mut reconciler, vol(id), 14);
            reconciler.add_spare(sid(), next, &spare).unwrap();
            let request = drop_request(vol(id), next);
            let shard_commits = commits(&store, Key::Shard(sid()));
            unknown_then_retry(&store, requests, arm, || {
                reconciler.retire_spare(sid(), &request)
            })
            .unwrap();
            assert_eq!(stored_volume(&store, vol(id)).state, VolumeState::Retired);
            assert_eq!(commits(&store, Key::Volume(vol(id))), 3, "{arm:?}: {id}");
            assert_eq!(stored(&store).1.spare, None, "{arm:?}: {id}");
            let repeated = requests == SPARE_SETTLE && commit;
            assert_eq!(
                commits(&store, Key::Shard(sid())),
                shard_commits + 2 + usize::from(repeated),
                "{arm:?}: {id}: one removal, and one settling write per attempt that commits it"
            );
        }
    }

    for requests in [SPARE_REWRITE, ACTIVE_MARK] {
        for arm in UNKNOWN {
            let (store, _) = spared();
            unknown_then_retry(&store, requests, arm, || {
                reconciler(&store).flip(&StandbyGate::qualified(), sid(), Target::of(&empty()))
            })
            .unwrap();
            assert_eq!(store.0.borrow().flips, vec![record().generation.get()]);
            let spare = commits(&store, Key::Volume(vol("vol-0b")));
            let mark = commits(&store, Key::Volume(active));
            let committed = committed(arm);
            let rewrites = match requests {
                SPARE_REWRITE => 1 + usize::from(committed),
                _ => 2,
            };
            assert_eq!((spare, mark), (2 + rewrites, 3), "{arm:?} at {requests}");
        }
    }
}

/// Shard creation refuses a record with a spare, a standby, a checkpoint, an attempt, a cut or an ancestry before any
/// request; a
/// replay finds its own record after the owner bumped `E` and makes no page write; a shard record that differs in
/// any field a creation sets, or a page another writer changed, refuses, and no shard record is created over such
/// a page.
#[test]
fn create_shard_adopts_only_its_own_records() {
    let store = Shared::new();
    let mut provisioner = provisioner(&store);
    for unclean in [
        record(),
        ShardRecord {
            standby: record().spare.map(|(_, host)| host),
            ..empty()
        },
        ShardRecord {
            checkpoint: Some(NamedCheckpoint::default()),
            ..empty()
        },
        ShardRecord {
            attempts: 1,
            ..empty()
        },
        ShardRecord { cut: 1, ..empty() },
        ShardRecord {
            ancestry: Ancestry::new(&[Suffix {
                session: crate::net::ownership::session_of(empty().generation.get() as u32, 2),
                start: 0,
                certified: 1,
                end: 1,
            }])
            .unwrap(),
            ..empty()
        },
    ] {
        store.schedule(Arm::Unavailable);
        assert_eq!(
            provisioner.create_shard(unclean).map(drop),
            Err(ReconcileError::Unclean)
        );
        assert_eq!(
            client(&store)
                .read::<ShardRecord>(Key::Shard(sid()))
                .map(drop),
            Err(StoreError::Unavailable),
            "the scheduled arm is left for the next request"
        );
    }
    assert_eq!(commits(&store, Key::Page(sid(), 0)), 0);

    provisioner.create_shard(empty()).unwrap();
    bump(&store);
    store.schedule(Arm::Pass);
    store.schedule(Arm::Unavailable);
    let replay = provisioner.create_shard(empty()).unwrap();
    assert_eq!(replay.value().attempts, 1);
    assert_eq!(
        client(&store)
            .read::<ShardRecord>(Key::Shard(sid()))
            .map(drop),
        Err(StoreError::Unavailable),
        "the replay made one read and no page write"
    );
    assert_eq!(commits(&store, Key::Page(sid(), 0)), 1);
    for other in [
        ShardRecord {
            active: vol("vol-0e"),
            ..empty()
        },
        ShardRecord {
            generation: ShardGeneration::new(4).unwrap(),
            ..empty()
        },
        ShardRecord {
            owner: host(15),
            ..empty()
        },
        ShardRecord {
            pages: NonZeroU16::new(3).unwrap(),
            ..empty()
        },
        ShardRecord {
            page_cap: NonZeroU32::new(8192).unwrap(),
            ..empty()
        },
        ShardRecord {
            namespace: crate::failover::records::Namespace::new([0x22; 16]).unwrap(),
            ..empty()
        },
    ] {
        assert_eq!(
            provisioner.create_shard(other).map(drop),
            Err(ReconcileError::Conflict),
            "{other:?}"
        );
    }
    assert_eq!(stored(&store).1.active, record().active);
    assert_eq!(commits(&store, Key::Shard(sid())), 2);

    for page in [
        CoveragePage {
            fence: 1,
            ..CoveragePage::default()
        },
        CoveragePage {
            entries: vec![1],
            ..CoveragePage::default()
        },
    ] {
        let store = Shared::new();
        client(&store).create(Key::Page(sid(), 1), page).unwrap();
        assert_eq!(
            self::provisioner(&store).create_shard(empty()).map(drop),
            Err(ReconcileError::Conflict)
        );
        assert_eq!(commits(&store, Key::Shard(sid())), 0);
    }
    let store = Shared::new();
    let mut host = client(&store);
    let read = host
        .create(Key::Page(sid(), 1), CoveragePage::default())
        .unwrap();
    host.replace(&read, CoveragePage::default()).unwrap();
    assert_eq!(
        self::provisioner(&store).create_shard(empty()).map(drop),
        Err(ReconcileError::Conflict),
        "an empty page past its first version was written"
    );
    assert_eq!(commits(&store, Key::Shard(sid())), 0);
}

/// A shard record another provisioner creates between this call's read and its create refuses the create on
/// its condition; the call returns that record when it records the same creation and refuses otherwise.
#[test]
fn create_shard_race_compares_the_winner() {
    for (winner, expected) in [
        (empty(), Ok(())),
        (
            ShardRecord {
                active: vol("vol-0e"),
                ..empty()
            },
            Err(ReconcileError::Conflict),
        ),
    ] {
        let store = Shared::new();
        let inner = store.clone();
        let hook = hooked(&store, Key::Shard(sid()), Point::BeforeWrite, move || {
            client(&inner).create(Key::Shard(sid()), winner).unwrap();
        });
        let mut provisioner = Reconciler::new(Client::open(hook, MemLog::default()).unwrap());
        assert_eq!(provisioner.create_shard(empty()).map(drop), expected);
        assert_eq!(commits(&store, Key::Shard(sid())), 1);
        assert_eq!(stored(&store).1, winner);
    }
}

/// Provisioning creates a provisioned record with no lineage, modification or event; a replay finds it, and a
/// record of another layout refuses and stays.
#[test]
fn provision_creates_one_provisioning_record() {
    let store = world();
    let mut reconciler = reconciler(&store);
    let id = vol("vol-0c");
    let expected = VolumeRecord {
        volume: id,
        state: VolumeState::Provisioning,
        source: CreationSource::Provisioned,
        lineage: Lineage::None,
        modification: None,
        layout: layout(),
        next: 0,
        forced: false,
        fence: 0,
        pairs: Vec::new(),
        events: Vec::new(),
    };
    assert_eq!(
        reconciler.provision(id, layout()).unwrap().value(),
        &expected
    );
    assert_eq!(stored_volume(&store, id), expected);
    assert_eq!(
        reconciler.provision(id, layout()).unwrap().value(),
        &expected
    );
    let other = Layout {
        units: 128,
        ..layout()
    };
    assert_eq!(
        reconciler.provision(id, other).map(drop),
        Err(ReconcileError::Conflict)
    );
    assert_eq!(stored_volume(&store, id), expected);
    assert_eq!(commits(&store, Key::Volume(id)), 1);
    let below = vol("vol-0d");
    let small = Layout {
        units: 9,
        ..layout()
    };
    assert_eq!(
        reconciler.provision(below, small).map(drop),
        Err(ReconcileError::Layout(LayoutRefusal::BelowFloor {
            units: 9,
            floor: 10
        }))
    );
    assert_eq!(commits(&store, Key::Volume(below)), 0);
}

/// An attach is recorded only on a provisioned record with no lineage or modification and no event; a replay
/// must match the host and the era, and every refusal leaves the record as it was.
#[test]
fn record_attach_refuses_another_record() {
    let store = world();
    let mut reconciler = reconciler(&store);
    let id = vol("vol-0c");
    reconciler.provision(id, layout()).unwrap();
    reconciler.record_attach(id, host(15), ERA).unwrap();
    let held = stored_volume(&store, id);
    for (holder, era) in [(SPARE, ERA), (15, ERA + 1)] {
        assert_eq!(
            reconciler.record_attach(id, host(holder), era).map(drop),
            Err(ReconcileError::Conflict),
            "host {holder}, era {era}"
        );
    }
    assert_eq!(stored_volume(&store, id), held);
    assert_eq!(commits(&store, Key::Volume(id)), 2);

    let mut other = client(&store);
    for (name, edit) in [
        (
            "vol-0d",
            VolumeRecord {
                source: CreationSource::Foreign,
                ..held.clone()
            },
        ),
        (
            "vol-0e",
            VolumeRecord {
                lineage: Lineage::Snapshot,
                ..held.clone()
            },
        ),
        (
            "vol-0f",
            VolumeRecord {
                modification: Some(Modification::InProgress),
                ..held.clone()
            },
        ),
        (
            "vol-0a1",
            VolumeRecord {
                layout: Layout {
                    units: 9,
                    ..layout()
                },
                ..held.clone()
            },
        ),
    ] {
        let record = VolumeRecord {
            volume: vol(name),
            state: VolumeState::Provisioning,
            next: 0,
            events: Vec::new(),
            ..edit
        };
        assert!(record.uncompacted(), "{name}");
        other
            .create(Key::Volume(vol(name)), record.clone())
            .unwrap();
        assert_eq!(
            reconciler.record_attach(vol(name), host(15), ERA).map(drop),
            Err(ReconcileError::Conflict),
            "{name}"
        );
        assert_eq!(stored_volume(&store, vol(name)), record);
    }
    let clean = VolumeRecord {
        volume: vol("vol-0a2"),
        state: VolumeState::Provisioning,
        next: 0,
        events: Vec::new(),
        ..held.clone()
    };
    let compacted = VolumeRecord {
        volume: vol("vol-0a3"),
        next: 1,
        ..clean.clone()
    };
    other
        .create(Key::Volume(compacted.volume), compacted.clone())
        .unwrap();
    assert_eq!(
        reconciler
            .record_attach(vol("vol-0a3"), host(15), ERA)
            .map(drop),
        Err(ReconcileError::Conflict),
        "a compacted history"
    );
    assert_eq!(stored_volume(&store, vol("vol-0a3")), compacted);
    assert_eq!(commits(&store, Key::Volume(vol("vol-0a3"))), 1);
    other.create(Key::Volume(clean.volume), clean).unwrap();
    assert!(
        reconciler
            .record_attach(vol("vol-0a2"), host(15), ERA)
            .is_ok(),
        "the same record without an edit takes its attach"
    );
    let recorded = stored_volume(&store, vol("vol-0a2"));
    assert!(
        reconciler
            .record_attach(vol("vol-0a2"), host(15), ERA)
            .is_ok(),
        "a replay over the recorded attach"
    );
    let mut bound = VolumeRecord {
        volume: vol("vol-0a4"),
        ..recorded.clone()
    };
    bound.events[0].instance = crate::failover::attachments::InstanceId::new("i-0000000f");
    assert!(bound.events[0].instance.is_some());
    other
        .create(Key::Volume(bound.volume), bound.clone())
        .unwrap();
    assert_eq!(
        reconciler
            .record_attach(vol("vol-0a4"), host(15), ERA)
            .map(drop),
        Err(ReconcileError::Conflict),
        "a replay over an attach that binds an instance"
    );
    assert_eq!(stored_volume(&store, vol("vol-0a4")), bound);
    assert_eq!(stored_volume(&store, vol("vol-0a2")), recorded);
    assert_eq!(commits(&store, Key::Volume(vol("vol-0a2"))), 2);
    let read = other.read::<VolumeRecord>(Key::Volume(id)).unwrap();
    let modified = VolumeRecord {
        modification: Some(Modification::Completed),
        ..held
    };
    other.replace(&read, modified).unwrap();
    assert_eq!(
        reconciler.record_attach(id, host(15), ERA).map(drop),
        Err(ReconcileError::Conflict),
        "a replay over a modified record"
    );
}

/// add_spare refuses the active volume, a modified volume and a volume with an attachment event besides its one
/// attach, and writes nothing.
#[test]
fn add_spare_refuses_a_used_volume() {
    let store = world();
    let mut reconciler = reconciler(&store);
    let target = Target::of(&empty());
    let active = reconciler
        .record_attach(record().active, host(OWNER), ERA)
        .unwrap();
    let modified = attach(&mut reconciler, vol("vol-0c"), SPARE);
    edit_volume(&store, vol("vol-0c"), |held| VolumeRecord {
        modification: Some(Modification::InProgress),
        ..held.clone()
    });
    let detached = attach(&mut reconciler, vol("vol-0d"), SPARE);
    edit_volume(&store, vol("vol-0d"), |held| {
        let mut next = held.clone();
        next.push(EventKind::Detach, host(SPARE), ERA);
        next
    });
    let before = commits(&store, Key::Shard(sid()));
    for (case, attached) in [
        ("active", &active),
        ("modified", &modified),
        ("detached", &detached),
    ] {
        assert_eq!(
            reconciler.add_spare(sid(), target, attached).map(drop),
            Err(ReconcileError::Conflict),
            "{case}"
        );
    }
    assert_eq!(commits(&store, Key::Shard(sid())), before);
    assert_eq!(stored(&store).1.spare, None);
}

/// `held` with its history compacted from the front and its one attach event kept one number later.
fn compact_history(held: &VolumeRecord) -> VolumeRecord {
    let mut next = held.clone();
    next.events[0].seq += 1;
    next.next += 1;
    next
}

/// `held` with a recorded pair of the spare host pinned to its first attach event.
fn register_pair(held: &VolumeRecord) -> VolumeRecord {
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
fn raise_fence(held: &VolumeRecord) -> VolumeRecord {
    VolumeRecord {
        fence: crate::net::ownership::session_of(1, 2),
        ..held.clone()
    }
}

/// A volume whose history was compacted, or that holds a recorded pair or a raised fence, is no longer in the state
/// provisioning wrote: an attach replay over any of them refuses, add_spare naming one with a compacted history, a
/// pair or a fence refuses, and neither writes.
#[test]
fn a_compacted_or_registered_volume_is_not_unused() {
    let store = world();
    let mut reconciler = reconciler(&store);
    let target = Target::of(&empty());
    let compacted = vol("vol-0c");
    let attach_event = AttachmentEvent {
        seq: 1,
        kind: EventKind::Attach,
        host: host(SPARE),
        era: ERA,
        instance: None,
    };
    client(&store)
        .create(
            Key::Volume(compacted),
            VolumeRecord {
                volume: compacted,
                state: VolumeState::Fresh,
                source: CreationSource::Provisioned,
                lineage: Lineage::None,
                modification: None,
                layout: layout(),
                next: 2,
                forced: false,
                fence: 0,
                pairs: Vec::new(),
                events: vec![attach_event],
            },
        )
        .unwrap();
    let registered = attach(&mut reconciler, vol("vol-0d"), SPARE);
    edit_volume(&store, vol("vol-0d"), register_pair);
    let fenced = attach(&mut reconciler, vol("vol-0e"), SPARE);
    edit_volume(&store, vol("vol-0e"), raise_fence);
    let trimmed = attach(&mut reconciler, vol("vol-0f"), SPARE);
    edit_volume(&store, vol("vol-0f"), compact_history);
    let volumes = [compacted, vol("vol-0d"), vol("vol-0e"), vol("vol-0f")];
    let before: Vec<_> = volumes
        .iter()
        .map(|id| commits(&store, Key::Volume(*id)))
        .collect();
    let shard_before = commits(&store, Key::Shard(sid()));
    for id in volumes {
        assert_eq!(
            reconciler.record_attach(id, host(SPARE), ERA).map(drop),
            Err(ReconcileError::Conflict),
            "an attach replay over {id:?}"
        );
    }
    for (case, attached) in [
        ("registered", &registered),
        ("fenced", &fenced),
        ("compacted", &trimmed),
    ] {
        assert_eq!(
            reconciler.add_spare(sid(), target, attached).map(drop),
            Err(ReconcileError::Conflict),
            "{case}"
        );
    }
    let after: Vec<_> = volumes
        .iter()
        .map(|id| commits(&store, Key::Volume(*id)))
        .collect();
    assert_eq!(after, before);
    assert_eq!(commits(&store, Key::Shard(sid())), shard_before);
    assert_eq!(stored(&store).1.spare, None);
}

/// A replay of a named spare writes nothing; a slot that holds another spare, or this volume under another
/// host, refuses.
#[test]
fn add_spare_replays_and_refuses_an_occupied_slot() {
    let (store, spare) = spared();
    let mut reconciler = reconciler(&store);
    let target = Target::of(&empty());
    let named = commits(&store, Key::Shard(sid()));
    assert_eq!(
        reconciler
            .add_spare(sid(), target, &spare)
            .unwrap()
            .value()
            .spare,
        Some((vol("vol-0b"), host(SPARE))),
    );
    let third = attach(&mut reconciler, vol("vol-0d"), SPARE);
    assert_eq!(
        reconciler.add_spare(sid(), target, &third).map(drop),
        Err(ReconcileError::Conflict),
        "another spare is named"
    );
    let mut other = client(&store);
    let read = other.read::<ShardRecord>(Key::Shard(sid())).unwrap();
    let rehosted = ShardRecord {
        spare: Some((vol("vol-0b"), host(14))),
        ..*read.value()
    };
    other.replace(&read, rehosted).unwrap();
    assert_eq!(
        reconciler.add_spare(sid(), target, &spare).map(drop),
        Err(ReconcileError::Conflict),
        "this volume under another host"
    );
    assert_eq!(commits(&store, Key::Shard(sid())), named + 1);
}

/// add_spare refuses a tenure the shard record no longer holds, after an owner change, an `E` bump or a flip, and
/// refuses the displaced active volume under the new tenure.
#[test]
fn add_spare_refuses_a_stale_tenure() {
    let store = world();
    let mut reconciler = reconciler(&store);
    let target = Target::of(&empty());
    let mine = attach(&mut reconciler, vol("vol-0b"), SPARE);
    let active = reconciler
        .record_attach(record().active, host(OWNER), ERA)
        .unwrap();
    let before = commits(&store, Key::Shard(sid()));
    for stale in [
        Target {
            owner: host(15),
            ..target
        },
        Target {
            attempts: 1,
            ..target
        },
    ] {
        assert_eq!(
            reconciler.add_spare(sid(), stale, &mine).map(drop),
            Err(ReconcileError::Stale),
            "{stale:?}"
        );
    }
    bump(&store);
    assert_eq!(
        reconciler.add_spare(sid(), target, &mine).map(drop),
        Err(ReconcileError::Stale),
        "the pre-bump tenure"
    );
    assert_eq!(commits(&store, Key::Shard(sid())), before + 1);

    let bumped = Target::of(&stored(&store).1);
    reconciler.add_spare(sid(), bumped, &mine).unwrap();
    reconciler
        .flip(&StandbyGate::qualified(), sid(), bumped)
        .unwrap();
    let flipped = commits(&store, Key::Shard(sid()));
    let next = Target::of(&stored(&store).1);
    let late = attach(&mut reconciler, vol("vol-0d"), SPARE);
    assert_eq!(
        reconciler.add_spare(sid(), bumped, &late).map(drop),
        Err(ReconcileError::Stale),
        "a retry from before the flip names no spare of the next generation"
    );
    assert_eq!(
        reconciler.add_spare(sid(), next, &active).map(drop),
        Err(ReconcileError::Conflict),
        "the displaced active volume"
    );
    assert_eq!(
        reconciler
            .record_attach(record().active, host(OWNER), ERA)
            .map(drop),
        Err(ReconcileError::Conflict)
    );
    assert_eq!(commits(&store, Key::Shard(sid())), flipped);
    assert_eq!(stored(&store).1.spare, None);
}

/// The flip marks a displaced active volume whose record never left provisioning, so a later attach and naming of
/// it refuse.
#[test]
fn flip_marks_a_provisioning_active_volume() {
    let store = Shared::new();
    provisioner(&store).create_shard(empty()).unwrap();
    let mut reconciler = reconciler(&store);
    reconciler.provision(record().active, layout()).unwrap();
    let spare = attach(&mut reconciler, vol("vol-0b"), SPARE);
    let target = Target::of(&empty());
    reconciler.add_spare(sid(), target, &spare).unwrap();
    reconciler
        .flip(&StandbyGate::qualified(), sid(), target)
        .unwrap();
    assert_eq!(
        stored_volume(&store, record().active).state,
        VolumeState::Active
    );
    assert_eq!(
        reconciler
            .record_attach(record().active, host(OWNER), ERA)
            .map(drop),
        Err(ReconcileError::Conflict)
    );
}

/// A flip refuses a spare whose volume record is retired, modified, holds another event, has a compacted history,
/// holds a recorded pair or a raised fence, before any write.
#[test]
fn flip_refuses_a_used_spare() {
    let edits: [fn(&VolumeRecord) -> VolumeRecord; 6] = [
        |held: &VolumeRecord| VolumeRecord {
            state: VolumeState::Retired,
            ..held.clone()
        },
        |held: &VolumeRecord| VolumeRecord {
            modification: Some(Modification::InProgress),
            ..held.clone()
        },
        |held: &VolumeRecord| {
            let mut next = held.clone();
            next.push(EventKind::Force, host(SPARE), ERA);
            next
        },
        compact_history,
        register_pair,
        raise_fence,
    ];
    for edit in edits {
        let (store, _) = spared();
        edit_volume(&store, vol("vol-0b"), edit);
        let shard = commits(&store, Key::Shard(sid()));
        let spare = commits(&store, Key::Volume(vol("vol-0b")));
        let active = commits(&store, Key::Volume(record().active));
        assert_eq!(
            reconciler(&store).flip(&StandbyGate::qualified(), sid(), Target::of(&empty())),
            Err(ReconcileError::Conflict)
        );
        assert_eq!(commits(&store, Key::Shard(sid())), shard);
        assert_eq!(commits(&store, Key::Volume(vol("vol-0b"))), spare);
        assert_eq!(commits(&store, Key::Volume(record().active)), active);
        assert!(store.0.borrow().flips.is_empty());
    }
}

#[test]
fn a_below_floor_spare_is_refused_at_attach_replay_and_flip() {
    let store = world();
    let id = vol("vol-0e");
    let below = VolumeRecord {
        volume: id,
        state: VolumeState::Fresh,
        source: CreationSource::Provisioned,
        lineage: Lineage::None,
        modification: None,
        layout: Layout {
            units: 9,
            ..layout()
        },
        next: 1,
        forced: false,
        fence: 0,
        pairs: Vec::new(),
        events: vec![AttachmentEvent {
            seq: 0,
            kind: EventKind::Attach,
            host: host(SPARE),
            era: ERA,
            instance: None,
        }],
    };
    let mut other = client(&store);
    other.create(Key::Volume(id), below.clone()).unwrap();
    let seeded = commits(&store, Key::Volume(id));
    let mut reconciler = reconciler(&store);
    assert_eq!(
        reconciler.record_attach(id, host(SPARE), ERA).map(drop),
        Err(ReconcileError::Conflict)
    );
    assert_eq!(commits(&store, Key::Volume(id)), seeded);
    let witness = attach(&mut self::reconciler(&world()), id, SPARE);
    let before = commits(&store, Key::Shard(sid()));
    assert_eq!(
        reconciler
            .add_spare(sid(), Target::of(&empty()), &witness)
            .map(drop),
        Err(ReconcileError::Conflict)
    );
    assert_eq!(commits(&store, Key::Shard(sid())), before);
    assert_eq!(stored(&store).1.spare, None);
    let read = other.read::<ShardRecord>(Key::Shard(sid())).unwrap();
    let named = ShardRecord {
        spare: Some((id, host(SPARE))),
        ..*read.value()
    };
    other.replace(&read, named).unwrap();
    let shard = commits(&store, Key::Shard(sid()));
    let active = commits(&store, Key::Volume(record().active));
    assert_eq!(
        reconciler.flip(&StandbyGate::qualified(), sid(), Target::of(&empty())),
        Err(ReconcileError::Conflict)
    );
    assert_eq!(commits(&store, Key::Shard(sid())), shard);
    assert_eq!(commits(&store, Key::Volume(record().active)), active);
    assert_eq!(commits(&store, Key::Volume(id)), seeded);
    assert_eq!(stored_volume(&store, id), below);
    assert!(store.0.borrow().flips.is_empty());
}

/// Retirement refuses a volume the shard record names active, or spare before its removal, and writes nothing;
/// a spare's removal admits only its own tenure and the spare role.
#[test]
fn retire_refuses_a_named_volume() {
    let (store, _) = spared();
    let mut reconciler = reconciler(&store);
    let shard = commits(&store, Key::Shard(sid()));
    for id in [record().active, vol("vol-0b")] {
        let held = stored_volume(&store, id);
        assert_eq!(
            reconciler.retire(sid(), id).map(drop),
            Err(ReconcileError::Named)
        );
        assert_eq!(stored_volume(&store, id), held);
    }
    let target = Target::of(&empty());
    assert_eq!(
        reconciler
            .retire_spare(sid(), &drop_request(record().active, target))
            .map(drop),
        Err(ReconcileError::Named)
    );
    let active = Retirement::new(
        vol("vol-0b"),
        Role::Active,
        target,
        Trigger::Attachment(Mismatch::Duplicate),
    )
    .unwrap();
    assert_eq!(
        reconciler.retire_spare(sid(), &active).map(drop),
        Err(ReconcileError::Conflict)
    );
    for stale in [
        Target {
            attempts: 1,
            ..target
        },
        Target {
            owner: host(15),
            ..target
        },
    ] {
        assert_eq!(
            reconciler
                .retire_spare(sid(), &drop_request(vol("vol-0b"), stale))
                .map(drop),
            Err(ReconcileError::Stale)
        );
    }
    assert_eq!(commits(&store, Key::Shard(sid())), shard);
    assert_eq!(
        stored_volume(&store, vol("vol-0b")).state,
        VolumeState::Fresh
    );
}

/// `retire_spare` returns `ReconcileError::Stale` before any write when the request's `(g, owner, E)` differs from
/// the shard record's. The receipt that records the spare keeps its version, so a concurrent step's receipt write
/// still matches the receipt version it read.
#[test]
fn a_stale_spare_removal_leaves_the_receipt_that_records_the_spare() {
    let store = world();
    receipt_after(&store, 0);
    let made = create(&store, &mut Provisioner::default())
        .unwrap()
        .value()
        .volume;
    let attached = reconciler(&store)
        .record_attach(made, host(SPARE), ERA)
        .unwrap();
    let target = Target::of(&empty());
    reconciler(&store)
        .add_spare(sid(), target, &attached)
        .unwrap();
    assert_eq!(stored_receipt(&store).phase, Phase::Created(made));
    let keys = [
        Key::Replacement(sid()),
        Key::Shard(sid()),
        Key::Volume(made),
    ];
    let held = keys.map(|key| commits(&store, key));
    for stale in [
        Target {
            attempts: 1,
            ..target
        },
        Target {
            owner: host(15),
            ..target
        },
    ] {
        assert_eq!(
            reconciler(&store)
                .retire_spare(sid(), &drop_request(made, stale))
                .map(drop),
            Err(ReconcileError::Stale)
        );
    }
    assert_eq!(
        keys.map(|key| commits(&store, key)),
        held,
        "a stale removal commits no receipt, shard or volume write"
    );
}

/// A deleted volume takes no retired-state write; both retirement steps make the settling shard write and
/// return the witness. Retiring the displaced active volume keeps the next generation's spare, and both writes
/// keep a checkpoint the host named.
#[test]
fn retirement_keeps_what_it_does_not_retire() {
    let (store, _) = spared();
    let mut reconciler = reconciler(&store);
    reconciler
        .flip(&StandbyGate::qualified(), sid(), Target::of(&empty()))
        .unwrap();
    let next = Target::of(&stored(&store).1);
    let mut owner = client(&store);
    let read = owner.read::<ShardRecord>(Key::Shard(sid())).unwrap();
    let named = NamedCheckpoint {
        slot: 1,
        session: (4 << 32) | 2,
        capture: 1,
        units: 4,
    };
    let published = ShardRecord {
        checkpoint: Some(named),
        ..*read.value()
    };
    owner.replace(&read, published).unwrap();
    let replacement = attach(&mut reconciler, vol("vol-0d"), 14);
    reconciler.add_spare(sid(), next, &replacement).unwrap();
    assert_eq!(
        stored(&store).1.checkpoint,
        Some(named),
        "add_spare keeps ck"
    );
    reconciler.retire(sid(), record().active).unwrap();
    let after = stored(&store).1;
    assert_eq!(after.spare, Some((vol("vol-0d"), host(14))));
    assert_eq!(after.checkpoint, Some(named));

    for (id, spare) in [("vol-0e", false), ("vol-0f", true)] {
        attach(&mut reconciler, vol(id), 15);
        edit_volume(&store, vol(id), |held| VolumeRecord {
            state: VolumeState::Deleted,
            ..held.clone()
        });
        let volume = commits(&store, Key::Volume(vol(id)));
        let shard = commits(&store, Key::Shard(sid()));
        if spare {
            reconciler
                .retire_spare(sid(), &drop_request(vol(id), next))
                .unwrap();
        } else {
            reconciler.retire(sid(), vol(id)).unwrap();
        }
        assert_eq!(commits(&store, Key::Volume(vol(id))), volume, "{id}");
        assert_eq!(commits(&store, Key::Shard(sid())), shard + 1, "{id}");
        assert_eq!(stored(&store).1.checkpoint, Some(named), "{id}");
    }
    let request = drop_request(vol("vol-0d"), next);
    reconciler.retire_spare(sid(), &request).unwrap();
    assert_eq!(stored(&store).1.spare, None);
    assert_eq!(stored(&store).1.checkpoint, Some(named));
}

/// A spare-naming write parked across a retirement never commits after the retirement's witness: the witness's
/// shard write raised the version the parked write conditions on.
#[test]
fn held_spare_write_never_outlives_retired_witness() {
    let store = world();
    let mut reconciler = reconciler(&store);
    let spare = attach(&mut reconciler, vol("vol-0b"), SPARE);
    park(&store, NAMING_WRITE, Arm::Hold);
    assert_eq!(
        reconciler
            .add_spare(sid(), Target::of(&empty()), &spare)
            .map(drop),
        Err(ReconcileError::Store(StoreError::Unknown))
    );
    self::reconciler(&store)
        .retire(sid(), vol("vol-0b"))
        .unwrap();
    assert_eq!(
        store.release(),
        vec![Outcome::NotCommitted(Refusal::Condition)]
    );
    assert_eq!(stored(&store).1.spare, None);
    assert_eq!(
        reconciler
            .add_spare(sid(), Target::of(&empty()), &spare)
            .map(drop),
        Err(ReconcileError::Conflict)
    );
}

/// add_spare reads the shard record before the volume record: a retirement that completes between the two reads
/// raises the shard version, so the naming write refuses on its condition and the shard names no spare.
#[test]
fn add_spare_reads_the_shard_before_the_volume() {
    let store = world();
    let spare = attach(&mut reconciler(&store), vol("vol-0b"), SPARE);
    let inner = store.clone();
    let hook = hooked(
        &store,
        Key::Volume(vol("vol-0b")),
        Point::AfterRead,
        move || {
            reconciler(&inner).retire(sid(), vol("vol-0b")).unwrap();
        },
    );
    let mut racing = Reconciler::new(Client::open(AsReconciler(hook), MemLog::default()).unwrap());
    assert_eq!(
        racing
            .add_spare(sid(), Target::of(&empty()), &spare)
            .map(drop),
        Err(ReconcileError::Store(StoreError::Refused(
            Refusal::Condition
        )))
    );
    assert_eq!(stored(&store).1.spare, None);
    assert_eq!(
        stored_volume(&store, vol("vol-0b")).state,
        VolumeState::Retired
    );
}

/// A retired-state write parked while the volume is named spare commits on a named volume; the flip then refuses
/// the spare, add_spare refuses it, and the retirement's retry clears the spare before it returns the witness.
/// Parked across a flip that activated the volume, the write refuses on its condition, since the flip raised the
/// volume's version, and the volume stays fresh and active.
#[test]
fn held_retired_write_is_settled_by_its_retry() {
    for flip in [false, true] {
        let store = world();
        let mut reconciler = reconciler(&store);
        let spare = attach(&mut reconciler, vol("vol-0b"), SPARE);
        park(&store, RETIRE_WRITE, Arm::Hold);
        assert_eq!(
            reconciler.retire(sid(), vol("vol-0b")).map(drop),
            Err(ReconcileError::Store(StoreError::Unknown))
        );
        let mut other = self::reconciler(&store);
        let target = Target::of(&empty());
        other.add_spare(sid(), target, &spare).unwrap();
        if flip {
            other
                .flip(&StandbyGate::qualified(), sid(), target)
                .unwrap();
            assert_eq!(
                store.release(),
                vec![Outcome::NotCommitted(Refusal::Condition)]
            );
            assert_eq!(
                stored_volume(&store, vol("vol-0b")).state,
                VolumeState::Fresh
            );
            assert_eq!(
                reconciler.retire(sid(), vol("vol-0b")).map(drop),
                Err(ReconcileError::Named)
            );
            assert_eq!(stored(&store).1.active, vol("vol-0b"));
            assert_eq!(
                stored_volume(&store, vol("vol-0b")).state,
                VolumeState::Fresh
            );
            continue;
        }
        assert!(matches!(store.release()[..], [Outcome::Committed(_)]));
        assert_eq!(
            stored_volume(&store, vol("vol-0b")).state,
            VolumeState::Retired
        );
        let shard = commits(&store, Key::Shard(sid()));
        assert_eq!(
            other.flip(&StandbyGate::qualified(), sid(), target),
            Err(ReconcileError::Conflict),
            "a retired spare is never activated"
        );
        assert_eq!(
            other.add_spare(sid(), target, &spare).map(drop),
            Err(ReconcileError::Conflict),
            "a retired named spare is not confirmed"
        );
        assert_eq!(commits(&store, Key::Shard(sid())), shard);
        reconciler.retire(sid(), vol("vol-0b")).unwrap();
        assert_eq!(stored(&store).1.spare, None);
    }
}

/// A spare's removal ends a pending naming of it: a stale retry that names the spare again between the removal
/// and the retired state is cleared by the removal's retry, even after the owner's `E` bump, and no later step
/// names the volume.
#[test]
fn retire_spare_ends_a_pending_add_spare() {
    for bumped in [false, true] {
        let (store, spare) = spared();
        let mut reconciler = reconciler(&store);
        let target = Target::of(&empty());
        let request = drop_request(vol("vol-0b"), target);
        park(&store, SPARE_RETIRE_WRITE, Arm::Hold);
        assert_eq!(
            reconciler.retire_spare(sid(), &request).map(drop),
            Err(ReconcileError::Store(StoreError::Unknown))
        );
        assert_eq!(stored(&store).1.spare, None);
        self::reconciler(&store)
            .add_spare(sid(), target, &spare)
            .unwrap();
        if bumped {
            bump(&store);
        }
        assert!(matches!(store.release()[..], [Outcome::Committed(_)]));
        reconciler.retire_spare(sid(), &request).unwrap();
        assert_eq!(stored(&store).1.spare, None, "bumped {bumped}");
        assert_eq!(
            reconciler
                .add_spare(sid(), Target::of(&stored(&store).1), &spare)
                .map(drop),
            Err(ReconcileError::Conflict)
        );
        assert_eq!(
            stored_volume(&store, vol("vol-0b")).state,
            VolumeState::Retired
        );
    }
}

/// A write parked while another writer moves the record is refused on its condition when released, which
/// shows only that the record moved; the step's retry on a fresh read converges. A retry whose first read is
/// stale refuses on its condition with nothing written, and the next retry finds the committed write.
#[test]
fn refused_retry_converges_on_a_fresh_read() {
    let store = world();
    let mut reconciler = reconciler(&store);
    let spare = attach(&mut reconciler, vol("vol-0b"), SPARE);
    let target = Target::of(&empty());
    park(&store, NAMING_WRITE, Arm::Hold);
    assert_eq!(
        reconciler.add_spare(sid(), target, &spare).map(drop),
        Err(ReconcileError::Store(StoreError::Unknown))
    );
    bump(&store);
    assert_eq!(
        store.release(),
        vec![Outcome::NotCommitted(Refusal::Condition)]
    );
    assert_eq!(
        reconciler.add_spare(sid(), target, &spare).map(drop),
        Err(ReconcileError::Stale)
    );
    let bumped = Target::of(&stored(&store).1);
    park(&store, NAMING_WRITE, Arm::Timeout { commit: true });
    assert_eq!(
        reconciler.add_spare(sid(), bumped, &spare).map(drop),
        Err(ReconcileError::Store(StoreError::Unknown))
    );
    let named = commits(&store, Key::Shard(sid()));
    store.schedule(Arm::StaleRead);
    assert_eq!(
        reconciler.add_spare(sid(), bumped, &spare).map(drop),
        Err(ReconcileError::Store(StoreError::Refused(
            Refusal::Condition
        ))),
        "the stale read shows no spare, and the naming write meets the committed one"
    );
    assert_eq!(commits(&store, Key::Shard(sid())), named);
    reconciler.add_spare(sid(), bumped, &spare).unwrap();
    assert_eq!(commits(&store, Key::Shard(sid())), named);
    reconciler
        .flip(&StandbyGate::qualified(), sid(), bumped)
        .unwrap();

    park(&store, RETIRE_SETTLE, Arm::Hold);
    assert_eq!(
        reconciler.retire(sid(), record().active).map(drop),
        Err(ReconcileError::Store(StoreError::Unknown))
    );
    bump(&store);
    assert_eq!(
        store.release(),
        vec![Outcome::NotCommitted(Refusal::Condition)]
    );
    let shard = commits(&store, Key::Shard(sid()));
    reconciler.retire(sid(), record().active).unwrap();
    assert_eq!(
        commits(&store, Key::Shard(sid())),
        shard + 1,
        "the settling write"
    );
    assert_eq!(
        stored_volume(&store, record().active).state,
        VolumeState::Retired
    );
}

/// A flip refuses a spare the shard record names under another host than the one its volume record attached.
#[test]
fn flip_refuses_a_spare_under_another_host() {
    let (store, _) = spared();
    let mut other = client(&store);
    let read = other.read::<ShardRecord>(Key::Shard(sid())).unwrap();
    let rehosted = ShardRecord {
        spare: Some((vol("vol-0b"), host(14))),
        ..*read.value()
    };
    other.replace(&read, rehosted).unwrap();
    let shard = commits(&store, Key::Shard(sid()));
    let spare = commits(&store, Key::Volume(vol("vol-0b")));
    let active = commits(&store, Key::Volume(record().active));
    assert_eq!(
        reconciler(&store).flip(&StandbyGate::qualified(), sid(), Target::of(&empty())),
        Err(ReconcileError::Conflict)
    );
    assert_eq!(commits(&store, Key::Shard(sid())), shard);
    assert_eq!(commits(&store, Key::Volume(vol("vol-0b"))), spare);
    assert_eq!(commits(&store, Key::Volume(record().active)), active);
    assert!(store.0.borrow().flips.is_empty());
}

/// A naming write that lands after a retirement step's shard read and before its settling write makes the settling
/// write refuse on its condition, and the step returns that refusal while the shard record names the volume spare.
/// The retry succeeds and clears the spare while the volume remains retired.
#[test]
fn naming_after_the_shard_read_refuses_the_settling_write() {
    for spare_step in [false, true] {
        let id = vol("vol-0b");
        let (store, attached) = if spare_step {
            spared()
        } else {
            let store = world();
            let attached = attach(&mut reconciler(&store), id, SPARE);
            (store, attached)
        };
        let target = Target::of(&empty());
        let inner = store.clone();
        let hook = hooked(&store, Key::Volume(id), Point::BeforeWrite, move || {
            reconciler(&inner)
                .add_spare(sid(), target, &attached)
                .unwrap();
        });
        let mut racing =
            Reconciler::new(Client::open(AsReconciler(hook), MemLog::default()).unwrap());
        let request = drop_request(id, target);
        let mut step = || {
            if spare_step {
                racing.retire_spare(sid(), &request)
            } else {
                racing.retire(sid(), id)
            }
        };
        assert_eq!(
            step().map(drop),
            Err(ReconcileError::Store(StoreError::Refused(
                Refusal::Condition
            ))),
            "retire_spare {spare_step}"
        );
        assert_eq!(stored(&store).1.spare, Some((id, host(SPARE))));
        assert_eq!(stored_volume(&store, id).state, VolumeState::Retired);
        step().unwrap();
        assert_eq!(stored(&store).1.spare, None, "retire_spare {spare_step}");
        assert_eq!(stored_volume(&store, id).state, VolumeState::Retired);
    }
}

/// Both retirement steps read the volume record before the shard record: a naming and a flip that complete
/// between the two reads raise the volume's version, so the retired-state write refuses on its condition and the
/// activated volume stays fresh.
#[test]
fn retirement_reads_the_volume_before_the_shard() {
    for spare_step in [false, true] {
        let store = world();
        let attached = attach(&mut reconciler(&store), vol("vol-0b"), SPARE);
        let inner = store.clone();
        let hook = hooked(&store, Key::Shard(sid()), Point::AfterRead, move || {
            let mut other = reconciler(&inner);
            other
                .add_spare(sid(), Target::of(&empty()), &attached)
                .unwrap();
            other
                .flip(&StandbyGate::qualified(), sid(), Target::of(&empty()))
                .unwrap();
        });
        let mut racing =
            Reconciler::new(Client::open(AsReconciler(hook), MemLog::default()).unwrap());
        let result = if spare_step {
            racing
                .retire_spare(sid(), &drop_request(vol("vol-0b"), Target::of(&empty())))
                .map(drop)
        } else {
            racing.retire(sid(), vol("vol-0b")).map(drop)
        };
        assert_eq!(
            result,
            Err(ReconcileError::Store(StoreError::Refused(
                Refusal::Condition
            ))),
            "retire_spare {spare_step}"
        );
        assert_eq!(stored(&store).1.active, vol("vol-0b"));
        assert_eq!(
            stored_volume(&store, vol("vol-0b")).state,
            VolumeState::Fresh
        );
    }
}

/// A retry whose first read is stale, after a committed unknown write, refuses on its condition with nothing
/// written to the record the stale read showed, and the next retry finds the committed write.
#[test]
fn stale_first_read_refuses_and_a_fresh_retry_converges() {
    let store = world();
    let mut reconciler = reconciler(&store);
    let id = vol("vol-0b");
    reconciler.provision(id, layout()).unwrap();
    park(&store, ATTACH_WRITE, Arm::Timeout { commit: true });
    assert_eq!(
        reconciler.record_attach(id, host(SPARE), ERA).map(drop),
        Err(ReconcileError::Store(StoreError::Unknown))
    );
    store.schedule(Arm::StaleRead);
    assert_eq!(
        reconciler.record_attach(id, host(SPARE), ERA).map(drop),
        Err(ReconcileError::Store(StoreError::Refused(
            Refusal::Condition
        )))
    );
    assert_eq!(commits(&store, Key::Volume(id)), 2);
    let spare = reconciler.record_attach(id, host(SPARE), ERA).unwrap();
    assert_eq!(commits(&store, Key::Volume(id)), 2);

    let target = Target::of(&empty());
    reconciler.add_spare(sid(), target, &spare).unwrap();
    park(&store, FLIP_WRITE, Arm::Timeout { commit: true });
    assert_eq!(
        reconciler.flip(&StandbyGate::qualified(), sid(), target),
        Err(ReconcileError::Store(StoreError::Unknown))
    );
    let shard = commits(&store, Key::Shard(sid()));
    store.schedule(Arm::StaleRead);
    assert_eq!(
        reconciler.flip(&StandbyGate::qualified(), sid(), target),
        Err(ReconcileError::Store(StoreError::Refused(
            Refusal::Condition
        )))
    );
    assert_eq!(commits(&store, Key::Shard(sid())), shard);
    assert_eq!(
        reconciler.flip(&StandbyGate::qualified(), sid(), target),
        Ok(Flip::Past)
    );
    assert_eq!(store.0.borrow().flips, vec![record().generation.get()]);

    park(&store, RETIRE_WRITE, Arm::Timeout { commit: true });
    assert_eq!(
        reconciler.retire(sid(), record().active).map(drop),
        Err(ReconcileError::Store(StoreError::Unknown))
    );
    let volume = commits(&store, Key::Volume(record().active));
    store.schedule(Arm::StaleRead);
    assert_eq!(
        reconciler.retire(sid(), record().active).map(drop),
        Err(ReconcileError::Store(StoreError::Refused(
            Refusal::Condition
        )))
    );
    assert_eq!(commits(&store, Key::Volume(record().active)), volume);
    reconciler.retire(sid(), record().active).unwrap();
    assert_eq!(commits(&store, Key::Volume(record().active)), volume);
    assert_eq!(
        stored_volume(&store, record().active).state,
        VolumeState::Retired
    );
}

/// The long-running reconciler's principal writes shard and volume records and no coverage page: no create of
/// a page, empty or not, and no replacement of one, entries, fence, saturation or version alone. The
/// provisioning principal creates the shard and its pages, retries a creation, and is denied every volume record.
/// The unrestricted store stands in for a host's principal, which fences a page. The keys carry the prefixes the
/// table policy's conditions name.
#[test]
fn principal_restrictions() {
    assert_eq!(dynamo::text(&Key::Shard(sid())), "shard#7");
    assert_eq!(dynamo::text(&Key::Volume(vol("vol-0c"))), "volume#vol-0c");
    assert_eq!(dynamo::text(&Key::Page(sid(), 0)), "page#7#0");
    assert_eq!(dynamo::text(&Key::Standbys(Zone(3))), "standbys#3");
    assert_eq!(dynamo::text(&Key::Replacement(sid())), "replacement#7");

    let store = Shared::new();
    let mut provisioner = provisioner(&store);
    provisioner.create_shard(empty()).unwrap();
    provisioner.create_shard(empty()).unwrap();
    let mut shards = Client::open(AsProvisioner(store.clone()), MemLog::default()).unwrap();
    for key in [Key::Standbys(ZONE), Key::Replacement(sid())] {
        assert_eq!(
            shards.read::<Census>(key).map(drop),
            Err(StoreError::Unavailable),
            "{key:?}"
        );
    }
    assert_eq!(
        shards
            .create(Key::Standbys(ZONE), Census::empty(ZONE))
            .map(drop),
        Err(StoreError::Refused(Refusal::Denied))
    );
    assert_eq!(
        shards
            .create(
                Key::Replacement(sid()),
                crate::failover::loss::tests::receipt()
            )
            .map(drop),
        Err(StoreError::Refused(Refusal::Denied))
    );
    assert_eq!(
        (
            commits(&store, Key::Standbys(ZONE)),
            commits(&store, Key::Replacement(sid()))
        ),
        (0, 0)
    );
    let mut writer = Client::open(AsReconciler(store.clone()), MemLog::default()).unwrap();
    let other_shard = crate::net::ownership::Shard::new(sid().get() + 1).unwrap();
    assert_eq!(
        writer
            .create(Key::Standbys(Zone(9)), Census::empty(ZONE))
            .map(drop),
        Err(StoreError::Codec(
            crate::failover::records::CodecError::Field
        )),
        "a census under another zone's key"
    );
    assert_eq!(
        writer
            .create(
                Key::Replacement(other_shard),
                crate::failover::loss::tests::receipt()
            )
            .map(drop),
        Err(StoreError::Codec(
            crate::failover::records::CodecError::Field
        )),
        "a receipt under another shard's key"
    );
    assert_eq!(
        (
            commits(&store, Key::Standbys(Zone(9))),
            commits(&store, Key::Replacement(other_shard))
        ),
        (0, 0)
    );
    assert_eq!(
        provisioner.provision(vol("vol-0c"), layout()).map(drop),
        Err(ReconcileError::Store(StoreError::Refused(Refusal::Denied)))
    );
    assert_eq!(commits(&store, Key::Volume(vol("vol-0c"))), 0);

    let fresh = Shared::new();
    assert_eq!(
        reconciler(&fresh).create_shard(empty()).map(drop),
        Err(ReconcileError::Store(StoreError::Refused(Refusal::Denied))),
        "the long-running principal creates no shard's pages"
    );
    assert_eq!(commits(&fresh, Key::Page(sid(), 0)), 0);

    let mut reconciler = reconciler(&store);
    attach(&mut reconciler, record().active, OWNER);
    let spare = attach(&mut reconciler, vol("vol-0c"), 13);
    let target = Target::of(&empty());
    reconciler.add_spare(sid(), target, &spare).unwrap();
    assert!(matches!(
        reconciler.flip(&StandbyGate::qualified(), sid(), target),
        Ok(Flip::Flipped(_))
    ));
    reconciler.retire(sid(), record().active).unwrap();
    let mut principal = Client::open(AsReconciler(store.clone()), MemLog::default()).unwrap();
    let absent = Key::Page(sid(), record().pages.get());
    for page in [
        CoveragePage::default(),
        CoveragePage {
            entries: vec![1],
            ..CoveragePage::default()
        },
        CoveragePage {
            fence: 1,
            ..CoveragePage::default()
        },
        CoveragePage {
            saturated: true,
            ..CoveragePage::default()
        },
    ] {
        assert_eq!(
            principal.create(absent, page).map(drop),
            Err(StoreError::Refused(Refusal::Denied))
        );
    }
    assert_eq!(commits(&store, absent), 0);
    let key = Key::Page(sid(), 0);
    let read = principal.read::<CoveragePage>(key).unwrap();
    for next in [
        CoveragePage {
            entries: vec![1, 2, 3],
            ..CoveragePage::default()
        },
        CoveragePage {
            fence: (3 << 32) | 2,
            ..CoveragePage::default()
        },
        CoveragePage {
            saturated: true,
            ..CoveragePage::default()
        },
        CoveragePage::default(),
    ] {
        assert_eq!(
            principal.replace(&read, next),
            Err(StoreError::Refused(Refusal::Denied))
        );
    }
    assert_eq!(commits(&store, key), 1, "the page holds only its create");
    let mut host = client(&store);
    let read = host.read::<CoveragePage>(key).unwrap();
    let fenced = CoveragePage {
        fence: (3 << 32) | 2,
        ..CoveragePage::default()
    };
    assert_eq!(
        host.replace(&read, fenced.clone()).unwrap().value(),
        &fenced
    );
}

fn wide() -> crate::failover::bounds::Bounds {
    crate::storage::gate_fixture::bounds_of(crate::storage::gate_fixture::limits())
}

/// The standby's local record on the active volume, bound to `instance`, carrying `pair`.
fn standby_record(instance: &str, pair: Pair) -> crate::failover::record::LocalRecord {
    let binding = crate::failover::record::Binding {
        instance: instance.to_owned(),
        volume: record().active.as_str().to_owned(),
        attachment: "vol-0a-attach".to_owned(),
    };
    crate::failover::record::LocalRecord::fresh(binding, pair.key, || Some(pair.exhid.bytes()))
        .unwrap()
}

/// `N_reg = n_reg` with the fixture's other bounds.
fn capped(n_reg: u32) -> crate::failover::bounds::Bounds {
    crate::failover::bounds::Bounds::new(n_reg, 1, u64::MAX, 100, 100, 0).unwrap()
}

fn enrolled_world() -> Shared {
    let store = world();
    edit_volume(&store, record().active, |held| {
        held.enroll(
            host(OWNER),
            crate::failover::evidence_tests::pair(1, 1, 1),
            &wide(),
        )
        .unwrap()
        .unwrap()
    });
    store
}

fn activated() -> Shared {
    let store = enrolled_world();
    fence_page(&store, 0, (record().generation.get() << 32) | 2);
    store
}

#[test]
fn a_page_zero_fence_whose_low_word_is_no_activated_epoch_records_no_standby() {
    let gate = StandbyGate::qualified();
    let active = record().active;
    let generation = record().generation.get();
    for low in [2, 1, 0xFFFF_FFFE] {
        let store = activated();
        plant_fence(&store, (generation << 32) | low);
        bump(&store);
        let before = commits(&store, Key::Volume(active));
        let recorded = reconciler(&store).record_standby(
            &gate,
            sid(),
            active,
            host(SPARE),
            ERA,
            &wide(),
            &crate::failover::sim::binding(host(SPARE)),
        );
        match low {
            2 => assert!(recorded.is_ok(), "{recorded:?}"),
            _ => {
                assert_eq!(
                    recorded.map(drop),
                    Err(ReconcileError::Conflict),
                    "{low:#x}"
                );
                assert_eq!(commits(&store, Key::Volume(active)), before);
            }
        }
    }
}

fn plant_fence(store: &Shared, fence: u64) {
    use crate::storage::store::{Store, Tracked, Write};
    let key = Key::Page(sid(), 0);
    let read = client(store).read::<CoveragePage>(key).unwrap();
    let page = CoveragePage {
        fence,
        ..read.value().clone()
    };
    let item = store.0.borrow().current(&key).cloned().unwrap();
    let write = Write::Exact {
        expect: item.version,
        value: page.encoded(&key).unwrap(),
    };
    let written = store.clone().write(&key, &write);
    assert!(matches!(written, Outcome::Committed(_)), "{written:?}");
}

fn fenced_world() -> Shared {
    let store = world();
    fence_page(&store, 0, (record().generation.get() << 32) | 2);
    store
}

fn fence_page(store: &Shared, page: u16, fence: u64) {
    let mut owner = client(store);
    let read = owner.read::<CoveragePage>(Key::Page(sid(), page)).unwrap();
    let next = CoveragePage {
        fence,
        ..read.value().clone()
    };
    owner.replace(&read, next).unwrap();
}

/// OWNER-FENCED-BEFORE-STANDBY: standby admission requires a coverage-page fence matching the shard's generation,
/// including after an uncommitted flip, owner enrollment, and the owner's `E` bump.
#[test]
fn a_flip_that_did_not_commit_admits_no_standby_before_the_owners_fence() {
    use crate::failover::poll::Holder;
    use crate::failover::reconcile::{StandbyRefusal, enroll_standby};
    let gate = StandbyGate::qualified();
    let active = record().active;
    let (store, _) = spared();
    let target = Target::of(&stored(&store).1);
    park(&store, FLIP_WRITE, Arm::Timeout { commit: false });
    assert_eq!(
        reconciler(&store).flip(&gate, sid(), target),
        Err(ReconcileError::Store(StoreError::Unknown))
    );
    assert_eq!(
        stored_volume(&store, active).state,
        VolumeState::Active,
        "the flip marked the displaced volume active before its shard write"
    );
    edit_volume(&store, active, |held| {
        held.enroll(
            host(OWNER),
            crate::failover::evidence_tests::pair(1, 1, 1),
            &wide(),
        )
        .unwrap()
        .unwrap()
    });
    bump(&store);
    assert_eq!(
        reconciler(&store).flip(&gate, sid(), target),
        Err(ReconcileError::Stale),
        "the owner's bump keeps the volume active"
    );
    let standby = Holder {
        volume: active,
        host: host(SPARE + 1),
        instance: crate::failover::sim::instance_of_host(host(SPARE + 1)),
    };
    let refuses = |store: &Shared, why: &str| {
        let before = commits(store, Key::Volume(active));
        assert_eq!(
            reconciler(store).record_standby(
                &gate,
                sid(),
                active,
                standby.host,
                2,
                &wide(),
                &crate::failover::sim::binding(standby.host)
            ),
            Err(ReconcileError::Conflict),
            "{why}"
        );
        assert_eq!(
            enroll_standby(&gate, sid(), &standby, &wide(), &mut client(store), |_| {
                panic!("the standby persists nothing before the owner's fence")
            }),
            Err(StandbyRefusal::Tenure),
            "{why}"
        );
        assert_eq!(commits(store, Key::Volume(active)), before, "{why}");
    };
    refuses(&store, "no page fenced");
    fence_page(&store, 0, (2 << 32) | 2);
    refuses(&store, "page 0 fenced in an earlier generation");
    fence_page(&store, 0, (3 << 32) | 2);
    let before = commits(&store, Key::Volume(active));
    reconciler(&store)
        .record_standby(
            &gate,
            sid(),
            active,
            standby.host,
            2,
            &wide(),
            &crate::failover::sim::binding(standby.host),
        )
        .unwrap();
    assert_eq!(commits(&store, Key::Volume(active)), before + 1);
}

/// Under the gate, a standby's attach on the shard's active volume appends one attach event at `E > 0`; a replay
/// writes nothing and another era conflicts; `E = 0`, the owner's host and a volume other than the active one
/// conflict before any write.
#[test]
fn a_standby_attach_records_once_under_the_gate() {
    let gate = StandbyGate::qualified();
    let store = activated();
    let active = record().active;
    let mut reconciler = reconciler(&store);
    attach(&mut reconciler, vol("vol-0b"), SPARE + 1);
    for (name, volume, holder) in [
        ("E = 0", active, SPARE),
        ("owner host", active, OWNER),
        ("another volume", vol("vol-0b"), SPARE),
    ] {
        if name == "owner host" {
            bump(&store);
        }
        let before = commits(&store, Key::Volume(volume));
        assert_eq!(
            reconciler.record_standby(
                &gate,
                sid(),
                volume,
                host(holder),
                2,
                &wide(),
                &crate::failover::sim::binding(host(holder))
            ),
            Err(ReconcileError::Conflict),
            "{name}"
        );
        assert_eq!(commits(&store, Key::Volume(volume)), before, "{name}");
    }
    let before = commits(&store, Key::Volume(active));
    let recorded = reconciler
        .record_standby(
            &gate,
            sid(),
            active,
            host(SPARE),
            2,
            &wide(),
            &crate::failover::sim::binding(host(SPARE)),
        )
        .unwrap();
    assert_eq!(commits(&store, Key::Volume(active)), before + 1);
    let held = stored_volume(&store, active);
    assert_eq!(
        held.live_hosts().collect::<Vec<_>>(),
        vec![host(OWNER), host(SPARE)]
    );
    assert_eq!(
        reconciler.record_standby(
            &gate,
            sid(),
            active,
            host(SPARE),
            2,
            &wide(),
            &crate::failover::sim::binding(host(SPARE))
        ),
        Ok(recorded)
    );
    assert_eq!(
        reconciler.record_standby(
            &gate,
            sid(),
            active,
            host(SPARE),
            3,
            &wide(),
            &crate::failover::sim::binding(host(SPARE))
        ),
        Err(ReconcileError::Conflict)
    );
    assert_eq!(commits(&store, Key::Volume(active)), before + 1);
    edit_volume(&store, active, |held| {
        let mut next = held.clone();
        next.push(EventKind::Attach, host(SPARE + 2), 2);
        next.events.last_mut().unwrap().instance =
            Some(crate::failover::attachments::InstanceId::new("i-0ccccccccccccccc0").unwrap());
        next
    });
    let bound = commits(&store, Key::Volume(active));
    assert_eq!(
        reconciler.record_standby(
            &gate,
            sid(),
            active,
            host(SPARE + 2),
            2,
            &wide(),
            &crate::failover::sim::binding(host(SPARE + 2))
        ),
        Err(ReconcileError::Conflict),
        "a replay under another instance"
    );
    assert_eq!(commits(&store, Key::Volume(active)), bound);
    edit_volume(&store, active, |held| ended(held, SPARE));
    let ended = stored_volume(&store, active);
    assert_eq!(ended.live(host(SPARE)), None);
    assert_eq!(
        reconciler
            .record_standby(
                &gate,
                sid(),
                active,
                host(SPARE),
                2,
                &wide(),
                &crate::failover::sim::binding(host(SPARE))
            )
            .map(drop),
        Err(ReconcileError::Conflict),
        "an ended entry that is not gone takes no new attach (ATTACH-AFTER-GONE)"
    );
    assert_eq!(commits(&store, Key::Volume(active)), bound + 1);
    edit_volume(&store, active, |held| {
        let mut next = held.clone();
        next.pairs.retain(|recorded| recorded.host != host(SPARE));
        next.fence = next.fence.max((record().generation.get() << 32) | 4);
        next
    });
    edit_volume(&store, active, |held| gone(held, SPARE));
    let gone = stored_volume(&store, active);
    assert_eq!(
        reconciler
            .record_standby(
                &gate,
                sid(),
                active,
                host(SPARE),
                2,
                &wide(),
                &crate::failover::sim::binding(host(SPARE))
            )
            .map(drop),
        Ok(()),
        "a gone entry's host takes a new attach"
    );
    let again = stored_volume(&store, active);
    assert_eq!(commits(&store, Key::Volume(active)), bound + 4);
    assert_eq!(again.live(host(SPARE)), Some(gone.next));
    assert_eq!(again.events[..gone.events.len()], gone.events[..]);
}

/// With the owner and two standbys attached, a third standby conflicts with no write; once one standby's entry ends
/// in place, a different host records.
#[test]
fn a_fourth_attachment_refuses_before_any_write() {
    let gate = StandbyGate::qualified();
    let store = activated();
    bump(&store);
    let active = record().active;
    let mut reconciler = reconciler(&store);
    for standby in [SPARE, SPARE + 1] {
        reconciler
            .record_standby(
                &gate,
                sid(),
                active,
                host(standby),
                2,
                &wide(),
                &crate::failover::sim::binding(host(standby)),
            )
            .unwrap();
    }
    let before = commits(&store, Key::Volume(active));
    assert_eq!(
        reconciler.record_standby(
            &gate,
            sid(),
            active,
            host(SPARE + 2),
            2,
            &wide(),
            &crate::failover::sim::binding(host(SPARE + 2))
        ),
        Err(ReconcileError::Conflict)
    );
    assert_eq!(commits(&store, Key::Volume(active)), before);
    edit_volume(&store, active, |held| ended(held, SPARE));
    reconciler
        .record_standby(
            &gate,
            sid(),
            active,
            host(SPARE + 2),
            2,
            &wide(),
            &crate::failover::sim::binding(host(SPARE + 2)),
        )
        .unwrap();
    assert_eq!(
        stored_volume(&store, active)
            .live_hosts()
            .collect::<Vec<_>>(),
        vec![host(OWNER), host(SPARE + 1), host(SPARE + 2)]
    );
}

/// The live attach, event and pair counts stay below their caps, so the exhausted sequence alone causes the second
/// standby's conflict.
/// The last attach the volume admits takes the last number that has a key, `u32::MAX - 2`, and enrolls under
/// incarnation `u32::MAX - 1`. The next attach conflicts with no write, and a live attach at a number that has no key
/// refuses `Enrollment(Key)` before `persist` and before any volume record write.
#[test]
fn a_standby_attach_conflicts_before_any_write_once_no_sequence_number_is_left() {
    use crate::failover::poll::Holder;
    use crate::failover::reconcile::{StandbyRefusal, enroll_standby};
    let gate = StandbyGate::qualified();
    let seeded = |next: u32| {
        let mut held = stored_volume(&activated(), record().active);
        held.next = next;
        held.events[0].seq = next - 1;
        held.pairs[0].attach = next - 1;
        let store = Shared::new();
        provisioner(&store).create_shard(empty()).unwrap();
        client(&store)
            .create(Key::Volume(held.volume), held)
            .unwrap();
        fence_page(&store, 0, (record().generation.get() << 32) | 2);
        bump(&store);
        store
    };
    let active = record().active;
    let standby = Holder {
        volume: active,
        host: host(SPARE),
        instance: crate::failover::sim::instance_of_host(host(SPARE)),
    };
    let last = u32::MAX - 2;
    let store = seeded(last);
    let mut attacher = reconciler(&store);
    attacher
        .record_standby(
            &gate,
            sid(),
            active,
            host(SPARE),
            2,
            &wide(),
            &crate::failover::sim::binding(host(SPARE)),
        )
        .unwrap();
    let exhausted = stored_volume(&store, active);
    assert_eq!(
        (exhausted.live(host(SPARE)), exhausted.next),
        (Some(last), u32::MAX - 1)
    );
    assert!(exhausted.attach_key(host(SPARE)).is_some());
    assert_eq!(crate::failover::records::attachment_key(u32::MAX - 1), None);
    let before = commits(&store, Key::Volume(active));
    assert_eq!(
        attacher.record_standby(
            &gate,
            sid(),
            active,
            host(SPARE + 1),
            2,
            &wide(),
            &crate::failover::sim::binding(host(SPARE + 1))
        ),
        Err(ReconcileError::Conflict)
    );
    assert_eq!(commits(&store, Key::Volume(active)), before);
    assert_eq!(stored_volume(&store, active), exhausted);
    let own = Pair {
        exhid: crate::failover::evidence_tests::exhid(2),
        key: ReservationKey::decode((1 << 32) | u64::from(u32::MAX - 1)).unwrap(),
    };
    assert_eq!(
        enroll_standby(
            &gate,
            sid(),
            &standby,
            &wide(),
            &mut client(&store),
            |key| {
                assert_eq!(key, own.key);
                Ok(standby_record(standby.instance.as_str(), own))
            }
        ),
        Ok(own),
        "the last attach the volume admits enrolls"
    );
    let store = seeded(u32::MAX - 1);
    let mut keyless = stored_volume(&store, active);
    keyless.push(EventKind::Attach, host(SPARE), 2).unwrap();
    keyless.events.last_mut().unwrap().instance =
        Some(crate::failover::sim::instance_of_host(host(SPARE)));
    assert_eq!(keyless.live(host(SPARE)), Some(u32::MAX - 1));
    edit_volume(&store, active, |_| keyless.clone());
    let before = commits(&store, Key::Volume(active));
    let (mut counted, requests) = counting(&store);
    assert_eq!(
        enroll_standby(&gate, sid(), &standby, &wide(), &mut counted, |_| {
            panic!("an attach whose number has no key reaches no persist")
        }),
        Err(StandbyRefusal::Enrollment(
            crate::failover::records::Enrollment::Key
        ))
    );
    assert_eq!(requests.seen().1, 0, "no store write request");
    assert_eq!(
        Attach::of(&keyless, host(SPARE), &wide()),
        Attach::Closed,
        "a live attach that can never enroll"
    );
    assert_eq!(
        reconciler(&store).record_standby(
            &gate,
            sid(),
            active,
            host(SPARE),
            2,
            &wide(),
            &crate::failover::sim::binding(host(SPARE))
        ),
        Err(ReconcileError::Conflict),
        "no attach witness for an attach that can never enroll"
    );
    assert_eq!(
        reconciler(&store).reserve(
            &gate,
            &Population { cap: 1 },
            &wide(),
            ZONE,
            sid(),
            &roomy(host(SPARE)),
            |_| false
        ),
        Err(ReconcileError::Population(PopulationRefusal::Closed))
    );
    assert!(store.0.borrow().current(&Key::Standbys(ZONE)).is_none());
    assert_eq!(commits(&store, Key::Volume(active)), before);
    assert_eq!(stored_volume(&store, active), keyless);
    let legacy = crate::failover::evidence_tests::pair(2, 3, 7);
    edit_volume(&store, active, |held| {
        let mut next = held.clone();
        next.pairs.push(crate::failover::records::RecordedPair {
            host: host(SPARE),
            pair: legacy,
            attach: u32::MAX - 1,
        });
        next
    });
    let before = commits(&store, Key::Volume(active));
    assert_eq!(
        enroll_standby(
            &gate,
            sid(),
            &standby,
            &wide(),
            &mut client(&store),
            |key| {
                assert_eq!(key, legacy.key, "the recorded pair's key");
                Ok(standby_record(standby.instance.as_str(), legacy))
            }
        ),
        Ok(legacy),
        "a pair recorded at a number with no key replays"
    );
    assert_eq!(commits(&store, Key::Volume(active)), before);
    assert!(
        reconciler(&store)
            .record_standby(
                &gate,
                sid(),
                active,
                host(SPARE),
                2,
                &wide(),
                &crate::failover::sim::binding(host(SPARE))
            )
            .is_ok(),
        "an enrolled attach replays its witness"
    );
}

/// A derived key that a recorded pair already holds opens no attach: with the owner's retained pair under entry 1's
/// key, a standby's attach refuses `Closed` at its reservation and `Conflict` at its record with no write, and an
/// attach already recorded at entry 1 refuses `Shared` before `persist`, with no store write request, and returns
/// no witness.
#[test]
fn a_derived_key_a_recorded_pair_holds_opens_no_attach() {
    use crate::failover::poll::Holder;
    use crate::failover::reconcile::{StandbyRefusal, enroll_standby};
    let gate = StandbyGate::qualified();
    let active = record().active;
    let mut held = stored_volume(&activated(), active);
    assert_eq!(held.next, 1);
    held.pairs[0].pair.key = ReservationKey::decode((1 << 32) | 2).unwrap();
    let store = Shared::new();
    provisioner(&store).create_shard(empty()).unwrap();
    client(&store)
        .create(Key::Volume(active), held.clone())
        .unwrap();
    fence_page(&store, 0, (record().generation.get() << 32) | 2);
    bump(&store);
    assert_eq!(Attach::of(&held, host(SPARE), &wide()), Attach::Closed);
    let before = commits(&store, Key::Volume(active));
    assert_eq!(
        reconciler(&store).reserve(
            &gate,
            &Population { cap: 1 },
            &wide(),
            ZONE,
            sid(),
            &roomy(host(SPARE)),
            |_| false
        ),
        Err(ReconcileError::Population(PopulationRefusal::Closed))
    );
    assert!(store.0.borrow().current(&Key::Standbys(ZONE)).is_none());
    assert_eq!(
        reconciler(&store).record_standby(
            &gate,
            sid(),
            active,
            host(SPARE),
            2,
            &wide(),
            &crate::failover::sim::binding(host(SPARE))
        ),
        Err(ReconcileError::Conflict)
    );
    assert_eq!(commits(&store, Key::Volume(active)), before);
    edit_volume(&store, active, |held| {
        let mut next = held.clone();
        next.push(EventKind::Attach, host(SPARE), 2).unwrap();
        next.events.last_mut().unwrap().instance =
            Some(crate::failover::sim::instance_of_host(host(SPARE)));
        next
    });
    let standby = Holder {
        volume: active,
        host: host(SPARE),
        instance: crate::failover::sim::instance_of_host(host(SPARE)),
    };
    let before = commits(&store, Key::Volume(active));
    let (mut counted, requests) = counting(&store);
    assert_eq!(
        enroll_standby(&gate, sid(), &standby, &wide(), &mut counted, |_| {
            panic!("a derived key a recorded pair holds reaches no persist")
        }),
        Err(StandbyRefusal::Enrollment(
            crate::failover::records::Enrollment::Shared
        ))
    );
    assert_eq!(requests.seen().1, 0);
    assert_eq!(
        reconciler(&store).record_standby(
            &gate,
            sid(),
            active,
            host(SPARE),
            2,
            &wide(),
            &crate::failover::sim::binding(host(SPARE))
        ),
        Err(ReconcileError::Conflict)
    );
    assert_eq!(commits(&store, Key::Volume(active)), before);
}

#[test]
fn a_standby_attach_refuses_a_volume_the_fresh_path_did_not_leave() {
    let gate = StandbyGate::qualified();
    let active = record().active;
    type Edit = fn(&VolumeRecord) -> VolumeRecord;
    type Seed = fn() -> Shared;
    let rows: [(&str, Seed, Edit); 5] = [
        ("owner unenrolled", fenced_world, |held| VolumeRecord {
            state: VolumeState::Active,
            ..held.clone()
        }),
        (
            "owner not yet activated",
            enrolled_world,
            VolumeRecord::clone,
        ),
        ("modified", activated, |held| VolumeRecord {
            modification: Some(Modification::InProgress),
            ..held.clone()
        }),
        ("retired", activated, |held| VolumeRecord {
            state: VolumeState::Retired,
            ..held.clone()
        }),
        ("events at their cap", activated, |held| {
            let mut next = held.clone();
            while next.events.len() < crate::failover::records::MAX_EVENTS {
                next.push(EventKind::Detach, host(OWNER + 50), ERA);
            }
            next
        }),
    ];
    for (name, seed, edit) in rows {
        let store = seed();
        bump(&store);
        edit_volume(&store, active, edit);
        let before = commits(&store, Key::Volume(active));
        assert_eq!(
            reconciler(&store).record_standby(
                &gate,
                sid(),
                active,
                host(SPARE),
                2,
                &wide(),
                &crate::failover::sim::binding(host(SPARE))
            ),
            Err(ReconcileError::Conflict),
            "{name}"
        );
        assert_eq!(commits(&store, Key::Volume(active)), before, "{name}");
    }
}

/// The standby gate's enrollment refuses `E = 0`, the owner's host, an unactivated owner and a missing attach before
/// `persist`; a failed `persist`, a misbound record, a full pair set and a record under another key than the attach's
/// own refuse with no write; `persist` takes the key of the standby's attach entry, the local record persists before
/// the enrollment write, `enroll_standby` returns the enrolled pair, and a rerun writes nothing.
#[test]
fn the_standby_persists_before_enrollment_and_returns_the_enrolled_pair() {
    use crate::failover::admission::AdmissionError;
    use crate::failover::evidence_tests::pair;
    use crate::failover::poll::Holder;
    use crate::failover::reconcile::{StandbyRefusal, enroll_standby};
    let gate = StandbyGate::qualified();
    let active = record().active;
    let standby = Holder {
        volume: active,
        host: host(SPARE),
        instance: crate::failover::sim::instance_of_host(host(SPARE)),
    };
    let own = pair(2, 1, 2);
    let local = |instance: &str| standby_record(instance, own);
    let store = enrolled_world();
    let persisted = std::cell::Cell::new(0);
    let persist = |key| {
        assert_eq!(
            key, own.key,
            "persist takes the key of the standby's own attach entry"
        );
        persisted.set(persisted.get() + 1);
        Ok(local(standby.instance.as_str()))
    };
    let mut host_client = client(&store);
    assert_eq!(
        enroll_standby(&gate, sid(), &standby, &wide(), &mut host_client, persist),
        Err(StandbyRefusal::Tenure),
        "E = 0"
    );
    bump(&store);
    let owner = Holder {
        host: host(OWNER),
        ..standby
    };
    assert_eq!(
        enroll_standby(&gate, sid(), &owner, &wide(), &mut host_client, persist),
        Err(StandbyRefusal::Tenure),
        "the owner's host"
    );
    assert_eq!(
        enroll_standby(&gate, sid(), &standby, &wide(), &mut host_client, persist),
        Err(StandbyRefusal::Tenure),
        "the owner has not activated the volume"
    );
    fence_page(&store, 0, (record().generation.get() << 32) | 2);
    assert_eq!(
        enroll_standby(&gate, sid(), &standby, &wide(), &mut host_client, persist),
        Err(StandbyRefusal::Enrollment(
            crate::failover::records::Enrollment::Unattached
        )),
        "no attach event"
    );
    assert_eq!(persisted.get(), 0);
    reconciler(&store)
        .record_standby(
            &gate,
            sid(),
            active,
            host(SPARE),
            2,
            &wide(),
            &crate::failover::sim::binding(host(SPARE)),
        )
        .unwrap();
    let before = commits(&store, Key::Volume(active));
    assert_eq!(
        enroll_standby(&gate, sid(), &standby, &wide(), &mut host_client, |_| {
            Err(AdmissionError::DurableWrite)
        }),
        Err(StandbyRefusal::Persist(AdmissionError::DurableWrite))
    );
    assert_eq!(
        enroll_standby(&gate, sid(), &standby, &wide(), &mut host_client, |_| {
            Ok(local("i-0ccccccccccccccc0"))
        }),
        Err(StandbyRefusal::Binding)
    );
    let narrow = crate::failover::bounds::Bounds::new(1, 1, u64::MAX, 100, 100, 0).unwrap();
    assert_eq!(
        enroll_standby(&gate, sid(), &standby, &narrow, &mut host_client, |_| {
            Ok(local(standby.instance.as_str()))
        }),
        Err(StandbyRefusal::Enrollment(
            crate::failover::records::Enrollment::Full
        )),
        "N_reg = 1 leaves no room beside the owner's pair"
    );
    for (what, key) in [
        ("the owner's attach key", pair(1, 1, 1).key),
        ("a key no attach of the volume derives", pair(2, 3, 2).key),
    ] {
        let (mut counted, requests) = counting(&store);
        assert_eq!(
            enroll_standby(&gate, sid(), &standby, &wide(), &mut counted, |_| {
                Ok(standby_record(
                    standby.instance.as_str(),
                    Pair { key, ..own },
                ))
            }),
            Err(StandbyRefusal::Enrollment(
                crate::failover::records::Enrollment::Key
            )),
            "{what}"
        );
        assert_eq!(requests.seen().1, 0, "{what}: no store write request");
    }
    assert_eq!(commits(&store, Key::Volume(active)), before);
    let enrolled = enroll_standby(&gate, sid(), &standby, &wide(), &mut host_client, |key| {
        assert_eq!(
            commits(&store, Key::Volume(active)),
            before,
            "the local record persists before the enrollment write"
        );
        assert_eq!(
            (key, Some(key)),
            (
                own.key,
                stored_volume(&store, active).attach_key(host(SPARE))
            ),
            "persist takes the key of the standby's own attach entry"
        );
        Ok(local(standby.instance.as_str()))
    });
    assert_eq!(enrolled, Ok(own));
    assert_eq!(commits(&store, Key::Volume(active)), before + 1);
    assert_eq!(
        stored_volume(&store, active).enrolled(host(SPARE)),
        Some(own)
    );
    assert_eq!(
        enroll_standby(&gate, sid(), &standby, &wide(), &mut host_client, persist),
        Ok(own),
        "a rerun finds the enrolled pair"
    );
    assert_eq!(persisted.get(), 1, "the rerun persists once");
    assert_eq!(commits(&store, Key::Volume(active)), before + 1);
    let legacy = pair(2, 3, 2);
    let store = standby_world(&[SPARE], &[]);
    edit_volume(&store, active, |held| {
        let mut next = held.clone();
        next.pairs.push(crate::failover::records::RecordedPair {
            host: host(SPARE),
            pair: legacy,
            attach: held.live(host(SPARE)).unwrap(),
        });
        next
    });
    assert_ne!(
        stored_volume(&store, active).attach_key(host(SPARE)),
        Some(legacy.key)
    );
    let before = commits(&store, Key::Volume(active));
    assert_eq!(
        enroll_standby(
            &gate,
            sid(),
            &standby,
            &wide(),
            &mut client(&store),
            |key| {
                assert_eq!(key, legacy.key, "a recorded pair's own key");
                Ok(standby_record(standby.instance.as_str(), legacy))
            }
        ),
        Ok(legacy),
        "a pair recorded under a key no entry derives replays"
    );
    assert_eq!(commits(&store, Key::Volume(active)), before);
}

/// INSTANCE-BOUND at enrollment: a holder whose instance differs from the one its live attach entry binds refuses
/// `Binding` before `persist` runs, with no store write request. The holder on the entry's instance enrolls, and so
/// does a holder on any instance over an entry that binds none, so the refusal comes from the entry's binding.
#[test]
fn an_enrollment_under_another_instance_than_its_entrys_refuses_before_persist() {
    use crate::failover::attachments::InstanceId;
    use crate::failover::poll::Holder;
    use crate::failover::reconcile::{StandbyRefusal, enroll_standby};
    use crate::failover::sim::instance_of_host;
    const ELSEWHERE: &str = "i-0ccccccccccccccc0";
    let gate = StandbyGate::qualified();
    let active = record().active;
    let store = standby_world(&[SPARE], &[]);
    let seq = stored_volume(&store, active).live(host(SPARE)).unwrap();
    assert_eq!(
        stored_volume(&store, active)
            .event(seq)
            .and_then(|entry| entry.instance),
        Some(instance_of_host(host(SPARE)))
    );
    let elsewhere = Holder {
        volume: active,
        host: host(SPARE),
        instance: InstanceId::new(ELSEWHERE).unwrap(),
    };
    let before = commits(&store, Key::Volume(active));
    let (mut counted, requests) = counting(&store);
    assert_eq!(
        enroll_standby(&gate, sid(), &elsewhere, &wide(), &mut counted, |_| {
            panic!("a holder on another instance than its entry's persists nothing")
        }),
        Err(StandbyRefusal::Binding)
    );
    assert_eq!(requests.seen().1, 0, "no store write request");
    assert_eq!(commits(&store, Key::Volume(active)), before);
    assert_eq!(stored_volume(&store, active).enrolled(host(SPARE)), None);

    let enroll = |store: &Shared, holder: &Holder| {
        enroll_standby(&gate, sid(), holder, &wide(), &mut client(store), |key| {
            Ok(standby_record(
                holder.instance.as_str(),
                Pair {
                    exhid: crate::failover::evidence_tests::exhid(SPARE as u8),
                    key,
                },
            ))
        })
    };
    let mut held = stored_volume(&store, active);
    held.events
        .iter_mut()
        .find(|event| event.seq == seq)
        .unwrap()
        .instance = None;
    let unbound = seeded_with(held);
    assert_eq!(
        enroll(&unbound, &elsewhere),
        Ok(attach_pair(&stored_volume(&unbound, active), SPARE)),
        "an entry that binds no instance enrolls the holder under its own"
    );
    let bound = Holder {
        instance: instance_of_host(host(SPARE)),
        ..elsewhere
    };
    assert_eq!(
        enroll(&store, &bound),
        Ok(attach_pair(&stored_volume(&store, active), SPARE))
    );
    assert_eq!(commits(&store, Key::Volume(active)), before + 1);
}

/// `records_admit_standby` is the part of the enrollment's precondition that the shard record and the volume record
/// decide. In each state where it is false, `enroll_standby` over the stored records refuses `Tenure` after its
/// volume read and its shard read, with no page read, no `persist` and no write. Where it is true, `enroll_standby`
/// reads page 0 next, and that page's fence decides.
#[test]
fn the_records_part_of_the_standby_precondition_is_false_only_where_the_enrollment_refuses_tenure()
{
    use crate::failover::attachments::InstanceId;
    use crate::failover::poll::Holder;
    use crate::failover::reconcile::{StandbyRefusal, enroll_standby, records_admit_standby};
    use crate::failover::records::Enrollment;
    use crate::storage::store::sim::{Recorder, Request};
    let gate = StandbyGate::qualified();
    let active = record().active;
    let enrollment = |store: &Shared, volume: VolumeId, enrolling: Host| {
        let (_, tenure) = stored(store);
        let admitted = records_admit_standby(&tenure, &stored_volume(store, volume), enrolling);
        let recorder = Recorder::new(store);
        let holder = Holder {
            volume,
            host: enrolling,
            instance: InstanceId::new("i-0bbbbbbbbbbbbbbb0").unwrap(),
        };
        let before = commits(store, Key::Volume(volume));
        let refused = enroll_standby(
            &gate,
            sid(),
            &holder,
            &wide(),
            &mut Client::open(recorder.clone(), MemLog::default()).unwrap(),
            |_| panic!("a refused precondition runs no persist"),
        )
        .unwrap_err();
        assert_eq!(commits(store, Key::Volume(volume)), before);
        let requests: Vec<(bool, Key)> = (recorder.take().into_iter())
            .filter_map(|request| match request {
                Request::Read(key) => Some((false, key)),
                Request::Write(key, _) => Some((true, key)),
                Request::Device(_) => None,
            })
            .collect();
        (admitted, refused, requests)
    };
    let reads = [(false, Key::Volume(active)), (false, Key::Shard(sid()))];
    type Edit = fn(&VolumeRecord) -> VolumeRecord;
    type Seed = fn() -> Shared;
    let refused: [(&str, Seed, bool, Edit, u64); 5] = [
        ("E = 0", activated, false, VolumeRecord::clone, SPARE),
        (
            "the owner's host",
            activated,
            true,
            VolumeRecord::clone,
            OWNER,
        ),
        (
            "owner unenrolled",
            fenced_world,
            true,
            VolumeRecord::clone,
            SPARE,
        ),
        (
            "modified",
            activated,
            true,
            |held| VolumeRecord {
                modification: Some(Modification::InProgress),
                ..held.clone()
            },
            SPARE,
        ),
        (
            "retired",
            activated,
            true,
            |held| VolumeRecord {
                state: VolumeState::Retired,
                ..held.clone()
            },
            SPARE,
        ),
    ];
    for (name, seed, bumped, edit, enrolling) in refused {
        let store = seed();
        if bumped {
            bump(&store);
        }
        edit_volume(&store, active, edit);
        assert_eq!(
            enrollment(&store, active, host(enrolling)),
            (false, StandbyRefusal::Tenure, reads.to_vec()),
            "{name}"
        );
    }

    let (spared, _) = spared();
    bump(&spared);
    let spare = vol("vol-0b");
    assert_eq!(
        enrollment(&spared, spare, host(SPARE)),
        (
            false,
            StandbyRefusal::Tenure,
            vec![(false, Key::Volume(spare)), (false, Key::Shard(sid()))]
        ),
        "a spare the shard record does not name active"
    );

    let page = [reads.as_slice(), &[(false, Key::Page(sid(), 0))]].concat();
    let admitted: [(&str, Seed, StandbyRefusal); 2] = [
        (
            "owner not yet activated",
            enrolled_world,
            StandbyRefusal::Tenure,
        ),
        (
            "serving",
            activated,
            StandbyRefusal::Enrollment(Enrollment::Unattached),
        ),
    ];
    for (name, seed, refusal) in admitted {
        let store = seed();
        bump(&store);
        assert_eq!(
            enrollment(&store, active, host(SPARE)),
            (true, refusal, page.clone()),
            "{name}"
        );
    }
}

/// KEY-PER-ATTACH's replay half: a pair the volume record pins for the standby's live attach under a key that attach
/// does not derive, as a record written before the key rule holds it, is the key `persist` receives, so the replay
/// returns that pair with no store write.
#[test]
fn a_standby_pair_pinned_under_a_retained_key_replays_under_that_key() {
    use crate::failover::evidence_tests::pair;
    use crate::failover::poll::Holder;
    use crate::failover::reconcile::enroll_standby;
    let gate = StandbyGate::qualified();
    let active = record().active;
    // The instance the standby's attach entry binds (BIND-AT-ATTACH), which `enroll_standby` checks the holder against.
    let standby = Holder {
        volume: active,
        host: host(SPARE),
        instance: crate::failover::sim::instance_of_host(host(SPARE)),
    };
    let store = enrolled_world();
    bump(&store);
    fence_page(&store, 0, (record().generation.get() << 32) | 2);
    reconciler(&store)
        .record_standby(
            &gate,
            sid(),
            active,
            host(SPARE),
            2,
            &wide(),
            &crate::failover::sim::binding(host(SPARE)),
        )
        .unwrap();
    let retained = pair(2, 6, 5);
    edit_volume(&store, active, |held| {
        let mut next = held.clone();
        next.pairs.push(RecordedPair {
            host: host(SPARE),
            pair: retained,
            attach: held.live(host(SPARE)).unwrap(),
        });
        next
    });
    assert_ne!(
        stored_volume(&store, active).attach_key(host(SPARE)),
        Some(retained.key)
    );
    let before = commits(&store, Key::Volume(active));
    let mut client = client(&store);
    let persisted = std::cell::Cell::new(0);
    assert_eq!(
        enroll_standby(&gate, sid(), &standby, &wide(), &mut client, |key| {
            persisted.set(persisted.get() + 1);
            assert_eq!(key, retained.key, "persist takes the pinned pair's key");
            Ok(standby_record(standby.instance.as_str(), retained))
        }),
        Ok(retained)
    );
    assert_eq!(persisted.get(), 1, "the replay runs persist once");
    assert_eq!(commits(&store, Key::Volume(active)), before);
    assert_eq!(
        enroll_standby(&gate, sid(), &standby, &wide(), &mut client, |_| {
            Err(crate::failover::admission::AdmissionError::Retained)
        }),
        Err(crate::failover::reconcile::StandbyRefusal::Persist(
            crate::failover::admission::AdmissionError::Retained
        )),
        "a refused persist refuses the replay"
    );
    assert_eq!(commits(&store, Key::Volume(active)), before);
}

/// Provisioning, the attach record and the owner's enrollment store format 2; a standby's attach entry binds its
/// instance (BIND-AT-ATTACH), which only format 3 expresses, so the record is format 3 from that write on.
#[test]
fn the_provisioning_writers_store_format_2_and_a_bound_standby_format_3() {
    use crate::failover::evidence_tests::pair;
    use crate::failover::poll::Holder;
    use crate::failover::reconcile::enroll_standby;
    let gate = StandbyGate::qualified();
    let active = record().active;
    let store = Shared::new();
    provisioner(&store).create_shard(empty()).unwrap();
    reconciler(&store).provision(active, layout()).unwrap();
    assert_eq!(stored_format(&store, active), 2, "provisioned");
    reconciler(&store)
        .record_attach(active, host(OWNER), ERA)
        .unwrap();
    assert_eq!(stored_format(&store, active), 2, "attach recorded");
    edit_volume(&store, active, |held| {
        held.enroll(host(OWNER), pair(1, 1, 1), &wide())
            .unwrap()
            .unwrap()
    });
    assert_eq!(stored_format(&store, active), 2, "owner enrolled");
    fence_page(&store, 0, (record().generation.get() << 32) | 2);
    bump(&store);
    reconciler(&store)
        .record_standby(
            &gate,
            sid(),
            active,
            host(SPARE),
            ERA,
            &wide(),
            &crate::failover::sim::binding(host(SPARE)),
        )
        .unwrap();
    assert_eq!(stored_format(&store, active), 3, "standby attach recorded");
    let standby = Holder {
        volume: active,
        host: host(SPARE),
        instance: crate::failover::sim::instance_of_host(host(SPARE)),
    };
    let own = pair(2, 1, 2);
    enroll_standby(&gate, sid(), &standby, &wide(), &mut client(&store), |_| {
        Ok(standby_record(standby.instance.as_str(), own))
    })
    .unwrap();
    assert_eq!(stored_format(&store, active), 3, "standby enrolled");
    assert_eq!(
        stored_volume(&store, active).enrolled(host(SPARE)),
        Some(own)
    );
}

#[test]
fn a_stored_format_2_volume_takes_a_format_3_successor() {
    let active = record().active;
    let seeded = || {
        let store = Shared::new();
        provisioner(&store).create_shard(empty()).unwrap();
        reconciler(&store).provision(active, layout()).unwrap();
        reconciler(&store)
            .record_attach(active, host(OWNER), ERA)
            .unwrap();
        edit_volume(&store, active, |held| {
            let mut next = held
                .enroll(
                    host(OWNER),
                    crate::failover::evidence_tests::pair(1, 1, 1),
                    &wide(),
                )
                .unwrap()
                .unwrap();
            next.push(EventKind::Attach, host(SPARE), ERA);
            next.push(EventKind::Detach, host(SPARE), ERA);
            next
        });
        assert_eq!(stored_format(&store, active), 2);
        store
    };
    let stored = stored_volume(&seeded(), active);
    let mut ended = stored.clone();
    ended.events[0].kind = EventKind::Ended;
    let mut bound = stored.clone();
    bound.push(EventKind::Attach, host(SPARE + 1), ERA);
    bound.events.last_mut().unwrap().instance =
        Some(crate::failover::attachments::InstanceId::new("i-0ccccccccccccccc0").unwrap());
    for (what, successor) in [("an ended attach", ended), ("an attach born bound", bound)] {
        let store = seeded();
        let mut writer = client(&store);
        let read = writer.read::<VolumeRecord>(Key::Volume(active)).unwrap();
        assert_eq!(read.value(), &stored, "{what}");
        writer.replace(&read, successor.clone()).unwrap();
        assert_eq!(stored_format(&store, active), 3, "{what}");
        let reread = client(&store)
            .read::<VolumeRecord>(Key::Volume(active))
            .unwrap();
        assert_eq!(reread.value(), &successor, "{what}");
        assert_eq!(reread.value().events[2].kind, EventKind::Detach, "{what}");
    }
}

/// A retry of a recorded standby attach applies STANDBY-TENURE and `serving` before it returns the witness: after a
/// modification, after the owner's pair leaves, or on a volume no longer active, the retry conflicts with no write.
#[test]
fn a_standby_attach_retry_needs_a_serving_volume() {
    let gate = StandbyGate::qualified();
    let active = record().active;
    type Edit = fn(&Shared, VolumeId);
    let rows: [(&str, Edit); 3] = [
        ("modified", |store, active| {
            edit_volume(store, active, |held| VolumeRecord {
                modification: Some(Modification::InProgress),
                ..held.clone()
            });
        }),
        ("owner's pair dropped by a fence", |store, active| {
            edit_volume(store, active, |held| VolumeRecord {
                pairs: Vec::new(),
                fence: (1 << 32) | 2,
                ..held.clone()
            });
        }),
        ("retired", |store, active| {
            edit_volume(store, active, |held| VolumeRecord {
                state: VolumeState::Retired,
                ..held.clone()
            });
        }),
    ];
    for (name, edit) in rows {
        let store = activated();
        bump(&store);
        let mut reconciler = reconciler(&store);
        reconciler
            .record_standby(
                &gate,
                sid(),
                active,
                host(SPARE),
                2,
                &wide(),
                &crate::failover::sim::binding(host(SPARE)),
            )
            .unwrap();
        edit(&store, active);
        let before = commits(&store, Key::Volume(active));
        assert_eq!(
            reconciler.record_standby(
                &gate,
                sid(),
                active,
                host(SPARE),
                2,
                &wide(),
                &crate::failover::sim::binding(host(SPARE))
            ),
            Err(ReconcileError::Conflict),
            "{name}"
        );
        assert_eq!(commits(&store, Key::Volume(active)), before, "{name}");
    }
}

/// A standby attach on a volume whose recorded pairs fill the owner's `N_reg` conflicts before any write, and so
/// does its enrollment before the standby persists anything. Once the pair is enrolled, the enrollment and the attach
/// record replay with no write under a bound the stored pairs fill.
#[test]
fn a_full_pair_set_refuses_the_standby_attach_and_its_enrollment_before_any_write() {
    use crate::failover::poll::Holder;
    use crate::failover::reconcile::{StandbyRefusal, enroll_standby};
    use crate::failover::records::Enrollment;
    let gate = StandbyGate::qualified();
    let active = record().active;
    let narrow = capped(1);
    let store = activated();
    bump(&store);
    let before = commits(&store, Key::Volume(active));
    assert_eq!(
        reconciler(&store).record_standby(
            &gate,
            sid(),
            active,
            host(SPARE),
            2,
            &narrow,
            &crate::failover::sim::binding(host(SPARE))
        ),
        Err(ReconcileError::Conflict)
    );
    assert_eq!(commits(&store, Key::Volume(active)), before);
    let witness = reconciler(&store)
        .record_standby(
            &gate,
            sid(),
            active,
            host(SPARE),
            2,
            &wide(),
            &crate::failover::sim::binding(host(SPARE)),
        )
        .unwrap();
    let standby = Holder {
        volume: active,
        host: host(SPARE),
        instance: crate::failover::sim::instance_of_host(host(SPARE)),
    };
    let before = commits(&store, Key::Volume(active));
    assert_eq!(
        enroll_standby(&gate, sid(), &standby, &narrow, &mut client(&store), |_| {
            panic!("a full pair set refuses before the standby persists its record")
        }),
        Err(StandbyRefusal::Enrollment(Enrollment::Full))
    );
    assert_eq!(commits(&store, Key::Volume(active)), before);
    let own = crate::failover::evidence_tests::pair(2, 1, 2);
    let persisted = std::cell::Cell::new(0);
    let local = |key| {
        assert_eq!(key, own.key, "the standby's own attach key");
        persisted.set(persisted.get() + 1);
        Ok(standby_record(standby.instance.as_str(), own))
    };
    assert_eq!(
        enroll_standby(&gate, sid(), &standby, &wide(), &mut client(&store), local),
        Ok(own)
    );
    let two = capped(2);
    let before = commits(&store, Key::Volume(active));
    assert_eq!(
        enroll_standby(&gate, sid(), &standby, &two, &mut client(&store), local),
        Ok(own),
        "an enrolled pair replays at the cap"
    );
    assert_eq!(
        persisted.get(),
        2,
        "the first enrollment and the replay persist once each"
    );
    assert_eq!(
        reconciler(&store).record_standby(
            &gate,
            sid(),
            active,
            host(SPARE),
            2,
            &two,
            &crate::failover::sim::binding(host(SPARE))
        ),
        Ok(witness),
        "a recorded attach replays at the cap"
    );
    assert_eq!(commits(&store, Key::Volume(active)), before);
}

/// Under `N_reg = 2` the owner's pair and one standby attach that awaits enrollment fill the pair budget, so a
/// second standby attach conflicts before its write although no standby has enrolled and only two hosts are live.
/// Under `N_reg = 3` an enrolled standby counts once: a second standby attach records with one write, and a third
/// conflicts with none.
#[test]
fn standby_attaches_awaiting_enrollment_count_against_the_pair_cap() {
    use crate::failover::poll::Holder;
    use crate::failover::reconcile::enroll_standby;
    let gate = StandbyGate::qualified();
    let active = record().active;
    let two = capped(2);
    let store = activated();
    bump(&store);
    let mut reconciler = reconciler(&store);
    reconciler
        .record_standby(
            &gate,
            sid(),
            active,
            host(SPARE),
            2,
            &two,
            &crate::failover::sim::binding(host(SPARE)),
        )
        .unwrap();
    let before = commits(&store, Key::Volume(active));
    assert_eq!(
        reconciler.record_standby(
            &gate,
            sid(),
            active,
            host(SPARE + 1),
            2,
            &two,
            &crate::failover::sim::binding(host(SPARE + 1))
        ),
        Err(ReconcileError::Conflict),
        "the owner's pair and one awaiting attach fill N_reg = 2"
    );
    assert_eq!(commits(&store, Key::Volume(active)), before);
    let three = capped(3);
    let standby = Holder {
        volume: active,
        host: host(SPARE),
        instance: crate::failover::sim::instance_of_host(host(SPARE)),
    };
    let own = crate::failover::evidence_tests::pair(2, 1, 2);
    enroll_standby(&gate, sid(), &standby, &three, &mut client(&store), |_| {
        Ok(standby_record(standby.instance.as_str(), own))
    })
    .unwrap();
    let before = commits(&store, Key::Volume(active));
    reconciler
        .record_standby(
            &gate,
            sid(),
            active,
            host(SPARE + 1),
            2,
            &three,
            &crate::failover::sim::binding(host(SPARE + 1)),
        )
        .unwrap();
    assert_eq!(commits(&store, Key::Volume(active)), before + 1);
    assert_eq!(
        reconciler.record_standby(
            &gate,
            sid(),
            active,
            host(SPARE + 2),
            2,
            &three,
            &crate::failover::sim::binding(host(SPARE + 2))
        ),
        Err(ReconcileError::Conflict),
        "two pairs and one awaiting attach fill N_reg = 3"
    );
    assert_eq!(commits(&store, Key::Volume(active)), before + 1);
}

/// The standby gate's store failures: a failed volume or shard read refuses with `Records` before `persist`, an
/// enrollment write without an acknowledgment refuses with `Write` whether or not it committed, and a rerun finds
/// the committed pair or writes it; a holder of a volume with no record refuses with `Records`; a volume of another origin,
/// with a lineage or below the layout floor refuses the attach and the enrollment with no write; and an attach write
/// that does not apply, or applies with no acknowledgment, returns no witness, after which a retry finds the
/// committed event or writes it.
/// A read failure after an attach or enrollment commit returns `ReconcileError::Store` or `StandbyRefusal::Records`,
/// respectively, while preserving the committed write.
#[test]
fn the_standby_gate_refuses_store_failures_and_unserved_volumes() {
    use crate::failover::evidence_tests::pair;
    use crate::failover::poll::Holder;
    use crate::failover::reconcile::{StandbyRefusal, enroll_standby};
    use crate::failover::records::{CreationSource, Lineage};
    let gate = StandbyGate::qualified();
    let active = record().active;
    let standby = Holder {
        volume: active,
        host: host(SPARE),
        instance: crate::failover::sim::instance_of_host(host(SPARE)),
    };
    let own = pair(2, 1, 2);
    let persisted = std::cell::Cell::new(0);
    let local = |key| {
        assert_eq!(
            key, own.key,
            "the standby's own attach key on every attempt"
        );
        persisted.set(persisted.get() + 1);
        Ok(standby_record(standby.instance.as_str(), own))
    };
    for commit in [false, true] {
        let store = activated();
        bump(&store);
        park(&store, STANDBY_WRITE, Arm::Timeout { commit });
        let mut reconciler = reconciler(&store);
        assert_eq!(
            reconciler.record_standby(
                &gate,
                sid(),
                active,
                host(SPARE),
                2,
                &wide(),
                &crate::failover::sim::binding(host(SPARE))
            ),
            Err(ReconcileError::Store(StoreError::Unknown)),
            "attach {commit}"
        );
        reconciler
            .record_standby(
                &gate,
                sid(),
                active,
                host(SPARE),
                2,
                &wide(),
                &crate::failover::sim::binding(host(SPARE)),
            )
            .unwrap();
        assert_eq!(
            stored_volume(&store, active)
                .live_hosts()
                .filter(|&live| live == host(SPARE))
                .count(),
            1,
            "attach {commit}"
        );
        for arms in [
            vec![Arm::Unavailable],
            vec![Arm::Pass, Arm::Unavailable],
            vec![Arm::Pass, Arm::Pass, Arm::Unavailable],
        ] {
            for arm in arms {
                store.schedule(arm);
            }
            assert_eq!(
                enroll_standby(&gate, sid(), &standby, &wide(), &mut client(&store), |_| {
                    panic!("a failed read refuses before persist")
                }),
                Err(StandbyRefusal::Records(StoreError::Unavailable))
            );
        }
        park(&store, STANDBY_WRITE, Arm::Timeout { commit });
        let unenrolled = commits(&store, Key::Volume(active));
        assert_eq!(
            enroll_standby(&gate, sid(), &standby, &wide(), &mut client(&store), local),
            Err(StandbyRefusal::Write(StoreError::Unknown)),
            "enroll {commit}"
        );
        assert_eq!(
            stored_volume(&store, active).enrolled(host(SPARE)),
            commit.then_some(own),
            "enroll {commit}"
        );
        assert_eq!(
            enroll_standby(&gate, sid(), &standby, &wide(), &mut client(&store), local),
            Ok(own),
            "enroll {commit}"
        );
        assert_eq!(
            stored_volume(&store, active).pairs.len(),
            2,
            "enroll {commit}: one enrolled pair beside the owner's"
        );
        assert_eq!(
            commits(&store, Key::Volume(active)),
            unenrolled + 1,
            "enroll {commit}: one enrollment commit across the lost reply and the retry"
        );
    }
    assert_eq!(persisted.get(), 4, "each enrollment attempt persists once");
    for reread in [STANDBY_WRITE + 1, STANDBY_WRITE + 2] {
        let store = activated();
        bump(&store);
        let before = commits(&store, Key::Volume(active));
        park(&store, reread, Arm::Unavailable);
        let mut reconciler = reconciler(&store);
        assert_eq!(
            reconciler.record_standby(
                &gate,
                sid(),
                active,
                host(SPARE),
                2,
                &wide(),
                &crate::failover::sim::binding(host(SPARE))
            ),
            Err(ReconcileError::Store(StoreError::Unavailable)),
            "attach, request {reread}"
        );
        assert_eq!(
            commits(&store, Key::Volume(active)),
            before + 1,
            "attach, request {reread}: the attach write committed before the failed read"
        );
        reconciler
            .record_standby(
                &gate,
                sid(),
                active,
                host(SPARE),
                2,
                &wide(),
                &crate::failover::sim::binding(host(SPARE)),
            )
            .unwrap();
        park(&store, reread, Arm::Unavailable);
        assert_eq!(
            enroll_standby(&gate, sid(), &standby, &wide(), &mut client(&store), local),
            Err(StandbyRefusal::Records(StoreError::Unavailable)),
            "enroll, request {reread}"
        );
        assert_eq!(
            stored_volume(&store, active).enrolled(host(SPARE)),
            Some(own),
            "enroll, request {reread}: the enrollment write committed before the failed read"
        );
        assert_eq!(
            enroll_standby(&gate, sid(), &standby, &wide(), &mut client(&store), local),
            Ok(own),
            "enroll, request {reread}"
        );
        assert_eq!(
            commits(&store, Key::Volume(active)),
            before + 2,
            "request {reread}: neither retry writes"
        );
    }
    let store = activated();
    bump(&store);
    park(&store, STANDBY_WRITE, Arm::Unavailable);
    assert_eq!(
        reconciler(&store).record_standby(
            &gate,
            sid(),
            active,
            host(SPARE),
            2,
            &wide(),
            &crate::failover::sim::binding(host(SPARE))
        ),
        Err(ReconcileError::Store(StoreError::Unknown))
    );
    assert_eq!(stored_volume(&store, active).live(host(SPARE)), None);
    let elsewhere = Holder {
        volume: vol("vol-0b"),
        ..standby
    };
    assert_eq!(
        enroll_standby(
            &gate,
            sid(),
            &elsewhere,
            &wide(),
            &mut client(&store),
            local
        ),
        Err(StandbyRefusal::Records(StoreError::Absent))
    );
    type Edit = fn(&VolumeRecord) -> VolumeRecord;
    let rows: [(&str, Edit); 3] = [
        ("another origin", |held| VolumeRecord {
            source: CreationSource::Foreign,
            ..held.clone()
        }),
        ("a lineage", |held| VolumeRecord {
            lineage: Lineage::Snapshot,
            ..held.clone()
        }),
        ("below the layout floor", |held| VolumeRecord {
            layout: Layout {
                slots: 2,
                ..held.layout
            },
            ..held.clone()
        }),
    ];
    let attached = activated();
    bump(&attached);
    reconciler(&attached)
        .record_standby(
            &gate,
            sid(),
            active,
            host(SPARE),
            2,
            &wide(),
            &crate::failover::sim::binding(host(SPARE)),
        )
        .unwrap();
    let held = stored_volume(&attached, active);
    for (name, edit) in rows {
        let store = Shared::new();
        provisioner(&store).create_shard(empty()).unwrap();
        client(&store)
            .create(Key::Volume(active), edit(&held))
            .unwrap();
        bump(&store);
        let before = commits(&store, Key::Volume(active));
        assert_eq!(
            reconciler(&store).record_standby(
                &gate,
                sid(),
                active,
                host(SPARE + 1),
                2,
                &wide(),
                &crate::failover::sim::binding(host(SPARE + 1))
            ),
            Err(ReconcileError::Conflict),
            "{name}"
        );
        assert_eq!(
            enroll_standby(&gate, sid(), &standby, &wide(), &mut client(&store), local),
            Err(StandbyRefusal::Tenure),
            "{name}"
        );
        assert_eq!(commits(&store, Key::Volume(active)), before, "{name}");
    }
}

/// The shard record `store` holds now, read without consuming a scheduled arm.
fn shard_held(store: &Shared) -> ShardRecord {
    stored(store).1
}

/// Host `h`'s pair for its live attach in `held`: host ID tag `h` under the attach's own key (KEY-PER-ATTACH).
fn attach_pair(held: &VolumeRecord, h: u64) -> Pair {
    Pair {
        exhid: crate::failover::evidence_tests::exhid(h as u8),
        key: held.attach_key(host(h)).unwrap(),
    }
}

/// [`activated`] at `E = 1` with `hosts` attached as standbys and, for those `enrolled` names, enrolled with their
/// own pairs.
fn standby_world(hosts: &[u64], enrolled: &[u64]) -> Shared {
    let gate = StandbyGate::qualified();
    let store = activated();
    bump(&store);
    let active = record().active;
    for &h in hosts {
        reconciler(&store)
            .record_standby(
                &gate,
                sid(),
                active,
                host(h),
                ERA,
                &wide(),
                &crate::failover::sim::binding(host(h)),
            )
            .unwrap();
    }
    for &h in enrolled {
        edit_volume(&store, active, |held| {
            held.enroll(host(h), attach_pair(held, h), &wide())
                .unwrap()
                .unwrap()
        });
    }
    store
}

const ZONE: Zone = Zone(1);

/// The census slot of the shard at its stored `(g, owner, E)` for `candidate`, reserved under a cap of one with
/// every other host shown lost, so the slot moves to `candidate` whoever held it.
fn slot_for(store: &Shared, candidate: u64) -> Slot {
    reconciler(store)
        .reserve(
            &StandbyGate::qualified(),
            &Population { cap: 1 },
            &wide(),
            ZONE,
            sid(),
            &roomy(host(candidate)),
            |h| h != host(candidate),
        )
        .unwrap()
}

/// REPORTS-CONFER-NO-AUTHORITY at the census: from equal stores, two candidate reports with the same writer, headroom,
/// shard and role, one whose entry for the shard also claims a completed takeover, a clear watermark and the named
/// standby, reserve the same slot and census through `Reconciler::reserve` and admit the same census through
/// `Population::admit`, and neither reservation writes the shard or volume record. The same holds where the entries
/// decide the admission: the candidate holds no attach of the active volume, the census reserves another shard for
/// it and its gauge has one free attachment slot, so `Census::pending` charges that reservation unless the report
/// lists the other shard in the standby role. A replacement listing of that shard refuses `Headroom` with and
/// without the claims, and a standby listing admits.
#[test]
fn report_claims_change_no_reservation() {
    use crate::failover::report::{
        RecordedRole, Recovery, RecoveryKind, RecoveryOutcome, VolumeEntry, Watermark, tests::bare,
    };
    use crate::failover::standbys::tests::listing;
    let gate = StandbyGate::qualified();
    let candidate = SPARE + 1;
    let active = record().active;
    let claiming = |entry: VolumeEntry| VolumeEntry {
        named: Some(true),
        watermark: Watermark::Clear,
        recovery: Recovery {
            kind: Some(RecoveryKind::Takeover),
            outcome: Some(RecoveryOutcome::Completed),
            ..Recovery::UNAVAILABLE
        },
        ..entry
    };
    let records = |store: &Shared| {
        let counts = (
            commits(store, Key::Shard(sid())),
            commits(store, Key::Volume(active)),
        );
        (stored(store), stored_volume(store, active), counts)
    };
    let reserving = |store: &Shared, census: &Census, cap, attach, entry| {
        let mut report = roomy(host(candidate));
        report.entries = vec![entry];
        let population = Population { cap };
        let before = records(store);
        let admitted = population.admit(census, &shard_held(store), &report, attach, |_| false);
        let slot =
            reconciler(store).reserve(&gate, &population, &wide(), ZONE, sid(), &report, |_| false);
        assert_eq!(records(store), before, "no shard or volume write");
        (admitted, slot, census_held(store))
    };
    let attached = |entry| {
        let store = standby_world(&[candidate], &[candidate]);
        reserving(&store, &Census::empty(ZONE), 1, Attach::Live, entry)
    };
    let neutral = VolumeEntry {
        shard: sid(),
        ..bare("vol-0a", RecordedRole::Standby)
    };
    let live = attached(neutral);
    assert!(live.1.is_ok(), "{:?}", live.1);
    assert_eq!(live, attached(claiming(neutral)));
    let other = crate::net::ownership::Shard::new(sid().get() + 1).unwrap();
    let unattached = |entry| {
        let store = standby_world(&[], &[]);
        let reserved = Entry {
            target: Target::of(&shard_held(&store)),
            host: host(candidate),
        };
        let census = listing(ZONE, other, reserved);
        client(&store)
            .create(Key::Standbys(ZONE), census.clone())
            .unwrap();
        reserving(&store, &census, 2, Attach::Open, entry)
    };
    let listed = |role| VolumeEntry {
        shard: other,
        ..bare("vol-0c", role)
    };
    let charged = unattached(listed(RecordedRole::Replacement));
    let headroom = PopulationRefusal::Headroom;
    assert_eq!(
        (&charged.0, &charged.1),
        (&Err(headroom), &Err(ReconcileError::Population(headroom)))
    );
    assert_eq!(
        charged,
        unattached(claiming(listed(RecordedRole::Replacement)))
    );
    let free = unattached(listed(RecordedRole::Standby));
    assert!(
        matches!(free.0, Ok(Some(_))) && free.1.is_ok(),
        "control: a standby listing of the other shard frees the slot: {free:?}"
    );
}

/// The slot of the shard for `candidate` at its stored `(g, owner, E)`, from a census written to list it alone, as
/// a reconciler wrote it before the shard's record or volume moved under it.
fn listed_slot(store: &Shared, candidate: u64) -> Slot {
    let entry = Entry {
        target: Target::of(&shard_held(store)),
        host: host(candidate),
    };
    let census = crate::failover::standbys::tests::listing(ZONE, sid(), entry);
    let mut writer = client(store);
    let written = match writer.read::<Census>(Key::Standbys(ZONE)) {
        Ok(read) => writer.replace(&read, census),
        Err(_) => writer.create(Key::Standbys(ZONE), census),
    }
    .unwrap();
    Slot::held(&written, sid(), host(candidate)).unwrap()
}

fn census_held(store: &Shared) -> Census {
    let item = store
        .0
        .borrow()
        .current(&Key::Standbys(ZONE))
        .cloned()
        .unwrap();
    Census::decode(&item.value).unwrap()
}

fn entry_of(store: &Shared, standby: u64) -> Option<Entry> {
    Some(Entry {
        target: Target::of(&shard_held(store)),
        host: host(standby),
    })
}

fn slot_held(store: &Shared) -> Entry {
    census_held(store).slot(sid()).unwrap()
}

/// `designate`: volume read, shard read, census read, page 0 read, then the designation write.
const DESIGNATE_WRITE: usize = 4;

/// The designation names an attached and enrolled host the standby by one exact-version write that keeps the
/// tenure, `ck` and the manifest; a retry writes nothing; a later designation replaces the standby and moves the
/// shard's census slot to its host. A slot reserved before the owner's bump refuses `Stale`. `reserve` refuses an
/// unattached host of a volume at its attach limit `Closed` and the owner or a record at `E = 0` `Ineligible`, with no
/// census write. Under a slot the census already lists, an unattached host, an attached host with no enrolled pair,
/// the owner and a record at `E = 0` with the host attached and enrolled refuse `Conflict`, each with no write, and
/// the owner's pair on its attach in a retained format-2 record that shows its detach still serves the designation.
#[test]
fn a_designation_names_an_enrolled_standby_and_replaces_it() {
    let gate = StandbyGate::qualified();
    let active = record().active;
    let (first, second, unenrolled, unattached) = (SPARE + 1, SPARE + 2, SPARE + 3, SPARE + 4);
    let store = standby_world(&[first, second], &[first, second]);
    let prior = shard_held(&store);
    let designated = reconciler(&store)
        .designate(&gate, &slot_for(&store, first), active)
        .unwrap();
    let expected = ShardRecord {
        standby: Some(host(first)),
        ..prior
    };
    assert_eq!(
        (*designated.value(), shard_held(&store)),
        (expected, expected)
    );
    let commits_now = commits(&store, Key::Shard(sid()));
    reconciler(&store)
        .designate(&gate, &slot_for(&store, first), active)
        .unwrap();
    assert_eq!(
        commits(&store, Key::Shard(sid())),
        commits_now,
        "a retry writes nothing"
    );

    reconciler(&store)
        .designate(&gate, &slot_for(&store, second), active)
        .unwrap();
    assert_eq!(shard_held(&store).standby, Some(host(second)));
    assert_eq!(
        (census_held(&store).len(), census_held(&store).slot(sid())),
        (1, entry_of(&store, second)),
        "the replacement moves the shard's slot"
    );

    let settled = (stored(&store), census_held(&store));
    for (candidate, refusal) in [
        (unattached, PopulationRefusal::Closed),
        (OWNER, PopulationRefusal::Ineligible),
    ] {
        assert_eq!(
            reconciler(&store).reserve(
                &gate,
                &Population { cap: 1 },
                &wide(),
                ZONE,
                sid(),
                &roomy(host(candidate)),
                |h| h != host(candidate)
            ),
            Err(ReconcileError::Population(refusal)),
            "{candidate}"
        );
    }
    assert_eq!((stored(&store), census_held(&store)), settled);
    let slot = listed_slot(&store, unattached);
    let before = stored(&store);
    assert_eq!(
        reconciler(&store).designate(&gate, &slot, active),
        Err(ReconcileError::Conflict),
        "an unattached host"
    );
    assert_eq!(stored(&store), before);
    assert_eq!(
        client(&store)
            .create(
                Key::Standbys(Zone(2)),
                crate::failover::standbys::tests::listing(
                    Zone(2),
                    sid(),
                    Entry {
                        target: Target::of(&shard_held(&store)),
                        host: host(OWNER),
                    },
                ),
            )
            .map(drop),
        Err(StoreError::Codec(
            crate::failover::records::CodecError::Field
        )),
        "a census entry naming the owner never reaches the store"
    );
    let reserved = slot_for(&store, first);
    bump(&store);
    let bumped = stored(&store);
    assert_eq!(
        reconciler(&store).designate(&gate, &reserved, active),
        Err(ReconcileError::Stale),
        "a slot reserved before the owner's bump"
    );
    assert_eq!(stored(&store), bumped);
    let attached_only = standby_world(&[unenrolled], &[]);
    let before = stored(&attached_only);
    assert_eq!(
        reconciler(&attached_only).designate(&gate, &slot_for(&attached_only, unenrolled), active),
        Err(ReconcileError::Conflict)
    );
    assert_eq!(stored(&attached_only), before);

    let unbumped = activated();
    edit_volume(&unbumped, active, |held| {
        let mut next = held.clone();
        next.push(EventKind::Attach, host(first), ERA);
        next.enroll(host(first), attach_pair(&next, first), &wide())
            .unwrap()
            .unwrap()
    });
    assert_eq!(
        reconciler(&unbumped).reserve(
            &gate,
            &Population { cap: 1 },
            &wide(),
            ZONE,
            sid(),
            &roomy(host(first)),
            |_| false
        ),
        Err(ReconcileError::Population(PopulationRefusal::Ineligible))
    );
    assert_eq!(commits(&unbumped, Key::Standbys(ZONE)), 0);

    let unpaired = standby_world(&[first], &[first]);
    edit_volume(&unpaired, active, |held| VolumeRecord {
        pairs: held
            .pairs
            .iter()
            .filter(|recorded| recorded.host != host(OWNER))
            .copied()
            .collect(),
        fence: held.fence.max((record().generation.get() << 32) | 4),
        ..held.clone()
    });
    let before = stored(&unpaired);
    assert_eq!(
        reconciler(&unpaired).designate(&gate, &slot_for(&unpaired, first), active),
        Err(ReconcileError::Conflict),
        "a volume record without the owner's pair leaves no serving volume"
    );
    assert_eq!(stored(&unpaired), before);

    // A retained format-2 record: the standby's attach and enrollment, then the owner's detach, each format 2.
    let detached = activated();
    bump(&detached);
    edit_volume(&detached, active, |held| {
        let mut next = held.clone();
        next.push(EventKind::Attach, host(first), ERA);
        next.enroll(host(first), attach_pair(&next, first), &wide())
            .unwrap()
            .unwrap()
    });
    assert_eq!(stored_format(&detached, active), 2, "enrolled");
    edit_volume(&detached, active, |held| {
        let mut next = held.clone();
        next.push(EventKind::Detach, host(OWNER), ERA);
        next
    });
    let held = stored_volume(&detached, active);
    assert_eq!(stored_format(&detached, active), 2, "owner detached");
    assert_eq!((held.live(host(OWNER)), held.pairs.len()), (None, 2));
    assert_eq!(
        reconciler(&detached)
            .designate(&gate, &slot_for(&detached, first), active)
            .map(|read| read.value().standby),
        Ok(Some(host(first))),
        "the owner's pair on its detached format-2 attach still serves the volume"
    );
}

/// `serving` accepts the owner's recorded pair on an ended entry: a designation over a record that ends the
/// owner's attach and keeps its pair writes the standby.
#[test]
fn an_owners_pair_on_an_ended_entry_still_serves_the_designation() {
    let gate = StandbyGate::qualified();
    let active = record().active;
    let first = SPARE + 1;
    let store = standby_world(&[first], &[first]);
    edit_volume(&store, active, |held| ended(held, OWNER));
    assert_eq!(stored_volume(&store, active).live(host(OWNER)), None);
    assert_eq!(
        reconciler(&store)
            .designate(&gate, &slot_for(&store, first), active)
            .map(|read| read.value().standby),
        Ok(Some(host(first)))
    );
}

/// ONE-HOST-PER-SLOT with two reconcilers on one shard: the first reserves the slot for X, and the second's
/// reservation for Y refuses `Taken` while X is live. Once the second's evidence shows X lost, it moves the slot to Y
/// and designates Y; the first's designation of X then refuses `Conflict` with no write, so a stale retry never
/// replaces the newer designation, and the first's own retry of its reservation refuses `Taken` while Y is live.
#[test]
fn a_stale_reconciler_cannot_replace_a_newer_designation() {
    let gate = StandbyGate::qualified();
    let cap = Population { cap: 1 };
    let active = record().active;
    let (x, y) = (SPARE + 1, SPARE + 2);
    let store = standby_world(&[x, y], &[x, y]);
    let reserve = |candidate: u64, lost: Option<u64>| {
        reconciler(&store).reserve(
            &gate,
            &cap,
            &wide(),
            ZONE,
            sid(),
            &roomy(host(candidate)),
            |h| Some(h.get()) == lost,
        )
    };
    let first = reserve(x, None).unwrap();
    assert_eq!(
        reserve(y, None),
        Err(ReconcileError::Population(PopulationRefusal::Taken))
    );
    let second = reserve(y, Some(x)).unwrap();
    reconciler(&store)
        .designate(&gate, &second, active)
        .unwrap();
    let settled = stored(&store);
    assert_eq!(
        reconciler(&store).designate(&gate, &first, active),
        Err(ReconcileError::Conflict)
    );
    assert_eq!(stored(&store), settled);
    assert_eq!(settled.1.standby, Some(host(y)));
    assert_eq!(
        reserve(x, None),
        Err(ReconcileError::Population(PopulationRefusal::Taken))
    );
}

/// A failed attach: X's slot is reserved and its attach recorded, and the attach request fails for good while X
/// stays live. A second candidate refuses `Taken` until the caller's evidence reports X lost, which a reserved host
/// whose attach failed for good counts as; the slot then moves to Y, Y's designation commits, and X's slot no longer
/// designates.
#[test]
fn a_reserved_host_whose_attach_failed_releases_its_slot_on_the_callers_evidence() {
    let gate = StandbyGate::qualified();
    let cap = Population { cap: 1 };
    let active = record().active;
    let (x, y) = (SPARE + 1, SPARE + 2);
    let store = standby_world(&[y], &[y]);
    let reserve = |candidate: u64, failed: Option<u64>| {
        reconciler(&store).reserve(
            &gate,
            &cap,
            &wide(),
            ZONE,
            sid(),
            &roomy(host(candidate)),
            |h| Some(h.get()) == failed,
        )
    };
    let stranded = reserve(x, None).unwrap();
    assert_eq!(stored_volume(&store, active).latest(host(x)), None);
    assert_eq!(
        reserve(y, None),
        Err(ReconcileError::Population(PopulationRefusal::Taken)),
        "a reserved host whose attach is not recorded yet keeps its slot"
    );
    reconciler(&store)
        .record_standby(
            &gate,
            sid(),
            active,
            host(x),
            ERA,
            &wide(),
            &crate::failover::sim::binding(host(x)),
        )
        .unwrap();
    assert_eq!(
        reserve(y, None),
        Err(ReconcileError::Population(PopulationRefusal::Taken))
    );
    let slot = reserve(y, Some(x)).unwrap();
    reconciler(&store).designate(&gate, &slot, active).unwrap();
    assert_eq!(shard_held(&store).standby, Some(host(y)));
    assert_eq!(
        reconciler(&store).designate(&gate, &stranded, active),
        Err(ReconcileError::Conflict)
    );
}

/// ONE-HOST-PER-SLOT through `designate`'s read order: a reconciler holding X's slot reads the shard record, and
/// another reconciler moves the slot to Y and designates Y before the first reads the census. The first reads the
/// census only after the shard record, finds the slot listed for Y and refuses `Conflict` with no write, so Y stays
/// the standby.
#[test]
fn designate_reads_the_census_after_the_shard() {
    let gate = StandbyGate::qualified();
    let active = record().active;
    let (x, y) = (SPARE + 1, SPARE + 2);
    let store = standby_world(&[x, y], &[x, y]);
    let stale = slot_for(&store, x);
    let inner = store.clone();
    let hook = hooked(&store, Key::Shard(sid()), Point::AfterRead, move || {
        let newer = slot_for(&inner, y);
        reconciler(&inner)
            .designate(&StandbyGate::qualified(), &newer, active)
            .unwrap();
    });
    let mut racing = Reconciler::new(Client::open(AsReconciler(hook), MemLog::default()).unwrap());
    assert_eq!(
        racing.designate(&gate, &stale, active).map(drop),
        Err(ReconcileError::Conflict),
        "the census read after the shard read lists Y"
    );
    assert_eq!(shard_held(&store).standby, Some(host(y)));
    assert_eq!(census_held(&store).slot(sid()), entry_of(&store, y));
}

/// CENSUS-COVERS through `release`'s read order. The census lists an unattached host `first` at the shard's target.
/// Once the inner store returns `release`'s shard read, the hooked step, another reconciler, bumps `E` and moves the
/// slot to a second unattached host `x` at the new target. Both of `release`'s reads precede the bump: it read the
/// census first, so the entry it read and the shard record it read hold one target, and it writes nothing and returns
/// that the slot is listed. The store's census then lists `x` at the new target, which only the step's reservation
/// produces.
#[test]
fn release_reads_the_shard_after_the_census() {
    let gate = StandbyGate::qualified();
    let (x, first) = (SPARE + 1, SPARE + 2);
    let store = standby_world(&[], &[]);
    slot_for(&store, first);
    let inner = store.clone();
    let hook = hooked(&store, Key::Shard(sid()), Point::AfterRead, move || {
        bump(&inner);
        slot_for(&inner, x);
    });
    let mut releasing =
        Reconciler::new(Client::open(AsReconciler(hook), MemLog::default()).unwrap());
    assert_eq!(
        releasing.release(&gate, ZONE, sid(), slot_held(&store), |_| false),
        Ok(true)
    );
    assert_eq!(census_held(&store).slot(sid()), entry_of(&store, x));
}

/// The owner's bump makes the unattached host's listed target stale. `release` removes the census entry only when
/// both its host and target match the caller's `judged` entry.
#[test]
fn release_drops_only_the_entry_its_caller_judged() {
    let gate = StandbyGate::qualified();
    let (x, first) = (SPARE + 1, SPARE + 2);
    let store = standby_world(&[], &[]);
    slot_for(&store, first);
    let listed = slot_held(&store);
    bump(&store);
    let other_host = Entry {
        host: host(x),
        ..listed
    };
    let other_target = entry_of(&store, first).unwrap();
    for judged in [other_host, other_target] {
        assert_eq!(
            reconciler(&store).release(&gate, ZONE, sid(), judged, |_| false),
            Ok(true),
            "{judged:?}"
        );
        assert_eq!(census_held(&store).slot(sid()), Some(listed));
    }
    assert_eq!(
        reconciler(&store).release(&gate, ZONE, sid(), listed, |_| false),
        Ok(false)
    );
    assert_eq!(census_held(&store).slot(sid()), None);
}

/// The attach rule `reserve` and `record_standby` share: a host with a live attach reads `Live`, an unattached host
/// reads `Open` while the volume admits an attach, and `Closed` at `MAX_ATTACHED` live attaches, at `MAX_EVENTS`
/// events with no gone entry, at a next number with no reservation key, or when the pairs and attaches awaiting
/// enrollment reach the owner's pair cap. A full record with a gone entry reads `Open`, and a host whose latest
/// event is a format-2 detach or force-detach reads as format 2 reads it.
/// For the unattached host z, `Closed::of` names the first bound the record stands at in the order live cap, entry
/// cap, pair cap, so a record at two bounds reads the earlier one; `the_closed_cause_follows_the_attach_rule` checks
/// the host-dependent bounds and the key bounds between them.
#[test]
fn the_attach_rule_reads_live_open_and_closed() {
    use crate::failover::standbys::Closed;
    let active = record().active;
    let (x, y, z) = (SPARE + 1, SPARE + 2, SPARE + 3);
    let one = stored_volume(&standby_world(&[x], &[x]), active);
    assert_eq!(Attach::of(&one, host(x), &wide()), Attach::Live);
    assert_eq!(Attach::of(&one, host(z), &wide()), Attach::Open);
    assert_eq!(Attach::of(&one, host(z), &capped(2)), Attach::Closed);
    assert_eq!(Closed::of(&one, host(z), &wide()), None);
    assert_eq!(Closed::of(&one, host(z), &capped(2)), Some(Closed::PairCap));
    let full = stored_volume(&standby_world(&[x, y], &[x, y]), active);
    assert_eq!(Attach::of(&full, host(z), &wide()), Attach::Closed);
    assert_eq!(
        Attach::of(&full, host(x), &wide()),
        Attach::Live,
        "a live enrolled host that is not the newest attach stays a candidate"
    );
    assert_eq!(Closed::of(&full, host(z), &wide()), Some(Closed::LiveCap));
    assert_eq!(
        Closed::of(&full, host(z), &capped(2)),
        Some(Closed::LiveCap),
        "the live cap reads before the pair cap"
    );
    let mut churned = one.clone();
    while churned.events.len() < crate::failover::records::MAX_EVENTS {
        for kind in [EventKind::Detach, EventKind::Attach] {
            churned.push(kind, host(y), ERA);
        }
    }
    churned
        .events
        .truncate(crate::failover::records::MAX_EVENTS);
    assert_eq!(Attach::of(&churned, host(z), &wide()), Attach::Closed);
    assert_eq!(
        Closed::of(&churned, host(z), &wide()),
        Some(Closed::LiveCap),
        "the live cap reads before the entry cap"
    );
    // Each record ends with y detached, so two hosts stay live and the event count alone decides.
    let detached = |events: usize| {
        let mut record = one.clone();
        while record.events.len() < events {
            let kind = if (events - record.events.len()) % 2 == 1 {
                EventKind::Detach
            } else {
                EventKind::Attach
            };
            record.push(kind, host(y), ERA);
        }
        assert_eq!(
            (record.events.len(), record.live_hosts().count()),
            (events, 2)
        );
        assert_eq!(VolumeRecord::decode(&record.encode()), Ok(record.clone()));
        record
    };
    let cap = crate::failover::records::MAX_EVENTS;
    assert_eq!(
        Attach::of(&detached(cap - 1), host(z), &wide()),
        Attach::Open
    );
    assert_eq!(Attach::of(&detached(cap), host(z), &wide()), Attach::Closed);
    assert_eq!(
        Attach::of(&detached(cap - 1), host(y), &wide()),
        Attach::Closed,
        "a host whose latest event is a detach (ATTACH-AFTER-GONE)"
    );
    let mut forced = detached(cap - 3);
    forced.push(EventKind::Force, host(y), ERA);
    assert_eq!(
        Attach::of(&forced, host(y), &wide()),
        Attach::Closed,
        "a host whose latest event is a force-detach (ATTACH-AFTER-GONE)"
    );
    let ended_full = filled_with_ended(&one);
    assert_eq!(
        VolumeRecord::decode(&ended_full.encode()),
        Ok(ended_full.clone())
    );
    assert_eq!(
        Attach::of(&ended_full, host(z), &wide()),
        Attach::Closed,
        "a full record with no gone entry"
    );
    let mut one_gone = ended_full.clone();
    one_gone.events.last_mut().unwrap().kind = EventKind::Gone;
    assert_eq!(
        Attach::of(&one_gone, host(z), &wide()),
        Attach::Open,
        "a full record with a gone entry"
    );
    let mut unbound_gone = one_gone.clone();
    unbound_gone.events.last_mut().unwrap().instance = None;
    assert_eq!(
        Attach::of(&unbound_gone, host(z), &wide()),
        Attach::Closed,
        "a full record whose only gone entry binds no instance"
    );
    let mut hiding = ended_full.clone();
    let hidden = hiding.events.len() - 2;
    let (shadowed, hider) = (hiding.events[hidden].host, hiding.events.len() - 1);
    hiding.events[hidden].kind = EventKind::Attach;
    hiding.events[hidden].instance = None;
    hiding.events[hider].host = shadowed;
    hiding.events[hider].kind = EventKind::Gone;
    assert_eq!(VolumeRecord::decode(&hiding.encode()), Ok(hiding.clone()));
    assert_eq!(
        Attach::of(&hiding, host(z), &wide()),
        Attach::Closed,
        "a full record whose only gone entry hides another host's attach"
    );
    assert_eq!(
        Attach::of(&hiding, shadowed, &wide()),
        Attach::Open,
        "the hidden host's own attach keeps its older attach hidden"
    );
    for kind in [EventKind::Detach, EventKind::Force] {
        let mut closing = hiding.clone();
        closing.events[hidden].kind = kind;
        closing.forced |= kind == EventKind::Force;
        assert_eq!(VolumeRecord::decode(&closing.encode()), Ok(closing.clone()));
        assert_eq!(
            Attach::of(&closing, host(z), &wide()),
            Attach::Closed,
            "a full record whose only gone entry hides another host's {kind:?}"
        );
        assert_eq!(
            Attach::of(&closing, shadowed, &wide()),
            Attach::Open,
            "the host's own attach follows its gone entry over its {kind:?}"
        );
    }
    assert_eq!(
        Closed::of(&detached(cap), host(z), &wide()),
        Some(Closed::EntryCap)
    );
    assert_eq!(
        Closed::of(&detached(cap), host(z), &capped(2)),
        Some(Closed::EntryCap),
        "the entry cap reads before the pair cap"
    );
    assert_eq!(Closed::of(&detached(cap - 1), host(z), &wide()), None);
    let mut ended = one.clone();
    let at = ended.live(host(x)).unwrap();
    let live = ended.events.iter_mut().find(|event| event.seq == at);
    live.unwrap().kind = EventKind::Ended;
    assert_eq!(VolumeRecord::decode(&ended.encode()), Ok(ended.clone()));
    assert_eq!(
        Attach::of(&ended, host(x), &wide()),
        Attach::Closed,
        "an ended entry that is not gone (ATTACH-AFTER-GONE)"
    );
    let mut released = ended.clone();
    released.pairs.retain(|recorded| recorded.attach != at);
    assert_eq!(
        VolumeRecord::decode(&released.encode()),
        Ok(released.clone())
    );
    assert_eq!(
        Attach::of(&released, host(x), &wide()),
        Attach::Closed,
        "an ended entry whose pair dropped"
    );
    let mut gone = released.clone();
    gone.events
        .iter_mut()
        .find(|event| event.seq == at)
        .unwrap()
        .kind = EventKind::Gone;
    assert_eq!(VolumeRecord::decode(&gone.encode()), Ok(gone.clone()));
    assert_eq!(
        Attach::of(&gone, host(x), &wide()),
        Attach::Open,
        "a gone entry's host"
    );
    let mut detached_after = ended.clone();
    detached_after.push(EventKind::Detach, host(x), ERA);
    assert_eq!(
        VolumeRecord::decode(&detached_after.encode()),
        Ok(detached_after.clone())
    );
    assert_eq!(
        Attach::of(&detached_after, host(x), &wide()),
        Attach::Closed,
        "a detach event after the ended entry"
    );
    let mut last = one.clone();
    last.next = u32::MAX - 2;
    assert_eq!(Attach::of(&last, host(z), &wide()), Attach::Open);
    for next in [u32::MAX - 1, u32::MAX] {
        let mut exhausted = one.clone();
        exhausted.next = next;
        assert_eq!(
            VolumeRecord::decode(&exhausted.encode()),
            Ok(exhausted.clone())
        );
        assert_eq!(
            Attach::of(&exhausted, host(z), &wide()),
            Attach::Closed,
            "{next}: the new attach's number has no key"
        );
        assert_eq!(Attach::of(&exhausted, host(x), &wide()), Attach::Live);
    }
    let mut exhausted = one;
    exhausted.next = u32::MAX;
    assert_eq!(
        Closed::of(&exhausted, host(z), &wide()),
        Some(Closed::EntryCap)
    );
    assert_eq!(Closed::of(&last, host(z), &wide()), None);
}

/// `base` filled to `MAX_EVENTS` entries with ended entries of distinct hosts, each bound to its host's instance, so
/// the record holds no gone entry to shed and keeps `base`'s live attaches and pairs.
fn filled_with_ended(base: &VolumeRecord) -> VolumeRecord {
    let room = crate::failover::records::MAX_EVENTS
        .checked_sub(base.events.len())
        .expect("a base within MAX_EVENTS entries");
    let mut full = base.clone();
    for at in 0..room as u64 {
        let h = host(SPARE + 40 + at);
        full.push(EventKind::Attach, h, ERA)
            .expect("a base with an entry number left for each fill");
        let entry = full.events.last_mut().unwrap();
        entry.instance = Some(crate::failover::sim::instance_of_host(h));
        entry.kind = EventKind::Ended;
    }
    full
}

/// `Closed::of` names the first check of the attach rule that fails, and `Attach::of` reads `Closed` exactly where
/// it names one. Each case states its literal attach verdict and cause: one case or more for each of the five
/// bounds, including bounds that depend on the host (a retained `Ended` entry, a latest detach or force-detach) or
/// on the key the attach takes (a next entry number with no key, a next key or a live unenrolled entry's key that a
/// recorded pair holds), and a full record that sheds a gone entry, where no bound applies. The cases that fail two
/// checks pin the order: own-entry before live-cap, live-cap before entry-cap, entry-cap before the next key's
/// bound, and key-taken before pair-cap.
#[test]
fn the_closed_cause_follows_the_attach_rule() {
    use crate::failover::bounds::Bounds;
    use crate::failover::records::attachment_key;
    use crate::failover::standbys::Closed;
    let active = record().active;
    let (x, y, z) = (SPARE + 1, SPARE + 2, SPARE + 3);
    let one = stored_volume(&standby_world(&[x], &[x]), active);
    let full = stored_volume(&standby_world(&[x, y], &[x, y]), active);
    let mut absent = one.clone();
    absent.next = u32::MAX - 1;
    let mut taken = one.clone();
    taken.pairs[0].pair.key = attachment_key(taken.next).unwrap();
    let mut unenrolled = one.clone();
    unenrolled.push(EventKind::Attach, host(y), ERA);
    let seq = unenrolled.live(host(y)).unwrap();
    unenrolled.pairs[0].pair.key = attachment_key(seq).unwrap();
    let mut keyless = one.clone();
    keyless.next = u32::MAX - 1;
    keyless.push(EventKind::Attach, host(y), ERA);
    let mut last_key = one.clone();
    last_key.next = u32::MAX - 2;
    last_key.push(EventKind::Attach, host(y), ERA);
    let mut awaiting = one.clone();
    awaiting.pairs.retain(|recorded| recorded.host != host(x));
    assert_eq!(
        (awaiting.pairs.len(), awaiting.live_hosts().count()),
        (1, 2)
    );
    let ended = ended(&one, x);
    let detached = |base: &VolumeRecord, kind| {
        let mut detached = base.clone();
        detached.push(EventKind::Attach, host(z), ERA);
        detached.push(kind, host(z), ERA);
        detached
    };
    let shed = {
        let mut shed = filled_with_ended(&one);
        shed.events.last_mut().unwrap().kind = EventKind::Gone;
        shed
    };
    let mut unshed = shed.clone();
    unshed.events.last_mut().unwrap().instance = None;
    let mut unshed_taken = unshed.clone();
    unshed_taken.pairs[0].pair.key = attachment_key(unshed_taken.next).unwrap();
    let (open, closed) = (Attach::Open, Attach::Closed);
    type Case = (
        &'static str,
        VolumeRecord,
        u64,
        Bounds,
        Attach,
        Option<Closed>,
    );
    let cases: Vec<Case> = vec![
        ("an open record", one.clone(), z, wide(), open, None),
        (
            "an enrolled live attach",
            one.clone(),
            x,
            capped(2),
            Attach::Live,
            None,
        ),
        (
            "three live attaches",
            full.clone(),
            z,
            wide(),
            closed,
            Some(Closed::LiveCap),
        ),
        (
            "a next number with no key",
            absent,
            z,
            wide(),
            closed,
            Some(Closed::EntryCap),
        ),
        (
            "a next key a recorded pair holds",
            taken.clone(),
            z,
            wide(),
            closed,
            Some(Closed::KeyTaken),
        ),
        (
            "a live unenrolled attach whose key another attach's pair holds",
            unenrolled,
            y,
            wide(),
            closed,
            Some(Closed::KeyTaken),
        ),
        (
            "a retained ended entry",
            ended,
            x,
            wide(),
            closed,
            Some(Closed::OwnEntry),
        ),
        (
            "a latest detach",
            detached(&one, EventKind::Detach),
            z,
            wide(),
            closed,
            Some(Closed::OwnEntry),
        ),
        (
            "a latest force-detach",
            detached(&one, EventKind::Force),
            z,
            wide(),
            closed,
            Some(Closed::OwnEntry),
        ),
        (
            "a full record with no gone entry to shed",
            unshed,
            z,
            wide(),
            closed,
            Some(Closed::EntryCap),
        ),
        (
            "a full record that sheds a gone entry",
            shed,
            z,
            wide(),
            open,
            None,
        ),
        (
            "a pair cap of two",
            one,
            z,
            capped(2),
            closed,
            Some(Closed::PairCap),
        ),
        (
            "a live unenrolled attach whose entry number has no key",
            keyless,
            y,
            wide(),
            closed,
            Some(Closed::EntryCap),
        ),
        (
            "a live unenrolled attach with a free key beside a keyless next number",
            last_key,
            y,
            wide(),
            Attach::Live,
            None,
        ),
        (
            "a recorded pair and an attach awaiting enrollment at a pair cap of two",
            awaiting.clone(),
            z,
            capped(2),
            closed,
            Some(Closed::PairCap),
        ),
        (
            "a recorded pair and an attach awaiting enrollment below a pair cap of three",
            awaiting,
            z,
            capped(3),
            open,
            None,
        ),
        (
            "own-entry before live-cap",
            detached(&full, EventKind::Detach),
            z,
            wide(),
            closed,
            Some(Closed::OwnEntry),
        ),
        (
            "live-cap before entry-cap",
            filled_with_ended(&full),
            z,
            wide(),
            closed,
            Some(Closed::LiveCap),
        ),
        (
            "entry-cap before the next key",
            unshed_taken,
            z,
            wide(),
            closed,
            Some(Closed::EntryCap),
        ),
        (
            "key-taken before pair-cap",
            taken,
            z,
            capped(2),
            closed,
            Some(Closed::KeyTaken),
        ),
    ];
    for (case, volume, candidate, bounds, verdict, cause) in cases {
        assert_eq!(
            VolumeRecord::decode(&volume.encode()),
            Ok(volume.clone()),
            "{case}"
        );
        let candidate = host(candidate);
        assert_eq!(Closed::of(&volume, candidate, &bounds), cause, "{case}");
        assert_eq!(Attach::of(&volume, candidate, &bounds), verdict, "{case}");
    }
}

/// SLOT-RECLAMATION after a failed replacement attach: the owner's designated standby Y is lost, the slot moves to X,
/// X's attach is recorded, and its attach request fails for good. The volume then records three live attaches, so a
/// host Z that was never attached refuses `Closed` at its reservation and `Conflict` at its attach record, each with
/// no write.
#[test]
fn a_failed_replacement_attach_leaves_no_attach_for_a_new_host() {
    let gate = StandbyGate::qualified();
    let cap = Population { cap: 1 };
    let active = record().active;
    let (y, x, z) = (SPARE + 1, SPARE + 2, SPARE + 3);
    let store = standby_world(&[y], &[y]);
    reconciler(&store)
        .designate(&gate, &slot_for(&store, y), active)
        .unwrap();
    reconciler(&store)
        .reserve(&gate, &cap, &wide(), ZONE, sid(), &roomy(host(x)), |h| {
            h == host(y)
        })
        .unwrap();
    reconciler(&store)
        .record_standby(
            &gate,
            sid(),
            active,
            host(x),
            ERA,
            &wide(),
            &crate::failover::sim::binding(host(x)),
        )
        .unwrap();
    let before = (stored(&store), census_held(&store));
    let gone = |h: Host| h == host(x) || h == host(y);
    assert_eq!(
        reconciler(&store).reserve(&gate, &cap, &wide(), ZONE, sid(), &roomy(host(z)), gone),
        Err(ReconcileError::Population(PopulationRefusal::Closed))
    );
    assert_eq!(
        reconciler(&store).record_standby(
            &gate,
            sid(),
            active,
            host(z),
            ERA,
            &wide(),
            &crate::failover::sim::binding(host(z))
        ),
        Err(ReconcileError::Conflict)
    );
    assert_eq!((stored(&store), census_held(&store)), before);
}

/// Restored reconciler journal: a designation whose write has an unknown outcome, retried by a new reconciler
/// process with its own empty watermark log, finds the earlier write when it committed and makes it when it did
/// not, so the record names the host once either way.
#[test]
fn a_restarted_reconciler_converges_on_one_designation() {
    let gate = StandbyGate::qualified();
    let active = record().active;
    for arm in UNKNOWN {
        let store = standby_world(&[SPARE + 1], &[SPARE + 1]);
        let slot = slot_for(&store, SPARE + 1);
        let retried = unknown_then_retry(&store, DESIGNATE_WRITE, arm, || {
            reconciler(&store).designate(&gate, &slot, active)
        })
        .unwrap();
        assert_eq!(retried.value().standby, Some(host(SPARE + 1)), "{arm:?}");
        assert_eq!(
            commits(&store, Key::Shard(sid())),
            2 + 1,
            "{arm:?}: creation, the bump and one designation"
        );
    }
}

/// A designation replay preserves the shard commit count while coverage page 0 still serves the shard record's
/// generation, and returns `Err(ReconcileError::Conflict)` with the count unchanged once page 0 advances past that
/// generation.
#[test]
fn a_designation_replay_refuses_a_volume_that_no_longer_serves() {
    let gate = StandbyGate::qualified();
    let active = record().active;
    let store = standby_world(&[SPARE + 1], &[SPARE + 1]);
    let slot = slot_for(&store, SPARE + 1);
    reconciler(&store).designate(&gate, &slot, active).unwrap();
    let designated = commits(&store, Key::Shard(sid()));
    reconciler(&store).designate(&gate, &slot, active).unwrap();
    assert_eq!(commits(&store, Key::Shard(sid())), designated);
    fence_page(&store, 0, ((record().generation.get() + 1) << 32) | 2);
    assert_eq!(
        reconciler(&store).designate(&gate, &slot, active).map(drop),
        Err(ReconcileError::Conflict)
    );
    assert_eq!(commits(&store, Key::Shard(sid())), designated);
}

/// Shard `sid() + n` of the AZ, owned and activated at `E = 1` on a volume attached to its owner alone, whose record
/// the cap tests reserve for.
fn extra_shard(store: &Shared, n: u32) -> crate::net::ownership::Shard {
    let other = crate::net::ownership::Shard::new(sid().get() + n).unwrap();
    let active = vol(&format!("vol-0d{n}"));
    attach(&mut reconciler(store), active, OWNER);
    let created = ShardRecord {
        shard: other,
        active,
        ..empty()
    };
    let mut owner = client(store);
    let read = owner.create_shard(created).unwrap();
    owner.bump(&read).unwrap();
    other
}

/// `reserve`: census read, shard read, volume read, then the census write.
const RESERVE_WRITE: usize = 3;

/// No enrollment slot, with two reconcilers. When no census exists, both read one free place and the second's
/// reservation runs between the first's census read and its create: the first's create fails its condition, and
/// its retry on a fresh read refuses `Full`. Over an existing census with one free place, the same race fails the
/// first's exact-version write, and its retry refuses `Full`. A candidate without headroom refuses before any census
/// write. An entry whose host holds a live attach of the active volume stays across the owner's bump. Once that
/// attach ends, a reservation that moves the entry between `release`'s census read and its write fails that write's
/// condition and keeps the entry; after the first shard's tenure moves with no standby named, `release` drops the
/// entry and the second reconciler's retry takes the place.
#[test]
fn concurrent_reservations_share_one_census_under_the_cap() {
    let gate = StandbyGate::qualified();
    let live = |_: Host| false;
    let store = standby_world(&[SPARE + 1], &[SPARE + 1]);
    let (other, third) = (extra_shard(&store, 1), extra_shard(&store, 2));
    let starved = crate::failover::standbys::tests::report_of(
        host(SPARE + 1),
        crate::failover::report::Gauge::Unavailable,
        crate::failover::report::Gauge::Unavailable,
    );
    let one = Population { cap: 1 };
    let absent = entry_of(&store, SPARE + 1).unwrap();
    assert_eq!(
        reconciler(&store).release(&gate, ZONE, sid(), absent, |_| false),
        Ok(false),
        "an AZ with no census lists no shard"
    );
    assert_eq!(
        reconciler(&store).reserve(&gate, &one, &wide(), ZONE, sid(), &starved, live),
        Err(ReconcileError::Population(PopulationRefusal::Headroom))
    );
    assert_eq!(commits(&store, Key::Standbys(ZONE)), 0);

    let racing = store.clone();
    let hook = hooked(&store, Key::Standbys(ZONE), Point::BeforeWrite, move || {
        slot_for(&racing, SPARE + 1);
    });
    let mut loser = Reconciler::new(Client::open(AsReconciler(hook), MemLog::default()).unwrap());
    let condition = Err(ReconcileError::Store(StoreError::Refused(
        Refusal::Condition,
    )));
    let candidate = roomy(host(SPARE + 2));
    assert_eq!(
        loser.reserve(&gate, &one, &wide(), ZONE, other, &candidate, live),
        condition
    );
    let full = Err(ReconcileError::Population(PopulationRefusal::Full));
    assert_eq!(
        loser.reserve(&gate, &one, &wide(), ZONE, other, &candidate, live),
        full
    );
    let listed = census_held(&store);
    assert_eq!((listed.len(), listed.slot(other)), (1, None));
    assert!(listed.slot(sid()).is_some());

    let two = Population { cap: 2 };
    let racing = store.clone();
    let hook = hooked(&store, Key::Standbys(ZONE), Point::BeforeWrite, move || {
        reconciler(&racing)
            .reserve(
                &StandbyGate::qualified(),
                &Population { cap: 2 },
                &wide(),
                ZONE,
                third,
                &roomy(host(SPARE + 3)),
                |_| false,
            )
            .unwrap();
    });
    let mut loser = Reconciler::new(Client::open(AsReconciler(hook), MemLog::default()).unwrap());
    assert_eq!(
        loser.reserve(&gate, &two, &wide(), ZONE, other, &candidate, live),
        condition
    );
    assert_eq!(
        loser.reserve(&gate, &two, &wide(), ZONE, other, &candidate, live),
        full
    );
    assert_eq!(census_held(&store).len(), 2);

    assert_eq!(
        reconciler(&store).release(&gate, ZONE, sid(), slot_held(&store), |_| false),
        Ok(true)
    );
    bump(&store);
    assert_eq!(
        reconciler(&store).release(&gate, ZONE, sid(), slot_held(&store), |_| false),
        Ok(true),
        "a host with a live attach of the active volume keeps its entry across the bump"
    );
    edit_volume(&store, record().active, |held| {
        let mut next = ended(held, SPARE + 1);
        next.pairs
            .retain(|recorded| recorded.host != host(SPARE + 1));
        next.fence = next.fence.max((record().generation.get() << 32) | 4);
        next
    });
    edit_volume(&store, record().active, |held| {
        let mut next = held.clone();
        let entry = next
            .events
            .iter_mut()
            .rfind(|event| event.host == host(SPARE + 1));
        entry.unwrap().kind = EventKind::Gone;
        next
    });
    let racing = store.clone();
    let hook = hooked(&store, Key::Standbys(ZONE), Point::BeforeWrite, move || {
        slot_for(&racing, SPARE + 1);
    });
    let mut releasing =
        Reconciler::new(Client::open(AsReconciler(hook), MemLog::default()).unwrap());
    assert_eq!(
        releasing.release(&gate, ZONE, sid(), slot_held(&store), |_| false),
        Err(ReconcileError::Store(StoreError::Refused(
            Refusal::Condition
        )))
    );
    assert_eq!(census_held(&store).slot(sid()), entry_of(&store, SPARE + 1));
    assert_eq!(
        reconciler(&store).release(&gate, ZONE, sid(), slot_held(&store), |_| false),
        Ok(true)
    );
    bump(&store);
    assert_eq!(
        reconciler(&store).release(&gate, ZONE, sid(), slot_held(&store), |_| false),
        Ok(false)
    );
    let slot = loser
        .reserve(&gate, &two, &wide(), ZONE, other, &candidate, live)
        .unwrap();
    assert_eq!((slot.shard(), slot.host()), (other, host(SPARE + 2)));
    let listed = census_held(&store);
    assert_eq!((listed.len(), listed.slot(sid())), (2, None));
}

/// Restored reconciler journal for the reservation: a reservation whose census create or write has an unknown
/// outcome, retried by a new reconciler process, finds the entry when the write committed and writes it when it did
/// not, so the census lists the shard once for its host at its target. A named standby keeps its entry across
/// `release` after the owner's bump, and a later reservation moves the entry to the record's new target in place.
#[test]
fn a_restarted_reconciler_converges_on_one_reservation() {
    let gate = StandbyGate::qualified();
    let cap = Population { cap: 1 };
    let active = record().active;
    for arm in UNKNOWN {
        let store = standby_world(&[SPARE + 1], &[SPARE + 1]);
        let reserve = || {
            reconciler(&store).reserve(
                &gate,
                &cap,
                &wide(),
                ZONE,
                sid(),
                &roomy(host(SPARE + 1)),
                |_| false,
            )
        };
        let slot = unknown_then_retry(&store, RESERVE_WRITE, arm, reserve).unwrap();
        let listed = entry_of(&store, SPARE + 1);
        assert_eq!(
            (Some(slot.target()), census_held(&store).slot(sid())),
            (listed.map(|e| e.target), listed),
            "{arm:?}"
        );
        assert_eq!(commits(&store, Key::Standbys(ZONE)), 1, "{arm:?}");
        reconciler(&store).designate(&gate, &slot, active).unwrap();
        bump(&store);
        assert_eq!(
            reconciler(&store).release(&gate, ZONE, sid(), slot_held(&store), |_| false),
            Ok(true),
            "{arm:?}"
        );
        let moved = unknown_then_retry(&store, RESERVE_WRITE, arm, reserve).unwrap();
        let bumped = Target::of(&shard_held(&store));
        assert_eq!(
            (moved.target(), census_held(&store).len()),
            (bumped, 1),
            "{arm:?}"
        );
        assert_eq!(commits(&store, Key::Standbys(ZONE)), 2, "{arm:?}");
    }
}

pub(crate) use crate::failover::zone_loop::tests::world::Provisioner;

/// The active volume's loss evidence.
fn lost_active() -> (VolumeId, Health) {
    (record().active, Health::Lost)
}

/// The receipt of the shard's replacement after a new reconciler process judges `others` impaired volumes beside
/// the lost active one, for a replacement of `layout`.
fn receipt_of(store: &Shared, others: usize, layout: Layout) -> Read<Receipt> {
    reconciler(store)
        .replacement(
            &StandbyGate::qualified(),
            sid(),
            lost_active(),
            others,
            layout,
        )
        .unwrap()
        .unwrap()
}

/// [`receipt_of`] for the default layout.
fn receipt_after(store: &Shared, others: usize) -> Read<Receipt> {
    receipt_of(store, others, layout())
}

/// A create by a new reconciler process with `others` impaired volumes beside the lost one.
fn create_beside(
    store: &Shared,
    others: usize,
    provider: &mut impl Provider,
) -> Result<Read<VolumeRecord>, ReconcileError> {
    reconciler(store).create_replacement(&StandbyGate::qualified(), sid(), others, provider)
}

fn create(
    store: &Shared,
    provider: &mut impl Provider,
) -> Result<Read<VolumeRecord>, ReconcileError> {
    create_beside(store, 0, provider)
}

/// The retirement witness of `volume`, a replacement no shard role names.
fn retired(store: &Shared, volume: VolumeId) -> Retired {
    reconciler(store).retire(sid(), volume).unwrap()
}

/// A provisioned record of the volume the provider names first, `vol-0c0`, attached to another host before the
/// create, so the create's provisioning finds another value under the returned name.
fn conflicted_world() -> Shared {
    let conflicted = world();
    bump(&conflicted);
    let replacement = vol("vol-0c0");
    reconciler(&conflicted)
        .provision(replacement, layout())
        .unwrap();
    edit_volume(&conflicted, replacement, |held| {
        let mut next = VolumeRecord {
            state: VolumeState::Fresh,
            ..held.clone()
        };
        next.push(EventKind::Attach, host(SPARE + 5), ERA);
        next
    });
    conflicted
}

/// `replacement`: shard read, receipt read, then the receipt write.
const RECEIPT_WRITE: usize = 2;
/// `create_replacement` over an open receipt: receipt read, shard read, then the issue write.
const ISSUE_WRITE: usize = 2;
/// `create_replacement` over an open receipt: receipt read, shard read, issue write, provider call, the volume
/// record's create, then the receipt's volume write.
const CREATED_WRITE: usize = 4;

/// Actual volume loss with a lost create response and restarts. An isolated loss of the active volume writes the
/// replacement's receipt at attempt 1 before the create, and the step marks the attempt issued before it calls the
/// provider. The create's response is lost; a new reconciler process reads the issued receipt and repeats the
/// token, and the provider returns the volume it created, so one volume exists, recorded in the receipt and as a
/// provisioned volume record, and every provider call received the receipt's layout. After `record_attach`, a
/// restarted reconciler's step calls no provider and returns the attached volume record. The attach record, spare
/// naming and flip converge after unknown store outcomes, and the shard flips once to the replacement at `g + 1` and
/// `E = 0` with no standby; a reconciler holding the displaced volume's loss report then retains the shard, and the
/// now active replacement refuses retirement, so no abandon can move the receipt. An impaired volume writes no
/// receipt.
#[test]
fn a_volume_loss_provisions_one_replacement_across_reconciler_restarts() {
    let gate = StandbyGate::qualified();
    let store = world();
    bump(&store);
    let lost = shard_held(&store);
    let wide = Layout {
        units: layout().units + 1,
        ..layout()
    };
    let impaired = (lost.active, Health::Impaired);
    assert_eq!(
        reconciler(&store).replacement(&gate, sid(), impaired, 0, wide),
        Ok(None)
    );
    let Decision::Provision(request) = decide(&lost, lost_active(), 0) else {
        panic!("an isolated loss provisions");
    };
    let mut provider = Provisioner {
        lose: 1,
        ..Provisioner::default()
    };
    let receipt = receipt_of(&store, 0, wide);
    assert_eq!(
        (receipt.value().attempt, receipt.value().phase),
        (1, Phase::Open)
    );
    assert_eq!(
        create(&store, &mut provider),
        Err(ReconcileError::Create(CreateError::Unknown))
    );
    let issued = receipt_of(&store, 0, wide);
    assert_eq!(issued.value().phase, Phase::Issued);
    let recorded = create(&store, &mut provider).unwrap();
    let replacement = recorded.value().volume;
    assert_eq!(provider.created, [(receipt.value().token(), replacement)]);
    assert_eq!(
        provider.layouts,
        [
            (receipt.value().token(), wide),
            (receipt.value().token(), wide)
        ]
    );
    assert_eq!(recorded.value().layout, wide);
    assert_eq!(
        receipt_of(&store, 0, wide).value().phase,
        Phase::Created(replacement)
    );

    let attached = unknown_then_retry(&store, ATTACH_WRITE, Arm::Timeout { commit: true }, || {
        reconciler(&store).record_attach(replacement, host(SPARE), ERA)
    })
    .unwrap();
    let calls = provider.calls;
    let after_attach = create(&store, &mut provider).unwrap();
    assert_eq!(after_attach.value().events.len(), 1, "the attached record");
    assert_eq!(provider.calls, calls, "a recorded volume calls no provider");
    let target = Target::of(&lost);
    unknown_then_retry(&store, NAMING_WRITE, Arm::Timeout { commit: false }, || {
        reconciler(&store).add_spare(sid(), target, &attached)
    })
    .unwrap();
    let flipped = unknown_then_retry(&store, FLIP_WRITE, Arm::Timeout { commit: true }, || {
        reconciler(&store).flip(&gate, sid(), target)
    })
    .unwrap();
    assert_eq!(flipped, Flip::Past);
    let after = shard_held(&store);
    assert_eq!(
        (
            after.generation,
            after.active,
            after.owner,
            after.attempts,
            after.standby
        ),
        (request.generation, replacement, host(SPARE), 0, None)
    );
    assert_eq!(decide(&after, lost_active(), 0), Decision::Retain);
    let created = stored_receipt(&store);
    assert_eq!(
        reconciler(&store).retire(sid(), replacement),
        Err(ReconcileError::Named)
    );
    assert_eq!(
        stored_receipt(&store),
        created,
        "an active volume's failure is a loss to decide"
    );
}

/// The shard's receipt as stored.
fn stored_receipt(store: &Shared) -> Receipt {
    client(store)
        .read::<Receipt>(Key::Replacement(sid()))
        .unwrap()
        .value()
        .clone()
}

/// Restored reconciler journal for the receipt writes: the receipt create, the issue write and the volume write each
/// end with an unknown outcome in one process and converge in the next, whichever way the write went, with one
/// receipt at attempt 1 and one provider volume.
#[test]
fn the_receipt_writes_converge_after_unknown_outcomes() {
    for arm in UNKNOWN {
        let store = world();
        bump(&store);
        unknown_then_retry(&store, RECEIPT_WRITE, arm, || {
            reconciler(&store).replacement(
                &StandbyGate::qualified(),
                sid(),
                lost_active(),
                0,
                layout(),
            )
        })
        .unwrap();
        let mut provider = Provisioner::default();
        park(&store, ISSUE_WRITE, arm);
        assert_eq!(
            create(&store, &mut provider),
            Err(ReconcileError::Store(StoreError::Unknown)),
            "{arm:?}"
        );
        assert_eq!(
            provider.calls, 0,
            "{arm:?}: no create before the issue write"
        );
        park(&store, CREATED_WRITE - usize::from(committed(arm)), arm);
        assert_eq!(
            create(&store, &mut provider),
            Err(ReconcileError::Store(StoreError::Unknown)),
            "{arm:?}"
        );
        let made = create(&store, &mut provider).unwrap();
        let receipt = receipt_after(&store, 0);
        assert_eq!(
            (receipt.value().attempt, receipt.value().phase),
            (1, Phase::Created(made.value().volume)),
            "{arm:?}"
        );
        assert_eq!(provider.created.len(), 1, "{arm:?}");
    }
}

/// A failed create: the provider refuses attempt 1's token for good, so the step raises the receipt to attempt 2,
/// whose new token creates the one volume. A volume that failed after its create is retired and abandoned on the
/// caller's evidence, which opens attempt 3, and a retry of that abandon returns the receipt as it is; attempt 3's
/// create makes another volume. Abandoning a retired volume the receipt does not record, or under another attempt,
/// refuses `Stale`, and abandoning beside another impaired volume opens attempt 4 held, as does a refused create
/// beside one. A volume record of another value under the created volume's name refuses `Conflict` on every repeat,
/// with the receipt still issued.
#[test]
fn a_failed_create_raises_the_attempt_and_the_next_token_creates_the_volume() {
    let gate = StandbyGate::qualified();
    let store = world();
    bump(&store);
    let first = receipt_after(&store, 0);
    let mut provider = Provisioner {
        failed: vec![first.value().token()],
        ..Provisioner::default()
    };
    assert_eq!(
        create(&store, &mut provider),
        Err(ReconcileError::Create(CreateError::Failed))
    );
    let second = receipt_after(&store, 0);
    assert_eq!(
        (second.value().attempt, second.value().phase),
        (2, Phase::Open)
    );
    let made = create(&store, &mut provider).unwrap();
    assert_eq!(
        provider.created,
        [(second.value().token(), made.value().volume)]
    );

    let stray = vol("vol-0e");
    reconciler(&store).provision(stray, layout()).unwrap();
    let before = stored_receipt(&store);
    let earlier = Receipt {
        attempt: 1,
        ..before.clone()
    };
    for (observed, volume) in [
        (&before, retired(&store, stray)),
        (&earlier, retired(&store, made.value().volume)),
    ] {
        assert_eq!(
            reconciler(&store).abandon(&gate, sid(), observed, &volume, 0),
            Err(ReconcileError::Stale),
            "{observed:?}"
        );
    }
    assert_eq!(stored_receipt(&store), before);
    let witness = retired(&store, made.value().volume);
    let third = reconciler(&store)
        .abandon(&gate, sid(), &before, &witness, 0)
        .unwrap();
    assert_eq!(
        (third.value().attempt, third.value().phase),
        (3, Phase::Open)
    );
    assert_eq!(
        reconciler(&store).abandon(&gate, sid(), &before, &witness, 0),
        Ok(third),
        "a retry after the abandon committed"
    );
    let remade = create(&store, &mut provider).unwrap();
    assert_eq!(provider.created.len(), 2);
    assert_ne!(remade.value().volume, made.value().volume);
    let observed = stored_receipt(&store);
    let fourth = reconciler(&store)
        .abandon(
            &gate,
            sid(),
            &observed,
            &retired(&store, remade.value().volume),
            1,
        )
        .unwrap();
    assert_eq!(
        (
            fourth.value().attempt,
            fourth.value().phase,
            fourth.value().held
        ),
        (4, Phase::Open, true)
    );
    let calls = provider.calls;
    assert_eq!(create(&store, &mut provider), Err(ReconcileError::Held));
    assert_eq!(provider.calls, calls);

    let beside = world();
    bump(&beside);
    receipt_after(&beside, 0);
    let mut unused = Provisioner::default();
    assert_eq!(
        create_beside(&beside, 1, &mut unused),
        Err(ReconcileError::Held)
    );
    let latched = stored_receipt(&beside);
    assert_eq!(
        (latched.attempt, latched.phase, latched.held, unused.calls),
        (1, Phase::Open, true, 0),
        "a create passed another impaired volume latches the hold before any provider call"
    );

    let conflicted = conflicted_world();
    receipt_after(&conflicted, 0);
    let before = stored(&conflicted);
    let mut provider = Provisioner::default();
    for repeat in 0..2 {
        assert_eq!(
            create(&conflicted, &mut provider),
            Err(ReconcileError::Conflict),
            "{repeat}"
        );
        assert_eq!(stored_receipt(&conflicted).phase, Phase::Issued, "{repeat}");
    }
    assert_eq!(stored(&conflicted), before);
}

/// A loss at the last generation a replacement can activate: a shard at `2^32 - 2` whose active volume is lost
/// refuses `Exhausted` with no receipt write, alone or beside an impaired volume, and an impaired volume there is
/// retained with no write.
#[test]
fn a_loss_at_the_last_generation_refuses_exhausted() {
    let gate = StandbyGate::qualified();
    let store = Shared::new();
    let last = ShardRecord {
        generation: ShardGeneration::new(u64::from(u32::MAX - 1)).unwrap(),
        ..empty()
    };
    provisioner(&store).create_shard(last).unwrap();
    attach(&mut reconciler(&store), record().active, OWNER);
    bump(&store);
    for others in [0, 1] {
        assert_eq!(
            reconciler(&store).replacement(&gate, sid(), lost_active(), others, layout()),
            Err(ReconcileError::Exhausted),
            "{others}"
        );
    }
    assert_eq!(
        reconciler(&store).replacement(
            &gate,
            sid(),
            (record().active, Health::Impaired),
            0,
            layout()
        ),
        Ok(None)
    );
    assert_eq!(commits(&store, Key::Replacement(sid())), 0);
}

/// Abandon after the shard moved: another spare wins the flip past the lost volume's generation, so the created
/// volume V is retired as unnamed and its abandon refuses `Stale` with the receipt unchanged. Abandon of a created
/// volume the shard names spare follows its removal by `retire_spare`: the receipt opens the next attempt, whose
/// create makes V2, which the shard names spare and flips to, while a stale `add_spare` of V refuses.
#[test]
fn abandon_follows_the_shard_record() {
    let gate = StandbyGate::qualified();
    let store = world();
    bump(&store);
    receipt_after(&store, 0);
    let made = create(&store, &mut Provisioner::default())
        .unwrap()
        .value()
        .volume;
    let observed = stored_receipt(&store);
    let target = Target::of(&shard_held(&store));
    let other = attach(&mut reconciler(&store), vol("vol-0f"), SPARE + 1);
    reconciler(&store).add_spare(sid(), target, &other).unwrap();
    reconciler(&store).flip(&gate, sid(), target).unwrap();
    let witness = retired(&store, made);
    assert_eq!(
        reconciler(&store).abandon(&gate, sid(), &observed, &witness, 0),
        Err(ReconcileError::Stale)
    );
    assert_eq!(stored_receipt(&store), observed);

    let store = world();
    bump(&store);
    receipt_after(&store, 0);
    let mut provider = Provisioner::default();
    let made = create(&store, &mut provider).unwrap().value().volume;
    let observed = stored_receipt(&store);
    let target = Target::of(&shard_held(&store));
    let first = reconciler(&store)
        .record_attach(made, host(SPARE), ERA)
        .unwrap();
    reconciler(&store).add_spare(sid(), target, &first).unwrap();
    let witness = reconciler(&store)
        .retire_spare(sid(), &drop_request(made, target))
        .unwrap();
    assert_eq!(shard_held(&store).spare, None);
    let next = reconciler(&store)
        .abandon(&gate, sid(), &observed, &witness, 0)
        .unwrap();
    assert_eq!((next.value().attempt, next.value().phase), (2, Phase::Open));
    let remade = create(&store, &mut provider).unwrap().value().volume;
    assert_ne!(remade, made);
    let second = reconciler(&store)
        .record_attach(remade, host(SPARE + 1), ERA)
        .unwrap();
    assert_eq!(
        reconciler(&store).add_spare(sid(), target, &first),
        Err(ReconcileError::Conflict),
        "the retired volume is no spare again"
    );
    reconciler(&store)
        .add_spare(sid(), target, &second)
        .unwrap();
    assert!(matches!(
        reconciler(&store).flip(&gate, sid(), target),
        Ok(Flip::Flipped(_))
    ));
    assert_eq!(shard_held(&store).active, remade);
}

/// An issued attempt keeps its receipt after another spare's flip passes its generation, since its create may have
/// made a volume: after a lost response, or after a hold that latched during the create and was released. A later
/// generation's receipt waits until the earlier attempt's volume is recorded and retired, and a repeat of the create
/// over the recorded volume returns `Stale` again and leaves the provider's call count unchanged.
#[test]
fn an_attempt_issued_before_another_spare_flipped_is_recorded_before_a_later_receipt() {
    let gate = StandbyGate::qualified();
    for latched in [false, true] {
        let store = world();
        bump(&store);
        receipt_after(&store, 0);
        let mut provider = if latched {
            let mut latching = Latching {
                store: store.clone(),
                inner: Provisioner::default(),
            };
            assert_eq!(
                create(&store, &mut latching),
                Err(ReconcileError::Store(StoreError::Refused(
                    Refusal::Condition
                )))
            );
            reconciler(&store)
                .release_hold(
                    &OperatorRelease::diagnosed(),
                    stored_receipt(&store).request,
                )
                .unwrap();
            latching.inner
        } else {
            let mut lossy = Provisioner {
                lose: 1,
                ..Provisioner::default()
            };
            assert_eq!(
                create(&store, &mut lossy),
                Err(ReconcileError::Create(CreateError::Unknown))
            );
            lossy
        };
        let target = Target::of(&shard_held(&store));
        let other = attach(&mut reconciler(&store), vol("vol-0f"), SPARE + 1);
        reconciler(&store).add_spare(sid(), target, &other).unwrap();
        reconciler(&store).flip(&gate, sid(), target).unwrap();
        let unresolved = stored_receipt(&store);
        let spare_lost = (vol("vol-0f"), Health::Lost);
        let later = || reconciler(&store).replacement(&gate, sid(), spare_lost, 0, layout());
        assert_eq!(later(), Err(ReconcileError::Conflict), "{latched}");
        assert_eq!(stored_receipt(&store), unresolved, "{latched}");

        assert_eq!(
            create(&store, &mut provider),
            Err(ReconcileError::Stale),
            "{latched}"
        );
        let [(token, made)] = provider.created.clone().try_into().unwrap();
        assert_eq!(token, unresolved.token(), "{latched}");
        assert_eq!(
            stored_receipt(&store).phase,
            Phase::Created(made),
            "{latched}"
        );
        assert_eq!(
            stored_volume(&store, made).state,
            VolumeState::Provisioning,
            "{latched}"
        );
        assert_eq!(later(), Err(ReconcileError::Conflict), "{latched}");
        let calls = provider.calls;
        assert_eq!(
            create(&store, &mut provider),
            Err(ReconcileError::Stale),
            "a repeat over the recorded volume, {latched}"
        );
        assert_eq!(provider.calls, calls, "{latched}");
        retired(&store, made);
        let started = later().unwrap().unwrap();
        let next = ShardGeneration::new(shard_held(&store).generation.get() + 1).unwrap();
        assert_eq!(
            (
                started.value().request.generation,
                started.value().attempt,
                started.value().phase
            ),
            (next, 1, Phase::Open),
            "{latched}"
        );
        assert_eq!(provider.created.len(), 1, "{latched}");
    }
}

/// The attempt counter's last value: a refused create of an issued receipt at attempt `u32::MAX` and the abandon of
/// a created one refuse `Conflict` with the receipt unchanged.
#[test]
fn the_last_attempt_refuses_another() {
    let gate = StandbyGate::qualified();
    for phase in [Phase::Issued, Phase::Created(vol("vol-0c0"))] {
        let store = world();
        bump(&store);
        let last = Receipt {
            attempt: u32::MAX,
            phase,
            ..receipt_after(&store, 0).value().clone()
        };
        let read = client(&store)
            .read::<Receipt>(Key::Replacement(sid()))
            .unwrap();
        client(&store).replace(&read, last.clone()).unwrap();
        let result = match phase {
            Phase::Issued => create(
                &store,
                &mut Provisioner {
                    failed: vec![last.token()],
                    ..Provisioner::default()
                },
            )
            .map(drop),
            _ => {
                reconciler(&store)
                    .provision(vol("vol-0c0"), layout())
                    .unwrap();
                let witness = retired(&store, vol("vol-0c0"));
                reconciler(&store)
                    .abandon(&gate, sid(), &last, &witness, 0)
                    .map(drop)
            }
        };
        assert_eq!(result, Err(ReconcileError::Conflict), "{phase:?}");
        assert_eq!(stored_receipt(&store), last, "{phase:?}");
    }
}

/// The create returns each of these errors at its read and leaves the stored receipt and the provider's call count
/// unchanged: `Layout` for an open receipt whose layout is below the floor, and `Stale` for an open receipt, or one
/// that records its volume, whose generation the shard record already holds.
#[test]
fn a_create_refuses_a_receipt_below_the_floor_or_past_its_generation() {
    for (name, edit, refusal) in [
        (
            "below the floor",
            (|receipt: &Receipt| Receipt {
                layout: Layout {
                    units: 1,
                    ..receipt.layout
                },
                ..receipt.clone()
            }) as fn(&Receipt) -> Receipt,
            ReconcileError::Layout(
                Layout {
                    units: 1,
                    ..layout()
                }
                .check_floor()
                .unwrap_err(),
            ),
        ),
        (
            "past its generation",
            |receipt: &Receipt| Receipt {
                request: Request {
                    generation: record().generation,
                    ..receipt.request
                },
                ..receipt.clone()
            },
            ReconcileError::Stale,
        ),
        (
            "created and past its generation",
            |receipt: &Receipt| Receipt {
                request: Request {
                    generation: record().generation,
                    ..receipt.request
                },
                phase: Phase::Created(record().active),
                ..receipt.clone()
            },
            ReconcileError::Stale,
        ),
    ] {
        let store = world();
        bump(&store);
        let stale = edit(&crate::failover::loss::tests::receipt());
        client(&store)
            .create(Key::Replacement(sid()), stale.clone())
            .unwrap();
        let mut provider = Provisioner::default();
        assert_eq!(create(&store, &mut provider), Err(refusal), "{name}");
        assert_eq!(provider.calls, 0, "{name}");
        assert_eq!(stored_receipt(&store), stale, "{name}");
        assert_eq!(commits(&store, Key::Replacement(sid())), 1, "{name}");
    }
}

/// CORRELATED-HOLD latches. A loss beside another impaired volume writes a held receipt, and the create refuses
/// `Held` with no provider call; a restarted reconciler deciding `Provision` after the impairment cleared keeps it
/// held. The operator's release opens it and marks it released, so a later hold of the same replacement, the AZ
/// still impaired, leaves it open and the create makes the one volume, and an abandon of that volume beside an
/// impaired volume opens the next attempt unheld. An open receipt that a later hold reaches latches whatever layout
/// the deciding reconciler passes. A release of a receipt that is not held returns it as it is, so a later hold still
/// latches it. Over a held receipt, a layout other than the receipt's refuses `Conflict`; a release of another
/// replacement refuses `Stale`; and a new receipt of a layout below the floor refuses `Layout` with no write.
#[test]
fn a_correlated_hold_latches_until_the_operator_releases_it() {
    let gate = StandbyGate::qualified();
    let store = world();
    bump(&store);
    let mut provider = Provisioner::default();
    for others in [1, 0] {
        let held = receipt_after(&store, others);
        assert_eq!(
            (held.value().phase, held.value().held),
            (Phase::Open, true),
            "{others}"
        );
        assert_eq!(create(&store, &mut provider), Err(ReconcileError::Held));
    }
    assert_eq!(provider.calls, 0);
    let held = receipt_after(&store, 1);
    let release = OperatorRelease::diagnosed();
    let mut other = held.value().request;
    other.generation = ShardGeneration::new(other.generation.get() + 1).unwrap();
    assert_eq!(
        reconciler(&store).release_hold(&release, other),
        Err(ReconcileError::Stale)
    );
    let released = reconciler(&store)
        .release_hold(&release, held.value().request)
        .unwrap();
    assert_eq!(
        (released.value().phase, released.value().released),
        (Phase::Open, true)
    );
    assert_eq!(receipt_after(&store, 1).value().phase, Phase::Open);
    let made = create_beside(&store, 1, &mut provider).unwrap();
    assert_eq!(provider.created.len(), 1);
    let observed = stored_receipt(&store);
    let reopened = reconciler(&store)
        .abandon(
            &gate,
            sid(),
            &observed,
            &retired(&store, made.value().volume),
            1,
        )
        .unwrap();
    assert_eq!(
        (
            reopened.value().attempt,
            reopened.value().phase,
            reopened.value().released
        ),
        (2, Phase::Open, true)
    );
    assert_eq!(receipt_after(&store, 1).value().phase, Phase::Open);

    let store = world();
    bump(&store);
    let wider = Layout {
        units: layout().units + 1,
        ..layout()
    };
    let open = receipt_after(&store, 0);
    assert_eq!(open.value().phase, Phase::Open);
    assert_eq!(
        reconciler(&store).release_hold(&release, open.value().request),
        Ok(open),
        "a receipt that is not held returns as it is"
    );
    let latched = receipt_of(&store, 1, wider);
    assert_eq!(
        (
            latched.value().phase,
            latched.value().held,
            latched.value().layout
        ),
        (Phase::Open, true, layout())
    );
    assert_eq!(
        create(&store, &mut Provisioner::default()),
        Err(ReconcileError::Held)
    );
    assert_eq!(
        reconciler(&store).replacement(&gate, sid(), lost_active(), 1, wider),
        Err(ReconcileError::Conflict)
    );

    let store = world();
    bump(&store);
    let below = Layout {
        units: 1,
        ..layout()
    };
    assert_eq!(
        reconciler(&store).replacement(&gate, sid(), lost_active(), 0, below),
        Err(ReconcileError::Layout(below.check_floor().unwrap_err()))
    );
    assert_eq!(commits(&store, Key::Replacement(sid())), 0);
}

/// CORRELATED-HOLD after the create finished: a hold decided over a receipt that records the created volume latches
/// it, keeping the volume, so the create returns `Held` and no volume record while it holds, and neither the spare
/// naming nor the flip advances the held volume: a hold latched before `add_spare` makes it refuse `Held`, and one
/// latched after it makes `flip` refuse `Held`, each with the shard record unchanged. The operator's release returns
/// the receipt to its volume, the create then returns that volume record with no provider call, and the spare naming
/// and the flip proceed. An abandon of the held volume refuses `Held` with the receipt unchanged.
#[test]
fn a_hold_latches_over_a_created_volume_until_the_release() {
    for named_first in [false, true] {
        let store = world();
        bump(&store);
        receipt_after(&store, 0);
        let mut provider = Provisioner::default();
        let made = create(&store, &mut provider).unwrap().value().volume;
        let attached = reconciler(&store)
            .record_attach(made, host(SPARE), ERA)
            .unwrap();
        let target = Target::of(&shard_held(&store));
        if named_first {
            reconciler(&store)
                .add_spare(sid(), target, &attached)
                .unwrap();
        }
        let held = receipt_after(&store, 1);
        assert_eq!(
            (held.value().phase, held.value().held),
            (Phase::Created(made), true)
        );
        assert_eq!(create(&store, &mut provider), Err(ReconcileError::Held));
        let before = shard_held(&store);
        let refused = if named_first {
            reconciler(&store)
                .flip(&StandbyGate::qualified(), sid(), target)
                .map(drop)
        } else {
            reconciler(&store)
                .add_spare(sid(), target, &attached)
                .map(drop)
        };
        assert_eq!(refused, Err(ReconcileError::Held), "{named_first}");
        assert_eq!(shard_held(&store), before, "{named_first}");
        let released = reconciler(&store)
            .release_hold(&OperatorRelease::diagnosed(), held.value().request)
            .unwrap();
        assert_eq!(
            (released.value().phase, released.value().released),
            (Phase::Created(made), true)
        );
        let calls = provider.calls;
        assert_eq!(create(&store, &mut provider).unwrap().value().volume, made);
        assert_eq!(provider.calls, calls);
        if !named_first {
            reconciler(&store)
                .add_spare(sid(), target, &attached)
                .unwrap();
        }
        assert!(matches!(
            reconciler(&store).flip(&StandbyGate::qualified(), sid(), target),
            Ok(Flip::Flipped(_))
        ));
        assert_eq!(shard_held(&store).active, made, "{named_first}");
    }

    let store = world();
    bump(&store);
    receipt_after(&store, 0);
    let made = create(&store, &mut Provisioner::default())
        .unwrap()
        .value()
        .volume;
    let observed = stored_receipt(&store);
    let held = receipt_after(&store, 1).value().clone();
    let witness = retired(&store, made);
    assert_eq!(
        reconciler(&store).abandon(&StandbyGate::qualified(), sid(), &observed, &witness, 0),
        Err(ReconcileError::Held),
        "an abandon under the hold"
    );
    assert_eq!(stored_receipt(&store), held);
}

/// CREATE-AFTER-ISSUE: a reconciler reads an open receipt, and another latches a hold before its issue write. The
/// issue write fails its condition, the provider receives no create, and the receipt stays held.
#[test]
fn a_hold_latched_before_the_issue_write_stops_the_create() {
    let store = world();
    bump(&store);
    receipt_after(&store, 0);
    let latching = store.clone();
    let hook = hooked(
        &store,
        Key::Replacement(sid()),
        Point::BeforeWrite,
        move || {
            receipt_after(&latching, 1);
        },
    );
    let mut racing = Reconciler::new(Client::open(AsReconciler(hook), MemLog::default()).unwrap());
    let mut provider = Provisioner::default();
    assert_eq!(
        racing.create_replacement(&StandbyGate::qualified(), sid(), 0, &mut provider),
        Err(ReconcileError::Store(StoreError::Refused(
            Refusal::Condition
        )))
    );
    assert_eq!(provider.calls, 0);
    let held = receipt_after(&store, 0);
    assert_eq!((held.value().phase, held.value().held), (Phase::Open, true));
}

/// A provider double that latches a correlated hold of the shard's replacement while its create is in flight.
struct Latching {
    store: Shared,
    inner: Provisioner,
}

impl Provider for Latching {
    fn create(&mut self, token: &str, layout: Layout) -> Result<VolumeId, CreateError> {
        receipt_after(&self.store, 1);
        self.inner.create(token, layout)
    }
}

/// CORRELATED-HOLD over an issued attempt: a hold latches while the create is in flight, so the step's attempt raise
/// after a refused create, or its volume write after a made one, fails its condition and the receipt stays held at
/// attempt 1. The next create refuses `Held` with no provider call. After the release, attempt 1 repeats its token:
/// the refused one raises the attempt and attempt 2 creates the volume, and the made one returns its volume, so the
/// provider holds one volume either way.
#[test]
fn a_hold_latched_while_an_attempt_is_issued_stops_the_next_create() {
    for refused in [true, false] {
        let store = world();
        bump(&store);
        let token = receipt_after(&store, 0).value().token();
        let mut latching = Latching {
            store: store.clone(),
            inner: Provisioner {
                failed: if refused { vec![token] } else { Vec::new() },
                ..Provisioner::default()
            },
        };
        assert_eq!(
            create(&store, &mut latching),
            Err(ReconcileError::Store(StoreError::Refused(
                Refusal::Condition
            ))),
            "{refused}"
        );
        let held = stored_receipt(&store);
        assert_eq!(
            (held.attempt, held.phase, held.held),
            (1, Phase::Issued, true),
            "{refused}"
        );
        let mut provider = latching.inner;
        assert_eq!(
            create(&store, &mut provider),
            Err(ReconcileError::Held),
            "{refused}"
        );
        assert_eq!(provider.calls, 1, "{refused}");
        reconciler(&store)
            .release_hold(&OperatorRelease::diagnosed(), held.request)
            .unwrap();
        if refused {
            assert_eq!(
                create(&store, &mut provider),
                Err(ReconcileError::Create(CreateError::Failed))
            );
            assert_eq!(stored_receipt(&store).attempt, 2);
        }
        let made = create(&store, &mut provider).unwrap();
        assert_eq!(provider.created.len(), 1, "{refused}");
        assert_eq!(provider.created[0].1, made.value().volume, "{refused}");
        assert_eq!(
            stored_receipt(&store).phase,
            Phase::Created(made.value().volume),
            "{refused}"
        );
    }
}

/// A provider double that, while its create is in flight, lets another reconciler finish the same issued create and
/// its caller run `record_attach`, then answers as `inner` does.
struct Finishing {
    store: Shared,
    inner: Provisioner,
}

impl Provider for Finishing {
    fn create(&mut self, token: &str, layout: Layout) -> Result<VolumeId, CreateError> {
        let made = create(&self.store, &mut self.inner).unwrap();
        reconciler(&self.store)
            .record_attach(made.value().volume, host(SPARE), ERA)
            .unwrap();
        self.inner.create(token, layout)
    }
}

/// Two reconcilers repeat one issued create. Reconciler A finishes it and its caller runs `record_attach` while B's
/// create is in flight, so B's provisioning finds the attached record and refuses `Conflict`; B then reads the
/// receipt recording the same volume and returns the attached record. A hold latched while B's create is in flight
/// over a foreign record under the returned name refuses `Stale`, since the receipt moved off B's read.
#[test]
fn a_duplicate_of_a_finished_create_returns_the_recorded_volume() {
    let store = world();
    bump(&store);
    receipt_after(&store, 0);
    let mut lossy = Provisioner {
        lose: 1,
        ..Provisioner::default()
    };
    assert_eq!(
        create(&store, &mut lossy),
        Err(ReconcileError::Create(CreateError::Unknown))
    );
    let mut finishing = Finishing {
        store: store.clone(),
        inner: lossy,
    };
    let duplicate = create(&store, &mut finishing).unwrap();
    assert_eq!(duplicate.value().events.len(), 1, "the attached record");
    assert_eq!(finishing.inner.created.len(), 1);
    assert_eq!(
        stored_receipt(&store).phase,
        Phase::Created(duplicate.value().volume)
    );

    let conflicted = conflicted_world();
    receipt_after(&conflicted, 0);
    let mut latching = Latching {
        store: conflicted.clone(),
        inner: Provisioner::default(),
    };
    assert_eq!(
        create(&conflicted, &mut latching),
        Err(ReconcileError::Stale)
    );
    let held = stored_receipt(&conflicted);
    assert_eq!((held.phase, held.held), (Phase::Issued, true));
}

/// A decision for a later generation over an earlier generation's held receipt starts that generation's receipt from
/// its own evidence, open for an isolated loss; a decision for an earlier generation than the receipt's refuses the
/// successor write.
#[test]
fn a_later_generation_starts_its_own_receipt() {
    let store = world();
    bump(&store);
    let current = receipt_after(&store, 0).value().clone();
    let earlier = Receipt {
        request: Request {
            generation: shard_held(&store).generation,
            ..current.request
        },
        held: true,
        ..current.clone()
    };
    let later = Receipt {
        request: Request {
            generation: ShardGeneration::new(current.request.generation.get() + 1).unwrap(),
            ..current.request
        },
        ..current.clone()
    };
    for (stored_receipt, expected) in [
        (earlier, Ok(Phase::Open)),
        (
            later,
            Err(ReconcileError::Store(StoreError::Successor(
                crate::failover::records::SuccessorRule::State,
            ))),
        ),
    ] {
        let store = world();
        bump(&store);
        client(&store)
            .create(Key::Replacement(sid()), stored_receipt)
            .unwrap();
        let result = reconciler(&store)
            .replacement(&StandbyGate::qualified(), sid(), lost_active(), 0, layout())
            .map(|read| read.unwrap().value().phase);
        assert_eq!(result, expected);
    }
}

/// A flip from `E = 1` whose shard write is delayed past a standby's reads, which follow the flip's active mark on
/// the displaced volume, and applies before the standby's volume write. The attach and the enrollment each return
/// no witness once the shard record names another volume active, so the standby makes no attach request and no
/// Register on the displaced volume (admitted-set-enrollment-is-not-ownership: a standby's attach record and
/// enrollment wait for a page-0 fence of the shard record's generation; [`StandbyRecorded`] and [`enroll_standby`]
/// act on the shard's active volume). The same holds after an earlier flip that did not commit, which leaves the
/// displaced volume active, so the next flip leaves that volume's record unchanged.
#[test]
fn a_standby_write_across_a_committed_flip_returns_no_witness() {
    use crate::failover::poll::Holder;
    use crate::failover::reconcile::{StandbyRefusal, enroll_standby};
    let gate = StandbyGate::qualified();
    let active = record().active;
    let standby = Holder {
        volume: active,
        host: host(SPARE + 1),
        instance: crate::failover::sim::instance_of_host(host(SPARE + 1)),
    };
    let own = crate::failover::evidence_tests::pair(2, 1, 2);
    for (name, earlier_flip) in [
        ("one flip", false),
        ("after a flip that did not commit", true),
    ] {
        for enrollment in [false, true] {
            let (store, _) = spared();
            if earlier_flip {
                park(&store, FLIP_WRITE, Arm::Timeout { commit: false });
                assert_eq!(
                    reconciler(&store).flip(&gate, sid(), Target::of(&stored(&store).1)),
                    Err(ReconcileError::Store(StoreError::Unknown)),
                    "{name}"
                );
            }
            edit_volume(&store, active, |held| {
                held.enroll(
                    host(OWNER),
                    crate::failover::evidence_tests::pair(1, 1, 1),
                    &wide(),
                )
                .unwrap()
                .unwrap()
            });
            bump(&store);
            fence_page(&store, 0, (record().generation.get() << 32) | 2);
            if enrollment {
                reconciler(&store)
                    .record_standby(
                        &gate,
                        sid(),
                        active,
                        standby.host,
                        2,
                        &wide(),
                        &crate::failover::sim::binding(standby.host),
                    )
                    .unwrap();
            }
            // A displaced volume already active takes no active mark, so the flip's shard write comes one request
            // earlier.
            let flip_write = FLIP_WRITE - usize::from(earlier_flip);
            let marks = commits(&store, Key::Volume(active));
            park(&store, flip_write, Arm::Hold);
            assert_eq!(
                reconciler(&store).flip(&gate, sid(), Target::of(&stored(&store).1)),
                Err(ReconcileError::Store(StoreError::Unknown)),
                "{name}: the flip's shard write is parked"
            );
            assert_eq!(
                commits(&store, Key::Volume(active)),
                marks + usize::from(!earlier_flip),
                "{name}: the flip marks the displaced volume only when it is not yet active"
            );
            assert_eq!(stored(&store).1.active, active, "{name}");
            let racing = store.clone();
            let mut client = Client::open(
                AsReconciler(hooked(
                    &store,
                    Key::Volume(active),
                    Point::BeforeWrite,
                    move || {
                        racing.release();
                    },
                )),
                MemLog::default(),
            )
            .unwrap();
            let witnessed = if enrollment {
                enroll_standby(&gate, sid(), &standby, &wide(), &mut client, |_| {
                    Ok(standby_record(standby.instance.as_str(), own))
                })
                .map(|_| ())
                .map_err(|refusal| assert_eq!(refusal, StandbyRefusal::Tenure, "{name}"))
            } else {
                Reconciler::new(client)
                    .record_standby(
                        &gate,
                        sid(),
                        active,
                        standby.host,
                        2,
                        &wide(),
                        &crate::failover::sim::binding(standby.host),
                    )
                    .map(|_| ())
                    .map_err(|error| assert_eq!(error, ReconcileError::Conflict, "{name}"))
            };
            let shard = stored(&store).1;
            assert_ne!(shard.active, active, "{name}: the parked flip applied");
            assert!(
                witnessed.is_err(),
                "{name}, enrollment {enrollment}: a standby witness on {active:?} while the shard record names {:?} \
                 active at generation {} and page 0 holds no fence of it",
                shard.active,
                shard.generation.get()
            );
            assert_eq!(
                commits(&store, Key::Volume(active)),
                marks + usize::from(!earlier_flip) + 1,
                "{name}, enrollment {enrollment}: the refused step's volume write committed"
            );
            let written = stored_volume(&store, active);
            assert!(
                written.live(standby.host).is_some(),
                "{name}, enrollment {enrollment}: the displaced volume's record holds the standby's attach event"
            );
            assert_eq!(
                written.enrolled(standby.host),
                enrollment.then_some(own),
                "{name}, enrollment {enrollment}: the displaced volume's record holds the standby's pair exactly when \
                 the refused step is its enrollment"
            );
            let settled = commits(&store, Key::Volume(active));
            if enrollment {
                let mut retry =
                    Client::open(AsReconciler(store.clone()), MemLog::default()).unwrap();
                assert_eq!(
                    enroll_standby(&gate, sid(), &standby, &wide(), &mut retry, |_| {
                        panic!("a retry on the displaced volume refuses before persist")
                    }),
                    Err(StandbyRefusal::Tenure),
                    "{name}: the enrollment's retry"
                );
            } else {
                assert_eq!(
                    reconciler(&store).record_standby(
                        &gate,
                        sid(),
                        active,
                        standby.host,
                        2,
                        &wide(),
                        &crate::failover::sim::binding(standby.host)
                    ),
                    Err(ReconcileError::Conflict),
                    "{name}: the attach's retry"
                );
            }
            assert_eq!(
                commits(&store, Key::Volume(active)),
                settled,
                "{name}, enrollment {enrollment}: the retry of the refused step writes nothing"
            );
        }
    }
}

/// The retirement step a case enters by.
#[derive(Debug, Clone, Copy)]
enum Step {
    Retire,
    RetireSpare,
}

/// [`world`] after another writer recorded its active volume in `state`; the shard record still names that volume
/// active.
fn active_volume_recorded(state: VolumeState) -> Shared {
    let store = world();
    edit_volume(&store, record().active, |held| VolumeRecord {
        state,
        ..held.clone()
    });
    store
}

/// Runs `step` for the active volume recorded in `state` and asserts the refusal, then that the shard record keeps
/// its commit count, version and value and the volume record its commit count and state, each read before the step.
fn settling_refuses_the_active_volume(step: Step, state: VolumeState) {
    let case = format!("{step:?} of a volume recorded {state:?}");
    let store = active_volume_recorded(state);
    let active = record().active;
    assert_eq!(
        stored_volume(&store, active).state,
        state,
        "{case}: the volume record"
    );
    let before = stored(&store);
    assert_eq!(before.1.active, active, "{case}: the shard names it active");
    let (shard, volume) = (
        commits(&store, Key::Shard(sid())),
        commits(&store, Key::Volume(active)),
    );

    let mut reconciler = reconciler(&store);
    let result = match step {
        Step::Retire => reconciler.retire(sid(), active),
        Step::RetireSpare => {
            let request = drop_request(active, Target::of(&before.1));
            reconciler.retire_spare(sid(), &request)
        }
    };
    assert_eq!(
        result.map(drop),
        Err(ReconcileError::Named),
        "{case}: the step refuses Named and returns no Retired witness"
    );
    assert_eq!(
        commits(&store, Key::Shard(sid())),
        shard,
        "{case}: no shard write"
    );
    assert_eq!(stored(&store), before, "{case}: the shard record stands");
    assert_eq!(
        commits(&store, Key::Volume(active)),
        volume,
        "{case}: no volume write"
    );
    assert_eq!(
        stored_volume(&store, active).state,
        state,
        "{case}: the volume record stands"
    );
}

/// `retire` takes a volume whose record shows it retired straight to the settling step, which reads the shard record
/// and refuses [`ReconcileError::Named`] ahead of its write while that record names the volume active: a [`Retired`]
/// witness comes only from a shard write that names the volume in no role (RETIRED-IS-FINAL). The refused step
/// leaves the shard record and the volume record at the commit counts read before it.
#[test]
fn retire_refuses_a_retired_volume_the_shard_record_names_active() {
    settling_refuses_the_active_volume(Step::Retire, VolumeState::Retired);
}

/// A deleted volume takes the same path through `retire` as a retired one: the settling step refuses
/// [`ReconcileError::Named`] ahead of its write while the shard record names the volume active, and both records
/// keep their commit counts.
#[test]
fn retire_refuses_a_deleted_volume_the_shard_record_names_active() {
    settling_refuses_the_active_volume(Step::Retire, VolumeState::Deleted);
}

/// `retire_spare` takes a retired volume to the settling step ahead of its own check of the active volume and of
/// the spare's removal, so the settling step's check of its shard read is the one that refuses
/// [`ReconcileError::Named`] for the volume the shard record names active. Both records keep their commit counts.
#[test]
fn retire_spare_refuses_a_retired_volume_the_shard_record_names_active() {
    settling_refuses_the_active_volume(Step::RetireSpare, VolumeState::Retired);
}

/// `retire_spare` of a deleted volume the shard record names active refuses [`ReconcileError::Named`] at the
/// settling step's check of its shard read, as for a retired one, and both records keep their commit counts.
#[test]
fn retire_spare_refuses_a_deleted_volume_the_shard_record_names_active() {
    settling_refuses_the_active_volume(Step::RetireSpare, VolumeState::Deleted);
}

/// The owner's verified instance in these tests.
const OWNER_INSTANCE: &str = "i-0123456789abcdef0";

/// A standby attach record's binding for `h` that also binds the owner's live entry, with `listing`.
fn binding_of<'a>(
    h: u64,
    owner: &'a [crate::failover::attachments::Peer],
    listing: Option<&'a [String]>,
) -> crate::failover::reconcile::Binding<'a> {
    crate::failover::reconcile::Binding {
        unbound: owner,
        listing,
        ..crate::failover::sim::binding(host(h))
    }
}

fn owner_peer() -> [crate::failover::attachments::Peer; 1] {
    [crate::failover::attachments::Peer {
        host: host(OWNER),
        instance: crate::failover::attachments::InstanceId::new(OWNER_INSTANCE).unwrap(),
    }]
}

/// BIND-AT-ATTACH: a standby's attach entry takes `seq = next` and the host's instance, the owner's live entry,
/// recorded without one, gains its instance in the same write, and the record is format 3; a retry writes nothing
/// and returns the witness, and a retry under another instance conflicts. The owner's poll, with no caller-bound
/// peer, then continues over a listing that shows the standby's instance. Control: the same entry recorded without
/// its instance retires that poll on the standby's listed attachment.
#[test]
fn a_standby_attach_entry_binds_its_instance_and_the_owners() {
    use crate::failover::poll::{Holder, Reads, Verdict, poll};
    use crate::failover::sim::instance_of_host;
    let gate = StandbyGate::qualified();
    let active = record().active;
    let store = activated();
    bump(&store);
    let owner = owner_peer();
    let before = stored_volume(&store, active);
    assert_eq!(before.events[0].instance, None);
    let unwritten = commits(&store, Key::Volume(active));
    let unreadable = vec![OWNER_INSTANCE.to_owned(), "i-NOT-AN-ID".to_owned()];
    let blank = vec![OWNER_INSTANCE.to_owned(), String::new()];
    let shown = vec![
        OWNER_INSTANCE.to_owned(),
        instance_of_host(host(SPARE)).as_str().to_owned(),
    ];
    for (rows, what) in [
        (&unreadable, "a listing row that is no instance ID"),
        (&blank, "an empty listing row"),
        (&shown, "the listing already shows the new entry's instance"),
    ] {
        assert_eq!(
            reconciler(&store)
                .record_standby(
                    &gate,
                    sid(),
                    active,
                    host(SPARE),
                    ERA,
                    &wide(),
                    &binding_of(SPARE, &owner, Some(rows)),
                )
                .map(drop),
            Err(ReconcileError::Conflict),
            "{what}, on a record with room"
        );
    }
    assert_eq!(commits(&store, Key::Volume(active)), unwritten);
    assert_eq!(stored_volume(&store, active), before);
    reconciler(&store)
        .record_standby(
            &gate,
            sid(),
            active,
            host(SPARE),
            ERA,
            &wide(),
            &binding_of(SPARE, &owner, None),
        )
        .unwrap();
    assert_eq!(commits(&store, Key::Volume(active)), unwritten + 1);
    let after = stored_volume(&store, active);
    assert_eq!(after.next, before.next + 1);
    let entry = *after.events.last().unwrap();
    assert_eq!(
        (entry.seq, entry.kind, entry.host, entry.instance),
        (
            before.next,
            EventKind::Attach,
            host(SPARE),
            Some(instance_of_host(host(SPARE)))
        )
    );
    assert_eq!(after.events[0].instance, Some(owner[0].instance));
    assert_eq!(stored_format(&store, active), 3);
    let written = commits(&store, Key::Volume(active));
    assert!(
        reconciler(&store)
            .record_standby(
                &gate,
                sid(),
                active,
                host(SPARE),
                ERA,
                &wide(),
                &binding_of(SPARE, &owner, None)
            )
            .is_ok()
    );
    let mut other = crate::failover::sim::binding(host(SPARE));
    other.instance = instance_of_host(host(SPARE + 9));
    assert_eq!(
        reconciler(&store).record_standby(&gate, sid(), active, host(SPARE), ERA, &wide(), &other),
        Err(ReconcileError::Conflict),
        "a retry under another instance"
    );
    assert_eq!(commits(&store, Key::Volume(active)), written);

    let shard = stored(&store).1;
    let holder = Holder {
        volume: active,
        host: host(OWNER),
        instance: owner[0].instance,
    };
    let entries = [crate::failover::evidence::Registrant {
        cntlid: 1,
        pair: crate::failover::evidence_tests::pair(1, 1, 1),
        holder: true,
    }];
    let report = crate::failover::evidence_tests::report(&entries);
    let listing = vec![
        OWNER_INSTANCE.to_owned(),
        instance_of_host(host(SPARE)).as_str().to_owned(),
    ];
    let verdict = |volume: &VolumeRecord| {
        poll(
            &holder,
            Target::of(&shard),
            crate::failover::evidence_tests::pair(1, 1, 1),
            Ok(&report),
            &Reads {
                shard: Some(&shard),
                volume: Some(volume),
                listed: Some(&listing),
                peers: &[],
            },
            &wide(),
        )
    };
    assert_eq!(verdict(&after), Verdict::Continue);
    let mut unbound = after.clone();
    unbound.events.last_mut().unwrap().instance = None;
    assert!(
        matches!(
            verdict(&unbound),
            Verdict::Retire(retirement) if retirement.trigger()
                == &Trigger::Attachment(Mismatch::Foreign(listing[1].clone()))
        ),
        "control: an entry recorded without its instance"
    );
}

/// ATTACH-AFTER-GONE at the attach record: a host whose entry is ended, with its pair or without it, conflicts with no
/// write; once the entry is gone the host takes a new entry under a new number.
#[test]
fn a_host_takes_a_new_entry_only_after_its_entry_is_gone() {
    let gate = StandbyGate::qualified();
    let active = record().active;
    let store = standby_world(&[SPARE], &[SPARE]);
    let first = stored_volume(&store, active).live(host(SPARE)).unwrap();
    edit_volume(&store, active, |held| ended(held, SPARE));
    let record_again = |store: &Shared| {
        reconciler(store).record_standby(
            &gate,
            sid(),
            active,
            host(SPARE),
            ERA,
            &wide(),
            &crate::failover::sim::binding(host(SPARE)),
        )
    };
    let fresh = crate::failover::reconcile::Binding {
        instance: crate::failover::sim::instance_of_host(host(SPARE + 60)),
        ..crate::failover::sim::binding(host(SPARE))
    };
    let record_fresh = |store: &Shared| {
        reconciler(store).record_standby(&gate, sid(), active, host(SPARE), ERA, &wide(), &fresh)
    };
    let before = commits(&store, Key::Volume(active));
    assert_eq!(
        record_again(&store).map(drop),
        Err(ReconcileError::Conflict),
        "ended with its pair"
    );
    assert_eq!(
        record_fresh(&store).map(drop),
        Err(ReconcileError::Conflict),
        "ended with its pair, under an instance no entry binds"
    );
    edit_volume(&store, active, |held| VolumeRecord {
        pairs: held
            .pairs
            .iter()
            .filter(|p| p.host != host(SPARE))
            .copied()
            .collect(),
        ..held.clone()
    });
    let dropped = commits(&store, Key::Volume(active));
    assert_eq!(dropped, before + 1);
    assert_eq!(
        record_again(&store).map(drop),
        Err(ReconcileError::Conflict),
        "ended, pair dropped"
    );
    assert_eq!(
        record_fresh(&store).map(drop),
        Err(ReconcileError::Conflict),
        "ended, pair dropped, under an instance no entry binds"
    );
    assert_eq!(commits(&store, Key::Volume(active)), dropped);
    edit_volume(&store, active, |held| gone(held, SPARE));
    let released = stored_volume(&store, active);
    assert_eq!(
        released.event(first).map(|entry| entry.kind),
        Some(EventKind::Gone)
    );
    let marked = commits(&store, Key::Volume(active));
    record_again(&store).unwrap();
    let again = stored_volume(&store, active);
    assert_eq!(commits(&store, Key::Volume(active)), marked + 1);
    assert_eq!(again.live(host(SPARE)), Some(released.next));
    assert_eq!(again.events[..released.events.len()], released.events[..]);
}

/// One attach, end and gone cycle of `h` on the active volume: the standby attach record, the end in place and the
/// gone mark, as the reconciler's steps leave them.
fn cycle(store: &Shared, h: u64) {
    let gate = StandbyGate::qualified();
    let active = record().active;
    let listing: Vec<String> = vec![OWNER_INSTANCE.to_owned()];
    reconciler(store)
        .record_standby(
            &gate,
            sid(),
            active,
            host(h),
            ERA,
            &wide(),
            &binding_of(h, &owner_peer(), Some(&listing)),
        )
        .unwrap();
    edit_volume(store, active, |held| ended(held, h));
    edit_volume(store, active, |held| gone(held, h));
}

/// A store whose active volume's record holds `MAX_EVENTS` entries: the owner's live entry, fourteen standby entries
/// of `hosts[..14]`, each ended and gone, and the ended entry of `hosts[14]`, under a fence raised to an activated
/// session. A record of 15 entries takes the 16th with no removal. Returns the store and the hosts.
fn full_record() -> (Shared, Vec<u64>) {
    use crate::failover::records::MAX_EVENTS;
    let gate = StandbyGate::qualified();
    let active = record().active;
    let store = activated();
    bump(&store);
    let hosts: Vec<u64> = (0..15).map(|at| SPARE + 10 + at).collect();
    for &h in &hosts[..14] {
        cycle(&store, h);
    }
    let fifteen = stored_volume(&store, active);
    assert_eq!(fifteen.events.len(), MAX_EVENTS - 1);
    let listing: Vec<String> = vec![OWNER_INSTANCE.to_owned()];
    reconciler(&store)
        .record_standby(
            &gate,
            sid(),
            active,
            host(hosts[14]),
            ERA,
            &wide(),
            &binding_of(hosts[14], &[], Some(&listing)),
        )
        .unwrap();
    let full = stored_volume(&store, active);
    assert_eq!(full.events.len(), MAX_EVENTS, "15 entries take the 16th");
    assert_eq!(full.events[..fifteen.events.len()], fifteen.events[..]);
    edit_volume(&store, active, |held| ended(held, hosts[14]));
    edit_volume(&store, active, |held| VolumeRecord {
        fence: (record().generation.get() << 32) | 4,
        ..held.clone()
    });
    (store, hosts)
}

/// `held` after a standby attach of `h` at number `held.next`, bound to its test instance, with the entry numbered
/// `removed` gone from it.
fn shed_into(held: &VolumeRecord, removed: u32, h: u64) -> VolumeRecord {
    let mut next = held.clone();
    next.events.retain(|event| event.seq != removed);
    next.push(EventKind::Attach, host(h), ERA).unwrap();
    next.events.last_mut().unwrap().instance =
        Some(crate::failover::sim::instance_of_host(host(h)));
    next
}

/// HistoryBound: fourteen standby attaches each ended and gone and a fifteenth ended in place fill the record to
/// `MAX_EVENTS` with the owner's live entry. The seventeenth attach of the volume's life removes exactly the oldest
/// gone entry whose instance a complete listing of the tick does not show, keeps every other entry, the force mark,
/// the fence and the pairs, takes number 16 and leaves `next` at 17, in one write. Its oldest gone entry leaves when
/// the listing shows only the owner, and stays when the listing shows its instance, so the next gone entry leaves. A
/// full record whose gone entries the listing all shows, with no complete listing, or with a listing row that is no
/// instance ID, refuses with no write.
#[test]
fn a_full_record_sheds_its_oldest_unlisted_gone_entry() {
    use crate::failover::sim::instance_of_host;
    let gate = StandbyGate::qualified();
    let active = record().active;
    let newcomer = SPARE + 40;
    let attach = |store: &Shared, listing: Option<&[String]>| {
        reconciler(store).record_standby(
            &gate,
            sid(),
            active,
            host(newcomer),
            ERA,
            &wide(),
            &binding_of(newcomer, &[], listing),
        )
    };
    let (store, hosts) = full_record();
    let full = stored_volume(&store, active);
    assert_eq!(full.fence, (record().generation.get() << 32) | 4);
    let gone: Vec<u32> = full
        .events
        .iter()
        .filter(|event| event.kind == EventKind::Gone)
        .map(|event| event.seq)
        .collect();
    assert_eq!(gone.len(), 14);
    let before = commits(&store, Key::Volume(active));
    let every: Vec<String> = hosts[..14]
        .iter()
        .map(|&h| instance_of_host(host(h)).as_str().to_owned())
        .chain([OWNER_INSTANCE.to_owned()])
        .collect();
    let unreadable: Vec<String> = vec![OWNER_INSTANCE.to_owned(), "i-NOT-AN-ID".to_owned()];
    let blank: Vec<String> = vec![OWNER_INSTANCE.to_owned(), String::new()];
    let newcomer_listed: Vec<String> = vec![
        OWNER_INSTANCE.to_owned(),
        instance_of_host(host(newcomer)).as_str().to_owned(),
    ];
    for (listing, what) in [
        (None, "no complete listing"),
        (
            Some(every.as_slice()),
            "the listing shows every gone entry's instance",
        ),
        (
            Some(unreadable.as_slice()),
            "a listing row that is no instance ID",
        ),
        (Some(blank.as_slice()), "an empty listing row"),
        (
            Some(newcomer_listed.as_slice()),
            "the listing already shows the new entry's instance",
        ),
    ] {
        assert_eq!(
            attach(&store, listing).map(drop),
            Err(ReconcileError::Conflict),
            "{what}"
        );
    }
    assert_eq!(commits(&store, Key::Volume(active)), before);
    assert_eq!(stored_volume(&store, active), full);

    let owner_only: Vec<String> = vec![OWNER_INSTANCE.to_owned()];
    attach(&store, Some(&owner_only)).unwrap();
    assert_eq!(commits(&store, Key::Volume(active)), before + 1);
    let shed = stored_volume(&store, active);
    assert_eq!(shed, shed_into(&full, gone[0], newcomer));
    assert_eq!((shed.next, shed.live(host(newcomer))), (17, Some(16)));

    let (store, _) = full_record();
    let before = commits(&store, Key::Volume(active));
    let oldest_listed: Vec<String> = vec![
        OWNER_INSTANCE.to_owned(),
        instance_of_host(host(hosts[0])).as_str().to_owned(),
    ];
    attach(&store, Some(&oldest_listed)).unwrap();
    assert_eq!(commits(&store, Key::Volume(active)), before + 1);
    assert_eq!(
        stored_volume(&store, active),
        shed_into(&full, gone[1], newcomer),
        "the listed oldest gone entry stays and the next one leaves"
    );
}

/// A store holding the shard created from [`empty`] and `held` as its active volume's record, with page 0 fenced and
/// `E = 1`.
fn seeded_with(held: VolumeRecord) -> Shared {
    let store = Shared::new();
    provisioner(&store).create_shard(empty()).unwrap();
    client(&store)
        .create(Key::Volume(held.volume), held)
        .unwrap();
    fence_page(&store, 0, (record().generation.get() << 32) | 2);
    bump(&store);
    store
}

/// The owner's activated volume record followed by `hidden`'s two attaches, the second gone, then gone entries of
/// `others`, each bound to its host's test instance. With `unbound`, the first of the others' gone entries binds
/// no instance.
fn gone_history(hidden: u64, others: &[u64], unbound: bool) -> VolumeRecord {
    use crate::failover::sim::instance_of_host;
    let mut held = stored_volume(&activated(), record().active);
    held.push(EventKind::Attach, host(hidden), ERA);
    for h in [hidden].iter().chain(others) {
        held.push(EventKind::Attach, host(*h), ERA);
        let entry = held.events.last_mut().unwrap();
        entry.instance = Some(instance_of_host(host(*h)));
        entry.kind = EventKind::Gone;
    }
    if unbound {
        held.events[3].instance = None;
    }
    assert_eq!(VolumeRecord::decode(&held.encode()), Ok(held.clone()));
    held
}

/// A full record whose lowest unlisted gone entry hides an older attach of its host, so that removing it would make
/// the older attach live, which the successor rule refuses: the write removes the next unlisted gone entry and binds
/// nothing to the hidden attach. With every other gone instance listed a new host refuses with no write, and a new
/// attach of the hidden host itself takes the removal, since its own entry hides the older attach.
#[test]
fn a_full_record_skips_a_gone_entry_whose_removal_revives_an_attach() {
    use crate::failover::records::MAX_EVENTS;
    use crate::failover::sim::instance_of_host;
    let gate = StandbyGate::qualified();
    let active = record().active;
    let (hidden, newcomer) = (SPARE + 9, SPARE + 40);
    let others: Vec<u64> = (0..13).map(|at| SPARE + 20 + at).collect();
    let held = gone_history(hidden, &others, false);
    assert_eq!(held.events.len(), MAX_EVENTS);
    assert_eq!(
        (held.live(host(hidden)), held.event(1).unwrap().kind),
        (None, EventKind::Attach)
    );
    let unbound = [
        owner_peer()[0],
        crate::failover::attachments::Peer {
            host: host(hidden),
            instance: crate::failover::attachments::InstanceId::new("i-0eeeeeeeeeeeeeee0").unwrap(),
        },
    ];
    let record_on = |store: &Shared, h: u64, listing: &[String]| {
        reconciler(store).record_standby(
            &gate,
            sid(),
            active,
            host(h),
            ERA,
            &wide(),
            &binding_of(h, &unbound, Some(listing)),
        )
    };
    let owner_only = vec![OWNER_INSTANCE.to_owned()];
    let store = seeded_with(held.clone());
    let before = commits(&store, Key::Volume(active));
    record_on(&store, newcomer, &owner_only).unwrap();
    assert_eq!(commits(&store, Key::Volume(active)), before + 1);
    let shed = stored_volume(&store, active);
    assert_eq!(shed.events[0].instance, Some(unbound[0].instance));
    assert_eq!(shed.event(2).map(|entry| entry.kind), Some(EventKind::Gone));
    assert_eq!(shed.event(3), None, "the next unlisted gone entry leaves");
    assert_eq!(shed.event(1).map(|entry| entry.instance), Some(None));
    assert_eq!(
        (shed.live(host(hidden)), shed.live(host(newcomer))),
        (None, Some(16))
    );

    let others_listed: Vec<String> = others
        .iter()
        .map(|&h| instance_of_host(host(h)).as_str().to_owned())
        .chain([OWNER_INSTANCE.to_owned()])
        .collect();
    let store = seeded_with(held.clone());
    let before = commits(&store, Key::Volume(active));
    assert_eq!(
        record_on(&store, newcomer, &others_listed).map(drop),
        Err(ReconcileError::Conflict),
        "only the entry that hides an attach is unlisted"
    );
    assert_eq!(commits(&store, Key::Volume(active)), before);
    record_on(&store, hidden, &others_listed).unwrap();
    let again = stored_volume(&store, active);
    assert_eq!(commits(&store, Key::Volume(active)), before + 1);
    assert_eq!((again.event(2), again.live(host(hidden))), (None, Some(16)));
    assert_eq!(
        again.event(1).map(|entry| (entry.kind, entry.instance)),
        Some((EventKind::Attach, None)),
        "the hidden attach stays unbound"
    );
    assert_eq!(again.events[0].instance, Some(unbound[0].instance));

    for kind in [EventKind::Detach, EventKind::Force] {
        let mut closing = held.clone();
        closing.events[1].kind = kind;
        closing.forced |= kind == EventKind::Force;
        assert_eq!(VolumeRecord::decode(&closing.encode()), Ok(closing.clone()));
        assert_eq!(Attach::of(&closing, host(hidden), &wide()), Attach::Open);
        let store = seeded_with(closing);
        record_on(&store, newcomer, &owner_only).unwrap();
        let shed = stored_volume(&store, active);
        assert_eq!(
            (shed.event(2).map(|entry| entry.kind), shed.event(3)),
            (Some(EventKind::Gone), None),
            "the gone entry over the host's {kind:?} stays and the next one leaves"
        );
        assert_eq!(
            Attach::of(&shed, host(hidden), &wide()),
            Attach::Open,
            "{kind:?}"
        );
    }
}

/// A gone entry that binds no instance stays in a full record, since no listing can show its instance absent: the
/// write removes the next gone entry, and a record whose only unlisted gone entry binds no instance refuses with no
/// write.
#[test]
fn a_full_record_keeps_a_gone_entry_that_binds_no_instance() {
    use crate::failover::sim::instance_of_host;
    let gate = StandbyGate::qualified();
    let active = record().active;
    let newcomer = SPARE + 40;
    let others: Vec<u64> = (0..13).map(|at| SPARE + 20 + at).collect();
    let held = gone_history(SPARE + 9, &others, true);
    assert_eq!(held.events[3].instance, None);
    assert_eq!(Attach::of(&held, host(newcomer), &wide()), Attach::Open);
    let mut unbound = held.clone();
    for event in unbound
        .events
        .iter_mut()
        .filter(|event| event.kind == EventKind::Gone)
    {
        event.instance = None;
    }
    assert_eq!(
        Attach::of(&unbound, host(newcomer), &wide()),
        Attach::Closed,
        "a full record whose gone entries bind no instance admits no new attach"
    );
    let owner = owner_peer();
    let attach = |store: &Shared, listing: &[String]| {
        reconciler(store).record_standby(
            &gate,
            sid(),
            active,
            host(newcomer),
            ERA,
            &wide(),
            &binding_of(newcomer, &owner, Some(listing)),
        )
    };
    let listed: Vec<String> = [SPARE + 9]
        .iter()
        .chain(&others[1..])
        .map(|&h| instance_of_host(host(h)).as_str().to_owned())
        .chain([OWNER_INSTANCE.to_owned()])
        .collect();
    let store = seeded_with(held.clone());
    let before = commits(&store, Key::Volume(active));
    assert_eq!(
        attach(&store, &listed).map(drop),
        Err(ReconcileError::Conflict),
        "the only unlisted gone entry binds no instance"
    );
    assert_eq!(commits(&store, Key::Volume(active)), before);
    let listed: Vec<String> = [SPARE + 9]
        .iter()
        .chain(&others[2..])
        .map(|&h| instance_of_host(host(h)).as_str().to_owned())
        .chain([OWNER_INSTANCE.to_owned()])
        .collect();
    attach(&store, &listed).unwrap();
    let shed = stored_volume(&store, active);
    assert_eq!(commits(&store, Key::Volume(active)), before + 1);
    assert_eq!(shed.event(3).map(|entry| entry.instance), Some(None));
    assert_eq!(shed.event(4), None);
    assert_eq!(shed.events[0].instance, Some(owner[0].instance));
}

/// One instance binds at most one attach or ended entry: a standby attach under the instance of another host's live
/// or ended entry conflicts with no write, and so does one whose binding of the owner's live entry repeats the new
/// entry's instance, or names two instances for the owner.
#[test]
fn a_standby_attach_refuses_an_instance_another_entry_binds() {
    use crate::failover::attachments::Peer;
    use crate::failover::sim::instance_of_host;
    let gate = StandbyGate::qualified();
    let active = record().active;
    let store = activated();
    bump(&store);
    let owner = owner_peer();
    let attach = |store: &Shared, h: u64, binding: &crate::failover::reconcile::Binding<'_>| {
        reconciler(store).record_standby(&gate, sid(), active, host(h), ERA, &wide(), binding)
    };
    attach(&store, SPARE, &binding_of(SPARE, &owner, None)).unwrap();
    let twin = crate::failover::reconcile::Binding {
        instance: instance_of_host(host(SPARE)),
        ..crate::failover::sim::binding(host(SPARE + 1))
    };
    let before = commits(&store, Key::Volume(active));
    assert_eq!(
        attach(&store, SPARE + 1, &twin).map(drop),
        Err(ReconcileError::Conflict),
        "a live entry's instance"
    );
    assert_eq!(commits(&store, Key::Volume(active)), before);
    edit_volume(&store, active, |held| ended(held, SPARE));
    let ended_at = commits(&store, Key::Volume(active));
    assert_eq!(
        attach(&store, SPARE + 1, &twin).map(drop),
        Err(ReconcileError::Conflict),
        "an ended entry's instance"
    );
    assert_eq!(commits(&store, Key::Volume(active)), ended_at);

    let store = activated();
    bump(&store);
    let held = stored_volume(&store, active);
    let clash = [Peer {
        host: host(OWNER),
        instance: instance_of_host(host(SPARE)),
    }];
    let split = [
        owner[0],
        Peer {
            host: host(OWNER),
            instance: instance_of_host(host(SPARE + 7)),
        },
    ];
    for (unbound, what) in [
        (
            &clash[..],
            "the owner's binding repeats the new entry's instance",
        ),
        (&split[..], "two instances named for the owner"),
    ] {
        assert_eq!(
            attach(&store, SPARE, &binding_of(SPARE, unbound, None)).map(drop),
            Err(ReconcileError::Conflict),
            "{what}"
        );
    }
    assert_eq!(stored_volume(&store, active), held);
}

/// The write binds each live entry without an instance to the instance `unbound` names for its host, whatever the
/// order of its rows, with rows for other hosts and identical repeats. A write whose `unbound` omits a live entry
/// that binds none, or names one instance for two such entries, conflicts with no write, and so does a retry over the
/// recorded host's own live entry that binds no instance.
#[test]
fn a_standby_attach_binds_each_live_entry_unbound_names() {
    use crate::failover::attachments::{InstanceId, Peer};
    use crate::failover::sim::instance_of_host;
    let gate = StandbyGate::qualified();
    let active = record().active;
    let legacy = SPARE + 5;
    let legacy_instance = InstanceId::new("i-0ddddddddddddddd0").unwrap();
    let seeded = || {
        let store = activated();
        bump(&store);
        edit_volume(&store, active, |held| {
            let mut next = held.clone();
            next.push(EventKind::Attach, host(legacy), ERA);
            next
        });
        store
    };
    let instance_of = |held: &VolumeRecord, h: u64| {
        let at = held.live(host(h)).unwrap();
        held.event(at).unwrap().instance
    };
    let stray = Peer {
        host: host(SPARE + 30),
        instance: instance_of_host(host(SPARE + 30)),
    };
    let named = [
        stray,
        Peer {
            host: host(legacy),
            instance: legacy_instance,
        },
        owner_peer()[0],
        owner_peer()[0],
    ];
    let store = seeded();
    let before = commits(&store, Key::Volume(active));
    assert_eq!(
        reconciler(&store)
            .record_standby(
                &gate,
                sid(),
                active,
                host(legacy),
                ERA,
                &wide(),
                &binding_of(legacy, &named, None),
            )
            .map(drop),
        Err(ReconcileError::Conflict),
        "a retry over the host's own entry that binds no instance"
    );
    assert_eq!(commits(&store, Key::Volume(active)), before);
    reconciler(&store)
        .record_standby(
            &gate,
            sid(),
            active,
            host(SPARE),
            ERA,
            &wide(),
            &binding_of(SPARE, &named, None),
        )
        .unwrap();
    assert_eq!(commits(&store, Key::Volume(active)), before + 1);
    let held = stored_volume(&store, active);
    assert_eq!(
        [OWNER, legacy, SPARE].map(|h| instance_of(&held, h)),
        [
            Some(owner_peer()[0].instance),
            Some(legacy_instance),
            Some(instance_of_host(host(SPARE)))
        ]
    );

    let store = seeded();
    let unwritten = stored_volume(&store, active);
    let before = commits(&store, Key::Volume(active));
    let one_for_both = [
        Peer {
            host: host(OWNER),
            instance: legacy_instance,
        },
        Peer {
            host: host(legacy),
            instance: legacy_instance,
        },
    ];
    for (unbound, what) in [
        (&named[..2], "the owner omitted"),
        (&one_for_both[..], "one instance named for two live entries"),
    ] {
        assert_eq!(
            reconciler(&store)
                .record_standby(
                    &gate,
                    sid(),
                    active,
                    host(SPARE),
                    ERA,
                    &wide(),
                    &binding_of(SPARE, unbound, None),
                )
                .map(drop),
            Err(ReconcileError::Conflict),
            "{what}"
        );
    }
    assert_eq!(commits(&store, Key::Volume(active)), before);
    assert_eq!(stored_volume(&store, active), unwritten);
}

/// ATTACH-AFTER-GONE over retained format-2 events: a host whose latest event is a detach, with or without its
/// earlier attach's pair, or a force-detach, takes no new entry, and the step conflicts with no write.
#[test]
fn a_host_whose_latest_event_is_a_detach_or_force_detach_takes_no_new_entry() {
    let gate = StandbyGate::qualified();
    let active = record().active;
    let (paired, unpaired, forced) = (SPARE + 1, SPARE + 2, SPARE + 3);
    let store = activated();
    bump(&store);
    edit_volume(&store, active, |held| {
        let mut next = held.clone();
        next.push(EventKind::Attach, host(paired), ERA);
        let mut next = next
            .enroll(host(paired), attach_pair(&next, paired), &wide())
            .unwrap()
            .unwrap();
        next.push(EventKind::Detach, host(paired), ERA);
        next.push(EventKind::Attach, host(unpaired), ERA);
        next.push(EventKind::Detach, host(unpaired), ERA);
        next.push(EventKind::Attach, host(forced), ERA);
        next.push(EventKind::Force, host(forced), ERA);
        next
    });
    assert_eq!(stored_format(&store, active), 2);
    let held = stored_volume(&store, active);
    assert!(held.forced);
    let before = commits(&store, Key::Volume(active));
    for h in [paired, unpaired, forced] {
        assert_eq!(
            reconciler(&store)
                .record_standby(
                    &gate,
                    sid(),
                    active,
                    host(h),
                    ERA,
                    &wide(),
                    &crate::failover::sim::binding(host(h)),
                )
                .map(drop),
            Err(ReconcileError::Conflict),
            "host {h}"
        );
    }
    assert_eq!(commits(&store, Key::Volume(active)), before);
    assert_eq!(stored_volume(&store, active), held);
}

/// A standby attach record whose write's outcome is unknown, retried by a second reconciler, leaves one entry for the
/// host and one witness, on a record with room and on a full record that sheds a gone entry. A committed write's
/// retry finds the entry with no owner peer and no listing and writes nothing; an uncommitted write's retry makes the
/// write once.
#[test]
fn an_unknown_standby_attach_write_leaves_one_entry() {
    let gate = StandbyGate::qualified();
    let active = record().active;
    let owner = owner_peer();
    let owner_only: Vec<String> = vec![OWNER_INSTANCE.to_owned()];
    for commit in [true, false] {
        let (full, _) = full_record();
        let roomy = activated();
        bump(&roomy);
        for (store, h, listing) in [
            (&roomy, SPARE, None),
            (&full, SPARE + 40, Some(owner_only.as_slice())),
        ] {
            let attach = |binding: &crate::failover::reconcile::Binding<'_>| {
                reconciler(store).record_standby(
                    &gate,
                    sid(),
                    active,
                    host(h),
                    ERA,
                    &wide(),
                    binding,
                )
            };
            let before = commits(store, Key::Volume(active));
            park(store, STANDBY_WRITE, Arm::Timeout { commit });
            assert_eq!(
                attach(&binding_of(h, &owner, listing)).map(drop),
                Err(ReconcileError::Store(StoreError::Unknown)),
                "commit {commit}"
            );
            assert_eq!(
                commits(store, Key::Volume(active)),
                before + usize::from(commit)
            );
            let retry = if commit {
                crate::failover::sim::binding(host(h))
            } else {
                binding_of(h, &owner, listing)
            };
            attach(&retry).unwrap();
            assert_eq!(
                commits(store, Key::Volume(active)),
                before + 1,
                "commit {commit}"
            );
            let held = stored_volume(store, active);
            assert_eq!(
                held.events
                    .iter()
                    .filter(|event| event.host == host(h))
                    .count(),
                1
            );
            assert!(held.live(host(h)).is_some());
            assert_eq!(held.events[0].instance, Some(owner[0].instance));
        }
    }
}

/// The complete listing of the active volume a tick reads in the slot-reuse tests: the owner's instance alone.
fn owner_listing() -> Vec<String> {
    vec![OWNER_INSTANCE.to_owned()]
}

/// The complete listing of the active volume the slot-reuse scripts leave: the shard owner's instance and the instance
/// of every attach or ended entry, since a script detaches an instance only before its gone mark.
fn attached_now(store: &Shared) -> Vec<String> {
    let owner = stored(store).1.owner;
    let mut listing = vec![match owner == host(OWNER) {
        true => OWNER_INSTANCE.to_owned(),
        false => crate::failover::sim::instance_of_host(owner)
            .as_str()
            .to_owned(),
    }];
    for event in stored_volume(store, record().active).events {
        if let (EventKind::Attach | EventKind::Ended, Some(instance)) = (event.kind, event.instance)
        {
            let listed = instance.as_str().to_owned();
            if !listing.contains(&listed) {
                listing.push(listed);
            }
        }
    }
    listing
}

/// Records `h`'s standby attach, binding the owner's entry, and enrolls its pair under its attach's key.
fn attach_enrolled(store: &Shared, h: u64) {
    let gate = StandbyGate::qualified();
    let active = record().active;
    let listing = attached_now(store);
    reconciler(store)
        .record_standby(
            &gate,
            sid(),
            active,
            host(h),
            ERA,
            &wide(),
            &binding_of(h, &owner_peer(), Some(&listing)),
        )
        .unwrap();
    edit_volume(store, active, |held| {
        held.enroll(host(h), attach_pair(held, h), &wide())
            .unwrap()
            .unwrap()
    });
}

/// The owner's drop of `h`'s ended pair after a Report showed its key absent: an exact-version write under the
/// unchanged fence, which the successor rule admits because the prior record holds the entry ended.
fn drop_ended_pair(store: &Shared, h: u64) {
    edit_volume(store, record().active, |held| VolumeRecord {
        pairs: held
            .pairs
            .iter()
            .filter(|p| p.host != host(h))
            .copied()
            .collect(),
        ..held.clone()
    });
}

fn latest_seq(store: &Shared, h: u64) -> u32 {
    stored_volume(store, record().active)
        .latest(host(h))
        .map_or(0, |(seq, _)| seq)
}

/// Slot-reuse tests count listings as settled at or after time 400.
const SETTLE: Settle = Settle {
    requested: 100,
    settle: 300,
};

/// The detach witness of `h`'s ended entry, then its gone mark over two settled listings of every attachment but the
/// witnessed one.
fn detach_and_release(store: &Shared, h: u64) {
    let gate = StandbyGate::qualified();
    let active = record().active;
    let witness = reconciler(store).detachable(active, host(h)).unwrap();
    let (seq, entry) = stored_volume(store, active)
        .latest(host(h))
        .map(|(seq, entry)| (seq, entry.instance))
        .unwrap();
    assert_eq!(
        (
            witness.volume(),
            witness.host(),
            witness.seq(),
            Some(witness.instance())
        ),
        (active, host(h), seq, entry)
    );
    let detached = witness.instance().as_str().to_owned();
    let clean: Vec<String> = attached_now(store)
        .into_iter()
        .filter(|listed| *listed != detached)
        .collect();
    let listings = [
        Listing {
            at: 400,
            instances: &clean,
        },
        Listing {
            at: 800,
            instances: &clean,
        },
    ];
    reconciler(store)
        .release_attach(&gate, &witness, &listings, SETTLE)
        .unwrap();
    assert_eq!(
        stored_volume(store, active)
            .latest(host(h))
            .map(|(_, event)| event.kind),
        Some(EventKind::Gone)
    );
}

/// The volume and history bounds hold, and the shard keeps the volume active at its generation, which nothing
/// retired.
fn bounded(store: &Shared, generation: ShardGeneration) {
    use crate::failover::records::{MAX_ATTACHED, MAX_EVENTS};
    let held = stored_volume(store, record().active);
    assert!(held.live_hosts().count() <= MAX_ATTACHED, "{held:?}");
    assert!(held.events.len() <= MAX_EVENTS, "{held:?}");
    assert!(
        matches!(held.state, VolumeState::Fresh | VolumeState::Active),
        "{held:?}"
    );
    let (_, shard) = stored(store);
    assert_eq!(
        (shard.generation, shard.active),
        (generation, record().active)
    );
}

/// END-RECORDED-FIRST: `end_attach` refuses the owner, the named standby and a third host's live attach at `E = 0`
/// with no write; for a third host at `E > 0` it ends the live entry in place with its pair recorded, frees the slot
/// for a new host, reports no naming, and a retry returns the witness with no write. Under a moved tenure the census
/// entry reserved for that host stays while its attach is live and leaves once it ended.
#[test]
fn end_attach_ends_only_a_third_hosts_attach() {
    let gate = StandbyGate::qualified();
    let active = record().active;
    let (named, third, newcomer) = (SPARE, SPARE + 1, SPARE + 2);
    let unbumped = activated();
    edit_volume(&unbumped, active, |held| {
        let mut next = held.clone();
        next.push(EventKind::Attach, host(third), ERA).unwrap();
        next.events.last_mut().unwrap().instance =
            Some(crate::failover::sim::instance_of_host(host(third)));
        next
    });
    let before = commits(&unbumped, Key::Volume(active));
    assert_eq!(
        reconciler(&unbumped)
            .end_attach(
                &gate,
                sid(),
                record().active,
                host(third),
                latest_seq(&unbumped, third)
            )
            .map(drop),
        Err(ReconcileError::Conflict),
        "E = 0"
    );
    assert_eq!(commits(&unbumped, Key::Volume(active)), before);
    assert!(stored_volume(&unbumped, active).live(host(third)).is_some());
    let store = standby_world(&[named, third], &[named, third]);
    let held = stored_volume(&store, active);
    let owner = held.live(host(OWNER)).unwrap();
    assert!(
        held.event(owner)
            .is_some_and(|entry| entry.instance.is_some())
    );
    assert_eq!(
        held.enrolled(host(OWNER)).map(|pair| pair.key),
        crate::failover::records::attachment_key(owner)
    );
    let slot = slot_for(&store, third);
    crate::failover::takeover::tests::designate(&store, Some(host(named)));
    let before_end = commits(&store, Key::Volume(active));
    for h in [OWNER, named] {
        assert_eq!(
            reconciler(&store)
                .end_attach(
                    &gate,
                    sid(),
                    record().active,
                    host(h),
                    latest_seq(&store, h)
                )
                .map(drop),
            Err(ReconcileError::Conflict),
            "host {h}"
        );
    }
    assert_eq!(commits(&store, Key::Volume(active)), before_end);
    assert_eq!(
        Attach::of(&stored_volume(&store, active), host(newcomer), &wide()),
        Attach::Closed
    );
    crate::failover::takeover::tests::designate(&store, None);
    bump(&store);
    assert_eq!(
        reconciler(&store).release(&gate, ZONE, sid(), slot_held(&store), |_| false),
        Ok(true),
        "the census entry of a host whose attach is live stays"
    );
    assert_eq!(
        census_held(&store).slot(sid()).map(|entry| entry.host),
        Some(slot.host())
    );
    let pair = stored_volume(&store, active).enrolled(host(third)).unwrap();
    let before_end = commits(&store, Key::Volume(active));
    let live = latest_seq(&store, third);
    for (volume, seq) in [(vol("vol-0e0e0e0e"), live), (active, live + 1)] {
        assert_eq!(
            reconciler(&store)
                .end_attach(&gate, sid(), volume, host(third), seq)
                .map(drop),
            Err(ReconcileError::Conflict),
            "{volume:?}, entry {seq}"
        );
    }
    assert_eq!(commits(&store, Key::Volume(active)), before_end);
    assert!(stored_volume(&store, active).live(host(third)).is_some());
    let ended = reconciler(&store)
        .end_attach(
            &gate,
            sid(),
            record().active,
            host(third),
            latest_seq(&store, third),
        )
        .unwrap();
    assert!(!ended.named());
    let held = stored_volume(&store, active);
    assert_eq!(held.live(host(third)), None);
    assert_eq!(
        held.latest(host(third)).map(|(_, event)| event.kind),
        Some(EventKind::Ended)
    );
    assert!(
        held.recorded().any(|recorded| *recorded == pair),
        "the pair stays recorded"
    );
    assert_eq!(
        Attach::of(&held, host(newcomer), &wide()),
        Attach::Open,
        "the slot is free"
    );
    let written = commits(&store, Key::Volume(active));
    assert_eq!(
        reconciler(&store).end_attach(
            &gate,
            sid(),
            record().active,
            host(third),
            latest_seq(&store, third)
        ),
        Ok(ended)
    );
    assert_eq!(commits(&store, Key::Volume(active)), written);
    assert_eq!(
        reconciler(&store).release(&gate, ZONE, sid(), slot_held(&store), |_| false),
        Ok(false),
        "the ended host's entry leaves as a host with no live attach"
    );
    assert_eq!(census_held(&store).slot(sid()), None);
}

/// An end write of unknown outcome, retried by a second reconciler, leaves one ended entry and one witness.
#[test]
fn an_unknown_end_write_leaves_one_ended_entry() {
    let gate = StandbyGate::qualified();
    let active = record().active;
    let store = standby_world(&[SPARE], &[SPARE]);
    let seq = latest_seq(&store, SPARE);
    park(&store, 2, Arm::Timeout { commit: true });
    assert_eq!(
        reconciler(&store)
            .end_attach(&gate, sid(), active, host(SPARE), seq)
            .map(drop),
        Err(ReconcileError::Store(StoreError::Unknown))
    );
    let written = commits(&store, Key::Volume(active));
    let ended = reconciler(&store)
        .end_attach(&gate, sid(), active, host(SPARE), seq)
        .unwrap();
    assert!(!ended.named());
    assert_eq!(commits(&store, Key::Volume(active)), written);
    let held = stored_volume(&store, active);
    assert_eq!(
        held.events
            .iter()
            .filter(|event| event.host == host(SPARE) && event.kind == EventKind::Ended)
            .count(),
        1
    );
}

#[test]
fn a_delayed_end_retry_keeps_the_hosts_later_attach_live() {
    let gate = StandbyGate::qualified();
    let active = record().active;
    let store = standby_world(&[SPARE], &[SPARE]);
    let first = latest_seq(&store, SPARE);
    park(&store, 2, Arm::Timeout { commit: true });
    assert_eq!(
        reconciler(&store)
            .end_attach(&gate, sid(), active, host(SPARE), first)
            .map(drop),
        Err(ReconcileError::Store(StoreError::Unknown))
    );
    drop_ended_pair(&store, SPARE);
    detach_and_release(&store, SPARE);
    attach_enrolled(&store, SPARE);
    let later = stored_volume(&store, active).live(host(SPARE));
    assert!(later.is_some_and(|later| later > first));
    let written = commits(&store, Key::Volume(active));
    assert_eq!(
        reconciler(&store)
            .end_attach(&gate, sid(), active, host(SPARE), first)
            .map(drop),
        Err(ReconcileError::Conflict)
    );
    assert_eq!(commits(&store, Key::Volume(active)), written);
    assert_eq!(stored_volume(&store, active).live(host(SPARE)), later);
}

/// A designation computed before the end commits after the end's write: `end_attach` reports the shard record
/// naming the ended host, a retry of the end returns the same witness with no write, `need_of` asks for a standby,
/// and a retry of the designation from its reserved slot refuses. With no host shown lost, a fresh host's
/// reservation takes the slot of the named standby that holds no live attach, and the fresh host is then attached,
/// enrolled and designated. Control: while the named standby's attach is live, the same reservation refuses
/// `Taken`. Nothing retires.
#[test]
fn a_designation_racing_the_end_is_reported_and_retires_nothing() {
    let gate = StandbyGate::qualified();
    let active = record().active;
    let fresh = SPARE + 1;
    let store = standby_world(&[SPARE], &[SPARE]);
    let generation = stored(&store).1.generation;
    let slot = slot_for(&store, SPARE);
    let reserve_fresh = |store: &Shared| {
        reconciler(store).reserve(
            &gate,
            &Population { cap: 1 },
            &wide(),
            ZONE,
            sid(),
            &roomy(host(fresh)),
            |_| false,
        )
    };
    let control = standby_world(&[SPARE], &[SPARE]);
    slot_for(&control, SPARE);
    crate::failover::takeover::tests::designate(&control, Some(host(SPARE)));
    assert_eq!(
        reserve_fresh(&control).map(drop),
        Err(ReconcileError::Population(PopulationRefusal::Taken)),
        "control: a named standby whose attach is live keeps its slot"
    );
    let racing = store.clone();
    let hook = hooked(&store, Key::Volume(active), Point::AfterWrite, move || {
        crate::failover::takeover::tests::designate(&racing, Some(host(SPARE)));
    });
    let mut ending = Reconciler::new(Client::open(AsReconciler(hook), MemLog::default()).unwrap());
    let ended = ending
        .end_attach(
            &gate,
            sid(),
            record().active,
            host(SPARE),
            latest_seq(&store, SPARE),
        )
        .unwrap();
    assert!(ended.named(), "the reread shows the designation");
    let written = commits(&store, Key::Volume(active));
    assert_eq!(
        reconciler(&store).end_attach(
            &gate,
            sid(),
            record().active,
            host(SPARE),
            latest_seq(&store, SPARE)
        ),
        Ok(ended),
        "a retry over the ended entry of a named host"
    );
    assert_eq!(commits(&store, Key::Volume(active)), written);
    let (_, shard) = stored(&store);
    assert_eq!(shard.standby, Some(host(SPARE)));
    let volume = stored_volume(&store, active);
    assert_eq!(
        crate::failover::standbys::need_of(&shard, &volume, |_| false),
        Some(crate::failover::standbys::Need::Standby)
    );
    let designated = commits(&store, Key::Shard(sid()));
    assert_eq!(
        reconciler(&store).designate(&gate, &slot, active).map(drop),
        Err(ReconcileError::Conflict),
        "the replay of a designation whose host's attach ended"
    );
    assert_eq!(commits(&store, Key::Shard(sid())), designated);
    bounded(&store, generation);

    let slot = reserve_fresh(&store).unwrap();
    assert_eq!(slot.host(), host(fresh));
    attach_enrolled(&store, fresh);
    reconciler(&store).designate(&gate, &slot, active).unwrap();
    let (_, shard) = stored(&store);
    assert_eq!(shard.standby, Some(host(fresh)));
    assert_eq!(
        crate::failover::standbys::need_of(&shard, &stored_volume(&store, active), |_| false),
        None
    );
    bounded(&store, generation);
}

/// A designation and the takeover it allows both commit after the end's write: the reread names the ended host
/// owner with no standby, and `end_attach` reports it through the owner alone.
#[test]
fn a_takeover_racing_the_end_is_reported() {
    let gate = StandbyGate::qualified();
    let active = record().active;
    let store = standby_world(&[SPARE], &[SPARE]);
    let racing = store.clone();
    let hook = hooked(&store, Key::Volume(active), Point::AfterWrite, move || {
        crate::failover::takeover::tests::designate(&racing, Some(host(SPARE)));
        let mut other = client(&racing);
        let read = other.read::<ShardRecord>(Key::Shard(sid())).unwrap();
        other
            .take_over(&read, Target::of(read.value()), host(SPARE))
            .unwrap();
    });
    let mut ending = Reconciler::new(Client::open(AsReconciler(hook), MemLog::default()).unwrap());
    let ended = ending
        .end_attach(
            &gate,
            sid(),
            record().active,
            host(SPARE),
            latest_seq(&store, SPARE),
        )
        .unwrap();
    let (_, shard) = stored(&store);
    assert_eq!((shard.owner, shard.standby), (host(SPARE), None));
    assert!(ended.named(), "the reread shows the takeover");
    assert_eq!(
        stored_volume(&store, active)
            .latest(host(SPARE))
            .map(|(_, event)| event.kind),
        Some(EventKind::Ended)
    );
}

/// `end_attach` leaves live, with no write, a third host's entry that binds no instance and one whose recorded pair
/// carries a key other than its number's: the deposed owner whose first attach no standby record bound, and a pair
/// whose key a later attach would take.
#[test]
fn end_attach_keeps_an_unbound_entry_and_a_pair_under_another_key() {
    use crate::failover::records::attachment_key;
    let gate = StandbyGate::qualified();
    let active = record().active;
    let mut unbound = stored_volume(&standby_world(&[SPARE], &[SPARE]), active);
    let owner_entry = unbound.live(host(OWNER)).unwrap();
    unbound
        .events
        .iter_mut()
        .find(|event| event.seq == owner_entry)
        .unwrap()
        .instance = None;
    let store = seeded_with(unbound);
    crate::failover::takeover::tests::designate(&store, Some(host(SPARE)));
    let read = client(&store)
        .read::<ShardRecord>(Key::Shard(sid()))
        .unwrap();
    client(&store)
        .take_over(&read, Target::of(read.value()), host(SPARE))
        .unwrap();
    assert_eq!(
        stored_volume(&store, active)
            .latest(host(OWNER))
            .map(|(_, event)| (event.kind, event.instance)),
        Some((EventKind::Attach, None))
    );
    let before = commits(&store, Key::Volume(active));
    assert_eq!(
        reconciler(&store)
            .end_attach(
                &gate,
                sid(),
                record().active,
                host(OWNER),
                latest_seq(&store, OWNER)
            )
            .map(drop),
        Err(ReconcileError::Conflict),
        "an entry that binds no instance"
    );
    assert_eq!(commits(&store, Key::Volume(active)), before);

    let store = standby_world(&[SPARE], &[]);
    let seq = stored_volume(&store, active).live(host(SPARE)).unwrap();
    let later = attachment_key(seq + 4).unwrap();
    edit_volume(&store, active, |held| {
        let pair = Pair {
            exhid: crate::failover::evidence_tests::exhid(SPARE as u8),
            key: later,
        };
        let mut next = held.clone();
        next.pairs.push(crate::failover::records::RecordedPair {
            host: host(SPARE),
            attach: seq,
            pair,
        });
        next
    });
    let before = commits(&store, Key::Volume(active));
    assert_eq!(
        reconciler(&store)
            .end_attach(
                &gate,
                sid(),
                record().active,
                host(SPARE),
                latest_seq(&store, SPARE)
            )
            .map(drop),
        Err(ReconcileError::Conflict),
        "a pair under a key a later attach would take"
    );
    assert_eq!(commits(&store, Key::Volume(active)), before);
    assert_eq!(stored_volume(&store, active).live(host(SPARE)), Some(seq));

    let store = activated();
    bump(&store);
    cycle(&store, SPARE + 7);
    let spent = stored_volume(&store, active)
        .latest(host(SPARE + 7))
        .map(|(seq, _)| seq)
        .unwrap();
    reconciler(&store)
        .record_standby(
            &gate,
            sid(),
            active,
            host(SPARE),
            ERA,
            &wide(),
            &binding_of(SPARE, &owner_peer(), Some(&owner_listing())),
        )
        .unwrap();
    let seq = stored_volume(&store, active).live(host(SPARE)).unwrap();
    edit_volume(&store, active, |held| {
        let mut next = held.clone();
        next.pairs.push(crate::failover::records::RecordedPair {
            host: host(SPARE),
            attach: seq,
            pair: Pair {
                exhid: crate::failover::evidence_tests::exhid(SPARE as u8),
                key: attachment_key(spent).unwrap(),
            },
        });
        next
    });
    reconciler(&store)
        .end_attach(
            &gate,
            sid(),
            record().active,
            host(SPARE),
            latest_seq(&store, SPARE),
        )
        .unwrap();
    assert_eq!(
        stored_volume(&store, active)
            .latest(host(SPARE))
            .map(|(_, event)| event.kind),
        Some(EventKind::Ended),
        "a pair under the key of an earlier entry that is no live attach"
    );
}

/// An unbound entry counts toward `MAX_ATTACHED`. At the cap, the reconciler rejects the attach that would bind the
/// entry and record another host's attach in the same write. Once another live attach ends, the same standby attach
/// commits and binds the entry, allowing `end_attach` to close it.
#[test]
fn an_unbound_entry_at_the_live_cap_keeps_its_slot_until_another_attach_ends() {
    let gate = StandbyGate::qualified();
    let active = record().active;
    let (named, third, fourth) = (SPARE, SPARE + 1, SPARE + 2);
    let mut unbound = stored_volume(&standby_world(&[named, third], &[named, third]), active);
    let entry = unbound.live(host(third)).unwrap();
    let event = unbound.events.iter_mut().find(|event| event.seq == entry);
    event.unwrap().instance = None;
    let store = seeded_with(unbound);
    crate::failover::takeover::tests::designate(&store, Some(host(named)));
    let attach = |h: u64| {
        let binding = crate::failover::sim::binding(host(h));
        reconciler(&store)
            .record_standby(&gate, sid(), active, host(h), ERA, &wide(), &binding)
            .map(drop)
    };
    let end = |h: u64, seq: u32| {
        reconciler(&store)
            .end_attach(&gate, sid(), active, host(h), seq)
            .map(drop)
    };
    let before = commits(&store, Key::Volume(active));
    assert_eq!(end(third, entry), Err(ReconcileError::Conflict));
    assert_eq!(attach(third), Err(ReconcileError::Conflict));
    assert_eq!(attach(fourth), Err(ReconcileError::Conflict));
    assert_eq!(commits(&store, Key::Volume(active)), before);

    crate::failover::takeover::tests::designate(&store, None);
    assert_eq!(end(named, latest_seq(&store, named)), Ok(()));
    assert_eq!(attach(fourth), Ok(()));
    let bound = stored_volume(&store, active);
    assert_eq!(
        bound.event(entry).and_then(|event| event.instance),
        Some(crate::failover::sim::instance_of_host(host(third)))
    );
    assert_eq!(attach(third), Ok(()));
    assert_eq!(end(third, entry), Ok(()));
    assert_eq!(stored_volume(&store, active).live(host(third)), None);
}

/// KEY-PER-ATTACH at the end write: an entry stays live while its pair carries a key that an attach holds or can
/// still take. The record holds the owner's entry 0, a gone entry 1, two live unenrolled standby attaches at 2 and 3
/// and the next number 4. The first standby's pair under the key of the other live attach, under the key of the next
/// number, under a later number's key, and under another epoch's key with the gone entry's incarnation each refuse
/// with no write. Under the gone entry's own key the entry ends.
#[test]
fn end_attach_keeps_an_entry_whose_pairs_key_an_attach_holds_or_can_take() {
    use crate::failover::records::attachment_key;
    let gate = StandbyGate::qualified();
    let active = record().active;
    let world = || {
        let store = activated();
        bump(&store);
        cycle(&store, SPARE + 7);
        for h in [SPARE, SPARE + 1] {
            reconciler(&store)
                .record_standby(
                    &gate,
                    sid(),
                    active,
                    host(h),
                    ERA,
                    &wide(),
                    &binding_of(h, &owner_peer(), Some(&owner_listing())),
                )
                .unwrap();
        }
        let held = stored_volume(&store, active);
        assert_eq!(
            (
                held.event(1).map(|event| event.kind),
                held.live(host(SPARE)),
                held.live(host(SPARE + 1)),
                held.next
            ),
            (Some(EventKind::Gone), Some(2), Some(3), 4)
        );
        store
    };
    let another_epoch = ReservationKey::new(Epoch::new(2).unwrap(), Incarnation::new(2).unwrap());
    for (key, ends, what) in [
        (
            attachment_key(3).unwrap(),
            false,
            "the key of another live attach",
        ),
        (
            attachment_key(4).unwrap(),
            false,
            "the key of the next number",
        ),
        (
            attachment_key(9).unwrap(),
            false,
            "the key of a later number",
        ),
        (
            another_epoch,
            false,
            "the gone entry's incarnation under another epoch",
        ),
        (attachment_key(1).unwrap(), true, "the gone entry's own key"),
    ] {
        let store = world();
        edit_volume(&store, active, |held| {
            let mut next = held.clone();
            next.pairs.push(RecordedPair {
                host: host(SPARE),
                attach: 2,
                pair: Pair {
                    exhid: crate::failover::evidence_tests::exhid(SPARE as u8),
                    key,
                },
            });
            next
        });
        let before = commits(&store, Key::Volume(active));
        let ended = reconciler(&store)
            .end_attach(
                &gate,
                sid(),
                record().active,
                host(SPARE),
                latest_seq(&store, SPARE),
            )
            .map(drop);
        let kind = stored_volume(&store, active)
            .latest(host(SPARE))
            .map(|(_, event)| event.kind);
        if ends {
            assert_eq!(
                (ended, kind, commits(&store, Key::Volume(active))),
                (Ok(()), Some(EventKind::Ended), before + 1),
                "{what}"
            );
        } else {
            assert_eq!(
                (ended, kind, commits(&store, Key::Volume(active))),
                (
                    Err(ReconcileError::Conflict),
                    Some(EventKind::Attach),
                    before
                ),
                "{what}"
            );
        }
    }
}

/// DETACH-AFTER-DROP and GONE-AFTER-CLEAN-LISTINGS: `release_attach` refuses a live entry and an ended entry that
/// keeps its pair, and no detach witness exists for the second; after the owner's drop the witness carries the
/// entry's instance. `release_attach` then refuses each listing set that fails the settle rule or shows the instance
/// or an unreadable record, each with no write, accepts two clean listings exactly at the settle bounds in reversed
/// order, and a retry writes nothing. Once the host attaches the same instance again and that entry ends, the earlier
/// witness refuses with no write, and the new entry's witness carries another number.
#[test]
fn an_ended_entry_is_detached_after_its_pair_drops_and_gone_after_two_clean_listings() {
    use crate::failover::sim::instance_of_host;
    let gate = StandbyGate::qualified();
    let active = record().active;
    let store = standby_world(&[SPARE], &[SPARE]);
    fn at(at: u64, instances: &[String]) -> Listing<'_> {
        Listing { at, instances }
    }
    let clean = owner_listing();
    let settled = [at(400, &clean), at(700, &clean)];
    let seq = stored_volume(&store, active).live(host(SPARE)).unwrap();
    let early = Detachable::forged(active, host(SPARE), seq, instance_of_host(host(SPARE)));
    let before = commits(&store, Key::Volume(active));
    assert_eq!(
        reconciler(&store).release_attach(&gate, &early, &settled, SETTLE),
        Err(ReconcileError::Conflict),
        "a live entry"
    );
    reconciler(&store)
        .end_attach(
            &gate,
            sid(),
            record().active,
            host(SPARE),
            latest_seq(&store, SPARE),
        )
        .unwrap();
    assert_eq!(
        reconciler(&store).detachable(active, host(SPARE)).map(drop),
        Err(ReconcileError::Conflict),
        "the ended entry keeps its pair"
    );
    let pinned = commits(&store, Key::Volume(active));
    assert_eq!(pinned, before + 1);
    assert_eq!(
        reconciler(&store).release_attach(&gate, &early, &settled, SETTLE),
        Err(ReconcileError::Conflict),
        "an ended entry that keeps its pair"
    );
    assert_eq!(commits(&store, Key::Volume(active)), pinned);
    drop_ended_pair(&store, SPARE);
    let witness = reconciler(&store).detachable(active, host(SPARE)).unwrap();
    assert_eq!(witness, early);
    let shown = vec![
        OWNER_INSTANCE.to_owned(),
        instance_of_host(host(SPARE)).as_str().to_owned(),
    ];
    let unreadable = vec![OWNER_INSTANCE.to_owned(), String::new()];
    let malformed = vec![
        OWNER_INSTANCE.to_owned(),
        format!("{} ", instance_of_host(host(SPARE)).as_str()),
    ];
    let before = commits(&store, Key::Volume(active));
    let timing = |requested, settle| Settle { requested, settle };
    for (what, listings, settle) in [
        ("no listing", vec![], SETTLE),
        ("one listing", vec![at(400, &clean)], SETTLE),
        (
            "three listings",
            vec![at(400, &clean), at(700, &clean), at(1000, &clean)],
            SETTLE,
        ),
        (
            "closer than the settle time",
            vec![at(400, &clean), at(600, &clean)],
            SETTLE,
        ),
        (
            "too soon after the request",
            vec![at(300, &clean), at(700, &clean)],
            SETTLE,
        ),
        (
            "a request after both listings",
            vec![at(400, &clean), at(800, &clean)],
            timing(900, 300),
        ),
        (
            "one listing twice under a zero settle time",
            vec![at(400, &clean), at(400, &clean)],
            timing(100, 0),
        ),
        (
            "two listings under a zero settle time",
            vec![at(400, &clean), at(700, &clean)],
            timing(100, 0),
        ),
        (
            "too soon after the request, reversed",
            vec![at(800, &clean), at(300, &clean)],
            SETTLE,
        ),
        (
            "a malformed spelling of the instance",
            vec![at(400, &clean), at(800, &malformed)],
            SETTLE,
        ),
        (
            "the later listing shows the instance",
            vec![at(400, &clean), at(800, &shown)],
            SETTLE,
        ),
        (
            "the earlier listing shows the instance",
            vec![at(400, &shown), at(800, &clean)],
            SETTLE,
        ),
        (
            "the earlier listing shows the instance, reversed",
            vec![at(800, &clean), at(400, &shown)],
            SETTLE,
        ),
        (
            "an unreadable record in the earlier listing",
            vec![at(400, &unreadable), at(800, &clean)],
            SETTLE,
        ),
        (
            "an unreadable record in the later listing",
            vec![at(400, &clean), at(800, &unreadable)],
            SETTLE,
        ),
        (
            "an unreadable record in both listings",
            vec![at(400, &unreadable), at(800, &unreadable)],
            SETTLE,
        ),
    ] {
        assert_eq!(
            reconciler(&store).release_attach(&gate, &witness, &listings, settle),
            Err(ReconcileError::Conflict),
            "{what}"
        );
    }
    assert_eq!(commits(&store, Key::Volume(active)), before);
    let listings = [at(700, &clean), at(400, &clean)];
    reconciler(&store)
        .release_attach(&gate, &witness, &listings, SETTLE)
        .unwrap();
    assert_eq!(commits(&store, Key::Volume(active)), before + 1);
    reconciler(&store)
        .release_attach(&gate, &witness, &listings, SETTLE)
        .unwrap();
    assert_eq!(commits(&store, Key::Volume(active)), before + 1);
    let other = Detachable::forged(
        active,
        host(SPARE),
        witness.seq(),
        instance_of_host(host(OWNER)),
    );
    assert_eq!(
        reconciler(&store).release_attach(&gate, &other, &listings, SETTLE),
        Err(ReconcileError::Conflict),
        "a witness of another instance under the gone entry's number"
    );
    for (what, refused) in [
        (
            "the detach witness of a gone entry",
            reconciler(&store).detachable(active, host(SPARE)).map(drop),
        ),
        (
            "the end of a gone entry",
            reconciler(&store)
                .end_attach(
                    &gate,
                    sid(),
                    record().active,
                    host(SPARE),
                    latest_seq(&store, SPARE),
                )
                .map(drop),
        ),
        (
            "the end of a host with no entry",
            reconciler(&store)
                .end_attach(
                    &gate,
                    sid(),
                    record().active,
                    host(SPARE + 30),
                    latest_seq(&store, SPARE + 30),
                )
                .map(drop),
        ),
    ] {
        assert_eq!(refused, Err(ReconcileError::Conflict), "{what}");
    }
    assert_eq!(commits(&store, Key::Volume(active)), before + 1);

    reconciler(&store)
        .record_standby(
            &gate,
            sid(),
            active,
            host(SPARE),
            ERA,
            &wide(),
            &crate::failover::sim::binding(host(SPARE)),
        )
        .unwrap();
    reconciler(&store)
        .end_attach(
            &gate,
            sid(),
            record().active,
            host(SPARE),
            latest_seq(&store, SPARE),
        )
        .unwrap();
    let again = commits(&store, Key::Volume(active));
    assert_eq!(
        reconciler(&store).release_attach(&gate, &witness, &listings, SETTLE),
        Err(ReconcileError::Conflict),
        "the witness of the earlier entry"
    );
    assert_eq!(commits(&store, Key::Volume(active)), again);
    assert_eq!(
        stored_volume(&store, active)
            .latest(host(SPARE))
            .map(|(_, event)| event.kind),
        Some(EventKind::Ended)
    );
    let fresh = reconciler(&store).detachable(active, host(SPARE)).unwrap();
    assert_eq!(fresh.instance(), witness.instance());
    assert!(fresh.seq() > witness.seq());
    let mismatched = Detachable::forged(
        active,
        host(SPARE),
        fresh.seq(),
        instance_of_host(host(OWNER)),
    );
    assert_eq!(
        reconciler(&store).release_attach(&gate, &mismatched, &listings, SETTLE),
        Err(ReconcileError::Conflict),
        "a witness of another instance under the ended entry's number"
    );
    let late = [at(1400, &clean), at(1700, &clean)];
    let after = Settle {
        requested: 1000,
        settle: 300,
    };
    reconciler(&store)
        .release_attach(&gate, &fresh, &late, after)
        .unwrap();
    let gone = commits(&store, Key::Volume(active));
    assert_eq!(
        reconciler(&store).release_attach(&gate, &witness, &late, after),
        Err(ReconcileError::Conflict),
        "the earlier witness against the later gone entry"
    );
    assert_eq!(commits(&store, Key::Volume(active)), gone);
}

/// A gone mark of unknown outcome, retried by a second reconciler with the same witness, leaves one gone entry.
#[test]
fn an_unknown_gone_write_leaves_one_gone_entry() {
    let gate = StandbyGate::qualified();
    let active = record().active;
    for commit in [false, true] {
        let store = standby_world(&[SPARE], &[SPARE]);
        reconciler(&store)
            .end_attach(
                &gate,
                sid(),
                record().active,
                host(SPARE),
                latest_seq(&store, SPARE),
            )
            .unwrap();
        drop_ended_pair(&store, SPARE);
        let witness = reconciler(&store).detachable(active, host(SPARE)).unwrap();
        let clean = owner_listing();
        let listings = [
            Listing {
                at: 400,
                instances: &clean,
            },
            Listing {
                at: 700,
                instances: &clean,
            },
        ];
        let before = commits(&store, Key::Volume(active));
        park(&store, 1, Arm::Timeout { commit });
        assert_eq!(
            reconciler(&store).release_attach(&gate, &witness, &listings, SETTLE),
            Err(ReconcileError::Store(StoreError::Unknown)),
            "commit {commit}"
        );
        assert_eq!(
            stored_volume(&store, active)
                .latest(host(SPARE))
                .map(|(_, event)| event.kind),
            Some(if commit {
                EventKind::Gone
            } else {
                EventKind::Ended
            })
        );
        reconciler(&store)
            .release_attach(&gate, &witness, &listings, SETTLE)
            .unwrap();
        assert_eq!(
            commits(&store, Key::Volume(active)),
            before + 1,
            "commit {commit}"
        );
    }
}

/// A record that binds one instance to a live entry and to another host's ended entry with no pair yields no detach
/// witness for the ended entry, and neither does one that binds it to another host's ended entry that keeps its pair.
/// Once that pair dropped, the witness exists.
#[test]
fn a_shared_instance_yields_no_detach_witness() {
    use crate::failover::sim::instance_of_host;
    let active = record().active;
    let mut held = stored_volume(&standby_world(&[SPARE], &[]), active);
    held.push(EventKind::Attach, host(SPARE + 1), ERA);
    let entry = held.events.last_mut().unwrap();
    entry.instance = Some(instance_of_host(host(SPARE)));
    entry.kind = EventKind::Ended;
    assert_eq!(VolumeRecord::decode(&held.encode()), Ok(held.clone()));
    let store = seeded_with(held);
    assert_eq!(
        reconciler(&store)
            .detachable(active, host(SPARE + 1))
            .map(drop),
        Err(ReconcileError::Conflict)
    );

    let mut held = stored_volume(&standby_world(&[SPARE], &[SPARE]), active);
    held = ended(&held, SPARE);
    assert!(held.pinned(host(SPARE), 1).is_some());
    held.push(EventKind::Attach, host(SPARE + 1), ERA);
    let entry = held.events.last_mut().unwrap();
    entry.instance = Some(instance_of_host(host(SPARE)));
    entry.kind = EventKind::Ended;
    assert_eq!(VolumeRecord::decode(&held.encode()), Ok(held.clone()));
    let store = seeded_with(held);
    assert_eq!(
        reconciler(&store)
            .detachable(active, host(SPARE + 1))
            .map(drop),
        Err(ReconcileError::Conflict),
        "another host's ended entry that keeps its pair binds the instance"
    );
    drop_ended_pair(&store, SPARE);
    let witness = reconciler(&store)
        .detachable(active, host(SPARE + 1))
        .unwrap();
    assert_eq!(
        (witness.seq(), witness.instance()),
        (2, instance_of_host(host(SPARE))),
        "once that pair dropped, no live or paired entry binds the instance"
    );
}

/// DETACH-RELISTED: a host whose latest entry is gone and binds an instance no attach or ended entry binds yields a
/// `Relisted` witness. Control: the same gone entry while a live entry, or another host's ended entry, binds its
/// instance yields none, and so does a latest entry that is ended, live or absent.
#[test]
fn a_gone_entry_yields_a_relisted_witness_only_while_no_live_or_ended_entry_binds_its_instance() {
    use crate::failover::sim::instance_of_host;
    let active = record().active;
    let base = stored_volume(&standby_world(&[SPARE], &[]), active);
    let with = |kind: EventKind, by: Option<(u64, EventKind)>| {
        let mut held = base.clone();
        let seq = held.live(host(SPARE)).unwrap();
        held.events.iter_mut().find(|e| e.seq == seq).unwrap().kind = kind;
        if let Some((h, other)) = by {
            held.push(EventKind::Attach, host(h), ERA);
            let entry = held.events.last_mut().unwrap();
            entry.instance = Some(instance_of_host(host(SPARE)));
            entry.kind = other;
        }
        held
    };
    let witness = |held: VolumeRecord| {
        let store = seeded_with(held);
        reconciler(&store)
            .relisted(active, host(SPARE))
            .map(|w| (w.seq(), w.instance()))
    };
    let gone = with(EventKind::Gone, None);
    let seq = gone.latest(host(SPARE)).unwrap().0;
    assert_eq!(witness(gone), Ok((seq, instance_of_host(host(SPARE)))));
    let refused = Err(ReconcileError::Conflict);
    assert_eq!(
        witness(with(EventKind::Gone, Some((SPARE + 1, EventKind::Attach)))),
        refused,
        "a live entry binds it"
    );
    assert_eq!(
        witness(with(EventKind::Gone, Some((SPARE + 1, EventKind::Ended)))),
        refused,
        "an ended entry binds it"
    );
    assert_eq!(witness(with(EventKind::Ended, None)), refused, "ended");
    assert_eq!(witness(with(EventKind::Attach, None)), refused, "live");
    let store = seeded_with(base.clone());
    assert_eq!(
        reconciler(&store)
            .relisted(active, host(SPARE + 9))
            .map(drop),
        Err(ReconcileError::Conflict),
        "no entry"
    );
}

/// Four standby replacements in a row, each through record, attach, enroll, designation, the end of the replaced
/// standby, the owner's pair drop, the detach witness and the gone mark; then owner loss and the last standby's
/// takeover; then two more replacements, the second the deposed owner attached again under a new entry and key;
/// then further replacements until the record sheds its oldest gone entries at `MAX_EVENTS`. The volume stays active at its generation, live entries never exceed
/// `MAX_ATTACHED`, entries never exceed `MAX_EVENTS`, and the last designation succeeds. Control: without
/// `end_attach` the fourth attach of the volume's life refuses `Closed`.
#[test]
fn a_volume_outlives_repeated_replacement_across_a_takeover() {
    use crate::failover::records::MAX_EVENTS;
    let gate = StandbyGate::qualified();
    let active = record().active;
    let control = standby_world(&[SPARE, SPARE + 1], &[SPARE, SPARE + 1]);
    assert_eq!(
        reconciler(&control)
            .record_standby(
                &gate,
                sid(),
                active,
                host(SPARE + 2),
                ERA,
                &wide(),
                &crate::failover::sim::binding(host(SPARE + 2))
            )
            .map(drop),
        Err(ReconcileError::Conflict),
        "control: the fourth attach of the volume's life without an end"
    );
    assert_eq!(
        Attach::of(&stored_volume(&control, active), host(SPARE + 2), &wide()),
        Attach::Closed
    );

    let store = activated();
    bump(&store);
    let generation = stored(&store).1.generation;
    let designate = |store: &Shared, h: u64| {
        let slot = slot_for(store, h);
        reconciler(store).designate(&gate, &slot, active).unwrap();
        assert_eq!(stored(store).1.standby, Some(host(h)));
    };
    let replace = |store: &Shared, old: Option<u64>, new: u64| {
        attach_enrolled(store, new);
        bounded(store, generation);
        designate(store, new);
        if let Some(old) = old {
            let ended = reconciler(store)
                .end_attach(
                    &gate,
                    sid(),
                    record().active,
                    host(old),
                    latest_seq(store, old),
                )
                .unwrap();
            assert!(!ended.named());
            drop_ended_pair(store, old);
            detach_and_release(store, old);
        }
        bounded(store, generation);
    };
    let standbys = [SPARE, SPARE + 1, SPARE + 2, SPARE + 3, SPARE + 4];
    replace(&store, None, standbys[0]);
    assert_eq!(standbys.windows(2).len(), 4);
    for pair in standbys.windows(2) {
        replace(&store, Some(pair[0]), pair[1]);
    }
    let successor = standbys[4];
    let read = client(&store)
        .read::<ShardRecord>(Key::Shard(sid()))
        .unwrap();
    client(&store)
        .take_over(&read, Target::of(read.value()), host(successor))
        .unwrap();
    assert_eq!(stored(&store).1.owner, host(successor));
    let old_key = stored_volume(&store, active)
        .attach_key(host(OWNER))
        .unwrap();
    let ended = reconciler(&store)
        .end_attach(
            &gate,
            sid(),
            record().active,
            host(OWNER),
            latest_seq(&store, OWNER),
        )
        .unwrap();
    assert!(!ended.named());
    drop_ended_pair(&store, OWNER);
    detach_and_release(&store, OWNER);
    bounded(&store, generation);
    replace(&store, None, SPARE + 5);
    replace(&store, Some(SPARE + 5), OWNER);
    let held = stored_volume(&store, active);
    let key = held
        .attach_key(host(OWNER))
        .expect("the deposed owner holds a live attach again");
    assert_ne!(
        key, old_key,
        "the deposed owner's new attach takes a new key"
    );
    assert_eq!(held.enrolled(host(OWNER)).map(|pair| pair.key), Some(key));
    assert_eq!(stored(&store).1.standby, Some(host(OWNER)));

    let mut old = OWNER;
    for new in SPARE + 6..SPARE + 16 {
        replace(&store, Some(old), new);
        old = new;
    }
    let held = stored_volume(&store, active);
    assert_eq!(held.events.len(), MAX_EVENTS);
    assert!(held.next as usize > MAX_EVENTS + 1, "{held:?}");
    assert!(
        held.event(0).is_none(),
        "the oldest gone entry, whose instance no listing shows, leaves first"
    );
    assert_eq!(stored(&store).1.standby, Some(host(old)));
}

/// A failed attach: the entry is recorded, the attach request errors, the entry is ended, and the listing later
/// shows the instance attached. The owner's poll continues over it, the host's enrollment refuses `Unattached`, the
/// detach witness exists at once since the attach never enrolled, and the entry goes only after two clean listings.
#[test]
fn a_failed_attach_ends_and_goes_only_after_clean_listings() {
    use crate::failover::attachments::InstanceId;
    use crate::failover::poll::{Holder, Reads, Verdict, poll};
    use crate::failover::reconcile::{StandbyRefusal, enroll_standby};
    use crate::failover::sim::instance_of_host;
    let gate = StandbyGate::qualified();
    let active = record().active;
    let store = activated();
    bump(&store);
    let listing = owner_listing();
    reconciler(&store)
        .record_standby(
            &gate,
            sid(),
            active,
            host(SPARE),
            ERA,
            &wide(),
            &binding_of(SPARE, &owner_peer(), Some(&listing)),
        )
        .unwrap();
    assert_eq!(
        reconciler(&store).detachable(active, host(SPARE)).map(drop),
        Err(ReconcileError::Conflict),
        "a live attach has no detach witness"
    );
    reconciler(&store)
        .end_attach(
            &gate,
            sid(),
            record().active,
            host(SPARE),
            latest_seq(&store, SPARE),
        )
        .unwrap();
    let late = vec![
        OWNER_INSTANCE.to_owned(),
        instance_of_host(host(SPARE)).as_str().to_owned(),
    ];
    let shard = stored(&store).1;
    let volume = stored_volume(&store, active);
    let entries = [crate::failover::evidence::Registrant {
        cntlid: 1,
        pair: crate::failover::evidence_tests::pair(1, 1, 1),
        holder: true,
    }];
    let holder = Holder {
        volume: active,
        host: host(OWNER),
        instance: InstanceId::new(OWNER_INSTANCE).unwrap(),
    };
    assert_eq!(
        poll(
            &holder,
            Target::of(&shard),
            crate::failover::evidence_tests::pair(1, 1, 1),
            Ok(&crate::failover::evidence_tests::report(&entries)),
            &Reads {
                shard: Some(&shard),
                volume: Some(&volume),
                listed: Some(&late),
                peers: &[],
            },
            &wide(),
        ),
        Verdict::Continue,
        "the late attachment of an ended entry retires nothing"
    );
    let standby = Holder {
        host: host(SPARE),
        instance: instance_of_host(host(SPARE)),
        ..holder
    };
    assert_eq!(
        enroll_standby(&gate, sid(), &standby, &wide(), &mut client(&store), |_| {
            panic!("an ended attach persists nothing")
        }),
        Err(StandbyRefusal::Enrollment(
            crate::failover::records::Enrollment::Unattached
        ))
    );
    let witness = reconciler(&store).detachable(active, host(SPARE)).unwrap();
    assert_eq!(witness.instance(), instance_of_host(host(SPARE)));
    let clean = owner_listing();
    assert_eq!(
        reconciler(&store).release_attach(
            &gate,
            &witness,
            &[
                Listing {
                    at: 400,
                    instances: &clean
                },
                Listing {
                    at: 800,
                    instances: &late
                }
            ],
            SETTLE
        ),
        Err(ReconcileError::Conflict),
        "the listing still shows the late attachment"
    );
    detach_and_release(&store, SPARE);
}

/// The owner's poll of the active volume over the records `store` holds now and `listing`, with no caller-bound
/// peer, under a Report in which the owner's pair holds and each pair of `beside` is registered without holding.
fn owners_poll(
    store: &Shared,
    listing: &[String],
    beside: &[Pair],
) -> crate::failover::poll::Verdict {
    use crate::failover::evidence_tests::{entry, pair, report};
    use crate::failover::poll::{Holder, Reads, poll};
    let own = pair(1, 1, 1);
    let shard = stored(store).1;
    let volume = stored_volume(store, shard.active);
    let mut entries = vec![entry(1, own, true)];
    entries.extend(
        beside
            .iter()
            .enumerate()
            .map(|(at, &registered)| entry(2 + at as u16, registered, false)),
    );
    poll(
        &Holder {
            volume: shard.active,
            host: host(OWNER),
            instance: crate::failover::attachments::InstanceId::new(OWNER_INSTANCE).unwrap(),
        },
        Target::of(&shard),
        own,
        Ok(&report(&entries)),
        &Reads {
            shard: Some(&shard),
            volume: Some(&volume),
            listed: Some(listing),
            peers: &[],
        },
        &wide(),
    )
}

/// The owner's retirement request on `trigger` under the records `store` holds now.
fn owner_retires(store: &Shared, trigger: Trigger) -> crate::failover::poll::Verdict {
    let shard = stored(store).1;
    crate::failover::poll::Verdict::Retire(
        Retirement::new(shard.active, Role::Active, Target::of(&shard), trigger).unwrap(),
    )
}

/// GONE-AFTER-CLEAN-LISTINGS rests on a premise of [`Settle`] that `release_attach` cannot check: the settle time
/// covers the span an owner's poll holds a listing before it reads the volume record. A poll that reads the listing
/// of the still-attached instance and then the volume record before the gone mark continues, and so does a poll whose
/// listing follows the detach. A poll that holds the earlier listing across the gone mark judges the instance against
/// a record that no longer admits it and requests the volume's retirement on `Attachment(Foreign)`.
#[test]
fn a_poll_that_holds_a_listing_across_the_gone_mark_requests_retirement() {
    use crate::failover::poll::Verdict;
    use crate::failover::sim::instance_of_host;
    let gate = StandbyGate::qualified();
    let store = activated();
    bump(&store);
    attach_enrolled(&store, SPARE);
    reconciler(&store)
        .end_attach(
            &gate,
            sid(),
            record().active,
            host(SPARE),
            latest_seq(&store, SPARE),
        )
        .unwrap();
    drop_ended_pair(&store, SPARE);
    let spare = instance_of_host(host(SPARE)).as_str().to_owned();
    let attached = attached_now(&store);
    assert_eq!(attached, [OWNER_INSTANCE.to_owned(), spare.clone()]);
    assert_eq!(
        owners_poll(&store, &attached, &[]),
        Verdict::Continue,
        "the record read before the gone mark admits the ended entry's instance"
    );
    detach_and_release(&store, SPARE);
    assert_eq!(attached_now(&store), owner_listing());
    assert_eq!(
        owners_poll(&store, &owner_listing(), &[]),
        Verdict::Continue,
        "a listing taken after the detach"
    );
    assert_eq!(
        owners_poll(&store, &attached, &[]),
        owner_retires(&store, Trigger::Attachment(Mismatch::Foreign(spare))),
        "a listing held across the gone mark shows an instance the record no longer admits"
    );
}

/// A gone entry's key reads as an ended key after the entry left the record. The seventeenth attach of the volume's
/// life sheds the oldest gone entry; a registrant under that entry's key, a late Register of the attach it recorded,
/// passes the owner's poll before the shed and after it. Control: a registrant under the key of the next unused
/// number, which no entry has taken, retires on `ForeignRegistrant`.
#[test]
fn a_shed_gone_entrys_key_still_reads_as_an_ended_key() {
    use crate::failover::evidence::NotSole;
    use crate::failover::poll::Verdict;
    use crate::failover::records::{Registration, attachment_key};
    let gate = StandbyGate::qualified();
    let active = record().active;
    let (store, hosts) = full_record();
    let full = stored_volume(&store, active);
    let oldest = full
        .events
        .iter()
        .find(|event| event.kind == EventKind::Gone)
        .map(|event| event.seq)
        .unwrap();
    assert_eq!(
        full.event(oldest).map(|event| event.host),
        Some(host(hosts[0]))
    );
    let late = Pair {
        exhid: crate::failover::evidence_tests::exhid(hosts[0] as u8),
        key: attachment_key(oldest).unwrap(),
    };
    assert_eq!(full.registrant(&late), Registration::Ended);
    assert_eq!(
        owners_poll(&store, &attached_now(&store), &[late]),
        Verdict::Continue,
        "the retained gone entry's key"
    );
    let newcomer = SPARE + 40;
    let listing = owner_listing();
    reconciler(&store)
        .record_standby(
            &gate,
            sid(),
            active,
            host(newcomer),
            ERA,
            &wide(),
            &binding_of(newcomer, &[], Some(&listing)),
        )
        .unwrap();
    let shed = stored_volume(&store, active);
    assert!(shed.event(oldest).is_none(), "the oldest gone entry left");
    assert_eq!(shed.registrant(&late), Registration::Ended);
    assert_eq!(
        owners_poll(&store, &attached_now(&store), &[late]),
        Verdict::Continue,
        "the shed entry's key is still an ended attach's"
    );
    let unused = Pair {
        key: attachment_key(shed.next).unwrap(),
        ..late
    };
    assert_eq!(shed.registrant(&unused), Registration::Unknown);
    assert_eq!(
        owners_poll(&store, &attached_now(&store), &[unused]),
        owner_retires(&store, Trigger::Report(NotSole::ForeignRegistrant)),
        "control: a key no entry has taken is a foreign registrant's"
    );
}

/// A failed attach that lands after its entry's detach request. While the entry is ended, its listed instance is
/// expected state: the owner's poll continues, and the gone mark refuses until two settled listings omit the instance
/// again. [`Settle`] leaves the landing of every request to the caller: an attachment that lands after the gone mark
/// is an instance no attach or ended entry binds, so the owner's poll requests retirement on `Attachment(Foreign)`,
/// and the host takes no new entry while a listing shows its instance.
#[test]
fn a_failed_attach_that_lands_after_its_detach_request_blocks_the_gone_mark() {
    use crate::failover::poll::Verdict;
    use crate::failover::sim::instance_of_host;
    let gate = StandbyGate::qualified();
    let active = record().active;
    let store = activated();
    bump(&store);
    let clean = owner_listing();
    let record_spare = |listing: &[String]| {
        reconciler(&store).record_standby(
            &gate,
            sid(),
            active,
            host(SPARE),
            ERA,
            &wide(),
            &binding_of(SPARE, &owner_peer(), Some(listing)),
        )
    };
    record_spare(&clean).unwrap();
    reconciler(&store)
        .end_attach(
            &gate,
            sid(),
            record().active,
            host(SPARE),
            latest_seq(&store, SPARE),
        )
        .unwrap();
    let witness = reconciler(&store).detachable(active, host(SPARE)).unwrap();
    let spare = instance_of_host(host(SPARE)).as_str().to_owned();
    let landed = vec![OWNER_INSTANCE.to_owned(), spare.clone()];
    assert_eq!(
        owners_poll(&store, &landed, &[]),
        Verdict::Continue,
        "the attachment landed while its entry is ended"
    );
    let before = commits(&store, Key::Volume(active));
    for (first, second, what) in [
        (
            &clean,
            &landed,
            "the later listing shows the landed attachment",
        ),
        (&landed, &clean, "the earlier listing shows it"),
        (&landed, &landed, "both listings show it"),
    ] {
        let listings = [
            Listing {
                at: 400,
                instances: first,
            },
            Listing {
                at: 800,
                instances: second,
            },
        ];
        assert_eq!(
            reconciler(&store).release_attach(&gate, &witness, &listings, SETTLE),
            Err(ReconcileError::Conflict),
            "{what}"
        );
    }
    assert_eq!(commits(&store, Key::Volume(active)), before);
    detach_and_release(&store, SPARE);
    assert_eq!(
        owners_poll(&store, &clean, &[]),
        Verdict::Continue,
        "the entry went after two clean listings"
    );
    assert_eq!(
        owners_poll(&store, &landed, &[]),
        owner_retires(&store, Trigger::Attachment(Mismatch::Foreign(spare))),
        "an attachment that lands after the gone mark is outside every entry"
    );
    let before = commits(&store, Key::Volume(active));
    assert_eq!(
        record_spare(&landed).map(drop),
        Err(ReconcileError::Conflict),
        "the host takes no new entry while a listing shows its instance"
    );
    assert_eq!(commits(&store, Key::Volume(active)), before);
    record_spare(&clean).unwrap();
    assert_eq!(
        owners_poll(&store, &landed, &[]),
        Verdict::Continue,
        "the host's new entry binds the instance again"
    );
}

/// With no owner past its fencing boundary to drop ended pairs, successors that each attach, enroll, stop and are
/// ended fill the pair cap: the next attach refuses `Closed` with no write, and nothing retires.
#[test]
fn ended_successors_fill_the_pair_cap_and_the_next_attach_refuses() {
    let gate = StandbyGate::qualified();
    let active = record().active;
    let store = activated();
    bump(&store);
    let generation = stored(&store).1.generation;
    let cap = wide().pair_cap();
    let successors: Vec<u64> = (0..cap as u64 - 1).map(|at| SPARE + 20 + at).collect();
    for &h in &successors {
        attach_enrolled(&store, h);
        reconciler(&store)
            .end_attach(
                &gate,
                sid(),
                record().active,
                host(h),
                latest_seq(&store, h),
            )
            .unwrap();
        bounded(&store, generation);
    }
    let held = stored_volume(&store, active);
    assert_eq!(held.pairs.len(), cap);
    let next = SPARE + 60;
    assert_eq!(Attach::of(&held, host(next), &wide()), Attach::Closed);
    let before = commits(&store, Key::Volume(active));
    let listing = owner_listing();
    assert_eq!(
        reconciler(&store)
            .record_standby(
                &gate,
                sid(),
                active,
                host(next),
                ERA,
                &wide(),
                &binding_of(next, &owner_peer(), Some(&listing))
            )
            .map(drop),
        Err(ReconcileError::Conflict)
    );
    assert_eq!(commits(&store, Key::Volume(active)), before);
    bounded(&store, generation);
}
