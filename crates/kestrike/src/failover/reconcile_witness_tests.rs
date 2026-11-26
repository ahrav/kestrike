//! A reconciler write of unknown outcome returns no witness, and the retry returns it.
//!
//! ACKNOWLEDGED-ONLY over a simulated store: a reconciler write whose reply is unknown, a timeout or a failure
//! that may or may not have committed, ends its step with `StoreError::Unknown` and no witness, and the retry
//! returns the witness after it finds the write or makes it. The three writes are the attach write of
//! `Reconciler::record_attach` and the retired-state write and the settling shard write of `Reconciler::retire`,
//! each under the four unknown-outcome arms, one store per arm.
//!
//! Each test reads what the calls left into a value, computes the value the arm must leave from the arm alone,
//! and asserts afterwards.

use crate::failover::reconcile::{ReconcileError, Reconciler};
use crate::failover::records::{
    AttachmentEvent, ERA, EventKind, Record, ShardRecord, VolumeId, VolumeRecord, VolumeState,
};
use crate::failover::sim::{host, layout};
use crate::storage::store::sim::{Arm, AsProvisioner, AsReconciler, MemLog, Shared};
use crate::storage::store::{Client, Key, StoreError};
use crate::storage::store_tests::{OWNER, SPARE, UNKNOWN, committed, record, shard as sid};

/// `record_attach`: the volume read, then the attach write.
const ATTACH_WRITE: usize = 1;
/// `retire` of a fresh volume: the volume read, the shard read, then the retired-state write.
const RETIRED_WRITE: usize = 2;
/// `retire` of a fresh volume: the settling shard write follows the retired-state write.
const SETTLING_WRITE: usize = 3;

/// The volume every step here acts on; the shard record never names it.
fn displaced() -> VolumeId {
    VolumeId::new("vol-0c").unwrap()
}

/// The long-running reconciler, over the store as its principal reaches it.
fn reconciler(store: &Shared) -> Reconciler<AsReconciler<Shared>, MemLog> {
    Reconciler::new(Client::open(AsReconciler(store.clone()), MemLog::default()).unwrap())
}

/// A store holding the shard created with no spare, its active volume provisioned and attached to the owner,
/// and [`displaced`] provisioned with no attach event.
fn world() -> Shared {
    let store = Shared::new();
    Reconciler::new(Client::open(AsProvisioner(store.clone()), MemLog::default()).unwrap())
        .create_shard(ShardRecord {
            spare: None,
            ..record()
        })
        .unwrap();
    let mut reconciler = reconciler(&store);
    reconciler.provision(record().active, layout()).unwrap();
    reconciler
        .record_attach(record().active, host(OWNER), ERA)
        .unwrap();
    reconciler.provision(displaced(), layout()).unwrap();
    store
}

/// [`world`] with [`displaced`] attached to the spare host, the state `retire` finds a volume in that no flip
/// names any more.
fn attached_world() -> Shared {
    let store = world();
    reconciler(&store)
        .record_attach(displaced(), host(SPARE), ERA)
        .unwrap();
    store
}

/// Queues `requests` passing requests and then `arm`, so `arm` meets the step's request of that index.
fn park(store: &Shared, requests: usize, arm: Arm) {
    for _ in 0..requests {
        store.schedule(Arm::Pass);
    }
    store.schedule(arm);
}

/// What the store holds for [`displaced`] and the shard: the volume's state, its attachment events, the commits
/// of its record and the commits of the shard record. Reading it consumes no scheduled arm.
type Held = (VolumeState, Vec<AttachmentEvent>, usize, usize);

fn held(store: &Shared) -> Held {
    let sim = store.0.borrow();
    let item = sim.current(&Key::Volume(displaced())).cloned().unwrap();
    let volume = VolumeRecord::decode(&item.value).unwrap();
    (
        volume.state,
        volume.events,
        sim.commit_count(&Key::Volume(displaced())),
        sim.commit_count(&Key::Shard(sid())),
    )
}

/// One step run twice: the first call's result without its witness, what the store held after it, whether the
/// retry returned a witness, and what the store held after the retry.
type Ran = (Result<(), ReconcileError>, Held, bool, Held);

/// Runs `step` with `arm` on its request of index `requests`, then runs it again with nothing scheduled.
fn unknown_then_retry<T>(
    store: &Shared,
    requests: usize,
    arm: Arm,
    mut step: impl FnMut() -> Result<T, ReconcileError>,
) -> Ran {
    park(store, requests, arm);
    let first = step().map(drop);
    let after_first = held(store);
    let retried = step().is_ok();
    (first, after_first, retried, held(store))
}

const UNKNOWN_OUTCOME: Result<(), ReconcileError> = Err(ReconcileError::Store(StoreError::Unknown));

/// The one attach event `record_attach` writes for [`displaced`] here.
fn attach_event() -> AttachmentEvent {
    AttachmentEvent {
        seq: 0,
        kind: EventKind::Attach,
        host: host(SPARE),
        era: ERA,
        instance: None,
    }
}

/// An attach write whose reply is unknown returns `Unknown` and no `AttachRecorded`, whether or not the store
/// committed it. The retry returns the witness: over a committed write it reads the event and writes nothing,
/// over an uncommitted one it makes the write, so the record ends fresh with the one event after exactly one
/// committed attach write. The provisioning create is the record's first commit and the attach write its second.
#[test]
fn an_attach_write_of_unknown_outcome_returns_no_witness_and_the_retry_returns_it_after_one_committed_write()
 {
    let mut ran = Vec::new();
    let mut expected = Vec::new();
    for arm in UNKNOWN {
        let store = world();
        let mut reconciler = reconciler(&store);
        ran.push((
            arm,
            unknown_then_retry(&store, ATTACH_WRITE, arm, || {
                reconciler.record_attach(displaced(), host(SPARE), ERA)
            }),
        ));
        let after_first = if committed(arm) {
            (VolumeState::Fresh, vec![attach_event()], 2, 1)
        } else {
            (VolumeState::Provisioning, Vec::new(), 1, 1)
        };
        let after_retry = (VolumeState::Fresh, vec![attach_event()], 2, 1);
        expected.push((arm, (UNKNOWN_OUTCOME, after_first, true, after_retry)));
    }
    assert_eq!(ran, expected);
}

/// A retired-state write whose reply is unknown returns `Unknown` and no `Retired`, and the step stops before
/// the settling shard write. The retry returns the witness: over a committed write it reads the retired state
/// and goes to the settling write, over an uncommitted one it writes the state first, so the volume record takes
/// exactly one retired-state write, its third commit, and the shard record one settling write, its second.
#[test]
fn a_retired_state_write_of_unknown_outcome_returns_no_witness_and_the_retry_returns_it_after_one_committed_write()
 {
    let mut ran = Vec::new();
    let mut expected = Vec::new();
    for arm in UNKNOWN {
        let store = attached_world();
        let mut reconciler = reconciler(&store);
        ran.push((
            arm,
            unknown_then_retry(&store, RETIRED_WRITE, arm, || {
                reconciler.retire(sid(), displaced())
            }),
        ));
        let after_first = if committed(arm) {
            (VolumeState::Retired, vec![attach_event()], 3, 1)
        } else {
            (VolumeState::Fresh, vec![attach_event()], 2, 1)
        };
        let after_retry = (VolumeState::Retired, vec![attach_event()], 3, 2);
        expected.push((arm, (UNKNOWN_OUTCOME, after_first, true, after_retry)));
    }
    assert_eq!(ran, expected);
}

/// A settling shard write whose reply is unknown returns `Unknown` and no `Retired`, with the retired state
/// already written. The retry reads the volume retired, writes no volume record and returns the witness from a
/// settling write of its own that the store acknowledges, so the shard record holds one settling commit more
/// when the unknown write had committed.
#[test]
fn a_settling_write_of_unknown_outcome_returns_no_witness_and_the_retry_returns_it_from_its_own_acknowledged_write()
 {
    let mut ran = Vec::new();
    let mut expected = Vec::new();
    for arm in UNKNOWN {
        let store = attached_world();
        let mut reconciler = reconciler(&store);
        ran.push((
            arm,
            unknown_then_retry(&store, SETTLING_WRITE, arm, || {
                reconciler.retire(sid(), displaced())
            }),
        ));
        let unknown_commits = usize::from(committed(arm));
        let after_first = (
            VolumeState::Retired,
            vec![attach_event()],
            3,
            1 + unknown_commits,
        );
        let after_retry = (
            VolumeState::Retired,
            vec![attach_event()],
            3,
            2 + unknown_commits,
        );
        expected.push((arm, (UNKNOWN_OUTCOME, after_first, true, after_retry)));
    }
    assert_eq!(ran, expected);
}
