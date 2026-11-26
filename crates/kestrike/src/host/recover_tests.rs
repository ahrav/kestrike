use super::fencer::{Fencer, Release};
use super::fencer_tests::{commands, connected, fencer_of, shared_table, stop};
use super::inputs::peers;
use super::inputs_tests::inputs_of;
use super::recover::{Recovery, Role, Sources, Tenure, fresh_exit, recover, restart_exit, role};
use super::{Exit, HostGate, Inputs, Refusal, Rerun};
use crate::failover::admission::AdmissionError;
use crate::failover::attachments::Peer;
use crate::failover::fresh::tests::{self as fresh_tests, registrant};
use crate::failover::fresh::{self, LocalRecords, Refusals};
use crate::failover::identity::Key as ReservationKey;
use crate::failover::poll::Holder;
use crate::failover::record::LocalRecord;
use crate::failover::records::CodecError;
use crate::failover::records::{Record, ShardRecord, VolumeId, VolumeRecord, VolumeState};
use crate::failover::report::{
    RecoveryCheck, RecoveryKind, RecoveryNext, RecoveryRefusal, RecoveryStatus,
};
use crate::failover::restart::tests::{host as owner_host, shard_record, store, volume_id};
use crate::failover::restart::tests::{own, shard_now};
use crate::failover::restart::{self as restart_seq, Check, Local, LocalSource};
use crate::failover::retire::Target;
use crate::failover::takeover::tests::{
    b_host, b_pair, c_host, c_pair, holder_of, instance_of, lineage, with_c, with_c_and_b,
};
use crate::net::ownership::session_of;
use crate::storage::BufferArena;
use crate::storage::device::connect::Connected;
use crate::storage::device::sim::SimControl;
use crate::storage::gate_fixture::{Control, Reserving, ZeroClock, arena_with, foreign};
use crate::storage::gate_fixture::{Ticking, limits};
use crate::storage::page_coverage::{FenceRefused, FencingRefusal, Withdraw};
use crate::storage::store::sim::{Arm, MemLog, Recorder, Shared};
use crate::storage::store::{Client, Key, StoreError};
use crate::storage::store_tests::{client, shard};
use crate::storage::test_platform::TestPlatform;
use crate::storage::{Bomb, Dropped};

/// A client over `store` and the recorder of every request it issues.
fn traced_client(store: &Shared) -> (Client<Recorder, MemLog>, Recorder) {
    let recorder = Recorder::new(store);
    let client = Client::open(recorder.clone(), MemLog::default()).unwrap();
    (client, recorder)
}

/// The role `holder` reads from `store`, with every store request in issue order as `(write, key)`.
fn traced_role(store: &Shared, holder: &Holder) -> (Result<Role, StoreError>, Vec<(bool, Key)>) {
    let (mut client, recorder) = traced_client(store);
    let role = role(&mut client, shard(), holder);
    (role, super::wait_tests::keyed(&recorder))
}

/// When the volume read succeeds, `role` issues exactly two requests: the volume read followed by the shard read
/// (READ-ORDER, ROLE-LICENSES-NOTHING).
pub(super) fn two_reads() -> Vec<(bool, Key)> {
    reads_of(volume_id())
}

/// The two requests of a role read for the host of `volume`: its volume read followed by the shard read.
pub(super) fn reads_of(volume: crate::failover::records::VolumeId) -> Vec<(bool, Key)> {
    vec![(false, Key::Volume(volume)), (false, Key::Shard(shard()))]
}

/// A, the owner, holds `Restart` at `E > 0`, `E = 1` included, and `Fresh` at `E = 0`, on a volume record in state
/// active and in state fresh, as the flip leaves it; C, the owner a takeover made, holds `Restart` though A attached
/// first; C, the record's standby, holds `Standby` at the record's `(g, owner, E)`; B's attachment and enrollment alone
/// yield `Unnamed`. Each tested role resolution issues exactly two requests: the volume read followed by the shard
/// read.
#[test]
fn the_records_name_each_role_with_two_reads_and_no_write() {
    let named = ShardRecord {
        standby: Some(c_host()),
        ..shard_record(4)
    };
    let taken = ShardRecord {
        owner: c_host(),
        ..shard_record(5)
    };
    let flipped = VolumeRecord {
        state: VolumeState::Fresh,
        ..with_c_and_b()
    };
    let flipped_c = flipped.clone();
    let cases = [
        (shard_record(4), with_c_and_b(), owner_host(), Role::Restart),
        (shard_record(1), with_c_and_b(), owner_host(), Role::Restart),
        (shard_record(0), with_c_and_b(), owner_host(), Role::Fresh),
        (
            shard_record(1),
            flipped.clone(),
            owner_host(),
            Role::Restart,
        ),
        (shard_record(0), flipped, owner_host(), Role::Fresh),
        (taken, with_c_and_b(), c_host(), Role::Restart),
        (
            named,
            with_c_and_b(),
            c_host(),
            Role::Standby {
                target: Target::of(&named),
            },
        ),
        (named, with_c_and_b(), b_host(), Role::Unnamed),
        (
            named,
            flipped_c,
            c_host(),
            Role::Standby {
                target: Target::of(&named),
            },
        ),
    ];
    for (record, volume, host, expected) in cases {
        let store = store(record, volume);
        let (read, calls) = traced_role(&store, &holder_of(host));
        assert_eq!(read, Ok(expected), "{host:?} {record:?}");
        assert_eq!(calls, two_reads(), "{host:?}");
    }
}

/// The host of a spare the shard record names, on a volume in state fresh, reads `Unnamed` before the flip and `Fresh`
/// once the flip names it owner of that volume at `E = 0`, each with the volume read followed by the shard read.
#[test]
fn a_named_spare_reads_unnamed_until_the_flip_names_it_owner() {
    let spare = VolumeRecord {
        state: VolumeState::Fresh,
        ..with_c_and_b()
    };
    let named = ShardRecord {
        active: VolumeId::new("vol-0c").unwrap(),
        spare: Some((volume_id(), b_host())),
        ..shard_record(4)
    };
    let flipped = ShardRecord {
        owner: b_host(),
        spare: None,
        ..shard_record(0)
    };
    for (record, expected) in [(named, Role::Unnamed), (flipped, Role::Fresh)] {
        let store = store(record, spare.clone());
        let (read, calls) = traced_role(&store, &holder_of(b_host()));
        assert_eq!(read, Ok(expected), "{record:?}");
        assert_eq!(calls, two_reads(), "{record:?}");
    }
}

/// A retired or deleted volume record reads `Retired` for the owner whether the shard record still names it active
/// or names another active volume: the volume state takes precedence over shard ownership. A volume record in state
/// active under a shard record that names another active volume reads `Retired` too (`flip::volume_state`). A volume
/// in state fresh or provisioning that the shard record does not name active, a spare's, reads `Unnamed`, for the
/// former owner and for the host the record names standby alike.
#[test]
fn a_retired_or_unnamed_volume_starts_no_sequence() {
    let elsewhere = ShardRecord {
        active: VolumeId::new("vol-0c").unwrap(),
        standby: Some(c_host()),
        ..shard_record(4)
    };
    for state in [VolumeState::Retired, VolumeState::Deleted] {
        let retired = VolumeRecord {
            state,
            ..lineage(&[(c_host(), c_pair())])
        };
        for record in [shard_record(4), elsewhere] {
            let store = store(record, retired.clone());
            let (read, calls) = traced_role(&store, &holder_of(owner_host()));
            assert_eq!(read, Ok(Role::Retired), "{state:?} {record:?}");
            assert_eq!(calls, two_reads(), "{state:?}");
        }
    }
    let displaced = lineage(&[(c_host(), c_pair())]);
    let spare = |state| VolumeRecord {
        state,
        ..displaced.clone()
    };
    for (volume, host, expected) in [
        (displaced.clone(), owner_host(), Role::Retired),
        (displaced.clone(), c_host(), Role::Retired),
        (spare(VolumeState::Fresh), owner_host(), Role::Unnamed),
        (spare(VolumeState::Fresh), c_host(), Role::Unnamed),
        (
            spare(VolumeState::Provisioning),
            owner_host(),
            Role::Unnamed,
        ),
        (spare(VolumeState::Provisioning), c_host(), Role::Unnamed),
    ] {
        let state = volume.state;
        let store = store(elsewhere, volume);
        let (read, calls) = traced_role(&store, &holder_of(host));
        assert_eq!(read, Ok(expected), "{state:?} {host:?}");
        assert_eq!(calls, two_reads(), "{state:?} {host:?}");
    }
}

/// `role` returns the first read error, after one request for a volume read failure or two for a shard read
/// failure; both paths issue reads alone. A missing volume record returns `Absent` after its one request, and a
/// missing shard record returns `Absent` after both.
#[test]
fn a_failed_read_returns_the_store_error_and_no_role() {
    let store = store(shard_record(4), with_c_and_b());
    store.schedule(Arm::Unavailable);
    let (read, calls) = traced_role(&store, &holder_of(owner_host()));
    assert_eq!(read, Err(StoreError::Unavailable));
    assert_eq!(calls, two_reads()[..1]);

    store.schedule(Arm::Pass);
    store.schedule(Arm::Unavailable);
    let (read, calls) = traced_role(&store, &holder_of(owner_host()));
    assert_eq!(read, Err(StoreError::Unavailable));
    assert_eq!(calls, two_reads());

    let (read, calls) = traced_role(&Shared::new(), &holder_of(owner_host()));
    assert_eq!(read, Err(StoreError::Absent));
    assert_eq!(calls, two_reads()[..1]);

    let unsharded = Shared::new();
    client(&unsharded)
        .create(Key::Volume(volume_id()), with_c_and_b())
        .unwrap();
    let (read, calls) = traced_role(&unsharded, &holder_of(owner_host()));
    assert_eq!(read, Err(StoreError::Absent));
    assert_eq!(calls, two_reads());
}

pub(super) fn inputs() -> Inputs {
    inputs_of(owner_host())
}

/// The fresh path's own pair, [`fresh_tests::own`]: its local record holds the key of the owner's attach, entry 0
/// of the fresh volume (KEY-PER-ATTACH). A restart over the restart fixtures issues as their [`own`] pair.
pub(super) fn fresh_own() -> crate::failover::evidence::Pair {
    fresh_tests::own()
}

/// The shared reservation with this host's pair holding and C's recorded pair registered.
pub(super) fn own_holds() -> Control {
    shared_table(vec![
        registrant(own(), 1, true),
        registrant(c_pair(), 2, false),
    ])
}

/// The host a test recovery runs as: its host, its pair and the local record its restart finds.
#[derive(Clone, Copy)]
pub(crate) struct Identity {
    pub(crate) host: crate::failover::records::Host,
    pub(crate) pair: crate::failover::evidence::Pair,
    pub(crate) local: fn() -> LocalRecord,
}

impl Identity {
    /// The restart fixtures' owner, `A`.
    pub(crate) fn owner() -> Self {
        Self {
            host: owner_host(),
            pair: own(),
            local: crate::failover::assignment_tests::record,
        }
    }

    /// `C`, the warm volume's named standby and recorded second attach.
    pub(crate) fn standby() -> Self {
        Self {
            host: crate::failover::takeover::tests::c_host(),
            pair: crate::failover::takeover::tests::c_pair(),
            local: crate::failover::takeover::tests::c_record,
        }
    }

    /// `B`, a third host that tests attach and enroll on the warm volume beside `A` and `C`.
    pub(crate) fn third() -> Self {
        Self {
            host: crate::failover::takeover::tests::b_host(),
            pair: crate::failover::takeover::tests::b_pair(),
            local: crate::failover::takeover::tests::b_record,
        }
    }
}

/// The same-host restart of `identity` through a fencer over `disk`, with `serving` as its serving clock.
pub(crate) fn restarted_as<'a>(
    identity: Identity,
    store: &Shared,
    device: (
        Reserving,
        &'a BufferArena<TestPlatform>,
        &'a dyn crate::storage::ServingClock,
    ),
    serving: Box<dyn crate::storage::ServingClock>,
) -> Recovery<'a, TestPlatform, Reserving> {
    restarted_over(identity, store.clone(), device, serving)
}

/// [`restarted_as`] whose store client reaches the store through `store`.
pub(crate) fn restarted_over<'a, S: crate::storage::store::Store>(
    identity: Identity,
    store: S,
    (disk, arena, clock): (
        Reserving,
        &'a BufferArena<TestPlatform>,
        &'a dyn crate::storage::ServingClock,
    ),
    serving: Box<dyn crate::storage::ServingClock>,
) -> Recovery<'a, TestPlatform, Reserving> {
    let log = fresh_tests::Log::default();
    let mut local = fresh_tests::holding(&log, (identity.local)());
    let fencer = fencer_of(disk, identity.pair, arena, clock);
    recover(
        &HostGate::qualified(),
        Role::Restart,
        (&inputs_of(identity.host), &[]),
        Sources {
            client: &mut Client::open(store, MemLog::default()).unwrap(),
            local: &mut local,
            plane: &mut fresh_tests::plane(),
            refusals: &mut Refusals::default(),
        },
        fencer,
        serving,
    )
}

/// `recover` of `role` through a fencer over `disk`. A restart finds the restart fixture's local record; the fresh
/// path persists the fresh fixture's, under the key of the owner's attach entry (KEY-PER-ATTACH), and lists the own
/// attachment. A fresh role's `disk` carries [`fresh_tests::own`].
pub(super) fn recovered<'a>(
    role: Role,
    store: &Shared,
    disk: Reserving,
    arena: &'a BufferArena<TestPlatform>,
    clock: &'a dyn crate::storage::ServingClock,
) -> Recovery<'a, TestPlatform, Reserving> {
    recovered_on(role, store, disk, arena, clock, Box::new(ZeroClock))
}

/// [`recovered`] whose tenure reads `serving` as its serving clock.
pub(super) fn recovered_on<'a>(
    role: Role,
    store: &Shared,
    disk: Reserving,
    arena: &'a BufferArena<TestPlatform>,
    clock: &'a dyn crate::storage::ServingClock,
    serving: Box<dyn crate::storage::ServingClock>,
) -> Recovery<'a, TestPlatform, Reserving> {
    let log = fresh_tests::Log::default();
    let pair = role_pair(role, store);
    let mut local = match role {
        Role::Fresh => fresh_tests::records(&log),
        _ if pair == fresh_tests::own() => fresh_tests::holding(&log, fresh_tests::local_record()),
        _ => restart_local(&log),
    };
    let fencer = fencer_of(disk, pair, arena, clock);
    recover(
        &HostGate::qualified(),
        role,
        (&inputs(), &[]),
        Sources {
            client: &mut client(store),
            local: &mut local,
            plane: &mut fresh_tests::plane(),
            refusals: &mut Refusals::default(),
        },
        fencer,
        serving,
    )
}

pub(super) fn tenure(
    recovery: Recovery<'_, TestPlatform, Reserving>,
) -> Tenure<'_, TestPlatform, Reserving> {
    match recovery {
        Recovery::Tenure(tenure) => *tenure,
        Recovery::Ended(ended) => panic!("the sequence ended {:?}", ended.exit),
        Recovery::Waits => panic!("the role waits"),
    }
}

/// What a recovery that acquired no tenure ended with, and its sequence's refusal class as a status reads it: the
/// check and the next step.
pub(super) fn ended_with_class(
    recovery: Recovery<'_, TestPlatform, Reserving>,
) -> (Exit, Release<'_, Reserving>, Option<Class>) {
    match recovery {
        Recovery::Ended(ended) => (ended.exit, ended.device, class_of(ended.refusal)),
        Recovery::Tenure(_) => panic!("a refusal built a tenure"),
        Recovery::Waits => panic!("the role waits"),
    }
}

/// A refusal's class as a status reads it: the check that refused and the next step.
pub(super) type Class = (RecoveryCheck, RecoveryNext);

/// The check and the next step a status reads for `refusal`, `None` for no refusal.
pub(super) fn class_of(refusal: Option<RecoveryRefusal>) -> Option<Class> {
    let mut status = RecoveryStatus::NO_ATTEMPT;
    status.start(RecoveryKind::Restart, 0);
    status.refuse(refusal?);
    let recovery = status.recovery(0);
    Some((
        recovery.check.expect("a refused status names its check"),
        recovery.next.expect("a refused status names its next step"),
    ))
}

/// What a recovery that acquired no tenure ended with.
pub(super) fn ended(
    recovery: Recovery<'_, TestPlatform, Reserving>,
) -> (Exit, Release<'_, Reserving>) {
    match recovery {
        Recovery::Ended(ended) => (ended.exit, ended.device),
        Recovery::Tenure(_) => panic!("a refusal built a tenure"),
        Recovery::Waits => panic!("the role waits"),
    }
}

fn driver(registry: &Control) -> (Reserving, SimControl) {
    super::fencer_tests::host(registry, own(), 1)
}

/// A driver over `registry` for the fresh path's pair.
fn fresh_driver(registry: &Control) -> (Reserving, SimControl) {
    super::fencer_tests::host(registry, fresh_tests::own(), 1)
}

/// The pair `role`'s owner issues as over `store`: a fresh role's is the fresh fixture's, and a restart's is the
/// fresh fixture's when the active volume record records that pair for the owner, as a fresh tenure's enrollment
/// leaves it (KEY-PER-ATTACH), and the restart fixture's otherwise. The read leaves the store's scheduled arms.
pub(crate) fn role_pair(role: Role, store: &Shared) -> crate::failover::evidence::Pair {
    let stored = |key: Key| Some(store.0.borrow().current(&key)?.value.clone());
    let fresh_owner = (stored(Key::Shard(shard())))
        .and_then(|bytes| ShardRecord::decode(&bytes).ok())
        .and_then(|record| stored(Key::Volume(record.active)))
        .and_then(|bytes| VolumeRecord::decode(&bytes).ok())
        .is_some_and(|volume| volume.enrolled(owner_host()) == Some(fresh_tests::own()));
    if role == Role::Fresh || fresh_owner {
        fresh_tests::own()
    } else {
        own()
    }
}

/// The restart fixture's local record, whose pair the restart fixture's volume records hold.
fn restart_local(log: &fresh_tests::Log) -> fresh_tests::Records {
    fresh_tests::holding(log, crate::failover::assignment_tests::record())
}

/// DEVICE-FAILURE-HOLD, NoEpochReuse: a bump whose reply is lost holds at the step-1 target with no device command
/// after Report #1, and returns the driver; whether the bump committed or not, the next incarnation's restart bumps
/// from the record's current `E`. `Exit::Held` retains only the recovery target; the `Ended` preserves the refusal
/// class.
#[test]
fn an_unknown_bump_holds_and_the_next_incarnation_bumps_from_the_current_e() {
    for commit in [false, true] {
        let store = store(shard_record(4), with_c());
        let registry = own_holds();
        let arena = arena_with(16, 9);
        let clock = Ticking::default();
        for arm in [Arm::Pass, Arm::Pass, Arm::Pass, Arm::Timeout { commit }] {
            store.schedule(arm);
        }
        let (exit, device, class) = ended_with_class(recovered(
            Role::Restart,
            &store,
            driver(&registry).0,
            &arena,
            &clock,
        ));
        assert_eq!(
            exit,
            Exit::Held {
                recovery: Target::of(&shard_record(4))
            },
            "commit {commit}"
        );
        assert_eq!(
            class,
            Some((RecoveryCheck::Bump, RecoveryNext::Hold)),
            "commit {commit}: the held exit's refusal class"
        );
        assert_eq!(commands(&registry), ["report"], "commit {commit}");
        assert!(matches!(device, Release::Driver(_)), "commit {commit}");
        drop(device);
        let current = shard_now(&store).attempts;
        assert_eq!(current, 4 + u32::from(commit));

        let next = tenure(recovered(
            Role::Restart,
            &store,
            driver(&registry).0,
            &arena,
            &clock,
        ));
        assert_eq!(next.authority.session().target().attempts, current + 1);
        assert_eq!(shard_now(&store).attempts, current + 1);
        assert!(
            !next.lineage(),
            "a self-preempt restart carries no lineage arm"
        );
    }
}

/// Each refusal class ends in one exit kind with no tenure: an observed unrecorded registrant requests the flip
/// (`Retire`), another owner deposes (`Deposed`), and a suffix-only record and a Report with nobody holding park
/// (`Refused`). A refusal at step 1 leaves the device untouched, one at Report #1 issues nothing after it, and
/// neither bumps `E`. A recorded holder of another host takes the lineage arm
/// (`a_recorded_holder_of_another_host_is_preempted_through_the_fencer`).
#[test]
fn each_restart_refusal_class_ends_in_one_exit_with_no_later_device_command() {
    use crate::failover::records::{Ancestry, Suffix};
    let read = Target::of(&shard_record(4));
    let suffix_only = ShardRecord {
        checkpoint: None,
        ancestry: Ancestry::new(&[Suffix {
            session: session_of(shard_record(4).generation.get() as u32, 4),
            start: 0,
            certified: 3,
            end: 3,
        }])
        .unwrap(),
        ..shard_record(4)
    };
    let deposed = ShardRecord {
        owner: c_host(),
        ..shard_record(4)
    };
    // Each row's `Ended` carries the class of the restart's own refusal: its check, and its next step, which follows
    // its flip request and its hold: a flip requested, no flip and no hold, and a hold.
    use RecoveryCheck as C;
    let (flip, stop, hold) = (RecoveryNext::Flip, RecoveryNext::Stop, RecoveryNext::Hold);
    type Row = (
        &'static str,
        ShardRecord,
        Vec<crate::failover::evidence::Registrant>,
        (Exit, Option<Class>),
        &'static [&'static str],
    );
    let rows: [Row; 4] = [
        (
            "unrecorded registrant",
            shard_record(4),
            vec![registrant(own(), 1, true), registrant(foreign(), 2, false)],
            (Exit::Retire(read), Some((C::NotHolding, flip))),
            &["report"],
        ),
        (
            "deposed",
            deposed,
            vec![registrant(own(), 1, true)],
            (Exit::Deposed, Some((C::Deposed, stop))),
            &[],
        ),
        (
            "suffix only",
            suffix_only,
            vec![registrant(own(), 1, true)],
            (
                Exit::Refused(Refusal::Restart(Check::SuffixOnly)),
                Some((C::SuffixOnly, stop)),
            ),
            &[],
        ),
        (
            "nobody holds",
            shard_record(4),
            vec![registrant(own(), 1, false), registrant(c_pair(), 2, false)],
            // The sequence holds on `Unheld`, and the exit parks it as `Refused`: the class is the sequence's own.
            (
                Exit::Refused(Refusal::Restart(Check::Unheld)),
                Some((C::Unheld, hold)),
            ),
            &["report"],
        ),
    ];
    for (row, record, entries, (expected, class), issued) in rows {
        let store = store(record, with_c());
        let registry = shared_table(entries);
        let arena = arena_with(16, 9);
        let clock = Ticking::default();
        let (exit, device, next) = ended_with_class(recovered(
            Role::Restart,
            &store,
            driver(&registry).0,
            &arena,
            &clock,
        ));
        assert_eq!(exit, expected, "{row}");
        assert_eq!(next, class, "{row}: the refusal's class");
        assert_eq!(commands(&registry), issued, "{row}");
        if issued.is_empty() {
            assert!(matches!(device, Release::Unconnected), "{row}");
        } else {
            assert!(
                matches!(device, Release::Driver(_)),
                "{row}: every command reached its terminal"
            );
        }
        assert_eq!(shard_now(&store), record, "{row}: no bump");
    }
}

/// The lineage arm through the host fencer: Report #1 shows C's recorded pair holding while the record names this
/// host owner, so the restart issues the lineage preempt naming C's key, takes Report #2 with the own pair as the one
/// holder, leaves the record at the bumped `E` and returns a tenure at that `E`. The order of the bump before the
/// preempt is `own_bump_first` of `failover::restart`'s lineage tests, over one trace of the store and the device.
#[test]
fn a_recorded_holder_of_another_host_is_preempted_through_the_fencer() {
    let store = store(shard_record(4), with_c());
    let registry = shared_table(vec![
        registrant(own(), 1, false),
        registrant(c_pair(), 2, true),
    ]);
    let arena = arena_with(16, 9);
    let clock = Ticking::default();
    let tenure = tenure(recovered(
        Role::Restart,
        &store,
        driver(&registry).0,
        &arena,
        &clock,
    ));
    assert_eq!(commands(&registry), ["report", "lineage", "report"]);
    assert!(
        tenure.lineage(),
        "the tenure carries the arm for the recovery report"
    );
    let holders: Vec<_> = (registry.borrow().entries.iter())
        .filter(|entry| entry.holder)
        .map(|entry| entry.pair)
        .collect();
    assert_eq!(holders, [own()]);
    assert!(
        (registry.borrow().entries.iter()).all(|entry| entry.pair != c_pair()),
        "the preempt removed C's registration"
    );
    assert_eq!(shard_now(&store), shard_record(5));
    assert_eq!(
        tenure.authority.session().target(),
        Target::of(&shard_record(5))
    );
}

/// `recover` of `role` through `fencer`, with the host-local records `local`, the peers `peers` and the refusal
/// tally `refusals`, over a client that traces `store`: the recovery and every store request in issue order.
pub(super) fn traced_recovery<'a, C, R>(
    role: Role,
    store: &Shared,
    fencer: Fencer<'a, TestPlatform, Reserving, C>,
    (local, peers, refusals): (&mut R, &[Peer], &mut Refusals),
) -> (Recovery<'a, TestPlatform, Reserving>, Vec<(bool, Key)>)
where
    C: FnOnce() -> Connected<Reserving>,
    R: LocalSource + LocalRecords,
{
    let (mut client, recorder) = traced_client(store);
    let recovery = recover(
        &HostGate::qualified(),
        role,
        (&inputs(), peers),
        Sources {
            client: &mut client,
            local,
            plane: &mut fresh_tests::plane(),
            refusals,
        },
        fencer,
        Box::new(ZeroClock),
    );
    (recovery, super::wait_tests::keyed(&recorder))
}

/// A fresh path whose Acquire a foreign holder refuses requests the empty spare's flip and parks as `Retire` after
/// its bump. Register and Acquire reached their terminals, so the driver comes back, and the fresh path's tally counts
/// one flip request before FB.
#[test]
fn a_fresh_refusal_retires_the_spare_and_returns_the_driver() {
    let store = fresh_tests::store(fresh_tests::shard_record(0), fresh_tests::volume_record());
    let registry = shared_table(vec![registrant(foreign(), 9, true)]);
    let arena = arena_with(16, 9);
    let clock = Ticking::default();
    let log = fresh_tests::Log::default();
    let mut refusals = Refusals::default();
    let fencer = fencer_of(
        fresh_driver(&registry).0,
        fresh_tests::own(),
        &arena,
        &clock,
    );
    let (recovery, _) = traced_recovery(
        Role::Fresh,
        &store,
        fencer,
        (&mut fresh_tests::records(&log), &[], &mut refusals),
    );
    let (exit, device, next) = ended_with_class(recovery);
    let flip = Target {
        attempts: 1,
        ..Target::of(&fresh_tests::shard_record(0))
    };
    assert_eq!(exit, Exit::Retire(flip));
    assert_eq!(
        next,
        Some((RecoveryCheck::Acquire, RecoveryNext::Flip)),
        "the fresh refusal's class"
    );
    assert_eq!(commands(&registry), ["register", "acquire"]);
    assert_eq!(registry.borrow().medium, 0, "no medium command");
    assert!(matches!(device, Release::Driver(_)));
    assert_eq!(
        (refusals.before_fb, refusals.flip_requests),
        (1, 1),
        "the tally counts the Acquire's refusal"
    );
}

/// RecordsBeforeDevice, ROLE-LICENSES-NOTHING: a standby and an unnamed host wait and a retired volume parks with no
/// store request and no connect. A waiting role given a fencer that had connected ends `Fault` and returns the
/// driver for the proven stop.
#[test]
fn the_roles_without_a_sequence_read_nothing_and_never_connect() {
    let store = fresh_tests::store(fresh_tests::shard_record(0), fresh_tests::volume_record());
    let arena = arena_with(16, 9);
    let clock = Ticking::default();
    let log = fresh_tests::Log::default();
    let unused = || -> Connected<Reserving> { panic!("a role without a sequence connected") };
    let roles = [
        Role::Unnamed,
        Role::Standby {
            target: Target::of(&fresh_tests::shard_record(1)),
        },
        Role::Retired,
    ];
    for role in roles {
        let fencer = Fencer::new(&HostGate::qualified(), unused, limits(), &arena, &clock);
        let (recovery, calls) = traced_recovery(
            role,
            &store,
            fencer,
            (&mut restart_local(&log), &[], &mut Refusals::default()),
        );
        assert!(calls.is_empty(), "{role:?}: no store request");
        match recovery {
            Recovery::Waits => assert_ne!(role, Role::Retired),
            Recovery::Ended(ended) => {
                assert_eq!((role, &ended.exit), (Role::Retired, &Exit::Retired));
                assert!(matches!(ended.device, Release::Unconnected));
                assert_eq!(ended.refusal, None, "no sequence refused");
            }
            Recovery::Tenure(_) => panic!("{role:?} built a tenure"),
        }
    }

    // A connected idle fencer returns its driver; a fencer whose Report never completed returns the table that still
    // owns the Report, which `stop` drains.
    for role in [roles[0], roles[1]] {
        for outstanding in [false, true] {
            let registry = shared_table(vec![registrant(own(), 1, true)]);
            let (disk, control) = driver(&registry);
            let mut fencer = fencer_of(disk, own(), &arena, &clock);
            restart_seq::Device::start(&mut fencer).unwrap();
            if outstanding {
                registry.borrow_mut().budget = Some(0);
                restart_seq::Device::ready(&mut fencer).unwrap();
                assert!(restart_seq::Device::report(&mut fencer).is_err());
            }
            let issued = commands(&registry);
            let (recovery, calls) = traced_recovery(
                role,
                &store,
                fencer,
                (&mut restart_local(&log), &[], &mut Refusals::default()),
            );
            let (exit, device, next) = ended_with_class(recovery);
            assert!(matches!(exit, Exit::Fault(_)), "{role:?}: {exit:?}");
            assert_eq!(next, None, "{role:?}: no sequence refused");
            assert!(calls.is_empty(), "{role:?}: no store request");
            assert_eq!(commands(&registry), issued, "{role:?}: no device command");
            match (outstanding, device) {
                (false, Release::Driver(_)) => {}
                (true, Release::Outstanding(table)) => drop(stop(table, &control)),
                _ => panic!("{role:?}, outstanding {outstanding}: another release"),
            }
        }
    }
}

/// RecordsBeforeDevice: the fresh path connects only after its acknowledged bump. A bump whose reply is lost, whether
/// it committed or not, parks before any connect or device command; an acknowledged bump has committed `E = 1`
/// before the connect runs.
#[test]
fn the_fresh_path_connects_only_after_its_acknowledged_bump() {
    let arena = arena_with(16, 9);
    let clock = Ticking::default();
    for commit in [false, true] {
        let store = fresh_tests::store(fresh_tests::shard_record(0), fresh_tests::volume_record());
        for arm in [Arm::Pass, Arm::Pass, Arm::Pass, Arm::Timeout { commit }] {
            store.schedule(arm);
        }
        let log = fresh_tests::Log::default();
        let unused = || -> Connected<Reserving> { panic!("a lost bump reply connected") };
        let fencer = Fencer::new(&HostGate::qualified(), unused, limits(), &arena, &clock);
        let (recovery, _) = traced_recovery(
            Role::Fresh,
            &store,
            fencer,
            (
                &mut fresh_tests::records(&log),
                &[],
                &mut Refusals::default(),
            ),
        );
        let (exit, device) = ended(recovery);
        assert!(matches!(exit, Exit::Retire(_)), "commit {commit}: {exit:?}");
        assert!(matches!(device, Release::Unconnected), "commit {commit}");
        assert_eq!(
            fresh_tests::shard_now(&store).attempts,
            u32::from(commit),
            "commit {commit}"
        );
    }

    let store = fresh_tests::store(fresh_tests::shard_record(0), fresh_tests::volume_record());
    let registry = shared_table(Vec::new());
    let (disk, control) = fresh_driver(&registry);
    let driving = super::fencer_tests::Driving::new(&control, []);
    let bumped = &store;
    let connect = move || {
        assert_eq!(
            fresh_tests::shard_now(bumped).attempts,
            1,
            "the bump committed before the connect"
        );
        connected(disk, fresh_tests::own())()
    };
    let log = fresh_tests::Log::default();
    let fencer = Fencer::new(&HostGate::qualified(), connect, limits(), &arena, &driving);
    let (recovery, _) = traced_recovery(
        Role::Fresh,
        &store,
        fencer,
        (
            &mut fresh_tests::records(&log),
            &[],
            &mut Refusals::default(),
        ),
    );
    assert_eq!(tenure(recovery).authority.session().target().attempts, 1);
}

/// A serving clock that unwinds at its first read after a reservation command was submitted. When `bomb` is
/// `Some(dropped)`, the unwind's payload is a [`Bomb`] that records its drop in `dropped`.
pub(super) struct UnwindsAfterSubmit {
    registry: Control,
    now: std::cell::Cell<u64>,
    bomb: Option<Dropped>,
}

impl UnwindsAfterSubmit {
    pub(super) fn over(registry: &Control, bomb: Option<Dropped>) -> Self {
        Self {
            registry: registry.clone(),
            now: std::cell::Cell::new(0),
            bomb,
        }
    }
}

impl crate::storage::ServingClock for UnwindsAfterSubmit {
    fn now_us(&self) -> Option<u64> {
        let submitted = !self.registry.borrow().log.is_empty();
        if let (true, Some(dropped)) = (submitted, &self.bomb) {
            std::panic::panic_any(Bomb(dropped.clone()));
        }
        assert!(!submitted, "a serving clock that unwinds");
        let now = self.now.get();
        self.now.set(now + 1);
        Some(now)
    }
}

/// A sequence that unwinds after submitting its first Report ends `Rerun(Unwound)` before the bump and returns the
/// fencer's table, which still owns the Report, for the proven stop.
#[test]
fn a_sequence_that_unwinds_returns_the_table_that_owns_its_report() {
    unwound_restart(None);
}

/// When the unwind's payload panics again as it drops, `recover` returns `Rerun(Unwound)` with the fencer's table.
#[test]
fn a_sequence_whose_unwind_payload_panics_on_drop_returns_the_table() {
    let dropped = Dropped::default();
    unwound_restart(Some(dropped.clone()));
    assert_eq!(*dropped.lock().unwrap(), ["bomb"]);
}

/// After the restart submits its first Report, the clock unwinds, with a [`Bomb`] payload when `bomb` is `Some`.
/// `recover` returns `Rerun(Unwound)` before the bump. The fencer's table still owns the first Report.
fn unwound_restart(bomb: Option<Dropped>) {
    let store = store(shard_record(4), with_c());
    let registry = own_holds();
    registry.borrow_mut().budget = Some(0);
    let (disk, control) = driver(&registry);
    let arena = arena_with(16, 9);
    let clock = UnwindsAfterSubmit::over(&registry, bomb);
    let log = fresh_tests::Log::default();
    let fencer = fencer_of(disk, own(), &arena, &clock);
    let (recovery, _) = traced_recovery(
        Role::Restart,
        &store,
        fencer,
        (&mut restart_local(&log), &[], &mut Refusals::default()),
    );
    let (exit, device, next) = ended_with_class(recovery);
    assert_eq!(exit, Exit::Rerun(Rerun::Unwound));
    assert_eq!(next, None, "an unwound sequence made no refusal");
    assert_eq!(commands(&registry), ["report"]);
    let Release::Outstanding(table) = device else {
        panic!("the pending Report keeps its table");
    };
    drop(stop(table, &control));
    assert_eq!(shard_now(&store).attempts, 4);
}

/// Each seeded coverage page ends both sequences through `recover` in one exit: entries past the interval bound, a
/// record that does not decode and a fence that is no activated session park as `Refused`, and a later tenure's
/// session deposes. The fresh path at `E = 0` refuses after its bump with the retention released, and the restart at
/// `E = 1`, over the same host-local records, refuses after its bump; each leaves the page as it was, issues no
/// medium command after the refusal, and returns its driver.
#[test]
fn each_coverage_page_refusal_ends_both_sequences_in_its_one_exit() {
    use crate::failover::records::CoveragePage;
    use crate::storage::CacheVersion;
    use crate::storage::page_coverage::{ENTRY_LEN, Interval, encode_entries};
    use crate::storage::store::{Outcome, Store, Write};
    enum Seed {
        Entries(Vec<u8>),
        Record(Vec<u8>),
        Fence(u64),
    }
    let one = |version| Interval::new(CacheVersion(version), CacheVersion(version)).unwrap();
    let past_bound = encode_entries(&[1, 3, 5, 7, 9].map(|version| ([0; 32], one(version))));
    assert!(past_bound.len() / ENTRY_LEN > 4);
    let generation = fresh_tests::shard_record(0).generation.get() as u32;
    let later = session_of(generation, 200);
    // `Session::activate` refuses generation `u32::MAX`.
    let exhausted = session_of(u32::MAX, 2);
    let rows = [
        (
            Seed::Entries(past_bound),
            Some(Withdraw::Malformed { page: 0 }),
        ),
        (
            Seed::Record(vec![0; 3]),
            Some(Withdraw::Store(StoreError::Codec(CodecError::Length))),
        ),
        (
            Seed::Fence(u64::MAX),
            Some(Withdraw::NewerFence {
                page: 0,
                fence: u64::MAX,
            }),
        ),
        (
            Seed::Fence(exhausted),
            Some(Withdraw::NewerFence {
                page: 0,
                fence: exhausted,
            }),
        ),
        (Seed::Fence(later), None),
    ];
    for (seed, parked) in rows {
        let store = fresh_tests::store(fresh_tests::shard_record(0), fresh_tests::volume_record());
        let key = Key::Page(shard(), 0);
        let stored = || store.0.borrow().current(&key).cloned().unwrap();
        let mut seeder = client(&store);
        let page = seeder.read::<CoveragePage>(key).unwrap();
        match seed {
            Seed::Record(bytes) => {
                let write = Write::Exact {
                    expect: stored().version,
                    value: bytes,
                };
                let written = Store::write(&mut store.clone(), &key, &write);
                assert!(matches!(written, Outcome::Committed(_)));
            }
            Seed::Entries(entries) => {
                let seeded = CoveragePage {
                    entries,
                    ..page.value().clone()
                };
                seeder.replace(&page, seeded).unwrap();
            }
            Seed::Fence(fence) => {
                let seeded = CoveragePage {
                    fence,
                    ..page.value().clone()
                };
                seeder.replace(&page, seeded).unwrap();
            }
        }
        let seeded = stored();
        let registry = shared_table(Vec::new());
        let (disk, control) = fresh_driver(&registry);
        let driving = super::fencer_tests::Driving::new(&control, []);
        let log = fresh_tests::Log::default();
        let mut local = fresh_tests::records(&log);
        let fresh_arena = arena_with(16, 9);
        let fencer = fencer_of(disk, fresh_tests::own(), &fresh_arena, &driving);
        let (recovery, _) = traced_recovery(
            Role::Fresh,
            &store,
            fencer,
            (&mut local, &[], &mut Refusals::default()),
        );
        let (exit, device) = ended(recovery);
        let expected = parked.map_or(Exit::Deposed, |withdraw| {
            Exit::Refused(Refusal::Fresh(fresh::Check::Fence(withdraw)))
        });
        assert_eq!(exit, expected, "fresh {parked:?}");
        assert_eq!(exit.parks(), parked.is_some());
        assert!(matches!(device, Release::Driver(_)));
        assert!(!local.refused, "{parked:?}: the retention released");
        assert_eq!(fresh_tests::shard_now(&store).attempts, 1);

        let medium = registry.borrow().medium;
        let issued = commands(&registry).len();
        let (disk, _control) = fresh_driver(&registry);
        let restart_arena = arena_with(16, 9);
        let clock = Ticking::default();
        let fencer = fencer_of(disk, fresh_tests::own(), &restart_arena, &clock);
        let (recovery, _) = traced_recovery(
            Role::Restart,
            &store,
            fencer,
            (&mut local, &[], &mut Refusals::default()),
        );
        let (exit, device) = ended(recovery);
        let expected = parked.map_or(Exit::Deposed, |withdraw| {
            Exit::Refused(Refusal::Restart(Check::Coverage(FenceRefused::Fence(
                withdraw,
            ))))
        });
        assert_eq!(exit, expected, "restart {parked:?}");
        assert!(matches!(device, Release::Driver(_)));
        assert_eq!(
            commands(&registry)[issued..],
            ["report", "preempt", "report"]
        );
        assert_eq!(
            registry.borrow().medium,
            medium,
            "{parked:?}: no medium command"
        );
        assert_eq!(fresh_tests::shard_now(&store).attempts, 2);
        let kept = stored();
        assert_eq!(
            (kept.version, kept.value),
            (seeded.version, seeded.value),
            "{parked:?}: the page is unchanged"
        );
    }
}

/// A host-local source that cannot read its record.
struct Unreadable;

impl LocalSource for Unreadable {
    fn local(&self) -> Result<LocalRecord, Local> {
        Err(Local::Unreadable)
    }
}

impl LocalRecords for Unreadable {
    fn persist(
        &mut self,
        _: &Holder,
        _: u32,
        _: ReservationKey,
    ) -> Result<LocalRecord, AdmissionError> {
        unreachable!("the restart persists no local record")
    }

    fn retain_refusal(&mut self, _: &LocalRecord) -> Result<(), AdmissionError> {
        unreachable!("the restart retains no refusal")
    }

    fn release_refusal(&mut self, _: &LocalRecord) -> Result<(), AdmissionError> {
        unreachable!("the restart releases no refusal")
    }
}

/// NoEpochReuse: a restart that cannot read its host-local record reruns before its first device command and its
/// bump, and the next incarnation, reading the record, bumps from the same `E`.
#[test]
fn an_unreadable_local_record_reruns_with_no_device_command_and_no_bump() {
    let store = store(shard_record(4), with_c());
    let registry = own_holds();
    let arena = arena_with(16, 9);
    let clock = Ticking::default();
    let fencer = fencer_of(driver(&registry).0, own(), &arena, &clock);
    let (recovery, _) = traced_recovery(
        Role::Restart,
        &store,
        fencer,
        (&mut Unreadable, &[], &mut Refusals::default()),
    );
    let (exit, device) = ended(recovery);
    assert_eq!(exit, Exit::Rerun(Rerun::Records));
    assert!(!exit.parks());
    assert!(matches!(device, Release::Unconnected));
    assert!(commands(&registry).is_empty());
    assert_eq!(shard_now(&store).attempts, 4);

    let next = tenure(recovered(
        Role::Restart,
        &store,
        driver(&registry).0,
        &arena,
        &clock,
    ));
    assert_eq!(next.authority.session().target().attempts, 5);
    assert!(
        !next.lineage(),
        "a self-preempt restart carries no lineage arm"
    );
}

/// `recover` binds the restart to the peers it is given: B's live attach, awaiting its pair enrollment, is admitted
/// when B is a peer, and retires the volume as an attachment outside the owner rule when it is not.
#[test]
fn a_restart_admits_the_attach_of_each_peer_it_is_given() {
    let pending = VolumeRecord {
        pairs: crate::failover::restart::tests::volume_record().pairs,
        ..lineage(&[(b_host(), b_pair())])
    };
    let holder = *inputs().holder();
    let bound = peers(&holder, &pending, |host| Some(instance_of(host))).unwrap();
    assert!(!bound.is_empty());
    let arena = arena_with(16, 9);
    let clock = Ticking::default();
    let log = fresh_tests::Log::default();

    let reached = store(shard_record(4), pending.clone());
    let registry = shared_table(vec![registrant(own(), 1, true)]);
    let fencer = fencer_of(driver(&registry).0, own(), &arena, &clock);
    let (recovery, _) = traced_recovery(
        Role::Restart,
        &reached,
        fencer,
        (&mut restart_local(&log), &bound, &mut Refusals::default()),
    );
    assert_eq!(tenure(recovery).authority.session().target().attempts, 5);

    let refusing = store(shard_record(4), pending);
    let registry = shared_table(vec![registrant(own(), 1, true)]);
    let fencer = fencer_of(driver(&registry).0, own(), &arena, &clock);
    let (recovery, _) = traced_recovery(
        Role::Restart,
        &refusing,
        fencer,
        (&mut restart_local(&log), &[], &mut Refusals::default()),
    );
    let (exit, device) = ended(recovery);
    assert_eq!(exit, Exit::Retire(Target::of(&shard_record(4))));
    assert!(matches!(device, Release::Unconnected));
    assert!(commands(&registry).is_empty());
}

/// Each refusal class maps to the one exit the host's table names, independently of the sequence's own split: a
/// later tenure's page fence deposes, a failed read and an unreadable host-local record rerun, a page whose record
/// or entries do not decode and a `C_page` below the encoded empty page park, an unresolved page and a failed page
/// read hold or rerun, and a fresh refusal whose retention release failed takes the exit of the refusal it wraps.
#[test]
fn each_refusal_maps_to_the_one_exit_its_class_names() {
    let at = Target::of(&shard_record(4));
    let malformed = Withdraw::Malformed { page: 0 };
    let undecodable = Withdraw::Store(StoreError::Codec(CodecError::Length));
    let generation = shard_record(4).generation.get() as u32;
    let newer = Withdraw::NewerFence {
        page: 0,
        fence: session_of(generation, 200),
    };
    let impossible = Withdraw::NewerFence {
        page: 0,
        fence: u64::MAX,
    };
    // `Session::activate` refuses generation `u32::MAX`.
    let exhausted = Withdraw::NewerFence {
        page: 0,
        fence: session_of(u32::MAX, 2),
    };
    let absent = Withdraw::Store(StoreError::Absent);
    let unavailable = Withdraw::Store(StoreError::Unavailable);
    let page_cap = FencingRefusal::PageCap;
    let held = Exit::Held { recovery: at };
    let records = Exit::Rerun(Rerun::Records);
    let parked = |check: &Check| Exit::Refused(Refusal::Restart(check.clone()));
    let restart_rows = [
        (
            Check::Records(StoreError::Unavailable),
            None,
            None,
            records.clone(),
        ),
        (Check::Fresh, None, None, records.clone()),
        (Check::Local(Local::Unreadable), None, None, records.clone()),
        (Check::Deposed, None, None, Exit::Deposed),
        (
            Check::Coverage(FenceRefused::Fence(newer)),
            None,
            Some(at),
            Exit::Deposed,
        ),
        (
            Check::Local(Local::Retained),
            Some(at),
            None,
            Exit::Retire(at),
        ),
        (
            Check::Bump(StoreError::Unknown),
            None,
            Some(at),
            held.clone(),
        ),
        (
            Check::Coverage(FenceRefused::Unresolved { page: 0 }),
            None,
            Some(at),
            held.clone(),
        ),
        (
            Check::Coverage(FenceRefused::Fence(unavailable)),
            None,
            Some(at),
            held.clone(),
        ),
    ];
    for (check, flip, recovery, expected) in restart_rows {
        let refused = restart_seq::Refused {
            check: check.clone(),
            flip,
            recovery,
        };
        assert_eq!(restart_exit(&refused), expected, "{check:?}");
    }
    let restart_parks = [
        Check::Unheld,
        Check::Local(Local::Binding),
        // ENDED-GRANTS-NOTHING: a volume record that ends the own attach refuses with no flip and no recovery, and
        // the host requests nothing.
        Check::Local(Local::Ended),
        Check::Coverage(FenceRefused::Fence(malformed)),
        Check::Coverage(FenceRefused::Fence(undecodable)),
        Check::Coverage(FenceRefused::Fence(impossible)),
        Check::Coverage(FenceRefused::Fence(exhausted)),
        Check::Coverage(FenceRefused::Fence(absent)),
        Check::Coverage(FenceRefused::Fencing(page_cap)),
    ];
    for check in restart_parks {
        let recovery = (!matches!(check, Check::Local(_))).then_some(at);
        let refused = restart_seq::Refused {
            check: check.clone(),
            flip: None,
            recovery,
        };
        let exit = restart_exit(&refused);
        assert_eq!(exit, parked(&check), "{check:?}");
        assert!(exit.parks(), "{check:?}");
    }

    let volume = inputs().holder().volume;
    let wrapped = |original: fresh::Check| fresh::Check::Retention {
        original: Box::new(original),
        error: AdmissionError::Instance,
    };
    let unactivated = Exit::Rerun(Rerun::Unactivated);
    let fresh_rows = [
        (
            fresh::Check::Records(StoreError::Unavailable),
            records.clone(),
        ),
        (fresh::Check::Restart, records.clone()),
        (fresh::Check::Deposed, Exit::Deposed),
        (fresh::Check::Superseded, Exit::Deposed),
        (fresh::Check::Fence(newer), Exit::Deposed),
        (wrapped(fresh::Check::Superseded), Exit::Deposed),
        (fresh::Check::Unobserved, unactivated.clone()),
        (
            fresh::Check::UnresolvedPage { page: 0 },
            unactivated.clone(),
        ),
        (fresh::Check::Fence(unavailable), unactivated.clone()),
        (wrapped(fresh::Check::Unobserved), unactivated),
    ];
    for (check, expected) in fresh_rows {
        let refused = fresh::Refused {
            check: check.clone(),
            flip: None,
        };
        assert_eq!(fresh_exit(&refused, volume), expected, "{check:?}");
    }
    // A retirement request comes first, before any wrapper is followed, including a retention that failed after an
    // unknown bump.
    let own = Target { attempts: 1, ..at };
    let retiring = [
        fresh::Check::Register(crate::failover::restart::Failed(None)),
        wrapped(fresh::Check::Bump(StoreError::Unknown)),
        wrapped(fresh::Check::Fence(malformed)),
    ];
    for check in retiring {
        let refused = fresh::Refused {
            check: check.clone(),
            flip: Some(own),
        };
        let target = refused
            .retirement(volume)
            .expect("a retirement request")
            .target;
        assert_eq!(
            fresh_exit(&refused, volume),
            Exit::Retire(target),
            "{check:?}"
        );
    }
    let fresh_parks = [
        fresh::Check::Fence(malformed),
        fresh::Check::Fence(undecodable),
        fresh::Check::Fence(impossible),
        fresh::Check::Fence(exhausted),
        fresh::Check::Fence(absent),
        wrapped(wrapped(fresh::Check::Fence(malformed))),
        fresh::Check::Fencing(page_cap),
        wrapped(fresh::Check::Fence(malformed)),
        wrapped(fresh::Check::Fencing(page_cap)),
    ];
    for check in fresh_parks {
        let refused = fresh::Refused {
            check: check.clone(),
            flip: None,
        };
        let exit = fresh_exit(&refused, volume);
        assert_eq!(
            exit,
            Exit::Refused(Refusal::Fresh(check.clone())),
            "{check:?}"
        );
        assert!(exit.parks(), "{check:?}");
    }
}

/// Every refusal of the lineage arm after its bump ends the incarnation `Held` at the bumped target, a failed shard
/// reread and a failed volume reread at Report #2 included: outside the arm the same record-read failures rerun as
/// `Rerun(Records)` and an observed Report #2 refusal parks as `Retire`.
#[test]
fn a_failed_step_of_the_lineage_arm_ends_held_at_the_bumped_target() {
    use crate::failover::evidence::NotSole;
    use crate::failover::restart::{Failed, Lineage};
    let bumped = Target::of(&shard_record(6));
    let held = |check: Check| restart_seq::Refused {
        check,
        flip: None,
        recovery: Some(bumped),
    };
    for step in [
        Lineage::Register(Failed(None)),
        Lineage::Superseded,
        Lineage::Reread(StoreError::Unavailable),
        Lineage::Preempt(Failed(None)),
        Lineage::Confirm(Box::new(Check::SecondReport(Failed(None)))),
        Lineage::Confirm(Box::new(Check::NotSole(NotSole::ForeignRegistrant))),
        Lineage::Confirm(Box::new(Check::Records(StoreError::Unavailable))),
    ] {
        let exit = restart_exit(&held(Check::Lineage(step.clone())));
        assert_eq!(exit, Exit::Held { recovery: bumped }, "{step:?}");
    }
    assert_eq!(
        restart_exit(&held(Check::Records(StoreError::Unavailable))),
        Exit::Rerun(Rerun::Records),
        "outside the arm"
    );
    let flip = restart_seq::Refused {
        check: Check::NotSole(NotSole::ForeignRegistrant),
        flip: Some(bumped),
        recovery: None,
    };
    assert_eq!(restart_exit(&flip), Exit::Retire(bumped), "outside the arm");
}

/// A report's next step is the refused sequence's own rule, and the host's exit is a separate classification of the
/// same refusal. Where the host parks or deposes a restart's no-holder or coverage hold, the report still reads
/// `Hold`, and where it parks a fresh coverage refusal after the bump, the report still reads `Restart`. A fresh
/// refusal that shows a later tenure, a superseding record or a page that tenure's activated session fenced, reads
/// `Stop` beside the host's `Deposed`, and both read that fence through one predicate: a fence above the own
/// session that no tenure can activate reads `Restart` where the host parks.
#[test]
fn a_reports_next_step_keeps_its_sequences_rule_where_the_host_parks_or_deposes() {
    let next = |kind, refusal| {
        let mut status = RecoveryStatus::NO_ATTEMPT;
        status.start(kind, 0);
        status.refuse(refusal);
        status.recovery(0).next
    };
    let at = Target::of(&shard_record(4));
    let malformed = Withdraw::Malformed { page: 0 };
    let newer = Withdraw::NewerFence {
        page: 0,
        fence: session_of(shard_record(4).generation.get() as u32, 200),
    };
    let restart_rows = [
        (Check::Unheld, true),
        (Check::Coverage(FenceRefused::Fence(malformed)), true),
        (Check::Coverage(FenceRefused::Fence(newer)), false),
    ];
    for (check, parks) in restart_rows {
        let refused = restart_seq::Refused {
            check: check.clone(),
            flip: None,
            recovery: Some(at),
        };
        let exit = restart_exit(&refused);
        assert_eq!(
            next(RecoveryKind::Restart, RecoveryRefusal::from(&refused)),
            Some(RecoveryNext::Hold),
            "{check:?}"
        );
        assert_eq!(exit.parks(), parks, "{check:?}");
        assert!(parks || exit == Exit::Deposed, "{check:?}");
    }
    let volume = inputs().holder().volume;
    let impossible = Withdraw::NewerFence {
        page: 0,
        fence: u64::MAX,
    };
    let exhausted = Withdraw::NewerFence {
        page: 0,
        fence: session_of(u32::MAX, 2),
    };
    let fresh_rows = [
        (fresh::Check::Fence(malformed), RecoveryNext::Restart, true),
        (fresh::Check::Fence(impossible), RecoveryNext::Restart, true),
        (fresh::Check::Fence(exhausted), RecoveryNext::Restart, true),
        (fresh::Check::Fence(newer), RecoveryNext::Stop, false),
        (fresh::Check::Superseded, RecoveryNext::Stop, false),
    ];
    for (check, step, parks) in fresh_rows {
        let refused = fresh::Refused {
            check: check.clone(),
            flip: None,
        };
        let exit = fresh_exit(&refused, volume);
        assert_eq!(
            next(RecoveryKind::Fresh, RecoveryRefusal::from(&refused)),
            Some(step),
            "{check:?}"
        );
        assert_eq!(exit.parks(), parks, "{check:?}");
        assert!(parks || exit == Exit::Deposed, "{check:?}");
    }
}
