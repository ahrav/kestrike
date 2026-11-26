use std::sync::atomic::{AtomicBool, Ordering};

use super::recover::{Role, role};
use super::recover_tests::two_reads;
use super::serve::wait;
use super::{Exit, HostGate, Rerun};
use crate::failover::records::{ShardRecord, VolumeId, VolumeRecord, VolumeState};
use crate::failover::restart::tests::{host as owner_host, shard_record, store};
use crate::failover::takeover::tests::{b_host, c_host, holder_of, rewrite, with_c_and_b};
use crate::storage::store::sim::{Arm, MemLog, Recorder, Request, Shared};
use crate::storage::store::{Client, Key};
use crate::storage::store_tests::{client as store_client, shard};

/// The requests `recorder` recorded since the last call, each as `(write, key)`.
pub(super) fn keyed(recorder: &Recorder) -> Vec<(bool, Key)> {
    (recorder.take().into_iter())
        .filter_map(|request| match request {
            Request::Read(key) => Some((false, key)),
            Request::Write(key, _) => Some((true, key)),
            Request::Device(_) => None,
        })
        .collect()
}

/// What a wait did: its exit, the view periods it took, and every store request it issued.
struct Waited {
    exit: Exit,
    periods: u32,
    calls: Vec<(bool, Key)>,
}

/// `wait` in `waiting` for `host` over `store`; `script` runs at each view period with the period's number and the
/// stop flag.
fn waited(
    store: &Shared,
    host: crate::failover::records::Host,
    waiting: Role,
    script: impl FnMut(u32, &AtomicBool),
) -> Waited {
    waited_over(store, MemLog::default(), host, waiting, script)
}

/// [`waited`] whose client records its watermark in `log`.
fn waited_over(
    store: &Shared,
    log: MemLog,
    host: crate::failover::records::Host,
    waiting: Role,
    mut script: impl FnMut(u32, &AtomicBool),
) -> Waited {
    let recorder = Recorder::new(store);
    let mut client = Client::open(recorder.clone(), log).unwrap();
    let stop = AtomicBool::new(false);
    let mut periods = 0;
    let exit = wait(
        &HostGate::qualified(),
        waiting,
        (shard(), &holder_of(host)),
        &mut client,
        &stop,
        || {
            periods += 1;
            assert!(periods < 100, "the wait never ended");
            script(periods, &stop);
        },
    );
    let calls = keyed(&recorder);
    Waited {
        exit,
        periods,
        calls,
    }
}

/// HOST-LOSS-KEEPS-VOLUME: a process parked after `Exit::Retire` keeps the role the records name it, `Restart`,
/// while the record still names it owner. Each view period issues one role read, two store reads, and nothing else.
/// The park ends with `Rerun(RoleChanged)` when a record names the host standby, so the next incarnation runs the
/// wait that holds the work of that role. A flip that names another active volume, while this volume's record
/// still shows it active, reads `Retired` and keeps the park until its stop request.
#[test]
fn a_parked_process_rereads_its_role_once_per_view_period_and_leaves_on_a_standby_or_unnamed_role()
{
    let designated = store(shard_record(4), with_c_and_b());
    let before = designated.0.borrow().commit_count(&Key::Shard(shard()));
    let left = waited(&designated, owner_host(), Role::Restart, |period, _| {
        if period == 3 {
            rewrite(&designated, |record| ShardRecord {
                owner: c_host(),
                attempts: record.attempts + 1,
                standby: Some(owner_host()),
                ..record
            });
        }
    });
    assert_eq!(left.exit, Exit::Rerun(Rerun::RoleChanged));
    assert_eq!(left.periods, 3);
    assert_eq!(left.calls, two_reads().repeat(3));
    assert_eq!(
        designated.0.borrow().commit_count(&Key::Shard(shard())),
        before + 1,
        "the one write is the script's"
    );

    let flipped = store(shard_record(4), with_c_and_b());
    let elsewhere = VolumeId::new("vol-0c").unwrap();
    let holder = holder_of(owner_host());
    let read_role = || role(&mut store_client(&flipped), shard(), &holder).unwrap();
    let kept = waited(&flipped, owner_host(), Role::Restart, |period, stop| {
        match period {
            2 => assert_eq!(read_role(), Role::Restart),
            3 => rewrite(&flipped, |record| ShardRecord {
                active: elsewhere,
                ..record
            }),
            4 => assert_eq!(read_role(), Role::Retired, "the flip alone"),
            _ => {}
        }
        stop.store(period == 6, Ordering::Release);
    });
    assert_eq!(kept.exit, Exit::Stopped, "the flip keeps the park");
    assert_eq!(kept.calls, two_reads().repeat(5));
}

/// A park entered in a standby or unnamed role ends `Rerun(RoleChanged)` at its first role read, with the record
/// unchanged: those roles wait in `stand_by`.
#[test]
fn a_park_entered_in_a_standby_or_unnamed_role_hands_off_at_its_first_read() {
    let named = ShardRecord {
        standby: Some(c_host()),
        ..shard_record(4)
    };
    let standby = Role::Standby {
        target: crate::failover::retire::Target::of(&named),
    };
    for (host, waiting) in [(b_host(), Role::Unnamed), (c_host(), standby)] {
        let store = store(named, with_c_and_b());
        let waited = waited(&store, host, waiting, |_, _| {});
        assert_eq!(waited.exit, Exit::Rerun(Rerun::RoleChanged));
        assert_eq!(waited.calls, two_reads());
    }
}

/// A retired volume keeps a park, entered as `Retired` or as `Restart`, with one role read a period until its stop
/// request.
#[test]
fn a_park_on_a_retired_volume_ends_only_on_its_stop_request() {
    let retired = VolumeRecord {
        state: VolumeState::Retired,
        ..with_c_and_b()
    };
    for waiting in [Role::Retired, Role::Restart] {
        let store = store(shard_record(4), retired.clone());
        let read = role(&mut store_client(&store), shard(), &holder_of(owner_host()));
        assert_eq!(read, Ok(Role::Retired), "the retirement record");
        let waited = waited(&store, owner_host(), waiting, |period, stop| {
            stop.store(period == 4, Ordering::Release);
        });
        assert_eq!(waited.exit, Exit::Stopped);
        assert_eq!(waited.calls, two_reads().repeat(3));
    }
}

/// A role read that fails keeps the park and issues no retry inside its period, and a stop request ends the park
/// `Stopped` before that period's read.
#[test]
fn a_failed_role_read_keeps_the_wait_and_a_stop_request_ends_it() {
    let store = store(shard_record(4), with_c_and_b());
    let waited = waited(
        &store,
        owner_host(),
        Role::Restart,
        |period, stop| match period {
            2 => store.schedule(Arm::Unavailable),
            5 => stop.store(true, Ordering::Release),
            _ => {}
        },
    );
    assert_eq!(waited.exit, Exit::Stopped);
    let mut expected = two_reads().repeat(4);
    // Period 2's volume read failed, so its role read issued no shard read.
    expected.remove(3);
    assert_eq!(waited.calls, expected);
}

/// When the log fails to record the raised watermark, the role read withdraws the client and the park ends
/// `Rerun(Records)` at that read. Only the script commits to the shard record during the park.
#[test]
fn a_role_read_that_withdraws_the_client_ends_the_park() {
    let store = store(shard_record(4), with_c_and_b());
    let before = store.0.borrow().commit_count(&Key::Shard(shard()));
    let log = MemLog::default();
    let fail = log.fail.clone();
    let waited = waited_over(&store, log, owner_host(), Role::Restart, |period, _| {
        if period == 2 {
            // A write that keeps the record's value raises its version, which the role read must log.
            rewrite(&store, |record| record);
            fail.set(true);
        }
    });
    assert_eq!(waited.exit, Exit::Rerun(Rerun::Records));
    assert_eq!(waited.periods, 2);
    assert_eq!(waited.calls, two_reads().repeat(2));
    assert_eq!(
        store.0.borrow().commit_count(&Key::Shard(shard())),
        before + 1,
        "the one write is the script's"
    );
}
