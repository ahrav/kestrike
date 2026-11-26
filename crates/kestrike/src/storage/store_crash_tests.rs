//! Crash cases at the shard-record writes. A crash drops the client and keeps the store and the host's durable
//! watermark log; the next process opens a client on that log and derives `g` and `E` from the shard record alone.
//! Every case checks the reference conditions: no two attempts adopt one `(g, n)` (`NoEpochReuse`), at most one flip
//! commits per generation (`OneActiveVolumePerShard`), and no client adopts a value from a write whose outcome was
//! unknown.

use super::store::sim::{Arm, MemLog, Shared};
use super::store::{Client, Key, Outcome, Refusal, Regression, StoreError};
use super::store_tests::{
    OWNER, SPARE, UNKNOWN, attempt, client, committed, record, reuses, seeded, shard, stored,
    withdrawn,
};
use crate::failover::flip::FlipRefusal;
use crate::failover::records::ShardRecord;

#[path = "marklog_replay_tests.rs"]
mod marklog_replay;

/// A new process of the host: a client that starts at the watermark in the host's durable `log`.
fn process(store: &Shared, log: &MemLog) -> Client<Shared, MemLog> {
    Client::open(store.clone(), log.clone()).unwrap()
}

/// The source generation of every committed flip, in commit order, so a second flip of one generation appears
/// twice.
fn flips(store: &Shared) -> Vec<u64> {
    store.0.borrow().flips.clone()
}

/// The reconciler's flip is acknowledged and the reconciler crashes. Its next process finds the flip committed and
/// no spare to flip to; the spare host's attempt takes `E = 0` of the next generation, and the old owner's attempt
/// refuses on the record.
#[test]
fn flip_acknowledged_then_crash() {
    let store = seeded();
    let log = MemLog::default();
    let mut reconciler = process(&store, &log);
    let read = reconciler.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    let flipped = reconciler.flip(&read).unwrap();
    drop(reconciler);

    let mut reconciler = process(&store, &log);
    assert_eq!(
        log.held().shard_mark(shard()).map(|mark| mark.1),
        Some((flipped.generation().get(), 0))
    );
    let again = reconciler.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    assert_eq!(
        reconciler.flip(&again),
        Err(StoreError::Flip(FlipRefusal::NoSpare))
    );
    let spare = attempt(&mut client(&store), SPARE).unwrap();
    assert_eq!(
        (spare.generation(), spare.attempt()),
        (flipped.generation(), 0)
    );
    assert_eq!(
        attempt(&mut client(&store), OWNER).map(|_| ()),
        Err(StoreError::Refused(Refusal::Condition))
    );
    assert_eq!(flips(&store), vec![3]);
}

/// The reconciler's flip times out or fails, in the arm that commits and the one that does not, and the reconciler
/// crashes. Its next process re-reads: a committed flip leaves no spare to flip to, an uncommitted one is flipped
/// again and acknowledged. Either way exactly one flip of the generation commits.
#[test]
fn flip_unacknowledged_then_crash() {
    for arm in UNKNOWN {
        let store = seeded();
        let log = MemLog::default();
        let mut reconciler = process(&store, &log);
        let read = reconciler.read::<ShardRecord>(Key::Shard(shard())).unwrap();
        store.schedule(arm);
        assert_eq!(reconciler.flip(&read), Err(StoreError::Unknown), "{arm:?}");
        assert_eq!(
            log.held().shard_mark(shard()).map(|mark| mark.1.0),
            Some(3),
            "{arm:?}: nothing adopted"
        );
        drop(reconciler);

        let mut reconciler = process(&store, &log);
        let again = reconciler.read::<ShardRecord>(Key::Shard(shard())).unwrap();
        let committed = committed(arm);
        assert_eq!(again.value().spare.is_none(), committed, "{arm:?}");
        let expected = match committed {
            true => Err(StoreError::Flip(FlipRefusal::NoSpare)),
            false => Ok(4),
        };
        assert_eq!(
            reconciler.flip(&again).map(|flip| flip.generation().get()),
            expected,
            "{arm:?}"
        );
        assert_eq!(flips(&store), vec![3], "{arm:?}");
        let (_, now) = stored(&store);
        assert_eq!((now.generation.get(), now.owner.get()), (4, SPARE));
    }
}

/// Every shard-record write a tenure or the reconciler makes, with every unknown-outcome arm, followed by a crash
/// of the writer: the shard's creation, an `E` bump, a currency proof and a flip. The crashed writer's watermark
/// keeps its read. The next process calls `create_shard` again after a creation, derives `g` and `E` from the shard
/// record and adopts only from its own acknowledged bump, so each attempt adopts a distinct `(g, n)` and at most one
/// flip commits.
#[test]
fn shard_write_unknown_then_crash() {
    type Write = fn(&mut Client<Shared, MemLog>) -> Result<(), StoreError>;
    let writes: [(&str, Write); 4] = [
        ("create", |client| client.create_shard(record()).map(|_| ())),
        ("bump", |client| attempt(client, OWNER).map(|_| ())),
        ("proof", |client| {
            let read = client.read::<ShardRecord>(Key::Shard(shard()))?;
            client.replace(&read, *read.value()).map(|_| ())
        }),
        ("flip", |client| {
            let read = client.read::<ShardRecord>(Key::Shard(shard()))?;
            client.flip(&read).map(|_| ())
        }),
    ];
    for (name, write) in writes {
        for arm in UNKNOWN {
            let (create, committed) = (name == "create", committed(arm));
            let store = match create {
                true => Shared::new(),
                false => seeded(),
            };
            let log = MemLog::default();
            let mut adopted = Vec::new();
            let mut writer = process(&store, &log);
            if !create && name != "bump" {
                let witness = attempt(&mut writer, OWNER).unwrap();
                adopted.push((witness.generation(), witness.attempt()));
            }
            let before = store
                .0
                .borrow()
                .current(&Key::Shard(shard()))
                .map(|item| item.version);
            match create {
                true => (0..record().pages.get()).for_each(|_| store.schedule(Arm::Pass)),
                false => store.schedule(Arm::Pass),
            }
            store.schedule(arm);
            assert_eq!(
                write(&mut writer),
                Err(StoreError::Unknown),
                "{name} {arm:?}"
            );
            assert_eq!(
                log.held().shard_mark(shard()).map(|mark| mark.0),
                before,
                "{name} {arm:?}: the watermark holds the read, nothing adopted"
            );
            drop(writer);

            let mut next = process(&store, &log);
            if create {
                let expected = match committed {
                    true => Err(StoreError::Refused(Refusal::Condition)),
                    false => Ok(()),
                };
                let created = next.create_shard(record()).map(|_| ());
                assert_eq!(created, expected, "{name} {arm:?}");
            }
            let read = next.read::<ShardRecord>(Key::Shard(shard())).unwrap();
            if name == "proof" {
                let advanced = read.version().get() - before.unwrap().get();
                assert_eq!(advanced, u64::from(committed), "{arm:?}");
            }
            let host = read.value().owner.get();
            let witness = next.bump(&read).unwrap();
            assert_eq!(
                witness.attempt(),
                read.value().attempts,
                "{name} {arm:?}: n is the read record's E"
            );
            adopted.push((witness.generation(), witness.attempt()));
            let again = attempt(&mut process(&store, &log), host).unwrap();
            adopted.push((again.generation(), again.attempt()));
            assert!(!reuses(&adopted), "{name} {arm:?}: {adopted:?}");
            let flipped = usize::from(name == "flip" && committed);
            assert_eq!(flips(&store).len(), flipped, "{name} {arm:?}");
        }
    }
}

/// A creation whose second page create times out uncommitted, followed by a crash, completes when the next process
/// calls `create_shard` again: the first page's create refuses on its condition, and the second page and the shard
/// record commit.
#[test]
fn create_shard_repeats_after_partial_create() {
    let store = Shared::new();
    let log = MemLog::default();
    store.schedule(Arm::Pass);
    store.schedule(Arm::Timeout { commit: false });
    assert_eq!(
        process(&store, &log).create_shard(record()).map(|_| ()),
        Err(StoreError::Unknown)
    );
    let created = process(&store, &log).create_shard(record()).unwrap();
    assert_eq!(created.value(), &record());
    for page in 0..record().pages.get() {
        assert!(
            store
                .0
                .borrow()
                .current(&Key::Page(shard(), page))
                .is_some()
        );
    }
}

/// The owner's bump is parked at the store with its outcome unknown, and the owner crashes. Its next process
/// re-reads, finds `E` unchanged and bumps it by its own acknowledged write; the parked bump, released after that
/// commit, fails its condition. `E` ends one past the successor's attempt, and the two processes adopt one
/// `(g, n)` between them.
#[test]
fn parked_bump_across_restart_fails_its_condition() {
    let store = seeded();
    let log = MemLog::default();
    let mut owner = process(&store, &log);
    let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    store.schedule(Arm::Hold);
    assert_eq!(owner.bump(&read), Err(StoreError::Unknown));
    drop(owner);

    let successor = attempt(&mut process(&store, &log), OWNER).unwrap();
    assert_eq!(successor.attempt(), 0);
    assert_eq!(store.release(), [Outcome::NotCommitted(Refusal::Condition)]);
    assert_eq!(stored(&store).1.attempts, successor.attempt() + 1);
    assert_eq!(flips(&store), Vec::<u64>::new());
}

/// The store acknowledges a bump under the lost-write arm and keeps the older record, and the owner crashes. The
/// owner's next process opens at the watermark its log recorded, so its read of the older record returns the
/// regression alarm and withdraws the client.
#[test]
fn restart_enforces_the_recorded_watermark() {
    let key = Key::Shard(shard());
    let store = seeded();
    let log = MemLog::default();
    let mut owner = process(&store, &log);
    let read = owner.read::<ShardRecord>(key).unwrap();
    store.schedule(Arm::LostWrite);
    owner.bump(&read).unwrap();
    drop(owner);

    let mut restarted = process(&store, &log);
    assert_eq!(
        restarted.read::<ShardRecord>(key).map(|_| ()),
        Err(StoreError::Regression(Regression::Value(key)))
    );
    assert_eq!(
        restarted.read::<ShardRecord>(key).map(|_| ()),
        Err(StoreError::Withdrawn)
    );
}

/// A second flip of one generation that the store applies over its failed condition appears twice in the flip
/// ledger, and its writer's exact-version commit at the wrong version raises the regression alarm.
#[test]
fn flip_ledger_counts_a_double_won_flip() {
    let store = seeded();
    let (mut a, mut b) = (client(&store), client(&store));
    let key = Key::Shard(shard());
    let (read_a, read_b) = (
        a.read::<ShardRecord>(key).unwrap(),
        b.read::<ShardRecord>(key).unwrap(),
    );
    a.flip(&read_a).unwrap();
    store.schedule(Arm::DoubleWin);
    assert_eq!(
        b.flip(&read_b).map(|_| ()),
        Err(StoreError::Regression(Regression::Value(key)))
    );
    withdrawn(&mut b);
    assert_eq!(flips(&store), vec![3, 3]);
}
