//! The planned transfer over the simulated store: the record it commits, its refusals before any request, its unknown
//! outcomes, and the target's restart bump over the committed record.

use super::store::sim::{Arm, MemLog, Shared};
use super::store::{Client, Key, Outgoing, Read, Refusal, StoreError, Transferred};
use super::store_tests::{
    OWNER, SPARE, UNKNOWN, attempt, client, committed, other_namespace, published_standby, record,
    shard, stored,
};
use crate::failover::reconcile::StandbyGate;
use crate::failover::records::{ATTEMPTS_MAX, Host, ShardRecord};
use crate::failover::retire::{Stale, Target};
use crate::storage::Session;

/// The owner's own bump of the record in `store`: the owner's client, the session the bump activated and the read it
/// committed.
fn serving(store: &Shared) -> (Client<Shared, MemLog>, Session, Read<ShardRecord>) {
    let mut owner = client(store);
    let bumped = attempt(&mut owner, OWNER).unwrap();
    let read = bumped.committed().clone();
    (owner, Session::activate(bumped).unwrap(), read)
}

fn standby() -> Host {
    Host::new(SPARE).unwrap()
}

fn transfer(
    owner: &mut Client<Shared, MemLog>,
    (read, session): (&Read<ShardRecord>, &Session),
    target: Host,
) -> Result<Transferred, StoreError> {
    owner.transfer(
        &StandbyGate::qualified(),
        read,
        &Outgoing::of(session),
        target,
    )
}

/// `prior` with `target` as owner at `E + 1` and no standby.
fn handed(prior: &ShardRecord, target: Host) -> ShardRecord {
    ShardRecord {
        owner: target,
        attempts: prior.attempts + 1,
        standby: None,
        ..*prior
    }
}

/// A store holding `record` at `attempts` with a client's create.
fn holding(record: ShardRecord, attempts: u32) -> Shared {
    let store = Shared::new();
    client(&store)
        .create_shard(ShardRecord { attempts, ..record })
        .unwrap();
    store
}

/// Asserts that the `Arm::Unavailable` scheduled before a refusal is still pending: the refusal issued no request.
#[track_caller]
fn unused(store: &Shared, case: &str) {
    assert_eq!(
        crate::storage::store::Store::read(&mut store.clone(), &Key::Shard(shard())).map(drop),
        Err(crate::storage::store::Unavailable),
        "{case}: the refusal issued no request"
    );
}

/// TRANSFER-NAMES-STANDBY: the transfer commits the read record with its standby as owner, `E + 1` and no standby,
/// and keeps the shard, `g`, the active volume, the named checkpoint, its cut, the ancestry, the spare, `B`, `C_page`
/// and the namespace. A second transfer over the same read refuses on its condition, and the outgoing owner's bump
/// over its stale read refuses. The target's own bump over the committed record commits at `E + 2` and activates
/// the target's session at that tenure.
#[test]
fn a_transfer_names_the_standby_owner_at_the_next_attempt_and_clears_the_standby() {
    let store = published_standby();
    let (mut owner, session, read) = serving(&store);
    let prior = *read.value();
    assert_eq!(prior.standby, Some(standby()));
    let transferred = transfer(&mut owner, (&read, &session), standby()).unwrap();
    let expected = handed(&prior, standby());
    assert_eq!(*transferred.committed().value(), expected);
    assert_eq!(stored(&store).1, expected);
    assert_eq!(
        transfer(&mut client(&store), (&read, &session), standby()).map(drop),
        Err(StoreError::Refused(Refusal::Condition))
    );
    assert_eq!(
        owner.bump(&read).map(drop),
        Err(StoreError::Refused(Refusal::Condition))
    );
    assert_eq!(stored(&store).1, expected);
    let bumped = attempt(&mut client(&store), SPARE).unwrap();
    let activated = Session::activate(bumped).unwrap();
    assert_eq!(
        activated.target(),
        Target {
            owner: standby(),
            attempts: prior.attempts + 2,
            ..Target::of(&prior)
        }
    );
}

/// An unknown transfer outcome adopts nothing and leaves the store at the prior record or the transferred one, as
/// the arm committed.
#[test]
fn an_unknown_transfer_adopts_nothing_in_either_arm() {
    for arm in UNKNOWN {
        let store = published_standby();
        let (mut owner, session, read) = serving(&store);
        let prior = *read.value();
        let before = owner.watermark().clone();
        store.schedule(arm);
        assert_eq!(
            transfer(&mut owner, (&read, &session), standby()).map(drop),
            Err(StoreError::Unknown),
            "{arm:?}"
        );
        assert_eq!(owner.watermark(), &before, "{arm:?}");
        let next = handed(&prior, standby());
        assert_eq!(
            stored(&store).1,
            if committed(arm) { next } else { prior },
            "{arm:?}"
        );
    }
}

/// Each refusal of the transfer's rule returns before any request, with no commit: a session of an earlier tenure of
/// the record, a target other than the named standby, the owner as target, a record that names no standby, a record
/// that names no checkpoint, and a record whose `E + 2` passes `ATTEMPTS_MAX`. A record whose `E + 2` equals
/// `ATTEMPTS_MAX` transfers, and its target's bump commits at `ATTEMPTS_MAX`.
#[test]
fn a_transfer_refuses_each_rule_before_any_request() {
    let key = Key::Shard(shard());
    let stale = Err(StoreError::Stale(Stale::Target));
    let store = published_standby();
    let (_, earlier, _) = serving(&store);
    let (mut owner, current, read) = serving(&store);
    let commits = store.0.borrow().commit_count(&key);
    for (session, target, case) in [
        (&earlier, standby(), "an earlier tenure's session"),
        (&current, Host::new(SPARE + 1).unwrap(), "an unnamed host"),
        (&current, Host::new(OWNER).unwrap(), "the owner"),
    ] {
        store.schedule(Arm::Unavailable);
        assert_eq!(
            transfer(&mut owner, (&read, session), target).map(drop),
            stale,
            "{case}"
        );
        unused(&store, case);
    }
    assert_eq!(store.0.borrow().commit_count(&key), commits);

    let checkpoint = stored(&published_standby()).1.checkpoint;
    let named = |checkpoint| ShardRecord {
        standby: Some(standby()),
        checkpoint,
        ..record()
    };
    for (record, attempts, expected, case) in [
        (record(), 1, stale, "no standby"),
        (named(None), 1, stale, "no checkpoint"),
        (
            named(checkpoint),
            ATTEMPTS_MAX - 2,
            Err(StoreError::AttemptsExhausted),
            "no room for the target's bump",
        ),
    ] {
        let store = holding(record, attempts);
        let (mut owner, session, read) = serving(&store);
        let commits = store.0.borrow().commit_count(&key);
        store.schedule(Arm::Unavailable);
        assert_eq!(
            transfer(&mut owner, (&read, &session), standby()).map(drop),
            expected,
            "{case}"
        );
        unused(&store, case);
        assert_eq!(store.0.borrow().commit_count(&key), commits, "{case}");
    }
    let store = holding(named(checkpoint), ATTEMPTS_MAX - 3);
    let (mut owner, session, read) = serving(&store);
    assert_eq!(read.value().attempts + 2, ATTEMPTS_MAX);
    let transferred = transfer(&mut owner, (&read, &session), standby()).unwrap();
    assert_eq!(transferred.committed().value().attempts, ATTEMPTS_MAX - 1);
    let bumped = attempt(&mut client(&store), SPARE).unwrap();
    assert_eq!(bumped.committed().value().attempts, ATTEMPTS_MAX);
}

/// A transfer over a read of another store instance refuses `Namespace`, which withdraws the client, and the next
/// transfer refuses `Withdrawn`; neither commits.
#[test]
fn a_transfer_of_another_store_instance_withdraws_the_client() {
    let key = Key::Shard(shard());
    let store = published_standby();
    let (mut owner, session, read) = serving(&store);
    let commits = store.0.borrow().commit_count(&key);
    store.0.borrow_mut().namespace = other_namespace();
    assert_eq!(
        transfer(&mut owner, (&read, &session), standby()).map(drop),
        Err(StoreError::Namespace)
    );
    assert_eq!(
        transfer(&mut owner, (&read, &session), standby()).map(drop),
        Err(StoreError::Withdrawn)
    );
    assert_eq!(store.0.borrow().commit_count(&key), commits);
}

/// The transfer's shard guard refuses before any request an outgoing session of another shard with the same
/// `(g, owner, E)`, and its owner guard refuses a record that names its own owner as standby with that owner as
/// target.
#[test]
fn a_transfer_refuses_another_shard_s_session_and_the_owner_as_target_before_any_request() {
    let key = Key::Shard(shard());
    let stale = Err(StoreError::Stale(Stale::Target));
    let other = crate::net::ownership::Shard::new(shard().get() + 1).unwrap();
    let store = published_standby();
    client(&store)
        .create_shard(ShardRecord {
            shard: other,
            ..stored(&store).1
        })
        .unwrap();
    let mut elsewhere = client(&store);
    let read = elsewhere.read::<ShardRecord>(Key::Shard(other)).unwrap();
    let foreign = Session::activate(elsewhere.bump(&read).unwrap()).unwrap();
    let (mut owner, session, read) = serving(&store);
    assert_eq!(
        (foreign.target(), foreign.shard()),
        (session.target(), other),
        "the sessions differ in their shard alone"
    );
    let commits = store.0.borrow().commit_count(&key);
    store.schedule(Arm::Unavailable);
    assert_eq!(
        transfer(&mut owner, (&read, &foreign), standby()).map(drop),
        stale,
        "another shard's session"
    );
    unused(&store, "another shard's session");
    assert_eq!(store.0.borrow().commit_count(&key), commits);

    // The record codec refuses a record that names its owner as standby, so the owner guard is checked on the
    // decoded value the rule receives.
    let owner_host = Host::new(OWNER).unwrap();
    let named = ShardRecord {
        standby: Some(owner_host),
        ..*read.value()
    };
    assert_eq!(
        crate::failover::flip::transferred(&named, (shard(), session.target()), owner_host),
        Err(crate::failover::flip::TenureRefusal::Target),
        "the owner named as its own standby"
    );
}

/// A transfer write the store parks, its reply unknown, leaves one owner whichever write applies first. Released
/// before the outgoing owner's next bump, it commits the standby as owner, and that bump over the earlier read fails
/// its condition. Released after that bump commits, its exact-version condition fails, and the record keeps the
/// outgoing owner's next tenure.
#[test]
fn a_parked_transfer_and_the_owner_s_next_bump_leave_one_owner_in_either_order() {
    use crate::storage::store::Outcome;
    for released_first in [true, false] {
        let store = published_standby();
        let (mut owner, session, read) = serving(&store);
        let prior = *read.value();
        store.schedule(Arm::Hold);
        assert_eq!(
            transfer(&mut owner, (&read, &session), standby()).map(drop),
            Err(StoreError::Unknown),
            "{released_first}"
        );
        assert_eq!(stored(&store).1, prior, "{released_first}: parked");
        let mut restarted = client(&store);
        if released_first {
            assert!(matches!(store.release()[..], [Outcome::Committed(_)]));
            assert_eq!(
                restarted.bump(&read).map(drop),
                Err(StoreError::Refused(Refusal::Condition))
            );
            assert_eq!(stored(&store).1, handed(&prior, standby()));
        } else {
            restarted.bump(&read).unwrap();
            assert!(matches!(
                store.release()[..],
                [Outcome::NotCommitted(Refusal::Condition)]
            ));
            let record = stored(&store).1;
            assert_eq!(
                (record.owner, record.attempts),
                (prior.owner, prior.attempts + 1)
            );
        }
    }
}
