//! `Reconciler::flip_for` over the simulated store. A request for the active volume flips the shard to its
//! spare only over a shard read the request admits: its exact `(g, owner, E)`, or `E + 1` at the same
//! `(g, owner)` for a recovering request. A read the request does not admit ends in `Stale`: with no write when
//! it is the first read, and with no shard write when it is a reread after a lost version condition.
//!
//! The reconciler runs over `Probe`, a `Store` that counts the reconciler's requests and lets a rival client
//! write on the same table right before one of the reconciler's shard writes, which then loses its version
//! condition and sends `flip_for` to a fresh read.
//!
//! Each test computes what the call returned and what the table holds into plain values, lets the store and
//! the clients go, and asserts last.

use std::cell::Cell;
use std::rc::Rc;

use super::flip::flipped;
use super::fresh::tests::{shard_record, store, volume_record};
use super::reconcile::{Flip, OperatorRelease, ReconcileError, Reconciler, StandbyGate};
use super::records::{Host, Namespace, ShardRecord, VolumeId, VolumeRecord};
use super::retire::{Retirement, Role, Stale, Target, Trigger};
use crate::net::ownership::ShardGeneration;
use crate::storage::store::sim::{MemLog, Shared};
use crate::storage::store::{Client, Item, Key, Outcome, Store, Unavailable, Write};
use crate::storage::store_tests::{SPARE, client, shard};

/// The version-condition losses after which `flip_for` returns `Retry`.
const ROUNDS: usize = 4;

/// The volume the seeded shard record names active.
fn first_volume() -> VolumeId {
    shard_record(0).active
}

/// The volume the seeded shard record names spare, held by the host `SPARE`.
fn spare_volume() -> VolumeId {
    shard_record(0).spare.unwrap().0
}

fn spare_host() -> Host {
    Host::new(SPARE).unwrap()
}

/// A host the seeded records name in no role.
fn standby() -> Host {
    Host::new(21).unwrap()
}

/// A version and a value of each record a flip reads or writes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Records {
    shard: (u64, ShardRecord),
    /// The record of [`first_volume`].
    first: (u64, VolumeRecord),
    /// The record of [`spare_volume`].
    spare: (u64, VolumeRecord),
}

fn records(store: &Shared) -> Records {
    let mut reader = client(store);
    let shard = reader.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    let first = reader
        .read::<VolumeRecord>(Key::Volume(first_volume()))
        .unwrap();
    let spare = reader
        .read::<VolumeRecord>(Key::Volume(spare_volume()))
        .unwrap();
    Records {
        shard: (shard.version().get(), *shard.value()),
        first: (first.version().get(), first.into_value()),
        spare: (spare.version().get(), spare.into_value()),
    }
}

/// The requests the reconciler's client made of the store.
#[derive(Default)]
struct Counts {
    reads: Cell<usize>,
    shard_reads: Cell<usize>,
    writes: Cell<usize>,
    shard_writes: Cell<usize>,
}

/// A write a rival client makes on the table right before the reconciler's shard write of the given round,
/// counted from zero.
type Rival = Box<dyn FnMut(&Shared, usize)>;

struct Probe {
    inner: Shared,
    counts: Rc<Counts>,
    rival: Option<Rival>,
}

impl Store for Probe {
    fn namespace(&self) -> Namespace {
        self.inner.namespace()
    }

    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        self.counts.reads.set(self.counts.reads.get() + 1);
        if matches!(key, Key::Shard(_)) {
            self.counts
                .shard_reads
                .set(self.counts.shard_reads.get() + 1);
        }
        self.inner.read(key)
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        self.counts.writes.set(self.counts.writes.get() + 1);
        if matches!(key, Key::Shard(_)) {
            let round = self.counts.shard_writes.get();
            self.counts.shard_writes.set(round + 1);
            if let Some(rival) = self.rival.as_mut() {
                rival(&self.inner, round);
            }
        }
        self.inner.write(key, write)
    }
}

/// How one `flip_for` call ended.
#[derive(Debug, PartialEq, Eq)]
enum Ending {
    /// The call's own acknowledged flip, to this generation.
    Flipped(u64),
    Past,
    Stale,
    Conflict,
    Retry,
    Other(String),
}

fn ending(result: Result<Flip, ReconcileError>) -> Ending {
    match result {
        Ok(Flip::Flipped(flipped)) => Ending::Flipped(flipped.generation().get()),
        Ok(Flip::Past) => Ending::Past,
        Err(ReconcileError::Stale) => Ending::Stale,
        Err(ReconcileError::Conflict) => Ending::Conflict,
        Err(ReconcileError::Retry) => Ending::Retry,
        Err(other) => Ending::Other(format!("{other:?}")),
    }
}

/// One `flip_for` call and the table around it.
#[derive(Debug)]
struct Seen {
    /// What the request's admission says of the shard record the table held before the call.
    admission: Result<(), Stale>,
    before: Records,
    ending: Ending,
    after: Records,
    reads: usize,
    shard_reads: usize,
    writes: usize,
    shard_writes: usize,
}

/// Seeds a table with `seed`, an active record of [`first_volume`] and an unused record of [`spare_volume`],
/// lets `prepare` write on it, then serves `request` with one `flip_for` call of a reconciler whose shard
/// writes `rival` precedes.
fn serve(
    seed: ShardRecord,
    prepare: impl FnOnce(&Shared),
    request: &Retirement,
    rival: Option<Rival>,
) -> Seen {
    let store = store(seed, volume_record());
    prepare(&store);
    let before = records(&store);
    let counts = Rc::new(Counts::default());
    let probe = Probe {
        inner: store.clone(),
        counts: Rc::clone(&counts),
        rival,
    };
    let mut reconciler = Reconciler::new(Client::open(probe, MemLog::default()).unwrap());
    let ending = ending(reconciler.flip_for(&OperatorRelease::diagnosed(), shard(), request));
    Seen {
        admission: request.admit(&before.shard.1).map(drop),
        ending,
        after: records(&store),
        before,
        reads: counts.reads.get(),
        shard_reads: counts.shard_reads.get(),
        writes: counts.writes.get(),
        shard_writes: counts.shard_writes.get(),
    }
}

fn ordinary(target: Target) -> Retirement {
    Retirement::new(first_volume(), Role::Active, target, Trigger::Activation).unwrap()
}

fn recovering(target: Target) -> Retirement {
    Retirement::recovering(first_volume(), target, Trigger::Activation).unwrap()
}

fn shard_now(store: &Shared) -> ShardRecord {
    *client(store)
        .read::<ShardRecord>(Key::Shard(shard()))
        .unwrap()
        .value()
}

/// The owner's bump of `E` on the record the table holds.
fn bump(store: &Shared) {
    let mut owner = client(store);
    let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    owner.bump(&read).unwrap();
}

/// Names `host` the standby of the tenure the table holds; the write changes no `(g, owner, E)` and no spare.
fn designate(store: &Shared, host: Host) {
    let mut writer = client(store);
    let read = writer.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    let target = Target::of(read.value());
    writer.designate(&read, target, host).unwrap();
}

/// The designated standby's takeover of the tenure the table holds: `(g, standby, E + 1)`.
fn take_over(store: &Shared) {
    let mut successor = client(store);
    let read = successor.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    let target = Target::of(read.value());
    successor.take_over(&read, target, standby()).unwrap();
}

/// Another reconciler's flip of the tenure the table holds.
fn flip(store: &Shared) {
    let target = Target::of(&shard_now(store));
    Reconciler::new(client(store))
        .flip(&StandbyGate::qualified(), shard(), target)
        .unwrap();
}

/// Replaces the spare the shard record names.
fn name_spare(store: &Shared, spare: Option<(VolumeId, Host)>) {
    let mut writer = client(store);
    let read = writer.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    let next = ShardRecord {
        spare,
        ..*read.value()
    };
    writer.replace(&read, next).unwrap();
}

/// A rival that runs `write` before the reconciler's shard write of each of the first `rounds` rounds.
fn rival(rounds: usize, write: impl Fn(&Shared, usize) + 'static) -> Option<Rival> {
    Some(Box::new(move |store, round| {
        if round < rounds {
            write(store, round);
        }
    }))
}

/// The shard record after a flip of `record`.
fn after_flip(record: &ShardRecord) -> ShardRecord {
    flipped(record).unwrap()
}

/// A request flips a record that holds its exact `(g, owner, E)`, and a recovering request also the record
/// its bump left at `E + 1`. The flip conditions on the one shard read: the shard record becomes the flip of
/// that read at the next version, the spare's unchanged volume record is rewritten once before it, and the
/// displaced volume's record, already active, is left as it is.
#[test]
fn a_request_the_read_record_admits_flips_the_shard_to_its_spare() {
    let exact = Target::of(&shard_record(1));
    let cases: [(&str, Seen); 4] = [
        (
            "an ordinary request at E = 0",
            serve(
                shard_record(0),
                |_| {},
                &ordinary(Target::of(&shard_record(0))),
                None,
            ),
        ),
        (
            "an ordinary request at E = 1",
            serve(shard_record(1), |_| {}, &ordinary(exact), None),
        ),
        (
            "a recovering request at its exact E",
            serve(shard_record(1), |_| {}, &recovering(exact), None),
        ),
        (
            "a recovering request after its bump committed",
            serve(shard_record(1), bump, &recovering(exact), None),
        ),
    ];
    let mut wrong = Vec::new();
    for (name, seen) in &cases {
        let read = seen.before.shard.1;
        let flipped = Records {
            shard: (seen.before.shard.0 + 1, after_flip(&read)),
            first: seen.before.first.clone(),
            spare: (seen.before.spare.0 + 1, seen.before.spare.1.clone()),
        };
        let holds = seen.admission == Ok(())
            && seen.ending == Ending::Flipped(read.generation.get() + 1)
            && seen.after == flipped
            && (seen.after.shard.1.active, seen.after.shard.1.owner)
                == (spare_volume(), spare_host())
            && (seen.shard_reads, seen.shard_writes) == (1, 1);
        if !holds {
            wrong.push(format!("{name}: {seen:?}"));
        }
    }
    let bumped = cases[3].1.before.shard.1.attempts;
    drop(cases);
    assert_eq!(
        bumped, 2,
        "the bump left the record at E + 1 of the request"
    );
    assert!(
        wrong.is_empty(),
        "flip_for did not flip a record its request admits: {wrong:#?}"
    );
}

/// A request computed before an `E` bump, a takeover or a second bump, or one that names another volume active
/// or another generation, is refused on the first read: `Stale`, one shard read, no write, and the shard
/// record and both volume records at the versions and values they held.
#[test]
fn a_request_the_record_no_longer_admits_is_stale_with_no_write() {
    let exact = Target::of(&shard_record(1));
    let designated_then_taken = |store: &Shared| {
        designate(store, standby());
        take_over(store);
    };
    let ahead = Target {
        generation: ShardGeneration::new(exact.generation.get() + 1).unwrap(),
        ..exact
    };
    let other_volume =
        Retirement::new(spare_volume(), Role::Active, exact, Trigger::Activation).unwrap();
    let cases: [(&str, Result<(), Stale>, Seen); 7] = [
        (
            "an ordinary request after the owner's bump from E = 0",
            Err(Stale::Target),
            serve(
                shard_record(0),
                bump,
                &ordinary(Target::of(&shard_record(0))),
                None,
            ),
        ),
        (
            "an ordinary request after the owner's bump from E = 1",
            Err(Stale::Target),
            serve(shard_record(1), bump, &ordinary(exact), None),
        ),
        (
            "a recovering request after two bumps",
            Err(Stale::Target),
            serve(
                shard_record(1),
                |store| {
                    bump(store);
                    bump(store);
                },
                &recovering(exact),
                None,
            ),
        ),
        (
            "an ordinary request after a takeover",
            Err(Stale::Target),
            serve(
                shard_record(1),
                designated_then_taken,
                &ordinary(exact),
                None,
            ),
        ),
        (
            "a recovering request after a takeover, which leaves E + 1 under another owner",
            Err(Stale::Target),
            serve(
                shard_record(1),
                designated_then_taken,
                &recovering(exact),
                None,
            ),
        ),
        (
            "a request that names another volume active at the record's (g, owner, E)",
            Err(Stale::Volume),
            serve(shard_record(1), |_| {}, &other_volume, None),
        ),
        (
            "a request for a generation above the record's",
            Err(Stale::Target),
            serve(shard_record(1), |_| {}, &ordinary(ahead), None),
        ),
    ];
    let mut unformed = Vec::new();
    let mut wrong = Vec::new();
    for (name, refusal, seen) in &cases {
        let record = seen.before.shard.1;
        if seen.admission != *refusal
            || record.active != first_volume()
            || record.spare != Some((spare_volume(), spare_host()))
        {
            unformed.push(format!("{name}: {seen:?}"));
        }
        let holds = seen.ending == Ending::Stale
            && seen.after == seen.before
            && (seen.shard_reads, seen.writes) == (1, 0);
        if !holds {
            wrong.push(format!("{name}: {seen:?}"));
        }
    }
    drop(cases);
    assert!(
        unformed.is_empty(),
        "the table does not hold the record the case names: {unformed:#?}"
    );
    assert!(
        wrong.is_empty(),
        "flip_for served a request its read record does not admit: {wrong:#?}"
    );
}

/// Once another reconciler flipped the request's tenure, the record is past the request's generation: `Past`
/// on the first read, for an ordinary and a recovering request, with no write.
#[test]
fn a_record_past_the_request_generation_is_past_with_no_write() {
    let exact = Target::of(&shard_record(1));
    let cases = [
        serve(shard_record(1), flip, &ordinary(exact), None),
        serve(shard_record(1), flip, &recovering(exact), None),
    ];
    let mut wrong = Vec::new();
    for seen in &cases {
        let record = seen.before.shard.1;
        let holds = record.generation.get() == exact.generation.get() + 1
            && record.active == spare_volume()
            && seen.ending == Ending::Past
            && seen.after == seen.before
            && (seen.shard_reads, seen.writes) == (1, 0);
        if !holds {
            wrong.push(format!("{seen:?}"));
        }
    }
    drop(cases);
    assert!(
        wrong.is_empty(),
        "flip_for did not end in Past with no write on a record past its request: {wrong:#?}"
    );
}

/// A rival write lands between the reconciler's shard read and its flip write, so the flip loses its version
/// condition and the next round judges the request on a fresh read. An `E` bump or a takeover there leaves a
/// record the ordinary request no longer admits: `Stale` with no shard write of the reconciler's, the record
/// holding the rival's tenure with its active volume and spare, after the earlier round rewrote the spare's
/// volume record. A recovering request admits one bump and flips the bumped record, and is `Stale` after a
/// second bump or a takeover.
#[test]
fn a_tenure_change_between_a_read_and_its_flip_write_is_judged_on_the_fresh_read() {
    let exact = Target::of(&shard_record(1));
    let designated = |store: &Shared| designate(store, standby());
    let bumps = |rounds: usize| rival(rounds, |store, _| bump(store));
    let takeover = || rival(1, |store, _| take_over(store));
    // The name, the rounds lost, the owner the table ends with, and whether the last read is admitted.
    let cases: [(&str, usize, Host, bool, Seen); 5] = [
        (
            "an ordinary request and one bump",
            1,
            exact.owner,
            false,
            serve(shard_record(1), |_| {}, &ordinary(exact), bumps(1)),
        ),
        (
            "a recovering request and one bump",
            1,
            exact.owner,
            true,
            serve(shard_record(1), |_| {}, &recovering(exact), bumps(1)),
        ),
        (
            "a recovering request and two bumps",
            2,
            exact.owner,
            false,
            serve(shard_record(1), |_| {}, &recovering(exact), bumps(2)),
        ),
        (
            "an ordinary request and a takeover",
            1,
            standby(),
            false,
            serve(shard_record(1), designated, &ordinary(exact), takeover()),
        ),
        (
            "a recovering request and a takeover",
            1,
            standby(),
            false,
            serve(shard_record(1), designated, &recovering(exact), takeover()),
        ),
    ];
    let mut wrong = Vec::new();
    for (name, lost, owner, admitted, seen) in &cases {
        let lost_writes = *lost as u64;
        // The record the rival's writes left, which the last round read.
        let rival_left = ShardRecord {
            owner: *owner,
            attempts: exact.attempts + *lost as u32,
            standby: None,
            ..seen.before.shard.1
        };
        let expected = if *admitted {
            (
                Ending::Flipped(exact.generation.get() + 1),
                Records {
                    shard: (
                        seen.before.shard.0 + lost_writes + 1,
                        after_flip(&rival_left),
                    ),
                    first: seen.before.first.clone(),
                    spare: (
                        seen.before.spare.0 + lost_writes + 1,
                        seen.before.spare.1.clone(),
                    ),
                },
                (lost + 1, lost + 1),
            )
        } else {
            (
                Ending::Stale,
                Records {
                    shard: (seen.before.shard.0 + lost_writes, rival_left),
                    first: seen.before.first.clone(),
                    spare: (
                        seen.before.spare.0 + lost_writes,
                        seen.before.spare.1.clone(),
                    ),
                },
                (lost + 1, *lost),
            )
        };
        let holds = seen.admission == Ok(())
            && (&seen.ending, &seen.after) == (&expected.0, &expected.1)
            && (seen.shard_reads, seen.shard_writes) == expected.2;
        if !holds {
            wrong.push(format!("{name}: expected {expected:?}, saw {seen:?}"));
        }
    }
    drop(cases);
    assert!(
        wrong.is_empty(),
        "flip_for did not judge its request on the read a lost version condition led to: {wrong:#?}"
    );
}

/// A rival designation changes the shard record's version and no `(g, owner, E)`, so each round's flip write
/// loses its condition and the next round reads again. After three losses the fourth round flips the record
/// it read, at the version after the three designations; after four losses the call ends in `Retry` with four
/// shard reads, four refused shard writes and the tenure, active volume and spare in place, and a later call
/// flips.
#[test]
fn version_condition_losses_reread_and_end_in_retry_after_four() {
    let exact = Target::of(&shard_record(1));
    let designations = |rounds: usize| {
        rival(rounds, |store, round| {
            designate(store, Host::new(21 + round as u64).unwrap())
        })
    };
    let three = serve(
        shard_record(1),
        |_| {},
        &ordinary(exact),
        designations(ROUNDS - 1),
    );
    let three_holds = three.ending == Ending::Flipped(exact.generation.get() + 1)
        && three.after.shard
            == (
                three.before.shard.0 + ROUNDS as u64,
                after_flip(&three.before.shard.1),
            )
        && three.after.first == three.before.first
        && three.after.spare
            == (
                three.before.spare.0 + ROUNDS as u64,
                three.before.spare.1.clone(),
            )
        && (three.shard_reads, three.shard_writes) == (ROUNDS, ROUNDS);

    let four = serve(
        shard_record(1),
        |_| {},
        &ordinary(exact),
        designations(ROUNDS),
    );
    let last_designated = ShardRecord {
        standby: Host::new(20 + ROUNDS as u64),
        ..four.before.shard.1
    };
    let four_holds = four.ending == Ending::Retry
        && four.after.shard == (four.before.shard.0 + ROUNDS as u64, last_designated)
        && four.after.first == four.before.first
        && four.after.spare
            == (
                four.before.spare.0 + ROUNDS as u64,
                four.before.spare.1.clone(),
            )
        && (four.shard_reads, four.shard_writes) == (ROUNDS, ROUNDS);

    // The same reconciler serves the request again once the rival is quiet.
    let store = store(shard_record(1), volume_record());
    let counts = Rc::new(Counts::default());
    let probe = Probe {
        inner: store.clone(),
        counts: Rc::clone(&counts),
        rival: designations(ROUNDS),
    };
    let mut reconciler = Reconciler::new(Client::open(probe, MemLog::default()).unwrap());
    let request = ordinary(exact);
    let again = [
        ending(reconciler.flip_for(&OperatorRelease::diagnosed(), shard(), &request)),
        ending(reconciler.flip_for(&OperatorRelease::diagnosed(), shard(), &request)),
        ending(reconciler.flip_for(&OperatorRelease::diagnosed(), shard(), &request)),
    ];
    let active = shard_now(&store).active;
    drop(reconciler);
    drop(store);

    assert!(
        three_holds,
        "three version-condition losses did not end in a flip of the fourth read: {three:#?}"
    );
    assert!(
        four_holds,
        "four version-condition losses did not end in Retry over four fresh reads: {four:#?}"
    );
    assert_eq!(
        (again, active),
        (
            [
                Ending::Retry,
                Ending::Flipped(exact.generation.get() + 1),
                Ending::Past
            ],
            spare_volume()
        ),
        "a call after Retry flips the tenure, and a call after that flip finds it past"
    );
}

/// A rival that names another spare, or none, between two rounds ends the call in `Conflict`: the reconciler
/// makes no shard write that commits, and the record keeps its tenure and active volume with the rival's spare.
#[test]
fn a_spare_that_changes_between_rounds_is_a_conflict() {
    let exact = Target::of(&shard_record(1));
    let replacement = Some((VolumeId::new("vol-ee").unwrap(), spare_host()));
    let cases = [replacement, None].map(|spare| {
        (
            spare,
            serve(
                shard_record(1),
                |_| {},
                &ordinary(exact),
                rival(1, move |store, _| name_spare(store, spare)),
            ),
        )
    });
    let mut wrong = Vec::new();
    for (spare, seen) in &cases {
        let renamed = ShardRecord {
            spare: *spare,
            ..seen.before.shard.1
        };
        let holds = seen.ending == Ending::Conflict
            && seen.after.shard == (seen.before.shard.0 + 1, renamed)
            && seen.after.first == seen.before.first
            && (seen.shard_reads, seen.shard_writes) == (2, 1);
        if !holds {
            wrong.push(format!("{seen:?}"));
        }
    }
    drop(cases);
    assert!(
        wrong.is_empty(),
        "flip_for did not refuse a spare that changed between rounds: {wrong:#?}"
    );
}

/// A request for the spare role is refused before any request to the store, though the record admits it.
#[test]
fn a_request_for_the_spare_role_is_a_conflict_before_any_request() {
    let exact = Target::of(&shard_record(1));
    let request = Retirement::new(spare_volume(), Role::Spare, exact, Trigger::Activation).unwrap();
    let seen = serve(shard_record(1), |_| {}, &request, None);
    let holds = seen.admission == Ok(())
        && seen.ending == Ending::Conflict
        && seen.after == seen.before
        && (seen.reads, seen.writes) == (0, 0);
    assert!(
        holds,
        "flip_for served or read for a request of the spare role: {seen:#?}"
    );
}
