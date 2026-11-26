//! Store-client tests over the simulated store: no adoption from an unknown outcome, the watermark against every
//! kill arm, one winner per flip, the flip's checkpoint clear, the volume-record cross-check, the client's guards
//! and the production class's classification.

use core::num::{NonZeroU16, NonZeroU32};
use std::path::PathBuf;

use super::store::Read;
use super::store::sim::{Arm, MemLog, Point, Shared, hooked};
use super::store::{
    Bumped, Client, Item, Key, Outcome, Refusal, Regression, Store, StoreError, Unavailable,
    Version, Watermark, WatermarkLog, Write,
};
use crate::failover::flip::{VolumeMismatch, volume_state};
use crate::failover::records::{
    ATTEMPTS_MAX, Ancestry, CodecError, CoveragePage, CreationSource, Host, Layout, Lineage,
    NamedCheckpoint, Record, ShardRecord, SuccessorRule, Suffix, VolumeId, VolumeRecord,
    VolumeState,
};
use crate::net::ownership::{Shard, ShardGeneration};

pub(crate) const OWNER: u64 = 11;
pub(crate) const SPARE: u64 = 12;

/// The unknown-outcome arms: a timeout and a failure, each in the arm that commits and the one that does not.
pub(crate) const UNKNOWN: [Arm; 4] = [
    Arm::Timeout { commit: true },
    Arm::Timeout { commit: false },
    Arm::Failure { commit: true },
    Arm::Failure { commit: false },
];

/// Whether an unknown-outcome arm commits its write.
pub(crate) fn committed(arm: Arm) -> bool {
    matches!(
        arm,
        Arm::Timeout { commit: true } | Arm::Failure { commit: true }
    )
}

pub(crate) fn shard() -> Shard {
    Shard::new(7).unwrap()
}

pub(crate) fn record() -> ShardRecord {
    ShardRecord {
        shard: shard(),
        generation: ShardGeneration::new(3).unwrap(),
        active: VolumeId::new("vol-0a").unwrap(),
        owner: Host::new(OWNER).unwrap(),
        attempts: 0,
        spare: Some((VolumeId::new("vol-0b").unwrap(), Host::new(SPARE).unwrap())),
        checkpoint: None,
        cut: 0,
        pages: NonZeroU16::new(2).unwrap(),
        page_cap: NonZeroU32::new(4096).unwrap(),

        namespace: crate::storage::store::sim::NAMESPACE,

        ancestry: Default::default(),
        standby: None,
    }
}

/// A client over `store` with its own durable log.
pub(crate) fn client(store: &Shared) -> Client<Shared, MemLog> {
    Client::open(store.clone(), MemLog::default()).unwrap()
}

/// A store holding [`record`] and its pages.
pub(crate) fn seeded() -> Shared {
    let store = Shared::new();
    client(&store).create_shard(record()).unwrap();
    store
}

pub(crate) fn record_under(session: &crate::storage::Session) -> ShardRecord {
    ShardRecord {
        generation: session.generation(),
        ..record()
    }
}

pub(crate) fn seeded_under(session: &crate::storage::Session) -> Shared {
    let store = Shared::new();
    client(&store).create_shard(record_under(session)).unwrap();
    store
}

/// One attempt: read the shard record, refuse unless `host` owns it, and bump `E`.
pub(crate) fn attempt(
    client: &mut Client<Shared, MemLog>,
    host: u64,
) -> Result<Bumped, StoreError> {
    let read = client.read::<ShardRecord>(Key::Shard(shard()))?;
    if read.value().owner.get() != host {
        return Err(StoreError::Refused(Refusal::Condition));
    }
    client.bump(&read)
}

/// Whether two attempts adopted one `(g, n)`: the `NoEpochReuse` kill condition.
pub(crate) fn reuses(adopted: &[(ShardGeneration, u32)]) -> bool {
    (1..adopted.len()).any(|at| adopted[..at].contains(&adopted[at]))
}

/// Asserts that the [`Arm::Unavailable`] scheduled before a refusal is still pending, so the refusal issued no
/// request: a read through the store consumes it.
#[track_caller]
fn unused_arm(store: &Shared) {
    assert_eq!(
        store.clone().read(&Key::Shard(shard())),
        Err(Unavailable),
        "a request consumed the scheduled arm"
    );
}

/// Asserts that `client`'s next call refuses because a regression withdrew it.
#[track_caller]
pub(crate) fn withdrawn<S: Store, L: WatermarkLog>(client: &mut Client<S, L>) {
    assert_eq!(
        client.read::<ShardRecord>(Key::Shard(shard())).map(|_| ()),
        Err(StoreError::Withdrawn)
    );
}

/// Asserts that `client`'s read of `key` raises the regression alarm and withdraws it.
#[track_caller]
fn regresses<S: Store, L: WatermarkLog>(client: &mut Client<S, L>, key: Key) {
    let result = match key {
        Key::Page(..) => client.read::<CoveragePage>(key).map(|_| ()),
        _ => client.read::<ShardRecord>(key).map(|_| ()),
    };
    assert_eq!(result, Err(StoreError::Regression(Regression::Value(key))));
    withdrawn(client);
}

/// The shard record `store` holds now, read without consuming a scheduled arm.
pub(crate) fn stored(store: &Shared) -> (Version, ShardRecord) {
    let item = store
        .0
        .borrow()
        .current(&Key::Shard(shard()))
        .cloned()
        .unwrap();
    (item.version, ShardRecord::decode(&item.value).unwrap())
}

pub(crate) fn page(store: &Shared, page: u16) -> CoveragePage {
    let item = store
        .0
        .borrow()
        .current(&Key::Page(shard(), page))
        .cloned()
        .unwrap();
    CoveragePage::decode(&item.value).unwrap()
}

/// Directory creation panics on a name collision. Mode `0o700` reserves entry creation for the owner.
pub(crate) fn fresh_directory(name: &str) -> std::path::PathBuf {
    use std::os::unix::fs::DirBuilderExt;

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("{name}-{}-{nanos}", std::process::id()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    directory
}

/// The re-read control: after an unknown bump, re-read and take the attempt the record shows consumed, `E - 1`.
pub(crate) fn reread_and_proceed(
    client: &mut Client<Shared, MemLog>,
) -> Option<(ShardGeneration, u32)> {
    let read = client.read::<ShardRecord>(Key::Shard(shard())).ok()?;
    read.value()
        .attempts
        .checked_sub(1)
        .map(|n| (read.value().generation, n))
}

/// The step and the caller each make one conditional write over the version the caller read. At `AfterRead` the
/// step's write lands between the caller's read and its write, and at `BeforeWrite` before the caller's write is
/// forwarded: either way the caller's write is refused and the step's commits. At `AfterWrite` the step runs after
/// the caller's write replied, so the caller's commits and the step's is refused. A hook on another key never runs
/// its step, and the caller's write commits.
#[test]
fn each_hook_point_orders_the_hooked_write_differently() {
    use std::cell::Cell;
    use std::rc::Rc;
    let key = Key::Shard(shard());
    for (point, on, caller_wins) in [
        (Point::AfterRead, key, false),
        (Point::BeforeWrite, key, false),
        (Point::AfterWrite, key, true),
        (Point::AfterRead, Key::Page(shard(), 0), true),
        (Point::BeforeWrite, Key::Page(shard(), 0), true),
        (Point::AfterWrite, Key::Page(shard(), 0), true),
    ] {
        let named = on == key;
        let store = seeded();
        let read = |store: &mut dyn Store| store.read(&key).unwrap().expect("the record").version;
        let before = read(&mut store.clone());
        let write = |expect| Write::Exact {
            expect,
            value: b"written".to_vec(),
        };
        let step: Rc<Cell<Option<Outcome>>> = Rc::default();
        let (inner, stepped) = (store.clone(), Rc::clone(&step));
        let mut hook = hooked(&store, on, point, move || {
            stepped.set(Some(inner.clone().write(&key, &write(before))));
        });
        let seen = read(&mut hook);
        assert_eq!(
            seen, before,
            "{point:?}: the caller reads the seeded version"
        );
        assert_eq!(
            step.get().is_some(),
            named && point == Point::AfterRead,
            "{point:?}: only AfterRead runs at the read"
        );
        let caller = hook.write(&key, &write(seen));
        let committed = Outcome::Committed(before.next().expect("a next version"));
        let refused = |outcome: Outcome| matches!(outcome, Outcome::NotCommitted(_));
        assert_eq!(
            step.get().is_some(),
            named,
            "{point:?}: the step runs only on its key"
        );
        if caller_wins {
            assert_eq!(caller, committed, "{point:?}");
            assert!(
                !named || step.get().is_some_and(refused),
                "{point:?}: {:?}",
                step.get()
            );
        } else {
            assert!(refused(caller), "{point:?}: {caller:?}");
            assert_eq!(step.get(), Some(committed), "{point:?}");
        }
    }
}

/// A timeout or a failure, in the arm that commits and the one that does not, makes the bump return
/// [`StoreError::Unknown`], produces no witness and leaves the watermark where the read put it. A second attempt then
/// bumps by its own acknowledged write and is the only holder of its attempt; the re-read control, which takes the
/// attempt the re-read shows consumed, shares that attempt in both arms.
#[test]
fn unknown_outcome_adopts_nothing() {
    for arm in UNKNOWN {
        let store = seeded();
        let mut first = client(&store);
        let read = first.read::<ShardRecord>(Key::Shard(shard())).unwrap();
        let before = first.watermark().clone();
        store.schedule(arm);
        assert_eq!(first.bump(&read), Err(StoreError::Unknown), "{arm:?}");
        assert_eq!(first.watermark(), &before, "{arm:?}: nothing adopted");

        let second = attempt(&mut client(&store), OWNER).unwrap();
        assert_eq!(second.shard(), shard());
        let committed = matches!(
            arm,
            Arm::Timeout { commit: true } | Arm::Failure { commit: true }
        );
        assert_eq!(
            second.attempt(),
            u32::from(committed),
            "{arm:?}: the second attempt's own n"
        );
        let adopted = [(second.generation(), second.attempt())];
        let control = [adopted[0], reread_and_proceed(&mut first).unwrap()];
        assert!(
            reuses(&control),
            "{arm:?}: the re-read control shares attempt {control:?}"
        );
    }
}

/// Each kill arm puts a result below the watermark of a client that observed the later value, or makes an
/// exact-version write commit at a version other than the one after its read's: that client refuses with the
/// regression alarm and is withdrawn. A lost write, an absent record the watermark holds, a page fence lowered by a
/// double win, a reused version, a checkpoint older than the adopted one and another checkpoint with the adopted
/// one's `(session, capture)` each regress.
///
/// One case violates before any re-read and is reported by the reference check as a `NoEpochReuse`
/// kill-condition hit: a lost write that a second attempt overwrites.
#[test]
fn watermark_regression_refuses() {
    let key = Key::Shard(shard());

    let store = seeded();
    let mut owner = client(&store);
    let read = owner.read::<ShardRecord>(key).unwrap();
    store.schedule(Arm::LostWrite);
    owner.bump(&read).unwrap();
    regresses(&mut owner, key);

    // A flip commits, then a stale bump wins over its failed condition.
    let store = seeded();
    let mut reconciler = client(&store);
    let read = reconciler.read::<ShardRecord>(key).unwrap();
    let mut owner = client(&store);
    let stale = owner.read::<ShardRecord>(key).unwrap();
    reconciler.flip(&read).unwrap();
    store.schedule(Arm::DoubleWin);
    assert_eq!(
        owner.bump(&stale),
        Err(StoreError::Regression(Regression::Value(key)))
    );
    withdrawn(&mut owner);
    regresses(&mut reconciler, key);

    let store = seeded();
    let mut owner = client(&store);
    attempt(&mut owner, OWNER).unwrap();
    store.schedule(Arm::StaleCurrentRead);
    regresses(&mut owner, key);

    // A lost write that a flip overwrites at the same version: an equal version with a different value.
    let store = seeded();
    let mut owner = client(&store);
    let read = owner.read::<ShardRecord>(key).unwrap();
    let mut reconciler = client(&store);
    let before = reconciler.read::<ShardRecord>(key).unwrap();
    store.schedule(Arm::LostWrite);
    owner.bump(&read).unwrap();
    reconciler.flip(&before).unwrap();
    assert_eq!(stored(&store).0, read.version().next().unwrap());
    regresses(&mut owner, key);

    // Two bumps from one read, the second winning over its failed condition.
    let store = seeded();
    let (mut a, mut b) = (client(&store), client(&store));
    let (read_a, read_b) = (
        a.read::<ShardRecord>(key).unwrap(),
        b.read::<ShardRecord>(key).unwrap(),
    );
    a.bump(&read_a).unwrap();
    store.schedule(Arm::DoubleWin);
    assert_eq!(
        b.bump(&read_b),
        Err(StoreError::Regression(Regression::Value(key)))
    );
    withdrawn(&mut b);
    assert!(a.read::<ShardRecord>(key).is_ok());

    // A lost create: the record the watermark holds is absent.
    for key in [Key::Shard(shard()), Key::Page(shard(), 0)] {
        let store = Shared::new();
        let mut creator = client(&store);
        store.schedule(Arm::LostWrite);
        match key {
            Key::Page(..) => creator.create(key, CoveragePage::default()).map(|_| ()),
            _ => creator.create(key, record()).map(|_| ()),
        }
        .unwrap();
        regresses(&mut creator, key);
    }

    let page = Key::Page(shard(), 0);
    let store = seeded();
    let mut writer = client(&store);
    let read = writer.read::<CoveragePage>(page).unwrap();
    let fenced = CoveragePage {
        fence: 9,
        ..read.value().clone()
    };
    writer.replace(&read, fenced).unwrap();
    store.schedule(Arm::StaleCurrentRead);
    regresses(&mut writer, page);

    // A stale page writer's lower fence wins over its failed condition.
    let store = seeded();
    let (mut a, mut b) = (client(&store), client(&store));
    let (read_a, read_b) = (
        a.read::<CoveragePage>(page).unwrap(),
        b.read::<CoveragePage>(page).unwrap(),
    );
    let fence = |fence| CoveragePage {
        fence,
        ..CoveragePage::default()
    };
    a.replace(&read_a, fence(9)).unwrap();
    store.schedule(Arm::DoubleWin);
    assert_eq!(
        b.replace(&read_b, fence(5)).map(|_| ()),
        Err(StoreError::Regression(Regression::Value(page)))
    );
    withdrawn(&mut b);
    regresses(&mut a, page);

    // A stale writer clears the named checkpoint the first client adopted at this generation.
    let store = seeded();
    let (mut a, mut b) = (client(&store), client(&store));
    let (read_a, read_b) = (
        a.read::<ShardRecord>(key).unwrap(),
        b.read::<ShardRecord>(key).unwrap(),
    );
    let named = NamedCheckpoint {
        slot: 1,
        session: (3 << 32) | 2,
        capture: 1,
        units: 4,
    };
    a.replace(
        &read_a,
        ShardRecord {
            checkpoint: Some(named),
            ..*read_a.value()
        },
    )
    .unwrap();
    store.schedule(Arm::DoubleWin);
    let proof = *read_b.value();
    assert_eq!(
        b.replace(&read_b, proof).map(|_| ()),
        Err(StoreError::Regression(Regression::Value(key)))
    );
    withdrawn(&mut b);
    assert_eq!(
        a.read::<ShardRecord>(key).map(|_| ()),
        Err(StoreError::Regression(Regression::Checkpoint(shard())))
    );
    withdrawn(&mut a);

    // A lost checkpoint publish, then a replace from the retained read: the commit lands at the version the
    // watermark already holds, a reused version.
    let store = seeded();
    let mut owner = client(&store);
    let retained = owner.read::<ShardRecord>(key).unwrap();
    let publish = |session, capture| ShardRecord {
        checkpoint: Some(NamedCheckpoint {
            slot: 0,
            session,
            capture,
            units: 1,
        }),
        ..*retained.value()
    };
    store.schedule(Arm::LostWrite);
    owner.replace(&retained, publish(5, 1)).unwrap();
    assert_eq!(
        owner.replace(&retained, publish(4, 9)).map(|_| ()),
        Err(StoreError::Regression(Regression::Value(key)))
    );
    withdrawn(&mut owner);

    // A lost bump, then a second bump from the same retained read at the reused version.
    let store = seeded();
    let mut owner = client(&store);
    let retained = owner.read::<ShardRecord>(key).unwrap();
    store.schedule(Arm::LostWrite);
    owner.bump(&retained).unwrap();
    assert_eq!(
        owner.bump(&retained),
        Err(StoreError::Regression(Regression::Value(key)))
    );
    withdrawn(&mut owner);

    // A stale writer names, beside the checkpoint the first client adopted, an earlier capture of its session, or
    // the same capture with another slot or unit count.
    let named = |capture| NamedCheckpoint {
        slot: 0,
        session: 5,
        capture,
        units: 1,
    };
    for stale in [
        named(1),
        NamedCheckpoint {
            slot: 1,
            ..named(2)
        },
        NamedCheckpoint {
            units: 2,
            ..named(2)
        },
    ] {
        let store = seeded();
        let (mut a, mut b) = (client(&store), client(&store));
        let (read_a, read_b) = (
            a.read::<ShardRecord>(key).unwrap(),
            b.read::<ShardRecord>(key).unwrap(),
        );
        let published = ShardRecord {
            checkpoint: Some(named(2)),
            ..*read_a.value()
        };
        a.replace(&read_a, published).unwrap();
        store.schedule(Arm::DoubleWin);
        let written = ShardRecord {
            checkpoint: Some(stale),
            ..*read_b.value()
        };
        assert_eq!(
            b.replace(&read_b, written).map(|_| ()),
            Err(StoreError::Regression(Regression::Value(key))),
            "{stale:?}"
        );
        assert_eq!(
            a.read::<ShardRecord>(key).map(|_| ()),
            Err(StoreError::Regression(Regression::Checkpoint(shard()))),
            "{stale:?}"
        );
        withdrawn(&mut a);
    }

    let store = seeded();
    let mut first = client(&store);
    let read = first.read::<ShardRecord>(key).unwrap();
    store.schedule(Arm::LostWrite);
    let lost = first.bump(&read).unwrap();
    let second = attempt(&mut client(&store), OWNER).unwrap();
    let adopted = [
        (lost.generation(), lost.attempt()),
        (second.generation(), second.attempt()),
    ];
    assert!(
        first.read::<ShardRecord>(key).is_ok(),
        "no result falls below the first attempt's watermark"
    );
    assert!(
        reuses(&adopted),
        "the reference check reports the kill-condition hit"
    );
}

/// A store holding, under `key`, bytes no record codec decodes at the first version and `value` at the second, as
/// a record first written in a format this build does not read and then rewritten leaves it.
fn undecodable_then(key: Key, value: Vec<u8>) -> Shared {
    let store = Shared::new();
    let garbage = Write::Create(vec![0xFF; 8]);
    let rewrite = Write::Exact {
        expect: Version::FIRST,
        value,
    };
    for write in [garbage, rewrite] {
        assert!(matches!(
            store.0.borrow_mut().write(&key, &write),
            Outcome::Committed(_)
        ));
    }
    store
}

/// A stale current read that returns a version below the watermark's regresses when the older bytes do not
/// decode: the version alone shows the result is older than one the client observed.
#[test]
fn a_stale_read_below_the_held_version_regresses_when_its_bytes_do_not_decode() {
    let key = Key::Shard(shard());
    let store = undecodable_then(key, record().encode());
    let mut host = client(&store);
    let read = host.read::<ShardRecord>(key).unwrap();
    assert_eq!(Some(read.version()), Version::FIRST.next());
    store.schedule(Arm::StaleCurrentRead);
    regresses(&mut host, key);

    let page = Key::Page(shard(), 0);
    let store = undecodable_then(page, CoveragePage::default().encode());
    let mut host = client(&store);
    let read = host.read::<CoveragePage>(page).unwrap();
    assert_eq!(Some(read.version()), Version::FIRST.next());
    store.schedule(Arm::StaleCurrentRead);
    regresses(&mut host, page);
}

/// A mark is raised only over bytes that decoded. Undecodable bytes at the mark's version are another value at
/// that version, so the read regresses and withdraws the client. The client's create raises the mark; a refused
/// second create makes [`GarblesAfterRefusal`] return undecodable bytes at the same version.
#[test]
fn an_undecodable_read_at_the_held_version_regresses() {
    for key in [Key::Shard(shard()), Key::Page(shard(), 0)] {
        let garbling = GarblesAfterRefusal {
            store: Shared::new(),
            garbled: key,
            refused: false,
        };
        let mut host = Client::open(garbling, MemLog::default()).unwrap();
        let create = |host: &mut Client<GarblesAfterRefusal, MemLog>| match key {
            Key::Page(..) => host
                .create(key, CoveragePage::default())
                .map(|read| read.version()),
            _ => host.create(key, record()).map(|read| read.version()),
        };
        assert_eq!(create(&mut host), Ok(Version::FIRST));
        assert_eq!(
            create(&mut host),
            Err(StoreError::Refused(Refusal::Condition))
        );
        regresses(&mut host, key);
    }
}

/// Undecodable bytes at a version above the mark may be a later write in a format this build does not read.
#[test]
fn an_undecodable_read_above_the_held_version_refuses_as_codec_and_stays_admitted() {
    let items = [
        (Key::Shard(shard()), record().encode()),
        (Key::Page(shard(), 0), CoveragePage::default().encode()),
    ];
    for (key, value) in items {
        let store = Shared::new();
        let garbage = Write::Exact {
            expect: Version::FIRST,
            value: vec![0xFF; 8],
        };
        let mut host = client(&store);
        let read = |host: &mut Client<Shared, MemLog>| match key {
            Key::Page(..) => host.read::<CoveragePage>(key).map(|read| read.version()),
            _ => host.read::<ShardRecord>(key).map(|read| read.version()),
        };
        let write = |write: &Write| {
            assert!(matches!(
                store.0.borrow_mut().write(&key, write),
                Outcome::Committed(_)
            ));
        };
        write(&Write::Create(value));
        assert_eq!(read(&mut host), Ok(Version::FIRST));
        write(&garbage);
        assert!(matches!(read(&mut host), Err(StoreError::Codec(_))));
        assert!(
            matches!(read(&mut host), Err(StoreError::Codec(_))),
            "the client stays admitted"
        );
    }
}

/// The sibling without the held mark: a client that never observed the record reads the same undecodable first
/// version as a codec refusal and stays admitted.
#[test]
fn an_undecodable_read_under_no_mark_refuses_as_codec_and_stays_admitted() {
    let key = Key::Shard(shard());
    let store = undecodable_then(key, record().encode());
    let mut host = client(&store);
    store.schedule(Arm::StaleCurrentRead);
    assert!(matches!(
        host.read::<ShardRecord>(key),
        Err(StoreError::Codec(_))
    ));
    assert!(host.read::<ShardRecord>(key).is_ok());
}

/// Two reconcilers that read one generation each flip it, with and without a currency proof committed between the
/// reads and the flips. At most one flip commits and at least one refuses on its condition; exactly one commits
/// unless the proof moved the version the flips expect.
#[test]
fn dual_flip_one_winner() {
    for proof_between in [false, true] {
        let store = seeded();
        let (mut a, mut b) = (client(&store), client(&store));
        let (read_a, read_b) = (
            a.read::<ShardRecord>(Key::Shard(shard())).unwrap(),
            b.read::<ShardRecord>(Key::Shard(shard())).unwrap(),
        );
        if proof_between {
            let mut owner = client(&store);
            let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
            owner.replace(&read, *read.value()).unwrap();
        }
        let results = [a.flip(&read_a), b.flip(&read_b)];
        let wins = results.iter().filter(|result| result.is_ok()).count();
        let expected = usize::from(!proof_between);
        assert_eq!(wins, expected, "proof {proof_between}: {results:?}");
        assert!(results.contains(&Err(StoreError::Refused(Refusal::Condition))));
        let (_, now) = stored(&store);
        assert_eq!(now.generation.get(), 3 + wins as u64);
    }
}

/// A flip of a shard record naming a standby, the spare's host or another non-owner host, clears the standby: the
/// flipped record names the spare active under its host at the next generation with no standby, and encodes format
/// 2, which a format-2 reader reads.
#[test]
fn a_flip_clears_the_named_standby() {
    for standby in [SPARE, SPARE + 1] {
        let store = Shared::new();
        let named = ShardRecord {
            standby: Some(Host::new(standby).unwrap()),
            ..record()
        };
        let mut reconciler = client(&store);
        let read = reconciler.create_shard(named).unwrap();
        reconciler.flip(&read).unwrap();
        let after = stored(&store).1;
        assert_eq!(after.generation.get(), named.generation.get() + 1);
        assert_eq!(Some((after.active, after.owner)), named.spare);
        assert_eq!(after.standby, None);
        assert_eq!(
            after.encode().len(),
            crate::failover::records::SHARD_LEN,
            "standby {standby}"
        );
    }
}

/// A flip of a shard record naming a checkpoint commits `ck := none` with the next generation, the spare active
/// under its host, `E = 0`, no spare, no cut and no ancestry, and keeps the shard, `B`, `C_page` and the namespace.
#[test]
fn flip_clears_named_checkpoint() {
    let store = seeded();
    let mut owner = client(&store);
    attempt(&mut owner, OWNER).unwrap();
    let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    let named = NamedCheckpoint {
        slot: 1,
        session: (3 << 32) | 2,
        capture: 1,
        units: 4,
    };
    let next = ShardRecord {
        checkpoint: Some(named),
        cut: 9,
        ancestry: Ancestry::new(&[Suffix {
            session: named.session,
            start: 9,
            certified: 12,
            end: 12,
        }])
        .unwrap(),
        ..*read.value()
    };
    owner.replace(&read, next).unwrap();
    let mut reconciler = client(&store);
    let read = reconciler.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    let flipped = reconciler.flip(&read).unwrap();
    let seen = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    assert_eq!(
        seen.value().checkpoint,
        None,
        "the owner's adopted checkpoint binds only its own generation"
    );
    let after = stored(&store).1;
    assert_eq!(
        after,
        ShardRecord {
            generation: ShardGeneration::new(4).unwrap(),
            active: VolumeId::new("vol-0b").unwrap(),
            owner: Host::new(SPARE).unwrap(),
            attempts: 0,
            spare: None,
            checkpoint: None,
            cut: 0,
            ancestry: Ancestry::default(),
            ..*read.value()
        }
    );
    assert_eq!(after.namespace, read.value().namespace);
    assert_eq!(
        (flipped.shard(), flipped.generation()),
        (shard(), after.generation)
    );
}

/// A client that creates a shard record naming a checkpoint adopts that checkpoint at the record's generation: a
/// later result at the same generation that clears it, names an earlier capture, or names the same capture with
/// another slot is a checkpoint regression.
#[test]
fn create_adopts_the_named_checkpoint() {
    let key = Key::Shard(shard());
    let named = |capture| NamedCheckpoint {
        slot: 0,
        session: 5,
        capture,
        units: 1,
    };
    for later in [
        None,
        Some(named(1)),
        Some(NamedCheckpoint {
            slot: 1,
            ..named(2)
        }),
    ] {
        let store = Shared::new();
        let mut creator = client(&store);
        let created = creator
            .create_shard(ShardRecord {
                checkpoint: Some(named(2)),
                ..record()
            })
            .unwrap();
        let overwritten = ShardRecord {
            checkpoint: later,
            ..*created.value()
        };
        let exact = Write::Exact {
            expect: created.version(),
            value: overwritten.encode(),
        };
        assert!(matches!(
            store.0.borrow_mut().write(&key, &exact),
            Outcome::Committed(_)
        ));
        assert_eq!(
            creator.read::<ShardRecord>(key).map(|_| ()),
            Err(StoreError::Regression(Regression::Checkpoint(shard()))),
            "{later:?}"
        );
        withdrawn(&mut creator);
    }
}

/// A client whose acknowledged bump carries a named checkpoint adopts it at the record's generation: when a stale
/// bump later restores an older checkpoint over its failed condition, the client's next read is a checkpoint
/// regression.
#[test]
fn bump_adopts_the_named_checkpoint() {
    let key = Key::Shard(shard());
    let named = |capture| NamedCheckpoint {
        slot: 0,
        session: 5,
        capture,
        units: 1,
    };
    let store = Shared::new();
    client(&store)
        .create_shard(ShardRecord {
            checkpoint: Some(named(1)),
            ..record()
        })
        .unwrap();
    let mut stale = client(&store);
    let old = stale.read::<ShardRecord>(key).unwrap();
    let mut publisher = client(&store);
    let read = publisher.read::<ShardRecord>(key).unwrap();
    publisher
        .replace(
            &read,
            ShardRecord {
                checkpoint: Some(named(2)),
                ..*read.value()
            },
        )
        .unwrap();
    let mut owner = client(&store);
    attempt(&mut owner, OWNER).unwrap();
    store.schedule(Arm::DoubleWin);
    assert_eq!(
        stale.bump(&old),
        Err(StoreError::Regression(Regression::Value(key)))
    );
    assert_eq!(stored(&store).1.checkpoint, Some(named(1)));
    assert_eq!(
        owner.read::<ShardRecord>(key).map(|_| ()),
        Err(StoreError::Regression(Regression::Checkpoint(shard())))
    );
    withdrawn(&mut owner);
}

/// After a flip, the old volume's record still showing active refuses; the spare's fresh record reads as active;
/// a retired or deleted record of the old volume reads as its own state; a retired record the shard record still
/// names active refuses.
#[test]
fn volume_record_active_mismatch_refuses() {
    let store = seeded();
    let mut reconciler = client(&store);
    let layout = Layout {
        units: 64,
        slots: 3,
        slot_units: 2,
        entries: 41,
    };
    let volume = |name, state| VolumeRecord {
        volume: VolumeId::new(name).unwrap(),
        state,
        source: CreationSource::Provisioned,
        lineage: Lineage::None,
        modification: None,
        layout,
        next: 0,
        forced: false,
        fence: 0,
        pairs: Vec::new(),
        events: Vec::new(),
    };
    let (old, spare) = (
        volume("vol-0a", VolumeState::Active),
        volume("vol-0b", VolumeState::Fresh),
    );
    for volume in [&old, &spare] {
        reconciler
            .create(Key::Volume(volume.volume), volume.clone())
            .unwrap();
    }
    let before = reconciler.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    assert_eq!(volume_state(before.value(), &old), Ok(VolumeState::Active));
    assert_eq!(volume_state(before.value(), &spare), Ok(VolumeState::Fresh));
    reconciler.flip(&before).unwrap();

    let mut host = client(&store);
    let after = host.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    let old_read = host.read::<VolumeRecord>(Key::Volume(old.volume)).unwrap();
    assert_eq!(
        volume_state(after.value(), old_read.value()),
        Err(VolumeMismatch::ActiveElsewhere)
    );
    assert_eq!(volume_state(after.value(), &spare), Ok(VolumeState::Active));
    let mut retired = old_read.value().clone();
    retired.state = VolumeState::Retired;
    reconciler.replace(&old_read, retired.clone()).unwrap();
    assert_eq!(
        volume_state(after.value(), &retired),
        Ok(VolumeState::Retired)
    );
    assert_eq!(
        volume_state(
            after.value(),
            &VolumeRecord {
                state: VolumeState::Deleted,
                ..retired.clone()
            }
        ),
        Ok(VolumeState::Deleted)
    );
    let named = ShardRecord {
        active: old.volume,
        ..*after.value()
    };
    assert_eq!(
        volume_state(&named, &retired),
        Err(VolumeMismatch::RetiredNamedActive)
    );
}

/// Under every contract arm the client adopts only values its own acknowledged writes committed, and every value
/// the store holds afterwards came from one commit of one requested write: a delayed write applies once when its
/// condition still holds, two reordered writes apply in the reverse of their order, a duplicate delivery fails its
/// condition, an unavailable store commits nothing, a stale read's compare-and-swap fails, and a value over the
/// size limit is rejected uncommitted.
#[test]
fn contract_arms_adopt_only_acknowledged_values() {
    let key = Key::Shard(shard());
    let store = seeded();
    let mut owner = client(&store);
    let read = owner.read::<ShardRecord>(key).unwrap();
    store.schedule(Arm::Delay);
    assert_eq!(owner.bump(&read), Err(StoreError::Unknown));
    assert_eq!(
        stored(&store).1.attempts,
        0,
        "the delayed bump is held until the next request"
    );
    assert_eq!(
        owner.bump(&read),
        Err(StoreError::Refused(Refusal::Condition))
    );
    assert_eq!(
        stored(&store).1.attempts,
        1,
        "the delayed bump applied at the next request"
    );

    // A bump and a proof on one read value: the reordered proof applies first, and the bump on the same read
    // version then fails its condition.
    let store = seeded();
    let (mut a, mut b) = (client(&store), client(&store));
    let (read_a, read_b) = (
        a.read::<ShardRecord>(key).unwrap(),
        b.read::<ShardRecord>(key).unwrap(),
    );
    store.schedule(Arm::Delay);
    store.schedule(Arm::Reorder);
    assert_eq!(a.bump(&read_a), Err(StoreError::Unknown));
    let proof = *read_b.value();
    assert_eq!(
        b.replace(&read_b, proof).map(|_| ()),
        Err(StoreError::Unknown)
    );
    client(&store).read::<ShardRecord>(key).unwrap();
    let (version, now) = stored(&store);
    assert_eq!(
        (version.get(), now.attempts),
        (read_b.version().get() + 1, 0),
        "the reordered proof applied first"
    );

    let store = seeded();
    let mut owner = client(&store);
    store.schedule(Arm::Pass);
    store.schedule(Arm::Duplicate);
    let witness = attempt(&mut owner, OWNER).unwrap();
    client(&store).read::<ShardRecord>(key).unwrap();
    assert_eq!(
        (witness.attempt(), stored(&store).1.attempts),
        (0, 1),
        "the duplicate delivery fails its condition"
    );
    assert_eq!(
        store.0.borrow().drained,
        [Outcome::NotCommitted(Refusal::Condition)],
        "one redelivery"
    );
    assert_eq!(
        store.0.borrow().commit_count(&key),
        2,
        "the create and one bump commit; the redelivery does not"
    );

    let store = seeded();
    let mut owner = client(&store);
    let read = owner.read::<ShardRecord>(key).unwrap();
    store.schedule(Arm::Unavailable);
    assert_eq!(
        owner.read::<ShardRecord>(key).map(|_| ()),
        Err(StoreError::Unavailable)
    );
    store.schedule(Arm::Unavailable);
    assert_eq!(owner.bump(&read), Err(StoreError::Unknown));
    assert_eq!(
        stored(&store).1.attempts,
        0,
        "an unavailable store commits nothing"
    );

    // A read that overlaps a bump: the bump is held and applies during the read, which misses it.
    let store = seeded();
    let mut owner = client(&store);
    let read = owner.read::<ShardRecord>(key).unwrap();
    store.schedule(Arm::Delay);
    assert_eq!(owner.bump(&read), Err(StoreError::Unknown));
    let mut lagging = client(&store);
    store.schedule(Arm::StaleRead);
    let stale = lagging.read::<ShardRecord>(key).unwrap();
    assert_eq!(stored(&store).1.attempts, 1);
    assert_eq!(stale.value().attempts, 0);
    let proof = lagging.replace(&stale, *stale.value());
    assert_eq!(
        proof.map(|_| ()),
        Err(StoreError::Refused(Refusal::Condition))
    );
    let store = seeded();
    store.0.borrow_mut().limit = 64;
    let mut owner = client(&store);
    let read = owner.read::<CoveragePage>(Key::Page(shard(), 1)).unwrap();
    let full = CoveragePage {
        entries: vec![0; 64],
        ..read.value().clone()
    };
    assert_eq!(
        owner.replace(&read, full).map(|_| ()),
        Err(StoreError::Refused(Refusal::Rejected))
    );
    let unchanged = owner.read::<CoveragePage>(Key::Page(shard(), 1)).unwrap();
    assert_eq!(unchanged.version(), read.version());
}

/// A bump held at the store while a later write on the same read value commits and is acknowledged fails its
/// condition on the proof's version when it applies, leaves the proof's commit current and adopts nothing.
#[test]
fn held_write_overtaken_fails_its_condition() {
    let key = Key::Shard(shard());
    let store = seeded();
    let (mut a, mut b) = (client(&store), client(&store));
    let read_a = a.read::<ShardRecord>(key).unwrap();
    store.schedule(Arm::Hold);
    assert_eq!(a.bump(&read_a), Err(StoreError::Unknown));
    let read_b = b.read::<ShardRecord>(key).unwrap();
    let proof = *read_b.value();
    let committed = b.replace(&read_b, proof).unwrap();
    let released = store.release();
    assert_eq!(released, [Outcome::NotCommitted(Refusal::Condition)]);
    assert_eq!(stored(&store), (committed.version(), proof));
}

/// The old owner keeps its read across a flip. Its stale `E` bump and its stale currency proof each refuse on
/// their condition before the successor bumps `E`; the record keeps the flipped generation and `E = 0`, and the old
/// owner holds no witness and stays admitted.
#[test]
fn stale_owner_refused_after_flip() {
    let key = Key::Shard(shard());
    let store = seeded();
    let mut owner = client(&store);
    let stale = owner.read::<ShardRecord>(key).unwrap();
    let mut reconciler = client(&store);
    let read = reconciler.read::<ShardRecord>(key).unwrap();
    reconciler.flip(&read).unwrap();
    let flipped = stored(&store);
    assert_eq!(
        owner.bump(&stale),
        Err(StoreError::Refused(Refusal::Condition))
    );
    let proof = *stale.value();
    assert_eq!(
        owner.replace(&stale, proof).map(|_| ()),
        Err(StoreError::Refused(Refusal::Condition))
    );
    assert_eq!(stored(&store), flipped);
    assert_eq!((flipped.1.generation.get(), flipped.1.attempts), (4, 0));
    assert!(owner.read::<ShardRecord>(key).is_ok());
}

/// A reconciler reads the shard record, another replaces its spare, and the reconciler's flip on the stale read
/// refuses on its condition: the record's version moved past the read's.
#[test]
fn stale_spare_flip_refuses() {
    let key = Key::Shard(shard());
    let store = seeded();
    let mut reconciler = client(&store);
    let stale = reconciler.read::<ShardRecord>(key).unwrap();
    let mut other = client(&store);
    let read = other.read::<ShardRecord>(key).unwrap();
    let replaced = ShardRecord {
        spare: Some((VolumeId::new("vol-0c").unwrap(), Host::new(13).unwrap())),
        ..*read.value()
    };
    other.replace(&read, replaced).unwrap();
    let before = stored(&store);
    assert_eq!(
        reconciler.flip(&stale),
        Err(StoreError::Refused(Refusal::Condition))
    );
    assert_eq!(stored(&store), before);
    assert_eq!(before.1.spare, replaced.spare);
}

/// A bump on a read older than the client's own checkpoint publish refuses on its condition and leaves the
/// published record.
#[test]
fn bump_on_a_read_before_a_publish_refuses() {
    let key = Key::Shard(shard());
    let store = seeded();
    let mut owner = client(&store);
    let old = owner.read::<ShardRecord>(key).unwrap();
    let named = NamedCheckpoint {
        slot: 0,
        session: (3 << 32) | 2,
        capture: 1,
        units: 4,
    };
    let published = ShardRecord {
        checkpoint: Some(named),
        ..*old.value()
    };
    let committed = owner.replace(&old, published).unwrap();
    assert_eq!(
        owner.bump(&old),
        Err(StoreError::Refused(Refusal::Condition))
    );
    assert_eq!(stored(&store), (committed.version(), published));
}

/// The client's guards refuse before any request: a successor that changes an immutable field, `(g, active,
/// owner, E)`, admits no ancestry or clears the named checkpoint; a value that does not name its key; and a bump at
/// `E = ATTEMPTS_MAX`. A scheduled `Unavailable` arm left for the next read shows no request was made. A stored
/// record that names another key or does not decode refuses on read.
#[test]
fn client_guards_refuse_before_any_request() {
    let key = Key::Shard(shard());
    let store = seeded();
    let mut owner = client(&store);
    let named = NamedCheckpoint {
        slot: 0,
        session: 1,
        capture: 1,
        units: 1,
    };
    let read = owner.read::<ShardRecord>(key).unwrap();
    let read = owner
        .replace(
            &read,
            ShardRecord {
                checkpoint: Some(named),
                ..*read.value()
            },
        )
        .unwrap();
    let before = owner.watermark().clone();
    let current = *read.value();
    let refused: [(ShardRecord, SuccessorRule); 5] = [
        (
            ShardRecord {
                pages: NonZeroU16::new(3).unwrap(),
                ..current
            },
            SuccessorRule::Pages,
        ),
        (
            ShardRecord {
                attempts: 1,
                ..current
            },
            SuccessorRule::Tenure,
        ),
        (
            ShardRecord {
                owner: Host::new(SPARE).unwrap(),
                ..current
            },
            SuccessorRule::Tenure,
        ),
        (
            ShardRecord {
                ancestry: Ancestry::new(&[Suffix::default()]).unwrap(),
                ..current
            },
            SuccessorRule::Ancestry,
        ),
        (
            ShardRecord {
                checkpoint: None,
                ..current
            },
            SuccessorRule::Checkpoint,
        ),
    ];
    for (next, field) in refused {
        store.schedule(Arm::Unavailable);
        assert_eq!(
            owner.replace(&read, next).map(|_| ()),
            Err(StoreError::Successor(field))
        );
        assert_eq!(owner.watermark(), &before);
        assert_eq!(
            owner.read::<ShardRecord>(key).map(|_| ()),
            Err(StoreError::Unavailable)
        );
    }

    let other = ShardRecord {
        shard: Shard::new(8).unwrap(),
        ..record()
    };
    let commits = store
        .0
        .borrow()
        .commit_count(&Key::Shard(Shard::new(9).unwrap()));
    assert_eq!(
        owner
            .create(Key::Shard(Shard::new(9).unwrap()), other)
            .map(|_| ()),
        Err(StoreError::Codec(CodecError::Field))
    );
    assert_eq!(
        store
            .0
            .borrow()
            .commit_count(&Key::Shard(Shard::new(9).unwrap())),
        commits
    );
    assert_eq!(
        owner
            .create(Key::Shard(Shard::new(9).unwrap()), CoveragePage::default())
            .map(|_| ()),
        Err(StoreError::Codec(CodecError::Field)),
        "a page names only a page key"
    );
    for (value, error) in [
        (other.encode(), CodecError::Field),
        (b"garbage".to_vec(), CodecError::Length),
        (vec![0; record().encode().len()], CodecError::Magic),
    ] {
        let store = seeded();
        let version = stored(&store).0;
        let write = Write::Exact {
            expect: version,
            value,
        };
        Store::write(&mut store.clone(), &key, &write);
        assert_eq!(
            client(&store).read::<ShardRecord>(key).map(|_| ()),
            Err(StoreError::Codec(error))
        );
    }

    let store = Shared::new();
    let mut owner = client(&store);
    let last = ShardRecord {
        attempts: ATTEMPTS_MAX - 1,
        ..record()
    };
    owner.create_shard(last).unwrap();
    let read = owner.read::<ShardRecord>(key).unwrap();
    assert_eq!(owner.bump(&read).unwrap().attempt(), ATTEMPTS_MAX - 1);
    let read = owner.read::<ShardRecord>(key).unwrap();
    assert_eq!(read.value().attempts, ATTEMPTS_MAX);
    store.schedule(Arm::Unavailable);
    assert_eq!(owner.bump(&read), Err(StoreError::AttemptsExhausted));
    assert_eq!(
        owner.read::<ShardRecord>(key).map(|_| ()),
        Err(StoreError::Unavailable)
    );
}

/// A watermark the log fails to record withdraws the client. Each acknowledged write, a bump, a flip, a
/// checkpoint publish and a shard's creation, returns [`StoreError::Log`] and no value or
/// witness, the log keeps the watermark it held, and the next call refuses. A read of a value the watermark already
/// holds records nothing, so it succeeds while the log fails.
#[test]
fn log_failure_withdraws_and_adopts_nothing() {
    let key = Key::Shard(shard());
    type Commit =
        fn(&mut Client<Shared, MemLog>, &super::store::Read<ShardRecord>) -> Result<(), StoreError>;
    let commits: [(&str, Commit); 3] = [
        ("bump", |owner, read| owner.bump(read).map(|_| ())),
        ("flip", |owner, read| owner.flip(read).map(|_| ())),
        ("publish", |owner, read| {
            let named = NamedCheckpoint {
                slot: 0,
                session: 1,
                capture: 1,
                units: 1,
            };
            let next = ShardRecord {
                checkpoint: Some(named),
                ..*read.value()
            };
            owner.replace(read, next).map(|_| ())
        }),
    ];
    for (name, commit) in commits {
        let store = seeded();
        let log = MemLog::default();
        let mut owner = Client::open(store.clone(), log.clone()).unwrap();
        let read = owner.read::<ShardRecord>(key).unwrap();
        let held = log.held();
        log.fail.set(true);
        assert!(owner.read::<ShardRecord>(key).is_ok());
        assert_eq!(commit(&mut owner, &read), Err(StoreError::Log), "{name}");
        assert!(stored(&store).0 > read.version(), "{name} committed");
        assert_eq!(log.held(), held, "{name}");
        log.fail.set(false);
        withdrawn(&mut owner);
    }
    let store = Shared::new();
    let log = MemLog::default();
    let mut creator = Client::open(store.clone(), log.clone()).unwrap();
    log.fail.set(true);
    assert_eq!(
        creator.create_shard(record()).map(|_| ()),
        Err(StoreError::Log)
    );
    assert_eq!(
        stored(&store),
        (Version::FIRST, record()),
        "the create committed"
    );
    assert_eq!(log.held(), Watermark::default());
    log.fail.set(false);
    withdrawn(&mut creator);
}

/// A file log that fails to record withdraws the client: once the log's directory is gone, the acknowledged bump
/// returns [`StoreError::Log`] and the next call refuses.
#[test]
fn file_log_failure_withdraws() {
    use super::store::{FileLog, Watermark, WatermarkLog};

    let directory = fresh_directory("watermark-fail");
    let path = directory.join("mark");
    FileLog::new(path.clone())
        .unwrap()
        .record(&Watermark::default())
        .unwrap();
    let store = seeded();
    let mut owner = Client::open(store.clone(), FileLog::new(path).unwrap()).unwrap();
    let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    std::fs::remove_dir_all(&directory).unwrap();
    assert_eq!(owner.bump(&read), Err(StoreError::Log));
    assert_eq!(
        owner.read::<ShardRecord>(Key::Shard(shard())).map(|_| ()),
        Err(StoreError::Withdrawn)
    );
}

/// Exact-version writes chain on the [`super::store::Read`] an acknowledged create or replace returns, with no read
/// between them: each commits at the version after the one before, and the store holds the last value.
#[test]
fn writes_chain_on_acknowledged_values() {
    let store = Shared::new();
    let mut owner = client(&store);
    let created = owner.create(Key::Shard(shard()), record()).unwrap();
    let first = ShardRecord {
        spare: None,
        ..record()
    };
    let proved = owner.replace(&created, first).unwrap();
    let second = ShardRecord {
        spare: Some((VolumeId::new("vol-0c").unwrap(), Host::new(SPARE).unwrap())),
        ..record()
    };
    assert_ne!(second, first);
    let again = owner.replace(&proved, second).unwrap();
    assert_eq!(
        [created.version(), proved.version(), again.version()].map(Version::get),
        [1, 2, 3]
    );
    assert_eq!(stored(&store), (again.version(), second));
}

/// A class that reports a create committed at a version other than the first, or an exact-version write committed
/// at a version other than the one after its condition's, is refused with the regression alarm and withdraws the
/// client.
#[test]
fn misreported_commit_version_regresses() {
    struct Misreports(Shared, u64);
    impl Store for Misreports {
        fn namespace(&self) -> crate::failover::records::Namespace {
            self.0.namespace()
        }

        fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
            self.0.read(key)
        }
        fn write(&mut self, key: &Key, write: &Write) -> Outcome {
            match self.0.write(key, write) {
                Outcome::Committed(version) => {
                    Outcome::Committed(Version::new(version.get() + self.1).unwrap())
                }
                outcome => outcome,
            }
        }
    }
    let key = Key::Shard(shard());
    let mut creator = Client::open(Misreports(Shared::new(), 1), MemLog::default()).unwrap();
    assert_eq!(
        creator.create(key, record()).map(|_| ()),
        Err(StoreError::Regression(Regression::Value(key)))
    );
    assert_eq!(
        creator.read::<ShardRecord>(key).map(|_| ()),
        Err(StoreError::Withdrawn)
    );
    let mut owner = Client::open(Misreports(seeded(), 1), MemLog::default()).unwrap();
    let read = owner.read::<ShardRecord>(key).unwrap();
    assert_eq!(
        owner.bump(&read).map(|bumped| bumped.attempt()),
        Err(StoreError::Regression(Regression::Value(key)))
    );
    assert_eq!(
        owner.read::<ShardRecord>(key).map(|_| ()),
        Err(StoreError::Withdrawn)
    );
}

/// The production class maps each error code the store qualification recorded to its outcome, every other code
/// and a transport failure to unknown, and makes one exchange call per request.
#[test]
fn dynamo_classifies_recorded_errors() {
    use std::cell::Cell;
    use std::rc::Rc;

    use super::store::dynamo::{Dynamo, Exchange, Fault, classify};

    for (code, outcome) in [
        (
            "ConditionalCheckFailedException",
            Outcome::NotCommitted(Refusal::Condition),
        ),
        (
            "com.amazonaws.dynamodb.v20120810#ValidationException",
            Outcome::NotCommitted(Refusal::Rejected),
        ),
        (
            "AccessDeniedException",
            Outcome::NotCommitted(Refusal::Denied),
        ),
        ("InternalServerError", Outcome::Unknown),
        ("ProvisionedThroughputExceededException", Outcome::Unknown),
        ("ThrottlingException", Outcome::Unknown),
    ] {
        assert_eq!(classify(code), outcome, "{code}");
    }
    struct Scripted(Vec<Result<Version, Fault>>, Rc<Cell<usize>>);
    impl Exchange for Scripted {
        fn get(&mut self, _: &str) -> Result<Option<Item>, Fault> {
            self.1.set(self.1.get() + 1);
            Err(Fault::Transport)
        }
        fn write(&mut self, key: &str, _: &Write) -> Result<Version, Fault> {
            assert_eq!(key, "shard#7");
            self.1.set(self.1.get() + 1);
            self.0.remove(0)
        }
        fn namespace(&self) -> crate::failover::records::Namespace {
            super::store::sim::NAMESPACE
        }
    }
    let replies = vec![
        Ok(Version::new(4).unwrap()),
        Err(Fault::Transport),
        Err(Fault::Error("ConditionalCheckFailedException".into())),
    ];
    let calls = Rc::new(Cell::new(0));
    let mut store = Dynamo(Scripted(replies, calls.clone()));
    let write = Write::Create(Vec::new());
    let key = Key::Shard(shard());
    let expected = [
        Outcome::Committed(Version::new(4).unwrap()),
        Outcome::Unknown,
        Outcome::NotCommitted(Refusal::Condition),
    ];
    for (at, outcome) in expected.into_iter().enumerate() {
        assert_eq!(store.write(&key, &write), outcome);
        assert_eq!(calls.get(), at + 1, "one call per write");
    }
    assert_eq!(store.read(&key), Err(Unavailable));
    assert_eq!(calls.get(), 4, "one call per read");
}

/// The watermark round-trips through its encoding with page marks and an adopted checkpoint, refuses truncated,
/// extended, bit-flipped and zeroed bytes, and survives the file log's replace at a path whose staging name differs
/// from it. A log with no file reports `NotFound`.
#[test]
fn watermark_round_trips_through_its_file_log() {
    use super::store::{FileLog, Watermark, WatermarkLog};

    let store = seeded();
    let mut owner = client(&store);
    attempt(&mut owner, OWNER).unwrap();
    let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    let named = NamedCheckpoint {
        slot: 2,
        session: (3 << 32) | 2,
        capture: 7,
        units: 9,
    };
    let published = ShardRecord {
        checkpoint: Some(named),
        ..*read.value()
    };
    owner.replace(&read, published).unwrap();
    let read = owner.read::<CoveragePage>(Key::Page(shard(), 1)).unwrap();
    let fenced = CoveragePage {
        fence: 5,
        ..read.value().clone()
    };
    owner.replace(&read, fenced).unwrap();
    let mark = owner.watermark().clone();
    let bytes = mark.encode();
    assert_eq!(
        bytes.len(),
        64 * (1 + 64),
        "a header and the 64-slot minimum"
    );
    assert_eq!(Watermark::decode(&bytes), Ok(mark.clone()));
    assert_eq!(
        Watermark::decode(&bytes[..bytes.len() - 1]),
        Err(CodecError::Length)
    );
    let mut extended = bytes.clone();
    extended.push(0);
    assert_eq!(Watermark::decode(&extended), Err(CodecError::Length));
    for at in [20, 64 + 20, 128 + 63, 64 * 64 + 1] {
        let mut flipped = bytes.clone();
        flipped[at] ^= 1;
        assert_eq!(
            Watermark::decode(&flipped),
            Err(CodecError::Checksum),
            "a bit flip at byte {at} of the header, a mark or a free slot"
        );
    }
    for slot in [1, 2, 64] {
        let mut zeroed = bytes.clone();
        zeroed[64 * slot..64 * (slot + 1)].fill(0);
        assert_eq!(
            Watermark::decode(&zeroed),
            Err(CodecError::Checksum),
            "zeroed slot {slot}"
        );
    }
    let mut freed = bytes.clone();
    freed.copy_within(64 * 3..64 * 4, 64 * 2);
    assert_eq!(
        Watermark::decode(&freed),
        Err(CodecError::Checksum),
        "a slot moved to another index"
    );

    let directory = fresh_directory("watermark");
    for path in [
        directory.join("mark.tmp"),
        directory.join(".tmp"),
        PathBuf::new(),
        directory.join(".."),
    ] {
        assert_eq!(
            FileLog::new(path.clone())
                .map(|_| ())
                .map_err(|error| error.kind()),
            Err(std::io::ErrorKind::InvalidInput),
            "{path:?}: a log never takes another log's staging name"
        );
    }
    for name in ["mark", "mark.next"] {
        let mut log = FileLog::new(directory.join(name)).unwrap();
        assert_eq!(
            log.load().map_err(|error| error.kind()),
            Err(std::io::ErrorKind::NotFound)
        );
        log.record(&Watermark::default()).unwrap();
        assert_eq!(log.load().unwrap(), Watermark::default());
        log.record(&mark).unwrap();
        assert_eq!(log.load().unwrap(), mark);
        let reopened =
            Client::open(store.clone(), FileLog::new(directory.join(name)).unwrap()).unwrap();
        assert_eq!(reopened.watermark(), &mark);
    }
    std::fs::write(directory.join("mark"), b"WMRK").unwrap();
    assert_eq!(
        FileLog::new(directory.join("mark"))
            .unwrap()
            .load()
            .map_err(|error| error.kind()),
        Err(std::io::ErrorKind::InvalidData)
    );
    std::fs::remove_dir_all(&directory).unwrap();
}

/// The file log raises a mark by rewriting its slot in place: across a fence of every page and repeated proofs the
/// file keeps its length until the marks outgrow its free slots, when the log replaces it whole with twice as many
/// slots as marks, and after every call the log loads the client's watermark. A raise before the log's first record
/// records the watermark whole, and a mark after a free slot refuses the load.
#[test]
fn file_log_raises_each_mark_in_place() {
    use super::store::{FileLog, Watermark, WatermarkLog};

    let directory = std::env::temp_dir().join(format!("watermark-raise-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("mark");
    FileLog::new(path.clone())
        .unwrap()
        .record(&Watermark::default())
        .unwrap();
    let store = Shared::new();
    let mut owner = Client::open(store.clone(), FileLog::new(path.clone()).unwrap()).unwrap();
    let held = |owner: &Client<Shared, FileLog>| {
        assert_eq!(
            &FileLog::new(path.clone()).unwrap().load().unwrap(),
            owner.watermark()
        );
        std::fs::metadata(&path).unwrap().len()
    };
    let pages = 100;
    let created = owner
        .create_shard(ShardRecord {
            pages: NonZeroU16::new(pages).unwrap(),
            ..record()
        })
        .unwrap();
    assert_eq!(held(&owner), 64 * (1 + 64), "the 64-slot minimum");
    for (at, page) in (0..pages).rev().enumerate() {
        let marks = at + 2;
        let slots = if marks <= 64 { 64 } else { 130 };
        let read = owner
            .read::<CoveragePage>(Key::Page(shard(), page))
            .unwrap();
        assert_eq!(held(&owner), 64 * (1 + slots), "{marks} marks");
        let fenced = CoveragePage {
            fence: 5,
            ..read.value().clone()
        };
        owner.replace(&read, fenced).unwrap();
        assert_eq!(held(&owner), 64 * (1 + slots), "{marks} marks");
    }
    let mut proved = created;
    for _ in 1..=3 {
        let next = *proved.value();
        proved = owner.replace(&proved, next).unwrap();
        assert_eq!(held(&owner), 64 * (1 + 130));
    }

    let mark = owner.watermark().clone();
    let fresh = directory.join("fresh");
    FileLog::new(fresh.clone())
        .unwrap()
        .raise(&mark, &[Key::Shard(shard())])
        .unwrap();
    assert_eq!(FileLog::new(fresh).unwrap().load().unwrap(), mark);

    let mut bytes = Watermark::encode(&mark);
    let free = Watermark::default().encode();
    bytes[64 * 2..64 * 3].copy_from_slice(&free[64 * 2..64 * 3]);
    assert_eq!(Watermark::decode(&bytes), Err(CodecError::Flag));
    std::fs::remove_dir_all(&directory).unwrap();
}

/// A bump rewrites one slot of the file log. A crash during it leaves that slot's previous or new bytes, and the
/// file holding either loads, the previous as the watermark before the bump and the new as the one after. A slot
/// holding bytes of both refuses the load.
#[test]
fn file_log_crash_leaves_previous_or_new_slot() {
    use std::os::unix::fs::MetadataExt;

    use super::store::{FileLog, Watermark, WatermarkLog};

    let directory = std::env::temp_dir().join(format!("watermark-crash-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("mark");
    FileLog::new(path.clone())
        .unwrap()
        .record(&Watermark::default())
        .unwrap();
    let store = seeded();
    let mut owner = Client::open(store.clone(), FileLog::new(path.clone()).unwrap()).unwrap();
    let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    let (previous, before) = (std::fs::read(&path).unwrap(), owner.watermark().clone());
    let inode = std::fs::metadata(&path).unwrap().ino();
    owner.bump(&read).unwrap();
    let (next, after) = (std::fs::read(&path).unwrap(), owner.watermark().clone());
    drop(owner);
    assert_ne!(before, after);
    assert_eq!(
        std::fs::metadata(&path).unwrap().ino(),
        inode,
        "the bump writes the recorded file in place"
    );
    let changed: Vec<usize> = (0..previous.len() / 64)
        .filter(|&slot| previous[64 * slot..][..64] != next[64 * slot..][..64])
        .collect();
    assert_eq!(changed, [1], "the bump rewrites the shard record's slot");
    let load = || FileLog::new(path.clone()).unwrap().load();
    for (bytes, expected) in [(&previous, &before), (&next, &after)] {
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(&load().unwrap(), expected);
    }
    let at = 64 * changed[0];
    let mut torn = previous.clone();
    torn[at..at + 32].copy_from_slice(&next[at..at + 32]);
    std::fs::write(&path, &torn).unwrap();
    assert_eq!(
        load().map_err(|error| error.kind()),
        Err(std::io::ErrorKind::InvalidData)
    );
    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn file_log_reload_keeps_the_file_for_in_place_raises() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::store::{FileLog, Watermark, WatermarkLog};

    let directory = fresh_directory("watermark-reload");
    let path = directory.join("mark");
    let reload = |path: &std::path::Path| {
        FileLog::new(path.to_path_buf())
            .unwrap()
            .reload()
            .map_err(|error| error.kind())
    };
    assert_eq!(reload(&path), Err(std::io::ErrorKind::NotFound));
    FileLog::new(path.clone())
        .unwrap()
        .record(&Watermark::default())
        .unwrap();
    let store = seeded();
    let read = Client::open(store.clone(), FileLog::new(path.clone()).unwrap())
        .unwrap()
        .read::<ShardRecord>(Key::Shard(shard()))
        .unwrap();
    let (held, inode) = (
        std::fs::read(&path).unwrap(),
        std::fs::metadata(&path).unwrap().ino(),
    );
    let mut owner = Client::open(store.clone(), FileLog::new(path.clone()).unwrap()).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), held);
    assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
    owner.bump(&read).unwrap();
    let next = std::fs::read(&path).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
    let changed: Vec<usize> = (0..held.len() / 64)
        .filter(|&slot| held[64 * slot..][..64] != next[64 * slot..][..64])
        .collect();
    assert_eq!(changed, [1], "the bump rewrites the shard record's slot");
    assert_eq!(
        &FileLog::new(path.clone()).unwrap().load().unwrap(),
        owner.watermark()
    );
    drop(owner);

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(reload(&path), Err(std::io::ErrorKind::InvalidData));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = directory.join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(reload(&link).is_err(), "a linked log");
    let fifo_path = directory.join("fifo");
    let fifo = std::ffi::CString::new(fifo_path.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: `fifo` is a NUL-terminated path that outlives the call.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert_eq!(reload(&fifo_path), Err(std::io::ErrorKind::InvalidData));
    assert_eq!(std::fs::read(&path).unwrap(), next);
    std::fs::remove_dir_all(&directory).unwrap();
}

/// `create_shard` refuses a shard record that does not encode before it creates any page: a spare equal to the
/// active volume returns [`StoreError::Codec`], no page commits, and a scheduled `Unavailable` arm waits for the
/// next read.
#[test]
fn create_shard_checks_its_record_first() {
    let store = Shared::new();
    let mut creator = client(&store);
    let onto_active = ShardRecord {
        spare: Some((record().active, Host::new(SPARE).unwrap())),
        ..record()
    };
    store.schedule(Arm::Unavailable);
    assert_eq!(
        creator.create_shard(onto_active).map(|_| ()),
        Err(StoreError::Codec(CodecError::Field))
    );
    assert_eq!(store.0.borrow().commit_count(&Key::Page(shard(), 0)), 0);
    assert_eq!(
        creator.read::<ShardRecord>(Key::Shard(shard())).map(|_| ()),
        Err(StoreError::Unavailable)
    );
}

/// A store holding, under `page`, bytes no page codec decodes at the first version and the empty page at the
/// second, as a page first written in a format this build does not read and then rewritten leaves it.
fn undecodable_then_empty(page: Key) -> Shared {
    let store = Shared::new();
    let garbage = Write::Create(vec![0xFF; 8]);
    let rewrite = Write::Exact {
        expect: Version::FIRST,
        value: CoveragePage::default().encode(),
    };
    for write in [garbage, rewrite] {
        assert!(matches!(
            store.0.borrow_mut().write(&page, &write),
            Outcome::Committed(_)
        ));
    }
    store
}

/// `create_shard`'s `# Errors` section gives [`StoreError::Regression`] when a page whose create is refused reads
/// below the mark the client holds for it. The check read that returns the page's first version under a mark at
/// the second is below the mark by its version alone, also when the older bytes do not decode: the call returns
/// [`Regression::Value`], withdraws the client and leaves the shard record uncreated.
#[test]
fn create_shard_regresses_on_a_page_below_its_held_mark_whose_bytes_do_not_decode() {
    let page = Key::Page(shard(), 0);
    let store = undecodable_then_empty(page);
    let mut host = client(&store);
    let read = host.read::<CoveragePage>(page).unwrap();
    assert_eq!(Some(read.version()), Version::FIRST.next());
    // The page's create takes the first arm and its check read the second.
    store.schedule(Arm::Pass);
    store.schedule(Arm::StaleCurrentRead);
    assert_eq!(
        host.create_shard(record()).map(drop),
        Err(StoreError::Regression(Regression::Value(page)))
    );
    withdrawn(&mut host);
    assert_eq!(store.0.borrow().commit_count(&Key::Shard(shard())), 0);
}

/// The sibling without the held mark: a client that never observed the page finds the same undecodable first
/// version as a page another writer changed, refuses on the page's condition and stays admitted.
#[test]
fn create_shard_refuses_an_undecodable_page_it_holds_no_mark_for() {
    let page = Key::Page(shard(), 0);
    let store = undecodable_then_empty(page);
    let mut host = client(&store);
    // The page's create takes the first arm and its check read the second.
    store.schedule(Arm::Pass);
    store.schedule(Arm::StaleCurrentRead);
    assert_eq!(
        host.create_shard(record()).map(drop),
        Err(StoreError::Refused(Refusal::Condition))
    );
    assert!(host.read::<CoveragePage>(page).is_ok());
    assert_eq!(store.0.borrow().commit_count(&Key::Shard(shard())), 0);
}

/// A store that, once it has refused a write of the record `garbled` names, returns that record at its current
/// version with bytes no record codec decodes: the store reused a version for another value.
struct GarblesAfterRefusal {
    store: Shared,
    garbled: Key,
    refused: bool,
}

impl Store for GarblesAfterRefusal {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        let item = self.store.read(key)?;
        if !self.refused || *key != self.garbled {
            return Ok(item);
        }
        Ok(item.map(|item| Item {
            version: item.version,
            value: vec![0xFF; 8],
        }))
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        let outcome = self.store.write(key, write);
        self.refused |= *key == self.garbled && matches!(outcome, Outcome::NotCommitted(_));
        outcome
    }

    fn namespace(&self) -> crate::failover::records::Namespace {
        self.store.namespace()
    }
}

/// Every mark the client holds was raised over bytes that decoded, so a check read that returns undecodable bytes
/// at the mark's own version holds another value at an equal version: `create_shard` returns
/// [`Regression::Value`], withdraws the client and leaves the shard record uncreated.
#[test]
fn create_shard_regresses_on_an_undecodable_page_at_its_held_mark() {
    let page = Key::Page(shard(), 0);
    let store = Shared::new();
    let garbling = GarblesAfterRefusal {
        store: store.clone(),
        garbled: page,
        refused: false,
    };
    let mut host = Client::open(garbling, MemLog::default()).unwrap();
    host.create(page, CoveragePage::default()).unwrap();
    assert_eq!(
        host.create_shard(record()).map(drop),
        Err(StoreError::Regression(Regression::Value(page)))
    );
    withdrawn(&mut host);
    assert_eq!(store.0.borrow().commit_count(&Key::Shard(shard())), 0);
}

/// The sibling without the held mark: a client that holds no mark for the page finds the undecodable bytes as a
/// page another writer changed, refuses on the page's condition and stays admitted.
#[test]
fn create_shard_refuses_an_undecodable_current_page_it_holds_no_mark_for() {
    let page = Key::Page(shard(), 0);
    let store = Shared::new();
    client(&store)
        .create(page, CoveragePage::default())
        .unwrap();
    let garbling = GarblesAfterRefusal {
        store: store.clone(),
        garbled: page,
        refused: false,
    };
    let mut host = Client::open(garbling, MemLog::default()).unwrap();
    assert_eq!(
        host.create_shard(record()).map(drop),
        Err(StoreError::Refused(Refusal::Condition))
    );
    assert_eq!(
        host.read::<ShardRecord>(Key::Shard(shard())).map(drop),
        Err(StoreError::Absent)
    );
}

/// `create_shard` passes a refused page create only for an empty page at [`Version::FIRST`]: a fenced page, a page
/// with an entry, and an empty page past its first version each refuse the call on the page's condition, and the
/// shard record is left uncreated.
#[test]
fn create_shard_refuses_a_written_page() {
    let written = [
        CoveragePage {
            fence: 1,
            ..CoveragePage::default()
        },
        CoveragePage {
            entries: vec![1],
            ..CoveragePage::default()
        },
    ];
    for page in written {
        let store = Shared::new();
        client(&store).create(Key::Page(shard(), 1), page).unwrap();
        assert_eq!(
            client(&store).create_shard(record()).map(drop),
            Err(StoreError::Refused(Refusal::Condition))
        );
        assert_eq!(store.0.borrow().commit_count(&Key::Shard(shard())), 0);
    }
    let store = Shared::new();
    let mut host = client(&store);
    let read = host
        .create(Key::Page(shard(), 1), CoveragePage::default())
        .unwrap();
    host.replace(&read, CoveragePage::default()).unwrap();
    assert_eq!(
        client(&store).create_shard(record()).map(drop),
        Err(StoreError::Refused(Refusal::Condition)),
        "an empty page past its first version was written"
    );
    assert_eq!(store.0.borrow().commit_count(&Key::Shard(shard())), 0);
}

/// A write arm scheduled on a read fails the test.
#[test]
#[should_panic(expected = "scheduled on a read")]
fn write_arm_on_a_read_panics() {
    let store = seeded();
    store.schedule(Arm::DoubleWin);
    let _ = client(&store).read::<ShardRecord>(Key::Shard(shard()));
}

/// A stale-read arm scheduled on a write fails the test.
#[test]
#[should_panic(expected = "scheduled on a write")]
fn stale_arm_on_a_write_panics() {
    let store = seeded();
    let mut owner = client(&store);
    let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    store.schedule(Arm::StaleRead);
    let _ = owner.bump(&read);
}

fn tenure_session(record: &ShardRecord, epoch: u32) -> u64 {
    crate::net::ownership::session_of(record.generation.get() as u32, epoch)
}

fn suffix(record: &ShardRecord, epoch: u32, start: u64, certified: u64, end: u64) -> Suffix {
    Suffix {
        session: tenure_session(record, epoch),
        start,
        certified,
        end,
    }
}

/// [`record`] after two attempts, naming a checkpoint at the cut and each attempt's suffix after it.
fn manifest() -> ShardRecord {
    let record = ShardRecord {
        attempts: 2,
        ..record()
    };
    ShardRecord {
        checkpoint: Some(NamedCheckpoint {
            slot: 1,
            session: tenure_session(&record, 2),
            capture: 1,
            units: 4,
        }),
        cut: 10,
        ancestry: Ancestry::new(&[
            suffix(&record, 2, 10, 14, 14),
            suffix(&record, 4, 14, 15, 16),
        ])
        .unwrap(),
        ..record
    }
}

/// Bumps `E` and appends the ancestry of `next` that the bumped tenure's session may write.
fn append_tenure(owner: &mut Client<Shared, MemLog>, next: &ShardRecord) {
    attempt(owner, OWNER).unwrap();
    let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    let held = read.value().ancestry.as_slice().len();
    let ancestry = Ancestry::new(&next.ancestry.as_slice()[..=held]).unwrap();
    let written = ShardRecord {
        checkpoint: next.checkpoint,
        cut: next.cut,
        ancestry,
        ..*read.value()
    };
    owner.replace(&read, written).unwrap();
}

/// A store holding [`manifest`], written by the owner's bumps, its publish and each tenure's append.
fn published() -> Shared {
    let store = seeded();
    let mut owner = client(&store);
    let manifest = manifest();
    append_tenure(&mut owner, &manifest);
    append_tenure(&mut owner, &manifest);
    assert_eq!(stored(&store).1, manifest);
    store
}

fn volume_with(pairs: Vec<crate::failover::records::RecordedPair>) -> VolumeRecord {
    use crate::failover::records::{AttachmentEvent, EventKind};
    VolumeRecord {
        volume: VolumeId::new("vol-0a").unwrap(),
        state: VolumeState::Active,
        source: CreationSource::Provisioned,
        lineage: Lineage::None,
        modification: None,
        layout: Layout {
            units: 64,
            slots: 3,
            slot_units: 2,
            entries: 41,
        },
        next: pairs.len().max(1) as u32,
        forced: false,
        fence: 0,
        events: (1..=pairs.len().max(1) as u64)
            .map(|host| AttachmentEvent {
                seq: host as u32 - 1,
                kind: EventKind::Attach,
                host: Host::new(host).unwrap(),
                era: crate::failover::records::ERA,
                instance: None,
            })
            .collect(),
        pairs,
    }
}

fn recorded(host: u64) -> crate::failover::records::RecordedPair {
    use crate::failover::identity::{Epoch, Exhid, Incarnation, Key as ReservationKey};
    crate::failover::records::RecordedPair {
        host: Host::new(host).unwrap(),
        pair: crate::failover::evidence::Pair {
            exhid: Exhid::new([host as u8; 16]).unwrap(),
            key: ReservationKey::new(
                Epoch::new(2).unwrap(),
                Incarnation::new(host as u32).unwrap(),
            ),
        },
        attach: host as u32 - 1,
    }
}

pub(crate) fn other_namespace() -> crate::failover::records::Namespace {
    crate::failover::records::Namespace::new([0x22; 16]).unwrap()
}

/// A shard record of another store instance withdraws the client that reads it: after another client's bump raises
/// the record, a client that read it before the store's namespace changed refuses its next read and keeps its
/// watermark, so the check runs before the watermark observes the raised value, and a client reopened over the same
/// log refuses the same way. A shard create under another namespace refuses before any request with no commit.
#[test]
fn a_record_of_another_store_instance_withdraws_the_client() {
    let key = Key::Shard(shard());
    let store = seeded();
    let log = MemLog::default();
    let mut reader = Client::open(store.clone(), log.clone()).unwrap();
    reader.read::<ShardRecord>(key).unwrap();
    let observed = reader.watermark().clone();
    assert_ne!(observed, Watermark::default());
    attempt(&mut client(&store), OWNER).unwrap();
    let commits = store.0.borrow().commit_count(&key);
    store.0.borrow_mut().namespace = other_namespace();
    assert_eq!(
        reader.read::<ShardRecord>(key).map(drop),
        Err(StoreError::Namespace),
        "a record of another store instance is read"
    );
    assert_eq!(
        reader.watermark(),
        &observed,
        "the refused value is observed"
    );
    withdrawn(&mut reader);
    let mut reopened = Client::open(store.clone(), log).unwrap();
    assert_eq!(
        reopened.read::<ShardRecord>(key).map(drop),
        Err(StoreError::Namespace),
        "a reopened client reads a record of another store instance"
    );
    assert_eq!(reopened.watermark(), &observed);
    withdrawn(&mut reopened);
    let mut provisioner = client(&store);
    store.schedule(Arm::Unavailable);
    assert_eq!(
        provisioner.create_shard(record()).map(drop),
        Err(StoreError::Namespace)
    );
    assert_eq!(provisioner.alarm(), super::store::Alarm::Namespace);
    withdrawn(&mut provisioner);
    unused_arm(&store);
    let mut creator = client(&store);
    store.schedule(Arm::Unavailable);
    assert_eq!(
        creator.create(key, record()).map(drop),
        Err(StoreError::Namespace)
    );
    assert_eq!(creator.alarm(), super::store::Alarm::Namespace);
    withdrawn(&mut creator);
    unused_arm(&store);
    assert_eq!(store.0.borrow().commit_count(&key), commits);
    store.0.borrow_mut().namespace = super::store::sim::NAMESPACE;
    client(&store).read::<ShardRecord>(key).unwrap();

    let receipt = crate::failover::loss::tests::receipt();
    let replacement = Key::Replacement(receipt.request.shard);
    client(&store).create(replacement, receipt.clone()).unwrap();
    store.0.borrow_mut().namespace = other_namespace();
    let mut reader = client(&store);
    assert_eq!(
        reader
            .read::<crate::failover::loss::Receipt>(replacement)
            .map(drop),
        Err(StoreError::Namespace),
        "a receipt of another store instance is read"
    );
    withdrawn(&mut reader);
    let mut creator = client(&store);
    store.schedule(Arm::Unavailable);
    assert_eq!(
        creator.create(replacement, receipt).map(drop),
        Err(StoreError::Namespace)
    );
    assert_eq!(creator.alarm(), super::store::Alarm::Namespace);
    withdrawn(&mut creator);
    unused_arm(&store);
    assert_eq!(store.0.borrow().commit_count(&replacement), 1);
}

/// An exact-version shard write from a read taken before the store's namespace changed refuses before any request
/// and withdraws the client. `Client::replace`, `Client::bump`, and `Client::flip` count as writes, as does removing
/// the spare in `Client::retire`.
#[test]
fn shard_writes_refuse_a_store_of_another_namespace() {
    use crate::failover::retire::{Retirement, Role, Target, Trigger};
    type Write =
        fn(&mut Client<Shared, MemLog>, &super::store::Read<ShardRecord>) -> Result<(), StoreError>;
    fn retire(
        client: &mut Client<Shared, MemLog>,
        read: &super::store::Read<ShardRecord>,
    ) -> Result<(), StoreError> {
        let (spare, _) = read.value().spare.unwrap();
        let target = Target::of(read.value());
        let request = Retirement::new(spare, Role::Spare, target, Trigger::Events).unwrap();
        client.retire(read, &request).map(drop)
    }
    let writes: [(&str, Write); 4] = [
        ("replace", |c, r| {
            c.replace(
                r,
                ShardRecord {
                    spare: None,
                    ..*r.value()
                },
            )
            .map(drop)
        }),
        ("bump", |c, r| c.bump(r).map(drop)),
        ("flip", |c, r| c.flip(r).map(drop)),
        ("retire the spare", retire),
    ];
    let key = Key::Shard(shard());
    for (what, write) in writes {
        let store = seeded();
        let mut owner = client(&store);
        let read = owner.read::<ShardRecord>(key).unwrap();
        let commits = store.0.borrow().commit_count(&key);
        store.0.borrow_mut().namespace = other_namespace();
        store.schedule(Arm::Unavailable);
        assert_eq!(
            write(&mut owner, &read),
            Err(StoreError::Namespace),
            "{what}"
        );
        assert_eq!(owner.alarm(), super::store::Alarm::Namespace, "{what}");
        unused_arm(&store);
        withdrawn(&mut owner);
        assert_eq!(store.0.borrow().commit_count(&key), commits, "{what}");
    }
}

/// Under each unknown-outcome arm, a bump, a consolidating publish and a certified raise leave the stored value
/// exactly the prior or the next value, leave the watermark unchanged, and the next bump keeps every manifest
/// field.
#[test]
fn unknown_writes_conserve_the_manifest() {
    type Write = fn(&ShardRecord) -> ShardRecord;
    let writes: [(&str, Write); 3] = [
        ("bump", |r| ShardRecord {
            attempts: r.attempts + 1,
            ..*r
        }),
        ("publish", |r| ShardRecord {
            checkpoint: Some(NamedCheckpoint {
                session: tenure_session(r, 4),
                capture: 0,
                ..r.checkpoint.unwrap()
            }),
            cut: 14,
            ancestry: Ancestry::new(&[suffix(r, 4, 14, 16, 16)]).unwrap(),
            ..*r
        }),
        ("certify", |r| ShardRecord {
            ancestry: Ancestry::new(&[suffix(r, 2, 10, 14, 14), suffix(r, 4, 14, 16, 18)]).unwrap(),
            ..*r
        }),
    ];
    for (name, write) in writes {
        for arm in UNKNOWN {
            let store = published();
            let mut owner = client(&store);
            let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
            let before = owner.watermark().clone();
            let (prior, next) = (*read.value(), write(read.value()));
            store.schedule(arm);
            let result = match name {
                "bump" => owner.bump(&read).map(drop),
                _ => owner.replace(&read, next).map(drop),
            };
            assert_eq!(result, Err(StoreError::Unknown), "{name} {arm:?}");
            assert_eq!(owner.watermark(), &before, "{name} {arm:?}");
            let (_, now) = stored(&store);
            let expected = if committed(arm) { next } else { prior };
            assert_eq!(now, expected, "{name} {arm:?}");
            let mut again = client(&store);
            let bumped = attempt(&mut again, OWNER).unwrap();
            let kept = bumped.committed().value();
            assert_eq!(
                ShardRecord {
                    attempts: expected.attempts,
                    ..*kept
                },
                expected,
                "{name} {arm:?}: the bump keeps every manifest field"
            );
        }
    }
}

/// A replace of a shard record over the simulated store.
type Replace = fn(
    &mut Client<Shared, MemLog>,
    &Read<ShardRecord>,
    ShardRecord,
) -> Result<Read<ShardRecord>, StoreError>;

/// Asserts that `replace` refuses `next` over `read` by `rule` before any request: the unavailable arm scheduled
/// before the call is still pending after it.
#[track_caller]
fn refuses_by_rule(
    store: &Shared,
    owner: &mut Client<Shared, MemLog>,
    read: &Read<ShardRecord>,
    next: ShardRecord,
    rule: SuccessorRule,
    replace: Replace,
) {
    store.schedule(Arm::Unavailable);
    assert_eq!(
        replace(owner, read, next).map(drop),
        Err(StoreError::Successor(rule)),
        "{next:?}"
    );
    unused_arm(store);
}

/// Negative control for the manifest successor rule: a replace without [`Record::succeeds`] issues its request for
/// a successor that lowers the cut under an unchanged checkpoint, so the call returns the scheduled unknown outcome
/// where the rule refuses `Checkpoint` before any request.
#[test]
#[should_panic(expected = "left: Err(Unknown)\n right: Err(Successor(Checkpoint))")]
fn negative_control_a_replace_without_the_successor_rule_issues_a_request_for_a_lowered_cut() {
    let store = published();
    let mut owner = client(&store);
    let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    let lowered = ShardRecord {
        cut: 9,
        ..*read.value()
    };
    refuses_by_rule(
        &store,
        &mut owner,
        &read,
        lowered,
        SuccessorRule::Checkpoint,
        Client::replace_without_successor_rule,
    );
}

/// Each manifest successor rule refuses through [`Client::replace`] before any request, with the commit count
/// unchanged.
#[test]
fn immutable_manifest_fields_refuse_before_any_request() {
    let key = Key::Shard(shard());
    let store = published();
    let mut owner = client(&store);
    let read = owner.read::<ShardRecord>(key).unwrap();
    let current = *read.value();
    let commits = store.0.borrow().commit_count(&key);
    let refused = [
        (
            ShardRecord {
                namespace: other_namespace(),
                ..current
            },
            SuccessorRule::Namespace,
        ),
        (ShardRecord { cut: 9, ..current }, SuccessorRule::Checkpoint),
        (
            ShardRecord { cut: 11, ..current },
            SuccessorRule::Checkpoint,
        ),
        (
            ShardRecord {
                checkpoint: None,
                cut: 0,
                ancestry: Ancestry::default(),
                ..current
            },
            SuccessorRule::Checkpoint,
        ),
        (
            ShardRecord {
                ancestry: Ancestry::default(),
                ..current
            },
            SuccessorRule::Ancestry,
        ),
        (
            ShardRecord {
                ancestry: Ancestry::new(&[
                    suffix(&current, 2, 10, 13, 14),
                    suffix(&current, 4, 14, 15, 16),
                ])
                .unwrap(),
                ..current
            },
            SuccessorRule::Ancestry,
        ),
        (
            ShardRecord {
                generation: ShardGeneration::new(4).unwrap(),
                ..current
            },
            SuccessorRule::Tenure,
        ),
        (
            ShardRecord {
                attempts: ATTEMPTS_MAX + 1,
                ..current
            },
            SuccessorRule::Tenure,
        ),
        (
            ShardRecord {
                attempts: 1 << 31,
                ..current
            },
            SuccessorRule::Tenure,
        ),
        (
            ShardRecord {
                attempts: u32::MAX,
                ..current
            },
            SuccessorRule::Tenure,
        ),
    ];
    for (next, rule) in refused {
        refuses_by_rule(&store, &mut owner, &read, next, rule, Client::replace);
    }
    let unencodable = ShardRecord {
        ancestry: Ancestry::new(&[
            suffix(&current, 2, 10, 14, 14),
            suffix(&current, 4, 14, 15, crate::storage::LSN_LIMIT + 2),
        ])
        .unwrap(),
        ..current
    };
    assert_eq!(
        owner.replace(&read, unencodable).map(drop),
        Err(StoreError::Codec(CodecError::Field)),
        "an end past LSN_LIMIT + 1 encodes bytes that refuse"
    );
    assert_eq!(store.0.borrow().commit_count(&key), commits);
    attempt(&mut owner, OWNER).unwrap();
    let bumped = owner.read::<ShardRecord>(key).unwrap();
    let commits = store.0.borrow().commit_count(&key);
    let current = *bumped.value();
    let overlapping = ShardRecord {
        checkpoint: Some(NamedCheckpoint {
            session: tenure_session(&current, 6),
            capture: 0,
            ..current.checkpoint.unwrap()
        }),
        cut: 16,
        ancestry: Ancestry::new(&[suffix(&current, 6, 15, 17, 17)]).unwrap(),
        ..current
    };
    store.schedule(Arm::Unavailable);
    assert_eq!(
        owner.replace(&bumped, overlapping).map(drop),
        Err(StoreError::Successor(SuccessorRule::Ancestry)),
        "a later session appended inside the history the cut drops"
    );
    unused_arm(&store);
    assert_eq!(store.0.borrow().commit_count(&key), commits);
    let later = ShardRecord {
        ancestry: Ancestry::new(&[suffix(&current, 6, 16, 17, 17)]).unwrap(),
        ..overlapping
    };
    let appended = owner.replace(&bumped, later).unwrap();
    let consolidated = ShardRecord {
        checkpoint: Some(NamedCheckpoint {
            capture: 1,
            ..later.checkpoint.unwrap()
        }),
        cut: 17,
        ancestry: Ancestry::default(),
        ..later
    };
    let consolidated = owner.replace(&appended, consolidated).unwrap();
    let inside = |record: &ShardRecord, epoch| ShardRecord {
        ancestry: Ancestry::new(&[suffix(record, epoch, 16, 18, 18)]).unwrap(),
        ..*record
    };
    let commits = store.0.borrow().commit_count(&key);
    store.schedule(Arm::Unavailable);
    assert_eq!(
        owner
            .replace(&consolidated, inside(consolidated.value(), 6))
            .map(drop),
        Err(StoreError::Successor(SuccessorRule::Ancestry)),
        "a continuation inside the history the checkpoint covers"
    );
    unused_arm(&store);
    attempt(&mut owner, OWNER).unwrap();
    let next_tenure = owner.read::<ShardRecord>(key).unwrap();
    store.schedule(Arm::Unavailable);
    assert_eq!(
        owner
            .replace(&next_tenure, inside(next_tenure.value(), 8))
            .map(drop),
        Err(StoreError::Successor(SuccessorRule::Ancestry)),
        "a later session inside the history the checkpoint covers"
    );
    unused_arm(&store);
    assert_eq!(store.0.borrow().commit_count(&key), commits + 1);
}

/// The maximal shard record, which names a standby, and the maximal volume record commit; a successor of the full
/// chain that drops its oldest suffix to append a fifth refuses with `Ancestry` before any request and keeps the
/// stored record; and a store whose limit is one byte short of the shard record rejects the write.
#[test]
fn records_at_their_caps_commit_under_the_item_limit() {
    use crate::failover::attachments::InstanceId;
    use crate::failover::records::{
        ERA, EventKind, MAX_CHAIN, MAX_EVENTS, MAX_REGISTRANTS, SHARD_MAX, VOLUME_MAX,
    };
    let named = ShardRecord {
        standby: Some(Host::new(SPARE).unwrap()),
        ..record()
    };
    let store = Shared::new();
    client(&store).create_shard(named).unwrap();
    let mut owner = client(&store);
    let current = ShardRecord {
        attempts: MAX_CHAIN as u32,
        ..named
    };
    let full: Vec<_> = (0..MAX_CHAIN as u64)
        .map(|at| {
            suffix(
                &current,
                2 + 2 * at as u32,
                10 + 4 * at,
                12 + 4 * at,
                14 + 4 * at,
            )
        })
        .collect();
    let next = ShardRecord {
        checkpoint: Some(NamedCheckpoint {
            slot: 1,
            session: tenure_session(&current, 2),
            capture: 1,
            units: 4,
        }),
        cut: 10,
        ancestry: Ancestry::new(&full).unwrap(),
        ..current
    };
    assert_eq!(next.encode().len(), SHARD_MAX);
    for _ in 0..MAX_CHAIN {
        append_tenure(&mut owner, &next);
    }
    assert_eq!(stored(&store).1, next);
    attempt(&mut owner, OWNER).unwrap();
    let at_cap = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    let (version, held) = stored(&store);
    let commits = store.0.borrow().commit_count(&Key::Shard(shard()));
    let mut five = full.clone();
    five.push(suffix(&current, 10, 26, 26, 28));
    let truncated = ShardRecord {
        ancestry: Ancestry::new(&five[1..]).unwrap(),
        ..held
    };
    store.schedule(Arm::Unavailable);
    assert_eq!(
        owner.replace(&at_cap, truncated).map(drop),
        Err(StoreError::Successor(SuccessorRule::Ancestry)),
        "a chain at its cap truncates its oldest suffix"
    );
    unused_arm(&store);
    assert_eq!(stored(&store), (version, held));
    assert_eq!(store.0.borrow().commit_count(&Key::Shard(shard())), commits);
    let mut volume = volume_with((1..=MAX_REGISTRANTS as u64).map(recorded).collect());
    for host in MAX_REGISTRANTS as u64 + 1..=MAX_EVENTS as u64 {
        volume.push(EventKind::Attach, Host::new(host).unwrap(), ERA);
    }
    for event in &mut volume.events {
        event.instance = InstanceId::new(&format!("i-{:017x}", event.host.get()));
    }
    assert_eq!(volume.encode().len(), VOLUME_MAX);
    let key = Key::Volume(volume.volume);
    owner.create(key, volume.clone()).unwrap();
    assert_eq!(
        *client(&store).read::<VolumeRecord>(key).unwrap().value(),
        volume
    );
    let narrow = Shared::new();
    narrow.0.borrow_mut().limit = SHARD_MAX - 1;
    assert_eq!(
        client(&narrow).create_shard(named).map(drop),
        Err(StoreError::Refused(Refusal::Rejected))
    );
}

/// Eight recorded pairs commit at the volume record's maximum; a ninth refuses through [`Client::replace`] before
/// any request, with zero commits past the create, and no pair leaves without a fence raise.
#[test]
fn recorded_pairs_at_their_cap_refuse_another_attach_and_keep_every_pair() {
    use crate::failover::records::MAX_REGISTRANTS;
    let store = Shared::new();
    let mut reconciler = client(&store);
    let volume = volume_with((1..=MAX_REGISTRANTS as u64).map(recorded).collect());
    let key = Key::Volume(volume.volume);
    let read = reconciler.create(key, volume.clone()).unwrap();
    let mut ninth = volume.clone();
    ninth.push(
        crate::failover::records::EventKind::Attach,
        Host::new(9).unwrap(),
        crate::failover::records::ERA,
    );
    ninth.pairs.push(recorded(9));
    store.schedule(Arm::Unavailable);
    assert_eq!(
        reconciler.replace(&read, ninth).map(drop),
        Err(StoreError::Codec(CodecError::Length))
    );
    unused_arm(&store);
    let mut dropped = volume.clone();
    dropped.pairs.remove(0);
    assert_eq!(
        reconciler.replace(&read, dropped.clone()).map(drop),
        Err(StoreError::Successor(SuccessorRule::Pairs))
    );
    assert_eq!(store.0.borrow().commit_count(&key), 1);
    dropped.fence = crate::net::ownership::session_of(1, 2);
    reconciler.replace(&read, dropped).unwrap();
    assert_eq!(store.0.borrow().commit_count(&key), 2);
}

/// A volume record holding an attachment event of an era below [`MIN_ERA`] fails [`Client::create`] and
/// [`Client::replace`] before any request, with the commit count unchanged, and one at the floor commits.
///
/// [`MIN_ERA`]: crate::failover::records::MIN_ERA
#[test]
fn an_event_below_the_era_floor_refuses_before_any_request() {
    use crate::failover::records::MIN_ERA;
    let store = Shared::new();
    let mut reconciler = client(&store);
    let mut old = volume_with(Vec::new());
    old.events[0].era = MIN_ERA - 1;
    let key = Key::Volume(old.volume);
    store.schedule(Arm::Unavailable);
    assert_eq!(
        reconciler.create(key, old.clone()).map(drop),
        Err(StoreError::Codec(CodecError::Field))
    );
    unused_arm(&store);
    old.events[0].era = MIN_ERA;
    let read = reconciler.create(key, old.clone()).unwrap();
    let mut next = old;
    next.push(next.events[0].kind, next.events[0].host, MIN_ERA - 1);
    store.schedule(Arm::Unavailable);
    assert_eq!(
        reconciler.replace(&read, next).map(drop),
        Err(StoreError::Codec(CodecError::Field))
    );
    unused_arm(&store);
    assert_eq!(store.0.borrow().commit_count(&key), 1);
}

/// A [`MemLog`] that counts the log writes made through it.
#[derive(Clone, Default)]
pub(crate) struct Counted {
    pub(crate) log: MemLog,
    pub(crate) writes: std::rc::Rc<std::cell::Cell<usize>>,
}

impl WatermarkLog for Counted {
    fn load(&self) -> std::io::Result<Watermark> {
        self.log.load()
    }

    fn record(&mut self, mark: &Watermark) -> std::io::Result<()> {
        self.writes.set(self.writes.get() + 1);
        self.log.record(mark)
    }
}

/// The keys of the shard's first `pages` coverage pages, after creating the shard with that many pages.
fn paged(store: &Shared, pages: u16) -> Vec<Key> {
    client(store)
        .create_shard(ShardRecord {
            pages: NonZeroU16::new(pages).unwrap(),
            ..record()
        })
        .unwrap();
    (0..pages).map(|page| Key::Page(shard(), page)).collect()
}

/// Raises `key`'s page to its next version through a client of its own, so another client's next read of it
/// raises its mark.
pub(crate) fn advance(store: &Shared, key: Key) {
    let mut writer = client(store);
    let read = writer.read::<CoveragePage>(key).unwrap();
    let next = CoveragePage {
        fence: read.value().fence + 1,
        ..read.value().clone()
    };
    writer.replace(&read, next).unwrap();
}

/// A batched read or write makes every mark its results raised durable with one log write before it returns, and a
/// batch that raises no mark writes nothing.
#[test]
fn batched_calls_make_their_raised_marks_durable_with_one_log_write() {
    let store = Shared::new();
    let keys = paged(&store, 4);
    let log = Counted::default();
    let mut owner = Client::open(store.clone(), log.clone()).unwrap();
    let opened = log.writes.get();
    let reads: Vec<_> = owner
        .read_all::<CoveragePage>(&keys)
        .into_iter()
        .map(Result::unwrap)
        .collect();
    assert_eq!(log.writes.get(), opened + 1, "four new marks, one write");
    assert_eq!(&log.log.held(), owner.watermark());
    assert!(
        owner
            .read_all::<CoveragePage>(&keys)
            .iter()
            .all(Result::is_ok)
    );
    assert_eq!(log.writes.get(), opened + 1, "unchanged marks, no write");
    let written = owner.replace_all(reads.iter().map(|read| {
        let next = CoveragePage {
            fence: 5,
            ..read.value().clone()
        };
        (read, next)
    }));
    assert!(written.iter().all(Result::is_ok));
    assert_eq!(log.writes.get(), opened + 2, "four raised marks, one write");
    assert_eq!(&log.log.held(), owner.watermark());
}

#[test]
fn a_single_call_makes_its_raised_mark_durable_with_one_log_write() {
    let store = seeded();
    let key = Key::Shard(shard());
    let log = Counted::default();
    let mut owner = Client::open(store.clone(), log.clone()).unwrap();
    let opened = log.writes.get();
    let read = owner.read::<ShardRecord>(key).unwrap();
    assert_eq!(log.writes.get(), opened + 1, "a new mark, one write");
    assert!(owner.read::<ShardRecord>(key).is_ok());
    assert_eq!(log.writes.get(), opened + 1, "an unchanged mark, no write");
    owner.bump(&read).unwrap();
    assert_eq!(log.writes.get(), opened + 2, "a raised mark, one write");
    assert_eq!(&log.log.held(), owner.watermark());
    let failing = MemLog::default();
    let mut reader = Client::open(store, failing.clone()).unwrap();
    let held = failing.held();
    failing.fail.set(true);
    assert_eq!(
        reader.read::<ShardRecord>(key).map(|_| ()),
        Err(StoreError::Log),
        "a raised mark the log fails to record returns no value"
    );
    assert_eq!(failing.held(), held);
    failing.fail.set(false);
    withdrawn(&mut reader);
}

/// A regression inside a batch withdraws the client: the results before it return with their raised marks durable,
/// and every later key returns [`StoreError::Withdrawn`].
#[test]
fn a_regression_inside_a_batch_keeps_the_earlier_results_and_withdraws() {
    let store = Shared::new();
    let keys = paged(&store, 3);
    advance(&store, keys[1]);
    let log = MemLog::default();
    let mut owner = Client::open(store.clone(), log.clone()).unwrap();
    owner.read::<CoveragePage>(keys[1]).unwrap();
    advance(&store, keys[0]);
    store.schedule(Arm::Pass);
    store.schedule(Arm::StaleCurrentRead);
    let results = owner.read_all::<CoveragePage>(&keys);
    assert_eq!(
        results[0].as_ref().map(|read| read.version()),
        Ok(Version::new(2).unwrap())
    );
    assert_eq!(
        results[1].as_ref().map(|_| ()),
        Err(&StoreError::Regression(Regression::Value(keys[1])))
    );
    assert_eq!(results[2].as_ref().map(|_| ()), Err(&StoreError::Withdrawn));
    assert_eq!(&log.held(), owner.watermark(), "page 0's raise is durable");
    assert_eq!(
        owner.alarm(),
        super::store::Alarm::Regression,
        "the batch's successful log write keeps the regression"
    );
    withdrawn(&mut owner);
}

/// A failed log write withdraws the client and fails every result of the batch that raised a mark, reads and
/// acknowledged writes alike; a result whose mark was already held returns its value.
#[test]
fn a_failed_log_write_fails_every_batched_result_that_raised_a_mark() {
    let store = Shared::new();
    let keys = paged(&store, 2);
    let log = MemLog::default();
    let mut owner = Client::open(store.clone(), log.clone()).unwrap();
    owner.read::<CoveragePage>(keys[1]).unwrap();
    advance(&store, keys[0]);
    let held = log.held();
    log.fail.set(true);
    let results = owner.read_all::<CoveragePage>(&keys);
    assert_eq!(results[0].as_ref().map(|_| ()), Err(&StoreError::Log));
    assert!(results[1].is_ok(), "page 1's mark was held");
    assert_eq!(log.held(), held);
    log.fail.set(false);
    withdrawn(&mut owner);

    let log = MemLog::default();
    let mut owner = Client::open(store.clone(), log.clone()).unwrap();
    let reads: Vec<_> = owner
        .read_all::<CoveragePage>(&keys)
        .into_iter()
        .map(Result::unwrap)
        .collect();
    log.fail.set(true);
    let written = owner.replace_all(reads.iter().map(|read| {
        let next = CoveragePage {
            fence: 9,
            ..read.value().clone()
        };
        (read, next)
    }));
    assert!(written.iter().all(|result| result == &Err(StoreError::Log)));
    for at in 0..2 {
        assert_eq!(page(&store, at).fence, 9, "page {at} committed");
    }
    log.fail.set(false);
    withdrawn(&mut owner);
}

/// A file-log raise of marks the file holds rewrites their slots in place with one sync; a crash during it leaves
/// each slot's previous or new bytes, and every such mix loads. A raise that brings several new marks replaces the
/// file whole, so the marks still fill a prefix of its slots.
#[test]
fn file_log_raises_held_marks_in_place_and_records_new_marks_whole() {
    use std::os::unix::fs::MetadataExt;

    use super::store::FileLog;

    let directory = fresh_directory("watermark-batch");
    let path = directory.join("mark");
    FileLog::new(path.clone())
        .unwrap()
        .record(&Watermark::default())
        .unwrap();
    let store = Shared::new();
    let keys = paged(&store, 4);
    let mut owner = Client::open(store.clone(), FileLog::new(path.clone()).unwrap()).unwrap();
    let inode = || std::fs::metadata(&path).unwrap().ino();
    let load = || FileLog::new(path.clone()).unwrap().load().unwrap();
    let opened = inode();
    let reads: Vec<_> = owner
        .read_all::<CoveragePage>(&keys)
        .into_iter()
        .map(Result::unwrap)
        .collect();
    assert_ne!(inode(), opened, "four new marks replace the file whole");
    assert_eq!(&load(), owner.watermark());
    let (previous, before, recorded) = (
        std::fs::read(&path).unwrap(),
        owner.watermark().clone(),
        inode(),
    );
    let written = owner.replace_all(reads.iter().map(|read| {
        let next = CoveragePage {
            fence: 5,
            ..read.value().clone()
        };
        (read, next)
    }));
    assert!(written.iter().all(Result::is_ok));
    assert_eq!(inode(), recorded, "held marks rise in place");
    let (next, after) = (std::fs::read(&path).unwrap(), owner.watermark().clone());
    drop(owner);
    let changed: Vec<usize> = (0..previous.len() / 64)
        .filter(|&slot| previous[64 * slot..][..64] != next[64 * slot..][..64])
        .collect();
    assert_eq!(changed.len(), keys.len(), "one slot per raised mark");
    for subset in 0..1usize << changed.len() {
        let mut bytes = previous.clone();
        for (bit, &slot) in changed.iter().enumerate() {
            if subset >> bit & 1 == 1 {
                bytes[64 * slot..][..64].copy_from_slice(&next[64 * slot..][..64]);
            }
        }
        std::fs::write(&path, &bytes).unwrap();
        let loaded = load();
        if subset == 0 {
            assert_eq!(loaded, before);
        } else if subset + 1 == 1 << changed.len() {
            assert_eq!(loaded, after);
        }
    }
    std::fs::remove_dir_all(&directory).unwrap();
}

/// A batch that reads one key twice and then fails its log write fails both results: the second read observed the
/// mark the first raised, and the log holds neither.
#[test]
fn a_failed_log_write_fails_every_result_of_a_raised_key_in_the_batch() {
    let store = Shared::new();
    let keys = paged(&store, 1);
    advance(&store, keys[0]);
    let log = MemLog::default();
    let mut owner = Client::open(store.clone(), log.clone()).unwrap();
    let held = log.held();
    log.fail.set(true);
    let results = owner.read_all::<CoveragePage>(&[keys[0], keys[0]]);
    assert_eq!(
        results
            .iter()
            .map(|result| result.as_ref().map(|_| ()))
            .collect::<Vec<_>>(),
        [Err(&StoreError::Log), Err(&StoreError::Log)]
    );
    assert_eq!(log.held(), held);
    log.fail.set(false);
    withdrawn(&mut owner);
}

/// A regression in the middle of a batched write withdraws the client: the earlier write returns with its mark
/// durable, the regressed write returns the regression, and the later write returns [`StoreError::Withdrawn`]
/// without reaching the store.
#[test]
fn a_regression_inside_a_write_batch_keeps_the_earlier_results_and_withdraws() {
    struct Misreports(Shared, Key);
    impl Store for Misreports {
        fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
            self.0.read(key)
        }
        fn write(&mut self, key: &Key, write: &Write) -> Outcome {
            match self.0.write(key, write) {
                Outcome::Committed(version) if *key == self.1 => {
                    Outcome::Committed(Version::new(version.get() + 1).unwrap())
                }
                outcome => outcome,
            }
        }
        fn namespace(&self) -> crate::failover::records::Namespace {
            self.0.namespace()
        }
    }
    let store = Shared::new();
    let keys = paged(&store, 3);
    let log = MemLog::default();
    let mut owner = Client::open(Misreports(store.clone(), keys[1]), log.clone()).unwrap();
    let reads: Vec<_> = owner
        .read_all::<CoveragePage>(&keys)
        .into_iter()
        .map(Result::unwrap)
        .collect();
    let written = owner.replace_all(reads.iter().map(|read| {
        let next = CoveragePage {
            fence: 5,
            ..read.value().clone()
        };
        (read, next)
    }));
    assert_eq!(
        written[0].as_ref().map(|read| read.version()),
        Ok(Version::new(2).unwrap())
    );
    assert_eq!(
        written[1].as_ref().map(|_| ()),
        Err(&StoreError::Regression(Regression::Value(keys[1])))
    );
    assert_eq!(written[2].as_ref().map(|_| ()), Err(&StoreError::Withdrawn));
    assert_eq!(
        page(&store, 2).fence,
        0,
        "page 2's write never reached the store"
    );
    assert_eq!(&log.held(), owner.watermark(), "page 0's raise is durable");
    assert_eq!(
        owner.alarm(),
        super::store::Alarm::Regression,
        "the batch's successful log write keeps the regression"
    );
}

/// The boundary of the in-place raise: two new marks record the file whole, and one new mark with held marks rises
/// in place, where every mix of the written slots' previous and new bytes loads.
#[test]
fn file_log_records_two_new_marks_whole_and_raises_one_new_mark_in_place() {
    use std::os::unix::fs::MetadataExt;

    use super::store::FileLog;

    let directory = fresh_directory("watermark-boundary");
    let path = directory.join("mark");
    FileLog::new(path.clone())
        .unwrap()
        .record(&Watermark::default())
        .unwrap();
    let store = Shared::new();
    let keys = paged(&store, 3);
    let mut owner = Client::open(store.clone(), FileLog::new(path.clone()).unwrap()).unwrap();
    let inode = || std::fs::metadata(&path).unwrap().ino();
    let load = || FileLog::new(path.clone()).unwrap().load().unwrap();
    let opened = inode();
    assert!(
        owner
            .read_all::<CoveragePage>(&keys[..2])
            .iter()
            .all(Result::is_ok)
    );
    assert_ne!(inode(), opened, "two new marks replace the file whole");
    assert_eq!(&load(), owner.watermark());
    advance(&store, keys[0]);
    advance(&store, keys[1]);
    let (previous, before, recorded) = (
        std::fs::read(&path).unwrap(),
        owner.watermark().clone(),
        inode(),
    );
    assert!(
        owner
            .read_all::<CoveragePage>(&keys)
            .iter()
            .all(Result::is_ok)
    );
    assert_eq!(
        inode(),
        recorded,
        "one new mark and two held marks rise in place"
    );
    let (next, after) = (std::fs::read(&path).unwrap(), owner.watermark().clone());
    drop(owner);
    let changed: Vec<usize> = (0..previous.len() / 64)
        .filter(|&slot| previous[64 * slot..][..64] != next[64 * slot..][..64])
        .collect();
    assert_eq!(changed.len(), 3, "two held slots and the next free slot");
    for subset in 0..1usize << changed.len() {
        let mut bytes = previous.clone();
        for (bit, &slot) in changed.iter().enumerate() {
            if subset >> bit & 1 == 1 {
                bytes[64 * slot..][..64].copy_from_slice(&next[64 * slot..][..64]);
            }
        }
        std::fs::write(&path, &bytes).unwrap();
        let loaded = load();
        if subset == 0 {
            assert_eq!(loaded, before);
        } else if subset + 1 == 1 << changed.len() {
            assert_eq!(loaded, after);
        }
    }
    std::fs::remove_dir_all(&directory).unwrap();
}

/// [`published`] over a record that names [`SPARE`] as its standby.
pub(crate) fn published_standby() -> Shared {
    let store = Shared::new();
    let named = ShardRecord {
        standby: Some(Host::new(SPARE).unwrap()),
        ..record()
    };
    client(&store).create_shard(named).unwrap();
    let mut owner = client(&store);
    append_tenure(&mut owner, &manifest());
    append_tenure(&mut owner, &manifest());
    store
}

/// The takeover of [`published_standby`]'s record by its standby [`SPARE`] under the read's own target.
fn take_over(
    client: &mut Client<Shared, MemLog>,
    read: &super::store::Read<ShardRecord>,
) -> Result<Bumped, StoreError> {
    client.take_over(
        read,
        crate::failover::retire::Target::of(read.value()),
        Host::new(SPARE).unwrap(),
    )
}

/// The takeover CAS writes the read record with the standby as owner, `E + 1` and no standby, and keeps the shard,
/// `g`, the active volume, the named checkpoint, its cut, the ancestry, the spare, `B`, `C_page` and the namespace;
/// its witness names the successor, so the session it activates is the successor's tenure `(g, 2E + 2)`. A second
/// takeover over the same read refuses on its condition, and the unknown arms adopt nothing and leave the stored
/// value at the prior or the next value.
#[test]
fn a_takeover_keeps_the_manifest_and_changes_only_owner_attempts_and_standby() {
    let store = published_standby();
    let mut successor = client(&store);
    let read = successor.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    let prior = *read.value();
    let taken = take_over(&mut successor, &read).unwrap();
    let expected = ShardRecord {
        owner: Host::new(SPARE).unwrap(),
        attempts: prior.attempts + 1,
        standby: None,
        ..prior
    };
    assert_eq!(*taken.committed().value(), expected);
    assert_eq!(stored(&store).1, expected);
    assert_eq!(
        (taken.owner(), taken.attempt()),
        (expected.owner, prior.attempts)
    );
    let session = crate::storage::Session::activate(taken).unwrap();
    assert_eq!(
        session.get(),
        tenure_session(&prior, 2 * prior.attempts + 2)
    );
    assert_eq!(
        session.target(),
        crate::failover::retire::Target::of(&expected)
    );
    assert_eq!(
        take_over(&mut client(&store), &read).map(drop),
        Err(StoreError::Refused(Refusal::Condition))
    );
    assert_eq!(stored(&store).1, expected);

    for arm in UNKNOWN {
        let store = published_standby();
        let mut successor = client(&store);
        let read = successor.read::<ShardRecord>(Key::Shard(shard())).unwrap();
        let prior = *read.value();
        let before = successor.watermark().clone();
        store.schedule(arm);
        assert_eq!(
            take_over(&mut successor, &read).map(drop),
            Err(StoreError::Unknown),
            "{arm:?}"
        );
        assert_eq!(successor.watermark(), &before, "{arm:?}");
        let next = ShardRecord {
            owner: Host::new(SPARE).unwrap(),
            attempts: prior.attempts + 1,
            standby: None,
            ..prior
        };
        assert_eq!(
            stored(&store).1,
            if committed(arm) { next } else { prior },
            "{arm:?}"
        );
    }
}

/// A takeover over a read taken before the owner published a newer checkpoint at the same `(g, owner, E)` and
/// standby refuses on its exact-version condition, and the store keeps the owner's record: the CAS conditions on the
/// version, not only on the target.
#[test]
fn a_takeover_on_a_read_before_a_publish_refuses() {
    let key = Key::Shard(shard());
    let store = published_standby();
    let mut successor = client(&store);
    let old = successor.read::<ShardRecord>(key).unwrap();
    let mut owner = client(&store);
    let read = owner.read::<ShardRecord>(key).unwrap();
    let named = read.value().checkpoint.unwrap();
    let republished = ShardRecord {
        checkpoint: Some(NamedCheckpoint {
            capture: named.capture + 1,
            ..named
        }),
        ..*read.value()
    };
    let committed = owner.replace(&read, republished).unwrap();
    assert_eq!(
        crate::failover::retire::Target::of(&republished),
        crate::failover::retire::Target::of(old.value())
    );
    assert_eq!(
        take_over(&mut successor, &old).map(drop),
        Err(StoreError::Refused(Refusal::Condition))
    );
    assert_eq!(stored(&store), (committed.version(), republished));
}

/// A takeover refuses before any request for a host the record does not name as standby, an attached owner included,
/// as `Stale(Target)`, and for a read of another store instance as `Namespace`, which withdraws the client, so its
/// next takeover refuses `Withdrawn`. The scheduled unavailable arms stay unused and the commit count is unchanged.
#[test]
fn a_takeover_refuses_an_unnamed_host_and_another_store_instance_before_any_request() {
    let key = Key::Shard(shard());
    let store = published_standby();
    let mut successor = client(&store);
    let read = successor.read::<ShardRecord>(key).unwrap();
    let target = crate::failover::retire::Target::of(read.value());
    let commits = store.0.borrow().commit_count(&key);
    for unnamed in [SPARE + 1, OWNER] {
        store.schedule(Arm::Unavailable);
        assert_eq!(
            successor
                .take_over(&read, target, Host::new(unnamed).unwrap())
                .map(drop),
            Err(StoreError::Stale(crate::failover::retire::Stale::Target)),
            "{unnamed}"
        );
        unused_arm(&store);
    }
    store.0.borrow_mut().namespace = other_namespace();
    store.schedule(Arm::Unavailable);
    assert_eq!(
        take_over(&mut successor, &read).map(drop),
        Err(StoreError::Namespace)
    );
    assert_eq!(successor.alarm(), super::store::Alarm::Namespace);
    unused_arm(&store);
    assert_eq!(
        take_over(&mut successor, &read).map(drop),
        Err(StoreError::Withdrawn)
    );
    assert_eq!(store.0.borrow().commit_count(&key), commits);
}

/// A withdrawn client refuses each tenure writer `Withdrawn` before its own refusal. In service, the same client and
/// read refuse each call on its own rule before any request: a bump at `ATTEMPTS_MAX` `AttemptsExhausted`; a takeover
/// there by a host the record does not name, and one by the named standby at an earlier target, `Stale(Target)`; a
/// designation of the owner `Stale(Target)`; a flip of the record, which names no spare, `Flip(NoSpare)`; and the
/// retirement of the active volume at an earlier target `Stale(Target)`. After the client is withdrawn, each call
/// returns `Withdrawn`. Each group leaves its scheduled unavailable arm unused and no write commits.
#[test]
fn a_withdrawn_client_refuses_each_tenure_writer_before_its_own_refusal() {
    use crate::failover::flip::FlipRefusal;
    use crate::failover::retire::{Retirement, Role, Stale, Target, Trigger};
    let key = Key::Shard(shard());
    let store = Shared::new();
    let (owner, spare) = (Host::new(OWNER).unwrap(), Host::new(SPARE).unwrap());
    client(&store)
        .create_shard(ShardRecord {
            attempts: ATTEMPTS_MAX,
            spare: None,
            standby: Some(spare),
            ..record()
        })
        .unwrap();
    let mut writer = client(&store);
    let read = writer.read::<ShardRecord>(key).unwrap();
    let target = Target::of(read.value());
    let earlier = Target {
        attempts: ATTEMPTS_MAX - 1,
        ..target
    };
    let unnamed = Host::new(SPARE + 1).unwrap();
    let retirement =
        Retirement::new(read.value().active, Role::Active, earlier, Trigger::Events).unwrap();
    let calls = |writer: &mut Client<Shared, MemLog>| {
        [
            writer.bump(&read).map(drop),
            writer.take_over(&read, target, unnamed).map(drop),
            writer.take_over(&read, earlier, spare).map(drop),
            writer.designate(&read, target, owner).map(drop),
            writer.flip(&read).map(drop),
            writer.retire(&read, &retirement).map(drop),
        ]
    };
    let commits = store.0.borrow().commit_count(&key);
    let stale = Err(StoreError::Stale(Stale::Target));
    store.schedule(Arm::Unavailable);
    assert_eq!(
        calls(&mut writer),
        [
            Err(StoreError::AttemptsExhausted),
            stale,
            stale,
            stale,
            Err(StoreError::Flip(FlipRefusal::NoSpare)),
            stale,
        ]
    );
    unused_arm(&store);
    store.0.borrow_mut().namespace = other_namespace();
    assert_eq!(
        writer.read::<ShardRecord>(key).map(drop),
        Err(StoreError::Namespace)
    );
    store.schedule(Arm::Unavailable);
    assert_eq!(calls(&mut writer), [Err(StoreError::Withdrawn); 6]);
    unused_arm(&store);
    assert_eq!(store.0.borrow().commit_count(&key), commits);
}

/// A takeover whose nomination target or standby the read does not hold refuses `Stale(Target)` before any
/// request: another `E`, owner or `g`, a record without a standby and one naming another standby. A read at
/// `ATTEMPTS_MAX` refuses `AttemptsExhausted`. The scheduled unavailable arm stays unused and no write commits.
#[test]
fn a_takeover_refuses_a_record_that_moved_before_any_request() {
    use crate::failover::retire::{Stale, Target};
    let key = Key::Shard(shard());
    let spare = Host::new(SPARE).unwrap();
    let prior = ShardRecord {
        attempts: 2,
        standby: Some(spare),
        ..record()
    };
    let stale = StoreError::Stale(Stale::Target);
    let other = Host::new(13).unwrap();
    let cases = [
        (
            Target {
                attempts: 3,
                ..Target::of(&prior)
            },
            prior,
            stale,
        ),
        (
            Target {
                owner: other,
                ..Target::of(&prior)
            },
            prior,
            stale,
        ),
        (
            Target {
                generation: ShardGeneration::new(prior.generation.get() + 1).unwrap(),
                ..Target::of(&prior)
            },
            prior,
            stale,
        ),
        (
            Target::of(&prior),
            ShardRecord {
                standby: None,
                ..prior
            },
            stale,
        ),
        (
            Target::of(&prior),
            ShardRecord {
                standby: Some(other),
                ..prior
            },
            stale,
        ),
        (
            Target {
                attempts: ATTEMPTS_MAX,
                ..Target::of(&prior)
            },
            ShardRecord {
                attempts: ATTEMPTS_MAX,
                ..prior
            },
            StoreError::AttemptsExhausted,
        ),
    ];
    for (target, value, error) in cases {
        let store = Shared::new();
        client(&store).create_shard(value).unwrap();
        let mut successor = client(&store);
        let read = successor.read::<ShardRecord>(key).unwrap();
        let commits = store.0.borrow().commit_count(&key);
        store.schedule(Arm::Unavailable);
        assert_eq!(
            successor.take_over(&read, target, spare).map(drop),
            Err(error),
            "{target:?} {value:?}"
        );
        unused_arm(&store);
        assert_eq!(store.0.borrow().commit_count(&key), commits);
    }
}

/// The designation write names the standby by an exact-version write that keeps every other field, the tenure,
/// checkpoint and ancestry included, and makes a takeover CAS over the earlier read fail its condition. A read
/// holding another target, `E = 0`, or the designated host as owner refuses `Stale(Target)` before any request, the
/// scheduled unavailable arm unused and no write committed.
#[test]
fn a_designation_changes_only_the_standby_and_refuses_a_moved_record_before_any_request() {
    use crate::failover::retire::{Stale, Target};
    let key = Key::Shard(shard());
    let (spare, other) = (Host::new(SPARE).unwrap(), Host::new(13).unwrap());
    let store = published_standby();
    let mut successor = client(&store);
    let earlier = successor.read::<ShardRecord>(key).unwrap();
    let prior = *earlier.value();
    let designated = client(&store)
        .designate(&earlier, Target::of(&prior), other)
        .unwrap();
    let expected = ShardRecord {
        standby: Some(other),
        ..prior
    };
    assert_eq!(
        (*designated.value(), stored(&store).1),
        (expected, expected)
    );
    assert_eq!(
        take_over(&mut successor, &earlier).map(drop),
        Err(StoreError::Refused(Refusal::Condition))
    );
    assert_eq!(stored(&store).1, expected);

    let prior = ShardRecord {
        attempts: 2,
        ..record()
    };
    let cases = [
        (
            Target {
                attempts: 3,
                ..Target::of(&prior)
            },
            prior,
            spare,
        ),
        (
            Target::of(&record()),
            ShardRecord {
                attempts: 0,
                ..prior
            },
            spare,
        ),
        (Target::of(&prior), prior, prior.owner),
    ];
    for (target, value, standby) in cases {
        let store = Shared::new();
        client(&store).create_shard(value).unwrap();
        let mut reconciler = client(&store);
        let read = reconciler.read::<ShardRecord>(key).unwrap();
        let commits = store.0.borrow().commit_count(&key);
        store.schedule(Arm::Unavailable);
        assert_eq!(
            reconciler.designate(&read, target, standby).map(drop),
            Err(StoreError::Stale(Stale::Target)),
            "{target:?} {value:?}"
        );
        unused_arm(&store);
        assert_eq!(store.0.borrow().commit_count(&key), commits);
    }
}

/// Moves `storage`'s readiness from `Detached` to `Loading`, as an attach gate's pass does.
pub(crate) fn start_loading(
    storage: &crate::storage::Storage<crate::storage::test_platform::TestPlatform>,
) -> Result<crate::storage::Readiness, crate::storage::ReadinessError> {
    storage
        .readiness
        .apply(crate::storage::readiness::Event::Attach)
}
/// An in-place raise into a log file the path no longer names reports `NotFound` and withdraws the client while
/// the file keeps a link under another name, and a later load of the path reads none of the raise: nothing once
/// the file was renamed aside, the replacing file's watermark once another log's file took the path, after a rename
/// aside or over a file that keeps a second link.
#[test]
fn file_log_raise_into_a_file_the_path_no_longer_names_reports_not_found() {
    use super::store::FileLog;

    let directory = fresh_directory("watermark-renamed-aside");
    let (path, other, aside) = (
        directory.join("mark"),
        directory.join("other"),
        directory.join("aside"),
    );
    let load = || {
        FileLog::new(path.clone())
            .unwrap()
            .load()
            .map_err(|error| error.kind())
    };
    let replace = || {
        FileLog::new(other.clone())
            .unwrap()
            .record(&Watermark::default())
            .unwrap();
        std::fs::rename(&other, &path).unwrap();
    };
    let mut unreported = Vec::new();
    for case in [
        "renamed aside",
        "renamed aside and replaced",
        "linked and replaced",
    ] {
        FileLog::new(path.clone())
            .unwrap()
            .record(&Watermark::default())
            .unwrap();
        let store = seeded();
        let mut owner = Client::open(store.clone(), FileLog::new(path.clone()).unwrap()).unwrap();
        let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
        let held = owner.watermark().clone();
        assert_eq!(
            load().as_ref(),
            Ok(&held),
            "{case}: the read's raise is durable"
        );
        let survivor = match case {
            "renamed aside" => {
                std::fs::rename(&path, &aside).unwrap();
                Err(std::io::ErrorKind::NotFound)
            }
            "renamed aside and replaced" => {
                std::fs::rename(&path, &aside).unwrap();
                replace();
                Ok(Watermark::default())
            }
            _ => {
                std::fs::hard_link(&path, &aside).unwrap();
                replace();
                Ok(Watermark::default())
            }
        };
        let raised = owner.bump(&read).map(|_| ());
        if raised != Err(StoreError::Log) {
            unreported.push((case, raised, load()));
            std::fs::remove_file(&path).ok();
            std::fs::remove_file(&aside).unwrap();
            continue;
        }
        withdrawn(&mut owner);
        assert_eq!(load(), survivor, "{case}: the path holds none of the raise");
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&aside).unwrap();
    }
    std::fs::remove_dir_all(&directory).unwrap();
    assert!(
        unreported.is_empty(),
        "raises into a file the path no longer names, with the path's later load: {unreported:?}"
    );
}

/// `create_shard` checks a page whose create is refused against the mark the client holds for it. A fence raise
/// that was acknowledged and never applied leaves the empty first version under a mark at the second, and a
/// fenced create that was lost and then made empty by another client leaves the first version under a mark of
/// another value: each returns [`Regression::Value`], withdraws the client and leaves the shard record uncreated.
#[test]
fn create_shard_regresses_on_a_page_below_its_held_mark() {
    let page = Key::Page(shard(), 1);
    let fenced = CoveragePage {
        fence: 1,
        ..CoveragePage::default()
    };

    let store = Shared::new();
    let mut host = client(&store);
    let read = host.create(page, CoveragePage::default()).unwrap();
    store.schedule(Arm::LostWrite);
    host.replace(&read, fenced.clone()).unwrap();
    let lost_raise = (store, host);

    let store = Shared::new();
    let mut host = client(&store);
    store.schedule(Arm::LostWrite);
    host.create(page, fenced).unwrap();
    client(&store)
        .create(page, CoveragePage::default())
        .unwrap();
    let reused_version = (store, host);

    for (store, mut host) in [lost_raise, reused_version] {
        assert_eq!(
            store.0.borrow().current(&page).map(|item| item.version),
            Some(Version::FIRST)
        );
        assert_eq!(
            host.create_shard(record()).map(drop),
            Err(StoreError::Regression(Regression::Value(page)))
        );
        withdrawn(&mut host);
        assert_eq!(store.0.borrow().commit_count(&Key::Shard(shard())), 0);
    }
}

/// The sibling without the fault: a client that holds the mark of the empty page it created at the first version
/// passes that page, and `create_shard` creates the shard record.
#[test]
fn create_shard_passes_an_empty_page_at_its_held_mark() {
    let page = Key::Page(shard(), 1);
    let store = Shared::new();
    let mut host = client(&store);
    host.create(page, CoveragePage::default()).unwrap();
    let created = host.create_shard(record()).unwrap();
    assert_eq!(created.version(), Version::FIRST);
    assert_eq!(store.0.borrow().commit_count(&page), 1);
    assert!(host.read::<CoveragePage>(page).is_ok());
}

/// A store that loses the record `lost` names once it has refused a write of it: the write is judged against the
/// record the store holds, and every later read finds the record absent.
struct LosesAfterRefusal {
    store: Shared,
    lost: Key,
    refused: bool,
}

impl Store for LosesAfterRefusal {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        if self.refused && *key == self.lost {
            return Ok(None);
        }
        self.store.read(key)
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        let outcome = self.store.write(key, write);
        self.refused |= *key == self.lost && matches!(outcome, Outcome::NotCommitted(_));
        outcome
    }

    fn namespace(&self) -> crate::failover::records::Namespace {
        self.store.namespace()
    }
}

/// `create_shard` judges the page it finds after a refused create against the mark the client holds, as a read
/// does: a page the client holds a mark for that the check read finds absent is a lost record, so the call returns
/// [`Regression::Value`], withdraws the client and leaves the shard record uncreated, as [`Client::read`] of the same
/// absent page does.
#[test]
fn create_shard_regresses_on_an_absent_page_it_holds_a_mark_for() {
    let page = Key::Page(shard(), 1);
    for through_read in [true, false] {
        let store = Shared::new();
        let losing = LosesAfterRefusal {
            store: store.clone(),
            lost: page,
            refused: false,
        };
        let mut host = Client::open(losing, MemLog::default()).unwrap();
        host.create(page, CoveragePage::default()).unwrap();
        let result = if through_read {
            assert_eq!(
                host.create(page, CoveragePage::default()).map(drop),
                Err(StoreError::Refused(Refusal::Condition))
            );
            host.read::<CoveragePage>(page).map(drop)
        } else {
            host.create_shard(record()).map(drop)
        };
        assert_eq!(
            result,
            Err(StoreError::Regression(Regression::Value(page))),
            "through a read: {through_read}"
        );
        withdrawn(&mut host);
        assert_eq!(store.0.borrow().commit_count(&Key::Shard(shard())), 0);
    }
}

/// A page create that succeeds found the page absent. Pages are never deleted, so for a page the client holds a
/// mark for that absence is a lost record, the same loss `create_shard` reports when its create is refused and the
/// check read finds the page absent. Here the client's log holds the mark of a page it created, and the store it
/// reopens over holds nothing. `create_shard` returns [`Regression::Value`], withdraws the client and creates no
/// shard record. The same call on a store that kept the page creates the shard.
#[test]
fn create_shard_regresses_on_a_page_it_holds_a_mark_for_that_its_create_finds_absent() {
    let page = Key::Page(shard(), 1);
    for lost in [false, true] {
        let (store, log) = (Shared::new(), MemLog::default());
        Client::open(store.clone(), log.clone())
            .unwrap()
            .create(page, CoveragePage::default())
            .unwrap();
        let store = if lost { Shared::new() } else { store };
        let mut host = Client::open(store.clone(), log).unwrap();
        let created = host.create_shard(record()).map(drop);
        if lost {
            assert_eq!(
                created,
                Err(StoreError::Regression(Regression::Value(page))),
                "a shard created over a page the store lost"
            );
            withdrawn(&mut host);
            assert_eq!(store.0.borrow().commit_count(&Key::Shard(shard())), 0);
        } else {
            assert_eq!(created, Ok(()), "premise: the store kept the page");
        }
    }
}

/// The sibling without the held mark: a client that holds no mark for the page its refused create names, and then
/// finds absent, has seen no record lost, so `create_shard` refuses on the page's condition and the client stays
/// admitted.
#[test]
fn create_shard_refuses_an_absent_page_it_holds_no_mark_for() {
    let page = Key::Page(shard(), 1);
    let store = Shared::new();
    client(&store)
        .create(page, CoveragePage::default())
        .unwrap();
    let losing = LosesAfterRefusal {
        store: store.clone(),
        lost: page,
        refused: false,
    };
    let mut host = Client::open(losing, MemLog::default()).unwrap();
    assert_eq!(
        host.create_shard(record()).map(drop),
        Err(StoreError::Refused(Refusal::Condition))
    );
    assert_eq!(
        host.read::<ShardRecord>(Key::Shard(shard())).map(drop),
        Err(StoreError::Absent)
    );
}

/// A [`MemLog`] whose record unwinds while `unwind` is set, leaving the held watermark.
#[derive(Clone, Default)]
struct Unwinding {
    log: MemLog,
    unwind: std::rc::Rc<std::cell::Cell<bool>>,
}

impl WatermarkLog for Unwinding {
    fn load(&self) -> std::io::Result<Watermark> {
        self.log.load()
    }

    fn record(&mut self, mark: &Watermark) -> std::io::Result<()> {
        assert!(!self.unwind.get(), "the log write unwinds");
        self.log.record(mark)
    }
}

/// A log write that unwinds is a failed record of the raised watermark (WATERMARK): once the caller catches the
/// unwind, the client is withdrawn, so no later call returns a value whose mark the log does not hold.
#[test]
fn a_log_write_that_unwinds_withdraws_the_client() {
    let store = seeded();
    let key = Key::Shard(shard());
    let mut writer = client(&store);
    let first = writer.read::<ShardRecord>(key).unwrap();
    writer.bump(&first).unwrap();
    let log = Unwinding::default();
    let mut reader = Client::open(store.clone(), log.clone()).unwrap();
    let held = log.log.held();
    log.unwind.set(true);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        reader.read::<ShardRecord>(key).map(|read| read.version())
    }));
    log.unwind.set(false);
    assert!(unwound.is_err(), "the raise unwound");
    assert_eq!(log.log.held(), held, "the unwound write recorded nothing");
    assert_eq!(reader.alarm(), super::store::Alarm::Log);
    assert_eq!(
        reader.read::<ShardRecord>(key).map(|read| read.version()),
        Err(StoreError::Withdrawn),
        "the log does not hold the mark the unwound read raised"
    );
}

/// A batched log write that unwinds withdraws the client as a single one does (WATERMARK): after the caller catches
/// the unwind out of [`Client::read_all`], a later read refuses.
#[test]
fn a_batched_log_write_that_unwinds_withdraws_the_client() {
    let store = seeded();
    let key = Key::Shard(shard());
    let log = Unwinding::default();
    let mut reader = Client::open(store.clone(), log.clone()).unwrap();
    log.unwind.set(true);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        reader.read_all::<ShardRecord>(&[key]).len()
    }));
    log.unwind.set(false);
    assert!(unwound.is_err(), "the raise unwound");
    assert_eq!(reader.alarm(), super::store::Alarm::Log);
    assert_eq!(
        reader.read::<ShardRecord>(key).map(|read| read.version()),
        Err(StoreError::Withdrawn),
        "the log does not hold the mark the unwound batch raised"
    );
}

/// A batch log write that unwinds after a later element regressed keeps `Regression`, the first cause: page 0's
/// read raises a mark, page 1 reads below its mark, and the log write that would record page 0's mark unwinds.
#[test]
fn a_batched_log_write_that_unwinds_after_a_regression_keeps_the_first_cause() {
    let store = Shared::new();
    let keys = paged(&store, 2);
    advance(&store, keys[1]);
    let log = Unwinding::default();
    let mut owner = Client::open(store.clone(), log.clone()).unwrap();
    owner.read::<CoveragePage>(keys[1]).unwrap();
    advance(&store, keys[0]);
    let held = log.log.held();
    store.schedule(Arm::Pass);
    store.schedule(Arm::StaleCurrentRead);
    log.unwind.set(true);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        owner.read_all::<CoveragePage>(&keys).len()
    }));
    log.unwind.set(false);
    let payload = unwound.expect_err("the log write unwound");
    assert_eq!(
        payload.downcast_ref::<&str>(),
        Some(&"the log write unwinds")
    );
    assert_eq!(log.log.held(), held, "the unwound write recorded nothing");
    assert_eq!(owner.alarm(), super::store::Alarm::Regression);
    assert_eq!(owner.outcomes(), super::store::Tally::default());
    withdrawn(&mut owner);
}

/// A [`Shared`] store whose read or write of the key `unwind` holds unwinds before it reaches the store.
struct UnwindingStore {
    store: Shared,
    unwind: std::rc::Rc<std::cell::Cell<Option<Key>>>,
}

impl Store for UnwindingStore {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        assert!(self.unwind.get() != Some(*key), "the store read unwinds");
        self.store.read(key)
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        assert!(self.unwind.get() != Some(*key), "the store write unwinds");
        self.store.write(key, write)
    }

    fn namespace(&self) -> crate::failover::records::Namespace {
        self.store.namespace()
    }
}

/// `Client`: "Whenever a call returns while the client is not withdrawn, the watermark it checks results against
/// equals the one its log holds." A batch read whose first read raised a mark in memory and whose second read
/// unwinds never reaches its log write, so once the caller catches the unwind the client is withdrawn and no later
/// call returns the first key's value. The sibling reads the same batch with no unwind: the log holds the raised
/// mark and the later read returns the value.
#[test]
fn a_batch_read_that_unwinds_after_a_raise_withdraws_the_client() {
    for unwinds in [false, true] {
        let store = Shared::new();
        let keys = paged(&store, 2);
        let log = MemLog::default();
        let unwind = std::rc::Rc::new(std::cell::Cell::new(None));
        let reading = UnwindingStore {
            store: store.clone(),
            unwind: std::rc::Rc::clone(&unwind),
        };
        let mut reader = Client::open(reading, log.clone()).unwrap();
        let held = log.held();
        unwind.set(unwinds.then_some(keys[1]));
        let batch = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            reader.read_all::<CoveragePage>(&keys).len()
        }));
        unwind.set(None);
        let later = reader.read::<CoveragePage>(keys[0]).map(drop);
        if !unwinds {
            assert_eq!(batch.ok(), Some(2), "the batch returned");
            assert_ne!(log.held(), held, "the log holds the raised marks");
            assert_eq!(later, Ok(()));
            assert_eq!(reader.alarm(), super::store::Alarm::Clear);
            continue;
        }
        assert!(batch.is_err(), "the second read unwound");
        assert_eq!(log.held(), held, "the unwound batch recorded nothing");
        assert_eq!(reader.alarm(), super::store::Alarm::Log);
        assert_eq!(
            later,
            Err(StoreError::Withdrawn),
            "the log does not hold the mark the unwound batch raised"
        );
    }
}

/// The batch write as the batch read above (WATERMARK): the first acknowledged write raised its mark in memory and
/// the second write unwinds before the log write, so the client is withdrawn once the caller catches the unwind.
/// The sibling writes the same batch with no unwind and the log holds both raised marks.
#[test]
fn a_batch_write_that_unwinds_after_a_raise_withdraws_the_client() {
    for unwinds in [false, true] {
        let store = Shared::new();
        let keys = paged(&store, 2);
        let log = MemLog::default();
        let unwind = std::rc::Rc::new(std::cell::Cell::new(None));
        let writing = UnwindingStore {
            store: store.clone(),
            unwind: std::rc::Rc::clone(&unwind),
        };
        let mut writer = Client::open(writing, log.clone()).unwrap();
        let reads: Vec<_> = writer
            .read_all::<CoveragePage>(&keys)
            .into_iter()
            .map(Result::unwrap)
            .collect();
        let held = log.held();
        unwind.set(unwinds.then_some(keys[1]));
        let batch = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let writes = reads.iter().map(|read| {
                let next = CoveragePage {
                    fence: 5,
                    ..read.value().clone()
                };
                (read, next)
            });
            writer.replace_all(writes).len()
        }));
        unwind.set(None);
        let later = writer.read::<CoveragePage>(keys[0]).map(drop);
        if !unwinds {
            assert_eq!(batch.ok(), Some(2), "the batch returned");
            assert_ne!(log.held(), held, "the log holds the raised marks");
            assert_eq!(later, Ok(()));
            assert_eq!(writer.alarm(), super::store::Alarm::Clear);
            continue;
        }
        assert!(batch.is_err(), "the second write unwound");
        assert_eq!(log.held(), held, "the unwound batch recorded nothing");
        assert_eq!(writer.alarm(), super::store::Alarm::Log);
        assert_eq!(
            later,
            Err(StoreError::Withdrawn),
            "the log does not hold the mark the unwound batch raised"
        );
    }
}

#[test]
fn the_store_double_counts_every_request_of_a_key_whatever_its_arm_and_outcome() {
    let store = seeded();
    let (key, other) = (Key::Shard(shard()), Key::Page(shard(), 0));
    let requests = |key: &Key| store.0.borrow().requests(key);
    let (before, untouched) = (requests(&key), requests(&other));
    let mut raw = store.clone();
    assert!(Store::read(&mut raw, &key).is_ok());
    store.schedule(Arm::Unavailable);
    assert!(Store::read(&mut raw, &key).is_err());
    let item = store.0.borrow().current(&key).cloned().unwrap();
    let stale = Write::Exact {
        expect: item.version.next().unwrap(),
        value: item.value.clone(),
    };
    let refused = Outcome::NotCommitted(Refusal::Condition);
    assert_eq!(Store::write(&mut raw, &key, &stale), refused);
    let exact = Write::Exact {
        expect: item.version,
        value: item.value,
    };
    store.schedule(Arm::Hold);
    assert_eq!(Store::write(&mut raw, &key, &exact), Outcome::Unknown);
    assert_eq!(store.release().len(), 1);
    assert_eq!(requests(&key), before + 4, "a released write counts once");
    assert_eq!(requests(&other), untouched);
    assert_eq!(store.0.borrow().versions(&key).len(), 2);
}

/// A write arm passes the actor's reads by and takes its next write, behind any request arm the actor holds.
#[test]
fn a_faulted_write_arm_passes_reads_by_and_takes_its_actors_next_write() {
    use super::store::sim::{ActorFaults, Faulted};
    let store = seeded();
    let faults = std::rc::Rc::new(std::cell::RefCell::new(ActorFaults::default()));
    let reach = |actor| Faulted {
        inner: store.clone(),
        actor,
        faults: faults.clone(),
    };
    let key = Key::Shard(shard());
    let rewrite = || {
        let item = store.0.borrow().current(&key).cloned().unwrap();
        Write::Exact {
            expect: item.version,
            value: item.value,
        }
    };
    faults
        .borrow_mut()
        .arm_write(1, Arm::Timeout { commit: true });
    assert!(
        reach(1).read(&key).is_ok(),
        "a timeout arm on a read would panic"
    );
    assert_eq!(faults.borrow().queued(1), 1);
    assert!(matches!(
        reach(2).write(&key, &rewrite()),
        Outcome::Committed(_)
    ));
    assert_eq!(reach(1).write(&key, &rewrite()), Outcome::Unknown);
    assert_eq!(faults.borrow().queued(1), 0);
    assert_eq!(
        store.0.borrow().versions(&key).len(),
        3,
        "the unknown write committed"
    );

    faults.borrow_mut().arm(3, Arm::Unavailable);
    faults
        .borrow_mut()
        .arm_write(3, Arm::Timeout { commit: false });
    assert_eq!(
        reach(3).read(&key),
        Err(Unavailable),
        "the request arm goes first"
    );
    assert_eq!(reach(3).write(&key, &rewrite()), Outcome::Unknown);
    assert_eq!(
        store.0.borrow().versions(&key).len(),
        3,
        "the lost write did not commit"
    );
}

/// A `BeforeWrite` hook under a faulted actor runs another actor's requests before the faulted write: they take
/// no arm of the first actor's, which its own write then takes.
#[test]
fn a_hooked_store_keeps_an_actors_arm_from_the_requests_its_hook_makes() {
    use super::store::sim::{ActorFaults, Faulted, Point, hooked};
    let store = seeded();
    let key = Key::Shard(shard());
    let rewrite = move |store: &super::store::sim::Shared| {
        let item = store.0.borrow().current(&key).cloned().unwrap();
        Write::Exact {
            expect: item.version,
            value: item.value,
        }
    };
    let faults = std::rc::Rc::new(std::cell::RefCell::new(ActorFaults::default()));
    let other = store.clone();
    let then = move || {
        let mut b = other.clone();
        assert!(b.read(&key).is_ok(), "B's read takes no arm");
        let write = rewrite(&other);
        assert!(
            matches!(b.write(&key, &write), Outcome::Committed(_)),
            "B commits"
        );
    };
    let mut a = Faulted {
        inner: hooked(&store, key, Point::BeforeWrite, then),
        actor: 1,
        faults: faults.clone(),
    };
    faults
        .borrow_mut()
        .arm_write(1, Arm::Timeout { commit: false });
    let stale = rewrite(&store);
    let versions = store.0.borrow().versions(&key).len();
    assert_eq!(a.write(&key, &stale), Outcome::Unknown);
    assert_eq!(
        store.0.borrow().versions(&key).len(),
        versions + 1,
        "B's write alone committed"
    );
    assert_eq!(faults.borrow().queued(1), 0);
}

/// Each actor's arms reach only that actor's requests, and an outage window stops the actor's requests before the
/// store counts them. `Faulted` withdraws the scheduled arm when `AsReconciler` denies the write before it reaches
/// the store.
#[test]
fn a_faulted_store_scopes_each_arm_and_outage_to_its_own_actor() {
    use super::store::sim::{ActorFaults, AsReconciler, Faulted};
    let store = seeded();
    let faults = std::rc::Rc::new(std::cell::RefCell::new(ActorFaults::default()));
    let reach = |actor| Faulted {
        inner: store.clone(),
        actor,
        faults: faults.clone(),
    };
    let key = Key::Shard(shard());
    let requests = || store.0.borrow().requests(&key);
    let rewrite = || {
        let item = store.0.borrow().current(&key).cloned().unwrap();
        Write::Exact {
            expect: item.version,
            value: item.value,
        }
    };
    faults.borrow_mut().arm(1, Arm::Timeout { commit: false });
    assert_eq!(
        reach(2).write(&key, &rewrite()),
        Outcome::Committed(Version::FIRST.next().unwrap())
    );
    assert_eq!(faults.borrow().queued(1), 1);
    assert_eq!(reach(1).write(&key, &rewrite()), Outcome::Unknown);
    assert_eq!(
        (
            faults.borrow().queued(1),
            store.0.borrow().versions(&key).len()
        ),
        (0, 2)
    );

    faults.borrow_mut().outage(Some(3), 10, 20);
    faults.borrow_mut().set_now(10);
    let before = requests();
    assert_eq!(reach(3).read(&key), Err(Unavailable));
    assert_eq!(reach(3).write(&key, &rewrite()), Outcome::Unknown);
    assert_eq!(
        requests(),
        before,
        "an outage stops the request before the store"
    );
    assert!(reach(4).read(&key).is_ok());
    faults.borrow_mut().set_now(20);
    assert!(reach(3).read(&key).is_ok());

    faults.borrow_mut().arm(5, Arm::Unavailable);
    let mut reconciler = Faulted {
        inner: AsReconciler(store.clone()),
        actor: 5,
        faults: faults.clone(),
    };
    let page = Key::Page(shard(), 0);
    let denied = Outcome::NotCommitted(Refusal::Denied);
    assert_eq!(reconciler.write(&page, &Write::Create(Vec::new())), denied);
    assert!(
        store.clone().read(&key).is_ok(),
        "the denied write's arm was withdrawn"
    );
}
