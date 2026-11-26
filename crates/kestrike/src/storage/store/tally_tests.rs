//! The store client's outcome tally and watermark alarm (MONITORS-OBSERVE): each tallied outcome counts once under
//! its record class, and the alarm keeps the first cause that withdrew the client.

use super::sim::{Arm, MemLog, Recorder, Shared};
use super::{
    Alarm, Client, Key, Read, RecordClass, Regression, Store, StoreError, Tallied, Tally, Tracked,
    WatermarkLog,
};
use crate::failover::records::{CoveragePage, NamedCheckpoint, ShardRecord, VolumeId};
use crate::storage::store_tests::{advance, client, other_namespace, seeded, shard, withdrawn};

/// The nonzero cells of `tally` in [`RecordClass::ALL`] then [`Tallied::ALL`] order.
pub(crate) fn nonzero(tally: Tally) -> Vec<(RecordClass, Tallied, u64)> {
    let mut cells = Vec::new();
    for class in RecordClass::ALL {
        for outcome in Tallied::ALL {
            let count = tally.get(class, outcome);
            if count != 0 {
                cells.push((class, outcome, count));
            }
        }
    }
    cells
}

fn page(at: u16) -> Key {
    Key::Page(shard(), at)
}

/// Reads `key` as `R` through `client` with the store's next read unavailable.
#[track_caller]
fn unavailable<R: Tracked, S: Store, L: WatermarkLog>(
    client: &mut Client<S, L>,
    store: &Shared,
    key: Key,
) {
    store.schedule(Arm::Unavailable);
    assert_eq!(
        client.read::<R>(key).map(drop),
        Err(StoreError::Unavailable),
        "{key:?}"
    );
}

/// A record the store double returns below the client's mark, at a lower version and `(g, E)`, reads `Regression`
/// and withdraws the client; the clean twin, the same version returned again, reads `Clear`.
#[test]
fn a_record_below_the_watermark_reads_regression() {
    let key = Key::Shard(shard());
    let store = seeded();
    let mut owner = client(&store);
    let read = owner.read::<ShardRecord>(key).unwrap();
    owner.bump(&read).unwrap();
    let again = owner.read::<ShardRecord>(key).unwrap();
    assert_eq!(again.version(), read.version().next().unwrap());
    assert_eq!(owner.alarm(), Alarm::Clear, "the same version read again");
    assert_eq!(owner.outcomes(), Tally::default());

    store.schedule(Arm::StaleCurrentRead);
    assert_eq!(
        owner.read::<ShardRecord>(key).map(drop),
        Err(StoreError::Regression(Regression::Value(key)))
    );
    assert_eq!(owner.alarm(), Alarm::Regression);
    withdrawn(&mut owner);
    assert_eq!(owner.alarm(), Alarm::Regression);
    assert_eq!(
        owner.outcomes(),
        Tally::default(),
        "a regression tallies nothing"
    );
}

/// A shard record whose checkpoint falls below the one adopted at its generation reads `Checkpoint`, while the
/// stale writer whose write committed at a version other than the one after its condition's reads `Regression`. The
/// clean twin, the adopted checkpoint read again by the client that adopted it, reads `Clear`.
#[test]
fn a_record_below_the_adopted_checkpoint_reads_checkpoint() {
    let key = Key::Shard(shard());
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
    assert_eq!(a.alarm(), Alarm::Clear);
    let adopted = a.read::<ShardRecord>(key).unwrap();
    assert_eq!(adopted.value().checkpoint, Some(named));
    assert_eq!(a.alarm(), Alarm::Clear, "the adopted checkpoint read again");
    store.schedule(Arm::DoubleWin);
    let stale = *read_b.value();
    assert_eq!(
        b.replace(&read_b, stale).map(drop),
        Err(StoreError::Regression(Regression::Value(key)))
    );
    assert_eq!(b.alarm(), Alarm::Regression);
    assert_eq!(
        a.read::<ShardRecord>(key).map(drop),
        Err(StoreError::Regression(Regression::Checkpoint(shard())))
    );
    assert_eq!(a.alarm(), Alarm::Checkpoint);
    withdrawn(&mut a);
}

/// A bump whose watermark log write fails reads `Log` and tallies one log failure under the shard class; the read
/// before it, whose log write succeeded, leaves the alarm `Clear` and the tally zero.
#[test]
fn a_failed_log_write_reads_log_and_is_tallied() {
    let key = Key::Shard(shard());
    let store = seeded();
    let log = MemLog::default();
    let mut owner = Client::open(store.clone(), log.clone()).unwrap();
    let read = owner.read::<ShardRecord>(key).unwrap();
    assert_eq!(
        (owner.alarm(), owner.outcomes()),
        (Alarm::Clear, Tally::default())
    );
    log.fail.set(true);
    assert_eq!(owner.bump(&read).map(drop), Err(StoreError::Log));
    assert_eq!(owner.alarm(), Alarm::Log);
    assert_eq!(
        nonzero(owner.outcomes()),
        [(RecordClass::Shard, Tallied::Log, 1)]
    );
    log.fail.set(false);
    withdrawn(&mut owner);
    assert_eq!(owner.alarm(), Alarm::Log);
}

/// A shard record that names another store instance reads `Namespace`, and the withdrawn client issues no further
/// request.
#[test]
fn a_record_of_another_store_instance_reads_namespace_and_stops_requests() {
    let key = Key::Shard(shard());
    let store = seeded();
    let recorder = Recorder::new(&store);
    let mut reader = Client::open(recorder.clone(), MemLog::default()).unwrap();
    reader.read::<ShardRecord>(key).unwrap();
    assert_eq!(reader.alarm(), Alarm::Clear);
    store.0.borrow_mut().namespace = other_namespace();
    assert_eq!(
        reader.read::<ShardRecord>(key).map(drop),
        Err(StoreError::Namespace)
    );
    assert_eq!(reader.alarm(), Alarm::Namespace);
    assert_eq!(
        recorder.take(),
        [
            super::sim::Request::Read(key),
            super::sim::Request::Read(key)
        ],
        "the recorder saw the clean read and the read that withdrew the client"
    );
    assert_eq!(
        reader.read::<ShardRecord>(key).map(drop),
        Err(StoreError::Withdrawn)
    );
    assert_eq!(
        reader.read::<CoveragePage>(page(0)).map(drop),
        Err(StoreError::Withdrawn)
    );
    assert_eq!(
        recorder.take(),
        Vec::new(),
        "a withdrawn client issued a request"
    );
    assert_eq!(reader.alarm(), Alarm::Namespace);
}

/// A regression followed by a failed log write keeps `Regression`, the first cause: a batch reads page 0, which
/// raises a mark, then page 1 below its mark, and the log write that would record page 0's mark fails. Page 0's
/// result becomes `Log` and counts once; the regression counts nothing.
#[test]
fn a_regression_then_a_log_failure_keeps_the_first_cause() {
    let store = seeded();
    let log = MemLog::default();
    let mut owner = Client::open(store.clone(), log.clone()).unwrap();
    let read = owner.read::<CoveragePage>(page(1)).unwrap();
    advance(&store, page(1));
    let raised = owner.read::<CoveragePage>(page(1)).unwrap();
    assert!(raised.version() > read.version());
    log.fail.set(true);
    store.schedule(Arm::Pass);
    store.schedule(Arm::StaleCurrentRead);
    let results: Vec<Result<(), StoreError>> = owner
        .read_all::<CoveragePage>(&[page(0), page(1)])
        .into_iter()
        .map(|result| result.map(drop))
        .collect();
    assert_eq!(
        results,
        vec![
            Err(StoreError::Log),
            Err(StoreError::Regression(Regression::Value(page(1))))
        ]
    );
    assert_eq!(owner.alarm(), Alarm::Regression);
    assert_eq!(
        nonzero(owner.outcomes()),
        [(RecordClass::Page, Tallied::Log, 1)]
    );
}

/// An unknown coverage page write, an unavailable volume read and a refused exact-version shard write each count
/// once under their own class and outcome, and none withdraws the client. The unknown page write counts under the
/// page class alone, so it reads as no shard-record write.
#[test]
fn each_tallied_outcome_counts_once_under_its_record_class() {
    let store = seeded();
    let mut owner = client(&store);
    let read: Read<CoveragePage> = owner.read(page(0)).unwrap();
    store.schedule(Arm::Timeout { commit: false });
    let fenced = CoveragePage {
        fence: 9,
        ..read.value().clone()
    };
    assert_eq!(
        owner.replace(&read, fenced).map(drop),
        Err(StoreError::Unknown)
    );
    assert_eq!(
        nonzero(owner.outcomes()),
        [(RecordClass::Page, Tallied::Unknown, 1)]
    );

    unavailable::<crate::failover::records::VolumeRecord, _, _>(
        &mut owner,
        &store,
        Key::Volume(VolumeId::new("vol-0a").unwrap()),
    );

    let key = Key::Shard(shard());
    let stale = owner.read::<ShardRecord>(key).unwrap();
    let mut other = client(&store);
    let current = other.read::<ShardRecord>(key).unwrap();
    other.bump(&current).unwrap();
    assert_eq!(
        owner.bump(&stale).map(drop),
        Err(StoreError::Refused(super::Refusal::Condition))
    );
    assert_eq!(
        nonzero(owner.outcomes()),
        [
            (RecordClass::Shard, Tallied::Refused, 1),
            (RecordClass::Volume, Tallied::Unavailable, 1),
            (RecordClass::Page, Tallied::Unknown, 1),
        ]
    );
    for (outcome, total) in [
        (Tallied::Unknown, 1),
        (Tallied::Unavailable, 1),
        (Tallied::Refused, 1),
        (Tallied::Log, 0),
    ] {
        assert_eq!(owner.outcomes().total(outcome), total, "{outcome:?}");
    }
    assert_eq!(owner.alarm(), Alarm::Clear);
    assert!(
        owner.read::<ShardRecord>(key).is_ok(),
        "the client stays admitted"
    );
    assert_eq!(other.outcomes(), Tally::default());
}

/// A client whose tally holds an unknown, an unavailable and a refused outcome under the shard and page classes and
/// an unavailable read under the volume, census and receipt classes, built by failing calls that change no record
/// and no watermark mark. A run over it starts from the records and watermark a fresh client's run starts from. A
/// log failure withdraws the client, so the log cells stay zero and the alarm stays `Clear`.
pub(crate) fn preloaded<S: super::Store, L: WatermarkLog>(
    client: &mut Client<S, L>,
    store: &Shared,
) {
    let fresh = client.watermark().clone();
    let unrelated = crate::net::ownership::Shard::new(shard().get() + 1).unwrap();
    let other = ShardRecord {
        shard: unrelated,
        ..crate::storage::store_tests::record()
    };
    unavailable::<ShardRecord, _, _>(client, store, Key::Shard(unrelated));
    store.schedule(Arm::Timeout { commit: false });
    assert_eq!(
        client.create(Key::Shard(unrelated), other).map(drop),
        Err(StoreError::Unknown)
    );
    store.schedule(Arm::Timeout { commit: false });
    assert_eq!(
        client
            .create(Key::Page(unrelated, 0), CoveragePage::default())
            .map(drop),
        Err(StoreError::Unknown)
    );
    let current = crate::storage::store_tests::stored(store).1;
    assert_eq!(
        client.create(Key::Shard(shard()), current).map(drop),
        Err(StoreError::Refused(super::Refusal::Condition))
    );
    assert_eq!(
        client
            .create(Key::Page(shard(), 0), CoveragePage::default())
            .map(drop),
        Err(StoreError::Refused(super::Refusal::Condition))
    );
    unavailable::<CoveragePage, _, _>(client, store, Key::Page(unrelated, 0));
    unavailable::<crate::failover::standbys::Census, _, _>(
        client,
        store,
        Key::Standbys(crate::failover::standbys::Zone(3)),
    );
    unavailable::<crate::failover::loss::Receipt, _, _>(client, store, Key::Replacement(unrelated));
    unavailable::<crate::failover::records::VolumeRecord, _, _>(
        client,
        store,
        Key::Volume(VolumeId::new("vol-0f").unwrap()),
    );
    assert_eq!(
        nonzero(client.outcomes()),
        [
            (RecordClass::Shard, Tallied::Unknown, 1),
            (RecordClass::Shard, Tallied::Unavailable, 1),
            (RecordClass::Shard, Tallied::Refused, 1),
            (RecordClass::Volume, Tallied::Unavailable, 1),
            (RecordClass::Page, Tallied::Unknown, 1),
            (RecordClass::Page, Tallied::Unavailable, 1),
            (RecordClass::Page, Tallied::Refused, 1),
            (RecordClass::Census, Tallied::Unavailable, 1),
            (RecordClass::Receipt, Tallied::Unavailable, 1),
        ]
    );
    assert_eq!(client.alarm(), Alarm::Clear);
    assert_eq!(client.watermark(), &fresh, "the preload raised no mark");
}

/// An unavailable read of the standby census and of a replacement receipt counts under the census and receipt
/// classes, so each key variant reads its own class, and the unavailable total sums the two classes.
#[test]
fn census_and_receipt_reads_count_under_their_own_classes() {
    let store = seeded();
    let mut reader = client(&store);
    let zone = crate::failover::standbys::Zone(3);
    unavailable::<crate::failover::standbys::Census, _, _>(
        &mut reader,
        &store,
        Key::Standbys(zone),
    );
    assert_eq!(
        nonzero(reader.outcomes()),
        [(RecordClass::Census, Tallied::Unavailable, 1)],
        "the census read counts under the census class"
    );
    unavailable::<crate::failover::loss::Receipt, _, _>(
        &mut reader,
        &store,
        Key::Replacement(shard()),
    );
    assert_eq!(
        nonzero(reader.outcomes()),
        [
            (RecordClass::Census, Tallied::Unavailable, 1),
            (RecordClass::Receipt, Tallied::Unavailable, 1),
        ]
    );
    assert_eq!(reader.outcomes().total(Tallied::Unavailable), 2);
}

/// A rerun of [`Client::create_shard`] after an unknown page create counts each store request: the refused page
/// create counts as refused though the call continues over the empty page it finds, and an unavailable reread of a
/// refused page counts as unavailable under the page class. A create over a page another writer changed counts its
/// refused page create once, though the call returns that refusal.
#[test]
fn a_create_shard_rerun_counts_its_refused_page_create_and_its_page_reread() {
    let store = Shared::new();
    let mut creator = client(&store);
    store.schedule(Arm::Timeout { commit: true });
    assert_eq!(
        creator
            .create_shard(crate::storage::store_tests::record())
            .map(drop),
        Err(StoreError::Unknown)
    );
    assert!(
        creator
            .create_shard(crate::storage::store_tests::record())
            .is_ok()
    );
    assert_eq!(
        nonzero(creator.outcomes()),
        [
            (RecordClass::Page, Tallied::Unknown, 1),
            (RecordClass::Page, Tallied::Refused, 1),
        ]
    );
    let store = Shared::new();
    let mut creator = client(&store);
    store.schedule(Arm::Timeout { commit: true });
    assert_eq!(
        creator
            .create_shard(crate::storage::store_tests::record())
            .map(drop),
        Err(StoreError::Unknown)
    );
    store.schedule(Arm::Pass);
    store.schedule(Arm::Unavailable);
    assert_eq!(
        creator
            .create_shard(crate::storage::store_tests::record())
            .map(drop),
        Err(StoreError::Unavailable)
    );
    assert_eq!(
        nonzero(creator.outcomes()),
        [
            (RecordClass::Page, Tallied::Unknown, 1),
            (RecordClass::Page, Tallied::Unavailable, 1),
            (RecordClass::Page, Tallied::Refused, 1),
        ]
    );

    let store = seeded();
    advance(&store, page(0));
    let mut creator = client(&store);
    assert_eq!(
        creator
            .create_shard(crate::storage::store_tests::record())
            .map(drop),
        Err(StoreError::Refused(super::Refusal::Condition))
    );
    assert_eq!(
        nonzero(creator.outcomes()),
        [(RecordClass::Page, Tallied::Refused, 1)]
    );
}

/// A batch whose one log write fails counts `Log` once for each result the failure turned into `Log`: two pages
/// that each raised a mark count two, and so does one page that raised a mark read twice beside a page whose mark
/// was already durable, which returns its value and counts nothing.
#[test]
fn a_failed_batch_log_write_counts_each_result_it_turned_into_log() {
    let store = seeded();
    let log = MemLog::default();
    let mut owner = Client::open(store.clone(), log.clone()).unwrap();
    owner.read::<CoveragePage>(page(1)).unwrap();
    log.fail.set(true);
    let results: Vec<Result<(), StoreError>> = owner
        .read_all::<CoveragePage>(&[page(0), page(0), page(1)])
        .into_iter()
        .map(|result| result.map(drop))
        .collect();
    assert_eq!(
        results,
        vec![Err(StoreError::Log), Err(StoreError::Log), Ok(())]
    );
    assert_eq!(
        nonzero(owner.outcomes()),
        [(RecordClass::Page, Tallied::Log, 2)]
    );
    assert_eq!(owner.alarm(), Alarm::Log);

    let store = seeded();
    let log = MemLog::default();
    let mut owner = Client::open(store.clone(), log.clone()).unwrap();
    log.fail.set(true);
    let results: Vec<Result<(), StoreError>> = owner
        .read_all::<CoveragePage>(&[page(0), page(1)])
        .into_iter()
        .map(|result| result.map(drop))
        .collect();
    assert_eq!(results, vec![Err(StoreError::Log), Err(StoreError::Log)]);
    assert_eq!(
        nonzero(owner.outcomes()),
        [(RecordClass::Page, Tallied::Log, 2)]
    );
    assert_eq!(owner.alarm(), Alarm::Log);
}

/// A batch whose caller's iterator unwinds after an earlier pair regressed keeps `Regression`, the first cause: the
/// stale pair's double win commits past the version after its condition's, and the unwind that follows leaves the
/// earlier cause in place.
#[test]
fn a_batch_that_unwinds_after_a_regression_keeps_the_first_cause() {
    let store = seeded();
    let mut owner = client(&store);
    let read = owner.read::<CoveragePage>(page(0)).unwrap();
    let next = CoveragePage {
        fence: 9,
        ..read.value().clone()
    };
    advance(&store, page(0));
    store.schedule(Arm::DoubleWin);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        owner
            .replace_all(
                [Some((&read, next))]
                    .into_iter()
                    .chain([None])
                    .map(|pair| pair.unwrap_or_else(|| panic!("the caller's iterator unwinds"))),
            )
            .len()
    }));
    let payload = unwound.expect_err("the iterator unwound");
    assert_eq!(
        payload.downcast_ref::<&str>(),
        Some(&"the caller's iterator unwinds")
    );
    assert_eq!(owner.alarm(), Alarm::Regression);
    withdrawn(&mut owner);
}

/// A tally whose outcomes span the record classes, with a different total for each: the preload's two unknown
/// creates (shard and page), five unavailable reads (shard, volume, page, census and receipt) and two refused creates
/// (shard and page), one more refused shard create, and last one failed watermark log write, which withdraws the
/// client.
pub(crate) fn distinct() -> Tally {
    let store = seeded();
    let log = MemLog::default();
    let mut owner = Client::open(store.clone(), log.clone()).unwrap();
    preloaded(&mut owner, &store);
    let current = crate::storage::store_tests::stored(&store).1;
    assert_eq!(
        owner.create(Key::Shard(shard()), current).map(drop),
        Err(StoreError::Refused(super::Refusal::Condition))
    );
    let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    log.fail.set(true);
    assert_eq!(owner.bump(&read).map(drop), Err(StoreError::Log));
    owner.outcomes()
}

/// A tally's gain over an earlier tally of the same client counts only the outcomes tallied between the two: a
/// baseline taken after an unavailable read leaves that read out of the gain and keeps a later unknown write.
#[test]
fn a_tally_since_a_baseline_counts_only_the_outcomes_after_it() {
    let store = seeded();
    let mut owner = client(&store);
    unavailable::<ShardRecord, _, _>(&mut owner, &store, Key::Shard(shard()));
    let baseline = owner.outcomes();
    assert_eq!(baseline.since(&baseline), Tally::default());
    let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    store.schedule(Arm::Timeout { commit: false });
    assert_eq!(owner.bump(&read).map(drop), Err(StoreError::Unknown));
    assert_eq!(
        nonzero(owner.outcomes().since(&baseline)),
        [(RecordClass::Shard, Tallied::Unknown, 1)]
    );
    assert_eq!(
        nonzero(owner.outcomes()),
        [
            (RecordClass::Shard, Tallied::Unknown, 1),
            (RecordClass::Shard, Tallied::Unavailable, 1)
        ]
    );
}
