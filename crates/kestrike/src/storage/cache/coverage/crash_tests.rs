//! A page's blocked set enters a tenure's coverage only from the tenure's own acknowledged write, and every
//! acknowledged entry reaches each later tenure that fenced every page.

use std::num::{NonZeroU16, NonZeroU32};

use super::super::super::store::sim::{Arm, AsReconciler, Counting, MemLog, Requests, Shared};
use super::super::super::store::{Client, Key, Outcome, Refusal, Store, StoreError, Write};
use super::super::super::store_tests::{page, record, seeded, shard};
use super::{
    Cover, Entry, Fencing, FencingRefusal, Interval, PageRequest, Progress, Withdraw,
    decode_entries, page_len, page_of,
};
use crate::failover::records::{CoveragePage, Record, ShardRecord};
use crate::net::ownership::{Shard, ShardGeneration};
use crate::storage::{CacheVersion, Session, session_at};

fn session_of_shard(shard: Shard) -> Session {
    let store = Shared::new();
    let mut client = process(&store, &MemLog::default());
    let read = client
        .create_shard(ShardRecord { shard, ..record() })
        .unwrap();
    Session::activate(client.bump(&read).unwrap()).unwrap()
}

#[test]
fn fencing_refuses_a_session_of_another_shard_or_generation() {
    let other = Shard::new(shard().get() + 1).unwrap();
    let foreign = session_of_shard(other);
    assert_eq!(
        (foreign.get(), foreign.shard()),
        (earlier().get(), other),
        "two shards' sessions can share their encoding"
    );
    assert_eq!(
        Fencing::new(&record(), &foreign, INTERVALS).err(),
        Some(FencingRefusal::Shard)
    );
    let flipped = ShardRecord {
        generation: ShardGeneration::new(4).unwrap(),
        ..record()
    };
    assert_eq!(
        Fencing::new(&flipped, &earlier(), INTERVALS).err(),
        Some(FencingRefusal::Generation)
    );
    assert!(Fencing::new(&record(), &earlier(), INTERVALS).is_ok());
}

const INTERVALS: usize = 4;

fn earlier() -> Session {
    session_at(3, 0)
}

fn later() -> Session {
    session_at(3, 1)
}

fn next() -> Session {
    session_at(3, 2)
}

fn process(store: &Shared, log: &MemLog) -> Client<Shared, MemLog> {
    Client::open(store.clone(), log.clone()).unwrap()
}

fn key_on(page: u16) -> [u8; 32] {
    let mut key = [page as u8 + 0x40; 32];
    key[..8].copy_from_slice(&u64::from(page).to_le_bytes());
    assert_eq!(page_of(&key, record().pages), page);
    key
}

fn entry(page: u16, low: u64, high: u64) -> Entry {
    (
        key_on(page),
        Interval::new(CacheVersion(low), CacheVersion(high)).unwrap(),
    )
}

fn unfenced(session: &Session) -> Fencing {
    Fencing::new(&record(), session, INTERVALS).unwrap()
}

fn commits(store: &Shared, at: u16) -> usize {
    store.0.borrow().commit_count(&Key::Page(shard(), at))
}

fn fenced(client: &mut Client<Shared, MemLog>, session: &Session) -> Fencing {
    let mut fencing = unfenced(session);
    for at in 0..record().pages.get() {
        assert_eq!(fencing.fence(client, at), Ok(Progress::Done));
    }
    fencing
}

fn invalidated(store: &Shared, session: &Session, at: u16) -> Entry {
    let mut client = process(store, &MemLog::default());
    let mut fencing = fenced(&mut client, session);
    let covered = entry(at, 5, 9);
    assert_eq!(
        fencing.cover_page(&mut client, &[covered]),
        Ok(Progress::Done)
    );
    covered
}

fn covers(fencing: &Fencing, (key, interval): Entry) -> bool {
    (interval.low().0..=interval.high().0).all(|v| fencing.partial().covers(&key, CacheVersion(v)))
}

#[test]
fn fence_crash_with_some_pages_fenced_fences_again_under_the_next_session() {
    let store = seeded();
    let acknowledged = invalidated(&store, &earlier(), 0);
    let log = MemLog::default();
    let mut client = process(&store, &log);
    let mut crashed = unfenced(&later());
    assert_eq!(crashed.fence(&mut client, 0), Ok(Progress::Done));
    drop((crashed, client));
    assert_eq!(page(&store, 0).fence, later().get());
    let before = commits(&store, 0);
    let mut client = process(&store, &log);
    let resumed = fenced(&mut client, &next());
    assert_eq!(
        commits(&store, 0),
        before + 1,
        "the restarted tenure writes its own fence over the crashed one"
    );
    assert!(resumed.complete());
    assert!(covers(&resumed, acknowledged));
    for at in 0..2 {
        assert_eq!(page(&store, at).fence, next().get());
    }
}

#[test]
fn fence_timeout_then_refence_or_confirm() {
    for commit in [true, false] {
        let store = seeded();
        let acknowledged = invalidated(&store, &earlier(), 1);
        let mut client = process(&store, &MemLog::default());
        let mut fencing = unfenced(&later());
        store.schedule(Arm::Pass);
        store.schedule(Arm::Timeout { commit });
        assert_eq!(fencing.fence(&mut client, 1), Ok(Progress::Unresolved));
        assert!(fencing.known(1).is_none(), "commit {commit}");
        assert!(!covers(&fencing, acknowledged), "commit {commit}");
        assert_eq!(page(&store, 1).fence == later().get(), commit);
        if commit {
            store.schedule(Arm::Pass);
            store.schedule(Arm::Timeout { commit: false });
            assert_eq!(fencing.fence(&mut client, 1), Ok(Progress::Unresolved));
            assert!(
                fencing.known(1).is_none(),
                "a read of the own fence adopts nothing before its confirming write"
            );
            assert!(!covers(&fencing, acknowledged));
        }
        let before = commits(&store, 1);
        assert_eq!(fencing.fence(&mut client, 1), Ok(Progress::Done));
        assert_eq!(
            commits(&store, 1),
            before + 1,
            "the confirm or the fence is a write"
        );
        assert!(covers(&fencing, acknowledged), "commit {commit}");
        assert_eq!(fencing.fence(&mut client, 0), Ok(Progress::Done));
        assert!(fencing.complete());
    }
}

#[test]
fn fence_finding_a_newer_tenure_withdraws() {
    let store = seeded();
    let mut later_client = process(&store, &MemLog::default());
    fenced(&mut later_client, &later());
    let before = commits(&store, 0);
    let mut client = process(&store, &MemLog::default());
    let mut fencing = unfenced(&earlier());
    assert_eq!(
        fencing.fence(&mut client, 0),
        Err(Withdraw::NewerFence {
            page: 0,
            fence: later().get()
        })
    );
    assert_eq!(fencing.partial(), unfenced(&earlier()).partial());
    assert_eq!(commits(&store, 0), before);
    assert_eq!(page(&store, 0).fence, later().get());
    let withdrawn = Err(Withdraw::NewerFence {
        page: 0,
        fence: later().get(),
    });
    let page_one = commits(&store, 1);
    assert_eq!(fencing.fence(&mut client, 1), withdrawn);
    assert_eq!(
        fencing.cover_page(&mut client, &[entry(1, 5, 9)]),
        withdrawn
    );
    assert_eq!(commits(&store, 1), page_one);
    assert!(fencing.coverage().is_none());
}

#[test]
fn fence_of_a_page_the_store_lacks_withdraws_and_latches() {
    let store = seeded();
    let three = ShardRecord {
        pages: NonZeroU16::new(3).unwrap(),
        ..record()
    };
    let mut client = process(&store, &MemLog::default());
    let mut fencing = Fencing::new(&three, &earlier(), INTERVALS).unwrap();
    let absent = Err(Withdraw::Store(StoreError::Absent));
    assert_eq!(fencing.fence(&mut client, 2), absent);
    assert!(fencing.known(2).is_none());
    let before = commits(&store, 0);
    assert_eq!(fencing.fence(&mut client, 0), absent);
    assert_eq!(commits(&store, 0), before);
}

#[test]
fn fence_rejected_saturated_write_withdraws() {
    let store = seeded();
    let mut client = process(&store, &MemLog::default());
    let mut fencing = fenced(&mut client, &earlier());
    store.0.borrow_mut().limit = page_len(0) - 1;
    let before = commits(&store, 1);
    let rejected = Err(Withdraw::Store(StoreError::Refused(Refusal::Rejected)));
    assert_eq!(fencing.cover_page(&mut client, &[entry(1, 5, 9)]), rejected);
    assert_eq!(commits(&store, 1), before);
    assert!(!page(&store, 1).saturated);
    assert!(fencing.coverage().is_none());
    assert_eq!(fencing.cover_page(&mut client, &[entry(1, 5, 9)]), rejected);
    assert_eq!(commits(&store, 1), before);
}

#[test]
fn fence_pending_covers_keep_memory_within_the_page_bounds() {
    let store = seeded();
    let capped = ShardRecord {
        page_cap: NonZeroU32::new(page_len(3) as u32).unwrap(),
        ..record()
    };
    let mut client = process(&store, &MemLog::default());
    let mut fencing = Fencing::new(&capped, &earlier(), 2).unwrap();
    assert_eq!(fencing.fence(&mut client, 0), Ok(Progress::Done));
    let before = commits(&store, 1);
    let hulled = key_on(1);
    for low in [1, 10, 20] {
        assert_eq!(
            fencing.cover_page(&mut client, &[entry(1, low, low)]),
            Ok(Progress::Unresolved)
        );
    }
    assert!(
        fencing.partial().covers(&hulled, CacheVersion(15)),
        "the hull"
    );
    let mut sibling = hulled;
    for (at, low) in [(31, 1), (30, 5), (29, 9)] {
        sibling[at] ^= 1;
        let pending = (
            sibling,
            Interval::new(CacheVersion(low), CacheVersion(low)).unwrap(),
        );
        assert_eq!(
            fencing.cover_page(&mut client, &[pending]),
            Ok(Progress::Unresolved)
        );
    }
    let mut unseen = hulled;
    unseen[28] ^= 1;
    assert!(
        fencing.partial().covers(&unseen, CacheVersion(u64::MAX)),
        "the page saturates in memory"
    );
    assert_eq!(commits(&store, 1), before);
}

#[test]
fn fence_successor_crashing_mid_fence_keeps_every_acknowledged_entry() {
    let store = seeded();
    let mut first_client = process(&store, &MemLog::default());
    let mut first_tenure = fenced(&mut first_client, &earlier());
    let first = entry(0, 5, 9);
    assert_eq!(
        first_tenure.cover_page(&mut first_client, &[first]),
        Ok(Progress::Done)
    );
    let successor_log = MemLog::default();
    let mut client = process(&store, &successor_log);
    let mut crashed = unfenced(&later());
    assert_eq!(crashed.fence(&mut client, 1), Ok(Progress::Done));
    drop((crashed, client));
    let late = entry(0, 20, 21);
    assert_eq!(
        first_tenure.cover_page(&mut first_client, &[late]),
        Ok(Progress::Done),
        "page 0 is still the earlier tenure's while the successor is down"
    );
    let mut client = process(&store, &successor_log);
    let resumed = fenced(&mut client, &next());
    for acknowledged in [first, late] {
        assert!(covers(&resumed, acknowledged));
    }
    assert_eq!(
        first_tenure.cover_page(&mut first_client, &[entry(0, 30, 30)]),
        Err(Withdraw::NewerFence {
            page: 0,
            fence: next().get()
        })
    );
}

#[test]
fn fence_control_marking_a_page_fenced_on_a_read_loses_an_acknowledgment() {
    let store = seeded();
    let mut first_client = process(&store, &MemLog::default());
    let mut first_tenure = fenced(&mut first_client, &earlier());
    let acknowledged = entry(0, 1, 2);

    let mut control_client = process(&store, &MemLog::default());
    let mut control = unfenced(&later());
    for at in 0..2 {
        assert_eq!(
            control.read_as_fenced(&mut control_client, at),
            Progress::Done
        );
    }
    assert!(control.complete());
    assert_eq!(
        first_tenure.cover_page(&mut first_client, &[acknowledged]),
        Ok(Progress::Done)
    );
    assert!(
        !covers(&control, acknowledged),
        "the control lost an acknowledged invalidation"
    );

    let mut successor_client = process(&store, &MemLog::default());
    let successor = fenced(&mut successor_client, &later());
    assert!(covers(&successor, acknowledged));
    assert_eq!(
        first_tenure.cover_page(&mut first_client, &[entry(0, 3, 4)]),
        Err(Withdraw::NewerFence {
            page: 0,
            fence: later().get()
        })
    );
}

#[test]
fn fence_failing_its_condition_adopts_nothing_until_a_fresh_fence() {
    let store = seeded();
    let mut first_client = process(&store, &MemLog::default());
    let mut first_tenure = fenced(&mut first_client, &earlier());
    let delayed = entry(0, 5, 9);
    store.schedule(Arm::Delay);
    assert_eq!(
        first_tenure.cover_page(&mut first_client, &[delayed]),
        Ok(Progress::Unresolved)
    );
    let mut client = process(&store, &MemLog::default());
    let mut fencing = unfenced(&later());
    store.schedule(Arm::StaleRead);
    assert_eq!(fencing.fence(&mut client, 0), Ok(Progress::Unresolved));
    let current = store
        .0
        .borrow()
        .current(&Key::Page(shard(), 0))
        .unwrap()
        .version;
    assert_eq!(
        store.0.borrow().drained,
        [Outcome::Committed(current)],
        "the read overlapped the delayed write's commit"
    );
    assert!(fencing.known(0).is_none());
    assert!(!covers(&fencing, delayed));
    assert_eq!(fencing.fence(&mut client, 0), Ok(Progress::Done));
    assert!(covers(&fencing, delayed));
    assert_eq!(
        first_tenure.cover_page(&mut first_client, &[delayed]),
        Err(Withdraw::NewerFence {
            page: 0,
            fence: later().get()
        })
    );
    assert_eq!(
        fencing.fence(&mut client, 2),
        Err(Withdraw::NoPage { page: 2 })
    );
}

#[test]
fn fence_retried_coverage_after_a_committed_timeout_writes_one_entry() {
    let store = seeded();
    let mut client = process(&store, &MemLog::default());
    let mut fencing = fenced(&mut client, &earlier());
    let retried = entry(1, 5, 9);
    store.schedule(Arm::Timeout { commit: true });
    assert_eq!(
        fencing.cover_page(&mut client, &[retried]),
        Ok(Progress::Unresolved)
    );
    let before = commits(&store, 1);
    assert_eq!(
        fencing.cover_page(&mut client, &[retried]),
        Ok(Progress::Unresolved),
        "the stale basis fails its condition and the re-read becomes the basis"
    );
    assert_eq!(
        fencing.cover_page(&mut client, &[retried]),
        Ok(Progress::Done),
        "the acknowledgment rests on a write of the retry's own"
    );
    assert_eq!(commits(&store, 1), before + 1);
    assert_eq!(decode_entries(&page(&store, 1).entries).unwrap(), [retried]);
    let held = fencing.partial().clone();
    let inside = (
        retried.0,
        Interval::new(CacheVersion(6), CacheVersion(7)).unwrap(),
    );
    assert_eq!(
        fencing.cover_page(&mut client, &[inside]),
        Ok(Progress::Done)
    );
    assert_eq!(
        commits(&store, 1),
        before + 2,
        "a contained interval's acknowledgment still rests on its own write"
    );
    assert_eq!(decode_entries(&page(&store, 1).entries).unwrap(), [retried]);
    assert_eq!(fencing.partial(), &held);
}

/// A write that follows a re-read merges into the keys the re-read brought: another writer of the tenure's fence
/// adds an interval of a second key to the page, the tenure's write fails its condition and adopts the re-read
/// page, and the next write, which carries an interval of the second key inside the stored one, leaves that key's
/// stored interval alone and adds the first key's.
#[test]
fn a_write_after_a_reread_merges_into_the_keys_the_reread_brought() {
    let store = seeded();
    let mut client = process(&store, &MemLog::default());
    let mut fencing = fenced(&mut client, &earlier());
    let first = entry(1, 5, 6);
    let mut second = entry(1, 1, 9);
    second.0[31] ^= 1;
    let mut other = process(&store, &MemLog::default());
    let read = other.read::<CoveragePage>(Key::Page(shard(), 1)).unwrap();
    let grown = CoveragePage {
        entries: super::encode_entries(&[second]),
        ..read.value().clone()
    };
    other.replace(&read, grown).unwrap();
    assert_eq!(
        fencing.cover_page(&mut client, &[first]),
        Ok(Progress::Unresolved),
        "the failed condition re-read the page"
    );
    let inside = (second.0, entry(1, 3, 4).1);
    assert_eq!(
        fencing.cover_page(&mut client, &[first, inside]),
        Ok(Progress::Done)
    );
    assert_eq!(
        decode_entries(&page(&store, 1).entries).unwrap(),
        [second, first]
    );
}

#[test]
fn fence_size_rejection_on_a_stale_basis_saturates_the_current_page() {
    let store = seeded();
    let mut client = process(&store, &MemLog::default());
    let mut fencing = fenced(&mut client, &earlier());
    let first = entry(1, 5, 9);
    store.schedule(Arm::Timeout { commit: true });
    assert_eq!(
        fencing.cover_page(&mut client, &[first]),
        Ok(Progress::Unresolved)
    );
    let stale = fencing.known(1).unwrap().version();
    store.0.borrow_mut().limit = page_len(0);
    let mut second = first;
    second.0[31] ^= 1;
    assert_eq!(
        fencing.cover_page(&mut client, &[second]),
        Ok(Progress::Done)
    );
    assert!(fencing.known(1).unwrap().version() > stale);
    assert!(page(&store, 1).saturated);
    assert_eq!(
        commits(&store, 1),
        4,
        "create, fence, the timed-out write, saturation"
    );
}

#[test]
fn fence_saturated_write_failing_its_condition_rereads() {
    let store = seeded();
    let mut client = process(&store, &MemLog::default());
    let mut fencing = fenced(&mut client, &earlier());
    let first = entry(1, 5, 9);
    store.schedule(Arm::Timeout { commit: true });
    assert_eq!(
        fencing.cover_page(&mut client, &[first]),
        Ok(Progress::Unresolved)
    );
    let stale = fencing.known(1).unwrap().version();
    store.0.borrow_mut().limit = page_len(0);
    let mut second = first;
    second.0[31] ^= 1;
    store.schedule(Arm::Pass);
    store.schedule(Arm::Unavailable);
    assert_eq!(
        fencing.cover_page(&mut client, &[second]),
        Ok(Progress::Unresolved),
        "the saturated write on the kept stale basis fails its condition"
    );
    assert!(
        fencing.known(1).unwrap().version() > stale,
        "the failed condition re-read the page"
    );
    assert!(!page(&store, 1).saturated);
    assert_eq!(
        fencing.cover_page(&mut client, &[second]),
        Ok(Progress::Done)
    );
    assert!(page(&store, 1).saturated);
}

#[test]
fn fence_saturated_write_failing_its_condition_with_an_unavailable_reread_keeps_the_basis() {
    let store = seeded();
    let mut client = process(&store, &MemLog::default());
    let mut fencing = fenced(&mut client, &earlier());
    let first = entry(1, 5, 9);
    store.schedule(Arm::Timeout { commit: true });
    assert_eq!(
        fencing.cover_page(&mut client, &[first]),
        Ok(Progress::Unresolved)
    );
    let stale = fencing.known(1).unwrap().version();
    store.0.borrow_mut().limit = page_len(0);
    let mut second = first;
    second.0[31] ^= 1;
    for arm in [Arm::Pass, Arm::Unavailable, Arm::Pass, Arm::Unavailable] {
        store.schedule(arm);
    }
    assert_eq!(
        fencing.cover_page(&mut client, &[second]),
        Ok(Progress::Unresolved)
    );
    assert_eq!(fencing.known(1).unwrap().version(), stale);
    assert!(!page(&store, 1).saturated);
    assert_eq!(
        fencing.cover_page(&mut client, &[second]),
        Ok(Progress::Done)
    );
    assert!(page(&store, 1).saturated);
}

#[test]
fn fence_terminal_store_error_latches_the_withdrawal() {
    let store = seeded();
    let mut denied = Client::open(AsReconciler(store.clone()), MemLog::default()).unwrap();
    let mut fencing = unfenced(&earlier());
    let refused = Err(Withdraw::Store(StoreError::Refused(Refusal::Denied)));
    assert_eq!(fencing.fence(&mut denied, 0), refused);
    assert!(fencing.known(0).is_none());
    assert_eq!(commits(&store, 0), 1);
    let mut client = process(&store, &MemLog::default());
    assert_eq!(
        fencing.fence(&mut client, 0),
        refused,
        "the withdrawal is latched"
    );
    assert_eq!(commits(&store, 0), 1);

    let mut covering = fenced(&mut client, &earlier());
    let before = commits(&store, 1);
    assert_eq!(covering.cover_page(&mut denied, &[entry(1, 5, 9)]), refused);
    assert_eq!(commits(&store, 1), before);
    assert!(covering.coverage().is_none());
    assert_eq!(covering.cover_page(&mut client, &[entry(1, 5, 9)]), refused);
    assert_eq!(commits(&store, 1), before);
}

#[test]
fn fence_cover_waits_for_every_page() {
    let store = seeded();
    let mut client = process(&store, &MemLog::default());
    let mut fencing = unfenced(&earlier());
    assert_eq!(fencing.fence(&mut client, 0), Ok(Progress::Done));
    let waiting = entry(0, 5, 9);
    let before = commits(&store, 0);
    assert_eq!(
        fencing.cover_page(&mut client, &[waiting]),
        Ok(Progress::Unresolved)
    );
    assert_eq!(commits(&store, 0), before);
    assert!(fencing.coverage().is_none());
    assert!(covers(&fencing, waiting));
    assert_eq!(fencing.fence(&mut client, 1), Ok(Progress::Done));
    assert_eq!(
        fencing.cover_page(&mut client, &[waiting]),
        Ok(Progress::Done)
    );
    assert_eq!(decode_entries(&page(&store, 0).entries).unwrap(), [waiting]);
}

#[test]
fn fence_refusing_an_undecodable_misplaced_or_oversized_page_writes_nothing() {
    let misplaced = entry(1, 1, 1);
    let mut sibling = entry(0, 1, 1);
    sibling.0[31] ^= 1;
    let oversized = super::encode_entries(&[entry(0, 1, 1), sibling]);
    for (entries, cap) in [
        (vec![0; 47], page_len(1)),
        (super::encode_entries(&[misplaced]), page_len(1)),
        (oversized, page_len(1)),
    ] {
        let capped = ShardRecord {
            page_cap: NonZeroU32::new(cap as u32).unwrap(),
            ..record()
        };
        let store = seeded();
        let mut client = process(&store, &MemLog::default());
        let mut writer = unfenced(&earlier());
        assert_eq!(writer.fence(&mut client, 0), Ok(Progress::Done));
        let basis = writer.known(0).unwrap().clone();
        let planted = CoveragePage {
            entries,
            ..basis.value().clone()
        };
        client.replace(&basis, planted.clone()).unwrap();
        let before = commits(&store, 0);
        let mut fencing = Fencing::new(&capped, &later(), INTERVALS).unwrap();
        let mut successor = process(&store, &MemLog::default());
        let malformed = Err(Withdraw::Malformed { page: 0 });
        assert_eq!(fencing.fence(&mut successor, 0), malformed);
        assert!(fencing.known(0).is_none());
        let fresh = Fencing::new(&capped, &later(), INTERVALS).unwrap();
        assert_eq!(fencing.partial(), fresh.partial());
        assert_eq!(page(&store, 0), planted);
        assert_eq!(commits(&store, 0), before);
        assert_eq!(fencing.fence(&mut successor, 1), malformed, "latched");
    }
}

#[test]
fn fence_earlier_write_held_across_the_successor_fence_is_refused() {
    let store = seeded();
    let mut first_client = process(&store, &MemLog::default());
    let mut first_tenure = fenced(&mut first_client, &earlier());
    let acknowledged = entry(0, 1, 2);
    assert_eq!(
        first_tenure.cover_page(&mut first_client, &[acknowledged]),
        Ok(Progress::Done)
    );
    let held = entry(0, 5, 9);
    store.schedule(Arm::Hold);
    assert_eq!(
        first_tenure.cover_page(&mut first_client, &[held]),
        Ok(Progress::Unresolved)
    );
    let mut client = process(&store, &MemLog::default());
    let mut successor = fenced(&mut client, &later());
    let own = entry(0, 20, 20);
    assert_eq!(
        successor.cover_page(&mut client, &[own]),
        Ok(Progress::Done)
    );
    let stored = page(&store, 0);
    assert_eq!(store.release(), [Outcome::NotCommitted(Refusal::Condition)]);
    assert_eq!(page(&store, 0), stored);
    assert_eq!(
        decode_entries(&stored.entries).unwrap(),
        [acknowledged, own]
    );
    assert_eq!(
        first_tenure.cover_page(&mut first_client, &[held]),
        Err(Withdraw::NewerFence {
            page: 0,
            fence: later().get()
        })
    );
    assert!(covers(&successor, acknowledged) && covers(&successor, own));
    assert!(!covers(&successor, held));
}

#[test]
fn fence_cover_on_a_saturated_page_writes_and_carries_the_saturation() {
    let store = seeded();
    let one_entry = ShardRecord {
        page_cap: NonZeroU32::new(page_len(1) as u32).unwrap(),
        ..record()
    };
    let mut client = process(&store, &MemLog::default());
    let mut fencing = Fencing::new(&one_entry, &earlier(), INTERVALS).unwrap();
    for at in 0..2 {
        assert_eq!(fencing.fence(&mut client, at), Ok(Progress::Done));
    }
    let first = entry(0, 5, 9);
    let mut second = first;
    second.0[31] ^= 1;
    for covered in [first, second] {
        assert_eq!(
            fencing.cover_page(&mut client, &[covered]),
            Ok(Progress::Done)
        );
    }
    assert!(page(&store, 0).saturated);
    let before = commits(&store, 0);
    let mut third = first;
    third.0[30] ^= 1;
    assert_eq!(
        fencing.cover_page(&mut client, &[third]),
        Ok(Progress::Done)
    );
    assert_eq!(commits(&store, 0), before + 1);
    assert!(page(&store, 0).saturated && page(&store, 0).entries.is_empty());
    assert_eq!(
        fencing.growth(),
        super::Growth {
            saturated_pages: 1,
            largest_page_bytes: page_len(0),
            pairs: 0,
            held_saturated_pages: 0,
        }
    );
    let mut successor_client = process(&store, &MemLog::default());
    let successor = fenced(&mut successor_client, &later());
    let coverage = successor.coverage().unwrap();
    for key in [first.0, second.0, third.0] {
        for version in [0, 7, u64::MAX] {
            assert!(coverage.covers(&key, CacheVersion(version)));
        }
    }
}

#[test]
fn fence_unavailable_reads_adopt_nothing() {
    let store = seeded();
    let mut client = process(&store, &MemLog::default());
    let mut fencing = unfenced(&earlier());
    let before = commits(&store, 0);
    store.schedule(Arm::Unavailable);
    assert_eq!(fencing.fence(&mut client, 0), Ok(Progress::Unresolved));
    assert!(fencing.known(0).is_none());
    assert_eq!(commits(&store, 0), before);
    for at in 0..2 {
        assert_eq!(fencing.fence(&mut client, at), Ok(Progress::Done));
    }

    let retried = entry(0, 5, 9);
    store.schedule(Arm::Timeout { commit: true });
    assert_eq!(
        fencing.cover_page(&mut client, &[retried]),
        Ok(Progress::Unresolved)
    );
    let basis = fencing.known(0).unwrap().clone();
    store.schedule(Arm::Pass);
    store.schedule(Arm::Unavailable);
    assert_eq!(
        fencing.cover_page(&mut client, &[retried]),
        Ok(Progress::Unresolved)
    );
    assert_eq!(fencing.known(0), Some(&basis));
    assert_eq!(
        fencing.cover_page(&mut client, &[retried]),
        Ok(Progress::Unresolved)
    );
    assert_eq!(
        fencing.cover_page(&mut client, &[retried]),
        Ok(Progress::Done)
    );

    store.0.borrow_mut().limit = page(&store, 1).encode().len();
    store.schedule(Arm::Pass);
    store.schedule(Arm::Unavailable);
    assert_eq!(
        fencing.cover_page(&mut client, &[entry(1, 2, 2)]),
        Ok(Progress::Done)
    );
    assert!(page(&store, 1).saturated);
}

#[test]
fn fencing_refuses_a_page_cap_below_the_empty_page() {
    let empty = CoveragePage::default().encode().len();
    for (cap, admitted) in [(empty - 1, false), (empty, true)] {
        let capped = ShardRecord {
            page_cap: NonZeroU32::new(cap as u32).unwrap(),
            ..record()
        };
        assert_eq!(
            Fencing::new(&capped, &earlier(), INTERVALS).err(),
            (!admitted).then_some(FencingRefusal::PageCap)
        );
    }
}

/// `fence_all` reads every unfenced page before it writes any: a newer fence on the last page withdraws the tenure
/// with no page written, and over pages that hold no newer fence one call fences every page with one write each.
#[test]
fn fence_all_reads_every_page_before_writing_any() {
    let store = seeded();
    let mut later_client = process(&store, &MemLog::default());
    let last = record().pages.get() - 1;
    assert_eq!(
        unfenced(&later()).fence(&mut later_client, last),
        Ok(Progress::Done)
    );
    let before: Vec<usize> = (0..=last).map(|at| commits(&store, at)).collect();
    let mut client = process(&store, &MemLog::default());
    let mut fencing = unfenced(&earlier());
    assert_eq!(
        fencing.fence_all(&mut client),
        Err(Withdraw::NewerFence {
            page: last,
            fence: later().get()
        })
    );
    let after: Vec<usize> = (0..=last).map(|at| commits(&store, at)).collect();
    assert_eq!(after, before, "no page is written");
    assert!(fencing.coverage().is_none());

    let mut client = process(&store, &MemLog::default());
    let mut fencing = unfenced(&next());
    assert_eq!(fencing.fence_all(&mut client), Ok(Progress::Done));
    for at in 0..=last {
        assert_eq!(commits(&store, at), before[usize::from(at)] + 1);
        assert_eq!(page(&store, at).fence, next().get());
    }
    assert!(fencing.coverage().is_some());
}

/// `fence_all` makes the fence of every page durable in the watermark with two log writes, one after the reads and
/// one after the writes, and a call over fully fenced pages writes nothing.
#[test]
fn fence_all_settles_its_reads_and_its_writes_with_one_log_write_each() {
    use super::super::super::store_tests::Counted;

    let store = seeded();
    let log = Counted::default();
    let mut client = Client::open(store.clone(), log.clone()).unwrap();
    let opened = log.writes.get();
    let mut fencing = unfenced(&later());
    assert_eq!(fencing.fence_all(&mut client), Ok(Progress::Done));
    assert_eq!(log.writes.get(), opened + 2);
    assert_eq!(fencing.fence_all(&mut client), Ok(Progress::Done));
    assert_eq!(log.writes.get(), opened + 2);
}

/// The later tenure fences page 1, so the earlier tenure's `fence_all` reads both pages and latches the newer
/// fence. The client stays admitted: its next read of the shard record succeeds and is the one request the store
/// then counts. Two more `fence_all` calls return the identical withdrawal, and the store's read and write counts
/// stay as they were before them.
#[test]
fn fence_all_on_a_latched_withdrawal_returns_it_with_no_read_or_write_sent() {
    let store = seeded();
    assert_eq!(record().pages.get(), 2);
    let mut successor = process(&store, &MemLog::default());
    assert_eq!(
        unfenced(&later()).fence(&mut successor, 1),
        Ok(Progress::Done)
    );

    let requests = Requests::default();
    let counting = Counting {
        store: store.clone(),
        requests: requests.clone(),
    };
    let mut client = Client::open(counting, MemLog::default()).unwrap();
    let mut fencing = unfenced(&earlier());
    let opened = requests.seen();
    let withdrawal = Withdraw::NewerFence {
        page: 1,
        fence: later().get(),
    };
    assert_eq!(fencing.fence_all(&mut client), Err(withdrawal));
    assert_eq!(
        requests.seen(),
        (opened.0 + 2, opened.1),
        "the latching call read both pages and wrote none"
    );

    assert!(client.read::<ShardRecord>(Key::Shard(shard())).is_ok());
    let latched = requests.seen();
    assert_eq!(latched, (opened.0 + 3, opened.1));

    for call in 0..2 {
        assert_eq!(fencing.fence_all(&mut client), Err(withdrawal), "{call}");
        assert_eq!(
            requests.seen(),
            latched,
            "call {call}: a latched withdrawal returns before requests begin"
        );
    }
    assert!(fencing.coverage().is_none());
}

/// REPLY-PAIRING: `cover_end` applies only the reply to the request its fencing awaits. An unsolicited re-read, the
/// reply to a request a later `cover_begin` replaced, a reply another tenure's fencing awaits, and the committed reply
/// of a second fencing of the same session over the same store at the same request count are each refused
/// `Unpaired` with the known value, the fenced count and the coverage as they were, and the awaited reply still
/// applies.
#[test]
fn a_page_reply_applies_only_to_the_request_its_fencing_awaits() {
    let store = seeded();
    let mut client = process(&store, &MemLog::default());
    let mut fencing = fenced(&mut client, &earlier());
    let stray = PageRequest::reread(shard(), 0).run(&mut client);
    assert_eq!(fencing.cover_end(stray).err(), Some(Withdraw::Unpaired));
    let (first, second, third) = (entry(0, 5, 9), entry(0, 12, 14), entry(0, 20, 22));
    let replaced = fencing.cover_begin(&[first]).unwrap().unwrap();
    let awaited = fencing.cover_begin(&[second]).unwrap().unwrap();
    let replaced = replaced.run(&mut client);
    assert_eq!(fencing.cover_end(replaced).err(), Some(Withdraw::Unpaired));
    let other_store = seeded();
    let mut other_client = process(&other_store, &MemLog::default());
    let mut other = fenced(&mut other_client, &later());
    let foreign = other.cover_begin(&[first]).unwrap().unwrap();
    let foreign = foreign.run(&mut other_client);
    assert_eq!(fencing.cover_end(foreign).err(), Some(Withdraw::Unpaired));
    let mut twin = fenced(&mut client, &earlier());
    let _ = twin.cover_begin(&[first]).unwrap().unwrap();
    let twin_reply = twin
        .cover_begin(&[third])
        .unwrap()
        .unwrap()
        .run(&mut client);
    let known = fencing.known(0).cloned();
    let committed = commits(&store, 0);
    assert_eq!(
        fencing.cover_end(twin_reply).err(),
        Some(Withdraw::Unpaired)
    );
    assert!(
        !page(&store, 0).entries.is_empty(),
        "the twin's write committed"
    );
    assert!(!covers(&fencing, third), "the twin's entry is not adopted");
    assert_eq!(
        fencing.known(0),
        known.as_ref(),
        "no refused reply is adopted"
    );
    assert!(fencing.complete());
    assert!(
        fencing.coverage().is_some(),
        "a refused reply latches nothing"
    );
    assert!(covers(&fencing, first) && covers(&fencing, second));
    let Ok(Cover::Next(reread)) = fencing.cover_end(awaited.run(&mut client)) else {
        panic!("the awaited write fails its condition on the later commits");
    };
    assert_eq!(commits(&store, 0), committed);
    assert!(matches!(
        fencing.cover_end(reread.run(&mut client)),
        Ok(Cover::Rebased)
    ));
    assert_eq!(
        fencing.known(0).map(|read| read.version()),
        store
            .0
            .borrow()
            .current(&Key::Page(shard(), 0))
            .map(|item| item.version),
        "the awaited re-read is adopted"
    );
}

/// A re-read of a fenced page that shows a fence below the tenure's session at a higher version is a store
/// regression: on a client that holds no mark of the page, the step withdraws with a regression, adopts nothing and
/// acknowledges nothing.
#[test]
fn a_reread_below_the_tenures_fence_withdraws_as_a_regression() {
    let store = seeded();
    let mut fencing = fenced(&mut process(&store, &MemLog::default()), &earlier());
    let known = fencing.known(0).cloned();
    let item = store
        .0
        .borrow()
        .current(&Key::Page(shard(), 0))
        .cloned()
        .unwrap();
    let lower = CoveragePage {
        fence: earlier().get() - 1,
        ..CoveragePage::decode(&item.value).unwrap()
    };
    let write = Write::Exact {
        expect: item.version,
        value: lower.encode(),
    };
    assert!(matches!(
        store.clone().write(&Key::Page(shard(), 0), &write),
        Outcome::Committed(_)
    ));
    let mut lane = process(&store, &MemLog::default());
    let covered = fencing.cover_page(&mut lane, &[entry(0, 5, 9)]);
    assert!(
        matches!(covered, Err(Withdraw::Store(StoreError::Regression(_)))),
        "{covered:?}"
    );
    assert_eq!(fencing.known(0), known.as_ref());
    assert!(fencing.coverage().is_none(), "the regression latches");
}
