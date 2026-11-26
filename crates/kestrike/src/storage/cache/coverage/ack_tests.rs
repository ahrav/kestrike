//! INVALIDATE acknowledgments over the simulated store: an acknowledgment follows its page write's acknowledged
//! success, INVALIDATEs on one page share one write, a resend after a timeout is acknowledged once its page covers
//! the interval, and every invalidation a crashed tenure could have acknowledged is in its successor's coverage.

use super::{Entry, Fencing, Interval, Progress, Withdraw, decode_entries, page_len, page_of};
use crate::storage::store::sim::{Arm, MemLog, Shared};
use crate::storage::store::{Client, Key, Outcome, Refusal};
use crate::storage::store_tests::{client, page, record, seeded, shard};
use crate::storage::{CacheVersion, session_at};

#[test]
fn one_dense_page_reserves_only_its_observed_entries() {
    let store = seeded();
    let mut client = client(&store);
    let mut settings = record();
    settings.pages = std::num::NonZeroU16::new(64).unwrap();
    settings.page_cap = std::num::NonZeroU32::new(1 << 20).unwrap();
    let entries: Vec<_> = (0..64).map(|n| (key(n * 64), interval(5, 9))).collect();
    let read = client
        .read::<crate::failover::records::CoveragePage>(Key::Page(shard(), 0))
        .unwrap();
    client
        .replace(
            &read,
            crate::failover::records::CoveragePage {
                entries: super::encode_entries(&entries),
                ..read.value().clone()
            },
        )
        .unwrap();
    let mut fencing = Fencing::new(&settings, &session_at(3, 1), 4).unwrap();
    assert_eq!(fencing.fence(&mut client, 0), Ok(Progress::Done));
    assert_eq!(fencing.coverage.full, entries.len());
    assert!(fencing.coverage.slots.len() <= entries.len() * 2);
    assert_eq!(fencing.fenced, 1);
}

fn key(n: u64) -> [u8; 32] {
    let mut key = [n as u8; 32];
    key[..8].copy_from_slice(&n.to_le_bytes());
    key
}

fn interval(low: u64, high: u64) -> Interval {
    Interval::new(CacheVersion(low), CacheVersion(high)).unwrap()
}

/// A fencing of tenure `tenure` whose every page is fenced over `store`.
fn fenced(store: &Shared, tenure: u32) -> (Fencing, Client<Shared, MemLog>) {
    let mut client = client(store);
    let mut fencing = Fencing::new(&record(), &session_at(3, tenure), 4).unwrap();
    for at in 0..record().pages.get() {
        assert!(
            (0..8).any(|_| fencing.fence(&mut client, at) == Ok(Progress::Done)),
            "page {} fences",
            at
        );
    }
    (fencing, client)
}

/// Two fencings that took equal inputs through equal steps print alike under `Debug`: when built, and once every
/// page is fenced and a coverage write committed. Their identities differ, and each coverage draws its own hash
/// keys, which place the covered key's mark.
#[test]
fn fencings_of_equal_inputs_and_steps_print_alike() {
    let built = || Fencing::new(&record(), &session_at(3, 0), 4).unwrap();
    let (one, other) = (built(), built());
    assert_ne!(one.id, other.id);
    assert_eq!(format!("{one:?}"), format!("{other:?}"));

    let covered = || {
        let (mut fencing, mut client) = fenced(&seeded(), 0);
        let entry = (key(1), interval(3, 5));
        assert_eq!(
            fencing.cover_page(&mut client, &[entry]),
            Ok(Progress::Done)
        );
        fencing
    };
    let (one, other) = (covered(), covered());
    assert_ne!(one.id, other.id);
    assert!(one.marks.iter().any(|marks| marks.len > 0));
    assert_eq!(format!("{one:?}"), format!("{other:?}"));
}

/// The writes the store has acknowledged on `entry`'s page.
fn replies(store: &Shared, entry: &Entry) -> usize {
    let at = page_of(&entry.0, record().pages);
    store
        .0
        .borrow()
        .replied
        .get(&Key::Page(shard(), at))
        .copied()
        .unwrap_or(0)
}

/// Whether the store's current value of `entry`'s page holds `entry` under `fence`.
fn committed(store: &Shared, entry: &Entry, fence: u64) -> bool {
    let value = page(store, page_of(&entry.0, record().pages));
    value.fence == fence
        && decode_entries(&value.entries).is_some_and(|entries| entries.contains(entry))
}

/// Runs one INVALIDATE under every store arm and checks the oracle: an acknowledgment needs an acknowledged reply
/// to the page write and the entry committed in the page under the tenure's fence. `ack_on_submit` acknowledges at
/// submission instead, the mutation the oracle catches.
fn acknowledgments(ack_on_submit: bool) -> Result<(), &'static str> {
    for arm in [
        Arm::Pass,
        Arm::Timeout { commit: true },
        Arm::Timeout { commit: false },
        Arm::Failure { commit: true },
        Arm::Failure { commit: false },
        Arm::Unavailable,
        Arm::Delay,
        Arm::Hold,
    ] {
        let store = seeded();
        let (mut fencing, mut client) = fenced(&store, 0);
        let own = session_at(3, 0).get();
        let entry = (key(1), interval(3, 5));
        let before = replies(&store, &entry);
        store.schedule(arm);
        let progress = fencing.cover_page(&mut client, &[entry]);
        let acknowledged = ack_on_submit || progress == Ok(Progress::Done);
        if acknowledged && (replies(&store, &entry) == before || !committed(&store, &entry, own)) {
            return Err("an INVALIDATE was acknowledged before its page write was");
        }
        if !acknowledged && !fencing.partial().covers(&entry.0, CacheVersion(4)) {
            return Err("an unacknowledged INVALIDATE left the coverage");
        }
    }
    Ok(())
}

/// No INVALIDATE is acknowledged before its page write is acknowledged with the entry committed under the
/// tenure's fence; an unacknowledged one stays in the coverage. The control acknowledges at submission, and the
/// timed-out and unavailable arms make the oracle name it.
#[test]
fn ack_only_after_page_write() {
    assert_eq!(acknowledgments(false), Ok(()));
    assert_eq!(
        acknowledgments(true),
        Err("an INVALIDATE was acknowledged before its page write was")
    );
}

/// An INVALIDATE whose write timed out after committing is resent: the resend's write fails its condition, its
/// re-read shows the committed entry, and the next resend is acknowledged with the page holding the interval once.
#[test]
fn resent_invalidate_idempotent() {
    let store = seeded();
    let (mut fencing, mut client) = fenced(&store, 0);
    let entry = (key(1), interval(3, 5));
    store.schedule(Arm::Timeout { commit: true });
    assert_eq!(
        fencing.cover_page(&mut client, &[entry]),
        Ok(Progress::Unresolved)
    );
    let mut resends = 0;
    while fencing.cover_page(&mut client, &[entry]) != Ok(Progress::Done) {
        resends += 1;
        assert!(resends < 4, "the resend is acknowledged");
    }
    let value = page(&store, page_of(&entry.0, record().pages));
    let entries = decode_entries(&value.entries).unwrap();
    assert_eq!(entries.iter().filter(|held| **held == entry).count(), 1);
    assert_eq!(entries.len(), 1);
}

/// Two INVALIDATEs on one page share one write: the page takes one commit for both, and both are acknowledged by
/// that write's success.
#[test]
fn invalidates_on_one_page_share_one_write() {
    let store = seeded();
    let (mut fencing, mut client) = fenced(&store, 0);
    let pages = record().pages;
    let second = (2..)
        .map(key)
        .find(|other| page_of(other, pages) == page_of(&key(1), pages))
        .unwrap();
    let entries = [(key(1), interval(1, 2)), (second, interval(7, 7))];
    let at = Key::Page(shard(), page_of(&key(1), pages));
    let before = store.0.borrow().commit_count(&at);
    assert_eq!(
        fencing.cover_page(&mut client, &entries),
        Ok(Progress::Done)
    );
    assert_eq!(store.0.borrow().commit_count(&at), before + 1);
    let own = session_at(3, 0).get();
    assert!(entries.iter().all(|entry| committed(&store, entry, own)));
}

/// Where tenure 0 stops before a crash. The boundaries after an acknowledgment, before its emission and before
/// its delivery, are owner-level cases in `net::put_tests`, where the INVALIDATED is emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Boundary {
    /// The entry is held in memory after the removal and no write was submitted.
    AfterRemoval,
    /// The write timed out uncommitted and the tenure lives on, refusing FILLs of the interval.
    TimedOutAlive,
    /// The write timed out after committing.
    TimeoutCommits,
    /// The client resent after a timeout and the resend was acknowledged.
    ClientRetry,
}

/// Tenure 0 runs one INVALIDATE to `boundary` and crashes; tenure 1 fences every page. Whether tenure 0
/// acknowledged is what its own steps returned, and an acknowledged INVALIDATE is in tenure 1's coverage, which
/// refuses a racing FILL of each covered version.
fn crash_at(boundary: Boundary) {
    let store = seeded();
    let (mut earlier, mut client) = fenced(&store, 0);
    let entry = (key(1), interval(3, 5));
    let acked = match boundary {
        Boundary::AfterRemoval => {
            earlier.hold(entry);
            false
        }
        Boundary::TimedOutAlive => {
            store.schedule(Arm::Timeout { commit: false });
            let progress = earlier.cover_page(&mut client, &[entry]);
            assert!(
                !earlier.admits(&entry.0, CacheVersion(4)),
                "the timed-out INVALIDATE refuses the FILL"
            );
            progress == Ok(Progress::Done)
        }
        Boundary::TimeoutCommits => {
            store.schedule(Arm::Timeout { commit: true });
            earlier.cover_page(&mut client, &[entry]) == Ok(Progress::Done)
        }
        Boundary::ClientRetry => {
            store.schedule(Arm::Timeout { commit: false });
            assert_eq!(
                earlier.cover_page(&mut client, &[entry]),
                Ok(Progress::Unresolved)
            );
            let mut resends = 0;
            while earlier.cover_page(&mut client, &[entry]) != Ok(Progress::Done) {
                resends += 1;
                assert!(resends < 4, "the resend is acknowledged");
            }
            true
        }
    };
    let committed = committed(&store, &entry, session_at(3, 0).get());
    let (later, _) = fenced(&store, 1);
    for version in 3..=5 {
        let covered = later
            .coverage()
            .unwrap()
            .covers(&entry.0, CacheVersion(version));
        assert!(
            covered || !acked,
            "{boundary:?}: an acknowledged v{version} lost"
        );
        assert_eq!(
            covered, committed,
            "{boundary:?}: the successor adopts exactly the committed entry"
        );
        assert_eq!(
            later.admits(&entry.0, CacheVersion(version)),
            !covered,
            "{boundary:?}"
        );
    }
    assert_eq!(
        (acked, committed),
        match boundary {
            Boundary::AfterRemoval | Boundary::TimedOutAlive => (false, false),
            Boundary::TimeoutCommits => (false, true),
            Boundary::ClientRetry => (true, true),
        },
        "{boundary:?}"
    );
}

#[test]
fn invalidate_ack_boundary_after_removal() {
    crash_at(Boundary::AfterRemoval);
}

#[test]
fn invalidate_ack_boundary_timed_out_alive() {
    crash_at(Boundary::TimedOutAlive);
}

#[test]
fn invalidate_ack_boundary_timeout_commits() {
    crash_at(Boundary::TimeoutCommits);
}

#[test]
fn invalidate_ack_boundary_client_retry() {
    crash_at(Boundary::ClientRetry);
}

/// Tenure 0's write is submitted and parked unacknowledged when it crashes. Released after tenure 1 fenced the
/// page, it fails its version condition, and tenure 1's page and coverage are unchanged; released before tenure 1
/// fences, it commits and tenure 1 adopts the entry. Tenure 0 acknowledged neither.
#[test]
fn invalidate_ack_boundary_submitted_unacknowledged() {
    for release_first in [false, true] {
        let store = seeded();
        let (mut earlier, mut client) = fenced(&store, 0);
        let entry = (key(1), interval(3, 5));
        store.schedule(Arm::Hold);
        assert_eq!(
            earlier.cover_page(&mut client, &[entry]),
            Ok(Progress::Unresolved)
        );
        let at = page_of(&entry.0, record().pages);
        if release_first {
            let released = store.release();
            assert!(
                matches!(released[..], [Outcome::Committed(_)]),
                "{released:?}"
            );
            let (later, _) = fenced(&store, 1);
            assert!(later.coverage().unwrap().covers(&entry.0, CacheVersion(4)));
            continue;
        }
        let (later, _) = fenced(&store, 1);
        let (page_before, covered_before) = (
            page(&store, at),
            later.coverage().unwrap().covers(&entry.0, CacheVersion(4)),
        );
        let released = store.release();
        assert!(
            matches!(released[..], [Outcome::NotCommitted(Refusal::Condition)]),
            "{released:?}"
        );
        assert_eq!(
            page(&store, at),
            page_before,
            "the stale write leaves tenure 1's page"
        );
        assert_eq!(page_before.fence, session_at(3, 1).get());
        assert_eq!(
            later.coverage().unwrap().covers(&entry.0, CacheVersion(4)),
            covered_before
        );
        assert!(
            !covered_before,
            "an unacknowledged, uncommitted INVALIDATE is not carried"
        );
    }
}

/// The test models FILL admission across a crash after acknowledgment of INVALIDATE(k, [3, 5]): the predicate the
/// insert check consults refuses version 4 under tenure 0's coverage and under tenure 1's fenced coverage.
#[test]
fn invalidate_ack_boundary_racing_covered_fill() {
    let store = seeded();
    let (mut earlier, mut client) = fenced(&store, 0);
    let entry = (key(1), interval(3, 5));
    assert!(
        earlier.admits(&entry.0, CacheVersion(4)),
        "version 4 is admissible before the INVALIDATE"
    );
    assert_eq!(
        earlier.cover_page(&mut client, &[entry]),
        Ok(Progress::Done)
    );
    assert!(
        !earlier.admits(&entry.0, CacheVersion(4)),
        "the predicate the insert check consults refuses version 4"
    );
    let (later, _) = fenced(&store, 1);
    assert!(!later.admits(&entry.0, CacheVersion(4)));
}

/// FILL admission refuses every FILL until every page is fenced and after a withdrawal. Once fenced, under
/// INVALIDATE(k, [3, 5]) it admits versions 2 and 6 of k and refuses 3 through 5, refuses version 0 of k, which
/// recovery judges by key alike, and admits version 0 of a key the coverage leaves untouched.
#[test]
fn fill_admission_over_versions_fencing_and_withdrawal() {
    let store = seeded();
    let mut client = client(&store);
    let mut fencing = Fencing::new(&record(), &session_at(3, 0), 4).unwrap();
    assert!(
        !fencing.admits(&key(2), CacheVersion(1)),
        "no page is fenced"
    );
    assert!(
        (0..8).any(|_| fencing.fence(&mut client, 0) == Ok(Progress::Done)),
        "page {} fences",
        0
    );
    assert!(
        !fencing.admits(&key(2), CacheVersion(0)),
        "one page is unfenced"
    );
    for at in 1..record().pages.get() {
        assert!(
            (0..8).any(|_| fencing.fence(&mut client, at) == Ok(Progress::Done)),
            "page {} fences",
            at
        );
    }
    assert_eq!(
        fencing.cover_page(&mut client, &[(key(1), interval(3, 5))]),
        Ok(Progress::Done)
    );
    let admitted: Vec<bool> = (2..=6)
        .map(|v| fencing.admits(&key(1), CacheVersion(v)))
        .collect();
    assert_eq!(admitted, [true, false, false, false, true]);
    // A checkpoint's stored version 0 is judged by key, so version 0 is too: an interval of the key that leaves 0
    // uncovered still refuses it, and a warm restore's key-judged omission removes no admitted fill.
    assert!(!fencing.admits(&key(1), CacheVersion(0)));
    assert!(fencing.admits(&key(2), CacheVersion(0)));
    let (_successor, _) = fenced(&store, 1);
    store.schedule(Arm::Pass);
    assert!(
        matches!(
            fencing.cover_page(&mut client, &[(key(2), interval(1, 1))]),
            Err(Withdraw::NewerFence { .. })
        ),
        "the newer fence withdraws"
    );
    assert!(
        !fencing.admits(&key(2), CacheVersion(9)),
        "a withdrawn tenure admits nothing"
    );
    assert!(!fencing.admits(&key(3), CacheVersion(0)));
}

/// A page whose coverage write is rejected for size saturates, and its saturation alone refuses a version 0 FILL of
/// a key on that page that holds no interval; a key on another page stays admitted.
#[test]
fn a_saturated_page_refuses_version_zero_fills_of_its_keys() {
    let store = seeded();
    let (mut fencing, mut client) = fenced(&store, 0);
    store.0.borrow_mut().limit = page_len(0);
    assert_eq!(
        fencing.cover_page(&mut client, &[(key(1), interval(5, 9))]),
        Ok(Progress::Done)
    );
    assert!(page(&store, page_of(&key(1), record().pages)).saturated);
    let on = page_of(&key(1), record().pages);
    let same = (2..).map(key).find(|k| page_of(k, record().pages) == on);
    let other = (2..).map(key).find(|k| page_of(k, record().pages) != on);
    assert!(!fencing.admits(&same.unwrap(), CacheVersion(0)));
    assert!(fencing.admits(&other.unwrap(), CacheVersion(0)));
}

/// A page that holds more intervals of one key than the fencing tenure's bound refuses `Malformed` at the fence, since
/// adopting it would merge the intervals into their hull and cover the versions between them; under a bound that holds
/// them the page fences and the gap stays admitted.
#[test]
fn a_page_past_the_tenures_interval_bound_refuses_rather_than_widening() {
    let store = seeded();
    let (mut writer, mut client) = fenced(&store, 0);
    for low in [1, 3] {
        assert_eq!(
            writer.cover_page(&mut client, &[(key(1), interval(low, low))]),
            Ok(Progress::Done)
        );
    }
    let at = page_of(&key(1), record().pages);
    for (bound, refuses) in [(1, true), (2, false)] {
        let mut successor = Fencing::new(&record(), &session_at(3, 1), bound).unwrap();
        let fenced = (0..8)
            .map(|_| successor.fence(&mut client, at))
            .find(|step| *step != Ok(Progress::Unresolved));
        if refuses {
            assert_eq!(
                fenced,
                Some(Err(Withdraw::Malformed { page: at })),
                "bound {bound}"
            );
            continue;
        }
        assert_eq!(fenced, Some(Ok(Progress::Done)), "bound {bound}");
        for other in 0..record().pages.get() {
            assert!((0..8).any(|_| successor.fence(&mut client, other) == Ok(Progress::Done)));
        }
        assert!(
            successor.admits(&key(1), CacheVersion(2)),
            "the gap stays admitted"
        );
        assert!(!successor.admits(&key(1), CacheVersion(3)));
    }
}

/// An interval bound of 0 retains one hull interval per key; a successor with the same bound fences that page, with the
/// hull's versions covered and later versions admitted.
#[test]
fn a_page_written_under_bound_zero_fences_under_bound_zero() {
    let store = seeded();
    let mut client = client(&store);
    let mut writer = Fencing::new(&record(), &session_at(3, 0), 0).unwrap();
    for at in 0..record().pages.get() {
        assert!((0..8).any(|_| writer.fence(&mut client, at) == Ok(Progress::Done)));
    }
    for low in [1, 3] {
        assert_eq!(
            writer.cover_page(&mut client, &[(key(1), interval(low, low))]),
            Ok(Progress::Done)
        );
    }
    let mut successor = Fencing::new(&record(), &session_at(3, 1), 0).unwrap();
    for at in 0..record().pages.get() {
        assert!((0..8).any(|_| successor.fence(&mut client, at) == Ok(Progress::Done)));
    }
    assert!(!successor.admits(&key(1), CacheVersion(2)));
    assert!(successor.admits(&key(1), CacheVersion(4)));
}

#[test]
fn acknowledging_an_unknown_outcome_fails_the_ack_on_commit_checks() {
    super::ACK_ON_UNKNOWN.with(|plant| plant.set(true));
    let oracle = acknowledgments(false);
    let crash = std::panic::catch_unwind(|| crash_at(Boundary::TimedOutAlive));
    super::ACK_ON_UNKNOWN.with(|plant| plant.set(false));
    assert_eq!(
        oracle,
        Err("an INVALIDATE was acknowledged before its page write was")
    );
    let payload = crash.expect_err("the crash boundary check fails");
    let message = payload
        .downcast_ref::<String>()
        .expect("the ACK-ON-COMMIT assertion formats its message");
    let lost = format!("{:?}: an acknowledged v3 lost", Boundary::TimedOutAlive);
    assert_eq!(
        message, &lost,
        "the acknowledged-version check, not another panic"
    );
}
