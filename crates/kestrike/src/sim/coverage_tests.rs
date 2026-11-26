//! Two tenures fence and write a shard's coverage pages through the simulated store.

use std::num::NonZeroU32;

use crate::failover::records::{CoveragePage, Record, ShardRecord};
use crate::storage::page_coverage::{
    Coverage, Entry, Fencing, Growth, Interval, Limits, Progress, Withdraw, decode_entries, merged,
    page_len, page_of,
};
use crate::storage::seeded::SplitMix64;
use crate::storage::store::sim::{Arm, MemLog, Shared};
use crate::storage::store::{Client, Key};
use crate::storage::store_tests::{client, page, record, seeded, shard};
use crate::storage::{CacheVersion, Session, session_at};

const INTERVALS: usize = 2;
const KEYS: u64 = 4;
const VERSIONS: u64 = 12;
const ARMS: [Arm; 11] = [
    Arm::Pass,
    Arm::Pass,
    Arm::Timeout { commit: true },
    Arm::Timeout { commit: false },
    Arm::Failure { commit: true },
    Arm::Failure { commit: false },
    Arm::Delay,
    Arm::Reorder,
    Arm::Hold,
    Arm::Duplicate,
    Arm::Unavailable,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mutant {
    None,
    AckOnSubmit,
    FenceOnRead,
    AdoptOnUnknown,
    FenceForgets,
    CoverAfterSubmit,
    DropEntries,
    FillBeforeFenced,
    AbsorbOnDone,
    AckWithoutWrite,
    AdoptOwnFenceOnRead,
    AckOnCommittedTimeout,
    ForgetAfterAck,
}

#[derive(Debug, Default)]
struct Reached {
    hull: bool,
    capped: bool,
    rejected: bool,
    complete: bool,
    deposed: bool,
    mid_fence_ack: bool,
    confirmed: bool,
}

fn replied(store: &Shared, at: u16) -> usize {
    store
        .0
        .borrow()
        .replied
        .get(&Key::Page(shard(), at))
        .copied()
        .unwrap_or(0)
}

fn earlier() -> Session {
    session_at(3, 0)
}

fn later() -> Session {
    session_at(3, 1)
}

fn key(n: u64) -> [u8; 32] {
    let mut key = [n as u8; 32];
    key[..8].copy_from_slice(&n.to_le_bytes());
    key
}

fn interval(low: u64, high: u64) -> Interval {
    Interval::new(CacheVersion(low), CacheVersion(high)).unwrap()
}

fn stored(store: &Shared) -> Coverage {
    let pages = record().pages;
    let values: Vec<_> = (0..pages.get()).map(|at| page(store, at)).collect();
    Coverage::of_pages(pages, &values)
}

fn fences(store: &Shared) -> Vec<u64> {
    (0..record().pages.get())
        .map(|at| page(store, at).fence)
        .collect()
}

fn covered(coverage: &Coverage, entries: &[Entry]) -> bool {
    entries.iter().all(|(key, interval)| {
        (interval.low().0..=interval.high().0).all(|v| coverage.covers(key, CacheVersion(v)))
    })
}

fn shrank(before: &Coverage, after: &Coverage) -> bool {
    (0..KEYS).any(|n| {
        (0..VERSIONS).any(|v| {
            before.covers(&key(n), CacheVersion(v)) && !after.covers(&key(n), CacheVersion(v))
        })
    })
}

fn fence(
    fencing: &mut Fencing,
    client: &mut Client<Shared, MemLog>,
    store: &Shared,
    mutant: Mutant,
    page: u16,
    arms: [Arm; 2],
    own: u64,
) -> Result<Progress, Withdraw> {
    if fencing.known(page).is_some() {
        return Ok(Progress::Done);
    }
    if mutant == Mutant::FenceOnRead
        || (mutant == Mutant::AdoptOwnFenceOnRead && self::page(store, page).fence == own)
    {
        return Ok(fencing.read_as_fenced(client, page));
    }
    for arm in arms {
        store.schedule(arm);
    }
    let before = fencing.partial().clone();
    let progress = fencing.fence(client, page);
    match (mutant, progress) {
        (Mutant::AdoptOnUnknown, Ok(Progress::Unresolved)) => {
            store.0.borrow_mut().unschedule();
            fencing.read_as_fenced(client, page);
        }
        (Mutant::FenceForgets, Ok(Progress::Done)) => fencing.replace_coverage(before),
        _ => {}
    }
    progress
}

fn cover(
    fencing: &mut Fencing,
    client: &mut Client<Shared, MemLog>,
    store: &Shared,
    mutant: Mutant,
    entry: Entry,
    arms: [Arm; 4],
) -> Result<Progress, Withdraw> {
    let at = page_of(&entry.0, record().pages);
    let unbounded = Limits {
        intervals: usize::MAX,
        page_bytes: usize::MAX,
    };
    if mutant == Mutant::AckWithoutWrite
        && let Some(known) = fencing.known(at)
        && merged(known.value(), entry, unbounded).as_ref() == Some(known.value())
    {
        return Ok(Progress::Done);
    }
    let before = fencing.clone();
    let commits = store.0.borrow().commit_count(&Key::Page(shard(), at));
    for arm in arms {
        store.schedule(arm);
    }
    let progress = fencing.cover_page(client, &[entry]);
    let committed = store.0.borrow().commit_count(&Key::Page(shard(), at)) > commits;
    match (mutant, progress) {
        (Mutant::CoverAfterSubmit, Ok(Progress::Unresolved)) => *fencing = before,
        (Mutant::AbsorbOnDone, Ok(Progress::Unresolved)) => {
            let mut coverage = before.partial().clone();
            coverage.insert(entry);
            fencing.replace_coverage(coverage);
        }
        _ => {}
    }
    match (mutant, progress) {
        (Mutant::AckOnSubmit, Ok(Progress::Unresolved)) => Ok(Progress::Done),
        (Mutant::AckOnCommittedTimeout, Ok(Progress::Unresolved)) if committed => {
            Ok(Progress::Done)
        }
        (_, progress) => progress,
    }
}

fn regime(seed: u64, store: &Shared) -> (ShardRecord, u64) {
    let regime = seed % 3;
    let shard_record = match regime {
        1 => ShardRecord {
            page_cap: NonZeroU32::new(page_len(2) as u32).unwrap(),
            ..record()
        },
        2 => {
            store.0.borrow_mut().limit = page_len(1);
            record()
        }
        _ => record(),
    };
    (shard_record, regime)
}

fn run(seed: u64, mutant: Mutant, reached: &mut Reached) -> Option<&'static str> {
    let mut rng = SplitMix64::new(seed);
    let store = seeded();
    let (shard_record, regime) = regime(seed, &store);
    let (mut first, mut second) = (client(&store), client(&store));
    let earlier_session = earlier().get();
    let mut earlier = Fencing::new(&shard_record, &earlier(), INTERVALS).unwrap();
    for at in 0..shard_record.pages.get() {
        assert_eq!(earlier.fence(&mut first, at), Ok(Progress::Done));
    }
    let later_session = later().get();
    let mut later = Fencing::new(&shard_record, &later(), INTERVALS).unwrap();
    let (mut acked, mut resident, mut own_fills) = (Vec::new(), Vec::new(), Vec::new());
    let mut deposed = false;
    let mut seen_fences = fences(&store);
    let mut seen_stored = stored(&store);
    let start = rng.below(8);
    for step in 0..24 {
        let arm = ARMS[rng.below(ARMS.len() as u64) as usize];
        let read_arm = [Arm::Pass, Arm::Unavailable][rng.below(2) as usize];
        let last_arm = ARMS[rng.below(ARMS.len() as u64) as usize];
        let last_read = [Arm::Pass, Arm::Unavailable][rng.below(2) as usize];
        let low = rng.below(8);
        let entry = (key(rng.below(KEYS)), interval(low, low + rng.below(3)));
        let fill = (key(rng.below(KEYS)), CacheVersion(rng.below(10)));
        let choice = rng.below(3);
        let held = (earlier.partial().clone(), later.partial().clone());
        if step >= start && choice == 0 && !later.complete() {
            let at = rng.below(u64::from(shard_record.pages.get())) as u16;
            let known = later.known(at).is_some();
            let shown = page(&store, at).fence == later_session;
            let replies = replied(&store, at);
            match fence(
                &mut later,
                &mut second,
                &store,
                mutant,
                at,
                [read_arm, arm],
                later_session,
            ) {
                Err(_) => return Some("UnexpectedWithdraw"),
                Ok(Progress::Unresolved) if later.known(at).is_some() => {
                    return Some("NoAdoptionFromUnknown");
                }
                Ok(Progress::Done)
                    if !known
                        && (page(&store, at).fence != later_session
                            || replied(&store, at) == replies) =>
                {
                    return Some("FenceOrder");
                }
                Ok(Progress::Done) => reached.confirmed |= !known && shown,
                Ok(Progress::Unresolved) => {}
            }
        } else if step >= start
            && choice == 1
            && (later.complete() || mutant == Mutant::FillBeforeFenced)
        {
            if !later.partial().covers(&fill.0, fill.1) {
                resident.push(fill);
            }
        } else if !deposed {
            let at = page_of(&entry.0, shard_record.pages);
            let replies = replied(&store, at);
            let arms = [arm, read_arm, last_arm, last_read];
            let covering = cover(&mut earlier, &mut first, &store, mutant, entry, arms);
            if !covered(earlier.partial(), &[entry]) {
                return Some("CoverBeforeSubmit");
            }
            own_fills.retain(|(key, version)| !earlier.partial().covers(key, *version));
            match covering {
                Ok(Progress::Done) => {
                    if replied(&store, at) == replies
                        || page(&store, at).fence != earlier_session
                        || !covered(&stored(&store), &[entry])
                    {
                        return Some("NoAckBeforeAuthoritative");
                    }
                    reached.mid_fence_ack |= later.known(0).is_some() != later.known(1).is_some();
                    if mutant == Mutant::ForgetAfterAck && !acked.is_empty() {
                        let empty =
                            Fencing::new(&shard_record, &self::earlier(), INTERVALS).unwrap();
                        earlier.replace_coverage(empty.partial().clone());
                    }
                    acked.push(entry);
                    if mutant == Mutant::DropEntries
                        && let Some(known) = earlier.known(at).cloned()
                    {
                        let emptied = CoveragePage {
                            entries: Vec::new(),
                            ..known.value().clone()
                        };
                        let _ = first.replace(&known, emptied);
                    }
                }
                Ok(Progress::Unresolved) => {
                    if !earlier.partial().covers(&fill.0, fill.1) {
                        own_fills.push(fill);
                    }
                }
                Err(Withdraw::NewerFence { fence, .. }) if fence == later_session => {
                    deposed = true;
                    reached.deposed = true;
                }
                Err(_) => return Some("UnexpectedWithdraw"),
            }
        }
        store.0.borrow_mut().unschedule();
        store.release();
        let now = fences(&store);
        let authoritative = stored(&store);
        for at in 0..shard_record.pages.get() {
            let value = page(&store, at);
            reached.capped |= value.saturated && regime == 1;
            reached.rejected |= value.saturated && regime == 2;
            reached.hull |= decode_entries(&value.entries)
                .unwrap()
                .iter()
                .any(|(_, held)| held.high().0 - held.low().0 > 2);
        }
        reached.complete |= later.complete();
        if now.iter().zip(&seen_fences).any(|(now, seen)| now < seen)
            || !covered(&authoritative, &acked)
            || shrank(&seen_stored, &authoritative)
        {
            return Some("CoverageNeverDecreases");
        }
        if shrank(&held.0, earlier.partial()) || shrank(&held.1, later.partial()) {
            return Some("CoverageNeverDecreases: memory");
        }
        seen_fences = now;
        if later.complete() && !covered(later.partial(), &acked) {
            return Some("FencedCoverageComplete");
        }
        if resident
            .iter()
            .any(|(key, version)| acked.iter().any(|(k, i)| k == key && i.contains(*version)))
        {
            return Some("NoCoveredResidency: successor");
        }
        if own_fills
            .iter()
            .any(|(key, version)| authoritative.covers(key, *version))
        {
            return Some("NoCoveredResidency: own fill");
        }
        seen_stored = authoritative;
    }
    None
}

#[test]
fn coverage_oracles_and_mutations() {
    let mut reached = Reached::default();
    for seed in 0..400 {
        assert_eq!(run(seed, Mutant::None, &mut reached), None, "seed {seed}");
    }
    assert!(
        reached.hull
            && reached.capped
            && reached.rejected
            && reached.complete
            && reached.deposed
            && reached.mid_fence_ack
            && reached.confirmed,
        "{reached:?}"
    );
    for (mutant, oracle) in [
        (Mutant::AckOnSubmit, "NoAckBeforeAuthoritative"),
        (Mutant::FenceOnRead, "FenceOrder"),
        (Mutant::AdoptOnUnknown, "NoAdoptionFromUnknown"),
        (Mutant::FenceForgets, "FencedCoverageComplete"),
        (Mutant::CoverAfterSubmit, "CoverBeforeSubmit"),
        (Mutant::DropEntries, "CoverageNeverDecreases"),
        (Mutant::FillBeforeFenced, "NoCoveredResidency: successor"),
        (Mutant::AbsorbOnDone, "NoCoveredResidency: own fill"),
        (Mutant::AckWithoutWrite, "NoAckBeforeAuthoritative"),
        (Mutant::AdoptOwnFenceOnRead, "FenceOrder"),
        (Mutant::AckOnCommittedTimeout, "NoAckBeforeAuthoritative"),
        (Mutant::ForgetAfterAck, "CoverageNeverDecreases: memory"),
    ] {
        assert!(
            (0..400).any(|seed| run(seed, mutant, &mut Reached::default()) == Some(oracle)),
            "{mutant:?} escaped {oracle}"
        );
    }
}

#[test]
fn over_approximation_before_submit() {
    let store = seeded();
    let mut writer = client(&store);
    let mut fencing = Fencing::new(&record(), &earlier(), INTERVALS).unwrap();
    for at in 0..2 {
        assert_eq!(fencing.fence(&mut writer, at), Ok(Progress::Done));
    }
    let hulled = key(2);
    assert_eq!(page_of(&hulled, record().pages), 0);
    for low in [1, 5] {
        assert_eq!(
            fencing.cover_page(&mut writer, &[(hulled, interval(low, low))]),
            Ok(Progress::Done)
        );
    }
    store.schedule(Arm::Hold);
    assert_eq!(
        fencing.cover_page(&mut writer, &[(hulled, interval(9, 9))]),
        Ok(Progress::Unresolved)
    );
    for version in 1..=9 {
        assert!(
            fencing.partial().covers(&hulled, CacheVersion(version)),
            "hull {version}"
        );
    }
    assert!(!stored(&store).covers(&hulled, CacheVersion(9)));
    store.release();
    assert!(stored(&store).covers(&hulled, CacheVersion(3)));
    assert_eq!(
        fencing.growth(),
        Growth {
            saturated_pages: 0,
            largest_page_bytes: page_len(2),
            pairs: 2,
            held_saturated_pages: 0,
        },
        "the growth monitor counts the pages the tenure knows committed"
    );

    let store = seeded();
    let mut writer = client(&store);
    let empty_cap = ShardRecord {
        page_cap: NonZeroU32::new(page_len(0) as u32).unwrap(),
        ..record()
    };
    let mut fencing = Fencing::new(&empty_cap, &earlier(), INTERVALS).unwrap();
    for at in 0..2 {
        assert_eq!(fencing.fence(&mut writer, at), Ok(Progress::Done));
    }
    let saturating = key(1);
    assert_eq!(page_of(&saturating, record().pages), 1);
    store.schedule(Arm::Hold);
    assert_eq!(
        fencing.cover_page(&mut writer, &[(saturating, interval(4, 4))]),
        Ok(Progress::Unresolved)
    );
    assert!(fencing.partial().covers(&key(3), CacheVersion(0)));
    assert!(!stored(&store).covers(&key(3), CacheVersion(0)));
    store.release();
    assert!(page(&store, 1).saturated);

    let store = seeded();
    let mut writer = client(&store);
    let mut fencing = Fencing::new(&record(), &earlier(), INTERVALS).unwrap();
    for at in 0..2 {
        assert_eq!(fencing.fence(&mut writer, at), Ok(Progress::Done));
    }
    let rejected = key(5);
    assert_eq!(page_of(&rejected, record().pages), 1);
    store.0.borrow_mut().limit = page(&store, 1).encode().len();
    store.schedule(Arm::Pass);
    store.schedule(Arm::Pass);
    store.schedule(Arm::Hold);
    let entry = (rejected, interval(2, 2));
    assert_eq!(
        fencing.cover_page(&mut writer, &[entry]),
        Ok(Progress::Unresolved)
    );
    assert!(fencing.partial().covers(&key(7), CacheVersion(1)));
    assert!(!page(&store, 1).saturated);
    store.release();
    assert!(page(&store, 1).saturated);
    let unsaturated = Growth {
        saturated_pages: 0,
        largest_page_bytes: page_len(0),
        pairs: 0,
        held_saturated_pages: 1,
    };
    assert_eq!(
        fencing.growth(),
        unsaturated,
        "the in-memory saturation shows before the tenure knows the page saturated"
    );
    assert_eq!(
        fencing.cover_page(&mut writer, &[entry]),
        Ok(Progress::Done),
        "the stale basis is rejected on size, and the saturated write goes on the re-read"
    );
    assert_eq!(
        fencing.growth(),
        Growth {
            saturated_pages: 1,
            held_saturated_pages: 0,
            ..unsaturated
        }
    );
}
