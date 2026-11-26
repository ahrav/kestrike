//! A fencing reports completion only with every page fenced.
//!
//! Each test scripts the simulated store, one arm per request, so that
//! some page of a shard record fences in the first `fence_all` pass while
//! another page stays unresolved: its read returns no value, its fence
//! write has an unknown outcome, or its fence write fails its condition.
//! The pass must report `Progress::Unresolved` and leave that page
//! unfenced, `Fencing::fenced` must refuse `FenceRefused::Unresolved`
//! naming the lowest unfenced page once its rounds are spent, and the
//! fresh activation must refuse `Check::UnresolvedPage` for the same page.
//!
//! A pass over the unfenced pages issues one read per page in page order,
//! then one write per page whose read returned a value, in page order. The
//! scripts below follow that order, and each test checks the store's
//! commit counts so that a script that reached other requests than the
//! ones it names fails.
//!
//! Each counterpart runs the same script with the unresolved page
//! resolving inside the rounds, and ends with every page fenced under the
//! tenure's session and the coverage present.
//!
//! Each test computes what the step left into plain values, lets the store
//! and the fixtures go, and asserts last.

use core::num::NonZeroU16;

use super::fresh::tests::{
    Card, Log, fresh_of, holder, plane, records, shard_record, volume_record,
};
use super::fresh::{Check, FENCE_ROUNDS, Refusals};
use super::records::ShardRecord;
use crate::storage::page_coverage::{FenceRefused, Fencing, Progress, Withdraw};
use crate::storage::session_at;
use crate::storage::store::Key;
use crate::storage::store::sim::{Arm, Shared};
use crate::storage::store_tests::{client, record, shard};

/// The intervals of one key the fencing keeps on a page; only the census test plants an interval, through the store.
const INTERVALS: usize = 4;

/// The requests a fresh activation issues before its first fencing pass.
const BEFORE_FENCING: usize = 5;

/// What a fencing holds, as plain values.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Held {
    /// Each page's known fence in page order, `None` while the page is unfenced.
    fences: Vec<Option<u64>>,
    complete: bool,
    /// `coverage()` is present, which opens FILL admission.
    coverage: bool,
}

fn held(fencing: &Fencing) -> Held {
    Held {
        fences: (0..fencing.pages().get())
            .map(|page| fencing.known(page).map(|read| read.value().fence))
            .collect(),
        complete: fencing.complete(),
        coverage: fencing.coverage().is_some(),
    }
}

/// A fencing with every page fenced under `own`.
fn all_fenced(own: u64, pages: usize) -> Held {
    Held {
        fences: vec![Some(own); pages],
        complete: true,
        coverage: true,
    }
}

/// The shard record of `store_tests` with `pages` coverage pages.
fn record_of(pages: u16) -> ShardRecord {
    ShardRecord {
        pages: NonZeroU16::new(pages).unwrap(),
        ..record()
    }
}

/// A store holding `record` and its pages, each page committed once.
fn seeded_with(record: ShardRecord) -> Shared {
    let store = Shared::new();
    client(&store).create_shard(record).unwrap();
    store
}

fn schedule(store: &Shared, arms: &[Arm]) {
    for &arm in arms {
        store.schedule(arm);
    }
}

/// The commits of each of the shard's first `pages` pages: 1 from the seeding, and one more per applied write.
fn commits(store: &Shared, pages: u16) -> Vec<usize> {
    (0..pages)
        .map(|page| store.0.borrow().commit_count(&Key::Page(shard(), page)))
        .collect()
}

/// `rounds` copies of `round`, one after another.
fn repeated(round: &[Arm], rounds: usize) -> Vec<Arm> {
    round.repeat(rounds)
}

/// The outcome of `Fencing::fenced` over a record of `pages` pages under the script `arms`, with the tenure's
/// session and each page's commits.
fn fenced_under(pages: u16, arms: &[Arm]) -> (Result<Held, FenceRefused>, u64, Vec<usize>) {
    let record = record_of(pages);
    let store = seeded_with(record);
    let session = session_at(record.generation.get(), 0);
    schedule(&store, arms);
    let outcome = Fencing::fenced(
        &mut client(&store),
        &record,
        &session,
        INTERVALS,
        FENCE_ROUNDS,
    )
    .map(|fencing| held(&fencing));
    (outcome, session.get(), commits(&store, pages))
}

/// Page 0 fences in the first round and page 1's read returns no value in every round: the refusal names
/// page 1, and page 1 was never written.
#[test]
fn a_read_with_no_value_in_every_round_refuses_unresolved_naming_that_page() {
    let mut arms = vec![Arm::Pass, Arm::Unavailable, Arm::Pass];
    arms.extend(repeated(&[Arm::Unavailable], FENCE_ROUNDS - 1));
    let (outcome, _, commits) = fenced_under(2, &arms);
    assert_eq!(
        commits,
        [2, 1],
        "the script fences page 0 once and writes page 1 never"
    );
    assert_eq!(
        outcome,
        Err(FenceRefused::Unresolved { page: 1 }),
        "page 1 is unfenced after the rounds, so the fencing is not complete"
    );
}

/// The same script with page 1's read returning its value in the last round: every page is fenced.
#[test]
fn a_read_that_returns_in_the_last_round_completes_the_fencing() {
    let mut arms = vec![Arm::Pass, Arm::Unavailable, Arm::Pass];
    arms.extend(repeated(&[Arm::Unavailable], FENCE_ROUNDS - 2));
    arms.extend([Arm::Pass, Arm::Pass]);
    let (outcome, own, commits) = fenced_under(2, &arms);
    assert_eq!(commits, [2, 2], "the script fences each page once");
    assert_eq!(outcome, Ok(all_fenced(own, 2)));
}

/// Page 1 fences in the first round and page 0's read returns no value in every round: the refusal names
/// page 0, so a fenced higher page does not complete the fencing either.
#[test]
fn an_unresolved_first_page_refuses_while_a_later_page_is_fenced() {
    let mut arms = vec![Arm::Unavailable, Arm::Pass, Arm::Pass];
    arms.extend(repeated(&[Arm::Unavailable], FENCE_ROUNDS - 1));
    let (outcome, _, commits) = fenced_under(2, &arms);
    assert_eq!(
        commits,
        [1, 2],
        "the script fences page 1 once and writes page 0 never"
    );
    assert_eq!(outcome, Err(FenceRefused::Unresolved { page: 0 }));
}

/// On three pages, page 0 fences in the first round and the reads of pages 1 and 2 return no value in every
/// round: the refusal names page 1, the lowest unfenced page.
#[test]
fn two_unresolved_pages_refuse_naming_the_lowest() {
    let mut arms = vec![Arm::Pass, Arm::Unavailable, Arm::Unavailable, Arm::Pass];
    arms.extend(repeated(
        &[Arm::Unavailable, Arm::Unavailable],
        FENCE_ROUNDS - 1,
    ));
    let (outcome, _, commits) = fenced_under(3, &arms);
    assert_eq!(commits, [2, 1, 1], "the script fences page 0 alone");
    assert_eq!(outcome, Err(FenceRefused::Unresolved { page: 1 }));
}

/// On three pages, pages 0 and 2 fence in the first round and page 1's fence write is unavailable in every
/// round, an unknown outcome that does not apply: the refusal names page 1 between two fenced pages.
#[test]
fn a_fence_write_with_an_unknown_outcome_in_every_round_refuses_unresolved() {
    let mut arms = vec![
        Arm::Pass,
        Arm::Pass,
        Arm::Pass,
        Arm::Pass,
        Arm::Unavailable,
        Arm::Pass,
    ];
    arms.extend(repeated(&[Arm::Pass, Arm::Unavailable], FENCE_ROUNDS - 1));
    let (outcome, _, commits) = fenced_under(3, &arms);
    assert_eq!(
        commits,
        [2, 1, 2],
        "the script fences pages 0 and 2 once and applies no write of page 1"
    );
    assert_eq!(outcome, Err(FenceRefused::Unresolved { page: 1 }));
}

/// The same script with page 1's fence write acknowledged in the last round: every page is fenced.
#[test]
fn a_fence_write_acknowledged_in_the_last_round_completes_the_fencing() {
    let mut arms = vec![
        Arm::Pass,
        Arm::Pass,
        Arm::Pass,
        Arm::Pass,
        Arm::Unavailable,
        Arm::Pass,
    ];
    arms.extend(repeated(&[Arm::Pass, Arm::Unavailable], FENCE_ROUNDS - 2));
    arms.extend([Arm::Pass, Arm::Pass]);
    let (outcome, own, commits) = fenced_under(3, &arms);
    assert_eq!(commits, [2, 2, 2], "the script fences each page once");
    assert_eq!(outcome, Ok(all_fenced(own, 3)));
}

/// One `fence_all` pass per cause the property names, on one fencing whose page 0 fenced in the first pass.
/// Page 1's fence write times out after it commits (an unknown outcome), then its read returns the version
/// before that commit so the write fails its condition, then its read returns no value, then its write is
/// unavailable. Every such pass reports `Unresolved` and leaves page 1 unfenced, the fencing incomplete and
/// the coverage absent. The next pass, with no fault, reports `Done` with every page fenced.
#[test]
fn each_unresolved_cause_reports_unresolved_and_keeps_the_page_unfenced() {
    const PASSES: [(&str, &[Arm]); 4] = [
        (
            "unknown outcome of a write that committed",
            &[
                Arm::Pass,
                Arm::Pass,
                Arm::Pass,
                Arm::Timeout { commit: true },
            ],
        ),
        ("failed condition", &[Arm::StaleRead, Arm::Pass]),
        ("read with no value", &[Arm::Unavailable]),
        (
            "unknown outcome of a write that did not apply",
            &[Arm::Pass, Arm::Unavailable],
        ),
    ];
    let record = record();
    let store = seeded_with(record);
    let session = session_at(record.generation.get(), 0);
    let own = session.get();
    let mut client = client(&store);
    let mut fencing = Fencing::new(&record, &session, INTERVALS).unwrap();
    let mut seen = Vec::new();
    for (cause, arms) in PASSES {
        schedule(&store, arms);
        let progress = fencing.fence_all(&mut client);
        seen.push((cause, progress, held(&fencing), commits(&store, 2)));
    }
    let last: Result<Progress, Withdraw> = fencing.fence_all(&mut client);
    let after = (last, held(&fencing), commits(&store, 2));
    drop((client, store));

    let unfenced = Held {
        fences: vec![Some(own), None],
        complete: false,
        coverage: false,
    };
    // Page 1's timed-out fence write is its second commit, and no unresolved pass adds another.
    let expected: Vec<_> = PASSES
        .iter()
        .map(|&(cause, _)| {
            (
                cause,
                Ok(Progress::Unresolved),
                unfenced.clone(),
                vec![2, 2],
            )
        })
        .collect();
    assert_eq!(
        seen, expected,
        "a pass that leaves page 1 unfenced reports Unresolved and adopts nothing for it"
    );
    assert_eq!(
        after,
        (Ok(Progress::Done), all_fenced(own, 2), vec![2, 3]),
        "the pass that fences page 1 reports Done"
    );
}

/// How a fresh activation over the two-page shard record ended under a script of the fencing's requests.
#[derive(Debug, PartialEq, Eq)]
struct Activation {
    /// The fencing the activation returned with whether each page's fence is the activation's session, or the
    /// refusing check.
    outcome: Result<(Held, bool), Check>,
    commits: Vec<usize>,
    /// The last refusal the activation recorded.
    recorded: Option<Check>,
}

fn activate_under(fencing_arms: &[Arm]) -> Activation {
    let store = super::fresh::tests::store(shard_record(0), volume_record());
    schedule(&store, &[Arm::Pass; BEFORE_FENCING]);
    schedule(&store, fencing_arms);
    let log = Log::default();
    let mut refusals = Refusals::default();
    let outcome = fresh_of(shard(), holder())
        .run(
            &mut client(&store),
            &mut plane(),
            &mut records(&log),
            &mut Card::new(&log),
            &mut refusals,
        )
        .map(|activated| {
            let held = held(activated.fencing());
            let own = Some(activated.session().get());
            let fenced_as_own = held.fences.iter().all(|&fence| fence == own);
            (held, fenced_as_own)
        })
        .map_err(|refused| refused.check);
    Activation {
        outcome,
        commits: commits(&store, 2),
        recorded: refusals.last,
    }
}

/// Through the fresh activation: page 0 fences in the first round and page 1's read returns no value in
/// every round, so the activation refuses `UnresolvedPage` for page 1 and records that refusal.
#[test]
fn a_fresh_activation_refuses_an_unresolved_page_after_its_rounds() {
    let mut arms = vec![Arm::Pass, Arm::Unavailable, Arm::Pass];
    arms.extend(repeated(&[Arm::Unavailable], FENCE_ROUNDS - 1));
    let activation = activate_under(&arms);
    assert_eq!(
        activation,
        Activation {
            outcome: Err(Check::UnresolvedPage { page: 1 }),
            commits: vec![2, 1],
            recorded: Some(Check::UnresolvedPage { page: 1 }),
        },
        "an activation with page 1 unfenced does not return a tenure"
    );
}

/// The same activation with page 1's read returning its value in the last round: it returns a tenure whose
/// fencing holds every page under the activation's session, with the coverage present.
#[test]
fn a_fresh_activation_completes_when_the_page_resolves_in_the_last_round() {
    let mut arms = vec![Arm::Pass, Arm::Unavailable, Arm::Pass];
    arms.extend(repeated(&[Arm::Unavailable], FENCE_ROUNDS - 2));
    arms.extend([Arm::Pass, Arm::Pass]);
    let activation = activate_under(&arms);
    let fences = activation
        .outcome
        .as_ref()
        .map(|(held, _)| held.fences.clone());
    let expected = Held {
        fences: fences.clone().unwrap_or_default(),
        complete: true,
        coverage: true,
    };
    assert_eq!(
        activation,
        Activation {
            outcome: Ok((expected, true)),
            commits: vec![2, 2],
            recorded: None,
        }
    );
    assert_eq!(
        fences.map(|fences| fences.iter().filter(|fence| fence.is_some()).count()),
        Ok(2),
        "both pages are fenced"
    );
}

/// The page census counts the saturated pages of the page count and the encoded bytes of the largest page of the
/// record's page capacity, over the pages the tenure fenced, and reads `None` before every page is known. A
/// saturated middle page counts one saturated page, a middle page that holds one interval is the largest while the
/// first and last pages stay empty, and a clean twin counts none at the empty page's size.
#[test]
fn the_page_census_counts_saturated_pages_and_the_largest_page() {
    use crate::failover::records::CoveragePage;
    use crate::storage::CacheVersion;
    use crate::storage::page_coverage::{Interval, encode_entries};
    let mut key = [0; 32];
    key[0] = 1;
    let interval = Interval::new(CacheVersion(3), CacheVersion(5)).unwrap();
    let grown = encode_entries(&[(key, interval)]);
    for (saturate, grow) in [(false, false), (true, false), (false, true)] {
        let record = record_of(3);
        let store = seeded_with(record);
        if saturate || grow {
            let page = Key::Page(shard(), 1);
            let mut writer = client(&store);
            let read = writer.read::<CoveragePage>(page).unwrap();
            let edited = CoveragePage {
                saturated: saturate,
                entries: if grow {
                    grown.clone()
                } else {
                    read.value().entries.clone()
                },
                ..read.value().clone()
            };
            writer.replace(&read, edited).unwrap();
        }
        let session = session_at(record.generation.get(), 0);
        let unfenced = Fencing::new(&record, &session, INTERVALS).unwrap();
        assert_eq!(unfenced.census(), None, "no page is known before the fence");
        let fencing = Fencing::fenced(
            &mut client(&store),
            &record,
            &session,
            INTERVALS,
            FENCE_ROUNDS,
        )
        .unwrap();
        let empty = CoveragePage::default().encoded_len();
        let largest = CoveragePage {
            entries: grown.clone(),
            ..CoveragePage::default()
        }
        .encoded_len();
        assert!(largest > empty, "the interval grows the page");
        assert_eq!(
            fencing.census(),
            Some(crate::storage::page_coverage::PageCensus {
                saturated: usize::from(saturate),
                pages: 3,
                largest: if grow { largest } else { empty },
                capacity: record.page_cap.get() as usize,
            }),
            "saturate: {saturate}, grow: {grow}"
        );
    }
}

/// The page census and the growth figures follow a known value that shrinks. Over three pages, page 0 takes four
/// intervals of one key and page 1 one interval of each of two keys, so page 0 is the largest. A fifth interval of
/// page 0's key, past the tenure's bound of four, replaces the key's intervals with their hull, and the largest
/// falls to page 1's two entries. A third entry on page 1 that the store rejects for size leaves page 1 saturated
/// and empty, and the largest falls to page 0's one entry beside one saturated page. A census whose largest only
/// rises fails at the hull.
#[test]
fn the_page_census_follows_a_page_that_shrinks() {
    use crate::storage::CacheVersion;
    use crate::storage::page_coverage::{Growth, Interval, PageCensus, page_len};
    let key = |n: u64| {
        let mut key = [n as u8; 32];
        key[..8].copy_from_slice(&n.to_le_bytes());
        key
    };
    let at = |version| Interval::new(CacheVersion(version), CacheVersion(version)).unwrap();
    let record = record_of(3);
    let store = seeded_with(record);
    let session = session_at(record.generation.get(), 0);
    let mut client = client(&store);
    let mut fencing =
        Fencing::fenced(&mut client, &record, &session, INTERVALS, FENCE_ROUNDS).unwrap();
    let mut figures = |fencing: &mut Fencing,
                       entries: &[([u8; 32], Interval)],
                       (saturated, largest, pairs): (usize, usize, usize)| {
        assert_eq!(fencing.cover_page(&mut client, entries), Ok(Progress::Done));
        assert_eq!(
            fencing.census(),
            Some(PageCensus {
                saturated,
                pages: 3,
                largest: page_len(largest),
                capacity: record.page_cap.get() as usize,
            }),
            "after {entries:?}"
        );
        assert_eq!(
            fencing.growth(),
            Growth {
                saturated_pages: saturated,
                largest_page_bytes: page_len(largest),
                pairs,
                held_saturated_pages: 0,
            },
            "after {entries:?}"
        );
    };
    let four = [1, 3, 5, 7].map(|version| (key(0), at(version)));
    figures(&mut fencing, &four, (0, 4, 4));
    figures(&mut fencing, &[(key(1), at(1)), (key(4), at(1))], (0, 4, 6));
    figures(&mut fencing, &[(key(0), at(9))], (0, 2, 3));
    store.0.borrow_mut().limit = page_len(2);
    figures(&mut fencing, &[(key(7), at(1))], (1, 1, 1));
}
