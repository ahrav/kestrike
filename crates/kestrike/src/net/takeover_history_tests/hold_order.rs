//! A fault-free history of two takeovers in which the first successor publishes an object between the held
//! INVALIDATEs of its key, judged by the history oracle and by what the second successor serves.
//!
//! The property is the retention the takeover histories judge by the oracle's rule "a retained entry outside every
//! damage set was lost on host loss": an object a tenure published and acknowledged before its boundary, whose
//! version no acknowledged INVALIDATE covers and whose units no fault touched, is served its exact bytes by the
//! next tenure.
//!
//! The history. Tenure A leaves objects 1 to 4 in its checkpoint and is lost. C takes the shard over, loads warm,
//! opens its suffix and serves. C's owner takes four INVALIDATEs of the key of object 9, of versions 1, 5, 9 and 13,
//! each acknowledged by its page write, so the key holds four intervals, the bound of this world's fencing. C's
//! owner then holds a burst: the key's versions 17 and 30 and a number of other keys that no object has, spread
//! over the two coverage pages. With all of them held the coverage admits the key at version 20, and C publishes
//! object 9 at version 20 through `Owner::publish_fill` and serves it. `Owner::cover_pending` writes the pages and
//! acknowledges the burst. C runs a capture pass, which seals its suffix records, serves object 9 once more, runs
//! until its device is quiet and is lost. The reconciler designates a fresh host D, which takes the shard over by
//! `Takeover::run`, loads warm and reads every object.
//!
//! No INVALIDATE names version 20 of the key, so D must serve object 9. A page write merges a page's entries in
//! the order it is given them, and the interval a fifth entry of one key joins depends on that order: held as
//! version 17 and then version 30, the key's intervals are [1, 17] and [30, 30]; merged as version 30 and then
//! version 17, they are the hull [1, 30], which covers version 20. D serves object 9 only when the page write
//! merges a page's entries in the order they were held, whatever the length of the burst.
//!
//! The INVALIDATEs of this history name versions other than the published one and keys of no object, and the
//! world's history event for an INVALIDATE means the world's own interval [0, 0], so the history handed to the
//! oracle holds none of them; each test also asserts directly that D serves object 9.

use super::*;
use crate::storage::page_coverage::{Interval, page_of};
use crate::storage::{CacheVersion, WorkBudget};

/// The object the first successor publishes: no object of tenure A's cut.
const MEMBER: u8 = 9;
/// The version it is published at: between the two INVALIDATEs of its key that the burst holds.
const PUBLISHED: CacheVersion = CacheVersion(20);

/// What one run of the history saw.
#[derive(Debug)]
struct Seen {
    /// The INVALIDATEs held when the burst's page writes ran.
    pending: usize,
    /// The objects the publishing tenure served in its last sweep, after every INVALIDATE was acknowledged.
    writer_served: Vec<u8>,
    /// Whether that tenure's coverage covered the published version after the page writes.
    covered: bool,
    /// The outcome of the next successor's warm load.
    outcome: MetadataOutcome,
    /// The objects the next successor served in its sweep.
    successor_served: Vec<u8>,
    /// The history oracle's verdict on the whole history when it is no pass.
    oracle: Option<String>,
}

fn one(version: u64) -> Interval {
    Interval::new(CacheVersion(version), CacheVersion(version)).expect("an ordered interval")
}

/// The `i`th other key: a key of page `page` that no object of the history has.
fn other_key(i: u64, pages: std::num::NonZeroU16, page: u16) -> [u8; 32] {
    let found = (0..1 << 16).find_map(|salt: u64| {
        let mut bytes = [0xEE; 32];
        bytes[..8].copy_from_slice(&((1 << 40) + (i << 16) + salt).to_le_bytes());
        let fresh = (1..=u8::MAX).all(|n| object_key(n) != bytes);
        (page_of(&bytes, pages) == page && fresh).then_some(bytes)
    });
    found.expect("premise: some key of the family lives on the page")
}

/// The owner takes INVALIDATE(`key`, `interval`) and holds it toward its page write.
fn hold(serving: &mut Serving<'_>, key: &[u8; 32], interval: Interval) {
    let mut budget = WorkBudget::new(1 << 20);
    (serving.owner)
        .invalidate_interval(key, interval, 4, &mut budget)
        .expect("premise: the owner takes the INVALIDATE");
}

/// Whether the tenure's coverage covers `version` of `key`.
fn covered(serving: &mut Serving<'_>, key: &[u8; 32], version: CacheVersion) -> bool {
    (serving.owner.coverage_mut())
        .expect("premise: the tenure's fencing is installed")
        .coverage()
        .expect("premise: every page is fenced")
        .covers(key, version)
}

/// Runs the held INVALIDATEs through their page writes; returns how many the owner acknowledged.
fn acknowledge(world: &World, serving: &mut Serving<'_>) -> usize {
    let mut acknowledged = Vec::new();
    for _ in 0..64 {
        let now = serving.step();
        let mut client = store_client(&world.records);
        (serving.owner)
            .cover_pending(&mut client, &mut acknowledged, now)
            .expect("premise: the tenure keeps its fencing");
        if serving.owner.held_invalidations() == 0 {
            break;
        }
    }
    acknowledged.len()
}

/// A whole capture pass, whose start seals the tenure's suffix records, then ticks until no device command is
/// pending.
fn seal(serving: &mut Serving<'_>) {
    let counter = (serving.storage.start_capture(1024, true, 1024))
        .expect("premise: the tenure starts a capture pass");
    while (serving.storage.capture_visit(counter, 64, |_| {})).expect("premise: a capture batch")
        > 0
    {}
    crate::storage::finish_test_capture(serving.storage, counter)
        .expect("premise: the pass finishes");
    for _ in 0..400 {
        serving.step();
    }
    assert_eq!(
        serving.control.pending(),
        0,
        "premise: the tenure's device is quiet before the host is lost"
    );
}

/// Runs the module's history. The burst holds the member's two INVALIDATEs and `others` INVALIDATEs of other keys,
/// whose pages `arrangement` chooses.
fn run(others: u64, arrangement: u8) -> Seen {
    let mut world = World::new(4, false);
    let (taken, _) = world.takeover(c_host());
    let taken = taken.expect("premise: C's takeover");
    let (pending, writer_served, covered) = serve(
        &mut world,
        taken,
        Source::Named,
        |world, serving, outcome| {
            assert_eq!(outcome, MetadataOutcome::Open, "premise: C loads warm");
            assert!(
                serving.open_suffix(&world.records),
                "premise: C's suffix opens"
            );
            let pages = restart_tests::shard_now(&world.records).pages;
            let member = object_key(MEMBER);
            let own = page_of(&member, pages);
            let other = (own + 1) % pages.get();

            // Four acknowledged INVALIDATEs of the member's key: its intervals reach the bound.
            for version in [1, 5, 9, 13] {
                hold(serving, &member, one(version));
                assert_eq!(
                    acknowledge(world, serving),
                    1,
                    "premise: the owner acknowledges the INVALIDATE of version {version}"
                );
            }
            assert!(
                !covered(serving, &member, CacheVersion(3)),
                "premise: four intervals of one key are kept apart"
            );

            // The burst, held and not yet written.
            hold(serving, &member, one(17));
            assert!(
                covered(serving, &member, CacheVersion(3)) && !covered(serving, &member, PUBLISHED),
                "premise: the fifth interval makes the hull [1, 17]"
            );
            hold(serving, &member, one(30));
            for i in 0..others {
                let page = match arrangement {
                    0 => [other, own][(i % 2) as usize],
                    1 => [own, other][(i % 2) as usize],
                    2 => [other, own, own][(i % 3) as usize],
                    _ => [own, other, other][(i % 3) as usize],
                };
                hold(serving, &other_key(i, pages, page), one(1));
            }
            let pending = serving.owner.held_invalidations();
            assert!(
                !covered(serving, &member, PUBLISHED),
                "premise: with every INVALIDATE held the coverage admits the member at version 20"
            );

            // The member is published at version 20 under the open suffix and served.
            assert!(
                serving.fill_at(world, MEMBER, PUBLISHED),
                "premise: the owner publishes the member at version 20"
            );
            assert!(
                serving.read_all(world).contains(&MEMBER),
                "premise: the owner serves the member"
            );

            // The page writes acknowledge the burst.
            assert_eq!(
                acknowledge(world, serving),
                pending,
                "premise: every held INVALIDATE is acknowledged"
            );
            // A capture pass over the tenure's membership seals the tenure's suffix records, and the tenure
            // runs on until its device is quiet, as a tenure of the cycle histories does before its cut.
            seal(serving);
            // The fill joins the retained set on its payload unit, as the cycle histories' `join_fills` records
            // a FILL of a tenure that reached its boundary.
            let fingerprint = (serving.storage.fingerprint_of(&member))
                .expect("premise: the member's key routes")
                .2;
            let resident = serving.resident();
            let unit = (resident.iter().find(|(of, _)| *of == fingerprint))
                .expect("premise: the member is resident at the tenure's end")
                .1 as u32;
            let object = world.objects.iter_mut().find(|object| object.n == MEMBER);
            object.expect("premise: the published fill").units = Some((unit, unit));
            world.events.push(Event::Captured {
                n: MEMBER,
                label: first(MEMBER),
                units: (unit, unit),
                cut: super::CUT,
            });
            let served = serving.read_all(world);
            (pending, served, covered(serving, &member, PUBLISHED))
        },
    );

    // C's host is lost. The reconciler designates a fresh host, which takes the shard over and loads warm.
    world.designate_fresh();
    let (taken, _) = world.takeover(d_host());
    let taken = taken.expect("premise: D's takeover");
    let (outcome, successor_served) = serve(
        &mut world,
        taken,
        Source::Named,
        |world, serving, outcome| (outcome, serving.read_all(world)),
    );
    let oracle = match world.judged() {
        Ok(_) => None,
        Err(verdict) => Some(format!("{verdict:?}")),
    };
    Seen {
        pending,
        writer_served,
        covered,
        outcome,
        successor_served,
        oracle,
    }
}

/// Sibling: the same history with a burst of 20 held INVALIDATEs, in each arrangement of the two pages. The lost
/// tenure's coverage does not cover the member after the page writes, the successor serves the member, and the
/// oracle passes the history.
#[test]
fn a_takeover_after_a_burst_of_twenty_serves_the_member() {
    for arrangement in 0..4 {
        let seen = run(18, arrangement);
        assert_eq!(seen.pending, 20, "premise: {seen:?}");
        assert!(
            seen.writer_served.contains(&MEMBER) && !seen.covered,
            "arrangement {arrangement}: {seen:?}"
        );
        assert_eq!(
            seen.outcome,
            MetadataOutcome::Open,
            "arrangement {arrangement}: {seen:?}"
        );
        assert!(
            seen.successor_served.contains(&MEMBER) && seen.oracle.is_none(),
            "arrangement {arrangement}: {seen:?}"
        );
    }
}

/// A takeover serves the member after bursts of 21, 22, 24 and 32 held INVALIDATEs, none of which names version 20
/// of the member's key, in each arrangement of the two pages. The lost tenure published the member, served it to
/// its end and recorded it in its suffix, and no fault touched it, so it is a retained entry: the successor's warm
/// load opens, the successor serves the member, and the oracle passes the history.
#[test]
fn a_takeover_serves_a_member_published_after_the_last_invalidate_of_its_key() {
    for others in [19, 20, 22, 30] {
        for arrangement in 0..4 {
            let seen = run(others, arrangement);
            assert!(
                seen.writer_served.contains(&MEMBER),
                "premise: the lost tenure served the member to its end: {seen:?}"
            );
            assert_eq!(
                seen.outcome,
                MetadataOutcome::Open,
                "premise: the successor's warm load opens: {seen:?}"
            );
            assert!(
                seen.successor_served.contains(&MEMBER),
                "a fault-free takeover lost object {MEMBER}, which the lost tenure published at version 20 after \
                 its last INVALIDATE of the key, with all {} INVALIDATEs of the burst held, and served until \
                 its end; no INVALIDATE names version 20. The lost tenure's coverage covered it after the page \
                 writes: {}. Burst of {others} other keys, arrangement {arrangement}. {seen:?}",
                seen.pending,
                seen.covered
            );
            assert!(
                seen.oracle.is_none(),
                "the history oracle fails the history: {seen:?}"
            );
        }
    }
}
