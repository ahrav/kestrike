//! After the store rejected a coverage write of a page, the tenure re-reads the page and writes it saturated
//! with its fence on the known version; the saturation enters the coverage before the write is submitted. A
//! rejection of the saturated write withdraws the tenure.
//!
//! Every test runs one tenure that fenced both pages of a seeded sim store, and lowers the store's item size
//! limit so that the store rejects the merged page of one entry. The expected values come from the scenario:
//! the fence is the session the tenure was built from, the page bytes are the scenario's own encoding of its
//! entry, and the versions are compared with the ones read before the step.
//!
//! - `a_rejected_merged_write_saturates_the_page_and_the_tenure_serves_on`: the limit admits the empty page
//!   only. The cover returns `Done`, the stored page is saturated under the tenure's fence at a later version,
//!   every version of another key on that page is refused, and a cover on the other page is served.
//! - `the_saturation_is_held_before_its_write_is_acknowledged`: the saturated write's outcome is unknown and
//!   it does not commit. The stored page is unchanged and the tenure already refuses every key on the page.
//! - `a_rejection_on_a_stale_basis_saturates_the_current_version`: an earlier cover timed out and committed,
//!   so the rejected write's basis is stale. The saturated write lands on the current version.
//! - `a_rejected_saturated_write_withdraws_and_latches`: the limit is below the empty page, so the store
//!   rejects the saturated write too. The tenure withdraws and every later call returns that withdrawal.
//! - `a_merged_write_within_the_limit_commits_its_entry_unsaturated`: the sibling. The same steps with the
//!   limit left alone commit the entry, and only the entry's versions are refused.
//!
//! Each test decides its observations into a value, drops the store, the client and the tenure, and asserts
//! last, so a failed check ends in the test's own result line.

use super::cache::coverage::{
    ENTRY_LEN, Entry, Fencing, Growth, Interval, Progress, Withdraw, page_len, page_of,
};
use super::store::sim::{Arm, MemLog, Shared};
use super::store::{Client, Key, Refusal, StoreError, Version};
use super::store_tests::{page, record, seeded, shard};
use super::{CacheVersion, Session, session_at};

/// The interval bound of the tenure: one entry of one key stays an entry.
const INTERVALS: usize = 4;

/// Versions asked of admission: version 0, then one below, one inside and one above the covered interval
/// `[5, 9]`, and the largest.
const ASKED: [u64; 5] = [0, 4, 7, 10, u64::MAX];

/// The session of the tenure, at the generation of the seeded shard record.
fn session() -> Session {
    session_at(3, 0)
}

/// A key on page `page` of the seeded record's two pages; `tail` tells keys of one page apart.
fn key_on(page: u16, tail: u8) -> [u8; 32] {
    let mut key = [tail; 32];
    key[..8].copy_from_slice(&u64::from(page).to_le_bytes());
    key
}

/// The entry that blocks versions 5 through 9 of `key`.
fn blocked(key: [u8; 32]) -> Entry {
    (
        key,
        Interval::new(CacheVersion(5), CacheVersion(9)).expect("5 is below 9"),
    )
}

/// The entry bytes of a page that holds `blocked(key)` alone: the key, then the bounds as little-endian words.
fn encoded(key: [u8; 32]) -> Vec<u8> {
    let mut bytes = key.to_vec();
    bytes.extend_from_slice(&5u64.to_le_bytes());
    bytes.extend_from_slice(&9u64.to_le_bytes());
    bytes
}

/// The store, a client of it and a tenure, with the result of fencing each page.
struct World {
    store: Shared,
    client: Client<Shared, MemLog>,
    fencing: Fencing,
    fenced: Vec<Result<Progress, Withdraw>>,
}

fn world() -> World {
    let store = seeded();
    let mut client =
        Client::open(store.clone(), MemLog::default()).expect("the log holds a watermark");
    let mut fencing =
        Fencing::new(&record(), &session(), INTERVALS).expect("the session is the record's");
    let fenced = (0..record().pages.get())
        .map(|at| fencing.fence(&mut client, at))
        .collect();
    World {
        store,
        client,
        fencing,
        fenced,
    }
}

impl World {
    fn commits(&self, at: u16) -> usize {
        self.store.0.borrow().commit_count(&Key::Page(shard(), at))
    }

    fn known(&self, at: u16) -> Option<Version> {
        self.fencing.known(at).map(|read| read.version())
    }

    fn set_limit(&self, limit: usize) {
        self.store.0.borrow_mut().limit = limit;
    }

    /// Whether admission admits each version of `ASKED` for `key`.
    fn admits(&self, key: &[u8; 32]) -> [bool; 5] {
        ASKED.map(|version| self.fencing.admits(key, CacheVersion(version)))
    }

    /// The stored page `at`: its fence, whether it is saturated, and its entry bytes.
    fn stored(&self, at: u16) -> (u64, bool, Vec<u8>) {
        let stored = page(&self.store, at);
        (stored.fence, stored.saturated, stored.entries)
    }
}

/// The premises every test shares: both pages fenced, and the keys on the pages the test names.
fn premises(fenced: &[Result<Progress, Withdraw>], on_one: &[[u8; 32]], on_zero: &[[u8; 32]]) {
    assert_eq!(
        fenced,
        [Ok(Progress::Done); 2],
        "premise: the tenure fenced both pages"
    );
    for key in on_one {
        assert_eq!(
            page_of(key, record().pages),
            1,
            "premise: the key is on page 1"
        );
    }
    for key in on_zero {
        assert_eq!(
            page_of(key, record().pages),
            0,
            "premise: the key is on page 0"
        );
    }
}

const REFUSED: [bool; 5] = [false; 5];
const ADMITTED: [bool; 5] = [true; 5];
/// Admission of a key that holds the interval `[5, 9]` alone: the versions inside it are refused, and so is
/// version 0, which admission refuses while its key holds any interval.
const INTERVAL_REFUSED: [bool; 5] = [false, true, false, true, true];

#[test]
fn a_rejected_merged_write_saturates_the_page_and_the_tenure_serves_on() {
    #[derive(Debug, PartialEq)]
    struct Seen {
        covered: Result<Progress, Withdraw>,
        stored: (u64, bool, Vec<u8>),
        later_version: bool,
        commits: usize,
        serving: bool,
        other_key: [bool; 5],
        covered_key: [bool; 5],
        other_page: [bool; 5],
        other_page_covered: Result<Progress, Withdraw>,
        other_page_stored: (u64, bool, Vec<u8>),
    }
    let (covered_key, other_key, other_page) = (key_on(1, 0x41), key_on(1, 0x42), key_on(0, 0x43));
    let mut world = world();
    let roomy = world.store.0.borrow().limit;
    let admitted_before = (world.admits(&other_key), world.admits(&other_page));
    let (known_before, commits_before) = (world.known(1), world.commits(1));
    world.set_limit(page_len(0));
    let covered = world
        .fencing
        .cover_page(&mut world.client, &[blocked(covered_key)]);
    let known_after = world.known(1);
    let mut seen = Seen {
        covered,
        stored: world.stored(1),
        later_version: known_before.is_some() && known_after > known_before,
        commits: world.commits(1) - commits_before,
        serving: world.fencing.coverage().is_some(),
        other_key: world.admits(&other_key),
        covered_key: world.admits(&covered_key),
        other_page: world.admits(&other_page),
        other_page_covered: Ok(Progress::Unresolved),
        other_page_stored: (0, false, Vec::new()),
    };
    world.set_limit(roomy);
    seen.other_page_covered = world
        .fencing
        .cover_page(&mut world.client, &[blocked(other_page)]);
    seen.other_page_stored = world.stored(0);
    let fenced = world.fenced.clone();
    drop(world);
    premises(&fenced, &[covered_key, other_key], &[other_page]);
    assert_eq!(
        admitted_before,
        (ADMITTED, ADMITTED),
        "premise: before the cover the tenure admits every asked version of the uncovered keys"
    );
    assert_eq!(
        seen,
        Seen {
            covered: Ok(Progress::Done),
            stored: (session().get(), true, Vec::new()),
            later_version: true,
            commits: 1,
            serving: true,
            other_key: REFUSED,
            covered_key: REFUSED,
            other_page: ADMITTED,
            other_page_covered: Ok(Progress::Done),
            other_page_stored: (session().get(), false, encoded(other_page)),
        },
        "a size rejection of the merged write saturates the page under the tenure's fence and the tenure serves on"
    );
}

#[test]
fn the_saturation_is_held_before_its_write_is_acknowledged() {
    #[derive(Debug, PartialEq)]
    struct Seen {
        covered: Result<Progress, Withdraw>,
        stored_saturated: bool,
        commits: usize,
        serving: bool,
        other_key: [bool; 5],
        other_page: [bool; 5],
        held_saturated_pages: usize,
        retried: Result<Progress, Withdraw>,
        retried_stored: (u64, bool, Vec<u8>),
        retried_growth: Growth,
    }
    let (covered_key, other_key, other_page) = (key_on(1, 0x41), key_on(1, 0x42), key_on(0, 0x43));
    let mut world = world();
    let commits_before = world.commits(1);
    world.set_limit(page_len(0));
    // The merged write is rejected on its size, the re-read passes, and the saturated write's outcome is
    // unknown with nothing committed.
    for arm in [Arm::Pass, Arm::Pass, Arm::Timeout { commit: false }] {
        world.store.schedule(arm);
    }
    let covered = world
        .fencing
        .cover_page(&mut world.client, &[blocked(covered_key)]);
    let mut seen = Seen {
        covered,
        stored_saturated: world.stored(1).1,
        commits: world.commits(1) - commits_before,
        serving: world.fencing.coverage().is_some(),
        other_key: world.admits(&other_key),
        other_page: world.admits(&other_page),
        held_saturated_pages: world.fencing.growth().held_saturated_pages,
        retried: Ok(Progress::Unresolved),
        retried_stored: (0, false, Vec::new()),
        retried_growth: Growth::default(),
    };
    seen.retried = world
        .fencing
        .cover_page(&mut world.client, &[blocked(covered_key)]);
    seen.retried_stored = world.stored(1);
    seen.retried_growth = world.fencing.growth();
    let fenced = world.fenced.clone();
    drop(world);
    premises(&fenced, &[covered_key, other_key], &[other_page]);
    assert_eq!(
        seen,
        Seen {
            covered: Ok(Progress::Unresolved),
            stored_saturated: false,
            commits: 0,
            serving: true,
            other_key: REFUSED,
            other_page: ADMITTED,
            held_saturated_pages: 1,
            retried: Ok(Progress::Done),
            retried_stored: (session().get(), true, Vec::new()),
            retried_growth: Growth {
                saturated_pages: 1,
                largest_page_bytes: page_len(0),
                pairs: 0,
                held_saturated_pages: 0,
            },
        },
        "the saturation enters the coverage before the saturated write is acknowledged"
    );
}

#[test]
fn a_rejection_on_a_stale_basis_saturates_the_current_version() {
    #[derive(Debug, PartialEq)]
    struct Seen {
        timed_out: Result<Progress, Withdraw>,
        timed_out_commits: usize,
        basis_stale: bool,
        covered: Result<Progress, Withdraw>,
        stored: (u64, bool, Vec<u8>),
        later_version: bool,
        commits: usize,
        serving: bool,
        first_key: [bool; 5],
        other_key: [bool; 5],
    }
    let (first_key, second_key, other_key) = (key_on(1, 0x41), key_on(1, 0x42), key_on(1, 0x44));
    let mut world = world();
    let (fenced_version, commits_before) = (world.known(1), world.commits(1));
    world.store.schedule(Arm::Timeout { commit: true });
    let timed_out = world
        .fencing
        .cover_page(&mut world.client, &[blocked(first_key)]);
    let (timed_out_commits, stale) = (world.commits(1) - commits_before, world.known(1));
    let committed_entry = world.stored(1).2 == encoded(first_key);
    world.set_limit(page_len(0));
    let covered = world
        .fencing
        .cover_page(&mut world.client, &[blocked(second_key)]);
    let seen = Seen {
        timed_out,
        timed_out_commits,
        basis_stale: committed_entry && stale.is_some() && stale == fenced_version,
        covered,
        stored: world.stored(1),
        later_version: world.known(1) > stale,
        commits: world.commits(1) - commits_before,
        serving: world.fencing.coverage().is_some(),
        first_key: world.admits(&first_key),
        other_key: world.admits(&other_key),
    };
    let fenced = world.fenced.clone();
    drop(world);
    premises(&fenced, &[first_key, second_key, other_key], &[]);
    assert_eq!(
        seen,
        Seen {
            timed_out: Ok(Progress::Unresolved),
            timed_out_commits: 1,
            basis_stale: true,
            covered: Ok(Progress::Done),
            stored: (session().get(), true, Vec::new()),
            later_version: true,
            commits: 2,
            serving: true,
            first_key: REFUSED,
            other_key: REFUSED,
        },
        "a size rejection on a stale basis re-reads the page and saturates its current version"
    );
}

#[test]
fn a_rejected_saturated_write_withdraws_and_latches() {
    #[derive(Debug, PartialEq)]
    struct Seen {
        covered: Result<Progress, Withdraw>,
        stored: (u64, bool, Vec<u8>),
        commits: [usize; 2],
        serving: bool,
        other_page: [bool; 5],
        later: [Result<Progress, Withdraw>; 3],
        later_commits: [usize; 2],
    }
    let (covered_key, other_page) = (key_on(1, 0x41), key_on(0, 0x43));
    let mut world = world();
    let roomy = world.store.0.borrow().limit;
    let commits_before = [world.commits(0), world.commits(1)];
    world.set_limit(page_len(0) - 1);
    let covered = world
        .fencing
        .cover_page(&mut world.client, &[blocked(covered_key)]);
    let mut seen = Seen {
        covered,
        stored: world.stored(1),
        commits: [
            world.commits(0) - commits_before[0],
            world.commits(1) - commits_before[1],
        ],
        serving: world.fencing.coverage().is_some(),
        other_page: world.admits(&other_page),
        later: [Ok(Progress::Unresolved); 3],
        later_commits: [0; 2],
    };
    // With room for any page again, a tenure that had not withdrawn would commit these.
    world.set_limit(roomy);
    seen.later = [
        world
            .fencing
            .cover_page(&mut world.client, &[blocked(covered_key)]),
        world
            .fencing
            .cover_page(&mut world.client, &[blocked(other_page)]),
        world.fencing.fence(&mut world.client, 0),
    ];
    seen.later_commits = [
        world.commits(0) - commits_before[0],
        world.commits(1) - commits_before[1],
    ];
    let fenced = world.fenced.clone();
    drop(world);
    premises(&fenced, &[covered_key], &[other_page]);
    let withdrawn = Err(Withdraw::Store(StoreError::Refused(Refusal::Rejected)));
    assert_eq!(
        seen,
        Seen {
            covered: withdrawn,
            stored: (session().get(), false, Vec::new()),
            commits: [0; 2],
            serving: false,
            other_page: REFUSED,
            later: [withdrawn; 3],
            later_commits: [0; 2],
        },
        "a rejection of the saturated write withdraws the tenure, and every later call returns that withdrawal"
    );
}

#[test]
fn a_merged_write_within_the_limit_commits_its_entry_unsaturated() {
    #[derive(Debug, PartialEq)]
    struct Seen {
        covered: Result<Progress, Withdraw>,
        stored: (u64, bool, Vec<u8>),
        later_version: bool,
        commits: usize,
        serving: bool,
        other_key: [bool; 5],
        covered_key: [bool; 5],
        growth: Growth,
    }
    let (covered_key, other_key) = (key_on(1, 0x41), key_on(1, 0x42));
    let mut world = world();
    let (known_before, commits_before) = (world.known(1), world.commits(1));
    let covered = world
        .fencing
        .cover_page(&mut world.client, &[blocked(covered_key)]);
    let seen = Seen {
        covered,
        stored: world.stored(1),
        later_version: known_before.is_some() && world.known(1) > known_before,
        commits: world.commits(1) - commits_before,
        serving: world.fencing.coverage().is_some(),
        other_key: world.admits(&other_key),
        covered_key: world.admits(&covered_key),
        growth: world.fencing.growth(),
    };
    let fenced = world.fenced.clone();
    drop(world);
    premises(&fenced, &[covered_key, other_key], &[]);
    assert_eq!(
        encoded(covered_key).len(),
        ENTRY_LEN,
        "premise: the scenario encodes one entry"
    );
    assert_eq!(
        seen,
        Seen {
            covered: Ok(Progress::Done),
            stored: (session().get(), false, encoded(covered_key)),
            later_version: true,
            commits: 1,
            serving: true,
            other_key: ADMITTED,
            covered_key: INTERVAL_REFUSED,
            growth: Growth {
                saturated_pages: 0,
                largest_page_bytes: page_len(1),
                pairs: 1,
                held_saturated_pages: 0,
            },
        },
        "a merged write the store accepts commits the entry and saturates nothing"
    );
}
