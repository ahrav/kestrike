use crate::net::observe::Failure;
use crate::oracle::Obligation;
use crate::sim::manifest::Manifest;
use crate::sim::trace::{Outcome, PAYLOAD, Terminal, load};

use super::super::super::bundle::{admit, failure_code, traced};
use super::super::super::replay::{Replayed, replay};
use super::super::tests::first_failure;
use super::super::{Expect, activated};
use super::{COVERED_HIT, COVERED_SUCCESSORS, PROBED, SUCCESSOR_PUBLISHED, TENURE_BOUND};

/// The roots the seeded tests pin: a small one and two drawn from the
/// 64-bit range.
const ROOTS: [u64; 3] = [11, 2_771_403_958_216_640_719, 17_905_336_124_870_551_203];

fn manifest(name: &str) -> Manifest {
    let text = crate::sim::manifest_tests::sample(name, &"a".repeat(64), "x86_64-linux");
    Manifest::parse(&text).expect("a valid manifest")
}

/// History `name` recorded under `root`: its ending, its violation record
/// and whether the bundle replayed to an equal digest.
fn successor_ran_at(name: &str, root: u64) -> (Outcome, Option<[u8; PAYLOAD]>, bool) {
    let mut manifest = manifest(name);
    manifest.root = root;
    let closed = traced(admit(&manifest).expect("admitted"), Vec::new());
    let loaded = load(&closed.sink, manifest.capacity().records()).expect("a loadable bundle");
    let Terminal::Complete { outcome, .. } = loaded.terminal else {
        panic!("{name} at {root}: {:?}", loaded.terminal);
    };
    let reproduced = replay(&closed.sink).expect("a replay").0 == Replayed::Reproduced;
    (outcome, loaded.violation, reproduced)
}

/// Under each pinned root both successor histories pass and replay to an
/// equal digest. The covered history's judges grant a pass only when the
/// successor leaves the upload of the key its predecessor invalidated
/// unpublished and unread, and the sibling's only when its successor
/// publishes the upload and reads it back exactly.
#[test]
fn a_successor_refuses_the_fill_its_predecessor_invalidated_and_admits_another() {
    for name in [
        "cs1-successor-put-of-a-key-its-predecessor-invalidated",
        "cs1-successor-put-of-a-key-its-predecessor-left",
    ] {
        for root in ROOTS {
            assert_eq!(
                successor_ran_at(name, root),
                (Outcome::Pass, None, true),
                "{name} at {root}"
            );
        }
    }
}

/// Each control ends through its family's rule under each pinned root and
/// replays: one fences a fresh store's pages in place of its predecessor's,
/// two hand a GET's judge a served read, and one runs the binding check on
/// a key its INVALIDATE left bound. Each declares its rule and a premise,
/// and the family holds no other history that expects a violation.
#[test]
fn every_covered_successor_control_fails_through_its_named_check() {
    let killed = [
        ("cs1-successor-fenced-other-pages", SUCCESSOR_PUBLISHED),
        ("cs1-successor-key-read-as-served", SUCCESSOR_PUBLISHED),
        ("cs0-tenure-key-read-as-served", TENURE_BOUND),
        ("cs0-tenure-key-left-judged-covered", TENURE_BOUND),
        ("cs2-tenure-key-read-as-served", COVERED_HIT),
    ];
    for (name, rule) in killed {
        let declared = COVERED_SUCCESSORS
            .iter()
            .find(|h| h.name == name)
            .expect(name);
        assert_eq!(
            declared.expect,
            Expect::Violation(Obligation::History, rule),
            "{name}"
        );
        assert!(!declared.premise.is_empty(), "{name} declares its premise");
        for root in ROOTS {
            assert_eq!(
                successor_ran_at(name, root),
                (
                    Outcome::Violation,
                    Some(failure_code(&Failure::Violation(Obligation::History, rule))),
                    true
                ),
                "{name} at {root}"
            );
        }
    }
    let controls = COVERED_SUCCESSORS
        .iter()
        .filter(|h| matches!(h.expect, Expect::Violation(..)))
        .count();
    assert_eq!(controls, killed.len());
}

/// Under each pinned root both tenure histories pass and replay to an
/// equal digest. The covered history's judges grant a pass only when a
/// lookup of the key its INVALIDATE names ends `Missing` and a GET of it
/// ends `Missing` with no byte, and the sibling's only when the key the
/// INVALIDATE left stays bound and reads back exactly.
#[test]
fn a_tenure_unbinds_the_key_its_invalidate_covered_and_keeps_another() {
    for name in [
        "cs0-tenure-binding-of-a-key-its-invalidate-covered",
        "cs0-tenure-binding-of-a-key-its-invalidate-left",
    ] {
        for root in ROOTS {
            assert_eq!(
                successor_ran_at(name, root),
                (Outcome::Pass, None, true),
                "{name} at {root}"
            );
        }
    }
}

/// With the storage's admission closed after the acknowledgment, no
/// registration can look the covered key up. The tenure history then
/// credits no removed binding: it ends unsuccessful under the premise that
/// the binding was read, at each pinned root.
#[test]
fn a_tenure_history_whose_binding_cannot_be_read_ends_unsuccessful() {
    ends_unsuccessful_under("cs0-tenure-binding-unread", PROBED);
}

#[test]
fn a_tenure_history_whose_get_is_cancelled_ends_unsuccessful() {
    ends_unsuccessful_under(
        "cs2-tenure-get-of-the-covered-key-cancelled",
        "fresh GET missed",
    );
}

fn ends_unsuccessful_under(name: &str, premise: &'static str) {
    let declared = COVERED_SUCCESSORS
        .iter()
        .find(|h| h.name == name)
        .expect(name);
    assert_eq!(declared.expect, Expect::Unsuccessful(premise));
    for root in ROOTS {
        assert_eq!(
            first_failure(name, root),
            Some(Failure::Unsuccessful(premise)),
            "{name} at {root}"
        );
        assert_eq!(
            successor_ran_at(name, root),
            (Outcome::Unsuccessful, None, true),
            "{name} at {root}"
        );
    }
}

/// Each passing successor history witnesses a check of every obligation it
/// declares.
#[test]
fn every_passing_covered_successor_history_activates_the_obligations_it_declares() {
    for history in COVERED_SUCCESSORS
        .iter()
        .filter(|h| h.expect == Expect::Pass)
    {
        let activated = activated(history.witnesses);
        for obligation in history.obligations {
            assert!(
                activated.contains(obligation),
                "{}: {obligation:?} has no witnessed check",
                history.name
            );
        }
    }
}
