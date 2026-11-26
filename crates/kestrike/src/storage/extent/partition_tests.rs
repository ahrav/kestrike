//! Raw-partition transitions in three domains. Conserved partitions whose
//! total fits `usize`: each reserve, publish, retire and release returns
//! the partition a `u128` model computes, its total unchanged, or refuses
//! with `LedgerOverflow` where the model does. Field-valid partitions whose
//! aggregate passes `usize::MAX`: a transition that overflows its
//! destination term refuses, and one whose changed terms fit succeeds. And
//! `total` itself, which returns exactly `usize::MAX` and refuses one byte
//! more.

use super::partition::{HeldPhase, RawPartition};
use crate::storage::ledger::LedgerOverflow;

const MAX: u128 = usize::MAX as u128;

fn terms(p: &RawPartition) -> [u128; 6] {
    [
        p.free, p.reserved, p.resident, p.retired, p.waste, p.metadata,
    ]
    .map(|t| t as u128)
}

fn partition([free, reserved, resident, retired, waste, metadata]: [u128; 6]) -> RawPartition {
    let narrow = |t: u128| usize::try_from(t).expect("a term fits usize");
    RawPartition {
        metadata: narrow(metadata),
        free: narrow(free),
        reserved: narrow(reserved),
        resident: narrow(resident),
        retired: narrow(retired),
        waste: narrow(waste),
    }
}

/// Applies `moves` to `start` in `u128`, each `(from, to, amount)` moving
/// `amount` from term `from` to term `to`, or returns `None` when a term
/// would leave `0..=usize::MAX`.
fn model(start: [u128; 6], moves: &[(usize, usize, u128)]) -> Option<[u128; 6]> {
    let mut next = start;
    for &(from, to, amount) in moves {
        next[from] = next[from].checked_sub(amount)?;
        next[to] += amount;
        if next[to] > MAX {
            return None;
        }
    }
    Some(next)
}

const FREE: usize = 0;
const RESERVED: usize = 1;
const RESIDENT: usize = 2;
const RETIRED: usize = 3;
const WASTE: usize = 4;

fn phase_term(phase: HeldPhase) -> usize {
    match phase {
        HeldPhase::Reserved => RESERVED,
        HeldPhase::Resident => RESIDENT,
        HeldPhase::Retired => RETIRED,
    }
}

/// Checks one transition of `start` against the model: the partition it
/// returns equals the model's with the same total, or it refuses where the
/// model does.
fn check(
    start: RawPartition,
    got: Result<RawPartition, LedgerOverflow>,
    expected: Option<[u128; 6]>,
    what: &str,
) {
    match expected {
        Some(terms_after) => {
            let after = got.unwrap_or_else(|_| panic!("{what}: refused {start:?}"));
            assert_eq!(terms(&after), terms_after, "{what}");
            assert_eq!(after.total(), start.total(), "{what}: total conserved");
        }
        None => assert_eq!(got, Err(LedgerOverflow), "{what}"),
    }
}

/// Every transition over conserved partitions at zero, one, exact funding,
/// one short, a payload past its extent and totals of exactly `usize::MAX`
/// matches the model. Release covers all three phases, with amounts drawn
/// from the free term and, separately, from its held term and the waste;
/// publish and retire draw amounts from the reserved and resident terms.
#[test]
fn ib_partition_checked_transitions_conserved_domain() {
    let starts: [[u128; 6]; 6] = [
        [0, 0, 0, 0, 0, 0],
        [100, 0, 0, 0, 0, 0],
        [40, 30, 20, 7, 3, 0],
        [40, 30, 20, 7, 3, 4096],
        [MAX, 0, 0, 0, 0, 0],
        [MAX - 4156, 20, 20, 10, 10, 4096],
    ];
    let amounts = |held: u128| [0, 1, held.saturating_sub(1), held, held + 1, MAX];
    for start in starts {
        let base = partition(start);
        assert_eq!(base.total().map(|t| t as u128), Ok(start.iter().sum()));
        for extent in amounts(start[FREE]) {
            for payload in [0, 1, extent.saturating_sub(1), extent, extent + 1] {
                let (Ok(e), Ok(p)) = (usize::try_from(extent), usize::try_from(payload)) else {
                    continue;
                };
                let expected = extent.checked_sub(payload).and_then(|waste| {
                    model(start, &[(FREE, RESERVED, payload), (FREE, WASTE, waste)])
                });
                check(
                    base,
                    base.reserve(e, p),
                    expected,
                    &format!("reserve {extent} {payload} of {start:?}"),
                );
                for phase in [HeldPhase::Reserved, HeldPhase::Resident, HeldPhase::Retired] {
                    let expected = extent.checked_sub(payload).and_then(|waste| {
                        model(
                            start,
                            &[(phase_term(phase), FREE, payload), (WASTE, FREE, waste)],
                        )
                    });
                    check(
                        base,
                        base.release(phase, e, p),
                        expected,
                        &format!("release {phase:?} {extent} {payload} of {start:?}"),
                    );
                }
            }
        }
        // Release funded from the held term and the waste: each at zero,
        // one, one short, exactly funded, one over and `usize::MAX`.
        for phase in [HeldPhase::Reserved, HeldPhase::Resident, HeldPhase::Retired] {
            for payload in amounts(start[phase_term(phase)]) {
                for waste in amounts(start[WASTE]) {
                    let extent = payload + waste;
                    let (Ok(e), Ok(p)) = (usize::try_from(extent), usize::try_from(payload)) else {
                        continue;
                    };
                    let expected = model(
                        start,
                        &[(phase_term(phase), FREE, payload), (WASTE, FREE, waste)],
                    );
                    check(
                        base,
                        base.release(phase, e, p),
                        expected,
                        &format!("release {phase:?} {extent} {payload} of {start:?}"),
                    );
                }
            }
        }
        for payload in amounts(start[RESERVED])
            .into_iter()
            .chain(amounts(start[RESIDENT]))
        {
            let Ok(p) = usize::try_from(payload) else {
                continue;
            };
            check(
                base,
                base.publish(p),
                model(start, &[(RESERVED, RESIDENT, payload)]),
                "publish",
            );
            check(
                base,
                base.retire(p),
                model(start, &[(RESIDENT, RETIRED, payload)]),
                "retire",
            );
        }
    }
}

/// Partitions whose terms each fit but whose aggregate passes `usize::MAX`
/// refuse a transition whose destination term would overflow, and admit
/// one whose changed terms all fit, since each transition checks only the
/// terms it changes.
#[test]
fn ib_partition_checked_transitions_aggregate_invalid_domain() {
    let max = usize::MAX;
    // Each partition holds one term at `usize::MAX` beside 10 free bytes,
    // so its aggregate passes `usize::MAX` while every field fits, and a
    // transition that adds to that term overflows it.
    let at_max = |term: usize| {
        let mut terms = [10, 0, 0, 0, 0, 0];
        terms[term] = MAX;
        partition(terms)
    };
    for term in [RESERVED, RESIDENT, RETIRED, WASTE] {
        assert_eq!(at_max(term).total(), Err(LedgerOverflow), "term {term}");
    }
    assert_eq!(
        at_max(RESERVED).reserve(5, 1),
        Err(LedgerOverflow),
        "reserved overflows"
    );
    assert_eq!(
        at_max(WASTE).reserve(5, 0),
        Err(LedgerOverflow),
        "waste overflows"
    );
    let mut publish = at_max(RESIDENT);
    publish.reserved = 1;
    assert_eq!(
        publish.publish(1),
        Err(LedgerOverflow),
        "resident overflows"
    );
    let mut retire = at_max(RETIRED);
    retire.resident = 1;
    assert_eq!(retire.retire(1), Err(LedgerOverflow), "retired overflows");
    for phase in [HeldPhase::Reserved, HeldPhase::Resident, HeldPhase::Retired] {
        let mut terms = [MAX, 0, 0, 0, 0, 0];
        terms[phase_term(phase)] = 1;
        let release = partition(terms);
        assert_eq!(
            release.release(phase, 1, 1),
            Err(LedgerOverflow),
            "free overflows"
        );
        assert_eq!(
            release.release(phase, 0, 0),
            Ok(release),
            "a zero release fits"
        );
    }
    // A transition whose changed terms fit succeeds while the aggregate
    // stays past `usize::MAX`.
    let roomy = RawPartition {
        metadata: 0,
        free: max,
        reserved: max - 1,
        resident: 0,
        retired: 0,
        waste: 0,
    };
    assert_eq!(
        roomy.publish(max - 1),
        Ok(RawPartition {
            reserved: 0,
            resident: max - 1,
            ..roomy
        })
    );
    assert_eq!(roomy.total(), Err(LedgerOverflow));
}

/// `total` returns exactly `usize::MAX` for terms summing to it, in any
/// split, and refuses a sum one byte past it.
#[test]
fn ib_partition_checked_transitions_total_at_the_limit() {
    let max = usize::MAX;
    for split in [
        [max, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, max, 0],
        [0, 0, 0, 0, 0, max],
        [
            max / 6,
            max / 6,
            max / 6,
            max / 6,
            max / 6,
            max - 5 * (max / 6),
        ],
    ] {
        let exact = partition(split.map(|t| t as u128));
        assert_eq!(exact.total(), Ok(max), "{split:?}");
        // One byte more on the smallest term passes `usize::MAX` while that
        // term still fits `usize`.
        let mut over = split;
        let least = (0..6).min_by_key(|&term| split[term]).expect("six terms");
        over[least] += 1;
        assert_eq!(
            partition(over.map(|t| t as u128)).total(),
            Err(LedgerOverflow),
            "{split:?}"
        );
    }
    let over = RawPartition {
        free: max,
        waste: 1,
        ..RawPartition::default()
    };
    assert_eq!(over.total(), Err(LedgerOverflow));
}
