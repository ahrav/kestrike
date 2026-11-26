//! `Storage::certify` publishes only a complete pass. On a heap-backed storage with at least two claimed
//! registration records, a reader whose record the first call does not reach pins the era at which an object
//! then retires. A `Storage::certify` call funded for its controls and one visit reports certified `None` and
//! `budget_exhausted`, the era report's certified value is unchanged, and service holds the retired slot
//! (anchor not released, count unchanged). Only the call that visits the last record below the claimed bound
//! publishes, the certificate never decreases across the calls, and service releases the anchor only after
//! the reader unpinned and a further complete pass certified past the retirement.

use super::RetireOutcome;
use super::budget::WorkBudget;
use super::grace::ERA_FIRST;
use super::grace_tests::{SLOTS, certified, handoff, refs, retire_era, storage};
use super::release::CERTIFY_CONTROLS;

/// Registration records of the scenario's storage, all below the claimed bound.
const READERS: usize = 2;

/// What one certification call and the service call after it left behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Step {
    /// The certification report as `(visited, certified, budget_exhausted)`, or `None` for a refused call.
    report: Option<(usize, Option<u64>, bool)>,
    /// The era report's certified value after the certification call.
    certificate: u64,
    /// The service report as `(held, released, serviced)`, or `None` for a refused call.
    service: Option<(usize, usize, usize)>,
    /// The retired slot's reference count after the service call: the anchor while it is held.
    refs: usize,
}

/// Everything one run observed, read after its fixtures are gone.
#[derive(Debug)]
struct Run {
    /// The record indices of the idle reader and of the pinning reader.
    records: (usize, usize),
    /// The certified value before any certification call.
    before: u64,
    /// The era the pinning reader entered at.
    pinned: u64,
    /// Whether the retirement was recorded under the gate, and the era it was stamped with.
    retired: (bool, u64),
    /// The first call, the second call, and the call after the reader unpinned.
    steps: [Step; 3],
}

/// One certification call with `allowance`, then one funded service call, observed on `slot`.
fn step(
    storage: &super::owner::Storage<super::test_platform::TestPlatform>,
    slot: usize,
    allowance: usize,
) -> Step {
    let report = storage
        .certify(&mut WorkBudget::new(allowance))
        .ok()
        .map(|report| (report.visited, report.certified, report.budget_exhausted));
    let certificate = certified(storage);
    let service = storage
        .service(&mut WorkBudget::new(400))
        .ok()
        .map(|pass| (pass.held, pass.released, pass.serviced));
    Step {
        report,
        certificate,
        service,
        refs: refs(storage, slot),
    }
}

/// The scenario: two claimed records, the reader of record 1 pinned at the era one object then retires at. The first
/// certification call is funded for its controls and `first_visits` visits, the second and the third for a whole
/// pass, and the reader unpins between the second and the third. The run returns what it observed only after the
/// pin, the registrations and the storage are gone, so a failed check unwinds through no fixture.
fn run(first_visits: usize) -> Run {
    let storage = storage(SLOTS, READERS);
    let before = certified(&storage);
    let idle = storage.register().unwrap();
    let mut reader = storage.register().unwrap();
    let records = (idle.index().0, reader.index().0);
    let (resident, lease) = handoff(&storage, &[5; 20]);
    let slot = resident.id().slot_index();
    drop(lease);
    let protected = reader.enter().unwrap();
    let pinned = protected.era();
    let recorded = resident.retire() == RetireOutcome::Recorded;
    let retired = (recorded, retire_era(&storage, slot));

    let first = step(&storage, slot, CERTIFY_CONTROLS + first_visits);
    let second = step(&storage, slot, CERTIFY_CONTROLS + READERS);
    protected.exit();
    let third = step(&storage, slot, CERTIFY_CONTROLS + READERS);
    drop(reader);
    drop(idle);
    drop(storage);
    Run {
        records,
        before,
        pinned,
        retired,
        steps: [first, second, third],
    }
}

/// The scenario's premises, which hold whatever the first call's allowance: the idle reader holds record 0 and the
/// pinning reader record 1, nothing is certified yet, and the object retired at the first era, the era of the pin.
fn premises(run: &Run) {
    assert_eq!(
        run.records,
        (0, 1),
        "premise: the readers hold records 0 and 1"
    );
    assert_eq!(
        run.before, 0,
        "premise: a storage no pass has completed on has certified nothing"
    );
    assert_eq!(
        run.pinned, ERA_FIRST,
        "premise: the reader pinned the first era"
    );
    assert_eq!(
        run.retired,
        (true, ERA_FIRST),
        "premise: the object retired at the pinned era"
    );
}

/// The certified value never decreases from one call to the next.
fn certificate_never_decreases(run: &Run) {
    let mut last = run.before;
    for step in &run.steps {
        assert!(
            step.certificate >= last,
            "the certified era decreased: {run:?}"
        );
        last = step.certificate;
    }
}

/// A certification call that runs out of allowance before the last claimed record publishes nothing. The call funded
/// for one visit reads record 0, which holds no pin, and stops before record 1, whose reader pinned the retirement's
/// era: it reports no certificate and an exhausted allowance, the certified value stays where it was, and service
/// holds the retired slot with its anchor counted. The call that then visits record 1 completes the pass and
/// certifies the pinned era, which releases nothing, because a retirement is released only strictly below the
/// certificate. After the reader unpins, a further complete pass certifies the era after the retirement and service
/// returns the slot.
#[test]
fn a_call_that_runs_out_of_allowance_publishes_nothing_and_the_completing_call_certifies() {
    let run = run(1);
    premises(&run);
    let [interrupted, completed, unpinned] = run.steps;
    assert_eq!(
        interrupted,
        Step {
            report: Some((1, None, true)),
            certificate: 0,
            service: Some((1, 0, 0)),
            refs: 1,
        },
        "a certification call that ran out of allowance before the last claimed record published a certificate or let the anchor go"
    );
    assert_eq!(
        completed,
        Step {
            report: Some((1, Some(ERA_FIRST), false)),
            certificate: ERA_FIRST,
            service: Some((1, 0, 0)),
            refs: 1,
        },
        "the call that visited the last claimed record did not certify the pinned era, or the anchor went at an equal certificate"
    );
    assert_eq!(
        unpinned,
        Step {
            report: Some((READERS, Some(ERA_FIRST + 1), false)),
            certificate: ERA_FIRST + 1,
            service: Some((0, 1, 1)),
            refs: 0,
        },
        "a complete pass after the reader unpinned did not certify past the retirement and return the slot"
    );
    certificate_never_decreases(&run);
}

/// The same steps with the first call funded for both records. That call completes its pass and certifies the pinned
/// era at once; the second pass, begun because the era moved at the retirement, still reads the pin and raises
/// nothing; the anchor stays held through both and goes after the reader unpins, as in the interrupted run.
#[test]
fn a_call_funded_for_every_claimed_record_certifies_on_its_own() {
    let run = run(READERS);
    premises(&run);
    let [whole, repeated, unpinned] = run.steps;
    let held = Step {
        report: Some((READERS, Some(ERA_FIRST), false)),
        certificate: ERA_FIRST,
        service: Some((1, 0, 0)),
        refs: 1,
    };
    assert_eq!(
        whole, held,
        "a complete pass over a pinned reader did not certify exactly the pinned era"
    );
    assert_eq!(
        repeated, held,
        "a second complete pass over the same pin raised the certificate or let the anchor go"
    );
    assert_eq!(
        unpinned,
        Step {
            report: Some((READERS, Some(ERA_FIRST + 1), false)),
            certificate: ERA_FIRST + 1,
            service: Some((0, 1, 1)),
            refs: 0,
        },
        "a complete pass after the reader unpinned did not certify past the retirement and return the slot"
    );
    certificate_never_decreases(&run);
}
