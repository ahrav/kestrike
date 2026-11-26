//! `Capture::left` records that a member whose step was `step` left the membership, its removal recorded in
//! the suffix or not. An unrecorded member of the snapshot, a step in `1..=t0`, makes the pass unpublishable.
//! A recorded removal lies at or above the pass's cut, so a replay from the cut excludes the member and the
//! pass stays publishable.
//!
//! Every pass here starts at `t0 = 10` over four slots and its walk is completed before the first leave, so
//! `Capture::intact` answers for the leaves alone: the proof while the pass is publishable, `Released` once
//! it is not.
//!
//! The first test gives one pass, in order, an unrecorded leave with step 0, unrecorded leaves with steps
//! above `t0`, and recorded leaves of snapshot members with steps 1, 5 and `t0`; `intact` returns the same
//! proof after each. An unrecorded leave of the snapshot member with step 5 then makes it return `Released`,
//! and no later leave of any kind brings the proof back. The pass ends, and the next pass is publishable. The
//! second test has no recorded leave: on a pass of its own each, an unrecorded leave with step 1 and with step
//! `t0` releases the pass, and one with step 0, `t0 + 1` or `u64::MAX` does not.
//!
//! The tests hold no fixture whose destructor checks state. Each gathers what `intact` returned into values
//! and asserts on them at its end.

use super::capture::{Capture, CaptureEpoch, CaptureError, CutIntact, SideCap};
use crate::net::ownership::Shard;

/// The `insert_step` reading every pass here is cut at: its snapshot is the members with a step in `1..=T0`.
const T0: u64 = 10;
/// The slots of every pass here.
const SLOTS: usize = 4;
/// The capture epoch every pass here starts under and is asked for its proof under.
const EPOCH: CaptureEpoch = CaptureEpoch(3);

type Answer = Result<CutIntact, CaptureError>;

fn tenure() -> Option<(Shard, u64)> {
    Shard::new(7).map(|shard| (shard, 2))
}

/// What `intact` returns for the pass in flight, or `Idle` when the test's tenure cannot be built.
fn answer(capture: &Capture) -> Answer {
    let tenure = tenure().ok_or(CaptureError::Idle)?;
    capture.intact(tenure, EPOCH)
}

/// Starts a pass at `T0` with two snapshot members and completes its walk, returning the pass counter.
fn walked(capture: &mut Capture) -> Result<u32, CaptureError> {
    let cap = SideCap {
        entries: 2,
        words: 8,
    };
    let counter = capture.start((T0, EPOCH), SLOTS, 2, SLOTS, true, cap)?;
    capture.advance(SLOTS)?;
    Ok(counter)
}

/// Each leave in order on the pass in flight, with what `intact` returned after it.
fn leaves(capture: &mut Capture, leaves: &[(u64, bool)]) -> Vec<((u64, bool), Answer)> {
    leaves
        .iter()
        .map(|&(step, recorded)| {
            capture.left(step, recorded);
            ((step, recorded), answer(capture))
        })
        .collect()
}

/// `leaves`, each paired with `expected`.
fn each(leaves: &[(u64, bool)], expected: Answer) -> Vec<((u64, bool), Answer)> {
    leaves.iter().map(|&leave| (leave, expected)).collect()
}

/// Leaves that keep a pass publishable: unrecorded ones of no snapshot member, then recorded ones of
/// snapshot members, the member with step `T0` included.
const KEEPING: [(u64, bool); 7] = [
    (0, false),
    (T0 + 1, false),
    (u64::MAX, false),
    (0, true),
    (1, true),
    (5, true),
    (T0, true),
];

/// Leaves of every kind, taken after the pass was released.
const AFTER_RELEASE: [(u64, bool); 5] = [
    (1, true),
    (T0, true),
    (0, false),
    (T0 + 1, false),
    (5, false),
];

#[test]
fn only_an_unrecorded_leave_of_a_snapshot_member_releases_the_pass() {
    let mut capture = Capture::default();
    let first = walked(&mut capture);
    let proof = answer(&capture);
    let kept = leaves(&mut capture, &KEEPING);
    let released = leaves(&mut capture, &[(5, false)]);
    let stayed = leaves(&mut capture, &AFTER_RELEASE);
    let saved = capture.finish().len();
    let ended = answer(&capture);
    let second = walked(&mut capture);
    let next = answer(&capture);

    assert_eq!(
        first,
        Ok(1),
        "premise: the first pass starts and its walk completes"
    );
    assert_eq!(
        proof.map(CutIntact::counter),
        Ok(1),
        "premise: a walked pass with no leave is publishable"
    );
    assert_eq!(
        kept,
        each(&KEEPING, proof),
        "an unrecorded leave of no snapshot member and a recorded leave of a snapshot member \
         keep the pass publishable, with the same proof"
    );
    assert_eq!(
        released,
        each(&[(5, false)], Err(CaptureError::Released)),
        "an unrecorded leave of a snapshot member makes the pass unpublishable"
    );
    assert_eq!(
        stayed,
        each(&AFTER_RELEASE, Err(CaptureError::Released)),
        "a released pass stays unpublishable until it ends"
    );
    assert_eq!(
        (saved, ended),
        (0, Err(CaptureError::Idle)),
        "premise: the pass ended with an empty side list"
    );
    assert_eq!(
        second,
        Ok(2),
        "premise: the next pass starts and its walk completes"
    );
    assert_eq!(
        next.map(CutIntact::counter),
        Ok(2),
        "the pass after a released one starts publishable"
    );
}

#[test]
fn an_unrecorded_leave_releases_exactly_the_snapshot_steps() {
    // One pass for each step, so that each answer is that leave's alone.
    let steps = [0, 1, T0, T0 + 1, u64::MAX];
    let seen: Vec<(u64, Result<u32, CaptureError>, bool, Answer)> = steps
        .iter()
        .map(|&step| {
            let mut capture = Capture::default();
            let started = walked(&mut capture);
            let publishable = answer(&capture).is_ok();
            capture.left(step, false);
            (step, started, publishable, answer(&capture))
        })
        .collect();

    let premises: Vec<_> = seen
        .iter()
        .map(|&(step, started, publishable, _)| (step, started, publishable))
        .collect();
    let expected: Vec<_> = steps.iter().map(|&step| (step, Ok(1), true)).collect();
    assert_eq!(premises, expected, "premise: each pass starts publishable");

    let released: Vec<(u64, bool)> = seen
        .iter()
        .map(|&(step, _, _, after)| (step, after == Err(CaptureError::Released)))
        .collect();
    assert_eq!(
        released,
        [
            (0, false),
            (1, true),
            (T0, true),
            (T0 + 1, false),
            (u64::MAX, false)
        ],
        "an unrecorded leave releases the pass exactly for a step in 1..=t0"
    );
    let kept = seen
        .iter()
        .filter(|(step, ..)| !(1..=T0).contains(step))
        .all(|(.., after)| after.is_ok());
    assert!(
        kept,
        "a pass that was not released still gives its proof: {seen:?}"
    );
}
