//! Each relation over real settled pairs: its valid pair compares equal and
//! replays strictly, a wrong byte under its valid premise differs in the
//! bound records, and an invalid premise is unsupported for its reason.

use super::super::bundle::Refusal;
use super::super::replay::{Replayed, replay};
use super::super::{CLIENT_POLL, OBJECT_LEN, OWNER_POLL, SERVICE, candidate, payload};
use super::*;

/// Runs `name` with no script.
fn run(name: &str) -> Side {
    side(name, ()).0
}

/// Asserts each side's bundle replays strictly to its own digest.
fn replays(sides: &[&Side]) {
    for side in sides {
        assert_eq!(replay(&side.bundle).unwrap().0, Replayed::Reproduced);
    }
}

/// Asserts the judgment is a difference in the field `why` names.
fn differs_in(judged: Judged, why: &str) {
    match judged {
        Judged::Differs(said) => assert!(said.starts_with(why), "{said}"),
        other => panic!("{other:?}"),
    }
}

/// Asserts the judgment is unsupported for `why`.
fn unsupported(judged: Judged, why: &str) {
    match judged {
        Judged::Unsupported(said) => assert!(said.starts_with(why), "{said}"),
        other => panic!("{other:?}"),
    }
}

/// A settled run reads its upload back exactly, then drains: its suffix
/// runs no workload action, crosses no deadline and leaves nothing
/// pending, and its census reconciles. A run that stops at its goal has
/// not drained, a run on too small a storage meets pressure, and unknown
/// scenario words are refused.
#[test]
fn a_settled_run_drains_after_its_exact_read() {
    let settled = run("settled").settled;
    let at = settled.reached.as_ref().expect("the goal held").len();
    assert_eq!(settled.turns, at + DRAIN as usize);
    assert_eq!((settled.suffix_acts, settled.undrained), (0, None));
    let suffix = settled.suffix.expect("a suffix");
    assert!(!suffix.changed && suffix.span_us > 0, "{suffix:?}");
    assert_eq!(
        (settled.census, settled.first, settled.pressure),
        (Ok(()), None, None)
    );
    let (outcome, bytes) = settled.gets[1].clone().expect("a read");
    assert_eq!(outcome, Some(Outcome::Complete));
    assert_eq!(bytes, payload(OBJECT_LEN as usize, 30));
    assert_eq!(
        settled.contents.len(),
        2,
        "the resident object and the upload"
    );
    let labelled = |bound: &Bound| bound.as_ref().is_ok_and(|record| record.label.is_some());
    assert!(settled.contents.iter().all(labelled));
    let hasty = run("settled-hasty");
    assert_eq!(hasty.settled.end, End::Done);
    assert_eq!(hasty.settled.undrained, Some("a read was pending"));
    assert_eq!(hasty.settled.gets[1].as_ref().unwrap().0, None);
    replays(&[&hasty]);
    let cramped = run("settled-cramped").settled.pressure;
    assert_eq!(cramped, Some("the storage evicted an object"));
    let manifest = Manifest::parse(&crate::sim::manifest_tests::sample(
        "settled-sideways",
        &"a".repeat(64),
        "x86_64-linux",
    ))
    .unwrap();
    assert!(matches!(admit(&manifest), Err(Refusal::Profile)));
}

/// Poll batching: owner batches of eight and three take different
/// schedules and settle to equal outcomes and exact bytes; a published
/// byte changed after the goal differs, and two runs that both fail their
/// checks earn no credit; faulted links, mismatched inputs,
/// an undrained pair and two writers leave the premise unmet.
#[test]
fn poll_batching_settles_alike_and_kills_its_controls() {
    let (eight, three) = (run("settled"), run("settled-batched"));
    assert_ne!(
        eight.settled.turns, three.settled.turns,
        "the schedules differ"
    );
    assert_eq!(batching(&eight.settled, &three.settled), Judged::Equal);
    let planted = run("settled-batched-planted");
    assert!(
        planted.settled.first.is_some(),
        "the boundary judged the byte"
    );
    differs_in(
        batching(&eight.settled, &planted.settled),
        "the bound records",
    );
    let planted_eight = run("settled-planted");
    differs_in(
        batching(&planted_eight.settled, &planted.settled),
        "the obligations failed alike",
    );
    replays(&[&eight, &three, &planted]);
    let faulted = (run("settled-faulted"), run("settled-faulted-batched"));
    unsupported(
        batching(&faulted.0.settled, &faulted.1.settled),
        "a path was faulted",
    );
    unsupported(
        batching(&eight.settled, &faulted.1.settled),
        "the pair's fixed inputs differ",
    );
    let hasty = (run("settled-hasty"), run("settled-hasty-batched"));
    for side in [&hasty.0, &hasty.1] {
        assert_eq!(side.settled.end, End::Done);
        assert_eq!(side.settled.undrained, Some("a read was pending"));
    }
    replays(&[&hasty.0, &hasty.1]);
    unsupported(
        batching(&hasty.0.settled, &hasty.1.settled),
        "a side had not drained",
    );
    let racing = |side: &Side| Settled {
        plan: Plan {
            puts: 2,
            ..side.settled.plan
        },
        ..side.settled.clone()
    };
    unsupported(
        batching(&racing(&eight), &racing(&three)),
        "two writers may race one key",
    );
    unsupported(
        batching(&eight.settled, &eight.settled),
        "the owner's batch was not varied",
    );
    let explicit = Settled {
        plan: Plan {
            batch: Some(super::super::OWNER.batch),
            ..eight.settled.plan
        },
        ..eight.settled.clone()
    };
    unsupported(
        batching(&eight.settled, &explicit),
        "the owner's batch was not varied",
    );
}

/// Schedule permutation: the two client polls the run offers together at
/// its start run in both orders, as do a client poll and the service call,
/// and each pair settles to equal logical contents; a planted byte
/// differs; one run paired with itself took no opposite orders, an owner
/// poll and a client poll share a link, and a pair taken
/// while both clients held requests, the read issued before the upload was
/// collected, may share a key, so both are unsupported; the service call
/// paired with itself rests after its first run, so the certificate names
/// the first event disabling the second.
#[test]
fn schedule_permutation_settles_alike_and_kills_its_controls() {
    let polls = [0, 1].map(|client| candidate(CLIENT_POLL, client, 0));
    let swapped = |name: &str, swap: Swap| side(name, swap);
    let both = |name: &str, first, second| {
        let (one, a) = swapped(name, Swap::new(first, second));
        let (other, b) = swapped(name, Swap::new(second, first));
        ((one, a), (other, b))
    };
    let ((forward, ahead), (backward, behind)) = both("settled", polls[0], polls[1]);
    assert_eq!(ahead.certificate(), Ok(()));
    assert_ne!(forward.bundle, backward.bundle, "the schedules differ");
    let judged = permutation((&forward.settled, &ahead), (&backward.settled, &behind));
    assert_eq!(judged, Judged::Equal);
    unsupported(
        permutation((&forward.settled, &ahead), (&forward.settled, &ahead)),
        "the runs did not take one pair in opposite orders",
    );
    let ((serviced, early), (polled, late)) = both("settled", candidate(SERVICE, 0, 0), polls[0]);
    assert_eq!(
        permutation((&serviced.settled, &early), (&polled.settled, &late)),
        Judged::Equal
    );
    replays(&[&forward, &backward, &serviced, &polled]);
    let (planted, planted_swap) = swapped("settled-planted", Swap::new(polls[1], polls[0]));
    differs_in(
        permutation(
            (&forward.settled, &ahead),
            (&planted.settled, &planted_swap),
        ),
        "the logical contents",
    );
    let ((one, first), (other, second)) = both("settled", candidate(OWNER_POLL, 0, 0), polls[0]);
    unsupported(
        permutation((&one.settled, &first), (&other.settled, &second)),
        "the pair shares",
    );
    let ((one, first), (other, second)) = both("settled-eager", polls[0], polls[1]);
    unsupported(
        permutation((&one.settled, &first), (&other.settled, &second)),
        "both clients held requests at the pair",
    );
    let service = candidate(SERVICE, 0, 0);
    let (_, twice) = swapped("settled", Swap::new(service, service));
    assert_eq!(
        twice.certificate(),
        Err("the first event disabled the second")
    );
}

/// Geometry scaling: the fixture and a storage of twice the units and
/// slots and twice the chunk length settle to equal per-key outcomes and
/// bytes, each census reconciling against its own geometry; a planted byte
/// differs, as does a census that fails; faulted links and a storage too
/// small for the work leave the premise unmet.
/// A scaling pair must run over two storage shapes.
#[test]
fn geometry_scaling_settles_alike_and_kills_its_controls() {
    let (fixture, scaled) = (run("settled"), run("settled-scaled"));
    assert_eq!(scaled.settled.census, Ok(()));
    assert_eq!(scaling(&fixture.settled, &scaled.settled), Judged::Equal);
    let planted = run("settled-scaled-planted");
    differs_in(
        scaling(&fixture.settled, &planted.settled),
        "the bound records",
    );
    replays(&[&fixture, &scaled, &planted]);
    let mut miscounted = scaled.settled.clone();
    miscounted.census = Err("slot partition: 15 against 16".into());
    differs_in(scaling(&fixture.settled, &miscounted), "a census failed");
    let faulted = (run("settled-faulted"), run("settled-faulted-scaled"));
    unsupported(
        scaling(&faulted.0.settled, &faulted.1.settled),
        "a path was faulted",
    );
    unsupported(
        scaling(&fixture.settled, &run("settled-cramped").settled),
        "a side met pressure: the storage evicted an object",
    );
    // A harness defect names itself ahead of the pressure the same side met.
    let mut defective = fixture.settled.clone();
    defective.end = End::Defect(crate::sim::turn::Defect::Due { now: 1, due: 1 });
    defective.pressure = Some("the storage evicted an object");
    unsupported(
        scaling(&defective, &fixture.settled),
        "a side ended in a harness defect",
    );
    unsupported(
        scaling(&fixture.settled, &fixture.settled),
        "the geometry was not varied",
    );
}

/// Drain-suffix idempotence: a drain twice as long shares the prefix to
/// the goal and leaves contents, outcomes and obligations equal while the
/// owner's counters advance; a planted byte differs; a suffix that
/// invalidates, an unrepeated suffix, a suffix whose clock-driven state
/// changed, a suffix spanning the TTL and a pair under pressure are
/// unsupported.
/// An idempotence pair must share its root seed and every turn before the
/// goal.
#[test]
fn drain_suffix_idempotence_holds_and_kills_its_controls() {
    let (once, twice) = (run("settled"), run("settled-twice"));
    assert_eq!(twice.settled.turns, once.settled.turns + DRAIN as usize);
    assert_eq!(idempotence(&once.settled, &twice.settled), Judged::Equal);
    assert_ne!(
        once.settled.counters, twice.settled.counters,
        "counters advance"
    );
    let planted = run("settled-twice-planted");
    differs_in(
        idempotence(&once.settled, &planted.settled),
        "the bound records",
    );
    replays(&[&once, &twice, &planted]);
    let invalidating = (
        run("settled-invalidating"),
        run("settled-invalidating-twice"),
    );
    unsupported(
        idempotence(&invalidating.0.settled, &invalidating.1.settled),
        "a suffix ran a workload action",
    );
    unsupported(
        idempotence(&once.settled, &once.settled),
        "the suffix was not repeated",
    );
    let mut ticked = twice.settled.clone();
    ticked.suffix = ticked.suffix.map(|suffix| Suffix {
        changed: true,
        ..suffix
    });
    unsupported(
        idempotence(&once.settled, &ticked),
        "a suffix crossed a deadline",
    );
    let mut lingered = twice.settled.clone();
    lingered.suffix = lingered.suffix.map(|suffix| Suffix {
        span_us: u64::from(TTL_MS) * 1000,
        ..suffix
    });
    unsupported(
        idempotence(&once.settled, &lingered),
        "a suffix crossed a deadline",
    );
    let mut pressed = twice.settled.clone();
    pressed.pressure = Some("the storage refused maintenance");
    unsupported(idempotence(&once.settled, &pressed), "a side met pressure");
    let (reseeded, ()) = side_with("settled-twice", &[("root", "4")], ());
    unsupported(
        idempotence(&once.settled, &reseeded.settled),
        "the pair's fixed inputs differ",
    );
    let mut detoured = twice.settled.clone();
    let goal = detoured.reached.as_mut().expect("the goal held");
    goal.last_mut().expect("a turn before the goal").outcome += 1;
    unsupported(
        idempotence(&once.settled, &detoured),
        "the runs reached the goal by different prefixes",
    );
}
