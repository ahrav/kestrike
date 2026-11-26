//! The external witness: emission apart from client observation over a
//! composed scene's uploads, the three observation classes, exclusions and
//! the freshness floor fed to the oracle across a crash, the digest across
//! die, dispose and relaunch, overflow, and the rebuild from a recorded
//! bundle.

use sha2::{Digest, Sha256};

use crate::oracle::{
    ActionKind, Decision, DurableFact, Hypothesis, Inconclusive, KeyId, Label, NoInformation,
    Obligation, Outcome, PutOutcome, Recorder, Row, Script, Verdict, check,
};
use crate::sim::ledger::LEDGER;
use crate::sim::trace::{
    Capacity, Event, Outcome as Ran, PAYLOAD, Recorder as Trace, Terminal, Work, load,
};
use crate::storage::Crc32c;
use crate::storage::device::sim::QuiesceMode;

use super::adapters::{Attempt, FRAGMENT, LEN, drive_then, tenures};
use super::frame::{Kind, parse};
use super::put_tests::Scene;
use super::restart::{Disposition, MANIFEST, Run, restart_scene, restart_scene_keyed};
use super::upload::UploadOutcome;
use super::witness::{Change, Class, Effect, LIMIT, OBSERVATION, Tuple, View, Witness};

const HYPOTHESIS: Hypothesis = Hypothesis("witnessed-exclusion");

/// The key every fixture uploads, and its two labels.
const NAME: u8 = 5;
const A: Label = Label(50);
const B: Label = Label(51);

/// A refused recovered lookup.
const REFUSED: Outcome = Outcome::NoInformation(NoInformation::Refused);

/// The frozen identity of A's binding.
const FROZEN: u64 = 0xa5;

/// What the tap does with a RESULT toward the uploading client.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tap {
    /// The RESULT travels on.
    Deliver,
    /// The link drops the RESULT.
    Drop,
    /// The RESULT travels on and the upload stops at the turn that emitted
    /// it, before its client polls again.
    Hold,
}

/// Uploads `label` at [`NAME`] through the scene's uploading client as
/// witnessed operation `op` with `effect`, within at most `turns` turns
/// and a PUT deadline `wait_us` away. A tap after each owner poll records
/// every RESULT toward the client as emission and handles it as `tap`
/// says; the client's consumed outcome is recorded under the exact tuple
/// and its class must agree with it, and `probe` reads the witness after
/// every turn. Returns the consumed outcome, the caller's rows and the
/// operation's tuple.
fn witnessed(
    scene: &mut Scene<'_, '_>,
    witness: &mut Witness,
    (op, label, effect): (u32, Label, Effect),
    (epoch, wait_us, tap): (u64, u64, Tap),
    (turns, probe): (u64, &mut dyn FnMut(&Witness)),
) -> (Option<UploadOutcome>, Vec<Row>, Tuple) {
    let mut rec = Recorder::new(1);
    let mut slots = tenures(scene);
    let mut attempt =
        Attempt::begin_waiting(scene, &mut rec, (NAME, label), LEN, &mut slots, wait_us);
    let wire = scene.clients[0]
        .put_wire(attempt.id)
        .expect("a live upload");
    let tuple = Tuple::of_wire(0, wire, epoch);
    witness.apply(Change::Began { op, tuple, effect });
    let digest = Sha256::digest(&attempt.object).into();
    witness.apply(Change::Intended { op, digest });
    let count = attempt.object.len().div_ceil(FRAGMENT) as u32;
    let crc = Crc32c::detect();
    let mut next = 0;
    for _ in 0..turns {
        while next < count && attempt.supply(scene, &mut rec, next) {
            next += 1;
        }
        let mut emitted = false;
        drive_then(scene, 1, &mut |_, nets| {
            nets[0].borrow_mut().retain(0, |bytes| {
                let result = parse(crc, bytes, false).is_ok_and(|frame| {
                    let header = frame.header();
                    header.kind == Kind::PutResult && header.request == wire
                });
                emitted |= result;
                !(result && tap == Tap::Drop)
            });
        });
        if emitted {
            witness.apply(Change::Emitted { op });
            if tap == Tap::Hold {
                return (None, rec.rows().to_vec(), tuple);
            }
        }
        attempt.observe(scene, &mut rec);
        probe(witness);
        if let Some(outcome) = attempt.outcome {
            let acknowledged = outcome == UploadOutcome::Published;
            witness.apply(Change::Consumed {
                tuple,
                acknowledged,
            });
            assert_eq!(agrees(witness.view(), op, outcome), Ok(()));
            return (Some(outcome), rec.rows().to_vec(), tuple);
        }
    }
    (None, rec.rows().to_vec(), tuple)
}

/// The identity word of the index binding that holds `name`'s record: the
/// tag, the incarnation's low bits and the slot, in the pair word's order.
fn frozen(scene: &Scene<'_, '_>, name: u8) -> Option<u64> {
    super::adapters::binding(scene, name).map(|binding| binding.identity.pack())
}

/// A's admission and every fact a recovered acquisition needs, under the
/// fixtures' hypothesis.
fn admitted_a(rows: &mut Script) {
    rows.publish(KeyId(NAME), A, 40);
    for fact in [
        DurableFact::Binding,
        DurableFact::Payload,
        DurableFact::Identity,
        DurableFact::Ownership,
        DurableFact::PortableExpiry,
        DurableFact::ServingAuthority,
    ] {
        rows.fact(HYPOTHESIS, KeyId(NAME), A, fact);
    }
    rows.admission(HYPOTHESIS, KeyId(NAME), A);
}

/// The rows of A admitted, then the witness's feed with A served at
/// `replayed`, then a recovered lookup of A answering `outcome`.
fn recovered(view: View<'_>, replayed: u64, outcome: Outcome) -> Verdict {
    let mut rows = Script::new();
    admitted_a(&mut rows);
    if let Err(inconclusive) = view.feed(&mut rows, HYPOTHESIS, (KeyId(NAME), &[A]), replayed) {
        return Verdict::Inconclusive(inconclusive);
    }
    let label = (outcome != Outcome::Missing).then_some(A);
    rows.recovered_lookup(HYPOTHESIS, KeyId(NAME), outcome, label);
    check(&rows.finish())
}

/// The rule a verdict violated, if any.
fn violated(verdict: &Verdict) -> Option<&'static str> {
    match verdict {
        Verdict::Violation(violation) => Some(violation.rule),
        _ => None,
    }
}

/// Uploads A with a live acknowledgment, then B whose acknowledgment
/// excludes A, recovery-safe when `safe`; then kills the owner, drains and
/// releases its bundle and relaunches, checking the witness digest after
/// death, disposal and relaunch. Each storage hashes under one fixed key
/// pair, so binding identities repeat between runs. Returns the witness and the identity word of A's binding, which a
/// recovery-safe exclusion freezes.
fn excluded_across_a_crash(safe: bool) -> (Witness, u64) {
    let mut kept = None;
    restart_scene_keyed(
        MANIFEST,
        (3, Some((0x5eed, 0xfeed))),
        |Run {
             mut scene,
             mut life,
             mut fresh,
             ..
         }| {
            let epoch = u64::from(life.incarnation());
            let witness = life.witness_mut();
            let (first, _, _) = witnessed(
                &mut scene,
                witness,
                (1, A, Effect::Live),
                (epoch, 30_000_000, Tap::Deliver),
                (600, &mut |_| {}),
            );
            assert_eq!(first, Some(UploadOutcome::Published));
            let bound = frozen(&scene, NAME).expect("A's binding");
            let effect = if safe {
                Effect::Exclusion {
                    key: KeyId(NAME),
                    label: A,
                    frozen: bound,
                }
            } else {
                Effect::Live
            };
            let (second, _, _) = witnessed(
                &mut scene,
                witness,
                (2, B, effect),
                (epoch, 30_000_000, Tap::Deliver),
                (600, &mut |_| {}),
            );
            assert_eq!(second, Some(UploadOutcome::Published));
            let view = life.witness();
            assert!(view.emitted(2));
            let intended = Recorder::content(KeyId(NAME), B, 0, LEN);
            assert_eq!(view.intended(2), Some(Sha256::digest(&intended).into()));
            assert_eq!(view.class(2, Some(epoch)), Some(Class::Observed));
            let before = view.digest();
            assert!(life.die(scene).is_ok());
            assert_eq!(life.witness().digest(), before, "death");
            let disposed = life.dead_mut(0).dispose(QuiesceMode::AllReturned);
            assert_eq!(disposed, Ok(Disposition::AllReturned));
            assert_eq!(life.witness().digest(), before, "disposal");
            assert!(life.release(0).is_ok());
            let relaunched = life.relaunch(fresh.remove(0), 1);
            assert!(relaunched.is_ok());
            assert_eq!(life.witness().digest(), before, "relaunch");
            assert_eq!(
                life.witness().class(2, Some(u64::from(life.incarnation()))),
                Some(Class::Observed)
            );
            kept = Some((life.witness_mut().clone(), bound));
        },
    );
    kept.expect("the scene ran")
}

#[test]
fn an_observed_recovery_safe_acknowledgment_binds_its_exclusion_across_a_crash() {
    let (witness, bound) = excluded_across_a_crash(true);
    let view = witness.view();
    assert_eq!(view.exclusions().len(), 1);
    assert_eq!(view.exclusions()[0].frozen, bound);
    assert_eq!(
        violated(&recovered(view, 0, Outcome::Hit)),
        Some("a recovery-safe exclusion was revived after restart")
    );
    assert!(recovered(view, 0, Outcome::Missing).satisfies(&[Obligation::Restart]));
    let mut rows = Script::new();
    rows.publish(KeyId(NAME), A, 40);
    view.feed(&mut rows, HYPOTHESIS, (KeyId(NAME), &[]), 0)
        .unwrap();
    for fact in [
        DurableFact::Binding,
        DurableFact::Payload,
        DurableFact::Identity,
        DurableFact::Ownership,
    ] {
        rows.fact(HYPOTHESIS, KeyId(NAME), A, fact);
    }
    rows.admission(HYPOTHESIS, KeyId(NAME), A);
    assert_eq!(
        violated(&check(&rows.finish())),
        Some("a recovery-safe exclusion was readmitted")
    );
}

#[test]
fn a_live_acknowledgment_adds_no_exclusion() {
    let (witness, _) = excluded_across_a_crash(false);
    let view = witness.view();
    assert!(view.exclusions().is_empty());
    let served = recovered(view, 0, Outcome::Hit);
    assert!(served.satisfies(&[Obligation::Restart]), "{served:?}");
}

/// A RESULT the link drops after the owner published leaves the operation
/// Ambiguous while its client lives and waits, and Unobserved once the
/// client gives up as `Unknown`; the exclusion it carried stays out of the
/// witness.
#[test]
fn a_response_lost_after_its_effect_leaves_the_caller_unknown_and_the_operation_unobserved() {
    restart_scene(
        MANIFEST,
        |Run {
             mut scene, life, ..
         }| {
            let epoch = u64::from(life.incarnation());
            let mut witness = Witness::default();
            let effect = Effect::Exclusion {
                key: KeyId(NAME),
                label: A,
                frozen: FROZEN,
            };
            let mut waiting = 0;
            let mut probe = |witness: &Witness| {
                let view = witness.view();
                if view.emitted(1) && view.class(1, Some(epoch)) == Some(Class::Ambiguous) {
                    waiting += 1;
                }
            };
            let (ended, caller, _) = witnessed(
                &mut scene,
                &mut witness,
                (1, B, effect),
                (epoch, 200_000, Tap::Drop),
                (4_000, &mut probe),
            );
            assert_eq!(ended, Some(UploadOutcome::Unknown));
            let result = caller.iter().find(|row| row.kind == ActionKind::PutResult);
            assert_eq!(
                result.and_then(|row| row.outcome),
                Some(Outcome::Put(PutOutcome::Unknown)),
                "the caller's row"
            );
            assert!(waiting > 0, "the response stood in flight");
            let view = witness.view();
            assert!(view.emitted(1));
            assert_eq!(view.class(1, Some(epoch)), Some(Class::Unobserved));
            assert!(view.exclusions().is_empty());
            assert!(super::adapters::bound(&scene, NAME), "the effect landed");
            let retained = recovered(view, 0, Outcome::Hit);
            assert!(retained.satisfies(&[Obligation::Restart]), "{retained:?}");
        },
    );
}

/// A RESULT the link drops leaves the client `Unknown` and the operation
/// Unobserved with no effect; a later acknowledged consumption under the
/// same tuple, as a delayed RESULT records, resolves it: the operation
/// becomes Observed and its exclusion applies once. A duplicate
/// acknowledgment and an acknowledgment under a foreign tuple change
/// nothing. The owner then dies and the run relaunches, and a witness
/// rebuilt from the recorded bundle equals the live one and still feeds
/// the exclusion to the oracle.
#[test]
fn an_unknown_resolved_by_a_delayed_publication_applies_its_effect_once_across_a_crash() {
    restart_scene_keyed(
        MANIFEST,
        (3, Some((0x5eed, 0xfeed))),
        |Run {
             mut scene,
             mut life,
             mut fresh,
             ..
         }| {
            let epoch = u64::from(life.incarnation());
            let witness = life.witness_mut();
            let (first, _, _) = witnessed(
                &mut scene,
                witness,
                (1, A, Effect::Live),
                (epoch, 30_000_000, Tap::Deliver),
                (600, &mut |_| {}),
            );
            assert_eq!(first, Some(UploadOutcome::Published));
            let bound = frozen(&scene, NAME).expect("A's binding");
            let effect = Effect::Exclusion {
                key: KeyId(NAME),
                label: A,
                frozen: bound,
            };
            let (lost, _, tuple) = witnessed(
                &mut scene,
                witness,
                (2, B, effect),
                (epoch, 200_000, Tap::Drop),
                (4_000, &mut |_| {}),
            );
            assert_eq!(lost, Some(UploadOutcome::Unknown));
            assert_eq!(
                witness.view().class(2, Some(epoch)),
                Some(Class::Unobserved)
            );
            assert!(
                witness.view().exclusions().is_empty(),
                "Unknown alone records no effect"
            );
            witness.apply(Change::Consumed {
                tuple,
                acknowledged: true,
            });
            let view = witness.view();
            assert_eq!(view.class(2, Some(epoch)), Some(Class::Observed));
            assert_eq!(view.exclusions().len(), 1);
            let (resolved, changes) = (view.digest(), witness.events().len());
            let foreign = Tuple {
                epoch: epoch + 1,
                ..tuple
            };
            for tuple in [tuple, foreign] {
                witness.apply(Change::Consumed {
                    tuple,
                    acknowledged: true,
                });
                witness.apply(Change::Consumed {
                    tuple,
                    acknowledged: false,
                });
            }
            assert_eq!(
                witness.view().digest(),
                resolved,
                "duplicates and foreign tuples"
            );
            assert_eq!(witness.events().len(), changes);
            assert!(life.die(scene).is_ok());
            let disposed = life.dead_mut(0).dispose(QuiesceMode::AllReturned);
            assert_eq!(disposed, Ok(Disposition::AllReturned));
            assert!(life.release(0).is_ok());
            assert!(life.relaunch(fresh.remove(0), 1).is_ok());
            assert_eq!(life.witness().digest(), resolved, "death and relaunch");
            let rebuilt =
                Witness::rebuild(&bundled(&life.witness_mut().events())).expect("witness events");
            let view = rebuilt.view();
            assert_eq!(
                view.digest(),
                resolved,
                "the rebuilt witness equals the live one"
            );
            assert_eq!(
                view.class(2, Some(u64::from(life.incarnation()))),
                Some(Class::Observed)
            );
            assert_eq!(view.exclusions().len(), 1);
            assert_eq!(view.exclusions()[0].frozen, bound);
            assert_eq!(
                violated(&recovered(view, 0, Outcome::Hit)),
                Some("a recovery-safe exclusion was revived after restart")
            );
        },
    );
}

/// `events` recorded into a bundle among turns and events of other kinds,
/// as a run records them, then loaded back from the bundle's bytes, the
/// form a rebuild reads after the recording process is gone.
fn bundled(events: &[Event]) -> Vec<Event> {
    let mut trace = Trace::new(Vec::new(), Capacity::new(8, 4, 10_000, 4).unwrap());
    for (turn, event) in (0..).zip(events) {
        trace.turn(turn * 100, &[turn as u8; 16], turn, &[0; 12]);
        trace.event(&Event {
            kind: LEDGER,
            payload: [turn as u8; PAYLOAD],
        });
        trace.event(event);
    }
    let terminal = Terminal::Complete {
        outcome: Ran::Pass,
        fired: 0,
        required: 0,
    };
    load(&trace.finish(terminal, Work::default()).sink, 10_000)
        .expect("a bundle")
        .events
}

/// The planted control: a witness that records an observed acknowledgment
/// as unobserved fails the check against the client's consumed outcome by
/// name; the planted witness alone passes the oracle, so only that check
/// catches it.
#[test]
fn an_observed_acknowledgment_classified_unobserved_fails_its_check() {
    let tuple = Tuple::of_wire(0, 7, 0);
    let effect = Effect::Exclusion {
        key: KeyId(NAME),
        label: A,
        frozen: FROZEN,
    };
    let consumed = |acknowledged| {
        let mut witness = Witness::default();
        witness.apply(Change::Began {
            op: 1,
            tuple,
            effect,
        });
        witness.apply(Change::Emitted { op: 1 });
        witness.apply(Change::Consumed {
            tuple,
            acknowledged,
        });
        witness
    };
    let honest = consumed(true);
    assert_eq!(agrees(honest.view(), 1, UploadOutcome::Published), Ok(()));
    let planted = consumed(false);
    assert_eq!(
        agrees(planted.view(), 1, UploadOutcome::Published),
        Err("an observed acknowledgment was classified unobserved")
    );
    assert!(recovered(planted.view(), 0, Outcome::Hit).satisfies(&[Obligation::Restart]));
    assert!(violated(&recovered(honest.view(), 0, Outcome::Hit)).is_some());
}

/// Observation needs the exact tuple: an outcome consumed under another
/// peer, slot, generation or epoch observes nothing.
#[test]
fn only_the_exact_tuple_observes_an_acknowledgment() {
    let tuple = Tuple::of_wire(0, (3 << 48) | 9, 2);
    let others = [
        Tuple { peer: 1, ..tuple },
        Tuple { slot: 4, ..tuple },
        Tuple {
            generation: 10,
            ..tuple
        },
        Tuple { epoch: 3, ..tuple },
    ];
    let effect = Effect::Freshness {
        cursor: 6,
        caller: false,
    };
    for other in others {
        let mut witness = Witness::default();
        witness.apply(Change::Began {
            op: 1,
            tuple,
            effect,
        });
        witness.apply(Change::Consumed {
            tuple: other,
            acknowledged: true,
        });
        assert_eq!(witness.view().class(1, Some(2)), Some(Class::Ambiguous));
        assert_eq!(witness.view().floor(), 0, "{other:?}");
    }
    assert_eq!((tuple.slot, tuple.generation), (3, 9));
}

/// Whether the witness's class for `op` agrees with the outcome its client
/// consumed.
fn agrees(view: View<'_>, op: u32, consumed: UploadOutcome) -> Result<(), &'static str> {
    let class = view.class(op, None);
    match (consumed == UploadOutcome::Published, class) {
        (true, Some(Class::Observed)) | (false, Some(Class::Unobserved)) => Ok(()),
        (true, _) => Err("an observed acknowledgment was classified unobserved"),
        (false, _) => Err("an unobserved outcome was classified observed"),
    }
}

/// A witness whose observed acknowledgments cover the invalidation feed
/// through each of `observed`, with one more acknowledgment of `unobserved`
/// its client never consumed as acknowledged; `caller` marks the cursors as
/// coming from the caller's freshness fields.
fn floored(observed: &[u64], unobserved: u64, caller: bool) -> Witness {
    let mut witness = Witness::default();
    for (op, &cursor) in (1..).zip(observed.iter().chain([&unobserved])) {
        let tuple = Tuple::of_wire(1, u64::from(op), 0);
        let effect = Effect::Freshness { cursor, caller };
        witness.apply(Change::Began { op, tuple, effect });
        witness.apply(Change::Consumed {
            tuple,
            acknowledged: op as usize <= observed.len(),
        });
    }
    witness
}

#[test]
fn partial_replay_below_the_floor_withholds_a_recovered_hit() {
    assert_eq!(
        floored(&[7, 3], 0, false).view().floor(),
        7,
        "the floor only rises"
    );
    let mut pending = floored(&[7], 0, false);
    let tuple = Tuple::of_wire(1, 9, 0);
    let effect = Effect::Freshness {
        cursor: 11,
        caller: false,
    };
    pending.apply(Change::Began {
        op: 9,
        tuple,
        effect,
    });
    assert_eq!(pending.view().class(9, Some(1)), Some(Class::Unobserved));
    assert_eq!(pending.view().floor(), 7, "an ended epoch leaves the floor");
    let witness = floored(&[3, 7], 9, false);
    let view = witness.view();
    assert_eq!(
        view.floor(),
        7,
        "an unobserved acknowledgment leaves the floor"
    );
    let served =
        "a recovered candidate was served without freshness, expiry, serving or replay authority";
    assert_eq!(violated(&recovered(view, 5, Outcome::Hit)), Some(served));
    let refused = recovered(view, 5, REFUSED);
    assert!(matches!(refused, Verdict::Pass(_)), "{refused:?}");
    for outcome in [Outcome::Missing, Outcome::Expired] {
        let verdict = recovered(view, 5, outcome);
        assert!(
            verdict.satisfies(&[Obligation::Restart]),
            "{outcome:?} {verdict:?}"
        );
    }
    for replayed in [7, 8] {
        let verdict = recovered(view, replayed, Outcome::Hit);
        assert!(verdict.satisfies(&[Obligation::Restart]), "{verdict:?}");
    }
}

#[test]
fn a_floor_resting_on_caller_freshness_is_inconclusive_by_its_decision() {
    for cursor in [0, 7] {
        let witness = floored(&[cursor], 0, true);
        for replayed in [5, 7] {
            let verdict = recovered(witness.view(), replayed, Outcome::Hit);
            assert!(
                matches!(
                    verdict,
                    Verdict::Inconclusive(Inconclusive::Unresolved {
                        decision: Decision::CallerFreshness,
                        ..
                    })
                ),
                "{cursor} at {replayed}: {verdict:?}"
            );
        }
    }
}

/// An observed cursor from the owner's feed equal to a floor the caller's
/// fields set lifts the caller mark; the caller's equal cursor leaves an
/// owner-set floor conclusive.
#[test]
fn an_equal_owner_cursor_lifts_the_caller_mark() {
    let served =
        "a recovered candidate was served without freshness, expiry, serving or replay authority";
    for cursor in [0, 7] {
        for callers in [[true, false], [false, true]] {
            let mut witness = Witness::default();
            for (op, caller) in (1..).zip(callers) {
                let tuple = Tuple::of_wire(1, u64::from(op), 0);
                let effect = Effect::Freshness { cursor, caller };
                witness.apply(Change::Began { op, tuple, effect });
                witness.apply(Change::Consumed {
                    tuple,
                    acknowledged: true,
                });
            }
            let view = witness.view();
            assert_eq!(view.floor(), cursor);
            let hit = recovered(view, cursor, Outcome::Hit);
            assert!(
                hit.satisfies(&[Obligation::Restart]),
                "{cursor} {callers:?}: {hit:?}"
            );
            if cursor > 0 {
                assert_eq!(
                    violated(&recovered(view, cursor - 1, Outcome::Hit)),
                    Some(served),
                    "{cursor} {callers:?}"
                );
            }
        }
    }
}

/// A replay short of a cursor the owner's feed confirmed is a violation
/// whatever higher cursor the caller's fields claim; once replay reaches
/// the owner's cursor the caller's claim leaves the verdict open.
#[test]
fn a_higher_caller_cursor_leaves_the_owner_floor_in_force() {
    let served =
        "a recovered candidate was served without freshness, expiry, serving or replay authority";
    let owner = (7, false);
    let claimed = (9, true);
    for order in [[owner, claimed], [claimed, owner]] {
        let mut witness = Witness::default();
        for (op, (cursor, caller)) in (1..).zip(order) {
            let tuple = Tuple::of_wire(1, u64::from(op), 0);
            let effect = Effect::Freshness { cursor, caller };
            witness.apply(Change::Began { op, tuple, effect });
            witness.apply(Change::Consumed {
                tuple,
                acknowledged: true,
            });
        }
        let view = witness.view();
        assert_eq!(view.floor(), 9);
        assert_eq!(
            violated(&recovered(view, 5, Outcome::Hit)),
            Some(served),
            "{order:?}"
        );
        let reached = recovered(view, 7, Outcome::Hit);
        assert!(
            matches!(
                reached,
                Verdict::Inconclusive(Inconclusive::Unresolved {
                    decision: Decision::CallerFreshness,
                    ..
                })
            ),
            "{order:?}: {reached:?}"
        );
    }
}

/// A RESULT staged toward a client whose owner then dies is emission only:
/// at the relaunched incarnation's cut the operation is Unobserved, and the
/// exclusion it carried stays out of the witness the lifecycle keeps.
#[test]
fn a_response_staged_when_its_consumer_dies_is_unobserved() {
    restart_scene(
        MANIFEST,
        |Run {
             mut scene,
             mut life,
             mut fresh,
             ..
         }| {
            let epoch = u64::from(life.incarnation());
            let effect = Effect::Exclusion {
                key: KeyId(NAME),
                label: A,
                frozen: FROZEN,
            };
            let (pending, _, _) = witnessed(
                &mut scene,
                life.witness_mut(),
                (1, B, effect),
                (epoch, 30_000_000, Tap::Hold),
                (600, &mut |_| {}),
            );
            assert_eq!(pending, None);
            assert_eq!(life.witness().class(1, Some(epoch)), Some(Class::Ambiguous));
            assert!(life.die(scene).is_ok());
            let disposed = life.dead_mut(0).dispose(QuiesceMode::AllReturned);
            assert_eq!(disposed, Ok(Disposition::AllReturned));
            assert!(life.release(0).is_ok());
            assert!(life.relaunch(fresh.remove(0), 1).is_ok());
            let living = Some(u64::from(life.incarnation()));
            let view = life.witness();
            assert!(view.emitted(1));
            assert_eq!(view.class(1, living), Some(Class::Unobserved));
            assert!(view.exclusions().is_empty());
            assert_eq!(view.floor(), 0);
        },
    );
}

/// Two fresh runs of the same composed scene, a recovery-safe exclusion
/// across a crash, leave equal witnesses and freeze the same binding.
#[test]
fn the_composed_fixture_records_the_same_witness_twice() {
    let (first, bound) = excluded_across_a_crash(true);
    let (second, again) = excluded_across_a_crash(true);
    assert_eq!(bound, again);
    assert_eq!(first.view().digest(), second.view().digest());
    assert_eq!(first.events(), second.events());
}

#[test]
fn a_witness_past_its_bound_is_inconclusive() {
    let mut witness = Witness::default();
    for op in 0..=LIMIT as u32 {
        let tuple = Tuple::of_wire(1, u64::from(op), 0);
        witness.apply(Change::Began {
            op,
            tuple,
            effect: Effect::Live,
        });
    }
    let mut rows = Script::new();
    assert!(matches!(
        witness
            .view()
            .feed(&mut rows, HYPOTHESIS, (KeyId(NAME), &[]), 0),
        Err(Inconclusive::DomainBound { .. })
    ));
    assert!(matches!(
        recovered(witness.view(), 0, Outcome::Missing),
        Verdict::Inconclusive(Inconclusive::DomainBound { .. })
    ));
    assert_eq!(
        witness.view().class(0, Some(0)),
        None,
        "an overflowed witness classifies nothing"
    );
    let rebuilt = Witness::rebuild(&witness.events()).expect("witness events");
    assert_eq!(rebuilt.view().digest(), witness.view().digest());
    assert!(matches!(
        rebuilt
            .view()
            .feed(&mut Script::new(), HYPOTHESIS, (KeyId(NAME), &[]), 0),
        Err(Inconclusive::DomainBound { .. })
    ));
}

/// The witness's changes, recorded as `OBSERVATION` events into a bundle
/// among turns and events of other kinds and loaded back, rebuild a
/// witness with an equal digest; a damaged event, and a consumption whose
/// operation never began, are refused by their position.
#[test]
fn a_recorded_bundle_rebuilds_an_equal_witness() {
    let (witness, _) = excluded_across_a_crash(true);
    let events = bundled(&witness.events());
    let rebuilt = Witness::rebuild(&events).expect("witness events");
    assert_eq!(rebuilt.view().digest(), witness.view().digest());
    assert_eq!(rebuilt.view().exclusions(), witness.view().exclusions());
    let mut damaged = events.clone();
    damaged[1].payload[0] = 9;
    assert_eq!(Witness::rebuild(&damaged).map(|_| ()), Err(1));
    let consumption = |event: &&Event| event.kind == OBSERVATION && event.payload[0] == 3;
    let orphan: Vec<Event> = events.iter().filter(consumption).copied().collect();
    assert_eq!(Witness::rebuild(&orphan).map(|_| ()), Err(0));
}

#[test]
fn a_second_beginning_under_another_tuple_is_refused_by_position() {
    let mut witness = Witness::default();
    let live = Effect::Live;
    let excluding = Effect::Exclusion {
        key: KeyId(NAME),
        label: A,
        frozen: FROZEN,
    };
    for (op, effect) in [(1, live), (2, excluding)] {
        let tuple = Tuple::of_wire(0, u64::from(op), 0);
        witness.apply(Change::Began { op, tuple, effect });
    }
    let mut events = witness.events();
    events[1].payload[1..5].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(Witness::rebuild(&events).map(|_| ()), Err(1));
}

#[test]
fn a_beginning_under_a_held_tuple_is_refused_by_position() {
    let mut witness = Witness::default();
    for op in [1, 2] {
        let tuple = Tuple::of_wire(0, u64::from(op), 0);
        witness.apply(Change::Began {
            op,
            tuple,
            effect: Effect::Live,
        });
    }
    let mut events = witness.events();
    let held = events[0].payload[5..24].to_vec();
    events[1].payload[5..24].copy_from_slice(&held);
    assert_eq!(Witness::rebuild(&events).map(|_| ()), Err(1));
}

/// A change the witness already holds changes neither its digest nor its
/// events, so a log that repeats one of its events is refused at the repeat.
#[test]
fn a_repeated_change_records_no_event_and_is_refused_by_position() {
    let tuple = Tuple::of_wire(0, 7, 0);
    let began = Change::Began {
        op: 7,
        tuple,
        effect: Effect::Live,
    };
    let changes = [
        began,
        Change::Intended {
            op: 7,
            digest: [3; 32],
        },
        Change::Emitted { op: 7 },
        Change::Consumed {
            tuple,
            acknowledged: true,
        },
    ];
    let mut witness = Witness::default();
    for (at, change) in changes.into_iter().enumerate() {
        witness.apply(change);
        let (digest, events) = (witness.view().digest(), witness.events());
        assert_eq!(events.len(), at + 1, "{change:?}");
        witness.apply(change);
        assert_eq!(witness.view().digest(), digest, "{change:?}");
        assert_eq!(witness.events(), events, "{change:?}");
    }
    let events = witness.events();
    for repeated in 0..events.len() {
        let mut log = events.clone();
        log.push(events[repeated]);
        assert_eq!(
            Witness::rebuild(&log).map(|_| ()),
            Err(events.len()),
            "event {repeated}"
        );
    }
}

#[test]
#[should_panic(expected = "begins under a held operation's ID or tuple with other fields")]
fn a_held_operation_beginning_under_another_effect_panics() {
    let mut witness = Witness::default();
    let tuple = Tuple::of_wire(0, 7, 0);
    for effect in [
        Effect::Live,
        Effect::Freshness {
            cursor: 1,
            caller: false,
        },
    ] {
        witness.apply(Change::Began {
            op: 7,
            tuple,
            effect,
        });
    }
}
