//! Boundary and teardown observations of a composed world.

use std::cell::RefCell;
use std::ops::Range;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::rc::Rc;

use crate::oracle::{
    ActionKind, Custodian, Inconclusive, Label, Obligation, Ordinal, Outcome, Owner, Pending,
    PutOutcome, Recorder, Row, Verdict, WideOp, check,
};
use crate::storage::PoolKind;
use crate::storage::SlotState;
use crate::storage::owner_fixture::{
    clear_abandoned, forge, hold_extent_of, invalidate, last_sample, leak_unit, reseal, set_refs,
    set_state, shadow_resident, swap_ident, with_duplicate_binding, with_pool_held,
    with_shadow_binding,
};

use super::adapters::{Attempt, bound, get, tenures};
use super::observe::{
    Cuts, FREE_RUNS, Failure, FirstFailure, LEDGER, Lenses, MALFORMED, OVERLAP, Observer, Registry,
    Tables, UNBOUND, Witnesses, boundary, conservation_failure, conserved, tables,
};
use super::owner_tests::{PRINCIPALS, key, payload};
use super::put_tests::{Scene, scene};
use super::upload::UploadOutcome;

const LEN: u64 = 3 * super::adapters::FRAGMENT as u64 - 100;

const UNEXPECTED: Failure = Failure::Violation(Obligation::History, "an unexpected binding");
const RECORD: Failure = Failure::Violation(
    Obligation::Bytes,
    "a bound slot's record fails its header or chunk checks",
);

/// The registry of a fresh scene: the one object its owner published.
fn registry() -> Registry {
    let mut registry = Registry::new(64);
    registry.register(key(1), Label(1), 0, payload(1000, 1));
    registry
}

fn checked(scene: &Scene<'_, '_>, registry: &Registry) -> Result<usize, Failure> {
    boundary(&scene.media(), registry, &mut Lenses::default())
}

/// A registry serves the whole body of a registered content of the key,
/// and a prefix starts one: the bytes past the content's metadata. Another
/// key's content is not served, and bytes of no content and a key with no
/// content match neither.
#[test]
fn a_registry_matches_a_keys_content_bodies_and_their_prefixes() {
    let mut registry = registry();
    let framed = [vec![9; 4], payload(600, 2)].concat();
    registry.register(key(1), Label(2), 4, framed);
    registry.register(key(2), Label(3), 0, payload(300, 3));
    for body in [payload(1000, 1), payload(600, 2)] {
        assert!(registry.serves(&key(1), &body));
        assert!(registry.starts(&key(1), &body));
        assert!(registry.starts(&key(1), &body[..100]));
        assert!(!registry.serves(&key(1), &body[..100]));
        assert!(!registry.serves(&key(2), &body));
    }
    assert!(registry.starts(&key(1), &[]));
    assert!(!registry.serves(&key(1), &[]));
    let mut changed = payload(1000, 1);
    changed[0] ^= 1;
    assert!(!registry.serves(&key(1), &changed));
    assert!(!registry.starts(&key(1), &changed[..1]));
    assert!(!registry.serves(&key(1), &payload(300, 3)));
    assert!(registry.knows(&key(2)) && !registry.knows(&key(7)));
    assert!(!registry.serves(&key(7), &[]) && !registry.starts(&key(7), &[]));
}

/// The device range of the scene's first bound slot.
fn bound_media(scene: &Scene<'_, '_>) -> Range<usize> {
    let (mut bindings, mut facts) = (Vec::new(), Vec::new());
    scene.storage.bindings_into(&mut bindings).unwrap();
    scene.storage.slot_facts_into(&mut facts).unwrap();
    let slot = bindings[0].identity.slot as usize;
    facts[slot].media().unwrap()
}

/// Flips byte `at` of the scene's first bound record on the device.
pub(super) fn flip(scene: &Scene<'_, '_>, at: usize) {
    let media = bound_media(scene);
    let byte = scene.control.device(media.start + at, 1)[0];
    scene.control.write_device(media.start + at, &[byte ^ 0x5a]);
}

/// Publishes a fresh object under key `name` through a live upload,
/// recording its rows; returns the recorder and the object.
fn uploaded(scene: &mut Scene<'_, '_>, name: u8, label: Label) -> (Recorder, Vec<u8>) {
    let mut rec = Recorder::new(1);
    let mut slots = tenures(scene);
    let mut attempt = Attempt::begin(scene, &mut rec, (name, label), LEN, &mut slots);
    attempt.run(scene, &mut rec, 600);
    assert_eq!(attempt.outcome, Some(UploadOutcome::Published));
    let object = attempt.object.clone();
    (rec, object)
}

/// The index bindings and raw media of a fresh scene and of one after a live
/// upload agree with the registry.
#[test]
fn bindings_and_raw_media_agree_with_the_registry() {
    scene(&PRINCIPALS, |mut scene| {
        let mut registry = registry();
        assert_eq!(checked(&scene, &registry), Ok(1));
        let (_, object) = uploaded(&mut scene, 6, Label(6));
        registry.register(key(6), Label(6), 0, object);
        assert_eq!(checked(&scene, &registry), Ok(2));
    });
}

/// A binding whose key has no registered content fails `History`; one
/// byte changed anywhere in a bound record's header, chunk table or payload
/// fails `Bytes`; a verified record whose payload is not the key's
/// registered content fails `Bytes` by its own rule.
#[test]
fn an_unexpected_binding_and_a_raw_corruption_fail_their_obligations() {
    scene(&PRINCIPALS, |mut scene| {
        uploaded(&mut scene, 6, Label(6));
        assert_eq!(checked(&scene, &registry()), Err(UNEXPECTED));
    });
    // The magic, the version, the header crc, the key, the allocation, the session, a length, the chunk table and the payload.
    for at in [0, 8, 12, 16, 48, 56, 64, 80, 300] {
        scene(&PRINCIPALS, |scene| {
            flip(&scene, at);
            assert_eq!(checked(&scene, &registry()), Err(RECORD), "byte {at}");
        });
    }
    scene(&PRINCIPALS, |scene| {
        let mut wrong = Registry::new(4);
        wrong.register(key(1), Label(1), 0, payload(1000, 2));
        assert_eq!(
            checked(&scene, &wrong),
            Err(Failure::Violation(
                Obligation::Bytes,
                "a bound slot's bytes match no registered content"
            ))
        );
    });
}

/// A binding to a slot that holds no object at the binding's incarnation
/// fails `History`.
#[test]
fn a_binding_to_an_empty_slot_fails_history() {
    scene(&PRINCIPALS, |scene| {
        let mut bindings = Vec::new();
        scene.storage.bindings_into(&mut bindings).unwrap();
        let slot = bindings[0].identity.slot as usize;
        let held = swap_ident(scene.storage, slot, 0);
        let found = checked(&scene, &registry());
        swap_ident(scene.storage, slot, held);
        assert_eq!(
            found,
            Err(Failure::Violation(
                Obligation::History,
                "a binding names a slot holding no resident object at its incarnation"
            ))
        );
        assert_eq!(checked(&scene, &registry()), Ok(1), "restored");
    });
}

/// A binding to a slot whose word is retired or still filling, while a
/// count holds it and its record verifies, fails `History`: only a resident
/// slot is bound.
#[test]
fn a_binding_to_a_slot_outside_the_resident_state_fails_history() {
    for state in [SlotState::Retired, SlotState::Filling] {
        scene(&PRINCIPALS, |scene| {
            let mut bindings = Vec::new();
            scene.storage.bindings_into(&mut bindings).unwrap();
            let slot = bindings[0].identity.slot as usize;
            set_state(scene.storage, slot, state);
            let found = checked(&scene, &registry());
            set_state(scene.storage, slot, SlotState::Resident);
            assert_eq!(
                found,
                Err(Failure::Violation(
                    Obligation::History,
                    "a binding names a slot holding no resident object at its incarnation"
                )),
                "{state:?}"
            );
            assert_eq!(checked(&scene, &registry()), Ok(1), "restored");
        });
    }
}

#[test]
fn two_bindings_naming_one_slot_fail_history() {
    scene(&PRINCIPALS, |scene| {
        let found = with_duplicate_binding(scene.storage, &key(1), || checked(&scene, &registry()));
        assert_eq!(
            found,
            Err(Failure::Violation(
                Obligation::History,
                "two bindings name one slot"
            ))
        );
        assert_eq!(checked(&scene, &registry()), Ok(1), "restored");
    });
}

#[test]
fn two_bindings_routing_one_fingerprint_fail_history() {
    scene(&PRINCIPALS, |scene| {
        let session = scene.owner.record_session();
        let shadow = shadow_resident(
            scene.storage,
            &scene.control,
            &key(1),
            &payload(1000, 1),
            session,
        );
        let found = with_shadow_binding(scene.storage, &key(1), shadow.id(), || {
            checked(&scene, &registry())
        });
        set_refs(scene.storage, shadow.id().slot_index(), 0);
        drop(shadow);
        assert_eq!(
            found,
            Err(Failure::Violation(
                Obligation::History,
                "two bindings route one fingerprint"
            ))
        );
        assert_eq!(checked(&scene, &registry()), Ok(1), "restored");
    });
}

#[test]
fn a_binding_to_a_slot_of_another_key_fails_history() {
    scene(&PRINCIPALS, |scene| {
        assert!(bound(&scene, 1));
        forge(scene.storage, &key(1), &key(2));
        assert_eq!(
            checked(&scene, &registry()),
            Err(Failure::Violation(
                Obligation::History,
                "a binding names a slot of another key"
            ))
        );
        assert!(!bound(&scene, 1), "a misrouted binding is no publication");
    });
}

#[test]
fn a_well_formed_record_of_another_session_fails_bytes() {
    for other in [false, true] {
        scene(&PRINCIPALS, |scene| {
            let session = scene.owner.record_session() + u64::from(other);
            reseal(scene.storage, &scene.control, &key(1), session, 0);
            let expected = if other { Err(RECORD) } else { Ok(1) };
            assert_eq!(checked(&scene, &registry()), expected, "other: {other}");
            assert_eq!(bound(&scene, 1), !other, "other: {other}");
        });
    }
}

/// A verified record whose header frames the registered bytes with another
/// metadata/body split fails `Bytes`: the content a key holds is its
/// metadata and its body, each with its length.
#[test]
fn a_well_formed_record_framed_with_another_split_fails_bytes() {
    scene(&PRINCIPALS, |scene| {
        let session = scene.owner.record_session();
        reseal(scene.storage, &scene.control, &key(1), session, 1);
        assert_eq!(
            checked(&scene, &registry()),
            Err(Failure::Violation(
                Obligation::Bytes,
                "a bound slot's bytes match no registered content"
            ))
        );
    });
}

/// A registry past its bound, or holding two payloads for one label, makes
/// the boundary unsuccessful before any binding is judged.
#[test]
fn a_registry_past_its_bound_is_unsuccessful() {
    scene(&PRINCIPALS, |scene| {
        let mut full = Registry::new(0);
        full.register(key(1), Label(1), 0, payload(1000, 1));
        assert_eq!(
            checked(&scene, &full),
            Err(Failure::Unsuccessful(
                "the content registry passed its bound"
            ))
        );
        let mut twice = registry();
        twice.register(key(1), Label(1), 0, payload(1000, 2));
        assert_eq!(
            checked(&scene, &twice),
            Err(Failure::Unsuccessful(
                "the content registry holds two payloads for one label"
            ))
        );
        let mut shared = registry();
        shared.register(key(6), Label(1), 0, payload(100, 6));
        assert_eq!(
            checked(&scene, &shared),
            Err(Failure::Unsuccessful(
                "the content registry holds two payloads for one label"
            )),
            "one label under two keys"
        );
    });
}

/// A warm boundary allocates nothing and changes nothing: no clock sample,
/// no slot fact; the pool's device-count lens allocates nothing warm either.
#[test]
fn warm_lenses_are_passive_and_allocate_nothing() {
    scene(&PRINCIPALS, |scene| {
        let registry = registry();
        let mut lenses = Lenses::default();
        boundary(&scene.media(), &registry, &mut lenses).unwrap();
        let sample = last_sample(scene.storage);
        let mut facts = Vec::new();
        scene.storage.slot_facts_into(&mut facts).unwrap();
        let before = crate::instrument::allocations();
        boundary(&scene.media(), &registry, &mut lenses).unwrap();
        conserved(scene.storage, &mut lenses).unwrap();
        assert_eq!(
            crate::instrument::allocations(),
            before,
            "a warm boundary and a warm conservation judgment allocate nothing"
        );
        assert_eq!(last_sample(scene.storage), sample, "no clock sample");
        let mut after = Vec::new();
        scene.storage.slot_facts_into(&mut after).unwrap();
        assert_eq!(after, facts, "no slot changed");
        let pools = scene.sourcing.pools();
        let mut counts = Vec::new();
        pools.device_counts_into(PoolKind::PacketHeader, &mut counts);
        let before = crate::instrument::allocations();
        pools.device_counts_into(PoolKind::PacketHeader, &mut counts);
        assert_eq!(crate::instrument::allocations(), before);
    });
}

/// The slot the scene's index binds, and a slot holding nothing.
fn bound_and_free(scene: &Scene<'_, '_>) -> (usize, usize) {
    let (mut bindings, mut facts) = (Vec::new(), Vec::new());
    scene.storage.bindings_into(&mut bindings).unwrap();
    scene.storage.slot_facts_into(&mut facts).unwrap();
    let bound = bindings[0].identity.slot as usize;
    let free = (0..facts.len())
        .find(|&slot| slot != bound && facts[slot].incarnation == 0)
        .expect("a slot that never held an object");
    (bound, free)
}

type Plant = fn(&Scene<'_, '_>, usize, usize);

/// A boundary whose eight registry and media checks pass fails by the
/// conservation rule's text for each plant: a free slot moved to `Filling`
/// over the bound object's extent overlaps it, a leaked unit leaves the
/// free runs short of the unheld units, a free slot moved to `Quarantined`
/// breaks the slot counts, and an object removed under a held pool gate
/// whose `ABANDONED` flag is then cleared is an unbound resident.
#[test]
fn each_conservation_text_fails_a_boundary_whose_earlier_checks_pass() {
    let cases: [(&str, Plant, Failure); 4] = [
        (
            "a shared extent",
            |scene, bound, free| hold_extent_of(scene.storage, free, bound),
            Failure::Violation(Obligation::Resources, OVERLAP),
        ),
        (
            "a leaked unit",
            |scene, _, _| assert!(leak_unit(scene.storage)),
            Failure::Violation(Obligation::Resources, FREE_RUNS),
        ),
        (
            "a quarantined free slot",
            |scene, _, free| set_state(scene.storage, free, SlotState::Quarantined),
            Failure::Violation(Obligation::Resources, LEDGER),
        ),
        (
            "an unbound resident",
            |scene, bound, _| {
                let removed = with_pool_held(scene.storage, || invalidate(scene.storage, &key(1)));
                assert!(removed.is_ok(), "{removed:?}");
                clear_abandoned(scene.storage, bound);
            },
            Failure::Violation(Obligation::History, UNBOUND),
        ),
    ];
    for (name, plant, failure) in cases {
        scene(&PRINCIPALS, |scene| {
            assert_eq!(checked(&scene, &registry()), Ok(1), "{name}: premise");
            let (bound, free) = bound_and_free(&scene);
            plant(&scene, bound, free);
            assert_eq!(checked(&scene, &registry()), Err(failure), "{name}");
        });
    }
}

/// A reserved bit of a slot word, which no well-formed word carries.
const RESERVED_BIT: u64 = 1 << 43;

/// A slot word that carries a reserved bit fails by the malformed-word
/// text. On a free slot the boundary's eight registry and media checks
/// pass and its conservation judgment raises the text. On the bound slot
/// the rule's own call raises it, where a boundary fails its earlier
/// binding check. Each restored word passes.
#[test]
fn a_malformed_slot_word_fails_by_its_own_text() {
    let malformed = Failure::Violation(Obligation::Resources, "a slot word is malformed");
    scene(&PRINCIPALS, |scene| {
        let mut lenses = Lenses::default();
        let (bound, free) = bound_and_free(&scene);
        let held = swap_ident(scene.storage, free, 0);
        swap_ident(scene.storage, free, held | RESERVED_BIT);
        let found = checked(&scene, &registry());
        swap_ident(scene.storage, free, held);
        assert_eq!(found, Err(malformed.clone()), "a free slot");
        assert_eq!(checked(&scene, &registry()), Ok(1), "restored");
        let held = swap_ident(scene.storage, bound, 0);
        swap_ident(scene.storage, bound, held | RESERVED_BIT);
        let ruled = conserved(scene.storage, &mut lenses);
        let found = checked(&scene, &registry());
        swap_ident(scene.storage, bound, held);
        assert_eq!(ruled, Err(malformed), "the bound slot");
        assert_eq!(
            found,
            Err(Failure::Violation(
                Obligation::History,
                "a binding names a slot holding no resident object at its incarnation"
            )),
            "the boundary's binding check comes first"
        );
        assert_eq!(conserved(scene.storage, &mut lenses), Ok(()), "restored");
    });
}

/// Each fault of the judge maps to its obligation and text: a malformed
/// word to the malformed-word text, the extent faults to the overlap text,
/// the ledger faults to the ledger text, and an unreadable snapshot to
/// unsuccessful under its reason.
#[test]
fn each_conservation_fault_maps_to_its_obligation_and_text() {
    use crate::storage::conservation::Fault;
    let resources = |text| Failure::Violation(Obligation::Resources, text);
    let history = |text| Failure::Violation(Obligation::History, text);
    for (fault, failure) in [
        (Fault::Unreadable("why"), Failure::Unsuccessful("why")),
        (Fault::Malformed { slot: 1 }, resources(MALFORMED)),
        (Fault::PastVolume { slot: 1 }, resources(OVERLAP)),
        (Fault::Overlap { slot: 1 }, resources(OVERLAP)),
        (Fault::FreeRuns, resources(FREE_RUNS)),
        (Fault::SlotCounts, resources(LEDGER)),
        (Fault::FreeSlots { slot: 1 }, resources(LEDGER)),
        (Fault::RawFree, resources(LEDGER)),
        (
            Fault::DuplicateBinding { slot: 1 },
            history("two bindings name one slot"),
        ),
        (
            Fault::NotResident { slot: 1 },
            history("a binding names a slot holding no resident object at its incarnation"),
        ),
        (Fault::UnboundResident { slot: 1 }, history(UNBOUND)),
    ] {
        assert_eq!(conservation_failure(fault), failure, "{fault:?}");
    }
}

/// A held pool gate makes `tables` return `Tables::Unreadable`; a leaked
/// unit makes it return `Tables::Violated(FREE_RUNS)`.
#[test]
fn the_tables_read_conserved_unreadable_or_violated() {
    scene(&PRINCIPALS, |scene| {
        let mut lenses = Lenses::default();
        assert_eq!(tables(scene.storage, &mut lenses), Tables::Conserved);
        let held = with_pool_held(scene.storage, || tables(scene.storage, &mut lenses));
        assert_eq!(
            held,
            Tables::Unreadable("the pool gate was held or poisoned")
        );
        assert!(leak_unit(scene.storage));
        assert_eq!(
            tables(scene.storage, &mut lenses),
            Tables::Violated(FREE_RUNS)
        );
    });
}

/// The two binding texts the boundary check raises first are raised by the
/// rule's own call too: a duplicate binding, and a bound slot whose count is
/// zero. Under a held pool gate the rule is unsuccessful.
#[test]
fn the_rule_raises_the_binding_texts_itself_and_fails_closed_under_a_held_gate() {
    scene(&PRINCIPALS, |scene| {
        let mut lenses = Lenses::default();
        assert_eq!(conserved(scene.storage, &mut lenses), Ok(()));
        let found = with_duplicate_binding(scene.storage, &key(1), || {
            conserved(scene.storage, &mut lenses)
        });
        assert_eq!(
            found,
            Err(Failure::Violation(
                Obligation::History,
                "two bindings name one slot"
            ))
        );
        let (bound, _) = bound_and_free(&scene);
        set_refs(scene.storage, bound, 0);
        let found = conserved(scene.storage, &mut lenses);
        set_refs(scene.storage, bound, 1);
        assert_eq!(
            found,
            Err(Failure::Violation(
                Obligation::History,
                "a binding names a slot holding no resident object at its incarnation"
            ))
        );
        assert_eq!(conserved(scene.storage, &mut lenses), Ok(()), "restored");
        let held = with_pool_held(scene.storage, || conserved(scene.storage, &mut lenses));
        assert_eq!(
            held,
            Err(Failure::Unsuccessful("the pool gate was held or poisoned"))
        );
        let held = with_pool_held(scene.storage, || checked(&scene, &registry()));
        assert_eq!(
            held,
            Err(Failure::Unsuccessful("the pool gate was held or poisoned")),
            "a boundary whose earlier checks pass ends with the rule's result"
        );
    });
}

/// The live call on the indexed storage passes first, so the unsuccessful
/// result that follows comes from finalization.
#[test]
fn the_rule_is_unsuccessful_once_its_storage_is_finalized() {
    let mut storage = crate::storage::owner_fixture::storage(8);
    let mut lenses = Lenses::default();
    assert_eq!(
        conserved(&storage, &mut lenses),
        Ok(()),
        "premise: a live indexed storage"
    );
    assert_eq!(
        storage.finalize(&mut crate::storage::WorkBudget::new(1 << 16)),
        Ok(crate::storage::Finalization::Drained),
        "premise: finalization drained the storage"
    );
    let judged = lenses.judgments();
    assert_eq!(
        conserved(&storage, &mut lenses),
        Err(Failure::Unsuccessful("the storage was no longer live"))
    );
    assert_eq!(lenses.judgments(), judged, "the binding read refused first");
}

#[test]
fn the_rule_is_unsuccessful_over_a_live_storage_without_an_index() {
    let storage = crate::storage::owner_fixture::unindexed(8);
    let mut holdings = crate::storage::conservation::Holdings::default();
    storage.holdings_into(&mut holdings);
    assert_eq!(
        holdings.judge(&[]),
        Ok(()),
        "premise: the tables pass with no bindings"
    );
    let mut lenses = Lenses::default();
    assert_eq!(
        conserved(&storage, &mut lenses),
        Err(Failure::Unsuccessful("the storage was no longer live"))
    );
    assert_eq!(lenses.judgments(), 0, "the binding read refused first");
}

/// The pending operations of a cut through `rows` after row `fed`: every
/// operation invoked before the cut with rows after it, at its first
/// invocation.
fn pending_at(rows: &[Row], fed: usize) -> Vec<Pending> {
    let first = |op| {
        rows.iter()
            .filter(|row| row.op == op)
            .flat_map(Row::ordinals)
            .map(|(_, at)| at)
            .min()
    };
    let mut pending: Vec<Pending> = Vec::new();
    for row in &rows[fed..] {
        let op = WideOp(u64::from(row.op.0));
        let before = rows[..fed].iter().any(|earlier| earlier.op == row.op);
        if before && !pending.iter().any(|open| open.op == op) {
            let invoked = first(row.op).expect("a row with an ordinal");
            pending.push(Pending { op, invoked });
        }
    }
    pending
}

/// The rows of a live upload and GET, cut at every row with every operation
/// open across a cut declared pending there, never violate at a cut, pass at
/// every cut once the upload's result is in, and judge as the whole history
/// does.
#[test]
fn boundary_cuts_carry_pending_operations_to_the_whole_verdict() {
    scene(&PRINCIPALS, |mut scene| {
        let (mut rec, _) = uploaded(&mut scene, 6, Label(6));
        get(&mut scene, &mut rec, 6, Label(6));
        let mut rows = rec.rows().to_vec();
        rows.sort_by_key(|row| row.ordinals().map(|(_, at)| at.0).max());
        let whole = check(&Recorder::rebuilt(rows.clone()));
        assert!(matches!(whole, Verdict::Pass(_)), "{whole:?}");
        let mut cuts = Cuts::new(Owner(0));
        let result = rows
            .iter()
            .position(|row| row.kind == ActionKind::PutResult)
            .unwrap();
        for fed in 1..=rows.len() {
            let pending = pending_at(&rows, fed);
            let verdict = cuts.cut(&rows[..fed], &pending).unwrap();
            if fed > result {
                assert!(
                    matches!(verdict, Verdict::Pass(_)),
                    "row {fed}: {verdict:?}"
                );
            } else {
                // The adapter records the begin settled, which a cut before the result reads as misstated.
                let misstated = matches!(
                    verdict,
                    Verdict::Inconclusive(Inconclusive::Malformed { .. })
                );
                assert!(misstated, "row {fed}: {verdict:?}");
            }
        }
        assert!(cuts.passed());
        assert_eq!(cuts.finish(), whole);
        // An operation invoked after the last recorded row is open at this
        // boundary; the cut lies past its invocation.
        let end = rows
            .iter()
            .flat_map(Row::ordinals)
            .map(|(_, at)| at.0)
            .max()
            .unwrap();
        let late = Pending {
            op: WideOp(u64::MAX),
            invoked: Ordinal(end + 1),
        };
        let verdict = cuts.cut(&rows, &[late]).unwrap();
        assert!(matches!(verdict, Verdict::Pass(_)), "{verdict:?}");
        assert_eq!(
            cuts.cut(&rows[..1], &[]),
            Err(Failure::Unsuccessful("the row log shrank across a cut"))
        );
    });
}

/// An observer that drops with nothing else run still judges the world: a
/// teardown-only case with an unregistered binding, or with a corrupted
/// record, fails at teardown and the failure lands in the cell; a sound
/// world passes; and Drop leaves every byte as it found it.
#[test]
fn a_teardown_only_case_runs_the_checker() {
    for (planted, expected) in [
        (None, Some(UNEXPECTED)),
        (Some(300), Some(RECORD)),
        (Some(0), None),
    ] {
        scene(&PRINCIPALS, |scene| {
            let mut registry = registry();
            if planted.is_none() {
                registry = Registry::new(64);
            }
            if expected.is_none() {
                registry = self::registry();
            } else if let Some(at) = planted {
                flip(&scene, at);
            }
            let first = FirstFailure::default();
            let media = bound_media(&scene);
            let before = scene.control.device(media.start, media.len());
            let rows = Rc::new(RefCell::new(Vec::new()));
            let observer = Observer::new(
                scene.media(),
                Rc::new(RefCell::new(registry)),
                rows,
                first.clone(),
            );
            drop(observer.quiet());
            assert_eq!(first.get(), expected, "{planted:?}");
            assert_eq!(
                scene.control.device(media.start, media.len()),
                before,
                "Drop heals nothing"
            );
        });
    }
}

#[test]
fn a_unit_leaked_after_the_last_boundary_fails_teardown_by_the_free_runs() {
    for leak in [false, true] {
        scene(&PRINCIPALS, |scene| {
            if leak {
                assert!(leak_unit(scene.storage), "premise: a unit leaked");
            }
            let first = FirstFailure::default();
            let observer = Observer::new(
                scene.media(),
                Rc::new(RefCell::new(registry())),
                Rc::new(RefCell::new(Vec::new())),
                first.clone(),
            );
            drop(observer.quiet());
            let expected = leak.then_some(Failure::Violation(Obligation::Resources, FREE_RUNS));
            assert_eq!(first.get(), expected, "leak {leak}");
        });
    }
}

/// A failure at teardown raises once on normal return.
#[test]
fn a_teardown_failure_raises_on_normal_return() {
    scene(&PRINCIPALS, |scene| {
        let rows = Rc::new(RefCell::new(Vec::new()));
        let registry = Rc::new(RefCell::new(Registry::new(64)));
        let observer = Observer::new(scene.media(), registry, rows, FirstFailure::default());
        let raised = catch_unwind(AssertUnwindSafe(|| drop(observer)));
        let payload = raised.expect_err("the failure raised");
        let message = payload.downcast_ref::<String>().expect("a message");
        assert!(message.contains("an unexpected binding"), "{message}");
    });
}

/// While a primary panic unwinds, the observer records the truncated
/// history's verdict beside it and raises nothing: the primary payload
/// propagates unchanged. A truncated history that passes its checks is
/// unsuccessful, so a caught panic counts as a failure.
#[test]
fn a_primary_panic_keeps_its_payload_beside_a_truncated_verdict() {
    for (registry, truncated) in [
        (Registry::new(64), UNEXPECTED),
        (
            registry(),
            Failure::Unsuccessful("a panic truncated the run before teardown"),
        ),
    ] {
        scene(&PRINCIPALS, |scene| {
            let first = FirstFailure::default();
            let rows = Rc::new(RefCell::new(Vec::new()));
            let registry = Rc::new(RefCell::new(registry));
            let unwound = catch_unwind(AssertUnwindSafe(|| {
                let _observer = Observer::new(scene.media(), registry, rows, first.clone());
                std::panic::panic_any("the primary failure");
            }));
            let payload = unwound.expect_err("the primary panic propagated");
            assert_eq!(payload.downcast_ref::<&str>(), Some(&"the primary failure"));
            assert_eq!(
                first.get(),
                Some(Failure::Truncated(Box::new(truncated.clone()))),
                "{truncated:?}"
            );
        });
    }
}

/// The first failure is written once: a later failure, an inconclusive
/// oracle verdict included, leaves it as it is. A poisoned cell keeps and
/// still reads what it holds, an empty poisoned cell reads unsuccessful, and
/// an observer over a sound world with a poisoned cell raises.
#[test]
fn the_first_failure_survives_later_failures_and_poison() {
    let first = FirstFailure::default();
    let primary = Failure::Violation(Obligation::Bytes, "primary");
    assert!(first.record(primary.clone()));
    let inconclusive = Verdict::Inconclusive(Inconclusive::SearchBound { limit: 1 });
    assert!(!first.record(Failure::Oracle(inconclusive)));
    assert!(!first.record(Failure::Unsuccessful("later")));
    assert_eq!(first.get(), Some(primary.clone()));
    first.poison();
    assert!(!first.record(Failure::Unsuccessful("after poison")));
    assert_eq!(
        first.get(),
        Some(primary),
        "a poisoned cell keeps what it holds"
    );
    let empty = FirstFailure::default();
    empty.poison();
    assert_eq!(
        empty.get(),
        Some(Failure::Unsuccessful("the first-failure cell was poisoned"))
    );
    scene(&PRINCIPALS, |scene| {
        let rows = Rc::new(RefCell::new(Vec::new()));
        let registry = Rc::new(RefCell::new(registry()));
        let observer = Observer::new(scene.media(), registry, rows, empty.clone());
        let raised = catch_unwind(AssertUnwindSafe(|| drop(observer)));
        assert!(raised.is_err(), "a poisoned report cannot pass");
    });
}

/// A borrowed registry at teardown is a missing report, and a recorded
/// history the oracle does not pass fails at teardown with its verdict.
#[test]
fn a_missing_report_or_a_failing_history_cannot_pass() {
    scene(&PRINCIPALS, |scene| {
        let first = FirstFailure::default();
        let registry = Rc::new(RefCell::new(registry()));
        let held = registry.borrow_mut();
        let rows = Rc::new(RefCell::new(Vec::new()));
        drop(Observer::new(scene.media(), Rc::clone(&registry), rows, first.clone()).quiet());
        drop(held);
        assert_eq!(
            first.get(),
            Some(Failure::Unsuccessful(
                "the registry was borrowed at teardown"
            ))
        );
    });
    scene(&PRINCIPALS, |mut scene| {
        let (rec, object) = uploaded(&mut scene, 6, Label(6));
        let mut registry = registry();
        registry.register(key(6), Label(6), 0, object);
        let rows: Vec<Row> = rec
            .rows()
            .iter()
            .filter(|row| row.kind != ActionKind::Publish)
            .cloned()
            .collect();
        let first = FirstFailure::default();
        let observer = Observer::new(
            scene.media(),
            Rc::new(RefCell::new(registry)),
            Rc::new(RefCell::new(rows)),
            first.clone(),
        );
        drop(observer.quiet());
        assert!(
            matches!(first.get(), Some(Failure::Oracle(Verdict::Violation(_)))),
            "{:?}",
            first.get()
        );
    });
}

const H1: &[&str] = &["held read", "invalidation"];

/// A required witness passes only when it was armed and fired with every
/// ingredient it requires set for one correlation: one assembled from two
/// requests does not fire, one fired before it was armed does not count, a
/// witness requiring nothing never fires, an unfired or never-armed witness
/// is unsuccessful, and an overflowed log cannot pass.
#[test]
fn required_witnesses_need_correlated_ingredients() {
    let mut witnesses = Witnesses::new(16);
    witnesses.require("H1", H1);
    witnesses.ingredient("H1", 1, "held read");
    witnesses.ingredient("H1", 1, "invalidation");
    assert!(!witnesses.fire("H1", 1), "an unarmed witness does not fire");
    assert_eq!(
        witnesses.verdict(),
        Err(Failure::Unsuccessful("a required witness was never armed"))
    );
    witnesses.activate("H1");
    witnesses.ingredient("H1", 2, "held read");
    witnesses.ingredient("H1", 3, "invalidation");
    assert!(!witnesses.fire("H1", 2), "two requests are no witness");
    assert_eq!(
        witnesses.verdict(),
        Err(Failure::Unsuccessful("a required witness never fired"))
    );
    assert!(witnesses.fire("H1", 1));
    assert_eq!(witnesses.verdict(), Ok(()));
    witnesses.require("empty", &[]);
    witnesses.activate("empty");
    assert!(
        !witnesses.fire("empty", 1),
        "a witness requiring nothing never fires"
    );
    let mut full = Witnesses::new(1);
    full.ingredient("H1", 1, "held read");
    full.ingredient("H1", 1, "invalidation");
    assert_eq!(
        full.verdict(),
        Err(Failure::Unsuccessful("the witness log passed its bound"))
    );
}

/// A capture an I3 witness needs that the link dropped at its bound leaves
/// the case unsuccessful though the witness fired, and an observer judging
/// the witnesses fails at teardown.
#[test]
fn a_dropped_capture_leaves_a_fired_witness_unsuccessful() {
    use super::datagram::Datagrams;
    use super::link::{Faults, network};
    use super::rules::{Bound, Chain, Effect, MANIFEST, Manifest, Rule, Selector};
    let small = Manifest {
        captures: 2,
        ..MANIFEST
    };
    let (mut near, _far, net) = network(8, 8384, 0, [Faults::default(); 2]);
    let rule = Rule::new(Selector::Any, Effect::Drop);
    net.borrow_mut()
        .set_rules(Chain::new(vec![rule], &[1], &small).unwrap());
    let header = [0u8; 8];
    for _ in 0..3 {
        let datagram = super::datagram::Outgoing {
            peer: super::datagram::PeerId(0),
            header: &header,
            payload: [super::datagram::Payload::EMPTY; 2],
        };
        near.send(&[datagram]).unwrap();
    }
    let mut witnesses = Witnesses::new(16);
    witnesses.require("I3", &["lost result"]);
    witnesses.activate("I3");
    witnesses.ingredient("I3", 1, "lost result");
    assert!(witnesses.fire("I3", 1));
    let captured = net.borrow().verdict(&[]);
    assert_eq!(
        captured,
        super::audit::Verdict::Inconclusive(Bound::Captures)
    );
    witnesses.captures(&captured);
    assert_eq!(
        witnesses.verdict(),
        Err(Failure::Unsuccessful(
            "a capture a witness needs was dropped"
        ))
    );
    scene(&PRINCIPALS, |scene| {
        let first = FirstFailure::default();
        let observer = Observer::new(
            scene.media(),
            Rc::new(RefCell::new(registry())),
            Rc::new(RefCell::new(Vec::new())),
            first.clone(),
        )
        .witnessing(Rc::new(RefCell::new(witnesses)));
        drop(observer.quiet());
        assert_eq!(
            first.get(),
            Some(Failure::Unsuccessful(
                "a capture a witness needs was dropped"
            ))
        );
    });
}

/// The registry prunes only at a validated cut: before any cut passed, or
/// with rows recorded past the last cut, it stays whole, and at a passing
/// cut through every row it drops what the caller no longer needs, the
/// boundary still passing.
#[test]
fn the_registry_prunes_only_at_a_validated_cut() {
    scene(&PRINCIPALS, |mut scene| {
        let mut registry = registry();
        let (rec, object) = uploaded(&mut scene, 6, Label(6));
        registry.register(key(6), Label(6), 0, object);
        registry.register(key(9), Label(2), 0, payload(100, 9));
        let mut cuts = Cuts::new(Owner(0));
        let rows = rec.rows().len();
        assert!(!registry.prune((&cuts, rows), |_, _| false), "no cut yet");
        assert_eq!(registry.len(), 3);
        let verdict = cuts.cut(rec.rows(), &[]).unwrap();
        assert!(matches!(verdict, Verdict::Pass(_)), "{verdict:?}");
        assert!(
            !registry.prune((&cuts, rows + 1), |_, _| false),
            "rows past the cut"
        );
        assert!(registry.prune((&cuts, rows), |_, label| label != Label(2)));
        assert_eq!(registry.len(), 2, "the unbound label went");
        assert_eq!(checked(&scene, &registry), Ok(2));
    });
}

/// The shared adapters judge a live upload's source custody, receipts,
/// publication, reads and outcome independently: the live history passes,
/// and each named control fails through its inherited obligation.
#[test]
fn the_shared_adapters_reject_each_upload_control() {
    scene(&PRINCIPALS, |mut scene| {
        let (mut rec, object) = uploaded(&mut scene, 6, Label(6));
        get(&mut scene, &mut rec, 6, Label(6));
        let rows = rec.rows().to_vec();
        let named = |rows: Vec<Row>| check(&Recorder::rebuilt(rows)).violated();
        assert!(matches!(
            check(&Recorder::rebuilt(rows.clone())),
            Verdict::Pass(_)
        ));
        let mut read = rows.clone();
        let delivery = read
            .iter_mut()
            .rev()
            .find(|row| row.payload.is_some())
            .unwrap();
        delivery.payload.as_mut().unwrap()[0] ^= 1;
        assert_eq!(
            named(read),
            Some((
                Obligation::Bytes,
                "a complete read returned bytes other than the label's content"
            )),
            "wrong published bytes served"
        );
        let unpublished: Vec<_> = rows
            .iter()
            .filter(|row| row.kind != ActionKind::Publish)
            .cloned()
            .collect();
        assert_eq!(
            named(unpublished),
            Some((
                Obligation::History,
                "Published without the attempt's publication"
            )),
            "a full-receipt ACK claimed as success"
        );
        let mut early = rows.clone();
        let release = early
            .iter()
            .position(|row| {
                row.kind == ActionKind::Release && row.custodian == Some(Custodian::Retransmission)
            })
            .unwrap();
        let moved = early.remove(release);
        let ack = early
            .iter()
            .position(|row| row.kind == ActionKind::Ack)
            .unwrap();
        early.insert(ack, moved);
        Recorder::renumber(&mut early);
        assert_eq!(
            named(early),
            Some((
                Obligation::Custody,
                "retransmission retention ended before the receipt base passed its fragment"
            )),
            "early source release"
        );
        let mut invented = rows.clone();
        let result = invented
            .iter_mut()
            .find(|row| row.kind == ActionKind::PutResult)
            .unwrap();
        result.outcome = Some(Outcome::Put(PutOutcome::NotStarted));
        result.label = None;
        result.serial = None;
        assert_eq!(
            named(invented),
            Some((
                Obligation::History,
                "an attempt that did not publish published"
            )),
            "an invented no-effect outcome"
        );
        let ready = rows
            .iter()
            .find(|row| row.kind == ActionKind::Ready)
            .unwrap()
            .clone();
        let mut credited = rows.clone();
        for _ in 0..2 {
            let mut fragment = ready.clone();
            fragment.kind = ActionKind::Fragment;
            fragment.fragment = Some(0);
            fragment.label = None;
            fragment.grant = None;
            fragment.payload = Some(object[..super::adapters::FRAGMENT].to_vec());
            credited.push(fragment);
        }
        Recorder::renumber(&mut credited);
        assert_eq!(
            named(credited),
            Some((
                Obligation::History,
                "an attempt validated one fragment twice"
            )),
            "duplicate credit"
        );
    });
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    a_binding_to_a_slot_outside_the_resident_state_fails_history,
    a_binding_to_an_empty_slot_fails_history,
    a_dropped_capture_leaves_a_fired_witness_unsuccessful,
    a_missing_report_or_a_failing_history_cannot_pass,
    a_primary_panic_keeps_its_payload_beside_a_truncated_verdict,
    a_registry_past_its_bound_is_unsuccessful,
    a_teardown_failure_raises_on_normal_return,
    a_teardown_only_case_runs_the_checker,
    a_well_formed_record_framed_with_another_split_fails_bytes,
    a_well_formed_record_of_another_session_fails_bytes,
    an_unexpected_binding_and_a_raw_corruption_fail_their_obligations,
    bindings_and_raw_media_agree_with_the_registry,
    boundary_cuts_carry_pending_operations_to_the_whole_verdict,
    the_first_failure_survives_later_failures_and_poison,
    the_registry_prunes_only_at_a_validated_cut,
    the_shared_adapters_reject_each_upload_control,
    two_bindings_naming_one_slot_fail_history,
    two_bindings_routing_one_fingerprint_fail_history,
    warm_lenses_are_passive_and_allocate_nothing,
);

/// The accounts check passes on consistent reports and fails under its rule
/// text on one delivery the owner never counted, on one received datagram
/// with no account, and on one truncated delivery counted as malformed. For
/// a poisoned owner it skips the second and third comparisons and still
/// fails the first.
#[test]
fn the_accounts_check_fails_each_comparison_under_its_rule() {
    use super::DropReason;
    use super::link::NetReport;
    use super::observe::{UNACCOUNTED, accounts};
    let link = |delivered, truncated| NetReport {
        delivered,
        truncated,
        ..NetReport::default()
    };
    let mut owner = super::OwnerReport {
        received: 5,
        handled: 3,
        dropped: 2,
        ..super::OwnerReport::default()
    };
    owner.dropped_by[DropReason::Truncated as usize] = 1;
    owner.dropped_by[DropReason::Session as usize] = 1;
    let failed = Err(Failure::Violation(Obligation::Contain, UNACCOUNTED));
    let links = [link(3, 1), link(2, 0)];
    assert_eq!(accounts(&owner, false, links), Ok(()));
    let uncounted = [link(4, 1), link(2, 0)];
    assert_eq!(
        accounts(&owner, false, uncounted),
        failed,
        "an uncounted delivery"
    );
    assert_eq!(
        accounts(&owner, true, uncounted),
        failed,
        "poisoned, first comparison"
    );
    let unaccounted = super::OwnerReport {
        handled: 2,
        ..owner
    };
    assert_eq!(accounts(&unaccounted, false, links), failed, "no account");
    assert_eq!(
        accounts(&unaccounted, true, links),
        Ok(()),
        "poisoned skips it"
    );
    let mut malformed = owner;
    malformed.dropped_by[DropReason::Truncated as usize] = 0;
    malformed.dropped_by[DropReason::Malformed as usize] = 1;
    assert_eq!(
        accounts(&malformed, false, links),
        failed,
        "truncated as malformed"
    );
    assert_eq!(
        accounts(&malformed, true, links),
        Ok(()),
        "poisoned skips it"
    );
    let mut strange = malformed;
    strange.dropped_by[DropReason::NoPeer as usize] = 1;
    strange.dropped_by[DropReason::Malformed as usize] = 0;
    assert_eq!(
        accounts(&strange, false, links),
        Ok(()),
        "a stranger lifts the truncation premise"
    );
    let mut vacant = malformed;
    vacant.dropped_by[DropReason::Vacant as usize] = 1;
    vacant.dropped_by[DropReason::Malformed as usize] = 0;
    assert_eq!(
        accounts(&vacant, false, links),
        Ok(()),
        "a vacant slot lifts the truncation premise"
    );
    for (lifted, name) in [(strange, "a stranger"), (vacant, "a vacant slot")] {
        assert_eq!(
            accounts(&lifted, false, uncounted),
            failed,
            "{name}: an uncounted delivery still fails"
        );
        let short = super::OwnerReport {
            handled: lifted.handled - 1,
            ..lifted
        };
        assert_eq!(
            accounts(&short, false, links),
            failed,
            "{name}: a received datagram with no account still fails"
        );
    }
    // Each comparison also fails when the owner's side is the larger.
    let overcounted = super::OwnerReport {
        received: 6,
        handled: 4,
        ..owner
    };
    assert_eq!(
        accounts(&overcounted, false, links),
        failed,
        "received above deliveries"
    );
    let handled = super::OwnerReport {
        handled: 4,
        ..owner
    };
    assert_eq!(accounts(&handled, false, links), failed, "an extra account");
    let mut truncated = owner;
    truncated.dropped_by[DropReason::Truncated as usize] = 2;
    truncated.dropped_by[DropReason::Session as usize] = 0;
    assert_eq!(
        accounts(&truncated, false, links),
        failed,
        "truncated drops above deliveries"
    );
    // A checked total above u64::MAX fails the comparison even when its
    // wrapped value matches the expected zero.
    let empty = super::OwnerReport::default();
    let wrapped = [link(u64::MAX, 0), link(1, 0)];
    assert_eq!(
        accounts(&empty, true, wrapped),
        failed,
        "deliveries past u64::MAX"
    );
    let mut overflowing = super::OwnerReport {
        received: 0,
        handled: u64::MAX,
        dropped: 1,
        ..super::OwnerReport::default()
    };
    overflowing.dropped_by[DropReason::Session as usize] = 1;
    assert_eq!(
        accounts(&overflowing, false, [link(0, 0)]),
        failed,
        "handled plus dropped past u64::MAX"
    );
    assert_eq!(
        accounts(&overflowing, true, [link(0, 0)]),
        Ok(()),
        "poisoned skips it"
    );
    let truncations = [link(0, u64::MAX), link(0, 1)];
    assert_eq!(
        accounts(&empty, false, truncations),
        failed,
        "truncated deliveries past u64::MAX"
    );
    let mut stranger = empty;
    stranger.dropped_by[DropReason::NoPeer as usize] = 1;
    stranger.dropped = 1;
    stranger.received = 1;
    assert_eq!(
        accounts(&stranger, false, [link(1, u64::MAX), link(0, 1)]),
        Ok(()),
        "a stranger exempts the truncation total"
    );
}
