//! Strict replay and reduction of mixed-world bundles.

use crate::oracle::Obligation;
use crate::sim::action::ActionKind;
use crate::sim::manifest::Manifest;
use crate::sim::trace::{RECORD, load, reseal};

use super::super::super::observe::{Failure, UNREGISTERED_BYTES};
use super::super::bundle::Site;
use super::super::bundle::{Refusal, admit, named, traced};
use super::{
    Change, Edit, Identity, Refused, Replayed, Step, Stop, Verdict, conditions, enabled, premise,
    reduce, reduce_with, replay,
};

/// A manifest of `profile` pinning a placeholder executable.
fn manifest(profile: &str) -> Manifest {
    let text = crate::sim::manifest_tests::sample(profile, &"a".repeat(64), "x86_64-linux");
    Manifest::parse(&text).unwrap()
}

/// The bundle a run of `profile` records.
fn recorded(profile: &str) -> (Manifest, Vec<u8>) {
    let manifest = manifest(profile);
    let bytes = traced(admit(&manifest).unwrap(), Vec::new()).sink;
    (manifest, bytes)
}

const CHOICE: u8 = 3;
const TURN: u8 = 4;
const DRAW_IDENTITY: u8 = 1;
const SELECTION: u8 = 3;

/// The semantic records of `bytes` between `Begin` and the terminal, as
/// `reseal` hands them to an edit.
fn records(bytes: &[u8], manifest: &Manifest) -> Vec<[u8; RECORD]> {
    let mut kept = Vec::new();
    reseal(bytes, manifest.capacity(), |records| {
        kept.clone_from(records)
    });
    kept
}

/// Indices, among `records`, of each decision's identity record.
fn decisions(records: &[[u8; RECORD]]) -> Vec<usize> {
    (0..records.len())
        .filter(|&at| records[at][0] == CHOICE && records[at][4] == DRAW_IDENTITY)
        .collect()
}

/// The records of the decision starting at `at`.
fn decision(records: &[[u8; RECORD]], at: usize) -> std::ops::Range<usize> {
    let end = (at + 1..records.len())
        .find(|&next| records[next][0] != CHOICE || records[next][4] == DRAW_IDENTITY)
        .unwrap_or(records.len());
    at..end
}

/// Replays `bytes` in process and says whether it reproduced.
fn reproduced(bytes: &[u8], _: &super::Identity) -> Result<bool, String> {
    Ok(matches!(replay(bytes), Ok((Replayed::Reproduced, _))))
}

/// Reduces `original` and counts the candidates whose identity the
/// catalog holds. Every such candidate holds its enabling conditions, and
/// no candidate panics. The reducer catches a panic inside `run`, so the
/// conditions are tallied there and asserted after the reduction returns.
fn reduce_cataloged(original: &[u8]) -> (super::Reduced, usize) {
    let (mut cataloged, mut unheld) = (0, 0);
    let mut run = |admitted: super::Admitted<'_>, sink: &mut Vec<u8>| {
        traced(admitted, &mut *sink);
        let loaded = load(sink, u64::MAX).ok();
        let identity = loaded.as_ref().and_then(super::violated);
        if let (Some(loaded), Some(identity)) = (&loaded, identity)
            && let Some(held) = enabled(&identity, loaded)
        {
            cataloged += 1;
            unheld += usize::from(!held);
        }
    };
    let reduced = reduce_with(original, &mut reproduced, &mut run, super::MAX_STEPS).unwrap();
    assert_eq!(unheld, 0, "a cataloged identity without its conditions");
    assert!(
        reduced
            .steps
            .iter()
            .all(|step| step.verdict != Verdict::Panicked),
        "{:?}",
        reduced.steps
    );
    (reduced, cataloged)
}

/// An unchanged bundle replays to its digest, decision count and terminal
/// for the upload, faulted and both planted profiles.
#[test]
fn an_unchanged_bundle_is_reproduced() {
    for profile in ["upload", "faulted", "planted", "acked"] {
        let (_, bytes) = recorded(profile);
        assert_eq!(replay(&bytes).unwrap().0, Replayed::Reproduced, "{profile}");
    }
}

/// Edited tapes report their first divergence, never a pass: a changed
/// turn selection diverges at that turn's record; a missing decision
/// diverges where it stood, and an extra copy of a decision at the decision
/// after the copy; a decision appended after
/// the last diverges where it stands, its leftover refused; an
/// out-of-range selection diverges as an index refusal with no turn
/// recorded past it; a changed scenario diverges; a tape that ends before
/// its last decision is rejected as exhausted.
#[test]
fn edited_inputs_report_their_first_divergence() {
    let (manifest, bytes) = recorded("upload");
    let capacity = manifest.capacity();
    let base = records(&bytes, &manifest);
    let starts = decisions(&base);
    // `reseal` hands the records after `Begin`, which is semantic record 0.
    let semantic = |at: usize| Some(at + 1);
    let turn_selection = (0..base.len())
        .find(|&at| {
            base[at][0] == CHOICE
                && base[at][4] == SELECTION
                && base.get(at + 1).is_some_and(|next| next[0] == TURN)
                && u64::from_le_bytes(base[at][13..21].try_into().unwrap()) > 1
        })
        .expect("a turn's selection among several candidates");
    let changed = reseal(&bytes, capacity, |records| {
        let selection = &mut records[turn_selection];
        let bound = u64::from_le_bytes(selection[13..21].try_into().unwrap());
        let value = u64::from_le_bytes(selection[5..13].try_into().unwrap());
        selection[5..13].copy_from_slice(&((value + 1) % bound).to_le_bytes());
    });
    let missing = reseal(&bytes, capacity, |records| {
        records.drain(decision(records, starts[5]));
    });
    let extra = reseal(&bytes, capacity, |records| {
        let copy: Vec<_> = records[decision(records, starts[5])].to_vec();
        records.splice(starts[5]..starts[5], copy);
    });
    let trailing = reseal(&bytes, capacity, |records| {
        let copy: Vec<_> = records[decision(records, starts[5])].to_vec();
        records.extend(copy);
    });
    let cases = [
        ("changed", &changed, semantic(turn_selection + 1)),
        ("missing", &missing, semantic(starts[5])),
        // The copy reads as the decision it repeats; the next one diverges.
        (
            "extra",
            &extra,
            semantic(starts[5] + decision(&base, starts[5]).len()),
        ),
    ];
    for (name, edited, expected) in cases {
        let (replayed, _) = replay(edited).unwrap();
        let Replayed::Diverged { at, reason } = replayed else {
            panic!("{name}: a divergence is never a pass: {replayed:?}");
        };
        assert_eq!(at, expected, "{name}");
        if name == "missing" {
            assert!(reason.contains("Identity"), "{reason}");
        }
    }
    let (replayed, _) = replay(&trailing).unwrap();
    // The original ends in the appended copy, which the replay never draws.
    let appended = semantic(base.len());
    assert!(
        matches!(&replayed, Replayed::Diverged { at, reason } if *at == appended && reason.contains("Trailing")),
        "{replayed:?}"
    );
    let out_of_range = reseal(&bytes, capacity, |records| {
        let selection = &mut records[turn_selection];
        let bound = selection[13..21].to_vec();
        selection[5..13].copy_from_slice(&bound);
    });
    let (replayed, again) = replay(&out_of_range).unwrap();
    let Replayed::Diverged {
        at: Some(at),
        reason,
    } = replayed
    else {
        panic!("an out-of-range selection diverges: {replayed:?}");
    };
    assert!(reason.contains("Index"), "{reason}");
    // The refused decision, from its identity record on, is the first the
    // replay leaves out: the chooser commits a decision only once it checks.
    let identity = starts
        .iter()
        .rev()
        .find(|&&start| start <= turn_selection)
        .copied();
    assert_eq!(Some(at), identity.and_then(semantic));
    let (records_again, _) = again.as_chunks::<RECORD>();
    let semantic_again: Vec<_> = records_again
        .iter()
        .filter(|record| crate::sim::trace::is_semantic(record[0]))
        .collect();
    assert!(
        semantic_again[at..].iter().all(|record| record[0] != TURN),
        "no turn applies past a refused draw"
    );
    let (profile, plan, _) = named("upload", manifest.root).unwrap();
    let mut fewer = Edit::of(&profile, &plan);
    fewer.counts[1] = 0;
    let rescoped = reseal(&bytes, capacity, |records| {
        let text: Vec<u8> = records
            .iter()
            .filter(|record| record[0] == 2 && record[1] == 1)
            .flat_map(|record| record[5..5 + usize::from(record[4])].to_vec())
            .collect();
        let text = String::from_utf8(text)
            .unwrap()
            .replace("scenario = base", &format!("scenario = {}", fewer.encode()));
        let at = records
            .iter()
            .position(|record| record[0] == 2 && record[1] == 1)
            .unwrap();
        records.retain(|record| !(record[0] == 2 && record[1] == 1));
        let fields: Vec<[u8; RECORD]> = text
            .as_bytes()
            .chunks(RECORD - 5)
            .enumerate()
            .map(|(chunk, bytes)| {
                let mut record = [0; RECORD];
                record[0] = 2;
                record[1] = 1;
                record[2..4].copy_from_slice(&(chunk as u16).to_le_bytes());
                record[4] = bytes.len() as u8;
                record[5..5 + bytes.len()].copy_from_slice(bytes);
                record
            })
            .collect();
        records.splice(at..at, fields);
    });
    let (replayed, _) = replay(&rescoped).unwrap();
    let field = base
        .iter()
        .position(|record| record[0] == 2 && record[1] == 1);
    assert!(
        matches!(replayed, Replayed::Diverged { at: Some(at), .. } if Some(at) > field.and_then(semantic)),
        "a changed scenario diverges past its recorded manifest: {replayed:?}"
    );
    let last = *starts.last().unwrap();
    let exhausted = reseal(&bytes, capacity, |records| {
        records.drain(decision(records, last));
    });
    assert_eq!(replay(&exhausted).err(), Some(Refused::Exhausted));
}

#[test]
fn a_refused_setup_draw_diverges_and_an_empty_tape_is_exhausted() {
    let (manifest, bytes) = recorded("upload");
    let capacity = manifest.capacity();
    let base = records(&bytes, &manifest);
    // `mixed_run` draws the index key pair as its first decision.
    let key_pair = decisions(&base)[0];
    let missing = reseal(&bytes, capacity, |records| {
        records.drain(decision(records, key_pair));
    });
    let (replayed, _) = replay(&missing).unwrap();
    assert!(
        matches!(&replayed, Replayed::Diverged { at, reason } if *at == Some(key_pair + 1) && reason.contains("Identity")),
        "{replayed:?}"
    );
    let empty = reseal(&bytes, capacity, |records| {
        records.retain(|record| record[0] != CHOICE);
    });
    assert_eq!(replay(&empty).err(), Some(Refused::Exhausted));
}

#[test]
fn a_refused_peer_setup_draw_diverges() {
    let (manifest, bytes) = recorded("h6-get");
    let base = records(&bytes, &manifest);
    let scripted_setup = 1 + super::super::ACTORS.len();
    let peer_key_pair = decisions(&base)[scripted_setup];
    let missing = reseal(&bytes, manifest.capacity(), |records| {
        records.drain(decision(records, peer_key_pair));
    });
    let (replayed, _) = replay(&missing).unwrap();
    assert!(
        matches!(&replayed, Replayed::Diverged { at, reason } if *at == Some(peer_key_pair + 1) && reason.contains("Identity")),
        "{replayed:?}"
    );
}

/// The failure identity `regression` keeps: a violation of `obligation`
/// whose full identity equals the one `original` records.
fn same_identity(
    original: &[u8],
    regression: &[u8],
    obligation: Obligation,
) -> crate::sim::trace::Loaded {
    let loaded = load(regression, u64::MAX).unwrap();
    let identity = super::violated(&loaded).expect("a violation");
    assert_eq!(
        (identity.bytes()[1], identity.bytes()[2]),
        (1, obligation as u8 + 1)
    );
    assert_eq!(
        Some(identity),
        super::violated(&load(original, u64::MAX).unwrap()),
        "the same claim"
    );
    loaded
}

/// Steps of `steps` the reducer kept.
fn kept(steps: &[Step]) -> Vec<Change> {
    steps
        .iter()
        .filter(|step| step.verdict == Verdict::Kept)
        .map(|step| step.change)
        .collect()
}

/// A planted record change caught at a later stopped boundary reduces to a
/// regression of the original's full identity, a Bytes violation, with its
/// premise: every cataloged candidate holds its enabling conditions and no
/// step panics, each round tries whole kinds and flags before it lowers a
/// budget, deleting a prerequisite the upload keeps breaks a dependency,
/// the regression keeps the upload's actions and replays, and it is
/// smaller.
#[test]
fn a_planted_cross_cut_failure_reduces_to_its_obligation() {
    let (_, bytes) = recorded("planted");
    let (reduced, cataloged) = reduce_cataloged(&bytes);
    assert!(cataloged > 1, "{cataloged} cataloged candidates");
    let loaded = same_identity(&bytes, &reduced.bundle, Obligation::Bytes);
    assert_eq!(premise(super::Plant::PublishedByte, &loaded), Some(true));
    assert_ne!(reduced.manifest.scenario, "base", "{:?}", reduced.steps);
    let kept = kept(&reduced.steps);
    assert!(
        kept.contains(&Change::Delete(ActionKind::DeferSupply)),
        "{kept:?}"
    );
    assert!(kept.contains(&Change::Clear("link_faults")), "{kept:?}");
    for round in reduced
        .steps
        .split_inclusive(|step| step.verdict == Verdict::Kept)
    {
        let late = |step: &Step| matches!(step.change, Change::Lower(..) | Change::Halve(..));
        let budget = round.iter().position(late);
        let group = round.iter().rposition(|step| !late(step));
        if let (Some(budget), Some(group)) = (budget, group) {
            assert!(
                group < budget || round[group].verdict == Verdict::Kept,
                "{round:?}"
            );
        }
    }
    let broken = Step {
        change: Change::Delete(ActionKind::PutPrepare),
        verdict: Verdict::Breaks,
    };
    assert!(reduced.steps.contains(&broken), "{:?}", reduced.steps);
    for kind in [
        ActionKind::PutInvoke,
        ActionKind::PutPrepare,
        ActionKind::Supply,
    ] {
        assert!(
            reduced.scenario.contains(&format!("{kind:?}")),
            "{}",
            reduced.scenario
        );
    }
    assert_eq!(replay(&reduced.bundle).unwrap().0, Replayed::Reproduced);
    assert!(
        reduced.bundle.len() < bytes.len(),
        "the regression is smaller"
    );
}

/// The planted claim of publication on acknowledgment reduces to a history
/// regression with its supplier and acknowledgment premise: the result
/// reaches the client in the turn its last fragment is acknowledged, so
/// clearing the dropped results, like deleting the supply or the outcome
/// collection, leaves another outcome the reducer rejects.
#[test]
fn a_planted_put_claim_reduces_to_its_history_violation() {
    let (_, bytes) = recorded("acked");
    let reduced = reduce(&bytes, &mut reproduced).unwrap();
    assert_eq!(reduced.stop, Stop::Exhausted, "{:?}", reduced.steps);
    let loaded = same_identity(&bytes, &reduced.bundle, Obligation::History);
    assert_eq!(premise(super::Plant::AckAsSuccess, &loaded), Some(true));
    let other = |change| Step {
        change,
        verdict: Verdict::OtherOutcome,
    };
    for change in [
        Change::Delete(ActionKind::Supply),
        Change::Delete(ActionKind::PutOutcome),
        Change::Clear("drop_result"),
    ] {
        assert!(
            reduced.steps.contains(&other(change)),
            "{change:?}: {:?}",
            reduced.steps
        );
    }
    assert_eq!(replay(&reduced.bundle).unwrap().0, Replayed::Reproduced);
}

/// The stalled heal reduces to its Progress violation with its premise: a
/// delivered rekey, a GET from each client and a witnessed read. Deleting
/// the reads or lowering either GET budget to 0 keeps the violation but
/// loses the premise, so the regression keeps the rekey, the GETs and the
/// read, and replays.
#[test]
fn a_planted_stalled_heal_reduces_to_its_progress_violation() {
    let (_, bytes) = recorded("rekey-stalled");
    let reduced = reduce(&bytes, &mut reproduced).unwrap();
    assert_eq!(reduced.stop, Stop::Exhausted, "{:?}", reduced.steps);
    let loaded = same_identity(&bytes, &reduced.bundle, Obligation::Progress);
    assert_eq!(premise(super::Plant::StalledHeal, &loaded), Some(true));
    for kind in [ActionKind::Rekey, ActionKind::Get, ActionKind::Read] {
        assert!(
            reduced.scenario.contains(&format!("{kind:?}")),
            "{}",
            reduced.scenario
        );
    }
    let unpremised = |change| Step {
        change,
        verdict: Verdict::NoPremise,
    };
    for change in [
        Change::Delete(ActionKind::Read),
        Change::Lower("gets_first", 0),
        Change::Lower("gets_second", 0),
    ] {
        assert!(
            reduced.steps.contains(&unpremised(change)),
            "{change:?}: {:?}",
            reduced.steps
        );
    }
    assert_eq!(replay(&reduced.bundle).unwrap().0, Replayed::Reproduced);
}

/// A plant's premise needs its witnesses: a run without the plant has none;
/// a planted run whose accepted supplies lose a fragment or split across
/// attempts, or whose outcome is never collected as published, loses its
/// premise, and a claim on acknowledgment loses it without its
/// acknowledgment.
/// A leaked unit, which the cataloged `leaked` control plants, takes the
/// same collected publication as its premise.
#[test]
fn a_premise_needs_every_witness() {
    use super::super::bundle::{PutRecord, UploadState};
    let (_, upload) = recorded("upload");
    let upload = load(&upload, u64::MAX).unwrap();
    assert_eq!(premise(super::Plant::None, &upload), None);
    let (_, planted) = recorded("planted");
    let planted = load(&planted, u64::MAX).unwrap();
    assert_eq!(premise(super::Plant::PublishedByte, &planted), Some(true));
    assert_eq!(
        premise(super::Plant::LeakedUnit, &planted),
        Some(true),
        "the leaked control's plant acts once the upload publishes"
    );
    let mut short = planted.clone();
    short.events.retain(|event| {
        PutRecord::of(event)
            .is_none_or(|put| put.kind != Some(ActionKind::Supply) || put.fragment != 2)
    });
    assert_eq!(premise(super::Plant::PublishedByte, &short), Some(false));
    let mut uncollected = planted.clone();
    uncollected
        .events
        .retain(|event| UploadState::of(event).is_none_or(|state| state.outcome == 0));
    let granted = uncollected
        .events
        .iter()
        .filter_map(UploadState::of)
        .any(|state| state.grant > 0);
    assert!(granted, "only the publication is gone");
    assert_eq!(
        premise(super::Plant::PublishedByte, &uncollected),
        Some(false)
    );
    let mut split = planted.clone();
    let supply = split
        .events
        .iter_mut()
        .find(|event| PutRecord::of(event).is_some_and(|put| put.kind == Some(ActionKind::Supply)))
        .unwrap();
    supply.payload[1] ^= 0x40;
    assert_eq!(
        premise(super::Plant::PublishedByte, &split),
        Some(false),
        "one attempt supplies all"
    );
    let (_, acked) = recorded("acked");
    let acked = load(&acked, u64::MAX).unwrap();
    assert_eq!(premise(super::Plant::AckAsSuccess, &acked), Some(true));
    let mut unacked = acked.clone();
    unacked.events.retain(|event| {
        UploadState::of(event)
            .is_none_or(|state| state.base != super::FRAGMENTS || state.outcome != 0)
    });
    assert_eq!(premise(super::Plant::AckAsSuccess, &unacked), Some(false));
}

/// A step whose run panics while the original is a violation is
/// unsuccessful, never a kept failure: the reducer rejects the step and
/// keeps what its deletion would have removed.
#[test]
fn a_panic_under_a_violation_is_never_kept() {
    let (_, bytes) = recorded("planted");
    let mut run = |admitted: super::Admitted<'_>, sink: &mut Vec<u8>| {
        let closed = traced(admitted, Vec::new());
        let declared = load(&closed.sink, u64::MAX).unwrap();
        let config = declared
            .fields
            .iter()
            .find(|(field, _)| *field == crate::sim::trace::Field::Config)
            .unwrap();
        assert!(
            config.1.contains(&(ActionKind::DeferSupply as u8)),
            "a production assertion"
        );
        sink.extend(closed.sink);
    };
    let reduced = reduce_with(&bytes, &mut reproduced, &mut run, super::MAX_STEPS).unwrap();
    let panicked = Step {
        change: Change::Delete(ActionKind::DeferSupply),
        verdict: Verdict::Panicked,
    };
    assert!(reduced.steps.contains(&panicked), "{:?}", reduced.steps);
    assert!(
        reduced.scenario.contains("DeferSupply"),
        "{}",
        reduced.scenario
    );
}

/// Every step is replayed in a fresh process before it is kept: when only
/// the original reproduces, every step that would be kept is rejected and
/// the result is the original.
#[test]
fn a_step_that_does_not_replay_is_never_kept() {
    let (_, bytes) = recorded("planted");
    let mut calls = 0;
    let mut first_only = |_: &[u8], _: &super::Identity| {
        calls += 1;
        Ok(calls == 1)
    };
    let reduced = reduce(&bytes, &mut first_only).unwrap();
    assert!(kept(&reduced.steps).is_empty(), "{:?}", reduced.steps);
    assert!(
        reduced
            .steps
            .iter()
            .any(|step| step.verdict == Verdict::Unreproduced)
    );
    assert_eq!(reduced.bundle, bytes);
    let (_, manifest) = super::recorded(&bytes).unwrap();
    let (profile, plan, _) = super::scenario(&manifest).unwrap();
    assert_eq!(reduced.manifest, manifest, "the original's manifest");
    assert_eq!(reduced.scenario, Edit::of(&profile, &plan).describe());
}

/// A planted violation whose bundle keeps its violation record and its
/// identity but none of the plant's premise is refused before any run.
#[test]
fn a_violation_without_the_premise_is_unreducible() {
    use crate::sim::trace::{Field, Outcome, Recorder, Terminal, Work};
    let (manifest, planted) = recorded("planted");
    let loaded = load(&planted, u64::MAX).unwrap();
    let violation = loaded.violation.expect("the planted run violates");
    let identity = loaded
        .events
        .iter()
        .find(|event| event.kind == super::super::bundle::IDENTITY)
        .expect("the planted run records its identity");
    let mut recorder = Recorder::new(Vec::new(), manifest.capacity());
    recorder.field(Field::Manifest, manifest.canonical().as_bytes());
    recorder.violation(&violation);
    recorder.event(identity);
    let terminal = Terminal::Complete {
        outcome: Outcome::Violation,
        fired: 0,
        required: 0,
    };
    let unwitnessed = recorder.finish(terminal, Work::default()).sink;
    assert_eq!(
        premise(
            super::Plant::PublishedByte,
            &load(&unwitnessed, u64::MAX).unwrap()
        ),
        Some(false)
    );
    let mut runs = 0;
    let mut unchanged = |_: super::Admitted<'_>, sink: &mut Vec<u8>| {
        runs += 1;
        sink.clone_from(&unwitnessed);
    };
    let reduced = reduce_with(
        &unwitnessed,
        &mut |_, _| Ok(true),
        &mut unchanged,
        super::MAX_STEPS,
    );
    assert!(
        matches!(&reduced, Err(Refused::Unreducible(reason))
            if reason == "the bundle does not witness its plant's premise"),
        "{reduced:?}"
    );
    assert_eq!(runs, 0);
}

/// A passing bundle, a bundle a fresh process does not reproduce, and a
/// fresh process that cannot run each refuse the reduction by their own
/// class.
#[test]
fn a_passing_or_unreproduced_bundle_is_unreducible() {
    let unreducible = |reason: &str| Err(Refused::Unreducible(reason.into()));
    let (_, passing) = recorded("upload");
    assert_eq!(
        reduce(&passing, &mut |_, _| Ok(true)).map(|_| ()),
        unreducible("the bundle records no complete violation and no panic")
    );
    let (_, failing) = recorded("planted");
    assert_eq!(
        reduce(&failing, &mut |_, _| Ok(false)).map(|_| ()),
        unreducible("the bundle does not replay in a fresh process")
    );
    let broken = reduce(&failing, &mut |_, _| Err("no worker".into()));
    assert_eq!(
        broken.err(),
        Some(Refused::Infrastructure("no worker".into()))
    );
}

/// An edit encodes and decodes to itself, applies only as a reduction, and
/// a manifest naming one admits the reduced scenario; a kind kept without
/// its budget, and a supply waiting on deferrals no kind makes, break a
/// dependency. A scripted plan's budget belongs to its script.
#[test]
fn an_edit_round_trips_and_only_reduces() {
    let (profile, plan, _) = named("planted", 3).unwrap();
    let edit = Edit::of(&profile, &plan);
    assert_eq!(Edit::decode(&edit.encode()), Some(edit));
    assert!(edit.apply(&profile, plan).is_some());
    let mut grown = edit;
    grown.counts[0] += 1;
    assert!(grown.apply(&profile, plan).is_none());
    let mut added = edit;
    added.kinds |= 1 << (ActionKind::Close as u8 - 1);
    assert!(added.apply(&profile, plan).is_none());
    assert!(Edit::decode("zz").is_none());
    let mut fewer = edit;
    fewer.flags[0] = false;
    let reduced = manifest("planted").with_scenario(fewer.encode());
    assert!(admit(&reduced).is_ok());
    assert!(admit(&reduced.clone().with_scenario(grown.encode())).is_err());
    let mut unfunded = edit;
    unfunded.counts[2] = 0;
    assert!(unfunded.breaks(), "an upload kept with no upload budget");
    assert!(!edit.breaks());
    let mut starved = edit;
    starved.kinds &= !(1 << (ActionKind::DeferSupply as u8 - 1));
    assert!(starved.counts[super::budget("withhold")] > 0);
    assert!(
        starved.breaks(),
        "a supply waiting on deferrals no kind makes"
    );
    starved.counts[super::budget("withhold")] = 0;
    assert!(!starved.breaks());
    let (profile, plan, _) = named("h1-get", 3).unwrap();
    let mut unscripted = Edit::of(&profile, &plan);
    unscripted.counts[1] = 0;
    assert!(unscripted.apply(&profile, plan).is_none());
    assert_eq!(
        admit(&manifest("h1-get").with_scenario(unscripted.encode())).err(),
        Some(Refusal::Scenario),
        "a scripted plan's budget belongs to its script"
    );
}

#[test]
fn a_refused_link_draw_diverges() {
    const LINK: u8 = 3;
    let (manifest, bytes) = recorded("faulted");
    let capacity = manifest.capacity();
    let base = records(&bytes, &manifest);
    let link = decisions(&base)
        .into_iter()
        .find(|&at| base[at][7] == LINK)
        .expect("a link draw in the faulted profile");
    let missing = reseal(&bytes, capacity, |records| {
        records.drain(decision(records, link));
    });
    let (replayed, _) = replay(&missing).unwrap();
    assert!(
        matches!(&replayed, Replayed::Diverged { at: Some(at), .. } if *at > link),
        "{replayed:?}"
    );
}

/// The bundle a run of `profile` records before its panic, and the panic.
fn panicked(profile: &str) -> (Vec<u8>, String) {
    let manifest = manifest(profile);
    let mut sink = Vec::new();
    let panic = crate::sim::unwind::caught(|| traced(admit(&manifest).unwrap(), &mut sink))
        .expect_err("the planted panic");
    (sink, panic)
}

/// Says in process whether `bytes` reproduces `identity`: a violation's
/// bundle replays to its digest, and a panicked run's manifest reruns to
/// the same panic and the same bundle.
fn replays_as(bytes: &[u8], identity: &super::Identity) -> Result<bool, String> {
    match identity {
        super::Identity::Violation(_) => reproduced(bytes, identity),
        super::Identity::Panic(panic) => {
            let (_, manifest) = super::recorded(bytes).map_err(|refusal| format!("{refusal:?}"))?;
            let mut sink = Vec::new();
            let rerun = crate::sim::unwind::caught(|| traced(admit(&manifest).unwrap(), &mut sink));
            Ok(rerun.err().as_ref() == Some(panic) && sink == bytes)
        }
    }
}

/// The `asserting` control's run panics at its planted debug assertion.
/// The test compiles in a build with debug assertions. A build without
/// them runs past the assertion, and a sweep of such a build counts the
/// control's runs as passed.
#[test]
#[cfg(debug_assertions)]
fn the_asserting_control_panics_at_its_debug_assertion() {
    let (_, panic) = panicked("asserting");
    assert!(
        panic.ends_with(": a planted debug assertion once the upload published"),
        "{panic}"
    );
}

/// A run that panicked reduces under its own identity: its bundle stops
/// at the panic, every kept step panics at the same location with the same
/// payload, the regression names both, and the regression's turn limit
/// ends at the turn where the panic occurred.
#[test]
fn a_panicking_original_reduces_under_its_panic() {
    let (bytes, panic) = panicked("panicking");
    assert!(
        panic.ends_with(": a planted panic once the upload published"),
        "{panic}"
    );
    assert!(panic.contains("world_tests.rs:"), "{panic}");
    let loaded = load(&bytes, u64::MAX).unwrap();
    assert_eq!(
        loaded.terminal,
        crate::sim::trace::Terminal::Infrastructure(crate::sim::trace::Infrastructure::Truncated)
    );
    let reduced = reduce(&bytes, &mut replays_as).unwrap();
    assert_eq!(reduced.identity, super::Identity::Panic(panic.clone()));
    assert!(!kept(&reduced.steps).is_empty(), "{:?}", reduced.steps);
    assert!(
        kept(&reduced.steps)
            .iter()
            .any(|change| matches!(change, Change::Schedule(_))),
        "{:?}",
        reduced.steps
    );
    let regression = load(&reduced.bundle, u64::MAX).unwrap();
    assert_eq!(
        reduced.manifest.count("turns"),
        regression.turns.len() as u64 + 1,
        "the turn limit ends at the turn where the panic occurred"
    );
    assert!(reduced.bundle.len() < bytes.len());
    assert_eq!(replays_as(&reduced.bundle, &reduced.identity), Ok(true));
    assert_eq!(replay(&reduced.bundle).err(), Some(Refused::Exhausted));
}

/// A step that panics elsewhere, with the original's payload, is another
/// failure: once the original's rerun panicked at its site, every
/// candidate panics at this test's site, and the reducer refuses each as a
/// reproducer and keeps the original.
#[test]
fn a_panic_at_another_site_is_refused_as_a_reproducer() {
    let (bytes, _) = panicked("panicking");
    let mut runs = 0;
    let mut run = |admitted: super::Admitted<'_>, sink: &mut Vec<u8>| {
        runs += 1;
        assert!(runs == 1, "a planted panic once the upload published");
        traced(admitted, sink);
    };
    let reduced = reduce_with(&bytes, &mut replays_as, &mut run, super::MAX_STEPS).unwrap();
    assert!(kept(&reduced.steps).is_empty(), "{:?}", reduced.steps);
    assert!(
        reduced
            .steps
            .iter()
            .any(|step| step.verdict == Verdict::Panicked),
        "{:?}",
        reduced.steps
    );
    assert_eq!(reduced.bundle, bytes);
}

/// A bundle cut short of its terminal whose rerun completes is no panic to
/// reduce under: the reducer refuses it before any step.
#[test]
fn a_truncated_bundle_whose_rerun_completes_is_unreducible() {
    let (_, bytes) = recorded("planted");
    let cut = &bytes[..bytes.len() / RECORD / 2 * RECORD];
    let reduced = reduce(cut, &mut |_, _| Ok(true));
    assert!(
        matches!(&reduced, Err(Refused::Unreducible(reason)) if reason.contains("does not panic")),
        "{reduced:?}"
    );
}

/// An unplanted violation, a resident record changed before the run,
/// reduces under its rule's cataloged enabling condition to a regression
/// that keeps the original's full identity, still checks a boundary, names
/// `boundary-checked`, and replays.
#[test]
fn an_unplanted_violation_reduces_under_its_enabling_conditions() {
    let (_, original) = recorded("corrupted");
    let (reduced, cataloged) = reduce_cataloged(&original);
    assert!(cataloged > 1, "{cataloged} cataloged candidates");
    assert_eq!(reduced.conditions, ["boundary-checked"]);
    assert!(
        reduced
            .steps
            .iter()
            .all(|step| step.verdict != Verdict::NoPremise),
        "{:?}",
        reduced.steps
    );
    assert_eq!(reduced.stop, Stop::Exhausted);
    assert!(!kept(&reduced.steps).is_empty(), "{:?}", reduced.steps);
    let Identity::Violation(identity) = &reduced.identity else {
        panic!("a violation identity");
    };
    assert_eq!(
        identity.bytes()[..5],
        [
            super::super::bundle::IDENTITY_VERSION,
            1,
            Obligation::Bytes as u8 + 1,
            0,
            Site::Run as u8
        ]
    );
    let loaded = load(&reduced.bundle, u64::MAX).unwrap();
    let before = load(&original, u64::MAX).unwrap();
    assert_eq!(super::violated(&before), Some(*identity));
    assert_eq!(super::violated(&loaded), Some(*identity), "the same claim");
    assert_eq!(enabled(identity, &loaded), Some(true));
    assert!(matches!(
        replay(&reduced.bundle),
        Ok((Replayed::Reproduced, _))
    ));
}

/// A reduction stops at its step bound with the best regression kept so
/// far, which keeps the original's identity, and marks it bounded.
#[test]
fn a_reduction_stops_at_its_step_bound() {
    let (_, original) = recorded("corrupted");
    let mut run = |admitted: super::Admitted<'_>, sink: &mut Vec<u8>| {
        traced(admitted, sink);
    };
    let reduced = reduce_with(&original, &mut reproduced, &mut run, 2).unwrap();
    assert_eq!(reduced.stop, Stop::Bounded);
    assert_eq!(reduced.steps.len(), 2, "{:?}", reduced.steps);
    assert!(!kept(&reduced.steps).is_empty(), "{:?}", reduced.steps);
    assert_ne!(reduced.bundle, original);
    same_identity(&original, &reduced.bundle, Obligation::Bytes);
    assert_eq!(reduced.conditions, ["boundary-checked"]);
}

/// A bundle of `manifest` that records `failure` surfacing at `site` as a
/// complete violation, and a stop event naming `checked` stopped
/// boundaries when `checked` is given.
fn violating(manifest: &Manifest, failure: &Failure, site: Site, checked: Option<u64>) -> Vec<u8> {
    violation_bundle(manifest, failure, Some(site), checked)
}

/// [`violating`] with the identity event recorded only when `site` is
/// given.
fn violation_bundle(
    manifest: &Manifest,
    failure: &Failure,
    site: Option<Site>,
    checked: Option<u64>,
) -> Vec<u8> {
    use super::super::bundle::{Composed, failure_code, identity_event, stop_event};
    use crate::sim::trace::{Field, Outcome, Recorder, Terminal, Work};
    let mut recorder = Recorder::new(Vec::new(), manifest.capacity());
    recorder.field(Field::Manifest, manifest.canonical().as_bytes());
    recorder.violation(&failure_code(failure));
    if let Some(site) = site {
        recorder.event(&identity_event(failure, site));
    }
    if let Some(checked) = checked {
        let composed = Composed {
            checked,
            owners: 1,
            clients: 2,
        };
        recorder.event(&stop_event(crate::sim::turn::End::Done, Some(composed)));
    }
    let terminal = Terminal::Complete {
        outcome: Outcome::Violation,
        fired: 0,
        required: 0,
    };
    recorder.finish(terminal, Work::default()).sink
}

/// The cataloged rule the synthetic reductions start from.
const CATALOGED: Failure = Failure::Violation(Obligation::Bytes, UNREGISTERED_BYTES);

/// A rule sharing the cataloged rule's first 41 bytes, which the violation
/// record keeps.
const SAME_PREFIX: Failure = Failure::Violation(
    Obligation::Bytes,
    "a bound slot's bytes match no registered contents",
);

/// Two rules that share the violation record's truncated prefix share one
/// violation record but keep distinct identities; another obligation or
/// another site is another identity too.
#[test]
fn rules_sharing_a_truncated_prefix_keep_distinct_identities() {
    use super::super::bundle::{failure_code, identity_event};
    assert_eq!(failure_code(&CATALOGED), failure_code(&SAME_PREFIX));
    let identity = |failure: &Failure, site| identity_event(failure, site).payload;
    let original = identity(&CATALOGED, Site::Run);
    assert_ne!(original, identity(&SAME_PREFIX, Site::Run));
    assert_ne!(original, identity(&CATALOGED, Site::Settled));
    assert_ne!(
        original,
        identity(
            &Failure::Violation(Obligation::History, UNREGISTERED_BYTES),
            Site::Run
        )
    );
}

/// A candidate that fails with the original's violation record under
/// another rule or at another site is another outcome: the reducer keeps
/// no step and returns the original.
#[test]
fn a_changed_rule_or_site_never_replaces_the_original_failure() {
    let manifest = manifest("corrupted");
    let original = violating(&manifest, &CATALOGED, Site::Run, Some(1));
    for (failure, site) in [(SAME_PREFIX, Site::Run), (CATALOGED, Site::Settled)] {
        let candidate = violating(&manifest, &failure, site, Some(1));
        let mut run = |_: super::Admitted<'_>, sink: &mut Vec<u8>| sink.clone_from(&candidate);
        let mut verified = 0;
        let mut verify = |_: &[u8], _: &Identity| {
            verified += 1;
            Ok(true)
        };
        let reduced = reduce_with(&original, &mut verify, &mut run, super::MAX_STEPS).unwrap();
        assert!(kept(&reduced.steps).is_empty(), "{:?}", reduced.steps);
        assert!(
            reduced.steps.iter().all(|step| matches!(
                step.verdict,
                Verdict::OtherOutcome | Verdict::Breaks | Verdict::Refused
            )),
            "{:?}",
            reduced.steps
        );
        assert!(
            reduced
                .steps
                .iter()
                .any(|step| step.verdict == Verdict::OtherOutcome)
        );
        assert_eq!(reduced.bundle, original);
        assert_eq!(verified, 1, "only the original replays");
    }
}

/// A candidate that keeps the identity but loses its rule's enabling
/// condition is rejected as `NoPremise` before any fresh-process replay.
#[test]
fn an_unplanted_candidate_without_its_enabling_condition_is_rejected() {
    let manifest = manifest("corrupted");
    let original = violating(&manifest, &CATALOGED, Site::Run, Some(1));
    let unchecked = violating(&manifest, &CATALOGED, Site::Run, Some(0));
    let mut run = |_: super::Admitted<'_>, sink: &mut Vec<u8>| sink.clone_from(&unchecked);
    let mut verified = 0;
    let mut verify = |_: &[u8], _: &Identity| {
        verified += 1;
        Ok(true)
    };
    let reduced = reduce_with(&original, &mut verify, &mut run, super::MAX_STEPS).unwrap();
    assert!(kept(&reduced.steps).is_empty(), "{:?}", reduced.steps);
    assert!(
        reduced
            .steps
            .iter()
            .any(|step| step.verdict == Verdict::NoPremise)
    );
    assert_eq!(reduced.bundle, original);
    assert_eq!(verified, 1, "only the original replays");
}

/// A fresh process that fails after a kept step stops the reduction with
/// that kept step's regression, manifest and scenario, never the
/// unverified candidate's, and a log that ends with the unverified
/// candidate, marked interrupted.
#[test]
fn an_interrupted_reduction_keeps_its_best_candidate_and_log() {
    let manifest = manifest("corrupted");
    let original = violating(&manifest, &CATALOGED, Site::Run, Some(1));
    let kept_bundle = violating(&manifest, &CATALOGED, Site::Run, Some(2));
    let unverified = violating(&manifest, &CATALOGED, Site::Run, Some(3));
    let mut runs = 0;
    let mut run = |_: super::Admitted<'_>, sink: &mut Vec<u8>| {
        runs += 1;
        sink.clone_from(if runs == 1 { &kept_bundle } else { &unverified });
    };
    let mut verified = 0;
    let mut verify = |_: &[u8], _: &Identity| {
        verified += 1;
        if verified <= 2 {
            Ok(true)
        } else {
            Err("no worker".into())
        }
    };
    let reduced = reduce_with(&original, &mut verify, &mut run, super::MAX_STEPS).unwrap();
    assert_eq!(reduced.stop, Stop::Interrupted("no worker".into()));
    assert_eq!(reduced.conditions, ["boundary-checked"]);
    let kept = kept(&reduced.steps);
    assert_eq!(kept.len(), 1, "{:?}", reduced.steps);
    assert_eq!(reduced.bundle, kept_bundle, "the last verified candidate");
    assert_ne!(reduced.bundle, unverified);
    let (_, recorded) = super::recorded(&original).unwrap();
    let (profile, plan, _) = super::scenario(&recorded).unwrap();
    let (_, edit, expected) = super::candidates(&(Edit::of(&profile, &plan), recorded), 0)
        .into_iter()
        .find(|(change, ..)| *change == kept[0])
        .expect("the kept change is a first-round candidate");
    assert_eq!(reduced.manifest, expected, "the one kept edit's manifest");
    assert_eq!(reduced.scenario, edit.describe());
    let last = reduced.steps.last().expect("a logged step");
    assert_eq!(last.verdict, Verdict::Unverified, "{:?}", reduced.steps);
    assert_ne!(last.change, kept[0]);
}

/// A bundle whose violation names an uncataloged rule, a cataloged rule
/// whose enabling condition did not hold, a violation without a failure
/// identity, and a cataloged violation of a cluster scenario each refuse
/// reduction before any step. The condition holds only for a stop event
/// naming a checked boundary.
#[test]
fn a_missing_or_unsupported_enabling_condition_refuses_reduction() {
    let manifest = manifest("corrupted");
    let uncataloged = Failure::Violation(Obligation::History, "a rule no catalog names");
    let identity = super::FailureIdentity::of_failure;
    assert!(conditions(&identity(&uncataloged, Site::Run)).is_none());
    assert!(conditions(&identity(&CATALOGED, Site::Settled)).is_none());
    let identity = identity(&CATALOGED, Site::Run);
    for (checked, expected) in [(None, false), (Some(0), false), (Some(1), true)] {
        let bundle = violating(&manifest, &CATALOGED, Site::Run, checked);
        assert_eq!(
            enabled(&identity, &load(&bundle, u64::MAX).unwrap()),
            Some(expected),
            "{checked:?} checked boundaries"
        );
    }
    let anonymous = violation_bundle(&manifest, &CATALOGED, None, None);
    for (bundle, reason) in [
        (
            violating(&manifest, &uncataloged, Site::Run, Some(1)),
            "names no cataloged enabling conditions",
        ),
        (
            violating(&manifest, &CATALOGED, Site::Run, None),
            "does not witness its rule's enabling conditions",
        ),
        (anonymous, "records no failure identity"),
        (
            violating(
                &self::manifest("cluster-broad"),
                &CATALOGED,
                Site::Run,
                Some(1),
            ),
            "only a mixed-world bundle reduces",
        ),
    ] {
        let mut runs = 0;
        let mut unchanged = |_: super::Admitted<'_>, _: &mut Vec<u8>| runs += 1;
        let refused = reduce_with(
            &bundle,
            &mut |_, _| Ok(true),
            &mut unchanged,
            super::MAX_STEPS,
        );
        assert!(
            matches!(&refused, Err(Refused::Unreducible(found)) if found.contains(reason)),
            "{refused:?}"
        );
        assert_eq!(runs, 0);
    }
}

/// Each verdict renders as one steps.txt entry, its text first and the
/// change after it.
#[test]
fn each_step_renders_its_verdict_and_change() {
    let change = Change::Delete(ActionKind::Read);
    for (verdict, text) in [
        (Verdict::Kept, "kept"),
        (Verdict::Breaks, "rejected, it breaks a dependency:"),
        (Verdict::Refused, "rejected, the manifest refuses it:"),
        (
            Verdict::Panicked,
            "rejected, its run panicked unlike the original:",
        ),
        (Verdict::OtherOutcome, "rejected, another outcome:"),
        (
            Verdict::NoPremise,
            "rejected, the premise or an enabling condition is gone:",
        ),
        (
            Verdict::Unreproduced,
            "rejected, it does not replay in a fresh process:",
        ),
        (
            Verdict::Unverified,
            "unverified, its fresh-process check failed:",
        ),
    ] {
        assert_eq!(
            Step { change, verdict }.to_string(),
            format!("{text} delete Read")
        );
    }
    for (change, text) in [
        (Change::Clear("link_faults"), "clear link_faults"),
        (Change::Schedule(9), "cut the schedule to 9 turns"),
        (Change::Lower("gets_first", 0), "lower gets_first to 0"),
        (Change::Halve("bytes", 8), "halve bytes to 8"),
    ] {
        let verdict = Verdict::Kept;
        assert_eq!(Step { change, verdict }.to_string(), format!("kept {text}"));
    }
}
