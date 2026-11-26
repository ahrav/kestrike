//! Schedule reduction checks: tape conversion, eligibility, history
//! predicates, candidate verdicts, budgets and stops.

use std::cell::{Cell, RefCell};

use crate::sim::choice::draws;
use crate::sim::manifest::Manifest;
use crate::sim::trace::{Loaded, RECORD, Tag, Terminal, load, reseal};

use super::super::branch::diverged;
use super::super::bundle::Site;
use super::super::bundle::{IDENTITY, admit, traced};
use super::super::campaign_fuzz::tests::worker;
use super::super::histories::STAY;
use super::super::histories::incidents::LOST_SOURCE_RELEASED;
use super::super::replay::FailureIdentity;
use super::super::replay::{Identity, Refused, Replayed, Stop, first_difference, replay, violated};
use super::super::suffix::walked;
use super::{
    Attempt, Budget, Change, Enabling, HISTORICAL, PAD, Reduced, Verdict, fed, lost_middle, reduce,
    reduce_with,
};
use crate::net::observe::Failure;
use crate::oracle::Obligation;

/// The control the reductions start from: `s3-d-19-mutated` at a root whose
/// run takes 71 decisions. The root is one the passes shorten: at most roots
/// the control's schedule stays as long, since a deletion shifts every later
/// draw and a zero tail selects the owner poll.
const CONTROL: (&str, u64) = ("s3-d-19-mutated", 45);

/// A manifest of `profile` at `root` pinning a placeholder executable.
fn manifest(profile: &str, root: u64) -> Manifest {
    let text = crate::sim::manifest_tests::sample(profile, &"a".repeat(64), "x86_64-linux");
    let mut manifest = Manifest::parse(&text).unwrap();
    manifest.root = root;
    manifest
}

fn recorded((profile, root): (&str, u64)) -> Vec<u8> {
    traced(admit(&manifest(profile, root)).unwrap(), Vec::new()).sink
}

fn loaded(bytes: &[u8]) -> Loaded {
    load(bytes, u64::MAX).unwrap()
}

/// Replays `bytes` in process and says whether it reproduced.
fn reproduced(bytes: &[u8], _: &Identity) -> Result<bool, String> {
    Ok(matches!(replay(bytes), Ok((Replayed::Reproduced, _))))
}

/// `bytes`' tape as the input a fed run reads, unpadded.
fn input_of(bytes: &[u8]) -> Vec<u8> {
    let draws = draws(&loaded(bytes).tape).unwrap();
    draws.iter().flat_map(|draw| &draw.bytes).copied().collect()
}

/// A fed run of `bytes`' recorded manifest from `input` padded to [`PAD`].
fn fed_from(bytes: &[u8], mut input: Vec<u8>) -> (Vec<u8>, bool) {
    let manifest = super::super::replay::manifest_of(&loaded(bytes)).unwrap();
    input.resize(PAD.max(input.len()), 0);
    fed(admit(&manifest).unwrap(), input)
}

fn verdicts(reduced: &Reduced) -> Vec<Verdict> {
    reduced
        .attempts
        .iter()
        .map(|attempt| attempt.verdict)
        .collect()
}

/// `bytes` with each SCRIPT turn of step `step` given the outcome STAY.
fn stayed(bytes: &[u8], step: u32) -> Vec<u8> {
    resealed(bytes, |records| outcomes(records, step, STAY))
}

/// `records` with each SCRIPT turn of step `step` given the outcome
/// `outcome`.
fn outcomes(records: &mut [[u8; RECORD]], step: u32, outcome: u64) {
    for record in records.iter_mut().filter(|record| {
        record[0] == Tag::Turn as u8
            && record[12..14] == [1, 5]
            && record[15..19] == step.to_be_bytes()
    }) {
        record[28..36].copy_from_slice(&outcome.to_le_bytes());
    }
}

/// `bytes` with payload byte `at` of its identity event flipped.
fn reidentified(bytes: &[u8], at: usize) -> Vec<u8> {
    resealed(bytes, |records| {
        let identity = records
            .iter_mut()
            .find(|record| record[..2] == [Tag::Event as u8, IDENTITY])
            .expect("an identity event");
        identity[4 + at] ^= 3;
    })
}

/// The index of step `name` in `profile`'s script.
fn step_of(profile: &str, name: &str) -> u32 {
    let (_, plan, _) = super::super::bundle::named(profile, 1).unwrap();
    plan.script
        .iter()
        .position(|step| step.name == name)
        .unwrap() as u32
}

/// The tape of each eligible kind of original, a branch child that took
/// another suffix and an explore leaf whose first selection was forced
/// converts to an input whose fed run records the same semantic records,
/// digest, decisions and terminal; one changed selection byte changes the
/// run, so the check compares the run the bytes make.
#[test]
fn converted_tapes_record_their_runs_again() {
    let c4 = recorded(("c4", 1));
    let h5 = recorded(("h5-put", 1));
    let (_, child) = diverged(&c4, "turn-1", Some(1)).unwrap();
    let leaf = [(&c4, [1, 0]), (&c4, [2, 0]), (&h5, [1, 0]), (&h5, [2, 0])]
        .into_iter()
        .filter_map(|(parent, path)| {
            let (_, leaf) = walked(parent, "turn-0", &path).ok()?;
            (loaded(&leaf).digest != loaded(parent).digest).then_some(leaf)
        })
        .next()
        .unwrap();
    assert_ne!(
        loaded(&child).digest,
        loaded(&c4).digest,
        "the child took another suffix"
    );
    for original in [
        recorded(CONTROL),
        recorded(("corrupted", 1)),
        recorded(("planted", 1)),
        child,
        leaf,
    ] {
        let (again, short) = fed_from(&original, input_of(&original));
        let (ran, was) = (loaded(&again), loaded(&original));
        assert!(!short);
        assert_eq!(
            (ran.digest, ran.decisions, ran.terminal),
            (was.digest, was.decisions, was.terminal)
        );
        assert_eq!(first_difference(&original, &again), None);
    }
    let original = recorded(CONTROL);
    let draws = draws(&loaded(&original).tape).unwrap();
    let at = (4..draws.len()).find(|&at| draws[at].bytes[0] > 0).unwrap();
    let mut input = input_of(&original);
    let offset: usize = draws[..at].iter().map(|draw| draw.bytes.len()).sum();
    input[offset] -= 1;
    assert_ne!(
        loaded(&fed_from(&original, input).0).digest,
        loaded(&original).digest
    );
}

/// An input past [`PAD`] runs whole: every run of the reduction reads the
/// converted input's own length, its last fill intact. The candidates all
/// pass, so none is kept, and the one pass tries its edits in order: the
/// zero-suffix bisection, each deletion, each lowering of an index or
/// bounded-value draw
/// holding a nonzero byte, fills left, then the turn-limit cut. The
/// reduction ends exhausted with the original's bytes and manifest.
#[test]
fn a_long_input_runs_whole_and_zero_keeps_return_the_original() {
    let control = recorded(CONTROL);
    let manifest = super::super::replay::manifest_of(&loaded(&control)).unwrap();
    let fill: Vec<u8> = (0..70_000u32).map(|at| (at % 251) as u8 + 1).collect();
    let original = reseal(&control, manifest.capacity(), |records| {
        let last = records
            .iter()
            .rposition(|record| record[0] == Tag::Choice as u8)
            .unwrap();
        let mut tape = vec![[0u8; 32]];
        tape[0][0] = 1;
        tape[0][16] = 3;
        tape[0][17..21].copy_from_slice(&(fill.len() as u32).to_le_bytes());
        for piece in fill.chunks(30) {
            let mut record = [0u8; 32];
            record[0] = 4;
            record[1] = piece.len() as u8;
            record[2..2 + piece.len()].copy_from_slice(piece);
            tape.push(record);
        }
        let choices = tape.iter().map(|choice| {
            let mut record = [0u8; RECORD];
            record[0] = Tag::Choice as u8;
            record[4..36].copy_from_slice(choice);
            record
        });
        records.splice(last + 1..last + 1, choices);
    });
    let whole = input_of(&original);
    assert!(whole.len() > PAD && whole.ends_with(&fill));
    let passing = recorded(("s3-d-19", 3));
    let lengths = RefCell::new(Vec::new());
    let mut run = |_: super::Admitted<'_>, input: Vec<u8>| {
        let first = lengths.borrow().is_empty();
        lengths.borrow_mut().push(input.len());
        if first {
            assert_eq!(input, whole, "the conversion run reads the whole input");
            return (original.clone(), false);
        }
        (passing.clone(), false)
    };
    let reduced = reduce_with(&original, &mut |_, _| Ok(true), &mut run, Budget::DEFAULT).unwrap();
    let lengths = lengths.into_inner();
    assert!(lengths.len() > 10);
    assert!(lengths.iter().all(|&len| len == whole.len()));
    assert!(
        verdicts(&reduced)
            .iter()
            .all(|&verdict| verdict == Verdict::OtherOutcome)
    );
    assert_eq!(reduced.stop, Stop::Exhausted);
    assert_eq!((&reduced.bundle, &reduced.manifest), (&original, &manifest));
    assert_eq!(reduced.spent.passes, 1);
    let draws = draws(&loaded(&original).tape).unwrap();
    let mut expected = Vec::new();
    let (mut low, high) = (0, draws.len());
    while low < high {
        let middle = low + (high - low) / 2;
        expected.push(Change::ZeroFrom(middle));
        low = middle + 1;
    }
    expected.extend((0..draws.len()).map(Change::Delete));
    let lowered = |at: &usize| !draws[*at].fill && draws[*at].bytes.iter().any(|&byte| byte > 0);
    expected.extend((0..draws.len()).filter(lowered).map(Change::Lower));
    expected.push(Change::Turns(loaded(&original).work.turns));
    let changes: Vec<Change> = reduced
        .attempts
        .iter()
        .map(|attempt| attempt.change)
        .collect();
    assert_eq!(changes, expected);
}

/// Zero-suffix bisection and deletion search the draws before the zero
/// tail, so each edit changes the input: with every candidate rejected, the
/// control with every selection lowered to zero, so that only its fills
/// hold nonzero bytes, is probed and has its draws deleted below the tail,
/// and its one pass converges, exhausted. A candidate budget that one such
/// pass spends leaves no candidate for the turn-limit cut, so the
/// reduction is bounded.
#[test]
fn zero_suffix_bisection_probes_only_the_draws_before_the_zero_tail() {
    let control = recorded(CONTROL);
    let split = draws(&loaded(&control).tape).unwrap();
    let raised = split
        .iter()
        .filter(|draw| !draw.fill && draw.bytes.iter().any(|&byte| byte > 0))
        .count();
    let original = reselected(
        &control,
        raised,
        |value, _| value > 0,
        |_, bound| (0, bound),
    );
    let draws = draws(&loaded(&original).tape).unwrap();
    let last = draws
        .iter()
        .rposition(|draw| draw.bytes.iter().any(|&byte| byte > 0));
    let nonzero = last.unwrap() + 1;
    assert!(nonzero < draws.len() / 2, "{nonzero} of {}", draws.len());
    let passing = recorded(("s3-d-19", 3));
    let budget = Budget {
        passes: 1,
        ..Budget::DEFAULT
    };
    let calls = Cell::new(0);
    let mut run = |_: super::Admitted<'_>, _: Vec<u8>| {
        calls.set(calls.get() + 1);
        let ran = if calls.get() == 1 {
            &original
        } else {
            &passing
        };
        (ran.clone(), false)
    };
    let reduced = reduce_with(&original, &mut |_, _| Ok(true), &mut run, budget).unwrap();
    let probes: Vec<usize> = reduced
        .attempts
        .iter()
        .filter_map(|attempt| match attempt.change {
            Change::ZeroFrom(at) => Some(at),
            _ => None,
        })
        .collect();
    let (mut low, mut expected) = (0, Vec::new());
    while low < nonzero {
        let middle = low + (nonzero - low) / 2;
        expected.push(middle);
        low = middle + 1;
    }
    assert!(!expected.is_empty());
    assert_eq!(probes, expected);
    let deleted: Vec<usize> = reduced
        .attempts
        .iter()
        .filter_map(|attempt| match attempt.change {
            Change::Delete(at) => Some(at),
            _ => None,
        })
        .collect();
    assert_eq!(deleted, (0..nonzero).collect::<Vec<_>>());
    assert_eq!((reduced.stop, reduced.spent.passes), (Stop::Exhausted, 1));
    let swept = reduced
        .attempts
        .iter()
        .filter(|attempt| !matches!(attempt.change, Change::Turns(_)))
        .count();
    assert!(swept < reduced.attempts.len(), "the cut was tried");
    calls.set(0);
    let budget = Budget {
        candidates: swept as u64,
        ..budget
    };
    let bounded = reduce_with(&original, &mut |_, _| Ok(true), &mut run, budget).unwrap();
    assert_eq!((bounded.stop, bounded.spent.passes), (Stop::Bounded, 1));
    assert_eq!(bounded.attempts.len(), swept);
}

/// The control reduces to fewer decisions under its failure identity and
/// its declared premise's predicate, its regression replays, records the
/// manifest the reduction returns and converts to an input that records it
/// again. Some candidates
/// end complete without the violation, so the identity check rejects a
/// changed terminal.
#[test]
fn the_control_reduces_under_its_identity_and_premise() {
    let original = recorded(CONTROL);
    let terminals = RefCell::new(Vec::new());
    let mut run = |admitted: super::Admitted<'_>, input: Vec<u8>| {
        let ran = fed(admitted, input);
        terminals
            .borrow_mut()
            .push(load(&ran.0, u64::MAX).ok().map(|ran| ran.terminal));
        ran
    };
    let reduced = reduce_with(&original, &mut reproduced, &mut run, Budget::DEFAULT).unwrap();
    let (before, after) = (loaded(&original), loaded(&reduced.bundle));
    assert!(
        after.decisions < before.decisions,
        "{} -> {}",
        before.decisions,
        after.decisions
    );
    assert_eq!(violated(&after), violated(&before));
    assert_eq!(reduced.requirement, ["s3-mutated-premise"]);
    let (_, plan, _) = super::super::bundle::named(CONTROL.0, 1).unwrap();
    assert!(HISTORICAL[2].holds(&reduced.bundle, plan.script));
    assert_eq!(replay(&reduced.bundle).unwrap().0, Replayed::Reproduced);
    let recorded_manifest = super::super::replay::manifest_of(&before).unwrap();
    let turns = reduced.manifest.count("turns");
    assert_eq!(
        reduced.manifest,
        recorded_manifest.clone().with("turns", turns)
    );
    assert!(turns == after.work.turns && turns < recorded_manifest.count("turns"));
    assert!(reduced.attempts.iter().any(|attempt| matches!(
        (attempt.change, attempt.verdict),
        (Change::Turns(_), Verdict::Kept)
    )));
    assert_eq!(
        super::super::replay::manifest_of(&after).unwrap(),
        reduced.manifest
    );
    let (again, _) = fed_from(&reduced.bundle, input_of(&reduced.bundle));
    assert_eq!(loaded(&again).digest, after.digest);
    assert_eq!(first_difference(&again, &reduced.bundle), None);
    assert_eq!(reduced.stop, Stop::Exhausted);
    assert!(reduced.scenario.starts_with("kinds = "));
    assert!(verdicts(&reduced).contains(&Verdict::Kept));
    let changed = terminals.into_inner().into_iter().flatten().any(|terminal| {
        matches!(terminal, Terminal::Complete { outcome, .. } if outcome != crate::sim::trace::Outcome::Violation)
    });
    assert!(changed, "no candidate ended without the violation");
}

/// The reduction of `original` whose every candidate run is `candidate`,
/// the conversion run returning `original`, within three candidates.
fn against(original: &[u8], candidate: &[u8]) -> Reduced {
    let calls = Cell::new(0);
    let mut run = |_: super::Admitted<'_>, _: Vec<u8>| {
        calls.set(calls.get() + 1);
        let ran = if calls.get() == 1 {
            original
        } else {
            candidate
        };
        (ran.to_vec(), false)
    };
    let budget = Budget {
        candidates: 3,
        ..Budget::DEFAULT
    };
    reduce_with(original, &mut |_, _| Ok(true), &mut run, budget).unwrap()
}

/// `bytes` with its semantic records edited by `edit`.
fn resealed(bytes: &[u8], edit: impl FnOnce(&mut Vec<[u8; RECORD]>)) -> Vec<u8> {
    let capacity = super::super::replay::manifest_of(&loaded(bytes))
        .unwrap()
        .capacity();
    reseal(bytes, capacity, edit)
}

/// `bytes` with the first `count` tape selections that `pick` accepts,
/// as (value, bound), rewritten by `change`.
fn reselected(
    bytes: &[u8],
    count: usize,
    pick: impl Fn(u64, u64) -> bool,
    change: impl Fn(u64, u64) -> (u64, u64),
) -> Vec<u8> {
    resealed(bytes, |records| {
        let word = |record: &[u8; RECORD], at: usize| {
            u64::from_le_bytes(record[at..at + 8].try_into().unwrap())
        };
        let mut left = count;
        for record in records.iter_mut() {
            let selection = record[0] == Tag::Choice as u8 && record[4] == 3;
            let (value, bound) = (word(record, 5), word(record, 13));
            if left > 0 && selection && pick(value, bound) {
                let (value, bound) = change(value, bound);
                record[5..13].copy_from_slice(&value.to_le_bytes());
                record[13..21].copy_from_slice(&bound.to_le_bytes());
                left -= 1;
            }
        }
        assert_eq!(left, 0, "{count} selections to rewrite");
    })
}

/// `bytes` with a bounded-value decision of each (value, bound) in
/// `selections` appended after its last choice record.
fn appended(bytes: &[u8], selections: &[(u64, u64)]) -> Vec<u8> {
    resealed(bytes, |records| {
        let last = records
            .iter()
            .rposition(|record| record[0] == Tag::Choice as u8)
            .unwrap();
        let choices = selections.iter().flat_map(|&(value, bound)| {
            let (mut identity, mut selection) = ([0u8; RECORD], [0u8; RECORD]);
            identity[0] = Tag::Choice as u8;
            (identity[4], identity[20]) = (1, 2);
            selection[0] = Tag::Choice as u8;
            selection[4] = 3;
            selection[5..13].copy_from_slice(&value.to_le_bytes());
            selection[13..21].copy_from_slice(&bound.to_le_bytes());
            [identity, selection]
        });
        records.splice(last + 1..last + 1, choices.collect::<Vec<_>>());
    })
}

/// A candidate is kept only when it is strictly smaller in decisions, then
/// the unpadded input's length, then its bytes: a run equal to the original
/// and one with a selection raised are no smaller, one with a selection
/// lowered is kept, one with fewer decisions is kept though its input is
/// longer, and one with as many decisions and a shorter input is kept
/// though its bytes are greater.
#[test]
fn only_a_strictly_smaller_run_is_kept() {
    let base = recorded(("s3-d-19-mutated", 3));
    let no_smaller = [Verdict::NotSmaller; 3];
    assert_eq!(verdicts(&against(&base, &base)), no_smaller);
    let raised = reselected(
        &base,
        1,
        |value, bound| value + 1 < bound,
        |v, b| (v + 1, b),
    );
    assert_eq!(verdicts(&against(&base, &raised)), no_smaller);
    let lowered = reselected(&base, 1, |value, _| value > 0, |v, b| (v - 1, b));
    let kept = against(&base, &lowered);
    assert_eq!(verdicts(&kept)[0], Verdict::Kept);
    assert_eq!(loaded(&kept.bundle).digest, loaded(&lowered).digest);
    let (longer, wider) = (
        appended(&base, &[(0, 2), (0, 2)]),
        appended(&base, &[(0, 1 << 24)]),
    );
    let (more, fewer) = (loaded(&longer), loaded(&wider));
    assert_eq!(more.decisions, fewer.decisions + 1);
    assert_eq!(input_of(&wider).len(), input_of(&longer).len() + 1);
    assert_eq!(verdicts(&against(&longer, &wider))[0], Verdict::Kept);
    let (wide, narrow) = (
        appended(&base, &[(5, 65_536)]),
        appended(&base, &[(255, 256)]),
    );
    let (long, short) = (input_of(&wide), input_of(&narrow));
    assert_eq!(
        (short.len() + 1, loaded(&narrow).decisions),
        (long.len(), loaded(&wide).decisions)
    );
    assert!(short > long, "the shorter input's bytes are greater");
    assert_eq!(verdicts(&against(&wide, &narrow))[0], Verdict::Kept);
}

/// A planted run's premise and a cataloged rule's enabling condition are
/// each the requirement a candidate must hold: the unedited run reaches the
/// size check, and one without the plant's upload states or with no checked
/// boundary is rejected for the lost requirement under the same identity.
#[test]
fn plant_premises_and_cataloged_conditions_are_enabling_requirements() {
    use super::super::bundle::{STOP, UPLOAD};
    let unplanted = |records: &mut Vec<[u8; RECORD]>| {
        records.retain(|record| record[..2] != [Tag::Event as u8, UPLOAD]);
    };
    let unchecked = |records: &mut Vec<[u8; RECORD]>| {
        for record in records.iter_mut() {
            if record[..2] == [Tag::Event as u8, STOP] {
                record[4 + 3..4 + 11].fill(0);
            }
        }
    };
    type Edit<'e> = &'e dyn Fn(&mut Vec<[u8; RECORD]>);
    let cases: [(&str, &str, Edit<'_>); 2] = [
        ("planted", "premise-PublishedByte", &unplanted),
        ("corrupted", "boundary-checked", &unchecked),
    ];
    for (profile, name, edit) in cases {
        let original = recorded((profile, 1));
        let held = against(&original, &original);
        assert_eq!(held.requirement, [name]);
        assert_eq!(verdicts(&held), [Verdict::NotSmaller; 3], "{profile}");
        let unheld = resealed(&original, edit);
        assert_eq!(violated(&loaded(&unheld)), violated(&loaded(&original)));
        assert_eq!(
            verdicts(&against(&original, &unheld)),
            [Verdict::Unenabled; 3],
            "{profile}"
        );
    }
}

/// The reduction of the control whose every candidate run is `edit` of
/// a real smaller run of the control's failure, the conversion run left as
/// it is, within three candidates; the smaller run unedited would be kept.
fn edited(edit: impl Fn(&[u8]) -> Vec<u8>) -> (Reduced, Vec<u8>) {
    let (original, smaller) = (recorded(CONTROL), recorded(("s3-d-19-mutated", 3)));
    assert!(loaded(&smaller).decisions < loaded(&original).decisions);
    assert_eq!(violated(&loaded(&smaller)), violated(&loaded(&original)));
    let candidate = edit(&smaller);
    let calls = Cell::new(0);
    let mut run = |admitted: super::Admitted<'_>, input: Vec<u8>| {
        calls.set(calls.get() + 1);
        match calls.get() {
            1 => fed(admitted, input),
            _ => (candidate.clone(), false),
        }
    };
    let budget = Budget {
        candidates: 3,
        ..Budget::DEFAULT
    };
    let reduced = reduce_with(&original, &mut |_, _| Ok(true), &mut run, budget).unwrap();
    (reduced, candidate)
}

/// A candidate whose identity shares the violation record but not the full
/// rule's hash, or names another obligation, audit class or site, is
/// another outcome and never kept; each edited run still records a
/// complete violation with an identity, and the unedited run is kept.
#[test]
fn a_candidate_with_another_identity_is_never_kept() {
    let target = violated(&loaded(&recorded(CONTROL))).unwrap();
    for at in [7, 2, 3, 4] {
        let (reduced, candidate) = edited(|bytes| reidentified(bytes, at));
        assert_eq!(verdicts(&reduced), [Verdict::OtherOutcome; 3], "{at}");
        assert_eq!(
            loaded(&reduced.bundle).digest,
            loaded(&recorded(CONTROL)).digest
        );
        let ran = loaded(&candidate);
        let found = ran
            .events
            .iter()
            .rev()
            .find_map(super::super::replay::FailureIdentity::of);
        assert!(
            ran.violation.is_some() && found.is_some_and(|found| found != target),
            "{at}"
        );
    }
    let (kept, _) = edited(<[u8]>::to_vec);
    assert_eq!(verdicts(&kept)[0], Verdict::Kept);
}

/// A candidate whose run keeps the identity without its premise's effect
/// step is rejected for the lost requirement; the unedited run holds it.
#[test]
fn a_candidate_without_its_premise_is_never_kept() {
    let (_, plan, _) = super::super::bundle::named(CONTROL.0, 1).unwrap();
    let effect = step_of(CONTROL.0, "effect");
    let (reduced, candidate) = edited(|bytes| {
        assert!(HISTORICAL[2].holds(bytes, plan.script));
        stayed(bytes, effect)
    });
    assert_eq!(verdicts(&reduced), [Verdict::Unenabled; 3]);
    assert_eq!(
        loaded(&reduced.bundle).digest,
        loaded(&recorded(CONTROL)).digest
    );
    assert_eq!(
        violated(&loaded(&candidate)),
        violated(&loaded(&recorded(CONTROL)))
    );
}

/// A run whose input ends before its violation, one that runs short after
/// its violation in a drain, and that run reported without its short input
/// all end in infrastructure and are rejected: as short inputs, then for
/// the infrastructure terminal that keeps the violation record.
#[test]
fn short_and_infrastructure_runs_are_never_kept() {
    let drained = recorded(("corrupted", 1));
    let before = drained
        .as_chunks::<RECORD>()
        .0
        .iter()
        .take_while(|record| record[0] != Tag::Violation as u8)
        .filter(|record| record[0] == Tag::Choice as u8 && record[4] == 1)
        .count();
    let draws = draws(&loaded(&drained).tape).unwrap();
    let through: usize = draws[..before].iter().map(|draw| draw.bytes.len()).sum();
    assert!(before < draws.len(), "decisions follow the violation");
    let control = recorded(CONTROL);
    for (original, cut, report, verdict, violation) in [
        (&control, 8, true, Verdict::Short, false),
        (&drained, through + 1, true, Verdict::Short, true),
        (&drained, through + 1, false, Verdict::Infrastructure, true),
    ] {
        let (calls, witnessed) = (Cell::new(0), Cell::new(0));
        let mut run = |admitted: super::Admitted<'_>, input: Vec<u8>| {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                return fed(admitted, input);
            }
            let (bytes, short) = fed(admitted, input_of(original)[..cut].to_vec());
            let ran = loaded(&bytes);
            let infrastructure = matches!(ran.terminal, Terminal::Infrastructure(_));
            if short && infrastructure && ran.violation.is_some() == violation {
                witnessed.set(witnessed.get() + 1);
            }
            (bytes, short && report)
        };
        let budget = Budget {
            candidates: 2,
            ..Budget::DEFAULT
        };
        let reduced = reduce_with(original, &mut |_, _| Ok(true), &mut run, budget).unwrap();
        assert_eq!(verdicts(&reduced), [verdict; 2], "{cut}");
        assert_eq!(witnessed.get(), 2, "{cut}");
    }
}

/// A fed run that panics returns the records written before the panic,
/// not short, which load with an infrastructure terminal, and that
/// candidate is rejected for it, so the original stays the regression.
#[test]
fn a_panicking_candidate_run_is_never_kept() {
    let panicking = manifest("panicking", 1);
    let mut traced_run = Vec::new();
    let _ = crate::sim::unwind::caught(|| traced(admit(&panicking).unwrap(), &mut traced_run));
    let mut input = input_of(&traced_run);
    input.resize(PAD, 0);
    let (panicked, short) = fed(admit(&panicking).unwrap(), input);
    assert!(!short);
    assert!(matches!(
        loaded(&panicked).terminal,
        Terminal::Infrastructure(_)
    ));
    let control = recorded(CONTROL);
    let reduced = against(&control, &panicked);
    assert_eq!(verdicts(&reduced), [Verdict::Infrastructure; 3]);
    assert_eq!(reduced.bundle, control);
}

/// A fresh process that does not reproduce a candidate rejects it, so no
/// candidate is kept; one that fails after a kept candidate interrupts the
/// reduction with that candidate's regression and a log that ends with the
/// unverified one.
#[test]
fn fresh_process_verdicts_reject_or_interrupt() {
    let original = recorded(CONTROL);
    let mut checks = 0;
    let mut unreproduced = |_: &[u8], _: &Identity| {
        checks += 1;
        Ok(checks == 1)
    };
    let budget = Budget {
        candidates: 40,
        ..Budget::DEFAULT
    };
    let rejected = reduce(&original, &mut unreproduced, budget).unwrap();
    assert!(verdicts(&rejected).contains(&Verdict::Unreproduced));
    assert!(!verdicts(&rejected).contains(&Verdict::Kept));
    assert_eq!(rejected.bundle, original);
    let kept = RefCell::new(None);
    let mut checks = 0;
    let mut failing = |candidate: &[u8], _: &Identity| {
        checks += 1;
        match checks {
            1 => Ok(true),
            2 => {
                kept.replace(Some(candidate.to_vec()));
                Ok(true)
            }
            _ => Err("no worker".to_owned()),
        }
    };
    let interrupted = reduce(&original, &mut failing, Budget::DEFAULT).unwrap();
    assert_eq!(interrupted.stop, Stop::Interrupted("no worker".into()));
    assert_eq!(Some(interrupted.bundle.clone()), kept.into_inner());
    let verdicts = verdicts(&interrupted);
    assert_eq!(
        verdicts
            .iter()
            .filter(|&&verdict| verdict == Verdict::Kept)
            .count(),
        1
    );
    assert_eq!(verdicts.last(), Some(&Verdict::Unverified));
}

/// Each budget stops the reduction before the work it cannot pay for: no
/// run refuses before the original's fresh check, one candidate stops the
/// first pass before it completes, the original's fresh check alone, that
/// and the conversion run, a candidate whose fresh check finds no run left,
/// a kept candidate's fresh check that takes the last run, and one pass
/// that kept a candidate, which stays bounded though the turn-limit cut
/// that follows is kept too.
#[test]
fn budgets_stop_the_reduction_before_their_work() {
    let original = recorded(CONTROL);
    let smaller = recorded(("s3-d-19-mutated", 3));
    assert!(loaded(&smaller).decisions < loaded(&original).decisions);
    assert_eq!(violated(&loaded(&smaller)), violated(&loaded(&original)));
    let reduce_within = |budget: Budget| {
        let calls = Cell::new(0);
        let mut run = |admitted: super::Admitted<'_>, input: Vec<u8>| {
            calls.set(calls.get() + 1);
            match calls.get() {
                1 => fed(admitted, input),
                _ => (smaller.clone(), false),
            }
        };
        let reduced = reduce_with(&original, &mut |_, _| Ok(true), &mut run, budget).unwrap();
        (reduced, calls.get())
    };
    let within = |candidates, passes, runs| Budget {
        candidates,
        passes,
        runs,
    };
    let (one, calls) = reduce_within(within(1, 8, 1026));
    assert_eq!(
        (
            one.attempts.len(),
            one.spent.candidates,
            one.stop.clone(),
            calls
        ),
        (1, 1, Stop::Bounded, 2)
    );
    assert_eq!(one.spent.passes, 0);
    let (checks, calls) = (Cell::new(0), Cell::new(0));
    let refused = reduce_with(
        &original,
        &mut |_, _| {
            checks.set(checks.get() + 1);
            Ok(true)
        },
        &mut |_, _| {
            calls.set(calls.get() + 1);
            (Vec::new(), false)
        },
        within(512, 8, 0),
    );
    assert_eq!(
        refused.unwrap_err(),
        Refused::Unreducible("no run is left for its fresh-process check".into())
    );
    assert_eq!((checks.get(), calls.get()), (0, 0));
    for (runs, ran) in [(1, 0), (2, 1)] {
        let (stopped, calls) = reduce_within(within(512, 8, runs));
        assert_eq!(
            (stopped.attempts.len(), calls, stopped.stop),
            (0, ran, Stop::Bounded)
        );
        assert_eq!(
            (stopped.bundle, stopped.spent.runs),
            (original.clone(), runs)
        );
    }
    let (last_run, calls) = reduce_within(within(512, 8, 4));
    assert_eq!(verdicts(&last_run), [Verdict::Kept]);
    assert_eq!(
        (last_run.stop, last_run.spent.runs, calls),
        (Stop::Bounded, 4, 2)
    );
    let (unchecked, _) = reduce_within(within(512, 8, 3));
    assert_eq!(verdicts(&unchecked), [Verdict::Unbudgeted]);
    assert_eq!(
        (unchecked.stop, unchecked.bundle),
        (Stop::Bounded, original.clone())
    );
    let (pass, _) = reduce_within(within(512, 1, 1026));
    assert_eq!(pass.stop, Stop::Bounded);
    assert_eq!(pass.spent.passes, 1);
    let last = pass.attempts.last().unwrap();
    assert!(matches!(
        (last.change, last.verdict),
        (Change::Turns(_), Verdict::Kept)
    ));
}

/// A bundle of another world, an unsuccessful or panicked run, a violation
/// whose failure names no enabling requirement, an original that does not
/// hold its requirement, replay in a fresh process or record its run
/// again from its input are each refused; a fresh check that fails for the
/// original is infrastructure.
#[test]
fn ineligible_originals_refuse_reduction() {
    let refused = |original: &[u8]| match reduce(original, &mut reproduced, Budget::DEFAULT) {
        Err(Refused::Unreducible(reason)) => reason,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        refused(&recorded(("cluster-broad", 1))),
        "only a mixed-world bundle reduces its schedule"
    );
    assert_eq!(
        refused(&recorded(("recovery-16k", 1))),
        "only a mixed-world bundle reduces its schedule"
    );
    let none = "the bundle records no complete violation with a failure identity";
    assert_eq!(refused(&recorded(("h1-get-unheld", 1))), none);
    let mut panicked = Vec::new();
    let panicking = manifest("panicking", 1);
    let admitted = admit(&panicking).unwrap();
    let _ = crate::sim::unwind::caught(|| traced(admitted, &mut panicked));
    assert!(matches!(
        loaded(&panicked).terminal,
        Terminal::Infrastructure(_)
    ));
    assert_eq!(refused(&panicked), none);
    let unknown = recorded(("h1-get-reused", 1));
    assert!(violated(&loaded(&unknown)).is_some());
    assert_eq!(
        refused(&unknown),
        "the failure names no checkable enabling requirement"
    );
    let unheld = stayed(&recorded(CONTROL), step_of(CONTROL.0, "effect"));
    assert!(violated(&loaded(&unheld)).is_some());
    assert_eq!(
        refused(&unheld),
        "the bundle does not witness its enabling requirement"
    );
    let control = recorded(CONTROL);
    let mut unreproduced = |_: &[u8], _: &Identity| Ok(false);
    assert_eq!(
        reduce(&control, &mut unreproduced, Budget::DEFAULT).unwrap_err(),
        Refused::Unreducible("the bundle does not replay in a fresh process".into())
    );
    // A tape whose selection sits at its bound does not split, refused
    // before any check or run.
    let unsplit = reselected(
        &control,
        1,
        |value, bound| value + 1 == bound,
        |_, b| (b, b),
    );
    let (checks, calls) = (Cell::new(0), Cell::new(0));
    let refused = reduce_with(
        &unsplit,
        &mut |_, _| {
            checks.set(checks.get() + 1);
            Ok(true)
        },
        &mut |_, _| {
            calls.set(calls.get() + 1);
            (Vec::new(), false)
        },
        Budget::DEFAULT,
    );
    assert_eq!(
        refused.unwrap_err(),
        Refused::Input("the tape does not split into decisions".into())
    );
    assert_eq!((checks.get(), calls.get()), (0, 0));
    let mut failing = |_: &[u8], _: &Identity| Err("no worker".to_owned());
    assert_eq!(
        reduce(&control, &mut failing, Budget::DEFAULT).unwrap_err(),
        Refused::Infrastructure("no worker".into())
    );
    let other = recorded(("s3-d-19-mutated", 3));
    let mut run = |_: super::Admitted<'_>, _: Vec<u8>| (other.clone(), false);
    match reduce_with(&control, &mut reproduced, &mut run, Budget::DEFAULT) {
        Err(Refused::Unreducible(reason)) => {
            assert_eq!(reason, "its tape as an input does not record its run again");
        }
        other => panic!("{other:?}"),
    }
}

/// `records` with the first completed SCRIPT turn of step `step` given
/// `outcome`, 0 as a failing check returns, and a violation record after
/// it.
fn raise(records: &mut Vec<[u8; RECORD]>, step: u32, outcome: u64) {
    let at = records
        .iter()
        .position(|record| {
            record[0] == Tag::Turn as u8
                && record[12..14] == [1, 5]
                && record[15..19] == step.to_be_bytes()
                && record[28..36] != STAY.to_le_bytes()
        })
        .expect("a completed turn of the step");
    records[at][28..36].copy_from_slice(&outcome.to_le_bytes());
    let mut violation = [0u8; RECORD];
    violation[0] = Tag::Violation as u8;
    records.insert(at + 1, violation);
}

/// `bytes` edited by `edit`, then raised at step `step` of `profile`.
fn raised(
    bytes: &[u8],
    (profile, step): (&str, &str),
    edit: impl FnOnce(&mut Vec<[u8; RECORD]>),
) -> Vec<u8> {
    resealed(bytes, |records| {
        edit(records);
        raise(records, step_of(profile, step), 0);
    })
}

/// Each history predicate holds over this build's run of its profile with
/// its raising step's turn returning 0 before a violation, each step
/// completing and, for the hole, the middle fragment's loss recorded toward
/// the owner. It fails when a step it needs stays waiting, when the
/// violation follows another step or a raising turn that marked, when that
/// loss names another fragment or comes after the violation, and under a
/// script that lacks a step it names. A predicate binds its profile and
/// failure.
#[test]
fn history_predicates_read_the_records_before_the_first_violation() {
    let script = |profile: &str| super::super::bundle::named(profile, 1).unwrap().1.script;
    for (enabling, root, last) in [
        (&HISTORICAL[0], 1, "put-supply"),
        (&HISTORICAL[1], 3, "effect"),
    ] {
        let (profile, raising) = (enabling.profile, enabling.raised);
        let passing = recorded((profile, root));
        assert!(loaded(&passing).violation.is_none());
        let script = script(profile);
        assert!(!enabling.holds(&passing, script), "{}", enabling.name);
        let bytes = raised(&passing, (profile, raising), |_| {});
        assert!(enabling.holds(&bytes, script), "{}", enabling.name);
        let waiting = raised(&passing, (profile, raising), |records| {
            outcomes(records, step_of(profile, last), STAY);
        });
        assert!(!enabling.holds(&waiting, script), "{}", enabling.name);
        let marked = resealed(&passing, |records| {
            raise(records, step_of(profile, raising), 1);
        });
        assert!(!enabling.holds(&marked, script), "{}", enabling.name);
    }
    // MOVED_MORE is raised by the live-GET check and by the retained one;
    // the s3 predicate names the first.
    let s3 = recorded(("s3-d-19", 3));
    let retained = raised(&s3, ("s3-d-19", "retained-checked"), |_| {});
    assert!(!HISTORICAL[1].holds(&retained, script("s3-d-19")));
    let passing = recorded(("i3-put-hole", 1));
    let hole = |edit: &dyn Fn(&mut Vec<[u8; RECORD]>)| {
        raised(&passing, ("i3-put-hole", "lost-held"), edit)
    };
    let rule =
        |record: &[u8; RECORD]| record[..2] == [Tag::Event as u8, super::super::bundle::RULE];
    assert!(HISTORICAL[0].holds(&hole(&|_| {}), script("i3-put-hole")));
    let elsewhere = hole(&|records| {
        for record in records.iter_mut().filter(|record| rule(record)) {
            record[4 + 1 + 14..4 + 1 + 18].copy_from_slice(&0u32.to_le_bytes());
        }
    });
    assert!(!HISTORICAL[0].holds(&elsewhere, script("i3-put-hole")));
    // Toward the client, another kind and a fault's drop each name another
    // loss; a loss recorded only after the first violation does not count.
    let code = 4 + 1;
    for (at, value) in [
        (code + 4, 0),
        (code + 13, super::super::super::frame::Kind::PutAck as u8),
        (code + 18, 1),
    ] {
        let other = hole(&|records| {
            for record in records.iter_mut().filter(|record| rule(record)) {
                record[at] = value;
            }
        });
        assert!(!HISTORICAL[0].holds(&other, script("i3-put-hole")), "{at}");
    }
    let late = resealed(&passing, |records| {
        raise(records, step_of("i3-put-hole", "lost-held"), 0);
        let lost = |r: &[u8; RECORD]| rule(r) && lost_middle(&r[4..]);
        let moved: Vec<[u8; RECORD]> = records.iter().filter(|r| lost(r)).copied().collect();
        assert!(!moved.is_empty());
        records.retain(|record| !lost(record));
        let at = records
            .iter()
            .position(|record| record[0] == Tag::Violation as u8)
            .unwrap();
        records.splice(at + 1..at + 1, moved);
    });
    assert!(!HISTORICAL[0].holds(&late, script("i3-put-hole")));
    // A setup whose guard failed returns 0 and injected nothing.
    let checked = raised(&s3, ("s3-d-19", "check"), |_| {});
    let guarded = raised(&s3, ("s3-d-19", "check"), |records| {
        outcomes(records, step_of("s3-d-19", "setup"), 0);
    });
    assert!(HISTORICAL[1].holds(&checked, script("s3-d-19")));
    assert!(!HISTORICAL[1].holds(&guarded, script("s3-d-19")));
    assert!(!HISTORICAL[1].holds(&checked, script("i3-put-hole")));
    let i3 = FailureIdentity::of_failure(
        &Failure::Violation(Obligation::Custody, LOST_SOURCE_RELEASED),
        Site::Run,
    );
    assert_eq!(
        Enabling::of("i3-put-hole", &i3).map(|found| found.name),
        Some("i3-lost-middle-after-single-upload")
    );
    assert!(Enabling::of("i3-put-duplicate", &i3).is_none());
    for other in [
        FailureIdentity::of_failure(
            &Failure::Violation(Obligation::Contain, LOST_SOURCE_RELEASED),
            Site::Run,
        ),
        FailureIdentity::of_failure(
            &Failure::Violation(Obligation::Custody, LOST_SOURCE_RELEASED),
            Site::Settled,
        ),
    ] {
        assert!(Enabling::of("i3-put-hole", &other).is_none());
    }
    let identity = violated(&loaded(&recorded(CONTROL))).unwrap();
    assert_eq!(
        Enabling::of("s3-d-19-mutated", &identity).map(|found| found.name),
        Some("s3-mutated-premise")
    );
    assert_eq!(
        Enabling::of("s3-d-19", &identity).map(|found| found.name),
        Some("s3-injected-then-counted")
    );
    assert!(Enabling::of("s3-d-19-retained-live", &identity).is_none());
    assert!(Enabling::of("i3-put-hole", &identity).is_none());
}

/// The control's one-pass reduction whose `nth` candidate run returns
/// `kept`, a smaller run of its failure, and every other one a passing
/// run, with the input of each candidate run; with `nth` 0 every candidate
/// is rejected.
fn keeping_at(nth: usize, kept: &[u8]) -> (Reduced, Vec<Vec<u8>>) {
    let (original, passing) = (recorded(CONTROL), recorded(("s3-d-19", 3)));
    let budget = Budget {
        passes: 1,
        ..Budget::DEFAULT
    };
    let (calls, inputs) = (Cell::new(0), RefCell::new(Vec::new()));
    let mut run = |_: super::Admitted<'_>, input: Vec<u8>| {
        calls.set(calls.get() + 1);
        if calls.get() > 1 {
            inputs.borrow_mut().push(input);
        }
        let ran = match calls.get() {
            1 => &original,
            call if call == nth + 1 => kept,
            _ => &passing,
        };
        (ran.to_vec(), false)
    };
    let reduced = reduce_with(&original, &mut |_, _| Ok(true), &mut run, budget).unwrap();
    (reduced, inputs.into_inner())
}

/// Each candidate of a pass that keeps nothing runs the input its change
/// names, padded to [`PAD`]: the draws before a zero suffix, the draws
/// without a deleted one, the draws with a lowered one zeroed, the whole
/// input under a cut turn limit. A pass that keeps a candidate only by a
/// deletion, only by a lowering or only by a zero suffix ends bounded at a
/// pass limit of one; a kept deletion is retried at the same index over
/// the kept run's own draws, and a zero suffix kept at the first probe
/// narrows the bisection to the kept run's draws before its zero tail.
#[test]
fn a_pass_that_keeps_any_edit_is_not_converged() {
    let smaller = recorded(("s3-d-19-mutated", 3));
    let (rejected, inputs) = keeping_at(0, &smaller);
    let control = draws(&loaded(&recorded(CONTROL)).tape).unwrap();
    let joined = |pick: &dyn Fn(usize, &[u8]) -> Vec<u8>| {
        let mut input: Vec<u8> = control
            .iter()
            .enumerate()
            .flat_map(|(at, draw)| pick(at, &draw.bytes))
            .collect();
        input.resize(PAD, 0);
        input
    };
    for (attempt, input) in rejected.attempts.iter().zip(&inputs) {
        let expected = match attempt.change {
            Change::ZeroFrom(from) => joined(&|at, bytes| {
                if at < from {
                    bytes.to_vec()
                } else {
                    Vec::new()
                }
            }),
            Change::Delete(gone) => joined(&|at, bytes| {
                if at == gone {
                    Vec::new()
                } else {
                    bytes.to_vec()
                }
            }),
            Change::Lower(low) => joined(&|at, bytes| {
                if at == low {
                    vec![0; bytes.len()]
                } else {
                    bytes.to_vec()
                }
            }),
            Change::Turns(_) => joined(&|_, bytes| bytes.to_vec()),
        };
        assert_eq!(*input, expected, "{attempt}");
    }
    assert_eq!(inputs.len(), rejected.attempts.len());
    let tried: Vec<Change> = rejected
        .attempts
        .iter()
        .map(|attempt| attempt.change)
        .collect();
    let first = |pick: fn(&Change) -> bool| tried.iter().position(pick).unwrap() + 1;
    for nth in [
        first(|change| matches!(change, Change::ZeroFrom(_))),
        first(|change| matches!(change, Change::Delete(_))),
        first(|change| matches!(change, Change::Lower(_))),
    ] {
        let (reduced, _) = keeping_at(nth, &smaller);
        assert_eq!(reduced.attempts[nth - 1].verdict, Verdict::Kept, "{nth}");
        assert_eq!(
            (reduced.stop, reduced.spent.passes),
            (Stop::Bounded, 1),
            "{nth}"
        );
    }
    let draws = draws(&loaded(&smaller).tape).unwrap();
    let last = draws
        .iter()
        .rposition(|draw| draw.bytes.iter().any(|&byte| byte > 0));
    let nonzero = last.unwrap() + 1;
    let at = first(|change| matches!(change, Change::Delete(_)));
    let (reduced, inputs) = keeping_at(at, &smaller);
    let Change::Delete(index) = reduced.attempts[at - 1].change else {
        panic!("{:?}", reduced.attempts[at - 1]);
    };
    assert_eq!(reduced.attempts[at].change, Change::Delete(index));
    let mut retried: Vec<u8> = draws
        .iter()
        .enumerate()
        .filter(|&(draw, _)| draw != index)
        .flat_map(|(_, draw)| draw.bytes.iter().copied())
        .collect();
    retried.resize(PAD, 0);
    assert_eq!(inputs[at], retried);
    let (reduced, _) = keeping_at(1, &smaller);
    let Change::ZeroFrom(middle) = reduced.attempts[0].change else {
        panic!("{:?}", reduced.attempts[0]);
    };
    assert!(nonzero < middle, "{nonzero} of {middle}");
    let (mut low, mut expected) = (0, vec![middle]);
    while low < nonzero {
        let probe = low + (nonzero - low) / 2;
        expected.push(probe);
        low = probe + 1;
    }
    let probes: Vec<usize> = reduced
        .attempts
        .iter()
        .filter_map(|attempt| match attempt.change {
            Change::ZeroFrom(at) => Some(at),
            _ => None,
        })
        .collect();
    assert_eq!(probes, expected);
}

/// steps.txt names the counts, budget and requirement, each verdict with
/// the step-N files of each fresh-process check after the original's
/// step-1, what was spent, the regression's counts and the stop, and the
/// summary line names the stop; an interrupted reduction has none and
/// gives the check's failure.
#[test]
fn the_report_names_each_check_and_how_the_reduction_stopped() {
    let (first, best) = ("the original's counts", "the regression's counts");
    let attempt = |change, verdict| Attempt { change, verdict };
    for (stop, stopped, line) in [
        (
            Stop::Exhausted,
            "exhausted".to_owned(),
            Ok(format!(
                "reduce-schedule: reduced to {best}, 1 kept, exhausted\n"
            )),
        ),
        (
            Stop::Bounded,
            "bounded".to_owned(),
            Ok(format!(
                "reduce-schedule: reduced to {best}, 1 kept, bounded\n"
            )),
        ),
        (
            Stop::Interrupted("no \"worker\"".into()),
            "interrupted, the fresh-process check failed: \"no \\\"worker\\\"\"".to_owned(),
            Err("no \"worker\"".to_owned()),
        ),
    ] {
        let reduced = Reduced {
            bundle: Vec::new(),
            manifest: manifest(CONTROL.0, CONTROL.1),
            scenario: String::new(),
            original: first.to_owned(),
            best: best.to_owned(),
            attempts: vec![
                attempt(Change::Delete(1), Verdict::Kept),
                attempt(Change::Lower(2), Verdict::NotSmaller),
                attempt(Change::Delete(4), Verdict::Unreproduced),
                attempt(Change::Lower(5), Verdict::Unbudgeted),
                attempt(Change::ZeroFrom(3), Verdict::Unverified),
            ],
            requirement: vec!["s3-mutated-premise".into()],
            budget: Budget {
                candidates: 11,
                passes: 12,
                runs: 13,
            },
            spent: Budget {
                candidates: 3,
                passes: 1,
                runs: 5,
            },
            stop,
        };
        let (steps, printed) = reduced.report();
        assert_eq!(
            steps,
            format!(
                "original: {first}\nbudget: 11 candidates, 12 passes, 13 runs\nrequirement: s3-mutated-premise\n\
                 kept delete draw 1 (step-2)\nrejected, it is no smaller: lower draw 2 to zero\n\
                 rejected, it does not replay in a fresh process: delete draw 4 (step-3)\n\
                 rejected, no run is left for its fresh-process check: lower draw 5 to zero\n\
                 unverified, its fresh-process check failed: zero the draws from 3 (step-4)\n\
                 spent: 3 candidates, 1 passes, 5 runs\nbest: {best}\nstopped: {stopped}\n"
            )
        );
        assert_eq!(printed, line);
    }
}

/// Each candidate renders its change and verdict on one line.
#[test]
fn each_attempt_renders_its_change_and_verdict() {
    let line = |change, verdict| super::Attempt { change, verdict }.to_string();
    assert_eq!(
        line(Change::ZeroFrom(4), Verdict::Kept),
        "kept zero the draws from 4"
    );
    assert_eq!(
        line(Change::Delete(2), Verdict::Short),
        "rejected, its input ran short: delete draw 2"
    );
    assert_eq!(
        line(Change::Turns(9), Verdict::Unverified),
        "unverified, its fresh-process check failed: cut the schedule to 9 turns"
    );
    assert_eq!(
        line(Change::Lower(1), Verdict::Unbudgeted),
        "rejected, no run is left for its fresh-process check: lower draw 1 to zero"
    );
}

/// The schedule form belongs to the worker: the library's test binary has
/// none, so its fresh-process case fails at the regression it never wrote.
#[test]
fn the_schedule_form_runs_only_in_the_worker() {
    let error = fresh_processes_reduce_a_schedule().unwrap_err();
    assert!(error.starts_with("out/regression.bundle: "), "{error}");
}

/// A bundle of `profile` at `root` pinned to this worker.
fn pinned((profile, root): (&str, u64)) -> Result<Vec<u8>, String> {
    use sha2::{Digest, Sha256};
    let path = std::env::current_exe().map_err(|error| error.to_string())?;
    let own = Sha256::digest(std::fs::read(path).map_err(|error| error.to_string())?);
    let own: String = own.iter().map(|byte| format!("{byte:02x}")).collect();
    let platform = format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS);
    let text = crate::sim::manifest_tests::sample(profile, &own, &platform);
    let mut manifest = Manifest::parse(&text).map_err(|error| format!("{error:?}"))?;
    manifest.root = root;
    let admitted = admit(&manifest).map_err(|refusal| format!("{refusal:?}"))?;
    Ok(traced(admitted, Vec::new()).sink)
}

/// Fresh worker processes reduce the control's schedule: the summary line
/// names fewer decisions, the keeps and an exhausted search; DIR holds the original
/// byte for byte, a regression whose recorded manifest is
/// regression.manifest and which the standard replay reproduces, the
/// requirement in conditions.txt, a steps.txt naming counts, budgets,
/// verdicts, spending and stop, and one step-N bundle and replay for each
/// fresh check, the original's first. Each limit flag sets its own budget
/// field, and one candidate's budget stops bounded before a pass completes.
/// Another world, an unsuccessful run, a bundle pinning another build, a
/// record bound passed, an irregular file, an existing DIR and malformed
/// bounds are refused with their exit codes.
pub(crate) fn fresh_processes_reduce_a_schedule() -> Result<(), String> {
    let dir = super::super::scratch("sim-schedule")?;
    let checked = (|| {
        let path = |name: &str| dir.join(name);
        let write = |name: &str, bytes: &[u8]| {
            std::fs::write(path(name), bytes).map_err(|error| error.to_string())
        };
        let read =
            |name: &str| std::fs::read(path(name)).map_err(|error| format!("{name}: {error}"));
        let text =
            |name: &str| read(name).map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
        let original = pinned(CONTROL)?;
        write("control.bundle", &original)?;
        let reduce = |bundle: &str, output: &str, extra: &[&str]| {
            let (bundle, output) = (path(bundle), path(output));
            let mut args = vec![
                "--reduce-schedule".as_ref(),
                bundle.as_os_str(),
                "--output".as_ref(),
                output.as_os_str(),
            ];
            args.extend(extra.iter().map(std::ffi::OsStr::new));
            worker(&args)
        };
        let ran = reduce("control.bundle", "out", &[])?;
        let printed = String::from_utf8_lossy(&ran.stdout).into_owned();
        let regression = read("out/regression.bundle")?;
        let after = load(&regression, u64::MAX).map_err(|e| format!("{e:?}"))?;
        let before = loaded(&original);
        let kept = super::super::replay::manifest_of(&after).map_err(|e| format!("{e:?}"))?;
        let steps = text("out/steps.txt")?;
        let counts = |bytes: &[u8], ran: &Loaded, manifest: &Manifest| {
            let (records, input) = (bytes.len() / RECORD, input_of(bytes).len());
            let (decisions, turns, limit) =
                (ran.decisions, ran.work.turns, manifest.count("turns"));
            format!(
                "{records} records, {decisions} decisions, {turns} of {limit} turns, {input} input bytes"
            )
        };
        let best = counts(&regression, &after, &kept);
        let keeps = steps
            .lines()
            .filter(|line| line.starts_with("kept "))
            .count();
        let line = format!("reduce-schedule: reduced to {best}, {keeps} kept, exhausted\n");
        if ran.status.code() != Some(0) || printed != line || after.decisions >= before.decisions {
            return Err(format!(
                "the reduction exited {}: {printed}{}",
                ran.status,
                String::from_utf8_lossy(&ran.stderr)
            ));
        }
        let recorded_manifest =
            super::super::replay::manifest_of(&before).map_err(|e| format!("{e:?}"))?;
        let numbered: Vec<&str> = steps
            .lines()
            .filter_map(|line| line.rsplit_once(" (step-").map(|(_, step)| step))
            .collect();
        let checks = 1 + numbered.len();
        let in_order = numbered
            .iter()
            .zip(2..)
            .all(|(step, at)| *step == format!("{at})"));
        let expected = [
            read("out/original.bundle")? == original,
            text("out/regression.manifest")? == kept.text(),
            text("out/conditions.txt")? == "s3-mutated-premise\n",
            text("out/scenario.txt")?.starts_with("kinds = "),
            steps.starts_with(&format!(
                "original: {}\nbudget: 512 candidates, 8 passes, 1026 runs\nrequirement: s3-mutated-premise\n",
                counts(&original, &before, &recorded_manifest)
            )),
            steps.ends_with(&format!("best: {best}\nstopped: exhausted\n")),
            steps.contains(&format!("\nspent: {} candidates, ", steps.lines().filter(|line| line.starts_with("kept") || line.starts_with("rejected") || line.starts_with("unverified")).count())),
            in_order,
            read("out/step-1.bundle")? == original,
            (1..=checks).all(|step| path(&format!("out/step-{step}.replay/replay.bundle")).is_file()),
            !path(&format!("out/step-{}.bundle", checks + 1)).exists(),
        ];
        if expected.contains(&false) {
            return Err(format!(
                "the reduction's files disagree: {expected:?}\n{steps}"
            ));
        }
        let (regression, replayed) = (path("out/regression.bundle"), path("replayed"));
        let replay = worker(&[
            "--replay".as_ref(),
            regression.as_os_str(),
            "--output".as_ref(),
            replayed.as_os_str(),
        ])?;
        if replay.status.code() != Some(0)
            || !String::from_utf8_lossy(&replay.stdout).starts_with("replay: reproduced")
        {
            return Err(format!("the regression's replay exited {}", replay.status));
        }
        let limits = [
            "--max-candidates",
            "1",
            "--max-passes",
            "3",
            "--max-runs",
            "100",
        ];
        let bounded = reduce("control.bundle", "bounded", &limits)?;
        let steps = text("bounded/steps.txt")?;
        if bounded.status.code() != Some(0)
            || !String::from_utf8_lossy(&bounded.stdout).ends_with(", bounded\n")
            || !steps.contains("\nbudget: 1 candidates, 3 passes, 100 runs\n")
            || !steps.contains("\nspent: 1 candidates, 0 passes, ")
            || !steps.ends_with("stopped: bounded\n")
        {
            return Err(format!("one candidate's budget exited {}", bounded.status));
        }
        write("cluster.bundle", &pinned(("cluster-broad", 1))?)?;
        write("unheld.bundle", &pinned(("h1-get-unheld", 1))?)?;
        write("foreign.bundle", &recorded(CONTROL))?;
        std::fs::create_dir(path("directory")).map_err(|error| error.to_string())?;
        for (bundle, output, extra, code) in [
            ("cluster.bundle", "cluster", &[][..], 1),
            ("unheld.bundle", "unheld", &[], 1),
            ("foreign.bundle", "foreign", &[], 2),
            ("control.bundle", "few", &["--max-records", "1"], 2),
            (
                "control.bundle",
                "unreadable",
                &["--max-records", "18446744073709551615"],
                2,
            ),
            ("directory", "irregular", &[], 2),
            ("control.bundle", "out", &[], 2),
            ("control.bundle", "zero", &["--max-runs", "0"], 2),
            ("control.bundle", "padded", &["--max-passes", "08"], 2),
            (
                "control.bundle",
                "twice",
                &["--max-runs", "3", "--max-runs", "3"],
                2,
            ),
            ("control.bundle", "unknown", &["--steps", "3"], 2),
        ] {
            let ran = reduce(bundle, output, extra)?;
            let fresh = !matches!(output, "out") && path(output).exists();
            if ran.status.code() != Some(code) || (code == 2 && fresh) {
                return Err(format!(
                    "{bundle} into {output} {extra:?} exited {}",
                    ran.status
                ));
            }
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    checked
}
