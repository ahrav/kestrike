//! Short interleavings within the declared bounds, compared row for row with
//! hand-derived allowed outcome tables.

use super::attempt::PutOutcome;
use super::checker::check;
use super::content::expected_bytes;
use super::golden::{FAILED, Position, put_then_lookup};
use super::history::History;
use super::ids::{ClockSample, KeyId, Label, OpId};
use super::obligation::Obligation;
use super::outcome::{NoInformation, Outcome};
use super::script::{META, Open, Script};
use super::verdict::Verdict;

const K: KeyId = KeyId(0);
const J: KeyId = KeyId(1);
const A: Label = Label(1);
const B: Label = Label(2);
const C: Label = Label(3);
const D: Label = Label(4);
const BODY: u64 = 16;
const ORDERS: [&str; 6] = ["XXLL", "XLXL", "XLLX", "LXXL", "LXLX", "LLXX"];
const HIT_OLD: usize = 0;
const HIT_NEW: usize = 1;
const MISSING: usize = 2;
const CONTENDED: usize = 3;

const INVALIDATE_ALLOWED: [(&str, [bool; 4]); 6] = [
    ("XXLL", [false, false, true, true]),
    ("XLXL", [true, false, true, true]),
    ("XLLX", [true, false, true, true]),
    ("LXXL", [true, false, true, true]),
    ("LXLX", [true, false, true, true]),
    ("LLXX", [true, false, true, true]),
];

const REPLACE_ALLOWED: [(&str, [bool; 4]); 6] = [
    ("XXLL", [true, true, true, true]),
    ("XLXL", [true, true, true, true]),
    ("XLLX", [true, true, true, true]),
    ("LXXL", [true, true, true, true]),
    ("LXLX", [true, true, true, true]),
    ("LLXX", [true, false, true, true]),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Effect {
    Invalidate,
    Replace,
}

fn outcome(index: usize, old: Label, new: Label) -> (Outcome, Option<Label>) {
    match index {
        HIT_OLD => (Outcome::Hit, Some(old)),
        HIT_NEW => (Outcome::Hit, Some(new)),
        MISSING => (Outcome::Missing, None),
        _ => (Outcome::NoInformation(NoInformation::Contended), None),
    }
}

struct Lane {
    key: KeyId,
    effect: Effect,
    order: &'static str,
    result: usize,
    old: Label,
    new: Label,
}

impl Lane {
    fn prepare(&self, s: &mut Script) {
        s.publish(self.key, self.old, BODY);
    }

    fn step(
        &self,
        s: &mut Script,
        effect: &mut Option<Open>,
        lookup: &mut Option<Open>,
        at: usize,
    ) {
        let event = self.order.as_bytes()[at];
        if event == b'X' {
            match effect.take() {
                None => {
                    *effect = Some(match self.effect {
                        Effect::Invalidate => s.begin_invalidate(self.key),
                        Effect::Replace => s.begin_replace(self.key, self.new, BODY),
                    });
                }
                Some(open) => {
                    s.close(open, Some(Outcome::Acknowledged));
                }
            }
        } else {
            match lookup.take() {
                None => *lookup = Some(s.begin_lookup(self.key, ClockSample::Seconds(1))),
                Some(open) => {
                    let (result, label) = outcome(self.result, self.old, self.new);
                    s.end_lookup(open, result, label);
                }
            }
        }
    }
}

fn run(lanes: &[Lane]) -> History {
    let mut s = Script::new();
    for lane in lanes {
        lane.prepare(&mut s);
    }
    let mut effects: Vec<Option<Open>> = lanes.iter().map(|_| None).collect();
    let mut lookups: Vec<Option<Open>> = lanes.iter().map(|_| None).collect();
    for at in 0..4 {
        for (i, lane) in lanes.iter().enumerate() {
            lane.step(&mut s, &mut effects[i], &mut lookups[i], at);
        }
    }
    s.finish()
}

fn allowed(table: &[(&str, [bool; 4]); 6], order: &str, result: usize) -> bool {
    table
        .iter()
        .find(|(o, _)| *o == order)
        .map(|(_, row)| row[result])
        .unwrap()
}

fn accepted(history: &History) -> bool {
    match check(history) {
        Verdict::Pass(_) => true,
        Verdict::Violation(violation) => {
            assert_eq!(violation.obligation, Obligation::History);
            false
        }
        verdict => panic!("{verdict:?}"),
    }
}

#[test]
fn invalidation_against_one_lookup_matches_the_hand_derived_table() {
    for order in ORDERS {
        for result in [HIT_OLD, MISSING, CONTENDED] {
            let lane = Lane {
                key: K,
                effect: Effect::Invalidate,
                order,
                result,
                old: A,
                new: B,
            };
            let expected = allowed(&INVALIDATE_ALLOWED, order, result);
            assert_eq!(accepted(&run(&[lane])), expected, "{order} {result}");
        }
    }
}

#[test]
fn replacement_against_one_lookup_matches_the_hand_derived_table() {
    for order in ORDERS {
        for result in [HIT_OLD, HIT_NEW, MISSING, CONTENDED] {
            let lane = Lane {
                key: K,
                effect: Effect::Replace,
                order,
                result,
                old: A,
                new: B,
            };
            let expected = allowed(&REPLACE_ALLOWED, order, result);
            assert_eq!(accepted(&run(&[lane])), expected, "{order} {result}");
        }
    }
}

#[test]
fn two_keys_with_two_labels_each_are_judged_independently() {
    for first in ORDERS {
        for second in ORDERS {
            for a in [HIT_OLD, MISSING, CONTENDED] {
                for b in [HIT_OLD, HIT_NEW, MISSING, CONTENDED] {
                    let lanes = [
                        Lane {
                            key: K,
                            effect: Effect::Invalidate,
                            order: first,
                            result: a,
                            old: A,
                            new: B,
                        },
                        Lane {
                            key: J,
                            effect: Effect::Replace,
                            order: second,
                            result: b,
                            old: C,
                            new: D,
                        },
                    ];
                    let expected = allowed(&INVALIDATE_ALLOWED, first, a)
                        && allowed(&REPLACE_ALLOWED, second, b);
                    assert_eq!(accepted(&run(&lanes)), expected, "{first} {a} {second} {b}");
                }
            }
        }
    }
}

#[test]
fn a_second_holder_keeps_its_old_read_across_every_interleaving() {
    for order in ORDERS {
        for result in [HIT_OLD, MISSING, CONTENDED] {
            let mut s = Script::new();
            s.publish(K, A, BODY);
            let holder: OpId = s.lookup(K, Outcome::Hit, Some(A));
            let lane = Lane {
                key: K,
                effect: Effect::Invalidate,
                order,
                result,
                old: A,
                new: B,
            };
            let mut effect = None;
            let mut lookup = None;
            for at in 0..4 {
                lane.step(&mut s, &mut effect, &mut lookup, at);
            }
            let payload = expected_bytes(K, A, META as usize + BODY as usize);
            s.deliver(holder, K, A, BODY, Outcome::Complete, payload);
            let history = s.finish();
            let expected = allowed(&INVALIDATE_ALLOWED, order, result);
            assert_eq!(accepted(&history), expected, "{order} {result}");
            if expected {
                assert!(check(&history).satisfies(&[Obligation::Bytes]));
            }
        }
    }
}

const UNPUBLISHED_HIT: &str = "a hit of a version no linearized fill published";
const UNPUBLISHED: &str = "an attempt that did not publish published";
const NO_PUBLICATION: &str = "Published without the attempt's publication";

/// The rule the history breaks, or `None` when it is allowed, for each client
/// result (`None` is a pending attempt), owner publication and lookup
/// position; each cell lists the hit on `A` and then the miss.
fn put_expected(
    result: Option<PutOutcome>,
    published: bool,
    position: Position,
) -> [Option<&'static str>; 2] {
    let by_publication = match (published, position) {
        (true, Position::Overlapping | Position::BeforeResult | Position::AfterResult) => {
            [None, None]
        }
        _ => [Some(UNPUBLISHED_HIT), None],
    };
    match (result, published) {
        (Some(PutOutcome::Published), false) => [Some(NO_PUBLICATION); 2],
        (Some(PutOutcome::Failed(_) | PutOutcome::NotStarted), true) => [Some(UNPUBLISHED); 2],
        _ => by_publication,
    }
}

type Anchor = (
    Option<PutOutcome>,
    bool,
    Position,
    usize,
    Option<&'static str>,
);

#[test]
fn literal_put_anchors_agree_with_the_allowed_table() {
    let anchors: [Anchor; 6] = [
        (
            Some(FAILED),
            true,
            Position::BeforePublication,
            0,
            Some(UNPUBLISHED),
        ),
        (
            Some(PutOutcome::Published),
            false,
            Position::AfterResult,
            1,
            Some(NO_PUBLICATION),
        ),
        (
            Some(PutOutcome::Unknown),
            true,
            Position::Overlapping,
            1,
            None,
        ),
        (
            Some(PutOutcome::Unknown),
            true,
            Position::BeforeResult,
            1,
            None,
        ),
        (None, false, Position::AfterResult, 0, Some(UNPUBLISHED_HIT)),
        (
            Some(PutOutcome::NotStarted),
            false,
            Position::AfterResult,
            1,
            None,
        ),
    ];
    for (result, published, position, lookup, rule) in anchors {
        assert_eq!(
            put_expected(result, published, position)[lookup],
            rule,
            "{result:?} {published} {position:?} {lookup}"
        );
    }
}

#[test]
fn every_put_result_publication_and_lookup_position_matches_the_allowed_table() {
    let label = super::golden::A;
    let results = [
        Some(PutOutcome::Published),
        Some(FAILED),
        Some(PutOutcome::NotStarted),
        Some(PutOutcome::Unknown),
        None,
    ];
    let positions = [
        Position::BeforePublication,
        Position::Overlapping,
        Position::BeforeResult,
        Position::AfterResult,
    ];
    for result in results {
        for published in [true, false] {
            for position in positions {
                let expected = put_expected(result, published, position);
                let lookups = [(Outcome::Hit, Some(label)), (Outcome::Missing, None)];
                for (lookup, rule) in lookups.into_iter().zip(expected) {
                    let verdict = check(&put_then_lookup(result, published, lookup, position));
                    let case = format!("{result:?} {published} {position:?} {lookup:?}");
                    match rule {
                        None => assert!(
                            verdict.satisfies(&[Obligation::History]),
                            "{case}: {verdict:?}"
                        ),
                        Some(rule) => assert_eq!(
                            verdict.violated(),
                            Some((Obligation::History, rule)),
                            "{case}"
                        ),
                    }
                }
            }
        }
    }
}
