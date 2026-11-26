//! Each ownership rule has a minimal failing history.

use super::ids::{CutId, OpId, Tenure};
use super::obligation::Obligation;
use super::ownership::{O1, O2, O3, Step, judge};
use super::row::Field;
use super::verdict::{Inconclusive, Verdict, Violation};

const CUT: CutId = CutId(9);
const A: Tenure = Tenure { g: 3, a: 10 };
const B: Tenure = Tenure { g: 3, a: 12 };
const C: Tenure = Tenure { g: 3, a: 14 };

fn fenced(tenure: Tenure) -> Step {
    Step::Fenced {
        tenure,
        durable: Some(CUT),
    }
}

fn commands(tenure: Tenure, accepted: u64, succeeded: &[u64]) -> Step {
    Step::Commands {
        tenure,
        accepted,
        succeeded: succeeded.to_vec(),
    }
}

fn recovered(tenure: Tenure, cut: Option<CutId>) -> Step {
    Step::Recovered { tenure, cut }
}

fn rule(steps: &[Step]) -> &'static str {
    match judge(steps) {
        Err(verdict) => match verdict.violated() {
            Some((Obligation::Restart, rule)) => rule,
            _ => panic!("{verdict:?}"),
        },
        Ok(()) => panic!("the steps passed: {steps:?}"),
    }
}

fn malformed_at(steps: &[Step]) -> OpId {
    match judge(steps) {
        Err(Verdict::Inconclusive(Inconclusive::Malformed {
            op,
            field: Field::Tenure,
        })) => op,
        judged => panic!("{judged:?}"),
    }
}

#[test]
fn every_ownership_rule_fails_its_minimal_history() {
    let o1 = "a deposed tenure's medium command, accepted after its successor's fence, succeeded";
    let o2 = "a withdrawn tenure's device accepted a medium command";
    let o3 = "a successor recovered from a cut other than the one its volume last made durable";
    assert_eq!([o1, o2, o3], [O1, O2, O3]);
    let cases: [(&str, Vec<Step>, Step, Step); 9] = [
        (
            o1,
            vec![fenced(A), fenced(B)],
            commands(A, 1, &[0]),
            commands(A, 1, &[]),
        ),
        (
            o1,
            vec![
                fenced(A),
                commands(A, 1, &[]),
                fenced(B),
                commands(A, 3, &[]),
                fenced(C),
            ],
            commands(A, 3, &[1]),
            commands(A, 3, &[0]),
        ),
        (
            o2,
            vec![
                fenced(A),
                commands(A, 1, &[]),
                Step::Withdrawn { tenure: A },
            ],
            commands(A, 2, &[]),
            commands(A, 1, &[]),
        ),
        (
            o2,
            vec![fenced(A), Step::Withdrawn { tenure: A }],
            commands(A, 1, &[]),
            commands(A, 0, &[]),
        ),
        (
            o2,
            vec![
                fenced(A),
                commands(A, 1, &[0]),
                fenced(B),
                commands(B, 3, &[]),
                Step::Withdrawn { tenure: A },
            ],
            commands(A, 2, &[0]),
            commands(A, 1, &[0]),
        ),
        (
            o3,
            vec![fenced(A)],
            recovered(A, None),
            recovered(A, Some(CUT)),
        ),
        (
            o3,
            vec![fenced(A)],
            recovered(A, Some(CutId(8))),
            recovered(A, Some(CUT)),
        ),
        (
            o3,
            vec![Step::Fenced {
                tenure: A,
                durable: None,
            }],
            recovered(A, Some(CUT)),
            recovered(A, None),
        ),
        (
            o3,
            vec![
                fenced(A),
                Step::Fenced {
                    tenure: B,
                    durable: Some(CutId(8)),
                },
            ],
            recovered(A, Some(CutId(8))),
            recovered(A, Some(CUT)),
        ),
    ];
    for (expected, prefix, failing, passing) in cases {
        let op = OpId(u32::try_from(prefix.len()).expect("a short list"));
        let mut failed = prefix.clone();
        failed.push(failing);
        let violation = Violation {
            obligation: Obligation::Restart,
            op,
            rule: expected,
        };
        assert_eq!(
            judge(&failed),
            Err(Verdict::Violation(violation)),
            "{failed:?}"
        );
        let mut passed = prefix;
        passed.push(passing);
        assert_eq!(judge(&passed), Ok(()), "{passed:?}");
    }
}

#[test]
fn legal_takeover_chains_pass() {
    let takeover = vec![
        fenced(A),
        recovered(A, Some(CUT)),
        commands(A, 4, &[0, 1, 2, 3]),
        fenced(B),
        commands(A, 4, &[0, 1, 2, 3]),
        recovered(B, Some(CUT)),
        commands(B, 2, &[0, 1]),
    ];
    let chain = vec![
        fenced(A),
        recovered(A, Some(CUT)),
        commands(A, 2, &[0, 1]),
        fenced(B),
        recovered(B, Some(CUT)),
        commands(B, 3, &[0, 1, 2]),
        fenced(C),
        recovered(C, Some(CUT)),
        commands(C, 1, &[0]),
    ];
    let restart = vec![
        fenced(A),
        recovered(A, Some(CUT)),
        commands(A, 2, &[0, 1]),
        Step::Fenced {
            tenure: Tenure { g: 3, a: 11 },
            durable: Some(CUT),
        },
        recovered(Tenure { g: 3, a: 11 }, Some(CUT)),
    ];
    let cold = vec![
        Step::Fenced {
            tenure: A,
            durable: None,
        },
        recovered(A, None),
        commands(A, 2, &[0, 1]),
    ];
    for steps in [takeover, chain, restart, cold] {
        assert_eq!(judge(&steps), Ok(()), "{steps:?}");
    }
}

#[test]
fn a_command_accepted_before_the_fence_may_succeed_after_it() {
    let steps = [
        fenced(A),
        commands(A, 2, &[0]),
        fenced(B),
        commands(A, 2, &[0, 1]),
    ];
    assert_eq!(judge(&steps), Ok(()));
}

#[test]
fn a_fence_at_or_below_an_earlier_one_is_malformed() {
    let equal = [fenced(B), recovered(B, Some(CUT)), fenced(B)];
    assert_eq!(malformed_at(&equal), OpId(2));
    let below = [fenced(B), fenced(A)];
    assert_eq!(malformed_at(&below), OpId(1));
    let unfenced = [fenced(A), commands(B, 1, &[])];
    assert_eq!(malformed_at(&unfenced), OpId(1));
    let unrecovered = [fenced(A), recovered(B, Some(CUT))];
    assert_eq!(malformed_at(&unrecovered), OpId(1));
    let unwithdrawn = [fenced(A), Step::Withdrawn { tenure: B }];
    assert_eq!(malformed_at(&unwithdrawn), OpId(1));
}

#[test]
fn a_list_with_no_step_is_malformed() {
    assert_eq!(malformed_at(&[]), OpId(0));
}

#[test]
fn an_accepted_count_that_falls_is_malformed() {
    let steps = [fenced(A), commands(A, 3, &[]), commands(A, 2, &[])];
    assert_eq!(malformed_at(&steps), OpId(2));
}

#[test]
fn a_success_ordinal_outside_the_accepted_commands_is_malformed() {
    let unfenced_successor = [fenced(A), commands(A, 0, &[0])];
    assert_eq!(malformed_at(&unfenced_successor), OpId(1));
    let after_the_fence = [fenced(A), fenced(B), commands(A, 0, &[0])];
    assert_eq!(malformed_at(&after_the_fence), OpId(2));
    let equal = [fenced(A), commands(A, 2, &[0, 2])];
    assert_eq!(malformed_at(&equal), OpId(1));
    let above = [fenced(A), commands(A, 1, &[3])];
    assert_eq!(malformed_at(&above), OpId(1));
    let above_after_the_fence = [fenced(A), fenced(B), commands(A, 1, &[3])];
    assert_eq!(malformed_at(&above_after_the_fence), OpId(2));
}

#[test]
fn a_malformed_step_after_a_violation_is_inconclusive() {
    let mut steps = vec![fenced(A), fenced(B), commands(A, 1, &[0])];
    assert_eq!(rule(&steps), O1);
    steps.push(fenced(B));
    assert_eq!(malformed_at(&steps), OpId(3));
    let falling = [
        fenced(A),
        recovered(A, None),
        commands(A, 2, &[]),
        commands(A, 1, &[]),
    ];
    assert_eq!(malformed_at(&falling), OpId(3));
    let mut after_o1 = vec![
        fenced(A),
        commands(A, 1, &[]),
        fenced(B),
        commands(A, 3, &[1]),
    ];
    assert_eq!(rule(&after_o1), O1);
    after_o1.push(commands(A, 2, &[1]));
    assert_eq!(malformed_at(&after_o1), OpId(4));
    let mut after_o2 = vec![
        fenced(A),
        Step::Withdrawn { tenure: A },
        commands(A, 3, &[]),
    ];
    assert_eq!(rule(&after_o2), O2);
    after_o2.push(commands(A, 2, &[]));
    assert_eq!(malformed_at(&after_o2), OpId(3));
}

#[test]
fn the_first_of_two_violations_is_the_verdict() {
    let steps = [
        fenced(A),
        recovered(A, None),
        Step::Withdrawn { tenure: A },
        commands(A, 1, &[]),
    ];
    let first = Violation {
        obligation: Obligation::Restart,
        op: OpId(1),
        rule: O3,
    };
    assert_eq!(judge(&steps), Err(Verdict::Violation(first)));
}

#[test]
fn a_falling_count_of_an_earlier_tenure_is_malformed() {
    let steps = [
        fenced(A),
        commands(A, 3, &[]),
        fenced(B),
        commands(B, 1, &[]),
        commands(A, 2, &[]),
    ];
    assert_eq!(malformed_at(&steps), OpId(4));
}

#[test]
fn a_second_withdrawal_changes_no_verdict() {
    let withdrawn = Step::Withdrawn { tenure: A };
    let mut steps = vec![
        fenced(A),
        commands(A, 1, &[]),
        withdrawn.clone(),
        commands(A, 1, &[]),
        withdrawn,
        commands(A, 1, &[]),
    ];
    assert_eq!(judge(&steps), Ok(()));
    steps.push(commands(A, 2, &[]));
    assert_eq!(rule(&steps), O2);
}

#[test]
fn a_step_that_breaks_o1_and_o2_fails_o1() {
    let steps = [
        fenced(A),
        commands(A, 1, &[]),
        fenced(B),
        Step::Withdrawn { tenure: A },
        commands(A, 2, &[1]),
    ];
    assert_eq!(rule(&steps), O1);
}
