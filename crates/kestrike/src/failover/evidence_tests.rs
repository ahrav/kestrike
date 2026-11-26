use super::bounds::Bounds;
use super::evidence::{Holding, Pair, Registrant, Report, ReservationType, find_from};
use super::identity::{Epoch, Exhid, Incarnation, Key};

pub(super) fn bounds() -> Bounds {
    Bounds::new(4, 2, 100, 10, 20, 5).unwrap()
}

pub(super) fn exhid(tag: u8) -> Exhid {
    let mut bytes = [0; 16];
    bytes[0] = tag;
    Exhid::new(bytes).unwrap()
}

pub(super) fn pair(tag: u8, epoch: u32, incarnation: u32) -> Pair {
    Pair {
        exhid: exhid(tag),
        key: Key::new(
            Epoch::new(epoch).unwrap(),
            Incarnation::new(incarnation).unwrap(),
        ),
    }
}

pub(super) fn entry(cntlid: u16, pair: Pair, holder: bool) -> Registrant {
    Registrant {
        cntlid,
        pair,
        holder,
    }
}

pub(super) fn report<'a>(entries: &'a [Registrant]) -> Report<'a> {
    Report {
        submitted_at: 0,
        rtype: ReservationType::ExclusiveAccess,
        regctl: entries.len() as u32,
        entries,
    }
}

/// Holding registrants group by pair: one pair is the holder, two pairs are `Several`, none is `Nobody`, an rtype of none holds nobody, and a header naming more than `N_reg` registrants or a count other than its entries is inconclusive.
#[test]
fn holding_groups_registrants_by_pair() {
    let old = pair(1, 3, 1);
    let entries = [entry(1, old, true), entry(2, pair(2, 1, 2), false)];
    assert_eq!(report(&entries).holding(&bounds()), Holding::One(old));
    let same_host = [entry(1, old, true), entry(4, old, true)];
    assert_eq!(report(&same_host).holding(&bounds()), Holding::One(old));
    let two = [entry(1, old, true), entry(2, pair(2, 1, 2), true)];
    assert_eq!(report(&two).holding(&bounds()), Holding::Several);
    let none = [entry(1, old, false)];
    assert_eq!(report(&none).holding(&bounds()), Holding::Nobody);
    let released = Report {
        rtype: ReservationType::None,
        ..report(&entries)
    };
    assert_eq!(released.holding(&bounds()), Holding::Nobody);
    assert_eq!(
        report(&[entry(1, old, true); 4]).holding(&bounds()),
        Holding::One(old)
    );
    assert_eq!(
        report(&[entry(1, old, true), entry(4, pair(1, 4, 1), true)]).holding(&bounds()),
        Holding::Several
    );
    let five = [entry(1, old, true); 5];
    assert_eq!(report(&five).holding(&bounds()), Holding::Inconclusive);
    let miscounted = Report {
        regctl: 1,
        ..report(&entries)
    };
    assert_eq!(miscounted.holding(&bounds()), Holding::Inconclusive);
}

/// The owner's flip request and the reconciler's retirement admission classify the same Report, so their decisions must agree on each refusal.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[test]
fn report_refusals_withdraw_and_retire_on_one_classification() {
    use super::evidence::NotSole::{self, *};
    use super::retire::Trigger;
    use super::serving::ReportTrigger;
    let refusals: [NotSole; 7] = [
        Excess,
        Unreadable,
        ReservationType,
        DuplicateOwnRecord,
        ForeignHolder,
        ForeignRegistrant,
        NotHolder,
    ];
    for refusal in refusals {
        let observed = refusal.observed();
        assert_eq!(observed, !matches!(refusal, Unreadable), "{refusal:?}");
        assert_eq!(
            ReportTrigger::new(refusal).is_some(),
            observed,
            "withdrawal: {refusal:?}"
        );
        assert_eq!(
            Trigger::Report(refusal).retires(),
            observed,
            "retirement: {refusal:?}"
        );
    }
}

#[test]
fn a_ghost_registration_leaves_the_holding_unchanged() {
    let (old, own) = (pair(1, 3, 1), pair(2, 4, 2));
    let ghost = [
        entry(1, old, true),
        entry(9, pair(2, 1, 2), false),
        entry(2, own, false),
    ];
    assert_eq!(report(&ghost).holding(&bounds()), Holding::One(old));
}

/// Every holder other than the own pair refuses, a recorded one included. A count over `N_reg` is conclusive when a
/// listed pair is unrecorded or the count exceeds the recorded pairs with the own pair, and no observation when they
/// account for it. Without a volume record, a non-holding registrant is no observation when a recorded pair could
/// explain it. `sole`, the rule over no recorded pair, refuses every registrant other than the own pair.
#[test]
fn registrants_judge_reports_against_the_recorded_pairs() {
    use super::evidence::NotSole::{self, *};
    let (own, standby, unknown) = (pair(1, 1, 1), pair(2, 1, 2), pair(9, 1, 9));
    let crowd: Vec<Pair> = (3..7).map(|tag| pair(tag, 1, u32::from(tag))).collect();
    let mut recorded = vec![standby];
    recorded.extend(&crowd);
    let alias = Pair {
        key: unknown.key,
        ..own
    };
    let own_five = [entry(1, own, true); 5];
    let mut recorded_five = vec![entry(1, own, true)];
    recorded_five.extend(crowd.iter().map(|pair| entry(2, *pair, false)));
    let mut unknown_five = recorded_five.clone();
    unknown_five[4] = entry(2, unknown, false);
    let mut recorded_six = recorded_five.clone();
    recorded_six.push(entry(3, standby, false));
    let mut recorded_seven = recorded_six.clone();
    recorded_seven.push(entry(4, standby, false));
    let aliased = [entry(1, own, true), entry(2, alias, false)];
    let unknown_holds = [entry(1, own, false), entry(2, unknown, true)];
    let unknown_registered = [entry(1, own, true), entry(2, unknown, false)];
    let unknown_beside_absent = [entry(1, own, false), entry(2, unknown, false)];
    let standby_holds = [entry(1, own, false), entry(2, standby, true)];
    let nobody = [entry(1, own, false), entry(2, standby, false)];
    let serving = [entry(1, own, true), entry(2, standby, false)];
    type Verdict = Result<(), NotSole>;
    type Row<'a> = (&'a str, Report<'a>, Verdict, Verdict, Verdict);
    let rows: [Row<'_>; 14] = [
        (
            "own pair over the bound",
            report(&own_five),
            Err(Unreadable),
            Err(Unreadable),
            Err(Excess),
        ),
        (
            "recorded pairs over the bound",
            report(&recorded_five),
            Err(Unreadable),
            Err(Unreadable),
            Err(Excess),
        ),
        (
            "recorded pairs and the own pair exactly account for the count",
            report(&recorded_six),
            Err(Unreadable),
            Err(Unreadable),
            Err(Excess),
        ),
        (
            "every pair recorded and a count above the recorded pairs with the own pair",
            report(&recorded_seven),
            Err(Excess),
            Err(Unreadable),
            Err(Excess),
        ),
        (
            "an unrecorded pair over the bound",
            report(&unknown_five),
            Err(Excess),
            Err(Unreadable),
            Err(Excess),
        ),
        (
            "miscounted",
            Report {
                regctl: 2,
                ..report(&own_five[..1])
            },
            Err(Unreadable),
            Err(Unreadable),
            Err(Unreadable),
        ),
        (
            "no reservation",
            Report {
                rtype: super::evidence::ReservationType::None,
                ..report(&own_five[..1])
            },
            Err(ReservationType),
            Err(ReservationType),
            Err(ReservationType),
        ),
        (
            "two own records",
            report(&aliased),
            Err(DuplicateOwnRecord),
            Err(DuplicateOwnRecord),
            Err(DuplicateOwnRecord),
        ),
        (
            "unknown holder",
            report(&unknown_holds),
            Err(ForeignHolder),
            Err(ForeignHolder),
            Err(ForeignHolder),
        ),
        (
            "recorded holder",
            report(&standby_holds),
            Err(ForeignHolder),
            Err(ForeignHolder),
            Err(ForeignHolder),
        ),
        (
            "unknown registrant",
            report(&unknown_registered),
            Err(ForeignRegistrant),
            Err(Unreadable),
            Err(ForeignRegistrant),
        ),
        (
            "unknown registrant, own not holding",
            report(&unknown_beside_absent),
            Err(ForeignRegistrant),
            Err(NotHolder),
            Err(ForeignRegistrant),
        ),
        (
            "nobody holds",
            report(&nobody),
            Err(NotHolder),
            Err(NotHolder),
            Err(ForeignRegistrant),
        ),
        (
            "own holds over a recorded registrant",
            report(&serving),
            Ok(()),
            Err(Unreadable),
            Err(ForeignRegistrant),
        ),
    ];
    for (name, report, read, unread, sole) in rows {
        assert_eq!(
            report.registrants(own, Some(&recorded), &bounds()),
            read,
            "{name}"
        );
        assert_eq!(
            report.registrants(own, None, &bounds()),
            unread,
            "{name} unread"
        );
        assert_eq!(report.sole(own, &bounds()), sole, "{name} sole");
    }
    let with_own: Vec<Pair> = core::iter::once(own)
        .chain(recorded.iter().copied())
        .collect();
    assert_eq!(
        report(&recorded_six).registrants(own, Some(&with_own), &bounds()),
        Err(Unreadable),
        "the own pair counts once whether or not it is recorded"
    );
    assert_eq!(
        report(&recorded_seven).registrants(own, Some(&with_own), &bounds()),
        Err(Excess)
    );
    let wide = Bounds::new(8, 2, 100, 10, 20, 5).unwrap();
    let over_wide: Vec<_> = (0..9)
        .map(|at| entry(at, pair(at as u8 + 1, 1, u32::from(at) + 1), at == 0))
        .collect();
    let first = over_wide[0].pair;
    assert_eq!(
        report(&over_wide).registrants(first, None, &wide),
        Err(Excess),
        "a bound at the recorded-pair cap keeps an over-bound count conclusive unread"
    );
    for (recorded, unparsed) in [
        (None, Unreadable),
        (Some(&recorded[..]), Excess),
        (Some(&[][..]), Excess),
    ] {
        assert_eq!(
            Excess.unparsed(recorded, &bounds()),
            unparsed,
            "{recorded:?}"
        );
        assert_eq!(Excess.unparsed(recorded, &wide), Excess, "{recorded:?}");
        assert_eq!(
            ForeignRegistrant.unparsed(recorded, &bounds()),
            ForeignRegistrant
        );
    }
}

/// Control: the planted mutation judges with the sole-registrant rule, ignoring the recorded pairs. On the enrolled
/// standby's witness the correct rule over the volume record's pairs passes, and the mutation refuses with an
/// observed `ForeignRegistrant`, which retires the volume.
#[test]
fn negative_control_a_sole_count_rule_retires_an_enrolled_standby() {
    let (own, standby) = (pair(1, 1, 1), pair(2, 1, 2));
    let entries = [entry(1, own, true), entry(2, standby, false)];
    let witness = report(&entries);
    let oracle = witness.registrants(own, Some(&[own, standby]), &bounds());
    assert_eq!(
        oracle,
        Ok(()),
        "the admitted-set rule keeps the owner serving"
    );
    let sole_count = |report: &Report<'_>| report.sole(own, &bounds());
    let mutated = sole_count(&witness);
    assert_eq!(mutated, Err(super::evidence::NotSole::ForeignRegistrant));
    assert!(
        mutated.is_err_and(super::evidence::NotSole::observed) && mutated != oracle,
        "an enrolled standby's registration retires the owner's volume"
    );
}

/// Control: the planted mutation admits every listed pair as recorded. On an unknown registrant's witness the
/// correct rule over an owner-only record refuses with `ForeignRegistrant`, and the mutation keeps the owner serving.
#[test]
fn negative_control_an_admit_all_rule_keeps_an_unknown_registrant() {
    let (own, unknown) = (pair(1, 1, 1), pair(9, 1, 9));
    let entries = [entry(1, own, true), entry(2, unknown, false)];
    let witness = report(&entries);
    let oracle = witness.registrants(own, Some(&[own]), &bounds());
    assert_eq!(oracle, Err(super::evidence::NotSole::ForeignRegistrant));
    let admit_all = |report: &Report<'_>| {
        let listed: Vec<Pair> = report.entries.iter().map(|entry| entry.pair).collect();
        report.registrants(own, Some(&listed), &bounds())
    };
    assert_eq!(
        admit_all(&witness),
        Ok(()),
        "an unknown registrant keeps the owner serving"
    );
    assert_ne!(admit_all(&witness), oracle);
}

/// The census asks about each entry of another pair once, in entry order, and never about the own pair. It counts
/// the own host ID's entries, marks that ID under another key, and keeps the first holding pair other than the own
/// pair with the caller's admission of it; a second such pair sets `several`, and an entry the caller does not admit
/// sets `unknown`.
#[test]
fn the_census_counts_the_entries_for_the_own_pair_in_one_pass() {
    let own = pair(1, 1, 1);
    let rekeyed = pair(1, 5, 5);
    let (admitted, stranger) = (pair(2, 1, 2), pair(3, 1, 3));
    let entries = [
        entry(1, own, true),
        entry(2, admitted, false),
        entry(3, stranger, true),
        entry(4, rekeyed, false),
        entry(5, admitted, true),
        entry(6, stranger, true),
    ];
    let mut asked = Vec::new();
    let census = report(&entries).census(own, |pair| {
        asked.push(*pair);
        *pair == admitted
    });
    assert_eq!(asked, [admitted, stranger, rekeyed, admitted, stranger]);
    assert_eq!(
        (census.own_host, census.rekeyed, census.held),
        (2, true, true)
    );
    assert_eq!(census.foreign, Some((stranger, false)));
    assert!(census.several && census.unknown);
    let alone = report(&entries[..1]).census(own, |_| panic!("the own pair needs no admission"));
    assert_eq!(
        (alone.own_host, alone.rekeyed, alone.held, alone.foreign),
        (1, false, true, None)
    );
    assert!(!alone.several && !alone.unknown);
    let twice = [entry(2, admitted, true), entry(7, admitted, true)];
    let one_pair = report(&twice).census(own, |_| true);
    assert_eq!(one_pair.foreign, Some((admitted, true)));
    assert!(!one_pair.several && !one_pair.unknown && !one_pair.held);
}

/// The holding read from a census equals [`Report::holding`] over every holder pattern of four entries of three
/// pairs, under both reservation types and under a conclusive, an over-bound and a mismatched count.
#[test]
fn the_holding_read_from_a_census_equals_the_holding_of_the_entries() {
    let own = pair(1, 1, 1);
    let pairs = [own, pair(2, 1, 2), pair(2, 1, 2), pair(3, 1, 3)];
    for holders in 0..16u8 {
        let entries: Vec<Registrant> = pairs
            .iter()
            .enumerate()
            .map(|(at, pair)| entry(at as u16, *pair, holders >> at & 1 == 1))
            .collect();
        for rtype in [ReservationType::ExclusiveAccess, ReservationType::None] {
            for regctl in [4, 5, 3] {
                let report = Report {
                    rtype,
                    regctl,
                    ..report(&entries)
                };
                let census = report.census(own, |_| true);
                assert_eq!(
                    report.holding_of(&census, own, &bounds()),
                    report.holding(&bounds()),
                    "holders {holders:04b}, {rtype:?}, count {regctl}"
                );
            }
        }
    }
}

/// A lookup starts where the last match ended and steps once over each item up to its match: one step for the next
/// item, two when it passes one item. A lookup for an earlier item wraps to it, a miss visits every item and leaves
/// the position, and an empty slice finds nothing.
#[test]
fn ordered_lookups_resume_after_the_last_match_and_wrap() {
    let items = [10, 20, 30, 40];
    let steps = std::cell::Cell::new(0);
    let find = |from: &mut usize, wanted: i32| {
        steps.set(0);
        find_from(&items, from, |item| {
            steps.set(steps.get() + 1);
            *item == wanted
        })
        .copied()
    };
    let mut from = 0;
    for (wanted, expected_steps) in [(10, 1), (20, 1), (40, 2)] {
        assert_eq!(find(&mut from, wanted), Some(wanted));
        assert_eq!(steps.get(), expected_steps, "{wanted}");
    }
    assert_eq!(from, 4);
    assert_eq!(find(&mut from, 30), Some(30));
    assert_eq!((from, steps.get()), (3, 3));
    assert_eq!(find(&mut from, 50), None);
    assert_eq!((from, steps.get()), (3, 4));
    assert_eq!(find(&mut from, 10), Some(10));
    assert_eq!((from, steps.get()), (1, 2));
    assert_eq!(find_from(&[0u8; 0], &mut from, |_| true), None);
}
