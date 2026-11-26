//! `Report::registrants` refuses any holder other than the own pair, recorded or not.
//!
//! ADMITTED-REGISTRANTS: `Report::registrants` admits the own pair as the holder and each recorded pair as a
//! non-holding registrant. Any holder other than the own pair refuses, recorded or not. A refusal that a
//! recorded pair could explain yields no observation when the caller read no recorded pairs, and an over-bound
//! count yields no observation under a bound below `MAX_REGISTRANTS` when the recorded pairs and the own pair
//! account for every listed pair and the count; every other refusal keeps its trigger.
//!
//! Each case is one Report, the own pair, the recorded pairs of a read volume record (`Some`) or of an unread
//! one (`None`), and a bound `N_reg`. The verdict each case requires is written beside it as a literal, taken
//! from the rule's sentences and never from a call of the code under test. The cases are:
//!
//! - the own pair holding beside recorded non-holding registrants passes (the same Report with the holder bit
//!   moved to a recorded pair's entry must refuse, as every refusal below shows);
//! - a holder bit on an entry of a recorded pair refuses `ForeignHolder`, when the own entry also holds and when it
//!   does not, for every size of the recorded set and every recorded pair that could hold, exactly as an unrecorded
//!   holder does, under a read record and under an unread one;
//! - an unrecorded non-holding registrant refuses `ForeignRegistrant` under a read record and `Unreadable` under an
//!   unread one;
//! - an over-bound count is `Excess` or `Unreadable` by the rule of `Bounds::covers_recorded_pairs`;
//! - the refusals the rule leaves alone keep their triggers.

use super::bounds::{Bounds, MAX_REGISTRANTS};
use super::evidence::{NotSole, Pair, Registrant, Report, ReservationType};
use super::identity::{Epoch, Exhid, Incarnation, Key};

/// Bounds with `N_reg` = `registrant_max`; the other bounds are positive and the window exceeds the timing sum.
fn bounds(registrant_max: u32) -> Bounds {
    Bounds::new(registrant_max, 3, 100, 10, 10, 1).expect("premise: the bounds are valid")
}

/// The pair of host `host` under a key of epoch `epoch`.
fn pair(host: u8, epoch: u32) -> Pair {
    let mut bytes = [0u8; 16];
    bytes[15] = host;
    Pair {
        exhid: Exhid::new(bytes).expect("premise: a nonzero host ID"),
        key: Key::new(
            Epoch::new(epoch).expect("premise: a usable epoch"),
            Incarnation::new(u32::from(host)).expect("premise: a usable incarnation"),
        ),
    }
}

/// The own pair: host 1.
fn own() -> Pair {
    pair(1, 5)
}

/// Recorded pair number `n`, from 0: hosts 10, 11, and so on.
fn recorded(n: u8) -> Pair {
    pair(10 + n, 4)
}

/// A pair no volume record of the scenario holds.
fn unrecorded() -> Pair {
    pair(200, 4)
}

fn holds(pair: Pair) -> Registrant {
    Registrant {
        cntlid: 0,
        pair,
        holder: true,
    }
}

fn registered(pair: Pair) -> Registrant {
    Registrant {
        cntlid: 0,
        pair,
        holder: false,
    }
}

/// The entries with controller IDs in entry order, as one controller per entry.
fn numbered(entries: &[Registrant]) -> Vec<Registrant> {
    (1u16..)
        .zip(entries)
        .map(|(cntlid, entry)| Registrant { cntlid, ..*entry })
        .collect()
}

/// One case: a Report of `entries` whose header counts `regctl` registrants, the recorded pairs the caller read,
/// the bound, and the verdict the property requires.
struct Case {
    name: &'static str,
    rtype: ReservationType,
    regctl: u32,
    entries: Vec<Registrant>,
    recorded: Option<Vec<Pair>>,
    registrant_max: u32,
    required: Result<(), NotSole>,
}

impl Case {
    /// A type-2 Report whose header count equals its entries, under `N_reg` = `MAX_REGISTRANTS`.
    fn counted(
        name: &'static str,
        entries: &[Registrant],
        recorded: Option<&[Pair]>,
        required: Result<(), NotSole>,
    ) -> Self {
        Self {
            name,
            rtype: ReservationType::ExclusiveAccess,
            regctl: entries.len() as u32,
            entries: numbered(entries),
            recorded: recorded.map(<[Pair]>::to_vec),
            registrant_max: MAX_REGISTRANTS as u32,
            required,
        }
    }

    fn with_count(mut self, regctl: u32) -> Self {
        self.regctl = regctl;
        self
    }

    fn under(mut self, registrant_max: u32) -> Self {
        self.registrant_max = registrant_max;
        self
    }

    fn of_type(mut self, rtype: ReservationType) -> Self {
        self.rtype = rtype;
        self
    }
}

/// Runs `Report::registrants` over each case and returns one line for each verdict that differs from the required
/// one.
fn judged(cases: &[Case]) -> Vec<String> {
    let mut refused = Vec::new();
    for case in cases {
        let report = Report {
            submitted_at: 7,
            rtype: case.rtype,
            regctl: case.regctl,
            entries: &case.entries,
        };
        let seen = report.registrants(
            own(),
            case.recorded.as_deref(),
            &bounds(case.registrant_max),
        );
        if seen != case.required {
            refused.push(format!(
                "ADMITTED-REGISTRANTS: {}: the verdict is {seen:?}, the property requires {:?}",
                case.name, case.required
            ));
        }
    }
    refused
}

/// The premises the cases rest on: the pairs are distinct, and the bounds mean what the cases take them to mean.
fn premises() {
    let named = [own(), recorded(0), recorded(1), recorded(6), unrecorded()];
    for (at, one) in named.iter().enumerate() {
        for other in &named[at + 1..] {
            assert_ne!(one, other, "premise: the scenario's pairs are distinct");
            assert_ne!(
                one.exhid, other.exhid,
                "premise: the scenario's hosts are distinct"
            );
        }
    }
    assert!(
        bounds(MAX_REGISTRANTS as u32).covers_recorded_pairs(),
        "premise: N_reg = MAX_REGISTRANTS covers the recorded pairs"
    );
    assert!(
        !bounds(2).covers_recorded_pairs(),
        "premise: N_reg = 2 is a bound below MAX_REGISTRANTS"
    );
}

#[test]
fn the_own_pair_holding_beside_recorded_registrants_passes() {
    premises();
    let both = [recorded(0), recorded(1)];
    let with_own = [recorded(0), own(), recorded(1)];
    let cases = [
        Case::counted(
            "the own pair holds alone, nothing recorded",
            &[holds(own())],
            Some(&[]),
            Ok(()),
        ),
        Case::counted(
            "the own pair holds alone, record unread",
            &[holds(own())],
            None,
            Ok(()),
        ),
        Case::counted(
            "the own pair holds beside two recorded non-holding registrants",
            &[
                holds(own()),
                registered(recorded(0)),
                registered(recorded(1)),
            ],
            Some(&both),
            Ok(()),
        ),
        Case::counted(
            "the own pair holds last, after two recorded non-holding registrants",
            &[
                registered(recorded(0)),
                registered(recorded(1)),
                holds(own()),
            ],
            Some(&both),
            Ok(()),
        ),
        Case::counted(
            "the own pair holds beside one of two recorded pairs, the record naming the own pair too",
            &[holds(own()), registered(recorded(1))],
            Some(&with_own),
            Ok(()),
        ),
    ];
    let refused = judged(&cases);
    assert!(refused.is_empty(), "{refused:#?}");
}

#[test]
fn a_recorded_pair_that_holds_refuses_foreign_holder_as_an_unrecorded_holder_does() {
    premises();
    let both = [recorded(0), recorded(1)];
    let foreign = Err(NotSole::ForeignHolder);
    let cases = [
        Case::counted(
            "a recorded pair holds and the own entry holds too",
            &[holds(own()), holds(recorded(0)), registered(recorded(1))],
            Some(&both),
            foreign,
        ),
        Case::counted(
            "a recorded pair holds and the own entry does not",
            &[
                registered(own()),
                holds(recorded(0)),
                registered(recorded(1)),
            ],
            Some(&both),
            foreign,
        ),
        Case::counted(
            "a recorded pair holds and the own entry is absent",
            &[holds(recorded(1)), registered(recorded(0))],
            Some(&both),
            foreign,
        ),
        Case::counted(
            "a recorded pair holds ahead of the own entry, which holds too",
            &[holds(recorded(1)), holds(own())],
            Some(&both),
            foreign,
        ),
        Case::counted(
            "an unrecorded pair holds and the own entry holds too",
            &[holds(own()), holds(unrecorded()), registered(recorded(1))],
            Some(&both),
            foreign,
        ),
        Case::counted(
            "an unrecorded pair holds and the own entry does not",
            &[
                registered(own()),
                holds(unrecorded()),
                registered(recorded(1)),
            ],
            Some(&both),
            foreign,
        ),
        Case::counted(
            "a pair holds beside the own entry, record unread",
            &[holds(own()), holds(recorded(0))],
            None,
            foreign,
        ),
        Case::counted(
            "a pair holds and the own entry does not, record unread",
            &[registered(own()), holds(recorded(0))],
            None,
            foreign,
        ),
        Case::counted(
            "a pair holds beside the own entry, nothing recorded",
            &[holds(own()), holds(recorded(0))],
            Some(&[]),
            foreign,
        ),
    ];
    let refused = judged(&cases);
    assert!(refused.is_empty(), "{refused:#?}");
}

#[test]
fn every_recorded_pair_of_every_record_size_refuses_as_the_holder() {
    premises();
    let mut refused = Vec::new();
    // A record of `size` pairs, the own entry and every recorded pair registered, `MAX_REGISTRANTS` entries at most.
    for size in 1..MAX_REGISTRANTS as u8 {
        let pairs: Vec<Pair> = (0..size).map(recorded).collect();
        for own_holds in [true, false] {
            let own_entry = if own_holds {
                holds(own())
            } else {
                registered(own())
            };
            // Without the fault: no recorded pair holds. It passes when the own entry holds and
            // refuses `NotHolder` when it does not.
            let mut entries = vec![own_entry];
            entries.extend(pairs.iter().copied().map(registered));
            let unfaulted = if own_holds {
                Ok(())
            } else {
                Err(NotSole::NotHolder)
            };
            refused.extend(judged(&[Case::counted(
                "no recorded pair holds",
                &entries,
                Some(&pairs),
                unfaulted,
            )]));
            for holder in 0..usize::from(size) {
                let mut entries = entries.clone();
                entries[1 + holder].holder = true;
                let lines = judged(&[Case::counted(
                    "one recorded pair holds",
                    &entries,
                    Some(&pairs),
                    Err(NotSole::ForeignHolder),
                )]);
                refused.extend(lines.into_iter().map(|line| {
                    format!("{line} (record of {size} pairs, pair {holder} holds, own holds: {own_holds})")
                }));
            }
        }
    }
    assert!(refused.is_empty(), "{refused:#?}");
}

#[test]
fn an_unrecorded_non_holding_registrant_refuses_by_whether_the_record_was_read() {
    premises();
    let both = [recorded(0), recorded(1)];
    let cases = [
        Case::counted(
            "an unrecorded non-holding registrant beside the holding own pair, record read",
            &[
                holds(own()),
                registered(recorded(0)),
                registered(unrecorded()),
            ],
            Some(&both),
            Err(NotSole::ForeignRegistrant),
        ),
        Case::counted(
            "an unrecorded non-holding registrant beside the holding own pair, record unread",
            &[
                holds(own()),
                registered(recorded(0)),
                registered(unrecorded()),
            ],
            None,
            Err(NotSole::Unreadable),
        ),
        Case::counted(
            "a recorded non-holding registrant beside the holding own pair, record unread",
            &[holds(own()), registered(recorded(0))],
            None,
            Err(NotSole::Unreadable),
        ),
        Case::counted(
            "a second registrant beside the holding own pair, nothing recorded",
            &[holds(own()), registered(recorded(0))],
            Some(&[]),
            Err(NotSole::ForeignRegistrant),
        ),
        Case::counted(
            "an unrecorded non-holding registrant and an own entry that does not hold, record read",
            &[registered(own()), registered(unrecorded())],
            Some(&both),
            Err(NotSole::ForeignRegistrant),
        ),
        Case::counted(
            "a non-holding registrant and an own entry that does not hold, record unread",
            &[registered(own()), registered(recorded(0))],
            None,
            Err(NotSole::NotHolder),
        ),
    ];
    let refused = judged(&cases);
    assert!(refused.is_empty(), "{refused:#?}");
}

#[test]
fn an_over_bound_count_is_excess_or_no_observation_by_the_rule_of_the_bound() {
    premises();
    let both = [recorded(0), recorded(1)];
    let with_own = [own(), recorded(0), recorded(1)];
    let three = [
        holds(own()),
        registered(recorded(0)),
        registered(recorded(1)),
    ];
    let nine: Vec<Registrant> = std::iter::once(holds(own()))
        .chain((0..MAX_REGISTRANTS as u8).map(|n| registered(recorded(n))))
        .collect();
    let eight: Vec<Pair> = (0..MAX_REGISTRANTS as u8).map(recorded).collect();
    let cases = [
        // N_reg = MAX_REGISTRANTS: an over-bound count is a second registrant whatever the caller read.
        Case::counted("nine registrants under N_reg 8, every pair recorded", &nine, Some(&eight), Err(NotSole::Excess)),
        Case::counted("nine registrants under N_reg 8, record unread", &nine, None, Err(NotSole::Excess)),
        // N_reg = 2, below MAX_REGISTRANTS.
        Case::counted(
            "three registrants under N_reg 2, the recorded pairs and the own pair account for all three",
            &three,
            Some(&both),
            Err(NotSole::Unreadable),
        )
        .under(2),
        Case::counted(
            "three registrants under N_reg 2, the record naming the own pair too",
            &three,
            Some(&with_own),
            Err(NotSole::Unreadable),
        )
        .under(2),
        Case::counted("three registrants under N_reg 2, record unread", &three, None, Err(NotSole::Unreadable)).under(2),
        Case::counted(
            "three registrants under N_reg 2, one listed pair outside the recorded pairs",
            &three,
            Some(&both[..1]),
            Err(NotSole::Excess),
        )
        .under(2),
        Case::counted(
            "a count of four under N_reg 2, above the recorded pairs and the own pair together",
            &three,
            Some(&both),
            Err(NotSole::Excess),
        )
        .with_count(4)
        .under(2),
        Case::counted(
            "three registrants under N_reg 2, an unrecorded registrant listed",
            &[holds(own()), registered(recorded(0)), registered(unrecorded())],
            Some(&both),
            Err(NotSole::Excess),
        )
        .under(2),
        // The same three registrants within the bound pass, beside the over-bound cases.
        Case::counted("three registrants under N_reg 3", &three, Some(&both), Ok(())).under(3),
    ];
    let refused = judged(&cases);
    assert!(refused.is_empty(), "{refused:#?}");
}

#[test]
fn every_other_refusal_keeps_its_trigger() {
    premises();
    let both = [recorded(0), recorded(1)];
    let rekeyed = Pair {
        exhid: own().exhid,
        key: recorded(0).key,
    };
    let cases = [
        Case::counted(
            "a count other than the entries",
            &[holds(own()), registered(recorded(0))],
            Some(&both),
            Err(NotSole::Unreadable),
        )
        .with_count(3),
        Case::counted(
            "no type-2 reservation",
            &[holds(own()), registered(recorded(0))],
            Some(&both),
            Err(NotSole::ReservationType),
        )
        .of_type(ReservationType::None),
        Case::counted(
            "two entries of the own pair",
            &[holds(own()), registered(own())],
            Some(&both),
            Err(NotSole::DuplicateOwnRecord),
        ),
        Case::counted(
            "the own host ID on a second entry under another key",
            &[holds(own()), registered(rekeyed)],
            Some(&both),
            Err(NotSole::DuplicateOwnRecord),
        ),
        Case::counted(
            "the own entry does not hold beside recorded registrants",
            &[registered(own()), registered(recorded(0))],
            Some(&both),
            Err(NotSole::NotHolder),
        ),
        Case::counted(
            "the own entry is absent and nobody holds",
            &[registered(recorded(0)), registered(recorded(1))],
            Some(&both),
            Err(NotSole::NotHolder),
        ),
        Case::counted("no entry at all", &[], Some(&both), Err(NotSole::NotHolder)),
    ];
    let refused = judged(&cases);
    assert!(refused.is_empty(), "{refused:#?}");
}
