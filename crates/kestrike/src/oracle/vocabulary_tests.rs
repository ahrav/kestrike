//! The tests check history-vocabulary admissibility.

use super::action::ActionKind;
use super::attempt::{FRAGMENT_BYTES, Open, Publication, PutOutcome, Receipt, Serial};
use super::bounds::{
    HISTORY_BOUND, MAX_HOLDERS, MAX_KEYS, MAX_LABELS_PER_KEY, SEARCH_BOUND, SearchBudget,
};
use super::checker::check;
use super::clients::Acceptance;
use super::coverage::Cover;
use super::custody::{Checkpoint, Custodian};
use super::evidence::{Decision, DurableFact, Evidence, Hypothesis, abstract_facts};
use super::history::{Admitted, History, admit, judge};
use super::ids::{
    ClockSample, CutId, Episode, Incarnation, KeyId, Label, OpId, Ordinal, ResourceId,
    ResourceKind, SessionId, Subject, Tenure,
};
use super::obligation::Obligation;
use super::outcome::{Failure, NoInformation, Outcome, OutcomeFamily, VisibilityCause};
use super::row::{Field, Report, ReportKind, ReportState, Row};
use super::tenure::Place;
use super::verdict::{Activations, Inconclusive, Verdict, Violation};

const KEY: KeyId = KeyId(0);
const LABEL: Label = Label(1);
const EPISODE: Episode = Episode(7);
const HYPOTHESIS: Hypothesis = Hypothesis("persisted-before-restart");

fn fill_field(row: &mut Row, field: Field, history: &mut History) {
    match field {
        Field::Key | Field::Subject => row.subject = Some(Subject::Key(KEY)),
        Field::Resource => {
            let kind = if matches!(row.kind, ActionKind::Terminal | ActionKind::WriteSubmit) {
                ResourceKind::Command
            } else {
                ResourceKind::Buffer
            };
            row.subject = Some(Subject::Resource(ResourceId { kind, index: 3 }));
        }
        Field::Label => row.label = Some(LABEL),
        Field::MetadataLength => row.metadata_len = Some(4),
        Field::BodyLength => row.body_len = Some(8),
        Field::Payload => row.payload = Some(vec![0xA5; 12]),
        Field::Session => row.session = Some(SessionId(9)),
        Field::Invocation => row.invoked = Some(history.tick()),
        Field::Response => row.responded = Some(history.tick()),
        Field::CustodyEnd => row.custody_end = Some(history.tick()),
        Field::Outcome => {
            row.outcome = Some(match row.kind.outcome_family() {
                Some(OutcomeFamily::Effect) => Outcome::Acknowledged,
                Some(OutcomeFamily::Lookup) => Outcome::Missing,
                Some(OutcomeFamily::Delivery) => Outcome::Complete,
                Some(OutcomeFamily::Put) => Outcome::Put(PutOutcome::Failed(3)),
                None => Outcome::NoInformation(NoInformation::Contended),
            });
        }
        Field::Clock => row.clock = Some(ClockSample::Seconds(5)),
        Field::Cause => row.cause = Some(VisibilityCause::Eviction),
        Field::Report => {
            row.report = Some(Report {
                kind: ReportKind::Pool,
                state: ReportState::Value(4),
            });
        }
        Field::Fact => row.fact = Some(DurableFact::Binding),
        Field::Episode => row.episode = Some(EPISODE),
        Field::Incarnation => row.incarnation = Some(Incarnation(1)),
        Field::Custodian => row.custodian = Some(Custodian::Storage),
        Field::Checkpoint => row.checkpoint = Some(Checkpoint::Stopped),
        Field::Evidence => row.evidence = Evidence::Abstract(HYPOTHESIS),
        Field::Serial => row.serial = Serial::new(4),
        Field::Fragment => row.fragment = Some(2),
        Field::Receipt => {
            row.receipt = Some(Receipt {
                base: 2,
                mask: 0b10,
            })
        }
        // A READY's grant stays within its one-fragment manifest; an ACK's
        // covers the fixture receipt's mask bit.
        Field::Grant => row.grant = Some(if row.kind == ActionKind::Ready { 1 } else { 6 }),
        Field::Open => row.open = Open::Pending,
        Field::Frozen => row.frozen = Some(7),
        Field::Tenure => row.tenure = Some(Tenure::INITIAL),
        Field::Target => row.target = Some(Place::In(Tenure::INITIAL)),
        Field::Acceptance => {
            row.acceptance = Some(Acceptance {
                high_water: None,
                accepted: true,
            });
        }
        Field::Version => row.version = Some(1),
        Field::Covers => row.covers = Some(Cover::All),
        Field::Cut => row.cut = Some(CutId(1)),
        Field::CapturedUnits => row.captured_units = Some((0, 1)),
        Field::DamagedUnit => row.damaged_unit = Some(0),
    }
}

fn clear_field(row: &mut Row, field: Field) {
    match field {
        Field::Key | Field::Resource | Field::Subject => row.subject = None,
        Field::Label => row.label = None,
        Field::MetadataLength => row.metadata_len = None,
        Field::BodyLength => row.body_len = None,
        Field::Payload => row.payload = None,
        Field::Session => row.session = None,
        Field::Invocation => row.invoked = None,
        Field::Response => row.responded = None,
        Field::CustodyEnd => row.custody_end = None,
        Field::Outcome => row.outcome = None,
        Field::Clock => row.clock = None,
        Field::Cause => row.cause = None,
        Field::Report => row.report = None,
        Field::Fact => row.fact = None,
        Field::Episode => row.episode = None,
        Field::Incarnation => row.incarnation = None,
        Field::Custodian => row.custodian = None,
        Field::Checkpoint => row.checkpoint = None,
        Field::Evidence => row.evidence = Evidence::Live,
        Field::Serial => row.serial = None,
        Field::Fragment => row.fragment = None,
        Field::Receipt => row.receipt = None,
        Field::Grant => row.grant = None,
        Field::Open => row.open = Open::Settled,
        Field::Frozen => row.frozen = None,
        Field::Tenure => row.tenure = None,
        Field::Target => row.target = None,
        Field::Acceptance => row.acceptance = None,
        Field::Version => row.version = None,
        Field::Covers => row.covers = None,
        Field::Cut => row.cut = None,
        Field::CapturedUnits => row.captured_units = None,
        Field::DamagedUnit => row.damaged_unit = None,
    }
}

fn complete(op: u32, kind: ActionKind, history: &mut History) -> Row {
    let mut row = Row::new(OpId(op), kind);
    row.episode = Some(EPISODE);
    for &field in kind.required() {
        fill_field(&mut row, field, history);
    }
    if kind.requires_recovery_evidence() {
        fill_field(&mut row, Field::Evidence, history);
    }
    if kind == ActionKind::Take {
        fill_field(&mut row, Field::Incarnation, history);
    }
    row
}

fn sealed(rows: impl IntoIterator<Item = Row>) -> History {
    let mut history = History::new();
    for row in rows {
        history.push(row);
    }
    history.seal();
    history
}

fn pass_everything(_: Admitted<'_>) -> Verdict {
    let mut activations = Activations::default();
    for obligation in Obligation::ALL {
        activations.activate(obligation);
    }
    Verdict::Pass(activations)
}

#[test]
fn every_kind_admits_a_complete_row_and_names_each_missing_field() {
    for kind in ActionKind::ALL {
        let mut ordinals = History::new();
        let row = complete(1, kind, &mut ordinals);
        assert_eq!(row.malformed_field(), None, "{kind:?}");
        assert!(kind.required().contains(&Field::Response), "{kind:?}");
        for &field in kind.required() {
            let mut gap = row.clone();
            clear_field(&mut gap, field);
            assert_eq!(
                gap.malformed_field(),
                Some(field),
                "{kind:?} without {field:?}"
            );
            let history = sealed([gap]);
            assert_eq!(
                admit(&history).map(|a| a.rows().len()).unwrap_err(),
                Inconclusive::Malformed { op: OpId(1), field },
            );
        }
    }
}

#[test]
fn complete_live_delivery_needs_key_label_lengths_and_terminal_outcome() {
    let mut ordinals = History::new();
    let delivery = complete(2, ActionKind::Deliver, &mut ordinals);
    assert_eq!(delivery.evidence, Evidence::Live);
    assert_eq!(delivery.key(), Some(KEY));
    let history = sealed([delivery.clone()]);
    assert_eq!(admit(&history).map(|a| a.rows().len()), Ok(1));
    for field in [
        Field::Key,
        Field::Label,
        Field::MetadataLength,
        Field::BodyLength,
        Field::Outcome,
    ] {
        let mut gap = delivery.clone();
        clear_field(&mut gap, field);
        let verdict = judge(&sealed([gap]), pass_everything);
        assert_eq!(
            verdict,
            Verdict::Inconclusive(Inconclusive::Malformed { op: OpId(2), field })
        );
        assert!(!verdict.satisfies(&[]));
    }
}

#[test]
fn outcome_outside_the_kind_family_or_a_hit_without_label_is_malformed() {
    let mut ordinals = History::new();
    let mut lookup = complete(3, ActionKind::Lookup, &mut ordinals);
    lookup.outcome = Some(Outcome::Complete);
    assert_eq!(lookup.malformed_field(), Some(Field::Outcome));
    lookup.outcome = Some(Outcome::Hit);
    assert_eq!(lookup.malformed_field(), Some(Field::Label));
    lookup.outcome = Some(Outcome::Expired);
    assert_eq!(lookup.malformed_field(), Some(Field::Label));
    lookup.label = Some(LABEL);
    lookup.clock = Some(ClockSample::Seconds(5));
    assert_eq!(lookup.malformed_field(), None);
    lookup.outcome = Some(Outcome::Hit);
    assert_eq!(lookup.malformed_field(), None);

    let mut delivery = complete(4, ActionKind::Deliver, &mut ordinals);
    for failure in [
        Failure::HeaderMismatch,
        Failure::ChunkMismatch { index: 1 },
        Failure::DeviceError,
        Failure::Short,
        Failure::Quiesced,
        Failure::Lost,
    ] {
        delivery.outcome = Some(Outcome::Damaged(failure));
        assert_eq!(delivery.malformed_field(), None, "{failure:?}");
    }
    delivery.outcome = Some(Outcome::Expired);
    assert_eq!(delivery.malformed_field(), Some(Field::Outcome));
}

#[test]
fn a_lookup_needs_a_whole_second_sample_only_for_a_hit_or_an_expiry() {
    let mut ordinals = History::new();
    let mut unsampled = complete(3, ActionKind::Lookup, &mut ordinals);
    unsampled.clock = None;
    for outcome in [
        Outcome::Missing,
        Outcome::NoInformation(NoInformation::Contended),
        Outcome::NoInformation(NoInformation::Closed),
    ] {
        unsampled.outcome = Some(outcome);
        assert_eq!(unsampled.malformed_field(), None, "{outcome:?}");
        let history = sealed([unsampled.clone()]);
        assert_eq!(
            admit(&history).map(|a| a.rows().len()),
            Ok(1),
            "{outcome:?}"
        );
    }

    let mut decided = unsampled;
    decided.label = Some(LABEL);
    for outcome in [Outcome::Hit, Outcome::Expired] {
        decided.outcome = Some(outcome);
        for clock in [None, Some(ClockSample::Unavailable)] {
            decided.clock = clock;
            assert_eq!(
                decided.malformed_field(),
                Some(Field::Clock),
                "{outcome:?} {clock:?}"
            );
        }
        decided.clock = Some(ClockSample::Seconds(5));
        assert_eq!(decided.malformed_field(), None, "{outcome:?}");
    }
}

#[test]
fn a_clock_unavailable_lookup_names_its_candidate_and_the_failed_sample() {
    let mut ordinals = History::new();
    let mut lookup = complete(3, ActionKind::Lookup, &mut ordinals);
    lookup.outcome = Some(Outcome::NoInformation(NoInformation::ClockUnavailable));
    lookup.label = None;
    lookup.clock = None;
    assert_eq!(lookup.malformed_field(), Some(Field::Label));
    lookup.label = Some(LABEL);
    for clock in [None, Some(ClockSample::Seconds(5))] {
        lookup.clock = clock;
        assert_eq!(lookup.malformed_field(), Some(Field::Clock), "{clock:?}");
    }
    lookup.clock = Some(ClockSample::Unavailable);
    assert_eq!(lookup.malformed_field(), None);
    assert_eq!(admit(&sealed([lookup])).map(|a| a.rows().len()), Ok(1));

    let mut publish = complete(4, ActionKind::Publish, &mut ordinals);
    publish.outcome = Some(Outcome::NoInformation(NoInformation::ClockUnavailable));
    assert_eq!(publish.malformed_field(), Some(Field::Clock));
    publish.clock = Some(ClockSample::Unavailable);
    assert_eq!(publish.malformed_field(), None);
}

#[test]
fn an_expiry_needs_a_whole_second_sample() {
    let mut ordinals = History::new();
    let mut expiry = complete(3, ActionKind::Expire, &mut ordinals);
    assert_eq!(expiry.malformed_field(), None);
    for clock in [None, Some(ClockSample::Unavailable)] {
        expiry.clock = clock;
        assert_eq!(expiry.malformed_field(), Some(Field::Clock), "{clock:?}");
        assert_eq!(
            admit(&sealed([expiry.clone()])).map(|a| a.rows().len()),
            Err(Inconclusive::Malformed {
                op: OpId(3),
                field: Field::Clock,
            }),
            "{clock:?}"
        );
    }
}

#[test]
fn a_terminal_carries_the_real_result_or_a_drop() {
    let mut ordinals = History::new();
    let mut terminal = complete(4, ActionKind::Terminal, &mut ordinals);
    for outcome in [
        Outcome::Complete,
        Outcome::Damaged(Failure::DeviceError),
        Outcome::NoInformation(NoInformation::Dropped),
    ] {
        terminal.outcome = Some(outcome);
        assert_eq!(terminal.malformed_field(), None, "{outcome:?}");
    }
    for member in NoInformation::ALL {
        if member == NoInformation::Dropped {
            continue;
        }
        terminal.outcome = Some(Outcome::NoInformation(member));
        assert_eq!(
            terminal.malformed_field(),
            Some(Field::Outcome),
            "{member:?}"
        );
    }
    let mut delivery = complete(5, ActionKind::Deliver, &mut ordinals);
    for member in [NoInformation::Cancelled, NoInformation::TimedOut] {
        delivery.outcome = Some(Outcome::NoInformation(member));
        assert_eq!(delivery.malformed_field(), None, "{member:?}");
    }
}

#[test]
fn a_release_of_an_incarnated_resource_names_the_incarnation() {
    let mut ordinals = History::new();
    let key_release = complete(6, ActionKind::Release, &mut ordinals);
    assert_eq!(key_release.incarnation, None);
    assert_eq!(key_release.malformed_field(), None);
    for kind in ResourceKind::ALL {
        let mut release = key_release.clone();
        release.subject = Some(Subject::Resource(ResourceId { kind, index: 0 }));
        if kind == ResourceKind::Command {
            release.custodian = Some(Custodian::Storage);
            release.incarnation = Some(Incarnation(2));
            assert_eq!(release.malformed_field(), Some(Field::Resource), "{kind:?}");
            continue;
        }
        let first = if kind.incarnated() {
            Field::Incarnation
        } else {
            Field::Custodian
        };
        assert_eq!(release.malformed_field(), Some(first), "{kind:?}");
        release.custodian = Some(if kind.client_buffer() {
            Custodian::Nic
        } else {
            Custodian::Storage
        });
        let expected = kind.incarnated().then_some(Field::Incarnation);
        assert_eq!(release.malformed_field(), expected, "{kind:?}");
        release.incarnation = Some(Incarnation(2));
        let expected = (!kind.incarnated()).then_some(Field::Incarnation);
        assert_eq!(release.malformed_field(), expected, "{kind:?}");
    }
    let incarnated: Vec<ResourceKind> = ResourceKind::ALL
        .into_iter()
        .filter(|kind| kind.incarnated())
        .collect();
    assert_eq!(
        incarnated,
        [
            ResourceKind::Extent,
            ResourceKind::Slot,
            ResourceKind::Buffer,
            ResourceKind::Command,
            ResourceKind::SourceSlot,
            ResourceKind::WriteQuota,
        ]
    );
}

#[test]
fn no_information_outcomes_fit_every_outcome_kind_and_carry_nothing() {
    for member in NoInformation::ALL {
        let outcome = Outcome::NoInformation(member);
        assert!(!outcome.carries_information(), "{member:?}");
        assert_eq!(outcome.family(), None);
        for kind in ActionKind::ALL {
            if kind.outcome_family().is_none()
                || kind == ActionKind::Terminal
                || kind.is_remote_put()
                || member == NoInformation::ClockUnavailable
            {
                continue;
            }
            let mut ordinals = History::new();
            let mut row = complete(5, kind, &mut ordinals);
            row.outcome = Some(outcome);
            assert_eq!(row.malformed_field(), None, "{kind:?} {member:?}");
        }
    }
    for outcome in [
        Outcome::Acknowledged,
        Outcome::Hit,
        Outcome::Missing,
        Outcome::Expired,
        Outcome::Complete,
    ] {
        assert!(outcome.carries_information(), "{outcome:?}");
    }
}

#[test]
fn write_completion_alone_adds_no_durable_fact() {
    let mut history = History::new();
    let fill = complete(1, ActionKind::Fill, &mut history);
    let receive = complete(1, ActionKind::Receive, &mut history);
    let written = complete(1, ActionKind::WriteCompleted, &mut history);
    let mut abstract_written = complete(1, ActionKind::WriteCompleted, &mut history);
    abstract_written.evidence = Evidence::Abstract(HYPOTHESIS);
    abstract_written.fact = Some(DurableFact::Payload);
    assert_eq!(abstract_written.malformed_field(), Some(Field::Fact));
    assert!(abstract_facts([&abstract_written]).is_empty());
    let rows = [fill, receive, written];
    assert!(abstract_facts(&rows).is_empty());
    let history = sealed(rows);
    assert_eq!(admit(&history).map(|a| a.rows().len()), Ok(3));
    assert!(abstract_facts(history.rows()).is_empty());
}

#[test]
fn abstract_persistence_rows_are_the_only_abstract_facts() {
    let mut ordinals = History::new();
    for fact in DurableFact::ALL {
        let mut row = complete(6, ActionKind::Persistence, &mut ordinals);
        row.fact = Some(fact);
        let facts = abstract_facts([&row]);
        assert_eq!(facts.len(), 1);
        assert!(facts.contains(&(HYPOTHESIS, EPISODE, KEY, LABEL, fact)));

        let mut other_episode = row.clone();
        other_episode.episode = Some(Episode(EPISODE.0 + 1));
        let two = abstract_facts([&row, &other_episode]);
        assert_eq!(two.len(), 2);
        assert!(two.contains(&(HYPOTHESIS, Episode(EPISODE.0 + 1), KEY, LABEL, fact)));

        let mut live = row.clone();
        live.evidence = Evidence::Live;
        assert!(abstract_facts([&live]).is_empty());
        assert_eq!(live.malformed_field(), Some(Field::Evidence));
    }
}

#[test]
fn abstract_rows_stay_out_of_the_live_summary() {
    let mut history = History::new();
    let lookup = complete(1, ActionKind::Lookup, &mut history);
    let restart = complete(2, ActionKind::Restart, &mut history);
    let admission = complete(3, ActionKind::Admission, &mut history);
    history.push(lookup);
    history.push(restart);
    history.push(admission);
    history.seal();
    let admitted = admit(&history).unwrap();
    let live: Vec<OpId> = admitted.live().map(|row| row.op).collect();
    assert_eq!(live, [OpId(1)]);
    assert_eq!(admitted.rows().len(), 3);
}

#[test]
fn a_row_on_an_open_decision_is_inconclusive_naming_it() {
    for decision in Decision::ALL {
        let mut history = History::new();
        let before = complete(7, ActionKind::Lookup, &mut history);
        let mut row = complete(8, ActionKind::Lookup, &mut history);
        row.unresolved = Some(decision);
        let after = complete(9, ActionKind::Evict, &mut history);
        history.push(before);
        history.push(row);
        history.push(after);
        history.seal();
        let verdict = judge(&history, pass_everything);
        assert_eq!(
            verdict,
            Verdict::Inconclusive(Inconclusive::Unresolved {
                op: OpId(8),
                decision,
            })
        );
        let violation = judge(&history, |admitted| {
            Verdict::Violation(Violation {
                obligation: Obligation::Restart,
                op: admitted.rows()[1].op,
                rule: "fresh acquisition after exclusion",
            })
        });
        assert_eq!(violation, verdict);
    }
}

#[test]
fn one_row_past_the_history_bound_is_inconclusive_naming_the_bound() {
    let mut at_bound = History::new();
    for op in 0..HISTORY_BOUND as u32 {
        let row = complete(op, ActionKind::Evict, &mut at_bound);
        at_bound.push(row);
    }
    at_bound.seal();
    assert_eq!(admit(&at_bound).map(|a| a.rows().len()), Ok(HISTORY_BOUND));

    let mut past = at_bound.clone();
    let row = complete(HISTORY_BOUND as u32, ActionKind::Evict, &mut past);
    past.push(row);
    past.seal();
    assert_eq!(
        judge(&past, pass_everything),
        Verdict::Inconclusive(Inconclusive::HistoryBound {
            limit: HISTORY_BOUND,
            rows: HISTORY_BOUND + 1,
        })
    );
}

#[test]
fn a_zero_search_budget_is_inconclusive_naming_the_search_bound() {
    let mut zero = SearchBudget::new(0);
    assert_eq!(zero.expand(), Err(Inconclusive::SearchBound { limit: 0 }));
    assert_eq!(zero.high_water(), 0);

    let mut per_key = SearchBudget::per_key();
    for _ in 0..SEARCH_BOUND {
        assert_eq!(per_key.expand(), Ok(()));
    }
    assert_eq!(per_key.high_water(), SEARCH_BOUND);
    assert_eq!(
        per_key.expand(),
        Err(Inconclusive::SearchBound {
            limit: SEARCH_BOUND
        })
    );
    assert_eq!((MAX_KEYS, MAX_LABELS_PER_KEY, MAX_HOLDERS), (2, 2, 2));
}

#[test]
fn an_unsealed_stream_is_truncated() {
    let mut history = History::new();
    let row = complete(1, ActionKind::Lookup, &mut history);
    history.push(row);
    assert_eq!(
        judge(&history, pass_everything),
        Verdict::Inconclusive(Inconclusive::Truncated)
    );
    assert_eq!(
        judge(&History::new(), pass_everything),
        Verdict::Inconclusive(Inconclusive::Truncated)
    );
}

fn measured(report: ReportKind) -> ResourceKind {
    match report {
        ReportKind::Pool | ReportKind::Mismatched => ResourceKind::Buffer,
        ReportKind::Table => ResourceKind::Command,
        ReportKind::Ledger => ResourceKind::Slot,
        ReportKind::EngineBudget => ResourceKind::BudgetCharge,
        ReportKind::RequestShares => ResourceKind::RequestShare,
        ReportKind::RetainedChunks => ResourceKind::RetainedChunk,
        ReportKind::WriteProgress => ResourceKind::WriteQuota,
    }
}

#[test]
fn a_poisoned_or_absent_report_is_inconclusive_naming_it() {
    let kinds = [
        ReportKind::Pool,
        ReportKind::Table,
        ReportKind::Ledger,
        ReportKind::EngineBudget,
        ReportKind::RequestShares,
        ReportKind::RetainedChunks,
        ReportKind::WriteProgress,
        ReportKind::Mismatched,
    ];
    for kind in kinds {
        let poisoned = Inconclusive::PoisonedReport {
            op: OpId(4),
            report: kind,
        };
        let absent = Inconclusive::AbsentReport {
            op: OpId(4),
            report: kind,
        };
        for (state, expected) in [
            (ReportState::Poisoned, poisoned),
            (ReportState::Absent, absent),
        ] {
            let mut history = History::new();
            let before = complete(3, ActionKind::Lookup, &mut history);
            let mut row = complete(4, ActionKind::Report, &mut history);
            row.report = Some(Report { kind, state });
            row.subject = Some(Subject::Resource(ResourceId {
                kind: measured(kind),
                index: 0,
            }));
            history.push(before);
            history.push(row);
            history.seal();
            assert_eq!(
                judge(&history, pass_everything),
                Verdict::Inconclusive(expected)
            );
        }
    }
}

#[test]
fn ordinals_come_from_one_counter_in_invocation_response_custody_order() {
    let mut history = History::new();
    let delivery = complete(1, ActionKind::Deliver, &mut history);
    let ordinals: Vec<_> = delivery.ordinals().map(|(_, o)| o).collect();
    assert_eq!(ordinals.len(), 3);
    assert!(ordinals.windows(2).all(|pair| pair[0] < pair[1]));

    let mut early = delivery.clone();
    early.invoked = Some(Ordinal(1));
    early.responded = Some(Ordinal(0));
    assert_eq!(early.malformed_field(), Some(Field::Response));

    let mut same = delivery.clone();
    same.custody_end = same.responded;
    assert_eq!(same.malformed_field(), Some(Field::CustodyEnd));

    let mut twin = complete(2, ActionKind::Evict, &mut History::new());
    twin.responded = delivery.invoked;
    let shared = sealed([delivery, twin]);
    assert_eq!(
        admit(&shared).map(|a| a.rows().len()),
        Err(Inconclusive::Malformed {
            op: OpId(2),
            field: Field::Response,
        })
    );
}

#[test]
fn only_pass_with_every_declared_obligation_active_satisfies_a_gate() {
    let mut activations = Activations::default();
    activations.activate(Obligation::History);
    let pass = Verdict::Pass(activations);
    assert!(pass.satisfies(&[Obligation::History]));
    assert!(!pass.satisfies(&[Obligation::History, Obligation::Bytes]));
    assert!(!pass.satisfies(&[]));
    assert!(!Verdict::Pass(Activations::default()).satisfies(&[]));
    assert_eq!(activations.count(Obligation::Bytes), 0);
    let violation = Verdict::Violation(Violation {
        obligation: Obligation::History,
        op: OpId(1),
        rule: "fresh acquisition of an invalidated label",
    });
    assert!(!violation.satisfies(&[]));
    assert!(!Verdict::Inconclusive(Inconclusive::Truncated).satisfies(&[]));
}

#[test]
fn rows_name_resources_incarnations_and_visibility_causes() {
    let resources: Vec<_> = ResourceKind::ALL
        .into_iter()
        .map(|kind| ResourceId { kind, index: 0 })
        .collect();
    let mut ordinals = History::new();
    let mut release = complete(1, ActionKind::Release, &mut ordinals);
    release.subject = Some(Subject::Resource(resources[2]));
    release.incarnation = Some(Incarnation(2));
    release.custodian = Some(Custodian::Nic);
    release.clock = Some(ClockSample::Unavailable);
    assert_eq!(release.malformed_field(), None);
    assert_eq!(release.resource(), Some(resources[2]));
    assert_eq!(release.key(), None);
    for cause in VisibilityCause::ALL {
        let mut ended = complete(2, ActionKind::VisibilityEnded, &mut ordinals);
        ended.cause = Some(cause);
        assert_eq!(ended.malformed_field(), None, "{cause:?}");
    }
}

#[test]
fn pushing_after_seal_reopens_the_stream() {
    let mut history = History::new();
    let row = complete(1, ActionKind::Evict, &mut history);
    history.push(row);
    history.seal();
    assert!(admit(&history).is_ok());
    let more = complete(2, ActionKind::Evict, &mut history);
    history.push(more);
    assert_eq!(
        admit(&history).map(|a| a.rows().len()),
        Err(Inconclusive::Truncated)
    );
}

#[test]
fn informative_outcomes_on_kinds_without_an_outcome_family_are_malformed() {
    let mut ordinals = History::new();
    for kind in ActionKind::ALL {
        if kind.outcome_family().is_some() {
            continue;
        }
        let mut row = complete(1, kind, &mut ordinals);
        row.outcome = Some(Outcome::Acknowledged);
        assert_eq!(row.malformed_field(), Some(Field::Outcome), "{kind:?}");
        row.outcome = Some(Outcome::NoInformation(NoInformation::Cancelled));
        if kind == ActionKind::Receive {
            assert_eq!(row.malformed_field(), Some(Field::Payload), "{kind:?}");
            row.payload = Some(Vec::new());
        }
        let field = kind.is_remote_put().then_some(Field::Outcome);
        assert_eq!(row.malformed_field(), field, "{kind:?}");
    }
}

#[test]
fn required_fields_match_the_vocabulary_table() {
    use super::row::Field::{
        BodyLength, Cause, Clock, CustodyEnd, Episode, Fact, Incarnation, Invocation, Key,
        MetadataLength, Payload, Report, Resource, Response, Session,
    };
    let label = Field::Label;
    let outcome = Field::Outcome;
    let subject = Field::Subject;
    let expected: [(ActionKind, &[Field]); 35] = [
        (
            ActionKind::Fill,
            &[
                Key,
                label,
                MetadataLength,
                BodyLength,
                Session,
                Incarnation,
                Invocation,
                Response,
                outcome,
                Episode,
            ],
        ),
        (
            ActionKind::Receive,
            &[Key, label, Invocation, Response, Payload, Episode],
        ),
        (ActionKind::WriteCompleted, &[Key, label, Response, Episode]),
        (
            ActionKind::Publish,
            &[Key, label, Invocation, Response, outcome, Episode],
        ),
        (
            ActionKind::Replace,
            &[Key, label, Invocation, Response, outcome, Episode],
        ),
        (
            ActionKind::Lookup,
            &[Key, Invocation, Response, outcome, Episode],
        ),
        (
            ActionKind::Deliver,
            &[
                Key,
                label,
                MetadataLength,
                BodyLength,
                Session,
                Incarnation,
                Invocation,
                Response,
                CustodyEnd,
                outcome,
                Payload,
                Episode,
            ],
        ),
        (
            ActionKind::Terminal,
            &[Resource, Incarnation, Response, outcome, Episode],
        ),
        (
            ActionKind::Invalidate,
            &[Key, Invocation, Response, outcome, Episode],
        ),
        (ActionKind::Expire, &[Key, label, Clock, Response, Episode]),
        (ActionKind::Evict, &[Key, label, Response, Episode]),
        (
            ActionKind::Cancel,
            &[Resource, Incarnation, Invocation, Response, Episode],
        ),
        (ActionKind::Pressure, &[Resource, Response, Episode]),
        (ActionKind::SessionChange, &[Session, Response, Episode]),
        (ActionKind::Close, &[Invocation, Response, outcome, Episode]),
        (ActionKind::Release, &[subject, Response, Episode]),
        (
            ActionKind::VisibilityEnded,
            &[Key, label, Cause, Response, Episode],
        ),
        (ActionKind::Report, &[Resource, Report, Response, Episode]),
        (
            ActionKind::Persistence,
            &[Key, label, Fact, Response, Episode],
        ),
        (ActionKind::Admission, &[Key, label, Response, Episode]),
        (ActionKind::Restart, &[Response, Episode]),
        (
            ActionKind::Take,
            &[Resource, Field::Custodian, Response, Episode],
        ),
        (
            ActionKind::Checkpoint,
            &[Field::Checkpoint, Response, Episode],
        ),
        (
            ActionKind::PutBegin,
            &[
                Key,
                label,
                MetadataLength,
                BodyLength,
                Invocation,
                Response,
                Episode,
            ],
        ),
        (
            ActionKind::Authority,
            &[Key, Field::Serial, Response, Episode],
        ),
        (
            ActionKind::Ready,
            &[
                Key,
                label,
                MetadataLength,
                BodyLength,
                Field::Serial,
                Field::Grant,
                Response,
                Episode,
            ],
        ),
        (
            ActionKind::Fragment,
            &[
                Key,
                Field::Serial,
                Field::Fragment,
                Payload,
                Response,
                Episode,
            ],
        ),
        (
            ActionKind::Ack,
            &[
                Key,
                Field::Serial,
                Field::Receipt,
                Field::Grant,
                Response,
                Episode,
            ],
        ),
        (
            ActionKind::WriteSubmit,
            &[
                Resource,
                Incarnation,
                Field::Serial,
                Invocation,
                Response,
                Episode,
            ],
        ),
        (ActionKind::PutResult, &[Key, Response, outcome, Episode]),
        (
            ActionKind::Retry,
            &[Key, Invocation, Response, outcome, Episode],
        ),
        (ActionKind::Abandon, &[Key, Response, Episode]),
        (
            ActionKind::Restore,
            &[Key, label, Field::Cut, Response, Episode],
        ),
        (
            ActionKind::Captured,
            &[
                Key,
                label,
                Field::Cut,
                Field::CapturedUnits,
                Response,
                Episode,
            ],
        ),
        (ActionKind::Damaged, &[Response, Episode]),
    ];
    for (kind, fields) in expected {
        assert_eq!(kind.required(), fields, "{kind:?}");
    }
    let kinds: Vec<ActionKind> = expected.iter().map(|&(kind, _)| kind).collect();
    assert_eq!(kinds, ActionKind::ALL);
}

#[test]
fn every_all_array_lists_each_variant_once() {
    fn distinct<T: PartialEq + std::fmt::Debug>(all: &[T], index: impl Fn(&T) -> usize) {
        for (position, item) in all.iter().enumerate() {
            assert_eq!(index(item), position, "{item:?}");
        }
    }
    distinct(&ActionKind::ALL, |k| match k {
        ActionKind::Fill => 0,
        ActionKind::Receive => 1,
        ActionKind::WriteCompleted => 2,
        ActionKind::Publish => 3,
        ActionKind::Replace => 4,
        ActionKind::Lookup => 5,
        ActionKind::Deliver => 6,
        ActionKind::Terminal => 7,
        ActionKind::Invalidate => 8,
        ActionKind::Expire => 9,
        ActionKind::Evict => 10,
        ActionKind::Cancel => 11,
        ActionKind::Pressure => 12,
        ActionKind::SessionChange => 13,
        ActionKind::Close => 14,
        ActionKind::Release => 15,
        ActionKind::VisibilityEnded => 16,
        ActionKind::Report => 17,
        ActionKind::Persistence => 18,
        ActionKind::Admission => 19,
        ActionKind::Restart => 20,
        ActionKind::Take => 21,
        ActionKind::Checkpoint => 22,
        ActionKind::PutBegin => 23,
        ActionKind::Authority => 24,
        ActionKind::Ready => 25,
        ActionKind::Fragment => 26,
        ActionKind::Ack => 27,
        ActionKind::WriteSubmit => 28,
        ActionKind::PutResult => 29,
        ActionKind::Retry => 30,
        ActionKind::Abandon => 31,
        ActionKind::Restore => 32,
        ActionKind::Captured => 33,
        ActionKind::Damaged => 34,
    });
    distinct(&NoInformation::ALL, |n| match n {
        NoInformation::Contended => 0,
        NoInformation::Closed => 1,
        NoInformation::ClockUnavailable => 2,
        NoInformation::LeaseLimit => 3,
        NoInformation::RetainLimit => 4,
        NoInformation::Refused => 5,
        NoInformation::Cancelled => 6,
        NoInformation::TimedOut => 7,
        NoInformation::Dropped => 8,
    });
    distinct(&Decision::ALL, |d| match d {
        Decision::CallerFreshness => 0,
        Decision::DurableBeforeExclusion => 1,
        Decision::ReserveExhaustion => 2,
    });
    distinct(&DurableFact::ALL, |f| match f {
        DurableFact::Binding => 0,
        DurableFact::Payload => 1,
        DurableFact::Identity => 2,
        DurableFact::Ownership => 3,
        DurableFact::Freshness => 4,
        DurableFact::PortableExpiry => 5,
        DurableFact::ServingAuthority => 6,
        DurableFact::InvalidationReplayed => 7,
        DurableFact::RecoveryExclusion => 8,
    });
    distinct(&ResourceKind::ALL, |r| match r {
        ResourceKind::Extent => 0,
        ResourceKind::Slot => 1,
        ResourceKind::Buffer => 2,
        ResourceKind::Command => 3,
        ResourceKind::Credit => 4,
        ResourceKind::BudgetCharge => 5,
        ResourceKind::RequestShare => 6,
        ResourceKind::RetainedChunk => 7,
        ResourceKind::SourceSlot => 8,
        ResourceKind::WriteQuota => 9,
    });
    distinct(&VisibilityCause::ALL, |c| match c {
        VisibilityCause::CollisionCollateral => 0,
        VisibilityCause::Eviction => 1,
        VisibilityCause::Expiry => 2,
        VisibilityCause::GraceEnd => 3,
    });
    distinct(&Obligation::ALL, |o| match o {
        Obligation::Bytes => 0,
        Obligation::History => 1,
        Obligation::Custody => 2,
        Obligation::Resources => 3,
        Obligation::Restart => 4,
        Obligation::Progress => 5,
        Obligation::Isolation => 6,
        Obligation::Contain => 7,
    });
}

#[test]
fn a_durable_fact_on_any_kind_but_persistence_is_malformed() {
    let mut ordinals = History::new();
    for kind in ActionKind::ALL {
        let mut row = complete(1, kind, &mut ordinals);
        row.fact = Some(DurableFact::Payload);
        let expected = (kind != ActionKind::Persistence).then_some(Field::Fact);
        assert_eq!(row.malformed_field(), expected, "{kind:?}");
    }
}

mod remote_put {
    use super::{
        ActionKind, Custodian, Episode, FRAGMENT_BYTES, Field, History, Incarnation, Inconclusive,
        KeyId, Label, NoInformation, Obligation, OpId, Open, Outcome, Publication, PutOutcome,
        Receipt, ResourceId, ResourceKind, Row, Serial, SessionId, Subject, abstract_facts, admit,
        check, complete, fill_field, sealed,
    };

    const KEY: KeyId = KeyId(0);
    const LABEL: Label = Label(3);
    const ATTEMPT: OpId = OpId(1);
    const SERIAL: Option<Serial> = Serial::new(7);
    const METADATA: u32 = 16;
    const BODY: u64 = 8176;
    const COMMAND: ResourceId = ResourceId {
        kind: ResourceKind::Command,
        index: 2,
    };
    const SOURCE: ResourceId = ResourceId {
        kind: ResourceKind::SourceSlot,
        index: 0,
    };

    fn fragments() -> u32 {
        (u64::from(METADATA) + BODY).div_ceil(FRAGMENT_BYTES as u64) as u32
    }

    struct Attempt {
        history: History,
    }

    impl Attempt {
        fn new() -> Self {
            Self {
                history: History::new(),
            }
        }

        fn row(kind: ActionKind, subject: Subject) -> Row {
            let mut row = Row::new(ATTEMPT, kind);
            row.subject = Some(subject);
            row.episode = Some(Episode(4));
            row
        }

        fn keyed(kind: ActionKind) -> Row {
            Self::row(kind, Subject::Key(KEY))
        }

        fn at_once(&mut self, mut row: Row) -> Row {
            row.responded = Some(self.history.tick());
            row
        }

        fn span(&mut self, mut row: Row) -> Row {
            row.invoked = Some(self.history.tick());
            row.responded = Some(self.history.tick());
            row
        }

        fn begin(&mut self, open: Open) -> Row {
            let mut row = Self::keyed(ActionKind::PutBegin);
            row.label = Some(LABEL);
            row.metadata_len = Some(METADATA);
            row.body_len = Some(BODY);
            row.open = open;
            self.span(row)
        }

        fn authority(&mut self) -> Row {
            let mut row = Self::keyed(ActionKind::Authority);
            row.serial = SERIAL;
            self.at_once(row)
        }

        fn ready(&mut self) -> Row {
            let mut row = Self::keyed(ActionKind::Ready);
            row.label = Some(LABEL);
            row.metadata_len = Some(METADATA);
            row.body_len = Some(BODY);
            row.serial = SERIAL;
            row.grant = Some(fragments());
            self.at_once(row)
        }

        fn source(&mut self, kind: ActionKind, custodian: Custodian) -> Row {
            let mut row = Self::row(kind, Subject::Resource(SOURCE));
            row.custodian = Some(custodian);
            row.incarnation = Some(Incarnation(1));
            row.fragment = Some(0);
            self.at_once(row)
        }

        fn fragment(&mut self) -> Row {
            let mut row = Self::keyed(ActionKind::Fragment);
            row.serial = SERIAL;
            row.fragment = Some(0);
            row.payload = Some(vec![0x5A; FRAGMENT_BYTES]);
            self.at_once(row)
        }

        fn ack(&mut self, base: u32) -> Row {
            let mut row = Self::keyed(ActionKind::Ack);
            row.serial = SERIAL;
            row.receipt = Some(Receipt { base, mask: 0 });
            row.grant = Some(base.max(fragments()));
            self.at_once(row)
        }

        fn write_submit(&mut self) -> Row {
            let mut row = Self::row(ActionKind::WriteSubmit, Subject::Resource(COMMAND));
            row.incarnation = Some(Incarnation(5));
            row.serial = SERIAL;
            self.span(row)
        }

        fn terminal(&mut self) -> Row {
            let mut row = Self::row(ActionKind::Terminal, Subject::Resource(COMMAND));
            row.incarnation = Some(Incarnation(5));
            row.outcome = Some(Outcome::Complete);
            self.at_once(row)
        }

        fn publish(&mut self) -> Row {
            let mut row = Self::keyed(ActionKind::Publish);
            row.label = Some(LABEL);
            row.serial = SERIAL;
            row.outcome = Some(Outcome::Acknowledged);
            self.span(row)
        }

        fn retry(&mut self, outcome: Outcome) -> Row {
            let mut row = Self::keyed(ActionKind::Retry);
            row.serial = SERIAL;
            row.outcome = Some(outcome);
            self.span(row)
        }

        fn result(&mut self, outcome: PutOutcome) -> Row {
            let mut row = Self::keyed(ActionKind::PutResult);
            row.outcome = Some(Outcome::Put(outcome));
            match outcome {
                PutOutcome::Published => {
                    row.label = Some(LABEL);
                    row.serial = SERIAL;
                }
                PutOutcome::Unknown => {
                    row.serial = SERIAL;
                    row.open = Open::Publication;
                }
                PutOutcome::Failed(_) | PutOutcome::NotStarted => {}
            }
            self.at_once(row)
        }
    }

    fn published_upload() -> Vec<Row> {
        let mut a = Attempt::new();
        vec![
            a.begin(Open::Settled),
            a.authority(),
            a.ready(),
            a.source(ActionKind::Take, Custodian::Retransmission),
            a.source(ActionKind::Take, Custodian::Nic),
            a.fragment(),
            a.ack(fragments()),
            a.source(ActionKind::Release, Custodian::Retransmission),
            a.source(ActionKind::Release, Custodian::Nic),
            a.write_submit(),
            a.terminal(),
            a.publish(),
            a.result(PutOutcome::Published),
        ]
    }

    #[test]
    fn an_upload_round_trips_with_each_fact_in_its_own_field() {
        let rows = published_upload();
        let history = sealed(rows.clone());
        let admitted = admit(&history).unwrap();
        assert_eq!(admitted.rows(), rows.as_slice());
        assert!(rows.iter().all(|row| row.op == ATTEMPT));
        let kinds_with = |has: fn(&Row) -> bool| -> Vec<ActionKind> {
            rows.iter().filter(|r| has(r)).map(|r| r.kind).collect()
        };
        assert_eq!(
            kinds_with(|r| matches!(r.outcome, Some(Outcome::Put(_)))),
            [ActionKind::PutResult]
        );
        assert_eq!(kinds_with(|r| r.receipt.is_some()), [ActionKind::Ack]);
        assert_eq!(
            kinds_with(|r| r.grant.is_some()),
            [ActionKind::Ready, ActionKind::Ack]
        );
        assert_eq!(
            kinds_with(|r| r.serial.is_some()),
            [
                ActionKind::Authority,
                ActionKind::Ready,
                ActionKind::Fragment,
                ActionKind::Ack,
                ActionKind::WriteSubmit,
                ActionKind::Publish,
                ActionKind::PutResult,
            ]
        );
        let custody: Vec<(ActionKind, Option<Custodian>)> = rows
            .iter()
            .filter(|r| r.resource() == Some(SOURCE))
            .map(|r| (r.kind, r.custodian))
            .collect();
        assert_eq!(
            custody,
            [
                (ActionKind::Take, Some(Custodian::Retransmission)),
                (ActionKind::Take, Some(Custodian::Nic)),
                (ActionKind::Release, Some(Custodian::Retransmission)),
                (ActionKind::Release, Some(Custodian::Nic)),
            ]
        );
        let published: Vec<Publication> = rows.iter().filter_map(Row::publication).collect();
        assert_eq!(published, [Publication::Certain]);
    }

    #[test]
    fn a_pending_or_unknown_attempt_keeps_both_owner_outcomes() {
        let mut a = Attempt::new();
        let pending = a.begin(Open::Pending);
        assert_eq!(pending.malformed_field(), None);
        assert_eq!(pending.outcome, None);
        assert!(pending.open.terminal() && pending.open.publication());
        assert_eq!(pending.publication(), Some(Publication::Open));
        let unknown = a.result(PutOutcome::Unknown);
        assert_eq!(unknown.malformed_field(), None);
        assert_eq!(unknown.label, None);
        assert!(!unknown.open.terminal() && unknown.open.publication());
        assert_eq!(unknown.publication(), Some(Publication::Open));
        assert!(!Outcome::Put(PutOutcome::Unknown).carries_information());

        for published in [false, true] {
            let mut b = Attempt::new();
            let mut rows = vec![b.begin(Open::Pending), b.authority()];
            if published {
                rows.push(b.publish());
            }
            let history = sealed(rows);
            assert!(admit(&history).is_ok(), "published {published}");
            assert_eq!(history.rows()[0].publication(), Some(Publication::Open));
            let mut c = Attempt::new();
            let mut rows = vec![c.begin(Open::Settled), c.authority()];
            if published {
                rows.push(c.publish());
            }
            rows.push(c.result(PutOutcome::Unknown));
            let history = sealed(rows);
            assert!(admit(&history).is_ok(), "published {published}");
            let last = history.rows().last().unwrap();
            assert_eq!(last.publication(), Some(Publication::Open));
        }

        let mut d = Attempt::new();
        let mut claimed = d.result(PutOutcome::Unknown);
        for open in [Open::Settled, Open::Pending] {
            claimed.open = open;
            assert_eq!(claimed.malformed_field(), Some(Field::Open), "{open:?}");
        }
        let mut half = d.begin(Open::Publication);
        assert_eq!(half.malformed_field(), Some(Field::Open));
        half.open = Open::Settled;
        assert_eq!(half.malformed_field(), None);
        assert_eq!(half.publication(), None);
    }

    #[test]
    fn a_pending_begin_with_a_result_or_abandonment_misstates_the_cut() {
        for last in [ActionKind::PutResult, ActionKind::Abandon] {
            let mut a = Attempt::new();
            let begin = a.begin(Open::Pending);
            let end = if last == ActionKind::PutResult {
                vec![a.result(PutOutcome::Failed(25))]
            } else {
                vec![
                    a.result(PutOutcome::Unknown),
                    a.at_once(Attempt::keyed(ActionKind::Abandon)),
                ]
            };
            let mut rows = vec![begin.clone()];
            rows.extend(end.iter().cloned());
            assert_eq!(
                admit(&sealed(rows)).unwrap_err(),
                Inconclusive::Malformed {
                    op: ATTEMPT,
                    field: Field::Open,
                },
                "{last:?}"
            );
            let mut rows: Vec<Row> = end
                .iter()
                .cloned()
                .map(|mut row| {
                    row.op = OpId(2);
                    row
                })
                .collect();
            rows.push(begin.clone());
            assert!(admit(&sealed(rows)).is_ok(), "{last:?}");
            let mut settled = begin;
            settled.open = Open::Settled;
            let mut rows = end;
            rows.push(settled);
            assert!(admit(&sealed(rows)).is_ok(), "{last:?}");
        }
    }

    #[test]
    fn a_begin_without_a_result_or_abandonment_declares_pending() {
        let mut a = Attempt::new();
        let settled = a.begin(Open::Settled);
        let authority = a.authority();
        let mut other = a.result(PutOutcome::Failed(25));
        other.op = OpId(2);
        for rows in [
            vec![settled.clone()],
            vec![settled.clone(), authority.clone(), other],
        ] {
            assert_eq!(
                admit(&sealed(rows)).unwrap_err(),
                Inconclusive::Malformed {
                    op: ATTEMPT,
                    field: Field::Open,
                },
            );
        }
        let mut pending = settled;
        pending.open = Open::Pending;
        assert!(admit(&sealed(vec![pending, authority])).is_ok());
    }

    #[test]
    fn a_put_result_names_a_put_outcome_and_never_no_information() {
        for member in NoInformation::ALL {
            let mut row = Attempt::new().result(PutOutcome::Failed(25));
            row.outcome = Some(Outcome::NoInformation(member));
            assert_eq!(row.malformed_field(), Some(Field::Outcome), "{member:?}");
            assert_eq!(
                admit(&sealed(vec![row])).unwrap_err(),
                Inconclusive::Malformed {
                    op: ATTEMPT,
                    field: Field::Outcome,
                },
                "{member:?}"
            );
        }
    }

    #[test]
    fn each_put_outcome_states_the_attempt_publication() {
        for (outcome, publication, informative) in [
            (PutOutcome::Published, Publication::Certain, true),
            (PutOutcome::Failed(25), Publication::Forbidden, true),
            (PutOutcome::NotStarted, Publication::Forbidden, true),
            (PutOutcome::Unknown, Publication::Open, false),
        ] {
            assert_eq!(outcome.publication(), publication, "{outcome:?}");
            assert_eq!(
                Outcome::Put(outcome).carries_information(),
                informative,
                "{outcome:?}"
            );
            let row = Attempt::new().result(outcome);
            assert_eq!(row.malformed_field(), None, "{outcome:?}");
            assert_eq!(row.publication(), Some(publication), "{outcome:?}");
        }
    }

    #[test]
    fn a_failed_result_names_a_put_error_status_other_than_unknown_outcome() {
        for status in [1, 23, 25, 28] {
            let row = Attempt::new().result(PutOutcome::Failed(status));
            assert_eq!(row.malformed_field(), None, "{status}");
        }
        for status in [0, 24, 29, u16::MAX] {
            let row = Attempt::new().result(PutOutcome::Failed(status));
            assert_eq!(row.malformed_field(), Some(Field::Outcome), "{status}");
            assert_eq!(
                admit(&sealed(vec![row])).unwrap_err(),
                Inconclusive::Malformed {
                    op: ATTEMPT,
                    field: Field::Outcome,
                },
                "{status}"
            );
        }
    }

    #[test]
    fn an_abandoned_attempt_holds_an_unknown_result() {
        let mut a = Attempt::new();
        let begin = a.begin(Open::Settled);
        let unknown = a.result(PutOutcome::Unknown);
        let abandon = a.at_once(Attempt::keyed(ActionKind::Abandon));
        assert!(admit(&sealed(vec![begin.clone(), unknown, abandon.clone()])).is_ok());
        let mut failed = a.result(PutOutcome::Failed(25));
        failed.op = OpId(2);
        let mut other = abandon.clone();
        other.op = OpId(2);
        for (rows, op) in [
            (vec![begin.clone(), abandon.clone()], ATTEMPT),
            (
                vec![begin.clone(), a.result(PutOutcome::Failed(25)), abandon],
                ATTEMPT,
            ),
            (
                vec![begin, a.result(PutOutcome::Unknown), failed, other],
                OpId(2),
            ),
        ] {
            assert_eq!(
                admit(&sealed(rows)).unwrap_err(),
                Inconclusive::Malformed {
                    op,
                    field: Field::Open,
                }
            );
        }
    }

    #[test]
    fn a_receipt_mask_names_only_granted_fragments() {
        let mut a = Attempt::new();
        for (base, grant, mask, field) in [
            (0, 1, 0b1, Some(Field::Receipt)),
            (0, 2, 0b1, None),
            (0, 2, 0b10, Some(Field::Receipt)),
            (3, 5, 0b1, None),
            (3, 5, 0b11, Some(Field::Receipt)),
            (0, 65, u64::MAX, None),
            (0, 64, u64::MAX, Some(Field::Receipt)),
            (u32::MAX, u32::MAX, 0b1, Some(Field::Receipt)),
        ] {
            let mut row = a.ack(base);
            row.receipt = Some(Receipt { base, mask });
            row.grant = Some(grant);
            assert_eq!(row.malformed_field(), field, "{base} {grant} {mask:#b}");
        }
    }

    #[test]
    fn a_grant_stays_within_the_window_above_the_receipt_base() {
        let mut a = Attempt::new();
        for (grant, field) in [(4096, None), (4097, Some(Field::Grant))] {
            let mut ready = a.ready();
            ready.body_len = Some(4097 * FRAGMENT_BYTES as u64);
            ready.grant = Some(grant);
            assert_eq!(ready.malformed_field(), field, "ready {grant}");
        }
        for (base, grant, field) in [
            (0, 4096, None),
            (0, 4097, Some(Field::Grant)),
            (1, 4097, None),
            (1, 4098, Some(Field::Grant)),
        ] {
            let mut ack = a.ack(base);
            ack.grant = Some(grant);
            assert_eq!(ack.malformed_field(), field, "ack {base} {grant}");
        }
    }

    #[test]
    fn a_ready_grant_stays_within_the_manifests_fragment_count() {
        let mut a = Attempt::new();
        for (metadata, body, grant, field) in [
            (METADATA, BODY, fragments(), None),
            (METADATA, BODY, fragments() + 1, Some(Field::Grant)),
            (0, 1, 1, None),
            (0, 1, 2, Some(Field::Grant)),
            (0, 0, 0, None),
            (0, 0, 1, Some(Field::Grant)),
            (1, FRAGMENT_BYTES as u64, 2, None),
            (1, FRAGMENT_BYTES as u64, 3, Some(Field::Grant)),
        ] {
            let mut ready = a.ready();
            ready.metadata_len = Some(metadata);
            ready.body_len = Some(body);
            ready.grant = Some(grant);
            assert_eq!(ready.malformed_field(), field, "{metadata} {body} {grant}");
        }
    }

    #[test]
    fn an_attempt_holds_one_resolved_result_and_an_unknown_one_resolves_published_or_failed() {
        let mut a = Attempt::new();
        let begin = a.begin(Open::Settled);
        let unknown = a.result(PutOutcome::Unknown);
        let published = a.result(PutOutcome::Published);
        assert!(
            admit(&sealed(vec![
                begin.clone(),
                unknown.clone(),
                published.clone()
            ]))
            .is_ok()
        );
        let again = a.result(PutOutcome::Unknown);
        assert!(admit(&sealed(vec![begin.clone(), unknown, again])).is_ok());
        let mut other = a.result(PutOutcome::Failed(25));
        other.op = OpId(2);
        assert!(admit(&sealed(vec![begin.clone(), published.clone(), other])).is_ok());
        let unknown = a.result(PutOutcome::Unknown);
        let not_started = a.result(PutOutcome::NotStarted);
        for rows in [
            vec![begin.clone(), unknown.clone(), not_started.clone()],
            vec![begin.clone(), not_started, unknown],
        ] {
            assert_eq!(
                admit(&sealed(rows)).unwrap_err(),
                Inconclusive::Malformed {
                    op: ATTEMPT,
                    field: Field::Outcome,
                }
            );
        }
        for second in [
            a.result(PutOutcome::Failed(25)),
            a.result(PutOutcome::NotStarted),
            a.result(PutOutcome::Published),
        ] {
            assert_eq!(
                admit(&sealed(vec![
                    begin.clone(),
                    published.clone(),
                    second.clone()
                ]))
                .unwrap_err(),
                Inconclusive::Malformed {
                    op: ATTEMPT,
                    field: Field::Outcome,
                },
                "{:?}",
                second.outcome
            );
        }
    }

    #[test]
    fn a_remote_body_length_fits_the_wire() {
        let mut a = Attempt::new();
        let begin = a.begin(Open::Settled);
        let ready = a.ready();
        let mut fill = Attempt::keyed(ActionKind::Fill);
        fill.label = Some(LABEL);
        fill.metadata_len = Some(METADATA);
        fill.body_len = Some(BODY);
        fill.session = Some(SessionId(1));
        fill.incarnation = Some(Incarnation(1));
        fill.outcome = Some(Outcome::Acknowledged);
        fill.serial = SERIAL;
        let fill = a.span(fill);
        let mut local = fill.clone();
        local.serial = None;
        for (len, field) in [
            (u64::from(u32::MAX), None),
            (u64::from(u32::MAX) + 1, Some(Field::BodyLength)),
        ] {
            for row in [&begin, &ready, &fill] {
                let mut row = row.clone();
                row.body_len = Some(len);
                assert_eq!(row.malformed_field(), field, "{:?} {len}", row.kind);
            }
            let mut row = local.clone();
            row.body_len = Some(len);
            assert_eq!(row.malformed_field(), None, "local fill {len}");
        }
    }

    #[test]
    fn put_fact_rows_carry_no_outcome_and_a_retry_only_a_refusal() {
        let mut a = Attempt::new();
        let facts = [
            a.begin(Open::Pending),
            a.authority(),
            a.ready(),
            a.fragment(),
            a.ack(0),
            a.write_submit(),
            a.at_once(Attempt::keyed(ActionKind::Abandon)),
        ];
        for member in NoInformation::ALL {
            for row in &facts {
                let mut row = row.clone();
                row.outcome = Some(Outcome::NoInformation(member));
                assert_eq!(
                    row.malformed_field(),
                    Some(Field::Outcome),
                    "{:?} {member:?}",
                    row.kind
                );
            }
            let retry = a.retry(Outcome::NoInformation(member));
            let field = (member != NoInformation::Refused).then_some(Field::Outcome);
            assert_eq!(retry.malformed_field(), field, "{member:?}");
        }
    }

    #[test]
    fn full_receipt_and_write_completion_supply_neither_published_nor_a_durable_fact() {
        let mut a = Attempt::new();
        let mut fill = Attempt::keyed(ActionKind::Fill);
        fill.label = Some(LABEL);
        fill.metadata_len = Some(METADATA);
        fill.body_len = Some(BODY);
        fill.session = Some(SessionId(1));
        fill.incarnation = Some(Incarnation(1));
        fill.outcome = Some(Outcome::Acknowledged);
        fill.serial = SERIAL;
        let fill = a.span(fill);
        let mut written = Attempt::keyed(ActionKind::WriteCompleted);
        written.label = Some(LABEL);
        written.serial = SERIAL;
        let written = a.at_once(written);
        let full = a.ack(fragments());
        assert_eq!(full.receipt.map(|r| r.base), Some(1));
        let rows = vec![
            a.begin(Open::Pending),
            a.authority(),
            a.ready(),
            fill,
            a.fragment(),
            full,
            a.write_submit(),
            a.terminal(),
            written,
        ];
        let history = sealed(rows.clone());
        assert_eq!(admit(&history).map(|a| a.rows().len()), Ok(rows.len()));
        assert!(abstract_facts(history.rows()).is_empty());
        let publications: Vec<Publication> = rows.iter().filter_map(Row::publication).collect();
        assert_eq!(publications, [Publication::Open]);

        let mut claimed = Attempt::new().ack(fragments());
        for outcome in [Outcome::Put(PutOutcome::Published), Outcome::Acknowledged] {
            claimed.outcome = Some(outcome);
            assert_eq!(
                claimed.malformed_field(),
                Some(Field::Outcome),
                "{outcome:?}"
            );
        }
    }

    #[test]
    fn a_serial_appears_only_on_kinds_after_the_authority() {
        let after_authority = [
            ActionKind::Fill,
            ActionKind::Receive,
            ActionKind::WriteCompleted,
            ActionKind::Publish,
            ActionKind::Replace,
            ActionKind::Authority,
            ActionKind::Ready,
            ActionKind::Fragment,
            ActionKind::Ack,
            ActionKind::WriteSubmit,
            ActionKind::PutResult,
            ActionKind::Retry,
        ];
        let remote = [
            ActionKind::PutBegin,
            ActionKind::Authority,
            ActionKind::Ready,
            ActionKind::Fragment,
            ActionKind::Ack,
            ActionKind::WriteSubmit,
            ActionKind::PutResult,
            ActionKind::Retry,
            ActionKind::Abandon,
        ];
        let mut ordinals = History::new();
        for kind in ActionKind::ALL {
            let mut row = complete(1, kind, &mut ordinals);
            assert_eq!(kind.is_remote_put(), remote.contains(&kind), "{kind:?}");
            row.serial = SERIAL;
            let expected = (!after_authority.contains(&kind)).then_some(Field::Serial);
            assert_eq!(row.malformed_field(), expected, "{kind:?}");
        }
        assert_eq!(Serial::new(0), None);
    }

    #[test]
    fn put_facts_outside_their_kinds_are_malformed() {
        let mut a = Attempt::new();
        let mut lookup = Attempt::keyed(ActionKind::Lookup);
        lookup.outcome = Some(Outcome::Missing);
        let lookup = a.span(lookup);
        let mut cases: Vec<(Row, Field)> = Vec::new();
        for field in [Field::Fragment, Field::Receipt, Field::Grant, Field::Open] {
            let mut row = lookup.clone();
            fill_field(&mut row, field, &mut a.history);
            cases.push((row, field));
        }
        let mut untagged = a.source(ActionKind::Take, Custodian::Nic);
        untagged.fragment = None;
        cases.push((untagged, Field::Fragment));
        let mut buffer = a.source(ActionKind::Take, Custodian::Nic);
        buffer.subject = Some(Subject::Resource(ResourceId {
            kind: ResourceKind::Buffer,
            index: 0,
        }));
        cases.push((buffer, Field::Fragment));
        let mut retained = a.source(ActionKind::Take, Custodian::Retransmission);
        retained.subject = Some(Subject::Resource(ResourceId {
            kind: ResourceKind::Buffer,
            index: 0,
        }));
        retained.fragment = None;
        cases.push((retained, Field::Custodian));
        for custodian in [
            Custodian::Owner,
            Custodian::Storage,
            Custodian::Reader,
            Custodian::Grace,
        ] {
            cases.push((a.source(ActionKind::Take, custodian), Field::Custodian));
            cases.push((a.source(ActionKind::Release, custodian), Field::Custodian));
        }
        let mut uncustodied = a.source(ActionKind::Take, Custodian::Nic);
        uncustodied.custodian = None;
        cases.push((uncustodied, Field::Custodian));
        for len in [0, FRAGMENT_BYTES + 1] {
            let mut fragment = a.fragment();
            fragment.payload = Some(vec![1; len]);
            cases.push((fragment, Field::Payload));
        }
        let mut ready = a.ready();
        ready.receipt = Some(Receipt { base: 0, mask: 0 });
        cases.push((ready, Field::Receipt));
        let mut fragment = a.fragment();
        fragment.grant = Some(2);
        cases.push((fragment, Field::Grant));
        let mut behind = a.ack(3);
        behind.grant = Some(2);
        cases.push((behind, Field::Grant));
        let mut submit = a.write_submit();
        submit.subject = Some(Subject::Resource(ResourceId {
            kind: ResourceKind::Buffer,
            index: 0,
        }));
        cases.push((submit, Field::Resource));
        let mut unlabelled = a.result(PutOutcome::Published);
        unlabelled.label = None;
        cases.push((unlabelled, Field::Label));
        let mut unnamed = a.result(PutOutcome::Published);
        unnamed.serial = None;
        cases.push((unnamed, Field::Serial));
        let mut uncertain = a.result(PutOutcome::Unknown);
        uncertain.serial = None;
        cases.push((uncertain, Field::Serial));
        let mut named = a.result(PutOutcome::NotStarted);
        named.serial = SERIAL;
        cases.push((named, Field::Serial));
        let mut failed = a.result(PutOutcome::Failed(25));
        failed.open = Open::Publication;
        cases.push((failed, Field::Open));
        cases.push((a.retry(Outcome::Put(PutOutcome::Published)), Field::Outcome));
        for (row, field) in cases {
            assert_eq!(row.malformed_field(), Some(field), "{row:?}");
            let history = sealed(vec![row.clone()]);
            assert_eq!(
                admit(&history).unwrap_err(),
                Inconclusive::Malformed { op: row.op, field },
                "{row:?}"
            );
        }
    }

    #[test]
    fn put_rows_next_to_the_malformed_cases_are_admissible() {
        let mut a = Attempt::new();
        let mut release = a.source(ActionKind::Release, Custodian::Nic);
        release.fragment = None;
        let accepted = [
            release,
            a.retry(Outcome::Acknowledged),
            a.retry(Outcome::NoInformation(NoInformation::Refused)),
            a.ack(3),
            a.at_once(Attempt::keyed(ActionKind::Abandon)),
        ];
        for row in accepted {
            assert_eq!(row.malformed_field(), None, "{row:?}");
        }
    }

    #[test]
    fn client_upload_custody_is_judged_with_the_attempt_receipt() {
        let mut a = Attempt::new();
        let rows = vec![
            a.begin(Open::Pending),
            a.authority(),
            a.ready(),
            a.source(ActionKind::Take, Custodian::Retransmission),
            a.source(ActionKind::Take, Custodian::Nic),
            a.fragment(),
            a.ack(fragments()),
            a.source(ActionKind::Release, Custodian::Nic),
            a.source(ActionKind::Release, Custodian::Retransmission),
        ];
        let verdict = check(&sealed(rows));
        assert!(verdict.satisfies(&[Obligation::Custody]), "{verdict:?}");
    }
}

/// Each tenure-order field sits only on the kinds that carry it, a client's
/// answer carries its tenure tag and its acceptance, an acceptance names a
/// client and a recorded tag and belongs only to an answer, an interval is
/// ordered, and activations rise
/// in `(g, a)` order: a row that breaks one is malformed by that field, and
/// activations that fall, repeat or exhaust the generation are malformed
/// by `Tenure`. A restart whose outcome carries no information activates
/// nothing.
#[test]
fn tenure_order_fields_admit_only_where_they_carry_meaning() {
    let lookup = |edit: fn(&mut Row)| {
        let mut row = complete(1, ActionKind::Lookup, &mut History::new());
        row.outcome = Some(Outcome::Missing);
        row.label = None;
        row.clock = None;
        row.client = Some(super::ids::ClientId(1));
        row.tenure = Some(Tenure::INITIAL);
        row.acceptance = Some(Acceptance {
            high_water: None,
            accepted: true,
        });
        edit(&mut row);
        row
    };
    type Edit = fn(&mut Row);
    let cases: [(Edit, Field); 6] = [
        (|row| row.tenure = None, Field::Tenure),
        (|row| row.acceptance = None, Field::Acceptance),
        (|row| row.version = Some(1), Field::Version),
        (|row| row.covers = Some(Cover::All), Field::Covers),
        (|row| row.cut = Some(CutId(1)), Field::Cut),
        (|row| row.damaged_unit = Some(0), Field::DamagedUnit),
    ];
    for (edit, field) in cases {
        assert_eq!(lookup(edit).malformed_field(), Some(field), "{field:?}");
    }
    assert_eq!(lookup(|_| {}).malformed_field(), None);
    let mut refused = lookup(|row| row.acceptance = None);
    refused.outcome = Some(Outcome::NoInformation(NoInformation::Refused));
    assert_eq!(refused.malformed_field(), Some(Field::Acceptance));
    let mut contended = lookup(|row| row.acceptance = None);
    contended.outcome = Some(Outcome::NoInformation(NoInformation::Contended));
    assert_eq!(contended.malformed_field(), Some(Field::Acceptance));
    let mut timed_out = lookup(|row| row.acceptance = None);
    timed_out.outcome = Some(Outcome::NoInformation(NoInformation::TimedOut));
    assert_eq!(timed_out.malformed_field(), None);
    timed_out.tenure = None;
    assert_eq!(timed_out.malformed_field(), None);
    timed_out.acceptance = Some(Acceptance {
        high_water: None,
        accepted: true,
    });
    assert_eq!(timed_out.malformed_field(), Some(Field::Acceptance));
    timed_out.tenure = Some(Tenure::INITIAL);
    assert_eq!(timed_out.malformed_field(), Some(Field::Acceptance));
    let captured_units = lookup(|row| row.captured_units = Some((0, 1)));
    assert_eq!(captured_units.malformed_field(), Some(Field::CapturedUnits));
    let mut close = complete(2, ActionKind::Close, &mut History::new());
    assert_eq!(close.malformed_field(), None);
    close.target = Some(Place::In(Tenure::INITIAL));
    assert_eq!(close.malformed_field(), Some(Field::Target));
    let mut invalidation = complete(3, ActionKind::Invalidate, &mut History::new());
    assert_eq!(invalidation.malformed_field(), None);
    invalidation.covers = Some(Cover::Range { lo: 2, hi: 1 });
    assert_eq!(invalidation.malformed_field(), Some(Field::Covers));
    let mut owner = lookup(|row| row.client = None);
    assert_eq!(owner.malformed_field(), Some(Field::Acceptance));
    owner.acceptance = None;
    assert_eq!(owner.malformed_field(), None);

    let attached = |op: u32, tenure: Option<Tenure>, at: u32| {
        let mut row = Row::new(OpId(op), ActionKind::Restart);
        row.evidence = Evidence::Abstract(HYPOTHESIS);
        row.episode = Some(EPISODE);
        row.tenure = tenure;
        row.responded = Some(Ordinal(at));
        row
    };
    let restart = |op: u32, g: u64, at: u32| attached(op, Some(Tenure { g, a: 0 }), at);
    let logged = |activations: &[Row]| {
        let rows: Vec<&Row> = activations.iter().collect();
        super::tenure::ActivationLog::of(&rows).map(|log| {
            log.activations()
                .iter()
                .map(|activation| activation.tenure)
                .collect::<Vec<_>>()
        })
    };
    let malformed = Err(Inconclusive::Malformed {
        op: OpId(2),
        field: Field::Tenure,
    });
    for second in [1, 2] {
        let activations = [restart(1, 2, 0), restart(2, second, 1)];
        assert_eq!(logged(&activations), malformed, "{second}");
    }
    let (first, reattached) = (Tenure { g: 1, a: 0 }, Tenure { g: 1, a: 1 });
    assert_eq!(
        logged(&[
            attached(1, Some(first), 0),
            attached(2, Some(reattached), 1)
        ]),
        Ok(vec![Tenure::INITIAL, first, reattached])
    );
    assert_eq!(
        logged(&[
            attached(1, Some(reattached), 0),
            attached(2, Some(first), 1)
        ]),
        malformed
    );
    let last = Tenure { g: u64::MAX, a: 0 };
    assert_eq!(
        logged(&[attached(1, Some(last), 0), attached(2, None, 1)]),
        malformed
    );
    let mut accepting = restart(1, 1, 0);
    accepting.client = Some(super::ids::ClientId(1));
    accepting.acceptance = Some(Acceptance {
        high_water: Some(Tenure { g: 9, a: 0 }),
        accepted: true,
    });
    assert_eq!(accepting.malformed_field(), Some(Field::Acceptance));
    let mut refused = restart(2, 2, 1);
    refused.outcome = Some(Outcome::NoInformation(NoInformation::Refused));
    assert_eq!(
        logged(&[restart(1, 1, 0), refused]),
        Ok(vec![Tenure::INITIAL, first])
    );
}
