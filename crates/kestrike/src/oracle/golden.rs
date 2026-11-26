//! Shared fixtures for the golden tests: labels, outcomes, the golden
//! history builders, and the bound-margin check over every golden.

use super::action::ActionKind;
use super::attempt::{PutOutcome, Serial};
use super::bounds::{HISTORY_BOUND, SEARCH_BOUND, SearchBudget};
use super::checker::{check, check_within};
use super::content::{Geometry, expected_bytes};
use super::evidence::{DurableFact, Hypothesis, PREDECESSORS, Qualified};
use super::history::History;
use super::ids::{ClockSample, KeyId, Label, Subject};
use super::obligation::Obligation;
use super::outcome::{Failure, NoInformation, Outcome, VisibilityCause};
use super::row::Row;
use super::script::{META, Script};
use super::verdict::Verdict;

pub(super) const K: KeyId = KeyId(0);

pub(super) const J: KeyId = KeyId(1);

pub(super) const A: Label = Label(10);

pub(super) const B: Label = Label(11);

pub(super) const C: Label = Label(20);

pub(super) const BODY: u64 = 40;

pub(super) const LONG: u64 = 200;

pub(super) const RECOVERED: Hypothesis = Hypothesis("persisted-before-restart");

pub(super) const B_OR_MISS: Hypothesis = Hypothesis("b-or-miss-after-exclusion");

pub(super) const ACK: Outcome = Outcome::Acknowledged;

pub(super) const HIT: Outcome = Outcome::Hit;

pub(super) const MISSING: Outcome = Outcome::Missing;

pub(super) const CONTENDED: Outcome = Outcome::NoInformation(NoInformation::Contended);

pub(super) const REFUSED: Outcome = Outcome::NoInformation(NoInformation::Refused);

pub(super) const CLOCK_UNAVAILABLE: Outcome =
    Outcome::NoInformation(NoInformation::ClockUnavailable);

pub(super) fn bytes(key: KeyId, label: Label, body: u64) -> Vec<u8> {
    expected_bytes(key, label, META as usize + body as usize)
}

pub(super) fn rule(verdict: &Verdict) -> Option<(Obligation, &'static str)> {
    match verdict {
        Verdict::Violation(violation) => Some((violation.obligation, violation.rule)),
        _ => None,
    }
}

pub(super) fn assert_violates(history: &History, obligation: Obligation) -> &'static str {
    let verdict = check(history);
    match rule(&verdict) {
        Some((found, text)) if found == obligation => text,
        _ => panic!("expected a {obligation:?} violation, got {verdict:?}"),
    }
}

pub(super) fn edited(history: &History, edit: impl FnOnce(&mut Vec<Row>)) -> History {
    let mut rows: Vec<Row> = history.rows().to_vec();
    edit(&mut rows);
    let mut edited = History::new();
    for row in rows {
        edited.push(row);
    }
    edited.seal();
    edited
}

pub(super) fn held_read_across_invalidation(fresh: Outcome, label: Option<Label>) -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let held = s.lookup(K, HIT, Some(A));
    s.invalidate(K, ACK);
    s.lookup(K, fresh, label);
    s.deliver(held, K, A, BODY, Outcome::Complete, bytes(K, A, BODY));
    s.finish()
}

pub(super) fn replacement_overlapping_lookup(outcome: Outcome, label: Option<Label>) -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let lookup = s.begin_lookup(K, ClockSample::Seconds(1));
    let replace = s.begin_replace(K, B, BODY);
    s.close(replace, Some(ACK));
    s.end_lookup(lookup, outcome, label);
    s.ended(K, A, VisibilityCause::GraceEnd);
    s.lookup(K, HIT, Some(B));
    s.finish()
}

pub(super) fn refused_effects(outcome: Outcome, label: Option<Label>) -> History {
    refused_with(REFUSED, outcome, label)
}

pub(super) fn refused_with(refusal: Outcome, outcome: Outcome, label: Option<Label>) -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let invalidate = s.begin_invalidate(K);
    if refusal == CLOCK_UNAVAILABLE {
        s.clock_unavailable(invalidate, A);
    } else {
        s.close(invalidate, Some(refusal));
    }
    let replace = s.begin_replace(K, B, BODY);
    s.close(replace, Some(REFUSED));
    s.lookup(K, outcome, label);
    s.finish()
}

pub(super) fn colliding_candidate(outcome: Outcome, payload: Vec<u8>) -> History {
    let mut s = Script::new();
    s.publish(J, C, BODY);
    let candidate = s.candidate_lookup(K, J, HIT, Some(C));
    s.deliver(candidate, K, C, BODY, outcome, payload);
    s.lookup(K, MISSING, None);
    s.finish()
}

pub(super) fn unpublished_then_expiry(unpublished: Outcome, at_deadline: Outcome) -> History {
    let mut s = Script::new();
    s.fill(K, B, BODY);
    let label = (unpublished == HIT).then_some(B);
    s.lookup(K, unpublished, label);
    let publish = s.begin_publish(K, A, BODY, Some(10));
    s.close(publish, Some(ACK));
    let before = s.begin_lookup(K, ClockSample::Seconds(9));
    s.end_lookup(before, HIT, Some(A));
    let at = s.begin_lookup(K, ClockSample::Seconds(10));
    s.end_lookup(at, at_deadline, Some(A));
    s.expire(K, A, 10);
    s.ended(K, A, VisibilityCause::Expiry);
    s.lookup(K, MISSING, None);
    s.finish()
}

pub(super) fn damaged_later_chunk(outcome: Outcome, prefix: usize) -> History {
    let mut s = Script::new();
    s.publish(K, A, LONG);
    let read = s.lookup(K, HIT, Some(A));
    let mut payload = bytes(K, A, LONG);
    payload.truncate(prefix);
    s.deliver(read, K, A, LONG, outcome, payload);
    s.finish()
}

pub(super) fn completion_as_durability(admitted: bool) -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    for fact in [
        DurableFact::Binding,
        DurableFact::Identity,
        DurableFact::Ownership,
    ] {
        s.fact(RECOVERED, K, A, fact);
    }
    if admitted {
        s.admission(RECOVERED, K, A);
    }
    s.restart(RECOVERED, K);
    s.recovered_lookup(RECOVERED, K, MISSING, None);
    s.finish()
}

pub(super) const ADMISSION: [DurableFact; 4] = [
    DurableFact::Binding,
    DurableFact::Payload,
    DurableFact::Identity,
    DurableFact::Ownership,
];

pub(super) const AUTHORITY: [DurableFact; 4] = [
    DurableFact::Freshness,
    DurableFact::PortableExpiry,
    DurableFact::ServingAuthority,
    DurableFact::InvalidationReplayed,
];

pub(super) fn recovered(
    withheld: Option<DurableFact>,
    excluded: bool,
    outcome: Outcome,
) -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    for fact in ADMISSION.into_iter().chain(AUTHORITY) {
        if Some(fact) != withheld {
            s.fact(RECOVERED, K, A, fact);
        }
    }
    s.admission(RECOVERED, K, A);
    if excluded {
        s.fact(RECOVERED, K, A, DurableFact::RecoveryExclusion);
    }
    s.restart(RECOVERED, K);
    let label = (outcome == HIT).then_some(A);
    s.recovered_lookup(RECOVERED, K, outcome, label);
    s.finish()
}

/// The qualified profile the qualified goldens record under.
pub(super) const PROFILE: &str = "declared-16k";
/// The attached identity the qualified goldens name.
pub(super) const IDENTITY: u64 = 0x5eed;
/// The boundary the qualified goldens' evidence observed.
pub(crate) const BOUNDARY: &str = "completion-without-volatile-cache";

/// The frozen identity of the binding the qualified exclusions exclude.
pub(super) const FROZEN: u64 = 0xa1;

/// Qualified evidence for `command` after `predecessor`, written by
/// `incarnation`.
pub(super) const fn qualified(
    command: u32,
    predecessor: Option<u32>,
    incarnation: u64,
) -> Qualified {
    let mut predecessors = [None; PREDECESSORS];
    predecessors[0] = predecessor;
    Qualified {
        profile: PROFILE,
        identity: IDENTITY,
        command,
        predecessors,
        boundary: BOUNDARY,
        incarnation,
    }
}

/// Records every admission and authority fact for `label` under the
/// qualified profile, written by `incarnation`, with commands numbered
/// from `first`: the payload first, then the binding that names it as its
/// predecessor, then the rest.
pub(super) fn qualified_facts(s: &mut Script, label: Label, incarnation: u64, first: u32) {
    s.fact(
        qualified(first, None, incarnation),
        K,
        label,
        DurableFact::Payload,
    );
    let rest = [
        DurableFact::Binding,
        DurableFact::Identity,
        DurableFact::Ownership,
    ];
    for (command, fact) in (first + 1..).zip(rest.into_iter().chain(AUTHORITY)) {
        let predecessor = (fact == DurableFact::Binding).then_some(first);
        s.fact(qualified(command, predecessor, incarnation), K, label, fact);
    }
}

/// How the qualified recovery golden departs from evidence that counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Qualification {
    /// Every row names the profile, identity and boundary, and each fact
    /// the incarnation its restarts leave writing.
    Matching,
    /// The payload row names another qualified profile.
    OtherProfile,
    /// The payload row names another attached identity.
    OtherIdentity,
    /// The payload row observed a boundary the profile does not name.
    OtherBoundary,
    /// The payload row names an incarnation the restarts have not reached.
    FutureIncarnation,
    /// Every row names a run profile no qualification accepted.
    Unqualified,
    /// The serving-authority row is recorded after the restart.
    AfterRestart,
    /// The binding row is recorded before the payload it names.
    RootFirst,
    /// The binding row is recorded after the payload and before the
    /// identity, its second predecessor.
    RootBeforeSecond,
}

/// A published label recovered as a hit under qualified evidence, departing
/// from evidence that counts as `qualification` names.
pub(super) fn qualified_recovery(qualification: Qualification) -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let scope = |command| {
        let mut evidence = qualified(command, None, 0);
        if qualification == Qualification::Unqualified {
            evidence.profile = "recovery-16k";
        }
        evidence
    };
    let mut payload = scope(1);
    match qualification {
        Qualification::OtherProfile => payload.profile = "declared-512",
        Qualification::OtherIdentity => payload.identity = IDENTITY + 1,
        Qualification::OtherBoundary => payload.boundary = "submission",
        Qualification::FutureIncarnation => payload.incarnation = 1,
        _ => {}
    }
    let binding = Qualified {
        predecessors: [Some(1), Some(3)],
        ..scope(2)
    };
    if qualification == Qualification::RootFirst {
        s.fact(binding, K, A, DurableFact::Binding);
    }
    s.fact(payload, K, A, DurableFact::Payload);
    if qualification == Qualification::RootBeforeSecond {
        s.fact(binding, K, A, DurableFact::Binding);
    }
    s.fact(scope(3), K, A, DurableFact::Identity);
    if !matches!(
        qualification,
        Qualification::RootFirst | Qualification::RootBeforeSecond
    ) {
        s.fact(binding, K, A, DurableFact::Binding);
    }
    let rest = [DurableFact::Ownership];
    let late = DurableFact::ServingAuthority;
    for (command, fact) in (4..).zip(rest.into_iter().chain(AUTHORITY)) {
        if qualification != Qualification::AfterRestart || fact != late {
            s.fact(scope(command), K, A, fact);
        }
    }
    s.admission(scope(20), K, A);
    s.restart(scope(21), K);
    if qualification == Qualification::AfterRestart {
        let evidence = Qualified {
            incarnation: 1,
            ..scope(22)
        };
        s.fact(evidence, K, A, late);
    }
    let lookup = Qualified {
        incarnation: 1,
        ..scope(23)
    };
    s.recovered_lookup(lookup, K, HIT, Some(A));
    s.finish()
}

/// Qualified rows within one profile, identity and incarnation name
/// distinct commands, since a predecessor names the row that counted under
/// its command; a reused command would let the binding count before the
/// payload it names. The payload row makes the history malformed.
pub(super) fn reused_command() -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.fact(qualified(1, None, 0), K, A, DurableFact::Identity);
    s.fact(qualified(2, Some(1), 0), K, A, DurableFact::Binding);
    s.fact(qualified(1, None, 0), K, A, DurableFact::Payload);
    let rest = [DurableFact::Ownership];
    for (command, fact) in (3..).zip(rest.into_iter().chain(AUTHORITY)) {
        s.fact(qualified(command, None, 0), K, A, fact);
    }
    s.admission(qualified(20, None, 0), K, A);
    s.restart(qualified(21, None, 0), K);
    s.recovered_lookup(qualified(22, None, 1), K, HIT, Some(A));
    s.finish()
}

/// A live completed write whose qualified payload row is lost, beside
/// qualified binding, identity and ownership rows; when `admitted`, the
/// admission rests on the completion alone. This is the labeled
/// contract-violation control for completion as durability under a
/// qualified profile.
pub(super) fn qualified_completion_as_durability(admitted: bool) -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let facts = [
        DurableFact::Binding,
        DurableFact::Identity,
        DurableFact::Ownership,
    ];
    for (command, fact) in (1..).zip(facts) {
        s.fact(qualified(command, None, 0), K, A, fact);
    }
    if admitted {
        s.admission(qualified(10, None, 0), K, A);
    }
    s.restart(qualified(11, None, 0), K);
    s.recovered_lookup(qualified(12, None, 1), K, MISSING, None);
    s.finish()
}

/// How the two-restart golden departs from an admission between the
/// restarts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Between {
    /// Incarnation 1 records the facts and the admission.
    Admitted,
    /// The admission follows the second restart, so the lookup's cut finds
    /// no admission before it.
    LateAdmission,
    /// The facts between the restarts name the incarnation the first
    /// restart ended.
    StaleFacts,
}

/// A label admitted between two restarts and found as a hit after the
/// second, departing as `between` names.
pub(super) fn two_restarts(between: Between) -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.restart(qualified(1, None, 0), K);
    let writer = u64::from(between != Between::StaleFacts);
    qualified_facts(&mut s, A, writer, 2);
    let late = between == Between::LateAdmission;
    if !late {
        s.admission(qualified(20, None, 1), K, A);
    }
    s.restart(qualified(21, None, 1), K);
    if late {
        s.admission(qualified(20, None, 2), K, A);
    }
    s.recovered_lookup(qualified(22, None, 2), K, HIT, Some(A));
    s.finish()
}

pub(super) fn commands_reused_across_incarnations() -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.fact(qualified(2, None, 0), K, A, DurableFact::Payload);
    s.restart(qualified(1, None, 0), K);
    qualified_facts(&mut s, A, 1, 2);
    let other = Qualified {
        identity: IDENTITY + 1,
        ..qualified(2, None, 1)
    };
    s.fact(other, K, A, DurableFact::Payload);
    s.admission(qualified(20, None, 1), K, A);
    s.restart(qualified(21, None, 1), K);
    s.recovered_lookup(qualified(22, None, 2), K, HIT, Some(A));
    s.finish()
}

/// The stale-version control: A is replaced by an acknowledged B, both are
/// admitted, A's recovery-safe exclusion names its frozen identity, and a
/// lookup after two restarts answers `outcome` with `label`.
pub(super) fn stale_version(outcome: Outcome, label: Option<Label>) -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let replace = s.begin_replace(K, B, BODY);
    s.close(replace, Some(ACK));
    qualified_facts(&mut s, A, 0, 1);
    s.admission(qualified(20, None, 0), K, A);
    qualified_facts(&mut s, B, 0, 21);
    s.admission(qualified(40, None, 0), K, B);
    s.exclusion(qualified(41, None, 0), K, A, FROZEN);
    s.restart(qualified(42, None, 0), K);
    s.restart(qualified(43, None, 1), K);
    s.recovered_lookup(qualified(44, None, 2), K, outcome, label);
    s.finish()
}

/// The post-restart exclusion control: an admitted A, a restart, A's
/// recovery-safe exclusion recorded by incarnation 1, a second restart,
/// and a hit on A after it.
pub(super) fn excluded_between_restarts() -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    qualified_facts(&mut s, A, 0, 1);
    s.admission(qualified(20, None, 0), K, A);
    s.restart(qualified(21, None, 0), K);
    s.exclusion(qualified(22, None, 1), K, A, FROZEN);
    s.restart(qualified(23, None, 1), K);
    s.recovered_lookup(qualified(24, None, 2), K, HIT, Some(A));
    s.finish()
}

/// An admitted A excluded before a restart; when `readmit`, the next
/// incarnation records A's facts again and admits it, which the exclusion
/// forbids. A second restart and a missing lookup follow.
pub(super) fn excluded_readmission(readmit: bool) -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    qualified_facts(&mut s, A, 0, 1);
    s.admission(qualified(20, None, 0), K, A);
    s.exclusion(qualified(21, None, 0), K, A, FROZEN);
    s.restart(qualified(22, None, 0), K);
    if readmit {
        qualified_facts(&mut s, A, 1, 23);
        s.admission(qualified(40, None, 1), K, A);
    }
    s.restart(qualified(41, None, 1), K);
    s.recovered_lookup(qualified(42, None, 2), K, MISSING, None);
    s.finish()
}

pub(super) fn b_or_miss(outcome: Outcome, label: Option<Label>) -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let replace = s.begin_replace(K, B, BODY);
    s.close(replace, Some(ACK));
    for fact in ADMISSION.into_iter().chain(AUTHORITY) {
        s.fact(B_OR_MISS, K, A, fact);
    }
    s.admission(B_OR_MISS, K, A);
    s.fact(B_OR_MISS, K, A, DurableFact::RecoveryExclusion);
    s.restart(B_OR_MISS, K);
    s.recovered_lookup(B_OR_MISS, K, outcome, label);
    s.finish()
}

pub(super) fn pending_publication(
    overlap: bool,
    outcome: Outcome,
    label: Option<Label>,
) -> History {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, None);
    if overlap {
        let lookup = s.begin_lookup(K, ClockSample::Seconds(1));
        s.close(publish, Some(ACK));
        s.end_lookup(lookup, outcome, label);
    } else {
        s.close(publish, Some(ACK));
        s.lookup(K, outcome, label);
    }
    s.finish()
}

pub(super) fn timed_out_publication(
    first: (Outcome, Option<Label>),
    second: (Outcome, Option<Label>),
) -> History {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, None);
    s.close(
        publish,
        Some(Outcome::NoInformation(NoInformation::TimedOut)),
    );
    s.lookup(K, first.0, first.1);
    s.lookup(K, second.0, second.1);
    s.finish()
}

pub(super) const FAILED: PutOutcome = PutOutcome::Failed(26);

/// Where a lookup falls against an upload's owner publication and client
/// result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Position {
    BeforePublication,
    /// The lookup is invoked before the owner publication and responds
    /// after it.
    Overlapping,
    BeforeResult,
    AfterResult,
}

/// A remote PUT of `A` to the fresh key `K`, published when `published`,
/// with the client's `result` (or a pending begin for `None`) and one lookup
/// at `position`. `NotStarted` and a pending attempt carry no owner row
/// unless `published` adds the owner's fill and publication.
pub(super) fn put_then_lookup(
    result: Option<PutOutcome>,
    published: bool,
    (outcome, label): (Outcome, Option<Label>),
    position: Position,
) -> History {
    let mut s = Script::new();
    let op = match result {
        None => s.put_begin(K, A, BODY, true),
        Some(PutOutcome::NotStarted) => s.put_begin(K, A, BODY, false),
        Some(_) => s.upload(K, A, BODY, true),
    };
    if published && matches!(result, None | Some(PutOutcome::NotStarted)) {
        s.owner_receives(op, K, A, BODY, true);
    }
    if position == Position::BeforePublication {
        s.lookup(K, outcome, label);
    }
    let overlapping =
        (position == Position::Overlapping).then(|| s.begin_lookup(K, ClockSample::Seconds(1)));
    if published {
        s.owner_publish(op, K, A);
    }
    if let Some(lookup) = overlapping {
        s.end_lookup(lookup, outcome, label);
    }
    if position == Position::BeforeResult {
        s.lookup(K, outcome, label);
    }
    if let Some(result) = result {
        s.put_result(op, K, A, result);
    }
    if position == Position::AfterResult {
        s.lookup(K, outcome, label);
    }
    s.finish()
}

/// A published upload followed by a GET of the uploaded label that hands
/// off `payload`.
pub(super) fn put_then_get(payload: Vec<u8>) -> History {
    let mut s = Script::new();
    let op = s.upload(K, A, BODY, true);
    s.owner_publish(op, K, A);
    s.put_result(op, K, A, PutOutcome::Published);
    let get = s.lookup(K, HIT, Some(A));
    s.deliver(get, K, A, BODY, Outcome::Complete, payload);
    s.finish()
}

/// A full receipt whose writes never completed, then the client's
/// `result` and a lookup.
pub(super) fn receipt_without_write(result: PutOutcome, lookup: Outcome) -> History {
    let mut s = Script::new();
    let op = s.upload(K, A, BODY, false);
    s.put_result(op, K, A, result);
    let label = (lookup == HIT).then_some(A);
    s.lookup(K, lookup, label);
    s.finish()
}

/// A published upload with full receipt and write completion, every
/// admission fact but `Payload`, an admission when `admitted`, then a
/// restart and a recovered miss.
pub(super) fn upload_as_durability(admitted: bool) -> History {
    let mut s = Script::new();
    let op = s.upload(K, A, BODY, true);
    s.owner_publish(op, K, A);
    s.put_result(op, K, A, PutOutcome::Published);
    for fact in [
        DurableFact::Binding,
        DurableFact::Identity,
        DurableFact::Ownership,
    ] {
        s.fact(RECOVERED, K, A, fact);
    }
    if admitted {
        s.admission(RECOVERED, K, A);
    }
    s.restart(RECOVERED, K);
    s.recovered_lookup(RECOVERED, K, MISSING, None);
    s.finish()
}

/// A lost RESULT resolved by a matching retry that replays the publication;
/// `republish` adds a second owner publication of the same attempt.
pub(super) fn matching_retry(republish: bool) -> History {
    let mut s = Script::new();
    let op = s.upload(K, A, BODY, true);
    s.owner_publish(op, K, A);
    s.put_result(op, K, A, PutOutcome::Unknown);
    s.retry(op, K, BODY, ACK);
    if republish {
        s.owner_publish(op, K, A);
    }
    s.put_result(op, K, A, PutOutcome::Published);
    s.lookup(K, HIT, Some(A));
    s.finish()
}

/// What a retry changes against its accepted attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Change {
    Key,
    Serial,
    Metadata,
    Body,
    Deadline,
}

/// A retry with one `change` answered `outcome`, while the accepted attempt
/// publishes unchanged.
pub(super) fn changed_retry(change: Change, outcome: Outcome) -> History {
    let mut s = Script::new();
    let op = s.upload(K, A, BODY, true);
    s.retry(op, K, BODY, outcome);
    s.owner_publish(op, K, A);
    s.put_result(op, K, A, PutOutcome::Published);
    s.lookup(K, HIT, Some(A));
    edited(&s.finish(), |rows| {
        let retry = rows
            .iter_mut()
            .find(|r| r.kind == ActionKind::Retry)
            .expect("the retry row");
        match change {
            Change::Key => retry.subject = Some(Subject::Key(J)),
            Change::Serial => retry.serial = Serial::new(99),
            Change::Metadata => retry.metadata_len = retry.metadata_len.map(|len| len + 1),
            Change::Body => retry.body_len = retry.body_len.map(|len| len + 8),
            Change::Deadline => retry.deadline = Some(30),
        }
    })
}

/// An attempt whose result stays `Unknown` once its terminal evidence is
/// gone, shown by a refused retry; when `late_fill`, the owner fills only
/// after its authority.
pub(super) fn expired_evidence(late_fill: bool) -> History {
    let mut s = Script::new();
    let op = s.put_begin(K, A, BODY, false);
    s.authority(op, K);
    s.put_result(op, K, A, PutOutcome::Unknown);
    s.retry(op, K, BODY, REFUSED);
    if late_fill {
        s.owner_fill(op, K, A, BODY);
    }
    s.lookup(K, MISSING, None);
    s.finish()
}

/// An incumbent `A`, then an upload of `B` that ends `result` without
/// publishing, then one lookup.
pub(super) fn failure_over_incumbent(
    result: PutOutcome,
    (outcome, label): (Outcome, Option<Label>),
) -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let op = if result == PutOutcome::NotStarted {
        s.put_begin(K, B, BODY, false)
    } else {
        s.upload(K, B, BODY, true)
    };
    s.put_result(op, K, B, result);
    s.lookup(K, outcome, label);
    s.finish()
}

/// A local publication of `A` that overlaps an upload of `B` ending `result`
/// without publishing, then one lookup.
pub(super) fn failure_beside_concurrent(
    result: PutOutcome,
    (outcome, label): (Outcome, Option<Label>),
) -> History {
    let mut s = Script::new();
    let local = s.begin_publish(K, A, BODY, None);
    let op = if result == PutOutcome::NotStarted {
        s.put_begin(K, B, BODY, false)
    } else {
        s.upload(K, B, BODY, true)
    };
    s.close(local, Some(ACK));
    s.put_result(op, K, B, result);
    s.lookup(K, outcome, label);
    s.finish()
}

/// How a published label stops being visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Ending {
    Replacement,
    Invalidation,
    Expiry,
    Eviction,
}

/// The latest whole second, at which an expiry of a label without a
/// deadline lands; a lookup after such an expiry samples it too.
const HORIZON: u64 = u32::MAX as u64;

fn lookup_after(s: &mut Script, ending: Ending, (outcome, label): (Outcome, Option<Label>)) {
    if ending == Ending::Expiry {
        let lookup = s.begin_lookup(K, ClockSample::Seconds(HORIZON));
        s.end_lookup(lookup, outcome, label);
    } else {
        s.lookup(K, outcome, label);
    }
}

fn end_visible(s: &mut Script, ending: Ending, visible: Label) {
    match ending {
        Ending::Replacement => {
            s.publish_replacing(K, C, BODY);
        }
        Ending::Invalidation => {
            s.invalidate(K, ACK);
        }
        Ending::Expiry => s.expire(K, visible, HORIZON),
        Ending::Eviction => s.evict(K, visible),
    }
}

/// An upload of `A` published and then ended by `ending`, the upload's
/// historical `Published` result and one lookup; a replacement publishes
/// `C`.
pub(super) fn historical_success(
    ending: Ending,
    (outcome, label): (Outcome, Option<Label>),
) -> History {
    let mut s = Script::new();
    let op = s.upload(K, A, BODY, true);
    s.owner_publish(op, K, A);
    end_visible(&mut s, ending, A);
    s.put_result(op, K, A, PutOutcome::Published);
    lookup_after(&mut s, ending, (outcome, label));
    s.finish()
}

/// A local publication of `A` overlapping an upload of `B` that ends
/// `result`, publishing `B` when `result` is `Published`; the visible label
/// then ends by `ending` before one lookup.
pub(super) fn concurrent_then_ended(
    result: PutOutcome,
    ending: Ending,
    (outcome, label): (Outcome, Option<Label>),
) -> History {
    let mut s = Script::new();
    let local = s.begin_publish(K, A, BODY, None);
    let op = s.upload(K, B, BODY, true);
    s.close(local, Some(ACK));
    let visible = if result == PutOutcome::Published {
        s.owner_publish(op, K, B);
        B
    } else {
        A
    };
    s.put_result(op, K, B, result);
    end_visible(&mut s, ending, visible);
    lookup_after(&mut s, ending, (outcome, label));
    s.finish()
}

/// An upload whose owner publication ends `publication` before the client's
/// `result` and one lookup.
pub(super) fn possible_publication(
    publication: NoInformation,
    result: PutOutcome,
    (outcome, label): (Outcome, Option<Label>),
) -> History {
    let mut s = Script::new();
    let op = s.upload(K, A, BODY, true);
    let mut publish = s.open(op, ActionKind::Publish, K, Some(A));
    publish.set_serial(Serial::new(u64::from(op.0)));
    s.close(publish, Some(Outcome::NoInformation(publication)));
    s.put_result(op, K, A, result);
    s.lookup(K, outcome, label);
    s.finish()
}

/// A `Published` result the client reports before the owner's publication.
pub(super) fn published_before_publication() -> History {
    let mut s = Script::new();
    let op = s.upload(K, A, BODY, true);
    s.put_result(op, K, A, PutOutcome::Published);
    s.owner_publish(op, K, A);
    s.finish()
}

/// An upload whose `Unknown` result is followed by an abandonment when
/// `abandon` and then by `later`; an `Unknown` `later` adds no result. The
/// owner publishes only for a `Published` `later`.
pub(super) fn resolved(abandon: bool, later: PutOutcome) -> History {
    let mut s = Script::new();
    let op = s.upload(K, A, BODY, true);
    if later == PutOutcome::Published {
        s.owner_publish(op, K, A);
    }
    s.put_result(op, K, A, PutOutcome::Unknown);
    if abandon {
        s.abandon(op, K);
    }
    if later != PutOutcome::Unknown {
        s.put_result(op, K, A, later);
    }
    s.finish()
}

pub(super) fn goldens() -> Vec<History> {
    vec![
        held_read_across_invalidation(MISSING, None),
        replacement_overlapping_lookup(HIT, Some(B)),
        refused_effects(HIT, Some(A)),
        colliding_candidate(Outcome::Damaged(Failure::HeaderMismatch), Vec::new()),
        unpublished_then_expiry(MISSING, Outcome::Expired),
        damaged_later_chunk(Outcome::Damaged(Failure::ChunkMismatch { index: 2 }), 112),
        completion_as_durability(false),
        recovered(None, false, HIT),
        b_or_miss(MISSING, None),
        pending_publication(true, MISSING, None),
        timed_out_publication((HIT, Some(A)), (HIT, Some(A))),
        put_then_get(bytes(K, A, BODY)),
        receipt_without_write(FAILED, MISSING),
        put_then_lookup(
            Some(PutOutcome::Unknown),
            true,
            (HIT, Some(A)),
            Position::AfterResult,
        ),
        matching_retry(false),
        changed_retry(Change::Body, REFUSED),
        expired_evidence(false),
        failure_over_incumbent(FAILED, (HIT, Some(A))),
        failure_beside_concurrent(PutOutcome::NotStarted, (HIT, Some(A))),
        historical_success(Ending::Invalidation, (MISSING, None)),
        concurrent_then_ended(PutOutcome::Published, Ending::Expiry, (MISSING, None)),
        resolved(true, PutOutcome::Published),
        upload_as_durability(false),
        qualified_recovery(Qualification::Matching),
        qualified_completion_as_durability(false),
        two_restarts(Between::Admitted),
        stale_version(MISSING, None),
        excluded_readmission(false),
    ]
}

#[test]
fn the_largest_golden_fits_both_bounds_with_twice_the_margin() {
    let mut largest_rows = 0;
    let mut largest_search = 0;
    for history in goldens() {
        let mut budget = SearchBudget::per_key();
        let verdict = check_within(&history, Geometry::GOLDEN, &mut budget);
        assert!(matches!(verdict, Verdict::Pass(_)), "{verdict:?}");
        largest_rows = largest_rows.max(history.rows().len());
        largest_search = largest_search.max(budget.high_water());
    }
    assert!(largest_rows * 2 <= HISTORY_BOUND, "{largest_rows} rows");
    assert!(
        largest_search * 2 <= SEARCH_BOUND,
        "{largest_search} expansions"
    );
    assert!(largest_search > 0);
}
