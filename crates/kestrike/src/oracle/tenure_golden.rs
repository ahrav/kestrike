//! Tenure-ordered goldens: histories across activated tenures, clients with
//! high-waters that accept or reject answers, versioned coverage, recorded
//! removals and restores, pending effects with and without a recorded
//! target, clock samples, closes and deadlines across activations, and
//! retained sets across host loss. Each builder returns one history under a
//! shared ordinal, and [`per_client`] declares per-client ordinals; the
//! history, recovery and continuation tests state each verdict.

use super::action::ActionKind;
use super::coverage::Cover;
use super::golden::{A, ACK, B, BODY, C, HIT, J, K, MISSING, RECOVERED, REFUSED, bytes, edited};
use super::history::History;
use super::ids::{ClientId, ClockSample, CutId, Label, Tenure};
use super::outcome::{NoInformation, Outcome, VisibilityCause};
use super::script::Script;
use super::tenure::{Ordinals, Place};

pub(super) const T1: Tenure = Tenure { g: 1, a: 0 };
pub(super) const T2: Tenure = Tenure { g: 2, a: 0 };
const T3: Tenure = Tenure { g: 3, a: 0 };
/// T1's generation reattached: above T1 and below T2.
const T1_REATTACHED: Tenure = Tenure { g: 1, a: 1 };
/// A tenure no golden activates.
pub(super) const T9: Tenure = Tenure { g: 9, a: 0 };
pub(super) const C1: ClientId = ClientId(1);
pub(super) const C2: ClientId = ClientId(2);
/// The restarted instance of client one, whose high-water starts absent.
const C1_RESTARTED: ClientId = ClientId(3);
pub(super) const CUT: CutId = CutId(1);
const OTHER_CUT: CutId = CutId(2);

const TIMED_OUT: Outcome = Outcome::NoInformation(NoInformation::TimedOut);

/// Rows recorded as `client`'s answers from `tenure`, or the owner's rows
/// tagged by the tenure active at their invocation when both are `None`.
fn as_of(s: &mut Script, tenure: Option<Tenure>, client: Option<ClientId>) {
    s.in_tenure(tenure);
    s.by_client(client);
}

/// Activates each of `tenures` in order, none naming a cut.
fn activated(tenures: &[Tenure]) -> Script {
    let mut s = Script::new();
    for &tenure in tenures {
        s.activate(RECOVERED, Some(tenure), None);
    }
    s
}

/// T1 publishes A, client two accepts a miss from `high_water` when it
/// names one, T2 acknowledges client one's invalidation, and client two
/// reads A from T1 after that acknowledgment: legal while client two's
/// high-water is below the successor, and a high-water failure at T2.
pub(super) fn deposed_hit(high_water: Option<Tenure>) -> History {
    let mut s = activated(&[T1, T2]);
    as_of(&mut s, Some(T1), None);
    s.publish(K, A, BODY);
    if let Some(high_water) = high_water {
        as_of(&mut s, Some(high_water), Some(C2));
        s.lookup(J, MISSING, None);
    }
    as_of(&mut s, Some(T2), Some(C1));
    s.invalidate(K, ACK);
    as_of(&mut s, Some(T1), Some(C2));
    s.lookup(K, HIT, Some(A));
    s.finish()
}

pub(super) fn deposed_hit_below_successor() -> History {
    deposed_hit(Some(T1))
}

/// A, a miss while the store is unreachable, then a hit on A whose bytes
/// are A's, all in one tenure.
pub(super) fn outage_miss_then_hit() -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.lookup(K, MISSING, None);
    let hit = s.lookup(K, HIT, Some(A));
    s.deliver(hit, K, A, BODY, Outcome::Complete, bytes(K, A, BODY));
    s.finish()
}

/// The outage history with an invalidation acknowledged before the final
/// lookup is invoked.
pub(super) fn outage_covered_twin() -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.lookup(K, MISSING, None);
    s.invalidate(K, ACK);
    let hit = s.lookup(K, HIT, Some(A));
    s.deliver(hit, K, A, BODY, Outcome::Complete, bytes(K, A, BODY));
    s.finish()
}

/// A at version 1 replaced by B at version 2, a same-host restart, then a
/// hit on the older A.
fn older_version_after_restart() -> History {
    let mut s = Script::new();
    let mut publish = s.begin_publish(K, A, BODY, None);
    publish.set_version(1);
    s.close(publish, Some(ACK));
    let mut replace = s.begin_replace(K, B, BODY);
    replace.set_version(2);
    s.close(replace, Some(ACK));
    s.activate(RECOVERED, None, None);
    s.lookup(K, HIT, Some(A));
    s.finish()
}

/// Client two's lookup overlaps client one's acknowledged invalidation in
/// one tenure and answers A after the acknowledgment.
fn lookup_overlapping_invalidation() -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    as_of(&mut s, Some(Tenure::INITIAL), Some(C2));
    let lookup = s.begin_lookup(K, ClockSample::Seconds(1));
    as_of(&mut s, Some(Tenure::INITIAL), Some(C1));
    s.invalidate(K, ACK);
    s.end_lookup(lookup, HIT, Some(A));
    s.finish()
}

/// T1 acknowledges client one's publication of A, then T2 answers client
/// two's lookup with a miss.
fn deposed_fill_then_successor_miss() -> History {
    let mut s = activated(&[T1, T2]);
    as_of(&mut s, Some(T1), Some(C1));
    s.publish(K, A, BODY);
    as_of(&mut s, Some(T2), Some(C2));
    s.lookup(K, MISSING, None);
    s.finish()
}

/// T1 publishes A; client one's invalidation bound to T1 times out; T2
/// answers client two with A.
fn timed_out_invalidation_then_later_hit() -> History {
    let mut s = activated(&[T1, T2]);
    as_of(&mut s, Some(T1), None);
    s.publish(K, A, BODY);
    as_of(&mut s, Some(T1), Some(C1));
    let mut invalidate = s.begin_invalidate(K);
    invalidate.set_target(Place::In(T1));
    s.close(invalidate, Some(TIMED_OUT));
    as_of(&mut s, Some(T2), Some(C2));
    s.lookup(K, HIT, Some(A));
    s.finish()
}

/// T1 publishes A; client one accepts T2's miss, then its invalidation
/// bound to T1 times out when the client crashes; T1 then answers A to the
/// restarted instance when `restarted`, and to client one otherwise. A
/// crash leaves the invalidation unknown as a timeout does, and only the
/// restarted instance's absent high-water admits the T1 answer.
pub(super) fn crashed_client_then_hit(restarted: bool) -> History {
    let mut s = activated(&[T1, T2]);
    as_of(&mut s, Some(T1), None);
    s.publish(K, A, BODY);
    as_of(&mut s, Some(T2), Some(C1));
    s.lookup(J, MISSING, None);
    let mut invalidate = s.begin_invalidate(K);
    invalidate.set_target(Place::In(T1));
    s.close(invalidate, Some(TIMED_OUT));
    let reader = if restarted { C1_RESTARTED } else { C1 };
    as_of(&mut s, Some(T1), Some(reader));
    s.lookup(K, HIT, Some(A));
    s.finish()
}

/// Client one accepts T2's miss, then rejects T1's stale hit on A,
/// delivered `deliveries` times, each delivery its own lookup recording
/// high-water T2.
pub(super) fn rejected_below_high_water(deliveries: u32) -> History {
    let mut s = activated(&[T1, T2]);
    as_of(&mut s, Some(T1), None);
    s.publish(K, A, BODY);
    as_of(&mut s, Some(T2), Some(C1));
    s.lookup(K, MISSING, None);
    as_of(&mut s, Some(T1), Some(C1));
    for _ in 0..deliveries {
        s.reject_next();
        s.lookup(K, HIT, Some(A));
    }
    s.finish()
}

/// Client one accepts T1's miss, rejects T2's miss above its high-water,
/// then accepts T1's hit on A recording high-water T1: a rejection leaves
/// the high-water where it was.
fn rejected_above_high_water() -> History {
    let mut s = activated(&[T1, T2]);
    as_of(&mut s, Some(T1), None);
    s.publish(K, A, BODY);
    as_of(&mut s, Some(T1), Some(C1));
    s.lookup(J, MISSING, None);
    as_of(&mut s, Some(T2), Some(C1));
    s.reject_next();
    s.lookup(J, MISSING, None);
    as_of(&mut s, Some(T1), Some(C1));
    s.lookup(K, HIT, Some(A));
    s.finish()
}

/// Client one rejects T1's miss while its row records high-water T3, then
/// accepts T2's miss recording high-water T2: the recorded high-water fell
/// though the client accepted no T3 answer.
pub(super) fn recorded_high_water_fell() -> History {
    let mut s = activated(&[T1, T2, T3]);
    as_of(&mut s, Some(T1), Some(C1));
    s.reject_next();
    s.lookup(K, MISSING, None);
    as_of(&mut s, Some(T2), Some(C1));
    s.lookup(K, MISSING, None);
    super::golden::edited(&s.finish(), |rows| {
        for (row, recorded) in rows
            .iter_mut()
            .filter(|row| row.acceptance.is_some())
            .zip([T3, T2])
        {
            if let Some(acceptance) = row.acceptance.as_mut() {
                acceptance.high_water = Some(recorded);
            }
        }
    })
}

/// The rejection history, then client one accepts another T1 answer whose
/// row records high-water T1, below the T2 it kept.
pub(super) fn rejected_then_high_water_fell() -> History {
    let mut s = activated(&[T1, T2]);
    as_of(&mut s, Some(T1), None);
    s.publish(K, A, BODY);
    as_of(&mut s, Some(T2), Some(C1));
    s.lookup(K, MISSING, None);
    as_of(&mut s, Some(T1), Some(C1));
    s.reject_next();
    s.lookup(K, HIT, Some(A));
    s.lookup(K, MISSING, None);
    super::golden::edited(&s.finish(), |rows| {
        let last = rows.last_mut().expect("the second T1 answer");
        if let Some(acceptance) = last.acceptance.as_mut() {
            acceptance.high_water = Some(T1);
        }
    })
}

/// Client one rejects a hit on A, a label no fill published.
pub(super) fn rejected_unpublished_hit() -> History {
    let mut s = activated(&[T1]);
    as_of(&mut s, Some(T1), Some(C1));
    s.reject_next();
    s.lookup(K, HIT, Some(A));
    s.finish()
}

/// Client one accepts T2's miss, restarts, and its new instance accepts
/// T1's hit on A.
fn restarted_client_accepts_deposed() -> History {
    let mut s = activated(&[T1, T2]);
    as_of(&mut s, Some(T1), None);
    s.publish(K, A, BODY);
    as_of(&mut s, Some(T2), Some(C1));
    s.lookup(K, MISSING, None);
    as_of(&mut s, Some(T1), Some(C1_RESTARTED));
    s.lookup(K, HIT, Some(A));
    s.finish()
}

/// Every history `tenure_order_legal_cases` passes, by name.
pub(super) fn legal() -> Vec<(&'static str, History)> {
    vec![
        (
            "deposed hit below the successor",
            deposed_hit_below_successor(),
        ),
        ("miss then hit with no restart", outage_miss_then_hit()),
        (
            "older uncovered version after a restart",
            older_version_after_restart(),
        ),
        (
            "lookup overlapping an invalidation",
            lookup_overlapping_invalidation(),
        ),
        (
            "deposed fill then successor miss",
            deposed_fill_then_successor_miss(),
        ),
        (
            "timed-out invalidation then later hit",
            timed_out_invalidation_then_later_hit(),
        ),
        (
            "restarted client accepts a deposed tenure",
            restarted_client_accepts_deposed(),
        ),
        ("crashed client then hit", crashed_client_then_hit(true)),
        (
            "stale route publication lands in its bound tenure",
            stale_route_publication(),
        ),
        (
            "client rejects a response below its high-water",
            rejected_below_high_water(1),
        ),
        (
            "client rejects a duplicated stale response",
            rejected_below_high_water(2),
        ),
        (
            "client rejects a response above its high-water",
            rejected_above_high_water(),
        ),
        (
            "a later tenure evicts while an earlier tenure's fill is open",
            eviction_after_fill_tenure(),
        ),
    ]
}

/// Client one's acknowledged invalidation, then client two's hit on the
/// covered A invoked after it.
pub(super) fn covered_hit_by_another_client() -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    as_of(&mut s, Some(Tenure::INITIAL), Some(C1));
    s.invalidate(K, ACK);
    as_of(&mut s, Some(Tenure::INITIAL), Some(C2));
    s.lookup(K, HIT, Some(A));
    s.finish()
}

/// T2's invalidation and T3's lookup are both invoked before the
/// invalidation's acknowledgment; T3 answers the covered A.
pub(super) fn covered_hit_from_later_tenure() -> History {
    let mut s = activated(&[T1, T2, T3]);
    as_of(&mut s, Some(T1), None);
    s.publish(K, A, BODY);
    as_of(&mut s, Some(T2), Some(C1));
    let invalidate = s.begin_invalidate(K);
    as_of(&mut s, Some(T3), Some(C2));
    let lookup = s.begin_lookup(K, ClockSample::Seconds(1));
    s.close(invalidate, Some(ACK));
    s.end_lookup(lookup, HIT, Some(A));
    s.finish()
}

/// Client one's invalidation sent and acknowledged twice, then client two's
/// hit on the covered A.
pub(super) fn duplicated_invalidation_then_hit() -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    as_of(&mut s, Some(Tenure::INITIAL), Some(C1));
    s.invalidate(K, ACK);
    s.invalidate(K, ACK);
    as_of(&mut s, Some(Tenure::INITIAL), Some(C2));
    s.lookup(K, HIT, Some(A));
    s.finish()
}

/// Client one publishes A, invalidates it, then reads the covered A.
pub(super) fn covered_hit_by_the_same_client() -> History {
    let mut s = Script::new();
    as_of(&mut s, Some(Tenure::INITIAL), Some(C1));
    s.publish(K, A, BODY);
    s.invalidate(K, ACK);
    s.lookup(K, HIT, Some(A));
    s.finish()
}

/// `history` declared with per-client ordinals.
pub(super) fn per_client(mut history: History) -> History {
    history.ordered_by(Ordinals::PerClient);
    history
}

/// An acknowledged invalidation of A, a restart, then a hit on A.
pub(super) fn covered_hit_after_restart() -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.invalidate(K, ACK);
    s.activate(RECOVERED, None, None);
    s.lookup(K, HIT, Some(A));
    s.finish()
}

/// Client one accepts T2's miss, then accepts T1's hit on A. When
/// `recorded` names a high-water, the hit's row records it in place of the
/// client's real high-water, T2.
pub(super) fn accepted_below_high_water(recorded: Option<Tenure>) -> History {
    let mut s = activated(&[T1, T2]);
    as_of(&mut s, Some(T1), None);
    s.publish(K, A, BODY);
    as_of(&mut s, Some(T2), Some(C1));
    s.lookup(K, MISSING, None);
    as_of(&mut s, Some(T1), Some(C1));
    s.lookup(K, HIT, Some(A));
    super::golden::edited(&s.finish(), |rows| {
        if let Some(recorded) = recorded {
            let hit = rows
                .iter_mut()
                .rfind(|row| row.outcome == Some(HIT))
                .expect("the hit");
            if let Some(acceptance) = hit.acceptance.as_mut() {
                acceptance.high_water = Some(recorded);
            }
        }
    })
}

/// How client one receives a lower tenure's answer after accepting a
/// higher tenure's miss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LowerAnswer {
    /// T1's miss recorded as recovery evidence after T2's.
    Recovered,
    /// T1's contended reply after T2's miss.
    Contended,
    /// T1's miss after the miss of T1's reattached generation.
    Reattached,
}

impl LowerAnswer {
    pub(super) const ALL: [Self; 3] = [Self::Recovered, Self::Contended, Self::Reattached];
}

/// Client one accepts the higher tenure's miss, then accepts the lower
/// tenure's answer `answer` names.
pub(super) fn lower_answer_accepted(answer: LowerAnswer) -> History {
    let high = if answer == LowerAnswer::Reattached {
        T1_REATTACHED
    } else {
        T2
    };
    let mut s = activated(&[T1, high]);
    as_of(&mut s, Some(high), Some(C1));
    s.lookup(K, MISSING, None);
    as_of(&mut s, Some(T1), Some(C1));
    match answer {
        LowerAnswer::Recovered => s.recovered_lookup(RECOVERED, K, MISSING, None),
        LowerAnswer::Contended => {
            s.lookup(K, Outcome::NoInformation(NoInformation::Contended), None);
        }
        LowerAnswer::Reattached => {
            s.lookup(K, MISSING, None);
        }
    }
    s.finish()
}

/// T1 publishes A and storage holds it in a slot; after T2 activates, T1
/// releases the slot by eviction, and client two reads A from `hit_from`.
/// The release's visibility end belongs to T1's segment.
pub(super) fn deposed_slot_eviction(hit_from: Tenure) -> History {
    let mut s = activated(&[T1, T2]);
    as_of(&mut s, Some(T1), None);
    s.publish(K, A, BODY);
    s.hold_slot(3, (K, A));
    s.end_slot_visibility(3, (K, A), VisibilityCause::Eviction);
    as_of(&mut s, Some(hit_from), Some(C2));
    s.lookup(K, HIT, Some(A));
    s.finish()
}

/// A published, B's fill acknowledged and live, an invalidation of K that
/// times out, then A's visibility end by eviction. Only the invalidation's
/// landed branch clears B's fill before the end.
pub(super) fn eviction_after_pending_invalidation() -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.fill(K, B, BODY);
    let invalidation = s.begin_invalidate(K);
    s.close_custody(invalidation, TIMED_OUT);
    s.ended(K, A, VisibilityCause::Eviction);
    s.finish()
}

/// B's fill is live when an invalidation of version two is acknowledged;
/// B then publishes at `version` and is read.
pub(super) fn range_over_live_fill(version: u64) -> History {
    let mut s = Script::new();
    let fill = s.fill(K, B, BODY);
    let mut invalidation = s.begin_invalidate(K);
    invalidation.set_covers(Cover::Range { lo: 2, hi: 2 });
    s.close(invalidation, Some(ACK));
    let mut publish = s.open(fill, ActionKind::Publish, K, Some(B));
    publish.set_version(version);
    s.close(publish, Some(ACK));
    s.lookup(K, HIT, Some(B));
    s.finish()
}

/// A's fill is live when an unversioned invalidation of K is acknowledged
/// and revokes it; a second fill of A then publishes and is read.
pub(super) fn refilled_after_invalidation() -> History {
    let mut s = Script::new();
    s.fill(K, A, BODY);
    s.invalidate(K, ACK);
    s.publish(K, A, BODY);
    s.lookup(K, HIT, Some(A));
    s.finish()
}

/// A published, an invalidation of K acknowledged, then a recorded
/// eviction of A, which the invalidation already removed.
pub(super) fn eviction_of_covered_label() -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.invalidate(K, ACK);
    s.evict(K, A);
    s.finish()
}

/// T1 publishes A with a deadline at second five; T2, or T1 when
/// `!activated_later`, records A's expiry at second three, before that
/// deadline in T1's clock domain.
pub(super) fn expiry_across_activation(activated_later: bool) -> History {
    let mut s = activated(&[T1, T2]);
    as_of(&mut s, Some(T1), None);
    let publish = s.begin_publish(K, A, BODY, Some(5));
    s.close(publish, Some(ACK));
    as_of(&mut s, Some(if activated_later { T2 } else { T1 }), None);
    s.expire(K, A, 3);
    s.finish()
}

/// T1 publishes A with a deadline at second five; T2, or T1 when
/// `!activated_later`, records A's visibility end by expiry with no sample
/// at or past that deadline in T1's clock domain. When `recorded` is false
/// the end carries no information.
pub(super) fn expiry_end_across_activation(activated_later: bool, recorded: bool) -> History {
    let mut s = activated(&[T1, T2]);
    as_of(&mut s, Some(T1), None);
    let publish = s.begin_publish(K, A, BODY, Some(5));
    s.close(publish, Some(ACK));
    as_of(&mut s, Some(if activated_later { T2 } else { T1 }), None);
    if !recorded {
        s.without_information_next();
    }
    s.ended(K, A, VisibilityCause::Expiry);
    s.finish()
}

/// T1 activated; client one fills A in T1, T1 acknowledges a close, and
/// the client's publication of A with an unrecorded target times out after
/// T2 activates; client two then reads A from T2. The publication lands
/// only in its fill's segment, which closed before it was sent, so no
/// tenure published A.
pub(super) fn publication_after_fill_tenure_closed() -> History {
    let mut s = activated(&[T1]);
    as_of(&mut s, Some(T1), Some(C1));
    let fill = s.fill(K, A, BODY);
    as_of(&mut s, Some(T1), None);
    s.close_cache(ACK);
    as_of(&mut s, Some(T1), Some(C1));
    let publish = s.open(fill, ActionKind::Publish, K, Some(A));
    s.activate(RECOVERED, Some(T2), None);
    as_of(&mut s, Some(T1), Some(C1));
    s.close_custody(publish, TIMED_OUT);
    as_of(&mut s, Some(T2), Some(C2));
    s.lookup(K, HIT, Some(A));
    s.finish()
}

/// [`invalidation_landing_after_close`] with the invalidation's floor
/// recorded as T2: tagged T1, it lands only in T2, whose cache never
/// closed.
pub(super) fn invalidation_floor_above_tag_after_close() -> History {
    let mut s = activated(&[T1]);
    as_of(&mut s, Some(T1), None);
    s.publish(K, A, BODY);
    as_of(&mut s, Some(T1), Some(C1));
    s.lookup(J, MISSING, None);
    as_of(&mut s, Some(T1), None);
    s.close_cache(ACK);
    s.activate(RECOVERED, Some(T2), None);
    as_of(&mut s, Some(T2), Some(C2));
    s.fill(K, C, BODY);
    as_of(&mut s, Some(T1), Some(C1));
    let mut invalidation = s.begin_invalidate(K);
    invalidation.set_target(Place::AtLeast(T2));
    s.close_custody(invalidation, TIMED_OUT);
    as_of(&mut s, Some(T2), None);
    s.ended(K, A, VisibilityCause::Eviction);
    s.finish()
}

/// T1 publishes C on J and delivers it as B's bytes after the unplaced
/// expiry end of [`expiry_end_after_pending_sample`]: the bytes violation
/// holds whatever the end's landing.
pub(super) fn unplaced_then_wrong_bytes() -> History {
    let mut s = pending_sample_script(None, true);
    as_of(&mut s, Some(T1), None);
    s.publish(J, C, BODY);
    let hit = s.lookup(J, HIT, Some(C));
    s.deliver(hit, J, C, BODY, Outcome::Complete, bytes(J, B, BODY));
    s.finish()
}

/// A restore of A, which no fill published, from the cut T1 names.
pub(super) fn restore_of_unpublished() -> History {
    let mut s = Script::new();
    s.activate(RECOVERED, Some(T1), Some(CUT));
    s.restore(K, A, CUT);
    s.finish()
}

/// T1 answers B to client one, then T2 publishes B.
pub(super) fn deposed_serves_later_fill() -> History {
    let mut s = activated(&[T1, T2]);
    as_of(&mut s, Some(T1), Some(C1));
    s.lookup(K, HIT, Some(B));
    as_of(&mut s, Some(T2), None);
    s.publish(K, B, BODY);
    s.finish()
}

/// The unrecorded-target expiry end after a restart, then a hit on J of
/// C, which no fill published: J's violation holds whatever the end's
/// landing.
pub(super) fn unplaced_then_unpublished_hit() -> History {
    let mut s = pending_sample_script(None, true);
    s.lookup(J, HIT, Some(C));
    s.finish()
}

/// T1 and T2 activated; T1 publishes A with a deadline at second five,
/// client one, at high-water T1, sends a publication of B on J sampled at
/// second ten with an unrecorded target, which times out, and T1 records
/// A's visibility end by expiry. The end's clock depends on whether the
/// publication lands in T1 or T2.
pub(super) fn unplaced_sample_at_collapse() -> History {
    unplaced_sample_at_collapse_script().finish()
}

/// [`unplaced_sample_at_collapse`], then T1 reads a label on K at second
/// eleven that no fill published: K's violation holds whatever the end's
/// landing, in the whole check and after a collapse met the uncertainty.
pub(super) fn unplaced_sample_at_collapse_then_unpublished_hit() -> History {
    let mut s = unplaced_sample_at_collapse_script();
    as_of(&mut s, Some(T1), None);
    let hit = s.begin_lookup(K, ClockSample::Seconds(11));
    s.end_lookup(hit, HIT, Some(Label(7)));
    s.finish()
}

fn unplaced_sample_at_collapse_script() -> Script {
    let mut s = activated(&[T1, T2]);
    as_of(&mut s, Some(T1), None);
    let publish = s.begin_publish(K, A, BODY, Some(5));
    s.close(publish, Some(ACK));
    as_of(&mut s, Some(T1), Some(C1));
    s.fill(J, C, BODY);
    let mut pending = s.begin_publish(J, B, BODY, None);
    pending.set_clock(ClockSample::Seconds(10));
    s.close_custody(pending, TIMED_OUT);
    as_of(&mut s, Some(T1), None);
    s.ended(K, A, VisibilityCause::Expiry);
    s
}

/// T1 and T2 activated; client one fills A in T1, sends its publication
/// with an unrecorded target, accepts a T2 miss while it is outstanding,
/// and client two reads A from T1. The floor is the high-water at send,
/// T1, so the publication lands in T1.
pub(super) fn floor_taken_at_send() -> History {
    let mut s = activated(&[T1, T2]);
    as_of(&mut s, Some(T1), Some(C1));
    let fill = s.fill(K, A, BODY);
    let publish = s.open(fill, ActionKind::Publish, K, Some(A));
    as_of(&mut s, Some(T2), Some(C1));
    s.lookup(J, MISSING, None);
    s.close_custody(publish, TIMED_OUT);
    as_of(&mut s, Some(T1), Some(C2));
    s.lookup(K, HIT, Some(A));
    s.finish()
}

/// T1 activated; client one's miss records a high-water of T9, which no
/// activation names.
pub(super) fn unlogged_high_water() -> History {
    let mut s = activated(&[T1]);
    as_of(&mut s, Some(T1), Some(C1));
    s.lookup(K, MISSING, None);
    super::golden::edited(&s.finish(), |rows| {
        let miss = rows
            .iter_mut()
            .rfind(|row| row.kind == ActionKind::Lookup)
            .expect("the miss");
        if let Some(acceptance) = miss.acceptance.as_mut() {
            acceptance.high_water = Some(T9);
        }
    })
}

/// A published and T1 activated from `CUT`, which no capture recorded; T1
/// restores A from it.
pub(super) fn restore_from_uncaptured_cut() -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.activate(RECOVERED, Some(T1), Some(CUT));
    s.restore(K, A, CUT);
    s.finish()
}

/// T1 activated; client one fills B in T1, client two misses K at second
/// five, then client one sends an invalidation of K and a publication of
/// B sampled at second twenty, both with unrecorded targets; the
/// publication times out, T2 activates, the invalidation times out, and
/// client two misses J in T1. The miss on K precedes the publication in
/// T1, and the invalidation may land in T1 or T2.
pub(super) fn unbound_effect_after_held_miss() -> History {
    let mut s = activated(&[T1]);
    as_of(&mut s, Some(T1), Some(C1));
    let fill = s.fill(K, B, BODY);
    as_of(&mut s, Some(T1), Some(C2));
    let miss = s.begin_lookup(K, ClockSample::Seconds(5));
    s.end_lookup(miss, MISSING, None);
    as_of(&mut s, Some(T1), Some(C1));
    let invalidation = s.begin_invalidate(K);
    let mut publish = s.open(fill, ActionKind::Publish, K, Some(B));
    publish.set_clock(ClockSample::Seconds(20));
    s.close_custody(publish, TIMED_OUT);
    s.activate(RECOVERED, Some(T2), None);
    as_of(&mut s, Some(T1), Some(C1));
    s.close_custody(invalidation, TIMED_OUT);
    as_of(&mut s, Some(T1), Some(C2));
    s.lookup(J, MISSING, None);
    s.finish()
}

/// T1 publishes A, client one accepts a T1 miss, T1 acknowledges a close,
/// and T2 activates; client two's fill of C is acknowledged by T2, client
/// one's invalidation of K with an unrecorded target times out, and T2
/// records A's visibility end by eviction. T1's close leaves the
/// invalidation's T2 landing open, the one branch that clears C's fill
/// before the end.
pub(super) fn invalidation_landing_after_close() -> History {
    let mut s = activated(&[T1]);
    as_of(&mut s, Some(T1), None);
    s.publish(K, A, BODY);
    as_of(&mut s, Some(T1), Some(C1));
    s.lookup(J, MISSING, None);
    as_of(&mut s, Some(T1), None);
    s.close_cache(ACK);
    s.activate(RECOVERED, Some(T2), None);
    as_of(&mut s, Some(T2), Some(C2));
    s.fill(K, C, BODY);
    as_of(&mut s, Some(T1), Some(C1));
    let invalidation = s.begin_invalidate(K);
    s.close_custody(invalidation, TIMED_OUT);
    as_of(&mut s, Some(T2), None);
    s.ended(K, A, VisibilityCause::Eviction);
    s.finish()
}

/// T1 activated; client one's fill of B is acknowledged by the initial
/// tenure; T1 publishes A and C, both captured in `CUT`; the client then
/// sends its replacement of A by B with an unrecorded target, tagged T1,
/// which times out; T2 activates from `CUT` and restores C. The
/// replacement lands only in its fill's segment, below A's, so T2 lost A.
pub(super) fn superseded_by_earlier_tenure_fill() -> History {
    let mut s = activated(&[T1]);
    as_of(&mut s, Some(Tenure::INITIAL), Some(C1));
    let fill = s.fill(K, B, BODY);
    as_of(&mut s, Some(T1), None);
    s.publish(K, A, BODY);
    s.publish(J, C, BODY);
    s.captured(RECOVERED, (K, A), CUT, (0, 1));
    s.captured(RECOVERED, (J, C), CUT, (0, 2));
    as_of(&mut s, Some(T1), Some(C1));
    let replace = s.open(fill, ActionKind::Replace, K, Some(B));
    s.close_custody(replace, TIMED_OUT);
    s.activate(RECOVERED, Some(T2), Some(CUT));
    as_of(&mut s, None, None);
    s.restore(J, C, CUT);
    s.finish()
}

/// T2 publishes B, then T1 answers B.
pub(super) fn deposed_serves_successor_fill() -> History {
    let mut s = activated(&[T1, T2]);
    as_of(&mut s, Some(T2), None);
    s.publish(K, B, BODY);
    as_of(&mut s, Some(T1), Some(C1));
    s.lookup(K, HIT, Some(B));
    s.finish()
}

/// A hit on A that delivers B's bytes.
pub(super) fn wrong_bytes() -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let hit = s.lookup(K, HIT, Some(A));
    s.deliver(hit, K, A, BODY, Outcome::Complete, bytes(K, B, BODY));
    s.finish()
}

/// A hit on A after A's fill only, or after A's refused publication.
pub(super) fn unpublished_hit(refused: bool) -> History {
    let mut s = Script::new();
    if refused {
        let publish = s.begin_publish(K, A, BODY, None);
        s.close(publish, Some(REFUSED));
    } else {
        s.fill(K, A, BODY);
    }
    s.lookup(K, HIT, Some(A));
    s.finish()
}

/// A with a deadline at second five, then a hit sampled at second five.
pub(super) fn hit_at_deadline() -> History {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, Some(5));
    s.close(publish, Some(ACK));
    let lookup = s.begin_lookup(K, ClockSample::Seconds(5));
    s.end_lookup(lookup, HIT, Some(A));
    s.finish()
}

/// T1 is activated, and client one's miss is tagged T2.
pub(super) fn unlogged_tag() -> History {
    let mut s = activated(&[T1]);
    as_of(&mut s, Some(T2), Some(C1));
    s.lookup(K, MISSING, None);
    s.finish()
}

/// A at version 1, an acknowledged invalidation of the absent version 2,
/// then B at version 2 and a hit on B.
pub(super) fn absent_version_covered() -> History {
    let mut s = Script::new();
    let mut publish = s.begin_publish(K, A, BODY, None);
    publish.set_version(1);
    s.close(publish, Some(ACK));
    let mut invalidate = s.begin_invalidate(K);
    invalidate.set_covers(Cover::Range { lo: 2, hi: 2 });
    s.close(invalidate, Some(ACK));
    let mut replace = s.begin_replace(K, B, BODY);
    replace.set_version(2);
    s.close(replace, Some(ACK));
    s.lookup(K, HIT, Some(B));
    s.finish()
}

/// A at version 1 and C at version 3 around an invalidation of version 2,
/// then hits on A and C.
pub(super) fn versions_outside_the_interval() -> History {
    let mut s = Script::new();
    let mut publish = s.begin_publish(K, A, BODY, None);
    publish.set_version(1);
    s.close(publish, Some(ACK));
    let mut replace = s.begin_replace(K, C, BODY);
    replace.set_version(3);
    s.close(replace, Some(ACK));
    let mut invalidate = s.begin_invalidate(K);
    invalidate.set_covers(Cover::Range { lo: 2, hi: 2 });
    s.close(invalidate, Some(ACK));
    s.lookup(K, HIT, Some(A));
    s.lookup(K, HIT, Some(C));
    s.finish()
}

/// A at version 1 and B at version 2, an invalidation of every version,
/// then a hit on `label`.
pub(super) fn all_versions_covered(label: Label) -> History {
    let mut s = Script::new();
    let mut publish = s.begin_publish(K, A, BODY, None);
    publish.set_version(1);
    s.close(publish, Some(ACK));
    let mut replace = s.begin_replace(K, B, BODY);
    replace.set_version(2);
    s.close(replace, Some(ACK));
    let mut invalidate = s.begin_invalidate(K);
    invalidate.set_covers(Cover::All);
    s.close(invalidate, Some(ACK));
    s.lookup(K, HIT, Some(label));
    s.finish()
}

/// An invalidation of every version, then a later publication of B, at
/// version 3 when `versioned`, and a hit on B.
pub(super) fn all_versions_then_later_publication(versioned: bool) -> History {
    let mut s = Script::new();
    let mut invalidate = s.begin_invalidate(K);
    invalidate.set_covers(Cover::All);
    s.close(invalidate, Some(ACK));
    let mut publish = s.begin_publish(K, B, BODY, None);
    if versioned {
        publish.set_version(3);
    }
    s.close(publish, Some(ACK));
    s.lookup(K, HIT, Some(B));
    s.finish()
}

/// An unversioned invalidation of an empty key, then B and a hit on B.
pub(super) fn unversioned_then_later_publication() -> History {
    let mut s = Script::new();
    s.invalidate(K, ACK);
    s.publish(K, B, BODY);
    s.lookup(K, HIT, Some(B));
    s.finish()
}

/// How a recorded row ends A's residency in its tenure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Removal {
    Evict,
    Expire,
    Ended(VisibilityCause),
}

impl Removal {
    pub(super) const ALL: [Self; 6] = [
        Self::Evict,
        Self::Expire,
        Self::Ended(VisibilityCause::CollisionCollateral),
        Self::Ended(VisibilityCause::Eviction),
        Self::Ended(VisibilityCause::Expiry),
        Self::Ended(VisibilityCause::GraceEnd),
    ];
}

/// A, `removal` of A, a restart when `restarted`, then a hit on A sampled
/// at second one. A has a deadline at second one only when an expiry
/// removes it.
pub(super) fn removal_then_hit(removal: Removal, restarted: bool) -> History {
    let mut s = Script::new();
    let expiring = matches!(
        removal,
        Removal::Expire | Removal::Ended(VisibilityCause::Expiry)
    );
    let publish = s.begin_publish(K, A, BODY, expiring.then_some(1));
    s.close(publish, Some(ACK));
    match removal {
        Removal::Evict => s.evict(K, A),
        Removal::Expire => s.expire(K, A, 1),
        Removal::Ended(VisibilityCause::Expiry) => {
            s.expire(K, A, 1);
            s.ended(K, A, VisibilityCause::Expiry);
        }
        Removal::Ended(cause) => s.ended(K, A, cause),
    }
    if restarted {
        s.activate(RECOVERED, None, None);
    }
    s.lookup(K, HIT, Some(A));
    s.finish()
}

/// How a recorded restore departs from an uncovered entry of the named cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Restored {
    /// The restore names the activation's cut and a hit follows.
    Uncovered,
    /// An acknowledged invalidation covers A before the activation; no hit
    /// follows the restore.
    Covered,
    /// The restore names a cut the activation did not name.
    OtherCut,
    /// A restore, an eviction, a second restore, then a hit.
    AgainAfterEviction,
}

impl Restored {
    pub(super) const ALL: [Self; 4] = [
        Self::Uncovered,
        Self::Covered,
        Self::OtherCut,
        Self::AgainAfterEviction,
    ];
}

/// A captured in `CUT`, then T1 activated from `CUT` and restoring A as
/// `restored` names.
pub(super) fn restored(restored: Restored) -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.captured(RECOVERED, (K, A), CUT, (0, 1));
    if restored == Restored::Covered {
        s.invalidate(K, ACK);
    }
    s.activate(RECOVERED, Some(T1), Some(CUT));
    let named = if restored == Restored::OtherCut {
        OTHER_CUT
    } else {
        CUT
    };
    s.restore(K, A, named);
    if restored == Restored::AgainAfterEviction {
        s.evict(K, A);
        s.restore(K, A, CUT);
    }
    if restored != Restored::Covered {
        s.lookup(K, HIT, Some(A));
    }
    s.finish()
}

/// Where the pending publication of B is placed against a hit on B.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Pending {
    /// Filled in T1 and bound to T2; the hit comes from T1.
    BoundLater,
    /// Filled in and bound to T2; the hit comes from T2.
    BoundSame,
    /// Filled in T1 with an unrecorded target at or above T1; the hit comes
    /// from T1.
    Unrecorded,
    /// Filled in T1 with an unrecorded target at or above T2; the hit comes
    /// from T1.
    UnrecordedAboveHit,
    /// Filled in and bound to T1; the hit responds before the publication
    /// is invoked.
    BoundBeforeInvocation,
    /// Filled in T1 with no recorded target or floor after client one
    /// accepted a T2 answer; the hit comes from T1.
    UnrecordedAboveHighWater,
    /// Filled in T1 with a recorded floor of T1 after client one accepted
    /// a T2 answer; the hit comes from T1.
    FloorBelowHighWater,
}

impl Pending {
    pub(super) const ALL: [Self; 7] = [
        Self::BoundLater,
        Self::BoundSame,
        Self::Unrecorded,
        Self::UnrecordedAboveHit,
        Self::BoundBeforeInvocation,
        Self::UnrecordedAboveHighWater,
        Self::FloorBelowHighWater,
    ];
}

/// T1 and T2 activated, client one's timed-out publication of B placed as
/// `pending` names, and client two's hit on B. A fill publishes only in
/// the tenure that acknowledged it, and a publication with no recorded
/// target lands at or above the client's high-water at send.
pub(super) fn targeted_publication(pending: Pending) -> History {
    let mut s = activated(&[T1, T2]);
    let (filled_in, target, hit_from) = match pending {
        Pending::BoundLater => (T1, Some(Place::In(T2)), T1),
        Pending::BoundSame => (T2, Some(Place::In(T2)), T2),
        Pending::Unrecorded => (T1, Some(Place::AtLeast(T1)), T1),
        Pending::UnrecordedAboveHit => (T1, Some(Place::AtLeast(T2)), T1),
        Pending::BoundBeforeInvocation => (T1, Some(Place::In(T1)), T1),
        Pending::UnrecordedAboveHighWater => (T1, None, T1),
        Pending::FloorBelowHighWater => (T1, Some(Place::AtLeast(T1)), T1),
    };
    if pending == Pending::BoundBeforeInvocation {
        as_of(&mut s, Some(hit_from), Some(C2));
        s.lookup(K, HIT, Some(B));
    }
    as_of(&mut s, Some(filled_in), Some(C1));
    let fill = s.fill(K, B, BODY);
    if matches!(
        pending,
        Pending::UnrecordedAboveHighWater | Pending::FloorBelowHighWater
    ) {
        as_of(&mut s, Some(T2), Some(C1));
        s.lookup(J, MISSING, None);
    }
    let mut publish = s.open(fill, ActionKind::Publish, K, Some(B));
    if let Some(target) = target {
        publish.set_target(target);
    }
    s.close(publish, Some(TIMED_OUT));
    if pending != Pending::BoundBeforeInvocation {
        as_of(&mut s, Some(hit_from), Some(C2));
        s.lookup(K, HIT, Some(B));
    }
    s.finish()
}

/// T1 acknowledges client one's fill of A; after T2 activates, the client's
/// stale route sends the publication bound to T1, which times out; T2
/// misses before and hits A after the publication's invocation.
pub(super) fn stale_route_publication() -> History {
    let mut s = activated(&[T1, T2]);
    as_of(&mut s, Some(T1), Some(C1));
    let fill = s.fill(K, A, BODY);
    as_of(&mut s, Some(T2), Some(C2));
    s.lookup(K, MISSING, None);
    as_of(&mut s, Some(T2), Some(C1));
    let mut publish = s.open(fill, ActionKind::Publish, K, Some(A));
    publish.set_target(Place::In(T1));
    s.close(publish, Some(TIMED_OUT));
    as_of(&mut s, Some(T2), Some(C2));
    s.lookup(K, HIT, Some(A));
    s.finish()
}

/// The stale route with an unrecorded target at or above T1: the
/// publication samples second fifty and carries a deadline at second one
/// hundred, and the lookups around it sample second one. It lands only in
/// T1, where its fill is live, so its sample and deadline belong to T1's
/// clock and T2's hit leaves the deadline unjudged.
pub(super) fn unrecorded_route_publication() -> History {
    let mut s = activated(&[T1, T2]);
    as_of(&mut s, Some(T1), Some(C1));
    let fill = s.fill(K, A, BODY);
    as_of(&mut s, Some(T2), Some(C2));
    let miss = s.begin_lookup(K, ClockSample::Seconds(1));
    s.end_lookup(miss, MISSING, None);
    as_of(&mut s, Some(T2), Some(C1));
    let mut publish = s.open(fill, ActionKind::Publish, K, Some(A));
    publish.set_target(Place::AtLeast(T1));
    publish.set_deadline(100);
    publish.set_clock(ClockSample::Seconds(50));
    s.close(publish, Some(TIMED_OUT));
    as_of(&mut s, Some(T2), Some(C2));
    s.lookup(K, HIT, Some(A));
    s.finish()
}

/// Whether the other key's sample in [`unbound_sample_beside_other_key`]
/// follows the publication's timeout or precedes its invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Beside {
    After,
    Before,
}

/// A later T1 hit forces the publication's landing into T1, so its sample
/// and a sample on another key at second `other` share T1's clock.
pub(super) fn unbound_sample_beside_other_key(
    target: Place,
    beside: Beside,
    other: u64,
) -> History {
    let mut s = activated(&[T1, T2]);
    as_of(&mut s, Some(T1), Some(C1));
    let fill = s.fill(K, A, BODY);
    let miss_on_j = |s: &mut Script| {
        let miss = s.begin_lookup(J, ClockSample::Seconds(other));
        s.end_lookup(miss, MISSING, None);
    };
    if beside == Beside::Before {
        miss_on_j(&mut s);
    }
    let mut publish = s.open(fill, ActionKind::Publish, K, Some(A));
    publish.set_target(target);
    publish.set_clock(ClockSample::Seconds(match beside {
        Beside::After => 50,
        Beside::Before => 1,
    }));
    s.close_custody(publish, TIMED_OUT);
    if beside == Beside::After {
        miss_on_j(&mut s);
    }
    let hit = s.begin_lookup(K, ClockSample::Seconds(60));
    s.end_lookup(hit, HIT, Some(A));
    s.finish()
}

/// T1 samples second fifty before the publication samples second one, so
/// a valid placement requires a later tenure admitted by `target` among
/// `tenures`.
pub(super) fn unbound_effect_sampled_below_its_floor(target: Place, tenures: &[Tenure]) -> History {
    let mut s = activated(tenures);
    as_of(&mut s, Some(T1), Some(C1));
    let fill = s.fill(K, A, BODY);
    let miss = s.begin_lookup(K, ClockSample::Seconds(50));
    s.end_lookup(miss, MISSING, None);
    let mut publish = s.open(fill, ActionKind::Publish, K, Some(A));
    publish.set_target(target);
    publish.set_clock(ClockSample::Seconds(1));
    s.close_custody(publish, TIMED_OUT);
    s.finish()
}

/// T1 publishes A; client one's invalidation with an unrecorded target
/// times out and its custody ends while client two's fill of B, which T2
/// answers, is in flight; client two then reads A from T1, T2 activates
/// and records A's visibility end by eviction while B's fill is current.
/// Only a landing in T2, activated after the invalidation's window ended,
/// would clear B's fill before that end without covering T1's hit.
pub(super) fn landing_after_window() -> History {
    let mut s = activated(&[T1]);
    as_of(&mut s, Some(T1), None);
    s.publish(K, A, BODY);
    as_of(&mut s, Some(T2), Some(C2));
    let fill = s.begin_fill(K, B, BODY);
    as_of(&mut s, Some(T1), Some(C1));
    let invalidate = s.begin_invalidate(K);
    s.close_custody(invalidate, TIMED_OUT);
    as_of(&mut s, Some(T1), Some(C2));
    s.lookup(K, HIT, Some(A));
    s.activate(RECOVERED, Some(T2), None);
    as_of(&mut s, Some(T2), Some(C2));
    s.close(fill, Some(ACK));
    as_of(&mut s, Some(T2), None);
    s.ended(K, A, VisibilityCause::Eviction);
    s.finish()
}

/// T1 acknowledges client one's fill of A, then T2 acknowledges its
/// publication.
pub(super) fn fill_published_by_successor() -> History {
    let mut s = activated(&[T1, T2]);
    as_of(&mut s, Some(T1), Some(C1));
    let fill = s.fill(K, A, BODY);
    as_of(&mut s, Some(T2), Some(C1));
    let publish = s.open(fill, ActionKind::Publish, K, Some(A));
    s.close(publish, Some(ACK));
    s.finish()
}

/// T1 and T2 activated; T1 acknowledges client one's fills of A and B,
/// then the client's timed-out publications of A, sampled at second
/// twenty, and of B, sampled at `second` and invoked after A's landing
/// window ended, both with unrecorded targets; client two then reads A and
/// B from T1 at second thirty. Both land only in T1, where real time
/// orders A's before B's, so a second below twenty regressed.
pub(super) fn unbound_publications_in_order(second: u64) -> History {
    let mut s = activated(&[T1, T2]);
    as_of(&mut s, Some(T1), Some(C1));
    let fills = [s.fill(K, A, BODY), s.fill(K, B, BODY)];
    for (fill, (label, sample)) in fills.into_iter().zip([(A, 20), (B, second)]) {
        let mut publish = s.open(fill, ActionKind::Publish, K, Some(label));
        publish.set_clock(ClockSample::Seconds(sample));
        s.close_custody(publish, TIMED_OUT);
    }
    as_of(&mut s, Some(T1), Some(C2));
    for label in [A, B] {
        let lookup = s.begin_lookup(K, ClockSample::Seconds(30));
        s.end_lookup(lookup, HIT, Some(label));
    }
    s.finish()
}

/// [`unbound_publications_in_order`] across two keys: T1 acknowledges
/// client one's fills of A on K and C on J, then the client's timed-out
/// publications of A, sampled at second twenty, and of C, sampled at
/// `second` and invoked after A's landing window ended, both with
/// unrecorded targets; client two then reads A and C from T1 at second
/// thirty. Each key's search places its publication alone, so a second
/// below twenty is a regression no search compares. With `separated`, a
/// T1 miss on K sampled at second twenty between the two publications
/// bounds C's T1 placement from below.
pub(super) fn unbound_publications_across_keys(second: u64, separated: bool) -> History {
    let mut s = activated(&[T1, T2]);
    as_of(&mut s, Some(T1), Some(C1));
    let fills = [s.fill(K, A, BODY), s.fill(J, C, BODY)];
    for (fill, (key, label, sample)) in fills.into_iter().zip([(K, A, 20), (J, C, second)]) {
        if separated && key == J {
            let miss = s.begin_lookup(K, ClockSample::Seconds(20));
            s.end_lookup(miss, MISSING, None);
        }
        let mut publish = s.open(fill, ActionKind::Publish, key, Some(label));
        publish.set_clock(ClockSample::Seconds(sample));
        s.close_custody(publish, TIMED_OUT);
    }
    as_of(&mut s, Some(T1), Some(C2));
    for (key, label) in [(K, A), (J, C)] {
        let lookup = s.begin_lookup(key, ClockSample::Seconds(30));
        s.end_lookup(lookup, HIT, Some(label));
    }
    s.finish()
}

/// Client one's publication of A, sampled at second ten with an unrecorded
/// target, times out with its custody ending before T1 activates, so its
/// sample belongs to T0; client two publishes B in T1 with a deadline at
/// second five, and T1 records B's visibility end by expiry with no sample.
/// T1's clock holds no sample at or past five, so the end is early in every
/// legal order.
pub(super) fn refusal_sampled_in_an_earlier_tenure() -> History {
    let mut s = Script::new();
    as_of(&mut s, Some(Tenure::INITIAL), Some(C1));
    let fill = s.fill(K, A, BODY);
    let mut publish = s.open(fill, ActionKind::Publish, K, Some(A));
    publish.set_clock(ClockSample::Seconds(10));
    s.close_custody(publish, TIMED_OUT);
    as_of(&mut s, None, None);
    s.activate(RECOVERED, Some(T1), None);
    as_of(&mut s, Some(T1), Some(C2));
    let b = s.begin_publish(K, B, BODY, Some(5));
    s.close(b, Some(ACK));
    as_of(&mut s, Some(T1), None);
    s.ended(K, B, VisibilityCause::Expiry);
    s.finish()
}

/// T1 acknowledges a fill of A; client one, whose high-water is absent,
/// sends its publication with an unrecorded target, which times out and
/// whose custody ends; client two then reads A from T1. The publication
/// lands only in T1, above its floor, after the fill.
pub(super) fn untargeted_publication_above_floor() -> History {
    let mut s = activated(&[T1]);
    as_of(&mut s, Some(T1), None);
    let fill = s.fill(K, A, BODY);
    as_of(&mut s, Some(T1), Some(C1));
    let publish = s.open(fill, ActionKind::Publish, K, Some(A));
    s.close_custody(publish, TIMED_OUT);
    as_of(&mut s, Some(T1), Some(C2));
    s.lookup(K, HIT, Some(A));
    s.finish()
}

/// T1 publishes A and acknowledges client one's fill of B, which never
/// publishes; T2 then records A's eviction and misses.
fn eviction_after_fill_tenure() -> History {
    let mut s = activated(&[T1, T2]);
    as_of(&mut s, Some(T1), None);
    s.publish(K, A, BODY);
    as_of(&mut s, Some(T1), Some(C1));
    s.fill(K, B, BODY);
    as_of(&mut s, Some(T2), None);
    s.evict(K, A);
    as_of(&mut s, Some(T2), Some(C2));
    s.lookup(K, MISSING, None);
    s.finish()
}

/// Client one's publication of A bound to an unlogged T9, or, when
/// `later`, to T2, which activates only after the publication is invoked.
pub(super) fn unlogged_target(later: bool) -> History {
    let mut s = activated(&[T1]);
    as_of(&mut s, Some(T1), Some(C1));
    let mut publish = s.begin_publish(K, A, BODY, None);
    publish.set_target(Place::In(if later { T2 } else { T9 }));
    s.close(publish, Some(TIMED_OUT));
    if later {
        s.activate(RECOVERED, Some(T2), None);
    }
    s.finish()
}

/// Who samples second ten between A's publication with a deadline at
/// second five and the owner's record of A's visibility end by expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Sampler {
    Nobody,
    Owner,
    OtherClient,
}

/// The owner publishes A with a deadline at second five, `sampler` looks
/// up J at second ten, and the owner records A's visibility end by expiry.
/// Under per-client ordinals only the owner's own sample orders before its
/// end.
pub(super) fn expiry_end_after_sample(sampler: Sampler) -> History {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, Some(5));
    s.close(publish, Some(ACK));
    let client = match sampler {
        Sampler::Nobody => None,
        Sampler::Owner => Some(None),
        Sampler::OtherClient => Some(Some(C1)),
    };
    if let Some(client) = client {
        as_of(&mut s, client.map(|_| Tenure::INITIAL), client);
        let lookup = s.begin_lookup(J, ClockSample::Seconds(10));
        s.end_lookup(lookup, MISSING, None);
        as_of(&mut s, None, None);
    }
    s.ended(K, A, VisibilityCause::Expiry);
    s.finish()
}

/// The owner publishes A with deadline 5 in the active tenure, client one
/// sends a timed-out publication of B sampled at 10 after a fill answered
/// by that tenure, or by the initial tenure when its target goes
/// unrecorded, and A's visibility ends by expiry. With an unrecorded target
/// after a restart the client's high-water at send leaves both tenures
/// open to the landing.
pub(super) fn expiry_end_after_pending_sample(target: Option<Place>, restarted: bool) -> History {
    pending_sample_script(target, restarted).finish()
}

fn pending_sample_script(target: Option<Place>, restarted: bool) -> Script {
    let (mut s, tenure) = if restarted {
        (activated(&[T1]), T1)
    } else {
        (Script::new(), Tenure::INITIAL)
    };
    let publish = s.begin_publish(K, A, BODY, Some(5));
    s.close(publish, Some(ACK));
    let answering = if target.is_none() {
        Tenure::INITIAL
    } else {
        tenure
    };
    as_of(&mut s, Some(answering), Some(C1));
    let mut pending = s.begin_publish(J, B, BODY, None);
    if let Some(target) = target {
        pending.set_target(target);
    }
    pending.set_clock(ClockSample::Seconds(10));
    s.close_custody(pending, TIMED_OUT);
    as_of(&mut s, None, None);
    s.ended(K, A, VisibilityCause::Expiry);
    s
}

/// Client one's fill of A is acknowledged, client two's invalidation of K
/// is acknowledged, and client one's receive for the fill follows, each
/// client's ordinals in that order. A shared ordinal places the receive
/// after an invalidation that revoked its fill; per-client ordinals order
/// the two clients' rows only within each client.
pub(super) fn receive_after_another_clients_invalidation() -> History {
    let mut s = Script::new();
    s.in_tenure(Some(Tenure::INITIAL));
    s.by_client(Some(C1));
    let fill = s.fill(K, A, BODY);
    s.by_client(Some(C2));
    let invalidation = s.invalidate(K, ACK);
    let mut at = 0;
    let mut next = move || {
        at += 1;
        Some(super::ids::Ordinal(at))
    };
    edited(&s.finish(), |rows| {
        let index = |kind, op| rows.iter().position(|row| row.kind == kind && row.op == op);
        let order = [
            index(ActionKind::Fill, fill),
            index(ActionKind::Invalidate, invalidation),
            index(ActionKind::Receive, fill),
            index(ActionKind::WriteCompleted, fill),
        ];
        for row in order.into_iter().map(|at| at.expect("the row")) {
            if rows[row].invoked.is_some() {
                rows[row].invoked = next();
            }
            rows[row].responded = next();
        }
    })
}

pub(super) fn hit_then_invalidation_by_another_client() -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    as_of(&mut s, Some(Tenure::INITIAL), Some(C2));
    s.lookup(K, HIT, Some(A));
    as_of(&mut s, Some(Tenure::INITIAL), Some(C1));
    s.invalidate(K, ACK);
    s.finish()
}

/// The owner publishes C on J with a deadline at second five and A on K;
/// client one looks up K at second ten, the owner records C's visibility
/// end by expiry, client one invalidates K, and client two then reads the
/// covered A at second eleven. The end's evidence and the covered hit both
/// rest on one client's row preceding another timeline's.
pub(super) fn covered_hit_after_cross_client_expiry() -> History {
    let mut s = Script::new();
    let publish = s.begin_publish(J, C, BODY, Some(5));
    s.close(publish, Some(ACK));
    s.publish(K, A, BODY);
    as_of(&mut s, Some(Tenure::INITIAL), Some(C1));
    let lookup = s.begin_lookup(K, ClockSample::Seconds(10));
    s.end_lookup(lookup, MISSING, None);
    as_of(&mut s, None, None);
    s.ended(J, C, VisibilityCause::Expiry);
    as_of(&mut s, Some(Tenure::INITIAL), Some(C1));
    s.invalidate(K, ACK);
    as_of(&mut s, Some(Tenure::INITIAL), Some(C2));
    let hit = s.begin_lookup(K, ClockSample::Seconds(11));
    s.end_lookup(hit, HIT, Some(A));
    s.finish()
}

/// Client one's miss tagged T2 carries ordinals below the owner's
/// activation of T2, as separate per-client and owner counters may.
pub(super) fn client_counter_behind_owner() -> History {
    let mut s = Script::new();
    as_of(&mut s, Some(T2), Some(C1));
    s.lookup(K, MISSING, None);
    s.activate(RECOVERED, Some(T1), None);
    s.activate(RECOVERED, Some(T2), None);
    s.finish()
}

/// T1's lookup sampled at second ten, then a lookup sampled at second one,
/// answered by T2 when `activated` and by T1 otherwise.
pub(super) fn sample_across_activation(activated: bool) -> History {
    let mut s = Script::new();
    s.activate(RECOVERED, Some(T1), None);
    let early = s.begin_lookup(K, ClockSample::Seconds(10));
    s.end_lookup(early, MISSING, None);
    if activated {
        s.activate(RECOVERED, Some(T2), None);
    }
    let late = s.begin_lookup(K, ClockSample::Seconds(1));
    s.end_lookup(late, MISSING, None);
    s.finish()
}

/// A published, T1's acknowledged close, then a hit on A answered by T2
/// when `activated` and by T1 otherwise.
pub(super) fn hit_after_close(activated: bool) -> History {
    let mut s = Script::new();
    s.activate(RECOVERED, Some(T1), None);
    s.publish(K, A, BODY);
    s.close_cache(ACK);
    if activated {
        s.activate(RECOVERED, Some(T2), None);
    }
    s.lookup(K, HIT, Some(A));
    s.finish()
}

/// T1 publishes A with a deadline at second five for a hit and at second
/// fifty for `Expired`, then a lookup sampled at second nine answers
/// `outcome` on A, from T2 when `activated` and from T1 otherwise.
pub(super) fn deadline_across_activation(activated: bool, outcome: Outcome) -> History {
    let mut s = Script::new();
    s.activate(RECOVERED, Some(T1), None);
    let deadline = if outcome == Outcome::Expired { 50 } else { 5 };
    let publish = s.begin_publish(K, A, BODY, Some(deadline));
    s.close(publish, Some(ACK));
    if activated {
        s.activate(RECOVERED, Some(T2), None);
    }
    let lookup = s.begin_lookup(K, ClockSample::Seconds(9));
    s.end_lookup(lookup, outcome, Some(A));
    s.finish()
}

/// Every tenure golden, legal and violating, for the continuation's
/// agreement check.
pub(super) fn tenure_goldens() -> Vec<History> {
    let mut histories: Vec<History> = legal().into_iter().map(|(_, history)| history).collect();
    histories.extend([
        crashed_client_then_hit(false),
        recorded_high_water_fell(),
        unrecorded_route_publication(),
        expiry_end_after_pending_sample(Some(Place::In(Tenure::INITIAL)), false),
        expiry_end_after_pending_sample(None, false),
        expiry_end_after_pending_sample(Some(Place::In(T1)), true),
        expiry_end_after_pending_sample(None, true),
        hit_then_invalidation_by_another_client(),
        landing_after_window(),
        fill_published_by_successor(),
        eviction_after_fill_tenure(),
        untargeted_publication_above_floor(),
        deposed_slot_eviction(T1),
        deposed_slot_eviction(T2),
        eviction_after_pending_invalidation(),
        range_over_live_fill(2),
        range_over_live_fill(3),
        refilled_after_invalidation(),
        eviction_of_covered_label(),
        expiry_across_activation(true),
        expiry_across_activation(false),
        unplaced_then_unpublished_hit(),
        unbound_effect_after_held_miss(),
        invalidation_landing_after_close(),
        invalidation_floor_above_tag_after_close(),
        publication_after_fill_tenure_closed(),
        unplaced_then_wrong_bytes(),
        unplaced_sample_at_collapse_then_unpublished_hit(),
        expiry_end_across_activation(true, true),
        expiry_end_across_activation(false, true),
        expiry_end_across_activation(true, false),
        superseded_by_earlier_tenure_fill(),
        unplaced_sample_at_collapse(),
        floor_taken_at_send(),
        unlogged_high_water(),
        restore_from_uncaptured_cut(),
        restore_of_unpublished(),
        unbound_publications_in_order(25),
        unbound_publications_in_order(5),
        unbound_publications_across_keys(25, false),
        unbound_publications_across_keys(5, false),
        unbound_publications_across_keys(5, true),
        refusal_sampled_in_an_earlier_tenure(),
        unlogged_target(false),
        unlogged_target(true),
        deposed_hit(Some(T2)),
        rejected_then_high_water_fell(),
        rejected_unpublished_hit(),
        duplicated_invalidation_then_hit(),
        covered_hit_by_the_same_client(),
        all_versions_then_later_publication(true),
        all_versions_then_later_publication(false),
        outage_covered_twin(),
        covered_hit_by_another_client(),
        covered_hit_from_later_tenure(),
        covered_hit_after_restart(),
        accepted_below_high_water(None),
        accepted_below_high_water(Some(T1)),
        deposed_serves_successor_fill(),
        deposed_serves_later_fill(),
        wrong_bytes(),
        unpublished_hit(false),
        unpublished_hit(true),
        hit_at_deadline(),
        unlogged_tag(),
        absent_version_covered(),
        versions_outside_the_interval(),
        all_versions_covered(A),
        all_versions_covered(B),
        unversioned_then_later_publication(),
    ]);
    for removal in Removal::ALL {
        histories.push(removal_then_hit(removal, false));
        histories.push(removal_then_hit(removal, true));
    }
    for activated in [false, true] {
        histories.push(sample_across_activation(activated));
        histories.push(hit_after_close(activated));
        for outcome in [HIT, Outcome::Expired] {
            histories.push(deadline_across_activation(activated, outcome));
        }
    }
    histories.extend(Restored::ALL.map(restored));
    histories.extend(Pending::ALL.map(targeted_publication));
    histories.extend(LowerAnswer::ALL.map(lower_answer_accepted));
    histories.extend(Retained::ALL.map(retained));
    for removal in Removal::ALL {
        histories.push(removed_then_recaptured(removal, false));
        histories.push(removed_then_recaptured(removal, true));
    }
    histories.push(invalidation_bound_above_recovery());
    histories.push(unbound_invalidation_before_forced_publication());
    for used in [
        LaterUse::Hit,
        LaterUse::Restore,
        LaterUse::Expire,
        LaterUse::Evict,
    ] {
        for restored in [false, true] {
            histories.push(invalidation_omitted_in_later_tenure(used, restored));
        }
    }
    for target in [Place::In(T1), Place::AtLeast(T1)] {
        for (beside, other) in [
            (Beside::After, 1),
            (Beside::After, 55),
            (Beside::Before, 50),
            (Beside::Before, 1),
        ] {
            histories.push(unbound_sample_beside_other_key(target, beside, other));
        }
    }
    for (target, tenures) in [
        (Place::AtLeast(T1), &[T1, T2][..]),
        (Place::AtLeast(T1), &[T1][..]),
        (Place::In(T1), &[T1, T2][..]),
        (Place::In(T2), &[T1, T2][..]),
    ] {
        histories.push(unbound_effect_sampled_below_its_floor(target, tenures));
    }
    histories
}

/// How a recovery treats the retained cut that captured A and C.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Retained {
    /// T1 restores A and C.
    Restored,
    /// T1 restores nothing and every lookup misses.
    Lost,
    /// T0 records an eviction of A before the host loss; T1 restores C.
    EvictedBefore,
    /// T0's eviction of A carries no information; T1 restores C.
    RefusedEviction,
    /// T0 records an eviction of A after T1 activates; T1 restores C.
    EvictedAfterActivation,
    /// T0's slot release ends A's visibility by eviction before the host
    /// loss; T1 restores C.
    ReleasedBefore,
    /// A's publication carries a deadline at second five and T0 records
    /// its expiry at second ten; T1 restores C.
    ExpiredBefore,
    /// A's publication carries a deadline at second five, T0 samples second
    /// ten and records A's visibility end by expiry; T1 restores C.
    ExpiryEndedBefore,
    /// A's capture carries no information; T1 restores C.
    CaptureRefused,
    /// Both captures carry no information; T1 restores nothing.
    AllCapturesRefused,
    /// T0 replaces A with B before the host loss; T1 restores C.
    SupersededBefore,
    /// T0's replacement of A with B is acknowledged after T1 activates; T1
    /// restores C.
    LateSupersession,
    /// T0's replacement of A with B overlaps A's publication and responds
    /// before it, so either may take effect last; T1 restores C.
    OverlappingSupersession,
    /// The overlapping supersession with B's replacement sampled at second
    /// one and A's publication at second two, so B takes effect first and
    /// A stays current; T1 restores C.
    OrderedOverlap,
    /// B's replacement begins sampled at second one, a miss of K sampled at
    /// second five is answered while it is open, A's publication without a
    /// sample is acknowledged, then B's replacement is acknowledged. The
    /// miss follows the replacement in the clock and precedes the
    /// publication in real time, so B takes effect before A in every legal
    /// order and A stays current; T1 restores C.
    OrderedThroughMiss,
    /// [`Self::OrderedThroughMiss`] with the miss sampled at second one, so
    /// the replacement may follow the miss and take effect after A; T1
    /// restores C.
    UnorderedThroughMiss,
    /// [`Self::OrderedThroughMiss`] with the miss begun after A's
    /// publication, so the replacement may take effect after A; T1 restores
    /// C.
    ThroughMissAfterPublication,
    /// T0's unversioned invalidation of K is begun while A's publication is
    /// open and times out after it is acknowledged; T1 restores C and reads
    /// A. A landing after the publication would cover A into T1, which the
    /// hit forbids, so A is uncovered in every legal order.
    PendingInvalidationOverlapsPublication,
    /// [`Self::PendingInvalidationOverlapsPublication`] with A's publication
    /// sampled at second one and a miss sampled at second five answered
    /// before the invalidation is begun, so the clock puts the publication
    /// before the invalidation and every landing covers A.
    PendingInvalidationAfterSampledPublication,
    /// T0's unversioned invalidation of K is begun before A's fill and
    /// acknowledged after A's publication; T1 restores C and reads A. The
    /// invalidation covers A after the publication and revokes the fill
    /// between fill and publication, so it takes effect before the fill in
    /// every legal order and A stays uncovered.
    AcknowledgedInvalidationBeforeFill,
    /// T0's unversioned invalidation of K is begun before B and A are
    /// published and times out after both; T1 restores C and reads B. A
    /// landing after B covers B and one between B's fill and publication
    /// revokes it, so the invalidation is refused or lands before B's fill,
    /// and A stays uncovered in every legal order.
    PendingInvalidationBeforeEarlierLabel,
    /// T1 restores C, acknowledges a fill of B, times out an unversioned
    /// invalidation of K and publishes B from that fill. A landed
    /// invalidation would revoke the fill B's acknowledged publication came
    /// from, so the invalidation is refused in every legal order and A stays
    /// in T1's retained set.
    PendingInvalidationBeforeAcknowledgedPublication,
    /// [`Self::PendingInvalidationBeforeAcknowledgedPublication`] with B's
    /// publication timed out and a hit of B after it: the hit proves B's
    /// publication landed from a fill a landed invalidation would have
    /// revoked, so the invalidation is refused in every legal order.
    PendingInvalidationBeforeLandedPublication,
    /// [`Self::PendingInvalidationBeforeLandedPublication`] with B's
    /// publication sent by client one from T2, tagged there with an
    /// unrecorded target, after T1's owner invalidation timed out: the
    /// publication lands only in its fill's T1 segment, where a landed
    /// invalidation would have revoked the fill.
    PendingInvalidationBeforeLandedPublicationTaggedLater,
    /// A's publication is sampled at second fifty; T1 restores C, its
    /// unversioned invalidation of K times out, B is published sampled at
    /// second ten after the invalidation's window and read. Tenure order
    /// puts A before B whatever their samples, so the invalidation may land
    /// before B and cover A.
    CoveredEntrySampledAboveLaterLabel,
    /// T0's unversioned invalidation of K with an unrecorded target at floor
    /// T0 is begun while A's publication is open and times out after T2
    /// reads A. Every landing at or below T2 before the hit covers A or
    /// revokes its fill, so the invalidation is refused or lands in T2 after
    /// the hit, and A is in T1's retained set.
    PendingInvalidationLandingAboveActivation,
    /// [`Self::OrderedOverlap`] with A's publication carrying an unrecorded
    /// target at floor T0 and timing out after T1 activates, so its
    /// placements span both tenures while its fill lets it land in T0
    /// alone, where its sample still follows B's; T1 restores C.
    OrderedOverlapAcrossActivation,
    /// T0's replacement of A with B times out; T1 restores C.
    PendingSupersession,
    /// T0's replacement of A with B, carrying a deadline at second five and
    /// sampled at second ten, times out; T1 restores C.
    LapsedSupersession,
    /// T0 publishes B before A; after the capture, a second fill of B
    /// times out publishing it again, which its published label refuses;
    /// T1 restores C.
    DuplicatePending,
    /// T0's replacement of A with B times out; T1 restores C and then
    /// publishes B from a second fill.
    LaterDuplicate,
    /// T0's replacement of A with B times out, then T0's invalidation of K
    /// times out; T1 restores C, publishes B from a second fill and reads
    /// B. T1's publication refuses T0's replacement in every legal order,
    /// so the hit leaves the invalidation free to land in T0 and cover A.
    LaterDuplicateThenPendingInvalidation,
    /// A carries version one; T0 acknowledges B's fill, then an
    /// invalidation of version two, then B's replacement at version two
    /// times out, which the invalidation revoked; T1 restores C.
    RevokedSupersession,
    /// A carries version one; T0 acknowledges B's fill, begins an
    /// invalidation of version two, begins B's replacement at version two
    /// sampled at second ten, acknowledges the invalidation, misses at
    /// second five and times the replacement out. The miss follows the
    /// invalidation and its sample puts the replacement after the miss, so
    /// the invalidation revokes the replacement in every legal order; T1
    /// restores C.
    OverlappingRevokedSupersession,
    /// [`Self::OverlappingRevokedSupersession`] with the replacement's
    /// target unrecorded at floor T0 and its custody ending after T1
    /// activates, so its placements span both tenures while its fill lets it
    /// land in T0 alone; T1 restores C.
    OverlappingRevokedSupersessionAcrossActivation,
    /// [`Self::OverlappingRevokedSupersession`] with the miss sampled at
    /// second ten, so the replacement may precede it and land before the
    /// invalidation; T1 restores C.
    OverlappingSupersessionSampledEqual,
    /// [`Self::OverlappingRevokedSupersession`] with the miss at second five
    /// taken before the invalidation is begun, so the replacement may land
    /// before the invalidation; T1 restores C.
    OverlappingSupersessionSampledBefore,
    /// A's publication, sampled at second ten, stays open across T0's
    /// timed-out unversioned invalidation of K and a miss at second five
    /// that follows the invalidation's window, then is acknowledged. The
    /// miss puts the publication after the invalidation in every legal
    /// order, so a landed invalidation would revoke A's fill and A stays
    /// uncovered; T1 restores C.
    PublicationForcedAfterPendingInvalidation,
    /// T0's invalidation of A is acknowledged after T1 activates; T1
    /// restores C.
    LateInvalidation,
    /// T0's invalidation of A is acknowledged after T1 activates; T1
    /// restores A and C.
    LateInvalidationRestored,
    /// T0's invalidation of K times out before the host loss; T1 restores
    /// C.
    PendingInvalidation,
    /// T0's invalidation of K times out, then T0 reads A, which rules out
    /// its landing; T1 restores C.
    PendingInvalidationOmitted,
    /// T0's expired lookup of A witnesses A uncovered after T0's timed-out
    /// invalidation of K; T1 restores C.
    PendingInvalidationOmittedByExpiry,
    /// An abstract invalidation of K, which the key search does not read,
    /// is acknowledged; T1 restores C.
    AbstractInvalidation,
    /// T0 acknowledges a close, then its invalidation of K times out, which
    /// the close leaves refused; T1 restores C.
    ClosedPendingInvalidation,
    /// A carries version one and T0 acknowledges an invalidation of version
    /// two; T1 restores C.
    RangeMissesVersion,
    /// A carries version one and T0 acknowledges an invalidation of version
    /// one; T1 restores C.
    RangeCoversVersion,
    /// A's publication at version one times out yet the cut captures it,
    /// and T0 acknowledges an invalidation of version one; T1 restores C.
    PendingPublicationCovered,
    /// A's publication at version one times out yet the cut captures it,
    /// T0's invalidation of version one times out, and T1 reads A after
    /// restoring C: the hit proves A's publication landed, and an
    /// invalidation landing before the hit would cover A.
    PendingPublicationPendingCover,
    /// T1 acknowledges an invalidation of K before any restore, then
    /// restores C.
    InvalidatedBeforeRestore,
    /// A's publication times out, T0 acknowledges an invalidation of K, a
    /// second fill's publication of A times out, and T1 reads A after
    /// restoring C. A landed first attempt would let the invalidation cover
    /// A and refuse both the second attempt and the hit, so the hit leaves
    /// A published after the invalidation and uncovered.
    PublishedAgainAfterInvalidation,
    /// [`Self::PublishedAgainAfterInvalidation`] with T1 restoring A and C.
    PublishedAgainAfterInvalidationRestored,
    /// T0's publication of B times out, its window ending before A is
    /// published; T1 restores C, its unversioned invalidation of K times
    /// out, a second fill's publication of B times out, and T1 reads B.
    /// The hit reads T1's B, published after the invalidation, so the
    /// invalidation may land in T1 and remove A.
    EarlierPendingTwinOmitted,
    /// A's publication times out with its custody left open, so it lands
    /// only in T0; T1 restores C, its unversioned invalidation of K times
    /// out, and T1 reads A. The hit proves A published and uncovered, and
    /// every landing of the invalidation follows the publication.
    OpenPublicationThenPendingInvalidation,
    /// T1 records an eviction of A before any restore, then restores C.
    StaleRefusal,
    /// T1 records A's visibility end by eviction before any restore, then
    /// restores C.
    StaleVisibilityEnd,
    /// T1 restores C, then records an eviction of A.
    EvictedAfterRestore,
    /// T1 restores C, and its restore of A carries no information.
    RefusedRestore,
    /// Damage in A's payload unit; T1 restores C.
    Damaged,
    /// Damage in the row unit A and C share; T1 restores nothing.
    DamagedRowUnit,
    /// Damage in A's payload unit carries no information; T1 restores C.
    RefusedDamage,
    /// Damage in A's payload unit; T1 restores A and loses C.
    DamagedOtherLost,
    /// T1 restores C and answers lookups before recording damage in A's
    /// payload unit.
    DamagedAfterServing,
    /// T1 restores C, a lookup of K times out, and T1 records damage in
    /// A's payload unit before answering any lookup.
    DamagedAfterUnansweredLookup,
    /// T0 evicts A; T1 restores A and C.
    RestoredNotRequired,
    /// T0 publishes B beside C after the capture; T1 restores A, C and the
    /// uncaptured B.
    RestoredUncaptured,
    /// T1 activates with no cut.
    ColdStart,
    /// T1 activates with no cut after the whole volume was damaged.
    ColdStartAfterWholeLoss,
    /// T1 activates with no cut and answers lookups before recording
    /// damage to the whole volume.
    ColdStartDamagedAfterServing,
    /// T1 activates from a cut no capture recorded.
    UnrecordedCut,
    /// The whole volume is damaged, then T1 activates from a cut no capture
    /// recorded and restores C from it.
    UnrecordedCutRestored,
}

impl Retained {
    pub(super) const ALL: [Self; 71] = [
        Self::Restored,
        Self::Lost,
        Self::EvictedBefore,
        Self::RefusedEviction,
        Self::EvictedAfterActivation,
        Self::ReleasedBefore,
        Self::ExpiredBefore,
        Self::ExpiryEndedBefore,
        Self::CaptureRefused,
        Self::AllCapturesRefused,
        Self::SupersededBefore,
        Self::LateSupersession,
        Self::OverlappingSupersession,
        Self::OrderedOverlap,
        Self::OrderedThroughMiss,
        Self::UnorderedThroughMiss,
        Self::ThroughMissAfterPublication,
        Self::PendingInvalidationOverlapsPublication,
        Self::PendingInvalidationAfterSampledPublication,
        Self::AcknowledgedInvalidationBeforeFill,
        Self::PendingInvalidationBeforeEarlierLabel,
        Self::PendingInvalidationBeforeAcknowledgedPublication,
        Self::PendingInvalidationBeforeLandedPublication,
        Self::PendingInvalidationBeforeLandedPublicationTaggedLater,
        Self::CoveredEntrySampledAboveLaterLabel,
        Self::PendingInvalidationLandingAboveActivation,
        Self::OrderedOverlapAcrossActivation,
        Self::PendingSupersession,
        Self::LapsedSupersession,
        Self::DuplicatePending,
        Self::LaterDuplicate,
        Self::LaterDuplicateThenPendingInvalidation,
        Self::RevokedSupersession,
        Self::OverlappingRevokedSupersession,
        Self::OverlappingRevokedSupersessionAcrossActivation,
        Self::OverlappingSupersessionSampledEqual,
        Self::OverlappingSupersessionSampledBefore,
        Self::PublicationForcedAfterPendingInvalidation,
        Self::LateInvalidation,
        Self::LateInvalidationRestored,
        Self::PendingInvalidation,
        Self::PendingInvalidationOmitted,
        Self::PendingInvalidationOmittedByExpiry,
        Self::AbstractInvalidation,
        Self::ClosedPendingInvalidation,
        Self::RangeMissesVersion,
        Self::RangeCoversVersion,
        Self::PendingPublicationCovered,
        Self::PendingPublicationPendingCover,
        Self::InvalidatedBeforeRestore,
        Self::PublishedAgainAfterInvalidation,
        Self::PublishedAgainAfterInvalidationRestored,
        Self::EarlierPendingTwinOmitted,
        Self::OpenPublicationThenPendingInvalidation,
        Self::StaleRefusal,
        Self::StaleVisibilityEnd,
        Self::EvictedAfterRestore,
        Self::RefusedRestore,
        Self::Damaged,
        Self::DamagedRowUnit,
        Self::RefusedDamage,
        Self::DamagedOtherLost,
        Self::DamagedAfterServing,
        Self::DamagedAfterUnansweredLookup,
        Self::RestoredNotRequired,
        Self::RestoredUncaptured,
        Self::ColdStart,
        Self::ColdStartAfterWholeLoss,
        Self::ColdStartDamagedAfterServing,
        Self::UnrecordedCut,
        Self::UnrecordedCutRestored,
    ];
}

/// A on one key and C on another, both captured in `CUT` at units `(0, 1)`
/// and `(0, 2)`, then T1 activated after host loss and recovering as
/// `retained` names.
pub(super) fn retained(retained: Retained) -> History {
    let mut s = Script::new();
    let versioned = matches!(
        retained,
        Retained::RangeMissesVersion
            | Retained::RangeCoversVersion
            | Retained::PendingPublicationCovered
            | Retained::PendingPublicationPendingCover
            | Retained::RevokedSupersession
            | Retained::OverlappingRevokedSupersession
            | Retained::OverlappingRevokedSupersessionAcrossActivation
            | Retained::OverlappingSupersessionSampledEqual
            | Retained::OverlappingSupersessionSampledBefore
    );
    let deadline = matches!(
        retained,
        Retained::ExpiredBefore
            | Retained::ExpiryEndedBefore
            | Retained::PendingInvalidationOmittedByExpiry
    )
    .then_some(5);
    if retained == Retained::DuplicatePending {
        s.publish(K, B, BODY);
    }
    if retained == Retained::EarlierPendingTwinOmitted {
        let early = s.begin_publish(K, B, BODY, None);
        s.close_custody(early, TIMED_OUT);
    }
    let miss_at = |s: &mut Script, seconds| {
        let miss = s.begin_lookup(K, ClockSample::Seconds(seconds));
        s.end_lookup(miss, MISSING, None);
    };
    let through_miss = matches!(
        retained,
        Retained::OrderedThroughMiss
            | Retained::UnorderedThroughMiss
            | Retained::ThroughMissAfterPublication
    )
    .then(|| {
        let mut replace = s.begin_replace(K, B, BODY);
        replace.set_clock(ClockSample::Seconds(1));
        match retained {
            Retained::OrderedThroughMiss => miss_at(&mut s, 5),
            Retained::UnorderedThroughMiss => miss_at(&mut s, 1),
            _ => {}
        }
        replace
    });
    let early_invalidation = matches!(
        retained,
        Retained::AcknowledgedInvalidationBeforeFill
            | Retained::PendingInvalidationBeforeEarlierLabel
    )
    .then(|| {
        let invalidation = s.begin_invalidate(K);
        if retained == Retained::PendingInvalidationBeforeEarlierLabel {
            s.publish(K, B, BODY);
        }
        invalidation
    });
    let mut spanning_invalidation = None;
    let mut publication = s.begin_publish(K, A, BODY, deadline);
    if versioned {
        publication.set_version(1);
    }
    let ordered = matches!(
        retained,
        Retained::OrderedOverlap | Retained::OrderedOverlapAcrossActivation
    );
    if retained == Retained::CoveredEntrySampledAboveLaterLabel {
        publication.set_clock(ClockSample::Seconds(50));
    }
    let mut open_publication = None;
    if ordered {
        publication.set_clock(ClockSample::Seconds(2));
    }
    if ordered || retained == Retained::OverlappingSupersession {
        let mut replace = s.begin_replace(K, B, BODY);
        if ordered {
            replace.set_clock(ClockSample::Seconds(1));
        }
        s.close(replace, Some(ACK));
    }
    match retained {
        Retained::PendingPublicationCovered
        | Retained::PendingPublicationPendingCover
        | Retained::PublishedAgainAfterInvalidation
        | Retained::PublishedAgainAfterInvalidationRestored => {
            s.close_custody(publication, TIMED_OUT);
        }
        Retained::OpenPublicationThenPendingInvalidation => {
            s.close(publication, Some(TIMED_OUT));
        }
        Retained::OrderedOverlapAcrossActivation => {
            publication.set_target(Place::AtLeast(Tenure::INITIAL));
            open_publication = Some(publication);
        }
        Retained::ThroughMissAfterPublication => {
            miss_at(&mut s, 5);
            s.close(publication, Some(ACK));
        }
        Retained::PendingInvalidationOverlapsPublication
        | Retained::PendingInvalidationAfterSampledPublication => {
            if retained == Retained::PendingInvalidationAfterSampledPublication {
                publication.set_clock(ClockSample::Seconds(1));
                miss_at(&mut s, 5);
            }
            let invalidation = s.begin_invalidate(K);
            s.close(publication, Some(ACK));
            s.close_custody(invalidation, TIMED_OUT);
        }
        Retained::AcknowledgedInvalidationBeforeFill => {
            s.close(publication, Some(ACK));
            s.close(
                early_invalidation.expect("the early invalidation"),
                Some(ACK),
            );
        }
        Retained::PendingInvalidationBeforeEarlierLabel => {
            s.close(publication, Some(ACK));
            s.close_custody(
                early_invalidation.expect("the early invalidation"),
                TIMED_OUT,
            );
        }
        Retained::PendingInvalidationLandingAboveActivation => {
            let mut invalidation = s.begin_invalidate(K);
            invalidation.set_target(Place::AtLeast(Tenure::INITIAL));
            spanning_invalidation = Some(invalidation);
            s.close(publication, Some(ACK));
        }
        Retained::PublicationForcedAfterPendingInvalidation => {
            publication.set_clock(ClockSample::Seconds(10));
            let invalidation = s.begin_invalidate(K);
            s.close_custody(invalidation, TIMED_OUT);
            let miss = s.begin_lookup(K, ClockSample::Seconds(5));
            s.end_lookup(miss, MISSING, None);
            s.close(publication, Some(ACK));
        }
        _ => {
            s.close(publication, Some(ACK));
        }
    }
    if let Some(replace) = through_miss {
        s.close(replace, Some(ACK));
    }
    if retained == Retained::ReleasedBefore {
        s.hold_slot(3, (K, A));
    }
    s.publish(J, C, BODY);
    if matches!(
        retained,
        Retained::CaptureRefused | Retained::AllCapturesRefused
    ) {
        s.without_information_next();
    }
    s.captured(RECOVERED, (K, A), CUT, (0, 1));
    if retained == Retained::AllCapturesRefused {
        s.without_information_next();
    }
    s.captured(RECOVERED, (J, C), CUT, (0, 2));
    let mut late = None;
    let mut late_timed_out = None;
    let invalidate_range = |s: &mut Script, version: u64| {
        let mut invalidation = s.begin_invalidate(K);
        invalidation.set_covers(Cover::Range {
            lo: version,
            hi: version,
        });
        s.close(invalidation, Some(ACK));
    };
    match retained {
        Retained::RestoredUncaptured => {
            s.publish(J, B, BODY);
        }
        Retained::EvictedBefore | Retained::RestoredNotRequired => s.evict(K, A),
        Retained::RefusedEviction => {
            s.without_information_next();
            s.evict(K, A);
        }
        Retained::ReleasedBefore => s.end_slot_visibility(3, (K, A), VisibilityCause::Eviction),
        Retained::ExpiredBefore => s.expire(K, A, 10),
        Retained::ExpiryEndedBefore => {
            let lookup = s.begin_lookup(J, ClockSample::Seconds(10));
            s.end_lookup(lookup, HIT, Some(C));
            s.ended(K, A, VisibilityCause::Expiry);
        }
        Retained::RevokedSupersession => {
            let fill = s.fill(K, B, BODY);
            invalidate_range(&mut s, 2);
            let mut replace = s.open(fill, ActionKind::Replace, K, Some(B));
            replace.set_version(2);
            s.close_custody(replace, TIMED_OUT);
        }
        Retained::OverlappingRevokedSupersession
        | Retained::OverlappingRevokedSupersessionAcrossActivation
        | Retained::OverlappingSupersessionSampledEqual
        | Retained::OverlappingSupersessionSampledBefore => {
            let fill = s.fill(K, B, BODY);
            if retained == Retained::OverlappingSupersessionSampledBefore {
                miss_at(&mut s, 5);
            }
            let mut invalidation = s.begin_invalidate(K);
            invalidation.set_covers(Cover::Range { lo: 2, hi: 2 });
            let mut replace = s.open(fill, ActionKind::Replace, K, Some(B));
            replace.set_version(2);
            replace.set_clock(ClockSample::Seconds(10));
            s.close(invalidation, Some(ACK));
            match retained {
                Retained::OverlappingRevokedSupersession => miss_at(&mut s, 5),
                Retained::OverlappingRevokedSupersessionAcrossActivation => {
                    replace.set_target(Place::AtLeast(Tenure::INITIAL));
                    miss_at(&mut s, 5);
                }
                Retained::OverlappingSupersessionSampledEqual => miss_at(&mut s, 10),
                _ => {}
            }
            if retained == Retained::OverlappingRevokedSupersessionAcrossActivation {
                late_timed_out = Some(replace);
            } else {
                s.close_custody(replace, TIMED_OUT);
            }
        }
        Retained::UnrecordedCutRestored => s.damaged(RECOVERED, None),
        Retained::SupersededBefore => {
            s.publish_replacing(K, B, BODY);
        }
        Retained::PendingSupersession => {
            let replace = s.begin_replace(K, B, BODY);
            s.close_custody(replace, TIMED_OUT);
        }
        Retained::LapsedSupersession => {
            let mut replace = s.begin_replace(K, B, BODY);
            replace.set_deadline(5);
            replace.set_clock(ClockSample::Seconds(10));
            s.close_custody(replace, TIMED_OUT);
        }
        Retained::DuplicatePending | Retained::LaterDuplicate => {
            let replace = s.begin_replace(K, B, BODY);
            s.close_custody(replace, TIMED_OUT);
        }
        Retained::LaterDuplicateThenPendingInvalidation => {
            let replace = s.begin_replace(K, B, BODY);
            s.close_custody(replace, TIMED_OUT);
            let invalidation = s.begin_invalidate(K);
            s.close_custody(invalidation, TIMED_OUT);
        }
        Retained::PendingInvalidationOmitted => {
            let invalidation = s.begin_invalidate(K);
            s.close_custody(invalidation, TIMED_OUT);
            s.lookup(K, HIT, Some(A));
        }
        Retained::PendingInvalidationOmittedByExpiry => {
            let invalidation = s.begin_invalidate(K);
            s.close_custody(invalidation, TIMED_OUT);
            let lookup = s.begin_lookup(K, ClockSample::Seconds(10));
            s.end_lookup(lookup, Outcome::Expired, Some(A));
        }
        Retained::AbstractInvalidation => {
            let mut invalidation = s.begin_invalidate(K);
            invalidation.set_evidence(RECOVERED);
            s.close(invalidation, Some(ACK));
        }
        Retained::LateInvalidation | Retained::LateInvalidationRestored => {
            as_of(&mut s, Some(Tenure::INITIAL), None);
            late = Some(s.begin_invalidate(K));
            as_of(&mut s, None, None);
        }
        Retained::LateSupersession => {
            as_of(&mut s, Some(Tenure::INITIAL), None);
            late = Some(s.begin_replace(K, B, BODY));
            as_of(&mut s, None, None);
        }
        Retained::ClosedPendingInvalidation | Retained::PendingInvalidation => {
            if retained == Retained::ClosedPendingInvalidation {
                s.close_cache(ACK);
            }
            let invalidation = s.begin_invalidate(K);
            s.close_custody(invalidation, TIMED_OUT);
        }
        Retained::RangeMissesVersion => invalidate_range(&mut s, 2),
        Retained::RangeCoversVersion | Retained::PendingPublicationCovered => {
            invalidate_range(&mut s, 1);
        }
        Retained::PendingPublicationPendingCover => {
            let mut invalidation = s.begin_invalidate(K);
            invalidation.set_covers(Cover::Range { lo: 1, hi: 1 });
            s.close_custody(invalidation, TIMED_OUT);
        }
        Retained::PublishedAgainAfterInvalidation
        | Retained::PublishedAgainAfterInvalidationRestored => {
            s.invalidate(K, ACK);
            let again = s.begin_publish(K, A, BODY, None);
            s.close_custody(again, TIMED_OUT);
        }
        _ => {}
    }
    let cut = match retained {
        Retained::ColdStart
        | Retained::ColdStartAfterWholeLoss
        | Retained::ColdStartDamagedAfterServing => None,
        Retained::UnrecordedCut | Retained::UnrecordedCutRestored => Some(OTHER_CUT),
        _ => Some(CUT),
    };
    s.activate(RECOVERED, Some(T1), cut);
    if let Some(late) = late {
        s.close(late, Some(ACK));
    }
    if let Some(late) = late_timed_out {
        s.close_custody(late, TIMED_OUT);
    }
    if let Some(publication) = open_publication {
        s.close_custody(publication, TIMED_OUT);
    }
    match retained {
        Retained::Restored | Retained::RestoredNotRequired | Retained::LateInvalidationRestored => {
            s.restore(K, A, CUT);
            s.restore(J, C, CUT);
        }
        Retained::RestoredUncaptured => {
            s.restore(K, A, CUT);
            s.restore(J, C, CUT);
            s.restore(J, B, CUT);
        }
        Retained::UnrecordedCutRestored => {
            s.restore(J, C, OTHER_CUT);
        }
        Retained::EvictedBefore
        | Retained::RefusedEviction
        | Retained::ExpiryEndedBefore
        | Retained::CaptureRefused
        | Retained::RevokedSupersession
        | Retained::OverlappingRevokedSupersession
        | Retained::OverlappingRevokedSupersessionAcrossActivation
        | Retained::OverlappingSupersessionSampledEqual
        | Retained::OverlappingSupersessionSampledBefore
        | Retained::PublicationForcedAfterPendingInvalidation
        | Retained::ReleasedBefore
        | Retained::ExpiredBefore
        | Retained::SupersededBefore
        | Retained::LateSupersession
        | Retained::OverlappingSupersession
        | Retained::OrderedOverlap
        | Retained::OrderedThroughMiss
        | Retained::UnorderedThroughMiss
        | Retained::ThroughMissAfterPublication
        | Retained::OrderedOverlapAcrossActivation
        | Retained::PendingSupersession
        | Retained::LapsedSupersession
        | Retained::DuplicatePending
        | Retained::PendingInvalidationOmitted
        | Retained::PendingInvalidationOmittedByExpiry
        | Retained::AbstractInvalidation
        | Retained::LateInvalidation
        | Retained::PendingInvalidation
        | Retained::ClosedPendingInvalidation
        | Retained::RangeMissesVersion
        | Retained::RangeCoversVersion
        | Retained::PendingPublicationCovered
        | Retained::DamagedAfterServing => {
            s.restore(J, C, CUT);
        }
        Retained::LaterDuplicate => {
            s.restore(J, C, CUT);
            s.publish(K, B, BODY);
        }
        Retained::LaterDuplicateThenPendingInvalidation => {
            s.restore(J, C, CUT);
            s.publish(K, B, BODY);
            s.lookup(K, HIT, Some(B));
        }
        Retained::PendingPublicationPendingCover => {
            s.restore(J, C, CUT);
            s.lookup(K, HIT, Some(A));
        }
        Retained::EvictedAfterActivation => {
            as_of(&mut s, Some(Tenure::INITIAL), None);
            s.evict(K, A);
            as_of(&mut s, None, None);
            s.restore(J, C, CUT);
        }
        Retained::InvalidatedBeforeRestore => {
            s.invalidate(K, ACK);
            s.restore(J, C, CUT);
        }
        Retained::OpenPublicationThenPendingInvalidation => {
            s.restore(J, C, CUT);
            let invalidation = s.begin_invalidate(K);
            s.close_custody(invalidation, TIMED_OUT);
            s.lookup(K, HIT, Some(A));
        }
        Retained::PublishedAgainAfterInvalidation
        | Retained::PendingInvalidationOverlapsPublication
        | Retained::PendingInvalidationAfterSampledPublication
        | Retained::AcknowledgedInvalidationBeforeFill => {
            s.restore(J, C, CUT);
            s.lookup(K, HIT, Some(A));
        }
        Retained::PendingInvalidationBeforeEarlierLabel => {
            s.restore(J, C, CUT);
            s.lookup(K, HIT, Some(B));
        }
        Retained::PendingInvalidationBeforeAcknowledgedPublication
        | Retained::PendingInvalidationBeforeLandedPublication => {
            s.restore(J, C, CUT);
            let fill = s.fill(K, B, BODY);
            let invalidation = s.begin_invalidate(K);
            s.close_custody(invalidation, TIMED_OUT);
            let publish = s.open(fill, ActionKind::Publish, K, Some(B));
            if retained == Retained::PendingInvalidationBeforeLandedPublication {
                s.close_custody(publish, TIMED_OUT);
                s.lookup(K, HIT, Some(B));
            } else {
                s.close(publish, Some(ACK));
            }
        }
        Retained::CoveredEntrySampledAboveLaterLabel => {
            s.restore(J, C, CUT);
            let invalidation = s.begin_invalidate(K);
            s.close_custody(invalidation, TIMED_OUT);
            let mut later = s.begin_publish(K, B, BODY, None);
            later.set_clock(ClockSample::Seconds(10));
            s.close(later, Some(ACK));
            let hit = s.begin_lookup(K, ClockSample::Seconds(10));
            s.end_lookup(hit, HIT, Some(B));
        }
        Retained::PendingInvalidationBeforeLandedPublicationTaggedLater => {
            s.restore(J, C, CUT);
            as_of(&mut s, Some(T1), Some(C1));
            let fill = s.fill(K, B, BODY);
            as_of(&mut s, None, None);
            let invalidation = s.begin_invalidate(K);
            s.close_custody(invalidation, TIMED_OUT);
            s.activate(RECOVERED, Some(T2), Some(CUT));
            s.restore(J, C, CUT);
            as_of(&mut s, Some(T2), Some(C1));
            let publish = s.open(fill, ActionKind::Publish, K, Some(B));
            s.close_custody(publish, TIMED_OUT);
            as_of(&mut s, None, None);
            s.lookup(K, HIT, Some(B));
        }
        Retained::PendingInvalidationLandingAboveActivation => {
            s.restore(J, C, CUT);
            s.activate(RECOVERED, Some(T2), Some(CUT));
            s.restore(J, C, CUT);
            s.lookup(K, HIT, Some(A));
            let invalidation = spanning_invalidation
                .take()
                .expect("the spanning invalidation");
            s.close_custody(invalidation, TIMED_OUT);
        }
        Retained::EarlierPendingTwinOmitted => {
            s.restore(J, C, CUT);
            let invalidation = s.begin_invalidate(K);
            s.close_custody(invalidation, TIMED_OUT);
            let again = s.begin_publish(K, B, BODY, None);
            s.close_custody(again, TIMED_OUT);
            s.lookup(K, HIT, Some(B));
        }
        Retained::PublishedAgainAfterInvalidationRestored => {
            s.restore(K, A, CUT);
            s.restore(J, C, CUT);
            s.lookup(K, HIT, Some(A));
        }
        Retained::StaleRefusal => {
            s.evict(K, A);
            s.restore(J, C, CUT);
        }
        Retained::StaleVisibilityEnd => {
            s.ended(K, A, VisibilityCause::Eviction);
            s.restore(J, C, CUT);
        }
        Retained::EvictedAfterRestore => {
            s.restore(J, C, CUT);
            s.evict(K, A);
        }
        Retained::RefusedRestore => {
            s.restore(J, C, CUT);
            s.without_information_next();
            s.restore(K, A, CUT);
        }
        Retained::Damaged => {
            s.damaged(RECOVERED, Some(1));
            s.restore(J, C, CUT);
        }
        Retained::DamagedRowUnit => s.damaged(RECOVERED, Some(0)),
        Retained::RefusedDamage => {
            s.without_information_next();
            s.damaged(RECOVERED, Some(1));
            s.restore(J, C, CUT);
        }
        Retained::DamagedOtherLost => {
            s.damaged(RECOVERED, Some(1));
            s.restore(K, A, CUT);
        }
        Retained::ColdStartAfterWholeLoss => s.damaged(RECOVERED, None),
        Retained::DamagedAfterUnansweredLookup => {
            s.restore(J, C, CUT);
            let lookup = s.begin_lookup(K, ClockSample::Seconds(1));
            s.end_lookup(lookup, TIMED_OUT, None);
            s.damaged(RECOVERED, Some(1));
        }
        Retained::Lost
        | Retained::ColdStart
        | Retained::ColdStartDamagedAfterServing
        | Retained::UnrecordedCut
        | Retained::AllCapturesRefused => {}
    }
    s.lookup(K, MISSING, None);
    s.lookup(J, MISSING, None);
    match retained {
        Retained::DamagedAfterServing => s.damaged(RECOVERED, Some(1)),
        Retained::ColdStartDamagedAfterServing => s.damaged(RECOVERED, None),
        _ => {}
    }
    s.finish()
}

/// T1's `removal` of A precedes T1's second restore of A and the
/// recapture of A and C in `OTHER_CUT`, so A is in the retained set T2
/// must restore; T2 restores C, or A and C when `restored`.
pub(super) fn removed_then_recaptured(removal: Removal, restored: bool) -> History {
    let mut s = Script::new();
    let publication = s.begin_publish(K, A, BODY, Some(5));
    s.close(publication, Some(ACK));
    s.publish(J, C, BODY);
    s.captured(RECOVERED, (K, A), CUT, (0, 1));
    s.captured(RECOVERED, (J, C), CUT, (0, 2));
    s.activate(RECOVERED, Some(T1), Some(CUT));
    s.restore(K, A, CUT);
    s.restore(J, C, CUT);
    match removal {
        Removal::Evict => s.evict(K, A),
        Removal::Expire => s.expire(K, A, 10),
        Removal::Ended(VisibilityCause::Expiry) => {
            s.expire(K, A, 10);
            s.ended(K, A, VisibilityCause::Expiry);
        }
        Removal::Ended(cause) => s.ended(K, A, cause),
    }
    s.restore(K, A, CUT);
    s.captured(RECOVERED, (K, A), OTHER_CUT, (0, 1));
    s.captured(RECOVERED, (J, C), OTHER_CUT, (0, 2));
    s.activate(RECOVERED, Some(T2), Some(OTHER_CUT));
    if restored {
        s.restore(K, A, OTHER_CUT);
    }
    s.restore(J, C, OTHER_CUT);
    s.lookup(K, MISSING, None);
    s.finish()
}

/// T1 activates from `CUT` and restores C; after T2 activates from `CUT`,
/// a T0-tagged invalidation of K bound to T2 times out, and T2 restores A
/// and C. The invalidation lands only in T2, so T1 lost A.
pub(super) fn invalidation_bound_above_recovery() -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.publish(J, C, BODY);
    s.captured(RECOVERED, (K, A), CUT, (0, 1));
    s.captured(RECOVERED, (J, C), CUT, (0, 2));
    s.activate(RECOVERED, Some(T1), Some(CUT));
    s.restore(J, C, CUT);
    s.activate(RECOVERED, Some(T2), Some(CUT));
    as_of(&mut s, Some(Tenure::INITIAL), Some(C1));
    let mut invalidation = s.begin_invalidate(K);
    invalidation.set_target(Place::In(T2));
    s.close_custody(invalidation, TIMED_OUT);
    as_of(&mut s, None, None);
    s.restore(K, A, CUT);
    s.restore(J, C, CUT);
    s.finish()
}

/// Client one's unversioned invalidation of K with an unrecorded target is
/// in custody when T1 activates; A's publication begins sampled at second
/// ten, the invalidation's custody ends timed out, a miss sampled at second
/// five follows, A is acknowledged and captured in `CUT`, and T2 activates
/// from `CUT` restoring nothing. The miss follows the invalidation's window
/// and its sample puts A's publication after the miss, so A is uncovered in
/// every legal order and T2 lost it.
pub(super) fn unbound_invalidation_before_forced_publication() -> History {
    let mut s = Script::new();
    s.by_client(Some(C1));
    let invalidation = s.begin_invalidate(K);
    s.by_client(None);
    s.activate(RECOVERED, Some(T1), None);
    let mut publication = s.begin_publish(K, A, BODY, None);
    publication.set_clock(ClockSample::Seconds(10));
    s.close_custody(invalidation, TIMED_OUT);
    let miss = s.begin_lookup(K, ClockSample::Seconds(5));
    s.end_lookup(miss, MISSING, None);
    s.close(publication, Some(ACK));
    s.captured(RECOVERED, (K, A), CUT, (0, 1));
    s.activate(RECOVERED, Some(T2), Some(CUT));
    s.lookup(K, MISSING, None);
    s.finish()
}

/// A hit, recorded restore, recorded expiry or recorded eviction of A in T1
/// witnesses A uncovered after T0's timed-out invalidation of K.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LaterUse {
    Hit,
    Restore,
    Expire,
    Evict,
}

pub(super) fn invalidation_omitted_in_later_tenure(used: LaterUse, restored: bool) -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.publish(J, C, BODY);
    s.captured(RECOVERED, (K, A), CUT, (0, 1));
    s.captured(RECOVERED, (J, C), CUT, (0, 2));
    let invalidation = s.begin_invalidate(K);
    s.close_custody(invalidation, TIMED_OUT);
    s.activate(RECOVERED, Some(T1), Some(CUT));
    match used {
        LaterUse::Hit => {
            if restored {
                s.restore(K, A, CUT);
            }
            s.restore(J, C, CUT);
            s.lookup(K, HIT, Some(A));
        }
        LaterUse::Expire | LaterUse::Evict => {
            if restored {
                s.restore(K, A, CUT);
            }
            s.restore(J, C, CUT);
            if used == LaterUse::Expire {
                s.expire(K, A, 10);
            } else {
                s.evict(K, A);
            }
        }
        LaterUse::Restore => {
            s.restore(K, A, CUT);
            s.restore(J, C, CUT);
            s.activate(RECOVERED, Some(T2), Some(CUT));
            if restored {
                s.restore(K, A, CUT);
            }
            s.restore(J, C, CUT);
        }
    }
    s.lookup(K, MISSING, None);
    s.finish()
}
