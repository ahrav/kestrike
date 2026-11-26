//! Segmented judgment against the whole check. Every golden, every custody
//! history and every cross-cut control, fed at each single cut and at every
//! ordinal at once, gets the whole check's verdict, first violation and
//! activations; cuts validate their pending operations; every limit stops
//! the continuation with its own bound; resources keep their owner
//! incarnation; and a stop proof ends only its own incarnation's retention.

use super::checker::check;
use super::custody::{Checkpoint, Custodian};
use super::custody_tests::remote_put_sources::{Fault, Order, sources};
use super::custody_tests::{BUFFER, nic_return, released_checkpoint};
use super::golden::{
    A, ACK, B, BODY, C, FAILED, HIT, J, K, MISSING, Position, bytes, completion_as_durability,
    goldens, held_read_across_invalidation, matching_retry, put_then_get, put_then_lookup,
    receipt_without_write, resolved, timed_out_publication, upload_as_durability,
};
use super::history::History;
use super::ids::{ClockSample, Label, OpId, ResourceKind};
use super::obligation::Obligation;
use super::recorder::Recorder;
use super::row::{Field, Row};
use super::script::Script;
use super::tenure::ActivationLog;
use super::tenure_golden::{
    T1, T2, covered_hit_from_later_tenure, deposed_hit_below_successor, outage_covered_twin,
    stale_route_publication, tenure_goldens,
};
use super::verdict::{Inconclusive, Verdict};
use super::{Continuation, Entry, Geometry, LIMITS, Limits, Ordinal, Owner, Pending, WideOp};
use super::{Outcome, PutOutcome, VisibilityCause};

/// The ordinal at which `row` completes.
fn end(row: &Row) -> u32 {
    row.ordinals().map(|(_, at)| at.0).max().unwrap_or(0)
}

fn start(row: &Row) -> u32 {
    row.ordinals().map(|(_, at)| at.0).min().unwrap_or(0)
}

/// `history`'s rows in completion order, as a recorder streams them.
fn streamed(history: &History) -> Vec<Row> {
    let mut rows = history.rows().to_vec();
    rows.sort_by_key(end);
    rows
}

fn sealed(rows: &[Row]) -> History {
    let mut history = History::new();
    for row in rows {
        history.push(row.clone());
    }
    history.seal();
    history
}

/// `verdict` with the operation it names given by its wide identity, which
/// the tests choose equal to the whole history's own.
fn widened(continuation: &Continuation, verdict: Verdict) -> Verdict {
    let Some(WideOp(wide)) = continuation.named(&verdict) else {
        return verdict;
    };
    let op = OpId(u32::try_from(wide).unwrap());
    match verdict {
        Verdict::Violation(violation) => {
            Verdict::Violation(super::verdict::Violation { op, ..violation })
        }
        Verdict::Inconclusive(Inconclusive::Malformed { field, .. }) => {
            Verdict::Inconclusive(Inconclusive::Malformed { op, field })
        }
        Verdict::Inconclusive(Inconclusive::Unresolved { decision, .. }) => {
            Verdict::Inconclusive(Inconclusive::Unresolved { op, decision })
        }
        Verdict::Inconclusive(Inconclusive::PoisonedReport { report, .. }) => {
            Verdict::Inconclusive(Inconclusive::PoisonedReport { op, report })
        }
        Verdict::Inconclusive(Inconclusive::AbsentReport { report, .. }) => {
            Verdict::Inconclusive(Inconclusive::AbsentReport { op, report })
        }
        Verdict::Inconclusive(Inconclusive::UnloggedTenure { tenure, .. }) => {
            Verdict::Inconclusive(Inconclusive::UnloggedTenure { op, tenure })
        }
        Verdict::Inconclusive(Inconclusive::UnplacedSample { .. }) => {
            Verdict::Inconclusive(Inconclusive::UnplacedSample { op })
        }
        other => other,
    }
}

/// One owner's entry for `row`, its wide identity its own operation.
fn entry(row: &Row, owner: u64) -> Entry {
    Entry::new(row.clone(), WideOp(u64::from(row.op.0)), Owner(owner))
}

/// The continuation fed `rows` in completion order, cut before each ordinal
/// of `cuts`, each cut declaring the operations whose later rows began
/// before it; `owner` names each row's owner incarnation.
fn fed(rows: &[Row], cuts: &[u32], limits: Limits, owner: impl Fn(&Row) -> u64) -> Continuation {
    fed_with(rows, cuts, limits, &owner, |_, _| {})
}

/// [`fed`] with `before` run on the continuation and the rows not yet fed
/// just before each cut's segment is admitted.
fn fed_with(
    rows: &[Row],
    cuts: &[u32],
    limits: Limits,
    owner: &impl Fn(&Row) -> u64,
    before: impl FnMut(&mut Continuation, &[Row]),
) -> Continuation {
    let (mut continuation, at) = cut_with(rows, cuts, limits, owner, before);
    let rest: Vec<Entry> = rows[at..]
        .iter()
        .map(|row| entry(row, owner(row)))
        .collect();
    continuation.segment(rest, Ordinal(u32::MAX), &[]);
    continuation
}

/// The continuation fed `rows` cut before each ordinal of `cuts` and no
/// further, each cut declaring every operation one of whose later rows
/// began before it, invoked where the earliest of those rows began, with
/// `before` run on the continuation and the rows not yet fed just before
/// each cut's segment is admitted; and the count of rows fed.
fn cut_with(
    rows: &[Row],
    cuts: &[u32],
    limits: Limits,
    owner: &impl Fn(&Row) -> u64,
    mut before: impl FnMut(&mut Continuation, &[Row]),
) -> (Continuation, usize) {
    let mut continuation = Continuation::new(limits, Geometry::GOLDEN);
    let mut at = 0;
    for &cut in cuts {
        let taken = rows[at..].iter().take_while(|row| end(row) < cut).count();
        let segment: Vec<Entry> = rows[at..at + taken]
            .iter()
            .map(|row| entry(row, owner(row)))
            .collect();
        at += taken;
        let mut pending: Vec<Pending> = Vec::new();
        for later in &rows[at..] {
            let op = WideOp(u64::from(later.op.0));
            if start(later) < cut && !pending.iter().any(|p| p.op == op) {
                let invoked = rows[at..]
                    .iter()
                    .filter(|row| row.op == later.op)
                    .map(start)
                    .min()
                    .unwrap();
                pending.push(Pending {
                    op,
                    invoked: Ordinal(invoked),
                });
            }
        }
        before(&mut continuation, &rows[at..]);
        continuation.segment(segment, Ordinal(cut), &pending);
    }
    (continuation, at)
}

/// The continuation's final verdict over `rows` cut at `cuts`, in the whole
/// history's identities.
fn judged(rows: &[Row], cuts: &[u32]) -> Verdict {
    finished(&fed(rows, cuts, LIMITS, |_| 0))
}

/// `continuation`'s final verdict in the whole history's identities.
fn finished(continuation: &Continuation) -> Verdict {
    widened(continuation, continuation.finish())
}

/// Whole and segmented checks of `history` agree at every single cut and
/// with a cut at every ordinal, and return the whole verdict.
fn agrees_at_every_cut(history: &History) -> Verdict {
    agrees_fed(history, |rows, cuts| fed(rows, cuts, LIMITS, |_| 0))
}

/// [`agrees_at_every_cut`] with each segmented check's continuation built
/// by `feed` from the streamed rows and the cuts.
fn agrees_fed(history: &History, feed: impl Fn(&[Row], &[u32]) -> Continuation) -> Verdict {
    let rows = streamed(history);
    let whole = check(&sealed(&rows));
    let judged = |cuts: &[u32]| finished(&feed(&rows, cuts));
    let last = rows.iter().map(end).max().unwrap_or(0) + 1;
    for cut in 0..=last {
        assert_eq!(judged(&[cut]), whole, "a cut before ordinal {cut}");
    }
    let every: Vec<u32> = (1..=last).collect();
    assert_eq!(judged(&every), whole, "a cut at every ordinal");
    whole
}

/// A write quota returns after its own command's terminal while the command
/// slot's next incarnation is held: the quota and its command share one
/// compact index.
fn quota_under_reused_command() -> History {
    let mut r = Recorder::new(1);
    let old = (ResourceKind::Command, 0, 0x100);
    let quota = (ResourceKind::WriteQuota, 0, 0x100);
    let reused = (ResourceKind::Command, 0, 0x101);
    r.take(old, Custodian::Storage, None);
    r.take(quota, Custodian::Storage, Some((0, 8)));
    r.terminal(old, Outcome::Complete);
    r.take(reused, Custodian::Storage, None);
    r.release(quota, Custodian::Storage);
    r.terminal(reused, Outcome::Complete);
    r.checkpoint(Checkpoint::Released);
    r.finish()
}

/// Every golden and every passing custody history judges alike whole,
/// streamed in completion order, and segmented at any cut, including the
/// pending publications whose landing stays open across a cut and the
/// held rights that cross every cut.
#[test]
fn whole_and_segmented_goldens_agree_at_every_cut() {
    let mut histories = goldens();
    histories.push(nic_return(false).finish());
    histories.push(released_checkpoint(None).finish());
    histories.push(sources(Order::ReceiptFirst, None));
    histories.push(sources(Order::NicFirst, None));
    histories.push(quota_under_reused_command());
    let (mut collapsed, mut widest) = (0, 0);
    for history in &histories {
        let whole = check(history);
        assert!(matches!(whole, Verdict::Pass(_)), "{whole:?}");
        assert_eq!(agrees_at_every_cut(history), whole);
        let rows = streamed(history);
        let every: Vec<u32> = (1..=rows.iter().map(end).max().unwrap() + 1).collect();
        let (ops, states) = fed(&rows, &every, LIMITS, |_| 0).collapsed();
        collapsed += ops;
        widest = widest.max(states);
    }
    assert!(
        collapsed > 0,
        "the goldens collapse operations into frontiers"
    );
    assert_eq!(widest, 1);
}

/// An invalidation overlapping a replacement leaves the replacement's label
/// covered or uncovered, so a cut after both carries a frontier of two
/// states: a later hit on the replacement passes as the whole check passes
/// it, a hit on the covered incumbent or on a third label fails as the whole
/// check fails it, and a frontier limit of one stops with
/// `ContinuationBound` before dropping a state.
#[test]
fn a_frontier_keeps_every_admissible_state_across_a_cut() {
    let concurrent = |label| {
        let mut s = Script::new();
        s.publish(K, A, BODY);
        let first = s.begin_invalidate(K);
        let second = s.begin_replace(K, B, BODY);
        s.close(first, Some(ACK));
        s.close(second, Some(ACK));
        s.lookup(K, HIT, Some(label));
        s.finish()
    };
    let overlapping = |second_cut: bool| {
        let mut s = Script::new();
        s.publish(K, A, BODY);
        let first = s.begin_invalidate(K);
        let second = s.begin_replace(K, B, BODY);
        s.close(first, Some(ACK));
        s.close(second, Some(ACK));
        if second_cut {
            s.lookup(K, HIT, Some(B));
        }
        let one = s.begin_lookup(K, ClockSample::Seconds(1));
        let two = s.begin_lookup(K, ClockSample::Seconds(1));
        s.end_lookup(one, HIT, Some(B));
        s.end_lookup(two, HIT, Some(A));
        s.finish()
    };
    for second_cut in [false, true] {
        let whole = agrees_at_every_cut(&overlapping(second_cut));
        assert!(!matches!(whole, Verdict::Pass(_)), "{whole:?}");
    }
    for label in [A, B, C] {
        let history = concurrent(label);
        let whole = agrees_at_every_cut(&history);
        assert_eq!(
            matches!(whole, Verdict::Pass(_)),
            label == B,
            "{label:?}: {whole:?}"
        );
        let rows = streamed(&history);
        let lookup = rows.iter().map(start).max().unwrap();
        let mut carried = Continuation::new(LIMITS, Geometry::GOLDEN);
        let before = rows.iter().filter(|row| end(row) < lookup);
        carried.segment(
            before.map(|row| entry(row, 0)).collect(),
            Ordinal(lookup),
            &[],
        );
        assert_eq!(
            carried.collapsed().1,
            2,
            "both orders' states cross the cut"
        );
        let narrowed = fed(
            &rows,
            &[lookup],
            Limits {
                frontier: 1,
                ..LIMITS
            },
            |_| 0,
        )
        .judge();
        assert_eq!(
            narrowed,
            Verdict::Inconclusive(Inconclusive::ContinuationBound {
                dimension: "frontier",
                limit: 1
            }),
            "a narrower frontier stops before dropping a state"
        );
    }
}

/// The recovered lookup treats a write completion as durable payload
/// evidence, and a released checkpoint after the recovered lookup retains a
/// leaked buffer.
fn leak_after_unadmitted_recovery() -> History {
    let mut rows = completion_as_durability(true).rows().to_vec();
    let ops = rows.iter().map(|row| row.op.0).max().unwrap() + 1;
    let ordinals = rows.iter().map(end).max().unwrap() + 1;
    let shift = |at: &mut Option<Ordinal>| {
        if let Some(Ordinal(ordinal)) = at {
            *ordinal += ordinals;
        }
    };
    for mut row in released_checkpoint(Some(BUFFER)).finish().rows().to_vec() {
        row.op = OpId(row.op.0 + ops);
        shift(&mut row.invoked);
        shift(&mut row.responded);
        shift(&mut row.custody_end);
        rows.push(row);
    }
    sealed(&rows)
}

/// A sampled lookup, then a lookup on another key invoked after it with a
/// lower sample: the shared timeline regresses across any cut between them.
fn regressed_clock() -> History {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, Some(10));
    s.close(publish, Some(ACK));
    let publish = s.begin_publish(J, C, BODY, Some(20));
    s.close(publish, Some(ACK));
    let at = s.begin_lookup(K, ClockSample::Seconds(10));
    s.end_lookup(at, Outcome::Expired, Some(A));
    let later = s.begin_lookup(J, ClockSample::Seconds(1));
    s.end_lookup(later, HIT, Some(C));
    s.finish()
}

/// The existing and PUT cross-cut controls fail under every cut, each named
/// control by its named rule: a
/// hit on a covered publication, a write completion as durability, a full
/// receipt or ACK taken as success, a hit on an unpublished upload, a
/// republished retry, wrong bytes, an upload as durability, early reuse, a
/// leaked charge, an early source release, a source reused under its NIC
/// reference, a failed owner returning custody its unproven stop retained,
/// a covered hit after a miss during an outage and a clock that regresses
/// across a cut; an `Unknown` result that regresses to `NotStarted` and hits
/// on two keys' unpublished labels judge as the whole check judges them.
#[test]
fn cross_cut_controls_fail_by_name_under_every_cut() {
    let controls = [
        (
            held_read_across_invalidation(HIT, Some(A)),
            Some((
                Obligation::History,
                "a hit of a version an acknowledged invalidation covered",
            )),
        ),
        (
            completion_as_durability(true),
            Some((
                Obligation::Restart,
                "a write completion was taken as durable payload evidence",
            )),
        ),
        (
            receipt_without_write(PutOutcome::Published, MISSING),
            Some((
                Obligation::History,
                "Published without the attempt's publication",
            )),
        ),
        (
            receipt_without_write(FAILED, HIT),
            Some((
                Obligation::History,
                "a hit of a version no linearized fill published",
            )),
        ),
        (
            matching_retry(true),
            Some((Obligation::History, "an attempt published twice")),
        ),
        (
            put_then_get(bytes(K, B, BODY)),
            Some((
                Obligation::Bytes,
                "a complete read returned bytes other than the label's content",
            )),
        ),
        (
            upload_as_durability(true),
            Some((
                Obligation::Restart,
                "a write completion was taken as durable payload evidence",
            )),
        ),
        (
            nic_return(true).finish(),
            Some((
                Obligation::Custody,
                "a resource was reused while a custodian held an earlier incarnation",
            )),
        ),
        (
            released_checkpoint(Some(BUFFER)).finish(),
            Some((
                Obligation::Resources,
                "a released checkpoint kept capacity its obligations no longer justify",
            )),
        ),
        (
            sources(Order::ReceiptFirst, Some(Fault::MaskOnly)),
            Some((
                Obligation::Custody,
                "retransmission retention ended before the receipt base passed its fragment",
            )),
        ),
        (resolved(true, PutOutcome::NotStarted), None),
        (
            isolated_release(),
            Some((
                Obligation::Isolation,
                "a failed owner returned custody its unproven stop retained",
            )),
        ),
        (
            sources(Order::ReceiptFirst, Some(Fault::ReuseUnderNic)),
            Some((
                Obligation::Custody,
                "a resource was reused while a custodian held an earlier incarnation",
            )),
        ),
        (
            outage_covered_twin(),
            Some((
                Obligation::History,
                "a hit of a version an acknowledged invalidation covered",
            )),
        ),
        (two_keys_unpublished(), None),
        (
            leak_after_unadmitted_recovery(),
            Some((
                Obligation::Resources,
                "a released checkpoint kept capacity its obligations no longer justify",
            )),
        ),
        (
            regressed_clock(),
            Some((
                Obligation::History,
                "a clock sample regressed behind an earlier one",
            )),
        ),
    ];
    for (history, named) in &controls {
        let whole = check(history);
        assert!(!matches!(whole, Verdict::Pass(_)), "{whole:?}");
        if let Some(named) = named {
            assert_eq!(whole.violated(), Some(*named));
        }
        agrees_at_every_cut(history);
    }
    for fault in [
        Fault::MaskOnly,
        Fault::ReuseUnderNic,
        Fault::DuplicateCredit,
        Fault::OvercountedReceipt,
        Fault::EarlyCredit,
        Fault::MislabelledRelease,
        Fault::ForeignCancel,
        Fault::InventedMaskBit,
    ] {
        let history = sources(Order::ReceiptFirst, Some(fault));
        assert!(check(&history).violated().is_some(), "{fault:?}");
        agrees_at_every_cut(&history);
    }
    for leak in [
        BUFFER,
        (ResourceKind::Slot, 3, 7),
        (ResourceKind::Command, 2, 0x10002),
        (ResourceKind::Credit, 0, 0),
    ] {
        let history = released_checkpoint(Some(leak)).finish();
        assert!(check(&history).violated().is_some(), "{leak:?}");
        agrees_at_every_cut(&history);
    }
}

/// A failed owner's isolated stop retains a buffer, which it then returns.
fn isolated_release() -> History {
    let mut r = Recorder::new(1);
    r.take(BUFFER, Custodian::Owner, None);
    r.isolated(BUFFER);
    r.release(BUFFER, Custodian::Owner);
    r.finish()
}

/// Hits on unpublished labels of two keys: the first key in key order names
/// the violation under every cut.
fn two_keys_unpublished() -> History {
    let mut s = Script::new();
    s.lookup(J, HIT, Some(C));
    s.lookup(K, HIT, Some(A));
    s.finish()
}

#[test]
fn a_tied_regression_names_the_whole_checks_operation() {
    let mut s = Script::new();
    let first = s.begin_lookup(K, ClockSample::Seconds(2));
    s.ended(K, A, VisibilityCause::Expiry);
    let early = s.begin_lookup(K, ClockSample::Seconds(0));
    let late = s.begin_lookup(K, ClockSample::Seconds(0));
    s.end_lookup(first, MISSING, None);
    s.end_lookup(late, MISSING, None);
    let regressed = s.end_lookup(early, MISSING, None);
    let whole = agrees_at_every_cut(&s.finish());
    assert_eq!(
        whole,
        Verdict::Violation(super::verdict::Violation {
            obligation: Obligation::History,
            op: regressed,
            rule: "a clock sample regressed behind an earlier one",
        })
    );
}

/// A row that began before a cut that never declared it, a row that starts
/// before its declared invocation, a first declaration invoked before the
/// previous cut, a redeclaration that moves its invocation earlier, a
/// declared pending operation no later row answers, an upload cut while
/// pending whose rows never arrive, a row naming another owner incarnation
/// than its operation's earlier rows, a row that completes at its cut, a
/// row that arrives at a cut before the previous one, a declaration at its
/// cut, and one cut declaring an operation twice, are each malformed; a later declaration keeps an operation open
/// across another cut; and every PUT golden has a cut that leaves part of
/// its upload pending.
#[test]
fn a_cut_validates_its_pending_operations() {
    let rows = streamed(&timed_out_publication((HIT, Some(A)), (HIT, Some(A))));
    let straddling = rows
        .iter()
        .find(|row| start(row) < end(row))
        .expect("a row spans ordinals");
    let cut = start(straddling) + 1;
    let (before, after): (Vec<&Row>, Vec<&Row>) = rows.iter().partition(|row| end(row) < cut);
    let mut undeclared = Continuation::new(LIMITS, Geometry::GOLDEN);
    undeclared.segment(
        before.iter().map(|row| entry(row, 0)).collect(),
        Ordinal(cut),
        &[],
    );
    undeclared.segment(
        after.iter().map(|row| entry(row, 0)).collect(),
        Ordinal(u32::MAX),
        &[],
    );
    assert!(matches!(
        undeclared.judge(),
        Verdict::Inconclusive(Inconclusive::Malformed {
            field: Field::Invocation,
            ..
        })
    ));
    let mut forgotten = Continuation::new(LIMITS, Geometry::GOLDEN);
    let pending = [Pending {
        op: WideOp(900),
        invoked: Ordinal(0),
    }];
    forgotten.segment(Vec::new(), Ordinal(1), &pending);
    assert_eq!(
        forgotten.finish(),
        Verdict::Inconclusive(Inconclusive::Malformed {
            op: OpId(0),
            field: Field::Response,
        }),
        "a forgotten pending operation"
    );
    let upload = goldens()
        .iter()
        .map(streamed)
        .find(|rows| rows.iter().any(|row| start(row) + 2 < end(row)))
        .expect("a golden row spans a cut");
    let last = upload.iter().map(end).max().unwrap();
    let open = (1..last)
        .find(|&cut| {
            upload
                .iter()
                .any(|row| end(row) >= cut && start(row) + 1 < cut)
        })
        .expect("a cut leaves a row pending");
    let (before, after): (Vec<&Row>, Vec<&Row>) = upload.iter().partition(|row| end(row) < open);
    let mut declared: Vec<Pending> = Vec::new();
    for row in after.iter().filter(|row| start(row) < open) {
        let op = WideOp(u64::from(row.op.0));
        if !declared.iter().any(|pending| pending.op == op) {
            declared.push(Pending {
                op,
                invoked: Ordinal(start(row)),
            });
        }
    }
    let first = |rows: &[&Row]| rows.iter().map(|row| entry(row, 0)).collect::<Vec<_>>();
    let upload = streamed(&sources(Order::ReceiptFirst, None));
    let during = (1..upload.iter().map(end).max().unwrap())
        .find(|&cut| upload.iter().any(|row| start(row) < cut && cut <= end(row)))
        .expect("a cut falls inside the upload");
    let (sent, withheld_rows): (Vec<&Row>, Vec<&Row>) =
        upload.iter().partition(|row| end(row) < during);
    let mut open_upload: Vec<Pending> = Vec::new();
    for row in withheld_rows.iter().filter(|row| start(row) < during) {
        let op = WideOp(u64::from(row.op.0));
        if !open_upload.iter().any(|pending| pending.op == op) {
            open_upload.push(Pending {
                op,
                invoked: Ordinal(start(row)),
            });
        }
    }
    let mut withheld = Continuation::new(LIMITS, Geometry::GOLDEN);
    withheld.segment(first(&sent), Ordinal(during), &open_upload);
    assert!(
        matches!(
            withheld.finish(),
            Verdict::Inconclusive(Inconclusive::Malformed {
                field: Field::Response,
                ..
            })
        ),
        "a pending upload whose rows never arrive"
    );
    let shifted = declared
        .iter()
        .find(|pending| pending.invoked.0 + 1 < open)
        .copied()
        .expect("a declaration can move later and stay before the cut");
    let late: Vec<Pending> = declared
        .iter()
        .map(|pending| {
            if pending.op == shifted.op {
                Pending {
                    invoked: Ordinal(pending.invoked.0 + 1),
                    ..*pending
                }
            } else {
                *pending
            }
        })
        .collect();
    let mut misdeclared = Continuation::new(LIMITS, Geometry::GOLDEN);
    misdeclared.segment(first(&before), Ordinal(open), &late);
    misdeclared.segment(first(&after), Ordinal(u32::MAX), &[]);
    let verdict = misdeclared.finish();
    assert!(
        matches!(
            verdict,
            Verdict::Inconclusive(Inconclusive::Malformed {
                field: Field::Invocation,
                ..
            })
        ),
        "a row that starts before its declared invocation: {verdict:?}"
    );
    assert_eq!(misdeclared.named(&verdict), Some(shifted.op));
    let mut moved = Continuation::new(LIMITS, Geometry::GOLDEN);
    moved.segment(first(&before), Ordinal(open), &late);
    moved.segment(Vec::new(), Ordinal(open + 1), &declared);
    assert!(
        matches!(
            moved.finish(),
            Verdict::Inconclusive(Inconclusive::Malformed {
                field: Field::Invocation,
                ..
            })
        ),
        "a redeclaration that moves its invocation earlier"
    );
    for history in [
        sources(Order::ReceiptFirst, None),
        put_then_get(bytes(K, A, BODY)),
        matching_retry(false),
        put_then_lookup(
            Some(PutOutcome::Unknown),
            true,
            (HIT, Some(A)),
            Position::AfterResult,
        ),
    ] {
        let rows = streamed(&history);
        let last = rows.iter().map(end).max().unwrap();
        assert!(
            (1..last).any(|cut| rows.iter().any(|row| end(row) >= cut && start(row) < cut)),
            "a cut leaves an upload operation pending"
        );
    }
    let mut undeclared_then_late = Continuation::new(LIMITS, Geometry::GOLDEN);
    undeclared_then_late.segment(Vec::new(), Ordinal(5), &[]);
    undeclared_then_late.segment(
        Vec::new(),
        Ordinal(8),
        &[Pending {
            op: WideOp(7),
            invoked: Ordinal(2),
        }],
    );
    assert!(
        matches!(
            undeclared_then_late.finish(),
            Verdict::Inconclusive(Inconclusive::Malformed {
                field: Field::Invocation,
                ..
            })
        ),
        "a first declaration invoked before the previous cut"
    );
    let mut kept = Continuation::new(LIMITS, Geometry::GOLDEN);
    kept.segment(Vec::new(), Ordinal(1), &pending);
    kept.segment(Vec::new(), Ordinal(2), &pending);
    assert!(
        matches!(kept.judge(), Verdict::Pass(_)),
        "a redeclared pending operation stays open"
    );
    let malformed = |continuation: &Continuation, field: Field, case: &str| {
        let verdict = continuation.judge();
        assert!(
            matches!(
                verdict,
                Verdict::Inconclusive(Inconclusive::Malformed { field: found, .. }) if found == field
            ),
            "{case}: {verdict:?}"
        );
    };
    let (owned, other) = (&upload[0], &upload[1]);
    assert_eq!(
        owned.op, other.op,
        "the golden's first two rows share an operation"
    );
    let mut reowned = Continuation::new(LIMITS, Geometry::GOLDEN);
    reowned.segment(
        vec![entry(owned, 0), entry(other, 1)],
        Ordinal(u32::MAX),
        &[],
    );
    malformed(
        &reowned,
        Field::Resource,
        "a row naming another owner incarnation than its operation's earlier rows",
    );
    let mut unfinished = Continuation::new(LIMITS, Geometry::GOLDEN);
    unfinished.segment(vec![entry(straddling, 0)], Ordinal(end(straddling)), &[]);
    malformed(
        &unfinished,
        Field::Response,
        "a row that completes at its segment's cut",
    );
    let past = upload.iter().map(end).max().unwrap() + 1;
    let mut retrograde = Continuation::new(LIMITS, Geometry::GOLDEN);
    retrograde.segment(Vec::new(), Ordinal(past + 1), &[]);
    retrograde.segment(vec![entry(owned, 0)], Ordinal(past), &[]);
    malformed(
        &retrograde,
        Field::Response,
        "a row that arrives at a cut before the previous one",
    );
    let mut at_cut = Continuation::new(LIMITS, Geometry::GOLDEN);
    at_cut.segment(
        Vec::new(),
        Ordinal(open),
        &[Pending {
            op: WideOp(900),
            invoked: Ordinal(open),
        }],
    );
    malformed(&at_cut, Field::Invocation, "a declaration at its cut");
    let twice = Pending {
        op: WideOp(900),
        invoked: Ordinal(0),
    };
    let mut duplicated = Continuation::new(LIMITS, Geometry::GOLDEN);
    duplicated.segment(Vec::new(), Ordinal(open), &[twice, twice]);
    malformed(
        &duplicated,
        Field::Invocation,
        "one cut declaring an operation twice",
    );
}

/// Each limit stops the continuation with its own bound before it drops a
/// row or a state, and the stop holds over every later segment.
#[test]
fn every_limit_stops_with_its_own_bound() {
    let golden = streamed(&timed_out_publication((HIT, Some(A)), (HIT, Some(A))));
    let last = golden.iter().map(end).max().unwrap() + 1;
    let every: Vec<u32> = (1..=last).collect();
    let bounded = |limits: Limits| fed(&golden, &every, limits, |_| 0).judge();
    let bound = |dimension, limit| {
        Verdict::Inconclusive(Inconclusive::ContinuationBound { dimension, limit })
    };
    assert_eq!(
        bounded(Limits {
            frontier: 0,
            ..LIMITS
        }),
        bound("frontier", 0)
    );
    assert_eq!(
        bounded(Limits {
            search: 0,
            ..LIMITS
        }),
        Verdict::Inconclusive(Inconclusive::SearchBound { limit: 0 })
    );
    let whole = fed(
        &golden,
        &[],
        Limits {
            window: 2,
            ..LIMITS
        },
        |_| 0,
    )
    .judge();
    assert_eq!(whole, bound("window", 2));
    let rows = fed(&golden, &every, Limits { rows: 3, ..LIMITS }, |_| 0).judge();
    assert_eq!(rows, bound("rows", 3));
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let held = s.begin_lookup(K, ClockSample::Seconds(1));
    for _ in 0..6 {
        s.invalidate(J, ACK);
    }
    s.end_lookup(held, HIT, Some(A));
    let spanned = streamed(&s.finish());
    let every: Vec<u32> = (1..=spanned.iter().map(end).max().unwrap() + 1).collect();
    let small = Limits {
        window: 4,
        ..LIMITS
    };
    assert_eq!(
        fed(&spanned, &every, small, |_| 0).judge(),
        bound("key window", 4),
        "each segment fits, and one key's open operations do not"
    );
    assert_eq!(
        judged(&spanned, &every),
        check(&sealed(&spanned)),
        "the default window judges it as the whole check does"
    );
    let midway: Vec<u32> = (1..spanned.iter().map(end).max().unwrap()).collect();
    let (open, _) = cut_with(&spanned, &midway, small, &|_| 0, |_, _| {});
    assert_eq!(
        open.judge(),
        bound("key window", 4),
        "a judgment midway orders more open operations than the window"
    );
    assert_eq!(
        open.collapsed().0,
        2,
        "only the operations before the held lookup collapse"
    );
    let mut pending = Continuation::new(
        Limits {
            pending: 0,
            ..LIMITS
        },
        Geometry::GOLDEN,
    );
    pending.segment(
        Vec::new(),
        Ordinal(1),
        &[Pending {
            op: WideOp(1),
            invoked: Ordinal(0),
        }],
    );
    pending.segment(
        golden.iter().map(|row| entry(row, 0)).collect(),
        Ordinal(u32::MAX),
        &[],
    );
    assert_eq!(pending.finish(), bound("pending", 0));
}

/// Wide operation identities past `u32` keep distinct compact identities: a
/// shifted control names its own wide operation, and two operations whose
/// identities differ only past bit 32 stay two. One resource index under two
/// owner incarnations is two resources: the second owner's take reuses
/// nothing the first holds.
#[test]
fn identities_are_wide_and_resources_carry_their_owner() {
    let control = streamed(&held_read_across_invalidation(HIT, Some(A)));
    let shift = |entries: &[Row], by: u64| -> Continuation {
        let mut continuation = Continuation::new(LIMITS, Geometry::GOLDEN);
        let shifted = entries
            .iter()
            .map(|row| Entry::new(row.clone(), WideOp(by + u64::from(row.op.0)), Owner(0)))
            .collect();
        continuation.segment(shifted, Ordinal(u32::MAX), &[]);
        continuation
    };
    let whole = check(&sealed(&control));
    let shifted = shift(&control, 1 << 40);
    let verdict = shifted.finish();
    assert_eq!(verdict.violated(), whole.violated());
    let named = |verdict: &Verdict| match verdict {
        Verdict::Violation(violation) => u64::from(violation.op.0),
        other => panic!("{other:?}"),
    };
    assert_eq!(
        shifted.named(&verdict),
        Some(WideOp((1 << 40) + named(&whole)))
    );
    let rows = streamed(&nic_return(false).finish());
    let mut split = Continuation::new(LIMITS, Geometry::GOLDEN);
    let wides: Vec<WideOp> = (0..rows.len() as u64)
        .map(|at| WideOp(if at % 2 == 0 { at } else { (1 << 32) + at - 1 }))
        .collect();
    let entries = rows
        .iter()
        .zip(&wides)
        .map(|(row, &op)| Entry::new(row.clone(), op, Owner(0)))
        .collect();
    split.segment(entries, Ordinal(u32::MAX), &[]);
    let mapped: Vec<WideOp> = (0..wides.len() as u32)
        .map(|op| split.wide(OpId(op)))
        .collect();
    assert_eq!(
        mapped, wides,
        "each wide identity keeps its own compact identity"
    );
    let mut r = Recorder::new(1);
    r.take(BUFFER, Custodian::Owner, None);
    let second = r.take(BUFFER, Custodian::Owner, None);
    let twice = streamed(&r.finish());
    assert_eq!(
        check(&sealed(&twice))
            .violated()
            .map(|(obligation, _)| obligation),
        Some(Obligation::Custody),
        "one owner taking a held resource again"
    );
    let owners = fed(&twice, &[], LIMITS, |row| u64::from(row.op == second));
    assert!(
        matches!(owners.finish(), Verdict::Pass(_)),
        "{:?}",
        owners.finish()
    );
}

/// Labels are wide: after label 0 is published and invalidated, a hit on
/// label 65,536 is a hit on a label never published, not the covered label 0 a
/// 16-bit label would wrap to; a published label past 16 bits serves its own
/// hit.
#[test]
fn labels_past_sixteen_bits_keep_their_own_identity() {
    let removed = |label: Label| {
        let mut s = Script::new();
        s.publish(K, Label(0), BODY);
        s.invalidate(K, ACK);
        s.lookup(K, HIT, Some(label));
        s.finish()
    };
    assert_eq!(
        agrees_at_every_cut(&removed(Label(0))).violated(),
        Some((
            Obligation::History,
            "a hit of a version an acknowledged invalidation covered"
        ))
    );
    assert_eq!(
        agrees_at_every_cut(&removed(Label(65_536))).violated(),
        Some((
            Obligation::History,
            "a hit of a version no linearized fill published"
        ))
    );
    let mut s = Script::new();
    s.publish(K, Label(65_536), BODY);
    s.lookup(K, HIT, Some(Label(65_536)));
    assert!(matches!(agrees_at_every_cut(&s.finish()), Verdict::Pass(_)));
}

/// An unproven stop retains its owner's custody across cuts: another owner
/// incarnation's stop proof ends nothing of it, so returning it is still a
/// violation, while its own incarnation's stop proof ends the retention.
#[test]
fn a_stop_proof_ends_only_its_own_incarnations_retention() {
    let history = |stopper: u64| {
        let mut r = Recorder::new(1);
        r.take(BUFFER, Custodian::Owner, None);
        r.checkpoint(Checkpoint::Unproven);
        let stopped = r.checkpoint(Checkpoint::Stopped);
        r.release(BUFFER, Custodian::Owner);
        let rows = streamed(&r.finish());
        let owner = move |row: &Row| if row.op == stopped { stopper } else { 0 };
        let last = rows.iter().map(end).max().unwrap() + 1;
        let every: Vec<u32> = (1..=last).collect();
        (rows.clone(), fed(&rows, &every, LIMITS, owner).judge())
    };
    let (rows, foreign) = history(1);
    assert!(
        matches!(check(&sealed(&rows)), Verdict::Pass(_)),
        "the default entry clears every retention at a stop"
    );
    assert_eq!(
        foreign.violated(),
        Some((
            Obligation::Resources,
            "an unproven stop returned retained custody"
        )),
        "another incarnation's stop proof"
    );
    let (_, own) = history(0);
    assert!(matches!(own, Verdict::Pass(_)), "{own:?}");
    let mut r = Recorder::new(1);
    r.take(BUFFER, Custodian::Owner, None);
    r.checkpoint(Checkpoint::Unproven);
    let released = r.checkpoint(Checkpoint::Released);
    r.release(BUFFER, Custodian::Owner);
    let rows = streamed(&r.finish());
    let foreign_release = fed(&rows, &[], LIMITS, |row| u64::from(row.op == released));
    assert_eq!(
        foreign_release.finish().violated(),
        Some((
            Obligation::Resources,
            "an unproven stop returned retained custody"
        )),
        "another incarnation's release ends nothing of a dead owner's custody"
    );
    let mut r = Recorder::new(1);
    let unproven = r.checkpoint(Checkpoint::Unproven);
    r.take(BUFFER, Custodian::Owner, None);
    r.release(BUFFER, Custodian::Owner);
    let rows = streamed(&r.finish());
    let held_before = |row: &Row| u64::from(row.op == unproven);
    let mut r = Recorder::new(1);
    r.take(BUFFER, Custodian::Owner, None);
    let stop = r.checkpoint(Checkpoint::Unproven);
    r.release(BUFFER, Custodian::Owner);
    let foreign_stop = streamed(&r.finish());
    assert_eq!(
        check(&sealed(&foreign_stop))
            .violated()
            .map(|(obligation, _)| obligation),
        Some(Obligation::Resources)
    );
    let scoped = fed(&foreign_stop, &[], LIMITS, |row| u64::from(row.op == stop)).finish();
    assert!(
        matches!(scoped, Verdict::Pass(_)),
        "another incarnation's unproven stop retains nothing of this owner: {scoped:?}"
    );
    assert!(matches!(
        fed(&rows, &[], LIMITS, held_before).finish(),
        Verdict::Pass(_)
    ));
}

/// An unproven stop's retention crosses many windows: with 300 lookups
/// between the stop and the release, more rows than the whole check admits,
/// the release still violates, and its own incarnation's stop proof before
/// it still ends the retention; another incarnation's two stop proofs end
/// nothing of it.
#[test]
fn retained_custody_crosses_many_windows() {
    let padded = |stops: &[u64]| {
        let mut r = Recorder::new(1);
        r.take(BUFFER, Custodian::Owner, None);
        r.checkpoint(Checkpoint::Unproven);
        for _ in 0..300 {
            r.lookup(J, MISSING, None);
        }
        let stopped: Vec<(OpId, u64)> = stops
            .iter()
            .map(|&owner| (r.checkpoint(Checkpoint::Stopped), owner))
            .collect();
        r.release(BUFFER, Custodian::Owner);
        (streamed(&r.finish()), stopped)
    };
    for (stops, passes) in [
        (&[][..], false),
        (&[1, 1][..], false),
        (&[1, 0][..], true),
        (&[0][..], true),
    ] {
        let (rows, stopped) = padded(stops);
        assert!(matches!(
            check(&sealed(&rows)),
            Verdict::Inconclusive(Inconclusive::HistoryBound { .. })
        ));
        let last = rows.iter().map(end).max().unwrap();
        let owner = |row: &Row| {
            stopped
                .iter()
                .find(|&&(op, _)| op == row.op)
                .map_or(0, |&(_, owner)| owner)
        };
        for cuts in [
            (100..last).step_by(100).collect::<Vec<u32>>(),
            (1..=last).collect(),
        ] {
            let verdict = fed(&rows, &cuts, LIMITS, owner).finish();
            if passes {
                assert!(
                    matches!(verdict, Verdict::Pass(_)),
                    "{stops:?}: {verdict:?}"
                );
            } else {
                assert_eq!(
                    verdict.violated(),
                    Some((
                        Obligation::Resources,
                        "an unproven stop returned retained custody"
                    )),
                    "{stops:?}"
                );
            }
            let (collapsed, _) = fed(&rows, &cuts, LIMITS, |_| 0).collapsed();
            assert!(collapsed > 128, "the lookups collapse across windows");
        }
    }
}

/// A released checkpoint judges its own owner incarnation's publications:
/// another incarnation's release passes over an open publication, and its
/// own release still fails on it.
#[test]
fn a_release_judges_only_its_own_incarnations_publications() {
    let mut r = Recorder::new(1);
    let slot = (ResourceKind::Slot, 3, 7);
    r.published(K, A, 4, BODY, (1, 1));
    r.hold(slot, Custodian::Storage, (K, A));
    r.release(slot, Custodian::Storage);
    let released = r.checkpoint(Checkpoint::Released);
    let rows = streamed(&r.finish());
    assert_eq!(
        check(&sealed(&rows)).violated(),
        Some((
            Obligation::Resources,
            "a released checkpoint left a publication's visibility open"
        ))
    );
    let foreign = fed(&rows, &[], LIMITS, |row| u64::from(row.op == released)).finish();
    assert!(matches!(foreign, Verdict::Pass(_)), "{foreign:?}");
    assert_eq!(judged(&rows, &[]), check(&sealed(&rows)));
}

/// The continuation fed `rows` cut before each ordinal of `cuts`, each cut
/// declaring its pending operations as [`cut_with`] does and, when
/// `tenure_cuts`, the lowest place among the rows not yet fed as its tenure
/// cut.
fn fed_with_tenure_cuts(rows: &[Row], cuts: &[u32], tenure_cuts: bool) -> Continuation {
    let all: Vec<&Row> = rows.iter().collect();
    let log = ActivationLog::of(&all).expect("a well-formed activation log");
    fed_with(rows, cuts, LIMITS, &|_| 0, |continuation, rest| {
        if let Some(floor) = rest
            .iter()
            .map(|row| log.place(row).tenure())
            .min()
            .filter(|_| tenure_cuts)
        {
            continuation.tenure_cut(floor);
        }
    })
}

/// Every tenure and retention golden judges alike whole and segmented at
/// every single cut and with a cut at every ordinal, each cut declaring the
/// lowest tenure still to come; the cuts include tenure cuts, cuts between
/// a miss and its hit and between an invalidation and a hit, and a cut
/// after a stale route sends an effect bound to a tenure below its tag.
/// Tenure cuts collapse operations that quiescent cuts alone keep open.
#[test]
fn tenure_cut_goldens_every_cut() {
    for history in tenure_goldens() {
        agrees_fed(&history, |rows, cuts| {
            fed_with_tenure_cuts(rows, cuts, true)
        });
    }
    for history in [
        covered_hit_from_later_tenure(),
        deposed_hit_below_successor(),
        stale_route_publication(),
    ] {
        let rows = streamed(&history);
        let every: Vec<u32> = (1..=rows.iter().map(end).max().unwrap_or(0) + 1).collect();
        let collapsed = |tenure_cuts| {
            fed_with_tenure_cuts(&rows, &every, tenure_cuts)
                .collapsed()
                .0
        };
        assert!(
            collapsed(true) > collapsed(false),
            "{} > {}",
            collapsed(true),
            collapsed(false)
        );
    }
}

/// A row placed below a declared tenure cut is malformed.
#[test]
fn a_row_below_a_declared_tenure_cut_is_malformed() {
    let rows = streamed(&deposed_hit_below_successor());
    let mut continuation = Continuation::new(LIMITS, Geometry::GOLDEN);
    continuation.tenure_cut(T2);
    continuation.segment(Vec::new(), Ordinal(0), &[]);
    let first = rows.iter().find(|row| row.tenure == Some(T1)).unwrap();
    continuation.segment(vec![entry(first, 0)], Ordinal(u32::MAX), &[]);
    let verdict = continuation.finish();
    assert!(matches!(
        verdict,
        Verdict::Inconclusive(Inconclusive::Malformed {
            field: Field::Tenure,
            ..
        })
    ));
    assert_eq!(
        continuation.named(&verdict),
        Some(WideOp(u64::from(first.op.0)))
    );
}

/// Overlapping interval invalidations of one live fill leave one frontier
/// state whatever order they linearize in, since equal revocation sets
/// compare equal.
#[test]
fn overlapping_interval_invalidations_of_a_live_fill_keep_one_state() {
    let mut s = Script::new();
    s.fill(K, B, BODY);
    let invalidations: Vec<_> = (1..=4)
        .map(|version| {
            let mut invalidation = s.begin_invalidate(K);
            invalidation.set_covers(super::coverage::Cover::Range {
                lo: version,
                hi: version + 1,
            });
            invalidation
        })
        .collect();
    for invalidation in invalidations {
        s.close(invalidation, Some(ACK));
    }
    s.lookup(K, MISSING, None);
    let history = s.finish();
    let rows = streamed(&history);
    let last = rows.iter().map(end).max().unwrap() + 1;
    let (collapsed, widest) = fed(&rows, &[last - 1], LIMITS, |_| 0).collapsed();
    assert!(collapsed > 4, "{collapsed}");
    assert_eq!(widest, 1);
    assert!(matches!(agrees_at_every_cut(&history), Verdict::Pass(_)));
}
