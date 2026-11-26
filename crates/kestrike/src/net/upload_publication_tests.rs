//! A client reports an upload Published only after the owner published it. A
//! receipt that covers every fragment says the owner received the bytes; only
//! PUT RESULT says the owner published them. The scenario separates the two
//! by holding every write command of the upload at the simulated device, so
//! the full receipt reaches the client while the owner cannot publish.

use crate::oracle::{ActionKind, Label, Obligation, Recorder, Verdict, check};
use crate::storage::CommandToken;
use crate::storage::owner_fixture::write_tokens;

use super::adapters::{Attempt, FRAGMENT, LEN, drive, drive_then, get, tenures};
use super::owner_tests::PRINCIPALS;
use super::put_tests::scene;
use super::upload::UploadOutcome;

/// Fragments of an object of [`LEN`] bytes.
const FRAGMENTS: u32 = LEN.div_ceil(FRAGMENT as u64) as u32;

/// What one recorded upload showed.
struct Observed {
    /// Write commands held at the device when the hold phase ended.
    held_writes: usize,
    /// The base of the client's receipt when the hold phase ended.
    receipt_base: u32,
    /// Whether the key was bound while the writes were held.
    published_while_held: bool,
    /// The client's outcome while the writes were held.
    outcome_while_held: Option<UploadOutcome>,
    /// The client's outcome at the end of the run.
    outcome: Option<UploadOutcome>,
    /// The publication row's and the client result row's places in the history.
    publish_row: Option<usize>,
    result_row: Option<usize>,
    /// The shared oracle's verdict over every recorded row.
    verdict: Verdict,
}

/// Records one upload of key 6 through the attempt adapter and a GET of the
/// key after it. With `hold`, every write command the owner submits for the
/// upload is held right after the owner's poll, before a device tick can run
/// it, until the client holds a receipt covering every fragment and every
/// source slot returned; the writes are then released. Each turn runs one
/// client poll and is observed, so the adapter orders every row.
fn recorded(hold: bool) -> Observed {
    let mut observed = None;
    scene(&PRINCIPALS, |mut scene| {
        let mut rec = Recorder::new(1);
        let mut tenures = tenures(&scene);
        let before = write_tokens(&scene.control).len();
        let mut attempt = Attempt::begin(&mut scene, &mut rec, (6, Label(1)), LEN, &mut tenures);
        let mut held: Vec<CommandToken> = Vec::new();
        let mut next = 0;
        for _ in 0..200 {
            while next < FRAGMENTS && attempt.supply(&mut scene, &mut rec, next) {
                next += 1;
            }
            drive_then(&mut scene, 1, &mut |control, _| {
                if hold {
                    for token in write_tokens(control).split_off(before + held.len()) {
                        control.hold(token);
                        held.push(token);
                    }
                }
            });
            attempt.observe(&scene, &mut rec);
            let received = attempt.receipt.0 == FRAGMENTS;
            if !hold || (received && attempt.slots.iter().all(Option::is_none)) {
                break;
            }
        }
        let (held_writes, receipt_base) = (held.len(), attempt.receipt.0);
        let (published_while_held, outcome_while_held) = (attempt.published, attempt.outcome);
        for token in held {
            scene.control.release(token);
        }
        for _ in 0..600 {
            while next < FRAGMENTS && attempt.supply(&mut scene, &mut rec, next) {
                next += 1;
            }
            drive(&mut scene, 1);
            attempt.observe(&scene, &mut rec);
            if attempt.published
                && attempt.outcome.is_some()
                && attempt.slots.iter().all(Option::is_none)
            {
                break;
            }
        }
        let outcome = attempt.outcome;
        get(&mut scene, &mut rec, 6, Label(1));
        let row = |kind| rec.rows().iter().position(|row| row.kind == kind);
        let (publish_row, result_row) = (row(ActionKind::Publish), row(ActionKind::PutResult));
        observed = Some(Observed {
            held_writes,
            receipt_base,
            published_while_held,
            outcome_while_held,
            outcome,
            publish_row,
            result_row,
            verdict: check(&rec.finish()),
        });
    });
    observed.expect("the scene ran its body")
}

/// The obligations a recorded upload and its GET activate.
const JUDGED: [Obligation; 4] = [
    Obligation::History,
    Obligation::Bytes,
    Obligation::Custody,
    Obligation::Resources,
];

/// The client holds a receipt covering every fragment while the owner's
/// writes are held, so the owner has published nothing. The client stays
/// undecided until the writes end and PUT RESULT arrives: the oracle finds
/// the `Published` result after the attempt's publication row.
#[test]
fn a_full_receipt_with_every_write_held_decides_published_only_after_the_publication() {
    let seen = recorded(true);
    // Premises: the scenario reached the state it is about.
    assert!(
        seen.held_writes > 0,
        "premise: the upload's writes were held"
    );
    assert_eq!(
        seen.receipt_base, FRAGMENTS,
        "premise: the client's receipt covers every fragment while the writes are held"
    );
    assert!(
        !seen.published_while_held,
        "premise: the owner publishes nothing while its writes are held"
    );
    // Judgments.
    assert!(
        seen.verdict.satisfies(&JUDGED),
        "the oracle refuses the upload's rows: {:?}",
        seen.verdict
    );
    assert_eq!(
        seen.outcome_while_held, None,
        "the client decided the upload before the owner published it"
    );
    assert_eq!(seen.outcome, Some(UploadOutcome::Published));
    assert!(
        seen.publish_row.is_some() && seen.publish_row < seen.result_row,
        "the publication row {:?} precedes the result row {:?}",
        seen.publish_row,
        seen.result_row
    );
}

/// The same upload with no write held: the owner publishes as the fragments
/// arrive, and the oracle passes the rows with the result after the
/// publication.
#[test]
fn the_same_upload_with_no_write_held_publishes_and_passes_the_oracle() {
    let seen = recorded(false);
    assert_eq!(seen.held_writes, 0, "premise: no write was held");
    assert!(
        seen.verdict.satisfies(&JUDGED),
        "the oracle refuses the upload's rows: {:?}",
        seen.verdict
    );
    assert_eq!(seen.outcome, Some(UploadOutcome::Published));
    assert!(
        seen.publish_row.is_some() && seen.publish_row < seen.result_row,
        "the publication row {:?} precedes the result row {:?}",
        seen.publish_row,
        seen.result_row
    );
}
