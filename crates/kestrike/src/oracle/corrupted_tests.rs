//! Each control pairs a scripted golden history with one edit to its recorded rows.
//! The base must pass with its declared obligations active. The edited history
//! must violate the named rule. A passing control test covers only the five
//! named rules, each for its specified edit on its scripted base.
//! These row edits can expose violations only in checks that read the finished history.
//! For a check on live simulator state, plant the defect during execution before
//! the check reads that state.

use super::golden::{A, B, BODY, FAILED, HIT, K, bytes, edited, put_then_get};
use super::row::Field;
use super::tenure_golden::{Retained, rejected_below_high_water, retained};
use super::{ActionKind, History, Obligation, Recorder, Row, Script, check};

struct Control {
    name: &'static str,
    base: fn() -> History,
    declared: &'static [Obligation],
    edit: fn(&mut Vec<Row>),
    // `fields` lists direct assignments; duplication also renumbers ordinals to keep them distinct.
    fields: &'static [Field],
}

fn published_get() -> History {
    put_then_get(bytes(K, A, BODY))
}

fn two_failed_uploads() -> History {
    let mut script = Script::new();
    let first = script.upload(K, A, BODY, true);
    let second = script.upload(K, B, BODY, true);
    script.put_result(first, K, A, FAILED);
    script.put_result(second, K, B, FAILED);
    script.finish()
}

const CONTROLS: [Control; 5] = [
    // O-RESTART requires this restart to restore retained label A on K.
    Control {
        name: "missing-restore",
        base: || retained(Retained::Restored),
        declared: &[Obligation::Restart],
        edit: |rows| {
            let index = rows
                .iter()
                .position(|row| {
                    row.kind == ActionKind::Restore && row.key() == Some(K) && row.label == Some(A)
                })
                .expect("missing-restore needs the restore of A on K");
            rows.remove(index);
        },
        fields: &[],
    },
    // O-BYTES requires a complete read to return the published label's content.
    Control {
        name: "wrong-delivered-byte",
        base: published_get,
        declared: &[Obligation::History, Obligation::Bytes],
        edit: |rows| {
            let row = rows
                .iter_mut()
                .find(|row| {
                    row.kind == ActionKind::Deliver && row.key() == Some(K) && row.label == Some(A)
                })
                .expect("wrong-delivered-byte needs the delivery of A on K");
            *row.payload
                .as_mut()
                .and_then(|bytes| bytes.first_mut())
                .expect("wrong-delivered-byte needs a payload byte") ^= 1;
        },
        fields: &[Field::Payload],
    },
    // The attempt judgment requires each ACK receipt to count only distinct fragments
    // the owner validated before that ACK. `check` rejects the copied owner row itself:
    // it records a second validation of fragment index zero in the same attempt.
    Control {
        name: "duplicate-fragment",
        base: published_get,
        declared: &[Obligation::History, Obligation::Bytes],
        edit: |rows| {
            let index = rows
                .iter()
                .position(|row| {
                    row.kind == ActionKind::Fragment
                        && row.key() == Some(K)
                        && row.fragment == Some(0)
                })
                .expect("duplicate-fragment needs fragment zero on K");
            rows.insert(index + 1, rows[index].clone());
            Recorder::renumber(rows);
        },
        fields: &[],
    },
    // For a given key, each `Serial` belongs to a single upload attempt.
    Control {
        name: "shared-serial",
        base: two_failed_uploads,
        declared: &[Obligation::History],
        edit: |rows| {
            let attempt = |label| {
                rows.iter()
                    .find(|row| {
                        row.kind == ActionKind::PutBegin
                            && row.key() == Some(K)
                            && row.label == Some(label)
                    })
                    .expect("shared-serial needs both upload begins on K")
                    .op
            };
            let first = attempt(A);
            let second = attempt(B);
            let serial = rows
                .iter()
                .filter(|row| row.op == first)
                .find_map(|row| row.serial)
                .expect("shared-serial needs a serial on the first attempt");
            let mut serials = rows
                .iter_mut()
                .filter(|row| row.op == second)
                .filter_map(|row| row.serial.as_mut())
                .peekable();
            assert!(
                serials.peek().is_some(),
                "shared-serial needs a serial on the second attempt"
            );
            for slot in serials {
                *slot = serial;
            }
        },
        fields: &[Field::Serial],
    },
    // O-HISTORY and the client judgment require rejection below the client's high-water.
    Control {
        name: "accepted-stale-hit",
        base: || rejected_below_high_water(1),
        declared: &[Obligation::History],
        edit: |rows| {
            let acceptance = rows
                .iter_mut()
                .filter(|row| {
                    row.kind == ActionKind::Lookup
                        && row.key() == Some(K)
                        && row.label == Some(A)
                        && row.outcome == Some(HIT)
                })
                .filter_map(|row| row.acceptance.as_mut())
                .find(|acceptance| !acceptance.accepted)
                .expect("accepted-stale-hit needs a rejected hit on A on K");
            acceptance.accepted = true;
        },
        fields: &[Field::Acceptance],
    },
];

#[test]
fn every_corrupted_history_base_passes_unedited() {
    for control in &CONTROLS {
        let base = (control.base)();
        let verdict = check(&base);
        assert!(
            verdict.satisfies(control.declared),
            "{}: {verdict:?} must activate {:?}",
            control.name,
            control.declared
        );
        assert_eq!(
            check(&edited(&base, |_| {})),
            verdict,
            "{}: empty edit",
            control.name
        );
    }
}

#[test]
fn every_corrupted_history_control_fails_through_its_named_rule() {
    // Binding an expectation to the catalog requires a control entry that names this test.
    // `scripts/verify-receipts.py admit` reads `controls` from `verification/obligations.json`
    // and checks for each entry's `violation` text as a substring of the named test function's source.
    let expected = [
        (
            "missing-restore",
            Obligation::Restart,
            "a retained entry outside every damage set was lost on host loss",
        ),
        (
            "wrong-delivered-byte",
            Obligation::Bytes,
            "a complete read returned bytes other than the label's content",
        ),
        (
            "duplicate-fragment",
            Obligation::History,
            "an attempt validated one fragment twice",
        ),
        (
            "shared-serial",
            Obligation::History,
            "two attempts share one serial",
        ),
        (
            "accepted-stale-hit",
            Obligation::History,
            "a client accepted a response tagged below its high-water",
        ),
    ];
    assert_eq!(CONTROLS.each_ref().map(|c| c.name), expected.map(|e| e.0));
    for (control, (name, obligation, rule)) in CONTROLS.iter().zip(expected) {
        let base = (control.base)();
        let changed = edited(&base, control.edit);
        assert_ne!(
            changed.rows(),
            base.rows(),
            "{name}: edit did not change the rows"
        );
        // A field edit keeps the row count, and a removal or a duplication changes it by one.
        let count_delta = changed.rows().len().abs_diff(base.rows().len());
        assert_eq!(
            count_delta,
            usize::from(control.fields.is_empty()),
            "{name}: row count after edit of {:?}",
            control.fields
        );
        let verdict = check(&changed);
        assert_eq!(
            verdict.violated(),
            Some((obligation, rule)),
            "{name}: {verdict:?}"
        );
    }
}
