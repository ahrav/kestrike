//! A rerun of the fresh path at `E = 0` keeps the landed record's host ID.
//!
//! Once a valid record of the same binding and key incarnation has landed, a rerun of the fresh path at
//! `E = 0` returns that record with its full stored key and host ID and draws nothing; an absent record, a
//! sector that fails decoding and a record bound elsewhere get the supplied key and a newly drawn host ID; a
//! record file that cannot be read and a record of the same binding with another key incarnation refuse
//! before a draw.
//!
//! Every landed record is read back from the sector its `encode` wrote, as a rerun reads it. Each call counts
//! the runs of its `existing` and `draw` closures, and each expected record is built from the constants below,
//! not read back from the call under test.

use super::admission::{AdmissionError, fresh};
use super::evidence::Pair;
use super::identity::{Epoch, Incarnation, Key};
use super::record::{Binding, LocalRecord, RECORD_BYTES, RecordError};

/// The host ID the first run drew and the landed record stores.
const LANDED_HOST: [u8; 16] = [0xA1; 16];
/// The host ID every rerun's `draw` offers.
const RERUN_HOST: [u8; 16] = [0xB2; 16];
/// The attachment's key incarnation.
const INCARNATION: u32 = 7;
/// An incarnation the attachment never held.
const OTHER_INCARNATION: u32 = 8;
/// Epochs of the stored and the supplied key; `Key::attachment` gives epoch 1.
const EPOCHS: [u32; 3] = [1, 5, 0xFFFF_FFFE];

fn binding() -> Binding {
    Binding {
        instance: "i-0123456789abcdef0".into(),
        volume: "vol-0123456789abcdef0".into(),
        attachment: "attach-0001".into(),
    }
}

fn key(epoch: u32, incarnation: u32) -> Key {
    Key::new(
        Epoch::new(epoch).expect("an epoch in range"),
        Incarnation::new(incarnation).expect("an incarnation in range"),
    )
}

/// The sector an earlier run wrote for `binding` and `key` with the host ID `LANDED_HOST`.
fn landed_sector(binding: Binding, key: Key) -> [u8; RECORD_BYTES] {
    LocalRecord::fresh(binding, key, || Some(LANDED_HOST))
        .expect("a nonzero host ID")
        .encode()
        .expect("a record with valid identifiers")
}

/// What one call of the fresh path at attempt 0 returned, and how often it read the record and drew.
struct Rerun {
    outcome: Result<LocalRecord, AdmissionError>,
    reads: usize,
    draws: usize,
}

/// One call of `fresh` at `E = 0` for `binding` and `key` over what `existing` reads, with `RERUN_HOST` on offer.
fn rerun(
    binding: Binding,
    key: Key,
    existing: Result<Option<Result<LocalRecord, RecordError>>, AdmissionError>,
) -> Rerun {
    let (mut reads, mut draws) = (0, 0);
    let outcome = fresh(
        binding,
        key,
        0,
        || {
            reads += 1;
            existing
        },
        || {
            draws += 1;
            Some(RERUN_HOST)
        },
    );
    Rerun {
        outcome,
        reads,
        draws,
    }
}

/// The host ID and key of a returned record, with its binding.
fn fields(record: &LocalRecord) -> (Binding, [u8; 16], Key) {
    let Pair { exhid, key } = record.pair();
    (record.binding().clone(), exhid.bytes(), key)
}

// A landed record of the same binding and incarnation comes back whole: its host ID and its stored key, whose
// epoch may differ from the supplied key's in either direction, and the rerun draws no host ID.
#[test]
fn a_rerun_over_a_landed_record_of_the_binding_and_incarnation_returns_it_and_draws_nothing() {
    let mut verdicts = Vec::new();
    for stored_epoch in EPOCHS {
        for supplied_epoch in EPOCHS {
            let stored = key(stored_epoch, INCARNATION);
            let supplied = key(supplied_epoch, INCARNATION);
            let sector = landed_sector(binding(), stored);
            let run = rerun(binding(), supplied, Ok(Some(LocalRecord::decode(&sector))));
            let kept = run.outcome.map(|record| fields(&record));
            verdicts.push((stored_epoch, supplied_epoch, kept, run.reads, run.draws));
        }
    }
    let attachment_key = Key::attachment(Incarnation::new(INCARNATION).expect("in range"));
    assert_eq!(attachment_key, key(EPOCHS[0], INCARNATION));
    for (stored_epoch, supplied_epoch, kept, reads, draws) in verdicts {
        assert_eq!(reads, 1, "the rerun reads the landed record once");
        assert_eq!(
            (kept, draws),
            (
                Ok((binding(), LANDED_HOST, key(stored_epoch, INCARNATION))),
                0
            ),
            "a rerun at E = 0 over a landed record of the same binding and incarnation \
             (stored epoch {stored_epoch}, supplied epoch {supplied_epoch}) keeps the host ID and the \
             stored key an earlier run wrote, and draws nothing"
        );
    }
}

// The same call with nothing landed that the attachment owns: no record, a sector whose crc fails, a sector of
// another length, and a valid record that differs in exactly one binding field. Each gets the supplied key and
// the drawn host ID under the supplied binding, from one draw.
#[test]
fn an_absent_an_undecodable_and_an_elsewhere_bound_record_get_the_supplied_key_and_a_drawn_host_id()
{
    let supplied = key(EPOCHS[1], INCARNATION);
    let mut torn = landed_sector(binding(), supplied);
    torn[100] ^= 0x01;
    let short = landed_sector(binding(), supplied);
    let elsewhere = [
        Binding {
            instance: "i-0fedcba9876543210".into(),
            ..binding()
        },
        Binding {
            volume: "vol-0fedcba9876543210".into(),
            ..binding()
        },
        Binding {
            attachment: "attach-0002".into(),
            ..binding()
        },
    ];
    let mut cases = vec![
        ("no record", None),
        ("a torn sector", Some(LocalRecord::decode(&torn))),
        (
            "a short sector",
            Some(LocalRecord::decode(&short[..RECORD_BYTES - 1])),
        ),
    ];
    for other in elsewhere {
        let sector = landed_sector(other, supplied);
        cases.push((
            "a record bound elsewhere",
            Some(LocalRecord::decode(&sector)),
        ));
    }
    // The premises: the two damaged sectors fail decoding and the three others decode.
    let decoded: Vec<_> = cases
        .iter()
        .map(|(_, existing)| {
            existing
                .as_ref()
                .map(|read| read.as_ref().map(|_| ()).map_err(|e| *e))
        })
        .collect();
    assert_eq!(
        decoded,
        [
            None,
            Some(Err(RecordError::Torn)),
            Some(Err(RecordError::Length)),
            Some(Ok(())),
            Some(Ok(())),
            Some(Ok(())),
        ]
    );
    let verdicts: Vec<_> = cases
        .into_iter()
        .map(|(case, existing)| {
            let run = rerun(binding(), supplied, Ok(existing));
            (
                case,
                run.outcome.map(|record| fields(&record)),
                run.reads,
                run.draws,
            )
        })
        .collect();
    for (case, drawn, reads, draws) in verdicts {
        assert_eq!(
            (drawn, reads, draws),
            (Ok((binding(), RERUN_HOST, supplied)), 1, 1),
            "{case} gets the supplied key and a newly drawn host ID"
        );
    }
}

// A record file that exists and cannot be read refuses with the reader's error, and a landed record of the
// same binding with another key incarnation refuses `Key`, whatever its epoch; neither draws a host ID.
#[test]
fn an_unreadable_record_file_and_another_key_incarnation_refuse_without_a_draw() {
    let supplied = key(EPOCHS[0], INCARNATION);
    let unreadable = rerun(binding(), supplied, Err(AdmissionError::StateDirectory));
    assert_eq!(
        (unreadable.outcome, unreadable.reads, unreadable.draws),
        (Err(AdmissionError::StateDirectory), 1, 0),
        "a record file that cannot be read refuses before a draw"
    );
    for stored_epoch in EPOCHS {
        let sector = landed_sector(binding(), key(stored_epoch, OTHER_INCARNATION));
        let run = rerun(binding(), supplied, Ok(Some(LocalRecord::decode(&sector))));
        assert_eq!(
            (run.outcome, run.reads, run.draws),
            (Err(AdmissionError::Key), 1, 0),
            "a record of the same binding with another key incarnation (stored epoch \
             {stored_epoch}) refuses before a draw"
        );
    }
}
