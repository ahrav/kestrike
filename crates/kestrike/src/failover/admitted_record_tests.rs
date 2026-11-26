//! `admission::fresh` at attempt 0 and `admission::validate_record`, called with a key of epoch 1 as new
//! provisioning uses. An existing valid record of the same binding and key incarnation whose stored key has
//! another epoch (epoch 6, for example) comes back unchanged, with its stored key and host ID and with no
//! draw. An absent, undecodable or differently bound record yields a new record with the given key from
//! `fresh`, and a record of the same binding with another key incarnation refuses `AdmissionError::Key`
//! before any draw.

use std::cell::Cell;

use super::admission::{self, AdmissionError};
use super::identity::{Epoch, Incarnation, Key};
use super::record::{Binding, LocalRecord, RecordError};

/// The incarnation the assignment gives this attachment.
const INCARNATION: u32 = 2;
/// The host ID every draw of these tests returns.
const DRAWN: [u8; 16] = [5; 16];

/// The binding the assignment names.
fn binding() -> Binding {
    Binding {
        instance: "i-0123456789abcdef0".into(),
        volume: "vol-0123456789abcdef0".into(),
        attachment: "attach-1".into(),
    }
}

fn key(epoch: u32, incarnation: u32) -> Key {
    Key::new(
        Epoch::new(epoch).unwrap(),
        Incarnation::new(incarnation).unwrap(),
    )
}

/// The key new provisioning builds for the assignment's incarnation: epoch 1.
fn provisioned() -> Key {
    let key = Key::attachment(Incarnation::new(INCARNATION).unwrap());
    assert_eq!(
        key.epoch().get(),
        1,
        "premise: new provisioning uses epoch 1"
    );
    key
}

/// A valid record as its sector holds it: drawn once with a host ID of `host` bytes, encoded, and decoded back.
fn stored(binding: Binding, key: Key, host: u8) -> LocalRecord {
    let drawn = LocalRecord::fresh(binding, key, || Some([host; 16])).unwrap();
    LocalRecord::decode(&drawn.encode().unwrap()).unwrap()
}

/// What the fresh path at `E = 0` and a connect make of one existing record under one key.
#[derive(Debug, Clone, PartialEq)]
struct Admitted {
    fresh: Result<LocalRecord, AdmissionError>,
    /// Host IDs the fresh path drew.
    draws: u32,
    connect: Result<LocalRecord, AdmissionError>,
}

fn admitted(existing: Option<Result<LocalRecord, RecordError>>, key: Key) -> Admitted {
    let draws = Cell::new(0);
    let read = existing.clone();
    let fresh = admission::fresh(
        binding(),
        key,
        0,
        || Ok(read),
        || {
            draws.set(draws.get() + 1);
            Some(DRAWN)
        },
    );
    let connect = admission::validate_record(&binding(), key, existing);
    Admitted {
        fresh,
        draws: draws.get(),
        connect,
    }
}

/// LOCAL-RECORD-ONCE: a valid record of the same binding and key incarnation preserves its full key and host ID across an epoch difference. The stored key has epoch 6 and the assignment's key epoch 1; the fresh path at `E = 0` and a connect both return the stored record, epoch 6 and host ID included, and the fresh path draws nothing. A rerun at a stale `E = 0` over the record the first run returned gives the same record again.
#[test]
fn a_record_of_the_same_incarnation_keeps_its_key_and_host_id_across_an_epoch_difference() {
    let record = stored(binding(), key(6, INCARNATION), 9);
    let first = admitted(Some(Ok(record.clone())), provisioned());
    let rerun = first
        .fresh
        .clone()
        .map(|landed| admitted(Some(Ok(landed)), provisioned()));
    let kept = Admitted {
        fresh: Ok(record.clone()),
        draws: 0,
        connect: Ok(record.clone()),
    };
    assert_eq!(
        (record.pair().key.encode(), record.pair().exhid.bytes()),
        ((6u64 << 32) | u64::from(INCARNATION), [9; 16]),
        "premise: the stored record holds epoch 6 and its own host ID"
    );
    assert_eq!(
        first, kept,
        "the stored key of another epoch and its host ID are kept, with no draw"
    );
    assert_eq!(
        rerun,
        Ok(kept),
        "a rerun at a stale E = 0 keeps the same record"
    );
}

/// The control without the epoch difference: the stored key is the assignment's own, and the same calls return the stored record with no draw.
#[test]
fn a_record_of_the_same_key_is_kept() {
    let record = stored(binding(), provisioned(), 9);
    let same = admitted(Some(Ok(record.clone())), provisioned());
    assert_eq!(
        same,
        Admitted {
            fresh: Ok(record.clone()),
            draws: 0,
            connect: Ok(record)
        }
    );
}

/// LOCAL-RECORD-ONCE: an absent, invalid or differently bound record yields a new record. For no record, a sector whose crc fails, and a record of epoch 6 that differs from the binding in one field, the fresh path returns a record of the assignment's binding with the given epoch-1 key and one drawn host ID; a connect refuses `Record`, `RecordCodec` and `Binding` in turn.
#[test]
fn an_absent_invalid_or_differently_bound_record_yields_a_new_record_with_the_given_key() {
    let mut torn = stored(binding(), key(6, INCARNATION), 9).encode().unwrap();
    torn[100] ^= 1;
    let torn = LocalRecord::decode(&torn);
    let mut cases = vec![
        (None, AdmissionError::Record),
        (
            Some(torn.clone()),
            AdmissionError::RecordCodec(RecordError::Torn),
        ),
    ];
    for field in 0..3 {
        let mut other = binding();
        match field {
            0 => other.instance = "i-0fffffffffffffff0".into(),
            1 => other.volume = "vol-0fffffffffffffff0".into(),
            _ => other.attachment = "attach-2".into(),
        }
        cases.push((
            Some(Ok(stored(other, key(6, INCARNATION), 9))),
            AdmissionError::Binding,
        ));
    }
    let new = LocalRecord::fresh(binding(), provisioned(), || Some(DRAWN)).unwrap();
    let outcomes: Vec<Admitted> = cases
        .iter()
        .map(|(existing, _)| admitted(existing.clone(), provisioned()))
        .collect();
    let expected: Vec<Admitted> = cases
        .iter()
        .map(|&(_, refusal)| Admitted {
            fresh: Ok(new.clone()),
            draws: 1,
            connect: Err(refusal),
        })
        .collect();
    assert_eq!(
        torn,
        Err(RecordError::Torn),
        "premise: the damaged sector fails its crc"
    );
    assert_eq!(
        (new.pair().key, new.pair().exhid.bytes(), new.binding()),
        (provisioned(), DRAWN, &binding()),
        "premise: a new record holds the given key, the drawn host ID and the assignment's binding"
    );
    assert_eq!(outcomes, expected);
}

/// LOCAL-RECORD-ONCE: a matching binding with another key incarnation causes refusal before writing. A record of the assignment's binding with incarnation 3, at the assignment's epoch and at epoch 6, refuses `Key` on the fresh path with no draw and on a connect.
#[test]
fn a_record_of_the_same_binding_with_another_incarnation_refuses_before_any_draw() {
    let refused = Admitted {
        fresh: Err(AdmissionError::Key),
        draws: 0,
        connect: Err(AdmissionError::Key),
    };
    let outcomes = [1, 6].map(|epoch| {
        let record = stored(binding(), key(epoch, INCARNATION + 1), 9);
        admitted(Some(Ok(record)), provisioned())
    });
    assert_eq!(outcomes, [refused.clone(), refused]);
}
