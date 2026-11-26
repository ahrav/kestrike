//! The packing and the order of a reservation key.
//!
//! A reservation key packs its epoch into bits 63..32 and its incarnation
//! into bits 31..0. Every usable pair of fields encodes to that packing
//! and decodes back to the same key; keys compare as their encoded values
//! do, the epoch first; and a zero or `0xFFFF_FFFF` field refuses with the
//! error that names it, the epoch before the incarnation.
//!
//! The expected packing and the expected order are computed here from the
//! raw field values, not read back from `Key`, so the tests hold `Key` to
//! the layout its documentation states.

use std::cmp::Ordering;

use super::identity::{Epoch, Field, IdentityError, Incarnation, Key};

/// Usable field values: both ends of `1..=0xFFFF_FFFE`, their neighbours and
/// the two values around the sign bit of a 32-bit field.
const USABLE: [u32; 6] = [1, 2, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFD, 0xFFFF_FFFE];

/// The device key of `epoch` and `incarnation` as the layout states it.
fn packed(epoch: u32, incarnation: u32) -> u64 {
    u64::from(epoch) * (1 << 32) + u64::from(incarnation)
}

/// The key of two usable field values, or the refusal of the first field
/// that is not usable.
fn key(epoch: u32, incarnation: u32) -> Result<Key, IdentityError> {
    Ok(Key::new(Epoch::new(epoch)?, Incarnation::new(incarnation)?))
}

/// Every pair of usable field values with the key built from it.
fn usable_keys() -> Vec<((u32, u32), Key)> {
    USABLE
        .iter()
        .flat_map(|&epoch| USABLE.iter().map(move |&incarnation| (epoch, incarnation)))
        .map(|fields| {
            let built = key(fields.0, fields.1).expect("both fields are usable");
            (fields, built)
        })
        .collect()
}

/// Each usable pair encodes to the packed value, decodes from it to an equal
/// key, and reads back its two fields; an attachment key carries epoch 1.
#[test]
fn usable_fields_round_trip_through_the_packed_key() {
    for ((epoch, incarnation), built) in usable_keys() {
        let raw = packed(epoch, incarnation);
        assert_eq!(
            built.encode(),
            raw,
            "encode of ({epoch:#x}, {incarnation:#x})"
        );
        assert_eq!(Key::decode(raw), Ok(built), "decode of {raw:#x}");
        assert_eq!(
            (built.epoch().get(), built.incarnation().get()),
            (epoch, incarnation),
            "fields of {raw:#x}"
        );
    }
    for incarnation in USABLE {
        let attached = Key::attachment(Incarnation::new(incarnation).expect("usable"));
        assert_eq!(attached.encode(), packed(1, incarnation));
        assert_eq!(Key::decode(packed(1, incarnation)), Ok(attached));
    }
}

/// Keys order by epoch first and then by incarnation, which is the order of
/// their encoded values. The first assertions fix the case the two fields
/// disagree on: a later epoch with a lower incarnation orders above an earlier
/// epoch with a higher one. The loop then holds every pair of the usable grid
/// to the order of its packed values, through `cmp`, `partial_cmp` and the
/// comparison operators, and a sort of the keys to the sort of those values.
#[test]
fn keys_order_by_epoch_first_as_their_encoded_values_do() {
    let later_epoch = key(2, 1).expect("usable");
    let earlier_epoch = key(1, 0xFFFF_FFFE).expect("usable");
    assert!(later_epoch.encode() > earlier_epoch.encode());
    assert_eq!(
        later_epoch.cmp(&earlier_epoch),
        Ordering::Greater,
        "epoch 2 with incarnation 1 orders above epoch 1 with incarnation 0xFFFF_FFFE"
    );
    assert!(earlier_epoch < later_epoch);
    assert_eq!(later_epoch.max(earlier_epoch), later_epoch);

    let keys = usable_keys();
    for &((epoch, incarnation), left) in &keys {
        for &((other_epoch, other_incarnation), right) in &keys {
            let by_fields = (epoch, incarnation).cmp(&(other_epoch, other_incarnation));
            let by_value = packed(epoch, incarnation).cmp(&packed(other_epoch, other_incarnation));
            assert_eq!(by_fields, by_value, "the packing keeps the field order");
            let context = format!(
                "({epoch:#x}, {incarnation:#x}) against ({other_epoch:#x}, {other_incarnation:#x})"
            );
            assert_eq!(left.cmp(&right), by_value, "cmp of {context}");
            assert_eq!(
                left.partial_cmp(&right),
                Some(by_value),
                "partial_cmp of {context}"
            );
            assert_eq!(left < right, by_value == Ordering::Less, "< of {context}");
            assert_eq!(
                left == right,
                by_value == Ordering::Equal,
                "== of {context}"
            );
            assert_eq!(
                left.encode().cmp(&right.encode()),
                by_value,
                "encoded {context}"
            );
        }
    }

    let mut sorted: Vec<Key> = keys.iter().rev().map(|&(_, built)| built).collect();
    sorted.sort();
    let sorted: Vec<u64> = sorted.into_iter().map(Key::encode).collect();
    let mut values: Vec<u64> = keys
        .iter()
        .map(|&((epoch, incarnation), _)| packed(epoch, incarnation))
        .collect();
    values.sort_unstable();
    assert_eq!(
        sorted, values,
        "sorted keys encode to the sorted packed values"
    );
}

/// A zero field refuses `Zero` and a `0xFFFF_FFFF` field refuses `Reserved`,
/// each naming its field, at the field's constructor and at `Key::decode`.
/// When both fields of a device key are unusable the refusal names the
/// epoch, whichever way the two fields fail.
#[test]
fn zero_and_reserved_fields_refuse_by_name_the_epoch_first() {
    let refusals = [
        (
            0,
            IdentityError::Zero(Field::Epoch),
            IdentityError::Zero(Field::Incarnation),
        ),
        (
            0xFFFF_FFFF,
            IdentityError::Reserved(Field::Epoch),
            IdentityError::Reserved(Field::Incarnation),
        ),
    ];
    for (value, as_epoch, as_incarnation) in refusals {
        assert_eq!(Epoch::new(value).map(Epoch::get), Err(as_epoch));
        assert_eq!(
            Incarnation::new(value).map(Incarnation::get),
            Err(as_incarnation)
        );
        for usable in USABLE {
            assert_eq!(
                Key::decode(packed(value, usable)),
                Err(as_epoch),
                "epoch {value:#x} beside usable incarnation {usable:#x}"
            );
            assert_eq!(
                Key::decode(packed(usable, value)),
                Err(as_incarnation),
                "incarnation {value:#x} beside usable epoch {usable:#x}"
            );
        }
        for (other, _, _) in refusals {
            assert_eq!(
                Key::decode(packed(value, other)),
                Err(as_epoch),
                "epoch {value:#x} beside unusable incarnation {other:#x}"
            );
        }
    }
}
