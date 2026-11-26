//! The attachment key of a new provisioning carries epoch 1.
//!
//! `Key::attachment` is the constructor both provisioning paths of the
//! owner lock call. For each of several incarnations, the two ends of the
//! usable range among them, it must return a key whose epoch is the
//! literal 1 and whose incarnation is the input, which encodes to
//! `(1 << 32) | incarnation` and equals the key `Key::decode` returns for
//! that raw value. Epoch 1 is the first epoch: the raw key one epoch lower
//! refuses with a zero epoch, and every key of epoch 2 orders above the
//! attachment key whatever the two incarnations are. The expected values
//! are written out as integers and never taken from a key that
//! `Key::attachment` built.
//!
//! The control runs the same observation over a key built at epoch 2 and
//! requires it to differ from the expected one in each epoch-bearing part,
//! so the comparison the tests rest on can fail.

use super::identity::{Epoch, Field, IdentityError, Incarnation, Key};

/// The largest usable incarnation.
const FIELD_MAX: u32 = 0xFFFF_FFFE;

/// The sampled incarnations: both ends of the usable range, their neighbors, and values whose high bit
/// would reach the epoch field if the encoding sign-extended or shifted the incarnation.
const INCARNATIONS: [u32; 7] = [1, 2, 7, 0x7FFF_FFFF, 0x8000_0000, FIELD_MAX - 1, FIELD_MAX];

/// What one key shows of itself: its epoch, its incarnation, its encoding, and whether it is the key
/// `expected_raw` decodes to.
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    epoch: u32,
    incarnation: u32,
    encoded: u64,
    is_decode_of_expected: bool,
}

/// The raw device key of a new provisioning with `incarnation`: epoch 1 in bits 63..32.
fn expected_raw(incarnation: u32) -> u64 {
    (1 << 32) | u64::from(incarnation)
}

fn observe(key: Key, incarnation: u32) -> Seen {
    Seen {
        epoch: key.epoch().get(),
        incarnation: key.incarnation().get(),
        encoded: key.encode(),
        is_decode_of_expected: Key::decode(expected_raw(incarnation)) == Ok(key),
    }
}

/// What the property requires of the attachment key of `incarnation`.
fn required(incarnation: u32) -> Seen {
    Seen {
        epoch: 1,
        incarnation,
        encoded: expected_raw(incarnation),
        is_decode_of_expected: true,
    }
}

fn incarnation(value: u32) -> Incarnation {
    Incarnation::new(value).expect("a sampled incarnation is in the usable range")
}

/// The attachment key of every sampled incarnation has epoch 1 and that incarnation, encodes to
/// `(1 << 32) | incarnation`, and is the key that raw value decodes to.
#[test]
fn the_attachment_key_of_a_new_provisioning_has_epoch_one_and_its_incarnation() {
    let seen: Vec<Seen> = INCARNATIONS
        .iter()
        .map(|&value| observe(Key::attachment(incarnation(value)), value))
        .collect();
    let required: Vec<Seen> = INCARNATIONS.iter().map(|&value| required(value)).collect();
    assert_eq!(
        seen, required,
        "a new provisioning's attachment key carries epoch 1 and the assignment's incarnation"
    );
}

/// The attachment key sits in the first epoch. One epoch below its encoding is no key at all, because
/// a zero epoch refuses, and a key of epoch 2 orders above it even when the attachment key holds the
/// largest incarnation and the epoch-2 key the smallest.
#[test]
fn the_attachment_key_is_in_the_first_epoch_and_below_every_key_of_the_second() {
    let second = Epoch::new(2).expect("2 is a usable epoch");
    let lowest_of_second = Key::new(second, incarnation(1));
    let one_epoch_lower: Vec<Result<Key, IdentityError>> = INCARNATIONS
        .iter()
        .map(|&value| Key::decode(Key::attachment(incarnation(value)).encode() - (1 << 32)))
        .collect();
    let below_second: Vec<bool> = INCARNATIONS
        .iter()
        .map(|&value| {
            let key = Key::attachment(incarnation(value));
            key < lowest_of_second && key.encode() < lowest_of_second.encode()
        })
        .collect();
    assert_eq!(
        one_epoch_lower,
        vec![Err(IdentityError::Zero(Field::Epoch)); INCARNATIONS.len()],
        "no usable epoch lies below the attachment key's"
    );
    assert_eq!(
        below_second,
        vec![true; INCARNATIONS.len()],
        "every key of epoch 2 orders above a new provisioning's attachment key"
    );
}

/// The control: a key of the same incarnation built at epoch 2 fails the comparison in its
/// epoch, its encoding and its decode, and keeps the incarnation.
#[test]
fn a_key_built_at_epoch_two_differs_from_the_required_attachment_key() {
    let second = Epoch::new(2).expect("2 is a usable epoch");
    let seen: Vec<Seen> = INCARNATIONS
        .iter()
        .map(|&value| observe(Key::new(second, incarnation(value)), value))
        .collect();
    let at_epoch_two: Vec<Seen> = INCARNATIONS
        .iter()
        .map(|&value| Seen {
            epoch: 2,
            incarnation: value,
            encoded: (2 << 32) | u64::from(value),
            is_decode_of_expected: false,
        })
        .collect();
    assert_eq!(seen, at_epoch_two);
    for (seen, &value) in seen.iter().zip(&INCARNATIONS) {
        assert_ne!(*seen, required(value));
    }
}
