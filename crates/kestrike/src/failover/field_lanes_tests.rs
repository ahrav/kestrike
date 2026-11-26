//! The lane check of a volume field against the grammar read bytewise.
//!
//! The tests restate the volume-name grammar one byte at a time and
//! compare it with `is_volume_field(len, &name)`, the sixteen-lane word
//! check plus the last byte. Each test collects the fields on which the
//! two disagree and asserts that there are none.

use crate::failover::identity::{MAX_VOLUME_LEN, is_volume_field};

const HEX: &[u8; 16] = b"0123456789abcdef";

/// The grammar, one byte at a time: `len` is in 5..=21, the first `len` bytes are `vol-` and then lowercase
/// hexadecimal digits, and every later byte is zero.
fn grammar(len: u8, name: &[u8; MAX_VOLUME_LEN]) -> bool {
    let len = usize::from(len);
    (5..=MAX_VOLUME_LEN).contains(&len)
        && name[..4] == *b"vol-"
        && name[4..len].iter().all(|byte| HEX.contains(byte))
        && name[len..].iter().all(|&byte| byte == 0)
}

/// A valid field of `len` bytes, `len` in 5..=21, whose digits walk the sixteen hexadecimal digits from the
/// digit `first`, so the 17 lengths together place every digit in every lane.
fn valid(len: usize, first: usize) -> [u8; MAX_VOLUME_LEN] {
    let mut name = [0; MAX_VOLUME_LEN];
    name[..4].copy_from_slice(b"vol-");
    for (at, byte) in name[4..len].iter_mut().enumerate() {
        *byte = HEX[(first + at) % 16];
    }
    name
}

/// The shortest name, `vol-` and one digit, and the longest, `vol-` and 17 digits, are admitted with every
/// digit, and each length from 5 to 21 is admitted with zero padding.
#[test]
fn the_shortest_and_longest_names_and_every_length_between_are_admitted() {
    let mut refused = Vec::new();
    for first in 0..16 {
        for len in 5..=MAX_VOLUME_LEN {
            let name = valid(len, first);
            if !grammar(len as u8, &name) || !is_volume_field(len as u8, &name) {
                refused.push((len, name));
            }
        }
    }
    assert!(refused.is_empty(), "valid fields refused: {refused:?}");
}

/// A byte that is no lowercase hexadecimal digit refuses the field wherever it stands among the digits: the
/// neighbors of both digit ranges, an uppercase digit, zero, and a digit with its high bit set.
#[test]
fn a_refused_digit_refuses_at_every_digit_position() {
    let refused_digits = [
        b'0' - 1,
        b'9' + 1,
        b'a' - 1,
        b'f' + 1,
        b'A',
        b'F',
        0,
        0x7F,
        b'0' | 0x80,
        b'a' | 0x80,
        0xFF,
    ];
    let mut admitted = Vec::new();
    for len in 5..=MAX_VOLUME_LEN {
        for at in 4..len {
            for byte in refused_digits {
                let mut name = valid(len, at);
                name[at] = byte;
                if grammar(len as u8, &name) || is_volume_field(len as u8, &name) {
                    admitted.push((len, at, byte));
                }
            }
        }
    }
    assert!(
        admitted.is_empty(),
        "fields with a refused digit admitted, as (len, position, byte): {admitted:?}"
    );
}

/// For a valid name shorter than 21 bytes, each single later byte set to any nonzero value refuses the field:
/// the bytes after the first `len` are padding, and padding is zero.
#[test]
fn a_nonzero_byte_after_the_name_refuses() {
    let mut admitted = Vec::new();
    for len in 5..MAX_VOLUME_LEN {
        for at in len..MAX_VOLUME_LEN {
            for byte in 1..=u8::MAX {
                let mut name = valid(len, len);
                name[at] = byte;
                if grammar(len as u8, &name) || is_volume_field(len as u8, &name) {
                    admitted.push((len, at, byte));
                }
            }
        }
    }
    assert!(
        admitted.is_empty(),
        "fields with nonzero padding admitted, as (len, position, byte): {admitted:?}"
    );
}

/// The check and the bytewise grammar agree on every field one byte away from a valid one, for every byte
/// value at every position of every valid length, the four bytes of `vol-` included.
#[test]
fn every_single_byte_change_agrees_with_the_bytewise_grammar() {
    let mut differing = Vec::new();
    for len in 5..=MAX_VOLUME_LEN {
        for at in 0..MAX_VOLUME_LEN {
            for byte in 0..=u8::MAX {
                let mut name = valid(len, at);
                name[at] = byte;
                let expected = grammar(len as u8, &name);
                if is_volume_field(len as u8, &name) != expected {
                    differing.push((len, at, byte, expected));
                }
            }
        }
    }
    assert!(
        differing.is_empty(),
        "the check differs from the grammar, as (len, position, byte, grammar): {differing:?}"
    );
}

/// The check and the bytewise grammar agree for every value of `len`, 0 to 255, over each valid field and over
/// the all-zero and all-digit fields: a length below 5 or above 21 refuses, and a length other than the name's
/// own refuses because it puts a digit in the padding or a zero among the digits.
#[test]
fn every_length_agrees_with_the_bytewise_grammar() {
    let mut fields: Vec<[u8; MAX_VOLUME_LEN]> =
        (5..=MAX_VOLUME_LEN).map(|len| valid(len, len)).collect();
    fields.push([0; MAX_VOLUME_LEN]);
    fields.push([b'a'; MAX_VOLUME_LEN]);
    let mut differing = Vec::new();
    for name in fields {
        for len in 0..=u8::MAX {
            let expected = grammar(len, &name);
            if is_volume_field(len, &name) != expected {
                differing.push((len, name, expected));
            }
        }
    }
    assert!(
        differing.is_empty(),
        "the check differs from the grammar, as (len, field, grammar): {differing:?}"
    );
}
