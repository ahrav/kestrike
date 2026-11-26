//! The checksum is crc32c (Castagnoli): reflected polynomial 0x82F63B78, initial value and final
//! xor 0xFFFFFFFF, check value 0xE3069283 for "123456789". `Crc32c::checksum` is the function that value is
//! stated for, and every mechanism (the portable table, the detected one, and each hardware mechanism the host
//! has) answers through it, so the scenario asks every mechanism the same questions.
//!
//! The reference here is written from those three parameters alone, bit by bit, and shares no code
//! with the tree. Premises, checked before any judgment: the reference itself returns the check value, and
//! the mechanism list holds the table and the detected mechanism.
//!
//! Judgments: for every mechanism, `checksum` over inputs of lengths below and above 8, 176, 256 and 384
//! bytes, at an aligned and an unaligned start, equals the reference; and a `RunningCrc` fed the same bytes,
//! whole or in two pieces, finishes to the same value. `crc32c_tests` holds the check value and the checksum
//! of no bytes for every mechanism.
//!
//! Each test computes its results into plain values first and asserts last, so a failed check ends in the
//! test's own result line.

use super::crc32c::Crc32c;
use super::crc32c_tests::mechanisms;

/// The property's parameters.
const POLYNOMIAL: u32 = 0x82F6_3B78;
const INITIAL: u32 = 0xFFFF_FFFF;
const FINAL_XOR: u32 = 0xFFFF_FFFF;
/// The property's check input and value.
const CHECK_INPUT: &[u8] = b"123456789";
const CHECK_VALUE: u32 = 0xE306_9283;

/// Lengths below, at and above 8, 176, 256 and 384 bytes, and a few far from them.
const LENGTHS: [usize; 18] = [
    0, 1, 7, 8, 9, 175, 176, 177, 255, 256, 257, 383, 384, 385, 1023, 1024, 4096, 4099,
];

/// crc32c of `bytes`, one bit at a time: the register starts at the initial value, each byte enters at the
/// low end, a set low bit shifts out through the reflected polynomial, and the final xor ends it.
fn reference(bytes: &[u8]) -> u32 {
    let mut register = INITIAL;
    for &byte in bytes {
        register ^= u32::from(byte);
        for _ in 0..8 {
            let low = register & 1;
            register >>= 1;
            if low == 1 {
                register ^= POLYNOMIAL;
            }
        }
    }
    register ^ FINAL_XOR
}

/// `len + 1` bytes that repeat with no short period; a test reads `len` of them from offset 0 or 1.
fn input(len: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15u64 ^ len as u64;
    (0..=len)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 56) as u8
        })
        .collect()
}

/// The premises every test here rests on.
fn premises(all: &[(&'static str, Crc32c)]) {
    assert_eq!(
        reference(CHECK_INPUT),
        CHECK_VALUE,
        "premise reference-returns-the-check-value: the bit-by-bit reference is not crc32c"
    );
    assert_eq!(
        reference(b""),
        0,
        "premise reference-returns-the-check-value: the bit-by-bit reference of no bytes is not 0"
    );
    for needed in ["table", "detected"] {
        assert!(
            all.iter().any(|(name, _)| *name == needed),
            "premise mechanisms-listed: the mechanism list lacks `{needed}`"
        );
    }
}

/// A case in which a mechanism's answer differs from the reference.
#[derive(Debug)]
#[allow(dead_code)]
struct Differs {
    mechanism: &'static str,
    len: usize,
    offset: usize,
    /// How the bytes reached the mechanism.
    path: &'static str,
    got: u32,
    reference: u32,
}

/// The first judgment: over every length and both starts, `checksum` equals the bit-by-bit crc32c,
/// and a `RunningCrc` started from the same mechanism and fed the same bytes at once finishes to that value
/// too, so the two agree with each other.
#[test]
fn every_mechanism_matches_the_bit_by_bit_crc32c_at_every_length() {
    let all = mechanisms();
    let mut cases = 0usize;
    let mut differs = Vec::new();
    for len in LENGTHS {
        let bytes = input(len);
        for offset in [0, 1] {
            let bytes = &bytes[offset..offset + len];
            let reference = reference(bytes);
            for &(mechanism, crc) in &all {
                let mut running = crc.start();
                running.update(bytes);
                for (path, got) in [
                    ("checksum", crc.checksum(bytes)),
                    ("running", running.finish()),
                ] {
                    cases += 1;
                    if got != reference {
                        differs.push(Differs {
                            mechanism,
                            len,
                            offset,
                            path,
                            got,
                            reference,
                        });
                    }
                }
            }
        }
    }

    premises(&all);
    assert_eq!(
        cases,
        LENGTHS.len() * 2 * all.len() * 2,
        "every length, start, mechanism and path ran"
    );
    assert!(
        differs.is_empty(),
        "checksum and RunningCrc equal crc32c with polynomial {POLYNOMIAL:#010X}, initial value and final xor \
         0xFFFFFFFF; {} of {cases} cases differ, the first: {:?}",
        differs.len(),
        differs.first()
    );
}

/// The comparison on the path `checksum` does not answer: a `RunningCrc` fed the bytes in two pieces, at
/// every cut of a short input and at cuts around the lengths above, finishes to the bit-by-bit crc32c. It
/// shows the reference, the inputs and the mechanism list hold up where `checksum` is not what answers.
#[test]
fn a_running_crc_fed_in_two_pieces_finishes_to_the_bit_by_bit_crc32c() {
    let all = mechanisms();
    let mut cases = 0usize;
    let mut differs = Vec::new();
    for len in LENGTHS {
        let bytes = input(len);
        let bytes = &bytes[..len];
        let reference = reference(bytes);
        let cuts: Vec<usize> = if len <= 9 {
            (0..=len).collect()
        } else {
            [0, 1, 7, 8, 9, len / 2, len - 9, len - 8, len - 1, len].to_vec()
        };
        for cut in cuts {
            for &(mechanism, crc) in &all {
                let mut running = crc.start();
                running.update(&bytes[..cut]);
                running.update(&bytes[cut..]);
                let got = running.finish();
                cases += 1;
                if got != reference {
                    differs.push(Differs {
                        mechanism,
                        len,
                        offset: cut,
                        path: "running, cut at offset",
                        got,
                        reference,
                    });
                }
            }
        }
    }

    premises(&all);
    assert!(cases > 0, "some case ran");
    assert!(
        differs.is_empty(),
        "a RunningCrc fed in two pieces finishes to crc32c; {} of {cases} cases differ, the first: {:?}",
        differs.len(),
        differs.first()
    );
}
