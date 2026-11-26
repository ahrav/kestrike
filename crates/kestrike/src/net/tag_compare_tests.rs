//! Callers of the authentication tag comparison, kept in the linked library-test executable for
//! `scripts/scan-tag-compare.py`.
//!
//! [`tag_compare_decision`] realizes the production comparison, [`tags_equal`], in its own extent and decides once,
//! calling [`accepted`] or [`rejected`]. The scan passes [`tag_compare_decision`] when every memory address in its
//! extent stays independent of the tags, every tag-dependent branch and conditional select depends on every byte
//! of both tags, and every path takes exactly one such branch. [`tag_compare_early_return`] compares byte by byte
//! and returns at the first mismatch, the negative control the scan must flag. The tests run both callers on equal tags and
//! on a mismatch at every tag position.

use std::hint::black_box;

use super::auth::{TAG_LEN, tags_equal};

/// The accept arm of a tag decision.
#[inline(never)]
pub(crate) fn accepted() -> bool {
    black_box(true)
}

/// The reject arm of a tag decision.
#[inline(never)]
pub(crate) fn rejected() -> bool {
    black_box(false)
}

/// Decides `tag` against `expected` through the production comparison. The exported C ABI keeps both
/// arguments pointers into the caller's tags, so the scan reads each tag byte from its load.
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn tag_compare_decision(tag: &[u8; TAG_LEN], expected: &[u8; TAG_LEN]) -> bool {
    if tags_equal(*tag, *expected) {
        accepted()
    } else {
        rejected()
    }
}

/// Decides `tag` against `expected` byte by byte, returning at the first mismatch.
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn tag_compare_early_return(tag: &[u8; TAG_LEN], expected: &[u8; TAG_LEN]) -> bool {
    for at in 0..TAG_LEN {
        if black_box(tag[at]) != expected[at] {
            return rejected();
        }
    }
    accepted()
}

/// Both callers accept equal tags and reject a mismatch at every tag position.
#[test]
fn the_tag_callers_decide_equal_tags_and_every_mismatch_position() {
    let expected: [u8; TAG_LEN] = std::array::from_fn(|at| (at as u8).wrapping_mul(37) ^ 0x5a);
    for decide in [tag_compare_decision, tag_compare_early_return] {
        assert!(decide(black_box(&expected), black_box(&expected)));
        for at in 0..TAG_LEN {
            for flip in [0x01, 0x80, 0xff] {
                let mut tag = expected;
                tag[at] ^= flip;
                assert!(
                    !decide(black_box(&tag), black_box(&expected)),
                    "mismatch at {at} by {flip:#04x}"
                );
            }
        }
    }
}
