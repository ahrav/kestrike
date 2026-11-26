//! The root codec against golden blocks built at hand-computed offsets, the decode order WHOLE-OR-ABSENT fixes, and the bootstrap decision over every pair of slot probes.

use super::super::record::Crc32c;
use super::MetadataOutcome;
use super::block::{FormatId, Layout, Undecodable};
use super::layout::Slot;
use super::root::{Decision, Probed, Root, decide, decode, encode};

const LAYOUT: Layout = Layout {
    unit: 4096,
    metadata_units: 2,
};
const FORMAT: FormatId = FormatId([
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
]);

/// Slot A's golden root: generation 7, root sequence 3, content incarnation 5 and the empty range `[9, 9)`, the crc32c computed outside this crate.
const EMPTY: &[u8] = include_bytes!("../../sim/fixtures/root-empty-range.block");
/// Slot B's golden root: the same fields with the one-block range `[9, 10)`.
const ONE: &[u8] = include_bytes!("../../sim/fixtures/root-one-block-range.block");

/// The tenure session every decision below writes under: `g = 1`, `a = 2`.
fn session() -> super::Session {
    super::session_at(1, 0)
}

fn golden(journal: std::ops::Range<u64>) -> Root {
    Root {
        generation: 7,
        history: 7,
        sequence: 3,
        incarnation: 5,
        journal,
        clock: crate::storage::TEST_CLOCK.encode(),
        feed: crate::storage::TEST_FEED.encode(),
    }
}

fn block(format: FormatId, root: &Root, slot: Slot) -> Vec<u8> {
    let mut bytes = vec![0xA5; 4096];
    encode(Crc32c::detect(), LAYOUT, format, root, slot, &mut bytes);
    bytes
}

/// A golden root decodes to exactly the range it holds, empty only when `S == D`, and the encoder writes the same bytes.
#[test]
fn golden_roots_decode_to_their_written_ranges_and_the_encoder_reproduces_them() {
    let crc = Crc32c::detect();
    let (format, empty) = decode(crc, LAYOUT, EMPTY, Slot::A).expect("the golden root decodes");
    assert_eq!((format, &empty), (FORMAT, &golden(9..9)));
    assert!(empty.journal.is_empty());
    let (_, one) = decode(crc, LAYOUT, ONE, Slot::B).expect("the golden root decodes");
    assert_eq!(one, golden(9..10));
    assert_eq!((one.journal.start, one.journal.end), (9, 10));
    assert_eq!(block(FORMAT, &golden(9..9), Slot::A), EMPTY);
    assert_eq!(block(FORMAT, &golden(9..10), Slot::B), ONE);
    // Each golden root names its own slot.
    assert_eq!(
        decode(crc, LAYOUT, EMPTY, Slot::B),
        Err(Undecodable::Invalid)
    );
    assert_eq!(decode(crc, LAYOUT, ONE, Slot::A), Err(Undecodable::Invalid));
}

#[test]
fn a_reset_root_carries_its_generation_as_incarnation_and_the_empty_range() {
    let root = Root::reset(
        9,
        crate::storage::TEST_CLOCK.encode(),
        crate::storage::TEST_FEED.encode(),
    );
    assert_eq!(
        (
            root.generation,
            root.sequence,
            root.incarnation,
            root.journal.clone()
        ),
        (9, 0, 9, 0..0)
    );
    let bytes = block(FORMAT, &root, Slot::B);
    assert_eq!(
        decode(Crc32c::detect(), LAYOUT, &bytes, Slot::B),
        Ok((FORMAT, root))
    );
}

/// Decode checks magic, version, recorded layout, crc, role, format ID, generation and self-index in that order: a version change wins over a crc it moved, and a layout change over a crc it broke.
#[test]
fn decode_checks_each_header_field_in_the_whole_or_absent_order() {
    let crc = Crc32c::detect();
    let valid = EMPTY.to_vec();
    let with = |at: usize, byte: u8| {
        let mut bytes = valid.clone();
        bytes[at] = byte;
        bytes
    };
    assert_eq!(
        decode(crc, LAYOUT, &with(0, b'X'), Slot::A),
        Err(Undecodable::Invalid)
    );
    // Another version may move the crc, so its block is unsupported whatever its crc says.
    assert_eq!(
        decode(crc, LAYOUT, &with(8, 0x04), Slot::A),
        Err(Undecodable::Unsupported { version: 0x8004 })
    );
    assert_eq!(
        decode(crc, LAYOUT, &with(8, 0x02), Slot::A),
        Err(Undecodable::Unsupported { version: 0x8002 })
    );
    assert_eq!(
        decode(crc, LAYOUT, &with(16, 3), Slot::A),
        Err(Undecodable::ForeignLayout)
    );
    assert_eq!(
        decode(crc, LAYOUT, &with(13, 0x20), Slot::A),
        Err(Undecodable::ForeignLayout)
    );
    assert_eq!(
        decode(crc, LAYOUT, &with(200, 1), Slot::A),
        Err(Undecodable::Invalid)
    );
    assert_eq!(
        decode(crc, LAYOUT, &valid[..2048], Slot::A),
        Err(Undecodable::Invalid)
    );
    // Fields past the crc refuse only as sealed blocks, each with a fresh crc.
    let zero_format = block(FormatId([0; 16]), &golden(9..9), Slot::A);
    assert_eq!(
        decode(crc, LAYOUT, &zero_format, Slot::A),
        Err(Undecodable::Invalid)
    );
    let zero_generation = block(
        FORMAT,
        &Root {
            generation: 0,
            history: 0,
            ..golden(9..9)
        },
        Slot::A,
    );
    assert_eq!(
        decode(crc, LAYOUT, &zero_generation, Slot::A),
        Err(Undecodable::Invalid)
    );
}

/// Reseals `bytes` with its crc32c, so a test changes one field and isolates its check from the crc's.
fn reseal(bytes: &mut [u8]) {
    let crc = Crc32c::detect();
    let mut running = crc.start();
    running.update(&bytes[..64]);
    running.update(&[0; 4]);
    running.update(&bytes[68..]);
    let sum = running.finish();
    bytes[64..68].copy_from_slice(&sum.to_le_bytes());
}

/// A sealed block whose role byte differs from the root's decodes invalid, so the role check holds apart from the crc.
#[test]
fn a_sealed_block_of_another_role_is_invalid() {
    for role in [2u8, 3, 4] {
        let mut bytes = EMPTY.to_vec();
        bytes[10] = role;
        reseal(&mut bytes);
        assert_eq!(
            decode(Crc32c::detect(), LAYOUT, &bytes, Slot::A),
            Err(Undecodable::Invalid),
            "{role:?}"
        );
    }
}

/// A root whose range start passes its end is refused, after its crc verified.
#[test]
fn a_root_whose_range_runs_backwards_is_invalid() {
    let crc = Crc32c::detect();
    let mut bytes = block(FORMAT, &golden(10..10), Slot::A);
    bytes[88..96].copy_from_slice(&9u64.to_le_bytes());
    let mut running = crc.start();
    running.update(&bytes[..64]);
    running.update(&[0; 4]);
    running.update(&bytes[68..]);
    let sum = running.finish();
    bytes[64..68].copy_from_slice(&sum.to_le_bytes());
    assert_eq!(
        decode(crc, LAYOUT, &bytes, Slot::A),
        Err(Undecodable::Invalid)
    );
}

/// Changing bytes between the feed contract's end at byte 140 and the history trailer and resealing preserves the decoded root. At equal ordinals, matching decoded fields produce RESET; differing decoded fields produce `Decision::Refused(TiedRoots)`.
#[test]
fn bytes_past_the_feed_contract_leave_the_decoded_root_and_the_tie_rule_unchanged() {
    use MetadataOutcome::TiedRoots;
    let crc = Crc32c::detect();
    let mut tailed = EMPTY.to_vec();
    let trailer = tailed.len() - 8;
    tailed[140..trailer].fill(0x5A);
    reseal(&mut tailed);
    let decoded = decode(crc, LAYOUT, &tailed, Slot::A).expect("the resealed root decodes");
    assert_eq!(decoded, (FORMAT, golden(9..9)));
    let twin = decode(crc, LAYOUT, &block(FORMAT, &golden(9..9), Slot::B), Slot::B)
        .expect("the encoded root decodes");
    assert_eq!(
        decide(&Some(Ok(decoded.clone())), &Some(Ok(twin)), &session()),
        reset(session().get(), Slot::A)
    );
    let other = decode(crc, LAYOUT, ONE, Slot::B).expect("the golden root decodes");
    assert_eq!(
        decide(&Some(Ok(decoded)), &Some(Ok(other)), &session()),
        Decision::Refused(TiedRoots)
    );
}

fn valid(generation: u64, sequence: u64, incarnation: u64) -> Probed {
    Some(Ok((
        FORMAT,
        Root {
            generation,
            history: generation,
            sequence,
            incarnation,
            journal: 0..0,
            clock: crate::storage::TEST_CLOCK.encode(),
            feed: crate::storage::TEST_FEED.encode(),
        },
    )))
}

const INVALID: Probed = Some(Err(Undecodable::Invalid));
const FOREIGN: Probed = Some(Err(Undecodable::ForeignLayout));

fn unsupported(version: u16) -> Probed {
    Some(Err(Undecodable::Unsupported { version }))
}

fn reset(session: u64, first: Slot) -> Decision {
    Decision::Reset {
        format: FORMAT,
        session,
        first,
    }
}

/// Every pair of probes decides one bootstrap: the refusals in their order, an unformatted pair, and the RESET's first slot under the tenure's session; a valid root at or above the session refuses.
#[test]
fn the_bootstrap_decision_follows_the_probes_of_both_slots() {
    use MetadataOutcome::*;
    let other: Probed = Some(Ok((
        FormatId([9; 16]),
        Root::reset(
            3,
            crate::storage::TEST_CLOCK.encode(),
            crate::storage::TEST_FEED.encode(),
        ),
    )));
    let rows = [
        (INVALID, INVALID, Decision::Unformatted),
        (valid(4, 0, 4), INVALID, reset(session().get(), Slot::B)),
        (INVALID, valid(4, 0, 4), reset(session().get(), Slot::A)),
        (
            valid(5, 0, 5),
            valid(4, 0, 4),
            reset(session().get(), Slot::B),
        ),
        (
            valid(4, 0, 4),
            valid(5, 0, 5),
            reset(session().get(), Slot::A),
        ),
        (
            valid(5, 1, 5),
            valid(5, 0, 5),
            reset(session().get(), Slot::B),
        ),
        (
            valid(5, 0, 5),
            valid(5, 0, 5),
            reset(session().get(), Slot::A),
        ),
        (valid(5, 0, 5), valid(5, 0, 6), Decision::Refused(TiedRoots)),
        (
            valid(5, 0, 5),
            other.clone(),
            Decision::Refused(FormatMismatch),
        ),
        (FOREIGN, INVALID, Decision::Refused(FormatMismatch)),
        (INVALID, FOREIGN, Decision::Refused(FormatMismatch)),
        (
            unsupported(2),
            valid(5, 0, 5),
            Decision::Refused(Unsupported {
                slot: Slot::A,
                version: 2,
            }),
        ),
        (
            valid(5, 0, 5),
            unsupported(3),
            Decision::Refused(Unsupported {
                slot: Slot::B,
                version: 3,
            }),
        ),
        (
            valid(5, 0, 5),
            None,
            Decision::Refused(SlotUnreadable { slot: Slot::B }),
        ),
        (
            None,
            None,
            Decision::Refused(SlotUnreadable { slot: Slot::A }),
        ),
        (
            unsupported(2),
            None,
            Decision::Refused(SlotUnreadable { slot: Slot::B }),
        ),
        (
            valid(u64::MAX, 0, 1),
            valid(4, 0, 4),
            Decision::Refused(StaleSession),
        ),
        (
            valid(session().get(), 0, 1),
            INVALID,
            Decision::Refused(StaleSession),
        ),
        (
            INVALID,
            valid(session().get() - 1, 0, 1),
            reset(session().get(), Slot::A),
        ),
    ];
    for (a, b, decision) in rows {
        assert_eq!(decide(&a, &b, &session()), decision, "{a:?} {b:?}");
    }
}

/// A continuation root keeps its older history generation through the block's last eight bytes, an equal one writes zero there, and a nonzero history at or above the generation, or beside a nonzero sequence, is refused.
#[test]
fn a_continuation_root_carries_its_history_in_the_block_trailer() {
    let crc = Crc32c::detect();
    let continuation = Root {
        history: 6,
        sequence: 0,
        ..golden(9..10)
    };
    let bytes = block(FORMAT, &continuation, Slot::A);
    assert_eq!(bytes[4088..], 6u64.to_le_bytes());
    assert_eq!(
        decode(crc, LAYOUT, &bytes, Slot::A),
        Ok((FORMAT, continuation))
    );
    assert_eq!(block(FORMAT, &golden(9..10), Slot::A)[4088..], [0; 8]);
    let sequenced = Root {
        history: 6,
        ..golden(9..10)
    };
    assert_eq!(
        decode(crc, LAYOUT, &block(FORMAT, &sequenced, Slot::A), Slot::A),
        Err(Undecodable::Invalid),
        "a continuation root carries sequence zero"
    );
    for history in [7, 8] {
        let issuance = Root {
            sequence: 0,
            ..golden(9..10)
        };
        let mut bytes = block(FORMAT, &issuance, Slot::A);
        bytes[4088..].copy_from_slice(&u64::to_le_bytes(history));
        reseal(&mut bytes);
        assert_eq!(
            decode(crc, LAYOUT, &bytes, Slot::A),
            Err(Undecodable::Invalid),
            "{history}"
        );
    }
}

#[test]
fn a_root_whose_incarnation_passes_its_history_is_invalid() {
    let crc = Crc32c::detect();
    for (history, incarnation) in [(7, 8), (6, 7)] {
        let root = Root {
            history,
            sequence: 0,
            incarnation,
            ..golden(9..10)
        };
        assert_eq!(
            decode(crc, LAYOUT, &block(FORMAT, &root, Slot::A), Slot::A),
            Err(Undecodable::Invalid),
            "history {history}, incarnation {incarnation}"
        );
    }
    let root = Root {
        history: 6,
        sequence: 0,
        incarnation: 6,
        ..golden(9..10)
    };
    assert_eq!(
        decode(crc, LAYOUT, &block(FORMAT, &root, Slot::A), Slot::A),
        Ok((FORMAT, root))
    );
}

/// One nonzero byte at each sampled offset between the head's end at byte 144 and the trailer fails the crc, and the same block under a fresh crc decodes to the root it held, so every byte the decoder leaves unfolded is zero.
#[test]
fn a_nonzero_byte_past_the_head_fails_the_crc_and_decodes_once_resealed() {
    let crc = Crc32c::detect();
    // The head's end, both sides of the first and of a middle 128-byte chunk boundary, the last whole chunk's end, and the bytes between it and the trailer.
    for at in [144, 271, 272, 2063, 2064, 3983, 3984, 4087] {
        let mut bytes = EMPTY.to_vec();
        bytes[at] = 1;
        assert_eq!(
            decode(crc, LAYOUT, &bytes, Slot::A),
            Err(Undecodable::Invalid),
            "{at}"
        );
        reseal(&mut bytes);
        assert_eq!(
            decode(crc, LAYOUT, &bytes, Slot::A),
            Ok((FORMAT, golden(9..9))),
            "{at}"
        );
    }
}

/// A root of a longer block, and of one whose bytes after the head end in a partial word, encoded into a buffer of stale bytes, carries the crc32c of its whole block, decodes to itself, and fails the crc on a nonzero byte just before its trailer.
#[test]
fn roots_of_other_block_lengths_seal_and_decode_over_their_whole_block() {
    let crc = Crc32c::detect();
    for unit in [8192, 4608, 4099] {
        let layout = Layout {
            unit,
            metadata_units: 2,
        };
        let mut bytes = vec![0xA5; unit as usize];
        encode(crc, layout, FORMAT, &golden(9..10), Slot::B, &mut bytes);
        let sealed = bytes.clone();
        reseal(&mut bytes);
        assert_eq!(bytes, sealed, "{unit}");
        assert_eq!(
            decode(crc, layout, &bytes, Slot::B),
            Ok((FORMAT, golden(9..10))),
            "{unit}"
        );
        bytes[unit as usize - 9] = 1;
        assert_eq!(
            decode(crc, layout, &bytes, Slot::B),
            Err(Undecodable::Invalid),
            "{unit}"
        );
    }
}
