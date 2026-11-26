//! The delta block codec: records round-trip through packed blocks whatever the split, a damaged, truncated or
//! foreign block decodes as a hole, and the region arithmetic places LSNs after the slots.

use super::capture::CaptureEntry;
use super::capture_tests::entry;
use super::delta::*;
use crate::failover::records::Layout;
use crate::net::ownership::Shard;
use crate::storage::extent::ExtentLocator;
use crate::storage::record::{Crc32c, HeaderMismatch};
use crate::storage::seeded::SplitMix64;

pub(crate) const SESSION: u64 = (3 << 32) | 4;

pub(crate) fn shard() -> Shard {
    Shard::new(7).unwrap()
}

pub(crate) fn block(lsn: u64) -> Block {
    Block {
        shard: shard(),
        session: SESSION,
        lsn,
    }
}

pub(crate) fn wide(slot: usize, start: u64, extents: usize) -> CaptureEntry {
    let mut entry = entry(slot, 2, start);
    entry.session = SESSION;
    entry.extents = (0..extents as u64)
        .map(|at| ExtentLocator::new(start + at, 1).unwrap().bits())
        .collect();
    entry
}

pub(crate) fn remove(entry: &CaptureEntry, cause: Cause) -> Record {
    Record::Remove {
        identity: identity_of(entry),
        cause,
    }
}

/// Feeds `part` and decodes the record it completes, as replay does.
pub(crate) fn fed(assembler: &mut Assembler, part: Part) -> Result<Option<Record>, BlockHole> {
    let Some(body) = assembler.feed(part)? else {
        return Ok(None);
    };
    Record::decode(part.0.kind, &body)
        .map(Some)
        .ok_or(BlockHole::Content)
}

/// Pushes a record of kind byte `kind` whose body is `body`.
pub(crate) fn push(packer: &mut Packer, seq: u64, (kind, body): (u8, &[u8])) {
    packer.push(seq, (kind, body.len()), |out| out.extend_from_slice(body));
}

pub(crate) fn packed(first: u64, records: &[Record]) -> Vec<Box<[u8; UNIT_LEN]>> {
    packed_as(block(first), records)
}

/// `records` packed into the blocks of `first`'s shard and session from `first`'s LSN on.
pub(crate) fn packed_as(first: Block, records: &[Record]) -> Vec<Box<[u8; UNIT_LEN]>> {
    packed_at(first, (0..).zip(records))
}

/// `packed_at` packs each record with its supplied sequence number. Output blocks use `first.shard` and
/// `first.session` and have consecutive LSNs starting at `first.lsn`.
pub(crate) fn packed_at<'a>(
    first: Block,
    records: impl IntoIterator<Item = (u64, &'a Record)>,
) -> Vec<Box<[u8; UNIT_LEN]>> {
    let crc = Crc32c::detect();
    let mut packer = Packer::default();
    for (seq, record) in records {
        let (kind, body) = record.body().unwrap();
        push(&mut packer, seq, (kind, &body));
    }
    packer.seal();
    let mut units = Vec::new();
    while let Some(payload) = packer.sealed.pop_front() {
        let lsn = first.lsn + units.len() as u64;
        units.push(seal(crc, Block { lsn, ..first }, &payload));
    }
    units
}

pub(crate) fn unpacked(first: u64, units: &[Box<[u8; UNIT_LEN]>]) -> Vec<(u64, Record)> {
    let crc = Crc32c::detect();
    let mut assembler = Assembler::default();
    let mut records = Vec::new();
    for (at, unit) in units.iter().enumerate() {
        let decoded = decode(
            crc,
            block(first + at as u64),
            SESSION,
            &unit[..],
            Vec::new(),
        )
        .unwrap();
        assembler.admit(&decoded).unwrap();
        for part in decoded {
            if let Some(record) = fed(&mut assembler, part).unwrap() {
                records.push((records.len() as u64, record));
            }
        }
    }
    records
}

fn random_record(rng: &mut SplitMix64, at: usize) -> Record {
    let extents = 1 + rng.below(4) as usize * rng.below(700) as usize;
    let entry = wide(at, 8 * at as u64, extents);
    match rng.below(3) {
        0 => Record::Insert(entry),
        1 => remove(&entry, Cause::Invalidate),
        _ => Record::Replace {
            old: identity_of(&entry),
            cause: Cause::Evict,
            new: wide(at + 1, 8 * at as u64 + 4, 1 + rng.below(3) as usize),
        },
    }
}

#[test]
fn records_round_trip_through_packed_blocks_in_any_split() {
    let mut rng = SplitMix64::new(0x1444);
    for round in 0..40 {
        let count = 1 + rng.below(12) as usize;
        let records: Vec<Record> = (0..count).map(|at| random_record(&mut rng, at)).collect();
        let units = packed(round, &records);
        let decoded = unpacked(round, &units);
        let expected: Vec<(u64, Record)> = records
            .iter()
            .cloned()
            .enumerate()
            .map(|(seq, record)| (seq as u64, record))
            .collect();
        assert_eq!(decoded, expected, "round {round}: {} units", units.len());
        let bodies: usize = records.iter().map(|r| r.body().unwrap().1.len()).sum();
        assert!(
            units.len() >= bodies.div_ceil(room()),
            "round {round}: the parts fill the blocks"
        );
    }
    let mut timed = wide(3, 40, 2);
    (timed.deadline_ns, timed.lifetime_ms, timed.tail) = (0x0102_0304_0506_0708, 0x0A0B_0C0D, 4095);
    let records = [
        Record::Insert(timed.clone()),
        remove(&timed, Cause::Expire),
        Record::Replace {
            old: identity_of(&timed),
            cause: Cause::Expire,
            new: timed,
        },
    ];
    let decoded = unpacked(0, &packed(0, &records));
    assert_eq!(decoded.len(), records.len());
    for ((_, decoded), record) in decoded.iter().zip(&records) {
        assert_eq!(decoded, record);
    }
}

/// The packer's payload room is the payload of the block's record layout, so a sealed payload and its header fill
/// one unit exactly.
#[test]
fn a_payload_and_its_header_fill_one_unit() {
    let (_, layout) = super::checkpoint::layout();
    assert_eq!(layout.body_len() as usize, room());
    assert_eq!(layout.header_bytes() + room(), UNIT_LEN);
    assert_eq!(layout.chunk_count(), 1);
}

#[test]
fn a_record_wider_than_a_block_spans_consecutive_blocks_and_its_placement_names_its_last_block() {
    let widest = Record::Replace {
        old: identity_of(&wide(0, 0, 1)),
        cause: Cause::Evict,
        new: wide(1, 100, 2115),
    };
    assert_eq!(widest.body().unwrap().1.len(), 57 + 72 + 8 * 2115);
    assert_eq!(
        unpacked(0, &packed(0, std::slice::from_ref(&widest))),
        vec![(0, widest)]
    );
    let record = Record::Insert(wide(1, 100, 2115));
    let (kind, body) = record.body().unwrap();
    assert!(
        body.len() > 4 * room(),
        "the widest entry spans many blocks"
    );
    let mut packer = Packer::default();
    let short = Record::Insert(wide(0, 0, 1));
    let (short_kind, short_body) = short.body().unwrap();
    assert_eq!(Packer::plan(0, short_body.len()), Some((0, 1)));
    push(&mut packer, 0, (short_kind, &short_body));
    let placed = Packer::plan(packer.open.len(), body.len()).unwrap();
    assert!(placed.0 >= 4 && placed.1 >= 5);
    push(&mut packer, 1, (kind, &body));
    packer.seal();
    let mut units = Vec::new();
    while let Some(payload) = packer.sealed.pop_front() {
        units.push(seal(Crc32c::detect(), block(units.len() as u64), &payload));
    }
    assert_eq!(units.len(), placed.0 + 1);
    let decoded = unpacked(0, &units);
    assert_eq!(decoded, vec![(0, short), (1, record)]);
}

#[test]
fn an_entry_with_no_extent_or_too_many_has_no_body() {
    let mut none = wide(0, 0, 1);
    none.extents.clear();
    assert_eq!(Record::Insert(none).body(), None);
    let many = wide(0, 0, usize::from(u16::MAX) + 1);
    assert_eq!(Record::Insert(many).body(), None);
    let past_limit = wide(0, 0, 2116);
    let mut whole_unit_tail = wide(0, 0, 1);
    whole_unit_tail.tail = 4096;
    let mut long = wide(0, 0, 1);
    long.extents[0] = ExtentLocator::new(0, 65).unwrap().bits();
    for entry in [past_limit, whole_unit_tail, long] {
        assert_eq!(Record::Insert(entry).body(), None);
    }
}

#[test]
fn the_overlap_check_ignores_what_its_buffer_held_and_leaves_it_empty() {
    let mut descending = wide(0, 8, 3);
    descending.extents.reverse();
    let mut overlapping = descending.clone();
    overlapping.extents[2] = overlapping.extents[0];
    // Two equal words read as overlapping spans, so a check that kept them would refuse the disjoint entry.
    let mut sorted = vec![u64::MAX; 2];
    let capacity = sorted.capacity();
    assert!(shaped_in(&descending, &mut sorted));
    assert!(sorted.is_empty());
    assert!(!shaped_in(&overlapping, &mut sorted));
    assert!(sorted.is_empty());
    assert!(sorted.capacity() >= capacity);
}

#[test]
fn a_block_of_another_lsn_session_or_shard_fails_identity_before_its_payload() {
    let crc = Crc32c::detect();
    let units = packed(5, &[Record::Insert(wide(0, 0, 1))]);
    let header = |block| match decode(crc, block, SESSION, &units[0][..], Vec::new()) {
        Err(BlockHole::Header(mismatch)) => mismatch,
        other => panic!("identity must fail first: {other:?}"),
    };
    assert!(matches!(
        header(block(5 + 3)),
        HeaderMismatch::Allocation {
            expected: 8,
            found: 5
        }
    ));
    assert!(matches!(
        header(Block {
            session: SESSION + 2,
            ..block(5)
        }),
        HeaderMismatch::Session { .. }
    ));
    assert!(matches!(
        header(Block {
            shard: Shard::new(8).unwrap(),
            ..block(5)
        }),
        HeaderMismatch::Key
    ));
    assert!(decode(crc, block(5), SESSION, &units[0][..], Vec::new()).is_ok());
}

#[test]
fn a_flipped_or_truncated_block_is_a_hole_and_never_another_decode() {
    let crc = Crc32c::detect();
    let records = [
        Record::Insert(wide(0, 0, 3)),
        remove(&wide(1, 8, 1), Cause::Expire),
    ];
    let units = packed(9, &records);
    let good = decode(crc, block(9), SESSION, &units[0][..], Vec::new()).unwrap();
    let used = {
        let (_, layout) = super::checkpoint::layout();
        let payload = &units[0][layout.header_bytes()..];
        layout.header_bytes() + payload.iter().rposition(|&b| b != 0).unwrap() + 1
    };
    let mut rng = SplitMix64::new(9);
    for _ in 0..400 {
        let mut torn = units[0].clone();
        let at = rng.below(used as u64) as usize;
        torn[at] ^= 1 << rng.below(8);
        let outcome = decode(crc, block(9), SESSION, &torn[..], Vec::new());
        assert!(outcome.is_err(), "byte {at}: a flipped block is a hole");
        assert_ne!(outcome.ok(), Some(good.clone()));
    }
    assert_eq!(
        decode(
            crc,
            block(9),
            SESSION,
            &units[0][..UNIT_LEN - 1],
            Vec::new()
        ),
        Err(BlockHole::Unread),
        "a short read is an unread unit, not checked content"
    );
    let mut dirty = units[0].clone();
    dirty[UNIT_LEN - 1] = 1;
    assert!(
        matches!(
            decode(crc, block(9), SESSION, &dirty[..], Vec::new()),
            Err(BlockHole::Chunk)
        ),
        "a nonzero trailing byte breaks the chunk crc"
    );
}

#[test]
fn a_block_whose_parts_do_not_chain_or_hold_a_malformed_body_is_a_hole() {
    let crc = Crc32c::detect();
    let (_, layout) = super::checkpoint::layout();
    let start = layout.header_bytes();
    let entry = wide(0, 0, 1);
    let units = packed(2, &[Record::Insert(entry.clone())]);
    // A block whose first part's sequence is not the block's first sequence.
    let mut payload = units[0][start..].to_vec();
    payload[..8].copy_from_slice(&7u64.to_le_bytes());
    let resealed = seal(crc, block(2), &payload[..payload.len()]);
    assert_eq!(
        decode(crc, block(2), SESSION, &resealed[..], Vec::new()),
        Err(BlockHole::Content)
    );
    // A part shortened by one byte leaves its last byte, the nonzero cause of an expiry, past the parts.
    let mut payload = packed(2, &[remove(&entry, Cause::Expire)])[0][start..].to_vec();
    let len = u16::from_le_bytes([payload[12], payload[13]]);
    payload[12..14].copy_from_slice(&(len - 1).to_le_bytes());
    let short = seal(crc, block(2), &payload);
    let decoded = decode(crc, block(2), SESSION, &short[..], Vec::new());
    assert!(
        matches!(decoded, Err(BlockHole::Content)),
        "the trailing body byte is nonzero past the part: {decoded:?}"
    );
    // A part shortened by a whole extent decodes, and its record is not one body of its kind.
    let mut payload = units[0][start..].to_vec();
    let len = u16::from_le_bytes([payload[12], payload[13]]);
    let body_end = 10 + PART_HEADER + usize::from(len);
    payload[12..14].copy_from_slice(&(len - 8).to_le_bytes());
    payload[body_end - 8..body_end].fill(0);
    let short = seal(crc, block(2), &payload);
    let decoded = decode(crc, block(2), SESSION, &short[..], Vec::new()).unwrap();
    let mut assembler = Assembler::default();
    assert_eq!(
        fed(&mut assembler, decoded[0]),
        Err(BlockHole::Content),
        "a body short of its extents is malformed"
    );
    let one = packed(2, &[remove(&entry, Cause::Expire)])[0][start..].to_vec();
    let two = packed(
        2,
        &[remove(&entry, Cause::Expire), remove(&entry, Cause::Evict)],
    )[0][start..]
        .to_vec();
    let patch = |payload: &[u8], at: usize, bytes: &[u8]| {
        let mut payload = payload.to_vec();
        payload[at..at + bytes.len()].copy_from_slice(bytes);
        seal(crc, block(2), &payload)
    };
    for (unit, case) in [
        (patch(&one, 11, &[1]), "a nonzero pad byte"),
        (patch(&one, 10, &[4]), "a kind past REPLACE"),
        (
            patch(&one, 22, &1u16.to_le_bytes()),
            "an index at its count",
        ),
        (patch(&one, 12, &0u16.to_le_bytes()), "an empty part"),
        (patch(&one, 8, &0u16.to_le_bytes()), "no part"),
        (patch(&two, 87, &2u64.to_le_bytes()), "a sequence gap"),
        (
            patch(&one, 24, &2u16.to_le_bytes()),
            "an unfinished part short of the block",
        ),
    ] {
        assert_eq!(
            decode(crc, block(2), SESSION, &unit[..], Vec::new()),
            Err(BlockHole::Content),
            "{case}"
        );
    }
    let mut same_record = two.clone();
    same_record[24..26].copy_from_slice(&2u16.to_le_bytes());
    same_record[87..95].copy_from_slice(&2u64.to_le_bytes());
    let unit = patch(&same_record, 87, &[0; 8]);
    let unit = patch(&unit[start..], 95, &1u16.to_le_bytes());
    let unit = patch(&unit[start..], 97, &2u16.to_le_bytes());
    assert_eq!(
        decode(crc, block(2), SESSION, &unit[..], Vec::new()),
        Err(BlockHole::Content),
        "a part after an unfinished part of its block"
    );
    let unit = patch(&one, 82, &[3]);
    let decoded = decode(crc, block(2), SESSION, &unit[..], Vec::new()).unwrap();
    assert_eq!(
        fed(&mut Assembler::default(), decoded[0]),
        Err(BlockHole::Content),
        "a cause byte past Expire"
    );
}

#[test]
fn the_delta_region_is_the_prefix_units_after_the_slots() {
    let layout = Layout {
        units: 1 + 3 * 4 + 5,
        slots: 3,
        slot_units: 4,
        entries: 1,
    };
    assert_eq!(blocks(&layout), 5);
    let tight = Layout {
        units: 13,
        ..layout
    };
    assert_eq!(
        blocks(&tight),
        0,
        "a layout with no unit past the slots has no delta block"
    );
}

#[test]
fn a_part_that_continues_no_open_record_is_dropped_and_a_cut_record_never_completes() {
    let records = [
        Record::Insert(wide(0, 0, 700)),
        Record::Insert(wide(1, 800, 1)),
    ];
    let units = packed(0, &records);
    assert!(units.len() >= 2);
    let crc = Crc32c::detect();
    // Block 0 is skipped: block 1 opens with a continuation part, which the assembler drops with no open record.
    let mut assembler = Assembler::default();
    let decoded = decode(crc, block(1), SESSION, &units[1][..], Vec::new()).unwrap();
    assert!(decoded[0].0.index > 0);
    let completed: Vec<_> = decoded
        .into_iter()
        .filter_map(|part| fed(&mut assembler, part).unwrap())
        .collect();
    assert_eq!(
        completed,
        vec![records[1].clone()],
        "only the whole record completes"
    );
}
