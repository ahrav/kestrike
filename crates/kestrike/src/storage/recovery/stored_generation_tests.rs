//! Stored generations of the delta block and the checkpoint unit. A stored generation is one committed file under
//! `fixtures/`, named `<format>-<n>.<ext>` with `n` counting from 1, whose bytes stay fixed once committed, together
//! with the literal value its test expects. Each format's table lists its generations oldest first; a change that
//! alters written bytes appends a generation, a line in the fixture ledger `format-fixtures.sha256` and a table row,
//! and keeps every existing file, line and row as it is.
//!
//! A generation decodes through the production decoder, with no damage, to its literal value, or it refuses at its
//! version. A delta file refuses when every unit fails with `HeaderMismatch::Version { found }`, where `found` is the
//! version in the unit's header. For a refused checkpoint slot, each unit decoded alone reports
//! `HeaderMismatch::Version` with `found` equal to its header version, and in the whole slot every
//! unit failed, and no entry loads. Every other outcome fails the test, and the newest generation decodes. The
//! current encoder reproduces the newest generation byte for byte, so a change to written bytes fails until a new
//! generation joins the table.
//!
//! The delta and checkpoint tests over every stored generation check how the decoder classifies damaged copies of the
//! newest generation. The expected classifications and the checkpoint encoder test's slot size are literals for the
//! newest generation's unit count and layout. Update those literals when appending a generation.
//!
//! Distinct expected values expose swaps between equal-width fields, and expected words with nonzero upper bits
//! expose truncation to 32 bits.

use std::ops::RangeBounds;

use super::capture::CaptureEntry;
use super::checkpoint::{Checkpoint, Damage, UNIT_LEN, UnitDamage, encode};
use super::checkpoint_tests::{Fed, canonical, loaded};
use super::delta::{self, Assembler, Block, BlockHole, Cause, Identity, Record, identity_of};
use super::delta_tests::{fed, packed_at};
use super::{GuardedLoad, LSN_LIMIT};
use crate::net::ownership::Shard;
use crate::storage::extent::ExtentLocator;
use crate::storage::record::{Crc32c, HeaderMismatch, admits};

/// Payload offset in a one-chunk 4096-byte unit: 108 fixed record header bytes, then a chunk table of two 4-byte
/// entries (chunk count + 1).
const PAYLOAD_AT: usize = 116;

/// Empty files and trailing partial units trigger an assertion before refusal classification.
fn units_of(bytes: &[u8]) -> usize {
    assert!(
        !bytes.is_empty() && bytes.len().is_multiple_of(UNIT_LEN),
        "{} bytes are not whole units",
        bytes.len()
    );
    bytes.len() / UNIT_LEN
}

/// The header version in `unit`'s bytes: the little-endian `u32` at offset 8 of the record header.
fn version_of(unit: &[u8]) -> u32 {
    u32::from_le_bytes(unit[8..12].try_into().unwrap())
}

fn at_version(bytes: &[u8], version: u32, units: impl RangeBounds<usize>) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    for (at, unit) in bytes.chunks_mut(UNIT_LEN).enumerate() {
        if units.contains(&at) {
            unit[8..12].copy_from_slice(&version.to_le_bytes());
        }
    }
    bytes
}

/// Asserts that `word` reads as `start` and `len` through the extent locator's accessors.
fn assert_extent(word: u64, (start, len): (u64, u32)) {
    let locator = ExtentLocator::from_bits(word);
    assert_eq!(
        (locator.start_unit(), locator.len_units()),
        (start, len),
        "{word:#018x}"
    );
}

/// One stored delta generation: the file, the block of its first unit, its records with their sequences, and one
/// extent word of those records with the start and length it encodes.
struct DeltaGeneration {
    bytes: &'static [u8],
    first: Block,
    records: Vec<(u64, Record)>,
    extent: (u64, (u64, u32)),
}

/// Every stored delta generation, oldest first.
fn delta_generations() -> Vec<DeltaGeneration> {
    vec![DeltaGeneration {
        bytes: include_bytes!("fixtures/delta-1.blocks"),
        first: Block {
            shard: Shard::new(11).unwrap(),
            session: 0x0000_0006_0000_000C,
            lsn: 0x0000_0000_F304_0531,
        },
        records: vec![
            (
                0x0A0B_0C0D_0E0F_1051,
                Record::Insert(CaptureEntry {
                    key: *b"delta generation 1: INSERT short",
                    allocation: 0x0000_0011_0000_0001,
                    session: 0x0000_0006_0000_0006,
                    version: 0x0102_0304_0506_0721,
                    deadline_ns: 0x1122_3344_5566_7788,
                    lifetime_ms: 0x0A0B_0C0D,
                    tail: 0x0123,
                    extents: vec![0x0000_03A0_0000_1234, 0x0000_0100_0000_1240],
                }),
            ),
            (
                0x0A0B_0C0D_0E0F_1052,
                Record::Remove {
                    identity: Identity {
                        key: *b"delta generation 1: REMOVE inval",
                        allocation: 0x0000_0012_0000_0002,
                        session: 0x0000_0006_0000_0004,
                        version: 0x0102_0304_0506_0722,
                    },
                    cause: Cause::Invalidate,
                },
            ),
            (
                0x0A0B_0C0D_0E0F_1053,
                Record::Remove {
                    identity: Identity {
                        key: *b"delta generation 1: REMOVE expir",
                        allocation: 0x0000_0013_0000_0003,
                        session: 0x0000_0006_0000_0002,
                        version: 0x0102_0304_0506_0723,
                    },
                    cause: Cause::Expire,
                },
            ),
            (
                0x0A0B_0C0D_0E0F_1054,
                Record::Replace {
                    old: Identity {
                        key: *b"delta generation 1: REPLACE old.",
                        allocation: 0x0000_0014_0000_0004,
                        session: 0x0000_0005_0000_0002,
                        version: 0x0102_0304_0506_0724,
                    },
                    cause: Cause::Evict,
                    new: CaptureEntry {
                        key: *b"delta generation 1: REPLACE new.",
                        allocation: 0x0000_0015_0000_0005,
                        session: 0x0000_0006_0000_0008,
                        version: 0x0102_0304_0506_0725,
                        deadline_ns: 0x2233_4455_6677_8899,
                        lifetime_ms: 0x1B1C_1D1E,
                        tail: 0x0456,
                        extents: vec![
                            0x0000_0100_0000_2000,
                            0x0000_0200_0000_2010,
                            0x0000_0300_0000_2020,
                        ],
                    },
                },
            ),
            (
                0x0A0B_0C0D_0E0F_1055,
                Record::Insert(CaptureEntry {
                    key: *b"delta generation 1: INSERT wide.",
                    allocation: 0x0000_0016_0000_0006,
                    session: 0x0000_0006_0000_000A,
                    version: 0x0102_0304_0506_0726,
                    deadline_ns: 0x3344_5566_7788_99AA,
                    lifetime_ms: 0x2B2C_2D2E,
                    tail: 0x0789,
                    extents: (0..600).map(|at| 0x0000_0100_0000_4000 + at).collect(),
                }),
            ),
        ],
        extent: (0x0000_03A0_0000_1234, (0x1234, 3)),
    }]
}

/// What a delta file decodes to: its records with their sequences; the version in each unit's header when every unit
/// fails with `HeaderMismatch::Version` at that version; or otherwise each unit's failure, `None` for a unit that
/// decoded and was not the first to fail assembly.
#[derive(Debug, PartialEq, Eq)]
enum DeltaOutcome {
    Decoded(Vec<(u64, Record)>),
    Refused(Vec<u32>),
    Other(Vec<Option<BlockHole>>),
}

/// Reads the units of `bytes` as consecutive blocks from `first`, for a reader of `first`'s session, through
/// `decode`, `Assembler` and `Record::decode`, the calls the delta replay makes.
fn delta_outcome(bytes: &[u8], first: Block) -> DeltaOutcome {
    let crc = Crc32c::detect();
    let mut holes = vec![None; units_of(bytes)];
    let mut decoded = Vec::new();
    for (at, unit) in bytes.chunks(UNIT_LEN).enumerate() {
        let block = Block {
            lsn: first.lsn + at as u64,
            ..first
        };
        match delta::decode(crc, block, first.session, unit, Vec::new()) {
            Ok(parts) => decoded.push(parts),
            Err(hole) => holes[at] = Some(hole),
        }
    }
    let refused = |(unit, hole): (&[u8], &Option<BlockHole>)| {
        *hole
            == Some(BlockHole::Header(HeaderMismatch::Version {
                found: version_of(unit),
            }))
    };
    if bytes.chunks(UNIT_LEN).zip(&holes).all(refused) {
        return DeltaOutcome::Refused(bytes.chunks(UNIT_LEN).map(version_of).collect());
    }
    if holes.iter().any(Option::is_some) {
        return DeltaOutcome::Other(holes);
    }
    let mut assembler = Assembler::default();
    let mut records = Vec::new();
    for (at, parts) in decoded.into_iter().enumerate() {
        let mut assemble = || -> Result<(), BlockHole> {
            assembler.admit(&parts)?;
            for &part in &parts {
                if let Some(record) = fed(&mut assembler, part)? {
                    records.push((part.0.seq, record));
                }
            }
            Ok(())
        };
        if let Err(hole) = assemble() {
            holes[at] = Some(hole);
            return DeltaOutcome::Other(holes);
        }
    }
    if assembler.open.is_some() {
        *holes.last_mut().unwrap() = Some(BlockHole::Content);
        return DeltaOutcome::Other(holes);
    }
    DeltaOutcome::Decoded(records)
}

/// Every stored delta generation takes one of its two legal outcomes, the newest decodes, and the extent word its
/// row names reads as its literal start and length. A copy of the newest generation with one flipped payload byte in
/// its first unit fails that unit's chunk crc alone, and a copy whose units both hold version 2 refuses at version 2.
/// When only the first unit holds version 2, the copy reports a single version hole in that unit.
/// A copy with version 2 in the first unit and a flipped payload byte in the second is damage: the second unit fails
/// its chunk crc at the current version.
#[test]
fn every_stored_delta_generation_decodes_to_its_records_or_refuses_at_its_version() {
    let generations = delta_generations();
    for (n, generation) in (1..).zip(&generations) {
        let units = units_of(generation.bytes) as u64;
        let last = generation.first.lsn.checked_add(units - 1);
        assert!(
            last.is_some_and(|last| last <= LSN_LIMIT),
            "delta generation {n}: LSN {last:?}"
        );
        match delta_outcome(generation.bytes, generation.first) {
            DeltaOutcome::Decoded(records) => {
                assert_eq!(records, generation.records, "delta generation {n}");
                let inserted: Vec<&CaptureEntry> = records
                    .iter()
                    .filter_map(|(_, record)| record.change().inserted)
                    .collect();
                for identity in inserted.iter().map(|entry| identity_of(entry)) {
                    assert!(
                        admits(&identity, &identity, generation.first.session),
                        "delta generation {n}: {identity:?}"
                    );
                }
                let (word, place) = generation.extent;
                assert!(
                    inserted.iter().any(|entry| entry.extents.contains(&word)),
                    "delta generation {n}"
                );
                assert_extent(word, place);
            }
            DeltaOutcome::Refused(_) => {
                assert!(
                    n < generations.len(),
                    "the newest delta generation {n} refuses"
                )
            }
            DeltaOutcome::Other(holes) => panic!("delta generation {n}: {holes:?}"),
        }
    }
    let newest = generations.last().unwrap();

    let mut flipped = newest.bytes.to_vec();
    flipped[PAYLOAD_AT + 200] ^= 0x01;
    assert_eq!(
        delta_outcome(&flipped, newest.first),
        DeltaOutcome::Other(vec![Some(BlockHole::Chunk), None])
    );
    assert_eq!(
        delta_outcome(&at_version(newest.bytes, 2, ..), newest.first),
        DeltaOutcome::Refused(vec![2, 2])
    );
    assert_eq!(
        delta_outcome(&at_version(newest.bytes, 2, ..1), newest.first),
        DeltaOutcome::Other(vec![
            Some(BlockHole::Header(HeaderMismatch::Version { found: 2 })),
            None
        ])
    );
    assert_eq!(
        delta_outcome(&at_version(newest.bytes, 2, 1..), newest.first),
        DeltaOutcome::Other(vec![
            None,
            Some(BlockHole::Header(HeaderMismatch::Version { found: 2 }))
        ])
    );
    let mut every = newest.bytes.to_vec();
    for unit in every.chunks_mut(UNIT_LEN) {
        unit[PAYLOAD_AT + 200] ^= 0x01;
    }
    assert_eq!(
        delta_outcome(&every, newest.first),
        DeltaOutcome::Other(vec![Some(BlockHole::Chunk), Some(BlockHole::Chunk)])
    );
    let mut mixed = at_version(newest.bytes, 2, ..1);
    for unit in mixed.chunks_mut(UNIT_LEN).skip(1) {
        unit[PAYLOAD_AT + 200] ^= 0x01;
    }
    assert_eq!(
        delta_outcome(&mixed, newest.first),
        DeltaOutcome::Other(vec![
            Some(BlockHole::Header(HeaderMismatch::Version { found: 2 })),
            Some(BlockHole::Chunk)
        ])
    );
    assert_eq!(
        delta_outcome(&newest.bytes[..UNIT_LEN], newest.first),
        DeltaOutcome::Other(vec![Some(BlockHole::Content)])
    );
}

/// The packer and the block encoder, given the newest generation's records at their sequences and its block
/// identity, write the file byte for byte.
#[test]
fn the_packer_reproduces_the_newest_delta_generation() {
    let newest = delta_generations().pop().unwrap();
    let records = newest.records.iter().map(|(seq, record)| (*seq, record));
    let bytes: Vec<u8> = packed_at(newest.first, records)
        .iter()
        .flat_map(|unit| unit.iter().copied())
        .collect();
    assert_eq!(bytes, newest.bytes);
}

/// `delta-1.blocks` holds two units whose payloads place their fields at the offsets of the delta payload layout.
/// In the first unit's payload, the first part header starts at 10, after the sequence and part count: its kind
/// byte is at 10 and its sequence at 14..22. The INSERT body starts at 26 with the key, allocation, session and
/// version. That two-extent body is 88 bytes, so the REMOVE part starts at 114, its body at 130, and its cause byte
/// at 186, after its 56-byte identity. The second unit's payload holds one part, index 1 of the final two-part
/// INSERT, so that record spans both units.
#[test]
fn the_first_delta_generation_holds_its_fields_at_the_documented_offsets() {
    let bytes = include_bytes!("fixtures/delta-1.blocks");
    assert_eq!(bytes.len(), 2 * 4096);
    let payload = &bytes[PAYLOAD_AT..4096];
    assert_eq!(payload[10], 1, "INSERT kind");
    assert_eq!(
        payload[14..22],
        0x0A0B_0C0D_0E0F_1051u64.to_le_bytes(),
        "sequence"
    );
    assert_eq!(payload[26..58], *b"delta generation 1: INSERT short", "key");
    assert_eq!(
        payload[58..66],
        0x0000_0011_0000_0001u64.to_le_bytes(),
        "allocation"
    );
    assert_eq!(
        payload[66..74],
        0x0000_0006_0000_0006u64.to_le_bytes(),
        "session"
    );
    assert_eq!(
        payload[74..82],
        0x0102_0304_0506_0721u64.to_le_bytes(),
        "version"
    );
    assert_eq!(payload[114], 2, "REMOVE kind");
    assert_eq!(
        payload[178..186],
        0x0102_0304_0506_0722u64.to_le_bytes(),
        "REMOVE version"
    );
    assert_eq!(
        payload[170..178],
        0x0000_0006_0000_0004u64.to_le_bytes(),
        "REMOVE session"
    );
    assert_eq!(payload[186], 1, "REMOVE cause Invalidate");
    let second = &bytes[4096 + PAYLOAD_AT..];
    assert_eq!(
        second[..8],
        0x0A0B_0C0D_0E0F_1055u64.to_le_bytes(),
        "the second unit's first sequence"
    );
    assert_eq!(second[8..10], [1, 0], "one part");
    assert_eq!(second[10], 1, "INSERT kind");
    assert_eq!(
        second[14..22],
        0x0A0B_0C0D_0E0F_1055u64.to_le_bytes(),
        "sequence"
    );
    assert_eq!(second[22..26], [1, 0, 2, 0], "part 1 of 2");
}

/// One stored checkpoint generation: the slot file, its entries, and one extent word of those entries with the
/// start and length it encodes.
struct CheckpointGeneration {
    bytes: &'static [u8],
    entries: Vec<CaptureEntry>,
    extent: (u64, (u64, u32)),
}

/// Every stored checkpoint generation, oldest first. Each is a slot of capture 5 of shard 7 by session `3·2^32 + 4`,
/// the checkpoint and reader session that `Fed` decodes with.
fn checkpoint_generations() -> Vec<CheckpointGeneration> {
    let mut long = vec![0x0000_0260_0000_0400];
    long.extend((1..45).map(|at| 0x0000_0100_0000_0500 + at));
    vec![CheckpointGeneration {
        bytes: include_bytes!("fixtures/checkpoint-1.slot"),
        entries: vec![
            CaptureEntry {
                key: *b"checkpoint generation 1: long...",
                allocation: 0x0000_0021_0000_0007,
                session: 0x0000_0003_0000_0002,
                version: 0x0203_0405_0607_0831,
                deadline_ns: 0x4455_6677_8899_AABB,
                lifetime_ms: 0x3B3C_3D3E,
                tail: 0x0234,
                extents: long,
            },
            CaptureEntry {
                key: *b"checkpoint generation 1: one....",
                allocation: 0x0000_0022_0000_0008,
                session: 0x0000_0003_0000_0004,
                version: 0x0203_0405_0607_0832,
                deadline_ns: 0x5566_7788_99AA_BBCC,
                lifetime_ms: 0x4B4C_4D4E,
                tail: 0x0345,
                extents: vec![0x0000_0400_0000_0600],
            },
            CaptureEntry {
                key: *b"checkpoint generation 1: two....",
                allocation: 0x0000_0023_0000_0009,
                session: 0x0000_0003_0000_0002,
                version: 0x0203_0405_0607_0833,
                deadline_ns: 0x6677_8899_AABB_CCDD,
                lifetime_ms: 0x5B5C_5D5E,
                tail: 0x0456,
                extents: vec![0x0000_0100_0000_0700, 0x0000_0200_0000_0710],
            },
        ],
        extent: (0x0000_0260_0000_0400, (0x400, 2)),
    }]
}

#[derive(Debug, PartialEq, Eq)]
enum CheckpointOutcome {
    Loaded(GuardedLoad),
    /// Header versions in unit order when every unit fails, each unit landed alone reports its header version as
    /// `found` in `HeaderMismatch::Version`, and the load yields zero entries.
    Refused(Vec<u32>),
    Other(Damage, GuardedLoad),
}

/// Lands every unit of `bytes` in order through the checkpoint tests' decode fixture and finishes the slot load.
/// `damage.failed` lists every failed unit by index, and `damage.first` gives the cause of one unit. To read the
/// cause of each failed unit, the unit lands alone in a fresh decode: the other units remain unread, a failed check
/// outranks a failed read, and that decode's first damage is the unit's own failure.
fn checkpoint_outcome(bytes: &[u8]) -> CheckpointOutcome {
    let units = units_of(bytes);
    let mut fed = Fed::new(units, 4);
    for (at, unit) in bytes.chunks(UNIT_LEN).enumerate() {
        fed.land(at, unit);
    }
    let slot = fed.finish();
    let load = slot.load();
    let Some(damage) = slot.damage else {
        return CheckpointOutcome::Loaded(load);
    };
    let versions: Vec<u32> = bytes.chunks(UNIT_LEN).map(version_of).collect();
    let refused = |&unit: &u32| {
        let at = unit as usize;
        let mut alone = Fed::new(units, 4);
        alone.land(at, &bytes[at * UNIT_LEN..][..UNIT_LEN]);
        let mismatch = HeaderMismatch::Version {
            found: versions[at],
        };
        alone.finish().damage.map(|damage| damage.first)
            == Some(UnitDamage::Header { unit, mismatch })
    };
    let every = damage.failed == (0..units as u32).collect::<Vec<_>>() && damage.unread.is_empty();
    let (GuardedLoad::Warm(entries) | GuardedLoad::Cold { entries, .. }) = &load;
    if every && entries.is_empty() && damage.failed.iter().all(refused) {
        return CheckpointOutcome::Refused(versions);
    }
    CheckpointOutcome::Other(damage, load)
}

/// Every stored checkpoint generation takes one of its two legal outcomes, the newest loads warm with its entries,
/// and the extent word its row names reads as its literal start and length. A copy of the newest generation with one
/// flipped payload byte in unit 1, the first row unit, fails that unit alone and loads warm with the two short
/// entries, whose rows all lie in unit 2, and a copy whose every unit holds version 2 refuses at version 2.
/// When only unit 0 holds version 2, the copy reports a single version failure in unit 0.
/// A copy with version 2 in unit 0 and a flipped payload byte in units 1 and 2 is damage: units 1 and 2 fail their
/// chunk crc at the current version.
#[test]
fn every_stored_checkpoint_generation_loads_its_entries_or_refuses_at_its_version() {
    let generations = checkpoint_generations();
    for (n, generation) in (1..).zip(&generations) {
        match checkpoint_outcome(generation.bytes) {
            CheckpointOutcome::Loaded(load) => {
                let expected = GuardedLoad::Warm(canonical(generation.entries.clone()));
                assert_eq!(load, expected, "checkpoint generation {n}");
                let (word, place) = generation.extent;
                let entries = loaded(load);
                assert!(
                    entries.iter().any(|entry| entry.extents.contains(&word)),
                    "checkpoint generation {n}"
                );
                assert_extent(word, place);
            }
            CheckpointOutcome::Refused(_) => assert!(
                n < generations.len(),
                "the newest checkpoint generation {n} refuses"
            ),
            CheckpointOutcome::Other(damage, load) => {
                panic!("checkpoint generation {n}: {damage:?} {load:?}")
            }
        }
    }
    let newest = generations.last().unwrap();

    let mut flipped = newest.bytes.to_vec();
    flipped[UNIT_LEN + PAYLOAD_AT + 100] ^= 0x01;
    let short = canonical(newest.entries[1..].to_vec());
    assert_eq!(
        checkpoint_outcome(&flipped),
        CheckpointOutcome::Other(
            Damage {
                first: UnitDamage::Chunk { unit: 1 },
                failed: vec![1],
                unread: vec![],
            },
            GuardedLoad::Warm(short)
        )
    );
    assert_eq!(
        checkpoint_outcome(&at_version(newest.bytes, 2, ..)),
        CheckpointOutcome::Refused(vec![2, 2, 2])
    );
    let version = |unit| UnitDamage::Header {
        unit,
        mismatch: HeaderMismatch::Version { found: 2 },
    };
    assert_eq!(
        checkpoint_outcome(&at_version(newest.bytes, 2, ..1)),
        CheckpointOutcome::Other(
            Damage {
                first: version(0),
                failed: vec![0],
                unread: vec![],
            },
            GuardedLoad::Warm(canonical(newest.entries.clone()))
        )
    );
    assert_eq!(
        checkpoint_outcome(&at_version(newest.bytes, 2, 1..)),
        CheckpointOutcome::Other(
            Damage {
                first: version(1),
                failed: vec![1, 2],
                unread: vec![],
            },
            GuardedLoad::Warm(Vec::new())
        )
    );
    let mut every = newest.bytes.to_vec();
    for unit in every.chunks_mut(UNIT_LEN) {
        unit[PAYLOAD_AT + 100] ^= 0x01;
    }
    assert_eq!(
        checkpoint_outcome(&every),
        CheckpointOutcome::Other(
            Damage {
                first: UnitDamage::Chunk { unit: 0 },
                failed: vec![0, 1, 2],
                unread: vec![],
            },
            GuardedLoad::Warm(Vec::new())
        )
    );
    let mut mixed = at_version(newest.bytes, 2, ..1);
    for unit in mixed.chunks_mut(UNIT_LEN).skip(1) {
        unit[PAYLOAD_AT + 100] ^= 0x01;
    }
    assert_eq!(
        checkpoint_outcome(&mixed),
        CheckpointOutcome::Other(
            Damage {
                first: version(0),
                failed: vec![0, 1, 2],
                unread: vec![],
            },
            GuardedLoad::Warm(Vec::new())
        )
    );
}

/// The checkpoint encoder, given the newest generation's entries, its checkpoint and a three-unit slot, writes the
/// file byte for byte.
#[test]
fn the_encoder_reproduces_the_newest_checkpoint_generation() {
    let newest = checkpoint_generations().pop().unwrap();
    let checkpoint = Checkpoint {
        shard: Shard::new(7).unwrap(),
        session: 0x0000_0003_0000_0004,
        capture: 5,
    };
    let units = encode(Crc32c::detect(), checkpoint, &newest.entries, 3).unwrap();
    assert_eq!(
        units
            .iter()
            .flat_map(|unit| unit.iter().copied())
            .collect::<Vec<u8>>(),
        newest.bytes
    );
}
