//! This module checks the recovery module's documented corruption-class table against the refusal types and the
//! tests the table cites, and holds the tamper cases of four of its rows.
//!
//! A label function per refusal type maps every variant to a class label or to [`OUTSIDE`], one arm per variant named
//! by its path, so a new variant stops this module from compiling until it has an arm. [`labels!`] emits each function
//! and the list of its arms, each a variant's name with its label, from the same arms. [`check`] requires a table row
//! for every label in those lists other than [`OUTSIDE`] and a `none` row for every label of [`NO_REFUSAL`], and a
//! test requires the variant name of each arm whose label is a class label to appear in the damage cell of a row of
//! that class.
//!
//! [`CASES`] holds at least one case for each of the four [`GAP_ROWS`]: header damage of a checkpoint unit
//! (`unit-header`), an intact unit 0 whose counts contradict themselves (`unit-0-counts`), header damage of a delta
//! block (`block-header`) and a unit of a session the reader does not admit (`header-session`). Each case decodes the
//! untouched image and requires the clean result, then edits it through [`tamper`] or stages a whole unit or another
//! reader, asserts the exact refusal, and returns the reader's action and the refusal's class: a slot case derives the
//! action from its load, and a block case reports `skip` for the hole its decode returned.
//!
//! The slot sweep of row `unit-unread` decodes the 60-entry image once for each of its units, leaving that one unit
//! unfed. It requires that unit unread, the `Unreadable` alarm, and a warm load of the entries whose rows lie entirely
//! on the other units.
//!
//! Offsets are literals from the documentation of the record header and the checkpoint payload: the magic at 0, the
//! key at 16, `body_len` at 76 and `chunk_len` at 80, and the payload after a 116-byte header: the 108 fixed bytes and a
//! two-entry chunk table.

use std::panic::{AssertUnwindSafe, catch_unwind};

use super::GuardedLoad;
use super::LoadRefusal;
use super::MetadataOutcome;
use super::block::Undecodable;
use super::capture::CaptureEntry;
use super::checkpoint::{Damage, SlotLoad, UNIT_LEN, UnitDamage, encode};
use super::checkpoint_tests::{Fed, SESSION, checkpoint, damaged, entries, outside, reseal, whole};
use super::delta::{self, BlockHole, Record};
use super::delta_tests::{block, packed, wide};
use crate::storage::record::fuzz_tests::u32_at;
use crate::storage::record::{Crc32c, HeaderMismatch};
use crate::storage::volume::activation;

/// The label of a variant outside the table's classes: a progress or success state, a refusal caused by the gate, the
/// entropy draw, a metadata write, a helper, a fingerprint collision, the configured limits or memory, or a wrapper
/// whose inner refusal carries the class.
const OUTSIDE: &str = "outside the table";

/// A label function of one refusal type and its arms, each the variant's name with the label it returns, [`OUTSIDE`]
/// included.
struct Labels<T: 'static> {
    of: fn(&T) -> &'static str,
    all: &'static [(&'static str, &'static str)],
}

/// Emits a [`Labels`] constant from `Variant => label` arms over the variants of `$type`: the function is the match of
/// those arms, and the list pairs each arm's variant name with its label. Each top-level pattern names a variant
/// through the type, and the compiler enforces coverage of top-level variants. Field patterns may use wildcards or
/// bindings.
macro_rules! labels {
    (
        $(#[$doc:meta])* $name:ident: $type:ty {
            $($variant:ident $(($($tuple:tt)*))? $({$($fields:tt)*})? => $label:expr),+ $(,)?
        }
    ) => {
        $(#[$doc])*
        const $name: Labels<$type> = Labels {
            of: |refusal| {
                type Of = $type;
                match refusal {
                    $(Of::$variant $(($($tuple)*))? $({$($fields)*})? => $label),+
                }
            },
            all: &[$((stringify!($variant), $label)),+],
        };
    };
}

labels! {
    /// Why the block open rejects a root block.
    UNDECODABLE: Undecodable {
        Invalid => "root-invalid",
        Unsupported { .. } => "root-unsupported",
        ForeignLayout => "root-format",
    }
}

labels! {
    /// The volume's metadata outcome. `Bootstrapping` and `Open` are progress and success states. `Unfenced`,
    /// `EntropyUnavailable` and `MetadataFailed` report the gate, the entropy draw, and metadata writes and helpers.
    /// `Collided` reports two valid keys that share a fingerprint under the hasher. `Unloadable` carries a
    /// [`LOAD_REFUSAL`] class.
    METADATA: MetadataOutcome {
        Bootstrapping => OUTSIDE,
        Unformatted => "root-unformatted",
        Open => OUTSIDE,
        SlotUnreadable { .. } => "root-slot-unreadable",
        Unsupported { .. } => "root-unsupported",
        FormatMismatch => "root-format",
        TiedRoots => "root-tied",
        StaleSession => "root-stale-session",
        Unfenced(_) => OUTSIDE,
        EntropyUnavailable => OUTSIDE,
        MetadataFailed => OUTSIDE,
        Collided => OUTSIDE,
        Unloadable(_) => OUTSIDE,
    }
}

labels! {
    /// Why the activation record's read-back fails to decode.
    ACTIVATION_DAMAGE: activation::Damage {
        Torn => "activation-torn",
        Invalid => "activation-invalid",
    }
}

labels! {
    /// Why the activation step refuses; `Damaged` carries an [`ACTIVATION_DAMAGE`] class.
    ACTIVATION_FAULT: activation::Fault {
        Damaged(_) => OUTSIDE,
        Foreign(_) => "activation-foreign",
    }
}

labels! {
    /// The first record header check that failed, in six classes.
    HEADER: HeaderMismatch {
        Truncated { .. } => "header-framing",
        Magic { .. } => "header-framing",
        Version { .. } => "header-framing",
        Lengths { .. } => "header-lengths",
        ExtentLength { .. } => "header-lengths",
        ChunkParameters { .. } => "header-lengths",
        HeaderCrc { .. } => "header-checksum",
        ContextCrc { .. } => "header-checksum",
        Key => "header-identity",
        Allocation { .. } => "header-identity",
        Session { .. } => "header-identity",
        CacheVersion { .. } => "header-identity",
        ForeignSession { .. } => "header-session",
        ExtentIndex { .. } => "header-position",
        Offset { .. } => "header-position",
    }
}

labels! {
    /// The damage of one checkpoint unit or of the slot's counts.
    UNIT_DAMAGE: UnitDamage {
        Header { .. } => "unit-header",
        Chunk { .. } => "unit-chunk",
        Content { .. } => "unit-content",
        Units { .. } => "unit-count",
        Unread { .. } => "unit-unread",
    }
}

labels! {
    /// Why a delta block is a hole.
    BLOCK_HOLE: BlockHole {
        Header(_) => "block-header",
        Chunk => "block-chunk",
        Content => "block-content",
        Unread => "block-unread",
    }
}

labels! {
    /// Why a load or a warm attach refuses. `Limits` judges the configured limits, the slot the store names and a
    /// restored set's keys per index shard, and `Memory` judges the engine budget and allocations: both judge the
    /// reader's configuration and resources.
    LOAD_REFUSAL: LoadRefusal {
        Limits => OUTSIDE,
        Memory => OUTSIDE,
        Bounds => "guard-refusal",
        Key => "guard-refusal",
        Slot => "guard-refusal",
        Overlap => "guard-refusal",
        Units => "guard-refusal",
        Entries => "guard-refusal",
        StaleWrite => "attach-stale-write",
        Unreadable => "attach-unreadable",
        Unrestorable => "attach-unrestorable",
    }
}

/// The arm lists of the eight label functions, one per refusal type.
const LISTS: [&[(&str, &str)]; 8] = [
    UNDECODABLE.all,
    METADATA.all,
    ACTIVATION_DAMAGE.all,
    ACTIVATION_FAULT.all,
    HEADER.all,
    UNIT_DAMAGE.all,
    BLOCK_HOLE.all,
    LOAD_REFUSAL.all,
];

fn arms() -> impl Iterator<Item = (&'static str, &'static str)> {
    LISTS.into_iter().flatten().copied()
}

/// Every class label the label functions return, each once, [`OUTSIDE`] left out.
fn class_labels() -> Vec<&'static str> {
    let mut labels: Vec<&str> = arms().map(|(_, label)| label).collect();
    labels.retain(|&label| label != OUTSIDE);
    labels.sort_unstable();
    labels.dedup();
    labels
}

/// The reader's action on a class of damage, as the table's action column names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    /// The reader proceeds and loses nothing beyond what the damage destroyed.
    Recover,
    /// The damaged unit, or the damaged record of a decoded delta block, yields nothing, and the load continues without
    /// what depends on it.
    Skip,
    /// The load or the attach ends with a typed outcome and installs nothing.
    Refuse,
}

impl Action {
    fn word(self) -> &'static str {
        match self {
            Action::Recover => "recover",
            Action::Skip => "skip",
            Action::Refuse => "refuse",
        }
    }
}

/// What a case reports: the reader's action, the class label of the refusal it returned, and, for a case of a `unit-`
/// or `block-` row, the class label of the header mismatch that refusal wraps. A slot case derives its action from
/// its load through [`slot_action`], and a block case reports `skip` for the hole its decode returned. A
/// `header-session` case reports the mismatch's class as its class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Observed {
    action: Action,
    class: &'static str,
    header: Option<&'static str>,
}

/// One entry of the matrix: the table row it binds, its declared action, and the run that decodes its image.
struct Case {
    row: &'static str,
    /// The header row whose class the wrapped header mismatch belongs to, for a case of a `unit-` or `block-` row whose
    /// refusal wraps one; a `header-session` case binds that row as its own.
    header: Option<&'static str>,
    name: &'static str,
    action: Action,
    /// Decodes the untouched image and requires the clean result, then asserts the exact refusal of the damaged image
    /// and returns its [`Observed`].
    run: fn() -> Observed,
}

/// The payload's first byte in a checkpoint unit or a delta block: the record header's 108 fixed bytes, then a chunk
/// table of two entries for one 3980-byte chunk.
const PAYLOAD: usize = 116;

/// The reader of the generation above `session`'s, at `session`'s epoch.
fn other_generation(session: u64) -> u64 {
    session + (1 << 32)
}

/// The reader of `session`'s generation at the even epoch below `session`'s.
///
/// # Panics
///
/// When `session`'s epoch is odd or below 4: the function returns `session - 2`, which holds an even nonzero epoch only
/// when `session`'s epoch is even and at least 4.
fn earlier_epoch(session: u64) -> u64 {
    let epoch = session as u32;
    assert!(
        epoch >= 4 && epoch.is_multiple_of(2),
        "epoch {epoch} has an even nonzero epoch below it"
    );
    session - 2
}

const PRE_IMAGE: &str = "the bytes at the offset start with the pre-image";
const WRITES_A_CHANGE: &str = "the new bytes differ from the pre-image and match its length";

/// Writes `new` at `at` of `bytes` once `bytes[at..]` starts with `old` and `new` is another value of `old`'s length,
/// and writes nothing otherwise.
///
/// # Panics
///
/// When either condition fails, with [`PRE_IMAGE`] or [`WRITES_A_CHANGE`] as the message's first line.
fn tamper(bytes: &mut [u8], at: usize, old: &[u8], new: &[u8]) {
    let found = bytes.get(at..).unwrap_or_default();
    assert!(
        found.starts_with(old),
        "{PRE_IMAGE}\nat {at}: expected {old:?}, found {:?}",
        &found[..old.len().min(found.len())]
    );
    assert!(
        new != old && new.len() == old.len(),
        "{WRITES_A_CHANGE}\nat {at}: {old:?} to {new:?}"
    );
    bytes[at..at + new.len()].copy_from_slice(new);
}

/// The units of the 60 entries under checkpoint 5, with those entries: unit 0 with the counts and three data units
/// holding the 120 rows.
fn slot_image() -> (Vec<CaptureEntry>, Vec<Box<[u8; UNIT_LEN]>>) {
    let entries = entries(60);
    let units = encode(Crc32c::detect(), checkpoint(5), &entries, u32::MAX).unwrap();
    assert_eq!(units.len(), 4, "120 rows span unit 0 and three data units");
    (entries, units)
}

/// The load of `units`, each landed once in unit order, for a reader of session `reader`.
fn slot_by(units: &[Box<[u8; UNIT_LEN]>], reader: u64) -> SlotLoad {
    let mut fed = Fed::read_by(units.len(), reader);
    for (at, unit) in units.iter().enumerate() {
        fed.land(at, &unit[..]);
    }
    fed.finish()
}

/// Requires `units` to load every one of `entries` warm, with no damage, for the checkpoint's own session.
fn accepted(units: &[Box<[u8; UNIT_LEN]>], entries: &[CaptureEntry]) {
    assert_eq!(
        whole(slot_by(units, SESSION)),
        GuardedLoad::Warm(entries.to_vec()),
        "the untouched slot loads every entry"
    );
}

/// The reader's action on a damaged slot of `entries`: `refuse` for a cold load, `skip` for a warm load of exactly the
/// entries with no row on a failed or unread unit.
///
/// # Panics
///
/// When the load is warm with any other entries.
fn slot_action(damage: &Damage, load: GuardedLoad, entries: &[CaptureEntry]) -> Action {
    let GuardedLoad::Warm(kept) = load else {
        return Action::Refuse;
    };
    let lost: Vec<u32> = damage
        .failed
        .iter()
        .chain(&damage.unread)
        .copied()
        .collect();
    let intact = lost.iter().fold(entries.to_vec(), |survivors, &unit| {
        let past = outside(entries, unit as usize);
        survivors
            .into_iter()
            .filter(|entry| past.contains(entry))
            .collect()
    });
    assert_eq!(
        kept, intact,
        "a warm damaged load holds the entries with no row on {lost:?}"
    );
    Action::Skip
}

/// The case of unit 1 with its header bytes at `at` changed from `old` to `new` and the header not resealed:
/// `Header { unit: 1, mismatch }` with the mismatch `expected` gives the changed unit, unit 1 alone failed, the alarm
/// `StaleWrite`, and a warm load of the entries with no row on unit 1.
fn unit_1_header(
    at: usize,
    old: &[u8],
    new: &[u8],
    expected: fn(&[u8]) -> HeaderMismatch,
) -> Observed {
    let (entries, mut units) = slot_image();
    accepted(&units, &entries);
    tamper(&mut units[1][..], at, old, new);
    let mismatch = expected(&units[1][..]);
    unit_1_failed(&entries, &units, mismatch)
}

/// Asserts that `units` fail unit 1 alone with `mismatch` and returns what the slot load observed.
fn unit_1_failed(
    entries: &[CaptureEntry],
    units: &[Box<[u8; UNIT_LEN]>],
    mismatch: HeaderMismatch,
) -> Observed {
    let (damage, load) = damaged(slot_by(units, SESSION));
    assert_eq!(damage.first, UnitDamage::Header { unit: 1, mismatch });
    assert_eq!(
        (&damage.failed[..], &damage.unread[..]),
        (&[1][..], &[][..])
    );
    assert_eq!(damage.alarm(), LoadRefusal::StaleWrite);
    Observed {
        class: (UNIT_DAMAGE.of)(&damage.first),
        action: slot_action(&damage, load, entries),
        header: Some((HEADER.of)(&mismatch)),
    }
}

/// Unit 1 of capture 4 staged in place of unit 1 of capture 5: the key matches, and the allocation word, compared
/// before the session and the cache version, differs.
fn unit_1_of_another_capture() -> Observed {
    let (entries, mut units) = slot_image();
    accepted(&units, &entries);
    let earlier = encode(Crc32c::detect(), checkpoint(4), &entries, u32::MAX).unwrap();
    units[1] = earlier[1].clone();
    let mismatch = HeaderMismatch::Allocation {
        expected: (5 << 32) | 1,
        found: (4 << 32) | 1,
    };
    unit_1_failed(&entries, &units, mismatch)
}

/// The case of unit 0 with its payload bytes at `at` changed from `old` to `new` and its header resealed: unit 0
/// passes its identity and crc checks, contradicts its counts as `Content { unit: 0 }`, is failed alone, and loads the
/// slot cold with `StaleWrite`.
fn unit_0_counts(at: usize, old: &[u8], new: &[u8]) -> Observed {
    let (entries, mut units) = slot_image();
    accepted(&units, &entries);
    tamper(&mut units[0][..], PAYLOAD + at, old, new);
    reseal(&mut units[0], 0);
    let (damage, load) = damaged(slot_by(&units, SESSION));
    assert_eq!(damage.first, UnitDamage::Content { unit: 0 });
    assert_eq!(
        (&damage.failed[..], &damage.unread[..]),
        (&[0][..], &[][..])
    );
    assert!(
        matches!(
            load,
            GuardedLoad::Cold {
                refusal: LoadRefusal::StaleWrite,
                ..
            }
        ),
        "a unit 0 that contradicts its counts loads the slot cold: {load:?}"
    );
    Observed {
        class: (UNIT_DAMAGE.of)(&damage.first),
        action: slot_action(&damage, load, &entries),
        header: None,
    }
}

/// The slot read by the reader session that `reader` computes from the checkpoint's session, a reader that does not
/// admit the checkpoint's session: each unit decoded alone fails with `ForeignSession` beside the unfed units, and the whole slot fails every unit and loads warm
/// and empty.
fn slot_of_a_foreign_session(reader: fn(u64) -> u64) -> Observed {
    let (entries, units) = slot_image();
    accepted(&units, &entries);
    let reader = reader(SESSION);
    let mismatch = HeaderMismatch::ForeignSession {
        found: SESSION,
        reader,
    };
    let all: Vec<u32> = (0..units.len() as u32).collect();
    for unit in all.iter().copied() {
        let mut fed = Fed::read_by(units.len(), reader);
        fed.land(unit as usize, &units[unit as usize][..]);
        let (damage, _) = damaged(fed.finish());
        assert_eq!(damage.first, UnitDamage::Header { unit, mismatch });
        let unfed: Vec<u32> = all.iter().copied().filter(|&at| at != unit).collect();
        assert_eq!((damage.failed, damage.unread), (vec![unit], unfed));
    }
    let (damage, load) = damaged(slot_by(&units, reader));
    assert_eq!(damage.first, UnitDamage::Header { unit: 0, mismatch });
    assert_eq!((&damage.failed, &damage.unread[..]), (&all, &[][..]));
    assert_eq!(load, GuardedLoad::Warm(Vec::new()), "no entry loads");
    Observed {
        class: (HEADER.of)(&mismatch),
        action: slot_action(&damage, load, &entries),
        header: None,
    }
}

/// The block at LSN 5 that holds one insert.
fn block_image() -> Box<[u8; UNIT_LEN]> {
    let mut blocks = packed(5, &[Record::Insert(wide(0, 0, 1))]);
    assert_eq!(blocks.len(), 1, "one insert packs into one block");
    blocks.remove(0)
}

/// Decodes `bytes` as block 5 for a reader of session `reader`.
fn block_decode(bytes: &[u8], reader: u64) -> Result<(), BlockHole> {
    delta::decode(Crc32c::detect(), block(5), reader, bytes, Vec::new()).map(drop)
}

/// The case of the block with its header bytes at `at` changed from `old` to `new`: `BlockHole::Header` with the
/// mismatch `expected` gives the changed block, a hole, which is the block decode's `skip`.
fn block_header(
    at: usize,
    old: &[u8],
    new: &[u8],
    expected: fn(&[u8]) -> HeaderMismatch,
) -> Observed {
    let mut unit = block_image();
    let session = block(5).session;
    block_decode(&unit[..], session).expect("the untouched block decodes");
    tamper(&mut unit[..], at, old, new);
    let mismatch = expected(&unit[..]);
    let hole = BlockHole::Header(mismatch);
    assert_eq!(block_decode(&unit[..], session), Err(hole));
    Observed {
        action: Action::Skip,
        class: (BLOCK_HOLE.of)(&hole),
        header: Some((HEADER.of)(&mismatch)),
    }
}

/// The block read by the reader session that `reader` computes from the block's session, a reader that does not admit
/// the block's session: `ForeignSession`, a hole, which is the block decode's `skip`.
fn block_of_a_foreign_session(reader: fn(u64) -> u64) -> Observed {
    let unit = block_image();
    let session = block(5).session;
    block_decode(&unit[..], session).expect("the untouched block decodes");
    let reader = reader(session);
    let mismatch = HeaderMismatch::ForeignSession {
        found: session,
        reader,
    };
    assert_eq!(
        block_decode(&unit[..], reader),
        Err(BlockHole::Header(mismatch))
    );
    Observed {
        action: Action::Skip,
        class: (HEADER.of)(&mismatch),
        header: None,
    }
}

/// The stored header crc and the crc of the tampered header with its crc field read as zero.
fn header_crc(bytes: &[u8]) -> HeaderMismatch {
    let mut header = bytes[..PAYLOAD].to_vec();
    header[12..16].fill(0);
    HeaderMismatch::HeaderCrc {
        stored: u32_at(bytes, 12),
        computed: Crc32c::detect().checksum(&header),
    }
}

/// The `body_len` of a 116-byte header in a 4096-byte unit.
const BODY_LEN: u32 = 3980;
const CHUNK_LEN: u32 = 4096;

/// The values the header cases write in place of the magic, `body_len` and `chunk_len`.
const EDITED_MAGIC: &[u8; 8] = b"IMGCREC0";
const EDITED_BODY_LEN: u32 = BODY_LEN - 1;
const EDITED_CHUNK_LEN: u32 = 2 * CHUNK_LEN;

fn magic(_: &[u8]) -> HeaderMismatch {
    HeaderMismatch::Magic {
        found: u64::from_le_bytes(*EDITED_MAGIC),
    }
}

fn lengths(_: &[u8]) -> HeaderMismatch {
    HeaderMismatch::Lengths {
        metadata_len: 0,
        body_len: EDITED_BODY_LEN,
    }
}

fn chunk_parameters(_: &[u8]) -> HeaderMismatch {
    HeaderMismatch::ChunkParameters {
        chunk_len: EDITED_CHUNK_LEN,
        chunk_count: 1,
    }
}

/// The matrix of the gap rows.
const CASES: &[Case] = &[
    Case {
        row: "unit-header",
        header: Some("header-framing"),
        name: "unit 1 magic",
        action: Action::Skip,
        run: || unit_1_header(0, b"IMGCREC1", EDITED_MAGIC, magic),
    },
    Case {
        row: "unit-header",
        header: Some("header-lengths"),
        name: "unit 1 body_len",
        action: Action::Skip,
        run: || {
            unit_1_header(
                76,
                &BODY_LEN.to_le_bytes(),
                &EDITED_BODY_LEN.to_le_bytes(),
                lengths,
            )
        },
    },
    Case {
        row: "unit-header",
        header: Some("header-lengths"),
        name: "unit 1 chunk_len",
        action: Action::Skip,
        run: || {
            unit_1_header(
                80,
                &CHUNK_LEN.to_le_bytes(),
                &EDITED_CHUNK_LEN.to_le_bytes(),
                chunk_parameters,
            )
        },
    },
    Case {
        row: "unit-header",
        header: Some("header-checksum"),
        name: "unit 1 key tag",
        action: Action::Skip,
        run: || unit_1_header(16, b"IMGCKCK1", b"IMGCKCK2", header_crc),
    },
    Case {
        row: "unit-header",
        header: Some("header-identity"),
        name: "unit 1 of capture 4",
        action: Action::Skip,
        run: unit_1_of_another_capture,
    },
    Case {
        row: "block-header",
        header: Some("header-framing"),
        name: "block magic",
        action: Action::Skip,
        run: || block_header(0, b"IMGCREC1", EDITED_MAGIC, magic),
    },
    Case {
        row: "block-header",
        header: Some("header-lengths"),
        name: "block body_len",
        action: Action::Skip,
        run: || {
            block_header(
                76,
                &BODY_LEN.to_le_bytes(),
                &EDITED_BODY_LEN.to_le_bytes(),
                lengths,
            )
        },
    },
    Case {
        row: "block-header",
        header: Some("header-lengths"),
        name: "block chunk_len",
        action: Action::Skip,
        run: || {
            block_header(
                80,
                &CHUNK_LEN.to_le_bytes(),
                &EDITED_CHUNK_LEN.to_le_bytes(),
                chunk_parameters,
            )
        },
    },
    Case {
        row: "block-header",
        header: Some("header-checksum"),
        name: "block key tag",
        action: Action::Skip,
        run: || block_header(16, b"IMGCKDL1", b"IMGCKDL2", header_crc),
    },
    Case {
        row: "header-session",
        header: None,
        name: "slot under another generation",
        action: Action::Skip,
        run: || slot_of_a_foreign_session(other_generation),
    },
    Case {
        row: "header-session",
        header: None,
        name: "slot under an earlier epoch",
        action: Action::Skip,
        run: || slot_of_a_foreign_session(earlier_epoch),
    },
    Case {
        row: "header-session",
        header: None,
        name: "block under another generation",
        action: Action::Skip,
        run: || block_of_a_foreign_session(other_generation),
    },
    Case {
        row: "header-session",
        header: None,
        name: "block under an earlier epoch",
        action: Action::Skip,
        run: || block_of_a_foreign_session(earlier_epoch),
    },
    Case {
        row: "unit-0-counts",
        header: None,
        name: "unit 0 entry count above its row count",
        action: Action::Refuse,
        run: || unit_0_counts(8, &60u64.to_le_bytes(), &121u64.to_le_bytes()),
    },
    Case {
        row: "unit-0-counts",
        header: None,
        name: "unit 0 row count of another unit span",
        action: Action::Refuse,
        run: || unit_0_counts(0, &120u64.to_le_bytes(), &124u64.to_le_bytes()),
    },
    Case {
        row: "unit-0-counts",
        header: None,
        name: "unit 0 payload byte 20",
        action: Action::Refuse,
        run: || unit_0_counts(16, &[4, 0, 0, 0, 0, 0, 0, 0], &[4, 0, 0, 0, 1, 0, 0, 0]),
    },
    Case {
        row: "unit-0-counts",
        header: None,
        name: "unit 0 last payload byte",
        action: Action::Refuse,
        run: || unit_0_counts(UNIT_LEN - PAYLOAD - 1, &[0], &[1]),
    },
];

/// Each case of [`CASES`] accepts its untouched image, ends in its exact refusal, reports its declared action, and
/// returns a refusal of the class its table row names, wrapping a header mismatch of the class its header row names.
#[test]
fn every_matrix_case_ends_in_its_declared_refusal_and_action() {
    let rows = rows(TABLE).expect("the table parses");
    for case in CASES {
        eprintln!("case: {}", case.name);
        let observed = (case.run)();
        assert_eq!(
            observed.action, case.action,
            "{}: the observed action",
            case.name
        );
        let class_of = |label| (rows.iter().find(|row| row.label == label)).map(|row| row.class);
        let class = class_of(case.row);
        assert_eq!(
            Some(observed.class),
            class,
            "{}: the class of row {}",
            case.name,
            case.row
        );
        assert_eq!(
            observed.header,
            case.header.and_then(class_of),
            "{}: the class of the wrapped header mismatch",
            case.name
        );
    }
}

/// Each unit of the 60-entry slot left unfed, one at a time, is `Unread` with the `Unreadable` alarm, and the slot
/// loads warm with the entries that have no row on it: the action of row `unit-unread`. The clean decode feeds the
/// four units, and the units the decode reports unread across the sweep are those four, each once.
#[test]
fn a_slot_with_each_unit_unfed_in_turn_skips_that_unit_as_unread() {
    let (entries, units) = slot_image();
    let rows = rows(TABLE).expect("the table parses");
    let row = rows.iter().find(|row| row.label == "unit-unread");
    let action = row.map(|row| row.action);
    accepted(&units, &entries);
    let mut unread: Vec<u32> = Vec::new();
    for unit in 0..units.len() {
        let mut decode = Fed::read_by(units.len(), SESSION);
        for at in (0..units.len()).filter(|&at| at != unit) {
            decode.land(at, &units[at][..]);
        }
        let (damage, load) = damaged(decode.finish());
        unread.extend(&damage.unread);
        let unit = unit as u32;
        assert_eq!(damage.first, UnitDamage::Unread { unit });
        assert_eq!(
            (&damage.failed[..], &damage.unread[..]),
            (&[][..], &[unit][..])
        );
        assert_eq!(damage.alarm(), LoadRefusal::Unreadable, "unit {unit}");
        let observed = slot_action(&damage, load, &entries);
        assert_eq!(observed, Action::Skip, "unit {unit}: the slot loads warm");
        assert_eq!(Some(observed.word()), action, "unit {unit}");
    }
    assert_eq!(
        unread,
        [0, 1, 2, 3],
        "the decode reports each unit of the clean decode unread once"
    );
}

/// Each label function has one arm per variant, and each arm that returns a class label has a row of that class whose
/// damage cell names the arm's variant as a word, so a swap of two labels inside one function fails here. Each header
/// mismatch has exactly one `header-` row naming it, and that row's class is the arm's label. The check reads the
/// declared arms and the table text, and a bare word counts: a row that names a same-named variant of another refusal
/// type, or names it as a wrapper's outcome, also satisfies an arm, and an arm's choice of [`OUTSIDE`] stays with
/// review.
#[test]
fn each_labeled_variant_is_named_by_a_row_of_its_class() {
    for list in LISTS {
        let mut variants: Vec<&str> = list.iter().map(|&(variant, _)| variant).collect();
        variants.sort_unstable();
        let count = variants.len();
        variants.dedup();
        assert_eq!(variants.len(), count, "one arm per variant in {list:?}");
    }
    let rows = rows(TABLE).expect("the table parses");
    let names = |row: &Row, variant: &str| {
        (row.damage.split(|c: char| !c.is_ascii_alphanumeric())).any(|word| word == variant)
    };
    for (variant, label) in arms().filter(|&(_, label)| label != OUTSIDE) {
        assert!(
            rows.iter()
                .any(|row| row.class == label && names(row, variant)),
            "a row of class {label} names {variant}"
        );
    }
    for &(variant, label) in HEADER.all {
        let named: Vec<&Row> = (rows.iter())
            .filter(|row| row.label.starts_with("header-") && names(row, variant))
            .collect();
        assert_eq!(named.len(), 1, "one header row names {variant}");
        assert_eq!(named[0].class, label, "{variant}");
    }
}

/// Runs `tamper` on a copy of a unit and returns the panic message and whether the copy kept every byte.
fn tamper_refusal(at: usize, old: &[u8], new: &[u8]) -> (String, bool) {
    let (_, units) = slot_image();
    let mut copy = units[1].to_vec();
    let panic = catch_unwind(AssertUnwindSafe(|| tamper(&mut copy, at, old, new)))
        .expect_err("the tamper panics");
    let message = (panic.downcast_ref::<String>().cloned()).expect("a formatted panic message");
    (message, copy == units[1][..])
}

/// The magic tamper one byte off its offset finds bytes other than its pre-image, panics at the pre-image assertion and
/// leaves every byte as it was.
#[test]
fn a_tamper_whose_pre_image_differs_panics_before_it_writes() {
    let (message, unchanged) = tamper_refusal(1, b"IMGCREC1", b"IMGCREC0");
    assert_eq!(message.lines().next(), Some(PRE_IMAGE), "{message}");
    assert!(unchanged, "the bytes are unchanged");
}

/// A tamper whose new bytes equal its pre-image would pass while changing nothing, and one whose new bytes are shorter
/// or longer would leave or overwrite bytes past the pre-image: each panics at its change assertion and leaves every
/// byte as it was. The shorter and longer values differ from the unit at byte 0, so a write before the assertion shows.
#[test]
fn a_tamper_that_would_write_its_pre_image_panics_before_it_writes() {
    for new in [&b"IMGCREC1"[..], b"XMGCREC", b"XMGCREC1X"] {
        let (message, unchanged) = tamper_refusal(0, b"IMGCREC1", new);
        assert_eq!(message.lines().next(), Some(WRITES_A_CHANGE), "{message}");
        assert!(unchanged, "{new:?}: the bytes are unchanged");
    }
}

/// The recovery module's source, whose documentation holds the table.
const TABLE: &str = include_str!("mod.rs");

/// The table's header line, above [`SEPARATOR_LINE`] and the rows.
const HEADER_LINE: &str =
    "//! | Row | Unit and reader | Damage and outcome | Class | Action | Tests |";

const SEPARATOR_LINE: &str = "//! |---|---|---|---|---|---|";

/// The modules whose tests the table cites, by their path under `storage`, each with its source.
const SOURCES: &[(&str, &str)] = &[
    ("recovery::capture_tests", include_str!("capture_tests.rs")),
    (
        "recovery::checkpoint_tests",
        include_str!("checkpoint_tests.rs"),
    ),
    (
        "recovery::corruption_tests",
        include_str!("corruption_tests.rs"),
    ),
    (
        "recovery::delta_replay_tests",
        include_str!("delta_replay_tests.rs"),
    ),
    ("recovery::delta_tests", include_str!("delta_tests.rs")),
    (
        "recovery::load_guard_tests",
        include_str!("load_guard_tests.rs"),
    ),
    ("recovery::root_tests", include_str!("root_tests.rs")),
    (
        "recovery::stored_generation_tests",
        include_str!("stored_generation_tests.rs"),
    ),
    (
        "record::header_tests",
        include_str!("../record/header_tests.rs"),
    ),
    ("checkpoint::tests", include_str!("../checkpoint_tests.rs")),
    (
        "volume::activation_tests",
        include_str!("../volume/activation_tests.rs"),
    ),
    (
        "volume::bootstrap_tests",
        include_str!("../volume/bootstrap_tests.rs"),
    ),
    (
        "volume::warm::read_tests",
        include_str!("../volume/warm_read_tests.rs"),
    ),
    (
        "volume::warm::tests",
        include_str!("../volume/warm_tests.rs"),
    ),
];

/// The labels of the rows whose class has no typed refusal: the table holds a `none` row for each, and each `none`
/// row carries one of them.
const NO_REFUSAL: &[&str] = &[
    "root-below-session",
    "slot-repeat",
    "suffix-damage",
    "suffix-tail",
    "suffix-dropped",
];

/// The rows each of which needs a case in [`CASES`].
const GAP_ROWS: [&str; 4] = [
    "unit-header",
    "unit-0-counts",
    "block-header",
    "header-session",
];

const MISSING_LABEL: &str = "missing label";
const UNKNOWN_LABEL: &str = "unknown label";
const MISSING_TEST: &str = "missing test";
const IGNORED_TEST: &str = "ignored test";
const UNKNOWN_ACTION: &str = "unknown action";
const CASE_ACTION: &str = "case action";
const GAP_WITHOUT_CASE: &str = "gap row without a case";
const UNPARSEABLE: &str = "unparseable table";

/// One parsed row of the table.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Row<'a> {
    label: &'a str,
    damage: &'a str,
    class: &'a str,
    action: &'a str,
    tests: Vec<&'a str>,
}

/// The text inside one pair of backticks.
fn ticked(cell: &str) -> Option<&str> {
    let inner = cell.strip_prefix('`')?.strip_suffix('`')?;
    (!inner.is_empty() && !inner.contains('`')).then_some(inner)
}

/// The row a table line holds, when it has six cells and its label, its class and each of its tests is one backticked
/// word, or its class is `none`.
fn parsed(line: &str) -> Option<Row<'_>> {
    let cells: Vec<&str> = line
        .strip_prefix("//! |")?
        .split('|')
        .map(str::trim)
        .collect();
    let [label, _, damage, class, action, tests, ""] = cells[..] else {
        return None;
    };
    let tests = match tests {
        "" => Vec::new(),
        tests => tests.split(", ").map(ticked).collect::<Option<_>>()?,
    };
    let class = if class == "none" {
        class
    } else {
        ticked(class)?
    };
    Some(Row {
        label: ticked(label)?,
        damage,
        class,
        action,
        tests,
    })
}

/// A doc line that holds text, with any whitespace before `//!`: a line of the table until the first other line.
fn in_table(line: &str) -> bool {
    (line.trim_start().strip_prefix("//!")).is_some_and(|text| !text.trim().is_empty())
}

/// A doc line whose text starts with `|`, with any whitespace before `//!` or `|`: a row wherever it stands.
fn table_line(line: &str) -> bool {
    (line.trim_start().strip_prefix("//!")).is_some_and(|text| text.trim_start().starts_with('|'))
}

/// The rows of the table in `source`: the [`in_table`] lines after [`HEADER_LINE`] and [`SEPARATOR_LINE`].
///
/// # Errors
///
/// [`UNPARSEABLE`] when the header or the separator is absent, a line of the table does not start with exactly
/// `//! |` or has other than six cells, its label, its class or a test is other than one backticked word and the class
/// other than `none`, two rows share a label, or a [`table_line`] follows the table's end.
fn rows(source: &str) -> Result<Vec<Row<'_>>, String> {
    let mut lines = source.lines().skip_while(|&line| line != HEADER_LINE);
    if lines.next().is_none() || lines.next() != Some(SEPARATOR_LINE) {
        return Err(format!(
            "{UNPARSEABLE}: no lines {HEADER_LINE:?} and {SEPARATOR_LINE:?}"
        ));
    }
    let mut rows: Vec<Row> = Vec::new();
    for line in lines.by_ref().take_while(|&line| in_table(line)) {
        let Some(row) = parsed(line) else {
            return Err(format!("{UNPARSEABLE}: {line:?}"));
        };
        if rows.iter().any(|earlier| earlier.label == row.label) {
            return Err(format!("{UNPARSEABLE}: row {} repeats", row.label));
        }
        rows.push(row);
    }
    match lines.find(|&line| table_line(line)) {
        Some(line) => Err(format!("{UNPARSEABLE}: {line:?} follows the table")),
        None => Ok(rows),
    }
}

/// `uncommented` replaces each non-newline character in nested and top-level block comments with a space, preserving
/// line numbers. A `//` comment runs to its line's end, and a delimiter inside a string literal counts as a delimiter.
fn uncommented(source: &str) -> String {
    let (mut text, mut depth) = (String::with_capacity(source.len()), 0usize);
    let mut chars = source.chars().peekable();
    while let Some(char) = chars.next() {
        match (char, chars.peek().copied()) {
            ('/', Some('*')) => {
                chars.next();
                depth += 1;
                text.push_str("  ");
            }
            ('*', Some('/')) if depth > 0 => {
                chars.next();
                depth -= 1;
                text.push_str("  ");
            }
            ('/', Some('/')) if depth == 0 => {
                text.push(char);
                while let Some(next) = chars.next_if(|&next| next != '\n') {
                    text.push(next);
                }
            }
            ('\n', _) => text.push('\n'),
            (_, _) if depth > 0 => text.push(' '),
            (char, _) => text.push(char),
        }
    }
    text
}

/// `runs` checks the attribute rule for the function named by the `storage` path `test` in its module's source in
/// `sources`, each source with its block comments already blanked by [`uncommented`]. The rule: the line above the
/// function is `#[test]`, and the scan above `#[test]` cuts each line at its first `//` and skips the lines left
/// blank. If a line remains, its trimmed code must end in `}` or `;`. A `#[` prefix on that code also fails the rule.
/// After the declaration, the scan runs until a line equals `}` or the source ends, and the rule fails on any scanned
/// line whose first non-whitespace characters are `#![`. Matches include an inner attribute of the body, such as
/// `ignore` or `cfg`, a line of a multi-line string literal, and a line of a later item when the function's closing
/// `}` shares its line with other text.
///
/// # Errors
///
/// [`MISSING_TEST`] for an unqualified `test`, an unlisted module, or a function absent from the module's source;
/// [`IGNORED_TEST`] when the function fails the attribute rule.
fn runs(test: &str, sources: &[(&str, String)]) -> Result<(), String> {
    let missing = || format!("{MISSING_TEST}: {test}");
    let (module, name) = test.rsplit_once("::").ok_or_else(missing)?;
    let (_, source) = (sources.iter().find(|(path, _)| *path == module)).ok_or_else(missing)?;
    let lines: Vec<&str> = source.lines().collect();
    let declares = |line: &&str| {
        let rest = line
            .strip_prefix("fn ")
            .and_then(|rest| rest.strip_prefix(name));
        rest.is_some_and(|rest| rest.starts_with('('))
    };
    let at = lines.iter().position(declares).ok_or_else(missing)?;
    fn code(line: &str) -> &str {
        line.split("//").next().unwrap_or_default().trim()
    }
    let ends_an_item =
        |line: &str| !line.starts_with("#[") && (line.ends_with('}') || line.ends_with(';'));
    let tested = lines[..at]
        .split_last()
        .is_some_and(|(&attribute, before)| {
            let lead_in = before
                .iter()
                .rev()
                .map(|line| code(line))
                .find(|line| !line.is_empty());
            attribute == "#[test]" && lead_in.is_none_or(ends_an_item)
        });
    let mut body = lines[at + 1..].iter().take_while(|&&line| line != "}");
    let inner = body.any(|line| line.trim_start().starts_with("#!["));
    (tested && !inner)
        .then_some(())
        .ok_or_else(|| format!("{IGNORED_TEST}: {test}"))
}

/// Checks the table in `table` against the class labels `labels`, the test sources `sources` and the matrix `cases`,
/// each a row label with its declared action.
///
/// For each cited test, [`runs`] checks the function's attribute lines in the source that [`SOURCES`] pairs with the
/// test's module path. Review covers attributes that a macro or the module's own attributes add, a comment delimiter
/// inside a string literal, a `//` inside a string literal on the code line above `#[test]`, which cuts that line, so
/// the rule accepts the test only when the cut text ends in `}` or `;` and does not start with `#[`, a test-shaped declaration inside a multi-line string literal, which counts as a function, whether each
/// listed module's `mod` line is built, the pairs in [`SOURCES`], and whether each cited test's body asserts its row's
/// refusal.
///
/// # Errors
///
/// The first failure, named by its constant: [`UNPARSEABLE`]; then per row [`UNKNOWN_ACTION`], [`UNKNOWN_LABEL`] for
/// a class no label function returns or a `none` class outside [`NO_REFUSAL`], [`MISSING_TEST`] and [`IGNORED_TEST`];
/// then [`MISSING_LABEL`] for a class label no row names or a label of [`NO_REFUSAL`] that no `none` row carries; then
/// [`CASE_ACTION`] for a case whose row is absent or carries another action; then [`GAP_WITHOUT_CASE`] for a row of
/// [`GAP_ROWS`] that no case names.
fn check(
    table: &str,
    labels: &[&str],
    sources: &[(&str, &str)],
    cases: &[(&str, Action)],
) -> Result<(), String> {
    let rows = rows(table)?;
    let sources: Vec<(&str, String)> = (sources.iter())
        .map(|&(module, source)| (module, uncommented(source)))
        .collect();
    for row in &rows {
        let label = row.label;
        if ![Action::Recover, Action::Skip, Action::Refuse]
            .map(Action::word)
            .contains(&row.action)
        {
            return Err(format!(
                "{UNKNOWN_ACTION}: row {label} has {:?}",
                row.action
            ));
        }
        let declared = match row.class {
            "none" => NO_REFUSAL.contains(&label),
            class => labels.contains(&class),
        };
        if !declared {
            return Err(format!("{UNKNOWN_LABEL}: row {label} names {}", row.class));
        }
        if row.tests.is_empty() {
            return Err(format!("{MISSING_TEST}: row {label} cites no test"));
        }
        for test in &row.tests {
            runs(test, &sources).map_err(|error| format!("{error} in row {label}"))?;
        }
    }
    if let Some(label) = (labels.iter()).find(|&&label| !rows.iter().any(|row| row.class == label))
    {
        return Err(format!("{MISSING_LABEL}: no row names {label}"));
    }
    let untyped = |label: &str| (rows.iter()).any(|row| row.label == label && row.class == "none");
    if let Some(label) = NO_REFUSAL.iter().find(|&&label| !untyped(label)) {
        return Err(format!("{MISSING_LABEL}: no `none` row is {label}"));
    }
    for &(case, action) in cases {
        match rows.iter().find(|row| row.label == case) {
            Some(row) if row.action == action.word() => {}
            row => {
                let tabled = row.map(|row| row.action);
                return Err(format!(
                    "{CASE_ACTION}: {case} declares {action:?}, its row {tabled:?}"
                ));
            }
        }
    }
    match GAP_ROWS
        .iter()
        .find(|&&gap| !cases.iter().any(|&(case, _)| case == gap))
    {
        Some(gap) => Err(format!("{GAP_WITHOUT_CASE}: {gap}")),
        None => Ok(()),
    }
}

/// The row label and declared action of each case of [`CASES`].
fn declared() -> Vec<(&'static str, Action)> {
    CASES.iter().map(|case| (case.row, case.action)).collect()
}

/// The table names every class label the label functions return and holds a `none` row for each label of
/// [`NO_REFUSAL`], each row's class is one of those class labels or a declared `none`, cites `#[test]` functions of
/// the listed sources and carries one of the three actions, and the matrix agrees with it.
#[test]
fn every_corruption_class_has_a_row_and_a_running_test() {
    check(TABLE, &class_labels(), SOURCES, &declared()).unwrap();
}

/// The check reports the error listed for each planted defect:
///
/// - `MISSING_TEST`: extended, unqualified, uncited, unlisted, or commented-out tests.
/// - `IGNORED_TEST`:
///   - `ignore` below `#[test]`.
///   - `ignore` above `#[test]`: alone, wrapped, above the doc comment, or above a blank line.
///   - `ignore` above `#[test]`, single-line or wrapped, followed by a comment ending in `;`.
///   - Inner `ignore` on the body's first line or below a wrapped signature.
/// - `MISSING_LABEL`: the dropped row of a class label, each dropped `none` row, or a `none` row given a typed class.
/// - `UNKNOWN_LABEL`: an unknown class or an undeclared `none`.
/// - `UNKNOWN_ACTION`: the action `ignore`.
/// - `CASE_ACTION`: a changed or absent case row.
/// - `GAP_WITHOUT_CASE`: a dropped gap case.
/// - `UNPARSEABLE`: a short or repeated row, a missing separator, a row after the table's end, a class without
///   backticks, or a last row with a mistyped prefix.
///
/// The check passes a line comment, a nested block comment, or a `const` item with a trailing comment above
/// `#[test]`, and an inner attribute in a later function's body.
#[test]
fn the_table_check_refuses_each_planted_table_defect() {
    /// [`SOURCES`] with `source` in place of the checkpoint tests.
    fn with(source: &str) -> Vec<(&str, &str)> {
        let mut sources = SOURCES.to_vec();
        sources.retain(|(module, _)| *module != "recovery::checkpoint_tests");
        sources.push(("recovery::checkpoint_tests", source));
        sources
    }
    let row = |label: &str| {
        let start = format!("//! | `{label}` |");
        (TABLE.lines())
            .find(|line| line.starts_with(&start))
            .unwrap()
    };
    let labels = class_labels();
    let cases = declared();
    let refuses = |name: &str, table: &str, sources: &[(&str, &str)], cases: &[(&str, Action)]| {
        let refusal = check(table, &labels, sources, cases).expect_err(name);
        assert!(refusal.starts_with(name), "{name}: {refusal}");
    };
    let (session_row, unit_header) = (row("header-session"), row("unit-header"));

    let cited = "fn a_unit_of_another_checkpoint_fails_its_identity(";
    let source = include_str!("checkpoint_tests.rs");
    assert!(source.contains(cited));
    let extended = source.replace(
        cited,
        "fn a_unit_of_another_checkpoint_fails_its_identity_twice(",
    );
    refuses(MISSING_TEST, TABLE, &with(&extended), &cases);
    let citation = "`recovery::checkpoint_tests::a_unit_of_another_checkpoint_fails_its_identity`";
    assert!(unit_header.contains(citation));
    let unqualified = unit_header.replace(
        citation,
        "`a_unit_of_another_checkpoint_fails_its_identity`",
    );
    refuses(
        MISSING_TEST,
        &TABLE.replace(unit_header, &unqualified),
        SOURCES,
        &cases,
    );
    let (before_tests, _) = unit_header.rsplit_once("| `").unwrap();
    refuses(
        MISSING_TEST,
        &TABLE.replace(unit_header, &format!("{before_tests}| |")),
        SOURCES,
        &cases,
    );
    let unlisted = unit_header.replace("recovery::checkpoint_tests::", "recovery::nowhere::");
    refuses(
        MISSING_TEST,
        &TABLE.replace(unit_header, &unlisted),
        SOURCES,
        &cases,
    );
    let test_at = source.find(&format!("#[test]\n{cited}")).unwrap();
    let test_end = test_at + 1 + source[test_at + 1..].find("\n#[test]").unwrap();
    let (open, close) = (concat!("/", "*"), concat!("*", "/"));
    let commented = format!(
        "{}{open} {open} {close}\n{}{close}\n{}",
        &source[..test_at],
        &source[test_at..test_end],
        &source[test_end..]
    );
    refuses(MISSING_TEST, TABLE, &with(&commented), &cases);

    let layouts = [
        "#[test]\n#[ignore = \"reason\"]\n",
        "#[ignore = \"reason\"]\n#[test]\n",
        "#[cfg_attr(\n    miri,\n    ignore = \"reason\"\n)]\n#[test]\n",
        "#[ignore = \"reason\"]\n/// A doc line.\n#[test]\n",
        "#[ignore = \"reason\"]\n\n#[test]\n",
        "#[cfg_attr(\n    miri,\n    ignore = \"reason\"\n)] // wrapped;\n#[test]\n",
        "#[ignore = \"reason\"] // disabled;\n#[test]\n",
    ];
    for layout in layouts {
        let ignored = source.replace(&format!("#[test]\n{cited}"), &format!("{layout}{cited}"));
        refuses(IGNORED_TEST, TABLE, &with(&ignored), &cases);
    }
    for lead_in in [
        format!("// {open} a line comment\n"),
        format!("{open} {open} {close} {close}\n"),
        "const NOTE: u8 = 0; // note\n".to_string(),
    ] {
        let kept = source.replace(
            &format!("#[test]\n{cited}"),
            &format!("{lead_in}#[test]\n{cited}"),
        );
        check(TABLE, &labels, &with(&kept), &cases).expect(&lead_in);
    }
    let opening = (source[source.find(cited).unwrap()..].lines().next()).unwrap();
    assert!(source.contains(&format!("{opening}\n    let crc")));
    let wrapped = opening.replace("() ", "()\n-> () ");
    assert_ne!(wrapped, opening);
    for signature in [opening, &wrapped] {
        let ignored = source.replace(
            opening,
            &format!("{signature}\n    #![ignore = \"reason\"]"),
        );
        refuses(IGNORED_TEST, TABLE, &with(&ignored), &cases);
    }
    let later = format!("{source}\nfn later() {{\n    #![allow(unused)]\n}}\n");
    check(TABLE, &labels, &with(&later), &cases).expect("an inner attribute of a later function");

    let without_session = TABLE.replace(&format!("{session_row}\n"), "");
    refuses(MISSING_LABEL, &without_session, SOURCES, &cases);
    for &label in NO_REFUSAL {
        let dropped = TABLE.replace(&format!("{}\n", row(label)), "");
        refuses(MISSING_LABEL, &dropped, SOURCES, &cases);
    }
    let tail_row = row("suffix-tail");
    let typed = tail_row.replace("| none | recover |", "| `block-header` | recover |");
    assert_ne!(typed, tail_row);
    refuses(
        MISSING_LABEL,
        &TABLE.replace(tail_row, &typed),
        SOURCES,
        &cases,
    );

    let unknown = format!(
        "{session_row}\n//! | `unit-torn` | unit | a torn unit | `unit-torn` | skip | `recovery::checkpoint_tests::a_torn_unit_loses_only_the_entries_with_a_row_on_it` |"
    );
    refuses(
        UNKNOWN_LABEL,
        &TABLE.replace(session_row, &unknown),
        SOURCES,
        &cases,
    );
    let undeclared = unit_header.replace("| `unit-header` | skip |", "| none | skip |");
    refuses(
        UNKNOWN_LABEL,
        &TABLE.replace(unit_header, &undeclared),
        SOURCES,
        &cases,
    );

    let ignore = unit_header.replace("| skip |", "| ignore |");
    refuses(
        UNKNOWN_ACTION,
        &TABLE.replace(unit_header, &ignore),
        SOURCES,
        &cases,
    );

    let refuse = unit_header.replace("| skip |", "| refuse |");
    refuses(
        CASE_ACTION,
        &TABLE.replace(unit_header, &refuse),
        SOURCES,
        &cases,
    );
    let absent = [cases.as_slice(), &[("unit-torn", Action::Skip)]].concat();
    refuses(CASE_ACTION, TABLE, SOURCES, &absent);

    let no_gap: Vec<(&str, Action)> = (cases.iter().copied())
        .filter(|&(case, _)| case != "unit-0-counts")
        .collect();
    refuses(GAP_WITHOUT_CASE, TABLE, SOURCES, &no_gap);

    let torn = format!("{session_row}\n//! | `header-torn` | unit |");
    refuses(
        UNPARSEABLE,
        &TABLE.replace(session_row, &torn),
        SOURCES,
        &cases,
    );
    let twice = format!("{session_row}\n{session_row}");
    refuses(
        UNPARSEABLE,
        &TABLE.replace(session_row, &twice),
        SOURCES,
        &cases,
    );
    let unseparated = TABLE.replace(&format!("{SEPARATOR_LINE}\n"), "");
    refuses(UNPARSEABLE, &unseparated, SOURCES, &cases);
    let unticked = unit_header.replace("| `unit-header` | skip |", "| unit-header | skip |");
    refuses(
        UNPARSEABLE,
        &TABLE.replace(unit_header, &unticked),
        SOURCES,
        &cases,
    );
    let last_row = (TABLE.lines())
        .rfind(|line| line.starts_with("//! | `"))
        .unwrap();
    for prefix in ["//!|", "//!  |", " //! |", "//!"] {
        let mistyped = last_row.replacen("//! |", prefix, 1);
        refuses(
            UNPARSEABLE,
            &TABLE.replace(last_row, &mistyped),
            SOURCES,
            &cases,
        );
    }
    for stray_prefix in ["//! |", "//!|"] {
        let stray = format!("{last_row}\n//!\n{stray_prefix} `header-torn` | unit |");
        refuses(
            UNPARSEABLE,
            &TABLE.replace(last_row, &stray),
            SOURCES,
            &cases,
        );
    }
}
