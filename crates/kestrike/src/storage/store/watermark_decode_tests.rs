//! `Watermark::decode` refuses nonzero header padding and a kind byte outside its values with `Flag`, and two slots of one key or an adopted checkpoint at generation zero with `Field`, each on an otherwise valid 64-slot file with the digest over the changed bytes resealed: the header's for padding, the slot's for a mark.

use sha2::{Digest, Sha256};

use super::{ENTRY, Entry, FREE, HEAD_BODY, MIN_SLOTS, Mark, SLOT, Watermark, sealed};
use crate::failover::records::{CodecError, NamedCheckpoint};
use crate::net::ownership::{Shard, ShardGeneration};
use crate::storage::store::Version;

/// The header's bytes before its padding: the magic, the format version and the slot count.
const HEAD_FIELDS: usize = 4 + 2 + 4;
/// The entry's offset of the adopted checkpoint's generation, its last four bytes.
const GENERATION: usize = ENTRY - 4;
/// The marks the valid file holds, which fill its first slots in key order: two shard records, the first with an adopted checkpoint, then a page.
const MARKS: usize = 3;

/// A watermark of [`MARKS`] marks and its encoding, a 64-slot file that decodes to it.
fn valid() -> (Watermark, Vec<u8>) {
    let shard = |n| Shard::new(n).unwrap();
    let mark = |version, value, adopted| Mark {
        version: Version::new(version).unwrap(),
        value,
        adopted,
    };
    let named = NamedCheckpoint {
        slot: 1,
        session: (3 << 32) | 2,
        capture: 1,
        units: 4,
    };
    let adopted = Some((ShardGeneration::new(5).unwrap(), named));
    let mut watermark = Watermark::default();
    watermark
        .marks
        .insert(Entry::Shard(shard(1)), mark(7, (5, 2), adopted));
    watermark
        .marks
        .insert(Entry::Shard(shard(2)), mark(3, (1, 1), None));
    watermark
        .marks
        .insert(Entry::Page(shard(1), 4), mark(9, (6, 0), None));
    assert_eq!(watermark.marks.len(), MARKS);
    let file = watermark.encode();
    assert_eq!(file.len(), SLOT * (1 + MIN_SLOTS));
    assert_eq!(MIN_SLOTS, 64);
    assert_eq!(Watermark::decode(&file).as_ref(), Ok(&watermark));
    (watermark, file)
}

/// `file` with its header digest recomputed over its header body.
fn resealed_header(mut file: Vec<u8>) -> Vec<u8> {
    let digest = Sha256::digest(&file[..HEAD_BODY]);
    file[HEAD_BODY..SLOT].copy_from_slice(&digest);
    file
}

/// `file` with the slot at `index` holding `entry` under a digest of that index and those bytes.
fn with_slot(mut file: Vec<u8>, index: usize, entry: &[u8]) -> Vec<u8> {
    file[SLOT * (1 + index)..][..SLOT].copy_from_slice(&sealed(index, entry));
    file
}

/// The entry bytes of the slot at `index` of `file`.
fn entry(file: &[u8], index: usize) -> Vec<u8> {
    file[SLOT * (1 + index)..][..ENTRY].to_vec()
}

/// Each header padding byte, set to each of several nonzero values under a resealed header digest, is refused with `Flag`; resealing the unchanged header still decodes.
#[test]
fn nonzero_header_padding_under_a_resealed_digest_is_refused_with_flag() {
    let (watermark, file) = valid();
    assert_eq!(
        Watermark::decode(&resealed_header(file.clone())).as_ref(),
        Ok(&watermark)
    );
    assert!(file[HEAD_FIELDS..HEAD_BODY].iter().all(|&byte| byte == 0));
    for at in HEAD_FIELDS..HEAD_BODY {
        for value in [1, 0x80, 0xFF] {
            let mut padded = file.clone();
            padded[at] = value;
            assert_eq!(
                Watermark::decode(&resealed_header(padded)),
                Err(CodecError::Flag),
                "padding byte {at} = {value:#x}"
            );
        }
    }
}

/// A mark whose kind byte is neither a shard's 0, a page's 1 nor the free marker, under a resealed slot digest, is refused with `Flag`, in a shard's slot and in a page's.
#[test]
fn a_kind_byte_outside_its_values_under_a_resealed_digest_is_refused_with_flag() {
    let (watermark, file) = valid();
    for index in 0..MARKS {
        let held = entry(&file, index);
        assert_eq!(
            Watermark::decode(&with_slot(file.clone(), index, &held)).as_ref(),
            Ok(&watermark),
            "resealing slot {index} unchanged"
        );
        for kind in [2, 3, 0x7F, 0x80, FREE - 1] {
            let mut bad = held.clone();
            bad[0] = kind;
            assert_eq!(
                Watermark::decode(&with_slot(file.clone(), index, &bad)),
                Err(CodecError::Flag),
                "slot {index} kind {kind:#x}"
            );
        }
    }
}

/// A second slot of a key the file already holds, sealed at its own index, is refused with `Field`: in the first free slot, and in place of another mark, with the same mark or another version.
#[test]
fn two_slots_of_one_key_under_resealed_digests_are_refused_with_field() {
    let (_, file) = valid();
    assert_eq!(entry(&file, MARKS)[0], FREE, "the first free slot");
    for from in 0..MARKS {
        let held = entry(&file, from);
        let mut raised = held.clone();
        // The version's low byte: the same key at another version.
        raised[1 + 4 + 2 + 7] ^= 0x10;
        for to in (0..=MARKS).filter(|to| *to != from) {
            for repeat in [&held, &raised] {
                assert_eq!(
                    Watermark::decode(&with_slot(file.clone(), to, repeat)),
                    Err(CodecError::Field),
                    "the key of slot {from} repeated in slot {to}"
                );
            }
        }
    }
}

/// A shard mark that names an adopted checkpoint at generation zero, under a resealed slot digest, is refused with `Field`.
#[test]
fn an_adopted_checkpoint_at_generation_zero_under_a_resealed_digest_is_refused_with_field() {
    let (watermark, file) = valid();
    let held = entry(&file, 0);
    assert_eq!(held[GENERATION..], 5u32.to_be_bytes(), "the generation");
    let mut later = held.clone();
    later[GENERATION..].copy_from_slice(&6u32.to_be_bytes());
    let decoded = Watermark::decode(&with_slot(file.clone(), 0, &later)).unwrap();
    assert_ne!(decoded, watermark, "the bytes are the generation's");
    let mut zero = held;
    zero[GENERATION..].fill(0);
    assert_eq!(
        Watermark::decode(&with_slot(file, 0, &zero)),
        Err(CodecError::Field)
    );
}
