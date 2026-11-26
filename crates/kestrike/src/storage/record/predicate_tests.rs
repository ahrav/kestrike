//! The read predicate over seeded identities: one flipped bit in the key, allocation word, session or cache version refuses, a reader of another generation or an earlier epoch refuses, and at the generation and epoch limits the reader's own epoch is admitted while zero, odd and later epochs are refused.

use super::super::seeded::SplitMix64;
use super::{RecordIdentity, admits};

fn session(generation: u64, epoch: u64) -> u64 {
    (generation << 32) | epoch
}

pub(super) fn named(rng: &mut SplitMix64) -> (u64, RecordIdentity) {
    let generation = rng.below(u64::from(u32::MAX));
    let reader_epoch = 2 + 2 * rng.below(u64::from(u32::MAX / 2 - 1));
    let epoch = 2 + 2 * rng.below(reader_epoch / 2);
    let mut key = [0; 32];
    for byte in &mut key {
        *byte = rng.next_u64() as u8;
    }
    let identity = RecordIdentity {
        key,
        allocation: rng.next_u64(),
        session: session(generation, epoch),
        version: rng.next_u64(),
    };
    (session(generation, reader_epoch), identity)
}

#[test]
fn read_predicate_rejects_foreign_triple() {
    let mut rng = SplitMix64::new(0x1284);
    for case in 0..4096 {
        let (reader, entry) = named(&mut rng);
        assert!(admits(&entry, &entry, reader), "case {case}");
        let mut key = entry.key;
        key[rng.below(32) as usize] ^= 1 << rng.below(8);
        let flip = 1 << rng.below(64);
        let found = [
            RecordIdentity { key, ..entry },
            RecordIdentity {
                allocation: entry.allocation ^ flip,
                ..entry
            },
            RecordIdentity {
                session: entry.session ^ flip,
                ..entry
            },
            RecordIdentity {
                version: entry.version ^ flip,
                ..entry
            },
        ];
        for (field, found) in found.iter().enumerate() {
            assert!(!admits(found, &entry, reader), "case {case} field {field}");
        }
        let epoch = entry.session & 0xFFFF_FFFF;
        let foreign = reader ^ (1 << (32 + rng.below(32)));
        let earlier = session(reader >> 32, epoch - 2);
        for reader in [foreign, earlier] {
            assert!(
                !admits(&entry, &entry, reader),
                "case {case} reader {reader:#x}"
            );
        }
    }
}

#[test]
fn read_predicate_holds_at_its_epoch_and_generation_bounds() {
    for generation in [0, 1, u64::from(u32::MAX - 1), u64::from(u32::MAX)] {
        for reader_epoch in [2, 4, u64::from(u32::MAX - 1)] {
            let reader = session(generation, reader_epoch);
            let entry = |epoch: u64| RecordIdentity {
                key: [7; 32],
                allocation: 1 << 32 | 1,
                session: session(generation, epoch),
                version: 3,
            };
            let at = entry(reader_epoch);
            assert!(admits(&at, &at, reader), "{generation} {reader_epoch}");
            let above =
                [reader_epoch + 1, reader_epoch + 2].map(|epoch| epoch.min(u64::from(u32::MAX)));
            for epoch in [0, reader_epoch - 1].into_iter().chain(above) {
                let refused = entry(epoch);
                assert!(
                    !admits(&refused, &refused, reader),
                    "{generation} {reader_epoch} {epoch}"
                );
            }
        }
    }
}
