use super::*;
use crate::storage::store_tests::record;

fn lost(record: &ShardRecord) -> (VolumeId, Health) {
    (record.active, Health::Lost)
}

fn next_of(record: &ShardRecord) -> Request {
    Request {
        namespace: record.namespace,
        shard: record.shard,
        generation: ShardGeneration::new(record.generation.get() + 1).unwrap(),
    }
}

/// An impaired volume is retained at any AZ count. Loss evidence about a volume a flip already displaced retains the
/// shard, so a restarted reconciler holding that evidence never provisions a second replacement. A permanent loss
/// alone in its AZ provisions the next generation; a loss beside another impaired or lost volume holds for that
/// replacement, and a loss at the last generation holds with none.
#[test]
fn only_an_isolated_permanent_loss_provisions_and_correlated_impairment_holds() {
    let held = record();
    for others in [0, 1, 4] {
        for health in [Health::Available, Health::Impaired] {
            assert_eq!(
                decide(&held, (held.active, health), others),
                Decision::Retain
            );
        }
        let displaced = VolumeId::new("vol-0f").unwrap();
        assert_eq!(
            decide(&held, (displaced, Health::Lost), others),
            Decision::Retain
        );
    }
    assert_eq!(
        decide(&held, lost(&held), 0),
        Decision::Provision(next_of(&held))
    );
    assert_eq!(
        decide(&held, lost(&held), 1),
        Decision::Hold(Some(next_of(&held)))
    );
    let at = |g: u32| ShardRecord {
        generation: ShardGeneration::new(u64::from(g)).unwrap(),
        ..held
    };
    let before_last = at(u32::MAX - 2);
    assert_eq!(
        decide(&before_last, lost(&before_last), 0),
        Decision::Provision(next_of(&before_last))
    );
    for last in [at(u32::MAX - 1), at(u32::MAX)] {
        assert_eq!(decide(&last, lost(&last), 0), Decision::Hold(None));
    }
}

pub(crate) fn receipt() -> Receipt {
    Receipt {
        request: next_of(&record()),
        layout: crate::failover::sim::layout(),
        attempt: 1,
        phase: Phase::Open,
        held: false,
        released: false,
    }
}

fn created(volume: &str) -> Phase {
    Phase::Created(VolumeId::new(volume).unwrap())
}

/// The token binds one create attempt of one replacement: each other namespace, shard, generation or attempt yields
/// another token, each 59 ASCII bytes, and the phase and the release leave it, so a retry after a lost response
/// repeats the request the provider deduplicates.
#[test]
fn the_provisioning_token_is_specific_to_its_generation_and_attempt() {
    let base = receipt();
    let request = base.request;
    assert_eq!(
        base.token(),
        "73696d756c617465642d73746f726531-00000007-00000004-00000001",
        "the namespace `simulated-store1`, shard 7, generation 4 and attempt 1 in lowercase hex"
    );
    for (phase, held) in [
        (Phase::Open, true),
        (Phase::Issued, false),
        (created("vol-0c"), false),
    ] {
        let same = Receipt {
            phase,
            held,
            released: !held,
            ..base.clone()
        };
        assert_eq!(same.token(), base.token());
    }
    let others = [
        Receipt {
            attempt: 2,
            ..base.clone()
        },
        Receipt {
            request: Request {
                generation: ShardGeneration::new(request.generation.get() + 1).unwrap(),
                ..request
            },
            ..base.clone()
        },
        Receipt {
            request: Request {
                shard: Shard::new(request.shard.get() + 1).unwrap(),
                ..request
            },
            ..base.clone()
        },
        Receipt {
            request: Request {
                namespace: Namespace::new([0x7e; 16]).unwrap(),
                ..request
            },
            ..base.clone()
        },
    ];
    for other in &others {
        assert_ne!(other.token(), base.token(), "{other:?}");
    }
    for token in others.iter().chain([&base]).map(Receipt::token) {
        assert_eq!(token.len(), 59);
        assert!(token.is_ascii());
    }
}

/// The receipt codec decodes exactly its encodings, and a volume field appears exactly in the created phase and in a
/// hold latched over it; a released hold and a generation of `2^32 - 1` refuse. Its successor rule keeps the namespace and shard, never lowers the generation, and within a
/// generation keeps the layout and a release and never lowers the attempt or replaces a volume recorded for the
/// attempt; a raised attempt reopens the receipt, a hold may latch over any unheld phase, and a receipt leaves a hold
/// only in the write that marks it released, which no other write makes.
/// Within an attempt, the phase advances from open to issued to created, and a hold and its release keep the phase.
#[test]
fn the_receipt_codec_and_successor_rule() {
    let base = receipt();
    let made = Receipt {
        phase: created("vol-0c"),
        ..base.clone()
    };
    let volume = VolumeId::new("vol-0c").unwrap();
    for phase in [Phase::Open, Phase::Issued, created("vol-0c")] {
        for (held, released) in [(false, false), (true, false), (false, true), (true, true)] {
            let value = Receipt {
                phase,
                held,
                released,
                ..base.clone()
            };
            let decoded = match (held, released) {
                (true, true) => Err(CodecError::Flag),
                _ => Ok(value.clone()),
            };
            assert_eq!(Receipt::decode(&value.encode()), decoded, "{value:?}");
            assert_eq!(value.encode().len(), RECEIPT_LEN);
        }
    }
    let last = Receipt {
        request: Request {
            generation: ShardGeneration::new(u64::from(u32::MAX)).unwrap(),
            ..base.request
        },
        ..base.clone()
    };
    assert_eq!(Receipt::decode(&last.encode()), Err(CodecError::Field));
    let patched = |value: &Receipt, at: usize, with: &[u8]| {
        let mut bytes = value.encode();
        bytes[at..at + with.len()].copy_from_slice(with);
        Receipt::decode(&bytes)
    };
    let bytes = made.encode();
    assert_eq!(
        Receipt::decode(&bytes[..bytes.len() - 1]),
        Err(CodecError::Length)
    );
    assert_eq!(patched(&made, 0, b"RPLX"), Err(CodecError::Magic));
    assert_eq!(patched(&made, 4, &[0, 2]), Err(CodecError::Version));
    for (name, at, with) in [
        ("zero namespace", 6, &[0u8; 16][..]),
        ("zero shard", 22, &[0; 4][..]),
        ("zero generation", 26, &[0; 4][..]),
        ("zero attempt", 30, &[0; 4][..]),
    ] {
        assert_eq!(patched(&made, at, with), Err(CodecError::Field), "{name}");
    }
    assert_eq!(patched(&made, 54, &[3]), Err(CodecError::Flag));
    assert_eq!(patched(&made, 55, &[2]), Err(CodecError::Flag));
    assert_eq!(patched(&made, 56, &[2]), Err(CodecError::Flag));
    let field = &bytes[57..];
    for open in [
        base.clone(),
        Receipt {
            phase: Phase::Issued,
            ..base.clone()
        },
    ] {
        assert_eq!(patched(&open, 57, field), Err(CodecError::Flag), "{open:?}");
    }
    assert_eq!(patched(&made, 57, &[0]), Err(CodecError::Field));
    assert_eq!(patched(&made, 57, &[0; VOLUME]), Err(CodecError::Field));

    let raised = Receipt {
        attempt: 2,
        ..base.clone()
    };
    let later = Receipt {
        request: Request {
            generation: ShardGeneration::new(base.request.generation.get() + 1).unwrap(),
            ..base.request
        },
        ..base.clone()
    };
    let issued = Receipt {
        phase: Phase::Issued,
        ..base.clone()
    };
    let hold = |receipt: &Receipt| Receipt {
        held: true,
        ..receipt.clone()
    };
    let release = |receipt: &Receipt| Receipt {
        released: true,
        ..receipt.clone()
    };
    let (held, held_issued, held_made) = (hold(&base), hold(&issued), hold(&made));
    let (released, released_issued, released_made) =
        (release(&base), release(&issued), release(&made));
    assert_eq!(held_made.phase.volume(), Some(volume));
    for (next, prior) in [
        (&issued, &base),
        (&made, &issued),
        (&made, &base),
        (&raised, &made),
        (&raised, &issued),
        (&later, &raised),
        (&later, &issued),
        (&held, &base),
        (&released, &held),
        (&held_issued, &issued),
        (&released_issued, &held_issued),
        (&held_made, &made),
        (&released_made, &held_made),
        (&later, &held),
    ] {
        assert_eq!(next.succeeds(prior), Ok(()), "{next:?} after {prior:?}");
    }
    let moved = Receipt {
        phase: created("vol-0d"),
        ..base.clone()
    };
    for (next, prior) in [
        (&base, &raised),
        (&base, &later),
        (&moved, &made),
        (&base, &made),
        (&issued, &made),
        (&base, &issued),
        (&released, &held_issued),
        (&base, &released),
        (&base, &held),
        (&raised, &held),
        (&made, &held_made),
        (&held, &held_made),
        (&released, &base),
    ] {
        assert_eq!(
            next.succeeds(prior),
            Err(SuccessorRule::State),
            "{next:?} after {prior:?}"
        );
    }
    let relaid = Receipt {
        layout: Layout {
            units: base.layout.units + 1,
            ..base.layout
        },
        ..base.clone()
    };
    assert_eq!(relaid.succeeds(&base), Err(SuccessorRule::Layout));
    let other = Receipt {
        request: Request {
            shard: Shard::new(base.request.shard.get() + 1).unwrap(),
            ..base.request
        },
        ..base.clone()
    };
    assert_eq!(other.succeeds(&base), Err(SuccessorRule::Identity));
}

/// A zero attempt alone refuses `Field` and a held byte of 2 alone refuses `Flag`. The attempt lies before the held
/// flag in the layout, so a receipt with both refuses `Field`, the refusal of its first failing field.
#[test]
fn a_receipt_with_a_zero_attempt_and_a_bad_held_flag_refuses_the_attempt_first() {
    // The attempt's four bytes follow the magic, the version, the namespace, the shard and the generation.
    const ATTEMPT_AT: usize = 4 + 2 + 16 + 4 + 4;
    // The held flag's byte follows the attempt, the layout and the phase byte.
    const HELD_AT: usize = ATTEMPT_AT + 4 + 20 + 1;
    let valid = receipt().encode();
    assert_eq!(valid.len(), RECEIPT_LEN);
    assert!(
        Receipt::decode(&valid).is_ok(),
        "control: the receipt decodes"
    );
    assert_eq!(valid[ATTEMPT_AT..ATTEMPT_AT + 4], 1u32.to_be_bytes());
    assert_eq!(valid[HELD_AT], 0);

    let mut zero_attempt = valid.clone();
    zero_attempt[ATTEMPT_AT..ATTEMPT_AT + 4].fill(0);
    assert_eq!(
        Receipt::decode(&zero_attempt).err(),
        Some(CodecError::Field),
        "control: a zero attempt alone"
    );
    let mut bad_held = valid.clone();
    bad_held[HELD_AT] = 2;
    assert_eq!(
        Receipt::decode(&bad_held).err(),
        Some(CodecError::Flag),
        "control: a held byte of 2 alone"
    );

    let mut both = zero_attempt;
    both[HELD_AT] = 2;
    assert_eq!(
        Receipt::decode(&both).err(),
        Some(CodecError::Field),
        "the attempt precedes the held flag in the layout"
    );
}

/// The single-fault controls produce distinct error kinds, so the double-fault result identifies which field
/// `Receipt::decode` checks first.
#[test]
fn a_receipt_with_a_bad_phase_byte_and_a_bad_volume_field_refuses_the_phase_first() {
    // The phase byte follows the magic, the version, the namespace, the shard, the generation, the attempt and the
    // layout.
    const PHASE_AT: usize = 4 + 2 + 16 + 4 + 4 + 4 + 20;
    // The volume field follows the phase byte and the held and released flags. Its first byte is the length of the
    // volume name, and the shortest volume name is longer than one byte.
    const VOLUME_AT: usize = PHASE_AT + 1 + 1 + 1;
    let valid = receipt().encode();
    assert_eq!(valid.len(), VOLUME_AT + VOLUME);
    assert!(
        Receipt::decode(&valid).is_ok(),
        "control: the receipt decodes"
    );
    assert_eq!(valid[PHASE_AT], 0);
    assert_eq!(valid[VOLUME_AT..], [0; VOLUME]);

    let mut bad_phase = valid.clone();
    bad_phase[PHASE_AT] = 3;
    assert_eq!(
        Receipt::decode(&bad_phase).err(),
        Some(CodecError::Flag),
        "control: a phase byte of 3 alone"
    );
    let mut bad_volume = valid.clone();
    bad_volume[VOLUME_AT] = 1;
    assert_eq!(
        Receipt::decode(&bad_volume).err(),
        Some(CodecError::Field),
        "control: a volume field whose length byte is 1 alone"
    );

    let mut both = bad_phase;
    both[VOLUME_AT] = 1;
    assert_eq!(
        Receipt::decode(&both).err(),
        Some(CodecError::Flag),
        "the phase byte precedes the volume field in the layout"
    );
}

/// The held-with-released check reads the held and released flags, which lie before the volume field. A volume
/// field that holds no volume name refuses `Field`, and so does a zero volume field under the created phase. A
/// receipt with held and released both set beside either one refuses `Flag`, the refusal of the flags.
#[test]
fn a_held_and_released_receipt_with_a_bad_volume_field_refuses_the_flags_first() {
    // The phase byte follows the magic, the version, the namespace, the shard, the generation, the attempt and the
    // layout. The held flag, the released flag and the volume field follow it in that order.
    const PHASE_AT: usize = 4 + 2 + 16 + 4 + 4 + 4 + 20;
    const HELD_AT: usize = PHASE_AT + 1;
    const RELEASED_AT: usize = HELD_AT + 1;
    const VOLUME_AT: usize = RELEASED_AT + 1;
    let valid = receipt().encode();
    assert_eq!(valid.len(), VOLUME_AT + VOLUME);
    assert!(
        Receipt::decode(&valid).is_ok(),
        "control: the receipt decodes"
    );
    assert_eq!(valid[PHASE_AT..VOLUME_AT], [0; 3]);
    assert_eq!(valid[VOLUME_AT..], [0; VOLUME]);

    let mut both_flags = valid.clone();
    both_flags[HELD_AT] = 1;
    both_flags[RELEASED_AT] = 1;
    assert_eq!(
        Receipt::decode(&both_flags).err(),
        Some(CodecError::Flag),
        "control: held and released both set alone"
    );
    // A volume field whose length byte is 1 holds no volume name.
    let mut bad_volume = valid.clone();
    bad_volume[VOLUME_AT] = 1;
    assert_eq!(
        Receipt::decode(&bad_volume).err(),
        Some(CodecError::Field),
        "control: a volume field whose length byte is 1 alone"
    );
    let mut no_volume = valid.clone();
    no_volume[PHASE_AT] = 2;
    assert_eq!(
        Receipt::decode(&no_volume).err(),
        Some(CodecError::Field),
        "control: the created phase over a zero volume field alone"
    );

    let mut flags_and_volume = both_flags.clone();
    flags_and_volume[VOLUME_AT] = 1;
    assert_eq!(
        Receipt::decode(&flags_and_volume).err(),
        Some(CodecError::Flag),
        "the released flag precedes the volume field in the layout"
    );
    let mut flags_and_phase = both_flags;
    flags_and_phase[PHASE_AT] = 2;
    assert_eq!(
        Receipt::decode(&flags_and_phase).err(),
        Some(CodecError::Flag),
        "the phase byte is checked against the volume field, which follows the released flag"
    );
}
