//! The metadata area attach admits and the evidence a metadata terminal gives: every block of the prefix must qualify, and `Persisted` stands only for a `Written` terminal of a qualifying range inside the prefix.

use super::super::device::identify_fixture::{EBS, Fields, facts_sized};
use super::super::device::{
    BufferArena, CommandToken, DeviceRange, DeviceStatus, Failure, Operation, PersistenceProfile,
    PoolKind, Terminal, TransferLimits,
};
use super::super::test_platform::TestPlatform;
use super::super::volume_fixture::{arena, facts_for};
use super::layout::TileRefusal;
use super::persisted::{Area, AreaRefusal, Persisted, Recorded};

const CAPACITY: u64 = 1 << 22;

fn profile() -> PersistenceProfile {
    PersistenceProfile::derive(&facts_for(CAPACITY, 16_384)).expect("the fixture profile derives")
}

/// A 4096-byte unit whose one boundary falls at sector 28, inside block 3 of a 4096-byte layout.
fn boundary_in_block_three() -> PersistenceProfile {
    let fields = Fields {
        awupf: 0,
        nsfeat: 0x02,
        nawupf: 7,
        nabo: 28,
        nabspf: u16::MAX,
        vendor: None,
        limits: TransferLimits {
            namespace_max: 16_384,
            boundary: 0,
            command: 16_384,
        },
        ..EBS
    };
    PersistenceProfile::derive(&facts_sized(fields, CAPACITY / 512)).expect("derives")
}

/// Attach admits a prefix only when it tiles into two or more whole blocks of the profile's unit and every one of them qualifies; a boundary inside block 3 refuses that block although blocks 0 to 2 qualify.
#[test]
fn an_area_admits_a_prefix_only_when_every_block_qualifies() {
    let area = Area::new(profile(), 2).expect("two blocks");
    assert_eq!(area.range(0), DeviceRange::new(0, 4096).ok());
    assert_eq!(area.range(1), DeviceRange::new(4096, 4096).ok());
    assert_eq!(area.range(2), None, "past the prefix");
    assert_eq!(
        Area::new(profile(), 1),
        Err(AreaRefusal::Layout {
            refusal: TileRefusal::TooFewBlocks,
            unit: 4096
        })
    );
    assert!(Area::new(boundary_in_block_three(), 3).is_ok());
    assert_eq!(
        Area::new(boundary_in_block_three(), 4),
        Err(AreaRefusal::Unqualified { block: 3 })
    );
}

fn terminal<'a>(arena: &'a BufferArena<TestPlatform>, outcome: u8) -> Terminal<'a> {
    let (token, buffer) = (
        CommandToken::from_raw(7),
        arena.acquire(PoolKind::Maintenance).expect("free"),
    );
    let status = DeviceStatus::Kernel(4096);
    match outcome {
        0 => Terminal::Written {
            token,
            buffer,
            status,
        },
        1 => Terminal::Failed {
            token,
            op: Operation::Write,
            buffer,
            status,
            failure: Failure::Device,
        },
        _ => Terminal::Quiesced {
            token,
            op: Operation::Write,
            buffer,
        },
    }
}

/// `Persisted` stands only for a `Written` terminal whose recorded range is the qualifying range of its recorded block: failed and quiesced terminals, a range of another block and a block past the prefix give none.
#[test]
fn persisted_needs_a_written_terminal_of_its_own_block_s_qualifying_range() {
    let area = Area::new(profile(), 2).expect("two blocks");
    let arena = arena();
    let recorded = Recorded {
        block: 1,
        generation: 4,
        range: area.range(1).expect("block 1"),
    };
    let written = terminal(&arena, 0);
    let persisted = Persisted::of(&written, &recorded, &area).expect("evidence");
    assert_eq!(persisted.recorded(), &recorded);
    drop(written);
    for outcome in [1, 2] {
        let ended = terminal(&arena, outcome);
        assert_eq!(Persisted::of(&ended, &recorded, &area), None, "{outcome}");
    }
    let written = terminal(&arena, 0);
    let foreign = Recorded {
        range: area.range(0).expect("block 0"),
        ..recorded
    };
    assert_eq!(Persisted::of(&written, &foreign, &area), None);
    let outside = Recorded {
        block: 2,
        range: DeviceRange::new(8192, 4096).unwrap(),
        ..recorded
    };
    assert_eq!(Persisted::of(&written, &outside, &area), None);
    let partial = Recorded {
        range: DeviceRange::new(4096, 2048).unwrap(),
        ..recorded
    };
    assert_eq!(Persisted::of(&written, &partial, &area), None);
}
