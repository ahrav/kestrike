//! Namespace and qpair facts against the driver's effective limits.

use super::limits::{LimitsError, MAX_COMMAND, NamespaceFacts};

fn facts(sector_size: u32) -> NamespaceFacts {
    NamespaceFacts {
        active: true,
        sector_size,
        sectors: (1 << 30) / u64::from(sector_size),
        metadata_size: 0,
        protection_type: 0,
        max_transfer: 128 << 10,
        boundary: 0,
        max_queue_size: 256,
    }
}

#[test]
fn both_sector_sizes_yield_a_4k_aligned_transfer_and_a_tracker_bounded_depth() {
    for sector in [512, 4096] {
        let limits = facts(sector).limits(64).unwrap();
        assert_eq!(
            (limits.sector_size, limits.capacity, limits.transfer),
            (sector, 1 << 30, 128 << 10)
        );
        assert_eq!(1u32 << limits.sector_shift, sector);
        assert_eq!(
            (limits.depth, limits.io_queue_size, limits.io_queue_requests),
            (64, 256, 64)
        );
        // A 256-entry qpair keeps 64 entries of completion headroom.
        assert_eq!(facts(sector).limits(1000).unwrap().depth, 192);
    }
}

#[test]
fn the_transfer_is_capped_at_256k_and_rounded_down_to_4k() {
    let mut big = facts(512);
    big.max_transfer = 1 << 20;
    assert_eq!(big.limits(8).unwrap().transfer, MAX_COMMAND);
    let mut odd = facts(512);
    odd.max_transfer = 130 << 10;
    assert_eq!(odd.limits(8).unwrap().transfer, 128 << 10);
    for bad in [0, 2048, (8 << 10) + 1] {
        let mut small = facts(512);
        small.max_transfer = bad;
        assert_eq!(small.limits(8), Err(LimitsError::Transfer(bad)), "{bad}");
    }
}

#[test]
fn a_boundary_splits_commands_so_depth_counts_child_trackers() {
    let mut split = facts(512);
    split.boundary = 64; // 32 KiB
    let limits = split.limits(1000).unwrap();
    // A 128 KiB command crosses at most four 32 KiB boundaries: five children and the parent.
    assert_eq!((limits.depth, limits.io_queue_requests), (192 / 5, 38 * 6));
    split.max_queue_size = 4;
    assert_eq!(split.limits(8), Err(LimitsError::Depth));
    assert_eq!(facts(512).limits(0), Err(LimitsError::Depth));
}

#[test]
fn unusable_namespaces_refuse_in_order() {
    let mut inactive = facts(512);
    inactive.active = false;
    assert_eq!(inactive.limits(8), Err(LimitsError::Inactive));
    let mut metadata = facts(512);
    metadata.metadata_size = 8;
    assert_eq!(metadata.limits(8), Err(LimitsError::Formatted));
    let mut protected = facts(512);
    protected.protection_type = 1;
    assert_eq!(protected.limits(8), Err(LimitsError::Formatted));
    for sector in [0, 520, 8192] {
        let mut odd = facts(512);
        odd.sector_size = sector;
        assert_eq!(odd.limits(8), Err(LimitsError::SectorSize(sector)));
    }
    let mut tiny = facts(512);
    tiny.sectors = 7;
    assert_eq!(tiny.limits(8), Err(LimitsError::ZeroCapacity));
}

/// The tracker count follows the qpair's completion headroom at both clamps.
#[test]
fn trackers_leave_the_qpair_s_completion_headroom() {
    for (entries, trackers) in [(2, 1), (4, 3), (256, 192), (1024, 896)] {
        let mut qpair = facts(512);
        qpair.max_queue_size = entries;
        assert_eq!(
            qpair.limits(u32::MAX).unwrap().depth,
            trackers,
            "{entries} entries"
        );
    }
}
