//! The recovery I/O share's split of a host share over its owners and each owner's bucket and report windows under
//! demand above the share, stalled time, refused charges and the suffix reserve.

use super::io_share::{HostShare, IoClass, IoShare, MAX_OWNERS, RESERVE};
use crate::storage::seeded::SplitMix64;

fn host(bytes: u64, interval: u64, owners: u32) -> HostShare {
    HostShare {
        bytes,
        interval,
        owners,
    }
}

/// A host share splits evenly over its owners; a zero interval, no owner, more than `MAX_OWNERS` owners, or an owner
/// part below the largest bulk charge plus the suffix reserve is refused.
#[test]
fn a_host_share_splits_over_its_owners_and_refuses_a_part_too_small_for_its_largest_charge() {
    assert_eq!(host(8 * RESERVE, 10, 4).part(RESERVE), Some(2 * RESERVE));
    assert_eq!(
        host(8 * RESERVE, 10, 5).part(RESERVE),
        None,
        "a part of 1.6 blocks"
    );
    assert_eq!(host(8 * RESERVE, 0, 4).part(RESERVE), None);
    assert_eq!(host(8 * RESERVE, 10, 0).part(RESERVE), None);
    assert_eq!(host(u64::MAX, 10, MAX_OWNERS + 1).part(RESERVE), None);
    assert!(host(u64::MAX, 10, MAX_OWNERS).part(RESERVE).is_some());
    assert_eq!(
        host(RESERVE, 10, 1).part(0),
        Some(RESERVE),
        "a suffix-only part"
    );
    assert!(IoShare::of(host(RESERVE, 10, 1), 1).is_none());
}

/// The bytes `admitted` charges, each a tick and its bytes in tick order, put from `ticks` ticks before the last
/// one's tick through that tick, both ends included.
fn last_span(admitted: &[(u64, u64)], ticks: u64) -> u64 {
    let now = admitted.last().map_or(0, |last| last.0);
    (admitted.iter().rev())
        .take_while(|(at, _)| now - at <= ticks)
        .map(|(_, bytes)| bytes)
        .sum()
}

/// Every owner of a host draws on its own part under random charges and tick steps whose demand is far above the
/// share: at every step the charges one owner made in the last one, two and three intervals sum to at most its
/// capacity plus as many parts, the charges all owners made in the last interval to at most the host share plus the
/// owners' capacities, which is within twice the host share, and a refusal charges nothing. Giving every owner the
/// whole host share fails the host bound, and a share that admits every charge fails the owner bound.
#[test]
fn the_owners_of_one_host_together_stay_within_the_host_share_and_their_capacities_per_interval() {
    const OWNERS: u32 = 4;
    const INTERVAL: u64 = 16;
    const LARGEST: u64 = 6_000;
    let run = |whole: bool| -> Result<(), String> {
        let share = host(4 * 10_000 + 4 * RESERVE, INTERVAL, OWNERS);
        let part = share.part(LARGEST).unwrap();
        // The capacity the module documents: the largest bulk charge, the reserve and the part's drain over one tick
        // of this interval, which is shorter than 64 ticks.
        let capacity = (LARGEST + RESERVE + part.div_ceil(INTERVAL)).min(part);
        assert!(u64::from(OWNERS) * capacity < share.bytes);
        let mut rng = SplitMix64::new(0x1449);
        let mut owners: Vec<_> = (0..OWNERS)
            .map(|_| {
                let each = if whole {
                    HostShare { owners: 1, ..share }
                } else {
                    share
                };
                (IoShare::of(each, LARGEST).unwrap(), Vec::new())
            })
            .collect();
        let (mut now, mut admitted) = (0u64, Vec::new());
        for step in 0..50_000 {
            now += rng.next_u64() % 3;
            for (at, (owner, own)) in owners.iter_mut().enumerate() {
                let bytes = 1 + rng.next_u64() % LARGEST;
                let class = if rng.next_u64().is_multiple_of(4) {
                    IoClass::Suffix
                } else {
                    IoClass::Bulk
                };
                let (peak, saturated) = (owner.peak(), owner.saturated());
                if owner.admit(now, bytes, class) {
                    own.push((now, bytes));
                    admitted.push((now, bytes));
                    let over = (1..=3).find(|&intervals| {
                        last_span(own, intervals * INTERVAL) > capacity + intervals * part
                    });
                    if let Some(intervals) = over.filter(|_| !whole) {
                        return Err(format!(
                            "step {step}: owner {at} passed its capacity and parts in {intervals} intervals"
                        ));
                    }
                } else if owner.peak() != peak || owner.saturated() > saturated + 1 {
                    return Err(format!(
                        "step {step}: a refusal charged bytes or counted twice"
                    ));
                }
            }
            let span = last_span(&admitted, INTERVAL);
            if span > share.bytes + u64::from(OWNERS) * capacity {
                return Err(format!(
                    "step {step}: the host holds {span} bytes in one interval"
                ));
            }
        }
        Ok(())
    };
    assert_eq!(run(false), Ok(()));
    assert!(
        run(true).is_err_and(|error| error.contains("the host holds")),
        "control: each owner taking the whole host share passes the host bound"
    );
    super::io_share::IGNORE.with(|plant| plant.set(true));
    let ignored = run(false);
    super::io_share::IGNORE.with(|plant| plant.set(false));
    assert!(
        ignored
            .as_ref()
            .is_err_and(|error| error.contains("passed its capacity and parts")),
        "control: a share that admits every charge passes an owner's capacity and parts: {ignored:?}"
    );
}

/// Bulk charges leave the reserve to suffix blocks: with bulk demand taking all the room it is offered at polls two
/// ticks apart, the slack's 1/64 of the interval, a suffix block offered once in every interval fits and a second
/// one at that tick is refused, the bulk charges still take the rest of the part, and a suffix block also takes bulk
/// room an idle bucket holds.
#[test]
fn bulk_charges_leave_the_reserve_to_suffix_blocks() {
    const INTERVAL: u64 = 128;
    let mut share = IoShare::of(host(3 * RESERVE, INTERVAL, 1), RESERVE).unwrap();
    let mut bulk = 0u64;
    for now in (0..100 * INTERVAL).step_by(2) {
        while share.admit(now, RESERVE, IoClass::Bulk) {
            bulk += 1;
        }
        if now % INTERVAL == 4 {
            assert!(
                share.admit(now, RESERVE, IoClass::Suffix),
                "tick {now}: the reserve holds a suffix block"
            );
            assert!(
                !share.admit(now, RESERVE, IoClass::Suffix),
                "tick {now}: the reserve is one block"
            );
        }
    }
    assert_eq!(
        bulk, 201,
        "the block the empty bucket holds at the first tick, then the part's three blocks per interval less the \
         suffix block, over 100 intervals"
    );
    let mut idle = IoShare::of(host(3 * RESERVE, INTERVAL, 1), RESERVE).unwrap();
    assert!(idle.admit(0, RESERVE, IoClass::Suffix) && idle.admit(0, RESERVE, IoClass::Suffix));
    assert!(
        !idle.admit(0, RESERVE, IoClass::Bulk),
        "the suffix blocks took the bulk room"
    );
}

/// A charge is for issue: with the clock stalled a bucket 256 bytes short of its bulk room refuses a block however
/// often it is asked, an earlier clock reading drains nothing, a fraction of an interval drains that fraction of the
/// part from the bucket, and one interval after the last charge the bucket is empty although no charged command
/// completed, so a stalled device or store holds no budget; a window counts as saturated once however many charges
/// it refuses.
#[test]
fn a_stalled_clock_admits_nothing_more_and_one_interval_empties_the_bucket() {
    // A part of four blocks per 100 ticks whose bucket holds two bulk blocks, the reserve and 256 bytes of slack.
    let mut share = IoShare::of(host(2 * RESERVE + 8_192, 100, 1), 8_192).unwrap();
    assert!(share.admit(1_000, 4_096, IoClass::Bulk) && share.admit(1_000, 4_096, IoClass::Bulk));
    for _ in 0..10_000 {
        assert!(!share.admit(1_000, RESERVE, IoClass::Bulk));
        assert!(
            !share.admit(900, RESERVE, IoClass::Bulk),
            "an earlier reading drains nothing"
        );
    }
    assert_eq!(share.saturated(), 1, "one saturated window");
    // A third block fits once 3,840 bytes drained: 23 ticks drain 3,768 and 24 ticks drain 3,932.
    assert!(!share.admit(1_023, RESERVE, IoClass::Bulk));
    assert!(share.admit(1_024, RESERVE, IoClass::Bulk));
    assert!(
        share.admit(1_124, 8_192 + 256, IoClass::Bulk),
        "the whole bulk room is back"
    );
    assert!(
        share.admit(1_124, RESERVE, IoClass::Suffix),
        "and the reserve"
    );
    assert!(
        !share.admit(1_124, 1, IoClass::Suffix),
        "the bucket is full"
    );
    assert_eq!((share.peak(), share.saturated()), (3 * RESERVE + 256, 2));
}

/// A window that refused a charge reads full until `interval` ticks after it opened and then reads not full with no
/// later charge, so the clock alone ends the share's pressure reading; a window with no refusal never reads full.
#[test]
fn a_refused_window_reads_full_until_its_interval_passes_with_no_later_charge() {
    let mut share = IoShare::of(host(2 * RESERVE, 100, 1), RESERVE).unwrap();
    assert!(share.admit(1_000, RESERVE, IoClass::Bulk));
    assert!(!share.full(1_000), "a window with no refusal");
    assert!(!share.admit(1_010, RESERVE, IoClass::Bulk));
    for now in 1_010..1_100 {
        assert!(share.full(now), "tick {now}: the open window refused");
    }
    for now in 1_100..10_000 {
        assert!(!share.full(now), "tick {now}: no window is open");
    }
    assert_eq!(share.saturated(), 1);
}

/// The first window opens at the first charge offered, whatever the clock reads then: with a first charge at tick 90
/// of a 100-tick interval, refusals at ticks 95 and 100 fall in one window that reads full through tick 189, and the
/// charges admitted at ticks 90 and 140 count in that window's peak.
#[test]
fn the_first_window_opens_at_the_first_charge_offered() {
    let mut share = IoShare::of(host(2 * RESERVE, 100, 1), RESERVE).unwrap();
    assert!(!share.full(90), "no window is open before the first charge");
    assert!(share.admit(90, RESERVE, IoClass::Bulk));
    assert!(!share.admit(95, RESERVE, IoClass::Bulk));
    assert!(!share.admit(100, RESERVE, IoClass::Bulk));
    assert_eq!(share.saturated(), 1, "both refusals fall in one window");
    assert!(share.admit(140, RESERVE, IoClass::Bulk));
    assert_eq!(share.peak(), 2 * RESERVE, "one window holds both charges");
    for now in 95..190 {
        assert!(share.full(now), "tick {now}: the window opened at tick 90");
    }
    assert!(!share.full(190), "the window is one interval old");
}

/// An interval shorter than 64 ticks gives the capacity one tick of the part's drain as slack, rounded up: a part
/// of 16,392 bytes per 16 ticks drains 1,024.5 bytes a tick, so the bucket holds a bulk charge of one block and
/// 1,025 bytes beside the reserve and not one byte more.
#[test]
fn an_interval_under_64_ticks_has_one_tick_of_the_part_s_drain_as_slack() {
    let mut share = IoShare::of(host(4 * RESERVE + 8, 16, 1), RESERVE).unwrap();
    assert!(share.admit(0, RESERVE + 1_025, IoClass::Bulk));
    assert!(share.admit(0, RESERVE, IoClass::Suffix));
    assert!(!share.admit(0, 1, IoClass::Suffix));
}

/// A refund returns a charge the device turned away: the bucket's room comes back for the next charge, and the peak
/// counts only the bytes left charged in the window.
#[test]
fn a_refund_returns_the_room_and_leaves_the_peak_at_the_charged_bytes() {
    let mut share = IoShare::of(
        HostShare {
            bytes: 2 * RESERVE,
            interval: 10,
            owners: 1,
        },
        RESERVE,
    )
    .unwrap();
    assert!(share.admit(10, RESERVE, IoClass::Bulk));
    assert!(!share.admit(10, 1, IoClass::Bulk), "the bulk room is spent");
    share.refund(RESERVE);
    assert_eq!(share.peak(), 0, "a refunded charge leaves no peak");
    assert!(
        share.admit(11, RESERVE, IoClass::Bulk),
        "the refund returned the room"
    );
    assert_eq!(share.peak(), RESERVE);
    assert!(share.admit(20, 1, IoClass::Bulk), "a new window");
    assert_eq!(share.peak(), RESERVE, "the closed window keeps its peak");
}

/// The share's window limit is its part plus its bucket capacity: the largest bulk charge, the reserve and one tick's
/// drain of the part, at most the part. A share whose capacity stays below its part reads part plus that capacity, one
/// whose capacity clamps to its part reads twice the part, and a sum past `u64::MAX` saturates.
#[test]
fn the_window_limit_is_the_part_plus_the_bucket_capacity() {
    const INTERVAL: u64 = 16;
    const LARGEST: u64 = 6_000;
    let share = host(4 * 100_000 + 4 * RESERVE, INTERVAL, 4);
    let part = 100_000 + RESERVE;
    let capacity = LARGEST + RESERVE + part.div_ceil(INTERVAL);
    assert!(capacity < part, "the capacity stays below the part");
    assert_eq!(
        IoShare::of(share, LARGEST).unwrap().limit(),
        part + capacity
    );
    let clamped = host(1 << 40, 1, 1);
    assert_eq!(IoShare::of(clamped, LARGEST).unwrap().limit(), 1 << 41);
    assert_eq!(
        IoShare::of(host(u64::MAX, 1, 1), LARGEST).unwrap().limit(),
        u64::MAX
    );
}
