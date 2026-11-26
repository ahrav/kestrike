//! The host part's gauge sources over plain inputs, and the standby census admission over the headroom they build.

use super::*;
use crate::failover::report::{RecoveryKind, RecoveryRefusal};
use crate::failover::sim::host;
use crate::failover::standbys::tests::{report_of, shard_record};
use crate::failover::standbys::{Attach, Census, Population, Refusal, Zone};

fn limit(n: u64) -> Option<NonZeroU64> {
    NonZeroU64::new(n)
}

fn admitted(recovery: Gauge) -> Result<(), Refusal> {
    admitted_with(Gauge::known(0, 3), recovery)
}

fn admitted_with(attachments: Gauge, recovery: Gauge) -> Result<(), Refusal> {
    let candidate = report_of(host(30), attachments, recovery);
    Population { cap: 3 }
        .admit(
            &Census::empty(Zone(1)),
            &shard_record(1, 11, None),
            &candidate,
            Attach::Open,
            |_| false,
        )
        .map(drop)
}

#[test]
fn a_full_or_missing_recovery_gauge_refuses_headroom() {
    let inputs = |recovering| HeadroomInputs {
        recovering,
        recovery_slots: limit(1),
        ..HeadroomInputs::UNAVAILABLE
    };
    let built =
        |recovering| Headroom::of(Gauge::Unavailable, Gauge::Unavailable, &inputs(recovering));
    assert_eq!(built(Some(1)).recovery, Gauge::known(1, 1));
    assert_eq!(built(None).recovery, Gauge::Unavailable);
    assert_eq!(admitted(built(Some(1)).recovery), Err(Refusal::Headroom));
    assert_eq!(admitted(built(None).recovery), Err(Refusal::Headroom));
    assert_eq!(admitted(built(Some(0)).recovery), Ok(()));
    let planted = |recovering: Option<u64>| built(Some(recovering.unwrap_or(0))).recovery;
    assert_eq!(planted(None), Gauge::known(0, 1));
    assert_eq!(
        admitted(planted(None)),
        Ok(()),
        "the planted source admits a host with unknown recovery headroom"
    );
}

#[test]
fn an_occupied_attachment_slot_refuses_a_new_attach() {
    let built = |unbound| {
        let inputs = HeadroomInputs {
            attached: attached([], unbound),
            attachment_slots: limit(1),
            ..HeadroomInputs::UNAVAILABLE
        };
        Headroom::of(Gauge::Unavailable, Gauge::Unavailable, &inputs).attachments
    };
    let free = Gauge::known(0, 2);
    assert_eq!(built(Some(1)), Gauge::known(1, 1));
    assert_eq!(admitted_with(built(Some(1)), free), Err(Refusal::Headroom));
    assert_eq!(admitted_with(built(None), free), Err(Refusal::Headroom));
    assert_eq!(admitted_with(built(Some(0)), free), Ok(()));
}

fn volume(name: &str) -> VolumeId {
    VolumeId::new(name).unwrap()
}

/// The sample of `owners` given in any order, `None` when two of them name one volume.
fn ordered(owners: &[(&str, u64, u64, u64)], at_us: u64) -> Option<DeviceSample> {
    let owners = owners
        .iter()
        .map(|&(name, sequence, ops, bytes)| DeviceCounts {
            volume: volume(name),
            sequence,
            ops,
            bytes,
        })
        .collect();
    DeviceSample::ordered(owners, at_us)
}

fn sample(owners: &[(&str, u64, u64, u64)], at_us: u64) -> DeviceSample {
    ordered(owners, at_us).unwrap()
}

fn full() -> HeadroomInputs {
    HeadroomInputs {
        previous: Some(sample(&[("vol-0a", 1, 1_000, 1 << 20)], 1_000_000)),
        current: Some(sample(&[("vol-0a", 2, 3_000, 3 << 20)], 2_000_000)),
        provisioned_iops: limit(16_000),
        provisioned_bandwidth: limit(1 << 30),
        attached: Some(3),
        attachment_slots: limit(4),
        roles: Some(2),
        host_roles_max: limit(10),
        recovering: Some(1),
        recovery_slots: limit(2),
    }
}

fn gauges(headroom: &Headroom) -> [Gauge; 5] {
    let h = headroom;
    [h.iops, h.bandwidth, h.attachments, h.workers, h.recovery]
}

#[test]
fn each_gauge_reads_unavailable_without_its_input() {
    let of = |inputs: &HeadroomInputs| {
        gauges(&Headroom::of(
            Gauge::Unavailable,
            Gauge::Unavailable,
            inputs,
        ))
    };
    let known = [
        Gauge::known(2_000, 16_000),
        Gauge::known(2 << 20, 1 << 30),
        Gauge::known(3, 4),
        Gauge::known(2, 10),
        Gauge::known(1, 2),
    ];
    assert_eq!(of(&full()), known);
    assert_eq!(gauges(&Headroom::sample(&full())), known);
    type ClearInput = fn(&mut HeadroomInputs);
    let rows: [(ClearInput, &[usize]); 10] = [
        (|i| i.previous = None, &[0, 1]),
        (|i| i.current = None, &[0, 1]),
        (|i| i.provisioned_iops = None, &[0]),
        (|i| i.provisioned_bandwidth = None, &[1]),
        (|i| i.attached = None, &[2]),
        (|i| i.attachment_slots = None, &[2]),
        (|i| i.roles = None, &[3]),
        (|i| i.host_roles_max = None, &[3]),
        (|i| i.recovering = None, &[4]),
        (|i| i.recovery_slots = None, &[4]),
    ];
    for (at, (clear_input, fed)) in rows.iter().enumerate() {
        let mut inputs = full();
        clear_input(&mut inputs);
        for (gauge, read) in of(&inputs).iter().enumerate() {
            let expected = if fed.contains(&gauge) {
                Gauge::Unavailable
            } else {
                known[gauge]
            };
            assert_eq!(*read, expected, "input {at}, gauge {gauge}");
        }
    }
    assert_eq!(
        Headroom::of(
            Gauge::Unavailable,
            Gauge::Unavailable,
            &HeadroomInputs::UNAVAILABLE
        ),
        crate::failover::report::tests::unavailable_headroom()
    );
}

fn rates(
    before: &DeviceSample,
    after: &DeviceSample,
    iops: Option<NonZeroU64>,
    bandwidth: Option<NonZeroU64>,
) -> [Gauge; 2] {
    let inputs = HeadroomInputs {
        previous: Some(before.clone()),
        current: Some(after.clone()),
        provisioned_iops: iops,
        provisioned_bandwidth: bandwidth,
        ..HeadroomInputs::UNAVAILABLE
    };
    let h = Headroom::of(Gauge::Unavailable, Gauge::Unavailable, &inputs);
    [h.iops, h.bandwidth]
}

#[test]
fn the_rates_read_the_summed_deltas_over_the_interval() {
    let before = sample(&[("vol-0a", 4, 100, 4_096), ("vol-0b", 9, 200, 6_144)], 0);
    let after = sample(
        &[("vol-0b", 10, 800, 12_288), ("vol-0a", 5, 700, 8_192)],
        500_000,
    );
    let wide = (limit(10_000), limit(1 << 20));
    assert_eq!(
        rates(&before, &after, wide.0, wide.1),
        [Gauge::known(2_400, 10_000), Gauge::known(20_480, 1 << 20)]
    );
    assert_eq!(
        rates(&before, &after, limit(1_000), limit(1_000)),
        [Gauge::known(1_000, 1_000), Gauge::known(1_000, 1_000)],
        "a rate above the provisioned one reads full"
    );
    assert_eq!(
        rates(&before, &after, None, wide.1),
        [Gauge::Unavailable, Gauge::known(20_480, 1 << 20)]
    );
    assert_eq!(
        rates(&before, &after, wide.0, None),
        [Gauge::known(2_400, 10_000), Gauge::Unavailable]
    );
    let idle = sample(
        &[("vol-0a", 5, 100, 4_096), ("vol-0b", 10, 800, 12_288)],
        500_000,
    );
    assert_eq!(
        rates(&before, &idle, wide.0, wide.1),
        [Gauge::known(1_200, 10_000), Gauge::known(12_288, 1 << 20)],
        "an idle owner beside a busy one adds a measured zero"
    );
    let one = |sequence, ops, bytes, at_us| sample(&[("vol-0a", sequence, ops, bytes)], at_us);
    assert_eq!(
        rates(&one(1, 0, 0, 0), &one(2, 7, 7, 4_000_000), wide.0, wide.1),
        [Gauge::known(1, 10_000), Gauge::known(1, 1 << 20)],
        "7 over 4 seconds rounds down to 1"
    );
    let max = limit(u64::MAX);
    assert_eq!(
        rates(&one(1, 0, 0, 0), &one(2, 1 << 63, 1 << 63, 1), max, max),
        [Gauge::known(u64::MAX, u64::MAX); 2],
        "a rate above u64::MAX caps there"
    );
    // The rate rounds down the same way on both sides of 18_446_744_073_709, the largest delta whose product with
    // 1_000_000 fits `u64`.
    for (delta, rate) in [
        (18_446_744_073_708, 6_148_914_691_236_000_000),
        (18_446_744_073_709, 6_148_914_691_236_333_333),
        (18_446_744_073_710, 6_148_914_691_236_666_666),
        (18_446_744_073_711, 6_148_914_691_237_000_000),
    ] {
        assert_eq!(
            rates(&one(1, 0, 0, 0), &one(2, delta, delta, 3), max, max),
            [Gauge::known(rate, u64::MAX); 2],
            "{delta} over 3 microseconds"
        );
    }
    let pair = |sequence, a, b, at_us| {
        sample(
            &[("vol-0a", sequence, a, a), ("vol-0b", sequence, b, b)],
            at_us,
        )
    };
    assert_eq!(
        rates(
            &pair(1, 0, 0, 0),
            &pair(2, u64::MAX, 1, 1_000_000),
            max,
            max
        ),
        [Gauge::known(u64::MAX, u64::MAX); 2],
        "the owners' delta sum saturates"
    );
    let empty = sample(&[], 0);
    assert_eq!(
        rates(&empty, &sample(&[], 500_000), wide.0, wide.1),
        [Gauge::known(0, 10_000), Gauge::known(0, 1 << 20)],
        "no owners read a measured zero"
    );
    let unavailable = |after: &DeviceSample, case: &str| {
        assert_eq!(
            rates(&before, after, wide.0, wide.1),
            [Gauge::Unavailable; 2],
            "{case}"
        );
    };
    unavailable(
        &sample(&[("vol-0b", 10, 800, 12_288)], 500_000),
        "a departure",
    );
    unavailable(
        &sample(
            &[
                ("vol-0a", 5, 700, 8_192),
                ("vol-0b", 10, 800, 12_288),
                ("vol-0c", 1, 1 << 40, 0),
            ],
            500_000,
        ),
        "a join",
    );
    unavailable(
        &sample(
            &[("vol-0a", 5, 700, 8_192), ("vol-0c", 1, 800, 12_288)],
            500_000,
        ),
        "a replacement",
    );
    unavailable(
        &sample(
            &[("vol-0a", 5, 50, 8_192), ("vol-0b", 10, 800, 12_288)],
            500_000,
        ),
        "operations fell and bytes rose",
    );
    unavailable(
        &sample(
            &[("vol-0a", 5, 700, 2_048), ("vol-0b", 10, 800, 12_288)],
            500_000,
        ),
        "bytes fell and operations rose",
    );
    unavailable(
        &sample(
            &[("vol-0a", 4, 700, 8_192), ("vol-0b", 10, 800, 12_288)],
            500_000,
        ),
        "a reused reading",
    );
    unavailable(
        &sample(
            &[("vol-0a", 1, 700, 8_192), ("vol-0b", 10, 800, 12_288)],
            500_000,
        ),
        "a replaced driver's lower sequence",
    );
    unavailable(
        &sample(&[("vol-0a", 5, 700, 8_192), ("vol-0b", 10, 800, 12_288)], 0),
        "an empty interval",
    );
    assert_eq!(
        ordered(&[("vol-0a", 5, 700, 8_192), ("vol-0a", 5, 700, 8_192)], 0),
        None,
        "a volume named twice gives no sample"
    );
    assert_eq!(
        ordered(
            &[
                ("vol-0b", 5, 700, 8_192),
                ("vol-0a", 5, 700, 8_192),
                ("vol-0b", 6, 800, 8_192),
            ],
            0
        ),
        None,
        "a volume named twice apart gives no sample"
    );
    assert_eq!(
        after.owners().iter().map(|o| o.volume).collect::<Vec<_>>(),
        [volume("vol-0a"), volume("vol-0b")],
        "a sample holds its owners in volume order, whatever order they came in"
    );
    let later = sample(
        &[("vol-0a", 3, 50, 2_048), ("vol-0b", 8, 100, 4_096)],
        1_000_000,
    );
    assert_eq!(
        rates(&later, &before, wide.0, wide.1),
        [Gauge::Unavailable; 2],
        "a reversed interval"
    );
    let first = HeadroomInputs {
        current: Some(after.clone()),
        provisioned_iops: wide.0,
        provisioned_bandwidth: wide.1,
        ..HeadroomInputs::UNAVAILABLE
    };
    let h = Headroom::of(Gauge::Unavailable, Gauge::Unavailable, &first);
    assert_eq!(
        [h.iops, h.bandwidth],
        [Gauge::Unavailable; 2],
        "a boot's first sample"
    );
}

#[test]
fn the_counts_read_their_sources() {
    let owner = |volume: &str, bdf: &str| {
        let mut mapping = crate::bind::mappings_tests::sample(None);
        let nvme = mapping.nvme.as_mut().unwrap();
        nvme.volume = volume.into();
        nvme.bdf = bdf.into();
        mapping
    };
    let network = Mappings {
        nvme: None,
        eni: Some(crate::bind::mappings_tests::eni(1)),
        ..crate::bind::mappings_tests::sample(None)
    };
    let mappings = [
        owner("vol-0123456789abcdef0", "0000:00:1d.0"),
        owner("vol-0123456789abcdef1", "0000:00:1e.0"),
        owner("vol-0123456789abcdef2", "0000:00:1f.0"),
        network,
    ];
    assert_eq!(attached(mappings.iter().map(Some), Some(0)), Some(3));
    assert_eq!(
        slots(attached(mappings.iter().map(Some), Some(1)), limit(5)),
        Gauge::known(4, 5)
    );
    assert_eq!(attached([], Some(0)), Some(0), "a host with no owners");
    assert_eq!(
        attached([Some(&mappings[0]), None], Some(0)),
        None,
        "a failed mappings read"
    );
    assert_eq!(attached(mappings.iter().map(Some), None), None);
    let twice = owner("vol-0123456789abcdef0", "0000:00:1c.0");
    assert_eq!(
        attached([Some(&mappings[0]), Some(&twice)], Some(0)),
        None,
        "two mappings of one volume"
    );
    assert_eq!(
        attached(
            [
                Some(&mappings[1]),
                Some(&twice),
                Some(&mappings[2]),
                Some(&mappings[0])
            ],
            Some(0)
        ),
        None,
        "two mappings of one volume with other volumes between them"
    );
    assert_eq!(
        attached(
            [Some(&mappings[2]), Some(&mappings[0]), Some(&mappings[1])],
            Some(0)
        ),
        Some(3),
        "the mappings in another order"
    );
    let mut running = RecoveryStatus::NO_ATTEMPT;
    running.start(RecoveryKind::Restart, 0);
    let mut done = running;
    done.complete();
    let target = crate::failover::retire::Target::of(&shard_record(1, 11, None));
    let restart = |check, flip, recovery| {
        RecoveryRefusal::from(&crate::failover::restart::Refused {
            check,
            flip,
            recovery,
        })
    };
    let refused = |refusal| {
        let mut status = running;
        status.refuse(refusal);
        status
    };
    use crate::failover::restart::Check;
    use crate::storage::store::StoreError;
    let hold = restart(Check::Bump(StoreError::Unknown), None, Some(target));
    let rerun = RecoveryRefusal::from(&crate::failover::fresh::Refused {
        check: crate::failover::fresh::Check::Confirm(StoreError::Unknown),
        flip: None,
    });
    let stop = restart(Check::Deposed, None, None);
    let flip = restart(
        Check::Exhausted(crate::storage::SessionRefusal::AttemptsExhausted),
        Some(target),
        None,
    );
    let statuses = [
        running,
        refused(hold),
        refused(rerun),
        done,
        refused(stop),
        refused(flip),
        RecoveryStatus::NO_ATTEMPT,
    ];
    assert_eq!(
        recovering(statuses.iter().map(|status| Some((status, false)))),
        Some(3)
    );
    assert_eq!(
        statuses.map(|status| status.holds_slot()),
        [true, true, true, false, false, false, false]
    );
    assert_eq!(
        recovering([Some((&done, false)), None]),
        None,
        "a missing status"
    );
    assert_eq!(recovering([]), Some(0));
    let gauge = |attach_before_live| {
        let inputs = HeadroomInputs {
            recovering: recovering([Some((&done, attach_before_live))]),
            recovery_slots: limit(1),
            ..HeadroomInputs::UNAVAILABLE
        };
        Headroom::of(Gauge::Unavailable, Gauge::Unavailable, &inputs).recovery
    };
    assert_eq!(
        (gauge(true), admitted(gauge(true))),
        (Gauge::known(1, 1), Err(Refusal::Headroom)),
        "a completed sequence whose attach has yet to reach Live keeps its slot"
    );
    assert_eq!(
        (gauge(false), admitted(gauge(false))),
        (Gauge::known(0, 1), Ok(()))
    );
    assert_eq!(
        slots(Some(5), limit(4)),
        Gauge::known(4, 4),
        "an over-committed host reads full"
    );
}

#[test]
fn the_host_part_reads_producer_health_and_recovery_io() {
    assert_eq!(
        producer_missing([true, true, false, true]),
        Members::Known { used: 1, limit: 4 }
    );
    assert_eq!(producer_missing([]), Members::Known { used: 0, limit: 0 });
    let share = HostShare {
        bytes: 10_000,
        interval: 10,
        owners: 2,
    };
    let peaks = [Gauge::known(3_000, 6_000), Gauge::known(4_500, 6_000)];
    assert_eq!(host_recovery_io(peaks, share), Gauge::known(7_500, 20_000));
    assert_eq!(
        host_recovery_io(
            [Gauge::known(15_000, 16_000), Gauge::known(9_000, 10_000)],
            share
        ),
        Gauge::known(20_000, 20_000)
    );
    assert_eq!(
        host_recovery_io([Gauge::known(3_000, 6_000), Gauge::Unavailable], share),
        Gauge::Unavailable
    );
    assert_eq!(host_recovery_io([], share), Gauge::known(0, 20_000));
    let huge = HostShare {
        bytes: u64::MAX,
        interval: 10,
        owners: 1,
    };
    assert_eq!(
        host_recovery_io([Gauge::known(5, 6)], huge),
        Gauge::known(5, u64::MAX)
    );
    for refused in [
        HostShare {
            interval: 0,
            ..share
        },
        HostShare { owners: 0, ..share },
        HostShare {
            owners: crate::failover::report::MAX_ENTRIES as u32 + 1,
            bytes: u64::MAX,
            ..share
        },
        HostShare { bytes: 0, ..share },
        HostShare {
            bytes: 1_000,
            ..share
        },
    ] {
        assert_eq!(
            host_recovery_io([], refused),
            Gauge::Unavailable,
            "{refused:?}"
        );
    }
}
