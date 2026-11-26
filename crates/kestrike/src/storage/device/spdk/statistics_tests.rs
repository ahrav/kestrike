//! Statistics page parsing: every counter at its fixed offset, the histograms' used bins, and the refusals.

use super::statistics::{
    HISTOGRAM_BINS, LatencyBin, PAGE_LEN, StatisticsError, StatisticsFailure, StatisticsHandle,
    parse,
};

/// A page with the EBS magic, counters `1..=11` times `base`, and `bins` in both histograms.
pub(super) fn page(base: u64, bins: &[(u64, u64, u32)]) -> [u8; PAGE_LEN] {
    let mut page = [0u8; PAGE_LEN];
    page[0..4].copy_from_slice(&0x3C23_B510u32.to_le_bytes());
    for index in 0..11u64 {
        let at = 8 + 8 * index as usize;
        page[at..at + 8].copy_from_slice(&((index + 1) * base).to_le_bytes());
    }
    for start in [512, 512 + 8 + HISTOGRAM_BINS * 24] {
        page[start..start + 8].copy_from_slice(&(bins.len() as u64).to_le_bytes());
        for (index, &(lower, upper, count)) in bins.iter().enumerate() {
            let at = start + 8 + 24 * index;
            page[at..at + 8].copy_from_slice(&lower.to_le_bytes());
            page[at + 8..at + 16].copy_from_slice(&upper.to_le_bytes());
            page[at + 16..at + 20].copy_from_slice(&count.to_le_bytes());
        }
    }
    page
}

#[test]
fn a_page_parses_every_counter_and_the_used_histogram_bins() {
    let parsed = parse(&page(10, &[(0, 128, 5), (128, 256, 7)])).unwrap();
    assert_eq!(
        [
            parsed.read_ops,
            parsed.write_ops,
            parsed.read_bytes,
            parsed.write_bytes,
            parsed.read_time_us,
            parsed.write_time_us,
            parsed.volume_exceeded_iops_us,
            parsed.volume_exceeded_throughput_us,
            parsed.instance_exceeded_iops_us,
            parsed.instance_exceeded_throughput_us,
            parsed.queue_length,
        ],
        [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110]
    );
    let bins = [
        LatencyBin {
            lower_us: 0,
            upper_us: 128,
            count: 5,
        },
        LatencyBin {
            lower_us: 128,
            upper_us: 256,
            count: 7,
        },
    ];
    assert_eq!(parsed.read_latency.bins(), bins);
    assert_eq!(parsed.write_latency.bins(), bins);
}

#[test]
fn a_page_without_the_magic_or_with_too_many_bins_is_refused() {
    let mut wrong = page(1, &[]);
    wrong[0] = 0;
    assert_eq!(parse(&wrong), Err(StatisticsError::Magic(0x3C23_B500)));
    let mut wide = page(1, &[]);
    wide[512..520].copy_from_slice(&65u64.to_le_bytes());
    assert_eq!(parse(&wide), Err(StatisticsError::Bins(65)));
}

#[test]
fn readings_are_numbered_from_one_in_publication_order() {
    let handle = StatisticsHandle(std::sync::Arc::default());
    assert_eq!(handle.latest(), None);
    handle.0.publish(Err(StatisticsFailure::Refused(-12)));
    handle.0.publish(Err(StatisticsFailure::Status(0x0002)));
    let latest = handle.latest().unwrap();
    assert_eq!(latest.sequence, 2);
    assert_eq!(latest.outcome, Err(StatisticsFailure::Status(0x0002)));
}

/// A page of noise from `seed` with the EBS magic, a read histogram naming
/// `counts.0` bins and a write histogram naming `counts.1` bins. Counters
/// and bin contents stay noise.
fn raw_page(seed: u64, counts: (u64, u64)) -> [u8; PAGE_LEN] {
    let mut rng = super::super::super::seeded::SplitMix64::new(seed);
    let mut page = [0u8; PAGE_LEN];
    for word in page.as_chunks_mut::<8>().0 {
        *word = rng.next_u64().to_le_bytes();
    }
    page[0..4].copy_from_slice(&[0x10, 0xb5, 0x23, 0x3c]);
    page[512..520].copy_from_slice(&counts.0.to_le_bytes());
    page[2056..2064].copy_from_slice(&counts.1.to_le_bytes());
    page
}

/// A page's eleven counters and its read and write histograms' bins.
type Literal = ([u64; 11], Vec<LatencyBin>, Vec<LatencyBin>);

/// The page's counters and histogram bins read at the format's offsets
/// alone: eleven little-endian `u64` counters from byte 8, then each
/// histogram's `u64` bin count, read at 512 and write at 2056, followed by
/// 24-byte bins of a `u64` lower bound, a `u64` upper bound and a `u32`
/// count. The error holds the first histogram bin count above 64.
fn expected(page: &[u8; PAGE_LEN]) -> Result<Literal, u64> {
    let u64_at = |at: usize| u64::from_le_bytes(page[at..at + 8].try_into().unwrap());
    let histogram = |at: usize| -> Result<Vec<LatencyBin>, u64> {
        let count = u64_at(at);
        if count > 64 {
            return Err(count);
        }
        Ok((0..count as usize)
            .map(|index| {
                let bin = at + 8 + 24 * index;
                LatencyBin {
                    lower_us: u64_at(bin),
                    upper_us: u64_at(bin + 8),
                    count: u32::from_le_bytes(page[bin + 16..bin + 20].try_into().unwrap()),
                }
            })
            .collect())
    };
    let counters = std::array::from_fn(|index| u64_at(8 + 8 * index));
    Ok((counters, histogram(512)?, histogram(2056)?))
}

/// Noise pages decode every counter and both histograms' bins at their
/// literal offsets for read and write bin counts of 0, 64, 65 and
/// `u64::MAX` in every pairing, so each histogram's bound check runs
/// independently. A count above 64 refuses `Bins` naming it, read
/// histogram first.
#[test]
fn raw_statistics_pages_decode_each_histogram_at_its_own_offset() {
    let counts = [0, 64, 65, u64::MAX];
    let mut seed = 0;
    for read in counts {
        for write in counts {
            seed += 1;
            let page = raw_page(seed, (read, write));
            let parsed = parse(&page);
            match expected(&page) {
                Err(count) => {
                    assert_eq!(parsed, Err(StatisticsError::Bins(count)), "{read} {write}")
                }
                Ok((counters, read_bins, write_bins)) => {
                    let parsed = parsed.unwrap();
                    assert_eq!(
                        [
                            parsed.read_ops,
                            parsed.write_ops,
                            parsed.read_bytes,
                            parsed.write_bytes,
                            parsed.read_time_us,
                            parsed.write_time_us,
                            parsed.volume_exceeded_iops_us,
                            parsed.volume_exceeded_throughput_us,
                            parsed.instance_exceeded_iops_us,
                            parsed.instance_exceeded_throughput_us,
                            parsed.queue_length,
                        ],
                        counters
                    );
                    assert_eq!(parsed.read_latency.bins(), read_bins, "{read} {write}");
                    assert_eq!(parsed.write_latency.bins(), write_bins, "{read} {write}");
                    if !read_bins.is_empty() && !write_bins.is_empty() {
                        assert_ne!(read_bins, write_bins, "noise makes the histograms differ");
                    }
                }
            }
        }
    }
}

/// An owner's device counts sum its statistics' read and write operations and bytes.
#[test]
fn an_owner_s_device_counts_sum_its_reads_and_writes() {
    use super::statistics::Reading;
    use crate::failover::records::VolumeId;
    use crate::failover::report::{DeviceCounts, DeviceSample};
    let counted = |read_ops, write_ops, read_bytes, write_bytes| {
        let mut statistics = parse(&page(1, &[])).unwrap();
        statistics.read_ops = read_ops;
        statistics.write_ops = write_ops;
        statistics.read_bytes = read_bytes;
        statistics.write_bytes = write_bytes;
        statistics
    };
    let (a, b) = (
        VolumeId::new("vol-0a").unwrap(),
        VolumeId::new("vol-0b").unwrap(),
    );
    let first = Reading {
        sequence: 7,
        outcome: Ok(counted(100, 20, 4_000, 600)),
    };
    let second = Reading {
        sequence: 3,
        outcome: Ok(counted(300, 5, 9_000, 1)),
    };
    let failed = Reading {
        sequence: 4,
        outcome: Err(StatisticsFailure::Refused(-5)),
    };
    let expected = [
        DeviceCounts {
            volume: a,
            sequence: 7,
            ops: 120,
            bytes: 4_600,
        },
        DeviceCounts {
            volume: b,
            sequence: 3,
            ops: 305,
            bytes: 9_001,
        },
    ];
    assert_eq!(DeviceCounts::of(a, &first), Some(expected[0].clone()));
    assert_eq!(DeviceCounts::of(a, &failed), None);
    let built = DeviceSample::of([(b, Some(&second)), (a, Some(&first))], 9, None);
    assert_eq!(
        built
            .as_ref()
            .map(|sample| (sample.owners(), sample.at_us())),
        Some((&expected[..], 9)),
        "owners supplied out of order give a sample that holds them in volume order"
    );
    let built = built.unwrap();
    assert!(built.measured(), "a boot's first complete sample");
    assert_eq!(
        DeviceSample::of([(a, Some(&first)), (b, Some(&second))], 9, None),
        Some(built.clone()),
        "the order the owners come in leaves the sample as it is"
    );
    assert_eq!(
        DeviceSample::of([(a, Some(&first)), (a, Some(&second))], 9, None),
        None,
        "a volume supplied twice leaves the sample unknown"
    );
    let newer = Reading {
        sequence: 4,
        outcome: Ok(counted(300, 5, 9_000, 1)),
    };
    let seen = |sample: Option<DeviceSample>| {
        let sample = sample.unwrap();
        let sequences: Vec<_> = sample.owners().iter().map(|o| o.sequence).collect();
        (sample.measured(), sequences)
    };
    assert_eq!(
        seen(DeviceSample::of([(b, Some(&second))], 10, Some(&built))),
        (false, vec![3]),
        "a reading the previous sample holds, behind another volume, is no measurement"
    );
    assert_eq!(
        seen(DeviceSample::of([(b, Some(&newer))], 10, Some(&built))),
        (true, vec![4]),
        "a newer reading of that volume is a measurement"
    );
    assert_eq!(
        seen(DeviceSample::of([(a, Some(&first)), (b, None)], 9, None)),
        (false, vec![7, 0]),
        "an owner with no reading, and none seen before, holds sequence 0"
    );
    assert_eq!(
        seen(DeviceSample::of(
            [(b, None), (a, Some(&first))],
            10,
            Some(&built)
        )),
        (false, vec![7, 3]),
        "an owner with no reading keeps the sequence the previous sample holds, and a reused one its own"
    );
    assert_eq!(
        seen(DeviceSample::of(
            [(a, Some(&first)), (b, Some(&failed))],
            9,
            None
        )),
        (false, vec![7, 4]),
        "a failed owner read is no measurement and holds the failed reading's sequence"
    );
    let lower = Reading {
        sequence: 2,
        outcome: Ok(counted(1, 1, 1, 1)),
    };
    assert_eq!(
        seen(DeviceSample::of([(b, Some(&lower))], 10, Some(&built))),
        (false, vec![2]),
        "a lower sequence replaces the one the previous sample holds"
    );
    // The counts stay equal across seals, so a known rate reads zero and differs from an unavailable one.
    let rolled = |seals: &[Option<Result<u64, u64>>]| {
        let mut previous = None;
        let mut known = Vec::new();
        for (seal, reading) in seals.iter().enumerate() {
            let reading = reading.map(|reading| match reading {
                Ok(sequence) => Reading {
                    sequence,
                    outcome: Ok(counted(0, 0, 0, 0)),
                },
                Err(sequence) => Reading {
                    sequence,
                    outcome: Err(StatisticsFailure::Refused(-5)),
                },
            });
            let at_us = (seal as u64 + 1) * 1_000_000;
            let current = DeviceSample::of([(a, reading.as_ref())], at_us, previous.as_ref());
            let inputs = crate::failover::report::HeadroomInputs {
                previous: previous.clone(),
                current: current.clone(),
                provisioned_iops: core::num::NonZeroU64::new(1_000),
                provisioned_bandwidth: core::num::NonZeroU64::new(1_000),
                ..crate::failover::report::HeadroomInputs::UNAVAILABLE
            };
            let headroom = crate::failover::report::Headroom::of(
                crate::failover::report::Gauge::Unavailable,
                crate::failover::report::Gauge::Unavailable,
                &inputs,
            );
            known.push(
                [headroom.iops, headroom.bandwidth]
                    .map(|gauge| gauge != crate::failover::report::Gauge::Unavailable),
            );
            previous = current;
        }
        known
    };
    let (no, yes) = ([false; 2], [true; 2]);
    assert_eq!(
        rolled(&[Some(Ok(7)), Some(Ok(7)), Some(Ok(8)), Some(Ok(9))]),
        [no, no, no, yes],
        "a reused reading leaves its seal and the next one unavailable, and two fresh readings with unchanged counts read a known zero"
    );
    assert_eq!(
        rolled(&[Some(Ok(7)), None, Some(Ok(7)), Some(Ok(8)), Some(Ok(9))]),
        [no, no, no, no, yes],
        "a seal with no reading keeps the sequence seen before it, so the same reading after it is a reused one"
    );
    assert_eq!(
        rolled(&[
            Some(Ok(7)),
            Some(Ok(7)),
            Some(Ok(7)),
            Some(Ok(8)),
            Some(Ok(9))
        ]),
        [no, no, no, no, yes],
        "a reading reused at two seals is no baseline at the second one, so the first newer reading's seal stays unavailable"
    );
    assert_eq!(
        rolled(&[Some(Ok(7)), Some(Err(8)), Some(Ok(9)), Some(Ok(10))]),
        [no, no, no, yes],
        "a failed reading costs its seal and the next one"
    );
    assert_eq!(
        rolled(&[
            Some(Ok(7)),
            Some(Err(8)),
            Some(Err(9)),
            Some(Ok(10)),
            Some(Ok(11))
        ]),
        [no, no, no, no, yes],
        "two failed readings in a row cost their seals and the next one"
    );
    assert_eq!(
        rolled(&[Some(Ok(7)), None, None, Some(Ok(8)), Some(Ok(9))]),
        [no, no, no, no, yes],
        "two seals with no reading cost themselves and the next one"
    );
    assert_eq!(
        rolled(&[Some(Ok(1_000)), Some(Ok(3)), Some(Ok(5)), Some(Ok(6))]),
        [no, no, no, yes],
        "a replaced driver's lower sequence becomes the sequence seen, so its next reading is a baseline"
    );
}
